//! Real child/FileMedium tests. SIGSTOP models a stalled child, not slow disk.
#![cfg(unix)]

use asupersync::runtime::legacy_profile::{LegacyCaps, LegacyProfile};
use franken_journal::{Commit, Journal, JournalError, Limits, Op};
use franken_speaker::file_medium::FileMedium;
use franken_speaker::journal_process::{ProcessStorage, WorkerCustody};
use std::future::poll_fn;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WORKER: &str = env!("CARGO_BIN_EXE_franken-journal-worker");

#[path = "journal_process/secrets.rs"]
mod secrets;
use secrets::TestSecrets;

// Test-only panic cleanup, outside production poll code. Production explicitly
// retains custody and never installs a blocking Drop implementation.
struct Owned(WorkerCustody);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.shutdown_off_loop(Duration::from_secs(2));
    }
}
struct ResumeChild(Child);
impl Drop for ResumeChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn medium() -> (PathBuf, Limits) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ffw-journal-process-{}-{nonce}.img",
        std::process::id()
    ));
    let limits = Limits::tiny();
    drop(FileMedium::create_new(&path, &limits).unwrap());
    (path, limits)
}

fn runtime() -> asupersync::runtime::Runtime {
    LegacyProfile::new(
        LegacyCaps {
            worker_threads: 1,
            thread_stack_bytes: 256 * 1024,
            blocking_max_threads: 0,
            blocking_thread_stack_bytes: 0,
            global_queue_limit: 8,
            blocking_max_queued: 0,
        },
        256 * 1024,
    )
    .caller_driven()
    .build()
    .unwrap()
}

fn signal(id: u32, name: &str) {
    assert!(
        Command::new("kill")
            .arg(name)
            .arg(id.to_string())
            .status()
            .unwrap()
            .success()
    );
}

fn bounded<F: std::future::Future>(runtime: &asupersync::runtime::Runtime, future: F) -> F::Output {
    runtime.block_on(async {
        let cx = asupersync::cx::Cx::current().expect("caller-driven runtime context");
        assert!(
            cx.timer_driver().is_some(),
            "deadline must use owned timer, not fallback thread"
        );
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), future)
            .await
            .expect("child operation deadline")
    })
}

struct CountWake {
    count: Arc<AtomicUsize>,
    forward: Waker,
}
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.forward.wake_by_ref();
    }
}

#[test]
fn actual_stalled_child_yields_and_reactor_wakes_commit_before_file_reopen() {
    stalled_child_case(false);
}

#[test]
fn pending_child_operation_rebinds_from_idle_runtime_a_to_runtime_b() {
    stalled_child_case(true);
}

fn stalled_child_case(migrate: bool) {
    let (path, limits) = medium();
    let (storage, custody) =
        ProcessStorage::spawn_off_loop(Path::new(WORKER), &path, &limits).unwrap();
    let mut owned = Owned(custody);
    assert!(owned.0.shutdown_off_loop(Duration::MAX).is_err());
    assert!(
        owned.0.try_reap().unwrap().is_none(),
        "invalid deadline must not kill child"
    );
    let (mut journal, _) = Journal::open(storage, limits.clone()).unwrap();
    signal(owned.0.id(), "-STOP");
    // An explicitly owned external process resumes the child after polling is
    // underway; no thread is injected into the caller-driven runtime.
    let mut resumer = ResumeChild(
        Command::new("sh")
            .arg("-c")
            .arg("read -r go; test \"$go\" = GO && kill -CONT \"$1\"")
            .arg("journal-test")
            .arg(owned.0.id().to_string())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let runtime = runtime();
    let first_runtime = self::runtime();
    let ops = [Op::Raise {
        key: b"floor".to_vec(),
        value: 7,
    }];
    let wakes = Arc::new(AtomicUsize::new(0));
    let mut pending = 0;
    let mut io_baseline = None;
    let mut observed_reactor_wake = false;
    {
        let mut cursor = journal.begin_commit(&ops).unwrap();
        if migrate {
            assert!(bounded(
                &first_runtime,
                poll_fn(|cx| Poll::Ready(cursor.poll_commit(cx).is_pending()))
            ));
            // Keep A alive but idle. Only B below can dispatch the resumed
            // child's readiness, so retaining A's registration would time out.
        }
        let result = bounded(
            &runtime,
            poll_fn(|cx| {
                let waker = Waker::from(Arc::new(CountWake {
                    count: Arc::clone(&wakes),
                    forward: cx.waker().clone(),
                }));
                let mut counted = Context::from_waker(&waker);
                if io_baseline.is_none() {
                    for _ in 0..4 {
                        let before = wakes.load(Ordering::SeqCst);
                        assert!(cursor.poll_commit(&mut counted).is_pending());
                        let after = wakes.load(Ordering::SeqCst);
                        if before == after {
                            io_baseline = Some(after);
                            break;
                        }
                    }
                    assert!(
                        io_baseline.is_some(),
                        "must reach stable I/O Pending while worker stopped"
                    );
                    writeln!(resumer.0.stdin.take().unwrap(), "GO").unwrap();
                    return Poll::Pending;
                }
                if !observed_reactor_wake {
                    if wakes.load(Ordering::SeqCst) <= io_baseline.unwrap() {
                        // Ignore a queued bookkeeping wake. Do not opportunistically
                        // read the ACK until the registered reactor waker fires.
                        return Poll::Pending;
                    }
                    observed_reactor_wake = true;
                }
                let before = Instant::now();
                let result = cursor.poll_commit(&mut counted);
                eprintln!(
                    "journal parent poll elapsed_us={}",
                    before.elapsed().as_micros()
                );
                if result.is_pending() {
                    pending += 1;
                }
                result
            }),
        );
        assert_eq!(result, Ok(Commit::Appended));
    }
    assert!(pending > 0);
    assert!(observed_reactor_wake);
    assert!(resumer.0.wait().unwrap().success());
    let mut storage = journal.into_storage();
    assert_eq!(
        bounded(
            if migrate { &first_runtime } else { &runtime },
            poll_fn(|cx| storage.poll_quiesce(cx))
        ),
        Ok(())
    );
    owned.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    assert!(owned.0.try_reap().unwrap().is_some());
    let (reopened, _) =
        Journal::open(FileMedium::open_existing(&path, &limits).unwrap(), limits).unwrap();
    assert_eq!(reopened.state().marks.get(b"floor".as_slice()), Some(&7));
}

#[test]
fn actual_cancelled_child_request_retains_custody_and_quiesces_before_recovery() {
    let (path, limits) = medium();
    let (storage, custody) =
        ProcessStorage::spawn_off_loop(Path::new(WORKER), &path, &limits).unwrap();
    let mut owned = Owned(custody);
    let (mut journal, _) = Journal::open(storage, limits.clone()).unwrap();
    let runtime = runtime();
    signal(owned.0.id(), "-STOP");
    let ops = [Op::Raise {
        key: b"floor".to_vec(),
        value: 11,
    }];
    {
        let mut cursor = journal.begin_commit(&ops).unwrap();
        assert!(bounded(
            &runtime,
            poll_fn(|cx| Poll::Ready(cursor.poll_commit(cx).is_pending()))
        ));
    }
    assert!(journal.is_poisoned());
    assert_eq!(
        journal.raise_mark(b"floor", 12),
        Err(JournalError::Poisoned)
    );
    assert!(
        FileMedium::open_existing(&path, &limits).is_err(),
        "child retains exclusive file custody"
    );
    assert!(owned.0.try_reap().unwrap().is_none());
    signal(owned.0.id(), "-CONT");
    let mut storage = journal.into_storage();
    assert_eq!(
        bounded(&runtime, poll_fn(|cx| storage.poll_quiesce(cx))),
        Ok(())
    );
    owned.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    assert!(owned.0.try_reap().unwrap().is_some());
    let (reopened, _) =
        Journal::open(FileMedium::open_existing(&path, &limits).unwrap(), limits).unwrap();
    // Quiesce synchronizes the accepted program even though its caller was
    // cancelled. Recovery, rather than the cancelled cursor, learns the result.
    assert_eq!(reopened.state().marks.get(b"floor".as_slice()), Some(&11));
}

#[test]
fn startup_failure_returns_the_spawned_child_for_explicit_reaping() {
    let path = std::env::temp_dir().join("ffw-journal-deliberately-absent-parent/no-medium");
    let failure = match ProcessStorage::spawn_off_loop(Path::new(WORKER), &path, &Limits::tiny()) {
        Ok(_) => panic!("absent medium must fail"),
        Err(failure) => failure,
    };
    let mut custody = failure
        .custody
        .expect("spawned child custody survives greeting failure");
    custody.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    assert!(custody.try_reap().unwrap().is_some());
}

#[test]
fn actual_child_death_fails_closed_without_publishing_or_losing_custody() {
    let (path, limits) = medium();
    let (storage, custody) =
        ProcessStorage::spawn_off_loop(Path::new(WORKER), &path, &limits).unwrap();
    let mut owned = Owned(custody);
    let (mut journal, _) = Journal::open(storage, limits).unwrap();
    let before = journal.state().clone();
    owned.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    let ops = [Op::Raise {
        key: b"floor".to_vec(),
        value: 14,
    }];
    let runtime = runtime();
    {
        let mut cursor = journal.begin_commit(&ops).unwrap();
        assert!(matches!(
            bounded(&runtime, poll_fn(|cx| cursor.poll_commit(cx))),
            Err(JournalError::Storage(_))
        ));
    }
    assert_eq!(journal.state(), &before);
    assert!(journal.is_poisoned());
    assert!(owned.0.try_reap().unwrap().is_some());
}

#[test]
fn provisioned_owner_commits_relative_command_through_real_child() {
    pending_owner_case(false);
}

#[test]
fn local_stop_during_real_child_pending_commit_prevents_live_delta() {
    pending_owner_case(true);
}

fn pending_owner_case(stop: bool) {
    use franken_control::channel::endpoint::{FecHandled, Handled};
    use franken_control::channel::owner::FleetControlOwner;
    use franken_control::channel::peer::{PeerId, PeerRole, compute_proof};
    use franken_control::channel::pipeline::{ChannelConfig, PendingStepFailure, SubmitResult};
    use franken_control::channel::request::{ControlCommand, ControlRequest, RequestBody};
    use franken_control::channel::wire::encode_request;
    use franken_session::{AuthorityToken, UnifiedGroupSession};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "ffw-owner-process-{}-{nonce}.img",
        std::process::id()
    ));
    let limits = Limits::fleet_control_development();
    let file = FileMedium::create_new(&path, &limits).unwrap();
    let (mut owner, _) = FleetControlOwner::boot(
        TestSecrets::fleet_control_development(),
        file,
        ChannelConfig::provisional(),
    )
    .unwrap();
    let peer = PeerId::parse("controller").unwrap();
    let key = b"public-test-only-controller-key-0123456789";
    owner
        .admit(&peer, PeerRole::Controller, key, Some(10), 1)
        .unwrap();
    let mut live = UnifiedGroupSession::new("grp", "coord", 10);
    owner
        .install_lease(&live, AuthorityToken::issue(&live, u64::MAX), 0)
        .unwrap();
    let body = RequestBody::new(
        peer,
        1,
        10,
        Some(live.state_revision),
        ControlCommand::AdjustGroupVolume { delta: 10 },
    )
    .unwrap();
    let proof = compute_proof(key, &body.signing_bytes());
    let bytes = encode_request(&ControlRequest::new(body, proof)).unwrap();
    assert!(matches!(
        owner.receive(0, &live, &bytes).unwrap(),
        FecHandled::Control(Handled::Request {
            result: SubmitResult::Queued { .. },
            ..
        })
    ));

    let Ok((handoff, file)) = owner.into_storage_handoff() else {
        panic!("healthy provisioned owner");
    };
    drop(file); // release real FileMedium custody before the worker acquires it
    let (storage, custody) =
        ProcessStorage::spawn_off_loop(Path::new(WORKER), &path, &limits).unwrap();
    let mut owned = Owned(custody);
    let (journal, recovery) = Journal::open(storage, limits.clone()).unwrap();
    assert_eq!(recovery.source, franken_journal::Source::Segment);
    let Ok(owner) = handoff.attach(journal) else {
        panic!("actual recovered provisioned state must match");
    };
    let mut pending = owner.into_pending_step(0, &live, 0);
    signal(owned.0.id(), "-STOP");
    let runtime = runtime();
    let wakes = Arc::new(AtomicUsize::new(0));
    let mut stalled = false;
    let mut generation = 0;
    bounded(
        &runtime,
        poll_fn(|cx| {
            let waker = Waker::from(Arc::new(CountWake {
                count: Arc::clone(&wakes),
                forward: cx.waker().clone(),
            }));
            let mut watched = Context::from_waker(&waker);
            let before = wakes.load(Ordering::SeqCst);
            let result = pending.poll_step(&mut watched, 0, &mut live, generation);
            if result.is_pending() && !stalled && wakes.load(Ordering::SeqCst) == before {
                // No bookkeeping self-wake: real ProcessStorage is waiting for the
                // stopped child. Local stop advances the owner's exact fence.
                assert_eq!(live.group_master_volume, 50);
                stalled = true;
                generation = u64::from(stop);
                signal(owned.0.id(), "-CONT");
                cx.waker().wake_by_ref();
            }
            result
        }),
    );
    assert!(stalled, "must exercise an actual blocked child operation");
    let Ok((owner, outcome, deferred)) = pending.finish() else {
        panic!("terminal ownership retained");
    };
    assert!(deferred.is_empty());
    if stop {
        assert!(matches!(
            outcome,
            Err(PendingStepFailure::FenceChanged { .. })
        ));
        assert_eq!(live.group_master_volume, 50);
    } else {
        let settlements = outcome.unwrap();
        assert_eq!(settlements.len(), 1);
        assert_eq!(live.group_master_volume, 60);
    }
    let mut storage = owner.into_storage();
    bounded(&runtime, poll_fn(|cx| storage.poll_quiesce(cx))).unwrap();
    owned.0.shutdown_off_loop(Duration::from_secs(2)).unwrap();
    drop(storage);
    let (journal, _) =
        Journal::open(FileMedium::open_existing(&path, &limits).unwrap(), limits).unwrap();
    assert!(
        journal.state().records.contains_key(b"n02.seq".as_slice()),
        "relative floor survives either outcome"
    );
}

#[path = "journal_process/settled_owner.rs"]
mod settled_owner;

#[test]
fn settled_owner_real_child_commit_and_stop_drain_custody_handoff() {
    for cancel in [false, true] {
        settled_owner::run(Path::new(WORKER), cancel);
    }
}
