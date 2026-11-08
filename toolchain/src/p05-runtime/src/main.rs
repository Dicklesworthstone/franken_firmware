//! P05's real runtime probe: the pinned Asupersync runtime, under its own bounded `LegacyProfile`, doing real work.
//!
//! Bead ffw-ipz. The sibling `p05-target` probe runs `franken-atomic` only; no Asupersync code executed in the guest. This one links
//! the Git-pinned runtime and exercises, in order: the profile's refusals and acceptance, a runtime built from that profile and
//! AUDITED against it, spawn and join, abort of a timer-parked task, a timer wake, loopback UDP, the bounded blocking pool at its
//! queue bound, and a root drain with live tasks. Every operation prints one `FFW_P05_RUNTIME:<NAME>` marker carrying what it
//! observed; `ok` or `failed` is computed from those observations at run time, and an operation this platform or API cannot do is
//! printed `unsupported` with the reason and counted. Nothing is polyfilled and nothing is reported as passed because it was skipped.
//! One `FFW_P05_RUNTIME:END` marker closes the transcript with the real counts; a transcript without it did not finish.
//!
//! Thread and memory census. Between phases (after each `block_on` has returned) and once inside a parked task, the probe reads
//! `/proc/self/task` and `/proc/self/status` (`Threads`, `VmRSS`, `VmHWM`) and `/proc/meminfo` (`MemAvailable`). A figure that cannot
//! be read, because `/proc` is not mounted or the field is absent, is printed `unknown`. It is never replaced by a guess or a zero.
//!
//! Scope. Loopback only: every socket is bound to `127.0.0.1` through a literal `SocketAddr`, so no name is resolved, and a bound
//! address that is not loopback is refused. No `unsafe` (the crate forbids it); as PID 1 the probe parks after END instead of calling
//! `reboot`, and the supervisor that owns the QEMU process ends it. What this does not show: it is not a memory-fit result, not a
//! throughput or latency figure, and not the cancellation audit; the stack sizes below are requested sizes, not measurements.
#![forbid(unsafe_code)]

use std::fmt::Display;
use std::fs;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::UdpSocket;
use asupersync::runtime::legacy_profile::{CapViolation, LegacyCaps, LegacyProfile};
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{
    BlockingSpawnErrorKind, BlockingTaskHandle, JoinError, RootDrainOutcome, RootDrainReport,
    Runtime, yield_now,
};
use asupersync::time::sleep;

const MIB: usize = 1024 * 1024;
const CHILDREN: usize = 8;
const DRAIN_TASKS: usize = 4;
const UDP_PAYLOAD: &[u8] = b"ffw-p05-runtime-udp";
/// A timer wake may be reported a few milliseconds early by a coarse timer; anything further is a failure.
const EARLY_TOLERANCE: Duration = Duration::from_millis(5);
const LONG: Duration = Duration::from_secs(10);
/// How long any one phase waits for something that should already be happening before it records a failure instead of waiting on.
const PHASE_LIMIT: Duration = Duration::from_secs(20);

/// Wait, yielding to the runtime, until `$child` has reached its terminal join state or `$limit` passes; evaluates to whether it did.
/// A macro and not a function so that no reference to the handle is held across the await (the phase futures must be `Send`).
macro_rules! finished_within {
    ($child:expr, $limit:expr) => {{
        let started = Instant::now();
        loop {
            if $child.is_finished() {
                break true;
            }
            if started.elapsed() >= $limit {
                break false;
            }
            yield_now().await;
        }
    }};
}

// ---- markers and counters ---------------------------------------------------------------------------------------------------

/// One marker line. Pure, so the format is tested natively.
fn line(name: &str, status: &str, detail: &str) -> String {
    format!("FFW_P05_RUNTIME:{name} status={status} {detail}")
}

fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

/// What an operation observed. Only `Pass` is a pass. `Fail` is a contradiction of the contract. `Unsupported` is for what this
/// platform or API cannot do here. `Partial` is an observation that was only partly readable or not taken at one instant, and
/// `Unknown` is one with nothing readable at all. The last three are counted and printed under their own names, never as `ok`.
enum Verdict {
    Pass(String),
    Fail(String),
    Unsupported(String),
    Partial(String),
    Unknown(String),
}

/// `ops == ok + failed + unsupported + partial + unknown` always; `census_samples` is how many of those operations were CENSUS lines.
#[derive(Default)]
struct Report {
    ops: u32,
    ok: u32,
    failed: u32,
    unsupported: u32,
    partial: u32,
    unknown: u32,
    census_samples: u32,
    /// The name of every recorded operation, in order, so a caller can check WHICH phases ran and not only how many.
    names: Vec<String>,
}

impl Report {
    fn record(&mut self, name: &str, verdict: Verdict) {
        self.ops += 1;
        self.names.push(name.to_string());
        if name == "CENSUS" {
            self.census_samples += 1;
        }
        let (status, detail) = match verdict {
            Verdict::Pass(detail) => {
                self.ok += 1;
                ("ok", detail)
            }
            Verdict::Fail(detail) => {
                self.failed += 1;
                ("failed", detail)
            }
            Verdict::Unsupported(detail) => {
                self.unsupported += 1;
                ("unsupported", detail)
            }
            Verdict::Partial(detail) => {
                self.partial += 1;
                ("partial", detail)
            }
            Verdict::Unknown(detail) => {
                self.unknown += 1;
                ("unknown", detail)
            }
        };
        emit(&line(name, status, &detail));
    }

    fn end(&self) -> String {
        let detail = format!(
            "ops={} ok={} failed={} unsupported={} partial={} unknown={} census_samples={}",
            self.ops,
            self.ok,
            self.failed,
            self.unsupported,
            self.partial,
            self.unknown,
            self.census_samples
        );
        line("END", "done", &detail)
    }

    /// 0 only when every operation passed; 1 if any failed; 2 if none failed but some were unsupported, partial or unknown.
    fn exit_code(&self) -> i32 {
        if self.failed > 0 {
            1
        } else if self.unsupported + self.partial + self.unknown > 0 {
            2
        } else {
            0
        }
    }
}

// ---- the census -------------------------------------------------------------------------------------------------------------

/// One reading of the process. The thread directory is counted BEFORE and AFTER the status file is read, so a thread that started or
/// ended during the sample is seen as a change and not mistaken for two sources disagreeing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Census {
    task_dir_before: Option<usize>,
    task_dir_after: Option<usize>,
    status_threads: Option<u64>,
    rss_kb: Option<u64>,
    hwm_kb: Option<u64>,
    mem_available_kb: Option<u64>,
}

impl Census {
    /// The thread count in `/proc/self/task` when it was readable both times and did not change between them.
    fn stable_task_dir(&self) -> Option<usize> {
        match (self.task_dir_before, self.task_dir_after) {
            (Some(before), Some(after)) if before == after => Some(before),
            _ => None,
        }
    }
}

/// The first line `<key>:` followed by a decimal number (any unit word after it is ignored). A missing key, a different key that merely
/// starts with this one, or a value that is not a number is `None`.
fn field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|row| {
        let rest = row.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

fn show<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_string(), |known| known.to_string())
}

fn task_dir_count() -> Option<usize> {
    fs::read_dir("/proc/self/task")
        .ok()
        .map(|entries| entries.filter(Result::is_ok).count())
}

fn census() -> Census {
    let task_dir_before = task_dir_count();
    let status = fs::read_to_string("/proc/self/status").ok();
    let task_dir_after = task_dir_count();
    let meminfo = fs::read_to_string("/proc/meminfo").ok();
    let in_status = |key: &str| status.as_deref().and_then(|text| field(text, key));
    Census {
        task_dir_before,
        task_dir_after,
        status_threads: in_status("Threads"),
        rss_kb: in_status("VmRSS"),
        hwm_kb: in_status("VmHWM"),
        mem_available_kb: meminfo
            .as_deref()
            .and_then(|text| field(text, "MemAvailable")),
    }
}

fn census_detail(phase: &str, c: &Census) -> String {
    let dir_stable = match (c.task_dir_before, c.task_dir_after) {
        (Some(before), Some(after)) => (before == after).to_string(),
        _ => "unknown".to_string(),
    };
    let agree = match (c.stable_task_dir(), c.status_threads) {
        (Some(dir), Some(status)) => (u64::try_from(dir).ok() == Some(status)).to_string(),
        _ => "unknown".to_string(),
    };
    format!(
        "phase={phase} threads_task_dir_before={} threads_task_dir_after={} task_dir_stable={dir_stable} threads_status={} sources_agree={agree} vm_rss_kb={} vm_hwm_kb={} mem_available_kb={}",
        show(c.task_dir_before),
        show(c.task_dir_after),
        show(c.status_threads),
        show(c.rss_kb),
        show(c.hwm_kb),
        show(c.mem_available_kb)
    )
}

/// What one census reading means. Pure, so every branch is tested with made-up readings.
/// * `Fail`: two sources that were read stably DISAGREE about the thread count, a thread figure is 0 (a running process has at
///   least one), or the high-water mark is below the current resident size.
/// * `Unknown`: nothing at all could be read.
/// * `Partial`: something could not be read, or the thread set changed while it was being read, so the two thread sources were not
///   read at one instant and no agreement or disagreement is claimed.
/// * `Pass`: both thread sources were stable and equal, and all three memory figures were read.
///
/// A missing figure is never turned into a number.
fn judge_census(phase: &str, c: &Census) -> Verdict {
    let detail = census_detail(phase, c);
    let stable = c.stable_task_dir();
    if let (Some(dir), Some(status)) = (stable, c.status_threads)
        && u64::try_from(dir).ok() != Some(status)
    {
        return Verdict::Fail(format!("{detail} reason=thread_sources_disagree"));
    }
    if stable == Some(0) || c.status_threads == Some(0) {
        return Verdict::Fail(format!("{detail} reason=zero_threads_in_a_running_process"));
    }
    if let (Some(hwm), Some(rss)) = (c.hwm_kb, c.rss_kb)
        && hwm < rss
    {
        return Verdict::Fail(format!("{detail} reason=high_water_below_resident"));
    }
    let nothing = c.task_dir_before.is_none()
        && c.task_dir_after.is_none()
        && c.status_threads.is_none()
        && c.rss_kb.is_none()
        && c.hwm_kb.is_none()
        && c.mem_available_kb.is_none();
    if nothing {
        return Verdict::Unknown(format!("{detail} reason=nothing_readable"));
    }
    let complete = stable.is_some()
        && c.status_threads.is_some()
        && c.rss_kb.is_some()
        && c.hwm_kb.is_some()
        && c.mem_available_kb.is_some();
    if complete {
        Verdict::Pass(detail)
    } else if c.task_dir_before.is_some() && c.task_dir_after.is_some() && stable.is_none() {
        Verdict::Partial(format!(
            "{detail} reason=thread_set_changed_during_the_reading"
        ))
    } else {
        Verdict::Partial(format!("{detail} reason=some_figures_unreadable"))
    }
}

/// Take one sample and record its judged verdict. Returns the reading for a caller that wants a figure from it.
fn sample(report: &mut Report, phase: &str) -> Census {
    let c = census();
    report.record("CENSUS", judge_census(phase, &c));
    c
}

// ---- the profile ------------------------------------------------------------------------------------------------------------

/// Two scheduler workers, one blocking thread and one queued blocking job, every queue bounded, every stack stated.
fn caps() -> LegacyCaps {
    LegacyCaps {
        worker_threads: 2,
        thread_stack_bytes: MIB,
        blocking_max_threads: 1,
        blocking_thread_stack_bytes: MIB / 2,
        global_queue_limit: 256,
        blocking_max_queued: 1,
    }
}

fn profile() -> Option<LegacyProfile> {
    let stated = caps();
    stated
        .worst_case_stack_bytes()
        .map(|budget| LegacyProfile::new(stated, budget))
}

/// The profile accepts the caps it was given and refuses, by name, the ones that leave something unbounded or over budget.
fn profile_phase(report: &mut Report) {
    let Some(good) = profile() else {
        report.record(
            "PROFILE_ACCEPT",
            Verdict::Fail("worst_case_stack_bytes=overflow".to_string()),
        );
        return;
    };
    let accepted = good.violations();
    let worst = good.caps().worst_case_stack_bytes();
    let detail = format!(
        "violations={} worst_case_stack_bytes={} budget={}",
        accepted.len(),
        show(worst),
        good.stack_budget_bytes()
    );
    let verdict = if accepted.is_empty() && good.validate().is_ok() {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    };
    report.record("PROFILE_ACCEPT", verdict);

    let budget = good.stack_budget_bytes();
    let no_workers = LegacyProfile::new(
        LegacyCaps {
            worker_threads: 0,
            ..good.caps()
        },
        budget,
    );
    let unbounded = LegacyProfile::new(
        LegacyCaps {
            global_queue_limit: 0,
            ..good.caps()
        },
        budget,
    );
    let over = LegacyProfile::new(good.caps(), budget.saturating_sub(1));
    let refused = [
        (
            "PROFILE_REFUSES_ZERO_WORKERS",
            no_workers.violations().contains(&CapViolation::NoWorkers),
            no_workers.builder().is_err(),
        ),
        (
            "PROFILE_REFUSES_UNBOUNDED_QUEUE",
            unbounded
                .violations()
                .contains(&CapViolation::GlobalQueueUnbounded),
            unbounded.builder().is_err(),
        ),
        (
            "PROFILE_REFUSES_OVER_BUDGET",
            over.violations()
                .iter()
                .any(|v| matches!(v, CapViolation::StackBudgetExceeded { .. })),
            over.builder().is_err(),
        ),
    ];
    for (name, named, builder_refused) in refused {
        let detail = format!("named_violation={named} builder_refused={builder_refused}");
        let verdict = if named && builder_refused {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        };
        report.record(name, verdict);
    }
}

/// Build the runtime from the profile and audit it against the profile. The reactor is the platform's own; when it cannot be
/// created the runtime is built without one and every phase that needs I/O says so.
fn build_phase(report: &mut Report, profile: &LegacyProfile) -> Option<(Runtime, bool)> {
    let builder = match profile.builder() {
        Ok(builder) => builder,
        Err(error) => {
            report.record(
                "RUNTIME_BUILD",
                Verdict::Fail(format!("builder_error={error:?}")),
            );
            return None;
        }
    };
    let (builder, reactor) = match create_reactor() {
        Ok(reactor) => {
            report.record("REACTOR", Verdict::Pass("kind=platform".to_string()));
            (builder.with_reactor(reactor), true)
        }
        Err(error) => {
            report.record(
                "REACTOR",
                Verdict::Unsupported(format!("create_reactor_error_kind={:?}", error.kind())),
            );
            (builder.enable_platform_reactor(false), false)
        }
    };
    let runtime = match builder.build() {
        Ok(runtime) => runtime,
        Err(error) => {
            report.record(
                "RUNTIME_BUILD",
                Verdict::Fail(format!("build_error={error:?}")),
            );
            return None;
        }
    };
    let audit = profile.audit(&runtime);
    let carried = LegacyCaps::of_runtime(&runtime);
    let stated = profile.caps();
    let detail = format!(
        "audit_ok={} workers={}/{} blocking_threads={}/{} global_queue={}/{} blocking_queue={}/{} (carried/stated)",
        audit.is_ok(),
        carried.worker_threads,
        stated.worker_threads,
        carried.blocking_max_threads,
        stated.blocking_max_threads,
        carried.global_queue_limit,
        stated.global_queue_limit,
        carried.blocking_max_queued,
        stated.blocking_max_queued
    );
    match audit {
        Ok(()) => report.record("RUNTIME_AUDIT", Verdict::Pass(detail)),
        Err(error) => report.record(
            "RUNTIME_AUDIT",
            Verdict::Fail(format!("{detail} error={error:?}")),
        ),
    }
    Some((runtime, reactor))
}

// ---- the async phases (each runs as a task under `block_on`) ----------------------------------------------------------------

fn run_async<F>(runtime: &Runtime, phase: F) -> Verdict
where
    F: Future<Output = Verdict> + Send + 'static,
{
    runtime.block_on(runtime.handle().spawn(phase))
}

async fn spawn_join_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let mut handles = Vec::new();
    for i in 0..CHILDREN {
        match cx.spawn(move |_child| async move {
            yield_now().await;
            i * i
        }) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                return Verdict::Fail(format!("spawn_refused={error:?} after={}", handles.len()));
            }
        }
    }
    let (mut joined, mut sum) = (0_usize, 0_usize);
    for mut handle in handles {
        if !finished_within!(handle, PHASE_LIMIT) {
            return Verdict::Fail(format!(
                "child_not_finished_within_{}s joined={joined}",
                PHASE_LIMIT.as_secs()
            ));
        }
        match handle.join(&cx).await {
            Ok(value) => {
                joined += 1;
                sum += value;
            }
            Err(error) => return Verdict::Fail(format!("join_error={error:?} joined={joined}")),
        }
    }
    let expected: usize = (0..CHILDREN).map(|i| i * i).sum();
    let detail = format!("children={CHILDREN} joined={joined} sum={sum} expected={expected}");
    if joined == CHILDREN && sum == expected {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

/// Abort a child parked on a 10 s timer: it must finish well inside a second and leave no timer registered.
async fn abort_timer_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let Some(timer) = cx.timer_driver() else {
        return Verdict::Unsupported("no_timer_driver_on_this_task".to_string());
    };
    let parked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&parked);
    let spawned = cx.spawn(move |child_cx| async move {
        let mut sleeper = pin!(sleep(child_cx.now(), LONG));
        std::future::poll_fn(|poll_cx| {
            let polled = sleeper.as_mut().poll(poll_cx);
            if polled.is_pending() {
                flag.store(true, Ordering::Release);
            }
            polled
        })
        .await;
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    let started = Instant::now();
    while !parked.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(2) {
        yield_now().await;
    }
    let during = census();
    let pending_before = timer.pending_count();
    child.abort();
    let t0 = Instant::now();
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "aborted_child_not_finished_within_{}s pending_timers_before={pending_before}",
            PHASE_LIMIT.as_secs()
        ));
    }
    let joined = child.join(&cx).await;
    let elapsed = t0.elapsed();
    let pending_after = timer.pending_count();
    // The contract, as the pinned audit asserts it for this very child
    // (`abort_and_join_complete_promptly_for_a_timer_parked_native_child`, `assert_eq!(result, Ok(()))`): `Sleep` has no error
    // output, so the cancellation it acknowledged completes the wait and the child's own result is preserved. Exactly `Ok(())`,
    // not "any Ok" and not "any outcome that finished": `Err(JoinError::Cancelled(_))` is the OTHER case, a future that did not
    // acknowledge (see `ABORT_BLIND_VALUE`), and here it is a contradiction. That audit runs on a current-thread runtime; this
    // runtime has two workers, so a `Cancelled` here is a finding to read, and the oracle is not loosened to accept it.
    let preserved = matches!(joined, Ok(()));
    let detail = format!(
        "parked={} pending_timers_before={pending_before} pending_timers_after={pending_after} abort_to_join_ms={} join_result={} expected_join_result=Ok threads_during_task_dir={} threads_during_status={}",
        parked.load(Ordering::Acquire),
        elapsed.as_millis(),
        join_kind(&joined),
        show(during.stable_task_dir()),
        show(during.status_threads)
    );
    let ok = parked.load(Ordering::Acquire)
        && pending_before >= 1
        && pending_after + 1 == pending_before
        && preserved
        && elapsed < Duration::from_secs(1);
    if ok {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

/// Which kind of result a join gave, by name, so a report says which contract case it saw.
fn join_kind<T>(joined: &Result<T, JoinError>) -> &'static str {
    match joined {
        Ok(_) => "Ok",
        Err(JoinError::Cancelled(_)) => "Cancelled",
        Err(JoinError::Panicked(_)) => "Panicked",
        #[allow(unreachable_patterns)]
        Err(_) => "OtherError",
    }
}

/// The other half of the abort contract. A child that never acknowledges cancellation and only returns a value once the abort has
/// been requested joins as `Err(JoinError::Cancelled(_))`, not as `Ok(value)` (the pinned audit's
/// `ordinary_spawn_keeps_cancellation_dominant_for_cancellation_blind_late_values`). The value is released only AFTER `abort()`, on
/// any worker, so the order is fixed by this code and not by which worker polls first.
async fn abort_blind_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let released = Arc::new(AtomicBool::new(false));
    let slot: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let (child_released, child_slot) = (Arc::clone(&released), Arc::clone(&slot));
    let spawned = cx.spawn(move |_child_cx| async move {
        std::future::poll_fn(|poll_cx| {
            if child_released.load(Ordering::Acquire) {
                return Poll::Ready(42_u32);
            }
            *child_slot.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(poll_cx.waker().clone());
            Poll::Pending
        })
        .await
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    let has_waker = || {
        slot.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    };
    let started = Instant::now();
    while !has_waker() && started.elapsed() < Duration::from_secs(2) {
        yield_now().await;
    }
    if !has_waker() {
        child.abort();
        let _ = child.join(&cx).await;
        return Verdict::Fail("blind_child_never_polled".to_string());
    }
    child.abort();
    released.store(true, Ordering::Release);
    let waker = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(waker) = waker {
        waker.wake();
    }
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "aborted_blind_child_not_finished_within_{}s",
            PHASE_LIMIT.as_secs()
        ));
    }
    let joined = child.join(&cx).await;
    let detail = format!(
        "join_result={} expected_join_result=Cancelled ok_value={:?}",
        join_kind(&joined),
        joined.as_ref().ok()
    );
    if matches!(joined, Err(JoinError::Cancelled(_))) {
        Verdict::Pass(detail)
    } else {
        Verdict::Fail(detail)
    }
}

async fn timer_wake_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let wanted = Duration::from_millis(50);
    let spawned = cx.spawn(move |child_cx| async move {
        let t0 = Instant::now();
        sleep(child_cx.now(), wanted).await;
        t0.elapsed()
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    if !finished_within!(child, PHASE_LIMIT) {
        return Verdict::Fail(format!(
            "sleeping_child_not_finished_within_{}s",
            PHASE_LIMIT.as_secs()
        ));
    }
    match child.join(&cx).await {
        Ok(elapsed) => {
            let detail = format!(
                "wanted_ms={} slept_ms={}",
                wanted.as_millis(),
                elapsed.as_millis()
            );
            let not_early = elapsed + EARLY_TOLERANCE >= wanted;
            if not_early && elapsed < Duration::from_secs(5) {
                Verdict::Pass(detail)
            } else {
                Verdict::Fail(detail)
            }
        }
        Err(error) => Verdict::Fail(format!("join_error={error:?}")),
    }
}

/// One datagram from one loopback socket to another, received by a spawned task; a timeout aborts the receiver instead of hanging.
async fn udp_phase() -> Verdict {
    let Some(cx) = Cx::current() else {
        return Verdict::Fail("no_current_cx".to_string());
    };
    let any = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut sender = match UdpSocket::bind(any).await {
        Ok(socket) => socket,
        Err(error) => return Verdict::Unsupported(format!("bind_error_kind={:?}", error.kind())),
    };
    let receiver = match UdpSocket::bind(any).await {
        Ok(socket) => socket,
        Err(error) => return Verdict::Unsupported(format!("bind_error_kind={:?}", error.kind())),
    };
    let (Ok(from), Ok(to)) = (sender.local_addr(), receiver.local_addr()) else {
        return Verdict::Unsupported("local_addr_unreadable".to_string());
    };
    if !from.ip().is_loopback() || !to.ip().is_loopback() {
        return Verdict::Fail(format!("not_loopback from={from} to={to}"));
    }
    let spawned = cx.spawn(move |_child| async move {
        let mut receiver = receiver;
        let mut buf = [0_u8; 64];
        receiver
            .recv_from(&mut buf)
            .await
            .map(|(n, peer)| (buf[..n].to_vec(), peer))
    });
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Verdict::Fail(format!("spawn_refused={error:?}")),
    };
    if let Err(error) = sender.send_to(UDP_PAYLOAD, to).await {
        child.abort();
        let _ = child.join(&cx).await;
        return Verdict::Fail(format!("send_error_kind={:?}", error.kind()));
    }
    let started = Instant::now();
    while !child.is_finished() && started.elapsed() < Duration::from_secs(3) {
        sleep(cx.now(), Duration::from_millis(5)).await;
    }
    if !child.is_finished() {
        child.abort();
        let _ = child.join(&cx).await;
        return Verdict::Fail("receive_timeout_after_3s receiver_aborted=true".to_string());
    }
    match child.join(&cx).await {
        Ok(Ok((bytes, peer))) => {
            let detail = format!(
                "bytes={} payload_equal={} peer_is_sender={}",
                bytes.len(),
                bytes == UDP_PAYLOAD,
                peer == from
            );
            if bytes == UDP_PAYLOAD && peer == from {
                Verdict::Pass(detail)
            } else {
                Verdict::Fail(detail)
            }
        }
        Ok(Err(error)) => Verdict::Fail(format!("recv_error_kind={:?}", error.kind())),
        Err(error) => Verdict::Fail(format!("join_error={error:?}")),
    }
}

// ---- the bounded blocking pool (plain threads, driven from the main thread) -------------------------------------------------

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
            open = self
                .changed
                .wait(open)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }
}

fn wait_until(limit: Duration, condition: impl Fn() -> bool) -> bool {
    let started = Instant::now();
    while !condition() {
        if started.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

fn gated_job(
    gate: &Arc<Gate>,
    running: &Arc<AtomicUsize>,
) -> impl FnOnce() + Send + 'static + use<> {
    let (gate, running) = (Arc::clone(gate), Arc::clone(running));
    move || {
        running.fetch_add(1, Ordering::SeqCst);
        gate.wait();
    }
}

/// One blocking thread and one queued job: the first job runs, the second queues, the third is refused as saturated, and after the
/// gate opens both admitted jobs finish. No blocking thread exists before the first job.
fn blocking_phase(report: &mut Report, runtime: &Runtime) {
    let Some(pool) = runtime.blocking_handle() else {
        report.record(
            "BLOCKING_POOL",
            Verdict::Unsupported("runtime_has_no_blocking_pool".to_string()),
        );
        return;
    };
    let (gate, running) = (Arc::new(Gate::default()), Arc::new(AtomicUsize::new(0)));
    let idle_threads = pool.active_threads();
    let first = pool.try_spawn(gated_job(&gate, &running));
    let started = wait_until(Duration::from_secs(5), || {
        running.load(Ordering::SeqCst) == 1
    });
    let second = pool.try_spawn(gated_job(&gate, &running));
    let third = pool.try_spawn(gated_job(&gate, &running));
    let third_kind = third.err().map(|refused| refused.kind());
    let (active, pending) = (pool.active_threads(), pool.pending_count());
    let held = census();
    gate.release();
    let done = (finished(&first), finished(&second));
    let detail = format!(
        "idle_threads={idle_threads} first_admitted={} first_started={started} second_admitted={} third_refused={third_kind:?} active_threads_while_held={active} pending_while_held={pending} threads_held_task_dir={} threads_held_status={} first_finished={} second_finished={} ran={}",
        first.is_ok(),
        second.is_ok(),
        show(held.stable_task_dir()),
        show(held.status_threads),
        done.0,
        done.1,
        running.load(Ordering::SeqCst)
    );
    let ok = idle_threads == 0
        && first.is_ok()
        && started
        && second.is_ok()
        && third_kind == Some(BlockingSpawnErrorKind::Saturated)
        && active == 1
        && pending == 1
        && done == (true, true)
        && running.load(Ordering::SeqCst) == 2;
    report.record(
        "BLOCKING_POOL",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        },
    );
}

/// Whether a submission was admitted AND its task completed within five seconds of the gate opening.
fn finished<E>(submitted: &Result<BlockingTaskHandle, E>) -> bool {
    submitted
        .as_ref()
        .is_ok_and(|task| task.wait_timeout(Duration::from_secs(5)))
}

// ---- drain ------------------------------------------------------------------------------------------------------------------

/// Root tasks parked on 10 s timers, then a bounded root drain: it must cancel them and leave no live task, obligation or finalizer.
fn drain_phase(report: &mut Report, runtime: &Runtime) {
    let handle = runtime.handle();
    let mut spawned = 0_usize;
    let mut tasks = Vec::new();
    // Each task counts itself the first time its sleep is polled to `Pending`, i.e. when it is really parked on the timer.
    let entered = Arc::new(AtomicUsize::new(0));
    // The runtime's timer driver, handed out by the tasks (a driver handle is only reachable from a task's `Cx`), so the main thread
    // can count the pending timers.
    let timer_slot = Arc::new(Mutex::new(None));
    for _ in 0..DRAIN_TASKS {
        let counter = Arc::clone(&entered);
        let slot = Arc::clone(&timer_slot);
        let parked = handle.try_spawn(async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            if let Some(timer) = cx.timer_driver() {
                *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(timer);
            }
            let mut sleeper = pin!(sleep(cx.now(), LONG));
            let mut counted = false;
            std::future::poll_fn(|poll_cx| {
                let polled = sleeper.as_mut().poll(poll_cx);
                if polled.is_pending() && !counted {
                    counted = true;
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                polled
            })
            .await;
        });
        if let Ok(task) = parked {
            spawned += 1;
            tasks.push(task);
        }
    }
    // The drain is triggered only once every admitted task has been SEEN parked, not after a guessed delay. If they do not all park
    // within the limit the drain is refused and said so, because a drain of tasks that never slept proves nothing about cancelling
    // parked ones.
    let all_parked = wait_until(PHASE_LIMIT, || entered.load(Ordering::SeqCst) == spawned);
    let parked_count = entered.load(Ordering::SeqCst);
    if !all_parked {
        let detail = format!(
            "drain_not_triggered: {parked_count}/{spawned} admitted tasks entered their sleep within {}s",
            PHASE_LIMIT.as_secs()
        );
        report.record("DRAIN", Verdict::Fail(detail));
        drop(tasks);
        return;
    }
    // `entered == spawned` says each task slept ONCE; it does not say they are all STILL parked (a 10 s sleep can end while a slow
    // task is only now starting). So, immediately before the trigger, look again: no admitted task may have finished, and the timer
    // driver must show at least one pending timer per task. Otherwise the drain is refused with the numbers seen, and no deadline is
    // loosened.
    let snapshot = ParkedSnapshot {
        admitted: tasks.len(),
        unfinished: tasks.iter().filter(|task| !task.is_finished()).count(),
        timers_pending: timer_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|timer| timer.pending_count()),
    };
    if !snapshot.all_parked(DRAIN_TASKS) {
        let detail = format!(
            "drain_refused_not_all_still_parked: {} parked_counter={parked_count}/{spawned}",
            snapshot.detail()
        );
        report.record("DRAIN", Verdict::Fail(detail));
        drop(tasks);
        return;
    }
    let bound = Duration::from_secs(5);
    let drained = runtime.shutdown_drained(bound);
    // Draining a root that is already closed is itself pinned (`handle_drain_of_an_already_closed_root_preserves_bounded_teardown`):
    // the same success, with nothing live.
    let again = runtime.shutdown_drained(Duration::ZERO);
    let detail = format!(
        "tasks_spawned={spawned}/{DRAIN_TASKS} tasks_parked_before_drain={parked_count} snapshot_before_drain=({}) {} elapsed_ms={} bound_ms={} repeat: {}",
        snapshot.detail(),
        drain_detail(&drained),
        drained.elapsed.as_millis(),
        bound.as_millis(),
        drain_detail(&again)
    );
    let ok = spawned == DRAIN_TASKS
        && parked_count == DRAIN_TASKS
        && drain_succeeded(&drained)
        && drained.elapsed < bound
        && drain_succeeded(&again);
    report.record(
        "DRAIN",
        if ok {
            Verdict::Pass(detail)
        } else {
            Verdict::Fail(detail)
        },
    );
    drop(tasks);
}

/// What was seen immediately before the drain was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParkedSnapshot {
    /// Handles of the tasks the runtime admitted.
    admitted: usize,
    /// Of those, the ones that had not reached their terminal join state.
    unfinished: usize,
    /// The timer driver's pending timers; `None` when no driver handle could be read.
    timers_pending: Option<usize>,
}

impl ParkedSnapshot {
    /// True only if exactly `want` tasks were admitted, none of them has finished, and the timer driver shows at least `want` pending
    /// timers (other timers may also be pending). A driver that could not be read is not a pass.
    fn all_parked(&self, want: usize) -> bool {
        self.admitted == want
            && self.unfinished == want
            && self.timers_pending.is_some_and(|timers| timers >= want)
    }

    fn detail(&self) -> String {
        format!(
            "admitted={} unfinished={} timers_pending={}",
            self.admitted,
            self.unfinished,
            show(self.timers_pending)
        )
    }
}

/// The pinned success contract of `shutdown_drained`. `Quiescent` is only reported when the root region is gone AND every count is
/// zero, so `live_regions == 0` is the baseline after a successful drain (the pinned timeout test reports `TimedOut` with
/// `live_regions == 1` while the root is still open). The report's counts are checked as well, not only the outcome, because the
/// documentation says a count of zero alone does not certify a drain.
fn drain_succeeded(report: &RootDrainReport) -> bool {
    report.outcome == RootDrainOutcome::Quiescent
        && report.live_tasks == 0
        && report.pending_obligations == 0
        && report.live_regions == 0
        && report.queued_finalizers == 0
        && report.pending_spawns == 0
        && !report.has_pending_obligation_posts
}

fn drain_detail(report: &RootDrainReport) -> String {
    format!(
        "outcome={:?} expected_outcome=Quiescent live_tasks={} pending_obligations={} live_regions={} expected_live_regions=0 queued_finalizers={} pending_spawns={} pending_obligation_posts={}",
        report.outcome,
        report.live_tasks,
        report.pending_obligations,
        report.live_regions,
        report.queued_finalizers,
        report.pending_spawns,
        report.has_pending_obligation_posts
    )
}

// ---- main -------------------------------------------------------------------------------------------------------------------

fn finish(report: &Report) -> ! {
    emit(&report.end());
    // As PID 1 there is nothing to return to and no `reboot` without `unsafe`: park, and the supervisor that owns the QEMU process
    // ends it once it has read END.
    if std::process::id() == 1 {
        loop {
            std::thread::park();
        }
    }
    std::process::exit(report.exit_code());
}

fn main() {
    let report = run_probe();
    finish(&report)
}

/// Every phase, in order, and the report of what happened. `main` calls it and then `finish`, unchanged (END, PID 1 parking, the exit
/// code); the native test calls it directly, so the REAL phases run under `cargo test`, not a stand-in. A failure to set up returns
/// the report so far, never an exit.
fn run_probe() -> Report {
    let mut report = Report::default();
    let begin = format!(
        "pid={} arch={} endian={} pointer_bits={} threads_available_to_std={}",
        std::process::id(),
        std::env::consts::ARCH,
        if cfg!(target_endian = "big") {
            "big"
        } else {
            "little"
        },
        usize::BITS,
        show(
            std::thread::available_parallelism()
                .ok()
                .map(std::num::NonZeroUsize::get)
        )
    );
    emit(&line("BEGIN", "start", &begin));
    sample(&mut report, "start");

    profile_phase(&mut report);
    let Some(stated) = profile() else {
        return report;
    };
    let Some((runtime, reactor)) = build_phase(&mut report, &stated) else {
        return report;
    };
    sample(&mut report, "after_build");

    report.record("SPAWN_JOIN", run_async(&runtime, spawn_join_phase()));
    sample(&mut report, "after_spawn_join");
    report.record(
        "ABORT_TIMER_PARKED",
        run_async(&runtime, abort_timer_phase()),
    );
    sample(&mut report, "after_abort_timer_parked");
    report.record(
        "ABORT_BLIND_VALUE",
        run_async(&runtime, abort_blind_phase()),
    );
    sample(&mut report, "after_abort_blind_value");
    report.record("TIMER_WAKE", run_async(&runtime, timer_wake_phase()));
    sample(&mut report, "after_timer_wake");
    if reactor {
        report.record("UDP_LOOPBACK", run_async(&runtime, udp_phase()));
    } else {
        report.record(
            "UDP_LOOPBACK",
            Verdict::Unsupported("no_reactor_on_this_runtime".to_string()),
        );
    }
    sample(&mut report, "after_udp");
    blocking_phase(&mut report, &runtime);
    sample(&mut report, "after_blocking_pool");
    drain_phase(&mut report, &runtime);
    sample(&mut report, "after_drain");
    drop(runtime);
    sample(&mut report, "after_runtime_drop");
    report
}

// ---- host tests of the helpers (the runtime phases are exercised by running the program, not by these) ----------------------

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str =
        "Name:\tffw\nThreads:\t7\nVmPeak:\t  9000 kB\nVmHWM:\t  4321 kB\nVmRSS:\t  4000 kB\n";

    #[test]
    fn a_field_is_read_by_its_exact_key_and_its_number() {
        assert_eq!(field(STATUS, "Threads"), Some(7));
        assert_eq!(field(STATUS, "VmHWM"), Some(4321));
        assert_eq!(field(STATUS, "VmRSS"), Some(4000));
        assert_eq!(
            field("MemAvailable:   123456 kB\n", "MemAvailable"),
            Some(123_456)
        );
    }

    #[test]
    fn a_missing_key_a_longer_key_and_a_non_number_are_unknown_not_zero() {
        assert_eq!(field(STATUS, "VmSwap"), None);
        assert_eq!(field("VmRSSx:\t5 kB\n", "VmRSS"), None);
        assert_eq!(field("Threads:\tmany\n", "Threads"), None);
        assert_eq!(field("Threads:\n", "Threads"), None);
        assert_eq!(field("", "Threads"), None);
        assert_eq!(field("Threads:\t-3\n", "Threads"), None);
        assert_eq!(show(field("", "Threads")), "unknown");
        assert_eq!(show(Some(0_u64)), "0");
    }

    #[test]
    fn the_first_matching_row_wins_and_a_later_bad_row_does_not_hide_it() {
        assert_eq!(field("Threads:\t3\nThreads:\tbad\n", "Threads"), Some(3));
        assert_eq!(field("Threads:\tbad\nThreads:\t3\n", "Threads"), Some(3));
    }

    #[test]
    fn a_marker_line_names_its_operation_and_status() {
        let text = line("SPAWN_JOIN", "ok", "children=8");
        assert_eq!(text, "FFW_P05_RUNTIME:SPAWN_JOIN status=ok children=8");
    }

    /// The REAL phases under `cargo test`; nothing here is simulated. It needs what the program needs (a platform reactor, loopback
    /// UDP, a readable /proc) and must be run with `--test-threads=1`: another test thread starting or ending during a census sample
    /// would, rightly, make that sample `partial`. It asserts the exact phase list and counts and an exit code of 0, so a skipped,
    /// unsupported, partial or failed phase fails it.
    #[test]
    fn native_runtime_exercises_all_phases_and_drains() {
        const PHASES: [&str; 13] = [
            "PROFILE_ACCEPT",
            "PROFILE_REFUSES_ZERO_WORKERS",
            "PROFILE_REFUSES_UNBOUNDED_QUEUE",
            "PROFILE_REFUSES_OVER_BUDGET",
            "REACTOR",
            "RUNTIME_AUDIT",
            "SPAWN_JOIN",
            "ABORT_TIMER_PARKED",
            "ABORT_BLIND_VALUE",
            "TIMER_WAKE",
            "UDP_LOOPBACK",
            "BLOCKING_POOL",
            "DRAIN",
        ];
        let report = run_probe();
        let summary = report.end();
        let phases: Vec<&str> = report
            .names
            .iter()
            .map(String::as_str)
            .filter(|name| *name != "CENSUS")
            .collect();
        assert_eq!(phases, PHASES, "{summary}");
        assert_eq!(report.census_samples, 10, "{summary}");
        assert_eq!(report.ops, 23, "{summary}");
        let tally = (
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        );
        assert_eq!(tally, (23, 0, 0, 0, 0), "{summary}");
        assert_eq!(report.exit_code(), 0, "{summary}");
    }

    fn counts(report: &Report) -> (u32, u32, u32, u32, u32, u32) {
        (
            report.ops,
            report.ok,
            report.failed,
            report.unsupported,
            report.partial,
            report.unknown,
        )
    }

    #[test]
    fn the_counters_count_what_was_recorded_and_the_exit_code_never_hides_a_failure() {
        let mut report = Report::default();
        assert_eq!(report.exit_code(), 0);
        report.record("A", Verdict::Pass("x=1".to_string()));
        assert_eq!(counts(&report), (1, 1, 0, 0, 0, 0));
        assert_eq!(report.exit_code(), 0);
        report.record("B", Verdict::Unsupported("why".to_string()));
        assert_eq!(counts(&report), (2, 1, 0, 1, 0, 0));
        assert_eq!(report.exit_code(), 2);
        report.record("C", Verdict::Partial("some".to_string()));
        report.record("D", Verdict::Unknown("none".to_string()));
        assert_eq!(counts(&report), (4, 1, 0, 1, 1, 1));
        assert_eq!(report.exit_code(), 2);
        report.record("E", Verdict::Fail("y=2".to_string()));
        assert_eq!(counts(&report), (5, 1, 1, 1, 1, 1));
        assert_eq!(report.exit_code(), 1);
        let (ops, ok, failed, unsupported, partial, unknown) = counts(&report);
        assert_eq!(ops, ok + failed + unsupported + partial + unknown);
        let end = report.end();
        assert!(end.starts_with("FFW_P05_RUNTIME:END status=done "));
        assert!(
            end.contains("ops=5 ok=1 failed=1 unsupported=1 partial=1 unknown=1 census_samples=0")
        );
    }

    #[test]
    fn a_partial_or_unknown_result_is_never_counted_as_a_pass() {
        let mut report = Report::default();
        report.record("CENSUS", Verdict::Partial("p".to_string()));
        report.record("CENSUS", Verdict::Unknown("u".to_string()));
        assert_eq!((report.ok, report.partial, report.unknown), (0, 1, 1));
        assert_eq!(report.census_samples, 2);
        assert_eq!(report.exit_code(), 2);
    }

    fn reading() -> Census {
        Census {
            task_dir_before: Some(3),
            task_dir_after: Some(3),
            status_threads: Some(3),
            rss_kb: Some(4000),
            hwm_kb: Some(4321),
            mem_available_kb: Some(90_000),
        }
    }

    fn word(verdict: &Verdict) -> &'static str {
        match verdict {
            Verdict::Pass(_) => "pass",
            Verdict::Fail(_) => "fail",
            Verdict::Unsupported(_) => "unsupported",
            Verdict::Partial(_) => "partial",
            Verdict::Unknown(_) => "unknown",
        }
    }

    #[test]
    fn a_complete_stable_reading_is_the_only_census_that_passes() {
        assert_eq!(word(&judge_census("t", &reading())), "pass");
    }

    #[test]
    fn two_stable_thread_sources_that_disagree_fail_and_do_not_pass() {
        let disagree = Census {
            status_threads: Some(4),
            ..reading()
        };
        let verdict = judge_census("t", &disagree);
        assert_eq!(word(&verdict), "fail");
        let Verdict::Fail(text) = verdict else {
            panic!("a disagreement must be a failure");
        };
        assert!(text.contains("reason=thread_sources_disagree"));
        assert!(text.contains("sources_agree=false"));
    }

    #[test]
    fn a_thread_set_that_changed_during_the_reading_is_partial_not_a_disagreement_and_not_a_pass() {
        let changed = Census {
            task_dir_before: Some(3),
            task_dir_after: Some(4),
            status_threads: Some(4),
            ..reading()
        };
        assert_eq!(word(&judge_census("t", &changed)), "partial");
        assert_eq!(changed.stable_task_dir(), None);
    }

    #[test]
    fn one_missing_figure_is_partial_and_every_missing_figure_is_unknown_never_zero() {
        let no_status = Census {
            status_threads: None,
            ..reading()
        };
        let no_hwm = Census {
            hwm_kb: None,
            ..reading()
        };
        let no_meminfo = Census {
            mem_available_kb: None,
            ..reading()
        };
        let no_dir = Census {
            task_dir_before: None,
            task_dir_after: None,
            ..reading()
        };
        for census in [&no_status, &no_hwm, &no_meminfo, &no_dir] {
            assert_eq!(word(&judge_census("t", census)), "partial");
        }
        let nothing = Census {
            task_dir_before: None,
            task_dir_after: None,
            status_threads: None,
            rss_kb: None,
            hwm_kb: None,
            mem_available_kb: None,
        };
        let verdict = judge_census("t", &nothing);
        assert_eq!(word(&verdict), "unknown");
        let Verdict::Unknown(text) = verdict else {
            panic!("not unknown");
        };
        assert!(text.contains("threads_status=unknown"));
        assert!(text.contains("vm_rss_kb=unknown"));
        assert!(!text.contains("=0 "));
        assert_eq!(nothing.stable_task_dir(), None);
    }

    #[test]
    fn a_zero_thread_count_and_a_high_water_mark_below_the_resident_size_fail() {
        let zero_dir = Census {
            task_dir_before: Some(0),
            task_dir_after: Some(0),
            status_threads: None,
            ..reading()
        };
        let zero_status = Census {
            status_threads: Some(0),
            ..reading()
        };
        let low_water = Census {
            hwm_kb: Some(3999),
            ..reading()
        };
        for census in [&zero_dir, &zero_status, &low_water] {
            assert_eq!(word(&judge_census("t", census)), "fail");
        }
        let equal_water = Census {
            hwm_kb: Some(4000),
            ..reading()
        };
        assert_eq!(word(&judge_census("t", &equal_water)), "pass");
    }

    #[test]
    fn the_census_of_a_real_process_never_passes_on_a_disagreement_and_prints_unknown_for_what_it_cannot_read()
     {
        let c = census();
        if let (Some(dir), Some(status)) = (c.stable_task_dir(), c.status_threads) {
            assert!(dir >= 1);
            assert!(status >= 1);
        }
        let text = census_detail("test", &c);
        assert!(text.starts_with("phase=test threads_task_dir_before="));
        let unreadable = Census {
            task_dir_before: None,
            task_dir_after: None,
            status_threads: None,
            rss_kb: None,
            hwm_kb: None,
            mem_available_kb: None,
        };
        let unknown = census_detail("none", &unreadable);
        assert!(
            unknown
                .contains("task_dir_stable=unknown threads_status=unknown sources_agree=unknown")
        );
        assert!(unknown.contains("mem_available_kb=unknown"));
    }

    fn drained() -> RootDrainReport {
        RootDrainReport {
            outcome: RootDrainOutcome::Quiescent,
            elapsed: Duration::from_millis(5),
            live_tasks: 0,
            pending_obligations: 0,
            live_regions: 0,
            queued_finalizers: 0,
            pending_spawns: 0,
            has_pending_obligation_posts: false,
        }
    }

    #[test]
    fn only_a_quiescent_report_with_every_count_zero_is_a_successful_drain() {
        assert!(drain_succeeded(&drained()));
        let timed_out = RootDrainReport {
            outcome: RootDrainOutcome::TimedOut,
            ..drained()
        };
        assert!(
            !drain_succeeded(&timed_out),
            "zero counts do not make a timeout a success"
        );
        let planted = [
            RootDrainReport {
                live_tasks: 1,
                ..drained()
            },
            RootDrainReport {
                pending_obligations: 1,
                ..drained()
            },
            RootDrainReport {
                live_regions: 1,
                ..drained()
            },
            RootDrainReport {
                queued_finalizers: 1,
                ..drained()
            },
            RootDrainReport {
                pending_spawns: 1,
                ..drained()
            },
            RootDrainReport {
                has_pending_obligation_posts: true,
                ..drained()
            },
        ];
        for report in &planted {
            assert!(!drain_succeeded(report), "{}", drain_detail(report));
        }
        let text = drain_detail(&timed_out);
        assert!(text.contains("outcome=TimedOut expected_outcome=Quiescent"));
        assert!(text.contains("live_regions=0 expected_live_regions=0"));
    }

    #[test]
    fn a_drain_is_triggered_only_when_every_task_is_still_parked_on_a_live_timer() {
        let parked = ParkedSnapshot {
            admitted: 4,
            unfinished: 4,
            timers_pending: Some(4),
        };
        assert!(parked.all_parked(4));
        let more_timers = ParkedSnapshot {
            timers_pending: Some(6),
            ..parked
        };
        assert!(
            more_timers.all_parked(4),
            "other pending timers are allowed"
        );
        let finished_child = ParkedSnapshot {
            unfinished: 3,
            ..parked
        };
        let missing_timer = ParkedSnapshot {
            timers_pending: Some(3),
            ..parked
        };
        let unreadable_timer = ParkedSnapshot {
            timers_pending: None,
            ..parked
        };
        let short_admission = ParkedSnapshot {
            admitted: 3,
            unfinished: 3,
            ..parked
        };
        for planted in [
            finished_child,
            missing_timer,
            unreadable_timer,
            short_admission,
        ] {
            assert!(!planted.all_parked(4), "{}", planted.detail());
        }
        assert!(unreadable_timer.detail().contains("timers_pending=unknown"));
        assert_eq!(parked.detail(), "admitted=4 unfinished=4 timers_pending=4");
    }

    #[test]
    fn a_join_is_named_by_its_kind() {
        let ok: Result<(), JoinError> = Ok(());
        assert_eq!(join_kind(&ok), "Ok");
    }

    #[test]
    fn wait_until_gives_up_at_its_limit_and_returns_at_once_when_true() {
        let started = Instant::now();
        assert!(!wait_until(Duration::from_millis(30), || false));
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(wait_until(Duration::from_secs(5), || true));
    }

    #[test]
    fn a_gate_holds_a_waiter_until_it_is_released() {
        let gate = Arc::new(Gate::default());
        let done = Arc::new(AtomicBool::new(false));
        let (g, d) = (Arc::clone(&gate), Arc::clone(&done));
        let waiter = std::thread::spawn(move || {
            g.wait();
            d.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !done.load(Ordering::SeqCst),
            "the waiter passed a closed gate"
        );
        gate.release();
        assert!(wait_until(Duration::from_secs(5), || done.load(Ordering::SeqCst)));
        assert!(waiter.join().is_ok());
    }

    #[test]
    fn the_probe_profile_is_bounded_and_the_planted_defects_are_refused_by_name() {
        let good = profile().expect("the stated caps do not overflow");
        assert!(good.violations().is_empty());
        let budget = good.stack_budget_bytes();
        let no_workers = LegacyProfile::new(
            LegacyCaps {
                worker_threads: 0,
                ..good.caps()
            },
            budget,
        );
        assert!(no_workers.violations().contains(&CapViolation::NoWorkers));
        let over = LegacyProfile::new(good.caps(), budget - 1);
        assert!(
            over.violations()
                .iter()
                .any(|v| matches!(v, CapViolation::StackBudgetExceeded { .. }))
        );
        let unbounded = LegacyProfile::new(
            LegacyCaps {
                blocking_max_queued: 0,
                ..good.caps()
            },
            budget,
        );
        assert!(
            unbounded
                .violations()
                .contains(&CapViolation::BlockingQueueUnbounded)
        );
    }
}
