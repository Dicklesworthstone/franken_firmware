//! Restart and power-cut tests for the update state machine over the REAL journal (`franken_journal::Journal` on `MemStorage`) and an
//! in-memory staging medium. The reference model says what a recovery may return (exactly the state before or exactly the state after the
//! transition that was running); these tests cut the power at every storage operation of every transition, under several byte budgets and both
//! write orders, and require that.
//!
//! What they do not show: a particular flash part, the wear of the real medium, or a real staging area. The journal's own cut-point and
//! process-kill evidence is U01's (`tests/u01_*.rs`); this file adds the update layer's use of it.

mod common;

use common::{Eng, board, doc, fresh_engine, limits, restart, unhex};
use franken_journal::{Journal, MemStorage, Namespace, Op};
use franken_update::UpdateError;
use franken_update::engine::{
    Engine, KEY_FAILED, KEY_INSTALLED, KEY_UPDATE, MARK_FLOOR, MemStaging, Phase, Staging,
    TRIAL_BOOTS, Upd, pack_failed,
};
use franken_update::manifest::{FEATURES_ALL, Manifest};
use franken_update::policy::{self, Dynamic, Installed, Policy, TrustStore};
use serde_json::Value;

/// Everything the update layer persists, exactly: the update record (phase, candidate digest, checkpoint, boots), the installed image, the
/// failed candidate's digest and the floor. `Engine::persisted()` is a summary that leaves out the boot count, the candidate's digest and the
/// failed digest, so it cannot be the oracle of a crash test (see `u02_the_summary_is_blind_where_the_exact_state_is_not`).
type Exact = (Option<Upd>, Option<Installed>, Option<[u8; 32]>, u64);

fn exact(e: &Eng) -> Exact {
    (
        e.update().expect("a readable update record"),
        e.installed().expect("a readable installed record"),
        e.failed().expect("a readable failed record"),
        e.floor(),
    )
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Begin,
    Chunk(usize),
    WrongChunk(usize),
    Finish,
    Activate,
    Boot(bool),
    Abort,
}

const CHUNK: usize = 16;

fn chunks(wrong: bool) -> Vec<Step> {
    (0..10)
        .map(|i| {
            if wrong {
                Step::WrongChunk(i)
            } else {
                Step::Chunk(i)
            }
        })
        .collect()
}

fn apply(e: &mut Eng, d: &Value, step: Step) -> Result<(), UpdateError> {
    let assets = &d["engine_assets"];
    match step {
        Step::Begin => e
            .begin_stage(&unhex(&assets["manifests"]["m1"]))
            .map(|_| ()),
        Step::Chunk(i) | Step::WrongChunk(i) => {
            let name = if matches!(step, Step::WrongChunk(_)) {
                "wrong"
            } else {
                "a1"
            };
            let bytes = unhex(&assets["artifacts"][name]);
            e.write_chunk(&bytes[i * CHUNK..(i + 1) * CHUNK])
        }
        Step::Finish => e.finish_stage(),
        Step::Activate => e.activate(),
        Step::Boot(healthy) => e.report_boot(healthy).map(|_| ()),
        Step::Abort => e.abort(),
    }
}

fn spec(d: &Value) -> Value {
    d["engine"][0]["ctx"].clone()
}

/// Cut the power at every storage operation of every step, and require the recovered state to be exactly the one before or exactly the one
/// after the step. Returns how many cuts were made.
fn cut_every_step(name: &str, steps: &[Step]) -> usize {
    let d = doc();
    let spec = spec(&d);
    let mut cuts = 0;
    for (s, current) in steps.iter().enumerate() {
        let mut e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        for step in &steps[..s] {
            apply(&mut e, &d, *step)
                .unwrap_or_else(|err| panic!("{name}: prefix step {step:?}: {err}"));
        }
        let before = exact(&e);
        let first_op = e.journal().storage().ops_done();
        let _ = apply(&mut e, &d, *current);
        let after = exact(&e);
        let end_op = e.journal().storage().ops_done();
        for k in first_op..end_op {
            for budget in [0, 5, 60, 100_000] {
                for reverse in [false, true] {
                    let mut storage = MemStorage::new(limits().segment_bytes);
                    storage.cut_after_ops = Some(k);
                    storage.cut_budget = budget;
                    storage.cut_reverse = reverse;
                    let mut e = fresh_engine(&d, &spec, storage);
                    for step in &steps[..s] {
                        apply(&mut e, &d, *step)
                            .unwrap_or_else(|err| panic!("{name}: prefix step {step:?}: {err}"));
                    }
                    let hit = apply(&mut e, &d, *current);
                    assert!(
                        hit.is_err(),
                        "{name}: step {s} {:?} cut at operation {k} must fail",
                        current
                    );
                    let (journal, staging, policy) = e.into_parts();
                    let image = journal.storage().durable().to_vec();
                    let storage = MemStorage::from_image(limits().segment_bytes, &image);
                    let (journal, _) =
                        Journal::open(storage, limits()).expect("the cut image opens");
                    let resumed =
                        Engine::open(journal, staging, policy).expect("the engine resumes");
                    let got = exact(&resumed);
                    assert!(
                        got == before || got == after,
                        "{name}: step {s} {:?} cut at operation {k} (budget {budget}, reverse {reverse}): recovered {got:?}, which is neither {before:?} nor {after:?}",
                        current
                    );
                    if let Some(image) = &got.1 {
                        assert!(
                            u64::from(image.security_version) >= got.3,
                            "{name}: the floor {} is above the installed image's security version {}",
                            got.3,
                            image.security_version
                        );
                    }
                    cuts += 1;
                }
            }
        }
    }
    cuts
}

#[test]
fn u02_cut_every_step_of_a_successful_update_leaves_exactly_the_old_or_the_new_state() {
    let mut steps = vec![Step::Begin];
    steps.extend(chunks(false));
    steps.extend([Step::Finish, Step::Activate, Step::Boot(true)]);
    let cuts = cut_every_step("success", &steps);
    // six transitions write a frame (begin, two checkpoints, finish, activate, confirm) at two operations each, 4 budgets, 2 orders
    assert!(cuts >= 96, "{cuts} cuts were made");
}

#[test]
fn u02_cut_every_step_of_a_trial_that_fails_leaves_exactly_the_old_or_the_new_state() {
    let mut steps = vec![Step::Begin];
    steps.extend(chunks(false));
    steps.extend([
        Step::Finish,
        Step::Activate,
        Step::Boot(false),
        Step::Boot(false),
        Step::Boot(false),
    ]);
    let cuts = cut_every_step("rollback", &steps);
    assert!(cuts >= 128, "{cuts} cuts were made");
}

#[test]
fn u02_cut_every_step_of_a_wrong_artifact_and_of_an_abort_leaves_exactly_the_old_or_the_new_state()
{
    let mut wrong = vec![Step::Begin];
    wrong.extend(chunks(true));
    wrong.push(Step::Finish);
    let a = cut_every_step("wrong artifact", &wrong);
    let mut abort = vec![Step::Begin];
    abort.extend((0..5).map(Step::Chunk));
    abort.push(Step::Abort);
    let b = cut_every_step("abort", &abort);
    assert!(a >= 32 && b >= 32, "{a} and {b} cuts were made");
}

#[test]
fn u02_the_floor_and_the_installed_image_are_never_split_by_a_cut_in_the_confirm() {
    // The strongest statement of the previous tests for the one transition that matters: the image and the floor move together or not at all.
    let d = doc();
    let spec = spec(&d);
    let mut steps = vec![Step::Begin];
    steps.extend(chunks(false));
    steps.extend([Step::Finish, Step::Activate]);
    for k_offset in 0..2 {
        for budget in [0, 7, 40, 100_000] {
            let mut probe = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
            for step in &steps {
                apply(&mut probe, &d, *step).expect("the prefix");
            }
            let first_op = probe.journal().storage().ops_done();
            let mut storage = MemStorage::new(limits().segment_bytes);
            storage.cut_after_ops = Some(first_op + k_offset);
            storage.cut_budget = budget;
            let mut e = fresh_engine(&d, &spec, storage);
            for step in &steps {
                apply(&mut e, &d, *step).expect("the prefix");
            }
            assert!(apply(&mut e, &d, Step::Boot(true)).is_err());
            let mut e = restart(e);
            let got = e.persisted().expect("a readable state");
            let old = (Phase::Trial, Some(90), 4);
            let new = (Phase::Idle, Some(100), 5);
            assert!(
                (got.phase, got.installed, got.floor) == old
                    || (got.phase, got.installed, got.floor) == new,
                "cut at +{k_offset} with budget {budget}: {got:?}"
            );
            // and the recovered engine is usable: a trial that survived the cut can still be confirmed
            if got.phase == Phase::Trial {
                assert_eq!(e.report_boot(true).map(|o| o.label()), Ok("committed"));
                assert_eq!(e.persisted().expect("state").floor, 5);
            }
        }
    }
}

#[test]
fn u02_a_power_cut_at_any_unsynced_byte_resumes_at_the_checkpoint_and_the_artifact_completes() {
    let d = doc();
    let spec = spec(&d);
    for keep in [0usize, 1, 17, 47, 48, 1000] {
        let mut e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        apply(&mut e, &d, Step::Begin).expect("begin");
        for i in 0..7 {
            apply(&mut e, &d, Step::Chunk(i)).expect("chunk");
        }
        // seven chunks written (112 bytes); the checkpoint 64 is persisted, the 48 bytes after it are not
        assert_eq!(e.persisted().expect("state").checkpoint, 64);
        e.staging_mut().power_cut(keep);
        let mut e = restart(e);
        assert_eq!(e.snapshot().expect("state").next, 64, "keep {keep}");
        assert_eq!(
            e.staging().staged_len(),
            64,
            "what is beyond the checkpoint is discarded (keep {keep})"
        );
        for i in 4..10 {
            apply(&mut e, &d, Step::Chunk(i)).expect("the resent chunk");
        }
        apply(&mut e, &d, Step::Finish).unwrap_or_else(|err| panic!("keep {keep}: finish: {err}"));
        apply(&mut e, &d, Step::Activate).expect("activate");
        assert_eq!(e.phase(), Ok(Phase::Trial));
    }
}

#[test]
fn u02_bit_rot_anywhere_in_the_staged_bytes_is_caught_at_activation() {
    let d = doc();
    let spec = spec(&d);
    for (at, bit) in [(0usize, 0u8), (79, 3), (159, 7)] {
        let mut e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        apply(&mut e, &d, Step::Begin).expect("begin");
        for i in 0..10 {
            apply(&mut e, &d, Step::Chunk(i)).expect("chunk");
        }
        apply(&mut e, &d, Step::Finish).expect("finish");
        e.staging_mut().corrupt(at, bit);
        assert_eq!(
            apply(&mut e, &d, Step::Activate),
            Err(UpdateError::ArtifactDigestMismatch),
            "byte {at}"
        );
        assert_eq!(e.phase(), Ok(Phase::Idle));
        assert_eq!(
            e.persisted().expect("state").installed,
            Some(90),
            "the installed image is untouched"
        );
        // and the control: the same sequence without the rot activates
        let mut ok = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        apply(&mut ok, &d, Step::Begin).expect("begin");
        for i in 0..10 {
            apply(&mut ok, &d, Step::Chunk(i)).expect("chunk");
        }
        apply(&mut ok, &d, Step::Finish).expect("finish");
        assert_eq!(apply(&mut ok, &d, Step::Activate), Ok(()));
    }
}

#[test]
fn u02_a_stage_is_resumed_only_if_its_signing_key_is_still_trusted() {
    let d = doc();
    let spec = spec(&d);
    let key = |name: &str| common::arr32(&d["keys"][name]["public"]);
    for (label, trust, resumes) in [
        (
            "key A still trusted",
            vec![(key("A"), false), (key("B"), false)],
            true,
        ),
        (
            "key A revoked since",
            vec![(key("A"), true), (key("B"), false)],
            false,
        ),
        (
            "key A no longer in the store",
            vec![(key("B"), false)],
            false,
        ),
    ] {
        let mut e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        apply(&mut e, &d, Step::Begin).expect("begin");
        apply(&mut e, &d, Step::Chunk(0)).expect("chunk");
        let (journal, staging, mut policy) = e.into_parts();
        policy.trust = TrustStore::new(&trust).expect("an admissible trust store");
        let e = Engine::open(journal, staging, policy).expect("open");
        let want = if resumes { Phase::Staging } else { Phase::Idle };
        assert_eq!(e.phase(), Ok(want), "{label}");
        assert_eq!(
            e.persisted().expect("state").installed,
            Some(90),
            "{label}: the installed image is untouched"
        );
        assert_eq!(e.floor(), 4, "{label}");
    }
}

#[test]
fn u02_a_manifest_copy_that_no_longer_matches_the_journal_is_not_resumed() {
    let d = doc();
    let spec = spec(&d);
    let mut e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
    apply(&mut e, &d, Step::Begin).expect("begin");
    apply(&mut e, &d, Step::Chunk(0)).expect("chunk");
    e.staging_mut().tamper_manifest(20);
    let e = restart(e);
    assert_eq!(e.phase(), Ok(Phase::Idle));
    // the control: an untouched copy resumes
    let mut ok = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
    apply(&mut ok, &d, Step::Begin).expect("begin");
    apply(&mut ok, &d, Step::Chunk(0)).expect("chunk");
    assert_eq!(restart(ok).phase(), Ok(Phase::Staging));
}

#[test]
fn u02_a_journal_that_failed_refuses_every_transition_until_it_is_reopened() {
    let d = doc();
    let spec = spec(&d);
    let first_op = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes))
        .journal()
        .storage()
        .ops_done();
    let mut storage = MemStorage::new(limits().segment_bytes);
    storage.cut_after_ops = Some(first_op);
    let mut e = fresh_engine(&d, &spec, storage);
    assert!(matches!(
        apply(&mut e, &d, Step::Begin),
        Err(UpdateError::Journal(_))
    ));
    assert_eq!(
        apply(&mut e, &d, Step::Begin),
        Err(UpdateError::Journal("poisoned"))
    );
    // reopened, the same engine admits the same candidate: the failed begin left nothing behind
    let mut e = restart(e);
    assert_eq!(e.phase(), Ok(Phase::Idle));
    assert_eq!(apply(&mut e, &d, Step::Begin), Ok(()));
}

#[test]
fn u02_records_this_code_cannot_read_are_corrupt_state_and_never_guessed_at() {
    let d = doc();
    let spec = spec(&d);
    for key in [KEY_UPDATE, KEY_INSTALLED, KEY_FAILED] {
        let e = fresh_engine(&d, &spec, MemStorage::new(limits().segment_bytes));
        let (mut journal, staging, policy) = e.into_parts();
        journal
            .commit(&[Op::Put {
                ns: Namespace::Records,
                key: key.to_vec(),
                value: vec![9, 9, 9],
            }])
            .expect("a record of any shape can be stored");
        let outcome = Engine::open(journal, staging, policy).and_then(|mut e| {
            e.begin_stage(&unhex(&d["engine_assets"]["manifests"]["m1"]))
                .map(|_| ())
        });
        assert_eq!(
            outcome,
            Err(UpdateError::CorruptState),
            "{}",
            String::from_utf8_lossy(key)
        );
    }
}

#[test]
fn u02_a_gap_in_the_staging_medium_is_refused_and_writes_nothing() {
    let mut staging = MemStaging::new(1 << 10);
    assert_eq!(staging.write(5, &[1, 2, 3]), Err(UpdateError::StagingGap));
    assert_eq!(staging.staged_len(), 0);
    assert_eq!(staging.write(0, &[1, 2, 3]), Ok(()));
    assert_eq!(staging.write(4, &[9]), Err(UpdateError::StagingGap));
    assert_eq!(staging.write(3, &[4]), Ok(()));
    assert_eq!(
        staging.write((1 << 10) - 1, &[1, 2]),
        Err(UpdateError::StagingGap)
    );
}

// ---- a restart is an admission under the policy of the day

/// Where the update is when the power goes: the four durable in-progress states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// Five chunks written: the checkpoint at 64 is persisted, 16 bytes beyond it are not.
    Staging,
    Staged,
    Trial,
    /// A trial with one unhealthy boot already spent (two left).
    TrialOneSpent,
}

const STARTS: [Start; 4] = [
    Start::Staging,
    Start::Staged,
    Start::Trial,
    Start::TrialOneSpent,
];

impl Start {
    fn phase(self) -> Phase {
        match self {
            Self::Staging => Phase::Staging,
            Self::Staged => Phase::Staged,
            Self::Trial | Self::TrialOneSpent => Phase::Trial,
        }
    }
}

fn reopen_under(e: Eng, change: &dyn Fn(&mut Policy)) -> Eng {
    let (journal, staging, mut policy) = e.into_parts();
    let image = journal.storage().durable().to_vec();
    let storage = MemStorage::from_image(limits().segment_bytes, &image);
    let (journal, _) = Journal::open(storage, limits()).expect("the durable image opens");
    change(&mut policy);
    Engine::open(journal, staging, policy).expect("the engine reopens")
}

/// An engine with `manifest` driven to `start` under the first engine script's context with `tweak` laid over it.
fn engine_at(d: &Value, manifest: &str, tweak: &[(&str, Value)], start: Start) -> Eng {
    let mut ctx = spec(d);
    for (key, value) in tweak {
        ctx[*key] = value.clone();
    }
    let mut e = fresh_engine(d, &ctx, MemStorage::new(limits().segment_bytes));
    e.begin_stage(&unhex(&d["engine_assets"]["manifests"][manifest]))
        .expect("the manifest is admitted under the original policy");
    let chunks = if start == Start::Staging { 5 } else { 10 };
    for i in 0..chunks {
        apply(&mut e, d, Step::Chunk(i)).expect("chunk");
    }
    match start {
        Start::Staging => {}
        Start::Staged => e.finish_stage().expect("finish"),
        Start::Trial | Start::TrialOneSpent => {
            e.finish_stage().expect("finish");
            e.activate().expect("activate");
            if start == Start::TrialOneSpent {
                assert_eq!(e.report_boot(false).map(|o| o.label()), Ok("retry"));
            }
        }
    }
    assert_eq!(e.phase(), Ok(start.phase()), "{start:?}");
    e
}

fn staged_engine(d: &Value, manifest: &str, tweak: &[(&str, Value)]) -> Eng {
    engine_at(d, manifest, tweak, Start::Staged)
}

/// The update record of `start` is what the case says it is: the candidate's digest, and the checkpoint or the boots that make the state worth
/// restarting from.
fn assert_shape(got: &Exact, start: Start, candidate: &Manifest, label: &str) {
    let update = got.0.expect("an update in progress");
    assert_eq!(
        (update.phase, update.sha),
        (start.phase(), candidate.sha256),
        "{label}"
    );
    match start {
        Start::Staging => assert_eq!(update.staged, 64, "{label}: the persisted checkpoint"),
        Start::Staged => {}
        Start::Trial => assert_eq!(update.boots, TRIAL_BOOTS, "{label}"),
        Start::TrialOneSpent => assert_eq!(update.boots, TRIAL_BOOTS - 1, "{label}"),
    }
}

/// After a dropped update: idle, the installed image, the failed record and the floor exactly as `want` says (the update record gone), neither
/// activation nor a boot report does anything, and the drop is DURABLE: the same tuple comes back from the durable bytes once under the
/// policy that dropped it and once under the policy that had admitted the stage.
fn assert_dropped(mut e: Eng, want: &Exact, original: &Policy, label: &str) {
    assert_eq!(e.phase(), Ok(Phase::Idle), "{label}");
    assert_eq!(e.update(), Ok(None), "{label}");
    let after = exact(&e);
    assert_eq!(
        (after.1, after.2, after.3),
        (want.1.clone(), want.2, want.3),
        "{label}: the installed image, the failed record and the floor are as they were, and the candidate was not recorded as failed"
    );
    assert_eq!(e.activate(), Err(UpdateError::NotStaged), "{label}");
    assert_eq!(
        e.report_boot(true).map(|o| o.label()),
        Err(UpdateError::NotInTrial),
        "{label}"
    );
    let dropped = exact(&e);
    let e = reopen_under(e, &|_| {});
    assert_eq!(
        exact(&e),
        dropped,
        "{label}: the drop survives a restart under the policy that made it"
    );
    let e = reopen_under(e, &|p: &mut Policy| *p = original.clone());
    assert_eq!(
        exact(&e),
        dropped,
        "{label}: and under the original policy nothing is resurrected"
    );
}

struct Case {
    label: &'static str,
    manifest: &'static str,
    /// What the stage was admitted under, laid over the first engine script's context.
    tweak: Vec<(&'static str, Value)>,
    /// What changes before the restart.
    change: Box<dyn Fn(&mut Policy)>,
    /// The rule of current admission that refuses the stage afterwards.
    refusal: UpdateError,
}

fn cases(d: &Value) -> Vec<Case> {
    let mips = board(d, "mips");
    let other_evidence = [0x5Au8; 32];
    let production_ctx = d["engine"]
        .as_array()
        .expect("engine scripts")
        .iter()
        .find(|s| common::text(s, "id") == "U02-ENG-026")
        .expect("the production-evidence script")["ctx"]
        .clone();
    vec![
        Case {
            label: "the board is another profile in every field",
            manifest: "m1",
            tweak: vec![],
            change: Box::new(move |p: &mut Policy| p.board = mips.clone()),
            refusal: UpdateError::WrongBoard,
        },
        Case {
            label: "only the board's profile id differs",
            manifest: "m1",
            tweak: vec![],
            change: Box::new(|p: &mut Policy| p.board.profile_id = "another-profile".to_string()),
            refusal: UpdateError::WrongBoard,
        },
        Case {
            label: "production is turned on over a synthetic fixture board",
            manifest: "m1",
            tweak: vec![],
            change: Box::new(|p: &mut Policy| p.production = true),
            refusal: UpdateError::ProfileNotAttested,
        },
        Case {
            label: "a feature the stage lacks is now required",
            manifest: "mdrop",
            tweak: vec![("required", Value::from(0))],
            change: Box::new(|p: &mut Policy| p.required = FEATURES_ALL),
            refusal: UpdateError::RequiredFeatureMissing,
        },
        Case {
            label: "consent to a downgrade is withdrawn",
            manifest: "low",
            tweak: vec![("allow_downgrade", Value::from(true))],
            change: Box::new(|p: &mut Policy| p.allow_downgrade = false),
            refusal: UpdateError::DowngradeNotPermitted,
        },
        Case {
            label: "the staging capacity no longer holds the artifact and its reserve",
            manifest: "m1",
            tweak: vec![],
            change: Box::new(|p: &mut Policy| p.staging_bytes = 1000),
            refusal: UpdateError::InsufficientCapacity,
        },
        Case {
            label: "the production evidence is another board's",
            manifest: "mev",
            tweak: vec![
                ("production", production_ctx["production"].clone()),
                ("board", production_ctx["board"].clone()),
                ("evidence", production_ctx["evidence"].clone()),
            ],
            change: Box::new(move |p: &mut Policy| p.evidence = Some(other_evidence)),
            refusal: UpdateError::EvidenceMismatch,
        },
        Case {
            label: "production is turned on with an all-zero evidence digest over an image that names none",
            manifest: "m1",
            tweak: vec![("board", Value::from("ppc_policy_standin"))],
            change: Box::new(|p: &mut Policy| {
                p.production = true;
                p.evidence = Some([0u8; 32]);
            }),
            refusal: UpdateError::EvidenceMismatch,
        },
        Case {
            label: "there is no A/B receipt and no recovery path any more",
            manifest: "m1",
            tweak: vec![],
            change: Box::new(|p: &mut Policy| p.recovery_path = false),
            refusal: UpdateError::NoRecoveryPath,
        },
    ]
}

#[test]
fn u02_a_restart_under_the_unchanged_policy_resumes_every_phase_and_the_update_still_completes() {
    let d = doc();
    let raw = unhex(&d["engine_assets"]["manifests"]["m1"]);
    let candidate = Manifest::parse(&raw).expect("m1 parses");
    for start in STARTS {
        let e = engine_at(&d, "m1", &[], start);
        let before = exact(&e);
        assert_shape(&before, start, &candidate, &format!("{start:?}"));
        let mut e = reopen_under(e, &|_| {});
        assert_eq!(
            exact(&e),
            before,
            "{start:?}: an unchanged policy resumes the update bit for bit"
        );
        match start {
            Start::Staging => {
                assert_eq!(e.snapshot().expect("state").next, 64);
                assert_eq!(
                    e.staging().staged_len(),
                    64,
                    "what is past the checkpoint is discarded"
                );
                for i in 4..10 {
                    apply(&mut e, &d, Step::Chunk(i)).expect("the resent chunk");
                }
                e.finish_stage().expect("finish");
                e.activate().expect("activate");
            }
            Start::Staged => e.activate().expect("activate"),
            Start::Trial | Start::TrialOneSpent => {}
        }
        assert_eq!(
            e.report_boot(true).map(|o| o.label()),
            Ok("committed"),
            "{start:?}"
        );
        assert_eq!(e.floor(), 5, "{start:?}");
        assert_eq!(e.installed().expect("state").map(|i| i.version), Some(100));
    }
}

#[test]
fn u02_a_changed_policy_drops_the_update_in_every_phase_and_the_unchanged_one_resumes_it() {
    let d = doc();
    for case in cases(&d) {
        let raw = unhex(&d["engine_assets"]["manifests"][case.manifest]);
        let candidate = Manifest::parse(&raw).expect("the case's manifest parses");
        for start in STARTS {
            let label = format!("{} / {start:?}", case.label);
            // the control first: with nothing changed the very same update resumes, bit for bit
            let control = engine_at(&d, case.manifest, &case.tweak, start);
            let control_before = exact(&control);
            assert_shape(&control_before, start, &candidate, &label);
            let resumed = reopen_under(control, &|_| {});
            assert_eq!(exact(&resumed), control_before, "{label}: control");
            // and the negative
            let e = engine_at(&d, case.manifest, &case.tweak, start);
            let before = exact(&e);
            let original = e.policy().clone();
            let mut changed = original.clone();
            (case.change)(&mut changed);
            let state = Dynamic {
                installed: before.1.clone(),
                floor: before.3,
                failed: before.2,
            };
            // the drop is attributed to CURRENT ADMISSION: the signature still verifies, the original policy still admits, the changed one refuses
            assert_eq!(
                policy::verify_signature(&changed, &candidate),
                Ok(()),
                "{label}: a signature-only open would resume this stage"
            );
            assert!(
                policy::admit(&original, &state, &raw).is_ok(),
                "{label}: the original policy admits it"
            );
            assert_eq!(
                policy::admit(&changed, &state, &raw).err(),
                Some(case.refusal),
                "{label}"
            );
            let dropped = reopen_under(e, case.change.as_ref());
            let want = (None, before.1.clone(), before.2, before.3);
            assert_dropped(dropped, &want, &original, &label);
        }
    }
}

#[test]
fn u02_a_floor_raised_above_the_candidate_drops_the_update_and_a_lower_one_does_not() {
    let d = doc();
    let raw = unhex(&d["engine_assets"]["manifests"]["m1"]);
    let candidate = Manifest::parse(&raw).expect("m1 parses");
    for start in STARTS {
        for (floor, resumes) in [(4u64, true), (5, true), (6, false)] {
            let label = format!("floor {floor} / {start:?}");
            let e = engine_at(&d, "m1", &[], start);
            let pre = exact(&e);
            let (mut journal, staging, policy) = e.into_parts();
            if floor > pre.3 {
                journal
                    .commit(&[Op::Raise {
                        key: MARK_FLOOR.to_vec(),
                        value: floor,
                    }])
                    .expect("the floor is raised");
            }
            let want_floor = pre.3.max(floor);
            let original = policy.clone();
            let state = Dynamic {
                installed: pre.1.clone(),
                floor: want_floor,
                failed: pre.2,
            };
            let admitted = policy::admit(&original, &state, &raw);
            assert_eq!(
                admitted.err(),
                (!resumes).then_some(UpdateError::BelowSecurityFloor),
                "{label}"
            );
            let e = Engine::open(journal, staging, policy).expect("open");
            if resumes {
                let got = exact(&e);
                assert_eq!(got.0, pre.0, "{label}: the update is resumed untouched");
                assert_eq!(got.3, want_floor, "{label}");
                assert_shape(&got, start, &candidate, &label);
            } else {
                // never a silent confirm and never a lower floor: the candidate is not installed and the raised floor stays
                let want = (None, pre.1.clone(), pre.2, want_floor);
                assert_dropped(e, &want, &original, &label);
            }
        }
    }
}

#[test]
fn u02_the_boots_left_survive_a_restart_between_two_unhealthy_reports_and_the_trial_rolls_back() {
    let d = doc();
    let raw = unhex(&d["engine_assets"]["manifests"]["m1"]);
    let candidate = Manifest::parse(&raw).expect("m1 parses");
    let e = engine_at(&d, "m1", &[], Start::TrialOneSpent);
    let spent = exact(&e);
    assert_eq!(spent.0.map(|u| u.boots), Some(TRIAL_BOOTS - 1));
    let mut e = reopen_under(e, &|_| {});
    assert_eq!(
        exact(&e),
        spent,
        "an unchanged policy resumes a trial with its boot count"
    );
    assert_eq!(e.report_boot(false).map(|o| o.label()), Ok("retry"));
    assert_eq!(exact(&e).0.map(|u| u.boots), Some(TRIAL_BOOTS - 2));
    let mut e = reopen_under(e, &|_| {});
    assert_eq!(
        exact(&e).0.map(|u| u.boots),
        Some(TRIAL_BOOTS - 2),
        "the boots left survive the restart between the two reports"
    );
    assert_eq!(e.report_boot(false).map(|o| o.label()), Ok("rolled_back"));
    let end = exact(&e);
    assert_eq!(
        (end.0, end.1, end.2, end.3),
        (None, spent.1.clone(), Some(candidate.sha256), spent.3),
        "rolled back: the installed image and the floor are untouched and the candidate is remembered as failed"
    );
    // and the failed candidate is not admitted again, even by a restarted engine
    let e = reopen_under(e, &|_| {});
    let state = Dynamic {
        installed: spent.1,
        floor: spent.3,
        failed: Some(candidate.sha256),
    };
    assert_eq!(
        policy::admit(e.policy(), &state, &raw).err(),
        Some(UpdateError::CandidatePreviouslyFailed)
    );
}

#[test]
fn u02_the_summary_is_blind_where_the_exact_state_is_not() {
    // Control for the oracle itself: two states that `persisted()` cannot tell apart and `exact` can. A crash test that compared the summary
    // would pass a recovery that lost a boot count or the digest of the failed candidate.
    let d = doc();
    let mut e = staged_engine(&d, "m1", &[]);
    e.activate().expect("activate");
    let (summary, whole) = (e.persisted().expect("state"), exact(&e));
    assert_eq!(e.report_boot(false).map(|o| o.label()), Ok("retry"));
    assert_eq!(
        e.persisted().expect("state"),
        summary,
        "the summary did not move"
    );
    assert_ne!(exact(&e), whole, "the boot count did");

    let idle = fresh_engine(&d, &spec(&d), MemStorage::new(limits().segment_bytes));
    let (summary, whole) = (idle.persisted().expect("state"), exact(&idle));
    let (mut journal, staging, policy) = idle.into_parts();
    journal
        .commit(&[Op::Put {
            ns: Namespace::Records,
            key: KEY_FAILED.to_vec(),
            value: pack_failed([0x77; 32]),
        }])
        .expect("a failed digest");
    let idle = Engine::open(journal, staging, policy).expect("open");
    assert_eq!(
        idle.persisted().expect("state"),
        summary,
        "the summary did not move"
    );
    assert_ne!(exact(&idle), whole, "the failed digest did");
}
