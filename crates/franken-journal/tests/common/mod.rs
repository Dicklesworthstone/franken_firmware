//! Shared test support: the scripted steps of the shared vectors, hex helpers, a script runner and the cut-point oracle.
//! The oracle is the same experiment as `tests/u01/reference.py::enumerate_cuts`, so the digests must agree.

#![allow(dead_code)]

use franken_journal::{
    Commit, Journal, JournalError, Limits, MemStorage, Namespace, Op, Storage, StorageFault,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

pub fn ns(raw: u64) -> Namespace {
    Namespace::from_u8(u8::try_from(raw).expect("namespace id")).expect("known namespace")
}

#[derive(Debug, Clone)]
pub enum Step {
    Put(Namespace, Vec<u8>, Vec<u8>),
    Delete(Namespace, Vec<u8>),
    ResetSettings,
    ClearCalibration,
    Install(Vec<u8>, u64, Vec<u8>),
    Revoke(Vec<u8>),
    ResetPairing,
    RaiseMark(Vec<u8>, u64),
    Stage(Vec<u8>, Vec<u8>),
    Flush(u64),
    /// One transaction of several operations, possibly in several namespaces, committed as a single frame.
    Commit(Vec<Op>),
}

/// One operation inside a `commit` step, spelled with the reference's operation tags.
pub fn parse_op(doc: &Value) -> Op {
    let args = doc["args"].as_array().expect("args");
    let bytes = |i: usize| unhex(args[i].as_str().expect("hex argument"));
    let int = |i: usize| args[i].as_u64().expect("integer argument");
    match doc["op"].as_str().expect("op") {
        "put" => Op::Put {
            ns: ns(int(0)),
            key: bytes(1),
            value: bytes(2),
        },
        "delete" => Op::Delete {
            ns: ns(int(0)),
            key: bytes(1),
        },
        "reset" => Op::Reset { ns: ns(int(0)) },
        "install" => Op::Install {
            id: bytes(0),
            version: int(1),
            secret: bytes(2),
        },
        "revoke" => Op::Revoke { id: bytes(0) },
        "reset_pairing" => Op::ResetPairing,
        "raise" => Op::Raise {
            key: bytes(0),
            value: int(1),
        },
        other => panic!("unknown operation {other}"),
    }
}

pub fn parse_step(doc: &Value) -> Step {
    let args = doc["args"].as_array().expect("args");
    let bytes = |i: usize| unhex(args[i].as_str().expect("hex argument"));
    let int = |i: usize| args[i].as_u64().expect("integer argument");
    match doc["op"].as_str().expect("op") {
        "put" => Step::Put(ns(int(0)), bytes(1), bytes(2)),
        "delete" => Step::Delete(ns(int(0)), bytes(1)),
        "reset_settings" => Step::ResetSettings,
        "clear_calibration" => Step::ClearCalibration,
        "install" => Step::Install(bytes(0), int(1), bytes(2)),
        "revoke" => Step::Revoke(bytes(0)),
        "reset_pairing" => Step::ResetPairing,
        "raise_mark" => Step::RaiseMark(bytes(0), int(1)),
        "stage_setting" => Step::Stage(bytes(0), bytes(1)),
        "flush_settings" => Step::Flush(int(0)),
        "commit" => Step::Commit(
            args[0]
                .as_array()
                .expect("operations")
                .iter()
                .map(parse_op)
                .collect(),
        ),
        other => panic!("unknown step {other}"),
    }
}

pub fn parse_steps(doc: &Value) -> Vec<Step> {
    doc.as_array()
        .expect("steps")
        .iter()
        .map(parse_step)
        .collect()
}

/// The outcome of one step, spelled as the reference spells it: `ok` for a staging call, `noop`/`appended`/`compacted`
/// for a commit, `error:<code>` for a rejection.
pub fn apply<S: Storage>(journal: &mut Journal<S>, step: &Step) -> Result<String, JournalError> {
    let commit = |outcome: Result<Commit, JournalError>| {
        outcome.map(|c| match c {
            Commit::Noop => "noop".to_string(),
            Commit::Appended => "appended".to_string(),
            Commit::Compacted => "compacted".to_string(),
        })
    };
    match step {
        Step::Put(n, k, v) => commit(journal.put(*n, k, v)),
        Step::Delete(n, k) => commit(journal.delete(*n, k)),
        Step::ResetSettings => commit(journal.reset_settings()),
        Step::ClearCalibration => commit(journal.clear_calibration()),
        Step::Install(id, version, secret) => commit(journal.install(id, *version, secret)),
        Step::Revoke(id) => commit(journal.revoke(id)),
        Step::ResetPairing => commit(journal.reset_pairing()),
        Step::RaiseMark(k, v) => commit(journal.raise_mark(k, *v)),
        Step::Stage(k, v) => journal.stage_setting(k, v).map(|()| "ok".to_string()),
        Step::Flush(now) => commit(journal.flush_settings(*now)),
        Step::Commit(ops) => commit(journal.commit(ops)),
    }
}

pub fn state_hex<S: Storage>(journal: &Journal<S>) -> String {
    hex(journal.state().canonical_bytes().expect("canonical state"))
}

/// A storage fault (the power went) stops a script; any other error is a rejected step and the script goes on.
fn fatal(err: &JournalError) -> bool {
    matches!(err, JournalError::Storage(_) | JournalError::Poisoned)
}

pub struct Run {
    pub outcomes: Vec<String>,
    pub states: Vec<String>,
    /// `ranges[i]` is the storage-operation range that produced `states[i]`; `ranges[0]` is the format.
    pub ranges: Vec<(usize, usize)>,
    pub frames_written: u64,
    pub compactions: u64,
    pub bytes_programmed: u64,
}

/// Format (open) and run `steps` against `storage`. Stops at the first storage fault.
pub fn run_script(
    lim: &Limits,
    steps: &[Step],
    storage: &mut MemStorage,
) -> Result<Run, JournalError> {
    let (mut journal, _recovery) = Journal::open(&mut *storage, lim.clone())?;
    let mut run = Run {
        outcomes: Vec::new(),
        states: vec![state_hex(&journal)],
        ranges: vec![(0, journal.storage().ops_done())],
        frames_written: 0,
        compactions: 0,
        bytes_programmed: 0,
    };
    for step in steps {
        let start = journal.storage().ops_done();
        match apply(&mut journal, step) {
            Ok(outcome) => run.outcomes.push(outcome),
            Err(err) if fatal(&err) => return Err(err),
            Err(err) => run.outcomes.push(format!("error:{}", err.code())),
        }
        run.states.push(state_hex(&journal));
        run.ranges.push((start, journal.storage().ops_done()));
    }
    run.frames_written = journal.frames_written();
    run.compactions = journal.compactions();
    run.bytes_programmed = journal.bytes_programmed();
    Ok(run)
}

pub struct Cuts {
    pub cuts: usize,
    pub old: usize,
    pub new: usize,
    pub total_ops: usize,
    pub digest: String,
}

/// Cut the power at every storage-operation boundary and every byte budget of the unsynced writes, restart, reopen, and
/// require the recovered state to be exactly the state before or after the step that was running; if the step had
/// finished, exactly the state after it; a torn format recovers as the empty journal.
pub fn enumerate_cuts(lim: &Limits, steps: &[Step], reverse: bool) -> Cuts {
    let mut baseline = MemStorage::new(lim.segment_bytes);
    let base = run_script(lim, steps, &mut baseline).expect("the uncut script runs");
    let total_ops = baseline.ops_done();
    let mut pending_before: Vec<usize> = baseline.pending_before().to_vec();
    pending_before.push(0);
    // One entry per storage operation of the uncut run, plus the final boundary where nothing is pending any more.
    assert_eq!(
        pending_before.len(),
        total_ops + 1,
        "one pending-bytes entry per storage operation"
    );
    let mut digests = Sha256::new();
    let (mut cuts, mut old, mut new) = (0, 0, 0);
    for (n, &budgets) in pending_before.iter().enumerate() {
        let idx = base.ranges.iter().position(|&(a, b)| a <= n && n < b);
        for k in 0..=budgets {
            let mut media = MemStorage::new(lim.segment_bytes);
            media.cut_after_ops = Some(n);
            media.cut_budget = k;
            media.cut_reverse = reverse;
            let _ = run_script(lim, steps, &mut media);
            if !media.is_dead() {
                media.power_cut(0, reverse);
            }
            digests.update(Sha256::digest(media.durable()));
            media.restart();
            let (reopened, _rec) =
                Journal::open(&mut media, lim.clone()).expect("a cut medium reopens");
            let got = state_hex(&reopened);
            let ok = match idx {
                None => got == base.states[base.states.len() - 1],
                Some(0) => got == base.states[0],
                Some(i) if n == base.ranges[i].0 && k == 0 => got == base.states[i - 1],
                Some(i) => got == base.states[i - 1] || got == base.states[i],
            };
            assert!(
                ok,
                "cut n={n} k={k} reverse={reverse}: recovered state is neither old nor new (step {idx:?})"
            );
            cuts += 1;
            match idx {
                Some(i)
                    if i > 0 && got == base.states[i] && base.states[i - 1] != base.states[i] =>
                {
                    new += 1
                }
                _ => old += 1,
            }
        }
    }
    Cuts {
        cuts,
        old,
        new,
        total_ops,
        digest: hex(digests.finalize()),
    }
}

pub fn fault_name(fault: StorageFault) -> &'static str {
    fault.code()
}
