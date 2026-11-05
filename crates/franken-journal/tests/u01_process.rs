//! Real-process proof for the U01 journal, run by plain `cargo test -p franken-journal` (the central path).
//!
//! The subject is the shipped example `journal_crash`: a file-backed `Storage` over the real `Journal` API. This test runs
//! it as a child process, kills it in the middle of a write, and has a FRESH process reopen the file image. It adds no
//! storage double and no second driver: the expectations are the shared vectors' (`u01_vectors.json`), which the Python
//! reference produced and the in-memory Rust tests already check.
//!
//! What it shows, on a real file and across real process boundaries:
//!   1. a clean run commits every step, leaves a file whose SHA-256 equals the reference's final medium, and a fresh
//!      process recovers exactly the final state; a second restart changes nothing;
//!   2. a process that dies (`abort`, no unwinding, no flush) at a sampled byte of the write or erase that crosses it
//!      recovers exactly the state before or exactly the state after the step that was running, never an acknowledged
//!      step lost and never a step more than one ahead;
//!   3. the same under `SIGKILL` at arbitrary moments after an acknowledged step;
//!   4. every committed hostile image (torn tails, flipped bits, replays, two segments, a newer schema, a legacy schema)
//!      recovers in a real process to the reference's state and source and leaves the reference's bytes behind.
//!
//! What it does not show: a power cut (a process kill keeps the bytes already handed to the OS, synced or not, which is the
//! prefix-of-unsynced-writes experiment; the cut-point oracle covers the rest), flash behaviour, wear, or timing. Nothing
//! here says anything about a physical device.
//!
//! Bounds: one child at a time per test, each with a 30 s wall-clock limit and capped output; at most 4 000 children in
//! the whole test binary; every sweep stops at the first budget that lets the script finish and must have killed at least
//! once. On a failure the message carries the script, the budget, the child's exit and output tails, and the full image
//! as hex, so `dump` on those bytes reproduces the recovery exactly.
//!
//! The binary is the example `journal_crash` that the SAME `cargo test -p franken-journal` invocation builds (cargo compiles a
//! package's examples for `cargo test`). It is found by walking up from this test executable to the nearest
//! `examples/journal_crash`: cargo puts test executables in `<target>/<profile>/deps/` or, with the build directory split out,
//! in `<target>/<profile>/build/franken-journal/<hash>/out/`, and examples in `<target>/<profile>/examples/` either way. There
//! is no separate build step, because a separate `cargo build` can run on another worker and a Linux binary is not brought
//! back to a macOS orchestrator. Run it as
//!
//!   cargo test --locked --offline --no-fail-fast -p franken-journal -- --nocapture
//!
//! (not `--test u01_process` alone, which builds only that target). If the binary is absent the test panics with
//! `U01_PROC_BLOCKED`, and the log judge reports the proof as BLOCKED. There is no fallback to a stand-in. A failing test
//! keeps its scratch directory (named in the log) instead of deleting it.

#![cfg(unix)]

mod common;

use common::{hex, sha256_hex, unhex};
use franken_journal::Limits;
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const STDOUT_CAP: u64 = 64 * 1024;
const STDERR_CAP: u64 = 8 * 1024;
const MAX_CHILDREN: u32 = 4_000;
const SWEEP_CAP: usize = 4_096;

/// The scripts of the clean-run case: the four scenarios of the shared vectors.
const CLEAN_SCRIPTS: [&str; 4] = ["U01-S-001", "U01-S-002", "U01-S-003", "U01-S-004"];
/// The scripts of the death sweep and the byte stride, as the Python driver uses (the long churn script is sampled).
const SWEEPS: [(&str, usize); 4] = [
    ("U01-S-001", 1),
    ("U01-S-002", 1),
    ("U01-S-004", 1),
    ("U01-S-003", 29),
];
/// SIGKILL after this many acknowledged steps.
const KILL_PLANS: [(&str, &[usize]); 2] = [
    ("U01-S-003", &[3, 17, 40, 41, 60, 83]),
    ("U01-S-002", &[2, 7, 14]),
];

/// Printed at the start of the panic message when the example binary is absent; `tests/u01/judge_log.py` reads it.
const BLOCKED_MARKER: &str = "U01_PROC_BLOCKED";

static CHILDREN: AtomicU32 = AtomicU32::new(0);
static DIRS: AtomicU32 = AtomicU32::new(0);

// ------------------------------------------------------------------------------------------------ plumbing

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// A fresh directory that this test binary alone owns: a direct child of the temp directory named with this process id
    /// and a counter. `create_dir` (not `create_dir_all`) refuses a path that already exists, so a stale or foreign
    /// directory is never adopted, and the only thing `Drop` can ever remove is a directory created here.
    fn new() -> Self {
        let n = DIRS.fetch_add(1, Ordering::SeqCst);
        let parent = std::env::temp_dir();
        let dir = parent.join(format!("u01-proc-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap_or_else(|e| {
            panic!("cannot create the scratch directory {}: {e}", dir.display())
        });
        assert_eq!(
            dir.parent(),
            Some(parent.as_path()),
            "the scratch directory must be a direct child of the temp directory"
        );
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    /// A passing test removes its directory. A failing one keeps it (and says where), so the failure images stay on disk
    /// until whoever judges the run has read the log; the log carries the same bytes as hex.
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "u01_process: a test failed; keeping {} for inspection",
                self.dir.display()
            );
            return;
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn p(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

/// The nearest `examples/journal_crash` above this test executable (at most eight levels up, so an unrelated file far away
/// is never taken). No fallback and no stand-in: an absent example means the proof did not run, and the marker lets the log
/// judge report that as BLOCKED rather than as a defect of the journal.
fn crash_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let name = format!("journal_crash{}", std::env::consts::EXE_SUFFIX);
    let found = exe
        .ancestors()
        .skip(1)
        .take(8)
        .map(|dir| dir.join("examples").join(&name))
        .find(|candidate| candidate.is_file());
    match found {
        Some(bin) => {
            eprintln!("u01_process: using {}", bin.display());
            bin
        }
        None => panic!(
            "{BLOCKED_MARKER}: no examples/{name} within eight levels above the test executable {}; run the whole package \
             with `cargo test -p franken-journal` (it builds the examples), not `--test u01_process` alone",
            exe.display()
        ),
    }
}

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("u01_vectors.json")
}

fn vectors() -> Value {
    let text = fs::read_to_string(vectors_path()).expect("vectors file");
    serde_json::from_str(&text).expect("vectors json")
}

struct Script {
    steps: usize,
    states: Vec<String>,
    final_sha: String,
}

fn script(doc: &Value, id: &str) -> Script {
    let found = doc["scripts"]
        .as_array()
        .expect("scripts")
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("no script {id} in the vectors"));
    Script {
        steps: found["steps"].as_array().expect("steps").len(),
        states: found["states_hex"]
            .as_array()
            .expect("states")
            .iter()
            .map(|v| v.as_str().expect("state").to_string())
            .collect(),
        final_sha: found["final_media_sha256"]
            .as_str()
            .expect("final digest")
            .to_string(),
    }
}

fn segment() -> usize {
    Limits::tiny().segment_bytes
}

struct Outcome {
    code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Outcome {
    fn completed(&self) -> bool {
        self.code == Some(0) && self.stdout.lines().any(|line| line == "done")
    }

    fn acks(&self) -> usize {
        self.stdout
            .lines()
            .filter(|line| line.starts_with("ack "))
            .count()
    }
}

fn count_child() {
    let n = CHILDREN.fetch_add(1, Ordering::SeqCst);
    assert!(
        n < MAX_CHILDREN,
        "more than {MAX_CHILDREN} child processes in this test binary: a loop is not terminating"
    );
}

fn read_capped(reader: impl Read, cap: u64) -> String {
    let mut bytes = Vec::new();
    let _ = reader.take(cap).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn wait_with_deadline(child: &mut Child, args: &[&str]) -> ExitStatus {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "a child process ran past {} s: {args:?}",
                CHILD_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn run_child(bin: &Path, args: &[&str]) -> Outcome {
    count_child();
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot spawn {}: {e}", bin.display()));
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || read_capped(stdout, STDOUT_CAP));
    let err_reader = std::thread::spawn(move || read_capped(stderr, STDERR_CAP));
    let status = wait_with_deadline(&mut child, args);
    Outcome {
        code: status.code(),
        signal: status.signal(),
        stdout: out_reader.join().expect("stdout reader"),
        stderr: err_reader.join().expect("stderr reader"),
    }
}

fn tail(text: &str, max: usize) -> &str {
    let start = text.len().saturating_sub(max);
    let start = (start..=text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    &text[start..]
}

/// The retained evidence of one child run: how it ended, what it printed, and the whole image (so `dump` can replay it).
fn describe(label: &str, out: &Outcome, image: &Path) -> String {
    let bytes = fs::read(image).unwrap_or_default();
    format!(
        "{label}: exit code {:?}, signal {:?}\n  stdout (last 600 bytes): {}\n  stderr (last 600 bytes): {}\n  \
         image ({} bytes, sha256 {}): {}\n  replay: journal_crash dump <file holding those bytes>",
        out.code,
        out.signal,
        tail(&out.stdout, 600).replace('\n', " | "),
        tail(&out.stderr, 600).replace('\n', " | "),
        bytes.len(),
        sha256_hex(&bytes),
        hex(&bytes)
    )
}

fn file_sha(path: &Path) -> String {
    sha256_hex(&fs::read(path).expect("read image"))
}

fn parse_dump(stdout: &str) -> (String, String) {
    let field = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::to_string)
    };
    (
        field("state ").expect("dump printed no state"),
        field("source ").expect("dump printed no source"),
    )
}

/// Reopen `image` in a fresh process (recovery runs) and return the recovered state and source.
fn dump(bin: &Path, image: &Path, label: &str) -> (String, String) {
    let out = run_child(bin, &["dump", p(image)]);
    assert_eq!(out.code, Some(0), "{}", describe(label, &out, image));
    parse_dump(&out.stdout)
}

/// After `acked` acknowledged steps the recovered state is the one after `acked` steps, or, if a step was still running,
/// the one after `acked + 1`. A finished run allows only the final state.
fn old_or_new(states: &[String], acked: usize, finished: bool, got: &str) -> Result<(), String> {
    let old = states
        .get(acked)
        .ok_or_else(|| format!("no state after {acked} steps"))?;
    let mut allowed = vec![old.as_str()];
    if !finished {
        allowed.push(states[(acked + 1).min(states.len() - 1)].as_str());
    }
    if allowed.contains(&got) {
        Ok(())
    } else {
        Err(format!(
            "recovered {got}, allowed {allowed:?} (after {acked} acknowledged steps, finished: {finished})"
        ))
    }
}

/// Spawn `run`, wait for `target` acknowledgements on its stdout, and SIGKILL it. Returns the acknowledgements the
/// child printed before it died and whether it finished by itself first.
fn kill_after_acks(bin: &Path, image: &Path, id: &str, target: usize) -> (usize, bool) {
    count_child();
    let vec_path = vectors_path();
    let mut child = Command::new(bin)
        .args(["run", p(image), p(&vec_path), id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot spawn {}: {e}", bin.display()));
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout.take(STDOUT_CAP))
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let (mut lines, mut acked, mut killed) = (Vec::new(), 0usize, false);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                if line.starts_with("ack ") {
                    acked += 1;
                }
                lines.push(line);
                if acked >= target && !killed {
                    let _ = child.kill();
                    killed = true;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{id}: the child ran past {} s", CHILD_TIMEOUT.as_secs());
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.wait().expect("wait");
    reader.join().expect("stdout reader");
    let finished = status.code() == Some(0) && lines.iter().any(|line| line == "done");
    (acked, finished)
}

// ------------------------------------------------------------------------------------------------ the cases

#[test]
fn u01_proc_a_clean_run_commits_every_step_and_a_fresh_process_recovers_the_exact_reference_bytes()
{
    let bin = crash_binary();
    let doc = vectors();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    for id in CLEAN_SCRIPTS {
        let s = script(&doc, id);
        let image = scratch.path(&format!("{id}.img"));
        let init = run_child(&bin, &["init", p(&image)]);
        assert_eq!(
            init.code,
            Some(0),
            "{}",
            describe(&format!("{id} init"), &init, &image)
        );
        assert_eq!(
            fs::read(&image).expect("image").len(),
            2 * segment(),
            "{id}: init must create exactly two segments"
        );

        let run = run_child(&bin, &["run", p(&image), p(&vec_path), id]);
        let note = describe(&format!("{id} run"), &run, &image);
        assert!(run.completed(), "the run did not finish: {note}");
        assert_eq!(run.acks(), s.steps, "{id}: every step acknowledged: {note}");
        let order: Vec<&str> = run
            .stdout
            .lines()
            .filter(|l| l.starts_with("ack "))
            .collect();
        for (i, line) in order.iter().enumerate() {
            assert_eq!(
                *line,
                format!("ack {}", i + 1),
                "{id}: acknowledgements out of order: {note}"
            );
        }
        assert_eq!(
            file_sha(&image),
            s.final_sha,
            "{id}: the file after a clean run must equal the reference's final medium byte for byte: {note}"
        );

        let want = s.states.last().expect("at least one state");
        let (state, source) = dump(&bin, &image, &format!("{id} first restart"));
        assert_eq!(
            &state, want,
            "{id}: the first restart must recover the final state"
        );
        assert_eq!(source, "segment", "{id}: source after a restart");
        let settled = file_sha(&image);
        assert_eq!(
            settled, s.final_sha,
            "{id}: the first restart of a cleanly finished image must write nothing (the Python reference leaves these four \
             byte-identical; a stale segment is retired inside the script)"
        );
        let (again, _) = dump(&bin, &image, &format!("{id} second restart"));
        assert_eq!(
            &again, want,
            "{id}: the second restart must recover the same state"
        );
        assert_eq!(
            file_sha(&image),
            settled,
            "{id}: the second restart must write nothing either"
        );
    }
}

#[test]
fn u01_proc_a_process_killed_at_sampled_bytes_recovers_exactly_the_old_or_the_new_state() {
    let bin = crash_binary();
    let doc = vectors();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    let blank = scratch.path("blank.img");
    fs::write(&blank, vec![0xFFu8; 2 * segment()]).expect("blank image");
    let image = scratch.path("work.img");
    for (id, stride) in SWEEPS {
        let s = script(&doc, id);
        let (mut died, mut finished) = (0usize, 0usize);
        for budget in (0..SWEEP_CAP).step_by(stride) {
            fs::copy(&blank, &image).expect("copy the blank image");
            let budget_text = budget.to_string();
            let run = run_child(
                &bin,
                &[
                    "run",
                    p(&image),
                    p(&vec_path),
                    id,
                    "--die-after-bytes",
                    budget_text.as_str(),
                ],
            );
            let label = format!("{id} budget {budget}");
            let done = run.completed();
            if !done {
                assert!(
                    run.signal.is_some(),
                    "{}",
                    describe(
                        &format!("{label}: the child exited instead of dying"),
                        &run,
                        &image
                    )
                );
            }
            let acked = if done { s.steps } else { run.acks() };
            let (state, _source) = dump(&bin, &image, &format!("{label} restart"));
            if let Err(why) = old_or_new(&s.states, acked, done, &state) {
                panic!("{label}: {why}\n{}", describe(&label, &run, &image));
            }
            if done {
                finished += 1;
                break;
            }
            died += 1;
        }
        assert!(
            died > 0,
            "{id}: the sweep never killed the child, so it proved nothing"
        );
        assert_eq!(
            finished, 1,
            "{id}: no budget below {SWEEP_CAP} let the script finish"
        );
    }
}

#[test]
fn u01_proc_sigkill_after_an_acknowledged_step_recovers_exactly_the_old_or_the_new_state() {
    let bin = crash_binary();
    let doc = vectors();
    let scratch = Scratch::new();
    let blank = scratch.path("blank.img");
    fs::write(&blank, vec![0xFFu8; 2 * segment()]).expect("blank image");
    let image = scratch.path("work.img");
    let mut killed_midway = 0usize;
    for (id, targets) in KILL_PLANS {
        let s = script(&doc, id);
        for &target in targets {
            fs::copy(&blank, &image).expect("copy the blank image");
            let (acked, finished) = kill_after_acks(&bin, &image, id, target);
            assert!(
                acked >= target.min(s.steps),
                "{id}: only {acked} of {target} acknowledgements arrived"
            );
            let label = format!("{id} SIGKILL after ack {target}");
            let (state, _source) = dump(&bin, &image, &format!("{label} restart"));
            if let Err(why) = old_or_new(&s.states, acked, finished, &state) {
                let bytes = fs::read(&image).unwrap_or_default();
                panic!(
                    "{label}: {why}\n  image ({} bytes): {}",
                    bytes.len(),
                    hex(&bytes)
                );
            }
            killed_midway += usize::from(!finished);
        }
    }
    assert!(
        killed_midway > 0,
        "no child was killed before it finished, so the case proved nothing"
    );
}

#[test]
fn u01_proc_every_hostile_image_recovers_in_a_real_process_as_the_reference_says() {
    let bin = crash_binary();
    let doc = vectors();
    let scratch = Scratch::new();
    let images = doc["images"].as_array().expect("images");
    assert_eq!(
        images.len(),
        16,
        "the committed hostile-image corpus has 16 images"
    );
    for case in images {
        let id = case["id"].as_str().expect("id");
        let bytes = unhex(case["image_hex"].as_str().expect("image"));
        assert_eq!(bytes.len(), 2 * segment(), "{id}: image size");
        let image = scratch.path(&format!("{id}.img"));
        fs::write(&image, &bytes).expect("write image");
        let expect = &case["expect"];
        let want_sha = case["media_after_sha256"].as_str().expect("digest");

        let first = run_child(&bin, &["dump", p(&image)]);
        let note = describe(&format!("{id} first open"), &first, &image);
        let first_state = if let Some(code) = expect["error"].as_str() {
            assert_eq!(
                first.code,
                Some(2),
                "{id}: an unreadable schema must be refused: {note}"
            );
            assert!(
                first.stderr.contains(&format!("open: {code}")),
                "{id}: expected the refusal `{code}`: {note}"
            );
            None
        } else {
            assert_eq!(first.code, Some(0), "{id}: open failed: {note}");
            let (state, source) = parse_dump(&first.stdout);
            assert_eq!(
                state,
                expect["state_hex"].as_str().expect("state"),
                "{id}: recovered state: {note}"
            );
            if let Some(want) = expect["source"].as_str() {
                assert_eq!(source, want, "{id}: recovery source: {note}");
            }
            Some(state)
        };
        assert_eq!(
            file_sha(&image),
            want_sha,
            "{id}: the file after recovery must be the reference's medium (repair writes included): {note}"
        );

        let second = run_child(&bin, &["dump", p(&image)]);
        let note = describe(&format!("{id} second open"), &second, &image);
        assert_eq!(
            second.code, first.code,
            "{id}: a second restart ends the same way: {note}"
        );
        if let Some(state) = first_state {
            assert_eq!(
                parse_dump(&second.stdout).0,
                state,
                "{id}: a second restart recovers the same state: {note}"
            );
        }
        assert_eq!(
            file_sha(&image),
            want_sha,
            "{id}: a second restart must write nothing: {note}"
        );
    }
}

#[test]
fn u01_proc_the_old_or_new_check_rejects_a_state_that_is_neither() {
    let states: Vec<String> = ["s0", "s1", "s2", "s3"].map(String::from).to_vec();
    // The unplanted shapes pass.
    assert!(old_or_new(&states, 1, false, "s1").is_ok(), "the old state");
    assert!(old_or_new(&states, 1, false, "s2").is_ok(), "the new state");
    assert!(old_or_new(&states, 3, true, "s3").is_ok(), "a finished run");
    assert!(
        old_or_new(&states, 3, false, "s3").is_ok(),
        "no successor after the last step"
    );
    // The planted ones do not.
    assert!(
        old_or_new(&states, 1, false, "s0").is_err(),
        "an acknowledged step must not be lost"
    );
    assert!(
        old_or_new(&states, 1, false, "s3").is_err(),
        "two steps ahead is not allowed"
    );
    assert!(
        old_or_new(&states, 3, true, "s2").is_err(),
        "a finished run allows only the final state"
    );
    assert!(
        old_or_new(&states, 1, false, "zz").is_err(),
        "a state from nowhere"
    );
    assert!(
        old_or_new(&states, 9, false, "s3").is_err(),
        "more acknowledgements than steps"
    );
}
