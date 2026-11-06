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
//!   2. a process that dies (no unwinding, no flush) at a sampled byte of the write or erase that crosses it recovers
//!      exactly the state before or exactly the state after the step that was running, never an acknowledged step lost and
//!      never a step more than one ahead. The sweep holds the child at that byte (`--await-kill`: it has written the bytes
//!      before the cut, prints `cut <n>` and waits) and SIGKILLs it from this parent, because `abort` makes an OS core-dump
//!      handler (Ubuntu's apport) start a process per death and a sweep dies thousands of times; focused tests show the
//!      two deaths leave the same image, that the child really waits alive for the kill, and that it never aborts by itself;
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
//! once (by SIGKILL at the announced cut; only the three-budget equivalence test aborts a child). On a failure the message carries the script, the budget, the child's exit and output tails, and the full image
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
/// The first word of the line a `--await-kill` child prints at its cut, and the two signals the tests tell apart.
const CUT_PREFIX: &str = "cut ";
const SIGABRT: i32 = 6;
const SIGKILL: i32 = 9;

/// The scripts of the clean-run case: the five scenarios of the shared vectors.
const CLEAN_SCRIPTS: [&str; 5] = [
    "U01-S-001",
    "U01-S-002",
    "U01-S-003",
    "U01-S-004",
    "U01-S-005",
];
/// The scripts of the death sweep and the byte stride, as the Python driver uses (the long churn script is sampled).
const SWEEPS: [(&str, usize); 5] = [
    ("U01-S-001", 1),
    ("U01-S-002", 1),
    ("U01-S-004", 1),
    ("U01-S-003", 29),
    ("U01-S-005", 3),
];
/// SIGKILL after this many acknowledged steps.
const KILL_PLANS: [(&str, &[usize]); 3] = [
    ("U01-S-003", &[3, 17, 40, 41, 60, 83]),
    ("U01-S-002", &[2, 7, 14]),
    ("U01-S-005", &[3, 4, 5, 6, 29, 30]),
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
    programmed: usize,
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
        programmed: usize::try_from(
            found["bytes_programmed"]
                .as_u64()
                .expect("bytes programmed"),
        )
        .expect("bytes programmed fit a usize"),
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

/// Run `args` (a `run ... --die-after-bytes N --await-kill` line) and kill it with SIGKILL from this parent at the cut. The child has
/// written every byte before the cut, then prints `cut <n>` and waits on its stdin, so the moment this parent reads that line the
/// child can do nothing more: the kill lands at exactly that byte, with no unwinding and no flush, and no core-dump handler runs
/// (SIGKILL starts none; `abort` starts one per death on a host that has one). `at_the_cut` runs once, after that line and before
/// the kill, with the child alive. A run that ends by itself (it finished, or failed) is returned as it ended. This parent holds the
/// child's stdin open until the child has been reaped, so a test that panics drops it and the child leaves by itself (exit code 3).
fn run_to_the_cut_and_kill(
    bin: &Path,
    args: &[&str],
    at_the_cut: impl FnOnce(&mut Child),
) -> Outcome {
    let (outcome, timed_out) =
        run_to_the_cut_and_kill_bounded(bin, args, STDOUT_CAP, CHILD_TIMEOUT, at_the_cut);
    assert!(
        !timed_out,
        "a child process ran past {} s: {args:?}; code {:?}, signal {:?}, stdout {:?}, stderr {:?}",
        CHILD_TIMEOUT.as_secs(),
        outcome.code,
        outcome.signal,
        tail(&outcome.stdout, 600),
        tail(&outcome.stderr, 600)
    );
    outcome
}

/// One absolute deadline covers both stdout and process exit. EOF (including the capped reader stopping) says nothing
/// about process liveness: in particular the child may still be waiting on the stdin this parent deliberately holds open.
/// Return a timeout separately, after SIGKILL and wait have reaped the child, so a negative test can inspect that real death.
fn run_to_the_cut_and_kill_bounded(
    bin: &Path,
    args: &[&str],
    stdout_cap: u64,
    timeout: Duration,
    at_the_cut: impl FnOnce(&mut Child),
) -> (Outcome, bool) {
    count_child();
    let deadline = Instant::now() + timeout;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot spawn {}: {e}", bin.display()));
    let hold_stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let err_reader = std::thread::spawn(move || read_capped(stderr, STDERR_CAP));
    let (tx, rx) = channel::<String>();
    let out_reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout.take(stdout_cap))
            .lines()
            .map_while(Result::ok)
        {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut at_the_cut = Some(at_the_cut);
    let mut lines: Vec<String> = Vec::new();
    let mut killed = false;
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                let is_cut = line.starts_with(CUT_PREFIX);
                lines.push(line);
                if is_cut && !killed {
                    if let Some(check) = at_the_cut.take() {
                        check(&mut child);
                    }
                    let _ = child.kill();
                    killed = true;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().expect("wait after deadline kill");
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    drop(hold_stdin);
    out_reader.join().expect("stdout reader");
    let outcome = Outcome {
        code: status.code(),
        signal: status.signal(),
        stdout: lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
        stderr: err_reader.join().expect("stderr reader"),
    };
    (outcome, timed_out)
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
            let run = run_to_the_cut_and_kill(
                &bin,
                &[
                    "run",
                    p(&image),
                    p(&vec_path),
                    id,
                    "--die-after-bytes",
                    budget_text.as_str(),
                    "--await-kill",
                ],
                |_| {},
            );
            let label = format!("{id} budget {budget}");
            let done = run.completed();
            if !done {
                assert_eq!(
                    run.signal,
                    Some(SIGKILL),
                    "{}",
                    describe(
                        &format!("{label}: the child was not killed at the cut"),
                        &run,
                        &image
                    )
                );
                let cut_line = format!("{CUT_PREFIX}{budget}");
                assert!(
                    run.stdout.lines().any(|line| line == cut_line),
                    "{}",
                    describe(
                        &format!(
                            "{label}: the child never announced the cut at this byte ({cut_line})"
                        ),
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
fn u01_proc_a_kill_at_the_cut_leaves_the_same_image_as_an_abort_at_the_same_byte() {
    let bin = crash_binary();
    let doc = vectors();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    let blank = scratch.path("blank.img");
    fs::write(&blank, vec![0xFFu8; 2 * segment()]).expect("blank image");
    let (by_abort, by_kill) = (scratch.path("abort.img"), scratch.path("kill.img"));
    let id = "U01-S-002";
    let s = script(&doc, id);
    // before any byte, inside the first write, and about halfway through the programmed bytes: all below the script's total
    for budget in [0, 41, s.programmed / 2] {
        fs::copy(&blank, &by_abort).expect("copy the blank image");
        fs::copy(&blank, &by_kill).expect("copy the blank image");
        let budget_text = budget.to_string();
        let label = format!("{id} budget {budget}");
        let aborted = run_child(
            &bin,
            &[
                "run",
                p(&by_abort),
                p(&vec_path),
                id,
                "--die-after-bytes",
                budget_text.as_str(),
            ],
        );
        let killed = run_to_the_cut_and_kill(
            &bin,
            &[
                "run",
                p(&by_kill),
                p(&vec_path),
                id,
                "--die-after-bytes",
                budget_text.as_str(),
                "--await-kill",
            ],
            |_| {},
        );
        assert!(
            !aborted.completed() && !killed.completed(),
            "{label}: the budget is past the end of the script, so no child died"
        );
        assert_eq!(
            aborted.signal,
            Some(SIGABRT),
            "{}",
            describe(&format!("{label}: the default death"), &aborted, &by_abort)
        );
        assert_eq!(
            killed.signal,
            Some(SIGKILL),
            "{}",
            describe(&format!("{label}: the death at the cut"), &killed, &by_kill)
        );
        assert_eq!(
            aborted.acks(),
            killed.acks(),
            "{label}: both deaths follow the same acknowledgements"
        );
        assert_eq!(
            fs::read(&by_abort).expect("abort image"),
            fs::read(&by_kill).expect("kill image"),
            "{label}: the two deaths must leave the same bytes"
        );
        assert_eq!(
            dump(&bin, &by_abort, &format!("{label} restart after abort")),
            dump(&bin, &by_kill, &format!("{label} restart after kill")),
            "{label}: the two images must recover the same state and source"
        );
    }
}

#[test]
fn u01_proc_the_child_waits_alive_at_the_cut_and_only_the_parents_kill_ends_it() {
    let bin = crash_binary();
    let doc = vectors();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    let image = scratch.path("work.img");
    fs::write(&image, vec![0xFFu8; 2 * segment()]).expect("blank image");
    let id = "U01-S-002";
    let s = script(&doc, id);
    let run = run_to_the_cut_and_kill(
        &bin,
        &[
            "run",
            p(&image),
            p(&vec_path),
            id,
            "--die-after-bytes",
            "41",
            "--await-kill",
        ],
        |child| {
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                child.try_wait().expect("try_wait").is_none(),
                "the child left by itself at the cut instead of waiting to be killed"
            );
        },
    );
    let note = describe("held at the cut", &run, &image);
    assert_eq!((run.code, run.signal), (None, Some(SIGKILL)), "{note}");
    let cuts: Vec<&str> = run
        .stdout
        .lines()
        .filter(|line| line.starts_with(CUT_PREFIX))
        .collect();
    assert_eq!(cuts, ["cut 41"], "{note}");
    assert!(!run.completed(), "{note}");
    let (state, _source) = dump(&bin, &image, "held at the cut, restart");
    if let Err(why) = old_or_new(&s.states, run.acks(), false, &state) {
        panic!("{why}\n{note}");
    }
}

#[test]
fn u01_proc_a_capped_stdout_does_not_bypass_the_child_deadline_or_leave_it_alive() {
    let bin = crash_binary();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    let image = scratch.path("work.img");
    let blank = vec![0xFFu8; 2 * segment()];
    fs::write(&image, &blank).expect("blank image");
    // At byte zero the real child reaches its cut during Journal::open, before `opened` is printed. A one-byte reader
    // sees at most "c", never the complete `cut 0` marker, then closes stdout. The child still waits on the held stdin;
    // EOF must not turn the parent's bounded wait into an unbounded child.wait() or a graceful stdin-close exit.
    let timeout = Duration::from_millis(300);
    let started = Instant::now();
    let (out, timed_out) = run_to_the_cut_and_kill_bounded(
        &bin,
        &[
            "run",
            p(&image),
            p(&vec_path),
            "U01-S-002",
            "--die-after-bytes",
            "0",
            "--await-kill",
        ],
        1,
        timeout,
        |_| panic!("a partial cut marker must never trigger a cut kill"),
    );
    let elapsed = started.elapsed();
    let note = describe("stdout capped before cut marker", &out, &image);
    assert!(
        timed_out,
        "the deadline must kill the still-waiting child: {note}"
    );
    assert_eq!((out.code, out.signal), (None, Some(SIGKILL)), "{note}");
    assert!(!out.stdout.contains("cut 0"), "{note}");
    assert!(
        elapsed >= timeout && elapsed < CHILD_TIMEOUT,
        "elapsed {elapsed:?}: {note}"
    );
    assert_eq!(fs::read(&image).expect("image"), blank, "{note}");
    eprintln!("u01_process: capped stdout deadline reaped SIGKILL child after {elapsed:?}");
}

#[test]
fn u01_proc_a_waiting_child_whose_parent_is_gone_leaves_by_itself_and_does_not_abort() {
    let bin = crash_binary();
    let doc = vectors();
    let vec_path = vectors_path();
    let scratch = Scratch::new();
    let image = scratch.path("work.img");
    fs::write(&image, vec![0xFFu8; 2 * segment()]).expect("blank image");
    let id = "U01-S-002";
    let s = script(&doc, id);
    // `run_child` gives the child a null stdin: end of input at once, which is what a parent that has gone away looks like
    let out = run_child(
        &bin,
        &[
            "run",
            p(&image),
            p(&vec_path),
            id,
            "--die-after-bytes",
            "41",
            "--await-kill",
        ],
    );
    let note = describe("parent gone", &out, &image);
    assert_eq!(
        (out.code, out.signal),
        (Some(3), None),
        "it must leave by itself with exit code 3, not abort and not hang: {note}"
    );
    assert!(out.stderr.contains("stdin closed"), "{note}");
    assert!(out.stdout.lines().any(|line| line == "cut 41"), "{note}");
    let (state, _source) = dump(&bin, &image, "parent gone, restart");
    if let Err(why) = old_or_new(&s.states, out.acks(), false, &state) {
        panic!("{why}\n{note}");
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
