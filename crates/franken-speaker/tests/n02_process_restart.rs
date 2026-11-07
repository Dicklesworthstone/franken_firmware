//! The durable control plane across a PROCESS boundary (`N02` / `ffw-ugf`): the real `franken-speaker` binary, run as
//! `--control-restart`, over a regular file ([`FileMedium`](franken_speaker::file_medium::FileMedium)).
//!
//! The in-process restart test in `control_adapter.rs` builds a second plane over the same RAM medium, so its "restart" shares the
//! medium's bytes with the first plane. Here the first plane is a process that ends (or is killed), and the second is a NEW process
//! that is handed no mark and no floor: it prints what `boot_durable` restored from the file, and the test compares that with what
//! the first process printed it had reached.
//!
//! What it shows, on a real file and across real process boundaries:
//!   1. a clean run, then a restart: the second process restores the revision mark and the relative-command floor from the FILE,
//!      refuses the delivered tailnet step again (UPnP fault 801, volume unchanged), accepts the next number, and the bridge's
//!      plain step applies once;
//!   2. the remove-the-plant control: the IDENTICAL request (same number, same revision, same delta) sent to a freshly created file
//!      is applied again, so the refusal in 1 comes from the file and the test could fail;
//!   3. a process killed by SIGKILL after its acknowledged steps, while it holds the file: a second opener is refused (`locked`),
//!      and a fresh process after the kill restores the same mark and floor;
//!   4. a file that is not this medium's (missing, directory, symlink, foreign bytes, wrong length, flipped header byte, second hard
//!      link, an existing path given to `init`) is refused by name before any plane exists, and its bytes are untouched; the
//!      paired valid file boots.
//!   5. a commit that FAILS (the first `program` of the file medium after the boot fails with an I/O fault, no effect on the file):
//!      the device panel's mute-on still applies to the live session and is answered OK, the plane latches, a controller's volume
//!      set and the panel's unmute are refused, and a fresh process finds the file's mark exactly as it was, so nothing was half
//!      stored; the same three steps with no fault all succeed;
//!   6. a `sync` that fails: the plane latches the same way, and a fresh process finds either the old mark or the new one (the
//!      outcome of a failed sync is unknown, and the file keeps the bytes already written).
//!
//! What it does not show: a power cut, flash, a block device, or `sync_all`. A process kill keeps every byte already handed to the
//! operating system, synced or not, so case 3 is evidence of a restart after a kill and nothing about durability. The session
//! (G01) is not stored in the file; each process rebuilds the fixture session and is told its revision and the member's volume,
//! and the test claims nothing about session durability. A fixture directory is not a device.
//!
//! Run it with the harness feature (the mode exists only in a harness build), and without a name filter:
//!
//!   cargo test --locked --offline --no-fail-fast -p franken-speaker --features harness -- --nocapture
//!
//! Without `--features harness` this file compiles to nothing, and nothing here ran. Bounds: an ordinary child has a 30 s wall-clock
//! limit; each wait for a held child's marker has its own 30 s deadline. Output is capped; at most thirteen children per test;
//! a held child is explicitly killed or killed and reaped on owner drop, never left behind; a passing test
//! removes only the scratch directory it made (under `CARGO_TARGET_TMPDIR`), a failing one keeps it and says where. The log lines
//! carry codes, marks, counts and volumes only: no path (a file is named by its base name), no byte of a file, no key.

#![cfg(all(unix, feature = "harness"))]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_franken-speaker");
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_CAP: u64 = 64 * 1024;
const OUTPUT_LINES: usize = 128;
const PREFIX: &str = "N02_PROC: ";
/// `Limits::standard().segment_bytes`, and the header of the file medium.
const SEGMENT: usize = 8192;
const FILE_BYTES: usize = 32 + 2 * SEGMENT;

static DIRS: AtomicU32 = AtomicU32::new(0);

// ------------------------------------------------------------------------------------------------ plumbing

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// A fresh directory this test binary alone owns, a direct child of Cargo's per-target temp directory. `create_dir` refuses a path
    /// that exists, so a stale or foreign directory is never adopted and `Drop` can only remove what was made here.
    fn new() -> Self {
        let n = DIRS.fetch_add(1, Ordering::SeqCst);
        let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let dir = parent.join(format!("n02-proc-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap_or_else(|e| panic!("cannot create the scratch directory: {e}"));
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "n02_process_restart: a test failed; keeping {}",
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

/// A file is named by its base name in the log; every other argument is printed as it is.
fn redact(arg: &str) -> String {
    if arg.contains('/') {
        Path::new(arg).file_name().map_or_else(
            || "<path>".to_string(),
            |n| n.to_string_lossy().into_owned(),
        )
    } else {
        arg.to_string()
    }
}

fn log_child(args: &[&str], status: &ExitStatus, lines: &[String]) {
    let shown: Vec<String> = args.iter().map(|a| redact(a)).collect();
    println!(
        "N02_PROC_TEST: child args=[{}] exit={:?} signal={:?}",
        shown.join(" "),
        status.code(),
        status.signal()
    );
    for line in lines {
        println!("N02_PROC_TEST:   {line}");
    }
}

fn read_bounded(source: impl Read) -> Result<String, String> {
    let mut text = String::new();
    source
        .take(OUTPUT_CAP + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("child output read failed: {error}"))?;
    if text.len() as u64 > OUTPUT_CAP {
        return Err("child output exceeded its byte limit".to_string());
    }
    Ok(text)
}

fn drain(source: impl Read + Send + 'static) -> thread::JoinHandle<Result<String, String>> {
    thread::spawn(move || read_bounded(source))
}

/// Reap even if an assertion or output-reader failure unwinds before the explicit wait.
struct ChildOwner(Child);

impl std::ops::Deref for ChildOwner {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for ChildOwner {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Ran {
    status: ExitStatus,
    lines: Vec<String>,
    stderr: String,
}

/// Run `franken-speaker --control-restart <args>` to its end, within the child timeout.
fn run(args: &[&str]) -> Ran {
    let mut child = ChildOwner(
        Command::new(BIN)
            .arg("--control-restart")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the franken-speaker binary starts"),
    );
    let out = drain(child.stdout.take().expect("piped stdout"));
    let err = drain(child.stderr.take().expect("piped stderr"));
    let started = Instant::now();
    let status = loop {
        match child.try_wait().expect("wait for the child") {
            Some(status) => break status,
            None if started.elapsed() > CHILD_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "N02_PROC_TIMEOUT: a child ran longer than {CHILD_TIMEOUT:?} and was killed"
                );
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let stdout = out.join().expect("stdout reader").expect("bounded stdout");
    let stderr = err.join().expect("stderr reader").expect("bounded stderr");
    let lines: Vec<String> = stdout.lines().map(str::to_string).collect();
    log_child(args, &status, &lines);
    Ran {
        status,
        lines,
        stderr,
    }
}

/// A child that stays alive after its steps (`--hold`), waiting for the parent's kill.
struct Held {
    child: ChildOwner,
    lines: Receiver<Result<String, String>>,
    seen: Vec<String>,
    stderr: Option<thread::JoinHandle<Result<String, String>>>,
}

fn start_held(args: &[&str]) -> Held {
    let mut child = ChildOwner(
        Command::new(BIN)
            .arg("--control-restart")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the franken-speaker binary starts"),
    );
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = Some(drain(child.stderr.take().expect("piped stderr")));
    let (tx, lines) = sync_channel(8);
    thread::spawn(move || {
        let mut bytes = 0usize;
        for (index, line) in BufReader::new(stdout.take(OUTPUT_CAP + 1))
            .lines()
            .enumerate()
        {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    let _ = tx.send(Err(format!("held output read failed: {error}")));
                    return;
                }
            };
            bytes = bytes.saturating_add(line.len() + 1);
            if index >= OUTPUT_LINES || bytes as u64 > OUTPUT_CAP {
                let _ = tx.send(Err(
                    "held output exceeded its line or byte limit".to_string()
                ));
                return;
            }
            if tx.send(Ok(line)).is_err() {
                break;
            }
        }
    });
    Held {
        child,
        lines,
        seen: Vec::new(),
        stderr,
    }
}

impl Held {
    /// Read lines until one starts with `PREFIX` and `word`; the child is killed and the test fails if it does not come in time.
    fn wait_for(&mut self, word: &str) -> String {
        let want = format!("{PREFIX}{word}");
        let started = Instant::now();
        loop {
            let left = CHILD_TIMEOUT.saturating_sub(started.elapsed());
            match self.lines.recv_timeout(left) {
                Ok(Ok(line)) => {
                    println!("N02_PROC_TEST:   {line}");
                    self.seen.push(line.clone());
                    if line.starts_with(&want) {
                        return line;
                    }
                }
                Ok(Err(error)) => panic!("N02_PROC_OUTPUT: {error}; seen {:?}", self.seen),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!(
                        "N02_PROC_TIMEOUT: no `{word}` line from the held child; seen {:?}",
                        self.seen
                    );
                }
            }
        }
    }

    /// SIGKILL: no unwinding, no flush, nothing after the last write. Returns the exit status.
    fn kill(mut self) -> ExitStatus {
        self.child.kill().expect("kill the held child");
        let status = self.child.wait().expect("reap the held child");
        let stderr = self
            .stderr
            .take()
            .expect("stderr handle")
            .join()
            .expect("held stderr reader")
            .expect("bounded held stderr");
        assert!(stderr.is_empty(), "held child stderr: {stderr}");
        status
    }
}

fn line_starting<'a>(lines: &'a [String], word: &str) -> &'a str {
    let want = format!("{PREFIX}{word}");
    lines
        .iter()
        .find(|l| l.starts_with(&want))
        .unwrap_or_else(|| panic!("no `{word}` line in {lines:?}"))
}

/// The value of ` key=` in `line`, up to the next space.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let needle = format!(" {key}=");
    let start = line
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{key}` in `{line}`"))
        + needle.len();
    line[start..].split(' ').next().unwrap_or("")
}

fn number(line: &str, key: &str) -> u64 {
    field(line, key)
        .parse()
        .unwrap_or_else(|_| panic!("`{key}` of `{line}` is not a number"))
}

fn step_line(lines: &[String], n: usize) -> &str {
    line_starting(lines, &format!("step {n} "))
}

fn init(path: &Path) {
    let ran = run(&["init", p(path)]);
    assert_eq!(ran.status.code(), Some(0), "{:?}", ran.lines);
    assert_eq!(
        ran.lines,
        [format!(
            "{PREFIX}init ok segment_bytes={SEGMENT} file_bytes={FILE_BYTES}"
        )]
    );
    assert!(ran.stderr.is_empty(), "stderr: {}", ran.stderr);
}

/// What a finished run reached: the session revision and the member's volume at its `end` line.
struct Reached {
    revision: u64,
    volume: u64,
}

fn reached(lines: &[String]) -> Reached {
    let end = line_starting(lines, "end ");
    Reached {
        revision: number(end, "session_revision"),
        volume: number(end, "member_volume"),
    }
}

// ------------------------------------------------------------------------------------------------ the cases

#[test]
fn child_output_at_the_limit_is_retained_and_one_extra_byte_is_an_error() {
    let exact = vec![b'x'; OUTPUT_CAP as usize];
    assert_eq!(
        read_bounded(exact.as_slice()).expect("exact cap").len(),
        exact.len()
    );
    let overflow = vec![b'x'; OUTPUT_CAP as usize + 1];
    assert!(read_bounded(overflow.as_slice()).is_err());
}

#[test]
fn dropping_a_held_child_reaps_it_and_releases_the_real_file_lock() {
    let scratch = Scratch::new();
    let file = scratch.path("guard.img");
    init(&file);
    let mut held = start_held(&["run", p(&file), "fresh", "-", "--hold"]);
    held.wait_for("held ");
    let before = fs::read(&file).expect("file bytes");
    drop(held);
    let reopened = run(&["run", p(&file), "fresh", "-"]);
    assert_eq!(reopened.status.code(), Some(0), "{:?}", reopened.lines);
    assert!(reopened.stderr.is_empty(), "{}", reopened.stderr);
    assert_eq!(fs::read(&file).expect("file bytes"), before);
}

#[test]
fn the_step_limit_accepts_sixty_four_and_refuses_sixty_five_before_opening_the_file() {
    let scratch = Scratch::new();
    let file = scratch.path("limit.img");
    init(&file);
    let steps = ["legacy:0"; 64].join(",");
    let accepted = run(&["run", p(&file), "fresh", &steps]);
    assert_eq!(accepted.status.code(), Some(0), "{:?}", accepted.lines);
    assert_eq!(
        accepted
            .lines
            .iter()
            .filter(|line| line.starts_with("N02_PROC: step "))
            .count(),
        64
    );
    let before = fs::read(&file).expect("file bytes");
    let refused = run(&["run", p(&file), "fresh", &format!("{steps},legacy:0")]);
    assert_eq!(refused.status.code(), Some(2), "{:?}", refused.lines);
    assert_eq!(refused.lines, ["N02_PROC: failed reason=too many steps"]);
    assert_eq!(fs::read(&file).expect("file bytes"), before);
}

#[test]
fn a_new_process_restores_the_mark_and_the_floor_from_the_file_and_refuses_the_delivered_step() {
    let scratch = Scratch::new();
    let file = scratch.path("plane.img");
    init(&file);

    // process 1: a blank file; a signed tailnet step (number 1) and a plain bridge step, both applied
    let first = run(&["run", p(&file), "fresh", "tail:1:cur:10,legacy:5"]);
    assert_eq!(first.status.code(), Some(0), "{:?}", first.lines);
    assert!(first.stderr.is_empty(), "stderr: {}", first.stderr);
    let boot = line_starting(&first.lines, "boot ");
    assert!(boot.contains(" restored_mark=FreshMedium "), "{boot}");
    assert!(boot.ends_with(" restored_floors=Nothing"), "{boot}");
    let step1 = step_line(&first.lines, 1);
    assert_eq!(
        (
            field(step1, "status"),
            field(step1, "volume"),
            field(step1, "fault")
        ),
        ("200", "60", "none"),
        "{step1}"
    );
    let step2 = step_line(&first.lines, 2);
    assert_eq!(
        (
            field(step2, "status"),
            field(step2, "volume"),
            field(step2, "fault")
        ),
        ("200", "65", "none"),
        "{step2}"
    );
    let reached_first = reached(&first.lines);
    assert_eq!(reached_first.volume, 65);

    // process 2: a NEW process. It is told the session (revision, volume), which G01 does not store, and nothing the file holds.
    let session = format!("{}:{}", reached_first.revision, reached_first.volume);
    let second = run(&[
        "run",
        p(&file),
        &session,
        "tail:1:cur:10,tail:2:cur:10,legacy:5",
    ]);
    assert_eq!(second.status.code(), Some(0), "{:?}", second.lines);
    assert!(second.stderr.is_empty(), "stderr: {}", second.stderr);
    let boot = line_starting(&second.lines, "boot ");
    // the mark comes from the file and equals what process 1 reached
    assert!(
        boot.contains(&format!(" restored_mark=Mark({}) ", reached_first.revision)),
        "{boot}"
    );
    assert!(
        boot.ends_with(" restored_floors=Table { identities: 1 }"),
        "{boot}"
    );
    // the delivered number is unknown (801) and does not move the volume
    let duplicate = step_line(&second.lines, 1);
    assert_eq!(
        (field(duplicate, "volume"), field(duplicate, "fault")),
        ("none", "801"),
        "{duplicate}"
    );
    // the next number applies (the paired permitted behavior), and the bridge's plain step applies once
    let next = step_line(&second.lines, 2);
    assert_eq!(
        (
            field(next, "status"),
            field(next, "volume"),
            field(next, "fault")
        ),
        ("200", "75", "none"),
        "{next}"
    );
    let bridge = step_line(&second.lines, 3);
    assert_eq!(
        (field(bridge, "volume"), field(bridge, "fault")),
        ("80", "none"),
        "{bridge}"
    );
    println!(
        "N02_PROC_TEST: restart restored mark={} floors=1 identity, refused number 1 with 801, applied number 2",
        reached_first.revision
    );

    // the remove-the-plant control: the IDENTICAL request (number 1, the same revision, delta 10) to a blank file is applied again
    let blank = scratch.path("blank.img");
    init(&blank);
    let control = run(&["run", p(&blank), &session, "tail:1:cur:10"]);
    assert_eq!(control.status.code(), Some(0), "{:?}", control.lines);
    let boot = line_starting(&control.lines, "boot ");
    assert!(boot.contains(" restored_mark=FreshMedium "), "{boot}");
    assert!(boot.ends_with(" restored_floors=Nothing"), "{boot}");
    let again = step_line(&control.lines, 1);
    assert_eq!(
        (field(again, "seq"), field(again, "sent_revision")),
        (field(duplicate, "seq"), field(duplicate, "sent_revision")),
        "the control must send the same request"
    );
    assert_eq!(
        (
            field(again, "status"),
            field(again, "volume"),
            field(again, "fault")
        ),
        ("200", "75", "none"),
        "{again}"
    );
    println!(
        "N02_PROC_TEST: control: the same request to a blank file was applied (volume 75); the refusal above came from the file"
    );
}

#[test]
fn a_process_killed_after_its_acknowledged_steps_holds_the_file_and_a_fresh_process_restores_from_it()
 {
    let scratch = Scratch::new();
    let file = scratch.path("plane.img");
    init(&file);

    let mut held = start_held(&["run", p(&file), "fresh", "tail:1:cur:10,legacy:5", "--hold"]);
    let boot = held.wait_for("boot ");
    assert!(boot.contains(" restored_mark=FreshMedium "), "{boot}");
    let end = held.wait_for("end ");
    let reached_first = Reached {
        revision: number(&end, "session_revision"),
        volume: number(&end, "member_volume"),
    };
    assert_eq!(reached_first.volume, 65);
    let held_line = held.wait_for("held ");
    assert!(
        held_line.contains("says nothing about sync_all"),
        "{held_line}"
    );

    // while the first process lives, a second opener of the same file is refused and changes nothing
    let before = fs::read(&file).expect("the file reads");
    let second_opener = run(&["run", p(&file), "fresh", "-"]);
    assert_eq!(
        second_opener.status.code(),
        Some(2),
        "{:?}",
        second_opener.lines
    );
    assert_eq!(
        second_opener.lines,
        [format!("{PREFIX}refused code=locked")]
    );
    assert_eq!(
        fs::read(&file).expect("the file reads"),
        before,
        "a refused opener changed the file"
    );

    let status = held.kill();
    assert_eq!(
        status.signal(),
        Some(9),
        "the held child must die by SIGKILL, got {status:?}"
    );
    println!(
        "N02_PROC_TEST: kill: SIGKILL keeps every byte already handed to the OS, synced or not; this case shows a restart after a kill and says nothing about sync_all"
    );

    // a fresh process after the kill: the lock went with the process, the mark and the floor are in the file
    let session = format!("{}:{}", reached_first.revision, reached_first.volume);
    let after = run(&["run", p(&file), &session, "tail:1:cur:10,tail:2:cur:10"]);
    assert_eq!(after.status.code(), Some(0), "{:?}", after.lines);
    let boot = line_starting(&after.lines, "boot ");
    assert!(
        boot.contains(&format!(" restored_mark=Mark({}) ", reached_first.revision)),
        "{boot}"
    );
    assert!(
        boot.ends_with(" restored_floors=Table { identities: 1 }"),
        "{boot}"
    );
    let duplicate = step_line(&after.lines, 1);
    assert_eq!(
        (field(duplicate, "volume"), field(duplicate, "fault")),
        ("none", "801"),
        "{duplicate}"
    );
    let next = step_line(&after.lines, 2);
    assert_eq!(
        (field(next, "status"), field(next, "volume")),
        ("200", "75"),
        "{next}"
    );
}

#[test]
fn what_is_not_this_mediums_file_is_refused_by_name_before_any_plane_exists_and_left_alone() {
    let scratch = Scratch::new();
    let valid = scratch.path("valid.img");
    init(&valid);

    // (label, path, the refusal code the run must print)
    let mut cases: Vec<(&str, PathBuf, &str)> =
        vec![("missing", scratch.path("missing.img"), "not_found")];

    let directory = scratch.path("directory");
    fs::create_dir(&directory).expect("directory");
    cases.push(("directory", directory, "not_regular_file"));

    let link = scratch.path("link.img");
    std::os::unix::fs::symlink(&valid, &link).expect("symlink");
    cases.push(("symlink to a valid file", link, "not_regular_file"));

    let foreign = scratch.path("foreign.bin");
    fs::write(&foreign, vec![0x5Au8; FILE_BYTES]).expect("foreign file of the right length");
    cases.push(("foreign bytes of the right length", foreign, "bad_header"));

    let short = scratch.path("short.bin");
    fs::write(&short, vec![0xFFu8; 100]).expect("short file");
    cases.push(("wrong length", short, "wrong_length"));

    let flipped = scratch.path("flipped.img");
    init(&flipped);
    let mut image = fs::read(&flipped).expect("the file reads");
    image[5] ^= 0x01;
    fs::write(&flipped, image).expect("flip one header byte");
    cases.push(("one header byte flipped", flipped, "bad_header"));

    let linked = scratch.path("linked.img");
    init(&linked);
    fs::hard_link(&linked, scratch.path("alias.img")).expect("hard link");
    cases.push(("a second hard link", linked, "not_exclusive"));

    for (label, path, code) in &cases {
        let before = fs::read(path).ok();
        let ran = run(&["run", p(path), "fresh", "-"]);
        assert_eq!(ran.status.code(), Some(2), "{label}: {:?}", ran.lines);
        assert_eq!(
            ran.lines,
            [format!("{PREFIX}refused code={code}")],
            "{label}"
        );
        assert!(ran.stderr.is_empty(), "{label}: stderr {}", ran.stderr);
        assert_eq!(
            fs::read(path).ok(),
            before,
            "{label}: a refusal changed what is at the path"
        );
    }

    // `init` onto any existing path is refused too, and the bytes stay
    let foreign_before = fs::read(scratch.path("foreign.bin")).expect("the file reads");
    let over = run(&["init", p(&scratch.path("foreign.bin"))]);
    assert_eq!(over.status.code(), Some(2), "{:?}", over.lines);
    assert_eq!(over.lines, [format!("{PREFIX}refused code=already_exists")]);
    assert_eq!(
        fs::read(scratch.path("foreign.bin")).expect("the file reads"),
        foreign_before
    );
    let over_valid = run(&["init", p(&valid)]);
    assert_eq!(
        over_valid.lines,
        [format!("{PREFIX}refused code=already_exists")]
    );

    // paired: the valid file boots as a blank journal and a clean run succeeds
    let ok = run(&["run", p(&valid), "fresh", "-"]);
    assert_eq!(ok.status.code(), Some(0), "{:?}", ok.lines);
    let boot = line_starting(&ok.lines, "boot ");
    assert!(boot.contains(" restored_mark=FreshMedium "), "{boot}");
    println!(
        "N02_PROC_TEST: {} refusals named, each with the file untouched; the valid file booted",
        cases.len() + 2
    );
}

/// The value of ` member_muted=` in a step or end line.
fn muted(line: &str) -> bool {
    match field(line, "member_muted") {
        "true" => true,
        "false" => false,
        other => panic!("member_muted is `{other}` in `{line}`"),
    }
}

fn latched(line: &str) -> bool {
    match field(line, "latched") {
        "true" => true,
        "false" => false,
        other => panic!("latched is `{other}` in `{line}`"),
    }
}

/// A file with one clean life behind it: a signed tailnet step and a bridge step applied. Returns the file and what the first process
/// reached (its revision is the mark it stored).
fn file_with_a_stored_mark(scratch: &Scratch, name: &str) -> (PathBuf, Reached) {
    let file = scratch.path(name);
    init(&file);
    let first = run(&["run", p(&file), "fresh", "tail:1:cur:10,legacy:5"]);
    assert_eq!(first.status.code(), Some(0), "{:?}", first.lines);
    let reached_first = reached(&first.lines);
    assert_eq!(reached_first.volume, 65);
    (file, reached_first)
}

#[test]
fn a_failed_commit_of_a_local_mute_on_still_silences_and_latches_and_the_file_keeps_its_old_mark() {
    let scratch = Scratch::new();
    let (file, before) = file_with_a_stored_mark(&scratch, "plane.img");
    let session = format!("{}:{}", before.revision, before.volume);
    let script = "panel:1:1,tail:2:cur:10,panel:2:0";

    // process A: the first storage write after the boot fails. The panel's mute-on is the first step.
    let a = run(&["run", p(&file), &session, script, "--fail-at", "program:1"]);
    assert_eq!(a.status.code(), Some(0), "{:?}", a.lines);
    assert!(a.stderr.is_empty(), "stderr: {}", a.stderr);
    let boot = line_starting(&a.lines, "boot ");
    assert!(
        boot.contains(&format!(" restored_mark=Mark({}) ", before.revision)),
        "{boot}"
    );
    assert!(
        boot.ends_with(" restored_floors=Table { identities: 1 }"),
        "{boot}"
    );
    assert!(!muted(boot), "{boot}");
    // the mute-on is applied to the live session although its commit failed, and it is answered OK; the plane is latched at once
    let mute_on = step_line(&a.lines, 1);
    assert_eq!(
        (
            field(mute_on, "kind"),
            field(mute_on, "status"),
            field(mute_on, "fault")
        ),
        ("panel", "200", "none"),
        "{mute_on}"
    );
    assert!(muted(mute_on), "the mute-on did not apply: {mute_on}");
    assert!(
        latched(mute_on),
        "the failed commit did not latch the plane: {mute_on}"
    );
    // a controller's volume set is refused and changes nothing (and is not recorded: it can be sent again after a reopen)
    let refused_set = step_line(&a.lines, 2);
    assert_ne!(field(refused_set, "status"), "200", "{refused_set}");
    assert_ne!(field(refused_set, "fault"), "none", "{refused_set}");
    assert_eq!(field(refused_set, "volume"), "none", "{refused_set}");
    // the panel's unmute is refused too: while latched only a mute-on or a stop still applies
    let refused_unmute = step_line(&a.lines, 3);
    assert_ne!(field(refused_unmute, "fault"), "none", "{refused_unmute}");
    assert!(
        muted(refused_unmute),
        "the refused unmute unmuted the member: {refused_unmute}"
    );
    let end = line_starting(&a.lines, "end ");
    assert_eq!(
        (number(end, "member_volume"), muted(end), latched(end)),
        (before.volume, true, true),
        "{end}"
    );

    // process B: a FRESH process, no fault, the same three steps. The file's mark is the one process A found: the failed commit
    // wrote nothing, and nothing is half stored.
    let b = run(&["run", p(&file), &session, script, "--fail-at", "none"]);
    assert_eq!(b.status.code(), Some(0), "{:?}", b.lines);
    let boot = line_starting(&b.lines, "boot ");
    assert!(
        boot.contains(&format!(" restored_mark=Mark({}) ", before.revision)),
        "the failed commit changed the file's mark: {boot}"
    );
    assert!(
        boot.ends_with(" restored_floors=Table { identities: 1 }"),
        "{boot}"
    );
    let mute_on = step_line(&b.lines, 1);
    assert_eq!(
        (field(mute_on, "status"), field(mute_on, "fault")),
        ("200", "none"),
        "{mute_on}"
    );
    assert!(muted(mute_on) && !latched(mute_on), "{mute_on}");
    // the paired permitted behavior: the controller's set that the latched plane refused applies now, and so does the unmute
    let set = step_line(&b.lines, 2);
    assert_eq!(
        (
            field(set, "status"),
            field(set, "volume"),
            field(set, "fault")
        ),
        ("200", "75", "none"),
        "{set}"
    );
    let unmute = step_line(&b.lines, 3);
    assert_eq!(
        (field(unmute, "status"), field(unmute, "fault")),
        ("200", "none"),
        "{unmute}"
    );
    assert!(!muted(unmute), "{unmute}");
    let end = line_starting(&b.lines, "end ");
    assert_eq!(
        (number(end, "member_volume"), muted(end), latched(end)),
        (75, false, false),
        "{end}"
    );
    println!(
        "N02_PROC_TEST: a failed commit: the panel mute-on applied live, the plane latched, the set and the unmute were refused, and the file kept mark {}; the same script with no fault succeeded in full",
        before.revision
    );
}

#[test]
fn an_unknown_sync_outcome_latches_the_plane_and_a_fresh_process_finds_the_old_or_the_new_mark() {
    let scratch = Scratch::new();
    let (file, before) = file_with_a_stored_mark(&scratch, "plane.img");
    let session = format!("{}:{}", before.revision, before.volume);

    // process A: the first sync after the boot fails; the bytes of the commit are already in the file
    let a = run(&[
        "run",
        p(&file),
        &session,
        "panel:1:1,tail:2:cur:10",
        "--fail-at",
        "sync:1",
    ]);
    assert_eq!(a.status.code(), Some(0), "{:?}", a.lines);
    let mute_on = step_line(&a.lines, 1);
    assert_eq!(
        (field(mute_on, "status"), field(mute_on, "fault")),
        ("200", "none"),
        "{mute_on}"
    );
    assert!(muted(mute_on) && latched(mute_on), "{mute_on}");
    let refused_set = step_line(&a.lines, 2);
    assert_ne!(field(refused_set, "fault"), "none", "{refused_set}");
    assert_eq!(field(refused_set, "volume"), "none", "{refused_set}");
    let a_revision = reached(&a.lines).revision;

    // process B: nothing to send, only the boot. The outcome of a failed sync is unknown, so the file holds the old mark or the new
    // one, and nothing else.
    let b = run(&["run", p(&file), &session, "-", "--fail-at", "none"]);
    assert_eq!(b.status.code(), Some(0), "{:?}", b.lines);
    let boot = line_starting(&b.lines, "boot ");
    let old = format!(" restored_mark=Mark({}) ", before.revision);
    let new = format!(" restored_mark=Mark({a_revision}) ");
    assert!(
        boot.contains(&old) || boot.contains(&new),
        "neither the old nor the new mark: {boot} (old {}, new {a_revision})",
        before.revision
    );
    println!(
        "N02_PROC_TEST: a failed sync: the plane latched; the file held the {} mark",
        if boot.contains(&old) { "OLD" } else { "NEW" }
    );
}
