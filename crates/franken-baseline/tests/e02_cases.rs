//! E02 (ffw-za4) end-to-end cases: the real `ffw-baseline` binary over the synthetic captures in
//! `tests/e02/`, compared with expected outputs that were worked out by hand (and cross-checked by the
//! independent Python oracle, `tests/e02/oracle.py`), never produced by this analyzer.
//!
//! Run centrally: `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline`.
//!
//! An expected file is a SUBSET of the report: every key it names must match exactly, extra keys in the
//! report are ignored, arrays must have the same length and match element by element. The subset rule
//! is itself tested below with planted differences, so a matcher that accepts anything would fail.
//!
//! A case may also name strings that must never appear in what the binary prints (`stderr_lacks`,
//! `stdout_lacks`): the planted site identifiers. A case may name the one summary line the run must print on stderr
//! (`summary`), written by hand; every run that writes a report must print exactly one summary line and exactly one line
//! of JSON. Each such string must really be in the case's capture, so
//! the check cannot pass vacuously, and `redaction_vectors.json` pins the classifier's answer for each shape.
//!
//! A failing check retains what a replay needs, in its own output (acceptance, "Owned test assets": each failure retains replay
//! command, versions, artifact digests, expected versus observed, and the first causal event). The first difference is in the
//! failure line. `failure_context` adds, for the case that failed, its exact replay command, the SHA-256 of its capture and of
//! its expected file, the crate, report-schema and capture-format versions, and the profile when an observed report exists;
//! `suite_context` does the same for a check over a data file with no single case. Every case-level check is a function over
//! its data (`check_case`, `orphan_problems`, `invariant_problems`, `echo_plant_problems`, `vector_problems`,
//! `summary_line_problems`), so each has a planted failure with its remove-the-plant control. Nothing is rerun or retried, so a
//! failure stays as it first happened, and every analyzer process is killed after `CHILD_DEADLINE`, with the failure naming its case.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn e02_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/e02")
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

/// `None` if `expected` is a subset of `actual`, else the first difference.
fn subset_diff(path: &str, expected: &Value, actual: &Value) -> Option<String> {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (key, ev) in e {
                match a.get(key) {
                    None => return Some(format!("{path}.{key}: missing from the report")),
                    Some(av) => {
                        if let Some(diff) = subset_diff(&format!("{path}.{key}"), ev, av) {
                            return Some(diff);
                        }
                    }
                }
            }
            None
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                return Some(format!(
                    "{path}: expected {} elements, report has {}",
                    e.len(),
                    a.len()
                ));
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                if let Some(diff) = subset_diff(&format!("{path}[{i}]"), ev, av) {
                    return Some(diff);
                }
            }
            None
        }
        (e, a) => {
            if e == a {
                None
            } else {
                Some(format!("{path}: expected {e}, report has {a}"))
            }
        }
    }
}

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

/// The longest an analyzer process may run before the test kills it and fails its case. The analyzer is a bounded batch function
/// over kilobyte captures, so this is generous; it exists so that a hang is a failure that names its case, not a stuck run.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

/// Run `cmd` to completion, or kill it (and reap it) after `deadline` and say so, naming the pid so a test can check it is gone.
fn run_bounded(mut cmd: Command, deadline: Duration) -> Result<Outcome, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start: {e}"))?;
    let pid = child.id();
    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out_pipe.read_to_end(&mut bytes);
        bytes
    });
    let err_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = err_pipe.read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(format!("cannot poll the child: {e}")),
        }
    };
    let stdout = out_reader.join().expect("stdout reader");
    let stderr = err_reader.join().expect("stderr reader");
    let Some(status) = status else {
        return Err(format!(
            "did not finish within {deadline:?} and was killed (pid {pid})"
        ));
    };
    Ok(Outcome {
        code: status
            .code()
            .ok_or_else(|| "ended without an exit code".to_string())?,
        stdout: String::from_utf8(stdout).map_err(|e| format!("stdout is not utf-8: {e}"))?,
        stderr: String::from_utf8(stderr).map_err(|e| format!("stderr is not utf-8: {e}"))?,
    })
}

/// The analyzer on `args`, run in the E02 directory under `CHILD_DEADLINE`; an `Err` says why it did not complete.
fn run_analyzer(
    args: &[&str],
    run: impl FnOnce(Command, Duration) -> Result<Outcome, String>,
) -> Result<Outcome, String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ffw-baseline"));
    cmd.args(args).current_dir(e02_dir());
    run(cmd, CHILD_DEADLINE)
}

/// For the helper tests, which have no case to name: the analyzer's outcome, or a panic that says why there is none.
fn run_cli(args: &[&str]) -> Outcome {
    completed(args, run_analyzer(args, run_bounded))
}

/// `outcome` if the analyzer finished, else a panic that names the command and says why not.
fn completed(args: &[&str], outcome: Result<Outcome, String>) -> Outcome {
    outcome.unwrap_or_else(|e| panic!("ffw-baseline {args:?}: {e}"))
}

/// SHA-256 of `data` as lower-case hex (FIPS 180-4), so a failure can name the digest of the files it ran on without a new
/// dependency. `sha256_matches_the_published_test_vectors` pins it.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (slot, word) in w.iter_mut().zip(block.chunks(4)) {
            *slot = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (k, wi) in K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*k)
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

/// The SHA-256 of a file, or why it could not be read.
fn digest_of(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(e) => format!("unreadable ({e})"),
    }
}

fn build() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// What one check found: the failure lines, and for each failing case or data file what a replay needs. Paths are relative to the
/// repository root, never absolute.
#[derive(Default)]
struct Report {
    failures: Vec<String>,
    retained: Vec<String>,
}

impl Report {
    fn absorb(&mut self, other: Report) {
        self.failures.extend(other.failures);
        self.retained.extend(other.retained);
    }

    fn assert_clean(&self, what: &str) {
        assert!(
            self.failures.is_empty(),
            "{what}: {} failure(s):\n{}\n\nretained for replay:\n{}",
            self.failures.len(),
            self.failures.join("\n"),
            self.retained.join("\n")
        );
    }
}

/// What a failing case retains besides its first difference (which its failure line states): the exact command that replays it,
/// the SHA-256 of its capture and of its expected file, and the crate, report-schema and capture-format versions, plus the
/// profile when an observed report exists.
fn failure_context(dir: &Path, case: &Value, observed: Option<&Value>) -> String {
    let id = case["id"].as_str().unwrap_or("?");
    let args = case_args(case);
    let mut lines = vec![
        format!(
            "{id}: replay: (cd tests/e02 && ffw-baseline {})",
            args.join(" ")
        ),
        "  whole suite: scripts/e2e/e02 --rust-only".to_string(),
    ];
    for arg in args.iter().filter(|a| a.starts_with("synthetic/")) {
        lines.push(format!(
            "  capture {arg} sha256 {}",
            digest_of(&dir.join(arg))
        ));
    }
    let capture_format = args
        .iter()
        .find(|a| a.starts_with("synthetic/"))
        .and_then(|a| std::fs::read_to_string(dir.join(a)).ok())
        .and_then(|text| {
            text.lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "n/a".to_string());
    let expected = case["expect"].as_str();
    lines.extend(expected.map(|e| format!("  expected {e} sha256 {}", digest_of(&dir.join(e)))));
    let schema = expected
        .and_then(|e| std::fs::read_to_string(dir.join(e)).ok())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|report| report["schema"].as_str().map(str::to_string))
        .unwrap_or_else(|| "n/a".to_string());
    let profile = observed
        .and_then(|report| report["profile"].as_str())
        .map(|p| format!("; profile {p}"))
        .unwrap_or_default();
    lines.push(format!(
        "  versions: franken-baseline {} (build {}); report schema {schema}; capture format {capture_format}{profile}",
        env!("CARGO_PKG_VERSION"),
        build()
    ));
    lines.join("\n")
}

/// The same for a check over a data file with no single case to replay: the test's own replay command, the digests of the data it
/// read, and the versions.
fn suite_context(dir: &Path, test: &str, data: &[&str]) -> String {
    let mut lines = vec![format!(
        "{test}: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases {test}"
    )];
    for rel in data {
        lines.push(format!("  data {rel} sha256 {}", digest_of(&dir.join(rel))));
    }
    lines.push(format!(
        "  versions: franken-baseline {} (build {})",
        env!("CARGO_PKG_VERSION"),
        build()
    ));
    lines.join("\n")
}

fn find_case<'a>(cases: &'a Value, id: &str) -> &'a Value {
    cases["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("{id} exists in cases.json"))
}

/// Everything the main test checks about one case, given what running it produced (`outcome`) and its parsed expected file, so a
/// planted outcome or expectation (a wrong number, a hung analyzer) exercises exactly the code a real run does.
fn check_case(
    dir: &Path,
    case: &Value,
    outcome: Result<Outcome, String>,
    expected: Option<Value>,
) -> Report {
    let mut report = Report::default();
    let id = case["id"].as_str().expect("case id").to_string();
    let want_code = case["exit"].as_i64().expect("exit code") as i32;
    let out = match outcome {
        Ok(out) => out,
        Err(why) => {
            report
                .failures
                .push(format!("{id}: the analyzer did not complete: {why}"));
            report.retained.push(failure_context(dir, case, None));
            return report;
        }
    };
    if out.code != want_code {
        report.failures.push(format!(
            "{id}: exit {} but expected {want_code}; stderr: {}",
            out.code,
            out.stderr.trim()
        ));
        report.retained.push(failure_context(dir, case, None));
        return report;
    }
    let mut found: Vec<String> = Vec::new();
    let missing_needle = case["stderr_contains"]
        .as_str()
        .filter(|needle| !out.stderr.contains(needle));
    if let Some(needle) = missing_needle {
        found.push(format!("stderr {:?} lacks {needle:?}", out.stderr.trim()));
    }
    found.extend(echoed(case, &out));
    found.extend(shape_problems(want_code, &out));
    found.extend(summary_problem(case, &out));
    let observed = serde_json::from_str::<Value>(out.stdout.trim()).ok();
    if let Some(expected) = expected {
        match &observed {
            None => found.push("stdout is not JSON".to_string()),
            Some(actual) => found.extend(subset_diff("$", &expected, actual)),
        }
    } else if !out.stdout.trim().is_empty() && want_code == 2 {
        found.push("an input error must not write a report to stdout".to_string());
    }
    if !found.is_empty() {
        report
            .failures
            .extend(found.into_iter().map(|line| format!("{id}: {line}")));
        report
            .retained
            .push(failure_context(dir, case, observed.as_ref()));
    }
    report
}

/// The planted strings a case says must never be printed, with the stream each one appeared in.
fn echoed(case: &Value, out: &Outcome) -> Vec<String> {
    let mut found = Vec::new();
    for (key, text) in [("stderr_lacks", &out.stderr), ("stdout_lacks", &out.stdout)] {
        if let Some(list) = case[key].as_array() {
            for needle in list.iter().filter_map(Value::as_str) {
                if text.contains(needle) {
                    found.push(format!("{key} violated: the output repeats {needle:?}"));
                }
            }
        }
    }
    found
}

/// What is wrong with the shape of a run's output: a run that writes a report prints exactly one line of JSON on stdout and
/// exactly one summary line on stderr, and a run that does not (exit 2) prints no summary.
fn shape_problems(want_code: i32, out: &Outcome) -> Vec<String> {
    let mut found = Vec::new();
    let err_lines: Vec<&str> = out.stderr.lines().collect();
    if want_code == 0 || want_code == 3 {
        let one_json_line = out.stdout.ends_with('\n') && out.stdout.matches('\n').count() == 1;
        let one_summary_line =
            err_lines.len() == 1 && err_lines.iter().all(|l| l.starts_with("ffw-baseline "));
        if !one_json_line {
            found.push(format!("stdout is not exactly one line: {:?}", out.stdout));
        }
        if !one_summary_line {
            found.push(format!(
                "stderr is not exactly one summary line: {:?}",
                out.stderr
            ));
        }
    } else if err_lines.iter().any(|l| l.starts_with("ffw-baseline ")) {
        found.push(format!(
            "a run that wrote no report printed a summary: {:?}",
            out.stderr
        ));
    }
    found
}

/// What is wrong with the summary line a run printed, against the line the case writes by hand; `None` if the case names no line
/// or the line matches exactly.
fn summary_problem(case: &Value, out: &Outcome) -> Option<String> {
    let want = format!("{}\n", case["summary"].as_str()?);
    if out.stderr == want {
        None
    } else {
        Some(format!(
            "stderr is {:?}, the case expects exactly {want:?}",
            out.stderr
        ))
    }
}

fn case_args(case: &Value) -> Vec<String> {
    case["args"]
        .as_array()
        .unwrap_or_else(|| panic!("case {} has no args", case["id"]))
        .iter()
        .map(|a| a.as_str().expect("args are strings").to_string())
        .collect()
}

#[test]
fn every_case_in_cases_json_runs_and_matches_its_expected_output() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let list = cases["cases"].as_array().expect("cases is an array");
    assert!(!list.is_empty(), "no cases would be a vacuous pass");
    let mut report = Report::default();
    for case in list {
        let args = case_args(case);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let expected = case["expect"]
            .as_str()
            .map(|file| read_json(&dir.join(file)));
        report.absorb(check_case(
            &dir,
            case,
            run_analyzer(&arg_refs, run_bounded),
            expected,
        ));
    }
    report.assert_clean("E02 cases");
}

/// Every file a case names must exist, and every file under `synthetic/` and `expected/` must be named by a case.
fn orphan_problems(dir: &Path, cases: &Value) -> Report {
    let mut report = Report::default();
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for case in cases["cases"].as_array().expect("cases") {
        let mut mine: Vec<String> = case_args(case)
            .into_iter()
            .filter(|a| a.starts_with("synthetic/"))
            .collect();
        mine.extend(case["expect"].as_str().map(str::to_string));
        let before = report.failures.len();
        for rel in mine.iter().filter(|rel| !dir.join(rel).is_file()) {
            report.failures.push(format!(
                "{}: {rel} is referenced by a case but missing",
                case["id"].as_str().unwrap_or("?")
            ));
        }
        if report.failures.len() > before {
            report.retained.push(failure_context(dir, case, None));
        }
        referenced.extend(mine);
    }
    let before = report.failures.len();
    for sub in ["synthetic", "expected"] {
        for entry in std::fs::read_dir(dir.join(sub)).expect("fixture directory") {
            let name = entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            if !referenced.contains(&format!("{sub}/{name}")) {
                report
                    .failures
                    .push(format!("{sub}/{name} is not used by any case"));
            }
        }
    }
    if report.failures.len() > before {
        report.retained.push(suite_context(
            dir,
            "no_capture_or_expected_file_is_orphaned_and_none_is_missing",
            &["cases.json"],
        ));
    }
    report
}

#[test]
fn no_capture_or_expected_file_is_orphaned_and_none_is_missing() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    orphan_problems(&dir, &cases).assert_clean("fixture files");
}

/// Case ids are unique; every invariant names existing cases or explains why it has none; every case covers an invariant.
fn invariant_problems(dir: &Path, cases: &Value) -> Report {
    let mut report = Report::default();
    let list = cases["cases"].as_array().expect("cases");
    let by_id: BTreeMap<&str, &Value> = list
        .iter()
        .filter_map(|c| c["id"].as_str().map(|id| (id, c)))
        .collect();
    let mut data_fault = false;
    let mut fault = |report: &mut Report, line: String| {
        report.failures.push(line);
        data_fault = true;
    };
    if by_id.len() != list.len() {
        fault(
            &mut report,
            "duplicate case ids (or a case without an id)".to_string(),
        );
    }
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for inv in cases["invariants"].as_array().expect("invariants") {
        let name = inv["id"].as_str().expect("invariant id");
        match (
            inv["cases"].as_array(),
            inv["inapplicable"].as_str(),
            inv["test_functions"].as_array(),
        ) {
            (Some(ids), None, None) => {
                if ids.is_empty() {
                    fault(&mut report, format!("{name} has an empty case list"));
                }
                for entry in ids {
                    match entry.as_str() {
                        Some(c) if by_id.contains_key(c) => {
                            covered.insert(c);
                        }
                        Some(c) => fault(&mut report, format!("{name} names unknown case {c}")),
                        None => fault(
                            &mut report,
                            format!("{name} lists a case id that is not a string"),
                        ),
                    }
                }
            }
            (None, Some(why), None) => {
                if why.len() <= 20 {
                    fault(&mut report, format!("{name}: explain the inapplicability"));
                }
            }
            (None, None, Some(tests)) => {
                if tests.is_empty() {
                    fault(
                        &mut report,
                        format!("{name} has an empty test-function list"),
                    );
                }
                for test in tests.iter().filter_map(Value::as_str) {
                    let found = if let Some(name) = test.strip_prefix("rust:") {
                        include_str!("e02_cases.rs")
                            .lines()
                            .any(|line| line.starts_with(&format!("fn {name}(")))
                    } else if let Some(name) = test.strip_prefix("python:") {
                        std::fs::read_to_string(dir.join("oracle.py")).is_ok_and(|source| {
                            source
                                .lines()
                                .any(|line| line.starts_with(&format!("def {name}(")))
                        })
                    } else {
                        false
                    };
                    if !found {
                        fault(
                            &mut report,
                            format!("{name} names unknown test function {test}"),
                        );
                    }
                }
                if tests.iter().any(|test| !test.is_string()) {
                    fault(
                        &mut report,
                        format!("{name} has a non-string test function"),
                    );
                }
            }
            _ => fault(
                &mut report,
                format!("{name} needs exactly one of `cases`, `test_functions` or `inapplicable`"),
            ),
        }
    }
    for (id, case) in &by_id {
        if !covered.contains(id) {
            report
                .failures
                .push(format!("case {id} covers no invariant"));
            report.retained.push(failure_context(dir, case, None));
        }
    }
    if data_fault {
        report.retained.push(suite_context(
            dir,
            "every_invariant_names_existing_cases_or_explains_why_it_has_none",
            &["cases.json"],
        ));
    }
    report
}

#[test]
fn every_invariant_names_existing_cases_or_explains_why_it_has_none() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    invariant_problems(&dir, &cases).assert_clean("invariants");
}

// -- the comparison itself, with planted differences -------------------------------------------------

#[test]
fn the_subset_matcher_accepts_extra_report_keys_and_nothing_else() {
    let expected = json!({"a": {"b": 1}, "c": [1, {"d": "x"}], "e": null});
    let ok =
        json!({"a": {"b": 1, "extra": 9}, "c": [1, {"d": "x", "more": true}], "e": null, "f": 0});
    assert_eq!(subset_diff("$", &expected, &ok), None);
}

#[test]
fn the_subset_matcher_rejects_every_kind_of_planted_difference() {
    let expected = json!({"a": {"b": 1}, "c": [1, {"d": "x"}], "e": null});
    let planted = [
        // A changed number, string and null.
        json!({"a": {"b": 2}, "c": [1, {"d": "x"}], "e": null}),
        json!({"a": {"b": 1}, "c": [1, {"d": "y"}], "e": null}),
        json!({"a": {"b": 1}, "c": [1, {"d": "x"}], "e": 0}),
        // A missing key, nested and top-level.
        json!({"a": {}, "c": [1, {"d": "x"}], "e": null}),
        json!({"a": {"b": 1}, "c": [1, {"d": "x"}]}),
        // An array that is too short or too long.
        json!({"a": {"b": 1}, "c": [1], "e": null}),
        json!({"a": {"b": 1}, "c": [1, {"d": "x"}, 3], "e": null}),
        // A type change.
        json!({"a": [1], "c": [1, {"d": "x"}], "e": null}),
        json!({"a": {"b": "1"}, "c": [1, {"d": "x"}], "e": null}),
    ];
    for (i, p) in planted.iter().enumerate() {
        assert!(
            subset_diff("$", &expected, p).is_some(),
            "planted difference #{i} was accepted: {p}"
        );
    }
}

#[test]
fn a_real_report_fails_against_a_planted_wrong_expectation() {
    // The clean capture really has full coverage; an expectation that says otherwise must not match.
    let out = run_cli(&["series", "synthetic/clean.cap"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let actual: Value = serde_json::from_str(out.stdout.trim()).expect("report is JSON");
    let right = json!({"denominators": {"coverage_ppm": 1_000_000}});
    let wrong = json!({"denominators": {"coverage_ppm": 999_999}});
    assert_eq!(subset_diff("$", &right, &actual), None);
    assert!(subset_diff("$", &wrong, &actual).is_some());
}

#[test]
fn the_cli_never_reports_a_bare_path_in_an_error() {
    let out = run_cli(&["series", "synthetic/no_such_file.cap"]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("no_such_file.cap"));
    assert!(
        !out.stderr.contains("synthetic/"),
        "diagnostics name the file, not its directory"
    );
    assert!(out.stdout.is_empty());
}

// -- redaction: the planted identifiers are real, the classifier agrees with its vectors ----------------

/// Every string a case says must never be echoed is really in its capture, or the check would pass vacuously.
fn echo_plant_problems(dir: &Path, cases: &Value) -> Report {
    let mut report = Report::default();
    let mut checked = 0;
    for case in cases["cases"].as_array().expect("cases") {
        let mut needles: Vec<&str> = Vec::new();
        for key in ["stderr_lacks", "stdout_lacks"] {
            if let Some(list) = case[key].as_array() {
                needles.extend(list.iter().filter_map(Value::as_str));
            }
        }
        let capture_text: String = case_args(case)
            .iter()
            .filter(|a| a.starts_with("synthetic/"))
            .map(|a| std::fs::read_to_string(dir.join(a)).expect("capture file"))
            .collect();
        for needle in needles {
            if !capture_text.contains(needle) {
                report.failures.push(format!(
                    "{}: {needle:?} is not in the capture, so 'never echoed' would pass vacuously",
                    case["id"].as_str().unwrap_or("?")
                ));
                report.retained.push(failure_context(dir, case, None));
            }
            checked += 1;
        }
    }
    if checked == 0 {
        report
            .failures
            .push("no case names a string that must not be echoed".to_string());
        report.retained.push(suite_context(
            dir,
            "every_string_a_case_says_is_never_echoed_is_really_in_its_capture",
            &["cases.json"],
        ));
    }
    report
}

#[test]
fn every_string_a_case_says_is_never_echoed_is_really_in_its_capture() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    echo_plant_problems(&dir, &cases).assert_clean("never-echoed strings");
}

#[test]
fn the_never_echoed_check_catches_a_planted_echo() {
    let case =
        json!({"id": "x", "stderr_lacks": ["192.0.2.17"], "stdout_lacks": ["00-00-5E-00-53-01"]});
    let leaky = Outcome {
        code: 2,
        stdout: "{\"profile\":\"00-00-5E-00-53-01\"}".to_string(),
        stderr: "line 2: BadIdentifier(\"192.0.2.17\")".to_string(),
    };
    assert_eq!(echoed(&case, &leaky).len(), 2);
    let clean = Outcome {
        code: 2,
        stdout: String::new(),
        stderr: "line 2: SiteIdentifier { field: \"profile\", class: \"ipv4\" }".to_string(),
    };
    assert!(echoed(&case, &clean).is_empty());
}

/// The classifier answers each vector as the vector says.
fn vector_problems(dir: &Path, vectors: &Value) -> Report {
    let mut report = Report::default();
    let list = vectors["vectors"].as_array().expect("vectors");
    if list.len() < 20 {
        report
            .failures
            .push("too few vectors to mean anything".to_string());
    }
    for v in list {
        let text = v["text"].as_str().expect("text");
        let want = v["class"].as_str();
        let got = franken_baseline::redact::classify(text).map(|c| c.as_str());
        if got != want {
            report.failures.push(format!(
                "{text:?}: classify says {got:?}, the vector says {want:?}"
            ));
        }
    }
    if !report.failures.is_empty() {
        report.retained.push(suite_context(
            dir,
            "the_redaction_vectors_agree_with_the_classifier",
            &["redaction_vectors.json"],
        ));
    }
    report
}

#[test]
fn the_redaction_vectors_agree_with_the_classifier() {
    let dir = e02_dir();
    let vectors = read_json(&dir.join("redaction_vectors.json"));
    vector_problems(&dir, &vectors).assert_clean("redaction vectors");
}

// -- the summary line ------------------------------------------------------------------------------------

#[test]
fn the_summary_checks_reject_planted_wrong_output() {
    let case = json!({"id": "x", "summary": "ffw-baseline series: verdict qualified; right"});
    let right = Outcome {
        code: 0,
        stdout: "{\"schema\":1}\n".to_string(),
        stderr: "ffw-baseline series: verdict qualified; right\n".to_string(),
    };
    assert_eq!(summary_problem(&case, &right), None);
    assert!(shape_problems(0, &right).is_empty());
    // A summary that differs, a case with no summary to check, a second stderr line, a second stdout line, and an exit-2 run
    // that printed a summary are each caught or ignored as they should be.
    let wrong = Outcome {
        stderr: "ffw-baseline series: verdict not_qualified; right\n".to_string(),
        ..right_clone(&right)
    };
    assert!(summary_problem(&case, &wrong).is_some());
    assert_eq!(summary_problem(&json!({"id": "y"}), &wrong), None);
    let two_err = Outcome {
        stderr: "ffw-baseline series: verdict qualified; right\nextra\n".to_string(),
        ..right_clone(&right)
    };
    assert!(summary_problem(&case, &two_err).is_some());
    assert!(!shape_problems(0, &two_err).is_empty());
    let two_out = Outcome {
        stdout: "{}\n{}\n".to_string(),
        ..right_clone(&right)
    };
    assert!(!shape_problems(0, &two_out).is_empty());
    assert!(!shape_problems(2, &right).is_empty());
}

fn right_clone(o: &Outcome) -> Outcome {
    Outcome {
        code: o.code,
        stdout: o.stdout.clone(),
        stderr: o.stderr.clone(),
    }
}

/// Every summary line a case writes by hand is one short plain line that starts as a summary does.
fn summary_line_problems(dir: &Path, cases: &Value) -> Report {
    let mut report = Report::default();
    let mut seen = 0;
    for case in cases["cases"].as_array().expect("cases") {
        let Some(line) = case["summary"].as_str() else {
            continue;
        };
        seen += 1;
        let id = case["id"].as_str().unwrap_or("?");
        let before = report.failures.len();
        if !line.starts_with("ffw-baseline ") {
            report.failures.push(format!(
                "{id}: summary {line:?} does not start with \"ffw-baseline \""
            ));
        }
        if !line.is_ascii() || line.contains('\n') {
            report.failures.push(format!(
                "{id}: summary {line:?} is not plain ASCII on one line"
            ));
        }
        if line.len() > 400 {
            report.failures.push(format!(
                "{id}: summary is not concise ({} bytes): {line}",
                line.len()
            ));
        }
        if report.failures.len() > before {
            report.retained.push(failure_context(dir, case, None));
        }
    }
    if seen == 0 {
        report
            .failures
            .push("no case names a summary line".to_string());
        report.retained.push(suite_context(
            dir,
            "every_summary_in_cases_json_is_one_short_plain_line",
            &["cases.json"],
        ));
    }
    report
}

#[test]
fn every_summary_in_cases_json_is_one_short_plain_line() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    summary_line_problems(&dir, &cases).assert_clean("summary lines");
}

// -- what a failure retains: a planted failure for every site, each with its remove-the-plant control --------

#[test]
fn sha256_matches_the_published_test_vectors() {
    let million_a = "a".repeat(1_000_000);
    for (message, want) in [
        (
            &b""[..],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            &b"abc"[..],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            million_a.as_bytes(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ] {
        assert_eq!(sha256_hex(message), want, "{} bytes", message.len());
    }
}

/// The text a retained context must carry for the case `id`, worked out here from the files themselves.
fn wanted_context(dir: &Path, id: &str, cli: &str, files: &[&str]) -> Vec<String> {
    let mut wants = vec![
        format!("{id}: replay: (cd tests/e02 && ffw-baseline {cli})"),
        "whole suite: scripts/e2e/e02 --rust-only".to_string(),
        format!("franken-baseline {}", env!("CARGO_PKG_VERSION")),
    ];
    for rel in files {
        let kind = if rel.starts_with("expected/") {
            "expected"
        } else {
            "capture"
        };
        wants.push(format!(
            "{kind} {rel} sha256 {}",
            sha256_hex(&std::fs::read(dir.join(rel)).expect("a committed file"))
        ));
    }
    wants
}

fn assert_has_all(context: &str, wants: &[String]) {
    for want in wants {
        assert!(
            context.contains(want.as_str()),
            "missing {want:?} in:\n{context}"
        );
    }
    assert!(
        !context.contains("/Users/"),
        "a retained path must be relative: {context}"
    );
}

#[test]
fn a_planted_wrong_expectation_fails_the_case_and_retains_its_replay_context() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let case = find_case(&cases, "E02-S-CLEAN");
    let args = case_args(case);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let truth = read_json(&dir.join(case["expect"].as_str().expect("expect")));
    // The plant: one wrong number in the hand-written expectation.
    let mut planted = truth.clone();
    planted["denominators"]["coverage_ppm"] = json!(1_000_001);
    let report = check_case(&dir, case, run_analyzer(&refs, run_bounded), Some(planted));
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
        report.failures[0].starts_with("E02-S-CLEAN: ")
            && report.failures[0].contains("expected 1000001, report has 1000000"),
        "{}",
        report.failures[0]
    );
    let mut wants = wanted_context(
        &dir,
        "E02-S-CLEAN",
        "series synthetic/clean.cap",
        &["synthetic/clean.cap", "expected/clean.json"],
    );
    wants.push("report schema ffw.baseline.series-report.v1".to_string());
    wants.push("capture format ffw.baseline.capture.v1".to_string());
    wants.push("profile synthetic-clean-v1".to_string());
    assert_has_all(&report.retained.join("\n"), &wants);
    // The plant removed: the same case passes, and nothing is retained.
    let clean = check_case(&dir, case, run_analyzer(&refs, run_bounded), Some(truth));
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_planted_missing_file_and_a_planted_orphan_are_reported_with_their_context() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    // Plant 1: a case that names a capture that is not there.
    let mut missing = cases.clone();
    missing["cases"].as_array_mut().expect("cases")[0]["args"] =
        json!(["series", "synthetic/no_such_capture.cap"]);
    let report = orphan_problems(&dir, &missing);
    assert!(
        report.failures.iter().any(|l| l.starts_with(
            "E02-S-CLEAN: synthetic/no_such_capture.cap is referenced by a case but missing"
        )),
        "{:?}",
        report.failures
    );
    assert!(
        report.retained.join("\n").contains(
            "E02-S-CLEAN: replay: (cd tests/e02 && ffw-baseline series synthetic/no_such_capture.cap)"
        ),
        "{:?}",
        report.retained
    );
    // Plant 2: the only case that names a fixture is dropped, so the fixture is an orphan.
    let mut orphaned = cases.clone();
    orphaned["cases"]
        .as_array_mut()
        .expect("cases")
        .retain(|c| c["id"].as_str() != Some("E02-E-LONGLINE"));
    let report = orphan_problems(&dir, &orphaned);
    assert!(
        report
            .failures
            .iter()
            .any(|l| l == "synthetic/longline.cap is not used by any case"),
        "{:?}",
        report.failures
    );
    let mut wants = vec![
        "no_capture_or_expected_file_is_orphaned_and_none_is_missing: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases no_capture_or_expected_file_is_orphaned_and_none_is_missing".to_string(),
    ];
    wants.push(format!(
        "data cases.json sha256 {}",
        sha256_hex(&std::fs::read(dir.join("cases.json")).expect("cases.json"))
    ));
    assert_has_all(&report.retained.join("\n"), &wants);
    // The plants removed: the real case file is clean.
    let clean = orphan_problems(&dir, &cases);
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_planted_invariant_fault_is_reported_with_its_case_context() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    // Plant 1: an invariant names a case that does not exist.
    let mut unknown = cases.clone();
    unknown["invariants"].as_array_mut().expect("invariants")[0]["cases"]
        .as_array_mut()
        .expect("the first invariant maps cases")
        .push(json!("E02-NO-SUCH-CASE"));
    let report = invariant_problems(&dir, &unknown);
    assert!(
        report
            .failures
            .iter()
            .any(|l| l.ends_with("names unknown case E02-NO-SUCH-CASE")),
        "{:?}",
        report.failures
    );
    assert_has_all(
        &report.retained.join("\n"),
        &[
            "every_invariant_names_existing_cases_or_explains_why_it_has_none: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases every_invariant_names_existing_cases_or_explains_why_it_has_none".to_string(),
            format!(
                "data cases.json sha256 {}",
                sha256_hex(&std::fs::read(dir.join("cases.json")).expect("cases.json"))
            ),
        ],
    );
    // Plant 2: the only invariant that covers a case is removed, so the case covers none.
    let mut uncovered = cases.clone();
    uncovered["invariants"]
        .as_array_mut()
        .expect("invariants")
        .retain(|i| i["id"].as_str() != Some("INV-LOG-BOUNDED"));
    let report = invariant_problems(&dir, &uncovered);
    assert!(
        report
            .failures
            .iter()
            .any(|l| l == "case E02-E-LONGLINE covers no invariant"),
        "{:?}",
        report.failures
    );
    let wants = wanted_context(
        &dir,
        "E02-E-LONGLINE",
        "series synthetic/longline.cap",
        &["synthetic/longline.cap"],
    );
    assert_has_all(&report.retained.join("\n"), &wants);
    // The plants removed: the real case file is clean.
    let clean = invariant_problems(&dir, &cases);
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_planted_vacuous_never_echoed_string_is_reported_with_its_case_context() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let mut planted = cases.clone();
    for case in planted["cases"].as_array_mut().expect("cases") {
        if case["id"].as_str() == Some("E02-S-CLEAN") {
            case["stdout_lacks"] = json!(["definitely-not-in-the-capture"]);
        }
    }
    let report = echo_plant_problems(&dir, &planted);
    assert!(
        report.failures.iter().any(|l| l
            .starts_with("E02-S-CLEAN: \"definitely-not-in-the-capture\" is not in the capture")),
        "{:?}",
        report.failures
    );
    let wants = wanted_context(
        &dir,
        "E02-S-CLEAN",
        "series synthetic/clean.cap",
        &["synthetic/clean.cap"],
    );
    assert_has_all(&report.retained.join("\n"), &wants);
    let clean = echo_plant_problems(&dir, &cases);
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_planted_wrong_vector_is_reported_with_its_replay_context() {
    let dir = e02_dir();
    let vectors = read_json(&dir.join("redaction_vectors.json"));
    let mut planted = vectors.clone();
    planted["vectors"][0]["class"] = json!("mac");
    let report = vector_problems(&dir, &planted);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
        report.failures[0].contains("classify says Some(\"ipv4\"), the vector says Some(\"mac\")"),
        "{}",
        report.failures[0]
    );
    let wants = vec![
        "the_redaction_vectors_agree_with_the_classifier: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases the_redaction_vectors_agree_with_the_classifier".to_string(),
        format!(
            "data redaction_vectors.json sha256 {}",
            sha256_hex(&std::fs::read(dir.join("redaction_vectors.json")).expect("vectors"))
        ),
        format!("franken-baseline {}", env!("CARGO_PKG_VERSION")),
    ];
    assert_has_all(&report.retained.join("\n"), &wants);
    let clean = vector_problems(&dir, &vectors);
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_planted_bad_summary_is_reported_with_its_case_context() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let mut planted = cases.clone();
    for case in planted["cases"].as_array_mut().expect("cases") {
        if case["id"].as_str() == Some("E02-SUM-QUALIFIED") {
            case["summary"] = json!("not a summary\nand a second line");
        }
    }
    let report = summary_line_problems(&dir, &planted);
    assert!(
        report
            .failures
            .iter()
            .any(|l| l.starts_with("E02-SUM-QUALIFIED: summary")
                && l.contains("does not start with")),
        "{:?}",
        report.failures
    );
    assert!(
        report
            .failures
            .iter()
            .any(|l| l.starts_with("E02-SUM-QUALIFIED: summary")
                && l.contains("is not plain ASCII on one line")),
        "{:?}",
        report.failures
    );
    let wants = wanted_context(
        &dir,
        "E02-SUM-QUALIFIED",
        "series synthetic/clean.cap",
        &["synthetic/clean.cap", "expected/clean.json"],
    );
    assert_has_all(&report.retained.join("\n"), &wants);
    let clean = summary_line_problems(&dir, &cases);
    assert!(
        clean.failures.is_empty() && clean.retained.is_empty(),
        "{:?}",
        clean.failures
    );
}

#[test]
fn a_check_that_found_nothing_to_check_is_reported_with_its_suite_context() {
    let dir = e02_dir();
    // The plant: a case list with no never-echoed string and no summary line. The plants removed are the two real-file controls above.
    let report = echo_plant_problems(&dir, &json!({"cases": []}));
    assert!(
        report
            .failures
            .iter()
            .any(|l| l == "no case names a string that must not be echoed"),
        "{:?}",
        report.failures
    );
    assert_has_all(
        &report.retained.join("\n"),
        &["every_string_a_case_says_is_never_echoed_is_really_in_its_capture: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases every_string_a_case_says_is_never_echoed_is_really_in_its_capture".to_string()],
    );
    let report = summary_line_problems(&dir, &json!({"cases": []}));
    assert!(
        report
            .failures
            .iter()
            .any(|l| l == "no case names a summary line"),
        "{:?}",
        report.failures
    );
    assert_has_all(
        &report.retained.join("\n"),
        &["every_summary_in_cases_json_is_one_short_plain_line: replay: RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline --test e02_cases every_summary_in_cases_json_is_one_short_plain_line".to_string()],
    );
}

/// The message of a caught panic, or `None` if nothing panicked.
fn panic_text(caught: Result<(), Box<dyn std::any::Any + Send>>) -> Option<String> {
    let payload = caught.err()?;
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
}

#[test]
fn the_helpers_print_the_failure_and_what_was_retained_for_it() {
    // What each site finally prints is `assert_clean`: the failure lines, then the retained context.
    let planted = Report {
        failures: vec!["E02-X: planted failure".to_string()],
        retained: vec![
            "E02-X: replay: (cd tests/e02 && ffw-baseline series synthetic/x.cap)".to_string(),
        ],
    };
    let message = panic_text(std::panic::catch_unwind(|| {
        planted.assert_clean("planted check")
    }))
    .expect("a report with a failure panics");
    for want in [
        "planted check: 1 failure(s):",
        "E02-X: planted failure",
        "retained for replay:",
        "E02-X: replay: (cd tests/e02 && ffw-baseline series synthetic/x.cap)",
    ] {
        assert!(message.contains(want), "missing {want:?} in: {message}");
    }
    // The plant removed: a report with nothing in it does not panic.
    assert!(
        panic_text(std::panic::catch_unwind(|| {
            Report::default().assert_clean("clean check")
        }))
        .is_none()
    );
    // A helper-run analyzer that did not finish panics naming its command and the reason; one that finished is passed through.
    let message = panic_text(std::panic::catch_unwind(|| {
        completed(
            &["series", "synthetic/clean.cap"],
            Err("did not finish within 60s and was killed (pid 1)".to_string()),
        );
    }))
    .expect("an analyzer that did not finish panics");
    assert!(
        message.contains(
            "ffw-baseline [\"series\", \"synthetic/clean.cap\"]: did not finish within 60s and was killed"
        ),
        "{message}"
    );
    let finished = completed(
        &["series"],
        Ok(Outcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }),
    );
    assert_eq!(finished.code, 0);
}

/// Whether process `pid` exists, by `kill -0`.
fn is_running(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn a_hung_analyzer_fails_its_case_with_the_replay_line_and_leaves_no_child_running() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let case = find_case(&cases, "E02-S-CLEAN");
    // The plant: an "analyzer" that never finishes.
    let mut hung = Command::new("sleep");
    hung.arg("30");
    let started = Instant::now();
    let outcome = run_bounded(hung, Duration::from_millis(500));
    let why = match &outcome {
        Err(why) => why.clone(),
        Ok(_) => panic!("a 30 s sleep cannot finish within 0.5 s"),
    };
    let report = check_case(&dir, case, outcome, None);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the hung child was not killed promptly"
    );
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(
        report.failures[0]
            .starts_with("E02-S-CLEAN: the analyzer did not complete: did not finish within"),
        "{}",
        report.failures[0]
    );
    let wants = wanted_context(
        &dir,
        "E02-S-CLEAN",
        "series synthetic/clean.cap",
        &["synthetic/clean.cap", "expected/clean.json"],
    );
    assert_has_all(&report.retained.join("\n"), &wants);
    // The child is gone. The probe is shown to see a live child first, or "gone" would prove nothing.
    let mut live = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .expect("sleep starts");
    assert!(is_running(live.id()), "`kill -0` cannot see a live child");
    let _ = live.kill();
    let _ = live.wait();
    let pid: u32 = why
        .rsplit("(pid ")
        .next()
        .and_then(|rest| rest.trim_end_matches(')').parse().ok())
        .unwrap_or_else(|| panic!("no pid in {why:?}"));
    assert!(!is_running(pid), "the hung child {pid} was left running");
    // The plant removed: the real analyzer finishes well within the deadline, and the case passes.
    let args = case_args(case);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let expected = read_json(&dir.join(case["expect"].as_str().expect("expect")));
    let clean = check_case(&dir, case, run_analyzer(&refs, run_bounded), Some(expected));
    assert!(clean.failures.is_empty(), "{:?}", clean.failures);
}

#[test]
fn the_analyzer_entrypoint_wires_its_finite_deadline_and_exact_command() {
    let result = run_analyzer(&["series", "synthetic/clean.cap"], |command, deadline| {
        assert_eq!(deadline, Duration::from_secs(60));
        assert!(deadline < Duration::MAX);
        assert_eq!(
            command.get_program(),
            Path::new(env!("CARGO_BIN_EXE_ffw-baseline")).as_os_str()
        );
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_str().expect("UTF-8 argument"))
                .collect::<Vec<_>>(),
            ["series", "synthetic/clean.cap"]
        );
        assert_eq!(command.get_current_dir(), Some(e02_dir().as_path()));
        Err("planted runner refusal".to_string())
    });
    assert!(matches!(result, Err(ref why) if why == "planted runner refusal"));
    // Remove the plant: the same entry point reaches the real bounded runner and analyzer.
    assert_eq!(
        run_analyzer(&["series", "synthetic/clean.cap"], run_bounded)
            .expect("analyzer finishes")
            .code,
        0
    );
}
