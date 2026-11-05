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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn run_cli(args: &[&str]) -> Outcome {
    let out = Command::new(env!("CARGO_BIN_EXE_ffw-baseline"))
        .args(args)
        .current_dir(e02_dir())
        .output()
        .expect("the ffw-baseline binary starts");
    Outcome {
        code: out.status.code().expect("exited normally"),
        stdout: String::from_utf8(out.stdout).expect("utf-8 stdout"),
        stderr: String::from_utf8(out.stderr).expect("utf-8 stderr"),
    }
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
    let mut failures: Vec<String> = Vec::new();
    for case in list {
        let id = case["id"].as_str().expect("case id").to_string();
        let args = case_args(case);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run_cli(&arg_refs);
        let want_code = case["exit"].as_i64().expect("exit code") as i32;
        if out.code != want_code {
            failures.push(format!(
                "{id}: exit {} but expected {want_code}; stderr: {}",
                out.code,
                out.stderr.trim()
            ));
            continue;
        }
        let missing_needle = case["stderr_contains"]
            .as_str()
            .filter(|needle| !out.stderr.contains(needle));
        if let Some(needle) = missing_needle {
            failures.push(format!(
                "{id}: stderr {:?} lacks {needle:?}",
                out.stderr.trim()
            ));
        }
        for violation in echoed(case, &out) {
            failures.push(format!("{id}: {violation}"));
        }
        for problem in shape_problems(want_code, &out) {
            failures.push(format!("{id}: {problem}"));
        }
        if let Some(problem) = summary_problem(case, &out) {
            failures.push(format!("{id}: {problem}"));
        }
        if let Some(expected_file) = case["expect"].as_str() {
            let expected = read_json(&dir.join(expected_file));
            match serde_json::from_str::<Value>(out.stdout.trim()) {
                Err(e) => failures.push(format!("{id}: stdout is not JSON: {e}")),
                Ok(actual) => {
                    if let Some(diff) = subset_diff("$", &expected, &actual) {
                        failures.push(format!("{id}: {diff}"));
                    }
                }
            }
        } else if !out.stdout.trim().is_empty() && want_code == 2 {
            failures.push(format!(
                "{id}: an input error must not write a report to stdout"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn no_capture_or_expected_file_is_orphaned_and_none_is_missing() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for case in cases["cases"].as_array().expect("cases") {
        for arg in case_args(case) {
            if arg.starts_with("synthetic/") {
                referenced.insert(arg);
            }
        }
        if let Some(e) = case["expect"].as_str() {
            referenced.insert(e.to_string());
        }
    }
    for rel in &referenced {
        assert!(
            dir.join(rel).is_file(),
            "{rel} is referenced by a case but missing"
        );
    }
    for sub in ["synthetic", "expected"] {
        for entry in std::fs::read_dir(dir.join(sub)).expect("fixture directory") {
            let name = entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            assert!(
                referenced.contains(&format!("{sub}/{name}")),
                "{sub}/{name} is not used by any case"
            );
        }
    }
}

#[test]
fn every_invariant_names_existing_cases_or_explains_why_it_has_none() {
    let cases = read_json(&e02_dir().join("cases.json"));
    let ids: BTreeSet<&str> = cases["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| c["id"].as_str().expect("id"))
        .collect();
    assert_eq!(
        ids.len(),
        cases["cases"].as_array().expect("cases").len(),
        "duplicate case ids"
    );
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for inv in cases["invariants"].as_array().expect("invariants") {
        let name = inv["id"].as_str().expect("invariant id");
        match (inv["cases"].as_array(), inv["inapplicable"].as_str()) {
            (Some(list), None) => {
                assert!(!list.is_empty(), "{name} has an empty case list");
                for c in list {
                    let c = c.as_str().expect("case id");
                    assert!(ids.contains(c), "{name} names unknown case {c}");
                    covered.insert(c);
                }
            }
            (None, Some(why)) => assert!(why.len() > 20, "{name}: explain the inapplicability"),
            _ => panic!("{name} needs exactly one of `cases` or `inapplicable`"),
        }
    }
    for id in &ids {
        assert!(covered.contains(id), "case {id} covers no invariant");
    }
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

#[test]
fn every_string_a_case_says_is_never_echoed_is_really_in_its_capture() {
    let dir = e02_dir();
    let cases = read_json(&dir.join("cases.json"));
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
            assert!(
                capture_text.contains(needle),
                "{}: {needle:?} is not in the capture, so 'never echoed' would pass vacuously",
                case["id"]
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no case names a string that must not be echoed"
    );
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

#[test]
fn the_redaction_vectors_agree_with_the_classifier() {
    let vectors = read_json(&e02_dir().join("redaction_vectors.json"));
    let list = vectors["vectors"].as_array().expect("vectors");
    assert!(list.len() >= 20, "too few vectors to mean anything");
    for v in list {
        let text = v["text"].as_str().expect("text");
        let want = v["class"].as_str();
        let got = franken_baseline::redact::classify(text).map(|c| c.as_str());
        assert_eq!(got, want, "{text:?}");
    }
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

#[test]
fn every_summary_in_cases_json_is_one_short_plain_line() {
    let cases = read_json(&e02_dir().join("cases.json"));
    let mut seen = 0;
    for case in cases["cases"].as_array().expect("cases") {
        if let Some(line) = case["summary"].as_str() {
            seen += 1;
            assert!(line.starts_with("ffw-baseline "), "{line}");
            assert!(line.is_ascii() && !line.contains('\n'), "{line}");
            assert!(line.len() <= 400, "not concise: {line}");
        }
    }
    assert!(seen > 0, "no case names a summary line");
}
