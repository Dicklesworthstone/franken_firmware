//! E02 (ffw-za4) end-to-end cases: the real `ffw-baseline` binary over the synthetic captures in
//! `tests/e02/`, compared with expected outputs that were worked out by hand (and cross-checked by the
//! independent Python oracle, `tests/e02/oracle.py`), never produced by this analyzer.
//!
//! Run centrally: `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-baseline`.
//!
//! An expected file is a SUBSET of the report: every key it names must match exactly, extra keys in the
//! report are ignored, arrays must have the same length and match element by element. The subset rule
//! is itself tested below with planted differences, so a matcher that accepts anything would fail.

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
            if arg.starts_with("captures/") {
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
    for sub in ["captures", "expected"] {
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
    let out = run_cli(&["series", "captures/clean.cap"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let actual: Value = serde_json::from_str(out.stdout.trim()).expect("report is JSON");
    let right = json!({"denominators": {"coverage_ppm": 1_000_000}});
    let wrong = json!({"denominators": {"coverage_ppm": 999_999}});
    assert_eq!(subset_diff("$", &right, &actual), None);
    assert!(subset_diff("$", &wrong, &actual).is_some());
}

#[test]
fn the_cli_never_reports_a_bare_path_in_an_error() {
    let out = run_cli(&["series", "captures/no_such_file.cap"]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("no_such_file.cap"));
    assert!(
        !out.stderr.contains("captures/"),
        "diagnostics name the file, not its directory"
    );
    assert!(out.stdout.is_empty());
}
