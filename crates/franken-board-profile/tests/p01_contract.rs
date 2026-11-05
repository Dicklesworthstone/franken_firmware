//! P01 (`ffw-h3g`): replays the shared contract vectors against the typed build contract.
//!
//! The vectors (`tests/vectors/p01_contract_vectors.json`) are written by hand from the rules in
//! `docs/contracts/p01.md` and are replayed, unchanged, by the independent Python reference
//! (`tests/p01/run_cases.py`). Each vector mutates the declared workspace contract
//! (`tests/vectors/p01_workspace_contract.json`) with set/remove/push operations and says exactly which
//! violations must result. The unmutated contract must be valid first, so a rejection can only come from
//! the planted defect.

use franken_board_profile::build_contract::{
    ContractError, ObservedArtifact, WorkspaceContract, canonical_json_value, code,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

const BASE: &str = include_str!("vectors/p01_workspace_contract.json");
const VECTORS: &str = include_str!("vectors/p01_contract_vectors.json");

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema: String,
    base_digest: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct ExpectAdmission {
    #[serde(default)]
    artifact: Option<String>,
    qualified: bool,
    blocks: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    kind: String,
    ops: Vec<Value>,
    #[serde(default)]
    artifact: Option<String>,
    #[serde(default)]
    rows: Vec<Value>,
    #[serde(default)]
    require_all: bool,
    #[serde(default)]
    expect_codes: Vec<String>,
    #[serde(default)]
    expect_subjects: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    expect_admission: Option<ExpectAdmission>,
    #[serde(default)]
    expect: Option<ExpectAdmission>,
    #[serde(default)]
    expect_digest: Option<String>,
    #[serde(default)]
    expect_changed: bool,
}

fn unescape(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

/// Index of the list element a path segment names: `key=value` selects by a string field, otherwise
/// the segment is a plain index.
fn element_index(items: &[Value], segment: &str) -> Result<usize, String> {
    if let Some((key, value)) = segment.split_once('=') {
        return items
            .iter()
            .position(|item| item.get(key).and_then(Value::as_str) == Some(value))
            .ok_or_else(|| format!("no element with {key}={value:?}"));
    }
    let index: usize = segment
        .parse()
        .map_err(|_| format!("{segment:?} is not an index"))?;
    if index < items.len() {
        Ok(index)
    } else {
        Err(format!("index {index} is out of range"))
    }
}

fn step<'a>(node: &'a mut Value, segment: &str) -> Result<&'a mut Value, String> {
    let segment = unescape(segment);
    match node {
        Value::Object(map) => map
            .get_mut(segment.as_str())
            .ok_or_else(|| format!("no key {segment:?}")),
        Value::Array(items) => {
            let index = element_index(items, &segment)?;
            Ok(&mut items[index])
        }
        _ => Err(format!("cannot step into a scalar at {segment:?}")),
    }
}

fn walk<'a>(doc: &'a mut Value, segments: &[&str]) -> Result<&'a mut Value, String> {
    let mut node = doc;
    for segment in segments {
        node = step(node, segment)?;
    }
    Ok(node)
}

fn apply_op(doc: &mut Value, op: &Value) -> Result<(), String> {
    let kind = op
        .get("op")
        .and_then(Value::as_str)
        .ok_or("operation without an op")?;
    let path = op
        .get("path")
        .and_then(Value::as_str)
        .ok_or("operation without a path")?;
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match kind {
        "push" => {
            let value = op.get("value").cloned().ok_or("push without a value")?;
            let target = walk(doc, &segments)?;
            target
                .as_array_mut()
                .ok_or("push target is not a list")?
                .push(value);
            Ok(())
        }
        "set" | "remove" => {
            let (last, parents) = segments.split_last().ok_or("empty path")?;
            let value = if kind == "set" {
                op.get("value").cloned().ok_or("set without a value")?
            } else {
                Value::Null
            };
            let last = unescape(last);
            match walk(doc, parents)? {
                Value::Object(map) => {
                    if kind == "set" {
                        map.insert(last, value);
                    } else if map.remove(last.as_str()).is_none() {
                        return Err(format!("no key {last:?}"));
                    }
                }
                Value::Array(items) => {
                    let index = element_index(items, &last)?;
                    if kind == "set" {
                        items[index] = value;
                    } else {
                        items.remove(index);
                    }
                }
                _ => return Err("parent is not a container".to_string()),
            }
            Ok(())
        }
        other => Err(format!("unknown op {other:?}")),
    }
}

fn mutated(base: &Value, ops: &[Value]) -> Result<Value, String> {
    let mut doc = base.clone();
    for op in ops {
        apply_op(&mut doc, op)?;
    }
    Ok(doc)
}

fn codes_of(errs: &[ContractError]) -> Vec<String> {
    let mut codes: Vec<String> = errs.iter().map(|err| err.code.to_string()).collect();
    codes.sort();
    codes.dedup();
    codes
}

fn subjects_of(errs: &[ContractError]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for err in errs {
        out.entry(err.code.to_string())
            .or_default()
            .push(err.subject.clone());
    }
    for subjects in out.values_mut() {
        subjects.sort();
        subjects.dedup();
    }
    out
}

fn check_subjects(vector: &Vector, errs: &[ContractError], failures: &mut Vec<String>) {
    let got = subjects_of(errs);
    for (code, want) in &vector.expect_subjects {
        let mut want = want.clone();
        want.sort();
        if got.get(code) != Some(&want) {
            failures.push(format!(
                "{}: subjects of {code}: got {:?}, want {want:?}",
                vector.id,
                got.get(code)
            ));
        }
    }
}

fn base_value() -> Value {
    serde_json::from_str(BASE).expect("the declared contract is JSON")
}

fn run_vector(base: &Value, base_digest: &str, vector: &Vector, failures: &mut Vec<String>) {
    let doc = match mutated(base, &vector.ops) {
        Ok(doc) => doc,
        Err(err) => {
            failures.push(format!("{}: operation failed: {err}", vector.id));
            return;
        }
    };
    let contract = WorkspaceContract::from_value(doc);
    if vector.kind == "parse" {
        match contract {
            Err(err) if err.code == code::PARSE_ERROR => {}
            other => failures.push(format!(
                "{}: expected parse_error, got {:?}",
                vector.id,
                other.map(|_| "a contract")
            )),
        }
        return;
    }
    let contract = match contract {
        Ok(contract) => contract,
        Err(err) => {
            failures.push(format!("{}: unexpected {err}", vector.id));
            return;
        }
    };
    match vector.kind.as_str() {
        "digest" => {
            let got = contract.digest();
            if let Some(want) = &vector.expect_digest {
                if &got != want {
                    failures.push(format!("{}: digest {got}, want {want}", vector.id));
                }
            } else if vector.expect_changed && got == base_digest {
                failures.push(format!("{}: digest did not change", vector.id));
            }
        }
        "validate" => {
            let errs = contract.validate();
            if codes_of(&errs) != vector.expect_codes {
                failures.push(format!(
                    "{}: codes {:?}, want {:?}",
                    vector.id,
                    codes_of(&errs),
                    vector.expect_codes
                ));
            }
            check_subjects(vector, &errs, failures);
            if let Some(want) = &vector.expect_admission {
                check_admission(&contract, &vector.id, want, failures);
            }
        }
        "admission" => match (&vector.artifact, &vector.expect) {
            (Some(artifact), Some(want)) => {
                let want = ExpectAdmission {
                    artifact: Some(artifact.clone()),
                    qualified: want.qualified,
                    blocks: want.blocks.clone(),
                };
                check_admission(&contract, &vector.id, &want, failures);
            }
            _ => failures.push(format!(
                "{}: admission vector without artifact/expect",
                vector.id
            )),
        },
        "observed" => {
            let rows: Result<Vec<ObservedArtifact>, _> = vector
                .rows
                .iter()
                .map(|row| serde_json::from_value::<ObservedArtifact>(row.clone()))
                .collect();
            match rows {
                Err(err) => failures.push(format!("{}: observed rows: {err}", vector.id)),
                Ok(rows) => {
                    let errs = contract.verify_observed(&rows, vector.require_all);
                    if codes_of(&errs) != vector.expect_codes {
                        failures.push(format!(
                            "{}: codes {:?}, want {:?}",
                            vector.id,
                            codes_of(&errs),
                            vector.expect_codes
                        ));
                    }
                    check_subjects(vector, &errs, failures);
                }
            }
        }
        other => failures.push(format!("{}: unknown vector kind {other:?}", vector.id)),
    }
}

fn check_admission(
    contract: &WorkspaceContract,
    id: &str,
    want: &ExpectAdmission,
    failures: &mut Vec<String>,
) {
    let Some(artifact) = &want.artifact else {
        failures.push(format!("{id}: admission expectation without an artifact"));
        return;
    };
    match contract.admission(artifact) {
        None => failures.push(format!("{id}: unknown artifact {artifact}")),
        Some(got) => {
            if got.qualified != want.qualified || got.blocks != want.blocks {
                failures.push(format!(
                    "{id}: admission of {artifact}: got qualified={} {:?}, want qualified={} {:?}",
                    got.qualified, got.blocks, want.qualified, want.blocks
                ));
            }
        }
    }
}

#[test]
fn the_shared_vectors_replay_exactly() {
    let file: VectorFile = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(file.schema, "ffw.p01.vectors.v1");
    assert!(file.vectors.len() >= 90, "vector file looks truncated");
    let base = base_value();
    let mut failures = Vec::new();
    for vector in &file.vectors {
        run_vector(&base, &file.base_digest, vector, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        file.vectors.len(),
        failures.join("\n")
    );
}

#[test]
fn the_declared_contract_is_valid_before_any_defect_is_planted() {
    let contract = WorkspaceContract::from_json(BASE).expect("declared contract parses");
    assert_eq!(contract.validate(), Vec::new());
    assert!(contract.artifacts.len() >= 7);
    // Nothing is claimed qualified: no evidence exists yet.
    for artifact in &contract.artifacts {
        let admission = contract.admission(&artifact.id).expect("declared artifact");
        assert!(
            !admission.qualified,
            "{} must not be qualified",
            artifact.id
        );
    }
}

#[test]
fn the_contract_digest_is_the_pinned_value_and_independent_of_the_file_layout() {
    let file: VectorFile = serde_json::from_str(VECTORS).expect("vectors parse");
    let contract = WorkspaceContract::from_json(BASE).expect("declared contract parses");
    assert_eq!(contract.digest(), file.base_digest);
    // The struct round-trips with nothing added or dropped, so the digest taken over the struct is
    // the digest taken over the file (the Python reference hashes the file's canonical form).
    assert_eq!(
        contract.canonical_json(),
        canonical_json_value(&base_value())
    );
}

#[test]
fn every_vector_id_is_unique_and_every_kind_is_known() {
    let file: VectorFile = serde_json::from_str(VECTORS).expect("vectors parse");
    let mut seen = std::collections::BTreeSet::new();
    for vector in &file.vectors {
        assert!(seen.insert(vector.id.clone()), "duplicate id {}", vector.id);
        assert!(
            matches!(
                vector.kind.as_str(),
                "validate" | "parse" | "admission" | "observed" | "digest"
            ),
            "{}: unknown kind {}",
            vector.id,
            vector.kind
        );
    }
}
