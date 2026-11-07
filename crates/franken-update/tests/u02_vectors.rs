//! Replays `tests/vectors/u02_vectors.json`, written by `tests/u02/make_vectors.py` from `tests/u02/reference.py`. Every expected value in
//! that file was written by hand from `docs/contracts/u02.md` and then checked against the Python model before it was committed; nothing
//! here asks this crate what the answer should be. The signatures were made by the Python oracle (byte-equal to OpenSSL), so the verifier
//! under test (`ed25519-dalek`'s `verify_strict`, behind `sig.rs`) shares no code with whatever produced them.

mod common;

use common::{
    Eng, arr32, board, doc, dynamic, fresh_engine, index, installed, limits, num, policy, restart,
    restart_with, text, unhex, wide,
};
use franken_board_profile::{CpuIsa, synthetic_test_fixture_catalog};
use franken_journal::MemStorage;
use franken_update::engine::{
    BootOutcome, CHECKPOINT, MemStaging, Staging, TRIAL_BOOTS, check_artifact,
};
use franken_update::group::{Member, group_decision, rollback_decision};
use franken_update::manifest::{FEATURES, MAX_MANIFEST, Manifest};
use franken_update::policy::{AbReceipt, Board, Installed, TrustStore, VENDOR_ACCEPTANCE, admit};
use franken_update::{ALL_CODES, UpdateError, sig};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn same(id: &str, got: Result<Value, UpdateError>, want: &Value) {
    let got = match got {
        Ok(v) => json!({ "ok": v }),
        Err(e) => json!({ "refuse": e.code() }),
    };
    assert_eq!(&got, want, "{id}");
}

#[test]
fn the_constants_the_vectors_were_written_for_are_the_crates() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(index(c, "max_manifest"), MAX_MANIFEST);
    assert_eq!(index(c, "checkpoint"), CHECKPOINT);
    assert_eq!(num(c, "trial_boots"), u64::from(TRIAL_BOOTS));
    let names: Vec<&str> = c["features"]
        .as_array()
        .expect("features")
        .iter()
        .map(|v| v.as_str().expect("a feature name"))
        .collect();
    assert_eq!(names, FEATURES);
}

/// The sections of the vector file and the family every case id in each one carries (`U02-ADM-004` is the fourth admission case).
const FAMILIES: [(&str, &str); 9] = [
    ("ed25519", "ED"),
    ("keys_check", "KEY"),
    ("trust", "TRUST"),
    ("parse", "PARSE"),
    ("admit", "ADM"),
    ("artifact", "ART"),
    ("engine", "ENG"),
    ("group", "GRP"),
    ("rollback", "RB"),
];

/// Codes of the crate that no vector can name: tests in this crate reach them directly (the board profile gate and the unknown ISA in
/// `a_profile_that_fails_its_own_gate_or_names_an_unknown_isa_is_not_a_board`, a gap in the staging medium and a record the journal holds that
/// this code cannot read in `u02_restart.rs`).
const OUTSIDE_THE_VECTORS: [&str; 4] = [
    "staging_gap",
    "profile_invalid",
    "isa_unsupported",
    "corrupt_state",
];

/// What a rolling-update decision may say. `invalid_target` is the answer for an index that names no member.
const GROUP_CODES: [&str; 4] = [
    "ok",
    "wire_incompatible",
    "unknown_member_state",
    "invalid_target",
];

/// The refusals the acceptance lines of `ffw-76j` stand on (`docs/contracts/u02.md` section 10), each with the code it must name and the permitted
/// case that sits beside it. They are written out here, apart from the file `make_vectors.py` writes, so that deleting one of these cases, renaming it,
/// or editing its expected code until a failing run passes is itself a failure. The vector file may hold more cases than these; engine scripts are
/// pinned by the replay of every state after every operation.
const REQUIRED: &[(&str, &str, &str)] = &[
    ("U02-ADM-002", "bad_signature", "U02-ADM-001"),
    ("U02-ADM-003", "bad_signature", "U02-ADM-001"),
    ("U02-ADM-004", "unknown_signing_key", "U02-ADM-001"),
    ("U02-ADM-005", "revoked_signing_key", "U02-ADM-006"),
    ("U02-ADM-009", "stage_forbidden", "U02-ADM-001"),
    ("U02-ADM-010", "stage_forbidden", "U02-ADM-001"),
    ("U02-ADM-011", "stage_forbidden", "U02-ADM-001"),
    ("U02-ADM-012", "vendor_claim_forbidden", "U02-ADM-001"),
    ("U02-ADM-013", "bypass_claim_forbidden", "U02-ADM-001"),
    ("U02-ADM-014", "ab_claim_forbidden", "U02-ADM-001"),
    ("U02-ADM-015", "wrong_board", "U02-ADM-019"),
    ("U02-ADM-016", "hardware_revision_mismatch", "U02-ADM-001"),
    ("U02-ADM-017", "isa_mismatch", "U02-ADM-019"),
    ("U02-ADM-018", "kernel_profile_mismatch", "U02-ADM-001"),
    ("U02-ADM-020", "profile_not_attested", "U02-ADM-023"),
    ("U02-ADM-024", "required_feature_missing", "U02-ADM-025"),
    ("U02-ADM-026", "below_security_floor", "U02-ADM-027"),
    ("U02-ADM-028", "downgrade_not_permitted", "U02-ADM-029"),
    ("U02-ADM-031", "version_reused", "U02-ADM-001"),
    ("U02-ADM-034", "candidate_previously_failed", "U02-ADM-035"),
    ("U02-ADM-037", "calibration_schema_mismatch", "U02-ADM-001"),
    ("U02-ADM-038", "settings_incompatible", "U02-ADM-039"),
    ("U02-ADM-045", "ssh_fix_missing", "U02-ADM-044"),
    ("U02-ADM-046", "ssh_fix_missing", "U02-ADM-048"),
    ("U02-ADM-052", "ssh_password_forbidden", "U02-ADM-053"),
    ("U02-ADM-056", "ssh_unqualified", "U02-ADM-057"),
    ("U02-ADM-058", "insufficient_capacity", "U02-ADM-059"),
    (
        "U02-ADM-062",
        "synthetic_receipt_for_real_profile",
        "U02-ADM-063",
    ),
    ("U02-ADM-064", "no_recovery_path", "U02-ADM-001"),
    ("U02-ADM-067", "no_recovery_path", "U02-ADM-066"),
    (
        "U02-ADM-068",
        "synthetic_receipt_for_real_profile",
        "U02-ADM-066",
    ),
    ("U02-ART-002", "artifact_truncated", "U02-ART-001"),
    ("U02-ART-004", "artifact_oversized", "U02-ART-001"),
    ("U02-ART-005", "artifact_digest_mismatch", "U02-ART-001"),
];

fn is_case_id(id: &str, family: &str) -> bool {
    id.strip_prefix("U02-")
        .and_then(|rest| rest.strip_prefix(family))
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|digits| digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Every refusal name in the document, with the ids of the cases that name it. A refusal belongs to the nearest enclosing object that has an `id`.
fn named_refusals<'a>(
    v: &'a Value,
    case: &'a str,
    found: &mut BTreeMap<String, BTreeSet<&'a str>>,
) {
    match v {
        Value::Object(map) => {
            let case = map.get("id").and_then(Value::as_str).unwrap_or(case);
            for (key, inner) in map {
                if key == "refuse" {
                    let code = inner.as_str().unwrap_or("<not text>");
                    found.entry(code.to_string()).or_default().insert(case);
                }
                named_refusals(inner, case, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                named_refusals(item, case, found);
            }
        }
        _ => {}
    }
}

/// What is wrong with the inventory of the vector document, one sentence each; empty when nothing is. It asks for what the acceptance needs rather
/// than for a number of refusals: every case id is unique and filed under its own family; every refusal the vectors name is a code of the crate; every
/// code of the crate is exercised except the four that tests here reach directly; each cited refusal is there with its code and beside its permitted
/// positive; and the rolling-update answers cover every decision, including a target that does not exist and a target other than member 0.
fn inventory_problems(d: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let mut by_id: BTreeMap<&str, &Value> = BTreeMap::new();
    for (section, family) in FAMILIES {
        let Some(cases) = d[section].as_array() else {
            problems.push(format!("section `{section}` is missing"));
            continue;
        };
        for case in cases {
            let Some(id) = case["id"].as_str() else {
                problems.push(format!("a case in `{section}` has no id"));
                continue;
            };
            if !is_case_id(id, family) {
                problems.push(format!(
                    "case `{id}` is misfiled: `{section}` holds only U02-{family}-NNN"
                ));
            }
            if by_id.insert(id, case).is_some() {
                problems.push(format!("case id `{id}` is used twice"));
            }
        }
    }
    let mut named = BTreeMap::new();
    named_refusals(d, "", &mut named);
    for (code, ids) in &named {
        if !ALL_CODES.contains(&code.as_str()) {
            let ids: Vec<&str> = ids.iter().copied().collect();
            problems.push(format!(
                "`{code}` is not a code of the crate (named by {})",
                ids.join(", ")
            ));
        }
    }
    for code in ALL_CODES {
        if !named.contains_key(*code) && !OUTSIDE_THE_VECTORS.contains(code) {
            problems.push(format!("no vector exercises `{code}`"));
        }
    }
    for &(refusal, code, positive) in REQUIRED {
        match by_id.get(refusal) {
            None => problems.push(format!("required case `{refusal}` is missing")),
            Some(case) if case["expect"] != json!({ "refuse": code }) => {
                problems.push(format!("required case `{refusal}` must refuse `{code}`"));
            }
            Some(_) => {}
        }
        match by_id.get(positive) {
            None => problems.push(format!(
                "`{positive}`, the permitted case beside `{refusal}`, is missing"
            )),
            Some(case) if case["expect"].get("ok").is_none() => {
                problems.push(format!(
                    "`{positive}` beside `{refusal}` must be a permitted outcome"
                ));
            }
            Some(_) => {}
        }
    }
    let mut decisions = BTreeSet::new();
    let (mut later_admits, mut later_refuses) = (false, false);
    for case in d["group"].as_array().into_iter().flatten() {
        let id = case["id"].as_str().unwrap_or("<no id>");
        let code = case["expect"]["code"].as_str().unwrap_or("<no code>");
        if !GROUP_CODES.contains(&code) {
            problems.push(format!(
                "group case `{id}` expects `{code}`, which is not a rolling-update decision"
            ));
        }
        decisions.insert(code);
        let members = u64::try_from(case["members"].as_array().map_or(0, Vec::len)).unwrap_or(0);
        let target = case["index"].as_u64().unwrap_or(0);
        if target > 0 && target < members {
            later_admits |= code == "ok";
            later_refuses |= code == "wire_incompatible";
        }
    }
    for code in GROUP_CODES {
        if !decisions.contains(code) {
            problems.push(format!("no group vector expects `{code}`"));
        }
    }
    if !later_admits {
        problems.push("no group vector admits a target other than member 0".to_string());
    }
    if !later_refuses {
        problems.push("no group vector refuses a target other than member 0".to_string());
    }
    problems
}

#[test]
fn every_refusal_a_vector_names_is_a_stable_code_of_the_crate() {
    // the vector file as committed: nothing missing, nothing twice, every refusal a code of the crate and every code of the crate exercised except
    // four, and every cited refusal there with its code beside its permitted case. There is no count of refusals to reach: `ffw-76j` asks for named
    // cases and coverage of the stable codes, not for a number.
    let problems = inventory_problems(&doc());
    assert!(problems.is_empty(), "{problems:#?}");
}

fn case_mut<'a>(d: &'a mut Value, section: &str, id: &str) -> &'a mut Value {
    d[section]
        .as_array_mut()
        .expect("a section")
        .iter_mut()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("no case {id} in {section}"))
}

fn remove_case(d: &mut Value, section: &str, id: &str) {
    let cases = d[section].as_array_mut().expect("a section");
    let before = cases.len();
    cases.retain(|case| case["id"] != id);
    assert_eq!(cases.len() + 1, before, "{id} was there once");
}

/// One edit to the committed vectors, and the sentence the inventory must then say.
fn plant(d: &mut Value, which: &str) -> String {
    match which {
        "a cited refusal is deleted" => {
            remove_case(d, "admit", "U02-ADM-004");
            "required case `U02-ADM-004` is missing".to_string()
        }
        "a cited refusal's code is edited to another real code" => {
            case_mut(d, "admit", "U02-ADM-004")["expect"] = json!({ "refuse": "bad_signature" });
            "required case `U02-ADM-004` must refuse `unknown_signing_key`".to_string()
        }
        "a permitted case is turned into a refusal" => {
            case_mut(d, "admit", "U02-ADM-006")["expect"] = json!({ "refuse": "bad_signature" });
            "`U02-ADM-006` beside `U02-ADM-005` must be a permitted outcome".to_string()
        }
        "a permitted case is deleted" => {
            remove_case(d, "admit", "U02-ADM-006");
            "`U02-ADM-006`, the permitted case beside `U02-ADM-005`, is missing".to_string()
        }
        "a case id is used twice" => {
            let copy = case_mut(d, "admit", "U02-ADM-001").clone();
            d["admit"].as_array_mut().expect("a section").push(copy);
            "case id `U02-ADM-001` is used twice".to_string()
        }
        "a case is filed under the wrong family" => {
            let mut copy = case_mut(d, "group", "U02-GRP-001").clone();
            copy["id"] = json!("U02-ADM-099");
            d["group"].as_array_mut().expect("a section").push(copy);
            "case `U02-ADM-099` is misfiled: `group` holds only U02-GRP-NNN".to_string()
        }
        "a refusal names a code that is not one" => {
            case_mut(d, "admit", "U02-ADM-004")["expect"] = json!({ "refuse": "made_up_code" });
            "`made_up_code` is not a code of the crate (named by U02-ADM-004)".to_string()
        }
        "the only case for a code is deleted" => {
            remove_case(d, "admit", "U02-ADM-052");
            "no vector exercises `ssh_password_forbidden`".to_string()
        }
        "no group vector names a missing target" => {
            for id in ["U02-GRP-013", "U02-GRP-014", "U02-GRP-015", "U02-GRP-016"] {
                remove_case(d, "group", id);
            }
            "no group vector expects `invalid_target`".to_string()
        }
        "every group vector targets member 0" => {
            for case in d["group"].as_array_mut().expect("a section") {
                case["index"] = json!(0);
            }
            "no group vector admits a target other than member 0".to_string()
        }
        other => panic!("unknown plant `{other}`"),
    }
}

#[test]
fn each_gap_planted_in_the_vector_inventory_is_named_and_the_unplanted_vectors_have_none() {
    // the permitted positive beside every plant: the committed vectors are clean
    assert_eq!(inventory_problems(&doc()), Vec::<String>::new());
    for which in [
        "a cited refusal is deleted",
        "a cited refusal's code is edited to another real code",
        "a permitted case is turned into a refusal",
        "a permitted case is deleted",
        "a case id is used twice",
        "a case is filed under the wrong family",
        "a refusal names a code that is not one",
        "the only case for a code is deleted",
        "no group vector names a missing target",
        "every group vector targets member 0",
    ] {
        let mut d = doc();
        let want = plant(&mut d, which);
        let problems = inventory_problems(&d);
        assert!(
            problems.contains(&want),
            "{which}: wanted `{want}`, got {problems:#?}"
        );
    }
}

#[test]
fn the_vector_boards_are_what_the_synthetic_catalog_says_and_none_is_attested() {
    let d = doc();
    let catalog = synthetic_test_fixture_catalog();
    for name in ["ppc", "mips"] {
        let want = board(&d, name);
        let profile = catalog
            .iter()
            .find(|p| p.profile_id == want.profile_id)
            .unwrap_or_else(|| panic!("no catalog row for {name}"));
        let got = Board::from_profile(profile).expect("a synthetic fixture is a valid board");
        assert_eq!(got, want, "{name}");
        assert!(got.synthetic && !got.attested, "{name}");
    }
    // the policy stand-in has the identity of the ppc board and only the two flags differ
    let (ppc, standin) = (board(&d, "ppc"), board(&d, "ppc_policy_standin"));
    assert_eq!(
        (ppc.profile_id, ppc.hw_rev, ppc.isa, ppc.kernel_profile),
        (
            standin.profile_id,
            standin.hw_rev,
            standin.isa,
            standin.kernel_profile
        )
    );
    assert!(!standin.synthetic && standin.attested);
}

#[test]
fn a_profile_that_fails_its_own_gate_or_names_an_unknown_isa_is_not_a_board() {
    let catalog = synthetic_test_fixture_catalog();
    let s5 = catalog
        .iter()
        .find(|p| p.model_number == "S5")
        .expect("S5")
        .clone();
    // a profile whose digest no longer matches
    let mut tampered = s5.clone();
    tampered.nominal_ram_mib += 1;
    assert_eq!(
        Board::from_profile(&tampered),
        Err(UpdateError::ProfileInvalid)
    );
    // a valid profile of an ISA this update format cannot name
    let mut unknown = s5.clone();
    unknown.cpu_isa = CpuIsa::Unknown;
    let unknown = unknown.with_computed_digest();
    assert_eq!(
        Board::from_profile(&unknown),
        Err(UpdateError::IsaUnsupported)
    );
    // the permitted positive beside both
    assert!(Board::from_profile(&s5).is_ok());
}

#[test]
fn signatures_verify_strictly_and_only_under_an_admissible_key() {
    let d = doc();
    let mut seen = 0;
    for v in d["ed25519"].as_array().expect("ed25519 vectors") {
        let public = arr32(&v["public"]);
        let ok = sig::key_admissible(&public)
            && sig::verify(&public, &unhex(&v["message"]), &unhex(&v["signature"]));
        assert_eq!(
            ok,
            v["expect"].as_bool().expect("a verdict"),
            "{}",
            text(v, "id")
        );
        seen += 1;
    }
    assert!(seen >= 15);
}

#[test]
fn keys_are_admitted_only_when_canonical_on_the_curve_not_small_order_and_torsion_free() {
    let d = doc();
    for v in d["keys_check"].as_array().expect("key vectors") {
        let raw = unhex(&v["public"]);
        let got =
            <[u8; 32]>::try_from(raw.as_slice()).is_ok_and(|public| sig::key_admissible(&public));
        assert_eq!(
            got,
            v["expect"].as_bool().expect("a verdict"),
            "{}",
            text(v, "id")
        );
    }
}

#[test]
fn a_trust_store_holds_at_most_four_distinct_admissible_keys() {
    let d = doc();
    for v in d["trust"].as_array().expect("trust vectors") {
        let keys: Vec<([u8; 32], bool)> = v["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| (arr32(&k["public"]), k["revoked"].as_bool().expect("a flag")))
            .collect();
        let got = TrustStore::new(&keys).map(|_| json!("built"));
        same(text(v, "id"), got, &v["expect"]);
    }
}

#[test]
fn every_manifest_parses_or_is_refused_by_the_structural_rule_written_for_it() {
    let d = doc();
    for v in d["parse"].as_array().expect("parse vectors") {
        let got = Manifest::parse(&unhex(&v["manifest"])).map(|m| json!({ "version": m.version }));
        same(text(v, "id"), got, &v["expect"]);
    }
}

#[test]
fn every_admission_gets_the_refusal_or_the_plan_written_by_hand() {
    let d = doc();
    let mut admitted = 0;
    for v in d["admit"].as_array().expect("admit vectors") {
        let spec = &v["ctx"];
        let got = admit(&policy(&d, spec), &dynamic(spec), &unhex(&v["manifest"])).map(|a| {
            json!({ "mode": a.plan.mode.label(), "ab": a.plan.ab.label(), "vendor_acceptance": VENDOR_ACCEPTANCE, "downgrade": a.downgrade })
        });
        admitted += usize::from(got.is_ok());
        same(text(v, "id"), got, &v["expect"]);
    }
    assert!(admitted >= 20, "the permitted positives ran: {admitted}");
}

fn plan_of(
    d: &Value,
    spec: &Value,
    raw: &[u8],
    receipt: Option<AbReceipt>,
    recovery_path: bool,
) -> Result<(&'static str, &'static str), UpdateError> {
    let mut p = policy(d, spec);
    p.ab_receipt = receipt;
    p.recovery_path = recovery_path;
    admit(&p, &dynamic(spec), raw).map(|a| (a.plan.mode.label(), a.plan.ab.label()))
}

#[test]
fn a_capacity_receipt_proves_two_slots_only_with_a_digest_and_room_and_a_missing_one_changes_nothing_else()
 {
    let d = doc();
    // U02-ADM-060: a non-synthetic board, so a synthetic receipt is refused; the receipts below replace the one it carries
    let v = d["admit"]
        .as_array()
        .expect("admit vectors")
        .iter()
        .find(|v| v["id"] == "U02-ADM-060")
        .expect("U02-ADM-060");
    let (spec, raw) = (&v["ctx"], unhex(&v["manifest"]));
    let need = Manifest::parse(&raw).expect("a manifest").artifact_size + wide(spec, "reserve");
    let receipt = |slot_bytes: u32, digest: [u8; 32], synthetic: bool| {
        Some(AbReceipt {
            slot_bytes,
            digest,
            synthetic,
        })
    };
    let plan =
        |r: Option<AbReceipt>, recovery_path: bool| plan_of(&d, spec, &raw, r, recovery_path);
    let proven: Result<(&str, &str), UpdateError> = Ok(("ab_slots", "proven_by_external_receipt"));
    let single: Result<(&str, &str), UpdateError> = Ok(("single_slot_recovery", "not_proven"));
    let (mut first_bit, mut last_bit) = ([0u8; 32], [0u8; 32]);
    first_bit[0] = 1;
    last_bit[31] = 1;
    // the permitted positives: any digest but zero, a slot of exactly the artifact plus its reserve
    for digest in [[7u8; 32], first_bit, last_bit] {
        assert_eq!(plan(receipt(need, digest, false), true), proven);
    }
    assert_eq!(plan(receipt(need - 1, [7; 32], false), true), single);
    assert_eq!(plan(None, true), single);
    // no digest: nothing is proven however large the slot it names, the recovery path decides, and a synthetic receipt for a real board is still refused
    assert_eq!(plan(receipt(u32::MAX, [0; 32], false), true), single);
    assert_eq!(
        plan(receipt(u32::MAX, [0; 32], false), false),
        Err(UpdateError::NoRecoveryPath)
    );
    for digest in [[0u8; 32], [7; 32]] {
        assert_eq!(
            plan(receipt(need, digest, true), true),
            Err(UpdateError::SyntheticReceiptForRealProfile)
        );
    }
}

#[test]
fn a_staged_artifact_is_whole_or_it_is_named_truncated_oversized_or_wrong() {
    let d = doc();
    for v in d["artifact"].as_array().expect("artifact vectors") {
        let m = Manifest::parse(&unhex(&v["manifest"])).expect("the vector's manifest parses");
        let staging = MemStaging::with_data(1 << 20, &unhex(&v["artifact"]));
        let got = check_artifact(&m, &staging).map(|()| json!("verified"));
        same(text(v, "id"), got, &v["expect"]);
    }
}

fn run_script(d: &Value, script: &Value) {
    let id = text(script, "id");
    let assets = &d["engine_assets"];
    let mut engine: Eng = fresh_engine(d, &script["ctx"], MemStorage::new(limits().segment_bytes));
    for (n, op) in script["ops"].as_array().expect("ops").iter().enumerate() {
        let kind = text(op, "op");
        let result: Result<&str, UpdateError> = match kind {
            "begin" => engine
                .begin_stage(&unhex(&assets["manifests"][text(op, "manifest")]))
                .map(|_| "staging"),
            "write" => {
                let artifact = unhex(&assets["artifacts"][text(op, "artifact")]);
                engine
                    .write_chunk(&artifact[index(op, "from")..index(op, "to")])
                    .map(|()| "written")
            }
            "finish" => engine.finish_stage().map(|()| "staged"),
            "activate" => engine.activate().map(|()| "trial"),
            "boot" => engine
                .report_boot(op["healthy"].as_bool().expect("a flag"))
                .map(BootOutcome::label),
            "abort" => engine.abort().map(|()| "idle"),
            "restart" => {
                engine = restart(engine);
                Ok("restarted")
            }
            "restart_with" => {
                engine = restart_with(engine, d, &script["ctx"], &op["ctx"]);
                Ok("restarted")
            }
            "power_cut" => {
                engine.staging_mut().power_cut(index(op, "keep"));
                engine = restart(engine);
                Ok("restarted")
            }
            "corrupt" => {
                let bit = u8::try_from(op["bit"].as_u64().unwrap_or(0)).expect("a bit number");
                engine.staging_mut().corrupt(index(op, "at"), bit);
                Ok("corrupted")
            }
            "tamper_manifest" => {
                engine.staging_mut().tamper_manifest(index(op, "at"));
                Ok("tampered")
            }
            "swap_manifest" => {
                let other = unhex(&assets["manifests"][text(op, "manifest")]);
                engine.staging_mut().put_manifest(&other);
                Ok("swapped")
            }
            other => panic!("{id}: unknown operation `{other}`"),
        };
        let got = match result {
            Ok(word) => json!({ "ok": word }),
            Err(e) => json!({ "refuse": e.code() }),
        };
        assert_eq!(got, op["expect"]["result"], "{id} op {n} {kind}");
        let snap = engine.snapshot().expect("a readable state");
        let state = json!({ "phase": snap.phase.label(), "installed": snap.installed, "floor": snap.floor, "next": snap.next });
        assert_eq!(state, op["expect"]["state"], "{id} op {n} {kind}: state");
    }
}

#[test]
fn every_engine_script_ends_in_the_state_written_by_hand_after_every_operation() {
    let d = doc();
    let scripts = d["engine"].as_array().expect("engine scripts");
    assert!(scripts.len() >= 29);
    for script in scripts {
        run_script(&d, script);
    }
}

fn member(m: &Value) -> Member {
    Member {
        id: text(m, "id").to_string(),
        image: installed(&json!({ "installed": m["image"] })),
        connected: m["connected"].as_bool().expect("a flag"),
    }
}

#[test]
fn a_member_takes_a_candidate_only_if_the_rest_of_the_group_can_still_talk_to_it_and_nobody_else_is_touched()
 {
    let d = doc();
    for v in d["group"].as_array().expect("group vectors") {
        let members: Vec<Member> = v["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(member)
            .collect();
        let candidate = installed(&json!({ "installed": v["candidate"] })).expect("a candidate");
        let before = members.clone();
        let got = group_decision(&members, index(v, "index"), &candidate);
        assert_eq!(
            members,
            before,
            "{}: the group was not touched",
            text(v, "id")
        );
        let want = &v["expect"];
        assert_eq!(
            got.admit,
            text(want, "decision") == "admit",
            "{}",
            text(v, "id")
        );
        assert_eq!(got.code, text(want, "code"), "{}", text(v, "id"));
        let list = |key: &str| -> Vec<String> {
            want[key]
                .as_array()
                .expect("a list")
                .iter()
                .map(|s| s.as_str().expect("an id").to_string())
                .collect()
        };
        assert_eq!(got.conflicts, list("conflicts"), "{}", text(v, "id"));
        assert_eq!(got.assumed, list("assumed"), "{}", text(v, "id"));
        assert!(
            want.get("upgrade_others").is_none(),
            "{}: the answer names no action on another member",
            text(v, "id")
        );
    }
}

fn group_case(d: &Value, id: &str) -> (Vec<Member>, Installed) {
    let v = d["group"]
        .as_array()
        .expect("group vectors")
        .iter()
        .find(|v| v["id"] == id)
        .unwrap_or_else(|| panic!("no group vector {id}"));
    let members = v["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(member)
        .collect();
    let candidate = installed(&json!({ "installed": v["candidate"] })).expect("a candidate");
    (members, candidate)
}

#[test]
fn an_index_that_names_no_member_is_refused_before_anyone_is_assessed_and_every_real_index_is_not()
{
    let d = doc();
    let (members, candidate) = group_case(&d, "U02-GRP-001");
    // the permitted positive: in a group where everyone can talk to the candidate, any member may take it
    for at in 0..members.len() {
        let got = group_decision(&members, at, &candidate);
        assert_eq!((got.admit, got.code), (true, "ok"), "member {at}");
    }
    for (name, group, at) in [
        ("an empty group", Vec::new(), 0),
        ("one past the last member", members.clone(), members.len()),
        ("the largest index", members.clone(), usize::MAX),
    ] {
        let got = group_decision(&group, at, &candidate);
        assert_eq!((got.admit, got.code), (false, "invalid_target"), "{name}");
        assert!(
            got.conflicts.is_empty() && got.assumed.is_empty(),
            "{name}: nobody was assessed"
        );
    }
    // a member nobody has heard from does not turn a missing target into a different refusal
    let mut with_unknown = members;
    with_unknown.push(Member {
        id: "z".to_string(),
        image: None,
        connected: true,
    });
    let got = group_decision(&with_unknown, 9, &candidate);
    assert_eq!((got.admit, got.code), (false, "invalid_target"));
}

#[test]
fn a_rollback_after_a_settings_migration_needs_a_reader_or_a_preserved_copy() {
    let d = doc();
    for v in d["rollback"].as_array().expect("rollback vectors") {
        let target = installed(&json!({ "installed": v["target"] })).expect("a target");
        let backup = v["settings_backup"]
            .as_u64()
            .map(|n| u16::try_from(n).expect("fits u16"));
        let stored = u16::try_from(num(v, "stored_settings_schema")).expect("fits u16");
        assert_eq!(
            rollback_decision(stored, backup, &target),
            text(v, "expect"),
            "{}",
            text(v, "id")
        );
    }
}
