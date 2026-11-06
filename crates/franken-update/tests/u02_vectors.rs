//! Replays `tests/vectors/u02_vectors.json`, written by `tests/u02/make_vectors.py` from `tests/u02/reference.py`. Every expected value in
//! that file was written by hand from `docs/contracts/u02.md` and then checked against the Python model before it was committed; nothing
//! here asks this crate what the answer should be. The signatures were made by the Python oracle (byte-equal to OpenSSL), so the verifier
//! under test (`ed25519-dalek`'s `verify_strict`, behind `sig.rs`) shares no code with whatever produced them.

mod common;

use common::{
    Eng, arr32, board, doc, dynamic, fresh_engine, index, installed, limits, num, policy, restart,
    restart_with, text, unhex,
};
use franken_board_profile::{CpuIsa, synthetic_test_fixture_catalog};
use franken_journal::MemStorage;
use franken_update::engine::{
    BootOutcome, CHECKPOINT, MemStaging, Staging, TRIAL_BOOTS, check_artifact,
};
use franken_update::group::{Member, group_decision, rollback_decision};
use franken_update::manifest::{FEATURES, MAX_MANIFEST, Manifest};
use franken_update::policy::{Board, TrustStore, VENDOR_ACCEPTANCE, admit};
use franken_update::{ALL_CODES, UpdateError, sig};
use serde_json::{Value, json};

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

#[test]
fn every_refusal_a_vector_names_is_a_stable_code_of_the_crate() {
    fn walk(v: &Value, found: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (key, inner) in map {
                    if key == "refuse" {
                        found.push(inner.as_str().expect("a code").to_string());
                    }
                    walk(inner, found);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(&doc(), &mut found);
    assert!(
        found.len() > 100,
        "the vectors name {} refusals",
        found.len()
    );
    for code in &found {
        assert!(
            ALL_CODES.contains(&code.as_str()),
            "`{code}` is not a code of the crate"
        );
    }
    // and every code of the crate is exercised by some vector, except these four, which tests in this crate reach directly (the board profile gate,
    // a gap in the staging medium, a record the journal holds that this code cannot read)
    let outside_the_vectors = [
        "staging_gap",
        "profile_invalid",
        "isa_unsupported",
        "corrupt_state",
    ];
    for code in ALL_CODES {
        assert!(
            found.iter().any(|f| f == code) || outside_the_vectors.contains(code),
            "no vector exercises `{code}`"
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
