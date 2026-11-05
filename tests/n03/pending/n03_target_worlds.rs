//! The HOST half of N03's target-ISA check (bead ffw-u07). The same source file the big-endian MIPS guest runs
//! (`toolchain/src/n03-target/src/cases.rs`, included below) runs here: the 30 scripted worlds of `tests/n03/vectors.json`
//! (the 28 worlds and the two members of the mixed-generation join) and the seeded simulated worlds. Each world prints one
//! `N03-TARGET-HOST {json}` record with a digest of all its records, which `toolchain/src/measure-n03-target.py`
//! byte-compares with the guest's. Equal is the expected result; a difference is a finding about the target ISA.
//!
//! The assertions below do not depend on the guest. They pin the shared interpreter to the reference's expected records
//! (so a port that drifted from `group/tests.rs` fails here), the seed derivation to known answers, and the seeded worlds
//! to figures computed by the independent Python model (`tests/n03/reference.py`), for three seeds.

#[path = "../../../toolchain/src/n03-target/src/cases.rs"]
#[allow(dead_code)]
mod cases;

use cases::{
    SIM_SHAPES, SimRun, all_worlds, seeded_run, sim_seed, splitmix64, truth_summary, vectors,
};
use franken_clock::group::ProbeResponse;
use serde_json::{Value, json};

/// Compare a record to the reference's, exactly, except for the fields the reference gives a tolerance for (the rate
/// estimator's float uncertainty, which the reference computes in a different way).
fn compare_record(id: &str, index: usize, want: &Value, got: &Value) {
    let want_map = want.as_object().expect("expected record");
    let got_map = got.as_object().expect("observed record");
    let tol = want_map.get("tol").and_then(Value::as_object);
    let mut want_keys: Vec<&String> = want_map.keys().filter(|k| k.as_str() != "tol").collect();
    let mut got_keys: Vec<&String> = got_map.keys().collect();
    want_keys.sort();
    got_keys.sort();
    assert_eq!(
        want_keys, got_keys,
        "{id} op {index}: the records carry different fields"
    );
    for key in want_keys {
        let (w, g) = (&want_map[key], &got_map[key]);
        match tol
            .and_then(|t| t.get(key.as_str()))
            .and_then(Value::as_i64)
        {
            Some(t) => {
                let (wi, gi) = (
                    w.as_i64().expect("tolerated field is an integer"),
                    g.as_i64().expect("integer"),
                );
                assert!(
                    (wi - gi).abs() <= t,
                    "{id} op {index} {key}: observed {gi}, reference {wi}, tolerance {t}"
                );
            }
            None => assert_eq!(w, g, "{id} op {index} {key}"),
        }
    }
}

#[test]
fn n03_target_worlds_are_the_vectors_worlds_and_the_mixed_members() {
    let vec = vectors();
    let worlds = all_worlds(&vec);
    let members = vec["mixed"]["members"].as_array().expect("members").len();
    assert_eq!(
        worlds.len(),
        vec["worlds"].as_array().expect("worlds").len() + members
    );
    assert_eq!(
        worlds.len(),
        30,
        "28 worlds and the two members of the mixed join"
    );
    let mut ids: Vec<&str> = worlds
        .iter()
        .map(|w| w["id"].as_str().expect("id"))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), worlds.len(), "world ids are unique");
    for w in &worlds {
        let (ops, expect) = (w["ops"].as_array().expect("ops"), w["expect"].as_array());
        assert!(!ops.is_empty(), "{}", w["id"]);
        assert_eq!(
            Some(ops.len()),
            expect.map(Vec::len),
            "{}: one expected record per op",
            w["id"]
        );
    }
}

#[test]
fn n03_target_worlds_reproduce_the_references_expected_records() {
    let vec = vectors();
    let mut total_ops = 0_usize;
    for world in all_worlds(&vec) {
        let id = world["id"].as_str().expect("id");
        let steps = cases::run_ops(&world);
        let want = world["expect"].as_array().expect("expect");
        assert_eq!(steps.len(), want.len(), "{id}: one record per op");
        for (index, (w, g)) in want.iter().zip(&steps).enumerate() {
            compare_record(id, index, w, g);
        }
        total_ops += steps.len();
        let encoded: Vec<String> = steps.iter().map(Value::to_string).collect();
        let (checks, max_err, max_unc, min_margin) = truth_summary(&world, &steps);
        if checks > 0 {
            assert!(
                max_err <= max_unc,
                "{id}: the truth is outside the uncertainty"
            );
            assert!(min_margin.is_some(), "{id}");
        }
        println!(
            "N03-TARGET-HOST {}",
            json!({"id": id, "steps": steps.len(), "fnv": format!("{:016x}", cases::fnv1a64_lines(&encoded)),
                   "checks": checks, "max_err": max_err, "max_unc": max_unc, "min_margin": min_margin})
        );
    }
    assert!(total_ops > 1_700, "the worlds ran their ops: {total_ops}");
}

#[test]
fn n03_target_seed_derivation_matches_known_answers() {
    // SplitMix64's published first output for state 0, and the seeds derived from three run seeds, computed in Python.
    assert_eq!(splitmix64(0), 0xE220_A839_7B1D_CDAF);
    let known: [(u64, u64, u32); 6] = [
        (1, 0, 608_700_732),
        (1, 1, 2_853_654_961),
        (2, 0, 245_271_993),
        (2, 1, 1_488_490_517),
        (0x0123_4567_89AB_CDEF, 0, 4_110_677_693),
        (0x0123_4567_89AB_CDEF, 1, 134_991_040),
    ];
    for (run_seed, index, expected) in known {
        assert_eq!(
            sim_seed(run_seed, index),
            expected,
            "run seed {run_seed:#x}, world {index}"
        );
    }
    assert_ne!(
        sim_seed(1, 0),
        sim_seed(1, 1),
        "the two worlds of a run use different seeds"
    );
    assert_ne!(sim_seed(1, 0), sim_seed(2, 0), "another run, another seed");
}

/// One pinned seeded world: `(run seed, world, probes, lost, checks, max err ns, max unc ns, min margin ns)`.
type Pin = (u64, usize, u64, u64, u64, u64, u64, u64);

/// The seeded worlds, pinned to what the independent Python model produced for the same seeds (its `Sim` and `Model`
/// in `tests/n03/reference.py`, counted instead of asserted).
#[test]
fn n03_target_seeded_worlds_match_the_independent_models_figures() {
    let pins: [Pin; 6] = [
        (1, 0, 300, 22, 278, 104_668, 341_687, 101_166),
        (1, 1, 600, 107, 493, 597_500, 1_026_255, 202_232),
        (2, 0, 300, 30, 270, 157_000, 317_684, 101_856),
        (2, 1, 600, 118, 482, 489_446, 1_082_261, 202_072),
        (
            0x0123_4567_89AB_CDEF,
            0,
            300,
            33,
            267,
            148_317,
            312_684,
            100_866,
        ),
        (
            0x0123_4567_89AB_CDEF,
            1,
            600,
            124,
            476,
            572_500,
            1_083_194,
            205_074,
        ),
    ];
    for (run_seed, index, probes, lost, checks, max_err, max_unc, min_margin) in pins {
        let run = seeded_run(run_seed, index);
        let want = SimRun {
            seed32: sim_seed(run_seed, index as u64),
            probes,
            lost,
            rejected: 0,
            checks,
            violations: 0,
            max_err,
            max_unc,
            min_margin: Some(min_margin),
            locked: true,
            resets: 0,
        };
        assert_eq!(run, want, "run seed {run_seed:#x}, world {index}");
    }
}

#[test]
fn n03_target_seeded_worlds_hold_their_properties_for_other_seeds() {
    for run_seed in [3_u64, 4, 5, 6, 7, 0xDEAD_BEEF] {
        for (index, shape) in SIM_SHAPES.iter().enumerate() {
            let run = seeded_run(run_seed, index);
            let seconds = shape.5;
            let context = format!("run seed {run_seed:#x}, world {index}: {run:?}");
            assert_eq!(run.rejected, 0, "{context}");
            assert_eq!(
                run.violations, 0,
                "{context}: the truth is inside the uncertainty"
            );
            assert_eq!(run.resets, 0, "{context}: a clean world never resets");
            assert!(run.locked, "{context}");
            assert!(run.checks > seconds / 2, "{context}");
            assert!(run.lost > 0, "{context}: the loss is real");
        }
    }
}

#[test]
fn n03_target_timing_stream_is_accepted_and_the_clock_then_maps_the_gate_path() {
    let stream = cases::timing_stream(600);
    assert_eq!(
        stream,
        cases::timing_stream(600),
        "the stream is deterministic"
    );
    let mut clock = cases::timing_clock();
    for &(t1, t2, t3, t4) in &stream {
        let req = clock.next_probe(t1);
        let resp = ProbeResponse {
            epoch: req.epoch,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: req.t1_local_ns,
            t2_group_ns: t2,
            t3_group_ns: t3,
        };
        assert!(
            clock.on_response(resp, t4).is_ok(),
            "an exchange of the stream was refused"
        );
    }
    assert_eq!(
        clock.stats().accepted,
        600,
        "every exchange of the stream is accepted"
    );
    assert_eq!(clock.stats().resets, 0);
    // the gate path of the CPU region works on a locked clock: a presentation time maps to a local instant
    let now = stream[599].3 + 1_500_000;
    let pts = clock
        .group_ns(now)
        .expect("a locked clock reads the group clock")
        + 500_000_000;
    let local = clock
        .local_for_group(pts, now)
        .expect("the presentation time maps");
    assert!(local > now, "the presentation time is in the future");
    let _ = clock.output(local);
}
