//! N04 tests (`ffw-nx0`). Expected values come from `tests/n04/reference.py` through `tests/n04/vectors.json`;
//! every test prints an `N04-OBSERVED {json}` line of what the Rust actually computed, which
//! `tests/n04/run_cases.py` re-derives from the reference, so a loosened assertion here cannot hide.
//!
//! Three kinds of check, none of them a measurement on a device:
//! * hand-written anchors (`expect` in the vectors, and the literals below), written from the contract;
//! * the reference's digest of every world's results, compared here and again, record by record, by the judge;
//! * properties checked with this file's own arithmetic over every world, sharing no code with the engine.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::*;

fn vectors() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(include_str!("../../../../tests/n04/vectors.json"))
            .expect("vectors.json parses")
    })
}

fn observed(line: &Value) {
    println!("N04-OBSERVED {line}");
}

fn u(v: &Value) -> u64 {
    v.as_u64().expect("unsigned integer")
}

fn text(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn profile_named(name: &str) -> PlayoutProfile {
    match name {
        "music" => PlayoutProfile::MUSIC,
        "realtime" => PlayoutProfile::REALTIME,
        other => panic!("unknown profile {other}"),
    }
}

fn config_of(v: &Value) -> PlayoutConfig {
    PlayoutConfig {
        work_ns: u(&v["work_ns"]),
        lead_ns: u(&v["lead_ns"]),
        tolerance_ns: u(&v["tolerance_ns"]),
    }
}

/// Sample `j` (interleaved L, R) of the test audio = `((seed * 7919 + j * 104729) mod 65536) - 32768`.
fn synth_payload(seed: u64, frames: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(usize::try_from(frames * 4).unwrap());
    for j in 0..frames * 2 {
        let v = i64::try_from((seed * 7919 + j * 104_729) % 65536).unwrap() - 32768;
        out.extend_from_slice(&i16::try_from(v).unwrap().to_be_bytes());
    }
    out
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn fnv_hex(data: &[u8]) -> String {
    format!("{:016x}", fnv1a64(data))
}

/// Key-sorted compact JSON, written out here so the digest cannot depend on a serde_json feature flag.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&m[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(e, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn digest(results: &[Value]) -> String {
    let mut s = String::new();
    canonical(&Value::Array(results.to_vec()), &mut s);
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn find_world(id: &str) -> &'static Value {
    vectors()["worlds"]
        .as_array()
        .expect("worlds")
        .iter()
        .find(|w| w["id"] == id)
        .unwrap_or_else(|| panic!("no world {id}"))
}

fn decision_json(d: &Decision, buf: &[u8; BLOCK_PAYLOAD_BYTES]) -> Value {
    let mut m = Map::new();
    m.insert("block".into(), json!(d.block));
    m.insert("outcome".into(), json!(d.outcome.code()));
    m.insert("pres".into(), json!(d.presentation_ns));
    m.insert("frames".into(), json!(d.frames));
    m.insert("gap_before".into(), json!(d.gap_before_ns));
    m.insert("submit_deadline".into(), json!(d.submit_deadline_ns));
    m.insert("late_by".into(), json!(d.late_by_ns));
    if let Outcome::Concealed { run } = d.outcome {
        m.insert("run".into(), json!(run));
    }
    if matches!(d.outcome, Outcome::Real | Outcome::Concealed { .. }) {
        m.insert(
            "fnv".into(),
            json!(fnv_hex(&buf[..usize::from(d.frames) * 4])),
        );
    }
    json!({"poll": "decision", "d": Value::Object(m)})
}

type Hook<'a> = &'a mut dyn FnMut(usize, &Value, &Value, &PlayoutEngine);

fn new_engine(world: &Value) -> PlayoutEngine {
    let profile = profile_named(text(&world["profile"]));
    PlayoutEngine::new(profile, config_of(&world["cfg"])).expect("config is valid")
}

/// Replay a world's ops against a fresh engine. `hook` sees every op, its result and the engine after it.
fn run_world_with(world: &Value, hook: Hook<'_>) -> Vec<Value> {
    let mut eng = new_engine(world);
    let mut out = Vec::new();
    let mut buf = [0u8; BLOCK_PAYLOAD_BYTES];
    let mut last_deadline = 0u64;
    for (i, op) in world["ops"].as_array().expect("ops").iter().enumerate() {
        let result = apply_op(&mut eng, op, &mut buf, &mut last_deadline);
        hook(i, op, &result, &eng);
        out.push(result);
    }
    out
}

/// One op against an engine, as the JSON the reference's results are compared with.
fn apply_op(
    eng: &mut PlayoutEngine,
    op: &Value,
    buf: &mut [u8; BLOCK_PAYLOAD_BYTES],
    last_deadline: &mut u64,
) -> Value {
    let a = op.as_array().expect("op is an array");
    let n = |k: usize| u(&a[k]);
    let view = || ClockView {
        group_ns: n(1),
        uncertainty_ns: n(2),
        usable: n(3) != 0,
    };
    match text(&a[0]) {
        "begin" => match eng.begin_stream(n(1), n(2), n(3)) {
            Ok(()) => json!({"ok": true, "reason": "started"}),
            Err(e) => json!({"ok": false, "reason": e.code()}),
        },
        "packet" => {
            let payload = synth_payload(n(8), n(7));
            let pkt = MediaPacket {
                epoch: n(4),
                start_frame: n(5),
                presentation_ns: n(6),
                frames: u32::try_from(n(7)).unwrap(),
                payload: &payload,
            };
            json!({"r": eng.on_packet(view(), &pkt).code()})
        }
        "bad" => {
            let payload = vec![0u8; usize::try_from(n(8)).unwrap()];
            let pkt = MediaPacket {
                epoch: n(4),
                start_frame: n(5),
                presentation_ns: n(6),
                frames: u32::try_from(n(7)).unwrap(),
                payload: &payload,
            };
            json!({"r": eng.on_packet(view(), &pkt).code()})
        }
        "repair" => {
            let payload = synth_payload(n(7), n(6));
            let block = RepairBlock {
                epoch: n(4),
                start_frame: n(5),
                frames: u32::try_from(n(6)).unwrap(),
                payload: &payload,
            };
            json!({"r": eng.on_repair(view(), &block).code()})
        }
        "decide" => match eng.decide(view(), buf) {
            Poll::Pending => json!({"poll": "pending"}),
            Poll::ClockUnusable => json!({"poll": "clock_unusable"}),
            Poll::ClockRegression => json!({"poll": "clock_regression"}),
            Poll::NotBound => json!({"poll": "not_bound"}),
            Poll::Decision(d) => {
                *last_deadline = d.submit_deadline_ns;
                decision_json(&d, buf)
            }
        },
        "change" => {
            let ch = LatencyChange {
                epoch: n(1),
                change_id: n(2),
                effective_frame: n(3),
                new_anchor_ns: n(4),
            };
            match eng.apply_change(ch) {
                Ok(delta) => json!({"ok": true, "reason": "accepted", "delta_ns": delta}),
                Err(e) => json!({"ok": false, "reason": e.code()}),
            }
        }
        "deliver" => {
            let name = match eng.settle_delivery(*last_deadline, a[1].as_u64()) {
                Delivery::Delivered => "delivered",
                Delivery::Abandoned => "abandoned",
            };
            json!({"delivery": name})
        }
        "advice" => {
            let adv = eng.advice();
            json!({"action": adv.action.code(), "blocks": adv.blocks, "reason": adv.reason})
        }
        "stats" => serde_json::to_value(eng.snapshot()).expect("snapshot serializes"),
        other => panic!("unknown op {other}"),
    }
}

fn run_world(world: &Value) -> Vec<Value> {
    run_world_with(world, &mut |_, _, _, _| {})
}

fn dig<'a>(mut v: &'a Value, path: &str) -> &'a Value {
    for part in path.split('.') {
        v = &v[part];
    }
    v
}

/// One scripted world: the hand-written anchors, the reference digest, and the observation for the judge.
fn judged_world(id: &str) {
    let world = find_world(id);
    let results = run_world(world);
    let labels = world["labels"].as_object().expect("labels");
    for e in world["expect"].as_array().expect("expect") {
        let label = text(&e["label"]);
        let result = &results[usize::try_from(u(&labels[label])).unwrap()];
        assert_eq!(
            dig(result, text(&e["key"])),
            &e["value"],
            "{id}: {label}.{} in {result}",
            text(&e["key"])
        );
    }
    let got = digest(&results);
    observed(&json!({"id": id, "digest": got, "results": results}));
    assert_eq!(
        got,
        text(&world["digest"]),
        "{id}: the results differ from the reference (the judge names the first op)"
    );
}

macro_rules! world_test {
    ($name:ident, $id:expr) => {
        #[test]
        fn $name() {
            judged_world($id);
        }
    };
}

world_test!(n04_world_w01_ontime, "W01-ONTIME");
world_test!(n04_world_w02_cutoff_boundary, "W02-CUTOFF-BOUNDARY");
world_test!(
    n04_world_w03_uncertainty_moves_cutoff,
    "W03-UNCERTAINTY-MOVES-CUTOFF"
);
world_test!(n04_world_w04_reorder_duplicate, "W04-REORDER-DUPLICATE");
world_test!(n04_world_w05_burst_music, "W05-BURST-MUSIC");
world_test!(n04_world_w06_burst_realtime, "W06-BURST-REALTIME");
world_test!(n04_world_w07_epoch, "W07-EPOCH");
world_test!(n04_world_w08_window_and_input, "W08-WINDOW-AND-INPUT");
world_test!(n04_world_w09_repair, "W09-REPAIR");
world_test!(n04_world_w09b_repair_before_dac, "W09B-REPAIR-BEFORE-DAC");
world_test!(n04_world_w10_clock, "W10-CLOCK");
world_test!(n04_world_w11_overdue, "W11-OVERDUE");
world_test!(n04_world_w11b_overdue_boundary, "W11B-OVERDUE-BOUNDARY");
world_test!(n04_world_w12_latency_up, "W12-LATENCY-UP");
world_test!(n04_world_w12b_step_limit, "W12B-STEP-LIMIT");
world_test!(n04_world_w12c_step_limit, "W12C-STEP-LIMIT");
world_test!(n04_world_w12d_net_cap, "W12D-NET-CAP");
world_test!(n04_world_w13_latency_down, "W13-LATENCY-DOWN");
world_test!(n04_world_w13b_latency_down_exact, "W13B-LATENCY-DOWN-EXACT");
world_test!(n04_world_w14_backpressure, "W14-BACKPRESSURE");
world_test!(n04_world_w15_advice, "W15-ADVICE");
world_test!(n04_world_w15b_advice_quiet, "W15B-ADVICE-QUIET");
world_test!(n04_world_w16_seeded_music, "W16-SEEDED-MUSIC");
world_test!(n04_world_w17_seeded_realtime, "W17-SEEDED-REALTIME");

/// Unlike W16/W17 (separate policy-specific stress worlds), BOTH engines consume these exact same ordered ops.
/// The independent Python judge regenerates the seed's schedule and every policy-specific result, op by op.
#[test]
fn n04_both_policies_replay_the_identical_seeded_trace_with_backpressure() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../tests/n04/paired_trace.json"))
            .expect("paired trace parses");
    assert_eq!(fixture["schema"], "ffw.n04.paired-trace.v1");
    let ops = fixture["ops"].as_array().expect("paired ops");
    let trace_digest = digest(ops);
    assert_eq!(trace_digest, text(&fixture["trace_digest"]));
    let blocks = u(&fixture["blocks"]);
    assert_eq!(blocks, 700);
    assert!(u(&fixture["cfg"]["work_ns"]) > 0);
    assert!(u(&fixture["cfg"]["lead_ns"]) > 0);
    let mut policies = Vec::new();
    for (profile, conceal_max) in [("music", 8), ("realtime", 3)] {
        // Only the policy changes. There is one common arrival/decision/submission schedule, with no per-policy rescheduling.
        let world = json!({"profile": profile, "cfg": fixture["cfg"], "ops": ops});
        let mut next_block = 0u64;
        let mut real = 0u64;
        let mut muted_gap = 0u64;
        let mut maximum_run = 0u64;
        let mut delivered = 0u64;
        let mut abandoned = 0u64;
        let results = run_world_with(&world, &mut |_, op, result, engine| {
            assert!(engine.snapshot().queued <= u32::from(profile_named(profile).horizon_blocks));
            if op[0] == "decide" {
                assert_eq!(
                    result["poll"], "decision",
                    "{profile}: every due position must be decided"
                );
                let decision = &result["d"];
                assert_eq!(
                    u(&decision["block"]),
                    next_block,
                    "{profile}: exactly once, in order"
                );
                let payload_frames =
                    if decision["outcome"] == "real" || decision["outcome"] == "concealed" {
                        256
                    } else {
                        0 // A muted decision advances one block but carries no audio payload.
                    };
                assert_eq!(u(&decision["frames"]), payload_frames);
                next_block += 1;
                if decision["outcome"] == "real" {
                    real += 1;
                } else if decision["outcome"] == "muted_gap" {
                    muted_gap += 1;
                }
                if let Some(run) = decision["run"].as_u64() {
                    maximum_run = maximum_run.max(run);
                }
            } else if op[0] == "deliver" {
                match text(&result["delivery"]) {
                    "delivered" => delivered += 1,
                    "abandoned" => abandoned += 1,
                    other => panic!("unknown delivery outcome {other}"),
                }
            }
        });
        assert_eq!(next_block, blocks);
        assert!(
            real > 0 && muted_gap > 0,
            "{profile}: positive playback and long-gap silence must both be reached"
        );
        assert_eq!(
            maximum_run, conceal_max,
            "{profile}: its own concealment bound is exercised"
        );
        assert!(
            delivered > 0 && abandoned > 0,
            "{profile}: permitted submission and backpressure must both be reached"
        );
        assert_eq!(delivered + abandoned, blocks);
        let got = digest(&results);
        assert_eq!(got, text(&fixture["expected_digests"][profile]));
        policies.push(json!({"profile": profile, "trace_digest": trace_digest, "digest": got, "results": results}));
    }
    observed(
        &json!({"id": "n04-paired-seeded", "seed": fixture["seed"], "blocks": blocks,
                     "trace_digest": trace_digest, "policies": policies}),
    );
}

const WORLD_IDS: [&str; 24] = [
    "W01-ONTIME",
    "W02-CUTOFF-BOUNDARY",
    "W03-UNCERTAINTY-MOVES-CUTOFF",
    "W04-REORDER-DUPLICATE",
    "W05-BURST-MUSIC",
    "W06-BURST-REALTIME",
    "W07-EPOCH",
    "W08-WINDOW-AND-INPUT",
    "W09-REPAIR",
    "W09B-REPAIR-BEFORE-DAC",
    "W10-CLOCK",
    "W11-OVERDUE",
    "W11B-OVERDUE-BOUNDARY",
    "W12-LATENCY-UP",
    "W12B-STEP-LIMIT",
    "W12C-STEP-LIMIT",
    "W12D-NET-CAP",
    "W13-LATENCY-DOWN",
    "W13B-LATENCY-DOWN-EXACT",
    "W14-BACKPRESSURE",
    "W15-ADVICE",
    "W15B-ADVICE-QUIET",
    "W16-SEEDED-MUSIC",
    "W17-SEEDED-REALTIME",
];

#[test]
fn n04_every_world_in_the_vectors_has_a_test() {
    let mut in_vectors: Vec<&str> = vectors()["worlds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| text(&w["id"]))
        .collect();
    let mut covered = WORLD_IDS.to_vec();
    in_vectors.sort_unstable();
    covered.sort_unstable();
    assert_eq!(in_vectors, covered);
}

// -- profiles, pure functions, tables -------------------------------------------------------------------------

#[test]
fn n04_profiles_are_the_frozen_table() {
    let v = vectors();
    assert_eq!(text(&v["profile_version"]), PROFILE_VERSION);
    for p in [PlayoutProfile::MUSIC, PlayoutProfile::REALTIME] {
        let r = &v["profiles"][p.name];
        assert_eq!(u(&r["horizon"]), u64::from(p.horizon_blocks), "{}", p.name);
        assert_eq!(
            u(&r["max_conceal"]),
            u64::from(p.max_conceal_blocks),
            "{}",
            p.name
        );
        assert_eq!(u(&r["notice"]), u64::from(p.notice_blocks), "{}", p.name);
        assert_eq!(
            u(&r["max_step"]),
            u64::from(p.max_step_blocks),
            "{}",
            p.name
        );
        assert_eq!(u(&r["max_net"]), u64::from(p.max_net_blocks), "{}", p.name);
        assert!(usize::from(p.max_conceal_blocks) <= CONCEAL_GAIN_Q15.len());
    }
    // The two horizons in time: 94 blocks is 501.333333 ms (floor), 9 blocks is exactly 48 ms.
    assert_eq!(frames_to_ns(94 * BLOCK_FRAMES), 501_333_333);
    assert_eq!(frames_to_ns(9 * BLOCK_FRAMES), 48_000_000);
    observed(&json!({"id": "n04-profiles", "profile_version": PROFILE_VERSION}));
}

fn capacity_cfg() -> PlayoutConfig {
    PlayoutConfig {
        work_ns: 1_500_000,
        lead_ns: 2_000_000,
        tolerance_ns: 100_000,
    }
}

fn zero_horizon() -> PlayoutProfile {
    PlayoutProfile {
        horizon_blocks: 0,
        ..PlayoutProfile::REALTIME
    }
}

#[test]
fn n04_capacity_the_footprint_is_stated_from_the_slot_and_matches_what_new_builds() {
    // A slot is the 1024-byte payload, a u16 frame count and a use flag: 1027 bytes, 1028 with the count's 2-byte alignment.
    const { assert!(SLOT_BYTES > BLOCK_PAYLOAD_BYTES + 2) };
    assert_eq!(SLOT_BYTES, 1028);
    // 94 x 1028 = 96 632 and 9 x 1028 = 9 252, worked out by hand; a horizon of zero still gets the one slot new() builds.
    assert_eq!(PlayoutProfile::MUSIC.playout_queue_bytes(), 96_632);
    assert_eq!(PlayoutProfile::REALTIME.playout_queue_bytes(), 9_252);
    assert_eq!(zero_horizon().playout_queue_bytes(), 1_028);
    // The stated numbers are what new() builds, read off the engine itself.
    for p in [
        PlayoutProfile::MUSIC,
        PlayoutProfile::REALTIME,
        zero_horizon(),
    ] {
        let eng = PlayoutEngine::new(p, capacity_cfg()).expect("valid configuration");
        assert_eq!(
            eng.slots.len() * core::mem::size_of::<Slot>(),
            p.playout_queue_bytes(),
            "{}",
            p.name
        );
        assert_eq!(
            PlayoutEngine::resident_bytes(&p),
            core::mem::size_of::<PlayoutEngine>() + p.playout_queue_bytes(),
            "{}",
            p.name
        );
    }
    // The struct holds, at least, the history, the arrival margins and the last real block it declares.
    assert!(
        core::mem::size_of::<PlayoutEngine>()
            >= HISTORY_BLOCKS + MARGIN_WINDOW * 8 + BLOCK_PAYLOAD_BYTES
    );
}

#[test]
fn n04_capacity_the_footprint_arithmetic_is_checked_and_the_widest_profile_is_refused_not_wrapped()
{
    assert_eq!(footprint(94, 1028, 1000), Some(94 * 1028 + 1000));
    assert_eq!(footprint(0, 1028, 7), Some(7));
    // The product wraps: refused, never a small number.
    assert_eq!(footprint(usize::MAX, 2, 0), None);
    assert_eq!(footprint(usize::MAX / 2 + 1, 2, 0), None);
    // The largest product that fits, the sum landing exactly on the top, and the sum that wraps.
    assert_eq!(footprint(usize::MAX / 2, 2, 0), Some(usize::MAX - 1));
    assert_eq!(footprint(usize::MAX / 2, 2, 1), Some(usize::MAX));
    assert_eq!(footprint(usize::MAX / 2, 2, 2), None);
    // The widest profile a u16 horizon names is representable on this target (also a compile-time assertion), and a budget that fits
    // the music profile refuses it with both numbers named, before anything is allocated.
    let widest = PlayoutProfile {
        horizon_blocks: u16::MAX,
        ..PlayoutProfile::MUSIC
    };
    assert_eq!(
        widest.playout_queue_bytes(),
        usize::from(u16::MAX) * SLOT_BYTES
    );
    let music = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
    let wide = PlayoutEngine::resident_bytes(&widest);
    assert_eq!(
        wide,
        usize::from(u16::MAX) * SLOT_BYTES + core::mem::size_of::<PlayoutEngine>()
    );
    assert!(matches!(
        PlayoutEngine::new_within(widest, capacity_cfg(), music),
        Err(AdmitError::Capacity(CapacityError { needed_bytes, budget_bytes }))
            if needed_bytes == wide && budget_bytes == music
    ));
}

#[test]
fn n04_capacity_an_engine_is_built_only_within_its_budget_and_a_refusal_builds_nothing() {
    let cfg = capacity_cfg();
    let need = PlayoutEngine::resident_bytes(&PlayoutProfile::MUSIC);
    let rt = PlayoutEngine::resident_bytes(&PlayoutProfile::REALTIME);
    assert!(rt < need);
    // Exactly the budget: admitted, and it is the engine new() builds.
    let within = PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need).expect("fits exactly");
    let plain = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg).expect("valid configuration");
    assert_eq!(within.snapshot(), plain.snapshot());
    assert_eq!(within.profile(), plain.profile());
    // One byte short: a typed capacity error that names both numbers.
    let short = PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, need - 1)
        .expect_err("one byte short is refused");
    assert_eq!(
        short,
        AdmitError::Capacity(CapacityError {
            needed_bytes: need,
            budget_bytes: need - 1,
        })
    );
    assert_eq!(short.code(), "capacity");
    // No budget at all is a refusal too, and a generous one admits.
    assert_eq!(
        PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, 0).expect_err("no budget"),
        AdmitError::Capacity(CapacityError {
            needed_bytes: need,
            budget_bytes: 0,
        })
    );
    assert!(PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, usize::MAX).is_ok());
    // A profile that does not fit is refused, not shrunk: the realtime budget builds realtime and refuses music.
    assert!(PlayoutEngine::new_within(PlayoutProfile::REALTIME, cfg, rt).is_ok());
    let music_in_realtime_budget = PlayoutEngine::new_within(PlayoutProfile::MUSIC, cfg, rt);
    assert!(matches!(
        music_in_realtime_budget,
        Err(AdmitError::Capacity(CapacityError { needed_bytes, budget_bytes })) if needed_bytes == need && budget_bytes == rt
    ));
    // The configuration is judged first, whatever the budget.
    let bad = PlayoutConfig { work_ns: 0, ..cfg };
    for budget in [0, need - 1, need, usize::MAX] {
        let refused = PlayoutEngine::new_within(PlayoutProfile::MUSIC, bad, budget)
            .expect_err("an invalid configuration is never built");
        assert_eq!(
            refused,
            AdmitError::Config(ConfigError::WorkNotPositive),
            "{budget}"
        );
        assert_eq!(refused.code(), "work_ns");
    }
    observed(&json!({
        "id": "n04-capacity",
        "slot_bytes": SLOT_BYTES,
        "inline_bytes": core::mem::size_of::<PlayoutEngine>(),
        "music_queue_bytes": PlayoutProfile::MUSIC.playout_queue_bytes(),
        "realtime_queue_bytes": PlayoutProfile::REALTIME.playout_queue_bytes(),
        "zero_horizon_queue_bytes": zero_horizon().playout_queue_bytes(),
        "music_resident_bytes": need,
        "realtime_resident_bytes": rt,
        "admitted_at_budget": true,
        "refused_one_byte_short": {"needed_bytes": need, "budget_bytes": need - 1, "code": short.code()},
        "config_error_wins_at_zero_budget": AdmitError::Config(ConfigError::WorkNotPositive).code(),
        "realtime_budget_refuses_music": true,
    }));
}

#[test]
fn n04_frames_to_ns_table_matches_the_reference_and_the_hand_derived_anchors() {
    let rows = vectors()["tables"]["frames_to_ns"].as_array().unwrap();
    let mut observed_rows = Vec::new();
    for r in rows {
        let (frames, want) = (u(&r[0]), u(&r[1]));
        assert_eq!(frames_to_ns(frames), want, "{frames} frames");
        observed_rows.push(json!([frames, frames_to_ns(frames)]));
    }
    // 1e9 / 48000 = 62500 / 3 ns per frame.
    assert_eq!(frames_to_ns(48_000), 1_000_000_000);
    assert_eq!(frames_to_ns(256), 5_333_333);
    assert_eq!(frames_to_ns(3), 62_500);
    assert_eq!(BLOCK_NS, frames_to_ns(BLOCK_FRAMES));
    observed(&json!({"id": "n04-frames-to-ns", "rows": observed_rows}));
}

#[test]
fn n04_consume_by_table_matches_the_reference_and_the_hand_derived_anchors() {
    let mut observed_rows = Vec::new();
    for r in vectors()["tables"]["consume_by"].as_array().unwrap() {
        let got = consume_by(u(&r[0]), u(&r[1]), u(&r[2]), u(&r[3]));
        assert_eq!(got, u(&r[4]), "{r}");
        observed_rows.push(json!([r[0], r[1], r[2], r[3], got]));
    }
    // 1 s presentation, 1.5 ms work, 2 ms lead, 0.2 ms uncertainty: 3.7 ms earlier.
    assert_eq!(
        consume_by(1_000_000_000, 1_500_000, 2_000_000, 200_000),
        996_300_000
    );
    // Equal to the guard: cutoff 0. Guard larger than the presentation time: clamped at 0, never wrapped.
    assert_eq!(consume_by(7_000_000, 1_500_000, 2_000_000, 3_500_000), 0);
    assert_eq!(consume_by(7_000_000, 1_500_000, 2_000_000, 3_500_001), 0);
    assert_eq!(consume_by(7_000_000, 1_500_000, 2_000_000, 3_499_999), 1);
    assert_eq!(consume_by(0, 1, 1, 0), 0);
    observed(&json!({"id": "n04-consume-by", "rows": observed_rows}));
}

#[test]
fn n04_conceal_gains_are_round_0_7_pow_n_in_q15() {
    let reference: Vec<i64> = vectors()["tables"]["conceal_gains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_i64().unwrap())
        .collect();
    for (n, gain) in CONCEAL_GAIN_Q15.iter().enumerate() {
        let exact = (0.7_f64.powi(i32::try_from(n + 1).unwrap()) * 32768.0).round();
        assert_eq!(f64::from(*gain), exact, "gain {}", n + 1);
        assert_eq!(i64::from(*gain), reference[n]);
    }
    observed(&json!({"id": "n04-conceal-gains", "gains": CONCEAL_GAIN_Q15}));
}

fn concealed_of(samples: &[i16], run: u8) -> Vec<i16> {
    let mut last = [0u8; BLOCK_PAYLOAD_BYTES];
    for (i, s) in samples.iter().enumerate() {
        last[i * 2..i * 2 + 2].copy_from_slice(&s.to_be_bytes());
    }
    let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
    conceal_block(&last, run, &mut out);
    (0..samples.len())
        .map(|i| i16::from_be_bytes([out[i * 2], out[i * 2 + 1]]))
        .collect()
}

#[test]
fn n04_conceal_blocks_match_the_reference_and_the_hand_derived_samples() {
    let mut rows = Vec::new();
    for r in vectors()["tables"]["conceal_blocks"].as_array().unwrap() {
        let (seed, run, frames) = (
            u(&r["seed"]),
            u8::try_from(u(&r["run"])).unwrap(),
            u(&r["frames"]),
        );
        let payload = synth_payload(seed, frames);
        let mut last = [0u8; BLOCK_PAYLOAD_BYTES];
        last[..payload.len()].copy_from_slice(&payload);
        let mut out = [0u8; BLOCK_PAYLOAD_BYTES];
        conceal_block(&last, run, &mut out);
        let got = fnv_hex(&out);
        assert_eq!(
            got,
            text(&r["fnv"]),
            "seed {seed} run {run} frames {frames}"
        );
        rows.push(json!({"seed": seed, "run": run, "frames": frames, "fnv": got}));
    }
    // Computed by exact integer division, floor((s * gain + 16384) / 32768), not by the shift the code uses.
    let samples: [i16; 11] = [10000, -10000, 32767, -32768, 0, 1, -1, 2, -2, 16384, -16384];
    assert_eq!(
        concealed_of(&samples, 1),
        [7000, -7000, 22937, -22938, 0, 1, -1, 1, -1, 11469, -11469]
    );
    assert_eq!(
        concealed_of(&samples, 8),
        [576, -576, 1889, -1889, 0, 0, 0, 0, 0, 945, -944],
        "round half up: +16384 rounds to 945, -16384 to -944"
    );
    // A run past the table is clamped to the last gain, never an out-of-range index.
    assert_eq!(concealed_of(&samples, 9), concealed_of(&samples, 8));
    assert_eq!(concealed_of(&samples, 0), concealed_of(&samples, 1));
    observed(&json!({"id": "n04-conceal-blocks", "rows": rows}));
}

#[test]
fn n04_invalid_configurations_are_refused_field_by_field() {
    let mut rows = Vec::new();
    for r in vectors()["tables"]["configs"].as_array().unwrap() {
        let c = &r["cfg"];
        // The reference's tolerance may be negative to test its own guard; the Rust type cannot hold that.
        let want = r["bad"].as_str();
        let got = match (
            c["work_ns"].as_u64(),
            c["lead_ns"].as_u64(),
            c["tolerance_ns"].as_u64(),
        ) {
            (Some(w), Some(l), Some(t)) => PlayoutConfig {
                work_ns: w,
                lead_ns: l,
                tolerance_ns: t,
            }
            .validate()
            .err()
            .map(ConfigError::code),
            _ => Some("tolerance_ns"),
        };
        assert_eq!(got, want, "{c}");
        rows.push(json!({"cfg": c, "bad": got}));
    }
    let ok = PlayoutConfig {
        work_ns: 1,
        lead_ns: 1,
        tolerance_ns: BLOCK_NS / 2 - 1,
    };
    assert_eq!(ok.validate(), Ok(()));
    assert!(PlayoutEngine::new(PlayoutProfile::MUSIC, PlayoutConfig { work_ns: 0, ..ok }).is_err());
    observed(&json!({"id": "n04-configs", "rows": rows}));
}

#[test]
fn n04_advice_table_matches_the_reference() {
    let mut rows = Vec::new();
    for r in vectors()["tables"]["advice"].as_array().unwrap() {
        let margins: Vec<i64> = r["margins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_i64().unwrap())
            .collect();
        let net = r["net_shift_ns"].as_i64().unwrap();
        let adv = latency_advice(&margins, net, &profile_named(text(&r["profile"])));
        let got = json!({"action": adv.action.code(), "blocks": adv.blocks, "reason": adv.reason});
        assert_eq!(got, r["out"], "{} margins, net {net}", margins.len());
        rows.push(got);
    }
    observed(&json!({"id": "n04-advice", "rows": rows}));
}

// -- the sender's deadline is not the receiver's ---------------------------------------------------------------

fn media_packet(kind: crate::PacketKind, consume_by_ns: u64) -> crate::AuthenticatedStreamPacket {
    crate::AuthenticatedStreamPacket {
        stream_id: crate::StreamId::new(0xA11C_E000_0000_0001).unwrap(),
        session_epoch: 1,
        seq: 0,
        kind,
        format: crate::StreamFormat::Pcm16BeStereo48k,
        flags: 0,
        start_frame: 0,
        presentation_time_ns: 2_000_000_000,
        consume_by_ns,
        fec_group_id: 0,
        fec_index: 0,
        fec_group_size: 0,
        payload: synth_payload(0, 256),
    }
}

#[test]
fn n04_the_senders_consume_by_never_extends_a_deadline() {
    let cfg = PlayoutConfig {
        work_ns: 1_500_000,
        lead_ns: 2_000_000,
        tolerance_ns: 100_000,
    };
    let cutoff = consume_by(2_000_000_000, cfg.work_ns, cfg.lead_ns, 200_000);
    let view = |t| ClockView {
        group_ns: t,
        uncertainty_ns: 200_000,
        usable: true,
    };
    // The sender claims a deadline a whole second after presentation. The receiver's own cutoff governs.
    let pkt = media_packet(crate::PacketKind::Media, 3_000_000_000);
    let media = MediaPacket::from_authenticated(&pkt).expect("a media packet");
    assert_eq!((media.epoch, media.start_frame, media.frames), (1, 0, 256));
    for (t, want) in [
        (cutoff - 1, Admission::Admitted),
        (cutoff, Admission::Late),
        (cutoff + 1, Admission::Late),
    ] {
        let mut eng = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg).unwrap();
        eng.begin_stream(1, 0, 2_000_000_000).unwrap();
        assert_eq!(
            eng.on_packet(view(t), &media),
            want,
            "arrival {t} against cutoff {cutoff}"
        );
    }
    // And the other direction: a sender that claims the deadline already passed does not make an on-time packet late.
    let early = media_packet(crate::PacketKind::Media, 0);
    let mut eng = PlayoutEngine::new(PlayoutProfile::MUSIC, cfg).unwrap();
    eng.begin_stream(1, 0, 2_000_000_000).unwrap();
    assert_eq!(
        eng.on_packet(
            view(cutoff - 1),
            &MediaPacket::from_authenticated(&early).unwrap()
        ),
        Admission::Admitted
    );
    // A repair packet is not media.
    assert!(MediaPacket::from_authenticated(&media_packet(crate::PacketKind::Repair, 0)).is_none());
    observed(&json!({"id": "n04-sender-consume-by", "cutoff": cutoff}));
}

// -- properties, with this file's own arithmetic ----------------------------------------------------------------

#[test]
fn n04_properties_hold_on_every_world() {
    let mut report = Vec::new();
    for world in vectors()["worlds"].as_array().unwrap() {
        let id = text(&world["id"]);
        let horizon = u64::from(profile_named(text(&world["profile"])).horizon_blocks);
        let (work, lead) = (u(&world["cfg"]["work_ns"]), u(&world["cfg"]["lead_ns"]));
        let changes = world["ops"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| text(&o[0]) == "change");
        let mut origin: Option<u64> = None;
        let mut played_seed: BTreeMap<u64, u64> = BTreeMap::new();
        let mut decisions = 0u64;
        let mut next_block: Option<u64> = None;
        let mut checked_admits = 0u64;
        let mut hook = |_: usize, op: &Value, result: &Value, eng: &PlayoutEngine| {
            let snap = eng.snapshot();
            // Buffer growth never exceeds the profile, after every single operation.
            assert!(
                u64::from(snap.queued) <= horizon,
                "{id}: {} queued of {horizon}",
                snap.queued
            );
            let a = op.as_array().unwrap();
            match text(&a[0]) {
                "begin" if result["ok"] == true => {
                    let frame = u(&a[2]);
                    origin = Some(u(&a[3]) - frames_to_ns(frame));
                    played_seed.clear();
                    next_block = Some(frame / BLOCK_FRAMES);
                }
                "packet" | "repair" if result["r"] == "admitted" => {
                    let frame = u(&a[5]);
                    let seed = if text(&a[0]) == "packet" {
                        u(&a[8])
                    } else {
                        u(&a[7])
                    };
                    played_seed.insert(frame / BLOCK_FRAMES, seed);
                    // Never admitted at or after its own cutoff (skipped where a latency change moves the timeline).
                    if !changes && text(&a[0]) == "packet" {
                        let pres = origin.unwrap() + frames_to_ns(frame);
                        let cutoff = pres.saturating_sub(work + lead + u(&a[2]));
                        assert!(
                            u(&a[1]) < cutoff,
                            "{id}: admitted at {} with cutoff {cutoff}",
                            u(&a[1])
                        );
                        checked_admits += 1;
                    }
                }
                "decide" if result["poll"] == "decision" => {
                    let d = &result["d"];
                    let block = u(&d["block"]);
                    // Exactly one decision per block, in order, none repeated, none skipped over.
                    assert_eq!(Some(block), next_block, "{id}: decision for block {block}");
                    next_block = Some(block + 1);
                    decisions += 1;
                    if d["outcome"] == "real" {
                        let seed = played_seed
                            .get(&block)
                            .copied()
                            .expect("a real block was admitted");
                        let frames = u(&d["frames"]);
                        // The bytes played are the bytes that were admitted for that block, not another's.
                        assert_eq!(
                            text(&d["fnv"]),
                            fnv_hex(&synth_payload(seed, frames)),
                            "{id}: block {block}"
                        );
                    }
                    if d["outcome"] == "skipped"
                        || d["outcome"].as_str().unwrap().starts_with("muted")
                    {
                        assert!(d.get("fnv").is_none(), "{id}: silence carries no audio");
                    }
                }
                _ => {}
            }
        };
        run_world_with(world, &mut hook);
        report.push(json!({"id": id, "decisions": decisions, "admits_checked": checked_admits}));
    }
    observed(&json!({"id": "n04-properties", "worlds": report}));
}

#[test]
fn n04_counters_account_for_every_packet_and_every_decision() {
    for id in ["W16-SEEDED-MUSIC", "W17-SEEDED-REALTIME"] {
        let world = find_world(id);
        let packets = world["ops"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| text(&o[0]) == "packet")
            .count() as u64;
        let results = run_world(world);
        let snap = results.last().unwrap();
        let s = &snap["stats"];
        let admission: u64 = [
            "admitted",
            "duplicate",
            "late",
            "stale_epoch",
            "future_epoch",
            "clock_unusable",
            "clock_regressions",
            "bad_input",
            "too_far_ahead",
            "timeline_mismatch",
            "not_bound",
        ]
        .iter()
        .map(|k| u(&s[*k]))
        .sum();
        assert_eq!(u(&s["packets_seen"]), packets, "{id}");
        assert_eq!(
            admission, packets,
            "{id}: every packet has exactly one fate"
        );
        let decided: u64 = [
            "decided_real",
            "decided_concealed",
            "decided_muted_gap",
            "decided_muted_nohistory",
            "decided_muted_overdue",
            "decided_skipped",
        ]
        .iter()
        .map(|k| u(&s[*k]))
        .sum();
        assert_eq!(decided, u(&snap["cursor"]), "{id}: one decision per block");
        // A block admitted but then decided overdue is not played, so this is an inequality, never an equality.
        assert!(
            u(&s["admitted"]) >= u(&s["decided_real"]),
            "{id}: more blocks played than were ever admitted"
        );
        observed(
            &json!({"id": format!("n04-accounting-{}", id.to_lowercase()), "packets": packets, "decided": decided}),
        );
    }
}

// ---- diagnostics (contract section 11) ------------------------------------------------------------------------
//
// The same worlds are run with the log on and a scripted sink. The expected lines are the reference's (checked here by
// count, kind and digest, and by the judge line by line); the claims that need no reference are checked with this
// file's own arithmetic: one line per decision and per refusal, nothing cut or reordered, every record accounted for,
// and the decisions identical to the run with no log.

fn log_config(world: &Value, plan: &Value) -> LogConfig {
    let v = &vectors()["log"];
    let cfg = LogConfig::new(
        text(&v["run_id"]),
        &text(&world["id"]).to_lowercase(),
        text(&v["member_id"]),
        text(&v["group_id"]),
        usize::try_from(u(&plan["capacity"])).unwrap(),
    )
    .expect("valid log config");
    match plan.get("max_line") {
        Some(m) => cfg
            .with_max_line(usize::try_from(u(m)).unwrap())
            .expect("valid bound"),
        None => cfg,
    }
}

fn reply_of(name: &str) -> SinkReply {
    match name {
        "taken" => SinkReply::Taken,
        "full" => SinkReply::Full,
        "unavailable" => SinkReply::Unavailable,
        other => panic!("unknown sink reply {other}"),
    }
}

/// A sink that answers from a script, repeating it, and keeps the lines it takes.
struct ScriptedSink {
    replies: Vec<SinkReply>,
    next: usize,
    taken: Vec<String>,
}

impl ScriptedSink {
    fn new(replies: Vec<SinkReply>) -> Self {
        Self {
            replies,
            next: 0,
            taken: Vec::new(),
        }
    }
}

impl LogSink for ScriptedSink {
    fn offer(&mut self, line: &str) -> SinkReply {
        let reply = self.replies[self.next % self.replies.len()];
        self.next += 1;
        if reply == SinkReply::Taken {
            self.taken.push(line.to_string());
        }
        reply
    }
}

struct LoggedRun {
    results: Vec<Value>,
    stats: LogStats,
    delivered: Vec<String>,
    /// What was still queued at the end (taken out afterwards, so the counts above are the run's own).
    rest: Vec<String>,
}

/// Run a world with the log on. After every `drain_every` ops, offer up to `budget` lines to a sink that answers from
/// the plan's script; at the end, `final_budget` more. `after_op` sees the engine after every op.
fn run_logged(world: &Value, plan: &Value, mut after_op: impl FnMut(&PlayoutEngine)) -> LoggedRun {
    let mut eng = new_engine(world);
    eng.enable_log(log_config(world, plan));
    let replies = plan["replies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| reply_of(text(r)))
        .collect();
    let mut sink = ScriptedSink::new(replies);
    let drain_every = usize::try_from(u(&plan["drain_every"])).unwrap();
    let budget = usize::try_from(u(&plan["budget"])).unwrap();
    let final_budget = plan
        .get("final_budget")
        .map_or(0, |v| usize::try_from(u(v)).unwrap());
    let mut buf = [0u8; BLOCK_PAYLOAD_BYTES];
    let mut last_deadline = 0u64;
    let mut results = Vec::new();
    for (i, op) in world["ops"].as_array().unwrap().iter().enumerate() {
        results.push(apply_op(&mut eng, op, &mut buf, &mut last_deadline));
        if (i + 1) % drain_every == 0 {
            eng.drain_log(&mut sink, budget);
        }
        after_op(&eng);
    }
    eng.drain_log(&mut sink, final_budget);
    let stats = eng.log_stats().expect("the log is on");
    let mut rest = ScriptedSink::new(vec![SinkReply::Taken]);
    eng.drain_log(&mut rest, usize::MAX);
    LoggedRun {
        results,
        stats,
        delivered: sink.taken,
        rest: rest.taken,
    }
}

/// sha256 of the lines, each followed by a newline: what a JSONL file of them hashes to.
fn lines_digest(lines: &[String]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn stats_json(stats: LogStats) -> Value {
    serde_json::to_value(stats).expect("stats serialize")
}

fn log_observation(id: String, run: &LoggedRun) -> Value {
    json!({
        "id": id,
        "results_digest": digest(&run.results),
        "stats": stats_json(run.stats),
        "complete": run.stats.evidence_complete(),
        "delivered_fnv": run.delivered.iter().map(|l| fnv_hex(l.as_bytes())).collect::<Vec<_>>(),
        "rest_fnv": run.rest.iter().map(|l| fnv_hex(l.as_bytes())).collect::<Vec<_>>(),
    })
}

/// The event kind an op's result must have produced, from the result alone (no reference, no engine state).
fn expected_kind(op: &Value, result: &Value) -> Option<String> {
    let a = op.as_array().unwrap();
    match text(&a[0]) {
        "begin" => Some(
            if result["ok"] == true {
                "n04.stream.started"
            } else {
                "n04.stream.refused"
            }
            .to_string(),
        ),
        "packet" | "bad" | "repair" if result["r"] != "admitted" => {
            Some(format!("n04.refusal.{}", text(&result["r"])))
        }
        "decide" => match text(&result["poll"]) {
            "pending" => None,
            "decision" => Some(format!("n04.decision.{}", text(&result["d"]["outcome"]))),
            other => Some(format!("n04.poll.{other}")),
        },
        "change" => Some(
            if result["ok"] == true {
                "n04.change.accepted"
            } else {
                "n04.change.refused"
            }
            .to_string(),
        ),
        "deliver" => Some(format!("n04.delivery.{}", text(&result["delivery"]))),
        _ => None,
    }
}

fn kind_of(line: &str) -> String {
    let v: Value = serde_json::from_str(line).expect("a JSON line");
    text(&v["event_kind"]).to_string()
}

/// `needle` is `hay` with some elements removed, order kept.
fn is_subsequence(needle: &[String], hay: &[String]) -> bool {
    let mut at = hay.iter();
    needle.iter().all(|n| at.any(|h| h == n))
}

#[test]
fn n04_log_keeps_up_logs_every_decision_and_refusal() {
    // The paired positive: with a sink that keeps up, nothing is lost, every decision and refusal has its line, and
    // the decisions are exactly the ones the reference takes with no log at all.
    let plan = &vectors()["keeps_up"];
    for world in vectors()["worlds"].as_array().unwrap() {
        let id = text(&world["id"]);
        let run = run_logged(world, plan, |_| {});
        assert_eq!(
            digest(&run.results),
            text(&world["digest"]),
            "{id}: the log changed a decision"
        );
        let ops = world["ops"].as_array().unwrap();
        let want: Vec<String> = ops
            .iter()
            .zip(&run.results)
            .filter_map(|(op, r)| expected_kind(op, r))
            .collect();
        let got: Vec<String> = run.delivered.iter().map(|l| kind_of(l)).collect();
        assert_eq!(got, want, "{id}: not one line per decision and refusal");
        let decisions = run
            .results
            .iter()
            .filter(|r| r["poll"] == "decision")
            .count();
        assert_eq!(
            got.iter()
                .filter(|k| k.starts_with("n04.decision."))
                .count(),
            decisions,
            "{id}: a decision without its line"
        );
        let count = u(&world["log"]["count"]);
        assert_eq!(run.delivered.len() as u64, count, "{id}");
        assert_eq!(
            lines_digest(&run.delivered),
            text(&world["log"]["digest"]),
            "{id}: the lines differ from the reference's"
        );
        let s = run.stats;
        assert_eq!(
            (
                s.emitted,
                s.delivered,
                s.queued,
                s.dropped(),
                s.critical_lost,
                s.offers
            ),
            (count, count, 0, 0, 0, count),
            "{id}: {s}"
        );
        assert!(s.accounted() && s.evidence_complete(), "{id}: {s}");
        assert!(run.rest.is_empty(), "{id}");
        assert!(
            run.delivered.iter().all(|l| l.len() <= MAX_LINE_BYTES),
            "{id}"
        );
        observed(&log_observation(
            format!("n04-log-{}", id.to_lowercase()),
            &run,
        ));
    }
}

#[test]
fn n04_log_loss_is_counted_when_the_sink_is_slow_full_or_unavailable() {
    // Slow (drained rarely), full, unavailable, flapping, and a ring too small: records are lost, never silently, and
    // not one decision differs from the run with no log.
    let keeps_up = &vectors()["keeps_up"];
    for sc in vectors()["log_scenarios"].as_array().unwrap() {
        let id = text(&sc["id"]);
        let world = find_world(text(&sc["world"]));
        let run = run_logged(world, &sc["plan"], |_| {});
        assert_eq!(
            digest(&run.results),
            text(&world["digest"]),
            "{id}: the sink changed a decision"
        );
        let s = run.stats;
        assert_eq!(stats_json(s), sc["stats"], "{id}: {s}");
        if let Some(expect) = sc["expect"].as_object() {
            for (key, want) in expect {
                assert_eq!(
                    &stats_json(s)[key.as_str()],
                    want,
                    "{id}: hand-derived {key}"
                );
            }
        }
        assert!(s.accounted(), "{id}: {s}");
        assert!(s.critical_lost <= s.dropped(), "{id}: {s}");
        assert_eq!(s.evidence_complete(), sc["complete"] == true, "{id}: {s}");
        assert_eq!(
            run.delivered.len() as u64 + run.rest.len() as u64 + s.dropped(),
            s.emitted,
            "{id}: counted from the lines themselves"
        );
        assert_eq!(
            run.delivered.len() as u64,
            u(&sc["delivered"]["count"]),
            "{id}"
        );
        assert_eq!(
            lines_digest(&run.delivered),
            text(&sc["delivered"]["digest"]),
            "{id}"
        );
        assert_eq!(run.rest.len() as u64, u(&sc["rest"]["count"]), "{id}");
        assert_eq!(lines_digest(&run.rest), text(&sc["rest"]["digest"]), "{id}");
        // Nothing cut, nothing reordered: what was delivered, then what stayed queued, is the full log with some
        // lines missing (the ones counted as dropped).
        let full = run_logged(world, keeps_up, |_| {}).delivered;
        let mut kept = run.delivered.clone();
        kept.extend(run.rest.iter().cloned());
        assert!(
            is_subsequence(&kept, &full),
            "{id}: lines were cut or reordered"
        );
        if !s.evidence_complete() {
            assert!(s.to_string().ends_with("evidence=INCOMPLETE"), "{id}");
        }
        observed(&log_observation(
            format!("n04-logscn-{}", id.to_lowercase()),
            &run,
        ));
    }
}

#[test]
fn n04_log_accounting_holds_after_every_op() {
    // emitted = delivered + queued + dropped, and critical_lost <= dropped, after every single op of every world and
    // every sink scenario: a drop that went uncounted would show at the op that made it.
    let mut ops_checked = 0u64;
    let (mut unaccounted, mut critical_over) = (0u64, 0u64);
    let mut check = |eng: &PlayoutEngine| {
        let s = eng.log_stats().expect("the log is on");
        ops_checked += 1;
        unaccounted += u64::from(!s.accounted());
        critical_over += u64::from(s.critical_lost > s.dropped());
    };
    for world in vectors()["worlds"].as_array().unwrap() {
        run_logged(world, &vectors()["keeps_up"], &mut check);
    }
    for sc in vectors()["log_scenarios"].as_array().unwrap() {
        run_logged(find_world(text(&sc["world"])), &sc["plan"], &mut check);
    }
    observed(
        &json!({"id": "n04-log-accounting", "ops_checked": ops_checked,
                     "unaccounted": unaccounted, "critical_over_dropped": critical_over}),
    );
    assert_eq!((unaccounted, critical_over), (0, 0));
}

/// A sink that blocks: every offer costs one second of (virtual) wall time before it takes the line.
struct BlockingSink<'a> {
    wall_ns: &'a std::cell::Cell<u64>,
    offers: usize,
}

impl LogSink for BlockingSink<'_> {
    fn offer(&mut self, _line: &str) -> SinkReply {
        self.offers += 1;
        self.wall_ns.set(self.wall_ns.get() + 1_000_000_000);
        SinkReply::Taken
    }
}

#[test]
fn n04_log_a_blocking_sink_is_never_called_on_the_decision_path() {
    let world = find_world("W16-SEEDED-MUSIC");
    let ops = world["ops"].as_array().unwrap().len();
    let want_digest = text(&world["digest"]);

    // 1. The producer never waits. A ring of four slots with no consumer at all is full almost at once; the whole
    //    700-block world must still run to the end (a producer that waited for room would hang, and the watchdog
    //    turns the hang into a failure) and take exactly the decisions it takes with no log.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let plan =
            json!({"capacity": 4, "drain_every": 1_000_000, "budget": 0, "replies": ["taken"]});
        let run = run_logged(find_world("W16-SEEDED-MUSIC"), &plan, |_| {});
        let _ = tx.send((digest(&run.results), run.stats));
    });
    let (full_digest, full_stats) = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the decision path blocked on a full log");
    assert_eq!(full_digest, want_digest, "a full log changed a decision");
    assert!(
        full_stats.dropped_full > 600 && full_stats.accounted(),
        "{full_stats}"
    );

    // 2. The sink is reachable only through `drain_log`, which makes at most `budget` offers. After every op, a drain
    //    with a budget of zero costs the blocking sink nothing; a budget of three costs exactly three offers.
    let plan = json!({"capacity": 8, "drain_every": 1, "budget": 0, "replies": ["taken"]});
    let wall = std::cell::Cell::new(0u64);
    let mut sink = BlockingSink {
        wall_ns: &wall,
        offers: 0,
    };
    let mut eng = new_engine(world);
    eng.enable_log(log_config(world, &plan));
    let mut buf = [0u8; BLOCK_PAYLOAD_BYTES];
    let mut last_deadline = 0u64;
    let mut results = Vec::new();
    for op in world["ops"].as_array().unwrap() {
        results.push(apply_op(&mut eng, op, &mut buf, &mut last_deadline));
        eng.drain_log(&mut sink, 0);
    }
    let (path_offers, path_ns) = (sink.offers, wall.get());
    let queued = eng.log_stats().unwrap().queued;
    let report = eng.drain_log(&mut sink, 3);
    assert_eq!(digest(&results), want_digest);
    assert_eq!((path_offers, path_ns), (0, 0));
    assert!(queued > 0, "nothing was queued to offer");
    assert_eq!((report.offered, report.taken), (3, 3));
    assert_eq!(report.stop, DrainStop::Budget);
    observed(&json!({
        "id": "n04-log-blocking", "world": "W16-SEEDED-MUSIC", "ops": ops,
        "decision_path_offers": path_offers, "decision_path_virtual_ns": path_ns,
        "results_digest": digest(&results), "drain_budget": 3, "drain_offers": sink.offers,
        "drain_virtual_ns": wall.get(), "queued_before_drain_nonzero": queued > 0,
    }));
}
