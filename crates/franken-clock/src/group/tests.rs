//! N03 tests (`ffw-u07`). Expected values come from `tests/n03/reference.py` through `tests/n03/vectors.json`;
//! nothing here derives an expectation from the code under test. Each vector-driven test also prints one
//! `N03-OBSERVED {json}` line of what the Rust actually computed, which `tests/n03/run_cases.py` re-derives from
//! the reference and compares.

use super::*;
use serde_json::{Map, Value, json};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../tests/n03/vectors.json"))
        .expect("vectors.json parses")
}

fn u(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a u64 in {v}"))
}

fn observed(line: &Value) {
    println!("N03-OBSERVED {line}");
}

fn std_cfg() -> GroupClockConfig {
    GroupClockConfig::standard().expect("standard config")
}

fn cfg_with(over: &Value) -> GroupClockConfig {
    let mut cfg = std_cfg();
    if let Some(map) = over.as_object() {
        for (key, value) in map {
            let n = value
                .as_u64()
                .unwrap_or_else(|| panic!("override {key} is not a u64"));
            match key.as_str() {
                "max_delay_ns" => cfg.max_delay_ns = n,
                "request_ttl_ns" => cfg.request_ttl_ns = n,
                "lock_uncertainty_ns" => cfg.lock_uncertainty_ns = n,
                "fresh_ns" => cfg.fresh_ns = n,
                "calibration_uncertainty_ns" => cfg.calibration_uncertainty_ns = n,
                "output_delay_ns" => cfg.output_delay_ns = n,
                "catchup_ns" => cfg.catchup_ns = n,
                "max_future_ns" => cfg.max_future_ns = n,
                other => panic!("unknown config override {other}"),
            }
        }
    }
    cfg.validate().expect("overridden config is valid");
    cfg
}

fn sample_of(v: &Value) -> Sample {
    Sample {
        delay_ns: u(v, "delay"),
        local_mid_ns: u(v, "local_mid"),
        group_mid_ns: u(v, "group_mid"),
    }
}

fn anchor_of(sample: Sample, ratio_ppb: i64, ratio_unc_ppb: u64) -> Anchor {
    Anchor {
        sample,
        ratio_ppb,
        ratio_unc_ppb,
        uncertainty_ns: 0,
    }
}

fn status_of(code: &str) -> ClockStatus {
    match code {
        "Unlocked" => ClockStatus::Unlocked,
        "Locked" => ClockStatus::Locked,
        "Holdover" => ClockStatus::Holdover,
        "Expired" => ClockStatus::Expired,
        other => panic!("unknown status {other}"),
    }
}

fn opt_u64(v: &Value) -> Option<u64> {
    v.as_u64()
}

// ------------------------------------------------------------------------------------------ configuration

#[test]
fn n03_defaults_equal_the_reference_parameters() {
    let v = vectors();
    let c = std_cfg();
    let p = &v["params"];
    let got: [(&str, u64); 17] = [
        ("max_delay_ns", c.max_delay_ns),
        ("request_ttl_ns", c.request_ttl_ns),
        ("min_probes_for_lock", u64::from(c.min_probes_for_lock)),
        ("lock_uncertainty_ns", c.lock_uncertainty_ns),
        ("fresh_ns", c.fresh_ns),
        ("oscillator_bound_ppb", c.oscillator_bound_ppb),
        ("rate_sigma_multiple", c.rate_sigma_multiple),
        ("wander_ppb", c.wander_ppb),
        ("timer_resolution_ns", c.timer_resolution_ns),
        ("calibration_uncertainty_ns", c.calibration_uncertainty_ns),
        ("output_delay_ns", c.output_delay_ns),
        ("prediction_slack_ns", c.prediction_slack_ns),
        ("rate_delay_slack_ns", c.rate_delay_slack_ns),
        ("catchup_ns", c.catchup_ns),
        ("max_future_ns", c.max_future_ns),
        ("window", u64::from(c.window)),
        ("max_outstanding", u64::from(c.max_outstanding)),
    ];
    assert_eq!(
        p.as_object().expect("params object").len(),
        got.len(),
        "every reference parameter is checked"
    );
    for (name, value) in got {
        assert_eq!(u(p, name), value, "{name}");
    }
    assert_eq!(c.rate, RateConfig::for_rate(48_000).expect("rate defaults"));
    assert_eq!(u(&v, "frame_rate_hz"), u64::from(FRAME_RATE_HZ));
    assert_eq!(u(&v, "max_timestamp_ns"), MAX_TIMESTAMP_NS);
    observed(&json!({"kind": "defaults", "id": "n03-defaults", "params": p}));
}

#[test]
fn n03_invalid_configurations_are_refused_field_by_field() {
    type Mutation = Box<dyn Fn(&mut GroupClockConfig)>;
    let bad: Vec<(&str, Mutation)> = vec![
        ("window 0", Box::new(|c| c.window = 0)),
        (
            "window past the cap",
            Box::new(|c| c.window = MAX_WINDOW + 1),
        ),
        (
            "lock needs more probes than the window",
            Box::new(|c| c.min_probes_for_lock = c.window + 1),
        ),
        (
            "lock needs zero probes",
            Box::new(|c| c.min_probes_for_lock = 0),
        ),
        (
            "no outstanding requests",
            Box::new(|c| c.max_outstanding = 0),
        ),
        (
            "too many outstanding requests",
            Box::new(|c| c.max_outstanding = 65),
        ),
        (
            "zero uncertainty threshold",
            Box::new(|c| c.lock_uncertainty_ns = 0),
        ),
        ("zero freshness", Box::new(|c| c.fresh_ns = 0)),
        ("zero request lifetime", Box::new(|c| c.request_ttl_ns = 0)),
        (
            "max delay past the request lifetime",
            Box::new(|c| c.max_delay_ns = c.request_ttl_ns + 1),
        ),
        (
            "catch-up as long as the future window",
            Box::new(|c| c.catchup_ns = c.max_future_ns),
        ),
        (
            "oscillator bound past 1000 ppm",
            Box::new(|c| c.oscillator_bound_ppb = 1_000_001),
        ),
        (
            "wander past 1000 ppm",
            Box::new(|c| c.wander_ppb = 1_000_001),
        ),
        (
            "zero sigma multiple",
            Box::new(|c| c.rate_sigma_multiple = 0),
        ),
        (
            "sigma multiple past 10",
            Box::new(|c| c.rate_sigma_multiple = 11),
        ),
        (
            "invalid rate configuration",
            Box::new(|c| c.rate.nominal_rate_hz = 1),
        ),
    ];
    for (what, mutate) in bad {
        let mut c = std_cfg();
        mutate(&mut c);
        assert!(
            matches!(c.validate(), Err(GroupClockError::InvalidConfig(_))),
            "{what} must be refused"
        );
        assert!(
            GroupClock::new(c, 1, 7, 1).is_err(),
            "{what}: no member is built from it"
        );
    }
    assert!(std_cfg().validate().is_ok());
}

#[test]
fn n03_board_profile_terms_are_converted_from_microseconds() {
    let mut profile = franken_board_profile::synthetic_test_fixture_catalog()
        .into_iter()
        .next()
        .expect("a fixture profile");
    profile.calibrated_output_delay_us = 1_850;
    profile.calibration_uncertainty_us = 150;
    let c = GroupClockConfig::for_board(&profile).expect("board config");
    assert_eq!(c.output_delay_ns, 1_850_000);
    assert_eq!(c.calibration_uncertainty_ns, 150_000);
    assert_eq!(
        c.lock_uncertainty_ns,
        std_cfg().lock_uncertainty_ns,
        "the threshold is not a board term"
    );
}

// ------------------------------------------------------------------------------------------ pure functions

/// Hand-derived, not from the vectors: t1=1.000000000 s, t2=5.000200000 s, t3=5.000250000 s, t4=1.000450000 s.
/// rtt = 450 000, dwell = 50 000, delay = 400 000; local_mid = 1 000 225 000; group_mid = 5 000 225 000.
#[test]
fn n03_a_symmetric_exchange_has_the_hand_derived_midpoints() {
    let s = Sample::from_exchange(
        1_000_000_000,
        5_000_200_000,
        5_000_250_000,
        1_000_450_000,
        &std_cfg(),
    )
    .expect("valid exchange");
    assert_eq!(s.delay_ns, 400_000);
    assert_eq!(s.local_mid_ns, 1_000_225_000);
    assert_eq!(s.group_mid_ns, 5_000_225_000);
    assert_eq!(s.offset_ns(), 4_000_000_000);
    // base uncertainty: half the delay (200 000) + 1 000 timer resolution + 0 calibration
    assert_eq!(base_uncertainty_ns(&std_cfg(), s.delay_ns), 201_000);
    // growth: 6 ms of age at 100 ppm is exactly 600 ns, rounded up
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns + 6_000_000, 100_000),
        201_600
    );
    // one ns of age at 1 ppb still costs a whole ns (never rounds down)
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns + 1, 1),
        201_001
    );
    // and a time before the midpoint costs nothing
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns - 5, 100_000),
        201_000
    );
}

#[test]
fn n03_exchange_table_matches_the_reference() {
    let v = vectors();
    let mut seen = Map::new();
    for case in v["exchanges"].as_array().expect("exchanges") {
        let id = case["id"].as_str().expect("id");
        let cfg = cfg_with(&case["cfg"]);
        let got = Sample::from_exchange(
            u(case, "t1"),
            u(case, "t2"),
            u(case, "t3"),
            u(case, "t4"),
            &cfg,
        );
        let result = match (&got, &case["expect"]) {
            (Err(reason), Value::String(want)) => {
                assert_eq!(reason.code(), want, "{id}");
                json!(reason.code())
            }
            (Ok(s), Value::Object(want)) => {
                assert_eq!(
                    s.delay_ns,
                    want["delay"].as_u64().expect("delay"),
                    "{id}: delay"
                );
                assert_eq!(
                    s.local_mid_ns,
                    want["local_mid"].as_u64().expect("mid"),
                    "{id}: local mid"
                );
                assert_eq!(
                    s.group_mid_ns,
                    want["group_mid"].as_u64().expect("mid"),
                    "{id}: group mid"
                );
                assert_eq!(
                    s.offset_ns(),
                    i128::from(want["offset"].as_i64().expect("offset")),
                    "{id}: offset"
                );
                json!({"delay": s.delay_ns, "local_mid": s.local_mid_ns, "group_mid": s.group_mid_ns,
                       "offset": i64::try_from(s.offset_ns()).expect("offset fits")})
            }
            other => panic!("{id}: got {other:?}, expected {}", case["expect"]),
        };
        seen.insert(id.to_string(), result);
    }
    assert!(seen.len() >= 20, "the table is not trivially short");
    observed(&json!({"kind": "exchanges", "id": "n03-exchanges", "cases": seen}));
}

#[test]
fn n03_every_probe_reject_code_is_distinct_and_counted_in_its_own_slot() {
    let mut codes: Vec<&str> = ProbeReject::ALL.iter().map(|r| r.code()).collect();
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), n, "codes are unique");
    let mut stats = GroupStats::default();
    for (i, r) in ProbeReject::ALL.iter().enumerate() {
        stats.rejected[r.index()] += (i as u64) + 1;
    }
    for (i, r) in ProbeReject::ALL.iter().enumerate() {
        assert_eq!(stats.rejected(*r), (i as u64) + 1, "{}", r.code());
    }
    assert_eq!(stats.rejected_total(), (1..=9).sum::<u64>());
}

#[test]
fn n03_transform_table_matches_the_reference_and_the_two_directions_are_consistent() {
    let v = vectors();
    let mut seen = Map::new();
    for case in v["transforms"].as_array().expect("transforms") {
        let id = case["id"].as_str().expect("id");
        let ratio = case["ratio_ppb"].as_i64().expect("ratio");
        let a = anchor_of(sample_of(&case["sample"]), ratio, 0);
        let g = group_at(&a, u(case, "now"));
        let l = local_of(&a, u(case, "group_target"));
        assert_eq!(g, u(case, "group_ns"), "{id}: group_at");
        assert_eq!(l, u(case, "local_for_group"), "{id}: local_of");
        // a round trip through both directions loses at most the two floors (1 ns each way, scaled by the ratio)
        let back = group_at(&a, l);
        let target = u(case, "group_target");
        if target > 0 {
            assert!(
                back.abs_diff(target) <= 2,
                "{id}: round trip drift {}",
                back.abs_diff(target)
            );
        }
        seen.insert(id.to_string(), json!({"group_ns": g, "local_for_group": l}));
    }
    observed(&json!({"kind": "transforms", "id": "n03-transforms", "cases": seen}));
}

#[test]
fn n03_selection_table_matches_the_reference() {
    let v = vectors();
    let cfg = std_cfg();
    let mut seen = Map::new();
    for case in v["selections"].as_array().expect("selections") {
        let id = case["id"].as_str().expect("id");
        let samples: Vec<Sample> = case["samples"]
            .as_array()
            .expect("samples")
            .iter()
            .map(sample_of)
            .collect();
        let a = select_anchor(
            &cfg,
            samples.iter(),
            u(case, "now"),
            0,
            u(case, "ratio_unc_ppb"),
        )
        .expect("a sample");
        let index = samples
            .iter()
            .position(|s| *s == a.sample)
            .expect("selected sample is one of the inputs");
        assert_eq!(index as u64, u(case, "index"), "{id}: index");
        assert_eq!(
            a.uncertainty_ns,
            u(case, "uncertainty_ns"),
            "{id}: uncertainty"
        );
        seen.insert(
            id.to_string(),
            json!({"index": index, "uncertainty_ns": a.uncertainty_ns}),
        );
    }
    assert!(
        select_anchor(&cfg, [].iter(), 0, 0, 0).is_none(),
        "no samples, no anchor"
    );
    observed(&json!({"kind": "selections", "id": "n03-selections", "cases": seen}));
}

#[test]
fn n03_holdover_table_matches_the_reference() {
    let v = vectors();
    let mut seen = Map::new();
    for case in v["holdovers"].as_array().expect("holdovers") {
        let id = case["id"].as_str().expect("id");
        let cfg = cfg_with(&case["cfg"]);
        let a = anchor_of(sample_of(&case["sample"]), 0, u(case, "ratio_unc_ppb"));
        let h = holdover_for(
            &cfg,
            &a,
            opt_u64(&case["authority"]),
            opt_u64(&case["buffer"]),
        );
        assert_eq!(h.until_local_ns, u(case, "until"), "{id}: until");
        assert_eq!(
            h.binding.code(),
            case["binding"].as_str().expect("binding"),
            "{id}: binding"
        );
        seen.insert(
            id.to_string(),
            json!({"until": h.until_local_ns, "binding": h.binding.code()}),
        );
    }
    observed(&json!({"kind": "holdovers", "id": "n03-holdovers", "cases": seen}));
}

#[test]
fn n03_start_plan_table_matches_the_reference() {
    let v = vectors();
    let mut seen = Map::new();
    for case in v["plans"].as_array().expect("plans") {
        let id = case["id"].as_str().expect("id");
        let cfg = cfg_with(&case["cfg"]);
        let a = anchor_of(
            sample_of(&case["sample"]),
            case["ratio_ppb"].as_i64().expect("ratio"),
            u(case, "ratio_unc_ppb"),
        );
        let ctx = StartContext {
            epoch: u(case, "epoch"),
            status: status_of(case["status"].as_str().expect("status")),
            anchor: &a,
            now_local_ns: u(case, "now"),
            authority_until: opt_u64(&case["authority"]),
            buffer_until: opt_u64(&case["buffer"]),
        };
        let sched = StartSchedule {
            epoch: u(case, "sched_epoch"),
            start_group_ns: u(case, "start_group_ns"),
        };
        let got = decide_start(&cfg, &ctx, sched);
        let want = &case["expect"];
        let result = match got {
            Err(r) => {
                assert_eq!(want["reject"].as_str(), Some(r.code()), "{id}");
                json!({"reject": r.code()})
            }
            Ok(p) => {
                assert_eq!(want["ok"], json!(true), "{id}: the reference rejects");
                assert_eq!(p.start_local_ns, u(want, "start_local_ns"), "{id}: start");
                assert_eq!(
                    p.deadline_local_ns,
                    u(want, "deadline_local_ns"),
                    "{id}: deadline"
                );
                assert_eq!(
                    p.uncertainty_at_start_ns,
                    u(want, "uncertainty_at_start_ns"),
                    "{id}: uncertainty"
                );
                assert_eq!(
                    p.valid_until_local_ns,
                    u(want, "valid_until_local_ns"),
                    "{id}: valid until"
                );
                assert_eq!(
                    p.binding.code(),
                    want["binding"].as_str().expect("binding"),
                    "{id}: binding"
                );
                json!({"ok": true, "start_local_ns": p.start_local_ns, "deadline_local_ns": p.deadline_local_ns,
                       "uncertainty_at_start_ns": p.uncertainty_at_start_ns, "valid_until_local_ns": p.valid_until_local_ns,
                       "binding": p.binding.code()})
            }
        };
        seen.insert(id.to_string(), result);
    }
    observed(&json!({"kind": "plans", "id": "n03-plans", "cases": seen}));
}

#[test]
fn n03_frame_position_wraps_at_two_to_the_32_frames() {
    let v = vectors();
    let wrap = u(&v, "wrap_group_ns");
    assert_eq!(frame_position(0), 0);
    assert_eq!(frame_position(1_000_000_000), 48_000);
    // 2^32 frames at 48 kHz is 89 478.485333 s: the last nanosecond before it, and the first after
    assert_eq!(frame_position(wrap - 1), u32::MAX);
    assert_eq!(
        frame_position(wrap + 1_000),
        0,
        "1 us past the wrap is frame 2^32, which reads 0"
    );
    // One counter period later the counter reads one frame LOWER (the period is not a whole number of ns): the
    // frame counter cannot tell 24.86 h apart, which is why the offset check exists. Hand-derived: 5 s is frame
    // 240 000; 5 s + 89 478 485 333 333 ns is frame 240 000 + 4 294 967 295.99998 -> floor -> 240 000 - 1 mod 2^32.
    assert_eq!(frame_position(5_000_000_000), 240_000);
    assert_eq!(frame_position(5_000_000_000 + wrap), 239_999);
}

// ------------------------------------------------------------------------------------------ the world engine

struct Truth {
    checks: u64,
    max_err: u64,
    max_unc: u64,
    min_margin: Option<u64>,
}

fn resp_from(v: &Value) -> ProbeResponse {
    ProbeResponse {
        epoch: u(v, "epoch"),
        leader: u(v, "leader"),
        seq: u(v, "seq"),
        t1_echo_ns: u(v, "t1_echo"),
        t2_group_ns: u(v, "t2"),
        t3_group_ns: u(v, "t3"),
    }
}

fn apply_override(r: &mut ProbeResponse, ovr: &Value) {
    let Some(map) = ovr.as_object() else { return };
    for (key, value) in map {
        let n = value.as_u64().expect("override value");
        match key.as_str() {
            "epoch" => r.epoch = n,
            "leader" => r.leader = n,
            "seq" => r.seq = n,
            "t1_echo" => r.t1_echo_ns = n,
            "t2" => r.t2_group_ns = n,
            "t3" => r.t3_group_ns = n,
            other => panic!("unknown response override {other}"),
        }
    }
}

fn output_fields(rec: &mut Map<String, Value>, out: Output) {
    match out {
        Output::Muted(reason) => {
            rec.insert("output".into(), json!("Muted"));
            rec.insert("mute".into(), json!(reason.code()));
        }
        Output::Armed { starts_in_ns } => {
            rec.insert("output".into(), json!("Armed"));
            rec.insert("starts_in_ns".into(), json!(starts_in_ns));
        }
        Output::Audible => {
            rec.insert("output".into(), json!("Audible"));
        }
    }
}

fn plan_fields(rec: &mut Map<String, Value>, plan: Result<StartPlan, StartReject>) {
    match plan {
        Ok(p) => {
            rec.insert("result".into(), json!("ok"));
            rec.insert("start_local_ns".into(), json!(p.start_local_ns));
            rec.insert("deadline_local_ns".into(), json!(p.deadline_local_ns));
            rec.insert(
                "uncertainty_at_start_ns".into(),
                json!(p.uncertainty_at_start_ns),
            );
            rec.insert("valid_until_local_ns".into(), json!(p.valid_until_local_ns));
            rec.insert("binding".into(), json!(p.binding.code()));
        }
        Err(r) => {
            rec.insert("result".into(), json!(r.code()));
        }
    }
}

fn sched_of(v: &Value) -> StartSchedule {
    StartSchedule {
        epoch: u(v, "epoch"),
        start_group_ns: u(v, "start_group_ns"),
    }
}

/// Run one scripted world and return one record per op (the shape `reference.run_script` produces).
fn run_ops(w: &Value) -> Vec<Value> {
    let cfg = cfg_with(&w["cfg"]);
    let mut gc = GroupClock::new(cfg.clone(), u(w, "epoch"), u(w, "leader"), u(w, "seq_base"))
        .expect("member");
    let mut sent: Vec<Option<ProbeResponse>> = Vec::new();
    let mut out = Vec::new();
    for op in w["ops"].as_array().expect("ops") {
        let kind = op["op"].as_str().expect("op kind");
        let mut rec = Map::new();
        rec.insert("op".into(), json!(kind));
        let mut this_resp = None;
        match kind {
            "probe" | "raw" | "replay" => {
                let (resp, t4) = match kind {
                    "probe" => {
                        let req = gc.next_probe(u(op, "t1"));
                        rec.insert("seq".into(), json!(req.seq));
                        let mut r = ProbeResponse {
                            epoch: req.epoch,
                            leader: gc.leader(),
                            seq: req.seq,
                            t1_echo_ns: req.t1_local_ns,
                            t2_group_ns: u(op, "t2"),
                            t3_group_ns: u(op, "t3"),
                        };
                        apply_override(&mut r, &op["ovr"]);
                        (r, u(op, "t4"))
                    }
                    "raw" => (resp_from(&op["resp"]), u(op, "t4")),
                    _ => {
                        let of = usize::try_from(u(op, "of")).expect("index");
                        (
                            sent[of].expect("the replayed op built a response"),
                            u(op, "t4"),
                        )
                    }
                };
                this_resp = Some(resp);
                match gc.on_response(resp, t4) {
                    Ok(a) => {
                        rec.insert("result".into(), json!("ok"));
                        rec.insert("delay".into(), json!(a.delay_ns));
                        rec.insert("offset".into(), json!(a.offset_ns));
                    }
                    Err(reason) => {
                        rec.insert("result".into(), json!(reason.code()));
                    }
                }
                rec.insert("status".into(), json!(gc.status(t4).code()));
            }
            "next" => {
                rec.insert("seq".into(), json!(gc.next_probe(u(op, "t1")).seq));
            }
            "check" => {
                let now = u(op, "now");
                let report = gc.report(now);
                let stats = gc.stats();
                rec.insert("status".into(), json!(report.status));
                rec.insert("samples".into(), json!(report.samples));
                rec.insert("accepted".into(), json!(report.accepted));
                rec.insert("rejected_total".into(), json!(report.rejected_total));
                rec.insert("resets".into(), json!(stats.resets));
                rec.insert("rate_restarts".into(), json!(stats.rate_restarts));
                let o = gc.output(now);
                assert_eq!(report.output, o.code(), "report and output agree");
                output_fields(&mut rec, o);
                if !rec.contains_key("mute") {
                    rec.insert("mute".into(), Value::Null);
                }
                assert_eq!(report.claim, CLAIM, "every report states what it is not");
                if let Some(a) = gc.reading(now) {
                    rec.insert("uncertainty_ns".into(), json!(a.uncertainty_ns));
                    rec.insert("ratio_ppb".into(), json!(a.ratio_ppb));
                    rec.insert("ratio_unc_ppb".into(), json!(a.ratio_unc_ppb));
                    rec.insert("group_ns".into(), json!(group_at(&a, now)));
                    rec.insert("anchor_local_mid".into(), json!(a.sample.local_mid_ns));
                    assert_eq!(report.uncertainty_ns, Some(a.uncertainty_ns));
                }
                if let Some(h) = gc.holdover(now) {
                    rec.insert("holdover_until".into(), json!(h.until_local_ns));
                    rec.insert("binding".into(), json!(h.binding.code()));
                }
            }
            "tick" => {
                let o = gc.tick(u(op, "now"));
                output_fields(&mut rec, o);
            }
            "plan" => plan_fields(
                &mut rec,
                gc.plan_start(sched_of(&op["sched"]), u(op, "now")),
            ),
            "admit" => plan_fields(&mut rec, gc.admit(sched_of(&op["sched"]), u(op, "now"))),
            "begin_epoch" => {
                let r = gc.begin_epoch(u(op, "epoch"), u(op, "leader"));
                rec.insert(
                    "result".into(),
                    json!(match r {
                        Ok(()) => "ok",
                        Err(GroupClockError::EpochNotAdvanced { .. }) => "EpochNotAdvanced",
                        Err(e) => panic!("unexpected {e}"),
                    }),
                );
            }
            "authority" => {
                let r = gc.set_authority(u(op, "epoch"), u(op, "expires"), u(op, "now"));
                rec.insert(
                    "result".into(),
                    json!(match r {
                        Ok(()) => "ok",
                        Err(GroupClockError::WrongEpoch { .. }) => "WrongEpoch",
                        Err(e) => panic!("unexpected {e}"),
                    }),
                );
            }
            "buffer" => {
                gc.set_buffer_until(opt_u64(&op["until"]));
                rec.insert("result".into(), json!("ok"));
            }
            "fault" => {
                gc.report_clock_fault();
                rec.insert("result".into(), json!("ok"));
            }
            "reboot" => {
                gc = GroupClock::new(cfg.clone(), gc.epoch(), gc.leader(), u(op, "seq_base"))
                    .expect("member");
                rec.insert("result".into(), json!("ok"));
            }
            other => panic!("unknown op {other}"),
        }
        sent.push(this_resp);
        rec.insert("rate_in_force".into(), json!(gc.rate_in_force()));
        out.push(Value::Object(rec));
    }
    out
}

/// Compare a record to the reference's, exactly, except for fields the reference gives a tolerance for (the rate
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

fn run_world(w: &Value) -> Value {
    let id = w["id"].as_str().expect("world id");
    let got = run_ops(w);
    let want = w["expect"].as_array().expect("expect");
    assert_eq!(got.len(), want.len(), "{id}: one record per op");
    let mut truth = Truth {
        checks: 0,
        max_err: 0,
        max_unc: 0,
        min_margin: None,
    };
    let res = w["clocks"]["res_ns"].as_u64();
    for (i, ((op, w_rec), g_rec)) in w["ops"]
        .as_array()
        .expect("ops")
        .iter()
        .zip(want)
        .zip(&got)
        .enumerate()
    {
        compare_record(id, i, w_rec, g_rec);
        // The central claim, against the simulated world's known truth, using what the Rust itself reported.
        if let (Some(t), Some(g), Some(unc)) = (
            op.get("truth_group"),
            g_rec.get("group_ns"),
            g_rec.get("uncertainty_ns"),
        ) {
            let (t, g, unc) = (
                t.as_u64().expect("truth"),
                g.as_u64().expect("group"),
                unc.as_u64().expect("unc"),
            );
            let err = t.abs_diff(g);
            assert!(
                err <= unc,
                "{id} op {i}: error {err} ns exceeds the reported uncertainty {unc} ns"
            );
            truth.checks += 1;
            truth.max_err = truth.max_err.max(err);
            truth.max_unc = truth.max_unc.max(unc);
            let margin = unc - err;
            truth.min_margin = Some(truth.min_margin.map_or(margin, |m| m.min(margin)));
        }
        // An asymmetric path biases the offset by exactly (forward - return) / 2: it is in the data, not the noise.
        if let (Some(truth_offset), Some(bias), Some(offset)) = (
            op.get("truth_offset"),
            op.get("bias_ns"),
            g_rec.get("offset"),
        ) {
            let (to, b, off) = (
                truth_offset.as_i64().expect("truth offset"),
                bias.as_i64().expect("bias"),
                offset.as_i64().expect("offset"),
            );
            let slack = i64::try_from(res.expect("clock resolution")).expect("fits");
            assert!(
                (off - to - b).abs() <= slack,
                "{id} op {i}: offset error {} ns, expected the path bias {b} ns",
                off - to
            );
        }
    }
    json!({"kind": "world", "id": id, "steps": got,
           "truth": {"checks": truth.checks, "max_err_ns": truth.max_err, "max_unc_ns": truth.max_unc,
                     "min_margin_ns": truth.min_margin}})
}

fn world_by_id(v: &Value, id: &str) -> Value {
    v["worlds"]
        .as_array()
        .expect("worlds")
        .iter()
        .chain(
            v["mixed"]["members"]
                .as_array()
                .expect("members")
                .iter()
                .map(|m| &m["world"]),
        )
        .find(|w| w["id"] == id)
        .unwrap_or_else(|| panic!("no world {id}"))
        .clone()
}

macro_rules! world_test {
    ($name:ident, $id:literal) => {
        #[test]
        fn $name() {
            let v = vectors();
            let w = world_by_id(&v, $id);
            let line = run_world(&w);
            observed(&line);
        }
    };
}

world_test!(n03_world_s01_symmetric, "S01-SYMMETRIC");
world_test!(n03_world_s02_asymmetric_lockable, "S02-ASYMMETRIC-LOCKABLE");
world_test!(n03_world_s03_asymmetric_too_wide, "S03-ASYMMETRIC-TOO-WIDE");
world_test!(n03_world_s04_drift_fast, "S04-DRIFT-FAST");
world_test!(n03_world_s05_drift_slow, "S05-DRIFT-SLOW");
world_test!(n03_world_s06_wrap, "S06-WRAP");
world_test!(
    n03_world_s07a_holdover_uncertainty,
    "S07A-HOLDOVER-UNCERTAINTY"
);
world_test!(n03_world_s07b_holdover_authority, "S07B-HOLDOVER-AUTHORITY");
world_test!(n03_world_s07c_holdover_buffer, "S07C-HOLDOVER-BUFFER");
world_test!(n03_world_s07d_holdover_tie, "S07D-HOLDOVER-TIE");
world_test!(n03_world_s08a_jump_local_suspend, "S08A-JUMP-LOCAL-SUSPEND");
world_test!(n03_world_s08b_jump_group_step, "S08B-JUMP-GROUP-STEP");
world_test!(n03_world_s08c_jump_half_range, "S08C-JUMP-HALF-RANGE");
world_test!(n03_world_s08d_jump_wrap_alias, "S08D-JUMP-WRAP-ALIAS");
world_test!(n03_world_s08e_jump_counter_reset, "S08E-JUMP-COUNTER-RESET");
world_test!(
    n03_world_s08f_jump_local_regression,
    "S08F-JUMP-LOCAL-REGRESSION"
);
world_test!(n03_world_s09a_step_at_bound, "S09A-STEP-AT-BOUND");
world_test!(n03_world_s09b_step_past_bound, "S09B-STEP-PAST-BOUND");
world_test!(n03_world_s10_leader_change, "S10-LEADER-CHANGE");
world_test!(n03_world_s11_admission, "S11-ADMISSION");
world_test!(n03_world_s12_outstanding_bound, "S12-OUTSTANDING-BOUND");
world_test!(n03_world_s13_reboot, "S13-REBOOT");
world_test!(n03_world_s14_sparse_probes, "S14-SPARSE-PROBES");
world_test!(n03_world_s15_soak_3h, "S15-SOAK-3H");
world_test!(n03_world_s16_join, "S16-JOIN");
world_test!(
    n03_world_s17_unlocked_cannot_output,
    "S17-UNLOCKED-CANNOT-OUTPUT"
);
world_test!(n03_world_s18_start_uncertainty, "S18-START-UNCERTAINTY");
world_test!(n03_world_s19_output_delay, "S19-OUTPUT-DELAY");

#[test]
fn n03_every_world_in_the_vectors_has_a_test_above() {
    let v = vectors();
    let have: Vec<&str> = vec![
        "S01-SYMMETRIC",
        "S02-ASYMMETRIC-LOCKABLE",
        "S03-ASYMMETRIC-TOO-WIDE",
        "S04-DRIFT-FAST",
        "S05-DRIFT-SLOW",
        "S06-WRAP",
        "S07A-HOLDOVER-UNCERTAINTY",
        "S07B-HOLDOVER-AUTHORITY",
        "S07C-HOLDOVER-BUFFER",
        "S07D-HOLDOVER-TIE",
        "S08A-JUMP-LOCAL-SUSPEND",
        "S08B-JUMP-GROUP-STEP",
        "S08C-JUMP-HALF-RANGE",
        "S08D-JUMP-WRAP-ALIAS",
        "S08E-JUMP-COUNTER-RESET",
        "S08F-JUMP-LOCAL-REGRESSION",
        "S09A-STEP-AT-BOUND",
        "S09B-STEP-PAST-BOUND",
        "S10-LEADER-CHANGE",
        "S11-ADMISSION",
        "S12-OUTSTANDING-BOUND",
        "S13-REBOOT",
        "S14-SPARSE-PROBES",
        "S15-SOAK-3H",
        "S16-JOIN",
        "S17-UNLOCKED-CANNOT-OUTPUT",
        "S18-START-UNCERTAINTY",
        "S19-OUTPUT-DELAY",
    ];
    let ids: Vec<&str> = v["worlds"]
        .as_array()
        .expect("worlds")
        .iter()
        .map(|w| w["id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, have, "a world was added to the vectors without a test");
}

#[test]
fn n03_mixed_profile_members_begin_within_their_summed_uncertainty() {
    let v = vectors();
    let m = &v["mixed"];
    let members = m["members"].as_array().expect("members");
    assert_eq!(members.len(), 2);
    let mut starts = Vec::new();
    let mut unc = 0_u64;
    let mut lines = Vec::new();
    for member in members {
        let line = run_world(&member["world"]);
        observed(&line);
        let steps = line["steps"].as_array().expect("steps");
        let admit = steps
            .iter()
            .find(|s| s["op"] == "admit")
            .expect("an admit step");
        assert_eq!(
            admit["result"], "ok",
            "both members join the same future start"
        );
        // the audible instant in true time is the true time of start_local plus the board's own output delay; the
        // generator solved it for each member's clock, the Rust reproduced start_local exactly (checked in run_world)
        starts.push(member["audible_true_ns"].as_u64().expect("true instant"));
        unc += u(admit, "uncertainty_at_start_ns");
        lines.push(
            json!({"id": member["world"]["id"], "start_local_ns": admit["start_local_ns"],
                          "uncertainty_at_start_ns": admit["uncertainty_at_start_ns"]}),
        );
    }
    let skew = starts[0].abs_diff(starts[1]);
    assert!(
        skew <= unc,
        "start skew {skew} ns exceeds the summed uncertainty {unc} ns"
    );
    assert!(
        skew <= u(m, "gate_ns"),
        "start skew {skew} ns exceeds the provisional room-group gate"
    );
    assert_eq!(skew, u(m, "skew_ns"), "the skew is the reference's");
    observed(
        &json!({"kind": "mixed", "id": "n03-mixed", "members": lines, "skew_ns": skew, "bound_ns": unc, "gate_ns": u(m, "gate_ns")}),
    );
}

// ------------------------------------------------------------------------------------------ an independent world

/// A second world generator, written here and not in the reference: a coordinator clock, a member clock with an
/// offset, a skew and a resolution, and seeded asymmetric delay with jitter and loss.
struct Sim {
    skew_ppb: i64,
    local0: u64,
    group0: u64,
    res: u64,
    seed: u32,
}

impl Sim {
    fn rand(&mut self) -> u64 {
        self.seed = self
            .seed
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        u64::from(self.seed >> 8)
    }

    fn q(&self, v: u64) -> u64 {
        v - v % self.res
    }

    fn local(&self, t: u64) -> u64 {
        let skewed = i128::from(t) * i128::from(self.skew_ppb);
        let v = i128::from(self.local0) + i128::from(t) + skewed.div_euclid(1_000_000_000);
        self.q(u64::try_from(v).expect("positive local time"))
    }

    fn group(&self, t: u64) -> u64 {
        self.q(self.group0 + t)
    }
}

struct Run {
    probes: u64,
    lost: u64,
    checks: u64,
    max_err: u64,
    max_unc: u64,
    min_margin: u64,
    locked: bool,
}

fn run_sim(
    seed: u32,
    skew_ppb: i64,
    base_us: u64,
    jitter_us: u64,
    asym_us: u64,
    loss_pct: u64,
    seconds: u64,
) -> Run {
    let mut sim = Sim {
        skew_ppb,
        local0: 3_000_000_000,
        group0: 40_000_000_000_000,
        res: 1_000,
        seed,
    };
    let mut gc = GroupClock::new(std_cfg(), 1, 7, u64::from(seed) << 20).expect("member");
    let mut run = Run {
        probes: 0,
        lost: 0,
        checks: 0,
        max_err: 0,
        max_unc: 0,
        min_margin: u64::MAX,
        locked: false,
    };
    for k in 0..seconds {
        let ts = k * 1_000_000_000 + sim.rand() % 5_000_000;
        let req = gc.next_probe(sim.local(ts));
        run.probes += 1;
        if sim.rand() % 100 < loss_pct {
            run.lost += 1;
            continue;
        }
        let df = (base_us + sim.rand() % (jitter_us + 1) + asym_us) * 1_000;
        let dr = (base_us + sim.rand() % (jitter_us + 1)) * 1_000;
        let dwell = 40_000;
        let resp = ProbeResponse {
            epoch: req.epoch,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: req.t1_local_ns,
            t2_group_ns: sim.group(ts + df),
            t3_group_ns: sim.group(ts + df + dwell),
        };
        let t_end = ts + df + dwell + dr;
        gc.on_response(resp, sim.local(t_end))
            .expect("a clean exchange is accepted");
        let t_now = t_end + 1_500_000;
        let now = sim.local(t_now);
        if let Some(a) = gc.reading(now) {
            let err = group_at(&a, now).abs_diff(sim.group(t_now));
            assert!(
                err <= a.uncertainty_ns,
                "seed {seed} second {k}: error {err} ns exceeds uncertainty {} ns",
                a.uncertainty_ns
            );
            run.checks += 1;
            run.max_err = run.max_err.max(err);
            run.max_unc = run.max_unc.max(a.uncertainty_ns);
            run.min_margin = run.min_margin.min(a.uncertainty_ns - err);
        }
    }
    run.locked = gc.status(sim.local(seconds * 1_000_000_000)) != ClockStatus::Unlocked;
    assert_eq!(
        gc.stats().resets,
        0,
        "seed {seed}: a clean world never resets"
    );
    run
}

#[test]
fn n03_an_independent_world_keeps_the_truth_inside_the_reported_uncertainty() {
    // (seed, skew ppb, base delay us, jitter us, extra forward delay us (asymmetry), loss percent, seconds)
    let worlds = [
        (1, 0, 150, 0, 0, 0, 120),
        (2, 90_000, 100, 300, 0, 10, 300),
        (3, -90_000, 100, 300, 200, 10, 300),
        (4, 25_000, 200, 800, 400, 20, 600),
        (5, -3_000, 50, 100, 900, 5, 300),
    ];
    let mut lines = Vec::new();
    for (seed, skew, base, jitter, asym, loss, seconds) in worlds {
        let run = run_sim(seed, skew, base, jitter, asym, loss, seconds);
        assert!(
            run.checks > seconds / 2,
            "seed {seed}: enough checks happened ({})",
            run.checks
        );
        assert!(run.locked, "seed {seed}: the member locked");
        lines.push(json!({"seed": seed, "skew_ppb": skew, "probes": run.probes, "lost": run.lost,
                          "checks": run.checks, "max_err_ns": run.max_err, "max_unc_ns": run.max_unc,
                          "min_margin_ns": run.min_margin}));
    }
    observed(&json!({"kind": "sim", "id": "n03-sim", "worlds": lines}));
}

// ------------------------------------------------------------------------------------------ properties

struct Lcg(u32);

impl Lcg {
    fn step(&mut self) -> u64 {
        // Two 24-bit draws: one draw is below 2^24, so `% 6_000_000_000` and friends would be no-ops and no start
        // would ever be admitted far enough ahead (catch-up needs 100 ms).
        let mut out = 0_u64;
        for _ in 0..2 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out = (out << 24) | u64::from(self.0 >> 8);
        }
        out
    }
}

/// Whatever the sequence of probes, jumps, faults, epochs, authorities and admissions, the output is never audible
/// unless the clock is locked or in holdover, its uncertainty is within the threshold, the authority is valid, a
/// start was admitted, and enough probes have been accepted since the last reset.
#[test]
fn n03_audible_output_always_rests_on_a_locked_clock_a_valid_authority_and_an_admitted_start() {
    let mut audible_total = 0_u64;
    let mut muted_after_reset = 0_u64;
    for seed in 1..=6_u32 {
        let mut rng = Lcg(seed);
        let mut sim = Sim {
            skew_ppb: 20_000 * i64::from(seed % 3) - 20_000,
            local0: 1_000_000_000,
            group0: 70_000_000_000_000,
            res: 1_000,
            seed,
        };
        let mut gc = GroupClock::new(std_cfg(), 1, 7, 500).expect("member");
        let mut leader = 7_u64;
        let mut t = 0_u64;
        let mut last_reset = 0_u32;
        for _ in 0..4_000 {
            t += 100_000_000 + rng.step() % 1_500_000_000;
            let now = sim.local(t);
            match rng.step() % 20 {
                0..=11 => {
                    let req = gc.next_probe(now);
                    let df = 100_000 + rng.step() % 600_000;
                    let dr = 100_000 + rng.step() % 600_000;
                    let resp = ProbeResponse {
                        epoch: req.epoch,
                        leader,
                        seq: req.seq,
                        t1_echo_ns: req.t1_local_ns,
                        t2_group_ns: sim.group(t + df),
                        t3_group_ns: sim.group(t + df + 40_000),
                    };
                    let _ = gc.on_response(resp, sim.local(t + df + 40_000 + dr));
                    t += df + 40_000 + dr;
                }
                12 => {
                    let g = gc.group_ns(now).unwrap_or(0);
                    let sched = StartSchedule {
                        epoch: gc.epoch(),
                        start_group_ns: g + rng.step() % 6_000_000_000,
                    };
                    let _ = gc.admit(sched, now);
                }
                13 => {
                    let _ = gc.set_authority(gc.epoch(), now + rng.step() % 30_000_000_000, now);
                }
                14 => gc.set_buffer_until(if rng.step().is_multiple_of(2) {
                    None
                } else {
                    Some(now + rng.step() % 20_000_000_000)
                }),
                15 => {
                    // the coordinator's clock steps (detected only by the next probe)
                    sim.group0 = sim
                        .group0
                        .saturating_add(rng.step() % 5_000_000)
                        .saturating_sub(rng.step() % 2_000_000);
                }
                16 => {
                    gc.report_clock_fault();
                }
                17 => {
                    let next_epoch = gc.epoch() + 1;
                    leader = 7 + next_epoch;
                    gc.begin_epoch(next_epoch, leader).expect("advances");
                }
                _ => {}
            }
            let now = sim.local(t);
            let out = gc.tick(now);
            let resets = gc.stats().resets + gc.stats().epochs;
            if resets != last_reset {
                last_reset = resets;
                assert!(
                    !out.is_audible(),
                    "seed {seed}: audible straight after a reset or epoch change"
                );
                muted_after_reset += 1;
            }
            if out.is_audible() {
                audible_total += 1;
                let status = gc.status(now);
                assert!(
                    matches!(status, ClockStatus::Locked | ClockStatus::Holdover),
                    "seed {seed}: audible while {status:?}"
                );
                let a = gc.reading(now).expect("a reading while audible");
                assert!(
                    a.uncertainty_ns <= gc.config().lock_uncertainty_ns,
                    "seed {seed}: audible at {} ns",
                    a.uncertainty_ns
                );
                assert!(
                    gc.authority_until.is_none_or(|expiry| now < expiry),
                    "seed {seed}: audible past the authority"
                );
                assert!(
                    gc.armed.is_some(),
                    "seed {seed}: audible without an admitted start"
                );
                assert!(
                    gc.accepted_in_epoch >= gc.config().min_probes_for_lock,
                    "seed {seed}: audible before the lock count"
                );
                assert!(gc.lock_seen, "seed {seed}: audible before ever locking");
            }
        }
    }
    assert!(
        audible_total > 100,
        "the property run reached the audible state often enough ({audible_total})"
    );
    assert!(
        muted_after_reset > 20,
        "the property run exercised resets ({muted_after_reset})"
    );
    observed(
        &json!({"kind": "property", "id": "n03-property", "audible": audible_total, "resets_checked": muted_after_reset}),
    );
}

// ------------------------------------------------------------------------------------------ API behaviour

fn locked_member(goff: u64) -> (GroupClock, u64) {
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    let mut t4 = 0;
    for k in 0..5_u64 {
        let t1 = 10_000_000_000 + k * 1_000_000_000;
        let req = gc.next_probe(t1);
        let resp = ProbeResponse {
            epoch: 1,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: t1,
            t2_group_ns: t1 + goff + 200_000,
            t3_group_ns: t1 + goff + 250_000,
        };
        t4 = t1 + 450_000;
        gc.on_response(resp, t4).expect("accepted");
    }
    (gc, t4)
}

#[test]
fn n03_report_has_no_side_effects_and_always_states_the_claim() {
    let (mut gc, t4) = locked_member(8_995_000_000_000);
    let before = gc.stats();
    let a = gc.report(t4 + 1_000_000);
    let b = gc.report(t4 + 1_000_000);
    assert_eq!(a, b);
    assert_eq!(gc.stats(), before);
    assert_eq!(a.claim, CLAIM);
    assert!(a.claim.contains("not DAC"), "the claim says what it is not");
    let text = serde_json::to_string(&a).expect("serializes");
    assert!(text.contains("network-clock-fit-only"));
    assert_eq!(a.status, "Locked");
    assert_eq!(a.mute_reason, Some("NotAdmitted"));
    // tick may change state, report must agree with it afterwards
    let _ = gc.tick(t4 + 1_000_000);
    assert_eq!(gc.report(t4 + 1_000_000).status, "Locked");
}

#[test]
fn n03_a_member_with_no_samples_has_no_reading_and_cannot_plan() {
    let gc = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    assert!(gc.reading(1).is_none());
    assert!(gc.group_ns(1).is_none());
    assert!(gc.local_for_group(1, 1).is_none());
    assert!(gc.holdover(1).is_none());
    assert_eq!(gc.status(1), ClockStatus::Unlocked);
    let sched = StartSchedule {
        epoch: 1,
        start_group_ns: 1_000_000_000,
    };
    assert_eq!(gc.plan_start(sched, 1), Err(StartReject::NotLocked));
    let r = gc.report(1);
    assert_eq!((r.uncertainty_ns, r.holdover_until_local_ns), (None, None));
    assert_eq!(r.mute_reason, Some("NotLocked"));
}

#[test]
fn n03_the_platform_clock_fault_clears_the_fit_and_names_itself() {
    let (mut gc, t4) = locked_member(8_995_000_000_000);
    gc.set_authority(1, t4 + 900_000_000_000, t4)
        .expect("authority");
    let sched = StartSchedule {
        epoch: 1,
        start_group_ns: gc.group_ns(t4).expect("group time") + 500_000_000,
    };
    gc.admit(sched, t4).expect("admitted");
    gc.report_clock_fault();
    assert_eq!(gc.tick(t4 + 1), Output::Muted(MuteReason::ClockFault));
    assert_eq!(gc.sample_count(), 0);
    assert_eq!(gc.stats().resets, 1);
    assert!(gc.plan_start(sched, t4 + 1).is_err());
}

#[test]
fn n03_requests_are_numbered_from_the_base_and_wrap_without_panicking() {
    let mut gc = GroupClock::new(std_cfg(), 1, 7, u64::MAX - 1).expect("member");
    assert_eq!(gc.next_probe(10).seq, u64::MAX - 1);
    assert_eq!(gc.next_probe(11).seq, u64::MAX);
    assert_eq!(gc.next_probe(12).seq, 0, "wraps");
    assert_eq!(gc.stats().probes_sent, 3);
}

#[test]
fn n03_a_response_for_an_older_request_does_not_answer_a_newer_one_with_the_same_send_time() {
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 50).expect("member");
    let first = gc.next_probe(1_000_000_000);
    let second = gc.next_probe(1_000_000_000);
    assert_ne!(first.seq, second.seq);
    let resp = |seq: u64| ProbeResponse {
        epoch: 1,
        leader: 7,
        seq,
        t1_echo_ns: 1_000_000_000,
        t2_group_ns: 9_000_000_200_000,
        t3_group_ns: 9_000_000_250_000,
    };
    assert!(gc.on_response(resp(first.seq), 1_000_450_000).is_ok());
    assert_eq!(
        gc.on_response(resp(first.seq), 1_000_500_000),
        Err(ProbeReject::UnsolicitedOrReplayed)
    );
    assert!(gc.on_response(resp(second.seq), 1_000_600_000).is_ok());
}
