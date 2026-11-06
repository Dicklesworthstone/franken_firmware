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
                "timer_resolution_ns" => cfg.timer_resolution_ns = n,
                "oscillator_bound_ppb" => cfg.oscillator_bound_ppb = n,
                "prediction_slack_ns" => cfg.prediction_slack_ns = n,
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
    // base uncertainty: half the delay (200 000) + twice the 1 000 timer resolution (the exchange, and the reading asked at) +
    // 0 calibration
    assert_eq!(base_uncertainty_ns(&std_cfg(), s.delay_ns), 202_000);
    // the second resolution (the tick of the reading asked at) read through the fitted ratio r and its uncertainty u costs ceil(1000 * (r + u) / 1e9) more:
    // 1 ns for u = 100 ppm (0.1000...) and for u = 1 ppb. Growth: 6 ms of age at 100 ppm is exactly 600 ns, rounded up
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns + 6_000_000, 0, 100_000),
        202_601
    );
    // one ns of age at 1 ppb still costs a whole ns (never rounds down)
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns + 1, 0, 1),
        202_002
    );
    // and a time before the midpoint costs no growth
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns - 5, 0, 100_000),
        202_001
    );
    // an exactly known ratio costs nothing more than the base
    assert_eq!(
        uncertainty_at(&std_cfg(), &s, s.local_mid_ns, 0, 0),
        202_000
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
                // The world carries the known truth: record the estimated error against it.
                if let Some(truth) = op.get("truth_group").and_then(Value::as_u64) {
                    let _ = gc.note_truth(now, truth);
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
        let mut labels = Vec::new();
        while let Some(event) = gc.pop_event() {
            labels.push(json!(event.payload.label()));
        }
        rec.insert("events".into(), Value::Array(labels));
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
world_test!(n03_world_s20_coarse_equal_lock, "S20-COARSE-EQUAL-LOCK");
world_test!(
    n03_world_s21_coarse_negative_delay,
    "S21-COARSE-NEGATIVE-DELAY"
);
world_test!(
    n03_world_s22_coarse_rounding_pair,
    "S22-COARSE-ROUNDING-PAIR"
);
world_test!(n03_world_s23_coarse_fitted_rate, "S23-COARSE-FITTED-RATE");

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
        "S20-COARSE-EQUAL-LOCK",
        "S21-COARSE-NEGATIVE-DELAY",
        "S22-COARSE-ROUNDING-PAIR",
        "S23-COARSE-FITTED-RATE",
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

// ------------------------------------------------------------------------------------------ diagnostics

/// Pop everything pending, oldest first.
fn drain(gc: &mut GroupClock) -> Vec<BufferedEvent<ClockEvent>> {
    let mut out = Vec::new();
    while let Some(event) = gc.pop_event() {
        out.push(event);
    }
    out
}

fn labels(gc: &mut GroupClock) -> Vec<String> {
    drain(gc).iter().map(|e| e.payload.label()).collect()
}

/// One exact exchange (no skew, no quantisation, a group clock `goff` ahead of the local one) delivered at once.
fn exact_probe(
    gc: &mut GroupClock,
    t1: u64,
    goff: u64,
) -> (ProbeResponse, u64, Result<Accepted, ProbeReject>) {
    let req = gc.next_probe(t1);
    let resp = ProbeResponse {
        epoch: req.epoch,
        leader: gc.leader(),
        seq: req.seq,
        t1_echo_ns: t1,
        t2_group_ns: t1 + goff + 200_000,
        t3_group_ns: t1 + goff + 250_000,
    };
    let t4 = t1 + 450_000;
    let outcome = gc.on_response(resp, t4);
    (resp, t4, outcome)
}

/// Hand-derived, not from the vectors: the events of a lock, a replay, a clock jump and the relock that follows.
#[test]
fn n03_events_follow_lock_replay_jump_and_relock_with_progress_counts() {
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    let goff = 8_995_000_000_000;
    let mut seen: Vec<String> = Vec::new();
    // Four exchanges: relock progress counts up, and the fourth locks.
    let mut last = None;
    for k in 0..4_u64 {
        let (resp, t4, outcome) = exact_probe(&mut gc, 10_000_000_000 + k * 1_000_000_000, goff);
        outcome.expect("accepted");
        last = Some((resp, t4));
        seen.extend(labels(&mut gc));
    }
    assert_eq!(
        seen,
        [
            "n03.probe.accepted@1/4",
            "n03.probe.accepted@2/4",
            "n03.probe.accepted@3/4",
            "n03.probe.accepted@4/4",
            "n03.status.locked",
        ]
    );
    let (resp, t4) = last.expect("a last exchange");
    // The first tick reports the output: locked but no start admitted.
    gc.tick(t4 + 500_000_000);
    assert_eq!(labels(&mut gc), ["n03.output.muted:NotAdmitted"]);
    // A replayed answer is rejected and changes no status.
    assert_eq!(
        gc.on_response(resp, t4 + 1_000),
        Err(ProbeReject::UnsolicitedOrReplayed)
    );
    assert_eq!(
        labels(&mut gc),
        ["n03.probe.rejected:UnsolicitedOrReplayed"]
    );
    // The group clock steps by 2 s: a discontinuity, a reset, and the status falls back to unlocked.
    let (_, _, jump) = exact_probe(&mut gc, 14_000_000_000, goff + 2_000_000_000);
    assert_eq!(jump, Err(ProbeReject::Discontinuity));
    assert_eq!(
        labels(&mut gc),
        [
            "n03.probe.rejected:Discontinuity",
            "n03.reset:Discontinuity",
            "n03.status.unlocked"
        ]
    );
    gc.tick(14_500_000_000);
    assert_eq!(labels(&mut gc), ["n03.output.muted:Discontinuity"]);
    // Relock progress starts again from 1 of 4, on the new timeline.
    let mut relock = Vec::new();
    for k in 0..4_u64 {
        let (_, _, outcome) = exact_probe(
            &mut gc,
            15_000_000_000 + k * 1_000_000_000,
            goff + 2_000_000_000,
        );
        outcome.expect("accepted");
        relock.extend(labels(&mut gc));
    }
    assert_eq!(
        relock,
        [
            "n03.probe.accepted@1/4",
            "n03.probe.accepted@2/4",
            "n03.probe.accepted@3/4",
            "n03.probe.accepted@4/4",
            "n03.status.locked",
        ]
    );
}

/// The events of a platform clock fault, pinned by hand: the admitted start is logged, then the reset with its
/// cause, then the fall to unlocked; the next tick logs the muted output with the fault as the reason.
#[test]
fn n03_a_platform_clock_fault_is_logged_as_a_reset_then_unlocked_then_muted() {
    let goff = 8_995_000_000_000;
    let (mut gc, t4) = locked_member(goff);
    let _ = drain(&mut gc);
    let sched = StartSchedule {
        epoch: 1,
        start_group_ns: gc.group_ns(t4).expect("group time") + 500_000_000,
    };
    gc.admit(sched, t4).expect("admitted");
    gc.report_clock_fault();
    assert_eq!(
        labels(&mut gc),
        [
            "n03.admit.accepted",
            "n03.reset:ClockFault",
            "n03.status.unlocked"
        ]
    );
    gc.tick(t4 + 1);
    assert_eq!(labels(&mut gc), ["n03.output.muted:ClockFault"]);
}

#[test]
fn n03_events_are_monotonic_numbered_and_each_states_the_clock_fit_claim() {
    let (mut gc, _) = locked_member(8_995_000_000_000);
    let events = drain(&mut gc);
    assert!(
        events.len() >= 6,
        "5 accepted exchanges and a lock: {}",
        events.len()
    );
    for pair in events.windows(2) {
        assert!(pair[1].payload.revision > pair[0].payload.revision);
        assert!(
            pair[1].payload.local_ns >= pair[0].payload.local_ns,
            "timestamps never go backwards"
        );
        assert!(pair[1].sequence > pair[0].sequence);
    }
    for event in &events {
        assert_eq!(event.payload.claim, CLAIM);
        assert_eq!(event.payload.epoch, 1);
        assert_eq!(event.payload.lock_needed, 4);
        assert_eq!(event.timestamp_mono_ns, event.payload.local_ns);
    }
    // the lock is critical evidence, an accepted exchange is not
    assert!(!events[0].critical);
    assert!(
        events
            .iter()
            .any(|e| e.critical && e.payload.kind == "n03.status.locked")
    );
    let line = serde_json::to_string(&events[0].payload).expect("serializes");
    assert!(line.contains("network-clock-fit-only"), "{line}");
    assert!(line.contains("\"kind\":\"n03.probe.accepted\""), "{line}");
}

#[test]
fn n03_estimated_error_against_known_truth_is_logged_and_a_violation_is_critical() {
    let goff = 8_995_000_000_000;
    let (mut gc, t4) = locked_member(goff);
    let _ = drain(&mut gc);
    let now = t4 + 1_000_000;
    // The transform is exact in this world, so the estimate equals the truth.
    assert_eq!(gc.note_truth(now, now + goff), Some(0));
    let within = drain(&mut gc);
    assert_eq!(within.len(), 1);
    assert_eq!(within[0].payload.kind, "n03.truth.within");
    assert_eq!(
        (within[0].payload.error_ns, within[0].critical),
        (Some(0), false)
    );
    // A truth outside the reported uncertainty is a critical violation carrying the signed error.
    let unc = gc.reading(now).expect("reading").uncertainty_ns;
    let wrong = now + goff + unc + 1;
    let expected_error = -i64::try_from(unc).expect("fits") - 1;
    assert_eq!(gc.note_truth(now, wrong), Some(expected_error));
    let violated = drain(&mut gc);
    assert_eq!(violated[0].payload.kind, "n03.truth.violated");
    assert!(violated[0].critical);
    assert_eq!(violated[0].payload.uncertainty_ns, Some(unc));
    // A truth absurdly far above the estimate saturates the signed error with the right sign.
    assert_eq!(gc.note_truth(now, u64::MAX), Some(i64::MIN));
    let _ = drain(&mut gc);
    // Without an estimate there is nothing to compare.
    let mut empty = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    assert_eq!(empty.note_truth(1, 1), None);
    assert_eq!(empty.pending_events(), 0);
}

fn stats_json(gc: &GroupClock) -> Value {
    let st = gc.event_stats();
    json!({"emitted": st.emitted, "delivered": st.delivered, "dropped_ordinary": st.dropped_ordinary,
           "evicted_ordinary": st.evicted_ordinary, "lost_critical": st.lost_critical,
           "rate_limited": st.rate_limited, "unavailable_drops": st.unavailable_drops,
           "regression_drops": st.regression_drops, "dropped": st.dropped, "critical_lost": st.critical_lost,
           "pending": gc.pending_events()})
}

fn unsolicited(gc: &mut GroupClock, i: u64, t4: u64) {
    let resp = ProbeResponse {
        epoch: 1,
        leader: 7,
        seq: 5_000 + i,
        t1_echo_ns: 0,
        t2_group_ns: 0,
        t3_group_ns: 0,
    };
    assert_eq!(
        gc.on_response(resp, t4),
        Err(ProbeReject::UnsolicitedOrReplayed)
    );
}

/// Hand-derived (see `reference.ring_scenario`): the shared buffer's accounting through a clock.
#[test]
fn n03_event_buffer_is_bounded_counts_every_drop_and_flags_lost_critical_events() {
    // 100 unsolicited responses one second apart fill the 64-event buffer and drop 36.
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    for i in 0..100_u64 {
        unsolicited(&mut gc, i, 1_000 + i * 1_000_000_000);
    }
    let after = stats_json(&gc);
    let st = gc.event_stats();
    assert_eq!(
        (
            st.emitted,
            st.dropped,
            st.dropped_ordinary,
            st.critical_lost
        ),
        (100, 36, 36, 0)
    );
    assert_eq!(gc.pending_events(), 64);
    // 70 critical epoch events: 64 evict an ordinary event each, the last 6 find only critical events and are lost.
    for epoch in 2..72_u64 {
        gc.begin_epoch(epoch, 7).expect("advances");
    }
    let fin = stats_json(&gc);
    let st = gc.event_stats();
    assert_eq!(
        (
            st.emitted,
            st.dropped,
            st.evicted_ordinary,
            st.lost_critical,
            st.critical_lost
        ),
        (170, 106, 64, 6, 6)
    );
    assert_eq!(gc.pending_events(), 64);
    assert_eq!(
        gc.pending_events() as u64 + st.delivered + st.dropped,
        st.emitted,
        "every event is delivered, pending or counted dropped"
    );
    assert_eq!(
        gc.report(1_000).events_critical_lost,
        6,
        "the report exposes lost evidence"
    );
    assert!(!st.loss_free());
    let mut kinds = std::collections::BTreeSet::new();
    for event in drain(&mut gc) {
        kinds.insert(event.payload.kind);
    }
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), ["n03.epoch.begin"]);
    // A flood inside one window is rate limited: 32 are admitted, 68 refused and counted, nothing evicted.
    let mut flooded = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    for i in 0..100_u64 {
        unsolicited(&mut flooded, i, 1_000 + i * 1_000);
    }
    let rate = stats_json(&flooded);
    let st = flooded.event_stats();
    assert_eq!(
        (st.rate_limited, st.dropped, st.dropped_ordinary),
        (68, 68, 0)
    );
    assert_eq!(flooded.pending_events(), 32);
    // An unavailable log drops everything it is offered, and says which of it was critical.
    let mut down = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    down.set_events_available(false);
    for i in 0..10_u64 {
        unsolicited(&mut down, i, 1_000 + i * 1_000_000_000);
    }
    for epoch in 2..5_u64 {
        down.begin_epoch(epoch, 7).expect("advances");
    }
    let unavailable = stats_json(&down);
    let st = down.event_stats();
    assert_eq!(
        (st.unavailable_drops, st.dropped, st.critical_lost),
        (13, 13, 3)
    );
    assert_eq!(down.pending_events(), 0);
    observed(&json!({
        "kind": "events", "id": "n03-events",
        "after_rejections": after, "final": fin, "pending_kinds": ["n03.epoch.begin"],
        "rate": rate, "unavailable": unavailable
    }));
}

/// The same world with its events popped after every step, never popped, and with the log unavailable: every
/// decision is identical, the popped run drops nothing, and the others drop and count.
#[test]
fn n03_a_full_unpopped_or_unavailable_event_buffer_changes_no_decision() {
    let goff = 8_995_000_000_000;
    let mut popped = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    let mut ignored = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    let mut down = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    down.set_events_available(false);
    let mut decisions = (Vec::new(), Vec::new(), Vec::new());
    for step in 0..300_u64 {
        let t1 = 10_000_000_000 + step * 1_000_000_000;
        // every 61st step the group clock steps (a discontinuity); every 7th step an answer is replayed
        let offset = goff + (step / 61) * 2_000_000_000;
        for (gc, record) in [
            (&mut popped, &mut decisions.0),
            (&mut ignored, &mut decisions.1),
            (&mut down, &mut decisions.2),
        ] {
            let (resp, t4, outcome) = exact_probe(gc, t1, offset);
            if step % 7 == 3 {
                let _ = gc.on_response(resp, t4 + 1_000);
            }
            let now = t4 + 500_000;
            let start = StartSchedule {
                epoch: 1,
                start_group_ns: now + offset + 1_000_000_000,
            };
            if gc.status(now) == ClockStatus::Locked && !gc.output(now).is_audible() {
                let _ = gc.admit(start, now);
            }
            record.push((
                outcome.is_ok(),
                gc.tick(now + 2_000_000_000),
                gc.status(now),
                gc.group_ns(now),
            ));
        }
        let _ = drain(&mut popped);
    }
    assert_eq!(
        decisions.0, decisions.1,
        "a popped and an unpopped buffer decide alike"
    );
    assert_eq!(decisions.0, decisions.2, "and so does an unavailable log");
    assert!(
        decisions.0.iter().any(|d| d.1.is_audible()),
        "the run reached the audible state"
    );
    assert!(decisions.0.iter().any(|d| !d.0), "and rejected exchanges");
    assert_eq!(popped.event_stats().dropped, 0);
    assert_eq!(popped.event_stats().critical_lost, 0);
    assert!(
        ignored.event_stats().dropped > 0,
        "the unpopped buffer dropped and counted"
    );
    assert_eq!(ignored.pending_events(), EVENT_RING_CAPACITY);
    assert_eq!(down.pending_events(), 0);
    assert_eq!(
        down.event_stats().unavailable_drops,
        down.event_stats().emitted
    );
    assert!(
        down.event_stats().critical_lost > 0,
        "an unavailable log loses critical evidence, and says so"
    );
}

fn log_ctx() -> LogContext {
    LogContext::new(
        "run-n03",
        "n03-log",
        "p-0123456789abcdef",
        "p-fedcba9876543210",
        None,
    )
    .expect("valid labels")
}

/// The production lines parse as the shared diagnostics schema and re-serialize to the same bytes, and they are the
/// lines the independent reference produces for the same scenario.
#[test]
fn n03_events_are_written_as_ffw_log_v1_lines_that_parse_back_byte_for_byte() {
    let goff = 8_995_000_000_000;
    let ctx = log_ctx();
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 100).expect("member");
    let mut lines = Vec::new();
    let take = |gc: &mut GroupClock, lines: &mut Vec<String>| {
        for event in drain(gc) {
            lines.push(
                event
                    .payload
                    .to_log_line(&ctx)
                    .expect("a line within the bound"),
            );
        }
    };
    let mut last = None;
    for k in 0..4_u64 {
        let (resp, t4, outcome) = exact_probe(&mut gc, 10_000_000_000 + k * 1_000_000_000, goff);
        outcome.expect("accepted");
        last = Some((resp, t4));
        take(&mut gc, &mut lines);
    }
    let (resp, t4) = last.expect("a last exchange");
    gc.tick(t4 + 500_000_000);
    take(&mut gc, &mut lines);
    let _ = gc.on_response(resp, t4 + 1_000);
    take(&mut gc, &mut lines);
    let _ = exact_probe(&mut gc, 14_000_000_000, goff + 2_000_000_000);
    take(&mut gc, &mut lines);
    gc.tick(14_500_000_000);
    take(&mut gc, &mut lines);
    for k in 0..4_u64 {
        let _ = exact_probe(
            &mut gc,
            15_000_000_000 + k * 1_000_000_000,
            goff + 2_000_000_000,
        );
        take(&mut gc, &mut lines);
    }
    assert_eq!(lines.len(), 16);
    for line in &lines {
        assert!(line.len() < MAX_LOG_LINE_BYTES);
        let parsed: franken_test_support::DiagnosticEvent =
            serde_json::from_str(line).expect("a line is a DiagnosticEvent");
        assert_eq!(parsed.schema_version, LOG_SCHEMA_VERSION);
        assert_eq!(parsed.run_id, "run-n03");
        assert_eq!(parsed.member_id, "p-0123456789abcdef");
        assert!(parsed.message.contains("network-clock-fit-only"), "{line}");
        assert_eq!(
            serde_json::to_string(&parsed).expect("serializes"),
            *line,
            "the line is exactly what the shared schema serializes"
        );
    }
    observed(&json!({"kind": "log_lines", "id": "n03-log-lines", "lines": lines}));
}

#[test]
fn n03_log_labels_are_validated_and_a_fault_entry_rides_along_when_given() {
    let too_long = "g".repeat(MAX_LABEL_LEN + 1);
    for (run, case, member, group, field) in [
        ("", "c", "m", "g", "run_id"),
        ("Run", "c", "m", "g", "run_id"),
        ("r", "c d", "m", "g", "case_id"),
        ("r", "c", "m@x", "g", "member"),
        ("r", "c", "m", too_long.as_str(), "group"),
    ] {
        assert_eq!(
            LogContext::new(run, case, member, group, None),
            Err(LogContextError::InvalidLabel { field })
        );
    }
    assert_eq!(
        LogContext::new("r", "c", "m", "g", Some("bad fault")),
        Err(LogContextError::InvalidLabel { field: "fault" })
    );
    // Paired positive: the longest legal labels, and a fault entry, still make a line within the bound.
    let long = "a".repeat(MAX_LABEL_LEN);
    let label = long.as_str();
    let ctx = LogContext::new(label, label, label, label, Some(label)).expect("legal labels");
    let (mut gc, _) = locked_member(8_995_000_000_000);
    let event = drain(&mut gc).remove(0).payload;
    let line = event.to_log_line(&ctx).expect("within the bound");
    assert!(line.len() < MAX_LOG_LINE_BYTES);
    let parsed: franken_test_support::DiagnosticEvent =
        serde_json::from_str(&line).expect("parses");
    assert_eq!(parsed.fault.as_deref(), Some(long.as_str()));
    assert_eq!(parsed.cause, None);
    // No peer string can reach a line: the leader id of a stranger's response is a number the clock never copies.
    let mut gc = GroupClock::new(std_cfg(), 1, 7, 1).expect("member");
    let stranger = ProbeResponse {
        epoch: 1,
        leader: 0xDEAD_BEEF,
        seq: 1,
        t1_echo_ns: 0,
        t2_group_ns: 0,
        t3_group_ns: 0,
    };
    assert_eq!(
        gc.on_response(stranger, 10),
        Err(ProbeReject::UnadmittedLeader)
    );
    let line = drain(&mut gc)[0]
        .payload
        .to_log_line(&log_ctx())
        .expect("line");
    assert!(
        !line.to_lowercase().contains("deadbeef") && !line.contains("3735928559"),
        "{line}"
    );
    assert!(line.contains("\"cause\":\"UnadmittedLeader\""), "{line}");
}

// ------------------------------------------------------------------------------------------ coarse clocks
//
// A coarse clock reads the same value before and after a short round trip. These tests give such a member a world with an exact
// true time it can only see through rounded readings, so every claim about the uncertainty is compared with a truth that is not
// in the code under test. The expectations of the pure cases are worked out by hand in the comments; the scenario figures
// (counts of equal-reading exchanges, number of checks) were predicted by running the same worlds through the Python reference
// `tests/n03/reference.py` before any compile. These tests belong to the case `N03-COARSE-CLOCK`.

/// Exact true time `t` (ns), a member clock and a coordinator clock that each read it rounded down to a multiple of their
/// resolution (a group resolution of 0 reads exact). The member's clock has a skew and a start phase.
struct Coarse {
    res: u64,
    group_res: u64,
    skew_ppb: i64,
    local0: u64,
    group0: u64,
}

impl Coarse {
    fn local(&self, t: u64) -> u64 {
        let skewed = i128::from(t) * i128::from(self.skew_ppb);
        let v = i128::from(self.local0) + i128::from(t) + skewed.div_euclid(1_000_000_000);
        let v = u64::try_from(v).expect("a positive local time");
        v - v % self.res
    }

    fn group_read(&self, t: u64) -> u64 {
        let v = self.group0 + t;
        if self.group_res == 0 {
            v
        } else {
            v - v % self.group_res
        }
    }

    fn group_true(&self, t: u64) -> u64 {
        self.group0 + t
    }

    /// The first true instant at which the member's clock shows `reading` (the clock never goes back).
    fn tick(&self, reading: u64) -> u64 {
        let (mut lo, mut hi) = (0_u64, 1_u64 << 44);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.local(mid) >= reading {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }
}

/// A coarse clock's configuration. The resolution is charged twice in every uncertainty, so the 2 ms default threshold would
/// refuse a 1.7 ms clock for good (its uncertainty is at least 3.4 ms); the worlds that must lock raise it to 4 ms.
fn coarse_cfg(res: u64) -> GroupClockConfig {
    let mut cfg = std_cfg();
    cfg.timer_resolution_ns = res;
    cfg.lock_uncertainty_ns = 4_000_000;
    cfg.validate().expect("a coarse configuration is valid");
    cfg
}

/// One exchange sent at true time `ts` with forward delay `df`, coordinator dwell and return delay `dr`: the member's request,
/// the coordinator's answer as the world reads it, and the member's receipt. Returns `(t1, t4, outcome)`.
fn coarse_probe(
    world: &Coarse,
    gc: &mut GroupClock,
    ts: u64,
    (df, dwell, dr): (u64, u64, u64),
) -> (u64, u64, Result<Accepted, ProbeReject>) {
    let req = gc.next_probe(world.local(ts));
    let resp = ProbeResponse {
        epoch: 1,
        leader: 7,
        seq: req.seq,
        t1_echo_ns: req.t1_local_ns,
        t2_group_ns: world.group_read(ts + df),
        t3_group_ns: world.group_read(ts + df + dwell),
    };
    let t4 = world.local(ts + df + dwell + dr);
    (req.t1_local_ns, t4, gc.on_response(resp, t4))
}

/// An exchange whose four readings the test states: group time `group` at both `t2` and `t3`, local readings `t1` and `t4`.
fn flat_exchange(
    gc: &mut GroupClock,
    t1: u64,
    t4: u64,
    group: u64,
) -> Result<Accepted, ProbeReject> {
    let req = gc.next_probe(t1);
    let resp = ProbeResponse {
        epoch: 1,
        leader: 7,
        seq: req.seq,
        t1_echo_ns: t1,
        t2_group_ns: group,
        t3_group_ns: group,
    };
    gc.on_response(resp, t4)
}

/// Uncertainty minus error at the reading `now`, the error taken against the exact group time at the instant the member's
/// clock first showed it (when a start scheduled by that reading fires).
fn tick_margin(world: &Coarse, gc: &GroupClock, now: u64) -> Option<i128> {
    let a = gc.reading(now)?;
    let error = group_at(&a, now).abs_diff(world.group_true(world.tick(now)));
    Some(i128::from(a.uncertainty_ns) - i128::from(error))
}

/// The same against the exact group time at any instant `t_now` at which the clock shows `now`. A coarse clock shows one value
/// for a whole tick, so this is the public claim the uncertainty has to meet, not the tick's first instant alone.
fn instant_margin(world: &Coarse, gc: &GroupClock, now: u64, t_now: u64) -> Option<i128> {
    let a = gc.reading(now)?;
    let error = group_at(&a, now).abs_diff(world.group_true(t_now));
    Some(i128::from(a.uncertainty_ns) - i128::from(error))
}

/// Hand-derived. Resolution R = 1.7 ms, t1 = t4 = 5 000 000 000, t2 = 9 000 000 000 000, so the round trip is below R:
/// delay 0 (all a reading can say), local_mid = t1, group_mid = t2 + dwell / 2 (floor), and the base uncertainty is 2R.
/// The coordinator's dwell is admitted below 2R (its own two readings are rounded too) and refused from 2R as a clock that
/// stood still. Readings that differ keep the exact rules, and a clock declared exact cannot stand still at all.
#[test]
fn n03_equal_readings_are_a_sub_resolution_exchange_on_a_coarse_clock_and_backwards_time_is_not() {
    let r = 1_700_000;
    let (t1, t2) = (5_000_000_000_u64, 9_000_000_000_000_u64);
    let cfg = coarse_cfg(r);
    let s = Sample::from_exchange(t1, t2, t2, t1, &cfg).expect("zero dwell");
    assert_eq!((s.delay_ns, s.local_mid_ns, s.group_mid_ns), (0, t1, t2));
    assert_eq!(base_uncertainty_ns(&cfg, s.delay_ns), 2 * r);
    let s = Sample::from_exchange(t1, t2, t2 + 1_000_000, t1, &cfg).expect("1 ms dwell");
    assert_eq!(
        (s.delay_ns, s.local_mid_ns, s.group_mid_ns),
        (0, t1, t2 + 500_000)
    );
    // for equal readings the bound is 2R plus the rate allowance over the hidden tick: 3 400 000 + ceil(1.7e6 * 100 ppm) = 3 400 170
    let s = Sample::from_exchange(t1, t2, t2 + 3_400_169, t1, &cfg).expect("one under the bound");
    assert_eq!(s.group_mid_ns, t2 + 1_700_084);
    assert_eq!(
        Sample::from_exchange(t1, t2, t2 + 3_400_170, t1, &cfg),
        Err(ProbeReject::LocalClockRegression),
        "the bound cannot hide inside one reading"
    );
    // an exact clock cannot read the same value across a round trip
    assert_eq!(
        Sample::from_exchange(t1, t2, t2, t1, &coarse_cfg(0)),
        Err(ProbeReject::LocalClockRegression)
    );
    // backwards time is never rounding, on any clock
    for res in [0, 1_000, r] {
        assert_eq!(
            Sample::from_exchange(t1, t2, t2, t1 - 1, &coarse_cfg(res)),
            Err(ProbeReject::LocalClockRegression),
            "resolution {res}"
        );
    }
    // readings one tick apart are an ordinary exchange: delay is the round trip less the dwell
    let s = Sample::from_exchange(t1, t2, t2 + 1_000_000, t1 + r, &cfg).expect("one tick apart");
    assert_eq!((s.delay_ns, s.local_mid_ns), (700_000, t1 + 850_000));
    // a dwell longer than the round trip is a rounding while the excess is below 2R plus the rate allowance, readings equal or not:
    // rtt 1 ms, allowance ceil((1 ms + the hidden tick 1.7 ms) * 100 ppm) = 270 ns, so the bound is 3 400 270; the delay is clamped to 0 below it
    let rtt = 1_000_000;
    let s = Sample::from_exchange(t1, t2, t2 + rtt + 3_400_269, t1 + rtt, &cfg)
        .expect("one under the bound");
    assert_eq!((s.delay_ns, s.local_mid_ns), (0, t1 + 500_000));
    assert_eq!(
        Sample::from_exchange(t1, t2, t2 + rtt + 3_400_270, t1 + rtt, &cfg),
        Err(ProbeReject::Malformed),
        "the bound is no rounding"
    );
    // the same one nanosecond over, at the default resolution, used to be Malformed and is a rounding
    let s = Sample::from_exchange(t1, t2, t2 + 101, t1 + 100, &std_cfg()).expect("a rounding");
    assert_eq!(
        (s.delay_ns, s.local_mid_ns, s.group_mid_ns),
        (0, t1 + 50, t2 + 50)
    );
    // the review's physical witness by hand: local grid 3 ms, group grid 4 ms, declared R = 4 ms. Send at true 2.5 ms: t1 = 0; it
    // arrives at 2.6 ms: t2 = 0; the reply leaves at 4.1 ms: t3 = 4 ms; it arrives at 4.2 ms: t4 = 3 ms. Round trip 3 ms, dwell 4 ms.
    let s = Sample::from_exchange(0, 0, 4_000_000, 3_000_000, &coarse_cfg(4_000_000))
        .expect("grids 3 ms and 4 ms");
    assert_eq!(
        (s.delay_ns, s.local_mid_ns, s.group_mid_ns),
        (0, 1_500_000, 2_000_000)
    );
    // an equal-reading exchange is still checked for impossible timestamps first
    assert_eq!(
        Sample::from_exchange(t1, t2, t2 - 1, t1, &cfg),
        Err(ProbeReject::Malformed)
    );
    assert_eq!(
        Sample::from_exchange(t1, MAX_TIMESTAMP_NS + 1, MAX_TIMESTAMP_NS + 1, t1, &cfg),
        Err(ProbeReject::Malformed)
    );
}

/// A member that sends on a tick of its own 1.7 ms clock and hears back inside the same tick reads t4 == t1 every time. Before
/// the correction every one of those exchanges was refused and the member never locked. The truth is compared at the first
/// and at the last instant at which the clock shows the reading asked about.
#[test]
fn n03_a_coarse_clock_that_probes_on_its_own_tick_locks_and_the_truth_stays_inside_the_reported_uncertainty()
 {
    let r = 1_700_000_u64;
    // (coordinator resolution, member skew in ppb, start phase in ns)
    for (group_res, skew_ppb, phase) in [(r, 0, 0), (0, 80_000, 0), (r, -80_000, 1_000_003)] {
        let world = Coarse {
            res: r,
            group_res,
            skew_ppb,
            local0: 3_000_000_000 + phase,
            group0: 40_000_000_000_000,
        };
        let mut gc = GroupClock::new(coarse_cfg(r), 1, 7, 1000).expect("member");
        let mut first_lock = None;
        let mut min_margin = i128::MAX;
        for k in 0..12_u64 {
            let ts = world.tick(world.local(k * 1_000_000_000) + r);
            let (t1, t4, outcome) = coarse_probe(&world, &mut gc, ts, (120_000, 40_000, 240_000));
            assert_eq!(
                t4, t1,
                "world {group_res}/{skew_ppb}: the exchange fits inside one tick"
            );
            let accepted = outcome.expect("an equal-reading exchange is admitted");
            if first_lock.is_none() && accepted.status == ClockStatus::Locked {
                first_lock = Some(k);
                // hand-derived: delay 0, age 0, no board term, so the uncertainty is twice the resolution (3.4 ms) plus 170 ns for
                // the second resolution read through the 100 ppm bound (1.7e6 * 1e5 / 1e9 = 170); the
                // headroom to the 4 ms threshold is 599 830 ns, which the 100 ppm bound spends in 5 998 300 000 ns (plus the next)
                assert_eq!(gc.reading(t4).expect("reading").uncertainty_ns, 2 * r + 170);
                assert_eq!(
                    gc.holdover(t4),
                    Some(Holdover {
                        until_local_ns: t1 + 5_998_300_001,
                        binding: Binding::Uncertainty
                    })
                );
            }
            let now = world.local(ts + 400_000 + 250_000_000);
            // the truth at the first instant the clock shows `now`, and at the last one, which is nearly a resolution later
            let first = world.tick(now);
            let last = world.tick(now + r) - 1;
            assert_eq!((world.local(first), world.local(last)), (now, now));
            for t_now in [first, last] {
                min_margin =
                    min_margin.min(instant_margin(&world, &gc, now, t_now).expect("a reading"));
            }
            min_margin = min_margin.min(tick_margin(&world, &gc, now).expect("a reading"));
        }
        assert_eq!(
            first_lock,
            Some(3),
            "it locks on the fourth, as any clock does"
        );
        assert!(
            min_margin > 0,
            "world {group_res}/{skew_ppb}: the truth left the uncertainty by {}",
            -min_margin
        );
        // the same exchanges on a clock declared exact are refused: the declared resolution is what admits them
        let mut exact = GroupClock::new(coarse_cfg(0), 1, 7, 1000).expect("member");
        let ts = world.tick(world.local(0) + r);
        let (_, _, outcome) = coarse_probe(&world, &mut exact, ts, (120_000, 40_000, 240_000));
        assert_eq!(outcome, Err(ProbeReject::LocalClockRegression));
        // estimated error against the known truth is logged as within
        let ts = world.tick(world.local(13 * 1_000_000_000) + r);
        let (_, _, outcome) = coarse_probe(&world, &mut gc, ts, (120_000, 40_000, 240_000));
        outcome.expect("admitted");
        let now = world.local(ts + 400_000 + 250_000_000);
        let error = gc
            .note_truth(now, world.group_true(world.tick(now)))
            .expect("an estimate");
        assert!(error.unsigned_abs() <= gc.reading(now).expect("reading").uncertainty_ns);
        let seen = labels(&mut gc);
        assert!(seen.iter().any(|l| l == "n03.truth.within"), "{seen:?}");
        assert!(!seen.iter().any(|l| l == "n03.truth.violated"), "{seen:?}");
    }
}

/// Every start phase, path asymmetry, member skew and coordinator resolution of a 1.7 ms and a 0.4 ms clock, 40 jittered
/// probes each: no reset, and the truth inside the uncertainty both at the clock's tick and at an arbitrary instant of the
/// tick. Predicted by the Python reference: 4 320 checks, 1 454 of the exchanges with equal readings
/// (all on the 1.7 ms clock; a 0.4 ms clock sees a 400 us round trip as one tick or more).
#[test]
fn n03_the_truth_stays_inside_the_uncertainty_for_every_phase_asymmetry_and_skew_of_a_coarse_clock()
{
    let (mut checks, mut equal) = (0_u64, 0_u64);
    let (mut worst_tick, mut worst_instant) = (i128::MAX, i128::MAX);
    for res in [1_700_000_u64, 400_000] {
        for group_res in [res, 0] {
            for skew_ppb in [0_i64, 80_000, -80_000] {
                for asym in [0_u64, 120_000, 240_000] {
                    for phase in [0, res / 3, res / 2 + 7] {
                        let world = Coarse {
                            res,
                            group_res,
                            skew_ppb,
                            local0: 3_000_000_000 + phase,
                            group0: 40_000_000_000_000,
                        };
                        let mut gc = GroupClock::new(coarse_cfg(res), 1, 7, 1000).expect("member");
                        let mut state = 1 + u32::try_from(phase % 7).expect("small");
                        for k in 0..40_u64 {
                            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                            let ts = k * 1_000_000_000 + u64::from(state) % 5_000_000;
                            let path = (120_000 + asym, 40_000, 240_000);
                            let (t1, t4, outcome) = coarse_probe(&world, &mut gc, ts, path);
                            outcome.expect("a clean coarse exchange is admitted");
                            equal += u64::from(t4 == t1);
                            let t_now = ts + path.0 + path.1 + path.2 + 1_500_000;
                            let now = world.local(t_now);
                            let on_tick = tick_margin(&world, &gc, now).expect("a reading");
                            let any_instant =
                                instant_margin(&world, &gc, now, t_now).expect("a reading");
                            worst_tick = worst_tick.min(on_tick);
                            worst_instant = worst_instant.min(any_instant);
                            checks += 1;
                        }
                        assert_eq!(gc.stats().resets, 0, "a clean coarse world never resets");
                    }
                }
            }
        }
    }
    assert_eq!((checks, equal), (4_320, 1_454));
    assert!(
        worst_tick > 0,
        "on the tick the truth left the uncertainty by {}",
        -worst_tick
    );
    assert!(
        worst_instant > 0,
        "at an instant of the tick the truth left the uncertainty by {}",
        -worst_instant
    );
}

/// Backwards time is still refused on a coarse clock, and equal readings across exchanges are not backwards time. Readings
/// are on the 1.7 ms grid; the group clock reads the same offset throughout.
#[test]
fn n03_backwards_time_is_rejected_on_a_coarse_clock_and_equal_readings_across_exchanges_are_not() {
    let r = 1_700_000_u64;
    let off = 8_994_999_200_000_u64;
    let tick = 5_100_000_000_u64; // 3 000 ticks
    let mut gc = GroupClock::new(coarse_cfg(r), 1, 7, 10).expect("member");
    assert!(flat_exchange(&mut gc, tick, tick, tick + off).is_ok());
    // t4 before t1 inside the exchange: a sample-level reject that leaves the fit alone
    assert_eq!(
        flat_exchange(&mut gc, tick + r, tick, tick + r + off),
        Err(ProbeReject::LocalClockRegression)
    );
    let stats = gc.stats();
    assert_eq!((stats.resets, stats.accepted, gc.sample_count()), (0, 1, 1));
    assert_eq!(stats.rejected(ProbeReject::LocalClockRegression), 1);
    // the same reading again, across exchanges: equal is not backwards, so it is admitted
    assert!(flat_exchange(&mut gc, tick, tick, tick + off).is_ok());
    assert_eq!((gc.stats().resets, gc.sample_count()), (0, 2));
    // one tick back between exchanges: the clock went back, so the fit is cleared and the member is muted
    assert_eq!(
        flat_exchange(&mut gc, tick - r, tick - r, tick - r + off),
        Err(ProbeReject::LocalClockRegression)
    );
    let stats = gc.stats();
    assert_eq!((stats.resets, gc.sample_count()), (1, 0));
    assert_eq!(stats.rejected(ProbeReject::LocalClockRegression), 2);
    assert_eq!(gc.tick(tick), Output::Muted(MuteReason::Discontinuity));
}

/// A local clock that does not advance while the group clock does is not a coarse clock, it is stuck: its exchanges are
/// admitted one at a time (equal readings, a small dwell) and each next one disagrees with the last by a second of group time,
/// which is a clock jump. It never gathers four samples, never locks and is never audible.
#[test]
fn n03_a_stuck_local_clock_never_locks_because_the_group_clock_keeps_moving() {
    let mut gc = GroupClock::new(coarse_cfg(1_700_000), 1, 7, 1000).expect("member");
    let frozen = 5_000_000_000_u64;
    let (mut accepted, mut jumps) = (0_u32, 0_u32);
    for k in 0..20_u64 {
        let req = gc.next_probe(frozen);
        let group = 9_000_000_000_000 + k * 1_000_000_000;
        let resp = ProbeResponse {
            epoch: 1,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: frozen,
            t2_group_ns: group,
            t3_group_ns: group + 40_000,
        };
        match gc.on_response(resp, frozen) {
            Ok(_) => accepted += 1,
            Err(ProbeReject::Discontinuity) => jumps += 1,
            Err(other) => panic!("unexpected rejection {other:?}"),
        }
        assert_ne!(gc.status(frozen), ClockStatus::Locked);
        assert!(!gc.tick(frozen).is_audible());
    }
    assert_eq!((accepted, jumps), (10, 10));
    assert_eq!(gc.stats().resets, 10);
}

/// Replay, unadmitted leader, wrong echo and stale epoch are refused on the equal-reading path, each beside the exchange that
/// is accepted. Two requests sent in the same tick carry the same `t1`, so the sequence number alone tells them apart.
#[test]
fn n03_replayed_unadmitted_and_stale_responses_are_refused_on_a_coarse_clock_beside_the_exchange_that_is_accepted()
 {
    let r = 1_700_000_u64;
    let t1 = 5_100_000_000_u64;
    let mut gc = GroupClock::new(coarse_cfg(r), 1, 7, 50).expect("member");
    let first = gc.next_probe(t1);
    let second = gc.next_probe(t1);
    assert_eq!(first.t1_local_ns, second.t1_local_ns);
    assert_ne!(first.seq, second.seq);
    let answer = |seq: u64| ProbeResponse {
        epoch: 1,
        leader: 7,
        seq,
        t1_echo_ns: t1,
        t2_group_ns: t1 + 8_994_999_200_000,
        t3_group_ns: t1 + 8_994_999_240_000,
    };
    assert!(gc.on_response(answer(first.seq), t1).is_ok());
    assert_eq!(
        gc.on_response(answer(first.seq), t1),
        Err(ProbeReject::UnsolicitedOrReplayed),
        "a request is answered once"
    );
    let mut stranger = answer(second.seq);
    stranger.leader = 99;
    assert_eq!(
        gc.on_response(stranger, t1),
        Err(ProbeReject::UnadmittedLeader)
    );
    let mut wrong_echo = answer(second.seq);
    wrong_echo.t1_echo_ns = t1 + r;
    assert_eq!(
        gc.on_response(wrong_echo, t1),
        Err(ProbeReject::UnsolicitedOrReplayed)
    );
    assert!(
        gc.on_response(answer(second.seq), t1).is_ok(),
        "the right answer still counts"
    );
    assert_eq!((gc.sample_count(), gc.stats().resets), (2, 0));
    gc.begin_epoch(2, 8).expect("a newer epoch");
    assert_eq!(
        gc.on_response(answer(second.seq), t1),
        Err(ProbeReject::StaleEpoch)
    );
}

/// The prediction check keeps its meaning on a coarse clock. After five samples on the 1.7 ms grid the sixth, a second
/// later, is judged against what the fit predicts. The step it may differ by is, by hand: the anchor's uncertainty at the new
/// midpoint (2R = 3 400 000, the second resolution through the 100 ppm bound 170, 100 ppm of the 999 600 000 ns age rounded up
/// 99 960), plus half the delay (0), plus the slack, 500 000: 3 400 000 + 170 + 99 960 + 500 000 = 4 000 130. Two coarse exchanges can differ by nearly 2R (3.4 ms) in what they
/// measure, which the anchor's own 2R covers. A step of exactly the allowance is noise; one nanosecond more is a jump that
/// clears the fit.
#[test]
fn n03_a_step_inside_what_two_roundings_can_account_for_is_noise_and_one_nanosecond_more_is_a_jump_on_a_coarse_clock()
 {
    let r = 1_700_000_u64;
    let off = 8_994_999_200_000_u64;
    let t1_of = |k: u64| 5_100_000_000 + k * 999_600_000; // 588 ticks apart, so on the grid
    for extra in [0_u64, 1] {
        let mut gc = GroupClock::new(coarse_cfg(r), 1, 7, 100).expect("member");
        for k in 0..5 {
            assert!(flat_exchange(&mut gc, t1_of(k), t1_of(k), t1_of(k) + off).is_ok());
        }
        let age = t1_of(5) - t1_of(4);
        assert_eq!(age, 999_600_000);
        let allowed = 2 * r + 170 + age.div_ceil(10_000) + 500_000;
        assert_eq!(allowed, 4_000_130);
        let outcome = flat_exchange(
            &mut gc,
            t1_of(5),
            t1_of(5),
            t1_of(5) + off + allowed + extra,
        );
        if extra == 0 {
            assert!(outcome.is_ok(), "{outcome:?}");
            assert_eq!(gc.stats().resets, 0);
        } else {
            assert_eq!(outcome, Err(ProbeReject::Discontinuity));
            assert_eq!((gc.stats().resets, gc.sample_count()), (1, 0));
        }
    }
}

/// A clock whose rounding alone, with the board term, is above the threshold admits every valid exchange and still never
/// locks, however many arrive: the reported uncertainty is twice the resolution plus the board term, which is why it stays
/// muted. The default 2 ms threshold is inclusive: an uncertainty of 2 000 000 locks, 2 000 001 does not. So a 1.7 ms clock
/// (3.4 ms) cannot lock at the default threshold at all.
#[test]
fn n03_a_clock_too_coarse_for_the_threshold_stays_muted_however_many_exchanges_are_admitted() {
    // (resolution, board calibration uncertainty, whether it can lock)
    // 2R + board + R * 100 ppm: for R = 800 000 that is 1 600 000 + board + 80; for 999 950 it is 1 999 900 + 100
    let cases = [
        (4_000_000_u64, 0_u64, false),
        (1_700_000, 0, false),
        (800_000, 399_920, true),
        (800_000, 399_921, false),
        (999_950, 0, true),
        (999_951, 0, false),
    ];
    for (r, cal, can_lock) in cases {
        let mut cfg = std_cfg();
        cfg.timer_resolution_ns = r;
        cfg.calibration_uncertainty_ns = cal;
        let mut gc = GroupClock::new(cfg, 1, 7, 7).expect("member");
        let mut ever_locked = false;
        let mut last = 0;
        for k in 0..40_u64 {
            let t1 = r * (3_000 + 600 * k);
            let accepted = flat_exchange(&mut gc, t1, t1, t1 + 9_000_000_000_000)
                .expect("a valid exchange is admitted whatever the clock can qualify");
            ever_locked |= accepted.status == ClockStatus::Locked;
            last = t1;
        }
        assert_eq!(ever_locked, can_lock, "resolution {r}, board term {cal}");
        assert_eq!(
            gc.reading(last).expect("reading").uncertainty_ns,
            2 * r + cal + r.div_ceil(10_000),
            "delay 0 and age 0: twice the resolution, the board term and the second resolution through the 100 ppm bound"
        );
        if !can_lock {
            let sched = StartSchedule {
                epoch: 1,
                start_group_ns: 9_000_000_000_000 + last + 500_000_000,
            };
            assert_eq!(gc.plan_start(sched, last), Err(StartReject::NotLocked));
            assert_eq!(gc.output(last), Output::Muted(MuteReason::NotLocked));
            assert_eq!(gc.status(last), ClockStatus::Unlocked);
        }
    }
}

/// The independent review's witness, by hand. R = 1.7 ms; the member's clock reads floor(t / R) * R; the true group time is
/// t + 1.6 ms and the coordinator reads it the same way. Four exchanges at true times 0 to 0.03 ms all read t1 = t4 = 0 and
/// t2 = t3 = floor((t + 1.6 ms) / R) * R = 0, so the offset is estimated as 0 where it is 1.6 ms. At true time 1.6 ms the
/// member still reads 0 (a tick lasts until 1.7 ms): the report is 0 and the true group time is 3.2 ms, an error of 3.2 ms.
/// Charging the resolution once (1.7 ms) was exceeded; charging it twice (3.4 ms) holds at every instant of the tick, and 3.4 ms
/// is above the default 2 ms threshold, so that clock must not lock there at all.
#[test]
fn n03_a_coarse_clock_read_late_inside_its_tick_is_still_inside_the_uncertainty_that_charges_the_resolution_twice()
 {
    let r = 1_700_000_u64;
    let world = Coarse {
        res: r,
        group_res: r,
        skew_ppb: 0,
        local0: 0,
        group0: 1_600_000,
    };
    for threshold in [2_000_000_u64, 4_000_000] {
        let mut cfg = std_cfg();
        cfg.timer_resolution_ns = r;
        cfg.lock_uncertainty_ns = threshold;
        let mut gc = GroupClock::new(cfg, 1, 7, 1000).expect("member");
        for k in 0..4_u64 {
            let (t1, t4, outcome) =
                coarse_probe(&world, &mut gc, k * 10_000, (5_000, 5_000, 5_000));
            assert_eq!((t1, t4), (0, 0));
            outcome.expect("admitted");
            assert_eq!(
                world.group_read(k * 10_000 + 5_000),
                0,
                "the coordinator reads 0 as well"
            );
        }
        let a = gc.reading(0).expect("reading");
        assert_eq!(
            a.uncertainty_ns,
            2 * r + 170,
            "delay 0, age 0: twice the resolution and the second one read through the 100 ppm bound, exactly"
        );
        if threshold == 2_000_000 {
            // 3.4 ms is above the 2 ms threshold: the bound cannot support a lock, so it does not lock
            assert_eq!(gc.status(0), ClockStatus::Unlocked);
            assert_eq!(gc.output(0), Output::Muted(MuteReason::NotLocked));
            continue;
        }
        assert_eq!(gc.status(0), ClockStatus::Locked);
        assert_eq!(group_at(&a, 0), 0, "the report");
        // at true time 1.6 ms the clock still shows 0 and the group is at 3.2 ms
        let error = group_at(&a, world.local(1_600_000)).abs_diff(world.group_true(1_600_000));
        assert_eq!(error, 3_200_000);
        assert!(error > r, "more than the single charge");
        assert!(error <= a.uncertainty_ns, "inside the doubled one");
        for t_now in (0..r).step_by(100_000).chain([r - 1]) {
            assert_eq!(world.local(t_now), 0);
            let margin = instant_margin(&world, &gc, 0, t_now).expect("a reading");
            assert!(margin >= 100_000, "true time {t_now}: margin {margin}");
        }
    }
}

/// The independent review's second witness, in a physical world: local grid 3 ms, group grid 4 ms, zero true offset and rate,
/// declared (coarsest) resolution 4 ms. Send at true 2.5 ms: t1 = 0. It arrives at 2.6 ms: t2 = 0. The reply leaves at 4.1 ms:
/// t3 = 4 ms. It arrives at 4.2 ms: t4 = 3 ms. The true dwell 1.5 ms is below the true round trip 1.7 ms, and the readings say a
/// round trip of 3 ms and a dwell of 4 ms. That exchange is admitted with the delay clamped to 0 (local_mid 1.5 ms, group_mid 2 ms),
/// where the old exact rule refused it. The bound is not blind: a dwell over the round trip by 2R plus the rate allowance
/// (8 ms + ceil((3 ms + the hidden tick 4 ms) * 100 ppm) = 700 ns) is `Malformed`, one nanosecond under it is a rounding, and
/// backwards time is still backwards.
#[test]
fn n03_a_dwell_over_the_round_trip_is_a_rounding_inside_the_bound_and_malformed_at_it_beside_backwards_time()
 {
    let world = Coarse {
        res: 3_000_000,
        group_res: 4_000_000,
        skew_ppb: 0,
        local0: 0,
        group0: 0,
    };
    let mut cfg = coarse_cfg(4_000_000);
    cfg.lock_uncertainty_ns = 10_000_000;
    let mut gc = GroupClock::new(cfg, 1, 7, 5).expect("member");
    let (t1, t4, outcome) = coarse_probe(&world, &mut gc, 2_500_000, (100_000, 1_500_000, 100_000));
    assert_eq!((t1, t4), (0, 3_000_000));
    assert_eq!(
        (world.group_read(2_600_000), world.group_read(4_100_000)),
        (0, 4_000_000)
    );
    outcome.expect("a quantization-consistent negative measured delay is admitted");
    let a = gc.reading(t4).expect("reading");
    assert_eq!(
        (
            a.sample.delay_ns,
            a.sample.local_mid_ns,
            a.sample.group_mid_ns
        ),
        (0, 1_500_000, 2_000_000)
    );
    // the bound, on a hand-built exchange of the same clocks (rtt 3 ms): the excess must stay under 8 000 000 + 700
    for (dwell, admitted) in [
        (3_000_000 + 8_000_699, true),
        (3_000_000 + 8_000_700, false),
    ] {
        let req = gc.next_probe(3_000_000);
        let resp = ProbeResponse {
            epoch: 1,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: 3_000_000,
            t2_group_ns: 4_000_000,
            t3_group_ns: 4_000_000 + dwell,
        };
        let outcome = gc.on_response(resp, 6_000_000);
        if admitted {
            assert!(outcome.is_ok(), "{outcome:?}");
        } else {
            assert_eq!(
                outcome,
                Err(ProbeReject::Malformed),
                "excess 2R + the rate allowance is no rounding"
            );
        }
    }
    // true backwards time, with an excess of dwell on top: still LocalClockRegression
    let req = gc.next_probe(9_000_000);
    let resp = ProbeResponse {
        epoch: 1,
        leader: 7,
        seq: req.seq,
        t1_echo_ns: 9_000_000,
        t2_group_ns: 8_000_000,
        t3_group_ns: 12_000_000,
    };
    assert_eq!(
        gc.on_response(resp, 8_999_999),
        Err(ProbeReject::LocalClockRegression)
    );
}

/// The independent review's natural prediction-slack witness, in a physical world: the same grids, zero offset, declared R = 4 ms.
/// Tiny exchanges around true 3 ms read (t1, t2, t3, t4) = (3 ms, 0, 0, 3 ms); around true 8 ms they read (6 ms, 8 ms, 8 ms, 6 ms).
/// The fit of the first predicts the group time 3 ms at local 6 ms and the new sample says 8 ms: a step of 5 ms that no clock
/// stepped. Charging the resolution once allowed R + 300 ns (3 ms of age at 100 ppm) + 500 us = 4 500 300 ns and called it a jump;
/// the anchor's 2R (8 ms) + 400 (the second resolution through 100 ppm: 4e6 * 1e5 / 1e9) + 300 + 500 000 = 8 500 700
/// admits it. A real step is still refused: the group clock jumping 10 ms makes it 13 ms (the coordinator reads 16 ms).
#[test]
fn n03_a_step_of_two_roundings_between_physical_samples_is_noise_and_a_real_group_clock_step_is_a_jump()
 {
    let mut cfg = coarse_cfg(4_000_000);
    cfg.lock_uncertainty_ns = 10_000_000;
    for step in [0_u64, 10_000_000] {
        let world = Coarse {
            res: 3_000_000,
            group_res: 4_000_000,
            skew_ppb: 0,
            local0: 0,
            group0: 0,
        };
        let stepped = Coarse {
            group0: step,
            ..world
        };
        let mut gc = GroupClock::new(cfg.clone(), 1, 7, 9).expect("member");
        for k in 0..4_u64 {
            let (t1, t4, outcome) =
                coarse_probe(&world, &mut gc, 3_000_000 + k * 10_000, (5_000, 0, 5_000));
            assert_eq!((t1, t4), (3_000_000, 3_000_000));
            assert_eq!(world.group_read(3_005_000 + k * 10_000), 0);
            outcome.expect("admitted");
        }
        let anchor = gc.reading(6_000_000).expect("reading");
        assert_eq!(
            anchor.ratio_unc_ppb, 100_000,
            "no fit is in force after four samples"
        );
        let (t1, t4, outcome) = coarse_probe(&stepped, &mut gc, 8_000_000, (5_000, 0, 5_000));
        assert_eq!((t1, t4), (6_000_000, 6_000_000));
        assert_eq!(
            stepped.group_read(8_005_000),
            8_000_000 + step / 4_000_000 * 4_000_000
        );
        let allowed = 2 * 4_000_000 + 400 + 300 + 500_000;
        assert_eq!(allowed, 8_500_700);
        if step == 0 {
            assert!(
                5_000_000 > 4_000_000 + 300 + 500_000,
                "the single charge would have refused this"
            );
            assert!(5_000_000 < allowed);
            outcome.expect("two roundings are noise");
            assert_eq!(gc.stats().resets, 0);
        } else {
            assert_eq!(outcome, Err(ProbeReject::Discontinuity));
            assert_eq!((gc.stats().resets, gc.sample_count()), (1, 0));
        }
    }
}

/// DarkValley's slow-clock witness (7852): the rate acts on the TRUE elapsed time, which an observed round trip of zero hides by up
/// to a whole tick. R = 4 ms; the member's clock is 80 ppm slow, `L(t) = 0.99992 t`, floored to R; the true group time is
/// `t + 3 999 980` ns, floored to R. Send at true 0: t1 = 0. It arrives at 10 ns: group 3 999 990, t2 = 0. The reply leaves at
/// 4 000 110: group 8 000 090, t3 = 8 000 000. It arrives at 4 000 120: `L = 3 999 799` is below R, t4 = 0. The true dwell
/// 4 000 100 ns is below the true round trip 4 000 120 ns, yet the readings give round trip 0 and dwell exactly 2R. A rate allowance
/// over the observed round trip alone (0) refuses it as a stalled clock; over the observed round trip plus the hidden tick it is
/// `2R + ceil(4e6 * 100 ppm) = 8 000 400`, which admits it (80 ppm is inside the 100 ppm bound), and an excess of 8 000 400 is no
/// rounding. Beside it, true backwards time is still refused.
#[test]
fn n03_a_slow_clock_that_reads_zero_across_a_tick_is_a_physical_exchange_beside_the_over_bound_refusal()
 {
    let world = Coarse {
        res: 4_000_000,
        group_res: 4_000_000,
        skew_ppb: -80_000,
        local0: 0,
        group0: 3_999_980,
    };
    assert_eq!(
        (
            world.local(0),
            world.group_read(10),
            world.group_read(4_000_110),
            world.local(4_000_120)
        ),
        (0, 0, 8_000_000, 0)
    );
    let mut gc = GroupClock::new(coarse_cfg(4_000_000), 1, 7, 3).expect("member");
    let (t1, t4, outcome) = coarse_probe(&world, &mut gc, 0, (10, 4_000_100, 10));
    assert_eq!((t1, t4), (0, 0));
    outcome.expect("a slow clock's exchange is physical, however it reads");
    let a = gc.reading(0).expect("reading");
    assert_eq!(
        (
            a.sample.delay_ns,
            a.sample.local_mid_ns,
            a.sample.group_mid_ns
        ),
        (0, 0, 4_000_000)
    );
    // the bound, hand-built on the same readings: an excess of 8 000 399 is a rounding, 8 000 400 is not
    for (dwell, admitted) in [(8_000_399_u64, true), (8_000_400, false)] {
        let req = gc.next_probe(0);
        let resp = ProbeResponse {
            epoch: 1,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: 0,
            t2_group_ns: 0,
            t3_group_ns: dwell,
        };
        let outcome = gc.on_response(resp, 0);
        if admitted {
            assert!(outcome.is_ok(), "{outcome:?}");
        } else {
            assert_eq!(outcome, Err(ProbeReject::LocalClockRegression));
        }
    }
    // and one reading back is backwards on any clock, whatever the rate
    assert_eq!(
        Sample::from_exchange(1, 0, 0, 0, &coarse_cfg(4_000_000)),
        Err(ProbeReject::LocalClockRegression)
    );
}

/// DarkValley's fitted-rate witness (7852): the query tick is read through the FITTED mean ratio plus its error, not through the error
/// alone. R = 100 us, fitted ratio +80 ppm, uncertainty 6 ppm: a local tick passes 100 000 * 1.000080 = 100 008 ns of group time, and
/// 100 000 * 1.000086 = 100 008.6 at the fastest admitted ratio, so the excess over R is `ceil(8.6) = 9` (the error alone would show
/// `ceil(0.6) = 1`). A slow fit has none: at -80 ppm +- 6 ppm the lag is at most R. The hold-over headroom shrinks by the same nanoseconds.
#[test]
fn n03_the_query_tick_follows_the_fitted_mean_ratio_and_not_only_its_error() {
    let mut cfg = std_cfg();
    cfg.timer_resolution_ns = 100_000;
    assert_eq!(query_tick_rate_excess_ns(&cfg, 80_000, 6_000), 9);
    assert_eq!(
        query_tick_rate_excess_ns(&cfg, 80_000, 0),
        8,
        "an exactly known fast ratio still costs"
    );
    assert_eq!(query_tick_rate_excess_ns(&cfg, 0, 6_000), 1);
    assert_eq!(
        query_tick_rate_excess_ns(&cfg, -80_000, 6_000),
        0,
        "the fastest admitted ratio is below 1"
    );
    assert_eq!(
        query_tick_rate_excess_ns(&cfg, -80_000, 100_000),
        2,
        "-80 ppm + 100 ppm = 20 ppm: 2 ns"
    );
    let mut exact = std_cfg();
    exact.timer_resolution_ns = 0;
    assert_eq!(
        query_tick_rate_excess_ns(&exact, 80_000, 6_000),
        0,
        "an exact clock has no tick"
    );
    // the sample: delay 0, so the base is 2R = 200 000
    let s = Sample {
        delay_ns: 0,
        local_mid_ns: 100_000_000_000,
        group_mid_ns: 9_000_000_000_000,
    };
    assert_eq!(
        uncertainty_at(&cfg, &s, s.local_mid_ns, 80_000, 6_000),
        200_009
    );
    assert_eq!(uncertainty_at(&cfg, &s, s.local_mid_ns, 0, 6_000), 200_001);
    assert_eq!(
        uncertainty_at(&cfg, &s, s.local_mid_ns, -80_000, 6_000),
        200_000
    );
    // the hold-over limit, closed form: headroom 2 000 000 - 200 009 = 1 799 991; at 6 ppm that lasts 299 998 500 000 ns (plus the next)
    let fast = holdover_for(&cfg, &anchor_of(s, 80_000, 6_000), None, None);
    assert_eq!(
        fast,
        Holdover {
            until_local_ns: s.local_mid_ns + 299_998_500_001,
            binding: Binding::Uncertainty
        }
    );
    // with the error alone (ratio 0) the headroom is 1 799 999 and lasts 299 999 833 333 ns (plus the next)
    let error_only = holdover_for(&cfg, &anchor_of(s, 0, 6_000), None, None);
    assert_eq!(error_only.until_local_ns, s.local_mid_ns + 299_999_833_334);
    // and the instant before the fast limit still meets the threshold, the limit does not, with the fitted ratio in the arithmetic
    assert!(
        uncertainty_at(&cfg, &s, fast.until_local_ns - 1, 80_000, 6_000) <= cfg.lock_uncertainty_ns
    );
    assert!(uncertainty_at(&cfg, &s, fast.until_local_ns, 80_000, 6_000) > cfg.lock_uncertainty_ns);
}

/// Hand-derived: the largest slope error rounding can cause is `R * ceil(sqrt(2n)) / span`, in ppb.
#[test]
fn n03_the_rounding_bound_on_a_fitted_ratio_is_hand_derived_and_never_binds_at_the_default_resolution()
 {
    // 8 points over 4 s: ceil(sqrt(16)) = 4, 1000 * 4 * 1e6 / 4e6 = 1000
    assert_eq!(quantization_ratio_ppb(1_000, 8, 4_000_000), 1_000);
    // 64 points over 4 s: ceil(sqrt(128)) = 12 (11.3 rounds up), 1000 * 12 * 1e6 / 4e6 = 3000
    assert_eq!(quantization_ratio_ppb(1_000, 64, 4_000_000), 3_000);
    // 1.7 ms, 16 points over 150 s: ceil(sqrt(32)) = 6, 1.7e6 * 6 * 1e6 / 150e6 = 68 000
    assert_eq!(quantization_ratio_ppb(1_700_000, 16, 150_000_000), 68_000);
    // rounding up: 1 ns, 3 points (ceil(sqrt(6)) = 3) over 1 s is 3 ppb, over 2 s 1.5 ppb -> 2
    assert_eq!(quantization_ratio_ppb(1, 3, 1_000_000), 3);
    assert_eq!(quantization_ratio_ppb(1, 3, 2_000_000), 2);
    assert_eq!(
        quantization_ratio_ppb(0, 64, 4_000_000),
        0,
        "an exact clock"
    );
    assert_eq!(
        quantization_ratio_ppb(1_000, 8, 0),
        u64::MAX,
        "no span, no bound"
    );
    // at the default 1 us resolution it never exceeds the 6 ppm wander term that already sits in every ratio uncertainty,
    // for any window the estimator can offer, so the default-configuration numbers are exactly what they were
    let cfg = std_cfg();
    for n in cfg.rate.min_observations..=cfg.rate.window {
        let bound = quantization_ratio_ppb(cfg.timer_resolution_ns, n, cfg.rate.min_span_us);
        assert!(bound <= cfg.wander_ppb, "{n} points: {bound} ppb");
    }
}

/// Aliasing is the case the statistical bound cannot see. A 1.7 ms clock probing exactly once a second sees the same rounding
/// on every sample, so the least-squares residuals are tiny and the estimator reports a small standard error for a ratio that
/// is wrong by tens of ppm. The truth here is a local clock 80 ppm slow, so group time runs 80 006 ppb fast against it. While the
/// estimator is `Valid` with a statistical claim (three sigmas plus wander) that the real error exceeds, the member must not use
/// it: the rounding bound is above the oscillator's own 100 ppm, so the oscillator bound stands. A finer 100 us clock, whose
/// rounding bound is below it, is paired: its fit is in force, its uncertainty is the larger of the two bounds, and it holds
/// the truth.
#[test]
fn n03_a_fit_that_rounding_could_have_moved_further_than_the_oscillator_may_drift_is_not_trusted_and_a_finer_clock_still_is()
 {
    const TRUE_RATIO_PPB: i64 = 80_006;
    let run = |res: u64, phase: u64| {
        let world = Coarse {
            res,
            group_res: res,
            skew_ppb: -80_000,
            local0: 3_000_000_000 + phase,
            group0: 40_000_000_000_000,
        };
        let mut gc = GroupClock::new(coarse_cfg(res), 1, 7, 1000).expect("member");
        let (mut valid, mut refused, mut fabricated, mut in_force) = (0_u32, 0_u32, 0_u32, 0_u32);
        for k in 0..70_u64 {
            let ts = world.tick(world.local(k * 1_000_000_000) + res);
            let (_, t4, outcome) = coarse_probe(&world, &mut gc, ts, (120_000, 40_000, 240_000));
            outcome.expect("admitted");
            let Some(e) = gc
                .rate
                .estimate()
                .filter(|e| e.status == EstimateStatus::Valid)
            else {
                continue;
            };
            valid += 1;
            // the bound by hand: the smallest root with root^2 >= 2n, then R * root * 1e6 / span, rounded up
            let root = (1..=12_u128)
                .find(|root| root * root >= 2 * u128::from(e.observations))
                .expect("at most 64 points");
            let rounding =
                u64::try_from((u128::from(res) * root * 1_000_000).div_ceil(u128::from(e.span_us)))
                    .expect("fits");
            let statistical = e.uncertainty_ppb * 3 + 6_000;
            let a = gc.reading(t4).expect("reading");
            if gc.rate_in_force() {
                in_force += 1;
                assert_eq!(a.ratio_ppb, e.correction_ppb);
                assert_eq!(
                    a.ratio_unc_ppb,
                    statistical.max(rounding),
                    "the larger of two bounds on one error"
                );
                assert!(rounding <= 100_000);
                assert!(
                    (e.ratio_ppb - TRUE_RATIO_PPB).unsigned_abs() <= a.ratio_unc_ppb,
                    "probe {k}: the claimed ratio uncertainty {} excludes the true ratio",
                    a.ratio_unc_ppb
                );
            } else {
                refused += 1;
                assert!(rounding > 100_000, "probe {k}: refused for a reason");
                assert_eq!((a.ratio_ppb, a.ratio_unc_ppb), (0, 100_000));
                assert!(
                    TRUE_RATIO_PPB.unsigned_abs() <= a.ratio_unc_ppb,
                    "the oscillator bound holds the truth"
                );
                if (e.ratio_ppb - TRUE_RATIO_PPB).unsigned_abs() > statistical {
                    fabricated += 1;
                }
            }
        }
        (valid, refused, fabricated, in_force)
    };
    // the 1.7 ms clock: the estimator is Valid on 63 of the 70 probes and is never trusted; on 3 of them the old statistical
    // claim (about 9 ppm) was off by about 81 ppm
    let (valid, refused, fabricated, in_force) = run(1_700_000, 1_000_003);
    assert!(valid >= 40, "the estimator was Valid on {valid} probes");
    assert_eq!((refused, in_force), (valid, 0));
    assert!(
        fabricated >= 1,
        "no probe showed a statistical claim the truth exceeds"
    );
    // the 100 us clock: the same estimator is in force on every Valid probe
    let (valid, refused, fabricated, in_force) = run(100_000, 33_333);
    assert!(valid >= 40);
    assert_eq!((refused, fabricated, in_force), (0, 0, valid));
}
