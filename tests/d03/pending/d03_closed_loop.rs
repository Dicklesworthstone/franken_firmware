//! D03 closed loop in virtual time: a drifting source, the rate estimator, the level trim and the
//! slew-limited resampler, over a playout queue. No audio is synthesised: the resampler runs through
//! `plan`, which `d03_plan_equals_render` (in `franken-dsp`) pins to `render` step for step, so a day
//! of virtual time costs a few seconds.
//!
//! Expected values (occupancy bound, final-ratio tolerance, wrap count, output total, discontinuity
//! reason) come from `tests/d03/vectors.json`, written by the independent Python reference. Each test
//! prints `D03-OBSERVED {json}` for `tests/d03/run_cases.py` to re-check.
//!
//! Glue policy under test (docs/contracts/d03.md section 5): the ratio target is the estimator's
//! correction (held for at most 60 s after the last valid estimate, then zero) plus a proportional
//! level trim; an estimator discontinuity triggers an explicit epoch on both the estimator and the
//! resampler.

use franken_clock::rate::{
    DiscontinuityReason, EstimateStatus, Observation, RateConfig, RateError, RateEstimator,
    ResetReason,
};
use franken_dsp::resample::{
    DriftResampler, LevelTrim, ResampleError, ResamplerConfig, ResetReason as DspReset,
};
use serde_json::{Value, json};

const RATE_HZ: u64 = 48_000;
const BLOCK: u64 = 256;
const BASE_US: u64 = 1_000_000_000;
const HOLD_US: u64 = 60_000_000;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../tests/d03/vectors.json"))
        .expect("vectors.json parses")
}

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

/// Frames the source has produced by `t_us`, for a source running `drift_ppb` from nominal.
fn source_frames_at(t_us: u64, drift_ppb: i64) -> u64 {
    let scale = u128::try_from(1_000_000_000_i64 + drift_ppb).expect("drift within +-100%");
    u64::try_from(u128::from(t_us) * u128::from(RATE_HZ) * scale / 1_000_000_000_000_000)
        .expect("fits u64")
}

struct Outcome {
    blocks: u64,
    produced: u64,
    queue_end: u64,
    max_deviation: u64,
    underruns: u32,
    final_ratio_ppb: i32,
    wraps: u32,
    discontinuities: u32,
    est_resets: u32,
    rs_resets: u32,
    outputs: u64,
    inputs: u64,
    rejoin_seen: bool,
    est_epoch: u32,
    last_est_reset: Option<ResetReason>,
    last_rs_reset: Option<DspReset>,
    has_estimate_at_end: bool,
    held_ratio_after_reset: Option<i32>,
}

struct Plan {
    drift_ppb: i64,
    seconds: u64,
    pos0: u64,
    jitter_us: i64,
    seed: u32,
    kp: i64,
    trim_limit: i64,
    slew_ppm: u32,
    level_target: u64,
    controlled: bool,
    jump: Option<(u64, u64)>,
    hold_check_after_s: u64,
}

fn plan_from(case: &Value, controlled: bool) -> Plan {
    let get = |k: &str| {
        case[k]
            .as_u64()
            .unwrap_or_else(|| panic!("vector field {k}"))
    };
    Plan {
        drift_ppb: case["drift_ppb"].as_i64().expect("drift_ppb"),
        seconds: get("virtual_seconds"),
        pos0: get("pos0"),
        jitter_us: i64::try_from(get("jitter_us")).unwrap(),
        seed: u32::try_from(get("seed")).unwrap(),
        kp: case["kp_ppb_per_frame"].as_i64().unwrap(),
        trim_limit: case["trim_limit_ppb"].as_i64().unwrap(),
        slew_ppm: u32::try_from(get("slew_ppm_per_block")).unwrap(),
        level_target: get("level_target_frames"),
        controlled,
        jump: case
            .get("jump_at_s")
            .map(|s| (s.as_u64().unwrap(), get("jump_frames"))),
        hold_check_after_s: case
            .get("hold_check_after_s")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

fn run(p: &Plan) -> Outcome {
    let mut est = RateEstimator::new(RateConfig::for_rate(48_000).unwrap()).unwrap();
    let mut rs = DriftResampler::new(ResamplerConfig {
        max_ratio_ppm: 500,
        max_slew_ppm_per_block: p.slew_ppm,
    })
    .unwrap();
    let trim = LevelTrim {
        target_frames: p.level_target,
        gain_ppb_per_frame: p.kp,
        limit_ppb: p.trim_limit,
    };
    let blocks = p.seconds * RATE_HZ / BLOCK;
    let (mut queue, mut produced_prev, mut max_dev) = (p.level_target, 0_u64, 0_u64);
    let (mut underruns, mut next_obs_s) = (0_u32, 1_u64);
    let mut rng = p.seed;
    let (mut held_ppb, mut held_since_us) = (0_i64, 0_u64);
    let (mut rejoin_seen, mut epoch) = (false, 0_u32);
    let (mut held_ratio_after_reset, mut reset_at_us) = (None, None::<u64>);

    for blk in 1..=blocks {
        let t_us = blk * BLOCK * 1_000_000 / RATE_HZ;
        let produced = source_frames_at(t_us, p.drift_ppb);
        queue += produced - produced_prev;
        produced_prev = produced;

        while next_obs_s * 1_000_000 <= t_us {
            let t_obs = next_obs_s * 1_000_000;
            let mut pos = p.pos0 + source_frames_at(t_obs, p.drift_ppb);
            if let Some((at_s, frames)) = p.jump
                && next_obs_s >= at_s
            {
                pos += frames; // the source's counter jumps; the audio it delivers does not
            }
            let jitter = i64::from(lcg(&mut rng) % u32::try_from(2 * p.jitter_us + 1).unwrap())
                - p.jitter_us;
            let local = u64::try_from(i64::try_from(BASE_US + t_obs).unwrap() + jitter).unwrap();
            let obs = Observation {
                position: u32::try_from(pos & 0xFFFF_FFFF).unwrap(),
                local_us: local,
            };
            match est.observe(obs) {
                Ok(()) => {}
                Err(RateError::Discontinuity(reason)) => {
                    epoch += 1;
                    est.begin_epoch(epoch, ResetReason::Discontinuity(reason))
                        .unwrap();
                    rs.begin_epoch(epoch, DspReset::Discontinuity).unwrap();
                    reset_at_us = Some(t_us);
                }
                Err(other) => panic!("observation {next_obs_s}: {other}"),
            }
            next_obs_s += 1;
        }

        if p.controlled {
            if let Some(e) = est.estimate_at(BASE_US + t_us) {
                match e.status {
                    EstimateStatus::Valid | EstimateStatus::Clamped => {
                        held_ppb = e.correction_ppb;
                        held_since_us = t_us;
                    }
                    EstimateStatus::Noisy => {}
                    EstimateStatus::RejoinRequired => rejoin_seen = true,
                }
            }
            let rate_term = if t_us.saturating_sub(held_since_us) <= HOLD_US {
                held_ppb
            } else {
                0
            };
            rs.set_target_ppb(rate_term + trim.trim_ppb(queue));
        }
        if let (Some(r0), None) = (reset_at_us, held_ratio_after_reset)
            && t_us >= r0 + p.hold_check_after_s * 1_000_000
        {
            held_ratio_after_reset = Some(rs.ratio_ppb());
        }

        let need = rs.plan(BLOCK);
        if queue >= need {
            queue -= need;
        } else {
            underruns += 1;
            queue = 0;
        }
        max_dev = max_dev.max(queue.abs_diff(p.level_target));
    }
    let stats = rs.stats();
    Outcome {
        blocks,
        produced: produced_prev,
        queue_end: queue,
        max_deviation: max_dev,
        underruns,
        final_ratio_ppb: rs.ratio_ppb(),
        wraps: est.stats().wraps,
        discontinuities: est.stats().discontinuities,
        est_resets: est.stats().resets,
        rs_resets: stats.epoch_resets,
        outputs: stats.outputs,
        inputs: stats.inputs_pulled,
        rejoin_seen,
        est_epoch: est.epoch(),
        last_est_reset: est.reset_log().last().map(|r| r.reason),
        last_rs_reset: rs.last_reset().map(|r| r.reason),
        has_estimate_at_end: est.estimate().is_some(),
        held_ratio_after_reset,
    }
}

fn observe(id: &str, p: &Plan, o: &Outcome, bound: u64) {
    println!(
        "D03-OBSERVED {}",
        json!({"id": id, "kind": "closed_loop", "controlled": p.controlled, "max_deviation_frames": o.max_deviation,
               "bound_frames": bound, "underruns": o.underruns, "final_ratio_ppb": o.final_ratio_ppb,
               "drift_ppb": p.drift_ppb, "wraps": o.wraps, "outputs": o.outputs, "inputs_pulled": o.inputs,
               "estimator_discontinuities": o.discontinuities, "resets": o.est_resets,
               "virtual_seconds": p.seconds})
    );
}

/// The checks every steady loop must meet.
fn check_steady(case: &Value, p: &Plan, o: &Outcome) {
    let id = case["id"].as_str().unwrap();
    let bound = case["occupancy_bound_frames"].as_u64().unwrap();
    let tol = case["final_ratio_tolerance_ppb"].as_i64().unwrap();
    observe(id, p, o, bound);
    assert_eq!(
        o.outputs,
        case["expect_total_outputs"].as_u64().unwrap(),
        "{id}: output count is exact"
    );
    assert_eq!(o.outputs, o.blocks * BLOCK, "{id}");
    assert_eq!(o.underruns, 0, "{id}: playout underran");
    assert!(
        o.max_deviation <= bound,
        "{id}: queue moved {} frames from target (bound {bound})",
        o.max_deviation
    );
    assert!(
        (i64::from(o.final_ratio_ppb) - p.drift_ppb).abs() <= tol,
        "{id}: final ratio {} ppb vs drift {} ppb (tolerance {tol})",
        o.final_ratio_ppb,
        p.drift_ppb
    );
    assert_eq!(
        u64::from(o.wraps),
        case["expect_wraps"].as_u64().unwrap(),
        "{id}: timeline wraps absorbed"
    );
    assert_eq!(
        (o.discontinuities, o.est_resets, o.rs_resets),
        (0, 0, 0),
        "{id}: wrap or drift caused a reset"
    );
    assert!(
        !o.rejoin_seen,
        "{id}: estimator asked for a rejoin on a source within the correction range"
    );
    // conservation: what the resampler consumed is what was produced, less what is still queued
    assert_eq!(
        o.inputs + o.queue_end,
        o.produced + p.level_target,
        "{id}: frames not conserved"
    );
}

fn steady(id: &str) {
    let v = vectors();
    let case = v["closed_loop"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no vector {id}"));
    let p = plan_from(case, true);
    let o = run(&p);
    check_steady(case, &p, &o);
}

#[test]
fn d03_closed_loop_holds_the_queue_for_ten_minutes_fast_source() {
    steady("d03-loop-10min-pos");
}

#[test]
fn d03_closed_loop_holds_the_queue_for_ten_minutes_slow_source() {
    steady("d03-loop-10min-neg");
}

#[test]
fn d03_closed_loop_absorbs_the_u32_timeline_wrap() {
    steady("d03-loop-wrap-20min");
}

/// 25.5 virtual hours crosses the u32 frame-counter wrap near 24.86 h that a 24-hour run misses.
/// Run explicitly (the soak tier): `cargo test -p franken-speaker --test d03_closed_loop -- --ignored`.
#[test]
#[ignore = "25.5 virtual hours; run with --ignored (soak tier)"]
fn d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap() {
    steady("d03-loop-25h-soak");
}

#[test]
fn d03_without_the_loop_the_same_drift_overruns_the_bound() {
    // Negative control: the bound is not vacuous. With no correction at all the queue integrates the
    // whole rate mismatch.
    let v = vectors();
    let case = &v["closed_loop"][0];
    let bound = case["occupancy_bound_frames"].as_u64().unwrap();
    let p = plan_from(case, false);
    let o = run(&p);
    observe("d03-loop-uncontrolled", &p, &o, bound);
    assert!(
        o.max_deviation > 5 * bound,
        "uncontrolled drift moved only {} frames",
        o.max_deviation
    );
    assert_eq!(o.final_ratio_ppb, 0);
}

#[test]
fn d03_source_counter_jump_resets_only_source_local_history_at_an_explicit_epoch() {
    let v = vectors();
    let case = &v["closed_loop_jump"];
    let id = case["id"].as_str().unwrap();
    let p = plan_from(case, true);
    let o = run(&p);
    let bound = case["occupancy_bound_frames"].as_u64().unwrap();
    observe(id, &p, &o, bound);

    assert_eq!(
        o.discontinuities, 1,
        "{id}: exactly one rejected observation"
    );
    assert_eq!(
        (o.est_resets, o.rs_resets, o.est_epoch),
        (1, 1, 1),
        "{id}: one explicit epoch on each side"
    );
    let want = case["expect_reason"].as_str().unwrap();
    match o.last_est_reset {
        Some(ResetReason::Discontinuity(r)) => assert_eq!(r.code(), want, "{id}: recorded reason"),
        other => panic!("{id}: unexpected reset reason {other:?}"),
    }
    assert_eq!(DiscontinuityReason::ImplausibleRate.code(), want);
    assert_eq!(o.last_rs_reset, Some(DspReset::Discontinuity), "{id}");
    assert!(
        o.has_estimate_at_end,
        "{id}: the estimator re-established an estimate in the new epoch"
    );
    // the endpoint-local ratio was held, not dropped to zero, while the new epoch warmed up
    let held = o
        .held_ratio_after_reset
        .expect("a ratio sample after the reset");
    let tol = case["hold_ratio_tolerance_ppb"].as_i64().unwrap();
    assert!(
        (i64::from(held) - p.drift_ppb).abs() <= tol,
        "{id}: ratio {held} ppb {} s after the reset, drift {} ppb",
        p.hold_check_after_s,
        p.drift_ppb
    );
    // no gap in the output, no underrun, and the queue stayed inside the analytic bound
    assert_eq!(
        o.outputs,
        case["expect_total_outputs"].as_u64().unwrap(),
        "{id}"
    );
    assert_eq!(o.underruns, 0, "{id}");
    assert!(
        o.max_deviation <= bound,
        "{id}: queue moved {} frames (bound {bound})",
        o.max_deviation
    );
    assert_eq!(
        o.inputs + o.queue_end,
        o.produced + p.level_target,
        "{id}: frames not conserved"
    );
}

#[test]
fn d03_resampler_epochs_must_advance_in_the_glue_too() {
    let mut rs = DriftResampler::new(ResamplerConfig::default()).unwrap();
    rs.begin_epoch(1, DspReset::NewSource).unwrap();
    assert_eq!(
        rs.begin_epoch(1, DspReset::Discontinuity),
        Err(ResampleError::EpochNotAdvanced {
            current: 1,
            requested: 1
        })
    );
}
