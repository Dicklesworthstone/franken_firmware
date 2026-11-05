//! D03 resampler tests. Expected values come from `tests/d03/vectors.json` (written by the
//! independent Python reference) or from exact mathematical properties; none is produced by this
//! module's own arithmetic. Each test prints `D03-OBSERVED {json}` records that
//! `tests/d03/run_cases.py` re-checks against the reference.

use super::*;
use serde_json::{Value, json};
use std::f64::consts::PI;

const RATE: f64 = 48_000.0;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../tests/d03/vectors.json"))
        .expect("vectors.json parses")
}

fn cfg() -> ResamplerConfig {
    ResamplerConfig::default()
}

fn fresh() -> DriftResampler {
    DriftResampler::new(cfg()).expect("default config is valid")
}

fn at(ppb: i32) -> DriftResampler {
    DriftResampler::with_initial_ppb(cfg(), ppb).expect("ratio within the default limit")
}

fn i32_of(v: &Value) -> i32 {
    i32::try_from(v.as_i64().expect("integer")).expect("fits i32")
}

fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

/// An endless stereo noise source that counts what it hands out.
struct Noise {
    state: u32,
    pulled: u64,
}

impl Noise {
    fn new(seed: u32) -> Self {
        Self {
            state: seed,
            pulled: 0,
        }
    }

    fn sample(&mut self) -> f32 {
        ((lcg(&mut self.state) >> 8) as f32 / 16_777_216.0 - 0.5) * 1.8
    }
}

impl FrameSource for Noise {
    fn pull(&mut self) -> Option<[f32; 2]> {
        self.pulled += 1;
        let l = self.sample();
        let r = self.sample();
        Some([l, r])
    }
}

/// Render exactly `total` frames in blocks of the given sizes (cycled), asserting the source never runs dry.
fn render_all<S: FrameSource>(
    rs: &mut DriftResampler,
    src: &mut S,
    total: usize,
    sizes: &[usize],
) -> (Vec<f32>, Vec<f32>) {
    let mut l = vec![0.0_f32; total];
    let mut r = vec![0.0_f32; total];
    let (mut done, mut k) = (0_usize, 0_usize);
    while done < total {
        let take = sizes[k % sizes.len()]
            .min(total - done)
            .min(FRAMES_PER_BLOCK);
        k += 1;
        let rep = rs
            .render(src, &mut l[done..done + take], &mut r[done..done + take])
            .expect("render");
        assert_eq!(rep.produced, take, "source ran dry at {done}");
        done += take;
    }
    (l, r)
}

fn bits(v: &[f32]) -> Vec<u32> {
    v.iter().map(|x| x.to_bits()).collect()
}

#[test]
fn d03_params_match_contract() {
    let v = vectors();
    let p = &v["params"];
    assert_eq!(TAPS as u64, p["taps"].as_u64().unwrap());
    assert_eq!(
        LOOKAHEAD_FRAMES as u64,
        p["lookahead_frames"].as_u64().unwrap()
    );
    assert_eq!(u64::from(PRIME_FRAMES), p["prime_frames"].as_u64().unwrap());
    assert_eq!(
        u64::from(UPDATE_QUANTUM_FRAMES),
        p["update_quantum_frames"].as_u64().unwrap()
    );
    assert_eq!(u64::from(RAMP_FRAMES), p["ramp_frames"].as_u64().unwrap());
    assert_eq!(FRAMES_PER_BLOCK as u64, p["block_frames"].as_u64().unwrap());
    assert_eq!(
        u64::from(DEFAULT_MAX_RATIO_PPM),
        p["default_max_ratio_ppm"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(HARD_MAX_RATIO_PPM),
        p["hard_max_ratio_ppm"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(DEFAULT_MAX_SLEW_PPM_PER_BLOCK),
        p["default_slew_ppm_per_block"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(HARD_MAX_SLEW_PPM_PER_BLOCK),
        p["hard_max_slew_ppm_per_block"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(FLOAT_OPS_PER_OUTPUT_FRAME),
        p["float_ops_per_output_frame"].as_u64().unwrap()
    );
    assert_eq!(
        u64::from(RAMP_EXTRA_FLOAT_OPS),
        p["ramp_extra_float_ops"].as_u64().unwrap()
    );
    assert_eq!(
        i64::from(fresh().slew_ppb_per_quantum()),
        p["slew_ppb_per_quantum"].as_i64().unwrap()
    );
    assert_eq!(
        p["sample_rate_hz"].as_u64().unwrap(),
        u64::from(crate::CANONICAL_SAMPLE_RATE_HZ)
    );
}

#[test]
fn d03_tone_quality_matches_independent_reference() {
    let v = vectors();
    for t in v["tones"].as_array().expect("tones") {
        let id = t["id"].as_str().unwrap();
        let f0 = t["f0_hz"].as_f64().unwrap();
        let ppb = i32_of(&t["ppb"]);
        let n_out = usize::try_from(t["n_out"].as_u64().unwrap()).unwrap();
        let n_in = usize::try_from(t["expect_inputs_pulled"].as_u64().unwrap()).unwrap();
        let skip = usize::try_from(t["skip_ramp_frames"].as_u64().unwrap()).unwrap();

        let mut rs = at(ppb);
        assert_eq!(rs.step_q32(), t["step_q32"].as_u64().unwrap(), "{id}: step");
        let (w, phase) = (2.0 * PI * f0 / RATE, 0.25_f64);
        let input: Vec<f32> = (0..n_in)
            .map(|m| (0.5 * (w * m as f64 + phase).sin()) as f32)
            .collect();
        let mut src = SliceSource::new(&input, &input).unwrap();
        let (out_l, out_r) = render_all(&mut rs, &mut src, n_out, &[FRAMES_PER_BLOCK]);
        assert_eq!(src.consumed(), n_in, "{id}: input frames consumed");
        assert_eq!(
            bits(&out_l),
            bits(&out_r),
            "{id}: channels differ for identical input"
        );

        let s = rs.step_q32() as f64 / 4_294_967_296.0;
        let (mut sig, mut err) = (0.0_f64, 0.0_f64);
        for (i, &y) in out_l.iter().enumerate().skip(skip) {
            let ideal = 0.5 * (w * (i as f64 * s) + phase).sin();
            let e = f64::from(y) - ideal;
            sig += ideal * ideal;
            err += e * e;
        }
        let snr_db = 10.0 * (sig / err.max(1.0e-300)).log10();

        // Frequency by phase slope: demodulate each half at the expected frequency; the phase change
        // between halves is the frequency error times the half length. Each half is Hann-weighted:
        // without it the real sine's negative-frequency image leaks into the estimate and biases it by
        // about 1/(N sin w) radians per half (an ideal double-precision sine, with no resampler at
        // all, reads 0.0037 Hz off at 440 Hz unweighted and 1e-6 Hz weighted).
        let f_exp = t["expect_out_hz"].as_f64().unwrap();
        let w_exp = 2.0 * PI * f_exp / RATE;
        let half = (n_out - skip) / 2;
        let demod = |a: usize, b: usize| -> f64 {
            let (mut re, mut im) = (0.0_f64, 0.0_f64);
            let len = (b - a) as f64;
            for (i, &s) in out_l.iter().enumerate().take(b).skip(a) {
                let hann = 0.5 * (1.0 - (2.0 * PI * ((i - a) as f64 + 0.5) / len).cos());
                let ph = w_exp * i as f64;
                let x = hann * f64::from(s);
                re += x * ph.cos();
                im -= x * ph.sin();
            }
            im.atan2(re)
        };
        let mut dphi = demod(skip + half, skip + 2 * half) - demod(skip, skip + half);
        while dphi > PI {
            dphi -= 2.0 * PI;
        }
        while dphi <= -PI {
            dphi += 2.0 * PI;
        }
        let dev_hz = dphi / (2.0 * PI * half as f64) * RATE;

        let floor = t["snr_floor_db"].as_f64().unwrap();
        let tol = t["freq_tol_hz"].as_f64().unwrap();
        println!(
            "D03-OBSERVED {}",
            json!({"id": id, "kind": "tone", "snr_db": snr_db, "freq_dev_hz": dev_hz,
                   "consumed": src.consumed(), "produced": n_out})
        );
        assert!(
            snr_db >= floor,
            "{id}: SNR {snr_db:.2} dB below the reference floor {floor}"
        );
        assert!(
            dev_hz.abs() <= tol,
            "{id}: frequency off by {dev_hz} Hz (tolerance {tol})"
        );
    }
}

#[test]
fn d03_output_counts_from_inputs_match_closed_form() {
    let v = vectors();
    for c in v["outputs"].as_array().expect("outputs") {
        let ppb = i32_of(&c["ppb"]);
        let n_in = usize::try_from(c["n_in"].as_u64().unwrap()).unwrap();
        let want = usize::try_from(c["expect_outputs"].as_u64().unwrap()).unwrap();
        let input = vec![0.25_f32; n_in];
        let mut rs = at(ppb);
        let mut src = SliceSource::new(&input, &input).unwrap();
        let (mut l, mut r) = ([0.0_f32; FRAMES_PER_BLOCK], [0.0_f32; FRAMES_PER_BLOCK]);
        let mut produced = 0_usize;
        loop {
            let rep = rs.render(&mut src, &mut l, &mut r).unwrap();
            produced += rep.produced;
            if rep.underrun {
                break;
            }
        }
        assert_eq!(produced, want, "ppb={ppb} n_in={n_in}");
        assert_eq!(
            src.consumed(),
            n_in,
            "ppb={ppb} n_in={n_in}: every input frame is taken before the underrun"
        );
    }
}

#[test]
fn d03_input_counts_for_outputs_match_closed_form() {
    let v = vectors();
    let mut longest = 0_u64;
    let mut reported = (0_i32, 0_u64, 0_u64);
    for c in v["pulled"].as_array().expect("pulled") {
        let ppb = i32_of(&c["ppb"]);
        let n_out = c["n_out"].as_u64().unwrap();
        let want = c["expect_inputs_pulled"].as_u64().unwrap();
        assert_eq!(at(ppb).plan(n_out), want, "plan ppb={ppb} n_out={n_out}");
        if n_out <= 4097 {
            let mut rs = at(ppb);
            let mut src = Noise::new(3);
            render_all(
                &mut rs,
                &mut src,
                usize::try_from(n_out).unwrap(),
                &[FRAMES_PER_BLOCK],
            );
            assert_eq!(src.pulled, want, "render ppb={ppb} n_out={n_out}");
        }
        if n_out >= longest {
            longest = n_out;
            reported = (ppb, n_out, want);
        }
    }
    assert_eq!(
        longest, 4_147_200_000,
        "the 24-hour case is part of the vectors"
    );
    println!(
        "D03-OBSERVED {}",
        json!({"id": "d03-pulled-longest", "kind": "count", "ppb": reported.0, "n_out": reported.1,
               "pulled": reported.2})
    );
}

#[test]
fn d03_slew_schedule_matches_per_quantum() {
    let v = vectors();
    for s in v["schedules"].as_array().expect("schedules") {
        let id = s["id"].as_str().unwrap();
        let mut rs = at(i32_of(&s["start_ppb"]));
        rs.set_target_ppb(s["target_ppb"].as_i64().unwrap());
        assert_eq!(
            i64::from(rs.slew_ppb_per_quantum()),
            s["slew_ppb_per_quantum"].as_i64().unwrap(),
            "{id}"
        );
        let mut src = Noise::new(1);
        let (mut l, mut r) = ([0.0_f32; 32], [0.0_f32; 32]);
        for (j, want) in s["schedule"].as_array().unwrap().iter().enumerate() {
            rs.render(&mut src, &mut l, &mut r).unwrap();
            assert_eq!(rs.ratio_ppb(), i32_of(want), "{id}: quantum {j}");
        }
    }
}

#[test]
fn d03_slew_counts_and_convergence_match() {
    let v = vectors();
    for c in v["slew_counts"].as_array().expect("slew counts") {
        let start = i32_of(&c["start_ppb"]);
        let target = c["target_ppb"].as_i64().unwrap();
        let n_out = c["n_out"].as_u64().unwrap();
        let mut rs = at(start);
        rs.set_target_ppb(target);
        assert_eq!(
            rs.plan(n_out),
            c["expect_inputs_pulled"].as_u64().unwrap(),
            "{start}->{target} n={n_out}"
        );
        if i64::from(start) != target {
            let q = c["quanta_to_converge"].as_u64().unwrap();
            let settle = |outputs: u64| {
                let mut a = at(start);
                a.set_target_ppb(target);
                a.plan(outputs);
                i64::from(a.ratio_ppb())
            };
            assert_eq!(
                settle(32 * q + 1),
                target,
                "{start}->{target}: converged after {q} quanta"
            );
            assert_ne!(
                settle(32 * (q - 1) + 1),
                target,
                "{start}->{target}: not converged one quantum earlier"
            );
        }
    }
}

#[test]
fn d03_output_does_not_depend_on_block_splitting() {
    let events: [(usize, i64); 3] = [(0, 300_000), (5_000, -200_000), (9_000, 0)];
    let total = 12_000_usize;
    let run = |seed: u32| -> (Vec<u32>, Vec<u32>, PhaseState, ResamplerStats) {
        let mut rs = fresh();
        let mut src = Noise::new(11);
        let (mut l, mut r) = (vec![0.0_f32; total], vec![0.0_f32; total]);
        let (mut done, mut ev) = (0_usize, 0_usize);
        let mut rng = seed ^ 0x9E37_79B9;
        while done < total {
            while ev < events.len() && events[ev].0 == done {
                rs.set_target_ppb(events[ev].1);
                ev += 1;
            }
            rs.render(&mut src, &mut [], &mut []).unwrap(); // a zero-length call between every block
            let room = events.get(ev).map_or(total, |e| e.0) - done;
            let take = if seed == 0 {
                room.min(FRAMES_PER_BLOCK)
            } else {
                (1 + (lcg(&mut rng) >> 16) as usize % FRAMES_PER_BLOCK).min(room)
            };
            let rep = rs
                .render(
                    &mut src,
                    &mut l[done..done + take],
                    &mut r[done..done + take],
                )
                .unwrap();
            assert_eq!(rep.produced, take);
            done += take;
        }
        (bits(&l), bits(&r), rs.phase_state(), rs.stats())
    };
    let baseline = run(0);
    for seed in 1..=8 {
        assert!(
            run(seed) == baseline,
            "split seed {seed} changed the output, state or counters"
        );
    }
    println!(
        "D03-OBSERVED {}",
        json!({"id": "d03-split-invariance", "kind": "split", "outputs": total, "splits_compared": 8})
    );
}

#[test]
fn d03_history_is_carried_across_short_blocks_exactly() {
    // Catmull-Rom reproduces a linear signal exactly, so a ramp is an independent oracle: if any
    // block boundary dropped the history, the first output after it would be visibly wrong.
    let n_out = 20_000_usize;
    let mut rs = at(137_000);
    let n_in = (n_out as f64 * (1.0 + 137.0e-6)) as usize + 8;
    let input: Vec<f32> = (0..n_in).map(|m| m as f32 / 65_536.0).collect();
    let mut src = SliceSource::new(&input, &input).unwrap();
    let (l, _) = render_all(&mut rs, &mut src, n_out, &[7, 1, 5, 13, 64, 3, 256, 2]);
    let s = rs.step_q32() as f64 / 4_294_967_296.0;
    let mut worst = 0.0_f64;
    for (i, &y) in l.iter().enumerate() {
        let gain = if i < RAMP_FRAMES as usize {
            i as f64 / f64::from(RAMP_FRAMES)
        } else {
            1.0
        };
        let want = (i as f64 * s) / 65_536.0 * gain;
        worst = worst.max((f64::from(y) - want).abs());
    }
    println!(
        "D03-OBSERVED {}",
        json!({"id": "d03-history-ramp", "kind": "history", "max_abs_error": worst})
    );
    assert!(
        worst < 2.0e-6,
        "worst deviation from the exact linear ramp: {worst}"
    );
}

#[test]
fn d03_zero_length_blocks_change_nothing() {
    let mut rs = fresh();
    let mut src = Noise::new(2);
    render_all(&mut rs, &mut src, 100, &[100]);
    let (state, stats, pulled) = (rs.phase_state(), rs.stats(), src.pulled);
    let rep = rs.render(&mut src, &mut [], &mut []).unwrap();
    assert_eq!((rep.produced, rep.pulled, rep.underrun), (0, 0, false));
    assert_eq!(
        (rs.phase_state(), rs.stats(), src.pulled),
        (state, stats, pulled)
    );
    assert_eq!(rs.plan(0), 0);
    assert_eq!(rs.phase_state(), state);
}

#[test]
fn d03_underrun_resumes_exactly() {
    let w = 2.0 * PI * 700.0 / RATE;
    let input: Vec<f32> = (0..2_000)
        .map(|m| (0.5 * (w * f64::from(m)).sin()) as f32)
        .collect();
    let total = 1_000_usize;
    let mut baseline_rs = fresh();
    let mut whole = SliceSource::new(&input, &input).unwrap();
    let (base_l, base_r) = render_all(&mut baseline_rs, &mut whole, total, &[FRAMES_PER_BLOCK]);

    let mut rs = fresh();
    let (mut l, mut r) = (vec![0.0_f32; total], vec![0.0_f32; total]);
    let mut done = 0_usize;
    let mut first = SliceSource::new(&input[..50], &input[..50]).unwrap();
    loop {
        let take = (total - done).min(FRAMES_PER_BLOCK);
        let rep = rs
            .render(
                &mut first,
                &mut l[done..done + take],
                &mut r[done..done + take],
            )
            .unwrap();
        done += rep.produced;
        if rep.underrun || done == total {
            break;
        }
    }
    assert!(
        done > 0 && done < total,
        "the first source must run dry part-way: {done}"
    );
    assert_eq!(rs.stats().underruns, 1);
    let mut second = SliceSource::new(&input[50..], &input[50..]).unwrap();
    while done < total {
        let take = (total - done).min(FRAMES_PER_BLOCK);
        let rep = rs
            .render(
                &mut second,
                &mut l[done..done + take],
                &mut r[done..done + take],
            )
            .unwrap();
        assert!(!rep.underrun);
        done += rep.produced;
    }
    assert_eq!(
        bits(&l),
        bits(&base_l),
        "resumed left channel differs from the uninterrupted run"
    );
    assert_eq!(bits(&r), bits(&base_r));
}

#[test]
fn d03_non_finite_and_out_of_range_input_is_contained() {
    let mut left = vec![0.25_f32; 64];
    let right = vec![0.25_f32; 64];
    for (i, bad) in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 5.0, -7.0]
        .into_iter()
        .enumerate()
    {
        left[i + 1] = bad;
    }
    let mut rs = fresh();
    let mut src = SliceSource::new(&left, &right).unwrap();
    let (l, r) = render_all(&mut rs, &mut src, 30, &[10]);
    for y in l.iter().chain(r.iter()) {
        assert!(y.is_finite() && (-1.0..=1.0).contains(y), "bad output {y}");
    }
    assert_eq!(rs.stats().sanitized_inputs, 5);
}

#[test]
fn d03_output_is_clamped_and_counted() {
    // A -1,1,1,-1 pattern makes the cubic overshoot to 1.25 at the midpoint.
    let pattern = [-1.0_f32, 1.0, 1.0, -1.0];
    let n_out = 6_000_usize;
    let input: Vec<f32> = (0..n_out + 16).map(|m| pattern[m % 4]).collect();
    let mut rs = at(500_000);
    let mut src = SliceSource::new(&input, &input).unwrap();
    let (l, _) = render_all(&mut rs, &mut src, n_out, &[FRAMES_PER_BLOCK]);
    assert!(l.iter().all(|y| (-1.0..=1.0).contains(y)));
    assert!(
        rs.stats().clamped_outputs > 0,
        "the overshoot was not limited or not counted"
    );

    let ones = vec![1.0_f32; 2_000];
    let mut rs = at(-500_000);
    let mut src = SliceSource::new(&ones, &ones).unwrap();
    let (l, _) = render_all(&mut rs, &mut src, 1_500, &[FRAMES_PER_BLOCK]);
    assert!(
        l.iter().all(|&y| y <= 1.0),
        "DC at full scale must not exceed full scale"
    );
    assert!(l.iter().skip(64).all(|&y| y > 0.999_9));
}

#[test]
fn d03_epoch_reset_clears_history_and_keeps_ratio() {
    let mut a = fresh();
    let mut s1 = Noise::new(1);
    render_all(&mut a, &mut s1, 300, &[100, 100, 100]);
    let record = a.begin_epoch(1, ResetReason::NewSource).unwrap();
    assert_eq!(
        record,
        ResetRecord {
            from_epoch: 0,
            to_epoch: 1,
            reason: ResetReason::NewSource,
            at_output: 300
        }
    );
    assert_eq!(
        (a.epoch(), a.last_reset(), a.stats().epoch_resets),
        (1, Some(record), 1)
    );
    let mut s2 = Noise::new(2);
    let (xl, xr) = render_all(&mut a, &mut s2, 200, &[64]);
    let mut b = fresh();
    let mut s3 = Noise::new(2);
    let (yl, yr) = render_all(&mut b, &mut s3, 200, &[64]);
    assert_eq!(
        (bits(&xl), bits(&xr)),
        (bits(&yl), bits(&yr)),
        "a reset must equal a fresh start"
    );

    // the endpoint-local ratio (and the counters) survive a source reset
    let mut c = at(100_000);
    c.set_target_ppb(-50_000);
    let mut s4 = Noise::new(4);
    render_all(&mut c, &mut s4, 100, &[100]);
    let (ratio, target, outputs) = (c.ratio_ppb(), c.target_ppb(), c.stats().outputs);
    c.begin_epoch(7, ResetReason::Discontinuity).unwrap();
    assert_eq!(
        (c.ratio_ppb(), c.target_ppb(), c.stats().outputs),
        (ratio, target, outputs)
    );
    assert_eq!(
        c.last_reset()
            .map(|r| (r.from_epoch, r.to_epoch, r.reason.code())),
        Some((0, 7, "Discontinuity"))
    );
}

#[test]
fn d03_epochs_must_advance() {
    let mut rs = fresh();
    assert_eq!(
        rs.begin_epoch(0, ResetReason::NewSource),
        Err(ResampleError::EpochNotAdvanced {
            current: 0,
            requested: 0
        })
    );
    rs.begin_epoch(1, ResetReason::NewSource).unwrap();
    assert!(rs.begin_epoch(1, ResetReason::Rejoin).is_err());
    assert!(
        rs.begin_epoch(u32::MAX, ResetReason::Rejoin).is_err(),
        "behind in wrapping order"
    );
    rs.begin_epoch(2, ResetReason::Rejoin).unwrap();
    assert_eq!(rs.stats().epoch_resets, 2);
    assert_eq!(rs.last_reset().map(|r| r.reason), Some(ResetReason::Rejoin));
}

#[test]
fn d03_fade_in_follows_start_and_reset() {
    let input: Vec<f32> = (0..400).map(|m| m as f32 / 65_536.0).collect();
    let check = |rs: &mut DriftResampler| {
        let mut src = SliceSource::new(&input, &input).unwrap();
        let (l, _) = render_all(rs, &mut src, 100, &[100]);
        for (i, &y) in l.iter().enumerate() {
            let gain = if i < RAMP_FRAMES as usize {
                i as f64 / f64::from(RAMP_FRAMES)
            } else {
                1.0
            };
            let want = i as f64 / 65_536.0 * gain;
            assert!(
                (f64::from(y) - want).abs() < 1.0e-7,
                "frame {i}: {y} vs {want}"
            );
        }
        assert_eq!(l[0], 0.0);
    };
    let mut rs = fresh();
    check(&mut rs);
    rs.begin_epoch(1, ResetReason::NewSource).unwrap();
    check(&mut rs);
}

#[test]
fn d03_ratio_target_is_clamped_to_the_limit() {
    let mut rs = fresh();
    assert_eq!(rs.set_target_ppb(900_000), 500_000);
    assert_eq!(rs.set_target_ppb(-900_000), -500_000);
    assert_eq!(rs.set_target_ppb(i64::MAX), 500_000);
    assert_eq!(rs.set_target_ppb(i64::MIN), -500_000);
    assert_eq!(rs.stats().target_clamps, 4);
    assert_eq!(rs.set_target_ppb(250_000), 250_000);
    assert_eq!(
        rs.stats().target_clamps,
        4,
        "an in-range target is not a clamp"
    );
    assert_eq!(rs.set_target_ppm(700), 500);
    assert_eq!(rs.set_target_ppm(-120), -120);
    let wide = DriftResampler::new(ResamplerConfig {
        max_ratio_ppm: 5_000,
        max_slew_ppm_per_block: 10,
    })
    .unwrap();
    assert_eq!(wide.slew_ppb_per_quantum(), 1_250);
    let mut wide = wide;
    assert_eq!(wide.set_target_ppm(4_000), 4_000);
    // slewing toward a clamped target settles exactly at the limit and never passes it
    let mut src = Noise::new(9);
    let (mut ol, mut or_) = ([0.0_f32; FRAMES_PER_BLOCK], [0.0_f32; FRAMES_PER_BLOCK]);
    for (target, outputs) in [(i64::MAX, 70_000_usize), (i64::MIN, 140_000)] {
        rs.set_target_ppb(target);
        for _ in 0..outputs / FRAMES_PER_BLOCK {
            rs.render(&mut src, &mut ol, &mut or_).unwrap();
            assert!(
                rs.ratio_ppb().abs() <= 500_000,
                "ratio {} passed the limit",
                rs.ratio_ppb()
            );
        }
        let want = if target > 0 { 500_000 } else { -500_000 };
        assert_eq!(
            rs.ratio_ppb(),
            want,
            "did not settle at the limit for target {target}"
        );
    }
}

#[test]
fn d03_config_is_validated() {
    for (ratio, slew) in [(10_001, 2), (500, 0), (500, 51), (u32::MAX, 2)] {
        assert!(
            matches!(
                DriftResampler::new(ResamplerConfig {
                    max_ratio_ppm: ratio,
                    max_slew_ppm_per_block: slew
                }),
                Err(ResampleError::InvalidConfig(_))
            ),
            "{ratio}/{slew}"
        );
    }
    assert!(
        DriftResampler::new(ResamplerConfig {
            max_ratio_ppm: 0,
            max_slew_ppm_per_block: 1
        })
        .is_ok()
    );
    assert!(
        DriftResampler::new(ResamplerConfig {
            max_ratio_ppm: 10_000,
            max_slew_ppm_per_block: 50
        })
        .is_ok()
    );
    assert!(DriftResampler::with_initial_ppb(cfg(), 500_001).is_err());
    assert!(DriftResampler::with_initial_ppb(cfg(), -500_001).is_err());
    assert!(DriftResampler::with_initial_ppb(cfg(), 500_000).is_ok());
}

#[test]
fn d03_slew_is_bounded_under_random_targets() {
    let mut rs = fresh();
    let mut src = Noise::new(5);
    let mut rng = 12_345_u32;
    let (mut ol, mut or_) = ([0.0_f32; 1], [0.0_f32; 1]);
    let mut ratios = Vec::with_capacity(12_000);
    for i in 0..12_000 {
        if i % 700 == 0 {
            let target = i64::from(lcg(&mut rng) >> 8) % 1_000_001 - 500_000;
            rs.set_target_ppb(target);
        }
        rs.render(&mut src, &mut ol, &mut or_).unwrap();
        ratios.push(rs.ratio_ppb());
    }
    let per_block = 2_000; // 2 ppm per 256 output frames
    let mut worst = 0;
    for i in 0..ratios.len() - 256 {
        worst = worst.max((ratios[i + 256] - ratios[i]).abs());
    }
    println!(
        "D03-OBSERVED {}",
        json!({"id": "d03-slew-bound", "kind": "slew", "max_change_per_256_ppb": worst,
               "max_step_ppb": rs.stats().max_ratio_step_ppb})
    );
    assert!(
        worst <= per_block,
        "ratio moved {worst} ppb within 256 output frames"
    );
    assert!(rs.stats().max_ratio_step_ppb <= 250);
    assert!(ratios.iter().all(|r| r.abs() <= 500_000));
}

#[test]
fn d03_plan_equals_render() {
    let mut rng = 99_u32;
    let (mut a, mut b) = (fresh(), fresh());
    let mut src = Noise::new(8);
    // Run lengths around the 32-frame update quantum and the 256-frame block, for steps that begin
    // already converged: that is the branch of `plan` that skips whole quanta in closed form.
    let edges = [0_usize, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257, 4_000];
    let (mut converged_steps, mut slewing_steps) = (0, 0);
    for step in 0..400 {
        let random_target = i64::from(lcg(&mut rng) >> 8) % 1_000_001 - 500_000;
        let random_n = (lcg(&mut rng) >> 8) as usize % 2_500;
        let edge_n = edges[(lcg(&mut rng) >> 8) as usize % edges.len()];
        let converged_start = step % 5 == 0;
        let (target, n) = if converged_start {
            (i64::from(a.ratio_ppb()), edge_n)
        } else {
            (random_target, random_n)
        };
        if converged_start {
            converged_steps += 1;
        } else {
            slewing_steps += 1;
        }
        a.set_target_ppb(target);
        b.set_target_ppb(target);
        let before = src.pulled;
        render_all(&mut a, &mut src, n, &[FRAMES_PER_BLOCK]);
        let rendered = src.pulled - before;
        assert_eq!(b.plan(n as u64), rendered, "step {step}: frames consumed");
        assert_eq!(a.phase_state(), b.phase_state(), "step {step}");
        let (sa, sb) = (a.stats(), b.stats());
        assert_eq!(
            (sa.outputs, sa.inputs_pulled, sa.float_ops),
            (sb.outputs, sb.inputs_pulled, sb.float_ops),
            "step {step}"
        );
        assert_eq!(sa.max_ratio_step_ppb, sb.max_ratio_step_ppb, "step {step}");
    }
    assert_eq!((converged_steps, slewing_steps), (80, 320));
}

#[test]
fn d03_operation_counts_are_accounted() {
    let v = vectors();
    let per = v["params"]["float_ops_per_output_frame"].as_u64().unwrap();
    let ramp = v["params"]["ramp_extra_float_ops"].as_u64().unwrap();
    let mut rs = fresh();
    let mut src = Noise::new(6);
    render_all(&mut rs, &mut src, 1_000, &[FRAMES_PER_BLOCK]);
    assert_eq!(
        rs.stats().float_ops,
        1_000 * per + u64::from(RAMP_FRAMES) * ramp
    );
    rs.begin_epoch(1, ResetReason::NewSource).unwrap();
    render_all(&mut rs, &mut src, 100, &[FRAMES_PER_BLOCK]);
    assert_eq!(
        rs.stats().float_ops,
        1_100 * per + 2 * u64::from(RAMP_FRAMES) * ramp
    );
    let block_ops = 256 * per;
    println!(
        "D03-OBSERVED {}",
        json!({"id": "d03-ops", "kind": "ops", "float_ops_per_output_frame": per, "float_ops_per_256_block": block_ops,
               "lookahead_frames": LOOKAHEAD_FRAMES, "cpu_on_target": "not measured: needs BE guest or hardware"})
    );
}

#[test]
fn d03_level_trim_is_proportional_and_bounded() {
    let t = LevelTrim {
        target_frames: 2_400,
        gain_ppb_per_frame: 100,
        limit_ppb: 100_000,
    };
    assert_eq!(t.trim_ppb(2_400), 0);
    assert_eq!(t.trim_ppb(2_500), 10_000);
    assert_eq!(t.trim_ppb(2_300), -10_000);
    assert_eq!(t.trim_ppb(10_000), 100_000);
    assert_eq!(t.trim_ppb(0), -100_000);
    assert_eq!(t.trim_ppb(u64::MAX), 100_000);
    let odd = LevelTrim {
        limit_ppb: -50_000,
        ..t
    };
    assert_eq!(
        odd.trim_ppb(10_000),
        50_000,
        "a negative limit is treated by magnitude, never a panic"
    );
}

#[test]
fn d03_oversize_and_mismatched_blocks_are_refused() {
    let mut rs = fresh();
    let mut src = Noise::new(1);
    let state = rs.phase_state();
    let (mut big_l, mut big_r) = (
        vec![0.0_f32; FRAMES_PER_BLOCK + 1],
        vec![0.0_f32; FRAMES_PER_BLOCK + 1],
    );
    assert_eq!(
        rs.render(&mut src, &mut big_l, &mut big_r),
        Err(ResampleError::BlockTooLong {
            frames: FRAMES_PER_BLOCK + 1,
            max: FRAMES_PER_BLOCK
        })
    );
    let (mut a, mut b) = ([0.0_f32; 4], [0.0_f32; 3]);
    assert_eq!(
        rs.render(&mut src, &mut a, &mut b),
        Err(ResampleError::ChannelLengthMismatch { left: 4, right: 3 })
    );
    assert_eq!(
        (rs.phase_state(), src.pulled),
        (state, 0),
        "a refused block must not change state"
    );
    assert!(SliceSource::new(&[0.0; 3], &[0.0; 2]).is_err());
}
