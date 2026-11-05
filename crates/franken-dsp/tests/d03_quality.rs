//! D03 resampler quality (`docs/contracts/d03.md` section 4.1): a pure sine at -1 dBFS through `DriftResampler`,
//! measured as THD+N (Q) and carrier gain from the emitted `f32` samples alone, against bands that were declared
//! before this file existed. Expected figures come from `tests/d03/reference.py` through `tests/d03/vectors.json`
//! (a double-precision kernel at exact Q32 positions), never from this file's own arithmetic. Each case prints one
//! `D03-OBSERVED {json}` record that `tests/d03/run_cases.py` re-checks. If a figure misses its band, the test
//! fails and says so; no band is changed here.

use franken_dsp::FRAMES_PER_BLOCK;
use franken_dsp::resample::{DriftResampler, ResamplerConfig, ResetReason, SliceSource};
use serde_json::{Value, json};
use std::f64::consts::PI;

const RATE: f64 = 48_000.0;
const Q32: f64 = 4_294_967_296.0;
const AMP: f64 = 0.891_250_938_133_745_6; // 10^(-1/20): -1 dBFS
const RAMP: usize = 64;

/// The declared bands (docs/contracts/d03.md section 4.1): tone Hz, Q floor dB, gain low dB, gain high dB. They are
/// written here, in the reference and in the contract, so moving one takes three deliberate edits.
const BANDS: [(u64, f64, f64, f64); 2] = [(1000, 85.0, -0.01, 0.01), (10_000, 22.0, -0.60, 0.05)];

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../tests/d03/vectors.json"))
        .expect("vectors.json parses")
}

fn f64_of(v: &Value, key: &str) -> f64 {
    v[key]
        .as_f64()
        .unwrap_or_else(|| panic!("{key} is not a number in {v}"))
}

fn u64_of(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not an unsigned integer in {v}"))
}

fn usize_of(v: &Value, key: &str) -> usize {
    usize::try_from(u64_of(v, key)).expect("fits usize")
}

fn quality() -> Value {
    vectors()["quality"].clone()
}

fn cases_where(q: &Value, pick: impl Fn(&Value) -> bool) -> Vec<Value> {
    q["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|c| pick(c))
        .cloned()
        .collect()
}

/// The driven signal, rounded to `f32` the way the resampler is handed it.
fn tone(f0: f64, phase: f64, n: usize) -> Vec<f32> {
    let w = 2.0 * PI * f0 / RATE;
    (0..n)
        .map(|m| (AMP * (w * m as f64 + phase).sin()) as f32)
        .collect()
}

/// Render `n` frames through the real resampler in blocks of `FRAMES_PER_BLOCK`, left channel returned.
fn render(rs: &mut DriftResampler, input: &[f32], n: usize) -> Vec<f32> {
    let mut src = SliceSource::new(input, input).expect("equal channels");
    render_from(rs, &mut src, n)
}

fn render_from(rs: &mut DriftResampler, src: &mut SliceSource<'_>, n: usize) -> Vec<f32> {
    let mut l = vec![0.0_f32; n];
    let mut r = vec![0.0_f32; n];
    let mut done = 0;
    while done < n {
        let take = FRAMES_PER_BLOCK.min(n - done);
        let rep = rs
            .render(src, &mut l[done..done + take], &mut r[done..done + take])
            .expect("render");
        assert_eq!(rep.produced, take, "the source ran dry at {done}");
        done += take;
    }
    assert_eq!(l, r, "channels differ for identical input");
    l
}

fn tap(input: &[f32], k: i64) -> f32 {
    usize::try_from(k)
        .ok()
        .and_then(|k| input.get(k).copied())
        .unwrap_or(0.0)
}

/// The planted interpolators: the same input at the same exact Q32 positions as the real resampler's, with a wrong
/// kernel. `kind` is `linear` or `nearest`.
fn plant(kind: &str, input: &[f32], step_q32: u64, n_out: usize) -> Vec<f32> {
    (0..n_out)
        .map(|i| {
            let pos = (i as u64) * step_q32;
            let m = i64::try_from(pos >> 32).expect("position fits");
            let frac = (pos & 0xFFFF_FFFF) as u32;
            match kind {
                "linear" => {
                    let t = (frac >> 8) as f32 * (1.0 / 16_777_216.0);
                    tap(input, m) * (1.0 - t) + tap(input, m + 1) * t
                }
                "nearest" => tap(input, if frac >= 1 << 31 { m + 1 } else { m }),
                other => panic!("unknown planted interpolator {other}"),
            }
        })
        .collect()
}

struct Fit {
    q_db: f64,
    gain_db: f64,
}

/// Least-squares carrier `a cos(wn) + b sin(wn)` over `y`, Q = carrier power / residual power, gain against `amp`.
fn fit(y: &[f32], w: f64, amp: f64) -> Fit {
    let (mut scc, mut sss, mut scs, mut syc, mut sys) =
        (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
    for (i, &v) in y.iter().enumerate() {
        let (s, c) = (w * i as f64).sin_cos();
        let v = f64::from(v);
        scc += c * c;
        sss += s * s;
        scs += c * s;
        syc += v * c;
        sys += v * s;
    }
    let det = scc * sss - scs * scs;
    let a = (syc * sss - sys * scs) / det;
    let b = (sys * scc - syc * scs) / det;
    let mut resid = 0.0_f64;
    for (i, &v) in y.iter().enumerate() {
        let (s, c) = (w * i as f64).sin_cos();
        let e = f64::from(v) - a * c - b * s;
        resid += e * e;
    }
    let pf = (a * a + b * b) / 2.0;
    let pr = (resid / y.len() as f64).max(1.0e-300);
    Fit {
        q_db: 10.0 * (pf / pr).log10(),
        gain_db: 20.0 * ((a * a + b * b).sqrt() / amp).log10(),
    }
}

/// The measured window of a rendered case.
fn measure(case: &Value, y: &[f32]) -> Fit {
    let (skip, n_meas) = (usize_of(case, "skip"), usize_of(case, "n_meas"));
    let w = 2.0 * PI * f64_of(case, "f0_hz") / RATE * (u64_of(case, "step_q32") as f64) / Q32;
    fit(&y[skip..skip + n_meas], w, AMP)
}

/// Error against the ideal tone scaled by the fade-in, outputs 1..63 (the ramp region after an epoch reset).
fn ramp_snr_db(case: &Value, y: &[f32]) -> f64 {
    let f0 = f64_of(case, "f0_hz");
    let w0 = 2.0 * PI * f0 / RATE;
    let step = u64_of(case, "step_q32");
    let phase = f64_of(case, "phase_b");
    let (mut sig, mut err) = (0.0_f64, 0.0_f64);
    for (i, &v) in y.iter().enumerate().take(RAMP).skip(1) {
        let pos = ((i as u64) * step) as f64 / Q32;
        let ideal = AMP * (w0 * pos + phase).sin() * i as f64 / RAMP as f64;
        sig += ideal * ideal;
        err += (f64::from(v) - ideal).powi(2);
    }
    10.0 * (sig / err.max(1.0e-300)).log10()
}

/// What a case measures and prints.
struct Measured {
    q_db: f64,
    gain_db: Option<f64>,
}

fn run_real(case: &Value) -> Measured {
    let cfg = ResamplerConfig::default();
    let ppb = i32::try_from(case["ppb"].as_i64().expect("ppb")).expect("ppb fits");
    let f0 = f64_of(case, "f0_hz");
    let (n_out, n_in) = (usize_of(case, "n_out"), usize_of(case, "n_in"));
    match case["scenario"].as_str().expect("scenario") {
        "steady" => {
            let mut rs =
                DriftResampler::with_initial_ppb(cfg, ppb).expect("ratio within the limit");
            assert_eq!(rs.step_q32(), u64_of(case, "step_q32"), "step");
            let input = tone(f0, f64_of(&quality(), "phase"), n_in + 8);
            let y = render(&mut rs, &input, n_out);
            let m = measure(case, &y);
            Measured {
                q_db: m.q_db,
                gain_db: Some(m.gain_db),
            }
        }
        scenario @ ("epoch_ramp" | "epoch_steady") => {
            let mut rs =
                DriftResampler::with_initial_ppb(cfg, ppb).expect("ratio within the limit");
            assert_eq!(rs.step_q32(), u64_of(case, "step_q32"), "step");
            let a = tone(f0, f64_of(case, "phase_a"), usize_of(case, "n_in_a"));
            let mut src_a = SliceSource::new(&a, &a).expect("equal channels");
            let _ = render_from(&mut rs, &mut src_a, usize_of(case, "seg_a_out"));
            rs.begin_epoch(1, ResetReason::NewSource)
                .expect("the epoch advances");
            let b = tone(f0, f64_of(case, "phase_b"), n_in + 8);
            let y = render(&mut rs, &b, n_out);
            if scenario == "epoch_ramp" {
                Measured {
                    q_db: ramp_snr_db(case, &y),
                    gain_db: None,
                }
            } else {
                let m = measure(case, &y);
                Measured {
                    q_db: m.q_db,
                    gain_db: Some(m.gain_db),
                }
            }
        }
        "slewed" => {
            let mut rs = DriftResampler::new(cfg).expect("default configuration");
            let target = case["target_ppb"].as_i64().expect("target");
            rs.set_target_ppb(target);
            let input = tone(f0, f64_of(&quality(), "phase"), n_in + 8);
            let y = render(&mut rs, &input, n_out);
            assert_eq!(i64::from(rs.ratio_ppb()), target, "the slew had settled");
            let m = measure(case, &y);
            Measured {
                q_db: m.q_db,
                gain_db: Some(m.gain_db),
            }
        }
        other => panic!("unknown scenario {other}"),
    }
}

fn run_plant(case: &Value) -> Measured {
    let f0 = f64_of(case, "f0_hz");
    let (n_out, n_in) = (usize_of(case, "n_out"), usize_of(case, "n_in"));
    let input = tone(f0, f64_of(&quality(), "phase"), n_in + 8);
    let y = plant(
        case["interp"].as_str().expect("interp"),
        &input,
        u64_of(case, "step_q32"),
        n_out,
    );
    let m = measure(case, &y);
    Measured {
        q_db: m.q_db,
        gain_db: Some(m.gain_db),
    }
}

fn meets_band(case: &Value, m: &Measured) -> bool {
    let q_ok = m.q_db >= f64_of(case, "band_q_db");
    let gain_ok = m
        .gain_db
        .is_none_or(|g| g >= f64_of(case, "gain_lo_db") && g <= f64_of(case, "gain_hi_db"));
    q_ok && gain_ok
}

fn observe(case: &Value, m: &Measured) {
    println!(
        "D03-OBSERVED {}",
        json!({"id": case["id"], "kind": "quality", "interp": case["interp"], "scenario": case["scenario"],
               "f0_hz": case["f0_hz"], "ppb": case["ppb"], "q_db": m.q_db, "gain_db": m.gain_db,
               "band_q_db": case["band_q_db"], "gain_lo_db": case["gain_lo_db"], "gain_hi_db": case["gain_hi_db"],
               "meets_band": meets_band(case, m)})
    );
}

/// The figure agrees with the reference's first-principles prediction: within the stated tolerance, or, above the
/// `f32` floor, at least the floor (nothing above it is claimed).
fn agrees_with_reference(q: &Value, case: &Value, m: &Measured) {
    let id = case["id"].as_str().unwrap_or("?");
    let (cap, tol_q, tol_g) = (
        f64_of(q, "q_cap_db"),
        f64_of(q, "tol_q_db"),
        f64_of(q, "tol_gain_db"),
    );
    let expect_q = f64_of(case, "expect_q_db");
    if expect_q > cap {
        assert!(
            m.q_db >= cap,
            "{id}: Q {:.3} dB is below the f32 floor {cap}",
            m.q_db
        );
    } else {
        assert!(
            (m.q_db - expect_q).abs() <= tol_q,
            "{id}: Q {:.3} dB, reference {expect_q:.3} dB (tolerance {tol_q})",
            m.q_db
        );
    }
    if let (Some(g), Some(expect_g)) = (m.gain_db, case["expect_gain_db"].as_f64()) {
        assert!(
            (g - expect_g).abs() <= tol_g,
            "{id}: gain {g:.5} dB, reference {expect_g:.5} dB (tolerance {tol_g})"
        );
    }
}

fn assert_band_met(case: &Value, m: &Measured) {
    let id = case["id"].as_str().unwrap_or("?");
    assert!(
        m.q_db >= f64_of(case, "band_q_db"),
        "{id}: MISSED its declared Q band: {:.3} dB against a floor of {} dB (reported, not moved)",
        m.q_db,
        f64_of(case, "band_q_db")
    );
    if let Some(g) = m.gain_db {
        assert!(
            g >= f64_of(case, "gain_lo_db") && g <= f64_of(case, "gain_hi_db"),
            "{id}: MISSED its declared gain band: {g:.5} dB against {}..{} dB (reported, not moved)",
            f64_of(case, "gain_lo_db"),
            f64_of(case, "gain_hi_db")
        );
    }
}

#[test]
fn d03_quality_bands_are_the_declared_ones() {
    let q = quality();
    let bands = q["bands"].as_object().expect("bands");
    assert_eq!(bands.len(), BANDS.len());
    for (hz, floor, lo, hi) in BANDS {
        let b = &bands[&hz.to_string()];
        assert_eq!(f64_of(b, "q_floor_db"), floor, "{hz} Hz: Q floor");
        assert_eq!(f64_of(b, "gain_lo_db"), lo, "{hz} Hz: gain low");
        assert_eq!(f64_of(b, "gain_hi_db"), hi, "{hz} Hz: gain high");
    }
    assert_eq!(f64_of(&q, "amp_dbfs"), -1.0);
    assert_eq!(f64_of(&q, "phase"), 0.25);
    assert_eq!(u64_of(&q, "n_meas"), 32_768);
    assert_eq!(u64_of(&q, "skip"), 192);
    assert_eq!(f64_of(&q, "plant_q_margin_db"), 3.0);
    assert_eq!(f64_of(&q, "plant_gain_margin_db"), 0.1);
    for c in q["cases"].as_array().expect("cases") {
        let hz = u64_of(c, "f0_hz");
        let (_, floor, lo, hi) = BANDS
            .iter()
            .copied()
            .find(|b| b.0 == hz)
            .expect("a declared tone");
        assert_eq!(f64_of(c, "band_q_db"), floor, "{}", c["id"]);
        assert_eq!(f64_of(c, "gain_lo_db"), lo, "{}", c["id"]);
        assert_eq!(f64_of(c, "gain_hi_db"), hi, "{}", c["id"]);
    }
}

/// The instrument, checked on signals whose Q and gain are known exactly (integer cycles: the second harmonic is
/// orthogonal to the fundamental over the window).
#[test]
fn d03_quality_metric_reads_a_known_tone_and_a_known_error() {
    let n = 48 * 682; // whole cycles of 1/48 cycle per sample, and of its second harmonic
    let w = 2.0 * PI / 48.0;
    // 0.5 sin(wn + 0.3) plus a second harmonic 60 dB down: Q = 20 log10(0.5 / 0.0005) = 60 dB, gain 0 dB against 0.5.
    let y: Vec<f32> = (0..n)
        .map(|i| (0.5 * (w * i as f64 + 0.3).sin() + 0.0005 * (2.0 * w * i as f64).sin()) as f32)
        .collect();
    let f = fit(&y, w, 0.5);
    assert!((f.q_db - 60.0).abs() < 0.01, "Q {}", f.q_db);
    assert!(f.gain_db.abs() < 1.0e-4, "gain {}", f.gain_db);
    // A pure gain error is not distortion: 0.9 of the level reads 20 log10(0.9) dB of gain and a Q at the f32 floor.
    let y: Vec<f32> = (0..n)
        .map(|i| (0.45 * (w * i as f64 + 1.0).sin()) as f32)
        .collect();
    let f = fit(&y, w, 0.5);
    assert!(
        (f.gain_db - 20.0 * 0.9_f64.log10()).abs() < 1.0e-4,
        "gain {}",
        f.gain_db
    );
    assert!(f.q_db > 110.0, "Q {}", f.q_db);
    // And a frequency the fit does not know is mostly residual: the same tone read at a different frequency.
    let off = fit(&y, w * 1.01, 0.5);
    assert!(
        off.q_db < 30.0,
        "a wrong frequency must not read as clean: {}",
        off.q_db
    );
}

#[test]
fn d03_quality_steady_ratios_meet_the_declared_bands() {
    let q = quality();
    let cases = cases_where(&q, |c| {
        c["scenario"] == "steady" && c["interp"] == "catmull_rom"
    });
    assert_eq!(cases.len(), 10, "two tones at five ratios");
    for case in &cases {
        let m = run_real(case);
        observe(case, &m);
        agrees_with_reference(&q, case, &m);
        assert_band_met(case, &m);
    }
}

#[test]
fn d03_quality_after_an_epoch_reset_meets_the_declared_bands() {
    let q = quality();
    let cases = cases_where(&q, |c| {
        c["scenario"]
            .as_str()
            .is_some_and(|s| s.starts_with("epoch"))
    });
    assert_eq!(cases.len(), 4, "ramp and steady, two tones");
    for case in &cases {
        let m = run_real(case);
        observe(case, &m);
        agrees_with_reference(&q, case, &m);
        assert_band_met(case, &m);
    }
}

#[test]
fn d03_quality_settled_after_a_slew_meets_the_declared_bands() {
    let q = quality();
    let cases = cases_where(&q, |c| c["scenario"] == "slewed");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        let m = run_real(case);
        observe(case, &m);
        agrees_with_reference(&q, case, &m);
        assert_band_met(case, &m);
    }
}

/// The planted negatives: nearest-neighbour and linear interpolation, fed the same input at the same positions. Each
/// must miss its band on at least one figure, by a stated margin; and the real kernel at the same tone and ratio
/// must meet it, so the miss is the interpolator's and not the harness's.
#[test]
fn d03_quality_planted_nearest_and_linear_interpolators_miss_the_bands() {
    let q = quality();
    let (q_margin, g_margin) = (
        f64_of(&q, "plant_q_margin_db"),
        f64_of(&q, "plant_gain_margin_db"),
    );
    let plants = cases_where(&q, |c| c["interp"] != "catmull_rom" && c["control"] != true);
    assert_eq!(
        plants.len(),
        16,
        "two interpolators, two tones, four ratios"
    );
    for case in &plants {
        let id = case["id"].as_str().unwrap_or("?").to_string();
        let m = run_plant(case);
        observe(case, &m);
        agrees_with_reference(&q, case, &m);
        let q_miss = f64_of(case, "band_q_db") - m.q_db;
        let g = m.gain_db.expect("a plant has a gain");
        let g_miss = (f64_of(case, "gain_lo_db") - g).max(g - f64_of(case, "gain_hi_db"));
        assert!(
            q_miss >= q_margin || g_miss >= g_margin,
            "{id}: the planted interpolator does not clearly miss its band (Q short by {q_miss:.3} dB, gain out by {g_miss:.4} dB)"
        );
        // the pair: the real kernel at the same tone and ratio, through the same measuring code
        let real = steady_case(&q, case);
        let r = run_real(&real);
        assert!(
            meets_band(&real, &r),
            "{id}: the real kernel misses the band the plant is judged against"
        );
        println!(
            "D03-OBSERVED {}",
            json!({"id": format!("{id}-pair"), "kind": "quality_pair", "plant_id": id, "real_id": real["id"],
                   "plant_q_db": m.q_db, "real_q_db": r.q_db, "plant_gain_db": m.gain_db, "real_gain_db": r.gain_db})
        );
    }
}

/// The steady real-kernel case at the same tone and ratio as `like`.
fn steady_case(q: &Value, like: &Value) -> Value {
    cases_where(q, |c| {
        c["scenario"] == "steady"
            && c["interp"] == "catmull_rom"
            && c["f0_hz"] == like["f0_hz"]
            && c["ppb"] == like["ppb"]
    })
    .into_iter()
    .next()
    .unwrap_or_else(|| panic!("no steady case for {}", like["id"]))
}

/// At exactly zero ratio the fractional position is always 0, so nearest-neighbour and linear interpolation are as
/// exact as the real kernel: that row cannot tell interpolators apart, and this test says so by passing the plants.
#[test]
fn d03_quality_at_zero_ratio_every_interpolator_is_exact_so_that_row_is_not_an_interpolation_test()
{
    let q = quality();
    let controls = cases_where(&q, |c| c["control"] == true);
    assert_eq!(controls.len(), 4, "two interpolators, two tones");
    for case in &controls {
        let m = run_plant(case);
        observe(case, &m);
        agrees_with_reference(&q, case, &m);
        assert_band_met(case, &m);
        assert!(
            m.q_db >= f64_of(&q, "q_cap_db"),
            "{}: exact at zero ratio, so at the f32 floor",
            case["id"]
        );
    }
}
