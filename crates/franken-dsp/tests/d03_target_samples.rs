//! The HOST half of D03's target-ISA quality check (bead ffw-j9r). The same source file the big-endian MIPS guest runs
//! (`toolchain/src/d03-target/src/cases.rs`, included below) renders the canonical quality cases here, and each
//! prints one `D03-TARGET-HOST {json}` record: a 64-bit digest of all samples, a digest per 1 024-sample chunk, and
//! the first eight samples. `toolchain/src/measure-d03-target.py` byte-compares the guest's digests with these. Equal
//! is the expected result; a difference is a finding about the target ISA's float behaviour, reported as such.
//!
//! The assertions below do not depend on the guest: they pin the shared case table to the declared quality vectors,
//! pin the shared tone generator to the analytic sine, pin the seed-to-phase derivation with known answers (the
//! judge reproduces it), and require the render to be deterministic and well-formed.

#[path = "../../../toolchain/src/d03-target/src/cases.rs"]
#[allow(dead_code)]
mod cases;

use cases::{AMP, CANONICAL, N_MEAS, N_OUT, SKIP, START_C, START_S, TONE_1K, TONE_10K, Tone};
use serde_json::{Value, json};
use std::f64::consts::PI;

const RATE: f64 = 48_000.0;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../tests/d03/vectors.json"))
        .expect("vectors.json parses")
}

fn quality_case(id: &str) -> Value {
    vectors()["quality"]["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("no quality case {id} in tests/d03/vectors.json"))
}

#[test]
fn d03_target_cases_are_the_declared_quality_cases() {
    for case in &CANONICAL {
        let v = quality_case(case.id);
        assert_eq!(v["scenario"], "steady", "{}", case.id);
        assert_eq!(v["interp"], "catmull_rom", "{}", case.id);
        assert_eq!(
            v["f0_hz"].as_u64(),
            Some(u64::from(case.tone.hz)),
            "{}",
            case.id
        );
        assert_eq!(v["ppb"].as_i64(), Some(i64::from(case.ppb)), "{}", case.id);
        assert_eq!(v["n_out"].as_u64(), Some(N_OUT as u64), "{}", case.id);
        assert_eq!(v["skip"].as_u64(), Some(SKIP as u64), "{}", case.id);
        assert_eq!(v["n_meas"].as_u64(), Some(N_MEAS as u64), "{}", case.id);
        assert_eq!(v["must_pass"], true, "{}", case.id);
    }
    let q = vectors()["quality"].clone();
    assert_eq!(q["n_meas"].as_u64(), Some(N_MEAS as u64));
    assert_eq!(q["skip"].as_u64(), Some(SKIP as u64));
    assert_eq!(q["phase"].as_f64(), Some(0.25));
}

fn assert_tone_constants(tone: &Tone) {
    let w = 2.0 * PI * f64::from(tone.hz) / RATE;
    assert!((tone.cos_w - w.cos()).abs() < 5.0e-16, "{} Hz cos", tone.hz);
    assert!((tone.sin_w - w.sin()).abs() < 5.0e-16, "{} Hz sin", tone.hz);
}

#[test]
fn d03_target_tone_generator_is_the_analytic_sine() {
    assert!(
        (AMP - 10.0_f64.powf(-1.0 / 20.0)).abs() < 5.0e-16,
        "amplitude"
    );
    assert!(
        (START_S - AMP * 0.25_f64.sin()).abs() < 5.0e-16,
        "start sine"
    );
    assert!(
        (START_C - AMP * 0.25_f64.cos()).abs() < 5.0e-16,
        "start cosine"
    );
    for tone in [&TONE_1K, &TONE_10K] {
        assert_tone_constants(tone);
        let w = 2.0 * PI * f64::from(tone.hz) / RATE;
        let input = cases::tone_input(tone, START_S, START_C, N_OUT + cases::INPUT_MARGIN);
        assert_eq!(input.len(), N_OUT + cases::INPUT_MARGIN);
        let mut worst = 0.0_f64;
        for (m, &sample) in input.iter().enumerate() {
            let exact = AMP * (w * m as f64 + 0.25).sin();
            worst = worst.max((f64::from(sample) - exact).abs());
        }
        // one f32 ulp at 0.89 is 6e-8; the recurrence's own drift is ~1e-12
        assert!(
            worst < 1.2e-7,
            "{} Hz: input is {worst:e} from the exact sine",
            tone.hz
        );
    }
}

/// Known answers computed independently in Python (`tests/d03` judge side): the seed-to-phase derivation must agree
/// bit for bit, because the judge rejects a transcript whose echoed phase differs from its own derivation.
#[test]
fn d03_target_seed_derivation_matches_known_answers() {
    assert_eq!(
        cases::splitmix64(0),
        0xE220_A839_7B1D_CDAF,
        "SplitMix64's published first output for state 0"
    );
    let known: [(u64, u32, u64); 6] = [
        (0, 1000, 0x3C1E_BA8B_4DCC_C148),
        (0, 10_000, 0x8A83_B1E0_9394_E27C),
        (1, 1000, 0x533E_00F7_F3C6_06D4),
        (1, 10_000, 0x0264_4708_B8FF_D890),
        (0x0123_4567_89AB_CDEF, 1000, 0xFA1D_34AF_1999_A9DA),
        (0x0123_4567_89AB_CDEF, 10_000, 0x7EEB_79AD_1768_018F),
    ];
    for (seed, hz, expected) in known {
        assert_eq!(
            cases::splitmix64(seed ^ u64::from(hz)),
            expected,
            "seed {seed:#x}, {hz} Hz"
        );
        let phase = cases::seeded_phase(seed, hz);
        assert!(
            (0.0..2.0 * PI).contains(&phase),
            "phase {phase} out of range"
        );
    }
    // the phase differs between seeds and between tones: a replayed transcript cannot carry the right one
    assert_ne!(
        cases::seeded_phase(1, 1000).to_bits(),
        cases::seeded_phase(2, 1000).to_bits()
    );
    assert_ne!(
        cases::seeded_phase(1, 1000).to_bits(),
        cases::seeded_phase(1, 10_000).to_bits()
    );
}

#[test]
fn d03_target_seeded_samples_depend_on_the_seed() {
    let (phase_a, a) = cases::seeded_samples(&TONE_1K, 7);
    let (phase_b, b) = cases::seeded_samples(&TONE_1K, 8);
    let (phase_a2, a2) = cases::seeded_samples(&TONE_1K, 7);
    assert_eq!(a, a2, "the same seed gives the same samples");
    assert_eq!(phase_a.to_bits(), phase_a2.to_bits());
    assert_ne!(phase_a.to_bits(), phase_b.to_bits());
    assert_eq!(a.len(), cases::SEEDED_FRAMES);
    let differing = a
        .iter()
        .zip(&b)
        .filter(|(x, y)| x.to_bits() != y.to_bits())
        .count();
    assert!(
        differing > cases::SEEDED_FRAMES / 2,
        "only {differing} samples differ between two seeds"
    );
}

#[test]
fn d03_target_canonical_samples_are_well_formed_and_digested() {
    for case in &CANONICAL {
        let samples = cases::canonical_samples(case);
        assert_eq!(samples.len(), N_OUT, "{}", case.id);
        assert!(
            samples.iter().all(|s| s.is_finite() && s.abs() <= 1.0),
            "{}: non-finite or out of range",
            case.id
        );
        let measured_peak = samples[SKIP..]
            .iter()
            .fold(0.0_f32, |acc, s| acc.max(s.abs()));
        assert!(
            measured_peak > 0.8 && measured_peak < 0.92,
            "{}: peak {measured_peak}",
            case.id
        );
        let again = cases::canonical_samples(case);
        assert_eq!(
            samples, again,
            "{}: the render is not deterministic",
            case.id
        );
        let lines = cases::hex_lines(&samples);
        assert_eq!(
            lines.len(),
            N_OUT.div_ceil(cases::SAMPLES_PER_LINE),
            "{}",
            case.id
        );
        assert!(
            lines
                .iter()
                .all(|l| l.len() % 8 == 0 && l.len() <= 8 * cases::SAMPLES_PER_LINE)
        );
        let head: Vec<String> = samples
            .iter()
            .take(8)
            .map(|s| format!("{:08x}", s.to_bits()))
            .collect();
        println!(
            "D03-TARGET-HOST {}",
            json!({"id": case.id, "hz": case.tone.hz, "ppb": case.ppb, "frames": samples.len(),
                   "fnv": format!("{:016x}", cases::fnv1a64(&samples)), "chunks": cases::chunk_digests(&samples),
                   "head": head.join("")})
        );
    }
}
