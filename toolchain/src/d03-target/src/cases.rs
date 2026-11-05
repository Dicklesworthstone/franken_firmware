//! The cases shared by the D03 target guest (`ffw-d03-target`, PID 1 on MIPS) and the host test
//! `crates/franken-dsp/tests/d03_target_samples.rs`, so that "the host build's samples" and "the guest's samples" come
//! from the same source text and differ only in the machine that ran it.
//!
//! No `unsafe` here: the host test includes this file under the workspace's `forbid(unsafe_code)`.
//!
//! The driven signal is a -1 dBFS sine produced by a complex-rotation recurrence (`s' = s cos w + c sin w`,
//! `c' = c cos w - s sin w`) whose constants are decimal literals computed once in Python. It uses only `+`, `-` and
//! `*` on `f64`, which IEEE 754 rounds identically on every machine, so the input is bit-identical on the host and
//! on the soft-float guest without either machine's `libm` being involved. It differs from an exact sine by a few
//! parts in 1e12 after 33 000 steps, far below the `f32` floor of the figure being measured.
//!
//! The one place `libm` is used is the SEEDED cases (`sin_cos` of a seed-derived phase). Those are judged by
//! `tests/d03`-style analytic comparison with a tolerance, never by byte equality, so a one-ulp `libm` difference
//! cannot matter there.

use franken_dsp::FRAMES_PER_BLOCK;
use franken_dsp::resample::{DriftResampler, ResamplerConfig, SliceSource};

/// -1 dBFS: 10^(-1/20), the shortest `f64` that round-trips.
pub const AMP: f64 = 0.891_250_938_133_745_6;
/// The canonical start state: `AMP * sin(0.25)` and `AMP * cos(0.25)`, the same phase as the host quality test.
pub const START_S: f64 = 0.220_499_010_783_596_54;
pub const START_C: f64 = 0.863_544_104_819_051_4;

/// Outputs skipped before the measured window (the 64-frame fade-in plus margin), as in `docs/contracts/d03.md` 4.1.
pub const SKIP: usize = 192;
/// Measured window of the declared bands.
pub const N_MEAS: usize = 32_768;
/// Outputs rendered per canonical case.
pub const N_OUT: usize = SKIP + N_MEAS;
/// Outputs per seeded case, and the ratio they run at.
pub const SEEDED_FRAMES: usize = 4_096;
pub const SEEDED_PPB: i32 = 137_000;
/// Samples per digest chunk, and per printed line.
pub const CHUNK: usize = 1_024;
pub const SAMPLES_PER_LINE: usize = 64;
/// Extra input frames generated beyond the outputs: the render pulls at most `n_out * (1 + 500e-6) + 3`.
pub const INPUT_MARGIN: usize = 64;

/// One tone: its frequency and the per-sample rotation `(cos w, sin w)`, `w = 2 pi hz / 48000`.
#[derive(Clone, Copy)]
pub struct Tone {
    pub hz: u32,
    pub cos_w: f64,
    pub sin_w: f64,
}

pub const TONE_1K: Tone = Tone {
    hz: 1_000,
    cos_w: 0.991_444_861_373_810_4,
    sin_w: 0.130_526_192_220_051_57,
};
pub const TONE_10K: Tone = Tone {
    hz: 10_000,
    cos_w: 0.258_819_045_102_520_74,
    sin_w: 0.965_925_826_289_068_3,
};

/// A canonical (seed-free) case: byte-compared against the host build and judged against the declared bands. The ids
/// are the host quality test's ids (`tests/d03/vectors.json`, `quality.cases`), the extremes of the shipped ratio
/// limit (+/-500 ppm).
pub struct Canonical {
    pub id: &'static str,
    pub tone: Tone,
    pub ppb: i32,
}

pub const CANONICAL: [Canonical; 4] = [
    Canonical {
        id: "q-steady-1000-p500",
        tone: TONE_1K,
        ppb: 500_000,
    },
    Canonical {
        id: "q-steady-1000-m500",
        tone: TONE_1K,
        ppb: -500_000,
    },
    Canonical {
        id: "q-steady-10000-p500",
        tone: TONE_10K,
        ppb: 500_000,
    },
    Canonical {
        id: "q-steady-10000-m500",
        tone: TONE_10K,
        ppb: -500_000,
    },
];

/// The seeded cases: one per tone, at a phase only the run's seed determines.
pub const SEEDED: [(&str, Tone); 2] = [("seed-1000", TONE_1K), ("seed-10000", TONE_10K)];

/// `n` samples of `tone` starting from the state `(s0, c0) = (A sin p, A cos p)`, rounded to `f32`.
pub fn tone_input(tone: &Tone, s0: f64, c0: f64, n: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(n);
    let (mut s, mut c) = (s0, c0);
    for _ in 0..n {
        out.push(s as f32);
        let next_s = s * tone.cos_w + c * tone.sin_w;
        let next_c = c * tone.cos_w - s * tone.sin_w;
        s = next_s;
        c = next_c;
    }
    out
}

/// The left channel of `n_out` outputs of the real [`DriftResampler`] at a constant `ppb`, fed `input` on both
/// channels in `FRAMES_PER_BLOCK` calls. Panics if the source runs dry or the channels differ.
pub fn render_left(ppb: i32, input: &[f32], n_out: usize) -> Vec<f32> {
    let mut rs = DriftResampler::with_initial_ppb(ResamplerConfig::default(), ppb)
        .expect("the ratio is within the default limit");
    let mut src = SliceSource::new(input, input).expect("equal channel lengths");
    let mut left = vec![0.0_f32; n_out];
    let mut right = vec![0.0_f32; n_out];
    let mut done = 0;
    while done < n_out {
        let take = FRAMES_PER_BLOCK.min(n_out - done);
        let report = rs
            .render(
                &mut src,
                &mut left[done..done + take],
                &mut right[done..done + take],
            )
            .expect("render");
        assert_eq!(report.produced, take, "the input ran dry at output {done}");
        done += take;
    }
    assert_eq!(left, right, "the channels differ for identical input");
    left
}

/// The `N_OUT` outputs of a canonical case.
pub fn canonical_samples(case: &Canonical) -> Vec<f32> {
    let input = tone_input(&case.tone, START_S, START_C, N_OUT + INPUT_MARGIN);
    render_left(case.ppb, &input, N_OUT)
}

/// SplitMix64's output for `state` (the state is advanced once, then mixed).
pub fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The start phase, in radians, of the seeded case for `seed` and `hz`: a pure function of two integers and four
/// IEEE operations, so the host judge reproduces its bits exactly.
pub fn seeded_phase(seed: u64, hz: u32) -> f64 {
    let x = splitmix64(seed ^ u64::from(hz));
    (x >> 11) as f64 / 9_007_199_254_740_992.0 * (2.0 * std::f64::consts::PI)
}

/// The phase used and the `SEEDED_FRAMES` outputs of a seeded case.
pub fn seeded_samples(tone: &Tone, seed: u64) -> (f64, Vec<f32>) {
    let phase = seeded_phase(seed, tone.hz);
    let (sin, cos) = phase.sin_cos();
    let input = tone_input(tone, AMP * sin, AMP * cos, SEEDED_FRAMES + INPUT_MARGIN);
    (phase, render_left(SEEDED_PPB, &input, SEEDED_FRAMES))
}

/// FNV-1a 64 over the big-endian bytes of each sample's `f32` bit pattern.
pub fn fnv1a64(samples: &[f32]) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for sample in samples {
        for byte in sample.to_bits().to_be_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    hash
}

/// The digest of each `CHUNK`-sample chunk, comma-separated lowercase hex (no spaces): a divergence is localised to
/// one chunk instead of reported as one bad hash.
pub fn chunk_digests(samples: &[f32]) -> String {
    samples
        .chunks(CHUNK)
        .map(|chunk| format!("{:016x}", fnv1a64(chunk)))
        .collect::<Vec<_>>()
        .join(",")
}

/// The samples as lines of `SAMPLES_PER_LINE` eight-digit big-endian hex words.
pub fn hex_lines(samples: &[f32]) -> Vec<String> {
    samples
        .chunks(SAMPLES_PER_LINE)
        .map(|line| {
            line.iter()
                .map(|sample| format!("{:08x}", sample.to_bits()))
                .collect::<String>()
        })
        .collect()
}
