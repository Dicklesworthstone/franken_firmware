//! `S02` / `ffw-6dh`: the 160/147 rate bridge against the independent Python reference.
//!
//! `tests/vectors/s02_bridge_vectors.json` is derived by `tests/s02/bridge_reference.py` from the closed form
//! `y[n] = round(sum_k C[n*147 mod 160][k] * x[floor(n*147/160) - k])`; the bridge under test advances those indices incrementally. The vectors
//! are exact integers (FNV-1a 64 over the big-endian `i32` output plus head and tail samples), so there is no tolerance in these comparisons.
//! The frequency-response and tone-quality judgement of the table lives in the Python judge (`bridge_reference.py --quality`), not here.
//!
//! Host simulation only: nothing here says how fast the bridge runs on a device.

use franken_codec::{
    BridgeStats, Q23_MAX, Q23_MIN, RateAdapter, RateBridge, RateError, RatePlan, f32_to_q23,
    outputs_after, plan_for_rate, q23_to_f32, q23_to_s16, s16_to_q23,
};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/s02_bridge_vectors.json");
const TAPS: usize = 64;

fn xorshift32(mut s: u32) -> u32 {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    s
}

fn tri(n: u64, period: u64, amp: i64) -> i64 {
    let t = (((4 * n) % (4 * period)) as i64 - 2 * period as i64).abs();
    (t * 2 * amp) / (2 * period as i64) - amp
}

/// The written source rule of `tests/s02/oracle.py::signal` at 16 bits.
fn signal16(frames: usize, seed_a: u32, seed_b: u32) -> Vec<(i32, i32)> {
    let (mut a, mut b) = (seed_a, seed_b);
    (0..frames)
        .map(|n| {
            a = xorshift32(a);
            b = xorshift32(b);
            let n = n as u64;
            let left = tri(n, 100, 6000) + tri(n, 37, 2000) + i64::from(a % 601) - 300;
            let right = tri(n, 91, 6000) + tri(n, 53, 2000) + i64::from(b % 601) - 300;
            (left as i32, right as i32)
        })
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn be_bytes(values: &[i32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn ints(value: &Value) -> Vec<i32> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| i32::try_from(v.as_i64().expect("an integer")).expect("fits i32"))
        .collect()
}

fn input_channels(spec: &Value) -> Vec<Vec<i32>> {
    let kind = spec["kind"].as_str().expect("kind");
    let frames = spec["frames"].as_u64().expect("frames") as usize;
    match kind {
        "tri" | "mono_tri" => {
            let pairs = signal16(
                frames,
                spec["seed_a"].as_u64().expect("seed_a") as u32,
                spec["seed_b"].as_u64().expect("seed_b") as u32,
            );
            let left: Vec<i32> = pairs.iter().map(|p| p.0 << 8).collect();
            let right: Vec<i32> = pairs.iter().map(|p| p.1 << 8).collect();
            if kind == "mono_tri" {
                vec![left]
            } else {
                vec![left, right]
            }
        }
        "dc" => {
            let v = spec["value"].as_i64().expect("value") as i32;
            vec![vec![v; frames]; 2]
        }
        "impulse" => {
            let mut x = vec![0i32; frames];
            x[spec["at"].as_u64().expect("at") as usize] =
                spec["amplitude"].as_i64().expect("amplitude") as i32;
            vec![x.clone(), x]
        }
        "square" => {
            let half = spec["half_period"].as_u64().expect("half_period") as usize;
            let amp = spec["amplitude"].as_i64().expect("amplitude") as i32;
            let x: Vec<i32> = (0..frames)
                .map(|n| {
                    if (n / half).is_multiple_of(2) {
                        amp
                    } else {
                        -amp
                    }
                })
                .collect();
            vec![x.clone(), x]
        }
        "silence" => vec![vec![0i32; frames]; 2],
        "explicit" => vec![ints(&spec["left"]), ints(&spec["right"])],
        other => panic!("unknown input kind {other}"),
    }
}

fn interleave(channels: &[Vec<i32>]) -> Vec<i32> {
    let frames = channels[0].len();
    (0..frames)
        .flat_map(|i| channels.iter().map(move |c| c[i]))
        .collect()
}

/// Run the bridge over `input` (interleaved) in chunks of `chunk_frames`, optionally flushing; returns the output and the counters.
fn run(
    channels: usize,
    input: &[i32],
    chunk_frames: usize,
    flush: bool,
) -> (Vec<i32>, BridgeStats) {
    let mut bridge = RateBridge::new(channels).expect("1 or 2 channels");
    let mut out = Vec::new();
    for chunk in input.chunks(chunk_frames * channels) {
        let need = bridge.output_samples_for(chunk.len() / channels);
        let mut buf = vec![0i32; need];
        let counts = bridge.process(chunk, &mut buf).expect("process");
        assert_eq!(counts.out_frames * channels, need);
        out.extend_from_slice(&buf);
    }
    if flush {
        let need = bridge.flush_output_samples();
        let mut buf = vec![0i32; need];
        bridge.flush(&mut buf).expect("flush");
        out.extend_from_slice(&buf);
    }
    (out, bridge.stats())
}

fn case(id: &str) -> Value {
    let doc: Value = serde_json::from_str(VECTORS).expect("the vector file parses");
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no vector case {id}"))
        .clone()
}

fn check_case(id: &str) {
    let case = case(id);
    let channels = input_channels(&case["input"]);
    assert_eq!(
        channels.len() as u64,
        case["channels"].as_u64().expect("channels"),
        "{id}: channels"
    );
    let flush = case["flush"].as_bool().expect("flush");
    let frames_in = case["frames_in"].as_u64().expect("frames_in");
    assert_eq!(channels[0].len() as u64, frames_in, "{id}: input length");
    let input = interleave(&channels);
    let (out, stats) = run(channels.len(), &input, frames_in.max(1) as usize, flush);

    assert_eq!(
        stats.in_frames,
        frames_in + if flush { TAPS as u64 } else { 0 },
        "{id}: frames consumed"
    );
    assert_eq!(
        stats.out_frames,
        case["frames_out"].as_u64().expect("frames_out"),
        "{id}: output frame count"
    );
    assert_eq!(
        stats.out_frames,
        outputs_after(stats.in_frames),
        "{id}: ceil(160 n / 147)"
    );
    assert_eq!(
        stats.clipped,
        case["clipped"].as_u64().expect("clipped"),
        "{id}: clamped samples"
    );
    assert_eq!(
        stats.macs,
        stats.out_frames * (TAPS * channels.len()) as u64,
        "{id}: counted MACs"
    );
    let head = ints(&case["head"]);
    let tail = ints(&case["tail"]);
    assert_eq!(&out[..head.len()], &head[..], "{id}: first samples");
    assert_eq!(
        &out[out.len() - tail.len()..],
        &tail[..],
        "{id}: last samples"
    );
    let expected = u64::from_str_radix(
        case["out_fnv1a64"]
            .as_str()
            .expect("hash")
            .trim_start_matches("0x"),
        16,
    )
    .expect("hex");
    assert_eq!(
        fnv1a64(&be_bytes(&out)),
        expected,
        "{id}: FNV-1a 64 of the whole output"
    );
}

macro_rules! vector_tests {
    ($($name:ident => $id:expr),* $(,)?) => {
        $( #[test] fn $name() { check_case($id); } )*
        const COVERED: &[&str] = &[$($id),*];
    };
}

vector_tests! {
    s02_bridge_vector_noise_tri => "noise_tri",
    s02_bridge_vector_noise_tri_flushed => "noise_tri_flushed",
    s02_bridge_vector_mono_noise_tri => "mono_noise_tri",
    s02_bridge_vector_dc => "dc",
    s02_bridge_vector_dc_negative => "dc_negative",
    s02_bridge_vector_impulse => "impulse",
    s02_bridge_vector_square_full_scale => "square_full_scale",
    s02_bridge_vector_silence => "silence",
    s02_bridge_vector_one_frame => "one_frame",
    s02_bridge_vector_tone_1000 => "tone_1000",
    s02_bridge_vector_tone_5000 => "tone_5000",
    s02_bridge_vector_tone_10000 => "tone_10000",
    s02_bridge_vector_tone_15000 => "tone_15000",
    s02_bridge_vector_tone_18000 => "tone_18000",
}

#[test]
fn s02_bridge_vector_file_has_no_case_that_is_not_tested() {
    let doc: Value = serde_json::from_str(VECTORS).expect("the vector file parses");
    let mut in_file: Vec<String> = doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| c["id"].as_str().expect("id").to_owned())
        .collect();
    let mut covered: Vec<String> = COVERED.iter().map(|s| (*s).to_owned()).collect();
    in_file.sort();
    covered.sort();
    assert_eq!(in_file, covered);
    assert_eq!(doc["up"], 160);
    assert_eq!(doc["down"], 147);
    assert_eq!(doc["taps"], TAPS as u64);
    assert_eq!(doc["delay_in_frames"], (TAPS / 2) as u64);
}

#[test]
fn s02_bridge_output_is_independent_of_how_the_input_is_chunked() {
    for id in ["noise_tri", "noise_tri_flushed", "mono_noise_tri"] {
        let case = case(id);
        let channels = input_channels(&case["input"]);
        let flush = case["flush"].as_bool().expect("flush");
        let input = interleave(&channels);
        let (whole, whole_stats) = run(channels.len(), &input, input.len(), flush);
        for chunk in [1usize, 2, 3, 7, 63, 64, 65, 146, 147, 148, 160, 1000] {
            let (split, stats) = run(channels.len(), &input, chunk, flush);
            assert_eq!(split, whole, "{id}: chunk of {chunk} frames");
            assert_eq!(
                stats, whole_stats,
                "{id}: counters, chunk of {chunk} frames"
            );
        }
    }
}

#[test]
fn s02_bridge_output_count_is_ceil_160_over_147_for_every_length() {
    for channels in [1usize, 2] {
        for frames in 0..=400usize {
            let input = vec![0i32; frames * channels];
            let (out, stats) = run(channels, &input, frames.max(1), false);
            let expected = outputs_after(frames as u64);
            assert_eq!(stats.out_frames, expected, "{frames} frames");
            assert_eq!(out.len() as u64, expected * channels as u64);
            assert_eq!(expected, (frames as u64 * 160).div_ceil(147));
        }
    }
}

#[test]
fn s02_bridge_dc_is_exact_once_the_history_is_full() {
    for id in ["dc", "dc_negative"] {
        let case = case(id);
        let value = case["input"]["value"].as_i64().expect("value") as i32;
        let channels = input_channels(&case["input"]);
        let (out, stats) = run(2, &interleave(&channels), 300, false);
        let first_full = outputs_after(TAPS as u64) as usize;
        assert!(stats.out_frames as usize > first_full + 100);
        let (frames, rest) = out.as_chunks::<2>();
        assert!(rest.is_empty(), "{id}: a whole number of stereo frames");
        for (n, frame) in frames.iter().enumerate().skip(first_full) {
            assert_eq!(*frame, [value, value], "{id}: output frame {n}");
        }
        // Before the history is full the start-up response is not the constant, which is what makes the check above bite.
        assert_ne!(&out[..2], &[value, value][..], "{id}: first frame");
    }
}

#[test]
fn s02_bridge_group_delay_is_32_input_frames() {
    let case = case("impulse");
    let at = case["input"]["at"].as_u64().expect("at") as f64;
    let channels = input_channels(&case["input"]);
    let (out, _) = run(2, &interleave(&channels), 300, false);
    let (frames, rest) = out.as_chunks::<2>();
    assert!(rest.is_empty(), "a whole number of stereo frames");
    let left: Vec<i32> = frames.iter().map(|f| f[0]).collect();
    let (peak_at, peak) = left
        .iter()
        .enumerate()
        .max_by_key(|(_, v)| v.unsigned_abs())
        .map(|(i, v)| (i, *v))
        .expect("output");
    // Output n sits at input time n * 147 / 160 - 32 (the stated delay).
    let expected = (at + 32.0) * 160.0 / 147.0;
    assert!(
        (peak_at as f64 - expected).abs() <= 1.0,
        "peak at output {peak_at}, expected near {expected}"
    );
    assert!(peak > 2_500_000, "peak {peak}");
}

#[test]
fn s02_bridge_clamps_and_counts_overshoot() {
    let case = case("square_full_scale");
    let channels = input_channels(&case["input"]);
    let (out, stats) = run(2, &interleave(&channels), 600, false);
    assert_eq!(stats.clipped, case["clipped"].as_u64().expect("clipped"));
    assert!(stats.clipped > 0, "the square wave must overshoot");
    assert!(out.iter().all(|v| (Q23_MIN..=Q23_MAX).contains(v)));
    assert!(out.contains(&Q23_MAX));
    assert!(out.contains(&Q23_MIN));
}

#[test]
fn s02_bridge_plan_admits_exactly_44100_and_48000() {
    assert_eq!(plan_for_rate(44_100), Ok(RatePlan::Bridge));
    assert_eq!(plan_for_rate(48_000), Ok(RatePlan::Direct));
    for rate_hz in [
        0u32, 8_000, 22_050, 32_000, 44_101, 47_999, 88_200, 96_000, 192_000,
    ] {
        assert_eq!(
            plan_for_rate(rate_hz),
            Err(RateError::UnsupportedRate { rate_hz }),
            "{rate_hz} Hz"
        );
    }
}

#[test]
fn s02_bridge_refuses_zero_and_too_many_channels() {
    for channels in [0usize, 3, 6, 8] {
        assert!(matches!(
            RateBridge::new(channels),
            Err(RateError::UnsupportedChannels { .. })
        ));
        assert!(matches!(
            RateAdapter::new(44_100, channels),
            Err(RateError::UnsupportedChannels { .. })
        ));
        assert!(matches!(
            RateAdapter::new(48_000, channels),
            Err(RateError::UnsupportedChannels { .. })
        ));
    }
    assert!(matches!(
        RateAdapter::new(88_200, 2),
        Err(RateError::UnsupportedRate { rate_hz: 88_200 })
    ));
}

#[test]
fn s02_bridge_rejects_ragged_input_and_a_small_output_without_consuming() {
    let mut bridge = RateBridge::new(2).expect("stereo");
    assert_eq!(
        bridge.process(&[1, 2, 3], &mut [0; 16]).unwrap_err(),
        RateError::RaggedInput {
            len: 3,
            channels: 2
        }
    );
    let input = vec![7i32; 200];
    let need = bridge.output_samples_for(100);
    let mut small = vec![0i32; need - 1];
    assert_eq!(
        bridge.process(&input, &mut small).unwrap_err(),
        RateError::OutputTooSmall {
            have: need - 1,
            need
        }
    );
    assert_eq!(bridge.stats(), BridgeStats::default());
    let mut exact = vec![0i32; need];
    let counts = bridge.process(&input, &mut exact).expect("exact size");
    assert_eq!(counts.in_frames, 100);
    assert_eq!(counts.out_frames * 2, need);
}

#[test]
fn s02_bridge_reset_restores_a_fresh_start() {
    let case = case("noise_tri");
    let input = interleave(&input_channels(&case["input"]));
    let mut bridge = RateBridge::new(2).expect("stereo");
    let mut first = vec![0i32; bridge.output_samples_for(input.len() / 2)];
    bridge.process(&input, &mut first).expect("first pass");
    bridge.reset();
    assert_eq!(bridge.stats(), BridgeStats::default());
    let mut second = vec![0i32; bridge.output_samples_for(input.len() / 2)];
    bridge.process(&input, &mut second).expect("second pass");
    assert_eq!(first, second);
}

#[test]
fn s02_adapter_at_48k_is_the_f32_to_q23_conversion_and_nothing_else() {
    let mut adapter = RateAdapter::new(48_000, 2).expect("48 kHz");
    assert_eq!(adapter.plan(), RatePlan::Direct);
    assert_eq!(adapter.source_rate_hz(), 48_000);
    let input = [0.0f32, 0.5, -0.5, 0.25, 1.0, -1.0, 1.5, f32::NAN];
    let mut out = Vec::new();
    adapter.process_f32(&input, &mut out).expect("convert");
    let expected: Vec<i32> = input.iter().map(|&x| f32_to_q23(x)).collect();
    assert_eq!(out, expected);
    assert_eq!(adapter.stats(), BridgeStats::default());
    adapter.flush(&mut out).expect("flush");
    assert!(out.is_empty());
    assert!(matches!(
        adapter.process_f32(&[0.0; 3], &mut out),
        Err(RateError::RaggedInput { .. })
    ));
}

#[test]
fn s02_adapter_at_44k_is_exactly_the_integer_bridge() {
    let case = case("noise_tri");
    let channels = input_channels(&case["input"]);
    let q23 = interleave(&channels);
    let as_f32: Vec<f32> = q23.iter().map(|&v| q23_to_f32(v)).collect();
    let (expected, _) = run(2, &q23, q23.len(), false);
    let mut adapter = RateAdapter::new(44_100, 2).expect("44.1 kHz");
    assert_eq!(adapter.plan(), RatePlan::Bridge);
    let mut out = Vec::new();
    adapter.process_f32(&as_f32, &mut out).expect("convert");
    assert_eq!(out, expected);
    assert_eq!(adapter.stats().out_frames, outputs_after(2000));
    // The same call split in two reaches the same stream.
    adapter.reset();
    let mut first = Vec::new();
    let mut second = Vec::new();
    adapter
        .process_f32(&as_f32[..1234], &mut first)
        .expect("first half");
    adapter
        .process_f32(&as_f32[1234..], &mut second)
        .expect("second half");
    first.extend_from_slice(&second);
    assert_eq!(first, expected);
}

#[test]
fn s02_sample_conversions_are_exact_and_clamp() {
    assert_eq!(f32_to_q23(f32::NAN), 0);
    assert_eq!(f32_to_q23(2.0), Q23_MAX);
    assert_eq!(f32_to_q23(-2.0), Q23_MIN);
    assert_eq!(f32_to_q23(1.0), Q23_MAX);
    assert_eq!(f32_to_q23(-1.0), Q23_MIN);
    for v in (Q23_MIN..=Q23_MAX).step_by(997) {
        assert_eq!(f32_to_q23(q23_to_f32(v)), v);
    }
    assert_eq!(f32_to_q23(q23_to_f32(Q23_MIN)), Q23_MIN);
    assert_eq!(f32_to_q23(q23_to_f32(Q23_MAX)), Q23_MAX);
    for v in i16::MIN..=i16::MAX {
        assert_eq!(q23_to_s16(s16_to_q23(v)), v);
    }
    assert_eq!(q23_to_s16(Q23_MAX), i16::MAX);
    assert_eq!(q23_to_s16(Q23_MIN), i16::MIN);
}
