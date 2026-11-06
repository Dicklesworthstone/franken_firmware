//! `S02` / `ffw-6dh`: the negotiated source codecs decoded through the real Symphonia decoders.
//!
//! The tracks in `tests/vectors/` were made by `tests/s02/make_vectors.py` with encoders and reference decoders that are NOT Symphonia (Apple
//! `afconvert`, ffmpeg's libmp3lame and native Vorbis encoders; ffmpeg and Apple decoders as references). Lossless tracks (ALAC, PCM) must equal the
//! integer source signal bit for bit; lossy tracks must stay within the pre-registered tolerance of the reference decode (4 LSB peak, 1.5 LSB rms,
//! derived from the observed disagreement between two independent reference decoders, written in the manifest before any Rust ran); lengths are
//! the gapless lengths the files' own tags state.
//!
//! Host simulation only. The `S02-STATS` lines count packets, bytes and the largest buffers our adapter held; they are not a CPU, heap or stack
//! measurement of any device.

use std::path::PathBuf;

use franken_codec::{
    BlockInfo, Caps, CodecError, ContainerDecoder, DecodeStats, PacketDecoder, PcmFormat,
    RateAdapter, RatePlan, SourceCodec, Step, decode_pcm_s16be, f32_to_s16, outputs_after,
    parse_aac_asc, parse_alac_cookie,
};
use serde_json::Value;

const MANIFEST: &str = include_str!("vectors/s02_vectors.json");

// ------------------------------------------------------------------------------------------------ vectors

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

fn track(id: &str) -> Value {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("the manifest parses");
    manifest["tracks"]
        .as_array()
        .expect("tracks")
        .iter()
        .find(|t| t["id"] == id)
        .unwrap_or_else(|| panic!("no track {id}"))
        .clone()
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(dir().join(file)).unwrap_or_else(|e| panic!("reading {file}: {e}"))
}

fn file_of(t: &Value) -> Vec<u8> {
    let name = t["file"].as_str().expect("file");
    let bytes = read(name);
    assert_eq!(
        bytes.len() as u64,
        t["bytes"].as_u64().expect("bytes"),
        "{name}: size"
    );
    bytes
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn split_packets(t: &Value, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut at = 0usize;
    let mut packets = Vec::new();
    for size in t["packets"]["sizes"].as_array().expect("packet sizes") {
        let size = size.as_u64().expect("size") as usize;
        packets.push(bytes[at..at + size].to_vec());
        at += size;
    }
    assert_eq!(at, bytes.len(), "the packet sizes cover the whole file");
    packets
}

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

/// The written source rule of `tests/s02/oracle.py::signal`, interleaved, at 16 or 24 bits.
fn signal(frames: usize, seeds: [u32; 3], bits: u32) -> Vec<i32> {
    let (mut a, mut b, mut c) = (seeds[0], seeds[1], seeds[2]);
    let mut out = Vec::with_capacity(frames * 2);
    for n in 0..frames {
        a = xorshift32(a);
        b = xorshift32(b);
        let n = n as u64;
        let mut left = tri(n, 100, 6000) + tri(n, 37, 2000) + i64::from(a % 601) - 300;
        let mut right = tri(n, 91, 6000) + tri(n, 53, 2000) + i64::from(b % 601) - 300;
        if bits == 24 {
            c = xorshift32(c);
            left = left * 256 + i64::from(c % 256);
            c = xorshift32(c);
            right = right * 256 + i64::from(c % 256);
        }
        out.push(left as i32);
        out.push(right as i32);
    }
    out
}

fn seeds_of(t: &Value) -> [u32; 3] {
    let s = t["source"]["seeds"].as_array().expect("seeds");
    [
        s[0].as_u64().expect("seed") as u32,
        s[1].as_u64().expect("seed") as u32,
        s[2].as_u64().expect("seed") as u32,
    ]
}

fn read_ref_s16(file: &str) -> Vec<i16> {
    let bytes = read(file);
    let (pairs, rest) = bytes.as_chunks::<2>();
    assert!(rest.is_empty(), "{file}: a 16-bit reference of odd length");
    pairs.iter().map(|&pair| i16::from_le_bytes(pair)).collect()
}

fn s16_of(samples: &[f32]) -> Vec<i16> {
    samples.iter().map(|&x| f32_to_s16(x)).collect()
}

/// (largest absolute error, rms error) in LSB.
fn error_stats(decoded: &[i16], reference: &[i16]) -> (i32, f64) {
    assert_eq!(decoded.len(), reference.len(), "compared lengths");
    let mut max = 0i32;
    let mut sum = 0f64;
    for (&d, &r) in decoded.iter().zip(reference) {
        let e = (i32::from(d) - i32::from(r)).abs();
        max = max.max(e);
        sum += f64::from(e) * f64::from(e);
    }
    (max, (sum / decoded.len().max(1) as f64).sqrt())
}

// ------------------------------------------------------------------------------------------------ drivers

struct Decoded {
    samples: Vec<f32>,
    blocks: Vec<BlockInfo>,
    stats: DecodeStats,
}

fn drain_partial(dec: &mut ContainerDecoder) -> (Decoded, Option<CodecError>) {
    let mut samples = Vec::new();
    let mut blocks = Vec::new();
    let mut buf = Vec::new();
    let mut error = None;
    let mut finished = false;
    for _ in 0..200_000 {
        match dec.next_block(&mut buf) {
            Ok(Step::Block(info)) => {
                assert_eq!(buf.len(), info.frames * usize::from(info.format.channels));
                samples.extend_from_slice(&buf);
                blocks.push(info);
            }
            Ok(Step::End) => {
                finished = true;
                break;
            }
            Err(e) => {
                error = Some(e);
                finished = true;
                break;
            }
        }
    }
    assert!(finished, "the decoder neither ended nor failed");
    let stats = dec.stats();
    (
        Decoded {
            samples,
            blocks,
            stats,
        },
        error,
    )
}

fn decode_container(codec: SourceCodec, bytes: Vec<u8>, caps: Caps) -> Decoded {
    let mut dec = ContainerDecoder::open(codec, bytes, caps).expect("open");
    let (decoded, error) = drain_partial(&mut dec);
    assert!(error.is_none(), "decode failed: {error:?}");
    decoded
}

/// Open and drain, returning what was decoded even when open or decode fails.
fn decode_any(
    codec: SourceCodec,
    bytes: Vec<u8>,
    caps: Caps,
) -> (Option<Decoded>, Option<CodecError>) {
    match ContainerDecoder::open(codec, bytes, caps) {
        Err(e) => (None, Some(e)),
        Ok(mut dec) => {
            let (decoded, error) = drain_partial(&mut dec);
            (Some(decoded), error)
        }
    }
}

fn decode_packets(
    dec: &mut PacketDecoder,
    packets: &[Vec<u8>],
) -> (Vec<f32>, Vec<BlockInfo>, Vec<usize>) {
    let mut samples = Vec::new();
    let mut blocks = Vec::new();
    let mut ends = Vec::new();
    let mut buf = Vec::new();
    for (i, packet) in packets.iter().enumerate() {
        let info = dec
            .decode(packet, &mut buf)
            .unwrap_or_else(|e| panic!("packet {i}: {e}"));
        assert_eq!(buf.len(), info.frames * usize::from(info.format.channels));
        samples.extend_from_slice(&buf);
        blocks.push(info);
        ends.push(samples.len());
    }
    (samples, blocks, ends)
}

fn report(id: &str, stats: &DecodeStats) {
    println!(
        "S02-STATS id={id} packets={} blocks={} frames={} bytes_in={} decode_errors={} empty_packets={} max_block_frames={} max_out_capacity_samples={}",
        stats.packets,
        stats.blocks,
        stats.frames,
        stats.bytes_in,
        stats.decode_errors,
        stats.empty_packets,
        stats.max_block_frames,
        stats.max_out_capacity_samples
    );
}

fn first_difference(a: &[f32], b: &[f32]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| x.to_bits() != y.to_bits())
}

fn assert_tolerance(id: &str, t: &Value, decoded: &[f32]) {
    let reference = read_ref_s16(t["reference"]["file"].as_str().expect("reference file"));
    let (max_abs, rms) = error_stats(&s16_of(decoded), &reference);
    println!("S02-ERR id={id} max_abs_lsb={max_abs} rms_lsb={rms:.4}");
    let tolerance = &t["tolerance"];
    assert!(
        f64::from(max_abs) <= tolerance["max_abs_lsb"].as_f64().expect("max_abs_lsb"),
        "{id}: peak error {max_abs} LSB"
    );
    assert!(
        rms <= tolerance["rms_lsb"].as_f64().expect("rms_lsb"),
        "{id}: rms error {rms} LSB"
    );
}

// ------------------------------------------------------------------------------------------------ lossy containers

fn check_container_track(id: &str, codec: SourceCodec, must_start_at_zero: bool) {
    let t = track(id);
    let rate = t["rate_hz"].as_u64().expect("rate") as u32;
    let expected = t["expected_frames"].as_u64().expect("expected_frames") as usize;
    let decoded = decode_container(codec, file_of(&t), Caps::default());
    let mut next = decoded.blocks.first().map_or(0, |b| b.position);
    if must_start_at_zero {
        assert_eq!(next, 0, "{id}: the first frame is position 0");
    }
    for (i, block) in decoded.blocks.iter().enumerate() {
        assert_eq!(
            block.format,
            PcmFormat {
                rate_hz: rate,
                channels: 2
            },
            "{id}: block {i} keeps the native format"
        );
        assert!(!block.format_changed, "{id}: block {i}");
        assert_eq!(block.position, next, "{id}: block {i} is contiguous");
        next += block.frames as i64;
    }
    assert_eq!(
        decoded.samples.len(),
        expected * 2,
        "{id}: gapless length in frames"
    );
    assert_tolerance(id, &t, &decoded.samples);
    report(id, &decoded.stats);
    assert!(decoded.stats.max_block_frames <= Caps::default().max_block_frames);
}

#[test]
fn s02_vorbis_44100_decodes_within_tolerance_with_the_gapless_length() {
    check_container_track("vorbis_44100", SourceCodec::OggVorbis, true);
}

#[test]
fn s02_vorbis_48000_decodes_within_tolerance_with_the_gapless_length() {
    check_container_track("vorbis_48000", SourceCodec::OggVorbis, true);
}

#[test]
fn s02_mp3_44100_decodes_within_tolerance_with_the_gapless_length() {
    check_container_track("mp3_44100", SourceCodec::Mp3, true);
}

#[test]
fn s02_mp3_48000_decodes_within_tolerance_with_the_gapless_length() {
    check_container_track("mp3_48000", SourceCodec::Mp3, true);
}

// ------------------------------------------------------------------------------------------------ AirPlay packets and PCM

fn check_alac(id: &str, bits: u32) {
    let t = track(id);
    let bytes = file_of(&t);
    let packets = split_packets(&t, &bytes);
    let cookie = hex(t["cookie_hex"].as_str().expect("cookie"));
    let config = parse_alac_cookie(&cookie, &Caps::default()).expect("the cookie parses");
    let fields = &t["cookie_fields"];
    assert_eq!(
        u64::from(config.frame_length),
        fields["frame_length"].as_u64().expect("frame_length")
    );
    assert_eq!(
        u64::from(config.bit_depth),
        fields["bit_depth"].as_u64().expect("bit_depth")
    );
    assert_eq!(
        u64::from(config.channels),
        fields["channels"].as_u64().expect("channels")
    );
    assert_eq!(
        u64::from(config.sample_rate),
        fields["sample_rate"].as_u64().expect("sample_rate")
    );
    let mut dec = PacketDecoder::alac(&cookie, Caps::default()).expect("alac decoder");
    let rate = t["rate_hz"].as_u64().expect("rate") as u32;
    assert_eq!(
        dec.format(),
        PcmFormat {
            rate_hz: rate,
            channels: 2
        }
    );
    let (samples, blocks, _) = decode_packets(&mut dec, &packets);
    let frames = t["expected_frames"].as_u64().expect("expected_frames") as usize;
    assert_eq!(samples.len(), frames * 2, "{id}: frames");
    let mut next = 0i64;
    for block in &blocks {
        assert_eq!(block.position, next);
        next += block.frames as i64;
    }
    let source = signal(frames, seeds_of(&t), bits);
    let scale = if bits == 24 { 8_388_608.0 } else { 32_768.0 };
    for (i, (&x, &s)) in samples.iter().zip(&source).enumerate() {
        let got = (x * scale).round() as i32;
        assert_eq!(got, s, "{id}: sample {i} is not bit exact");
    }
    report(id, &dec.stats());
    assert_eq!(dec.stats().max_block_frames, config.frame_length as usize);
}

#[test]
fn s02_alac_44100_16_is_bit_exact() {
    check_alac("alac_44100_16", 16);
}

#[test]
fn s02_alac_48000_24_is_bit_exact() {
    check_alac("alac_48000_24", 24);
}

fn check_aac(id: &str) {
    let t = track(id);
    let bytes = file_of(&t);
    let packets = split_packets(&t, &bytes);
    let asc = hex(t["asc_hex"].as_str().expect("asc"));
    let mut dec = PacketDecoder::aac_lc(&asc, Caps::default()).expect("aac decoder");
    let rate = t["rate_hz"].as_u64().expect("rate") as u32;
    assert_eq!(
        dec.format(),
        PcmFormat {
            rate_hz: rate,
            channels: 2
        }
    );
    let (samples, blocks, _) = decode_packets(&mut dec, &packets);
    let frames = t["expected_frames"].as_u64().expect("expected_frames") as usize;
    assert_eq!(
        samples.len(),
        frames * 2,
        "{id}: raw frames, packets x 1024"
    );
    assert_eq!(blocks.len(), packets.len());
    assert!(blocks.iter().all(|b| b.frames == 1024));
    assert_tolerance(id, &t, &samples);
    report(id, &dec.stats());
}

#[test]
fn s02_aac_lc_44100_decodes_within_tolerance() {
    check_aac("aac_lc_44100");
}

#[test]
fn s02_aac_lc_48000_decodes_within_tolerance() {
    check_aac("aac_lc_48000");
}

#[test]
fn s02_pcm_s16be_44100_is_bit_exact() {
    let t = track("pcm_s16be_44100");
    let bytes = file_of(&t);
    let mut out = Vec::new();
    let frames = decode_pcm_s16be(&bytes, 2, &mut out).expect("pcm");
    assert_eq!(
        frames,
        t["expected_frames"].as_u64().expect("expected_frames") as usize
    );
    let source = signal(frames, seeds_of(&t), 16);
    for (i, (&x, &s)) in out.iter().zip(&source).enumerate() {
        assert_eq!((x * 32_768.0).round() as i32, s, "sample {i}");
    }
    assert_eq!(out.len(), source.len());
    // A byte count that ends inside a frame is refused, not truncated.
    assert!(matches!(
        decode_pcm_s16be(&bytes[..bytes.len() - 1], 2, &mut out),
        Err(CodecError::Malformed(_))
    ));
    assert!(matches!(
        decode_pcm_s16be(&bytes, 0, &mut out),
        Err(CodecError::TooManyChannels { .. })
    ));
    assert!(matches!(
        decode_pcm_s16be(&bytes, 3, &mut out),
        Err(CodecError::TooManyChannels { .. })
    ));
}

// ------------------------------------------------------------------------------------------------ the native rate reaches the rate stage

/// Decode any manifest track to (format, samples) by its codec name.
fn decode_track(id: &str) -> (PcmFormat, Vec<f32>) {
    let t = track(id);
    let bytes = file_of(&t);
    match t["codec"].as_str().expect("codec") {
        "vorbis" => {
            let d = decode_container(SourceCodec::OggVorbis, bytes, Caps::default());
            (d.blocks[0].format, d.samples)
        }
        "mp3" => {
            let d = decode_container(SourceCodec::Mp3, bytes, Caps::default());
            (d.blocks[0].format, d.samples)
        }
        "alac" => {
            let mut dec = PacketDecoder::alac(
                &hex(t["cookie_hex"].as_str().expect("cookie")),
                Caps::default(),
            )
            .expect("alac");
            let (samples, _, _) = decode_packets(&mut dec, &split_packets(&t, &bytes));
            (dec.format(), samples)
        }
        "aac" => {
            let mut dec =
                PacketDecoder::aac_lc(&hex(t["asc_hex"].as_str().expect("asc")), Caps::default())
                    .expect("aac");
            let (samples, _, _) = decode_packets(&mut dec, &split_packets(&t, &bytes));
            (dec.format(), samples)
        }
        "pcm" => {
            let mut out = Vec::new();
            decode_pcm_s16be(&bytes, 2, &mut out).expect("pcm");
            (
                PcmFormat {
                    rate_hz: t["rate_hz"].as_u64().expect("rate") as u32,
                    channels: 2,
                },
                out,
            )
        }
        other => panic!("unknown codec {other}"),
    }
}

#[test]
fn s02_native_rate_is_carried_from_every_decoder_to_the_rate_stage() {
    for (id, rate, plan) in [
        ("vorbis_44100", 44_100, RatePlan::Bridge),
        ("vorbis_48000", 48_000, RatePlan::Direct),
        ("mp3_44100", 44_100, RatePlan::Bridge),
        ("mp3_48000", 48_000, RatePlan::Direct),
        ("alac_44100_16", 44_100, RatePlan::Bridge),
        ("alac_48000_24", 48_000, RatePlan::Direct),
        ("aac_lc_44100", 44_100, RatePlan::Bridge),
        ("aac_lc_48000", 48_000, RatePlan::Direct),
        ("pcm_s16be_44100", 44_100, RatePlan::Bridge),
    ] {
        let (format, samples) = decode_track(id);
        assert_eq!(format.rate_hz, rate, "{id}: decoded at its native rate");
        assert_eq!(format.channels, 2, "{id}");
        let mut adapter = RateAdapter::new(format.rate_hz, usize::from(format.channels))
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(adapter.plan(), plan, "{id}");
        assert_eq!(adapter.source_rate_hz(), rate, "{id}");
        let frames = samples.len() / 2;
        let mut out = Vec::new();
        adapter.process_f32(&samples, &mut out).expect("convert");
        let expected_frames = match plan {
            RatePlan::Direct => frames as u64,
            RatePlan::Bridge => outputs_after(frames as u64),
        };
        assert_eq!(out.len() as u64, expected_frames * 2, "{id}: 48 kHz frames");
    }
}

// ------------------------------------------------------------------------------------------------ seek

fn check_seek(id: &str, codec: SourceCodec) {
    let t = track(id);
    let bytes = file_of(&t);
    let full = decode_container(codec, bytes.clone(), Caps::default());
    let total = full.samples.len() / 2;
    let targets: Vec<u64> = t["seek_targets"]
        .as_array()
        .expect("seek_targets")
        .iter()
        .map(|v| v.as_u64().expect("target"))
        .collect();
    assert!(targets.len() >= 5);
    for target in targets {
        let mut dec = ContainerDecoder::open(codec, bytes.clone(), Caps::default()).expect("open");
        let info = dec
            .seek(target)
            .unwrap_or_else(|e| panic!("{id}: seek {target}: {e}"));
        assert_eq!(info.target, target);
        assert!(!info.saturated);
        let (after, error) = drain_partial(&mut dec);
        assert!(error.is_none(), "{id}: after seek {target}: {error:?}");
        let expected = &full.samples[target as usize * 2..];
        assert_eq!(
            after.samples.len(),
            expected.len(),
            "{id}: frames after a seek to {target} (total {total})"
        );
        assert_eq!(
            first_difference(&after.samples, expected),
            None,
            "{id}: output after a seek to {target} differs from continuous decoding"
        );
        assert_eq!(
            after.blocks.first().map(|b| b.position),
            Some(target as i64)
        );
    }
}

#[test]
fn s02_vorbis_seek_equals_continuous_decoding_from_every_target() {
    check_seek("vorbis_44100", SourceCodec::OggVorbis);
}

#[test]
fn s02_mp3_seek_equals_continuous_decoding_from_every_target() {
    check_seek("mp3_44100", SourceCodec::Mp3);
}

#[test]
fn s02_seek_past_the_end_saturates_to_the_duration_and_yields_nothing() {
    for (id, codec) in [
        ("vorbis_44100", SourceCodec::OggVorbis),
        ("mp3_44100", SourceCodec::Mp3),
    ] {
        let t = track(id);
        let mut dec = ContainerDecoder::open(codec, file_of(&t), Caps::default()).expect("open");
        let Some(total) = dec.track_frames() else {
            // A stream that does not state its length cannot saturate; that is reported, not guessed.
            println!("S02-NOTE id={id} states no track length, saturation not exercised");
            continue;
        };
        assert_eq!(
            total,
            t["expected_frames"].as_u64().expect("frames"),
            "{id}"
        );
        let info = dec.seek(total + 12_345).expect("seek past the end");
        assert!(info.saturated, "{id}");
        assert_eq!(info.target, total, "{id}");
        let (after, error) = drain_partial(&mut dec);
        assert!(error.is_none(), "{id}: {error:?}");
        assert!(after.samples.is_empty(), "{id}: nothing after the end");
        // Exactly at the end is not a saturation and also yields nothing.
        let mut dec = ContainerDecoder::open(codec, file_of(&t), Caps::default()).expect("open");
        let info = dec.seek(total).expect("seek to the end");
        assert!(!info.saturated);
        let (after, _) = drain_partial(&mut dec);
        assert!(after.samples.is_empty(), "{id}");
    }
}

#[test]
fn s02_packet_decoders_restart_after_a_reset_with_the_documented_preroll() {
    for (id, preroll) in [("alac_44100_16", 0usize), ("aac_lc_44100", 1usize)] {
        let t = track(id);
        let bytes = file_of(&t);
        let packets = split_packets(&t, &bytes);
        let make = || {
            if t["codec"] == "alac" {
                PacketDecoder::alac(
                    &hex(t["cookie_hex"].as_str().expect("cookie")),
                    Caps::default(),
                )
                .expect("alac")
            } else {
                PacketDecoder::aac_lc(&hex(t["asc_hex"].as_str().expect("asc")), Caps::default())
                    .expect("aac")
            }
        };
        let mut continuous = make();
        let (all, _, ends) = decode_packets(&mut continuous, &packets);
        assert_eq!(
            t["preroll"]["packets"].as_u64().expect("preroll") as usize,
            preroll,
            "{id}: the manifest states the same preroll"
        );
        for start in [1usize, 3, packets.len() / 2, packets.len() - 1] {
            let mut dec = make();
            dec.reset();
            let mut buf = Vec::new();
            for packet in &packets[start - preroll..start] {
                dec.decode(packet, &mut buf).expect("preroll packet");
            }
            let (after, _, _) = decode_packets(&mut dec, &packets[start..]);
            let from = ends[start - 1];
            assert_eq!(
                after.len(),
                all.len() - from,
                "{id}: frames after restarting at packet {start}"
            );
            assert_eq!(
                first_difference(&after, &all[from..]),
                None,
                "{id}: restarting at packet {start} differs from continuous decoding"
            );
        }
    }
}

// ------------------------------------------------------------------------------------------------ rate and channel changes

fn check_chain(id: &str, codec: SourceCodec, part2_frames: usize) {
    let t = track(id);
    let decoded = decode_container(codec, file_of(&t), Caps::default());
    let changed: Vec<usize> = decoded
        .blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.format_changed)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        changed.len(),
        1,
        "{id}: the change is reported once, explicitly"
    );
    let k = changed[0];
    assert!(k > 0);
    for b in &decoded.blocks[..k] {
        assert_eq!(
            b.format,
            PcmFormat {
                rate_hz: 44_100,
                channels: 2
            },
            "{id}"
        );
    }
    for b in &decoded.blocks[k..] {
        assert_eq!(
            b.format,
            PcmFormat {
                rate_hz: 48_000,
                channels: 2
            },
            "{id}"
        );
    }
    let before: usize = decoded.blocks[..k].iter().map(|b| b.frames).sum();
    let after: usize = decoded.blocks[k..].iter().map(|b| b.frames).sum();
    assert_eq!(
        before,
        t["first_part_frames"].as_u64().expect("first part") as usize,
        "{id}: frames of the first stream"
    );
    assert_eq!(after, part2_frames, "{id}: frames of the second stream");
    report(id, &decoded.stats);
    // The rate stage refuses to be reconfigured silently: the new block needs a new adapter at its own rate.
    assert_eq!(
        RateAdapter::new(decoded.blocks[0].format.rate_hz, 2)
            .expect("44.1")
            .plan(),
        RatePlan::Bridge
    );
    assert_eq!(
        RateAdapter::new(decoded.blocks[k].format.rate_hz, 2)
            .expect("48")
            .plan(),
        RatePlan::Direct
    );
}

#[test]
fn s02_chained_vorbis_reports_the_rate_change_explicitly() {
    let second = track("vorbis_48000")["expected_frames"]
        .as_u64()
        .expect("frames") as usize;
    check_chain("chain_vorbis_44100_48000", SourceCodec::OggVorbis, second);
}

#[test]
fn s02_chained_mp3_reports_the_rate_change_explicitly() {
    // The second stream is past the first stream's tag-stated length, so its frames are not trimmed: every audio frame of it is delivered.
    let second = track("mp3_48000");
    let frames = second["stream"]["xing_frames"].as_u64().expect("xing") as usize * 1152;
    check_chain("chain_mp3_44100_48000", SourceCodec::Mp3, frames);
}

// ------------------------------------------------------------------------------------------------ ID3, wrong codec

#[test]
fn s02_mp3_with_a_leading_id3v2_tag_decodes_identically() {
    let t = track("mp3_44100");
    let plain = file_of(&t);
    let mut tagged = vec![b'I', b'D', b'3', 3, 0, 0];
    let size = 2000usize;
    tagged.extend_from_slice(&[
        ((size >> 21) & 0x7F) as u8,
        ((size >> 14) & 0x7F) as u8,
        ((size >> 7) & 0x7F) as u8,
        (size & 0x7F) as u8,
    ]);
    tagged.extend(std::iter::repeat_n(0u8, size));
    tagged.extend_from_slice(&plain);
    let a = decode_container(SourceCodec::Mp3, plain, Caps::default());
    let b = decode_container(SourceCodec::Mp3, tagged, Caps::default());
    assert_eq!(a.samples.len(), b.samples.len());
    assert_eq!(first_difference(&a.samples, &b.samples), None);
}

#[test]
fn s02_a_container_of_another_codec_is_refused_by_name() {
    let mp3 = file_of(&track("mp3_44100"));
    let ogg = file_of(&track("vorbis_44100"));
    assert!(matches!(
        ContainerDecoder::open(SourceCodec::OggVorbis, mp3, Caps::default()),
        Err(CodecError::WrongCodec {
            expected: "ogg_vorbis",
            found: "mp3"
        })
    ));
    assert!(matches!(
        ContainerDecoder::open(SourceCodec::Mp3, ogg, Caps::default()),
        Err(CodecError::WrongCodec {
            expected: "mp3",
            found: "vorbis"
        })
    ));
    // Raw-packet codecs are not containers.
    assert!(matches!(
        ContainerDecoder::open(SourceCodec::Alac, vec![0; 64], Caps::default()),
        Err(CodecError::Unsupported(_))
    ));
}

// ------------------------------------------------------------------------------------------------ malformed, truncated, capped

#[test]
fn s02_truncated_containers_never_invent_audio() {
    for (id, codec) in [
        ("vorbis_44100", SourceCodec::OggVorbis),
        ("mp3_44100", SourceCodec::Mp3),
    ] {
        let t = track(id);
        let bytes = file_of(&t);
        let full = decode_container(codec, bytes.clone(), Caps::default());
        let n = bytes.len();
        let mut refused = 0;
        let mut partial = 0;
        for cut in [
            0,
            1,
            4,
            27,
            28,
            58,
            100,
            500,
            4000,
            n / 4,
            n / 2,
            3 * n / 4,
            n - 200,
            n - 30,
            n - 1,
        ] {
            let (decoded, error) = decode_any(codec, bytes[..cut].to_vec(), Caps::default());
            match decoded {
                None => {
                    assert!(error.is_some());
                    refused += 1;
                }
                Some(d) => {
                    assert!(
                        d.samples.len() <= full.samples.len(),
                        "{id}: cut {cut} produced more audio than the whole stream"
                    );
                    let common = d.samples.len().min(full.samples.len());
                    assert_eq!(
                        first_difference(&d.samples[..common], &full.samples[..common]),
                        None,
                        "{id}: cut {cut} changed decoded samples"
                    );
                    if !d.samples.is_empty() && d.samples.len() < full.samples.len() {
                        partial += 1;
                    }
                }
            }
        }
        assert!(refused >= 1, "{id}: an empty input must be refused");
        assert!(
            partial >= 1,
            "{id}: some truncation must yield a shorter prefix"
        );
    }
}

#[test]
fn s02_flipped_bits_never_panic_and_stay_inside_the_caps() {
    let caps = Caps::default();
    for (id, codec) in [
        ("vorbis_44100", SourceCodec::OggVorbis),
        ("mp3_44100", SourceCodec::Mp3),
    ] {
        let t = track(id);
        let bytes = file_of(&t);
        let full = decode_container(codec, bytes.clone(), Caps::default());
        let (mut refused, mut failed, mut altered, mut same) = (0, 0, 0, 0);
        for i in 0..96usize {
            let at = 11 + i * (bytes.len() - 12) / 96;
            let mut damaged = bytes.clone();
            damaged[at] ^= 1 << (i % 8);
            let (decoded, error) = decode_any(codec, damaged, caps);
            match decoded {
                None => refused += 1,
                Some(d) => {
                    assert!(d.stats.max_block_frames <= caps.max_block_frames);
                    assert!(d.samples.len() <= caps.max_input_bytes);
                    if error.is_some() {
                        failed += 1;
                    } else if d.samples.len() != full.samples.len()
                        || first_difference(&d.samples, &full.samples).is_some()
                    {
                        altered += 1;
                    } else {
                        same += 1;
                    }
                }
            }
        }
        println!(
            "S02-FLIPS id={id} refused={refused} failed={failed} altered={altered} unchanged={same}"
        );
        assert!(
            refused + failed + altered > 0,
            "{id}: damage must be visible somewhere"
        );
    }
}

#[test]
fn s02_garbage_and_header_only_inputs_are_refused_or_end_without_panic() {
    let mut noise = Vec::new();
    let mut s = 0x1234_5678u32;
    for _ in 0..4096 {
        s = xorshift32(s);
        noise.push((s >> 8) as u8);
    }
    let mut ogg_zeros = b"OggS".to_vec();
    ogg_zeros.extend(vec![0u8; 1000]);
    let mp3_like: Vec<u8> = std::iter::repeat_n([0xFFu8, 0xFB, 0x90, 0x64], 1000)
        .flatten()
        .collect();
    let inputs: [Vec<u8>; 6] = [
        Vec::new(),
        vec![0; 16],
        vec![0; 100_000],
        noise,
        ogg_zeros,
        mp3_like,
    ];
    for (i, bytes) in inputs.iter().enumerate() {
        for codec in [SourceCodec::OggVorbis, SourceCodec::Mp3] {
            let (decoded, error) = decode_any(codec, bytes.clone(), Caps::default());
            if let Some(d) = decoded {
                assert!(
                    d.samples.len() < 64 * 1024 * 1024,
                    "input {i} {codec:?}: runaway output"
                );
            } else {
                assert!(error.is_some());
            }
        }
    }
}

#[test]
fn s02_caps_stop_oversize_input_blocks_and_channels() {
    let t = track("vorbis_44100");
    let bytes = file_of(&t);
    let n = bytes.len();
    // Input larger than the cap is refused before probing.
    let caps = Caps {
        max_input_bytes: n - 1,
        ..Caps::default()
    };
    assert!(matches!(
        ContainerDecoder::open(SourceCodec::OggVorbis, bytes.clone(), caps),
        Err(CodecError::InputTooLarge { len, cap }) if len == n && cap == n - 1
    ));
    // The smallest Vorbis block holds more than 100 frames, so a cap of 100 stops the first block.
    let caps = Caps {
        max_block_frames: 100,
        ..Caps::default()
    };
    let (decoded, error) = decode_any(SourceCodec::OggVorbis, bytes.clone(), caps);
    assert!(
        matches!(error, Some(CodecError::BlockTooLarge { cap: 100, .. })),
        "{error:?}"
    );
    assert!(decoded.expect("open succeeds").samples.is_empty());
    // A stereo stream under a mono cap is refused at open or at the first block, never decoded.
    let caps = Caps {
        max_channels: 1,
        ..Caps::default()
    };
    let (decoded, error) = decode_any(SourceCodec::OggVorbis, bytes, caps);
    assert!(
        matches!(error, Some(CodecError::TooManyChannels { cap: 1, .. })),
        "{error:?}"
    );
    assert!(decoded.is_none_or(|d| d.samples.is_empty()));
    // Packets over the cap are refused before the decoder sees them.
    let t = track("alac_44100_16");
    let mut dec = PacketDecoder::alac(
        &hex(t["cookie_hex"].as_str().expect("cookie")),
        Caps::default(),
    )
    .expect("alac");
    let mut out = Vec::new();
    assert!(matches!(
        dec.decode(&vec![0u8; 64 * 1024 + 1], &mut out),
        Err(CodecError::PacketTooLarge { .. })
    ));
    assert!(matches!(
        dec.decode(&[], &mut out),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn s02_alac_cookie_is_validated_before_any_decoding() {
    let t = track("alac_44100_16");
    let base = hex(t["cookie_hex"].as_str().expect("cookie"));
    let caps = Caps::default();
    let ok = parse_alac_cookie(&base, &caps).expect("the real cookie");
    assert_eq!(
        (ok.frame_length, ok.bit_depth, ok.channels, ok.sample_rate),
        (4096, 16, 2, 44_100)
    );
    let with = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut c = base.clone();
        edit(&mut c);
        parse_alac_cookie(&c, &caps)
    };
    assert!(matches!(
        with(&|c| c.truncate(23)),
        Err(CodecError::Unsupported(_))
    ));
    assert!(matches!(
        with(&|c| c.push(0)),
        Err(CodecError::Unsupported(_))
    ));
    assert!(matches!(
        with(&|c| c[4] = 1),
        Err(CodecError::Unsupported(_))
    ));
    for depth in [0u8, 8, 12, 20, 32] {
        assert!(
            matches!(with(&|c| c[5] = depth), Err(CodecError::Unsupported(_))),
            "depth {depth}"
        );
    }
    for channels in [0u8, 3, 6, 8, 255] {
        assert!(
            matches!(with(&|c| c[9] = channels), Err(CodecError::Unsupported(_))),
            "channels {channels}"
        );
    }
    for length in [0u32, 16_385, 65_536, u32::MAX] {
        assert!(
            matches!(
                with(&|c| c[0..4].copy_from_slice(&length.to_be_bytes())),
                Err(CodecError::BlockTooLarge { .. })
            ),
            "frame length {length}"
        );
    }
    assert!(
        with(&|c| c[0..4].copy_from_slice(&16_384u32.to_be_bytes())).is_ok(),
        "the cap itself is allowed"
    );
    assert!(matches!(
        with(&|c| c[20..24].copy_from_slice(&0u32.to_be_bytes())),
        Err(CodecError::Unsupported(_))
    ));
    assert!(matches!(
        PacketDecoder::alac(&base[..23], caps),
        Err(CodecError::Unsupported(_))
    ));
}

fn asc(object: u8, frequency: u8, channels: u8, frame_flag: u8) -> [u8; 2] {
    [
        (object << 3) | (frequency >> 1),
        ((frequency & 1) << 7) | (channels << 3) | (frame_flag << 2),
    ]
}

fn unsupported_text(result: Result<franken_codec::AacConfig, CodecError>) -> String {
    match result {
        Err(CodecError::Unsupported(text)) => text.to_owned(),
        other => panic!("expected an unsupported refusal, got {other:?}"),
    }
}

#[test]
fn s02_aac_config_accepts_only_lc_and_refuses_the_rest_by_name() {
    let caps = Caps::default();
    for (id, rate) in [("aac_lc_44100", 44_100), ("aac_lc_48000", 48_000)] {
        let t = track(id);
        let config = parse_aac_asc(&hex(t["asc_hex"].as_str().expect("asc")), &caps)
            .expect("the real config");
        assert_eq!((config.sample_rate, config.channels), (rate, 2), "{id}");
    }
    assert_eq!(
        parse_aac_asc(&asc(2, 3, 1, 0), &caps)
            .expect("mono 48k")
            .channels,
        1
    );
    // The negotiated 5.1 / 7.1 requirement is BLOCKED: refused before any decoding, by its ledger name, never downmixed.
    let six = track("aac_lc_48000_6ch");
    let text = unsupported_text(parse_aac_asc(
        &hex(six["asc_hex"].as_str().expect("asc")),
        &caps,
    ));
    assert!(
        text.contains("BLOCKED: airplay.aac_lc_multichannel"),
        "{text}"
    );
    assert!(
        PacketDecoder::aac_lc(&hex(six["asc_hex"].as_str().expect("asc")), caps).is_err(),
        "no decoder is built for 5.1"
    );
    for channels in [3u8, 4, 5, 6, 7] {
        let text = unsupported_text(parse_aac_asc(&asc(2, 3, channels, 0), &caps));
        assert!(text.contains("multichannel"), "{channels}: {text}");
    }
    assert!(unsupported_text(parse_aac_asc(&asc(2, 3, 0, 0), &caps)).contains("program config"));
    assert!(unsupported_text(parse_aac_asc(&asc(5, 3, 2, 0), &caps)).contains("HE-AAC"));
    assert!(unsupported_text(parse_aac_asc(&asc(29, 3, 2, 0), &caps)).contains("HE-AAC"));
    assert!(unsupported_text(parse_aac_asc(&asc(23, 3, 2, 0), &caps)).contains("AAC-LD"));
    assert!(unsupported_text(parse_aac_asc(&asc(1, 3, 2, 0), &caps)).contains("LC object type"));
    assert!(unsupported_text(parse_aac_asc(&asc(2, 3, 2, 1), &caps)).contains("960"));
    assert!(unsupported_text(parse_aac_asc(&asc(2, 13, 2, 0), &caps)).contains("frequency index"));
    assert!(unsupported_text(parse_aac_asc(&asc(2, 15, 2, 0), &caps)).contains("frequency index"));
    // AAC-ELD is signalled with the escape object type 31 followed by 39 - 32 = 7.
    assert!(
        unsupported_text(parse_aac_asc(&[0xF8, 0xE2, 0x20], &caps)).contains("AAC-ELD"),
        "AirPlay 2 realtime audio is named, not decoded as LC"
    );
    assert!(matches!(
        parse_aac_asc(&[0x12], &caps),
        Err(CodecError::Malformed(_))
    ));
    assert!(matches!(
        parse_aac_asc(&[], &caps),
        Err(CodecError::Malformed(_))
    ));
    let one_channel_only = Caps {
        max_channels: 1,
        ..Caps::default()
    };
    assert!(matches!(
        parse_aac_asc(&asc(2, 3, 2, 0), &one_channel_only),
        Err(CodecError::TooManyChannels { .. })
    ));
}

#[test]
fn s02_damaged_raw_packets_fail_or_decode_but_never_panic() {
    for id in ["alac_44100_16", "aac_lc_44100"] {
        let t = track(id);
        let bytes = file_of(&t);
        let packets = split_packets(&t, &bytes);
        let make = || {
            if t["codec"] == "alac" {
                PacketDecoder::alac(
                    &hex(t["cookie_hex"].as_str().expect("cookie")),
                    Caps::default(),
                )
                .expect("alac")
            } else {
                PacketDecoder::aac_lc(&hex(t["asc_hex"].as_str().expect("asc")), Caps::default())
                    .expect("aac")
            }
        };
        let mut errors = 0;
        let mut buf = Vec::new();
        let mut s = 0x9E37_79B9u32;
        for (i, packet) in packets.iter().enumerate() {
            // Half of the packet, then the packet with one flipped byte, then pure noise of the same length.
            let mut dec = make();
            if dec.decode(&packet[..packet.len() / 2], &mut buf).is_err() {
                errors += 1;
            }
            let mut flipped = packet.clone();
            let at = (i * 7 + 3) % flipped.len();
            flipped[at] ^= 0x5A;
            if make().decode(&flipped, &mut buf).is_err() {
                errors += 1;
            }
            let noise: Vec<u8> = (0..packet.len())
                .map(|_| {
                    s = xorshift32(s);
                    (s >> 11) as u8
                })
                .collect();
            if make().decode(&noise, &mut buf).is_err() {
                errors += 1;
            }
            assert!(buf.len() <= Caps::default().max_block_frames * 2);
        }
        println!(
            "S02-DAMAGE id={id} errors={errors} attempts={}",
            3 * packets.len()
        );
        assert!(errors > 0, "{id}: damage must be visible somewhere");
    }
}
