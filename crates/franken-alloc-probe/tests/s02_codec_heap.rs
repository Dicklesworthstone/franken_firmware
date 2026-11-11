//! Calling-thread requested-byte heap observations for the existing S02 fixture tracks.
//!
//! Each window starts before the encoded fixture is copied into caller-owned memory and ends
//! after the decoder, decoded output, seek buffers, and rate-adapter output have been dropped.
//! Static fixture/reference bytes are test inputs outside the window, not decoder allocations.
//! `CountingAllocator` is per-thread and counts requested sizes, not process RSS or other
//! threads; its conservative realloc peak may overstate an in-place resize. First-use net
//! retention is reported as unknown shared state, not excluded. A second identical warm run
//! must return to its own starting live-byte figure. Neither run supplies a board budget.
//!
//! Fixture sizes, source FNVs, reference FNVs, frame counts, and packet boundaries are pinned
//! from the existing `s02_vectors.json`; lossy comparisons retain its 4 LSB / 1.5 LSB limits.
//! The time check is a harness deadline checked between calls, not a CPU performance claim;
//! a central runner must also impose an external timeout for a single stuck decoder call.

use std::hint::black_box;
use std::time::{Duration, Instant};

use franken_alloc_probe::{
    AllocSnapshot, CountingAllocator, HeapWindow, heap_is_tracked, is_active, measure, measure_heap,
};
use franken_codec::{
    Caps, ContainerDecoder, PacketDecoder, PcmFormat, RateAdapter, RatePlan, SourceCodec, Step,
    decode_pcm_s16be, f32_to_q23, f32_to_s16, outputs_after,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const MAX_STEPS: usize = 200_000;
const DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
enum Kind {
    Vorbis,
    Mp3,
    Alac,
    Aac,
    Pcm,
}

struct Track {
    id: &'static str,
    kind: Kind,
    data: &'static [u8],
    input_fnv: u64,
    frames: usize,
    rate: u32,
    bits: u32,
    seeds: [u32; 3],
    config: &'static [u8],
    packet_sizes: &'static [usize],
    reference: Option<&'static [u8]>,
    reference_fnv: u64,
    lossless_fnv: u64,
}

static TRACKS: &[Track] = &[
    Track {
        // Encoded SHA-256 from s02_vectors.json: 4b53d3e8499deb4f776fc420f52b20ccd8d6c7f7e9d3bad0f723d8276dce2b04
        id: "vorbis_44100",
        kind: Kind::Vorbis,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/vorbis_44100.ogg"
        )),
        input_fnv: 0xbbdad5e420d6428a,
        frames: 22080,
        rate: 44100,
        bits: 16,
        seeds: [1, 2, 0],
        config: &[],
        packet_sizes: &[],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/vorbis_44100.ref.s16"
        ))),
        reference_fnv: 0x1cdcd9ff8c1d4123,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: de7d8f0c485ca2e3708523f9b27b60c23130b0101d0b9cc8bd63968699d53139
        id: "vorbis_48000",
        kind: Kind::Vorbis,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/vorbis_48000.ogg"
        )),
        input_fnv: 0xf94c053f05a74830,
        frames: 24000,
        rate: 48000,
        bits: 16,
        seeds: [3, 4, 0],
        config: &[],
        packet_sizes: &[],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/vorbis_48000.ref.s16"
        ))),
        reference_fnv: 0x2fe2c6908152a919,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: 4821bd0c5beb92ec8e562703edcf344e25709adb9151e65cc765262cb368f45c
        id: "mp3_44100",
        kind: Kind::Mp3,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/mp3_44100.mp3"
        )),
        input_fnv: 0x4518c9c39edcf8d9,
        frames: 22050,
        rate: 44100,
        bits: 16,
        seeds: [5, 6, 0],
        config: &[],
        packet_sizes: &[],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/mp3_44100.ref.s16"
        ))),
        reference_fnv: 0x0c5868a9c6e8f1f2,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: aa911fba4c8f1a17083e85127eee7e749b0b2f8e4284260d4fccb64b2aef868a
        id: "mp3_48000",
        kind: Kind::Mp3,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/mp3_48000.mp3"
        )),
        input_fnv: 0xda1589c2833424c5,
        frames: 24000,
        rate: 48000,
        bits: 16,
        seeds: [7, 8, 0],
        config: &[],
        packet_sizes: &[],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/mp3_48000.ref.s16"
        ))),
        reference_fnv: 0x46a8dd21d7b5b39e,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: 265bc0b9529fae22c83e5ef7a269889ae637b3fb8602e9332b32ac67f76b09ce
        id: "alac_44100_16",
        kind: Kind::Alac,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/alac_44100_16.packets"
        )),
        input_fnv: 0x41fb0464c21fa59d,
        frames: 22050,
        rate: 44100,
        bits: 16,
        seeds: [9, 10, 0],
        config: &[
            0, 0, 16, 0, 0, 16, 40, 10, 14, 2, 0, 255, 0, 0, 44, 171, 0, 12, 229, 122, 0, 0, 172,
            68,
        ],
        packet_sizes: &[11435, 11030, 10816, 10741, 10723, 4130],
        reference: None,
        reference_fnv: 0x0000000000000000,
        lossless_fnv: 0x0ffca3cb285a2d14,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: e81f0873555e89e19d974fae4542a7e4ce5b099a04dd77925c0469c707269ae8
        id: "alac_48000_24",
        kind: Kind::Alac,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/alac_48000_24.packets"
        )),
        input_fnv: 0x860081587dcefc51,
        frames: 24000,
        rate: 48000,
        bits: 24,
        seeds: [11, 12, 13],
        config: &[
            0, 0, 16, 0, 0, 24, 40, 10, 14, 2, 0, 255, 0, 0, 76, 206, 0, 26, 199, 245, 0, 0, 187,
            128,
        ],
        packet_sizes: &[19662, 19322, 19103, 19013, 18957, 16271],
        reference: None,
        reference_fnv: 0x0000000000000000,
        lossless_fnv: 0x9ae44ac037d91f8c,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: ca086db0594432b588d31946f791074e5dc86a0547efe34d39a66219ea536987
        id: "aac_lc_44100",
        kind: Kind::Aac,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/aac_lc_44100.packets"
        )),
        input_fnv: 0x86a9fff0486906dc,
        frames: 24576,
        rate: 44100,
        bits: 16,
        seeds: [14, 15, 0],
        config: &[18, 16],
        packet_sizes: &[
            6, 273, 348, 317, 335, 324, 314, 320, 318, 321, 338, 322, 318, 333, 326, 331, 329, 320,
            328, 339, 328, 318, 352, 157,
        ],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/aac_lc_44100.ref.s16"
        ))),
        reference_fnv: 0xf3adfc64a0c62177,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: d58dfd400d642191cf9f4279b797018aea5efa0412d7be3ec98ed6f890948c8a
        id: "aac_lc_48000",
        kind: Kind::Aac,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/aac_lc_48000.packets"
        )),
        input_fnv: 0x029b82fd9e9f2701,
        frames: 26624,
        rate: 48000,
        bits: 16,
        seeds: [16, 17, 0],
        config: &[17, 144],
        packet_sizes: &[
            6, 307, 328, 310, 328, 305, 294, 303, 320, 307, 300, 303, 305, 325, 290, 315, 303, 304,
            315, 305, 297, 300, 320, 315, 328, 78,
        ],
        reference: Some(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/aac_lc_48000.ref.s16"
        ))),
        reference_fnv: 0x772d5ecf0dbb38e4,
        lossless_fnv: 0x0000000000000000,
    },
    Track {
        // Encoded SHA-256 from s02_vectors.json: ce968a5e37981ed317c2d8bc438c44c8580d79195e6aee4e400f6b0babd024cf
        id: "pcm_s16be_44100",
        kind: Kind::Pcm,
        data: include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-codec/tests/vectors/pcm_s16be_44100.raw"
        )),
        input_fnv: 0x994dcfd2292ef613,
        frames: 22050,
        rate: 44100,
        bits: 16,
        seeds: [18, 19, 0],
        config: &[],
        packet_sizes: &[],
        reference: None,
        reference_fnv: 0x0000000000000000,
        lossless_fnv: 0x6102078e21639f83,
    },
];

fn fnv_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn xorshift32(mut value: u32) -> u32 {
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    value
}

fn tri(n: u64, period: u64, amp: i64) -> i64 {
    let t = (((4 * n) % (4 * period)) as i64 - 2 * period as i64).abs();
    (t * 2 * amp) / (2 * period as i64) - amp
}

fn check_lossless(track: &Track, samples: &[f32]) -> u64 {
    let [mut a, mut b, mut c] = track.seeds;
    let mut hash = FNV_OFFSET;
    let scale = if track.bits == 24 {
        8_388_608.0
    } else {
        32_768.0
    };
    for (n, pair) in samples.as_chunks::<2>().0.iter().enumerate() {
        a = xorshift32(a);
        b = xorshift32(b);
        let n = n as u64;
        let mut left = tri(n, 100, 6000) + tri(n, 37, 2000) + i64::from(a % 601) - 300;
        let mut right = tri(n, 91, 6000) + tri(n, 53, 2000) + i64::from(b % 601) - 300;
        if track.bits == 24 {
            c = xorshift32(c);
            left = left * 256 + i64::from(c % 256);
            c = xorshift32(c);
            right = right * 256 + i64::from(c % 256);
        }
        for (&sample, expected) in pair.iter().zip([left, right]) {
            let actual = (sample * scale).round() as i32;
            assert_eq!(i64::from(actual), expected, "{}: lossless sample", track.id);
            let bytes = actual.to_le_bytes();
            hash = fnv_update(hash, &bytes[..(track.bits as usize / 8)]);
        }
    }
    assert_eq!(hash, track.lossless_fnv, "{}: source digest", track.id);
    hash
}

fn check_lossy(track: &Track, samples: &[f32], reference: &[u8]) -> u64 {
    assert_eq!(
        reference.len(),
        samples.len() * 2,
        "{}: reference length",
        track.id
    );
    assert_eq!(
        fnv_update(FNV_OFFSET, reference),
        track.reference_fnv,
        "{}: reference digest",
        track.id
    );
    let mut hash = FNV_OFFSET;
    let mut max_error = 0_i32;
    let mut square_error = 0_f64;
    for (&sample, pair) in samples.iter().zip(reference.as_chunks::<2>().0.iter()) {
        let actual = f32_to_s16(sample);
        let expected = i16::from_le_bytes([pair[0], pair[1]]);
        let error = (i32::from(actual) - i32::from(expected)).abs();
        max_error = max_error.max(error);
        square_error += f64::from(error) * f64::from(error);
        hash = fnv_update(hash, &actual.to_le_bytes());
    }
    assert!(max_error <= 4, "{}: reference peak tolerance", track.id);
    assert!(
        (square_error / samples.len().max(1) as f64).sqrt() <= 1.5,
        "{}: reference rms tolerance",
        track.id
    );
    hash
}

fn deadline(start: Instant) {
    assert!(
        start.elapsed() <= DEADLINE,
        "fixture exceeded the between-call deadline"
    );
}

fn check_block(info: franken_codec::BlockInfo, rate: u32, position: usize, samples: &[f32]) {
    assert_eq!(
        info.format,
        PcmFormat {
            rate_hz: rate,
            channels: 2
        }
    );
    assert!(!info.format_changed);
    assert_eq!(info.position, position as i64);
    assert_eq!(samples.len(), info.frames * 2);
}

fn container(track: &Track, owned: Vec<u8>, start: Instant) -> Vec<f32> {
    let codec = match track.kind {
        Kind::Vorbis => SourceCodec::OggVorbis,
        Kind::Mp3 => SourceCodec::Mp3,
        _ => unreachable!(),
    };
    let mut dec = ContainerDecoder::open(codec, owned, Caps::default()).expect("container open");
    let mut samples = Vec::new();
    let mut block = Vec::new();
    let mut ended = false;
    for _ in 0..MAX_STEPS {
        deadline(start);
        match dec.next_block(&mut block).expect("container decode") {
            Step::Block(info) => {
                check_block(info, track.rate, samples.len() / 2, &block);
                samples.extend_from_slice(&block);
                assert!(
                    samples.len() <= track.frames * 2,
                    "{}: excess frames",
                    track.id
                );
            }
            Step::End => {
                ended = true;
                break;
            }
        }
    }
    assert!(
        ended && !dec.truncated(),
        "{}: no clean bounded EOF",
        track.id
    );
    assert_eq!(samples.len(), track.frames * 2, "{}: frames", track.id);
    // Use the existing suite's fresh-decoder seek contract. The retained output and
    // the second caller-owned encoded copy both remain in this measured window.
    drop(dec);
    let seek_input = black_box(track.data.to_vec());
    let mut dec = ContainerDecoder::open(codec, seek_input, Caps::default()).expect("seek open");
    let seek_frame = 1_000_u64;
    let seek = dec.seek(seek_frame).expect("fixture seek");
    assert_eq!(seek.target, seek_frame);
    assert!(!seek.saturated);
    let mut compared = seek_frame as usize * 2;
    let mut seek_ended = false;
    for _ in 0..MAX_STEPS {
        deadline(start);
        match dec.next_block(&mut block).expect("seek decode") {
            Step::Block(info) => {
                check_block(info, track.rate, compared / 2, &block);
                let end = compared.checked_add(block.len()).expect("seek offset");
                assert!(end <= samples.len());
                assert!(
                    block
                        .iter()
                        .zip(&samples[compared..end])
                        .all(|(a, b)| a.to_bits() == b.to_bits()),
                    "{}: seek differs",
                    track.id
                );
                compared = end;
            }
            Step::End => {
                seek_ended = true;
                break;
            }
        }
    }
    assert!(
        seek_ended && compared == samples.len(),
        "{}: seek did not reach EOF",
        track.id
    );
    samples
}

fn packets(track: &Track, owned: &[u8], start: Instant) -> Vec<f32> {
    let mut dec = match track.kind {
        Kind::Alac => PacketDecoder::alac(track.config, Caps::default()).expect("ALAC open"),
        Kind::Aac => PacketDecoder::aac_lc(track.config, Caps::default()).expect("AAC open"),
        _ => unreachable!(),
    };
    assert_eq!(
        dec.format(),
        PcmFormat {
            rate_hz: track.rate,
            channels: 2
        }
    );
    assert!(!track.packet_sizes.is_empty() && track.packet_sizes.len() <= MAX_STEPS);
    let mut offset = 0_usize;
    let mut samples = Vec::new();
    let mut block = Vec::new();
    for &size in track.packet_sizes {
        deadline(start);
        let end = offset.checked_add(size).expect("packet offset");
        let packet = owned.get(offset..end).expect("fixture packet boundary");
        let info = dec.decode(packet, &mut block).expect("packet decode");
        check_block(info, track.rate, samples.len() / 2, &block);
        samples.extend_from_slice(&block);
        assert!(
            samples.len() <= track.frames * 2,
            "{}: excess frames",
            track.id
        );
        offset = end;
    }
    assert_eq!(offset, owned.len(), "{}: packet bytes", track.id);
    assert_eq!(samples.len(), track.frames * 2, "{}: frames", track.id);
    samples
}

#[derive(Clone, Copy)]
struct Observation {
    frames: usize,
    decoded_fnv: u64,
    bridge_frames: usize,
    bridge_fnv: u64,
    elapsed_ms: u128,
}

fn exercise(track: &Track) -> Observation {
    let start = Instant::now();
    // This copy is inside the window: encoded input ownership is not silently omitted.
    let owned = black_box(track.data.to_vec());
    assert_eq!(
        fnv_update(FNV_OFFSET, &owned),
        track.input_fnv,
        "{}: encoded digest",
        track.id
    );
    let samples = match track.kind {
        Kind::Vorbis | Kind::Mp3 => container(track, owned, start),
        Kind::Alac | Kind::Aac => packets(track, &owned, start),
        Kind::Pcm => {
            let mut samples = Vec::new();
            let frames = decode_pcm_s16be(&owned, 2, &mut samples).expect("PCM decode");
            assert_eq!(frames, track.frames);
            samples
        }
    };
    assert_eq!(samples.len(), track.frames * 2);
    let decoded_fnv = match track.reference {
        Some(reference) => check_lossy(track, &samples, reference),
        None => check_lossless(track, &samples),
    };
    let mut adapter = RateAdapter::new(track.rate, 2).expect("rate adapter");
    let mut output = Vec::new();
    adapter
        .process_f32(&samples, &mut output)
        .expect("rate bridge");
    let expected_frames = if track.rate == 44_100 {
        assert_eq!(adapter.plan(), RatePlan::Bridge);
        outputs_after(track.frames as u64) as usize
    } else {
        assert_eq!(adapter.plan(), RatePlan::Direct);
        track.frames
    };
    assert_eq!(output.len(), expected_frames * 2);
    if track.rate == 48_000 {
        assert!(
            output
                .iter()
                .zip(&samples)
                .all(|(&out, &input)| out == f32_to_q23(input))
        );
    }
    let mut bridge_fnv = FNV_OFFSET;
    for value in &output {
        bridge_fnv = fnv_update(bridge_fnv, &value.to_be_bytes());
    }
    deadline(start);
    black_box(Observation {
        frames: track.frames,
        decoded_fnv,
        bridge_frames: expected_frames,
        bridge_fnv,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn emit(track: &Track, phase: &str, obs: Observation, heap: HeapWindow, calls: AllocSnapshot) {
    let release = if heap.net_bytes == 0 {
        "net_zero"
    } else {
        "unknown_nonzero_net"
    };
    println!(
        "S02-HEAP {{\"schema\":\"s02.codec-heap.v1\",\"id\":\"{}\",\"phase\":\"{}\",\"scope\":\"calling_thread_owned_input_decode_seek_rate\",\"release\":\"{}\",\"frames\":{},\"decoded_fnv1a64\":\"{:016x}\",\"bridge_frames\":{},\"bridge_fnv1a64\":\"{:016x}\",\"peak_requested_bytes\":{},\"net_requested_bytes\":{},\"allocations\":{},\"reallocations\":{},\"deallocations\":{},\"bytes_requested\":{},\"elapsed_ms\":{}}}",
        track.id,
        phase,
        release,
        obs.frames,
        obs.decoded_fnv,
        obs.bridge_frames,
        obs.bridge_fnv,
        heap.peak_above_start,
        heap.net_bytes,
        calls.allocations,
        calls.reallocations,
        calls.deallocations,
        calls.bytes_requested,
        obs.elapsed_ms
    );
}

#[test]
fn s02_codec_internal_heap_tracks_owned_inputs_and_warm_release() {
    assert!(is_active(), "allocator activity sensor must be live");
    assert!(heap_is_tracked(), "heap high-water sensor must be live");
    for (index, track) in TRACKS.iter().enumerate() {
        // First-use includes any initialization actually done on this calling thread; earlier
        // tracks can already have initialized shared statics, so it is not universally cold.
        let ((first, first_calls), first_heap) = measure_heap(|| measure(|| exercise(track)));
        assert!(first_heap.peak_above_start >= track.data.len());
        assert!(first_calls.allocations > 0 && first_calls.bytes_requested >= track.data.len());
        let phase = if index == 0 {
            "process_first_use"
        } else {
            "track_first_use_after_shared"
        };
        emit(track, phase, first, first_heap, first_calls);
        let ((warm, warm_calls), warm_heap) = measure_heap(|| measure(|| exercise(track)));
        assert!(warm_heap.peak_above_start >= track.data.len());
        assert!(warm_calls.allocations > 0 && warm_calls.bytes_requested >= track.data.len());
        emit(track, "warm", warm, warm_heap, warm_calls);
        assert_eq!(
            warm_heap.net_bytes, 0,
            "{}: warm scope retained or released unexplained bytes",
            track.id
        );
        assert_eq!(
            (
                warm.frames,
                warm.decoded_fnv,
                warm.bridge_frames,
                warm.bridge_fnv
            ),
            (
                first.frames,
                first.decoded_fnv,
                first.bridge_frames,
                first.bridge_fnv
            ),
            "{}: warm output changed",
            track.id
        );
    }
}
