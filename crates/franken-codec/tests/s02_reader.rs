//! Reader tests use the same actual encoded vectors as the existing S02 tests.
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

use franken_codec::{
    Caps, CodecError, ContainerDecoder, SourceCodec, SourceReaderLimits, Step, f32_to_s16,
};
use serde_json::Value;

const MANIFEST: &str = include_str!("vectors/s02_vectors.json");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn limits() -> SourceReaderLimits {
    SourceReaderLimits {
        max_read_calls: 100_000,
        max_reads_per_operation: 100_000,
        max_seek_calls: 1_000,
        max_read_chunk_bytes: 17,
    }
}

struct Controlled {
    file: File,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    max_request: Arc<AtomicUsize>,
}

impl Read for Controlled {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.max_request.fetch_max(output.len(), Ordering::Relaxed);
        match self.mode.load(Ordering::Relaxed) {
            1 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            2 => Ok(0),
            _ => self.file.read(output),
        }
    }
}
impl Seek for Controlled {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.file.seek(from)
    }
}

fn controlled(
    name: &str,
) -> (
    Controlled,
    u64,
    Arc<AtomicU8>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let file = File::open(fixture(name)).expect("encoded fixture");
    let len = file.metadata().expect("metadata").len();
    let mode = Arc::new(AtomicU8::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let max = Arc::new(AtomicUsize::new(0));
    (
        Controlled {
            file,
            mode: Arc::clone(&mode),
            calls: Arc::clone(&calls),
            max_request: Arc::clone(&max),
        },
        len,
        mode,
        calls,
        max,
    )
}

fn drain(decoder: &mut ContainerDecoder) -> Vec<f32> {
    let mut result = Vec::new();
    let mut block = Vec::new();
    for _ in 0..200_000 {
        match decoder.next_block(&mut block).expect("decode") {
            Step::Block(info) => {
                assert_eq!(block.len(), info.frames * usize::from(info.format.channels));
                result.extend_from_slice(&block);
            }
            Step::End => return result,
        }
    }
    panic!("decoder did not finish")
}

fn manifest_track(id: &str) -> Value {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("vector manifest");
    manifest["tracks"]
        .as_array()
        .expect("tracks")
        .iter()
        .find(|track| track["id"] == id)
        .unwrap_or_else(|| panic!("missing manifest track {id}"))
        .clone()
}

fn reference_pcm(track: &Value) -> Vec<i16> {
    let reference = &track["reference"];
    let path = reference["file"].as_str().expect("reference file");
    let bytes = std::fs::read(fixture(path)).expect("committed reference PCM");
    assert_eq!(
        bytes.len() as u64,
        reference["bytes"].as_u64().expect("reference bytes")
    );
    let mut fnv = 0xcbf29ce484222325u64;
    for byte in &bytes {
        fnv = (fnv ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    assert_eq!(
        format!("{fnv:016x}"),
        reference["fnv1a64"].as_str().expect("reference hash")
    );
    let (pairs, remainder) = bytes.as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "reference PCM must have complete samples"
    );
    pairs.iter().map(|&pair| i16::from_le_bytes(pair)).collect()
}

fn pcm_errors(decoded: &[i16], reference: &[i16]) -> (i32, f64) {
    assert_eq!(decoded.len(), reference.len(), "compared sample count");
    assert!(
        !decoded.is_empty(),
        "reference comparison must not be empty"
    );
    let mut max = 0i32;
    let mut sum = 0f64;
    for (&actual, &expected) in decoded.iter().zip(reference) {
        let error = (i32::from(actual) - i32::from(expected)).abs();
        max = max.max(error);
        sum += f64::from(error) * f64::from(error);
    }
    (max, (sum / decoded.len() as f64).sqrt())
}

#[test]
fn s02_reader_matches_manifest_frames_and_independent_pcm_reference() {
    for (id, codec) in [
        ("vorbis_44100", SourceCodec::OggVorbis),
        ("vorbis_48000", SourceCodec::OggVorbis),
        ("mp3_44100", SourceCodec::Mp3),
        ("mp3_48000", SourceCodec::Mp3),
    ] {
        let track = manifest_track(id);
        let frames = track["expected_frames"].as_u64().expect("expected frames") as usize;
        let channels = track["channels"].as_u64().expect("channels") as usize;
        assert_eq!(channels, 2, "{id}: fixture channel count");
        assert_eq!(track["reference"]["frames"].as_u64(), Some(frames as u64));
        let filename = track["file"].as_str().expect("encoded filename");
        let (source, len, _, _, _) = controlled(filename);
        assert_eq!(Some(len), track["bytes"].as_u64(), "{id}: encoded size");
        let mut reader =
            ContainerDecoder::open_reader(codec, source, len, Caps::default(), limits())
                .expect("reader open");
        let samples = drain(&mut reader);
        assert_eq!(
            samples.len(),
            frames * channels,
            "{id}: gapless frame count"
        );
        assert!(
            samples.iter().all(|sample| sample.is_finite()),
            "{id}: non-finite sample"
        );
        let samples: Vec<i16> = samples.into_iter().map(f32_to_s16).collect();
        let reference = reference_pcm(&track);
        let (max, rms) = pcm_errors(&samples, &reference);
        let tolerance = &track["tolerance"];
        assert_eq!(tolerance["max_abs_lsb"].as_f64(), Some(4.0));
        assert_eq!(tolerance["rms_lsb"].as_f64(), Some(1.5));
        assert!(f64::from(max) <= 4.0, "{id}: peak {max} LSB exceeds 4");
        assert!(rms <= 1.5, "{id}: RMS {rms} LSB exceeds 1.5");
    }
}

#[test]
fn s02_reference_oracle_rejects_retained_bad_vorbis_reference() {
    let track = manifest_track("vorbis_44100");
    let good = reference_pcm(&track);
    let bad_name = track["retained_bad_reference"]["file"]
        .as_str()
        .expect("negative reference");
    let bad = std::fs::read(fixture(bad_name)).expect("retained negative reference");
    let (pairs, remainder) = bad.as_chunks::<2>();
    assert!(remainder.is_empty());
    let bad: Vec<i16> = pairs.iter().map(|&pair| i16::from_le_bytes(pair)).collect();
    let (max, rms) = pcm_errors(&bad, &good);
    assert!(max > 4, "negative reference must fail the peak threshold");
    assert!(rms > 1.5, "negative reference must fail the RMS threshold");
}

#[test]
fn s02_file_reader_matches_vec_and_seek_with_bounded_reads() {
    for (name, codec) in [
        ("vorbis_44100.ogg", SourceCodec::OggVorbis),
        ("mp3_44100.mp3", SourceCodec::Mp3),
    ] {
        let bytes = std::fs::read(fixture(name)).expect("fixture");
        let mut reference =
            ContainerDecoder::open(codec, bytes, Caps::default()).expect("vec open");
        let expected = drain(&mut reference);
        assert!(!expected.is_empty());
        let (source, len, _, calls, max) = controlled(name);
        let mut reader =
            ContainerDecoder::open_reader(codec, source, len, Caps::default(), limits())
                .expect("reader open");
        assert_eq!(drain(&mut reader), expected, "{name} continuous decode");
        assert!(calls.load(Ordering::Relaxed) > 1);
        assert!(max.load(Ordering::Relaxed) <= 17);
        assert!(!reader.truncated());

        let (source, len, _, _, _) = controlled(name);
        let mut reader =
            ContainerDecoder::open_reader(codec, source, len, Caps::default(), limits())
                .expect("reader open for seek");
        let seek = reader.seek(1000).expect("seek");
        assert_eq!(seek.target, 1000);
        assert_eq!(drain(&mut reader), expected[2000..], "{name} seek output");
    }
}

#[test]
fn s02_reader_rejects_size_and_work_limits_before_reading() {
    let (source, len, _, calls, _) = controlled("vorbis_44100.ogg");
    let caps = Caps {
        max_input_bytes: len as usize - 1,
        ..Caps::default()
    };
    assert!(matches!(
        ContainerDecoder::open_reader(SourceCodec::OggVorbis, source, len, caps, limits()),
        Err(CodecError::InputTooLarge { .. })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let (source, len, _, calls, _) = controlled("vorbis_44100.ogg");
    let bad = SourceReaderLimits {
        max_read_chunk_bytes: 0,
        ..limits()
    };
    assert!(matches!(
        ContainerDecoder::open_reader(SourceCodec::OggVorbis, source, len, Caps::default(), bad),
        Err(CodecError::Limit(_))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let (source, len, _, calls, _) = controlled("vorbis_44100.ogg");
    assert!(matches!(
        ContainerDecoder::open_reader(
            SourceCodec::OggVorbis,
            source,
            len + 1,
            Caps::default(),
            limits()
        ),
        Err(CodecError::Seek(_))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let (source, len, _, _, _) = controlled("vorbis_44100.ogg");
    let tiny = SourceReaderLimits {
        max_read_calls: 1,
        max_reads_per_operation: 1,
        ..limits()
    };
    assert!(matches!(
        ContainerDecoder::open_reader(SourceCodec::OggVorbis, source, len, Caps::default(), tiny),
        Err(CodecError::Limit(_))
    ));
}

#[test]
fn s02_reader_operation_counter_accepts_upper_bound_and_rejects_overflow() {
    let maximum = SourceReaderLimits {
        max_read_calls: 1_000_000,
        max_reads_per_operation: 1_000_000,
        ..limits()
    };
    let (source, len, _, _, _) = controlled("mp3_44100.mp3");
    let mut reader =
        ContainerDecoder::open_reader(SourceCodec::Mp3, source, len, Caps::default(), maximum)
            .expect("maximum admissible read budget");
    let mut out = Vec::new();
    assert!(matches!(reader.next_block(&mut out), Ok(Step::Block(_))));
    assert!(!out.is_empty());

    let (source, len, _, calls, _) = controlled("mp3_44100.mp3");
    let above = SourceReaderLimits {
        max_reads_per_operation: 1_000_001,
        ..maximum
    };
    assert!(matches!(
        ContainerDecoder::open_reader(SourceCodec::Mp3, source, len, Caps::default(), above),
        Err(CodecError::Limit(_))
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

fn observe(mut decoder: ContainerDecoder) -> (Vec<f32>, Option<CodecError>, bool) {
    let mut result = Vec::new();
    let mut block = Vec::new();
    for _ in 0..200_000 {
        match decoder.next_block(&mut block) {
            Ok(Step::Block(_)) => result.extend_from_slice(&block),
            Ok(Step::End) => return (result, None, decoder.truncated()),
            Err(error) => return (result, Some(error), decoder.truncated()),
        }
    }
    panic!("decoder did not finish")
}

#[test]
fn s02_reader_actual_truncated_bytes_match_existing_vec_contract() {
    for (name, codec) in [
        ("vorbis_44100.ogg", SourceCodec::OggVorbis),
        ("mp3_44100.mp3", SourceCodec::Mp3),
    ] {
        let complete = std::fs::read(fixture(name)).expect("fixture");
        let mut partial_count = 0;
        for cut in [
            complete.len() * 3 / 4,
            complete.len() - 200,
            complete.len() - 1,
        ] {
            let bytes = complete[..cut].to_vec();
            let vec_result = ContainerDecoder::open(codec, bytes.clone(), Caps::default());
            let reader_result = ContainerDecoder::open_reader(
                codec,
                std::io::Cursor::new(bytes),
                cut as u64,
                Caps::default(),
                limits(),
            );
            match (vec_result, reader_result) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(observe(a), observe(b), "{name} cut {cut}");
                    partial_count += 1;
                }
                (Err(a), Err(b)) => assert_eq!(a, b, "{name} cut {cut}"),
                _ => panic!("{name} cut {cut}: reader and Vec open differed"),
            }
        }
        assert!(
            partial_count > 0,
            "{name}: no truncated case reached the demuxer"
        );
    }
}

#[test]
fn s02_reader_shortage_and_premature_eof_poison_parser_and_clear_output() {
    for (mode_value, message) in [
        (1, "temporarily unavailable"),
        (2, "before declared length"),
    ] {
        let (source, len, mode, calls, _) = controlled("mp3_44100.mp3");
        let mut decoder =
            ContainerDecoder::open_reader(SourceCodec::Mp3, source, len, Caps::default(), limits())
                .expect("open");
        let mut output = Vec::new();
        assert!(matches!(
            decoder.next_block(&mut output),
            Ok(Step::Block(_))
        ));
        assert!(
            !output.is_empty(),
            "healthy block must precede fault injection"
        );
        let calls_before_fault = calls.load(Ordering::Relaxed);
        mode.store(mode_value, Ordering::Relaxed);
        let mut failure = None;
        for _ in 0..200_000 {
            output.resize(output.len() + 1, 123.0);
            match decoder.next_block(&mut output) {
                Err(error) => {
                    failure = Some(error);
                    break;
                }
                Ok(Step::Block(_)) => {}
                Ok(Step::End) => panic!("source fault was mistaken for EOF"),
            }
        }
        let error = failure.expect("decoder did not report source failure");
        assert!(
            calls.load(Ordering::Relaxed) > calls_before_fault,
            "injection must reach the inner reader"
        );
        assert!(
            matches!(&error, CodecError::Io(s) if s.contains(message)),
            "{error:?}"
        );
        assert!(output.is_empty());
        let calls_at_failure = calls.load(Ordering::Relaxed);
        mode.store(0, Ordering::Relaxed);
        output.push(123.0);
        assert_eq!(decoder.next_block(&mut output), Err(error));
        assert!(output.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), calls_at_failure);
    }
}

struct NonSeekable;
impl Read for NonSeekable {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("must reject before reading")
    }
}
impl Seek for NonSeekable {
    fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
        Err(io::Error::other("not seekable"))
    }
}

#[test]
fn s02_reader_refuses_nonseekable_and_classifies_faults_during_probe() {
    assert!(matches!(
        ContainerDecoder::open_reader(SourceCodec::Mp3, NonSeekable, 1, Caps::default(), limits()),
        Err(CodecError::Seek(_))
    ));
    for (mode_value, message) in [
        (1, "temporarily unavailable"),
        (2, "before declared length"),
    ] {
        let (source, len, mode, _, _) = controlled("vorbis_44100.ogg");
        mode.store(mode_value, Ordering::Relaxed);
        let result = ContainerDecoder::open_reader(
            SourceCodec::OggVorbis,
            source,
            len,
            Caps::default(),
            limits(),
        );
        assert!(matches!(result, Err(CodecError::Io(s)) if s.contains(message)));
    }
}
