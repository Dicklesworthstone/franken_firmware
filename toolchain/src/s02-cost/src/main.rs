//! S02 finite MP3 decoder probe under the D02 QEMU MIPS instruction ruler.
//!
//! Probe only: three real reader decodes of one immutable fixture. Each
//! `next_block` call is timed separately; source opening, calibration, PCM
//! comparison, reporting and cleanup are outside those intervals. The timed
//! scope includes demux, bounded reader work, decoder and output allocations.
//! Results are raw CP0 ticks, not instructions, CPU cycles, real-board time,
//! RSS, stack use or a performance admission. The host must qualify the same
//! boot's before/after D02-style spin rulers and counter-wrap assumptions.

#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]

use std::hint::black_box;
use std::io::{Cursor, Write};
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::Duration;

use franken_codec::{Caps, ContainerDecoder, SourceCodec, SourceReaderLimits, Step, f32_to_s16};

const ENCODED: &[u8] =
    include_bytes!("../../../../crates/franken-codec/tests/vectors/mp3_48000.mp3");
const REFERENCE: &[u8] =
    include_bytes!("../../../../crates/franken-codec/tests/vectors/mp3_48000.ref.s16");
const ENCODED_FNV: u64 = 0xda15_89c2_8334_24c5;
const REFERENCE_FNV: u64 = 0x46a8_dd21_d7b5_b39e;
const EXPECTED_FRAMES: usize = 24_000;
const CHANNELS: usize = 2;
const REPS: usize = 3;
const MAX_PULLS: usize = 1_000;
const RULER_REPS: usize = 2;
const SPIN3_ITERATIONS: [u32; 4] = [1_300_000, 5_000_000, 12_000_000, 20_000_000];
const SPIN5_ITERATIONS: [u32; 4] = [800_000, 3_000_000, 7_200_000, 12_000_000];

// Copied narrowly from the existing D02 ruler, for its admitted MIPS32r2
// Malta/Linux QEMU environment only. Compiler memory fences bracket every pull.
#[cfg(target_arch = "mips")]
#[inline(always)]
fn count() -> u32 {
    let value: u32;
    // SAFETY: `rdhwr` reads a user-enabled register; no stack or memory is
    // accessed. The block is not marked `nomem`, preserving compiler ordering.
    // The compiler may choose $1 for the output. Scoped `noat` permits that
    // explicit register without an assembler temporary; push/pop restore state.
    unsafe {
        core::arch::asm!(
            ".set push", ".set noat", "rdhwr {0}, $2", ".set pop",
            out(reg) value, options(nostack)
        );
    }
    value
}
#[cfg(not(target_arch = "mips"))]
fn count() -> u32 {
    0
}

#[cfg(target_arch = "mips")]
#[inline(never)]
fn spin3(iterations: u32) -> u32 {
    let start = count();
    // SAFETY: only general registers are touched; the explicit delay slot and
    // noreorder make the body exactly three instructions per positive iteration.
    unsafe {
        core::arch::asm!(".set push", ".set noreorder", "2:",
            "addiu {n}, {n}, -1", "bnez {n}, 2b", "nop", ".set pop",
            n = inout(reg) iterations => _, options(nostack, nomem));
    }
    count().wrapping_sub(start)
}
#[cfg(target_arch = "mips")]
#[inline(never)]
fn spin5(iterations: u32) -> u32 {
    let start = count();
    // SAFETY: as above; the two additional scratch-register instructions
    // cancel and make the body exactly five instructions per iteration.
    unsafe {
        core::arch::asm!(".set push", ".set noreorder", "2:",
            "addiu {n}, {n}, -1", "addiu {t}, {t}, 1", "addiu {t}, {t}, -1",
            "bnez {n}, 2b", "nop", ".set pop",
            n = inout(reg) iterations => _, t = inout(reg) 0u32 => _,
            options(nostack, nomem));
    }
    count().wrapping_sub(start)
}
#[cfg(not(target_arch = "mips"))]
fn spin3(_: u32) -> u32 {
    0
}
#[cfg(not(target_arch = "mips"))]
fn spin5(_: u32) -> u32 {
    0
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

struct Oracle<'a> {
    reference: &'a [u8],
    samples: usize,
    max_abs: u32,
    sum_sq: u64,
}
impl<'a> Oracle<'a> {
    fn new(reference: &'a [u8]) -> Self {
        Self {
            reference,
            samples: 0,
            max_abs: 0,
            sum_sq: 0,
        }
    }
    fn add(&mut self, output: &[f32]) -> Result<(), &'static str> {
        for &sample in output {
            if !sample.is_finite() {
                return Err("nonfinite_pcm");
            }
            let offset = self.samples.checked_mul(2).ok_or("sample_overflow")?;
            let bytes = self
                .reference
                .get(offset..offset + 2)
                .ok_or("too_many_samples")?;
            let expected = i16::from_le_bytes([bytes[0], bytes[1]]);
            let actual = f32_to_s16(sample);
            let error = (i32::from(actual) - i32::from(expected)).unsigned_abs();
            self.max_abs = self.max_abs.max(error);
            self.sum_sq = self
                .sum_sq
                .checked_add(u64::from(error) * u64::from(error))
                .ok_or("error_overflow")?;
            self.samples += 1;
        }
        Ok(())
    }
    fn finish(&self, expected_samples: usize) -> Result<(), &'static str> {
        if expected_samples == 0
            || self.samples != expected_samples
            || self.reference.len() != expected_samples * 2
        {
            return Err("sample_count");
        }
        // Exact integer form of RMS <= 1.5 LSB, with the existing max <= 4.
        if self.max_abs > 4 || u128::from(self.sum_sq) * 4 > (expected_samples as u128) * 9 {
            return Err("pcm_tolerance");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Ruler {
    shape: u8,
    iterations: u32,
    ticks: u32,
}
fn ruler() -> Vec<Ruler> {
    let mut values = Vec::with_capacity(RULER_REPS * 8);
    for _ in 0..RULER_REPS {
        for iterations in SPIN3_ITERATIONS {
            values.push(Ruler {
                shape: 3,
                iterations,
                ticks: spin3(iterations),
            });
        }
        for iterations in SPIN5_ITERATIONS {
            values.push(Ruler {
                shape: 5,
                iterations,
                ticks: spin5(iterations),
            });
        }
    }
    values
}

fn empty_reads() -> [u32; 8] {
    let mut values = [0; 8];
    for value in &mut values {
        let start = count();
        *value = count().wrapping_sub(start);
    }
    values
}

struct Run {
    blocks: usize,
    frames: usize,
    pull_ticks_sum: u64,
    pull_ticks_max: u32,
    eof_ticks: u32,
    max_abs: u32,
    sum_sq: u64,
}
fn decode_one(encoded: &'static [u8]) -> Result<Run, String> {
    let limits = SourceReaderLimits {
        max_read_calls: 100_000,
        max_reads_per_operation: 100_000,
        max_seek_calls: 1_000,
        max_read_chunk_bytes: 32 * 1024,
    };
    let mut decoder = ContainerDecoder::open_reader(
        SourceCodec::Mp3,
        Cursor::new(encoded),
        encoded.len() as u64,
        Caps::default(),
        limits,
    )
    .map_err(|e| format!("open: {e}"))?;
    let mut output = Vec::new();
    let mut oracle = Oracle::new(REFERENCE);
    let mut blocks = 0usize;
    let mut frames = 0usize;
    let mut ticks_sum = 0u64;
    let mut ticks_max = 0u32;
    for _ in 0..MAX_PULLS {
        compiler_fence(Ordering::SeqCst);
        let start = count();
        compiler_fence(Ordering::SeqCst);
        let step = black_box(decoder.next_block(black_box(&mut output)));
        compiler_fence(Ordering::SeqCst);
        let elapsed = count().wrapping_sub(start);
        compiler_fence(Ordering::SeqCst);
        match step.map_err(|e| format!("decode: {e}"))? {
            Step::Block(info) => {
                if info.format.rate_hz != 48_000
                    || usize::from(info.format.channels) != CHANNELS
                    || output.len() != info.frames * CHANNELS
                    || info.format_changed
                {
                    return Err("unexpected_format_or_block".into());
                }
                blocks += 1;
                frames = frames.checked_add(info.frames).ok_or("frame_overflow")?;
                ticks_sum = ticks_sum
                    .checked_add(u64::from(elapsed))
                    .ok_or("tick_overflow")?;
                ticks_max = ticks_max.max(elapsed);
                oracle.add(&output).map_err(str::to_owned)?;
            }
            Step::End => {
                if frames != EXPECTED_FRAMES
                    || blocks == 0
                    || decoder.truncated()
                    || decoder.stats().decode_errors != 0
                {
                    return Err("frame_count_or_decode_status".into());
                }
                oracle
                    .finish(EXPECTED_FRAMES * CHANNELS)
                    .map_err(str::to_owned)?;
                return Ok(Run {
                    blocks,
                    frames,
                    pull_ticks_sum: ticks_sum,
                    pull_ticks_max: ticks_max,
                    eof_ticks: elapsed,
                    max_abs: oracle.max_abs,
                    sum_sq: oracle.sum_sq,
                });
            }
        }
    }
    Err("pull_limit".into())
}

/// A caller-provisioned test fixture is required in addition to the target and
/// PID guards: a target triple by itself cannot identify a QEMU guest.
#[cfg(all(target_os = "linux", target_arch = "mips", target_endian = "big"))]
const GUEST_MARKER: &[u8] = b"ffw-s02-qemu-only-v1\n";
const IS_GUEST_TARGET: bool = cfg!(all(
    target_os = "linux",
    target_arch = "mips",
    target_endian = "big"
));

fn guest_shutdown_allowed(guest_target: bool, pid: u32, opted_in: bool) -> bool {
    guest_target && pid == 1 && opted_in
}

#[cfg(all(target_os = "linux", target_arch = "mips", target_endian = "big"))]
fn guest_marker_present() -> bool {
    use std::io::Read as _;
    let Ok(mut file) = std::fs::File::open("/ffw-s02-qemu-pid1") else {
        return false;
    };
    let mut bytes = [0u8; GUEST_MARKER.len()];
    let mut extra = [0u8; 1];
    file.read_exact(&mut bytes).is_ok()
        && bytes.as_slice() == GUEST_MARKER
        && matches!(file.read(&mut extra), Ok(0))
}

#[cfg(not(all(target_os = "linux", target_arch = "mips", target_endian = "big")))]
fn guest_marker_present() -> bool {
    false
}

#[cfg(all(target_os = "linux", target_arch = "mips", target_endian = "big"))]
unsafe extern "C" {
    fn reboot(command: core::ffi::c_int) -> core::ffi::c_int;
}

/// Fallible transcript writer. A partial or failed write is retained as an
/// incomplete transcript even if later writes or flushes succeed.
struct Report<O: Write, E: Write> {
    out: O,
    err: E,
    failed: bool,
}
impl<O: Write, E: Write> Report<O, E> {
    fn out(&mut self, message: std::fmt::Arguments<'_>) {
        if writeln!(self.out, "{message}").is_err() {
            self.failed = true;
        }
    }
    fn err(&mut self, message: std::fmt::Arguments<'_>) {
        if writeln!(self.err, "{message}").is_err() {
            self.failed = true;
        }
    }
    fn flush(&mut self) {
        let stdout_ok = self.out.flush().is_ok();
        let stderr_ok = self.err.flush().is_ok();
        self.failed |= !stdout_ok || !stderr_ok;
    }
    fn finish_status(&mut self, status: i32) -> i32 {
        self.flush();
        if self.failed {
            // Try both streams: the diagnostic stream itself may be broken.
            // If both fail, the external judge must treat the transcript as incomplete.
            let _ = writeln!(self.out, "FFW_S02COST_OUTPUT_FAILED");
            let _ = writeln!(self.err, "FFW_S02COST_OUTPUT_FAILED");
            let _ = self.out.flush();
            let _ = self.err.flush();
            if status == 0 { 1 } else { status }
        } else {
            status
        }
    }
}

fn completion<O: Write, E: Write>(
    report: &mut Report<O, E>,
    status: i32,
    guest_target: bool,
    pid: u32,
    opted_in: bool,
) -> (i32, bool) {
    (
        report.finish_status(status),
        guest_shutdown_allowed(guest_target, pid, opted_in),
    )
}

/// Flush every handled outcome before exit or the explicitly admitted QEMU
/// PID 1 reboot. A returned reboot is a failure, never a successful run.
fn finish<O: Write, E: Write>(status: i32, guest_opted_in: bool, report: &mut Report<O, E>) -> ! {
    let (status, reboot_allowed) = completion(
        report,
        status,
        IS_GUEST_TARGET,
        std::process::id(),
        guest_opted_in,
    );
    #[cfg(all(target_os = "linux", target_arch = "mips", target_endian = "big"))]
    if reboot_allowed {
        const RB_AUTOBOOT: core::ffi::c_int = 0x0123_4567;
        // SAFETY: this libc call is reachable only with the compiled BE-MIPS
        // Linux target, PID 1, and the explicit QEMU-initramfs marker. It
        // returns only on failure. It does not alter Rust-managed memory.
        let result = unsafe { reboot(RB_AUTOBOOT) };
        report.err(format_args!("FFW_S02COST_REBOOT_FAILED status={result}"));
        report.flush();
        std::process::exit(if status == 0 { 1 } else { status });
    }
    #[cfg(not(all(target_os = "linux", target_arch = "mips", target_endian = "big")))]
    let _ = reboot_allowed;
    std::process::exit(status);
}

fn main() {
    let mut report = Report {
        out: std::io::stdout(),
        err: std::io::stderr(),
        failed: false,
    };
    if !IS_GUEST_TARGET {
        report.err(format_args!(
            "FFW_S02COST_REFUSED reason=requires_big_endian_mips_guest"
        ));
        finish(2, false, &mut report);
    }
    if std::process::id() != 1 {
        report.err(format_args!(
            "FFW_S02COST_REFUSED reason=requires_guest_pid1"
        ));
        finish(2, false, &mut report);
    }
    let guest_opted_in = guest_marker_present();
    if !guest_opted_in {
        report.err(format_args!(
            "FFW_S02COST_REFUSED reason=missing_qemu_guest_marker"
        ));
        finish(2, false, &mut report);
    }
    report.out(format_args!("FFW_S02COST_ALIVE"));
    report.flush();
    if report.failed {
        finish(1, guest_opted_in, &mut report);
    }
    std::thread::sleep(Duration::from_millis(2000));
    if ENCODED.len() != 8_877
        || REFERENCE.len() != 96_000
        || fnv1a64(ENCODED) != ENCODED_FNV
        || fnv1a64(REFERENCE) != REFERENCE_FNV
    {
        report.err(format_args!("FFW_S02COST_REFUSED reason=fixture_identity"));
        finish(2, guest_opted_in, &mut report);
    }
    let floor_before = empty_reads();
    let before = ruler();
    let mut runs = Vec::with_capacity(REPS);
    let mut failure = None;
    for _ in 0..REPS {
        match decode_one(ENCODED) {
            Ok(run) => runs.push(run),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let after = ruler();
    let floor_after = empty_reads();
    report.out(format_args!(
        "FFW_S02COST_BEGIN version=1 codec=mp3_48000 frames_expected={EXPECTED_FRAMES} reps={REPS} input_fnv={ENCODED_FNV:016x} reference_fnv={REFERENCE_FNV:016x}"
    ));
    report.out(format_args!(
        "FFW_S02COST_EMPTY phase=before ticks={floor_before:?}"
    ));
    report.out(format_args!(
        "FFW_S02COST_EMPTY phase=after ticks={floor_after:?}"
    ));
    for (phase, readings) in [("before", before), ("after", after)] {
        for (index, r) in readings.iter().enumerate() {
            report.out(format_args!(
                "FFW_S02COST_RULER phase={phase} rep={} shape={} iterations={} ticks={}",
                index / 8,
                r.shape,
                r.iterations,
                r.ticks
            ));
        }
    }
    for (rep, run) in runs.iter().enumerate() {
        report.out(format_args!(
            "FFW_S02COST_RUN rep={rep} frames={} blocks={} pull_ticks_sum={} pull_ticks_max={} eof_ticks={} peak_lsb={} sum_sq_lsb={} samples={}",
            run.frames,
            run.blocks,
            run.pull_ticks_sum,
            run.pull_ticks_max,
            run.eof_ticks,
            run.max_abs,
            run.sum_sq,
            run.frames * CHANNELS
        ));
    }
    if let Some(error) = failure {
        report.err(format_args!("FFW_S02COST_FAIL reason={error}"));
        finish(1, guest_opted_in, &mut report);
    }
    report.out(format_args!(
        "FFW_S02COST_END checked_reps={} counter_wrap_unresolved=1 stack_unmeasured=1 allocator_unmeasured=1",
        runs.len()
    ));
    finish(0, guest_opted_in, &mut report);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestWriter {
        bytes: Vec<u8>,
        fail_write: bool,
        fail_flush: bool,
        flushes: usize,
    }
    impl Write for TestWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected",
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn reporting_failures_never_prevent_guarded_shutdown_decision() {
        let mut good = Report {
            out: TestWriter::default(),
            err: TestWriter::default(),
            failed: false,
        };
        good.out(format_args!("FFW_S02COST_ALIVE"));
        assert_eq!(completion(&mut good, 0, true, 1, true), (0, true));
        assert_eq!(good.out.bytes, b"FFW_S02COST_ALIVE\n");

        for (out_write, err_write, out_flush, err_flush) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
            (true, true, true, true),
        ] {
            let mut report = Report {
                out: TestWriter {
                    fail_write: out_write,
                    fail_flush: out_flush,
                    ..TestWriter::default()
                },
                err: TestWriter {
                    fail_write: err_write,
                    fail_flush: err_flush,
                    ..TestWriter::default()
                },
                failed: false,
            };
            report.out(format_args!("output"));
            report.err(format_args!("diagnostic"));
            assert_eq!(completion(&mut report, 0, true, 1, true), (1, true));
            assert!(report.failed);
            assert!(report.out.flushes > 0 && report.err.flushes > 0);
            if !out_write {
                assert!(
                    report
                        .out
                        .bytes
                        .windows(b"FFW_S02COST_OUTPUT_FAILED".len())
                        .any(|window| window == b"FFW_S02COST_OUTPUT_FAILED")
                );
            }
            if !err_write {
                assert!(
                    report
                        .err
                        .bytes
                        .windows(b"FFW_S02COST_OUTPUT_FAILED".len())
                        .any(|window| window == b"FFW_S02COST_OUTPUT_FAILED")
                );
            }
            assert_eq!(completion(&mut report, 0, true, 2, true), (1, false));
            assert_eq!(completion(&mut report, 0, false, 1, true), (1, false));
            assert_eq!(completion(&mut report, 0, true, 1, false), (1, false));
        }
        let mut failure = Report {
            out: TestWriter::default(),
            err: TestWriter::default(),
            failed: false,
        };
        failure.err.fail_write = true;
        failure.err(format_args!("error"));
        assert_eq!(failure.finish_status(2), 2);
    }

    #[test]
    fn shutdown_policy_requires_opted_in_mips_linux_guest_pid1() {
        assert!(guest_shutdown_allowed(true, 1, true));
        assert!(!guest_shutdown_allowed(true, 2, true));
        assert!(!guest_shutdown_allowed(false, 1, true));
        assert!(!guest_shutdown_allowed(true, 1, false));
        assert!(!guest_shutdown_allowed(false, 2, false));
    }

    #[test]
    fn actual_full_mp3_passes_and_truncated_mp3_is_refused() {
        let full = decode_one(ENCODED).expect("actual full encoded MP3 must pass");
        assert_eq!(full.frames, EXPECTED_FRAMES);
        assert!(full.blocks > 0);
        let truncated = &ENCODED[..ENCODED.len() * 3 / 4];
        assert!(truncated.len() < ENCODED.len());
        assert!(
            decode_one(truncated).is_err(),
            "actual shortened MP3 must not pass the full-file oracle"
        );
    }

    #[test]
    fn oracle_rejects_bad_samples_and_missing_tail() {
        let reference = [0u8; 8];
        let mut valid = Oracle::new(&reference);
        valid.add(&[0.0; 4]).unwrap();
        assert!(valid.finish(4).is_ok());
        let mut bad = Oracle::new(&reference);
        bad.add(&[0.5, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(bad.finish(4), Err("pcm_tolerance"));
        let mut short = Oracle::new(&reference);
        short.add(&[0.0; 3]).unwrap();
        assert_eq!(short.finish(4), Err("sample_count"));
        assert_eq!(short.add(&[f32::NAN]), Err("nonfinite_pcm"));
    }
}
