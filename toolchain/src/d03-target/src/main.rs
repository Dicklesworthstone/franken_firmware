//! `ffw-d03-target`: D03's drift resampler on the soft-float big-endian MIPS device target, measured inside QEMU
//! (bead ffw-j9r, "Measure quality and CPU on target ISA").
//!
//! It runs as PID 1 of the existing Debian/Malta guest and prints `FFW_D03T_*` lines that
//! `toolchain/src/measure-d03-target.py` parses and judges. Two things are produced:
//!
//! * CPU: guest INSTRUCTIONS per output frame of `DriftResampler::render`, read from the CP0 Count (`rdhwr $2`) under
//!   `-icount shift=0`, with the same ruler discipline as the D02 cost guest (`toolchain/src/d02-cost`, copied, not
//!   shared): the counter is a RULER, calibrated in the same boot against loops of known instruction count, once
//!   before and once after the D03 phase; the program settles for two virtual seconds first; and NOTHING is printed
//!   until every measurement is done, so serial transmit interrupts cannot land inside a timed region.
//! * Quality: the resampled `f32` samples of the host quality tones, printed as hex for the host to judge against the
//!   declared bands (`docs/contracts/d03.md` section 4.1) and to compare with the host build's samples
//!   (`crates/franken-dsp/tests/d03_target_samples.rs` runs the same `cases.rs`). Two kinds of case:
//!   canonical ones (fixed phase, byte-compared with the host build) and SEEDED ones, whose phase is derived from a
//!   per-run seed the host chooses and packs into the initramfs as `/ffw_seed`. A transcript replayed from another
//!   run, or samples copied from the host build, cannot carry the right seeded phase.
//!
//! The numbers are INSTRUCTIONS EXECUTED UNDER EMULATION on QEMU's 24Kf model. They are not cycles on a real core:
//! no cache, pipeline or memory-latency effect is modelled, and no board clock is involved. They say nothing about
//! the real DAC path.
//!
//! TEST HOOK, never shipped: if the initramfs holds `/plant-replay`, the quality section is NOT computed; the
//! contents of `/replay` (the quality lines of an earlier transcript) are printed in its place. That is the planted
//! negative "a guest that emits earlier samples instead of computing them"; the judge must fail it.

#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]

mod cases;

use std::hint::black_box;
use std::io::Write as _;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

use franken_dsp::resample::{DriftResampler, ResamplerConfig, SliceSource};
use franken_dsp::FRAMES_PER_BLOCK;

/// 8 blocks of 256 frames per repetition: 2048 output frames.
const BLOCKS_PER_REP: usize = 8;
/// Enough to finish the 64-frame fade-in and touch every page before anything is timed.
const WARMUP_BLOCKS: usize = 6;
const REPS: usize = 5;
/// Input frames available to each repetition: 2048 outputs pull at most 2048 * 1.0005 + 3.
const INPUT_FRAMES: usize = BLOCKS_PER_REP * FRAMES_PER_BLOCK + 32;
/// Same noise as the D02 cost guest and the G02 PCM slice: `i16 / 32768 * 0.25`, exact in f32.
const AMPLITUDE: f32 = 0.25;
const SETTLE: Duration = Duration::from_millis(2000);
/// Ruler repetitions per phase. Each phase is run before and after the D03 measurements.
const RULER_REPS: usize = 2;
/// 3 and 5 instructions per iteration: about 3.9 M, 15 M, 36 M and 60 M instructions each.
const SPIN3_ITERATIONS: [u32; 4] = [1_300_000, 5_000_000, 12_000_000, 20_000_000];
const SPIN5_ITERATIONS: [u32; 4] = [800_000, 3_000_000, 7_200_000, 12_000_000];

struct Lcg(u32);

impl Lcg {
    fn next_sample(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let raw = (self.0 >> 16) as u16 as i16;
        f32::from(raw) / 32768.0 * AMPLITUDE
    }
}

// ---- the cycle counter and the calibration loops (MIPS only) ------------------------------------------------------

/// The CP0 Count, through hardware register 2 (`rdhwr $2`). Linux enables it for user mode on MIPS32r2, and QEMU
/// returns the live count, broken out of the translation block so that it is exact under `-icount`.
#[cfg(target_arch = "mips")]
#[inline(always)]
fn count() -> u32 {
    let value: u32;
    // SAFETY: reads a hardware register into a general register. No memory is accessed and the stack is not used;
    // the block is deliberately not `nomem`, so the compiler treats it as a barrier for memory operations and keeps
    // the measured region between two reads.
    unsafe {
        core::arch::asm!("rdhwr {0}, $2", out(reg) value, options(nostack));
    }
    value
}

#[cfg(not(target_arch = "mips"))]
fn count() -> u32 {
    0
}

/// Exactly `3 * iterations` instructions: `addiu`, `bnez`, and the `nop` in its delay slot. Returns counter ticks.
#[cfg(target_arch = "mips")]
#[inline(never)]
fn spin3(iterations: u32) -> u32 {
    let start = count();
    // SAFETY: only general registers are touched; `noreorder` keeps the explicit delay slot, so the loop body is
    // exactly the three instructions written. `iterations` is at least 1, so the loop terminates.
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set noreorder",
            "2:",
            "addiu {n}, {n}, -1",
            "bnez {n}, 2b",
            "nop",
            ".set pop",
            n = inout(reg) iterations => _,
            options(nostack, nomem),
        );
    }
    count().wrapping_sub(start)
}

/// Exactly `5 * iterations` instructions: a different loop shape, to show the ruler does not depend on the shape.
#[cfg(target_arch = "mips")]
#[inline(never)]
fn spin5(iterations: u32) -> u32 {
    let start = count();
    // SAFETY: as for `spin3`; the two extra `addiu` cancel on a scratch register.
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set noreorder",
            "2:",
            "addiu {n}, {n}, -1",
            "addiu {t}, {t}, 1",
            "addiu {t}, {t}, -1",
            "bnez {n}, 2b",
            "nop",
            ".set pop",
            n = inout(reg) iterations => _,
            t = inout(reg) 0u32 => _,
            options(nostack, nomem),
        );
    }
    count().wrapping_sub(start)
}

#[cfg(not(target_arch = "mips"))]
fn spin3(_iterations: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "mips"))]
fn spin5(_iterations: u32) -> u32 {
    0
}

extern "C" {
    /// musl's `reboot(2)` wrapper (`int reboot(int)`), the same call the E07 PID 1 ends with.
    fn reboot(cmd: core::ffi::c_int) -> core::ffi::c_int;
}

const RB_AUTOBOOT: core::ffi::c_int = 0x0123_4567;

// ---- the CPU measurement ------------------------------------------------------------------------------------------

/// A resampler configuration to cost: a constant ratio, or a slew from 0 toward `slew_to` that is still in progress
/// during the measurement (it costs a ratio update per 32-frame quantum).
struct CpuCase {
    name: &'static str,
    ppb: i32,
    slew_to: Option<i64>,
    /// Also measure digital silence (a soft-float fast path), not only noise.
    silence: bool,
}

const CPU_CASES: [CpuCase; 4] = [
    CpuCase {
        name: "nominal",
        ppb: 0,
        slew_to: None,
        silence: true,
    },
    CpuCase {
        name: "fast500",
        ppb: 500_000,
        slew_to: None,
        silence: true,
    },
    CpuCase {
        name: "slow500",
        ppb: -500_000,
        slew_to: None,
        silence: true,
    },
    CpuCase {
        name: "slewing",
        ppb: 0,
        slew_to: Some(500_000),
        silence: false,
    },
];

fn noise_channel(seed: u32) -> Vec<f32> {
    let mut lcg = Lcg(seed);
    (0..INPUT_FRAMES).map(|_| lcg.next_sample()).collect()
}

/// One ruler phase: both loop shapes at every size, `RULER_REPS` times. Results are returned, not printed.
fn ruler_phase(phase: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for _ in 0..RULER_REPS {
        for iterations in SPIN3_ITERATIONS {
            let ticks = spin3(iterations);
            lines.push(format!(
                "FFW_D03T_RULER phase={phase} shape=3 iterations={iterations} ticks={ticks}"
            ));
        }
        for iterations in SPIN5_ITERATIONS {
            let ticks = spin5(iterations);
            lines.push(format!(
                "FFW_D03T_RULER phase={phase} shape=5 iterations={iterations} ticks={ticks}"
            ));
        }
    }
    lines
}

fn peak(block: &[f32]) -> f32 {
    block.iter().fold(0.0_f32, |acc, &s| acc.max(s.abs()))
}

fn run_cpu_case(case: &CpuCase, noise: (&[f32], &[f32]), silence: &[f32]) -> Vec<String> {
    let mut lines = Vec::new();
    let inputs: Vec<(&str, &[f32], &[f32])> = if case.silence {
        vec![("noise", noise.0, noise.1), ("silence", silence, silence)]
    } else {
        vec![("noise", noise.0, noise.1)]
    };
    for (input, left_in, right_in) in inputs {
        let mut rs = DriftResampler::with_initial_ppb(ResamplerConfig::default(), case.ppb)
            .expect("the ratio is within the default limit");
        if let Some(target) = case.slew_to {
            rs.set_target_ppb(target);
        }
        let mut out_l = [0.0_f32; FRAMES_PER_BLOCK];
        let mut out_r = [0.0_f32; FRAMES_PER_BLOCK];
        for _ in 0..WARMUP_BLOCKS {
            let mut src = SliceSource::new(left_in, right_in).expect("equal channel lengths");
            black_box(rs.render(&mut src, &mut out_l, &mut out_r).expect("render"));
        }
        lines.push(format!(
            "FFW_D03T_WARM name={} input={} ramp_left={} ratio_ppb={} target_ppb={}",
            case.name,
            input,
            rs.phase_state().ramp_left,
            rs.ratio_ppb(),
            rs.target_ppb()
        ));
        let mut runs = Vec::with_capacity(REPS);
        for rep in 0..REPS {
            let mut src = SliceSource::new(left_in, right_in).expect("equal channel lengths");
            let mut produced = 0_usize;
            compiler_fence(Ordering::SeqCst);
            let start = count();
            compiler_fence(Ordering::SeqCst);
            for _ in 0..BLOCKS_PER_REP {
                let report =
                    black_box(rs.render(&mut src, &mut out_l, &mut out_r).expect("render"));
                produced += report.produced;
            }
            compiler_fence(Ordering::SeqCst);
            let ticks = count().wrapping_sub(start);
            compiler_fence(Ordering::SeqCst);
            runs.push((
                rep,
                ticks,
                produced,
                peak(&out_l).max(peak(&out_r)),
                rs.ratio_ppb(),
            ));
        }
        for (rep, ticks, produced, block_peak, ratio) in runs {
            lines.push(format!(
                "FFW_D03T_RUN name={} input={} rep={} frames={} ticks={} peak={:.6} ratio_ppb={}",
                case.name, input, rep, produced, ticks, block_peak, ratio
            ));
        }
    }
    lines
}

// ---- the quality section ------------------------------------------------------------------------------------------

/// Print the lines of one case: `<tag>BEGIN`, the data lines, `<tag>END` with the whole-case and per-chunk digests.
fn dump_case(lines: &mut Vec<String>, tag: &str, id: &str, extra: &str, samples: &[f32]) {
    lines.push(format!(
        "FFW_D03T_{tag}BEGIN id={id} frames={} {extra}",
        samples.len()
    ));
    for (index, line) in cases::hex_lines(samples).iter().enumerate() {
        lines.push(format!(
            "FFW_D03T_{tag}DATA id={id} off={} {line}",
            index * cases::SAMPLES_PER_LINE
        ));
    }
    lines.push(format!(
        "FFW_D03T_{tag}END id={id} frames={} fnv={:016x} chunks={}",
        samples.len(),
        cases::fnv1a64(samples),
        cases::chunk_digests(samples)
    ));
}

fn read_seed() -> Option<u64> {
    std::fs::read_to_string("/ffw_seed")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

fn quality_lines(seed: Option<u64>) -> Vec<String> {
    let mut lines = Vec::new();
    for case in &cases::CANONICAL {
        let samples = cases::canonical_samples(case);
        let extra = format!("hz={} ppb={}", case.tone.hz, case.ppb);
        dump_case(&mut lines, "Q", case.id, &extra, &samples);
    }
    if let Some(seed) = seed {
        for (id, tone) in &cases::SEEDED {
            let (phase, samples) = cases::seeded_samples(tone, seed);
            let extra = format!(
                "hz={} ppb={} phase_bits={:016x}",
                tone.hz,
                cases::SEEDED_PPB,
                phase.to_bits()
            );
            dump_case(&mut lines, "S", id, &extra, &samples);
        }
    }
    lines
}

/// The planted replay: print the quality lines of an earlier transcript instead of computing any.
fn replayed_lines() -> Vec<String> {
    match std::fs::read_to_string("/replay") {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) => vec![format!("FFW_D03T_REPLAY_MISSING error={error}")],
    }
}

fn power_off() -> ! {
    let _ = std::io::stdout().flush();
    // SAFETY: a plain libc call with a valid command; it only returns on failure (for example when this program is
    // not PID 1 and lacks the privilege), in which case the transcript says so and the process exits.
    let status = unsafe { reboot(RB_AUTOBOOT) };
    println!("FFW_D03T_REBOOT_FAILED status={status}");
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

fn main() {
    if !cfg!(target_arch = "mips") {
        println!("FFW_D03T_HOST_BUILD counts are meaningless off the MIPS target");
        std::process::exit(2);
    }
    // The only line printed before the measurements: if the program dies at the first counter read, the transcript
    // still shows it started. The settling sleep below also lets its serial transmit interrupts drain.
    println!("FFW_D03T_ALIVE");
    let _ = std::io::stdout().flush();
    std::thread::sleep(SETTLE);

    let mut lines = vec![format!(
        "FFW_D03T_BEGIN version=1 block_frames={FRAMES_PER_BLOCK} blocks_per_rep={BLOCKS_PER_REP} reps={REPS} \
         warmup_blocks={WARMUP_BLOCKS} ruler_reps={RULER_REPS} skip={} n_meas={} seeded_frames={}",
        cases::SKIP,
        cases::N_MEAS,
        cases::SEEDED_FRAMES
    )];
    let seed = read_seed();
    lines.push(match seed {
        Some(value) => format!("FFW_D03T_SEED value={value}"),
        None => "FFW_D03T_SEED value=none".to_string(),
    });
    let floor: Vec<u32> = (0..8)
        .map(|_| {
            let start = count();
            count().wrapping_sub(start)
        })
        .collect();
    lines.push(format!("FFW_D03T_EMPTY ticks={floor:?}"));

    let noise_l = noise_channel(1);
    let noise_r = noise_channel(2);
    let silence = vec![0.0_f32; INPUT_FRAMES];

    // Measure first, print last: the ruler before and after the D03 phase, with the D03 phase in between.
    let ruler_before = ruler_phase("A");
    let mut measured = Vec::new();
    for case in &CPU_CASES {
        measured.extend(run_cpu_case(case, (&noise_l, &noise_r), &silence));
    }
    let ruler_after = ruler_phase("B");

    // The quality section is not timed; computing it after the ruler keeps the timed work undisturbed.
    let replay = std::path::Path::new("/plant-replay").exists();
    let quality = if replay {
        replayed_lines()
    } else {
        quality_lines(seed)
    };

    lines.extend(ruler_before);
    lines.extend(measured);
    lines.extend(ruler_after);
    lines.extend(quality);
    lines.push("FFW_D03T_END".to_string());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        let _ = writeln!(out, "{line}");
    }
    drop(out);
    power_off();
}
