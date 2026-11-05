//! `ffw-d02-cost`: the instruction count of D02's per-frame protection chain on the soft-float MIPS device
//! target, measured inside QEMU (bead ffw-7s0, "D02 f64 target CPU cost").
//!
//! It runs as PID 1 of the existing Debian/Malta guest and prints `FFW_D02COST_*` lines that
//! `toolchain/src/measure-d02-cost.py` parses and judges. The host side starts QEMU with
//! `-icount shift=0`, which ties the guest's virtual clock to executed instructions, and this program reads the
//! CPU's cycle counter (`rdhwr $2`, the CP0 Count) around each measured region.
//!
//! The counter is a RULER, not an oracle. Its scale differs from boot to boot (observed 4.45 to 5.91 instructions
//! per tick on the same kernel and options), so it is calibrated in the same boot against loops of known length
//! (`spin3`: exactly 3 instructions per iteration; `spin5`: exactly 5), once BEFORE and once AFTER the D02 phase so
//! the host can see whether the scale drifted while D02 ran. No QEMU constant is assumed anywhere.
//!
//! Two things matter for honest numbers and shape this file:
//! * Nothing is printed until every measurement is done. The guest's serial port is slow, and transmit interrupts
//!   from one line otherwise land inside the next timed region (seen in a probe: reps inflated by ~1.6%).
//! * The program first sleeps two virtual seconds, so boot-time kernel work has finished (seen in a probe: the first
//!   reps after boot cost up to 2.2x). Stray interrupts and preemptions can only ADD ticks, so the host takes the
//!   minimum over repetitions and requires the lowest ones to agree.
//!
//! What is measured is `ProtectedBoardDsp::render_into` over 256-frame blocks, the real D02 code linked into this
//! binary, on noise (the typical case) and on digital silence (a soft-float fast path). The numbers are
//! INSTRUCTIONS EXECUTED UNDER EMULATION. They are not cycles on a real 24K core: no cache, pipeline or
//! memory-latency effect is modelled beyond the instructions themselves.
//!
//! Which `Section` is in the binary (f64 state, as shipped, or the f32-state control) is not declared by a flag:
//! the program runs the 120 Hz low-pass step response through the real `Section` and prints the `f32` bits of
//! sample 127, which differ between the two realizations (D02 vector D02-RESP-004), so the transcript itself
//! says which one it measured.

#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]

use std::hint::black_box;
use std::io::Write as _;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

use franken_board_profile::{synthetic_test_fixture_catalog, BoardProfile, TransducerRole};
use franken_dsp::protection::{
    butterworth2_lowpass, synthetic_calibration_for, Admission, BoardCalibration, BoardStatus,
    ProtectedBoardDsp, ProtectedOutput, Section,
};
use franken_dsp::{StereoAudioBlock, FRAMES_PER_BLOCK};

const FS_HZ: f64 = 48_000.0;
/// 8 blocks of 256 frames per repetition: 2048 frames. Chosen so the largest region (the 27-section, 9-channel
/// stress board) stays inside the ruler's range of 4 to 60 million instructions.
const BLOCKS_PER_REP: usize = 8;
/// Enough to finish the 10 ms gain ramp (480 frames) and touch every page before anything is timed.
const WARMUP_BLOCKS: usize = 6;
const REPS: usize = 5;
/// Same noise as the G02 PCM slice: two LCG streams, `i16 / 32768 * 0.25`, exact in f32.
const AMPLITUDE: f32 = 0.25;
const SETTLE: Duration = Duration::from_millis(2000);
/// Ruler repetitions per phase. Each phase is run before and after the D02 measurements.
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

/// The CP0 Count, through hardware register 2 (`rdhwr $2`). Linux enables it for user mode on MIPS32r2
/// (`configure_hwrena`), and QEMU returns the live count, broken out of the translation block so that it is exact
/// under `-icount`. A hand-assembled probe confirmed this on the Debian 4.19 Malta kernel under QEMU 11.1.2.
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

// ---- inputs and configurations ------------------------------------------------------------------------------------

fn noise_blocks() -> Vec<StereoAudioBlock> {
    let (mut left, mut right) = (Lcg(1), Lcg(2));
    (0..BLOCKS_PER_REP)
        .map(|index| {
            let mut block = StereoAudioBlock::silence((index * FRAMES_PER_BLOCK) as u64);
            for (l, r) in block.left.iter_mut().zip(block.right.iter_mut()) {
                *l = left.next_sample();
                *r = right.next_sample();
            }
            block
        })
        .collect()
}

fn silence_blocks() -> Vec<StereoAudioBlock> {
    (0..BLOCKS_PER_REP)
        .map(|index| StereoAudioBlock::silence((index * FRAMES_PER_BLOCK) as u64))
        .collect()
}

fn fixture(model: &str) -> BoardProfile {
    synthetic_test_fixture_catalog()
        .into_iter()
        .find(|profile| profile.model_number == model)
        .unwrap_or_else(|| panic!("no synthetic fixture board `{model}`"))
}

struct Config {
    name: &'static str,
    profile: BoardProfile,
    calibration: BoardCalibration,
    /// Also measure digital silence (a soft-float fast path), not only noise.
    silence: bool,
}

/// `stress` raises every mid and woofer channel to the most sections admission allows (four), the worst case a real
/// calibration could ask for. Tweeters keep one high-pass section: a second one trips the intermediate-range bound.
fn config(name: &'static str, model: &str, stress: bool, silence: bool) -> Config {
    let profile = fixture(model);
    let mut calibration = synthetic_calibration_for(&profile);
    if stress {
        for channel in &mut calibration.channels {
            let design = match channel.role {
                TransducerRole::MidLeft
                | TransducerRole::MidRight
                | TransducerRole::ArrayMidWoofer(_) => Some(5000.0),
                TransducerRole::WooferCenter => Some(300.0),
                _ => None,
            };
            if let Some(cutoff_hz) = design {
                channel.sections = (0..4)
                    .map(|_| butterworth2_lowpass(cutoff_hz, FS_HZ))
                    .collect();
            }
        }
    }
    Config {
        name,
        profile,
        calibration,
        silence,
    }
}

// ---- measurement --------------------------------------------------------------------------------------------------

fn min_channel_peak(out: &ProtectedOutput) -> i32 {
    out.samples
        .iter()
        .take(out.channels)
        .map(|lane| {
            lane[..out.frames]
                .iter()
                .map(|&s| i32::from(s).abs())
                .max()
                .unwrap_or(0)
        })
        .min()
        .unwrap_or(0)
}

/// One ruler phase: both loop shapes at every size, `RULER_REPS` times. Results are returned, not printed.
fn ruler_phase(phase: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for _ in 0..RULER_REPS {
        for iterations in SPIN3_ITERATIONS {
            let ticks = spin3(iterations);
            lines.push(format!(
                "FFW_D02COST_RULER phase={phase} shape=3 iterations={iterations} ticks={ticks}"
            ));
        }
        for iterations in SPIN5_ITERATIONS {
            let ticks = spin5(iterations);
            lines.push(format!(
                "FFW_D02COST_RULER phase={phase} shape=5 iterations={iterations} ticks={ticks}"
            ));
        }
    }
    lines
}

fn run_config(
    config: &Config,
    noise: &[StereoAudioBlock],
    silence: &[StereoAudioBlock],
) -> Vec<String> {
    let mut lines = Vec::new();
    let sections: usize = config
        .calibration
        .channels
        .iter()
        .map(|channel| channel.sections.len())
        .sum();
    let mut dsp = ProtectedBoardDsp::admit(
        &config.profile,
        Some(&config.calibration),
        Admission::HostSimulation,
    );
    let active = matches!(dsp.status(), BoardStatus::Active);
    lines.push(format!(
        "FFW_D02COST_CONFIG name={} channels={} sections={} admitted={} status={:?}",
        config.name,
        config.calibration.channels.len(),
        sections,
        u8::from(active),
        dsp.status()
    ));
    if !active {
        return lines;
    }
    dsp.set_user_gain(1.0);
    dsp.set_muted(false).expect("an active board unmutes");
    let mut out = ProtectedOutput::new();
    let inputs: Vec<(&str, &[StereoAudioBlock])> = if config.silence {
        vec![("noise", noise), ("silence", silence)]
    } else {
        vec![("noise", noise)]
    };
    for (input, blocks) in inputs {
        for block in blocks.iter().take(WARMUP_BLOCKS) {
            dsp.render_into(block, &mut out);
        }
        lines.push(format!(
            "FFW_D02COST_WARM name={} input={} applied_gain={:.6}",
            config.name,
            input,
            dsp.applied_gain()
        ));
        let mut runs = Vec::with_capacity(REPS);
        for rep in 0..REPS {
            compiler_fence(Ordering::SeqCst);
            let start = count();
            compiler_fence(Ordering::SeqCst);
            for block in blocks {
                black_box(dsp.render_into(block, &mut out));
            }
            compiler_fence(Ordering::SeqCst);
            let ticks = count().wrapping_sub(start);
            compiler_fence(Ordering::SeqCst);
            runs.push((rep, ticks, min_channel_peak(&out)));
        }
        for (rep, ticks, peak) in runs {
            lines.push(format!(
                "FFW_D02COST_RUN name={} input={} rep={} frames={} ticks={} min_channel_peak={}",
                config.name,
                input,
                rep,
                blocks.len() * FRAMES_PER_BLOCK,
                ticks,
                peak
            ));
        }
    }
    lines
}

/// Which `Section` this binary holds. The 120 Hz low-pass step response, sample 127, is 0.72293953... with f64
/// state and 0.72299069... with f32 state (D02 vector D02-RESP-004), so the f32 bits tell the two apart.
fn section_selftest() -> u32 {
    let spec = butterworth2_lowpass(120.0, FS_HZ);
    let mut section = Section::from_spec(&spec).expect("the 120 Hz low-pass is admissible");
    let mut y = 0.0f32;
    for _ in 0..=127 {
        y = section.process(1.0);
    }
    y.to_bits()
}

fn power_off() -> ! {
    let _ = std::io::stdout().flush();
    // SAFETY: a plain libc call with a valid command; it only returns on failure (for example when this program is
    // not PID 1 and lacks the privilege), in which case the transcript says so and the process exits.
    let status = unsafe { reboot(RB_AUTOBOOT) };
    println!("FFW_D02COST_REBOOT_FAILED status={status}");
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

fn main() {
    if !cfg!(target_arch = "mips") {
        println!("FFW_D02COST_HOST_BUILD counts are meaningless off the MIPS target");
        std::process::exit(2);
    }
    // The only line printed before the measurements: if the program dies at the first counter read, the transcript
    // still shows it started. The settling sleep below also lets its serial transmit interrupts drain.
    println!("FFW_D02COST_ALIVE");
    let _ = std::io::stdout().flush();
    std::thread::sleep(SETTLE);

    let mut lines = vec![
        format!(
            "FFW_D02COST_BEGIN version=2 block_frames={FRAMES_PER_BLOCK} blocks_per_rep={BLOCKS_PER_REP} \
             reps={REPS} warmup_blocks={WARMUP_BLOCKS} ruler_reps={RULER_REPS}"
        ),
        format!(
            "FFW_D02COST_SELFTEST section=lp120_step127 bits={:08x}",
            section_selftest()
        ),
    ];
    let floor: Vec<u32> = (0..8)
        .map(|_| {
            let start = count();
            count().wrapping_sub(start)
        })
        .collect();
    lines.push(format!("FFW_D02COST_EMPTY ticks={floor:?}"));

    let noise = noise_blocks();
    let silence = silence_blocks();
    let configs = [
        config("S1", "S1", false, false),
        config("S3", "S3", false, false),
        config("S5", "S5", false, true),
        config("S9", "S9", false, false),
        config("S5-max", "S5", true, true),
        config("S9-max", "S9", true, false),
    ];

    // Measure first, print last: the ruler before and after the D02 phase, with D02 in between.
    let ruler_before = ruler_phase("A");
    let mut measured = Vec::new();
    for config in &configs {
        measured.extend(run_config(config, &noise, &silence));
    }
    let ruler_after = ruler_phase("B");

    lines.extend(ruler_before);
    lines.extend(measured);
    lines.extend(ruler_after);
    lines.push("FFW_D02COST_END".to_string());
    for line in &lines {
        println!("{line}");
    }
    power_off();
}
