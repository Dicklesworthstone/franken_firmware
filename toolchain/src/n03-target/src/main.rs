//! `ffw-n03-target`: N03's group clock on the soft-float big-endian MIPS device target, measured inside QEMU
//! (bead ffw-u07: "CPU on the target ISA" and the clock's decisions on a 32-bit big-endian machine).
//!
//! It runs as PID 1 of the existing Debian/Malta guest and prints `FFW_N03T_*` lines that
//! `toolchain/src/measure-n03-target.py` parses and judges. Three things are produced:
//!
//! * WORLDS: the scripted worlds of `tests/n03/vectors.json` (28, plus the two members of the mixed-generation join), run
//!   through the public API of `franken_clock::group`, one JSON record per op. The judge compares every record with the
//!   independent Python reference (`tests/n03/reference.py`) and with the host build's digests. The clock does
//!   64-bit and 128-bit integer arithmetic, rational least squares and `f64` on a 32-bit big-endian soft-float target,
//!   which is where host-green code can differ.
//! * SEEDED WORLDS: two simulated worlds (a coordinator clock, a member clock with offset, skew and resolution, seeded
//!   asymmetric delay, jitter and loss) whose LCG seeds are derived from a per-run seed the host packs into the
//!   initramfs as `/ffw_seed`. The judge re-derives the expected figures from the reference, so a replayed or canned
//!   transcript cannot carry the right ones.
//! * CPU: guest INSTRUCTIONS for a steady stream of exchanges (`next_probe` + `on_response`) and for the gate path
//!   (`tick`, `local_for_group`, `output`), read from the CP0 Count (`rdhwr $2`) under `-icount shift=0`, with the same
//!   ruler discipline as the D02 and D03 guests (copied, not shared): calibrated in the same boot against loops of known
//!   instruction count before and after, a settling sleep first, and NOTHING printed until every measurement is done.
//!
//! The numbers are INSTRUCTIONS EXECUTED UNDER EMULATION on QEMU's 24Kf model. They are not cycles on a real core: no
//! cache, pipeline or memory-latency effect is modelled, and no board clock is involved.
//!
//! TEST HOOK, never shipped: if the initramfs holds `/plant-replay`, the worlds and seeded worlds are NOT computed; the
//! contents of `/replay` (those lines from an earlier transcript) are printed in their place. That is the planted
//! negative "a guest that replays an earlier run's records"; the judge must fail it.

#![cfg_attr(target_arch = "mips", feature(asm_experimental_arch))]

mod cases;

use std::hint::black_box;
use std::io::Write as _;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

use franken_clock::group::ProbeResponse;
use serde_json::Value;

/// Exchanges before the first timed repetition (the sample window and the rate fit are full by then).
const WARM_EXCHANGES: usize = 100;
/// Exchanges per timed repetition, and repetitions.
const EXCHANGES_PER_REP: usize = 100;
const GATE_CALLS_PER_REP: usize = 400;
const REPS: usize = 5;
const SETTLE: Duration = Duration::from_millis(2000);
/// Ruler repetitions per phase. Each phase is run before and after the measurements.
const RULER_REPS: usize = 2;
/// 3 and 5 instructions per iteration: about 3.9 M, 15 M, 36 M and 60 M instructions each.
const SPIN3_ITERATIONS: [u32; 4] = [1_300_000, 5_000_000, 12_000_000, 20_000_000];
const SPIN5_ITERATIONS: [u32; 4] = [800_000, 3_000_000, 7_200_000, 12_000_000];

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

/// One ruler phase: both loop shapes at every size, `RULER_REPS` times. Results are returned, not printed.
fn ruler_phase(phase: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for _ in 0..RULER_REPS {
        for iterations in SPIN3_ITERATIONS {
            let ticks = spin3(iterations);
            lines.push(format!(
                "FFW_N03T_RULER phase={phase} shape=3 iterations={iterations} ticks={ticks}"
            ));
        }
        for iterations in SPIN5_ITERATIONS {
            let ticks = spin5(iterations);
            lines.push(format!(
                "FFW_N03T_RULER phase={phase} shape=5 iterations={iterations} ticks={ticks}"
            ));
        }
    }
    lines
}

/// The two timed regions. Everything the regions consume is generated first, outside any timed span.
fn cpu_regions() -> Vec<String> {
    let total = WARM_EXCHANGES + REPS * EXCHANGES_PER_REP;
    let stream = cases::timing_stream(total);
    let mut clock = cases::timing_clock();
    let exchange = |clock: &mut franken_clock::group::GroupClock,
                    (t1, t2, t3, t4): (u64, u64, u64, u64)| {
        let req = clock.next_probe(t1);
        let resp = ProbeResponse {
            epoch: req.epoch,
            leader: 7,
            seq: req.seq,
            t1_echo_ns: req.t1_local_ns,
            t2_group_ns: t2,
            t3_group_ns: t3,
        };
        black_box(clock.on_response(resp, t4)).is_ok()
    };
    let mut accepted_warm = 0_usize;
    for &step in &stream[..WARM_EXCHANGES] {
        if exchange(&mut clock, step) {
            accepted_warm += 1;
        }
    }
    let mut lines = vec![format!(
        "FFW_N03T_WARM region=exchange exchanges={WARM_EXCHANGES} accepted={accepted_warm}"
    )];
    let mut runs = Vec::with_capacity(REPS);
    for rep in 0..REPS {
        let chunk = &stream[WARM_EXCHANGES + rep * EXCHANGES_PER_REP..][..EXCHANGES_PER_REP];
        let mut accepted = 0_usize;
        compiler_fence(Ordering::SeqCst);
        let start = count();
        compiler_fence(Ordering::SeqCst);
        for &step in chunk {
            if exchange(&mut clock, step) {
                accepted += 1;
            }
        }
        compiler_fence(Ordering::SeqCst);
        let ticks = count().wrapping_sub(start);
        compiler_fence(Ordering::SeqCst);
        runs.push(("exchange", rep, EXCHANGES_PER_REP, accepted, ticks));
    }
    // The gate path a node runs per block: settle the clock's state, map the block's presentation time to the local
    // clock, ask whether that instant may sound. The clock is locked after the stream above.
    let last_local = stream[total - 1].3;
    let probe_now = last_local + 1_500_000;
    let base_group = clock.group_ns(probe_now).unwrap_or(0);
    let calls: Vec<(u64, u64)> = (0..GATE_CALLS_PER_REP as u64)
        .map(|k| {
            (
                probe_now + k * 5_333_333,
                base_group + 500_000_000 + k * 5_333_333,
            )
        })
        .collect();
    let locked = calls.iter().take(8).all(|&(now, pts)| {
        let _ = clock.tick(now);
        clock.local_for_group(pts, now).is_some()
    });
    lines.push(format!(
        "FFW_N03T_WARM region=gate calls={GATE_CALLS_PER_REP} mapped={}",
        u8::from(locked)
    ));
    for rep in 0..REPS {
        let mut mapped = 0_usize;
        compiler_fence(Ordering::SeqCst);
        let start = count();
        compiler_fence(Ordering::SeqCst);
        for &(now, pts) in &calls {
            black_box(clock.tick(now));
            if let Some(local) = black_box(clock.local_for_group(pts, now)) {
                black_box(clock.output(local));
                mapped += 1;
            }
        }
        compiler_fence(Ordering::SeqCst);
        let ticks = count().wrapping_sub(start);
        compiler_fence(Ordering::SeqCst);
        runs.push(("gate", rep, GATE_CALLS_PER_REP, mapped, ticks));
    }
    for (region, rep, ops, done, ticks) in runs {
        lines.push(format!(
            "FFW_N03T_RUN region={region} rep={rep} ops={ops} done={done} ticks={ticks}"
        ));
    }
    lines.push(format!(
        "FFW_N03T_STATS accepted={} probes_sent={} resets={}",
        clock.stats().accepted,
        clock.stats().probes_sent,
        clock.stats().resets
    ));
    lines
}

// ---- the worlds and the seeded worlds -----------------------------------------------------------------------------

fn opt(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_string(), |v| v.to_string())
}

fn world_lines() -> Vec<String> {
    let vectors = cases::vectors();
    let mut lines = Vec::new();
    for world in cases::all_worlds(&vectors) {
        let id = world["id"].as_str().unwrap_or("?").to_string();
        let steps = cases::run_ops(&world);
        let encoded: Vec<String> = steps.iter().map(Value::to_string).collect();
        for (index, step) in encoded.iter().enumerate() {
            lines.push(format!("FFW_N03T_STEP id={id} i={index} {step}"));
        }
        let (checks, max_err, max_unc, min_margin) = cases::truth_summary(&world, &steps);
        lines.push(format!(
            "FFW_N03T_WEND id={id} steps={} fnv={:016x} checks={checks} max_err={max_err} max_unc={max_unc} min_margin={}",
            steps.len(),
            cases::fnv1a64_lines(&encoded),
            opt(min_margin)
        ));
    }
    lines
}

fn sim_lines(seed: u64) -> Vec<String> {
    (0..cases::SIM_SHAPES.len())
        .map(|index| {
            let run = cases::seeded_run(seed, index);
            format!(
                "FFW_N03T_SIM idx={index} run_seed={seed} seed32={} probes={} lost={} rejected={} checks={} violations={} \
                 max_err={} max_unc={} min_margin={} locked={} resets={}",
                run.seed32,
                run.probes,
                run.lost,
                run.rejected,
                run.checks,
                run.violations,
                run.max_err,
                run.max_unc,
                opt(run.min_margin),
                u8::from(run.locked),
                run.resets
            )
        })
        .collect()
}

fn read_seed() -> Option<u64> {
    std::fs::read_to_string("/ffw_seed")
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// The planted replay: print the world and seeded-world lines of an earlier transcript instead of computing any.
fn replayed_lines() -> Vec<String> {
    match std::fs::read_to_string("/replay") {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) => vec![format!("FFW_N03T_REPLAY_MISSING error={error}")],
    }
}

fn power_off() -> ! {
    let _ = std::io::stdout().flush();
    // SAFETY: a plain libc call with a valid command; it only returns on failure (for example when this program is
    // not PID 1 and lacks the privilege), in which case the transcript says so and the process exits.
    let status = unsafe { reboot(RB_AUTOBOOT) };
    println!("FFW_N03T_REBOOT_FAILED status={status}");
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

fn main() {
    if !cfg!(target_arch = "mips") {
        println!("FFW_N03T_HOST_BUILD counts are meaningless off the MIPS target");
        std::process::exit(2);
    }
    // The only line printed before the measurements: if the program dies at the first counter read, the transcript
    // still shows it started. The settling sleep below also lets its serial transmit interrupts drain.
    println!("FFW_N03T_ALIVE");
    let _ = std::io::stdout().flush();
    std::thread::sleep(SETTLE);

    let seed = read_seed();
    let mut lines = vec![
        format!(
            "FFW_N03T_BEGIN version=1 warm_exchanges={WARM_EXCHANGES} exchanges_per_rep={EXCHANGES_PER_REP} \
             gate_calls_per_rep={GATE_CALLS_PER_REP} reps={REPS} ruler_reps={RULER_REPS} sims={}",
            cases::SIM_SHAPES.len()
        ),
        match seed {
            Some(value) => format!("FFW_N03T_SEED value={value}"),
            None => "FFW_N03T_SEED value=none".to_string(),
        },
    ];
    let floor: Vec<u32> = (0..8)
        .map(|_| {
            let start = count();
            count().wrapping_sub(start)
        })
        .collect();
    lines.push(format!("FFW_N03T_EMPTY ticks={floor:?}"));

    // Measure first, print last: the ruler before and after the timed regions, with the regions in between.
    let ruler_before = ruler_phase("A");
    let regions = cpu_regions();
    let ruler_after = ruler_phase("B");

    // The worlds are not timed; computing them after the ruler keeps the timed work undisturbed.
    let replay = std::path::Path::new("/plant-replay").exists();
    let computed = if replay {
        replayed_lines()
    } else {
        let mut out = world_lines();
        if let Some(value) = seed {
            out.extend(sim_lines(value));
        }
        out
    };

    lines.extend(ruler_before);
    lines.extend(regions);
    lines.extend(ruler_after);
    lines.extend(computed);
    lines.push("FFW_N03T_END".to_string());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &lines {
        let _ = writeln!(out, "{line}");
    }
    drop(out);
    power_off();
}
