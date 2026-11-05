# E06: floating-point ABI of the two big-endian targets

Reproduce with `python3 -B -I scripts/e06/fp_isa.py` (add `--json OUT` for a new record). `fp-isa.json` is that record, made
with `rustc 1.101.0-nightly (48f4b0553, 2026-10-23)` and zig 0.15.2. Nothing was built with cargo, linked or run: the tool
prints each target's spec, compiles a one-line float add and multiply to **assembly**, and asks zig's preprocessor which
float-ABI macros each musl target spelling defines.

## What the compiler does

| | MIPS `mips-unknown-linux-musl` | PowerPC `powerpc-unknown-linux-musl` |
|---|---|---|
| target spec | `features: "+mips32r2,+soft-float"` | **silent on float**: no `features`, `cpu`, `llvm-floatabi` or `rustc-abi` entry |
| `a + b` (f32) compiles to | a call to `__addsf3` | `fadds 1, 1, 2` (a hardware instruction) |
| `a * b` (f64) compiles to | a call to `__muldf3` | `fmul 1, 1, 2` |
| float ABI the compiler targets | **soft** | **hard** (operands in FP registers) |

The PowerPC spec cannot say "hard" by itself, because it says nothing about float; the assembly does. MIPS is the control:
the same method reports soft where the spec says `+soft-float`.

## What the linker's libc must match (zig 0.15.2)

zig spells the float ABI of MIPS and PowerPC musl targets with `eabi` (soft) and `eabihf` (hard), as for ARM. Its own macros:

| zig target | float ABI | macros defined |
|---|---|---|
| `mips-linux-musleabi` | soft | `__mips_soft_float` |
| `mips-linux-musleabihf` | hard | `__mips_hard_float` |
| **`mips-linux-musl`** | **hard** | `__mips_hard_float` |
| `powerpc-linux-musleabi` | soft | `_SOFT_FLOAT`, `_SOFT_DOUBLE`, `__NO_FPRS__` |
| `powerpc-linux-musleabihf` | hard | none |
| `powerpc-linux-musl` | hard | none |

So the Rust objects pair with: MIPS `mips-linux-musleabi`; PowerPC `powerpc-linux-musleabihf` (or the bare `-musl`). Two
traps follow: the **bare `mips-linux-musl` is hard-float** and would pair a hard-float libc with soft-float Rust objects,
and `powerpc-linux-musleabi` is a soft-float, no-FPR ABI that does not match what rustc emits for PowerPC.

## What this does not establish: any board's FPU

**The FPU of any board is not established** by this tool or by anything else in the repository. The compiler's choice says
nothing about a CPU. For the Play:5 Gen 1 the repo's inventory records an **NXP MPC8247 (603e
class), by published teardown: "historical hypothesis, not silicon-verified"**, joined to the product by name only, and the
committed image evidence records `float_abi: null`. So the board's CPU is itself unverified.

For the hypothesised part the vendor datasheet is **internally inconsistent**. Freescale `MPC8272EC` Rev. 3 (09/2011), which
covers the MPC8272, MPC8248, MPC8271 and MPC8247, section 1.1 (pages 3 to 4), headlines the core as a **"Dual-issue integer
(G2_LE) core"** and "a core version of the MPC603e microprocessor", yet lists, as a sub-bullet of that core, **"Floating-point
unit (FPU) supports floating-point arithmetic"**; Figure 1's block diagram shows the G2_LE core with no FPU block. The
datasheet cannot be resolved from itself. The G2 core reference manual would settle it; it was not read. (PDF read:
sha256 `4c1b4520ea091908…`, not committed.) Secondary web results were also not decisive.

## What it means for D02's float DSP

- **MIPS:** every `f32`/`f64` operation is a library call; the compiler is soft-float whatever the board has. Budget it as
  software float.
- **PowerPC:** the compiler emits hardware FP instructions. If the board has an FPU they run on it. If it does not, the first
  one is a program exception: it would be rescued only by kernel math emulation (slow and variable latency, never observed
  here) or avoided by a soft-float target, which rustc does not provide for this triple. A custom target spec with
  `"features": "+soft-float"` plus zig's `powerpc-linux-musleabi` is a possible route; it has not been built or qualified.
- **To close the question:** an observation of the board (a live unit's `/proc/cpuinfo`, the kernel's boot log, or the
  `Tag_GNU_Power_ABI_FP` attribute of an extracted userland ELF) is needed. None is in the repo. That is a decision about a
  device, not something the compiler can answer.
