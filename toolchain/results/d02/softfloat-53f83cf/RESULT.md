# D02 soft-float reading of `franken-dsp`, revision 53f83cf

**Scope.** A host reading of compiled object code: which f64 soft-float helpers the D02 render path calls, on soft-float
big-endian MIPS32 (`mips-unknown-linux-musl`). Nothing was executed. There is no device, no timing and no instruction count
here. The object was built with **LTO off**, so this reads that object, **not the shipped fat-LTO speaker ELF**, which may
inline differently (see "Limits").

The machine-readable record is `softfloat-record.json`, derived by `toolchain/src/softfloat-record.py` from the kept artefacts and
refused if it would hold a local path, a worker id or an address. The central run was b56, on one worker, from a `git archive`
export of 53f83cf plus the `d02-softfloat-check` v4 patch.

## What was built, and by what

| | |
|---|---|
| compiler | `rustc 1.101.0-nightly (708c94ef0 2026-11-03)`, LLVM 23.1.5; `cargo 1.101.0-nightly (31d3246e0 2026-10-27)`; host x86_64-unknown-linux-gnu |
| build script | `toolchain/src/softfloat-build.sh` (`49054c206701baa3...`), `-Z build-std=core,alloc,std,panic_abort`, `--offline --release`, `-j 2` |
| deviations from the shipped build | `lto=off` (changes generated code: under `lto = true` rustc writes LLVM bitcode for the rlib and for `--emit=obj`, which has no relocations to read, and the checker refused both on the first run); `strip=none` and `-C symbol-mangling-version=legacy` (no code-generation effect; the second needs `-Z unstable-options` on this nightly) |
| artefacts | `libfranken_dsp-4ba94165e5b2af33.rlib` (421,858 bytes, `6814d1db294bafbd...`); `franken_dsp-5b4f199e070ecefc.o` (359,256 bytes, `bcde5338557e109a...`) |

The rlib's one code member and the separately built `.o` come from two separate cargo invocations and are **byte-equal**
(`bcde5338557e109a...`). Both hold 446 code sections, `fp_abi` 0 (the abiflags state no float ABI), and 26,881 executable words with
**0 FPU opcode words**: the evidence that they are soft-float code is that absence, not an abiflags claim.

## What the reading says

The checker starts at `ProtectedBoardDsp::render_into` and follows relocations in executable sections. Verdict **PASS** on both
artefacts: no f64 helper outside the five `Section::process` needs (widen, multiply, add, subtract, narrow) is reachable.

| | |
|---|---|
| code sections / reachable from `render_into` | 446 / 23 |
| f64 helper call sites on the path | `__extendsfdf2` 6, `__muldf3` 5, `__adddf3` 2, `__subdf3` 2, `__truncdfsf2` 1 |

By function:

- **`ProtectedBoardDsp::render_into`** holds `__extendsfdf2` 1, `__muldf3` 5, `__adddf3` 2, `__subdf3` 2, `__truncdfsf2` 1: exactly one
  copy of the `Section::process` pattern (1 widen, 5 multiplies, 2 adds, 2 subtracts, 1 narrow). The object has no `Section::process`
  symbol at all (its `Section` symbols are `from_stored`, `passthrough` and `from_spec`), so it is inlined, and `render_into` holds it.
- **`Section::from_stored`** holds `__extendsfdf2` 5, which is the five `as f64` casts of its source. It is reached through
  `render_into -> ProtectedBoardDsp::install -> Section::from_stored`. The object shows reachability, not how often. In the source
  (`runtime.rs`, `advance_gain`), `install` is called only inside `if self.applied_gain == 0.0 { if let Some(board) = self.pending.take() {`,
  which is the point where a profile switch swaps the new chain in. So the widenings run when a switch is applied, not per block or per
  sample. The D02 cost measurements (steady-state blocks, no pending switch) do not include them. That is a reading of the object and of
  the source, not a measurement.
- **`franken_dsp::convert::f32_to_s16` and `f32_to_int`** survive as symbols, are on the path, and reference **no** f64 helper. This
  checks D01's claim that the integer-only conversion calls no f64 helper, on this object.
- 10 other functions use f64 helpers but are **not** reachable from `render_into` (the calibration validator and its helpers,
  `serde_json` number parsing, `Vec::extend_trusted`). They are setup code and are listed in the record, not judged.

## A correction to the first reading

The v4 checker counted every relocation as a call site. PIC code makes each call two relocations against one symbol
(`R_MIPS_CALL16`, then the `R_MIPS_JALR` hint), so its first report doubled every count: `render_into` read as "exactly 2 times the
pattern" and `from_stored` as 10 widenings. The source says 1 pattern and 5 casts. v5 counts calls, not relocations, and was checked
against a real PIC object (a zig-built C object read independently with `llvm-readelf`) as well as the real franken-dsp objects. The
same defect class is why the checker now also reports counts per function.

## Limits

- It reads the **object** it was given, built with LTO off. The shipped speaker is fat-LTO'd and stripped, so it may inline across
  crates differently and has no symbols to read.
- Attribution is per surviving function. A function inlined into its caller is judged as part of the caller. The helper-set rule cannot
  see an extra widen, multiply, add, subtract or narrow that inlined non-`Section` code adds. (`Section::process` is inlined into
  `render_into` here, and `render_into` holds exactly one copy of its pattern, which is what would show such an addition.)
- Reachability follows relocations, calls and address references alike, so it over-approximates. An indirect call is not resolved.
- Counts are call sites in the object, not executions. No timing or instruction count is claimed.
- It says nothing about whether f64 state is acceptable on a soft-float board, or which board is the soft-float MIPS; that is the
  owner's decision.
- PowerPC is hard-float; this question does not arise there and nothing PowerPC was read.

## Reproduce

The two central lines and the check command are in `softfloat-record.json` (`commands`). Rebuild the artefacts with them, then
`python3 -B -I toolchain/src/softfloat-record.py --revision <rev> --out <file> <rlib> <obj>`.
