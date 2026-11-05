# E06: codec candidates at pinned commits (Symphonia 0.6.1 family, opus-pure 0.2.2)

Read-only and offline. The two candidates were chosen by the project's root for **evaluation**, with exact sources and digests supplied
(`consumers.json`); this is an audit-input choice, **not an admission** and not a size, speed or conformance claim. Everything below is a
resolver and source read made with the existing `scripts/e06/audit.py` (`--subject upstream`), in a scratch consumer workspace per
configuration, the same method as `../upstream/README.md`. Nothing was built, linked or run: the check lines in section 3 are **unrun**.

## 1. What was audited

| | Symphonia | opus-pure |
|---|---|---|
| pin | `ee35874b571a35a9a6e15d3bc9a3aaf8f11fbeee` (tag v0.6.1) | `cf954a76381ae8968b2bc35bb5d578b3a2311d53` (0.2.2) |
| selection | `symphonia` with `default-features = false`, features `aac alac vorbis pcm ogg isomp4` | defaults (the `probe` feature is OFF) |
| license | MPL-2.0 (all ten Symphonia crates); registry crates MIT / Apache-2.0 / Zlib | BSD-3-Clause |
| linked per big-endian target | 18 packages (10 Symphonia, 8 registry) + the scratch `probe`; host-only: `autocfg` | 1 package (no dependencies) + `probe` |
| own `unsafe` tokens | **0** in all ten Symphonia crates (`symphonia-core` declares `forbid(unsafe_code)`; `-common` and `-format-isomp4` declare nothing) | **132**, in 10 files (celt: bands, kiss_fft, lpc, mdct, mod, pitch, pvq; silk: nsq_del_dec, resampler, sigproc_fix); no `unsafe_code` attribute, crate-level `allow(unsafe_op_in_unsafe_fn)` |
| `unsafe` in dependencies | 425 tokens: bytemuck 332, smallvec 80, log 6, bitflags 2, lazy_static 2, num-complex 2, num-traits 1 (regex-lite 0) | none (no dependencies) |
| std / alloc | every Symphonia crate is `std` (it needs `std::io`); the registry crates are `no_std`-capable (bitflags, bytemuck, lazy_static, log, smallvec) or `std` (num-*, regex-lite); `alloc` is referenced by bytemuck, log, regex-lite, smallvec | `std` (`std::thread` in `parallel.rs`; an `AtomicU8` CPU-feature cache in an x86-only module) |
| build scripts / native code | none except `num-traits` (an `autocfg` probe, host-only); no `links`, no C compiler | none |
| floats | `symphonia-core`, `-codec-aac`, `-codec-vorbis`, `-format-isomp4`, `-format-ogg` (and bytemuck, log, num-*) | everywhere (965 `f32`/`f64` mentions) |
| 64-bit atomics | none in the ten crates; `bytemuck` names `AtomicU64/I64` only under `cfg(target_has_atomic = "64")` | none (`AtomicU8` only) |
| `compile_error!` | none in the ten crates; `log` has seven, all feature-combination guards; `regex-lite` needs a 32/64-bit pointer width (32 here) | none |
| lock | 20 entries, **generated offline** (Symphonia commits none), sha256 `99e4fff5…` | 2 entries, generated offline, sha256 `ddd8830f…` |
| analyzer exit / findings | 3, **0 blockers**, 14 review, 21 info | 3, **0 blockers**, 5 review, 12 info |

`selected.inventory.json` / `default.inventory.json` are the compact per-package records; `*.audit.txt` is the analyzer's stdout. The first
run placed the consumer outside the export and got an `external-path-dependency` blocker; that was my layout, not a finding, and the
recorded layout (the export inside the consumer workspace, as `../upstream`) is the one used.

### Classifying the findings: dependency facts, scratch-consumer artifacts, audit gaps
* **Findings about the candidates (unqualified, for S02 to weigh):** the MPL-2.0 license is file-level copyleft and needs a human reading before
  a firmware image ships it; Symphonia's own README lists **AAC-LC only** (HE-AAC and HE-AACv2 appear with no support, "-"; AAC-ELD is not listed) and the facade has **no
  Opus feature** (`symphonia-codec-opus` exists in the workspace but is not selectable through `symphonia` at this pin and was not audited);
  425 `unsafe` tokens in seven registry dependencies the `forbid` in `symphonia-core` does not cover; opus-pure is pure Rust but **not unsafe-free**
  (132 tokens: x86_64 SSE/AVX and aarch64 NEON branches); every f32/f64 operation on the soft-float MIPS target is software, "a measured render
  budget decides whether that is acceptable" (the analyzer's words), and the actual-board FPU stays **unqualified** (E06 open item 1); Symphonia
  branches on `cfg!(target_endian = "little")` in `audio/sample.rs`, so a big-endian target takes the other branch.
* **Artifacts of the scratch consumer, not findings:** `license-missing` and `upstream-crate-no-unsafe-declaration` on `probe@0.0.0`.
* **Limits of this audit (incompleteness, not defects of the candidates):** the generated locks are this machine's registry cache, not upstream
  pins (a worker may resolve differently only if `--locked` is dropped); `unsafe` under a macro is invisible and `unsafe` under an off `cfg` is
  **counted** (so 132 is the whole file set, see section 2 for the per-target split); `tests/`, `benches/`, `examples/` are not scanned; only the
  selected feature sets were resolved (other Symphonia codecs and containers, `opt-simd`, opus-pure's `probe` feature are not evaluated, which is
  "not audited", not "unsupported"); nothing compiled, so no statement about whether either graph type-checks on a big-endian target yet.

## 2. Predictions (stated before any run), with how they were made
* **Graph `cargo check`, both candidates, both targets: PASS.** Symphonia: high confidence (no `compile_error!` that can fire, no 64-bit atomics, no
  target gates in the selected crates, registry dependencies likewise; the same `-Z build-std=std,panic_abort` recipe passed for all 24 workspace crates).
  opus-pure: medium-high (249 `target_arch` gates, but the non-x86/aarch64 paths are the scalar ones; edition 2024 and rust-version 1.88 are
  within the nightly). The only things that would fail these lines that this audit cannot see: nightly drift on a worker, or a `cfg` mistake in a branch
  that no machine has compiled for a big-endian target.
* **Root `-F unsafe_code` lint on opus-pure, both targets: PASS (zero `unsafe` is cfg-active).** By a textual cfg classification
  (`unsafe` token against the `#[cfg]` items that enclose it, evaluated for big-endian 32-bit Linux): of 130 tokens, 49 are active on x86_64, 65 on
  aarch64 and **0 on mips and powerpc** (all are gated on `target_arch`). The analyzer counts 132 and the classifier 130; the two-token difference is
  not explained (the classifier blanks comments and strings first). The compiler decides; this is a prediction, medium confidence.
* **The planted control: FAIL** with `error: usage of an `unsafe` block` ("requested on the command line with `-F unsafe_code`"). If it passes, the
  flag did not reach `opus-pure`, and the two PASS lines above prove nothing.
* No graph line is predicted to fail, so there is no predicted failure to explain. If one does fail, it is a finding for S02 (record the class: compile,
  resolve, or infrastructure), not a defect to patch.

## 3. The original check plan (execution update below)
Prepare the four directories (offline, no shell, refuses an existing `--out`), from the repository root:
```
python3 -B -I toolchain/results/e06/codecs/prepare_candidates.py --archives-dir build/e06-candidates --locks-dir toolchain/results/e06/codecs/locks --out <NEW dir P>
```
It verifies both archive digests and the three lock digests, extracts with tarfile's `data` filter, and prints a tree digest for each directory;
they must equal `consumers.json` (`consumer_tree_sha256`, `lint_tree_sha256`, `lint_planted_tree_sha256`). Then, each with its `cwd` and
`RCH_CANONICAL_PROJECT_ROOT` set to that directory, `RCH_WORKER=trj,hz3` (the workers with `rust-src`; ts1 is not admitted), `-j 2`:

| id | cwd (under P) | command after `rch exec --` | predicted |
|---|---|---|---|
| c01 | `symphonia-ws` | `cargo +nightly check --locked --release -p probe --target mips-unknown-linux-musl -Z build-std=std,panic_abort -j 2` | pass |
| c02 | `symphonia-ws` | same, `--target powerpc-unknown-linux-musl` | pass |
| c03 | `opus-ws` | `cargo +nightly check --locked --release -p probe --target mips-unknown-linux-musl -Z build-std=std,panic_abort -j 2` | pass |
| c04 | `opus-ws` | same, `--target powerpc-unknown-linux-musl` | pass |
| c05 | `opus-lint` | `cargo +nightly rustc --locked --release --lib -p opus-pure --target mips-unknown-linux-musl -Z build-std=std,panic_abort -j 2 -- -F unsafe_code` | pass |
| c06 | `opus-lint` | same, `--target powerpc-unknown-linux-musl` | pass |
| c07 | `opus-lint-planted` | same as c05 | **fail** (control) |
| c08 | `opus-lint-planted` | same as c06 | **fail** (control) |

(`plan-graph.txt` in each candidate directory is the analyzer's own plan, byte for byte; `opus-pure-.../plan-root-lint.txt` carries c05-c08.)

### How each line is judged (from its raw log, by name; a missing or 103-only log is "no result", never a pass)
* **c01-c04**: `audit.py ingest` (existing), one call per candidate with its own `--plan-file` and `--rev` (the pin above), over rows
  `{"crate": "probe", "target": <triple>, "status": "pass"|"fail", "evidence": "<log file>", "note": "rc=<n> worker=<alias> rev=<pin>"}`. It reads
  each raw log, requires the command, the exit status, the worker and the `Finished` line to agree with the row, and writes a redacted record only if
  every claim holds.
* **c05, c06**: pass = remote exit 0 and a cargo `Finished` line with no `error`. A failure whose log names `-F unsafe_code` lists the cfg-active
  `unsafe` sites: that is a finding about opus-pure on that target.
* **c07, c08**: the control holds only if the exit is nonzero **and** the log contains ``usage of an `unsafe` block`` and `-F unsafe_code`. A
  nonzero exit without those (a toolchain or sync error) is "no result". A control that passes voids c05 and c06.

## 4. Observed central outcomes (2026-11-05)

All eight audit obligations have observed outcomes: four graph checks and two
clean root-lint checks passed; both planted-unsafe controls were rejected.
The records preserve the controls as failures, not successful builds:

| Obligations | Targets | Actual outcome | Verified records |
|---|---|---|---|
| c01, c02: Symphonia graph | MIPS, PowerPC | exit 0 | `central/symphonia-checks.jsonl` |
| c03, c04: opus-pure graph | MIPS, PowerPC | exit 0 | `central/opus-checks.jsonl` |
| c05, c06: clean opus-pure root lint | MIPS, PowerPC | exit 0 | `central/opus-root-lint-checks.jsonl` |
| c07, c08: planted unsafe root lint | MIPS, PowerPC | exit 101, explicit unsafe-block rejection | `central/opus-root-lint-controls.jsonl` |

**The lint invocation changed, transparently.** c05-c08 were executed as
`cargo +nightly clippy --locked --release --lib -p opus-pure --target <triple> -Z build-std=std,panic_abort -j 2 -- --no-deps -F unsafe_code`,
through strict RCH with a source-content receipt. The originally proposed
`cargo rustc` code-generation commands did not complete and are not claimed as
run. They needed RCH's generic job mode, which reserved 20 GiB; classified
Clippy reserved 4 GiB without reducing the worker's protected disk floor.
Clippy establishes the builtin root unsafe-lint obligation on this exact
source, not rustc code generation. The pinned root has no `cfg(clippy)` branch
or build script. Both targets use the same source, lock, features and forbid
flag for their clean and planted cases. Each control has the unsafe diagnostic
and also a separate `missing_docs` error from the planted public function;
nonzero exit alone is not the control oracle.

The six new records bind raw-log digests and RCH source receipts. Independent
review compared all 1,566 transferred file entries against the pinned consumer
trees, including file bytes, sizes and executable bits, and verified terminal
ACK, absent owners and retirement/releases for all six jobs. Raw logs remain
private because they contain machine paths and worker addresses. Earlier CLI,
disk-admission and slot refusals are retained separately and earn no pass.
The prior c03 pass was repeated once to obtain a directly available raw log;
the new record is the observation cited here.

The existing ingest now recognizes only RCH's exact paired managed build-dir
and target-dir override, bound to the same log's worker, rewrite witness and
source receipt. It still compares all remaining argv to the independent plan
and rejects unrelated configuration changes. Root-lint records use the same
command/result verifier with the actual Clippy plan and additionally require
the causal unsafe diagnostic for each planted control. No dependency is
admitted by these observations.

## 5. Not established
Anything about runtime: decoder conformance for AAC-LC, ALAC, Vorbis, Ogg, MP4 or Opus, real-time budget on either soft- or hard-float CPU, memory use,
or the board FPU. Whether the other Symphonia codecs, containers and
`opt-simd` features, or `symphonia-codec-opus`, are acceptable (not audited). Whether the registry versions a worker resolves equal the generated locks
(`--locked` makes a mismatch an error, not a drift). No dependency is admitted by any of this.
