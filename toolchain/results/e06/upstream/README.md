# E06: third-party inventory at pinned revisions (Asupersync, `franken_kernel`, FrankenLibC)

Read-only and offline. The two upstream repositories are local clones; this work never wrote to them. Each run exported the
pinned revision with `git archive` into a scratch directory and audited the export with `scripts/e06/audit.py`. Nothing was
downloaded, built with cargo, linked or run, and these are **inventories of dependency graphs**, not admissions.

| subject | revision | clone state | lock |
|---|---|---|---|
| Asupersync (includes `franken_kernel`, `franken_evidence`, `franken_decision`) | `8940119023c0e01b4d6d3e2c1399f41417c2ad24` | clean | committed `Cargo.lock`, 477 entries |
| FrankenLibC | `76d7f3469f5f5251661b3662926d3d6a2b36d494` | clean | **none committed**: see below |

`franken_kernel` is a crate inside the Asupersync repository (`franken_kernel/`, package `franken-kernel` 0.6.0), so it is pinned by
the same revision. `frankenfs` and `franken_remote` are not in scope here.

## Method, and one trap that cost a first attempt

**`cargo metadata` of an upstream workspace is not an inventory of one configuration.** It resolves every member together, so
features that other members enable (`fuzz`, `test-internals`, `metrics`, `tracing-integration`, even `default`) are unified into
`asupersync` whatever `--no-default-features` says. The first attempt reported identical closures for default, bare and
`runtime-core`, and `asupersync` showed those extra features enabled with no feature selected. It was discarded.

What is used instead, for Asupersync, is a **scratch consumer workspace**: one member (`probe`) depending on the pinned export by
path with the exact feature set, starting from the upstream's own `Cargo.lock` so every registry package keeps the upstream's
pinned version. Cargo pruned the lock and added the probe. `consumers.json` records, per configuration, the probe's dependency
lines and that **all 175 registry packages in the consumer lock are exactly the upstream lock's (name, version, checksum)**
(11 of 11 for the `franken_*` crates): no version drift. This is the method the audit's own candidate text describes.

**FrankenLibC has no `Cargo.lock` at this revision**, so its transitive versions are not pinned by the repository. The audit
generated one **offline from this machine's registry cache** (`Cargo.lock.generated`, sha256 `b2957df3533a…`, 98 entries) and says
so in the report (`lock.origin: generated-offline`, finding `lock-generated-not-an-upstream-pin`). The generated lock is **not an upstream pin**: another machine or date can
resolve different versions. `--generate-lock` refuses to run inside a git work tree, so it only ever writes into an export.

**FrankenLibC cannot be resolved offline as a whole.** Thirteen crates (`asupersync-conformance 0.5.0` and twelve `ftui-*`) are not in
the local registry cache; they are dev-dependencies of `frankenlibc-membrane` and of tooling members, so they never reach a firmware
graph, but `cargo metadata` resolves dev-dependencies and nothing was downloaded. `unreduced-attempt.txt` keeps that failure. The
inventory is of a **reduced scratch export**, with exactly two edits recorded in `export-edits.json` (file, removed lines, sha256
before and after): the workspace members reduced to `frankenlibc-core`, `-abi` and `-membrane`, and the seven dev-dependency lines
for the missing crates removed from the membrane's manifest. Nothing else changed. Dev-dependencies do not affect a firmware build.

## What was found

### Asupersync (`runtime-core` is a marker; the closure is large with no features at all)
- **The features `runtime-core` and `native-runtime` are `= []` in `Cargo.toml`.** Selecting them adds and removes nothing:
  `--no-default-features`, `--features runtime-core` and `--features runtime-core,native-runtime` give the **same 145 packages** and
  the same findings. Default adds exactly one package, `asupersync-macros` (host-side, via `proc-macros`). So the name excludes no
  dependency: the bead's warning, measured.
- **With no features, the probe's closure is 115 linked packages on each big-endian target: the probe, Asupersync and 113 dependencies**
  (110 registry, 5 path including the probe), with 21 more host-only. Both targets have the same closure. It includes a crypto stack (`aes-gcm`, `chacha20poly1305`, `ed25519-dalek`,
  `curve25519-dalek`, `sha1`, `sha2`), `sysinfo`, `nix`, `rustix`, `linux-raw-sys`, `signal-hook`, `socket2`, `polling`, `tempfile`,
  `xattr`, `prost`, `serde_json`, `rmp-serde` and `bincode-next`. A slim profile needs real gates upstream (P05); the markers are not that.
- **Unsafe:** Asupersync's own crate has 562 `unsafe` tokens (declared `deny`, not `forbid`); **76 of the linked dependencies contain
  `unsafe` in their own source (15,548 tokens in all)**, the heaviest being `linux-raw-sys` (6,930), `rustix` (1,587), `nix` (840),
  `libc` (799), `sysinfo` (634) and `portable-atomic` (628). The `libc` crate is linked on both big-endian targets (it is an FFI table).
- **Native code:** no `links` key anywhere; build-script signals on `signal-hook` (a `cc` build-dependency) plus two `autocfg` probes.
- **License:** every linked package declares one. Four workspace crates (`asupersync`, `franken-kernel`, `-evidence`, `-decision`) are
  `LicenseRef-MIT-OpenAI-Anthropic-Rider`, a non-SPDX reference to a custom rider, which needs a human reading before any reuse.
- **64-bit atomics (a static signal, not a verdict):** 431 source files use `AtomicU64`/`AtomicI64` (3,197 mentions), all through
  `crate::sync::atomic` (or its public path `asupersync::sync::atomic`), which re-exports `core`'s types when `target_has_atomic = "64"`
  and `portable_atomic`'s sharded lock-table `fallback` otherwise (never `unsafe-assume-single-core`). A search of `src/` found **no
  direct `std::`/`core::` path to a 64-bit atomic outside the facade file**. Its header cites this project's `P05` / `ffw-ipz`.
  Dependencies' own 64-bit atomics were not scanned. The facade is a lock-based emulation: its semantics are P05's to classify.
- **std:** 57 packages `no_std`, 56 `std`, 2 undecided (`ppv-lite86`, `zerocopy`, both `cfg_attr(..., no_std)` on predicates the audit
  does not model). `asupersync` itself is `std` (threads, sockets, signals).
- Seven duplicate versions are linked (`block-buffer`, `const-oid`, `crypto-common`, `digest`, `getrandom`, `rand_core`, `sha2`).

### `franken_kernel`, `franken_evidence`, `franken_decision`
- Ten packages linked on each target: the three crates, `serde`, `serde_core`, `serde_json`, `itoa`, `memchr`, `zmij`, and the probe.
- **`franken-kernel` is `#![no_std]` plus `extern crate alloc`** (it uses `String` and `Vec`, so it needs a global allocator but no OS),
  **but its effective mode is `std`, because `serde = { version = "1.0", features = ["derive"] }` leaves serde's default `std` feature
  on.** Its own source is no_std; the dependency declaration is what links std. That is the transitive choice to validate before
  reuse, and it is upstream's one-line change (`default-features = false`) to make or not.
- `franken-evidence` and `franken-decision` are `std` (no `#![no_std]`) and use floats. All three `forbid(unsafe_code)` with 0 unsafe tokens.
- Six dependencies carry `unsafe` (433 tokens: `serde` 2, `serde_core` 2, `serde_json` 13, `itoa` 13, `memchr` 333, `zmij` 70).

### FrankenLibC runtime crates (`frankenlibc-core`, `-abi`, `-membrane`)
- 28 packages linked on each target (25 registry, 3 path) and 58 host-only (build-time).
- **`frankenlibc-abi` has 23,858 `unsafe` tokens and declares no `forbid` or `deny`**; `-core` has 965 and `-membrane` 115 (both declare `deny`).
  The workspace lint is `unsafe_code = "allow"`. Twenty-one dependencies add 2,329 more.
- `blake3`'s build script uses `cc`, a native-code build signal (what it compiles on these targets was not read); `frankenlibc-abi`
  emits a `rustc-cdylib-link-arg`.
- The workspace license is a `license-file` (`../../LICENSE`) rather than an SPDX expression.
- A libc replacement for these ISAs is a different question from this inventory: nothing here says its syscall layer targets MIPS or PowerPC.

## Central check lines (proposed; nothing here was run)
The plan files are in the format `scripts/e06/audit.py plan` prints, and feed `audit.py ingest`. Run each **inside a clean export of the pinned
revision**, so `--locked` uses that revision's lock.

| plan file | lines | notes |
|---|---|---|
| `asupersync-8940119023c0/plan-default.txt` | 2 | `-p asupersync` |
| `.../plan-no-default-features.txt` | 2 | `--no-default-features` |
| `.../plan-runtime-core-only.txt` | 2 | `--no-default-features --features runtime-core` |
| `.../plan-runtime-core-and-native-runtime.txt` | 2 | adds `native-runtime` |
| `.../plan-franken-support-crates.txt` | 6 | `franken-kernel`, `-evidence`, `-decision` |
| `frankenlibc-76d7f3469f5f/plan-runtime-crates.txt` | 6 | needs the edits and lock below |

- **Toolchain:** both repositories pin `nightly-2026-08-31` in `rust-toolchain.toml`; the planned `cargo +nightly` overrides it and uses
  the worker's nightly, so a failure could be nightly drift and not the code. Asupersync's `.cargo/config.toml` sets only `-Z threads=4`.
- **FrankenLibC's `.cargo/config.toml` applies `-Cllvm-args=-enable-tlsdesc` to every target**, and its own comment calls that an
  x86-64 TLS dialect option. Whether MIPS and PowerPC accept it is what the check will show; a failure there is the upstream config,
  not necessarily its code. It also needs nightly cargo features (`panic-immediate-abort`, `profile-rustflags`).
- **FrankenLibC setup:** export the pinned revision, apply the two edits in `export-edits.json` (members list; remove the seven
  dev-dependency lines), and copy `Cargo.lock.generated` over `Cargo.lock`. Without those, `--locked` has no lock to use.
- A failing Asupersync check (for example the `AtomicU64` facade) is an expected, recordable finding for P05, not a reason to stop.

## Not established
- Anything about runtime behavior, or that any of this builds: these are resolver and source reads. The checks above are what would show type-checking.
- Asupersync's *dependencies'* use of 64-bit atomics; `unsafe` under macros; `unsafe` under a `cfg` that is off (it is counted).
- A pinned FrankenLibC dependency set: the repository has none, and the generated lock is this machine's.
- Codec crates: none is named in the plan (see `docs/contracts/e06.md`). `frankenfs` and `franken_remote` were not audited.

## Files
| file | what it is |
|---|---|
| `asupersync-8940119023c0/*.inventory.json` | compact per-package inventory per configuration (`ffw.e06.inventory.v1`) |
| `asupersync-8940119023c0/plan-*.txt` | the proposed central check lines |
| `asupersync-8940119023c0/consumers.json` | the consumer dependency lines and the lock pin check |
| `frankenlibc-76d7f3469f5f/runtime-crates.inventory.json`, `plan-runtime-crates.txt` | the FrankenLibC inventory and plan |
| `frankenlibc-76d7f3469f5f/Cargo.lock.generated`, `export-edits.json`, `unreduced-attempt.txt` | the generated lock, the exact edits, and the failed whole-workspace attempt |
