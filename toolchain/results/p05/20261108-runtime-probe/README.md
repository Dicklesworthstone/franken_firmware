# P05 standalone runtime probe: scoped compiler and execution evidence

> **Current source has separate compiler results from the historical record below.**
> Fresh-eyes corrections add six tests (25 total), bounded failure cleanup,
> timer-independent watchdogs, shared blocking deadlines, lossless census
> error handling and child-side cancellation cleanup witnesses. Formatting,
> strict remote compilation and Clippy now pass for those exact source bytes.
> All 25 cases and the standalone probe now also passed in a bounded native
> x86-64 GNU/Linux execution. BE/QEMU qualification remains pending; native
> success does not establish stock-kernel compatibility, resource fit or playback.

The consumer is [`ffw-p05-runtime`](../../../src/p05-runtime/Cargo.toml), a
standalone research executable for P05 (`ffw-ipz`). It links Asupersync at
`460306de2aa4169510873716018ade44fdb01534` and builds a bounded `LegacyProfile`.
Its native test calls the same `run_probe()` implementation as the executable:
spawn/join, cancellation-aware and cancellation-blind abort, timers, loopback
UDP, bounded blocking work and root drain. It checks 13 named phases and ten
thread/memory census samples. The original source had 19 tests. The current
25-test candidate also covers watchdog failures, missing start observations,
cleanup witnesses, census errors and shared blocking budgets.

**Current native execution passed; BE/QEMU qualification remains pending.**
The original compiler-only record below remains historical. The new native
record covers the current 25 cases, retaining all 19 original names. It is
not evidence of memory fit, stock-kernel compatibility, physical
audio or a completed P05/P03 acceptance condition. The existing `p05-target`
guest executes atomic-cell tests, not this runtime probe.

## Current candidate compiler checks

Both checks below used `x86_64-unknown-linux-gnu`, strict remote RCH on `hz2`,
`nightly-2026-08-31`, `--locked -j 1 --all-targets`, defaults disabled and
the current three input digests listed below. Check build
`30100509981409854` finished in 3m 22s; strict Clippy build
`30100509981409859` finished in 2.69s with `-- -D warnings`. Both commands
returned zero, emitted no compiler diagnostics and finished with terminal
acknowledgment, released sources, retired tree/pair and released staging.
All 25 Rust cases compiled; these commands executed none of them.

The source-content receipts independently verified exactly `Cargo.toml`,
`Cargo.lock` and `src/main.rs`, with check content root
`8a0590d91b6e099bf083607157f848b35d5b0acbb81d0d722766c6f97b7e1a33`
and Clippy content root
`26dc04fbddc58830bcd065784b604c4808d6e16516af6052f2bab5d6715aaca5`.
The build input was a standalone export preserving those bytes. Its
per-invocation canonical root used the resolved filesystem path; on macOS,
`/tmp` and `/private/tmp` must not be confused. No global RCH topology,
fallback, disk floor or worker setting changed.

Earlier attempts did not reach Cargo: a repository clean-overlay namespace
collision and an unresolved export path were settled through their exact RCH
job identities before proceeding. A Clippy admission refusal required a live
capacity refresh after the previous build released its reservation. These
failures remain recorded; they earn no compiler or runtime credit.

## Historical compiler checks

Both commands used strict remote RCH, one compiler slot, the pinned
`nightly-2026-08-31`, defaults disabled in the standalone dependency and the
committed Cargo lock. The lock was produced by the official Cargo resolver;
it has 179 dependencies, 180 packages including the probe.

| Check | Remote build | Observed result |
| --- | --- | --- |
| `cargo check --locked -j 1 --all-targets` | `30099060530610986` | Exit 0; Cargo finished in 5m 50s; no diagnostics |
| `cargo clippy --locked -j 1 --all-targets -- -D warnings` | `30099060530611005` | Exit 0; Cargo finished in 1.31s; no diagnostics |
| `rustfmt --edition 2024 --check --config skip_children=true` on `src/main.rs` | Local noncompiling check | Exit 0; rustfmt 1.10.0-stable (`b940084d7e`, 2026-09-28) |

Each remote job finished with terminal acknowledgment, a dead wrapper,
absent owner, released source authority, retired tree and pair, and a
completed project output phase. No executable artifact was produced by
these check/lint commands. They execute no Rust test.

The source was frozen before both commands:

| Input | SHA-256 |
| --- | --- |
| `Cargo.toml` | `3634d5a6dcfeb02280aa25372635a101ee6ce687c1e140561e37ddba1243b01d` |
| `Cargo.lock` | `870ae5f544e41b3b81769427bc3234d1862896eff7b27f12ed04d0e24b77773f` |
| `src/main.rs` | `efdf354a395a5dacfc2ff40aaa8174b393691c28aa4c19c18cbba477ea6988d6` |

Both clean-overlay receipts identify base
`76e6263f813254b4278504948ae871810dffda18`, overlay fingerprint
`90e7ed1cf1f2fa3dc642ae2f2983fe81fc50111d23d3cd74d950f15d484cd719`
and tree `faeaa98040b2d207a29dfa936a09f990fb4ad469`. These are clean-overlay
identities, not full per-file source-content receipts. Complete retained
private capture digests are:

- Check: `d077671c34cd9c683656cc3886d1bfc107bdf7fd1ded3cef9dfe4df7f1e4a2cb`.
- Clippy: `ff542e377601aa35751b4e52cb4696f8f797cc6485aacfc060d8b2a3599fef14`.

## Reproduce the verified source selection

Run from the repository root with a suitable Linux worker. The immutable
published commit below contains the three recorded original input digests;
it does not silently overlay the currently changed Rust source. Capacity and
ownership admission must succeed for each command.

```sh
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 \
rch exec --worker "${FFW_VERIFY_WORKER:?select an eligible Linux worker}" \
  --base fb466781e005465198339bce7fb920b3e317cee9 --clean-overlay --no-overlay \
  -- env CARGO_TARGET_DIR=/tmp/rch_target_p05_runtime \
  CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +nightly-2026-08-31 check \
  --manifest-path toolchain/src/p05-runtime/Cargo.toml --locked -j 1 --all-targets
```

For the lint command, replace `check` with `clippy` and append
`-- -D warnings`. Future native testing must run every named test with
`--test-threads=1`, retain failed/partial/unknown counts, and verify the
executable's observed phase markers. A missing executable, missing test or
incomplete census cannot be credited as a pass.

This probe predates the separate process-module feature change at
Asupersync `e30c91fd7593dd1396314c83a28afbbaf8890e98`. It does not verify
that new slim feature graph. Neither `runtime-core` nor `native-runtime`
removes dependencies at the probe's pin, and no size reduction is claimed.

## Runtime capture path

The existing P05 entry point exposes the real runtime separately from the
atomic-cell analyzer. The current Rust candidate has 25 tests; their native
execution is recorded below, separately from the pending BE guest path.

A direct `/init` installation of this probe would neither mount `/proc` nor
bring loopback up. It also parks after `END` as PID 1. The runtime runner
therefore reuses the existing `ffw-hello-init` supervisor, built with
**`speaker-smoke` only**. The supervisor mounts proc, brings loopback up,
launches and reaps the runtime as a child, then completes its normal probe
summary and reboot. The temporary slot is `/franken-speaker --catalog`;
`p05-runtime` ignores argv. This is a research harness slot, not production
speaker integration. Enabling `speaker-platform` would invoke another child
and is rejected by the transcript checks.

Build the runtime and matching supervisor ELFs through strict RCH first.
With the existing kernel cache in `FFW_BUILD_DIR`, boot already-built bytes:

```sh
scripts/e2e/p05 --runtime run --arch mips \
  --elf "$FFW_RUNTIME_ELF" --supervisor "$FFW_SUPERVISOR_ELF" \
  --log-dir "$FFW_FRESH_LOG_DIR" --receipt "$FFW_NEW_RECEIPT"
```

Use `--arch powerpc` for the matching PowerPC pair. The QEMU machines,
CPUs, consoles and 64 MiB guest memory follow the existing boot scripts;
`-nic none` disables emulated LAN interfaces. This does not test 32 MiB fit.
Capture retains at most 1 MiB across stdout/stderr and has a finite timeout
(180 seconds by default). Separate raw files are flushed as chunks arrive,
including on timeout or output overflow. Existing log files and receipts
are never overwritten. Both ELF hashes are checked against the packaged
archive before launching; the archive's bytes are independently read back.
The kernel is copied into a read-only, exclusively created
`vmlinux.runtime-snapshot` in the capture directory and that snapshot is what
QEMU loads. Kernel and initramfs hashes are checked after capture too, so a
changed or unreadable input cannot produce a green receipt. Exclusive
archive creation protects a competing writer even if it races the initial
empty-directory check.

The checker requires all 13 named phases, ten complete census samples and
matching `END` totals, with independent checks of the printed phase facts.
It checks the child's byte count, FNV and exit status, then applies the
unchanged strict bootstrap checker to the supervisor envelope. Missing
reboot, contradictory details, unsupported/partial/unknown observations,
timeouts and nonzero exits remain failures. Atomic-cell markers cannot
satisfy this path.

Serial marker boundaries must be LF or CRLF; Python's additional Unicode
line separators and bare control characters are rejected. Numeric facts
must be canonical ASCII decimal. Analysis input uses the same 1 MiB limit
as live capture, and ELF identity is hashed incrementally. The checker also
requires unique child-side cancellation cleanup observations after each
sleep resumes and before its original natural deadline. Legacy traces that
lack these observations are explicitly **blocked**, not upgraded into
cancellation proof by quiescent runtime counts alone.

For a separately captured native **standalone executable** transcript:

```sh
scripts/e2e/p05 --runtime analyze --arch x86_64 \
  --elf "$FFW_RUNTIME_ELF" --log "$FFW_RAW_TRANSCRIPT" \
  --receipt "$FFW_NEW_RECEIPT"
```

The native Rust test calls `run_probe()`, emits its observed `END` before
assertions and checks its report directly. The full test stream also includes
other helper markers; use the standalone binary for this transcript command.
Analysis checks supplied bytes, not execution custody or process exit:
retain the original RCH terminal result and artifact/source receipt too.
Receipts distinguish captured guest execution from supplied transcript
analysis and hash raw bytes, including CRLF. A source revision supplied on
the command line is an operator claim, not compiler attestation.
An existing receipt is rejected before execution, and a success result is
printed only after the requested receipt has been persisted successfully.

## Runner regression results

The original Python-only runner change at `9257308` passed:

- 35 new checker, packaging and capture tests: exit 0, 6.549 seconds.
- 313 existing serial, atomic-cell, initramfs, speaker-smoke and
  platform-smoke tests: exit 0, 13.953 seconds.
- `python3 -m py_compile` on the three touched Python files, `bash -n` on
  `scripts/e2e/p05`, and `git diff --check`: exit 0.

Reproduce the tests:

```sh
python3 -B -m unittest discover -s toolchain/tests -p test_measure_p05_runtime.py -v
PYTHONPATH=toolchain/tests python3 -B -m unittest -v \
  test_serial_validator test_measure_p05_target test_initramfs_archive \
  test_speaker_smoke test_platform_smoke
```

Transcript/ELF fixtures test the checker; actual bounded Python subprocesses
test capture behavior. The packaging tests substitute a clearly labeled
synthetic driver and exercise the real archive/capture plumbing. **No QEMU
guest or Asupersync runtime ran in these tests.** Independent source review
caught and confirmed corrections to phase-detail validation and raw-byte
hashing; source review is not runtime qualification. P05/P03 stay open.
The capture regressions also verify that selector-setup failures reap the
actual owned subprocess and close its pipes, and that raw output is readable
while the captured process is still running.

The fresh-eyes Python candidate passed **50/50 checker/capture tests** in
7.179 seconds and **313/313 existing regressions** in 18.160 seconds, both
exit 0. Final Python compilation, Rust formatting and whitespace checks
also returned 0. Those results do not qualify the changed Rust source.
All 19 original Rust test names are retained alongside six new cases.
All 25 subsequently passed in the bounded native run below. Full P05/P03
acceptance, actual BE execution and resource qualification remain open.

The current Rust candidate is distinguishable from the historical source
by these digests:

| Input | SHA-256 |
| --- | --- |
| `Cargo.toml` | `e8a0422d66dbf812fff67199422e68f5dea4ca3b72a14ab9f85f126bdb1157ae` |
| `Cargo.lock` | `870ae5f544e41b3b81769427bc3234d1862896eff7b27f12ed04d0e24b77773f` |
| `src/main.rs` | `518ea6fb815f75b828c8fcfcb339962e856641107196261938bd996e0380a90d` |

The 25-name native test list was frozen before any execution attempt;
its SHA-256 is
`76eb41f06710e0a23406f204250dd54f5771a826067a396d6ab31f1df5603608`.
The original dependency pin and lock remain unchanged. The manifest changes
only correct stale documentation about the supervisor and lockfile.

The second framing review planted two false-positive cases before fixing
them: malformed outer supervisor line separators and a child launched before
the remaining bootstrap probes. Protocol framing is strict from one literal
standalone `USERSPACE_START` onward, with CRLF normalized exactly once;
`CR CR LF` cannot be repaired into a valid boundary. OpenBIOS preamble
controls remain permitted: retained PPC captures contain bare CR before
userspace, and rejecting the whole raw stream would break valid captures.

## Observed native execution

Strict RCH build `30100509981409860` linked both executables on `hz2` with
`nightly-2026-08-31`, `--locked -j 1 --all-targets`, explicit
`x86_64-unknown-linux-gnu`, debug info disabled and incremental compilation
disabled. Cargo finished in 5m 43s, exit zero. The worker-verified source
receipt contains the same three input file digests above; its content root is
`35c26ee56c08dccbb0dd18be14ebc9f773cc82d9646f7ed8c49d91959906f475`.
Both outputs are dynamically linked x86-64 GNU/Linux ELFs, **not musl or BE
binaries**. RCH retrieved the application but omitted the test executable
under `debug/build`; read-only retrieval of that exact compiler-reported
test path matched the local hash and remote hashes around retrieval.

| Artifact | SHA-256 |
| --- | --- |
| Standalone ELF | `fe3b20f7cea5385472b34d132cab2a81cf275c340c7c10a9d0e659513964eacd` |
| Test ELF | `c6eb220ad8c55d5db6b5d856c8bcbfa320916a3f69baf7d43d4eae192d5269ca` |

Strict RCH execution job `30100509981409889`, wrapper
`rchw-4d100dd9-0f2f-4e3b-b202-55e92d50fdba`, then ran both built artifacts
on `hz2`. It ran no compiler. The exact [launcher](run-native.py) reused
`capture_guest` from the committed bootstrap runner, with 180-second and
1 MiB limits per process, separate exclusive-create raw stream files, and
ELF hashes checked before and after execution. The whole remote command
finished in 5.514 seconds, exit zero; result retrieval completed and native
job evidence confirms terminal acknowledgment, dead wrapper, absent owner,
released sources and staging, and retired tree/pair.

- [Test stdout](native-tests.stdout.txt): **25 passed, 0 failed, 0 ignored,
  0 measured, 0 filtered**, in 1.52 seconds. Every name in the
  [pre-execution frozen list](native-required-tests.txt) occurred exactly once.
- [Standalone stdout](native-standalone.stdout.txt): 13 phases, ten complete
  census samples and matching END totals: 23 ok, all other counts zero.
  Timer cancellation resumed one child and root drain resumed four distinct
  children under cancellation before natural expiry. The repeated root drain
  was quiescent with all outstanding counts zero.
- Both actual capture records ([tests](native-tests.capture.json),
  [standalone](native-standalone.capture.json)) report return code zero,
  no timeout/output-limit flag, matching ELF hashes, and empty stderr.
- The existing native transcript analyzer passed all six gates; its
  [analysis receipt](native-analysis.json) retains the correct
  `supplied_transcript_analysis` evidence class. Execution custody comes
  from the separate capture records and RCH job, not from this analysis.

An independent reviewer read the retrieved bytes, checked all frozen names
and hashes, and reran the Python analyzer against the actual ELF. That is
independent review of the same-origin execution, not a second native run.

The recorded execution command, from a fresh artifact capsule containing
the two exact ELFs under the launcher's expected names, the launcher at its
root, and `run-qemu-verification.py`, `mkinitramfs.py`, `speaker_expect.py`
and `platform_expect.py` under `toolchain/src/`, was:

```sh
RCH_REQUIRE_REMOTE=1 RCH_CANONICAL_PROJECT_ROOT="$(pwd -P)" \
RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 \
rch exec --worker hz2 --job --result-dir results -- python3 run-native.py
```

This launcher records the two exact linked artifacts; it is neither a
builder nor a general validator for newly rebuilt ELFs. New build inputs
need their own recorded identities before execution. No binaries enter Git.
The deployed CLI rejects `--job` with `--source-content-receipt`; the
execution job therefore has ordinary RCH custody and explicit worker-side
ELF hash checks, rather than a fabricated source-content receipt. Compiler
commands have their separate three-source-file receipts.

Earlier execution attempts were refused **before the payload started** by
active worker disk reservations. They returned 120, were reconciled by
their exact job IDs and earned zero test credit. The successful attempt
used fresh measured headroom and RCH's native retirement of dead process
groups. No disk budget/floor was lowered and no peer or ledger was changed.

This closes the compiler-only evidence gap for this narrow native consumer.
It does not qualify BE execution, stock kernels, 32 MiB fit, physical audio,
native service integrations, the separate upstream feature-graph change,
the original 196/public 23/cancellation regression sets, or P05/P03 closure.
