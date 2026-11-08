# P05 standalone runtime probe: compile and lint evidence

The consumer is [`ffw-p05-runtime`](../../../src/p05-runtime/Cargo.toml), a
standalone research executable for P05 (`ffw-ipz`). It links Asupersync at
`460306de2aa4169510873716018ade44fdb01534` and builds a bounded `LegacyProfile`.
Its native test calls the same `run_probe()` implementation as the executable:
spawn/join, cancellation-aware and cancellation-blind abort, timers, loopback
UDP, bounded blocking work and root drain. It checks 13 named phases and ten
thread/memory census samples. Eighteen other tests exercise its parsing and
classification helpers, including permitted positives and planted defects.

**Native execution and BE/QEMU qualification are pending.** All 19 test
functions type-check; none has an execution result in this record. This is
not evidence of memory fit, latency, stock-kernel compatibility, physical
audio or a completed P05/P03 acceptance condition. The existing `p05-target`
guest executes atomic-cell tests, not this runtime probe.

## Observed checks

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

Run from the repository root with a suitable Linux worker. The explicit
three-file overlay reproduces the captured input selection; capacity and
ownership admission must succeed for each command.

```sh
RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 \
rch exec --worker "${FFW_VERIFY_WORKER:?select an eligible Linux worker}" \
  --base 76e6263f813254b4278504948ae871810dffda18 --clean-overlay \
  --overlay-path toolchain/src/p05-runtime/Cargo.toml \
  --overlay-path toolchain/src/p05-runtime/Cargo.lock \
  --overlay-path toolchain/src/p05-runtime/src/main.rs \
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

The existing P05 entry point now exposes the real runtime separately from
the atomic-cell analyzer. The Rust probe and its 19 tests are unchanged;
none has executed in this record.

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
archive; the archive's bytes are independently read back.

The checker requires all 13 named phases, ten complete census samples and
matching `END` totals, with independent checks of the printed phase facts.
It checks the child's byte count, FNV and exit status, then applies the
unchanged strict bootstrap checker to the supervisor envelope. Missing
reboot, contradictory details, unsupported/partial/unknown observations,
timeouts and nonzero exits remain failures. Atomic-cell markers cannot
satisfy this path.

For a separately captured native **standalone executable** transcript:

```sh
scripts/e2e/p05 --runtime analyze --arch x86_64 \
  --elf "$FFW_RUNTIME_ELF" --log "$FFW_RAW_TRANSCRIPT" \
  --receipt "$FFW_NEW_RECEIPT"
```

The native Rust test calls `run_probe()` and checks its report directly; it
does not print `END`. Use the standalone binary for this transcript command.
Analysis checks supplied bytes, not execution custody or process exit:
retain the original RCH terminal result and artifact/source receipt too.
Receipts distinguish captured guest execution from supplied transcript
analysis and hash raw bytes, including CRLF. A source revision supplied on
the command line is an operator claim, not compiler attestation.

## Runner regression results

The Python-only runner change passed:

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
