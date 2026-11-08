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
