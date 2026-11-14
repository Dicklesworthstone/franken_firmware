# Timely owned lease renewal: host execution evidence

Source commit: `68004323fcd7d39859aef7932e4d5c98f8d47032`.
Baseline: `76fb9f0fc716861a670d70bb41c5bfe89070ad4a`.

The active fresh `SettledRender` now accepts a trusted configured issuer's
same-epoch renewal intent. It checks the exact held canonical, control and
join tokens, health, identity and stop state. It preallocates replacements,
takes final conservative time bounds, validates every old lease through the
admitted publication budget, and caps the new expiry from the earliest
plausible current time plus the actual membership maximum. After the one
fallible control installation, only synchronous authority/join swaps follow.

This is a trusted in-process operation: a public token is not a credential.
The publication budget is a caller-admitted group-time bound requiring target
qualification. It is not proof against arbitrary OS preemption. Renewal first
reconciles committed gain/mute policy; a refused candidate preserves token
and grant copies but is not a side-effect-free policy probe.

## Observed gates

| Native execution | Actual result |
| --- | --- |
| `30107136981729364` | Strict remote workspace/all-target Clippy, warnings denied; exit 0 |
| `30107136981729365` | Focused: 12 passed, 0 failed, 0 ignored, 819 filtered; two footers; exit 0 |
| `30107136981729366` | Workspace: 3,070 passed, 0 failed, 2 existing ignored, 0 filtered; 81 footers; exit 0 |

All twelve added cases pass once in both test executions. The full session
harness retains all 119 prior cases plus four new ones; the speaker harness
retains all 700 prior cases plus eight new ones. The control harness retains
all 690 prior cases, including the installed-lease equality assertions. Both
existing ignored tests
remain identified in the selected output. Seven touched Rust files pass
Rustfmt 1.99.0, edition 2024; no Python changed.

The positive and rejection-then-positive cases use actual authenticated
localhost PCM buffered under the old live lease. Each requires a new nonzero
protected HAL-model submission after an independently computed earliest
possible group time beyond the old expiry, complete 512-frame reference PCM,
and actual model drain acknowledgement with no pending/UAF/mutation. The
reference is separately assembled using the same DSP implementation; this is
integration evidence, not independent DSP or physical correctness proof.

Other cases check strict extension and earliest-time horizon, checked time
and budget overflow, configured-vs-quorum/discovery/identity, exact expiry
and publication-margin boundaries, fresh final-clock-sample expiry, storage
failure, STOP, no automatic output grant, fixed N03 authority expiry, and
withheld flush acknowledgement. The exact installed-control-token predicate
also adds positive/mismatch assertions to its existing full-suite case.
Private control/join corruption is not injected; encapsulation and the
source-reviewed equality checks own that unexecuted internal invariant.

The frozen inventory contains 1,686 files. Every native receipt matches all
1,684 transferred path/hash/size/executable tuples; only the two tracker
files are excluded. Terminal acknowledgements, absent wrappers and released
staging/source/pair/tree/record custody are verified. `receipt.json` binds
raw-log hashes; `observed.txt` preserves selected actual lines and all 81
workspace footers.

## Reproduction

Use an immutable source candidate at the source commit and a freshly
admissible remote Rust 1.99 worker. Preserve strict remote/offline operation;
refresh source, disk, current holds and admission before each gate.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
```

Proceed only after terminal exit 0, exact same-execution source receipt,
terminal ACK, released staging/source/pair/tree/record custody and absent
wrapper. Shell sequencing does not prove those checks.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline -p franken-session -p franken-speaker --lib lease_renewal:: -j1 -- \
  --show-output --test-threads=1
```

Before the full suite require the same receipt/ACK/custody gate and exactly
12 passes, zero failures/ignored, 819 filtered, two footers and all twelve
required names once/OK. Stop on mismatch and retain the failure. Refresh
source, disk, current holds and admission again.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- \
  --show-output --test-threads=1
```

## Qualification boundary

Renewal does not extend N03 clock authority, issue an output grant, reset
protection/mute, change the source/epoch, revive stopped playback or restore
cross-restart authority. It is not signed renewal transport, quorum proof,
post-expiry granted drain, takeover or complete group/source lease renewal.
No QEMU/SDK/target fit, physical audio/network, provider or native-tailnet run
was performed. Original G01 acceptance/dependencies stay open; canonical
Asupersync and its AGY hold are unchanged.

This historical capsule serves the owner and independent publication reviewer,
gates revision-bound publication required by AGENTS.md, and records the
observed missing owner renewal seam and the reconciliation/timing-proof risks.
It retires from active maintenance when this wave ends; it adds no runtime
machinery.
