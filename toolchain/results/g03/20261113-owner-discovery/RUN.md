# Owner-backed discovery and eventing qualification

Code commit: `5c66e7402478283ee9f90de43516d4037bdafb0a` (tree
`6209c51f61518ed98be185cb2978938628dc2e74`), parent
`76f42445acc729932ca9659662ce4b5253689afd`. The separate client package
uses the pinned Frankensonos input `8f422c333269073a256fe59c6f50e7e8429a1bf9`.

## Delivered component

A validated Device identity now drives the actual Endpoint description,
headers, local topology and topology events. A concrete-mailbox loopback
constructor attaches the real event outbox and requires an owner-serviced
description preflight before readiness or SSDP advertisement. It compares
XML plus unique location, content-type and cache-age headers. Later requests
still reach the same owner. The real client tests use one SettledRender for
discovery, topology, subscriptions, volume, protected PCM and transport
restart/resubscription. This is bounded host-loopback and modeled-HAL proof.

Legacy constructors and their positive behavior remain. Unconfigured Tailnet
GET retains its original bare405; configured Tailnet descriptions refuse401.
The new constructor deliberately accepts generic mailbox owners; caller
responses cannot attest that a protected playback owner is present. The
actual-client tests, rather than a caller-supplied boolean, exercise that
protected-owner composition.

## Commands and source identity

The following are path-normalized commands: `$SNAPSHOT` is an immutable
two-repository qualification copy, `$RCH_CONFIG_DIR` and `$RCH_SOCKET_PATH`
select its existing private helper, and `$RCH_WORKER` is its single admitted
remote worker. RCH additionally injects its remote build-directory and
source-provenance Cargo config. Those machine-specific paths are omitted.
Every Cargo command used `RCH_REQUIRE_REMOTE=1`; no local fallback, global
shim change or concurrent Cargo job was used by this verification sequence.

```sh
cd "$SNAPSHOT/franken_firmware"
export RCH_REQUIRE_REMOTE=1 RCH_CONFIG_DIR RCH_SOCKET_PATH

rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings

rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- \
  --show-output --test-threads=1

rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  cargo +nightly-2026-08-31 clippy --locked --offline \
  --manifest-path tests/g03/fsonos-client/Cargo.toml --all-targets -j1 -- -D warnings

rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  cargo +nightly-2026-08-31 test --locked --offline \
  --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 -- \
  --show-output --test-threads=1

rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  "RUSTFLAGS=-D warnings -C debuginfo=0" \
  cargo +1.99.0 test --locked --offline -j1 -p franken-speaker \
  --features harness --doc start_discoverable_eventing_with_mailbox
```

The corrected native snapshot contains1648 firmware files, with two tracker
configuration files excluded from transfer (1646 transferred). It is baseline
`c93f3e2d551c1a8e724ede47c687bdffe517fe8e` plus the five Rust and three Python
inputs listed by the frozen source record. The three Python inputs were
subsequently published in parent76f42445 without changing bytes. Every
transferred path/hash/length/executable tuple was independently compared,
including1705 tuples for the SDK gates (1646 firmware plus4 sibling metadata,
51 protocol and4 type files). Runtime receipt roots differ by execution;
source equality was established from tuples, not equality of job roots.

The committed case registry is the **only** changed file versus that native
snapshot. It adds G03-I36 for three new server tests and maps two existing
regressions to existing invariants. No prior case, vector or validator was
removed or weakened. Its separate full offline qualification was:

```sh
cd "$REGISTRY_SUCCESSOR/franken_firmware"
scripts/e2e/g03 --tier full --judge "$WORKSPACE_TEST_RAW_LOG" --receipts "$RECEIPTS"
```

This Python reference/unit-log pipeline passed52/52 cases, judged189/189
Rust results, and produced105 complete diagnostic events with zero dropped
or lost-critical records. All28 referenced artifact hashes were verified.
Its actual-client gate remains OPEN; the separate native323 suite supplies
the narrower actual-client evidence described here, not full G03 acceptance.

## Observed results and preserved failures

`observed.txt` retains all test footers plus required-case, ignored-case and
failed-case result lines. `receipt.json` records exact denominators, source
and raw-log hashes, native IDs, terminal acknowledgments and applicable
source/pair/tree/record/staging release status. Raw remote logs are retained
privately because they contain machine paths; this capsule contains no live
site identifiers, credentials, firmware or packet captures.

| Native suffix | Check | Observed result |
|---|---|---|
|316|Initial workspace Clippy|exit0, compile check only|
|317|Initial full workspace|**2972 passed,5 failed,2 ignored**, exit101|
|318|One focused original loopback test|1 passed,1 filtered; three nested cases passed|
|319|One focused original group test|1 passed,2 filtered; three nested cases passed|
|320|Corrected workspace Clippy|exit0, compile check only|
|321|Corrected full workspace|2977 passed,0 failed,2 ignored,0 filtered;81 footers|
|322|Actual-client Clippy|exit0, compile check only|
|323|Full actual-client package|22 passed,0 failed/ignored/filtered;7 footers|
|324|Harness API rustdoc|2 compile-only examples passed;2 footers|

The45 required workspace names and22 required client names each occur
exactly once as successful results. Both324 examples are compile-only:
the positive is no_run; the negative has compile_fail,E0308 annotation.
Normal raw output shows compile-fail success but does not print the actual
diagnostic code. Formatting passed for the five Rust inputs; the diagnostic
Python changes were py_compile checked and30/30 tests passed.

Initial317 failed on a production-stepper source-classification test, two
legacy unconfigured-Tailnet405 assertions, and two MP3 process oracles.
Explicit cfg(test) nesting fixed classification without changing the scanner;
the original405 fallback was restored without changing old assertions.
The MP3 failures were:

- source_group_processes_match_pcm_and_isolate_wrong_key: receiver1 exited
  without done in the long three-speaker MP3 case.
- source_loopback_processes_match_independent_pcm_and_reject_wrong_key:
  long MP3 reported concealed/rejected media.

Original failures lacked attributable per-process counters/stderr in the
recorded evidence. Native318/319 added bounded actual failure diagnostics,
with unchanged audio cases, deadlines, assertions and tolerances. Each
original case passed on its one authorized focused attempt and in321.
**Cause remains unknown; NOT REPRODUCED does not mean fixed.** The initial
client Clippy/client tests/docs were NOT RUN after317; later320–324 are a
separate corrected-source sequence. Failed317 has no owned/configured
retrieval-stage record: staging release is N/A, not fabricated true.

Two offline registry attempts also failed and remain failures:50passed/1failed
for the original unclaimed-test budget, then50passed/2failed for an invalid
SSDP namespace and the still-unmapped original regressions. The corrected
server invariant and explicit existing mappings passed52/52 with unchanged
coverage validators and vectors. No golden regeneration or threshold change
was used to obtain a pass.

## Remaining qualification

G03 remains open for actual group/join/leave and complete controller E2E
acceptance. Production listener, multi-ingress event routing, native Tailnet,
provider, target-resource and physical-device qualification are also not
established by this host component. No live device, unlock, exploit, firmware
install or provider action occurred. The known MP3 reliability finding stays
open. Source and same-execution evidence reviews are independent reviews,
not independent runtime replications.
