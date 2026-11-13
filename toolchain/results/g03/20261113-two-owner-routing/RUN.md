# Two independent owners through the actual client

Code commit: 7e8d0ca5af916b16f1353f5fa07dc6f443e372c2, tree
a6554537448b42352b885a5c72e0553bcd038a22, parent
0de50777ab5b9d82aa61afdbab69a3d09a63badc. The separate client uses the pinned
Frankensonos protocol/type inputs at8f422c333269073a256fe59c6f50e7e8429a1bf9.

## Behavior and corrected test evidence

The bounded host adapter can now advertise distinct logical loopback player
addresses for distinct actual mailbox owners. The old constructor delegates
with its original localhost default. The new constructor and Device helper
retain fixed advertised port1400, validate the logical address before startup,
and keep actual TCP/UDP sockets on127.0.0.1 ephemeral ports. No multicast,
wildcard listener or off-host listener was added.

Actual owner-serviced metadata preflight still checks exact XML and unique
location/type/cache-age headers before readiness and responder creation.
Exclusive mailbox/outbox association and later owner-routed requests remain.
No public factory or caller flag can substitute for that preflight. The API
can serve generic mailbox owners; protected playback is established by the
actual SettledRender tests, not inferred from the API type alone.

Fresh review found that the preceding actual-client fixture named coordinator
coord without including it among its sole member. Its parser accepted that
shape, while the real grouping reconciler rejects it. The earlier passing
results are retained at their stated scopes; they did not prove grouping
readiness. All one-owner fixtures now self-coordinate through the same actual
session, issued authority and fresh-group provisioning. Parsed topology must
contain its coordinator exactly once.

The new paired case has two genuine standalone owners with distinct member
UUIDs, group IDs and endpoint subscription namespaces. Two explicitly targeted
actual SDK unicast SSDP searches each find their own responder. A confined
client with two routes then reaches both real owners for description, topology,
volume and subscriptions. One search does not discover both unicast responders.
The test wrapper validates exact hosts/description URLs, unique routes and
actual localhost destinations before using Lan; Lan routes alone are not a
network allowlist. Callbacks use their actual localhost peer addresses.

The case checks independent SID/sequence/state/callback behavior and nonzero
protected PCM against same-identity baselines. Wrong-owner mailbox use, reused
attachments, mismatched advertised metadata and wrong-owner SID renewal refuse.
After one adapter is stopped and its owner performs fenced cleanup, the other
remains operational. Actual modeled flush acknowledgments are still required.
Synthetic media keys and numerical clock leader are shared fixture inputs;
this proves neither key separation nor distributed-clock synchronization.

Source review rejected the first paired oracle: it checked only required
positive service and used cached last-response snapshots for peer state.
That source was never run or committed. The corrected helper joins its real
SDK worker and requires the exact per-owner service pattern. Fresh owner-serviced
reads check the untouched peer. A deliberate successful B-then-A read under an
A-only expectation must fail specifically with observed[true,true] versus
expected[true,false], followed by a permitted paired read. The bounded
FFW_TWO_OWNER_ISOLATION_CANARY line records that expected rejection; it is not
an unexpected failed test. Prior callback, PCM, token, stop, revision and deadline
checks remain. The invalid coordinator expectation is corrected, with stronger
membership and fresh-read assertions.

## Commands and complete source binding

All five exact Rust inputs passed pinned Rust1.99 formatting. These are the
actual remote recipes with machine-specific paths normalized. SNAPSHOT denotes
the immutable two-root copy. The helper/worker variables select the existing
private verifier; RCH additionally injects build-directory/source metadata
Cargo config. RCH_REQUIRE_REMOTE=1 was enforced for every command. There was
one active build at a time, no local fallback and no global shim/cache change.

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

The native freeze84857e25bf88b88004edb401bfa324700714e293bb2c189ff832c3ecea624d5a
contains1651 firmware files; every committed code-commit blob/mode matches that
copy. Native receipts transfer1649, excluding only the two tracked .beads
configuration files. Client gates transfer1708 tuples across firmware1649,
sibling workspace metadata4, protocol51 and types4. Every unique path, hash,
length and executable flag was checked; no excluded tracker/Git/EE data enters
the transferred sets. The unchanged sibling inventory retains an earlier
freeze label in its header; equality is established by its full file tuples,
not by asserting that the old header names this freeze.

## Observed final results

| Native suffix | Gate | Actual result |
|---|---|---|
|325|Workspace all-target Clippy|exit0, warnings denied|
|326|Complete workspace tests|2984 passed,0 failed,2 existing ignored,0 filtered;81 footers|
|327|Separate actual-client all-target Clippy|exit0, warnings denied|
|328|Complete actual-client package|24 passed,0 failed/ignored/filtered;7 footers|
|329|Explicit harness API examples|2 compile-only examples passed;2 footers|

All52 required workspace names and24 required client names occur once with ok.
The two existing ignored cases are the exhaustive2^32 float sweep and the
25.5virtual-hour D03 soak. They were not run and are not relabeled passed.
The API examples are a no_run accepted-client compile and a compile-fail wrong
control-type case. Its E0308 annotation is source evidence; normal rustdoc
output does not print the actual compiler diagnostic code. Neither example
executes the runtime.

The unchanged full offline G03 pipeline was also run once against native326:

```sh
scripts/e2e/g03 --tier full --judge "$WORKSPACE_TEST_RAW_LOG" --receipts "$RECEIPTS"
```

It passed52/52 cases, judged189/189 Rust results, verified28 declared artifact
hashes, and retained105 complete diagnostic events with zero drops or lost
critical records. That reference/unit-log pipeline leaves its actual-client
gate OPEN. The separate24-case package supplies the narrower host-client
component evidence described here; neither result closes full G03.

receipt.json records exact denominators, source hashes, jobs, terminal ACK and
all applicable staging/source/pair/tree/record release facts. All five wrappers
were confirmed exited. observed.txt retains actual result lines, all test
footers and the bounded expected canary. Raw RCH logs stay private because they
contain machine paths; their SHA-256 identities are recorded. Independent
source, same-execution evidence and privacy reviews are not runtime replications.

## Preserved failures and remaining work

The first source-only paired oracle was rejected with SDK hash6856fca3... and
freeze d2c7b671...; it remains NOT RUN. The final source strengthens its
service/peer-state checks instead of removing assertions. The original
native317 failure and two failed offline registry attempts remain in
[the preceding evidence](../20261113-owner-discovery/RUN.md).
Later passes do not explain the original MP3 process failure causes.

This component does not implement actual group join/leave or authenticated
coordinator readiness/authority transfer. Production ingress, full originalG03
E2E acceptance, target resources, physical audio, providers and required native
Tailnet remain unqualified here. No requested feature was removed, no bead was
self-closed, and no live device, unlock, firmware install or provider action
occurred. The separate P05 guest experiment has its own evidence and does not
supply physical-speaker or production memory qualification for this component.
