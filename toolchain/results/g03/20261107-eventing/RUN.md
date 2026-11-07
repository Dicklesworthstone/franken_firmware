# G03 host event delivery and controller integration

The first real-client eventing run executed successfully: **16 passed,
0 failed, 0 ignored**. The client is the actual sibling `fsonos-proto`, speaking
to the real endpoint through confined loopback sockets. Discovery, subscription,
ordered notifications, restart/stale-SID refusal, volume/mute, stalled callbacks
and refused destinations were exercised. No speaker, provider or tailnet was
contacted. These observations precede the same-server composition change below.

## First eventing source and native result

Base `b24b588` plus the reviewed eventing, wide-SID and callback-bound patches:
`4a1c1363`, `42b50cf9`, `882e0421`, `5fb30275`, `826c0f95`, `da8bf3bc`.
Legacy constructors and golden subscription IDs remain unchanged. The host
harness reads a boot incarnation once; device entropy qualification is separate.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
RCH_CONFIG_DIR="$BULK_PROFILE_DIR" rch exec --source-content-receipt --worker trj -- \
  cargo +nightly-2026-08-31 test --locked \
  --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 \
  -- --show-output --test-threads=1
```

The invocation-specific profile changes only `transfer.remote_base` and
`remediation.pooled_target.store_base` to the worker's existing bulk volume;
resource floors, growth reservations and fallback policy are unchanged.
Earlier slot, project-exclusion, queue and disk refusals remain retained and
contribute no test credit.

Build `30099060530610686`: exit 0; discovery 6/6, eventing 5/5 and control 5/5.
The retained end-to-end command took 2,500.5 seconds, including the cold build.
All **1,425/1,425** captured inputs matched before the later composition edit:
firmware 1,368; sibling workspace manifests 4; `fsonos-proto` 49; types 4.
The sibling revision was `71da04327c596db61858f79ad4851bd6c143767d`.
Firmware content root:
`c433686c8e9ddbf2c3cddb341896da8865eae98aa2a9a55adddeb17365f77c91`.
Terminal acknowledgment, wrapper termination, owner absence and all five
source/tree/pair/staging/recovery releases were verified.

[client-before-composition.txt](client-before-composition.txt) retains the
observed test names and verdicts. Complete operational log SHA-256:
`ca6dbce2deba53561c50f1f6b831bcf9d012338305e4ed3b4377bc09d595e5b9`.

## Unit, model and lint checks

The strict-remote control/speaker batch `30099060530610678` executed
**1,022 passed, 0 failed, 1 existing D03 soak ignored**. The command selected
`-p franken-control -p franken-speaker --features franken-speaker/harness`.
[unit-before-composition.txt](unit-before-composition.txt) retains the G03 names
and every test-group verdict; it is an excerpt, not the complete capture.

Its wrapper initially refused completion because two unrelated DNS evidence
files were added during full-source capture. Same-ID recovery completed without
replay. No source-content receipt was emitted for that run; a later receipt is
not substituted as its native byte witness.

Workspace strict Clippy `30099060530610683` exited 0 with no Rust diagnostics:
`clippy --locked --offline -j1 --workspace --all-targets
--features franken-speaker/harness -- -D warnings`.
All 1,368 captured inputs matched; terminal acknowledgment and all releases were
verified. Formatting passed. Python model/judge tests passed 85/85.
The full G03 judge against the executed unit log passed 46/46 cases and
162 named Rust tests, with 93 critical diagnostic events, zero drops and complete
evidence. That judge explicitly keeps the actual-controller gate separate.

## Same-server composition candidate

Reviewed patch `32ddd34769b7919ae37773297f8b2acd7841519c78ae44af18408dbd426e290c`
connects discovery and eventing through one existing server/session. It adds
three server tests and three actual-client tests. It was applied after the
results above. The later executions below qualify those additions separately;
the earlier 16-case result is not reported as execution of the new cases.

## Final composition verification

All commands used the pinned nightly, locked dependencies, one build slot and
strict remote execution. The final checks were:

```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1
# Existing bulk profile, unchanged limits; same command as above plus --offline.
RCH_REQUIRE_REMOTE=1 RCH_CONFIG_DIR="$BULK_PROFILE_DIR" \
  rch exec --source-content-receipt --worker trj -- \
  cargo +nightly-2026-08-31 test --locked --offline \
  --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 \
  -- --show-output --test-threads=1

RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- \
  cargo +nightly-2026-08-31 test --locked --offline -j1 \
  -p franken-speaker --features harness --lib fsonos_loopback \
  -- --show-output --test-threads=1

RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- \
  cargo +nightly-2026-08-31 clippy --locked --offline -j1 \
  --workspace --all-targets --features franken-speaker/harness -- -D warnings

RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- \
  cargo +nightly-2026-08-31 clippy --locked \
  --manifest-path tests/g03/fsonos-client/Cargo.toml --all-targets -j1 -- -D warnings
```

| Check | Build | Observed result | Matched captured inputs |
| --- | --- | --- | --- |
| Actual client, all four test binaries | `30099060530610719` | 19 passed, 0 failed, 0 ignored | 1,429/1,429 across four roots |
| Focused server tests | `30099060530610723` | 58 passed, 0 failed, 0 ignored; 360 filtered out | 1,372/1,372 |
| Workspace all-target Clippy | `30099060530610725` | Exit 0, no Rust diagnostics | 1,372/1,372 |
| Standalone client all-target Clippy | `30099060530610731` | Exit 0, no Rust diagnostics | 1,429/1,429 across four roots |

Every row has terminal acknowledgment, a terminated wrapper, absent owner and
all five source/tree/pair/staging/recovery releases verified. Input hashes were
matched before this documentation/evidence publication; the Rust and case-file
bytes did not change afterwards. [code-inputs.sha256](code-inputs.sha256) retains
the relevant relative-path code hashes from the worker receipt. These are host
executions, not guest or hardware receipts.

[client-composed.txt](client-composed.txt) and
[server-composed.txt](server-composed.txt) retain the observed names/verdicts.
The former includes the full same-server discovery -> description/topology ->
subscribe -> volume/mute -> ordered callbacks -> renew/unsubscribe journey, its
permitted local-link behavior, and the selected unauthenticated-tailnet refusal.
The server run also exercises malformed identities/limits and bounded cleanup.
It is a 58-case filter, not another full speaker-library execution.

The offline standalone-client Clippy attempt failed before checking any crate
because that worker lacked locked `cc v1.11.1`. The successful retry allowed
registry downloads while preserving the lockfile, features and `-D warnings`.
Earlier admission refusals and that cache failure remain retained.

Complete operational-log SHA-256 values:

- Client native: `6ac728d4271fa7dcfd3bb0dc6a38817798b11d4a4f7e6bbfa6a9fead6ecd31b3`.
- Server native: `57d810d3f017f3713d4de21e2abe22224f1f28537e9822323d429d960b63d48c`.
- Workspace Clippy: `047814458647358e9973bd94a8d0aaa9b05eb9e06a967ebc9c4aee2d566d309e`.
- Client Clippy: `e0ff98963b22acb2bc3e1f9c1aabf4ff1b085bfbdb48342316957d0c4bccfaf9`.

Formatting passed and the 85 Python model/judge tests passed after composition.
The publication recheck initially failed: two documentation assertions still
pinned the old unrun status, causing ten cascading judge-test failures. The
status table and those assertions now distinguish executed host integration
from the remaining grouping, native-tailnet and physical qualification. The
corrected suite passed **85/85**; the full judge recheck passed **46/46** cases
and **162/162** named Rust tests, with 93 critical events and zero drops. Its
conservative actual-client gate output is not a verdict on the separate
19-case integration execution above.

G03 remains open for its original acceptance and G01/G02 prerequisites.
These host results establish no physical playback, provider, native tailnet,
guest-kernel, thermal, acoustic or fleet-wide reliability qualification.
