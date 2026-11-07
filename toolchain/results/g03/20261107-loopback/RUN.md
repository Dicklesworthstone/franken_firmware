# G03 loopback integration: compile evidence, native qualification pending

Source: `4a0b8b4` (the commit contains the checked source). The exact transferred
working-tree snapshot was captured before that commit; this is not a claim that
later repository contents have the same digest. Scope is the harness-only server
and standalone real-client package. No device or provider was contacted.

## Executed formatting and Python checks

```sh
rustfmt +nightly-2026-08-31 --check --edition 2024 \
  crates/franken-speaker/src/lib.rs \
  tests/g03/fsonos-client/src/lib.rs \
  tests/g03/fsonos-client/tests/real_client.rs
python3 -m unittest discover -s tests/g03 -p 'test_*.py'
```

Observed: formatting exit 0; Python exit 0:

```text
Ran 85 tests in 11.415s
OK
```

The Python models/judges are not the Rust server or real-client execution.
The retained Python log SHA-256 is
`756a7862641870657b2641ab28b0771ab74076c636de86d8c8d503f4926f7960`.

## Executed strict remote compile check

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=0 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker ovh-b -- \
  cargo +nightly-2026-08-31 clippy --locked -j1 -p franken-speaker \
  --features harness --all-targets -- -D warnings
```

Observed output excerpts (not the complete private operational log):

```text
Finished `dev` profile [unoptimized] target(s) in 35.09s
Remote command finished: exit=0 in 37943ms
[RCH] remote ovh-b (71.0s)
```

Zero Rust errors and warnings. Receipt schema `rch.source_content_receipt.v1`:

- Build: `30099060530610522`; command exit 0.
- Command SHA-256: `c99eb36e306efe39087814557b7ae8a3c18eafa206cb7cd0509957cba3e03011`.
- Primary root: 1,354 files, 44,908,612 bytes.
- Content root: `7206553fa5d9933437ab5970c335b39805cab89780da14e753ddbe27fbc268f5`.
- All 1,354 captured local files matched their receipt hashes before commit.
- Terminal acknowledgment, wrapper dead, owner absent and source/tree/pair/
  staging/recovery retirement were checked. Earlier build `30099060530610507`
  also passed the combined stream/speaker/alloc-probe strict check.
- Complete operational log SHA-256:
  `d5f4fbd1263384040e2cc7e5e8476fe2c496471915b35bbbe3e0ee88bdc95480`.

This compiles the server and its test targets. It does not compile the standalone
real-client package, which has its own workspace and sibling path dependency.

## Native attempts: NOT RUN, not passing tests

The combined native stream/speaker/alloc-probe harness batch encountered two
prestart selection refusals, two pre-Cargo disk-reservation refusals and one
bounded queue timeout. No assertion ran in those attempts. The original failed
attempts remain retained; no floor, growth budget, fallback or timeout changed.

The actual-client command correctly planned both repository roots:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +nightly-2026-08-31 test \
  --manifest-path tests/g03/fsonos-client/Cargo.toml \
  --test real_client -j1 -- --nocapture --test-threads=1
```

It was refused before Cargo, exit 120, by live competing disk reservations.
No client test compiled or ran. Its retained operational log SHA-256 is
`f0c20730ab71612f0083c9757e4c38dceab23eb4f2f7ccb643b29253c1c2bae2`.
The package needs its first generated lockfile retained, then a locked run.

The thirteen server cases and five client cases are source, not executed test
credit. G03 stays open for actual-client execution, discovery, subscriptions,
grouping and reconnect qualification. Clippy, Python models and source review
cannot substitute for that behavior or for board playback.

## Later native execution: server passed, combined batch failed

At 16:19 UTC, a repeat of the previously executed complete consumer command
was admitted on `hz2`, without modifying admission or compiler-profile settings:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=0 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker hz2 -- \
  cargo +nightly-2026-08-31 test --locked --no-fail-fast -j1 \
  -p franken-control -p franken-speaker -p franken-alloc-probe \
  --features franken-speaker/harness -- --show-output --test-threads=1
```

Observed: **1,012 passed, 4 failed, 1 ignored across 20 test groups**, exit 101.
The ignored case is the unrun D03 soak. All thirteen
`fsonos_loopback::tests` passed, including real socket volume/mute, endpoint
faults, bounded parsing, stalled clients and listener shutdown. The real N06
speaker-consumer cases passed 12/12; N07 speaker-consumer cases passed 22/22.
This command does not run the `franken-stream` unit-test binary.

The four failures are in `n07_carrier_heap` (one other case passed): admission
and report coverage omitted the separately allocated group registry. The first
red is retained. The repair must account for its actual owner/capacity and keep
the exact admission check and planted growth/underreporting negatives; it may
not add a fitted tolerance. The combined batch is **not qualified**.

Build `30099060530610537`; exact content root
`fd8414231c8c0f931f5e40d1f88454c146b92ca1b073a85a6f9c11c3ed6bcd16`.
All 1,355 captured inputs matched before this evidence update. The wrapper is
finished, exit 101 acknowledged, owner absent, source/tree/pair retired;
staging-release is null on this failed execution, not claimed true.

The separate five-case actual-client package remains UNRUN. A second attempt
on `hz2` also received a pre-Cargo disk-reservation refusal, exit 120.
