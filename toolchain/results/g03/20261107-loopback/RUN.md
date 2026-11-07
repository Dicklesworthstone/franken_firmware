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

## Discovery transport and actual-client compilation follow-up

Base `6458ff2`, with discovery patch `11aa3c88315b429b96163181229d8452cdab4895adec754466eb80b6a908d314`,
UDP write-timeout correction `3866cb84f0bbbf451f43982113d283aba2f2cdbec3a4dd9709a7ec46ba1556da`,
and source-derived GET-405 test correction `8e4e92ac943b12066141d1fe25f10704cba31cb64b32f7b5c881a8eabceb0340`.
The last correction preserves the endpoint's behavior: unknown GET methods
receive 405; an unauthenticated control POST remains 401. No core authorization
rule changed. The only description-vector change adds the escaped `roomName`
which the real client's parser reads.

All compiler commands below used strict remote execution, one build slot,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0`; no admission floor or fallback changed.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- cargo +nightly-2026-08-31 test --locked --offline -j1 --no-fail-fast -p franken-stream -p franken-speaker -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked -j1 -p franken-control -p franken-stream -p franken-speaker --features franken-speaker/harness --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked --manifest-path tests/g03/fsonos-client/Cargo.toml --tests -j1 -- -D warnings
python3 -B -m unittest discover -s tests/g03 -p 'test_*.py'
```

Native build `30099060530610602`: **633 passed / 0 failed / 1 existing ignored
D03 soak**, across 14 result groups. This includes **20 HTTP and 11 UDP shim
tests**, **42 carrier unit tests** and **15 link unit tests**. Both strict
Clippy commands passed with no Rust diagnostics (builds `30099060530610601`
and `30099060530610614`). G03 Python passed **85/85**; touched Rust formatting
and Python compilation passed. `native-discovery.txt` retains selected original
verdicts and observations, without machine paths. The N07 judge also reproduces
**25/25 cases, zero metadata failures** from that excerpt.

The first two captures matched **1,361/1,361** files before this status/evidence
update. The actual-client capture matched **1,418/1,418** across four roots:
FrankenFirmware 1,361, the sibling workspace manifest inputs 4, `fsonos-proto`
49 and `fsonos-types` 4. The sibling revision was
`71da04327c596db61858f79ad4851bd6c143767d`. All three jobs were finished,
exit zero acknowledged, wrapper dead, owner absent, all five release flags true.

| Capture | Complete raw-log SHA-256 | Primary source root |
|---|---|---|
| Native | `cbb31fdddda4a7567349bbddfb856846c7b28ebea8312828eebd3c0371f96ab6` | `7adb8cf4024d67d14cd4fbf18532d9a4d5717af579426aabc9a27b82fe2d4723` |
| Workspace Clippy | `89698baea1f5c22922bbf7666935e5edbc90b450be69c9a1faad1ae7004fcfb6` | `fe37b02a600ee6b4970c6fd90b8581b8074789e3c98d6c69d4a6967ef53ba2f4` |
| Actual-client Clippy | `61e8757f934b46ff6c5e7deec6cef75bed3c6d8a70ca318f2752b9b4a7bb95cf` | `ec07eaafaba4cb0c18d58af8349906d87257b0ced9e4806721f2795182ae6667` |

The standalone lockfile was generated offline as metadata, without compiling
locally. It pins 241 packages, including the real client's published Asupersync
0.5.0 dependency; it does not substitute the mutable local Asupersync 0.6.2.
Lockfile SHA-256: `c1ccda353f0519580e1e32587a20082f67982e4ac50607f5e5d1fa113307f93a`.

**Actual-client execution remains NOT RUN.** Its first strict-Clippy attempt on
TS1 was refused for active-project exclusion before Cargo. A later native test
attempt was refused for disk headroom (26 GiB available versus 40 GiB required),
also before Cargo. Eleven compiled tests are not eleven passing tests. The
new adapter remains loopback-only and harness-only; GENA delivery, real-client
group/reconnect qualification, radio behavior and board playback remain open.
