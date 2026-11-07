# Durable control and HAL-fence component qualification

Base `053dfcd`; two component commits were qualified together as one frozen 24-path snapshot.
`qualification.json` records the actual captured and published input hashes. Five strict remote
captures each matched all **1,312/1,312** local files at review, with terminal ACK, absent
wrapper/owner and all five release flags. Publication changed only G03 Markdown and Rust
module documentation to describe the already implemented local-silence exception. That
delta is included; fresh all-target Clippy and 85 G03 Python tests passed afterward.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker hz2 -- cargo +nightly-2026-08-31 test --locked --no-fail-fast -j1 -p franken-control -p franken-speaker -p franken-alloc-probe -p franken-hal --features franken-speaker/harness -- --show-output --test-threads=1
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked --offline -j1 -p franken-control -p franken-speaker -p franken-alloc-probe -p franken-hal --features franken-speaker/harness --all-targets -- -D warnings
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-control -p franken-speaker -p franken-hal --features franken-speaker/harness --lib --target powerpc-unknown-linux-musl -Z build-std=std,panic_abort
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-control -p franken-speaker -p franken-hal --features franken-speaker/harness --lib --target mips-unknown-linux-musl -Z build-std=std,panic_abort
```

Native: **1,107 passed, zero failed, one ignored**, across 20 result groups. The ignored test
is the D03 25.5 virtual-hour soak; it was not run. Control library: 562 passed; HAL library:
151 passed; speaker library: 326 passed, including 16 output-fence tests. Strict all-target
Clippy and both BE library checks passed. BE checks are compilation, not guest execution.
Public logs retain compiler results, test verdicts and heap/transport observations; private
RCH manifests and machine paths are omitted. Raw and published hashes are distinct.

N02 now writes bounded per-identity relative-command floors before effects, stages mutations,
withholds unsafe rolled-back settlements, and latches storage failure. The first accepted
local stop/mute-on still applies to the live session and receives its real outcome. Prior
pending rejections retain the live revision rather than a speculative one. Explicit durable,
latched and development steppers prevent a request from silently choosing volatile execution.
Prototype boot restores mark and floors together; the current owner still uses RAM.

The actual durable heap run used 16 identities, 640 steps, a 226-byte floors record, 1,247
journal frames and 79 compactions. Peak step allocation was **59,681 <= 62,640 bytes** against
the original bound; datagram peak was **1,812 <= 12,528**, and retained high was
**58,953 <= 152,544**. This is requested heap on x86_64, with only 2,959 bytes of step margin.
It excludes stack, allocator overhead, kernel buffers and boot allocations. Target heap/RSS,
larger sessions and physical flash wear remain unmeasured; a future overrun is a finding.

`history.json` retains initial compiler findings, a missing-worker-cache attempt, a slot
admission refusal and the causal native failure. The old forgotten-restore test incorrectly
expected the exempt local mute to be withheld. Its unsafe-command assertion remains one
withheld result, with added no-effect and proper-restore positives; a separate same-fault
test checks applied mute and withheld unsafe volume. Production behavior was unchanged by
that correction. Caught planted allocator panics are passing rejection canaries.

Independent nonauthor review: GrayMeadow AM11185. Full N02/S03 acceptance remains open:
there is no device owner, file-backed control process restart or physical driver proof in
this snapshot. The later private controller-pair test `cf04a2f6` is not included or qualified.

The existing `scripts/e2e/g03 --judge toolchain/results/n02/20261107-control-hal/native.log`
also passed: 46 planned cases, 46 passed, zero failed/blocked, 156 required Rust tests all
reported `ok`; 93 critical diagnostic events, zero dropped or lost. This qualifies only its
offline/model and logged Rust-test side. The judge explicitly leaves the actual `fsonos`
client gate open and does not exercise listeners, real subscription expiry or network time.
