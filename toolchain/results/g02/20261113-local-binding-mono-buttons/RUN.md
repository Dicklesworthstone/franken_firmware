# Local binding, initial mono routing and button recovery

Code 9a62697f2f80b13ff6f9942d11f139cf15f749ae, based on c99aa104c555ec14cc9c9317f517314cfb9c2d2a.
The three code groups are 194e674c77a244dca7b3a121b10c4597f5feac71 (binding),
e534fd238d7911bf8320a55de7099039524854bb (MonoSum) and 9a62697f2f80b13ff6f9942d11f139cf15f749ae (buttons).
All 1,622 committed blobs, lengths and executable bits match the exact final
qualified inventory; the eight changed files are hashed in [receipt.json](receipt.json).

## Behavior

The durable control owner can store one versioned desired group/issuer/incarnation
and local member/profile/role binding, within existing journal limits. It commits
and syncs before success, refuses overwrite and nonfresh backfill, and distinguishes
missing, malformed, full and poisoned state. A 32-byte PeerId is a type/encoding
bound; durable credentials reserve the cp: prefix, leaving 29 issuer bytes. The
corresponding real maximum record is 243 bytes, not the standalone 246-byte encoding.
This is configuration intent only; it authenticates no current authority or history.
The separate private PendingMember consumer is absent from this qualified revision.

Initial MonoSum now maps half of each input into both non-sub board inputs, after
resampling and before calibrated protection. Half-weighting before addition keeps
same-sign finite f32 extremes finite. Pure Sub, Bridge and mixed/invalid layouts
remain refused. Existing Sub mapping, profile custody and role immutability remain.
The PCM oracle independently maps channels but shares the production D02 filters.
It does not independently qualify crossover correctness or physical audio.

A fault/reset can turn a still-held mute into a new debounced Down. The adapter now
retains an uncertain mute state until an observed Up. During uncertainty a Down
may mute an unmuted room, but cannot unmute current local intent, including mute
set during the outage. Repeated faults/Unknown retain the latch and repeat history;
unrelated known-up volume controls remain usable. An unseen outage release may
require a further observed release before unmuting. Tests use the actual modeled
HAL channel fault/reset/debounce, not a decoded physical button driver.

## Actual execution

| Source/gate | Native job | Result |
| --- | --- | --- |
| v2 workspace | 30107136981729288 | Compile exit101; zero tests executed; all12 new cases NOT RUN |
| Final v3 workspace | 30107136981729289 | 2,917 passed /0 failed /2 existing ignored;81 footers |
| Final v3 workspace all-target Clippy | 30107136981729290 | Exit0, warnings denied |

All12 named new cases passed individually. The two ignored campaigns remain the
existing exhaustive 2^32 float conversion and D03 soak spanning25.5 virtual hours;
neither ran. No new ignore, seed, tolerance, memory allowance or coverage floor
was introduced or weakened. The former unsupported-MonoSum assertion was replaced
by permitted PCM plus layout refusals. The unsafe post-fault-unmute expectation
was corrected with explicit release/fresh-press positives.

The first button draft was rejected in source review for the late-mute
interleaving and was never executed. Actual v2 failed on a second obsolete oracle
wildcard after all ChannelRole variants became explicit. V3 removes exactly that
one line; the other seven files, formulas and assertions are unchanged. The failure
is retained as a real unexpected compile failure, not relabeled an expected RED.

Strict remote RCH used pinned Rust1.99.0, locked/offline dependencies, one build job
and one test thread. The exact environment/Cargo payloads are in receipt.json.
Reproduction payloads, after ordinary RCH admission and native routing:

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline --workspace -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
~~~

Pinned Rustfmt edition2024 checks passed all eight exact inputs. All1,620
transferred entries matched the bound inventory; two .beads metadata files were
excluded. Terminal ACK, dead wrappers and source/pair/tree retirement were checked.
Successful jobs record staging release; failed-job staging remains null/unrecorded.
[observed.txt](observed.txt) contains selected native output with ANSI removed and
private routing paths omitted; full raw logs remain private. Reviews inspected
these same executions and are not independent second executions.

## Remaining qualification

This is default-feature native-host library/localhost/synthetic-HAL evidence.
It is not QEMU or deployed firmware, current-authority/reboot recovery, persisted
local volume intent, dynamic roles, physical ABI/calibration, native services or
tailnet, legacy-kernel/32MiB resource qualification or real synchronization. No full
original G02/N02 bead is closed. This record serves supervisor/operator review of
this exact source; changed source/profile ends its applicability.
