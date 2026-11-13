# Finite capture and bounded credit recovery: host evidence

Code revision: `57e955fda59cc2dbe1ba56daa2b84730d516340b` (stream change
`c857f69deca914951bd86609f743f59ec1dfe237` plus control regression coverage).

This is confined host execution, not a Sonos firmware, radio or physical
playback qualification. The consumer is the repository supervisor and owner;
this capsule gates publication claims for the observed finite-capture/credit
faults. It retires as current evidence when these exact inputs are superseded;
the historical results, including failures, remain attributable here.

## Behavior

The opt-in source profile buffers transient credit-window stalls within existing
per-peer and aggregate bounds instead of skipping a peer while another advances.
Default carrier APIs retain their old policy. Sequence/cooldown/expiry/MTU,
authentication, epoch and send-time-credit guards remain enforced.

Trusted local fixture START declares the finite frame horizon separately from
END permission. The receiver records actual N04 decisions through that horizon,
including a partial tail, without post-end concealment or trimming a bad capture.
Controllers wait for actual final credit retirement before the deliberately
750 ms delayed END. Retirement is not proof of physical playout or receipt of
every earlier packet. Arbitrary premature trusted END/STOP can strand credit;
a production authenticated EOF/ACK protocol remains open.

Raw PCM and decision records are pre-reserved. Hex/JSON allocation and writes
occur once after finite decisions, outside their deadline path. The existing
4 MiB serialized limit is preserved. Logical storage bounds are not an exact
allocator-capacity, RSS or 32 MiB target-fit guarantee. Existing STOP fences
terminal private custody but retains bounded queues until owner drop.

Control production behavior is unchanged: a retained relative retry applies
once, while SOAP NewVolume reports current state after intervening commands.
Six additive durable-adapter tests cover expiry, restart, same-step ordering
and capacity eviction. The original contrary-to-cached-reply consumer test is
unchanged and passes; pipeline.rs equals the baseline bytes.

## Exact source identities

Baseline: `9634a5da426d843f8b1195bb0113ef90f29bc0c0`.
Native v11 freeze: `c9a30ca030a63d553e5defec08f0033840aa68ace18fcc333355ade9a25cca76`.
Inventory: `18ec9c2aaf01ca17bfc2d9a3e10857949532e8f7f538e0cd1465e9230c20be5a`, 1,659 files.
RCH compared all 1,657 transferred path/hash/size/executable tuples; only the
two tracker metadata files listed in receipt.json are excluded.

Final consumer v12 freeze: `aa1f5e9629a66fee5e910ee6b2a96c654f31fc09ef34cfb121a61e2bf8d20a81`.
Inventory: `66343516fcb7d00dd35932ab201b0ae7e6156feaca7732de00af11fd372534f7`.
All 1,659 Git blobs and executable modes at the code revision match v12.
Exactly 1,658 tuples match native v11. The sole delta is tests/g03/cases.json:
six already-passing test names appended to existing G03-I29, preserving its
statement, original names, model, validator and unclaimed-test threshold.
Old/new mapping hashes are in receipt.json. No Rust/build input reads this
mapping; the unchanged full G03 consumer was rerun separately. This is not a
claim that the whole v12 tree executed natively.

The client uses the previously qualified fsonos SDK pin
`8f422c333269073a256fe59c6f50e7e8429a1bf9`: only 59 metadata/proto/types
files were selected and checked against that pin's previous receipt. The SDK
runs compare four roots and all 1,716 unique source tuples. No live service or
canonical sibling source was changed.

## Commands and observed outcomes

Run from the immutable native v11 firmware root with the pinned sibling SDK
closure. The supervisor selected one eligible worker and retained full raw
stdout/stderr; machine-specific paths are kept outside the public repository.

```sh
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_ELIGIBLE_WORKER" -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_ELIGIBLE_WORKER" -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_ELIGIBLE_WORKER" -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +nightly-2026-08-31 clippy --locked --offline --manifest-path tests/g03/fsonos-client/Cargo.toml --all-targets -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_ELIGIBLE_WORKER" -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +nightly-2026-08-31 test --locked --offline --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 -- --show-output --test-threads=1
```

| Gate | Actual result |
| --- | --- |
| Workspace Clippy, native 341 | Exit 0, warnings denied |
| Full workspace, native 342 | 3,000 passed, 0 failed, 2 ignored, 0 filtered; 81 result footers |
| Required focused regressions | All 21 names occur once with ok |
| Finite host process scenarios | 6/6 within two Rust tests; not added to the Rust denominator |
| SDK Clippy, native 343 | Exit 0, warnings denied |
| Actual confined fsonos SDK, native 344 | 24 passed, 0 failed/ignored/filtered; 7 footers, all 24 required names once |
| Python runner units / N07 judge units | 34/34 and 44/44 on byte-identical Python inputs; earlier results reused |
| Formatting / Python compilation | rustfmt 1.99 on six changed Rust paths; py_compile on six Python paths |
| N07 raw-log consumer | 25/25 cases, 7 metadata checks, 0 metadata failures |
| Corrected full G03 consumer | 52/52 cases, 195/195 logged Rust cases; 105 critical events, 0 lost/dropped |

The SDK isolation canary deliberately detects an all-owners mutation and its
expected assertion text appears in a passing test. It is a negative control,
not a failed suite. SDK tests exercise actual confined localhost endpoints;
they do not specifically qualify authenticated relative retry on a deployed
native tailnet. Those six adapter cases are in-process unit tests.

The two ignored tests (exhaustive four-billion-pattern conversion and the
25.5-hour counter-wrap soak) were NOT RUN. Zero-test doc-target footers remain
in the 81-footer count and do not inflate the 3,000-test total.

Process checks compare exact complete independently referenced 48 kHz PCM:
Vorbis 24,000 frames/94 blocks/192-frame tail, MP3 72,000/282/64. Positive
peak error is 1 LSB and RMS about 0.0459 LSB, within unchanged peak<=4/RMS<=1.5
limits. Two/three-member groups and wrong-key isolation pass. No alignment,
rescaling, trimming, added lead time or relaxed deadline makes these results.

Both evidence consumers received the complete actual raw 342 log, never the
selected observed.txt excerpt. Their commands are:

```sh
scripts/e2e/n07 --judge "$RAW_342" --revision "freeze:$NATIVE_V11_FREEZE" --receipts "$NEW_N07_RECEIPTS"
scripts/e2e/g03 --tier full --judge "$RAW_342" --receipts "$NEW_G03_RECEIPTS"
```

Each passing remote execution has exact source checks, exit 0, terminal ACK,
absent wrapper and released staging/source/pair/tree/record custody. Independent
same-execution reviews checked those facts and the v11/v12 distinction. They
are reviews of these executions, not additional independent runtime samples.

## Retained failures and corrections

| Earlier native suffix | Actual pass/fail/ignored | Observation and disposition |
| --- | --- | --- |
| 331 | 2987/1/2 | Healthy single Vorbis capture gap; captures unavailable after retirement. Cause unknown. |
| 334 | 2987/1/2 | Group peer sent85 versus expected94, skipped_stalled9. Exact triggering guard unknown; the separately proven credit-window admission defect was fixed. |
| 336 | 2991/1/2 | New STOP test wrongly required immediate queue deletion. Corrected only that new test to existing terminal bounded-custody semantics. Dispatch also missed a newer HOLD; retained as an orchestration failure. |
| 338 | 2991/1/2 | Actual receiver2 block6 was muted_overdue by42,237,305ns despite94 sends each and0skips/drops. Pause cause unknown; separate source inspection found avoidable capture I/O in the decision loop. |
| 340 | 2999/1/2 | Proposed cached reply returned60 while existing consumer required current70. Proposal withdrawn; original consumer/model/assertions preserved. |

Each failed native run exited101 across81 footers. Applicable ACK/source/pair/
tree/record settlement was checked; missing failed-run staging ownership is
N/A, never invented as a true staging release. Original raw hashes and source
receipt roots are retained in receipt.json. The first full G03 consumer was
51/52 with195RustOK because six tests lacked explicit invariant bindings;
only the mapping was repaired, and the old failure remains recorded.

Full N07, N02 and G03 original acceptance stays open. These results do not
qualify target ISA/ABI execution of this patch, retained drivers, CPU/RAM or
32 MiB fit, distributed clocks/acoustics, physical Wi-Fi, Spotify, AirPlay,
Alexa, or native Tailscale. No live device was contacted.
