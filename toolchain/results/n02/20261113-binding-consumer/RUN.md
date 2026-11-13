# Connect durable local intent to the fresh renderer

Code be96e2c83fdcff79f322b2dea8b76e3b1765de5a, based on published 2bb6a30fbfb2934de8781bab1371e2d2dc20400f.
All 1,626 committed files, lengths and executable bits match the qualified
inventory; the three changed paths are hashed in [receipt.json](receipt.json).

The fresh constructor now consumes the existing journal binding: when present,
its group, configured issuer, local member, profile and role must match the group
bundle and PendingMember. Unreadable or mismatching intent refuses admission
before clock checks, lease installation, software-silent arm or proposals. An
absent binding retains the original explicit fresh-provisioning behavior.

The matching-binding and absent-binding controls enroll the coordinator in the
real modeled fleet/journal, perform proposal/ACK/commit/activation, deliver
authenticated localhost PCM and require actual nonzero protected submissions
and pulled source frames, then acknowledged stop. Separate stored member/profile/
role mismatches refuse without Start, unmute or additional submission. The exact
primed retained token remains readable after by-value refusal/drop. No flush ACK
or physical mute is inferred from dropping that owner.

Negative pull counters are measured at entry, because no source handle survives
the consuming error. Source inspection establishes that the new refusal branch
precedes all start/tick/source operations; this is not a measured post-error
source counter. Configuration equality is not authenticated current authority,
restored live membership/history, old-output cessation or reboot recovery.

| Gate | Native job | Actual result |
| --- | --- | --- |
| Complete affected speaker package | 30107136981729291 | 638 passed /0 failed /1 existing ignored;10 footers |
| Workspace all-target Clippy | 30107136981729292 | Exit0, warnings denied |

Both new named cases passed. The one ignored D03 campaign remains a25.5 virtual
hour soak and did not run. No ignore, assertion, tolerance, seed or budget was
weakened. Only Speaker source changes; predecessor full-workspace2917/0/2 is
unchanged-crate evidence, not a final full-workspace rerun. Totals overlap.
Pinned Rustfmt edition2024 checks passed all three exact inputs.

Exact Cargo/environment payloads, dispatched through strict-remote RCH with
native source-content receipts and ordinary admission:

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline -p franken-speaker -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
~~~

Each native receipt matches all1,624 transferred paths/hash/length/exec tuples;
two .beads metadata paths were excluded. Terminal ACK, absent wrappers and recorded
staging/source/pair/tree retirement were checked. Selected actual output appears
in [observed.txt](observed.txt); full raw logs remain private. Independent review
uses these same executions, not a second run.

This is default-feature native host library/localhost/synthetic retained-HAL
evidence, not deployed firmware, physical button ABI/audio, providers/native
tailnet, legacy-kernel/32MiB or full original N02/G02 acceptance. The separate
private button-owner integration is not in this source and does not inherit
these results. This record serves supervisor/operator review of this exact
source; changed source/profile ends its applicability.
