# Own local buttons in the protected renderer

Code ba0b6fce71132b0179b158e738f9d84773725c6c, based on published 523bda9aab8a6bbf1323703773a59e8109521348.
All 1,630 committed source files, lengths and executable bits match the native
inventory. Seven changed paths are hashed in [receipt.json](receipt.json).

SettledRender now owns the existing ButtonAdapter alongside the MemberVolume
that controls its actual protected PCM. Button map and bounds are explicit,
validated inputs with no physical default. Configuration is one-time before
the first successful join proposal; it stays closed through abort and stop.
The initial unknown mute state permits reduce-only mute-on until an observed
release. Fault/reset, repeat and stuck-button state cannot be reset by replacing
the adapter. Read-only statistics and bounded stuck polling remain available.

Accepted local mute/trim changes reconcile that same owned volume. Results
separate local intent, optional render-policy application and actual retained
HAL stop/flush acknowledgment. Remote member mute contributes to the reported
effective reason. Ignored/reset events do not tick rendering, even when an
active renderer's group clock is unavailable. A mute press records local intent
before a failed clock reconciliation; failure does not stand in for a mute ACK.

Six new integration cases drive the production modeled-HAL debounce channel,
authenticated localhost audio and retained buffers: initial/late local mute,
fault/release and stuck diagnostics, immutable pre-join configuration, independently
different protected trim PCM, actual controller member-mute revisions 1/2, and
clock-failure actions versus ignored events. ACK and timeout controls retain
and inspect the exact nonzero program token. These are host models, not a
physical event ABI or an installed speaker process.

The existing G02 runner had a real regression: its documented/pinned 128 cases
lagged the actual 131, and the role/owned-button children were not required.
It now requires the existing 76 Rust cases plus 15 protected-role and 6 owned-button
cases. Together with 4 meta checks and 51 unchanged vectors, the full plan is 152.
Missing source cannot silently shrink that denominator. New judge controls pair
a consistent-log positive with missing-result, FAILED-result and missing-child
rejections. No vector, sample expectation, tolerance, seed or assertion was
regenerated or weakened.

| Gate | Execution | Actual result |
| --- | --- | --- |
| Complete speaker package | Native 30107136981729293 | 644 passed / 0 failed / 1 existing ignored;10 footers |
| Workspace all-target Clippy | Native 30107136981729294 | Exit 0, warnings denied |
| Python judge controls | Local source/judge tests | 44 passed / 0 failed |
| Actual G02 native-log judge | Final speaker 293 + unchanged DSP 289 | 152 passed / 0 failed / 0 blocked |

The one ignored D03 campaign is 25.5 virtual hours and did not run. Rustfmt 1.99
edition 2024 passed all four changed Rust inputs; py_compile passed both changed
Python scripts. The two native receipts each match all 1,628 transferred source
path/hash/length/exec tuples; two .beads metadata files were excluded. Terminal
ACK, absent wrapper processes and staging/source/pair/tree retirement were
checked. Independent review inspects these same executions, not a second run.

Exact native payloads, dispatched using ordinary strict-remote RCH admission:

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline -p franken-speaker -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
python3 -B tests/g02/test_g02.py
scripts/e2e/g02 --tier full --judge "$DSP_WORKSPACE_289_LOG" "$SPEAKER_293_LOG" --receipts "$PRIVATE_RESULT_DIR"
~~~

The G02 judge reused only the earlier 289 DSP observations after comparing 39
unchanged DSP/dependency/root-manifest/lock/toolchain/vector tuples. Exact input
log hashes and all 152 named case outcomes are in the receipt. There was no
final full-workspace runtime rerun; overlapping totals are not added.

Earlier failures remain failures: baseline Python 40/41 (stale 128 versus 131),
v1 Python 43/44 and v2 Python 43/44 (original acceptance-map documentation checks).
The checks remained intact; v3 corrects two status labels. Independent source
review also rejected a test using a local-panel identity that bypassed remote
controller revision checks; its successor supplies the enrolled Controller and
observed revisions 1 and 2. No native job was run on v1 or v2. Selected actual
output and clearly marked failure annotations are in [observed.txt](observed.txt).

This record serves supervisor/operator acceptance of this exact host-library
source. Changed source/profile ends its applicability. It does not qualify
physical audio/buttons, deployed firmware, provider/native-tailnet behavior,
legacy-kernel/32MiB budgets, persisted local volume, dynamic role changes,
current-authority reboot recovery, or full original G02/N02 acceptance. Those
features and acceptance obligations remain required and open.
