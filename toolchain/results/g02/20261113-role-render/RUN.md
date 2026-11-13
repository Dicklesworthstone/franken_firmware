# Initial member roles in the protected renderer

Code: c770a3f5f1d0d513c01d0c11b5232aa96a9f4b52, based on
47fdbb209660c43815bc177bf5462584d3efea7d. All 1,619 committed source files,
lengths and executable bits match the final qualified inventory. The eight
changed files are individually hashed in [receipt.json](receipt.json).

## Behavior and boundaries

The owned control/membership renderer admits initial Stereo, Left, Right and
Sub roles. It binds the existing RolePlan before join readiness and maps the
resampled fixed block before calibrated board protection. A refused proposal
does not change routing, and a running or busy renderer cannot rebind its role.
The new mapping does not reset protection or resampler history.

The HAL retains its admitted board-profile digest. Installed and pending DSP
profiles must match that identity; same-ID profiles with different valid
digests are refused. A public whole-DSP replacement is checked before start or
any tick that can render or submit. Uncalibrated construction remains muted.
Digest equality proves profile binding, not calibration accuracy or continuity
of protection history after a trusted caller replaces an entire same-profile
DSP. The existing planted history-reset test remains unchanged.

Cancellation-only draining continues to poll real modeled HAL acknowledgements
or its bounded timeout even when the DSP is invalid. It cannot render new source
or submit busy PCM. Active and graceful-ramp paths still enforce identity. ACK
releases the actual retained token; timeout retains readable custody.

The tests use actual library owners, localhost transport, synthetic board
calibration and a retained FakeBackend. They are host prototype evidence, not
installed firmware, physical sound or distributed synchronization.

## Actual execution

All jobs used strict remote RCH, Rust 1.99, locked/offline dependencies, one
build job and one runtime test thread. Environment: CARGO_INCREMENTAL=0,
CARGO_PROFILE_DEV_DEBUG=0, RUSTFLAGS=-D warnings -C debuginfo=0. Pinned
Rustfmt edition 2024 checks passed all final changed files. Exact user payloads,
native hashes and selected observed output are retained in
[receipt.json](receipt.json) and [observed.txt](observed.txt).

| Source and gate | Native job | Actual result |
| --- | --- | --- |
| Earlier guard with successor cleanup tests | 30107136981729283 | 1 passed / 1 failed, exit 101 |
| Corrected final2 full workspace | 30107136981729284 | 2,905 passed / 0 failed / 2 existing ignored |
| Final2 strict all-target Clippy | 30107136981729285 | Exit 101, two test-code lints |
| Final3 complete affected speaker package | 30107136981729286 | 631 passed / 0 failed / 1 existing ignored |
| Final3 strict workspace all-target Clippy | 30107136981729287 | Exit 0, warnings denied |

The full workspace belongs to final2 bytes. Final3 changes only two equivalent
test forms: a uniform assignment loop becomes slice.fill, and the same fixture
tuple receives a type alias. Every assertion and expected value is retained;
all production and other test files are identical. The affected speaker package
and strict all-target Clippy were rerun on final3. Do not add overlapping totals.

All 17 new named cases passed in the full workspace. Final3 reran the 15 owned
by the speaker package; the other two are unchanged DSP tests. Ignored campaigns
are the existing exhaustive 2^32 float conversion and the D03 soak spanning
25.5 virtual hours. Neither ran; no new test was ignored.

The predeclared regression actually compiled and ran both selected tests. Its
cancel case failed with ProtectionFault instead of DrainTimedOut, while the
graceful-drain refusal passed. The corrected cancel test exercises 16 combinations
of prepared/active, wrong-profile/uncalibrated, replacement before/during cancel
and ACK/noACK. Invalid DSP state remains installed through cleanup. Separate
controls retain an actual nonzero program submission, its exact slot and
generation, and its readability until acknowledgement.

The PCM oracle independently maps asymmetric stereo input but uses the existing
D02 filter implementation as its protection reference. Sub mid mapping is
observationally equivalent to stereo entering D02's Mid route; its sample output
alone cannot prove RolePlan invocation. A direct stored-plan test complements it.
This integration test does not independently verify crossover correctness.

Every native transferred path/hash/length/executable tuple matched its bound
inventory: 1,617 per job, with two .beads metadata files excluded. Terminal ACK,
dead wrappers and source/pair/tree retirement were checked. Successful jobs also
record staging release. Failed-job staging fields remain null/unrecorded; no
release is asserted for them. Independent review inspected the same native logs
and source bytes; it is not a second execution.

## Remaining qualification

Existing-media/reboot recovery, persisted local intent, dynamic role switching
and MonoSum, deployment-binary ownership wiring, native service/tailnet adapters,
real driver/calibration, legacy-kernel and 32 MiB resource/deadline measurements,
and physical synchronization remain open. These component results close no full
original bead. This record is consumed by the operator and supervisor for this
exact source qualification; changed source/profile ends its applicability while
historical failures remain retained.
