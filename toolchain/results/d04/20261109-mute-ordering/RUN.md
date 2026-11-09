# D04 mute ordering: native RED/GREEN execution

Date: 2026-11-09 UTC. Code published in `d87a89b0d54e860e8398862777728cb89b754129`.
The centrally tested workspace was an archive of
`251e5b74f4cb0ccbeb590d8599a77408092a3072` with exactly two changed paths:
`crates/franken-speaker/src/render.rs` and `tests/d04/cases.json`.
The published versions of both paths are byte-identical to GREEN.

This is native Linux test execution with the existing FakeHAL. It establishes
neither big-endian guest execution nor physical mute, audio deadlines, retained
driver compatibility, provider operation, or production playback. D04 stays open.

## Observed results

| Execution | Result | Cargo/RCH exit | Output |
|---|---|---|---|
| RED: old implementation plus new tests | 37 passed, 2 failed, 0 ignored; 383 filtered | 101, expected | [red-render.txt](red-render.txt) |
| GREEN: strict package Clippy, all targets | No warning/error diagnostics | 0 | [green-clippy.txt](green-clippy.txt) |
| GREEN: render tests | 39 passed, 0 failed, 0 ignored; 383 filtered | 0 | [green-render.txt](green-render.txt) |
| GREEN: full default-feature speaker package | 450 passed, 0 failed, 1 ignored | 0 | [green-speaker.txt](green-speaker.txt) |
| Local existing D04 full-tier gate | 51 passed, 0 failed, 4 blocked | 3, NOT QUALIFIED | [d04-full.txt](d04-full.txt) |

The full package ran 422 library cases and integration groups of 16, 6 and 6
passing cases, plus one ignored case. The 25.5-hour virtual counter-wrap soak
was already ignored at the base revision; this change did not add an ignore.
The `harness` feature was **not** selected: its N02 integration target built and
ran an empty zero-test executable, with the process integration test body
excluded by `cfg`. No N02 process integration was exercised. Zero-test targets
add no evidence.
Package Clippy is not the D04 gate's requested workspace-wide Clippy, and these
runs do not supply its two device builds or external qualification.

Before execution, the expected RED failures were named:

- `render::tests::a_later_mute_supersedes_unmutes_even_beyond_the_first_control_batch`
- `render::tests::a_repeated_mute_supersedes_an_intervening_unmute_without_widening_the_queue`

The permitted-positive case
`render::tests::an_unmute_after_the_latest_mute_is_preserved` passes on both
implementations. In RED, the first failing test panics at backlog 0; it does
not reach its backlog 4 and 15 branches. GREEN executes all three backlogs,
preserves queued gain updates and a fresh unmute, and retains the 16-command
queue limit and four-command render batch. `D04_CONTROL_ORDER` lines in the
transcripts record these scenarios. The fix removes only older queued Unmute
requests when a newer Mute is accepted under the enqueue mutex. It retains the
existing snapshot boundary: a Mute arriving after a render snapshot is serviced
at the next control service point.

The registry change maps the three new tests and a previously unmapped existing
lifecycle test. The original base D04 gate was 50 passed / 1 failed / 4 blocked,
exit 1; its failure was the orphan mapping. The final gate is 51 / 0 / 4, exit 3.
An initial wrong `unittest discover` invocation collected zero tests and exited
5; it is NOT RUN evidence, not a pass.

## Commands and source identity

The inner commands are recorded verbatim per execution in
[execution-record.json](execution-record.json). Each ran through
`RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt`, with
`RCH_BUILD_SLOTS=2`, `RCH_TEST_SLOTS=2`, `RCH_TEST_TIMEOUT_SEC=2400`,
`RCH_BUILD_TIMEOUT_SEC=2400`, and an explicit canonical project root pointing at
its exported workspace. The submitted command requested
`env CARGO_TARGET_DIR=/tmp/rch_target_ffw_d04m CARGO_INCREMENTAL=0`.
The observed artifact directory was RCH's per-worker pool directory (shown as
`<TARGET_DIR>`), and the logs do not independently establish the incremental
setting. The request is not a claim that RCH preserved that target directory.
All four executions ran on their first attempt. The original helper advertised
six attempts, but none of these four retried. The helper's automatic refusal
requeue was subsequently disabled; replay should not use that helper.

Each native job was independently observed finished and acknowledged, with a
dead wrapper, absent owner, and released source/tree/pair custody. GREEN staging
release was true. RED did not publish a positive artifact and had no staging
release field. The public record is a derived snapshot of these observations,
**not a signed RCH attestation**. It includes the original private log digests,
source-content receipt roots, exact two source hashes, build IDs and terminal
fields. Operational transport records and full private manifests are omitted;
The public transcripts retain the Cargo execution portion, replacing only its
transient source and target directory prefixes with `<BUILD_ROOT>` and
`<TARGET_DIR>`. They omit the helper's attempt header/footer and the RCH receipt,
worker and duration lines; those operational records remain in the private raw
logs whose digests are recorded.

RED is reproducible from the base plus the frozen
[tests-only.patch](tests-only.patch), SHA-256
`fb58a0200272dc0e20e10b957d6026e65d254206ff8b5f3832738805f2dee8a6`.
GREEN is reproducible from the same base plus the two-path diff to `d87a89b`.
The frozen patch retains its exact bytes, including the one-space blank context
line required by unified-diff syntax. `git diff --check` on this evidence patch
flags that line as trailing whitespace; it is not altered or suppressed. The
other seven files pass that check, and the patch was applied to a fresh base
export to verify the resulting source hashes.
For example, from the repository root, prepare fresh exports without modifying
the checkout:

```bash
set -euo pipefail
source_repo=$PWD
replay_dir=$(mktemp -d)
mkdir "$replay_dir/red" "$replay_dir/green"
git archive 251e5b74f4cb0ccbeb590d8599a77408092a3072 | tar -x -C "$replay_dir/red"
git archive 251e5b74f4cb0ccbeb590d8599a77408092a3072 | tar -x -C "$replay_dir/green"
git -C "$replay_dir/red" apply "$source_repo/toolchain/results/d04/20261109-mute-ordering/tests-only.patch"
git diff 251e5b74f4cb0ccbeb590d8599a77408092a3072 d87a89b0d54e860e8398862777728cb89b754129 -- crates/franken-speaker/src/render.rs tests/d04/cases.json > "$replay_dir/fixed.patch"
git -C "$replay_dir/green" apply "$replay_dir/fixed.patch"
```

Run the recorded Cargo commands from the corresponding export through strict
RCH, retaining their actual exits; RED's 101 is the expected negative result.
These preparation commands describe a replay, not an additional execution.
The local non-compiling gate command was `scripts/e2e/d04 --tier full`.

## Corrections and remaining verification

The central preflight log incorrectly printed local D04 exits as 0 because it
expanded `$(basename ...)` before reading `$?`. Direct local runs established
the actual base exit 1 and final exit 3 above. The original log was retained and
the supervisor acknowledged the correction; new scripts save status immediately
before formatting it. The four Cargo execution exits in this record come from
their source-content receipts and native terminal records, not that broken
preflight printout.

Two independent source reviews found no defect. They are source reviews, not
independent repetitions of the runtime tests. The source commit appeared and was
pushed after these checks; neither the root implementer nor the central verifier
created it. Its publishing actor has not been independently identified; the
verifier inferred an automatic commit from prior behavior, which is not proof
of the actor's identity.
The eight downstream consumer gate comparisons were still pending at source
publication and are not credited here. Any later result must retain its own
revision and actual failures/blocked counts.
