# Finite source authority: host execution evidence

Source commit: `8e4fba851e58f5d01aec0e968e043ee9fafcb6f9`.
Baseline: `e4fd66d85d4eb43bcf0a8294ca416130f9f00330`.

The source owner now retains its caller-admitted finite authority and checks
the current group-time bound before preparation, after blocking decode, before
queued/held/probe/EOF sending and before source/group commands. A trusted
same-session renewal can continue the same source while the old grant remains
live. Invalid candidates preserve the old token; observed expiry is terminal.
The configured static authority margin, dynamic clock uncertainty and admitted
work/lead budget accumulate conservatively, with equality and saturation refused.

## Observed results

| Native execution | Source | Result |
| --- | --- | --- |
| `30107136981729354` | Guard-disabled control | Exit 101; 2 passed, 6 failed, 0 ignored, 671 filtered; one footer |
| `30107136981729355` | Corrected final v2 | Strict workspace/all-target Clippy, warnings denied; exit 0 |
| `30107136981729356` | Same corrected final v2 | Exit 0; 3,037 passed, 0 failed, 2 existing ignored, 0 filtered; 81 footers |

All eight added authority cases occur once and pass in the corrected run.
The speaker library executes all 671 prior named cases plus the eight new
cases, with no missing or extra names. Existing source-group and source-loopback
process oracle cases also pass in the workspace run.

The complete MP3 renewal test uses actual authenticated localhost datagrams
and real receiver reports. It crosses the old expiry and finishes 24,000 frames
in 94 packets, including the 192-frame tail. The unchanged independent scalar
PCM reference comparison measures peak error 1 LSB and RMS error
0.7097975063354337 LSB; all 94 receiver reports are accepted, with empty
queues/in-flight accounting and actual source `Drained`.

Clock observations and the renewed token are explicit test inputs, not a live
clock or quorum. The test separates group and interface origins by nine
seconds. Its 500 microsecond work/lead budget, one millisecond transport
margin, 250 millisecond lookahead and scripted progression are configured
assumptions, not measured CPU deadlines. PCM comparison is before board DSP,
retained HAL or acoustic output.

## Causal control and retained mistakes

The control differs only by removing the retained-token check in `observe`.
Constructor/data wiring, candidate checks, source/transport behavior and all
test assertions remain identical. Candidate-command rejection and the timely
renewed UDP positive pass; the six retained-authority regression cases fail
at their expected-authority assertions. A failing assertion ends that case;
later branches are not claimed observed. This is an expected-failure control,
not a passing product gate or an executed baseline image.

The predeclared filtered count was incorrectly 678. The verifier stopped on
that mismatch before admitting positive gates. Prior native 353 actually
executed 671 speaker tests; the new eight yield 679 total, so the focused
eight-case control filters 671. The wrong forecast had included seven tests
instrumented only in an earlier control as though they were baseline tests.
Independent review reconciled the source lineage and actual logs. No source,
assertion or frozen manifest changed, and the control was not rerun.

A second extraction mistake initially found only 654 historical test names
by starting at Cargo's stderr header. The raw harness `running 671 tests`
line and 17 test results precede that header. Starting at the actual harness
line and ending at its footer recovers all 671 unique names. The mistaken
count and correction remain recorded; no denominator is silently replaced.

The first test draft was rejected before execution because it did not prove
unchanged retained authority after each rejected renewal, or continued signed
tail custody across EOF. The successor adds those assertions without changing
existing cases, timings, reference vectors or tolerances. Both rejected v1
snapshots remain preserved and unrun.

## Source binding and reproduction

The final inventory contains 1,672 files, six owned overlays and eight new
tests. Each native receipt matches all 1,670 transferred path/hash/size/mode
tuples; only the two tracker files are excluded. Each job finished with a
terminal acknowledgement and released source/pair/tree/record custody. The
successful jobs also released staging; control artifacts were skipped and its
staging flag is absent/null, not asserted true. Wrapper processes are absent.
`receipt.json` binds source, raw logs, inventories, commands and review records;
`observed.txt` contains selected exact output, including the failed control.

Use an independently prepared immutable candidate and an admissible remote
worker. Select the guard-disabled candidate only for the expected-failure
control. These commands compile and execute strictly remotely:

```sh
cd "$CONTROL_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline -p franken-speaker --lib \
  source_runtime::tests::authority:: -j1 -- --show-output --test-threads=1
```

On the corrected candidate, the two positive gates are:

```sh
cd "$FINAL_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- \
  --show-output --test-threads=1
```

Five touched Rust files passed the edition-2024 Rustfmt check from Rust 1.99.0.
No Python source changed. No SDK test was rerun for this candidate.

## Qualification boundary

This is a source-side currentness/send gate. Token authenticity, quorum
renewal and revocation delivery remain the trusted control owner's job.
Stopping the sender does not recall delivered audio, issue a HAL stop or
change receiver output grants. Already-granted output and takeover waiting
retain their separate contracts. Direct `SourceMedia` callers are not secured
by this owner, and a full source/control/output-grant bridge remains open.
Constructor identity validation precedes probing; actual expiry is sampled
later. Genuine prior receiver reports may retire credit before a step checks
expiry; credit does not authorize new source work or prove audible output.

No target/QEMU execution, board RAM/deadline fit, physical radio/audio,
provider or native-tailnet qualification is claimed. Original N07 acceptance
and dependencies remain open.

This minimal historical record serves the owner and independent publication
reviewer. It gates revision-bound publication under `AGENTS.md`, covers the
observed authority/oracle/count defects, and retires from active maintenance
when this publication wave ends; it is not a new runtime framework.
