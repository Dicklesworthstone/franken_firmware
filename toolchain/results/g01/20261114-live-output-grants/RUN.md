# Live-lease output grants: host execution evidence

Source commit: `890011084ed67ed611f1a0443a83b4f52e81f0d8`.
Baseline: `8b654441ec025b4b45017d997c01eced1b9cb555`.

The fresh single-epoch `SettledRender` can opt into explicit whole-block output
grants before joining. A trusted in-process request validates canonical
membership/control/join authority and fresh conservative group time. The same
owned membership gates actual `NetworkRender` work before N04 preparation and
again after its fresh clock observation. Grant issuance may allocate on the
control path; the render predicate does not.

Busy-block permission and next-block permission are separate. A missing next
grant retains PCM and still services running HAL completions/faults. Revoking
busy permission cancels before submission; already-submitted buffers retain
actual drain/flush acknowledgement custody. Rational group-frame conversion
keeps the exclusive output boundary conservative, including admitted mapping
and fresh clock uncertainty. Waiting never rebases the original deadline.

## Observed gates

| Native execution | Actual result |
| --- | --- |
| `30107136981729361` | Strict remote workspace/all-target Clippy, warnings denied; exit 0 |
| `30107136981729362` | Focused: 9 passed, 0 failed, 0 ignored, 691 filtered; exit 0 |
| `30107136981729363` | Workspace: 3,058 passed, 0 failed, 2 existing ignored, 0 filtered; 81 footers; exit 0 |

All nine required cases occur once and pass in both successor test runs.
Stereo and LeftMono positives each check 512 source frames and eight protected
blocks against a separately assembled role/resampler/protection reference,
including nonzero output and actual model drain ACK. This shares the DSP
implementation; it is an integration oracle, not independent DSP or physical
correctness proof. The expiry case crosses the real canonical owner lease
during actual preparation, paired with a live-authority PCM positive.

The full speaker harness contains all 691 prior named cases plus the nine new
ones: 700 unique cases, none missing or extra. The full workspace retains both
existing ignored tests. Selected exact output, the ignored-case lines and all
81 workspace footers are in `observed.txt` (one remote private candidate
prefix is elided in the failure location); `receipt.json` binds raw logs,
inputs, terminal acknowledgements and custody. Six touched Rust files pass
Rustfmt 1.99.0, edition 2024. No Python changed.

The frozen inventory has 1,681 files. Each successor native receipt matches
all 1,679 transferred path/hash/size/executable tuples; only the two tracker
files are excluded. All three jobs have terminal ACK, absent wrappers and
released staging/source/pair/tree/record custody.

## Retained failure and review corrections

Before execution, review found that a running no-grant wait could stop polling
HAL completions/faults. The wait path was repaired and tested. Another review
required a real canonical lease-expiry crossing case, rather than only direct
predicate refusal; it was added using the existing shared test clock.

The first executed candidate passed Clippy (native `30107136981729359`) but
its focused run (native `30107136981729360`) failed: 8 passed, 1 failed,
0 ignored, 691 filtered. The revocation case failed `assert!(reached)` before
its custody assertions. The workspace run for that candidate was not started.
Source review identified that normal completions can return the first HAL
buffer before the next CPU block becomes busy; the failed log did not contain
a per-tick causal trace. Two reviewers approved an explicit completion-loss
fault to create
the intended retained-buffer overlap. The only executed-candidate source
change is one `set_lose_completions(true)` in that fixture. Every assertion,
case name and timing value remains; the backend's separate actual flush ACK
still has to settle custody. The failure remains recorded, not reclassified
as a pass. Its failed execution skipped artifact retrieval and has no staging
release value; other required custody was released. This capsule preserves
that null rather than claiming a staging acknowledgement.

## Reproduction

Prepare an immutable source candidate at the source commit and a freshly
admissible remote Rust 1.99 worker with offline dependencies. Use a strict
remote RCH instance; refresh admission, source and disk checks before each job.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
```

Proceed only after terminal exit 0, an exact same-execution source receipt,
terminal ACK, released staging/source/pair/tree/record custody and an absent
wrapper. Shell sequencing alone does not establish these checks.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline -p franken-speaker --lib output_grants:: -j1 -- \
  --show-output --test-threads=1
```

Before the full workspace run, require the same receipt/ACK/custody checks,
exactly nine passes, zero failures/ignored, 691 filtered, one footer, and every
required name once/OK. Stop on mismatch; retain the failure. Refresh admission
and source/disk checks again.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- \
  --show-output --test-threads=1
```

## Qualification boundary

This is authenticated localhost PCM and protected render/HAL-model execution
with scripted clocks and injected faults. No QEMU/SDK, target resource/deadline,
physical speaker/radio/audio, Spotify/AirPlay/Alexa or native-tailnet run was
performed. The default owner behavior remains unchanged. This optional mode
retains conservative lease-expiry stop; it does not implement already-granted
post-lease drain, N03 drain authority, takeover/rejoin/persistent grants,
partial-block clipping, or an authenticated G03/N02 grant command. Original G01
acceptance and dependencies remain open; no feature was waived. Canonical
Asupersync and its AGY custody hold were not changed.

This historical capsule serves the owner and independent publication reviewer,
gates revision-bound publication required by AGENTS.md, and records the
observed callback-starvation, expiry-oracle and fixture-schedule defects. It
retires from active maintenance when this publication wave ends and adds no
runtime machinery.
