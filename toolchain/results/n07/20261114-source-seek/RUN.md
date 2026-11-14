# Targeted source seek: host execution evidence

Source commit: `fea2e12afcb0c1eed26d289aa36a4b33be523334`.
Baseline: `aa759e64b5212902484aa55381798c9bfdff7ac1`.

`SourceRuntime::seek_source_new_epoch` now connects the existing real finite
decoder seek to the privately owned carrier epoch transition. Native source
position and 48 kHz transport start are independent. The targetless policy
command remains policy admission only.

The operation validates retained/candidate authority and the complete new
transport plan before changing media. It purges old queued/held wire, advances
the carrier, performs the actual seek, and checks fresh authority, uncertainty,
clock continuity and first-packet cutoff after blocking work. Partial failures
are terminal. Lifetime diagnostics remain cumulative; a checked loss baseline
makes completion specific to the new epoch without erasing prior losses.

## Observed results

| Native execution | Actual result |
| --- | --- |
| `30107136981729357` | Strict remote workspace/all-target Clippy, warnings denied; exit 0 |
| `30107136981729358` | Full workspace; exit 0; 3,049 passed, 0 failed, 2 existing ignored, 0 filtered; 81 footers |

All twelve added seek cases occur once and pass. The speaker library runs all
679 prior named cases plus the twelve new cases: 691 unique cases, none
missing or extra. Existing group and source-loopback process oracles each
pass their three cases in this same workspace execution. Selected exact
output, including both ignored-case lines and all 81 footers, is in
`observed.txt`; `receipt.json` binds raw-log hashes and exact inputs.

The main positive uses the actual MP3 decoder, authenticated localhost
datagrams and genuine receiver reports. The old epoch reaches EOF with a
signed held tail and one sent-but-unreported packet. The caller explicitly
advances the receiver epoch. The sender purges the old tail; late old signed
wire injected over loopback is rejected. Seeking to native frame 1,000 then
delivers every sample of the unchanged independent PCM reference suffix:
23,000 frames in 90 packets, including the 216-frame tail. Peak error is
1 LSB and RMS error is 0.7100673574907616 LSB under unchanged peak 4/RMS 1.5
tolerances. Sequence, frame and presentation mapping are asserted for every
packet. The test sends 90 genuine reports; authenticated cumulative credit
reaches 90 with the sender queue and in-flight accounting empty. This does
not assert that every intermediate report was received.

Other cases cover repeated seek, a nonzero wire start independent of native
target, preserved buffered-credit choice and clock latch, invalid preflight
without decoder movement, retained and candidate lease expiry across a real
backward seek, and live/at/after first-cutoff boundaries. Actual injected
reader failure remains terminal with no old-wire flush. Explicit stop cannot
resume. Three injected transport errors make the new epoch Incomplete; a
later clean epoch drains while lifetime loss counters remain visible. The MP3
known-length premise is asserted at 24,000 frames; a beyond-end seek
saturates to EOF and sends no media. These fixture premises were unverified
before the native run; the cases passed rather than skipping them.

## Pre-execution review corrections

The first composition put the new test child outside the existing fixture
module, which would not compile. Root caught this and Gray independently
reported it; it was nested under `tests::seek` before the frozen candidate.
Gray also identified that a blocking seek could cross its preflight cutoff
while authority remained live. A fresh post-seek upper-bound check and paired
inside/equality/after regressions were added before freeze. No executed test
failed, no native candidate was rerun, and no source/assertion/golden changed
after either native admission. This wave did not execute an old-code or
guard-disabled causal control; no such result is claimed.

The initial publication recipe put the two commands together without the
actual intervening gate. Gray33848 rejected that draft. The corrected recipe
separates the commands and requires the settled Clippy receipt/ACK/custody
checks before starting the workspace run; no source or native rerun changed.

## Source binding and reproduction

The frozen inventory has 1,676 files and four explicit owned overlays. Both
native receipts match all 1,674 transferred path/hash/size/executable tuples;
only the two tracker files are excluded. Both jobs have terminal
acknowledgments, absent wrappers, and released staging/source/pair/tree/record
custody. The three touched Rust files passed Rust 1.99.0 Rustfmt with edition
2024. No Python changed. No SDK or QEMU rerun was performed.

Use an independently prepared immutable source candidate at the source commit
and a freshly admissible remote worker with Rust 1.99 and offline dependencies.
The two positive gate commands are:

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
```

Before starting the workspace test, require the Clippy job to finish with
exit 0, its same-execution source receipt to match the candidate inventory,
terminal acknowledgment to be true, the wrapper to be absent, and all
staging/source/pair/tree/record custody to be released. Stop on any mismatch
or unsettled state. Shell command sequencing alone does not prove this gate.
Refresh admission and disk/source checks before the second command.

```sh
cd "$SOURCE_CANDIDATE"
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "$RCH_WORKER" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- \
  --show-output --test-threads=1
```

## Qualification boundary

This is a source-side operation, scheduled outside protected rendering. The
clock, work/lead budget and receiver epoch admission are explicit test inputs;
they are not real fleet clock or CPU-deadline measurements. The caller must
resolve old receiver output and admit the new receiver timeline under existing
output grants/fencing. Sender transition cannot recall sent datagrams, issue
a HAL flush/stop ACK, establish audible seek completion, or certify delivery
of the old unreported packet. Drained describes only the new epoch.

No G03/provider seek binding, S03 completion ticket, full source/control/output
grant bridge, target RAM/deadline fit, retained-radio ownership, physical
network/audio, provider or native-tailnet qualification is established here.
Original N07/S03 acceptance and N07 dependencies remain open. Canonical
Asupersync and its AGY hold were not changed.

This historical capsule serves the owner and independent publication reviewer,
gates revision-bound publication required by AGENTS.md, and records the
observed module-scope/cutoff/oracle risks. It retires from active maintenance
when this publication wave ends; it adds no runtime framework.
