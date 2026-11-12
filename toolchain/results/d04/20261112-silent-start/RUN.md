# D04 reset-proven software-silent startup

Code: `6268d42798ee5e64fbc80f4d0d1f2e9c86ee9a0a`, on baseline
`edad89b3818d08aed539609df85080529a45e74d`. Its complete 1,610-file tree
matches the immutable GREEN inventory. Four changed source files are hashed
in `receipt.json`; later controller/co-owner drafts are not included.

## Behavior

`RenderLoop::start_silent` requires zero actual applied DSP gain and a HAL
session with proven silence-only preparation. It sets the DSP mute before
backend start and enters `Muted` directly, before any source pull. The original
audible `start` remains available and the HAL's required silence prime still
applies. This is a software-silent output contract: normal HAL start still
calls backend start and unmute. It does not prove physical amplifier silence.

HAL preparation becomes trusted only after reset ACK **and** an adapter's
explicit guarantee that reset discards every accepted playback byte, including
copied FIFO contents, with exclusive submission authority through start.
Unknown adapters default to no guarantee. Any nonzero Prepared submission
attempt invalidates the proof before the backend call, including short,
zero-accepted and ambiguous failed writes. Startup consumes the proof.

Eight integration tests use a bounded copied-byte FIFO model around the actual
FakeBackend retained-buffer contract. They inspect actual bytes accepted before
an injected write error, retention across failed/no-ACK reset, ACK purge,
readable retained DMA, unknown capability, nonzero prequeue and applied gain,
required priming through the new wrapper, actual source pulls yielding silent
protected PCM, subsequent nonzero recovery, and ordinary audible startup.
Two HAL unit tests and one render unit test cover additional refusal boundaries.

## Actual execution

All jobs used strict remote RCH, Rust 1.99.0, `--locked --offline`, one build
job, and one test thread. Commands and actual Cargo excerpts are in
`observed.txt`; executed-command hashes, compiler environment and native source
receipts are recorded in `receipt.json`.

| Gate | Native build | Result |
| --- | --- | --- |
| Private capability-bypass RED, eight startup cases | `30106308287922523` | Expected exit 101: 7 passed, 1 failed, 0 ignored |
| GREEN full HAL library | `30106308287922542` | Exit 0: 163 passed, 0 failed, 0 ignored |
| GREEN speaker library + D03 + startup | `30106308287922544` | Exit 0: 537 + 6 + 8 passed, 1 existing D03 soak ignored |
| GREEN HAL/speaker all-target Clippy, warnings denied | `30106308287922548` | Exit 0, reached `Finished` |

Total GREEN: **714 passed, 0 failed, 1 ignored**. The ignored 25.5-hour soak was
not executed. All eight startup cases individually passed. Pinned Rustfmt
passed for all four source files before commitment.

The private mutant changes only the session's reset-purge capability check to
`true`. It fails exactly `unqualified_fake_reset_ack_never_establishes_silent_proof`
at `!s.silent_prepared_after_reset()`; the other seven startup cases pass.
It is not in the committed code. This distinguishes a working negative oracle
from a candidate failure or a test setup that rejects everything.

Root compared all 1,608 transferred paths, hashes, sizes and executable flags
for each of four jobs against its 1,610-file inventory. Two Beads metadata
files are excluded by transfer policy. GREEN entry arrays agree; differing
receipt/content roots are not treated as differing source. Every job has a
terminal ACK, dead wrapper, released source/pair custody and retired tree.
Staging release is reported separately with its provenance: the local wrapper
lease lacks that field; the verifier reports GREEN released and RED unknown.
Unknown is not reported as released.

GrayDeer independently reviewed exact source/receipt entries and retained output
(Agent Mail 30910); this is shared-log review, not a second execution. Public
excerpts remove ANSI and replace private source/target path prefixes; full raw
private log hashes remain in the receipt.

Disk guards initially prevented execution, and the GREEN guard failed again
after RED. Jobs began only after actual capacity crossings at the approved
20 GiB local / 40 GiB remote limits. RED was not rerun. The requested lower
local exception was unnecessary and unused; no global settings changed.

## Remaining qualification

These are remote host tests with synthetic board/calibration, scripted timing,
FakeBackend and an explicit FIFO model. They do not qualify a real driver's
reset/flush semantics, legacy-target execution, physical audio, 32 MiB resource
fit, hardware deadlines, providers, or the controller/co-owner drafts. Original
D04/G02/G03/Q07 requirements remain open; no requirement or failure was moved
to a follow-up to claim a full bead closure.
