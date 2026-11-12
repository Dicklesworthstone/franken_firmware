# D04: authenticated network PCM into protected rendering

The normal speaker library now connects `MediaEndpoint`/N04 prepared PCM to
`RenderLoop`, D03 resampling, D02 board protection and retained HAL submissions.
The new `network_render::NetworkRender` owns these stages and a fixed-capacity
PCM queue. Its caller admits one finite source epoch, its frame boundary and a
rational mapping between device ticks and group time. It exposes no raw
renderer or control port. This is a library integration; the existing
finite-source CLI still exports prepared PCM to a file.

Tested code commit: `d2a60417bbe6acc8d1a8bef65144a4239e1eef2d`, on top of
`0759da53357dddb1e2725380537aabf0094e91ec`.
The immutable candidate was baseline `8a3935d67480e39feb2059b1899ee8f9196b1377`
plus the five overlays recorded in [receipt.json](receipt.json). Root compared
every one of the **1,602** committed files against that candidate: exact hash,
length and executable mask, with no missing or additional files. Candidate
files were read-only. Each of the six actual RCH attempts also matched every
one of its **1,600** transferred files; only the two recorded `.beads` metadata
files were excluded. Source reviews do not substitute for those executions.

## Behavior checked

Preparation decodes big-endian stereo PCM into a bounded ring outside the
source-pull path. Pulling neither allocates nor performs network I/O. Partial
network blocks retain their full timeline slot; they do not implicitly end a
stream. Real, concealed, timeline-silence and final-lookahead pulls are counted
separately. Explicit finite EOF supplies at most two lookahead frames, then
uses the actual resampler phase to avoid truncating negative drift or emitting
an extra empty device block. The final short device block is padded through
the existing protection stage.

The render loop projects its next release, submission deadline, presentation
time and source demand without advancing either the source or device. A
finish-only tick can submit existing busy work and advance cancellation
acknowledgments without starting another source block. Ordinary `tick` keeps
its previous behavior. Temporary source absence remains starvation by default.

Fresh clock/epoch/authority checks gate ingress, preparation and active render
steps. N04's whole-block handoff deadline and each device slice's deadline are
checked separately. Clock or authority failure clears unsubmitted PCM and
cancels before cached busy work can submit. A bad MAC does not revoke valid
queued audio. Already-submitted device buffers remain held until the HAL's
actual completion or flush acknowledgment; missing acknowledgment faults and
quarantines the storage.

Normal finite EOF also waits for the admitted scheduled presentation end.
An early DMA completion is not presentation. After that end, lost completion
cannot prevent a bounded cancel/flush attempt; `Complete` requires the actual
renderer to reach `Stopped`. These checks use synthetic clock bounds, not a
measurement of acoustic output.

| Executed PCM case | Source frames | Independently checked output |
|---|---:|---|
| Complete two-block source | 512 | 512 frames in eight protected device blocks |
| Partial final source | 549 | 549 frames in nine blocks, with device-tail padding |
| Negative 500 ppm drift | 8,192 | 8,197 output frames |
| Unity ratio | 8,192 | 8,192 output frames |
| Positive 500 ppm drift | 8,192 | 8,188 output frames |
| Bad MAC followed by authentic packet | 512 | Same owner completes with exact, nonzero protected PCM |

The tests drive real localhost UDP authentication and N04 preparation. Every
captured retained-FakeBackend byte is compared against separately driven
D03/D02 stages, including order and full finite tails. They also observe
early DMA completion without early flush, and a lost-completion/no-flush-ACK
case that reaches the exact `DrainTimedOut` fault in **nine ticks** against an
admitted eight-tick deadline with the existing strict-greater timeout rule.
That case retains a quarantined DMA buffer and successfully reads its live
kernel view; no fake use-after-free or modification is recorded.

## Commands and outcomes

CyanPike alone ran the centralized native gates with Rust 1.99, default
features, locked/offline dependency resolution and `-j1`. The logical commands
below precede RCH's source/target remapping. Exact executed-command hashes,
private full-log hashes and terminal records are in the JSON.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +1.99.0 test --locked --offline -p franken-speaker \
  --lib --test d03_closed_loop -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  cargo +1.99.0 clippy --locked --offline -p franken-speaker \
  --all-targets -j1 -- -D warnings
```

The environment included `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`
and `RUSTFLAGS='-D warnings -C debuginfo=0'`. All compilation remained remote.
The standing authorized 20 GiB dispatcher floor exception was used; remote
reservation floors and global fallback/shim settings were unchanged.

| Native attempt | Result |
|---|---|
| `30106308287922397` | Compile failure: incorrect platform root imports. Exit 101, **zero tests run**. |
| `30106308287922402` | Test compile failure: `i32` drift value passed to an `i64` API. Exit 101, **zero tests run**. |
| `30106308287922408` | Prior source: 530 library plus six D03 tests pass; one existing D03 soak ignored. |
| `30106308287922415` | Prior-source strict Clippy fails on the fixed-byte chunk idiom. Exit 101. |
| `30106308287922422` | **Final source: 530 library plus six D03 tests pass**, zero failures, one existing soak ignored. |
| `30106308287922428` | **Final-source all-target Clippy exits zero**, warnings denied. |

All **24 new tests** ran and passed individually: seven render-seam tests,
three owner mapping/accounting tests and fourteen consumer tests. The original
D04 log judge independently finds all **65** required render tests in the
final native log. This is one selected judge case, not full qualification.
Its 19 Python judge controls pass; the additive registry has 25 invariants,
79 name entries including repeats and all 65 distinct tests mapped. Pinned
Rustfmt passes on all four touched Rust files. No test, golden, threshold or
lint policy was weakened; the corrections preserve the same PCM groups and
references. [tests.txt](tests.txt) retains both compilation errors, prior-pass
diagnostics and final actual Cargo output. [clippy.txt](clippy.txt) retains
the lint failure and final successful check. Both are explicitly excerpts.

Root independently read the source, actual test output and all six complete
transfer receipts. Final test and Clippy wrappers are dead, terminal ACKs are
recorded and staging/source/pair custody is released with trees retired.
The three failed attempts have terminal ACKs and released/retired source and
pair custody, but their staging-release fields are **null/unknown**, not
asserted released. Artifact selection was zero; no native binary or raw
per-test capture is claimed to have been retrieved.

YellowRabbit reviewed the exact scheduling/timing source and mechanical
corrections; GrayDeer reviewed queue/D03/EOF semantics and the retained actual
PCM/EOF output from the preceding passed run, `22408`. Root checked the final
run after the mechanical corrections. These reviews are not independent second
runtime executions. Root
preserved the shared Git index and existing empty lock; publication used a
private index and staged only explicit qualified paths.

## Remaining acceptance

The tests use a scripted group clock, synthetic board calibration and a
retained FakeBackend. They establish neither physical presentation nor
legacy-board boot, retained driver behavior, actual CPU/memory deadlines,
radio reliability or native Spotify/AirPlay/Tailscale/Alexa operation.
No device or live LAN experiment was performed. D04's original qualification
and prerequisites remain open; no acceptance was moved into a follow-up to
claim a close. The separate volume/mute control draft is not included in
this source commit or evidence.
