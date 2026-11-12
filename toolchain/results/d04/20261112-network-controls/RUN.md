# D04 serialized network-owner volume and mute

Code: `f013e34c14f143fba7527ba5f1f2ab636a3cf344`, on baseline
`9fd482f1cb0a88ad22d1f9824eb8a7f11ef65e9c`. The committed 1,606-file tree
matches the immutable GREEN source inventory, including both changed files.
`receipt.json` records their hashes, native build identities and source receipts.

## Behavior and tests

`NetworkRender::set_gain`, `mute` and `unmute` keep control serialized with
source-phase, authority, clock and deadline checks. They retain the private
renderer boundary. Valid controls during busy render bookkeeping change future
DSP targets without changing already-rendered PCM, source position, queue or
held DMA. These are D02 ramp controls; mute does not revoke submitted audio or
assert an immediate hardware mute.

Six added tests exercise real authenticated localhost UDP through MediaEndpoint,
NetworkRender and the existing D03/D02 stages. The positive test compares all
4,096 source frames against separately driven protected DSP output across gain,
mute and recovery. Controls occur while work is busy and prior DMA is held;
snapshots check unchanged source phase, queue, counters, submitted bytes and HAL
calls. Mute reaches silence and recovery produces nonzero PCM.

Four negative tests begin actually muted, then attempt unmute after a clock
fault, a busy clock fault, a busy deadline expiry or authority expiry. They
drain prior events and require loss-free `Muted -> Draining`, without an
intervening `Running`. Busy negatives retain readable DMA until flush ACK and
reject stale submissions. A separate EOF case rejects three controls while
preserving the scheduled finite drain. A fresh owner is a positive recovery
control after the terminal clock fault.

The private RED mutant adds only `self.render.unmute()` before `control_ready()`.
It fails exactly those four ordered-event checks: actual transitions are
`Muted -> Running -> Draining`. The positive 4,096-frame test and EOF test still
pass. The mutant is not in the committed source.

## Executed verification

All commands used `RCH_REQUIRE_REMOTE=1 rch exec`, Rust 1.99.0, `--locked
--offline`, one build job and one test thread. The logical commands and actual
ANSI-free Cargo output are in `observed.txt`. RCH also injected isolated target
directories, source custody configuration and the environment recorded in
`receipt.json`; the actual executed-command hashes are retained there.

| Gate | Native build | Actual result |
| --- | --- | --- |
| Private RED, `--lib network_render::` | `30106308287922465` | Expected exit 101: 19 passed, 4 failed, 0 ignored, 513 filtered |
| GREEN, `--lib --test d03_closed_loop` | `30106308287922468` | Exit 0: library 536 passed; D03 6 passed, 1 existing ignored soak |
| GREEN, Clippy `--all-targets -- -D warnings` | `30106308287922479` | Exit 0, reached `Finished` |

Both source files passed pinned `rustfmt +1.99.0 --check` before commitment.
Root compared every transfer receipt entry to its immutable inventory: 1,604
files per job, zero mismatches. The two excluded inventory files are Beads
metadata, listed explicitly in the receipt. All three native jobs finished with
terminal ACK, dead wrappers and released source/pair custody plus retired trees.
RED's staging-release field is **UNKNOWN**; it is not reported as released.

The public transcript omits RCH orchestration and full source receipt JSON,
removes ANSI, and replaces private source/target path prefixes. Full private
log hashes are retained. GrayDeer independently checked the same source and
retained outputs (Agent Mail 30684); this is shared-log review, not a second run.

## Qualification boundary

This is native remote **host integration** with scripted clock, kernel and
calibration plus a bounded FakeBackend capture. It does not qualify this owner
on a legacy guest kernel, a physical speaker, real Wi-Fi, or a 32 MiB board.
Spotify, AirPlay, Alexa, native tailnet and SOAP-to-render application remain
separate unmet original requirements. D04 and Q07 remain open; these results
record a component improvement, not completed firmware or a full bead closure.
