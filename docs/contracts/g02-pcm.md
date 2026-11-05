# G02 slice 2 contract: known PCM through the channels while the controls change (`ffw-ld0`)

Scope: the acceptance item slice 1 left open, an end-to-end run in which **known multichannel PCM goes
through D02's driver channels** while group volume, local buttons, mutes and membership change
mid-stream at exact frames. Slice 1's contract is `docs/contracts/g02.md`; this file adds to it and
changes none of it. Code: `crates/franken-dsp/tests/g02_pcm.rs` (new), `tests/g02/pcm_*` (new),
`scripts/e2e/g02-pcm` (new). Slice 1's files are not edited.

**Numerical tests do not prove physical behavior.** Nothing here touches a device, a speaker or a
button. The PCM is synthetic noise, the board is a synthetic fixture with a synthetic calibration, and
the ramp timing is D02's synthetic 10 ms. Verification status lives on the bead, not in this file.

## The oracle, and why it does not need a model of the filters

D02 processes a sample as: route, DC rejection, crossover sections, **then** gain
(`min(trim * applied, max_gain) * fade`), thermal scaling, limiter, ceiling, `i16`. The filters see only
the input, never the controls. So two boards fed the same samples have the same filtered signal
`x[n]`, and only the gain differs. The run therefore drives three real `ProtectedBoardDsp` instances
in lockstep, one frame per call:

| Board | Controls | Fed |
|---|---|---|
| **B**, controlled | a `MemberVolume` applies the case's frame-exact schedule, then `sync` | the stream through `RolePlan` |
| **A**, unity reference | none: unmuted at gain 1.0 for the whole stream | the same stream |
| **R**, role reference | none: unmuted at gain 1.0 | the **pre-mapped** stream, written out in the harness with the contract's formulas |

In the **linear regime** (limiter, thermal model and ceiling never engaged; the synthetic calibration
has `trim = max_gain = 1.0`, so the gain is exactly `applied * fade` with no clamp) the output of
every channel at every frame satisfies

```
out_B[n][c]  =  round(x[n][c] * g_B[n])        out_A[n][c] = round(x[n][c] * g_A[n])
|out_B[n][c] - out_A[n][c] * g_B[n] / g_A[n]|  <=  0.5 + 0.5 + 0.01  =  1.01 LSB
```

Both outputs are rounded once (`f32_to_s16` is `round_ties_even`, so at most 0.5 LSB each); the
reference's error is scaled by a ratio of at most 1; 0.01 LSB covers the `f32` products at up to 16384
LSB. **The filters cancel**, so this check does not depend on D02's filter correctness (D02's own
vectors cover that) or on any model of it. It ties the **PCM** to the **applied gain**, frame by frame,
across ramps, mutes and membership changes. `g_A` and `g_B` are the boards' own `applied_gain()` after
each frame, which is the gain that frame used.

The applied-gain trajectory itself is checked separately, against the slice 1 controls model
(`tests/g02/reference.py`, read and never edited) simulated at judge time, **at every frame**, to 1e-7
(`f32` is emulated operation by operation, so the values agree to the last bit).

## The known input

Two integer LCG streams, `state = state * 1664525 + 1013904223 (mod 2^32)`, sample `(state >> 16)` as
an `i16`, scaled to `i16 / 32768 * 0.25`. Every sample is a dyadic rational, exact in `f32`, so Python
and Rust reproduce them bit for bit. The first samples for seed 1 are worked out on paper
(`1015568748 >> 16 = 15496`, then raw 24200 and -32490) and pinned in both languages. The harness
fingerprints (FNV-1a 64 over the little-endian `f32` bits) the stream **actually fed to the board**
after the role remap; the judge recomputes it, so a wrong seed, a wrong remap or a dropped frame is
caught. Left and right use different seeds, so Left, Right and Stereo rooms are distinguishable.

## What is checked, per case

| Check | Meaning |
|---|---|
| input fingerprint | the board was fed the documented stream |
| operation results and the gain trajectory | every frame of `g_A` and `g_B` equals the model's, and the results (including each mute reason after each operation) match |
| gain bounds | `0 <= g <= 1`; no step larger than one ramp step (`1/480` plus half an `f32` ulp); under a fixed ceiling `g` never exceeds it; **while a mute reason holds, the gain only falls** |
| linearity | the bound above, at every frame and channel |
| exact silence | whenever `g_B == 0`, every channel is exactly 0 |
| linear-regime certificate | limiter minimum 1.0, no thermal scaling, no clipping on all three boards, and no output above 0.8 of full scale |
| non-vacuity | every channel peaks at 50 LSB or more in the reference run, and carries signal in the controlled run while the gain is audible |
| role routing | for a Left or Right room the two tweeters (channels 0/1) and the two mids (2/3) are **bit-identical** on every frame; for a Stereo room they differ in more than a quarter of the frames (so the equality check is not vacuous); the role-mapped stream equals the pre-mapped stream bit for bit |

If the regime or non-vacuity precondition fails, the case **fails**; it is never passed on a check that
could not have caught anything.

## Cases

| Case | Stream |
|---|---|
| `G02PCM-001` | volume ramps with retargets that land mid-ramp: down, then up, then down, then up; trim by command and by local button |
| `G02PCM-002` | mute wins over volume commands that land mid-fade; unmute, group mute and a 10-frame re-mute ramp from where the output is |
| `G02PCM-003` | membership: reconnects fade the room out, the join returns it to the group's level only, a group-mute snapshot holds it silent after the join |
| `G02PCM-004` / `005` | a Left / Right room on the 5-driver board through volume changes and a local mute |
| `G02PCM-006` | the Sub board with the sub role: volume, local mute, a relative step |
| `G02PCM-007` | ceilings in the stream: a 2.0x trim bounded at 0.5, a fault ceiling, a NaN ceiling failing closed to exact silence |
| `G02PCM-008` | everything interleaved on one stream, including a local button pressed **while locally muted** |

## Invariant map

| Invariant | Evidence |
|---|---|
| `G02PCM-INV-CEILING` | `G02PCM-007` |
| `G02PCM-INV-EXACT-SILENCE` | `G02PCM-002/003/004/005/006/007/008` |
| `G02PCM-INV-FRAME-EXACT-GAIN` | `G02PCM-001/002/003/004/005/006/007/008` |
| `G02PCM-INV-KNOWN-INPUT` | `G02PCM-001/002/003/004/005/006/007/008` |
| `G02PCM-INV-LINEAR-REGIME` | `G02PCM-001/002/003/004/005/006/007/008` |
| `G02PCM-INV-MUTE-IN-FLIGHT` | `G02PCM-002/008` |
| `G02PCM-INV-PCM-LINEAR` | `G02PCM-001/002/003/004/005/006/007/008` |
| `G02PCM-INV-RECONNECT-NO-SPIKE` | `G02PCM-003/008` |
| `G02PCM-INV-ROLE-ROUTING` | `G02PCM-004/005/006/008` |

## Running, and the evidence boundary

```
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp --test g02_pcm -- --nocapture > pcm.log
scripts/e2e/g02-pcm --judge pcm.log [--receipts DIR]
```

A full pass plans 14 cases: 3 meta, 8 vectors and 3 Rust tests. Observations are large (about 300 KB
per case: every frame's gain and every channel's output for two boards), so `pcm.log` is a few
megabytes. The judge reuses the D01 cargo-log parser. A case or required Rust test with no observation
is `blocked` (exit 3), never passed. The Rust harness runs the same checks inline, so a violation also
fails `cargo test`, and a control test plants corruptions (a 3 LSB error, 1 LSB while muted, a gain off
by 0.01, a wrong fingerprint, an engaged limiter, a broken pair, a role mismatch) and requires each to
be reported.

**Planted defects.** `tests/g02/test_g02_pcm.py` checks the judge against a **toy board** defined in
that file (its own simple filters, then the gain; it has the one structural property the oracle uses, and
is not D02). It plants defects in the PCM path (the output jumping ahead of the reported ramp, using the
previous frame's gain, leaking 1 LSB at zero gain, a 3 % channel error, a Left room fed the right
channel, a wrong input seed, a broken tweeter pair, an engaged limiter, a dead channel) and in the
controls (a volume command that unmutes, a group unmute that clears a local mute, no clamp before the
ramp, a reconnect that keeps the stored volume or skips the join mute, a trim reset by a volume change,
a ramp that restarts, a local button that unmutes). The unmutated baseline is green first, each defect
is caught, and removing it restores green. The PCM-path defects are caught by the **named property of
the raw PCM**, not by the reference comparison, because they leave the reported gains untouched.

## Limits, stated plainly

* **This does not test D02's filters.** They cancel out of the oracle by construction; D02's own
  vectors are their evidence.
* **Linear regime only.** The check is valid below the limiter threshold and the thermal soft limit
  (the stream is 0.25 amplitude noise). The limiter and thermal behaviour are not exercised here; the
  run certifies it stayed out of the way, and fails if it did not.
* **One frame per `render_into` call.** The applied gain is only observable per frame this way, so
  block-sized calls (up to 256 frames) are not exercised here; D02's gain advance is per sample inside
  the block loop, but this slice does not prove that.
* **Control changes land between frames**, as a real control path would between blocks, not inside a
  frame. There is no thread or timer: "concurrently" means interleaved at frame granularity, which is
  what a single-threaded audio callback sees.
* **The gain model is a second implementation by the same author** (slice 1's), so a shared
  misreading would pass. The raw-PCM properties (linearity, exact silence, the pair equalities, the
  certificate) do not depend on it, which is the reason they are there.
* **The toy board in the tests is not D02.** It stands in only to exercise the judge. Whether the real
  renderer satisfies the oracle is decided by the central run, which is the first Rust execution of
  `g02_pcm.rs`.
* Host-only, synthetic noise, synthetic fixture and calibration; no real board, speaker or button.
