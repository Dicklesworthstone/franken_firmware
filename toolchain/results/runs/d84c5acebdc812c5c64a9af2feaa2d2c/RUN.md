# D03 target-ISA run d84c5ace, 2026-11-05

**Scope.** The D03 drift resampler built for soft-float big-endian MIPS32r2 and run as PID 1 of the Debian 4.19 Malta
guest under QEMU 11.1.2 (`-icount shift=0`, 24Kf). It prints the resampled `f32` samples of the host quality tones and
the guest instructions per output frame; `toolchain/src/measure-d03-target.py` judges the transcript. This is host
simulation, **not** hardware: instructions executed, not cycles; no cache, pipeline, memory or multiplier timing; no
board clock; nothing about the real DAC. No physical device or provider service was contacted.

## What was run

Two real boots of one ELF (`7ae93f2f64e43458...`, built centrally from repository head `0189791` plus the three
guest-crate files listed in the receipt) with different per-run seeds, and two planted negatives. Commands are in
`d03-target-receipt.json`; the paths of the machine that ran them are deliberately not recorded.

## Results

| run | judge exit | outcome |
|---|---|---|
| normal-1 | 0 | all six gates passed |
| plant-replay | 1 | `D03T-SEEDED: seed-1000: the phase the guest used (400285bc912a048a) is not the one this run's seed derives (3ff90ebb09de799a): the samples were not co` |
| normal-2 | 0 | all six gates passed |
| plant-truncate | 1 | `D03T-TRANSCRIPT: transcript is incomplete (BEGIN True, END False)` |

Quality on the target ISA (run 1): 1 kHz Q 91.707057 dB against a floor of 85,
10 kHz Q 28.976903 dB against a floor of 22; the four canonical sample dumps are
byte-identical to the host build (`host-records.bin`). CPU, guest instructions per output frame (minimum of 5 repetitions
of 2048 frames, run 1): fast500/noise 3040.0, fast500/silence 2685.5, nominal/noise 2283.7, nominal/silence 2224.9, slewing/noise 3044.1, slow500/noise 3040.8, slow500/silence 2685.3.

## Files

* `d03-target-receipt.json`: the receipt (commands, hashes, seeds, every gate's verdict, the figures).
* `normal-1.serial.bin`, `normal-2.serial.bin`, `plant-replay.serial.bin`: raw QEMU serial transcripts of the three boots.
* `plant-truncate.serial.bin`: **derived**, run 2's transcript cut at 60 % of the sample dump by the judge's own
  `truncate_dump`; it is not a separate boot.
* `host-records.bin`: the four `D03-TARGET-HOST` records of the host build, the input of the byte comparison.

The guest ELF and the full host log are not committed (the log carries worker names and local paths).
