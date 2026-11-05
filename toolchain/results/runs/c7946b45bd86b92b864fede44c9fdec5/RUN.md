# N03 target-ISA run c7946b45, 2026-11-05

**Scope.** N03's group clock built for soft-float big-endian MIPS32r2 and run as PID 1 of the Debian 4.19 Malta guest under
QEMU 11.1.2 (`-icount shift=0`, 24Kf). It runs the 30 scripted worlds of `tests/n03/vectors.json` and two seeded simulated
worlds, and measures guest instructions for the exchange and gate paths; `toolchain/src/measure-n03-target.py` judges the
transcript. This is host simulation, **not** hardware: executed instructions, not cycles; no cache, pipeline, memory or
multiplier timing; no board clock; the clock is a network-clock fit and says nothing about the DAC. No physical device or provider
service was contacted.

## What was run

Two real boots of one ELF (`bf1957e2e0d98288...`, built centrally from repository head `e77f24d` plus the guest
crate) with different per-run seeds, and two planted negatives. Commands are in `n03-target-receipt.json`; the paths of the
machine that ran them are deliberately not recorded.

## Results

| run | judge exit | outcome |
|---|---|---|
| normal-1 | 0 | all six gates passed |
| plant-replay | 1 | `N03T-SEEDED: seeded world 0: the guest used run seed 3317816542148013125 / LCG seed 1763172332, this run's seed derives 2289910933517311761 / 1997896231: the records were` |
| normal-2 | 0 | all six gates passed |
| plant-truncate | 1 | `N03T-TRANSCRIPT: transcript is incomplete (BEGIN True, END False)` |

All 30 worlds (1,839 records) equal the independent reference and the host build's digests, byte for byte. Guest instructions
(minimum of 5 repetitions, run 1): exchange 155057.4 per operation, gate 56933.9 per operation; about
11.584 Minstr/s of one member's clock work at one gate call per 256-frame block and one
exchange per 32 blocks.

## Files

* `n03-target-receipt.json`: the receipt (commands, hashes, seeds, every gate's verdict, the figures).
* `normal-1.serial.bin`, `normal-2.serial.bin`, `plant-replay.serial.bin`: raw QEMU serial transcripts of the three boots.
* `plant-truncate.serial.bin`: **derived**, run 2's transcript cut at 60 % by the judge's own `truncate_dump`; not a separate boot.
* `host-records.bin`: the 30 `N03-TARGET-HOST` records of the host build, the input of the byte comparison.

The guest ELF and the full host log are not committed (the log carries worker names and local paths).
