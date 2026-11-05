# P02 FFW_PLATFORM smoke, central QEMU run 570cd370, 2026-11-05

**Scope:** the device speaker's platform startup (`/franken-speaker --platform-startup`, retained-kernel backend) and its board
catalog (`--catalog`) under Debian QEMU kernels (Malta/24Kf/Linux 4.19 and g3beige/G3/Linux 4.9). This is not a stock Sonos
kernel, the audio driver, or a physical device. No device or provider service was contacted.

## Inputs
- Tree: revision `e77f24d` + DarkPeak's `p02-judge.patch` (sha256 `9ef8ec9a…`). The patch's eight files are unchanged from
  `e77f24d` to the commit that adds this record, and the committed files are byte-equal to the booted tree.
- Speakers: the device `franken-speaker` ELFs from the central P01 run at `e77f24d` (receipt
  `toolchain/results/p01/rev-e77f24d28777/`): mips sha256 `616cc22f0283fc80…`, powerpc
  `e6e8e35a2cd8006d…`.
- Host catalog: what the host speaker of that tree printed centrally, taken verbatim (sha256 `69c2e38da2ea10c8…`,
  10006 bytes); the runner compares it byte for byte with each device speaker's serial output.

## Command
From the snapshot root; `<...>` stands for local paths, which are not recorded:
```sh
FFW_BUILD_DIR=<kernel cache> RCH_WORKER=trj RCH_REQUIRE_REMOTE=1 RCH_DISABLE_TARGET_REUSE=1 \
  python3 toolchain/src/run-qemu-verification.py --timeout 60 --jobs 2 \
  --speaker-mips <mips franken-speaker> --speaker-ppc <powerpc franken-speaker> \
  --speaker-host-catalog host-catalog.json --speaker-platform --platform-controls --target-dir <snapshot>/build/p02-platform-target
```
The runner built both guests itself on worker `trj` (`rch exec --source-content-receipt -- cargo +nightly build --release --target <T>
-Z build-std=core,panic_abort --features speaker-smoke,speaker-platform -j 2`). `RCH_DISABLE_TARGET_REUSE=1` was set because an
earlier attempt on the same tree left an unfinished lease on the pooled target dir. The guest Rust was also checked centrally
(`cargo +nightly clippy --release --target <T> -Z build-std=core,panic_abort [--features speaker-smoke,speaker-platform] -j 2 -- -D warnings`,
mips and powerpc with the features, mips without: exit 0, no diagnostics). `rustfmt --edition 2021 --check` is clean, and
`python3 -B -m unittest discover -s toolchain/tests` passed 369 tests.

## Results (`e07-e03-verification-receipt.json`, status `PASS`)
| guest | kernel | guest init sha256 | catalog | platform verdict |
|---|---|---|---|---|
| mips | `3803357e…` 4.19 malta | `3b4bd79f…` | byte-equal to the host | **degraded** |
| powerpc | `289f40b6…` 4.9 g3beige | `0717cd02…` | byte-equal to the host | **green** |

mips serial:
```
FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup
FFW_PLATFORM:BEGIN abi=mips32 evidence=harness-mips-4.19 backend=kernel kernel=4.19.0-21-4kc-malta
FFW_PLATFORM:KERNEL status=PASS
FFW_PLATFORM:CLOCK status=PASS provenance=kernel
FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded
FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd
FFW_PLATFORM:END started=0 refused=entropy:not_seeded
FFW_PLATFORM_STEP_EXIT status=3 stdout_bytes=372 stdout_fnv1a64=e8f28288365874c5
```
powerpc serial:
```
FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup
FFW_PLATFORM:BEGIN abi=powerpc32 evidence=harness-ppc-4.9 backend=kernel kernel=4.9.0-0.bpo.6-powerpc
FFW_PLATFORM:KERNEL status=PASS
FFW_PLATFORM:CLOCK status=PASS provenance=kernel
FFW_PLATFORM:ENTROPY status=PASS provenance=kernel
FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd
FFW_PLATFORM:END started=1
FFW_PLATFORM_STEP_EXIT status=0 stdout_bytes=327 stdout_fnv1a64=d4434d30b079ba67
```
**Mips refused to start, and that is the correct behaviour, not a pass of the positive path.** The 4.19 Malta guest's kernel
entropy pool was not seeded, so the speaker refused (`ENTROPY status=REFUSED provenance=kernel reason=not_seeded`,
`started=0`, exit 3) instead of blocking or inventing entropy. On powerpc every capability passed with kernel provenance and the
speaker started (`started=1`, exit 0).

**Controls** (`--platform-controls`, per guest; each must turn the platform verdict red with exactly its planted error): the BEGIN
line says backend=simulated; the ENTROPY line is missing; CLOCK claims provenance=double; CLOCK says provenance=simulated; the run
stops after CLOCK. All five were red with only their planted error on both guests.

The initramfs images are build products that carry the speaker binary, so they are not committed; the receipt records their
sha256.

**Not shown:** a seeded-entropy start on the mips guest (P02's positive path on BE MIPS), a stock Sonos kernel, real hardware.
