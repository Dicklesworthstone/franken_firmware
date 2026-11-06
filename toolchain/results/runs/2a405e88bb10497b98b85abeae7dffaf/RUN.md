# P02 explicit legacy entropy provider, bound central QEMU run 2a405e88, 2026-11-06

**Scope.** This run covers:
- the device speaker's platform startup with the **explicitly selected legacy provider**
  (`/franken-speaker --platform-startup --entropy-provider=legacy-dev-random-test-environment`, a nonblocking `/dev/random` read
  that is admitted only in a test environment);
- its board catalog (`--catalog`).

Both ran under Debian QEMU kernels: Malta/24Kf/Linux 4.19 and g3beige/G3/Linux 4.9. This is not a stock Sonos kernel, the audio
driver, or a physical device. No device or provider service was contacted.

## Inputs
- **Tree.** `git archive d583a09` plus four patches, applied in this order with `patch -p1 --fuzz=0`:
  1. DarkPeak's provider runner, judge and guest slice v2 (sha256 `2c9a765d…`);
  2. YellowBrook's `p02.md` text (`866d7ecc…`);
  3. DarkPeak's admission gate v3 (`7ba23539…`);
  4. YellowBrook's receipt delta (`2ef3409d…`).

  None of the stack's files changed between `d583a09` and the commit that adds this record. The committed files are byte-equal to
  the booted tree with one exception, made at landing: `toolchain/tests/test_platform_smoke.py`. In it, one literal input of a
  redaction test changed from `10.1.2.3` to the RFC 5737 documentation address `192.0.2.10`, so that no non-documentation address
  sits in this public repository. Both are dotted addresses the receipt must replace with `unrecognized`, and the assertion is
  unchanged. The runner, the judge and the guest are byte-equal.
- **Speakers.** The device `franken-speaker` ELFs from the central P01 run at `342975861657` (receipt
  `toolchain/results/p01/rev-342975861657/`): mips sha256 `93755bbf2ee1bdb1…`, powerpc `572352947936cece…`.
- **Host catalog.** What the host speaker printed centrally, taken verbatim (sha256 `69c2e38da2ea10c8…`, 10006 bytes). The runner
  compares it byte for byte with each device speaker's serial output.

## Command
From the snapshot root; `<...>` stands for local paths, which are not recorded:
```sh
FFW_BUILD_DIR=<kernel cache> RCH_WORKER=trj RCH_REQUIRE_REMOTE=1 RCH_DISABLE_TARGET_REUSE=1 \
  python3 toolchain/src/run-qemu-verification.py --timeout 60 --jobs 2 \
  --speaker-mips <mips franken-speaker> --speaker-ppc <powerpc franken-speaker> \
  --speaker-host-catalog host-catalog.json --speaker-platform \
  --entropy-provider legacy-dev-random-test-environment --platform-controls --target-dir <snapshot>/build/p02-provider-target-pvB1
```

**How the guests were built.** The runner built both guests itself on worker `trj`:
```sh
rch exec --source-content-receipt -- cargo +nightly build --release --target <T> -Z build-std=core,panic_abort \
  --features speaker-smoke,speaker-platform,speaker-platform-legacy-test-env -j 2
```
These were RCH builds 30096834294711764 and 30096834294711775.
- **Admission gate (v3).** Before each build the gate took a fresh capacity sample (`rch workers capabilities --refresh --json`) and
  got a positive native admission (`rch admit --json -- <that argv>`) on the first try:
  - mips: `offload` / `observed` / `success`;
  - powerpc: `offload` / `observed` / `affinity_pinned`;
  - worker `trj` for both.

  The gate passes the refresh call's stderr through and does not record its exit code. This run's log carries no stderr from either
  refresh call.
- **Central clippy.** The guest Rust is byte-identical to what was checked earlier on `trj`, with `-D warnings`, exit 0 and no
  diagnostics:
  ```sh
  cargo +nightly clippy --release --target <T> -Z build-std=core,panic_abort [--features speaker-smoke,speaker-platform,speaker-platform-legacy-test-env] -j 2 -- -D warnings
  ```
  This covered mips and powerpc with the features, and mips without them.
- `rustfmt --edition 2021 --check` is clean on the guest source.

## Results (`e07-e03-verification-receipt.json`, status `PASS`)
| guest | kernel | guest init sha256 | catalog | platform verdict |
|---|---|---|---|---|
| mips | `3803357e…` 4.19 malta | `d47bfc7a…` | byte-equal to the host | **green** |
| powerpc | `289f40b6…` 4.9 g3beige | `4cc5b366…` | byte-equal to the host | **degraded** |

mips serial:
```
FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup --entropy-provider=legacy-dev-random-test-environment
FFW_PLATFORM:BEGIN abi=mips32 evidence=harness-mips-4.19 backend=kernel kernel=4.19.0-21-4kc-malta
FFW_PLATFORM:KERNEL status=PASS
FFW_PLATFORM:CLOCK status=PASS provenance=kernel
FFW_PLATFORM:ENTROPY status=PASS provenance=kernel provider=legacy_dev_random_test_environment
FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd
FFW_PLATFORM:END started=1
FFW_PLATFORM_STEP_EXIT status=0 stdout_bytes=368 stdout_fnv1a64=029c2cefeaac890e
```
powerpc serial:
```
FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup --entropy-provider=legacy-dev-random-test-environment
FFW_PLATFORM:BEGIN abi=powerpc32 evidence=harness-ppc-4.9 backend=kernel kernel=4.9.0-0.bpo.6-powerpc
FFW_PLATFORM:KERNEL status=PASS
FFW_PLATFORM:CLOCK status=PASS provenance=kernel
FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel provider=legacy_dev_random_test_environment reason=not_seeded
FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd
FFW_PLATFORM:END started=0 refused=entropy:not_seeded
FFW_PLATFORM_STEP_EXIT status=3 stdout_bytes=419 stdout_fnv1a64=c77711b2429bfbcc
```
**On mips the legacy provider read the kernel's `/dev/random` and the speaker started** (`ENTROPY status=PASS provenance=kernel
provider=legacy_dev_random_test_environment`, `started=1`, exit 0). This is one observation of the real adapter on that guest's kernel.

**On powerpc the speaker refused to start.** That is the provider's designed refusal, not a pass of the positive path: the pool had
nothing to give (`reason=not_seeded`), and the speaker neither blocked nor invented entropy. `p02.md` reports this as `degraded`,
neither green nor red, because one run per guest does not show that the pool stays unseeded.

The same two kernels gave the opposite split in run 570cd370 (default provider: mips degraded, powerpc green). Whether a guest's pool
is seeded at that point of boot is not stable from run to run, and neither run is evidence about a device.

**Controls** (`--platform-controls`). There are 8 per guest, and each must turn the platform verdict red with exactly its planted
error:
- the BEGIN line says backend=simulated;
- the ENTROPY line is missing;
- CLOCK claims provenance=double;
- CLOCK says provenance=simulated;
- ENTROPY has no `provider=` token (the default provider ran);
- ENTROPY names the evidence-qualified `legacy_dev_random` when the test environment was selected;
- ENTROPY names `urandom`, which is not a provider;
- the run stops after CLOCK.

All 8 were red with only their planted error, on both guests.

The initramfs images are build products that carry the speaker binary, so they are not committed; the receipt records their sha256.

**Not shown:**
- a seeded start on the powerpc guest with this provider;
- the exit code of either capability refresh (the gate does not record it);
- a stock Sonos kernel;
- real hardware.
