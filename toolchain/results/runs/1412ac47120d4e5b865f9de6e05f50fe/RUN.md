# E07/E03 central QEMU run 1412ac47, 2026-11-05

This re-run exists to bind the complete source tree in the receipt. Run
`f0a91e7b` had a gap: its `build_manifest.sources_sha256` hashed only
`src/*.rs`. The runner now hashes every file under `src/` recursively and
refuses symlinked or unreadable directories. This receipt lists 12 sources,
including `src/e03_probes/net.rs` and `src/e03_judge/net.rs`.

**Scope:** freestanding raw-syscall PID-1 probes on Debian QEMU kernels
(Malta/24Kf/Linux 4.19 and g3beige/G3/Linux 4.9). This is **not**
musl/std/Asupersync, a stock Sonos kernel, the audio driver, or speaker
qualification. No physical device or provider service was contacted.

## Command

Run from the repository root at HEAD `e073c2a`. The guest crate equalled HEAD,
and the runner and its tests were the versions committed with this run.
`FFW_BUILD_DIR` selected the local kernel cache; that machine-specific path is
deliberately not recorded.

```sh
RCH_WORKER=ts1,hz3,hz4 python3 toolchain/src/run-qemu-verification.py \
  --timeout 60 --jobs 2 --target-dir build/hello-init-target
```

The runner built both guests itself with strict RCH (`RCH_REQUIRE_REMOTE=1`,
`-j 2`), so `sources_bound_to_binary` is true.

## Results (see `e07-e03-verification-receipt.json`)

| guest | kernel sha256 | binary = booted init | probes | QEMU |
|---|---|---|---|---|
| mips | `3803357e…` | `37652d88…` | 29 PASS, `GETRANDOM` UNSEEDED | exit 0 |
| ppc | `289f40b6…` | `75ef9b04…` | 30 PASS | exit 0 |

- The markers are in order, with no validation errors, no missing markers and
  no forbidden hits.
- Both binaries and both initramfs archives are **byte-identical** to run
  `f0a91e7b`. The rebuild from the same sources and toolchain
  (`rustc 1.101.0-nightly 708c94ef0`) reproduced exactly.

`boot-*-stdout.bin` and `boot-*-stderr.bin` preserve the exact captured bytes,
and `boot-*-serial.log` is the parser view of them. The initramfs archives are
reproducible build products and are not committed.
