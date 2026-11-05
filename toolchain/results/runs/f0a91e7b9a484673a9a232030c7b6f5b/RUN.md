# E07/E03 central QEMU run f0a91e7b, 2026-11-05

Both guests passed. **Scope:** freestanding raw-syscall PID-1 probes on Debian
QEMU kernels (Malta/24Kf/Linux 4.19 and g3beige/G3/Linux 4.9). This is **not**
musl/std/Asupersync, a stock Sonos kernel, the audio driver, or speaker
qualification. No physical device or provider service was contacted.

## Command

From the repository root at HEAD `2a3cd9e`, with the guest crate sources listed
below in the working tree. `FFW_BUILD_DIR` explicitly selected the local kernel
cache, which is deliberately not recorded as a machine-specific path.

```sh
RCH_WORKER=ts1,hz3,hz4 python3 toolchain/src/run-qemu-verification.py \
  --timeout 60 --jobs 2 --target-dir build/hello-init-target
```

The runner built both guests itself (`sources_bound_to_binary: true`):
`rch exec --source-content-receipt -- cargo +nightly build --release --target <T> -Z build-std=core,panic_abort -j 2`,
with `RCH_REQUIRE_REMOTE=1`. Both builds ran on worker `ts1`, and each exited 0.
Each RCH source-content receipt covers all 12 crate files. `ts1` was pinned with
the other two workers because a guest `-Z build-std` build needs nightly rust-src,
and `-j 2` is required because RCH admits jobs against a worker's slot count.

## Results (see `e07-e03-verification-receipt.json`)

| guest | kernel sha256 | binary = booted init | probes | markers | QEMU |
|---|---|---|---|---|---|
| mips | `3803357e…` 4.19.0-21-4kc-malta | `37652d88…` | 29 PASS, `GETRANDOM` UNSEEDED (rc=-11) | in order, 0 errors | exit 0, 4.9 s |
| ppc | `289f40b6…` 4.9.0-0.bpo.6-powerpc | `75ef9b04…` | 30 PASS | in order, 0 errors | exit 0, 4.6 s |

- **Threads and TLS:** `THREADS` got a real child tid, and `TLS` read back the
  `CLONE_SETTLS` value `0x12345678` (305419896) on both ISAs.
- **Signals:** `EINTR_READ` returned `-EINTR` (-4), which is a genuine
  interruption, not the bounded wake-up byte.
- **Network:** `ACCEPT4`, `UDP_LOOPBACK` and `LOOPBACK_UP` passed on direct
  socket syscalls.
- **Unseeded entropy:** MIPS `GETRANDOM` is UNSEEDED because the entropy pool is
  not yet initialised at about 2 s into this guest's boot. This is an observed
  property of this guest, not a pass.

## Coverage gap: runner source digests

The receipt's `build_manifest.sources_sha256` lists only `src/*.rs`. It **omits**
the two subdirectory modules. Those two files are bound here instead, by the RCH
source-content receipts and a pre-run digest:

- `src/e03_probes/net.rs` `840d7713c36efd3606256c301a4a95be6ef072af71314511a843fde51a84b352`
- `src/e03_judge/net.rs` `84a677b24a1dc88145eb32d12dd8502fc3c9b91b88dd41db0ffb31d193dc74f5`

The runner fix is tracked in E07.

`boot-*-stdout.bin` and `boot-*-stderr.bin` preserve the exact captured bytes.
`boot-*-serial.log` is the parser view of those bytes. The initramfs archives
are reproducible build products and are not committed.
