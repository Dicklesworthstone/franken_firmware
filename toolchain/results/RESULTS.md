# Toolchain bake-off & verification results — 2026-11-04

Decision point from `FIRMWARE_ASSESSMENT.md` and the revised plan: can we
build and boot `/init` binaries for the fleet's two big-endian architectures
with zero initramfs corruption, full userspace serial output, verified kernel
ABI capabilities, and a compiling `asupersync` + `franken-kernel` stack on both
`powerpc-unknown-linux-musl` and `mips-unknown-linux-musl`? All work offline
(QEMU + cross-compile); no device touched.

## Environment

- Host: macOS arm64 (Darwin 27), rustc 1.101.0-nightly (48f4b0553, 2026-10-23)
- Cross std: `-Z build-std=core,compiler_builtins` for `no_std` PID 1 (`ffw-hello-init`),
  and `-Z build-std=core,alloc,std,panic_abort` for `asupersync` + `franken-kernel`
- Linker: `ld.lld` (Homebrew llvm), static, `-e _start`, `relocation-model=static`
- QEMU 11.1.2 (`qemu-system-mips`, `qemu-system-ppc`)
- Kernels: Debian archive `linux-image-4.19.0-21-4kc-malta` (BE MIPS32r2) and
  `linux-image-4.9.0-0.bpo.6-powerpc` (BE PPC)
- Initramfs: `../src/mkinitramfs.py` — deterministic `newc` cpio (`mtime=0`)
  with independent structural verifier (`parse_cpio_bytes` / `verify_initramfs_bytes`),
  4x4 alignment self-test (`python3 toolchain/src/mkinitramfs.py --self-test`),
  and device nodes `/dev/console` (5,1), `/dev/ttyS0` (4,64), `/dev/ttyPZ0` (204,192),
  `/dev/null` (1,3), `/dev/zero` (1,5), `/dev/urandom` (1,9), plus `/init` (mode `0755`).

## Build artifacts (`ffw-hello-init`)

| Target | file(1) | Size | Initramfs (`.cpio.gz`) |
|---|---|---|---|
| `mips-unknown-linux-musl` | `ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, stripped` | 6,412 B | 2,000 B |
| `powerpc-unknown-linux-musl` | `ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), statically linked, stripped` | 5,092 B | 1,923 B |

Source: `src/ffw-hello-init/` — `no_std`, `#![feature(asm_experimental_arch)]`,
raw syscalls + negative/positive errno tests + 7 kernel ABI capability probes.
Five critical ABI and packaging bugs were identified and fixed (`E07` / `E03`):

1. **MIPS o32 syscall numbers are 4000-based** (`write` = 4004, not 4).
2. **`mkinitramfs.py` major/minor tuple bug**: `os.major(dev[0]), os.minor(dev[0])`
   previously turned `dev=(5, 1)` into `(0, 5)`, causing the kernel's initial
   `open("/dev/console")` to fail (`Warning: unable to open an initial console`).
   Fixed via `normalize_dev_tuple(dev)` and verified by `verify_initramfs_bytes`.
3. **PowerPC `g3beige` serial console device node**: `g3beige` uses `pmac_zilog`
   (`ttyPZ0`, major 204, minor 192) rather than 8250 (`ttyS0`). Adding `/dev/ttyPZ0`
   (204,192) and passing `console=ttyPZ0,38400` in `boot-ppc.sh` enabled full
   userspace serial output on BE-PPC.
4. **PowerPC32 SVR4 `sc` register clobbers**: Linux PowerPC `sc` clobbers `r4`..`r12`,
   `cr0`, `ctr`, and `xer`. Declaring `r4`..`r7` as `inlateout` (and `cr0`, `ctr`, `xer`
   as `lateout`) prevents LLVM from reusing clobbered registers across loop iterations.
5. **MIPS O32 `syscall` error flag (`$7`/`a3`) and `$1` (`$at`) clobber**: Linux MIPS
   sets `$7 != 0` on error with positive `errno` in `$2`, and the kernel clobbers `$1`
   (`$at`) during `syscall`. `sys_raw5` now saves/restores `$1` at `20($29)` around
   `syscall` and negates `$2` when `$7 != 0`.

## Boot & Kernel ABI Probe Results (`E07` + `E03`)

Pre-repair baseline logs are preserved at `baseline-pre-e07-mips-serial.log` and
`baseline-pre-e07-ppc-serial.log`. Full machine-readable verification receipt is
committed at `e07-e03-verification-receipt.json`.

### BE-MIPS (`Malta`, 4.19.0-21-4kc-malta) — Full Pass ✅ (`boot-mips-serial.log`)

```
[    1.213030] Unpacking initramfs...
[    1.221141] Freeing initrd memory: 12K
[    1.805820] Run /init as init process
FFW_MARKER:USERSPACE_START arch=mips-be
ffw-init: hello from BIG-ENDIAN MIPS32 (o32) PID 1
FFW_KERNEL_VERSION: Linux version 4.19.0-21-4kc-malta (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 Debian 4.19.249-2 (2022-06-30)
FFW_SYSCALL_TEST:ERR_ENOENT status=PASS
FFW_SYSCALL_TEST:ERR_EBADF status=PASS
FFW_SYSCALL_TEST:ERR_ENOSYS status=PASS
FFW_SYSCALL_TEST:POS_FD_SHORT_WRITE status=PASS
FFW_ABI_PROBE:CLOCK_MONOTONIC status=PASS
FFW_ABI_PROBE:NONBLOCK_PIPE status=PASS
FFW_ABI_PROBE:POLL status=PASS
FFW_ABI_PROBE:EPOLL status=PASS
FFW_ABI_PROBE:SOCKET_UDP status=PASS
FFW_ABI_PROBE:ENTROPY status=PASS
FFW_ABI_PROBE:ATOMICS_32 status=PASS
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
[    1.815235] reboot: Restarting system
```

- Zero initramfs unpack errors, zero console warnings, 11/11 syscall + ABI probes PASS,
  clean `reboot(RB_AUTOBOOT)` exit in 4.17s.

### BE-PPC (`g3beige`, 4.9.0-0.bpo.6-powerpc) — Full Pass ✅ (`boot-ppc-serial.log`)

```
[    0.665604] Unpacking initramfs...
[    0.669967] Freeing initrd memory: 4K (c1ff2000 - c1ff3000)
FFW_MARKER:USERSPACE_START arch=powerpc-be
ffw-init: hello from BIG-ENDIAN PowerPC32 PID 1
FFW_KERNEL_VERSION: Linux version 4.9.0-0.bpo.6-powerpc (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 Debian 4.9.88-1+deb9u1~bpo8+1 (2018-05-13)
FFW_SYSCALL_TEST:ERR_ENOENT status=PASS
FFW_SYSCALL_TEST:ERR_EBADF status=PASS
FFW_SYSCALL_TEST:ERR_ENOSYS status=PASS
FFW_SYSCALL_TEST:POS_FD_SHORT_WRITE status=PASS
FFW_ABI_PROBE:CLOCK_MONOTONIC status=PASS
FFW_ABI_PROBE:NONBLOCK_PIPE status=PASS
FFW_ABI_PROBE:POLL status=PASS
FFW_ABI_PROBE:EPOLL status=PASS
FFW_ABI_PROBE:SOCKET_UDP status=PASS
FFW_ABI_PROBE:ENTROPY status=PASS
FFW_ABI_PROBE:ATOMICS_32 status=PASS
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
[    1.812423] reboot: Restarting system
```

- Zero initramfs unpack errors, zero `unable to open an initial console` warnings,
  full userspace serial output on `ttyPZ0`, 11/11 syscall + ABI probes PASS,
  clean `reboot(RB_AUTOBOOT)` exit in 3.72s.

## `asupersync` + `franken-kernel` 32-Bit Big-Endian Port (`P05` + `P06`) — Full Pass ✅

- **Baseline (`ddda2bf82cc8b3f3946c63f2ffc44177a4e34824`):**
  `cargo +nightly check --no-default-features --lib -p asupersync --target powerpc-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort`
  failed with **133 errors** (`std::sync::atomic::AtomicU64` missing on 32-bit PPC/MIPS where `max-atomic-width = 32`).
- **Fix Implemented in `asupersync`:**
  1. Added `portable-atomic = { version = "1.15.0", default-features = false, features = ["fallback"] }` to `asupersync/Cargo.toml`.
  2. Created `asupersync/src/sync/atomic.rs` re-exporting `core::sync::atomic::{AtomicU64, AtomicI64}` when `#[cfg(target_has_atomic = "64")]` and `portable_atomic::{AtomicU64, AtomicI64}` when `#[cfg(not(target_has_atomic = "64"))]`.
  3. Migrated all 64-bit atomic call sites in `asupersync/src/` to `crate::sync::atomic` and replaced 5 unstable `.try_update(...)` calls with stable `.fetch_update(...)`.
- **Verification Results:**
  - `cargo +nightly check --manifest-path /Users/jemanuel/projects/asupersync/Cargo.toml --no-default-features --lib --config build.incremental=false --target powerpc-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort`:
    **0 errors** (compiled `franken-kernel v0.6.0`, `franken-evidence v0.6.0`, `franken-decision v0.6.0`, `asupersync v0.6.2`).
  - `cargo +nightly check --manifest-path /Users/jemanuel/projects/asupersync/Cargo.toml --no-default-features --lib --config build.incremental=false --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort`:
    **0 errors** (compiled `franken-kernel v0.6.0`, `franken-evidence v0.6.0`, `franken-decision v0.6.0`, `asupersync v0.6.2`).

## Reproduction

```sh
# 1. Run mkinitramfs structural + negative-oracle self-tests
python3 toolchain/src/mkinitramfs.py --self-test

# 2. Run full build + initramfs verification + QEMU BE-MIPS & BE-PPC boot harness
python3 toolchain/src/run-qemu-verification.py
```
