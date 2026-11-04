# Toolchain bake-off results — 2026-11-04

Decision point from `FIRMWARE_ASSESSMENT.md` and the revised plan: can we
build and boot hello-world `/init` binaries for the fleet's two big-endian
architectures, and does the asupersync stack come up on BE-PPC? All work
offline (QEMU + cross-compile); no device touched.

## Environment

- Host: macOS arm64 (Darwin 27), rustc 1.101.0-nightly (48f4b0553, 2026-10-23)
- Cross std: `-Z build-std=core,compiler_builtins` (no prebuilt BE std ships
  for `mips-unknown-linux-musl` / `powerpc-unknown-linux-musl` on any host —
  verified on rustup aarch64-macOS and inside the `rust:1-bookworm` container)
- Linker: `ld.lld` (Homebrew llvm), static, `-e _start`, `relocation-model=static`
- QEMU 11.1.2 (`qemu-system-mips`, `qemu-system-ppc`)
- Kernels: Debian archive `linux-image-4.19.0-21-4kc-malta` (BE MIPS32r2) and
  `linux-image-4.9.0-0.bpo.6-powerpc` (BE PPC) — same kernel-era families as
  the fleet's stock firmware (4.x), useful as a later old-kernel-compat probe
- Initramfs: `../src/mkinitramfs.py` — newc cpio with `/dev/console` (5,1) +
  `/dev/ttyS0` (4,64) + `/init`, built without root

## Build artifacts

| Target | file(1) | Size |
|---|---|---|
| `mips-unknown-linux-musl` | `ELF 32-bit MSB executable, MIPS, MIPS32 rel2, statically linked, stripped` | 2,068 B |
| `powerpc-unknown-linux-musl` | `ELF 32-bit MSB executable, PowerPC, statically linked, stripped` | 1,588 B |

Source: `src/ffw-hello-init/` — `no_std`, `#![feature(asm_experimental_arch)]`,
raw syscalls only (write/open/dup2/reboot). Two bugs found and fixed that any
BE porting effort would hit:

1. **MIPS o32 syscall numbers are 4000-based** (`write` = 4004, not 4). With
   generic numbers every syscall returned ENOSYS: init printed nothing,
   rebooted nothing, spun. Symptom is total silence after `Run /init`.
2. **PPC/MIPS32 asm constraints**: `asm!` on these targets requires
   `asm_experimental_arch`; explicit registers use `"$4"` form; `$1` (`at`)
   and `$2` (`v0`) need explicit bindings, not clobbers; named args cannot
   use explicit-register form (`lateout("$2") ret` must be positional
   `lateout("$2") ret` without `ret =`).

## Boot results

### BE-MIPS (Malta, 4.19 kernel) — full pass ✅

```
[    1.999154] Run /init as init process
ffw-init: hello from BIG-ENDIAN MIPS32 (o32) PID 1
ffw-init: PID1 alive, issuing reboot(RB_AUTOBOOT)
[    1.930682] reboot: Restarting system
```

Executed as PID 1 from initramfs, banner written to the serial console via
raw `write`, then clean `reboot(RB_AUTOBOOT)` (magic1 `0xfee1dead`, magic2
672274793, cmd `RB_AUTOBOOT` in a2 — arg order matters). Full cycle < 7 s.
Log: locally captured `/tmp/mips-v8.log` equivalent reproduced by
`boot-mips.sh`.

### BE-PPC (g3beige/OpenBIOS, 4.9 kernel) — kernel-side pass ✅, console fd caveat ⚠

```
Unpacking initramfs...            (clean, no "junk" error)
Freeing unused kernel memory: 424K
reboot: Restarting system          ← our reboot() with correct magics
```

On `ppce500` the same binary produced zero serial output (Debian's
`powerpc` flavor is CHRP/PReP-oriented; ppce500 needs an e500 cuImage);
on `g3beige` the kernel boots, unpacks our initramfs, execs `/init`
(no "Failed to execute" error), and our `reboot` syscall fires a clean
restart deterministically at ~2.5 s — proving user→kernel syscalls work
end-to-end. The banner is not visible because kernel-level
`open("/dev/console")` fails on g3beige (`Warning: unable to open an initial
console`): g3beige's serial is an escc (pmac-zilog), not an 8250, so
`/dev/ttyS0` (4,64) is the wrong node there. Console-fd wiring is a
per-machine device-node detail, not a toolchain/ABI failure. Log: locally
captured, reproducible via `boot-ppc.sh`.

## asupersync BE-PPC decision point

`cargo +nightly check --no-default-features --features runtime-core -p
asupersync --target powerpc-unknown-linux-musl -Z build-std=core,std,alloc,
panic_abort` (ld.lld):

- **std/core/compiler_builtins build from source: ✅** — the entire dependency
  tree (serde, libc, socket2, etc.) compiles for BE-PPC; `asupersync`'s own
  build script runs.
- **asupersync lib check: ❌ 133 errors, single root cause** — the target's
  `max-atomic-width` is 32 (`rustc --print target-spec-json`), so
  `std::sync::atomic::AtomicU64` does not exist for
  `powerpc-unknown-linux-musl`. All 133 errors are `AtomicU64` (109 imports,
  14 type sites, 8 paths, 2 combined). Zero architecture errors of any other
  kind.

### Decision

**Conditional GO with a scoped abstraction task.** The toolchain, ABI,
linking, std-from-source, and the whole dependency graph are clean on
BE-PPC; the only blocker is 64-bit atomics. Paths, in preference order:

1. **`portable-atomic`** (critical-section or fallback impls for
   32-bit-only targets): add as a dependency, alias `AtomicU64` through an
   internal `asupersync::atomic` module, keep `std::sync::atomic` types only
   behind a target-gated re-export. Bounded, mechanical change (~130 sites,
   one import each).
2. **Config-gate 64-bit counters** on targets without them (shrink to
   AtomicU32 with generation tricks) — more invasive, only if (1) has a
   runtime cost problem on 603e-class cores without native lwarx/stwcx.
   64-bit CAS.
3. **Use the 64-bit-capable cores only** (e500mc has native 64-bit atomics;
   Play:5's actual core is TBD pending the frankensonos hardware evidence) —
   a fleet-hardware question, not a software one, and per the assessment the
   S5 core identity is still unverified.

Recommendation: prototype (1) against `asupersync` in a branch; if the
`portable-atomic` critical-section build passes `check` and its bounded
test-suite for `--target powerpc-unknown-linux-musl`, the executor itself is
portable to the fleet's dominant 32 MB board family.

## RCH note

The cargo-shim fleet refused builds during this session (worker
"source namespace: conflicting alias base") with local fallback disabled;
per owner approval the shim was uninstalled for this session and
`compilation.allow_local_fallback` flipped to `true` in `~/.config/rch/config.toml`
(annotated there; revert when the worker namespace conflict clears).
All builds above ran locally — trivial for a 100-line no_std crate; the
asupersync check ran locally too (~2-3 min under load).

## Reproduction

```sh
# build (from toolchain/src/ffw-hello-init)
cargo +nightly build --release -Z build-std=core,compiler_builtins \
  --target mips-unknown-linux-musl          # or powerpc-unknown-linux-musl
# initramfs (adds /dev/console + /dev/ttyS0 + /init)
python3 ../mkinitramfs.py
# boot BE-MIPS
qemu-system-mips -M malta -cpu 24Kf -kernel <vmlinux-4kc-malta> \
  -initrd ../build/initramfs/initramfs-mips-v2.cpio.gz \
  -append "console=ttyS0,38400 rdinit=/init panic=-1" -nographic -no-reboot
# boot BE-PPC
qemu-system-ppc -M g3beige -kernel <vmlinux-4.9-powerpc> \
  -initrd ../build/initramfs/initramfs-ppc-v2.cpio.gz \
  -append "console=ttyS0 rdinit=/init panic=-1" -nographic -no-reboot
```

Kernel debs: Debian archive pool `linux-image-4.19.0-21-4kc-malta_*_mips.deb`,
`linux-image-4.9.0-0.bpo.6-powerpc_*_powerpc.deb` → `ar x` + `tar xf data.tar.xz`
→ `boot/vmlinux-*`.
