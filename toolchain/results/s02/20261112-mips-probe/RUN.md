# S02: real decoder execution in a generic MIPS guest — 2026-11-12

The final static MIPS probe actually booted as PID 1, decoded the same MP3
fixture three times, compared every output sample with the existing independent
FFmpeg PCM, and rebooted cleanly. Each run produced **24,000 stereo frames /
48,000 samples**, peak error **1 LSB**, squared-error sum **24,103** and RMS
**0.70862249 LSB**. The original limits remain peak <=4 / RMS <=1.5 LSB.
This is generic guest execution, not Sonos hardware or resource qualification.

The binary is **1,477,400 bytes**, ELF32 big-endian MIPS32r2, static and
stripped, soft-float ABI 3 with zero FPU words found in executable sections.
Its SHA-256 is `440c0361d716d959d71fd9d9f0b85c66a371a596386d79664c01b1c7dffcb2b0`.
Disk size is not process RAM, stack, allocator or RSS evidence.

## Exact source and native checks

Baseline `8d415c68f3c73d24f4434b0412da1436372dffb7` plus eight overlays
forms frozen inventory `5faa6fc589e2e41f2a2100fa03ccb715791454afceb2f39687c526514f0b2210`:
1,590 files, of which 1,588 transferred; only the two tracker metadata files
were excluded. Root independently compared every native receipt input's
hash, byte length and executable flag, and checked terminal ACK, returned
status and source/staging/pair release and tree retirement for every final job.

| Final native job | Executed scope | Result |
|---|---|---|
| 30105869848936710 | standalone codec/reporting/shutdown unit tests | 4 passed, 0 failed/ignored/filtered |
| 30105869848936714 | standalone all-target Clippy, `-D warnings` | exit 0 |
| 30105869848936716 | actual speaker `source_runtime_cli` integration target | 2 passed, 0 failed/ignored/filtered |
| 30105869848936718 | static BE-MIPS release cross-build and artifact retrieval | exit 0, actual ELF returned |

One of the two integration tests contains **three** actual process cases;
they are not three extra Rust tests. The repaired host supervisor checked all
24,000 Vorbis frames and 72,000 long-MP3 frames against independent PCM and
exact sample positions/times, plus 16 actual wrong-key authentication
rejections with no captured PCM. Both positive captures peak at 1 LSB with
RMS approximately 0.0458 LSB. Python controls passed **18/18** for the guest
runner and **19/19** for the host supervisor. Synthetic transcripts and the
injected kernel are only unit controls. Earlier repetitions of these tests
are not added to the final denominator. The unrelated 818-test suite was
not replayed for these narrow changes.

The central verifier used `RCH_REQUIRE_REMOTE=1 rch exec`, with local
fallback prohibited. Logical input commands are below; RCH remapped source
and target directories and added its build-directory/source-identity config.
The hashes of the complete actual native logs and executed command strings
are recorded in [source-inputs.json](source-inputs.json).

```sh
cargo +1.99.0 test --locked --offline -j1 \
  --manifest-path toolchain/src/s02-cost/Cargo.toml \
  -- --show-output --test-threads=1
cargo +1.99.0 clippy --locked --offline -j1 \
  --manifest-path toolchain/src/s02-cost/Cargo.toml --all-targets -- -D warnings
cargo +1.99.0 test --locked --offline -j1 -p franken-speaker \
  --test source_runtime_cli -- --show-output --test-threads=1
cargo +nightly-2026-09-21 build --offline --locked --release -j1 \
  --manifest-path toolchain/src/s02-cost/Cargo.toml \
  --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort \
  --config 'target.mips-unknown-linux-musl.linker="toolchain/linker/zig-cc-mips-be"' \
  --config 'target.mips-unknown-linux-musl.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
```

Native host checks used `CARGO_INCREMENTAL=0`, zero profile debug information
and `RUSTFLAGS='-D warnings -C debuginfo=0'`. Cross-build used the pinned
nightly rustc `bba531001d4de6d7f49693e0836a2668ca063282`, rust-src library
lock and Zig 0.14.1. Actual identities are in the JSON. Rustfmt, four touched
Python py_compile checks and git diff --check passed.

The process-custody correction is commit `ea3d04401ec558df3227adb7dae9bed7b92ef2c0`;
the probe is commit `451c49ab224f8e2406257b6e184bafe811987f6b`.
The published README replaces the tested private draft's stale status and
adds actual usage; this documentation-only delta is recorded separately.
All executable source and test inputs match the qualified overlays.

## Actual final QEMU execution

The runner froze the actual retrieved ELF, helper scripts and the full-hash
pinned Debian Malta 4.19 kernel, then built and independently verified an
initramfs with the explicit PID1 opt-in. Kernel SHA-256:
`3803357ef7821dbf691c901105fb9b2b00382abf67fce8a4be2a0d592267dc61`.
QEMU reported **11.1.3**. The command below uses `$RUN` for the retained run
directory; these exact relative asset identities are hash-bound in the JSON.

```sh
qemu-system-mips -M malta -cpu 24Kf -m 64M -nographic -no-reboot -nic none \
  -icount shift=0,align=off,sleep=off \
  -kernel "$RUN/kernel" -initrd "$RUN/initramfs.cpio.gz" \
  -append 'console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3'
```

The external deadline was 180 seconds. QEMU exited zero, stderr was empty,
and the runner exited zero after all three complete PCM records, END and
`[  234.100306] reboot: Restarting system`. The **complete serial stdout** is displayed in [observed.txt](observed.txt)
with CRLF normalized to LF for Git text. The exact original CRLF bytes are
retained as `final_guest.serial_stdout_raw_base64` in the JSON; no validator
consumes the normalized display. The raw SHA-256 is `513ea03ed0623e014b35d58f9053847809f9d20c73629baf4026bd3e86658b3d`.
No binary, kernel or initramfs image is committed.

## Retained failures and limits

The original lock attempt was refused before admission because its estimated
four-slot request could not fit the one-slot worker. Native 36672 then
stopped before payload start with monitor error E330: an opaque shell hid the
Cargo cache path. Supported direct Cargo resolved that envelope issue. The
first generated lock selected smallvec 1.16.5 and was held; an actual offline
update restored approved 1.16.4. All **24/24** registry versions, sources and
checksums now match the repository lock. No global fallback or worker floor
was changed and no canonical Asupersync work was performed.

The first built probe (native 36696) also decoded all three full fixtures
and rebooted, but its runner returned **non-pass**: the restart parser omitted
the kernel's numeric timestamp prefix. That original raw capture and false
result are preserved. The narrow timestamp correction was independently
reviewed with a valid observed prefix and malformed-prefix controls; reanalysis
of the old capture is not another execution. The final guest above is a fresh
boot of the final rebuilt ELF. During development, controls/review also found
and fixed malformed-helper failure receipts, descriptor ownership, descendant
retirement, pre-reap signaling and bounded handling of signal failure.

The first target build's `$at` assembler warning is retained; scoped
push/noat/pop removed it in the final build without changing the intended
counter instruction or sample oracles. The separate warning about an absent
prebuilt target rustlib directory remains in the successful build-std/static
link log. It is not hidden or presented as a warning-free cross-build.

All 32 ruler records are retained as raw observations. **Counter wrap is
unresolved; no qualified instruction count, CPU percentage or real-time budget
is claimed.** Stack, allocator and RSS are unmeasured. No Sonos silicon,
retained old kernel, driver, radio, native provider, tailnet service or physical
audio qualification follows from this result. S02, N07 and Q07 retain their
original unmet acceptance and stay open.
