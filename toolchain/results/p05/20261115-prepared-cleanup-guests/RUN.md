# Immutable prepared-cleanup consumer: big-endian generic guests

The existing recorder completed three actual full-system QEMU runs: MIPS32 big-endian at 64 MiB and
32 MiB, and PowerPC32 big-endian at 64 MiB. Each retained transcript reports
30 successful operations, 12 single-thread census observations, zero failed,
unsupported, partial or unknown operations, and all eight existing runtime
and supervisor/capture gates passed. QEMU exited naturally with code 0;
serial and stderr bytes match each receipt. These are generic guests, not
Sonos devices or a production speaker workload.

The twelve existing `/proc` census rows per run also expose these observed
process-memory values (Linux reports these fields in KiB):

| Generic guest | Maximum sampled `VmRSS` | Maximum observed `VmHWM` |
| --- | ---: | ---: |
| MIPS / 4.19 / 32 MiB | 2,688 KiB | 2,892 KiB |
| MIPS / 4.19 / 64 MiB | 2,684 KiB | 2,892 KiB |
| PPC / 4.9 / 64 MiB | 2,308 KiB | 2,512 KiB |
| PPC / 3.16 / 32 MiB, distinct run below | 2,308 KiB | 2,512 KiB |

These are measurements of this short runtime probe through its census points.
`VmHWM` is the kernel's process resident high-water field, not a separate
heap/stack allocation census or a worst-case production bound. The probe has
no decoder, native service session, retained audio driver or active speaker
render workload. These numbers cannot allocate a production RAM budget.

The experimental probe selects immutable Asupersync
`1a144aa5696f600665e083df601ae4974f6950b5` with default features disabled and
`slim-runtime-profile` explicitly selected; the resolved Asupersync features
are `native-runtime`, `runtime-core` and `slim-runtime-profile`. Asupersync
`proc-macros` and `test-internals` are disabled; ordinary transitive derive
macro crates remain. Firmware source export is the named 4825c0b
candidate; production speaker dependency remains 36141e21. The original
receipt file lists, not the revision label alone, bind the exported inputs.

## Source and artifact review

MIPS job 30109207290184222 and PPC job 30109207290184223 have exit-zero,
strict-remote terminal acknowledgements and released source/tree/pair custody.
Both original outer receipt digests and every nested content-root digest were
recomputed using the existing RCH serialization order. All 1,722 listed files
were compared by SHA-256, byte count and executable bit against the immutable
export. Both builds have identical file entries, listed in source-inputs.sha256.
Their content-root digests differ because receipts also bind job-specific paths.
Public build-*.json records original receipt/content roots, command hashes,
source counts and custody observations. These are reduced observations, not
new signed receipts; original digests do not hash the redacted JSON.

The actual returned ELF bytes match the ELF hash inside each guest archive and
runtime receipt. Historical supervisor ELF bytes were independently rehashed;
the kernel snapshots and compressed initramfs were also rehashed against each
execution receipt. file.txt records the actual returned ELF format; the live
QEMU version matched recorded QEMU 11.1.3. This is an operational source/build/
artifact chain, not a cryptographic compiler attestation. No binary is included.

## Commands

build-mips.txt and build-ppc.txt contain the exact recorded caller Cargo command.
Run those commands through strict RCH from the intended immutable source root;
relative linker paths deliberately resolve in that synchronized root. For example:

```sh
cd "$SOURCE_EXPORT"
RCH_REQUIRE_REMOTE=1 RCH_ALLOW_FOREIGN_ARTIFACTS=1 \
  RCH_CANONICAL_PROJECT_ROOT="$PWD" rch exec --source-content-receipt --json -- \
  env CARGO_INCREMENTAL=0 cargo +nightly-2026-08-31 build \
  --release --locked --offline -j1 \
  --manifest-path toolchain/src/p05-runtime/Cargo.toml \
  --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort \
  --config 'target.mips-unknown-linux-musl.linker="toolchain/linker/zig-cc-mips-be"' \
  --config 'target.mips-unknown-linux-musl.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
```

For PPC use target powerpc-unknown-linux-musl and linker zig-cc-powerpc-be,
with both target configuration keys changed accordingly. Linker wrappers require
Zig 0.14.1; this is static-musl linkage with build-std, not cargo-check evidence.
RCH_ALLOW_FOREIGN_ARTIFACTS permits return of a foreign ELF, never local builds.
Worker selection, disk admission and source-topology setup remain operator
prerequisites; a refusal is not a completed build.

The existing guest entrypoint (no compilation) is:

```sh
FFW_BUILD_DIR="$KERNEL_CACHE" scripts/e2e/p05 --runtime run \
  --arch mips --profile caller-driven --elf "$RUNTIME_ELF" \
  --supervisor "$SUPERVISOR_ELF" --receipt "$RUN/receipt.json" \
  --log-dir "$RUN/capture" --revision 4825c0b-asup1a144aa \
  --timeout 600 --guest-memory-mib 64
```

Use --arch powerpc for PPC, and --guest-memory-mib 32 for the recorded second
MIPS run. RUN must be new; the recorder creates outputs exclusively. The MIPS
kernel cache filename is kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta; PPC is
kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc. Match hashes in each receipt.
Each subdirectory contains the actual QEMU argv with only capture-directory
paths normalized to $CAPTURE. The supervisor child slot is /franken-speaker
--catalog; the packed caller-driven marker selects this runtime profile. It is
not runtime-as-PID1. NICs are disabled; guest loopback remains available.

All three captures use the existing bounded recorder (600 seconds, shared
1,048,576-byte output cap). A runtime END alone never terminates the guest or
earns a capture pass. The raw serial and empty stderr files are retained.
Normalized receipt path substitutions are identified explicitly; stdout hashes
remain hashes of unmodified raw bytes. --revision is an operator label only.

## Failed predecessors and limits

The first PPC attempt (v1), job 30109207290184208, failed linking with exit
101: its host-absolute linker path did not exist remotely. The first MIPS
attempt (v1) was cancelled before admission with exit130 and no native job.
The second MIPS attempt (v2), native job 30109207290184209, originally reported
`disk_budget_exceeded`, remote exit137 and fail-closed without local fallback.
Later same-ID recovery reported exit120, terminal acknowledgement and
cancellation-unconfirmed. These are distinct original/recovery observations;
neither establishes a native compiler pass or a diagnosed compiler failure.
PPC v2 and both architectures' v3 attempts were refused without an established
terminal build result. Both v3 logs explicitly reported the selected manifest
outside configured source topology and refused acknowledgement without an
observed command exit. MIPS v2 is the native disk-budget attempt above, not
one of these subsequent pre-execution refusals.

These failed/cancelled/refused attempts are not overwritten by the later
successful v4 jobs. The corrected commands used relative linker paths and a
correctly configured immutable export; no assertions, markers or guest memory
thresholds were relaxed.

The older Linux 4.9 PPC/32 MiB pre-userspace timeout remains a failure. The
separate historical Debian 3.16/OpenBIOS 32 MiB success used an older runtime;
it does not qualify this candidate. A separate, explicitly predeclared PPC32 experiment is recorded below.
MIPS32 success means this short probe ran in that emulated physical-memory
configuration; it does not establish production stack, heap, fragmentation,
reserved-driver, codec or network-buffer ceilings. Observed census samples
are not continuous allocation or thread bounds.

Prepared cleanup is registered while the ordinary task quota is occupied and
is executed after normal tasks drain. This is not concurrent cleanup polling
with an occupied task slot, an allocation-free activation guarantee, or
recoverable allocator-abort proof. The candidate excludes newer upstream
synchronization fixes; production advancement must select and requalify them.
Stock kernels, physical drivers/DMA, audio, provider integrations and original
P05/P03 completion remain unqualified. No bead is closed by this bundle.


## Distinct candidate PPC32 / Debian 3.16 / explicit OpenBIOS run

After the three runs above, one authorized experiment used the exact same new
PPC candidate ELF, supervisor and packed initramfs as powerpc-64m. The kernel
was explicitly Debian 3.16.56, with the separately hashed current OpenBIOS blob;
no file was substituted under the 4.9 cache filename. Frozen private input
copies and a predeclared command preceded execution. Existing capture_guest
ran once with timeout600s, cap1MiB and NICnone. It completed naturally in
4.200 seconds, return code0, no stop reason, zero stderr. Input hashes remained
unchanged before/after; checker helper hashes also matched after analysis.

The separate existing analyze-runtime invocation returned0 with all SEVEN
analysis gates passed. No eighth capture gate is fabricated: execution.json
records actual capture and bytes; analysis.json remains supplied-transcript
analysis. Serial reports30 operations successful and12 single-thread census
samples, including the new prepared-cleanup markers. Raw optional GETRANDOM
ENOSYS/FAIL remains preserved as the existing supervisor permits it.

```sh
qemu-system-ppc -M g3beige -cpu G3 -m 32M -nographic -no-reboot -nic none \
  -bios "$INPUTS/bios" -kernel "$INPUTS/kernel" -initrd "$INPUTS/initramfs" \
  -append 'console=ttyPZ0,38400 rdinit=/init panic=-1'
python3 -B toolchain/src/measure-p05-target.py analyze-runtime \
  --arch powerpc --profile caller-driven --elf "$INPUTS/runtime" \
  --supervisor "$INPUTS/supervisor" --log "$RUN/runtime.serial.log" \
  --receipt "$RUN/analysis.json" --revision 4825c0b-asup1a144aa
```

Kernel SHA-256: 0e20e7ffd30fd89a2967131bd1d9100bb29384590a481ce4214f6c88c883b1c7.
BIOS SHA-256: 032884eab588cd8d45903ed7be718f7a23fecaa4fc45c2dbf18c1220f13218ef.
Other inputs and helper hashes are in powerpc-32m-debian316/execution.json.
This narrow successful candidate execution does not reverse the old4.9/32MiB
failure or qualify the production speaker, stock Sonos kernel, driver memory,
DMA/audio, allocator exhaustion or worst-case stack/heap use.
