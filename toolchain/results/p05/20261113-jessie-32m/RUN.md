# PowerPC caller-driven runtime in a 32 MiB Debian 3.16 guest

One actual full-system QEMU execution completed in 4.163 seconds with
**18 named runtime phases plus 12 census operations: 30 ok, 0 failed,
0 unsupported, 0 partial, 0 unknown**. The supervisor reported the child exit, stdout byte count and hash; the
analyzer verified the child envelope and hash. The supervisor reported success,
requested reboot, and QEMU exited naturally
with code0. No timeout, output truncation, build or hidden retry occurred.

This is one distinct Debian Linux3.16.56/QEMU11.1.3 profile with **32 MiB of
emulated guest physical RAM**. It is a short Asupersync probe, not the speaker
application, a physical device test or production memory-fit qualification.
The earlier Linux4.9.88/32MiB failure remains unchanged in the
[original four-execution archive](../20261109-caller-driven-guests/RUN.md).
Its 600-second timeout reached no runtime operations; this experiment does
not reverse that result or identify its historical BIOS bytes.

## Exact inputs and execution

The runtime, PID1 supervisor, gzip initramfs and profile marker are byte-for-byte
identical to the retained PowerPC caller-driven experiment. The only new kernel
is the unmodified Debian package identified below. The installed current
OpenBIOS blob was copied, hashed and selected explicitly with -bios; because
the old execution never hashed its BIOS, this is a distinct guest profile,
not an established single-variable historical comparison.

| Input | SHA-256 |
|---|---|
|Original runtime ELF|410ed6461d318666753ca906a01eb5b3ae5c5c3b92520043311dc74f2adc0fce|
|Original supervisor ELF|faf5f35a17b11047092a907be5e3ae86097d82682fa44bdb0534b46235caf721|
|Original gzip initramfs|8b4028c3b91d4e601e881d142beb33348e6f5932a9cfe9ed2ae07ab7ed8232c3|
|Original raw CPIO|c24636b4700c548593f8a8fee1407ea3fe913833d41f5821e91b9fd4d6465319|
|Debian3.16.56 PPC kernel|0e20e7ffd30fd89a2967131bd1d9100bb29384590a481ce4214f6c88c883b1c7|
|Explicit current OpenBIOS|032884eab588cd8d45903ed7be718f7a23fecaa4fc45c2dbf18c1220f13218ef|

The original archive has15 members excluding its CPIO trailer (the parser
records16 entries including TRAILER!!!), one executable /init, one executable
/franken-speaker and exactly caller-driven followed by newline in the profile
marker. The committed parser verified entry uniqueness, padding, required
device nodes and member hashes. No repacking occurred. The unchanged runtime
uses the supervisor child slot, not PID1 itself. Original compiler/source
bindings are carried forward from
[the earlier build evidence](../20261109-caller-driven-guests/build-source-summary.json);
no new compilation or upstream source qualification is claimed.

These are the actual argv with machine paths normalized. KERNEL, INITRAMFS and
BIOS denote the immutable snapshots with the hashes above, not names to resolve
from an installed default. The executable itself is also hashed in execution.json.

```sh
qemu-system-ppc -M g3beige -cpu G3 -m 32M -nographic -no-reboot -nic none \
  -bios "$BIOS" -kernel "$KERNEL" -initrd "$INITRAMFS" \
  -append 'console=ttyPZ0,38400 rdinit=/init panic=-1'
```

The actual recorder called the unchanged capture_guest from
toolchain/src/run-qemu-verification.py with this argv, timeout600 seconds,
shared stdout/stderr cap1048576 bytes, and exclusive-create separate raw files.
It starts an isolated process group, retains partial output on failure and
waits/reaps its leader. This record asserts reaped leader, not independently
observed absence of every possible descendant. Normal completion retained
17956 stdout bytes and zero stderr bytes. All input, QEMU and checker-helper
hashes remained unchanged before/after capture and after analysis.

The unchanged analyzer was invoked separately:

```sh
python3 toolchain/src/measure-p05-target.py analyze-runtime \
  --arch powerpc --elf "$RUNTIME_ELF" --supervisor "$SUPERVISOR_ELF" \
  --profile caller-driven --log runtime.serial.log --receipt analysis.json \
  --revision 91509bcd8ac1f1cb00417b9b3a6d54875cbfce05
```

It returned0 with all seven analysis gates passed: transcript order, environment,
required phases, actual cancellation cleanup, census, END accounting and
supervisor framing/hash/ordered reboot. Its receipt intentionally remains
supplied_transcript_analysis and contains no invented execution metadata.
The separate execution.json binds the actual capture and raw stdout hash to
that analysis. It records the five exact checker source hashes, including
speaker_expect.py and platform_expect.py. Source/revision labels alone do not
attest an ELF build, and an analysis pass alone does not prove a clean capture.

## Observed capability and memory boundaries

Every one of12 census samples had consistent task-directory-before/after and
process-status thread counts of1. Maximum sampled VmHWM was2284KiB; minimum
sampled guest MemAvailable was18560KiB. These are observations of this short
probe, not continuous thread/heap bounds or production headroom. Audio DMA,
retained Sonos drivers, codecs, Spotify/AirPlay/Tailnet sessions and worst-case
transition/fragmentation costs are absent.

The raw supervisor also reports:

```text
FFW_PROBE:ENTROPY status=PASS fd=4
FFW_PROBE:GETRANDOM status=FAIL rc=-38
```

The second is ENOSYS on this older kernel and is an accepted optional-capability
result under the unchanged supervisor. It is preserved, not described as an
all-syscalls pass. Runtime END unsupported=0 counts its own30 operations;
it does not erase this separate capability absence. Observed access to the
selected entropy provider is not full cryptographic entropy qualification.

## Kernel provenance and why this experiment was chosen

The exact [Debian Jessie package](https://archive.debian.org/debian/pool/main/l/linux/linux-image-3.16.0-6-powerpc_3.16.56-1%2Bdeb8u1_powerpc.deb)
is25742544 bytes, SHA-256
e45aa67da39f7ee9815743a84af0133d9475ceb7c92d807177317ba26af646d9.
Its package hash matched Debian Packages.gz metadata, whose hash matched the
[Jessie Release file](https://archive.debian.org/debian/dists/jessie/Release).
The Release GPG signature was not verified; published-metadata integrity is
not independently authenticated signer provenance. Kernel/config binaries
are not committed. Configuration identity and package metadata are recorded
in execution.json.

The retained4.9 direct-boot layout could not satisfy Linux's1MiB contiguous
initial device-tree request. Source tracing found no supported direct relocation
knob for the pinned QEMU/OpenBIOS path. The smaller unmodified3.16 image left a
predicted contiguous window without removing probe operations or altering RAM,
assertions, resource fields or deadline. Its actual serial records the new
layout and completed boot; prediction alone was not credited as execution.
A source-only3.2 candidate was rejected before download/boot because it lacks
the unchanged census's MemAvailable field. No sensor substitution or judge
relaxation was made to accept it.

Independent same-execution capture/analysis review passed (not another boot).
No speaker, provider, unlock, firmware installation, Asupersync edit or build
occurred. Stock Linux2.4, physical drivers/audio, production speaker resources,
full minimal dependency/feature gating and complete P05/P03 acceptance remain
unqualified. Canonical upstream AGY work was left untouched.
