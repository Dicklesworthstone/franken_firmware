# Caller-driven runtime: big-endian guest execution and RAM-limit experiment

This archive contains four fresh full-system QEMU executions of the same frozen
runtime and supervisor ELF pairs. Three completed successfully; the 32 MiB
PowerPC attempt failed during early kernel boot and reached its original
600-second timeout. Both outcomes are retained. No speaker or provider was
accessed, and no P05/P03 acceptance condition is waived.

## Actual executions

| Guest | RAM | Outer runner / QEMU exit | Runtime markers / census rows | Result |
|---|---:|---|---|---|
| MIPS Malta / 24Kf / Debian Linux 4.19.249 | 64 MiB | 0 / 0 | 32 / 12 | eight execution gates passed |
| PowerPC g3beige / G3 / Debian Linux 4.9.88 | 64 MiB | 0 / 0 | 32 / 12 | eight execution gates passed |
| Same MIPS machine, kernel and initramfs | 32 MiB | 0 / 0 | 32 / 12 | eight execution gates passed |
| Same PowerPC machine, kernel and initramfs | 32 MiB | 1 / -9 | 0 / 0 | timeout; no runtime execution observed |

QEMU version is 11.1.3. All commands disabled the NIC with `-nic none`.
`commands.json` records actual runner commands, exits and elapsed durations;
each execution receipt records the actual QEMU argv, kernel/initramfs hashes,
capture outcome and packaged executable identities. The 32 MiB QEMU commands
differ from their respective 64 MiB controls only at argv element 6:
`64M` becomes `32M`. Both kernel and initramfs hashes are unchanged.

Each successful run reports 18 feature phases and 12 census operations, with
`END ops=30 ok=30 failed=0 unsupported=0 partial=0 unknown=0`. Census counts and
in-task thread readings are all one. Eight spawned children join with sum 140;
timer abort observes one cancellation cleanup and retires one timer; blind abort
returns Cancelled; timer wake and 19-byte guest loopback complete; blocking work
is refused without starting a pool job; handle-spawn work waits for `block_on`;
drain observes four unique cancelled children and two quiescent reports. The
runtime is a child of the E07 PID-1 supervisor, not PID 1 itself. Child exit and
stdout byte/FNV checks precede bootstrap success and the natural reboot exit.

| Successful run | Maximum sampled VmHWM | Minimum sampled MemAvailable |
|---|---:|---:|
| MIPS 64 MiB | 2640 KiB | 44812 KiB |
| PowerPC 64 MiB | 2284 KiB | 48232 KiB |
| MIPS 32 MiB | 2640 KiB | 13448 KiB |

These are observations of this short runtime probe, not a production speaker
budget. They exclude the intended audio pipeline, codecs, native service
sessions, retained Sonos drivers and worst-case transition/fragmentation costs.
The PowerPC 32 MiB run has no process memory observations.

## Retained PowerPC failure and diagnostic correction

The 32 MiB PowerPC serial ends with `Can't allocate initial device-tree chunk`.
Its reported kernel/initrd layout has `alloc_bottom=01bb3000` and
`ram_top=02000000`. The original bound expired after 600.692 seconds and the
capture killed QEMU: exit -9, stop reason `timeout`. There was no retry, RAM
increase, alternate kernel/machine, modified binary or timeout adjustment.

The message originates in Linux's early PowerPC Open Firmware handoff code,
not the runtime: see
[Linux stable v4.9.88 prom_init.c](https://github.com/gregkh/linux/blob/v4.9.88/arch/powerpc/kernel/prom_init.c#L2091).
The serial has reached that early Linux code, but not normal kernel startup,
PID 1 or the runtime. Earlier private review shorthand called it "pre-Linux"
or an "OpenBIOS failure"; those descriptions were too broad. The exact firmware
claim/allocation cause has a source-grounded explanation, with a historical
BIOS-custody limitation: this is not an observed runtime OOM and does not
establish that a different PowerPC boot setup would fit.

At QEMU 11.1.3's
[pinned OpenBIOS revision](https://gitlab.com/qemu-project/openbios/-/blob/e5ac46dd24e6216c36aa80462af25457e7029440/arch/ppc/qemu/ofmem.c),
the 32 MiB firmware reservations leave only 660 KiB immediately above this
initrd and a separate 960 KiB hole. Neither can satisfy Linux's contiguous
1 MiB request. The current installed BIOS matches the published QEMU 11.1.3
blob (673104 bytes; SHA-256
`032884eab588cd8d45903ed7be718f7a23fecaa4fc45c2dbf18c1220f13218ef`),
and its build banner matches the serial. The original execution did not hash
the BIOS, so this explains the observed layout by source inference, not an
observed historical firmware claim map. The QEMU
[OldWorld loader](https://github.com/qemu/qemu/blob/v11.1.3/hw/ppc/mac_oldworld.c#L145)
places the kernel at 16 MiB and the initrd after the kernel plus a 1 MiB gap.

A possible separate experiment would compress the identical raw CPIO with XZ,
which this cached kernel's companion configuration enables. The predicted
first usable allocation requires an archive no larger than 614400 bytes.
Offline size measurements did not meet that fixed boundary: ordinary XZ was
672672 bytes; PowerPC BCJ plus LZMA2 with a 2 MiB dictionary and extreme-9
compression produced 629180 bytes. Decompression recovered the exact raw CPIO
in both cases. No XZ guest was launched and no bound was relaxed. Smaller
source/dependency output or another explicitly qualified boot layout remains
future work; the recorded four-execution denominator is unchanged.

The original execution receipt correctly fails overall: six failed gates, one
blocked cleanup gate, and a misleading passed `P05R-PHASES` gate because no
operations were present to contradict it. That receipt remains unchanged.
Commit `eee1e2e` repairs the diagnostic by requiring each selected operation
exactly once, preserving the single-owner declared-unsupported exception and all
other original gates. Each `postfix-analysis.*` records separate analysis of
the retained serial, not another execution: three pass; the PowerPC 32 MiB
transcript remains failed and now fails the phase gate too. Analysis has no
capture gate and cannot qualify memory metadata by itself.

The two new regression methods fail 111 subcases against the original checker.
The first corrected-code run executed 113 test methods and reported nine
failing subcases in the new boot-failure diagnostic test because it expected a
late error beyond the existing six-error diagnostic bound. The test now checks
an early shared missing operation; the diagnostic
bound is unchanged. Final complete suite: **113/113 passed**. Both failed runs
and the final output are retained. The preceding memory-option suite passed
111/111 with all 107 older methods retained. Python compilation, whitespace
checks and independent source review passed.

## Executable and source bindings

| Runtime ELF | Bytes | SHA-256 |
|---|---:|---|
| MIPS32r2 BE, static, stripped | 2515448 | `91f434450a6e22d53616f8f41e39cb601f5bafabe5eff551d27958ae17845c15` |
| PowerPC32 BE, static, stripped | 1946688 | `410ed6461d318666753ca906a01eb5b3ae5c5c3b92520043311dc74f2adc0fce` |

`elf-file-output.txt` contains actual `file(1)` output for both runtime and
supervisor pairs. Independent archive parsing checked that `/init` and
`/franken-speaker` in each initramfs have those exact supplied ELF bytes.
No ELF, kernel, initramfs, firmware image or packet capture is committed here.

The four actual strict-remote builds were 30101959465763521 (MIPS runtime),
30101959465763532 (MIPS supervisor), 30101959465763535 (PowerPC runtime) and
30101959465763537 (PowerPC supervisor). All exited zero with terminal ACK, dead
wrappers, absent owners and released source/tree/pair custody.
`build-source-summary.json` retains the selected nine source/manifest/linker
bindings from each full source-content receipt, checked against firmware
`ef0fb9d042dd2806e454086ea87eefae68c71a0a`. The locked consumer pins Asupersync
`91509bcd8ac1f1cb00417b9b3a6d54875cbfce05`. Runtime source SHA is
`0eb93f643165b25f1606e21e4f7bcafe87477eada2722850b1ea26cd13eeca9b`.
These input receipts and the execution/packaging hashes are distinct evidence;
they are not independent cryptographic compiler/output-source attestation.

Both runtime builds emitted one linker warning for the absent prebuilt rustlib
directory while building std from source; the links still completed. The
warnings remain in the logs. `build-launches.txt` retains launch text copied
from the coordinator's original session, with personal paths replaced by
placeholders. The original refused config-file supervisor attempt 530, busy/
draining worker and queue-timeout prestarts remain private and are not counted
as successful builds or guest attempts. The inline-config replacement is build
532; it is not a reclassification of refused 530.

The 32 MiB processes loaded the runner from `8d76ad0`; their source-before
hashes are retained. The phase diagnostic was subsequently edited while the
PowerPC process was waiting, so no unchanged-source-throughout-wait claim is
made. The ELF, kernel and initramfs inputs did remain unchanged. The 64 MiB
independent replays used `ef0fb9d`. Two earlier original 64 MiB executions also
passed their captured gates, but the original MIPS outer status was not
retained; it is not invented here. This archive's four-run table uses the
fresh independent invocations with actual outer statuses.

## Independent rejection checks and reproducibility

`independent-negative-cases.json` records twelve real-transcript derivatives
rejected with exit 1: missing timer marker, false joined count, false cleanup
witness, excess thread count, NUL and truncation on each architecture. Two
wrong-architecture runtime ELFs were rejected with exit 2 before analysis.
These are checker tests, not additional runtime executions.

The historical independent review uses private-era filenames: its
`mips-replay/` and `ppc-replay/` correspond to `mips-64m/` and `powerpc-64m/`
here; its `rejection-cases.json` is published as
`independent-negative-cases.json`. Its `commands.json` included analysis and
execution; this archive's `commands.json` selects actual executions and
`postfix-analysis-commands.json` records the later separate analysis. Kernel,
initramfs and ELF binaries mentioned in that review remain outside Git.

The same reviewer confirmed that a wrong **same-architecture** ELF can still
analyze a genuine supplied transcript successfully. Analysis checks ELF
architecture and protocol observations; it cannot bind an arbitrary supplied
ELF to historical execution. Do not claim arbitrary wrong-image exclusion.
The execution receipts and parsed initramfs membership bind the four actual
runs to their packaged bytes instead. This boundary was not hidden with
synthetic binary signatures or an invented attestation scheme.

For another admitted offline execution, use the existing runner from the repo
root, built ELF inputs and the provisioned generic kernels:

```sh
FFW_BUILD_DIR="$BUILD_DIR" scripts/e2e/p05 --runtime run \
  --arch mips --profile caller-driven --guest-memory-mib 32 \
  --elf "$ELF_ROOT/mips/ffw-p05-runtime" \
  --supervisor "$ELF_ROOT/mips/ffw-hello-init" \
  --log-dir "$FRESH_RUN_DIR" --receipt "$FRESH_RECEIPT" --timeout 600
```

Use `--arch powerpc` with its corresponding ELF pair for the PowerPC setup;
the recorded 32 MiB setup fails as shown above. Omitting `--guest-memory-mib`
preserves 64 MiB. The analysis subcommand deliberately cannot accept that
option. `postfix-analysis-commands.json` gives the actual separate reanalysis
commands with path placeholders.

Raw serial/stderr files are copied byte-for-byte. Execution receipts already
use external-path placeholders; `published-artifact-identities.json` records
raw/public hashes and transformations. Build logs remove ANSI, replace
personal/worker paths and IP-shaped strings, and omit only the enormous full
receipt line with its exact byte count/digest retained. Failure counts and
warnings remain. No credentials or site identifiers are included.
Raw serial line endings and unittest's spaces preceding subtest failure
details are preserved; Git's whitespace check consequently flags evidence
bytes. Source whitespace checks pass. The ignored `.log` evidence paths are
explicitly included; no ignore policy was changed.

## Remaining qualification

This is generic QEMU execution, not Sonos silicon or its stock kernels.
PowerPC 32 MiB userspace remains unqualified. Production RAM/flash fit, real
module/dependency feature reduction, allocator-failure coverage, board CPU and
render deadlines, retained-driver completion, physical audio, Spotify, AirPlay,
Alexa, video sync and native tailnet integrations retain their original gates.
Full P05/P03 acceptance remains open; no implementation bead was self-closed.
