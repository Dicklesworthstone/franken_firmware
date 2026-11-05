# franken-speaker QEMU smoke (E07 runner change)

**Status.** The guest-side code passed centrally (commit `376039d`): hello-init lib tests, the `speaker-smoke` build for both
triples, clippy with no warnings, and the feature-off A/B, which is byte-identical to the committed E07 digests. The smoke
itself has one committed result: `toolchain/results/runs/22637af083874c1a8c2204a7620838e2/` (2026-11-05), both guests PASS.
The device speakers in that run were built from `1688a75` (MIPS `476a2d1c…`, PowerPC `f05bcbc6…`) and judged against that
revision's host catalog (FNV-1a64 `920a91647ae4af73`); hello-init was built from this file's commit, with the console-level
step below. The command was the one under Command plus `--target-dir`; all six controls were caught. The E07 digests
committed earlier describe the hello-init before the console-level change; this run's receipt carries the new ones
(speaker-smoke builds only; no feature-off digest was taken).

A pass would show a linked, static `franken-speaker` starting as a userspace process under the E07 guests (MIPS Malta, Linux
4.19; PowerPC g3beige, Linux 4.9) and printing the catalog the Rust source defines. It would not show anything about Sonos
silicon, the float ABI (the catalog has no floats), networking, audio, timing or memory pressure.

## Command

`FFW_BUILD_DIR` (the Debian guest-kernel cache, not in the repo) must be set in the environment.

```sh
RCH_WORKER=ts1,hz3,hz4 python3 toolchain/src/run-qemu-verification.py --timeout 60 --jobs 2 \
  --speaker-mips build/p01-target/mips-unknown-linux-musl/release/franken-speaker \
  --speaker-ppc  build/p01-target/powerpc-unknown-linux-musl/release/franken-speaker \
  --speaker-host-catalog host-catalog.json --speaker-controls
```

`python3 toolchain/src/run-qemu-verification.py --check-catalog host-catalog.json` judges the HOST build's `--catalog` output
alone; run it first. It validates the checker (including its SHA-256 replication) before a guest is held to it.

## Markers (fixed before any run)

```
...every existing E07/E03 line, unchanged...
FFW_SPEAKER_BEGIN path=/franken-speaker argv=--catalog
<the child's stdout: the pretty-printed catalog>
FFW_SPEAKER_EXIT status=0 stdout_bytes=<N> stdout_fnv1a64=<16 hex>
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
```

The only success form is status 0 with at least one byte of stdout. Every other form is a named failure
(`speaker_failed:<the guest's words>`). The console text between BEGIN and EXIT must match the guest's own count and FNV, and
must be the catalog the Rust source defines (`speaker_expect.py` parses the nine rows out of `canonical_board_catalog()`).
Without the speaker flags any `FFW_SPEAKER_*` line fails the guest.

**Console quiet (every guest run, with or without the speaker flags).** `hello-init`'s first action is
`klogctl(SYSLOG_ACTION_CONSOLE_LEVEL, NULL, 1)`, so only `KERN_EMERG` reaches the serial console and a kernel `printk`
cannot land inside a marker; one did on the first PowerPC smoke (`FFW_MARKER:TEST_SUCCESS fai[ ... random: crng init done`
then `lures=0`). The guest prints `FFW_GUEST:CONSOLE_LEVEL status=PASS rc=0` after `USERSPACE_START`; the verifier requires
that exact line, names a refused call (`console_level_refused:<what the kernel answered>`), and stays strict about partial
lines on purpose. The line is guest setup, not an E03 capability probe, so it never reaches the capability matrix.

## Controls (`--speaker-controls`)

One extra boot each, from the same hello-init binary. Each must fail for exactly the planted reason, and only counts if the
unplanted run of that guest passed.

| plant | the guest must print | errno |
|---|---|---|
| no `/franken-speaker` | `FFW_SPEAKER_EXIT spawn=exec errno=2` | ENOENT |
| mode 0644 | `FFW_SPEAKER_EXIT spawn=exec errno=13` | EACCES |
| the other ISA's speaker | `FFW_SPEAKER_EXIT spawn=exec errno=8` | ENOEXEC |

## Where the spec is

The runner (`toolchain/src/run-qemu-verification.py`), `toolchain/src/speaker_expect.py`, the guest step
(`toolchain/src/ffw-hello-init/src/speaker_smoke.rs`, cargo feature `speaker-smoke`, off by default) and
`toolchain/tests/test_speaker_smoke.py`.
