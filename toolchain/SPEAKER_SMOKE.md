# franken-speaker QEMU smoke (E07 runner change)

**Status.** The guest-side code passed centrally (commit `376039d`): hello-init lib tests, the `speaker-smoke` build for both
triples, clippy with no warnings, and the feature-off A/B, which is byte-identical to the committed E07 digests. The smoke
itself, the speaker booting in the guests, has no committed result yet. Nothing below is evidence of a boot until a receipt
under `toolchain/results/runs/` is committed.

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
