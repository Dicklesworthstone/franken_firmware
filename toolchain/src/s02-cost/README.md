# S02 MP3 guest probe

This standalone package exercises the real `franken-codec` finite-reader MP3
decoder inside a generic big-endian MIPS32r2 Linux guest. It compares every
sample from three complete 24,000-frame stereo decodes against the existing
independent FFmpeg reference. Each decode must have no truncation, format
change or decoder error and meet the original peak <=4 LSB / RMS <=1.5 LSB
limits. The full-file positive and an actual shortened encoded-file rejection
also run in the host unit tests.

The package has its own committed Cargo.lock. Its registry package versions
and checksums match the approved repository lock, including smallvec 1.16.4.
The application workspace and its lock do not change.

Run from the repository root through the central verifier:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo +1.99.0 test --locked --offline \
  --manifest-path toolchain/src/s02-cost/Cargo.toml -j1 \
  -- --show-output --test-threads=1
python3 -B toolchain/src/s02-cost/test_guest.py -v
```

The host executable refuses to claim a MIPS measurement. Unit tests use the
actual decoder and injected reporting failures; the Python synthetic transcript,
kernel and helper controls are explicitly unit evidence, not guest execution.
The central release cross-build pins nightly-2026-09-21, rust-src and Zig
0.14.1, using the existing `toolchain/linker/zig-cc-mips-be` soft-float linker
and static target flags. Build commands and identities are recorded with the
[qualification evidence](../../results/s02/20261112-mips-probe/RUN.md).

Use the already built target executable with the offline guest runner:

```sh
python3 -B toolchain/src/s02-cost/run-s02-cost.py \
  --repo "$PWD" --elf "$S02_ELF" --kernel "$S02_KERNEL" \
  --output-dir "$S02_NEW_OUTPUT_DIR" --timeout 180
```

The output directory must not exist. The runner freezes the input executable,
full-hash-pinned Debian Malta 4.19 kernel and helper sources; builds and verifies
an initramfs with the explicit guest opt-in; starts QEMU Malta/24Kf with 64 MiB,
`-icount shift=0,align=off,sleep=off`, no NIC and no reboot loop; and retains
bounded raw serial/stderr plus a result receipt. It never invokes Cargo or
contacts a speaker. Success requires complete decode/oracle records, END,
a subsequent observed kernel restart and QEMU exit zero. END alone is not
completion. Numeric kernel timestamp prefixes are accepted; arbitrary prefixes,
missing, duplicated or contradictory records and failure markers are refused.

The guest requests reboot only for a BE-MIPS/Linux build running as PID 1
with the exact `/ffw-s02-qemu-pid1` marker supplied by the runner. This is an
explicit opt-in, not virtualization attestation. Reporting uses fallible writes
so an output error cannot panic before guarded shutdown. Missing opt-in or an
unrelated panic still cannot guarantee clean shutdown and must be rejected or
time out externally. An incomplete transcript never earns success.

The before/after 3- and 5-instruction rulers and empty-read floors are raw
observations. Timed pulls include `next_block` demux, reader, decoder and output
allocations; source open, hashing, PCM comparison, printing and cleanup are
outside the timed region. EOF pulls are separate. **Counter wrap remains
unresolved**, so neither successful exit nor raw ticks qualify an instruction
count, real CPU percentage or real-time deadline. No stack, allocator or RSS
measurement is performed. The earlier host requested-byte heap evidence remains
separate. This probe does not qualify Sonos silicon, legacy stock kernels,
provider sessions, radio performance, drivers or physical audio.
