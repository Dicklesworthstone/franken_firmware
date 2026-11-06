# P02 legacy random-device diagnostic

The new archive reaches the explicitly selected legacy `/dev/random` provider.
It reports `REFUSED ... reason=not_seeded`, rather than the former missing-device
refusal. This is a diagnostic of the real provider path, **not a qualifying
positive, normal boot, or P02 completion**. It neither seeds the pool nor changes
provider policy. The speaker is an existing source-bound P01 ELF; no build ran.

The full observed serial output is `console.log`; source/artifact hashes and
termination status are in `receipt.json`; tool versions are in `tools.txt`.
Private host paths in the invocation are replaced by the parameters below.
The archive and guest binaries are deliberately excluded from Git.

```sh
python3 toolchain/src/mkinitramfs.py --init "$P01_PPC_SPEAKER_ELF" --out "$EVIDENCE_DIR/legacy-ppc.cpio.gz"
QEMU_AUDIO_DRV=none qemu-system-ppc -M g3beige -cpu G3 -m 64M \
  -nographic -no-reboot -nic none -kernel "$PPC_GUEST_KERNEL" \
  -initrd "$EVIDENCE_DIR/legacy-ppc.cpio.gz" \
  -append 'console=ttyPZ0,38400 rdinit=/init panic=-1 -- --platform-startup --entropy-provider legacy-dev-random-test-environment'
```

A 50-second timeout was prepared but did not fire. The one-shot speaker exited
3 as PID1; the kernel then panicked, and QEMU exited 0 because of `-no-reboot`.
The `kernel=invalid` application marker is retained, so this cannot substitute
for the official harness, its identity check, or an admitted legacy-entropy
positive. No host entropy, artificial seed, network traffic, or physical device
was used. Retire this diagnostic as the relevant qualification input once the
regular provider-aware guest runner supplies an admitted result.

Archive regression verification: 13 independent unit tests; the builder
self-test covers 16 alignment combinations and three negative oracles. The
existing speaker-smoke regression suite passed all 53 tests. These archive and
runner tests do not establish a seeded entropy pool or physical compatibility.
