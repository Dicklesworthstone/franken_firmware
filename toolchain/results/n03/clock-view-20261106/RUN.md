# Clock-view error accounting and epoch recovery

The existing playout adapter now uses the default-library `ClockViewBridge`.
Holding a backwards clock reading steady adds that displacement to its
uncertainty. Overflow or a bound above the existing clock policy produces an
unusable view without advancing the latch. A new admitted clock epoch resets
the timestamp latch, while temporary loss of lock within an epoch preserves it.
Clock usability remains separate from permission to emit audio.

The exact source hashes and commands in `receipt.json` passed 250 speaker
library tests, with zero failures or ignored tests, and strict remote Clippy
over all speaker targets with the harness feature. Six new tests exercise
injected truth intervals, threshold equality, overflow, invalid-read recovery,
the real group-clock API and lower-timeline epoch recovery. An independent
source review found the epoch issue before these final tests and found no
remaining defect in this bounded slice.

Both native commands finished with acknowledgement, dead wrappers, absent
owners and released source/tree/pair custody. Logs retain both output streams;
paths, addresses and worker identities are sanitized, with raw and published
hashes recorded separately. Earlier disk-admission exit120 and queue-timeout
exit103 attempts ran no Cargo and are not counted as tests.

This is host evidence. It provides no BE guest, physical speaker, DAC alignment,
Spotify or other service qualification. N03 remains open: separate coarse-clock
bound corrections and the media consumer require their own exact-source checks.
