# Prepared cleanup: immutable host consumer

This experimental probe selects upstream Git revision
`1a144aa5696f600665e083df601ae4974f6950b5`, with default features off and
`slim-runtime-profile`. Its resolved Asupersync features are `native-runtime`,
`runtime-core` and `slim-runtime-profile`. The optional Asupersync `proc-macros`
feature and `test-internals` are disabled; ordinary transitive derive macros
remain. The production speaker dependency stays at `36141e21`.

The probe pre-admits a real cleanup resource while the ordinary task quota is
occupied. It verifies the same quota refusal before and after caller-driven
execution, an actually parked cancellation-aware child, asynchronous cleanup,
callback/resource destruction exactly once, retained-work non-quiescence,
bounded drain and stable thread census between drives and after runtime drop.
Finalizers run after ordinary tasks drain; this is not evidence that a finalizer
polls concurrently with an occupied ordinary task slot or that cleanup allocates
no memory.

## Executed checks

- Probe unit tests, job 30109207290184187: **47 passed, 0 failed, 0 filtered**,
  including the real prepared-resource positive and retained-cleanup negative.
- Full canonical Python analyzer suite: **115 passed, 0 failed**. The corrected
  transcript puts prepared fields before the existing `repeat:` separator.
  Controls reject missing/false observations and fields moved past that
  separator across all three profiles. Earlier source review caught the wrong
  placement before canonical application. A full test attempt in a partial
  staging tree lacked helper files and failed; it is not a native proof or a
  passing full-suite result.
- Strict probe/all-target Clippy, job 30109207290184195: exit 0, `-D warnings`.
- Standalone caller-driven job 30109207290184200: command and artifact delivery
  exit 0; **30 operations passed**, zero unsupported/partial/unknown, and all
  **12 census points observed one thread**. The existing analyzer and actual
  downloaded x86_64 ELF pass all six host protocol gates.

`source-inputs.sha256`, commands and source-receipt roots bind these observations
to the selected inputs. Terminal ACK and source/tree/pair retirement were
verified. The binary remains outside Git; the ELF hash is in `analysis.json`.

## Failures and qualification boundaries

An earlier standalone command, job 30109207290184194, executed 30 operations
successfully but its RCH artifact delivery **failed with exit 102**: the command
omitted the documented foreign-artifact opt-in for a Linux ELF on a Mac caller.
Its original failure is retained. Readback verified that binary, and the one
subsequent run added only `RCH_ALLOW_FOREIGN_ARTIFACTS=1`; code, profile, marker
requirements and oracles were unchanged. An earlier worker refused the native
test job 30109207290184185 for disk admission (exit 120, zero executed tests).

The earlier mutable-local upstream job 30109207290184080 executed 30 passing
tests but detected 24 source differences after execution. Peer-published codec
and synchronization commits appeared during that long build. Recovery settled
its command, but no source receipt was emitted; it cannot qualify current HEAD
or this immutable candidate. That is why this consumer uses an immutable Git
revision instead of depending on a mutable sibling checkout.

This candidate deliberately excludes newer synchronization fixes through
`686f462766b3499d202a50bd754428074cfd1a11`. Their production relevance remains;
production advancement must select and requalify them. Host execution does not
establish static-musl linkage, big-endian execution, old-kernel compatibility,
stack/heap/allocation ceilings, hardware drain, provider support or board RAM
fit. Older captures without the new cleanup markers cannot qualify this new
candidate. P05 and its dependent P03 remain open.
