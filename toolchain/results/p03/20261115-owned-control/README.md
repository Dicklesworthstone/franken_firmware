# Owned pending control and process journal integration

The control owner can retain its journal transaction across `Pending` while the
renderer and local Stop continue. Relative-command floors and revision high-water
are acknowledged before staged effects publish. Session, binding and stop fences
prevent stale publication. Failed or unfinished extraction returns the complete
owner; successful extraction requires both a settled journal and HAL stop ACK.

The actual child process/FileMedium backend is exercised through SettledRender.
HAL and clock are explicit synthetic fixtures. A stopped child produces Pending;
local Stop and its modeled HAL drain complete while journal custody remains held.
After the child resumes, the test settles, quiesces, reaps and reopens storage.

`native.txt` records the complete suite denominators and selected named observations
from job 30109207290184088. `clippy.txt` records strict workspace/all-target Clippy
job 30109207290184085. Both have terminal ACK and retired source/tree/pair custody.
Every tuple in `source-inputs.sha256` matches both remote source receipts.

The integration fixture uses an explicit simulated platform admission function.
It rejects native provenance/ABI before operations and retains the original
matrix-evidence gate. The existing speaker startup construction census is unchanged.
The simulated feature is a dev-dependency; normal device dependency graphs exclude
it and test-support. Nineteen existing platform-marker tests and default/harness
metadata checks also passed; those are source/graph checks, not native device proof.

## Qualification limits

This is an offline host prototype. There is no hardware, old-kernel, QEMU,
provider, acoustic synchronization, or hard per-poll/deadline qualification here.
Normal SOAP/control-loop selection is a subsequent integration change; these
results exercise the public pending-owner API. P03 remains open.

The consuming APIs intentionally return full custody on refusal. Six local
`result_large_err` expectations and two speaker layout/custody expectations avoid
adding an allocation during recovery or each control transition. Independent
source review examined them separately from the strict lint gate. The host lint
diagnostics reported a ControlSlot variant of at least 4,048 bytes and a stopped
owner error variant of at least 56,855 bytes. These are host type-size lower
bounds, not target sizes or measured stack use. Moves, return slots and call
chains may need additional space. Target layout and stack/high-water admission
must precede any target-fit or P03 completion claim.

## Retained earlier failures

An earlier native gate failed because an integration-only secret-store helper was
not exported by its dependency. Its replacement remains test-local. A later gate
caught an extra platform construction path; the original census was preserved
and simulation moved to the existing simulated platform module. The pinned
worker later timed out before execution, and a Clippy attempt lacked a supported
worker runtime. Strict remote refused both local fallbacks. Two successive Clippy
runs reported the consuming-owner/layout lints discussed above. Only the final
full test and strict Clippy passes qualify the source tuples in this directory.
