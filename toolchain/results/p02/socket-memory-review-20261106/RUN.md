# P02 socket, memory and startup review

Source `d17a315` matches the recorded Rust, manifest and lock hashes. The final
strict remote run executed 504 passing tests, zero failures, and one explicitly
ignored pre-existing D03 soak. New P02 cases cover both ABI errno conventions,
kernel allocation/resource failures, arithmetic overflow, and actual diagnostic
CLI argument/backend behavior. Host Clippy, including the platform simulation
feature, and MIPS/PPC library and binary Clippy completed with `-D warnings`.

All four native jobs acknowledged completion; wrappers are dead, owners absent,
and source, tree and pair custody released. Exact argv, hashes and native
identities are in `receipt.json`. Each command ran as
`RCH_REQUIRE_REMOTE=1 rch exec -- <argv>` in a frozen export. BE checks here
compile code; they do not execute a guest binary.

Logs retain stdout and stderr. ANSI, local paths, worker aliases, logins and
addresses are sanitized; raw and published hashes are separate. An initial
offline MIPS attempt failed with exit101 because a locked dependency was absent
from the worker cache. A locked retry allowed dependency fetching and passed.
An obsolete speaker check was cancelled while queued, before any grant; the
corrected final source was then tested. Neither attempt is counted green.

Socket calls have no guest execution proof. This record does not qualify a stock
kernel, physical speaker, service integration, real-time budget or codec resource
usage. Original full P02 acceptance also requires the separately tested tiered
bounded Python evidence adapter; compiler results alone do not close it.
