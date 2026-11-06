# E06 audit of the landed lock (S02 merged over P02 wall-time)

`audit.json` here is the E06 audit (`ffw.e06.audit.v1`) of `Cargo.lock` sha256
`e2469ade4d83492a899bf8438ad240174f7ee41044ef5f9105d56d1e9c46f837` (61 entries). That lock is the S02 delta
(`audit-s02-lock-229463f7eb80/`: 42 -> 61 packages, purely additive) merged natively over main's lock `9605c4c95415`,
which already carried P02's wall-time edges (`hmac`, `sha2` under `franken-platform`; `audit-walltime-e1ce2c5a78e7/`).
The merge is `git merge-file` of main's lock, the 0f963c8 base lock and the S02 lock, clean; it differs from the S02 lock
only by those two dependency lines. No package was added, removed or moved by the merge.

How it was made (a local job: cargo's resolver reads, the compiler's target specs and the cached dependency sources; no
build, no RCH, no test, no clippy), on a clean `git archive` export of `fd01231` with the S02 landing applied:

    python3 -I scripts/e06/audit.py audit --manifest-path <export>/Cargo.toml --jobs 2 --json audit.json

`cargo metadata --locked --offline` resolved for the host and the two big-endian targets. Exit 3 (review items only):
**0 blockers, 20 review items, 44 info**, the same counts as the S02 lock audit. The target specs read `unavailable`, as in
the two audits beside it. `build_checks` reads `planned=32 pass=0 fail=0 not-run=32`: no build result is folded in, and
nothing here says any of those type-checks passes.

The facts and the decisions left to a person are the S02 audit's (see `docs/contracts/s02.md` section 8): the MPL-2.0
licence of the nine Symphonia crates and the third-party `unsafe` they pull in. The tool admits nothing.
