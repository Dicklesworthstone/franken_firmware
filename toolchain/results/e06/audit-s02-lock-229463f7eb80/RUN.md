# E06 re-audit for the S02 lock change (`franken-codec` + Symphonia 0.6.1)

`audit.json` here is the E06 audit (`ffw.e06.audit.v1`) of the workspace as it is with the S02 slice: `Cargo.lock` sha256
`229463f7eb80c932987e06ef27c32c345c6ebf7c2dbab2923702711dab817bb8` (61 entries; the base lock `8e3ea0d826c2eceaea978d7c64cbfb5c45e30c7eff6359617071c4d2e5364f82`
had 42, and the change is purely additive: 19 packages added, none removed or changed). It is kept beside the earlier audits, not over them, as the
`08d5a002` re-audit was. P01-BLK-005 prefers an audit that binds the current lock; an older audit beside it never blocks it.

How it was made (a local job: cargo's resolver reads, the compiler's target specs and the cached dependency sources; no build, no RCH, no test, no clippy):

    CARGO_HOME=<private home that ran `cargo fetch`> python3 -I scripts/e06/audit.py audit --manifest-path <export>/Cargo.toml --jobs 2 --json audit.json

on a clean `git archive` export of `0f963c8` with the S02 delivery, the S02 P01 rows and the S02 lock delta applied. `cargo metadata --locked --offline` resolved
for the host and the two big-endian targets. Exit 3 (review items only): **0 blockers, 20 review items, 44 info** (the `08d5a002` audit: 0, 13, 37).
The `host` section and the target specs come from the compiler on the machine that ran it (`aarch64-apple-darwin`).

**No build results are folded in.** `build_checks` reads `planned=32 pass=0 fail=0 not-run=32`: the run7 type-checks were of another lock and another
crate set, so they are not carried over. The 30 older lines have to be re-run with the new lock and the two new lines (`franken-codec` x mips/powerpc)
have never been run; that is a central job and nothing here says any of them passes.

## What the S02 closure adds (19 packages; facts, not decisions)
| package | licence | unsafe tokens in its own source | note |
|---|---|---|---|
| `symphonia` 0.6.1 and its 8 `symphonia-*` crates | **MPL-2.0** | 0 (`forbid(unsafe_code)` declared, except `symphonia-common`: none declared, none present) | the crates.io packages are built from the commit E06 pinned (`ee35874b571a`); `src/` is byte-identical to that checkout |
| `bytemuck` 1.25.2 | Zlib OR Apache-2.0 OR MIT | **332** | pulled in by `symphonia-core`; the parent's `forbid(unsafe_code)` does not cover it |
| `smallvec` 1.16.4 | MIT OR Apache-2.0 | **80** | pulled in by `symphonia-core`, `symphonia-metadata` |
| `log` 0.4.35 | MIT OR Apache-2.0 | 6 | |
| `bitflags` 2.13.2, `lazy_static` 1.5.1, `num-complex` 0.4.6 | MIT OR Apache-2.0 | 2 each | |
| `num-traits` 0.2.19 | MIT OR Apache-2.0 | 1, and a **build script that uses `autocfg`** | a compiler probe, not native code |
| `autocfg` 1.5.1, `regex-lite` 0.1.9 | MIT OR Apache-2.0 | 0 (`regex-lite` declares `forbid`) | |

Decisions that stay with a human (the tool admits nothing): the MPL-2.0 licence of the nine decoder crates (file-level copyleft; what it requires of a
firmware distribution is a licensing decision, not a build fact); the third-party `unsafe` above, most of it `bytemuck`; and whether the 18 new crates'
cached sources are on every worker (`--locked --offline` refuses without them).
