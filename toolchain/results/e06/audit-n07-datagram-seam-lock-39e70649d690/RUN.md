# E06 audit of the N07 datagram-seam candidate `90606cc`, same lock as the heap-probe records

`audit.json` here is the E06 audit (`ffw.e06.audit.v1`) of a clean committed export of **`90606cc`** (`feat(platform): add bounded datagram peer I/O and BE socketcall routes`),
for `Cargo.lock` sha256 `39e70649d690a342c74157bada974cfabaf76bfbbcb4dc05a33fa0af6181c58c` (72 entries), made by the corrected auditor of
`audit-n02-heap-lock-inventoried-39e70649d690/` (so every locked entry has a record and a pin, including the three that no platform links).

It is a **candidate-scoped artifact**: it describes exactly that commit and nothing after it. The record of `fe32efe` in `audit-n02-heap-lock-inventoried-39e70649d690/` (and the
earlier ones) stay as they are, historical.

## What differs from the `fe32efe` record, by the tool

The same lock, the same 72 packages, the same pins and the same three `unlinked` records. Counts are the same, **0 blockers, 23 review, 57 info**. The only differences:

* `franken-platform-linux`: **21 unsafe tokens, all in `src/sys.rs`, where there were 19** (the crate is in the unsafe-allowed policy input, so it stays the information item
  `workspace-unsafe-permitted`; the item's text now says 21). Five source files are scanned, where there were four (the new `src/datagram_route.rs`, which holds no unsafe token).
* `franken-platform`: one more source file scanned (the new `src/datagram.rs`); it holds no unsafe token.

The tool counts `unsafe` tokens. Whether the two additional ones are sound, and whether the leaf's boundary is the minimal one, is a reading of the source by a person and is not decided here.

## How it was made

A local job that builds nothing (cargo's resolver reads, the compiler's target specs and the cached dependency sources; no RCH, no test run), from a directory outside the
repository so that rustup picks the nightly and the target specs are captured:

    python3 -I -B scripts/e06/audit.py audit --manifest-path <repo>/Cargo.toml --jobs 2 \
        --unsafe-allowed franken-platform-linux --json audit.json

`cargo 1.101.0-nightly (15be64aa0 2026-10-20)`, `rustc 1.101.0-nightly (48f4b0553 2026-10-23)`; analysis host `aarch64-apple-darwin`, targets `mips-unknown-linux-musl` (soft-float) and
`powerpc-unknown-linux-musl`. Exit 3 (review items only). Two runs gave a byte-identical `audit.json`. Reproducing it needs the corrected auditor.

## Boundaries that stand, unchanged

The crypto chain and its compiled-versus-runtime boundary are as written in `audit-u02-lock-fe219a8abdf9/` and `audit-n02-heap-lock-inventoried-39e70649d690/`: by source the 32-bit `serial`
backend is selected for a PowerPC or MIPS build, which is source custody and not an observed build, and host vector agreement is not target arithmetic evidence. `build_checks` reads
`planned=34 pass=0 fail=0 not-run=34`: no build result is folded in. `P01-BLK-005` binds the lock only, so this record neither changes nor adds to what that case judges.
