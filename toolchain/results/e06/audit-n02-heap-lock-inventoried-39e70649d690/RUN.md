# E06 audit of the N02 heap-probe lock, with the locked-but-unlinked entries inventoried

`audit.json` here is the E06 audit (`ffw.e06.audit.v1`) of `Cargo.lock` sha256
`39e70649d690a342c74157bada974cfabaf76bfbbcb4dc05a33fa0af6181c58c` (72 entries), made by the **corrected auditor** (`scripts/e06/audit.py`
changed in the same patch). It is the audit of the same lock as `audit-n02-heap-lock-39e70649d690/`, where that record is also committed
(made before the correction, so it has no record or pin for the three entries below). That directory, `audit-u02-lock-fe219a8abdf9/` and
every earlier audit are left exactly as they are.

## What was missing, and what the auditor now does

Three `Cargo.lock` entries are in **no resolved platform graph**: `curve25519-dalek-derive@0.1.1` and `syn@2.0.119` (the derive's dependency) are
gated on `x86_64` without the `serial` or `fiat` backend, and `fiat-crypto@0.3.0` only under `cfg(curve25519_dalek_backend = "fiat")`; neither
big-endian target and not the `aarch64` analysis host activates either gate. A platform-filtered `cargo metadata` omits them, so the auditor reported
only the information note `lock-unused-entries` and gave them no pin, licence or unsafe fact, which the pinned-inventory consumers (P01-BLK-005 and one
`tests/e06/test_live.py` check) require for **every** locked package.

Now `gather` also takes one more non-building read, `cargo metadata --locked --offline` with no platform filter, which lists every locked package and
its registry cache path. For each lock entry no platform graph links (in an `own` workspace) the auditor:

1. requires the cached `.crate` archive to hash to the lock's checksum, and the extracted source directory to hold exactly that archive's files, byte for
   byte (cargo's own `.cargo-ok` marker aside) and nothing else: no symbolic link anywhere in it (a file, a directory, the marker or the directory itself, whatever it
   points at), no device or pipe, no extra or missing file, checked by name and type before any file is read, and each file opened without following a link. The cached
   archive itself is opened by the same plain-file opener (no link followed, no blocking on a pipe, regular by the descriptor's own type), so a pipe, link, device or
   directory in its place is refused by type instead of hanging the audit before the size cap applies. Every
   step is bounded before it reads on: the archive's size, the extracted tree's entry count (every kind of entry, files, directories and the marker, counted as a lazy
   iterative `scandir` produces it and stopped at the first one over a cap of twice the archive's entry cap plus one, never a whole directory listed at once), the
   archive's inflation (read with a size, never all at once), its entry count, a duplicate name (refused) and each
   member's declared size against the bounded stream; the tar is parsed header by header, never listed whole, only plain files are accepted, and every stream is
   closed. Only then does it read the source with the existing scan;
2. records it like any other package (pin from the lock, licence, unsafe, native signals) with every platform's role `absent` and an `unlinked` object, and
   gives it a `pins.<platform>.rows` row with `role: "unlinked"` on all three platforms. It is **not** marked linked, host-only or reachable anywhere, and the
   label comes from this run's graphs alone, so an entry a later graph links is an ordinary linked record with its own findings;
3. keeps the `lock-unused-entries` information and adds one `unlinked-locked-package` information item per entry carrying its facts;
4. makes a source that is missing, mismatched, different from its archive, over a bound or not located by cargo a **blocker** (`lock-entry-source-missing`,
   `-checksum-mismatch`, `-source-differs`, `-not-located`, `-unsupported-source`) with no record and no pin row. Nothing is fabricated. The same blocker (`-not-located`)
   stands for an audit that was given no lock-wide listing at all, so a library caller cannot get a zero-blocker report that lacks these entries; that is judged only when
   every audited platform resolved, and an upstream or scoped audit, or one with no unused entry, is unchanged.

No consumer gate was loosened. `tests/p01/inventory.py` is unchanged and passes this audit; the one `test_live.py` assertion that refused every `lock-` finding now
excludes only the information note `lock-unused-entries`, and a new test beside it requires every locked registry package to have its record, checksum and pin, and
every entry the note names to be labelled, `absent` on every platform and `unlinked` in every pin list.

## The three entries, read from their verified sources

| Entry | Files compared | Licence | Unsafe tokens | Build script |
|---|---|---|---|---|
| `curve25519-dalek-derive@0.1.1` | 9 | MIT/Apache-2.0 | 5 (`src/lib.rs`) | none |
| `fiat-crypto@0.3.0` | 44 | MIT OR Apache-2.0 OR BSD-1-Clause | 0 | none |
| `syn@2.0.119` | 105 | MIT OR Apache-2.0 | 67 in 10 files (`src/buffer.rs` 29, `src/item.rs` 17, the other eight files 1 to 4 each) | none |

Each is reported as information, because nothing links it. A package with the same facts that a graph linked into a big-endian target would be a review item (`unsafe-in-dependency`)
under the existing rules. Their gates are cfg-gated on `x86_64`, so an audit run on an `x86_64` host would resolve `curve25519-dalek-derive` and `syn@2.0.119` in its graph instead.

## What changed in the audit, by the tool

Against `audit-n02-heap-lock-39e70649d690/` (same lock, same inputs, earlier auditor): 72 packages instead of 69 and 80 findings instead of 77. The only differences are the three added package
records, the three `unlinked-locked-package` items, three `unlinked` pin rows on each platform (so the pin digests change) and the information count. No existing record, finding or pin row
changed, and the counts are **0 blockers, 23 review, 57 info** (54 info before). All 72 lock entries now have a record, and every external one a pin row.

## How it was made

A local job that builds nothing (cargo's resolver reads, the compiler's target specs and the cached dependency sources; no RCH, no test run, no clippy), from a directory outside the
repository so that rustup picks the nightly and the target specs are captured:

    python3 -I -B scripts/e06/audit.py audit --manifest-path <repo>/Cargo.toml --jobs 2 \
        --unsafe-allowed franken-platform-linux --json audit.json

`cargo 1.101.0-nightly (15be64aa0 2026-10-20)`, `rustc 1.101.0-nightly (48f4b0553 2026-10-23)`; analysis host `aarch64-apple-darwin`, targets `mips-unknown-linux-musl` (soft-float) and
`powerpc-unknown-linux-musl`. Exit 3 (review items only). Two runs gave a byte-identical `audit.json`. The input was a clean committed export of `fe32efe` (no overlay): its `Cargo.lock`
(`39e70649d690…`), `crates/franken-alloc-probe/Cargo.toml` (`380540e7af5d2809…`) and `src/lib.rs` (`927842d7e660cd7c…`) are the files the earlier record audited.

## Controls that ran

From the repository checkout under `RUSTUP_TOOLCHAIN=nightly`: the whole `scripts/e2e/e06 --tests-only` suite, 365 tests OK (1 skipped, as before); `tests.e06.test_audit`, `test_rustscan` and
`test_checks`, 172 tests OK (141 before this change); `tests.p01.test_p01.InventoryTests`, 15 OK. `P01-BLK-005` reads **pass** on this audit (55 external packages pinned on host/mips/powerpc,
17 workspace crates recorded), where it failed on the audit without the three entries. The verifier has its own tests (`RegistrySourceVerifierTests`) with exact-bound positives and one-over
refusals for the archive size, the inflation and the entry count (the caps are patched down, so no fixture is large), a decompression bomb and a compressed header storm stopped before any tar
is parsed, a declared member larger than the data, a duplicate name, a hard-link or contiguous-file member, and links, pipes and devices in the extracted tree including a file symbolic link
to byte-identical content and a pipe standing for an archive file (refused by type before any path of the tree is opened, under a watchdog so a regression fails instead of hanging), and a
pipe, a link (to identical bytes) or a directory standing for the cached archive itself (refused by type with no blocking open and no inflate; every open is non-blocking and no-follow). An
audit given no lock-wide listing is blocked, paired with the cases where it must not be (nothing unused, upstream, scoped, a platform that did not resolve). The extracted tree's entry cap
has an exact-bound positive and a one-over refusal for each kind of entry (files, directories, the marker), and a flat storm of extra files and a nested storm of empty directories are each
stopped having pulled exactly one entry past the cap, with the archive never parsed and no file opened. They fail on the first version
(15 tests; the last five alone fail on the previous cut), and a sweep of 35 single planted defects (links, bounds and off-by-ones, the whole-archive listing, open streams, a blocking opener, checksum and content comparison, a refused entry still given a
record, a graph role given to an unlinked entry, no pin rows, the missing-listing rule in each direction) leaves none alive. One existing test fixture
(`ContaminatedGraphTests.test_with_only_review_items_left_the_exit_code_is_three_not_zero`) now drops its leftover entries from the lock with their edges, because a locked entry with no
checksum or a git source that no graph links is a blocker; its assertions are unchanged.

## Boundaries that stand, unchanged

The crypto chain (`ed25519-dalek =3.0.0`, `curve25519-dalek 5.0.0`, `subtle 2.6.1`) is as read in `audit-u02-lock-fe219a8abdf9/`. By source, `build.rs` picks the `serial` backend with 32-bit limbs
for a PowerPC or MIPS build; that is source custody, not an observed build. An x86_64 host build compiles a SIMD-capable backend, while runtime selection depends on CPU features and may choose Serial.
Neither outcome establishes the 32-bit serial arithmetic used by a PPC/MIPS build, and host vector agreement is therefore not target arithmetic evidence. Reading the three unlinked entries does not
change that. `build_checks` reads `planned=34 pass=0 fail=0 not-run=34`: no build result is folded in, and nothing here says any of those type-checks passes.
