# T01 run record (bead ffw-32a): native Tailscale feasibility, offline

Date: 2026-11-06. Run on the orchestrator host (macOS, Python 3.15.0) by the T01 owner. **No cargo build, no rch job, no network contact beyond read-only fetches of public sources, no
login, enrollment, device or provider.** Contract: `docs/contracts/t01.md`; study: `docs/tailscale/feasibility.md`; profile: `docs/tailscale/profiles.json`
(`t01-profile-2026-11-06.1`).

## What was fetched (read-only; commands in `tests/tailscale-fixtures/evidence/FETCH.md`)

| input | pin | digest |
|---|---|---|
| tailscale-rs v0.6.1 | commit `d34658bbb2eb4593ae6df959aa93e9ee1e0457c6` | tree digest `400e6b2ebd40134a490d47a4d3a111e9a976b6a637675057d9536f8299d73d06`; `Cargo.lock` sha256 `4745e012086b9abeb901c26541e95cea35cb65a868a3a76fc95b018e6fe8b6fd`; the GitHub tarball as downloaded was `b5dc106a7b62054b8a9f515cd5b8b70f95c1663d4aca8bca09cc5c021b254e80` (not byte-stable across downloads; the tree digest is the pin) |
| aws-lc-sys 0.45.0 | crates.io | crate sha256 `9bff6c3b54fad79a2e60b8102caf565819711497c1f5f092f49508e2f5c31b27`; tree digest `54f614b4be438cdd31a1a55205f25146426553dea64de14ce5c6ef3e73e17bd9` |
| mio 1.2.1 | crates.io | crate sha256 `02bd0af71c67b473010cbbc60715ee815645a4dc942899111f494b4b737d6fda`; tree digest `30c857b9b9781fd4bb8e9a0d36149bfe51d9cfc44f061cddd3d47b5a012347d2` |
| tailscale v1.104.5, Go 1.27.3 files, documentation pages | see the ledger (`T01-E01` to `T01-E47`) | per-entry digests of what was retrieved |

The pinned trees are not committed (third-party source). `--sources DIR` re-checks them; the ledger holds the excerpts.

## Runs (receipts and JSONL logs in `receipts/`, each with the sha256 of every artifact judged)

| command | receipt | outcome |
|---|---|---|
| `scripts/e2e/t01 --tier smoke --receipts toolchain/results/tailscale/receipts` | `t01-8cdc69be60fccfa2.json` | exit 0, 8 passed; diag `events=17 critical=17 dropped=0 critical_lost=0`, complete |
| `scripts/e2e/t01 --tier full --sources SOURCES_DIR --receipts ...` | `t01-01665612603d232e.json` | exit 3, **13 passed, 0 failed, 2 blocked** (`T01-X01`, `T01-X02`); diag `events=31 critical=31 dropped=0 critical_lost=0` |
| `scripts/e2e/t01 --tier full --receipts ...` (no sources) | `t01-9f4270b321a6868a.json` | exit 3, 8 passed, 7 blocked (the five source probes and the two central cases) |
| `scripts/e2e/t01 --tier soak` | none | exit 4, NOT RUN |
| `python3 -B -W error -m unittest tests/t01/test_t01.py` | none | 48 tests (30 before the review fixes + 11 in `Bounds` + 7 in `ReadBoundary`), OK, 1 skipped (the real-tree probe test, which needs `T01_SOURCES`); with `T01_SOURCES` set to the pinned trees the skipped test also passes (48/48) |
| `python3 tests/p01/run_cases.py --tier smoke` | none | before registering the two new test directories: 243 passed, 1 failed (`P01-CON-002 asset_uncovered[tests/t01]`), 7 blocked; after: **244 passed, 0 failed, 7 blocked**, unchanged from main |

The two blocked cases are the point of the study, not an omission: `T01-X01` (the exact legacy-ISA build) needs a central build and `T01-X02` (on-target memory and CPU) needs a guest
that does not exist. A run that blocks them exits 3 and is never qualified.

## Cross-checks with a different tool

* `grep -c '^\[\[package\]\]' Cargo.lock` on the pinned tree: **689**; the probe (`tomllib`): 689 (`T01-P01` also holds the independent anchor in `cases.json`).
* An earlier exploratory script, written separately from the probes, gave the same census: 689 packages, 621 distinct names, 590 reachable from `tailscale` (over-approximate), 37 workspace
  crates in that closure, 45 declared members, 5 crates with `forbid(unsafe_code)`, and the same `unsafe` token counts per crate. The probes' definitions are fixed in `t01lib.py`.
* The workspace-edge lists (23 crates with no INTRA-WORKSPACE edge to the runtime/OS/TLS allowlist, 20 with one) were first obtained from the manifests by a scratch script and are recomputed
  by `T01-P02-workspace-edges`. This is not a portability list: nine of the 23 (including `ts_tunnel`, `ts_keys`, `ts_noise`) reach `libc` through their third-party closure in the pinned lock
  (`rand` 0.10.2 -> `getrandom` 0.4.3 -> `libc`; declared normal and build edges, every target and feature, an over-approximation), so they stay unqualified until a selected Cargo graph and build.

## Review corrections (independent review of the first cut, mails 7998 and 7999)

1. A present but malformed source tree raised an uncaught `FileNotFoundError` (with the private path) before the case log opened. Now every case runs under `guarded`: an error is a FAILED case
   whose detail names the exception type and, for I/O, the base name only; the case log is opened before the first case and a crash outside a case is recorded as a failed `T01-RUNNER`.
2. The probes ran in-process over unbounded trees (review 7998/7999), and the first fix bounded only the preflight (review 8056: a file grown to 8,388,609 bytes after the preflight was still hashed in
   full, and a deadline called off the main thread or without `setitimer` silently ran the probe). Now each supplied tree is admitted by an `lstat`-only walk (lazy directory listing with an entry cap;
   refuses any symlink, any non-regular file, a file over 8 MiB, more than 5000 files or 160 MiB, more than 16 levels, or a walk over 30 s) and is then read ONLY through `Source.read`: same root
   (device and inode), every path component opened with `O_NOFOLLOW` relative to its parent, a regular file of exactly the admitted size opened nonblocking, the read stopped at that size plus one
   byte, a 320 MiB total; hashing, the TOML/text probes and the ledger re-cut all consume those bytes. A file that was not admitted is never opened. `with_deadline` fails closed: a passed deadline
   raises, and without SIGALRM in the main thread the probe is not run and its case fails. The pinned trees measure at most 2029 files, 67 MB, 3.3 MB per file and 8 levels, so they pass with room, and
   their tree digests are unchanged. Limits: this is an in-process guard plus an alarm, not an owned child process; a same-size content swap after admission is not detected by the read (the pinned
   tree digest and the ledger digests are what catch changed content); the admission walk itself lists by path, so a swap during the walk only changes what is admitted, and every read re-checks.
3. `probe_portable_core` was renamed `probe_workspace_edges` and reports only intra-workspace edges; `probe_third_party_reach` adds the lock-derived third-party reach. The docs, profile and contract no
   longer say portable, runtime-free or OS-free.
4. The profile status, `native_requirement.closes` (now empty) and `feasibility.md` no longer say the study closes T01: it is INCOMPLETE and pending while X01/X02 are blocked.

## An observation that is not a pin

This machine's offline cargo registry cache (`~/.cargo/registry/src/*/`) holds **473 of the 643 registry packages** (exact `name-version`) in the pinned `Cargo.lock`; 170 are absent, among
them `smoltcp`, and the locked `tokio` 1.52.3 is absent (other 1.53.x are present). The count depends on this machine and on the date, so it is not recorded in the profile. It matters because
the repository is offline-only: a `cargo --locked --offline` build of the candidate needs those sources imported first (an authorized step), which is part of the blocker on `T01-X01`.

## Not done

No build of any candidate for any target, no on-target or guest figure, no enrollment, and no crypto known-answer probe. The X01 central lines are unproven: a `cargo metadata --offline` of a
scratch consumer workspace over the seven core crates failed on this machine at a missing registry package (`crypto_box`), so an authorized registry import step must precede them; only the lock walk behind it (`core_import_manifest`, used by the third-party reach probe) is in this patch; a committed import manifest, its check and a consumer-workspace form of the lines are NOT. `ledger-pass*` drafts of the evidence ledger and the scratch fetch
directory are kept privately by the author.
