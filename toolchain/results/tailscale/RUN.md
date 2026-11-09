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
that does not exist. A run that blocks them exits 3 and is never qualified. (This paragraph and the three receipts above are the record of that first run and are kept as they were: for `T01-X01`
they say BLOCKED because no build record existed then. The next section supersedes it for X01 only.)

## X01: the judge of the captured compile-only build records (2026-11-07)

The contract (section 6) asks for two attempts on each legacy target: the check of the seven core crates AND the same check of the whole library. Root ran them through its strict-remote lane from one
synced root (the pinned tailscale-rs tree, `x01_core` over the seven core crates, and the cargo-resolved lock `89b750bec181a50442b5663f804b34911d706c4b8156778aea3ead94810f52ea`): the core check with
`-p x01_core` and the whole-library check with `--manifest-path tailscale-rs/Cargo.toml -p tailscale`, each on PowerPC and on MIPS. `judge_build_record` in `tests/t01/t01lib.py`, wired into `T01-X01` in
`tests/t01/run_cases.py`, judges the captured logs; the contract section 6 says what it reads and what a pass is. **It judges the captured log, not anyone's account of it. A pass is a type-check only, and
`T01-X01` passes only when all four attempts built.** A stop is kept, named and never read as a pass; core records alone are partial evidence.

The MIPS whole library needed a C compiler for aws-lc-sys that the workers do not have, so it has five records: the first stopped for want of one, then four attempts with a Zig 0.14.1 wrapper. All five are
kept; the last two built.

| attempt | raw log (root's capture, not committed: it holds a worker address and home paths) | committed record (redacted), under `builds/` | judged outcome |
|---|---|---|---|
| core, powerpc | 275,705 bytes, sha256 `ffed89b27665c8646518396077d19d185723cbfa1428a6dbb79cf7caa039aa48` | `x01-core-powerpc-unknown-linux-musl-20261107.log`, 274,459 bytes, `72f5114291c4c4a173d4fea7135cc643e81332c3d2b3df9bd9f8461f064a9748` | BUILT: 176 artifacts (119 crates.io, 19 tailscale-rs, `x01_core`, 11 std/toolchain), rch exit 0 |
| core, mips | 274,468 bytes, `8719715de99f7072b8d9a01a2e687f3a4fbc992b1c7179b923604e18b3075177` | `x01-core-mips-unknown-linux-musl-20261107.log`, 273,222 bytes, `f3a8274b50f41f3853c13bde182f68b6e3a38104943ac95fc2b048b024a3ae1e` | BUILT: the same counts |
| whole, powerpc | 445,069 bytes, `473ea8b8967c149abf4437f6c905315cc8ff01d19f8137495fd7fa86a2b6d57a` | `x01-whole-powerpc-unknown-linux-musl-20261107.log`, 443,823 bytes, `8391da0a6ee1619dc0d9aeabd6542bd8475f158c12226c857effaf4bacbcbbfe` | BUILT: 340 artifacts (243 crates.io, 36 tailscale-rs packages including `tailscale`, 11 std/toolchain), `Finished dev` in 4m 24s, rch exit 0 |
| whole, mips (1: no C compiler) | 284,143 bytes, `b7a372794e724d658fcbfc7817b6f242aa361effc39aefaf8f6710a2c8a8c1a7` | `x01-whole-mips-unknown-linux-musl-20261107.log`, 283,239 bytes, `119161ccd4349419019fa3e63144c33b68fcd94a38eb217632ad99eb3d31ca1e` | STOPPED at the `aws-lc-sys v0.45.0` build script (exit 101 in cargo, rch and the receipt, after 145 artifacts): cc-rs found no `mips-linux-musl-gcc` on the worker. A toolchain blocker, not an ISA or source finding |
| whole, mips (2: inline config) | 97,825 bytes, `34bd8a68eb69fb3f24da69733217ceaa183c54feb6b9fffc45b8839fb6b842e5` | `x01-whole-mips-unknown-linux-musl-zig-inline-20261107.log`, 97,233 bytes, `b66a5e6ec0ae794da0f586cdf5b02b11d51085994ff502a149cfd7e315eff9bb` | REJECTED by cargo before it built anything (no cargo message, exit 101): the one-argument inline-table `--config` for the original wrapper is not accepted. A syntax failure, not an ISA or source finding |
| whole, mips (3: original wrapper) | 311,919 bytes, `a181d2471819952fdf28e265b8c3c1553147ab6b8e207b76b42cc301f9f408f0` | `x01-whole-mips-unknown-linux-musl-zig-keys-20261107.log`, 311,081 bytes, `9c041c477ae69d54682dc94aa1c7f26e7a2e1346597276f2314d96b1791675c7` | STOPPED at `aws-lc-sys v0.45.0` (exit 101, 145 artifacts): three explicit keys, the repository's own wrapper `x01-cc/zig-cc-mips-be`; Zig answered `unable to parse target query 'mips-unknown-linux-musl'` because cc-rs appends the Rust `--target=` spelling. An adapter failure, not an ISA or source finding |
| whole, mips (4: adapter, first) | 438,111 bytes, `9b946b63c090ce7c5c118fa8879c9a9b69c22bd2d37aeef7c86788c1f5b3ad80` | `x01-whole-mips-unknown-linux-musl-zig-ccrs-20261107.log`, 436,931 bytes, `0a6401ab1e6df450bf618e866a697b47e0ecd5a9f09f4edc4d3125499749dd1a` | **BUILT**: 340 artifacts, `Finished dev` in 3m 25s, rch exit 0, with the adapter `x01-cc/zig-cc-mips-be-ccrs` (sha256 `17848d169db2dc71d048a13999c8a605104b6b77d3e846b2359039ab725bfa8d`) set by exactly three explicit cargo env keys; 552 synced files, the two extra ones being the two pinned wrappers |
| whole, mips (5: adapter, hardened) | 430,054 bytes, `e3f0d6158728b52a4ae790afa96b490df7d36ae55f65d2b164e150d31c902619` | `x01-whole-mips-unknown-linux-musl-zig-ccrs-v2-20261107.log`, 428,874 bytes, `dee4fadaf85330546356fac1e61acedb04cd5116e481c2d17739818a11b3fba3` | **BUILT**: 340 artifacts, `Finished dev` in 41.34s, rch exit 0, with the hardened adapter `x01-cc/zig-cc-mips-be-ccrs-v2` (sha256 `3dc93ff4f618cd96f1a8f4dbe68b0f37a9712778d3bf0f3f6e3d634eb61e64ab`) set by exactly three explicit cargo env keys; 553 synced files, the three extra ones being the three pinned wrappers. The configured path differs from record 4, so cargo reran the C build instead of trusting objects from the earlier run |

The records are made by `scripts/e2e/t01 --redact-build-log RAW DEST` (terminal colors removed; IPv4 addresses, the login name used to reach a worker, and the local and remote home-directory prefixes replaced by
`<ip>`, `<user>`, `<local>` and `<home>`); the judge reads the same facts from the raw and the redacted text. The resolved lock is committed as `tests/tailscale-fixtures/x01/consumer.lock` (183 packages: 163 crates.io,
20 path). For every attempt the tailscale-rs tree digest is RECOMPUTED from rch's per-file list and equals the pin `400e6b2e...`, the four consumer files equal their pins, and no cargo config, toolchain override or
build script is synced. The C compiler wrappers: the original is the repository's own `toolchain/linker/zig-cc-mips-be` byte for byte (sha256 `b0d60bcb...`); the first adapter is committed as
`tests/tailscale-fixtures/x01/x01-cc/zig-cc-mips-be-ccrs` (unchanged, its recorded build stands) and drops exactly `--target=mips-unknown-linux-musl` and `--target=mips-linux-musleabi`, refusing `--target=OTHER` and
`-target` but, by an oversight in its own wording, forwarding the bare two-argument `--target OTHER` and `-target=OTHER`; this did not touch the recorded cc-rs invocation, which only appends `--target=`. The hardened
adapter `x01-cc/zig-cc-mips-be-ccrs-v2` (sha256 `3dc93ff4...`, committed beside it) refuses all four spellings; all three enforce Zig 0.14.1.

| item | value |
|---|---|
| `T01-X01` on the committed records | **PASSED**: all four required attempts built (type-check only); the account lists the three earlier stops of the MIPS whole library and both wrappers that built it; nothing is linked or run |
| `scripts/e2e/t01 --tier full --sources SOURCES_DIR --receipts ...` | `t01-09ad140ddcc4f2c3.json`: exit 3, **14 passed, 0 failed, 1 blocked** (`T01-X02`); diag `events=31 critical=31 dropped=0 critical_lost=0`, complete |
| `python3 -B -W error -m unittest tests/t01/test_t01.py` | 80 tests (the 48 earlier tests, of which three that assert the state before any build record existed and one that pins the profile version are changed on purpose, plus 32 in `BuildRecord`), OK; with `T01_SOURCES` set to the pinned trees the real-tree test runs too |
| `scripts/e2e/t01 --tier full` (no sources) and `--tier smoke` | 9 passed / 0 failed / 6 blocked, exit 3; 8 passed, exit 0 |
| P01 smoke on a git-archive export of the base, before and after | see the hand-off mail: identical per-case statuses |

The three earlier tests changed here assert the state before any build record existed, which is no longer the repository's state: the runner's passed and blocked case sets, the receipt counts (8 passed, 7 blocked
became 9 and 6) and the entry point's `planned=15 passed=8 failed=0 blocked=7` (now `passed=9 blocked=6`, with `T01-X02` asserted blocked). Nothing was weakened: each now asserts the new state exactly.

Paired falsifiers (each is made in a copy of a real record's text, must be reported for the named reason, and the unplanted record must pass again): everything listed in the earlier version of this section (wrong target,
missing crates, stale or changed inputs, truncated and failed logs, every disagreement between the three terminal witnesses, a changed command, a foreign package), and for the C compiler configuration: an unpinned
wrapper path, a missing key, an extra key, a different environment variable, a patched dependency, a command and remote command that disagree, the configuration on another target, the refused inline spelling
claimed to have built, a changed wrapper, the original wrapper changed, the configured wrapper not synced, an unpinned file beside the wrappers; for a cargo refusal: no error text, exit 0, another exit in the receipt, no exit
line, cut before the receipt. The two new stop classes are read only from the log's own text (changing or removing that text makes the stop `unclassified`, and a refused argument that this command did not carry is not
that class). The adapter itself is run with a stand-in `zig`: it drops exactly the two known target spellings, refuses any other override (exit 98) and any other Zig version (exit 97). The account is shown to fit the
shared 1024-character detail bound with the compile-versus-runtime boundary stated first, so nothing can truncate it away.

The hardened adapter is tested with a stand-in `zig`: it refuses `--target=OTHER`, bare `--target OTHER`, `-target OTHER` and `-target=OTHER` (and a bare `--target` or `-target` without a value), exit 98, still
drops the two known spellings, forwards every other flag in order (flags that only mention "target" are not overrides) and refuses any other Zig version (exit 97). The first adapter is run beside it as the retained
baseline: it forwards the two spellings the hardened one refuses and refuses the two it always refused, so the oversight is documented by a test rather than by prose.

Profile and study wording (decision record for `t01-profile-2026-11-07.1`, which replaces `t01-profile-2026-11-06.1` as the profile's own rule asks): the statements that said nothing was built or that no build receipt
existed were true when written and are not true now, so they are corrected WITHIN the proven compile scope and nowhere else. Changed: the profile's status line, the per-cell `build` blockers of the four tailscale-rs
targets (a type-check of the whole library and its seven core crates passed for the target's triple; no linked build has been made, so the figure stays pending), their `binary_bytes` blockers (`cargo check` does not
link, so no binary exists), the two Go-client `build` blockers (they pointed at T01-X01, which covers tailscale-rs only), the three platform notes that said nothing was built, the workspace-edge note,
`t01_status`, `closes_note`, and the stale lines in `feasibility.md` and the contract. **Unchanged, and tested as unchanged:** every platform state (`ppc32be_stock` stays `incompatible` on the kernel's missing
`epoll_create1`; the other three stay `no_evidence`; none becomes `build_ok_unrun` or `ran_on_target`, which need a receipt), every measurement state (all pending: a type-check is not a build, a binary, an RSS or a CPU
figure), every evidence citation, every cell, the native requirement (required, unwaived, unsatisfied, closes nothing) and `T01-X02`. The version pin in `test_the_committed_profile_holds` moved to the new version.

PROVENANCE LIMIT (also in the contract): the successful log does not show the compiler being run. That Zig 0.14.1 compiled aws-lc-sys's C sources rests on the pinned wrapper file, which enforces the version, the three
keys that point cargo at it, the synced hash that says which file it was, and the three earlier records of the same attempt without it; it is not observed in the log.

LIMITS (also in the contract): the log is not signed, so a log edited consistently everywhere is indistinguishable from a real one; rch's own `receipt_root`, `content_root` and `command_sha256` are recorded, not
recomputed; the separate status file and any custody note are not used; for the whole-library attempts the judge does not re-derive the closure against the upstream lock (`--locked` and the pinned tree digest, which
includes `tailscale-rs/Cargo.lock`, carry it); the redaction removes addresses, the login name and home paths, nothing else. A pass says the commands type-checked what they name. It says nothing about linking,
running, memory, CPU, enrollment or a native endpoint, and `T01-X02` and the native requirement are untouched.

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

No link or run of any candidate for any target, no on-target or guest figure, no enrollment, and no crypto known-answer probe. The compile-only X01 records are type-checks: the seven core crates and the whole
library on both targets (the MIPS whole library with a pinned Zig 0.14.1 C compiler wrapper after three earlier stops). The lock walk behind the earlier import list (`core_import_manifest`) remains
in this study, and the resolved lock fixture is what the judge holds a core log against. `ledger-pass*` drafts of the evidence ledger and the scratch fetch directory are kept privately by the author.

## Central verification of the final v6 judge (2026-11-07)

The final integrated judge passed all85 Python tests with warnings treated as errors and all three pinned source trees supplied. The full run produced `receipts/t01-0db87ae2afa33766.json`:14 passed, zero failed, one blocked (`T01-X02`),31 critical events and zero lost. No client was linked, executed or enrolled. The type-check evidence covers both the seven core crates and the whole library on each BE32 target; the five successful records cover those four attempts and the three earlier stops remain recorded. Native/platform/measurement states stay unadmitted.

Independent supervisor review reproduced rejection of empty remote commands and cross-target promotion with missing output filenames. Required target artifacts now have nonempty output witnesses under the selected target directory. A second independent review reproduced byte-for-byte equality between all eight public records and redactions of their original raw logs; no public record was unmatched or ambiguous. The logs remain unsigned and do not themselves establish runtime or resource behavior.

Root also corrected three current-status statements that still said no BE build evidence existed: the native-requirement summary, the contract comparison table and its no-claim list. Earlier dated records above stay historical. The initial root source-dependent test used the build snapshot without the aws-lc-sys/mio sibling trees and failed; correcting that input, without changing tests, yielded85/85. A new native client guest measurement is still required for qualification.

## Profile version t01-profile-2026-11-09.1 (2026-11-09)

Decision record for `docs/tailscale/profiles.json` version `t01-profile-2026-11-09.1`, which replaces `t01-profile-2026-11-07.1` as the profile's own rule asks (a changed fact makes a new version and a
decision record, never a silent edit). Cause: the two X02 guest receipts committed on 2026-11-08 (`measurements/x02-v3b-mips-20261108.json` and `measurements/x02-v3b-powerpc-20261108.json`, each judged,
`T01-X02-target-resources` passes) made the profile's X02 statements untrue: its status line, `t01_status`, `closes_note`, the last sentence of `study_outcome` and the `rss_peak_bytes` and `cpu` blockers of the four
tailscale-rs rows said X02 was blocked or that no harness-guest figure had been run, and `docs/tailscale/feasibility.md` said the same.

Changed, and only within the proven scope (the X02 probe ran once in one harness guest per architecture; it links the seven core crates and a known-answer phase and is not a client): those five profile statements,
and the study text (the dates and profile version in its header, the outcome paragraph, and item 5 of "What would change the answer"). Added: five scenario items, `scenario_enrollment`,
`scenario_maps_at_peer_cap`, `scenario_reconnect`, `scenario_relay_traffic` and `scenario_key_rotation`, to every one of the eight `measurements` rows (the bead's tailnet resource table: "identity enrollment, maps at
the declared peer cap, reconnect, relay traffic and key rotation while audio runs"), each `pending` with its exact blocker, or `not_applicable` for the Go client on the two PowerPC targets (no Go port,
`T01-E01`). `check_profile` (`tests/t01/t01lib.py`) now refuses a row that lacks one of the five, and refuses `not_applicable` on **any** measurement item (the four earlier ones too) unless the candidate has no
build for the target at all (`has_no_build_for_target`). That is derived from the profile's own facts, not from a list of rows: the candidate's language is Go, the target's Rust triple is powerpc, and its platform on
that target is `incompatible` with `T01-E01` (Go 1.27.3 has no 32-bit linux/ppc port) among the evidence. It admits exactly two rows, the Go client on `ppc32be_stock` and `ppc32be_harness` (nine items each, eighteen
in all, ten of them scenario items); a tailscale-rs row has a build path on every target, so a figure it lacks stays `pending` with its blocker and cannot be hidden as inapplicable.

`check_profile` also refuses `"state": "measured"` unless the item's `receipt` names a `.json` file directly under `toolchain/results/tailscale/measurements/` that exists as a plain regular file and parses as a JSON
object (`receipt_problem`; the runner's `T01-META-PROFILE` passes the repository, so a bare string such as `x` or a missing file fails the case). No row is measured today, so nothing changes now; this holds before any
row is marked measured. It does not judge that the file holds the figure: that is `x02_judge.judge_receipt`'s job, and nothing binds the item's value to the receipt yet.

The same rule, with its own directory, applies to a platform state `build_ok_unrun` (`receipt_problem(..., "build_ok_unrun")`, wired into the platform loop of `check_profile`): the `receipt` must name a `.log` or `.json` directly
under `toolchain/results/tailscale/builds/` (where `run_cases.BUILD_DIR` reads the captured build records, contract section 6) that exists as a plain regular file, and is a non-empty UTF-8 text for a `.log` or a JSON
object for a `.json`. `ran_on_target` is not touched: it already derives a `supported` cell, which `check_profile` refuses. No platform claims a build today. **Limit:** an X01 log is a `cargo check` record, so it satisfies
the form although a type-check is not a linked build, and no judge exists for a linked build yet; the rule makes the claim name a real record, not prove it is a build. Planting the state on the two Go PowerPC rows is refused by the
`not_applicable` rule instead, since the profile cannot say both that no build exists and that one does.

The blockers say what is missing and nothing more. No linked tailscale-rs client exists on any target (X01 is a type-check); a real tailnet is a provider and needs a separate authorized receipt (the bead's
evidence rule); no audio path runs beside the component (Q04 and Q06 own that); no peer cap is declared for the tailnet component in any T01 artifact (`docs/SLIM_SPEAKER_PLAN.md`: every profile declares maximum peers;
`tailnet_ram_cap_bytes` stays null, T04/Q02 allocate it); and tailscale-rs 0.6.1 has no automatic key rotation (`T01-E15` to `T01-E17`), so there is no flow to measure. Where a scenario needs a registered
client, the blocker also names the reported `Device::new` hang (the library's registration path does not return against a refusing control address) **as a report from the T01-X03 study, not yet a committed
receipt**; when that receipt is committed, this wording is the line to tighten.

**Unchanged, and tested as unchanged:** every platform state (`ppc32be_stock` stays `incompatible` on the kernel's missing `epoll_create1`; the other three stay `no_evidence`), every behavior and cell, every evidence
citation, the `build` and `binary_bytes` items, the Go client's `rss_peak_bytes` and `cpu` blockers (still true: no Go figure exists), every measurement state (all pending or not applicable: a probe reading is not a
client figure, and no X02 figure was copied into the profile), the budgets (no cap allocated), and the native requirement (required, unwaived, unsatisfied, closes nothing, does not close T02, T04 or Q06).
No negative result is recorded: BrightLion's ruling (Agent Mail 16942) allows a bounded `Device::new` timeout to be recorded as a negative study result only once every original study requirement is covered, and
this version does not claim that.

Paired tests (`tests/t01/test_closure_map.py`, both directions, each plant restored): the five items on every row and their states, a planted missing, `measured`-without-receipt, mis-stated or blocker-less item reported;
the profile and the study carry none of eight stale X02 sentences while the receipts are committed, and a stale sentence put back is reported; the blockers name receipt files that exist; the decision record
exists. The version pin in `test_the_committed_profile_holds` and `test_the_x01_statements_in_the_profile_and_the_study_match_the_recorded_scope_and_strengthen_nothing` (`tests/t01/test_t01.py`) moved to the
new version, and the latter's two assertions that the status line says `nothing linked or run` and that `t01_status` says `nothing was linked or run` became `no client linked or run` and `no client was
linked, run or enrolled`: the same facts, worded for a repository in which the probe has run. No other assertion in `test_t01.py` changed.
