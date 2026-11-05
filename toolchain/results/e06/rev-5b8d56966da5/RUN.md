# E06 central `cargo check` run at revision 5b8d5696, 2026-11-05

The minimal-graph build checks planned by `scripts/e06/audit.py plan`, run centrally, and the audit of the same
revision with those results folded in. **They are type-checks.** `cargo check` shows that the pinned dependency graph
resolves and type-checks for each big-endian target with `-Z build-std=std,panic_abort`. It does not show that
anything links, runs or boots, and it says nothing about a stock Sonos kernel, the audio driver or a physical board.
Linking `franken-speaker` is P01-BLK-002 and is not covered here.

## Who did what
- **The 24 checks were run by the supervisor (BeigeMaple)**, centrally, from a clean `git archive` export of
  revision `5b8d56966da5dc1050c074adf21fdb738ad4a408` with `scripts/e06` copied in, on RCH worker `ts1`.
- **YellowBrook did not run them.** YellowBrook wrote the planner and the analyzer, regenerated the plan from the same
  revision (byte-identical to the supervisor's plan), verified every result row against its raw log with
  `audit.py ingest`, and ran the audit.

## Command
Each of the 24 planned lines ran exactly (RCH adds only its own `--config env.RCH_*` trailer, which the ingest
removes before comparing):

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p <crate> \
  --target <mips|powerpc>-unknown-linux-musl -Z build-std=std,panic_abort -j 2
```

`plan.txt` is the planner's output for this revision. `--jobs 2` is in the command because RCH admits a build against
a worker's slot count and ignores `CARGO_BUILD_JOBS`.

## Results (denominator: 12 workspace crates x 2 targets = 24)
| | mips-unknown-linux-musl | powerpc-unknown-linux-musl |
|---|---|---|
| pass | 12 | 12 |
| fail / not-run / conflicting | 0 / 0 / 0 | 0 / 0 / 0 |

Every check exited 0 on worker `ts1`, with a cargo `Finished` line, no warnings and no error lines; the 24 remote
runs took 194 s in total. All 24 are `std,panic_abort`: none of the crates qualifies for `core,alloc` because serde,
thiserror and others link `std` under the features cargo enabled.

## What was verified, and what was not
`audit.py ingest` does not trust the supplied results file. For each row it reads the raw log and requires: the
command the worker ran equals the planned command; the remote exit status is the row's `rc` and is 0 exactly when
the row says `pass`; a `Finished` line is present and there is no error line; the worker and revision in the row's
note are the log's and the expected revision. It also requires that every planned check has exactly one result and
that no result is for an unplanned check. Nothing is written unless every claim is supported. `checks.jsonl` is that
verified record.

**The raw logs are not committed.** RCH prints the worker's network address, the absolute paths of the machine that
ran the checks (including a user name) and the worker's home directory into them, and this repository is public.
`checks.jsonl` keeps the exact command, exit status, elapsed times, the number of units type-checked, warning and error
counts, and the **sha256 and size of each raw log**, so the log can be produced later and shown to be the one
summarized. The logs are held by the supervisor; this directory does not contain them and nothing here can be
re-derived from them without them. The worker is recorded by alias only.

## Files
| file | what it is |
|---|---|
| `plan.txt` | the 24 planned commands (`audit.py plan --jobs 2` on the export of this revision) |
| `checks.jsonl` | one verified, redacted record per check (schema `ffw.e06.checks.v1`) |
| `audit.json` | the full audit report (`ffw.e06.audit.v1`) of this revision with `checks.jsonl` folded in |

To re-verify: with the raw logs and the supervisor's results file, `audit.py ingest --plan-file plan.txt --results
<results> --logs-dir <logs> --rev 5b8d56966da5dc1050c074adf21fdb738ad4a408 --out <new file>` must reproduce
`checks.jsonl` byte for byte; and `audit.py audit --manifest-path <export of the revision>/Cargo.toml --build-results
checks.jsonl --jobs 2` must reproduce the counts in `audit.json`. The `host` platform and the target specs in
`audit.json` come from the compiler on the machine that ran the audit (here a macOS arm64 host and a recent
nightly), so a different machine's `host` section will differ; the two big-endian platforms are what this evidence is
about.

## Audit result at this revision (Cargo.lock sha256 `55ee4dab437f6210…`, 40 entries)
0 blockers, 14 review items, 38 info. The review items are facts for a human to decide, never admissions: 12 linked
dependencies contain `unsafe` in their own source (block-buffer, cmov, const-oid, hybrid-array, itoa, memchr,
portable-atomic, serde, serde_core, serde_json, sha2, zmij; none is `links` or has a native build signal), the
workspace's float users on the soft-float MIPS target, and `franken-alloc-probe` as the one workspace crate with
documented unsafe that nothing depends on. Several of the `unsafe` dependencies sit under a parent that
`forbid(unsafe_code)`; the finding names the parent and says its forbid does not cover the child.

## Limits
- One run, one worker, one revision. No repeat run, so nothing here measures variation between workers.
- `cargo check` stops before code generation: nothing is assembled, linked or run, so it cannot show a link error,
  a missing symbol, an unsupported instruction or a runtime failure on either target.
- The audit reads the resolver and the cached dependency sources; it cannot see macro-generated `unsafe`, and it
  counts `unsafe` under a `cfg` that is off for the target. See `docs/contracts/e06.md` for the full list.
- Asupersync, `franken_kernel`, FrankenLibC and any codec are not in this workspace's dependency graph, so they are
  not evaluated here; the audit lists each as `not in graph; unevaluated` and says what would evaluate it. The Rust
  `libc` crate (an FFI binding table, not a libc) is in `Cargo.lock` but linked only on the host reference platform
  and absent from both big-endian graphs; the audit reports it on its own row and does not count it as a candidate.
