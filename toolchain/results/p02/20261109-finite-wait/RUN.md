# Finite poll prerequisite: native and compile evidence

Source: `3bbb52d78d09bdc308e5c6bba45e98edf1cb1b28`. The next P03 implementer and the repository's command/output gate consume this archive. It records the missing finite wait and a backend-input mutation defect. Later qualification may supersede these results; these original observations remain historical evidence.

The four core commands ran against `c4b8e54dd384c661c300189b9dd5de1a5e0ef5e3` plus frozen patch `dd666cc7b09886ab620fdf5f2e5d67077bf85139bc88bc90d10bd9fc237e24d2`. All eleven changed-file hashes equal the published source. Unrelated concurrent changes on main were outside that validation snapshot; this is not whole-workspace qualification at the published HEAD.

| Check | Observed result |
|---|---|
| Native platform + Linux-leaf tests | 248 +36 =284 passed; no failed/ignored/filtered cases. The two empty doctest targets add no evidence. |
| Added Rust cases | All 29 names matched exactly once in the final native log; see `v3-29-case-check.json`. |
| Host strict Clippy | Both crates, all targets, `-D warnings`: exit 0. |
| Big-endian MIPS/PPC leaf Clippy | Both exit 0; compilation only, no target execution. |
| Python P02 and smoke | 182 passed; corrected smoke 2/2 (run on v2; the Python files are unchanged in v3). These are checker/model tests, not Rust or guest execution. |
| Formatting and touched Python syntax | rustfmt and py_compile exit 0, observed by the runner; the empty syntax capture alone is not proof of status. |
| Receipt custody | Four strict-remote jobs finished0, ACKed, dead wrappers and absent owners; source/tree/pair retirement and staging release verified in `terminal.json`. All four full 1417-file content sets were identical. |

`manifest.json` supplies exact Cargo argv, raw-input SHA256 values, normalized-log mappings, source hashes and the content-set fingerprint. Commands used `RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt`, `-j1`, and `CARGO_INCREMENTAL=0`. Operational roots are placeholders. `CARGO_TARGET_DIR` was requested; RCH remapped it to its pool. The host pin was 1.99.0, also reflected by the retained v2 Clippy diagnostic URL; no `rustc -V` capture was supplied. Both BE commands explicitly selected `+nightly-2026-08-31`.

## Retained failures and reproduction

From the base, apply `finite-wait-v1.patch`, then `red-scaffold.patch`, and execute the `red` command in the manifest under strict remote policy. The scaffold adds three tests and the error-variant declaration; v1 production `poll_once` is unchanged. Exactly the two intended backend-input assertions failed. Actual selection was 6 tests: 4 passed, 2 failed, 242 filtered, exit 101. The original three-case selection plan was **not met** because substring filters selected three additional controls. This is reproducible defect evidence, not a passing three-case RED gate. The wrong plan and actual output are both retained.

The later v2 native test passed 284, but strict Clippy failed101 on an assertion over constants. Final v3 moved that same bound into a compile-time assertion and passed strict Clippy. The first v2 native attempt was refused before execution with E330/started:false and exit 120; it remains NOT RUN. A Python invocation of the Bash smoke entrypoint failed with SyntaxError; the corrected Bash invocation passed 2/2. Both outputs are retained.

The historical batch shell ignored errors after its first command and could exit 0 despite failed lines. Per-line results here are authoritative. The supervisor replaced it with a guarded continuation after letting the active job settle; killing only that paused outer shell produced 137, which is an orchestration event, not a Rust failure. Private stub tests prove only that continuation's control flow.

## Qualification limits

No speaker-service, Asupersync reactor, guest, stock-kernel, hardware, provider, timing or playback qualification is established. The original startup consumer checks were refused before execution; a corrected startup consumer with 42 source cases is under separate qualification. The earlier hello-program poll probe cannot establish execution of this wrapper. P03 and its original dependency/acceptance remain unchanged; no bead is closed by this archive.

Operational receipt payloads were omitted, paths/addresses/worker labels/attempt IDs pseudonymized, and ANSI styling removed. Complete test output and compiler diagnostics remain; no test/diagnostic line was truncated. The two reproduction patches retain exact original unified-diff bytes, including their context markers; their hashes are checked as data rather than changing them to silence whitespace warnings.
