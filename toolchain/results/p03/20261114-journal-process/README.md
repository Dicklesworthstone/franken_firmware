# Owned journal and isolated file backend verification

Consumer: P03 integration reviewer. Gate: publication of this backend, not P03 closure.
Observed defect classes: blocking file I/O on the control loop, lost child custody,
and journal ownership across Pending. Retire as current qualification when these sources change.

These are native Linux remote tests, not QEMU, device, flash, audio-deadline,
or complete P03 acceptance results. The process backend is opt-in and regular-file only.
All three runs used RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec with
--source-content-receipt. The final journal run additionally used --json.
Native jobs reported terminal acknowledgement and source/tree/pair retirement.

The speaker run preceded removal of a redundant method-level must_use attribute
on Journal::into_commit. The type-level must_use remains. Final journal tests and
workspace Clippy cover that final source. No runtime code changed between them.

Earlier attempts are not counted as passes: one remote reservation refusal,
one missing feature gate compile failure, one services manifest assertion failure
(725 unit passes, one failure; integration targets not reached), and one redundant
must_use Clippy failure. A disjoint local edit invalidated an earlier source barrier;
same-ID recovery recovered its failed command result. Subsequent runs froze sources.

Output excerpts retain every test result line plus test names and build completion;
RCH orchestration details, paths and the full private source manifest are omitted.
Zero-test targets do not add coverage. Speaker: 788 passed, 0 failed, 1 existing ignored.
Journal: 47 passed, 0 failed, 0 ignored. Clippy: exit 0.

## journal
Native build: `30109207290183959`. Raw log SHA-256: `a6afb517b802c8ad46f4c418306abd5a7956dd055d1945152dd6e5ab46365b51`.
```sh
cargo +1.99.0 test -p franken-journal -j1 -- --test-threads=1 --show-output
```

## speaker
Native build: `30109207290183933`. Raw log SHA-256: `8418344c55ea90e9c98d9d3093a30b69b8a4d727dea7acdd01c2af5dca8ca3d7`.
```sh
cargo +1.99.0 test -p franken-speaker --features journal-process -j1 -- --test-threads=1 --show-output
```

## clippy
Native build: `30109207290183951`. Raw log SHA-256: `62dd3f1bc84eb902b1cc534bc8a89b6431ad0b8c3fa74929fc9a0ffa4dcab891`.
```sh
cargo +1.99.0 clippy --workspace --all-targets --features franken-speaker/journal-process -j1 -- -D warnings
```

Final RCH source receipt root: `562ef6b10baa73b9855489d1fa4dc556e1254117dcd12349ae3fb1dfe99ca85c`.
This is source snapshot identity, not a transitive compiler-input attestation.

## Published source SHA-256

- `crates/franken-journal/src/commit_cursor.rs`: `fdadb8b53b848eef24ee0c0d88fbc6831e9a8cbbde56a9ad403bbbf1d94bc4dc`
- `crates/franken-journal/src/journal.rs`: `77e0c6c253c375712ab72394285528b6ac8b5c323445500ced32395264be6ceb`
- `crates/franken-journal/src/lib.rs`: `48dafcc69982609c9f7b2e2ad915b5c32c7180118c165d9acab66ae863a96760`
- `crates/franken-speaker/Cargo.toml`: `6d477d56053a60fe5ae189e605dea6f8b24310db72adc827027701d5f327cd97`
- `crates/franken-speaker/src/lib.rs`: `c643aeee9a3886dda7296e904aa310070457865212dec65f930348eec3a40d95`
- `crates/franken-speaker/src/file_medium.rs`: `a2cd234520b54d5eec1334b32883a6d0f5100ea81931661c17ce347ab5aab9ba`
- `crates/franken-speaker/src/journal_process.rs`: `1e02e7b784f7b0034325d03a86ad6785f7c4a7133f54d52b891a0311bfcafd98`
- `crates/franken-speaker/src/bin/franken-journal-worker.rs`: `48ac6275a3d0871f9ed0ef7da4d88470dacbad72a60ed80d7eb591ccd9b27bcf`
- `crates/franken-speaker/tests/journal_process.rs`: `fb0336e78106bc31943196915c6023623e7fd26f1e6e8b486680cdf859701bde`
- `crates/franken-speaker/src/services.rs`: `d29aa12c2a400c936b1fbe7184eb8d4ee191549950c533b333661528ce7cd97d`
