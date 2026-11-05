# P01 central run at revision b8f8426, 2026-11-05 (evidence for P01-BLK-001)

The workspace test, the host `franken-speaker` build and the two bootstrap-probe builds of the P01 command plan, run on the
central rch path from a directory that is not the repository root, offline and locked. `receipt.json` is the sanitized,
revision-bound record of that run. **It is a build-and-test record.** It shows that these commands exited 0 on a worker and
what the produced files hash to. It does not show that anything ran on a guest, booted, or touched a device, and it is not an
attestation of the compiler.

## Who did what
- **The supervisor (BeigeMaple)** ran the five steps centrally from a clean `git archive` export of revision
  `b8f8426de828270375eaae14f5547edd8e0cc033`, on RCH worker `ts1`, with the command lines of DarkPeak's proposal. The working
  directory was `crates/franken-board-profile`, not the repository root.
- **NavyHollow** turned the raw rch logs into `receipt.json` with `scripts/e2e/p01 ingest`. The raw logs are not committed:
  they name the worker's address and local paths (the E06 precedent). Each step's record keeps the SHA-256 of its raw log, so
  whoever holds the log can check it.

## Command
Each step is `RCH_REQUIRE_REMOTE=1 rch exec -- <command>` with `CARGO_TARGET_DIR=<export>/build/p01-target`. The commands as the
worker ran them, with the export directory written `<repo>` and rch's own `--config env.RCH_*` trailer removed:

| step | command |
|---|---|
| `toolchain` | `rustc +nightly -vV` |
| `workspace-test` | `cargo test --locked --offline --manifest-path <repo>/Cargo.toml --workspace --config build.incremental=false -j 2` |
| `build-franken-speaker-host` | `cargo build --locked --offline --manifest-path <repo>/crates/franken-speaker/Cargo.toml --release -p franken-speaker --features franken-speaker/harness -j 2` |
| `build-ffw-hello-init-mips_be` | `cargo +nightly build --locked --offline --manifest-path <repo>/toolchain/src/ffw-hello-init/Cargo.toml --release --config <repo>/toolchain/src/ffw-hello-init/.cargo/config.toml --target mips-unknown-linux-musl -Z build-std=core,panic_abort -j 2` |
| `build-ffw-hello-init-powerpc_be` | the same with `--target powerpc-unknown-linux-musl` |

`ingest` required each logged command to equal the command the plan builds for that step; all five did.

## Results
| step | exit | seconds |
|---|---|---|
| `toolchain` | 0 | 1.3 |
| `workspace-test` | 0 | 34.5 |
| `build-franken-speaker-host` | 0 | 22.8 |
| `build-ffw-hello-init-mips_be` | 0 | 22.2 |
| `build-ffw-hello-init-powerpc_be` | 0 | 24.3 |

- **Workspace test:** 533 passed, 0 failed, 1 ignored, in 32 test-result blocks.
- **Compiler named by the `toolchain` step:** `rustc 1.101.0-nightly (708c94ef0 2026-11-03)`, LLVM 23.1.5, host
  `x86_64-unknown-linux-gnu`.
- **Artifacts, read from the built files:**

| artifact | SHA-256 | bytes | ELF |
|---|---|---|---|
| `speaker-host-full` | `e58e37a110bdef90a6e79aef9dec05fd29ae410b35f57235cf1e5a0be84286a2` | 488464 | 64-bit little-endian x86-64 (the worker's host) |
| `hello-init-mips` | `37652d885d4c146ad13d71f56823aee7383c3c74901176ba24fb521b23eab326` | 27444 | 32-bit big-endian MIPS |
| `hello-init-ppc` | `75ef9b04a3ea3abf871592a09dbdb8acf0d68e94ed60d30e6884f3713dd6825e` | 24416 | 32-bit big-endian PowerPC |

  The two bootstrap-probe digests equal the ones the committed E07 receipts record
  (`toolchain/results/runs/f0a91e7b…` and `…/1412ac47…`), so the P01 flags (`--locked --offline --manifest-path --config`, run
  from another directory) reproduce E07's bytes.
- **Verification against the contract** (digest `11d928eda2b6d468…`): no code; the artifact rows hold.

## One deviation, stated
Step `build-franken-speaker-host` was run with `RCH_ALLOW_FOREIGN_ARTIFACTS=1` in the environment, because rch refuses to fetch a
Linux executable to a macOS operator otherwise. The logs do not show the environment, so `receipt.json` records it as
`attested_env` (the supervisor's statement, not something the log proves). The current plan carries that variable on the host
build, and only there. The fetched file was hashed and its header read; it was not run.

## What this does not show
- **Not every step of the current plan has run.** The plan has since gained a `toolchain-default` step (plain `rustc -vV`, the
  compiler a bare `cargo` resolves to on the worker, which is what the workspace test used and nothing recorded). It has not run
  centrally, so `P01-BLK-001` judges this record as **stale** and reports `BLOCKED`, naming that step, until a central run of the
  current plan is ingested. Five of the six steps in scope match the current plan and exited 0.
- **P01-BLK-004 is still open:** this run does not say which compiler the workspace test used.
- **P01-BLK-002 is not covered:** the two device speaker builds (`build-franken-speaker-mips_be`, `-powerpc_be`) did not run, so
  four of the seven binary artifacts are missing from the record (`missing` in `receipt.json`).
- **Nothing ran `franken-speaker --virtual-house`.** The host build only proves the harness build compiles and links.
