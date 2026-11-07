# N04 realtime boundaries: native execution and BE compilation

Tested runtime/test source: 192261a85eec91e9e0a8e9e44a4c9f983bbd1d8b.
The capture began from its parent plus the five-file boundary delta; all four successful RCH source-content receipts match the published source bytes. Later contract/accounting prose and evidence exports do not change the compiled code, fixtures or judge.

This package is consumed by the existing N04 offline acceptance review and N04/Q01 judges. It establishes host execution and compilation. Physical output, board CPU/RAM, listening quality, provider/native-service qualification and the integrated 24-hour campaign remain unmeasured under their existing qualification owners.

| Evidence | Observed result |
|---|---|
| host-tests.log | 457 passed, 0 failed, 1 ignored; 18 result groups, 0 filtered; actual remote Linux execution |
| ignored test | d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap; separate D03 soak, unrun and never counted as passed |
| host-judge.log | current N04 full judge: 31/31 passed, 0 failed/blocked; complete diagnostics |
| q01-judge.log | current Q01 judge: 28/28 passed, 0 failed/blocked |
| clippy.log | strict remote, all targets, harness enabled, warnings denied; exit 0 |
| powerpc-check.log | BE-PPC all-target check; exit 0, no guest execution |
| mips-check.log | BE-MIPS all-target check; exit 0, no guest execution |
| Python controls | 57/57 passed; judge/model controls, not native execution |

The new native test replays three hand-derived realtime boundary worlds through the real playout engine: horizon +8 is admitted and played while +9 is refused; notice 2 is accepted while 1 is refused; a 4-block transition is accepted while 4 blocks plus 1 ns and 5 blocks are refused. Both sides are mandatory under the existing N04-PROFILES case. Original vectors and the paired music/realtime trace are unchanged.

## Commands

The worker selector is redacted as <worker>; select admitted capacity. Every Cargo argument and profile override below is retained. All builds were strictly remote.

    RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo +1.99.0 test --locked --no-fail-fast -p franken-stream -p franken-alloc-probe -p franken-speaker --features franken-speaker/harness -j1 -- --nocapture

    RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +1.99.0 clippy --locked -p franken-stream -p franken-alloc-probe -p franken-speaker --all-targets --features franken-speaker/harness -j1 -- -D warnings

    RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +nightly-2026-08-31 check --locked -p franken-stream -p franken-speaker --all-targets --features franken-speaker/harness --target powerpc-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1

    RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +nightly-2026-08-31 check --locked -p franken-stream -p franken-speaker --all-targets --features franken-speaker/harness --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1

    python3 -m unittest discover -s tests/n04 -p 'test_*.py'
    scripts/e2e/n04 --tier full --judge toolchain/results/n04/20261107-192261a/host-tests.log
    scripts/e2e/q01 --judge toolchain/results/n04/20261107-192261a/host-tests.log

Host toolchains: Rust/Cargo 1.99.0 and nightly-2026-08-31 (Rust 1.100.0-nightly), x86_64-unknown-linux-gnu. The BE commands compile target code only.

## Delivery, failed attempts and export integrity

The native Cargo command exited 0 and emitted its verified source receipt. Its wrapper initially exited 1 because release of a remote source-authority lock timed out. Supported recovery of the same job completed with delivery exit 0 and terminal acknowledgment; the final lease is finished with dead wrapper/absent owner, and sources, tree, pair and retrieval staging are released. The daemon's earlier 130 versus recovered delivery 0 is retained privately alongside the original wrapper failure. Recovery did not replay the tests.

The first lint request expired in the admission queue before a compiler ran. The first PPC request was refused at disk admission (started=false) because active reservations and the protected floor did not fit. Both refusals settled before capacity-backed retries; no remote budget/floor, global fallback setting or peer job was changed.

The export preserves all 600 test/result/runtime-observation lines verbatim after ANSI removal, including stdout before Cargo stderr headers and the Q01-MEMBER, Q01-PLANT, D03-OBSERVED and N04-OBSERVED records. Compiler paths are normalized; orchestration frames and full private manifests are excluded. Intermediate exports omitted required non-N04 records and correctly failed Q01 replay; those failed exports remain private. The corrected transcript passes both current judges. Raw logs are unchanged.

The earlier [456-test run and original native failure](../20261107-acb7a3d/README.md) remain historical evidence. Their transcript alone cannot satisfy the current mandatory boundary control.

## Source-content witnesses

Each receipt below has command exit 0. Complete manifests are retained privately; their public receipt roots bind the selected bytes. Final acknowledgment and custody were separately verified.

| Run | Native build ID | Receipt root |
|---|---|---|
| native tests | 30098575685845161 | 83ca8d8d77be3ac9dfae078397df2a5206b838fcc3aa285d4df116731865fb58 |
| strict Clippy | 30098575685845163 | 96cfabe06615303daae2fe29aa10117d1ebabd360e5eea8c42043e7bbd21b33d |
| BE-PPC | 30098575685845170 | 9570c03329030677aabf9416cd4e3a1a9c6309a9f5b505534d37282ebfc0337e |
| BE-MIPS | 30098575685845174 | fbb36cb917627f8ca7fe17f8e024b8b6d76329938c6627cf9e0b5db91bc0da49 |

| Boundary source path | SHA-256 in all four receipts |
|---|---|
| crates/franken-stream/src/playout/tests.rs | 8eb9a80fe1bb0f87ba96a73c6e0bc7a45f825bdf77ea1bd8baa5291d0c6248ad |
| tests/n04/boundary.py | 46d360c3ea097f81edac502cdc6411a0399a6d28959cfc2f5a92f1a19c34d0b5 |
| tests/n04/boundary_trace.json | a33eac5e185f9c62cbc6e94437a7a593cca762ec5e0883be9c874a86c346046e |
| tests/n04/run_cases.py | 21bc3b8d1ea07a090f2f4fa68c7bf183cee3febbfcbedab0d8a033cb9964e0c4 |
| tests/n04/test_judge.py | 3ffb071ebd90286e60e4465d7929a6064b0a404c3a900528b23461042105f02e |
