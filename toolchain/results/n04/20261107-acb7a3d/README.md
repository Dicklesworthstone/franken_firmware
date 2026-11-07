# N04 host execution and big-endian compilation, 2026-11-07

Historical evidence for the matching `acb7a3d` source. The current judge also requires the additive realtime boundary
test and observation, so this transcript alone no longer qualifies current N04. Use the
[current boundary evidence](../20261107-192261a/README.md) to replay the current judge.

Tested source bytes: `acb7a3dd46e47fbd8e2dec51b43eae8ac5c0122d`.
The native capture began before that commit was published and reported its parent as dirty. The native, strict-Clippy and both cross-check source-content receipts independently match all 12 changed blobs below; the source bytes establish identity.

This evidence is consumed by the existing N04 offline acceptance review and its existing judge. It records host execution and compilation only. Physical output, real-service admission, actual board resources, listening quality and the 24-hour integrated campaign remain unmeasured under their existing qualification owners.

| Evidence | Observed result |
|---|---|
| `host-tests.log` | 456 passed, 0 failed, 1 ignored, 18 result groups; actual remote Linux host execution |
| ignored D03 test | `d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap`; separate soak tier, unrun and never counted as passed |
| `host-judge.log` | N04 full: 31/31 checks passed, 0 failed/blocked; complete diagnostics, 0 critical loss |
| `clippy.log` | exit 0, all targets, harness enabled, warnings denied |
| `powerpc-check.log` | exit 0, BE-PPC all-target check; no guest execution |
| `mips-check.log` | exit 0, BE-MIPS all-target check; no guest execution |
| `first-failure.log` | preceding actual run: speaker 283 passed / 3 failed; stream tests not reached after Cargo stopped |

The first failure is retained. Two tests advanced simulated arrival time to the delayed tail before rendering block zero; their prefix decisions now precede that advancement and retain every payload/counter assertion. The third expected duplicate counts at the engine although raw duplicates are now refused by N01; its oracle now checks the exact independently scheduled N01 replay count and zero engine duplicates. No loss threshold, schedule, golden, required case or positive control was relaxed. New controls require the delayed old tail, fresh-epoch restart, replay/MAC refusal, per-generation capacity, identical paired trace, production pre-format rate admission and its real allocator probe.

## Commands and tool versions

The private worker selector is redacted as `<worker>`; use an admitted worker. Every Cargo argument, profile override and strict-remote setting is retained. RCH rewrites target/source paths on the worker. No local Cargo fallback was used.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 cargo +1.99.0 test --locked --no-fail-fast -p franken-stream -p franken-alloc-probe -p franken-speaker --features franken-speaker/harness -j1 -- --nocapture

RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +1.99.0 clippy --locked -p franken-stream -p franken-alloc-probe -p franken-speaker --all-targets --features franken-speaker/harness -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +nightly-2026-08-31 check --locked -p franken-stream -p franken-speaker --all-targets --features franken-speaker/harness --target powerpc-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1

RCH_REQUIRE_REMOTE=1 rch exec --worker <worker> --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo +nightly-2026-08-31 check --locked -p franken-stream -p franken-speaker --all-targets --features franken-speaker/harness --target mips-unknown-linux-musl -Z build-std=core,alloc,std,panic_abort -j1
```

- `rustc 1.99.0 (b940084d7 2026-09-28)`; `cargo 1.99.0 (5f94df478 2026-08-27)`; host `x86_64-unknown-linux-gnu`.
- `rustc 1.100.0-nightly (908501772 2026-08-30)`; `cargo 1.100.0-nightly (e8cb624d5 2026-08-22)`; host `x86_64-unknown-linux-gnu`.

## Transcript sanitization and replay

The transcript retains every test, result and `N04-OBSERVED` line verbatim, including stdout that arrived before Cargo's `Finished`/`Running` stderr headers. ANSI formatting, RCH orchestration frames/full private source manifests and private filesystem prefixes are removed; worker target prefixes become `target`, source prefixes become `<workspace>`, and compiler source paths become `<rust-sysroot>`. No outcome or observation is fabricated or rewritten. The complete sanitized transcript independently passed this command with the matching `acb7a3d` judge; the current judge requires the additional boundary evidence linked above:

```sh
scripts/e2e/n04 --tier full --judge toolchain/results/n04/20261107-acb7a3d/host-tests.log
```

An initial private export omitted pre-header allocator output and correctly failed qualification; it is not the transcript here. The raw captures and that failed export remain retained privately. The sanitized success and preceding native failure are distinct artifacts.

## Source-content witnesses

The full private RCH manifests are deliberately excluded from the public repository. These public source hashes are the exact changed-file entries checked against all four successful source receipts.

| Path | SHA-256 |
|---|---|
| `crates/franken-alloc-probe/tests/playout_no_alloc.rs` | `e9d8d66be3c3431a61ea120a6cd148e1e5a6450e2ae9a4c222a63ec2d4c8be59` |
| `crates/franken-speaker/src/harness.rs` | `f7ec8cdb4738e41f9b0533cddf4614e75c6ee329ce0d28ffd82e69635ebf8a45` |
| `crates/franken-speaker/src/playout_adapter.rs` | `9f28f75e287afc795ffb238b4f67e509eb8a2380589e4671422127619911d4e4` |
| `crates/franken-stream/src/playout/log.rs` | `c37adff7b843a29441ed7cdc3e3f0dc5dc8b9cb90a20e4d2ed3e02b5bf6fb983` |
| `crates/franken-stream/src/playout/log/tests.rs` | `f2566d6a80244297425de09649285a66adbe6c0277a3f943da6028d77d20ed82` |
| `crates/franken-stream/src/playout/tests.rs` | `3697097d32a5bb6425ab590d578187a968ca25dec2beb04163ca2d9da1e9a194` |
| `docs/contracts/n04.md` | `b84e441c39b39415e5580c461d12d87aad47535f65b7e526c3fceefc3a0108a5` |
| `tests/n04/paired.py` | `7c57872893fca4c0a228b4d6f17b046bb02dea538793aca437600d1c88cf8872` |
| `tests/n04/paired_trace.json` | `8aa98e8bd87f48781b584d27913ea7cade2375eac32b0da294d86479e5b94a1b` |
| `tests/n04/reference.py` | `5185101f1a585307647a646fa8984ea60fd6ef15e4fb1b90935f164364516923` |
| `tests/n04/run_cases.py` | `75104bcaceb3cf030ff7ad850e0f6078475a0d7795a2d9101033612c2f87e4e3` |
| `tests/n04/test_judge.py` | `7f86e16638b6d4d12bd8b7d83cc9e1db56a098ba080daf6985a5a443feca8fa7` |
