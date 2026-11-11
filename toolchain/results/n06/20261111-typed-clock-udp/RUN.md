# Host qualification: typed clock ingress and localhost UDP

Commit `b04038b4728e7bf072e2b0c07506b87122986cbe` delivers the seven focused inputs in `source-inputs.json`. The exported worker tree had no Git metadata and reported build source `unknown`; its exact selected content, rather than a Git stamp, binds this evidence. This is host development proof, not Sonos execution, board fit, provider compatibility or physical output qualification.

## Observed behavior

`FleetControlOwner::receive_with_future_clock` derives time from the actual admitted next-epoch GroupClock and checks its Armed output and authenticated common start. A first PREPARE with the wrong start is refused before round, timing or clock-floor insertion; the same signed request can subsequently succeed with a valid clock. Invalid clocks still fence an existing round. Ordinary control, FFCNv1 and the endpoint's aggregate ingress bucket retain their established behavior. The raw group-time API keeps an explicit caller-trusted boundary.

The existing two-target READY fixture now sends and receives PREPARE, READY and exact retries over bounded localhost UDP before passing the received bytes to production ingress. It checks sender identity, bounded length and exact received bytes. Distinct media streams/keys, unchanged old real PCM, resource charges and release remain required. Armed-output documentation now states group-clock nanoseconds; the clock arithmetic is unchanged.

## Commands and results

These are the executed caller command bodies. Private worker placement is parameterized; compiler options, lockfile and test scope are unchanged.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_LIBRARY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-control -p franken-stream -p franken-speaker --lib --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_LIBRARY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-alloc-probe --test n06_control_proof_heap --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_CLIPPY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 --keep-going -- -D warnings
```

| Gate | Native job | Actual result |
|---|---|---|
| Full control/speaker/stream libraries | 30104858719682877 | 649 + 468 + 207 = 1,324 passed; zero failed, ignored or filtered |
| Real fixed-proof allocator integration | 30104858719682884 | 3 passed; zero failed, ignored or filtered |
| Strict workspace/all-target Clippy | 30104858719682886 | exit 0 with `-D warnings` |

The supervisor independently matched all 1,535 selected path/hash/length entries against the frozen 1,537-file inventory for each passing job. Only `.beads/.gitignore` and `.beads/config.yaml` were excluded. Each native lease finished with exit zero and terminal acknowledgement; wrappers were absent and staging/source/tree/pair custody was released and retired before delivery.

All four new typed-clock tests and the actual UDP test appear once as `ok` in `observed.txt`. The allocator measured 512 verified changing requests with zero calling-thread allocations, reallocations, deallocations or requested bytes; its permitted legacy positive sensor measured two allocations and 20 bytes. These are fixture-specific counts, not whole-process RSS, stack or old-board admission.

The unchanged existing consumer now requires 110 names: all prior 106 plus four actual clock tests. It retains every original case, observation and integration blocker. Independent smoke consumption of the successful current library and allocator captures passes 3/3 with zero failures, blockers, not-run cases or dropped diagnostics, while `qualified=false`; joined log digest `b71e14e22cbcdb7fcdffe21a74c7e54d244e98ebe52a9ee8ab2a860b09a51862`. Formatting of five Rust files, all 26 Python controls and script compilation passed after delivery.

The first Clippy placement refused before native admission because the selected worker lacked the required runtime. No Cargo ran there; strict remote refused local fallback. The exact unchanged command then passed on a demonstrated eligible worker. That refusal remains retained privately.

A separate exact-candidate coding-reference job is pending and is not credited in this snapshot. The [prior READY source snapshot](../20261111-ready-resources/RUN.md) records its own three passing reference tests. `N06-CARRIER` and `N06-PACED-SENDER` remain open: production still needs authenticated READY-to-active coordination and matching per-target transport delivery. Private per-target sender work is excluded from this evidence.
