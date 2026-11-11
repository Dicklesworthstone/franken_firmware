# Host qualification: per-member READY resources

This snapshot records 1,320 passing library tests, three passing allocator tests and strict workspace/all-target Clippy for authenticated PREPARE/READY resource handling. All compilers ran on Linux workers through strict RCH. This does not qualify Sonos execution, board RAM/CPU, provider services, distributed activation or physical audio output.

The exported qualification tree had no Git metadata, so its build source stamp was `unknown`. Its starting revision was `664402621ffbdb0ec54132d0f3bf665a8a138eb3`, with the prior working-tree follow-up and the 13 changes listed in `source-inputs.json`. The supervisor compared all 1,535 selected file hashes and lengths in each passing worker receipt to the frozen candidate. Only `.beads/.gitignore` and `.beads/config.yaml` were excluded. The base commit alone does not contain these changes.

The 13 focused runtime/test inputs were subsequently delivered in commit `6c066b73db374adade9443eb79d3c4e8578b924f`. That publication does not change the exported build's `unknown` source stamp or qualify unrelated concurrent changes.

## Executed caller commands

These commands ran from the frozen qualification tree. RCH added its managed target and source-stamp options. They used Rust 1.99.0 and the existing lockfile; no owner Asupersync working checkout was accessed.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-control -p franken-stream -p franken-speaker --lib --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-alloc-probe --test n06_control_proof_heap --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 --keep-going -- -D warnings
```

## Results and limits

| Gate | Native job | Observed result |
|---|---|---|
| Full control/speaker/stream libraries | 30104858719682862 | 645 + 468 + 207 = 1,320 passed; zero failed, ignored or filtered |
| Fixed request-proof allocator tests | 30104858719682863 | 3 passed; zero failed, ignored or filtered |
| Workspace/all-target Clippy | 30104858719682866 | exit 0 with `-D warnings` |

The supervisor independently checked terminal acknowledgement, wrapper termination and source/tree/pair release and retirement for all three jobs. `observed.txt` contains actual captured output, including the synthetic fixture's READY/FUTURE records and test footers. It contains no raw credentials, wire payloads or site inventory.

The two-target fixture authenticates distinct member streams and media-key commitments, reserves future receiver state while old real PCM remains consumable, emits bounded signed READY records, admits identical retries and releases charges when guards drop. READY is an expiring assertion at emission; it cannot retract sent bytes or authorize activation. Internal charge counters are not process RSS or a 32 MiB board-fit measurement.

The allocator fixture signs and verifies 512 changing requests through the real PeerDirectory with zero measured calling-thread allocations, reallocations, deallocations or requested bytes. Its permitted legacy authentication sensor observes two allocations and 20 requested bytes. This qualifies the fixed helper with that fixture store; full READY emission, other stores, stack and whole-process memory remain separate.

All 100 library-mapped N06 tests and the three allocator tests appeared once with `ok`. These include all 17 newly required READY tests. Independent READY/FUTURE/heap/sensor checkers accept the actual output. Smoke passes 3/3 cases and remains `qualified=false`. This snapshot does not close N06 or the original two integration blockers.

## Preserved unsuccessful attempts

- Job 30103800983323724 stopped before Cargo with a publication permission error. The private root was mode 0500 while RCH needs to create an exclusive publication probe there. Owner write access was restored without source changes. The attribution follows source inspection, permissions and the subsequent execution; no system-call trace was captured.
- Job 30104858719682852 executed with 1,318 passing and two failing tests. Both existing `file_medium` AF_UNIX tests failed while creating fresh relative scratch in the mode-0500 package CWD. Only that private directory's permissions changed. Source and assertions stayed unchanged, and the entire three-library command was repeated successfully above.
- Job 30104858719682870 reached Cargo but failed offline resolution of the pinned Git Asupersync revision on the selected worker. Zero reference tests ran. The full 13-case consumer then reported 10 passed, zero failed and three blocked: missing current reference evidence and the original two integration blockers. Pinned-cache recovery is separate from the three passing gates archived here.

New typed GroupClock ingress and localhost UDP fixture changes are a separate source wave and are excluded from this snapshot.
