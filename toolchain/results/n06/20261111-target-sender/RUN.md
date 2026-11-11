# Host qualification: separately keyed target sender

Commit `a16fa4c` delivers four focused carrier/test/consumer files. The same frozen qualification tree also contains a documentation-only codec correction. `source-inputs.json` records all five exact overlays and the passing source receipts. The worker export had no Git metadata; its content hashes, rather than a build stamp, bind this proof. No Sonos device or provider was contacted.

## Delivered behavior

The previous sender signed one group configuration and copied its datagrams to every peer. The new trusted provisioning API admits up to two distinct stream/key configurations, signs each target's wires separately and retains that target's repair windows. Actual authenticated feedback is checked against its source peer and own configuration; a repair reaches only that peer. Two real FEC receivers and N04 outputs verify byte-exact `Outcome::Real` PCM after induced loss. The production sender/pacer is used through an in-process scripted port; this fixture does not claim LAN or physical output.

Five new tests cover distinct target recovery, bad bindings with continuing real N01, work/cancellation/restart fences, missing-window refusal counters in both modes, and exact retained capacity versus one byte short. Cross-key, stream, source, replay and epoch refusals are paired with permitted real behavior. The continuing caller allowance charges actual vector/deque capacities and named live scratch arrays. Two targets consume 299,008 of the unchanged 400,000 synthetic work units; three targets are refused. This is neither complete board memory admission nor measured CPU/stack/RSS.

The two-target cap belongs to this separately keyed host profile. It does not reduce the existing 21-member common-group path or waive the required whole-fleet grouping feature. That larger integrated profile still needs its own admission and activation evidence.

## Executed gates

Private placement selectors are parameterized; the compiler, lockfile and command options are unchanged.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_LIBRARY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-control -p franken-stream -p franken-speaker --lib --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_ALLOCATOR_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-alloc-probe --test n06_control_proof_heap --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_CLIPPY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 --keep-going -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_REFERENCE_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test --manifest-path toolchain/n06-fec-profile/Cargo.toml --locked --offline -j1 -- --show-output
```

| Gate | Native job | Observed result |
|---|---|---|
| Full control/speaker/stream libraries | 30104858719682922 | 649 + 468 + 212 = 1,329 passed; zero failed, ignored or filtered |
| Fixed-proof allocator integration | 30104858719682924 | 3 passed; zero failed, ignored or filtered |
| Strict workspace/all-target Clippy | 30104858719682925 | exit 0 with `-D warnings` |
| Exact-candidate standalone coding reference | 30104858719682930 | 3 passed; zero failed, ignored or filtered |

The supervisor independently compared every selected path, SHA-256 and length: 1,535 matching files per job against the frozen 1,537-file inventory, only two Beads metadata exclusions, no extras. All four leases ended with command/returned exit zero, terminal acknowledgement, absent wrappers and complete staging/source/tree/pair release and retirement. The allocator proves 512 changing requests with zero calling-thread allocation, reallocation, deallocation or requested bytes. Its permitted legacy positive sensor records two allocations/20 bytes. It does not measure sender process memory.

All five target tests appear exactly once as `ok` in the actual library capture. The existing N06 registry grows from 110 to 115 without deleting any requirement or observation. Formatting, script compilation and the 28 existing Python controls pass. An initial local unittest invocation used the wrong import directory and two nonexistent module names; it failed with three loader errors, executed no controls and contributes no pass credit. Correct execution from `tests/n06` passed all 28.

## Failure history and remaining scope

The first target candidate, native job `30104858719682906`, failed compilation because an older test passed a group ID to a helper now requiring the actual peer index. No test binary ran. The correction resolves the real admitted peer with `index_of(7)`; it adds no cast, arbitrary index or weakened assertion. The failed source and log remain retained separately. All later results above bind the corrected source.

The exact-candidate standalone coding reference completed in job `30104858719682930`: all 65,536 GF products, four basis encodes and 163/163 subsets match the pinned libraries. Its allocator sensor records one allocation/1,024 bytes, with zero packet allocation calls or bytes. Zero-test doctest output adds no credit. The existing full 13-case consumer, fed the actual current-source captures, reports 11 passed, zero failed, two blocked, zero not-run and zero dropped diagnostics, with `qualified=false`; combined log digest `7473e5e841dd1979b15187da43fd07ad47342c8be1bac65fa3bc16f562d920a4`.

Raw target bindings and the numeric retained allowance are trusted caller inputs. Fresh authenticated READY consumption, control-member-to-route identity, receiver promotion and coordinated activation remain open. Both `N06-CARRIER` and `N06-PACED-SENDER` remain blocked; native services, old-kernel/board fit, radio, long soak, acoustic and deployment qualification remain unclaimed. Subsequent staged-sender, work-accounting and heap-probe work is excluded from this snapshot's source and results.
