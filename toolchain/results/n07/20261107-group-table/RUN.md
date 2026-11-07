# N07 group table: account for the allocation and prevent growth

Base: `6c624de70248549c37c41c91fdd4b78ed5880104`, with the reviewed four-file
patch `52dbe08b5161cfe8b419aeaaacaa8b8b59eb08a0ed8e050c7afb627dcb9921d3`.
The contract wording was clarified after verification to distinguish measured
host allocations from unqualified board resident memory. Code hashes below
identify the tested code; that wording change does not alter it.

The first native batch (build `30099060530610537`, exit 101) passed 1,012 tests,
failed four and ignored one existing soak test. All four failures reported
`ADMIT` and `REPORT-COVERS`: the primary group vector allocated 56 requested
bytes which neither the report nor its bound named. In the ordinary case,
the measured admission level was 4,792 bytes: the reported 4,608-byte peer
table plus 128 bytes of sequence storage left those 56 bytes unexplained.
This was a missing owner, not permission to add arbitrary tolerance.

The sender now allocates the group vector at its configured maximum once,
reports its capacity separately and bounds it by the size of its real state.
At the tested eight-peer cap, this intentionally costs 448 bytes instead of
56. The tests derive the larger allowance from the same configured cap and
type layout. Payload and sequence limits keep their previous meanings.
Tests at caps three and five cover add-to-cap, refusal, removal and re-add
without allocation; planted one-byte under-reporting still fails the oracle.

## Executed checks

All compiler commands used `RCH_REQUIRE_REMOTE=1`, `RCH_BUILD_SLOTS=1`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0`. No fallback or admission floor was changed.

```sh
rch exec --source-content-receipt --worker ts1 -- cargo +nightly-2026-08-31 test --locked --no-fail-fast -j1 -p franken-control -p franken-speaker -p franken-alloc-probe --features franken-speaker/harness -- --show-output --test-threads=1
rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked -j1 -p franken-stream -p franken-speaker -p franken-alloc-probe --features franken-speaker/harness --all-targets -- -D warnings
rustfmt +nightly-2026-08-31 --edition 2024 --check crates/franken-stream/src/carrier.rs crates/franken-stream/src/carrier/tests.rs crates/franken-alloc-probe/tests/n07_carrier_heap.rs
python3 -B -m unittest discover -s tests/n07 -p 'test_*.py'
```

Native build `30099060530610578`: exit **0**, **1,018 passed / 0 failed /
1 ignored**, across 20 result groups; `n07_carrier_heap` passed **7/7**.
The ignored D03 25.5-hour soak was not run. Strict all-target Clippy build
`30099060530610569`: exit **0**, no Rust diagnostics. Formatting passed.
Python: **32/32 passed**. `native.log` contains selected, unmodified observed
test verdicts and N07 records from the complete native capture.

Both remote captures matched all **1,355/1,355** local input files before
this evidence and the contract clarification were added. Both jobs were
terminal and acknowledged, with wrapper dead, owner absent and all five
source/tree/pair/retirement/staging release flags true.

| Capture | SHA-256 |
|---|---|
| Complete native log | `df519728c5737ff8e571d9afd73bf4475d23b97631d2874a6c29881a46ac251e` |
| Native source root | `ecb8ae3ead1d47106b0591d587dcfaf07ae1e14ec9ac3dca9b07a0efb71a300f` |
| Complete Clippy log | `a662aedb2476ec6bbed4da1c387dff07da74eebe69a144ff4cc523cef50071d2` |
| Clippy source root | `6f293ea3f2f40cd03d3da38b44658e63ba994b08079b8d7c099ad5f5194019b9` |
| `crates/franken-stream/src/carrier.rs` | `600ca6154a564a642bfc3e8131981330afc7648ab14111575203fbfc709867c7` |
| `crates/franken-stream/src/carrier/tests.rs` | `dc4cfd3d14b504790cc839252dc75e6abe661e5afc55fcafe4a8bfa714af02d9` |
| `crates/franken-alloc-probe/tests/n07_carrier_heap.rs` | `84094b100d643918cecc3fc8801f1b857bdff29320c238115122c805dd4f8d08` |

Earlier immediate/queued no-slot and disk-reservation refusals were pre-Cargo
attempts, not passing tests. They remain in the private complete captures.
The successful batch does not execute `franken-stream`'s own unit binary;
the two new assertions there have compile/Clippy proof only at publication.
This record qualifies host requested-allocation accounting, not board RSS,
old-kernel execution, physical radio behavior or playback. N07 remains open
for its original acceptance and prerequisites.
