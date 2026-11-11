# Host qualification: staged target sender and work-budget corrections

The sender can now prepare separately keyed target delivery while old authenticated N01 audio continues. The owned preparation binds the actual sender identity and a non-wrapping generation. Drop releases staged resources; commit consumes the same capacities after checking membership, routes, local addresses, live fences, epoch and current allowance. Rejected pure validation leaves a valid preparation usable. Actual mutation, port escape, restart and ABA invalidate it. Activation timing, the numeric continuing reservation and exclusive backend custody remain explicit caller contracts; this is not authenticated distributed activation.

Two work-accounting defects are corrected. Checked elapsed subtraction prevents repeated maximum-clock readings from refilling the allowance, while preserving a legitimate interval ending exactly at the maximum. Common-group submission now charges per-peer fanout copies before encoding or changing retained windows and queues. One and two peers cost 149,504 and 158,720 synthetic units respectively. The cap remains 400,000; these are model charges, not measured CPU or board admission.

Eight new tests check byte-exact old N01 during staging, actual two-target delivery and repair after commit, drop/cancellation, exact budgets, foreign ownership, membership/path/epoch ABA, live MTU failure, harmless rejected requests, clock boundaries and exhausted-work recovery. All previous native requirements remain. The existing N06 consumer requires 123 names and retains both integration blockers.

## Actual commands and source scopes

Private worker placement is parameterized. The executed compiler, arguments and existing lockfiles are unchanged.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_LIBRARY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-control -p franken-stream -p franken-speaker --lib --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$N06_CLIPPY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 --keep-going -- -D warnings
```

| Gate | Native job | Result |
|---|---|---|
| Full libraries | 30104858719682992 | 649 control + 468 speaker + 220 stream = 1,337 passed; zero failed, ignored or filtered |
| Corrected strict workspace/all-target Clippy | 30104858719683012 | Passed, exit 0; workspace/all targets with `-D warnings` |

The library run binds the staged source inventory. A subsequent export differs in exactly one test-only file: two codec heap-test iterator expressions were changed to satisfy Clippy. Every production Rust source, library test, manifest and lockfile used by the three library packages is unchanged. The 1,337 result is preserved with that explicit scope, not relabeled a new whole-tree execution. The corrected heap test has its own [actual source-bound qualification](../../s02/20261111-codec-heap/RUN.md).

The supervisor independently checked all 1,550 selected library source hashes and lengths against the frozen 1,552-file inventory, only two Beads metadata exclusions, terminal acknowledgement, absent wrapper and complete custody retirement. Source manifests and observed native output accompany this record.

The current 13-case consumer, with actual library records and explicitly reused unchanged component evidence, reports 11 passed, zero failed, two blocked, zero not-run and zero dropped diagnostics, with `qualified=false`; combined log digest `7cf90c4cc07430ad200b545d95e23a77c91d77c7c79367a10f05badda7ca43f4`. Prior reference job `30104858719682930` covers 20 byte-identical FEC/reference algorithm and pinned-input files; it did not execute this newer whole tree. The unchanged fixed-proof allocator retains its separate three-test evidence. All 29 local Python controls pass. Synthetic controls are not native execution.

## Preserved failures and remaining acceptance

First placement `30104858719682978` was refused by remote disk admission with causal `started=false`, zero Cargo tests and no source receipt. Its wrapper-launch flag is not Cargo execution. Source/tree/pair custody retired; no local retrieval staging was created. No guard or floor was lowered. An admissible worker later ran the unchanged library command.

Workspace Clippy `30104858719683001` failed on two `chunks_exact_to_as_chunks` warnings in the new codec heap test. Its exact failed source and receipt remain retained. The subsequent correction changes only the two iterator expressions; it removes no assertion or tolerance. An early formatting invocation used the wrong working directory and found no Rust files; the separate correct invocation passed.

Authenticated READY consumption, control-member-to-route provisioning, receiver promotion and coordinated activation remain open. The type-level 21-member ceiling still needs actual queue, pacing, feedback and resource admission. No native provider, board/kernel/radio fit, physical output, long soak or deployment qualification is implied; N06 remains open.

Landed source: sender `41322777a9dd4fc071b6fdd07ce4e0b198c2f78e`; codec heap and consumer `f3de19ab318ac6fd8c7337f687fa4a23257de191`. The supervisor matched the landed file hashes to the qualified exports. Both native jobs completed with terminal acknowledgements, absent wrappers and retired custody. No job remains active for this batch.
