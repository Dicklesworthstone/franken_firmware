# Callback shutdown closes admission before counting abandonment

Source commit 0617afc1b9937bc8647df14a944d01b9491549c6, tree 3facf7e204046e8aa6c303139cb0048f4557a010, based on 3ee61d106601f6dec6dff76846233b0bc180654a. All 1,644 committed blobs, byte lengths and executable bits match the qualified frozen source. Only callback.rs and callback/tests.rs change. [receipt.json](receipt.json) records input and native receipt digests; [observed.txt](observed.txt) retains every suite footer and every required result line.

The delivery loop previously drained its receiver before taking the accounting mutex. An outbox could admit another notification after that final drain but before receiver destruction. Its queued count could then exceed delivered, failed and abandoned counts. The repair takes receiver ownership into the delivery loop and holds the same mutex used by admission across the finite final drain, receiver disconnect and abandonment count. An offer is serialized before the drain and counted, or sees the disconnected receiver afterward and is dropped. No socket I/O or blocking receive occurs under the retirement lock. Work scales with configured queue capacity; no universal fairness or latency bound is established.

Both new tests execute the actual queue, Outbox and shared cleanup code. The first preserves admitted/full/closed-queue controls, exact abandonment and a late cloned outbox. Independent review rejected this case alone as a causal regression: an owning wrapper around old ordering could also pass it. The second test observes the real post-drain/pre-disconnect boundary, probes the accounting mutex and starts a real cloned-outbox producer with bounded handshakes. When the boundary is unprotected it waits for actual admission before disconnect, forcing the lost-accounting schedule. In fixed ordering, the locked boundary and source serialization exclude that admission. The producer-entered signal alone does not prove it blocked on the mutex.

One preregistered instrumented old-order mutation moved only the helper's lock acquisition below the drain synchronization point. Test bytes and parameters stayed identical. Native311 failed its intended boundary assertion with offered 3/queued 3/abandoned 2/dropped 0/reconciled=false. It is an intentional failure, not untouched historical code or a passing gate. It ran once, with no retuning or repeat. Fixed native 313 emitted offered 3/queued 2/abandoned 2/dropped 1/reconciled=true.

| Gate | Native execution | Actual result |
| --- | --- | --- |
| Workspace all-target Clippy |30107136981729312|Exit0; warnings denied|
| Complete workspace tests |30107136981729313|2,963 passed / 0 failed /2 existing ignored / 0 filtered; 81 footers; 26/26 required names|
| Actual-client all-target Clippy |30107136981729314|Exit0; warnings denied|
| Complete actual-client package |30107136981729315|20 passed / 0 failed / 0 ignored / 0 filtered; 7 footers; 20/20 required names|

Each workspace receipt matches all 1,642 transferred firmware paths, hashes, lengths and executable bits. Each client receipt matches all 1,701 tuples over firmware 1,642, sibling workspace metadata 4, fsonos-proto 51 and fsonos-types 4. Two tracked .beads metadata files are excluded; no .ee/.git/.beads component transferred. All four final jobs exited0 with terminal acknowledgment, absent wrappers and execution/staging/source/pair/tree/record release checked. Control311 exited101 with source/pair/tree/record release and an absent wrapper. Its lease records no owned retrieval stage, no configured stage and incomplete unpublished phases; owned-stage release is explicitly N/A. This is not a true release bit or proof of physical directory absence. The deployed RCH 2.1.36 source makes owned-stage release conditional on ownership.

Caller commands below are normalized invoker arguments. RCH-injected target/build-directory arguments and full private paths remain in the raw logs bound by digest. The first two use Rust 1.99; the separate actual-client workspace uses nightly-2026-08-31. The source snapshot includes the pinned sibling revision 8f422c333269073a256fe59c6f50e7e8429a1bf9.

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +nightly-2026-08-31 clippy --locked --offline --manifest-path tests/g03/fsonos-client/Cargo.toml --all-targets -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +nightly-2026-08-31 test --locked --offline --manifest-path tests/g03/fsonos-client/Cargo.toml --no-fail-fast -j1 -- --show-output --test-threads=1
~~~

On the separate control snapshot, the one exact control command was:

~~~sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo +1.99.0 test --locked --offline -p franken-speaker --lib -j1 fsonos_loopback::callback::tests::orderly_shutdown_serializes_live_offers_with_final_drain_and_disconnect -- --exact --show-output --test-threads=1
~~~

Pinned 1.99 rustfmt checked both changed Rust files, edition 2024/skip_children=true. Existing assertions, deadlines, ignores, goldens and CI configuration remain unchanged. The ignored exhaustive 2^32 DSP sweep and D03 25.5 virtual-hour soak did not run. The source-only v1 NO-GO and its exact source are retained. An initial author-source handoff was briefly mutable; v1 was restored to both original hashes, v2 uses distinct readonly inputs, and both complete candidates were independently rehashed before execution. No mixed candidate qualified.

This capsule gates operator/supervisor admission of this exact host repair and retires as admission evidence when relevant inputs change. Same-execution review is not runtime replication. The TCP adapter remains harness-only; callback panic accounting, production listener supervision, multi-ingress/nonHTTP event routing and full G03 remain open. Hardware, provider, target/resource, physical output and native Tailnet requirements remain unqualified. Broader earlier native failures and the publication-contention control are retained in the [preceding qualification](../20261113-owned-eventing/RUN.md).
