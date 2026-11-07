# S03 compressed lookahead component

Base `80fa336`; the four source inputs in `qualification.json` match every remote capture.
All four captures matched **1,297/1,297** local files before publication, and finished with
terminal ACK, absent wrapper/owner and all five release flags. The public logs retain
compiler result lines and native test verdicts; machine paths and private RCH manifests
are omitted. Raw and published log hashes are recorded separately.

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker vmi1293453 -- cargo +nightly-2026-08-31 test --locked --offline -j1 -p franken-session -- --show-output --test-threads=1
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked --offline -j1 -p franken-session --all-targets -- -D warnings
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-session --lib --target powerpc-unknown-linux-musl -Z build-std=std,panic_abort
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-session --lib --target mips-unknown-linux-musl -Z build-std=std,panic_abort
```

Native: **117 passed, zero failed or ignored** (113 library, four G01 replay integration tests),
including **41 lookahead tests**. Strict all-target Clippy and both BE library checks passed.
Rustfmt and diff checks passed. BE checks establish compilation, not guest execution.
The first native request was cancelled while queued on `hz4`, before any build was admitted;
its acknowledged terminal state is retained in the qualification record. No local fallback ran.

The queue separately caps compressed bytes, exact-frame media time, chunks and outstanding
decoder work. Variable-rate payloads and zero-frame configuration chunks remain valid.
Gapless fetch position and playback head are distinct; shrinking evicts furthest-ahead data
and restores the refetch position. Seek/skip invalidates old ingress immediately but waits
for outstanding work to retire and for a matching output-domain tail to drain or flush.
Queue-bound handoff identities reject foreign tickets even when sequence and epoch collide.
Tests cover rate conversion domains, stale/superseded fences, timeout, capacity boundaries,
late submissions and seeded state-machine sequences with an independent shadow state.

The real `OutputFenceSource` HAL adapter is absent in this revision. `UnqualifiedFence`
refuses to acknowledge handed-out output. Provider fetching, decoding, native source
qualification, board RSS and memory-ledger admission remain open; this is not full S03
completion. Review of the frozen source is recorded in Agent Mail10902.
