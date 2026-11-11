# Host qualification: actual codec heap observations and bounded replay

The existing decoder now has an actual counting-allocator probe, not an estimate from output-buffer capacities. One native test exercises nine existing stereo fixtures twice: first use and warm use. Each measurement owns the encoded input copy, decoder internals, accumulated complete output, container seek overlap and rate-adapter output. A positive sensor proves the allocator is active. The largest observed requested-byte peak above the calling-thread baseline is **1,960,746 bytes**. This is not process RSS, streaming steady-state memory, a universal input bound or old-board admission.

All nine warm scopes have net zero requested bytes. Three first-use scopes retain unexplained positive deltas: 10,792, 334,028 and 319,524 bytes. They remain `unknown_nonzero_net`; no cache explanation or leak-free claim is invented. Earlier tracks may initialize shared state for later ones. Static fixture/reference storage, other threads, stack, allocator overhead and total resident memory are outside the measurement. No numeric device RAM threshold was admitted.

## Executed gates

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_HEAP_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-alloc-probe --test s02_codec_heap --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_CLIPPY_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 --keep-going -- -D warnings
python3 -B tests/s02/run_cases.py --tier full --judge "$S02_ACTUAL_CODEC_LOG" "$S02_ACTUAL_HEAP_LOG" --receipts "$S02_PRIVATE_RECEIPTS"
```

| Gate | Native job | Result |
|---|---|---|
| Corrected dedicated heap test | 30104858719683010 | 1 passed; 18 observations across nine fixtures; zero failed, ignored or filtered |
| Strict workspace/all-target Clippy | 30104858719683012 | Passed, exit 0; workspace/all targets with `-D warnings` |

The supervisor independently matched all 1,550 selected paths, SHA-256 values and lengths to the corrected 1,552-file inventory and checked the heap job's terminal acknowledgement, absent wrapper and retired custody. The Rust lock change adds exactly one existing workspace codec edge to the test-only allocator package; no package version, checksum, feature, decoder algorithm, fixture, expected length or tolerance changed.

The native probe checks actual decoded samples, existing source/reference digests and the original four-LSB/1.5-LSB-RMS lossy limits. It performs real container seeks. The 44.1 kHz bridge digest checks cross-run consistency; independent bridge correctness remains the existing 27-test evidence, not a newly pinned joined-output oracle. The 60-second deadline is checked between calls; it cannot interrupt one stuck decoder call.

The previous [60-test codec snapshot](../20261111-native-host/RUN.md) remains evidence for unchanged decode/admission/bridge implementation and vectors. Its original whole-tree source is not relabeled current. The final Python-only follow-on has separate source hashes and controls; it does not mutate either native export.

## Consumer and replay behavior

The existing S02 runner retains all 69 earlier cases and adds one required heap case. Actual codec and corrected heap captures produce **70 passed, zero failed and zero blocked**, with all 141 critical diagnostic events complete and none dropped or lost. Host qualification does not remove the ledger's blocked AAC multichannel row or the three unrequested Spotify formats, and it does not close S02's remaining acceptance.

Input capture rejects nonregular files, invalid UTF-8, growth past eight MiB per file, more than 32 MiB in total or more than 64 attempts. Duplicate input consumes both budgets. D01 attribution, heap records and counts consume the same bounded captured bytes. Private owner-only snapshots are retained; the receipt maps every original path and digest to its exact snapshot. Replay uses full retained paths and preserves attempted order and duplicates, so changed originals and identical basenames cannot silently alter the evidence. These private runtime paths are not public fixture data.

All 64 Python controls execute: 63 pass, zero fail or error, and one existing optional libvorbis/soundfile comparison is skipped. This includes actual CLI replay controls over synthetic logs; those controls do not provide native codec evidence. Two earlier controls failed because their own temporary copies inherited read-only source permissions. Only those owned copies receive write permission before the intended planted mutation; original inputs and assertions remain unchanged. The original errors are retained. Review also caught and corrected basename-only replay and dropped duplicate attempts; no failed verdict was changed into success by discarding input.

## Retained history and limits

Initial native heap job `30104858719682998` passed against its own original source. Strict Clippy `30104858719683001` then failed on two test iterator lints. The corrected export changes only those two expressions, preserves all assertions and has the separate actual heap execution above. Neither passing heap run supplies a Clippy pass. The earlier remote disk-admission refusal is retained in the [staged-sender snapshot](../../n06/20261111-staged-sender/RUN.md).

Whole-input allocation bounds, stack/RSS, old-CPU timing, streaming renderer integration, native providers, physical output and required multichannel support remain unqualified. No firmware was installed and no device was contacted.

Landed source: sender `41322777a9dd4fc071b6fdd07ce4e0b198c2f78e`; codec heap and consumer `f3de19ab318ac6fd8c7337f687fa4a23257de191`. The supervisor matched the landed file hashes to the qualified exports. Both native jobs completed with terminal acknowledgements, absent wrappers and retired custody. No job remains active for this batch.
