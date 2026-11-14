# Dynamic source uncertainty: retained PCM and bounded sends

Source revision: `ec943347dce1668a95b22bb8860189244bb67922`; baseline: `b4f922898fbfcf0c83382a3a1b3c003f21be7c72`. The seven source overlays match the tested immutable candidate. These three evidence files are appended after testing and do not change Rust.

A wider usable clock interval can move its conservative lower bound backwards while local and nominal group time remain monotonic. The corrected owner retains temporarily early prepared PCM and rechecks the actual presentation of every queued frame, signed retry and probe before sending. It leaves the old API defaults, source-policy checks, control budgets and late last-sequence/probe recovery exception intact.

## Executed results

- Original control native 350: expected exit 101; 2 passed / 5 failed / 663 unrelated filtered. Valid widened intervals wrongly stopped with Clock.
- Guard-only control native 351: expected exit 101; 4 passed / 3 failed / 663 unrelated filtered. Post-decode still returned Clock; two other cases actually sent one packet where zero was permitted.
- Corrected strict-remote workspace Clippy native 352: exit 0, all targets, warnings denied.
- Corrected strict-remote workspace native 353: 3029 passed / 0 failed / 2 existing ignored / 0 filtered across 81 result groups. All 15 new declared names occurred once/ok.
- Real localhost UDP positive: 24000 frames / 94 packets / 192 final frames, peak 1 LSB and RMS 0.7097975063354337 against unchanged 4 / 1.5 tolerances; 94 real reports sent/accepted, zero queue/in-flight and terminal Drained.

Both controls execute the same frozen seven-test prefix. The corrected test child retains that prefix byte-for-byte and adds the complete UDP case; seven carrier cases cover horizon equality, independent peer progress, retry identity, probes/credit/cancellation, late last-sequence recovery, overflow and compatibility. A source-review defect in the initial probe test expected an unchanged stall counter; the corrected expectation requires exactly +1 and full equality for every other field. A later test-only copy cleanup changes five single-element slice arguments without altering assertions. Neither source revision is represented as an observed native lint failure.

The controls each matched 1665 source tuples; final Clippy/tests each matched 1666. Completed commands have terminal ACK, actual source/pair/tree/record release and absent wrappers. Successful final gates also have explicit staging release; failure controls have artifacts skipped and no staging-release flag, recorded as null. Independent source and same-execution reviews do not count as additional experiments.

## Reproduction

Use the source revision above, a fresh eligible worker, and complete retained stdout/stderr plus terminal/custody evidence. Private RCH socket/config paths are omitted. Tested semantic commands after worker selection:

```sh
RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "${RCH_WORKER_ID:?set an eligible worker}" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --locked --offline --workspace --all-targets -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 rch --no-self-healing exec --source-content-receipt --worker "${RCH_WORKER_ID:?set an eligible worker}" -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline --workspace --no-fail-fast -j1 -- --show-output --test-threads=1
```

The two control inventories bind baseline b4f9228 with only the runtime test-module include and the identical seven-test child. Guard-only additionally removes solely the decreasing-lower-bound predicate. Each used the same strict-remote environment and `cargo +1.99.0 test --locked --offline -p franken-speaker --lib source_runtime::tests::uncertainty:: -j1 -- --show-output --test-threads=1`. Their exact failures remain in observed.txt and their source/log hashes in receipt.json.

## Qualification boundary

The positive uses actual localhost UDP, codec, frame authentication and receiver-issued reports. Its clock is scripted; configured 500 us work, 1 ms margin and 250 ms horizon are admitted test assumptions, not measured CPU or device deadlines. The PCM oracle covers received media before protection DSP. The other unit ports and clocks are explicit models. No supplied test source reads its reference PCM as decoder input.

This does not qualify live distributed clock authority, finite control-lease expiry, provider/native-tailnet sessions, post-DSP/acoustic output, big-endian execution, legacy-board RAM/CPU fit, or the source/control authority bridge. The separate client SDK was not rerun on this candidate. Original N07 acceptance and dependencies remain open.

Consumer: supervisor/reviewer deciding whether this demonstrated source/pump correction may be published under AGENTS.md. The minimal snapshot binds causal failures and positive runs to exact source; active maintenance retires at completion of this bounded publication, retaining historical evidence only.
