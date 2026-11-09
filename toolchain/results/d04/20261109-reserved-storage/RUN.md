# D04 reserved cleanup storage: native evidence

This is native library-test and source proof for the retained-HAL host model, not speaker, guest, provider or complete D04 qualification. The source in `722aeff` reserves slot payload storage, fault records, session/render events and control queues before Running; event polling borrows a fixed-size record and retains malformed record lengths. A fresh review corrected a short-submit regression: retained memory accounting uses full reserved capacity rather than payload length. The original ownership assertions remain.

## Commands and observed results

From the repository root, centralized verification used strict remote RCH, not local compilation:

```sh
RCH_REQUIRE_REMOTE=1 RCH_TEST_TIMEOUT_SEC=3600 rch exec --source-content-receipt -- cargo test --locked -j 1 -p franken-hal -p franken-speaker --lib
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- cargo clippy --locked -j 1 -p franken-hal -p franken-speaker --all-targets -- -D warnings
python3 tests/d04/run_cases.py --tier full --judge <retained-native-test-log>
```

Test command: **161 HAL + 437 speaker = 598 passed, zero failed, zero ignored**, with all 13 added tests (10 HAL and 3 render) reported once each. This command runs the two library test binaries, not the complete workspace or every integration-test binary. Clippy: **exit 0**, all targets of these two packages with warnings denied. Both jobs have terminal ACK and released source/tree/pair/staging custody in the derived summary.

The full D04 pipeline judges all 58 required render/render-log tests in the actual transcript: **57 planned cases, 54 passed, zero failed, three blocked, exit 3 NOT QUALIFIED**. Remaining cases are board/driver CPU and output qualification, process-death mute qualification, and the production P03 runtime. Do not turn these blocked cases into passes.

Five modified Rust files passed direct `rustfmt --check --edition 2024`; the modified Python runner compiled; its existing unit suite passed 19/19 before and after integration. The full pipeline without a native log was 53 passed/0 failed/4 blocked. These local checks are not target or physical execution.

## Recovery and source limits

Native job `30101959465763438` executed successfully but its original wrapper refused delivery: the coordinator applied P05 files while it was alive. The source-content barrier reported 11 P05-only deltas. The initial ten-file freeze and published blobs agree; no D04 path was among the reported deltas. **The original test job did not emit a passing full source receipt.** Supported same-ID recovery returned command exit 0 and released custody; its daemon's earlier 130 was the wrapper refusal. `test.log` retains that refusal. No replay, source rollback, ignored mismatch or fallback was used.

Clippy job `30101959465763443` subsequently emitted a full source receipt. Its ten D04 hashes match the frozen source and published blobs. `receipt-summary.json` contains that receipt identity/root plus selected source hashes and actual terminal/custody fields read from the native lease records. It is a derived summary, not a replacement native signed receipt. The complete large receipt line is omitted from the public Clippy transcript, with its exact byte count/digest retained; all other lines are retained with ANSI removed and personal paths/addresses redacted. Raw log digests are also recorded.

The independent source review found the reserved-capacity accounting defect and reviewed its correction; agreement between reviewers is not a second runtime execution. The separate Python P05 attribution defect discovered after these runs does not alter D04's judge, test binary names or the source hashes retained here.

## Boundaries

The source audit and stable capacities do not measure allocation failure across a real backend or prove a process-wide memory bound. Arc admission can still abort on process OOM, and the fake backend has allocations outside the audited owner queues. No real driver ABI, electrical mute, hardware DMA, target CPU deadline, kernel OOM recovery, P03 integration, Spotify, AirPlay, Alexa or native Tailscale qualification is claimed. Original D04 and P04 acceptance remains open. No live device was touched.

A concurrent publication swept the code and contract paths into `722aeff` and `13aa046` before this evidence archive was written. The verification bytes are unchanged; this archive records results and limits without rewriting those commits.
