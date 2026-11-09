# P05 native cancellation audit: executed evidence

One native audit gate executed successfully: **50 passed, 0 failed, 0 ignored, 0 filtered out**, in 4.14 seconds. This is native remote-host evidence for the frozen source below. It does not complete P05 or qualify the whole project, P03, big-endian/guest execution, hardware, service/provider behavior or release. Root independently checked the archived source hashes, all fifty names, terminal custody and privacy before publication.

## Source and exact command

Public Asupersync commit: `4f624497ad28944027cc1d8193054ec2a11a210e`. The observed Bash invocation checked this exact HEAD and clean status; the retained command output records the same clean revision at launch and completion. The source-content receipt binds one root with 21,001 files. `receipt-summary.json` retains the twelve selected source hashes, including runtime legacy_profile/builder/current_thread and both audit source files. Receipt root: `2e3c4d48a2be912bf05fb89d5162515b0f0518b7da9cc621c24750873ee23fa3`.

The observed execution invocation, with operational paths pseudonymized:

```sh
bash <operational-path> 1 -- env RCH_REQUIRE_REMOTE=1 RCH_TEST_TIMEOUT_SEC=3600 rch exec --source-content-receipt -- env CARGO_TARGET_DIR=<operational-path> CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-D warnings -C debuginfo=0" cargo test -p asupersync --locked -j 1 --test runtime_abort_vs_cancel_semantics_audit -- --nocapture
```

This is copied from the first observed execution call (`2026-11-09T06:43:09.532Z`, `toolu_01TC3YpSVNqMki2df57ZzqBf`); its raw input-file hash and complete sanitized Bash input are in the summary. The second recorded call was monitoring, not another execution. The exact Cargo argv is unfiltered: no test-name selector follows `--`, only `--nocapture`. Command text was not reconstructed from `command_sha256`.

## Count reconciliation and actual output

The original predeclared count of **48** covered the parent file only. It omitted two tests in the included `stream_cancellation` module:

- `stream_cancellation::channel_streams_cancel_without_producer_on_native_current_thread`
- `stream_cancellation::channel_streams_cancel_without_producer_on_native_sharded_workers`

Source inspection finds 48 parent functions plus these 2 included functions. Their 50 distinct names exactly match the 50 observed `ok` lines. The unfiltered command was unchanged; this correction does not turn the original 48 into a claim that 50 were predeclared. No test, selector, expectation or assertion was changed to reconcile the count.

`audit.log` retains the actual compilation/test output, all 50 named passes, seven expected panic-hook diagnostics and the terminal result. The panic diagnostics remain visible; the Rust test summary reports zero failures. Only the giant source-content receipt line is omitted. Its exact byte count/hash, the complete raw log hash, full receipt hash and native lease hash remain in `receipt-summary.json`. Log receipt and supplied full receipt are semantically identical.

An earlier clean-overlay attempt was refused before Cargo execution by the installed client's namespace comparison. It ran zero tests and is not a failed Rust test or a second successful audit. Its raw log binding is retained in the summary; the successful ordinary-receipt run does not erase that refusal. Later focused-library and formatting attempts are separate pending gates.

## Terminal custody and limits

Build `30100509981410708` is recorded finished with exit 0, strict remote, terminal acknowledgment, wrapper dead and owner absent. Source, tree, pair, retired and staging release fields are true. These are facts from the exact unrounded native identity, not a nearby numeric ID.

The executed audit parent SHA256 is `83c620459150469003c4038988c70598477d469a5c60add01028ba76c06e9d39`; the included child is `daf75da8c73ad7d61391ae7c8f017ed704d7898e0e1d28b11295588a860c2d6a`. A later local readback matched 11 of the selected 12 files; `src/observability/otel/sdk/traces.rs` had changed. This archive retains its executed receipt hash and qualifies that snapshot only.

All operational paths, addresses, account and fleet-worker labels are pseudonymized; actual diagnostics and verdicts are preserved. Archive preparation performed no additional builds or source changes. Unrelated later lib and formatting attempts are outside this evidence.
