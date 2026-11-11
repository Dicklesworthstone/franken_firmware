# S02 native host decode and rate-bridge evidence

The existing codec implementation passes **60 native Rust tests and all 69 cases of the existing host consumer**. This snapshot qualifies host decode, conversion and admission behavior on the committed synthetic vectors. It does not qualify old-board CPU, heap, stack, native Spotify/AirPlay operation or physical output. AirPlay AAC multichannel remains blocked in the ledger.

No decoder, vector, expected length, coefficient or sample tolerance changed for this run. `source-inputs.json` records the focused source/fixture hashes and the actual source-content receipt. The exported tree had no Git metadata; its build stamp was `unknown`. The supervisor and a separate reviewer independently compared all 1,535 selected path/hash/length entries with the frozen 1,537-file inventory; only two Beads metadata files were excluded.

A later documentation-only correction removes the unsupported assertion that the PowerPC CPU has no FPU from `rate_bridge.rs`. Every non-documentation line remains identical. The 60-test evidence retains its original pre-comment source hash; strict workspace/all-target Clippy separately passed the corrected comment source in job `30104858719682925`.

## Executed commands

The native caller command ran on a Linux worker through strict RCH. Its private placement selector is parameterized below; the compiler, options, scope and existing lockfile are unchanged.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-codec --locked --offline -j1 --no-fail-fast -- --show-output

# Same job only: no codec command was replayed.
rch jobs recover --no-self-healing --timeout-secs 30 --json rchw-32c2da86-590f-4222-9fbe-dd0bdec6afb2

# Independent consumption from the frozen source tree.
python3 -B tests/s02/run_cases.py --tier full --judge "$S02_ACTUAL_CODEC_LOG" --receipts "$S02_PRIVATE_RECEIPTS"
```

| Native job 30104858719682899 | Passed | Failed | Ignored | Filtered |
|---|---:|---:|---:|---:|
| `s02_admission` | 8 | 0 | 0 | 0 |
| `s02_bridge` | 27 | 0 | 0 | 0 |
| `s02_decode` | 25 | 0 | 0 | 0 |

The separate zero-test library and doctest footers contribute no executed tests. The full existing consumer reports 69 planned, 69 passed, zero failed and zero blocked. Its nine META checks pass, and all 139 critical diagnostic events are complete with zero dropped or lost. The full codec capture digest is `0e2c95c5ff6e056a5b9e8428a0e5cc18bfca680874864aa3ed2d8d2e3f08a4a4`; the supervisor's host consumer receipt digest is `eefe30434b57686fe75678c047195a3c0a75af9f32bfecca2768dea678aaff7c`. Actual test names, footers and bounded sample/error counters are preserved in `observed.txt`.

The stereo Vorbis, MP3 and AAC-LC sample comparisons each report a maximum error of one LSB against their existing independent references, within the unchanged four-LSB/1.5-LSB-RMS limits. ALAC and PCM retain their existing lossless checks. The exact integer rate bridge, seek/gapless, malformed-input, format-change and admission tests also run. Decoder capability vectors at 48 kHz do not expand the pinned Spotify admission offers, which still require their declared rates.

The consumer independently keeps `airplay.aac_lc_multichannel` blocked and the three unrequested Spotify formats marked `not_requested_by_pin`. Its host `QUALIFIED` result is not full S02 acceptance. Caller buffer capacities and operation counts are not process RSS or a complete decoder allocation bound; internal codec allocations, native target timing and stack remain unqualified. This run does not wire a source decoder to the speaker renderer.

## Preserved failure and recovery history

Cargo actually exited zero, but an SSH timeout while retiring the remote tree initially left RCH completion unconfirmed and source custody retained. The original wrapper capture remains a failure of completion delivery, not a zero-test run or a settled pass. Supported recovery of that exact wrapper completed without re-executing Cargo. The supervisor then checked command/returned exit zero, terminal acknowledgement, wrapper absence and complete staging/source/tree/pair release and retirement.

Before native evidence arrived, the same 69-case consumer reported nine META passes and 60 native cases blocked. An auxiliary Python unittest invocation separately recorded 38 passes and one argument-parsing invocation error; the affected existing mirror control subsequently passed alone with clean arguments. These earlier outcomes are retained. They are not additional native test executions and are not substituted for the 60-test codec result.

The historical 2026-11-06 Clippy failure and independently corroborated Vorbis-reference correction remain documented in [the S02 contract](../../../../docs/contracts/s02.md). No golden, tolerance, assertion or mandatory ledger row was changed to obtain this result.
