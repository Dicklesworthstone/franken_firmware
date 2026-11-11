# Host qualification: bounded finite-reader decoding

`ContainerDecoder::open_reader` accepts stable finite seekable Ogg Vorbis and
MP3 input without requiring the decoder to own an entire encoded-input `Vec`.
The supplied reader may itself retain the whole input. Existing `Vec`, raw
AAC/ALAC and PCM interfaces remain available. This is a synchronous finite
input API, not a resumable live network stream or a board-memory admission.

## Behavior and coverage

Declared length, lifetime reads, reads per public operation, lifetime seeks
and read-chunk size are bounded. Reader limits are checked before admitting
unbounded work; the operation counter uses `AtomicU32` for 32-bit portability.
A sticky out-of-band fault preserves an I/O or budget error that demuxer
probing might otherwise swallow. A reader-backed public operation error
poisons the decoder, and a failed pull clears its output. `WouldBlock` is
fatal under this API; retry/resume requires a different source contract.

Eight integration tests use actual committed encoded fixtures, independent
PCM references, short reads, real seeks, bad references, limits and injected
faults after a valid decoded block. Two unit tests exercise per-pull limits
and decoded seek-error poisoning. The original sample counts and lossy
four-LSB maximum / 1.5-LSB RMS limits are unchanged. Encoded truncation with
a matching declared length may retain the established `End` plus truncated
status; premature underlying EOF violates the reader contract and poisons it.

The existing S02 consumer retains all 61 original Rust case definitions and
nine META cases, and adds `S02-READER`. That case requires all eight reader
integration results exactly once from the attributed `s02_reader` binary.
Headerless or wrong-binary verdicts, repeated input and duplicate results
cannot qualify it. Reader evidence is linked only to the two container rows,
`spotify.ogg_vorbis` and `spotify.mp3`; raw AirPlay rows are independent.

## Executed commands and results

Worker and private-log locations below are parameters. All compilation ran
remotely through RCH; no local Cargo fallback or hardware experiment ran.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-codec --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-alloc-probe --test s02_codec_heap --locked --offline -j1 -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$S02_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 -- -D warnings
rustfmt --check --edition 2024 crates/franken-codec/src/decode.rs crates/franken-codec/src/lib.rs crates/franken-codec/tests/s02_reader.rs
python3 -m py_compile tests/s02/run_cases.py tests/s02/test_s02.py
python3 tests/s02/run_cases.py --tier full --judge "$S02_CODEC_LOG" "$S02_HEAP_LOG" --receipts "$S02_PRIVATE_RECEIPTS"
```

| Gate | Native job | Observed result |
|---|---|---|
| Corrected codec tests | `30104858719683157` | 70 passed: 2 unit + 8 admission + 27 bridge + 25 decode + 8 reader; zero failed, ignored or filtered; zero doctests |
| Dedicated existing heap component | `30104858719683147` | 1 passed; 18 observations; zero failed, ignored or filtered |
| Corrected strict workspace/all-target Clippy | `30104858719683159` | Exit 0 with `-D warnings` |

The final canonical Python controls ran 69 tests: **68 passed, zero failed or
errored, one existing optional libvorbis cross-check skipped** because its
external interpreter was not configured. The actual-log full S02 consumer,
executed with the canonical scripts from outside the checkout, reports
**71 passed, zero failed or blocked**. All **143 critical events** are complete;
zero are dropped or lost. These 71 evidence-pipeline cases are distinct from
the 70 native codec tests. Synthetic rejection controls do not add native
decoder executions.

The supervisor independently matched all 1,562 receipt-selected paths,
SHA-256 values, lengths and executable flags against each 1,564-input export.
The two excluded paths are Beads configuration, not compiler inputs. All
three successful jobs have terminal acknowledgement, absent wrappers, exit
and returned status zero, and released/retired source, tree, pair and staging
custody. Custody retirement does not assert that retained private directories
were deleted. Focused source bindings, receipt roots and log hashes are in
`source-inputs.json`; selected actual output is in `observed.txt`.

The final native export is Git baseline
`8478fbd242756f84b74a0a1d880b623c5683c332` plus the six recorded Rust/Python
overlays. The later contract text is separately hashed and was not compiled.
The heap run precedes a one-line reader-test-only Clippy repair. Its decoder,
library, dependencies, lock and heap-test inputs are identical to the final
ones. Its earlier whole-tree snapshot is not relabeled as the corrected
codec/Clippy snapshot.

## Retained failures and correction history

- Queue request `9253476895574458528` timed out before admission or Cargo;
  exit 103 (`RCH-I001`). It has no native execution or source receipt.
- Native `30104858719683141` uploaded source, then failed with local `EACCES`
  before execution. The immutable export root was mode `0555`, preventing
  RCH's local output-publication probe. A publication-style exclusive-open
  reproduction denied permission; the original syscall was not traced.
  Changing only that owned root to `0755` left all 1,564 input bytes and
  executable flags unchanged. Contained source files remain read-only.
  This applies RCH's existing writable-publication-root requirement; it does
  not bypass a guard or change global RCH settings.
- Native `30104858719683143` then actually passed 70 codec tests against that
  earlier reader-test source. It remains evidence for its own snapshot.
- Strict Clippy `30104858719683150` failed with exit 101 on a repeated-sentinel
  `same_item_push` lint. The only correction replaces one `push(123.0)` with
  an equivalent one-element `resize`, preserving all poisoning assertions.
  No lint allowance, tolerance change or assertion weakening was added.
  The corrected 70-test rerun and strict Clippy pass are recorded above.

The heap observations retain the prior measurement boundary: the existing
**Vec-based** decode/seek/rate path, not File-reader steady-state RSS. The
largest calling-thread requested-byte peak above baseline is **1,960,746**.
All nine warm scopes have net zero requested bytes. Three first-use retained
deltas, **10,792 / 334,028 / 319,524**, remain `unknown_nonzero_net`; no cache
explanation or leak-free claim is inferred. Full heap scope is documented in
the [previous heap qualification](../20261111-codec-heap/RUN.md).

## Qualification boundary

Setup/probing may block, read, seek and allocate; it belongs off the protected
render path with its own budget. Symphonia's read ring starts at 64 KiB and
may grow to 128 KiB for Ogg, with a 192 KiB old/new transient; this is not a
bound on all decoder or process memory. The default encoded-length cap
remains 32 MiB. No long-track or network-resume capability is implied.

Target CPU/stack/RSS, 32 MiB board admission, renderer integration, native
Spotify/AirPlay, required AAC multichannel and physical output remain
unqualified. Generic host tests are not a QEMU firmware boot or legacy-board
performance result. S02 remains open against its original acceptance. No
device was contacted and no firmware was installed.

Landed feature source: `3e1c969b5102691d4f6cc6471223d415e26e486c`.
The supervisor matched all seven committed source paths byte-for-byte to the
reviewed worktree and rechecked all 35 focused publication bindings. Native
results remain bound to their recorded exports, not to a relabeled whole tree.
