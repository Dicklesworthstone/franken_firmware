# Finite-source owner and host-process qualification — 2026-11-12

The normal speaker executable can now read a finite Vorbis or MP3 source,
apply the existing group/source policy, pace authenticated localhost UDP,
and capture actual N04-prepared PCM in another process. The owner uses fresh
clock observations, bounds decoding lookahead, fences old work after source
or topology changes, and distinguishes EOF from transport drain. A genuine
receiver-credit heartbeat recovers a lost final report without replaying PCM.
These are host capabilities. A drained sender is not evidence of DAC playout.

The frozen input is baseline `b1c0324f4eb8375070c407ec13d4b5c5f7f5456f`
plus the thirteen overlays in [source-inputs.json](source-inputs.json).
All six Rust/README paths in commit
`0a362a57cf3a2d6c1823abf3d7334e93868083eb` match that exact candidate.
The source inventory digest is
`94fc078ac1e82865b25eeefcfc262d42eac44a5a63dfceaa01012b527bcaa4fe`.
The supervisor independently checked every candidate file, each transferred
receipt input, the terminal status and source/pair release. Native jobs
transferred 1,579 files; only the two tracker metadata files were excluded.
All thirteen overlays still matched the checkout at publication preparation.
The process supervisor, controls and long vector are committed in
`e491253a2b42af179216e8d33212dce79b079761`.

## Executed verification

The sole verifier used strict remote RCH with local fallback prohibited:
`RCH_REQUIRE_REMOTE=1 rch exec`. These are the executed Cargo arguments,
with RCH's per-job remote build directory represented by `$REMOTE_TARGET`:

```bash
env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --locked --offline -j1 \
  -p franken-stream -p franken-speaker \
  --config "build.build-dir=\"$REMOTE_TARGET\"" --target-dir "$REMOTE_TARGET" \
  --config 'env.RCH_BUILD_SOURCE.value="unknown"' \
  --config 'env.RCH_BUILD_SOURCE.force=true' \
  -- --show-output --test-threads=1

env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 \
  --config "build.build-dir=\"$REMOTE_TARGET\"" --target-dir "$REMOTE_TARGET" \
  --config 'env.RCH_BUILD_SOURCE.value="unknown"' \
  --config 'env.RCH_BUILD_SOURCE.force=true' -- -D warnings
```

Native test job **30105869848936479** completed with **818 passed, zero
failed, one preexisting ignored and zero filtered**, across fifteen result
footers. Four targets executed zero tests and earn no test credit. Seventeen
new Rust tests ran: ten owner tests, five CLI tests and two integration tests.
One integration test contains the three process cases below; they are not
three additional Rust tests. All-target workspace Clippy job
**30105869848936481** completed with exit zero and `-D warnings`.
Both jobs have terminal ACK, zero returned status, released source/pair
custody and retired trees. Native artifact retrieval reported zero build
files; no distributable executable is published by these receipts.

| Actual process case | Frames / samples | Blocks / partial tail | Peak / RMS error |
|---|---:|---:|---:|
| 48 kHz stereo Vorbis | 24,000 / 48,000 | 94 / 192 frames | 1 / 0.04587119648174295 LSB |
| 48 kHz stereo MP3, 1.5 seconds | 72,000 / 144,000 | 282 / 64 frames | 1 / 0.04579543888011362 LSB |
| Wrong authentication key | zero accepted/captured | 16 authentication rejections | no PCM output |

The longer source exceeds the receiver's 94-block window. Both complete
captures match independent scalar reference PCM, exact lengths, contiguous
frame positions and presentation times. The limits remain peak <=4 LSB and
RMS <=1.5 LSB, without alignment search, trimming or scaling. The original
S02 fixtures, manifest and limits were not changed. The added long fixture
has a reproducible FFmpeg generator and its own hash-bound manifest.

The Python supervisor freezes the input executable and source bytes, owns
only its child process groups, bounds waits/output, and retains failure
artifacts. Its seventeen oracle/supervisor controls passed, including a real
hung helper and descendant cleanup. D01 controls passed 59/59; existing N07
validator controls passed 44/44. The unchanged N07 consumer accepted the
complete final native test log: **25/25 cases, 7/7 META checks**. That is
additional consumption of the same execution, not another native run.
Changed Rust paths passed rustfmt; all three Python files passed py_compile;
the shell entry point passed bash -n; git diff --check passed.

[observed.txt](observed.txt) is an explicitly selected sanitized excerpt,
with the actual process summary and result footers. It is not the raw input
to the N07 consumer. Raw-log, receipt-root and source hashes, including prior
failures, are retained in [source-inputs.json](source-inputs.json).

## Retained failures and corrections

- Job **30104858719683341** exited 101 during compilation before any test
  ran: a test-only AtomicUsize fetch_update deprecation under Rust 1.99.0
  met the verifier's `-D warnings`. The compiler-proposed try_update call
  replaced it. This attempt earns no test or Clippy pass.
- Job **30104858719683357** passed 818 tests, with one ignored, but its
  serial `--nocapture` output interrupted result prefixes. The unchanged
  N07 anti-spoof policy rejected all 25 evidence cases. Those were evidence
  failures, not 25 failed Rust tests. The supervisor's capture choice caused
  an avoidable extra run; final verification used supported `--show-output`
  without filtering raw output or weakening the consumer.
- Clippy job **30104858719683365** exited 101 on a chunks_exact iteration
  lint. The CLI uses as_chunks in the final candidate; a test type alias
  cleanup was preemptive. Assertions, references and tolerances stayed fixed.
- A tool/service interruption delayed final admission and scheduled tending.
  The frozen candidate was preserved; work resumed after fresh remote
  admission and custody checks. No continuous-monitoring claim spans that gap.

## Remaining acceptance

These results do not qualify Spotify or AirPlay sessions, Alexa, native
Tailscale, a legacy-kernel guest, per-board CPU/RAM/stack budgets, radio
performance, clocks on different machines, drivers, physical audio, or the
full Q07 service journeys. Decoder preparation can block and must be placed
away from a protected renderer. Topology changes terminally fence this owner
and require a rebind; dynamic joining is not delivered here. The same-host
anchor is a test fixture, not N03 fleet clock synchronization. S02, N07 and
Q07 retain their original unmet acceptance requirements and remain open.
