# N07 stream library unit execution

The stream library's own unit binary executed **194 passed, 0 failed,
0 ignored**, including all **42/42** carrier names predeclared in
`tests/n07/run_cases.py` before the run.
This closes the component execution gap recorded in N07 comment 358; the full
N07 bead remains open. [native.txt](native.txt) preserves the observed names and
summary. The tests completed in 14.67 seconds.

From the FrankenFirmware root at `09207c424545946a398a62e178e9563bfa5dd10e`:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker trj -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-ffw-stream-unit \
  cargo test --locked -p franken-stream --lib --no-fail-fast -j1 -- \
  --show-output --test-threads=1
```

Build `30099060530610864` returned 0. The remote command took 268.342 seconds;
the complete remote invocation took 325.9 seconds. All **1,386/1,386** captured
source files matched their current bytes, sizes and executable modes before
this evidence was added. [code-inputs.sha256](code-inputs.sha256) retains the
stream-package and root build-input hashes from that receipt. Content root:
`1281a720851f9fbaf4e96a259a6d81e90b14a7cf8cd99c9c5993ae25384a3601`;
receipt root:
`6a102b82e459cb02b54505647868456066f44894d8ee16b0bcb3d51f383e2493`.
Terminal acknowledgment, a dead wrapper, absent owner and all five
source/tree/pair/output/recovery completion checks were verified.

This is native host unit execution, including scripted transport and timing
fixtures. It adds no claim that these cases ran the device socket backend,
physical radio, group audio output, or a board's CPU/memory profile. Existing
isolated-loopback evidence remains separately identified. E04/P03/N02,
multicast/radio lifecycle and other original N07 requirements remain binding.
The earlier speaker-level and heap-accounting results are not replaced.

The complete operational capture is retained privately with SHA-256
`4850d554ab34dab6c72a4f20d110ab32c5ee6c6e19fd47927e382ffc20f68550`;
this directory contains selected output and source witnesses, not the raw
worker transcript or source-manifest JSON.
