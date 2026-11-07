# N05: source-bound offline repair comparison

Profile `n05.rfc6330.k4-r4.v4`, seed `6221061`, 2026-11-07.
This is a synthetic host experiment using real Rust coding and N04 playout
code. It is not device, radio, provider, old-kernel, DAC, acoustics, 24-hour
reliability or board CPU/RAM qualification. It admits no production FEC profile.

The study compares concealment, bounded retransmission, actual RFC 6330
RaptorQ, and RaptorQ followed by a bounded retransmission tail. All strategies
share the source trace, packetization, deadlines, channel and work allowance.
Both retransmission paths use the same observed-prefix planning and admission
seam; future channel delivery happens after request send times are fixed.
Actual N04 admission rejects late and duplicate repairs. Positive, cancelled,
exhausted-work, render-starvation and explicitly unenforced controls are retained.

## Observed commands

All Rust compilation and native execution ran through strictly remote RCH.
The standalone lock is separate from the firmware lock. The final native call
selected the same worker as the first run to reuse its compiled artifacts;
worker identities and private paths are omitted here.

```sh
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=3 CARGO_PROFILE_TEST_OPT_LEVEL=3 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 test \
  --manifest-path toolchain/n05-repair-study/Cargo.toml --locked -j1 \
  -- --show-output --test-threads=1

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=3 CARGO_PROFILE_TEST_OPT_LEVEL=3 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 clippy \
  --manifest-path toolchain/n05-repair-study/Cargo.toml --locked --all-targets -j1 \
  -- -D warnings

python3 -B -W error -m unittest discover -s tests/n05 -p 'test_*.py'
scripts/e2e/n05 --tier full \
  --judge toolchain/results/n05/20261107-profile-v4/native.log \
  --receipts build/n05-public-review
```

## Actual results

- All-target check passed. Initial Clippy failed on callback type complexity;
  a type alias fixed that spelling, without a suppression or behavior change.
  Final strict all-target Clippy passed.
- Both native runs passed all 21 tests: 18 library, two allocation tests and
  one isolated-worker campaign. All original test names remain required.
- The first native command used serial `--nocapture`. Its output was refused
  by the existing D01 attribution guard: E2E reported three passed, nine
  blocked. This was not promoted to a qualification pass.
- The unchanged source/profile rerun used captured-output reporting. The
  existing full judge passed 12/12, with zero failed, blocked or lost-diagnostic
  cases. No parser, expected outcome or timing threshold was changed.
- There are 37 actual isolated-worker observations. Exhaustive allocation
  measurement covers all 163 admitted receive subsets and agrees with the
  independent `raptorq =2.0.1` reference. All subsets recovered; none was
  rank-deficient. Maximum conservative decoder heap bound: 146,540 bytes,
  below the frozen 1,048,576-byte limit. This is requested-allocation accounting,
  not process RSS, allocator fragmentation, stack or whole-board memory.

For the frozen 100 ms burst:

| Strategy | Unrecovered blocks | Repair bytes | Feedback bytes |
| --- | ---: | ---: | ---: |
| Concealment | 19 | 0 | 0 |
| Retransmission | 5 | 20,976 | 192 |
| RaptorQ | 17 | 70,912 | 0 |
| Hybrid | 1 | 89,680 | 160 |

These observations expose the traffic/recovery tradeoff. They are not a
universal winner, a dropout-proof promise, or physical network evidence.
Packet/decision CPU on the virtual calendar and board WCET remain unqualified.
The optimized recipe, 1 ms coding reserve and 20 ms work allowance were frozen
before measurements and were not relaxed after a failing result.

`native.log` retains exact public observation and libtest lines from the actual
final raw log, including all controls and the exhaustive memory record. Raw
worker addresses, paths and source manifests are excluded. The same full judge
passes this public excerpt. The initial blocked E2E output is retained in
`initial-attribution-blocked.log`; initial lint failure is recorded separately.
Source hashes, raw-log digests, receipt roots and settled custody are in
`qualification.json`. The contract's subsequent status-only update is distinct
from its capture-time digest; runtime/test/vector/manifest bytes are unchanged.
