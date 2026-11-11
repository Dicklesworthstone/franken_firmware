# Future-epoch receiver staging: native host evidence

The actual media path can now reserve and prefetch a separate next-epoch
FEC receiver, playout engine and ingress binding while the old N01 stream
continues. `VerifiedFecProposal` comes from the existing authenticated control
endpoint; `FutureFecAuthority` borrows the currently installed
`FleetControlOwner` round. Fresh checks reject changed authority, member
snapshot, stream, epoch, origin, binding or start relation.

This component prepares resources. It does not acknowledge remote readiness
or activate a group transition. FFCN v1 authenticates the proposal tuple;
its capability ACK does not authenticate the locally supplied anchor/start
or media key. The new candidate deliberately exposes no activation operation.

## Commands and actual results

Run from the repository root with Rust 1.99.0 and provisioned locked offline
dependencies. The private worker selectors are omitted below; these are the
executed remote command bodies. No local Cargo or fallback was used.

```sh
# Native 30103800983323521
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test -p franken-control -p franken-stream -p franken-speaker \
  --lib --locked --offline -j1 --no-fail-fast -- --show-output

# Native 30103800983323524
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 \
  --keep-going -- -D warnings

# Native 30103800983323529; qualifier has its own lockfile
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --manifest-path toolchain/n06-fec-profile/Cargo.toml \
  --locked --offline -j1 -- --show-output

# Non-compiling source/adapter checks
rustfmt +1.99.0 --edition 2024 --check --config skip_children=true \
  crates/franken-control/src/channel/fec_negotiation.rs \
  crates/franken-control/src/channel/owner.rs \
  crates/franken-speaker/src/media_playout.rs \
  crates/franken-speaker/src/net_carrier.rs
python3 -B tests/n06/test_judge.py
python3 -B tests/n06/test_future_observation.py
python3 -m py_compile tests/n06/reference.py tests/n06/test_future_observation.py \
  tests/n06/run_cases.py tests/n06/test_judge.py

# Supply the two actual captures above, not fabricated observation rows.
# Expected current result: exit 3, 11 passed, 0 failed, 2 blocked, qualified=false.
python3 -B tests/n06/run_cases.py --tier full \
  --judge "$N06_LIBRARIES_LOG" --judge "$N06_REFERENCE_LOG"
```

| Gate | Passed | Failed | Ignored | Filtered | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full control library | 636 | 0 | 0 | 0 | 0 |
| Full speaker library | 464 | 0 | 0 | 0 | 0 |
| Full stream library | 206 | 0 | 0 | 0 | 0 |
| Standalone coding reference | 3 | 0 | 0 | 0 | 0 |
| Strict workspace/all-target Clippy | Not a test run | — | — | — | 0 |
| Python adapter/oracle controls | 16 | 0 | 0 | 0 | 0 |
| Original full N06 evidence pipeline | 11 | 0 | — | — | 3: two blocked |

The library total is 1,306, not an addition of overlapping earlier runs.
The reference also has a separate zero-test doctest footer, which contributes
no executed tests. Its actual observations verify 65,536 GF products, all
163 recovery subsets, a positive allocator sensor and zero packet-path heap
allocations in the tested scenario. These remain host-development checks,
not a measured board work bound.

All seven new native names occur once as `ok` rows. The actual
`N06-FUTURE` record independently checks exact old and recovered future PCM,
next-epoch identity and two recovered blocks. The logical host reservation
counter changes from 101,040 to 276,925 bytes and returns to 101,040 after
drop. Both outputs require `Outcome::Real`; concealment cannot satisfy the
PCM oracle. Refusal tests preserve current PCM, replay state and carrier
credit through stale authority/binding, wrong owner, insufficient budget,
cancellation, restart and generation exhaustion.

The supervisor compared every one of the 1,567 captured files with the
checkout for all three gates before publication. All three captured trees
match; eight wave hashes and both Cargo lockfiles are retained in
`source-inputs.json`. Commands/wrappers exited zero, terminal ACKs were
recorded, and source/tree/pair/lease custody was released before edits.
Raw captures stay private because they contain infrastructure addresses.
`observed.txt` contains explicitly selected actual output excerpts.

The additive Python adapter preserves all 82 prior case/stem/name mappings
and requires seven new names, for 89 total. It additionally requires exactly
one independently checked actual future record. Planted parser controls
reject missing, ignored, ambiguous or failed native requirements and absent,
malformed, duplicate or corrupt observations. Synthetic control rows are
never native proof. All 13 original cases and both unresolved integration
blockers remain; the full pipeline truthfully returns unqualified.

## Failure and source history retained

- Initial native 30103800983323484 stopped before Cargo: installed RCH
  2.1.36 compared String-sorted and path-component-sorted namespaces.
  Equal path sets were independently reproduced with different order.
  No tests ran. Its settled refusal is retained, not counted as a code failure.
  Recovery used supported ordinary source-receipt mode with source guards
  intact. It includes the unchanged peer T01 staged assets; it makes no
  clean-overlay exclusion claim. No ignores or global settings were changed.
- Native 30103800983323494 passed the same 1,306 tests. Strict Clippy
  30103800983323502 then failed on `u64::MAX & !1023` in an overflow test.
  The sole repair, `!1023_u64`, preserves the exact value
  `0xfffffffffffffc00` and all assertions. Independent review reconstructed
  the entire original file hash by reversing that one expression. The final
  test and Clippy runs above cover the repaired source; the failure remains.
- Reuse of older reference 30103800983323096 was rejected: two of 80 checked
  Cargo/Rust inputs had changed. An exploratory parse of that old capture is
  not current qualification. The actual current-source replacement 23529
  above supplies the accepted coding observations.
- A concurrent session committed six source/test files as `6644026` before
  author freeze and verification. That history was preserved. The supervisor
  qualified the actual frozen sources after the commit and kept unrelated
  staged work outside this publication commit.

## Qualification boundary

These are native Linux host tests with scripted clocks, synthetic ledgers
and test credentials. Byte counters describe the explicitly accounted
objects on these hosts, not process RSS, a 32 MiB endpoint fit or board WCET.
No Sonos silicon, retained driver, physical output, provider, old kernel or
QEMU guest was exercised by these gates.

The candidate remains separate from active output. Its v1 local key/start
inputs are not authenticated receiver readiness. Endpoint staging does not
inspect unread port datagrams or establish a network ingress fence. Shared
Arc construction may still abort on allocator failure; numeric capacity and
fallible receiver-reservation refusals are different, and no allocator abort
was forced. A candidate surviving its media owner remains caller-owned and
must remain budgeted. Original authenticated readiness and coordinated
activation acceptance stays open; N06 is not closed.
