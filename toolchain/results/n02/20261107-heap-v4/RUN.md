# N02: measured control-channel heap and panic-safe probe

Strictly remote host execution, 2026-11-07, Rust `nightly-2026-08-31`.
This is requested-allocation accounting for the existing two-member fixture,
not process RSS, allocator overhead/fragmentation, stack, target execution or
a production memory admission. N02 remains open.

The allocator now counts live requested bytes and preserves enclosing peaks
when a nested measurement unwinds. The real control endpoint, channel,
authentication, logging and session run against bounds derived from their
declared caps. The large and small campaigns use 6,000 and 2,000 operations.

```sh
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 clippy \
  --locked --offline -p franken-alloc-probe --all-targets -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 test \
  --locked --offline -p franken-alloc-probe -j1 \
  -- --show-output --test-threads=1

scripts/e2e/n02
python3 tests/p01/make_vectors.py --check
```

Final all-target Clippy passed; native execution passed all 36 named tests,
including 13 allocator and six channel-heap tests. The independent Python
reference checks passed 72/72; all 137 workspace vectors were current. That
reference entry point explicitly does not execute Rust. The native command
above supplies the separate actual Rust evidence. Formatting and Python
compilation checks passed. No assertion or numeric memory bound was relaxed.

The provisional channel's measured datagram/step peaks were 2,900/8,008 bytes
against bounds 12,528/62,640; maximum retained bytes were 58,219 against
152,544. Third/fourth-quarter floors were both 53,150. The small channel's
figures and exact original observation lines are in `native.log`.

Real-channel plants exercise retained-message growth and transient scratch
allocation. Step-peak and slow-growth plants use synthetic observations;
the 1,696-byte growth allowance can hide smaller leaks over that interval.
Larger groups and full-board resource accounting still require qualification.

The new unwind regression was also executed against the exact preceding
allocator, with all 13 tests retained: 12 passed and one failed. After an
earlier 4,194,304-byte peak, the old allocator reported only 1,654 bytes when
a nested panic was caught. `old-red.log` retains that actual causal failure.
The corrected allocator was restored byte for byte and the final complete
native run passed. A prior native attempt was refused by RCH's disk budget
before the Rust command started; that refusal was not counted as a test run.

Both final captures match all 1,229 source files checked at review and the
ten selected inputs in `qualification.json`; terminal acknowledgment and
source/worker release were verified. Public logs retain verbatim test and
observation lines while excluding transport manifests and private paths.
Direct local compiler checks performed by a reviewer were excluded.

The lock change adds two existing path dev-dependencies to the test-only
allocator probe. No registry package version/checksum changed. The prior
N05 qualification remains tied to its own recorded source and lock hashes;
this change does not relabel it as a run of the new tree. E06's lock-bound
inventory is refreshed separately before admitting the combined candidate.
