# N03 coarse-clock host checks, 2026-11-06

This is native host test and lint evidence. It does not qualify a refreshed
big-endian guest, legacy kernel, physical speaker, audio output or provider.
N03 remains open. The old guest receipt is stale and failing against the
corrected model; it has not been regenerated into a pass.

`inputs.json` records 1,017 repository-export file hashes for candidate v8.
Replace its one `v7_replace_hashes` entry to reconstruct the recorded v7
file-hash set. This is an overapproximation of repository inputs, not a
compiler dependency trace, complete external dependency inventory or toolchain
attestation. Source contents remain in the repository/history; hashes are
evidence bindings, not a self-contained source archive.

## Actual results and changes

- v5: clock 95 unit plus 23 integration tests passed; speaker 263 passed and
  one failed on the old uncertainty expectation. Native exit 101 is retained
  in `tests-v5-failure.txt`; subsequent speaker integration binaries did not run.
- v7: 411 passed, zero failed, one ignored across ten binaries, with all 34
  `N03-TARGET-HOST` records. The ignored case is the separately selected
  25.5-virtual-hour D03 soak. See the whole Cargo test payload in `tests-v7.txt`.
- v7 Clippy: exit 101, because a clock test asserted always-true constant
  arithmetic. The original diagnostic is in `clippy-v7-failure.txt`.
- v8 Clippy: exit zero with warnings denied. The test now captures the public
  clock's prediction before the exchange, measures the independent world's
  actual 5 ms prediction error, and preserves both admission and real-step
  refusal assertions. `clippy-v8.txt` contains the Cargo payload.
- v8 workspace formatting and guest formatting both exited zero. Shared guest
  cases use style edition 2024 without changing the guest's compilation edition.
- **v8 runtime replay is not run.** Its only change from v7 is the strengthened
  clock test. Do not describe the 411-test result as execution of that new test.

The two earlier speaker pins were independently rederived: old reference
uncertainty 621,773 ns and holdover endpoint 21,530,425,001 ns; corrected model
622,774 ns and 21,520,415,001 ns. Only those uncertainty-dependent expectations
changed. Exact presentation-time/frame assertions were preserved.

## Commands

Commands ran from their prepared source exports with strict remote admission
and one requested slot. Worker names below identify build workers, not speakers.

```sh
RCH_REQUIRE_REMOTE=1 RCH_CHECK_SLOTS=1 RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 \
  rch exec --worker trj -- cargo test --locked -p franken-clock \
  -p franken-speaker --all-targets --features harness -j1 -- --nocapture

RCH_REQUIRE_REMOTE=1 RCH_CHECK_SLOTS=1 RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 \
  rch exec --worker ovh-b -- cargo +nightly-2026-08-31 clippy --locked \
  -p franken-clock -p franken-speaker --all-targets --features harness \
  -j1 -- -D warnings

RCH_REQUIRE_REMOTE=1 rch exec --job --worker ovh-b -- \
  cargo +nightly-2026-08-31 fmt --all -- --check

RCH_REQUIRE_REMOTE=1 rch exec --job --worker trj -- \
  cargo fmt --manifest-path toolchain/src/n03-target/Cargo.toml -- --check
```

The runtime and guest-format commands used unversioned Cargo; their compiler
version was not captured. Clippy and workspace formatting used the explicit
nightly pin shown. No compiler-version claim is inferred from a later probe.

`receipt.json` binds the raw retained log hashes, public payload hashes, native
job identities and terminal custody. All listed jobs have terminal ACK, dead
wrappers, absent owners and retired source/tree/pair custody. Public payloads
omit RCH transport chatter; source-mirror and pooled-target paths are replaced
with `<source>` and `<target>`. Cargo test output, counts, failures and stdout
records within those payloads are retained without selecting only successes.

Remaining checks are the current runtime replay, refreshed guest execution and
its seeded/replay/truncation controls, and current target checks. Worker
admission refusals and telemetry failures remain failures or not-run outcomes;
none is treated as a code pass.
