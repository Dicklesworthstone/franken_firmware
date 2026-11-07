# N07 retained carrier: host execution and BE compile qualification

Baseline `cc4fd89`; exact captured inputs and publication hashes are in `qualification.json`.
The only post-capture source difference is the contract's status text. All code, tests, model,
fixture and script bytes match all four remote source receipts. Each capture matched all
1,286 local files before publication; terminal ACK, absent wrapper/owner and all five release
flags were checked. Public logs retain compiler result lines, test verdicts and all 18 actual
`N07-OBSERVED` records; private RCH manifests and machine paths are omitted. Raw-log hashes
remain in the qualification record. The published native log itself reproduces the judge.

Commands (all through strict remote RCH, pinned `nightly-2026-08-31`; compiler jobs used `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, and tests also used `CARGO_PROFILE_TEST_DEBUG=0`):

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker vmi1293453 -- cargo +nightly-2026-08-31 test --locked --offline -j1 --no-fail-fast -p franken-stream -p franken-speaker -- --show-output --test-threads=1
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker vmi1293453 -- cargo +nightly-2026-08-31 clippy --locked --offline -j1 -p franken-stream -p franken-speaker --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-stream -p franken-speaker --lib --target powerpc-unknown-linux-musl -Z build-std=std,panic_abort
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-stream -p franken-speaker --lib --target mips-unknown-linux-musl -Z build-std=std,panic_abort
python3 -B tests/n07/run_cases.py --judge toolchain/results/n07/20261107-retained-carrier/native.log --revision cc4fd89-dirty --receipts toolchain/results/n07/20261107-retained-carrier
python3 -B -m unittest discover -s tests/n07 -p 'test_*.py'
```

Native: **521 passed, 0 failed, 1 ignored**, across 13 result groups. The ignored test is
`d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap`; that long soak was not run.
Strict all-target Clippy and both BE library checks passed. BE checks establish compilation,
not guest execution or old-kernel compatibility. Python: **32 passed**. The independent
host-log judge: **24 passed, 0 failed, 0 failed metadata checks** (`receipt.json`).

The actual carrier now feeds N01 authentication and N04 playout, with bounded pacing,
per-peer isolation, authenticated consumed credit, long-outage probes, protected sequence
recovery, epoch fencing and MTU validation. Host loopback worlds include live rendering
through an ingress outage, stale datagrams earning credit without stale PCM, and fresh
audio after recovery. Capacity reporting includes allocated retained payloads and saturates
at `usize::MAX` instead of wrapping. It excludes allocator overhead, queue structures and
kernel buffers; it is not a board RSS measurement.

Earlier failures remain recorded in `history.json`. The initial three host failures exposed
test-world errors in rebind counting, whole-process versus ingress freezing, and expected
link generations. A subsequent run caught a sample oracle that repeated every 200 blocks:
the revised oracle includes the block index and has an explicit old-collision control.
The first arithmetic-regression Python run failed because the new Rust test was not mapped;
it was registered before the final 32-test run. Cache and admission failures were not
counted as product test failures. No assertions were weakened to obtain the final results.

This component does **not** close `ffw-ybr`: its E04/P03/N02 prerequisites remain open.
WiFi/radio ownership, multicast, DHCP, actual board CPU/RAM and old-kernel guest execution
remain unqualified. The lifecycle ownership matrix preserves those blockers. No hardware
or provider traffic was used. The separate FEC adapter candidate is not included here.
