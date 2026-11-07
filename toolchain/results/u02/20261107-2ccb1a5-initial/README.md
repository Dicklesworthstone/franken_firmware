# U02 initial verification, 2026-11-07

These are the first actual U02 compiler and native-test results at source revision
`2ccb1a5c8b1746cd7c5a486e4d077bca393e1605`. **Not qualified:** the native
suite returned101 with28passed/1failed/0ignored. Its independent E2E judge
returned1:5passed/1failed/0blocked;13critical diagnostic events,0lost.

The failed test imposed `found.len()>100` despite the committed vectors containing
97refusal occurrences covering all47expected vector refusal codes. The four
remaining codes are exercised directly. This is an incorrect generic count
precondition, not permission to omit any invariant or manufacture refusal cases.
The original failure and every test-status/result line are retained verbatim
(after ANSI removal). A later correction must preserve all original vectors
and semantic obligations and retain this failed run.

Two additional model defects were independently reproduced by the supervisor
against the original Python reference: an empty group admits an absent target,
and an all-zero capacity-receipt digest yields `proven_by_external_receipt`.
`boundary-bugs-python.log` is an ad-hoc offline Python reproduction, not Rust
execution or a passing acceptance test. Both require paired positive/negative
regressions before acceptance.

## Command outcomes

| Capture | Native build | Exit | Source-content receipt root |
|---|---|---|---|
| `host-check.log` | `30098575685845210` | 0 | `6fd8c67843ed45c8d86c437823125cc65898968637b9d2e31caba864c160851b` |
| `clippy.log` | `30098575685845229` | 0 | `e994bd7d70c53ba2ad63f1bf6f904acb518d26039bc162640d31889c51ca3969` |
| `powerpc-check.log` | `30098575685845242` | 0 | `63f0dfcd69c2a8686cc3cc550f8ad0684caa0f2298889495593765c42b4fe913` |
| `mips-check.log` | `30098575685845253` | 0 | `04c79551b8a3e6efcdec396106ceeb08ddf4fdf9e1cc6de80510b14ece624204` |
| `host-tests-failed.log` | `30098575685845255` | 101 | `1c5c7baaf3df8b8c2baf7d46140187466edb96a6b5bda8d62e24ce71942b63c6` |

All five jobs were strictly remote through `RCH_REQUIRE_REMOTE=1 rch exec`
with `--source-content-receipt`, locked dependencies and one Cargo build job.
The native command was:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- \
  env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo +1.99.0 test --locked -p franken-update --no-fail-fast -j1 -- --nocapture
scripts/e2e/u02 --tier full --judge NATIVE_LOG --receipts RECEIPT_DIR
```

Strict host Clippy used `cargo +1.99.0 clippy --locked -p franken-update
--all-targets --message-format=json -j1 -- -D warnings`. PPC and MIPS used
`cargo +nightly-2026-08-31 check --locked -p franken-update --all-targets
--message-format=json --target TARGET -Z build-std=core,alloc,std,panic_abort -j1`,
with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`.

The JSON build-script observations record actual selected crypto cfgs:
host64-bit/SIMD, both big-endian targets32-bit/serial. They prove compilation
configuration, not executed CPU dispatch, target guest execution or board timing.
All13selected Cargo/update source files match each receipt. Terminal command
statuses, ACK, wrapper death/absence and source/tree/pair retirement were
confirmed. Successful checks also confirmed local staging release; the failed
native run had no `staging_released` field, so that fact is not asserted.

Complete raw logs and full private receipts are retained by the supervisor;
these public logs omit transfer metadata and Cargo artifact JSON and replace
source/target/sysroot prefixes. No failed product assertion is normalized into
a pass. No hardware, vendor acceptance, actual A/B capacity, daemon SSH patch
or external service qualification is established. The current bootstrap has
no SSH daemon; any future image retaining one still needs actual daemon/libc/
effective-authentication guest evidence, including the long-password boundaries.

## Capture hashes

- `host-check.log` raw SHA-256 `8e1e21407981b3f82db0bbe6a17f3bc829651681374ed5abb71a0df4dd289f59`; public SHA-256 `0aa7c15ccef58c924f571bb50552c0c31ae19f16ebb1fc436c3dab7b7d3bb387`.
- `clippy.log` raw SHA-256 `e27569354a6b7098d1a554eea210157f427645bc005e67dbd5b259486a7bbf8a`; public SHA-256 `1402956db29a247a7ab166060f2eb3807bb5a98b5756571246fff3f4c26c1ab6`.
- `powerpc-check.log` raw SHA-256 `a1977a957a0d0c0632bf5522b633e0696272df212ebfe3df1595410c6adb9ab2`; public SHA-256 `5384cf42d423722c8556b3b92ddabdc28bd4b3f813f61978d7437f0912c2c485`.
- `mips-check.log` raw SHA-256 `acc8e12e25a07331453a1c3929da7166d59803c152c37863fa1d767d00b53b89`; public SHA-256 `1843023136be2670e3c8db673ee259082bd94ba07ad9c56d85e4e15d745da888`.
- `host-tests-failed.log` raw SHA-256 `251beb048be02d560572b4d3de423d3df2ff614f91a0299466594e54190d4567`; public SHA-256 `5b077cce200c1f1ebc20befcfb5dc490fa9cff5e206b87585c3cdc63d070af1a`.
