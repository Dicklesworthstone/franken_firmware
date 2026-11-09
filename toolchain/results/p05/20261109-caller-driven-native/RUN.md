# P05 caller-driven runtime probe: native verification

This archive retains native GNU/Linux execution of the 45-test runtime probe at Asupersync `91509bcd8`, including its original failure and corrected rerun. It does not qualify a speaker, the legacy kernels, a minimal dependency graph, resource fit or the complete P05/P03 acceptance.

## Reproduce the actual commands

Run from the repository root with an eligible Linux worker and unchanged source. Central execution used strict remote RCH and the following direct Cargo commands (the usual worker-scoped target/source paths are rewritten by RCH):

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo +nightly-2026-08-31 test --manifest-path toolchain/src/p05-runtime/Cargo.toml --locked -j 1 -- --test-threads=1 --nocapture
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo +nightly-2026-08-31 clippy --manifest-path toolchain/src/p05-runtime/Cargo.toml --locked -j 1 --all-targets -- -D warnings
```

| Actual native job | Result | Source |
|---|---|---|
| 30101959465763451 | 44 passed, 1 failed, 0 ignored/filtered, exit101 | `99b1dde`; original test retains stale source-address assertions |
| 30101959465763468 | 45 passed, 0 failed/ignored/filtered, exit0 | Main SHA `0eb93f643165b25f1606e21e4f7bcafe87477eada2722850b1ea26cd13eeca9b`, published as `97e3584` |
| 30101959465763467 | strict all-target Clippy exit0 | Same corrected source |

The failing test, `the_caller_driven_mode_is_unsupported_unknown_or_failed_and_never_ok`, still expected the previous pin's source-address strings after the implementation intentionally introduced a separate caller-driven profile. The one-site repair checks the complete new declaration literally, including reason, `reason_source=profile_split`, constructor evidence and observed=false. Every unsupported/failed/unknown/never-pass assertion and the test name remains. Independent source review confirmed the actual constructor forbids a blocking pool while the single-owner profile retains one. No production runtime behavior or test registry was changed by the repair. The original 44/1 failure is retained, not replaced.

## Attribution and custody

The corrected reconciler from `4d6256f` judges the actual successful log COMPLETE45/45 and rejects the actual failed log. `reconcile.txt` retains both observed results and commands. The successful log has **nine** results credited by libtest closure because printing interrupted their rows. That is the actual observed count, distinct from the synthetic regression builder's five. Explicit Cargo binary headers are validated independently; closure is not permission to accept a foreign test binary. These are not 45 separately uninterrupted `test ... ok` lines.

All three jobs have strict-remote terminal records with the actual command exit, ACK, and released source/tree/pair custody. The two successful jobs also released retrieval staging. The failed command has no staging-release field; it is retained as null rather than manufactured true.

`receipt-summary.json` is a derived selection from actual native leases and full source-content receipts, with six relevant source files bound to the corresponding immutable source reference. It retains receipt identities, roots and command digests plus raw/public log digests. The single large full receipt line in each log is omitted with exact byte count and digest retained. All other lines are kept with ANSI removed and personal paths/addresses redacted. No root repository or source file was rewritten to conceal a failed run.

The full P05 Python suite passed74/74 after the separate attribution correction; the unchanged runtime-measurement suite passed107/107. Neither is a replacement for these actual native tests. Formatting of the one-site Rust correction passed before the remote test and Clippy runs.

## Remaining qualification

The test binary executes the actual caller-driven runtime profile and its phases in a native test process. This is not a standalone `/init` execution or a BE guest boot; a standalone run and both target guests remain separate. Full dependency/module feature reduction is still pending: `runtime-core` and `native-runtime` are marker features at the pinned revision. Thread/job admission does not establish a total process memory ceiling. No 32MiB-fit, target CPU/deadline, retained-driver, physical-output, Spotify, AirPlay, Alexa or native-tailnet qualification is claimed. P05/P03 remain open against their original acceptance. No hardware or provider was touched.
