# P01 safe host-only studies and diagnostic accounting

Baseline: `90606cc`. The workspace contract now permits an excluded host-only study with no device targets to declare its own manifest/source `forbid(unsafe_code)`. Device-target startup probes retain `bootstrap_probe`. Unknown or scoped-unsafe policies remain refused. The source scanner is a conservative textual check; rustc remains the safety-policy enforcer.

Central strict-remote RCH results: 26 library tests, four integration tests replaying all 143 vectors, 18 speaker service-contract tests, and strict all-target Clippy passed. All 1,253 synced inputs matched each capture before the Python-only logging followup; terminal ACK, absent wrapper/owner, and all five release flags were verified. `qualification.json` records commands, content roots and the unchanged Rust/vector input hashes. No BE guest or physical/provider behavior is admitted by these host tests.

Final Python tests: 230 passed with warnings treated as errors. Logging tests independently map fail/blocked/pass exits, retain an explicit zero-failed-case health check, and plant missing begin/end events: case verdicts stay unchanged while evidence becomes incomplete and qualification fails. Rustfmt, py_compile and diff checks passed. The full host tier remains NOT QUALIFIED: 253 passed, zero failed, eight blocked, 523 critical events, zero lost. No blocked requirement was waived.

The initial native request on the smaller worker was refused before execution for disk headroom; it is not a test result. Native execution then succeeded on the admitted worker without reducing any guard. Source-only Python logging changes followed the Rust captures and were tested separately; no subsequent Rust/vector change occurred.

Consumers: P01 Rust vector replay, the speaker service-contract reader, and the full host-tier judge. These receipts qualify this bounded contract change, not firmware deployment. Replace their claims only with a newer exact-source qualification; preserve these historical results.
