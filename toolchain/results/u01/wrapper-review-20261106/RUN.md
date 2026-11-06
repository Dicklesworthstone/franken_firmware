# Bounded U01 evidence runner

The runner preserves its crash/recovery oracles while giving owned child
processes absolute deadlines, bounded stdout and stderr, and process-group
cleanup. Noise cannot extend an acknowledgement deadline. Output overflow
fails instead of becoming truncated positive evidence. The unit battery runs
in a bounded child, failures retain their first cause, and errors omit private
paths and redact credentials before human or structured output.

The final source passed 53 Python tests: 40 focused runner regressions and 13
original journal-model tests. Actual smoke passed 2/2 with complete shared Q00
diagnostics. Full without a local Rust binary correctly exited3 with four
blocked process cases; soak exited4 as NOT RUN. The original JSON and JSONL
artifacts are retained byte-for-byte. Commands:

```sh
python3 -B -W error -m unittest discover -s tests/u01 -p 'test*.py'
scripts/e2e/u01 --tier smoke --receipts OUTPUT_DIR
scripts/e2e/u01 --tier full --receipts OUTPUT_DIR
scripts/e2e/u01 --tier soak
```

The alternate central Rust process form is independently retained: 37 named
tests pass, including real abrupt process deaths, acknowledged-step SIGKILL,
recovery and 16 hostile images. Its unchanged 13 journal/toolchain files, all
24 locked package records, workspace package/lints/profiles and relevant
dependency pins match the retained source. Both original native commands are
finished and acknowledged, wrappers dead, owners absent and custody retired.
The receipt records precise identities as decimal strings and source/log hashes.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test --locked --offline --no-fail-fast -p franken-journal -j 1 -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy --locked --offline -p franken-journal --all-targets -j 1 -- -D warnings
python3 tests/u01/judge_log.py CAPTURED_RUST_LOG --root .
```

The central sampled-byte cases use strides1/1/29/1/3 across five scripts;
E003/E004/E005 correspond to S002/S001/S003, and E006 to the acknowledged-step
SIGKILL case. Exhaustive model cut points are separate from sampled real
process deaths. A Python stand-in exercises only this runner and is not Rust
proof. No flash, physical device or hardware power-cut qualification is claimed.

Text logs sanitize paths, addresses and worker identities; raw and public hashes
are separate. Missing local process evidence remains blocked rather than being
silently relabeled as a local pass; the central evidence is its explicit
alternative under the original U01 contract.
