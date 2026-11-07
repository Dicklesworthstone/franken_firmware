# N02 regular-file and process boundary

Component source: `83fad9e`; the subsequent test-only symlink correction is `bc1253c`.
`qualification.json` binds the twelve owned inputs, actual remote content roots, raw-log
hashes and terminal custody observations. Public logs are explicitly selected subsets of
the observed output, rather than full private RCH captures.

The full native batch reported **980 passed, zero failed, one ignored** across nineteen
result groups. This includes sixteen file-medium tests, eight real-process tests and the
separate same-step safety regression. The ignored case is
`d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap`; it was not run. A final focused
run of the corrected valid-symlink test passed **one**, with 341 unrelated cases filtered
out. This is a rerun of one case, not 981 distinct tests.

Strict all-target Clippy passed with and without the harness feature. Both big-endian
PowerPC and MIPS library checks passed. The final fixture correction also passed strict
all-target harness Clippy. Each successful source capture matched all 1,326 files when
reviewed, reached terminal acknowledgment, had no live wrapper or owner, and released
source, tree, pair and staging custody. The only source difference between the five
component gates and the final two gates is the included `cfg(test)` symlink correction.
The BE results are compilation, not guest execution or hardware qualification.

The commands below were run through strict remote RCH. The common native/Clippy environment
was `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`; BE checks
used the first two settings. Later focused jobs declared `RCH_BUILD_SLOTS=1`. No global
fallback, disk floor or build budget was changed.

```sh
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker hz2 -- cargo +nightly-2026-08-31 test --locked --no-fail-fast -j1 -p franken-control -p franken-speaker -p franken-alloc-probe --features franken-speaker/harness -- --show-output --test-threads=1
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- cargo +nightly-2026-08-31 clippy --locked --all-targets -j1 -p franken-control -p franken-speaker -p franken-alloc-probe --features franken-speaker/harness -- -D warnings
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker hz2 -- cargo +nightly-2026-08-31 clippy --locked --offline --all-targets -j1 -p franken-control -p franken-speaker -- -D warnings
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-control -p franken-speaker --features franken-speaker/harness --lib --target powerpc-unknown-linux-musl -Z build-std=std,panic_abort
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ovh-b -- cargo +nightly-2026-08-31 check --locked --offline -j1 -p franken-control -p franken-speaker --features franken-speaker/harness --lib --target mips-unknown-linux-musl -Z build-std=std,panic_abort
RCH_QUEUE_WHEN_BUSY=0 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker trj -- cargo +nightly-2026-08-31 test --locked -j1 -p franken-speaker --features harness --lib what_is_not_a_regular_file_with_one_link_is_refused_and_untouched -- --show-output --test-threads=1
RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt --worker ts1 -- cargo +nightly-2026-08-31 clippy --locked --offline --all-targets -j1 -p franken-speaker --features harness -- -D warnings
```

The existing Python checks passed: N02 72, G03 85 and Q01 99. Independent nonauthor source
review was provided by GrayMeadow (AM11253 and the focused correction review), with owner
review by IvoryFalcon and DarkPeak. Source review did not stand in for these runtime runs.

The prototype now runs the actual control owner over a locked, bounded, versioned regular
file. A new process restores its revision mark and relative-command floors, refuses a
delivered relative change, and accepts the next command. The identical request on a fresh
file is a permitted positive control. Other cases exercise lock release after kill, named
file refusals, first program/sync failures, live local mute with unsafe commands withheld,
bounded output, owner-drop cleanup and the 64-command boundary. The permission-denial
negative actually executed on the unprivileged full-run worker; no not-run marker appeared.

`history.json` preserves the initial failed setup, the temporary dangling-symlink defect and
the infrastructure refusals. Shortening the socket fixture kept its refusal assertions but
accidentally made the link target relative to the link's directory. The correction supplies
an absolute existing target and proves `read(link) == image` before asserting refusal and
unchanged target bytes.

This remains an offline harness prototype. The G01 session revision and volume are supplied
fixture state; the file restores the durable mark and floors, not a live session. A process
kill retains bytes already handed to the OS and is not a power-cut or `sync_all` proof.
Injected file-operation failures are not kernel disk-full or real flash failures. No device,
provider, physical output or complete N02 qualification is claimed. N02 stays open, including
its P03 dependency and remaining original acceptance requirements.
