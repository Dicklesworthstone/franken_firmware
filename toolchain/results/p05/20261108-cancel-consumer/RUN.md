# P05 refreshed cancellation-audit consumer

The existing consumer pins Asupersync
`460306de2aa4169510873716018ade44fdb01534`, consuming its runtime changes and exact
upstream audit sources. The seven-file refresh is committed as
`527b687a8300d3159e49971c988323a842134d88`. Subsequent independent strict-remote
compiler and lint runs passed. **The 50 audit tests and 14 native provenance
controls have not executed in this consumer at this pin.** The first native
attempt exited 103 before execution because no worker slot was available.
P05/P03 remain open.

The copied main audit contains 48 tests plus two unchanged helper tests. All 48
previous names remain; the two additions check atomic-ordering type identity
and reject weakened publication orderings. The copied files match immutable
upstream bytes. All 14 existing guard tests remain. The eight-feature selection
is unchanged. Cargo resolved the lock with only five Git references changed;
all 214 package identities, registry versions/checksums and dependency lists
otherwise stayed unchanged.

From the FrankenFirmware root, with the seven-file refresh:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_REQUIRE_REMOTE=1 \
rch exec --source-content-receipt --worker vmi1152480 -- \
  env CARGO_TARGET_DIR=/tmp/rch-target-ffw-audit-current \
  cargo +nightly-2026-08-31 check --locked \
  --manifest-path toolchain/asupersync-cancel-audit/Cargo.toml \
  --tests --keep-going -j1
```

The strict lint run uses the same prefix and manifest, replacing `check` with
`clippy` and selecting `--lib --tests --keep-going -j1 -- -D warnings`.
Locked Cargo metadata inventories exactly one library, two registered tests and
a build script; automatic bins/examples/benches/tests are disabled. Every
declared library/test target is selected.

| Check | Build | Actual result | Remote command time |
| --- | --- | --- | --- |
| Test-target compiler check | `30099060530610881` | Exit 0 | 298.514 s |
| Library and both test targets, strict Clippy | `30099060530610893` | Exit 0, no diagnostics | 6.703 s |
| Native audit and guard execution | Not admitted | 0 tests; exit 103 | Not run |

[compile.txt](compile.txt) preserves selected terminal output and both full
private capture digests. All **1,389/1,389** captured source files matched bytes,
sizes and executable modes after each successful run and before publication
edits. Both wrappers had terminal acknowledgment, terminated processes, absent
owners and all five source/output retirement checks. The Git dependency is
subject to the existing build-time checkout/pin checks; native mutation controls
remain unexecuted. [code-inputs.sha256](code-inputs.sha256) retains eleven
compiler, audit and guard witnesses. Publication changes affect this evidence
and the consumer README, not those inputs.

Compiler content root:
`92122984ec5e2009b5b9237e2b7f899dbfe39a670384fd7401aa5087c14afb56`;
receipt root:
`d158ffd064168142f6a6c16c69524a1f9160f9955cb4ec9a5fce84b4fedc7d98`.
Lint content root:
`27e941541d4cc9c347ddd1f5aa2209209192bbdd99f2d2286c99814008138b23`;
receipt root:
`9ff252ba2cc9f75d43dc866a14aa325814f035c174eecc8a28f52d8b74f3a00b`.

Static and lock guards, Python compilation and wrapper formatting passed. The
immutable copied audit retains one identical formatter hunk from the preceding
pin; its file-format check fails on that inherited hunk. Exact upstream bytes
were preserved. The comparison used explicit preceding commit `e27bad4`, with
both outputs retained; stdin formatter exit 0 was not a file-format pass.

Older `14032b8` compile/lint evidence and separate original-lane execution remain
historical results with their own source identities. Neither supplies missing
native execution here. This updates a verification consumer; it does not install
an Asupersync runtime in the speaker executable or qualify hardware/providers.
