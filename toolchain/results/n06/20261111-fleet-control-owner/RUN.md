# Durable fleet-control consumer: native host evidence

The explicit `FleetControlOwner` now composes N02 peer custody and command
floors, G03 SOAP dispatch and N06 authenticated agreement with one journal.
The actual loopback HTTP worker accepts a caller-provided owner and refuses a
failed factory rather than silently selecting the legacy implementation.
The 33-identity **host-development** profile is explicit; standard limits and
the existing 21-member media ceiling remain unchanged.

This is bounded native Linux host evidence. It does **not** qualify Sonos
hardware, retained drivers, QEMU guests, 32 MiB fit, native service providers,
receiver preflight or distributed media cutover. N02 and N06 remain open.

## Commands and results

Run from the repository root with the pinned Rust 1.99.0 toolchain and locked,
offline dependencies on a provisioned RCH worker. Every compilation used
`RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt`. The worker and target
pool are infrastructure configuration; no local fallback was used.

The executed command bodies were:

```sh
# Control library: build 30103800983323291
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test -p franken-control --lib --locked --offline -j1 \
  --no-fail-fast -- --show-output

# Whole workspace, all targets: build 30103800983323292
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test --workspace --all-targets --locked --offline -j1 \
  --no-fail-fast -- --show-output

# Journal package, including its actual process tests: build 30103800983323300
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test -p franken-journal --locked --offline -j1 \
  --no-fail-fast -- --show-output

# Strict all-target workspace Clippy: build 30103800983323303
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 \
  --keep-going -- -D warnings
```

| Gate | Passed | Failed | Ignored | Filtered | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Control library | 633 | 0 | 0 | 0 | 0 |
| Whole workspace, 59 libtest summaries | 2,633 | 0 | 2 | 0 | 0 |
| Journal package, five summaries | 38 | 0 | 0 | 0 | 0 |
| Strict workspace Clippy | Not a test run | — | — | — | 0 |

The counts overlap: do not sum the three test gates. Eight workspace targets
have zero tests; they contribute no passes. The two ignored cases were not
executed. The workspace run includes nine actual U01 process tests, all seven
N07 carrier scenarios, nine new owner tests and both new localhost HTTP
consumer tests. The journal package independently executes its nine process
cases. `observed.txt` contains selected actual test rows and every result
footer; it is an excerpt, not a full capture. Full private captures remain
with the operator because RCH output contains infrastructure addresses.

The all-target workspace run reused the same remote target pool in which the
normal `journal_crash` executable had been built. On a clean worker, first
build that normal example with the same RCH worker, toolchain, environment
and target-pool policy:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 build -p franken-journal --example journal_crash --locked --offline -j1
```

`cargo test --all-targets` alone produces an example *test harness*, which is
not a substitute for the executable the process tests launch. The earlier
example-build command returned zero remotely but its artifact-sync wrapper
refused a foreign Linux artifact; that wrapper failure remains recorded.
The later actual process tests, not that incomplete wrapper, establish the
host process results here. No artifact-admission check was disabled.

## Exact sources and additional checks

`source-inputs.json` records all 28 selected source hashes, each gate's
source-content receipt root and the original capture hashes. The independent
supervisor matched all 1,560 captured files to the checkout before creating
these evidence files; all 28 selected inputs matched each of the four gates.
Each gate's wrapper and command exited zero, terminal acknowledgment was
recorded and source/tree/pair/lease custody was released before publication.

Direct `rustfmt +1.99.0 --edition 2024 --check --config skip_children=true`
passed on the 16 changed or new Rust files. The five changed Python files
passed `python3 -m py_compile`. N06 Python parser controls passed 8/8 and N07
Python controls passed 33/33; these are parser/model checks, not native or
hardware substitutes. The N06 native registry retains its original 65 names
and adds nine required owner tests (74 total); the original 13 suite cases
and both pending qualification blockers remain unchanged.

The N07 repair adds explicit idle FEC fields only on the expected side for
original N01 worlds. Actual observations and strict comparison remain intact;
missing, nonzero, wrong-type and unknown fields still fail. Original vectors
were not regenerated.

## Failures and limits retained

- Earlier full-workspace build 30103800983323165 had 2,600 passes, 15 failures
  and two ignored cases: seven N07 expected-schema mismatches and eight
  journal process setup failures. These failures were corrected and rerun,
  not hidden by skipping cases.
- Build 30103800983323249 failed Clippy on a match expression. The equivalent
  `matches!` form was fixed before the current strict pass.
- A source-handoff race caused builds 30103800983323253/23254 to lose source
  eligibility; neither is credited. The author edited before the verifier's
  explicit hold acknowledgment. Same-ID recovery settled both attempts.
- Build 30103800983323283 failed compilation on a private durability latch;
  no tests ran. The single visibility change to `pub(super)` preserves its
  body and allows the sibling owner to use the existing failure latch.
- Build 30103800983323288 ran 632 passes and one failed test: its intended
  positive request omitted the required observed revision. The current test
  retains that request as an explicit negative and asserts the valid request
  is queued before checking its committed effect. A storage-failure test was
  also strengthened with a valid lease and revision so an unrelated refusal
  cannot falsely satisfy its expected failure.

First claim atomically persists the profile and both required marks. An
interruption after empty-journal formatting but before that first claim can
leave counterless nonblank media: boot deliberately refuses it and requires
explicit provisioning. Automatic recovery at every first-boot cut is not
claimed. Loopback restart tests use supplied RAM-backed journal images and
fresh key stores; they are not physical power-cut, key sealing, process-kill
or native-tailnet evidence. Existing U01 process tests are a separate proof.
