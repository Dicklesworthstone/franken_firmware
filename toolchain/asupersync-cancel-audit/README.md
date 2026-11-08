# asupersync-cancel-audit

Runs asupersync's **original** `tests/runtime_abort_vs_cancel_semantics_audit.rs` (and its `stream_cancellation` helper), byte for
byte, against asupersync `460306de2aa4169510873716018ade44fdb01534` built as a **normal Git dependency**. The original lane
(`cargo test -p asupersync --test runtime_abort_vs_cancel_semantics_audit`) also compiles asupersync's ~300 dev-dependencies
(sqlx-mysql, criterion, tokio, redis, ...) and hit the 2 h external deadline before running a test. This lane builds only asupersync
plus the optional dependencies its own features pull in.

It repairs the build fan-out of that one lane. It does **not** replace the broad all-target, lint, big-endian or resource gates,
qualifies no board or provider, and says nothing about the health of the workspace. The broad lane stays as it is.

## What is the same as the original lane

| | original lane | here | how it is held |
|---|---|---|---|
| audit source | `tests/runtime_abort_vs_cancel_semantics_audit.rs` + `.../stream_cancellation.rs` | the same bytes | sha256 in `provenance/expected.json`, checked by `build.rs`, `audit_check.py static` and `provenance_guard` |
| tests run | 48 + 2 (helper module) = **50** | the same 50 | `audit_check.py run` needs every one of the 50 (and the guard's own) `ok` in its own binary, via D01's cargo-log parser (header/section pairing, whichever order RCH delivers stdout and stderr), plus a clean terminal state and the caller's exit status |
| asupersync features | `default` plus what dev-dependency `asupersync-conformance` asks (`metrics`, `test-internals`, `tracing-integration`, `fuzz`), closed over `[features]` = 8 features | the same 8, `default-features = false` | derived from the pinned manifests by `audit_check.py derive`; compared by `static`, `build.rs`, `provenance_guard` |
| asupersync source | the checkout | Cargo's immutable git checkout of the same rev | `build.rs` asks read-only `git`: the directory has Git metadata of its own, `HEAD` is exactly the pinned commit, and `git status` over `src`, `tests`, the manifests and the lock shows nothing modified, untracked or ignored (a stray `.rs` is read by the census); `Cargo.lock` must pin `asupersync` to the same commit. No override; no file digests |
| profile / rustflags / toolchain | dev profile; `RUSTFLAGS='-D warnings -C debuginfo=0'`, `CARGO_PROFILE_TEST_DEBUG=0`; `nightly-2026-08-31` | pass the same; `rust-toolchain.toml` is the pinned file | the pin has no `[patch]`, no `[replace]`, no dev/test profile overrides |

The feature set was taken from the pinned manifests, and cross-checked against the crates the original run actually compiled
(`arbitrary`, `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-proto`, `regex`, `tracing*`, `visibility`).

## The one interposition

The audit's structural pins read `env!("CARGO_MANIFEST_DIR")/src/**` (and `tests/*`), and one census walks all of `src`. Inside
asupersync that is the asupersync root; here it would name this harness. `tests/cancel_audit.rs` defines a `macro_rules! env` that
answers only `CARGO_MANIFEST_DIR` with `ASUP_ROOT`; these immutable audit files make no other environment query.
A new unsupported query fails compilation. `build.rs` sets `ASUP_ROOT` only after
`provenance/verify.rs` proves the directory is the pinned commit, clean. A wrong or missing tree fails the build; it cannot pass a pin.
Consequence: libtest names are `audit::<name>` and `audit::stream_cancellation::<name>`.

## Run (central)

Pin history, kept apart. The previous pin `14032b8` contained 46 + 2 = 48 tests (audit sha256 `5f13a1ba...`); its focused all-target
compile and strict all-target Clippy passed remotely on 2026-11-07 after correcting an unused macro arm and a test-helper type alias.
Those native harness tests did not run. The compile/Clippy result qualifies only that pin. Among the copied audit and pinned
manifest/lock/toolchain inputs, the current pin `460306d` changes only the main audit file (sha256 `83c62045...`, two added tests, `crate_atomic_ordering_is_the_core_ordering_the_publication_pins_name` and
`stable_publication_pins_reject_relaxed_orderings`, one more file read, `src/sync/atomic.rs`); the helper, the root manifest, the lock,
the conformance manifest and the toolchain file are byte-identical, so the 8-feature set is unchanged (derived again, not assumed). The upstream runtime implementation also changes and requires
new qualification.
Cargo has re-resolved the consumer lock to the current pin: only the five Asupersync-family Git source identities changed;
all registry versions, checksums and dependency lists stayed the same. The 50 original tests and 14 provenance controls have
**not run** in this harness at the current pin. A copied audit file retains one formatting hunk from upstream; preserving its
exact bytes is part of the provenance contract. No compile or cancellation result is claimed for this refreshed consumer yet,
and the broader P05 bead remains open.

```
python3 scripts/audit_check.py static
cargo fetch                                   # first resolution writes Cargo.lock; commit it
python3 scripts/audit_check.py lock --asup-lock <CARGO_HOME>/git/checkouts/asupersync-*/460306d/Cargo.lock   # prints `cargo update -p X --precise V` for drift
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo +nightly-2026-08-31 test --locked -j1 -- --nocapture > audit.log 2>&1; status=$?
python3 scripts/audit_check.py run audit.log --exit-status "$status"      # --repo FRANKEN_FIRMWARE if this is not toolchain/asupersync-cancel-audit
```

## Where equivalence is weaker than "identical" (read before calling it equivalent)

1. **Locked versions.** The original uses asupersync's committed `Cargo.lock`; a fresh resolution here can pick newer third-party
   versions. `audit_check.py lock` finds every package that differs and prints the exact `cargo update --precise` to align it.
2. **Third-party feature unification.** The original unifies features across ~300 dev-dependencies; here fewer crates exist.
   asupersync's own feature set is identical; the feature sets of third-party crates may differ. The audit uses only
   asupersync, std and `serde_json::json!` (diagnostic `eprintln!`, never asserted).
3. **Lint gate on asupersync itself.** A dependency is compiled with `--cap-lints allow`, so `-D warnings` no longer gates
   asupersync's own code here (the broad clippy lane still does). It still gates the audit and this harness.
4. **Test names** carry the `audit::` prefix (above).
5. **Compile observations, still awaiting native execution:** `macro_rules! env` shadows the built-in `env!` for the audit module; Cargo's git
   checkout lives at `$CARGO_HOME/git/checkouts/asupersync-*/<rev prefix>`, keeps its `.git`, and `git` can read it (git refuses
   a directory owned by another user; the build then fails with git's words rather than skipping the check). If any is wrong
   the build or the guard fails; none can produce a pass.
6. **The judge needs the caller's exit status and RCH's own custody line.** A log alone cannot show that the command succeeded.
