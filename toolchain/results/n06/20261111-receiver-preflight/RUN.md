# Local receiver resource preflight: native host evidence

`MediaPlayout` now prepares actual allocated FEC receiver storage without
selecting it. The existing `enable_host_fec` API delegates to prepare/commit.
`MediaEndpoint` wraps that reservation with actual carrier identity, progress
and in-memory queue checks. This adds a local resource-admission seam, not an
authenticated remote-readiness protocol or a distributed cutover.

One outstanding preparation owns its receiver and shares an atomic charge
with its media owner. The footprint includes the reservation bookkeeping,
caller-held preparation and endpoint wrapper. Abort/drop frees the receiver
before releasing its charge. A retained empty receiver allocation transfers
into preparation, so immediate reselection still fits its original exact
budget. Stream/epoch/origin, progress, changed budget, restart/ABA and
cross-owner checks run again before commit. Non-wrapping context generations
refuse new preparation at exhaustion. Refusal leaves current selection and
N01 samples, replay state and credit intact.

## Executed gates

Run from the repository root on a provisioned RCH worker with pinned Rust
1.99.0 and the locked offline dependency set. No local Cargo or fallback was
used. The actual remote command bodies were:

```sh
# Native build 30103800983323342
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 test -p franken-stream -p franken-speaker --lib \
  --locked --offline -j1 --no-fail-fast -- --show-output

# Native build 30103800983323346
RCH_REQUIRE_REMOTE=1 rch exec --source-content-receipt -- env \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  'RUSTFLAGS=-D warnings -C debuginfo=0' \
  cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 \
  --keep-going -- -D warnings

# Formatting and Python adapter controls (no compilation)
rustfmt +1.99.0 --edition 2024 --check --config skip_children=true \
  crates/franken-speaker/src/media_playout.rs \
  crates/franken-speaker/src/net_carrier.rs crates/franken-stream/src/lib.rs
python3 tests/n06/test_judge.py
python3 -m py_compile tests/n06/run_cases.py tests/n06/test_judge.py
```

| Gate | Passed | Failed | Ignored | Filtered | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full speaker library | 460 | 0 | 0 | 0 | 0 |
| Full stream library | 206 | 0 | 0 | 0 | 0 |
| Strict all-target workspace Clippy | Not a test run | — | — | — | 0 |
| N06 Python parser/registry controls | 9 | 0 | 0 | 0 | 0 |

All eight new Rust test names occur exactly once as actual `ok` rows.
Positive cases recover missing authenticated PCM through the real media path
and through localhost UDP. Paired negative cases cover capacity/binding,
abort, progress, same-timeline restart, epoch change, ABA, wrong owner,
changed budget and generation exhaustion. The exact-budget reselection test
recovers PCM after reusing and after abandoning retained storage. Assertions
require `Outcome::Real` and exact bytes; muted output cannot pass them.

The supervisor independently matched all 1,563 captured files to the checkout
for both native gates before adding publication evidence and the Python-only
registry update. `source-inputs.json` records the tested source hashes,
receipt roots, capture hashes and the separately checked Python hashes.
Both native command/wrapper exits are zero, terminal acknowledgments were
recorded, and source/tree/pair/staging/lease custody was released before
publication. Full raw RCH captures remain private because they include
infrastructure addresses. `observed.txt` is an explicitly selected excerpt.

The existing N06 end-to-end source registry initially had no consumers for
the eight new test functions. The additive adapter fix now requires all
82 names (the original 74 plus eight), retains the 13 full cases and both
qualification blockers, and passes its nine Python controls. Those controls
are parser evidence, not substitute native receipts. Independent source
review verified the exact names and unchanged observations/failure handling.

## Earlier failure retained

Native build 30103800983323339 exited 101: speaker 458 passed and two failed;
stream 206 passed. The failures were the baseline N01 audio checks in
`n06_preflight_capacity_binding_and_abort_preserve_real_n01_audio` and
`n06_preflight_progress_epoch_and_cross_owner_invalidate_without_effect`.
The shared test scheduling helper unconditionally applied N06's 500 us
uncertainty floor to N01, requesting a decision before N01's actual cutoff
and receiving `Pending`.

The repair applies that floor only when FEC is selected and explicitly
asserts convergence to the selected path's actual `consume_by`. Both original
real-audio, exact PCM, replay and state assertions remain. Replacing only the
helper in memory with its original HEAD version independently reproduces the
entire prior frozen media-file hash
`67db45ff60ab2f96ebbc1f3eb656b9e335caa9b6fb998d861e44d35404011464`.
No production or other test bytes changed in this repair. The failed capture
hash is `4672125eff2a97317c876974096261525885c4fe54bf5b2fc04e12234f39d1b7`.

## Qualification boundary

This is local native Linux host evidence with scripted kernel clocks,
synthetic keys/ledgers and actual localhost sockets. It does not qualify a
board, old kernel, QEMU guest, memory/WCET envelope, service provider or DAC.
Any media progress invalidates the preparation; this is not proof that a
live playing group can hold readiness across a remote network round.

Endpoint preparation checks the in-memory carrier queue; it cannot inspect
unread datagrams retained by the port. It is not an ingress fence. There is
no authenticated readiness ACK, remote clock/start preflight or coordinated
group activation here. Those original N06 acceptance conditions remain open.
Shared `Arc` construction uses Rust's ordinary infallible API and can abort
on allocator failure; typed fallible receiver reservation and numeric capacity
refusal are different. No actual allocator-abort branch was executed or
qualified. If the media owner is dropped while its preparation survives, the
caller still owns and must account for those surviving resources. N06 stays
open; no physical or native-tailnet/provider claim is made.
