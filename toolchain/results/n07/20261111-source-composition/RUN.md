# Host qualification: real finite source and protected group transport

The normal speaker library now composes the real finite-reader decoder and
rate bridge with authenticated N01 delivery and N04 playout. Preparation can
block and stays outside protected rendering. Publication requires a newly
supplied trusted observation, preserves exclusive source custody and lets
healthy members progress independently. All-peer admission remains explicit.
The runtime owner supplies canonical policy/session views and serializes
mutation; this component does not independently revoke fabricated clones.

## Actual gates

All Rust compilation ran strictly remotely, on Rust 1.99, with locked/offline
dependencies, one Cargo job and source-content receipts. Worker and retained
log paths are parameters, not committed site data.

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker "$FFW_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-stream -p franken-speaker --locked --offline -j1 --no-fail-fast -- --show-output
RCH_REQUIRE_REMOTE=1 rch exec --worker "$FFW_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 clippy --workspace --all-targets --locked --offline -j1 -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec --worker "$FFW_WORKER" --source-content-receipt -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 'RUSTFLAGS=-D warnings -C debuginfo=0' cargo +1.99.0 test -p franken-board-profile --test p01_contract --locked --offline -j1 -- --show-output
python3 -B tests/n07/run_cases.py --judge "$FFW_ACTUAL_LOG" --revision "$FFW_SOURCE_ID" --receipts "$FFW_PRIVATE_RECEIPTS"
python3 -B tests/s02/run_cases.py --tier full --judge "$S02_CODEC_LOG" "$S02_HEAP_LOG" --receipts "$S02_PRIVATE_RECEIPTS"
```

| Gate | Native job | Observed result |
|---|---|---|
| Complete stream and speaker packages | `30104858719683211` | 801 passed, zero failed, one existing ignored soak, zero filtered; 14 target/doctest footers |
| Strict workspace/all-target Clippy | `30104858719683223` | Exit 0 with `-D warnings` |
| Affected P01 contract integration target | `30104858719683224` | Four passed, zero failed/ignored/filtered; shared corpus retains all 143 vectors |

The native libraries execute 496 speaker and 256 stream tests. Other targets
add 49 passes: CLI 16, protection history six, closed-loop six, N01 loopback
one, wire replay seven, actual loopback carrier ten and ownership three.
The existing closed-loop soak remains ignored. Zero-test main/bin/doc targets
earn zero credit. The separate four-test P01 leaf qualifies the actual Rust
consumer of the changed dependency declaration and vector identities; it is
not another 143 outer native tests.

The supervisor independently matched every selected path, SHA-256, length
and executable flag in all three successful receipts: 1,563 selected inputs
from a 1,565-file export. Only two Beads configuration paths are excluded.
Every job has actual execution/return zero, terminal acknowledgement, absent
wrapper and released/retired source, staging, tree and pair custody. Private
directories remain preserved; custody retirement does not assert deletion.

The export is baseline `8478fbd242756f84b74a0a1d880b623c5683c332` plus
19 exact overlays, inventory SHA-256
`0dbd12a53b39db19f47d7fefd4babc598731dcd9ceed73e623997616f748dcd4`.
Input files are read-only; the publication root is writable. The supervisor
also verified the Git baseline and each successive source difference. Public
proof and the later S02 contract append are noncompiler follow-ons, separately
bound rather than relabeled as native-export inputs.

## Consumer and sample evidence

The unmodified final native capture passes all **25 N07 cases and seven
source META checks**. Its worlds include real loopback datagrams; other
source/renderer tests use explicit host ports and the real codec, authentication
and N04 implementations. Full 44.1 kHz output, including the single bridge
tail, is compared to an independent closed-form PCM reference. A real small
receiver window requires authenticated consumption reports before source
advancement. These are host observations, not physical speaker outputs.

Canonical Python controls pass **59 D01 and 44 N07 tests**. S02 runs 69:
**68 pass and one optional libvorbis cross-check is skipped**. All assertions
are unchanged by the test executor; temporary directories are retained.
S02's actual-log pipeline passes **71/71 cases with 143 complete critical
events**, zero dropped or lost. Synthetic judge controls, native tests and
evidence-pipeline cases are separate denominators.

S02 uses the earlier qualified codec and Vec-heap captures as component
evidence. Decoder algorithms/vectors/tolerances remain unchanged; the codec
source difference is three documentation corrections, and package versions
and checksums are unchanged. The heap result is not a new File-reader/RSS
measurement; its three first-use retained deltas remain unexplained. Exact
prior scopes are in the [finite-reader qualification](../../s02/20261111-finite-reader/RUN.md).

## Failures retained and corrected

1. First coherent native `30104858719683183` failed: 798 passed, three
   failed, one ignored. The ABA test had never prepared the pending frame it
   asserted survived; the full-track test requested more source before
   applying real receiver credit; and a cooldown test's nominal third send
   never reached transport because the pacer was empty. Corrections establish
   those actual preconditions, retain the assertions and independent PCM
   oracle, and exercise the reported retry deadline without increasing limits.
2. Corrected native `30104858719683194` passed 801 with one ignored, against
   its own earlier source. Strict Clippy `30104858719683197` then failed on
   a 544-byte result enum. A superseded documentation-only replay,
   `30104858719683203`, reproduced the known failure; that unnecessary run
   remains in the history. The final API writes the full fixed 64-peer report
   into caller-owned storage and returns a small status, preserving reporting
   and error semantics without hot-path boxing or a lint allowance.
3. The earlier N07 consumer rejected all 25 cases in the otherwise passing
   83194 capture: a legitimate zero-test `main.rs` header shared the library
   binary stem and globally invalidated attribution. The correction retains
   every header in counted ordinal pairing and checks exact target labels
   per section. `main.rs` cannot confer library provenance; malformed headers,
   wrong targets, duplicates and incomplete counts still fail. The original
   failed receipt remains preserved. A first incomplete-support-tree control
   failure is also retained separately from its corrected complete-tree run.

All original test names, 25 N07 cases, per-peer outcomes and requested
features remain. Required radio, source-service and platform acceptance was
not moved into follow-ups to claim completion. S02/N07 remain open.

## Qualification boundary

This is a tested library composition, with normal dependency wiring.
Runtime-owner, PID1/daemon, native Spotify/AirPlay/Tailscale/Alexa, legacy
kernel and physical output qualification remain separate obligations.
Blocking setup may read, seek and allocate before source selection. The
small result and reusable report do not establish measured stack/RSS, total
decoder allocation bounds, old-CPU deadlines or 32 MiB board fit. No device
was contacted, no provider session enrolled and no firmware installed.
