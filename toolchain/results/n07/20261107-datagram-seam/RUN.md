# N07/P02: datagram policy and BE syscall routing

This record covers the additive eight-file datagram ABI component. It does
not qualify the broader carrier, a device, or a BE guest's socket I/O.

The safe API sends a complete datagram to a typed IPv4/IPv6 peer and receives
the kernel-reported sender. It bounds interrupted retries, clears sender
storage for each attempt, rejects short/impossible sends and incomplete
addresses, and distinguishes a consumed bad-sender datagram from retryable
backpressure. Truncated payloads retain the known sender for accounting.

The Linux leaf adds two minimal unsafe wrappers, reusing the existing raw
trampoline and a six-word socketcall argument block. Host tests exercise the
safe policy with scripted KernelOps and the route tables as plain data.
They do not execute this leaf. The BE checks/lints below compile it.

All commands used strictly remote RCH and Rust nightly-2026-08-31:

```sh
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 test \
  --locked --offline -p franken-platform -p franken-platform-linux \
  -p franken-stream -p franken-speaker --no-fail-fast -j1 \
  -- --show-output --test-threads=1

RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 clippy \
  --locked --offline -p franken-platform -p franken-platform-linux \
  -p franken-stream -p franken-speaker --all-targets -j1 -- -D warnings

# Executed separately for powerpc-unknown-linux-musl and mips-unknown-linux-musl:
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 check \
  --locked --offline -p franken-platform-linux --target "$TARGET" \
  -Z build-std=core,alloc,std,panic_abort -j1
RCH_REQUIRE_REMOTE=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  rch exec --source-content-receipt -- cargo +nightly-2026-08-31 clippy \
  --locked --offline -p franken-platform-linux --lib --target "$TARGET" \
  -Z build-std=core,alloc,std,panic_abort -j1 -- -D warnings
```

All 23 new ABI tests passed: 16 policy and seven route tests. The enclosing
native command **failed with exit 101**: 752 passed, three failed, one ignored.
The three speaker failures concern initial rebind accounting, stale playback
on a slow peer, and link-generation expectations. `parent-failures.log`
retains their exact diagnostics, including only isolated-loopback addresses.
Those carrier paths remain uncommitted and unqualified.

The final host Clippy and both BE check/Clippy pairs passed. All eight
component inputs match all six captured source manifests. At review, all
1,249 captured source files matched for each gate; terminal acknowledgment,
dead wrappers, absent owners and source/worker releases were verified.
`qualification.json` binds the raw-log hashes, receipt roots and inputs.
`native.log` retains every new component test result verbatim.

Formatting, Python compilation and diff checks passed. Existing P02 Python
tests passed 175/175; P06 passed 77/77. These are separate source/model checks.
The raw syscall bodies are unchanged. The typed-wrapper count and its
existing checks were updated from 12 to 14 without weakening assertions.

No BE guest has issued either new socketcall. Old-kernel flag admission,
actual kernel availability, driver/radio behavior and physical output remain
open. The two new unsafe blocks require the combined candidate's E06
inventory refresh. This development component closes neither P02 nor N07.
