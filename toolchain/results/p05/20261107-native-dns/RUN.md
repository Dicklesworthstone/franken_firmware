# P05 DNS future erasure: executed host regression evidence

The recursive DNS/runtime type no longer exceeds the compiler recursion limit
in the checked capability census. The native cancellation, blocking-pool and
HTTP/DNS regressions also executed successfully: **57 passed, 0 failed,
0 ignored**. This is host evidence for the source below, not QEMU, big-endian
guest, physical speaker, or the later byte-admission patches.

## Exact source

Asupersync base `69a33d8a3190d73916cf0ac39b73ea256c371266` with only
`src/net/dns/resolver.rs` and `src/net/dns/resolver/native.rs` overlaid:

- Overlay fingerprint:
  `870aec53fc8a6ed69a7b2a8420c55c774947472580382e3a41e5f39126ce6791`.
- Materialized Git tree: `6bef0f058d37ace3b0d5e8fdd4fcba2e886bea72`.
- `resolver.rs` SHA-256:
  `b39ba8b9a4015f9c5251311e3a6f194176018d3454d008e7c505e3dd42f2b9b4`.
- `native.rs` SHA-256:
  `13d8f2cd734f910daec7b14ab12b26d7e440973b6e955c317630afada4ae7473`.

The change erases the native resolver future at its recursive boundary; it does
not raise the library or consumer recursion limits. It adds a boxed future per
lookup. The HTTP positive uses an actual loopback UDP nameserver and TCP HTTP
server with blocking-pool admission forbidden, paired with the missing-resolver
refusal. It does not contact a public resolver or provider.

## Commands and observations

Both commands ran through strict remote RCH on `trj`, with one slot,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0`. The shared source options were:

```sh
RCH_REQUIRE_REMOTE=1 rch exec --worker trj \
  --base 69a33d8a3190d73916cf0ac39b73ea256c371266 --clean-overlay \
  --overlay-path src/net/dns/resolver.rs \
  --overlay-path src/net/dns/resolver/native.rs -- \
  cargo +nightly-2026-08-31 check --locked \
  --test capability_io_entrypoint_census -j1

RCH_REQUIRE_REMOTE=1 rch exec --worker trj \
  --base 69a33d8a3190d73916cf0ac39b73ea256c371266 --clean-overlay \
  --overlay-path src/net/dns/resolver.rs \
  --overlay-path src/net/dns/resolver/native.rs -- \
  cargo +nightly-2026-08-31 test --locked -j1 \
  --test runtime_abort_vs_cancel_semantics_audit \
  --test blocking_pool_toctou --test http_client_dns_forbidden_pool \
  --no-fail-fast -- --show-output --test-threads=1
```

The first command exited 0, with no recursion-depth or overflow diagnostics,
errors or warnings. Build `30099060530610500`; complete retained operational
log SHA-256:
`9c6824d8db3f850bb122d01a1732c12cea4c5f224592337e8d1806fb585ea580`.
This compiled the census; it did not execute its test functions.

The second command exited 0 (build `30099060530610567`):

| Executed test target | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `blocking_pool_toctou` | 6 | 0 | 0 |
| `http_client_dns_forbidden_pool` | 1 | 0 | 0 |
| `runtime_abort_vs_cancel_semantics_audit` | 50 | 0 | 0 |
| Total | 57 | 0 | 0 |

The retained command took 4,053.3 seconds, including compilation, transfer and
retrieval. The individual test groups took 3.06, 0.09 and 11.18 seconds.
Terminal acknowledgment, wrapper termination, owner absence and all five
source/tree/pair/staging/recovery release fields were independently checked.

[native.txt](native.txt) preserves the observed test names and verdicts, with
compiler/operational chatter omitted. Its SHA-256 is
`79d828cd90134b7df586cfc49e7c0b6a77c35453131ae6d8b8263431b168c470`.
The complete private operational log SHA-256 is
`76447cc75fbf3e6fd572f7a53b5aecbf43f543aae2cad61fbc1f26aac628aa78`.

## Qualification boundary

This focused combined run is not the complete ordered cancellation proof-runner
or a release qualification. P05 remains open for its original acceptance,
including the later captured-byte reservation and completion-order changes,
their native tests and strict Clippy, and the required target/guest evidence.
No device, provider, tailnet or acoustic playback was tested here.
