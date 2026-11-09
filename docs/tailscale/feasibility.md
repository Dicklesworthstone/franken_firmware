# Native Tailscale on the legacy speakers: feasibility (T01, `ffw-32a`)

Date of the study: 2026-11-06, with the compile-only T01-X01 records of 2026-11-07 and the T01-X02 guest runs of 2026-11-08. Contract and candidate table: `docs/contracts/t01.md`. Frozen profile: `docs/tailscale/profiles.json` (`t01-profile-2026-11-09.1`, which replaced `t01-profile-2026-11-07.1` and, before it, `t01-profile-2026-11-06.1`; see its `frozen_note` and the decision record in `toolchain/results/tailscale/RUN.md`). Evidence ledger:
`tests/tailscale-fixtures/evidence/ledger.json` (ids `T01-E01` to `T01-E47`, cited below). Offline; the builds are root's compile-only type-checks (T01-X01) and the operator's release builds of the X02 probe, and no tailscale-rs client was linked, run on a target, enrolled or measured: the X02 probe (the seven core crates and a known-answer phase) ran once in one harness guest per architecture, and it is not a client.

## The question

The owner asked for native on-device Tailscale: each speaker enrolled under its own identity, receiving the network map, applying policy, reaching peers through NAT traversal or relays, with
key rotation and honest DNS naming. A WireGuard tunnel alone is not that, and a host gateway is gateway access, not per-speaker membership. The targets are PowerPC 32-bit big-endian (stock
Linux 2.6.14, 32 MB nominal) and MIPS32r2 big-endian (stock Linux 2.6.35, 128 MB nominal), both kernels *reported and unqualified*.

## What the official client is, and why it is not the answer here

The Go client is the reference for every behavior in the contract (E38-E41): control-plane identity, policy, DNS and coordination, and a WireGuard data plane on each device. Three facts,
all from the pinned sources, keep it out:

1. It is not strict Rust. The bead is explicit that no Go reference client counts.
2. There is no 32-bit PowerPC Go port: the toolchain's port table has linux/ppc64 and ppc64le only (E01), and the official static tarballs have no PowerPC build (E06).
3. For big-endian MIPS a static binary exists (E05-E07, a 36,700,859-byte compressed archive, which says nothing about memory), but Go's documented minimum is Linux 3.2 (E02) against the
   reported 2.6.35. This is conditional on the reported release being right; a measured kernel change would make the same sentence read differently. Nothing here assumes a kernel swap.

Its documented userspace mode (a SOCKS5/HTTP proxy, E08) is an operating mode of that Go daemon, not a small Rust implementation (E46): a wrapper, classed separately. A host gateway is
gateway access (E47). Neither counts, and neither was assessed beyond its class.

## The strict-Rust candidate

`tailscale/tailscale-rs` v0.6.1 is official, BSD-3-Clause, and says it is a preview. It has real code for the hard control-side pieces: registration and a streaming network map over a Noise IK
channel (E21), a packet filter built from the map's policy (E20), a partial but interoperable WireGuard tunnel that had a third-party cryptographic audit (E19, E25), and relay through public
DERP (E14). By its own README it does **not** have NAT traversal (STUN, disco), lookup by hostname, MagicDNS, private DERP, automatic key rotation or application capabilities (E15-E17), and its
disco crate is incomplete (E18). The wire types for rotation exist (E27); the flow that uses them does not. Its supported platforms are 64-bit Linux, macOS ARM64 and Windows (E13).

Three findings are specific to our targets, each from a pinned source, none from a build:

* **The reactor.** The library is built on tokio; `net` rides on mio, and mio 1.2.1 creates its epoll instance with `epoll_create1` and has no `epoll_create` fallback (E34, E35). That call exists
  since Linux 2.6.27 (E36). The reported PowerPC kernel is 2.6.14 (E31), so as shipped the library cannot start its I/O driver there; the reported MIPS kernel, 2.6.35, clears this floor. This is a
  property of the reactor choice. The project's own platform layer (P02) was designed with a poll fallback for exactly this, which is an argument for re-hosting the I/O half, not for the library as is.
* **The TLS backend.** `ts_tls_util` depends unconditionally on `tokio-rustls` with the `aws-lc-rs` backend (E22). Its `aws-lc-sys` 0.45.0 ships assembly source sets only for x86_64, aarch64, arm, x86
  and powerpc64 (E28), and refuses its no-assembly switch in optimized builds (E29). The C library does define `OPENSSL_PPC32BE` and `OPENSSL_MIPS` (E30), so a portable-C build is plausible; whether it
  compiles and passes on big-endian 32-bit was unknown. The central type-check (T01-X01) answers the compile half at type-check level: `aws-lc-sys` 0.45.0's build script ran inside the whole-library `cargo check` for
  `powerpc-unknown-linux-musl` with no compiler configuration, and for `mips-unknown-linux-musl` only once a pinned Zig 0.14.1 C compiler wrapper was configured, after the worker's missing C compiler stopped the first
  attempt (the account is in `toolchain/results/tailscale/RUN.md`). A type-check links and runs nothing, so whether the crypto passes on big-endian 32-bit stays unknown.
* **The protocol-core crates: a workspace-edge fact, not a portability claim.** A static look at the declared normal dependencies of the 45 workspace crates shows that the protocol-core crates
  (keys, Noise, the WireGuard tunnel, the wire types, the packet filter, the disco message types, the routers) have no intra-workspace edge to a tokio, OS or TLS crate, while the control client,
  the relay client, the data-plane wiring, the network monitor and the netstack glue do (`derived_facts` `workspace_edges`). The probe stops at every third-party package, and the pinned lock
  shows why that is not enough: nine of those crates (including `ts_tunnel`, `ts_keys`, `ts_noise`) reach `libc` through their third-party closure (`rand` 0.10.2 -> `getrandom` 0.4.3 -> `libc`; an
  over-approximation over every target and feature). Whether any of that is OS-free for these targets stays **unqualified**: the selected Cargo graph is recorded now (T01-X01: the seven core crates and their locked closure type-check for both triples, with `libc` and `getrandom` among the packages), but a type-check
  neither links nor runs anything and OS-freedom is a property of the linked program. If it holds, the shape of an implementable path is: re-host the I/O half on the project's reactor and reuse the core, with the
  `unsafe` in `ts_packet` (6 tokens), `ts_bart` (5) and `ts_disco_protocol` (3) reviewed against our rule, `rand` served by the P02 entropy provider rather than a silent fallback, and the
  `chrono` wall-clock types handled with the P02 wall-clock policy. All of it is declared dependencies read from manifests; none of it has been compiled for these targets.

## The outcome of the study

No candidate is supported on any target. Of the 240 derived matrix cells (5 candidates, 4 targets, 12 behaviors), none is `supported`: the official client is `incompatible` on both stock targets;
tailscale-rs is `incompatible` on the PowerPC stock kernel (conditional on the reported release), `no_evidence` where it is implemented but unbuilt, and `implementable_upstream_work` for NAT traversal,
key rotation, MagicDNS and the partly implemented peer-discovery and relay behaviors. Strict-Rust native Tailscale on these targets is therefore **not shown feasible and not shown impossible**: it is
real, bounded engineering with named gaps. Of its two cheapest decisive experiments, the compile-only build (T01-X01) and a protocol-core probe in a harness guest (T01-X02) are done and do not answer the question; the one still open is a linked tailscale-rs client run in a harness guest.

The native requirement stays required. **This study is INCOMPLETE and pending**: the legacy-ISA compile attempts (T01-X01) built as type-checks only, and the X02 probe ran once in one harness guest per architecture (both committed receipts pass the judge; the figures are indicative only, are of the probe and not a client, and are not a stock kernel or a board), so no client was linked, run, enrolled or measured and the five tailnet scenario rows of the profile (enrollment, maps at the peer cap, reconnect, relay traffic, key rotation) are pending with their blockers. No closure of T01 is claimed, and the open work is not moved to another bead. It does not close T02, T04 or Q06.

## What would change the answer, in order of cost

1. **Done at type-check level (T01-X01):** the protocol-core crates and the whole library type-check for both triples (the MIPS whole library once a C compiler wrapper was pinned); no crate stopped the build after that. Still open: a linked build, a run on a target, and the TLS backend's behavior on big-endian 32-bit.
2. **A decision on the reactor**: tokio-free I/O for the control, relay and netstack halves over the P02 platform layer, or a kernel/runtime change. This is T04's question.
3. **Upstream or ours**: NAT traversal (disco), key rotation, MagicDNS and private DERP are upstream's stated roadmap or absent; contributing them or owning them is a staffing decision.
4. **A budget**: no numeric RAM cap exists for the tailnet component (absent budget is pending, not pass); T04/Q02 allocate it. Only then can a measurement be a verdict.
5. **A guest** that matches a stock kernel (none exists). **Done for the probe, not for a client:** the existing harness guests (Debian 4.19 MIPS Malta, Debian 4.9 PowerPC g3beige) ran the X02 probe once each, as an indicative stand-in (contract section 9, "What ran"); a linked client run in them, for any client figure, is still open.

## Not read in this study

The Go client's offline behavior, clock handling, diagnostics and resource bounds; the rest of tailscale-rs beyond what the cited files state; any other Rust or WireGuard implementation; Headscale
(a control server, not a client); `libtailscale`/`tsnet` bindings (Go runtime wrappers, classed as wrappers by definition and not assessed).
