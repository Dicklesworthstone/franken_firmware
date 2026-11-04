<div align="center">

# FrankenFirmware

**Your Sonos speakers, your firmware.** A research workspace for building
memory-safe Rust replacement firmware for the Sonos hardware you already own —
Play:5, Play:1, Play:3, Sub, Playbar, Bridge — spanning two SoC families
(big-endian PowerPC and big-endian MIPS) and two firmware generations (S1 and
S2).

![status: research](https://img.shields.io/badge/status-research%2Fpre--alpha-orange)
![language: Rust 2024](https://img.shields.io/badge/Rust-2024-dea584)
![license: MIT + rider](https://img.shields.io/badge/license-MIT%20%2B%20OpenAI%2FAnthropic%20rider-blue)
![targets: mips32 BE · powerpc BE](https://img.shields.io/badge/targets-mips32%20BE%20%C2%B7%20powerpc%20BE-7b4bff)
![safety: forbid(unsafe_code) app crates](https://img.shields.io/badge/safety-forbid%28unsafe_code%29%20app%20crates-blue)

</div>

> **Status: research workspace, pre-alpha.** The firmware does not exist yet.
> What exists and is committed: a fleet inventory (sanitized), a
> hardware/architecture evidence base, a two-peer-reviewed engineering
> assessment, and the first gate on the critical path — the
> **cross-toolchain bake-off**: hello-world `/init` binaries for
> `mips-unknown-linux-musl` (big-endian) and `powerpc-unknown-linux-musl`
> (big-endian), booted as PID 1 under QEMU. Results and serial logs live under
> [`toolchain/`](toolchain/).

---

## Why

Sonos hardware is excellent and lasts for years; the software around it is
where it falls short. The legacy S1 line is frozen forever, S2 moves on
without it, the two generations refuse to coexist in one group, and none of it
is hackable in the way this owner wants. The companion project
[**FrankenSonos**](https://github.com/Dicklesworthstone/frankensonos) already
replaced the *controller* side: a Rust daemon that runs the whole house over
the speakers' own UPnP/SOAP/GENA protocols. FrankenFirmware is the deferred
"much-later, human-led research track" from that project's plan: replace the
*firmware* side too, on hardware the owner already possesses, on the owner's
own LAN.

The shape of the end state (per `FIRMWARE_ASSESSMENT.md`, which two
independent peer reviews refined):

- a **shared memory-safe audio appliance core** (control plane, session
  lifecycle, signed update machinery) reused across board-support packages;
- a **retained-Linux first increment**: a static-musl Rust userspace under the
  stock kernel layout class, before any bare-metal ambition;
- the **fsonos daemon contract preserved** (UPnP/SOAP/GENA on :1400) so the
  house keeps working through the migration;
- a capable **host coordinator** (Spotify/AirPlay termination, decode-once
  PCM distribution) so the 32 MiB endpoints stay small.

## Repository layout

```
AGENTS.md                  rules for AI agents (also the human onboarding path)
FIRMWARE_ASSESSMENT.md     the engineering assessment + peer-review reconciliations
inventory/                 sanitized fleet inventory + capture scripts (no personal data)
toolchain/                 cross-toolchain bake-off: scripts, results, QEMU boot logs
docs/                      deeper notes as they land
.local-real/               git-ignored: raw captures with real IPs/MACs/serials
```

## What is proven so far

See `toolchain/results/` for the full evidence files. Headline:

| Gate | Target | Status |
|---|---|---|
| Hello `/init` builds, correct arch | `mips-unknown-linux-musl` (BE) | ✅ built, `file(1)`-verified, QEMU-booted as PID 1 |
| Hello `/init` builds, correct arch | `powerpc-unknown-linux-musl` (BE) | ✅ built, `file(1)`-verified, QEMU-booted as PID 1 |
| Runtime "hello" from PID 1 under QEMU | both | ✅ serial logs committed |
| franken_kernel (`no_std`) compiles for both targets | `--target` check | see `toolchain/results/` |
| asupersync executor on BE-PPC | compile + run | decision point — see results |

## Safety and scope

- **This repo never touches hardware.** Flashing, device experiments, and
  unlock/exploit work are human-led and live in the frankensonos project.
- Public repo hygiene: no real IPs, MACs, serials, household IDs, captures,
  keys, or firmware images. Raw captures live in git-ignored `.local-real/`.
- Memory-safety contract (from the assessment): `forbid(unsafe_code)` across
  application/protocol/DSP crates; minimal audited `unsafe` only in platform
  crates (startup/MMIO/DMA).

## Related

- [FrankenSonos](https://github.com/Dicklesworthstone/frankensonos) — the live
  host-side controller and daemon; its docs contain the installed-firmware
  ground truth and the human-led hardware process.
- asupersync · franken_kernel · frankenlibc · frankenfs · franken_remote — the
  franken library stack this firmware aims to reuse.

## License

MIT with an OpenAI/Anthropic rider — see [LICENSE](LICENSE).
