<div align="center">

# FrankenFirmware

**Replacement firmware for the Sonos hardware you already own**, written in
memory-safe Rust. The fleet: eight Play:5 Gen1, four Play:1, a Play:3, a Sub,
a Playbar, three Bridges. Two instruction-set families appear in the
extracted firmware images (big-endian PowerPC and big-endian MIPS; the exact
SoCs and which units run which image are still unresolved), two firmware
generations (S1 and S2), one target codebase.

![status: research](https://img.shields.io/badge/status-research%2Fpre--alpha-orange)
![language: Rust 2021/2024](https://img.shields.io/badge/Rust-2021%2F2024-dea584)
![license: MIT + rider](https://img.shields.io/badge/license-MIT%20%2B%20OpenAI%2FAnthropic%20rider-blue)
![toolchain targets: mips BE · powerpc BE](https://img.shields.io/badge/toolchain%20targets-mips%20BE%20%C2%B7%20powerpc%20BE-7b4bff)
![safety: forbid(unsafe_code) app crates](https://img.shields.io/badge/safety-forbid%28unsafe_code%29%20app%20crates-blue)

</div>

> **Status: research workspace, pre-alpha.** The live tracker has 56 beads;
> the 2026-11-05 review found five closed (E01, E03, E05, E07 and Q00).
> Use `br list --all --deferred --limit 0 --json` for current counts and
> `br ready --json` for actionable work. The Rust workspace, offline suites
> and cross-target evidence are implemented in this tree; each open bead
> still requires its own acceptance review. Passing host tests or cross-checks
> does not qualify playback on Sonos hardware.

---

## Why

Sonos hardware lasts for years; the software around it does not keep up. The
S1 line is frozen, S2 dropped it, and the two generations cannot share a
group. The companion project
[**FrankenSonos**](https://github.com/Dicklesworthstone/frankensonos) already
replaced the controller side with a Rust daemon that runs the whole house
over the speakers' own UPnP/SOAP/GENA protocols. FrankenFirmware is the
firmware side of that plan: new software on hardware the owner already
possesses, on the owner's own LAN.

The architecture follows the assessment (two independent peer reviews) and
the bead graph.

Retained kernel first: a static-musl Rust userspace runs under the stock
kernel layout class; a from-scratch OS is a later, separate ambition. The
audio path uses the retained stock drivers behind audited HAL adapters
(E04, P04, D04).

Host-assisted by design: Spotify sessions, AirPlay, Alexa and Tailscale
admission live on a host coordinator. The 32 MiB endpoints (the eight Play:5
Gen1 units are the fleet's center of gravity) run a small render and network
runtime, fed by decode-once PCM distribution rather than per-speaker
clients.

The fsonos contract survives: a compatibility adapter (G03) keeps the
existing daemon, CLI and MCP surfaces working over the new firmware, so the
house keeps working through the migration.

Reversibility is designed in from the start: signed staged artifacts with
anti-rollback (U02), a human-led activation runbook with rollback triggers
(U03), and calibration/state custody handled before any activation (U01).

Native integrations are gated. Spotify (S01-S03) is the first source;
AirPlay (A01-A02), Alexa (X01-X05, including optional local voice on
microphone-bearing boards), Tailscale (T01-T04) and video sync (V01-V02)
each carry their own qualification beads, and a bead closes only when its
qualification evidence does.

## The plan: 56 beads

Task state lives in `.beads/` (the beads tracker). The graph has two roots,
E01 (reconcile device/firmware identity evidence) and Q00 (deterministic
test/receipt infrastructure); everything else waits on them in a dependency
graph 19 waves deep, with no cycles (`br dep cycles` is clean). Run
`br ready --json` for what is actionable right now. The families:

| Family | Beads | What it covers |
|---|---|---|
| E — Evidence | 7 | board/firmware identity reconciliation, incumbent baselines, legacy kernel ABI matrix, retained audio driver ownership, boot/rollback semantics, dependency audit, BE bootstrap harness repair |
| P — Platform | 6 | Rust workspace and build profiles, legacy platform capability layer, bounded Asupersync execution profile, board HAL adapters, Asupersync upstream adaptation, portable Franken library subsets |
| D — DSP/render | 4 | fixed-size audio blocks, board protection DSP, drift correction and resampling, render scheduling against the retained HAL |
| N — Network transport | 7 | authenticated stream framing, bounded control channel, group clock and synchronized join, jitter and concealment, RaptorQ evaluation, bounded FEC, link lifecycle and paced delivery |
| G — Groups/control | 3 | unified cross-generation group state machine, volume/mute/roles, fsonos compatibility adapter |
| S — Spotify | 3 | source session contract, codec profile qualification, cache and source placement |
| U — Update/state | 4 | persistent state and calibration custody, signed staged artifacts, reversible activation handoff, readiness/recovery UX |
| Q — Qualification | 8 | test infrastructure, virtual-house harness, footprint and deadline budgets, acoustic/network qualification, combined-candidate qualification, release handoff, external-gate validation, real-process E2E |
| T/A/X/V/L — Integrations | 14 | Tailscale (4), AirPlay (2), Alexa (5), video sync (2), line-in (1) |

## Repository layout

```
AGENTS.md                  rules for AI agents (also the human onboarding path)
FIRMWARE_ASSESSMENT.md     engineering assessment with two peer-review reconciliations
inventory/                 sanitized fleet inventory + capture scripts (no personal data)
toolchain/                 bake-off sources, initramfs builder, boot scripts, results
docs/                      per-bead contracts will land here (E01 targets docs/contracts/e01.md)
.beads/                    the task graph (br CLI); commit alongside code
.local-real/               git-ignored raw captures with real IPs/MACs/serials
```

## What is proven so far

Evidence lives in `toolchain/results/` with committed serial logs.

| Gate | Target | Status |
|---|---|---|
| Hello `/init` builds | `mips-unknown-linux-musl` (BE) | done: 2,068 B static ELF, `file(1)`-verified |
| Hello `/init` builds | `powerpc-unknown-linux-musl` (BE) | done: 1,588 B static ELF |
| Boot as PID 1, banner on serial, clean reboot | BE-MIPS (QEMU Malta, 4.19 kernel) | done, full cycle |
| Initramfs unpack, `/init` exec, user→kernel syscalls, clean reboot | BE-PPC (QEMU g3beige/OpenBIOS, 4.9 kernel) | done; userspace output reaches the serial console through the `pmac_zilog` driver (`/dev/ttyPZ0`, `console=ttyPZ0`); run `toolchain/results/runs/1412ac47120d4e5b865f9de6e05f50fe` |
| std + full dependency graph cross-compiles | BE-PPC via `-Z build-std` | done |
| asupersync legacy runtime on BE-PPC | | the initial `AtomicU64` compile blocker has been addressed; P05 remains open for its bounded-runtime acceptance and target evidence (`docs/contracts/p05.md`) |

These are cross-build and emulation results on generic QEMU machines (Malta,
g3beige). They show the toolchain and boot path work for the two big-endian
instruction-set families; they say nothing about Sonos silicon. The committed
image evidence records no ISA revision, ABI or float ABI for the MIPS image
(`abi: null` in `inventory/image-evidence.json`), and no live unit is mapped to
that image (`inventory/INVENTORY.md`, `docs/contracts/e01.md` §11).

Two porting bugs were found and fixed along the way, and both are documented
in `toolchain/results/RESULTS.md`: MIPS o32 syscall numbers are 4000-based
(`write` is 4004; using the generic numbers fails silently), and `asm!` on
these targets needs `asm_experimental_arch` with explicit `$N` register
bindings.

## Safety and scope

This repo never touches hardware. Flashing, device experiments and
unlock/exploit work are human-led and live in the frankensonos project
(`docs/SCOPE.md` there). Activation of anything onto a speaker is bead U03:
a human-led runbook with rollback.

Public repo hygiene: no real IPs, MACs, serials, household IDs, captures,
keys or firmware images. Raw captures live in git-ignored `.local-real/`.

Memory-safety contract: `forbid(unsafe_code)` in application, protocol and
DSP crates; minimal audited `unsafe` only in platform crates (startup, MMIO,
DMA), per the assessment.

## Working on this repo

`AGENTS.md` is the onboarding path. The tracker is beads: `br ready --json`
shows actionable work, `br show <id> --json` gives scope and acceptance
criteria, and each bead's owned outputs (a contract doc under
`docs/contracts/` plus code) land as the bead is worked. Beads commit
alongside code (`br sync --flush-only` before `git add .beads/`).

## Related

- [FrankenSonos](https://github.com/Dicklesworthstone/frankensonos): the live
  host-side controller and daemon; its docs hold the installed-firmware
  ground truth and the human-led hardware process.
- asupersync, franken_kernel, frankenlibc, frankenfs, franken_remote: the
  franken library stack; bead P06 owns extracting the portable subsets.

## License

MIT with an OpenAI/Anthropic rider; see [LICENSE](LICENSE).
