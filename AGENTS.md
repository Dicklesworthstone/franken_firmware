# AGENTS.md — FrankenFirmware

Guidelines for AI coding agents working in this repository. Claude-compatible
tools also read `CLAUDE.md`, which points here.

## Rule 0 — Direct Instructions

Follow Jeffrey's direct instructions. These rules encode standing preferences;
they do not overrule the user. Finish authorized work and report concrete
results, with the checks that support them. Do not claim runtime or emulation
success from documentation or a passing `cargo check` alone — a QEMU boot log
with the expected markers is the minimum bar for any "runs" claim.

## Rule 1 — Scope boundary is law

FrankenFirmware is a **research and prototyping workspace for replacement
firmware for the owner's own Sonos hardware**, on the owner's own LAN. It is
the "much-later, human-led research track" that the
[`frankensonos`](https://github.com/Dicklesworthstone/frankensonos) plan
deferred. Agents may:

- maintain and extend the inventory and hardware-profile evidence;
- cross-compile, emulate and test software under QEMU (never on hardware);
- build toolchains, initramfs images, boot/OTA tooling **offline**;
- document protocols, package formats, and boot chains from public evidence
  and from artifacts the owner's agents have already lawfully extracted.

The hard rules that bind every lane:

- **Never commit real site data or secrets to this public repo** — no real
  IPs, MAC addresses, serial numbers, household IDs, tokens, keys,
  certificates, firmware images, or packet captures. Public docs and fixtures
  use placeholders; real captures live in the git-ignored `.local-real/`
  directory (and in the frankensonos repo's own git-ignored captures).
- **Hardware flashing, device-affecting network experiments, and unlock or
  exploit attempts are OUT OF SCOPE here.** They are owned by the
  frankensonos project's human-led process (`docs/SCOPE.md` +
  `docs/ROOT_LANE_STATUS.md` there). This repo consumes their published
  findings; it never touches a live device. Read-only observation already
  captured into inventory files is the only device-derived data here.
- **No Deletion Or Destructive Git.** Do not delete files or directories
  without explicit written permission, including files you created. No
  `git reset --hard`, `git clean -fd`, `rm -rf`, force pushes, or branch
  deletes without explicit authorization for the exact operation. Preserve
  work you did not create; stage explicit owned paths only. Work on `main`.
- If a task reads as "flash this", "unlock that", or "run this against the
  speaker", stop — that is frankensonos's lane, not this repo's.

## Project Mission And Reading Order

Mission: a **memory-safe Rust firmware replacement** for the owner's mixed
Sonos fleet (Play:5 Gen1 on PowerPC, Play:1-class on big-endian MIPS, plus
Play:3/Sub/Playbar/Bridge), preserving the UPnP/SOAP/GENA contract that the
`fsonos` daemon already depends on, with signed A/B updates and
host-coordinated multi-room playback.

Reading order for a new agent:

1. `README.md` — what this is, current status, layout.
2. `FIRMWARE_ASSESSMENT.md` — the engineering assessment with its two peer
   reviews; contains the standing architecture constraints and the
   installed-firmware evidence base. Where it conflicts with earlier chat
   claims, the assessment wins.
3. `inventory/INVENTORY.md` — sanitized fleet counts and hardware classes.
4. `toolchain/` — the cross-toolchain bake-off evidence (BE-MIPS and BE-PPC
   musl targets, QEMU boot proof).
5. Frankensonos docs (separate repo) for the live device-side ground truth:
   `FIRMWARE_PATHS.md`, `ROOT_LANE_STATUS.md`, `UPDATE_FEED_AND_SIGNATURE.md`.

## Engineering Rules

- Toolchain: Rust stable, edition 2024; `#![forbid(unsafe_code)]` in
  application/protocol crates. Platform crates (startup, MMIO, DMA) may use
  `unsafe` in minimal audited form, per the assessment's memory-safety
  contract section.
- Every "runs" claim needs the command line and the observed output committed
  under `toolchain/results/` (QEMU serial logs, `file(1)` output, QEMU
  version). Evidence files must contain no personal data.
- Prefer reproducible scripts over narrative docs; scripts must be idempotent
  and safe to re-run.
- Never pin absolute personal paths in committed scripts — derive from
  `$(pwd)` / env vars.
- Run formatting and clippy before committing Rust changes. Run
  `python3 -m py_compile` on touched scripts.
- Keep firmware images, toolchain tarballs and kernel builds out of git
  entirely (build them from committed scripts into git-ignored `build/`).

## Related Repos

- [`frankensonos`](https://github.com/Dicklesworthstone/frankensonos) — the
  live host-side controller; its daemon defines the device-facing contract
  any replacement firmware must preserve, and its docs hold the installed
  firmware ground truth. Its human-led process owns all hardware work.
- `asupersync`, `frankenlibc`, `frankenfs`, `franken_remote` — the franken
  library stack assessed in `FIRMWARE_ASSESSMENT.md`; `franken_kernel` (the
  `no_std` type substrate) is the first candidate for on-device reuse.
