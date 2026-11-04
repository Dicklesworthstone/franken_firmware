# FrankenFirmware — CHANGELOG

All notable changes to this repository are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
has no releases yet, so entries are organized by commit rather than version.

Scope window: 2026-11-04 (initial commit `9d8d530`) through the present
head; the full history, as the repository is one day old.

## Version Timeline

| Commit | Date (2026-11-04, US/Eastern) | Summary |
|---|---|---|
| [`9d8d530`](https://github.com/Dicklesworthstone/franken_firmware/commit/9d8d5308d6844c6339283ae088c6cb9bcd2da4da) | 13:35 | Initial commit: assessment, sanitized inventory, agent rules |
| [`534dc65`](https://github.com/Dicklesworthstone/franken_firmware/commit/534dc6502cad73f565ee6eb8e9af1fa5abe4c443) | 16:10 | Toolchain bake-off: BE-MIPS full boot pass; BE-PPC kernel-side pass |
| [`f3caa4e`](https://github.com/Dicklesworthstone/franken_firmware/commit/f3caa4e44738257d1d353b8605487ce424d96fd4) | 16:10 | README: point results reference at `toolchain/results/` |
| [`38fe605`](https://github.com/Dicklesworthstone/franken_firmware/commit/38fe6050468ffcfe92150d8697b5e8045a2a17de) | 16:33 | README: rewrite around the 56-bead plan; de-slopify pass |
| [`fb276a0`](https://github.com/Dicklesworthstone/franken_firmware/commit/fb276a0d13ca85c1abf7d4c1c21d2b29e3ed5959) | 16:39 | Clarify code-first swarm verification and ownership rules (AGENTS.md) |

There are no tags and no GitHub Releases yet; the rows above are plain
commits, linked live. Bead Q05 ("Produce release and maintenance handoff")
owns the first tagged release.

## Capability waves

### Wave 0: Governance and ground truth (9d8d530)

The repository opened with the documents every later decision rests on.

Delivered capability:

- `FIRMWARE_ASSESSMENT.md`: the engineering assessment for replacement
  firmware across the fleet (eight Play:5 Gen1 on big-endian PowerPC,
  four Play:1 and one Play:3/Sub on big-endian MIPS, Playbar, Bridges),
  carrying two independent peer-review reconciliation sections that
  supersede earlier architecture guesses and set the memory-safety contract
  (`forbid(unsafe_code)` in application/protocol/DSP crates; minimal
  audited `unsafe` only in platform crates).
- `inventory/`: sanitized fleet inventory (18 devices, model-level only)
  with the capture scripts (`scan.py`, `enrich.py`, `reconcile.py`) that
  reproduce it against a live LAN; real addresses, MACs and serials stay in
  the git-ignored `.local-real/` area.
- `AGENTS.md` / `CLAUDE.md`: agent governance, including the rule that this
  repo never flashes or probes hardware; all device-affecting work stays in
  the frankensonos project's human-led process.
- Repo plumbing: `.gitignore` (personal-data exclusions, build outputs),
  LICENSE (MIT + OpenAI/Anthropic rider).

Closed workstreams: repo bootstrap; the "what are we even building"
question answered with peer-reviewed scope.

Representative commits: [`9d8d530`](https://github.com/Dicklesworthstone/franken_firmware/commit/9d8d5308d6844c6339283ae088c6cb9bcd2da4da).

### Wave 1: Cross-toolchain bake-off (534dc65, f3caa4e)

The first hard gate on the critical path: prove that Rust userspace can be
built, linked, and booted as PID 1 on both big-endian architectures the
fleet actually contains.

Delivered capability:

- `toolchain/src/ffw-hello-init/`: a `no_std`, raw-syscall PID-1 program
  (write / open / dup2 / reboot) that builds for
  `mips-unknown-linux-musl` (2,068 B static ELF) and
  `powerpc-unknown-linux-musl` (1,588 B) via `-Z build-std=core,
  compiler_builtins` and `ld.lld` static linking.
- `toolchain/src/mkinitramfs.py`: rootless newc-cpio initramfs builder
  (kernel-correct header layout, `/dev/console` and `/dev/ttyS0` nodes).
- `toolchain/src/boot-mips.sh` / `boot-ppc.sh`: reproducible QEMU boots
  (Malta 24Kf with a Debian 4.19 BE kernel; g3beige/OpenBIOS with a Debian
  4.9 BE kernel).
- `toolchain/results/RESULTS.md`: the evidence write-up.

Measured results:

- BE-MIPS: full cycle under QEMU: kernel boots, `/init` runs, banner
  reaches the serial console, clean `reboot(RB_AUTOBOOT)`.
- BE-PPC: initramfs unpacks, `/init` executes, the program's `reboot`
  syscall restarts the machine deterministically; userspace console output
  remains open (g3beige's escc serial does not match an 8250 `/dev/ttyS0`
  node).
- asupersync under BE-PPC: the standard library and the full dependency
  graph cross-compile; the library itself fails with exactly 133 errors,
  all one root cause (`std::sync::atomic::AtomicU64` does not exist for
  `powerpc-unknown-linux-musl`, whose `max-atomic-width` is 32). The
  decision recorded in `RESULTS.md` is GO with a `portable-atomic`
  abstraction task.

Bugs found and fixed during the bake-off, documented for the next porter:

- MIPS o32 syscall numbers are 4000-based (`write` is 4004); using the
  generic numbers makes every syscall fail silently.
- `asm!` on MIPS/PPC requires `#![feature(asm_experimental_arch)]` with
  explicit `$N` register bindings (and `$1`/`$at` cannot be a named
  clobber).
- The cpio writer initially produced a wrong trailer (`namesize` field 0
  instead of 11), used the wrong octal constant for `S_IFCHR`, and
  mis-padded file data relative to names; all three broke the kernel
  unpacker in different ways.

Closed workstreams: the "can we even build for these machines" question —
yes for both architectures, with the asupersync atomics gap scoped.

Representative commits: [`534dc65`](https://github.com/Dicklesworthstone/franken_firmware/commit/534dc6502cad73f565ee6eb8e9af1fa5abe4c443) (bake-off), [`f3caa4e`](https://github.com/Dicklesworthstone/franken_firmware/commit/f3caa4e44738257d1d353b8605487ce424d96fd4) (results link).

Known limitation at this commit: `toolchain/src/mkinitramfs.py` computes
device numbers through `os.major(dev[0])`, which encodes `(5,1)` as
rdevmajor 0 / rdevminor 5. Bead E07 owns the repair (a corrected
`normalize_dev_tuple` implementation is in development in the working tree
alongside a verification receipt) and the fresh regression tests for the
newc parser. Consequence: initramfs archives built by this commit's script
have device nodes with wrong major/minor numbers, which is why userspace
console output on some machines fails even though init runs.

### Wave 2: Plan publication and hygiene (38fe605)

Delivered capability:

- README rewritten around the live beads plan: 56 tracked beads across 13
  families (Evidence, Platform, DSP, Network, Groups, Spotify, Update,
  Qualification, plus integration families), with counts verified against
  `br list --json` and the two actionable roots (E01, Q00) named.
- Architecture section re-cast from bullet-slog to prose; AI-writing
  artifacts removed in a de-slopify pass.
- `.beads/` tracker config committed so the task graph travels with the
  repo (the JSONL export stays local per `.gitignore` policy).

Closed workstreams: the "what is the plan and what is done" question,
answered from the tracker rather than from memory.

Representative commits: [`38fe605`](https://github.com/Dicklesworthstone/franken_firmware/commit/38fe6050468ffcfe92150d8697b5e8045a2a17de).

### Wave 3: Swarm governance hardening (fb276a0)

Delivered capability:

- `AGENTS.md` gains Implementation Swarm Rules: code-first with batch
  remote verification (`RCH_REQUIRE_REMOTE=1 rch exec`), no self-closing of
  beads (supervisor verifies acceptance at the exact revision), no
  placeholder success or weakened assertions, narrow Agent Mail file
  reservations keyed by bead ID, and the requirement that native tailnet
  support survives any host-assistance shortcut.

Closed workstreams: process rules that keep the 56-bead build-out honest
as multiple agents work it in parallel.

Representative commits: [`fb276a0`](https://github.com/Dicklesworthstone/franken_firmware/commit/fb276a0d13ca85c1abf7d4c1c21d2b29e3ed5959).

## Workstreams in flight (not yet landed)

From the beads tracker, 56 open/in-progress beads as of this entry. The two
roots of the dependency graph are:

- E01, Reconcile device and firmware identity evidence (sanitized
  board-profile manifest; in progress).
- Q00, Deterministic test, receipt and bounded-logging infrastructure
  (in progress).

Everything else (11 dependency waves) hangs behind them: platform layer
(P01-P06), DSP and render (D01-D04), network transport (N01-N07), groups
and the fsonos compatibility adapter (G01-G03), Spotify source (S01-S03),
updates and activation (U01-U03, UX01), qualification (Q01-Q07), and the
gated integrations: Tailscale (T01-T04), AirPlay (A01-A02), Alexa
(X01-X05), video sync (V01-V02), line-in (L01).

## Notes for agents

- The tracker record for any bead is `br show <id> --json`; the family
  overview lives in `README.md` ("The plan: 56 beads").
- Boot evidence for the bake-off lives in `toolchain/results/RESULTS.md`;
  serial-log captures are being re-run and re-attached under E07's
  verification lane, so treat `RESULTS.md` numbers (binary sizes, error
  counts) as the durable record and the logs as working evidence.
- The `.beads/issues.jsonl` export is deliberately git-ignored in this
  repo (mirror of the frankensonos convention); use the live database via
  `br` rather than expecting the JSONL in-tree.
