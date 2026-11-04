# Bespoke Rust Sonos firmware: initial engineering assessment

2026-11-04. Scope assumes arbitrary firmware installation is already possible. No flashing, playback changes, exploit execution or physical access performed. Inventory: 17 reachable devices, with raw descriptions/status and individual EE records under inventory/. Published specifications are attached to each device in devices.json. Unknowns are explicit; this is not a complete board-support package.

## Main decision

Build a shared, memory-safe audio appliance core, multiple board-support packages, and a capable host coordinator. Start with wired PCM playback on one spare device. Make Asupersync the control-plane foundation, not the audio interrupt scheduler. Do not start by placing the entirety of every Franken project on each speaker.

Seven S5 Play:5s dominate the fleet. Published teardown evidence suggests a 32 MiB RAM / 32 MiB NAND PowerPC platform. Supporting those well is a more consequential constraint than optimizing a newer ARM board. The Play:1 S1/S12 split requires explicit board mapping: product names do not identify processor architecture reliably. See inventory/hardware-profiles.json for primary sources and uncertainty.

## What the existing projects actually contribute

Source snapshots inspected (README/manifests; no builds or runtime qualification):

| Project | Revision | Reuse | Work still required |
|---|---|---|---|
| asupersync | ddda2bf82 | Structured task ownership, cancel/drain lifecycle, bounded channels, deterministic laboratory | Extract embedded-compatible executor/platform boundary; existing feature markers do not remove all native dependencies. Audit atomics, allocation, TLS, threads, reactor and timer assumptions on each target. |
| frankenlibc | a77173e43 | Select safe algorithms; potentially Linux compatibility during bring-up | Current Linux glibc-shaped ABI has host wrappers and unsupported symbols; x86_64/aarch64 emphasis is not PowerPC/ARMv7 readiness. A native no_std firmware need not implement libc at all. |
| frankenfs | da7bbffaa | Filesystem parsers and selected storage algorithms | Current userspace/FUSE design does not supply raw NAND ECC, bad-block handling, wear management or a boot filesystem. Prefer immutable image plus small crash-consistent configuration store initially. |
| franken_remote | 873f4827 | Session authentication and bounded media-queue design ideas | Desktop/tailnet/codec/process assumptions are inappropriate wholesale on these speakers. Remote desktop video can discard late frames; audio needs continuous clocked playout and concealment. |
| frankensonos | bba905c0 | Discovery, room/group model, existing controller and host-facing API | Controller is not device firmware; adapt the host API to a new device protocol, rather than duplicating cloud/service complexity in tiny endpoints. |

These are source-derived suitability assessments, not claims that the projects compile or run on Sonos targets. Keep dependency reviews separate from README claims.

## Memory safety contract

Literal zero unsafe code across a from-scratch hardware stack is not a realistic conventional Rust requirement: startup, MMIO, interrupt entry, DMA, allocator implementation and cache maintenance require a trusted boundary. Adopt forbid(unsafe_code) in application/protocol/DSP crates; isolate and audit unsafe/assembly in minimal platform crates. Require the same dependency-wide accounting for crypto, decoders and runtime. Existing Asupersync uses deny with local exceptions, not an unconditional whole-stack forbid.

Memory-safe Rust does not establish real-time behavior, correct sample rates, safe speaker excursion, or power-fail consistency. Replacing Linux would also mean supplying scheduling, virtual memory where needed, networking, device drivers and boot/recovery services. Running Rust on retained Linux is a useful intermediate milestone but does not satisfy an all-Rust-from-scratch OS claim.

## Device architecture

Boot ROM -> recoverable bootloader -> board support/kernel -> dedicated audio engine + Asupersync control services.

Board support must define CPU/ABI/endian/atomics, RAM map, interrupts, timers, watchdog, Ethernet, radio, I2C/SPI, I2S/TDM, DMA/cache coherency, flash controller, GPIO and amplifier reset/mute. Distinct PowerPC 603e/e300 and ARM targets require separate images and toolchain qualification. Published clock ratings are not live clock measurements.

The audio engine owns fixed-size preallocated rings and DMA buffers. No allocation, filesystem operations, networking waits or general executor work in its deadline path. Validate crossover and per-driver routing before enabling amplifiers. Preserve or recreate factory EQ, gain limits, DC rejection, thermal/excursion limits, mute ramps and fault shutdown. Five-way output on an S5 is materially different from stereo line output. Start with amplifier mute asserted, then instrumented low-level output on a spare unit.

Asupersync owns discovery, configuration, stream session lifecycle, update download and telemetry. Cancellation of a stream triggers a ramp-to-silence and bounded buffer drain; it must never free buffers still owned by DMA. A stalled control task must not stop the audio clock.

## Synchronization and resource envelope

Use timestamped audio blocks, sequence numbers, a group epoch and future playout deadlines. Estimate clock offset AND frequency drift; apply bounded asynchronous sample-rate conversion. Specify leader loss, partitions, rejoin, duplicates and late packet policies. Stereo and Sub alignment need tighter relative timing than separate-room music. Software clock agreement alone is insufficient: measure DAC presentation latency and oscillator drift.

Example sizing, not measured device performance: 48 kHz stereo 16-bit PCM is 192,000 bytes/s (1.536 Mbit/s before overhead); 250 ms buffering is 48,000 bytes. Five channels of 32-bit internal samples at 48 kHz consume 960,000 bytes/s, so 250 ms is 240,000 bytes. A 32 MiB device can hold these buffers; uncontrolled dependencies, TLS state, stacks, caches and diagnostics are more likely to exhaust it. One second of stereo PCM is not tens of megabytes.

Set explicit link-map flash and peak-RAM budgets per board, including stacks, allocator metadata, retransmission windows and worst-case packets. Measure DSP cycles and deadline misses under loss and control-plane load. Use bounded FEC only after comparing its latency/CPU costs with concealment or deadline-bounded retransmission. Avoid a full general-purpose database on endpoints.

Keep service login, catalog, transcoding and rich management on the host. Speakers accept a small authenticated stream/configuration protocol. Preserve local autonomous playback only where required; host failure behavior must be specified. Existing Sonos service credentials/DRM and proprietary mesh compatibility are separate integrations, not granted by firmware installation. Ethernet first avoids making Wi-Fi/SonosNet reverse engineering a prerequisite for first sound.

## Update and recovery

Signed manifests bind image to board identity and version. Preserve calibration, radio parameters and identity separately. Use watchdog-backed trial boot and rollback; A/B only if actual partition capacity permits it. Otherwise require a recovery boot path and power-fail-safe staging design. Never assume two images fit 32 MiB NAND. Read-only factory dumps and demonstrable recovery precede replacement.

## Milestones and exit evidence

1. Complete exact board mapping: CPU, actual RAM/flash, boot chain, radio and audio silicon, partition/calibration layout. Existing network observations plus published profiles are the starting ledger, not final proof.
2. Cross-compile minimal startup/serial/timer/memory tests for one board; exercise recovery before audio.
3. Wired PCM to protected single-speaker output. Measure frequency response, distortion, output limits, DMA underruns and thermal behavior.
4. Two-speaker timed playback; measure analog relative skew and drift over long runs, including packet loss, rejoin and leader failure. Lab-runtime tests complement physical measurements.
5. Integrate host control and signed power-fail-tested updates. Then port to the remaining board families and wireless paths.

The likely critical path is board/driver and acoustic reconstruction, not Rust application development. A small endpoint with host-assisted services is feasible in principle; claiming whole-fleet production firmware before those milestones would be premature. No trustworthy calendar estimate exists until first-board driver and recovery feasibility are established.

## Sources

- https://www.ifixit.com/News/4299/sonos-play3-teardown
- https://www.52audio.com/archives/47378.html
- https://www.huxiu.com/article/39121.html
- https://www.nxp.com/products/MPC8247
- https://github.com/trulyspinach/sonos-fenway
- https://doc.rust-lang.org/stable/embedded-book/
- Local project README.md, Cargo.toml and asupersync/src/lib.rs at the revisions above.

## Peer review reconciliation (2026-11-04; supersedes conflicting inventory statements above)

Fleet is now 18 distinct serial numbers, including eight S5s. Direct read-only GET verified the peer's extra unit (room "X"). Its table totals 18 despite its repeated claim of 17. Original SSDP snapshot found 17; discovery absence was not device absence.

Our original capacity uncertainty was an extraction mistake: saved description XML already contains lowercase memory, flash, seriesid. Device-reported nominal MB: S5 P100 32/32; Bridge X999 8/8; Playbar A100 128/128; Play:1 A101 128/64; Play:1 A200 256/256; Sub A100 128/64; Play:3 A100 128/64. Owned Play:3 overrides the older teardown's 64 MiB RAM sample. CPU identity still requires separate evidence. See corrected inventory/INVENTORY.md and EE correction facts.

Adopt these additions:
- Reuse franken_kernel identifiers/context/budget types. Source confirms no_std and forbid(unsafe_code), but also extern crate alloc and serde with default features enabled in Cargo.toml. Validate transitive no_std configuration. It is a types substrate, not a working embedded scheduler or OS kernel.
- Offer a retained-Linux Rust userspace prototype as a distinct intermediate track. Validate exact CPU/ABI/kernel syscall compatibility before choosing musl targets. Retained C kernel/musl does not fulfill an entirely memory-safe Rust firmware claim.
- Prefer a spare A200 Play:1 for first roomy prototype, followed promptly by one 32 MB S5 to validate the fleet's dominant constraint. Do not select the Sub on the premise that it is amp-only or low risk.
- Evaluate franken_remote control leases (with epochs/fencing and offline behavior), and bounded ATP/RaptorQ OTA transfer after measuring memory and CPU. Simple resumable transfer is the baseline; fleet size alone does not justify fountain coding.
- Inspect stock image metadata, board support, calibration and update layout before choosing partitioning or image formats. Host/QEMU tests validate software behavior only; generic QEMU ARM machines do not emulate these Sonos boards.

Reject unsupported peer claims:
- Marvell Orion/Armada guesses conflict with published PowerPC MPC8247/MPC8314 evidence. Do not select ARMv5/ARMv7 targets by age.
- NCC's One/Era-100 work is useful research methodology, not hardware or exploit applicability evidence for this fleet. No owned One/Era-100 was found. NCC reports fixes for the described vulnerabilities.
- Playbar uses optical TV input, not HDMI ARC.
- NAND is not interchangeable with SPI NOR; a CH341A clip does not establish recoverability. Read-only UART attachment has electrical/mechanical risk, and flash dumps do not make devices unbrickable.
- A/B plus permanent stock rescue is conditional on actual flash layout and capacity. Neither Linux mainline support nor accessible stock ALSA/DSP tuning is established.
- Runtime budgets are not physical heap or hard real-time limits; 12–16 MB free RAM is unmeasured. Do not treat arbitrary install access as solved drivers, cloud protocol licensing, or recovery.

Additional sources:
- https://www.nccgroup.com/research/blackhat-usa-2024-listen-up-sonos-over-the-air-remote-kernel-exploitation-and-covert-wiretap/
- https://support.sonos.com/en-ca/article/tv-requirements-for-sonos-home-theater-speakers
- /Users/jemanuel/projects/asupersync/franken_kernel/src/lib.rs and Cargo.toml (read live).

## Narrowed product scope: reliable Spotify and unified groups

User priority: Spotify, synchronized arbitrary cross-generation groups, volume, native Tailscale, iPhone AirPlay, YouTube lip-sync, Alexa control. Legacy format/library parity is explicitly unnecessary.

Recommended design: capable local coordinator terminates Spotify/AirPlay and external control integrations, decodes once per independent program, distributes one fixed timestamped PCM format to bounded speaker endpoints. Endpoints retain clock discipline/resampling, group epochs, volume ramps, per-board crossover/EQ/protection, DMA output, authenticated control, watchdog/recovery. No S1/S2 distinction exists in the new group protocol; board capability profiles remain. This needs actual replacement endpoints to remove the stock segregation.

48 kHz stereo 16-bit PCM: 192 kB/s; 1-second buffer ~188 KiB. Reconciled fleet has fifteen audio devices plus three Bridges; fifteen independent unicast copies cost 23.04 Mbit/s of payload before overhead. Shared-channel Wi-Fi airtime, retransmission and AP behavior still need testing. Multicast is not automatically better. No guarantee that removal of codecs alone fixes RF or hardware faults. Compare packet-loss/clock/deadline telemetry against current failures.

Keep two playout policies: music favors generous fixed buffering; video favors measured short deadlines and source-coordinated video delay. All members in a group share a presentation timeline. Dynamic latency changes require a coordinated transition; do not independently vary each speaker's delay. Universal YouTube lip-sync is impossible from audio endpoints alone if the display/player does not cooperate. AirPlay timing can help where the source honors it; controlled desktop/browser playback can delay video explicitly. Phone app and TV paths require separate validation.

Native on-device Tailscale remains requested, not silently substituted: distinguish it from gateway-mediated tailnet access. Stock official client availability for legacy 32-bit PowerPC is not established; memory, CPU, kernel and language constraints require a separate feasibility experiment. A minimal WireGuard implementation alone is not a Tailscale client. Gateway access is the practical initial option, subject to user acceptance; endpoint-native support remains open.

AirPlay can expose logical rooms/groups from coordinator-side receiver instances; endpoint-native AirPlay adds footprint and maintenance. Shairport Sync is a compatibility reference/prototype option, not strict Rust implementation proof. Spotify librespot requires Premium and ongoing protocol maintenance. Alexa volume/playback control integration is separate from Alexa music-service destination/default-speaker support and requires an authenticated service bridge; Alexa cloud cannot directly reach a private tailnet-only endpoint. No on-speaker microphone/voice assistant is required to receive commands from an existing Echo.

First success criterion: one Spotify program rendered continuously by a mixed-generation group, with measured output skew, bounded memory and no underruns during a specified loss/rejoin/load test. Add AirPlay, remote control, Alexa and per-source video sync after the renderer is qualified. Treat slimmer/faster/more robust as testable objectives, not achieved claims.

References checked: https://github.com/librespot-org/librespot/blob/dev/README.md ; https://github.com/mikebrady/shairport-sync ; https://pkgs.tailscale.com/stable/ ; https://www.developer.amazon.com/docs/alexaplus/device-apis/alexa-speaker

## Second peer review: existing firmware evidence and migration contract

Read-only verification: local model-16 57.23 anacapad is ELF32 big-endian PowerPC; local model-12 57.23 anacapad is ELF32 big-endian MIPS. Model-16 audiodev.o is PowerPC relocatable. This confirms two architecture families in extracted firmware, not exact SoC identity or a complete live device-to-image mapping. Supersede earlier candidate ARM mapping wherever a matching image establishes MIPS. Do not infer QCA9558 solely from ELF ISA. Inventory profiles' published teardown candidates remain historical hypotheses, not hardware identity.

Peer reports 21 devices. Direct GETs to additional .5.217/.6.119/.6.130 all timed out this review. Preserve 18 independently observed distinct serials plus three peer-reported candidates; do not claim these are nonexistent or independently verified. Bridges are not speakers, so 21 devices would mean 18 audio devices. The peer's newer S13 One requires its own mapping; mutually alternative NXP/Amlogic labels are not exact identification.

Adopt: map existing fsonos-proto SOAP/GENA/SSDP contract and fsonos-core call sites into a minimal compatibility adapter. Preserve public CLI/API behavior and implement only needed device actions/events; do not embed entire fsonos-core/database stack into speakers. Host backend adaptation is also an option. Custom firmware need not reproduce the old inter-speaker transport or all legacy services.

Adopt: investigate retained stock audio/radio drivers for first sound. Define the audio-device ioctl/mmap/ring ABI, ownership, format, clocks and amplifier controls before presuming ALSA. Merely loading a user process from /tmp is not zero-risk or sufficient for playback: the stock daemon may exclusively own hardware, and dual owners are unsafe.

New highest-priority offline gate: exact legacy kernel compatibility. ELF GNU/Linux minimum annotations are not proof of the running kernel release. If the reported Linux 2.4.x/2.6.x kernels are confirmed, modern Rust std/musl assumptions, threading/TLS, futex, atomics, reactor wakeup, timer and entropy APIs all need validation. Run a capability probe in a matching full-system guest; QEMU user mode on a modern host cannot establish old-kernel support. Then test a minimal Asupersync executor. frankenlibc is not an established upward syscall polyfill: accept+fcntl races, pipe flags, secure randomness and clock semantics need individual contracts; missing kernel behavior cannot always be emulated correctly.

Installation evidence boundary: genuine signed image installation, envelope decrypt/re-encrypt, mapped devmode routes and source analysis do not establish arbitrary modified-image installation. ROOT_LANE_STATUS explicitly retains the package signature barrier and describes developer routes as ready for a future unlock. FIRMWARE_PATHS contains conflicting historical statement-binding descriptions (fixed replayable vs device-bound); resolve per exact firmware before relying on portal availability. No portal-issued authorization or successful custom boot was verified here. Treat transport trust issues as separate from package authenticity. Do not adopt a rush-before-revocation strategy.

Rejected as unmeasured: <2.4 MB binary, <6.5 MB RAM, <50 microsecond skew, <15 ms whole-house line-in, architecture-agnostic dependency compatibility, nearly risk-free flashing. Keep these as optional targets only after qualification. At 48 kHz one sample is about 20.8 microseconds; <50 microseconds demands analog-output measurement, not merely clock packet agreement. Hard lower latency and robustness under long Wi-Fi outages trade off.

Next work remains offline: firmware identity/provenance matrix; kernel/ABI capability matrix; minimal contract adapter specification; single-stream renderer resource budget and actual build measurements. Device-affecting experiments remain separately coordinated under frankensonos's human-led rules. No builder repair, key use, unlock, exploit experiment or flash was performed in this review.

Sources: frankensonos/docs/ROOT_LANE_STATUS.md, docs/FIRMWARE_PATHS.md, docs/SCOPE.md; file(1) on the named local artifacts; https://doc.rust-lang.org/rustc/platform-support.html .
