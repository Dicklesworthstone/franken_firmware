# FrankenFirmware slim speaker implementation plan

Status: reviewed implementation plan; task creation is complete only with Beads receipts. This artifact does not authorize hardware deployment.

## Product decision

Build a shared Rust speaker appliance on retained, qualified stock kernels and audio/radio drivers.
The default ambition is native capability on each admitted device class, with capability-based profiles.
Use one protocol and common codebase, separately compiled for each actual ISA/ABI.
Do not require a host coordinator to satisfy a requirement called native.
Coordinator-assisted profiles are explicit early milestones and optional operation modes.
The user wants reliable Spotify, arbitrary cross-generation groups, volume/mute and synchronization.
Also preserve native Tailscale, AirPlay2 discovery/playback, source-aware video lip-sync and Alexa control.
Retain line-in distribution and optional local voice as planned capabilities.
Do not preserve obsolete service catalogs, SMB library indexing or unused codecs merely for stock parity.
A replacement must preserve the useful fsonos controller contract, not every old daemon behavior.

## Evidence and language contract

The root MOR_CASE.md records evidence IDs and unknowns.
The supplied peer design is the architectural direction, not proof of footprint or performance.
Claims of 1.15 MB binary, 2.8 MB RAM, 19 MB spare and fixed integration latencies are unmeasured targets.
File size does not measure resident memory or establish the cause of stock dropouts.
Nominal installed RAM differs from available process memory after kernel/device reservations.
A tiny driver object does not imply simple, complete or safe audio control.
A common Rust binary cannot execute unchanged on incompatible CPU instruction sets.
Retained Linux, vendor modules and libc are trusted non-Rust dependencies in the first profile.
Application, protocol and DSP crates forbid unsafe; platform code needs minimal explicit audited exceptions.
Dependencies are included in the safety inventory; first-party lints do not certify transitive code.
Firmware envelope keys, authorized unlock state and arbitrary installation are separate capabilities.
No vulnerability exploitation, signing bypass, credentials extraction or device modification is part of this plan execution here.

## Deliverable reading order

1. This document defines scope, milestones, task graph and acceptance requirements.
2. SLIM_RUNTIME_DESIGN.md defines platform/audio/transport contracts and rationale.
3. SLIM_INTEGRATIONS_DESIGN.md defines the external protocols and user workflows.
4. MOR_CASE.md and MOR_CLAIMS.jsonl distinguish observations, hypotheses and audited decisions.
5. Beads tasks duplicate enough context to implement without reopening the entire plan.

## User journeys

Spotify: choose a room or group, start playback, adjust any room, add an older speaker without restarting the program.
Group change: admit capabilities, assign channels, choose future epoch, buffer silently, then enter at the agreed sample position.
Network interruption: play buffered content within policy, conceal bounded short gaps, mute smoothly when continuity is impossible, then rejoin silently.
AirPlay: discover named room/group, pair if required, stream audio, maintain identity and volume semantics across source route changes.
Video: preserve source timestamps and measured render delay; compensate display only through a supported cooperative source mechanism.
Tailnet: remote authenticated control reaches an admitted native endpoint or an explicitly named gateway profile.
Alexa: discover supported control capabilities, resolve room names, apply volume/mute/playback with bounded authenticated commands.
Line-in: choose the physical source once, prevent feedback, schedule capture samples on the selected group timeline.
Local voice: supported mic hardware only, visible listening state, bounded processing and no default retained recordings.
Recovery: preserve stock return path and calibration, surface degraded capabilities, never silently loop in loud or unprotected output.

## Non-goals and exclusions

No full SMAPI service catalog, legacy shared-library indexing or arbitrary codec compatibility.
No universal zero-dropout promise under arbitrary network outages.
No universal automatic YouTube synchronization for unmodified applications that do not expose timing control.
No automatic conversion of WireGuard code into a complete Tailscale identity/control implementation.
No assumption that every Echo accepts every local bridge protocol or exposes unrestricted Spotify destination registration.
No universal zero-risk deployment claim from a writable boot hook or an untouched rootfs partition.
No audio endpoint role for Bridge devices unless a separate non-audio networking use is justified.
No product implementation in the planning/review session.

## Architecture decisions and rationale

Retain drivers first because acoustic protection, DMA and radio behavior are expensive hardware-specific knowledge.
Use typed HAL ownership because double ownership of the audio device can corrupt timing and protection state.
Keep realtime rendering separate from cooperative runtime work because service cleanup cannot be allowed to miss an audio deadline.
Preallocate bounded data structures because the smallest endpoint cannot absorb unbounded peer, parser or retry state.
Keep group epochs and fencing because reconnection must not revive obsolete leaders or replay stale volume changes.
Use fixed canonical transport representations because explicit byte order and channel layout avoid heterogeneous-CPU ambiguity.
Admit FEC only after comparing alternatives because repair consumes both playout delay and old-CPU cycles.
Distinguish long music lookahead from short live playout because future live audio does not exist to prefetch.
Use authenticated minimal controls because removing legacy complexity should not introduce unauthenticated actuator control.
Treat integration adapters independently because provider drift must not destabilize the audio kernel or force fleet-wide changes.
Preserve native scope separately from assisted scope because identical UI does not establish identical deployment properties.
Measure analog output timing because packet clocks and software queue depth omit DAC and acoustic pipeline offsets.

## Resource model

For a 320 kbit/s compressed stream, payload consumption is 40,000 bytes per second.
Eight decimal MB stores 200 seconds of that representation before metadata and codec state.
At 48 kHz stereo signed 16-bit PCM, consumption is 192,000 bytes per second.
Eight decimal MB stores about 41.7 seconds of that PCM representation.
Neither calculation proves service prefetch permission, download speed, free RAM or realtime decoding.
One second of stereo PCM occupies 192,000 bytes, making bounded jitter buffering plausible.
Internal per-driver float or 32-bit blocks may consume much more than stereo network PCM.
Track compressed cache, decode queue, resampler history, FEC symbols, sockets, DMA and kernel buffers separately.
Do not sum disk library sizes to estimate RSS; mapped sharing, BSS, heaps and page cache differ.
Admission uses measured worst-case peak plus a stated reserve, not average idle usage.
Every profile declares maximum peers, independent streams, subscriptions, pending commands and parser sizes.
Music and live-video profiles use different latency envelopes, explicitly negotiated by the whole group.

## Critical path and stage exits

Gate A: exact board/image identity, driver contract and kernel capability evidence.
Gate B: minimal Rust platform/runtime in a representative full-system kernel environment.
Gate C: bounded renderer and protocol in a simulated multi-device house with sample-level assertions.
Gate D: exact target footprint/deadline measurements and reviewed human-led activation plan.
Gate E: separately authorized hardware qualification with acoustic protection and return-to-stock evidence.
Gate F: offline combined native-integration candidate; Gate G: externally supplied provider/physical qualification matrix Q06 before release handoff.
An unavailable hardware gate does not block unrelated offline parser, DSP, contract or integration design.
A failed native profile creates a feature-specific blocker; it does not silently relabel gateway mode as native completion.

## Test strategy and evidence levels

Unit: arithmetic, codec, DSP, parser and state-machine invariants with deterministic inputs.
Property/fuzz: hostile packet lengths, queue capacities, clock wrap, invalid calibration and cancellation races.
Virtual-house E2E: packet loss, asymmetry, reorder, partitions, leader failover, reconnect, pause/seek and volume changes.
Full-system guest: actual legacy syscall, libc, CPU/ABI startup and runtime behavior under a matching kernel.
Real service: owner-account provider compatibility; successful simulated service responses do not qualify it.
Hardware: driver ownership, output format, sound level, thermal protection, analog skew and actual radio behavior.
Release: all required lanes tied to exact source revision, artifact hashes, command logs and denominator.
Each receipt records environment, profile, injected fault, expected result, actual result and unresolved limitations.
Logs are bounded and omit raw account credentials, private device identifiers and copyrighted audio samples.

## Rollout sequencing

Start with one admitted roomy speaker-class profile in emulation and one 32 MB profile in parallel.
Do not let the roomy profile hide smallest-device incompatibilities until late integration.
First product milestone is one Spotify program across mixed-generation custom renderers.
Next add deliberate join/leave, volume, loss and recovery qualification.
Then qualify AirPlay, video timing, Tailscale, Alexa, line-in and optional voice individually.
No live rollout occurs from this repository; hand off a precise reviewed runbook to the human-led device process.

## Granular task specifications

Each task below is self-contained in purpose, outputs, acceptance, failure handling and dependency role.
Dependencies refer to stable plan keys; conversion records their actual br IDs.

## Milestones and canonical task keys

M1 is the offline mixed-generation Spotify candidate: Q01/Q02 execution evidence and Q03/U03 human handoff.
Hardware qualification is separately pending until authorized external receipts exist.
M2 is Q04 offline combined qualification, then externally evidenced Q06 and Q05 release handoff; no optional gateway/FEC/local-voice prerequisite.
N05/N06, T03 and X03 are retained optional branches with profile-specific qualification.
The canonical task keys below own completion; R01-R15 and INT-001-018 are mapped design packages, not duplicate issues.
The full runtime and integration specifications follow the task catalog in this document.


### E01 — Reconcile device and firmware identity evidence

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: owner scope, sanitized inventory and existing evidence registry.
Blocks: E02, E03, E04, E05, X03, U02.
Scope: Sanitized board-profile manifest joining model, revision, ISA, ABI, nominal resources, image digest and evidence provenance; private identifiers stay local.
Acceptance: Reject ambiguous mappings; test duplicate identities, changed addresses, missing fields and conflicting historical images; never derive CPU from product era.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### E02 — Measure incumbent resource and dropout baseline

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E01.
Blocks: Q03.
Scope: Offline baseline-analysis schema and human-run baseline recipe; analyze existing captures if available. Missing live measurements remain separate.
Acceptance: Package completion is not baseline measurement. Missing comparison bars quantified improvement claims but permits absolute qualification.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### E03 — Map legacy kernel ABI capability matrix

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E01.
Blocks: E06, P02, P06.
Scope: Per-image kernel version provenance and syscall/ABI probes for timers, poll/epoll, eventfd, futex, entropy, TLS, atomics and process startup.
Acceptance: Run in exact-version full-system guests when available; user-mode QEMU is CPU evidence only; unsupported features return explicit capability failures.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### E04 — Specify retained audio driver ownership and protection

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E01.
Blocks: P04, D02, L01.
Scope: Document ioctl numbers, payload endianness/alignment, mmap/DMA ownership, channel map, rates, drain/mute and amplifier sequencing from permitted evidence. Include retained radio/Wi-Fi driver capabilities, mesh dependencies and scheduler interference in the offline contract matrix; do not assume stock radio behavior survives daemon replacement.
Acceptance: Require artifact anchors; unknown ioctl fields block hardware eligibility; simulator asserts exclusive ownership and no buffer release while DMA owns it. External human qualification must include multicast/unicast, power-save, roam and congestion behavior; no live test here.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### E05 — Qualify boot-hook and rollback semantics offline

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E01.
Blocks: U01, U03.
Scope: Trace Configure.dev/runanacapa/stop marker behavior per image, ordering, permissions, persistence, watchdog and recovery semantics.
Acceptance: Hook presence does not prove writable access or successful startup; fault-injection model covers missing file, failed binary, repeated restart and interrupted configuration write.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### E06 — Audit dependency features and target availability

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E03.
Blocks: P01, S02, T01, P05, P06.
Scope: Pinned per-target dependency/unsafe/license feature inventory for Asupersync, franken_kernel, libc candidates, DSP, codecs and crypto.
Acceptance: Build minimal graph first; inspect transitive std/alloc/native dependencies and floating-point ISA; no dependency admitted solely because its parent crate forbids unsafe.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P01 — Define Rust workspace and build profiles

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E06.
Blocks: P02, D01, N01, P05, P06.
Scope: Workspace specification and later scaffold for franken-speaker, franken-hal, franken-dsp, protocol, session, source adapters and host tools. Define typed secret-store, source-session, command and latency contracts with ephemeral test implementations.
Acceptance: Single shared source with distinct ISA artifacts; reproducible lockfile and target configuration; no binary claimed universal across PPC/MIPS/ARM.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P02 — Implement minimal legacy platform capability layer

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P01, E03, P06.
Blocks: P03, P04, N03, T01, U01, P05.
Scope: Small audited platform boundary with explicit clock, reactor wakeup, socket, memory and entropy capabilities.
Acceptance: No insecure entropy fallback; no fake syscall success; test absent syscalls and interrupted calls; document accept/fcntl concurrency implications. Library changes are allowed: consume the selected upstream portable subset and exact revision; do not infer ABI semantics from a removed cfg guard.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P03 — Bring up bounded Asupersync execution profile

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P02, P05.
Blocks: N02, S01, A01, X03.
Scope: Single-thread cooperative control runtime with bounded tasks, timers, channels and diagnostics; DSP has its own deadline path. Consume the explicit upstream slim runtime profile, including no-atomic64 semantics and finite thread/job caps.
Acceptance: Real target guest markers for spawn/cancel/drain, timers and sockets; measure stack/heap high-water; a stalled task cannot indefinitely own audio resources. Census all threads and allocations before/after first blocking, file, reconnect and cancellation calls. No-thread mode rejects unsupported blocking closures rather than running them inline on the render owner. Bound captured pending-job bytes, not only job count; census between block_on calls as well as startup.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P04 — Implement board HAL adapters and fake-device harness

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P02, E04.
Blocks: D04, X03.
Scope: Typed read/write/control interfaces for each admitted driver ABI with explicit ownership tokens and drop behavior. Device owner retains pool-slot ownership independent of future/token Drop. Expose minimum submission lead and an irrevocable-until presentation cursor, plus bounded acknowledged flush/stop behavior.
Acceptance: Malformed device responses and ioctl errors fail muted; endian golden vectors; deterministic fake hardware and separate true-device qualification ledger. Forget completion futures/tokens, cancel drains, inject stale completions and try slot reuse. Never reuse storage still accessible by the kernel; quarantine remains bounded. A copying-write ABI may avoid shared-memory leases only with explicit evidence. Include destruction of the lease table/device owner itself; table ownership is insufficient if its Drop frees externally referenced storage.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### D01 — Implement fixed-size audio blocks and conversion

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P01.
Blocks: D02, D03, N04, S02.
Scope: Canonical stream format descriptors, channel layouts, sample conversion, saturation and bounded rings.
Acceptance: Bit-exact endian vectors, clipping/NaN handling, queue wrap tests, no allocation in render hot path; representation and bytes-per-frame explicit.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### D02 — Implement board protection DSP

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: D01, E04.
Blocks: D04, G02.
Scope: Per-board crossover/EQ, gain ceilings, limiter, DC rejection, ramp and fault-mute parameter loading.
Acceptance: No generic stereo PCM sent blindly to individual drivers; validate coefficients/stability, malformed calibration and fail-muted unknown board. Existing stability validation also covers admitted realization/quantization, intermediate ranges and nonzero-state profile switches. Board-lifetime thermal/excursion/protection history survives seek, reconnect and source replacement; source-local histories follow an explicit reset/ramp policy.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### D03 — Implement drift correction and resampling

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: D01.
Blocks: D04, N03.
Scope: Bounded clock-rate estimator and resampler with discontinuity handling and state reset by epoch.
Acceptance: Measure quality and CPU on target ISA; deterministic vectors for drift, wrap and clock jump; bounded slew avoids audible pitch steps.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### D04 — Integrate render scheduling with retained HAL

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P04, D02, D03.
Blocks: V01, U03, Q01, Q02.
Scope: Preallocated render loop, driver timestamp accounting and explicit mute/drain lifecycle.
Acceptance: Deadline/underrun counters distinguish missing packets from CPU misses; watchdog path mutes; host simulator is not acoustic proof. Pre-admit cleanup records and buffer ownership before Running; inject allocator failure during start, cancel, drain and reconnect. Logical capacity rejection is distinct from process/kernel OOM; process-death mute remains external qualification.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N01 — Specify and implement authenticated stream framing

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P01.
Blocks: N02, N03.
Scope: Versioned bounded datagram headers with stream ID, epoch, sequence, presentation time, format and payload limits. Define authentication coverage over timing/epoch/format and payload.
Acceptance: Golden wire vectors across endianness; reject oversize, duplicate/replay, stale epoch and unknown critical fields; fuzz parsers offline. Reject mutation before scheduling or DSP; cap untrusted parsing work.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N02 — Implement reliable bounded control channel

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N01, P03, U01.
Blocks: G01, S01, A01, T02, X02, X03.
Scope: Idempotent commands with IDs, expected epoch, acknowledged state revision and authenticated pairing. Own peer key admission/revocation and group-epoch key binding through U01; ephemeral synthetic pairing is allowed only in tests.
Acceptance: No unbounded retry queue; stale leaders cannot alter current group; retries preserve exactly one logical volume/group transition. Check authentication before authority-bearing mutation.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N03 — Implement group clock and synchronized join

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N01, D03, P02.
Blocks: N04, G01, A02.
Scope: Clock probes, offset/frequency fit, future start schedule, uncertainty estimate and muted catch-up. Consume P02 timer resolution/wrap/failure contract, N01 timestamps and D03 sample positions. Produce clock transform, uncertainty, admissible-start deadline and expiry.
Acceptance: Explicit uncertainty threshold; stale timing causes mute/rejoin; test asymmetric delay, leader change, suspend and reboot; no promise from NTP-style offset alone. Reject unadmitted/replayed/stale timing inputs; test asymmetric delays, drift, clock jumps and expiry. Estimator error is not physical DAC skew. Holdover duration is min(buffer coverage, authority validity, clock-uncertainty bound). Inject counter wrap/reset and half-range ambiguity rather than relying on a 24-hour wall-clock run.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N04 — Implement adaptive bounded jitter and concealment

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N03, D01.
Blocks: N05, S03, V01.
Scope: Music and realtime policies with fixed caps, late-packet handling, short-gap concealment and shared latency transitions. Compute consume_by from presentation time minus admitted DSP/conversion work, submission lead and uncertainty. Choose real or concealed output exactly once at consumption cutoff.
Acceptance: Buffer growth never exceeds profile; late packets cannot reorder played audio; source latency changes require group coordination. Recovery before DAC presentation but after consume_by is late. Synthetic deadline vectors must include positive downstream cost and backpressure.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N05 — Evaluate RaptorQ against simpler repair strategies

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N04.
Blocks: N06.
Scope: Reproducible traces comparing plain UDP concealment, deadline-bounded retransmit and FEC by CPU/RAM/latency/loss.
Acceptance: Burst outages longer than repair horizon are explicit failures; validate symbol limits and peak decode memory; promote only a measured winning profile. All strategies use identical consume_by boundaries and bounded work, not merely DAC deadlines; expired repair must not delay the next block.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### N06 — Implement bounded admitted FEC profile

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N05.
Blocks: release readiness and future maintenance.
Scope: Optional capped repair windows and authenticated symbols; reliable control remains independent. Implement only if N05 admits a measured FEC profile; no-FEC outcome keeps this optional capability deferred.
Acceptance: Decline unsupported block sizes; test corrupt symbols, decode overload, adversarial duplicates and packet storms; fallback retains bounded state. Admit a repair job only if its conservative remaining-work bound fits before consume_by; never insert recovered output after concealment committed.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### G01 — Implement unified group membership state machine

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: N02, N03.
Blocks: G02, G03, T03, L01, X04.
Scope: Cross-generation groups, join/leave, coordinator leases, fencing, peer capability admission and selected source ownership. Own shared source arbitration across all adapters with explicit replace/reject policy per command class. First profile uses one configured authority per group incarnation; followers never independently mint a higher valid epoch. Network isolation sacrifices new control availability, not authority uniqueness. Automatic replacement requires a separately specified grant/quorum/lease-expiry protocol before enabling it.
Acceptance: One group epoch across members; partitions never produce conflicting audible programs; group timeout behavior and isolated volume controls are explicit. Concurrent starts/seeks/group changes admit one source epoch. Replaced sources cannot publish. Fault/local mute priority dominates remote unmute. Cutover readiness includes every member's irrevocable old-output tail. Choose qualified drain cutover, acknowledged muted abort/restart, or exclude/abort. Two partitioned followers must not become simultaneous valid leaders. Protection state is not reset with the source epoch. Exclusion or UI removal is not output-stop evidence. Before conflicting output under the same group identity, all prior grant holders, including disconnected/excluded members, must acknowledge stop or pass a bounded output expiry plus irrevocable tail, clock uncertainty and stop/drain lead. Receivers enforce output deadlines including queued samples. Unknown or unenforceable bounds refuse conflicting start. Model assertions cover all prior grant holders, not only current members.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### G02 — Implement volume, mute and channel roles

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: G01, D02.
Blocks: G03, X01.
Scope: Group master volume, per-room trim, stereo L/R/Sub assignments and atomic smooth transitions.
Acceptance: Bound final gains before interpolation; test mute priority, overflow, retries, stale commands and missing members; no volume spikes on reconnect.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### G03 — Implement fsonos compatibility adapter

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: G01, G02.
Blocks: X01, Q01.
Scope: Minimum actually-used SSDP descriptions, SOAP actions and GENA state contracts; use fsonos-proto where suitable. Declare local legacy-SOAP compatibility access policy; tailnet ingress must use authenticated command authorization.
Acceptance: Controller contract tests include subscription renewal/expiry, escaping, topology events and unknown actions; do not reintroduce legacy content catalog.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### S01 — Implement Spotify source capability and session contract

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P03, N02.
Blocks: S03.
Scope: Pinned Spotify client integration profile with secure account storage, discovery, session refresh, disconnect and track transitions.
Acceptance: Premium/account conditions explicit; no credential export in logs; provider failure is separate from renderer failure; actual service tests remain owner-account qualified.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### S02 — Qualify negotiated source-codec profiles

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: D01, E06.
Blocks: S03, A02.
Scope: Bounded pure-Rust codec selection with malformed-input caps, seek/gapless semantics and exact target benchmark. Derive mandatory decoder set from pinned Spotify/AirPlay negotiated formats; keep optional internal transport codec separate.
Acceptance: Measure worst-case CPU, stack, heap and samples; codec name or source code existence does not prove old-CPU realtime support. Unsupported negotiated formats fail explicitly; no Vorbis-only provider assumption.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### S03 — Implement Spotify cache and source placement

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: S01, S02, N04, U01.
Blocks: Q01, X04.
Scope: Bounded compressed lookahead and decoded playout queues with endpoint-native and optional coordinator profiles.
Acceptance: State seconds and bytes separately; fetch duration depends on provider and link; eviction never writes secrets; no guaranteed three-minute fetch in two seconds. A successful seek/skip is not acknowledged until old submitted output is drained or qualified flush/mute is acknowledged at the agreed boundary; old ingress rejection alone is insufficient.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### A01 — Specify native AirPlay2 discovery and pairing

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P03, N02.
Blocks: A02.
Scope: Service identity, pairing/authentication, advertised room/group mapping, crypto dependencies and protocol-version compatibility matrix.
Acceptance: No false service capability advertisements; test bounded discovery churn, identity persistence and pairing reset; distinguish AirPlay1 from AirPlay2.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### A02 — Implement AirPlay audio timing and decoding

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: A01, S02, N03, U01.
Blocks: V02, Q04.
Scope: AAC/ALAC capability profiles, timing mapping, buffer negotiation and authenticated receiver sessions.
Acceptance: Protocol test captures must be authorized and scrubbed; source-provided timing and render offset tested separately; native renderer scope not satisfied by gateway alone.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### V01 — Implement end-to-end latency ledger

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: D04, N04.
Blocks: V02, L01.
Scope: Measured ingress/decode/FEC/queue/DSP/DMA timeline with uncertainty and fixed-vs-variable offset accounting.
Acceptance: Never double-count overlapping pipeline stages; validate against known injected delays and monotonic clock transforms.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### V02 — Implement source-aware video synchronization

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: V01, A02.
Blocks: Q04.
Scope: AirPlay source compatibility matrix and optional desktop/browser helper that can delay video for synchronized audio.
Acceptance: Qualify seek/pause/rate/route changes per source; unsupported app reports limitation; no automatic universal iPhone YouTube guarantee.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### T01 — Qualify native Tailscale protocol and resource profile

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E06, P02.
Blocks: T02, T03, T04.
Scope: Endpoint identity/control registration/discovery/NAT/relay/key rotation feasibility beyond WireGuard encryption alone. Own docs/tailscale/feasibility.md, docs/tailscale/profiles.json, tests/tailscale-fixtures/ and toolchain/results/tailscale/. Record provisional per-target budget if combined headroom has not been measured; provisional development admission belongs to T04; final native qualification remains pending until Q06 evidence. Produce docs/contracts/t01.md candidate table with pinned revisions, protocol scope, kernel/ISA requirements, Rust/FFI boundary, measured resources where executable and exact blockers otherwise.
Acceptance: Exact legacy ISA build and memory/CPU measurements; assess official client versus Rust implementation honestly; gateway route is separately named. Synthetic identity/network-map/relay/key-expiry fixtures only. A reproducible negative feasibility result closes investigation but leaves T02/native requirement blocked. No Go reference client or gateway counts as strict-Rust native implementation. Closing a negative study does not close T04. T04 is provisional development admission; full native qualification is a separate Q06 result after implementation and combined tests.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### T02 — Implement native tailnet endpoint integration

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: T01, N02, U01, T04.
Blocks: Q04.
Scope: Admitted client profile with ACL enforcement, key rotation, identity lifecycle, diagnostics and remote control routing.
Acceptance: Test denied access, expired identity, relay fallback, offline control and key rotation; local audio does not depend on WAN/tailnet control availability. Start from T04's positive provisional candidate or bounded upstream-adaptation decision. Restrict initial native tailnet exposure to explicit authenticated control services; proxy/gateway identity is not native identity.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### T03 — Implement optional redundant gateway service mode

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: T01, G01.
Blocks: release readiness and future maintenance.
Scope: Explicit user-visible gateway-assisted mode with fencing and stable room service identities.
Acceptance: Gateway identity is not native identity per speaker; test split brain, stale routes, failover and no accidental LAN exposure.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### X01 — Specify Alexa command and music-destination capabilities

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: G02, G03.
Blocks: X02, X04.
Scope: Separate local discovery/control, cloud skill bridge, music destination/provider authorization and group naming.
Acceptance: No assumption Hue/UPnP/Matter equivalence; enumerate supported commands and source authentication; microsecond latency is not claimed for cloud voice.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### X02 — Implement Alexa control integration

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: X01, N02.
Blocks: Q04, X04.
Scope: Authenticated command adapter, discovery, state reporting and idempotent group/volume/mute actions.
Acceptance: Test replay, duplicate voice delivery, ambiguous room name, unavailable group and revoked account; distinguish acknowledgement from audible execution.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### X03 — Qualify optional local voice on supported microphone boards

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E01, P04, P03, N02.
Blocks: release readiness and future maintenance.
Scope: Microphone/echo-cancellation ABI and franken_whisper compute/privacy feasibility; host-assisted option documented.
Acceptance: No assumption all One variants have identical mic arrays; explicit recording indicator and no retention by default; CPU budget cannot starve audio.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### L01 — Implement line-in capture and synchronized distribution

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E04, V01, G01.
Blocks: Q04.
Scope: Capture HAL, source timestamps, feedback-loop prevention and music/realtime group policies.
Acceptance: Measure ADC-to-DAC latency; audio capture clock drift accounted; unavailable inputs fail clearly; claimed 15 ms remains benchmark target only.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### U01 — Implement minimal persistent state and calibration custody

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P02, E05.
Blocks: N02, S03, A02, T02, U02.
Scope: Small versioned crash-consistent settings journal; selective frankenfs algorithm reuse with wear/write limits. Separate credential namespaces and calibration; define replacement/revocation, permissions, secret-redacted errors, bounded capacity/write rates and crash consistency. Persistence does not imply encryption or hardware-backed custody. Define record schema, publication state machine, bounded scanner and old/new-state recovery oracle; tombstone generations prevent normal recovery resurrecting revoked identities.
Acceptance: Power-cut fault simulation across every publication step; no full filesystem stack dependency by default; preserve calibration separately. Inject failures before/after each write/sync/publication and torn-record boundary: recover complete old or new value, never mixed credentials/calibration. Test capacity, checksum, malformed length, schema, failed sync and revocation. Physical rollback resistance remains separate.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### U02 — Implement signed staged artifact/update design

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: U01, E01.
Blocks: U03.
Scope: Per-board manifests, artifact verification, anti-rollback policy and offline activation/rollback models.
Acceptance: A/B only where capacity proven; factory trust boundary distinct from our signing scheme; no vendor bypass implied.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### U03 — Specify reversible userspace activation handoff

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: E05, D04, U02.
Blocks: Q03, Q05.
Scope: Human-led activation runbook with exclusive stock/custom audio ownership, rollback trigger and qualified watchdog behavior.
Acceptance: Planning output only here; no runtime hook changes; verify rootfs unchanged does not mean JFFS or running-device risk absent.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q01 — Build offline end-to-end virtual house harness

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: G03, S03, D04.
Blocks: Q02.
Scope: Multiple mixed-profile renderers on virtual clock with controllable network/clock/device faults and structured receipts.
Acceptance: Check samples and state, not log strings alone; separate unit/mock simulation from full-system and hardware evidence. Race two real adapter interfaces replacing sources and retrying relative volume; assert sample/state revisions.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q02 — Qualify footprint and deadline budgets

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: Q01, D04.
Blocks: Q03.
Scope: Per-target link map, compressed/uncompressed image sizes, peak resident set, stacks, DMA, allocator fragmentation and deadline percentiles.
Acceptance: Sweep concurrent controls and hostile inputs; no 1.15 MB/2.8 MB/19 MB headroom claim without exact artifact measurements. No-FEC is valid for baseline. Repeat with each enabled optional profile.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q03 — Define owner-run acoustic and network qualification

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: Q02, U03, E02.
Blocks: Q04, Q06.
Scope: Instrumented mixed-generation Spotify soak, output skew measurement, loss/roam/rejoin matrix and return-to-stock criteria.
Acceptance: Live execution belongs human-led external process; analog measurements required for sub-sample claims; capture duration and test denominator explicit. Baseline Spotify, volume, joins, source restart, loss envelope and rollback. Declare thresholds before execution. Report absolute vs comparative evidence separately.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q04 — Qualify offline combined native-integration candidate

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: Q03, T02, X02, X04, A02, V02, L01.
Blocks: Q05, Q06.
Scope: Native and assisted profiles labeled separately across Spotify/AirPlay/video/Alexa/Tailscale, independent groups and recovery. This is an offline software/guest combined campaign; real provider and physical receipts belong to Q06 and X05.
Acceptance: No feature silently removed when optional assistance used; document unsupported combinations and exact reproducible acceptance receipts. Gateway and FEC qualification are conditional on enabled profiles; optional absence neither closes nor blocks native requirements. Repeat combined peak memory/CPU/deadline qualification with all enabled native services simultaneously, pairing/reconnect/key rotation and background control load. Repeat source arbitration for each adapter. Isolated component success is insufficient. Missing external receipts do not block this offline campaign, but prevent native release eligibility. Distinguish enabled native control-plane residency from simultaneously active audio sources; only one admitted source per group.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q05 — Produce release and maintenance handoff

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: Q04, U03, Q06.
Blocks: release readiness and future maintenance.
Scope: Versioned per-board compatibility/support table, key rotation policy, rollback documentation and regression corpus.
Acceptance: No production declaration from guest-only tests; release evidence pins exact sources/toolchain/artifacts; retain unresolved optional voice qualification. Release eligibility requires the complete artifact-bound Q06 evidence matrix, including pair/Sub-specific criteria when enabled; software task closure alone cannot advertise native or hardware-qualified capability.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### X04 — Implement offline Alexa voice-to-Spotify routing contract

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: X01, X02, S03, G01.
Blocks: Q04, X05.
Scope: Supported music-destination/account-routing integration with explicit provider admission and target group selection.
Acceptance:  Offline supported-mechanism specification, account/group routing adapter and positive/negative directive fixtures pass. If provider admission is unavailable, label the adapter unqualified. This software task never establishes actual voice-to-playback success; X05 owns external proof and remains open until received.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P05 — Adapt Asupersync upstream for bounded legacy runtime profiles

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P01, P02, E06.
Blocks: P03.
Scope: Own changes in the Asupersync repository: real minimal module/dependency feature gates; semantic replacements for unavailable AtomicU64; explicit worker/blocking/job/stack caps; pre-admitted cleanup records. Keep structured concurrency and cancellation contracts.
Acceptance: Stable target feature graphs for BE PPC/MIPS compile or report exact blockers; thread-local u64 is allowed only for local state, shared fallbacks preserve atomic semantics and stay off render deadlines. No silent u32 truncation or naive split-word atomics. Saturation/allocator-failure/cancel/drain tests plus guest receipts required; cfg metadata is not runtime proof.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### P06 — Extract and adapt portable Franken support-library subsets

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: P01, E06, E03.
Blocks: P02.
Scope: Own selected upstream franken_kernel/frankenlibc/frankenfs/franken_remote adaptations. Publish pinned feature and unsafe/FFI inventory; factor alloc/std/host-only dependencies; port only selected platform primitives or use semantic references behind a small adapter, without importing full desktop/filesystem stacks.
Acceptance: Each selected primitive has BE layout, errno, time-width, syscall/TLS and target tests as applicable. Removing an architecture compile_error alone is not a port. Resolve differing Asupersync pins explicitly. Portable parsers/settings algorithms may be extracted without claiming raw-flash/filesystem support; LocalAPI delegation is not native Tailscale.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### T04 — Admit a native tailnet development candidate per target profile

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: T01.
Blocks: T02.
Scope: Machine-readable positive provisional development decision keyed by exact target, candidate revision and adaptation strategy. Separate source availability, offline feasibility and final native interoperability. A bounded owner-authorized upstream implementation may be the selected strategy.
Acceptance: Negative T01 leaves this gate open and T02 blocked. Positive decision names required native identity/control/data-plane behavior, unresolved limits and next discriminators; it does not assert final resource fit or interoperability. Graph fixture verifies negative study closure cannot clear this independent gate.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### X05 — Validate externally supplied Alexa music-routing qualification evidence

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: X04.
Blocks: Q06.
Scope: Consume authorized external receipts for supported provider admission and utterance-to-selected-group playback. No enrollment, voice request or device command is executed from this repository. Validate receipt identities and feature scope.
Acceptance: Remain open when receipts or supported provider mechanism are absent. Offline fixtures and volume/mute success cannot close this gate. Positive/negative/revocation/source-change outcomes and exact software/profile identity required; reject stale or unrelated artifacts.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.


### Q06 — Validate external native-service and physical qualification gates

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: Q04, Q03, X05.
Blocks: Q05.
Scope: Validate imported owner-authorized provider/hardware evidence against exact build/profile capability ledger: Spotify, native AirPlay2/Tailscale, Alexa, source-specific video, line-in and mixed-generation audio. Record candidate, offline, combined, provider and physical levels independently.
Acceptance: Remain open until every required capability in the frozen owner-approved profile, independent of implementation enable flags has matching receipts; no device/provider execution here. Stereo/Sub roles need their own phase/polarity/crossover/delay criterion and evidence, not the room skew band. Stale code/profile/calibration invalidates affected evidence. Optional unsupported features are explicit; no silent native-to-assisted substitution. Disabling an unimplemented required feature cannot remove it from the required set; only explicitly optional features can be absent without blocking.
Implementation authority: offline code/tests/design only in this repository; human-led hardware work is a separate handoff.
Background: retain stock kernel/driver knowledge while replacing unnecessary playback-service complexity.
Feature rule: native capabilities remain distinct from coordinator-assisted equivalents.
Safety boundary: application/protocol/DSP forbid unsafe; any platform exception requires an explicit invariant and reviewer.
Resource rule: bound memory, work per input and queued effects; report maximum tested values.
Evidence rule: attach exact source/artifact identity and command receipts; do not promote mocks to live compatibility proof.
Failure contract: typed failure must identify the unavailable capability and preserve a muted or unchanged state where output is affected.
Test ownership: this task owns focused unit/property/contract tests; shared integration harness tasks consume its contract.
Logging: structured event, profile, state transition and bounded diagnostic; no secrets or site identifiers.
Concurrency: edit only the task's owned files; preserve concurrent work and respect dependent task contracts.
Completion: implementation, focused checks and documentation agree; pending hardware/provider qualification is separately marked.
Reversal: if acceptance cannot be met, record the measured discriminator and revise the affected profile without dropping the user requirement.
Do not close on: a design sketch, compiled hello-world, successful command submission or inherited peer claim alone.



# Detailed specification: SLIM_RUNTIME_DESIGN.md

# Slim runtime, audio transport, and retained-driver design

Status: proposed implementation specification, not built firmware.
This document specifies the runtime portion of the slim-speaker plan.
The owner wants reliable Spotify, unified groups, volume, AirPlay, video sync,
native Tailscale, and Alexa without historical Sonos feature parity.
The selected direction is a small Rust userspace over retained kernel drivers.
Native integrations remain product goals; host assistance is an explicit profile.
An assisted profile must never be advertised as an endpoint-native implementation.
All activities specified here execute offline in this repository.
Hardware activation belongs to the separately authorized human-led process.

## 1. Evidence and meaning of compatibility

The current assessment records PowerPC and MIPS big-endian ELF artifacts.
A single source workspace can serve both architectures.
One identical executable cannot execute on incompatible instruction sets.
Produce separately identified binaries with a shared protocol and behavior.
A model number alone is insufficient to select a binary or calibration profile.
An ELF minimum-kernel annotation is insufficient to identify the running kernel.
A successful generic QEMU boot is insufficient to qualify a Sonos board.
A retained stock driver is a compatibility resource, not a memory-safety proof.
The trusted computing base includes that kernel, driver, toolchain, and firmware.
New application, protocol, and DSP crates must forbid unsafe Rust.
A minimal platform adapter may contain reviewed unsafe operations.
Every such operation needs an invariant and a testable safe interface.

The following peer numbers are targets or hypotheses, not baseline facts:

- A 1.15 MB speaker executable.
- A 2.8 MB runtime memory footprint.
- Nineteen MB of remaining memory on a 32 MB device.
- Three minutes of buffered Spotify within two seconds of starting playback.
- Twenty milliseconds of end-to-end video latency.
- Fifty microseconds of inter-speaker analog output skew.
- A universal fifteen-percent packet-loss recovery capability.
- A zero-risk deployment path based on a boot hook.

A file's disk size does not establish its resident memory use.
Allocated memory is not the same as resident memory, free memory, or peak RSS.
Compressed-stream lookahead is not the same as decoded audio buffering.
Dropping codecs may reduce footprint without changing the actual dropout cause.
The implementation must measure these distinctions rather than repeat estimates.

## 2. Proposed crate responsibilities

`franken-speaker` is the executable and composition root.
It selects a board profile, validates configuration, and supervises sessions.
It does not contain raw ioctl layouts or codec algorithms.
It owns admission control and exposes observable lifecycle states.

`franken-hal` contains safe audio and clock interfaces.
Its platform-specific implementation translates the admitted driver ABI.
Its offline backend supports deterministic lifecycle and fault testing.
Its interfaces make buffer ownership and device exclusivity explicit.

`franken-dsp` contains sample conversion, routing, volume ramps, and filters.
It accepts bounded blocks and never performs network or filesystem operations.
It distinguishes transport channels from physical loudspeaker channels.
It validates finite coefficients and rejects profiles with invalid topology.

`franken-stream` contains framing, sequencing, jitter buffering, and FEC policy.
It has fixed ceilings on packet length, active blocks, and repair work.
Its output is a timestamped block or an explicit missing-block decision.
It has no authority to change volume or hardware routing.

`franken-clock` estimates offset, drift, uncertainty, and presentation mapping.
It does not represent a network timestamp as an exact DAC timestamp.
It exposes confidence sufficient for group admission and degraded operation.
It supports replay under synthetic time without reading the wall clock.

`franken-session` defines epochs, leases, group transitions, and source ownership.
It has no dependency on a particular Spotify or AirPlay implementation.
It serializes group-affecting operations through one state owner.
It rejects stale commands even when packets arrive out of order.

`franken-control` adapts the required fsonos SOAP/GENA contract.
It implements a bounded subset selected from actual controller calls.
Unsupported actions return explicit protocol faults.
It does not instantiate a general document database or media-library indexer.

`franken-platform` contains the small system-call and allocation boundary.
It centralizes differences in kernel capabilities and target ABIs.
It is the only userspace crate permitted to reach raw device handles directly.
Its code-size and unsafe inventory are reviewed separately from application code.

Native service adapters are independent feature sets.
Spotify, AirPlay, Tailscale, and Alexa must not become mandatory dependencies
of the minimal synchronized renderer or of each other.
Feature separation permits measured per-board profiles without protocol splits.

## 3. Board profile contract

A board profile is data with a version and an integrity digest.
Its identity binds the executable target to a supported hardware revision range.
It names the CPU ISA, endianness, ABI, float ABI, and required atomic widths.
It names the kernel capability profile, not just a nominal kernel version.
It names the audio-device ABI and required driver version or digest evidence.
It defines supported transport sample formats and hardware output formats.
It defines hardware channel count and channel-to-driver routing.
It defines mute control, safe startup order, and fault-state behavior.
It defines calibrated delay and the uncertainty of that calibration.
It defines thermal and output limits only where justified by evidence.
It defines permitted buffer sizes, alignment, and queue-depth measurement methods.
It names persistent-state paths through a platform abstraction.
It must not embed private device identifiers in public fixtures.

Unknown profiles are rejected before opening an output device.
A generic fallback may decode into an offline sink, never enable an amplifier.
A mismatched calibration profile is not automatically converted or approximated.
Profile migration must preserve original metadata for rollback.
Unsigned development profiles are allowed only in offline test configurations.
Production profile admission is a distinct policy decision in the update design.

## 4. Legacy kernel and ABI feasibility gate

The first executable experiment is a small capability probe, not the full stack.
The probe must record its target triple, compiler version, linker, and libc.
It must record the guest kernel identity and the provenance of that guest.
The probe reports each result independently instead of one broad pass status.
It must exit nonzero when a required capability is absent or ambiguous.

Probe the following capabilities before importing the full executor:

- Static executable entry and environment initialization.
- Monotonic clock availability and observed resolution.
- Timer wakeup behavior under repeated interrupts.
- File-descriptor readiness for sockets and audio-like character devices.
- Nonblocking reads and writes with partial completion.
- Socket creation, bind, send, receive, and truncated-datagram reporting.
- Poll or epoll functionality admitted by the selected platform profile.
- Reactor wakeup using an explicitly supported mechanism.
- Signal delivery and shutdown handling.
- Supported thread creation and thread-local storage, if threads are required.
- Atomic operations actually used by the selected dependency graph.
- Allocator alignment, failure behavior, and peak-memory reporting.
- Secure entropy availability through an admitted provider.
- Filesystem sync and atomic rename behavior needed for configuration.
- Appropriate handling of absent syscalls without startup abort.

The retained-kernel profile must name which features require threads.
Do not add threading merely because a desktop runtime defaults to a thread pool.
If only a single-thread executor is feasible, concurrent I/O remains possible.
CPU-heavy decode and FEC still require explicit time budgeting on that thread.
A single-thread configuration does not make blocking calls harmless.

Modern Linux user-mode emulation exposes the host's system-call behavior.
It can test executable ISA correctness but not an old kernel contract.
Use a matching full-system guest where a reproducible kernel is available.
If no matching guest exists, record compatibility as unqualified.
Do not mark retained-driver behavior validated with a substitute fake driver.
The substitute is useful for the safe interface contract only.

A libc shim is not a blanket solution to missing kernel semantics.
Emulating accept flags with accept plus fcntl can introduce races.
Emulating secure randomness with a deterministic generator is unacceptable.
Emulating a monotonic clock with wall time changes the timing contract.
Every fallback needs its own capability declaration and failure policy.
FrankenLibC reuse is admitted function-by-function after target review.

The owner authorizes upstream changes to Asupersync and all Franken support libraries.
Current limitations are specific portability work, not immutable exclusions.
Selected stable PPC/MIPS target metadata lacks atomic64; classify each shared u64 by semantics.
Keep local counters owner-local, preserve synchronized shared state through admitted fallbacks,
and never truncate timestamps/identities or substitute naive split-word shared reads.
A runtime-core marker is insufficient unless it actually excludes host modules/dependencies.
Audit the exact pinned dependency graph; sibling HEAD inspection does not qualify another Git pin.
A reviewed capability manifest is an inventory and test input, not a promise that dependency scanning discovers every dynamic syscall.

## 5. Asupersync integration

Use Asupersync for session supervision, control I/O, and cancellation ownership.
Retain its region ownership rather than creating detached background tasks.
Define regions for device lifetime, control sessions, streams, and update staging.
A stream region owns ingress, decode, packet recovery, and telemetry tasks.
The audio output owner outlives the stream until drain or safe stop completes.
Cancellation must not free memory still referenced by the kernel or DMA.
A region closing successfully means its software obligations ended.
It does not establish that external hardware has stopped without HAL evidence.

The production runtime needs a minimal target feature profile.
Read the actual dependency graph and record native dependencies that remain.
A feature named runtime-core is not proof that the build excludes all I/O stacks.
Do not include SQL, web frameworks, or desktop telemetry by default.
FrankenKernel type reuse requires validating its transitive no_std/alloc choices.
No_std is not the same as no allocation or small binary size.

Asupersync cancellation budgets are not hard preemption or heap limits.
Enforce memory ceilings at allocation and admission boundaries.
Enforce work ceilings by processing bounded packet and codec units.
Audio deadline handling must not depend on a cooperative task eventually yielding.
The rendering path must have a separately measured execution budget.
A blocked management request cannot hold the render owner's lock.

Use bounded channels with a documented capacity and overflow policy.
Control commands requiring a response must not disappear silently.
Telemetry may drop older samples with an explicit dropped-count metric.
Audio queues advance according to presentation time rather than queue fullness.
Backpressure must never cause old audio to accumulate without a deadline.
Reserve-and-commit APIs are useful where cancellation could lose ownership.
No public request may allocate an unbounded number of tasks or regions.

An explicit slim Asupersync profile owns every worker, helper thread, blocking-job queue and stack cap.
The current_thread preset is not a no-thread guarantee; audit background and blocking workers.
A no-thread profile rejects forbidden blocking operations rather than executing them inline on the renderer.
Pre-admit task/future, cleanup and finalizer capacity before Running; ordinary admission cannot consume stop capacity.
A lifetime arena is a candidate: recycle only after region drain AND HAL completion, with allocation-failure tests.
Quota exhaustion, allocator abort and process/kernel OOM are different failures; only the first two modeled paths
can be reasoned about here, and actual process-death hardware mute remains externally unqualified.

## 6. Audio ownership and HAL API

The proposed HAL state machine is Closed, Prepared, Running, Draining, Faulted.
Only one owner can move the hardware instance out of Closed.
Preparing validates profile, buffer geometry, format, and output limits.
Preparing must not imply that audible output has been enabled.
Running starts only after a valid presentation mapping and safe gain are installed.
Draining retains buffer ownership until the driver confirms completion or stop.
Faulted requires a safe mute request and captures the fault code.
A recovery operation cannot silently clear a persistent hardware fault.

The safe interface needs operations equivalent to these contracts:

- Query capabilities without changing audio state.
- Acquire exclusive ownership or return a typed busy error.
- Prepare format and buffers while maintaining mute.
- Submit a bounded block with an explicit frame count.
- Query consumed/presented frames with an uncertainty classification.
- Request start at an admitted hardware/software boundary.
- Set a bounded ramp or safe gain state.
- Request graceful drain with an upper wait bound.
- Abort into mute and return whether hardware acknowledgment was obtained.
- Release only after all outstanding buffer leases are accounted for.

The exact driver calls are not specified until the ABI is mapped.
Possible write, ioctl, mmap, or shared-ring interfaces must be distinguished.
Opaque ioctl numbers require argument size, signedness, and endian documentation.
Structures must not use Rust's unspecified default layout at an ABI boundary.
Pointer lifetime and kernel access duration must be included in the safety proof.
Driver-returned lengths and counters are untrusted input to the safe wrapper.
A counter wrap must not become an enormous buffer index.

The first tests use an offline model of the contract.
The model injects short writes, delayed completions, wraparound, and device loss.
Hardware qualification remains a separate evidence row owned by the human lane.
The model cannot establish amplifier sequencing or electrical behavior.

HAL buffer lifetime must tolerate safe callers forgetting futures or completion tokens.
The device owner retains pool-slot ownership; a forgotten token cannot return kernel-visible storage.
Destruction of that owner/table must also preserve outstanding kernel ownership; moving a buffer into a table alone is not a lifetime proof.
Quarantine lost completions within a fixed slot cap; a qualified copying-write ABI may avoid shared DMA leases.
Expose minimum submission lead, clock uncertainty and the irrevocable-until output cursor.
Stop-requested is distinct from acknowledged flush/drain completion, especially during partial writes.

## 7. Render path and DSP

The render path processes a fixed maximum number of frames per invocation.
Its scratch memory is allocated before entering Running.
It does not allocate, resolve DNS, read files, or emit blocking logs.
It must tolerate zero-length and final partial blocks without indexing errors.
A panic in rendering is a process failure, not an acceptable concealment method.
Every arithmetic operation involving lengths uses checked conversions.

The initial input format is a negotiated canonical PCM representation.
Wire sample endianness is explicit and independent of host CPU endianness.
The first implementation may choose one sample rate for the entire group.
Additional rates are admitted only with a defined transition and resource test.
Internal DSP precision is selected by measured accuracy and CPU cost.
Fixed point and floating point are candidates, not ideological requirements.
A soft-float target must not silently inherit expensive floating-point assumptions.

Processing order is explicit:

1. Validate block identity and presentation window.
2. Convert sample representation without reinterpreting unaligned pointers.
3. Apply drift correction/resampling in a bounded work unit.
4. Select stereo, mono, Sub, or individual-driver routing.
5. Apply board-specific crossover and equalization.
6. Apply user gain and calibrated trims with smooth ramps.
7. Apply justified output protection and clipping policy.
8. Convert to the driver-admitted output format.
9. Submit to the device owner and record frame accounting.

This order may change only with audio-quality justification and updated fixtures.
A Sub route receives the agreed bass-management signal, not arbitrary stereo data.
A tweeter route must never receive unfiltered full-range output by default.
Missing DSP calibration disables audible activation on that board profile.
Retained driver protection cannot be presumed to implement all stock DSP behavior.
Factory data may parameterize behavior only after its meaning is established.

Volume has three concepts: user value, acoustic gain, and protection-limited gain.
Expose the user value consistently while reporting active limiting separately.
A group volume change preserves per-member trims unless explicitly reset.
Mute is a ramp to silence followed by the admitted safe device state.
Unmute never bypasses profile validation or restores an out-of-range gain.
A codec or transport error must not become a full-scale sample burst.

In addition to the existing stability requirement, validate the admitted filter realization under quantization,
including coefficient/intermediate-state ranges and nonzero-history profile transitions.
Keep device protection history alive across seeks, reconnects and source changes; reset only under a justified board policy.
Source-local decoder/filter/resampler histories have separately specified reset/ramp rules.
A final clipper alone does not prove thermal/excursion safety or numerical stability.

## 8. Stream identity and framing

Every stream has a random session identity generated from admitted entropy.
Every group transition has a monotonically ordered epoch within its authority.
A packet includes protocol version, stream identity, epoch, sequence, and timestamp.
It includes codec/PCM format identity and the bounded payload length.
Repair packets also identify their coding block and symbol position.
Authentication covers the header fields used to route or allocate resources.
Reject lengths before allocating payload storage.
Reject unsupported versions with a bounded diagnostic response.
Ignore stale epochs without modifying the current stream.
Duplicate packets do not advance the playout cursor twice.
Packets beyond the admissible future window are discarded and counted.

Do not serialize native structs directly onto the wire.
Integers use an explicit byte order and documented maximum values.
Timestamp units, epoch origin, wrap rules, and clock domain are part of the protocol.
A packet timestamp refers to a defined frame boundary, not receipt time.
Frame count must be derivable and checked against payload length.
Codec framing must identify discontinuities and reset points.

Separate reliable control from deadline-constrained media delivery.
Control may retry idempotently using command identifiers.
Media retransmission is allowed only when the remaining deadline permits it.
A successful network send does not mean a receiver admitted or played the block.
Receiver reports distinguish received, recovered, decoded, queued, and presented.

## 9. Buffer allocation and accounting

Use one memory ledger for every feature profile and board class.
Account for text/data mappings, stacks, allocator metadata, and fragmentation.
Account for kernel buffers and driver allocations separately from process RSS.
Account for decoder state, repair matrices, crypto state, and pending handshakes.
Account for both peak transition memory and steady-state playback memory.
Do not count a buffer twice merely because two layers reference it.
Do count a copied representation when a layer retains its own copy.

Define separate queues for compressed lookahead and decoded playout.
Compressed lookahead may be long when a source permits fetching future media.
Decoded playout is sized for the chosen latency and loss envelope.
Live line-in and interactive video cannot supply future audio in advance.
A seek invalidates buffered content from the preceding timeline.
A service may limit prefetch or change content availability.
The system therefore must not promise a universal prefetch completion time.

For illustration, 48,000 frames/s times two channels times two bytes is 192,000 B/s.
A one-second stereo PCM queue therefore contains 192,000 payload bytes.
At 320,000 bits/s, 180 seconds of compressed content contains 7,200,000 bytes.
Fetching that content in two seconds requires at least 28.8 Mbit/s of payload.
These are arithmetic bounds, not observed throughput or service permission.
An eight-MiB buffer has substantially different durations for PCM and compression.
All user-facing buffer duration estimates must use the actual representation.

Memory admission occurs before changing the active stream configuration.
If a requested profile does not fit, return a typed capacity error.
Never evict the active render buffer to make room for a new login handshake.
Prioritize continuous playback over optional metrics or background updates.
Persist a small bounded summary rather than retaining unlimited diagnostic history.
An out-of-memory path must fail into bounded silence or reject new work.

## 10. Packet recovery and FEC

RaptorQ is a candidate recovery mechanism behind a bounded transport interface.
Its benefit depends on repair overhead, block size, loss pattern, and deadlines.
A fifteen-percent random loss result does not establish burst-loss tolerance.
A microwave outage can erase an entire coding window.
FEC cannot recover a block without enough independent received information.
Recovery CPU and memory are charged to the same resource ledger as decoding.

Compare three transport profiles on identical recorded loss schedules:

- PCM or codec frames with concealment and no repair.
- Deadline-aware selective retransmission with bounded outstanding requests.
- Bounded FEC plus optional retransmission only within remaining slack.

Use the same content, packetization, delay distribution, and output deadline.
Report useful payload, overhead, late output, CPU, and memory for each profile.
Do not compare one system's long latency with another system's short latency.
A profile is selected per session and changed only through a group transition.
Receiver feedback is aggregated to prevent fleet-sized feedback storms.
A receiver cannot force unlimited repair computation or packet amplification.

FEC block authentication precedes expensive recovery where feasible.
Malformed coding metadata must fail within a fixed resource ceiling.
Coding symbols from different streams or epochs cannot be combined.
Derive consume_by(frame) = presentation time minus admitted downstream processing, device submission lead and uncertainty guard.
Repair must finish by consume_by, which is earlier than physical presentation; use conservative work bounds.
Choose real or concealed output exactly once at that cutoff; discard later repair even before DAC presentation.
A repair that cannot finish in remaining slack is not scheduled and cannot starve the next frame.
A late recovered frame must not rewind the device's sample clock.

## 11. Clock synchronization

The group protocol maintains a mapping from source frames to presentation time.
Each endpoint estimates offset and frequency error against the selected clock.
The estimate includes uncertainty and observation age.
Network asymmetry may bias an estimate even when packet round-trip time is small.
Clock samples with excessive delay or implausible jumps are rejected.
A new leader cannot instantly inherit the old leader's timestamp interpretation.

Use a monotonic local clock for scheduling and elapsed durations.
Wall-clock adjustments do not change the current audio timeline.
Source timestamps must be converted into the admitted group clock domain.
An endpoint's oscillator drift is corrected gradually within a bounded ratio.
A large discontinuity invokes a rebuffer/rejoin transition rather than extreme resampling.
The render engine records the effective resampling ratio and accumulated correction.

Clock alignment and audio alignment are different measurements.
Audio alignment includes decode delay, resampler delay, DSP delay, and DMA depth.
Board-specific calibrated delay must be part of the presentation mapping.
A driver queue-depth estimate must report whether it is exact, sampled, or inferred.
Unknown DAC pipeline delay prevents a claim of exact analog alignment.
A fifty-microsecond target is a test objective requiring analog measurement.
At 48 kHz, one sample lasts approximately 20.833 microseconds.

Stereo pairs and Sub bindings may have tighter admitted skew than room groups.
Define separate acceptance bands rather than one unsupported universal guarantee.
The provisional room-group baseline is p99 <= 2 ms and maximum <= 5 ms electrical-output skew after lock.
One millisecond p99 is a separate stretch objective; it does not override the baseline.
The versioned QUALIFICATION_TARGETS contract defines the campaign and measurement boundaries.
That objective remains provisional until measurements establish perceptual adequacy.
A stricter pair/Sub objective must be set with acoustic and hardware evidence.
Every timing report includes sample count, duration, percentile, and worst case.

Holdover is bounded by min(buffer coverage, authority validity, growing clock uncertainty).
Inject counter rollover/reset and half-range ambiguity in synthetic tests: u32 frames at 48 kHz wrap near 24.86 hours,
so a 24-hour soak alone misses that boundary. This is a test vector, not an assertion of actual driver counter width.

## 12. Group and membership state machine

A group consists of members, a source owner, a clock authority, and an epoch.
A membership proposal does not immediately alter audible output.
New members validate format, buffer resources, and clock confidence first.
The authority proposes a future cutover frame and gathers readiness acknowledgments.
A commit activates the new membership at that frame.
A missing acknowledgment produces an explicit exclusion or abort policy.
Do not hold all existing members indefinitely for one unreachable device.

Joining a playing group starts from the group's current timeline.
It does not replay a cached beginning or independently start a track.
Leaving a group ramps out at a coordinated boundary where possible.
A failed member may stop locally without stopping all healthy members.
The group UI distinguishes disconnected, buffering, synchronized, and faulted.
A source change receives a new stream identity and an explicit epoch transition.

A lease identifies which controller may make group-affecting mutations.
The lease is scoped to a group and includes an epoch/fencing token.
A stale coordinator cannot overwrite a newer group's state after a partition.
Members reject commands whose authority token is no longer current.
Lease expiration policy defines whether existing buffered playback continues.
It must not permit two leaders to independently advance one group identity.

The first admitted authority policy uses one configured issuer per group incarnation on an admitted speaker.
Followers do not mint replacement valid epochs during isolation; new control may be unavailable while safe buffered playback continues.
An issuer restart cannot revoke an unexpired grant on a disconnected receiver by merely changing a token.
Require qualified expiry/clock guards and non-overlap before reassignment, or refuse reassignment.
A later automatic failover profile needs a specified grant/quorum/expiry protocol and partition model tests.
Cutover readiness includes every member's irrevocable old-output tail and acknowledged stop/flush capability.
Either drain to a common future cutover, perform acknowledged muted abort/restart, or exclude/abort the member.
Successful seek/skip acknowledgement cannot precede completion of this contract; stale ingress rejection alone is insufficient.
Exclusion is not evidence that a disconnected prior member has stopped sounding.
Before a conflicting program begins under the same group identity, every prior output grant must have an acknowledged stop or a conservatively bounded expiry plus irrevocable output tail.
Receivers enforce output authorization deadlines, including queued samples; the bound includes clock uncertainty and the qualified stop/drain lead.
If that bound is unknown or cannot be enforced, refuse the conflicting start; issuer restart and UI membership removal cannot waive it.
Partition tests assert no overlap of incompatible authorized output across all prior grant holders, including excluded/disconnected members; inject expiry, clock uncertainty, delayed stop acknowledgement and queued old samples.
Already committed identical buffered audio may continue only within its admitted authorization horizon.

Persist only stable membership intent, not volatile packet queues or lease validity.
After restart, discover current authority before resuming group mutation.
A restored desired group is not a restored live session.
A monotonically ordered control sequence handles duplicated retry requests.
Report terminal results by command ID so clients can reconcile timeouts.

## 13. Music mode and video mode

Music mode optimizes continuity across bounded network disturbances.
Video mode optimizes measured latency subject to a smaller loss envelope.
Both modes retain the same stream identity and timing semantics.
Mode selection must be visible to source integrations and diagnostics.
No endpoint independently expands its latency while pretending to remain synchronized.

A latency change proposes a new common presentation offset at a future boundary.
If the source cannot cooperate, pause/rebuffer is preferable to silent desynchronization.
A video-mode twenty-millisecond window is an experiment configuration.
It is not an end-to-end guarantee for an AirPlay source or display.
End-to-end delay includes capture, encoding, network, decoding, DSP, DMA, and display.
A speaker cannot compensate for late audio by playing samples before arrival.
The video source must delay presentation when the audio path requires it.

The runtime reports component delays and uncertainty, not a fabricated exact sum.
If component estimates overlap, avoid double-counting the same queued samples.
AirPlay reporting must follow its negotiated protocol semantics.
A WebSocket helper can request video delay only in a player it actually controls.
Source behavior must be validated separately for phone apps, browsers, and TVs.
A source that ignores timing reports remains explicitly unsupported for automatic sync.

## 14. Failure behavior

No network: continue admitted buffered playback, then conceal briefly and ramp to silence.
No clock confidence: refuse new synchronized start or enter a defined rejoin state.
Decoder failure: terminate that stream, retain device control, and expose the error.
Invalid DSP profile: keep output muted and reject activation.
Driver short write: retain unconsumed frames with bounded retry/deadline handling.
Driver counter reset: invalidate presentation mapping and reinitialize safely.
Thermal fault: request safe mute and preserve a sticky fault until recovery policy allows it.
Control flood: bound requests and protect render scheduling capacity.
FEC overload: stop repair work at its ceiling and use the missing-frame policy.
Telemetry overload: drop diagnostic samples and increment a counter.
Coordinator loss: apply the configured lease and buffer continuation policy.
Split brain: accept only commands from the admitted authority epoch.
Process crash: rely on qualified supervisor/mute behavior, not an assumed benign driver default.
Restart loop: back off and retain a diagnostic reason without repeated audible activation.

A fault result records what is known and what was merely requested.
For example, mute-requested is not mute-acknowledged.
A process that cannot confirm stopped DMA must not reclaim shared buffers unsafely.
Fault recovery must be idempotent and safe to invoke after partial completion.

## 15. Observability and reproducibility

The renderer exposes bounded counters rather than verbose per-frame logs.
Counters include accepted packets, duplicates, stale epochs, and rejected lengths.
Counters distinguish loss, recovered frames, concealment, underruns, and late frames.
Timing metrics include offset uncertainty, drift ratio, and presentation residuals.
Memory metrics include configured caps, measured high-water marks, and rejected admissions.
Lifecycle events include source changes, joins, lease changes, and hardware faults.
Each diagnostic report names executable digest and board/profile version.
Public logs use synthetic member identities and omit service credentials.

A deterministic trace contains input events, synthetic time, and expected transitions.
It does not include private audio recordings unless separately authorized and isolated.
Synthetic tone, impulse, silence, and shaped-noise fixtures cover DSP behavior.
Recorded random seeds make loss and scheduling tests reproducible.
A passing replay validates the model under that trace, not physical output.
Native CPU timing tests and physical qualification are separate evidence classes.

## 16. Acceptance campaign

A release candidate requires an exact feature profile and target build identity.
Run malformed-input and resource-ceiling tests before sustained playback tests.
Run decoder and DSP tests on both endian targets or faithful emulation.
Run a long-duration synthetic-clock test with rate mismatch and counter wrap.
Run mixed-member grouping with join, leave, reconnect, and source replacement.
Run cancellation while ingress, decode, output submission, and drain are each active.
Run memory-pressure tests during service reconnect and update staging.
Run packet loss tests with independent loss and burst patterns.
Run delayed/reordered/duplicated control requests against epoch transitions.
Run old-kernel capability tests separately from current-kernel functional tests.

Proposed first integrated campaign: twenty-four hours of synthetic audio playback.
It includes a published schedule of loss, jitter, source changes, and member restarts.
Report all underruns and recoveries, even if the final state is healthy.
The pass threshold is declared before the run and never relaxed afterward.
A failure creates a bounded reproduction with the smallest relevant trace.
An unexecuted physical test remains pending, never replaced by a simulator badge.

## 17. Implementation task boundaries and dependencies

R01: establish the exact target and legacy-kernel capability matrix.
Inputs are sanitized image provenance and existing toolchain scripts/results.
Outputs are per-target capability results and unresolved physical requirements.
Acceptance requires independently reported syscall/clock/thread/entropy outcomes.
Blocks R02 and R03; unblocks honest runtime-profile selection.

R02: define the small platform boundary and admitted fallbacks.
Depends on R01; outputs typed APIs and per-fallback semantic contracts.
Acceptance includes absence/error injection and target-endian layout checks.
Blocks the production Asupersync adapter and HAL binding.

R03: qualify the minimal Asupersync feature/dependency profile.
Depends on R01; outputs dependency inventory, build map, and executor probe.
Acceptance requires observed start/cancel/drain markers in an admitted guest.
A compile-only result cannot close this task's runtime criterion.

R04: specify and model the retained audio driver ABI.
Depends on the board evidence matrix; no live-device work belongs in this task.
Outputs are structure layouts, state transitions, ownership invariants, and test model.
Acceptance covers short writes, stale handles, counter wrap, and incomplete drain.
Blocks R05 and the board-specific activation handoff.

R05: implement the safe HAL interface against the offline driver model.
Depends on R02 and R04; outputs exclusive owner and buffer lease types.
Acceptance proves the model never observes use-after-release or concurrent owners.
Physical driver behavior remains an external qualification requirement.

R06: implement bounded PCM conversion and DSP routing.
Depends on R05's format contracts and admitted board profile schema.
Acceptance covers endian fixtures, channel mapping, invalid coefficients, and ramps.
No audible board activation is permitted by this task's completion.

R07: implement explicit framing and bounded ingress.
Depends on session/frame schemas and R02 network capability contracts.
Acceptance includes truncation, overflow, duplicate, stale-epoch, and future-window cases.
Outputs feed R08 and R09 without exposing allocator control to packets.

R08: implement the jitter queue and deadline decisions.
Depends on R07; outputs fixed-capacity storage and missing-frame policy.
Acceptance covers wraparound, late recovery, seek invalidation, and resource rejection.
Blocks the initial synchronized-renderer integration.

R09: run the FEC-versus-retransmission experiment.
Depends on R07 and R08; compare identical loss/deadline schedules.
Acceptance is a measured selection report, including a valid no-FEC outcome.
Do not make FEC mandatory merely because the library already exists.

R10: implement clock estimation and resampling control.
Depends on R01 timer capabilities and R06 sample contracts.
Acceptance covers asymmetric delay, oscillator drift, jumps, and uncertainty aging.
Blocks group admission and source-aware latency reporting.

R11: implement group epochs, leases, and cutover transactions.
Depends on R08 and R10; outputs a deterministic session state machine.
Acceptance includes split brain, delayed commit, failed join, and coordinator restart.
Blocks unified grouping in the fsonos adapter.

R12: compose the bounded rendering pipeline.
Depends on R03, R05, R06, R08, R10, and R11.
Acceptance requires sustained offline execution with memory and deadline evidence.
Outputs the minimal renderer baseline before native service features are added.

R13: implement the minimal fsonos compatibility adapter.
Depends on the controller call-surface inventory and R11 session contracts.
Acceptance uses real protocol serialization and bounded controller integration tests.
Unsupported legacy actions are explicit faults rather than invented success.

R14: add source-aware mode transitions and delay reporting.
Depends on R10 through R13 and the integration-specific timing contracts.
Acceptance covers music/video transition, noncooperative source, and stale delay reports.
Automatic lip-sync claims require source-specific validation beyond this core task.

R15: perform the resource and reliability acceptance campaign.
Baseline depends on R12/R13; R14 and R09 are required only for enabled video/recovery profiles.
Outputs exact denominators, traces, peak resources, and remaining hardware gaps.
A failed campaign blocks release but does not invalidate unrelated static proofs.


# Detailed specification: SLIM_INTEGRATIONS_DESIGN.md

# Slim speaker integrations: source, control, and timing design

Status: proposed design; no integration described here has been qualified on a speaker.
This document supplements the slim-speaker implementation plan and runtime design.
It owns service integrations, presentation behavior, controller compatibility, and their acceptance work.
All work authorized in this repository is offline planning, implementation, and emulation.
Future device measurements belong to the human-led frankensonos process.

## 1. Product contract

The primary outcome is reliable Spotify playback across one mixed-generation household.
Users choose a room or group, control volume, and hear synchronized audio.
The replacement protocol must not carry forward the S1/S2 grouping restriction.
Additional desired outcomes are native AirPlay reception, native Tailscale membership,
YouTube lip sync on supported source paths, Alexa control, and existing line-in use.
Optional Sonos One voice processing must not become a prerequisite for basic playback.
Removing unused service clients and formats reduces scope and offers a plausible resource saving.
It does not establish the cause of current dropouts or prove any particular memory saving.

The application shares source and protocol definitions across hardware profiles.
Each supported ISA/ABI receives its own executable and dependency qualification.
A single executable cannot run unchanged on PowerPC, MIPS, and ARM.
Native integrations remain explicit deliverables even when a host-assisted prototype comes first.
A gateway that exposes an old speaker remotely is useful but does not satisfy native Tailscale.
An external AirPlay receiver feeding a speaker is useful but does not satisfy native AirPlay.
Retained vendor kernel and drivers remain outside the Rust application memory-safety boundary.
No bridge profile is required to decode audio or implement every source integration.

### Capability profiles

| Profile | Meaning | Required disclosure |
| --- | --- | --- |
| Native endpoint | Integration executes on the selected speaker | Target, resources, service compatibility |
| Member coordinator | Another qualified speaker terminates the source for a group | Coordinator ownership and failover limits |
| Optional host assist | Owner's host terminates a source or supplies a helper | Host dependency and unavailable-host behavior |
| Unsupported pending proof | Implementation or resource gate remains open | Exact missing proof; no silent substitution |

Group membership and source termination are independent capabilities.
A small speaker can join a source stream without duplicating cloud authentication or decoding.
A capable member may coordinate a group without making every member a full service client.
The target remains a documented native profile for the oldest audio hardware where feasible.
Native source roles are admitted by measured budgets rather than generation labels.

## 2. Integration boundary

All adapters submit commands to one authoritative playback state machine.
Adapters never independently open the audio driver or change DMA ownership.
A source session identifies the source kind, stable logical endpoint, group, and stream epoch.
Session IDs and transport identities are distinct from service tokens and account identifiers.
A stream descriptor records format, rate, channel layout, sample origin, and presentation mapping.
The renderer receives bounded audio blocks and timing metadata through the shared runtime interface.
The coordinator owns membership and target presentation deadlines for its current lease term.
A stale coordinator cannot resume playback after a newer term has acquired ownership.

Each command carries an idempotency token where its transport supports one.
Absolute volume is naturally repeatable; relative volume requires duplicate suppression.
Control acknowledgement means accepted or completed according to the protocol's actual semantics.
The adapter must not report completed playback merely because it queued a command.
Source errors distinguish authentication, unsupported media, network starvation, and renderer failure.
Recovery keeps those categories visible instead of endlessly restarting every component.

Every adapter has bounded connections, metadata size, parser depth, and pending commands.
Cloud metadata and LAN XML are untrusted inputs, even on an owner-controlled network.
Resource accounting includes TLS handshakes, reconnect overlap, metadata artwork, and token refresh.
Artwork is optional and must never consume the audio reserve.
Persistent credentials use an explicit storage interface with redaction and replacement semantics.
Factory identity material is not copied into public fixtures or shared between unrelated nodes.

Source transitions carry an irrevocable-output readiness result from each renderer.
Accepted seek/skip is distinct from completed seek/skip; old submitted output must drain or be acknowledged flushed/muted.
Source-local state resets never erase device protection history.
Candidate-development admission, offline combined qualification and external provider/physical qualification are distinct capability-ledger states.
Bind each state to artifact, target, profile and calibration identity; stale evidence cannot enable advertised capabilities.

## 3. Spotify

### Desired user behavior

A room or stable logical group appears as a Spotify Connect destination.
Selecting it establishes one program for that group, with member-specific volume preserved.
Joining a member does not restart the track on members already playing.
Leaving a group does not revoke the source session for everyone else.
Seek and skip create a new stream epoch so queued old audio cannot leak through.
Pause preserves the intended position while stopping presentation coherently.
Resume chooses a new common deadline rather than letting each speaker restart independently.

The initial integration candidate is a selectively integrated librespot stack.
Its upstream project supports Spotify Connect and currently requires Spotify Premium.
Those properties do not establish compatibility with this project's old kernels or strict Rust boundary.
Pin a reviewed revision and record selected features, dependency licenses, and decoder backends.
Source: [librespot upstream](https://github.com/librespot-org/librespot).

### Source placement and implementation

Implement the service adapter behind a source trait rather than embedding it in the renderer.
Test native source termination on each intended target profile before declaring that profile supported.
A member coordinator may decode once and distribute the internal stream to the group.
An optional host can supply the same stream contract during development or as an explicit fallback.
Neither fallback closes the native-source task for the oldest audio profile.
Document whether endpoint identity follows a logical group or a physical coordinator.
Do not move credentials or reuse a session concurrently during failover without a defined service contract.
Cloud session recovery and local group-coordinator recovery need separate state machines.

Do not hardcode the claim that Spotify always supplies one particular encoded format.
Validate the pinned client's actual negotiated media paths and feature requirements.
Keep the service codec independent of the internal group transport codec.
PCM offers a simple first interchange format; compressed transport is a measured optimization.
Any extra runtime required by an imported client must be measured or adapted to asupersync deliberately.
An imported Tokio dependency cannot be relabeled as an asupersync-native implementation.

### Buffering and reliability

Compressed lookahead and renderer PCM buffers have different purposes and accounting.
At 320,000 bits per second, three minutes of encoded payload occupies 7.2 MB before overhead.
That arithmetic does not guarantee the service exposes three minutes for immediate prefetch.
Downloading that payload in two seconds would require at least 28.8 Mbps of payload throughput.
Do not make startup wait for minutes of lookahead.
Start with a measured minimum readiness threshold and fill additional bounded reserve afterward.
Track useful decoded horizon separately from encrypted or unvalidated bytes already downloaded.
Metadata fetches, login retries, and prefetch cannot starve delivery of imminent audio.

The service adapter must survive token expiry, temporary connection loss, and coordinator changes.
An exhausted buffer enters a deliberate concealment or pause policy shared by all members.
After recovery, members resume at one epoch and presentation point.
Do not promise uninterrupted playback during arbitrarily long outages.
Define a supported outage envelope and measure stalls inside and outside that envelope.
Account concurrency restrictions remain source-service behavior rather than a grouping bug.

## 4. AirPlay reception

### Identity and discovery

Native reception means the endpoint itself implements the required receiver state and protocol.
Expose stable, human-readable room identities and optionally stable logical group identities.
Avoid duplicate group advertisements from competing coordinators.
Persist synthetic receiver identity independently of display-name changes.
Advertise only capabilities actually implemented by the current build.
Keep source discovery behavior distinct from the fsonos UPnP identity.
LAN discovery and tailnet reachability are separate acceptance cases.
Do not assume multicast discovery automatically crosses a tailnet.

AirPlay 2 and older RAOP compatibility are separate profile entries.
An older RAOP receiver passing one audio test does not establish AirPlay 2 support.
Pairing, encryption, transport negotiation, session teardown, and timing all belong in the native scope.
No receiver size is estimated from an unimplemented Rust rewrite.
A reference implementation can provide behavioral comparisons without being part of the shipping binary.
Source: [Shairport Sync upstream](https://github.com/mikebrady/shairport-sync).

### Session behavior

Bound pairing attempts and concurrent sessions so reconnect storms cannot exhaust memory.
Store pairing state through the durable state API; redact all secret fields in traces.
A new sender must follow a specified replace-or-reject policy for an occupied endpoint.
Changing a room into a group must preserve clear ownership of the active source.
When the sender is itself controlling multiple endpoints, avoid applying duplicate grouping semantics.
A group endpoint should terminate one source session and distribute one internal presentation timeline.
Volume mapping must identify sender volume, group gain, member trim, and final protection limiter.
Avoid double attenuation or unexpectedly restoring an old sender volume after a reconnect.

### Timing and video boundary

Measure the complete receiver presentation delay, including decoding, buffering, resampling, and DMA.
Report latency only through protocol mechanisms supported by the negotiated session.
Use the sender's timing information according to its actual semantics.
The sender may account for receiver delay; acceptance requires observing that behavior per source path.
No receiver can compel every iPhone application to delay arbitrary video through a generic timing packet.
A source that ignores the negotiated delay must be reported as unqualified for automatic lip sync.
Changing group membership must not introduce an unannounced delay change mid-session.
Use a negotiated rebuffer or epoch transition when a new member needs a larger horizon.

## 5. YouTube and other video sources

### Source capability classes

| Path | Available control | Qualification question |
| --- | --- | --- |
| iPhone application through AirPlay | Receiver protocol timing only | Does this application honor the negotiated delay? |
| Desktop browser with helper | Audio capture plus permitted media timeline control | Can the helper safely delay the selected video? |
| Desktop system-audio stream | Capture timestamps; video control may be absent | Is fixed or manual calibration required? |
| Analog line-in from a video source | Audio arrival only | Can the source delay video externally? |

The product should automatically compensate on qualified paths and explain unsupported paths clearly.
A blanket promise of automatic sync for all YouTube playback paths is not a testable contract.
Do not treat a 20 ms receiver buffer as equivalent to 20 ms end-to-end latency.
Capture, service buffering, codec lookahead, network transfer, DSP, and DAC queues all contribute.
A source cannot display future video earlier to compensate for audio that arrived too late.
Compensation generally needs control over video delay or sufficiently low audio latency.

### Timeline model

Represent source media time and local monotonic time with an explicit mapping and uncertainty.
Carry sample positions through decode and resampling without losing discontinuity information.
Map a sample's scheduled DAC presentation to source media time at the coordinator.
Calculate fixed and variable delay separately so short jitter does not cause visible video pumping.
Select one group presentation horizon that every admitted member can meet.
If one member cannot meet the video profile, surface a membership choice or rebuffer policy.
Do not silently desynchronize that member to preserve a misleading low-latency label.

Browser helper work must identify a selected tab or media element rather than capturing everything.
Request only required permissions and keep source control understandable to the owner.
Handle seek, playback-rate changes, ads, source replacement, and background throttling explicitly.
On helper disconnect, stop compensating from stale measurements and show the current mode.
Do not claim a browser helper fixes a separate native iPhone application's playback.
A calibration mode may estimate fixed offset, but dynamic drift requires continued timing observation.

### Measurement

Use a source fixture with simultaneously generated visible events and audio impulses.
Measure acoustic output against displayed events using an external reference in the later human lane.
Offline simulations validate timestamp propagation and control logic, not physical lip sync.
Record signed offset distributions, variability, drift, and discontinuity recovery.
Identify source application, OS, receiver profile, group membership, and network conditions.
Choose pass thresholds before the qualification run rather than after seeing the distribution.

## 6. Native Tailscale

### Definition of native support

Each native node enrolls under its own identity, receives network state, and applies access policy.
Its control and data planes must interoperate with the owner's intended tailnet deployment.
A userspace WireGuard tunnel by itself does not implement Tailscale membership.
The native scope includes enrollment, key lifecycle, network-map updates, peer discovery,
NAT traversal, relay fallback where needed, policy enforcement, and reachability diagnostics.
DNS naming must reflect real node identity and lifecycle rather than merely adding host aliases.
No native footprint is promised before a complete configuration has been measured.

Tailscale's documented userspace mode can run tailscaled as a SOCKS5 or HTTP proxy.
That documents an operating mode, not a tiny Rust Tailscale implementation for these targets.
Source: [Tailscale userspace networking](https://tailscale.com/docs/concepts/userspace-networking).
Evaluate compatibility, licensing, kernel needs, and memory of candidate approaches explicitly.
A Rust-native implementation is a substantial integration effort with its own interoperability suite.
Native support remains open until target resources and enrollment behavior are demonstrated.

### Gateway fallback and group behavior

A qualified newer speaker or optional host may provide a tailnet-to-LAN gateway.
Label this as gateway access rather than per-speaker native membership.
Redundant gateways need independent identities and a deliberate failover mechanism.
Do not clone a node key across simultaneously active gateways.
A gateway failure must not interrupt local music already flowing between speakers.
Keep group audio on the LAN by default; remote control should not force audio through a relay.
If remote audio is enabled, it receives a separate jitter and bandwidth profile.
Remote users should see unavailable native features rather than a fictitious uniform capability list.

### Exposure and resource isolation

Expose a narrow authenticated management interface to the tailnet.
Do not automatically export every legacy unauthenticated UPnP action to remote peers.
Apply authorization before state-changing control and preserve command replay protections.
Rate-limit handshake and connection churn independently of the realtime renderer.
Bound relay buffers, peer counts, and concurrent management sessions.
Token expiry, revoked access, and a disconnected control plane require explicit offline behavior.
Device clock uncertainty must not be hidden when credential or certificate validation needs time.
Logs record lifecycle events without authentication material or actual site identities.

## 7. Alexa

### Separate capabilities

Alexa volume/mute, transport control, grouping, and music destination selection are distinct deliverables.
Amazon's Speaker interface describes volume and mute properties and directives.
It does not by itself establish arbitrary room grouping or Spotify music routing.
Source: [Alexa Speaker interface](https://developer.amazon.com/docs/alexaplus/device-apis/alexa-speaker).
A Spotify Connect endpoint does not automatically become an Alexa-selectable speaker destination.
A local bridge protocol does not automatically provide the same capability surface as a cloud skill.

Create a capability matrix for the actual Echo families and integration paths selected later.
Evaluate documented local interoperability separately from cloud account-linked control.
Do not implement speculative Hue or Matter impersonation as the foundation of media support.
If a supported bridge path provides only volume or power-like actions, report that exact scope.
A cloud-backed path needs account linking, endpoint discovery, authorization, and state reporting.
Music routing additionally needs its own supported service/device integration mechanism.
If that mechanism is unavailable, retain the goal as blocked and offer an explicit alternate workflow.

### Control semantics

Map Alexa room names to stable logical endpoints, not transient coordinator addresses.
Use absolute group volume when possible; duplicate relative commands must not compound gain.
Acknowledge successful execution only after the relevant state transition meets the interface contract.
Return meaningful unavailable responses when a group is offline or a command is unsupported.
Commands from Alexa, fsonos, buttons, and AirPlay must converge on the same state machine.
Define last-writer and source-ownership policy so simultaneous controllers cannot oscillate playback.
Measure LAN command execution separately from speech recognition and cloud round-trip time.
Do not promise under-30-ms spoken-command response from a fast local handler benchmark.

## 8. Optional Sonos One local voice

The presence and exact revision of a suitable One is an evidence gate, not an inventory assumption.
Microphone capture, channel layout, calibration, and driver access need their own offline evidence.
A nominal RAM quantity does not prove franken_whisper inference can meet the target workload.
Profile model size, working memory, sustained CPU, and impact on rendering before enabling it.
Use an optional process or resource-isolated task with a strict budget and watchdog policy.
Failure of speech recognition must never stop playback or disable physical mute control.

Local voice requires explicit microphone enablement and a clear active indication.
Default recording retention is off; diagnostic capture needs a separate owner action.
Do not assume the stock microphone privacy button remains effective after replacing its userspace handler.
Verify the privacy control's hardware and software behavior before admitting microphone operation.
Echo cancellation and own-playback rejection are part of voice qualification.
Interpret recognized commands through the same authorization and playback state machine.
A local voice command path is separate from being an Alexa Voice Service endpoint.

## 9. Line-in

Line-in is a source capability on boards whose ADC path has been established.
Preserve source gain, overload reporting, channel mapping, and mute/ramp behavior.
The ADC clock and receiving DAC clocks can drift even when nominal sample rates match.
Timestamp capture blocks and use the same group presentation discipline as network sources.
Prevent a line-in source from accidentally monitoring a feedback route through itself.
Select one capture owner per input; a stale coordinator cannot leave capture running indefinitely.

A low-latency monitoring mode and a resilient whole-house mode need separate budgets.
Do not claim a universal 15 ms analog-to-acoustic delay.
Measure capture DMA period, conversion delay, transport, resampling, playback DMA, and group skew.
Source disconnect and reconnect create explicit events with a click-free policy.
Preserve stereo-pair and Sub routing constraints when distributing the captured program.
Video connected through line-in still requires the source-dependent compensation rules above.

## 10. fsonos compatibility

Use fsonos-proto as the contract starting point, then enumerate actual daemon call sites.
The currently inspected control module exposes play, pause, stop, next, previous, track/time seek,
transport-URI assignment, queue operations, join/leave/delegate group, volume, mute,
bass, treble, loudness, group volume, volume ramping, state queries, and sleep timers.
Not every exposed helper is necessarily required by every controller workflow.
Generate an action matrix from actual usage before committing the compatibility surface.
Related source: ../frankensonos/crates/fsonos-proto/src/control.rs.

Group topology and GENA subscription behavior are compatibility requirements alongside SOAP replies.
Preserve semantic state transitions and error behavior, not only XML element spelling.
Use bounded parsing and serialization rather than importing unrestricted XML trees by default.
Test renewal, expiry, sequence wrap, duplicate notifications, reconnect, and stale subscriptions.
Synthetic fixture identities must stay stable across test runs without resembling real site data.
A custom endpoint must advertise its supported capabilities honestly.
Unsupported service actions return defined errors instead of fabricated success.

During migration, stock speakers and replacement speakers need an explicit controller view.
Do not promise proprietary stock transport interoperability solely from SOAP compatibility.
The unified replacement transport joins custom endpoints across generations.
Stock endpoints remain separately represented until a proven bridging path exists.
A control compatibility adapter should not require bundling all fsonos-core storage and UI machinery.
Extract the smallest reusable protocol types and document any upstream changes needed.

## 11. Evidence and resource qualification

Maintain one integration ledger row per target profile, service revision, and operating mode.
Each row states source revision, feature set, build size, peak memory, CPU, and measured behavior.
Include reconnect storms, cryptographic handshake peaks, and overlapping sessions in peak measurements.
Measure all enabled integrations together before claiming a combined resource budget.
A stripped binary size is neither peak RSS nor a prediction of flash layout suitability.
Offline emulator success does not qualify driver timing, radio behavior, or real cloud interoperability.

Public evidence contains synthetic identifiers and sanitized commands only.
Private account material and source captures stay outside tracked artifacts.
Integration traces use event kinds and opaque synthetic correlation tokens.
Record test denominators and unsupported cases so a single successful demo cannot imply completeness.
No stage requires sending test traffic to a live speaker from this repository.
Future live tests are handed to the authorized frankensonos human process as written runbooks.

## 12. Beads-ready implementation tasks

Each task below is a proposed engineering unit, not a claim that work has already passed.
Dependencies named RUNTIME and HAL refer to the companion runtime and platform workstreams.
Native goals stay open if an optional fallback alone passes.

### INT-001 — Integration capability and dependency ledger

Inputs: assessment, sanitized inventory, pinned candidate source revisions.
Output: per-profile native/member-coordinator/host-assist matrix and dependency license inventory.
Audit runtime, unsafe/FFI, endianness, kernel syscall, crypto, and allocation requirements.
Dependencies: verified target ABI profiles; no service implementation needed.
Acceptance: every desired feature has an explicit native status and measurable missing proof.
Validation: schema checks and reviewer reconciliation against source manifests.

### INT-002 — Shared source-session and command contracts

Output: epoch, source ownership, bounded metadata, command results, and presentation interfaces.
Dependencies: RUNTIME state machine and group lease definitions.
Specify cancellation, duplicate commands, stale-owner rejection, and source replacement.
Acceptance: all adapters map to one state machine without direct driver ownership.
Validation: deterministic transition/property tests including seek versus late packets.

### INT-003 — Spotify client extraction and native build probe

Output: pinned minimal client configuration and per-target dependency/build report.
Dependencies: INT-001, target toolchains, old-kernel compatibility work.
Identify actual media formats and any additional async runtime dependency.
Acceptance: report each native target honestly as buildable, executable offline, or blocked.
Validation: synthetic handshake/media fixtures and emulator logs where execution is claimed.

### INT-004 — Spotify session and group integration

Output: session lifecycle, Connect identity policy, seek/skip epochs, and source distribution adapter.
Dependencies: INT-002, INT-003, RUNTIME transport.
Specify optional coordinator without retiring oldest-profile native work.
Acceptance: group changes and source recovery preserve coherent state in deterministic tests.
Validation: token expiry, loss, account conflict, repeated commands, and source restart fixtures.

### INT-005 — Spotify resource and service qualification package

Output: peak-memory scenarios and future service-interoperability runbook.
Dependencies: INT-004 and offline profiler harness.
Measure startup, prefetch, reconnect, metadata overload, and combined background integrations.
Acceptance: no memory or dropout claim lacks a measured scenario and denominator.
Validation: offline resource gates; future authorized account tests reported separately.

### INT-006 — AirPlay protocol and receiver identity design

Output: separate AirPlay2/RAOP capability contracts, pairing state, discovery, and group identity policy.
Dependencies: INT-001, INT-002, bounded network/crypto substrate.
Use public implementations as behavioral references with explicit source and license boundaries.
Acceptance: native receiver scope includes timing and authentication rather than decoder-only support.
Validation: malformed negotiation fixtures and duplicate-coordinator discovery scenarios.

### INT-007 — AirPlay native session implementation and qualification

Output: bounded receiver adapter, stream timing map, teardown, and volume mapping.
Dependencies: INT-006, RUNTIME rendering contract.
Maintain separate per-target resource records and optional host-reference comparisons.
Acceptance: offline session corpus passes; real sender interoperability remains a separate gate.
Validation: pairing persistence, reconnect, source replacement, timing discontinuities, and resource peaks.

### INT-008 — Video timeline and latency controller

Output: source-time/presentation mapping, uncertainty handling, and group horizon transitions.
Dependencies: INT-002, RUNTIME clock discipline, INT-007 for AirPlay path.
Separate fixed delay correction from adaptive jitter behavior.
Acceptance: deterministic fixtures preserve known offset and prevent stale-epoch compensation.
Validation: drift, seek, rate change, delayed member, and helper disconnect scenarios.

### INT-009 — Optional browser/desktop video helper

Output: selected-source capture/control adapter and explicit supported-source matrix.
Dependencies: INT-008 and host integration permission design.
Document paths with no authority to delay video and provide manual-calibration behavior.
Acceptance: no claim that desktop control applies to arbitrary native iPhone apps.
Validation: synthetic visible/audio fixture, source replacement, ads, and background behavior.

### INT-010 — Native Tailscale feasibility and interoperability scope

Output: full membership/control/data-plane requirements and candidate implementation comparison.
Dependencies: INT-001 and target crypto/time/syscall profiles.
Distinguish WireGuard-only, proxy, gateway, and actual native node designs.
Acceptance: explicit per-target resource/compatibility blockers with a retained native task.
Validation: source audit plus offline enrollment/network-map fixtures without real credentials.

### INT-011 — Native tailnet adapter and optional gateway profile

Output: identity lifecycle, authenticated control, peer/relay bounds, and gateway failover contract.
Dependencies: INT-010, INT-002, durable secret-state interface.
Keep local playback operational when remote access fails.
Acceptance: gateway success is labeled separately from native node success.
Validation: revocation, key rotation, peer churn, relay failure, and duplicate identity prevention.

### INT-012 — Alexa capability discovery and control mapping

Output: documented integration-path matrix, endpoint naming, directive/state mappings.
Dependencies: INT-001, INT-002; external service research may reveal admission blockers.
Separate volume, transport, grouping, and music-destination capability evidence.
Acceptance: unsupported music routing remains open rather than inferred from Spotify Connect.
Validation: synthetic directives, duplicate relative volume, unreachable endpoint, and state-report tests.

### INT-013 — Alexa integration qualification package

Output: local-handler metrics and distinct end-to-end voice/service test runbook.
Dependencies: INT-012 and selected supported integration mechanism.
Specify account linking and secret handling where cloud integration requires them.
Acceptance: each advertised action maps to a supported path and observed result category.
Validation: offline contract tests; later owner-operated Echo checks recorded separately.

### INT-014 — Line-in source adapter

Output: bounded capture source, clock mapping, gain, disconnect, and feedback prevention behavior.
Dependencies: HAL ADC contract, INT-002, RUNTIME presentation transport.
Provide separate resilient and low-latency profiles without unsupported delay guarantees.
Acceptance: synthetic capture with drift remains coherent across group changes.
Validation: clipping, disconnect, clock skew, stereo routing, and stale capture-owner tests.

### INT-015 — Optional local voice feasibility and privacy contract

Output: qualified hardware evidence checklist, franken_whisper resource probe, privacy-state design.
Dependencies: proven microphone profile, HAL capture, INT-002.
Keep voice outside mandatory renderer startup and budget it independently.
Acceptance: no microphone operation or recognition claim without the corresponding evidence.
Validation: offline model benchmarks and mute/indicator state-machine tests using synthetic input.

### INT-016 — fsonos compatibility extraction

Output: exact action/call-site matrix, topology schemas, subscription contract, and synthetic corpus.
Dependencies: pinned fsonos-proto and daemon source revisions.
Identify required, optional, and deliberately unsupported actions.
Acceptance: every required controller workflow has a response and event sequence specification.
Validation: fixture replay against parser/adapter boundaries and bounded malformed inputs.

### INT-017 — Unified control arbitration and compatibility adapter

Output: SOAP/GENA adapter and arbitration for buttons, AirPlay, Spotify, Alexa, and remote control.
Dependencies: INT-002, INT-016; integration adapters may be added incrementally.
Preserve volume trims and enforce source ownership across conflicting commands.
Acceptance: deterministic concurrent-control scenarios converge without duplicate audible streams.
Validation: event ordering, retries, subscription expiry, stale topology, and volume ramp cancellation.

### INT-018 — Combined integration qualification and migration handoff

Output: per-profile feature ledger, combined peak resource runs, and human-lane acceptance runbooks.
Dependencies: relevant native adapters, HAL/RUNTIME evidence, individual test packages.
Exercise enabled integrations together, including reconnect storms during group playback.
Acceptance: native features, optional fallbacks, offline proofs, and live-unrun cases remain distinct.
Validation: sanitized evidence review and requirement-to-task coverage audit before any rollout proposal.

## 13. Qualification separation from fresh review

T01 closes an investigation even when negative; T04 is an independent positive development-admission gate.
T02 implements the admitted native strategy. Q04 exercises offline combined workloads, and Q06 validates external native/physical receipts.
X04 owns offline Alexa music routing; X05 requires externally supplied supported-provider and utterance-to-group evidence.
Q05 release remains blocked until Q06; no offline simulator or control-only success establishes complete native support.
Changes to owned Franken libraries are permitted remediation, with exact upstream revision and target tests recorded.
The first native tailnet profile may expose only a fixed authenticated application-control allowlist; general subnet routing is not required.
It still owns endpoint identity/control/data-plane functionality and is not replaced by a host gateway.

# Design-package crosswalk

Canonical catalog keys own completion. Copy the mapped detailed contracts into Beads; do not create duplicate R/INT issues.

| Design package | Canonical tasks |
|---|---|
| R01 | E01, E03 |
| R02 | P02 |
| R03 | E06, P03 |
| R04 | E04 |
| R05 | P04 |
| R06 | D01, D02 |
| R07 | N01, N02 |
| R08 | N04 |
| R09 | N05, N06 |
| R10 | N03, D03, P02 |
| R11 | G01, G02 |
| R12 | D04, Q01 |
| R13 | G03 |
| R14 | V01, V02 |
| R15 | Q02, Q03, Q04 |
| INT-001 | E01, E06, P01 |
| INT-002 | P01, N02, G01 |
| INT-003 | S01, E06 |
| INT-004 | S01, S03 |
| INT-005 | S03, Q02, Q03 |
| INT-006 | A01 |
| INT-007 | A02 |
| INT-008 | V01, V02 |
| INT-009 | V02 |
| INT-010 | T01 |
| INT-011 | T02, T03, U01 |
| INT-012 | X01 |
| INT-013 | X02, X04 |
| INT-014 | L01 |
| INT-015 | X03 |
| INT-016 | G03 |
| INT-017 | G01, G02, G03, Q01, Q04 |
| INT-018 | Q04, Q05 |

# Provisional qualification targets

These are proposed engineering acceptance thresholds, not measured performance or owner guarantees. Freeze a versioned profile before execution; failed thresholds produce a new decision record rather than silent relaxation.

- Baseline music: 48 kHz stereo16 canonical PCM, 500 ms playout horizon; separate source lookahead. Test 1% seeded independent packet loss, 100 ms total-loss bursts separated by at least 10 seconds, 50 ms added jitter, reorder and duplicates. Freeze the jitter distribution, reorder depth, duplicate rate and burst schedule before execution. Report each condition separately. Baseline clean-network playback must have zero unexplained output underruns during a 24-hour campaign. Loss-profile acceptance must declare recovery/concealment tolerances before running; no dropout-proof claim.
- Group synchronization: proposed electrical-output relative skew target p99 <= 2 ms and maximum <= 5 ms after lock under the admitted network profile; measure each board pair over at least one hour. Startup/relock excluded only with explicit muted-state accounting. Sub-sample/50 microsecond claims require an additional stricter instrumented campaign. Acoustic location delays are separate.
- Smallest audio endpoint: nominal 32 MB is not process budget. E02/P02 must measure or bound kernel, driver, DMA and irreducible reservations. Provisional policy reserves at least 4 MiB beyond measured worst-case total usage; if not feasible, admit a narrower explicitly named profile or keep the required native feature blocked. No fixed 2.8 MB RSS claim.
- CPU/deadlines: declare actual render block period; every tested render submission must complete before its device deadline. Track maximum and p99.99 latency, with a provisional 25% execution-time reserve against the available release-to-submission-deadline interval. Guest wall-clock results never substitute for board CPU measurements.
- Tailnet: resource table includes identity enrollment, maps at the declared peer cap, reconnect, relay traffic and key rotation while audio runs. No admitted numeric RAM cap exists until the shared budget is allocated; absent budget is pending, not pass.
- Video: report measured end-to-end audio latency and source-compensated A/V residual separately. Provisional cooperative-source residual target p99(abs(residual)) <= 40 ms over play/pause/seek and route changes. Uncooperative sources are outside automatic compensation claims. A 20 ms pipeline is a stretch experiment, not the baseline gate.
- All tests publish exact build, target, profile, duration, seeds, denominator, maxima, failures and whether results are host simulation, guest execution, real service or physical output.
