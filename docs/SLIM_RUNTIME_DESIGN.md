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
