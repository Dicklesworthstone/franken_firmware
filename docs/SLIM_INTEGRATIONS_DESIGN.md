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
