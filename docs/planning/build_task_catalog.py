"""Render planning task specifications; issue mutations happen only through br."""
import json
import os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
# key, title, dependencies, deliverable, acceptance: each describes a distinct implementation unit.
rows=[
('E01','Reconcile device and firmware identity evidence',[], 'Sanitized board-profile manifest joining model, revision, ISA, ABI, nominal resources, image digest and evidence provenance; private identifiers stay local.', 'Reject ambiguous mappings; test duplicate identities, changed addresses, missing fields and conflicting historical images; never derive CPU from product era.'),
('E02','Measure incumbent resource and dropout baseline',['E01'],'Offline analysis schema and human-run capture recipe for kernel reservations, process RSS/PSS, slab, page cache, DMA, faults and Wi-Fi loss; no device execution here.','Separate disk bytes from resident pages; compare synchronized loss/buffer traces; classify memory/RF/clock hypotheses without causal claims from correlations alone.'),
('E03','Map legacy kernel ABI capability matrix',['E01'],'Per-image kernel version provenance and syscall/ABI probes for timers, poll/epoll, eventfd, futex, entropy, TLS, atomics and process startup.','Run in exact-version full-system guests when available; user-mode QEMU is CPU evidence only; unsupported features return explicit capability failures.'),
('E04','Specify retained audio driver ownership and protection',['E01'],'Document ioctl numbers, payload endianness/alignment, mmap/DMA ownership, channel map, rates, drain/mute and amplifier sequencing from permitted evidence.','Require artifact anchors; unknown ioctl fields block hardware eligibility; simulator asserts exclusive ownership and no buffer release while DMA owns it.'),
('E05','Qualify boot-hook and rollback semantics offline',['E01'],'Trace Configure.dev/runanacapa/stop marker behavior per image, ordering, permissions, persistence, watchdog and recovery semantics.','Hook presence does not prove writable access or successful startup; fault-injection model covers missing file, failed binary, repeated restart and interrupted configuration write.'),
('E06','Audit dependency features and target availability',['E03'],'Pinned per-target dependency/unsafe/license feature inventory for Asupersync, franken_kernel, libc candidates, DSP, codecs and crypto.','Build minimal graph first; inspect transitive std/alloc/native dependencies and floating-point ISA; no dependency admitted solely because its parent crate forbids unsafe.'),
('P01','Define Rust workspace and build profiles',['E06'],'Workspace specification and later scaffold for franken-speaker, franken-hal, franken-dsp, protocol, session, source adapters and host tools.','Single shared source with distinct ISA artifacts; reproducible lockfile and target configuration; no binary claimed universal across PPC/MIPS/ARM.'),
('P02','Implement minimal legacy platform capability layer',['P01','E03'],'Small audited platform boundary with explicit clock, reactor wakeup, socket, memory and entropy capabilities.','No insecure entropy fallback; no fake syscall success; test absent syscalls and interrupted calls; document accept/fcntl concurrency implications.'),
('P03','Bring up bounded Asupersync execution profile',['P02'],'Single-thread cooperative control runtime with bounded tasks, timers, channels and diagnostics; DSP has its own deadline path.','Real target guest markers for spawn/cancel/drain, timers and sockets; measure stack/heap high-water; a stalled task cannot indefinitely own audio resources.'),
('P04','Implement board HAL adapters and fake-device harness',['P02','E04'],'Typed read/write/control interfaces for each admitted driver ABI with explicit ownership tokens and drop behavior.','Malformed device responses and ioctl errors fail muted; endian golden vectors; deterministic fake hardware and separate true-device qualification ledger.'),
('D01','Implement fixed-size audio blocks and conversion',['P01'],'Canonical stream format descriptors, channel layouts, sample conversion, saturation and bounded rings.','Bit-exact endian vectors, clipping/NaN handling, queue wrap tests, no allocation in render hot path; representation and bytes-per-frame explicit.'),
('D02','Implement board protection DSP',['D01','E04'],'Per-board crossover/EQ, gain ceilings, limiter, DC rejection, ramp and fault-mute parameter loading.','No generic stereo PCM sent blindly to individual drivers; validate coefficients/stability, malformed calibration and fail-muted unknown board.'),
('D03','Implement drift correction and resampling',['D01'],'Bounded clock-rate estimator and resampler with discontinuity handling and state reset by epoch.','Measure quality and CPU on target ISA; deterministic vectors for drift, wrap and clock jump; bounded slew avoids audible pitch steps.'),
('D04','Integrate render scheduling with retained HAL',['P04','D02','D03'],'Preallocated render loop, driver timestamp accounting and explicit mute/drain lifecycle.','Deadline/underrun counters distinguish missing packets from CPU misses; watchdog path mutes; host simulator is not acoustic proof.'),
('N01','Specify and implement authenticated stream framing',['P01'],'Versioned bounded datagram headers with stream ID, epoch, sequence, presentation time, format and payload limits.','Golden wire vectors across endianness; reject oversize, duplicate/replay, stale epoch and unknown critical fields; fuzz parsers offline.'),
('N02','Implement reliable bounded control channel',['N01','P03'],'Idempotent commands with IDs, expected epoch, acknowledged state revision and authenticated pairing.','No unbounded retry queue; stale leaders cannot alter current group; retries preserve exactly one logical volume/group transition.'),
('N03','Implement group clock and synchronized join',['N01','D03'],'Clock probes, offset/frequency fit, future start schedule, uncertainty estimate and muted catch-up.','Explicit uncertainty threshold; stale timing causes mute/rejoin; test asymmetric delay, leader change, suspend and reboot; no promise from NTP-style offset alone.'),
('N04','Implement adaptive bounded jitter and concealment',['N03','D01'],'Music and realtime policies with fixed caps, late-packet handling, short-gap concealment and shared latency transitions.','Buffer growth never exceeds profile; late packets cannot reorder played audio; source latency changes require group coordination.'),
('N05','Evaluate RaptorQ against simpler repair strategies',['N04'],'Reproducible traces comparing plain UDP concealment, deadline-bounded retransmit and FEC by CPU/RAM/latency/loss.','Burst outages longer than repair horizon are explicit failures; validate symbol limits and peak decode memory; promote only a measured winning profile.'),
('N06','Implement bounded admitted FEC profile',['N05'],'Optional capped repair windows and authenticated symbols; reliable control remains independent.','Decline unsupported block sizes; test corrupt symbols, decode overload, adversarial duplicates and packet storms; fallback retains bounded state.'),
('G01','Implement unified group membership state machine',['N02','N03'],'Cross-generation groups, join/leave, coordinator leases, fencing, peer capability admission and selected source ownership.','One group epoch across members; partitions never produce conflicting audible programs; group timeout behavior and isolated volume controls are explicit.'),
('G02','Implement volume, mute and channel roles',['G01','D02'],'Group master volume, per-room trim, stereo L/R/Sub assignments and atomic smooth transitions.','Bound final gains before interpolation; test mute priority, overflow, retries, stale commands and missing members; no volume spikes on reconnect.'),
('G03','Implement fsonos compatibility adapter',['G01','G02'],'Minimum actually-used SSDP descriptions, SOAP actions and GENA state contracts; use fsonos-proto where suitable.','Controller contract tests include subscription renewal/expiry, escaping, topology events and unknown actions; do not reintroduce legacy content catalog.'),
('S01','Implement Spotify source capability and session contract',['P03','N02'],'Pinned Spotify client integration profile with secure account storage, discovery, session refresh, disconnect and track transitions.','Premium/account conditions explicit; no credential export in logs; provider failure is separate from renderer failure; actual service tests remain owner-account qualified.'),
('S02','Qualify Vorbis and optional source codecs',['D01','E06'],'Bounded pure-Rust codec selection with malformed-input caps, seek/gapless semantics and exact target benchmark.','Measure worst-case CPU, stack, heap and samples; codec name or source code existence does not prove old-CPU realtime support.'),
('S03','Implement Spotify cache and source placement',['S01','S02','N04'],'Bounded compressed lookahead and decoded playout queues with endpoint-native and optional coordinator profiles.','State seconds and bytes separately; fetch duration depends on provider and link; eviction never writes secrets; no guaranteed three-minute fetch in two seconds.'),
('A01','Specify native AirPlay2 discovery and pairing',['P03','N02'],'Service identity, pairing/authentication, advertised room/group mapping, crypto dependencies and protocol-version compatibility matrix.','No false service capability advertisements; test bounded discovery churn, identity persistence and pairing reset; distinguish AirPlay1 from AirPlay2.'),
('A02','Implement AirPlay audio timing and decoding',['A01','S02','N03'],'AAC/ALAC capability profiles, timing mapping, buffer negotiation and authenticated receiver sessions.','Protocol test captures must be authorized and scrubbed; source-provided timing and render offset tested separately; native renderer scope not satisfied by gateway alone.'),
('V01','Implement end-to-end latency ledger',['D04','N04'],'Measured ingress/decode/FEC/queue/DSP/DMA timeline with uncertainty and fixed-vs-variable offset accounting.','Never double-count overlapping pipeline stages; validate against known injected delays and monotonic clock transforms.'),
('V02','Implement source-aware video synchronization',['V01','A02'],'AirPlay source compatibility matrix and optional desktop/browser helper that can delay video for synchronized audio.','Qualify seek/pause/rate/route changes per source; unsupported app reports limitation; no automatic universal iPhone YouTube guarantee.'),
('T01','Qualify native Tailscale protocol and resource profile',['E06','P02'],'Endpoint identity/control registration/discovery/NAT/relay/key rotation feasibility beyond WireGuard encryption alone.','Exact legacy ISA build and memory/CPU measurements; assess official client versus Rust implementation honestly; gateway route is separately named.'),
('T02','Implement native tailnet endpoint integration',['T01','N02'],'Admitted client profile with ACL enforcement, key rotation, identity lifecycle, diagnostics and remote control routing.','Test denied access, expired identity, relay fallback, offline control and key rotation; local audio does not depend on WAN/tailnet control availability.'),
('T03','Implement optional redundant gateway service mode',['T01','G01'],'Explicit user-visible gateway-assisted mode with fencing and stable room service identities.','Gateway identity is not native identity per speaker; test split brain, stale routes, failover and no accidental LAN exposure.'),
('X01','Specify Alexa command and music-destination capabilities',['G02','G03'],'Separate local discovery/control, cloud skill bridge, music destination/provider authorization and group naming.','No assumption Hue/UPnP/Matter equivalence; enumerate supported commands and source authentication; microsecond latency is not claimed for cloud voice.'),
('X02','Implement Alexa control integration',['X01','N02'],'Authenticated command adapter, discovery, state reporting and idempotent group/volume/mute actions.','Test replay, duplicate voice delivery, ambiguous room name, unavailable group and revoked account; distinguish acknowledgement from audible execution.'),
('X03','Qualify optional local voice on supported microphone boards',['E01','X02'],'Microphone/echo-cancellation ABI and franken_whisper compute/privacy feasibility; host-assisted option documented.','No assumption all One variants have identical mic arrays; explicit recording indicator and no retention by default; CPU budget cannot starve audio.'),
('L01','Implement line-in capture and synchronized distribution',['E04','V01','G01'],'Capture HAL, source timestamps, feedback-loop prevention and music/realtime group policies.','Measure ADC-to-DAC latency; audio capture clock drift accounted; unavailable inputs fail clearly; claimed 15 ms remains benchmark target only.'),
('U01','Implement minimal persistent state and calibration custody',['P02','E05'],'Small versioned crash-consistent settings journal; selective frankenfs algorithm reuse with wear/write limits.','Power-cut fault simulation across every publication step; no full filesystem stack dependency by default; preserve calibration separately.'),
('U02','Implement signed staged artifact/update design',['U01','E01'],'Per-board manifests, artifact verification, anti-rollback policy and offline activation/rollback models.','A/B only where capacity proven; factory trust boundary distinct from our signing scheme; no vendor bypass implied.'),
('U03','Specify reversible userspace activation handoff',['E05','D04','U02'],'Human-led activation runbook with exclusive stock/custom audio ownership, rollback trigger and qualified watchdog behavior.','Planning output only here; no runtime hook changes; verify rootfs unchanged does not mean JFFS or running-device risk absent.'),
('Q01','Build offline end-to-end virtual house harness',['G03','S03'],'Multiple mixed-profile renderers on virtual clock with controllable network/clock/device faults and structured receipts.','Check samples and state, not log strings alone; separate unit/mock simulation from full-system and hardware evidence.'),
('Q02','Qualify footprint and deadline budgets',['Q01','N06','D04'],'Per-target link map, compressed/uncompressed image sizes, peak resident set, stacks, DMA, allocator fragmentation and deadline percentiles.','Sweep concurrent controls and hostile inputs; no 1.15 MB/2.8 MB/19 MB headroom claim without exact artifact measurements.'),
('Q03','Define owner-run acoustic and network qualification',['Q02','V02','L01'],'Instrumented mixed-generation Spotify soak, output skew measurement, loss/roam/rejoin matrix and return-to-stock criteria.','Live execution belongs human-led external process; analog measurements required for sub-sample claims; capture duration and test denominator explicit.'),
('Q04','Qualify complete requested integration matrix',['Q03','T02','T03','X02','A02'],'Native and assisted profiles labeled separately across Spotify/AirPlay/video/Alexa/Tailscale, independent groups and recovery.','No feature silently removed when optional assistance used; document unsupported combinations and exact reproducible acceptance receipts.'),
('Q05','Produce release and maintenance handoff',['Q04','U03'],'Versioned per-board compatibility/support table, key rotation policy, rollback documentation and regression corpus.','No production declaration from guest-only tests; release evidence pins exact sources/toolchain/artifacts; retain unresolved optional voice qualification.')]
# Accepted review-1 and integration-challenger corrections.
updates={
'E02': {'scope': 'Offline baseline-analysis schema and human-run baseline recipe; analyze existing captures if available. Missing live measurements remain separate.', 'acceptance': 'Package completion is not baseline measurement. Missing comparison bars quantified improvement claims but permits absolute qualification.'},
'P01': {'scope_extra': ' Define typed secret-store, source-session, command and latency contracts with ephemeral test implementations.'},
'S02': {'title': 'Qualify negotiated source-codec profiles', 'scope_extra': ' Derive mandatory decoder set from pinned Spotify/AirPlay negotiated formats; keep optional internal transport codec separate.', 'acceptance_extra': ' Unsupported negotiated formats fail explicitly; no Vorbis-only provider assumption.'},
'S03': {'deps_extra':['U01']}, 'A02': {'deps_extra':['U01']}, 'T02': {'deps_extra':['U01']},
'X03': {'deps':['E01','P04','P03','N02']},
'U01': {'scope_extra':' Separate credential namespaces and calibration; define replacement/revocation, permissions, secret-redacted errors, bounded capacity/write rates and crash consistency. Persistence does not imply encryption or hardware-backed custody.'},
'Q01': {'deps_extra':['D04']},
'Q02': {'deps':['Q01','D04'], 'acceptance_extra':' No-FEC is valid for baseline. Repeat with each enabled optional profile.'},
'Q03': {'deps':['Q02','U03','E02'], 'acceptance_extra':' Baseline Spotify, volume, joins, source restart, loss envelope and rollback. Declare thresholds before execution. Report absolute vs comparative evidence separately.'},
'Q04': {'deps':['Q03','T02','X02','X04','A02','V02','L01'], 'acceptance_extra':' Gateway and FEC qualification are conditional on enabled profiles; optional absence neither closes nor blocks native requirements.'},
'N06': {'scope_extra':' Implement only if N05 admits a measured FEC profile; no-FEC outcome keeps this optional capability deferred.'}
}
revised=[]
for key,title,deps,scope,accept in rows:
 u=updates.get(key,{})
 revised.append((key,u.get('title',title),u.get('deps',deps)+u.get('deps_extra',[]),u.get('scope',scope)+u.get('scope_extra',''),u.get('acceptance',accept)+u.get('acceptance_extra','')))
rows=revised
rows.append(('X04','Implement and qualify Alexa voice-to-Spotify routing',['X01','X02','S03','G01'],'Supported music-destination/account-routing integration with explicit provider admission and target group selection.','Offline directives do not qualify music routing. Require documented supported mechanism and later owner-operated utterance-to-selected-group playback receipt; unavailable provider admission remains blocked, not silently replaced by volume control.'))

# Accepted review-2 exact contract repairs and NTM platform review.
review2={
'N03': (' Consume P02 timer resolution/wrap/failure contract, N01 timestamps and D03 sample positions. Produce clock transform, uncertainty, admissible-start deadline and expiry.', ' Reject unadmitted/replayed/stale timing inputs; test asymmetric delays, drift, clock jumps and expiry. Estimator error is not physical DAC skew.'),
'T01': (' Own docs/tailscale/feasibility.md, docs/tailscale/profiles.json, tests/tailscale-fixtures/ and toolchain/results/tailscale/. Record provisional per-target budget if combined headroom has not been measured; native admission remains pending until combined Q04 evidence. Produce docs/contracts/t01.md candidate table with pinned revisions, protocol scope, kernel/ISA requirements, Rust/FFI boundary, measured resources where executable and exact blockers otherwise.', ' Synthetic identity/network-map/relay/key-expiry fixtures only. A reproducible negative feasibility result closes investigation but leaves T02/native requirement blocked. No Go reference client or gateway counts as strict-Rust native implementation.'),
'U01': (' Define record schema, publication state machine, bounded scanner and old/new-state recovery oracle; tombstone generations prevent normal recovery resurrecting revoked identities.', ' Inject failures before/after each write/sync/publication and torn-record boundary: recover complete old or new value, never mixed credentials/calibration. Test capacity, checksum, malformed length, schema, failed sync and revocation. Physical rollback resistance remains separate.'),
'G01': (' Own shared source arbitration across all adapters with explicit replace/reject policy per command class.', ' Concurrent starts/seeks/group changes admit one source epoch. Replaced sources cannot publish. Fault/local mute priority dominates remote unmute.'),
'N02': (' Own peer key admission/revocation and group-epoch key binding through U01; ephemeral synthetic pairing is allowed only in tests.', ' Check authentication before authority-bearing mutation.'),
'N01': (' Define authentication coverage over timing/epoch/format and payload.', ' Reject mutation before scheduling or DSP; cap untrusted parsing work.'),
'G03': (' Declare local legacy-SOAP compatibility access policy; tailnet ingress must use authenticated command authorization.', ''),
'Q01': ('', ' Race two real adapter interfaces replacing sources and retrying relative volume; assert sample/state revisions.'),
'Q04': ('', ' Repeat combined peak memory/CPU/deadline qualification with all enabled native services simultaneously, pairing/reconnect/key rotation and background control load. Repeat source arbitration for each adapter. Isolated component success is insufficient.'),
'E04': (' Include retained radio/Wi-Fi driver capabilities, mesh dependencies and scheduler interference in the offline contract matrix; do not assume stock radio behavior survives daemon replacement.', ' External human qualification must include multicast/unicast, power-save, roam and congestion behavior; no live test here.')
}
newrows=[]
for k,t,d,s,a in rows:
 extra=review2.get(k,('','')); d=d+(['P02'] if k=='N03' else [])+(['U01'] if k=='N02' else [])
 newrows.append((k,t,d,s+extra[0],a+extra[1]))
rows=newrows

# Fresh-review amendments are explicit source data, applied before rendering.
amendments=json.loads((ROOT/'docs/planning/fresh-review-amendments.json').read_text())
newrows=[]
for k,t,d,s,a in rows:
 u=amendments['updates'].get(k,{})
 for old,new in u.get('scope_replace',{}).items():
  s=s.replace(old,new)
 newrows.append((k,u.get('title',t),list(dict.fromkeys(d+u.get('deps_add',[]))),u.get('scope',s)+u.get('scope_append',''),u.get('acceptance',a)+u.get('acceptance_append','')))
rows=newrows+[(x['key'],x['title'],x['deps'],x['scope'],x['acceptance']) for x in amendments['new_tasks']]
tasks=[]
for key,title,deps,scope,accept in rows:
 tasks.append(dict(key=key,title=title,deps=deps,scope=scope,acceptance=accept))
Path('docs/planning/task-catalog.json').write_text(json.dumps(tasks,indent=2)+'\n')
header='''# FrankenFirmware slim speaker implementation plan

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
'''
header+='''
## Milestones and canonical task keys

M1 is the offline mixed-generation Spotify candidate: Q01/Q02 execution evidence and Q03/U03 human handoff.
Hardware qualification is separately pending until authorized external receipts exist.
M2 is Q04 offline combined qualification, then externally evidenced Q06 and Q05 release handoff; no optional gateway/FEC/local-voice prerequisite.
N05/N06, T03 and X03 are retained optional branches with profile-specific qualification.
The canonical task keys below own completion; R01-R15 and INT-001-018 are mapped design packages, not duplicate issues.
The full runtime and integration specifications follow the task catalog in this document.

'''
parts=[header]
for t in tasks:
 consumers=[x['key'] for x in tasks if t['key'] in x['deps']]
 parts.append(f'''### {t['key']} — {t['title']}

Purpose: deliver one bounded increment toward the owner's reliable unified speaker appliance.
Required inputs: {', '.join(t['deps']) if t['deps'] else 'owner scope, sanitized inventory and existing evidence registry'}.
Blocks: {', '.join(consumers) if consumers else 'release readiness and future maintenance'}.
Scope: {t['scope']}
Acceptance: {t['acceptance']}
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

''')
for companion in ('SLIM_RUNTIME_DESIGN.md','SLIM_INTEGRATIONS_DESIGN.md'):
 parts.append('\n# Detailed specification: '+companion+'\n\n'+Path('docs',companion).read_text())
Path('docs/SLIM_SPEAKER_PLAN.md').write_text('\n'.join(parts))
