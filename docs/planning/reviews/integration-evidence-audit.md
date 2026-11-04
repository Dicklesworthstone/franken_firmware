RESULT_STATUS: MATERIAL_INCREMENT

# Integration challenger: decision audit

Reviewer: integration-plan child agent, acting as challenger on the composed plan.
Independence limitation: this reviewer authored SLIM_INTEGRATIONS_DESIGN.md; this is a fresh adversarial pass, not an independent second author of that document.
Scope: MOR_CASE.md, SLIM_SPEAKER_PLAN.md, SLIM_RUNTIME_DESIGN.md, SLIM_INTEGRATIONS_DESIGN.md, task-catalog.json, pinned inspection of fsonos-proto control helpers, primary-source integration documentation consulted during this session.
No hardware, accounts, unlock routes, or live devices were exercised.

## Atomic findings

### IC-01 — Alexa music destination has research ownership but no explicit implementation exit

Claim: the main plan's X01 identifies music-destination/provider authorization, while X02's implementation scope only names commands, discovery, state reporting, and group/volume/mute actions.
Evidence: docs/SLIM_SPEAKER_PLAN.md:858-886; docs/SLIM_INTEGRATIONS_DESIGN.md:252-265; E001.
Consequence: X01/X02 can pass and Q04 can be reached without an actual supported voice-to-Spotify destination path.
Materiality: medium/high feature-completeness gap; a named Spotify Connect endpoint is not sufficient evidence for Alexa music routing.
Revision: add an explicit Alexa music-routing implementation/qualification task, or expand X02 with a separately tracked acceptance condition and a blocked disposition if provider admission is unavailable.
Discriminator: documented supported integration mechanism plus a future owner-operated utterance-to-selected-room/group playback receipt; offline directives alone do not settle it.
Defeater: a task or acceptance row already explicitly implementing this path and gating the feature-completion ledger would remove the gap.
Primary reference: https://developer.amazon.com/docs/alexaplus/device-apis/alexa-speaker covers volume/mute; it is not evidence for music routing.

### IC-02 — Optional gateway is currently a mandatory final qualification dependency

Claim: Q04 requires T03 even though T03 is explicitly an optional gateway service mode.
Evidence: docs/SLIM_SPEAKER_PLAN.md:836-842 and 1078-1085; task-catalog.json T03/Q04 dependencies.
Consequence: a fully native implementation can be held behind an unneeded gateway, contradicting the native-first product decision and increasing work before a useful release.
Revision: require T02 for native completion; validate T03 only for a release profile enabling gateway support. Record optional-feature exclusions in the matrix without closing native tasks with gateway receipts.
Discriminator: dependency graph admits a native-only integration qualification profile while still retaining gateway tasks.
Defeater: explicit product decision that redundant gateways are mandatory even when native nodes all qualify would justify the existing edge; no such instruction was found.

### IC-03 — Local voice feasibility is unnecessarily downstream of Alexa implementation

Claim: X03 requires X02, while the companion design correctly states that local voice is a separate path from Alexa Voice Service.
Evidence: docs/SLIM_SPEAKER_PLAN.md:902-909; docs/SLIM_INTEGRATIONS_DESIGN.md:282-297.
Consequence: unavailable cloud/partner integration could block independent offline microphone/model/compute/privacy feasibility work.
Revision: depend on verified microphone-board evidence, HAL capture, bounded runtime, and shared command contract rather than Alexa adapter completion.
Discriminator: local voice feasibility is ready once hardware evidence and offline capture interfaces exist, even when Alexa music routing is blocked.
Defeater: a specific implementation dependency requiring X02 code rather than merely shared command types would justify the edge, but should be named.

### IC-04 — Three task namespaces need an explicit mapping to prevent completion gaps

Claim: main plan tasks use E/P/D/N/G/S/A/V/T/X/L/U/Q keys; runtime uses R01-R15; integration uses INT-001-INT-018, with no mapping in the inspected documents.
Evidence: docs/SLIM_SPEAKER_PLAN.md:127 onward; SLIM_RUNTIME_DESIGN.md section 17; SLIM_INTEGRATIONS_DESIGN.md section 12; task-catalog.json.
Consequence: source-specific acceptance details can disappear when only the main catalog becomes Beads. Examples include INT-016 exact fsonos call-site extraction and INT-005 Spotify reconnect-resource scenarios.
Revision: create a stable companion-to-catalog mapping and add companion sections as acceptance references to every affected bead. This is a mapping need, not a recommendation to create duplicate tasks.
Discriminator: every R/INT key maps to one or more Beads task IDs, with unmapped requirements explicitly listed and resolved.
Defeater: a generated mapping already present outside the inspected files would resolve this finding after validation.

### IC-05 — Spotify service and internal codecs need a negotiated-format acceptance row

Claim: S02's title singles out Vorbis, while companion design warns against assuming the provider always supplies a particular encoded format.
Evidence: docs/SLIM_SPEAKER_PLAN.md:660-669; docs/SLIM_INTEGRATIONS_DESIGN.md:98-104.
Consequence: an implementer could treat AAC/ALAC/internal Opus as vague optional follow-up despite selected AirPlay or media profiles requiring specific formats. Conversely, forcing all codec names into every build would defeat slimming.
Revision: bind decoder requirements to actual negotiated service profiles, identify which are mandatory per profile, and keep internal transport codec selection separate. Rename S02 or strengthen its acceptance text to remove the provider-format assumption.
Discriminator: pinned client/profile negotiation fixtures select supported codecs; unsupported negotiated formats fail explicitly without allocation or audible garbage.
Defeater: current pinned client and selected scope demonstrably require only Vorbis, with other source profiles separately owning their codecs; record that evidence if so.

## Supported corrections that survived challenge

IC-S1: Native Tailscale is explicitly broader than WireGuard/proxy/gateway. Main T01/T02 and integration section 6 preserve identity/control/NAT/relay/key lifecycle and measure rather than assume footprint. Tailscale userspace documentation describes a proxy operating mode, not a tiny Rust native client: https://tailscale.com/docs/concepts/userspace-networking.
IC-S2: Video scope explicitly separates application-controlled AirPlay timing, desktop helper control, and uncontrolled analog/system paths. No universal automatic iPhone YouTube correction is asserted. Main V01/V02 and integration section 5 require source-specific receipts.
IC-S3: Memory arithmetic is correctly separated from RSS and achievable source prefetch. The shared plan and both companion documents reject the pasted 1.15 MB/2.8 MB/19 MB performance claims as unmeasured.
IC-S4: Native integrations remain goals rather than capability silently discarded for a host. This is consistent across all three documents, subject to IC-02's graph correction.
IC-S5: fsonos compatibility is distinguished from proprietary stock/custom media interoperability. SOAP compatibility alone does not promise one transport group containing untouched stock endpoints.

## Decision recommendation

Retain the slim retained-driver architecture and native-feature ambition.
Revise the dependency and coverage graph using IC-01 through IC-05 before calling the Beads plan complete.
Do not infer hardware success, provider interoperability, memory fit, or end-to-end latency from this audit.
The most valuable early integration experiment remains a minimal native source/profile dependency probe plus realistic combined peak-resource scenarios on the oldest admitted ABI.
