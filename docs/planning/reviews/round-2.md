# Plan review round 2 — remaining readiness and security contracts

Status: proposed bounded corrections only; no plan or catalog edits in this pass.
Reviewed the revised canonical catalog, milestone/task text, and embedded runtime/integration designs.
Also checked graph closure programmatically; this was a planning-data check, not a runtime test.
The 46-key catalog has no dangling dependencies or cycles.
Q03 closure excludes N05/N06, T03, X03, AirPlay, video, and line-in.
Q05 closure excludes optional N05/N06, T03, and X03 while including native Tailscale and X04 Alexa music routing.
Round-1 milestone corrections are accepted; no further restructuring is needed.

## 1. N03 lacks its actual platform clock prerequisite

Observation: N03 depends on N01/D03, neither of which depends on P02.
N03 needs the admitted timer/monotonic-clock contract to implement uncertainty and wakeup behavior.
A pure mathematical estimator can begin without P02, but the complete task cannot qualify target timing without it.

Exact correction:
- Set N03 deps to `[N01,D03,P02]`.
- Add scope: "Consume P02 monotonic-clock resolution/wrap/failure contract, N01 timestamp encoding, and D03 sample-position/rate interface. Produce clock transform plus uncertainty, admissible start deadline, and stale-clock status for N04/G01."
- Add acceptance: "Use synthetic asymmetric-delay and oscillator-drift traces with predeclared confidence/expiry bounds; report estimator error independently of physical DAC skew. Missing target clock capability blocks native timing qualification."

This is a direct missing input, not a request for a new subsystem.

## 2. T01 must be a terminating feasibility decision

Observation: T01 currently requires exact legacy build and memory measurements even if every candidate is incompatible.
A feasibility task should close on a well-supported rejection while leaving the implementation requirement blocked.
Otherwise the investigation itself becomes impossible to complete honestly.

Exact correction:
- Add T01 outputs: "Per-target candidate decision table with pinned revision, implemented protocol scope, kernel/ISA needs, transitive Rust/FFI boundary, measured resources where executable, and exact blocking evidence otherwise."
- Amend acceptance: "A reproducible negative feasibility result closes the investigation but leaves T02 and the native requirement blocked; it does not waive them. Compile-only results are labeled separately from guest execution and real-tailnet interoperability."
- Add test inputs: "Synthetic identity/network-map/relay/key-expiry fixtures; no real credentials or enrollment performed in offline probes."
- Add failure contract: "Do not select a gateway or Go reference client as completion of strict-Rust endpoint implementation; retain them as explicitly labeled comparisons or optional modes."

No new dependency is necessary beyond E06/P02.

## 3. U01 needs a precise recovery oracle

Observation: namespace separation and capacity/wear requirements are now present.
"Power-cut simulation across every publication step" still does not specify what state is acceptable after recovery.

Exact correction:
- Add outputs: "Versioned record schema, publication state machine, bounded recovery scanner, and old/new-state recovery oracle."
- Add acceptance: "Inject interruption before and after each write/sync/publication boundary and each supported torn-record boundary. Recovery returns either the complete prior committed value or complete next committed value, never mixed credentials/calibration."
- Add acceptance: "Test capacity exhaustion, malformed length, checksum failure, unsupported schema, failed sync, interrupted revocation, and repeated reboot; rejected writes preserve the last valid state."
- Add scope: "Revocation generation/tombstone semantics must prevent automatic resurrection through normal crash recovery; physical rollback resistance is a separate unproven property."
- Add boundary: "Do not assume rename/fsync or byte programming atomicity absent P02/E05 filesystem evidence."

These changes make an obscure task implementable without inventing its consistency model.

## 4. Shared source arbitration is specified but has no canonical implementation owner

Observation: embedded INT-017 explicitly owns cross-adapter arbitration.
Canonical G01 mentions selected source ownership; G03 is framed mainly as SOAP/GENA compatibility.
No catalog acceptance currently requires the conflicting-controller cases from INT-017.

Exact correction:
- Add G01 scope: "Own shared source arbitration for Spotify, AirPlay, local controls, Alexa, and tailnet adapters; specify replace/reject and last-writer policy per command class."
- Add G01 acceptance: "Concurrent source start/seek/group-change requests yield at most one admitted source epoch. A stale source cannot publish after replacement; physical/fault mute dominates remote unmute according to explicit priority."
- Add Q01 acceptance: "Exercise two real adapter interfaces racing source replacement and relative-volume retries; assert samples and state revisions, not only accepted-command responses."
- Add Q04 acceptance: "Repeat arbitration scenarios with every enabled native adapter; source-service failure must not create an unowned renderer."

No additional task or broad dependency fanout is needed.

## 5. Pairing persistence and clock authentication need an explicit trust boundary

Observation: N02 claims authenticated pairing but lacks U01, while other durable adapters now have it.
N03 clock probes can influence audible group behavior; the task says nothing about unauthorized timing inputs.
The intended authenticated transport is useful but not a complete identity lifecycle contract.

Exact correction:
- Add U01 to N02 deps for durable pairing completion; ephemeral synthetic pairing may be used in unit tests beforehand.
- Add N02 scope: "Specify peer-key creation/admission/revocation and group-epoch key binding; persist pairing through U01. Authentication is checked before authority-bearing mutations."
- Add N03 acceptance: "Reject timing probes from unadmitted peers, replayed sessions, stale epochs, and out-of-window sequence values; bound unauthenticated parsing/work before verification."
- Add N01 acceptance: "Define authentication coverage over immutable timing/epoch/format fields and payload; reject mutation before handing data to scheduling or DSP."
- Add G03 boundary: "Preserving legacy unauthenticated SOAP compatibility does not grant arbitrary remote trust; declare the local compatibility access policy and keep tailnet access behind authenticated command authorization."

Adding N02 -> U01 does not create a cycle: U01 depends only on P02/E05.

## 6. Companion IDs still lack an actual crosswalk

Observation: main text says R/INT design packages are mapped, but names no explicit mapping table.
Exact correction: add a compact canonical-key crosswalk before Beads creation.
At minimum identify INT-017 -> G01/G03/Q01/Q04 and R10 -> D03/N03/P02.
Do not create duplicate issues for companion IDs.
This can be a planning artifact; it need not expand the implementation graph.

## Exit and unchanged decisions

Retain M1 as an offline Spotify candidate and human handoff, never a hardware-qualified product claim.
Retain M2 and optional branches as revised in round 1.
No new product capability, hardware action, or service requirement is proposed.
After edits, rerun cycle/dangling checks and inspect N03/T01/U01 Beads text standalone.
A negative feasibility result must be distinguishable from unmet implementation acceptance.
MOR support: E001 for requirement scope, E002 for offline/secret boundaries, E005 for runtime capability qualification,
E009/E010 for resource and timing limits; graph observations above come directly from the revised catalog.
