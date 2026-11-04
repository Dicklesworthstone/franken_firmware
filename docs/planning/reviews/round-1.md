# Plan review round 1 — dependency integrity and first useful milestone

Status: review proposals only; reviewed plan files are unchanged by this pass.
Reviewed: AGENTS.md, SLIM_SPEAKER_PLAN.md, SLIM_RUNTIME_DESIGN.md,
SLIM_INTEGRATIONS_DESIGN.md, task-catalog.json, and root MOR_CASE.md.
No device access, implementation, provider interaction, or runtime qualification occurred.

## Finding 1 — optional FEC currently blocks every budget qualification

Observation: Q02 depends on N06, and N06 requires implementing FEC.
N05 explicitly permits selecting a simpler repair strategy.
The runtime design R09 also explicitly accepts a no-FEC outcome.
These contracts conflict: an honest no-FEC experiment cannot satisfy mandatory N06 implementation.
Severity: high; this can stall the first Spotify milestone without product justification.

Proposed exact changes:
- Change Q02 deps from `[Q01,N06,D04]` to `[Q01,D04]`.
- Add Q02 acceptance: "Record the selected recovery profile; no-FEC is a valid baseline. Repeat budget qualification when an optional FEC build is admitted."
- Keep N05 and N06 as an optional improvement branch.
- Add N06 scope: "Only implement if N05 admits a measured FEC profile; a no-FEC selection leaves this optional capability deferred, not falsely implemented."
- Add optional-profile qualification to Q04 scope without adding a mandatory N06 edge.

Rationale: prototype and measure a simple bounded renderer before adding repair complexity.
Evidence: MOR E009 supports representation-aware budgets; E010 supports finite live deadlines.
Neither item establishes that FEC will win on these processors.

## Finding 2 — first Spotify qualification is blocked by video and line-in

Observation: Q03 is the Spotify acoustic/network qualification package but depends on V02 and L01.
V02 additionally depends on A02; this pulls native AirPlay into the Spotify critical path.
The main plan says first mixed-generation Spotify, then qualify additional integrations individually.
Severity: high; dependency graph contradicts rollout sequencing.

Proposed exact changes:
- Change Q03 deps from `[Q02,V02,L01]` to `[Q02,U03]`.
- Keep Q03 as a written owner-run Spotify qualification package, not hardware execution here.
- Add Q03 acceptance: "Cover baseline mixed-generation Spotify, volume, join/leave, source restart, supported loss envelope, and return-to-stock. Publish exact predeclared thresholds and pending physical gates."
- Change Q04 deps to `[Q03,T02,X02,A02,V02,L01]`.
- Add a named milestone M1: "Spotify offline candidate: Q01 and Q02 evidence plus Q03/U03 handoff; no hardware-ready claim without external receipts."
- Add M2: "Full requested native integration qualification: Q04 plus Q05; optional profiles reported independently."

Rationale: this preserves full scope while making the first useful product independently reviewable.
Evidence: MOR E001 and the MOR decision horizon explicitly prioritize Spotify before other integrations.
MOR E002 requires the distinction between a qualification package and actual device qualification.

## Finding 3 — optional gateway is a mandatory native-product blocker

Observation: Q04 depends on T03 although T03 is explicitly optional redundant gateway mode.
The requirement is native Tailscale, whose implementation task is T02.
Severity: medium; unnecessary work and potential scope substitution.

Proposed exact changes:
- Remove T03 from mandatory Q04 deps as specified above.
- Add Q04 acceptance: "Qualify any enabled optional gateway profile separately; absent optional gateway does not close or block native Tailscale evidence."
- Retain T03 as discoverable optional work with T01/G01 prerequisites.
- Keep X03 optional and outside Q04/Q05 mandatory completion; explicitly report its deferred status.

Rationale: native requirements must neither be satisfied by gateways nor be held hostage to them.
Evidence: MOR E001 preserves native goals; no MOR observation proves native Tailscale is feasible yet.

## Finding 4 — incumbent baseline E02 is orphaned

Observation: no catalog task depends on E02, while its generated prose says it blocks release readiness.
The comparison against stock dropouts needs a consumer and explicit unavailable-baseline handling.
Severity: medium; evidence gathering can be forgotten while claims of improvement remain tempting.

Proposed exact changes:
- Add E02 to Q03 deps, yielding `[Q02,U03,E02]`.
- Clarify E02 scope: "Produce offline analysis schema, human-run baseline recipe, and analysis of existing lawful captures if available; separately mark missing measurements."
- Add E02 acceptance: "Task completion certifies the package, not live baseline capture. Missing comparative measurements bar quantified improvement claims, but do not bar absolute acceptance tests."
- Add Q03 acceptance: "State whether incumbent measurements exist and whether improvement or only absolute qualification can be assessed."

Rationale: no live measurement is authorized here, so a mandatory live-baseline implementation gate would be wrong.
The package and provenance must nonetheless reach the milestone that consumes them.
Evidence: MOR E008 rejects RSS inference from file sizes; E009 gives arithmetic but not free memory.

## Finding 5 — shared persistent credential state is absent from adapter dependencies

Observation: S01 and A01 include secure state/pairing persistence; T02 includes key lifecycle.
Their graph omits U01, the only concrete persistent-state task.
The integrations design INT-011 correctly names a durable secret-state interface prerequisite.
Severity: medium; parallel agents can invent incompatible or unsafe storage schemes.

Proposed exact changes:
- Add a persistent-secret interface contract to P01, with ephemeral test implementation permitted.
- Add U01 to S03, A02, and T02 deps for integration completion.
- Extend U01 scope with credential namespace separation, replace/revoke semantics, permissions, secret-redacted error paths, and crash-consistent updates.
- Preserve calibration separately; a crash-safe journal does not automatically provide encrypted or hardware-backed key protection.

Rationale: interface-first work can proceed before storage implementation, but persistence claims require it.
Evidence: MOR E002 excludes public secrets; this storage design is a recommendation rather than an observed implementation.

## Finding 6 — companion task namespaces are not mapped to the canonical graph

Observation: runtime R01–R15 and integrations INT-001–INT-018 use separate dependency labels.
Some dependencies are prose such as RUNTIME, HAL, and "session/frame schemas."
Main plan promises self-contained Beads tasks, but generic repeated text does not resolve these references.
Severity: medium; obscure tasks could omit required inputs or be duplicated.

Proposed exact changes:
- Declare task-catalog keys canonical and companion IDs explanatory design work packages.
- Add a crosswalk table before task conversion, including one-to-many mappings where needed.
- Example: R09 -> N05; R12 -> D04/N04/G01/Q01; INT-010 -> T01; INT-011 -> T02/T03/U01.
- Replace opaque "Required inputs: P03,N02" with IDs plus artifact contract names in Beads descriptions.
- For N03 include clock capability interface, wire timestamp representation, sample-origin mapping, uncertainty thresholds and output consumed by N04/G01.
- For U01 include supported persistence semantics, fixed capacity/write-rate bounds, publication order, power-cut test matrix, and what remains pending on real flash.
- For each task identify owned outputs, exact failure behavior, minimum tests, and evidence level; do not rely on a repeated global paragraph for all implementation context.

Rationale: graph references are useful for ordering but insufficient as implementation specifications.
Evidence: MOR success contract requires self-contained dependency-aware tasks; E005 supports explicit runtime dependency audits.

## Finding 7 — inconsistent render qualification prerequisites

Observation: Q01 depends on G03/S03 but not D04, although it claims multiple renderers and sample assertions.
Q02 adds D04 later; this permits a virtual-house success claim without the actual render composition.
Runtime R15 requires R14 (video timing) and R09 (FEC selection), again tying baseline acceptance to optional/later work.

Proposed exact changes:
- Add D04 to Q01 deps.
- Split runtime R15 acceptance into baseline renderer campaign and feature-profile reruns.
- Baseline depends on R12/R13; R14 and R09 only when corresponding modes are enabled.
- Distinguish early harness skeleton construction from completion against composed production interfaces.

Rationale: avoid both an under-integrated baseline and unnecessary feature critical paths.
Evidence: MOR E011 warns that success language requires actual receipts, not merely documentation.

## MOR observations versus recommendations

Observation O1: incompatible PPC/MIPS families require separate artifacts; evidence E004/E008.
Observation O2: compressed and PCM representations consume different bytes per second; evidence E009.
Observation O3: sample period and causality constrain synchronization claims; evidence E010.
Observation O4: existing driver object size is not process RSS; evidence E008.
Observation O5: current task graph contains the edges named above; evidence is task-catalog.json itself.
Observation O6: MOR E011 is time-bound and must be refreshed before repeating absent-receipt claims.
Recommendation R1: decouple Spotify acceptance from video/AirPlay/line-in; rationale E001 plus graph finding 2.
Recommendation R2: keep FEC and gateway optional; rationale graph findings 1/3, not proof those features fail.
Recommendation R3: make E02 a comparative-evidence consumer prerequisite; rationale E008/E009.
Recommendation R4: retain native integrations as open gates when resources fail; rationale E001.
Recommendation R5: place persistence interface and acceptance dependencies explicitly; rationale E002 plus contract mismatch.
None of these recommendations establishes target RAM, provider compatibility, real driver safety, or acoustic timing.

## Review exit

Apply accepted changes to catalog and generated main plan together.
Recompute graph closure for M1 and M2; verify optional N06/T03/X03 are absent from mandatory M1/M2 closure.
Verify all native requirements remain represented in M2 and deferred optional requirements remain visible.
Audit orphan tasks by intended optionality rather than requiring every task to block release.
Run a cycle/dangling-reference check and inspect three obscure task descriptions independently.
No product code or device execution is required to close this review round.
