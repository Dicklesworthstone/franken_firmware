# Beads polish pass 6 — stored feature and acceptance audit

RESULT_STATUS: MATERIAL_INCREMENT

Read AGENTS.md before review. No Beads mutations, device operations, or plan edits were made.
This review queried the actual store using `RUST_LOG=off br list --json` and `br show <id> --json`.
All 46 IDs in docs/planning/bead-map.json were individually read through `br show`.
The stored graph contains 46 open tasks and 99 blocking dependency edges.
Recursive traversal found no cycle or unmapped dependency ID.
This is task-data validation, not firmware or integration test execution.

## One material correction

Stored N01 through N06 contain two different proposed room-skew thresholds without precedence:

- Embedded clock design: "The initial proposed room-group objective is at most one millisecond p99 skew."
- Appended qualification targets: electrical-output relative skew "p99 <= 2 ms and maximum <= 5 ms".

Affected IDs: N01 ffw-ey5, N02 ffw-ugf, N03 ffw-u07, N04 ffw-nx0, N05 ffw-8cy, N06 ffw-re8.
Both are explicitly provisional, so neither is a false measured-performance claim.
However an implementer cannot tell which threshold governs passing the same room-group qualification.
The issue matters because it changes whether a measured 1.5 ms p99 result passes.

Minimal requested correction: designate the versioned 2 ms p99/5 ms maximum profile as baseline,
and explicitly label 1 ms p99 as a stretch objective that does not override baseline acceptance,
or choose one consistent baseline in both locations. Keep separate tighter pair/Sub requirements.
Update the source design/enrichment text and affected stored descriptions together to prevent regeneration drift.
Do not relax a threshold after a measurement; this is resolution before any experiment.
No additional feature or broad graph restructuring is requested.

## Actual stored issue checks

| Key and issue | Observed stored behavior | Disposition |
| --- | --- | --- |
| S03 ffw-mxt | Depends on S01/S02/N04/U01; native and optional coordinator roles explicit; bytes versus seconds and provider-limited prefetch retained | Preserved |
| T02 ffw-rjy | Depends on T01/N02/U01; full node identity/control scope, access denial, expiry, relay and rotation tests; local audio survives WAN loss | Preserved |
| T01 ffw-32a | Negative feasibility can close investigation while native implementation stays blocked; neither Go reference nor gateway satisfies strict-Rust native | Preserved |
| X04 ffw-myi | Depends on X01/X02/S03/G01; requires supported routing mechanism and later utterance-to-group receipt; volume-only success cannot close it | Preserved |
| Q04 ffw-t9c | Depends on Q03/T02/X02/X04/A02/V02/L01; combined native-service peaks and cross-adapter arbitration required | Preserved |
| A02 ffw-caw | Pairing, transport, crypto and timing scope remains native; ignored sender delay is unqualified for automatic sync | Preserved |
| V02 ffw-8mr | Source-specific seek/pause/rate/route acceptance; no universal iPhone-video correction claim | Preserved |
| X03 ffw-5lj | Depends on E01/P04/P03/N02, with no Alexa implementation prerequisite; microphone/privacy/model budget retained | Preserved |

## Required versus optional graph

Q03's stored transitive closure contains Spotify, rendering, grouping, durable state and activation handoff.
It excludes AirPlay/video/line-in/Tailscale/Alexa and optional FEC/gateway/voice.
Thus the first offline mixed-generation Spotify candidate does not wait for unrelated integrations.

Q05's stored closure includes native AirPlay, video, Tailscale, Alexa control and music routing, and line-in.
It excludes optional N05/N06, T03 and X03.
The full feature campaign cannot substitute gateway completion for native Tailscale completion.
Local voice feasibility is retained without blocking the full mandatory campaign.
Existing fsonos compatibility and bounded group volume/mute remain in the baseline closure.
No requested feature was found missing from stored issues.

## Acceptance specificity

Actual stored issues include detailed contracts, explicit inputs/outputs, fault cases and evidence boundaries.
The appended provisional target profile supplies a concrete 24-hour clean-network baseline,
seeded loss/burst/jitter scenarios, resource reserve policy, render deadline accounting,
and a source-cooperative video residual objective. These remain proposed test criteria.
Source-specific interoperability still requires its own future authorized receipt.
Synthetic contracts and guest execution cannot close physical-output or cloud-service claims.
Native Tailscale memory fit is correctly pending until a complete profile budget is allocated and measured.

Apart from the conflicting skew threshold above, this pass found no new material feature-coverage or graph defect.
