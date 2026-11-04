# Decision Contract

Question: What material defects remain in the slim retained-kernel speaker plan, and which bounded technical innovations improve reliability/fit without substituting away the requested features?
Owner: hardware owner. Horizon: first mixed-generation Spotify candidate, then complete native integrations.
Scope: fresh design/issue/source review, offline calculations/probes, plan/task corrections. No device actions, firmware installation, unlock research or provider enrollment.
Loss: avoid wrong ABI/acoustic assumptions, unimplementable task dependencies, false native equivalence and resource/latency promises; preserve existing work and user intent.
Reversibility: specifications and task structure remain reversible; proposed mechanisms require measured promotion criteria.
Success: audited actionable findings and testable ideas, corrected plans/Beads, reproducible checks, no manufactured disagreement.

## Evidence Index

- E001: Owner's latest request and quoted desired design: retain kernel/audio/radio drivers, reduce service surface, common protocol and native features. Numerical/causal claims are hypotheses.
- E002: Current AGENTS.md: offline-only work, private-data exclusion, protected concurrent work, runtime receipts required.
- E003: docs/SLIM_RUNTIME_DESIGN.md, initial content snapshot manifest in this run: runtime, HAL, clocks, transport, failure design.
- E004: docs/SLIM_INTEGRATIONS_DESIGN.md: source/service protocols and product contracts.
- E005: docs/planning/build_task_catalog.py, enrich_catalog.py, render_bead_bodies.py, render_planning.py, section-map.json and check_planning.py: generated plan/issue source pipeline and offline consistency validation; input-manifest preserves pre-amendment identities.
- E006: actual br issue export .beads/issues.jsonl and docs/planning/bead-map.json: completion/dependency graph.
- E007: docs/planning/QUALIFICATION_TARGETS.md: provisional campaign thresholds, not measurements.
- E008: FIRMWARE_ASSESSMENT.md and inventory/INVENTORY.md: attributed artifact identities and nominal resources; exact boards/SoCs are not universally verified.
- E009: sibling asupersync/franken_kernel and runtime sources; frankenlibc/frankenfs/franken_remote actual dependency contracts as inspected by assigned reviewers.
- E010: Transparent queue/copy/airtime/frame/phase arithmetic and standalone counterexample scripts stored under this run repro directory.
- E011: research/slim-speaker prior evidence/handback: one completed NTM source investigation and explicitly incomplete pair pipeline; not additional hardware evidence.

- E012: Owner steering this pass: Asupersync and all Franken suite libraries may be changed. Dependency incompatibilities are candidates for upstream adaptation, not immutable exclusions.

- E013: This run repro/driver-metadata.txt: fresh file/wc/strings inspection of retained model-16 audio module; 77380 bytes, ELF32 BE PPC, CS44800/audioctl/dsp_dev/m8260 symbols. Static symbols do not establish active board behavior.

## Pivotal Unknowns

Board-specific protection/calibration; legacy syscall/atomic/runtime support; joint native-service resource fit; radio behavior and congestion; clock/phase measurement; actual provider interoperability; safe process ownership/recovery.

## Source Access

Read local source, public primary documentation and synthetic planning inputs only. No live hardware/network experiments or install-path investigation. Archived prior root artifacts preserve the earlier run. Independent reviews may return checked nulls.
