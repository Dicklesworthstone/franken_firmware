# Qualification-target and T01 follow-up audit

Reviewed 2026-11-04: `docs/planning/QUALIFICATION_TARGETS.md`, the T01 generator entry and enrichments in `docs/planning/build_task_catalog.py`, and the corresponding working-tree catalog and plan. This is a static planning audit, not a feasibility, performance or interoperability result.

**Disposition: safe to incorporate as a provisional experiment contract, with the A/V percentile correction below.** The document explicitly distinguishes chosen acceptance thresholds from measured results, requires profile freezing, preserves failed results, and separates host, guest, service and physical evidence. Neither 500 ms buffering, the skew targets, the 4 MiB reserve nor the 25% timing reserve is presented as proven achievable or sufficient for every workload. No new feasibility claim is warranted by this review.

## Required narrow correction

Replace `abs(p99) <= 40 ms` for signed A/V residual with **`p99(abs(residual)) <= 40 ms`**, stating residual sign convention and reporting both signed tails and maximum absolute residual. Taking absolute value after a signed percentile can hide a large negative tail: 98% of residuals at -200 ms and 2% at +10 ms can have a signed p99 of +10 ms while nearly all observations fail a 40 ms absolute-error target. This is a statistical-definition error, not a claim that the numerical target is wrong. Quantiles must use a declared estimator and sampling denominator.

## Clarifications needed before an executable profile is frozen

- Define render timing reserve relative to the interval from block release to its required device submission deadline. A testable version is `maximum observed release-to-submission latency <= 0.75 * available interval`, with the submission deadline itself tied to the device presentation contract. State whether queueing, preemption and driver-call time are included; CPU execution time alone can pass while wall-clock deadlines miss. This remains a sampled campaign result, not a worst-case execution-time proof.
- Specify whether 50 ms added jitter means maximum, distribution scale or another quantity; freeze packet size, reorder depth/frequency and duplicate frequency. Independent loss and burst loss are separate named conditions as already required. A 500 ms horizon is not by itself proof that every loss case is recoverable.
- Define synchronized-output skew as an absolute paired-output timing error, document instrument uncertainty and pairing/sampling, and report each board pair. Keep startup/relock exclusion durations and mute failures visible. The 2/5 ms targets do not establish stereo/Sub acoustic acceptability; those profiles need their own criteria.
- Compute the 4 MiB reserve against actual available capacity using consistent units and a non-overlapping memory accounting model. Sum neither shared resident pages twice nor DMA already included in kernel accounting. A measured campaign maximum is not a universal upper bound; preserve workload limits and residual uncertainty.
- Declare the number of independent runs and samples used for p99.99 latency. Reporting a percentile on too few samples adds no useful tail evidence; keep maxima and misses even when a percentile is not estimable. The existing denominator requirement supports this clarification.

These clarifications can be filled during profile registration; they do not require an additional hardware investigation now. Loss/concealment tolerances and tailnet budgets are explicitly pending and must remain pending until declared. The document is a planning contract, not a runnable completed test specification.

## T01 self-containment follow-up

The expanded generator addresses the prior review's major gaps: it names owned feasibility/profile/fixture/receipt paths, pins candidate identities, requires protocol and kernel/ISA comparisons, preserves resource blockers, and distinguishes negative feasibility completion from native-feature completion. The enriched catalog embeds the native membership contract and dependency descriptions, and links INT-010. Combined enabled-service admission remains at Q04, so isolated T01 success does not promise endpoint headroom.

**T01 is now sufficiently specified to begin the bounded offline feasibility assessment.** It is not prequalified for native implementation or service completion. A negative result may close the investigation while T02 and native support remain blocked, as the revised acceptance explicitly states. Before fixture work, the implementer must freeze case parameters and candidate-specific expected outcomes in its owned contract. Those are task outputs rather than missing user decisions.

At inspection time, the generator contained the latest explicit `docs/tailscale/`, fixture and receipt paths, while the plan/catalog snapshot still had the preceding T01 scope. Regenerate the derived artifacts before publishing or creating task bodies; confirm those bodies include the detailed contract and input descriptions. If the catalog is the complete execution input, a short task title alone must not replace it.

No canonical audit status is upgraded here. The original C007 FEC option remains a hypothesis until comparisons exist; the new target document merely makes future experiments more discriminating. No devices, external services, keys or private captures were accessed.
