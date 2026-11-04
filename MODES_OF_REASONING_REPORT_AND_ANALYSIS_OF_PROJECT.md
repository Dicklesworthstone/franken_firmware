# Slim speaker design: fresh evidence review

Run: `20261104T204109Z`. Scope: design, dependency source, offline counterexamples and task consistency. No firmware implementation, device execution, provider enrollment or acoustic qualification occurred.

The retained-kernel, slim Rust userspace architecture remains a useful engineering direction. The review makes it more concrete; it does not establish that every requested native service fits the oldest player. The owner permits changes to Asupersync and every Franken library, so upstream adaptation is now explicit planned work. The plan preserves endpoint-native requirements rather than calling a gateway an equivalent implementation.

## Material corrections incorporated

| Finding | Consequence and change | Evidence and qualification boundary |
|---|---|---|
| Asupersync includes unconditional `AtomicU64` sites while the selected BE PPC/MIPS target configurations lack 64-bit atomics | P05 owns a bounded legacy runtime profile and semantics-preserving portability changes; P06 owns portable library subsets | Source and stable compiler target metadata; no full cross-build or device run was executed in this review |
| A current-thread executor does not establish a zero-extra-thread runtime | Inventory startup, first-use and between-`block_on` threads; cap blocking work and captured job bytes; no-thread mode must refuse unsupported blocking work | Native default maximum of 512 blocking workers is a lazy cap, not 512 startup threads; stack reservation is not RSS |
| Generic finalization can allocate | Pre-admit cleanup capacity or use a demonstrated nonallocating stop path; distinguish quota rejection, allocation abort and process death | Conditional design requirement, not a reproduced firmware OOM bug |
| Safe Rust callers may forget a HAL token/future | Ownership must survive missing destructors, including destruction of the device-owner table; quarantine bounded buffers until completion | Depends on whether the retained ABI copies synchronously or retains a pointer; neither behavior has been universally qualified |
| Repair can finish before presentation but after downstream consumption must begin | Use `consume_by`, subtracting DSP/conversion, submission lead and uncertainty; commit real/concealed output once | Synthetic 500 ms presentation minus 8 ms submission and 4 ms DSP gives 488 ms cutoff; 495 ms repair is late |
| A new epoch cannot retract already submitted old audio | Readiness includes an irrevocable-output cursor and acknowledged drain/stop; a successful seek cannot be acknowledged prematurely | Synthetic 4,800 frames at 48 kHz are 100 ms; no particular driver queue length is inferred |
| Fencing alone does not resolve disconnected authorities | First profile uses a configured on-speaker issuer; refuse uncertain reassignment, require enforceable expiry and nonoverlap; automatic failover needs its own protocol | Availability is deliberately sacrificed when authority cannot be established; no claim that an implemented split-brain bug was found |
| Generic DSP stability acceptance was already present | Refine finite-precision/intermediate-range checks and preserve board-lifetime protection state across seeks/reconnects | The broader allegation that stability was missing was narrowed by independent audit |
| Closing a negative feasibility task could satisfy a graph prerequisite | Add positive provisional native-tailnet admission T04 before T02 | A negative result remains useful evidence but does not enable native development by itself |
| Offline and external qualification were conflated | Split X04/X05 and Q04/Q06; release Q05 requires Q06; required capabilities are frozen independently of implementation flags | Offline checks cannot claim Alexa/provider/hardware interoperability |
| Plan regeneration did not own complete issue bodies | Add deterministic full-body rendering and explicit task-to-section mapping | Final independent audit checks actual issue descriptions and dependencies, not just local files |

Ledger mapping: retained-driver observation C001; audio/authority refinements C002–C005; platform findings C006–C009; historical task/generation defects C010–C013; bounded mechanism hypotheses C014–C016. Independent dispositions: 10 VERIFIED, 3 PARTIALLY_SUPPORTED, 3 HYPOTHESIS. Verified specification findings do not mean implemented behavior is verified.

## Small mechanisms worth testing

These remain hypotheses, with promotion criteria rather than size or speed promises.

1. **Reviewed capability manifest tied to exact build/profile identity.** Enumerate the selected runtime and ABI requirements before output opens. Remove each declared capability in an offline admission test and require typed rejection. Retire a claim of coverage if late selected paths can invoke undeclared requirements. A dependency graph alone cannot automatically enumerate all syscalls.
2. **Pre-admitted lifetime arena.** Reserve task, cleanup and buffer-ownership metadata before entering Running; recycle only after software drain and external ownership completion. Instrument allocator calls and reconnect high-water. Hidden allocations or unbounded overlapping lifetimes defeat the intended guarantee.
3. **Single-owner telemetry with bounded snapshots.** Use this only for fields proved to be observational counters. Shared identity, authoritative clocks and epochs retain their actual synchronization requirements. Compare cancellation/epoch semantics and measured cost on both target families before adopting the optimization.

The NTM continuity review also proposed clock-uncertainty expiry and transition-memory credits. These refine existing clock aging and peak-admission requirements; they are not separately validated performance improvements. Unknown oscillator bounds cannot be replaced by guessed constants.

## What the attractive original story does not prove

Fresh inspection confirms a 77,380-byte, unstripped ELF32 big-endian module with PowerPC classification and CS44800, `dsp_dev`, `audioctl`, thermal and m8260-related strings. Its digest and independent recheck are recorded in the run. This is useful artifact evidence. It does not prove the exact SoC, a simple safe driver ABI, all acoustic protections, anacapad resident memory, or the cause of dropouts.

The quoted 1.15 MB binary, 2.8 MB runtime footprint, 19 MB spare RAM, tiny complete AirPlay/Tailscale implementations, sub-30 ms Alexa response and dropout-proof playback are unmeasured targets or unsupported predictions. A common protocol can remove our own S1/S2 grouping distinction; different CPU/ABI families still require different compiled artifacts. Supporting fewer formats helps scope, but native authentication, transport, clocks, protection, radio conditions and simultaneous resource peaks remain real work.

FEC cannot guarantee recovery through arbitrary outages or after an audio deadline. Compressed source lookahead and endpoint PCM playout buffers have different sizes and purposes. Video synchronization requires a source that actually honors a supported timing/control contract; reporting latency alone cannot guarantee every YouTube/iPhone path. Retaining C kernel/drivers also means the complete system is not exclusively memory-safe Rust, even when application crates forbid unsafe code.

## Verification and remaining boundaries

The independent final export audit found 51/51 live full bodies, titles and predecessor sets equal to the canonical source, 114 blocking edges, zero cycles, and 135/135 mapped source sections present verbatim. Scratch regeneration matched 55/55 generated artifacts, was deterministic outside the project working directory, and propagated a controlled acceptance edit to the expected artifacts. These are planning consistency results.

Source review, compiler target metadata, arithmetic counterexamples and schema checks are separate evidence classes. None establishes target std/musl compatibility with an old kernel, safe audio output, measured memory fit, native protocol interoperability or physical phase synchronization. Those remain explicit implementation and qualification tasks.

Independent auditors narrowed unsupported interpretations rather than creating artificial disagreement. No material aligned conflict required voting or a new review round. Further broad design review has lower value than the planned identity, ABI and bounded-runtime experiments.

The late NTM partition finding received an additional independent check after correction: exclusion cannot waive prior output grants; unknown stop/expiry bounds refuse conflicting playback. Research import repairs also passed 17/17 record-to-export matches and 38/38 resolved relationship references, with three assumptions separately enumerable. These close research/specification findings, not product tasks. See [fresh-resolution.md](research/slim-speaker/fresh-resolution.md).

## Provenance and methodology limits

Canonical audited claims: [MOR_CLAIMS.jsonl](MOR_CLAIMS.jsonl). Case: [MOR_CASE.md](MOR_CASE.md). Source passes, independent audits and reproducible probes: [.mor/run-20261104T204109Z](.mor/run-20261104T204109Z). Corrected implementation plan: [docs/SLIM_SPEAKER_PLAN.md](docs/SLIM_SPEAKER_PLAN.md).

The requested Brenner/NTM review produced a bounded Codex continuity pass and evidence-backed research findings. It reused the investigator context; fresh independent root reviewers supplied separate claim audits. The prior Claude automatic safety pause was not retried or routed around. Missing peer distillation and phase inputs prevent claims of completed pair adjudication, cross-family consensus or full ten-phase Brenner completion. See [fresh-review-cod.md](research/slim-speaker/distillations/fresh-review-cod.md) and its evidence pack. Agent Mail coordination was authorized by the invoked Brenner skill.
