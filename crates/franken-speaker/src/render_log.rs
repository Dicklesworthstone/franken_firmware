//! Diagnostics for the D04 render loop, as `ffw.log.v1` JSONL (`D04` / `ffw-5h5`).
//!
//! [`RenderLog`] turns what [`crate::render::RenderLoop`] reports (its [`RenderEvent`]s and its
//! [`RenderCounters`]) into structured, bounded, redacted log lines. It follows the shape of E04's
//! `ContractLog` and reuses its identifier check, its stats type and the HAL's critical-first queue.
//! This module writes the JSONL itself: `franken-test-support` is a dev-dependency only, and the
//! tests use it to check that every line has exactly the `ffw.log.v1` shape and survives its
//! redactor unchanged.
//!
//! The log is a **consumer** of the loop's events. It is handed a shared reference and nothing it
//! does can reach back into the loop, so a full, slow, absent or never-drained log changes no
//! deadline and no outcome (pinned by a test that runs the same scenario with and without one).
//!
//! What a line says, by event:
//! * a state change: an ordinary line, and a **critical** one when it enters `faulted`;
//! * a block: its outcome, with the four causes kept apart in `cause` (`ingress_loss`,
//!   `decode_delay`, `cpu_miss`, plus `capacity_rejected` and `short_write`); a CPU miss carries its
//!   lateness in `latency_us` when the owner says how long a tick is;
//! * a driver underrun and a rejected control command: ordinary lines;
//! * a fault: a **critical** line naming the reason in `fault` and its root in `cause`. A driver counter
//!   regress is the one reason whose line also carries the loop's reaction: its `cause` is
//!   `driver_counter_regress` and its message ends `mapping_invalidated`. That line is the only one that
//!   does; the `faulted` state line that follows it is critical like every fault's and names no reaction;
//! * a summary: a **critical** line with the counters that matter, including how many events the
//!   loop's own queue dropped and how many lines this log dropped.
//!
//! Properties, each pinned by a test:
//! * **Bounded.** At most the configured number of lines are kept, each message at most
//!   [`MAX_MESSAGE_CHARS`] characters. A full log drops ordinary lines first; a critical line evicts
//!   the oldest ordinary one and is lost only when the log holds nothing but critical lines, which is
//!   counted and marks the evidence incomplete. It never blocks.
//! * **Loss is visible from both sides.** [`RenderLog::evidence_complete`] is false when this log lost
//!   a critical line **or** the loop reported (in its counters) that its own queue did.
//! * **Redacted by construction.** A line is built from enum names, numbers and identifiers that
//!   passed [`safe_id`]. No audio, no free text.
//! * **Not a clock unless told.** `timestamp_mono_ns` is the loop's tick count scaled by the tick
//!   length the owner supplies with [`RenderLog::with_tick_micros`]; without it a tick is one
//!   nanosecond and `latency_us` is 0, because the loop's tick is the device's tick and this module
//!   does not know its length. Nothing here is a hardware claim.
//!
//! The loop's own sink is the bounded queue behind `RenderLoop::take_event`. This log sits after it.

use crate::render::{
    AdmitFaults, BlockOutcome, FaultReason, RenderCounters, RenderEvent, RenderEventKind,
};
use franken_hal::contract_log::{LOG_SCHEMA_VERSION, LogStats, MAX_MESSAGE_CHARS, safe_id};
use franken_hal::emit::{Critical, CriticalQueue, PushOutcome};
use serde::Serialize;

fn clip(message: String) -> String {
    if message.chars().count() <= MAX_MESSAGE_CHARS {
        message
    } else {
        message.chars().take(MAX_MESSAGE_CHARS).collect()
    }
}

/// The `snake_case` name serde gives a unit-like value.
fn serde_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The documented root of each fault reason (see `FaultReason`).
const fn root_cause(reason: FaultReason) -> &'static str {
    match reason {
        FaultReason::SessionFaulted => "hal_session_fault",
        FaultReason::DeviceLost => "device_gone",
        FaultReason::DrainTimedOut => "flush_not_acknowledged",
        FaultReason::WatchdogTripped => "consecutive_cpu_misses",
        FaultReason::ProtectionFault => "protection_dsp_inactive",
        FaultReason::RenderInternal => "resampler_refused_block",
        FaultReason::CounterRegress => "driver_counter_regress",
    }
}

/// What the loop did about a fault, when that is part of the reason itself: appended to the message of
/// the one critical line that reports it.
const fn reaction_note(reason: FaultReason) -> &'static str {
    match reason {
        FaultReason::CounterRegress => " mapping_invalidated",
        FaultReason::SessionFaulted
        | FaultReason::DeviceLost
        | FaultReason::DrainTimedOut
        | FaultReason::WatchdogTripped
        | FaultReason::ProtectionFault
        | FaultReason::RenderInternal => "",
    }
}

/// The injected admission failures in force, as one label, or `None` when there are none.
fn admit_label(faults: AdmitFaults) -> Option<String> {
    let mut parts = Vec::new();
    if faults.start {
        parts.push("admit_start");
    }
    if faults.cancel {
        parts.push("admit_cancel");
    }
    if faults.drain {
        parts.push("admit_drain");
    }
    if faults.reconnect {
        parts.push("admit_reconnect");
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("+"))
    }
}

/// One `ffw.log.v1` line. Field order is the schema's; the optional fields are left out when absent,
/// as the schema's own type does.
#[derive(Debug, Clone, Serialize)]
struct LogLine {
    schema_version: &'static str,
    timestamp_mono_ns: u64,
    run_id: String,
    case_id: String,
    correlation_id: String,
    member_id: String,
    group_id: String,
    source_epoch: u64,
    state_revision: u64,
    event_kind: String,
    message: String,
    queue_depth: usize,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fault: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<String>,
}

/// What the caller says about one line.
struct Draft {
    kind: &'static str,
    message: String,
    epoch: u64,
    depth: usize,
    latency_us: u64,
    fault: Option<String>,
    cause: Option<String>,
    critical: bool,
}

#[derive(Debug)]
struct Entry {
    critical: bool,
    line: String,
}

impl Critical for Entry {
    fn critical(&self) -> bool {
        self.critical
    }
}

/// A bounded, non-blocking log of what the render loop reported.
#[derive(Debug)]
pub struct RenderLog {
    run_id: String,
    case_id: String,
    member_id: String,
    group_id: String,
    tick_us: u64,
    admit: Option<String>,
    queue: CriticalQueue<Entry>,
    stats: LogStats,
    revision: u64,
    upstream_lost_critical: u64,
}

impl RenderLog {
    /// A log that keeps at most `capacity` lines (at least one). Identifiers are validated.
    #[must_use]
    pub fn new(run_id: &str, case_id: &str, capacity: usize) -> Self {
        Self {
            run_id: safe_id(run_id),
            case_id: safe_id(case_id),
            member_id: "none".to_string(),
            group_id: "none".to_string(),
            tick_us: 0,
            admit: None,
            queue: CriticalQueue::new(capacity.max(1)),
            stats: LogStats::default(),
            revision: 0,
            upstream_lost_critical: 0,
        }
    }

    /// Pseudonymous member and group identifiers (validated; never a device or site name).
    #[must_use]
    pub fn with_pseudonyms(mut self, member: &str, group: &str) -> Self {
        self.member_id = safe_id(member);
        self.group_id = safe_id(group);
        self
    }

    /// How many microseconds one device tick is, when the owner knows. Without it `latency_us` is 0.
    #[must_use]
    pub fn with_tick_micros(mut self, tick_us: u64) -> Self {
        self.tick_us = tick_us;
        self
    }

    /// Record which injected admission failures are in force; later lines name them in `fault`.
    pub fn set_admit_faults(&mut self, faults: AdmitFaults) {
        self.admit = admit_label(faults);
    }

    #[must_use]
    pub const fn stats(&self) -> LogStats {
        self.stats
    }

    /// False once a critical line could not be kept here, or the loop reported that its own event queue
    /// lost a critical event: the evidence behind a result is incomplete.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.stats.lost_critical == 0 && self.upstream_lost_critical == 0
    }

    /// Lines waiting to be drained.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Take every kept line, oldest first, as JSONL (one object per line, no trailing newline).
    pub fn drain_jsonl(&mut self) -> String {
        let mut lines = Vec::new();
        while let Some(entry) = self.queue.pop() {
            lines.push(entry.line);
        }
        lines.join("\n")
    }

    fn enqueue(&mut self, tick: u64, correlation: String, draft: Draft) {
        let tick_ns = self.tick_us.saturating_mul(1000).max(1);
        let line = LogLine {
            schema_version: LOG_SCHEMA_VERSION,
            timestamp_mono_ns: tick.saturating_mul(tick_ns),
            run_id: self.run_id.clone(),
            case_id: self.case_id.clone(),
            correlation_id: correlation,
            member_id: self.member_id.clone(),
            group_id: self.group_id.clone(),
            source_epoch: draft.epoch,
            state_revision: self.revision,
            event_kind: draft.kind.to_string(),
            message: clip(draft.message),
            queue_depth: draft.depth,
            latency_us: draft.latency_us,
            fault: draft.fault,
            cause: draft.cause,
        };
        let text = serde_json::to_string(&line).unwrap_or_default();
        self.stats.emitted += 1;
        let entry = Entry {
            critical: draft.critical,
            line: text,
        };
        match self.queue.push(entry) {
            PushOutcome::Queued => {}
            PushOutcome::DroppedOrdinary => self.stats.dropped_ordinary += 1,
            PushOutcome::EvictedOrdinary => self.stats.evicted_ordinary += 1,
            PushOutcome::LostCritical => self.stats.lost_critical += 1,
        }
    }

    /// Log one event the loop reported. `counters` and `in_flight` are the loop's own, read when the
    /// event was taken: `counters.epoch_resets` is the source epoch, `in_flight` the queue depth.
    pub fn log_event(&mut self, event: &RenderEvent, counters: &RenderCounters, in_flight: usize) {
        self.upstream_lost_critical = self
            .upstream_lost_critical
            .max(counters.events_lost_critical);
        let tick = event.tick;
        let mut correlation = format!("tick-{tick}");
        let mut draft = Draft {
            kind: "d04_state",
            message: String::new(),
            epoch: counters.epoch_resets,
            depth: in_flight,
            latency_us: 0,
            fault: self.admit.clone(),
            cause: None,
            critical: event.critical(),
        };
        match event.kind {
            RenderEventKind::State { from, to } => {
                self.revision = self.revision.saturating_add(1);
                draft.message = format!("state {} to {}", serde_name(&from), serde_name(&to));
            }
            RenderEventKind::Block { index, outcome } => {
                correlation = format!("block-{index}");
                draft.kind = "d04_block";
                let (text, cause, late_ticks) = match outcome {
                    BlockOutcome::OnTime => (format!("block {index} on_time"), None, 0),
                    BlockOutcome::Starved {
                        cause,
                        silence_frames,
                    } => (
                        format!(
                            "block {index} starved {} silence_frames={silence_frames}",
                            serde_name(&cause)
                        ),
                        Some(serde_name(&cause)),
                        0,
                    ),
                    BlockOutcome::CpuMiss { late_by } => (
                        format!("block {index} cpu_miss late_by_ticks={late_by}"),
                        Some("cpu_miss".to_string()),
                        late_by,
                    ),
                    BlockOutcome::CapacityRejected => (
                        format!("block {index} capacity_rejected logical"),
                        Some("capacity_rejected".to_string()),
                        0,
                    ),
                    BlockOutcome::ShortWrite { discarded_frames } => (
                        format!("block {index} short_write discarded_frames={discarded_frames}"),
                        Some("short_write".to_string()),
                        0,
                    ),
                };
                draft.message = text;
                draft.cause = cause;
                draft.latency_us = late_ticks.saturating_mul(self.tick_us);
            }
            RenderEventKind::DriverUnderrun => {
                draft.kind = "d04_driver_underrun";
                draft.message = format!(
                    "driver_underruns={} explained={}",
                    counters.driver_underruns, counters.underruns_explained
                );
                draft.cause = Some("driver".to_string());
            }
            RenderEventKind::ControlRejected => {
                draft.kind = "d04_control_rejected";
                draft.message = "control queue full".to_string();
                draft.cause = Some("queue_full".to_string());
            }
            RenderEventKind::Fault { reason } => {
                draft.kind = "d04_fault";
                let name = serde_name(&reason);
                draft.message = format!("fault {name}{}", reaction_note(reason));
                draft.fault = Some(name);
                draft.cause = Some(root_cause(reason).to_string());
            }
        }
        self.enqueue(tick, correlation, draft);
    }

    /// Log the closing summary: a **critical** line carrying the counters that matter, so a reader can
    /// check the denominator, and how much was dropped by the loop's queue (`evd`, `eve`, `evc`) and by
    /// this log (`ld`, `lc`) before this line.
    pub fn log_summary(&mut self, tick: u64, counters: &RenderCounters, in_flight: usize) {
        self.upstream_lost_critical = self
            .upstream_lost_critical
            .max(counters.events_lost_critical);
        let admit = self.admit.clone().unwrap_or_else(|| "none".to_string());
        let message = format!(
            "n={} ok={} ing={} dec={} cpu={} cap={} sw={} ur={} evd={} eve={} evc={} ld={} lc={} admit={admit}",
            counters.blocks_started,
            counters.blocks_on_time,
            counters.ingress_loss_blocks,
            counters.decode_delay_blocks,
            counters.cpu_miss_blocks,
            counters.capacity_rejected_blocks,
            counters.short_write_blocks,
            counters.driver_underruns,
            counters.events_dropped,
            counters.events_evicted,
            counters.events_lost_critical,
            self.stats.dropped_ordinary + self.stats.evicted_ordinary,
            self.stats.lost_critical,
        );
        let draft = Draft {
            kind: "d04_summary",
            message,
            epoch: counters.epoch_resets,
            depth: in_flight,
            latency_us: 0,
            fault: self.admit.clone(),
            cause: None,
            critical: true,
        };
        self.enqueue(tick, format!("tick-{tick}"), draft);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{
        RenderConfig, RenderLoop, RenderSource, RenderState, ScriptedTiming, Starvation,
    };
    use franken_dsp::protection::{Admission, ProtectedBoardDsp, synthetic_calibration_for};
    use franken_dsp::resample::{DriftResampler, FrameSource, ResamplerConfig};
    use franken_hal::abi::{DeviceEvent, RawGeometry};
    use franken_hal::backend::{FakeBackend, FakeConfig, FakeProbe};
    use franken_hal::session::{HalSession, SessionConfig, StartPreconditions};
    use franken_hal::slots::LeakLedger;
    use franken_test_support::{DiagnosticEvent, redact_sensitive_text};
    use std::sync::Arc;

    /// The hand-written scripted run and the exact lines it must produce. `tests/d04/log_reference.py`
    /// derives the same lines independently from the same events.
    const GOLDEN: &str = include_str!("../../../tests/d04/log_golden.json");

    fn ev(tick: u64, kind: RenderEventKind) -> RenderEvent {
        RenderEvent { tick, kind }
    }

    fn lines_of(log: &mut RenderLog) -> Vec<serde_json::Value> {
        log.drain_jsonl()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// One event of every kind, with every outcome and every fault reason, in tick order.
    fn every_event() -> Vec<RenderEvent> {
        let first = ev(
            1,
            RenderEventKind::State {
                from: RenderState::Ready,
                to: RenderState::Running,
            },
        );
        let outcomes = [
            BlockOutcome::OnTime,
            BlockOutcome::Starved {
                cause: Starvation::IngressLoss,
                silence_frames: 16,
            },
            BlockOutcome::Starved {
                cause: Starvation::DecodeDelay,
                silence_frames: 8,
            },
            BlockOutcome::CpuMiss { late_by: 3 },
            BlockOutcome::CapacityRejected,
            BlockOutcome::ShortWrite {
                discarded_frames: 32,
            },
        ];
        let blocks = outcomes.into_iter().enumerate().map(|(i, outcome)| {
            let index = u64::try_from(i).unwrap();
            ev(2 + index, RenderEventKind::Block { index, outcome })
        });
        let reasons = [
            FaultReason::SessionFaulted,
            FaultReason::DeviceLost,
            FaultReason::DrainTimedOut,
            FaultReason::WatchdogTripped,
            FaultReason::ProtectionFault,
            FaultReason::RenderInternal,
            FaultReason::CounterRegress,
        ];
        let faults = reasons.into_iter().enumerate().map(|(i, reason)| {
            ev(
                12 + u64::try_from(i).unwrap(),
                RenderEventKind::Fault { reason },
            )
        });
        let last = ev(
            20,
            RenderEventKind::State {
                from: RenderState::Running,
                to: RenderState::Faulted,
            },
        );
        std::iter::once(first)
            .chain(blocks)
            .chain([
                ev(10, RenderEventKind::DriverUnderrun),
                ev(11, RenderEventKind::ControlRejected),
            ])
            .chain(faults)
            .chain(std::iter::once(last))
            .collect()
    }

    // ------------------------------------------------------------------ shape and redaction

    #[test]
    fn every_line_has_exactly_the_ffw_log_v1_shape_and_survives_the_redactor_unchanged() {
        let mut log = RenderLog::new("d04-run-1", "d04-shape", 256)
            .with_pseudonyms("m-1", "g-1")
            .with_tick_micros(1000);
        log.set_admit_faults(AdmitFaults {
            start: true,
            drain: true,
            ..AdmitFaults::default()
        });
        let counters = RenderCounters::default();
        let events = every_event();
        for event in &events {
            log.log_event(event, &counters, 2);
        }
        log.log_summary(99, &counters, 0);
        assert!(log.evidence_complete());
        let text = log.drain_jsonl();
        let mut count = 0;
        for line in text.lines() {
            // The schema's own type reads the line and writes it back byte for byte: the field names,
            // their order and the omission of absent optional fields all match.
            let event: DiagnosticEvent = serde_json::from_str(line).unwrap();
            assert_eq!(serde_json::to_string(&event).unwrap(), line);
            assert_eq!(
                event.schema_version,
                franken_test_support::LOG_SCHEMA_VERSION
            );
            assert_eq!(event.schema_version, LOG_SCHEMA_VERSION);
            assert_eq!(redact_sensitive_text(line), line);
            count += 1;
        }
        assert_eq!(count, events.len() + 1);
    }

    #[test]
    fn a_hostile_identifier_never_reaches_a_line() {
        let mut log = RenderLog::new("run 1; token=abc", "10.0.0.7", 16)
            .with_pseudonyms("password=hunter2", "has a space");
        let counters = RenderCounters::default();
        log.log_event(
            &ev(
                1,
                RenderEventKind::Fault {
                    reason: FaultReason::DeviceLost,
                },
            ),
            &counters,
            0,
        );
        let text = log.drain_jsonl();
        for secret in ["token=abc", "10.0.0.7", "hunter2", "has a space"] {
            assert!(!text.contains(secret), "{secret} reached a line");
        }
        assert!(text.contains("invalid_id"));
        assert_eq!(redact_sensitive_text(&text), text);
    }

    #[test]
    fn a_long_message_is_cut() {
        assert_eq!(clip("x".repeat(500)).chars().count(), MAX_MESSAGE_CHARS);
        assert_eq!(clip("short".to_string()), "short");
    }

    // ------------------------------------------------------------------ what a line says

    #[test]
    fn the_causes_are_kept_apart_and_a_cpu_miss_carries_its_lateness() {
        let mut log = RenderLog::new("r", "c", 64).with_tick_micros(1000);
        let counters = RenderCounters::default();
        let outcomes = [
            BlockOutcome::Starved {
                cause: Starvation::IngressLoss,
                silence_frames: 1,
            },
            BlockOutcome::Starved {
                cause: Starvation::DecodeDelay,
                silence_frames: 1,
            },
            BlockOutcome::CpuMiss { late_by: 3 },
            BlockOutcome::CapacityRejected,
            BlockOutcome::ShortWrite {
                discarded_frames: 1,
            },
        ];
        for (i, outcome) in outcomes.into_iter().enumerate() {
            let index = u64::try_from(i).unwrap();
            log.log_event(
                &ev(index, RenderEventKind::Block { index, outcome }),
                &counters,
                0,
            );
        }
        log.log_event(&ev(9, RenderEventKind::DriverUnderrun), &counters, 0);
        let lines = lines_of(&mut log);
        let causes: Vec<&str> = lines.iter().map(|l| l["cause"].as_str().unwrap()).collect();
        assert_eq!(
            causes,
            [
                "ingress_loss",
                "decode_delay",
                "cpu_miss",
                "capacity_rejected",
                "short_write",
                "driver"
            ]
        );
        // Only the CPU miss has a latency, and it is ticks times the tick length the owner gave.
        let latencies: Vec<u64> = lines
            .iter()
            .map(|l| l["latency_us"].as_u64().unwrap())
            .collect();
        assert_eq!(latencies, [0, 0, 3000, 0, 0, 0]);
        assert_eq!(lines[2]["correlation_id"], "block-2");
        assert_eq!(lines[2]["message"], "block 2 cpu_miss late_by_ticks=3");
    }

    #[test]
    fn without_a_tick_length_latency_is_zero_and_a_tick_is_one_nanosecond() {
        let mut log = RenderLog::new("r", "c", 8);
        let counters = RenderCounters::default();
        let event = ev(
            7,
            RenderEventKind::Block {
                index: 0,
                outcome: BlockOutcome::CpuMiss { late_by: 5 },
            },
        );
        log.log_event(&event, &counters, 0);
        let lines = lines_of(&mut log);
        assert_eq!(lines[0]["latency_us"], 0);
        assert_eq!(lines[0]["timestamp_mono_ns"], 7);
        // With the tick length, the timestamp is scaled and the lateness is converted.
        let mut log = RenderLog::new("r", "c", 8).with_tick_micros(250);
        log.log_event(&event, &counters, 0);
        let lines = lines_of(&mut log);
        assert_eq!(lines[0]["timestamp_mono_ns"], 7 * 250_000);
        assert_eq!(lines[0]["latency_us"], 5 * 250);
    }

    #[test]
    fn state_revision_counts_state_changes_and_timestamps_never_go_back() {
        let mut log = RenderLog::new("r", "c", 256);
        let counters = RenderCounters::default();
        for event in every_event() {
            log.log_event(&event, &counters, 0);
        }
        let lines = lines_of(&mut log);
        let revisions: Vec<u64> = lines
            .iter()
            .map(|l| l["state_revision"].as_u64().unwrap())
            .collect();
        assert!(revisions.windows(2).all(|w| w[1] >= w[0]));
        assert_eq!(revisions.first(), Some(&1));
        assert_eq!(revisions.last(), Some(&2));
        let stamps: Vec<u64> = lines
            .iter()
            .map(|l| l["timestamp_mono_ns"].as_u64().unwrap())
            .collect();
        assert!(stamps.windows(2).all(|w| w[1] >= w[0]));
    }

    #[test]
    fn a_fault_is_critical_names_its_reason_and_root_and_the_schedule_is_named_on_other_lines() {
        let mut log = RenderLog::new("r", "c", 64);
        log.set_admit_faults(AdmitFaults {
            drain: true,
            reconnect: true,
            ..AdmitFaults::default()
        });
        let counters = RenderCounters::default();
        log.log_event(
            &ev(
                1,
                RenderEventKind::Block {
                    index: 0,
                    outcome: BlockOutcome::OnTime,
                },
            ),
            &counters,
            0,
        );
        log.log_event(
            &ev(
                2,
                RenderEventKind::Fault {
                    reason: FaultReason::WatchdogTripped,
                },
            ),
            &counters,
            0,
        );
        let lines = lines_of(&mut log);
        assert_eq!(lines[0]["fault"], "admit_drain+admit_reconnect");
        assert_eq!(lines[1]["event_kind"], "d04_fault");
        assert_eq!(lines[1]["fault"], "watchdog_tripped");
        assert_eq!(lines[1]["cause"], "consecutive_cpu_misses");
        // With no injected failure in force, the field is left out.
        let mut clean = RenderLog::new("r", "c", 8);
        clean.log_event(
            &ev(
                1,
                RenderEventKind::Block {
                    index: 0,
                    outcome: BlockOutcome::OnTime,
                },
            ),
            &counters,
            0,
        );
        assert!(lines_of(&mut clean)[0].get("fault").is_none());
        assert_eq!(admit_label(AdmitFaults::default()), None);
    }

    // ------------------------------------------------------------------ bounds and loss

    #[test]
    fn a_small_log_drops_ordinary_lines_first_keeps_the_fault_and_accounts_for_every_line() {
        let mut log = RenderLog::new("r", "c", 3);
        let counters = RenderCounters::default();
        for i in 0..10u64 {
            log.log_event(
                &ev(
                    i,
                    RenderEventKind::Block {
                        index: i,
                        outcome: BlockOutcome::OnTime,
                    },
                ),
                &counters,
                0,
            );
        }
        log.log_event(
            &ev(
                10,
                RenderEventKind::Fault {
                    reason: FaultReason::DeviceLost,
                },
            ),
            &counters,
            0,
        );
        let stats = log.stats();
        assert_eq!(stats.emitted, 11);
        assert_eq!(stats.lost_critical, 0);
        assert!(log.evidence_complete());
        let lines = lines_of(&mut log);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2]["event_kind"], "d04_fault");
        // The first three queued, the next seven were dropped, and the fault evicted the oldest ordinary
        // line, so blocks 1 and 2 and the fault are what is left (tests/d04/log_golden.json `bounded`).
        let kept: Vec<&str> = lines
            .iter()
            .map(|l| l["correlation_id"].as_str().unwrap())
            .collect();
        assert_eq!(kept, ["block-1", "block-2", "tick-10"]);
        assert_eq!((stats.dropped_ordinary, stats.evicted_ordinary), (7, 1));
        assert_eq!(
            stats.emitted,
            3 + stats.dropped_ordinary + stats.evicted_ordinary + stats.lost_critical
        );
    }

    #[test]
    fn a_log_holding_only_critical_lines_loses_the_next_one_and_says_so() {
        let mut log = RenderLog::new("r", "c", 2);
        let counters = RenderCounters::default();
        for tick in 0..3 {
            log.log_event(
                &ev(
                    tick,
                    RenderEventKind::Fault {
                        reason: FaultReason::SessionFaulted,
                    },
                ),
                &counters,
                0,
            );
        }
        assert_eq!(log.stats().lost_critical, 1);
        assert!(!log.evidence_complete());
        assert_eq!(log.pending(), 2);
    }

    #[test]
    fn a_critical_event_the_loops_own_queue_lost_marks_the_evidence_incomplete_too() {
        let mut log = RenderLog::new("r", "c", 16);
        let counters = RenderCounters {
            events_lost_critical: 1,
            ..RenderCounters::default()
        };
        log.log_event(&ev(1, RenderEventKind::ControlRejected), &counters, 0);
        assert_eq!(log.stats().lost_critical, 0);
        assert!(!log.evidence_complete());
        // The summary reports the loop's loss in its own counters.
        log.log_summary(2, &counters, 0);
        let lines = lines_of(&mut log);
        assert!(
            lines[1]["message"]
                .as_str()
                .unwrap()
                .contains("evc=1 ld=0 lc=0")
        );
    }

    // ------------------------------------------------------------------ the golden run

    /// Overlay a partial counters object on the defaults; an unknown key is a mistake, not ignored.
    fn counters_from(overlay: &serde_json::Value) -> RenderCounters {
        let mut base = serde_json::to_value(RenderCounters::default()).unwrap();
        let map = base.as_object_mut().unwrap();
        for (key, value) in overlay.as_object().unwrap() {
            assert!(map.contains_key(key), "unknown counter {key}");
            map.insert(key.clone(), value.clone());
        }
        serde_json::from_value(base).unwrap()
    }

    fn admit_from(v: &serde_json::Value) -> AdmitFaults {
        let flag = |name: &str| v[name].as_bool().unwrap_or(false);
        AdmitFaults {
            start: flag("start"),
            cancel: flag("cancel"),
            drain: flag("drain"),
            reconnect: flag("reconnect"),
        }
    }

    #[test]
    fn the_scripted_run_produces_exactly_the_hand_written_lines() {
        let golden: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        let id = &golden["identity"];
        let mut log = RenderLog::new(
            id["run_id"].as_str().unwrap(),
            id["case_id"].as_str().unwrap(),
            usize::try_from(id["capacity"].as_u64().unwrap()).unwrap(),
        )
        .with_pseudonyms(
            id["member_id"].as_str().unwrap(),
            id["group_id"].as_str().unwrap(),
        )
        .with_tick_micros(id["tick_us"].as_u64().unwrap());
        for step in golden["steps"].as_array().unwrap() {
            if let Some(faults) = step.get("set_admit_faults") {
                log.set_admit_faults(admit_from(faults));
                continue;
            }
            let counters = counters_from(&step["counters"]);
            let in_flight = usize::try_from(step["in_flight"].as_u64().unwrap()).unwrap();
            if let Some(summary) = step.get("summary") {
                log.log_summary(summary["tick"].as_u64().unwrap(), &counters, in_flight);
            } else {
                let event: RenderEvent = serde_json::from_value(step["event"].clone()).unwrap();
                log.log_event(&event, &counters, in_flight);
            }
        }
        assert!(log.evidence_complete());
        let got = log.drain_jsonl();
        let want: Vec<&str> = golden["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        let got_lines: Vec<&str> = got.lines().collect();
        assert_eq!(got_lines.len(), want.len());
        for (i, (g, w)) in got_lines.iter().zip(want.iter()).enumerate() {
            assert_eq!(g, w, "line {i}");
        }
    }

    // ------------------------------------------------------------------ the real loop

    const READY: StartPreconditions = StartPreconditions {
        presentation_mapping_installed: true,
        safe_gain_installed: true,
    };

    fn profile() -> franken_board_profile::BoardProfile {
        franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S1")
            .unwrap()
    }

    /// Four 64-frame slots, two channels, a completion two ticks after a submit (the same fake the loop's
    /// own tests use).
    fn fake_config() -> FakeConfig {
        let mut cfg = FakeConfig::retained();
        cfg.geometry = RawGeometry {
            ring_depth: 4,
            frames_per_block: 64,
            channels: 2,
            bytes_per_sample: 2,
        };
        cfg.completion_delay_ticks = 2;
        cfg
    }

    fn started_loop() -> (RenderLoop<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(fake_config());
        let ledger = Arc::new(LeakLedger::new(64));
        let config = SessionConfig::with_ledger(Arc::clone(&ledger), 2);
        let mut session = HalSession::open(profile(), backend, config).unwrap();
        session.prepare().unwrap();
        let calibration = synthetic_calibration_for(&profile());
        let dsp =
            ProtectedBoardDsp::admit(&profile(), Some(&calibration), Admission::HostSimulation);
        let resampler = DriftResampler::new(ResamplerConfig::default()).unwrap();
        let mut l = RenderLoop::new(session, dsp, resampler, RenderConfig::standard(64)).unwrap();
        l.start(READY).unwrap();
        (l, probe)
    }

    struct ToneSource {
        pos: u64,
    }

    impl FrameSource for ToneSource {
        fn pull(&mut self) -> Option<[f32; 2]> {
            let phase = (self.pos % 48) as f32 / 48.0;
            self.pos += 1;
            let v = 0.25 * (2.0 * std::f32::consts::PI * phase).sin();
            Some([v, -v])
        }
    }

    impl RenderSource for ToneSource {
        fn starvation(&self) -> Option<Starvation> {
            None
        }
    }

    /// Three late renders in a row trip the watchdog (the loop's own test for it). Every tick the events
    /// the loop produced are handed to `log`, if there is one.
    fn watchdog_run(
        mut log: Option<&mut RenderLog>,
    ) -> (RenderCounters, RenderState, u64, Option<usize>) {
        let (mut l, _probe) = started_loop();
        let mut src = ToneSource { pos: 0 };
        let mut t = ScriptedTiming {
            default_cost: 1,
            costs: [(0, 6), (1, 6), (2, 6)].into_iter().collect(),
            ..ScriptedTiming::default()
        };
        for _ in 0..19 {
            l.tick(&mut src, &mut t);
            while let Some(event) = l.take_event() {
                if let Some(log) = log.as_deref_mut() {
                    log.log_event(&event, &l.counters(), l.in_flight());
                }
            }
        }
        if let Some(log) = log.as_deref_mut() {
            log.log_summary(l.now(), &l.counters(), l.in_flight());
        }
        (
            l.counters(),
            l.state(),
            l.now(),
            log.map(|log| log.pending()),
        )
    }

    #[test]
    fn the_real_loop_tripping_its_watchdog_leaves_a_log_that_tells_the_story() {
        let mut log = RenderLog::new("d04-run-2", "d04-watchdog", 128).with_tick_micros(1000);
        let (counters, state, _now, _) = watchdog_run(Some(&mut log));
        assert_eq!(state, RenderState::Faulted);
        assert!(log.evidence_complete());
        let text = log.drain_jsonl();
        for line in text.lines() {
            let parsed: DiagnosticEvent = serde_json::from_str(line).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), line);
            assert_eq!(redact_sensitive_text(line), line);
        }
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let blocks: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|l| l["event_kind"] == "d04_block")
            .collect();
        let messages: Vec<&str> = blocks
            .iter()
            .map(|l| l["message"].as_str().unwrap())
            .collect();
        assert_eq!(
            messages,
            [
                "block 0 cpu_miss late_by_ticks=3",
                "block 1 cpu_miss late_by_ticks=5",
                "block 2 cpu_miss late_by_ticks=7"
            ]
        );
        let latencies: Vec<u64> = blocks
            .iter()
            .map(|l| l["latency_us"].as_u64().unwrap())
            .collect();
        assert_eq!(latencies, [3000, 5000, 7000]);
        let faults: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|l| l["event_kind"] == "d04_fault")
            .collect();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0]["fault"], "watchdog_tripped");
        assert_eq!(faults[0]["cause"], "consecutive_cpu_misses");
        let states: Vec<&str> = lines
            .iter()
            .filter(|l| l["event_kind"] == "d04_state")
            .map(|l| l["message"].as_str().unwrap())
            .collect();
        assert_eq!(states.last(), Some(&"state running to faulted"));
        // The summary agrees with the loop's own counters.
        let summary = lines.last().unwrap();
        assert_eq!(summary["event_kind"], "d04_summary");
        let message = summary["message"].as_str().unwrap();
        assert!(message.contains(&format!("n={} ", counters.blocks_started)));
        assert!(message.contains("cpu=3 "));
        assert!(message.contains("ok=0 "));
    }

    #[test]
    fn a_tiny_or_absent_log_changes_nothing_the_loop_does() {
        let (without, state_without, now_without, _) = watchdog_run(None);
        let mut tiny = RenderLog::new("r", "c", 1);
        let (with_tiny, state_tiny, now_tiny, pending) = watchdog_run(Some(&mut tiny));
        assert_eq!(without, with_tiny);
        assert_eq!(state_without, state_tiny);
        assert_eq!(now_without, now_tiny);
        // The tiny log was bounded the whole time, and the fault was not lost to the ordinary lines.
        assert_eq!(pending, Some(1));
        assert!(tiny.stats().dropped_ordinary + tiny.stats().evicted_ordinary > 0);
        // A log nobody drains is the same.
        let mut unread = RenderLog::new("r", "c", 4);
        let (with_unread, _, _, _) = watchdog_run(Some(&mut unread));
        assert_eq!(without, with_unread);
    }

    // ------------------------------------------------------------------ a driver counter regress

    /// The hand-written regress runs and the exact lines they must produce. `tests/d04/log_reference.py`
    /// derives the same lines independently from the same events.
    const REGRESS_GOLDEN: &str = include_str!("../../../tests/d04/regress_golden.json");

    #[test]
    fn the_regress_runs_produce_exactly_the_hand_written_lines() {
        let golden: serde_json::Value = serde_json::from_str(REGRESS_GOLDEN).unwrap();
        let runs = golden["log_runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        for run in runs {
            let name = run["name"].as_str().unwrap();
            let id = &run["identity"];
            let mut log = RenderLog::new(
                id["run_id"].as_str().unwrap(),
                id["case_id"].as_str().unwrap(),
                usize::try_from(id["capacity"].as_u64().unwrap()).unwrap(),
            )
            .with_pseudonyms(
                id["member_id"].as_str().unwrap(),
                id["group_id"].as_str().unwrap(),
            )
            .with_tick_micros(id["tick_us"].as_u64().unwrap());
            for step in run["steps"].as_array().unwrap() {
                let counters = counters_from(&step["counters"]);
                let in_flight = usize::try_from(step["in_flight"].as_u64().unwrap()).unwrap();
                if let Some(summary) = step.get("summary") {
                    log.log_summary(summary["tick"].as_u64().unwrap(), &counters, in_flight);
                } else {
                    let event: RenderEvent = serde_json::from_value(step["event"].clone()).unwrap();
                    log.log_event(&event, &counters, in_flight);
                }
            }
            assert!(log.evidence_complete(), "{name}");
            let got = log.drain_jsonl();
            let want: Vec<&str> = run["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap())
                .collect();
            let got_lines: Vec<&str> = got.lines().collect();
            assert_eq!(got_lines.len(), want.len(), "{name}");
            for (i, (g, w)) in got_lines.iter().zip(want.iter()).enumerate() {
                assert_eq!(g, w, "{name}: line {i}");
            }
        }
    }

    /// One tick of the real loop, with the events it produced handed to `log`. Returns the critical ones.
    fn tick_and_log(
        l: &mut RenderLoop<FakeBackend>,
        src: &mut ToneSource,
        t: &mut ScriptedTiming,
        log: &mut RenderLog,
    ) -> Vec<RenderEvent> {
        l.tick(src, t);
        let mut critical = Vec::new();
        while let Some(event) = l.take_event() {
            if event.critical() {
                critical.push(event);
            }
            log.log_event(&event, &l.counters(), l.in_flight());
        }
        critical
    }

    /// The real loop with 192 frames in flight, a counter baseline and a clean 64-frame step, then one
    /// more report. Returns the loop, the critical events it produced, and the log lines.
    fn counter_fault_run(
        report: u32,
    ) -> (
        RenderLoop<FakeBackend>,
        Vec<RenderEvent>,
        Vec<serde_json::Value>,
    ) {
        let (mut l, probe) = started_loop();
        let mut src = ToneSource { pos: 0 };
        let mut t = ScriptedTiming {
            default_cost: 1,
            ..ScriptedTiming::default()
        };
        let mut log = RenderLog::new("d04-run-3", "d04-regress", 128).with_tick_micros(1000);
        let mut critical = Vec::new();
        for _ in 0..12 {
            critical.extend(tick_and_log(&mut l, &mut src, &mut t, &mut log));
        }
        assert!(critical.is_empty(), "nothing critical has happened yet");
        assert_eq!(l.session().irrevocable_until_frames(), 192);
        for counter in [1000_u32, 1064] {
            probe.queue_event(DeviceEvent::Position { counter });
        }
        critical.extend(tick_and_log(&mut l, &mut src, &mut t, &mut log));
        assert!(critical.is_empty(), "a clean step is not news");
        assert_eq!(l.state(), RenderState::Running);
        probe.queue_event(DeviceEvent::Position { counter: report });
        critical.extend(tick_and_log(&mut l, &mut src, &mut t, &mut log));
        assert!(log.evidence_complete());
        let lines = lines_of(&mut log);
        (l, critical, lines)
    }

    #[test]
    fn a_driver_counter_regress_leaves_exactly_one_critical_line_that_carries_the_reaction() {
        let (l, critical, lines) = counter_fault_run(1063);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::CounterRegress));
        // Two critical events, as for every fault: the fault, then the state change it caused.
        let kinds: Vec<RenderEventKind> = critical.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                RenderEventKind::Fault {
                    reason: FaultReason::CounterRegress
                },
                RenderEventKind::State {
                    from: RenderState::Running,
                    to: RenderState::Faulted
                }
            ]
        );
        // Exactly one line carries the reaction, and it is the fault line.
        let carrying: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|l| {
                l["message"]
                    .as_str()
                    .unwrap()
                    .contains("mapping_invalidated")
            })
            .collect();
        assert_eq!(carrying.len(), 1);
        assert_eq!(carrying[0]["event_kind"], "d04_fault");
        assert_eq!(carrying[0]["fault"], "counter_regress");
        assert_eq!(carrying[0]["cause"], "driver_counter_regress");
        assert_eq!(
            carrying[0]["message"],
            "fault counter_regress mapping_invalidated"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l["cause"] == "driver_counter_regress")
                .count(),
            1
        );
        // The faulted state line after it is critical too and names no reaction.
        let state = lines.last().unwrap();
        assert_eq!(state["event_kind"], "d04_state");
        assert_eq!(state["message"], "state running to faulted");
        assert!(state.get("cause").is_none());
    }

    #[test]
    fn a_forward_overclaim_leaves_no_line_that_carries_the_reaction() {
        let (l, critical, lines) = counter_fault_run(1064 + 4096);
        assert_eq!(l.state(), RenderState::Faulted);
        assert_eq!(l.fault(), Some(FaultReason::SessionFaulted));
        assert!(l.presentation_mapping_valid());
        assert_eq!(critical.len(), 2);
        let fault_lines: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|l| l["event_kind"] == "d04_fault")
            .collect();
        assert_eq!(fault_lines.len(), 1);
        assert_eq!(fault_lines[0]["fault"], "session_faulted");
        assert_eq!(fault_lines[0]["cause"], "hal_session_fault");
        assert_eq!(fault_lines[0]["message"], "fault session_faulted");
        assert!(lines.iter().all(|l| {
            !l["message"]
                .as_str()
                .unwrap()
                .contains("mapping_invalidated")
                && l["cause"] != "driver_counter_regress"
        }));
    }
}
