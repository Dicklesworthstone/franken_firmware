//! Diagnostics for the E04 contract and simulator, as `ffw.log.v1` JSONL (`E04` / `ffw-25l`).
//!
//! [`ContractLog`] turns what the contract evaluation and the trace simulator found into structured,
//! bounded, redacted log lines. This crate writes the JSONL itself: `franken-test-support` is a
//! dev-dependency only, and the tests use it to check that every line has exactly the `ffw.log.v1`
//! shape and survives its redactor unchanged.
//!
//! What it logs:
//! * an eligibility verdict: one summary line, and one **critical** line for every missing item
//!   (record, field and the reason or the external blocker that would establish it);
//! * every simulator step: an ordinary line for what applied or was refused, a **critical** line
//!   for a driver anomaly, a drain timeout or an unacknowledged mute, and a critical line naming
//!   the exact step when a replay disagrees with its hand-written expectation.
//!
//! Properties, each pinned by a test:
//! * **Bounded.** At most the configured number of lines are kept, each at most
//!   [`MAX_MESSAGE_CHARS`] characters of message. A full log drops ordinary lines first; a critical
//!   line evicts the oldest ordinary one and is lost only when the log holds nothing but critical
//!   lines, which is counted and marks the evidence incomplete. It never blocks.
//! * **Redacted by construction.** A line is built from enum names, numbers and identifiers that
//!   passed [`safe_id`]. Free text from a matrix (a blocker's `needs`, an inconsistency's detail)
//!   is never copied, so a hostile record id or description cannot reach a line.
//! * **Not a clock.** `timestamp_mono_ns` is a line counter scaled to nanoseconds; it orders
//!   lines and is not wall time. Nothing here is a hardware claim.

use crate::contract::{ContractScope, EligibilityReport, MissingContract, MissingReason};
use crate::dma_sim::{Mismatch, SimEvent, SimSnapshot, SlotState, StepOutcome, TraceCase};
use crate::emit::{Critical, CriticalQueue, PushOutcome};
use serde::Serialize;

/// The schema string every line carries.
pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";
/// Longest identifier [`safe_id`] accepts.
pub const MAX_ID_CHARS: usize = 64;
/// Longest message a line carries; a longer one is cut.
pub const MAX_MESSAGE_CHARS: usize = 160;

/// An identifier that is safe to put in a log line, or `invalid_id`.
///
/// Letters, digits, `.`, `_`, `:` and `-` only, 1 to [`MAX_ID_CHARS`] characters. Anything else, a
/// space or an `=` or a dotted quad, is replaced rather than escaped: an identifier the log cannot
/// vouch for is not worth quoting.
#[must_use]
pub fn safe_id(raw: &str) -> String {
    let ok = !raw.is_empty()
        && raw.chars().count() <= MAX_ID_CHARS
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    // A bare dotted quad is made only of allowed characters; it still is not an identifier.
    let dotted_quad = raw.split('.').count() == 4
        && raw
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    if ok && !dotted_quad {
        raw.to_string()
    } else {
        "invalid_id".to_string()
    }
}

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

fn event_type(event: &SimEvent) -> String {
    serde_json::to_value(event)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str().map(str::to_string)))
        .unwrap_or_else(|| "unknown".to_string())
}

/// One `ffw.log.v1` line. Field order is the schema's; the optional fields are left out when
/// absent, as the schema's own type does.
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

/// What a caller says about one line.
struct Draft {
    kind: &'static str,
    message: String,
    revision: u64,
    depth: usize,
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

/// Exact accounting: `emitted == drained + pending + dropped_ordinary + evicted_ordinary +
/// lost_critical`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LogStats {
    pub emitted: u64,
    pub dropped_ordinary: u64,
    pub evicted_ordinary: u64,
    pub lost_critical: u64,
}

/// A bounded, non-blocking log of what the contract and the simulator found.
#[derive(Debug)]
pub struct ContractLog {
    run_id: String,
    queue: CriticalQueue<Entry>,
    seq: u64,
    stats: LogStats,
}

impl ContractLog {
    /// A log that keeps at most `capacity` lines (at least one). `run_id` is validated.
    #[must_use]
    pub fn new(run_id: &str, capacity: usize) -> Self {
        Self {
            run_id: safe_id(run_id),
            queue: CriticalQueue::new(capacity.max(1)),
            seq: 0,
            stats: LogStats::default(),
        }
    }

    #[must_use]
    pub const fn stats(&self) -> LogStats {
        self.stats
    }

    /// False once a critical line could not be kept: the evidence behind a verdict is incomplete.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.stats.lost_critical == 0
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

    fn push(&mut self, case_id: &str, draft: Draft) {
        self.seq += 1;
        let case = safe_id(case_id);
        let line = LogLine {
            schema_version: LOG_SCHEMA_VERSION,
            timestamp_mono_ns: self.seq.saturating_mul(1_000_000),
            run_id: self.run_id.clone(),
            case_id: case.clone(),
            correlation_id: case,
            member_id: "none".to_string(),
            group_id: "none".to_string(),
            source_epoch: 0,
            state_revision: draft.revision,
            event_kind: draft.kind.to_string(),
            message: clip(draft.message),
            queue_depth: draft.depth,
            latency_us: 0,
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

    /// Log a verdict: a summary, then every missing item.
    pub fn log_eligibility(&mut self, case_id: &str, report: &EligibilityReport) {
        self.push(
            case_id,
            Draft {
                kind: "e04_eligibility",
                message: format!(
                    "hardware_eligible={} offline_model_ok={} missing={}",
                    report.hardware_eligible,
                    report.offline_model_ok,
                    report.missing.len()
                ),
                revision: 0,
                depth: report.missing.len(),
                fault: None,
                cause: None,
                critical: true,
            },
        );
        for (index, item) in report.missing.iter().enumerate() {
            self.push(case_id, missing_line(index, item));
        }
    }

    /// Log one simulator step and what it did.
    pub fn log_step(
        &mut self,
        case_id: &str,
        index: usize,
        event: &SimEvent,
        outcome: &StepOutcome,
        after: &SimSnapshot,
    ) {
        let revision = u64::try_from(index).unwrap_or(u64::MAX);
        let in_flight = after
            .slots
            .iter()
            .filter(|s| matches!(s, SlotState::DmaOwned | SlotState::Quarantined))
            .count();
        let name = event_type(event);
        let (kind, critical, fault, cause, verb) = match outcome {
            StepOutcome::Applied => ("e04_step", false, None, None, "ok".to_string()),
            StepOutcome::Partial { remainder } => (
                "e04_step",
                false,
                None,
                None,
                format!("partial remainder={remainder}"),
            ),
            StepOutcome::Refused { reason } => (
                "e04_refused",
                false,
                None,
                Some(serde_name(reason)),
                "refused".to_string(),
            ),
            StepOutcome::Anomaly { kind } => (
                "e04_anomaly",
                true,
                None,
                Some(serde_name(kind)),
                "anomaly".to_string(),
            ),
            StepOutcome::DrainTimedOut => (
                "e04_fault",
                true,
                Some("drain_timed_out".to_string()),
                None,
                "drain timed out".to_string(),
            ),
            StepOutcome::MuteFailed => (
                "e04_fault",
                true,
                Some("mute_failed".to_string()),
                None,
                "mute was not acknowledged".to_string(),
            ),
        };
        self.push(
            case_id,
            Draft {
                kind,
                message: format!("step {index} {name} {verb}"),
                revision,
                depth: in_flight,
                fault,
                cause,
                critical,
            },
        );
    }

    /// Replay a trace exactly as [`crate::dma_sim::replay`] does, logging every step and, on a
    /// disagreement, a critical line that names the step. The verdict is the replay's own.
    pub fn replay_logged(&mut self, case: &TraceCase) -> Result<(), Mismatch> {
        let mut sim = case.sim();
        for (index, step) in case.steps.iter().enumerate() {
            let observed = sim.apply(&step.event);
            self.log_step(&case.id, index, &step.event, &observed, &sim.snapshot());
            if observed != step.expect {
                self.log_mismatch(&case.id, Some(index));
                return Err(Mismatch {
                    case: case.id.clone(),
                    step: Some(index),
                    expected: format!("{:?}", step.expect),
                    observed: format!("{observed:?}"),
                });
            }
        }
        let snapshot = sim.snapshot();
        if snapshot == case.expect_final {
            Ok(())
        } else {
            self.log_mismatch(&case.id, None);
            Err(Mismatch {
                case: case.id.clone(),
                step: None,
                expected: format!("{:?}", case.expect_final),
                observed: format!("{snapshot:?}"),
            })
        }
    }

    fn log_mismatch(&mut self, case_id: &str, step: Option<usize>) {
        let (revision, where_) = match step {
            Some(index) => (
                u64::try_from(index).unwrap_or(u64::MAX),
                format!("step {index}"),
            ),
            None => (u64::MAX, "the final state".to_string()),
        };
        self.push(
            case_id,
            Draft {
                kind: "e04_replay_mismatch",
                message: format!("the replay disagrees with its expectation at {where_}"),
                revision,
                depth: 0,
                fault: Some("replay_mismatch".to_string()),
                cause: None,
                critical: true,
            },
        );
    }
}

fn missing_line(index: usize, item: &MissingContract) -> Draft {
    let scope = match item.scope {
        ContractScope::AudioOutput => "audio_output",
        ContractScope::RadioCoexistence => "radio_coexistence",
        ContractScope::Topology => "topology",
        ContractScope::AmpSequencing => "amp_sequencing",
    };
    let cause = match &item.reason {
        MissingReason::NoRecord => "no_record".to_string(),
        MissingReason::Unknown { blocker } => safe_id(&blocker.id),
        MissingReason::SyntheticAnchor { .. } => "synthetic_anchor".to_string(),
        MissingReason::UnregisteredArtifact { .. } => "unregistered_artifact".to_string(),
        MissingReason::BadAnchor { .. } => "bad_anchor".to_string(),
        MissingReason::Inconsistent { .. } => "inconsistent".to_string(),
    };
    Draft {
        kind: "e04_missing",
        message: format!(
            "{scope} {} {}",
            safe_id(&item.record),
            serde_name(&item.field)
        ),
        revision: u64::try_from(index).unwrap_or(u64::MAX),
        depth: 0,
        fault: None,
        cause: Some(cause),
        critical: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::fixtures::{anchor_synthetic, complete_matrix};
    use crate::contract::{ContractMatrix, MissingReason};
    use crate::dma_sim::{SimCases, replay};
    use franken_test_support::{DiagnosticEvent, redact_sensitive_text};

    const MATRIX_JSON: &str = include_str!("../../../tests/e04/matrix_audiodev_m16.json");
    const CASES_JSON: &str = include_str!("../../../tests/e04/sim_cases.json");

    fn committed_matrix() -> ContractMatrix {
        serde_json::from_str(MATRIX_JSON).unwrap()
    }

    fn cases() -> SimCases {
        serde_json::from_str(CASES_JSON).unwrap()
    }

    fn lines_of(log: &mut ContractLog) -> Vec<serde_json::Value> {
        log.drain_jsonl()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn every_line_has_exactly_the_ffw_log_v1_shape_and_survives_the_redactor_unchanged() {
        let mut log = ContractLog::new("e04-run-1", 4096);
        log.log_eligibility("matrix-m16", &committed_matrix().evaluate());
        log.log_eligibility(
            "matrix-synthetic",
            &complete_matrix(anchor_synthetic).evaluate(),
        );
        for case in &cases().cases {
            let _ = log.replay_logged(case);
        }
        assert!(log.evidence_complete());
        let text = log.drain_jsonl();
        let mut count = 0;
        for line in text.lines() {
            // The schema's own type reads the line and writes it back byte for byte: the field
            // names, their order and the omission of absent optional fields all match.
            let event: DiagnosticEvent = serde_json::from_str(line).unwrap();
            assert_eq!(serde_json::to_string(&event).unwrap(), line);
            assert_eq!(
                event.schema_version,
                franken_test_support::LOG_SCHEMA_VERSION
            );
            assert_eq!(event.schema_version, LOG_SCHEMA_VERSION);
            // Nothing in it is something the redactor would change.
            assert_eq!(redact_sensitive_text(line), line);
            count += 1;
        }
        // 1 + 111 for the committed matrix, 1 + 111 for the synthetic one, and every step of 20 cases.
        assert!(count > 224, "{count}");
    }

    #[test]
    fn the_committed_matrix_logs_a_summary_and_one_critical_line_per_missing_item() {
        let mut log = ContractLog::new("e04-run-1", 512);
        log.log_eligibility("matrix-m16", &committed_matrix().evaluate());
        assert_eq!(log.stats().emitted, 112);
        assert!(log.evidence_complete());
        let lines = lines_of(&mut log);
        assert_eq!(lines.len(), 112);
        let summary = &lines[0];
        assert_eq!(summary["event_kind"], "e04_eligibility");
        assert_eq!(
            summary["message"],
            "hardware_eligible=false offline_model_ok=false missing=111"
        );
        // The first missing item names its record, its field and the external blocker, not the
        // blocker's free text.
        let first = &lines[1];
        assert_eq!(first["event_kind"], "e04_missing");
        assert_eq!(
            first["message"],
            "audio_output op.query_capabilities interface"
        );
        assert_eq!(first["cause"], "EXT-E04-OP-MAPPING");
        assert!(!first.to_string().contains("not established"));
        // The new records are in the log too.
        assert!(lines.iter().any(|l| {
            l["message"] == "topology topology.audio_output routing"
                && l["cause"] == "EXT-E04-CHANNEL-TOPOLOGY"
        }));
        assert!(lines.iter().any(|l| {
            l["message"] == "amp_sequencing amp.startup steps"
                && l["cause"] == "EXT-E04-AMP-SEQUENCE"
        }));
    }

    #[test]
    fn a_small_log_is_bounded_and_counts_every_line_it_could_not_keep() {
        let mut log = ContractLog::new("e04-run-1", 8);
        log.log_eligibility("matrix-m16", &committed_matrix().evaluate());
        // Every line of a verdict is critical, so a log that holds eight keeps the first eight and
        // counts the other 104 as lost evidence.
        assert_eq!(log.pending(), 8);
        let stats = log.stats();
        assert_eq!(
            stats,
            LogStats {
                emitted: 112,
                dropped_ordinary: 0,
                evicted_ordinary: 0,
                lost_critical: 104
            }
        );
        assert!(!log.evidence_complete());
        let kept = u64::try_from(lines_of(&mut log).len()).unwrap();
        assert_eq!(
            stats.emitted,
            kept + stats.dropped_ordinary + stats.evicted_ordinary + stats.lost_critical
        );
    }

    #[test]
    fn a_full_log_drops_ordinary_lines_before_it_loses_a_critical_one() {
        let file = cases();
        let case = file.cases.iter().find(|c| c.id == "E04-SIM-016").unwrap();
        // SIM-016 has refusals (ordinary) and two anomalies (critical) among ten steps.
        let mut log = ContractLog::new("e04-run-1", 4);
        replay(case).unwrap();
        log.replay_logged(case).unwrap();
        let stats = log.stats();
        assert_eq!(stats.emitted, 10);
        assert_eq!(stats.lost_critical, 0, "{stats:?}");
        assert!(stats.dropped_ordinary + stats.evicted_ordinary > 0);
        let kept = lines_of(&mut log);
        assert_eq!(kept.len(), 4);
        // Both anomalies survived.
        let anomalies = kept
            .iter()
            .filter(|l| l["event_kind"] == "e04_anomaly")
            .count();
        assert_eq!(anomalies, 2);
    }

    #[test]
    fn a_refusal_and_an_anomaly_are_logged_with_the_cause_the_model_gave() {
        let file = cases();
        let case = file.cases.iter().find(|c| c.id == "E04-SIM-016").unwrap();
        let mut log = ContractLog::new("e04-run-1", 64);
        log.replay_logged(case).unwrap();
        let lines = lines_of(&mut log);
        assert_eq!(lines.len(), 10);
        // Step 0 of the case is acquire, so the first byte-level submit is step 2: refused.
        assert_eq!(lines[2]["event_kind"], "e04_refused");
        assert_eq!(lines[2]["cause"], "partial_frame");
        assert_eq!(lines[2]["message"], "step 2 submit_bytes refused");
        assert_eq!(lines[3]["event_kind"], "e04_anomaly");
        assert_eq!(lines[3]["cause"], "accepted_partial_frame");
        // The lines are ordered: a counter, not a clock.
        let stamps: Vec<u64> = lines
            .iter()
            .map(|l| l["timestamp_mono_ns"].as_u64().unwrap())
            .collect();
        assert!(stamps.windows(2).all(|w| w[1] > w[0]));
        // A step in flight is reflected in queue_depth: after the partial submit one slot is DMA-owned.
        assert_eq!(lines[6]["queue_depth"], 1);
    }

    #[test]
    fn a_replay_that_disagrees_logs_a_critical_line_that_names_the_step() {
        let file = cases();
        let mut case = file
            .cases
            .iter()
            .find(|c| c.id == "E04-SIM-002")
            .unwrap()
            .clone();
        case.steps[4].expect = StepOutcome::Applied;
        let mut log = ContractLog::new("e04-run-1", 64);
        let mismatch = log.replay_logged(&case).unwrap_err();
        assert_eq!(mismatch.step, Some(4));
        let lines = lines_of(&mut log);
        let last = lines.last().unwrap();
        assert_eq!(last["event_kind"], "e04_replay_mismatch");
        assert_eq!(last["state_revision"], 4);
        assert_eq!(last["fault"], "replay_mismatch");
        // The unmodified case replays cleanly through the log, with the same verdict as the replay.
        let mut log = ContractLog::new("e04-run-1", 64);
        for case in &file.cases {
            assert_eq!(log.replay_logged(case).is_ok(), replay(case).is_ok());
        }
    }

    #[test]
    fn identifiers_are_validated_not_trusted() {
        assert_eq!(safe_id("op.query_capabilities"), "op.query_capabilities");
        assert_eq!(safe_id("EXT-E04-OP-MAPPING"), "EXT-E04-OP-MAPPING");
        let too_long = "x".repeat(MAX_ID_CHARS + 1);
        for hostile in [
            "",
            "password=hunter2",
            "has a space",
            "10.0.0.7",
            "new\nline",
            "tab\there",
            too_long.as_str(),
        ] {
            assert_eq!(safe_id(hostile), "invalid_id", "{hostile:?}");
        }
        // The longest identifier that is allowed is.
        let longest = "x".repeat(MAX_ID_CHARS);
        assert_eq!(safe_id(&longest), longest);
        // A hostile record id in a matrix cannot reach a line.
        let mut matrix = complete_matrix(anchor_synthetic);
        matrix.interfaces[0].id = "10.0.0.7 password=hunter2".to_string();
        let mut log = ContractLog::new("run 1; token=abc", 512);
        log.log_eligibility("case with spaces", &matrix.evaluate());
        let text = log.drain_jsonl();
        assert!(!text.contains("hunter2") && !text.contains("10.0.0.7") && !text.contains("abc"));
        assert!(text.contains("invalid_id"));
        for line in text.lines() {
            assert_eq!(redact_sensitive_text(line), line);
        }
    }

    #[test]
    fn a_long_message_is_cut_and_a_blocker_description_is_never_copied() {
        assert_eq!(clip("x".repeat(500)).chars().count(), MAX_MESSAGE_CHARS);
        let mut matrix = committed_matrix();
        if let crate::contract::FieldStatus::Unknown { blocker } =
            &mut matrix.interfaces[0].interface
        {
            blocker.needs = "secret=topsecret at 192.168.1.9".to_string();
        }
        let mut log = ContractLog::new("run", 512);
        log.log_eligibility("m", &matrix.evaluate());
        let text = log.drain_jsonl();
        assert!(!text.contains("topsecret") && !text.contains("192.168.1.9"));
        // The reason's kind is still in the line, as the blocker id.
        let report = matrix.evaluate();
        assert!(matches!(
            report.missing[0].reason,
            MissingReason::Unknown { .. }
        ));
        assert!(text.contains("EXT-E04-OP-MAPPING"));
    }
}
