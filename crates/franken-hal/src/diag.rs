//! Diagnostics through the real emission path (`P04` / `ffw-0bh`). Test-only.
//!
//! It is declared `#[cfg(test)] mod diag;` because the bounded, redacting sink and the `ffw.log.v1`
//! event type live in `franken-test-support`, which this crate depends on only for tests.
//!
//! The path under test is the production one: a [`LoggedSession`] emits one [`HalLogRecord`] per
//! call to a [`HalLogSink`]; [`DiagnosticAdapter`] is that sink, turning each record into a summary
//! event and each new fault into a critical event on a [`BoundedDiagnosticSink`]. Nothing is
//! reconstructed after the fact.
//!
//! What is mapped, per `docs/contracts/p04.md`:
//! * `run_id`, `case_id`, `correlation_id`: fixed by the harness; `member_id` and `group_id` are
//!   pseudonymized by the sink when it is given a key;
//! * `timestamp_mono_ns`: the call sequence number, scaled. It orders events; it is not wall time;
//! * `state_revision`: the frames the device has accepted (a monotonic counter);
//! * `queue_depth`: slots in flight plus quarantined;
//! * `fault`: the injected fault schedule entry the harness was running;
//! * `cause`: the session's own fault code, which is the causal chain.
//!
//! Everything here is a host simulation: every summary carries the record's `evidence` and `scope`,
//! so a log cannot be read as device evidence.

use crate::logged::{HalLogRecord, HalLogSink};
use franken_test_support::{BoundedDiagnosticSink, DiagnosticEvent, LOG_SCHEMA_VERSION};

/// Feeds a [`BoundedDiagnosticSink`] from a [`crate::logged::LoggedSession`].
pub struct DiagnosticAdapter {
    pub sink: BoundedDiagnosticSink,
    /// The injected fault schedule entry in force, if the harness is injecting one.
    pub injected: Option<&'static str>,
}

impl DiagnosticAdapter {
    fn event(
        &self,
        record: &HalLogRecord,
        kind: &str,
        message: String,
        cause: Option<String>,
    ) -> DiagnosticEvent {
        DiagnosticEvent {
            schema_version: LOG_SCHEMA_VERSION.to_string(),
            timestamp_mono_ns: record.seq * 1_000_000,
            run_id: "p04-run-1".to_string(),
            case_id: "p04-diag-case".to_string(),
            correlation_id: "corr-1".to_string(),
            member_id: "spk-fixture-s5".to_string(),
            group_id: "grp-fixture".to_string(),
            source_epoch: 0,
            state_revision: record.accepted_frames,
            event_kind: kind.to_string(),
            message,
            queue_depth: record.slots_in_flight + record.slots_quarantined,
            latency_us: 0,
            fault: self.injected.map(str::to_string),
            cause,
        }
    }
}

impl HalLogSink for DiagnosticAdapter {
    /// One summary event for the call, and one critical event for each fault the call caused.
    ///
    /// What the return value means depends on the record. For a record that carries a fault it is
    /// whether every fault event was stored: the summary is ordinary, may be dropped when the sink is
    /// full, and must not make a stored fault look lost. For any other record it is whether the
    /// summary was stored. The sink's own counters stay exact per event either way.
    fn emit(&mut self, record: HalLogRecord, _critical: bool) -> bool {
        let summary = format!(
            "op={:?} ok={} phase={:?} amp={:?} evidence={} scope={} anomalies={}",
            record.op,
            record.ok,
            record.phase,
            record.amp,
            record.evidence,
            record.scope,
            record.anomalies
        );
        let summary_kept = self
            .sink
            .try_emit(self.event(&record, "hal_call", summary, None));
        if record.new_faults.is_empty() {
            return summary_kept;
        }
        let mut faults_kept = true;
        for fault in &record.new_faults {
            let cause = format!("{:?}", fault.code);
            let event = self.event(
                &record,
                "hal_fault",
                "the session faulted and muted".to_string(),
                Some(cause),
            );
            faults_kept &= self.sink.emit_critical(event);
        }
        faults_kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::DeviceEvent;
    use crate::backend::{FakeBackend, FakeConfig, FakeProbe};
    use crate::logged::LoggedSession;
    use crate::session::{
        DrainOutcome, HalSession, SessionConfig, SessionReceipt, StartPreconditions,
    };
    use crate::slots::LeakLedger;
    use std::sync::Arc;

    const READY: StartPreconditions = StartPreconditions {
        presentation_mapping_installed: true,
        safe_gain_installed: true,
    };
    const BLOCK: [u8; 16] = [0x5A; 16];

    fn session_with(
        cfg: FakeConfig,
        quarantine_cap: usize,
    ) -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(cfg);
        let profile = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), quarantine_cap);
        (HalSession::open(profile, backend, config).unwrap(), probe)
    }

    fn adapter(max_events: usize) -> DiagnosticAdapter {
        DiagnosticAdapter {
            sink: BoundedDiagnosticSink::new(max_events, 1 << 16).with_pseudonym_key([7; 32]),
            injected: Some("stale_completion@poll1"),
        }
    }

    /// prepare, start, submit one block, then a completion for a generation the slot was never at,
    /// a second poll, and a submit that the faulted session refuses: six calls, one fault.
    fn stale_completion_run(
        logged: &mut LoggedSession<FakeBackend, DiagnosticAdapter>,
        probe: &FakeProbe,
    ) {
        logged.prepare().unwrap();
        logged.start(READY).unwrap();
        let _token = logged.submit(&BLOCK).unwrap().token.unwrap();
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 99,
        });
        logged.poll();
        logged.poll();
        assert!(logged.submit(&BLOCK).is_err());
    }

    #[test]
    fn a_faulted_session_emits_its_causal_chain_as_bounded_pseudonymized_jsonl() {
        let (s, probe) = session_with(FakeConfig::retained(), 2);
        let mut logged = LoggedSession::new(s, adapter(64));
        stale_completion_run(&mut logged, &probe);
        assert!(logged.evidence_complete());
        let (_session, adapter) = logged.into_parts();
        let jsonl = adapter.sink.to_jsonl();
        let lines: Vec<serde_json::Value> = jsonl
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // Six calls and one fault: six summaries and one critical fault event.
        assert_eq!(lines.len(), 7);
        for line in &lines {
            assert_eq!(line["schema_version"], LOG_SCHEMA_VERSION);
            assert_eq!(line["run_id"], "p04-run-1");
            assert_eq!(line["correlation_id"], "corr-1");
        }
        let faults: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|l| l["event_kind"] == "hal_fault")
            .collect();
        assert_eq!(
            faults.len(),
            1,
            "a fault is reported once, not on every later call"
        );
        let cause = faults[0]["cause"].as_str().unwrap();
        assert!(
            cause.contains("BadCompletion") && cause.contains("StaleGeneration"),
            "{cause}"
        );
        assert_eq!(faults[0]["fault"], "stale_completion@poll1");
        // Every summary says what kind of evidence this is, so a log cannot pass for device evidence.
        for line in lines.iter().filter(|l| l["event_kind"] == "hal_call") {
            let message = line["message"].as_str().unwrap();
            assert!(
                message.contains("evidence=model") && message.contains("scope=host_simulation"),
                "{message}"
            );
        }
        // The identifiers are pseudonymized, and no audio is logged.
        assert!(!jsonl.contains("spk-fixture-s5") && !jsonl.contains("grp-fixture"));
        assert!(!jsonl.contains("5a5a5a"));
        assert!(adapter.sink.is_evidence_complete());
        assert_eq!(adapter.sink.dropped_event_count(), 0);
        assert!(adapter.sink.human_summary().contains("evidence=complete"));
    }

    #[test]
    fn a_full_sink_drops_ordinary_events_but_keeps_the_fault() {
        // Two events fit. Traced by hand: prepare and start fill it; submit's summary is dropped;
        // the faulting poll's summary is dropped and its fault evicts the oldest ordinary event; the
        // last two summaries are dropped.
        let (s, probe) = session_with(FakeConfig::retained(), 2);
        let mut logged = LoggedSession::new(s, adapter(2));
        stale_completion_run(&mut logged, &probe);
        assert!(logged.evidence_complete(), "the fault was stored");
        let (_session, adapter) = logged.into_parts();
        let kinds: Vec<&str> = adapter
            .sink
            .events()
            .iter()
            .map(|e| e.event_kind.as_str())
            .collect();
        assert_eq!(kinds, vec!["hal_call", "hal_fault"]);
        assert_eq!(adapter.sink.events().len(), 2);
        assert_eq!(adapter.sink.emitted_event_count(), 7);
        assert_eq!(adapter.sink.dropped_event_count(), 5);
        assert_eq!(adapter.sink.evicted_event_count(), 1);
        assert!(adapter.sink.is_evidence_complete());
    }

    #[test]
    fn losing_a_fault_marks_both_the_sink_and_the_wrapper_incomplete() {
        // A drain that times out with the quarantine cap at 1 records two faults in one call. A sink
        // that holds one event can keep only the first.
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (s, probe) = session_with(cfg, 1);
        let mut logged = LoggedSession::new(s, adapter(1));
        logged.prepare().unwrap();
        logged.start(READY).unwrap();
        probe.set_lose_completions(true);
        let _a = logged.submit(&BLOCK).unwrap().token.unwrap();
        let _b = logged.submit(&BLOCK).unwrap().token.unwrap();
        assert_eq!(
            logged.drain(1),
            Ok(DrainOutcome::TimedOut { waited_ticks: 1 })
        );
        assert!(!logged.evidence_complete());
        assert_eq!(logged.log_stats().critical_lost, 1);
        let (_session, adapter) = logged.into_parts();
        assert_eq!(adapter.sink.critical_evidence_lost(), 1);
        assert!(!adapter.sink.is_evidence_complete());
        let kept: Vec<&str> = adapter
            .sink
            .events()
            .iter()
            .filter_map(|e| e.cause.as_deref())
            .collect();
        assert_eq!(
            kept,
            vec!["DrainTimedOut"],
            "the first fault was kept; the second was lost"
        );
        assert_eq!(
            adapter.sink.emitted_event_count(),
            u64::try_from(adapter.sink.events().len()).unwrap()
                + adapter.sink.dropped_event_count(),
            "every event is stored or counted"
        );
    }

    fn bare_cycle() -> (Vec<String>, SessionReceipt) {
        let (mut s, _probe) = session_with(FakeConfig::retained(), 2);
        let transcript = vec![
            format!("{:?}", s.prepare()),
            format!("{:?}", s.start(READY)),
            format!("{}", s.submit(&BLOCK).unwrap().accepted_frames),
            s.step().completions.to_string(),
            s.step().completions.to_string(),
            format!("{:?}", s.drain(5)),
        ];
        (transcript, s.receipt())
    }

    fn logged_cycle(adapter: DiagnosticAdapter) -> (Vec<String>, SessionReceipt) {
        let (s, _probe) = session_with(FakeConfig::retained(), 2);
        let mut l = LoggedSession::new(s, adapter);
        let transcript = vec![
            format!("{:?}", l.prepare()),
            format!("{:?}", l.start(READY)),
            format!("{}", l.submit(&BLOCK).unwrap().accepted_frames),
            l.step().completions.to_string(),
            l.step().completions.to_string(),
            format!("{:?}", l.drain(5)),
        ];
        (transcript, l.session().receipt())
    }

    #[test]
    fn no_sink_condition_changes_what_the_session_does() {
        let bare = bare_cycle();
        // The drain waited one tick and was acknowledged, the same in every case below.
        assert_eq!(bare.0[5], "Ok(Acknowledged { waited_ticks: 1 })");

        let healthy = logged_cycle(adapter(100));
        let full = {
            // A sink that is already full of an unrelated event before the run starts.
            let mut a = adapter(1);
            let filler = a.event(
                &HalLogRecord {
                    schema: String::new(),
                    seq: 0,
                    op: crate::logged::LoggedOp::Prepare,
                    ok: true,
                    error: None,
                    phase: crate::session::SessionPhase::Closed,
                    amp: crate::session::Amp::Muted,
                    accepted_frames: 0,
                    consumed_frames: 0,
                    slots_in_flight: 0,
                    slots_quarantined: 0,
                    anomalies: 0,
                    new_faults: Vec::new(),
                    evidence: "model".to_string(),
                    scope: "host_simulation".to_string(),
                },
                "filler",
                "x".to_string(),
                None,
            );
            assert!(a.sink.try_emit(filler));
            logged_cycle(a)
        };
        let unavailable = {
            let mut a = adapter(100);
            a.sink.set_unavailable(true);
            logged_cycle(a)
        };
        assert_eq!(healthy, bare);
        assert_eq!(full, bare);
        assert_eq!(unavailable, bare);
    }
}
