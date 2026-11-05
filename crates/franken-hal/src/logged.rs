//! Log emission around a [`HalSession`] (`P04` / `ffw-0bh`).
//!
//! [`LoggedSession`] is a decorator. Every call is forwarded to the session unchanged and its result
//! is returned unchanged; afterwards one [`HalLogRecord`] is handed to a [`HalLogSink`].
//!
//! What a record says about transitions comes from the session itself: [`HalSession`] emits an event
//! at each transition into its own bounded queue (see [`crate::emit`]), and the wrapper takes those
//! events after every call. Nothing is reconstructed from a receipt afterwards.
//!
//! The properties, each pinned by a test:
//! * **Transparent.** The result of every call is exactly what the bare session returns. The sink is
//!   written to after the call and its answer is only counted, so a healthy, slow, full or
//!   unavailable sink cannot change what the session does.
//! * **Non-blocking, bounded.** The sink trait takes a record and answers whether it kept it. The
//!   wrapper holds O(1) state, and a record is bounded by the session's event queue capacity.
//! * **Loss is counted, from both sides.** A record the sink refuses is counted, and one that carried
//!   a fault marks the evidence incomplete. Events the session's own queue could not keep are
//!   reported in the record that follows, and a lost fault marks the evidence incomplete too.
//! * **Timebase.** `seq` counts calls. It is not wall time; this layer has no clock.
//! * **No audio.** A record carries counters and fault codes, never samples.
//!
//! Each call builds a receipt, which allocates. This is a harness and diagnostics layer, not the
//! render loop.
//!
//! Records say `evidence: model` and `scope: host_simulation` for the fake, via the receipt, so a
//! log can never be read as device evidence.

use crate::backend::DeviceBackend;
use crate::emit::{EmitStats, SessionEvent};
use crate::session::{
    AbortReport, Amp, DrainOutcome, HalSession, PollReport, SessionError, SessionPhase,
    StartPreconditions, SubmitReceipt,
};
use serde::{Deserialize, Serialize};

/// Schema string of a [`HalLogRecord`]. `v2` replaced the receipt-diffed `new_faults` list with the
/// session's own `events` and the two loss counters.
pub const LOG_SCHEMA: &str = "ffw.p04.log.v2";

/// The session operation a record is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggedOp {
    Prepare,
    Start,
    Submit,
    Poll,
    Step,
    Drain,
    CancelDrain,
    AbortMute,
    ResetDevice,
}

/// One log record: the state after a call, and the events that call caused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HalLogRecord {
    pub schema: String,
    /// Call sequence number, starting at 1. The timebase of this log.
    pub seq: u64,
    pub op: LoggedOp,
    pub ok: bool,
    /// The error's text when the call failed.
    pub error: Option<String>,
    pub phase: SessionPhase,
    pub amp: Amp,
    pub accepted_frames: u64,
    pub consumed_frames: u64,
    pub slots_in_flight: usize,
    pub slots_quarantined: usize,
    pub anomalies: u32,
    /// Events the session emitted that this record is the first to report, oldest first. Their
    /// `seq` values show any gap.
    pub events: Vec<SessionEvent>,
    /// Ordinary events the session's queue dropped or evicted since the previous record.
    pub events_lost: u64,
    /// Critical events (faults) the session's queue could not keep since the previous record.
    pub critical_events_lost: u64,
    /// `model` for a fake device, `driver` for a real one.
    pub evidence: String,
    pub scope: String,
}

impl HalLogRecord {
    /// A record that carries a fault, or reports that one was lost, is evidence a result cannot be
    /// trusted without.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical_events_lost > 0 || self.events.iter().any(|e| e.kind.is_critical())
    }

    /// One JSON line, without a trailing newline.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Where records go. It must not block. `critical` marks a record that carries a fault.
pub trait HalLogSink {
    /// Returns whether the record's evidence was kept. For a critical record that is the fault
    /// information it carries; a sink may drop that record's ordinary parts and still answer true.
    fn emit(&mut self, record: HalLogRecord, critical: bool) -> bool;
}

/// A sink that keeps nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl HalLogSink for NullSink {
    fn emit(&mut self, _record: HalLogRecord, _critical: bool) -> bool {
        false
    }
}

/// Exact accounting of what the sink did with the records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogStats {
    pub emitted: u64,
    pub kept: u64,
    pub dropped: u64,
    /// Refused records that carried a fault.
    pub critical_lost: u64,
}

fn error_text<T>(result: &Result<T, SessionError>) -> Option<String> {
    result.as_ref().err().map(ToString::to_string)
}

/// A session whose every call is logged.
pub struct LoggedSession<B: DeviceBackend, L: HalLogSink> {
    session: HalSession<B>,
    sink: L,
    seq: u64,
    /// The session's event accounting as of the previous record, so each record reports only what
    /// was lost since.
    events_seen: EmitStats,
    stats: LogStats,
}

impl<B: DeviceBackend, L: HalLogSink> LoggedSession<B, L> {
    /// Wrap a session. Events it emitted earlier and nobody has taken are reported in the first
    /// record, and so is any loss so far; events the owner already took are not repeated.
    #[must_use]
    pub fn new(session: HalSession<B>, sink: L) -> Self {
        Self {
            session,
            sink,
            seq: 0,
            events_seen: EmitStats::default(),
            stats: LogStats::default(),
        }
    }

    /// Read-only view of the session.
    #[must_use]
    pub const fn session(&self) -> &HalSession<B> {
        &self.session
    }

    #[must_use]
    pub const fn log_stats(&self) -> LogStats {
        self.stats
    }

    /// False once a record carrying a fault was refused by the sink, or the session's own queue lost
    /// a fault.
    #[must_use]
    pub const fn evidence_complete(&self) -> bool {
        self.stats.critical_lost == 0 && self.session.event_evidence_complete()
    }

    /// Give the session and the sink back, for example to close the session.
    #[must_use]
    pub fn into_parts(self) -> (HalSession<B>, L) {
        (self.session, self.sink)
    }

    fn log(&mut self, op: LoggedOp, error: Option<String>) {
        let receipt = self.session.receipt();
        let events: Vec<SessionEvent> = std::iter::from_fn(|| self.session.take_event()).collect();
        let now = self.session.event_stats();
        let before = self.events_seen;
        let events_lost = (now.dropped_ordinary + now.evicted_ordinary)
            .saturating_sub(before.dropped_ordinary + before.evicted_ordinary);
        let critical_events_lost = now.lost_critical.saturating_sub(before.lost_critical);
        self.events_seen = now;
        self.seq += 1;
        let record = HalLogRecord {
            schema: LOG_SCHEMA.to_string(),
            seq: self.seq,
            op,
            ok: error.is_none(),
            error,
            phase: receipt.phase,
            amp: receipt.amp,
            accepted_frames: receipt.accepted_frames,
            consumed_frames: receipt.consumed_frames,
            slots_in_flight: receipt.slots_in_flight,
            slots_quarantined: receipt.slots_quarantined,
            anomalies: receipt.anomalies,
            events,
            events_lost,
            critical_events_lost,
            evidence: receipt.evidence,
            scope: receipt.scope,
        };
        let critical = record.is_critical();
        self.stats.emitted += 1;
        if self.sink.emit(record, critical) {
            self.stats.kept += 1;
        } else {
            self.stats.dropped += 1;
            if critical {
                self.stats.critical_lost += 1;
            }
        }
    }

    pub fn prepare(&mut self) -> Result<(), SessionError> {
        let result = self.session.prepare();
        self.log(LoggedOp::Prepare, error_text(&result));
        result
    }

    pub fn start(&mut self, pre: StartPreconditions) -> Result<(), SessionError> {
        let result = self.session.start(pre);
        self.log(LoggedOp::Start, error_text(&result));
        result
    }

    pub fn submit(&mut self, bytes: &[u8]) -> Result<SubmitReceipt, SessionError> {
        let result = self.session.submit(bytes);
        self.log(LoggedOp::Submit, error_text(&result));
        result
    }

    pub fn poll(&mut self) -> PollReport {
        let report = self.session.poll();
        self.log(LoggedOp::Poll, None);
        report
    }

    pub fn step(&mut self) -> PollReport {
        let report = self.session.step();
        self.log(LoggedOp::Step, None);
        report
    }

    pub fn drain(&mut self, max_wait_ticks: u64) -> Result<DrainOutcome, SessionError> {
        let result = self.session.drain(max_wait_ticks);
        self.log(LoggedOp::Drain, error_text(&result));
        result
    }

    pub fn cancel_drain(&mut self) -> Result<(), SessionError> {
        let result = self.session.cancel_drain();
        self.log(LoggedOp::CancelDrain, error_text(&result));
        result
    }

    pub fn abort_mute(&mut self) -> Result<AbortReport, SessionError> {
        let result = self.session.abort_mute();
        self.log(LoggedOp::AbortMute, error_text(&result));
        result
    }

    pub fn reset_device(&mut self) -> Result<(), SessionError> {
        let result = self.session.reset_device();
        self.log(LoggedOp::ResetDevice, error_text(&result));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::DeviceEvent;
    use crate::backend::{FakeBackend, FakeConfig, FakeProbe};
    use crate::emit::SessionEventKind;
    use crate::session::{FaultCode, SessionConfig, SessionReceipt};
    use crate::slots::{CompletionProblem, LeakLedger};
    use std::sync::Arc;

    const READY: StartPreconditions = StartPreconditions {
        presentation_mapping_installed: true,
        safe_gain_installed: true,
    };
    const BLOCK: [u8; 16] = [0xAA; 16];

    fn session() -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(FakeConfig::retained());
        let profile = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), 2);
        (HalSession::open(profile, backend, config).unwrap(), probe)
    }

    fn session_caps(
        cfg: FakeConfig,
        quarantine_cap: usize,
        event_cap: usize,
    ) -> (HalSession<FakeBackend>, FakeProbe) {
        let (backend, probe) = FakeBackend::new(cfg);
        let profile = franken_board_profile::synthetic_test_fixture_catalog()
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let config = SessionConfig::with_ledger(Arc::new(LeakLedger::new(64)), quarantine_cap)
            .with_event_queue_cap(event_cap);
        (HalSession::open(profile, backend, config).unwrap(), probe)
    }

    fn stale_fault() -> SessionEventKind {
        SessionEventKind::Fault {
            code: FaultCode::BadCompletion {
                problem: CompletionProblem::StaleGeneration {
                    expected: 1,
                    got: 99,
                },
            },
        }
    }

    /// Keeps every record.
    #[derive(Default)]
    struct KeepSink {
        records: Vec<(HalLogRecord, bool)>,
    }

    impl HalLogSink for KeepSink {
        fn emit(&mut self, record: HalLogRecord, critical: bool) -> bool {
            self.records.push((record, critical));
            true
        }
    }

    /// Keeps the first `cap` records and then refuses everything: a sink that has filled up.
    struct CapSink {
        cap: usize,
        kept: usize,
    }

    impl HalLogSink for CapSink {
        fn emit(&mut self, _record: HalLogRecord, _critical: bool) -> bool {
            if self.kept < self.cap {
                self.kept += 1;
                true
            } else {
                false
            }
        }
    }

    fn submit_text(result: Result<SubmitReceipt, SessionError>) -> String {
        match result {
            Ok(r) => format!(
                "ok {} {} {}",
                r.accepted_bytes, r.accepted_frames, r.remainder_bytes
            ),
            Err(e) => format!("err {e}"),
        }
    }

    /// The same calls on a bare session and on a wrapped one, so results can be compared.
    trait Ops {
        fn do_prepare(&mut self) -> String;
        fn do_start(&mut self) -> String;
        fn do_submit(&mut self) -> String;
        fn do_poll(&mut self) -> usize;
        fn do_step(&mut self) -> usize;
        fn do_drain(&mut self, ticks: u64) -> String;
    }

    impl Ops for HalSession<FakeBackend> {
        fn do_prepare(&mut self) -> String {
            format!("{:?}", HalSession::prepare(self))
        }
        fn do_start(&mut self) -> String {
            format!("{:?}", HalSession::start(self, READY))
        }
        fn do_submit(&mut self) -> String {
            submit_text(HalSession::submit(self, &BLOCK))
        }
        fn do_poll(&mut self) -> usize {
            HalSession::poll(self).anomalies
        }
        fn do_step(&mut self) -> usize {
            HalSession::step(self).completions
        }
        fn do_drain(&mut self, ticks: u64) -> String {
            format!("{:?}", HalSession::drain(self, ticks))
        }
    }

    impl<L: HalLogSink> Ops for LoggedSession<FakeBackend, L> {
        fn do_prepare(&mut self) -> String {
            format!("{:?}", LoggedSession::prepare(self))
        }
        fn do_start(&mut self) -> String {
            format!("{:?}", LoggedSession::start(self, READY))
        }
        fn do_submit(&mut self) -> String {
            submit_text(LoggedSession::submit(self, &BLOCK))
        }
        fn do_poll(&mut self) -> usize {
            LoggedSession::poll(self).anomalies
        }
        fn do_step(&mut self) -> usize {
            LoggedSession::step(self).completions
        }
        fn do_drain(&mut self, ticks: u64) -> String {
            format!("{:?}", LoggedSession::drain(self, ticks))
        }
    }

    /// A clean cycle: prepare, start, submit one block, two steps (the completion lands on the
    /// second), drain.
    fn clean_cycle<S: Ops>(s: &mut S) -> Vec<String> {
        vec![
            s.do_prepare(),
            s.do_start(),
            s.do_submit(),
            s.do_step().to_string(),
            s.do_step().to_string(),
            s.do_drain(5),
        ]
    }

    /// A faulting cycle: a stale completion is injected after the submit.
    fn faulting_cycle<S: Ops>(s: &mut S, probe: &FakeProbe) -> Vec<String> {
        let mut out = vec![s.do_prepare(), s.do_start(), s.do_submit()];
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 99,
        });
        out.push(s.do_poll().to_string());
        out.push(s.do_poll().to_string());
        out.push(s.do_submit());
        out
    }

    #[test]
    fn every_call_is_logged_in_order_with_the_state_it_left() {
        let (s, _probe) = session();
        let mut logged = LoggedSession::new(s, KeepSink::default());
        let transcript = clean_cycle(&mut logged);
        assert_eq!(transcript[5], "Ok(Acknowledged { waited_ticks: 1 })");
        assert_eq!(
            logged.log_stats(),
            LogStats {
                emitted: 6,
                kept: 6,
                dropped: 0,
                critical_lost: 0
            }
        );
        assert!(logged.evidence_complete());
        let (_session, sink) = logged.into_parts();
        // (op, phase, amp, accepted_frames, slots_in_flight), traced by hand: the block is accepted
        // at tick 0 and completes at tick 2; the drain's flush is acknowledged one tick after.
        let shape: Vec<(LoggedOp, SessionPhase, Amp, u64, usize)> = sink
            .records
            .iter()
            .map(|(r, _)| (r.op, r.phase, r.amp, r.accepted_frames, r.slots_in_flight))
            .collect();
        assert_eq!(
            shape,
            vec![
                (LoggedOp::Prepare, SessionPhase::Prepared, Amp::Muted, 0, 0),
                (LoggedOp::Start, SessionPhase::Running, Amp::Unmuted, 0, 0),
                (LoggedOp::Submit, SessionPhase::Running, Amp::Unmuted, 4, 1),
                (LoggedOp::Step, SessionPhase::Running, Amp::Unmuted, 4, 1),
                (LoggedOp::Step, SessionPhase::Running, Amp::Unmuted, 4, 0),
                (LoggedOp::Drain, SessionPhase::Prepared, Amp::Muted, 4, 0),
            ]
        );
        let seqs: Vec<u64> = sink.records.iter().map(|(r, _)| r.seq).collect();
        assert_eq!(
            seqs,
            vec![1, 2, 3, 4, 5, 6],
            "the timebase is the call count"
        );
        assert!(sink.records.iter().all(|(r, critical)| r.ok
            && !critical
            && r.events_lost == 0
            && r.critical_events_lost == 0
            && r.events.iter().all(|e| !e.kind.is_critical())));
        // The events each record reports come from the session's own emission, traced by hand: only
        // prepare, start and the acknowledged stop are transitions, and the stop is acknowledged
        // with the block's four frames accepted.
        let events: Vec<Vec<(u64, u64, SessionEventKind)>> = sink
            .records
            .iter()
            .map(|(r, _)| {
                r.events
                    .iter()
                    .map(|e| (e.seq, e.accepted_frames, e.kind.clone()))
                    .collect()
            })
            .collect();
        let want: Vec<Vec<(u64, u64, SessionEventKind)>> = vec![
            vec![(1, 0, SessionEventKind::Prepared)],
            vec![(2, 0, SessionEventKind::Started)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![(3, 4, SessionEventKind::StopAcknowledged)],
        ];
        assert_eq!(events, want);
        assert!(sink.records.iter().all(|(r, _)| r.schema == LOG_SCHEMA
            && r.evidence == "model"
            && r.scope == "host_simulation"));
    }

    #[test]
    fn a_fault_is_logged_once_as_critical_with_its_cause_and_later_calls_do_not_repeat_it() {
        let (s, probe) = session();
        let mut logged = LoggedSession::new(s, KeepSink::default());
        let transcript = faulting_cycle(&mut logged, &probe);
        assert_eq!(transcript[5], "err not allowed in phase Faulted");
        let (_session, sink) = logged.into_parts();
        let first_poll = &sink.records[3];
        assert_eq!(first_poll.0.op, LoggedOp::Poll);
        assert!(
            first_poll.1,
            "the record that carries a new fault is critical"
        );
        assert_eq!(first_poll.0.phase, SessionPhase::Faulted);
        assert_eq!(first_poll.0.amp, Amp::Muted);
        assert_eq!(
            (first_poll.0.slots_in_flight, first_poll.0.slots_quarantined),
            (0, 1)
        );
        assert_eq!(first_poll.0.anomalies, 1);
        // Prepare was event 1 and start was event 2, so the fault is event 3, with four frames accepted.
        assert_eq!(
            first_poll.0.events,
            vec![SessionEvent {
                seq: 3,
                accepted_frames: 4,
                kind: stale_fault()
            }]
        );
        // The same fault is not reported again.
        assert!(sink.records[4].0.events.is_empty() && !sink.records[4].1);
        // A failed call is logged with its error and is not critical on its own.
        let failed = &sink.records[5];
        assert!(!failed.0.ok && !failed.1);
        assert_eq!(
            failed.0.error.as_deref(),
            Some("not allowed in phase Faulted")
        );
    }

    type CleanRun = (Vec<String>, SessionReceipt);
    type FaultRun = (Vec<String>, SessionReceipt, LogStats);

    fn bare_clean() -> CleanRun {
        let (mut s, _probe) = session();
        let transcript = clean_cycle(&mut s);
        (transcript, s.receipt())
    }

    fn wrapped_clean<L: HalLogSink>(sink: L) -> CleanRun {
        let (s, _probe) = session();
        let mut logged = LoggedSession::new(s, sink);
        let transcript = clean_cycle(&mut logged);
        (transcript, logged.session().receipt())
    }

    fn bare_fault() -> (Vec<String>, SessionReceipt) {
        let (mut s, probe) = session();
        let transcript = faulting_cycle(&mut s, &probe);
        (transcript, s.receipt())
    }

    fn wrapped_fault<L: HalLogSink>(sink: L) -> FaultRun {
        let (s, probe) = session();
        let mut logged = LoggedSession::new(s, sink);
        let transcript = faulting_cycle(&mut logged, &probe);
        (transcript, logged.session().receipt(), logged.log_stats())
    }

    #[test]
    fn the_wrapper_returns_exactly_what_the_bare_session_returns_under_any_sink() {
        // The clean cycle: same results and same final receipt whether the sink keeps everything,
        // refuses everything, or fills up after two records.
        let bare = bare_clean();
        assert_eq!(wrapped_clean(KeepSink::default()), bare);
        assert_eq!(wrapped_clean(NullSink), bare);
        assert_eq!(wrapped_clean(CapSink { cap: 2, kept: 0 }), bare);

        // The faulting cycle, the same way. The sink changes only the log accounting.
        let (bare_transcript, bare_receipt) = bare_fault();
        let (t, r, stats) = wrapped_fault(KeepSink::default());
        assert_eq!((t, r), (bare_transcript.clone(), bare_receipt.clone()));
        assert_eq!(
            stats,
            LogStats {
                emitted: 6,
                kept: 6,
                dropped: 0,
                critical_lost: 0
            }
        );

        let (t, r, stats) = wrapped_fault(NullSink);
        assert_eq!((t, r), (bare_transcript.clone(), bare_receipt.clone()));
        // Every record was refused, and the one that carried the fault is counted as lost evidence.
        assert_eq!(
            stats,
            LogStats {
                emitted: 6,
                kept: 0,
                dropped: 6,
                critical_lost: 1
            }
        );

        let (t, r, stats) = wrapped_fault(CapSink { cap: 3, kept: 0 });
        assert_eq!((t, r), (bare_transcript, bare_receipt));
        // The sink filled up after three records, before the fault arrived, so that record was lost.
        assert_eq!(
            stats,
            LogStats {
                emitted: 6,
                kept: 3,
                dropped: 3,
                critical_lost: 1
            }
        );
    }

    #[test]
    fn a_refused_fault_record_marks_the_evidence_incomplete() {
        let (s, probe) = session();
        let mut refused = LoggedSession::new(s, NullSink);
        faulting_cycle(&mut refused, &probe);
        assert!(!refused.evidence_complete());
        let (s, probe) = session();
        let mut kept = LoggedSession::new(s, KeepSink::default());
        faulting_cycle(&mut kept, &probe);
        assert!(kept.evidence_complete());
        // A refused ordinary record alone does not: the clean cycle through a refusing sink.
        let (s, _probe) = session();
        let mut clean = LoggedSession::new(s, NullSink);
        clean_cycle(&mut clean);
        assert_eq!(clean.log_stats().dropped, 6);
        assert!(
            clean.evidence_complete(),
            "no fault was lost, so nothing critical is missing"
        );
    }

    #[test]
    fn a_record_serializes_to_one_json_line_with_exactly_the_documented_keys() {
        let (s, _probe) = session();
        let mut logged = LoggedSession::new(s, KeepSink::default());
        logged.prepare().unwrap();
        let (_session, sink) = logged.into_parts();
        let line = sink.records[0].0.to_json_line();
        assert!(!line.contains('\n'));
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "accepted_frames",
                "amp",
                "anomalies",
                "consumed_frames",
                "critical_events_lost",
                "error",
                "events",
                "events_lost",
                "evidence",
                "ok",
                "op",
                "phase",
                "schema",
                "scope",
                "seq",
                "slots_in_flight",
                "slots_quarantined",
            ],
            "a record carries counters and fault codes, never audio"
        );
        assert_eq!(value["schema"], LOG_SCHEMA);
        assert_eq!(value["op"], "prepare");
        assert_eq!(value["events"][0]["kind"]["kind"], "prepared");
        let back: HalLogRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, sink.records[0].0);
    }

    fn faulted_session() -> HalSession<FakeBackend> {
        let (mut s, probe) = session();
        s.prepare().unwrap();
        s.start(READY).unwrap();
        let _token = s.submit(&BLOCK).unwrap().token.unwrap();
        probe.queue_event(DeviceEvent::Completed {
            slot: 0,
            generation: 99,
        });
        s.poll();
        assert_eq!(s.receipt().faults.len(), 1);
        s
    }

    #[test]
    fn events_waiting_before_wrapping_are_reported_once_and_events_already_taken_are_not() {
        // Nobody took them: the first record reports prepare, start and the fault.
        let mut logged = LoggedSession::new(faulted_session(), KeepSink::default());
        logged.poll();
        logged.poll();
        let (_session, sink) = logged.into_parts();
        let first: Vec<(u64, SessionEventKind)> = sink.records[0]
            .0
            .events
            .iter()
            .map(|e| (e.seq, e.kind.clone()))
            .collect();
        let want: Vec<(u64, SessionEventKind)> = vec![
            (1, SessionEventKind::Prepared),
            (2, SessionEventKind::Started),
            (3, stale_fault()),
        ];
        assert_eq!(first, want);
        assert!(sink.records[0].1, "it carries a fault");
        assert!(sink.records[1].0.events.is_empty(), "and not again");

        // The owner took them first: nothing is repeated.
        let mut s = faulted_session();
        let taken: Vec<SessionEvent> = std::iter::from_fn(|| s.take_event()).collect();
        assert_eq!(taken.len(), 3);
        let mut logged = LoggedSession::new(s, KeepSink::default());
        logged.poll();
        let (_session, sink) = logged.into_parts();
        assert!(sink.records[0].0.events.is_empty() && !sink.records[0].1);
    }

    #[test]
    fn a_fault_the_sessions_own_queue_lost_is_reported_and_marks_the_evidence_incomplete() {
        // A one-event queue and a quarantine cap of 1: the drain timeout records two faults in one
        // call, and only the first fits.
        let mut cfg = FakeConfig::retained();
        cfg.flush_ack_delay_ticks = None;
        let (s, probe) = session_caps(cfg, 1, 1);
        let mut logged = LoggedSession::new(s, KeepSink::default());
        logged.prepare().unwrap();
        logged.start(READY).unwrap();
        probe.set_lose_completions(true);
        let _a = logged.submit(&BLOCK).unwrap().token.unwrap();
        let _b = logged.submit(&BLOCK).unwrap().token.unwrap();
        assert_eq!(
            logged.drain(1),
            Ok(DrainOutcome::TimedOut { waited_ticks: 1 })
        );
        logged.poll();
        // The sink kept every record, so the loss is the session's, not the sink's.
        assert_eq!(logged.log_stats().critical_lost, 0);
        assert!(!logged.evidence_complete());
        assert_eq!(logged.session().event_stats().lost_critical, 1);
        let (_session, sink) = logged.into_parts();
        let drain = &sink.records[4];
        assert_eq!(drain.0.op, LoggedOp::Drain);
        assert!(drain.1);
        let kinds: Vec<(u64, u64, SessionEventKind)> = drain
            .0
            .events
            .iter()
            .map(|e| (e.seq, e.accepted_frames, e.kind.clone()))
            .collect();
        let want: Vec<(u64, u64, SessionEventKind)> = vec![(
            3,
            8,
            SessionEventKind::Fault {
                code: FaultCode::DrainTimedOut,
            },
        )];
        assert_eq!(
            kinds, want,
            "event 4, the saturation fault, is the one missing"
        );
        assert_eq!((drain.0.events_lost, drain.0.critical_events_lost), (0, 1));
        // The loss is reported once: the next record does not repeat it.
        let after = &sink.records[5];
        assert_eq!(after.0.op, LoggedOp::Poll);
        assert_eq!((after.0.events_lost, after.0.critical_events_lost), (0, 0));
        assert!(after.0.events.is_empty() && !after.1);
    }

    #[test]
    fn the_wrapped_session_can_be_taken_back_and_closed() {
        let (s, _probe) = session();
        let mut logged = LoggedSession::new(s, KeepSink::default());
        clean_cycle(&mut logged);
        let (session, sink) = logged.into_parts();
        assert_eq!(sink.records.len(), 6);
        let receipt = session.close().unwrap();
        assert_eq!(receipt.phase, SessionPhase::Closed);
    }
}
