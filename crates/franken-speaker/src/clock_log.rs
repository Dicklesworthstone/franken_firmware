//! The owner-side drain of a group clock's events into the existing bounded diagnostic sink (`N03` / `ffw-u07`,
//! `docs/contracts/n03.md` sections 12 and 13).
//!
//! `franken-clock` records what its `GroupClock` does as plain `ClockEvent`s in its own fixed buffer and can write
//! each as an `ffw.log.v1` line, but it links no sink: `BoundedDiagnosticSink` lives in `franken-test-support`, which
//! the P01 workspace contract keeps out of every device closure. This module is where the two meet, and like
//! `harness.rs` it is compiled only with the `harness` feature (or for unit tests).
//!
//! What the drain promises, each pinned by a test below:
//!
//! * **It only reads the clock.** It pops the clock's pending events and calls nothing else on it, so whatever the sink
//!   does cannot change a clock decision or the audible gate.
//! * **It offers each event once, and never waits.** The work of one call is bounded by the events pending when it
//!   starts; a sink that is full, zero-sized or unavailable refuses the event, the sink counts the drop, and the drain
//!   moves on. A drain that retried, or that treated a refusal as a fault of the clock, is caught by name.
//! * **Criticality is kept.** A clock event marked critical goes in with `emit_critical` (it evicts an ordinary event
//!   rather than be lost, and is counted lost only if the sink holds nothing but critical ones); the rest go in with
//!   `try_emit`.
//! * **Labels are the owner's, and can be pseudonyms.** The lines carry the member and group labels the owner gives
//!   (`LogContext`), and the clock builds `correlation_id` from the member label. A keyed sink rewrites only `member_id` and
//!   `group_id`, so handing it raw labels leaves the raw member label in every `correlation_id`. [`ClockLog::new_with_key`]
//!   therefore derives the labels first, through the shared sink's own keyed path, and keeps its own sink unkeyed (keying
//!   it as well would hash a pseudonym a second time and the log could no longer be joined to any other).
//! * **The counts are exposed.** [`ClockLogSummary`] carries the sink's emitted, stored, dropped and critical-lost counts,
//!   the events the clock's own buffer dropped before the drain saw them, and events too long to write as a line.

use franken_clock::group::{GroupClock, LogContext};
use franken_test_support::{BoundedDiagnosticSink, DiagnosticEvent};
use serde::{Deserialize, Serialize};

/// A member's clock log: 256 events and 128 KiB. No rate limit of its own; the clock's buffer already admits at most 32
/// ordinary events per second of the clock's own time.
const CLOCK_LOG_MAX_EVENTS: usize = 256;
const CLOCK_LOG_MAX_BYTES: usize = 128 * 1024;
/// The group label a member's clock log carries (the harness has one group).
const CLOCK_LOG_GROUP: &str = "grp-virtual-house";
/// Room for the one probe event that [`log_labels`] hands a keyed sink.
const PROBE_MAX_BYTES: usize = 4096;

/// What one call of [`drain_clock_events`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DrainReport {
    /// Events popped from the clock and handed to the sink, once each (stored, evicted later or counted dropped there).
    pub offered: usize,
    /// Events popped but not offered because their line would exceed the bound; the caller counts them.
    pub unwritable: usize,
}

/// Pop the clock's pending events, oldest first, and hand each to `sink` exactly once.
///
/// The number of events considered is the number pending when the call starts, so one call is bounded work whatever the
/// sink does. The clock is only read through [`GroupClock::pop_event`].
pub(crate) fn drain_clock_events(
    clock: &mut GroupClock,
    ctx: &LogContext,
    sink: &mut BoundedDiagnosticSink,
) -> DrainReport {
    let mut report = DrainReport::default();
    for _ in 0..clock.pending_events() {
        let Some(buffered) = clock.pop_event() else {
            break;
        };
        let event = buffered
            .payload
            .to_log_line(ctx)
            .and_then(|line| serde_json::from_str::<DiagnosticEvent>(&line).ok());
        let Some(event) = event else {
            report.unwritable += 1;
            continue;
        };
        if buffered.critical {
            sink.emit_critical(event);
        } else {
            sink.try_emit(event);
        }
        report.offered += 1;
    }
    report
}

/// The member and group labels a clock log writes. Without a key they are `member_id` and `group_id` as given. With one
/// they are the keyed pseudonyms (`p-` and sixteen hex characters) that the shared diagnostics sink gives those ids, read
/// back from a one-event sink built with `with_pseudonym_key`, so the derivation is the sink's own and is not repeated here.
/// A campaign sink with the same key therefore labels the same member identically, and the logs can be joined.
fn log_labels(
    member_id: &str,
    group_id: &str,
    key: Option<[u8; 32]>,
) -> Result<(String, String), String> {
    let Some(key) = key else {
        return Ok((member_id.to_string(), group_id.to_string()));
    };
    let mut probe = BoundedDiagnosticSink::new(1, PROBE_MAX_BYTES).with_pseudonym_key(key);
    let stored = probe.try_emit(DiagnosticEvent {
        schema_version: String::new(),
        timestamp_mono_ns: 0,
        run_id: "probe".to_string(),
        case_id: "probe".to_string(),
        correlation_id: "probe".to_string(),
        member_id: member_id.to_string(),
        group_id: group_id.to_string(),
        source_epoch: 0,
        state_revision: 0,
        event_kind: "probe".to_string(),
        message: "pseudonym probe".to_string(),
        queue_depth: 0,
        latency_us: 0,
        fault: None,
        cause: None,
    });
    match probe.events().first() {
        Some(event) if stored => Ok((event.member_id.clone(), event.group_id.clone())),
        _ => Err("the pseudonym probe was not stored".to_string()),
    }
}

/// The counts a member's clock log ends a run with.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClockLogSummary {
    /// Events handed to the sink.
    pub emitted: u64,
    /// Events the sink holds.
    pub stored: usize,
    /// Events the sink refused or evicted (`emitted == stored + dropped`).
    pub dropped: u64,
    /// Critical events the sink could not keep. Non-zero means the clock's evidence for the run is incomplete.
    pub critical_lost: u64,
    /// Events the clock's own buffer dropped before the drain could see them.
    pub clock_buffer_dropped: u64,
    /// Events popped whose line would have exceeded the bound.
    pub unwritable: u64,
    /// False once any critical event was lost, here or in the clock's own buffer.
    pub evidence_complete: bool,
}

/// One member's log of its clock: the labels its lines carry, the sink they go to, and the count of unwritable events.
#[derive(Debug, Clone)]
pub(crate) struct ClockLog {
    ctx: LogContext,
    sink: BoundedDiagnosticSink,
    unwritable: u64,
}

impl ClockLog {
    pub(crate) fn new(member_id: &str) -> Result<Self, String> {
        Self::new_with_key(member_id, None)
    }

    /// As [`Self::new`], pseudonymous when `key` is given: the member and group labels, and so the `correlation_id`
    /// built from the member label, are the keyed pseudonyms, and no raw label reaches a stored field. The key is a
    /// parameter; where a real one comes from is the platform's entropy capability (P02), and the harness has none.
    pub(crate) fn new_with_key(member_id: &str, key: Option<[u8; 32]>) -> Result<Self, String> {
        let (member, group) = log_labels(member_id, CLOCK_LOG_GROUP, key)?;
        let ctx = LogContext::new("vh-clock", "n03-clock", &member, &group, None)
            .map_err(|e| format!("clock log labels for member {member_id}: {e:?}"))?;
        Ok(Self {
            ctx,
            sink: BoundedDiagnosticSink::new(CLOCK_LOG_MAX_EVENTS, CLOCK_LOG_MAX_BYTES),
            unwritable: 0,
        })
    }

    /// The same log with another sink (a full, zero-sized, unavailable or pseudonymising one).
    #[cfg(test)]
    pub(crate) fn with_sink(mut self, sink: BoundedDiagnosticSink) -> Self {
        self.sink = sink;
        self
    }

    pub(crate) fn drain(&mut self, clock: &mut GroupClock) -> DrainReport {
        let report = drain_clock_events(clock, &self.ctx, &mut self.sink);
        self.unwritable += report.unwritable as u64;
        report
    }

    #[cfg(test)]
    pub(crate) fn sink(&self) -> &BoundedDiagnosticSink {
        &self.sink
    }

    pub(crate) fn summary(&self, clock: &GroupClock) -> ClockLogSummary {
        let ring = clock.event_stats();
        ClockLogSummary {
            emitted: self.sink.emitted_event_count(),
            stored: self.sink.events().len(),
            dropped: self.sink.dropped_event_count(),
            critical_lost: self.sink.critical_evidence_lost(),
            clock_buffer_dropped: ring.dropped,
            unwritable: self.unwritable,
            evidence_complete: self.sink.is_evidence_complete() && ring.critical_lost == 0,
        }
    }
}

/// Every place a raw label appears in what a sink holds: the field it is in, for each stored event, and `to_jsonl` for the
/// serialised log. It looks at every field of the serialised event, so a field added later is covered too. The clock log's tests
/// and the campaign's (`harness.rs`) both use it.
#[cfg(test)]
pub(crate) fn leaks_of(sink: &BoundedDiagnosticSink, raws: &[&str]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for event in sink.events() {
        let value = serde_json::to_value(event).expect("an event serialises");
        for (field, v) in value.as_object().expect("an event is an object") {
            let text = v.to_string();
            for raw in raws {
                if text.contains(raw) {
                    found.push((field.clone(), (*raw).to_string()));
                }
            }
        }
    }
    let jsonl = sink.to_jsonl();
    for raw in raws {
        if jsonl.contains(raw) {
            found.push(("to_jsonl".to_string(), (*raw).to_string()));
        }
    }
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VirtualSpeakerNode;
    use franken_board_profile::synthetic_test_fixture_catalog;
    use franken_clock::group::{
        Accepted, ClockStatus, GroupClockConfig, Output, ProbeReject, ProbeResponse, StartSchedule,
    };
    use franken_control::channel::diag::{ChannelLog, LogConfig, LogKey};

    /// A group clock this many nanoseconds ahead of the local one.
    const GOFF: u64 = 8_995_000_000_000;

    type Decision = (bool, Output, ClockStatus, Option<u64>);
    type DrainFn = fn(&mut GroupClock, &LogContext, &mut BoundedDiagnosticSink) -> usize;
    /// What each sink ended with: its name, the sink, and the events the clock's own buffer dropped.
    type Seen = Vec<(&'static str, BoundedDiagnosticSink, u64)>;

    fn log_ctx() -> LogContext {
        LogContext::new("run-n03", "n03-log", "spk-test", "grp-test", None).expect("valid labels")
    }

    fn new_clock() -> GroupClock {
        let cfg = GroupClockConfig::standard().expect("standard config");
        GroupClock::new(cfg, 1, 7, 100).expect("member")
    }

    /// One exact exchange (no skew, no quantisation, a group clock `goff` ahead of the local one) delivered at once.
    fn exact_probe(
        gc: &mut GroupClock,
        t1: u64,
        goff: u64,
    ) -> (ProbeResponse, u64, Result<Accepted, ProbeReject>) {
        let req = gc.next_probe(t1);
        let resp = ProbeResponse {
            epoch: req.epoch,
            leader: gc.leader(),
            seq: req.seq,
            t1_echo_ns: t1,
            t2_group_ns: t1 + goff + 200_000,
            t3_group_ns: t1 + goff + 250_000,
        };
        let t4 = t1 + 450_000;
        let outcome = gc.on_response(resp, t4);
        (resp, t4, outcome)
    }

    /// The events of a lock, a replay, a clock jump and the relock that follows, with `after` called after each step
    /// (so a drain sees what that step produced).
    fn relock_script(gc: &mut GroupClock, mut after: impl FnMut(&mut GroupClock)) {
        let mut last = None;
        for k in 0..4_u64 {
            let (resp, t4, outcome) = exact_probe(gc, 10_000_000_000 + k * 1_000_000_000, GOFF);
            outcome.expect("accepted");
            last = Some((resp, t4));
            after(gc);
        }
        let (resp, t4) = last.expect("a last exchange");
        gc.tick(t4 + 500_000_000);
        after(gc);
        let _ = gc.on_response(resp, t4 + 1_000);
        after(gc);
        let _ = exact_probe(gc, 14_000_000_000, GOFF + 2_000_000_000);
        after(gc);
        gc.tick(14_500_000_000);
        after(gc);
        for k in 0..4_u64 {
            let _ = exact_probe(gc, 15_000_000_000 + k * 1_000_000_000, GOFF + 2_000_000_000);
            after(gc);
        }
    }

    fn pairs(sink: &BoundedDiagnosticSink) -> Vec<(String, Option<String>)> {
        sink.events()
            .iter()
            .map(|e| (e.event_kind.clone(), e.cause.clone()))
            .collect()
    }

    fn pair(kind: &str, cause: Option<&str>) -> (String, Option<String>) {
        (kind.to_string(), cause.map(str::to_string))
    }

    /// Hand-derived from `docs/contracts/n03.md` section 13, not read from the clock: what the sink must hold after a
    /// lock, a tick, a replayed answer, a 2 s clock step (rejected, reset, unlocked), a tick and the relock.
    fn documented_relock_sequence() -> Vec<(String, Option<String>)> {
        let accepted = || pair("n03.probe.accepted", None);
        vec![
            accepted(),
            accepted(),
            accepted(),
            accepted(),
            pair("n03.status.locked", None),
            pair("n03.output.muted", Some("NotAdmitted")),
            pair("n03.probe.rejected", Some("UnsolicitedOrReplayed")),
            pair("n03.probe.rejected", Some("Discontinuity")),
            pair("n03.reset", Some("Discontinuity")),
            pair("n03.status.unlocked", None),
            pair("n03.output.muted", Some("Discontinuity")),
            accepted(),
            accepted(),
            accepted(),
            accepted(),
            pair("n03.status.locked", None),
        ]
    }

    #[test]
    fn a_clock_log_can_be_made_for_every_member_of_the_house() {
        // `LogContext` accepts only 1-64 bytes of `a-z0-9._-` starting with a lowercase letter or digit. A label it
        // refuses fails the member's bring-up, and so every campaign: the case id once began with a capital.
        for id in [
            "spk-office-s5",
            "spk-bedroom-s1",
            "spk-kitchen-s12",
            "spk-den-s3",
            "spk-living-sub",
            "spk-test",
        ] {
            ClockLog::new(id).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        // and the refusal is real: a capital in a member label is refused, with the field named
        let err = ClockLog::new("Spk-Office").expect_err("a capital is not a valid label");
        assert!(err.contains("InvalidLabel"), "{err}");
    }

    #[test]
    fn the_drain_writes_the_documented_relock_sequence_into_the_real_sink() {
        let ctx = log_ctx();
        let mut gc = new_clock();
        let mut sink = BoundedDiagnosticSink::new(512, 256 * 1024);
        let mut offered = 0;
        relock_script(&mut gc, |gc| {
            offered += drain_clock_events(gc, &ctx, &mut sink).offered;
        });
        assert_eq!(pairs(&sink), documented_relock_sequence());
        assert_eq!(offered, 16);
        assert_eq!(sink.emitted_event_count(), 16);
        assert_eq!(sink.dropped_event_count(), 0);
        assert!(sink.is_evidence_complete());
        assert_eq!(
            sink.non_monotonic_event_count(),
            0,
            "the clock's stamps never go back"
        );
        // every line is the shared schema, with this member's labels and the clock-fit-only claim
        for event in sink.events() {
            assert_eq!(event.run_id, "run-n03");
            assert_eq!(event.member_id, "spk-test");
            assert_eq!(event.group_id, "grp-test");
            assert!(
                event.message.contains("network-clock-fit-only"),
                "{}",
                event.message
            );
        }
        // nothing is left in the clock's buffer, and its own accounting balances
        let ring = gc.event_stats();
        assert_eq!(gc.pending_events(), 0);
        assert_eq!(ring.emitted, ring.delivered + ring.dropped);
        assert_eq!((ring.dropped, ring.critical_lost), (0, 0));
    }

    #[test]
    fn critical_events_survive_a_small_sink_and_every_drop_is_counted() {
        let ctx = log_ctx();
        let mut gc = new_clock();
        // Five slots for sixteen events: the four ordinary accepts fill four, the first lock takes the fifth, and from
        // then on every ordinary event is refused while each critical one (reset, unlocked, locked) evicts the oldest
        // ordinary event. Derived by hand from the sink's rules.
        let mut sink = BoundedDiagnosticSink::new(5, 256 * 1024);
        relock_script(&mut gc, |gc| {
            drain_clock_events(gc, &ctx, &mut sink);
        });
        assert_eq!(
            pairs(&sink),
            vec![
                pair("n03.probe.accepted", None),
                pair("n03.status.locked", None),
                pair("n03.reset", Some("Discontinuity")),
                pair("n03.status.unlocked", None),
                pair("n03.status.locked", None),
            ]
        );
        assert_eq!(sink.emitted_event_count(), 16);
        assert_eq!(sink.dropped_event_count(), 11);
        assert_eq!(sink.evicted_event_count(), 3);
        assert_eq!(sink.critical_evidence_lost(), 0);
        assert!(sink.is_evidence_complete(), "no critical event was lost");
        assert_eq!(
            sink.emitted_event_count(),
            sink.events().len() as u64 + sink.dropped_event_count()
        );
    }

    /// One world, 120 exchanges a second apart: every 61st step the group clock steps (a discontinuity), every 7th an
    /// answer is replayed, and a start is admitted whenever the clock is locked and silent. `drain` is called after each
    /// step, or never.
    fn world(
        drain: Option<DrainFn>,
        sink: &mut BoundedDiagnosticSink,
    ) -> (Vec<Decision>, GroupClock) {
        let ctx = log_ctx();
        let mut gc = new_clock();
        let mut decisions = Vec::new();
        for step in 0..120_u64 {
            let t1 = 10_000_000_000 + step * 1_000_000_000;
            let offset = GOFF + (step / 61) * 2_000_000_000;
            let (resp, t4, outcome) = exact_probe(&mut gc, t1, offset);
            if step % 7 == 3 {
                let _ = gc.on_response(resp, t4 + 1_000);
            }
            let now = t4 + 500_000;
            let start = StartSchedule {
                epoch: 1,
                start_group_ns: now + offset + 1_000_000_000,
            };
            if gc.status(now) == ClockStatus::Locked && !gc.output(now).is_audible() {
                let _ = gc.admit(start, now);
            }
            decisions.push((
                outcome.is_ok(),
                gc.tick(now + 2_000_000_000),
                gc.status(now),
                gc.group_ns(now),
            ));
            if let Some(drain) = drain {
                drain(&mut gc, &ctx, sink);
            }
        }
        (decisions, gc)
    }

    fn sinks() -> Vec<(&'static str, BoundedDiagnosticSink)> {
        let mut unavailable = BoundedDiagnosticSink::new(100_000, 16 * 1024 * 1024);
        unavailable.set_unavailable(true);
        vec![
            (
                "working",
                BoundedDiagnosticSink::new(100_000, 16 * 1024 * 1024),
            ),
            ("full", BoundedDiagnosticSink::new(3, 64 * 1024)),
            ("zero-sized", BoundedDiagnosticSink::new(0, 0)),
            ("unavailable", unavailable),
        ]
    }

    /// The properties a drain must have, judged on one world run against every kind of sink and against no sink at all.
    /// On success it returns what each sink ended with, for the contrasts a caller wants to pin.
    fn judge_drain(drain: DrainFn) -> Result<Seen, String> {
        let mut unused = BoundedDiagnosticSink::new(1, 1);
        let (baseline, _) = world(None, &mut unused);
        let mut seen = Vec::new();
        for (label, mut sink) in sinks() {
            let (decisions, gc) = world(Some(drain), &mut sink);
            if decisions != baseline {
                return Err(format!(
                    "{label}: the drain changed a clock decision (the world decided otherwise than with no sink)"
                ));
            }
            let delivered = gc.event_stats().delivered;
            if sink.emitted_event_count() != delivered {
                return Err(format!(
                    "{label}: the drain offered {} events to the sink for {delivered} popped: an event was offered more than once",
                    sink.emitted_event_count()
                ));
            }
            if sink.emitted_event_count() != sink.events().len() as u64 + sink.dropped_event_count()
            {
                return Err(format!("{label}: the sink's accounting does not balance"));
            }
            seen.push((label, sink, gc.event_stats().dropped));
        }
        Ok(seen)
    }

    fn real_drain(
        gc: &mut GroupClock,
        ctx: &LogContext,
        sink: &mut BoundedDiagnosticSink,
    ) -> usize {
        drain_clock_events(gc, ctx, sink).offered
    }

    fn event_of(
        buffered: &franken_clock::events::BufferedEvent<franken_clock::group::ClockEvent>,
        ctx: &LogContext,
    ) -> DiagnosticEvent {
        let line = buffered.payload.to_log_line(ctx).expect("a line");
        serde_json::from_str(&line).expect("a line is an event")
    }

    /// PLANT: waits for room. A sink with none is waited on (a bounded stand-in for forever), so every refused event is
    /// offered over and over.
    fn blocking_drain(
        gc: &mut GroupClock,
        ctx: &LogContext,
        sink: &mut BoundedDiagnosticSink,
    ) -> usize {
        let mut offered = 0;
        for _ in 0..gc.pending_events() {
            let Some(buffered) = gc.pop_event() else {
                break;
            };
            let event = event_of(&buffered, ctx);
            for _ in 0..50 {
                let stored = if buffered.critical {
                    sink.emit_critical(event.clone())
                } else {
                    sink.try_emit(event.clone())
                };
                if stored {
                    break;
                }
            }
            offered += 1;
        }
        offered
    }

    /// PLANT: treats a refusal as a fault of the clock and mutes the node.
    ///
    /// Its loop is bounded by the events pending when the call starts, as the real drain's is, and that bound is
    /// load-bearing. `report_clock_fault` always pushes a new critical `n03.reset` event, so a loop of
    /// `while let Some(_) = gc.pop_event()` meets that event next; a sink that refuses it faults the clock again, and
    /// so on without end. b36 ran exactly that for 13 minutes. The plant's defect is the fault, not an endless loop.
    fn gate_changing_drain(
        gc: &mut GroupClock,
        ctx: &LogContext,
        sink: &mut BoundedDiagnosticSink,
    ) -> usize {
        let mut offered = 0;
        for _ in 0..gc.pending_events() {
            let Some(buffered) = gc.pop_event() else {
                break;
            };
            let event = event_of(&buffered, ctx);
            let stored = if buffered.critical {
                sink.emit_critical(event)
            } else {
                sink.try_emit(event)
            };
            offered += 1;
            if !stored {
                gc.report_clock_fault();
            }
        }
        offered
    }

    #[test]
    fn a_working_a_full_an_unavailable_and_no_sink_leave_the_clock_deciding_alike() {
        let seen = judge_drain(real_drain).expect("the real drain is harmless");
        let by = |name: &str| seen.iter().find(|s| s.0 == name).expect("a sink");
        // the decisions were equal in all four (judge_drain); what differs is only what each sink kept and counted
        let working = &by("working").1;
        assert_eq!(working.dropped_event_count(), 0);
        assert!(working.is_evidence_complete());
        assert_eq!(working.events().len() as u64, working.emitted_event_count());
        let full = &by("full").1;
        assert!(full.dropped_event_count() > 0 && !full.events().is_empty());
        for name in ["zero-sized", "unavailable"] {
            let sink = &by(name).1;
            assert!(sink.events().is_empty(), "{name}");
            assert_eq!(
                sink.dropped_event_count(),
                sink.emitted_event_count(),
                "{name}"
            );
            assert!(
                sink.critical_evidence_lost() > 0 && !sink.is_evidence_complete(),
                "{name}"
            );
        }
        // drained every step, the clock's own buffer never dropped; left alone it did, and decided the same
        for (name, _, ring_dropped) in &seen {
            assert_eq!(*ring_dropped, 0, "{name}");
        }
        let mut unused = BoundedDiagnosticSink::new(1, 1);
        let (_, undrained) = world(None, &mut unused);
        assert!(
            undrained.event_stats().dropped > 0,
            "an undrained buffer drops, and counts it"
        );
        // the world exercised what matters: audible output, rejected exchanges, a reset
        let (decisions, _) = world(None, &mut unused);
        assert!(decisions.iter().any(|d| d.1.is_audible()));
        assert!(decisions.iter().any(|d| !d.0));
    }

    #[test]
    fn a_drain_that_waits_on_the_sink_is_caught_by_the_offer_count() {
        let err = judge_drain(blocking_drain).expect_err("the planted drain must be caught");
        assert!(err.contains("an event was offered more than once"), "{err}");
        // the positive control: the real drain passes the same judge
        assert!(judge_drain(real_drain).is_ok());
    }

    #[test]
    fn a_drain_that_lets_the_sink_mute_the_clock_is_caught_by_the_decision_comparison() {
        let err = judge_drain(gate_changing_drain).expect_err("the planted drain must be caught");
        assert!(err.contains("changed a clock decision"), "{err}");
        // and it is the refusing sinks that expose it: with room for everything the planted drain is harmless
        let mut working = BoundedDiagnosticSink::new(100_000, 16 * 1024 * 1024);
        let mut unused = BoundedDiagnosticSink::new(1, 1);
        let (baseline, _) = world(None, &mut unused);
        let (decisions, _) = world(Some(gate_changing_drain), &mut working);
        assert_eq!(decisions, baseline);
        assert!(judge_drain(real_drain).is_ok());
    }

    /// The pseudonym key of the tests below, and the pseudonyms it gives, computed with Python's `hashlib` and not with
    /// this code: `sha256(b"ffw.pseudonym.v1" + key + len(id) as big-endian u64 + id)`, first 8 bytes, prefixed `p-`.
    const KEY: [u8; 32] = [7; 32];
    const KEY_OTHER: [u8; 32] = [8; 32];
    const OFFICE: &str = "spk-office-s5";
    const DEN: &str = "spk-den-s3";

    /// Drain every step of the relock script into `log`'s sink, as a node's gate does.
    fn drained(mut log: ClockLog) -> ClockLog {
        let mut gc = new_clock();
        relock_script(&mut gc, |gc| {
            log.drain(gc);
        });
        log
    }

    #[test]
    fn the_leak_scan_names_every_field_a_raw_label_is_in() {
        // The scan itself is judged first: a label planted in each field in turn is found, by that field's name.
        let blank = || DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: 1,
            run_id: "run-1".into(),
            case_id: "case-1".into(),
            correlation_id: "corr-1".into(),
            member_id: "member-1".into(),
            group_id: "group-1".into(),
            source_epoch: 1,
            state_revision: 1,
            event_kind: "kind-1".into(),
            message: "message-1".into(),
            queue_depth: 0,
            latency_us: 0,
            fault: None,
            cause: None,
        };
        let plant = |put: &dyn Fn(&mut DiagnosticEvent)| {
            let mut sink = BoundedDiagnosticSink::new(4, 4096);
            let mut event = blank();
            put(&mut event);
            assert!(sink.try_emit(event));
            leaks_of(&sink, &["raw-id"])
        };
        let named = |field: &str| {
            vec![
                (field.to_string(), "raw-id".to_string()),
                ("to_jsonl".to_string(), "raw-id".to_string()),
            ]
        };
        assert_eq!(plant(&|e| e.run_id = "x-raw-id".into()), named("run_id"));
        assert_eq!(plant(&|e| e.case_id = "x-raw-id".into()), named("case_id"));
        assert_eq!(
            plant(&|e| e.correlation_id = "x-raw-id#4".into()),
            named("correlation_id")
        );
        assert_eq!(
            plant(&|e| e.member_id = "raw-id".into()),
            named("member_id")
        );
        assert_eq!(plant(&|e| e.group_id = "raw-id".into()), named("group_id"));
        assert_eq!(
            plant(&|e| e.event_kind = "raw-id".into()),
            named("event_kind")
        );
        assert_eq!(
            plant(&|e| e.message = "for raw-id".into()),
            named("message")
        );
        assert_eq!(plant(&|e| e.fault = Some("raw-id".into())), named("fault"));
        assert_eq!(plant(&|e| e.cause = Some("raw-id".into())), named("cause"));
        // and the control: an event with none of it is clean
        assert_eq!(plant(&|_| {}), Vec::<(String, String)>::new());
    }

    #[test]
    fn a_keyed_sink_alone_leaves_the_raw_member_label_in_the_correlation_id() {
        // PLANT: the owner keys the sink but hands the drain raw labels. The sink rewrites `member_id` and `group_id`
        // and nothing else, and `correlation_id` is `member#revision`.
        let keyed = BoundedDiagnosticSink::new(512, 256 * 1024).with_pseudonym_key(KEY);
        let log = drained(ClockLog::new("spk-test").expect("labels").with_sink(keyed));
        let sink = log.sink();
        assert_eq!(sink.events().len(), 16);
        for event in sink.events() {
            assert!(event.member_id.starts_with("p-") && event.member_id != "spk-test");
            assert!(event.group_id.starts_with("p-") && event.group_id != CLOCK_LOG_GROUP);
            assert_eq!(
                event.member_id,
                sink.events()[0].member_id,
                "one member, one pseudonym"
            );
        }
        assert_eq!(
            leaks_of(sink, &["spk-test", CLOCK_LOG_GROUP]),
            vec![
                ("correlation_id".to_string(), "spk-test".to_string()),
                ("to_jsonl".to_string(), "spk-test".to_string()),
            ],
            "the raw member label is in every correlation_id, and so in the serialised log"
        );
    }

    #[test]
    fn a_pseudonymous_clock_log_carries_no_raw_label_in_any_field_or_in_the_jsonl() {
        let log = drained(ClockLog::new_with_key("spk-test", Some(KEY)).expect("labels"));
        let sink = log.sink();
        // the same events as an unkeyed log, so pseudonymising changed what is written about, not whether it is
        assert_eq!(pairs(sink), documented_relock_sequence());
        assert_eq!(
            leaks_of(sink, &["spk-test", CLOCK_LOG_GROUP]),
            Vec::<(String, String)>::new()
        );
        for event in sink.events() {
            assert_eq!(event.member_id, "p-c6192b6d33c1d5ad");
            assert_eq!(event.group_id, "p-eb446a8738577621");
            assert!(
                event.correlation_id.starts_with("p-c6192b6d33c1d5ad#"),
                "{}",
                event.correlation_id
            );
        }
        // the log's own sink is unkeyed: a second keying would have hashed the pseudonym again
        let unkeyed = drained(ClockLog::new("spk-test").expect("labels"));
        assert_eq!(unkeyed.sink().events().len(), sink.events().len());
        assert_eq!(unkeyed.sink().events()[0].member_id, "spk-test");
    }

    #[test]
    fn the_clock_log_pseudonyms_are_stable_keyed_and_the_ones_the_other_logs_give() {
        let labels = |member: &str, key: [u8; 32]| log_labels(member, CLOCK_LOG_GROUP, Some(key));
        let pair = |m: &str, g: &str| Ok((m.to_string(), g.to_string()));
        // the independent vectors
        assert_eq!(
            labels(OFFICE, KEY),
            pair("p-23c474019dcf2b45", "p-eb446a8738577621")
        );
        assert_eq!(
            labels(DEN, KEY),
            pair("p-62384aea378372b8", "p-eb446a8738577621")
        );
        assert_eq!(
            labels(OFFICE, KEY_OTHER),
            pair("p-adf579930c67676f", "p-613ef612fefe8ae4")
        );
        // stable; different for another member and for another key
        assert_eq!(labels(OFFICE, KEY), labels(OFFICE, KEY));
        assert_ne!(labels(OFFICE, KEY), labels(DEN, KEY));
        assert_ne!(labels(OFFICE, KEY), labels(OFFICE, KEY_OTHER));
        // without a key the labels are the ones given
        assert_eq!(
            log_labels(OFFICE, CLOCK_LOG_GROUP, None),
            pair(OFFICE, CLOCK_LOG_GROUP)
        );
        // the pseudonym a campaign's keyed sink gives the raw id: the logs can be joined
        let mut campaign = BoundedDiagnosticSink::new(4, 4096).with_pseudonym_key(KEY);
        assert!(campaign.try_emit(DiagnosticEvent {
            schema_version: String::new(),
            timestamp_mono_ns: 1,
            run_id: "run-1".into(),
            case_id: "case-1".into(),
            correlation_id: "corr-1".into(),
            member_id: OFFICE.into(),
            group_id: CLOCK_LOG_GROUP.into(),
            source_epoch: 1,
            state_revision: 1,
            event_kind: "kind-1".into(),
            message: "message-1".into(),
            queue_depth: 0,
            latency_us: 0,
            fault: None,
            cause: None,
        }));
        assert_eq!(
            labels(OFFICE, KEY),
            pair(
                &campaign.events()[0].member_id,
                &campaign.events()[0].group_id
            )
        );
        // and the third implementation, the control channel's own log
        let control = ChannelLog::new(
            LogConfig::new("run-1", "case-1", 4, 4096).expect("config"),
            LogKey::new(KEY),
        );
        assert_eq!(
            labels(OFFICE, KEY),
            pair(
                &control.pseudonym_of(OFFICE),
                &control.pseudonym_of(CLOCK_LOG_GROUP)
            )
        );
        // every member of the house gets its own valid label, and a clock log can be made from it
        let mut seen = std::collections::BTreeSet::new();
        for id in [
            "spk-office-s5",
            "spk-bedroom-s1",
            "spk-kitchen-s12",
            "spk-den-s3",
            "spk-living-sub",
        ] {
            ClockLog::new_with_key(id, Some(KEY)).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert!(seen.insert(labels(id, KEY).expect("labels").0), "{id}");
        }
    }

    fn s5() -> franken_board_profile::BoardProfile {
        synthetic_test_fixture_catalog()
            .into_iter()
            .find(|profile| profile.model_number == "S5")
            .expect("the S5 fixture board")
    }

    fn gates_with(sink: BoundedDiagnosticSink) -> (Vec<(Output, Option<u64>)>, VirtualSpeakerNode) {
        let mut node =
            VirtualSpeakerNode::bring_up_admitted("spk-test", s5(), 1).expect("bring-up");
        node.clock_log = ClockLog::new("spk-test").expect("labels").with_sink(sink);
        let mut gates = Vec::new();
        for blk in 0..400_u64 {
            let gate = node.gate_block(blk);
            gates.push((gate.output, gate.presented_local_ns));
        }
        (gates, node)
    }

    #[test]
    fn a_nodes_audible_gate_is_the_same_whatever_its_clock_log_does() {
        let mut unavailable = BoundedDiagnosticSink::new(256, 128 * 1024);
        unavailable.set_unavailable(true);
        let (working, node) = gates_with(BoundedDiagnosticSink::new(256, 128 * 1024));
        let (full, full_node) = gates_with(BoundedDiagnosticSink::new(3, 64 * 1024));
        let (down, down_node) = gates_with(unavailable);
        assert_eq!(working, full, "a full clock log changes no block's gate");
        assert_eq!(working, down, "and neither does an unavailable one");
        assert!(working.iter().any(|g| g.0.is_audible()), "the node sounded");
        // what differs is only what the logs kept and counted
        let kept = node.clock_log.sink();
        assert!(
            kept.emitted_event_count() >= 12,
            "an exchange every 32 blocks is logged"
        );
        assert_eq!(kept.dropped_event_count(), 0);
        assert!(full_node.clock_log.sink().dropped_event_count() > 0);
        assert!(down_node.clock_log.sink().events().is_empty());
        assert_eq!(
            down_node.clock_log.sink().dropped_event_count(),
            down_node.clock_log.sink().emitted_event_count()
        );
    }

    #[test]
    fn every_member_of_a_campaign_reports_its_clock_log() {
        let report = crate::run_virtual_house_campaign(0x2026_1104, 40).expect("campaign");
        assert_eq!(report.members.len(), 5);
        for (id, stats) in &report.members {
            let log = &stats.clock_log;
            // bring-up alone logs four accepted exchanges and the lock
            assert!(log.emitted >= 5, "{id}: {log:?}");
            assert_eq!(log.stored as u64, log.emitted, "{id}: nothing dropped");
            assert_eq!(
                (log.dropped, log.critical_lost, log.clock_buffer_dropped),
                (0, 0, 0),
                "{id}"
            );
            assert_eq!(log.unwritable, 0, "{id}");
            assert!(log.evidence_complete, "{id}");
        }
    }
}
