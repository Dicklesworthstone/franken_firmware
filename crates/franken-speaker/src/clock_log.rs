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
//! * **The counts are exposed.** [`ClockLogSummary`] carries the sink's emitted, stored, dropped and critical-lost counts,
//!   the events the clock's own buffer dropped before the drain saw them, and events too long to write as a line.

use franken_clock::group::{GroupClock, LogContext};
use franken_test_support::{BoundedDiagnosticSink, DiagnosticEvent};
use serde::{Deserialize, Serialize};

/// A member's clock log: 256 events and 128 KiB. No rate limit of its own; the clock's buffer already admits at most 32
/// ordinary events per second of the clock's own time.
const CLOCK_LOG_MAX_EVENTS: usize = 256;
const CLOCK_LOG_MAX_BYTES: usize = 128 * 1024;

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
        let ctx = LogContext::new(
            "vh-clock",
            "N03-clock",
            member_id,
            "grp-virtual-house",
            None,
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VirtualSpeakerNode;
    use franken_board_profile::synthetic_test_fixture_catalog;
    use franken_clock::group::{
        Accepted, ClockStatus, GroupClockConfig, Output, ProbeReject, ProbeResponse, StartSchedule,
    };

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
        while let Some(buffered) = gc.pop_event() {
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
    fn gate_changing_drain(
        gc: &mut GroupClock,
        ctx: &LogContext,
        sink: &mut BoundedDiagnosticSink,
    ) -> usize {
        let mut offered = 0;
        while let Some(buffered) = gc.pop_event() {
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

    #[test]
    fn the_sink_pseudonymises_the_labels_the_drain_hands_it() {
        let ctx = log_ctx();
        let mut gc = new_clock();
        let mut sink = BoundedDiagnosticSink::new(512, 256 * 1024).with_pseudonym_key([7; 32]);
        relock_script(&mut gc, |gc| {
            drain_clock_events(gc, &ctx, &mut sink);
        });
        assert_eq!(sink.events().len(), 16);
        for event in sink.events() {
            assert!(event.member_id.starts_with("p-") && event.member_id != "spk-test");
            assert!(event.group_id.starts_with("p-") && event.group_id != "grp-test");
            assert_eq!(
                event.member_id,
                sink.events()[0].member_id,
                "one member, one pseudonym"
            );
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
