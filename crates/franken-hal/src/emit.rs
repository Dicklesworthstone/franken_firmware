//! Bounded event emission (`P04` / `ffw-0bh`): the one queue policy, and the events a
//! [`crate::session::HalSession`] emits as it changes state.
//!
//! # One policy, two users
//!
//! [`CriticalQueue`] is the bounded queue behind both the local-event channel
//! ([`crate::events::LocalEventChannel`]) and the session's own events. The policy is the one the
//! event vectors and sweeps already test:
//!
//! * the queue never holds more than its cap;
//! * an **ordinary** event that arrives when the queue is full is dropped, and the caller counts it;
//! * a **critical** event that arrives when the queue is full evicts the oldest ordinary event;
//! * a critical event is lost only when the queue holds nothing but critical events, and the caller
//!   counts that and treats the evidence as incomplete.
//!
//! Nothing is dropped without [`PushOutcome`] saying so.
//!
//! # What the session emits
//!
//! Session events are state transitions, not raw edges. There is nothing to debounce in them, so the
//! part of the local-event path that carries over is the bounded, critical-first queue with exact
//! accounting. A flood is bounded and counted, never dropped silently: every event is delivered,
//! queued, dropped, evicted or lost, and [`EmitStats`] adds up to the total.
//!
//! [`SessionEvent::seq`] counts every event the session emitted, including ones the queue could not
//! keep, so a consumer sees a gap where something was lost.
//!
//! Events carry counters and fault codes, never audio. The session that emits them is a model when it
//! drives the fake device, and its receipt says so; an event does not repeat that.

use crate::session::FaultCode;
use serde::{Deserialize, Serialize};
use std::collections::{TryReserveError, VecDeque};

/// Default capacity of a session's event queue.
pub const DEFAULT_EVENT_QUEUE_CAP: usize = 32;

/// An event that may or may not be allowed to be lost.
pub trait Critical {
    /// True for events that must not be lost silently.
    fn critical(&self) -> bool;
}

/// What [`CriticalQueue::push`] did with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The event is in the queue.
    Queued,
    /// The queue was full and the event was ordinary: it was not kept.
    DroppedOrdinary,
    /// The queue was full; the oldest ordinary event was removed and this critical one was kept.
    EvictedOrdinary,
    /// The queue was full of critical events: this critical event was not kept.
    LostCritical,
}

/// A queue with a hard cap that gives critical events priority over ordinary ones.
#[derive(Debug)]
pub struct CriticalQueue<T> {
    cap: usize,
    items: VecDeque<T>,
}

impl<T: Critical> CriticalQueue<T> {
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            cap,
            items: VecDeque::new(),
        }
    }

    /// A queue whose storage for `cap` events is reserved now, with the fallible allocation API, so that
    /// no push, pop or eviction after this call allocates: [`CriticalQueue::new`] grows on demand instead,
    /// which would put an allocation inside whichever path first emits.
    ///
    /// # Errors
    /// The reservation was refused (the size, or the allocator): nothing was built.
    pub fn reserved(cap: usize) -> Result<Self, TryReserveError> {
        let mut items = VecDeque::new();
        items.try_reserve_exact(cap)?;
        Ok(Self { cap, items })
    }

    /// Events the queue can hold without allocating. It does not change after [`CriticalQueue::reserved`].
    #[must_use]
    pub fn reserved_capacity(&self) -> usize {
        self.items.capacity()
    }

    /// Add an event. The queue never grows past its cap.
    pub fn push(&mut self, item: T) -> PushOutcome {
        if self.items.len() < self.cap {
            self.items.push_back(item);
            return PushOutcome::Queued;
        }
        if !item.critical() {
            return PushOutcome::DroppedOrdinary;
        }
        if let Some(index) = self.items.iter().position(|e| !e.critical()) {
            let _evicted = self.items.remove(index);
            self.items.push_back(item);
            PushOutcome::EvictedOrdinary
        } else {
            PushOutcome::LostCritical
        }
    }

    /// The oldest event still queued.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// What a session event is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEventKind {
    /// `Closed -> Prepared`.
    Prepared,
    /// `Prepared -> Running`, with the amplifier unmuted.
    Started,
    /// The device acknowledged a stop (a drain or an abort): `Draining -> Prepared`.
    StopAcknowledged,
    /// The device acknowledged a reset, which freed what was quarantined.
    ResetAcknowledged,
    /// The session recorded a fault: a driver error, a malformed record, a bad completion, a drain
    /// timeout, quarantine saturation, an unacknowledged mute, a lost device, and so on.
    Fault { code: FaultCode },
    /// The device went away while the session was already faulted, so no new fault was recorded but
    /// the amplifier is now `Unknown`.
    DeviceLostWhileFaulted,
}

impl SessionEventKind {
    /// Faults and device loss must not be lost silently; transitions may be dropped under a flood.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(self, Self::Fault { .. } | Self::DeviceLostWhileFaulted)
    }
}

/// One emitted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Counts every event the session emitted, kept or not, starting at 1. A gap means loss.
    pub seq: u64,
    /// Frames the device had accepted when the event was emitted.
    pub accepted_frames: u64,
    pub kind: SessionEventKind,
}

impl Critical for SessionEvent {
    fn critical(&self) -> bool {
        self.kind.is_critical()
    }
}

/// Exact accounting of a session's events:
/// `emitted == delivered + pending + dropped_ordinary + evicted_ordinary + lost_critical`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitStats {
    pub emitted: u64,
    /// Taken by the consumer.
    pub delivered: u64,
    /// Ordinary events that arrived with the queue full.
    pub dropped_ordinary: u64,
    /// Ordinary events removed to make room for a critical one.
    pub evicted_ordinary: u64,
    /// Critical events that could not be kept at all.
    pub lost_critical: u64,
}

/// A session's bounded event queue with its sequence counter and accounting.
#[derive(Debug)]
pub(crate) struct EventQueue {
    queue: CriticalQueue<SessionEvent>,
    next_seq: u64,
    stats: EmitStats,
}

impl EventQueue {
    /// A session's queue with room for `cap` events reserved now, so that emitting one never allocates.
    pub(crate) fn reserved(cap: usize) -> Result<Self, TryReserveError> {
        Ok(Self {
            queue: CriticalQueue::reserved(cap)?,
            next_seq: 1,
            stats: EmitStats {
                emitted: 0,
                delivered: 0,
                dropped_ordinary: 0,
                evicted_ordinary: 0,
                lost_critical: 0,
            },
        })
    }

    pub(crate) fn reserved_capacity(&self) -> usize {
        self.queue.reserved_capacity()
    }

    pub(crate) fn emit(&mut self, kind: SessionEventKind, accepted_frames: u64) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.stats.emitted += 1;
        let outcome = self.queue.push(SessionEvent {
            seq,
            accepted_frames,
            kind,
        });
        match outcome {
            PushOutcome::Queued => {}
            PushOutcome::DroppedOrdinary => self.stats.dropped_ordinary += 1,
            PushOutcome::EvictedOrdinary => self.stats.evicted_ordinary += 1,
            PushOutcome::LostCritical => self.stats.lost_critical += 1,
        }
    }

    pub(crate) fn take(&mut self) -> Option<SessionEvent> {
        let event = self.queue.pop();
        if event.is_some() {
            self.stats.delivered += 1;
        }
        event
    }

    pub(crate) fn pending(&self) -> usize {
        self.queue.len()
    }

    pub(crate) const fn stats(&self) -> EmitStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Item {
        id: u8,
        critical: bool,
    }

    impl Critical for Item {
        fn critical(&self) -> bool {
            self.critical
        }
    }

    const fn ord(id: u8) -> Item {
        Item {
            id,
            critical: false,
        }
    }

    const fn crit(id: u8) -> Item {
        Item { id, critical: true }
    }

    fn ids(q: &mut CriticalQueue<Item>) -> Vec<u8> {
        std::iter::from_fn(|| q.pop()).map(|i| i.id).collect()
    }

    #[test]
    fn the_queue_never_exceeds_its_cap_and_critical_events_outrank_ordinary_ones() {
        let mut q = CriticalQueue::new(3);
        assert_eq!(q.push(ord(1)), PushOutcome::Queued);
        assert_eq!(q.push(ord(2)), PushOutcome::Queued);
        assert_eq!(q.push(crit(3)), PushOutcome::Queued);
        // Full. An ordinary event is dropped; the queue is unchanged.
        assert_eq!(q.push(ord(4)), PushOutcome::DroppedOrdinary);
        assert_eq!(q.len(), 3);
        // A critical event evicts the OLDEST ordinary one (1, not 2) and keeps its place at the back.
        assert_eq!(q.push(crit(5)), PushOutcome::EvictedOrdinary);
        assert_eq!(q.len(), 3);
        // Another critical event evicts the remaining ordinary one.
        assert_eq!(q.push(crit(6)), PushOutcome::EvictedOrdinary);
        // Now only critical events are held: the next critical event has nowhere to go.
        assert_eq!(q.push(crit(7)), PushOutcome::LostCritical);
        assert_eq!(q.push(ord(8)), PushOutcome::DroppedOrdinary);
        assert_eq!(
            ids(&mut q),
            vec![3, 5, 6],
            "oldest first, nothing reordered"
        );
        assert!(q.is_empty());
        // Permitted positive: once drained, the queue accepts events again.
        assert_eq!(q.push(ord(9)), PushOutcome::Queued);
    }

    fn fault() -> SessionEventKind {
        SessionEventKind::Fault {
            code: FaultCode::DrainTimedOut,
        }
    }

    #[test]
    fn a_reserved_queue_holds_its_whole_cap_and_no_push_pop_or_eviction_leaves_the_reservation() {
        let mut q = CriticalQueue::<Item>::reserved(3).expect("three items can be reserved");
        let reserved = q.reserved_capacity();
        assert!(reserved >= 3, "the cap is reserved up front");
        for round in 0..50u8 {
            // Fills it, drops ordinary events, evicts ordinary ones, and loses critical ones.
            for item in [
                ord(round),
                crit(round),
                ord(round),
                ord(round),
                crit(round),
                crit(round),
                crit(round),
            ] {
                q.push(item);
            }
            assert_eq!(q.reserved_capacity(), reserved, "round {round}");
            while q.pop().is_some() {}
            assert_eq!(q.reserved_capacity(), reserved, "round {round}, drained");
        }
    }

    #[test]
    fn a_reservation_nothing_could_satisfy_is_a_refusal_not_a_panic_and_a_small_one_is_made() {
        assert!(CriticalQueue::<Item>::reserved(usize::MAX).is_err());
        assert!(EventQueue::reserved(usize::MAX).is_err());
        // Permitted positive: ordinary sizes are reserved.
        assert!(CriticalQueue::<Item>::reserved(1).is_ok());
        assert!(EventQueue::reserved(2).is_ok());
    }

    #[test]
    fn the_accounting_adds_up_and_a_gap_in_seq_shows_what_was_lost() {
        let mut q = EventQueue::reserved(2).expect("two events can be reserved");
        q.emit(SessionEventKind::Prepared, 0); // seq 1, queued
        q.emit(SessionEventKind::Started, 0); // seq 2, queued; the queue is now full
        q.emit(SessionEventKind::StopAcknowledged, 4); // seq 3, dropped
        q.emit(fault(), 4); // seq 4, evicts seq 1
        q.emit(fault(), 8); // seq 5, evicts seq 2
        q.emit(fault(), 8); // seq 6, nothing ordinary left: lost
        let stats = q.stats();
        assert_eq!(
            stats,
            EmitStats {
                emitted: 6,
                delivered: 0,
                dropped_ordinary: 1,
                evicted_ordinary: 2,
                lost_critical: 1,
            }
        );
        let first = q.take().unwrap();
        let second = q.take().unwrap();
        assert_eq!((first.seq, first.accepted_frames), (4, 4));
        assert_eq!((second.seq, second.accepted_frames), (5, 8));
        assert_eq!(q.take(), None);
        let stats = q.stats();
        assert_eq!(stats.delivered, 2);
        let pending = u64::try_from(q.pending()).unwrap();
        assert_eq!(
            stats.emitted,
            stats.delivered
                + pending
                + stats.dropped_ordinary
                + stats.evicted_ordinary
                + stats.lost_critical,
            "every emitted event is accounted for"
        );
        // seq 4 then 5: the consumer sees 1, 2, 3 and 6 missing from the stream.
    }

    #[test]
    fn an_event_serializes_with_a_kind_tag_and_round_trips() {
        let event = SessionEvent {
            seq: 3,
            accepted_frames: 4,
            kind: fault(),
        };
        let line = serde_json::to_string(&event).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["seq"], 3);
        assert_eq!(value["kind"]["kind"], "fault");
        assert_eq!(value["kind"]["code"]["kind"], "drain_timed_out");
        assert_eq!(serde_json::from_str::<SessionEvent>(&line).unwrap(), event);
        let plain = serde_json::to_value(SessionEventKind::StopAcknowledged).unwrap();
        assert_eq!(plain["kind"], "stop_acknowledged");
    }
}
