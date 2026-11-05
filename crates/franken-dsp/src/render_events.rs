//! Bounded, nonblocking render-path events (`D01` / `ffw-f3b`, `D02` / `ffw-7s0`, `G02` / `ffw-ld0`).
//!
//! The shared logging clause of those three beads: *the render path emits bounded counters and events to a
//! nonblocking sink; a slow, full or unavailable sink must not change audio deadlines; the log bounds its event
//! rate and memory, exposes dropped-event counts, carries no audio payload or identifier, and loss of critical
//! evidence marks the result incomplete.*
//!
//! # Shape
//!
//! [`event_channel`] builds a single-producer, single-consumer ring of fixed-size [`RenderEvent`]s, allocated
//! once, before the render loop runs. The render thread owns the [`EventProducer`]; whatever writes the log (a
//! file, a socket, the shared test runner) owns the [`EventConsumer`], on another thread. The render thread never
//! touches the log writer, only the ring.
//!
//! * **Nonblocking.** [`EventProducer::emit`] performs a fixed number of atomic loads and stores: no loop, no
//!   lock, no allocation, no system call, and no wait on the consumer. Its only read of consumer state is one
//!   `Acquire` load of the consumer's position. A consumer that is slow, stopped or gone therefore changes what
//!   the ring *holds*, never how long the render thread takes to call it.
//! * **Bounded.** Memory is `capacity` slots of 12 bytes. Event rate is bounded per block: the three adapters
//!   below emit at most [`MAX_EVENTS_PER_BLOCK`] events for one block, one per nonzero counter, never one per
//!   sample.
//! * **Loss is counted, never silent.** When the ring is full the event is dropped and counted; the next event
//!   that is kept carries a sequence number that skips the dropped ones, so the log shows *where* the gap is.
//! * **Critical events outrank ordinary ones.** A single-producer ring cannot evict an older event (the consumer
//!   owns that end), so room is reserved instead: ordinary events may fill only `capacity - critical_reserve`
//!   slots, critical ones (a board entering fail-muted, a latched protection fault) may fill all of them. A
//!   critical event is lost only when the whole ring is full of undelivered events; that is counted separately
//!   and [`EventConsumer::evidence_complete`] turns `false`.
//! * **No payload.** An event is a sequence number, a fieldless kind and one `u32` count. It has no string, no
//!   identifier and no sample, so there is nothing to redact.
//!
//! # What the render loop calls
//!
//! The DSP kernels do not know this module exists, so the signatures that other tests and vectors pin are
//! untouched. The render loop calls an adapter after each call it already makes, from the report that call
//! returned: [`EventProducer::convert_stats`] after `convert_block`, [`EventProducer::ring_counters`] with the
//! ring's cumulative over/underrun counters, and [`EventProducer::protection_report`] after `render_into`.
//!
//! # What this does not show
//!
//! * That a log writer behind the [`EventConsumer`] is healthy. If it stops, the ring fills and events are
//!   dropped and counted; the writer must report its own failure. [`EventProducer::consumer_connected`] only says
//!   whether the consumer endpoint still exists.
//! * Any timing. Nothing here measures how long `emit` takes on a board. "Wait-free" above is a statement about
//!   the code: it has no loop, lock or wait.
//! * The log file format. Mapping events onto versioned JSONL belongs to the shared test runner (Q00).
//!
//! `seq` is a `u32` that counts every event the producer attempted, kept or not, and wraps after 2^32 events.

use crate::convert::ConvertStats;
use crate::protection::{BlockReport, BoardStatus, FaultCode};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(test)]
mod tests;

/// Largest ring. A power of two so a slot index is `counter & mask` and stays continuous when the 32-bit
/// counters wrap.
pub const MAX_CAPACITY: usize = 1 << 16;

/// Most events the three adapters can emit for one render block: two from [`EventProducer::convert_stats`],
/// two from [`EventProducer::ring_counters`] and four from [`EventProducer::protection_report`].
pub const MAX_EVENTS_PER_BLOCK: usize = 8;

/// What happened. Fieldless, so it carries no identifier. The meaning of [`RenderEvent::value`] is given per
/// kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderEventKind {
    /// Samples a conversion clamped to the destination range in one block. Ordinary.
    ConvertSaturated,
    /// Non-finite samples a conversion flushed to zero in one block. Ordinary.
    ConvertNonFinite,
    /// Ring writes refused for lack of room since the previous report. Ordinary.
    RingOverrun,
    /// Ring reads refused for lack of data since the previous report. Ordinary.
    RingUnderrun,
    /// Output samples the protection chain's hard clip changed in one block. Ordinary.
    ProtectionClipped,
    /// Output samples the thermal model scaled in one block. Ordinary.
    ProtectionThermalScaled,
    /// Non-finite input samples the protection chain replaced by silence in one block. Ordinary.
    ProtectionInputNonFinite,
    /// The board is admitted and running (`value` is 0). Ordinary.
    BoardActive,
    /// The board is not admitted, or was switched to an unsafe profile, and renders silence (`value` is 0).
    /// The typed cause is the `ProtectionError` the admission call returned, not repeated here. Critical.
    BoardFailMuted,
    /// A filter produced NaN or infinity and latched a fault; `value` is the channel. Critical.
    BoardFaultNonFiniteState,
    /// A value left the admitted intermediate range and latched a fault; `value` is the channel. Critical.
    BoardFaultStateRange,
    /// The thermal model reached its hard limit and latched a fault; `value` is the channel. Critical.
    BoardFaultThermalHard,
}

impl RenderEventKind {
    /// Every kind, in index order. A test pins that `ALL[i].index() == i`.
    pub const ALL: [Self; 12] = [
        Self::ConvertSaturated,
        Self::ConvertNonFinite,
        Self::RingOverrun,
        Self::RingUnderrun,
        Self::ProtectionClipped,
        Self::ProtectionThermalScaled,
        Self::ProtectionInputNonFinite,
        Self::BoardActive,
        Self::BoardFailMuted,
        Self::BoardFaultNonFiniteState,
        Self::BoardFaultStateRange,
        Self::BoardFaultThermalHard,
    ];

    /// Evidence a result cannot be trusted without: the board went silent or latched a fault.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::BoardFailMuted
                | Self::BoardFaultNonFiniteState
                | Self::BoardFaultStateRange
                | Self::BoardFaultThermalHard
        )
    }

    /// The stable snake_case name, identical to the serialized form.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConvertSaturated => "convert_saturated",
            Self::ConvertNonFinite => "convert_non_finite",
            Self::RingOverrun => "ring_overrun",
            Self::RingUnderrun => "ring_underrun",
            Self::ProtectionClipped => "protection_clipped",
            Self::ProtectionThermalScaled => "protection_thermal_scaled",
            Self::ProtectionInputNonFinite => "protection_input_non_finite",
            Self::BoardActive => "board_active",
            Self::BoardFailMuted => "board_fail_muted",
            Self::BoardFaultNonFiniteState => "board_fault_non_finite_state",
            Self::BoardFaultStateRange => "board_fault_state_range",
            Self::BoardFaultThermalHard => "board_fault_thermal_hard",
        }
    }

    const fn index(self) -> u32 {
        self as u32
    }

    fn from_index(index: u32) -> Option<Self> {
        usize::try_from(index)
            .ok()
            .and_then(|i| Self::ALL.get(i))
            .copied()
    }
}

/// One event as the consumer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RenderEvent {
    /// Position among every event the producer attempted, kept or dropped. A jump between two consecutive
    /// events read from the ring is the number of events lost between them.
    pub seq: u32,
    pub kind: RenderEventKind,
    /// A count or a channel number; see [`RenderEventKind`].
    pub value: u32,
}

/// What became of one [`EventProducer::emit`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emitted {
    /// The event is in the ring.
    Kept,
    /// An ordinary event found fewer than `critical_reserve + 1` free slots and was counted as dropped.
    DroppedOrdinary,
    /// A critical event found the ring completely full and was counted as lost.
    LostCritical,
}

/// Why [`event_channel`] refused a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EventConfigError {
    #[error("event ring capacity {capacity} is not a power of two between 2 and the maximum")]
    Capacity { capacity: usize },
    #[error("critical reserve {reserve} must be at least 1 and less than the capacity {capacity}")]
    Reserve { reserve: usize, capacity: usize },
}

/// A snapshot of the ring's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventStats {
    pub capacity: usize,
    pub critical_reserve: usize,
    /// Events in the ring that the consumer has not read yet.
    pub pending: usize,
    /// Ordinary events dropped because the ring had no room beyond the critical reserve (saturating).
    pub dropped_ordinary: u32,
    /// Critical events lost because the ring was completely full (saturating).
    pub lost_critical: u32,
    /// Slots the consumer could not decode. Always 0 unless the ring is corrupted (saturating).
    pub undecodable: u32,
}

#[derive(Debug)]
struct Slot {
    seq: AtomicU32,
    kind: AtomicU32,
    value: AtomicU32,
}

impl Slot {
    fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            kind: AtomicU32::new(0),
            value: AtomicU32::new(0),
        }
    }
}

#[derive(Debug)]
struct Shared {
    slots: Box<[Slot]>,
    /// `capacity - 1`; `capacity` is a power of two.
    mask: u32,
    capacity: u32,
    reserve: u32,
    /// Events published so far, modulo 2^32. Written by the producer only.
    tail: AtomicU32,
    /// Events consumed so far, modulo 2^32. Written by the consumer only.
    head: AtomicU32,
    /// Written by the producer only.
    dropped_ordinary: AtomicU32,
    /// Written by the producer only.
    lost_critical: AtomicU32,
}

impl Shared {
    fn slot(&self, counter: u32) -> Option<&Slot> {
        usize::try_from(counter & self.mask)
            .ok()
            .and_then(|index| self.slots.get(index))
    }

    fn pending(&self) -> u32 {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

/// Saturating increment. Each counter has exactly one writer, so a plain load and store cannot lose an update.
fn bump(counter: &AtomicU32) {
    counter.store(
        counter.load(Ordering::Relaxed).saturating_add(1),
        Ordering::Relaxed,
    );
}

/// Build a ring of `capacity` events, `critical_reserve` of which only critical events may use.
///
/// `capacity` must be a power of two from 2 to [`MAX_CAPACITY`]; `critical_reserve` must be at least 1 and less
/// than `capacity`. This allocates; call it before the render loop starts.
///
/// # Errors
/// [`EventConfigError`] for a capacity that is not a power of two in range, or a reserve outside `1..capacity`.
pub fn event_channel(
    capacity: usize,
    critical_reserve: usize,
) -> Result<(EventProducer, EventConsumer), EventConfigError> {
    if !capacity.is_power_of_two() || !(2..=MAX_CAPACITY).contains(&capacity) {
        return Err(EventConfigError::Capacity { capacity });
    }
    if critical_reserve == 0 || critical_reserve >= capacity {
        return Err(EventConfigError::Reserve {
            reserve: critical_reserve,
            capacity,
        });
    }
    let (Ok(capacity32), Ok(reserve32)) =
        (u32::try_from(capacity), u32::try_from(critical_reserve))
    else {
        return Err(EventConfigError::Capacity { capacity });
    };
    let shared = Arc::new(Shared {
        slots: (0..capacity).map(|_| Slot::new()).collect(),
        mask: capacity32 - 1,
        capacity: capacity32,
        reserve: reserve32,
        tail: AtomicU32::new(0),
        head: AtomicU32::new(0),
        dropped_ordinary: AtomicU32::new(0),
        lost_critical: AtomicU32::new(0),
    });
    Ok((
        EventProducer {
            shared: Arc::clone(&shared),
            next_seq: 0,
            seen_overruns: 0,
            seen_underruns: 0,
            last_status: BoardStatus::Active,
        },
        EventConsumer {
            shared,
            undecodable: 0,
        },
    ))
}

/// The render thread's end of the ring.
#[derive(Debug)]
pub struct EventProducer {
    shared: Arc<Shared>,
    next_seq: u32,
    seen_overruns: u32,
    seen_underruns: u32,
    last_status: BoardStatus,
}

impl EventProducer {
    /// Record one event, or count that it was not recorded. Never waits and never allocates.
    pub fn emit(&mut self, kind: RenderEventKind, value: u32) -> Emitted {
        let shared = &*self.shared;
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        let critical = kind.is_critical();
        let tail = shared.tail.load(Ordering::Relaxed);
        let head = shared.head.load(Ordering::Acquire);
        let free = shared.capacity.saturating_sub(tail.wrapping_sub(head));
        let needed = if critical {
            1
        } else {
            shared.reserve.saturating_add(1)
        };
        match shared.slot(tail) {
            Some(slot) if free >= needed => {
                slot.seq.store(seq, Ordering::Relaxed);
                slot.kind.store(kind.index(), Ordering::Relaxed);
                slot.value.store(value, Ordering::Relaxed);
                shared.tail.store(tail.wrapping_add(1), Ordering::Release);
                Emitted::Kept
            }
            _ if critical => {
                bump(&shared.lost_critical);
                Emitted::LostCritical
            }
            _ => {
                bump(&shared.dropped_ordinary);
                Emitted::DroppedOrdinary
            }
        }
    }

    /// After `convert_block`: one event for each nonzero counter in the block's [`ConvertStats`].
    pub fn convert_stats(&mut self, stats: ConvertStats) {
        if stats.saturated > 0 {
            self.emit(RenderEventKind::ConvertSaturated, stats.saturated);
        }
        if stats.non_finite > 0 {
            self.emit(RenderEventKind::ConvertNonFinite, stats.non_finite);
        }
    }

    /// With the ring's cumulative `overruns()` and `underruns()`: one event for each that grew since the
    /// previous call, carrying the growth. A counter that went backwards (a different ring) is taken as the new
    /// baseline and emits nothing.
    pub fn ring_counters(&mut self, overruns: u32, underruns: u32) {
        let new_overruns = overruns.saturating_sub(self.seen_overruns);
        let new_underruns = underruns.saturating_sub(self.seen_underruns);
        self.seen_overruns = overruns;
        self.seen_underruns = underruns;
        if new_overruns > 0 {
            self.emit(RenderEventKind::RingOverrun, new_overruns);
        }
        if new_underruns > 0 {
            self.emit(RenderEventKind::RingUnderrun, new_underruns);
        }
    }

    /// After `render_into`: one event for each nonzero protection counter in the block's [`BlockReport`], and
    /// one event when the board's status differs from the previous report. The producer starts out assuming
    /// the board is [`BoardStatus::Active`], so a board that is already fail-muted at the first block reports
    /// that.
    pub fn protection_report(&mut self, report: &BlockReport) {
        if report.clipped_samples > 0 {
            self.emit(RenderEventKind::ProtectionClipped, report.clipped_samples);
        }
        if report.thermal_scaled_samples > 0 {
            self.emit(
                RenderEventKind::ProtectionThermalScaled,
                report.thermal_scaled_samples,
            );
        }
        if report.input_non_finite > 0 {
            self.emit(
                RenderEventKind::ProtectionInputNonFinite,
                report.input_non_finite,
            );
        }
        if report.status != self.last_status {
            self.last_status = report.status;
            let (kind, value) = status_event(report.status);
            self.emit(kind, value);
        }
    }

    /// Events this producer has tried to record, kept or not. `attempted = kept + dropped_ordinary +
    /// lost_critical`, modulo 2^32.
    #[must_use]
    pub fn attempted(&self) -> u32 {
        self.next_seq
    }

    #[must_use]
    pub fn dropped_ordinary(&self) -> u32 {
        self.shared.dropped_ordinary.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn lost_critical(&self) -> u32 {
        self.shared.lost_critical.load(Ordering::Relaxed)
    }

    /// Whether the [`EventConsumer`] still exists. Informational: [`EventProducer::emit`] behaves identically
    /// either way, because a missing consumer is indistinguishable from one that never reads.
    #[must_use]
    pub fn consumer_connected(&self) -> bool {
        Arc::strong_count(&self.shared) > 1
    }
}

/// The status event for a board status. Exhaustive on purpose: a new fault code is a compile error here.
fn status_event(status: BoardStatus) -> (RenderEventKind, u32) {
    match status {
        BoardStatus::Active => (RenderEventKind::BoardActive, 0),
        BoardStatus::FailMuted(_) => (RenderEventKind::BoardFailMuted, 0),
        BoardStatus::Faulted(FaultCode::NonFiniteState { channel }) => (
            RenderEventKind::BoardFaultNonFiniteState,
            u32::from(channel),
        ),
        BoardStatus::Faulted(FaultCode::StateRange { channel }) => {
            (RenderEventKind::BoardFaultStateRange, u32::from(channel))
        }
        BoardStatus::Faulted(FaultCode::ThermalHard { channel }) => {
            (RenderEventKind::BoardFaultThermalHard, u32::from(channel))
        }
    }
}

/// The log writer's end of the ring. Not for the render thread.
#[derive(Debug)]
pub struct EventConsumer {
    shared: Arc<Shared>,
    undecodable: u32,
}

impl EventConsumer {
    /// The oldest event in the ring, or `None` when it is empty.
    pub fn pop(&mut self) -> Option<RenderEvent> {
        let shared = &*self.shared;
        loop {
            let head = shared.head.load(Ordering::Relaxed);
            let tail = shared.tail.load(Ordering::Acquire);
            if head == tail {
                return None;
            }
            let words = shared.slot(head).map(|slot| {
                (
                    slot.seq.load(Ordering::Relaxed),
                    slot.kind.load(Ordering::Relaxed),
                    slot.value.load(Ordering::Relaxed),
                )
            });
            shared.head.store(head.wrapping_add(1), Ordering::Release);
            let event = words.and_then(|(seq, kind, value)| {
                RenderEventKind::from_index(kind).map(|kind| RenderEvent { seq, kind, value })
            });
            match event {
                Some(event) => return Some(event),
                None => self.undecodable = self.undecodable.saturating_add(1),
            }
        }
    }

    /// Append up to one ring's worth of events to `out`, oldest first; returns how many were appended.
    pub fn drain_into(&mut self, out: &mut Vec<RenderEvent>) -> usize {
        let mut appended = 0;
        while appended < self.capacity() {
            match self.pop() {
                Some(event) => {
                    out.push(event);
                    appended += 1;
                }
                None => break,
            }
        }
        appended
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.slots.len()
    }

    #[must_use]
    pub fn stats(&self) -> EventStats {
        let shared = &*self.shared;
        EventStats {
            capacity: shared.slots.len(),
            critical_reserve: usize::try_from(shared.reserve).unwrap_or(usize::MAX),
            pending: usize::try_from(shared.pending()).unwrap_or(usize::MAX),
            dropped_ordinary: shared.dropped_ordinary.load(Ordering::Relaxed),
            lost_critical: shared.lost_critical.load(Ordering::Relaxed),
            undecodable: self.undecodable,
        }
    }

    /// `false` once any critical event was lost, or a slot could not be decoded: a result that depends on this
    /// log must then be marked incomplete. Dropped ordinary events do not clear it; they are counted in
    /// [`EventStats::dropped_ordinary`] and visible as gaps in `seq`.
    #[must_use]
    pub fn evidence_complete(&self) -> bool {
        let stats = self.stats();
        stats.lost_critical == 0 && stats.undecodable == 0
    }
}
