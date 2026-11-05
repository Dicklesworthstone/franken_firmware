//! Fixed-storage events shared by group-clock and latency computations.
//!
//! The owner transfers popped values to a control-side serializer. This module
//! performs no I/O, allocations, callbacks, locking or retries. It is not a
//! cross-thread queue; synchronization belongs outside the render path.
//! Critical priority follows `franken-hal/src/emit.rs::CriticalQueue`: evict
//! the oldest ordinary event, and lose a critical only when none can be evicted.
//! The fixed array avoids the HAL model queue's VecDeque allocations.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EventStats {
    pub emitted: u64,
    pub delivered: u64,
    pub dropped_ordinary: u64,
    pub evicted_ordinary: u64,
    /// Critical events refused because capacity held only critical records.
    pub lost_critical: u64,
    pub rate_limited: u64,
    pub unavailable_drops: u64,
    pub regression_drops: u64,
    /// All lost events, including evictions. emitted = delivered + pending + dropped.
    pub dropped: u64,
    /// All lost critical events, including unavailable/regressed-clock loss.
    /// This is a subset of dropped, not an additional term in that identity.
    pub critical_lost: u64,
    pub counters_saturated: bool,
}

impl EventStats {
    /// Loss accounting only. Pending records are not yet durable evidence.
    pub fn loss_free(self) -> bool {
        self.dropped == 0 && !self.counters_saturated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BufferedEvent<T> {
    pub sequence: u64,
    pub critical: bool,
    pub timestamp_mono_ns: u64,
    pub counters_before: EventStats,
    pub pending_before: usize,
    pub payload: T,
}

#[derive(Debug)]
pub struct EventBuffer<T: Copy, const N: usize = 8> {
    queue: [Option<BufferedEvent<T>>; N],
    read_index: usize,
    len: usize,
    stats: EventStats,
    available: bool,
    max_per_window: u32,
    window_ns: u64,
    window_start: Option<u64>,
    window_count: u32,
    last_timestamp: Option<u64>,
}

fn increment(counter: &mut u64, saturated: &mut bool) {
    if let Some(value) = counter.checked_add(1) {
        *counter = value;
    } else {
        *saturated = true;
    }
}

impl<T: Copy, const N: usize> EventBuffer<T, N> {
    pub fn new(max_per_window: u32, window_ns: u64) -> Self {
        Self {
            queue: [None; N],
            read_index: 0,
            len: 0,
            stats: EventStats::default(),
            available: true,
            max_per_window,
            window_ns: window_ns.max(1),
            window_start: None,
            window_count: 0,
            last_timestamp: None,
        }
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub const fn stats(&self) -> EventStats {
        self.stats
    }

    pub const fn pending(&self) -> usize {
        self.len
    }

    /// Tries once; ordinary floods are rate- and capacity-limited.
    pub fn try_emit(&mut self, now_ns: u64, payload: T) -> bool {
        self.emit(now_ns, payload, false)
    }

    /// Critical records bypass the ordinary rate cap but never the storage cap.
    pub fn try_emit_critical(&mut self, now_ns: u64, payload: T) -> bool {
        self.emit(now_ns, payload, true)
    }

    fn note_loss(&mut self, critical: bool) {
        increment(&mut self.stats.dropped, &mut self.stats.counters_saturated);
        if critical {
            increment(
                &mut self.stats.critical_lost,
                &mut self.stats.counters_saturated,
            );
        }
    }

    fn emit(&mut self, now_ns: u64, payload: T, critical: bool) -> bool {
        increment(&mut self.stats.emitted, &mut self.stats.counters_saturated);
        if self.last_timestamp.is_some_and(|last| now_ns < last) {
            increment(
                &mut self.stats.regression_drops,
                &mut self.stats.counters_saturated,
            );
            self.note_loss(critical);
            return false;
        }
        self.last_timestamp = Some(now_ns);
        if !self.available {
            increment(
                &mut self.stats.unavailable_drops,
                &mut self.stats.counters_saturated,
            );
            self.note_loss(critical);
            return false;
        }
        if !critical {
            if self
                .window_start
                .is_none_or(|start| now_ns - start >= self.window_ns)
            {
                self.window_start = Some(now_ns);
                self.window_count = 0;
            }
            if self.window_count >= self.max_per_window {
                increment(
                    &mut self.stats.rate_limited,
                    &mut self.stats.counters_saturated,
                );
                self.note_loss(false);
                return false;
            }
            self.window_count += 1;
        }
        if self.len == N {
            if !critical {
                increment(
                    &mut self.stats.dropped_ordinary,
                    &mut self.stats.counters_saturated,
                );
                self.note_loss(false);
                return false;
            }
            let ordinary = (0..self.len).find(|&i| {
                self.queue[(self.read_index + i) % N].is_some_and(|event| !event.critical)
            });
            let Some(position) = ordinary else {
                increment(
                    &mut self.stats.lost_critical,
                    &mut self.stats.counters_saturated,
                );
                self.note_loss(true);
                return false;
            };
            // Preserve FIFO order among retained records, including ring wrap.
            for i in position..self.len - 1 {
                self.queue[(self.read_index + i) % N] = self.queue[(self.read_index + i + 1) % N];
            }
            self.queue[(self.read_index + self.len - 1) % N] = None;
            self.len -= 1;
            increment(
                &mut self.stats.evicted_ordinary,
                &mut self.stats.counters_saturated,
            );
            self.note_loss(false);
        }
        // N == 0 returned above; modulo is never evaluated for a disabled queue.
        let index = (self.read_index + self.len) % N;
        self.queue[index] = Some(BufferedEvent {
            sequence: self.stats.emitted,
            critical,
            timestamp_mono_ns: now_ns,
            counters_before: self.stats,
            pending_before: self.len,
            payload,
        });
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> Option<BufferedEvent<T>> {
        if self.len == 0 {
            return None;
        }
        let event = self.queue[self.read_index].take();
        self.read_index = (self.read_index + 1) % N;
        self.len -= 1;
        increment(
            &mut self.stats.delivered,
            &mut self.stats.counters_saturated,
        );
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn hal_critical_queue_policy_vector_and_recovery() {
        // Same hand-traced sequence as franken-hal/src/emit.rs's policy test.
        let mut queue = EventBuffer::<u8, 3>::new(u32::MAX, 1);
        assert!(queue.try_emit(1, 1));
        assert!(queue.try_emit(2, 2));
        assert!(queue.try_emit_critical(3, 3));
        assert!(!queue.try_emit(4, 4));
        assert!(queue.try_emit_critical(5, 5));
        assert!(queue.try_emit_critical(6, 6));
        assert!(!queue.try_emit_critical(7, 7));
        assert!(!queue.try_emit(8, 8));
        assert_eq!(queue.pending(), 3);
        let retained: Vec<_> = std::iter::from_fn(|| queue.pop())
            .map(|e| e.payload)
            .collect();
        assert_eq!(retained, vec![3, 5, 6]);
        assert_eq!(queue.stats().dropped_ordinary, 2);
        assert_eq!(queue.stats().evicted_ordinary, 2);
        assert_eq!(queue.stats().lost_critical, 1);
        assert_eq!(queue.stats().critical_lost, 1);
        assert_eq!(queue.stats().dropped, 5);
        assert_eq!(
            queue.stats().emitted,
            queue.stats().delivered + queue.stats().dropped
        );
        assert!(queue.try_emit(9, 9));
        assert_eq!(queue.pop().unwrap().payload, 9);
    }

    fn model_sequences<const N: usize>() {
        for schedule in 0u32..3u32.pow(7) {
            let mut encoded = schedule;
            let mut model: VecDeque<(u64, bool)> = VecDeque::new();
            let mut queue = EventBuffer::<(u64, bool), N>::new(u32::MAX, 1);
            let mut emitted = 0;
            let mut dropped = 0;
            let mut delivered = 0;
            for time in 0..7 {
                match encoded % 3 {
                    0..=1 => {
                        let critical = encoded % 3 == 1;
                        emitted += 1;
                        let payload = (emitted, critical);
                        let mut admitted = true;
                        if model.len() == N {
                            if critical {
                                if let Some(index) = model.iter().position(|&(_, c)| !c) {
                                    let _ = model.remove(index);
                                    dropped += 1;
                                } else {
                                    admitted = false;
                                    dropped += 1;
                                }
                            } else {
                                admitted = false;
                                dropped += 1;
                            }
                        }
                        if admitted {
                            model.push_back(payload);
                        }
                        let actual = if critical {
                            queue.try_emit_critical(time, payload)
                        } else {
                            queue.try_emit(time, payload)
                        };
                        assert_eq!(actual, admitted, "N={N}, schedule={schedule}, time={time}");
                    }
                    _ => {
                        let expected = model.pop_front();
                        let actual = queue.pop().map(|event| event.payload);
                        assert_eq!(actual, expected, "N={N}, schedule={schedule}, time={time}");
                        delivered += u64::from(expected.is_some());
                    }
                }
                encoded /= 3;
                assert_eq!(queue.pending(), model.len());
                assert_eq!(queue.stats().emitted, emitted);
                assert_eq!(queue.stats().dropped, dropped);
                assert_eq!(queue.stats().delivered, delivered);
                assert_eq!(emitted, delivered + dropped + queue.pending() as u64);
            }
            let actual: Vec<_> = std::iter::from_fn(|| queue.pop())
                .map(|event| event.payload)
                .collect();
            assert_eq!(actual, Vec::from(model));
        }
    }

    #[test]
    fn every_seven_step_policy_schedule_matches_independent_deque() {
        model_sequences::<0>();
        model_sequences::<1>();
        model_sequences::<3>();
    }

    #[test]
    fn critical_bypasses_ordinary_rate_limit_but_loss_is_explicit() {
        let mut queue = EventBuffer::<u8, 1>::new(0, 10);
        assert!(!queue.try_emit(1, 1));
        assert!(queue.try_emit_critical(1, 2));
        assert!(!queue.try_emit_critical(2, 3));
        queue.set_available(false);
        assert!(!queue.try_emit_critical(3, 4));
        assert!(!queue.try_emit_critical(2, 5));
        assert_eq!(queue.stats().rate_limited, 1);
        assert_eq!(queue.stats().lost_critical, 1);
        assert_eq!(queue.stats().unavailable_drops, 1);
        assert_eq!(queue.stats().regression_drops, 1);
        assert_eq!(queue.stats().critical_lost, 3);
        assert_eq!(queue.stats().dropped, 4);
        assert_eq!(queue.stats().emitted, 5);
    }

    #[test]
    fn saturation_never_wraps_evidence_loss_to_zero() {
        let mut queue = EventBuffer::<u8, 0>::new(u32::MAX, 1);
        queue.stats.emitted = u64::MAX;
        queue.stats.dropped_ordinary = u64::MAX;
        queue.stats.dropped = u64::MAX;
        assert!(!queue.try_emit(1, 4));
        assert_eq!(queue.stats.emitted, u64::MAX);
        assert_eq!(queue.stats.dropped_ordinary, u64::MAX);
        assert!(queue.stats.counters_saturated);
        assert!(!queue.stats.loss_free());
    }
}
