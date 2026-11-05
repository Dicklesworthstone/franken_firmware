//! Test-only PLANTED DEFECTS: the two wrong replacements the bead names. They exist so the tests can show
//! they fail. Nothing outside `cfg(test)` may use them.
//!
//! * [`SplitCell`]: a "64-bit atomic" made of two independent 32-bit atomics. Each word is atomic, the
//!   pair is not: a reader can see the new high word with the old low word, and an add carries between the
//!   words in two separate steps.
//! * [`TruncCell`]: a 32-bit atomic that cuts every value with `as u32`.
//!
//! Both are driven one micro-step at a time by the scheduler in `model.rs`, so the interleavings that
//! expose them are deterministic and replayable from a seed. The two are deliberately honest attempts: they
//! differ from the real cell only in the one thing being planted (word splitting, truncation).

use crate::model::{Op, Resp, StepCell};
use std::sync::atomic::{AtomicU32, Ordering};

fn join(hi: u32, lo: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

#[derive(Clone, Copy)]
struct Pending {
    op: Op,
    phase: u8,
    hi: u32,
    lo: u32,
    seen: u64,
    carry: u32,
}

/// Two independent 32-bit words. `load` reads high then low; `store` writes high then low; `compare_exchange`
/// is load, compare, store; `fetch_add` adds the low word, then adds the high word and the carry.
pub(crate) struct SplitCell {
    hi: AtomicU32,
    lo: AtomicU32,
    pending: Vec<Option<Pending>>,
}

impl SplitCell {
    pub(crate) fn new(initial: u64, threads: usize) -> Self {
        Self {
            hi: AtomicU32::new((initial >> 32) as u32),
            lo: AtomicU32::new(initial as u32),
            pending: vec![None; threads],
        }
    }
}

impl StepCell for SplitCell {
    fn begin(&mut self, thread: usize, op: Op) {
        self.pending[thread] = Some(Pending {
            op,
            phase: 0,
            hi: 0,
            lo: 0,
            seen: 0,
            carry: 0,
        });
    }

    fn step(&mut self, thread: usize) -> Option<Resp> {
        let mut p = self.pending[thread].expect("step without begin");
        let phase = p.phase;
        p.phase += 1;
        let resp = match (p.op, phase) {
            (Op::Load, 0) => {
                p.hi = self.hi.load(Ordering::SeqCst);
                None
            }
            (Op::Load, _) => {
                p.lo = self.lo.load(Ordering::SeqCst);
                Some(Resp::Value(join(p.hi, p.lo)))
            }
            (Op::Store(value), 0) => {
                self.hi.store((value >> 32) as u32, Ordering::SeqCst);
                None
            }
            (Op::Store(value), _) => {
                self.lo.store(value as u32, Ordering::SeqCst);
                Some(Resp::Stored)
            }
            (Op::Cas { .. }, 0) => {
                p.hi = self.hi.load(Ordering::SeqCst);
                None
            }
            (Op::Cas { .. }, 1) => {
                p.lo = self.lo.load(Ordering::SeqCst);
                p.seen = join(p.hi, p.lo);
                None
            }
            (Op::Cas { current, new }, 2) => {
                if p.seen == current {
                    self.hi.store((new >> 32) as u32, Ordering::SeqCst);
                }
                None
            }
            (Op::Cas { current, new }, _) => {
                if p.seen == current {
                    self.lo.store(new as u32, Ordering::SeqCst);
                    Some(Resp::Cas(Ok(p.seen)))
                } else {
                    Some(Resp::Cas(Err(p.seen)))
                }
            }
            (Op::FetchAdd(delta), 0) => {
                let low = delta as u32;
                let old_lo = self.lo.fetch_add(low, Ordering::SeqCst);
                p.lo = old_lo;
                p.carry = u32::from(old_lo.checked_add(low).is_none());
                None
            }
            (Op::FetchAdd(delta), _) => {
                let high = ((delta >> 32) as u32).wrapping_add(p.carry);
                let old_hi = self.hi.fetch_add(high, Ordering::SeqCst);
                Some(Resp::Add(Ok(join(old_hi, p.lo))))
            }
        };
        self.pending[thread] = if resp.is_some() { None } else { Some(p) };
        resp
    }
}

/// One 32-bit word; values are cut with `as u32` on the way in and widened on the way out.
pub(crate) struct TruncCell {
    word: AtomicU32,
    pending: Vec<Option<Op>>,
}

impl TruncCell {
    pub(crate) fn new(initial: u64, threads: usize) -> Self {
        Self {
            word: AtomicU32::new(initial as u32),
            pending: vec![None; threads],
        }
    }
}

impl StepCell for TruncCell {
    fn begin(&mut self, thread: usize, op: Op) {
        self.pending[thread] = Some(op);
    }

    fn step(&mut self, thread: usize) -> Option<Resp> {
        let op = self.pending[thread].take().expect("step without begin");
        Some(match op {
            Op::Load => Resp::Value(u64::from(self.word.load(Ordering::SeqCst))),
            Op::Store(value) => {
                self.word.store(value as u32, Ordering::SeqCst);
                Resp::Stored
            }
            Op::Cas { current, new } => {
                let seen = u64::from(self.word.load(Ordering::SeqCst));
                if seen == current {
                    self.word.store(new as u32, Ordering::SeqCst);
                    Resp::Cas(Ok(seen))
                } else {
                    Resp::Cas(Err(seen))
                }
            }
            Op::FetchAdd(delta) => Resp::Add(Ok(u64::from(
                self.word.fetch_add(delta as u32, Ordering::SeqCst),
            ))),
        })
    }
}
