//! An independent model of the receiver's sequence window (`docs/contracts/n01.md` section 4), a set of accepted
//! sequence numbers and a high-water mark, with no bitmap. It exists so a stateful run can say exactly what the real
//! window must answer, and so "an accepted sequence number never goes backwards or repeats" is a checked property.

use std::collections::BTreeSet;

pub const WINDOW: u64 = 64;
pub const MAX_GAP: u64 = 1024;

#[derive(Debug, Default, Clone)]
pub struct Window {
    seen: BTreeSet<u64>,
    high: Option<u64>,
}

impl Window {
    /// What the window must answer for `seq` in the current epoch: `"OK"`, `"FUTURE_SEQUENCE"` or `"REPLAY_OR_DUPLICATE"`.
    pub fn judge(&self, seq: u64) -> &'static str {
        match self.high {
            None => {
                if seq > MAX_GAP {
                    "FUTURE_SEQUENCE"
                } else {
                    "OK"
                }
            }
            Some(high) if seq > high => {
                if seq - high > MAX_GAP {
                    "FUTURE_SEQUENCE"
                } else {
                    "OK"
                }
            }
            Some(high) => {
                if high - seq >= WINDOW || self.seen.contains(&seq) {
                    "REPLAY_OR_DUPLICATE"
                } else {
                    "OK"
                }
            }
        }
    }

    /// Record an accepted sequence number. Only call it after `judge` said `"OK"`.
    pub fn record(&mut self, seq: u64) {
        let high = self.high.map_or(seq, |h| h.max(seq));
        self.high = Some(high);
        self.seen.insert(seq);
        // Nothing more than one window behind the high-water mark can matter again.
        let floor = high.saturating_sub(WINDOW - 1);
        self.seen = self.seen.split_off(&floor);
    }

    pub fn high(&self) -> Option<u64> {
        self.high
    }
}
