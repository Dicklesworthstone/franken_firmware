//! Fixed K4/R4 scalar subset of RFC6330. No allocation or monolithic solve in poll.
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

pub const K: usize = 4;
pub const N: usize = 8;
pub const BYTES: usize = 1024;
const WIDTH: usize = K + BYTES;
/// Source-derived candidate, checked against the exact pinned Asup encoder by
/// the thin reference crate. No production admission follows from this constant.
pub const GENERATOR: [[u8; K]; N] = [
    [1, 0, 0, 0],
    [0, 1, 0, 0],
    [0, 0, 1, 0],
    [0, 0, 0, 1],
    [1, 231, 134, 93],
    [205, 116, 135, 33],
    [170, 185, 126, 59],
    [59, 211, 122, 228],
];
/// Init <=8*1028, pivot/search/swap/normalize/eliminate
/// <=4*(8+1028+1028+8*(1028+2)+4), verify <=8*1024*5,
/// hash <=66*256, publication allowance4*2048, inverse<=4*14, setup<=264.
/// Strictly below this ceiling, including state transitions and row copies.
pub const MAX_WORK: u64 = 120_000;
pub const HASH_WORK: u64 = 256;
pub const PUBLICATION_WORK: u64 = 2048;

/// Eight fixed bit rounds, using the same 0x11d field as Asupersync.
pub fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        out ^= a & 0_u8.wrapping_sub(b & 1);
        b >>= 1;
        a = (a << 1) ^ (0x1d & 0_u8.wrapping_sub(a >> 7));
    }
    out
}
fn inverse(a: u8) -> u8 {
    // Fixed fourteen multiplications (exponent254), never a data-dependent search.
    let mut value = a;
    for _ in 0..6 {
        value = multiply(multiply(value, value), a);
    }
    multiply(value, value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeState {
    Idle,
    Pending,
    Ready,
    RankDeficit,
    Contradiction,
    Integrity,
    Cancelled,
    Exhausted,
}
#[derive(Clone, Copy)]
enum Phase {
    Init(usize),
    Search(usize),
    Swap(usize),
    Normalize(usize),
    Eliminate(usize, usize),
    Verify(usize, usize, usize, u8),
    Hash(usize),
    Done,
}

pub struct IncrementalDecode {
    matrix: [[u8; WIDTH]; N],
    esis: [usize; N],
    rows: usize,
    pivot: usize,
    chosen: usize,
    inverse: u8,
    phase: Phase,
    state: DecodeState,
    used: u64,
    digest: Sha256,
    expected: [u8; 32],
}
impl Default for IncrementalDecode {
    fn default() -> Self {
        Self::new()
    }
}
impl IncrementalDecode {
    pub fn new() -> Self {
        Self {
            matrix: [[0; WIDTH]; N],
            esis: [0; N],
            rows: 0,
            pivot: 0,
            chosen: 0,
            inverse: 0,
            phase: Phase::Done,
            state: DecodeState::Idle,
            used: 0,
            digest: Sha256::new(),
            expected: [0; 32],
        }
    }
    /// Setup is eight index checks and one fixed metadata hash block. Input bytes
    /// are copied by later scalar steps; they must remain immutable during a job.
    pub fn begin(&mut self, mask: u8, expected: [u8; 32], metadata: &[u8; 64]) -> DecodeState {
        self.rows = 0;
        for esi in 0..N {
            if mask & (1 << esi) != 0 {
                self.esis[self.rows] = esi;
                self.rows += 1;
            }
        }
        self.pivot = 0;
        self.used = HASH_WORK + 264;
        self.expected = expected;
        self.digest = Sha256::new();
        self.digest.update(super::DIGEST_DOMAIN);
        self.digest.update(metadata);
        self.state = if self.rows < K {
            DecodeState::RankDeficit
        } else {
            DecodeState::Pending
        };
        self.phase = Phase::Init(0);
        self.state
    }
    pub fn state(&self) -> DecodeState {
        self.state
    }
    pub fn used(&self) -> u64 {
        self.used
    }
    pub fn next_step_work(&self) -> u64 {
        if self.state != DecodeState::Pending {
            return 0;
        }
        match self.phase {
            Phase::Hash(63) => HASH_WORK * 2,
            Phase::Hash(_) => HASH_WORK,
            Phase::Swap(byte) if byte + 1 == WIDTH => 15,
            _ => 1,
        }
    }
    pub fn remaining_bound(&self) -> u64 {
        if self.state == DecodeState::Pending {
            MAX_WORK - self.used
        } else {
            0
        }
    }
    pub fn cancel(&mut self) {
        self.state = DecodeState::Cancelled;
        self.phase = Phase::Done;
    }
    pub fn output(&self, block: usize) -> Option<&[u8]> {
        (self.state == DecodeState::Ready && block < K).then(|| &self.matrix[block][K..])
    }
    /// At most quota charged operations. Cancellation is sampled BEFORE every
    /// scalar operation / fixed64-byte hash block. No callbacks, allocation or join.
    pub fn poll(
        &mut self,
        input: &[[u8; BYTES]; N],
        quota: u64,
        cancelled: &AtomicBool,
    ) -> DecodeState {
        if cancelled.load(Ordering::Acquire) {
            self.cancel();
            return self.state;
        }
        let mut spent = 0;
        while self.state == DecodeState::Pending && spent < quota {
            if cancelled.load(Ordering::Acquire) {
                self.cancel();
                break;
            }
            let cost = self.next_step_work();
            if spent + cost > quota {
                break;
            }
            if self.used + cost > MAX_WORK {
                self.state = DecodeState::Exhausted;
                break;
            }
            self.used += cost;
            spent += cost;
            match self.phase {
                Phase::Init(index) => {
                    let row = index / WIDTH;
                    let byte = index % WIDTH;
                    let esi = self.esis[row];
                    self.matrix[row][byte] = if byte < K {
                        GENERATOR[esi][byte]
                    } else {
                        input[esi][byte - K]
                    };
                    self.phase = if index + 1 == self.rows * WIDTH {
                        Phase::Search(0)
                    } else {
                        Phase::Init(index + 1)
                    };
                }
                Phase::Search(row) => {
                    if row >= self.rows {
                        self.state = DecodeState::RankDeficit;
                    } else if self.matrix[row][self.pivot] != 0 {
                        self.chosen = row;
                        self.phase = Phase::Swap(0);
                    } else {
                        self.phase = Phase::Search(row + 1);
                    }
                }
                Phase::Swap(byte) => {
                    let value = self.matrix[self.pivot][byte];
                    self.matrix[self.pivot][byte] = self.matrix[self.chosen][byte];
                    self.matrix[self.chosen][byte] = value;
                    if byte + 1 == WIDTH {
                        self.inverse = inverse(self.matrix[self.pivot][self.pivot]);
                        self.phase = Phase::Normalize(0);
                    } else {
                        self.phase = Phase::Swap(byte + 1);
                    }
                }
                Phase::Normalize(byte) => {
                    self.matrix[self.pivot][byte] =
                        multiply(self.matrix[self.pivot][byte], self.inverse);
                    self.phase = if byte + 1 == WIDTH {
                        Phase::Eliminate(0, 0)
                    } else {
                        Phase::Normalize(byte + 1)
                    };
                }
                Phase::Eliminate(row, byte) => {
                    if row == self.rows {
                        self.pivot += 1;
                        self.phase = if self.pivot == K {
                            Phase::Verify(0, 0, 0, 0)
                        } else {
                            Phase::Search(self.pivot)
                        };
                    } else if row == self.pivot {
                        self.phase = Phase::Eliminate(row + 1, 0);
                    } else {
                        // Keep the pivot coefficient until last: it is the factor.
                        let at = if byte + 1 == WIDTH {
                            self.pivot
                        } else if byte >= self.pivot {
                            byte + 1
                        } else {
                            byte
                        };
                        let factor = self.matrix[row][self.pivot];
                        self.matrix[row][at] ^= multiply(factor, self.matrix[self.pivot][at]);
                        self.phase = if byte + 1 == WIDTH {
                            Phase::Eliminate(row + 1, 0)
                        } else {
                            Phase::Eliminate(row, byte + 1)
                        };
                    }
                }
                Phase::Verify(row, byte, col, acc) => {
                    let esi = self.esis[row];
                    if col < K {
                        self.phase = Phase::Verify(
                            row,
                            byte,
                            col + 1,
                            acc ^ multiply(GENERATOR[esi][col], self.matrix[col][K + byte]),
                        );
                    } else if acc != input[esi][byte] {
                        self.state = DecodeState::Contradiction;
                    } else if byte + 1 < BYTES {
                        self.phase = Phase::Verify(row, byte + 1, 0, 0);
                    } else if row + 1 < self.rows {
                        self.phase = Phase::Verify(row + 1, 0, 0, 0);
                    } else {
                        self.phase = Phase::Hash(0);
                    }
                }
                Phase::Hash(chunk) => {
                    let row = chunk / (BYTES / 64);
                    let start = K + (chunk % (BYTES / 64)) * 64;
                    self.digest.update(&self.matrix[row][start..start + 64]);
                    if chunk + 1 == K * (BYTES / 64) {
                        let actual: [u8; 32] = self.digest.clone().finalize().into();
                        self.state = if actual == self.expected {
                            DecodeState::Ready
                        } else {
                            DecodeState::Integrity
                        };
                        self.phase = Phase::Done;
                    } else {
                        self.phase = Phase::Hash(chunk + 1);
                    }
                }
                Phase::Done => break,
            }
        }
        self.state
    }
}
