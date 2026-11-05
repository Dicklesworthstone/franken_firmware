//! Identifier and generation allocation that never wraps.

use crate::error::Exhausted;
use crate::shared::SharedU64;

/// Hands out strictly increasing 64-bit identifiers, each exactly once, across threads.
///
/// The sequence issues `first`, `first + 1`, ... up to and including `u64::MAX - 1`. **`u64::MAX` is never
/// issued**: it is the exhausted state, so "no more" is a value the cell can hold and every later call
/// reports [`Exhausted`] instead of reusing an identifier. A sequence created at `u64::MAX` is exhausted
/// from the start.
///
/// This is for identifiers, generations, ticket numbers and the like, where reuse after a wrap would be a
/// correctness failure. It is a shared, lock-based cell: do not call it from a render deadline.
#[derive(Debug)]
pub struct Sequence {
    next: SharedU64,
}

impl Sequence {
    /// A sequence whose first identifier is `first`.
    #[must_use]
    pub const fn new(first: u64) -> Self {
        Self {
            next: SharedU64::new(first),
        }
    }

    /// The next identifier, or [`Exhausted`] once `u64::MAX - 1` has been issued.
    pub fn next_id(&self) -> Result<u64, Exhausted> {
        self.next.fetch_add(1).map_err(|_| Exhausted)
    }

    /// The identifier the next call would return (`u64::MAX` when exhausted). Another thread may take it
    /// before the caller does; this is for diagnostics, never for reserving an identifier.
    pub fn peek(&self) -> u64 {
        self.next.load()
    }
}
