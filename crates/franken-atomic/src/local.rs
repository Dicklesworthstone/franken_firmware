//! Owner-local 64-bit state: a plain value with no atomics, which is why it is allowed.

use crate::error::ArithError;
use core::cell::Cell;

/// A 64-bit counter or value that exactly one thread at a time may touch.
///
/// It is built on [`Cell`], so it is `Send` (ownership can move to another thread) and **not `Sync`**
/// (two threads cannot hold a shared reference to it). That is the point: local state needs no atomic
/// instruction and no lock, so it costs nothing on a render path, and the type system, not a comment,
/// keeps it from being shared. Anything two threads must both read or write is a
/// [`SharedU64`](crate::SharedU64) or [`SharedI64`](crate::SharedI64) instead.
#[derive(Debug, Default)]
pub struct LocalU64 {
    value: Cell<u64>,
}

impl LocalU64 {
    /// A new local value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value: Cell::new(value) }
    }

    /// The current value.
    pub fn get(&self) -> u64 {
        self.value.get()
    }

    /// Replaces the value.
    pub fn set(&self, value: u64) {
        self.value.set(value);
    }

    /// Adds `delta` and returns the previous value; **checked**, the value is unchanged on error.
    pub fn add(&self, delta: u64) -> Result<u64, ArithError<u64>> {
        let seen = self.value.get();
        match seen.checked_add(delta) {
            Some(next) => {
                self.value.set(next);
                Ok(seen)
            }
            None => Err(ArithError::Overflow { current: seen, delta }),
        }
    }

    /// Adds `delta` modulo 2^64 and returns the previous value. Wrapping by name, for values where wrapping
    /// is the meaning.
    pub fn add_wrapping(&self, delta: u64) -> u64 {
        let seen = self.value.get();
        self.value.set(seen.wrapping_add(delta));
        seen
    }
}
