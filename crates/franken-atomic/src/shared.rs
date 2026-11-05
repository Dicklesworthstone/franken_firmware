//! Shared 64-bit cells for targets with no native 64-bit atomics.
//!
//! A cell is one `Mutex` around one integer. Every operation takes the lock, reads or writes the **whole**
//! value, and releases it. No caller code runs while the lock is held (there is no closure-taking
//! `fetch_update`), so the critical section is a handful of instructions, cannot re-enter, and cannot be
//! cancelled half way: an operation either happened completely or not at all.
//!
//! This is not lock-free and it is not for a render deadline; see the crate documentation.

use crate::error::{ArithError, Contended};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

fn add_err_unsigned(current: u64, delta: u64) -> ArithError<u64> {
    ArithError::Overflow { current, delta }
}

fn sub_err_unsigned(current: u64, delta: u64) -> ArithError<u64> {
    ArithError::Underflow { current, delta }
}

fn add_err_signed(current: i64, delta: i64) -> ArithError<i64> {
    if delta < 0 {
        ArithError::Underflow { current, delta }
    } else {
        ArithError::Overflow { current, delta }
    }
}

fn sub_err_signed(current: i64, delta: i64) -> ArithError<i64> {
    if delta < 0 {
        ArithError::Overflow { current, delta }
    } else {
        ArithError::Underflow { current, delta }
    }
}

macro_rules! shared_int {
    ($(#[$meta:meta])* $name:ident, $t:ty, $add_err:path, $sub_err:path) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name {
            inner: Mutex<$t>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new(0)
            }
        }

        impl $name {
            /// A new cell holding `value`.
            #[must_use]
            pub const fn new(value: $t) -> Self {
                Self { inner: Mutex::new(value) }
            }

            // A poisoned lock means some thread panicked while holding the guard. No code of ours can
            // panic inside the critical section and the value is written in one assignment, so the value is
            // always a whole value that some operation stored: it is recovered, never reported as torn.
            fn guard(&self) -> MutexGuard<'_, $t> {
                self.inner.lock().unwrap_or_else(PoisonError::into_inner)
            }

            fn try_guard(&self) -> Result<MutexGuard<'_, $t>, Contended> {
                match self.inner.try_lock() {
                    Ok(guard) => Ok(guard),
                    Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
                    Err(TryLockError::WouldBlock) => Err(Contended),
                }
            }

            /// The current value, all 64 bits of it.
            pub fn load(&self) -> $t {
                *self.guard()
            }

            /// Replaces the value.
            pub fn store(&self, value: $t) {
                *self.guard() = value;
            }

            /// Replaces the value and returns the previous one.
            pub fn swap(&self, value: $t) -> $t {
                let mut guard = self.guard();
                core::mem::replace(&mut *guard, value)
            }

            /// Stores `new` only if the value equals `current` over all 64 bits. `Ok(previous)` when it
            /// did, `Err(seen)` with the value that was there when it did not.
            pub fn compare_exchange(&self, current: $t, new: $t) -> Result<$t, $t> {
                let mut guard = self.guard();
                let seen = *guard;
                if seen == current {
                    *guard = new;
                    Ok(seen)
                } else {
                    Err(seen)
                }
            }

            /// Adds `delta` and returns the previous value. **Checked**: if the exact result does not fit,
            /// returns the typed error and leaves the value untouched. It never wraps.
            pub fn fetch_add(&self, delta: $t) -> Result<$t, ArithError<$t>> {
                let mut guard = self.guard();
                let seen = *guard;
                match seen.checked_add(delta) {
                    Some(next) => {
                        *guard = next;
                        Ok(seen)
                    }
                    None => Err($add_err(seen, delta)),
                }
            }

            /// Subtracts `delta` and returns the previous value. Checked like [`Self::fetch_add`].
            pub fn fetch_sub(&self, delta: $t) -> Result<$t, ArithError<$t>> {
                let mut guard = self.guard();
                let seen = *guard;
                match seen.checked_sub(delta) {
                    Some(next) => {
                        *guard = next;
                        Ok(seen)
                    }
                    None => Err($sub_err(seen, delta)),
                }
            }

            /// Adds `delta` modulo 2^64 and returns the previous value. The name is the contract: use it only
            /// where wrapping is the meaning (a free-running hash or phase), never for an identifier,
            /// generation, byte count or timestamp.
            pub fn fetch_add_wrapping(&self, delta: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                *guard = seen.wrapping_add(delta);
                seen
            }

            /// Subtracts `delta` modulo 2^64 and returns the previous value. See [`Self::fetch_add_wrapping`].
            pub fn fetch_sub_wrapping(&self, delta: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                *guard = seen.wrapping_sub(delta);
                seen
            }

            /// Stores the larger of the value and `other`; returns the previous value.
            pub fn fetch_max(&self, other: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                if other > seen {
                    *guard = other;
                }
                seen
            }

            /// Stores the smaller of the value and `other`; returns the previous value.
            pub fn fetch_min(&self, other: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                if other < seen {
                    *guard = other;
                }
                seen
            }

            /// Bitwise AND over all 64 bits; returns the previous value.
            pub fn fetch_and(&self, mask: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                *guard = seen & mask;
                seen
            }

            /// Bitwise OR over all 64 bits; returns the previous value.
            pub fn fetch_or(&self, mask: $t) -> $t {
                let mut guard = self.guard();
                let seen = *guard;
                *guard = seen | mask;
                seen
            }

            /// Like [`Self::load`] but does not wait: `Err(Contended)` if the lock is held.
            pub fn try_load(&self) -> Result<$t, Contended> {
                Ok(*self.try_guard()?)
            }

            /// Like [`Self::store`] but does not wait: `Err(Contended)` if the lock is held, and then the
            /// value is not changed.
            pub fn try_store(&self, value: $t) -> Result<(), Contended> {
                *self.try_guard()? = value;
                Ok(())
            }

            /// Exclusive access to the value. The borrow checker proves nobody else has the cell.
            pub fn get_mut(&mut self) -> &mut $t {
                self.inner.get_mut().unwrap_or_else(PoisonError::into_inner)
            }

            /// Consumes the cell and returns the value.
            #[must_use]
            pub fn into_inner(self) -> $t {
                self.inner.into_inner().unwrap_or_else(PoisonError::into_inner)
            }
        }
    };
}

shared_int!(
    /// A shared unsigned 64-bit cell: the replacement for `AtomicU64` where the target has none.
    ///
    /// Operations are linearizable per cell: each takes effect at one instant between its call and its
    /// return, in an order every thread agrees on, and an operation that returns having observed another's
    /// effect also sees everything that other thread did before it. Different cells share no order.
    SharedU64,
    u64,
    add_err_unsigned,
    sub_err_unsigned
);

shared_int!(
    /// A shared signed 64-bit cell: the replacement for `AtomicI64` where the target has none.
    /// Same contract as [`SharedU64`].
    SharedI64,
    i64,
    add_err_signed,
    sub_err_signed
);

#[cfg(test)]
mod private_tests {
    use super::*;

    #[test]
    fn p05_poisoned_lock_keeps_the_whole_value() {
        let cell = SharedU64::new(0x0000_0001_0000_0007);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cell.inner.lock().expect("a fresh lock is not poisoned");
            panic!("poison the lock on purpose");
        }));
        assert!(outcome.is_err());
        assert!(cell.inner.is_poisoned());
        // Every operation still works, and the value was not lost or torn.
        assert_eq!(cell.load(), 0x0000_0001_0000_0007);
        assert_eq!(cell.fetch_add(1), Ok(0x0000_0001_0000_0007));
        assert_eq!(cell.try_load(), Ok(0x0000_0001_0000_0008));
        cell.store(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(cell.fetch_add(1), Err(ArithError::Overflow { current: u64::MAX, delta: 1 }));
        assert_eq!(cell.into_inner(), u64::MAX);
    }

    #[test]
    fn p05_try_ops_report_contention_instead_of_blocking() {
        // The same thread holds the lock, as a signal handler or a re-entrant callback would find it. A
        // blocking call would deadlock; the try_ calls answer at once and change nothing.
        let cell = SharedU64::new(9);
        let held = cell.inner.lock().expect("a fresh lock is not poisoned");
        assert_eq!(cell.try_load(), Err(Contended));
        assert_eq!(cell.try_store(1), Err(Contended));
        drop(held);
        assert_eq!(cell.try_load(), Ok(9));
        assert_eq!(cell.try_store(0x1_0000_0001), Ok(()));
        assert_eq!(cell.load(), 0x1_0000_0001);
    }

    #[test]
    fn p05_try_ops_work_on_a_poisoned_idle_lock() {
        let cell = SharedI64::new(-5);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cell.inner.lock().expect("a fresh lock is not poisoned");
            panic!("poison the lock on purpose");
        }));
        assert!(outcome.is_err());
        assert_eq!(cell.try_load(), Ok(-5));
        assert_eq!(cell.try_store(i64::MIN), Ok(()));
        assert_eq!(cell.load(), i64::MIN);
    }
}
