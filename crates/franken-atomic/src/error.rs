//! Typed failures. None of them is ever returned silently as a wrapped or truncated value.

use core::fmt;

/// A checked 64-bit add or subtract left the range of its type. The cell is **unchanged**.
///
/// `Overflow` means the exact result would be above the type's maximum; `Underflow`, below its minimum.
/// For an unsigned cell a subtract can only underflow and an add can only overflow; for a signed cell the
/// direction follows the sign of the operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArithError<T> {
    /// `current + delta` (or `current - delta`) would be above the maximum of the type.
    Overflow {
        /// The value the cell held, and still holds.
        current: T,
        /// The operand that was refused.
        delta: T,
    },
    /// The result would be below the minimum of the type.
    Underflow {
        /// The value the cell held, and still holds.
        current: T,
        /// The operand that was refused.
        delta: T,
    },
}

impl<T: fmt::Display> fmt::Display for ArithError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow { current, delta } => {
                write!(
                    f,
                    "64-bit arithmetic overflow: current {current}, operand {delta}"
                )
            }
            Self::Underflow { current, delta } => {
                write!(
                    f,
                    "64-bit arithmetic underflow: current {current}, operand {delta}"
                )
            }
        }
    }
}

impl<T: fmt::Debug + fmt::Display> std::error::Error for ArithError<T> {}

/// A `try_*` operation found the cell's lock held and did not wait for it.
///
/// This is the answer for a caller that must not block, for example code that could run while the same
/// thread already holds the lock (a signal handler, a re-entrant callback) or a path with a deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Contended;

impl fmt::Display for Contended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("shared 64-bit cell is locked; the operation did not wait")
    }
}

impl std::error::Error for Contended {}

/// A [`Sequence`](crate::Sequence) has handed out every identifier it can. It never wraps to reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Exhausted;

impl fmt::Display for Exhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("64-bit identifier sequence exhausted")
    }
}

impl std::error::Error for Exhausted {}
