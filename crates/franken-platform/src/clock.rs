//! The monotonic clock, and nothing else (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! "Emulating a monotonic clock with wall time changes the timing contract" (E03 section 4), so this layer has no
//! wall-clock path to fall back to: [`crate::ops::KernelOps`] has no `clock_gettime(CLOCK_REALTIME)` method, which
//! makes the substitution unrepresentable and not merely unpracticed. A failing monotonic clock is an error. (The Linux leaf's
//! clock is `std::time::Instant`, which cannot fail, so on a real kernel the error paths here are policy for a seam that a
//! different or a failing backend could present; they are tested with scripted replies. The reading's epoch is the backend's:
//! see [`crate::ops`].)
//!
//! A reading is validated before it is believed: `tv_sec` must not be negative, `tv_nsec` must be in
//! `0..1_000_000_000`, and the nanosecond total must fit a `u64`. A call that "succeeds" with a positive return
//! value is not a clock success (it returns 0), and neither is a value that is not an errno or a result.
//! Time going backwards is caught one level up, in [`crate::layer::PlatformLayer::now_ns`], because it needs the
//! previous reading.

use crate::abi::{Abi, SysError};
use crate::ops::{KernelOps, Timespec};

pub const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Why no monotonic reading was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    #[error(
        "the monotonic clock call is absent (ENOSYS in this ABI); there is no wall-clock fallback"
    )]
    Absent,
    #[error("the monotonic clock call was interrupted on every one of its bounded attempts")]
    Interrupted,
    #[error("the monotonic clock call failed with errno {0}")]
    Failed(i32),
    #[error("the monotonic clock call returned {0}, which is neither a result nor an errno")]
    Malformed(isize),
    #[error("clock_gettime returned {0}; success is exactly 0")]
    UnexpectedReturn(usize),
    #[error("the kernel timespec is out of range (secs {secs}, nanos {nanos})")]
    InvalidTimespec { secs: i64, nanos: i64 },
    #[error("the monotonic reading does not fit 64 bits of nanoseconds")]
    Overflow,
    #[error("the monotonic clock went backwards ({now_ns} ns after {last_ns} ns)")]
    WentBackwards { last_ns: u64, now_ns: u64 },
}

fn from_sys(error: SysError) -> ClockError {
    match error {
        SysError::Absent => ClockError::Absent,
        SysError::Interrupted => ClockError::Interrupted,
        // A clock call has no use for these two; an errno they carry is reported as the errno it is.
        SysError::WouldBlock => ClockError::Failed(crate::abi::EAGAIN),
        SysError::Invalid => ClockError::Failed(crate::abi::EINVAL),
        SysError::Errno(number) => ClockError::Failed(number),
        SysError::Malformed(value) => ClockError::Malformed(value),
    }
}

/// One validated monotonic reading in nanoseconds. Its epoch is the backend's (see [`crate::ops`]): only differences between
/// readings of one backend are meaningful.
///
/// # Errors
/// See [`ClockError`] (all but [`ClockError::WentBackwards`], which needs the previous reading).
pub fn now_ns<O: KernelOps + ?Sized>(ops: &mut O, abi: Abi) -> Result<u64, ClockError> {
    let mut ts = Timespec::default();
    let returned = abi
        .call_retrying(|| ops.clock_gettime_monotonic(&mut ts))
        .map_err(from_sys)?;
    if returned != 0 {
        return Err(ClockError::UnexpectedReturn(returned));
    }
    let invalid = ClockError::InvalidTimespec {
        secs: ts.secs,
        nanos: ts.nanos,
    };
    if !(0..NANOS_PER_SEC).contains(&ts.nanos) {
        return Err(invalid);
    }
    // `try_from` is also what rejects a negative `tv_sec`.
    let secs = u64::try_from(ts.secs).map_err(|_| invalid)?;
    let nanos = u64::try_from(ts.nanos).map_err(|_| invalid)?;
    secs.checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanos))
        .ok_or(ClockError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::MAX_INTERRUPTED_ATTEMPTS;
    use crate::sim::{Call, ScriptedOps};

    #[test]
    fn a_valid_reading_is_seconds_times_a_billion_plus_nanos() {
        let mut ops = ScriptedOps::new().clock(0, 5, 123);
        assert_eq!(now_ns(&mut ops, Abi::PowerPc32), Ok(5_000_000_123));
        // The edges of the valid range: zero, and the largest nanosecond field.
        let mut ops = ScriptedOps::new().clock(0, 0, 0).clock(0, 1, 999_999_999);
        assert_eq!(now_ns(&mut ops, Abi::Mips32), Ok(0));
        assert_eq!(now_ns(&mut ops, Abi::Mips32), Ok(1_999_999_999));
        // Only the monotonic call was ever made.
        assert!(ops.calls().iter().all(|call| *call == Call::Clock));
    }

    #[test]
    fn an_absent_clock_is_an_error_in_the_guests_own_numbering_and_there_is_no_wall_clock_to_use() {
        for (abi, enosys) in [(Abi::PowerPc32, 38isize), (Abi::Mips32, 89)] {
            let mut ops = ScriptedOps::new().clock(-enosys, 0, 0);
            assert_eq!(now_ns(&mut ops, abi), Err(ClockError::Absent), "{abi:?}");
            // Exactly one call, and it was the monotonic one. `KernelOps` has no realtime method, so a fallback
            // to wall time cannot even be written against this seam.
            assert_eq!(ops.calls(), vec![Call::Clock]);
        }
        let mut ops = ScriptedOps::new().clock(-38, 0, 0);
        assert_eq!(
            now_ns(&mut ops, Abi::Mips32),
            Err(ClockError::Failed(38)),
            "PowerPC's ENOSYS number is not absence on MIPS"
        );
    }

    #[test]
    fn an_interruption_storm_is_reported_after_the_bounded_attempts() {
        let mut ops = ScriptedOps::new();
        for _ in 0..10 {
            ops = ops.clock(-4, 0, 0);
        }
        assert_eq!(
            now_ns(&mut ops, Abi::PowerPc32),
            Err(ClockError::Interrupted)
        );
        assert_eq!(ops.calls().len(), MAX_INTERRUPTED_ATTEMPTS as usize);

        let mut ops = ScriptedOps::new().clock(-4, 0, 0).clock(0, 2, 0);
        assert_eq!(now_ns(&mut ops, Abi::PowerPc32), Ok(2_000_000_000));
        assert_eq!(ops.calls().len(), 2);
    }

    #[test]
    fn a_timespec_outside_the_valid_range_is_never_turned_into_a_time() {
        for (secs, nanos) in [
            (-1i64, 0i64),
            (0, -1),
            (0, 1_000_000_000),
            (3, i64::MAX),
            (i64::MIN, 0),
        ] {
            let mut ops = ScriptedOps::new().clock(0, secs, nanos);
            assert_eq!(
                now_ns(&mut ops, Abi::PowerPc32),
                Err(ClockError::InvalidTimespec { secs, nanos }),
                "{secs}/{nanos}"
            );
        }
    }

    #[test]
    fn a_reading_too_large_for_64_bits_is_overflow() {
        let mut ops = ScriptedOps::new().clock(0, i64::MAX, 0);
        assert_eq!(now_ns(&mut ops, Abi::Mips32), Err(ClockError::Overflow));
        // The largest second count that still fits is accepted.
        let fits = i64::try_from(u64::MAX / 1_000_000_000).unwrap();
        let mut ops = ScriptedOps::new().clock(0, fits, 0);
        assert_eq!(
            now_ns(&mut ops, Abi::Mips32),
            Ok(fits as u64 * 1_000_000_000)
        );
    }

    #[test]
    fn success_is_exactly_zero_and_other_returns_are_not_a_time() {
        let mut ops = ScriptedOps::new().clock(3, 1, 1);
        assert_eq!(
            now_ns(&mut ops, Abi::PowerPc32),
            Err(ClockError::UnexpectedReturn(3))
        );
        let mut ops = ScriptedOps::new().clock(-5000, 1, 1);
        assert_eq!(
            now_ns(&mut ops, Abi::PowerPc32),
            Err(ClockError::Malformed(-5000))
        );
        let mut ops = ScriptedOps::new().clock(-22, 1, 1);
        assert_eq!(
            now_ns(&mut ops, Abi::PowerPc32),
            Err(ClockError::Failed(22))
        );
    }
}
