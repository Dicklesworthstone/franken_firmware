//! Secure entropy: `getrandom(GRND_NONBLOCK)` or nothing (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! ## There is no fallback, on purpose
//! The only provider is the kernel's `getrandom` with `GRND_NONBLOCK`. Every other way to produce bytes is refused
//! by construction, because each is the insecure fallback the acceptance criterion forbids:
//! * **`/dev/urandom`** never blocks and cannot say whether the pool is seeded. The E03 harness guests show both
//!   sides: on the MIPS guest the kernel logged `random: init: uninitialized urandom read` and `getrandom` answered
//!   `UNSEEDED` (`-EAGAIN`); on the PPC guest `getrandom` returned 16 bytes. Reading `/dev/urandom` there would have
//!   produced bytes in both cases and told the caller nothing. `urandom_entropy` in the capability matrix is a
//!   *liveness* observation and is not read as a secure-entropy claim anywhere in this crate.
//! * **A deterministic or time/PID-seeded generator** is not entropy.
//! * **`GRND_INSECURE` and `GRND_RANDOM`** are never requested: the flags are a constant, not a parameter.
//!
//! What the layer does instead of falling back:
//! * `-EAGAIN` (pool not seeded) is [`EntropyError::NotSeeded`]: no bytes, a distinct, retryable error. The layer
//!   does not spin and does not sleep (it owns no clock to sleep with); the caller decides how long to wait.
//! * `-ENOSYS` in the guest's own ABI numbering is [`EntropyError::Absent`], and `EINVAL` is **not** read as
//!   absence ([`EntropyError::Invalid`]).
//! * On every error the whole caller buffer is zeroed, including bytes an earlier iteration had received, so a
//!   caller that ignores the `Result` cannot use half a key.
//! * A kernel return that is longer than the request, zero for a nonzero request, or (for requests of 16 bytes or
//!   more) a buffer of identical bytes is an error ([`EntropyError::OverLong`], [`EntropyError::NoProgress`],
//!   [`EntropyError::Degenerate`]). The last one is a sanity check against a backend that reports success without
//!   producing bytes; it is not a randomness test (see the known limits in the contract).
//!
//! Short reads are continued from where they stopped. An interrupted call is repeated a bounded number of times
//! ([`crate::abi::MAX_INTERRUPTED_ATTEMPTS`]) and then reported.

use crate::CapabilityStatus;
use crate::abi::{Abi, SysError};
use crate::ops::KernelOps;
use serde::{Deserialize, Serialize};

/// `GRND_NONBLOCK`: the only flag this layer ever passes. `GRND_RANDOM` (2) and `GRND_INSECURE` (4) are not
/// reachable from any API here.
pub const GRND_NONBLOCK: u32 = 0x1;

/// A request at least this long that comes back as one repeated byte value is rejected as [`EntropyError::Degenerate`].
/// For 16 bytes a genuine kernel produces this with probability 2^-120.
pub const DEGENERATE_CHECK_MIN_LEN: usize = 16;

/// What the capability matrix says about secure entropy for a guest that matches the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntropyAvailability {
    /// `getrandom(GRND_NONBLOCK)` returned bytes in the matching guest.
    ObservedSeeded,
    /// The call exists but answered `-EAGAIN` at PID-1 boot in the matching guest. Callers must expect
    /// [`EntropyError::NotSeeded`] and decide how long to wait; nothing here shortens that wait.
    ObservedUnseededAtBoot,
    /// Secure entropy is not available on this profile. Carries the matrix status that says why. Includes
    /// [`CapabilityStatus::AbsentFallbackAdmitted`]: no fallback is admitted for entropy, so "absent" can never be
    /// "fine".
    Unavailable { status: CapabilityStatus },
}

impl EntropyAvailability {
    /// Map the matrix's `getrandom_syscall` status.
    #[must_use]
    pub const fn from_status(status: CapabilityStatus) -> Self {
        match status {
            CapabilityStatus::Supported => Self::ObservedSeeded,
            CapabilityStatus::ObservedUnseeded => Self::ObservedUnseededAtBoot,
            CapabilityStatus::AbsentFallbackAdmitted
            | CapabilityStatus::MissingRequired
            | CapabilityStatus::UnqualifiedPendingStockGuest => Self::Unavailable { status },
        }
    }

    /// Whether a call to [`fill`] is worth making.
    #[must_use]
    pub const fn may_attempt(self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

/// Why no entropy was produced. Every variant means the caller's buffer was zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntropyError {
    #[error("a zero-length entropy request is a caller error")]
    ZeroLength,
    #[error(
        "secure entropy is unavailable on this profile (matrix status {status:?}); no fallback exists"
    )]
    Unavailable { status: CapabilityStatus },
    #[error(
        "the kernel entropy pool is not seeded yet (EAGAIN); no bytes were produced and none were substituted"
    )]
    NotSeeded,
    #[error("getrandom is absent (ENOSYS in this ABI); there is no fallback")]
    Absent,
    #[error("getrandom was interrupted on every one of its bounded attempts")]
    Interrupted,
    #[error("getrandom rejected its arguments (EINVAL); that is not absence")]
    Invalid,
    #[error("getrandom made no progress")]
    NoProgress,
    #[error("getrandom reported {returned} bytes for a request of {requested}")]
    OverLong { requested: usize, returned: usize },
    #[error("getrandom output is degenerate (every byte equal)")]
    Degenerate,
    #[error("getrandom failed with errno {0}")]
    Failed(i32),
    #[error("getrandom returned {0}, which is neither a result nor an errno")]
    Malformed(isize),
}

fn from_sys(error: SysError) -> EntropyError {
    match error {
        SysError::Absent => EntropyError::Absent,
        SysError::WouldBlock => EntropyError::NotSeeded,
        SysError::Interrupted => EntropyError::Interrupted,
        SysError::Invalid => EntropyError::Invalid,
        SysError::Errno(number) => EntropyError::Failed(number),
        SysError::Malformed(value) => EntropyError::Malformed(value),
    }
}

fn fill_inner<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = buf.len() - filled;
        let got = abi
            .call_retrying(|| ops.getrandom(&mut buf[filled..], GRND_NONBLOCK))
            .map_err(from_sys)?;
        if got == 0 {
            return Err(EntropyError::NoProgress);
        }
        if got > remaining {
            return Err(EntropyError::OverLong {
                requested: remaining,
                returned: got,
            });
        }
        filled += got;
    }
    Ok(())
}

fn is_degenerate(buf: &[u8]) -> bool {
    buf.len() >= DEGENERATE_CHECK_MIN_LEN && buf.iter().all(|byte| *byte == buf[0])
}

/// Fill `buf` with kernel entropy, or fail and leave `buf` all zero.
///
/// # Errors
/// See [`EntropyError`]. [`EntropyError::NotSeeded`] is the expected answer at boot on a guest whose pool is not
/// seeded yet; it is not a failure of the platform and it is not retried here.
pub fn fill<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    if buf.is_empty() {
        return Err(EntropyError::ZeroLength);
    }
    let outcome = fill_inner(ops, abi, buf).and_then(|()| {
        if is_degenerate(buf) {
            Err(EntropyError::Degenerate)
        } else {
            Ok(())
        }
    });
    if outcome.is_err() {
        buf.fill(0);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::MAX_INTERRUPTED_ATTEMPTS;
    use crate::sim::{Call, ScriptedOps};

    const PPC: Abi = Abi::PowerPc32;
    const MIPS: Abi = Abi::Mips32;

    fn sixteen() -> Vec<u8> {
        (1..=16u8).collect()
    }

    #[test]
    fn a_full_read_fills_the_buffer_and_asks_only_for_nonblock() {
        let mut ops = ScriptedOps::new().random(16, &sixteen());
        let mut buf = [0u8; 16];
        assert_eq!(fill(&mut ops, PPC, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), sixteen());
        assert_eq!(
            ops.calls(),
            vec![Call::GetRandom {
                len: 16,
                flags: GRND_NONBLOCK
            }]
        );
        // GRND_RANDOM (2) and GRND_INSECURE (4) are not part of what the layer can request.
        assert_eq!(GRND_NONBLOCK, 1);
        assert_eq!(GRND_NONBLOCK & (0x2 | 0x4), 0);
    }

    #[test]
    fn a_short_read_is_continued_from_where_it_stopped() {
        let all = sixteen();
        let mut ops = ScriptedOps::new()
            .random(10, &all[..10])
            .random(6, &all[10..]);
        let mut buf = [0u8; 16];
        assert_eq!(fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), all);
        assert_eq!(
            ops.calls(),
            vec![
                Call::GetRandom {
                    len: 16,
                    flags: GRND_NONBLOCK
                },
                Call::GetRandom {
                    len: 6,
                    flags: GRND_NONBLOCK
                },
            ]
        );
    }

    #[test]
    fn an_unseeded_pool_is_an_error_with_no_bytes_and_no_other_source_tried() {
        let mut ops = ScriptedOps::new().random(-11, &[]);
        let mut buf = [0xAAu8; 16];
        assert_eq!(fill(&mut ops, MIPS, &mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(
            buf, [0u8; 16],
            "the caller's buffer must not keep stale or partial bytes"
        );
        // Exactly one getrandom call: no retry spin, no open/read of /dev/urandom (the seam has no such call),
        // no second provider.
        assert_eq!(
            ops.calls(),
            vec![Call::GetRandom {
                len: 16,
                flags: GRND_NONBLOCK
            }]
        );
    }

    #[test]
    fn a_failure_after_partial_bytes_still_zeroes_the_whole_buffer() {
        let mut ops = ScriptedOps::new()
            .random(8, &[1, 2, 3, 4, 5, 6, 7, 8])
            .random(-11, &[]);
        let mut buf = [0xAAu8; 16];
        assert_eq!(fill(&mut ops, PPC, &mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(
            buf, [0u8; 16],
            "the eight good bytes must not survive an error"
        );
    }

    #[test]
    fn absence_is_the_guest_abis_own_enosys_and_never_another_abis() {
        for (abi, enosys) in [(PPC, 38isize), (MIPS, 89)] {
            let mut ops = ScriptedOps::new().random(-enosys, &[]);
            let mut buf = [0xAAu8; 32];
            assert_eq!(
                fill(&mut ops, abi, &mut buf),
                Err(EntropyError::Absent),
                "{abi:?}"
            );
            assert_eq!(buf, [0u8; 32]);
        }
        // The other ABI's ENOSYS is just an errno here: the call exists and failed some other way.
        let mut ops = ScriptedOps::new().random(-89, &[]);
        assert_eq!(
            fill(&mut ops, PPC, &mut [0u8; 16]),
            Err(EntropyError::Failed(89))
        );
        let mut ops = ScriptedOps::new().random(-38, &[]);
        assert_eq!(
            fill(&mut ops, MIPS, &mut [0u8; 16]),
            Err(EntropyError::Failed(38))
        );
    }

    #[test]
    fn einval_is_not_absence_and_other_errnos_keep_their_number() {
        let mut ops = ScriptedOps::new().random(-22, &[]);
        assert_eq!(
            fill(&mut ops, PPC, &mut [0u8; 16]),
            Err(EntropyError::Invalid)
        );
        let mut ops = ScriptedOps::new().random(-12, &[]);
        assert_eq!(
            fill(&mut ops, MIPS, &mut [0u8; 16]),
            Err(EntropyError::Failed(12))
        );
    }

    #[test]
    fn an_interrupted_call_is_retried_a_bounded_number_of_times() {
        let mut ops = ScriptedOps::new()
            .random(-4, &[])
            .random(-4, &[])
            .random(-4, &[])
            .random(16, &sixteen());
        let mut buf = [0u8; 16];
        assert_eq!(fill(&mut ops, PPC, &mut buf), Ok(()));
        assert_eq!(ops.calls().len(), 4);
        assert_eq!(buf.to_vec(), sixteen());

        // A signal storm: twenty interruptions are scripted, only the bounded number is ever issued.
        let mut storm = ScriptedOps::new();
        for _ in 0..20 {
            storm = storm.random(-4, &[]);
        }
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            fill(&mut storm, PPC, &mut buf),
            Err(EntropyError::Interrupted)
        );
        assert_eq!(storm.calls().len(), MAX_INTERRUPTED_ATTEMPTS as usize);
        assert_eq!(
            storm.pending_random(),
            20 - MAX_INTERRUPTED_ATTEMPTS as usize
        );
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn a_kernel_that_reports_more_than_was_asked_or_nothing_at_all_is_an_error() {
        let mut ops = ScriptedOps::new().random(17, &sixteen());
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::OverLong {
                requested: 16,
                returned: 17
            })
        );
        assert_eq!(buf, [0u8; 16]);

        let mut ops = ScriptedOps::new().random(0, &[]);
        assert_eq!(
            fill(&mut ops, PPC, &mut [0u8; 16]),
            Err(EntropyError::NoProgress)
        );
    }

    #[test]
    fn a_success_that_produced_one_repeated_byte_is_degenerate_not_entropy() {
        let mut ops = ScriptedOps::new().random(16, &[0u8; 16]);
        let mut buf = [0xAAu8; 16];
        assert_eq!(fill(&mut ops, PPC, &mut buf), Err(EntropyError::Degenerate));
        assert_eq!(buf, [0u8; 16]);

        let mut ops = ScriptedOps::new().random(32, &[0xABu8; 32]);
        assert_eq!(
            fill(&mut ops, MIPS, &mut [0u8; 32]),
            Err(EntropyError::Degenerate)
        );

        // The check is only applied from 16 bytes up: a short request cannot be judged this way, and the test
        // records that limit instead of hiding it.
        let mut ops = ScriptedOps::new().random(15, &[7u8; 15]);
        let mut buf = [0u8; 15];
        assert_eq!(fill(&mut ops, PPC, &mut buf), Ok(()));
        assert_eq!(buf, [7u8; 15]);
    }

    #[test]
    fn a_zero_length_request_is_an_error_and_makes_no_call() {
        let mut ops = ScriptedOps::new();
        assert_eq!(fill(&mut ops, PPC, &mut []), Err(EntropyError::ZeroLength));
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_return_value_that_is_not_an_errno_is_malformed_never_success() {
        let mut ops = ScriptedOps::new().random(-5000, &[]);
        assert_eq!(
            fill(&mut ops, PPC, &mut [0u8; 16]),
            Err(EntropyError::Malformed(-5000))
        );
    }

    #[test]
    fn matrix_status_maps_to_availability_and_absent_with_fallback_is_unavailable() {
        use CapabilityStatus::*;
        assert_eq!(
            EntropyAvailability::from_status(Supported),
            EntropyAvailability::ObservedSeeded
        );
        assert_eq!(
            EntropyAvailability::from_status(ObservedUnseeded),
            EntropyAvailability::ObservedUnseededAtBoot
        );
        for status in [
            AbsentFallbackAdmitted,
            MissingRequired,
            UnqualifiedPendingStockGuest,
        ] {
            let availability = EntropyAvailability::from_status(status);
            assert_eq!(availability, EntropyAvailability::Unavailable { status });
            assert!(!availability.may_attempt(), "{status:?}");
        }
        assert!(EntropyAvailability::ObservedSeeded.may_attempt());
        assert!(EntropyAvailability::ObservedUnseededAtBoot.may_attempt());
    }
}
