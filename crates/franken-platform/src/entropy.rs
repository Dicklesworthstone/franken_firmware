//! Secure entropy: one explicitly selected provider, or nothing (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! ## There is no insecure fallback, on purpose
//! The acceptance criterion is *no insecure entropy fallback*. A provider is a kernel facility that says "nothing yet" instead of
//! inventing bytes, and it is chosen by an [`EntropyProfile`], **never by the failure of another provider**:
//! * [`EntropyProvider::Getrandom`], the default: `getrandom(GRND_NONBLOCK)` (Linux 3.17 and later).
//! * [`EntropyProvider::LegacyDevRandom`], for retained kernels older than 3.17 (the stock kernels are 2.6.14 and 2.6.35, E03): a
//!   nonblocking read of `/dev/random`. It is selected only by `EntropyProfile::LegacyDevRandom(..)`, so it is **not a downgrade**: a
//!   `getrandom` that answers `EAGAIN`, `EINVAL` or `ENOSYS` never causes it, and a layer that selected it never calls `getrandom`.
//!
//! Every other way to produce bytes is refused by construction, because each is the insecure fallback the criterion forbids:
//! * **`/dev/urandom`** never blocks and cannot say whether the pool is seeded. The E03 harness guests show both
//!   sides: on the MIPS guest the kernel logged `random: init: uninitialized urandom read` and `getrandom` answered
//!   `UNSEEDED` (`-EAGAIN`); on the PPC guest `getrandom` returned 16 bytes. Reading `/dev/urandom` there would have
//!   produced bytes in both cases and told the caller nothing. `urandom_entropy` in the capability matrix is a
//!   *liveness* observation and is not read as a secure-entropy claim anywhere in this crate.
//! * **A deterministic or time/PID-seeded generator** is not entropy.
//! * **`GRND_INSECURE` and `GRND_RANDOM`** are never requested: the flags are a constant, not a parameter.
//!
//! ## The legacy provider, from the kernel source
//! What a nonblocking read of `/dev/random` does on the stock kernels is read from `drivers/char/random.c` at the tags `v2.6.35`
//! (lines 997 to 1051, `random_read`; 884 to 919, `extract_entropy_user`; 770 to 807, `account`) and `v2.6.14` (937 to 997, 822 to
//! 857, 721 to 757): the two are identical for this purpose. The contract (`docs/contracts/p02.md`) names the sources and what each
//! fact below rests on; this is what the code relies on:
//! * **A read returns after its first successful extraction** (`random_read`'s `break`, "like a named pipe") and never more than
//!   `SEC_XFER_SIZE` (512) bytes, and `account` limits an extraction to the entropy the blocking pool holds (`entropy_count / 8`).
//!   So a short read is normal, not a fault: it is continued, within a bound.
//! * **`-EAGAIN` is the only "nothing available" answer** of a nonblocking read (`n == 0` with `O_NONBLOCK`). It is
//!   [`EntropyError::NotSeeded`]: the provider is *waiting*, no bytes were produced, and every byte already received in this call is
//!   discarded with the rest.
//! * **A signal surfaces as `EINTR`** only when the extraction produced nothing (`-ERESTARTSYS`, lines 897 and 1032); it is repeated a
//!   bounded number of times and then reported.
//! * **`/dev/urandom` is a different pool and a different answer**: `urandom_read` (lines 1053 to 1057 at `v2.6.35`) draws from the
//!   nonblocking pool, which sets no `.limit` (lines 442 to 445) while the blocking pool does (`.limit = 1`, line 436), so the clamp
//!   in `account` (line 787) never applies to it and it never says "nothing yet". That is why it is not a provider.
//!
//! The provider **opens the device for each call and closes it before returning**, so nothing is cached across calls: a pool that was
//! seeded a moment ago is asked again, and "seeded" is never assumed. A request is limited to [`LEGACY_MAX_REQUEST_BYTES`] bytes
//! (each byte is debited from a pool other readers share) and to [`LEGACY_MAX_READS`] reads.
//!
//! What this establishes: the policy's behaviour over the seam. It does **not** show that any stock kernel behaves as the source above
//! says (no stock kernel has been run: E03's stock cells are unqualified), and a scripted reply is an input, not entropy.
//!
//! What the layer does instead of falling back:
//! * `-EAGAIN` (pool not seeded) is [`EntropyError::NotSeeded`]: no bytes, a distinct, retryable error. The layer
//!   does not spin and does not sleep (it owns no clock to sleep with); the caller decides how long to wait.
//! * `-ENOSYS` in the guest's own ABI numbering is [`EntropyError::Absent`], and `EINVAL` is **not** read as
//!   absence ([`EntropyError::Invalid`]). (For the legacy provider a missing device is [`EntropyError::DeviceAbsent`].)
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
use crate::abi::{Abi, EAGAIN, EINTR, EINVAL, O_CLOEXEC, SysError};
use crate::ops::KernelOps;
use serde::{Deserialize, Serialize};

/// `GRND_NONBLOCK`: the only flag this layer ever passes. `GRND_RANDOM` (2) and `GRND_INSECURE` (4) are not
/// reachable from any API here.
pub const GRND_NONBLOCK: u32 = 0x1;

/// A request at least this long that comes back as one repeated byte value is rejected as [`EntropyError::Degenerate`].
/// For 16 bytes a genuine kernel produces this with probability 2^-120.
pub const DEGENERATE_CHECK_MIN_LEN: usize = 16;

/// The longest request the legacy provider serves in one call. A legacy `/dev/random` read debits the entropy it returns from a pool
/// that every reader shares, so an oversized request is refused with [`EntropyError::RequestTooLarge`] before any kernel call instead
/// of draining it; key-sized requests (16 to 32 bytes) are what the device needs.
pub const LEGACY_MAX_REQUEST_BYTES: usize = 64;

/// The most `read` calls (not counting the bounded repeats of an interrupted one) the legacy provider issues for one request. A read
/// that returns bytes returns at least one, so a request of up to this many bytes can always complete within it (the startup probe
/// asks for 16), while a longer request against a device that hands bytes out one or two at a time ends with
/// [`EntropyError::ReadBudget`] instead of looping on a pool that is only trickling.
pub const LEGACY_MAX_READS: usize = 16;

/// Which kernel facility supplies secure entropy. The choice belongs to an [`EntropyProfile`]; **no failure of one provider ever
/// selects the other**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntropyProvider {
    /// `getrandom(GRND_NONBLOCK)`: the default, Linux 3.17 and later.
    Getrandom,
    /// A nonblocking read of `/dev/random`, for retained kernels without `getrandom`. Explicit only.
    LegacyDevRandom,
}

impl EntropyProvider {
    /// The stable lowercase name printed in the startup markers (`provider=`) for a provider that is not the default.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Getrandom => "getrandom",
            Self::LegacyDevRandom => "legacy_dev_random",
        }
    }
}

/// What a profile says about the legacy provider's capability on the kernel it describes. There is no "assume it works": the default
/// for a stock kernel is [`Self::Unqualified`], and the layer then refuses without a kernel call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderQualification {
    /// A full-system guest that matches the profile was observed to do a nonblocking `/dev/random` read: `Supported` when it returned
    /// bytes, [`CapabilityStatus::ObservedUnseeded`] when it answered `-EAGAIN`; any other status makes the provider unavailable.
    /// Nothing in this repository records such an observation yet.
    Observed(CapabilityStatus),
    /// No observation exists for this provider on this profile (every stock kernel today): refused without a kernel call.
    Unqualified,
    /// No observation, but the caller **explicitly** names an admitted test environment (a harness guest, not a device): the provider
    /// may be tried, and what it returns is **not** an observation about any kernel and not device evidence.
    TestEnvironment,
}

/// The explicit entropy selection for a layer. [`Self::Getrandom`] (the default) reads availability from the capability matrix, as
/// before; [`Self::LegacyDevRandom`] carries its own qualification and ignores the matrix's `getrandom_syscall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyProfile {
    Getrandom,
    LegacyDevRandom(ProviderQualification),
}

impl EntropyProfile {
    /// The provider this profile selects.
    #[must_use]
    pub const fn provider(self) -> EntropyProvider {
        match self {
            Self::Getrandom => EntropyProvider::Getrandom,
            Self::LegacyDevRandom(_) => EntropyProvider::LegacyDevRandom,
        }
    }

    /// Whether the selected provider may be tried. `getrandom_availability` is what the matrix says about `getrandom`
    /// ([`crate::KernelCapabilityMatrix::secure_entropy`]); only [`Self::Getrandom`] reads it.
    #[must_use]
    pub const fn availability(
        self,
        getrandom_availability: EntropyAvailability,
    ) -> EntropyAvailability {
        match self {
            Self::Getrandom => getrandom_availability,
            Self::LegacyDevRandom(ProviderQualification::Observed(status)) => {
                EntropyAvailability::from_status(status)
            }
            Self::LegacyDevRandom(ProviderQualification::Unqualified) => {
                EntropyAvailability::Unavailable {
                    status: CapabilityStatus::UnqualifiedPendingStockGuest,
                }
            }
            Self::LegacyDevRandom(ProviderQualification::TestEnvironment) => {
                EntropyAvailability::AttemptableUnobserved
            }
        }
    }
}

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
    /// The explicitly selected legacy provider has **no observation** on this profile, but the caller named an admitted test
    /// environment ([`ProviderQualification::TestEnvironment`]): it may be tried. This is not [`Self::ObservedSeeded`]: nothing was
    /// observed, and a success is not evidence about any kernel.
    AttemptableUnobserved,
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
        "the kernel entropy pool has nothing to give yet (EAGAIN); the provider is waiting, no bytes were produced and none were substituted"
    )]
    NotSeeded,
    #[error("getrandom is absent (ENOSYS in this ABI); there is no fallback")]
    Absent,
    #[error("the entropy call was interrupted on every one of its bounded attempts")]
    Interrupted,
    #[error("the entropy call rejected its arguments (EINVAL); that is not absence")]
    Invalid,
    #[error("the entropy call made no progress")]
    NoProgress,
    #[error("the entropy call reported {returned} bytes for a request of {requested}")]
    OverLong { requested: usize, returned: usize },
    #[error("entropy output is degenerate (every byte equal)")]
    Degenerate,
    #[error("the entropy call failed with errno {0}")]
    Failed(i32),
    #[error("the entropy call returned {0}, which is neither a result nor an errno")]
    Malformed(isize),
    /// Legacy provider only: the request is longer than [`LEGACY_MAX_REQUEST_BYTES`]. No kernel call was made.
    #[error(
        "a request of {requested} bytes exceeds the legacy provider's per-call limit of {max}; no kernel call was made"
    )]
    RequestTooLarge { requested: usize, max: usize },
    /// Legacy provider only: the request was not filled within [`LEGACY_MAX_READS`] reads.
    #[error("the legacy provider did not fill the request within {reads} reads")]
    ReadBudget { reads: usize },
    /// Legacy provider only: the `/dev/random` device could not be opened because it does not exist (`ENOENT`, `ENXIO`, `ENODEV`).
    /// No other file is tried.
    #[error(
        "the legacy entropy device /dev/random does not exist on this kernel; no other source is tried"
    )]
    DeviceAbsent,
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

/// `ENOENT`, `ENXIO` and `ENODEV`: the same numbers on both legacy ABIs. An `open` that answers one of them found no such device.
const DEVICE_MISSING_ERRNOS: [i32; 3] = [2, 6, 19];

/// An error from the legacy provider's `open` (`opening`) or `read`. `getrandom`'s "absent" does not exist here: an `ENOSYS` from `open`
/// or `read` is not a statement about `getrandom`, so it is reported as the errno it is; a missing device has its own error; and an
/// `EAGAIN` is "nothing to give yet" only from a `read`, never from an `open`.
fn legacy_from_sys(abi: Abi, error: SysError, opening: bool) -> EntropyError {
    match error {
        SysError::Absent => EntropyError::Failed(abi.enosys()),
        SysError::WouldBlock if opening => EntropyError::Failed(EAGAIN),
        SysError::Errno(number) if opening && DEVICE_MISSING_ERRNOS.contains(&number) => {
            EntropyError::DeviceAbsent
        }
        other => from_sys(other),
    }
}

/// An error from the `close` that ends a legacy call: always the errno it is, never a statement about the pool.
fn close_failure(abi: Abi, error: SysError) -> EntropyError {
    match error {
        SysError::Absent => EntropyError::Failed(abi.enosys()),
        SysError::WouldBlock => EntropyError::Failed(EAGAIN),
        SysError::Interrupted => EntropyError::Failed(EINTR),
        SysError::Invalid => EntropyError::Failed(EINVAL),
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

/// The legacy provider's reads: `fd` is an open nonblocking `/dev/random`. At most [`LEGACY_MAX_READS`] reads, each repeated at most
/// [`crate::abi::MAX_INTERRUPTED_ATTEMPTS`] times on `EINTR`; a short read (the device's normal answer) continues from where it
/// stopped, and the first read that answers `EAGAIN` ends the call (the pool has nothing more to give).
fn read_legacy<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    fd: i32,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    let mut filled = 0usize;
    for _ in 0..LEGACY_MAX_READS {
        let remaining = buf.len() - filled;
        let got = abi
            .call_retrying(|| ops.read(fd, &mut buf[filled..]))
            .map_err(|error| legacy_from_sys(abi, error, false))?;
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
        if filled == buf.len() {
            return Ok(());
        }
    }
    Err(EntropyError::ReadBudget {
        reads: LEGACY_MAX_READS,
    })
}

/// One legacy request: open the device nonblocking, read, and **always close it once**, whatever the reads did. The first failure is
/// the one reported: a read error is not replaced by a close error, and a close error after good reads is an error too (the caller
/// zeroes the buffer), so a descriptor that could not be released never yields bytes.
fn fill_legacy<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    if buf.len() > LEGACY_MAX_REQUEST_BYTES {
        return Err(EntropyError::RequestTooLarge {
            requested: buf.len(),
            max: LEGACY_MAX_REQUEST_BYTES,
        });
    }
    let flags = abi.o_nonblock() | O_CLOEXEC;
    let raw = abi
        .call_retrying(|| ops.open_dev_random(flags))
        .map_err(|error| legacy_from_sys(abi, error, true))?;
    let fd = i32::try_from(raw)
        .map_err(|_| EntropyError::Malformed(isize::try_from(raw).unwrap_or(isize::MAX)))?;
    let read_result = read_legacy(ops, abi, fd, buf);
    let close_result = abi.decode(ops.close(fd));
    read_result?;
    match close_result {
        Ok(0) | Err(SysError::Interrupted) => Ok(()),
        Ok(other) => Err(EntropyError::Malformed(
            isize::try_from(other).unwrap_or(isize::MAX),
        )),
        Err(error) => Err(close_failure(abi, error)),
    }
}

fn is_degenerate(buf: &[u8]) -> bool {
    buf.len() >= DEGENERATE_CHECK_MIN_LEN && buf.iter().all(|byte| *byte == buf[0])
}

/// Fill `buf` with entropy from the **named** provider, or fail and leave `buf` all zero. The provider is the caller's explicit
/// choice (see [`EntropyProfile`]); nothing here ever tries the other one.
///
/// # Errors
/// See [`EntropyError`]. [`EntropyError::NotSeeded`] is the expected answer at boot on a guest whose pool is not seeded yet; it is
/// not a failure of the platform and it is not retried here.
pub fn fill_with<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    provider: EntropyProvider,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    if buf.is_empty() {
        return Err(EntropyError::ZeroLength);
    }
    let attempt = match provider {
        EntropyProvider::Getrandom => fill_inner(ops, abi, buf),
        EntropyProvider::LegacyDevRandom => fill_legacy(ops, abi, buf),
    };
    let outcome = attempt.and_then(|()| {
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

/// Fill `buf` with `getrandom` entropy, or fail and leave `buf` all zero: [`fill_with`] for [`EntropyProvider::Getrandom`].
///
/// # Errors
/// See [`EntropyError`].
pub fn fill<O: KernelOps + ?Sized>(
    ops: &mut O,
    abi: Abi,
    buf: &mut [u8],
) -> Result<(), EntropyError> {
    fill_with(ops, abi, EntropyProvider::Getrandom, buf)
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

    // ---- the explicitly selected legacy provider (root decision 5126, `ffw-jub` comment 205) ----
    //
    // A scripted reply is an INPUT. These tests show what the policy does with a reply over the seam, and nothing about a kernel: no
    // byte below is entropy, and the real adapter and a real guest are other proof classes (the QEMU speaker smoke, run centrally).

    const LEGACY: EntropyProvider = EntropyProvider::LegacyDevRandom;

    fn legacy_fill(ops: &mut ScriptedOps, abi: Abi, buf: &mut [u8]) -> Result<(), EntropyError> {
        fill_with(ops, abi, LEGACY, buf)
    }

    fn open_flags(abi: Abi) -> u32 {
        abi.o_nonblock() | O_CLOEXEC
    }

    fn opened(abi: Abi) -> Call {
        Call::OpenDevRandom {
            flags: open_flags(abi),
        }
    }

    fn count_reads(ops: &ScriptedOps) -> usize {
        ops.calls()
            .iter()
            .filter(|call| matches!(call, Call::Read { .. }))
            .count()
    }

    #[test]
    fn a_selected_legacy_provider_fills_exactly_the_buffer_through_open_read_close_on_both_abis() {
        for abi in [PPC, MIPS] {
            let mut ops = ScriptedOps::new()
                .open_random(7)
                .read(16, &sixteen())
                .close(0);
            let mut buf = [0u8; 16];
            assert_eq!(legacy_fill(&mut ops, abi, &mut buf), Ok(()), "{abi:?}");
            assert_eq!(buf.to_vec(), sixteen(), "{abi:?}");
            assert_eq!(
                ops.calls(),
                vec![
                    opened(abi),
                    Call::Read { fd: 7, cap: 16 },
                    Call::Close { fd: 7 }
                ],
                "{abi:?}: one open, one read of the whole request, one close, and nothing else"
            );
            assert_ne!(
                open_flags(abi) & abi.o_nonblock(),
                0,
                "{abi:?}: the device must be opened nonblocking, or a read could sleep"
            );
        }
        assert_eq!(open_flags(PPC), 0x800 | O_CLOEXEC);
        assert_eq!(open_flags(MIPS), 0x80 | O_CLOEXEC);
    }

    #[test]
    fn short_reads_are_the_devices_normal_answer_and_are_continued_from_where_they_stopped() {
        let all = sixteen();
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(5, &all[..5])
            .read(7, &all[5..12])
            .read(4, &all[12..])
            .close(0);
        let mut buf = [0u8; 16];
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), all);
        assert_eq!(
            ops.calls(),
            vec![
                opened(MIPS),
                Call::Read { fd: 5, cap: 16 },
                Call::Read { fd: 5, cap: 11 },
                Call::Read { fd: 5, cap: 4 },
                Call::Close { fd: 5 },
            ]
        );
    }

    #[test]
    fn an_empty_pool_is_waiting_with_every_byte_zeroed_and_the_device_closed_once() {
        let mut ops = ScriptedOps::new().open_random(5).read(-11, &[]).close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::NotSeeded)
        );
        assert_eq!(buf, [0u8; 16], "no stale or partial bytes may remain");
        // One read: no retry spin, no `getrandom`, no `/dev/urandom` (the seam cannot open it), no second source.
        assert_eq!(
            ops.calls(),
            vec![
                opened(MIPS),
                Call::Read { fd: 5, cap: 16 },
                Call::Close { fd: 5 }
            ]
        );
    }

    #[test]
    fn bytes_received_before_a_failure_never_survive_it() {
        for (errno, expected) in [
            (-11isize, EntropyError::NotSeeded),
            (-5, EntropyError::Failed(5)),
            (-14, EntropyError::Failed(14)),
            (-22, EntropyError::Invalid),
        ] {
            let mut ops = ScriptedOps::new()
                .open_random(5)
                .read(8, &[1, 2, 3, 4, 5, 6, 7, 8])
                .read(errno, &[])
                .close(0);
            let mut buf = [0xAAu8; 16];
            assert_eq!(
                legacy_fill(&mut ops, PPC, &mut buf),
                Err(expected),
                "errno {errno}"
            );
            assert_eq!(
                buf, [0u8; 16],
                "errno {errno}: the eight good bytes must not survive"
            );
            assert_eq!(
                ops.calls().last(),
                Some(&Call::Close { fd: 5 }),
                "errno {errno}: the device is still closed"
            );
        }
    }

    #[test]
    fn an_interrupted_read_is_repeated_a_bounded_number_of_times_and_then_reported() {
        let mut ops = ScriptedOps::new().open_random(5);
        for _ in 0..20 {
            ops = ops.read(-4, &[]);
        }
        ops = ops.close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::Interrupted)
        );
        assert_eq!(count_reads(&ops), MAX_INTERRUPTED_ATTEMPTS as usize);
        assert_eq!(ops.pending_read(), 20 - MAX_INTERRUPTED_ATTEMPTS as usize);
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(ops.calls().last(), Some(&Call::Close { fd: 5 }));

        // Interrupted twice, then served: an ordinary signal costs nothing.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(-4, &[])
            .read(-4, &[])
            .read(16, &sixteen())
            .close(0);
        let mut buf = [0u8; 16];
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), sixteen());
    }

    #[test]
    fn an_interrupted_open_is_repeated_a_bounded_number_of_times_and_no_read_or_close_follows() {
        let mut ops = ScriptedOps::new();
        for _ in 0..20 {
            ops = ops.open_random(-4);
        }
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::Interrupted)
        );
        assert_eq!(ops.calls().len(), MAX_INTERRUPTED_ATTEMPTS as usize);
        assert!(
            ops.calls().iter().all(|call| *call == opened(MIPS)),
            "only opens: there is no descriptor to read or close"
        );
        assert_eq!(ops.pending_open(), 20 - MAX_INTERRUPTED_ATTEMPTS as usize);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn a_read_that_reports_more_than_was_asked_or_nothing_is_an_error_and_the_device_is_still_closed()
     {
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(17, &sixteen())
            .close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::OverLong {
                requested: 16,
                returned: 17
            })
        );
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(ops.calls().last(), Some(&Call::Close { fd: 5 }));

        // Over-long on a later read is measured against what was still wanted, not against the whole request.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(8, &[1, 2, 3, 4, 5, 6, 7, 8])
            .read(9, &[9u8; 9])
            .close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::OverLong {
                requested: 8,
                returned: 9
            })
        );
        assert_eq!(buf, [0u8; 16]);

        let mut ops = ScriptedOps::new().open_random(5).read(0, &[]).close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::NoProgress)
        );
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(count_reads(&ops), 1, "a zero read is not retried");
    }

    #[test]
    fn a_request_over_the_per_call_limit_is_refused_before_any_kernel_call_and_the_limit_itself_is_served()
     {
        assert_eq!(LEGACY_MAX_REQUEST_BYTES, 64);
        let mut ops = ScriptedOps::new();
        let mut buf = [0xAAu8; LEGACY_MAX_REQUEST_BYTES + 1];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::RequestTooLarge {
                requested: LEGACY_MAX_REQUEST_BYTES + 1,
                max: LEGACY_MAX_REQUEST_BYTES
            })
        );
        assert!(
            buf.iter().all(|byte| *byte == 0),
            "the whole buffer is zeroed"
        );
        assert!(ops.calls().is_empty(), "no open: the pool is not drained");

        let all: Vec<u8> = (1..=64u8).collect();
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &all[..16])
            .read(16, &all[16..32])
            .read(16, &all[32..48])
            .read(16, &all[48..])
            .close(0);
        let mut buf = [0u8; LEGACY_MAX_REQUEST_BYTES];
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), all);
    }

    #[test]
    fn a_device_that_trickles_a_byte_at_a_time_ends_in_the_read_budget_not_a_loop() {
        assert_eq!(LEGACY_MAX_READS, 16);
        let bytes: Vec<u8> = (1..=32u8).collect();
        let trickle = |reads: usize| {
            let mut ops = ScriptedOps::new().open_random(5);
            for index in 0..reads {
                ops = ops.read(1, &bytes[index..=index]);
            }
            ops.close(0)
        };
        let mut ops = trickle(LEGACY_MAX_READS);
        let mut buf = [0xAAu8; 32];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::ReadBudget {
                reads: LEGACY_MAX_READS
            })
        );
        assert_eq!(count_reads(&ops), LEGACY_MAX_READS);
        assert_eq!(buf, [0u8; 32]);
        assert_eq!(ops.calls().last(), Some(&Call::Close { fd: 5 }));

        // The boundary: sixteen bytes in sixteen one-byte reads is exactly what the budget allows, and it is served.
        let mut ops = trickle(16);
        let mut buf = [0u8; 16];
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), bytes[..16].to_vec());
    }

    #[test]
    fn a_missing_device_is_reported_as_such_and_no_other_file_is_tried() {
        for errno in [-2isize, -6, -19] {
            let mut ops = ScriptedOps::new().open_random(errno);
            let mut buf = [0xAAu8; 16];
            assert_eq!(
                legacy_fill(&mut ops, MIPS, &mut buf),
                Err(EntropyError::DeviceAbsent),
                "errno {errno}"
            );
            assert_eq!(buf, [0u8; 16]);
            assert_eq!(
                ops.calls(),
                vec![opened(MIPS)],
                "errno {errno}: one open, no read, no close (there is no descriptor), no other source"
            );
        }
    }

    #[test]
    fn other_open_failures_keep_their_number_and_are_never_read_as_waiting_or_as_getrandom_absence()
    {
        for (abi, raw, expected) in [
            (PPC, -13isize, EntropyError::Failed(13)),
            (MIPS, -24, EntropyError::Failed(24)),
            (PPC, -38, EntropyError::Failed(38)),
            (MIPS, -89, EntropyError::Failed(89)),
            (PPC, -11, EntropyError::Failed(11)),
            (MIPS, -22, EntropyError::Invalid),
            (PPC, -5000, EntropyError::Malformed(-5000)),
        ] {
            let mut ops = ScriptedOps::new().open_random(raw);
            let mut buf = [0xAAu8; 16];
            assert_eq!(
                legacy_fill(&mut ops, abi, &mut buf),
                Err(expected),
                "{abi:?} {raw}"
            );
            assert_eq!(buf, [0u8; 16]);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn a_descriptor_that_does_not_fit_an_int_is_malformed_and_never_used() {
        let mut ops = ScriptedOps::new().open_random(isize::MAX);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::Malformed(isize::MAX))
        );
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(
            ops.calls(),
            vec![opened(PPC)],
            "no read or close with a truncated number"
        );
    }

    #[test]
    fn a_return_that_is_not_an_errno_from_a_read_is_malformed_and_the_device_is_closed() {
        let mut ops = ScriptedOps::new().open_random(5).read(-5000, &[]).close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::Malformed(-5000))
        );
        assert_eq!(ops.calls().last(), Some(&Call::Close { fd: 5 }));
    }

    #[test]
    fn closing_is_part_of_the_call_a_failed_close_discards_the_bytes_and_an_eintr_close_does_not() {
        // A close that fails after good bytes: the descriptor could not be released, so the bytes are not handed out.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &sixteen())
            .close(-9);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::Failed(9))
        );
        assert_eq!(buf, [0u8; 16]);

        // `close` answering EINTR has already released the descriptor on Linux: one attempt, and the bytes are kept.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &sixteen())
            .close(-4);
        let mut buf = [0u8; 16];
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), sixteen());
        let closes = ops
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .count();
        assert_eq!(closes, 1, "close is issued once, never retried");

        // A positive close result is not a kernel answer.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &sixteen())
            .close(3);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::Malformed(3))
        );
        assert_eq!(buf, [0u8; 16]);

        // The first failure is the one reported: a read error is not replaced by a close error.
        let mut ops = ScriptedOps::new().open_random(5).read(-5, &[]).close(-9);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::Failed(5))
        );
    }

    #[test]
    fn a_success_that_produced_one_repeated_byte_is_degenerate_for_the_legacy_provider_too() {
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &[0u8; 16])
            .close(0);
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut buf),
            Err(EntropyError::Degenerate)
        );
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn a_zero_length_request_is_an_error_for_the_legacy_provider_and_makes_no_call() {
        let mut ops = ScriptedOps::new();
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut []),
            Err(EntropyError::ZeroLength)
        );
        assert!(ops.calls().is_empty());
    }

    #[test]
    fn a_getrandom_failure_never_selects_the_legacy_provider() {
        // Nothing is scripted for `open`, `read` or `close`: a silent switch to /dev/random would panic on the unscripted call, and
        // the call log would show it.
        for (abi, raw) in [
            (PPC, -11isize),
            (PPC, -22),
            (PPC, -38),
            (MIPS, -11),
            (MIPS, -22),
            (MIPS, -89),
        ] {
            let mut ops = ScriptedOps::new().random(raw, &[]);
            let mut buf = [0xAAu8; 16];
            assert!(fill(&mut ops, abi, &mut buf).is_err(), "{abi:?} {raw}");
            assert_eq!(
                ops.calls(),
                vec![Call::GetRandom {
                    len: 16,
                    flags: GRND_NONBLOCK
                }],
                "{abi:?} {raw}: exactly one getrandom, nothing else"
            );
            assert_eq!(buf, [0u8; 16]);
        }
    }

    #[test]
    fn a_legacy_failure_never_falls_back_to_getrandom() {
        // Nothing is scripted for `getrandom`: a silent fallback would panic on the unscripted call.
        for raw in [-11isize, -4, -5, -22, 0] {
            let mut ops = ScriptedOps::new().open_random(5);
            for _ in 0..MAX_INTERRUPTED_ATTEMPTS {
                ops = ops.read(raw, &[]);
            }
            ops = ops.close(0);
            let mut buf = [0xAAu8; 16];
            assert!(legacy_fill(&mut ops, MIPS, &mut buf).is_err(), "{raw}");
            assert!(
                !ops.calls()
                    .iter()
                    .any(|call| matches!(call, Call::GetRandom { .. })),
                "{raw}: the legacy provider asked getrandom"
            );
            assert_eq!(buf, [0u8; 16]);
        }
    }

    #[test]
    fn nothing_is_cached_between_calls_a_seeded_answer_is_asked_again() {
        // Bytes now, waiting next: the second call does not assume the first call's pool is still seeded.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(16, &sixteen())
            .close(0)
            .open_random(6)
            .read(-11, &[])
            .close(0);
        let mut first = [0u8; 16];
        let mut second = [0xAAu8; 16];
        assert_eq!(legacy_fill(&mut ops, PPC, &mut first), Ok(()));
        assert_eq!(
            legacy_fill(&mut ops, PPC, &mut second),
            Err(EntropyError::NotSeeded)
        );
        assert_eq!(second, [0u8; 16]);
        assert_eq!(
            ops.calls(),
            vec![
                opened(PPC),
                Call::Read { fd: 5, cap: 16 },
                Call::Close { fd: 5 },
                opened(PPC),
                Call::Read { fd: 6, cap: 16 },
                Call::Close { fd: 6 },
            ],
            "each call opens and closes its own descriptor"
        );
        // Waiting now, bytes next: a pool that was empty is asked again, not remembered as empty.
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(-11, &[])
            .close(0)
            .open_random(6)
            .read(16, &sixteen())
            .close(0);
        let mut buf = [0u8; 16];
        assert_eq!(
            legacy_fill(&mut ops, MIPS, &mut buf),
            Err(EntropyError::NotSeeded)
        );
        assert_eq!(legacy_fill(&mut ops, MIPS, &mut buf), Ok(()));
        assert_eq!(buf.to_vec(), sixteen());
    }

    #[test]
    fn the_profile_decides_availability_and_only_getrandom_reads_the_matrix() {
        use CapabilityStatus::{
            AbsentFallbackAdmitted, MissingRequired, ObservedUnseeded, Supported,
            UnqualifiedPendingStockGuest,
        };
        let seeded = EntropyAvailability::ObservedSeeded;
        let waiting = EntropyAvailability::ObservedUnseededAtBoot;
        let unavailable = EntropyAvailability::Unavailable {
            status: MissingRequired,
        };
        let unqualified = EntropyAvailability::Unavailable {
            status: UnqualifiedPendingStockGuest,
        };
        // `Getrandom` passes the matrix's answer through, whatever it is.
        for matrix_says in [seeded, waiting, unavailable] {
            assert_eq!(
                EntropyProfile::Getrandom.availability(matrix_says),
                matrix_says
            );
        }
        // The legacy profile ignores the matrix's `getrandom` answer in both directions.
        for matrix_says in [seeded, waiting, unavailable] {
            assert_eq!(
                EntropyProfile::LegacyDevRandom(ProviderQualification::Observed(Supported))
                    .availability(matrix_says),
                seeded
            );
            assert_eq!(
                EntropyProfile::LegacyDevRandom(ProviderQualification::Observed(ObservedUnseeded))
                    .availability(matrix_says),
                waiting
            );
            assert_eq!(
                EntropyProfile::LegacyDevRandom(ProviderQualification::Unqualified)
                    .availability(matrix_says),
                unqualified
            );
            assert_eq!(
                EntropyProfile::LegacyDevRandom(ProviderQualification::TestEnvironment)
                    .availability(matrix_says),
                EntropyAvailability::AttemptableUnobserved
            );
        }
        for status in [
            MissingRequired,
            AbsentFallbackAdmitted,
            UnqualifiedPendingStockGuest,
        ] {
            assert_eq!(
                EntropyProfile::LegacyDevRandom(ProviderQualification::Observed(status))
                    .availability(seeded),
                EntropyAvailability::Unavailable { status },
                "{status:?}"
            );
        }
        assert!(EntropyAvailability::AttemptableUnobserved.may_attempt());
        assert!(!unqualified.may_attempt());
        assert_eq!(
            EntropyProfile::Getrandom.provider(),
            EntropyProvider::Getrandom
        );
        assert_eq!(
            EntropyProfile::LegacyDevRandom(ProviderQualification::Unqualified).provider(),
            LEGACY
        );
        assert_eq!(EntropyProvider::Getrandom.name(), "getrandom");
        assert_eq!(LEGACY.name(), "legacy_dev_random");
    }

    #[test]
    fn no_error_and_no_call_record_can_carry_the_bytes_a_call_received() {
        // Bytes that cannot be mistaken for a count or a file descriptor: 201 to 216.
        let secret: Vec<u8> = (201..=216u8).collect();
        let mut ops = ScriptedOps::new()
            .open_random(5)
            .read(8, &secret[..8])
            .read(-11, &[])
            .close(0);
        let mut buf = [0u8; 16];
        let error = legacy_fill(&mut ops, MIPS, &mut buf).expect_err("waiting after eight bytes");
        let shown = format!("{error:?} | {error} | {:?}", ops.calls());
        for byte in &secret {
            assert!(
                !shown.contains(&byte.to_string()),
                "{byte} appears in {shown}"
            );
        }
        assert_eq!(buf, [0u8; 16]);
    }
}
