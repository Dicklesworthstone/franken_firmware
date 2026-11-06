//! Legacy platform capability matrix, 64-bit shared cells (from `franken-atomic`), and memory budget ledger
//! (`E03` / `ffw-q2p`, `P02` / `ffw-jub`, `P05` / `ffw-ipz`, `P06` / `ffw-2nw`).

#![forbid(unsafe_code)]

pub mod abi;
pub mod clock;
pub mod durable;
pub mod entropy;
pub mod layer;
pub mod net;
pub mod ops;
pub mod socket;
pub mod wake;
pub mod wall_clock;

// Test doubles. Compiled for tests and under the `sim` feature only; a device image is built without it.
#[cfg(any(test, feature = "sim"))]
pub mod sim;

use crate::entropy::EntropyAvailability;
use franken_board_profile::{BoardProfile, CpuIsa};
use serde::{Deserialize, Serialize};

pub use core::sync::atomic::{
    AtomicBool, AtomicI8, AtomicI16, AtomicI32, AtomicIsize, AtomicPtr, AtomicU8, AtomicU16,
    AtomicU32, AtomicUsize, Ordering, compiler_fence, fence,
};

// 64-bit shared state. `core`'s `AtomicU64`/`AtomicI64` do not exist on the big-endian MIPS32 and PPC32 targets, and a
// cfg-selected alias would give the host and the device different APIs (an `Ordering` argument, a silently wrapping
// `fetch_add`), so code would compile on the host that the device build rejects. These are the same types on every
// target: typed overflow, no `Ordering`, linearizable per cell, and not for a render deadline (docs/contracts/p05.md).
pub use franken_atomic::{
    ArithError, Contended, Exhausted, LocalU64, Sequence, SharedI64, SharedU64,
};

/// Returns `true` when the compilation target provides hardware lock-free 64-bit atomics.
#[must_use]
pub const fn has_native_64bit_atomics() -> bool {
    cfg!(target_has_atomic = "64")
}

/// Whether a guest's reported kernel release is the release a profile names.
///
/// Equal, or `observed` extends `nominal` at a release boundary (`.`, `-`, `+`, `_`): `2.6.14` matches
/// `2.6.14.7` and `2.6.14-sonos`, but not `2.6.145`, `2.6.1` or `4.9.0-0.bpo.6-powerpc`. An empty
/// release never matches. The host classifier (`tests/e03/abi.py::kernel_matches`) applies the same rule.
#[must_use]
pub fn guest_kernel_matches(nominal: &str, observed: &str) -> bool {
    if nominal.is_empty() || observed.is_empty() {
        return false;
    }
    observed == nominal
        || (observed.starts_with(nominal)
            && matches!(
                observed.as_bytes().get(nominal.len()),
                Some(b'.' | b'-' | b'+' | b'_')
            ))
}

/// Classification of how a kernel ABI capability was probed or qualified.
///
/// Every status is a statement about the profile's own kernel and holds only for a guest that matches it
/// (see [`guest_kernel_matches`]); `check_admission` refuses any profile without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Observed working in a full-system guest whose kernel matches the profile.
    Supported,
    /// Observed absent (an exact `-ENOSYS` in the guest's own ABI numbering) in a guest whose kernel
    /// matches the profile, with a declared fallback admitted.
    AbsentFallbackAdmitted,
    /// Observed in a matching guest: the call exists and answered `-EAGAIN` because the kernel's entropy pool was
    /// not seeded at PID-1 boot (E03's `GETRANDOM` `UNSEEDED`). It is not `Supported` (no entropy was obtained) and
    /// not an absence. Meaningful for `getrandom_syscall` only; any other field holding it fails `check_admission`.
    ObservedUnseeded,
    /// Required capability is missing or broken; blocks runtime admission.
    MissingRequired,
    /// Only CPU user-mode or unverified guest evidence exists; not yet qualified for stock kernel.
    UnqualifiedPendingStockGuest,
}

/// Per-target legacy kernel ABI capability matrix (`E03` / `P02`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCapabilityMatrix {
    pub profile_id: String,
    pub target_triple: String,
    /// The kernel release the profile is about (for example the stock `2.6.14.7`).
    pub nominal_kernel_version: String,
    /// The kernel release of the full-system guest every status below was observed on; `None` when no
    /// guest was exercised. It must match `nominal_kernel_version` or admission is refused.
    pub guest_kernel_observed: Option<String>,
    pub static_elf_startup: CapabilityStatus,
    pub clock_monotonic: CapabilityStatus,
    pub clock_monotonic_res_ns: u64,
    pub nonblocking_pipe_io: CapabilityStatus,
    pub poll_syscall: CapabilityStatus,
    pub epoll_syscall: CapabilityStatus,
    pub udp_socket_io: CapabilityStatus,
    /// `/dev/urandom` opens and reads: **liveness only**. The E03 guests' pools were unseeded or past their first
    /// stage at PID-1 boot, so those bytes are not secure entropy, and nothing in this crate reads this field as a
    /// secure-entropy claim. Secure entropy is `getrandom_syscall`.
    pub urandom_entropy: CapabilityStatus,
    /// `getrandom(GRND_NONBLOCK)`: `Supported` when it returned bytes (`PASS`), [`CapabilityStatus::ObservedUnseeded`]
    /// when it answered `-EAGAIN` (`UNSEEDED`). No fallback is admitted for entropy, so
    /// [`CapabilityStatus::AbsentFallbackAdmitted`] here means "unavailable". See [`crate::entropy`].
    pub getrandom_syscall: CapabilityStatus,
    pub atomics_32bit: CapabilityStatus,
    pub atomics_64bit_fallback: CapabilityStatus,
    pub eventfd_syscall: CapabilityStatus,
}

impl KernelCapabilityMatrix {
    /// What this profile says about secure entropy: the `getrandom_syscall` observation and nothing else.
    ///
    /// `urandom_entropy` is deliberately not consulted. A `/dev/urandom` read succeeds on a guest whose pool is not
    /// seeded (E03 run `1412ac47`: the MIPS kernel logged `uninitialized urandom read` while that read passed), so
    /// treating it as entropy availability would be the insecure fallback `P02` forbids. Like every status here this
    /// holds only for a matching guest; [`Self::check_admission`] is what refuses a profile without one.
    #[must_use]
    pub const fn secure_entropy(&self) -> EntropyAvailability {
        EntropyAvailability::from_status(self.getrandom_syscall)
    }

    /// Verify whether all mandatory capabilities for the single-threaded reactor + DSP loop are present.
    ///
    /// Refuses with [`PlatformAdmissionError::NoMatchingGuest`] before looking at any capability status
    /// unless `guest_kernel_observed` matches `nominal_kernel_version`: a status observed on a different
    /// kernel (a Debian 4.x harness guest for a 2.6.x profile) is not evidence about this one, so
    /// compatibility stays unqualified rather than inherited.
    pub fn check_admission(&self) -> Result<ReactorWakeMechanism, PlatformAdmissionError> {
        let guest_matches = self
            .guest_kernel_observed
            .as_deref()
            .is_some_and(|observed| guest_kernel_matches(&self.nominal_kernel_version, observed));
        if !guest_matches {
            return Err(PlatformAdmissionError::NoMatchingGuest {
                nominal_kernel_version: self.nominal_kernel_version.clone(),
                guest_kernel_observed: self.guest_kernel_observed.clone(),
            });
        }
        let required = [
            ("static_elf_startup", self.static_elf_startup),
            ("clock_monotonic", self.clock_monotonic),
            ("nonblocking_pipe_io", self.nonblocking_pipe_io),
            ("udp_socket_io", self.udp_socket_io),
            ("urandom_entropy", self.urandom_entropy),
            ("atomics_32bit", self.atomics_32bit),
            ("atomics_64bit_fallback", self.atomics_64bit_fallback),
        ];
        for (name, status) in required {
            if status != CapabilityStatus::Supported {
                return Err(PlatformAdmissionError::MissingRequiredCapability {
                    capability: name.to_string(),
                    observed: status,
                });
            }
        }
        if self.clock_monotonic_res_ns == 0 || self.clock_monotonic_res_ns > 10_000_000 {
            return Err(PlatformAdmissionError::CoarseMonotonicClock {
                resolution_ns: self.clock_monotonic_res_ns,
            });
        }
        // Reactor readiness mux: accept epoll or poll
        if self.epoll_syscall != CapabilityStatus::Supported
            && self.poll_syscall != CapabilityStatus::Supported
        {
            return Err(PlatformAdmissionError::MissingRequiredCapability {
                capability: "poll_or_epoll".to_string(),
                observed: self.poll_syscall,
            });
        }
        // Wakeup mechanism: eventfd when observed supported, the self-pipe when observed absent.
        match self.eventfd_syscall {
            CapabilityStatus::Supported => Ok(ReactorWakeMechanism::EventFd),
            CapabilityStatus::AbsentFallbackAdmitted => Ok(ReactorWakeMechanism::SelfPipe),
            other => Err(PlatformAdmissionError::MissingRequiredCapability {
                capability: "eventfd_or_self_pipe".to_string(),
                observed: other,
            }),
        }
    }
}

/// Admitted reactor wakeup mechanism on legacy Linux kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactorWakeMechanism {
    EventFd,
    SelfPipe,
}

/// Memory budget ledger enforcing the `>= 4 MiB` free safety floor (`E01` / `Q02`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBudgetLedger {
    pub nominal_ram_bytes: u64,
    pub kernel_and_driver_reserved_bytes: u64,
    pub dma_ring_reserved_bytes: u64,
    pub core_runtime_peak_bytes: u64,
    pub stream_and_jitter_bytes: u64,
    pub native_integrations_bytes: u64,
    pub required_safety_floor_bytes: u64,
}

impl MemoryBudgetLedger {
    pub const MIN_SAFETY_FLOOR_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

    #[must_use]
    pub fn for_board(profile: &BoardProfile) -> Self {
        let nominal_ram_bytes = u64::from(profile.nominal_ram_mib) * 1024 * 1024;
        Self {
            nominal_ram_bytes,
            kernel_and_driver_reserved_bytes: 14 * 1024 * 1024,
            dma_ring_reserved_bytes: 512 * 1024,
            core_runtime_peak_bytes: 3 * 1024 * 1024,
            stream_and_jitter_bytes: 2 * 1024 * 1024,
            native_integrations_bytes: 4 * 1024 * 1024,
            required_safety_floor_bytes: Self::MIN_SAFETY_FLOOR_BYTES,
        }
    }

    #[must_use]
    pub const fn total_committed_bytes(&self) -> u64 {
        let committed = self.committed_wide();
        if committed > u64::MAX as u128 {
            u64::MAX
        } else {
            committed as u64
        }
    }

    const fn committed_wide(&self) -> u128 {
        self.kernel_and_driver_reserved_bytes as u128
            + self.dma_ring_reserved_bytes as u128
            + self.core_runtime_peak_bytes as u128
            + self.stream_and_jitter_bytes as u128
            + self.native_integrations_bytes as u128
    }

    /// Signed headroom, clamped only after computing the exact difference. The
    /// deserializable fields can exceed `i64::MAX`; clamping each operand first
    /// would lose small deficits between large values and hide overcommitment.
    #[must_use]
    pub const fn remaining_headroom_bytes(&self) -> i64 {
        // Five u64 commitments fit in u128 and i128 without overflow.
        let difference = self.nominal_ram_bytes as i128 - self.committed_wide() as i128;
        if difference > i64::MAX as i128 {
            i64::MAX
        } else if difference < i64::MIN as i128 {
            i64::MIN
        } else {
            difference as i64
        }
    }

    pub fn verify_budget(&self) -> Result<u64, PlatformAdmissionError> {
        let floor = self
            .required_safety_floor_bytes
            .max(Self::MIN_SAFETY_FLOOR_BYTES);
        let committed = self.total_committed_bytes();
        // Subtract before comparing: saturating the addition can admit an
        // overflowing commitment+floor when nominal itself is u64::MAX.
        let Some(headroom) = self.nominal_ram_bytes.checked_sub(committed) else {
            return Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: self.nominal_ram_bytes,
                committed_bytes: committed,
                required_floor_bytes: floor,
            });
        };
        if headroom < floor {
            return Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: self.nominal_ram_bytes,
                committed_bytes: committed,
                required_floor_bytes: floor,
            });
        }
        Ok(headroom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PlatformAdmissionError {
    #[error(
        "no matching full-system guest: profile kernel `{nominal_kernel_version}`, observed {guest_kernel_observed:?}; compatibility is unqualified"
    )]
    NoMatchingGuest {
        nominal_kernel_version: String,
        guest_kernel_observed: Option<String>,
    },
    #[error("missing or unqualified kernel capability `{capability}`: {observed:?}")]
    MissingRequiredCapability {
        capability: String,
        observed: CapabilityStatus,
    },
    #[error("monotonic clock resolution {resolution_ns} ns exceeds 10 ms maximum")]
    CoarseMonotonicClock { resolution_ns: u64 },
    #[error(
        "memory budget exceeded: committed {committed_bytes} + floor {required_floor_bytes} > nominal {nominal_ram_bytes}"
    )]
    MemoryBudgetExceeded {
        nominal_ram_bytes: u64,
        committed_bytes: u64,
        required_floor_bytes: u64,
    },
    #[error("unsupported CPU ISA {0:?}")]
    UnsupportedIsa(CpuIsa),
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture: the canonical catalog holds non-admissible hypotheses.
    use franken_board_profile::synthetic_test_fixture_catalog as canonical_board_catalog;

    #[test]
    fn shared_u64_is_the_same_semantic_cell_on_every_target() {
        // The sequence the removed `portable_atomic` test asserted, unchanged, now under the explicit wrapping name:
        // six consecutive values, unique across the wrap, then a compare-exchange that compares all 64 bits.
        let cell = SharedU64::new(u64::MAX - 3);
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(cell.fetch_add_wrapping(1));
        }
        assert_eq!(
            seen,
            vec![u64::MAX - 3, u64::MAX - 2, u64::MAX - 1, u64::MAX, 0, 1]
        );
        assert_eq!(
            cell.compare_exchange(2, 0xDEAD_BEEF_CAFE_BABE),
            Ok(2),
            "compare-exchange compares all 64 bits"
        );
        assert_eq!(cell.load(), 0xDEAD_BEEF_CAFE_BABE);

        // What the plain add does instead of wrapping, and what the `core` atomic it replaces never did: it refuses
        // with a typed error and leaves the value alone, so an identifier or a timestamp cannot wrap unseen.
        let cell = SharedU64::new(u64::MAX - 1);
        assert_eq!(cell.fetch_add(1), Ok(u64::MAX - 1));
        assert_eq!(cell.load(), u64::MAX);
        assert_eq!(
            cell.fetch_add(1),
            Err(ArithError::Overflow {
                current: u64::MAX,
                delta: 1
            })
        );
        assert_eq!(cell.load(), u64::MAX, "a refused add changes nothing");
    }

    #[test]
    fn shared_u64_crossing_the_32_bit_boundary_is_never_seen_torn() {
        // A writer adds one 512 times across 2^32 while this thread reads. A read may be any value the counter
        // really held, so the reads never go backwards and never fall below the start.
        let start = 0xFFFF_FF00u64;
        let cell = SharedU64::new(start);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                for _ in 0..512 {
                    cell.fetch_add(1).expect("no overflow near 2^32");
                }
            });
            let mut previous = start;
            // `is_finished` is also true if the writer panicked, so a failure ends the loop instead of hanging it.
            while !writer.is_finished() {
                let seen = cell.load();
                assert!(
                    seen >= previous,
                    "a read went backwards: {seen:#x} after {previous:#x}"
                );
                previous = seen;
            }
        });
        assert_eq!(cell.load(), start + 512);
        assert!(
            cell.load() > 0xFFFF_FFFF,
            "the run crossed the 32-bit boundary"
        );
    }

    /// PLANTED DEFECT, test only: a "64-bit counter" made of two independent 32-bit atomics updated without a lock.
    struct SplitCounter {
        hi: AtomicU32,
        lo: AtomicU32,
    }

    impl SplitCounter {
        fn new(value: u64) -> Self {
            Self {
                hi: AtomicU32::new((value >> 32) as u32),
                lo: AtomicU32::new(value as u32),
            }
        }

        /// First half of an add: the low word. Returns whether it carried out of the word.
        fn add_low(&self, delta: u32) -> bool {
            let old = self.lo.fetch_add(delta, Ordering::SeqCst);
            old.checked_add(delta).is_none()
        }

        /// Second half: the carry into the high word.
        fn add_high(&self, carry: bool) {
            self.hi.fetch_add(u32::from(carry), Ordering::SeqCst);
        }

        fn read(&self) -> u64 {
            (u64::from(self.hi.load(Ordering::SeqCst)) << 32)
                | u64::from(self.lo.load(Ordering::SeqCst))
        }
    }

    /// The property a shared 64-bit counter must keep: a read is the value before an operation or the value after
    /// it, never a mixture.
    fn is_before_or_after(seen: u64, before: u64, after: u64) -> bool {
        seen == before || seen == after
    }

    #[test]
    fn planted_split_counter_fails_the_check_a_shared_cell_passes() {
        let before = 0xFFFF_FFFFu64;
        let after = 0x1_0000_0000u64;

        // The split counter, with a read between its two steps: the low word has wrapped, the carry is not yet in.
        let split = SplitCounter::new(before);
        let carry = split.add_low(1);
        let torn = split.read();
        split.add_high(carry);
        assert_eq!(
            split.read(),
            after,
            "the split counter ends correct; only the read in between is wrong"
        );
        assert_eq!(
            torn, 0,
            "the torn read is 0, a value the counter never held"
        );
        assert!(
            !is_before_or_after(torn, before, after),
            "the check must reject the split counter"
        );

        // The same add on the shared cell has no step in between, so the same check holds.
        let shared = SharedU64::new(before);
        assert!(is_before_or_after(shared.load(), before, after));
        assert_eq!(shared.fetch_add(1), Ok(before));
        assert!(is_before_or_after(shared.load(), before, after));
    }

    #[test]
    fn planted_truncating_counter_fails_the_check_a_shared_cell_passes() {
        // A counter that keeps only the low 32 bits, as `as u32` would.
        let stored = 0x1_0000_0001u64;
        let truncating = AtomicU32::new(0);
        truncating.store(stored as u32, Ordering::SeqCst);
        let loaded = u64::from(truncating.load(Ordering::SeqCst));
        assert_eq!(loaded, 1);
        assert!(
            !is_before_or_after(loaded, 0, stored),
            "the check must reject the truncating counter"
        );

        let shared = SharedU64::new(0);
        shared.store(stored);
        assert!(is_before_or_after(shared.load(), 0, stored));
        assert_eq!(shared.load(), stored);
    }

    const HARNESS_PPC_KERNEL: &str = "4.9.0-0.bpo.6-powerpc";
    const STOCK_PPC_KERNEL: &str = "2.6.14.7";

    /// Gate-logic fixture: every capability reads `Supported`, so only the guest-kernel rule can object.
    /// It describes no real kernel; the statuses are inputs, not observations.
    fn all_supported_matrix(nominal: &str, observed: Option<&str>) -> KernelCapabilityMatrix {
        KernelCapabilityMatrix {
            profile_id: "gate-logic-fixture".to_string(),
            target_triple: "powerpc-unknown-linux-musl".to_string(),
            nominal_kernel_version: nominal.to_string(),
            guest_kernel_observed: observed.map(str::to_string),
            static_elf_startup: CapabilityStatus::Supported,
            clock_monotonic: CapabilityStatus::Supported,
            clock_monotonic_res_ns: 1,
            nonblocking_pipe_io: CapabilityStatus::Supported,
            poll_syscall: CapabilityStatus::Supported,
            epoll_syscall: CapabilityStatus::Supported,
            udp_socket_io: CapabilityStatus::Supported,
            urandom_entropy: CapabilityStatus::Supported,
            getrandom_syscall: CapabilityStatus::Supported,
            atomics_32bit: CapabilityStatus::Supported,
            atomics_64bit_fallback: CapabilityStatus::Supported,
            eventfd_syscall: CapabilityStatus::Supported,
        }
    }

    #[test]
    fn secure_entropy_follows_getrandom_alone_and_never_the_urandom_liveness_status() {
        let mut matrix = all_supported_matrix(HARNESS_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        assert_eq!(matrix.secure_entropy(), EntropyAvailability::ObservedSeeded);

        // The MIPS harness guest: /dev/urandom reads fine, getrandom answered EAGAIN. Entropy must follow getrandom.
        matrix.getrandom_syscall = CapabilityStatus::ObservedUnseeded;
        assert_eq!(matrix.urandom_entropy, CapabilityStatus::Supported);
        assert_eq!(
            matrix.secure_entropy(),
            EntropyAvailability::ObservedUnseededAtBoot
        );

        // And the reverse: getrandom broken makes entropy unavailable even though /dev/urandom still reads fine,
        // while admission (whose required set this field does not join) still passes. Entropy availability is its
        // own fact; it is not folded into the gate and not inferred from urandom.
        matrix.getrandom_syscall = CapabilityStatus::MissingRequired;
        assert_eq!(
            matrix.secure_entropy(),
            EntropyAvailability::Unavailable {
                status: CapabilityStatus::MissingRequired
            }
        );
        assert_eq!(matrix.urandom_entropy, CapabilityStatus::Supported);
        assert!(
            matrix.check_admission().is_ok(),
            "the gate's required set is unchanged by this field"
        );
    }

    #[test]
    fn an_unseeded_status_is_not_a_pass_for_any_capability_the_gate_requires() {
        let mut matrix = all_supported_matrix(HARNESS_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        matrix.udp_socket_io = CapabilityStatus::ObservedUnseeded;
        assert_eq!(
            matrix.check_admission(),
            Err(PlatformAdmissionError::MissingRequiredCapability {
                capability: "udp_socket_io".to_string(),
                observed: CapabilityStatus::ObservedUnseeded,
            })
        );
        let mut matrix = all_supported_matrix(HARNESS_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        matrix.eventfd_syscall = CapabilityStatus::ObservedUnseeded;
        assert!(matches!(
            matrix.check_admission(),
            Err(PlatformAdmissionError::MissingRequiredCapability { .. })
        ));
    }

    #[test]
    fn matching_guest_admits_eventfd_or_self_pipe_by_the_observed_eventfd_status() {
        let mut matrix = all_supported_matrix(HARNESS_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        assert_eq!(matrix.check_admission(), Ok(ReactorWakeMechanism::EventFd));

        matrix.eventfd_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        assert_eq!(matrix.check_admission(), Ok(ReactorWakeMechanism::SelfPipe));

        // An eventfd that was never qualified is neither of the two: the gate does not pick one.
        matrix.eventfd_syscall = CapabilityStatus::UnqualifiedPendingStockGuest;
        assert_eq!(
            matrix.check_admission(),
            Err(PlatformAdmissionError::MissingRequiredCapability {
                capability: "eventfd_or_self_pipe".to_string(),
                observed: CapabilityStatus::UnqualifiedPendingStockGuest,
            })
        );

        // The mandatory-capability checks still run for a matching guest.
        let mut broken = all_supported_matrix(HARNESS_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        broken.urandom_entropy = CapabilityStatus::MissingRequired;
        assert_eq!(
            broken.check_admission(),
            Err(PlatformAdmissionError::MissingRequiredCapability {
                capability: "urandom_entropy".to_string(),
                observed: CapabilityStatus::MissingRequired,
            })
        );
    }

    #[test]
    fn stock_profile_is_refused_when_the_observed_guest_is_a_different_kernel() {
        // Every capability says `Supported`, as they would if a 4.9 harness result were copied onto the
        // 2.6.14 profile. That is the claim this gate must not honor.
        let matrix = all_supported_matrix(STOCK_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        assert_eq!(
            matrix.check_admission(),
            Err(PlatformAdmissionError::NoMatchingGuest {
                nominal_kernel_version: STOCK_PPC_KERNEL.to_string(),
                guest_kernel_observed: Some(HARNESS_PPC_KERNEL.to_string()),
            })
        );

        // Neither does an eventfd fallback or any other status rescue it.
        let mut absent = matrix;
        absent.eventfd_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        assert!(matches!(
            absent.check_admission(),
            Err(PlatformAdmissionError::NoMatchingGuest { .. })
        ));
    }

    #[test]
    fn stock_profile_without_any_observed_guest_is_unqualified() {
        let matrix = all_supported_matrix(STOCK_PPC_KERNEL, None);
        assert_eq!(
            matrix.check_admission(),
            Err(PlatformAdmissionError::NoMatchingGuest {
                nominal_kernel_version: STOCK_PPC_KERNEL.to_string(),
                guest_kernel_observed: None,
            })
        );
    }

    #[test]
    fn the_gate_admits_only_on_matching_evidence_and_the_two_cases_stay_distinct() {
        // Gate logic only: no 2.6.14 guest exists, so this builds the *evidence class* a future matching
        // guest would have and shows the gate then admits, while the non-matching class above is refused.
        let matching = all_supported_matrix(STOCK_PPC_KERNEL, Some("2.6.14.7-fixture"));
        assert_eq!(
            matching.check_admission(),
            Ok(ReactorWakeMechanism::EventFd)
        );
        let non_matching = all_supported_matrix(STOCK_PPC_KERNEL, Some(HARNESS_PPC_KERNEL));
        assert_ne!(matching.check_admission(), non_matching.check_admission());
    }

    #[test]
    fn guest_kernel_match_is_a_release_boundary_not_a_string_prefix() {
        for (nominal, observed) in [
            ("2.6.14.7", "2.6.14.7"),
            ("2.6.14", "2.6.14.7"),
            ("2.6.14", "2.6.14-sonos"),
            ("2.6.14", "2.6.14+local"),
            ("2.6.14", "2.6.14_x"),
            (HARNESS_PPC_KERNEL, HARNESS_PPC_KERNEL),
        ] {
            assert!(
                guest_kernel_matches(nominal, observed),
                "{nominal} vs {observed}"
            );
        }
        for (nominal, observed) in [
            ("2.6.14", "2.6.145"),
            ("2.6.14", "2.6.14x"),
            ("2.6.14", "2.6.1"),
            ("2.6.14.7", "2.6.14"),
            ("2.6.14", HARNESS_PPC_KERNEL),
            ("", "2.6.14"),
            ("2.6.14", ""),
            ("", ""),
        ] {
            assert!(
                !guest_kernel_matches(nominal, observed),
                "{nominal} vs {observed}"
            );
        }
    }

    #[test]
    fn memory_budget_enforces_4mib_safety_floor_across_audio_boards() {
        let catalog = canonical_board_catalog();
        for board in catalog.iter().filter(|b| b.hardware_channels > 0) {
            let ledger = MemoryBudgetLedger::for_board(board);
            let headroom = ledger
                .verify_budget()
                .expect("64/128 MiB audio boards fit with >=4 MiB floor");
            assert!(headroom >= MemoryBudgetLedger::MIN_SAFETY_FLOOR_BYTES);
        }

        let br100 = catalog.iter().find(|b| b.model_number == "BR100").unwrap();
        let mut tight = MemoryBudgetLedger::for_board(br100);
        tight.native_integrations_bytes = 12 * 1024 * 1024;
        assert!(matches!(
            tight.verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded { .. })
        ));
    }

    // ---- the memory budget is P02's one typed memory refusal: its edge, its numbers and its arithmetic (docs/contracts/p02.md,
    // "Memory budget and allocation failure") ----

    const MIB: u64 = 1024 * 1024;
    const FLOOR: u64 = MemoryBudgetLedger::MIN_SAFETY_FLOOR_BYTES;

    /// A ledger whose whole commitment is `committed` bytes (all of it in the kernel reservation) against `nominal` bytes of RAM.
    fn ledger(nominal: u64, committed: u64, floor: u64) -> MemoryBudgetLedger {
        MemoryBudgetLedger {
            nominal_ram_bytes: nominal,
            kernel_and_driver_reserved_bytes: committed,
            dma_ring_reserved_bytes: 0,
            core_runtime_peak_bytes: 0,
            stream_and_jitter_bytes: 0,
            native_integrations_bytes: 0,
            required_safety_floor_bytes: floor,
        }
    }

    #[test]
    fn the_budget_edge_is_inclusive_and_the_refusal_carries_the_numbers_it_was_decided_on() {
        let committed = 20 * MIB;
        // Exactly the commitments plus the floor: admitted, and the headroom is the floor.
        assert_eq!(
            ledger(committed + FLOOR, committed, FLOOR).verify_budget(),
            Ok(FLOOR)
        );
        // One byte less: refused, with the three numbers the decision used, in the right fields and in the message.
        let nominal = committed + FLOOR - 1;
        let refused = ledger(nominal, committed, FLOOR).verify_budget();
        assert_eq!(
            refused,
            Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: nominal,
                committed_bytes: committed,
                required_floor_bytes: FLOOR,
            })
        );
        assert_eq!(
            refused.map_err(|error| error.to_string()),
            Err(format!(
                "memory budget exceeded: committed {committed} + floor {FLOOR} > nominal {nominal}"
            ))
        );
    }

    #[test]
    fn a_ledger_cannot_ask_for_a_floor_below_four_mib() {
        let committed = 20 * MIB;
        for asked in [0, 1, FLOOR - 1] {
            // Each of these would fit if the asked floor were believed: committed + asked <= nominal < committed + FLOOR.
            let nominal = committed + FLOOR - 1;
            assert_eq!(
                ledger(nominal, committed, asked).verify_budget(),
                Err(PlatformAdmissionError::MemoryBudgetExceeded {
                    nominal_ram_bytes: nominal,
                    committed_bytes: committed,
                    required_floor_bytes: FLOOR,
                }),
                "asked floor {asked}"
            );
            assert_eq!(
                ledger(nominal + 1, committed, asked).verify_budget(),
                Ok(FLOOR),
                "asked floor {asked}"
            );
        }
    }

    #[test]
    fn a_ledger_that_asks_for_a_higher_floor_is_held_to_it() {
        let committed = 20 * MIB;
        let asked = 8 * MIB;
        // Room for the default floor and not for the asked one.
        let nominal = committed + asked - 1;
        assert_eq!(
            ledger(nominal, committed, FLOOR).verify_budget(),
            Ok(asked - 1)
        );
        assert_eq!(
            ledger(nominal, committed, asked).verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: nominal,
                committed_bytes: committed,
                required_floor_bytes: asked,
            })
        );
        assert_eq!(
            ledger(nominal + 1, committed, asked).verify_budget(),
            Ok(asked)
        );
    }

    #[test]
    fn commitments_that_overflow_saturate_into_a_refusal_and_never_into_an_admission() {
        // Wrapping arithmetic turns u64::MAX + 5 MiB into 5 MiB - 1, which fits in 64 MiB.
        let mut huge = ledger(64 * MIB, u64::MAX, FLOOR);
        huge.dma_ring_reserved_bytes = 5 * MIB;
        assert_eq!(huge.total_committed_bytes(), u64::MAX);
        assert_eq!(
            huge.verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: 64 * MIB,
                committed_bytes: u64::MAX,
                required_floor_bytes: FLOOR,
            })
        );
        // The floor term saturates too: a floor that makes the sum overflow is a refusal (wrapped, 1 + u64::MAX would be 0).
        assert!(matches!(
            ledger(64 * MIB, 1, u64::MAX).verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded {
                required_floor_bytes: u64::MAX,
                ..
            })
        ));
    }

    #[test]
    fn a_headroom_that_does_not_fit_an_i64_saturates_instead_of_wrapping_or_overflowing() {
        // Commitments that saturate at u64::MAX against 64 MiB: hugely over-committed, so hugely negative. Through `as i64` the
        // commitment read as -1 and the headroom as 64 MiB + 1.
        let mut huge = ledger(64 * MIB, u64::MAX, FLOOR);
        huge.dma_ring_reserved_bytes = 5 * MIB;
        assert_eq!(huge.remaining_headroom_bytes(), i64::MIN);
        // One field above i64::MAX (reachable: the fields are public and deserializable) overflowed the subtraction.
        let big = ledger(64 * MIB, (1_u64 << 63) + 5, FLOOR);
        assert!(big.remaining_headroom_bytes() < 0);
        // A nominal size above i64::MAX with nothing committed saturates at the top.
        assert_eq!(
            ledger(u64::MAX, 0, FLOOR).remaining_headroom_bytes(),
            i64::MAX
        );
    }

    #[test]
    fn extreme_nominal_ram_does_not_hide_overflow_or_a_small_deficit() {
        let over = ledger(u64::MAX, u64::MAX, FLOOR);
        assert!(matches!(
            over.verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded { .. })
        ));
        let mut excess = ledger(u64::MAX, u64::MAX, FLOOR);
        excess.dma_ring_reserved_bytes = 1;
        assert_eq!(excess.remaining_headroom_bytes(), -1);
        assert!(excess.verify_budget().is_err());
        assert_eq!(
            ledger(u64::MAX, u64::MAX - 1, FLOOR).remaining_headroom_bytes(),
            1
        );
        assert_eq!(
            ledger(u64::MAX - 1, u64::MAX, FLOOR).remaining_headroom_bytes(),
            -1
        );
        let edge = ledger(u64::MAX, u64::MAX - FLOOR, FLOOR);
        assert_eq!(edge.verify_budget(), Ok(FLOOR));
        assert_eq!(edge.remaining_headroom_bytes(), FLOOR as i64);
    }

    #[test]
    fn a_nominal_size_below_the_commitments_is_a_refusal_and_a_negative_headroom() {
        let under = ledger(10 * MIB, 14 * MIB, FLOOR);
        assert_eq!(
            under.verify_budget(),
            Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: 10 * MIB,
                committed_bytes: 14 * MIB,
                required_floor_bytes: FLOOR,
            })
        );
        assert_eq!(
            under.remaining_headroom_bytes(),
            -4 * i64::try_from(MIB).expect("fits")
        );
        // At the edge the two views agree: the admitted headroom is the unsigned remainder, and the signed one is the same number.
        let edge = ledger(14 * MIB + FLOOR, 14 * MIB, FLOOR);
        assert_eq!(
            edge.verify_budget()
                .map(|bytes| i64::try_from(bytes).expect("fits")),
            Ok(edge.remaining_headroom_bytes())
        );
    }
}
