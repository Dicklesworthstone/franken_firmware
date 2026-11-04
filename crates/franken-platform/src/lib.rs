//! Legacy platform capability matrix, portable 64-bit atomics, and memory budget ledger
//! (`E03` / `ffw-q2p`, `P02` / `ffw-jub`, `P05` / `ffw-ipz`, `P06` / `ffw-2nw`).

#![forbid(unsafe_code)]

use franken_board_profile::{BoardProfile, CpuIsa};
use serde::{Deserialize, Serialize};

pub use core::sync::atomic::{
    AtomicBool, AtomicI8, AtomicI16, AtomicI32, AtomicIsize, AtomicPtr, AtomicU8, AtomicU16,
    AtomicU32, AtomicUsize, Ordering, compiler_fence, fence,
};

#[cfg(target_has_atomic = "64")]
pub use core::sync::atomic::{AtomicI64, AtomicU64};

#[cfg(not(target_has_atomic = "64"))]
pub use portable_atomic::{AtomicI64, AtomicU64};

/// Returns `true` when the compilation target provides hardware lock-free 64-bit atomics.
#[must_use]
pub const fn has_native_64bit_atomics() -> bool {
    cfg!(target_has_atomic = "64")
}

/// Classification of how a kernel ABI capability was probed or qualified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// Verified in a matching kernel or full-system guest.
    Supported,
    /// Verified absent on this kernel ABI (e.g. `epoll_create1` or `eventfd` on Linux 2.6.14).
    AbsentFallbackAdmitted,
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
    pub nominal_kernel_version: String,
    pub guest_kernel_observed: Option<String>,
    pub static_elf_startup: CapabilityStatus,
    pub clock_monotonic: CapabilityStatus,
    pub clock_monotonic_res_ns: u64,
    pub nonblocking_pipe_io: CapabilityStatus,
    pub poll_syscall: CapabilityStatus,
    pub epoll_syscall: CapabilityStatus,
    pub udp_socket_io: CapabilityStatus,
    pub urandom_entropy: CapabilityStatus,
    pub atomics_32bit: CapabilityStatus,
    pub atomics_64bit_fallback: CapabilityStatus,
    pub eventfd_syscall: CapabilityStatus,
}

impl KernelCapabilityMatrix {
    /// Verify whether all mandatory capabilities for the single-threaded reactor + DSP loop are present.
    pub fn check_admission(&self) -> Result<ReactorWakeMechanism, PlatformAdmissionError> {
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
        // Wakeup mechanism: use eventfd when supported, or self-pipe when absent on older 2.6.14 kernels
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
        self.kernel_and_driver_reserved_bytes
            .saturating_add(self.dma_ring_reserved_bytes)
            .saturating_add(self.core_runtime_peak_bytes)
            .saturating_add(self.stream_and_jitter_bytes)
            .saturating_add(self.native_integrations_bytes)
    }

    #[must_use]
    pub const fn remaining_headroom_bytes(&self) -> i64 {
        (self.nominal_ram_bytes as i64) - (self.total_committed_bytes() as i64)
    }

    pub fn verify_budget(&self) -> Result<u64, PlatformAdmissionError> {
        let floor = self
            .required_safety_floor_bytes
            .max(Self::MIN_SAFETY_FLOOR_BYTES);
        let committed = self.total_committed_bytes();
        if committed.saturating_add(floor) > self.nominal_ram_bytes {
            return Err(PlatformAdmissionError::MemoryBudgetExceeded {
                nominal_ram_bytes: self.nominal_ram_bytes,
                committed_bytes: committed,
                required_floor_bytes: floor,
            });
        }
        Ok(self.nominal_ram_bytes - committed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PlatformAdmissionError {
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
    use franken_board_profile::canonical_board_catalog;

    #[test]
    fn portable_atomic_u64_preserves_monotonic_uniqueness_and_cas_across_wrap() {
        let atom = AtomicU64::new(u64::MAX - 3);
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(atom.fetch_add(1, Ordering::SeqCst));
        }
        assert_eq!(
            seen,
            vec![u64::MAX - 3, u64::MAX - 2, u64::MAX - 1, u64::MAX, 0, 1]
        );
        assert_eq!(
            atom.compare_exchange(
                2,
                0xDEAD_BEEF_CAFE_BABE,
                Ordering::AcqRel,
                Ordering::Acquire
            ),
            Ok(2)
        );
        assert_eq!(atom.load(Ordering::Acquire), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn capability_matrix_admits_self_pipe_when_eventfd_absent_on_2_6_14() {
        let matrix = KernelCapabilityMatrix {
            profile_id: "sonos-s5-ppc-rev-1.16.3.1-2".to_string(),
            target_triple: "powerpc-unknown-linux-musl".to_string(),
            nominal_kernel_version: "2.6.14.7".to_string(),
            guest_kernel_observed: Some("4.9.0-0.bpo.6-powerpc".to_string()),
            static_elf_startup: CapabilityStatus::Supported,
            clock_monotonic: CapabilityStatus::Supported,
            clock_monotonic_res_ns: 1,
            nonblocking_pipe_io: CapabilityStatus::Supported,
            poll_syscall: CapabilityStatus::Supported,
            epoll_syscall: CapabilityStatus::Supported,
            udp_socket_io: CapabilityStatus::Supported,
            urandom_entropy: CapabilityStatus::Supported,
            atomics_32bit: CapabilityStatus::Supported,
            atomics_64bit_fallback: CapabilityStatus::Supported,
            eventfd_syscall: CapabilityStatus::AbsentFallbackAdmitted,
        };
        assert_eq!(matrix.check_admission(), Ok(ReactorWakeMechanism::SelfPipe));

        let mut broken = matrix;
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
}
