//! Kernel capability evidence for the guests E03 observed (`P02` / `ffw-jub`). GENERATED: do not edit.
//!
//! Regenerate with `scripts/p02/gen_guest_evidence.py --write`; `scripts/p02/gen_guest_evidence.py` (no flag) and
//! `tests/p02/test_guest_evidence.py` fail when this file differs from what the committed transcripts give. Every status below
//! comes from the E03 oracle (`tests/e03/abi.py`) classifying a committed full-system QEMU serial transcript of central run
//! `1412ac47120d4e5b865f9de6e05f50fe`; nothing is typed by hand. The generator refuses to emit evidence the oracle does not call matching-guest.
//!
//! These are the **only** kernels with evidence: two Debian harness kernels, one run each. They are not the stock kernels the
//! boards run (every stock cell in E03 stays unqualified), and a real board's kernel is the vendor's. A status here is what E03
//! observed on the guest whose release is `kernel_release`; it says nothing about another kernel. The speaker picks the matrix by
//! the backend's ABI, which the target fixes at compile time, and does **not** compare the running kernel's release to it:
//! `platform_start` records the release and lets the probes (each syscall's typed answer) decide.

use franken_platform::abi::Abi;
use franken_platform::{CapabilityStatus, KernelCapabilityMatrix};

/// What E03 observed on one full-system harness guest, and the identity of the transcript it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestEvidence {
    /// The oracle's profile name for the guest.
    pub profile_id: &'static str,
    pub abi: Abi,
    pub target_triple: &'static str,
    /// The kernel release the guest reported: what the observations were made on. Evidence about that guest, not a check on the running kernel.
    pub kernel_release: &'static str,
    /// The central run the transcript is committed under (`toolchain/results/runs/1412ac47120d4e5b865f9de6e05f50fe`).
    pub run_id: &'static str,
    /// SHA-256 of the committed serial transcript.
    pub transcript_sha256: &'static str,
    clock_monotonic_res_ns: u64,
    static_elf_startup: CapabilityStatus,
    clock_monotonic: CapabilityStatus,
    nonblocking_pipe_io: CapabilityStatus,
    poll_syscall: CapabilityStatus,
    epoll_syscall: CapabilityStatus,
    udp_socket_io: CapabilityStatus,
    urandom_entropy: CapabilityStatus,
    getrandom_syscall: CapabilityStatus,
    atomics_32bit: CapabilityStatus,
    atomics_64bit_fallback: CapabilityStatus,
    eventfd_syscall: CapabilityStatus,
}

impl GuestEvidence {
    /// The capability matrix this evidence supports: the profile is the guest's own kernel, and the guest observed is the same
    /// release, so `check_admission` accepts it. It is what the layer is admitted against; it is not compared to the running kernel.
    #[must_use]
    pub fn matrix(&self) -> KernelCapabilityMatrix {
        KernelCapabilityMatrix {
            profile_id: self.profile_id.to_string(),
            target_triple: self.target_triple.to_string(),
            nominal_kernel_version: self.kernel_release.to_string(),
            guest_kernel_observed: Some(self.kernel_release.to_string()),
            static_elf_startup: self.static_elf_startup,
            clock_monotonic: self.clock_monotonic,
            clock_monotonic_res_ns: self.clock_monotonic_res_ns,
            nonblocking_pipe_io: self.nonblocking_pipe_io,
            poll_syscall: self.poll_syscall,
            epoll_syscall: self.epoll_syscall,
            udp_socket_io: self.udp_socket_io,
            urandom_entropy: self.urandom_entropy,
            getrandom_syscall: self.getrandom_syscall,
            atomics_32bit: self.atomics_32bit,
            atomics_64bit_fallback: self.atomics_64bit_fallback,
            eventfd_syscall: self.eventfd_syscall,
        }
    }
}

/// The evidence for the guest of `abi`.
#[must_use]
pub fn for_abi(abi: Abi) -> &'static GuestEvidence {
    match abi {
        Abi::PowerPc32 => &HARNESS_PPC,
        Abi::Mips32 => &HARNESS_MIPS,
    }
}

/// Every guest with evidence.
pub static ALL: [&GuestEvidence; 2] = [&HARNESS_PPC, &HARNESS_MIPS];

/// `harness-ppc-4.9`: kernel `4.9.0-0.bpo.6-powerpc`, E03 verdict `green`.
pub static HARNESS_PPC: GuestEvidence = GuestEvidence {
    profile_id: "harness-ppc-4.9",
    abi: Abi::PowerPc32,
    target_triple: "powerpc-unknown-linux-musl",
    kernel_release: "4.9.0-0.bpo.6-powerpc",
    run_id: "1412ac47120d4e5b865f9de6e05f50fe",
    transcript_sha256: "c2176da63977e191f61491b634b80dc56f1d2bace2aa105c1df698c8601be638",
    clock_monotonic_res_ns: 1,
    static_elf_startup: CapabilityStatus::Supported,
    clock_monotonic: CapabilityStatus::Supported,
    nonblocking_pipe_io: CapabilityStatus::Supported,
    poll_syscall: CapabilityStatus::Supported,
    epoll_syscall: CapabilityStatus::Supported,
    udp_socket_io: CapabilityStatus::Supported,
    urandom_entropy: CapabilityStatus::Supported,
    getrandom_syscall: CapabilityStatus::Supported,
    atomics_32bit: CapabilityStatus::Supported,
    atomics_64bit_fallback: CapabilityStatus::Supported,
    eventfd_syscall: CapabilityStatus::Supported,
};

/// `harness-mips-4.19`: kernel `4.19.0-21-4kc-malta`, E03 verdict `degraded`.
pub static HARNESS_MIPS: GuestEvidence = GuestEvidence {
    profile_id: "harness-mips-4.19",
    abi: Abi::Mips32,
    target_triple: "mips-unknown-linux-musl",
    kernel_release: "4.19.0-21-4kc-malta",
    run_id: "1412ac47120d4e5b865f9de6e05f50fe",
    transcript_sha256: "da1bff4032bedee4dd5236a59d972cb4962ee745542e30cdffb8847f165938d8",
    clock_monotonic_res_ns: 1,
    static_elf_startup: CapabilityStatus::Supported,
    clock_monotonic: CapabilityStatus::Supported,
    nonblocking_pipe_io: CapabilityStatus::Supported,
    poll_syscall: CapabilityStatus::Supported,
    epoll_syscall: CapabilityStatus::Supported,
    udp_socket_io: CapabilityStatus::Supported,
    urandom_entropy: CapabilityStatus::Supported,
    getrandom_syscall: CapabilityStatus::ObservedUnseeded,
    atomics_32bit: CapabilityStatus::Supported,
    atomics_64bit_fallback: CapabilityStatus::Supported,
    eventfd_syscall: CapabilityStatus::Supported,
};
