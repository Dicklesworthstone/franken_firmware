//! The admitted platform layer: the one object that offers the clock, the reactor wakeup and the entropy source
//! (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! A [`PlatformLayer`] can only be built through [`PlatformLayer::admit`], and `admit` starts with
//! [`KernelCapabilityMatrix::check_admission`]: a profile with no matching full-system guest, or with a required
//! capability not observed, is refused **before any kernel call is made**. The ABI is read from the matrix's own
//! target triple, never passed separately, so the errno numbers cannot disagree with the profile.
//!
//! The layer composes policy that lives in [`crate::clock`], [`crate::entropy`] and [`crate::wake`]; it adds two
//! things of its own:
//! * a monotonic guard: a reading smaller than the previous one is [`ClockError::WentBackwards`] and does not
//!   replace it. `CLOCK_MONOTONIC` cannot go backwards, so a smaller value means the backend split or truncated a
//!   word, and believing it would corrupt every deadline computed from it.
//! * ownership of the wake descriptors: they are closed when the layer is dropped, or explicitly by
//!   [`PlatformLayer::close`], which reports a failure that `Drop` can only swallow.
//!
//! Sockets (`accept4`, datagram truncation) and the memory ledger are the next slice of `P02`; they are not here.

use crate::abi::Abi;
use crate::clock::{self, ClockError};
use crate::entropy::{self, EntropyAvailability, EntropyError, EntropyProfile, EntropyProvider};
use crate::ops::{KernelOps, Provenance};
use crate::wake::{Drained, WakeError, WakeOutcome, Waker};
use crate::{KernelCapabilityMatrix, PlatformAdmissionError};

/// Why a layer was not built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayerError {
    /// The E03 gate refused the profile (no matching guest, a required capability not observed, ...).
    #[error(transparent)]
    Admission(#[from] PlatformAdmissionError),
    /// The profile's target triple is not one of the two legacy big-endian ABIs.
    #[error("target triple `{triple}` is not a supported legacy ABI")]
    UnknownAbi { triple: String },
    /// A real backend was compiled for one legacy ABI and the profile names the other. The errno numbers and flag
    /// values the layer decodes with are the profile's; the numbers the backend issues are its own.
    #[error("the backend speaks {backend:?} but the profile is {profile:?}")]
    AbiMismatch { profile: Abi, backend: Abi },
    /// The admitted wake mechanism could not be opened. No other mechanism is tried.
    #[error("the admitted reactor wake source could not be opened: {0}")]
    Wake(WakeError),
}

/// An admitted platform: clock, wakeup and entropy over a kernel seam.
pub struct PlatformLayer<O: KernelOps> {
    ops: O,
    abi: Abi,
    /// Whether the **selected** provider may be tried (see [`Self::with_entropy_profile`]).
    entropy: EntropyAvailability,
    /// What the matrix says about `getrandom`, kept so a later explicit selection of that provider reads the same fact.
    getrandom_availability: EntropyAvailability,
    entropy_profile: EntropyProfile,
    clock_resolution_ns: u64,
    last_ns: Option<u64>,
    waker: Waker,
    closed: bool,
}

impl<O: KernelOps> PlatformLayer<O> {
    /// Admit `matrix` and open the wake source it selects.
    ///
    /// # Errors
    /// [`LayerError::Admission`] before any kernel call when the gate refuses; [`LayerError::UnknownAbi`] before any
    /// kernel call for a triple that is not a legacy ABI; [`LayerError::AbiMismatch`] before any kernel call when a
    /// real backend was compiled for the other ABI; [`LayerError::Wake`] when the admitted mechanism cannot be opened.
    pub fn admit(matrix: &KernelCapabilityMatrix, mut ops: O) -> Result<Self, LayerError> {
        let mechanism = matrix.check_admission()?;
        let abi = Abi::from_target_triple(&matrix.target_triple).ok_or_else(|| {
            LayerError::UnknownAbi {
                triple: matrix.target_triple.clone(),
            }
        })?;
        if let Some(backend) = ops.backend_abi()
            && backend != abi
        {
            return Err(LayerError::AbiMismatch {
                profile: abi,
                backend,
            });
        }
        let waker = Waker::open(&mut ops, abi, mechanism).map_err(LayerError::Wake)?;
        let getrandom_availability = matrix.secure_entropy();
        Ok(Self {
            ops,
            abi,
            entropy: getrandom_availability,
            getrandom_availability,
            entropy_profile: EntropyProfile::Getrandom,
            clock_resolution_ns: matrix.clock_monotonic_res_ns,
            last_ns: None,
            waker,
            closed: false,
        })
    }

    /// The ABI the layer decodes kernel returns with.
    #[must_use]
    pub const fn abi(&self) -> Abi {
        self.abi
    }

    /// Where the answers come from: [`Provenance::Kernel`], or a test double's [`Provenance::Simulated`]. Anything a
    /// caller records about what this layer produced should carry it.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        self.ops.provenance()
    }

    /// The kernel seam, for inspection.
    #[must_use]
    pub const fn ops(&self) -> &O {
        &self.ops
    }

    /// The monotonic resolution the matrix recorded for this guest (an observation, not a measurement here).
    #[must_use]
    pub const fn clock_resolution_ns(&self) -> u64 {
        self.clock_resolution_ns
    }

    /// What the profile says about secure entropy from the **selected** provider (see [`Self::entropy_provider`]).
    #[must_use]
    pub const fn entropy_availability(&self) -> EntropyAvailability {
        self.entropy
    }

    /// Select the entropy provider **explicitly**. The default, set by [`Self::admit`], is [`EntropyProfile::Getrandom`]; this is the
    /// only way to select another, it makes no kernel call, and nothing selects a provider as a consequence of a failure (a `getrandom`
    /// that answers `EAGAIN`, `EINVAL` or `ENOSYS` leaves the selection as it was). `Getrandom` reads the matrix's `getrandom_syscall`
    /// exactly as before; `LegacyDevRandom` carries its own qualification (see [`entropy::ProviderQualification`]) and is refused
    /// without a kernel call when it is [`entropy::ProviderQualification::Unqualified`].
    #[must_use]
    pub fn with_entropy_profile(mut self, profile: EntropyProfile) -> Self {
        self.entropy = profile.availability(self.getrandom_availability);
        self.entropy_profile = profile;
        self
    }

    /// The provider [`Self::fill_random`] uses: whichever was selected explicitly, `Getrandom` if none was.
    #[must_use]
    pub const fn entropy_provider(&self) -> EntropyProvider {
        self.entropy_profile.provider()
    }

    /// The descriptor a reactor polls for readability.
    #[must_use]
    pub const fn wake_fd(&self) -> i32 {
        self.waker.read_fd()
    }

    /// One monotonic reading, never smaller than the previous one.
    ///
    /// # Errors
    /// See [`ClockError`]. A reading smaller than the previous one is [`ClockError::WentBackwards`] and is not
    /// recorded.
    pub fn now_ns(&mut self) -> Result<u64, ClockError> {
        let now = clock::now_ns(&mut self.ops, self.abi)?;
        if let Some(last) = self.last_ns
            && now < last
        {
            return Err(ClockError::WentBackwards {
                last_ns: last,
                now_ns: now,
            });
        }
        self.last_ns = Some(now);
        Ok(now)
    }

    /// Fill `buf` with kernel entropy from the **selected** provider, or fail and leave it zeroed. Makes no kernel call when the profile
    /// says secure entropy is unavailable for that provider.
    ///
    /// # Errors
    /// [`EntropyError::Unavailable`] without a kernel call; otherwise see [`EntropyError`]. An unseeded pool is
    /// [`EntropyError::NotSeeded`] on every call until the kernel says otherwise: nothing is cached or substituted, and no other provider
    /// is tried.
    pub fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if let EntropyAvailability::Unavailable { status } = self.entropy {
            buf.fill(0);
            return Err(EntropyError::Unavailable { status });
        }
        entropy::fill_with(
            &mut self.ops,
            self.abi,
            self.entropy_profile.provider(),
            buf,
        )
    }

    /// Ask the reactor to wake.
    ///
    /// # Errors
    /// See [`crate::wake::Waker::signal`].
    pub fn signal_wake(&mut self) -> Result<WakeOutcome, WakeError> {
        self.waker.signal(&mut self.ops, self.abi)
    }

    /// Consume pending wakes.
    ///
    /// # Errors
    /// See [`crate::wake::Waker::drain`].
    pub fn drain_wake(&mut self) -> Result<Drained, WakeError> {
        self.waker.drain(&mut self.ops, self.abi)
    }

    /// Close the wake descriptors and report a failure. Dropping the layer closes them too but can only ignore a
    /// failure.
    ///
    /// # Errors
    /// The first close failure, after every descriptor was closed.
    pub fn close(mut self) -> Result<(), WakeError> {
        self.closed = true;
        self.waker.close(&mut self.ops, self.abi)
    }
}

impl<O: KernelOps> Drop for PlatformLayer<O> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.waker.close(&mut self.ops, self.abi);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ProviderQualification;
    use crate::sim::{Call, ScriptedOps};
    use crate::wake::WakeCall;
    use crate::{CapabilityStatus, ReactorWakeMechanism};
    use std::cell::RefCell;
    use std::rc::Rc;

    const HARNESS_PPC: &str = "4.9.0-0.bpo.6-powerpc";
    const STOCK_PPC: &str = "2.6.14.7";

    /// A gate-logic fixture: every capability reads `Supported`, so only the rule under test can object. It
    /// describes no real kernel; its statuses are inputs, not observations.
    fn matrix(triple: &str, nominal: &str, observed: Option<&str>) -> KernelCapabilityMatrix {
        KernelCapabilityMatrix {
            profile_id: "layer-gate-fixture".to_string(),
            target_triple: triple.to_string(),
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

    fn ppc_matrix() -> KernelCapabilityMatrix {
        matrix("powerpc-unknown-linux-musl", HARNESS_PPC, Some(HARNESS_PPC))
    }

    #[test]
    fn a_matching_guest_with_eventfd_opens_exactly_an_eventfd() {
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        assert_eq!(layer.abi(), Abi::PowerPc32);
        assert_eq!(layer.wake_fd(), 7);
        assert_eq!(layer.clock_resolution_ns(), 1);
        assert_eq!(
            *log.borrow(),
            vec![Call::Eventfd2 {
                initval: 0,
                flags: 0x800 | crate::abi::O_CLOEXEC
            }]
        );
    }

    #[test]
    fn eventfd_observed_absent_with_the_fallback_admitted_opens_a_self_pipe_and_only_that() {
        let mut m = matrix(
            "mips-unknown-linux-musl",
            "4.19.0-21-4kc-malta",
            Some("4.19.0-21-4kc-malta"),
        );
        m.eventfd_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        let ops = ScriptedOps::new().pipe(0, [5, 6]);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&m, ops).expect("admitted");
        assert_eq!(layer.abi(), Abi::Mips32);
        assert_eq!(layer.wake_fd(), 5);
        assert_eq!(
            *log.borrow(),
            vec![Call::Pipe2 {
                flags: 0x80 | crate::abi::O_CLOEXEC
            }]
        );
    }

    #[test]
    fn a_profile_with_no_matching_guest_is_refused_before_any_kernel_call() {
        // The stock profile with a result from the 4.9 harness guest copied onto it: the claim the gate must refuse.
        let m = matrix("powerpc-unknown-linux-musl", STOCK_PPC, Some(HARNESS_PPC));
        let ops = ScriptedOps::new();
        let log = ops.log_handle();
        let Err(refused) = PlatformLayer::admit(&m, ops) else {
            panic!("a profile with no matching guest was admitted");
        };
        assert!(matches!(
            refused,
            LayerError::Admission(PlatformAdmissionError::NoMatchingGuest { .. })
        ));
        assert!(
            log.borrow().is_empty(),
            "a refused profile touched the kernel: {:?}",
            log.borrow()
        );

        let none = matrix("powerpc-unknown-linux-musl", STOCK_PPC, None);
        assert!(matches!(
            PlatformLayer::admit(&none, ScriptedOps::new()).err(),
            Some(LayerError::Admission(
                PlatformAdmissionError::NoMatchingGuest { .. }
            ))
        ));
    }

    #[test]
    fn a_required_capability_that_was_not_observed_is_refused_before_any_kernel_call() {
        let mut m = ppc_matrix();
        m.udp_socket_io = CapabilityStatus::UnqualifiedPendingStockGuest;
        let ops = ScriptedOps::new();
        let log = ops.log_handle();
        assert!(matches!(
            PlatformLayer::admit(&m, ops).err(),
            Some(LayerError::Admission(
                PlatformAdmissionError::MissingRequiredCapability { .. }
            ))
        ));
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn a_backend_compiled_for_the_other_abi_is_refused_before_any_kernel_call() {
        for (triple, profile, backend) in [
            ("powerpc-unknown-linux-musl", Abi::PowerPc32, Abi::Mips32),
            ("mips-unknown-linux-musl", Abi::Mips32, Abi::PowerPc32),
        ] {
            let m = matrix(triple, HARNESS_PPC, Some(HARNESS_PPC));
            let ops = ScriptedOps::new().compiled_for(backend);
            let log = ops.log_handle();
            assert_eq!(
                PlatformLayer::admit(&m, ops).err(),
                Some(LayerError::AbiMismatch { profile, backend }),
                "{triple}"
            );
            assert!(
                log.borrow().is_empty(),
                "{triple}: a mismatched backend was called"
            );
        }
        // The same ABI is accepted, and a double that names none is accepted for either.
        let ops = ScriptedOps::new().compiled_for(Abi::PowerPc32).eventfd(7);
        assert!(PlatformLayer::admit(&ppc_matrix(), ops).is_ok());
        let ops = ScriptedOps::new().eventfd(7);
        assert!(PlatformLayer::admit(&ppc_matrix(), ops).is_ok());
    }

    #[test]
    fn a_double_reports_itself_as_simulated_through_the_layer() {
        let layer =
            PlatformLayer::admit(&ppc_matrix(), ScriptedOps::new().eventfd(7)).expect("admitted");
        assert_eq!(layer.provenance(), Provenance::Simulated);
        assert_ne!(layer.provenance(), Provenance::Kernel);
    }

    #[test]
    fn a_triple_that_is_not_a_legacy_abi_is_refused_before_any_kernel_call() {
        for triple in [
            "mipsel-unknown-linux-musl",
            "powerpc64-unknown-linux-musl",
            "aarch64-apple-darwin",
            "",
        ] {
            let m = matrix(triple, HARNESS_PPC, Some(HARNESS_PPC));
            let ops = ScriptedOps::new();
            let log = ops.log_handle();
            assert_eq!(
                PlatformLayer::admit(&m, ops).err(),
                Some(LayerError::UnknownAbi {
                    triple: triple.to_string()
                }),
                "{triple}"
            );
            assert!(log.borrow().is_empty(), "{triple}");
        }
    }

    #[test]
    fn an_admitted_wake_mechanism_that_cannot_be_opened_is_an_error_not_a_different_mechanism() {
        let ops = ScriptedOps::new().eventfd(-38);
        let log = ops.log_handle();
        assert_eq!(
            PlatformLayer::admit(&ppc_matrix(), ops).err(),
            Some(LayerError::Wake(WakeError::Absent {
                call: WakeCall::Eventfd2
            }))
        );
        assert_eq!(log.borrow().len(), 1, "no pipe2 after the failed eventfd2");
    }

    #[test]
    fn entropy_that_the_matrix_says_is_unavailable_is_refused_without_a_kernel_call_and_with_no_bytes()
     {
        for status in [
            CapabilityStatus::UnqualifiedPendingStockGuest,
            CapabilityStatus::MissingRequired,
            CapabilityStatus::AbsentFallbackAdmitted,
        ] {
            let mut m = ppc_matrix();
            m.getrandom_syscall = status;
            let ops = ScriptedOps::new().eventfd(7);
            let log = ops.log_handle();
            let mut layer = PlatformLayer::admit(&m, ops).expect("admitted");
            assert_eq!(
                layer.entropy_availability(),
                EntropyAvailability::Unavailable { status }
            );
            let mut buf = [0xAAu8; 16];
            assert_eq!(
                layer.fill_random(&mut buf),
                Err(EntropyError::Unavailable { status }),
                "{status:?}"
            );
            assert_eq!(buf, [0u8; 16]);
            assert!(
                !log.borrow()
                    .iter()
                    .any(|call| matches!(call, Call::GetRandom { .. })),
                "{status:?}: getrandom was called although the matrix says it is unavailable"
            );
        }
    }

    #[test]
    fn an_unseeded_pool_is_asked_again_every_time_and_never_remembered_or_papered_over() {
        let mut m = ppc_matrix();
        m.getrandom_syscall = CapabilityStatus::ObservedUnseeded;
        let seeded: Vec<u8> = (1..=16u8).collect();
        let ops = ScriptedOps::new()
            .eventfd(7)
            .random(-11, &[])
            .random(-11, &[])
            .random(16, &seeded);
        let mut layer = PlatformLayer::admit(&m, ops).expect("admitted");
        assert_eq!(
            layer.entropy_availability(),
            EntropyAvailability::ObservedUnseededAtBoot
        );
        let mut buf = [0u8; 16];
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(buf, [0u8; 16]);
        assert_eq!(layer.fill_random(&mut buf), Ok(()));
        assert_eq!(buf.to_vec(), seeded);
    }

    #[test]
    fn the_monotonic_reading_never_goes_backwards_and_a_bad_reading_is_not_recorded() {
        let ops = ScriptedOps::new()
            .eventfd(7)
            .clock(0, 10, 0)
            .clock(0, 9, 0)
            .clock(0, 11, 0)
            .clock(0, 11, 0);
        let mut layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        assert_eq!(layer.now_ns(), Ok(10_000_000_000));
        assert_eq!(
            layer.now_ns(),
            Err(ClockError::WentBackwards {
                last_ns: 10_000_000_000,
                now_ns: 9_000_000_000
            })
        );
        assert_eq!(
            layer.now_ns(),
            Ok(11_000_000_000),
            "the bad reading did not replace the last good one"
        );
        assert_eq!(
            layer.now_ns(),
            Ok(11_000_000_000),
            "an equal reading is not backwards"
        );
    }

    #[test]
    fn a_signal_then_a_drain_round_trips_through_the_layer() {
        let one = 1u64.to_ne_bytes();
        let ops = ScriptedOps::new().eventfd(7).write(8).read(8, &one);
        let mut layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        assert_eq!(layer.signal_wake(), Ok(WakeOutcome::Signalled));
        assert_eq!(
            layer.drain_wake(),
            Ok(Drained {
                wakes: 1,
                more_pending: false
            })
        );
        assert_eq!(layer.ops().pending_read(), 0);
    }

    #[test]
    fn dropping_the_layer_closes_what_it_opened_exactly_once() {
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        drop(PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted"));
        let closes: Vec<Call> = log
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .cloned()
            .collect();
        assert_eq!(closes, vec![Call::Close { fd: 7 }]);

        let mut mips = matrix(
            "mips-unknown-linux-musl",
            "4.19.0-21-4kc-malta",
            Some("4.19.0-21-4kc-malta"),
        );
        mips.eventfd_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        let ops = ScriptedOps::new().pipe(0, [5, 6]);
        let log = ops.log_handle();
        drop(PlatformLayer::admit(&mips, ops).expect("admitted"));
        let closes: Vec<Call> = log
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .cloned()
            .collect();
        assert_eq!(closes, vec![Call::Close { fd: 5 }, Call::Close { fd: 6 }]);
    }

    #[test]
    fn an_explicit_close_reports_a_failure_and_the_later_drop_does_not_close_again() {
        let mut mips = matrix(
            "mips-unknown-linux-musl",
            "4.19.0-21-4kc-malta",
            Some("4.19.0-21-4kc-malta"),
        );
        mips.eventfd_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        let ops = ScriptedOps::new().pipe(0, [5, 6]).close(-9).close(0);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&mips, ops).expect("admitted");
        assert_eq!(
            layer.close(),
            Err(WakeError::Sys {
                call: WakeCall::Close,
                error: crate::abi::SysError::Errno(9)
            })
        );
        let closes = log
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Close { .. }))
            .count();
        assert_eq!(
            closes, 2,
            "both descriptors closed once, and not again on drop"
        );
    }

    #[test]
    fn the_layer_reads_the_mechanism_from_the_gate_and_never_swaps_it() {
        // eventfd2 observed Supported selects the eventfd even though a self-pipe would also work.
        assert_eq!(
            ppc_matrix().check_admission(),
            Ok(ReactorWakeMechanism::EventFd)
        );
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let _layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        assert!(
            !log.borrow()
                .iter()
                .any(|call| matches!(call, Call::Pipe2 { .. }))
        );
    }

    // ---- the explicitly selected legacy entropy provider at layer level (root decision 5126) ----
    //
    // Scripted replies are inputs: what these tests show is which provider the LAYER routes to and when it refuses without a call.

    /// The calls made after admission (the wake source's own open is not what these tests are about).
    fn since_admission(log: &Rc<RefCell<Vec<Call>>>, admitted_with: usize) -> Vec<Call> {
        log.borrow()[admitted_with..].to_vec()
    }

    #[test]
    fn the_default_provider_is_getrandom_and_selecting_another_makes_no_kernel_call() {
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        assert_eq!(layer.entropy_provider(), EntropyProvider::Getrandom);
        let admitted_with = log.borrow().len();
        let layer = layer.with_entropy_profile(EntropyProfile::LegacyDevRandom(
            ProviderQualification::TestEnvironment,
        ));
        assert_eq!(layer.entropy_provider(), EntropyProvider::LegacyDevRandom);
        assert_eq!(
            layer.entropy_availability(),
            EntropyAvailability::AttemptableUnobserved
        );
        assert_eq!(
            log.borrow().len(),
            admitted_with,
            "selection is not a kernel call"
        );
        // And back: selecting `Getrandom` again reads the matrix's own answer for it.
        let layer = layer.with_entropy_profile(EntropyProfile::Getrandom);
        assert_eq!(layer.entropy_provider(), EntropyProvider::Getrandom);
        assert_eq!(
            layer.entropy_availability(),
            EntropyAvailability::ObservedSeeded
        );
    }

    #[test]
    fn an_unqualified_legacy_provider_is_refused_without_a_kernel_call_even_if_getrandom_would_work()
     {
        // The matrix says getrandom is Supported; the legacy profile has no observation. No downgrade, and no upgrade either.
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        let admitted_with = log.borrow().len();
        let mut layer = layer.with_entropy_profile(EntropyProfile::LegacyDevRandom(
            ProviderQualification::Unqualified,
        ));
        let status = CapabilityStatus::UnqualifiedPendingStockGuest;
        assert_eq!(
            layer.entropy_availability(),
            EntropyAvailability::Unavailable { status }
        );
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            layer.fill_random(&mut buf),
            Err(EntropyError::Unavailable { status })
        );
        assert_eq!(buf, [0u8; 16]);
        assert!(
            since_admission(&log, admitted_with).is_empty(),
            "neither /dev/random nor getrandom was called"
        );
    }

    #[test]
    fn a_getrandom_layer_that_is_unavailable_never_opens_the_legacy_device() {
        let mut m = ppc_matrix();
        m.getrandom_syscall = CapabilityStatus::AbsentFallbackAdmitted;
        let ops = ScriptedOps::new().eventfd(7);
        let log = ops.log_handle();
        let mut layer = PlatformLayer::admit(&m, ops).expect("admitted");
        let admitted_with = log.borrow().len();
        let mut buf = [0xAAu8; 16];
        assert_eq!(
            layer.fill_random(&mut buf),
            Err(EntropyError::Unavailable {
                status: CapabilityStatus::AbsentFallbackAdmitted
            })
        );
        assert!(
            since_admission(&log, admitted_with).is_empty(),
            "a missing getrandom must not turn into /dev/random"
        );
    }

    #[test]
    fn an_explicitly_selected_legacy_provider_fills_through_open_read_close_and_never_asks_getrandom()
     {
        // The matrix says getrandom is MISSING: that is a fact about the other provider and does not touch this one.
        let mut m = ppc_matrix();
        m.getrandom_syscall = CapabilityStatus::MissingRequired;
        let bytes: Vec<u8> = (1..=16u8).collect();
        let ops = ScriptedOps::new()
            .eventfd(7)
            .open_random(9)
            .read(16, &bytes)
            .close(0);
        let log = ops.log_handle();
        let layer = PlatformLayer::admit(&m, ops).expect("admitted");
        let admitted_with = log.borrow().len();
        let mut layer = layer.with_entropy_profile(EntropyProfile::LegacyDevRandom(
            ProviderQualification::TestEnvironment,
        ));
        let mut buf = [0u8; 16];
        assert_eq!(layer.fill_random(&mut buf), Ok(()));
        assert_eq!(buf.to_vec(), bytes);
        assert_eq!(
            since_admission(&log, admitted_with),
            vec![
                Call::OpenDevRandom {
                    flags: 0x800 | crate::abi::O_CLOEXEC
                },
                Call::Read { fd: 9, cap: 16 },
                Call::Close { fd: 9 },
            ]
        );
    }

    #[test]
    fn an_observed_unseeded_legacy_provider_reports_waiting_every_time_and_is_not_remembered() {
        let ops = ScriptedOps::new()
            .eventfd(7)
            .open_random(5)
            .read(-11, &[])
            .close(0)
            .open_random(6)
            .read(-11, &[])
            .close(0);
        let layer = PlatformLayer::admit(&ppc_matrix(), ops).expect("admitted");
        let mut layer = layer.with_entropy_profile(EntropyProfile::LegacyDevRandom(
            ProviderQualification::Observed(CapabilityStatus::ObservedUnseeded),
        ));
        assert_eq!(
            layer.entropy_availability(),
            EntropyAvailability::ObservedUnseededAtBoot
        );
        let mut buf = [0xAAu8; 16];
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(layer.fill_random(&mut buf), Err(EntropyError::NotSeeded));
        assert_eq!(buf, [0u8; 16]);
    }
}
