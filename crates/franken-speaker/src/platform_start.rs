//! Platform bring-up for the device speaker (`P02` / `ffw-jub`). Contract: `docs/contracts/p02.md`.
//!
//! The device speaker takes its clock, reactor wakeup and entropy from `franken_platform`'s [`PlatformLayer`], built over a
//! kernel backend, and never from a seeded or simulated stand-in. [`bring_up`] is the **one** function that builds the layer, and
//! [`bring_up_device`] is the one place the Linux backend is constructed: every start of the device speaker, `--platform-startup`
//! included, goes through them (a source test pins that nothing else constructs a layer or the backend). Every way it can say no
//! is a typed [`StartupError`], and none has a fallback:
//!
//! 1. **The backend must be the kernel.** A backend that declares [`Provenance::Simulated`], or that names no ABI, is refused
//!    before any kernel call. A device build is wired to the Linux leaf; a build wired to a simulation is refused here.
//! 2. **The ABI picks the evidence, the probes decide.** The capability matrix is what E03 observed on the harness guests for the
//!    backend's ABI ([`crate::guest_evidence`]); the ABI is fixed at compile time by the target. The speaker does **not** refuse on
//!    the running kernel's release (a real board's kernel is the vendor's and never equals a harness kernel): the release is read
//!    and *recorded* in the `BEGIN` line, bounded and sanitised, and never compared. If a kernel lacks a call the probe says so
//!    and startup refuses with that call's typed code (for example `wake_open_failed` for a missing `eventfd2`).
//! 3. **The layer is admitted, then each capability is exercised once:** two monotonic readings, `getrandom(GRND_NONBLOCK)` for
//!    16 bytes, and one wake signalled and drained. An error is the refusal; nothing falls back. In particular an unseeded entropy
//!    pool is [`StartupError::Entropy`] (`not_seeded`), retryable by the caller, and **never** answered with a seeded or
//!    time-derived value.
//!
//! Every capability is reported on its own line whether or not an earlier one failed ([`StartupReport`]), with the provenance the
//! layer declared and `NOT_RUN` when it could not be tried (always after an earlier `REFUSED`), so a transcript carries the failure
//! and not-run counts. The marker lines are rendered in one function ([`StartupReport::markers`]) so the grammar the QEMU speaker
//! smoke judges has one home. The lines never contain a clock value or an entropy byte.

use crate::guest_evidence;
use franken_platform::ReactorWakeMechanism;
use franken_platform::abi::Abi;
use franken_platform::clock::ClockError;
use franken_platform::entropy::EntropyError;
use franken_platform::layer::{LayerError, PlatformLayer};
use franken_platform::ops::{KernelOps, Provenance};
use franken_platform::wake::{WakeError, WakeOutcome};

/// Where the running kernel's release is read from (recorded, never compared).
pub const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
/// Bytes of entropy requested at startup (and discarded: startup proves the capability, it keeps nothing).
pub const ENTROPY_PROBE_BYTES: usize = 16;
/// Longest `kernel=` value recorded; a longer release is recorded as [`INVALID_KERNEL`].
pub const MAX_KERNEL_FIELD_LEN: usize = 64;
/// What `kernel=` says when the release is unreadable, too long, or has bytes outside `[A-Za-z0-9._+-]`.
pub const INVALID_KERNEL: &str = "invalid";
/// Exit status when the platform started.
pub const EXIT_STARTED: u8 = 0;
/// Exit status when startup was refused with a typed [`StartupError`].
pub const EXIT_REFUSED: u8 = 3;

/// The closed set of `reason=` codes, per capability. The marker grammar test pins this against the committed examples.
pub const REASON_CODES: [(&str, &[&str]); 4] = [
    (
        "kernel",
        &[
            "simulated_backend",
            "no_abi",
            "not_admitted",
            "unknown_abi",
            "abi_mismatch",
            "wake_open_failed",
        ],
    ),
    (
        "clock",
        &[
            "absent",
            "interrupted",
            "failed",
            "malformed",
            "unexpected_return",
            "invalid_timespec",
            "overflow",
            "went_backwards",
        ],
    ),
    (
        "entropy",
        &[
            "zero_length",
            "unavailable",
            "not_seeded",
            "absent",
            "interrupted",
            "invalid",
            "no_progress",
            "over_long",
            "degenerate",
            "failed",
            "malformed",
        ],
    ),
    (
        "wake",
        &[
            "absent",
            "sys",
            "unexpected",
            "bad_descriptor",
            "short_write",
            "short_read",
            "zero_counter",
            "end_of_file",
            "not_observed",
            "not_signalled",
            "close_failed",
        ],
    ),
];

/// What startup checks. `Kernel` is "could the platform be brought up on this backend at all".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Kernel,
    Clock,
    Entropy,
    Wake,
}

impl Capability {
    /// The lowercase name used in `refused=<name>:<code>` and in [`REASON_CODES`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Clock => "clock",
            Self::Entropy => "entropy",
            Self::Wake => "wake",
        }
    }
}

/// Why the platform may not be used. Each variant is a typed startup refusal; none has a fallback.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupError {
    #[error(
        "the backend declares {provenance:?}; the device speaker admits only a kernel-backed platform"
    )]
    NotKernelBacked { provenance: Provenance },
    #[error("the backend names no ABI, so its numbers cannot be checked against a profile")]
    BackendNamesNoAbi,
    #[error("the platform was not brought up: {0}")]
    Admission(LayerError),
    #[error("clock: {0}")]
    Clock(ClockError),
    #[error("entropy: {0}")]
    Entropy(EntropyError),
    #[error("wake: {0}")]
    Wake(WakeError),
    #[error("the wake was signalled but {outcome:?} was reported instead of a delivery")]
    WakeNotSignalled { outcome: WakeOutcome },
    #[error(
        "the wake was signalled but a drain saw {wakes} wake(s) with more pending: {more_pending}"
    )]
    WakeNotObserved { wakes: u64, more_pending: bool },
}

/// Every refusal of the layer's admission belongs to the `KERNEL` line: the platform could not be brought up. That includes a wake
/// source the kernel cannot open (a missing `eventfd2`), which is a probe's answer, refused on its typed code.
const fn layer_code(error: &LayerError) -> &'static str {
    match error {
        LayerError::Admission(_) => "not_admitted",
        LayerError::UnknownAbi { .. } => "unknown_abi",
        LayerError::AbiMismatch { .. } => "abi_mismatch",
        LayerError::Wake(_) => "wake_open_failed",
    }
}

const fn clock_code(error: &ClockError) -> &'static str {
    match error {
        ClockError::Absent => "absent",
        ClockError::Interrupted => "interrupted",
        ClockError::Failed(_) => "failed",
        ClockError::Malformed(_) => "malformed",
        ClockError::UnexpectedReturn(_) => "unexpected_return",
        ClockError::InvalidTimespec { .. } => "invalid_timespec",
        ClockError::Overflow => "overflow",
        ClockError::WentBackwards { .. } => "went_backwards",
    }
}

const fn entropy_code(error: &EntropyError) -> &'static str {
    match error {
        EntropyError::ZeroLength => "zero_length",
        EntropyError::Unavailable { .. } => "unavailable",
        EntropyError::NotSeeded => "not_seeded",
        EntropyError::Absent => "absent",
        EntropyError::Interrupted => "interrupted",
        EntropyError::Invalid => "invalid",
        EntropyError::NoProgress => "no_progress",
        EntropyError::OverLong { .. } => "over_long",
        EntropyError::Degenerate => "degenerate",
        EntropyError::Failed(_) => "failed",
        EntropyError::Malformed(_) => "malformed",
    }
}

const fn wake_code(error: &WakeError) -> &'static str {
    match error {
        WakeError::Absent { .. } => "absent",
        WakeError::Sys { .. } => "sys",
        WakeError::Unexpected { .. } => "unexpected",
        WakeError::BadDescriptor { .. } => "bad_descriptor",
        WakeError::ShortWrite { .. } => "short_write",
        WakeError::ShortRead { .. } => "short_read",
        WakeError::ZeroCounter => "zero_counter",
        WakeError::EndOfFile => "end_of_file",
    }
}

impl StartupError {
    /// Which capability line this refusal belongs to.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        match self {
            Self::NotKernelBacked { .. } | Self::BackendNamesNoAbi | Self::Admission(_) => {
                Capability::Kernel
            }
            Self::Clock(_) => Capability::Clock,
            Self::Entropy(_) => Capability::Entropy,
            Self::Wake(_) | Self::WakeNotSignalled { .. } | Self::WakeNotObserved { .. } => {
                Capability::Wake
            }
        }
    }

    /// The stable `reason=` code (a member of [`REASON_CODES`] for [`Self::capability`]).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotKernelBacked { .. } => "simulated_backend",
            Self::BackendNamesNoAbi => "no_abi",
            Self::Admission(error) => layer_code(error),
            Self::Clock(error) => clock_code(error),
            Self::Entropy(error) => entropy_code(error),
            Self::Wake(error) => wake_code(error),
            Self::WakeNotSignalled { .. } => "not_signalled",
            Self::WakeNotObserved { .. } => "not_observed",
        }
    }

    /// Whether trying again later can succeed: only an entropy pool that is not seeded yet. The caller decides how long to wait;
    /// startup itself never waits and never substitutes.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Entropy(EntropyError::NotSeeded))
    }
}

/// How one capability fared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Refused(&'static str),
    NotRun,
}

impl Outcome {
    const fn status(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Refused(_) => "REFUSED",
            Self::NotRun => "NOT_RUN",
        }
    }

    fn reason(self) -> String {
        match self {
            Self::Refused(code) => format!(" reason={code}"),
            Self::Pass | Self::NotRun => String::new(),
        }
    }
}

/// Everything startup learned, one outcome per capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupReport {
    /// The ABI the backend declared, when it was asked.
    pub abi: Option<Abi>,
    /// The evidence profile whose matrix the layer was admitted against, when one was selected.
    pub evidence: Option<&'static str>,
    /// What the backend declared itself to be.
    pub backend: Provenance,
    /// The running kernel's release as recorded (`kernel=`): sanitised and bounded, never compared, never a reason to refuse.
    pub kernel_release: String,
    /// What the admitted layer declared; `None` when no layer was built.
    pub layer_provenance: Option<Provenance>,
    /// The wake mechanism the matrix selects, when the matrix was admissible.
    pub mechanism: Option<ReactorWakeMechanism>,
    pub kernel: Outcome,
    pub clock: Outcome,
    pub entropy: Outcome,
    pub wake: Outcome,
}

const fn abi_name(abi: Option<Abi>) -> &'static str {
    match abi {
        Some(Abi::PowerPc32) => "powerpc32",
        Some(Abi::Mips32) => "mips32",
        None => "none",
    }
}

const fn provenance_name(provenance: Option<Provenance>) -> &'static str {
    match provenance {
        Some(Provenance::Kernel) => "kernel",
        Some(Provenance::Simulated) => "simulated",
        None => "none",
    }
}

const fn mechanism_name(mechanism: Option<ReactorWakeMechanism>) -> &'static str {
    match mechanism {
        Some(ReactorWakeMechanism::EventFd) => "eventfd",
        Some(ReactorWakeMechanism::SelfPipe) => "self_pipe",
        None => "none",
    }
}

/// The text the `BEGIN` line records as `kernel=`: the release trimmed, if it is one to 64 bytes of `[A-Za-z0-9._+-]`, else the
/// literal `invalid` (an unreadable release, a longer one, or other bytes). It is evidence of which kernel answered and nothing
/// else: no function in this crate compares it.
#[must_use]
pub fn sanitize_kernel(raw: Option<&str>) -> String {
    let Some(text) = raw.map(str::trim) else {
        return INVALID_KERNEL.to_string();
    };
    let allowed =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-');
    if text.is_empty() || text.len() > MAX_KERNEL_FIELD_LEN || !text.bytes().all(allowed) {
        return INVALID_KERNEL.to_string();
    }
    text.to_string()
}

/// The running kernel's release as the kernel reports it, or `None` if it cannot be read (no `/proc`). Unreadable is recorded as
/// `kernel=invalid` and is not a refusal.
#[must_use]
pub fn read_running_release() -> Option<String> {
    std::fs::read_to_string(OSRELEASE_PATH).ok()
}

impl StartupReport {
    fn new(backend: Provenance, kernel_release: String) -> Self {
        Self {
            abi: None,
            evidence: None,
            backend,
            kernel_release,
            layer_provenance: None,
            mechanism: None,
            kernel: Outcome::NotRun,
            clock: Outcome::NotRun,
            entropy: Outcome::NotRun,
            wake: Outcome::NotRun,
        }
    }

    /// Every capability passed.
    #[must_use]
    pub fn started(&self) -> bool {
        [self.kernel, self.clock, self.entropy, self.wake]
            .iter()
            .all(|outcome| *outcome == Outcome::Pass)
    }

    /// The first refusal in the order kernel, clock, entropy, wake.
    #[must_use]
    pub fn first_refusal(&self) -> Option<(Capability, &'static str)> {
        [
            (Capability::Kernel, self.kernel),
            (Capability::Clock, self.clock),
            (Capability::Entropy, self.entropy),
            (Capability::Wake, self.wake),
        ]
        .into_iter()
        .find_map(|(capability, outcome)| match outcome {
            Outcome::Refused(code) => Some((capability, code)),
            Outcome::Pass | Outcome::NotRun => None,
        })
    }

    /// The process exit status this report calls for.
    #[must_use]
    pub fn exit_status(&self) -> u8 {
        if self.started() {
            EXIT_STARTED
        } else {
            EXIT_REFUSED
        }
    }

    /// The marker lines the QEMU speaker smoke judges: six lines, always, newline-terminated, and nothing after `END`. A capability
    /// that could not be tried says `NOT_RUN`; `provenance=none` means no layer existed to ask.
    #[must_use]
    pub fn markers(&self) -> String {
        let layer = provenance_name(self.layer_provenance);
        let end = match self.first_refusal() {
            None if self.started() => "FFW_PLATFORM:END started=1".to_string(),
            None => "FFW_PLATFORM:END started=0".to_string(),
            Some((capability, code)) => {
                format!(
                    "FFW_PLATFORM:END started=0 refused={}:{code}",
                    capability.name()
                )
            }
        };
        let lines = [
            format!(
                "FFW_PLATFORM:BEGIN abi={} evidence={} backend={} kernel={}",
                abi_name(self.abi),
                self.evidence.unwrap_or("none"),
                provenance_name(Some(self.backend)),
                self.kernel_release
            ),
            format!(
                "FFW_PLATFORM:KERNEL status={}{}",
                self.kernel.status(),
                self.kernel.reason()
            ),
            format!(
                "FFW_PLATFORM:CLOCK status={} provenance={layer}{}",
                self.clock.status(),
                self.clock.reason()
            ),
            format!(
                "FFW_PLATFORM:ENTROPY status={} provenance={layer}{}",
                self.entropy.status(),
                self.entropy.reason()
            ),
            format!(
                "FFW_PLATFORM:WAKE status={} provenance={layer} mechanism={}{}",
                self.wake.status(),
                mechanism_name(self.mechanism),
                self.wake.reason()
            ),
            end,
        ];
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

fn refuse_kernel<T>(
    mut report: StartupReport,
    error: StartupError,
) -> (Result<T, StartupError>, StartupReport) {
    report.kernel = Outcome::Refused(error.code());
    (Err(error), report)
}

fn probe_clock<O: KernelOps>(layer: &mut PlatformLayer<O>) -> Result<(), StartupError> {
    let first = layer.now_ns().map_err(StartupError::Clock)?;
    let second = layer.now_ns().map_err(StartupError::Clock)?;
    if second < first {
        return Err(StartupError::Clock(ClockError::WentBackwards {
            last_ns: first,
            now_ns: second,
        }));
    }
    Ok(())
}

fn probe_entropy<O: KernelOps>(layer: &mut PlatformLayer<O>) -> Result<(), StartupError> {
    // The bytes prove the capability and are dropped here: nothing prints or keeps them.
    let mut bytes = [0u8; ENTROPY_PROBE_BYTES];
    layer.fill_random(&mut bytes).map_err(StartupError::Entropy)
}

fn probe_wake<O: KernelOps>(layer: &mut PlatformLayer<O>) -> Result<(), StartupError> {
    match layer.signal_wake().map_err(StartupError::Wake)? {
        WakeOutcome::Signalled => {}
        outcome => return Err(StartupError::WakeNotSignalled { outcome }),
    }
    let drained = layer.drain_wake().map_err(StartupError::Wake)?;
    if drained.wakes != 1 || drained.more_pending {
        return Err(StartupError::WakeNotObserved {
            wakes: drained.wakes,
            more_pending: drained.more_pending,
        });
    }
    let again = layer.drain_wake().map_err(StartupError::Wake)?;
    if again.wakes != 0 || again.more_pending {
        return Err(StartupError::WakeNotObserved {
            wakes: again.wakes,
            more_pending: again.more_pending,
        });
    }
    Ok(())
}

fn settle(result: Result<(), StartupError>, first: &mut Option<StartupError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Pass,
        Err(error) => {
            let outcome = Outcome::Refused(error.code());
            if first.is_none() {
                *first = Some(error);
            }
            outcome
        }
    }
}

/// Build the platform layer over `ops`. **The one place a layer is built**: the device speaker's every start calls this (through
/// [`bring_up_device`]), and so does the generic check the unit tests drive.
///
/// `running_release` is the kernel's release as read, if it could be read; it is only recorded (see [`sanitize_kernel`]).
/// Returns the live layer when every capability passed, or the first typed refusal; the report always says what happened to each
/// capability. A refused backend is never called.
///
/// # Errors
/// A [`StartupError`], whose [`StartupError::code`] is the `reason=` of the refusing line.
pub fn bring_up<O: KernelOps>(
    ops: O,
    running_release: Option<&str>,
) -> (Result<PlatformLayer<O>, StartupError>, StartupReport) {
    let backend = ops.provenance();
    let mut report = StartupReport::new(backend, sanitize_kernel(running_release));
    if backend != Provenance::Kernel {
        return refuse_kernel(
            report,
            StartupError::NotKernelBacked {
                provenance: backend,
            },
        );
    }
    let Some(abi) = ops.backend_abi() else {
        return refuse_kernel(report, StartupError::BackendNamesNoAbi);
    };
    report.abi = Some(abi);
    let evidence = guest_evidence::for_abi(abi);
    report.evidence = Some(evidence.profile_id);
    let matrix = evidence.matrix();
    report.mechanism = matrix.check_admission().ok();
    let mut layer = match PlatformLayer::admit(&matrix, ops) {
        Ok(layer) => layer,
        Err(error) => return refuse_kernel(report, StartupError::Admission(error)),
    };
    report.kernel = Outcome::Pass;
    report.layer_provenance = Some(layer.provenance());

    let mut first_error = None;
    report.clock = settle(probe_clock(&mut layer), &mut first_error);
    report.entropy = settle(probe_entropy(&mut layer), &mut first_error);
    report.wake = settle(probe_wake(&mut layer), &mut first_error);
    match first_error {
        Some(error) => (Err(error), report),
        None => (Ok(layer), report),
    }
}

/// Bring the device speaker's platform up over the Linux backend: **the one place `LinuxKernel` is constructed**, and the function
/// any startup of the device speaker must call and refuse to start on an `Err` from. Only a big-endian 32-bit MIPS or PowerPC
/// build has the backend.
#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
pub fn bring_up_device() -> (
    Result<PlatformLayer<franken_platform_linux::LinuxKernel>, StartupError>,
    StartupReport,
) {
    bring_up(
        franken_platform_linux::LinuxKernel::new(),
        read_running_release().as_deref(),
    )
}

/// Release what [`bring_up`] opened and report: what `franken-speaker --platform-startup` does after it. A failure to close the
/// wake descriptors is a wake refusal (`close_failed`).
#[must_use]
pub fn finish_check<O: KernelOps>(
    brought_up: (Result<PlatformLayer<O>, StartupError>, StartupReport),
) -> StartupReport {
    let (result, mut report) = brought_up;
    if let Ok(layer) = result
        && layer.close().is_err()
    {
        report.wake = Outcome::Refused("close_failed");
    }
    report
}

/// `--platform-startup` on a device build: [`bring_up_device`], released, as a report.
#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
#[must_use]
pub fn check_device() -> StartupReport {
    finish_check(bring_up_device())
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_platform::abi::SysError;
    use franken_platform::entropy::GRND_NONBLOCK;
    use franken_platform::ops::Timespec;
    use franken_platform::wake::WakeCall;
    use franken_platform::{CapabilityStatus, PlatformAdmissionError};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    const PPC_RELEASE: &str = "4.9.0-0.bpo.6-powerpc";
    const MIPS_RELEASE: &str = "4.19.0-21-4kc-malta";

    #[derive(Default)]
    struct Calls {
        clock: Cell<u32>,
        random: Cell<u32>,
        eventfd: Cell<u32>,
        pipe: Cell<u32>,
        write: Cell<u32>,
        read: Cell<u32>,
        close: Cell<u32>,
        random_flags: RefCell<Vec<u32>>,
        random_lens: RefCell<Vec<usize>>,
    }

    impl Calls {
        fn total(&self) -> u32 {
            self.clock.get()
                + self.random.get()
                + self.eventfd.get()
                + self.pipe.get()
                + self.write.get()
                + self.read.get()
                + self.close.get()
        }
    }

    #[derive(Clone, Copy)]
    enum Random {
        Bytes,
        Errno(isize),
    }

    /// A test double. It says whatever `provenance` and `abi` the test gives it, which is the whole point of the refusal tests, and
    /// it proves only the logic of this module: that a double declares `Kernel` is not evidence about any kernel. The proof that the
    /// real backend does is the QEMU speaker smoke.
    struct Fake {
        provenance: Provenance,
        abi: Option<Abi>,
        clock_error: Option<isize>,
        random: Random,
        eventfd_error: Option<isize>,
        wake_write_error: Option<isize>,
        close_error: Option<isize>,
        swallow_wake: bool,
        ticks: i64,
        pending: u64,
        calls: Rc<Calls>,
    }

    impl Fake {
        fn new(provenance: Provenance, abi: Option<Abi>) -> (Self, Rc<Calls>) {
            let calls = Rc::new(Calls::default());
            let fake = Self {
                provenance,
                abi,
                clock_error: None,
                random: Random::Bytes,
                eventfd_error: None,
                wake_write_error: None,
                close_error: None,
                swallow_wake: false,
                ticks: 0,
                pending: 0,
                calls: Rc::clone(&calls),
            };
            (fake, calls)
        }

        fn kernel(abi: Abi) -> (Self, Rc<Calls>) {
            Self::new(Provenance::Kernel, Some(abi))
        }
    }

    impl KernelOps for Fake {
        fn provenance(&self) -> Provenance {
            self.provenance
        }

        fn backend_abi(&self) -> Option<Abi> {
            self.abi
        }

        fn clock_gettime_monotonic(&mut self, out: &mut Timespec) -> isize {
            self.calls.clock.set(self.calls.clock.get() + 1);
            if let Some(error) = self.clock_error {
                return error;
            }
            self.ticks += 1;
            out.secs = self.ticks;
            out.nanos = 0;
            0
        }

        fn getrandom(&mut self, buf: &mut [u8], flags: u32) -> isize {
            self.calls.random.set(self.calls.random.get() + 1);
            self.calls.random_flags.borrow_mut().push(flags);
            self.calls.random_lens.borrow_mut().push(buf.len());
            match self.random {
                Random::Errno(error) => error,
                Random::Bytes => {
                    for (index, byte) in buf.iter_mut().enumerate() {
                        *byte = u8::try_from(index)
                            .unwrap_or(0)
                            .wrapping_mul(37)
                            .wrapping_add(11);
                    }
                    isize::try_from(buf.len()).unwrap_or(-1)
                }
            }
        }

        fn eventfd2(&mut self, _initval: u32, _flags: u32) -> isize {
            self.calls.eventfd.set(self.calls.eventfd.get() + 1);
            self.eventfd_error.unwrap_or(7)
        }

        fn pipe2(&mut self, fds: &mut [i32; 2], _flags: u32) -> isize {
            self.calls.pipe.set(self.calls.pipe.get() + 1);
            *fds = [8, 9];
            0
        }

        fn write(&mut self, _fd: i32, buf: &[u8]) -> isize {
            self.calls.write.set(self.calls.write.get() + 1);
            if let Some(error) = self.wake_write_error {
                return error;
            }
            if !self.swallow_wake {
                self.pending += 1;
            }
            isize::try_from(buf.len()).unwrap_or(-1)
        }

        fn read(&mut self, _fd: i32, buf: &mut [u8]) -> isize {
            self.calls.read.set(self.calls.read.get() + 1);
            if self.pending == 0 {
                return -11;
            }
            buf[..8].copy_from_slice(&self.pending.to_ne_bytes());
            self.pending = 0;
            8
        }

        fn close(&mut self, _fd: i32) -> isize {
            self.calls.close.set(self.calls.close.get() + 1);
            self.close_error.unwrap_or(0)
        }
    }

    fn lines(report: &StartupReport) -> Vec<String> {
        report.markers().lines().map(str::to_string).collect()
    }

    // ---- the paired positive (logic only) and the planted negative ----

    #[test]
    fn a_kernel_declaring_backend_starts_and_every_capability_reports_kernel() {
        // Logic only: the double declares `Kernel`. What shows the real backend does is the QEMU speaker smoke.
        for (abi, release, abi_text, evidence) in [
            (Abi::PowerPc32, PPC_RELEASE, "powerpc32", "harness-ppc-4.9"),
            (Abi::Mips32, MIPS_RELEASE, "mips32", "harness-mips-4.19"),
        ] {
            let (fake, calls) = Fake::kernel(abi);
            let (result, report) = bring_up(fake, Some(release));
            assert!(result.is_ok(), "{abi:?}");
            assert!(report.started(), "{abi:?}");
            assert_eq!(report.exit_status(), EXIT_STARTED);
            assert_eq!(report.first_refusal(), None);
            assert_eq!(
                lines(&report),
                vec![
                    format!(
                        "FFW_PLATFORM:BEGIN abi={abi_text} evidence={evidence} backend=kernel kernel={release}"
                    ),
                    "FFW_PLATFORM:KERNEL status=PASS".to_string(),
                    "FFW_PLATFORM:CLOCK status=PASS provenance=kernel".to_string(),
                    "FFW_PLATFORM:ENTROPY status=PASS provenance=kernel".to_string(),
                    "FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd".to_string(),
                    "FFW_PLATFORM:END started=1".to_string(),
                ],
                "{abi:?}"
            );
            // Two clock readings, one nonblocking getrandom, one eventfd, one signal, two drains; no other call.
            assert_eq!(calls.clock.get(), 2);
            assert_eq!(calls.random.get(), 1);
            assert_eq!(*calls.random_flags.borrow(), vec![GRND_NONBLOCK]);
            // One request of the pinned length, which is long enough for the layer's degenerate-output check to apply.
            assert_eq!(*calls.random_lens.borrow(), vec![ENTROPY_PROBE_BYTES]);
            assert!(
                calls
                    .random_lens
                    .borrow()
                    .iter()
                    .all(|len| *len >= franken_platform::entropy::DEGENERATE_CHECK_MIN_LEN)
            );
            assert_eq!((calls.eventfd.get(), calls.pipe.get()), (1, 0));
            assert_eq!((calls.write.get(), calls.read.get()), (1, 2));
        }
    }

    #[test]
    fn a_device_build_wired_to_a_simulated_backend_is_refused_before_any_kernel_call() {
        // Planted negative. The double declares `Simulated` and, as a double does, names no ABI; a second one also names an ABI and
        // a release, so only the declaration can refuse it.
        for abi in [None, Some(Abi::PowerPc32), Some(Abi::Mips32)] {
            let (fake, calls) = Fake::new(Provenance::Simulated, abi);
            let (result, report) = bring_up(fake, Some(PPC_RELEASE));
            assert_eq!(
                result.err(),
                Some(StartupError::NotKernelBacked {
                    provenance: Provenance::Simulated
                }),
                "{abi:?}"
            );
            assert_eq!(calls.total(), 0, "{abi:?}: a simulated backend was called");
            assert!(!report.started());
            assert_eq!(report.kernel, Outcome::Refused("simulated_backend"));
            assert_eq!(
                (report.clock, report.entropy, report.wake),
                (Outcome::NotRun, Outcome::NotRun, Outcome::NotRun)
            );
            assert_eq!(report.backend, Provenance::Simulated);
            assert_eq!(
                lines(&report),
                vec![
                    format!(
                        "FFW_PLATFORM:BEGIN abi=none evidence=none backend=simulated kernel={PPC_RELEASE}"
                    ),
                    "FFW_PLATFORM:KERNEL status=REFUSED reason=simulated_backend".to_string(),
                    "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none".to_string(),
                    "FFW_PLATFORM:ENTROPY status=NOT_RUN provenance=none".to_string(),
                    "FFW_PLATFORM:WAKE status=NOT_RUN provenance=none mechanism=none".to_string(),
                    "FFW_PLATFORM:END started=0 refused=kernel:simulated_backend".to_string(),
                ]
            );
            assert_eq!(report.exit_status(), EXIT_REFUSED);
        }
    }

    #[test]
    fn a_kernel_backend_that_names_no_abi_is_refused_before_any_kernel_call() {
        let (fake, calls) = Fake::new(Provenance::Kernel, None);
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(result.err(), Some(StartupError::BackendNamesNoAbi));
        assert_eq!(calls.total(), 0);
        assert_eq!(report.kernel, Outcome::Refused("no_abi"));
        assert_eq!(report.abi, None);
    }

    // ---- the kernel release is recorded and is never a gate ----

    #[test]
    fn the_running_kernel_is_recorded_and_never_a_reason_to_refuse() {
        let long = "9".repeat(MAX_KERNEL_FIELD_LEN + 1);
        // A real board's kernel is the vendor's; none of these may refuse, and none may change what the probes see.
        for (release, recorded) in [
            (Some(PPC_RELEASE), PPC_RELEASE),
            (Some("2.6.14.7"), "2.6.14.7"),
            (Some("2.6.35-sonos+local_1"), "2.6.35-sonos+local_1"),
            (Some(MIPS_RELEASE), MIPS_RELEASE), // another guest's release on this ABI
            (Some("  4.9.0  \n"), "4.9.0"),
            (None, INVALID_KERNEL), // unreadable
            (Some(""), INVALID_KERNEL),
            (Some("has space"), INVALID_KERNEL),
            (Some("semi;colon"), INVALID_KERNEL),
            (Some(long.as_str()), INVALID_KERNEL),
        ] {
            let (fake, calls) = Fake::kernel(Abi::PowerPc32);
            let (result, report) = bring_up(fake, release);
            assert!(result.is_ok(), "{release:?}: a release must never refuse");
            assert!(report.started(), "{release:?}");
            assert_eq!(report.kernel_release, recorded, "{release:?}");
            assert!(
                report
                    .markers()
                    .lines()
                    .next()
                    .is_some_and(|begin| begin.ends_with(&format!(" kernel={recorded}"))),
                "{release:?}"
            );
            assert_eq!(calls.clock.get(), 2, "{release:?}: the probes ran as usual");
        }
    }

    #[test]
    fn the_kernel_field_is_one_to_sixty_four_safe_bytes_or_the_literal_invalid() {
        assert_eq!(
            sanitize_kernel(Some("4.19.0-21-4kc-malta")),
            "4.19.0-21-4kc-malta"
        );
        assert_eq!(sanitize_kernel(Some("a")), "a");
        assert_eq!(
            sanitize_kernel(Some(&"x".repeat(MAX_KERNEL_FIELD_LEN))).len(),
            MAX_KERNEL_FIELD_LEN
        );
        assert_eq!(
            sanitize_kernel(Some(&"x".repeat(MAX_KERNEL_FIELD_LEN + 1))),
            INVALID_KERNEL
        );
        for bad in [
            "", "   ", "a b", "a/b", "a;b", "a\nb", "a\u{0}b", "\u{e9}", "a=b", "a,b", "a:b",
        ] {
            assert_eq!(sanitize_kernel(Some(bad)), INVALID_KERNEL, "{bad:?}");
        }
        assert_eq!(sanitize_kernel(None), INVALID_KERNEL);
        // every byte the value may carry
        let all = "ABCxyz019._+-";
        assert_eq!(sanitize_kernel(Some(all)), all);
    }

    // ---- clock, entropy and wake: a failure is a typed refusal and nothing is substituted ----

    #[test]
    fn a_wake_source_the_kernel_cannot_open_refuses_the_platform_on_its_typed_code() {
        // A kernel without eventfd2 answers -ENOSYS; the speaker refuses on that probe result, and does not look at a version string.
        let (mut fake, calls) = Fake::kernel(Abi::PowerPc32);
        fake.eventfd_error = Some(-38);
        let (result, report) = bring_up(fake, Some("2.6.14.7"));
        let error = result.err().expect("refused");
        assert_eq!(error.capability(), Capability::Kernel);
        assert_eq!(error.code(), "wake_open_failed");
        assert_eq!(report.kernel, Outcome::Refused("wake_open_failed"));
        // Nothing could be tried without a layer, and every NOT_RUN follows an earlier REFUSED.
        assert_eq!(
            (report.clock, report.entropy, report.wake),
            (Outcome::NotRun, Outcome::NotRun, Outcome::NotRun)
        );
        assert_eq!(calls.eventfd.get(), 1, "no other wake mechanism was tried");
        assert_eq!(calls.pipe.get(), 0);
        assert_eq!(report.layer_provenance, None);
        assert!(
            report
                .markers()
                .ends_with("FFW_PLATFORM:END started=0 refused=kernel:wake_open_failed\n")
        );
    }

    #[test]
    fn a_clock_that_is_absent_is_a_typed_refusal_and_the_other_capabilities_are_still_tried() {
        let (mut fake, calls) = Fake::kernel(Abi::PowerPc32);
        fake.clock_error = Some(-38); // PowerPC ENOSYS
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(result.err(), Some(StartupError::Clock(ClockError::Absent)));
        assert_eq!(report.clock, Outcome::Refused("absent"));
        assert_eq!(
            (report.entropy, report.wake),
            (Outcome::Pass, Outcome::Pass)
        );
        assert_eq!(report.first_refusal(), Some((Capability::Clock, "absent")));
        assert!(
            report
                .markers()
                .ends_with("FFW_PLATFORM:END started=0 refused=clock:absent\n")
        );
        assert_eq!(
            calls.clock.get(),
            1,
            "a clock that is absent is asked once, not worked around"
        );
    }

    #[test]
    fn an_unseeded_pool_is_a_retryable_refusal_and_is_never_answered_with_a_seeded_value() {
        let (mut fake, calls) = Fake::kernel(Abi::Mips32);
        fake.random = Random::Errno(-11);
        let (result, report) = bring_up(fake, Some(MIPS_RELEASE));
        let error = result.err().expect("refused");
        assert_eq!(error, StartupError::Entropy(EntropyError::NotSeeded));
        assert!(error.is_retryable());
        assert_eq!(report.entropy, Outcome::Refused("not_seeded"));
        assert_eq!(
            (report.kernel, report.clock, report.wake),
            (Outcome::Pass, Outcome::Pass, Outcome::Pass)
        );
        // One nonblocking request. The seam has no other source, and nothing here makes one up.
        assert_eq!(calls.random.get(), 1);
        assert_eq!(*calls.random_flags.borrow(), vec![GRND_NONBLOCK]);
        assert_eq!(
            lines(&report),
            vec![
                format!(
                    "FFW_PLATFORM:BEGIN abi=mips32 evidence=harness-mips-4.19 backend=kernel kernel={MIPS_RELEASE}"
                ),
                "FFW_PLATFORM:KERNEL status=PASS".to_string(),
                "FFW_PLATFORM:CLOCK status=PASS provenance=kernel".to_string(),
                "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded"
                    .to_string(),
                "FFW_PLATFORM:WAKE status=PASS provenance=kernel mechanism=eventfd".to_string(),
                "FFW_PLATFORM:END started=0 refused=entropy:not_seeded".to_string(),
            ]
        );
        assert_eq!(report.exit_status(), EXIT_REFUSED);
    }

    #[test]
    fn only_an_unseeded_pool_is_retryable() {
        for error in [
            StartupError::Entropy(EntropyError::Absent),
            StartupError::Entropy(EntropyError::Degenerate),
            StartupError::Clock(ClockError::Absent),
            StartupError::Wake(WakeError::ZeroCounter),
            StartupError::BackendNamesNoAbi,
            StartupError::Admission(LayerError::Wake(WakeError::ZeroCounter)),
        ] {
            assert!(!error.is_retryable(), "{error}");
        }
    }

    #[test]
    fn an_entropy_call_that_is_absent_or_degenerate_is_refused_not_papered_over() {
        let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
        fake.random = Random::Errno(-38);
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(
            result.err(),
            Some(StartupError::Entropy(EntropyError::Absent))
        );
        assert_eq!(report.entropy, Outcome::Refused("absent"));
        // The other ABI's number is not absence on this one.
        let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
        fake.random = Random::Errno(-89);
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(
            result.err(),
            Some(StartupError::Entropy(EntropyError::Failed(89)))
        );
        assert_eq!(report.entropy, Outcome::Refused("failed"));
    }

    #[test]
    fn a_wake_that_cannot_be_signalled_or_is_not_seen_is_a_typed_refusal() {
        let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
        fake.wake_write_error = Some(-9);
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(result.err().map(|e| e.code()), Some("sys"));
        assert_eq!(report.wake, Outcome::Refused("sys"));

        // Signalled, but a drain finds nothing: the wake did not arrive.
        let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
        fake.swallow_wake = true;
        let (result, report) = bring_up(fake, Some(PPC_RELEASE));
        assert_eq!(
            result.err(),
            Some(StartupError::WakeNotObserved {
                wakes: 0,
                more_pending: false
            })
        );
        assert_eq!(report.wake, Outcome::Refused("not_observed"));
    }

    // ---- the one-shot check ----

    #[test]
    fn the_one_shot_check_closes_the_layer_it_opened() {
        let (fake, calls) = Fake::kernel(Abi::PowerPc32);
        let report = finish_check(bring_up(fake, Some(PPC_RELEASE)));
        assert!(report.started());
        assert_eq!(calls.close.get(), 1, "the eventfd is closed once");
        // A refused start closes what it opened too (the layer's drop).
        let (mut fake, calls) = Fake::kernel(Abi::PowerPc32);
        fake.clock_error = Some(-38);
        let report = finish_check(bring_up(fake, Some(PPC_RELEASE)));
        assert!(!report.started());
        assert_eq!(calls.close.get(), 1);
    }

    #[test]
    fn a_wake_source_that_will_not_close_is_a_wake_refusal_and_not_a_silent_pass() {
        let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
        fake.close_error = Some(-9);
        let report = finish_check(bring_up(fake, Some(PPC_RELEASE)));
        assert!(!report.started());
        assert_eq!(report.wake, Outcome::Refused("close_failed"));
        assert_eq!(
            report.first_refusal(),
            Some((Capability::Wake, "close_failed"))
        );
        assert!(
            report
                .markers()
                .ends_with("FFW_PLATFORM:END started=0 refused=wake:close_failed\n")
        );
        assert_eq!(report.exit_status(), EXIT_REFUSED);
    }

    // ---- one construction site: normal startup and `--platform-startup` are the same path ----

    fn rs_files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("the crate directory is readable")
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                rs_files(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// `(layer builds, backend builds)` in `text`, ignoring `//` comments and whitespace (so `PlatformLayer :: admit (` counts).
    fn construction_sites(text: &str) -> (usize, usize) {
        let code: String = text
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let squeezed: String = code.split_whitespace().collect();
        (
            squeezed.matches("PlatformLayer::admit(").count(),
            squeezed.matches("LinuxKernel::new(").count()
                + squeezed.matches("LinuxKernel{").count(),
        )
    }

    #[test]
    fn the_speaker_builds_a_layer_and_the_backend_in_exactly_one_place_each() {
        // Pinned on the source, so a second construction path (a `--run` mode, a helper in `main.rs`, a test-only shortcut that
        // ships) fails here instead of drifting. `tests/p02/test_platform_markers.py` holds the same pin on the host.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src"), &mut files);
        rs_files(&root.join("tests"), &mut files);
        assert!(
            files.iter().any(|path| path.ends_with("src/main.rs"))
                && files
                    .iter()
                    .any(|path| path.ends_with("src/platform_start.rs")),
            "the scan did not find the crate's own sources: {files:?}"
        );
        let mut here = None;
        for path in &files {
            let text = std::fs::read_to_string(path).expect("source is UTF-8");
            if path.ends_with("src/platform_start.rs") {
                // Only the part before this test module counts: the module itself names the calls in order to look for them.
                here = Some(construction_sites(
                    text.split("#[cfg(test)]").next().unwrap_or(""),
                ));
            } else {
                assert_eq!(
                    construction_sites(&text),
                    (0, 0),
                    "{} builds a layer or the Linux backend outside bring_up",
                    path.display()
                );
                let code: String = text
                    .lines()
                    .map(|line| line.split("//").next().unwrap_or(""))
                    .collect();
                for name in ["franken_platform_linux", "SeededSim", "ScriptedOps"] {
                    assert!(!code.contains(name), "{} names {name}", path.display());
                }
            }
        }
        assert_eq!(
            here,
            Some((1, 1)),
            "bring_up and bring_up_device each build once"
        );
    }

    #[test]
    fn the_construction_counter_sees_a_second_site_and_ignores_prose() {
        // The control for the test above: plant a site and it is counted; mention one in a comment and it is not.
        assert_eq!(
            construction_sites("let l = PlatformLayer::admit(&m, ops);"),
            (1, 0)
        );
        assert_eq!(
            construction_sites("let l = PlatformLayer :: admit (&m, ops);"),
            (1, 0)
        );
        assert_eq!(
            construction_sites("let b = franken_platform_linux::LinuxKernel::new();"),
            (0, 1)
        );
        assert_eq!(construction_sites("let b = LinuxKernel {};"), (0, 1));
        assert_eq!(
            construction_sites("// PlatformLayer::admit(&m, ops) is called once, in bring_up"),
            (0, 0)
        );
        assert_eq!(
            construction_sites("/// `LinuxKernel::new()` is built in bring_up_device"),
            (0, 0)
        );
    }

    // ---- the reason codes and the committed marker examples ----

    fn one_of_each_error() -> Vec<StartupError> {
        vec![
            StartupError::NotKernelBacked {
                provenance: Provenance::Simulated,
            },
            StartupError::BackendNamesNoAbi,
            StartupError::Admission(LayerError::Admission(
                PlatformAdmissionError::CoarseMonotonicClock { resolution_ns: 0 },
            )),
            StartupError::Admission(LayerError::UnknownAbi {
                triple: "t".to_string(),
            }),
            StartupError::Admission(LayerError::AbiMismatch {
                profile: Abi::Mips32,
                backend: Abi::PowerPc32,
            }),
            StartupError::Admission(LayerError::Wake(WakeError::ZeroCounter)),
            StartupError::Clock(ClockError::Absent),
            StartupError::Clock(ClockError::Interrupted),
            StartupError::Clock(ClockError::Failed(1)),
            StartupError::Clock(ClockError::Malformed(-5000)),
            StartupError::Clock(ClockError::UnexpectedReturn(3)),
            StartupError::Clock(ClockError::InvalidTimespec { secs: -1, nanos: 0 }),
            StartupError::Clock(ClockError::Overflow),
            StartupError::Clock(ClockError::WentBackwards {
                last_ns: 2,
                now_ns: 1,
            }),
            StartupError::Entropy(EntropyError::ZeroLength),
            StartupError::Entropy(EntropyError::Unavailable {
                status: CapabilityStatus::MissingRequired,
            }),
            StartupError::Entropy(EntropyError::NotSeeded),
            StartupError::Entropy(EntropyError::Absent),
            StartupError::Entropy(EntropyError::Interrupted),
            StartupError::Entropy(EntropyError::Invalid),
            StartupError::Entropy(EntropyError::NoProgress),
            StartupError::Entropy(EntropyError::OverLong {
                requested: 1,
                returned: 2,
            }),
            StartupError::Entropy(EntropyError::Degenerate),
            StartupError::Entropy(EntropyError::Failed(5)),
            StartupError::Entropy(EntropyError::Malformed(-5000)),
            StartupError::Wake(WakeError::Absent {
                call: WakeCall::Pipe2,
            }),
            StartupError::Wake(WakeError::Sys {
                call: WakeCall::Write,
                error: SysError::Errno(9),
            }),
            StartupError::Wake(WakeError::Unexpected {
                call: WakeCall::Close,
                value: 3,
                expected: 0,
            }),
            StartupError::Wake(WakeError::BadDescriptor {
                read_fd: -1,
                write_fd: -1,
            }),
            StartupError::Wake(WakeError::ShortWrite {
                wrote: 1,
                expected: 8,
            }),
            StartupError::Wake(WakeError::ShortRead {
                got: 1,
                expected: 8,
            }),
            StartupError::Wake(WakeError::ZeroCounter),
            StartupError::Wake(WakeError::EndOfFile),
            StartupError::WakeNotSignalled {
                outcome: WakeOutcome::Backlogged,
            },
            StartupError::WakeNotObserved {
                wakes: 2,
                more_pending: true,
            },
        ]
    }

    #[test]
    fn every_reason_code_is_produced_by_some_error_and_belongs_to_its_capabilitys_closed_set() {
        let errors = one_of_each_error();
        for (name, codes) in REASON_CODES {
            for (index, code) in codes.iter().enumerate() {
                assert!(
                    code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                    "{name}:{code} is not snake_case"
                );
                assert!(
                    !codes[index + 1..].contains(code),
                    "{name}:{code} listed twice"
                );
            }
            // Every code in the set is produced by an error of that capability, except close_failed, which is an Outcome
            // that finish_check sets when releasing the layer fails.
            for code in codes.iter().filter(|code| **code != "close_failed") {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.capability().name() == name && e.code() == *code),
                    "{name}:{code} is in the set but no error produces it"
                );
            }
        }
        // And the other direction: every error's code is in its capability's set.
        for error in &errors {
            let set = REASON_CODES
                .iter()
                .find(|(name, _)| *name == error.capability().name())
                .map(|(_, codes)| *codes)
                .expect("a set for the capability");
            assert!(set.contains(&error.code()), "{error:?} -> {}", error.code());
        }
        // No code mentions the kernel's release: the speaker never refuses on it.
        assert!(
            REASON_CODES
                .iter()
                .flat_map(|(_, codes)| codes.iter())
                .all(|code| !code.contains("release"))
        );
    }

    /// Run the named scenario and give its report. Every scenario has a committed example (and the reverse).
    fn scenario(name: &str) -> StartupReport {
        match name {
            "powerpc_all_pass" => {
                finish_check(bring_up(Fake::kernel(Abi::PowerPc32).0, Some(PPC_RELEASE)))
            }
            "mips_all_pass" => {
                finish_check(bring_up(Fake::kernel(Abi::Mips32).0, Some(MIPS_RELEASE)))
            }
            "mips_entropy_not_seeded" => {
                let (mut fake, _) = Fake::kernel(Abi::Mips32);
                fake.random = Random::Errno(-11);
                finish_check(bring_up(fake, Some(MIPS_RELEASE)))
            }
            "simulated_backend_refused" => finish_check(bring_up(
                Fake::new(Provenance::Simulated, None).0,
                Some(PPC_RELEASE),
            )),
            "stock_kernel_release_recorded_not_refused" => {
                finish_check(bring_up(Fake::kernel(Abi::PowerPc32).0, Some("2.6.14.7")))
            }
            "unreadable_kernel_release_recorded_as_invalid" => {
                finish_check(bring_up(Fake::kernel(Abi::PowerPc32).0, None))
            }
            "wake_source_absent_powerpc" => {
                let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
                fake.eventfd_error = Some(-38);
                finish_check(bring_up(fake, Some("2.6.14.7")))
            }
            "clock_absent_powerpc" => {
                let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
                fake.clock_error = Some(-38);
                finish_check(bring_up(fake, Some(PPC_RELEASE)))
            }
            "wake_not_observed_powerpc" => {
                let (mut fake, _) = Fake::kernel(Abi::PowerPc32);
                fake.swallow_wake = true;
                finish_check(bring_up(fake, Some(PPC_RELEASE)))
            }
            other => panic!("no scenario named {other}"),
        }
    }

    #[test]
    fn the_committed_marker_examples_are_exactly_what_each_scenario_prints_and_the_reason_set_matches()
     {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/p02_platform_markers.json"))
                .expect("the vector file is JSON");
        assert_eq!(vectors["schema"], "ffw.p02.platform-markers.v2");
        // The closed reason sets in the file are the ones in the code.
        for (name, codes) in REASON_CODES {
            let committed: Vec<&str> = vectors["reason_codes"][name]
                .as_array()
                .expect("a list of codes")
                .iter()
                .map(|code| code.as_str().expect("a string"))
                .collect();
            assert_eq!(committed, codes.to_vec(), "{name}");
        }
        let examples = vectors["examples"].as_object().expect("an examples object");
        for (name, example) in examples {
            let report = scenario(name);
            let expected: Vec<&str> = example["lines"]
                .as_array()
                .expect("a list of lines")
                .iter()
                .map(|line| line.as_str().expect("a string"))
                .collect();
            let printed = report.markers();
            assert_eq!(printed.lines().collect::<Vec<_>>(), expected, "{name}");
            assert!(
                printed.ends_with('\n'),
                "{name}: every line is newline-terminated"
            );
            assert_eq!(
                u64::from(report.exit_status()),
                example["exit"].as_u64().expect("an exit status"),
                "{name}"
            );
        }
        // Every scenario the tests know has a committed example.
        for name in [
            "powerpc_all_pass",
            "mips_all_pass",
            "mips_entropy_not_seeded",
            "simulated_backend_refused",
            "stock_kernel_release_recorded_not_refused",
            "unreadable_kernel_release_recorded_as_invalid",
            "wake_source_absent_powerpc",
            "clock_absent_powerpc",
            "wake_not_observed_powerpc",
        ] {
            assert!(
                examples.contains_key(name),
                "{name} has no committed example"
            );
        }
    }
}
