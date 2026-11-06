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
//! 3. **The layer is admitted, then each capability is exercised once:** two monotonic readings, 16 bytes from the **selected**
//!    entropy provider, and one wake signalled and drained. The provider is [`EntropySelection::Getrandom`]
//!    (`getrandom(GRND_NONBLOCK)`) unless the caller names the legacy `/dev/random` provider ([`EntropySelection`],
//!    `--entropy-provider`); no failure of one ever selects the other. An error is the refusal; nothing falls back. In particular an
//!    unseeded entropy pool is [`StartupError::Entropy`] (`not_seeded`), retryable by the caller, and **never** answered with a
//!    seeded or time-derived value.
//!
//! Every capability is reported on its own line whether or not an earlier one failed ([`StartupReport`]), with the provenance the
//! layer declared and `NOT_RUN` when it could not be tried (always after an earlier `REFUSED`), so a transcript carries the failure
//! and not-run counts. The marker lines are rendered in one function ([`StartupReport::markers`]) so the grammar the QEMU speaker
//! smoke judges has one home. The lines never contain a clock value or an entropy byte.

use crate::guest_evidence;
use franken_platform::ReactorWakeMechanism;
use franken_platform::abi::Abi;
use franken_platform::clock::ClockError;
use franken_platform::entropy::{EntropyError, EntropyProfile, ProviderQualification};
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
/// Exit status for a command line that names a provider this build does not know, or any other malformed `--platform-startup`
/// argument: nothing is started and nothing is guessed.
pub const EXIT_USAGE: u8 = 2;

/// What the committed guest evidence says about a nonblocking `/dev/random` read: **nothing**. E03's probes opened `/dev/urandom`
/// (liveness) and called `getrandom`; no run has observed the legacy device, so the evidence for it is [`Unqualified`]
/// ([`ProviderQualification::Unqualified`]) and the explicitly selected legacy provider is refused with `unavailable`, without a kernel
/// call, wherever the caller has not named a test environment. Replace this constant only when a matching guest transcript carries a
/// line for it and the evidence generator reads it: a number typed here is a claim, not an observation.
pub const LEGACY_DEV_RANDOM_QUALIFICATION: ProviderQualification =
    ProviderQualification::Unqualified;

/// The entropy provider startup uses. **The default is `Getrandom`, the provider every committed transcript was made with, and a
/// failure of either provider never selects the other**: the legacy provider is selected only by naming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntropySelection {
    /// `getrandom(GRND_NONBLOCK)`: the default. Its marker line is unchanged (no `provider=` token).
    #[default]
    Getrandom,
    /// The legacy `/dev/random` provider, qualified by the committed evidence ([`LEGACY_DEV_RANDOM_QUALIFICATION`]): refused
    /// `unavailable` today. Marker token `provider=legacy_dev_random`.
    LegacyDevRandom,
    /// The legacy `/dev/random` provider in an explicitly admitted **test environment** (a harness guest, not a device): it may be
    /// tried although no observation exists. A start it reports says nothing about a device or a stock kernel. Marker token
    /// `provider=legacy_dev_random_test_environment`.
    LegacyDevRandomTestEnvironment,
}

/// The command-line spellings, in the order [`EntropySelection::ALL`] lists the variants.
const PROVIDER_ARGUMENTS: [&str; 3] = [
    "getrandom",
    "legacy-dev-random",
    "legacy-dev-random-test-environment",
];

impl EntropySelection {
    /// Every selection, in the order of [`PROVIDER_ARGUMENTS`].
    pub const ALL: [Self; 3] = [
        Self::Getrandom,
        Self::LegacyDevRandom,
        Self::LegacyDevRandomTestEnvironment,
    ];

    /// The profile this selection hands the platform layer.
    #[must_use]
    pub const fn profile(self) -> EntropyProfile {
        match self {
            Self::Getrandom => EntropyProfile::Getrandom,
            Self::LegacyDevRandom => {
                EntropyProfile::LegacyDevRandom(LEGACY_DEV_RANDOM_QUALIFICATION)
            }
            Self::LegacyDevRandomTestEnvironment => {
                EntropyProfile::LegacyDevRandom(ProviderQualification::TestEnvironment)
            }
        }
    }

    /// The `provider=` value the `ENTROPY` marker line carries, or `None` for the default (whose line has no such token, so every
    /// committed transcript stays byte-identical).
    #[must_use]
    pub const fn marker_provider(self) -> Option<&'static str> {
        match self {
            Self::Getrandom => None,
            Self::LegacyDevRandom => Some("legacy_dev_random"),
            Self::LegacyDevRandomTestEnvironment => Some("legacy_dev_random_test_environment"),
        }
    }

    /// The selection a `--entropy-provider` value names, or `None` for any other text (there is no default for an unknown name).
    #[must_use]
    pub fn from_argument(value: &str) -> Option<Self> {
        PROVIDER_ARGUMENTS
            .iter()
            .position(|name| *name == value)
            .map(|index| Self::ALL[index])
    }
}

/// The arguments after `--platform-startup`: none (the default provider), or exactly one `--entropy-provider <name>` /
/// `--entropy-provider=<name>`. Anything else is an error, never a default: an unknown provider name, a missing value, a repeated
/// flag and any other argument all refuse to start, so a typo cannot silently select (or silently keep) a provider.
///
/// # Errors
/// A message for the usage line.
pub fn parse_startup_args(args: &[String]) -> Result<EntropySelection, String> {
    let mut selection = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let value = if arg == "--entropy-provider" {
            index += 1;
            args.get(index).map(String::as_str)
        } else if let Some(value) = arg.strip_prefix("--entropy-provider=") {
            Some(value)
        } else {
            return Err(format!("unexpected argument {arg:?}"));
        };
        let Some(value) = value else {
            return Err("--entropy-provider needs a value".to_string());
        };
        if selection.is_some() {
            return Err("--entropy-provider was given twice".to_string());
        }
        selection = Some(EntropySelection::from_argument(value).ok_or_else(|| {
            format!(
                "unknown entropy provider {value:?} (known: {})",
                PROVIDER_ARGUMENTS.join(", ")
            )
        })?);
        index += 1;
    }
    Ok(selection.unwrap_or_default())
}

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
        // The legacy provider's own errors reuse the closed set, so no reason code and no judge changes: a request over its per-call
        // limit is a caller's invalid request (startup asks for 16 bytes and cannot produce it), a trickling device made no
        // progress within its read budget, and a missing device is an absent one.
        EntropyError::RequestTooLarge { .. } => "invalid",
        EntropyError::ReadBudget { .. } => "no_progress",
        EntropyError::DeviceAbsent => "absent",
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

    /// What a person may safely do about this refusal, in words (see [`safe_next_action`]). `is_retryable` is a fact about the error;
    /// this is the instruction, and it says to start again only where retrying can help.
    #[must_use]
    pub fn safe_next_action(&self) -> &'static str {
        safe_next_action(self.capability(), self.code()).unwrap_or(ACTION_REPORT)
    }
}

// ---- the safe next action of each refusal --------------------------------------------------------------------------------------
// Bead acceptance: the diagnostics "name the unavailable capability and the safe next action, without leaking system secrets". The
// `FFW_PLATFORM:*` marker lines name the capability and the typed reason; the words below say what to do about it. Each text is
// plain ASCII with no digit, no `=` and no path, so it cannot carry an address, a value or a forged marker, and each says what the
// speaker will NOT do in place of the missing capability (no wall time, no weaker entropy, no second wake mechanism).

/// The one refusal that is a wait and not a stop (`not_seeded`): the caller decides how long to wait.
const ACTION_RETRY: &str = "Start again later: the kernel has not seeded its random pool yet. The speaker neither waits nor substitutes another entropy source, so the caller decides how long to wait.";
const ACTION_WRONG_BUILD: &str = "Do not start. This build is not wired to the device kernel backend for this board. Use the device build for big-endian MIPS or PowerPC that matches the board; a simulated or mismatched backend is never accepted.";
const ACTION_NOT_ADMITTED: &str = "Do not start. This kernel has no qualified profile for the platform layer. Run a kernel image with a matching admitted profile; compatibility stays unqualified until one is recorded.";
const ACTION_WAKE_ABSENT: &str = "Do not start. The kernel does not provide the wakeup call the profile selects. Use a kernel that provides it; the speaker never tries another mechanism in its place.";
const ACTION_WAKE_OPEN_FAILED: &str = "Do not start. The selected wake source could not be opened. Keep this output and report the failure to the platform owner; the speaker never substitutes another mechanism.";
const ACTION_CLOCK_ABSENT: &str = "Do not start. The kernel does not provide the monotonic clock call. Use a kernel that provides it; the speaker never falls back to wall time.";
const ACTION_ENTROPY_ABSENT: &str = "Do not start. The kernel does not provide secure entropy through the selected provider. Use a kernel that does; the speaker never falls back to a weaker source.";
const ACTION_ENTROPY_UNQUALIFIED: &str = "Do not start. The profile does not qualify the selected entropy provider on this kernel. A provider needs its own recorded evidence; the speaker never switches to another one.";
/// Every other refusal means the platform answered something it should not: nothing a person can safely change, so stop and report.
const ACTION_REPORT: &str = "Do not start and do not work around it. The platform gave an answer it should not give. Keep this output and give it to the platform owner.";

/// Whether `code` is a member of [`REASON_CODES`] for `capability`.
fn is_reason_code(capability: Capability, code: &str) -> bool {
    REASON_CODES
        .iter()
        .any(|(name, codes)| *name == capability.name() && codes.contains(&code))
}

/// The safe next action for the refusal `capability:code`, or `None` when `code` is not a reason code of that capability. One text per
/// reason code, and only `entropy:not_seeded` says to start again.
#[must_use]
pub fn safe_next_action(capability: Capability, code: &str) -> Option<&'static str> {
    if !is_reason_code(capability, code) {
        return None;
    }
    Some(match (capability, code) {
        (Capability::Entropy, "not_seeded") => ACTION_RETRY,
        (Capability::Kernel, "simulated_backend" | "no_abi" | "unknown_abi" | "abi_mismatch") => {
            ACTION_WRONG_BUILD
        }
        (Capability::Kernel, "not_admitted") => ACTION_NOT_ADMITTED,
        (Capability::Kernel, "wake_open_failed") => ACTION_WAKE_OPEN_FAILED,
        (Capability::Wake, "absent") => ACTION_WAKE_ABSENT,
        (Capability::Clock, "absent") => ACTION_CLOCK_ABSENT,
        (Capability::Entropy, "absent") => ACTION_ENTROPY_ABSENT,
        (Capability::Entropy, "unavailable") => ACTION_ENTROPY_UNQUALIFIED,
        _ => ACTION_REPORT,
    })
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
    /// The entropy provider the caller selected. Anything but the default is printed on the `ENTROPY` line (`provider=`), so a
    /// transcript always shows which provider produced (or refused) its entropy.
    pub entropy_selection: EntropySelection,
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
    fn new(
        backend: Provenance,
        kernel_release: String,
        entropy_selection: EntropySelection,
    ) -> Self {
        Self {
            abi: None,
            evidence: None,
            backend,
            kernel_release,
            layer_provenance: None,
            mechanism: None,
            entropy_selection,
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

    /// The safe next action for the first refusal ([`safe_next_action`]), or `None` when nothing was refused.
    #[must_use]
    pub fn next_action(&self) -> Option<&'static str> {
        self.first_refusal()
            .and_then(|(capability, code)| safe_next_action(capability, code))
    }

    /// One human line for the first refusal: the unavailable capability, its reason code and the safe next action; `None` when nothing
    /// was refused. It is a diagnostic for a person and is **not** one of the [`Self::markers`]: the judged `--platform-startup` step is
    /// compared byte for byte against what the guest measured, so nothing is added to its output.
    #[must_use]
    pub fn diagnostic(&self) -> Option<String> {
        let (capability, code) = self.first_refusal()?;
        let action = safe_next_action(capability, code)?;
        Some(format!(
            "platform startup refused: capability {} unavailable, reason {code}. {action}",
            capability.name()
        ))
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
                "FFW_PLATFORM:ENTROPY status={} provenance={layer}{}{}",
                self.entropy.status(),
                self.entropy_selection
                    .marker_provider()
                    .map(|name| format!(" provider={name}"))
                    .unwrap_or_default(),
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

/// Build the platform layer over `ops` with the default entropy provider ([`EntropySelection::Getrandom`]): [`bring_up_with`] with the
/// default selection, so every start that does not name another provider is exactly what it was before the legacy provider existed.
///
/// # Errors
/// A [`StartupError`], whose [`StartupError::code`] is the `reason=` of the refusing line.
pub fn bring_up<O: KernelOps>(
    ops: O,
    running_release: Option<&str>,
) -> (Result<PlatformLayer<O>, StartupError>, StartupReport) {
    bring_up_with(ops, running_release, EntropySelection::Getrandom)
}

/// Build the platform layer over `ops`, with the entropy provider the caller **named**. **The one place a layer is built**: the device
/// speaker's every start calls this (through [`bring_up_device_with`]), and so does the generic check the unit tests drive.
///
/// `running_release` is the kernel's release as read, if it could be read; it is only recorded (see [`sanitize_kernel`]).
/// `selection` is applied after admission and makes no kernel call; a layer whose selection the profile does not qualify refuses its
/// entropy capability (`unavailable`) without one. Returns the live layer when every capability passed, or the first typed refusal;
/// the report always says what happened to each capability. A refused backend is never called.
///
/// # Errors
/// A [`StartupError`], whose [`StartupError::code`] is the `reason=` of the refusing line.
pub fn bring_up_with<O: KernelOps>(
    ops: O,
    running_release: Option<&str>,
    selection: EntropySelection,
) -> (Result<PlatformLayer<O>, StartupError>, StartupReport) {
    let backend = ops.provenance();
    let mut report = StartupReport::new(backend, sanitize_kernel(running_release), selection);
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
        Ok(layer) => layer.with_entropy_profile(selection.profile()),
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
    bring_up_device_with(EntropySelection::Getrandom)
}

/// [`bring_up_device`] with the entropy provider the caller **named** (`--entropy-provider`): **the one place `LinuxKernel` is
/// constructed**. The default call above is this one with [`EntropySelection::Getrandom`].
#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
pub fn bring_up_device_with(
    selection: EntropySelection,
) -> (
    Result<PlatformLayer<franken_platform_linux::LinuxKernel>, StartupError>,
    StartupReport,
) {
    bring_up_with(
        franken_platform_linux::LinuxKernel::new(),
        read_running_release().as_deref(),
        selection,
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
    check_device_with(EntropySelection::Getrandom)
}

/// `--platform-startup --entropy-provider <name>` on a device build: [`bring_up_device_with`], released, as a report.
#[cfg(all(
    target_os = "linux",
    target_endian = "big",
    target_pointer_width = "32",
    any(target_arch = "mips", target_arch = "powerpc")
))]
#[must_use]
pub fn check_device_with(selection: EntropySelection) -> StartupReport {
    finish_check(bring_up_device_with(selection))
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
    use std::collections::VecDeque;
    use std::rc::Rc;

    const PPC_RELEASE: &str = "4.9.0-0.bpo.6-powerpc";
    const MIPS_RELEASE: &str = "4.19.0-21-4kc-malta";

    #[derive(Default)]
    struct Calls {
        clock: Cell<u32>,
        random: Cell<u32>,
        open: Cell<u32>,
        open_flags: RefCell<Vec<u32>>,
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
                + self.open.get()
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
        /// What `open_dev_random` answers: a descriptor (a number no wake descriptor uses) or `-errno`.
        legacy_open: isize,
        /// The scripted replies of reads on the legacy descriptor, one per call; an empty script answers `-EAGAIN`, an empty pool.
        legacy_reads: VecDeque<(isize, Vec<u8>)>,
        calls: Rc<Calls>,
    }

    /// The descriptor the double's legacy device opens as: distinct from the wake descriptors it hands out (7, 8, 9).
    const LEGACY_FD: isize = 20;

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
                legacy_open: LEGACY_FD,
                legacy_reads: VecDeque::new(),
                calls: Rc::clone(&calls),
            };
            (fake, calls)
        }

        fn kernel(abi: Abi) -> (Self, Rc<Calls>) {
            Self::new(Provenance::Kernel, Some(abi))
        }

        /// A kernel double whose legacy `/dev/random` answers `replies` in order, then `-EAGAIN` (an empty pool).
        fn with_legacy_reads(abi: Abi, replies: &[(isize, &[u8])]) -> (Self, Rc<Calls>) {
            let (mut fake, calls) = Self::kernel(abi);
            fake.legacy_reads = replies
                .iter()
                .map(|(ret, bytes)| (*ret, bytes.to_vec()))
                .collect();
            (fake, calls)
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

        fn open_dev_random(&mut self, flags: u32) -> isize {
            self.calls.open.set(self.calls.open.get() + 1);
            self.calls.open_flags.borrow_mut().push(flags);
            self.legacy_open
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

        fn read(&mut self, fd: i32, buf: &mut [u8]) -> isize {
            self.calls.read.set(self.calls.read.get() + 1);
            if self.legacy_open >= 0 && isize::try_from(fd).is_ok_and(|fd| fd == self.legacy_open) {
                // A read on the legacy descriptor: a scripted reply, or an empty pool.
                let Some((ret, bytes)) = self.legacy_reads.pop_front() else {
                    return -11;
                };
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                return ret;
            }
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

    // ---- the explicitly selected legacy entropy provider at startup (root decision 5126, `ffw-jub` comment 205) ----
    //
    // Logic only: the double's replies are inputs, and a double that declares `Kernel` is not a kernel. The real adapter is the Linux
    // leaf and the proof that it reads `/dev/random` is a QEMU guest run centrally, a different proof class from every test below.

    const LEGACY_TEST_ENV: EntropySelection = EntropySelection::LegacyDevRandomTestEnvironment;

    fn entropy_line(report: &StartupReport) -> String {
        lines(report)[3].clone()
    }

    #[test]
    fn the_default_selection_prints_no_provider_token_and_never_opens_the_legacy_device() {
        for (abi, release) in [(Abi::PowerPc32, PPC_RELEASE), (Abi::Mips32, MIPS_RELEASE)] {
            let (fake, calls) = Fake::kernel(abi);
            let (result, report) = bring_up(fake, Some(release));
            assert!(result.is_ok(), "{abi:?}");
            assert_eq!(report.entropy_selection, EntropySelection::Getrandom);
            assert_eq!(
                entropy_line(&report),
                "FFW_PLATFORM:ENTROPY status=PASS provenance=kernel",
                "{abi:?}: the default line is byte-identical to every committed transcript"
            );
            assert_eq!(calls.random.get(), 1, "{abi:?}");
            assert_eq!(
                calls.open.get(),
                0,
                "{abi:?}: the legacy device is not opened"
            );
        }
    }

    #[test]
    fn a_selected_legacy_provider_in_a_test_environment_starts_through_open_and_never_calls_getrandom()
     {
        for (abi, release, nonblock) in [
            (Abi::PowerPc32, PPC_RELEASE, 0x800u32),
            (Abi::Mips32, MIPS_RELEASE, 0x80u32),
        ] {
            let bytes: Vec<u8> = (1..=16u8).collect();
            let (fake, calls) = Fake::with_legacy_reads(abi, &[(16, bytes.as_slice())]);
            let report = finish_check(bring_up_with(fake, Some(release), LEGACY_TEST_ENV));
            assert!(report.started(), "{abi:?}");
            assert_eq!(
                entropy_line(&report),
                "FFW_PLATFORM:ENTROPY status=PASS provenance=kernel provider=legacy_dev_random_test_environment",
                "{abi:?}"
            );
            assert_eq!(calls.random.get(), 0, "{abi:?}: getrandom was called");
            assert_eq!(calls.open.get(), 1, "{abi:?}");
            assert_eq!(
                *calls.open_flags.borrow(),
                vec![nonblock | franken_platform::abi::O_CLOEXEC],
                "{abi:?}: opened nonblocking"
            );
        }
    }

    #[test]
    fn the_evidence_qualified_legacy_provider_is_refused_unavailable_without_any_entropy_call() {
        // The committed guest evidence has no observation of the legacy device, so naming the provider without a test environment is
        // refused: no downgrade, no attempt, and the other capabilities still run and pass.
        for (abi, release) in [(Abi::PowerPc32, PPC_RELEASE), (Abi::Mips32, MIPS_RELEASE)] {
            let (fake, calls) = Fake::kernel(abi);
            let (result, report) =
                bring_up_with(fake, Some(release), EntropySelection::LegacyDevRandom);
            let unavailable = StartupError::Entropy(EntropyError::Unavailable {
                status: CapabilityStatus::UnqualifiedPendingStockGuest,
            });
            let Err(error) = result else {
                panic!("{abi:?}: an unqualified provider must be refused");
            };
            assert_eq!(error, unavailable, "{abi:?}");
            assert!(
                !error.is_retryable(),
                "{abi:?}: waiting does not qualify a provider"
            );
            assert_eq!(report.entropy, Outcome::Refused("unavailable"));
            assert_eq!((report.clock, report.wake), (Outcome::Pass, Outcome::Pass));
            assert_eq!(
                entropy_line(&report),
                "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel provider=legacy_dev_random reason=unavailable"
            );
            assert_eq!(
                report.first_refusal(),
                Some((Capability::Entropy, "unavailable"))
            );
            assert_eq!(
                (calls.open.get(), calls.random.get()),
                (0, 0),
                "{abi:?}: neither /dev/random nor getrandom was called"
            );
        }
    }

    #[test]
    fn an_empty_legacy_pool_is_waiting_and_retryable_with_the_provider_shown_and_no_getrandom() {
        // No scripted reads: the double's legacy device answers EAGAIN, an empty pool.
        let (fake, calls) = Fake::kernel(Abi::Mips32);
        let (result, report) = bring_up_with(fake, Some(MIPS_RELEASE), LEGACY_TEST_ENV);
        let Err(error) = result else {
            panic!("an empty pool must refuse");
        };
        assert_eq!(error, StartupError::Entropy(EntropyError::NotSeeded));
        assert!(error.is_retryable());
        assert_eq!(
            entropy_line(&report),
            "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel provider=legacy_dev_random_test_environment reason=not_seeded"
        );
        assert_eq!(
            report.markers().lines().last(),
            Some("FFW_PLATFORM:END started=0 refused=entropy:not_seeded")
        );
        assert_eq!(report.exit_status(), EXIT_REFUSED);
        assert_eq!((calls.open.get(), calls.random.get()), (1, 0));
    }

    #[test]
    fn a_missing_legacy_device_and_a_failed_read_keep_their_own_typed_refusals() {
        let (mut fake, calls) = Fake::kernel(Abi::Mips32);
        fake.legacy_open = -2;
        let (result, report) = bring_up_with(fake, Some(MIPS_RELEASE), LEGACY_TEST_ENV);
        assert_eq!(
            result.err(),
            Some(StartupError::Entropy(EntropyError::DeviceAbsent))
        );
        assert_eq!(report.entropy, Outcome::Refused("absent"));
        assert_eq!(
            calls.random.get(),
            0,
            "a missing device is not a reason to call getrandom"
        );

        let no_bytes: &[u8] = &[];
        let (fake, calls) = Fake::with_legacy_reads(Abi::PowerPc32, &[(-5, no_bytes)]);
        let (result, report) = bring_up_with(fake, Some(PPC_RELEASE), LEGACY_TEST_ENV);
        assert_eq!(
            result.err(),
            Some(StartupError::Entropy(EntropyError::Failed(5)))
        );
        assert_eq!(report.entropy, Outcome::Refused("failed"));
        assert_eq!(calls.random.get(), 0);
    }

    #[test]
    fn a_getrandom_failure_at_startup_never_opens_the_legacy_device() {
        for (abi, release, errno) in [
            (Abi::PowerPc32, PPC_RELEASE, -11isize),
            (Abi::PowerPc32, PPC_RELEASE, -22),
            (Abi::Mips32, MIPS_RELEASE, -89),
        ] {
            let (mut fake, calls) = Fake::kernel(abi);
            fake.random = Random::Errno(errno);
            let (_result, report) = bring_up(fake, Some(release));
            assert!(
                matches!(report.entropy, Outcome::Refused(_)),
                "{abi:?} {errno}"
            );
            assert_eq!(calls.random.get(), 1, "{abi:?} {errno}");
            assert_eq!(
                calls.open.get(),
                0,
                "{abi:?} {errno}: getrandom failing must not select /dev/random"
            );
            assert!(
                !entropy_line(&report).contains("provider="),
                "{abi:?} {errno}: nothing selected another provider"
            );
        }
    }

    #[test]
    fn the_command_line_selects_a_provider_only_by_naming_it_and_refuses_everything_else() {
        let args =
            |list: &[&str]| -> Vec<String> { list.iter().map(|s| (*s).to_string()).collect() };
        assert_eq!(
            parse_startup_args(&args(&[])),
            Ok(EntropySelection::Getrandom)
        );
        assert_eq!(
            parse_startup_args(&args(&["--entropy-provider", "getrandom"])),
            Ok(EntropySelection::Getrandom)
        );
        assert_eq!(
            parse_startup_args(&args(&["--entropy-provider", "legacy-dev-random"])),
            Ok(EntropySelection::LegacyDevRandom)
        );
        assert_eq!(
            parse_startup_args(&args(&[
                "--entropy-provider=legacy-dev-random-test-environment"
            ])),
            Ok(EntropySelection::LegacyDevRandomTestEnvironment)
        );
        for bad in [
            vec!["--entropy-provider"],
            vec!["--entropy-provider", ""],
            vec!["--entropy-provider", "legacy"],
            vec!["--entropy-provider", "LEGACY-DEV-RANDOM"],
            vec!["--entropy-provider=nope"],
            vec![
                "--entropy-provider",
                "getrandom",
                "--entropy-provider",
                "getrandom",
            ],
            vec!["--entropy-provider", "getrandom", "extra"],
            vec!["--legacy"],
            vec!["legacy-dev-random"],
            vec!["--entropy-provider", "--entropy-provider"],
        ] {
            assert!(
                parse_startup_args(&args(&bad)).is_err(),
                "{bad:?} must be refused, not defaulted"
            );
        }
    }

    #[test]
    fn every_selection_has_one_spelling_and_the_default_alone_has_no_marker_token() {
        for (selection, name) in EntropySelection::ALL.iter().zip(PROVIDER_ARGUMENTS) {
            assert_eq!(EntropySelection::from_argument(name), Some(*selection));
        }
        assert_eq!(EntropySelection::default(), EntropySelection::Getrandom);
        assert_eq!(EntropySelection::Getrandom.marker_provider(), None);
        assert_eq!(
            EntropySelection::LegacyDevRandom.marker_provider(),
            Some("legacy_dev_random")
        );
        assert_eq!(
            LEGACY_TEST_ENV.marker_provider(),
            Some("legacy_dev_random_test_environment")
        );
        assert_eq!(
            EntropySelection::Getrandom.profile(),
            EntropyProfile::Getrandom
        );
        // The evidence-qualified legacy provider is unqualified today: no observation of the device exists.
        assert_eq!(
            EntropySelection::LegacyDevRandom.profile(),
            EntropyProfile::LegacyDevRandom(ProviderQualification::Unqualified)
        );
        assert_eq!(
            LEGACY_TEST_ENV.profile(),
            EntropyProfile::LegacyDevRandom(ProviderQualification::TestEnvironment)
        );
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
        // A kernel without eventfd2 answers -ENOSYS in its own ABI's number (38 on PowerPC, 89 on MIPS o32); the speaker refuses on that
        // probe result, the same typed refusal on both profiles, and does not look at a version string.
        for (abi, enosys) in [(Abi::PowerPc32, -38_isize), (Abi::Mips32, -89)] {
            let (mut fake, calls) = Fake::kernel(abi);
            fake.eventfd_error = Some(enosys);
            let (result, report) = bring_up(fake, Some("2.6.14.7"));
            let error = result.err().expect("refused");
            assert_eq!(error.capability(), Capability::Kernel, "{abi:?}");
            assert_eq!(error.code(), "wake_open_failed", "{abi:?}");
            assert_eq!(
                report.kernel,
                Outcome::Refused("wake_open_failed"),
                "{abi:?}"
            );
            // Nothing could be tried without a layer, and every NOT_RUN follows an earlier REFUSED.
            assert_eq!(
                (report.clock, report.entropy, report.wake),
                (Outcome::NotRun, Outcome::NotRun, Outcome::NotRun),
                "{abi:?}"
            );
            assert_eq!(
                calls.eventfd.get(),
                1,
                "{abi:?}: no other wake mechanism was tried"
            );
            assert_eq!(calls.pipe.get(), 0, "{abi:?}");
            assert_eq!(report.layer_provenance, None, "{abi:?}");
            assert!(
                report
                    .markers()
                    .ends_with("FFW_PLATFORM:END started=0 refused=kernel:wake_open_failed\n"),
                "{abi:?}"
            );
            // The same unavailable capability, named with the same safe next action, on both profiles.
            assert_eq!(
                report.next_action(),
                Some(ACTION_WAKE_OPEN_FAILED),
                "{abi:?}"
            );
            assert_eq!(error.safe_next_action(), ACTION_WAKE_OPEN_FAILED, "{abi:?}");
        }
    }

    #[test]
    fn a_clock_that_is_absent_is_a_typed_refusal_and_the_other_capabilities_are_still_tried() {
        // Each profile's own ENOSYS (PowerPC 38, MIPS o32 89): the same typed refusal, the same marker, the same next action.
        for (abi, release, enosys) in [
            (Abi::PowerPc32, PPC_RELEASE, -38_isize),
            (Abi::Mips32, MIPS_RELEASE, -89),
        ] {
            let (mut fake, calls) = Fake::kernel(abi);
            fake.clock_error = Some(enosys);
            let (result, report) = bring_up(fake, Some(release));
            assert_eq!(
                result.err(),
                Some(StartupError::Clock(ClockError::Absent)),
                "{abi:?}"
            );
            assert_eq!(report.clock, Outcome::Refused("absent"), "{abi:?}");
            assert_eq!(
                (report.entropy, report.wake),
                (Outcome::Pass, Outcome::Pass),
                "{abi:?}"
            );
            assert_eq!(
                report.first_refusal(),
                Some((Capability::Clock, "absent")),
                "{abi:?}"
            );
            assert!(
                report
                    .markers()
                    .ends_with("FFW_PLATFORM:END started=0 refused=clock:absent\n"),
                "{abi:?}"
            );
            assert_eq!(
                calls.clock.get(),
                1,
                "{abi:?}: a clock that is absent is asked once, not worked around"
            );
            assert_eq!(report.next_action(), Some(ACTION_CLOCK_ABSENT), "{abi:?}");
            let line = report.diagnostic().expect("a refusal has a diagnostic");
            assert!(
                line.contains("capability clock unavailable, reason absent."),
                "{abi:?}: {line}"
            );
            assert!(line.ends_with(ACTION_CLOCK_ABSENT), "{abi:?}: {line}");
        }
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

    // ---- every refusal has one safe next action in words, and only a wait says to start again ----

    type ActionFn = fn(Capability, &str) -> Option<&'static str>;

    fn capability_named(name: &str) -> Capability {
        [
            Capability::Kernel,
            Capability::Clock,
            Capability::Entropy,
            Capability::Wake,
        ]
        .into_iter()
        .find(|capability| capability.name() == name)
        .expect("REASON_CODES names a known capability")
    }

    /// The verdict on a table of next actions: one for every reason code of every capability; exactly `entropy:not_seeded` says to start
    /// again and every other one says to stop; and each is safe to log (ASCII, no digit, no `=`, no path, short, one sentence run).
    fn judge_next_actions(action: ActionFn) -> Result<(), String> {
        for (name, codes) in REASON_CODES {
            let capability = capability_named(name);
            for code in codes {
                let Some(text) = action(capability, code) else {
                    return Err(format!("ACTION-MISSING: {name}:{code} has no next action"));
                };
                let waits = (name, *code) == ("entropy", "not_seeded");
                if text.starts_with("Start again later") != waits {
                    return Err(format!(
                        "ACTION-RETRY-MISMATCH: {name}:{code} says {text:?}, and only entropy:not_seeded may say to start again"
                    ));
                }
                if !waits && !text.starts_with("Do not start") {
                    return Err(format!("ACTION-NOT-A-STOP: {name}:{code} says {text:?}"));
                }
                let unsafe_text = !text.is_ascii()
                    || text.len() > 260
                    || !text.ends_with('.')
                    || text.contains(['=', '/', '\\'])
                    || text.bytes().any(|byte| byte.is_ascii_digit());
                if unsafe_text {
                    return Err(format!("ACTION-UNSAFE-TEXT: {name}:{code} says {text:?}"));
                }
            }
        }
        Ok(())
    }

    /// A plant: the entropy provider that the profile does not qualify has no action.
    fn actions_without_the_unqualified_provider(
        capability: Capability,
        code: &str,
    ) -> Option<&'static str> {
        if (capability, code) == (Capability::Entropy, "unavailable") {
            return None;
        }
        safe_next_action(capability, code)
    }

    /// A plant: every refusal says to start again (what a bare `is_retryable` read as an instruction would invite).
    fn actions_that_always_retry(capability: Capability, code: &str) -> Option<&'static str> {
        safe_next_action(capability, code).map(|_| ACTION_RETRY)
    }

    /// A plant: an action that tells a person to edit a setting.
    fn actions_that_carry_a_setting(capability: Capability, code: &str) -> Option<&'static str> {
        if (capability, code) == (Capability::Clock, "absent") {
            return Some("Do not start. Set clock=realtime in the config file.");
        }
        safe_next_action(capability, code)
    }

    #[test]
    fn every_refusal_code_has_one_safe_next_action_and_only_not_seeded_says_to_start_again() {
        assert_eq!(judge_next_actions(safe_next_action), Ok(()));
        let plants: [(&str, ActionFn, &str); 3] = [
            (
                "no action for an unqualified provider",
                actions_without_the_unqualified_provider,
                "ACTION-MISSING",
            ),
            (
                "always start again",
                actions_that_always_retry,
                "ACTION-RETRY-MISMATCH",
            ),
            (
                "an action that carries a setting",
                actions_that_carry_a_setting,
                "ACTION-UNSAFE-TEXT",
            ),
        ];
        for (name, plant, prefix) in plants {
            let verdict = judge_next_actions(plant);
            assert!(
                verdict.as_ref().is_err_and(|why| why.starts_with(prefix)),
                "the plant `{name}` was not caught: {verdict:?}"
            );
        }
        // A code that is not a reason code of that capability has no action: the table cannot answer for a refusal it does not know.
        assert_eq!(safe_next_action(Capability::Clock, "no_such_code"), None);
        assert_eq!(safe_next_action(Capability::Clock, "not_seeded"), None);
        assert_eq!(safe_next_action(Capability::Wake, ""), None);
    }

    #[test]
    fn a_startup_error_carries_the_action_of_its_code_and_says_to_start_again_exactly_when_it_is_retryable()
     {
        for error in one_of_each_error() {
            let action = error.safe_next_action();
            assert_eq!(
                Some(action),
                safe_next_action(error.capability(), error.code()),
                "{error}"
            );
            assert_eq!(
                action.starts_with("Start again later"),
                error.is_retryable(),
                "{error}: {action}"
            );
        }
        // The plant for the pairing: a retry flag read as the instruction would tell a clock-less kernel to start again.
        assert!(!StartupError::Clock(ClockError::Absent).is_retryable());
        assert!(
            !StartupError::Clock(ClockError::Absent)
                .safe_next_action()
                .starts_with("Start again")
        );
    }

    #[test]
    fn a_refused_report_names_the_capability_the_reason_and_the_next_action_and_the_markers_stay_as_they_were()
     {
        for (scenario_name, capability, code, action) in [
            (
                "clock_absent_powerpc",
                "clock",
                "absent",
                ACTION_CLOCK_ABSENT,
            ),
            (
                "wake_source_absent_powerpc",
                "kernel",
                "wake_open_failed",
                ACTION_WAKE_OPEN_FAILED,
            ),
            (
                "mips_entropy_not_seeded",
                "entropy",
                "not_seeded",
                ACTION_RETRY,
            ),
            (
                "simulated_backend_refused",
                "kernel",
                "simulated_backend",
                ACTION_WRONG_BUILD,
            ),
        ] {
            let report = scenario(scenario_name);
            assert_eq!(report.next_action(), Some(action), "{scenario_name}");
            let line = report.diagnostic().expect("a refusal has a diagnostic");
            assert_eq!(
                line,
                format!(
                    "platform startup refused: capability {capability} unavailable, reason {code}. {action}"
                ),
                "{scenario_name}"
            );
            assert!(!line.contains('\n'), "{scenario_name}: one line");
            // The judged step's output is compared byte for byte: the action is never one of the marker lines.
            assert!(!report.markers().contains(action), "{scenario_name}");
        }
        for started in ["powerpc_all_pass", "mips_all_pass"] {
            let report = scenario(started);
            assert_eq!(report.next_action(), None, "{started}");
            assert_eq!(report.diagnostic(), None, "{started}");
        }
    }

    #[test]
    fn an_entropy_call_that_is_absent_or_degenerate_is_refused_not_papered_over() {
        // (profile, its release, its own ENOSYS, the other profile's ENOSYS number)
        for (abi, release, enosys, other) in [
            (Abi::PowerPc32, PPC_RELEASE, 38_i32, 89_i32),
            (Abi::Mips32, MIPS_RELEASE, 89, 38),
        ] {
            let (mut fake, _) = Fake::kernel(abi);
            fake.random = Random::Errno(-(enosys as isize));
            let (result, report) = bring_up(fake, Some(release));
            assert_eq!(
                result.err(),
                Some(StartupError::Entropy(EntropyError::Absent)),
                "{abi:?}"
            );
            assert_eq!(report.entropy, Outcome::Refused("absent"), "{abi:?}");
            assert_eq!(report.next_action(), Some(ACTION_ENTROPY_ABSENT), "{abi:?}");
            // The other ABI's number is not absence on this one.
            let (mut fake, _) = Fake::kernel(abi);
            fake.random = Random::Errno(-(other as isize));
            let (result, report) = bring_up(fake, Some(release));
            assert_eq!(
                result.err(),
                Some(StartupError::Entropy(EntropyError::Failed(other))),
                "{abi:?}"
            );
            assert_eq!(report.entropy, Outcome::Refused("failed"), "{abi:?}");
            // A failure that is not an absence is not told it can be fixed by a different kernel: stop and report.
            assert_eq!(report.next_action(), Some(ACTION_REPORT), "{abi:?}");
        }
    }

    #[test]
    fn a_wake_open_resource_or_permission_failure_does_not_claim_the_call_is_absent() {
        for abi in [Abi::PowerPc32, Abi::Mips32] {
            // ENOMEM, EMFILE, EACCES have the same numbers on both admitted ABIs.
            for errno in [12_isize, 24, 13] {
                let (mut fake, calls) = Fake::kernel(abi);
                fake.eventfd_error = Some(-errno);
                let (result, report) = bring_up(fake, None);
                let error = result.err().expect("wake open must fail");
                assert_eq!(error.code(), "wake_open_failed");
                assert_eq!(error.safe_next_action(), ACTION_WAKE_OPEN_FAILED);
                assert_eq!(report.next_action(), Some(ACTION_WAKE_OPEN_FAILED));
                let line = report.diagnostic().expect("a refusal has advice");
                assert!(
                    !line.contains("does not provide"),
                    "{abi:?} errno{errno}: {line}"
                );
                assert!(
                    !line.contains("Use a kernel"),
                    "{abi:?} errno{errno}: {line}"
                );
                assert_eq!(calls.eventfd.get(), 1);
                assert_eq!(calls.pipe.get(), 0);
            }
            let (fake, _) = Fake::kernel(abi);
            assert!(
                bring_up(fake, None).0.is_ok(),
                "{abi:?}: permitted counterpart"
            );
        }
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
            StartupError::Entropy(EntropyError::RequestTooLarge {
                requested: 65,
                max: 64,
            }),
            StartupError::Entropy(EntropyError::ReadBudget { reads: 16 }),
            StartupError::Entropy(EntropyError::DeviceAbsent),
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

    /// The scenarios of `p02_legacy_entropy_markers.json`: each is one explicit selection.
    fn legacy_scenario(name: &str) -> StartupReport {
        match name {
            "legacy_test_environment_all_pass_powerpc" => {
                let bytes: Vec<u8> = (1..=16u8).collect();
                let (fake, _) = Fake::with_legacy_reads(Abi::PowerPc32, &[(16, bytes.as_slice())]);
                finish_check(bring_up_with(fake, Some(PPC_RELEASE), LEGACY_TEST_ENV))
            }
            "legacy_test_environment_not_seeded_mips" => {
                let (fake, _) = Fake::kernel(Abi::Mips32);
                finish_check(bring_up_with(fake, Some(MIPS_RELEASE), LEGACY_TEST_ENV))
            }
            "legacy_evidence_qualified_unavailable_powerpc" => {
                let (fake, _) = Fake::kernel(Abi::PowerPc32);
                finish_check(bring_up_with(
                    fake,
                    Some(PPC_RELEASE),
                    EntropySelection::LegacyDevRandom,
                ))
            }
            "legacy_device_absent_mips" => {
                let (mut fake, _) = Fake::kernel(Abi::Mips32);
                fake.legacy_open = -2;
                finish_check(bring_up_with(fake, Some(MIPS_RELEASE), LEGACY_TEST_ENV))
            }
            "legacy_selected_with_a_simulated_backend_refused" => finish_check(bring_up_with(
                Fake::new(Provenance::Simulated, None).0,
                Some(PPC_RELEASE),
                LEGACY_TEST_ENV,
            )),
            other => panic!("no legacy scenario named {other}"),
        }
    }

    #[test]
    fn the_committed_legacy_marker_examples_are_exactly_what_each_scenario_prints() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/vectors/p02_legacy_entropy_markers.json"
        ))
        .expect("the vector file is JSON");
        assert_eq!(vectors["schema"], "ffw.p02.legacy-entropy-markers.v1");
        // The provider values in the file are exactly the markers the code can print for a non-default selection.
        let committed: Vec<&str> = vectors["provider_values"]
            .as_array()
            .expect("a list of provider values")
            .iter()
            .map(|value| value.as_str().expect("a string"))
            .collect();
        let printable: Vec<&str> = EntropySelection::ALL
            .iter()
            .filter_map(|selection| selection.marker_provider())
            .collect();
        assert_eq!(committed, printable);
        let examples = vectors["examples"].as_object().expect("an examples object");
        for (name, example) in examples {
            let report = legacy_scenario(name);
            let expected: Vec<&str> = example["lines"]
                .as_array()
                .expect("a list of lines")
                .iter()
                .map(|line| line.as_str().expect("a string"))
                .collect();
            let printed = report.markers();
            assert_eq!(printed.lines().collect::<Vec<_>>(), expected, "{name}");
            assert!(printed.ends_with('\n'), "{name}: newline-terminated");
            assert_eq!(
                u64::from(report.exit_status()),
                example["exit"].as_u64().expect("an exit status"),
                "{name}"
            );
        }
        // Every scenario has a committed example, and the file has no example without a scenario.
        let names = [
            "legacy_test_environment_all_pass_powerpc",
            "legacy_test_environment_not_seeded_mips",
            "legacy_evidence_qualified_unavailable_powerpc",
            "legacy_device_absent_mips",
            "legacy_selected_with_a_simulated_backend_refused",
        ];
        for name in names {
            assert!(
                examples.contains_key(name),
                "{name} has no committed example"
            );
        }
        assert_eq!(examples.len(), names.len());
    }
}
