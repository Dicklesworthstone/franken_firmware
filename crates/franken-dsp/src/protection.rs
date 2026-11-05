//! Board protection DSP (`D02` / `ffw-7s0`). Contract: `docs/contracts/d02.md`.
//!
//! A [`ProtectedBoardDsp`] turns canonical stereo blocks into per-driver `i16` channels for one
//! board, but only after a [`BoardCalibration`] for exactly that board has been admitted:
//!
//! * No generic stereo PCM reaches an individual driver: every driver channel has an explicit
//!   route, DC rejection, a crossover/EQ chain, a gain ceiling, a thermal model, a limiter and a
//!   hard output ceiling, and tweeter/woofer/sub roles must pass a stop-band guard.
//! * An unknown board, a missing calibration, a malformed or unstable calibration, or a
//!   provenance that does not match the mode comes up **fail-muted**: it renders silence and
//!   refuses to unmute.
//! * Coefficients are validated in the realization actually used: quantized to `f32`, checked for
//!   stability, with exact L1 gain and rigorous intermediate-range bounds.
//! * Thermal and limiter history live as long as the board: seek, reconnect and source
//!   replacement never reset them; a profile switch drains to silence, swaps, and carries them
//!   over; a faulted board stays muted until it has cooled and is explicitly cleared.
//!
//! Numerical tests do not prove physical protection. Calibration here is synthetic; no real
//! board coefficients exist in this repository.

mod calibration;
mod runtime;
#[cfg(test)]
mod tests;

pub use calibration::{
    BiquadSpec, BoardCalibration, CALIBRATION_SCHEMA, CalibrationProvenance, ChannelCalibration,
    LimiterSpec, ProvenanceKind, RouteSource, ThermalSpec, butterworth2_highpass,
    butterworth2_lowpass, smoothing_coefficient, synthetic_calibration_for,
};
pub use runtime::{BlockReport, DcRejector, Limiter, ProtectedBoardDsp, ProtectedOutput, Section};

/// Most filter sections one driver channel may carry.
pub const MAX_SECTIONS_PER_CHANNEL: usize = 4;
/// Largest accepted coefficient magnitude, measured on the quantized `f32` value.
pub const MAX_COEFFICIENT_ABS: f64 = 8.0;
/// Margin the Jury stability conditions must clear, measured on the quantized coefficients.
pub const STABILITY_MARGIN: f64 = 1.0e-6;
/// Largest admitted L1 norm (worst-case peak gain for `|x| <= 1`) of DC rejection plus sections.
pub const MAX_L1_GAIN: f64 = 8.0;
/// Largest admitted intermediate value (any section output or state) for `|x| <= 1`. A policy
/// bound for the admitted `f32` realization, also enforced at run time as a fault.
pub const MAX_INTERMEDIATE: f64 = 16.0;
/// Samples of impulse response summed to bound a chain's L1 norm.
pub const L1_HORIZON: usize = 8192;
/// Stop-band guard: tweeter roles must attenuate `TWEETER_GUARD_HZ` to at most this magnitude.
pub const TWEETER_GUARD_HZ: f64 = 500.0;
/// Woofer roles must attenuate `WOOFER_GUARD_HZ` to at most `GUARD_MAX_MAGNITUDE`.
pub const WOOFER_GUARD_HZ: f64 = 8_000.0;
/// Sub roles must attenuate `SUB_GUARD_HZ` to at most `GUARD_MAX_MAGNITUDE`.
pub const SUB_GUARD_HZ: f64 = 2_000.0;
/// Magnitude (linear, 0.1 = -20 dB) a role's stop-band guard must reach. Provisional and synthetic.
pub const GUARD_MAX_MAGNITUDE: f64 = 0.1;

/// Which calibrations a board may be admitted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A real board: an attested, non-synthetic profile and a measured/published calibration that
    /// carries an acoustic-qualification reference. Nothing in this repository satisfies it.
    Production,
    /// Offline simulation only: a synthetic fixture profile and a synthetic calibration.
    HostSimulation,
}

/// Named calibration parameter for [`ProtectionError::InvalidParameter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    SampleRate,
    Ramp,
    FaultRamp,
    SourceRamp,
    Trim,
    MaxGain,
    Ceiling,
    DcBlockHz,
    LimiterThreshold,
    LimiterAttack,
    LimiterRelease,
    ThermalTau,
    ThermalSoft,
    ThermalHard,
}

impl Param {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SampleRate => "sample_rate",
            Self::Ramp => "ramp",
            Self::FaultRamp => "fault_ramp",
            Self::SourceRamp => "source_ramp",
            Self::Trim => "trim",
            Self::MaxGain => "max_gain",
            Self::Ceiling => "ceiling",
            Self::DcBlockHz => "dc_block_hz",
            Self::LimiterThreshold => "limiter_threshold",
            Self::LimiterAttack => "limiter_attack",
            Self::LimiterRelease => "limiter_release",
            Self::ThermalTau => "thermal_tau",
            Self::ThermalSoft => "thermal_soft",
            Self::ThermalHard => "thermal_hard",
        }
    }
}

/// Typed, `Copy` refusal. `code()` names are stable and used in receipts and test vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtectionError {
    #[error("no calibration was supplied for this board")]
    NoCalibration,
    #[error("the calibration document is malformed")]
    MalformedCalibration,
    #[error("the calibration schema is not supported")]
    SchemaMismatch,
    #[error("the board is unknown or not admitted for this mode")]
    UnknownBoard,
    /// An appliance with no audio output path (a Bridge): not an audio board at all, so there is
    /// nothing to calibrate or protect. Named separately from a malformed layout on purpose.
    #[error("the appliance has no audio output")]
    NoAudioOutput,
    #[error("the board has no usable driver-channel layout")]
    InvalidLayout,
    #[error("the board's amplifier policy forbids activation")]
    AmplifierForbidden,
    #[error("the calibration is not bound to this profile")]
    ProfileBindingMismatch,
    #[error("the calibration provenance is not admissible in this mode")]
    ProvenanceRefused,
    #[error("the calibration channel count differs from the profile")]
    ChannelCountMismatch,
    #[error("the calibration role of channel {channel} differs from the profile")]
    RoleMismatch { channel: u8 },
    #[error("invalid parameter {parameter:?} (channel {channel:?})")]
    InvalidParameter {
        channel: Option<u8>,
        parameter: Param,
    },
    #[error("channel {channel} carries more than the maximum number of sections")]
    TooManySections { channel: u8 },
    #[error("a coefficient of channel {channel} section {section} is not finite or out of range")]
    CoefficientInvalid { channel: u8, section: u8 },
    #[error("channel {channel} section {section} is not stable in the admitted realization")]
    Unstable { channel: u8, section: u8 },
    #[error("channel {channel} exceeds the admitted worst-case gain")]
    GainBoundExceeded { channel: u8 },
    #[error("channel {channel} exceeds the admitted intermediate range")]
    IntermediateRangeExceeded { channel: u8 },
    #[error("channel {channel} violates its role's stop-band guard")]
    BandPolicyViolated { channel: u8 },
    #[error("unmute refused: the board is not in a state that may produce audio")]
    UnmuteRefused,
    #[error("a protection fault is latched")]
    FaultLatched,
    #[error("the board has not cooled below its thermal soft limit")]
    NotCooled,
}

impl ProtectionError {
    /// Stable machine-readable name of the variant.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NoCalibration => "no_calibration",
            Self::MalformedCalibration => "malformed_calibration",
            Self::SchemaMismatch => "schema_mismatch",
            Self::UnknownBoard => "unknown_board",
            Self::NoAudioOutput => "no_audio_output",
            Self::InvalidLayout => "invalid_layout",
            Self::AmplifierForbidden => "amplifier_forbidden",
            Self::ProfileBindingMismatch => "profile_binding_mismatch",
            Self::ProvenanceRefused => "provenance_refused",
            Self::ChannelCountMismatch => "channel_count_mismatch",
            Self::RoleMismatch { .. } => "role_mismatch",
            Self::InvalidParameter { .. } => "invalid_parameter",
            Self::TooManySections { .. } => "too_many_sections",
            Self::CoefficientInvalid { .. } => "coefficient_invalid",
            Self::Unstable { .. } => "unstable",
            Self::GainBoundExceeded { .. } => "gain_bound_exceeded",
            Self::IntermediateRangeExceeded { .. } => "intermediate_range_exceeded",
            Self::BandPolicyViolated { .. } => "band_policy_violated",
            Self::UnmuteRefused => "unmute_refused",
            Self::FaultLatched => "fault_latched",
            Self::NotCooled => "not_cooled",
        }
    }

    /// Driver channel the error refers to, if any.
    #[must_use]
    pub const fn channel(&self) -> Option<u8> {
        match self {
            Self::RoleMismatch { channel }
            | Self::TooManySections { channel }
            | Self::CoefficientInvalid { channel, .. }
            | Self::Unstable { channel, .. }
            | Self::GainBoundExceeded { channel }
            | Self::IntermediateRangeExceeded { channel }
            | Self::BandPolicyViolated { channel } => Some(*channel),
            Self::InvalidParameter { channel, .. } => *channel,
            _ => None,
        }
    }

    /// Filter section the error refers to, if any.
    #[must_use]
    pub const fn section(&self) -> Option<u8> {
        match self {
            Self::CoefficientInvalid { section, .. } | Self::Unstable { section, .. } => {
                Some(*section)
            }
            _ => None,
        }
    }

    /// Calibration parameter the error refers to, if any.
    #[must_use]
    pub const fn parameter(&self) -> Option<&'static str> {
        match self {
            Self::InvalidParameter { parameter, .. } => Some(parameter.name()),
            _ => None,
        }
    }
}

/// A protection fault detected while rendering. Latched until [`ProtectedBoardDsp::clear_fault`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCode {
    /// A filter produced NaN or infinity; the channel is silenced immediately.
    NonFiniteState { channel: u8 },
    /// A value left the admitted intermediate range; the channel is silenced immediately.
    StateRange { channel: u8 },
    /// The thermal model reached its hard limit; the board ramps to silence.
    ThermalHard { channel: u8 },
}

impl FaultCode {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NonFiniteState { .. } => "non_finite_state",
            Self::StateRange { .. } => "state_range",
            Self::ThermalHard { .. } => "thermal_hard",
        }
    }

    #[must_use]
    pub const fn channel(&self) -> u8 {
        match self {
            Self::NonFiniteState { channel }
            | Self::StateRange { channel }
            | Self::ThermalHard { channel } => *channel,
        }
    }
}

/// Whether a board may currently produce audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardStatus {
    /// Admitted and running; the user's mute and gain apply.
    Active,
    /// Not admitted (or switched to an unsafe profile): renders silence, refuses to unmute.
    FailMuted(ProtectionError),
    /// A protection fault is latched: ramps to silence and stays silent.
    Faulted(FaultCode),
}

impl BoardStatus {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::FailMuted(_) => "fail_muted",
            Self::Faulted(_) => "faulted",
        }
    }
}

/// A discontinuity in the source feeding the board. Board-lifetime protection history is never
/// reset by any of them; only a fade-in from silence is applied (see the contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEvent {
    Seek,
    Reconnect,
    SourceReplaced,
}
