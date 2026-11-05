//! Calibration documents and their validation (`D02`). Everything here runs on the control path
//! and may allocate; nothing here is called while rendering.

use super::{
    Admission, GUARD_MAX_MAGNITUDE, L1_HORIZON, MAX_COEFFICIENT_ABS, MAX_INTERMEDIATE, MAX_L1_GAIN,
    MAX_SECTIONS_PER_CHANNEL, Param, ProtectionError, STABILITY_MARGIN, SUB_GUARD_HZ,
    TWEETER_GUARD_HZ, WOOFER_GUARD_HZ,
};
use crate::{CANONICAL_SAMPLE_RATE_HZ, MAX_HARDWARE_CHANNELS};
use franken_board_profile::{AmplifierPolicy, BoardProfile, FactStatus, TransducerRole};
use serde::{Deserialize, Serialize};
use std::f64::consts::{PI, SQRT_2};

/// Schema identifier every calibration document must carry.
pub const CALIBRATION_SCHEMA: &str = "ffw.d02.calibration.v1";

/// Where a calibration came from. `Synthetic` is fabricated for offline simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    Synthetic,
    OwnerMeasured,
    PublishedDatasheet,
}

/// Calibration provenance, preserved with the running board. Acoustic qualification is a separate
/// receipt that numerical validation can never replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationProvenance {
    pub kind: ProvenanceKind,
    /// Where the numbers come from (a fixture name, a measurement receipt id, a datasheet).
    pub reference: String,
    /// Receipt id of the acoustic qualification that covers this calibration, if any.
    #[serde(default)]
    pub acoustic_qualification: Option<String>,
}

/// Which input signal feeds a driver channel. There is no implicit stereo-to-driver mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    Left,
    Right,
    /// `0.5 * (left + right)`.
    Mid,
}

/// One second-order section with `a0` normalised to 1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BiquadSpec {
    pub b0: f64,
    pub b1: f64,
    pub b2: f64,
    pub a1: f64,
    pub a2: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimiterSpec {
    /// Linear level above which gain reduction starts, `0.01..=ceiling`.
    pub threshold: f64,
    pub attack_ms: f64,
    pub release_ms: f64,
}

/// Leaky mean-square model: `level += alpha * (v*v - level)`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalSpec {
    pub tau_s: f64,
    /// Mean-square level above which output is scaled by `sqrt(soft / level)`.
    pub soft_ms: f64,
    /// Mean-square level at which the board latches a thermal fault.
    pub hard_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCalibration {
    pub role: TransducerRole,
    pub source: RouteSource,
    pub trim: f64,
    /// Highest linear gain `trim * user_gain` may reach for this driver.
    pub max_gain: f64,
    /// Hard output ceiling (linear, at most 1.0).
    pub ceiling: f64,
    pub dc_block_hz: f64,
    pub sections: Vec<BiquadSpec>,
    pub limiter: LimiterSpec,
    pub thermal: ThermalSpec,
}

/// A calibration for exactly one board profile (bound by id and integrity digest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardCalibration {
    pub schema: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub provenance: CalibrationProvenance,
    pub sample_rate_hz: u32,
    pub ramp_ms: f64,
    pub fault_ramp_ms: f64,
    pub source_ramp_ms: f64,
    pub channels: Vec<ChannelCalibration>,
}

impl BoardCalibration {
    /// Parse a calibration document. Unknown fields, wrong types and missing fields are refused.
    pub fn from_json(text: &str) -> Result<Self, ProtectionError> {
        serde_json::from_str(text).map_err(|_| ProtectionError::MalformedCalibration)
    }
}

/// Second-order Butterworth low-pass (bilinear transform, `Q = 1/sqrt(2)`). Synthetic design aid.
#[must_use]
pub fn butterworth2_lowpass(fc_hz: f64, fs_hz: f64) -> BiquadSpec {
    let k = (PI * fc_hz / fs_hz).tan();
    let norm = 1.0 / (1.0 + SQRT_2 * k + k * k);
    let b0 = k * k * norm;
    BiquadSpec {
        b0,
        b1: 2.0 * b0,
        b2: b0,
        a1: 2.0 * (k * k - 1.0) * norm,
        a2: (1.0 - SQRT_2 * k + k * k) * norm,
    }
}

/// Second-order Butterworth high-pass (bilinear transform). Synthetic design aid.
#[must_use]
pub fn butterworth2_highpass(fc_hz: f64, fs_hz: f64) -> BiquadSpec {
    let k = (PI * fc_hz / fs_hz).tan();
    let norm = 1.0 / (1.0 + SQRT_2 * k + k * k);
    BiquadSpec {
        b0: norm,
        b1: -2.0 * norm,
        b2: norm,
        a1: 2.0 * (k * k - 1.0) * norm,
        a2: (1.0 - SQRT_2 * k + k * k) * norm,
    }
}

/// `1 - exp(-1 / (time_ms * fs / 1000))`: the one-pole smoothing coefficient for a time constant.
/// A non-positive or non-finite time constant yields `1.0` (instantaneous).
#[must_use]
pub fn smoothing_coefficient(time_ms: f64, fs_hz: f64) -> f32 {
    let samples = time_ms * 1.0e-3 * fs_hz;
    if !(samples.is_finite() && samples > 0.0) {
        return 1.0;
    }
    (1.0 - (-1.0 / samples).exp()) as f32
}

/// A SYNTHETIC calibration for a fixture profile: Butterworth crossovers per role with
/// conservative limiter and thermal parameters. Never real board data; its provenance says so, and
/// [`Admission::Production`] refuses it.
#[must_use]
pub fn synthetic_calibration_for(profile: &BoardProfile) -> BoardCalibration {
    let fs = f64::from(CANONICAL_SAMPLE_RATE_HZ);
    let channels = profile
        .channel_routing
        .iter()
        .map(|&role| synthetic_channel(role, fs))
        .collect();
    BoardCalibration {
        schema: CALIBRATION_SCHEMA.to_string(),
        profile_id: profile.profile_id.clone(),
        profile_digest: profile.integrity_sha256.clone(),
        provenance: CalibrationProvenance {
            kind: ProvenanceKind::Synthetic,
            reference: "synthetic-fixture:d02-v1".to_string(),
            acoustic_qualification: None,
        },
        sample_rate_hz: CANONICAL_SAMPLE_RATE_HZ,
        ramp_ms: 10.0,
        fault_ramp_ms: 2.0,
        source_ramp_ms: 20.0,
        channels,
    }
}

fn synthetic_channel(role: TransducerRole, fs: f64) -> ChannelCalibration {
    let (source, sections) = match role {
        TransducerRole::TweeterLeft => (RouteSource::Left, vec![butterworth2_highpass(2200.0, fs)]),
        TransducerRole::TweeterRight => {
            (RouteSource::Right, vec![butterworth2_highpass(2200.0, fs)])
        }
        TransducerRole::TweeterMono | TransducerRole::ArrayTweeter(_) => {
            (RouteSource::Mid, vec![butterworth2_highpass(2200.0, fs)])
        }
        TransducerRole::MidLeft => (RouteSource::Left, Vec::new()),
        TransducerRole::MidRight => (RouteSource::Right, Vec::new()),
        TransducerRole::ArrayMidWoofer(_) => (RouteSource::Mid, Vec::new()),
        TransducerRole::WooferCenter => (RouteSource::Mid, vec![butterworth2_lowpass(300.0, fs)]),
        TransducerRole::WooferMono => (RouteSource::Mid, vec![butterworth2_lowpass(2000.0, fs)]),
        TransducerRole::SubwooferLfe => (RouteSource::Mid, vec![butterworth2_lowpass(120.0, fs)]),
    };
    ChannelCalibration {
        role,
        source,
        trim: 1.0,
        max_gain: 1.0,
        ceiling: 0.95,
        dc_block_hz: 5.0,
        sections,
        limiter: LimiterSpec {
            threshold: 0.8,
            attack_ms: 1.0,
            release_ms: 80.0,
        },
        thermal: ThermalSpec {
            tau_s: 2.0,
            soft_ms: 0.30,
            hard_ms: 0.90,
        },
    }
}

// ---- validation -------------------------------------------------------------------------------

/// One driver channel after validation, in the exact `f32` values the renderer will use.
#[derive(Debug, Clone)]
pub(super) struct ValidatedChannel {
    pub source: RouteSource,
    pub trim: f32,
    pub max_gain: f32,
    pub ceiling: f32,
    pub dc_r: f32,
    pub sections: Vec<[f32; 5]>,
    pub threshold: f32,
    pub a_attack: f32,
    pub a_release: f32,
    pub thermal_alpha: f32,
    pub thermal_soft: f32,
    pub thermal_hard: f32,
}

/// A whole board after validation.
#[derive(Debug, Clone)]
pub(super) struct ValidatedBoard {
    pub provenance: CalibrationProvenance,
    pub channels: Vec<ValidatedChannel>,
    pub ramp_step: f32,
    pub fault_ramp_step: f32,
    pub source_step: f32,
}

fn in_range(value: f64, lo: f64, hi: f64) -> bool {
    value.is_finite() && value >= lo && value <= hi
}

fn invalid(channel: Option<u8>, parameter: Param) -> ProtectionError {
    ProtectionError::InvalidParameter { channel, parameter }
}

/// The profile must be a usable, admitted audio board for `admission`.
fn gate_profile(profile: &BoardProfile, admission: Admission) -> Result<usize, ProtectionError> {
    let channels = usize::from(profile.hardware_channels);
    // A Bridge has no audio output at all: say so, rather than calling it a malformed layout.
    if channels == 0 {
        return Err(ProtectionError::NoAudioOutput);
    }
    if channels > MAX_HARDWARE_CHANNELS || profile.channel_routing.len() != channels {
        return Err(ProtectionError::InvalidLayout);
    }
    // The more specific reason first: `verify_integrity` also refuses this policy.
    if profile.amplifier_policy == AmplifierPolicy::ForbiddenFailMuted {
        return Err(ProtectionError::AmplifierForbidden);
    }
    if profile.verify_integrity().is_err() {
        return Err(ProtectionError::UnknownBoard);
    }
    let admitted = match admission {
        Admission::Production => {
            profile.activation_blockers().is_empty()
                && profile.facts.calibration == FactStatus::Attested
        }
        Admission::HostSimulation => profile.is_synthetic_fixture(),
    };
    if admitted {
        Ok(channels)
    } else {
        Err(ProtectionError::UnknownBoard)
    }
}

fn check_provenance(
    provenance: &CalibrationProvenance,
    admission: Admission,
) -> Result<(), ProtectionError> {
    let acceptable = match admission {
        Admission::HostSimulation => provenance.kind == ProvenanceKind::Synthetic,
        Admission::Production => {
            provenance.kind != ProvenanceKind::Synthetic
                && !provenance.reference.trim().is_empty()
                && provenance
                    .acoustic_qualification
                    .as_deref()
                    .is_some_and(|receipt| !receipt.trim().is_empty())
        }
    };
    if acceptable {
        Ok(())
    } else {
        Err(ProtectionError::ProvenanceRefused)
    }
}

/// Quantize one section to the `f32` realization and check it there: every coefficient finite
/// after quantization and at most [`MAX_COEFFICIENT_ABS`], and the Jury stability conditions
/// `1+a1+a2`, `1-a1+a2`, `1-a2` all above [`STABILITY_MARGIN`], evaluated on the stored values.
pub(super) fn quantize_section(
    spec: &BiquadSpec,
    channel: u8,
    section: u8,
) -> Result<[f32; 5], ProtectionError> {
    let bad = ProtectionError::CoefficientInvalid { channel, section };
    let raw = [spec.b0, spec.b1, spec.b2, spec.a1, spec.a2];
    let mut stored = [0.0f32; 5];
    for (slot, &value) in stored.iter_mut().zip(raw.iter()) {
        if !value.is_finite() {
            return Err(bad);
        }
        let quantized = value as f32;
        if !quantized.is_finite() || f64::from(quantized).abs() > MAX_COEFFICIENT_ABS {
            return Err(bad);
        }
        *slot = quantized;
    }
    let (a1, a2) = (f64::from(stored[3]), f64::from(stored[4]));
    let stable = 1.0 + a1 + a2 > STABILITY_MARGIN
        && 1.0 - a1 + a2 > STABILITY_MARGIN
        && 1.0 - a2 > STABILITY_MARGIN;
    if stable {
        Ok(stored)
    } else {
        Err(ProtectionError::Unstable { channel, section })
    }
}

fn widen(section: &[f32; 5]) -> [f64; 5] {
    [
        f64::from(section[0]),
        f64::from(section[1]),
        f64::from(section[2]),
        f64::from(section[3]),
        f64::from(section[4]),
    ]
}

/// L1 norm of one section's impulse response over [`L1_HORIZON`] samples (direct form I in `f64`),
/// and whether the response had decayed by the end of the horizon.
fn section_l1(c: &[f64; 5]) -> (f64, bool) {
    let (mut x1, mut x2, mut y1, mut y2) = (0.0f64, 0.0f64, 0.0f64, 0.0f64);
    let mut sum = 0.0f64;
    let mut tail_peak = 0.0f64;
    for n in 0..L1_HORIZON {
        let x = if n == 0 { 1.0 } else { 0.0 };
        let y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2;
        sum += y.abs();
        if n >= L1_HORIZON - 256 {
            tail_peak = tail_peak.max(y.abs());
        }
        x2 = x1;
        x1 = x;
        y2 = y1;
        y1 = y;
    }
    (sum, tail_peak <= 1.0e-6)
}

/// Rigorous worst-case bounds for `|x| <= 1` through the DC rejector (L1 = 2 for `0 < R < 1`) and
/// the sections: `(cascade gain bound, largest intermediate bound, all sections converged)`.
fn chain_bounds(sections: &[[f64; 5]]) -> (f64, f64, bool) {
    let mut x_bound = 2.0f64;
    let mut worst = x_bound;
    let mut converged = true;
    for c in sections {
        let (l1, done) = section_l1(c);
        converged &= done;
        let y_bound = l1 * x_bound;
        let z2 = c[2].abs() * x_bound + c[4].abs() * y_bound;
        let z1 = c[1].abs() * x_bound + c[3].abs() * y_bound + z2;
        worst = worst.max(y_bound).max(z1).max(z2);
        x_bound = y_bound;
    }
    (x_bound, worst, converged)
}

/// `|H(e^{jw})|` of the cascade at `hz`, from the stored coefficients.
fn magnitude(sections: &[[f64; 5]], hz: f64, fs_hz: f64) -> f64 {
    let w = 2.0 * PI * hz / fs_hz;
    let (c1, s1) = (w.cos(), w.sin());
    let (c2, s2) = ((2.0 * w).cos(), (2.0 * w).sin());
    let mut m = 1.0f64;
    for c in sections {
        let (br, bi) = (c[0] + c[1] * c1 + c[2] * c2, -(c[1] * s1 + c[2] * s2));
        let (ar, ai) = (1.0 + c[3] * c1 + c[4] * c2, -(c[3] * s1 + c[4] * s2));
        m *= ((br * br + bi * bi) / (ar * ar + ai * ai)).sqrt();
    }
    m
}

/// The stop-band guard a role must meet: `(frequency, maximum linear magnitude)`.
fn band_guard(role: TransducerRole) -> Option<(f64, f64)> {
    match role {
        TransducerRole::TweeterLeft
        | TransducerRole::TweeterRight
        | TransducerRole::TweeterMono
        | TransducerRole::ArrayTweeter(_) => Some((TWEETER_GUARD_HZ, GUARD_MAX_MAGNITUDE)),
        TransducerRole::WooferCenter | TransducerRole::WooferMono => {
            Some((WOOFER_GUARD_HZ, GUARD_MAX_MAGNITUDE))
        }
        TransducerRole::SubwooferLfe => Some((SUB_GUARD_HZ, GUARD_MAX_MAGNITUDE)),
        TransducerRole::MidLeft | TransducerRole::MidRight | TransducerRole::ArrayMidWoofer(_) => {
            None
        }
    }
}

fn validate_channel(
    index: u8,
    channel: &ChannelCalibration,
    fs: f64,
) -> Result<ValidatedChannel, ProtectionError> {
    let at = Some(index);
    if !in_range(channel.trim, 0.01, 4.0) {
        return Err(invalid(at, Param::Trim));
    }
    if !in_range(channel.max_gain, 0.01, 4.0) {
        return Err(invalid(at, Param::MaxGain));
    }
    if !in_range(channel.ceiling, 0.01, 1.0) {
        return Err(invalid(at, Param::Ceiling));
    }
    if !in_range(channel.dc_block_hz, 1.0, 100.0) {
        return Err(invalid(at, Param::DcBlockHz));
    }
    if !in_range(channel.limiter.threshold, 0.01, channel.ceiling) {
        return Err(invalid(at, Param::LimiterThreshold));
    }
    if !in_range(channel.limiter.attack_ms, 0.05, 100.0) {
        return Err(invalid(at, Param::LimiterAttack));
    }
    if !in_range(channel.limiter.release_ms, 1.0, 5000.0) {
        return Err(invalid(at, Param::LimiterRelease));
    }
    if !in_range(channel.thermal.tau_s, 0.05, 600.0) {
        return Err(invalid(at, Param::ThermalTau));
    }
    if !in_range(channel.thermal.soft_ms, 0.001, 1.0) {
        return Err(invalid(at, Param::ThermalSoft));
    }
    if !(in_range(channel.thermal.hard_ms, 0.001, 4.0)
        && channel.thermal.hard_ms > channel.thermal.soft_ms)
    {
        return Err(invalid(at, Param::ThermalHard));
    }
    if channel.sections.len() > MAX_SECTIONS_PER_CHANNEL {
        return Err(ProtectionError::TooManySections { channel: index });
    }

    let mut stored: Vec<[f32; 5]> = Vec::with_capacity(channel.sections.len());
    for (s, spec) in channel.sections.iter().enumerate() {
        stored.push(quantize_section(spec, index, s as u8)?);
    }
    let wide: Vec<[f64; 5]> = stored.iter().map(widen).collect();

    let (gain_bound, intermediate_bound, converged) = chain_bounds(&wide);
    if !converged || gain_bound > MAX_L1_GAIN {
        return Err(ProtectionError::GainBoundExceeded { channel: index });
    }
    if intermediate_bound > MAX_INTERMEDIATE {
        return Err(ProtectionError::IntermediateRangeExceeded { channel: index });
    }
    if let Some((hz, max_magnitude)) = band_guard(channel.role)
        && magnitude(&wide, hz, fs) > max_magnitude
    {
        return Err(ProtectionError::BandPolicyViolated { channel: index });
    }

    Ok(ValidatedChannel {
        source: channel.source,
        trim: channel.trim as f32,
        max_gain: channel.max_gain as f32,
        ceiling: channel.ceiling as f32,
        dc_r: (-2.0 * PI * channel.dc_block_hz / fs).exp() as f32,
        sections: stored,
        threshold: channel.limiter.threshold as f32,
        a_attack: smoothing_coefficient(channel.limiter.attack_ms, fs),
        a_release: smoothing_coefficient(channel.limiter.release_ms, fs),
        thermal_alpha: smoothing_coefficient(channel.thermal.tau_s * 1000.0, fs),
        thermal_soft: channel.thermal.soft_ms as f32,
        thermal_hard: channel.thermal.hard_ms as f32,
    })
}

/// Validate `calibration` for `profile`. Checks run in a fixed order, so the reported error is
/// deterministic: schema, profile gate, profile binding, provenance, board-wide parameters,
/// channel count, roles, then each channel in order (parameters, sections, gain bound,
/// intermediate range, stop-band guard).
pub(super) fn validate(
    profile: &BoardProfile,
    calibration: &BoardCalibration,
    admission: Admission,
) -> Result<ValidatedBoard, ProtectionError> {
    if calibration.schema != CALIBRATION_SCHEMA {
        return Err(ProtectionError::SchemaMismatch);
    }
    let channel_count = gate_profile(profile, admission)?;
    if calibration.profile_id != profile.profile_id
        || calibration.profile_digest != profile.integrity_sha256
    {
        return Err(ProtectionError::ProfileBindingMismatch);
    }
    check_provenance(&calibration.provenance, admission)?;
    if calibration.sample_rate_hz != CANONICAL_SAMPLE_RATE_HZ {
        return Err(invalid(None, Param::SampleRate));
    }
    if !in_range(calibration.ramp_ms, 1.0, 1000.0) {
        return Err(invalid(None, Param::Ramp));
    }
    if !in_range(calibration.fault_ramp_ms, 0.1, 100.0) {
        return Err(invalid(None, Param::FaultRamp));
    }
    if !in_range(calibration.source_ramp_ms, 1.0, 1000.0) {
        return Err(invalid(None, Param::SourceRamp));
    }
    if calibration.channels.len() != channel_count {
        return Err(ProtectionError::ChannelCountMismatch);
    }
    for (i, (cal, role)) in calibration
        .channels
        .iter()
        .zip(profile.channel_routing.iter())
        .enumerate()
    {
        if cal.role != *role {
            return Err(ProtectionError::RoleMismatch { channel: i as u8 });
        }
    }

    let fs = f64::from(CANONICAL_SAMPLE_RATE_HZ);
    let mut channels = Vec::with_capacity(channel_count);
    for (i, cal) in calibration.channels.iter().enumerate() {
        channels.push(validate_channel(i as u8, cal, fs)?);
    }
    let step = |ms: f64| (1.0 / (ms * 1.0e-3 * fs)).min(1.0) as f32;
    Ok(ValidatedBoard {
        provenance: calibration.provenance.clone(),
        channels,
        ramp_step: step(calibration.ramp_ms),
        fault_ramp_step: step(calibration.fault_ramp_ms),
        source_step: step(calibration.source_ramp_ms),
    })
}
