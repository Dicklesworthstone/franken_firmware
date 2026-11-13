//! Run-time half of `D02`: the realization primitives (`Section`, `DcRejector`, `Limiter`) and
//! the board renderer. `render_into` and everything it calls neither allocate nor panic on any
//! input; the control-path methods (`admit`, `request_profile_switch`) may allocate.

use super::calibration::{
    BiquadSpec, BoardCalibration, CalibrationProvenance, RouteSource, ValidatedBoard,
    ValidatedChannel, dc_pole, quantize_section, validate,
};
use super::{
    Admission, BoardStatus, FaultCode, MAX_INTERMEDIATE, MAX_SECTIONS_PER_CHANNEL, ProtectionError,
    SourceEvent,
};
use crate::{
    FRAMES_PER_BLOCK, HardwareOutputBlock, MAX_HARDWARE_CHANNELS, StereoAudioBlock, unit_f32_to_i16,
};
use franken_board_profile::BoardProfile;

/// Run-time guard on every filter output: the admitted intermediate range, as an `f32`.
const INTERMEDIATE_LIMIT: f32 = MAX_INTERMEDIATE as f32;

/// One second-order section in the admitted realization: coefficients **stored as `f32`**, direct
/// form II transposed arithmetic and state in **`f64`**; the sample enters and leaves as `f32`.
///
/// ```text
/// y  = b0*x + z1
/// z1 = b1*x - a1*y + z2
/// z2 = b2*x - a2*y
/// ```
///
/// Why `f64` state: measured, not assumed. With the same stored coefficients, an `f32` state drifts
/// from an exact evaluation of that very filter by about 6.5e-5 (300 Hz low-pass) and 5.2e-4 (120 Hz)
/// within 512 samples, because the poles sit at radius 0.973 and 0.989 and the roundoff is amplified
/// by roughly `1/(1-r)`. `f64` state removes it (difference below 1e-13). The coefficients stay
/// `f32` on purpose: they are what validation judges (finite, at most 8, stable, bounded), and the
/// reference uses the same stored values. CPU cost: on a soft-float MIPS32r2 guest under QEMU the `f64` state
/// costs about 541 more instructions per section per frame than `f32` (guest instructions, not core cycles; no
/// board clock; `docs/contracts/d02.md`). The PowerPC targets are not measured.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Section {
    b0: f64,
    b1: f64,
    b2: f64,
    a1: f64,
    a2: f64,
    z1: f64,
    z2: f64,
}

impl Section {
    /// Quantize `spec` to `f32` and admit it only if the stored values are finite, in range and
    /// stable (see [`quantize_section`](super::calibration)). State starts at zero.
    pub fn from_spec(spec: &BiquadSpec) -> Result<Self, ProtectionError> {
        quantize_section(spec, 0, 0).map(Self::from_stored)
    }

    /// Widen the stored `f32` coefficients exactly (every `f32` is an `f64`).
    pub(super) const fn from_stored(c: [f32; 5]) -> Self {
        Self {
            b0: c[0] as f64,
            b1: c[1] as f64,
            b2: c[2] as f64,
            a1: c[3] as f64,
            a2: c[4] as f64,
            z1: 0.0,
            z2: 0.0,
        }
    }

    #[must_use]
    pub const fn passthrough() -> Self {
        Self::from_stored([1.0, 0.0, 0.0, 0.0, 0.0])
    }

    #[inline]
    pub fn process(&mut self, x: f32) -> f32 {
        let x = f64::from(x);
        let y = self.b0 * x + self.z1;
        self.z1 = self.b1 * x - self.a1 * y + self.z2;
        self.z2 = self.b2 * x - self.a2 * y;
        y as f32
    }

    pub fn reset(&mut self) {
        self.z1 = 0.0;
        self.z2 = 0.0;
    }

    /// The two state variables `(z1, z2)`.
    #[must_use]
    pub const fn state(&self) -> (f64, f64) {
        (self.z1, self.z2)
    }
}

/// First-order DC rejector `y[n] = x[n] - x[n-1] + R*y[n-1]` with `R = exp(-2*pi*f/fs)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DcRejector {
    r: f32,
    x1: f32,
    y1: f32,
}

impl DcRejector {
    /// `hz` is the -3 dB-ish corner; callers go through calibration validation (`1..=100` Hz).
    #[must_use]
    pub fn new(hz: f64, fs_hz: f64) -> Self {
        Self::with_pole(dc_pole(hz, fs_hz))
    }

    pub(super) const fn with_pole(r: f32) -> Self {
        Self {
            r,
            x1: 0.0,
            y1: 0.0,
        }
    }

    #[inline]
    pub fn process(&mut self, x: f32) -> f32 {
        let y = x - self.x1 + self.r * self.y1;
        self.x1 = x;
        self.y1 = y;
        y
    }

    pub fn reset(&mut self) {
        self.x1 = 0.0;
        self.y1 = 0.0;
    }
}

/// Peak limiter without look-ahead. Per sample, with `a = |v|`:
///
/// ```text
/// target = threshold / a   if a > threshold, else 1
/// coef   = a_attack        if target < gain,  else a_release
/// gain  += (target - gain) * coef
/// out    = v * gain
/// ```
///
/// With no look-ahead the first samples of a burst pass before the gain has fallen, so the
/// board's hard output ceiling (applied after the limiter and counted) bounds the output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limiter {
    threshold: f32,
    a_attack: f32,
    a_release: f32,
    gain: f32,
}

impl Limiter {
    /// Coefficients come from [`smoothing_coefficient`](super::smoothing_coefficient).
    #[must_use]
    pub const fn new(threshold: f32, a_attack: f32, a_release: f32) -> Self {
        Self {
            threshold,
            a_attack,
            a_release,
            gain: 1.0,
        }
    }

    #[inline]
    pub fn process(&mut self, v: f32) -> f32 {
        let a = v.abs();
        let target = if a > self.threshold && a > 0.0 {
            self.threshold / a
        } else {
            1.0
        };
        let coef = if target < self.gain {
            self.a_attack
        } else {
            self.a_release
        };
        self.gain += (target - self.gain) * coef;
        v * self.gain
    }

    /// Current gain, `1.0` when not limiting.
    #[must_use]
    pub const fn gain(&self) -> f32 {
        self.gain
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Thermal {
    alpha: f32,
    soft: f32,
    hard: f32,
    level: f32,
}

#[derive(Debug, Clone, Copy)]
enum FaultKind {
    NonFinite,
    StateRange,
    ThermalHard,
}

fn classify(x: f32) -> Option<FaultKind> {
    if !x.is_finite() {
        Some(FaultKind::NonFinite)
    } else if x.abs() > INTERMEDIATE_LIMIT {
        Some(FaultKind::StateRange)
    } else {
        None
    }
}

struct BlockStats {
    min_limiter_gain: f32,
    thermal_scaled: u32,
    clipped: u32,
    input_non_finite: u32,
}

fn clean(x: f32, stats: &mut BlockStats) -> f32 {
    if x.is_finite() {
        x.clamp(-1.0, 1.0)
    } else {
        stats.input_non_finite = stats.input_non_finite.saturating_add(1);
        0.0
    }
}

/// One driver channel's signal path and history.
#[derive(Debug, Clone, Copy)]
struct ChannelRt {
    source: RouteSource,
    trim: f32,
    max_gain: f32,
    ceiling: f32,
    dc: DcRejector,
    sections: [Section; MAX_SECTIONS_PER_CHANNEL],
    section_count: usize,
    limiter: Limiter,
    thermal: Thermal,
    /// Silenced after a non-finite or out-of-range fault until the fault is cleared.
    dead: bool,
}

impl ChannelRt {
    const fn idle() -> Self {
        Self {
            source: RouteSource::Mid,
            trim: 1.0,
            max_gain: 1.0,
            ceiling: 1.0,
            dc: DcRejector::with_pole(0.0),
            sections: [Section::passthrough(); MAX_SECTIONS_PER_CHANNEL],
            section_count: 0,
            limiter: Limiter::new(1.0, 1.0, 1.0),
            thermal: Thermal {
                alpha: 0.0,
                soft: 1.0,
                hard: 2.0,
                level: 0.0,
            },
            dead: false,
        }
    }

    fn from_validated(v: &ValidatedChannel) -> Self {
        let mut sections = [Section::passthrough(); MAX_SECTIONS_PER_CHANNEL];
        for (slot, coefficients) in sections.iter_mut().zip(v.sections.iter()) {
            *slot = Section::from_stored(*coefficients);
        }
        Self {
            source: v.source,
            trim: v.trim,
            max_gain: v.max_gain,
            ceiling: v.ceiling,
            dc: DcRejector::with_pole(v.dc_r),
            sections,
            section_count: v.sections.len().min(MAX_SECTIONS_PER_CHANNEL),
            limiter: Limiter::new(v.threshold, v.a_attack, v.a_release),
            thermal: Thermal {
                alpha: v.thermal_alpha,
                soft: v.thermal_soft,
                hard: v.thermal_hard,
                level: 0.0,
            },
            dead: false,
        }
    }

    /// Signal-path state (filters, DC rejector). Protection history is not touched.
    fn reset_signal_state(&mut self) {
        self.dc.reset();
        for section in &mut self.sections {
            section.reset();
        }
    }

    fn kill(&mut self, kind: FaultKind) -> (f32, Option<FaultKind>) {
        self.dead = true;
        self.reset_signal_state();
        (0.0, Some(kind))
    }

    /// One sample: route, DC rejection, crossover/EQ, gain, thermal scaling, limiter, ceiling.
    #[inline]
    fn process(
        &mut self,
        left: f32,
        right: f32,
        mid: f32,
        user: f32,
        fade: f32,
        stats: &mut BlockStats,
    ) -> (f32, Option<FaultKind>) {
        if self.dead {
            return (0.0, None);
        }
        let source = match self.source {
            RouteSource::Left => left,
            RouteSource::Right => right,
            RouteSource::Mid => mid,
        };
        let mut x = self.dc.process(source);
        if let Some(kind) = classify(x) {
            return self.kill(kind);
        }
        let mut fault = None;
        for section in &mut self.sections[..self.section_count] {
            x = section.process(x);
            fault = classify(x);
            if fault.is_some() {
                break;
            }
        }
        if let Some(kind) = fault {
            return self.kill(kind);
        }

        let gain = (self.trim * user).min(self.max_gain) * fade;
        let mut v = x * gain;

        let thermal = &mut self.thermal;
        thermal.level += thermal.alpha * (v * v - thermal.level);
        let thermal_fault = if thermal.level >= thermal.hard {
            Some(FaultKind::ThermalHard)
        } else {
            None
        };
        if thermal.level > thermal.soft {
            v *= (thermal.soft / thermal.level).sqrt();
            stats.thermal_scaled = stats.thermal_scaled.saturating_add(1);
        }

        v = self.limiter.process(v);
        stats.min_limiter_gain = stats.min_limiter_gain.min(self.limiter.gain);
        if v.abs() > self.ceiling {
            stats.clipped = stats.clipped.saturating_add(1);
            v = v.clamp(-self.ceiling, self.ceiling);
        }
        (v, thermal_fault)
    }
}

/// Per-driver output of one block, preallocated by the caller (no heap).
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedOutput {
    pub frames: usize,
    pub channels: usize,
    pub samples: [[i16; FRAMES_PER_BLOCK]; MAX_HARDWARE_CHANNELS],
}

impl ProtectedOutput {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            frames: 0,
            channels: 0,
            samples: [[0; FRAMES_PER_BLOCK]; MAX_HARDWARE_CHANNELS],
        }
    }
}

impl Default for ProtectedOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// What one block did. The user's gain is reported as set; the applied gain and protection
/// activity are reported separately.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockReport {
    pub frames: usize,
    /// The user value as last set (`0.0..=1.0`).
    pub user_gain: f32,
    /// The slewed user gain actually applied at the end of the block.
    pub applied_gain: f32,
    pub source_fade: f32,
    /// Lowest limiter gain any channel reached (`1.0` when never limiting).
    pub min_limiter_gain: f32,
    /// Highest thermal mean-square level over all channels at the end of the block.
    pub max_thermal_level: f32,
    pub thermal_scaled_samples: u32,
    pub clipped_samples: u32,
    /// Non-finite input samples replaced by silence.
    pub input_non_finite: u32,
    pub status: BoardStatus,
}

/// One board's protected renderer.
#[derive(Debug)]
pub struct ProtectedBoardDsp {
    profile_id: String,
    // The validated profile's SHA-256 hex bytes; fixed-size to avoid adding
    // any allocation or deallocation to a calibrated switch in render_into.
    profile_digest: Option<[u8; 64]>,
    bound_profile_digest: Option<[u8; 64]>,
    provenance: Option<CalibrationProvenance>,
    status: BoardStatus,
    channel_count: usize,
    channels: [ChannelRt; MAX_HARDWARE_CHANNELS],
    /// True while the channel chain may still carry signal (running, or ramping to silence).
    chain_live: bool,
    /// True once a chain was ever installed: protection history then outlives any switch.
    has_history: bool,
    user_gain: f32,
    muted: bool,
    applied_gain: f32,
    source_fade: f32,
    ramp_step: f32,
    fault_ramp_step: f32,
    source_step: f32,
    pending: Option<(ValidatedBoard, [u8; 64])>,
    faults_total: u32,
}

impl ProtectedBoardDsp {
    fn blank(profile_id: String, channel_count: usize) -> Self {
        Self {
            profile_id,
            profile_digest: None,
            bound_profile_digest: None,
            provenance: None,
            status: BoardStatus::FailMuted(ProtectionError::NoCalibration),
            channel_count,
            channels: [ChannelRt::idle(); MAX_HARDWARE_CHANNELS],
            chain_live: false,
            has_history: false,
            user_gain: 1.0,
            muted: true, // a new board starts muted; audio needs an explicit unmute
            applied_gain: 0.0,
            source_fade: 1.0,
            ramp_step: 1.0,
            fault_ramp_step: 1.0,
            source_step: 1.0,
            pending: None,
            faults_total: 0,
        }
    }

    /// Admit a board. Never fails: anything that cannot be admitted comes up **fail-muted**
    /// (renders silence, refuses to unmute) with the reason in [`status`](Self::status).
    #[must_use]
    pub fn admit(
        profile: &BoardProfile,
        calibration: Option<&BoardCalibration>,
        admission: Admission,
    ) -> Self {
        let count = usize::from(profile.hardware_channels).min(MAX_HARDWARE_CHANNELS);
        let mut dsp = Self::blank(profile.profile_id.clone(), count);
        dsp.status = match calibration {
            None => BoardStatus::FailMuted(ProtectionError::NoCalibration),
            Some(calibration) => match validate(profile, calibration, admission).and_then(|board| {
                let digest = profile
                    .integrity_sha256
                    .as_bytes()
                    .try_into()
                    .map_err(|_| ProtectionError::ProfileBindingMismatch)?;
                Ok((board, digest))
            }) {
                Ok((board, digest)) => {
                    dsp.install(board, digest);
                    BoardStatus::Active
                }
                Err(error) => BoardStatus::FailMuted(error),
            },
        };
        dsp
    }

    /// Install a validated board, carrying board-lifetime protection history (thermal level and
    /// limiter gain) over channel-for-channel when a chain has existed before. Signal-path state
    /// starts at zero.
    fn install(&mut self, board: ValidatedBoard, digest: [u8; 64]) {
        let previous = self.channels;
        let previous_count = self.channel_count;
        let carry = self.has_history;
        self.channel_count = board.channels.len().min(MAX_HARDWARE_CHANNELS);
        self.channels = [ChannelRt::idle(); MAX_HARDWARE_CHANNELS];
        for (i, validated) in board
            .channels
            .iter()
            .take(MAX_HARDWARE_CHANNELS)
            .enumerate()
        {
            let mut runtime = ChannelRt::from_validated(validated);
            if carry && i < previous_count {
                if previous[i].thermal.level.is_finite() {
                    runtime.thermal.level = previous[i].thermal.level;
                }
                if previous[i].limiter.gain.is_finite() {
                    runtime.limiter.gain = previous[i].limiter.gain;
                }
            }
            self.channels[i] = runtime;
        }
        self.ramp_step = board.ramp_step;
        self.fault_ramp_step = board.fault_ramp_step;
        self.source_step = board.source_step;
        self.provenance = Some(board.provenance);
        self.profile_digest = Some(digest);
        self.status = BoardStatus::Active;
        self.chain_live = true;
        self.has_history = true;
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Digest of the currently installed validated board profile, if any.
    #[must_use]
    pub fn profile_digest(&self) -> Option<&[u8]> {
        self.profile_digest.as_ref().map(|digest| &digest[..])
    }

    /// Permanently bind this DSP owner to its HAL profile. A not-yet-
    /// calibrated DSP remains fail-muted until a matching profile is admitted.
    pub fn bind_profile_digest(&mut self, digest: &[u8]) -> Result<(), ProtectionError> {
        let digest: [u8; 64] = digest
            .try_into()
            .map_err(|_| ProtectionError::ProfileBindingMismatch)?;
        if self
            .bound_profile_digest
            .is_some_and(|bound| bound != digest)
            || self
                .profile_digest
                .is_some_and(|installed| installed != digest)
            || self
                .pending
                .as_ref()
                .is_some_and(|(_, pending)| *pending != digest)
        {
            return Err(ProtectionError::ProfileBindingMismatch);
        }
        self.bound_profile_digest = Some(digest);
        Ok(())
    }

    #[must_use]
    pub const fn status(&self) -> BoardStatus {
        self.status
    }

    /// Provenance of the admitted calibration, preserved with the running board.
    #[must_use]
    pub const fn provenance(&self) -> Option<&CalibrationProvenance> {
        self.provenance.as_ref()
    }

    #[must_use]
    pub const fn channel_count(&self) -> usize {
        self.channel_count
    }

    #[must_use]
    pub const fn user_gain(&self) -> f32 {
        self.user_gain
    }

    #[must_use]
    pub const fn applied_gain(&self) -> f32 {
        self.applied_gain
    }

    #[must_use]
    pub const fn is_muted(&self) -> bool {
        self.muted
    }

    #[must_use]
    pub const fn has_pending_switch(&self) -> bool {
        self.pending.is_some()
    }

    #[must_use]
    pub const fn faults_total(&self) -> u32 {
        self.faults_total
    }

    /// Thermal mean-square level of a driver channel (board-lifetime history).
    #[must_use]
    pub fn thermal_level(&self, channel: usize) -> Option<f32> {
        (channel < self.channel_count).then(|| self.channels[channel].thermal.level)
    }

    /// Limiter gain of a driver channel (board-lifetime history).
    #[must_use]
    pub fn limiter_gain(&self, channel: usize) -> Option<f32> {
        (channel < self.channel_count).then(|| self.channels[channel].limiter.gain)
    }

    /// First filter section's state of a driver channel (signal-path history).
    #[must_use]
    pub fn section_state(&self, channel: usize) -> Option<(f64, f64)> {
        (channel < self.channel_count).then(|| self.channels[channel].sections[0].state())
    }

    /// Test hook: corrupt the first filter section of `channel` so the run-time fault path can be
    /// exercised. Not part of the public API.
    #[cfg(test)]
    pub(super) fn corrupt_section_state_for_test(&mut self, channel: usize, z1: f32) {
        if let Some(runtime) = self.channels[..self.channel_count].get_mut(channel) {
            runtime.sections[0].z1 = f64::from(z1);
        }
    }

    /// Set the user's gain (`0.0..=1.0`); non-finite input is treated as `0.0`. Returns the stored
    /// value. The applied gain follows by a bounded slew, never a step.
    pub fn set_user_gain(&mut self, gain: f32) -> f32 {
        self.user_gain = if gain.is_finite() {
            gain.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.user_gain
    }

    /// Mute ramps to silence. Unmute is refused unless the board is `Active`: a fail-muted or
    /// faulted board can never be unmuted by this call.
    pub fn set_muted(&mut self, muted: bool) -> Result<(), ProtectionError> {
        if !muted && !matches!(self.status, BoardStatus::Active) {
            return Err(ProtectionError::UnmuteRefused);
        }
        self.muted = muted;
        Ok(())
    }

    /// A discontinuity in the source. Board-lifetime history (thermal, limiter, fault latch, user
    /// gain, mute) is untouched; the output fades in from silence over the calibrated source ramp.
    pub fn on_source_event(&mut self, event: SourceEvent) {
        match event {
            SourceEvent::Seek | SourceEvent::Reconnect | SourceEvent::SourceReplaced => {
                self.source_fade = 0.0;
            }
        }
    }

    /// Request a calibration switch on the same board. A valid candidate is installed only after
    /// the output has ramped to silence; thermal and limiter history carry over and filter state
    /// starts at zero. An invalid candidate puts the board in `FailMuted` (it ramps to silence and
    /// stays there) and the error is returned. A latched fault must be cleared first.
    pub fn request_profile_switch(
        &mut self,
        profile: &BoardProfile,
        calibration: &BoardCalibration,
        admission: Admission,
    ) -> Result<(), ProtectionError> {
        if matches!(self.status, BoardStatus::Faulted(_)) {
            return Err(ProtectionError::FaultLatched);
        }
        if profile.profile_id != self.profile_id {
            return Err(ProtectionError::ProfileBindingMismatch);
        }
        if self
            .bound_profile_digest
            .as_ref()
            .is_some_and(|bound| bound.as_slice() != profile.integrity_sha256.as_bytes())
        {
            return Err(ProtectionError::ProfileBindingMismatch);
        }
        match validate(profile, calibration, admission).and_then(|board| {
            let digest = profile
                .integrity_sha256
                .as_bytes()
                .try_into()
                .map_err(|_| ProtectionError::ProfileBindingMismatch)?;
            Ok((board, digest))
        }) {
            Ok(board) => {
                self.pending = Some(board);
                Ok(())
            }
            Err(error) => {
                self.pending = None;
                self.status = BoardStatus::FailMuted(error);
                Err(error)
            }
        }
    }

    /// Clear a latched fault. Refused until every channel's thermal level is back at or below its
    /// soft limit. Signal-path state restarts at zero; thermal history is kept.
    pub fn clear_fault(&mut self) -> Result<(), ProtectionError> {
        if !matches!(self.status, BoardStatus::Faulted(_)) {
            return Ok(());
        }
        for channel in &self.channels[..self.channel_count] {
            let cooled =
                channel.thermal.level.is_finite() && channel.thermal.level <= channel.thermal.soft;
            if !cooled {
                return Err(ProtectionError::NotCooled);
            }
        }
        for channel in &mut self.channels[..self.channel_count] {
            channel.reset_signal_state();
            channel.dead = false;
            if !channel.limiter.gain.is_finite() {
                channel.limiter.gain = 1.0;
            }
        }
        self.status = BoardStatus::Active;
        self.chain_live = true;
        Ok(())
    }

    fn enter_fault(&mut self, code: FaultCode) {
        if matches!(self.status, BoardStatus::Active) {
            self.status = BoardStatus::Faulted(code);
            self.pending = None;
            self.faults_total = self.faults_total.saturating_add(1);
        }
    }

    /// Advance the gain slews by one sample and apply a pending profile switch once silent.
    fn advance_gain(&mut self) {
        let active = matches!(self.status, BoardStatus::Active);
        let target = if active && !self.muted && self.pending.is_none() {
            self.user_gain
        } else {
            0.0
        };
        let step = if active {
            self.ramp_step
        } else {
            self.fault_ramp_step
        };
        let diff = target - self.applied_gain;
        self.applied_gain = if diff.abs() <= step {
            target
        } else if diff > 0.0 {
            self.applied_gain + step
        } else {
            self.applied_gain - step
        };
        if self.source_fade < 1.0 {
            self.source_fade = (self.source_fade + self.source_step).min(1.0);
        }
        if self.applied_gain == 0.0 {
            if let Some((board, digest)) = self.pending.take() {
                self.install(board, digest);
            } else if !active {
                self.chain_live = false;
            }
        }
    }

    /// Render one block into `out` (no allocation). Zero-length and partial blocks are fine; at
    /// most [`FRAMES_PER_BLOCK`] frames are read. A board that is not `Active` ramps to silence
    /// and then renders zeros.
    pub fn render_into(
        &mut self,
        input: &StereoAudioBlock,
        out: &mut ProtectedOutput,
    ) -> BlockReport {
        let frames = input.frames.min(FRAMES_PER_BLOCK);
        out.frames = frames;
        out.channels = self.channel_count;
        for lane in &mut out.samples {
            lane[..frames].fill(0);
        }
        let mut stats = BlockStats {
            min_limiter_gain: 1.0,
            thermal_scaled: 0,
            clipped: 0,
            input_non_finite: 0,
        };
        let count = self.channel_count;
        for (f, (&left, &right)) in input
            .left
            .iter()
            .zip(input.right.iter())
            .take(frames)
            .enumerate()
        {
            self.advance_gain();
            if !self.chain_live {
                // The signal path is silent but the board keeps cooling: thermal history decays
                // with the wall clock, so a faulted board can eventually be cleared.
                for channel in &mut self.channels[..count] {
                    channel.thermal.level *= 1.0 - channel.thermal.alpha;
                }
                continue;
            }
            let l = clean(left, &mut stats);
            let r = clean(right, &mut stats);
            let mid = 0.5 * (l + r);
            let (user, fade) = (self.applied_gain, self.source_fade);
            let mut fault: Option<FaultCode> = None;
            for (c, (channel, lane)) in self.channels[..count]
                .iter_mut()
                .zip(out.samples.iter_mut())
                .enumerate()
            {
                let (value, kind) = channel.process(l, r, mid, user, fade, &mut stats);
                lane[f] = unit_f32_to_i16(value);
                if fault.is_none()
                    && let Some(kind) = kind
                {
                    let index = c as u8;
                    fault = Some(match kind {
                        FaultKind::NonFinite => FaultCode::NonFiniteState { channel: index },
                        FaultKind::StateRange => FaultCode::StateRange { channel: index },
                        FaultKind::ThermalHard => FaultCode::ThermalHard { channel: index },
                    });
                }
            }
            if let Some(code) = fault {
                self.enter_fault(code);
            }
        }
        let max_thermal_level = self.channels[..count]
            .iter()
            .map(|channel| channel.thermal.level)
            .fold(0.0f32, f32::max);
        BlockReport {
            frames,
            user_gain: self.user_gain,
            applied_gain: self.applied_gain,
            source_fade: self.source_fade,
            min_limiter_gain: stats.min_limiter_gain,
            max_thermal_level,
            thermal_scaled_samples: stats.thermal_scaled,
            clipped_samples: stats.clipped,
            input_non_finite: stats.input_non_finite,
            status: self.status,
        }
    }

    /// Compatibility wrapper that allocates a [`HardwareOutputBlock`]; the render path proper is
    /// [`render_into`](Self::render_into).
    #[must_use]
    pub fn render_block(&mut self, input: &StereoAudioBlock) -> HardwareOutputBlock {
        let mut out = ProtectedOutput::new();
        self.render_into(input, &mut out);
        HardwareOutputBlock {
            profile_id: self.profile_id.clone(),
            start_frame: input.start_frame,
            frames: out.frames,
            channels: out.channels,
            channel_samples: out.samples[..out.channels].to_vec(),
        }
    }
}
