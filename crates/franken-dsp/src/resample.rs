//! Bounded drift resampler (`D03` / `ffw-j9r`): consumes a source slightly faster or slower than the
//! local output clock so the playout queue neither fills nor drains.
//!
//! Contract: `docs/contracts/d03.md` section 3. In short:
//!
//! * **Ratio.** `step` is input frames consumed per output frame, `1 + ppb/1e9`, held as a Q32
//!   fixed-point number. It is limited to `max_ratio_ppm` (default [`DEFAULT_MAX_RATIO_PPM`]).
//!   Positions, counts and slewing are integer arithmetic, so output counts are exact and
//!   reproducible; only the per-sample interpolation uses `f32`.
//! * **Bounded slew.** The ratio moves toward its target by at most `max_slew_ppm_per_block` per
//!   256 output frames, applied in steps every [`UPDATE_QUANTUM_FRAMES`] output frames. Because the
//!   step schedule is counted in output frames, the result does not depend on how calls are split.
//!   The whole ±500 ppm range is under 0.9 cent of pitch (1 ppm = 0.00173 cent), so there is no
//!   audible pitch step; the slew limit keeps the rate of change small as well.
//! * **Kernel.** Catmull-Rom cubic over four taps (one before, two after), exact for linear and
//!   quadratic signals, `f32` arithmetic, [`FLOAT_OPS_PER_OUTPUT_FRAME`] operations per stereo frame.
//! * **History.** A four-frame window carried across calls; nothing is zeroed at a block boundary.
//!   Short, zero-length and final partial blocks are ordinary. The first output needs
//!   [`LOOKAHEAD_FRAMES`] frames beyond itself, a fixed algorithmic delay.
//! * **Pull-driven.** Input is taken from a [`FrameSource`] only as the next output needs it. An
//!   empty source ends the call early (`underrun`) with the state intact; supplying more input later
//!   continues exactly where it stopped.
//! * **Epochs.** [`DriftResampler::begin_epoch`] clears the source-local history (window and phase)
//!   and fades the output in over [`RAMP_FRAMES`]; the endpoint-local ratio is kept.
//!
//! Sample handling: inputs are sanitised (non-finite becomes 0, clamped to ±1) and outputs clamped
//! to ±1 with a count, so a bad frame cannot become a full-scale burst. No `unsafe`, no allocation,
//! no panic on any input.

use crate::{FRAMES_PER_BLOCK, MAX_DRIFT_PPM, sanitize_sample};
use serde::{Deserialize, Serialize};

/// Interpolation taps (one before the position, two after).
pub const TAPS: usize = 4;
/// Frames pulled before the first output: the window (`TAPS - 1`).
pub const PRIME_FRAMES: u8 = 3;
/// Frames of lookahead the kernel needs beyond the interpolation position.
pub const LOOKAHEAD_FRAMES: usize = 2;
/// Output frames between ratio updates.
pub const UPDATE_QUANTUM_FRAMES: u32 = 32;
/// Output frames over which output fades in after a start or an epoch reset.
pub const RAMP_FRAMES: u32 = 64;
/// Default ratio limit (the crate's `MAX_DRIFT_PPM`).
pub const DEFAULT_MAX_RATIO_PPM: u32 = MAX_DRIFT_PPM as u32;
/// Largest ratio limit a configuration may ask for.
pub const HARD_MAX_RATIO_PPM: u32 = 10_000;
/// Default slew limit, ppm per 256 output frames.
pub const DEFAULT_MAX_SLEW_PPM_PER_BLOCK: u32 = 2;
/// Largest slew limit a configuration may ask for.
pub const HARD_MAX_SLEW_PPM_PER_BLOCK: u32 = 50;
/// `f32` operations per stereo output frame: 15 (weights) + 2 (position) + 14 (two 4-tap dot
/// products) + 4 (clamp compares). Counted by hand from `interpolate`.
pub const FLOAT_OPS_PER_OUTPUT_FRAME: u32 = 35;
/// Extra multiplies per output frame while the fade-in is active.
pub const RAMP_EXTRA_FLOAT_OPS: u32 = 2;
/// Algorithmic delay the resampler adds to the presentation mapping, in frames.
pub const DELAY_FRAMES: usize = LOOKAHEAD_FRAMES;

const Q32_ONE: i64 = 1 << 32;
const FRAC_MASK: u64 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ResampleError {
    #[error("invalid resampler configuration: {0}")]
    InvalidConfig(String),
    #[error("output channel slices differ in length: left {left}, right {right}")]
    ChannelLengthMismatch { left: usize, right: usize },
    #[error("block of {frames} frames exceeds the bounded work unit of {max}")]
    BlockTooLong { frames: usize, max: usize },
    #[error("epoch {requested} does not advance current epoch {current}")]
    EpochNotAdvanced { current: u32, requested: u32 },
}

/// Why source-local history was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetReason {
    NewSource,
    Discontinuity,
    Rejoin,
}

impl ResetReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NewSource => "NewSource",
            Self::Discontinuity => "Discontinuity",
            Self::Rejoin => "Rejoin",
        }
    }
}

/// One explicit epoch transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetRecord {
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub reason: ResetReason,
    /// Output frames produced before the reset.
    pub at_output: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResamplerConfig {
    /// Ratio limit either way, in ppm of the nominal rate.
    pub max_ratio_ppm: u32,
    /// Slew limit, in ppm of ratio per 256 output frames.
    pub max_slew_ppm_per_block: u32,
}

impl Default for ResamplerConfig {
    fn default() -> Self {
        Self {
            max_ratio_ppm: DEFAULT_MAX_RATIO_PPM,
            max_slew_ppm_per_block: DEFAULT_MAX_SLEW_PPM_PER_BLOCK,
        }
    }
}

impl ResamplerConfig {
    pub fn validate(&self) -> Result<(), ResampleError> {
        if self.max_ratio_ppm > HARD_MAX_RATIO_PPM {
            return Err(ResampleError::InvalidConfig(format!(
                "max_ratio_ppm {} exceeds {HARD_MAX_RATIO_PPM}",
                self.max_ratio_ppm
            )));
        }
        if self.max_slew_ppm_per_block == 0
            || self.max_slew_ppm_per_block > HARD_MAX_SLEW_PPM_PER_BLOCK
        {
            return Err(ResampleError::InvalidConfig(format!(
                "max_slew_ppm_per_block must be 1..={HARD_MAX_SLEW_PPM_PER_BLOCK}"
            )));
        }
        Ok(())
    }
}

/// Where input frames come from. `None` means no frame is available now (an underrun), not the end
/// of the stream: the call ends early and can be resumed.
pub trait FrameSource {
    fn pull(&mut self) -> Option<[f32; 2]>;
}

/// A [`FrameSource`] over two equal-length channel slices.
#[derive(Debug, Clone)]
pub struct SliceSource<'a> {
    left: &'a [f32],
    right: &'a [f32],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    pub fn new(left: &'a [f32], right: &'a [f32]) -> Result<Self, ResampleError> {
        if left.len() != right.len() {
            return Err(ResampleError::ChannelLengthMismatch {
                left: left.len(),
                right: right.len(),
            });
        }
        Ok(Self {
            left,
            right,
            pos: 0,
        })
    }

    /// Frames taken so far.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.pos
    }

    /// Frames not yet taken.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.left.len() - self.pos
    }
}

impl FrameSource for SliceSource<'_> {
    fn pull(&mut self) -> Option<[f32; 2]> {
        let l = *self.left.get(self.pos)?;
        let r = *self.right.get(self.pos)?;
        self.pos += 1;
        Some([l, r])
    }
}

/// Counters that survive epoch resets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResamplerStats {
    pub outputs: u64,
    pub inputs_pulled: u64,
    pub underruns: u32,
    /// Input samples that were non-finite or outside ±1 and were corrected.
    pub sanitized_inputs: u32,
    /// Output samples limited to ±1.
    pub clamped_outputs: u32,
    /// Times a requested target was beyond the ratio limit and was clamped.
    pub target_clamps: u32,
    pub epoch_resets: u32,
    /// Largest single ratio step applied, in ppb.
    pub max_ratio_step_ppb: u32,
    /// Hand-counted `f32` operations performed (see [`FLOAT_OPS_PER_OUTPUT_FRAME`]).
    pub float_ops: u64,
}

/// What one [`DriftResampler::render`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderReport {
    pub produced: usize,
    pub pulled: usize,
    /// The source ran dry before `produced` reached the block length.
    pub underrun: bool,
    pub ratio_ppb: i32,
}

/// The phase-and-ratio state that fully determines future output counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseState {
    pub frac: u32,
    pub pending: u8,
    pub current_ppb: i32,
    pub target_ppb: i32,
    pub since_update: u32,
    pub ramp_left: u32,
}

/// Input frames consumed per output frame, Q32, for a ratio in ppb (truncating toward zero).
fn step_q32_for(ppb: i32) -> u64 {
    let delta = (i64::from(ppb) * Q32_ONE) / 1_000_000_000;
    u64::try_from(Q32_ONE + delta).unwrap_or(1 << 32)
}

#[derive(Debug, Clone)]
pub struct DriftResampler {
    max_ratio_ppb: i32,
    slew_ppb: i32,
    /// Frames at offsets -1, 0, +1, +2 around the interpolation position.
    win: [[f32; 2]; TAPS],
    frac: u32,
    pending: u8,
    current_ppb: i32,
    target_ppb: i32,
    step_q32: u64,
    since_update: u32,
    ramp_left: u32,
    epoch: u32,
    stats: ResamplerStats,
    last_reset: Option<ResetRecord>,
}

impl DriftResampler {
    pub fn new(cfg: ResamplerConfig) -> Result<Self, ResampleError> {
        cfg.validate()?;
        let range = |v: u32| {
            i32::try_from(v)
                .map_err(|_| ResampleError::InvalidConfig("configuration out of range".to_string()))
        };
        Ok(Self {
            max_ratio_ppb: range(cfg.max_ratio_ppm * 1_000)?,
            slew_ppb: range(cfg.max_slew_ppm_per_block * 125)?,
            win: [[0.0; 2]; TAPS],
            frac: 0,
            pending: PRIME_FRAMES,
            current_ppb: 0,
            target_ppb: 0,
            step_q32: step_q32_for(0),
            since_update: 0,
            ramp_left: RAMP_FRAMES,
            epoch: 0,
            stats: ResamplerStats::default(),
            last_reset: None,
        })
    }

    /// Start at a known ratio (for example one restored from saved state). Beyond the limit is an error.
    pub fn with_initial_ppb(cfg: ResamplerConfig, ppb: i32) -> Result<Self, ResampleError> {
        let mut rs = Self::new(cfg)?;
        if ppb.unsigned_abs() > rs.max_ratio_ppb.unsigned_abs() {
            return Err(ResampleError::InvalidConfig(format!(
                "initial ratio {ppb} ppb is beyond the limit of {} ppb",
                rs.max_ratio_ppb
            )));
        }
        rs.current_ppb = ppb;
        rs.target_ppb = ppb;
        rs.step_q32 = step_q32_for(ppb);
        Ok(rs)
    }

    /// The ratio the resampler is working toward, clamped to the limit. Returns what was applied.
    pub fn set_target_ppb(&mut self, ppb: i64) -> i32 {
        let limit = i64::from(self.max_ratio_ppb);
        let clamped = ppb.clamp(-limit, limit);
        if clamped != ppb {
            self.stats.target_clamps = self.stats.target_clamps.saturating_add(1);
        }
        let applied = i32::try_from(clamped).unwrap_or(0);
        self.target_ppb = applied;
        applied
    }

    /// As [`Self::set_target_ppb`], in whole ppm. Returns the ppm applied.
    pub fn set_target_ppm(&mut self, ppm: i32) -> i32 {
        self.set_target_ppb(i64::from(ppm) * 1_000) / 1_000
    }

    #[must_use]
    pub const fn ratio_ppb(&self) -> i32 {
        self.current_ppb
    }

    #[must_use]
    pub const fn target_ppb(&self) -> i32 {
        self.target_ppb
    }

    #[must_use]
    pub const fn step_q32(&self) -> u64 {
        self.step_q32
    }

    /// Ratio change allowed per update quantum, in ppb.
    #[must_use]
    pub const fn slew_ppb_per_quantum(&self) -> i32 {
        self.slew_ppb
    }

    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    #[must_use]
    pub const fn stats(&self) -> ResamplerStats {
        self.stats
    }

    #[must_use]
    pub const fn last_reset(&self) -> Option<ResetRecord> {
        self.last_reset
    }

    #[must_use]
    pub const fn phase_state(&self) -> PhaseState {
        PhaseState {
            frac: self.frac,
            pending: self.pending,
            current_ppb: self.current_ppb,
            target_ppb: self.target_ppb,
            since_update: self.since_update,
            ramp_left: self.ramp_left,
        }
    }

    /// Clear the source-local history and start a new epoch. The window and phase are reset and the
    /// output fades in; the ratio (an endpoint property) and the counters are kept. `epoch` must
    /// advance the current one in wrapping order.
    pub fn begin_epoch(
        &mut self,
        epoch: u32,
        reason: ResetReason,
    ) -> Result<ResetRecord, ResampleError> {
        if (epoch.wrapping_sub(self.epoch) as i32) <= 0 {
            return Err(ResampleError::EpochNotAdvanced {
                current: self.epoch,
                requested: epoch,
            });
        }
        let record = ResetRecord {
            from_epoch: self.epoch,
            to_epoch: epoch,
            reason,
            at_output: self.stats.outputs,
        };
        self.win = [[0.0; 2]; TAPS];
        self.frac = 0;
        self.pending = PRIME_FRAMES;
        self.ramp_left = RAMP_FRAMES;
        self.epoch = epoch;
        self.stats.epoch_resets = self.stats.epoch_resets.saturating_add(1);
        self.last_reset = Some(record);
        Ok(record)
    }

    /// Produce up to `out_l.len()` frames, pulling input from `src` only as needed. At most
    /// [`FRAMES_PER_BLOCK`] frames per call. If the source runs dry the call ends early with
    /// `underrun` set and the state ready to continue.
    pub fn render<S: FrameSource>(
        &mut self,
        src: &mut S,
        out_l: &mut [f32],
        out_r: &mut [f32],
    ) -> Result<RenderReport, ResampleError> {
        if out_l.len() != out_r.len() {
            return Err(ResampleError::ChannelLengthMismatch {
                left: out_l.len(),
                right: out_r.len(),
            });
        }
        let n = out_l.len();
        if n > FRAMES_PER_BLOCK {
            return Err(ResampleError::BlockTooLong {
                frames: n,
                max: FRAMES_PER_BLOCK,
            });
        }
        let mut produced = 0_usize;
        let mut pulled = 0_usize;
        let mut underrun = false;
        'outputs: while produced < n {
            while self.pending > 0 {
                match src.pull() {
                    Some(frame) => {
                        self.shift_in(frame);
                        self.pending -= 1;
                        pulled += 1;
                    }
                    None => {
                        underrun = true;
                        break 'outputs;
                    }
                }
            }
            if self.since_update >= UPDATE_QUANTUM_FRAMES {
                self.update_ratio();
                self.since_update = 0;
            }
            let [l, r] = self.interpolate();
            if let (Some(a), Some(b)) = (out_l.get_mut(produced), out_r.get_mut(produced)) {
                *a = l;
                *b = r;
            }
            self.advance();
            produced += 1;
        }
        self.stats.inputs_pulled = self.stats.inputs_pulled.saturating_add(pulled as u64);
        if underrun {
            self.stats.underruns = self.stats.underruns.saturating_add(1);
        }
        Ok(RenderReport {
            produced,
            pulled,
            underrun,
            ratio_ppb: self.current_ppb,
        })
    }

    /// Advance exactly as [`Self::render`] would for `n_out` outputs from an always-available source,
    /// without producing audio, and return the input frames consumed. The arithmetic is closed-form
    /// per update quantum (per call once the ratio has settled), so a day of virtual time is cheap.
    pub fn plan(&mut self, n_out: u64) -> u64 {
        let mut remaining = n_out;
        let mut consumed: u64 = 0;
        while remaining > 0 {
            consumed = consumed.saturating_add(u64::from(self.pending));
            self.pending = 0;
            if self.since_update >= UPDATE_QUANTUM_FRAMES {
                self.update_ratio();
                self.since_update = 0;
            }
            let converged = self.current_ppb == self.target_ppb;
            let room = u64::from(UPDATE_QUANTUM_FRAMES - self.since_update);
            let chunk = if converged {
                remaining
            } else {
                remaining.min(room)
            };
            let step = u128::from(self.step_q32);
            let c = u128::from(chunk);
            let frac = u128::from(self.frac);
            let total = frac + c * step;
            let shifts = total >> 32;
            let before_last = (frac + (c - 1) * step) & u128::from(FRAC_MASK);
            let k_last = (before_last + step) >> 32;
            consumed = consumed.saturating_add(u64::try_from(shifts - k_last).unwrap_or(u64::MAX));
            self.pending = u8::try_from(k_last).unwrap_or(2);
            self.frac = u32::try_from(total & u128::from(FRAC_MASK)).unwrap_or(0);
            let s = u64::from(self.since_update);
            let quantum = u64::from(UPDATE_QUANTUM_FRAMES);
            self.since_update = if converged {
                // ((s + chunk - 1) mod 32) + 1, written so it cannot overflow for any chunk
                u32::try_from((s + (chunk - 1) % quantum) % quantum + 1)
                    .unwrap_or(UPDATE_QUANTUM_FRAMES)
            } else {
                self.since_update + u32::try_from(chunk).unwrap_or(UPDATE_QUANTUM_FRAMES)
            };
            let ramp = u64::from(self.ramp_left).min(chunk);
            self.ramp_left -= u32::try_from(ramp).unwrap_or(0);
            self.stats.outputs = self.stats.outputs.saturating_add(chunk);
            self.stats.float_ops = self
                .stats
                .float_ops
                .saturating_add(chunk.saturating_mul(u64::from(FLOAT_OPS_PER_OUTPUT_FRAME)))
                .saturating_add(ramp * u64::from(RAMP_EXTRA_FLOAT_OPS));
            remaining -= chunk;
        }
        self.stats.inputs_pulled = self.stats.inputs_pulled.saturating_add(consumed);
        consumed
    }

    fn clean(&mut self, x: f32) -> f32 {
        if !x.is_finite() || x.abs() > 1.0 {
            self.stats.sanitized_inputs = self.stats.sanitized_inputs.saturating_add(1);
        }
        if x.is_finite() {
            sanitize_sample(x)
        } else {
            0.0
        }
    }

    fn shift_in(&mut self, frame: [f32; 2]) {
        let l = self.clean(frame[0]);
        let r = self.clean(frame[1]);
        self.win = [self.win[1], self.win[2], self.win[3], [l, r]];
    }

    fn update_ratio(&mut self) {
        let diff = self.target_ppb - self.current_ppb;
        let d = diff.clamp(-self.slew_ppb, self.slew_ppb);
        if d != 0 {
            self.current_ppb += d;
            self.step_q32 = step_q32_for(self.current_ppb);
            self.stats.max_ratio_step_ppb = self.stats.max_ratio_step_ppb.max(d.unsigned_abs());
        }
    }

    fn limit(&mut self, y: f32) -> f32 {
        if y > 1.0 {
            self.stats.clamped_outputs = self.stats.clamped_outputs.saturating_add(1);
            1.0
        } else if y < -1.0 {
            self.stats.clamped_outputs = self.stats.clamped_outputs.saturating_add(1);
            -1.0
        } else {
            y
        }
    }

    /// Catmull-Rom at the current fractional position. Operation count (stereo): `h`, `t2`, `t3h`
    /// (3) + `w0` (2) + `w1` (4) + `w2` (4) + `w3` (2) = 15 weight operations; 2 for the position;
    /// 14 for the two dot products; 4 for the clamp compares.
    fn interpolate(&mut self) -> [f32; 2] {
        let t = (self.frac >> 8) as f32 * (1.0 / 16_777_216.0);
        let h = 0.5 * t;
        let t2 = t * t;
        let t3h = t2 * h;
        let w0 = t2 - h - t3h;
        let w1 = 1.0 - 2.5 * t2 + 3.0 * t3h;
        let w2 = h + 2.0 * t2 - 3.0 * t3h;
        let w3 = t3h - h * t;
        let w = &self.win;
        let mut l = w0 * w[0][0] + w1 * w[1][0] + w2 * w[2][0] + w3 * w[3][0];
        let mut r = w0 * w[0][1] + w1 * w[1][1] + w2 * w[2][1] + w3 * w[3][1];
        if self.ramp_left > 0 {
            let gain = (RAMP_FRAMES - self.ramp_left) as f32 * (1.0 / RAMP_FRAMES as f32);
            l *= gain;
            r *= gain;
            self.ramp_left -= 1;
            self.stats.float_ops = self
                .stats
                .float_ops
                .saturating_add(u64::from(RAMP_EXTRA_FLOAT_OPS));
        }
        self.stats.float_ops = self
            .stats
            .float_ops
            .saturating_add(u64::from(FLOAT_OPS_PER_OUTPUT_FRAME));
        [self.limit(l), self.limit(r)]
    }

    /// Move the interpolation position on by one step; the frames it passes are pulled lazily.
    fn advance(&mut self) {
        let total = u64::from(self.frac) + self.step_q32;
        self.pending = u8::try_from(total >> 32).unwrap_or(2);
        self.frac = u32::try_from(total & FRAC_MASK).unwrap_or(0);
        self.since_update += 1;
        self.stats.outputs = self.stats.outputs.saturating_add(1);
    }
}

/// Proportional trim from queue level to ratio. A rate estimate alone cannot bound the queue over
/// hours: any residual rate error integrates into the level. This closes the loop on the level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelTrim {
    /// The level to hold, in frames.
    pub target_frames: u64,
    /// Ratio correction per frame of level error, in ppb. Positive: consume faster when too full.
    pub gain_ppb_per_frame: i64,
    /// The trim never exceeds this, in ppb.
    pub limit_ppb: i64,
}

impl LevelTrim {
    #[must_use]
    pub fn trim_ppb(&self, level_frames: u64) -> i64 {
        let error = i128::from(level_frames) - i128::from(self.target_frames);
        let raw = error.saturating_mul(i128::from(self.gain_ppb_per_frame));
        let limit = i128::from(self.limit_ppb.unsigned_abs());
        i64::try_from(raw.clamp(-limit, limit)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
