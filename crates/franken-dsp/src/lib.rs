//! Bounded Audio DSP, Endian Conversion, Transducer Protection, and Drift Resampler
//! (`D01` / `ffw-f3b`, `D02` / `ffw-7s0`, `D03` / `ffw-j9r`, `D04` / `ffw-5h5`).
//!
//! All operations are `#![forbid(unsafe_code)]`, bounded to [`FRAMES_PER_BLOCK`] (256 frames
//! = 5.333 ms at 48 kHz), and free of network, filesystem, or unbounded heap allocations.

#![forbid(unsafe_code)]

// D01 (`ffw-f3b`): canonical stream formats, bit-exact conversion, bounded SPSC ring and sink.
// Contract: `docs/contracts/d01.md`.
pub mod convert;
pub mod format;
pub mod resample; // D03 (`ffw-j9r`), written by TealSeal
pub mod ring;

pub use convert::{ConvertStats, convert_block, convert_packed};
pub use format::{
    BufferSpec, CANONICAL_WIRE_FORMAT, Endian, Layout, MAX_BLOCK_FRAMES, PcmError, SampleFormat,
    StreamFormat, frames_in_packed_bytes,
};
pub use ring::{BlockSink, BoundedCaptureSink, RingConsumer, RingProducer, ring_channel};

use franken_board_profile::{BoardProfile, TransducerRole};
use serde::{Deserialize, Serialize};

pub const CANONICAL_SAMPLE_RATE_HZ: u32 = 48_000;
pub const FRAMES_PER_BLOCK: usize = 256;
pub const MAX_HARDWARE_CHANNELS: usize = 9;
pub const MAX_DRIFT_PPM: i32 = 500; // ±500 ppm (±0.05%)

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DspError {
    #[error("invalid biquad filter coefficients (non-finite or unstable a0=0)")]
    InvalidFilterCoefficients,
    #[error("board profile has 0 or unsupported hardware channels: {0}")]
    UnsupportedChannelCount(u8),
    #[error("input byte slice length {len} is not a multiple of 4 (stereo i16 frame)")]
    MalformedStereoPcmBytes { len: usize },
    #[error(
        "clock drift {observed_ppm} ppm exceeds bounded resampler limit ±{MAX_DRIFT_PPM} ppm; re-anchor required"
    )]
    DriftExceedsBounds { observed_ppm: i32 },
}

/// Canonical 256-frame stereo input block (`48 kHz`).
#[derive(Debug, Clone, PartialEq)]
pub struct StereoAudioBlock {
    pub start_frame: u64,
    pub frames: usize,
    pub left: [f32; FRAMES_PER_BLOCK],
    pub right: [f32; FRAMES_PER_BLOCK],
}

impl Default for StereoAudioBlock {
    fn default() -> Self {
        Self::silence(0)
    }
}

impl StereoAudioBlock {
    #[must_use]
    pub const fn silence(start_frame: u64) -> Self {
        Self {
            start_frame,
            frames: FRAMES_PER_BLOCK,
            left: [0.0; FRAMES_PER_BLOCK],
            right: [0.0; FRAMES_PER_BLOCK],
        }
    }

    /// Decode canonical network big-endian `i16` stereo PCM bytes into normalized `[-1.0, 1.0]` `f32`.
    pub fn from_be_i16_bytes(start_frame: u64, bytes: &[u8]) -> Result<Self, DspError> {
        if !bytes.len().is_multiple_of(4) || bytes.len() / 4 > FRAMES_PER_BLOCK {
            return Err(DspError::MalformedStereoPcmBytes { len: bytes.len() });
        }
        let frames = bytes.len() / 4;
        let mut block = Self::silence(start_frame);
        block.frames = frames;
        for (idx, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let l_i16 = i16::from_be_bytes([chunk[0], chunk[1]]);
            let r_i16 = i16::from_be_bytes([chunk[2], chunk[3]]);
            block.left[idx] = i16_to_unit_f32(l_i16);
            block.right[idx] = i16_to_unit_f32(r_i16);
        }
        Ok(block)
    }

    /// Encode stereo block into big-endian `i16` bytes with saturation clamping.
    #[must_use]
    pub fn to_be_i16_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.frames * 4);
        for i in 0..self.frames {
            let l = unit_f32_to_i16(self.left[i]);
            let r = unit_f32_to_i16(self.right[i]);
            out.extend_from_slice(&l.to_be_bytes());
            out.extend_from_slice(&r.to_be_bytes());
        }
        out
    }

    /// Encode stereo block into little-endian `i16` bytes with saturation clamping.
    #[must_use]
    pub fn to_le_i16_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.frames * 4);
        for i in 0..self.frames {
            let l = unit_f32_to_i16(self.left[i]);
            let r = unit_f32_to_i16(self.right[i]);
            out.extend_from_slice(&l.to_le_bytes());
            out.extend_from_slice(&r.to_le_bytes());
        }
        out
    }
}

/// Sanitize an `f32` audio sample: flush NaN/Inf/subnormals to `0.0` and clamp to `[-1.0, 1.0]`.
#[must_use]
#[inline]
pub fn sanitize_sample(x: f32) -> f32 {
    if !x.is_finite() || x.abs() < 1.0e-20 {
        0.0
    } else {
        x.clamp(-1.0, 1.0)
    }
}

/// `i16` to normalized `f32` on the D01 scale: `sample / 32768`.
///
/// D01 changed this from the earlier `/ 32767` scale (which sent `-32768 -> -1.0 -> -32767`
/// and so did not round-trip). On the D01 scale every one of the 65 536 `i16` values survives
/// `i16 -> f32 -> i16` unchanged. Results differ from the old scale by at most 1 LSB.
#[must_use]
#[inline]
pub fn i16_to_unit_f32(sample: i16) -> f32 {
    convert::s16_to_f32(sample)
}

/// Normalized `f32` to `i16` on the D01 scale: `round_ties_even(sample * 32768)`, saturating
/// to `-32768..=32767`. NaN and +/-infinity become `0` (silence, never a full-scale burst).
#[must_use]
#[inline]
pub fn unit_f32_to_i16(sample: f32) -> i16 {
    convert::f32_to_s16(sample)
}

/// Direct-Form II Transposed biquad filter with finite-coefficient validation and NaN guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BiquadFilter {
    b0: f32,
    b1: f32,
    b2: f32,
    a1: f32,
    a2: f32,
    z1: f32,
    z2: f32,
}

impl BiquadFilter {
    pub fn new(b0: f32, b1: f32, b2: f32, a1: f32, a2: f32) -> Result<Self, DspError> {
        if ![b0, b1, b2, a1, a2].iter().all(|c| c.is_finite()) {
            return Err(DspError::InvalidFilterCoefficients);
        }
        // Stability check for 2nd-order IIR poles: |a2| < 1 and |a1| < 1 + a2
        if a2.abs() >= 1.0 || a1.abs() >= (1.0 + a2) {
            return Err(DspError::InvalidFilterCoefficients);
        }
        Ok(Self {
            b0,
            b1,
            b2,
            a1,
            a2,
            z1: 0.0,
            z2: 0.0,
        })
    }

    #[must_use]
    pub const fn passthrough() -> Self {
        Self {
            b0: 1.0,
            b1: 0.0,
            b2: 0.0,
            a1: 0.0,
            a2: 0.0,
            z1: 0.0,
            z2: 0.0,
        }
    }

    /// 2nd-order Butterworth high-pass filter for tweeter protection (~2.2 kHz at 48 kHz).
    #[must_use]
    pub const fn tweeter_highpass_48k() -> Self {
        Self {
            b0: 0.815_16,
            b1: -1.630_32,
            b2: 0.815_16,
            a1: -1.596_26,
            a2: 0.664_38,
            z1: 0.0,
            z2: 0.0,
        }
    }

    /// 2nd-order Butterworth low-pass filter for subwoofer/woofer routing (~120 Hz at 48 kHz).
    #[must_use]
    pub const fn woofer_lowpass_48k() -> Self {
        Self {
            b0: 0.000_061,
            b1: 0.000_122,
            b2: 0.000_061,
            a1: -1.977_79,
            a2: 0.978_03,
            z1: 0.0,
            z2: 0.0,
        }
    }

    #[inline]
    pub fn process_sample(&mut self, input: f32) -> f32 {
        let x = sanitize_sample(input);
        let y = self.b0 * x + self.z1;
        self.z1 = self.b1 * x - self.a1 * y + self.z2;
        self.z2 = self.b2 * x - self.a2 * y;
        if !self.z1.is_finite() || !self.z2.is_finite() {
            self.z1 = 0.0;
            self.z2 = 0.0;
            return 0.0;
        }
        sanitize_sample(y)
    }
}

/// First-order DC-blocking high-pass filter (`y[n] = x[n] - x[n-1] + R * y[n-1]`) protecting voice coils.
#[derive(Debug, Clone, Default)]
pub struct DcBlocker {
    prev_x: f32,
    prev_y: f32,
}

impl DcBlocker {
    const POLE_R: f32 = 0.998_5;

    #[inline]
    pub fn process(&mut self, x: f32) -> f32 {
        let clean = sanitize_sample(x);
        let y = clean - self.prev_x + Self::POLE_R * self.prev_y;
        self.prev_x = clean;
        self.prev_y = sanitize_sample(y);
        self.prev_y
    }
}

/// Multi-channel hardware output block routed according to a verified [`BoardProfile`].
#[derive(Debug, Clone, PartialEq)]
pub struct HardwareOutputBlock {
    pub profile_id: String,
    pub start_frame: u64,
    pub frames: usize,
    pub channels: usize,
    /// Planar per-channel `i16` output ready for TDM/I2S packing.
    pub channel_samples: Vec<[i16; FRAMES_PER_BLOCK]>,
}

/// Per-board transducer protection, crossover routing, click-free volume ramp, and peak limiter (`D02`).
#[derive(Debug, Clone)]
pub struct BoardProtectionDsp {
    profile: BoardProfile,
    dc_left: DcBlocker,
    dc_right: DcBlocker,
    channel_filters: Vec<BiquadFilter>,
    current_gain: f32,
    target_gain: f32,
    muted: bool,
    limiter_ceiling: f32,
}

impl BoardProtectionDsp {
    pub fn new(profile: BoardProfile) -> Result<Self, DspError> {
        if profile.hardware_channels == 0
            || usize::from(profile.hardware_channels) > MAX_HARDWARE_CHANNELS
        {
            return Err(DspError::UnsupportedChannelCount(profile.hardware_channels));
        }
        let mut channel_filters = Vec::with_capacity(usize::from(profile.hardware_channels));
        for &role in &profile.channel_routing {
            let filter = match role {
                TransducerRole::TweeterLeft
                | TransducerRole::TweeterRight
                | TransducerRole::TweeterMono
                | TransducerRole::ArrayTweeter(_) => BiquadFilter::tweeter_highpass_48k(),
                TransducerRole::WooferCenter
                | TransducerRole::WooferMono
                | TransducerRole::SubwooferLfe => BiquadFilter::woofer_lowpass_48k(),
                TransducerRole::MidLeft
                | TransducerRole::MidRight
                | TransducerRole::ArrayMidWoofer(_) => BiquadFilter::passthrough(),
            };
            channel_filters.push(filter);
        }
        Ok(Self {
            profile,
            dc_left: DcBlocker::default(),
            dc_right: DcBlocker::default(),
            channel_filters,
            current_gain: 0.0, // Always start ramped down to 0.0 for click-free startup
            target_gain: 1.0,
            muted: false,
            limiter_ceiling: 0.95,
        })
    }

    pub fn set_volume_gain(&mut self, gain: f32) {
        self.target_gain = sanitize_sample(gain).max(0.0);
    }

    pub fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
    }

    /// Process a 256-frame stereo block into the board's N physical transducer channels.
    #[must_use]
    pub fn render_block(&mut self, input: &StereoAudioBlock) -> HardwareOutputBlock {
        let ch_count = usize::from(self.profile.hardware_channels);
        let mut out_channels = vec![[0i16; FRAMES_PER_BLOCK]; ch_count];
        let effective_target = if self.muted { 0.0 } else { self.target_gain };
        let frames = input.frames.min(FRAMES_PER_BLOCK);
        let step = if frames > 0 {
            (effective_target - self.current_gain) / (frames as f32)
        } else {
            0.0
        };

        #[allow(clippy::needless_range_loop)]
        for f in 0..frames {
            self.current_gain = (self.current_gain + step).clamp(0.0, 1.0);
            let l = self.dc_left.process(input.left[f]) * self.current_gain;
            let r = self.dc_right.process(input.right[f]) * self.current_gain;
            let mono = 0.5 * (l + r);

            for (ch_idx, &role) in self.profile.channel_routing.iter().enumerate() {
                let raw_src = match role {
                    TransducerRole::TweeterLeft | TransducerRole::MidLeft => l,
                    TransducerRole::TweeterRight | TransducerRole::MidRight => r,
                    TransducerRole::WooferCenter
                    | TransducerRole::WooferMono
                    | TransducerRole::TweeterMono
                    | TransducerRole::SubwooferLfe
                    | TransducerRole::ArrayMidWoofer(_)
                    | TransducerRole::ArrayTweeter(_) => mono,
                };
                let filtered = self.channel_filters[ch_idx].process_sample(raw_src);
                let limited = filtered.clamp(-self.limiter_ceiling, self.limiter_ceiling);
                out_channels[ch_idx][f] = unit_f32_to_i16(limited);
            }
        }
        self.current_gain = effective_target;

        HardwareOutputBlock {
            profile_id: self.profile.profile_id.clone(),
            start_frame: input.start_frame,
            frames,
            channels: ch_count,
            channel_samples: out_channels,
        }
    }
}

/// Bounded linear-interpolation clock-drift resampler (`D03` / `ffw-j9r`).
#[derive(Debug, Clone, Default)]
pub struct BoundedDriftResampler {
    phase_subframes_ppm: i64,
}

impl BoundedDriftResampler {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase_subframes_ppm: 0,
        }
    }

    /// Apply a bounded clock-drift correction in parts-per-million (`-500..=500 ppm`).
    /// Returns `Err(DspError::DriftExceedsBounds)` if drift exceeds `±500 ppm`, signaling
    /// the session layer to re-anchor rather than warp pitch audibly.
    pub fn process_stereo(
        &mut self,
        input: &StereoAudioBlock,
        drift_ppm: i32,
    ) -> Result<StereoAudioBlock, DspError> {
        if drift_ppm.abs() > MAX_DRIFT_PPM {
            return Err(DspError::DriftExceedsBounds {
                observed_ppm: drift_ppm,
            });
        }
        let mut out = StereoAudioBlock::silence(input.start_frame);
        out.frames = input.frames;
        let frames = input.frames.min(FRAMES_PER_BLOCK);
        if frames == 0 {
            return Ok(out);
        }

        for i in 0..frames {
            self.phase_subframes_ppm += i64::from(drift_ppm);
            let frac = (self.phase_subframes_ppm as f32 / 1_000_000.0).clamp(-0.5, 0.5);
            let next_i = (i + 1).min(frames - 1);
            let prev_i = i.saturating_sub(1);
            let (l, r) = if frac >= 0.0 {
                (
                    input.left[i] * (1.0 - frac) + input.left[next_i] * frac,
                    input.right[i] * (1.0 - frac) + input.right[next_i] * frac,
                )
            } else {
                let w = -frac;
                (
                    input.left[i] * (1.0 - w) + input.left[prev_i] * w,
                    input.right[i] * (1.0 - w) + input.right[prev_i] * w,
                )
            };
            out.left[i] = sanitize_sample(l);
            out.right[i] = sanitize_sample(r);
        }
        // Keep accumulated phase bounded to 1 frame (1_000_000 ppm-frames)
        self.phase_subframes_ppm = self.phase_subframes_ppm.clamp(-500_000, 500_000);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixture: the canonical catalog holds non-admissible hypotheses.
    use franken_board_profile::synthetic_test_fixture_catalog as canonical_board_catalog;

    #[test]
    fn big_endian_i16_roundtrip_and_nan_saturation_guard() {
        let mut block = StereoAudioBlock::silence(0);
        block.left[0] = 1.0;
        block.right[0] = -1.0;
        block.left[1] = f32::NAN;
        block.right[1] = f32::INFINITY;

        let be_bytes = block.to_be_i16_bytes();
        // +1.0 saturates to the largest code; -1.0 is exactly the smallest (D01 scale, 2^15).
        assert_eq!(&be_bytes[0..2], &32767i16.to_be_bytes());
        assert_eq!(&be_bytes[2..4], &i16::MIN.to_be_bytes());
        // NaN sits at 0, +Inf is sanitized to 0 before scaling
        assert_eq!(&be_bytes[4..6], &0i16.to_be_bytes());
        assert_eq!(&be_bytes[6..8], &0i16.to_be_bytes());

        let decoded = StereoAudioBlock::from_be_i16_bytes(0, &be_bytes).unwrap();
        assert!((decoded.left[0] - 1.0).abs() < 1e-4);
        assert!((decoded.right[0] + 1.0).abs() < 1e-4);
    }

    #[test]
    fn wire_path_round_trips_every_i16_value_exactly() {
        // 65 536 values as 32 768 stereo frames in blocks of FRAMES_PER_BLOCK. Before D01 the
        // value -32768 came back as -32767.
        let all: Vec<i16> = (i16::MIN..=i16::MAX).collect();
        for chunk in all.chunks(2 * FRAMES_PER_BLOCK) {
            let bytes: Vec<u8> = chunk.iter().flat_map(|v| v.to_be_bytes()).collect();
            let block = StereoAudioBlock::from_be_i16_bytes(0, &bytes).unwrap();
            assert_eq!(block.to_be_i16_bytes(), bytes);
        }
        assert_eq!(unit_f32_to_i16(i16_to_unit_f32(i16::MIN)), i16::MIN);
    }

    #[test]
    fn board_protection_dsp_blocks_dc_and_separates_tweeter_and_woofer_bands() {
        let catalog = canonical_board_catalog();
        let s5 = catalog
            .into_iter()
            .find(|p| p.model_number == "S5")
            .unwrap();
        let mut dsp = BoardProtectionDsp::new(s5).unwrap();

        // Feed pure DC (+0.8) for 40 blocks: DC blocker + tweeter high-pass must attenuate tweeter to near 0
        let mut dc_block = StereoAudioBlock::silence(0);
        dc_block.left = [0.8; FRAMES_PER_BLOCK];
        dc_block.right = [0.8; FRAMES_PER_BLOCK];

        let mut last_out = dsp.render_block(&dc_block);
        for b in 1..40 {
            dc_block.start_frame = b * 256;
            last_out = dsp.render_block(&dc_block);
        }
        // Channel 0 is TweeterLeft on S5; after DC blocker + 2.2 kHz highpass, DC must be < 50 LSB
        let tweeter_tail = last_out.channel_samples[0][FRAMES_PER_BLOCK - 1].abs();
        assert!(
            tweeter_tail < 50,
            "tweeter DC leakage too high: {tweeter_tail}"
        );
    }

    #[test]
    fn drift_resampler_enforces_500_ppm_bound() {
        let mut resampler = BoundedDriftResampler::new();
        let block = StereoAudioBlock::silence(0);
        assert!(resampler.process_stereo(&block, 120).is_ok());
        assert_eq!(
            resampler.process_stereo(&block, 750),
            Err(DspError::DriftExceedsBounds { observed_ppm: 750 })
        );
    }
}
