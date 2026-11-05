//! Canonical PCM stream format descriptors, buffer layouts/strides and block-length
//! validation (`D01` / `ffw-f3b`). Contract: `docs/contracts/d01.md`.
//!
//! Everything here is plain data plus checked arithmetic. Nothing allocates and nothing
//! indexes a caller's buffer; lengths are validated before any byte is touched.

use serde::{Deserialize, Serialize};

/// Largest number of frames in one block handled by the render path (inclusive).
pub const MAX_BLOCK_FRAMES: usize = crate::FRAMES_PER_BLOCK;
/// Most channels a stream format may carry.
pub const MAX_STREAM_CHANNELS: u8 = 16;
/// Lowest accepted sample rate.
pub const MIN_SAMPLE_RATE_HZ: u32 = 8_000;
/// Highest accepted sample rate.
pub const MAX_SAMPLE_RATE_HZ: u32 = 384_000;
/// Largest accepted frame (interleaved) or plane (planar) stride, in bytes.
pub const MAX_STRIDE_BYTES: usize = 1 << 20;
/// Most frames a ring may hold (65 536 frames: 1.36 s at 48 kHz).
pub const MAX_RING_FRAMES: usize = 1 << 16;

/// Typed, allocation-free, `Copy` errors for the D01 conversion and ring paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum PcmError {
    #[error("block is empty (zero frames)")]
    EmptyBlock,
    #[error("block of {frames} frames exceeds the maximum of {max}")]
    BlockTooLarge { frames: usize, max: usize },
    #[error("block length {len} bytes is not a whole number of {bytes_per_frame}-byte frames")]
    MisalignedBlock { len: usize, bytes_per_frame: usize },
    #[error("channel count {channels} is outside 1..={MAX_STREAM_CHANNELS}")]
    InvalidChannels { channels: u8 },
    #[error("sample rate {hz} Hz is outside {MIN_SAMPLE_RATE_HZ}..={MAX_SAMPLE_RATE_HZ}")]
    InvalidSampleRate { hz: u32 },
    #[error("stride {stride} bytes is smaller than the required {minimum}")]
    StrideTooSmall { stride: usize, minimum: usize },
    #[error("stride {stride} bytes exceeds the maximum of {MAX_STRIDE_BYTES}")]
    StrideTooLarge { stride: usize },
    #[error("channel counts differ: source {src}, destination {dst}")]
    ChannelMismatch { src: u8, dst: u8 },
    #[error("sample rates differ: source {src} Hz, destination {dst} Hz")]
    SampleRateMismatch { src: u32, dst: u32 },
    #[error("buffer holds {have} bytes but {need} are required")]
    BufferTooSmall { have: usize, need: usize },
    #[error("length arithmetic overflowed")]
    LengthOverflow,
    #[error("ring capacity of {frames} frames is outside 1..={MAX_RING_FRAMES}")]
    InvalidRingCapacity { frames: usize },
    #[error("ring full: {free_frames} frames free, {needed_frames} needed")]
    RingFull {
        free_frames: usize,
        needed_frames: usize,
    },
    #[error("ring underrun: {available_frames} frames available, {needed_frames} needed")]
    RingUnderrun {
        available_frames: usize,
        needed_frames: usize,
    },
}

impl PcmError {
    /// Stable, machine-readable name of the variant (used in receipts and e2e vectors).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyBlock => "empty_block",
            Self::BlockTooLarge { .. } => "block_too_large",
            Self::MisalignedBlock { .. } => "misaligned_block",
            Self::InvalidChannels { .. } => "invalid_channels",
            Self::InvalidSampleRate { .. } => "invalid_sample_rate",
            Self::StrideTooSmall { .. } => "stride_too_small",
            Self::StrideTooLarge { .. } => "stride_too_large",
            Self::ChannelMismatch { .. } => "channel_mismatch",
            Self::SampleRateMismatch { .. } => "sample_rate_mismatch",
            Self::BufferTooSmall { .. } => "buffer_too_small",
            Self::LengthOverflow => "length_overflow",
            Self::InvalidRingCapacity { .. } => "invalid_ring_capacity",
            Self::RingFull { .. } => "ring_full",
            Self::RingUnderrun { .. } => "ring_underrun",
        }
    }
}

/// Sample representation of one channel value.
///
/// * `S16`: 16-bit two's complement, 2 bytes.
/// * `S24In32`: 24-bit two's complement in a 4-byte container, **right-justified**. Writers store
///   the value sign-extended into the top byte; readers ignore the top byte and sign-extend bit 23.
/// * `S32`: 32-bit two's complement, 4 bytes.
/// * `F32`: IEEE-754 binary32, 4 bytes, nominal full scale `[-1.0, 1.0]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SampleFormat {
    S16,
    S24In32,
    S32,
    F32,
}

impl SampleFormat {
    /// Every sample format, in a fixed order.
    pub const ALL: [Self; 4] = [Self::S16, Self::S24In32, Self::S32, Self::F32];

    /// Bytes one sample occupies in memory (the container, not the significant bits).
    #[must_use]
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            Self::S16 => 2,
            Self::S24In32 | Self::S32 | Self::F32 => 4,
        }
    }

    /// Significant bits of an integer format; `0` for `F32`.
    #[must_use]
    pub const fn integer_bits(self) -> u32 {
        match self {
            Self::S16 => 16,
            Self::S24In32 => 24,
            Self::S32 => 32,
            Self::F32 => 0,
        }
    }

    #[must_use]
    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32)
    }

    /// Stable lowercase name (`s16`, `s24in32`, `s32`, `f32`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::S16 => "s16",
            Self::S24In32 => "s24in32",
            Self::S32 => "s32",
            Self::F32 => "f32",
        }
    }
}

/// Byte order of multi-byte samples. Explicit and independent of the host CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    pub const ALL: [Self; 2] = [Self::Big, Self::Little];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Big => "big",
            Self::Little => "little",
        }
    }
}

/// Validated stream format: sample format, endianness, channel count and rate.
///
/// Bytes per frame is always `channels * bytes_per_sample` and is exposed explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct StreamFormat {
    sample_format: SampleFormat,
    endian: Endian,
    channels: u8,
    sample_rate_hz: u32,
}

/// The wire format used by the existing stream path: big-endian `s16`, stereo, 48 kHz.
pub const CANONICAL_WIRE_FORMAT: StreamFormat = StreamFormat {
    sample_format: SampleFormat::S16,
    endian: Endian::Big,
    channels: 2,
    sample_rate_hz: crate::CANONICAL_SAMPLE_RATE_HZ,
};

impl StreamFormat {
    /// Build a format, rejecting zero/oversized channel counts and out-of-range rates.
    pub fn new(
        sample_format: SampleFormat,
        endian: Endian,
        channels: u8,
        sample_rate_hz: u32,
    ) -> Result<Self, PcmError> {
        if channels == 0 || channels > MAX_STREAM_CHANNELS {
            return Err(PcmError::InvalidChannels { channels });
        }
        if !(MIN_SAMPLE_RATE_HZ..=MAX_SAMPLE_RATE_HZ).contains(&sample_rate_hz) {
            return Err(PcmError::InvalidSampleRate { hz: sample_rate_hz });
        }
        Ok(Self {
            sample_format,
            endian,
            channels,
            sample_rate_hz,
        })
    }

    #[must_use]
    pub const fn sample_format(&self) -> SampleFormat {
        self.sample_format
    }

    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    #[must_use]
    pub const fn channels(&self) -> u8 {
        self.channels
    }

    #[must_use]
    pub const fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    #[must_use]
    pub const fn bytes_per_sample(&self) -> usize {
        self.sample_format.bytes_per_sample()
    }

    /// Bytes in one packed frame: `channels * bytes_per_sample`. At most 64.
    #[must_use]
    pub const fn bytes_per_frame(&self) -> usize {
        (self.channels as usize) * self.sample_format.bytes_per_sample()
    }
}

/// Memory arrangement of a multi-channel buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layout {
    /// Frame after frame; within a frame, channel 0, 1, ... Frames start `stride_bytes` apart.
    Interleaved,
    /// One contiguous run of samples per channel. Planes start `stride_bytes` apart.
    Planar,
}

impl Layout {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Interleaved => "interleaved",
            Self::Planar => "planar",
        }
    }
}

/// A stream format together with its buffer layout and stride.
///
/// * Interleaved: sample `(frame, channel)` is at `frame * stride + channel * bytes_per_sample`.
///   `stride >= bytes_per_frame`; bytes between frames are padding and are never written.
/// * Planar: sample `(frame, channel)` is at `channel * stride + frame * bytes_per_sample`.
///   `stride` must cover `frames * bytes_per_sample` for every block converted through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BufferSpec {
    format: StreamFormat,
    layout: Layout,
    stride_bytes: usize,
}

impl BufferSpec {
    /// Tightly packed interleaved buffer (`stride == bytes_per_frame`).
    #[must_use]
    pub const fn packed(format: StreamFormat) -> Self {
        Self {
            format,
            layout: Layout::Interleaved,
            stride_bytes: format.bytes_per_frame(),
        }
    }

    /// Interleaved buffer whose frames start `stride_bytes` apart (padding allowed).
    pub fn interleaved(format: StreamFormat, stride_bytes: usize) -> Result<Self, PcmError> {
        if stride_bytes > MAX_STRIDE_BYTES {
            return Err(PcmError::StrideTooLarge {
                stride: stride_bytes,
            });
        }
        let minimum = format.bytes_per_frame();
        if stride_bytes < minimum {
            return Err(PcmError::StrideTooSmall {
                stride: stride_bytes,
                minimum,
            });
        }
        Ok(Self {
            format,
            layout: Layout::Interleaved,
            stride_bytes,
        })
    }

    /// Planar buffer whose channel planes start `plane_stride_bytes` apart.
    pub fn planar(format: StreamFormat, plane_stride_bytes: usize) -> Result<Self, PcmError> {
        if plane_stride_bytes > MAX_STRIDE_BYTES {
            return Err(PcmError::StrideTooLarge {
                stride: plane_stride_bytes,
            });
        }
        let minimum = format.bytes_per_sample();
        if plane_stride_bytes < minimum {
            return Err(PcmError::StrideTooSmall {
                stride: plane_stride_bytes,
                minimum,
            });
        }
        Ok(Self {
            format,
            layout: Layout::Planar,
            stride_bytes: plane_stride_bytes,
        })
    }

    #[must_use]
    pub const fn format(&self) -> &StreamFormat {
        &self.format
    }

    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }

    #[must_use]
    pub const fn stride_bytes(&self) -> usize {
        self.stride_bytes
    }

    /// Bytes a buffer must hold to carry `frames` frames through this spec.
    ///
    /// Interleaved: the last frame needs only its payload, not trailing padding. Planar: the
    /// plane stride must cover `frames` samples, otherwise planes would overlap.
    pub fn required_len(&self, frames: usize) -> Result<usize, PcmError> {
        if frames == 0 {
            return Ok(0);
        }
        let bytes_per_sample = self.format.bytes_per_sample();
        let channels = usize::from(self.format.channels());
        match self.layout {
            Layout::Interleaved => (frames - 1)
                .checked_mul(self.stride_bytes)
                .and_then(|lead| lead.checked_add(self.format.bytes_per_frame()))
                .ok_or(PcmError::LengthOverflow),
            Layout::Planar => {
                let plane = frames
                    .checked_mul(bytes_per_sample)
                    .ok_or(PcmError::LengthOverflow)?;
                if self.stride_bytes < plane {
                    return Err(PcmError::StrideTooSmall {
                        stride: self.stride_bytes,
                        minimum: plane,
                    });
                }
                (channels - 1)
                    .checked_mul(self.stride_bytes)
                    .and_then(|lead| lead.checked_add(plane))
                    .ok_or(PcmError::LengthOverflow)
            }
        }
    }

    /// Byte offset of sample `(frame, channel)`. Checked; does not validate against a buffer.
    pub fn sample_offset(&self, frame: usize, channel: usize) -> Result<usize, PcmError> {
        let bytes_per_sample = self.format.bytes_per_sample();
        let (major, minor, step_major, step_minor) = match self.layout {
            Layout::Interleaved => (frame, channel, self.stride_bytes, bytes_per_sample),
            Layout::Planar => (channel, frame, self.stride_bytes, bytes_per_sample),
        };
        major
            .checked_mul(step_major)
            .and_then(|a| minor.checked_mul(step_minor).and_then(|b| a.checked_add(b)))
            .ok_or(PcmError::LengthOverflow)
    }
}

/// Number of whole frames in a packed interleaved byte block of `len` bytes.
///
/// Checked in this order, so the reported error is deterministic:
/// 1. `len == 0` -> [`PcmError::EmptyBlock`]
/// 2. `len` not a multiple of `bytes_per_frame` -> [`PcmError::MisalignedBlock`]
/// 3. more than [`MAX_BLOCK_FRAMES`] frames -> [`PcmError::BlockTooLarge`]
///
/// Exactly [`MAX_BLOCK_FRAMES`] frames is accepted; so is any shorter final partial block.
pub fn frames_in_packed_bytes(len: usize, format: &StreamFormat) -> Result<usize, PcmError> {
    if len == 0 {
        return Err(PcmError::EmptyBlock);
    }
    let bytes_per_frame = format.bytes_per_frame();
    if !len.is_multiple_of(bytes_per_frame) {
        return Err(PcmError::MisalignedBlock {
            len,
            bytes_per_frame,
        });
    }
    let frames = len / bytes_per_frame;
    if frames > MAX_BLOCK_FRAMES {
        return Err(PcmError::BlockTooLarge {
            frames,
            max: MAX_BLOCK_FRAMES,
        });
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(sf: SampleFormat, channels: u8) -> StreamFormat {
        StreamFormat::new(sf, Endian::Big, channels, 48_000).unwrap()
    }

    #[test]
    fn bytes_per_frame_is_explicit_for_every_format_and_channel_count() {
        let expect = [
            (SampleFormat::S16, 2usize),
            (SampleFormat::S24In32, 4),
            (SampleFormat::S32, 4),
            (SampleFormat::F32, 4),
        ];
        for (sf, bps) in expect {
            assert_eq!(sf.bytes_per_sample(), bps);
            for ch in 1..=MAX_STREAM_CHANNELS {
                let f = fmt(sf, ch);
                assert_eq!(f.bytes_per_frame(), usize::from(ch) * bps, "{sf:?} x{ch}");
            }
        }
        assert_eq!(CANONICAL_WIRE_FORMAT.bytes_per_frame(), 4);
        assert_eq!(SampleFormat::S24In32.integer_bits(), 24);
        assert_eq!(SampleFormat::F32.integer_bits(), 0);
    }

    #[test]
    fn stream_format_rejects_bad_channels_and_rates() {
        let ok = |ch, hz| StreamFormat::new(SampleFormat::S16, Endian::Big, ch, hz);
        assert_eq!(
            ok(0, 48_000),
            Err(PcmError::InvalidChannels { channels: 0 })
        );
        assert_eq!(
            ok(17, 48_000),
            Err(PcmError::InvalidChannels { channels: 17 })
        );
        assert!(ok(1, 48_000).is_ok());
        assert!(ok(16, 48_000).is_ok());
        assert_eq!(ok(2, 0), Err(PcmError::InvalidSampleRate { hz: 0 }));
        assert_eq!(ok(2, 7_999), Err(PcmError::InvalidSampleRate { hz: 7_999 }));
        assert!(ok(2, 8_000).is_ok());
        assert!(ok(2, 384_000).is_ok());
        assert_eq!(
            ok(2, 384_001),
            Err(PcmError::InvalidSampleRate { hz: 384_001 })
        );
    }

    #[test]
    fn packed_block_lengths_zero_max_misaligned_and_partial() {
        let f = fmt(SampleFormat::S16, 2); // 4 bytes per frame
        assert_eq!(frames_in_packed_bytes(0, &f), Err(PcmError::EmptyBlock));
        assert_eq!(frames_in_packed_bytes(4, &f), Ok(1));
        assert_eq!(frames_in_packed_bytes(12, &f), Ok(3)); // final partial block
        assert_eq!(frames_in_packed_bytes(4 * 255, &f), Ok(255));
        assert_eq!(frames_in_packed_bytes(4 * 256, &f), Ok(256)); // maximum is inclusive
        assert_eq!(
            frames_in_packed_bytes(4 * 257, &f),
            Err(PcmError::BlockTooLarge {
                frames: 257,
                max: 256
            })
        );
        for odd in [1, 2, 3, 5, 4 * 256 + 1, 4 * 257 + 3] {
            assert_eq!(
                frames_in_packed_bytes(odd, &f),
                Err(PcmError::MisalignedBlock {
                    len: odd,
                    bytes_per_frame: 4
                }),
                "len {odd}"
            );
        }
        // A length that would overflow a naive frames*bytes product is still a clean error.
        assert_eq!(
            frames_in_packed_bytes(usize::MAX, &f),
            Err(PcmError::MisalignedBlock {
                len: usize::MAX,
                bytes_per_frame: 4
            })
        );
        assert!(matches!(
            frames_in_packed_bytes(usize::MAX - (usize::MAX % 4), &f),
            Err(PcmError::BlockTooLarge { .. })
        ));
    }

    #[test]
    fn interleaved_required_len_and_offsets_with_padding() {
        let f = fmt(SampleFormat::S16, 2);
        let packed = BufferSpec::packed(f);
        assert_eq!(packed.stride_bytes(), 4);
        assert_eq!(packed.required_len(0), Ok(0));
        assert_eq!(packed.required_len(1), Ok(4));
        assert_eq!(packed.required_len(3), Ok(12));

        let padded = BufferSpec::interleaved(f, 8).unwrap();
        assert_eq!(padded.required_len(1), Ok(4)); // no trailing padding needed
        assert_eq!(padded.required_len(3), Ok(2 * 8 + 4));
        assert_eq!(padded.sample_offset(0, 0), Ok(0));
        assert_eq!(padded.sample_offset(0, 1), Ok(2));
        assert_eq!(padded.sample_offset(2, 1), Ok(2 * 8 + 2));

        assert_eq!(
            BufferSpec::interleaved(f, 3),
            Err(PcmError::StrideTooSmall {
                stride: 3,
                minimum: 4
            })
        );
        assert_eq!(
            BufferSpec::interleaved(f, MAX_STRIDE_BYTES + 1),
            Err(PcmError::StrideTooLarge {
                stride: MAX_STRIDE_BYTES + 1
            })
        );
    }

    #[test]
    fn planar_required_len_offsets_and_overlap_rejection() {
        let f = fmt(SampleFormat::S24In32, 3); // 4 bytes per sample
        let planar = BufferSpec::planar(f, 40).unwrap(); // room for 10 frames per plane
        assert_eq!(planar.layout(), Layout::Planar);
        assert_eq!(planar.required_len(10), Ok(2 * 40 + 10 * 4));
        assert_eq!(planar.required_len(1), Ok(2 * 40 + 4));
        assert_eq!(planar.sample_offset(0, 0), Ok(0));
        assert_eq!(planar.sample_offset(3, 0), Ok(12));
        assert_eq!(planar.sample_offset(0, 2), Ok(80));
        assert_eq!(planar.sample_offset(5, 1), Ok(40 + 20));
        // 11 frames would overflow a 40-byte plane into the next one.
        assert_eq!(
            planar.required_len(11),
            Err(PcmError::StrideTooSmall {
                stride: 40,
                minimum: 44
            })
        );
        assert_eq!(
            BufferSpec::planar(f, 3),
            Err(PcmError::StrideTooSmall {
                stride: 3,
                minimum: 4
            })
        );
    }

    #[test]
    fn offset_arithmetic_is_checked() {
        let f = fmt(SampleFormat::F32, 2);
        let spec = BufferSpec::interleaved(f, MAX_STRIDE_BYTES).unwrap();
        assert_eq!(
            spec.sample_offset(usize::MAX, 0),
            Err(PcmError::LengthOverflow)
        );
        assert_eq!(spec.required_len(usize::MAX), Err(PcmError::LengthOverflow));
    }

    #[test]
    fn error_codes_are_stable_and_distinct() {
        let all = [
            PcmError::EmptyBlock,
            PcmError::BlockTooLarge { frames: 1, max: 0 },
            PcmError::MisalignedBlock {
                len: 1,
                bytes_per_frame: 2,
            },
            PcmError::InvalidChannels { channels: 0 },
            PcmError::InvalidSampleRate { hz: 0 },
            PcmError::StrideTooSmall {
                stride: 0,
                minimum: 1,
            },
            PcmError::StrideTooLarge { stride: 0 },
            PcmError::ChannelMismatch { src: 1, dst: 2 },
            PcmError::SampleRateMismatch { src: 1, dst: 2 },
            PcmError::BufferTooSmall { have: 0, need: 1 },
            PcmError::LengthOverflow,
            PcmError::InvalidRingCapacity { frames: 0 },
            PcmError::RingFull {
                free_frames: 0,
                needed_frames: 1,
            },
            PcmError::RingUnderrun {
                available_frames: 0,
                needed_frames: 1,
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for e in all {
            assert!(seen.insert(e.code()), "duplicate code {}", e.code());
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(seen.len(), 14);
    }
}
