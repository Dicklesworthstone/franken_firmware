//! Bit-exact sample conversion between widths, signs, endiannesses and layouts
//! (`D01` / `ffw-f3b`). Contract and rule table: `docs/contracts/d01.md`.
//!
//! Rules (all deterministic, host-endianness independent):
//!
//! * **Integer to wider integer**: left shift (zero-fill). Full scale maps to full scale
//!   shifted, e.g. `s16 0x7FFF -> s32 0x7FFF_0000`; the conversion is exactly reversible.
//! * **Integer to narrower integer**: round to nearest, ties toward `+infinity`
//!   (`(v + half) >> shift`), then saturate. Saturation is counted, not logged per sample.
//! * **Integer to `f32`**: `v / 2^(bits-1)` rounded once to `f32` (nearest-even). Result is in
//!   `[-1.0, 1.0]`.
//! * **`f32` to integer**: non-finite -> `0`; otherwise `round_ties_even(x * 2^(bits-1))`, saturated
//!   to the integer range. `+1.0` saturates to `max`; `-1.0` is exactly `min`.
//!
//! The two float conversions and the `f32` clamp are computed with integer arithmetic on the IEEE-754
//! fields. Their values are exactly those of the `f64` formulas they replaced (the original is kept as
//! the oracle in `convert/soft_float_tests.rs`), but a soft-float target (`mips-unknown-linux-musl`)
//! executes no floating-point helper call for them: the `f64` divide, multiply, round and compare ran on
//! every sample of every channel.
//! * **`f32` to `f32`**: non-finite -> `+0.0`; finite values clamp to `[-1.0, 1.0]`; everything
//!   else (including `-0.0` and subnormals) passes through bit-for-bit.
//!
//! Non-finite samples become silence, never full scale: a codec or transport error must not
//! turn into a sample burst. Nothing here allocates, logs per sample, or can panic on a
//! caller-controlled length.

use crate::format::{
    BufferSpec, Endian, MAX_BLOCK_FRAMES, PcmError, SampleFormat, StreamFormat,
    frames_in_packed_bytes,
};
use serde::Serialize;

/// Per-block counters. Bounded diagnostics instead of per-sample logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ConvertStats {
    /// Samples clamped to the destination range (including rounding that overflowed).
    pub saturated: u32,
    /// Non-finite `f32` samples flushed to zero.
    pub non_finite: u32,
}

impl ConvertStats {
    fn note_saturated(&mut self) {
        self.saturated = self.saturated.saturating_add(1);
    }

    fn note_non_finite(&mut self) {
        self.non_finite = self.non_finite.saturating_add(1);
    }

    /// Add another block's counters (saturating).
    pub fn merge(&mut self, other: Self) {
        self.saturated = self.saturated.saturating_add(other.saturated);
        self.non_finite = self.non_finite.saturating_add(other.non_finite);
    }
}

/// `bits` clamped to `1..=32`, minus one: the exponent of the full-scale code `2^(bits-1)`.
fn scale_shift(bits: u32) -> u32 {
    bits.clamp(1, 32) - 1
}

/// Signed `bits`-bit integer to `f32` in `[-1.0, 1.0]`: `value / 2^(bits-1)`, rounded once to nearest-even.
///
/// Integer arithmetic on the IEEE-754 fields only, so a soft-float target executes no floating-point helper
/// call. Scaling by a power of two is exact, so the result is the integer rounded to a 24-bit significand
/// with the exponent lowered by `bits - 1`; for every `i32` that exponent stays normal. Bit-identical to the
/// `f64` division it replaced (`convert/soft_float_tests.rs` keeps that original as the oracle).
#[must_use]
pub fn int_to_f32(value: i32, bits: u32) -> f32 {
    if value == 0 {
        return 0.0;
    }
    let magnitude = value.unsigned_abs();
    let top = 31 - magnitude.leading_zeros();
    let (significand, carry) = if top <= 23 {
        (magnitude << (23 - top), 0)
    } else {
        let dropped = top - 23;
        let kept = magnitude >> dropped;
        let rest = magnitude & ((1u32 << dropped) - 1);
        let half = 1u32 << (dropped - 1);
        let rounded = kept + u32::from(rest > half || (rest == half && kept & 1 == 1));
        if rounded == 1 << 24 {
            (rounded >> 1, 1)
        } else {
            (rounded, 0)
        }
    };
    let exponent = 127 + top + carry - scale_shift(bits);
    let sign = u32::from(value < 0) << 31;
    f32::from_bits(sign | (exponent << 23) | (significand & 0x007F_FFFF))
}

/// `value / 2^dropped` rounded half to even, for a 24-bit `value` and `dropped >= 1`. Dropping 25 or more bits
/// leaves less than half of one unit, so the result is 0.
fn round_shift_right(value: u32, dropped: u32) -> u32 {
    if dropped > 24 {
        return 0;
    }
    let kept = value >> dropped;
    let rest = value & ((1u32 << dropped) - 1);
    let half = 1u32 << (dropped - 1);
    kept + u32::from(rest > half || (rest == half && kept & 1 == 1))
}

/// The saturated code for the sign of the input, counted. `limit` is `2^(bits-1)`.
fn saturated_code(negative: bool, limit: u32, stats: &mut ConvertStats) -> i32 {
    stats.note_saturated();
    if negative {
        (limit as i32).wrapping_neg()
    } else {
        (limit - 1) as i32
    }
}

/// `f32` to a signed `bits`-bit integer: non-finite -> 0, ties-to-even, saturating.
///
/// Integer arithmetic on the IEEE-754 fields only (see [`int_to_f32`]). With a 24-bit significand `s` and biased
/// exponent `e`, `|x| * 2^(bits-1) = s * 2^(e - 150 + bits - 1)`: a left shift, or a right shift rounded half to
/// even. Positive results saturate at `2^(bits-1)` and above, negative ones above `2^(bits-1)`, so `-1.0` is
/// exactly the smallest code and `+1.0` saturates to the largest. Zero and subnormals are far below half a code.
pub fn f32_to_int(x: f32, bits: u32, stats: &mut ConvertStats) -> i32 {
    let raw = x.to_bits();
    let biased = (raw >> 23) & 0xFF;
    if biased == 0xFF {
        stats.note_non_finite();
        return 0;
    }
    if biased == 0 {
        return 0;
    }
    let negative = raw >> 31 == 1;
    let limit = 1u32 << scale_shift(bits);
    let significand = (raw & 0x007F_FFFF) | 0x0080_0000;
    let shift = biased as i32 - 150 + scale_shift(bits) as i32;
    let scaled = if shift > 8 {
        // At least 2^32: beyond every code, whatever the sign.
        return saturated_code(negative, limit, stats);
    } else if shift >= 0 {
        significand << shift
    } else {
        round_shift_right(significand, shift.unsigned_abs())
    };
    if negative {
        if scaled > limit {
            return saturated_code(true, limit, stats);
        }
        return (scaled as i32).wrapping_neg();
    }
    if scaled >= limit {
        return saturated_code(false, limit, stats);
    }
    scaled as i32
}

/// Signed `from_bits`-bit integer to a signed `to_bits`-bit integer (widen = shift, narrow =
/// round-half-up then saturate).
pub fn int_to_int(value: i32, from_bits: u32, to_bits: u32, stats: &mut ConvertStats) -> i32 {
    if to_bits >= from_bits {
        return value << (to_bits - from_bits);
    }
    let shift = from_bits - to_bits;
    let half = 1i64 << (shift - 1);
    let rounded = (i64::from(value) + half) >> shift;
    let max = (1i64 << (to_bits - 1)) - 1;
    let min = -(1i64 << (to_bits - 1));
    if rounded > max {
        stats.note_saturated();
        return max as i32;
    }
    if rounded < min {
        stats.note_saturated();
        return min as i32;
    }
    rounded as i32
}

/// `f32` to `f32`: non-finite -> `+0.0`, finite values clamp to `[-1.0, 1.0]`.
pub fn f32_to_f32(x: f32, stats: &mut ConvertStats) -> f32 {
    // Integer compares on the magnitude bits: for finite values `|x| > 1.0` is `bits > 0x3F80_0000`, so no
    // soft-float comparison helper runs. NaN and infinity have an all-ones exponent.
    let raw = x.to_bits();
    let magnitude = raw & 0x7FFF_FFFF;
    if magnitude >= 0x7F80_0000 {
        stats.note_non_finite();
        return 0.0;
    }
    if magnitude > 0x3F80_0000 {
        stats.note_saturated();
        return if raw >> 31 == 1 { -1.0 } else { 1.0 };
    }
    x
}

/// `s16` to `f32` on the D01 scale (`v / 32768`). Exactly reversible by [`f32_to_s16`].
#[must_use]
pub fn s16_to_f32(sample: i16) -> f32 {
    int_to_f32(i32::from(sample), 16)
}

/// `f32` to `s16` on the D01 scale (`round_ties_even(x * 32768)`, saturating, non-finite -> 0).
#[must_use]
pub fn f32_to_s16(sample: f32) -> i16 {
    let mut stats = ConvertStats::default();
    f32_to_int(sample, 16, &mut stats) as i16
}

/// One decoded sample: an integer already sign-extended to `i32`, or an `f32`.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Raw {
    Int(i32),
    Float(f32),
}

fn load_u32(bytes: &[u8], endian: Endian) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(match endian {
        Endian::Big => u32::from_be_bytes(array),
        Endian::Little => u32::from_le_bytes(array),
    })
}

fn read_sample(bytes: &[u8], format: SampleFormat, endian: Endian) -> Option<Raw> {
    match format {
        SampleFormat::S16 => {
            let array: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
            let value = match endian {
                Endian::Big => i16::from_be_bytes(array),
                Endian::Little => i16::from_le_bytes(array),
            };
            Some(Raw::Int(i32::from(value)))
        }
        // Right-justified 24-bit value; the top byte is ignored and bit 23 is sign-extended.
        SampleFormat::S24In32 => {
            let raw = load_u32(bytes, endian)?;
            Some(Raw::Int(((raw << 8) as i32) >> 8))
        }
        SampleFormat::S32 => Some(Raw::Int(load_u32(bytes, endian)? as i32)),
        SampleFormat::F32 => Some(Raw::Float(f32::from_bits(load_u32(bytes, endian)?))),
    }
}

fn store_u32(slot: &mut [u8], value: u32, endian: Endian) -> Option<()> {
    let bytes = match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    };
    slot.get_mut(..4)?.copy_from_slice(&bytes);
    Some(())
}

fn write_sample(slot: &mut [u8], format: SampleFormat, endian: Endian, raw: Raw) -> Option<()> {
    match (format, raw) {
        (SampleFormat::S16, Raw::Int(value)) => {
            let value = i16::try_from(value).ok()?;
            let bytes = match endian {
                Endian::Big => value.to_be_bytes(),
                Endian::Little => value.to_le_bytes(),
            };
            slot.get_mut(..2)?.copy_from_slice(&bytes);
            Some(())
        }
        // `value` is already sign-extended, so the top byte is written as the sign extension.
        (SampleFormat::S24In32 | SampleFormat::S32, Raw::Int(value)) => {
            store_u32(slot, value as u32, endian)
        }
        (SampleFormat::F32, Raw::Float(x)) => store_u32(slot, x.to_bits(), endian),
        _ => None,
    }
}

fn convert_raw(raw: Raw, from: SampleFormat, to: SampleFormat, stats: &mut ConvertStats) -> Raw {
    match (raw, to.is_float()) {
        (Raw::Int(v), false) => {
            Raw::Int(int_to_int(v, from.integer_bits(), to.integer_bits(), stats))
        }
        (Raw::Int(v), true) => Raw::Float(int_to_f32(v, from.integer_bits())),
        (Raw::Float(x), false) => Raw::Int(f32_to_int(x, to.integer_bits(), stats)),
        (Raw::Float(x), true) => Raw::Float(f32_to_f32(x, stats)),
    }
}

/// Convert `frames` frames from `src` (laid out per `src_spec`) into `dst` (per `dst_spec`).
///
/// * `frames` must be `1..=MAX_BLOCK_FRAMES`; zero and oversized blocks are typed errors.
/// * Channel counts and sample rates must match; this function never mixes or resamples.
/// * Both buffers are length-checked against `required_len(frames)` before any byte is read or
///   written; on error `dst` is untouched. Buffers may be longer than required; bytes outside
///   the addressed samples (padding, guard bytes) are never written.
/// * Does not allocate.
pub fn convert_block(
    src: &[u8],
    src_spec: &BufferSpec,
    dst: &mut [u8],
    dst_spec: &BufferSpec,
    frames: usize,
) -> Result<ConvertStats, PcmError> {
    if frames == 0 {
        return Err(PcmError::EmptyBlock);
    }
    if frames > MAX_BLOCK_FRAMES {
        return Err(PcmError::BlockTooLarge {
            frames,
            max: MAX_BLOCK_FRAMES,
        });
    }
    let src_format = src_spec.format();
    let dst_format = dst_spec.format();
    if src_format.channels() != dst_format.channels() {
        return Err(PcmError::ChannelMismatch {
            src: src_format.channels(),
            dst: dst_format.channels(),
        });
    }
    if src_format.sample_rate_hz() != dst_format.sample_rate_hz() {
        return Err(PcmError::SampleRateMismatch {
            src: src_format.sample_rate_hz(),
            dst: dst_format.sample_rate_hz(),
        });
    }
    let need_src = src_spec.required_len(frames)?;
    let need_dst = dst_spec.required_len(frames)?;
    let src_len = src.len();
    let dst_len = dst.len();
    if src_len < need_src {
        return Err(PcmError::BufferTooSmall {
            have: src_len,
            need: need_src,
        });
    }
    if dst_len < need_dst {
        return Err(PcmError::BufferTooSmall {
            have: dst_len,
            need: need_dst,
        });
    }

    let src_sample_bytes = src_format.bytes_per_sample();
    let dst_sample_bytes = dst_format.bytes_per_sample();
    let src_short = PcmError::BufferTooSmall {
        have: src_len,
        need: need_src,
    };
    let dst_short = PcmError::BufferTooSmall {
        have: dst_len,
        need: need_dst,
    };
    let mut stats = ConvertStats::default();
    for frame in 0..frames {
        for channel in 0..usize::from(src_format.channels()) {
            let src_start = src_spec.sample_offset(frame, channel)?;
            let dst_start = dst_spec.sample_offset(frame, channel)?;
            let src_end = src_start
                .checked_add(src_sample_bytes)
                .ok_or(PcmError::LengthOverflow)?;
            let dst_end = dst_start
                .checked_add(dst_sample_bytes)
                .ok_or(PcmError::LengthOverflow)?;
            let raw = src
                .get(src_start..src_end)
                .and_then(|bytes| {
                    read_sample(bytes, src_format.sample_format(), src_format.endian())
                })
                .ok_or(src_short)?;
            let converted = convert_raw(
                raw,
                src_format.sample_format(),
                dst_format.sample_format(),
                &mut stats,
            );
            let slot = dst.get_mut(dst_start..dst_end).ok_or(dst_short)?;
            write_sample(
                slot,
                dst_format.sample_format(),
                dst_format.endian(),
                converted,
            )
            .ok_or(dst_short)?;
        }
    }
    Ok(stats)
}

/// Convert a packed interleaved block, deriving the frame count from `src.len()`.
///
/// Returns `(frames, stats)`; `frames * dst_format.bytes_per_frame()` bytes of `dst` were
/// written. Zero, misaligned and oversized `src` lengths are typed errors
/// (see [`frames_in_packed_bytes`]).
pub fn convert_packed(
    src: &[u8],
    src_format: &StreamFormat,
    dst: &mut [u8],
    dst_format: &StreamFormat,
) -> Result<(usize, ConvertStats), PcmError> {
    let frames = frames_in_packed_bytes(src.len(), src_format)?;
    let stats = convert_block(
        src,
        &BufferSpec::packed(*src_format),
        dst,
        &BufferSpec::packed(*dst_format),
        frames,
    )?;
    Ok((frames, stats))
}

#[cfg(test)]
mod soft_float_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    fn fmt(sf: SampleFormat, endian: Endian, channels: u8) -> StreamFormat {
        StreamFormat::new(sf, endian, channels, 48_000).unwrap()
    }

    fn f32_bytes(values: &[f32], endian: Endian) -> Vec<u8> {
        values
            .iter()
            .flat_map(|v| match endian {
                Endian::Big => v.to_bits().to_be_bytes(),
                Endian::Little => v.to_bits().to_le_bytes(),
            })
            .collect()
    }

    // ---- byte-level endian vectors (literal, hand-computed) -------------------------------

    fn written(format: SampleFormat, endian: Endian, raw: Raw) -> Vec<u8> {
        let mut slot = vec![0xEEu8; format.bytes_per_sample()];
        write_sample(&mut slot, format, endian, raw).expect("write");
        slot
    }

    #[test]
    fn s16_endian_vectors() {
        assert_eq!(
            written(SampleFormat::S16, Endian::Big, Raw::Int(0x1234)),
            [0x12, 0x34]
        );
        assert_eq!(
            written(SampleFormat::S16, Endian::Little, Raw::Int(0x1234)),
            [0x34, 0x12]
        );
        assert_eq!(
            written(SampleFormat::S16, Endian::Big, Raw::Int(-2)),
            [0xFF, 0xFE]
        );
        assert_eq!(
            written(SampleFormat::S16, Endian::Little, Raw::Int(-2)),
            [0xFE, 0xFF]
        );
        assert_eq!(
            written(SampleFormat::S16, Endian::Big, Raw::Int(-32768)),
            [0x80, 0x00]
        );
        assert_eq!(
            written(SampleFormat::S16, Endian::Little, Raw::Int(32767)),
            [0xFF, 0x7F]
        );
    }

    #[test]
    fn s24_in_32_endian_and_justification_vectors() {
        let f = SampleFormat::S24In32;
        assert_eq!(
            written(f, Endian::Big, Raw::Int(0x12_3456)),
            [0x00, 0x12, 0x34, 0x56]
        );
        assert_eq!(
            written(f, Endian::Little, Raw::Int(0x12_3456)),
            [0x56, 0x34, 0x12, 0x00]
        );
        // Negative values are written sign-extended into the top byte.
        assert_eq!(
            written(f, Endian::Big, Raw::Int(-2)),
            [0xFF, 0xFF, 0xFF, 0xFE]
        );
        assert_eq!(
            written(f, Endian::Little, Raw::Int(-2)),
            [0xFE, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            written(f, Endian::Big, Raw::Int(-8_388_608)),
            [0xFF, 0x80, 0x00, 0x00]
        );
        assert_eq!(
            written(f, Endian::Big, Raw::Int(8_388_607)),
            [0x00, 0x7F, 0xFF, 0xFF]
        );
        // Readers ignore the top byte and sign-extend bit 23.
        assert_eq!(
            read_sample(&[0x7F, 0x80, 0x00, 0x00], f, Endian::Big),
            Some(Raw::Int(-8_388_608))
        );
        assert_eq!(
            read_sample(&[0x12, 0x00, 0x00, 0x01], f, Endian::Big),
            Some(Raw::Int(1))
        );
        // Little-endian bytes 01 00 80 AB are the word 0xAB80_0001: low 24 bits 0x80_0001 with
        // bit 23 set, so the value is 0x80_0001 - 0x100_0000 = -8_388_607 (top byte 0xAB ignored).
        assert_eq!(
            read_sample(&[0x01, 0x00, 0x80, 0xAB], f, Endian::Little),
            Some(Raw::Int(-8_388_607))
        );
        assert_eq!(
            read_sample(&[0x01, 0x00, 0x00, 0xAB], f, Endian::Little),
            Some(Raw::Int(1))
        );
    }

    #[test]
    fn s32_and_f32_endian_vectors() {
        assert_eq!(
            written(SampleFormat::S32, Endian::Big, Raw::Int(0x0102_0304)),
            [1, 2, 3, 4]
        );
        assert_eq!(
            written(SampleFormat::S32, Endian::Little, Raw::Int(0x0102_0304)),
            [4, 3, 2, 1]
        );
        assert_eq!(
            written(SampleFormat::S32, Endian::Big, Raw::Int(i32::MIN)),
            [0x80, 0, 0, 0]
        );
        let f = SampleFormat::F32;
        assert_eq!(written(f, Endian::Big, Raw::Float(1.0)), [0x3F, 0x80, 0, 0]);
        assert_eq!(
            written(f, Endian::Little, Raw::Float(1.0)),
            [0, 0, 0x80, 0x3F]
        );
        assert_eq!(written(f, Endian::Big, Raw::Float(-2.0)), [0xC0, 0, 0, 0]);
        assert_eq!(written(f, Endian::Big, Raw::Float(0.5)), [0x3F, 0, 0, 0]);
        assert_eq!(written(f, Endian::Big, Raw::Float(-0.0)), [0x80, 0, 0, 0]);
    }

    #[test]
    fn read_rejects_short_slices_without_panicking() {
        for f in SampleFormat::ALL {
            let need = f.bytes_per_sample();
            for len in 0..need {
                let bytes = vec![0u8; len];
                assert_eq!(read_sample(&bytes, f, Endian::Big), None, "{f:?} len {len}");
                let mut slot = vec![0u8; len];
                let raw = if f.is_float() {
                    Raw::Float(0.0)
                } else {
                    Raw::Int(0)
                };
                assert_eq!(write_sample(&mut slot, f, Endian::Big, raw), None);
            }
        }
        // A float raw cannot be written as an integer format, and vice versa.
        let mut slot = [0u8; 4];
        assert_eq!(
            write_sample(&mut slot, SampleFormat::S32, Endian::Big, Raw::Float(0.0)),
            None
        );
        assert_eq!(
            write_sample(&mut slot, SampleFormat::F32, Endian::Big, Raw::Int(0)),
            None
        );
        // An out-of-range value for s16 is refused, never wrapped.
        assert_eq!(
            write_sample(&mut slot, SampleFormat::S16, Endian::Big, Raw::Int(40_000)),
            None
        );
    }

    // ---- integer width table (literal) ------------------------------------------------------

    #[test]
    fn integer_width_vectors() {
        // (value, from_bits, to_bits, expected, expected_saturations)
        let table: &[(i32, u32, u32, i32, u32)] = &[
            // widening is a plain left shift
            (0x7FFF, 16, 32, 0x7FFF_0000, 0),
            (-0x8000, 16, 32, i32::MIN, 0),
            (1, 16, 32, 0x1_0000, 0),
            (-1, 16, 32, -0x1_0000, 0),
            (0x7FFF, 16, 24, 0x7F_FF00, 0),
            (-0x8000, 16, 24, -0x80_0000, 0),
            (0x7F_FFFF, 24, 32, 0x7FFF_FF00, 0),
            (-0x80_0000, 24, 32, i32::MIN, 0),
            // identity
            (123, 16, 16, 123, 0),
            (-0x80_0000, 24, 24, -0x80_0000, 0),
            (i32::MIN, 32, 32, i32::MIN, 0),
            // narrowing 32 -> 16: round half up, then saturate
            (0x0000_7FFF, 32, 16, 0, 0),
            (0x0000_8000, 32, 16, 1, 0),
            (-0x0000_8000, 32, 16, 0, 0),
            (-0x0000_8001, 32, 16, -1, 0),
            (0x7FFF_7FFF, 32, 16, 32767, 0),
            (0x7FFF_8000, 32, 16, 32767, 1),
            (i32::MAX, 32, 16, 32767, 1),
            (i32::MIN, 32, 16, -32768, 0),
            // narrowing 32 -> 24
            (0x7FFF_FF7F, 32, 24, 0x7F_FFFF, 0),
            (0x7FFF_FF80, 32, 24, 0x7F_FFFF, 1),
            (i32::MAX, 32, 24, 0x7F_FFFF, 1),
            (i32::MIN, 32, 24, -0x80_0000, 0),
            (0x7F, 32, 24, 0, 0),
            (0x80, 32, 24, 1, 0),
            // narrowing 24 -> 16
            (0x7F_FFFF, 24, 16, 32767, 1),
            (0x7F_FF7F, 24, 16, 32767, 0),
            (0x7F, 24, 16, 0, 0),
            (0x80, 24, 16, 1, 0),
            (-0x80, 24, 16, 0, 0),
            (-0x81, 24, 16, -1, 0),
            (-0x80_0000, 24, 16, -32768, 0),
        ];
        for &(value, from, to, expected, sat) in table {
            let mut stats = ConvertStats::default();
            let got = int_to_int(value, from, to, &mut stats);
            assert_eq!(got, expected, "{value:#x} {from}->{to}");
            assert_eq!(stats.saturated, sat, "{value:#x} {from}->{to} saturations");
            assert_eq!(stats.non_finite, 0);
        }
    }

    // ---- f32 -> integer / f32 -> f32 / integer -> f32 (literal) ----------------------------------

    #[test]
    fn float_to_integer_vectors() {
        let tiny_half = 0.5f32 / 32768.0; // exactly half an s16 LSB
        let table: &[(f32, u32, i32, u32, u32)] = &[
            // (input, bits, expected, saturated, non_finite)
            (0.0, 16, 0, 0, 0),
            (-0.0, 16, 0, 0, 0),
            (0.5, 16, 16384, 0, 0),
            (-0.5, 16, -16384, 0, 0),
            (1.0, 16, 32767, 1, 0),
            (-1.0, 16, -32768, 0, 0),
            (2.0, 16, 32767, 1, 0),
            (-2.0, 16, -32768, 1, 0),
            (f32::MAX, 16, 32767, 1, 0),
            (f32::MIN, 16, -32768, 1, 0),
            (f32::NAN, 16, 0, 0, 1),
            (f32::INFINITY, 16, 0, 0, 1),
            (f32::NEG_INFINITY, 16, 0, 0, 1),
            (f32::from_bits(1), 16, 0, 0, 0), // smallest subnormal
            // exact ties go to even
            (tiny_half, 16, 0, 0, 0),
            (3.0 * tiny_half, 16, 2, 0, 0),
            (5.0 * tiny_half, 16, 2, 0, 0),
            (7.0 * tiny_half, 16, 4, 0, 0),
            (-tiny_half, 16, 0, 0, 0),
            (-3.0 * tiny_half, 16, -2, 0, 0),
            (-5.0 * tiny_half, 16, -2, 0, 0),
            // just past a tie rounds away
            (f32::from_bits(tiny_half.to_bits() + 1), 16, 1, 0, 0),
            // 24- and 32-bit full scale
            (1.0, 24, 0x7F_FFFF, 1, 0),
            (-1.0, 24, -0x80_0000, 0, 0),
            (0.5, 24, 0x40_0000, 0, 0),
            (1.0, 32, i32::MAX, 1, 0),
            (-1.0, 32, i32::MIN, 0, 0),
            (0.5, 32, 0x4000_0000, 0, 0),
            (f32::from_bits(0x3F7F_FFFF), 32, 2_147_483_520, 0, 0), // 1 - 2^-24
            (f32::from_bits(0x3F80_0001), 32, i32::MAX, 1, 0),      // 1 + 2^-23
        ];
        for &(x, bits, expected, sat, nonfinite) in table {
            let mut stats = ConvertStats::default();
            let got = f32_to_int(x, bits, &mut stats);
            assert_eq!(got, expected, "{x:?} ({:#010x}) -> s{bits}", x.to_bits());
            assert_eq!(stats.saturated, sat, "{x:?} s{bits} saturations");
            assert_eq!(stats.non_finite, nonfinite, "{x:?} s{bits} non-finite");
        }
    }

    #[test]
    fn integer_to_float_vectors() {
        assert_eq!(int_to_f32(0, 16), 0.0);
        assert_eq!(int_to_f32(16384, 16), 0.5);
        assert_eq!(int_to_f32(-32768, 16), -1.0);
        // 32767 / 32768 = 0.999969482421875 exactly (15 significant bits), written as the exact
        // quotient so the f32 value is spelled out without a literal longer than f32 carries.
        assert_eq!(int_to_f32(32767, 16), 32_767.0 / 32_768.0);
        assert_eq!(int_to_f32(1, 16), 1.0 / 32768.0);
        assert_eq!(int_to_f32(0x7F_FFFF, 24), 1.0 - 1.0 / 8_388_608.0);
        assert_eq!(int_to_f32(-0x80_0000, 24), -1.0);
        assert_eq!(int_to_f32(0x4000_0000, 32), 0.5);
        assert_eq!(int_to_f32(i32::MIN, 32), -1.0);
        // (2^31 - 1) / 2^31 is not representable in f32; it rounds to 1.0 once.
        assert_eq!(int_to_f32(i32::MAX, 32), 1.0);
        assert!(int_to_f32(i32::MAX, 32) <= 1.0);
    }

    #[test]
    fn float_to_float_policy() {
        let mut stats = ConvertStats::default();
        assert_eq!(f32_to_f32(0.25, &mut stats), 0.25);
        assert_eq!(f32_to_f32(1.0, &mut stats), 1.0);
        assert_eq!(f32_to_f32(-1.0, &mut stats), -1.0);
        assert_eq!(stats, ConvertStats::default());
        // -0.0 and subnormals are preserved bit-for-bit.
        assert_eq!(f32_to_f32(-0.0, &mut stats).to_bits(), (-0.0f32).to_bits());
        assert_eq!(f32_to_f32(f32::from_bits(1), &mut stats).to_bits(), 1);
        assert_eq!(stats, ConvertStats::default());
        assert_eq!(f32_to_f32(2.0, &mut stats), 1.0);
        assert_eq!(f32_to_f32(-2.0, &mut stats), -1.0);
        assert_eq!(f32_to_f32(f32::MAX, &mut stats), 1.0);
        assert_eq!(stats.saturated, 3);
        assert_eq!(f32_to_f32(f32::NAN, &mut stats).to_bits(), 0);
        assert_eq!(f32_to_f32(f32::INFINITY, &mut stats).to_bits(), 0);
        assert_eq!(f32_to_f32(f32::NEG_INFINITY, &mut stats).to_bits(), 0);
        assert_eq!(stats.non_finite, 3);
    }

    // ---- exhaustive s16 ------------------------------------------------------------------

    #[test]
    fn every_s16_value_round_trips_through_every_wider_format_and_endianness() {
        let mono = |sf, e| fmt(sf, e, 1);
        let wide = [
            (SampleFormat::S24In32, Endian::Big),
            (SampleFormat::S24In32, Endian::Little),
            (SampleFormat::S32, Endian::Big),
            (SampleFormat::S32, Endian::Little),
            (SampleFormat::F32, Endian::Big),
            (SampleFormat::F32, Endian::Little),
        ];
        let s16_be = mono(SampleFormat::S16, Endian::Big);
        let mut total = 0usize;
        for chunk_start in (0..65_536usize).step_by(MAX_BLOCK_FRAMES) {
            let values: Vec<i16> = (chunk_start..chunk_start + MAX_BLOCK_FRAMES)
                .map(|i| (i as u32 as i32 - 32_768) as i16)
                .collect();
            let src: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
            for (sf, e) in wide {
                let wide_fmt = mono(sf, e);
                let mut mid = vec![0u8; MAX_BLOCK_FRAMES * wide_fmt.bytes_per_frame()];
                let (frames, up) = convert_packed(&src, &s16_be, &mut mid, &wide_fmt).unwrap();
                assert_eq!(frames, MAX_BLOCK_FRAMES);
                assert_eq!(up, ConvertStats::default(), "widening never saturates");
                let mut back = vec![0u8; src.len()];
                let (_, down) = convert_packed(&mid, &wide_fmt, &mut back, &s16_be).unwrap();
                assert_eq!(down, ConvertStats::default(), "{sf:?} {e:?} narrowing");
                assert_eq!(
                    back, src,
                    "{sf:?} {e:?} round trip from chunk {chunk_start}"
                );
            }
            total += values.len();
        }
        assert_eq!(total, 65_536);
    }

    #[test]
    fn legacy_scalar_helpers_use_the_d01_scale_and_round_trip_all_s16() {
        for v in i16::MIN..=i16::MAX {
            assert_eq!(f32_to_s16(s16_to_f32(v)), v, "value {v}");
        }
        assert_eq!(s16_to_f32(i16::MIN), -1.0);
        assert_eq!(f32_to_s16(-1.0), i16::MIN);
        assert_eq!(f32_to_s16(1.0), i16::MAX);
        assert_eq!(f32_to_s16(f32::NAN), 0);
        assert_eq!(f32_to_s16(f32::INFINITY), 0);
    }

    // ---- block-level behavior ----------------------------------------------------------------

    #[test]
    fn endianness_swap_is_lossless_for_every_format() {
        let samples_f32: Vec<f32> = vec![
            0.0,
            -0.0,
            1.0,
            -1.0,
            0.5,
            -0.25,
            0.999_999_94,
            f32::from_bits(1),
            1.0e-30,
        ];
        let frames = samples_f32.len();
        for sf in SampleFormat::ALL {
            let big = fmt(sf, Endian::Big, 1);
            let little = fmt(sf, Endian::Little, 1);
            // Build a source in big-endian form by converting from f32.
            let f32_big = fmt(SampleFormat::F32, Endian::Big, 1);
            let src_f32 = f32_bytes(&samples_f32, Endian::Big);
            let mut in_big = vec![0u8; frames * big.bytes_per_frame()];
            convert_packed(&src_f32, &f32_big, &mut in_big, &big).unwrap();
            let mut in_little = vec![0u8; in_big.len()];
            let (_, stats) = convert_packed(&in_big, &big, &mut in_little, &little).unwrap();
            assert_eq!(stats, ConvertStats::default(), "{sf:?}");
            let mut again = vec![0u8; in_big.len()];
            convert_packed(&in_little, &little, &mut again, &big).unwrap();
            assert_eq!(again, in_big, "{sf:?} BE->LE->BE");
            // The little-endian image is the byte-reversed big-endian image, sample by sample.
            let bps = sf.bytes_per_sample();
            for (b, l) in in_big.chunks_exact(bps).zip(in_little.chunks_exact(bps)) {
                let mut reversed = b.to_vec();
                reversed.reverse();
                assert_eq!(l, reversed.as_slice(), "{sf:?}");
            }
        }
    }

    #[test]
    fn non_finite_samples_become_silence_and_are_counted() {
        let f32_be = fmt(SampleFormat::F32, Endian::Big, 2);
        let s16_be = fmt(SampleFormat::S16, Endian::Big, 2);
        let src = f32_bytes(
            &[f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 2.0],
            Endian::Big,
        );
        let mut dst = [0xEEu8; 8];
        let (frames, stats) = convert_packed(&src, &f32_be, &mut dst, &s16_be).unwrap();
        assert_eq!(frames, 2);
        assert_eq!(dst, [0, 0, 0, 0, 0, 0, 0x7F, 0xFF]);
        assert_eq!(
            stats,
            ConvertStats {
                saturated: 1,
                non_finite: 3
            }
        );
    }

    #[test]
    fn block_length_errors_zero_max_misaligned_and_short_buffers() {
        let a = fmt(SampleFormat::S16, Endian::Big, 2);
        let b = fmt(SampleFormat::S32, Endian::Little, 2);
        let mut dst = vec![0u8; 8 * MAX_BLOCK_FRAMES];

        assert_eq!(
            convert_packed(&[], &a, &mut dst, &b),
            Err(PcmError::EmptyBlock)
        );
        assert_eq!(
            convert_packed(&[0u8; 3], &a, &mut dst, &b),
            Err(PcmError::MisalignedBlock {
                len: 3,
                bytes_per_frame: 4
            })
        );
        // Exactly the maximum converts; one frame more is refused.
        let max_src = vec![0u8; 4 * MAX_BLOCK_FRAMES];
        assert_eq!(
            convert_packed(&max_src, &a, &mut dst, &b).map(|(f, _)| f),
            Ok(MAX_BLOCK_FRAMES)
        );
        let over_src = vec![0u8; 4 * (MAX_BLOCK_FRAMES + 1)];
        assert_eq!(
            convert_packed(&over_src, &a, &mut dst, &b),
            Err(PcmError::BlockTooLarge {
                frames: MAX_BLOCK_FRAMES + 1,
                max: MAX_BLOCK_FRAMES
            })
        );
        // Destination too small leaves it untouched.
        let mut small = [0xEEu8; 15]; // needs 16 for 2 frames of 8 bytes
        assert_eq!(
            convert_packed(&[0u8; 8], &a, &mut small, &b),
            Err(PcmError::BufferTooSmall { have: 15, need: 16 })
        );
        assert_eq!(small, [0xEEu8; 15]);
        // convert_block with explicit frame counts.
        let (sa, sb) = (BufferSpec::packed(a), BufferSpec::packed(b));
        assert_eq!(
            convert_block(&[0u8; 4], &sa, &mut dst, &sb, 0),
            Err(PcmError::EmptyBlock)
        );
        assert_eq!(
            convert_block(&[0u8; 4], &sa, &mut dst, &sb, 2),
            Err(PcmError::BufferTooSmall { have: 4, need: 8 })
        );
    }

    #[test]
    fn channel_and_rate_mismatches_are_refused() {
        let stereo = fmt(SampleFormat::S16, Endian::Big, 2);
        let mono = fmt(SampleFormat::S16, Endian::Big, 1);
        let other_rate = StreamFormat::new(SampleFormat::S16, Endian::Big, 2, 44_100).unwrap();
        let mut dst = [0u8; 16];
        assert_eq!(
            convert_packed(&[0u8; 4], &stereo, &mut dst, &mono),
            Err(PcmError::ChannelMismatch { src: 2, dst: 1 })
        );
        assert_eq!(
            convert_packed(&[0u8; 4], &stereo, &mut dst, &other_rate),
            Err(PcmError::SampleRateMismatch {
                src: 48_000,
                dst: 44_100
            })
        );
    }

    #[test]
    fn interleaved_stride_to_planar_widening_with_padding_and_guards_untouched() {
        // Source: s16 big-endian stereo, frame stride 8 (4 bytes of 0xEE padding per frame).
        let src_fmt = fmt(SampleFormat::S16, Endian::Big, 2);
        let src_spec = BufferSpec::interleaved(src_fmt, 8).unwrap();
        let src = [
            0x01, 0x02, 0x03, 0x04, 0xEE, 0xEE, 0xEE, 0xEE, //
            0x05, 0x06, 0x07, 0x08, 0xEE, 0xEE, 0xEE, 0xEE, //
            0x09, 0x0A, 0x0B, 0x0C,
        ];
        assert_eq!(src_spec.required_len(3), Ok(src.len()));

        // Destination: s32 little-endian planar, plane stride 16 (4 frames of room per plane).
        let dst_fmt = fmt(SampleFormat::S32, Endian::Little, 2);
        let dst_spec = BufferSpec::planar(dst_fmt, 16).unwrap();
        assert_eq!(dst_spec.layout(), Layout::Planar);
        let mut dst = [0xAAu8; 32];
        let stats = convert_block(&src, &src_spec, &mut dst, &dst_spec, 3).unwrap();
        assert_eq!(stats, ConvertStats::default());
        let expected = [
            // plane 0 (left): 0x0102<<16, 0x0506<<16, 0x090A<<16 little-endian, then 4 untouched
            0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x06, 0x05, 0x00, 0x00, 0x0A, 0x09, //
            0xAA, 0xAA, 0xAA, 0xAA, //
            // plane 1 (right)
            0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x0C, 0x0B, //
            // guard bytes past the last addressed sample
            0xAA, 0xAA, 0xAA, 0xAA,
        ];
        assert_eq!(dst, expected);

        // And back: planar s32 LE -> interleaved s16 BE with stride 8; padding stays 0xEE.
        let mut back = [0xEEu8; 20];
        let stats = convert_block(&dst, &dst_spec, &mut back, &src_spec, 3).unwrap();
        assert_eq!(stats, ConvertStats::default());
        assert_eq!(back, src);
    }

    #[test]
    fn planar_destination_whose_stride_cannot_hold_the_block_is_refused() {
        let f = fmt(SampleFormat::S16, Endian::Big, 2);
        let src = BufferSpec::packed(f);
        let dst_spec = BufferSpec::planar(f, 4).unwrap(); // only 2 frames of room per plane
        let mut dst = [0u8; 64];
        assert_eq!(
            convert_block(&[0u8; 12], &src, &mut dst, &dst_spec, 3),
            Err(PcmError::StrideTooSmall {
                stride: 4,
                minimum: 6
            })
        );
        assert!(convert_block(&[0u8; 8], &src, &mut dst, &dst_spec, 2).is_ok());
    }

    #[test]
    fn eight_channel_and_one_frame_blocks_convert() {
        let wide = fmt(SampleFormat::S16, Endian::Big, 8);
        let out = fmt(SampleFormat::F32, Endian::Big, 8);
        let src: Vec<u8> = (0..8i16).flat_map(|c| (c * 4096).to_be_bytes()).collect();
        let mut dst = vec![0u8; 8 * 4];
        let (frames, _) = convert_packed(&src, &wide, &mut dst, &out).unwrap();
        assert_eq!(frames, 1);
        let (samples, remainder) = dst.as_chunks::<4>();
        assert!(
            remainder.is_empty(),
            "8 channels of f32 are whole 4-byte samples"
        );
        assert_eq!(samples.len(), 8);
        for (c, sample) in samples.iter().enumerate() {
            let got = f32::from_bits(u32::from_be_bytes(*sample));
            assert_eq!(got, (c as f32 * 4096.0) / 32768.0, "channel {c}");
        }
    }
}
