//! The integer-only conversions against the `f64` implementation they replaced (`D01` / `ffw-f3b`, the
//! soft-float clause of section 7: "a soft-float target must not silently inherit expensive floating-point
//! assumptions").
//!
//! `original_*` below is the previous implementation, copied unchanged and kept ONLY as the oracle. Each test
//! compares bit patterns and `ConvertStats`, never approximate values, because the claim is that the rewrite
//! changes no result. `hand_derived_anchors_*` is independent of both implementations: its expected values are
//! worked out on paper from the rules in `docs/contracts/d01.md`.
//!
//! What these tests do NOT show: that the compiled MIPS code calls no floating-point helper (that needs the
//! device ELF), or what the change saves (that needs the `toolchain/src/d02-cost` instrument on a build that
//! contains it).

use super::*;

// ---- the original f64 implementation, verbatim, as the oracle ------------------------------------------------------

fn original_full_scale(bits: u32) -> f64 {
    f64::from(1u32 << (bits.clamp(1, 32) - 1))
}

fn original_int_to_f32(value: i32, bits: u32) -> f32 {
    (f64::from(value) / original_full_scale(bits)) as f32
}

fn original_f32_to_int(x: f32, bits: u32, stats: &mut ConvertStats) -> i32 {
    if !x.is_finite() {
        stats.note_non_finite();
        return 0;
    }
    let scale = original_full_scale(bits);
    let scaled = (f64::from(x) * scale).round_ties_even();
    if scaled > scale - 1.0 {
        stats.note_saturated();
        return (scale - 1.0) as i32;
    }
    if scaled < -scale {
        stats.note_saturated();
        return (-scale) as i32;
    }
    scaled as i32
}

fn original_f32_to_f32(x: f32, stats: &mut ConvertStats) -> f32 {
    if !x.is_finite() {
        stats.note_non_finite();
        return 0.0;
    }
    if x > 1.0 {
        stats.note_saturated();
        return 1.0;
    }
    if x < -1.0 {
        stats.note_saturated();
        return -1.0;
    }
    x
}

// ---- helpers --------------------------------------------------------------------------------------------------------

/// Seeded and fixed, so a failure replays: SplitMix64.
struct SplitMix(u64);

impl SplitMix {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn check_int_to_f32(value: i32, bits: u32) {
    let (new, old) = (int_to_f32(value, bits), original_int_to_f32(value, bits));
    assert_eq!(
        new.to_bits(),
        old.to_bits(),
        "int_to_f32({value}, {bits}): new {new:?} ({:#010x}), original {old:?} ({:#010x})",
        new.to_bits(),
        old.to_bits()
    );
}

fn check_f32_to_int(x: f32, bits: u32) {
    let (mut new_stats, mut old_stats) = (ConvertStats::default(), ConvertStats::default());
    let new = f32_to_int(x, bits, &mut new_stats);
    let old = original_f32_to_int(x, bits, &mut old_stats);
    assert_eq!(
        (new, new_stats),
        (old, old_stats),
        "f32_to_int({x:?} = {:#010x}, {bits}): new vs original (value, counters)",
        x.to_bits()
    );
}

fn check_f32_to_f32(x: f32) {
    let (mut new_stats, mut old_stats) = (ConvertStats::default(), ConvertStats::default());
    let new = f32_to_f32(x, &mut new_stats);
    let old = original_f32_to_f32(x, &mut old_stats);
    assert_eq!(
        (new.to_bits(), new_stats),
        (old.to_bits(), old_stats),
        "f32_to_f32({x:?} = {:#010x}): new vs original (bits, counters)",
        x.to_bits()
    );
}

/// A magnitude and a sign as an `i32`, when it fits (`-2^31` is the one negative magnitude of `2^31`).
fn signed(magnitude: u32, negative: bool) -> Option<i32> {
    if negative {
        i32::try_from(-i64::from(magnitude)).ok()
    } else {
        i32::try_from(magnitude).ok()
    }
}

// ---- anchors worked out on paper, independent of both implementations -------------------------------------------------

#[test]
fn hand_derived_anchors_hold_for_the_new_and_the_original_implementation() {
    // (value, bits, expected f32 bits): value / 2^(bits-1), rounded once to nearest-even.
    let int_cases: [(i32, u32, u32); 12] = [
        (0, 16, 0x0000_0000),
        (1, 16, 0x3800_0000), // 2^-15
        (-1, 16, 0xB800_0000),
        (32767, 16, 0x3F7F_FE00),     // 1 - 2^-15
        (-32768, 16, 0xBF80_0000),    // exactly -1.0
        (1, 1, 0x3F80_0000),          // bits = 1: the scale is 2^0
        (0x7F_FFFF, 24, 0x3F7F_FFFE), // 1 - 2^-23 (0x3F7F_FFFF is 1 - 2^-24: f32 spacing below 1.0 is 2^-24)
        (i32::MAX, 32, 0x3F80_0000),  // 2^31 - 1 rounds up to 2^31: the carry case, exactly +1.0
        (i32::MIN, 32, 0xBF80_0000),
        (16_777_217, 32, 0x3C00_0000), // 2^24 + 1: a tie, to the even significand, which is 2^24
        (16_777_219, 32, 0x3C00_0002), // 2^24 + 3: a tie, to the even significand 2^24 + 4
        (5, 0, 0x40A0_0000),           // bits is clamped to 1, so the scale is 1 and 5 stays 5.0
    ];
    for (value, bits, expected) in int_cases {
        assert_eq!(
            int_to_f32(value, bits).to_bits(),
            expected,
            "new int_to_f32({value}, {bits})"
        );
        assert_eq!(
            original_int_to_f32(value, bits).to_bits(),
            expected,
            "original int_to_f32({value}, {bits})"
        );
    }

    // (x, bits, expected code, saturations, non-finite): round_ties_even(x * 2^(bits-1)), saturating.
    let s = 32768.0f32;
    let float_cases: [(f32, u32, i32, u32, u32); 21] = [
        (0.0, 16, 0, 0, 0),
        (-0.0, 16, 0, 0, 0),
        (0.5 / s, 16, 0, 0, 0),  // 0.5 -> 0 (even)
        (1.5 / s, 16, 2, 0, 0),  // 1.5 -> 2
        (2.5 / s, 16, 2, 0, 0),  // 2.5 -> 2
        (3.5 / s, 16, 4, 0, 0),  // 3.5 -> 4
        (-0.5 / s, 16, 0, 0, 0), // -0.5 -> 0, not "minus zero"
        (-2.5 / s, 16, -2, 0, 0),
        (1.0, 16, 32767, 1, 0),           // +1.0 saturates to the largest code
        (-1.0, 16, -32768, 0, 0),         // -1.0 is exactly the smallest code: not a saturation
        (32767.5 / s, 16, 32767, 1, 0),   // 32767.5 -> 32768 (even): out of range, counted
        (-32768.5 / s, 16, -32768, 0, 0), // -32768.5 -> -32768 (even): in range
        (-32769.0 / s, 16, -32768, 1, 0),
        (f32::NAN, 16, 0, 0, 1),
        (f32::INFINITY, 16, 0, 0, 1),
        (f32::NEG_INFINITY, 16, 0, 0, 1),
        (1.0e-40, 16, 0, 0, 0), // subnormal: far below half a code
        (1.0, 32, i32::MAX, 1, 0),
        (-1.0, 32, i32::MIN, 0, 0),
        (0.5, 32, 1_073_741_824, 0, 0), // 2^30 exactly
        (0.75, 1, 0, 1, 0),             // bits = 1: codes are {-1, 0}; 0.75 -> 1 is out of range
    ];
    for (x, bits, expected, saturated, non_finite) in float_cases {
        let want = (
            expected,
            ConvertStats {
                saturated,
                non_finite,
            },
        );
        let (mut new_stats, mut old_stats) = (ConvertStats::default(), ConvertStats::default());
        let new = (f32_to_int(x, bits, &mut new_stats), new_stats);
        let old = (original_f32_to_int(x, bits, &mut old_stats), old_stats);
        assert_eq!(new, want, "new f32_to_int({x:?}, {bits})");
        assert_eq!(old, want, "original f32_to_int({x:?}, {bits})");
    }

    // The f32 clamp: non-finite -> +0.0; |x| > 1 clamps with its sign; everything else passes bit for bit.
    let clamp_cases: [(f32, f32, u32, u32); 9] = [
        (0.25, 0.25, 0, 0),
        (-0.0, -0.0, 0, 0),
        (1.0, 1.0, 0, 0),
        (-1.0, -1.0, 0, 0),
        (1.0000001, 1.0, 1, 0),
        (-1.0000001, -1.0, 1, 0),
        (f32::NAN, 0.0, 0, 1),
        (f32::NEG_INFINITY, 0.0, 0, 1),
        (1.0e-40, 1.0e-40, 0, 0),
    ];
    for (x, expected, saturated, non_finite) in clamp_cases {
        let (mut new_stats, mut old_stats) = (ConvertStats::default(), ConvertStats::default());
        let new = f32_to_f32(x, &mut new_stats);
        let old = original_f32_to_f32(x, &mut old_stats);
        let want = ConvertStats {
            saturated,
            non_finite,
        };
        assert_eq!(
            (new.to_bits(), new_stats),
            (expected.to_bits(), want),
            "new f32_to_f32({x:?})"
        );
        assert_eq!(
            (old.to_bits(), old_stats),
            (expected.to_bits(), want),
            "original f32_to_f32({x:?})"
        );
    }
}

// ---- integer to f32 ---------------------------------------------------------------------------------------------------

#[test]
fn int_to_f32_matches_the_original_for_every_s16_value_at_every_width_including_out_of_range_bits()
{
    for bits in 0..=34 {
        for value in i16::MIN..=i16::MAX {
            check_int_to_f32(i32::from(value), bits);
        }
    }
}

#[test]
fn int_to_f32_matches_the_original_for_every_24_bit_value() {
    for value in -(1i32 << 23)..(1i32 << 23) {
        check_int_to_f32(value, 24);
    }
}

#[test]
fn int_to_f32_matches_the_original_on_every_rounding_and_tie_pattern_of_the_wide_widths() {
    // top in 24..=30 means 1..=7 bits are dropped; sweep every dropped-bit pattern against significands that
    // sit at the edges (carry out of 24 bits, all ones, small).
    let kept_low = [0u32, 1, 2, 3, 0x7F_FFFC, 0x7F_FFFD, 0x7F_FFFE, 0x7F_FFFF];
    let mut cases = 0u64;
    for dropped in 1..=8u32 {
        for low in kept_low {
            let kept = (1u32 << 23) | low;
            for rest in 0..(1u32 << dropped) {
                let magnitude = (kept << dropped) | rest;
                for negative in [false, true] {
                    if let Some(value) = signed(magnitude, negative) {
                        for bits in 24..=33 {
                            check_int_to_f32(value, bits);
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    for value in [
        i32::MAX,
        i32::MIN,
        i32::MAX - 1,
        i32::MIN + 1,
        1 << 24,
        (1 << 24) + 1,
        -(1 << 24) - 1,
    ] {
        for bits in 0..=34 {
            check_int_to_f32(value, bits);
        }
    }
    // 40,650 are evaluated today (many magnitudes above 2^31 do not fit an i32); a drop below 30,000 means the sweep thinned.
    assert!(cases > 30_000, "the sweep was thin: {cases} cases");
}

#[test]
fn int_to_f32_matches_the_original_on_a_million_seeded_values_and_widths() {
    let mut rng = SplitMix(0x00D0_1F3B_0001);
    for _ in 0..1_000_000 {
        let draw = rng.draw();
        check_int_to_f32((draw >> 16) as u32 as i32, (draw & 0x3F) as u32);
    }
}

// ---- f32 to integer ---------------------------------------------------------------------------------------------------

/// Floats around the half-integer ties and the integer codes of one width, with their bit neighbours.
fn float_samples(bits: u32) -> Vec<f32> {
    let k = bits.clamp(1, 32) - 1;
    let scale = (1u64 << k) as f64;
    let mut codes: Vec<i64> = Vec::new();
    if k <= 15 {
        let limit = 1i64 << k;
        codes.extend(-limit - 3..=limit + 2);
    } else {
        let limit = 1i64 << k;
        for centre in [-limit, -1, 0, limit - 1] {
            codes.extend(centre - 3..=centre + 3);
        }
        let step = ((2 * limit) / 20_000) | 1;
        let mut code = -limit;
        while code < limit {
            codes.push(code);
            code += step;
        }
    }
    let mut out = Vec::with_capacity(codes.len() * 20);
    for code in codes {
        for offset in [0.0f64, 0.5] {
            let base = ((code as f64 + offset) / scale) as f32;
            for delta in -2i64..=2 {
                let pattern = i64::from(base.to_bits()) + delta;
                if let Ok(pattern) = u32::try_from(pattern) {
                    out.push(f32::from_bits(pattern));
                    out.push(-f32::from_bits(pattern));
                }
            }
        }
    }
    out
}

#[test]
fn f32_to_int_matches_the_original_on_every_tie_and_integer_code_with_bit_neighbours_at_every_width()
 {
    let mut cases = 0u64;
    for bits in 1..=32 {
        for x in float_samples(bits) {
            check_f32_to_int(x, bits);
            cases += 1;
        }
    }
    assert!(cases > 5_000_000, "the sweep was thin: {cases} cases");
}

#[test]
fn f32_to_int_matches_the_original_on_mantissas_at_every_boundary_of_every_exponent_near_the_scale()
{
    for bits in [1u32, 2, 8, 15, 16, 17, 24, 25, 31, 32, 33] {
        let k = bits.clamp(1, 32) - 1;
        let low = (127 - i64::from(k) - 3).max(1);
        let high = (127 + 3).min(254);
        let mut exponents: Vec<i64> = (low..=high).collect();
        exponents.extend([1, 2, 126 - 24, 253, 254]);
        for exponent in exponents {
            let mut mantissas: Vec<u32> =
                vec![0, 1, 2, 3, 0x7F_FFFC, 0x7F_FFFD, 0x7F_FFFE, 0x7F_FFFF];
            for j in 0..23 {
                for delta in [-1i64, 0, 1] {
                    if let Ok(m) = u32::try_from((1i64 << j) + delta) {
                        mantissas.push(m & 0x7F_FFFF);
                    }
                }
            }
            mantissas.extend((0..0x80_0000u32).step_by(8191));
            // exact ties for every number of dropped bits: the low `r` bits of the significand are 100..0
            for r in 1..=24u32 {
                for high_part in [0u32, 1, 2, 3, 0x15_5555, 0x2A_AAAA, 0x7F_FFFF] {
                    let significand = ((high_part << r) | (1 << (r - 1))) & 0xFF_FFFF;
                    mantissas.push(significand & 0x7F_FFFF);
                }
            }
            for mantissa in mantissas {
                for sign in [0u32, 1] {
                    let raw = (sign << 31) | ((exponent as u32) << 23) | mantissa;
                    check_f32_to_int(f32::from_bits(raw), bits);
                }
            }
        }
    }
}

#[test]
fn f32_to_int_matches_the_original_on_two_million_seeded_bit_patterns_at_random_widths() {
    let mut rng = SplitMix(0x00D0_1F3B_0002);
    for _ in 0..2_000_000 {
        let draw = rng.draw();
        check_f32_to_int(f32::from_bits((draw >> 8) as u32), (draw & 0x3F) as u32);
    }
}

// ---- f32 to f32 ---------------------------------------------------------------------------------------------------

#[test]
fn f32_to_f32_matches_the_original_around_one_at_zero_and_on_every_class_of_non_finite() {
    let mut patterns: Vec<u32> = Vec::new();
    for centre in [
        0x3F80_0000u32,
        0x0000_0000,
        0x0080_0000,
        0x7F80_0000,
        0x7FC0_0000,
    ] {
        for delta in -4i64..=4 {
            if let Ok(bits) = u32::try_from(i64::from(centre) + delta) {
                patterns.push(bits);
                patterns.push(bits | 0x8000_0000);
            }
        }
    }
    patterns.extend([
        0x7FFF_FFFF,
        0xFFFF_FFFF,
        0x7F80_0001,
        0xFF80_0001,
        0x7FA0_0000,
        0x0000_0001,
        0x807F_FFFF,
    ]);
    let mut rng = SplitMix(0x00D0_1F3B_0003);
    patterns.extend((0..2_000_000).map(|_| (rng.draw() >> 11) as u32));
    for bits in patterns {
        check_f32_to_f32(f32::from_bits(bits));
    }
}

// ---- the guard against regressing --------------------------------------------------------------------------------------

#[test]
fn the_conversion_code_contains_no_double_precision_and_no_float_compare() {
    // A heuristic guard on the source text of the non-test code, not a proof about the compiled MIPS code (that
    // needs the device ELF). Comments are skipped; the conversions are meant to stay soft-float-free.
    let source = include_str!("../convert.rs");
    let code: Vec<&str> = source
        .split("#[cfg(test)]")
        .next()
        .expect("the source has a non-test part")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    let code = code.join("\n");
    for forbidden in [
        "f64",
        "is_finite",
        "round_ties_even",
        " as f32",
        " as f64",
        ".abs()",
        ".round()",
    ] {
        assert!(
            !code.contains(forbidden),
            "convert.rs non-test code mentions `{forbidden}`"
        );
    }
}

// ---- exhaustive, opt-in --------------------------------------------------------------------------------------------------

/// All 2^32 bit patterns for the production width, against the original. Its duration has not been measured; it
/// is expected to take minutes in release mode and far too long in a debug build, so it is opt-in and not a
/// required case: `cargo test --release -p franken-dsp --lib -- --ignored soft_float_tests`.
#[test]
#[ignore = "exhaustive 2^32 sweep: run in release mode with --ignored"]
fn f32_to_s16_and_the_clamp_match_the_original_over_all_four_billion_bit_patterns() {
    for raw in 0..=u32::MAX {
        let x = f32::from_bits(raw);
        check_f32_to_int(x, 16);
        check_f32_to_f32(x);
    }
}
