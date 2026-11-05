"""Hand-computed anchors for the D01 conversion rules.

These literals were worked out by hand from the rule table in docs/contracts/d01.md. The same
numbers appear as literals in the Rust unit tests (crates/franken-dsp/src/convert.rs). The
reference (reference.py) must reproduce every one, so the reference and the Rust tests agree on
hand-derived values without either one generating the other's expectations.
"""
from __future__ import annotations

import importlib.util
import os
import struct
import sys
from typing import Any, List

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d01_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
FMT = {16: "s16", 24: "s24in32", 32: "s32"}

# (value, from_bits, to_bits, expected, expected_saturations)
INT_WIDTH = [
    (0x7FFF, 16, 32, 0x7FFF0000, 0), (-0x8000, 16, 32, -0x80000000, 0), (1, 16, 32, 0x10000, 0),
    (-1, 16, 32, -0x10000, 0), (0x7FFF, 16, 24, 0x7FFF00, 0), (-0x8000, 16, 24, -0x800000, 0),
    (0x7FFFFF, 24, 32, 0x7FFFFF00, 0), (-0x800000, 24, 32, -0x80000000, 0),
    (123, 16, 16, 123, 0), (-0x800000, 24, 24, -0x800000, 0), (-0x80000000, 32, 32, -0x80000000, 0),
    (0x00007FFF, 32, 16, 0, 0), (0x00008000, 32, 16, 1, 0), (-0x00008000, 32, 16, 0, 0),
    (-0x00008001, 32, 16, -1, 0), (0x7FFF7FFF, 32, 16, 32767, 0), (0x7FFF8000, 32, 16, 32767, 1),
    (0x7FFFFFFF, 32, 16, 32767, 1), (-0x80000000, 32, 16, -32768, 0),
    (0x7FFFFF7F, 32, 24, 0x7FFFFF, 0), (0x7FFFFF80, 32, 24, 0x7FFFFF, 1), (0x7FFFFFFF, 32, 24, 0x7FFFFF, 1),
    (-0x80000000, 32, 24, -0x800000, 0), (0x7F, 32, 24, 0, 0), (0x80, 32, 24, 1, 0),
    (0x7FFFFF, 24, 16, 32767, 1), (0x7FFF7F, 24, 16, 32767, 0), (0x7F, 24, 16, 0, 0),
    (0x80, 24, 16, 1, 0), (-0x80, 24, 16, 0, 0), (-0x81, 24, 16, -1, 0), (-0x800000, 24, 16, -32768, 0),
]

HALF_LSB16 = 0.5 / 32768.0  # exactly half an s16 LSB (2**-16)


def _bits(x: float) -> int:
    return struct.unpack(">I", struct.pack(">f", x))[0]


def _from_bits(b: int) -> float:
    return struct.unpack(">f", struct.pack(">I", b))[0]


# (input float, destination bits, expected, saturations, non_finite)
FLOAT_TO_INT = [
    (0.0, 16, 0, 0, 0), (-0.0, 16, 0, 0, 0), (0.5, 16, 16384, 0, 0), (-0.5, 16, -16384, 0, 0),
    (1.0, 16, 32767, 1, 0), (-1.0, 16, -32768, 0, 0), (2.0, 16, 32767, 1, 0), (-2.0, 16, -32768, 1, 0),
    (3.4028234663852886e38, 16, 32767, 1, 0), (-3.4028234663852886e38, 16, -32768, 1, 0),
    (float("nan"), 16, 0, 0, 1), (float("inf"), 16, 0, 0, 1), (float("-inf"), 16, 0, 0, 1),
    (_from_bits(1), 16, 0, 0, 0),
    # exact halves round to even
    (HALF_LSB16, 16, 0, 0, 0), (3 * HALF_LSB16, 16, 2, 0, 0), (5 * HALF_LSB16, 16, 2, 0, 0),
    (7 * HALF_LSB16, 16, 4, 0, 0), (-HALF_LSB16, 16, 0, 0, 0), (-3 * HALF_LSB16, 16, -2, 0, 0),
    (-5 * HALF_LSB16, 16, -2, 0, 0),
    (_from_bits(_bits(HALF_LSB16) + 1), 16, 1, 0, 0),  # one ulp above a tie rounds away
    (1.0, 24, 0x7FFFFF, 1, 0), (-1.0, 24, -0x800000, 0, 0), (0.5, 24, 0x400000, 0, 0),
    (1.0, 32, 0x7FFFFFFF, 1, 0), (-1.0, 32, -0x80000000, 0, 0), (0.5, 32, 0x40000000, 0, 0),
    (_from_bits(0x3F7FFFFF), 32, 2147483520, 0, 0), (_from_bits(0x3F800001), 32, 0x7FFFFFFF, 1, 0),
]

# (integer, source bits, expected float)
INT_TO_FLOAT = [
    (0, 16, 0.0), (16384, 16, 0.5), (-32768, 16, -1.0), (32767, 16, 0.999969482421875),
    (1, 16, 1.0 / 32768.0), (0x7FFFFF, 24, 1.0 - 1.0 / 8388608.0), (-0x800000, 24, -1.0),
    (0x40000000, 32, 0.5), (-0x80000000, 32, -1.0), (0x7FFFFFFF, 32, 1.0),
]

# (format, endian, value, expected bytes)
ENDIAN_VECTORS = [
    ("s16", "big", 0x1234, bytes([0x12, 0x34])), ("s16", "little", 0x1234, bytes([0x34, 0x12])),
    ("s16", "big", -2, bytes([0xFF, 0xFE])), ("s16", "little", -2, bytes([0xFE, 0xFF])),
    ("s16", "big", -32768, bytes([0x80, 0x00])), ("s16", "little", 32767, bytes([0xFF, 0x7F])),
    ("s24in32", "big", 0x123456, bytes([0x00, 0x12, 0x34, 0x56])),
    ("s24in32", "little", 0x123456, bytes([0x56, 0x34, 0x12, 0x00])),
    ("s24in32", "big", -2, bytes([0xFF, 0xFF, 0xFF, 0xFE])),
    ("s24in32", "little", -2, bytes([0xFE, 0xFF, 0xFF, 0xFF])),
    ("s24in32", "big", -8388608, bytes([0xFF, 0x80, 0x00, 0x00])),
    ("s24in32", "big", 8388607, bytes([0x00, 0x7F, 0xFF, 0xFF])),
    ("s32", "big", 0x01020304, bytes([1, 2, 3, 4])), ("s32", "little", 0x01020304, bytes([4, 3, 2, 1])),
    ("s32", "big", -0x80000000, bytes([0x80, 0, 0, 0])),
]
# s24-in-32 readers ignore the top byte and sign-extend bit 23
S24_READ = [
    (bytes([0x7F, 0x80, 0x00, 0x00]), "big", -8388608), (bytes([0x12, 0x00, 0x00, 0x01]), "big", 1),
    (bytes([0x01, 0x00, 0x80, 0xAB]), "little", -8388607), (bytes([0x01, 0x00, 0x00, 0xAB]), "little", 1),
]
F32_ENDIAN = [(1.0, "big", bytes([0x3F, 0x80, 0, 0])), (1.0, "little", bytes([0, 0, 0x80, 0x3F])),
              (-2.0, "big", bytes([0xC0, 0, 0, 0])), (0.5, "big", bytes([0x3F, 0, 0, 0])),
              (-0.0, "big", bytes([0x80, 0, 0, 0]))]

# interleaved s16-BE stereo with frame stride 8 -> planar s32-LE with plane stride 16, three frames
STRIDE_SRC = bytes([
    0x01, 0x02, 0x03, 0x04, 0xEE, 0xEE, 0xEE, 0xEE,
    0x05, 0x06, 0x07, 0x08, 0xEE, 0xEE, 0xEE, 0xEE,
    0x09, 0x0A, 0x0B, 0x0C])
STRIDE_EXPECTED = bytes([
    0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x06, 0x05, 0x00, 0x00, 0x0A, 0x09, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x0C, 0x0B, 0xAA, 0xAA, 0xAA, 0xAA])

# f32 BE stereo [NaN, +inf, -inf, 2.0] -> s16 BE stereo
NONFINITE_SRC_BITS = [0x7FC00000, 0x7F800000, 0xFF800000, 0x40000000]
NONFINITE_EXPECTED = bytes([0, 0, 0, 0, 0, 0, 0x7F, 0xFF])


def check() -> List[str]:
    """Run every anchor through the reference; returns human-readable failures (empty = all hold)."""
    failures: List[str] = []

    def expect(label: str, got: Any, want: Any) -> None:
        if got != want:
            failures.append(f"{label}: reference gave {got!r}, hand-computed anchor is {want!r}")

    for value, fb, tb, want, sat in INT_WIDTH:
        stats = {"saturated": 0, "non_finite": 0}
        kind, got = ref.convert_value(("i", value), FMT[fb], FMT[tb], stats)
        expect(f"int {value:#x} s{fb}->s{tb}", (got, stats["saturated"], stats["non_finite"]), (want, sat, 0))
    for x, bits, want, sat, nonfinite in FLOAT_TO_INT:
        stats = {"saturated": 0, "non_finite": 0}
        _, got = ref.convert_value(("f", x), "f32", FMT[bits], stats)
        expect(f"float {x!r} -> s{bits}", (got, stats["saturated"], stats["non_finite"]), (want, sat, nonfinite))
    for value, bits, want in INT_TO_FLOAT:
        stats = {"saturated": 0, "non_finite": 0}
        _, got = ref.convert_value(("i", value), FMT[bits], "f32", stats)
        packed = struct.unpack(">f", struct.pack(">f", got))[0]  # the f32 that would be stored
        expect(f"int {value:#x} s{bits} -> f32", packed, want)
    for fmt, endian, value, want in ENDIAN_VECTORS:
        expect(f"encode {fmt} {endian} {value:#x}", ref.encode(("i", value), fmt, endian), want)
    for raw, endian, want in S24_READ:
        expect(f"decode s24in32 {endian} {raw.hex()}", ref.decode(raw, "s24in32", endian), ("i", want))
    for x, endian, want in F32_ENDIAN:
        expect(f"encode f32 {endian} {x!r}", ref.encode(("f", x), "f32", endian), want)

    src_spec = ref.Spec("s16", "big", 2, 48_000, "interleaved", 8)
    dst_spec = ref.Spec("s32", "little", 2, 48_000, "planar", 16)
    got, stats = ref.convert_block(STRIDE_SRC, src_spec, bytes([0xAA]) * 32, dst_spec, 3)
    expect("stride/planar block bytes", got, STRIDE_EXPECTED)
    expect("stride/planar block stats", stats, {"saturated": 0, "non_finite": 0})
    back, _ = ref.convert_block(got, dst_spec, bytes([0xEE]) * 20, src_spec, 3)
    expect("planar -> interleaved restores the source, padding untouched", back, STRIDE_SRC)

    f32_be = ref.Spec("f32", "big", 2, 48_000)
    s16_be = ref.Spec("s16", "big", 2, 48_000)
    src = b"".join(struct.pack(">I", b) for b in NONFINITE_SRC_BITS)
    got, stats = ref.convert_block(src, f32_be, bytes([0xEE]) * 8, s16_be, 2)
    expect("non-finite block bytes", got, NONFINITE_EXPECTED)
    expect("non-finite block stats", stats, {"saturated": 1, "non_finite": 3})
    return failures


if __name__ == "__main__":
    problems = check()
    for p in problems:
        print("ANCHOR MISMATCH:", p)
    print("anchors: all hold" if not problems else f"anchors: {len(problems)} mismatch(es)")
    sys.exit(1 if problems else 0)
