"""Deterministic D01 test-vector generator (ffw-f3b).

Builds tests/d01/vectors.json from ``reference.py`` only: the expected bytes come from Python's
``struct`` and integer/float arithmetic, never from the Rust implementation. Run through
``run_cases.py --write-vectors``; the committed file must equal a fresh generation (the runner
checks this on every run, so a stale or hand-edited vector file fails).
"""
from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
from typing import Any, Dict, Iterator, List

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    path = os.path.join(HERE, name + ".py")
    spec = importlib.util.spec_from_file_location("d01_" + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")

SCHEMA = "ffw.d01.vectors.v1"
GUARD_BYTES = 8
FILL = 0xA5

INVARIANTS: Dict[str, str] = {
    "D01-INV-BYTES-PER-FRAME": "bytes per frame is explicit: channels x container bytes, for every format and channel count",
    "D01-INV-ENDIAN": "bit-exact big- and little-endian byte vectors for every sample format",
    "D01-INV-WIDTH-SIGN": "bit-exact width and sign conversion between s16, s24-in-32, s32 and f32 (shift / round-half-up / ties-even)",
    "D01-INV-SATURATE": "saturation at both rails is counted and never wraps",
    "D01-INV-NONFINITE": "NaN and +/-inf become silence, never full scale, and are counted",
    "D01-INV-STRIDE-LAYOUT": "interleaved strides with padding, planar planes, and untouched padding/guard bytes",
    "D01-INV-BLOCK-LEN": "zero, maximum, misaligned, oversize and short-buffer block lengths are typed errors",
    "D01-INV-RING-WRAP": "bounded SPSC ring: FIFO across wrap, exact-capacity, full, underrun, never-fits",
    "D01-INV-ROUNDTRIP-E2E": "known PCM round-trips conversion, ring and sink and equals the independent reference",
    "D01-INV-NO-ALLOC": "the render path (convert, ring, sink) performs no allocator calls",
    "D01-INV-SCALE-COMPAT": "legacy i16 helpers and the stereo wire path use the D01 scale and round-trip all 65536 values",
}

# Invariants proved by Rust tests rather than by data vectors (the runner requires them in the log).
EXTERNAL_INVARIANTS: Dict[str, List[str]] = {
    "D01-INV-NO-ALLOC": [
        "franken-alloc-probe::convert_ring_convert_sink_pipeline_does_not_allocate",
        "franken-alloc-probe::error_paths_alone_do_not_allocate",
        "franken-alloc-probe::the_counter_is_installed_and_really_counts",
    ],
    "D01-INV-SCALE-COMPAT": [
        "franken-dsp::tests::wire_path_round_trips_every_i16_value_exactly",
        "franken-dsp::convert::tests::legacy_scalar_helpers_use_the_d01_scale_and_round_trip_all_s16",
        "franken-dsp::convert::tests::every_s16_value_round_trips_through_every_wider_format_and_endianness",
    ],
}


def prng(seed: int) -> Iterator[int]:
    """xorshift32; deterministic on every Python."""
    x = (seed & 0xFFFFFFFF) or 1
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        yield x


def f32_bits(x: float) -> int:
    return struct.unpack(">I", struct.pack(">f", x))[0]


F32_NON_FINITE_BITS = [0x7FC00000, 0xFFC00001, 0x7F800000, 0xFF800000, 0x7F800001]


def int_boundaries(bits: int) -> List[int]:
    """Rails, near-zero, and for every narrower target width the exact rounding ties and the
    last-non-saturating / first-saturating values on both sides."""
    hi, lo = 2 ** (bits - 1) - 1, -(2 ** (bits - 1))
    vals = {lo, lo + 1, -2, -1, 0, 1, 2, hi - 1, hi}
    for target in (16, 24, 32):
        if target >= bits:
            continue
        shift = bits - target
        half = 2 ** (shift - 1)
        hi_t, lo_t = 2 ** (target - 1) - 1, -(2 ** (target - 1))
        for k in (1, 2, 3):
            tie = (2 * k - 1) * half
            vals.update((tie - 1, tie, tie + 1, -tie - 1, -tie, -tie + 1))
        vals.update((hi_t * 2 ** shift + half - 1, hi_t * 2 ** shift + half))
        vals.update((lo_t * 2 ** shift - half, lo_t * 2 ** shift - half + 1,
                     lo_t * 2 ** shift + half - 1, lo_t * 2 ** shift + half))
    return sorted(v for v in vals if lo <= v <= hi)


def f32_boundaries() -> List[int]:
    """f32 bit patterns: zeros, +/-1, halves, just-inside/outside full scale, extremes,
    subnormals, exact half-LSB ties for every integer target width, and non-finite values."""
    floats = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 0.25, -0.25, 2.0, -2.0,
              1.0000001192092896, -1.0000001192092896, 0.99999994039535522, -0.99999994039535522,
              3.4028234663852886e38, -3.4028234663852886e38,
              1.401298464324817e-45, -1.401298464324817e-45, 1.1754943508222875e-38, 1e-10]
    bits = [f32_bits(x) for x in floats]
    for target in (16, 24, 32):
        for j in range(4):
            tie = (2 * j + 1) * 2.0 ** -target  # j == 0: exactly half an LSB of the target width
            for sign in (1, -1):
                b = f32_bits(sign * tie)
                bits.extend((b - 1, b, b + 1))
    bits.extend(F32_NON_FINITE_BITS)
    return sorted(set(bits))


def random_items(fmt: str, rng: Iterator[int], count: int) -> List[int]:
    out = []
    for _ in range(count):
        r = next(rng)
        if fmt == "f32":
            out.append(f32_bits((r / 2 ** 32) * 3.0 - 1.5))
        else:
            bits = ref.FORMATS[fmt][1]
            out.append(r % 2 ** bits - 2 ** (bits - 1))
    return out


def sample_bytes(fmt: str, endian: str, item: int) -> bytes:
    """Source sample as bytes; floats are given as raw bit patterns so NaN payloads survive."""
    if fmt == "f32":
        return struct.pack(ref.ENDIANS[endian] + "I", item)
    return ref.encode(("i", item), fmt, endian)


def pack_samples(fmt: str, endian: str, items: List[int]) -> bytes:
    return b"".join(sample_bytes(fmt, endian, item) for item in items)


def boundary_items(fmt: str) -> List[int]:
    return f32_boundaries() if fmt == "f32" else int_boundaries(ref.FORMATS[fmt][1])


def convert_case(case_id: str, invariants: List[str], src_spec, dst_spec, src: bytes, frames: int,
                 dst_len: int, fill: int = FILL) -> dict:
    dst_init = bytes([fill]) * dst_len
    expected, stats = ref.convert_block(src, src_spec, dst_init, dst_spec, frames)
    return {
        "id": case_id, "kind": "convert", "invariants": invariants,
        "src": src_spec.to_dict(), "dst": dst_spec.to_dict(), "frames": frames,
        "src_hex": src.hex(), "dst_len": dst_len, "dst_fill": fill,
        "dst_expected_hex": expected.hex(), "expected": stats,
    }


def matrix_cases() -> List[dict]:
    """Every (source format, endian) x (destination format, endian): 8 x 8 = 64 cases, stereo."""
    pairs = [(f, e) for f in ref.FORMATS for e in ref.ENDIANS]
    cases = []
    for i, (sfmt, se) in enumerate(pairs):
        for j, (dfmt, de) in enumerate(pairs):
            items = boundary_items(sfmt) + random_items(sfmt, prng(0xD01 + 100 * i + j), 32)
            if len(items) % 2:
                items.append(items[0])
            frames = len(items) // 2
            src_spec = ref.Spec(sfmt, se, 2, 48_000)
            dst_spec = ref.Spec(dfmt, de, 2, 48_000)
            src = pack_samples(sfmt, se, items)
            invariants = ["D01-INV-ENDIAN", "D01-INV-WIDTH-SIGN", "D01-INV-BYTES-PER-FRAME"]
            src_bits, dst_bits = ref.FORMATS[sfmt][1], ref.FORMATS[dfmt][1]
            narrowing = src_bits is not None and dst_bits is not None and dst_bits < src_bits
            if sfmt == "f32" or narrowing:
                invariants.append("D01-INV-SATURATE")
            if sfmt == "f32":
                invariants.append("D01-INV-NONFINITE")
            cases.append(convert_case(
                f"D01-CONV-{sfmt}-{se}__{dfmt}-{de}", invariants, src_spec, dst_spec, src, frames,
                frames * dst_spec.bpf + GUARD_BYTES))
    return cases


def _ints(fmt: str, seed: int, count: int) -> List[int]:
    return random_items(fmt, prng(seed), count)


def layout_cases() -> List[dict]:
    S = ref.Spec
    inv = ["D01-INV-STRIDE-LAYOUT", "D01-INV-BYTES-PER-FRAME"]
    cases = []

    # interleaved with padding -> planar (widening); the padding and the plane gaps stay untouched
    src_spec = S("s16", "big", 2, 48_000, "interleaved", 8)
    dst_spec = S("s32", "little", 2, 48_000, "planar", 16)
    src = bytearray([0xEE]) * src_spec.required_len(3)
    for f, (l, r) in enumerate(((0x0102, 0x0304), (0x0506, 0x0708), (0x090A, 0x0B0C))):
        src[f * 8:f * 8 + 4] = ref.encode(("i", l), "s16", "big") + ref.encode(("i", r), "s16", "big")
    cases.append(convert_case("D01-LAYOUT-001", inv, src_spec, dst_spec, bytes(src), 3, 32, 0xAA))

    # planar -> interleaved with a wide stride, three channels, narrowing with ties
    src_spec = S("s32", "little", 3, 48_000, "planar", 64)
    dst_spec = S("s24in32", "big", 3, 48_000, "interleaved", 20)
    planes = bytearray([0xEE]) * src_spec.required_len(10)
    values = _ints("s32", 0xA11, 30)
    # plant a saturating value and two exact rounding ties for the s32 -> s24 narrowing
    values[0], values[10 + 1], values[20 + 2] = 0x7FFFFF80, -0x80, 0x80
    for ch in range(3):
        for f in range(10):
            off = src_spec.offset(f, ch)
            planes[off:off + 4] = ref.encode(("i", values[ch * 10 + f]), "s32", "little")
    cases.append(convert_case("D01-LAYOUT-002", inv + ["D01-INV-SATURATE"], src_spec, dst_spec,
                              bytes(planes), 10, dst_spec.required_len(10) + 12, 0xAA))

    # planar -> planar with different plane strides
    src_spec = S("f32", "big", 2, 44_100, "planar", 48)
    dst_spec = S("s16", "little", 2, 44_100, "planar", 30)
    buf = bytearray([0xEE]) * src_spec.required_len(12)
    fl = f32_boundaries()
    for ch in range(2):
        for f in range(12):
            off = src_spec.offset(f, ch)
            buf[off:off + 4] = struct.pack(">I", fl[(ch * 12 + f) * 3 % len(fl)])
    cases.append(convert_case("D01-LAYOUT-003", inv + ["D01-INV-NONFINITE", "D01-INV-SATURATE"], src_spec,
                              dst_spec, bytes(buf), 12, dst_spec.required_len(12) + 6, 0xAA))

    # same format, endianness swap only, maximum block, mono, at 8 kHz
    src_spec = S("f32", "big", 1, 8_000)
    dst_spec = S("f32", "little", 1, 8_000)
    fl = f32_boundaries() + random_items("f32", prng(0xA12), 256)
    src = pack_samples("f32", "big", fl[:256])
    cases.append(convert_case("D01-LAYOUT-004", inv + ["D01-INV-BLOCK-LEN", "D01-INV-NONFINITE"], src_spec,
                              dst_spec, src, 256, 256 * 4 + GUARD_BYTES))

    # eight channels, one frame
    src_spec = S("s16", "big", 8, 48_000)
    dst_spec = S("f32", "big", 8, 48_000)
    src = pack_samples("s16", "big", [c * 4096 - 12000 for c in range(8)])
    cases.append(convert_case("D01-LAYOUT-005", inv + ["D01-INV-BLOCK-LEN"], src_spec, dst_spec, src, 1,
                              8 * 4 + GUARD_BYTES))

    # sixteen channels (the maximum), four frames, narrowing
    src_spec = S("s32", "little", 16, 96_000)
    dst_spec = S("s16", "little", 16, 96_000)
    src = pack_samples("s32", "little", _ints("s32", 0xA13, 64))
    cases.append(convert_case("D01-LAYOUT-006", inv + ["D01-INV-SATURATE"], src_spec, dst_spec, src, 4,
                              4 * 32 + GUARD_BYTES))

    # one frame, exactly the maximum block, exactly one-short buffers
    src_spec = S("s16", "big", 2, 48_000)
    dst_spec = S("s32", "big", 2, 48_000)
    src = pack_samples("s16", "big", _ints("s16", 0xA14, 512))
    cases.append(convert_case("D01-LAYOUT-007", inv + ["D01-INV-BLOCK-LEN"], src_spec, dst_spec, src, 256,
                              256 * 8))
    return cases


def packed_len_cases() -> List[dict]:
    cases = []
    n = 0
    for fmt, endian, channels, lens in (
        ("s16", "big", 2, [0, 1, 2, 3, 4, 8, 12, 1020, 1024, 1025, 1028, 1029, 2 ** 31, 2 ** 31 + 1]),
        ("f32", "little", 8, [0, 31, 32, 33, 32 * 255, 32 * 256, 32 * 256 + 1, 32 * 257]),
        ("s24in32", "big", 1, [0, 1, 3, 4, 8, 4 * 256, 4 * 257, 4 * 256 + 2]),
        ("s16", "little", 1, [0, 1, 2, 4, 512, 514]),
    ):
        spec = ref.Spec(fmt, endian, channels, 48_000)
        for length in lens:
            n += 1
            try:
                expect: dict = {"frames": ref.packed_frames(length, spec)}
            except ref.RefError as e:
                expect = {"error": e.code}
            cases.append({"id": f"D01-LEN-{n:03d}", "kind": "packed_len", "invariants": ["D01-INV-BLOCK-LEN", "D01-INV-BYTES-PER-FRAME"],
                          "format": spec.to_dict(), "len": length, "expect": expect})
    return cases


def spec_cases() -> List[dict]:
    cases = []
    n = 0

    def add(op: str, spec_dict: dict, extra: dict, expect: dict) -> None:
        nonlocal n
        n += 1
        cases.append({"id": f"D01-SPEC-{n:03d}", "kind": "spec", "invariants": ["D01-INV-BLOCK-LEN", "D01-INV-STRIDE-LAYOUT", "D01-INV-BYTES-PER-FRAME"],
                      "op": op, "spec": spec_dict, **extra, "expect": expect})

    for channels in (0, 1, 2, 16, 17, 255):
        s = ref.Spec("s16", "big", channels, 48_000)
        try:
            s.validate_format()
            add("format", s.to_dict(), {}, {"ok": True, "bytes_per_frame": s.bpf})
        except ref.RefError as e:
            add("format", s.to_dict(), {}, {"error": e.code})
    for rate in (0, 7_999, 8_000, 44_100, 384_000, 384_001):
        s = ref.Spec("f32", "little", 2, rate)
        try:
            s.validate_format()
            add("format", s.to_dict(), {}, {"ok": True, "bytes_per_frame": s.bpf})
        except ref.RefError as e:
            add("format", s.to_dict(), {}, {"error": e.code})
    for fmt in ref.FORMATS:
        s = ref.Spec(fmt, "big", 3, 48_000)
        add("format", s.to_dict(), {}, {"ok": True, "bytes_per_frame": s.bpf})
    for layout, stride in (("interleaved", 3), ("interleaved", 4), ("interleaved", 5), ("interleaved", ref.MAX_STRIDE_BYTES),
                           ("interleaved", ref.MAX_STRIDE_BYTES + 1), ("planar", 1), ("planar", 2),
                           ("planar", 3), ("planar", ref.MAX_STRIDE_BYTES + 1)):
        s = ref.Spec("s16", "big", 2, 48_000, layout, stride)
        try:
            s.validate_stride()
            add("stride", s.to_dict(), {}, {"ok": True})
        except ref.RefError as e:
            add("stride", s.to_dict(), {}, {"error": e.code})
    for layout, stride, frames in (("interleaved", 4, 0), ("interleaved", 4, 1), ("interleaved", 4, 3), ("interleaved", 8, 3),
                                   ("interleaved", 1024, 256), ("planar", 40, 0), ("planar", 40, 1), ("planar", 40, 10),
                                   ("planar", 40, 11), ("planar", 1024, 256), ("planar", 2, 1)):
        s = ref.Spec("s16", "big", 2, 48_000, layout, stride)
        try:
            add("required_len", s.to_dict(), {"frames": frames}, {"len": s.required_len(frames)})
        except ref.RefError as e:
            add("required_len", s.to_dict(), {"frames": frames}, {"error": e.code})
    return cases


def convert_error_cases() -> List[dict]:
    S = ref.Spec
    stereo16 = S("s16", "big", 2, 48_000)
    stereo32 = S("s32", "little", 2, 48_000)
    mono16 = S("s16", "big", 1, 48_000)
    rate44 = S("s16", "big", 2, 44_100)
    planar_small = S("s16", "big", 2, 48_000, "planar", 4)
    rows = [
        ("zero frames", stereo16, stereo32, 0, 4, 8),
        ("one frame past the maximum", stereo16, stereo32, 257, 4 * 257, 8 * 257),
        ("maximum frames, exact buffers", stereo16, stereo32, 256, 4 * 256, 8 * 256),
        ("channel mismatch", stereo16, mono16, 1, 4, 2),
        ("rate mismatch", stereo16, rate44, 1, 4, 4),
        ("source one byte short", stereo16, stereo32, 4, 4 * 4 - 1, 8 * 4),
        ("destination one byte short", stereo16, stereo32, 4, 4 * 4, 8 * 4 - 1),
        ("destination exact", stereo16, stereo32, 4, 4 * 4, 8 * 4),
        ("buffers longer than required", stereo16, stereo32, 4, 100, 100),
        ("planar plane stride too small for the block", stereo16, planar_small, 3, 12, 64),
        ("planar plane stride exactly enough", stereo16, planar_small, 2, 8, 64),
    ]
    cases = []
    for n, (title, src_spec, dst_spec, frames, src_len, dst_len) in enumerate(rows, start=1):
        try:
            ref.convert_block(bytes(src_len), src_spec, bytes(dst_len), dst_spec, frames)
            expect: dict = {"ok": True}
        except ref.RefError as e:
            expect = {"error": e.code}
        cases.append({"id": f"D01-CERR-{n:03d}", "kind": "convert_error", "title": title,
                      "invariants": ["D01-INV-BLOCK-LEN"], "src": src_spec.to_dict(), "dst": dst_spec.to_dict(),
                      "frames": frames, "src_len": src_len, "dst_len": dst_len, "expect": expect})
    return cases


def _ring_case(case_id: str, title: str, spec, capacity: int, ops: List[list], invariants: List[str]) -> dict:
    model = ref.RingModel(spec, capacity)
    results = []
    for op in ops:
        try:
            if op[0] == "push":
                results.append({"ok": model.push(bytes.fromhex(op[1])), "avail": model.frames})
            else:
                data = model.pop(op[1])
                results.append({"ok": len(data) // spec.bpf, "hex": data.hex(), "avail": model.frames})
        except ref.RefError as e:
            results.append({"error": e.code, "avail": model.frames})
    return {"id": case_id, "kind": "ring", "title": title, "invariants": invariants,
            "format": spec.to_dict(), "capacity": capacity, "ops": ops, "expect": results}


def _block(spec, start: int, frames: int) -> str:
    """Deterministic frame data: byte i is (start + i) mod 256."""
    return bytes((start + i) % 256 for i in range(frames * spec.bpf)).hex()


def ring_cases() -> List[dict]:
    mono = ref.Spec("s16", "big", 1, 48_000)
    inv = ["D01-INV-RING-WRAP"]
    cases = []
    cases.append(_ring_case("D01-RING-001", "FIFO across the wrap point", mono, 5, [
        ["push", _block(mono, 1, 3)], ["pop", 6], ["push", _block(mono, 100, 4)], ["pop", 8],
        ["push", _block(mono, 7, 5)], ["pop", 10], ["push", _block(mono, 9, 2)], ["push", _block(mono, 50, 3)],
        ["pop", 4], ["pop", 6]], inv))
    cases.append(_ring_case("D01-RING-002", "underrun, full, exact capacity", mono, 5, [
        ["pop", 6], ["push", _block(mono, 1, 3)], ["push", _block(mono, 20, 3)], ["pop", 6], ["pop", 2],
        ["push", _block(mono, 30, 5)], ["push", _block(mono, 40, 1)], ["pop", 10], ["pop", 2]], inv))
    big = ref.Spec("s16", "big", 1, 48_000)
    cases.append(_ring_case("D01-RING-003", "empty, misaligned, oversize and never-fits blocks", big, 5, [
        ["push", ""], ["pop", 0], ["push", "010203"], ["pop", 5], ["push", _block(big, 0, 6)], ["pop", 12],
        ["push", _block(big, 0, 5)], ["pop", 10]], ["D01-INV-RING-WRAP", "D01-INV-BLOCK-LEN"]))
    large = ref.Spec("s16", "big", 1, 48_000)
    cases.append(_ring_case("D01-RING-004", "maximum block fits, one frame more does not", large, 1000, [
        ["push", _block(large, 0, 256)], ["push", _block(large, 3, 257)], ["pop", 2 * 257], ["pop", 2 * 256]],
        ["D01-INV-RING-WRAP", "D01-INV-BLOCK-LEN"]))
    tri = ref.Spec("s24in32", "little", 3, 48_000)
    cases.append(_ring_case("D01-RING-005", "multichannel frames stay whole across the wrap", tri, 4, [
        ["push", _block(tri, 0, 3)], ["pop", 24], ["push", _block(tri, 100, 3)], ["pop", 48], ["pop", 12]], inv))

    # a long deterministic script on a prime capacity, so positions wrap many times
    capacity = 7
    spec = ref.Spec("s16", "little", 2, 48_000)
    rng = prng(0xD0105)
    ops: List[list] = []
    counter = 0
    for _ in range(400):
        frames = next(rng) % 4 + 1
        if next(rng) % 2 == 0:
            ops.append(["push", bytes((counter + i) % 256 for i in range(frames * spec.bpf)).hex()])
            counter += frames * spec.bpf
        else:
            ops.append(["pop", frames * spec.bpf])
    cases.append(_ring_case("D01-RING-006", "400-op seeded script, capacity 7, positions wrap many times", spec, capacity, ops, inv))
    return cases


def pipeline_cases() -> List[dict]:
    """Known PCM through convert -> ring -> convert -> sink; expected from the reference alone."""
    rows = [
        ("D01-PIPE-001", ("s16", "big", 2, 48_000), ("f32", "little", 2, 48_000), ("s24in32", "big", 2, 48_000), 1000, 64, 200, 2, 0xB01),
        ("D01-PIPE-002", ("s24in32", "little", 1, 44_100), ("s32", "big", 1, 44_100), ("f32", "big", 1, 44_100), 700, 256, 600, 1, 0xB02),
        ("D01-PIPE-003", ("f32", "big", 6, 48_000), ("s16", "little", 6, 48_000), ("s32", "little", 6, 48_000), 150, 7, 29, 3, 0xB03),
        ("D01-PIPE-004", ("s32", "little", 2, 96_000), ("s24in32", "big", 2, 96_000), ("s16", "big", 2, 96_000), 513, 100, 301, 2, 0xB04),
    ]
    cases = []
    for case_id, s, r, o, total, block, ring_frames, lag, seed in rows:
        src_spec, ring_spec, out_spec = ref.Spec(*s), ref.Spec(*r), ref.Spec(*o)
        fmt = s[0]
        count = total * src_spec.channels
        items = random_items(fmt, prng(seed), count)
        boundaries = boundary_items(fmt)
        for i, b in enumerate(boundaries[:count]):
            items[(i * 5) % count] = b  # plant rails, ties and (for f32) non-finite values
        src = pack_samples(fmt, s[1], items)
        out = bytearray()
        stats = {"saturated": 0, "non_finite": 0}
        model = ref.RingModel(ring_spec, ring_frames)
        chunks, pos = [], 0
        while pos < total:
            n = min(block, total - pos)
            chunks.append(src[pos * src_spec.bpf:(pos + n) * src_spec.bpf])
            pos += n

        def drain(k: int) -> None:
            """Pop chunk k from the ring model and convert it to the output format."""
            data = model.pop(len(pending[k]))
            assert data == pending[k], "ring model must be a transparent FIFO"
            back, s2 = ref.convert_packed(data, ring_spec, out_spec)
            out.extend(back)
            for key in stats:
                stats[key] += s2[key]

        # Schedule shared with the Rust harness: after pushing chunk k, pop chunk k - lag (when
        # k >= lag); once everything is pushed, pop what is left in order.
        pending: List[bytes] = []
        for k, chunk in enumerate(chunks):
            mid, s1 = ref.convert_packed(chunk, src_spec, ring_spec)
            model.push(mid)  # raises ring_full if the schedule overflows the ring
            pending.append(mid)
            for key in stats:
                stats[key] += s1[key]
            if k >= lag:
                drain(k - lag)
        for k in range(max(0, len(chunks) - lag), len(chunks)):
            drain(k)
        assert len(out) == total * out_spec.bpf
        cases.append({"id": case_id, "kind": "pipeline",
                      "invariants": ["D01-INV-ROUNDTRIP-E2E", "D01-INV-RING-WRAP", "D01-INV-WIDTH-SIGN", "D01-INV-ENDIAN"],
                      "src": src_spec.to_dict(), "ring": ring_spec.to_dict(), "out": out_spec.to_dict(),
                      "ring_frames": ring_frames, "block_frames": block, "lag": lag,
                      "src_hex": src.hex(), "out_expected_hex": bytes(out).hex(), "expected": stats})
    return cases


def build() -> dict:
    cases = (matrix_cases() + layout_cases() + packed_len_cases() + spec_cases() + convert_error_cases()
             + ring_cases() + pipeline_cases())
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    return {"schema": SCHEMA, "generator": "tests/d01/generate.py (reference: tests/d01/reference.py)",
            "invariants": INVARIANTS, "external": EXTERNAL_INVARIANTS, "cases": cases}


def dumps(doc: dict) -> str:
    """One case per line so a vector diff is reviewable; stable key order."""
    def j(x: Any) -> str:
        return json.dumps(x, sort_keys=True, separators=(",", ":"))

    head = {k: v for k, v in doc.items() if k != "cases"}
    lines = [j(head)[:-1] + ',"cases":[']
    for i, case in enumerate(doc["cases"]):
        lines.append("  " + j(case) + ("," if i + 1 < len(doc["cases"]) else ""))
    lines.append("]}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    # usage: generate.py [OUT.json]   (stdout when no path is given)
    text = dumps(build())
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
