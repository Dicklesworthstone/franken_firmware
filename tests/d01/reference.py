"""Independent reference for D01 (ffw-f3b): PCM format conversion, block lengths and the ring.

Written from the rule table in docs/contracts/d01.md using only the standard library
(``struct`` for byte layout, Python ints/floats for arithmetic). It shares no code with the Rust
implementation and never reads Rust output; the e2e runner compares the two.

Everything here is deterministic and offline.
"""
from __future__ import annotations

import math
import struct
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

MAX_BLOCK_FRAMES = 256
MAX_CHANNELS = 16
MIN_RATE_HZ = 8_000
MAX_RATE_HZ = 384_000
MAX_STRIDE_BYTES = 1 << 20
MAX_RING_FRAMES = 1 << 16

# name -> (container bytes, significant bits; None for float)
FORMATS: Dict[str, Tuple[int, Optional[int]]] = {
    "s16": (2, 16),
    "s24in32": (4, 24),
    "s32": (4, 32),
    "f32": (4, None),
}
ENDIANS = {"big": ">", "little": "<"}


class RefError(Exception):
    """A typed refusal; ``code`` matches ``PcmError::code()`` in the Rust crate."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Spec:
    """Stream format plus buffer layout. ``stride`` is the frame stride (interleaved) or the
    plane stride (planar), in bytes."""

    def __init__(self, fmt: str, endian: str, channels: int, rate: int, layout: str = "interleaved",
                 stride: Optional[int] = None):
        self.fmt, self.endian, self.channels, self.rate, self.layout = fmt, endian, channels, rate, layout
        self.stride = self.bpf if stride is None else stride

    @classmethod
    def from_dict(cls, d: dict) -> "Spec":
        return cls(d["format"], d["endian"], d["channels"], d["rate"], d["layout"], d["stride"])

    def to_dict(self) -> dict:
        return {"format": self.fmt, "endian": self.endian, "channels": self.channels, "rate": self.rate,
                "layout": self.layout, "stride": self.stride}

    @property
    def bps(self) -> int:
        return FORMATS[self.fmt][0]

    @property
    def bpf(self) -> int:
        return self.channels * self.bps

    def validate_format(self) -> None:
        if self.channels == 0 or self.channels > MAX_CHANNELS:
            raise RefError("invalid_channels")
        if not MIN_RATE_HZ <= self.rate <= MAX_RATE_HZ:
            raise RefError("invalid_sample_rate")

    def validate_stride(self) -> None:
        """Construction rules: stride bound first, then the minimum for the layout."""
        self.validate_format()
        if self.stride > MAX_STRIDE_BYTES:
            raise RefError("stride_too_large")
        minimum = self.bpf if self.layout == "interleaved" else self.bps
        if self.stride < minimum:
            raise RefError("stride_too_small")

    def required_len(self, frames: int) -> int:
        if frames == 0:
            return 0
        if self.layout == "interleaved":
            return (frames - 1) * self.stride + self.bpf
        plane = frames * self.bps
        if self.stride < plane:
            raise RefError("stride_too_small")
        return (self.channels - 1) * self.stride + plane

    def offset(self, frame: int, channel: int) -> int:
        if self.layout == "interleaved":
            return frame * self.stride + channel * self.bps
        return channel * self.stride + frame * self.bps


# ---- sample coding ------------------------------------------------------------------------


def decode(raw: bytes, fmt: str, endian: str):
    """bytes -> ("i", int) or ("f", float). s24in32 ignores the top byte and sign-extends bit 23."""
    e = ENDIANS[endian]
    if fmt == "s16":
        return ("i", struct.unpack(e + "h", raw)[0])
    if fmt == "s24in32":
        low = struct.unpack(e + "I", raw)[0] & 0xFFFFFF
        return ("i", low - 0x1000000 if low >= 0x800000 else low)
    if fmt == "s32":
        return ("i", struct.unpack(e + "i", raw)[0])
    return ("f", struct.unpack(e + "f", raw)[0])


def encode(value, fmt: str, endian: str) -> bytes:
    """("i", int) / ("f", float) -> bytes. s24in32 is written sign-extended into the top byte."""
    e = ENDIANS[endian]
    _, v = value
    if fmt == "s16":
        return struct.pack(e + "h", v)
    if fmt in ("s24in32", "s32"):
        return struct.pack(e + "i", v)
    return struct.pack(e + "f", v)


def _clamp_int(r: int, bits: int, stats: dict) -> int:
    hi, lo = 2 ** (bits - 1) - 1, -(2 ** (bits - 1))
    if r > hi:
        stats["saturated"] += 1
        return hi
    if r < lo:
        stats["saturated"] += 1
        return lo
    return r


def convert_value(value, src_fmt: str, dst_fmt: str, stats: dict):
    """One sample under the D01 rules (see docs/contracts/d01.md, "Conversion rules")."""
    src_bits, dst_bits = FORMATS[src_fmt][1], FORMATS[dst_fmt][1]
    kind, v = value
    if kind == "i":
        if dst_bits is None:
            return ("f", v / 2 ** (src_bits - 1))  # int/int true division: correctly rounded
        if dst_bits >= src_bits:
            return ("i", v * 2 ** (dst_bits - src_bits))
        shift = src_bits - dst_bits
        rounded = (v + 2 ** (shift - 1)) // 2 ** shift  # floor division == arithmetic shift
        return ("i", _clamp_int(rounded, dst_bits, stats))
    if not math.isfinite(v):
        stats["non_finite"] += 1
        return ("f", 0.0) if dst_bits is None else ("i", 0)
    if dst_bits is None:
        if v > 1.0:
            stats["saturated"] += 1
            return ("f", 1.0)
        if v < -1.0:
            stats["saturated"] += 1
            return ("f", -1.0)
        return ("f", v)
    scaled = round(v * 2 ** (dst_bits - 1))  # Python rounds exact halves to even
    return ("i", _clamp_int(scaled, dst_bits, stats))


# ---- block-level operations ----------------------------------------------------------------


def packed_frames(length: int, spec: Spec) -> int:
    """Whole frames in a packed interleaved block of ``length`` bytes (zero, misaligned, max)."""
    if length == 0:
        raise RefError("empty_block")
    if length % spec.bpf != 0:
        raise RefError("misaligned_block")
    frames = length // spec.bpf
    if frames > MAX_BLOCK_FRAMES:
        raise RefError("block_too_large")
    return frames


def convert_block(src: bytes, src_spec: Spec, dst: bytes, dst_spec: Spec, frames: int):
    """Returns (new dst bytes, stats). ``dst`` is the buffer before the call; bytes outside the
    addressed samples (padding, guard) are returned unchanged. Raises RefError in the contract's
    check order."""
    if frames == 0:
        raise RefError("empty_block")
    if frames > MAX_BLOCK_FRAMES:
        raise RefError("block_too_large")
    if src_spec.channels != dst_spec.channels:
        raise RefError("channel_mismatch")
    if src_spec.rate != dst_spec.rate:
        raise RefError("sample_rate_mismatch")
    need_src = src_spec.required_len(frames)
    need_dst = dst_spec.required_len(frames)
    if len(src) < need_src or len(dst) < need_dst:
        raise RefError("buffer_too_small")
    out = bytearray(dst)
    stats = {"saturated": 0, "non_finite": 0}
    for frame in range(frames):
        for channel in range(src_spec.channels):
            so = src_spec.offset(frame, channel)
            do = dst_spec.offset(frame, channel)
            value = decode(src[so:so + src_spec.bps], src_spec.fmt, src_spec.endian)
            converted = convert_value(value, src_spec.fmt, dst_spec.fmt, stats)
            out[do:do + dst_spec.bps] = encode(converted, dst_spec.fmt, dst_spec.endian)
    return bytes(out), stats


def convert_packed(src: bytes, src_spec: Spec, dst_spec: Spec) -> Tuple[bytes, dict]:
    """Packed interleaved -> packed interleaved; returns the exact output bytes and stats."""
    frames = packed_frames(len(src), src_spec)
    out, stats = convert_block(src, src_spec, bytes(frames * dst_spec.bpf), dst_spec, frames)
    return out, stats


# ---- ring model ---------------------------------------------------------------------------


class RingModel:
    """A bounded byte FIFO of whole frames: the behavioural spec of the Rust ring."""

    def __init__(self, spec: Spec, capacity: int):
        if capacity == 0 or capacity > MAX_RING_FRAMES:
            raise RefError("invalid_ring_capacity")
        self.spec, self.capacity = spec, capacity
        self.fifo: Deque[int] = deque()

    @property
    def frames(self) -> int:
        return len(self.fifo) // self.spec.bpf

    def _check(self, length: int) -> int:
        frames = packed_frames(length, self.spec)
        if frames > self.capacity:
            raise RefError("block_too_large")
        return frames

    def push(self, block: bytes) -> int:
        frames = self._check(len(block))
        if frames > self.capacity - self.frames:
            raise RefError("ring_full")
        self.fifo.extend(block)
        return frames

    def pop(self, length: int) -> bytes:
        frames = self._check(length)
        if frames > self.frames:
            raise RefError("ring_underrun")
        return bytes(self.fifo.popleft() for _ in range(frames * self.spec.bpf))


def locate(spec: Spec, frames: int, offset: int) -> Optional[Tuple[int, int]]:
    """(frame, channel) of the sample covering byte ``offset``; None for padding or guard bytes."""
    for frame in range(frames):
        for channel in range(spec.channels):
            start = spec.offset(frame, channel)
            if start <= offset < start + spec.bps:
                return frame, channel
    return None
