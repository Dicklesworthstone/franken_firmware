"""Independent Python codec for the P04 adapter wire records.

Written from the layout in docs/contracts/p04.md without reading crates/franken-hal. It decodes the
same hand-computed vectors as the Rust codec. Same author as the Rust code, so agreement is a
cross-check, not a second author.

``endian`` exists so the runner can plant a defect (a host-endian read) and require that the
vectors catch it.
"""
from __future__ import annotations

from typing import Any, Dict

EVENT_LEN = 12
GEOMETRY_LEN = 16
KINDS = {1: "completed", 2: "position", 3: "flush_ack", 4: "device_lost"}


class AbiError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def _word(data: bytes, at: int, endian: str) -> int:
    return int.from_bytes(data[at:at + 4], endian)


def decode_event(data: bytes, endian: str = "big") -> Dict[str, Any]:
    if len(data) != EVENT_LEN:
        raise AbiError("length")
    kind, a, b = _word(data, 0, endian), _word(data, 4, endian), _word(data, 8, endian)
    if kind not in KINDS:
        raise AbiError("unknown_kind")
    if kind == 1:
        if a > 0xFFFF:
            raise AbiError("slot_range")
        return {"kind": "completed", "slot": a, "generation": b}
    if kind == 2:
        if b != 0:
            raise AbiError("reserved_non_zero")
        return {"kind": "position", "counter": a}
    if a != 0 or b != 0:
        raise AbiError("reserved_non_zero")
    return {"kind": KINDS[kind]}


def encode_event(event: Dict[str, Any], endian: str = "big") -> bytes:
    kind = {v: k for k, v in KINDS.items()}[event["kind"]]
    a = event.get("slot", event.get("counter", 0))
    b = event.get("generation", 0)
    return b"".join(x.to_bytes(4, endian) for x in (kind, a, b))


def decode_geometry(data: bytes, endian: str = "big") -> Dict[str, int]:
    if len(data) != GEOMETRY_LEN:
        raise AbiError("length")
    names = ("ring_depth", "frames_per_block", "channels", "bytes_per_sample")
    return {name: _word(data, 4 * i, endian) for i, name in enumerate(names)}


def encode_geometry(g: Dict[str, int], endian: str = "big") -> bytes:
    names = ("ring_depth", "frames_per_block", "channels", "bytes_per_sample")
    return b"".join(g[n].to_bytes(4, endian) for n in names)
