"""Independent Python decoder and debounce model for the P04 local-event record.

Written from the layout in docs/contracts/p04.md without reading crates/franken-hal. The record is a
harness MODEL, not a driver ABI. Same author as the Rust code, so agreement is a cross-check.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Type

RECORD_LEN = 8
SYNC = 0xA5
KINDS = {1: "button_down", 2: "button_up", 3: "led_fault", 4: "device_fault"}


class RecordError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


def decode_record(data: bytes, endian: str = "big") -> Dict[str, Any]:
    if len(data) != RECORD_LEN:
        raise RecordError("length")
    if data[0] != SYNC:
        raise RecordError("bad_sync")
    if data[1] not in KINDS:
        raise RecordError("unknown_kind")
    if data[3] != 0:
        raise RecordError("flags_non_zero")
    return {"kind": KINDS[data[1]], "id": data[2], "device_ticks": int.from_bytes(data[4:8], endian)}


def encode_record(event: Dict[str, Any], endian: str = "big") -> bytes:
    code = {v: k for k, v in KINDS.items()}[event["kind"]]
    return bytes([SYNC, code, event["id"], 0]) + event["device_ticks"].to_bytes(4, endian)


class Debounce:
    """One button. Mirrors the rules in docs/contracts/p04.md, not the Rust code.

    ``edge`` returns what happened to a raw edge: ``"ignored"`` (a repeat), ``"bounce"`` (it replaced a
    pending change) or ``"pending"`` (it started a wait). ``settle`` returns the new reported state
    once the raw state has been steady for ``window`` ticks, otherwise None.
    """

    def __init__(self, window: int) -> None:
        self.window = window
        self.reported = "unknown"
        self.raw = "unknown"
        self.raw_since = 0

    def edge(self, state: str, now: int) -> str:
        if state == self.raw:
            return "ignored"
        bounce = self.raw != self.reported
        self.raw, self.raw_since = state, now
        return "bounce" if bounce else "pending"

    def settle(self, now: int) -> Optional[str]:
        if self.raw != "unknown" and self.raw != self.reported and now - self.raw_since >= self.window:
            self.reported = self.raw
            return self.reported
        return None


def replay_debounce(window: int, steps: List[Tuple[int, Optional[str]]],
                    model: Type[Debounce] = Debounce) -> Dict[str, Any]:
    """Run (tick, edge-or-None) steps; each step applies the edge, then settles at that tick."""
    b = model(window)
    reported: List[Tuple[int, str]] = []
    bounces = duplicates = 0
    for now, state in steps:
        if state is not None:
            outcome = b.edge(state, now)
            if outcome == "bounce":
                bounces += 1
            elif outcome == "ignored":
                duplicates += 1
        out = b.settle(now)
        if out is not None:
            reported.append((now, out))
    return {"reported": reported, "bounces": bounces, "duplicates": duplicates, "final": b.reported}
