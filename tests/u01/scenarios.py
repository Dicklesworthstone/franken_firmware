"""Scripted scenarios for U01, shared by the vector generator and the tests. A step is (method, *args); the argument
kinds of each method are in SIGNATURES so a script can be written to JSON (bytes as lowercase hex) and read back by the
Rust replay with the same table."""
from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

import reference as ref

SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "put": ("int", "bytes", "bytes"), "delete": ("int", "bytes"), "reset_settings": (), "clear_calibration": (),
    "install": ("bytes", "int", "bytes"), "revoke": ("bytes",), "reset_pairing": (), "raise_mark": ("bytes", "int"),
    "stage_setting": ("bytes", "bytes"), "flush_settings": ("int",),
}


def b(text: str) -> bytes:
    return text.encode("ascii")


def step_to_json(step: Sequence[Any]) -> Dict[str, Any]:
    kinds = SIGNATURES[step[0]]
    return {"op": step[0], "args": [a.hex() if k == "bytes" else a for k, a in zip(kinds, step[1:])]}


def step_from_json(doc: Dict[str, Any]) -> Tuple:
    kinds = SIGNATURES[doc["op"]]
    return (doc["op"],) + tuple(bytes.fromhex(a) if k == "bytes" else a for k, a in zip(kinds, doc["args"]))


def namespaces() -> List[Tuple]:
    """Every namespace written once, then reset one at a time: the three resets are separate operations."""
    return [
        ("stage_setting", b("vol"), b("40")), ("flush_settings", 0),
        ("put", ref.NS_CALIBRATION, b("board-a"), b("cal-1")),
        ("install", b("peer-1"), 1, b("secret-1")),
        ("put", ref.NS_RECORDS, b("voter"), b("rec-1")),
        ("raise_mark", b("epoch"), 7),
        ("reset_settings",),            # settings gone; calibration, credentials, records, marks untouched
        ("clear_calibration",),         # calibration gone; the rest untouched
        ("reset_pairing",),             # credentials revoked (tombstoned); records and marks untouched
        ("delete", ref.NS_RECORDS, b("voter")),
    ]


def credentials() -> List[Tuple]:
    """Versioned credentials: replacement needs a strictly higher version, revocation leaves a tombstone, a revoked
    identity returns only with a strictly higher version, and a tombstone still occupies its identity slot."""
    return [
        ("install", b("a"), 1, b("s-a1")),
        ("install", b("b"), 1, b("s-b1")),
        ("install", b("a"), 1, b("s-a1x")),     # rejected: not newer
        ("revoke", b("a")),
        ("install", b("a"), 1, b("s-a1")),      # rejected: revoked at 1
        ("install", b("a"), 2, b("s-a2")),      # admitted: strictly higher than the tombstone
        ("revoke", b("a")),
        ("revoke", b("a")),                     # rejected: already revoked
        ("reset_pairing",),
        ("install", b("c"), 1, b("s-c1")),      # third identity slot (a, b, c)
        ("install", b("d"), 1, b("s-d1")),      # rejected: no free identity slot, tombstones count
        ("raise_mark", b("epoch"), 3),
        ("raise_mark", b("epoch"), 2),          # rejected: a mark never goes down
        ("raise_mark", b("epoch"), 3),          # no change: nothing is written
        ("raise_mark", b("epoch"), 4),
    ]


def churn(rounds: int = 40) -> List[Tuple]:
    """Enough small commits to fill a segment and compact more than once, with a revocation before the first compaction
    so the tombstone has to survive both."""
    steps: List[Tuple] = [("install", b("a"), 1, b("s-a1")), ("install", b("b"), 1, b("s-b1")), ("revoke", b("a"))]
    for i in range(rounds):
        steps.append(("stage_setting", b("vol"), b(f"{i:02d}")))
        steps.append(("flush_settings", 100 * (i + 1)))
    steps.append(("put", ref.NS_CALIBRATION, b("board-a"), b("cal-x")))
    return steps


def limits_error_cases() -> List[Tuple]:
    long_key, long_value = b("k" * 9), b("v" * 17)
    return [
        ("put", ref.NS_SETTINGS, b(""), b("v")),                   # empty key
        ("put", ref.NS_SETTINGS, long_key, b("v")),                # key too long
        ("put", ref.NS_SETTINGS, b("k"), long_value),              # value too long
        ("put", ref.NS_CREDENTIALS, b("k"), b("v")),               # credentials are not a blob namespace
        ("put", ref.NS_SETTINGS, b("a"), b("1")), ("put", ref.NS_SETTINGS, b("b"), b("2")),
        ("put", ref.NS_SETTINGS, b("c"), b("3")),                  # namespace full (two entries)
        ("delete", ref.NS_SETTINGS, b("zz")),                      # not found
        ("revoke", b("nobody")),                                   # not found
        ("install", b("p"), 0, b("s")),                            # version 0 is not a version
        ("install", b("p"), 1, b("s" * 17)),                       # secret too long
    ]


SCENARIOS: Dict[str, List[Tuple]] = {
    "namespaces": namespaces(), "credentials": credentials(), "churn": churn(), "rejections": limits_error_cases(),
}
