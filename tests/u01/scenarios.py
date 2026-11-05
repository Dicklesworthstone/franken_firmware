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
    "commit": ("ops",),  # one transaction of several operations, possibly in several namespaces
}
# The operations inside a `commit` step, spelled with the reference's operation tags (reference.apply_op).
OP_SIGNATURES: Dict[str, Tuple[str, ...]] = {
    "put": ("int", "bytes", "bytes"), "delete": ("int", "bytes"), "reset": ("int",), "install": ("bytes", "int", "bytes"),
    "revoke": ("bytes",), "reset_pairing": (), "raise": ("bytes", "int"),
}


def b(text: str) -> bytes:
    return text.encode("ascii")


def _arg_to_json(kind: str, value: Any) -> Any:
    if kind == "bytes":
        return value.hex()
    if kind == "ops":
        return [{"op": op[0], "args": [_arg_to_json(k, a) for k, a in zip(OP_SIGNATURES[op[0]], op[1:])]} for op in value]
    return value


def _arg_from_json(kind: str, value: Any) -> Any:
    if kind == "bytes":
        return bytes.fromhex(value)
    if kind == "ops":
        return [(d["op"],) + tuple(_arg_from_json(k, a) for k, a in zip(OP_SIGNATURES[d["op"]], d["args"])) for d in value]
    return value


def step_to_json(step: Sequence[Any]) -> Dict[str, Any]:
    kinds = SIGNATURES[step[0]]
    return {"op": step[0], "args": [_arg_to_json(k, a) for k, a in zip(kinds, step[1:])]}


def step_from_json(doc: Dict[str, Any]) -> Tuple:
    kinds = SIGNATURES[doc["op"]]
    return (doc["op"],) + tuple(_arg_from_json(k, a) for k, a in zip(kinds, doc["args"]))


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


def cross_namespace() -> List[Tuple]:
    """Transactions that span namespaces. Each `commit` is ONE frame, so a power cut recovers all of it or none of it: the
    credential and the calibration that a transaction wrote are both the old pair or both the new pair, never one of each.
    One transaction is rejected for its second operation; its valid first operation must not stay applied. Twelve settings
    flushes then fill the segment, so the next transaction is published by compaction (a snapshot in the other segment), and
    one more transaction follows it so the stale segment is retired inside the script."""
    filler: List[Tuple] = []
    for i in range(12):
        filler += [("stage_setting", b("vol"), b(f"{i:02d}")), ("flush_settings", 100 * (i + 1))]
    return [
        ("put", ref.NS_CALIBRATION, b("board-a"), b("cal-1")),
        ("install", b("peer"), 1, b("secret-1")),
        # a credential replacement and a new calibration in one transaction
        ("commit", [("install", b("peer"), 2, b("secret-2")), ("put", ref.NS_CALIBRATION, b("board-a"), b("cal-2"))]),
        # three namespaces at once: calibration, a record and a mark
        ("commit", [("put", ref.NS_CALIBRATION, b("board-a"), b("cal-3")), ("put", ref.NS_RECORDS, b("voter"), b("rec-1")),
                    ("raise", b("epoch"), 5)]),
        # rejected: the credential version is not newer. The calibration write before it is valid and must not stay.
        ("commit", [("put", ref.NS_CALIBRATION, b("board-a"), b("cal-REJ")), ("install", b("peer"), 2, b("secret-x"))]),
    ] + filler + [
        # a revocation and a calibration clear together (published by compaction)
        ("commit", [("revoke", b("peer")), ("reset", ref.NS_CALIBRATION)]),
        # after the compaction: a record and a mark together, appended to the new segment (it also retires the old one)
        ("commit", [("put", ref.NS_RECORDS, b("voter"), b("rec-2")), ("raise", b("epoch"), 6)]),
    ]


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
    "cross_namespace": cross_namespace(),
}
