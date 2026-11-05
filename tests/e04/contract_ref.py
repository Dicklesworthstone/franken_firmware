"""Reference model of the E04 contract records and hardware eligibility, written in Python.

Independent of crates/franken-hal: it works on the JSON shape the Rust types serialize to, and
re-derives the verdict from the rules in docs/contracts/e04.md. Same author as the Rust code, so
agreement is a cross-check, not a second author.

Nothing here reads a driver's size as evidence of safety. ``evaluate`` has no code path that looks
at ``size_bytes``; the runner pins that by evaluating the same matrix with different sizes.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "ffw.e04.contract_matrix.v1"
OPERATIONS = ["query_capabilities", "acquire_exclusive", "prepare_format", "submit_block", "query_position",
              "start", "set_gain", "drain", "abort_mute", "release"]
DUTIES = ["multicast_delivery", "unicast_delivery", "power_save", "roam", "congestion", "mesh_membership",
          "scheduler_interference"]
INTERFACE_FIELDS = ["interface", "selector", "full_command", "direction", "payload_size", "endianness",
                    "alignment", "field_map"]
RADIO_FIELDS = [("owner", "owner"), ("survives_daemon_replacement", "survives_daemon_replacement"),
                ("audio_interference_bound_us", "audio_interference_bound")]
FIXTURE_SHA = "0123456789abcdef" * 4

# ---- PowerPC ioctl layout: nr 0..7, type 8..15, size 16..28, direction 29..31 ----


def decode_ppc_ioctl(cmd: int) -> Dict[str, int]:
    return {"nr": cmd & 0xFF, "type_byte": (cmd >> 8) & 0xFF, "size": (cmd >> 16) & 0x1FFF, "dir_bits": cmd >> 29}


def encode_ppc_ioctl(dir_bits: int, type_byte: int, nr: int, size: int) -> Optional[int]:
    if not 0 <= dir_bits <= 7 or not 0 <= size <= 0x1FFF or not 0 <= type_byte <= 255 or not 0 <= nr <= 255:
        return None
    return (dir_bits << 29) | (size << 16) | (type_byte << 8) | nr


DIRECTION = {1: "no_data", 2: "read", 4: "write", 6: "read_write"}


def read_uint(data: List[int], offset: int, width: int, endian: str) -> Dict[str, Any]:
    """Returns {"ok": value} or {"err": kind}, checking width, then alignment, then bounds."""
    if width not in (1, 2, 4, 8):
        return {"err": "bad_width"}
    if offset % width:
        return {"err": "misaligned"}
    if offset + width > len(data):
        return {"err": "out_of_bounds"}
    chunk = data[offset:offset + width]
    return {"ok": int.from_bytes(bytes(chunk), "big" if endian == "big" else "little")}


def validate_field_map(fields: List[Dict[str, Any]], payload_size: int, alignment: int) -> Optional[str]:
    """None when the fields tile the payload exactly, otherwise the name of the first problem."""
    if alignment not in (1, 2, 4, 8):
        return "bad_alignment"
    seen = set()
    for f in fields:
        if not f["name"].strip():
            return "empty_name"
        if f["name"] in seen:
            return "duplicate_name"
        seen.add(f["name"])
        if f["width"] == 0:
            return "zero_width"
        if f["kind"] != "padding":
            if f["width"] not in (1, 2, 4, 8):
                return "bad_integer_width"
            if f["offset"] % f["width"]:
                return "misaligned"
            if f["width"] > alignment:
                return "alignment_too_small"
    nxt = 0
    for f in sorted(fields, key=lambda x: x["offset"]):
        if f["offset"] < nxt:
            return "overlap"
        if f["offset"] > nxt:
            return "gap"
        nxt = f["offset"] + f["width"]
        if nxt > payload_size:
            return "out_of_bounds"
    return "gap" if nxt < payload_size else None


# ---- matrix evaluation ----


def _hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _anchor_problem(matrix: Dict[str, Any], anchor: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = anchor["kind"]
    if kind == "synthetic_fixture":
        if not anchor["label"].strip():
            return {"kind": "bad_anchor", "detail": "a synthetic anchor has no label"}
        return {"kind": "synthetic_anchor", "label": anchor["label"]}
    if kind == "source":
        if not anchor["reference"].strip():
            return {"kind": "bad_anchor", "detail": "a source anchor has no reference"}
        return None
    sha = anchor["sha256"]
    if not _hex64(sha):
        return {"kind": "bad_anchor", "detail": "artifact digest is not 64 lowercase hex characters"}
    artifact = next((a for a in matrix["artifacts"] if a["sha256"] == sha), None)
    if artifact is None:
        return {"kind": "unregistered_artifact", "sha256": sha}
    section = next((s for s in artifact["sections"] if s["name"] == anchor["section"]), None)
    if section is None:
        return {"kind": "bad_anchor", "detail": f"section {anchor['section']} is not registered for the artifact"}
    if anchor["offset"] >= section["size"]:
        return {"kind": "bad_anchor", "detail": f"offset {anchor['offset']:#x} is outside section "
                                                f"{anchor['section']} ({section['size']:#x} byte(s))"}
    if anchor.get("symbol") is not None and not anchor["symbol"].strip():
        return {"kind": "bad_anchor", "detail": "the artifact anchor has an empty symbol name"}
    return None


def _field_reason(matrix: Dict[str, Any], status: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    s = status["status"]
    if s == "known":
        return _anchor_problem(matrix, status["anchor"])
    if s == "unknown":
        b = status["blocker"]
        if not b["id"].strip() or not b["needs"].strip():
            return {"kind": "inconsistent", "detail": "an unknown field has no named external blocker"}
        return {"kind": "unknown", "blocker": b}
    if not status["reason"].strip():
        return {"kind": "inconsistent", "detail": "a not-applicable field gives no reason"}
    return None


def _value(status: Dict[str, Any]) -> Any:
    return status["value"] if status["status"] == "known" else None


def _consistency(rec: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    kind = _value(rec["interface"])
    is_ioctl = kind == "ioctl"
    na = lambda k: rec[k]["status"] == "not_applicable"  # noqa: E731
    if kind is not None and not is_ioctl:
        if not na("selector"):
            out.append(("selector", "non-ioctl selector must be not applicable"))
        if not na("full_command"):
            out.append(("full_command", "non-ioctl full command must be not applicable"))
    if is_ioctl and na("selector"):
        out.append(("selector", "ioctl selector cannot be not applicable"))
    if is_ioctl and na("full_command"):
        out.append(("full_command", "ioctl full command cannot be not applicable"))
    nr = _value(rec["selector"])
    if nr is not None and nr > 0xFF:
        out.append(("selector", "selector exceeds the 8-bit command number"))
    cmd = _value(rec["full_command"])
    size = _value(rec["payload_size"])
    if cmd is not None:
        parts = decode_ppc_ioctl(cmd)
        if nr is not None and parts["nr"] != nr:
            out.append(("full_command", "command number differs from the selector"))
        encoded = DIRECTION.get(parts["dir_bits"])
        if encoded is None:
            out.append(("full_command", "command encodes no valid direction"))
        elif _value(rec["direction"]) not in (None, encoded):
            out.append(("direction", "command direction differs from the record"))
        if size is not None and size != parts["size"]:
            out.append(("payload_size", "command size differs from the record"))
    if is_ioctl and size is not None and size > 0x1FFF:
        out.append(("payload_size", "payload exceeds the 13-bit ioctl size field"))
    if _value(rec["direction"]) == "no_data" and size not in (None, 0):
        out.append(("payload_size", "a no-data command cannot carry bytes"))
    align = _value(rec["alignment"])
    if align is not None and align not in (1, 2, 4, 8):
        out.append(("alignment", "alignment is not 1, 2, 4 or 8"))
    fields = _value(rec["field_map"])
    if fields is not None:
        effective = size if rec["payload_size"]["status"] == "known" else (
            0 if rec["payload_size"]["status"] == "not_applicable" else None)
        if effective is not None and align in (1, 2, 4, 8):
            problem = validate_field_map(fields, effective, align)
            if problem:
                out.append(("field_map", problem))
    return out


def evaluate(matrix: Dict[str, Any]) -> Dict[str, Any]:
    missing: List[Dict[str, Any]] = []

    def add(scope: str, record: str, field: str, reason: Dict[str, Any]) -> None:
        missing.append({"scope": scope, "record": record, "field": field, "reason": reason})

    if matrix["schema"] != SCHEMA:
        add("audio_output", "matrix", "record", {"kind": "inconsistent", "detail": "schema"})
    for op in OPERATIONS:
        if not any(r["operation"] == op for r in matrix["interfaces"]):
            add("audio_output", f"operation:{op}", "record", {"kind": "no_record"})
    for rec in matrix["interfaces"]:
        for field in INTERFACE_FIELDS:
            reason = _field_reason(matrix, rec[field])
            if reason:
                add("audio_output", rec["id"], field, reason)
        for field, detail in _consistency(rec):
            add("audio_output", rec["id"], field, {"kind": "inconsistent", "detail": detail})
    for duty in DUTIES:
        if not any(r["duty"] == duty for r in matrix["radio"]):
            add("radio_coexistence", f"radio:{duty}", "record", {"kind": "no_record"})
    for rec in matrix["radio"]:
        for key, field in RADIO_FIELDS:
            reason = _field_reason(matrix, rec[key])
            if reason:
                add("radio_coexistence", rec["id"], field, reason)
    return {
        "offline_model_ok": all(m["reason"]["kind"] == "synthetic_anchor" for m in missing),
        "hardware_eligible": not missing,
        "missing": missing,
    }


# ---- scenario builders: constructed matrices for the unit-level cases (never evidence) ----


def _known(value: Any, anchor: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "known", "value": value, "anchor": copy.deepcopy(anchor)}


def artifact_anchor(offset: int = 0x10, section: str = ".text") -> Dict[str, Any]:
    return {"kind": "artifact", "sha256": FIXTURE_SHA, "section": section, "offset": offset, "symbol": "fixture_symbol"}


def synthetic_anchor() -> Dict[str, Any]:
    return {"kind": "synthetic_fixture", "label": "unit-test"}


def complete_matrix(anchor: Dict[str, Any]) -> Dict[str, Any]:
    interfaces = []
    for i, op in enumerate(OPERATIONS):
        nr = i + 1
        cmd = encode_ppc_ioctl(4, 0x7E, nr, 8)
        interfaces.append({
            "id": f"fixture.{op}", "operation": op, "device": "fixture-dsp",
            "interface": _known("ioctl", anchor), "selector": _known(nr, anchor), "full_command": _known(cmd, anchor),
            "direction": _known("write", anchor), "payload_size": _known(8, anchor),
            "endianness": _known("big", anchor), "alignment": _known(4, anchor),
            "field_map": _known([{"name": "a", "offset": 0, "width": 4, "kind": "unsigned"},
                                 {"name": "b", "offset": 4, "width": 4, "kind": "unsigned"}], anchor),
        })
    radio = [{"id": f"fixture.radio.{d}", "duty": d, "owner": _known("kernel_driver", anchor),
              "survives_daemon_replacement": _known(True, anchor),
              "audio_interference_bound_us": _known(250, anchor)} for d in DUTIES]
    return {"schema": SCHEMA, "artifacts": [{
        "sha256": FIXTURE_SHA, "size_bytes": 4096, "description": "unit-test double, not a real driver",
        "sections": [{"name": ".text", "size": 0x1000}, {"name": ".rodata", "size": 0x400}]}],
        "interfaces": interfaces, "radio": radio}


def unknown(blocker_id: str, needs: str) -> Dict[str, Any]:
    return {"status": "unknown", "blocker": {"id": blocker_id, "needs": needs}}


def record(matrix: Dict[str, Any], op: str) -> Dict[str, Any]:
    return next(r for r in matrix["interfaces"] if r["operation"] == op)
