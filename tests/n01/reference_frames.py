#!/usr/bin/env python3
"""Independent reference for the N01 authenticated stream framing contract (bead ffw-ey5).

This is a second implementation of docs/contracts/n01.md written against the contract, not
against the Rust source: it uses only the standard library (`hmac`, `hashlib`, `struct`), packs
the header with one big-endian `struct` format, and models the replay window with a plain set
instead of the Rust 64-bit bitmap. It produces the golden vectors that
crates/franken-stream/src/lib.rs replays, so a layout, MAC-coverage or window-semantics mistake
has to be made twice, in two different ways, to go unnoticed.

Every rejection vector carries a hand-written expected code; `decode` is then required to
reproduce it, so the reference is checked against intent and not against its own output.

    reference_frames.py --write [PATH]   regenerate the vector file
    reference_frames.py --check [PATH]   verify the committed file is byte-identical to a fresh
                                         generation and that every expectation holds (default)

Exit 0 only when everything holds. This offline tool proves nothing about the Rust code on its
own; the Rust half runs under the centralized RCH cargo test.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTORS = ROOT / "crates" / "franken-stream" / "tests" / "vectors" / "n01_wire_vectors.json"

MAGIC = b"FFWS"
VERSION = 1
HEADER = struct.Struct(">4sBBBBQQQQQQHBBHH")
HEADER_LEN = 64
TAG_LEN = 16
BYTES_PER_FRAME = 4
FRAMES_PER_BLOCK = 256
MAX_PAYLOAD = FRAMES_PER_BLOCK * BYTES_PER_FRAME
MIN_DATAGRAM = HEADER_LEN + TAG_LEN
MAX_DATAGRAM = HEADER_LEN + MAX_PAYLOAD + TAG_LEN
AUTH_CONTEXT = b"FFWS-v1-auth"
CRITICAL_MASK = 0xF0
MAX_TS_NS = 1 << 62
MAX_FEC_GROUP = 16
REPLAY_WINDOW = 64
MAX_FORWARD_GAP = 1024
KIND_WIRE = {"media": 1, "repair": 2}
KIND_NAME = {1: "media", 2: "repair"}
U64 = (1 << 64) - 1

assert HEADER.size == HEADER_LEN

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))

# Every code a datagram can be rejected with by the receive path.
RECEIVE_CODES = (
    "PACKET_TOO_SHORT",
    "DATAGRAM_TOO_LONG",
    "BAD_MAGIC",
    "UNSUPPORTED_VERSION",
    "PAYLOAD_TOO_LARGE",
    "TRUNCATED",
    "TRAILING_BYTES",
    "AUTH_FAILED",
    "UNKNOWN_PACKET_KIND",
    "UNKNOWN_CRITICAL_FLAGS",
    "UNKNOWN_FORMAT",
    "FRAME_COUNT_OUT_OF_RANGE",
    "FRAME_COUNT_MISMATCH",
    "MISALIGNED_START_FRAME",
    "INVALID_TIMESTAMPS",
    "INVALID_FEC_FIELDS",
    "INVALID_STREAM_ID",
    "WRONG_STREAM",
    "STALE_EPOCH",
    "FUTURE_EPOCH",
    "REPLAY_OR_DUPLICATE",
    "FUTURE_SEQUENCE",
)


def pattern(n: int, salt: int = 0) -> bytes:
    return bytes(((i * 7 + 3 + salt) % 251) for i in range(n))


def tag(key: bytes, header: bytes, payload: bytes) -> bytes:
    return hmac.new(key, AUTH_CONTEXT + header + payload, hashlib.sha256).digest()[:TAG_LEN]


def pack_header(
    *,
    stream_id: int,
    epoch: int,
    seq: int,
    start_frame: int,
    presentation: int,
    consume_by: int,
    frame_count: int,
    payload_len: int,
    magic: bytes = MAGIC,
    version: int = VERSION,
    kind: int = 1,
    flags: int = 0,
    fmt: int = 1,
    fec_group_id: int = 0,
    fec_index: int = 0,
    fec_group_size: int = 0,
) -> bytes:
    return HEADER.pack(
        magic, version, kind, flags, fmt, stream_id, epoch, seq, start_frame, presentation,
        consume_by, fec_group_id, fec_index, fec_group_size, frame_count, payload_len,
    )


def default_fields(**overrides) -> dict:
    fields = {
        "stream_id": 0xA11CE00000000001,
        "epoch": 7,
        "seq": 100,
        "kind": "media",
        "flags": 0,
        "start_frame": 25_600,
        "presentation_time_ns": 500_000_000,
        "consume_by_ns": 495_000_000,
        "fec_group_id": 25,
        "fec_index": 0,
        "fec_group_size": 0,
        "payload": pattern(MAX_PAYLOAD),
    }
    fields.update(overrides)
    return fields


def encode(fields: dict, key: bytes = KEY, **raw) -> bytes:
    """Build a datagram from `fields`. `raw` overrides individual raw header values (the names of
    `pack_header` arguments) so tests can forge a validly authenticated but malformed frame."""
    payload = fields["payload"]
    header_args = dict(
        stream_id=fields["stream_id"],
        epoch=fields["epoch"],
        seq=fields["seq"],
        start_frame=fields["start_frame"],
        presentation=fields["presentation_time_ns"],
        consume_by=fields["consume_by_ns"],
        frame_count=len(payload) // BYTES_PER_FRAME,
        payload_len=len(payload),
        kind=KIND_WIRE[fields["kind"]],
        flags=fields["flags"],
        fec_group_id=fields["fec_group_id"],
        fec_index=fields["fec_index"],
        fec_group_size=fields["fec_group_size"],
    )
    header_args.update(raw)
    header = pack_header(**header_args)
    return header + payload + tag(key, header, payload)


def decode(wire: bytes, key: bytes = KEY):
    """Return ("ACCEPT", fields) or (CODE, None), checking in the contract's order."""
    n = len(wire)
    if n < MIN_DATAGRAM:
        return "PACKET_TOO_SHORT", None
    if n > MAX_DATAGRAM:
        return "DATAGRAM_TOO_LONG", None
    (magic, version, kind, flags, fmt, stream_id, epoch, seq, start_frame, presentation,
     consume_by, fec_group_id, fec_index, fec_group_size, frame_count, payload_len) = HEADER.unpack(
        wire[:HEADER_LEN]
    )
    if magic != MAGIC:
        return "BAD_MAGIC", None
    if version != VERSION:
        return "UNSUPPORTED_VERSION", None
    if payload_len > MAX_PAYLOAD:
        return "PAYLOAD_TOO_LARGE", None
    expected = HEADER_LEN + payload_len + TAG_LEN
    if n < expected:
        return "TRUNCATED", None
    if n > expected:
        return "TRAILING_BYTES", None
    payload = wire[HEADER_LEN:HEADER_LEN + payload_len]
    if not hmac.compare_digest(wire[HEADER_LEN + payload_len:], tag(key, wire[:HEADER_LEN], payload)):
        return "AUTH_FAILED", None
    if kind not in KIND_NAME:
        return "UNKNOWN_PACKET_KIND", None
    if flags & CRITICAL_MASK:
        return "UNKNOWN_CRITICAL_FLAGS", None
    if fmt != 1:
        return "UNKNOWN_FORMAT", None
    if frame_count == 0 or frame_count > FRAMES_PER_BLOCK:
        return "FRAME_COUNT_OUT_OF_RANGE", None
    if payload_len != frame_count * BYTES_PER_FRAME:
        return "FRAME_COUNT_MISMATCH", None
    if start_frame % FRAMES_PER_BLOCK:
        return "MISALIGNED_START_FRAME", None
    if presentation > MAX_TS_NS or consume_by > presentation:
        return "INVALID_TIMESTAMPS", None
    if KIND_NAME[kind] == "media":
        if fec_group_size == 0:
            fec_ok = fec_index == 0
        else:
            fec_ok = fec_group_size <= MAX_FEC_GROUP and fec_index < fec_group_size
    else:
        fec_ok = 1 <= fec_group_size <= MAX_FEC_GROUP and fec_index < MAX_FEC_GROUP
    if not fec_ok:
        return "INVALID_FEC_FIELDS", None
    if stream_id == 0:
        return "INVALID_STREAM_ID", None
    return "ACCEPT", {
        "stream_id": stream_id,
        "epoch": epoch,
        "seq": seq,
        "kind": KIND_NAME[kind],
        "flags": flags,
        "start_frame": start_frame,
        "presentation_time_ns": presentation,
        "consume_by_ns": consume_by,
        "fec_group_id": fec_group_id,
        "fec_index": fec_index,
        "fec_group_size": fec_group_size,
        "payload": payload,
    }


class ReceiverModel:
    """Set-based model of the receive path's state: stream identity, epoch, replay window."""

    def __init__(self, key: bytes, stream_id: int, epoch: int):
        self.key = key
        self.bind(stream_id, epoch)

    def bind(self, stream_id: int, epoch: int) -> None:
        """Only a different identity opens a new sequence space (contract section 4). Binding the identity already held is not a
        restart: a repeated bind changes nothing, a bind naming a newer epoch is an epoch announcement, an older one is ignored."""
        if getattr(self, "stream_id", None) == stream_id:
            self.advance_epoch(epoch)
            return
        self.stream_id = stream_id
        self.epoch = epoch
        self._reset()

    def advance_epoch(self, epoch: int) -> None:
        if epoch > self.epoch:
            self.epoch = epoch
            self._reset()

    def _reset(self) -> None:
        self.origin = 0
        self.high = None
        self.seen = set()

    def accept(self, wire: bytes) -> str:
        code, fields = decode(wire, self.key)
        if code != "ACCEPT":
            return code
        if fields["stream_id"] != self.stream_id:
            return "WRONG_STREAM"
        if fields["epoch"] < self.epoch:
            return "STALE_EPOCH"
        if fields["epoch"] > self.epoch:
            return "FUTURE_EPOCH"
        seq = fields["seq"]
        if self.high is None:
            if seq < self.origin:
                return "REPLAY_OR_DUPLICATE"
            if seq - self.origin > MAX_FORWARD_GAP:
                return "FUTURE_SEQUENCE"
        elif seq > self.high:
            if seq - self.high > MAX_FORWARD_GAP:
                return "FUTURE_SEQUENCE"
        elif self.high - seq >= REPLAY_WINDOW or seq in self.seen:
            return "REPLAY_OR_DUPLICATE"
        self.seen.add(seq)
        self.high = seq if self.high is None else max(self.high, seq)
        return "OK"


class SplitMix64:
    def __init__(self, seed: int):
        self.state = seed & U64

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & U64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & U64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & U64
        return z ^ (z >> 31)

    def below(self, bound: int) -> int:
        return self.next() % bound


def fields_json(fields: dict) -> dict:
    out = {k: v for k, v in fields.items() if k != "payload"}
    out["payload_hex"] = fields["payload"].hex()
    return out


def build_vectors() -> list:
    vectors = []

    def accept(vid, name, fields):
        wire = encode(fields)
        vectors.append({"id": vid, "name": name, "expect": "ACCEPT",
                        "fields": fields_json(fields), "wire_hex": wire.hex()})

    def reject(vid, name, expect, wire, note):
        vectors.append({"id": vid, "name": name, "expect": expect, "note": note,
                        "wire_hex": wire.hex()})

    base = default_fields()
    base_wire = encode(base)
    partial = default_fields(seq=101, start_frame=512, payload=pattern(12, 5))
    partial_wire = encode(partial)

    accept("N01-GV-001", "media_full_block", base)
    accept("N01-GV-002", "media_partial_final_block", partial)
    accept("N01-GV-003", "repair_packet", default_fields(
        seq=104, kind="repair", fec_group_id=25, fec_index=0, fec_group_size=4))
    accept("N01-GV-004", "big_endian_field_probe", default_fields(
        stream_id=0x0102030405060708, epoch=0x1112131415161718, seq=0x2122232425262728,
        kind="repair", flags=0x05, start_frame=0x3132333435363700,
        presentation_time_ns=0x0102030405060708, consume_by_ns=0x0102030405060707,
        fec_group_id=0xABCD, fec_index=3, fec_group_size=4, payload=bytes([9, 8, 7, 6])))
    accept("N01-GV-005", "ignorable_flag_bits", default_fields(flags=0x0F, payload=pattern(8, 9)))
    accept("N01-GV-006", "maximum_field_values", default_fields(
        stream_id=U64, epoch=U64, seq=U64 - 1, start_frame=(U64 // 256) * 256,
        presentation_time_ns=MAX_TS_NS, consume_by_ns=MAX_TS_NS, fec_group_id=0xFFFF,
        fec_index=15, fec_group_size=16))
    accept("N01-GV-007", "minimum_field_values", default_fields(
        stream_id=1, epoch=0, seq=0, start_frame=0, presentation_time_ns=0, consume_by_ns=0,
        fec_group_id=0, payload=pattern(4, 1)))

    def flip(wire, index, mask=0x01):
        out = bytearray(wire)
        out[index] ^= mask
        return bytes(out)

    reject("N01-GV-101", "payload_bit_flipped", "AUTH_FAILED", flip(base_wire, HEADER_LEN + 10),
           "one payload bit changed after signing")
    reject("N01-GV-102", "tag_bit_flipped", "AUTH_FAILED", flip(base_wire, len(base_wire) - 1),
           "one tag bit changed")
    reject("N01-GV-103", "epoch_tampered", "AUTH_FAILED", flip(base_wire, 16 + 7),
           "epoch changed without re-signing")
    reject("N01-GV-104", "format_tampered", "AUTH_FAILED", flip(base_wire, 7, 0x03),
           "format byte changed without re-signing")
    reject("N01-GV-105", "stream_id_tampered", "AUTH_FAILED", flip(base_wire, 8 + 7),
           "stream identity changed without re-signing")
    reject("N01-GV-106", "timing_tampered", "AUTH_FAILED", flip(base_wire, 40 + 6),
           "presentation time changed without re-signing")
    reject("N01-GV-107", "signed_under_another_key", "AUTH_FAILED", encode(base, OTHER_KEY),
           "valid frame signed with a different key")
    reject("N01-GV-108", "truncated_by_one_byte", "TRUNCATED", base_wire[:-1],
           "last tag byte missing")
    reject("N01-GV-109", "truncated_inside_header", "PACKET_TOO_SHORT", base_wire[:50],
           "datagram ends inside the header")
    reject("N01-GV-110", "truncated_below_minimum", "PACKET_TOO_SHORT", base_wire[:HEADER_LEN + TAG_LEN - 1],
           "one byte under header plus tag")
    reject("N01-GV-111", "trailing_byte", "TRAILING_BYTES", partial_wire + b"\x00",
           "one byte beyond the declared length")
    reject("N01-GV-112", "datagram_over_maximum", "DATAGRAM_TOO_LONG", base_wire + b"\x00" * 4,
           "longer than the largest legal datagram")
    reject("N01-GV-113", "declared_payload_over_maximum", "PAYLOAD_TOO_LARGE",
           partial_wire[:60] + struct.pack(">HH", 3, MAX_PAYLOAD + 1) + partial_wire[HEADER_LEN:],
           "header declares 1025 payload bytes; rejected on the declaration, before any MAC")
    reject("N01-GV-114", "wrong_version_authenticated", "UNSUPPORTED_VERSION",
           encode(base, version=2), "version 2, correctly signed: still not interpreted")
    reject("N01-GV-115", "bad_magic", "BAD_MAGIC", encode(base, magic=b"FFWX"), "magic differs")
    reject("N01-GV-116", "unknown_critical_flag", "UNKNOWN_CRITICAL_FLAGS",
           encode(base, flags=0x80), "critical flag bit this version does not define")
    reject("N01-GV-117", "unknown_packet_kind", "UNKNOWN_PACKET_KIND", encode(base, kind=3),
           "kind 3 is undefined")
    reject("N01-GV-118", "unknown_format", "UNKNOWN_FORMAT", encode(base, fmt=2),
           "format 2 is undefined")
    reject("N01-GV-119", "frame_count_zero", "FRAME_COUNT_OUT_OF_RANGE",
           encode(default_fields(payload=b""), frame_count=0, payload_len=0), "empty frame")
    reject("N01-GV-120", "frame_count_over_block", "FRAME_COUNT_OUT_OF_RANGE",
           encode(base, frame_count=257), "257 frames exceeds one block")
    reject("N01-GV-121", "frame_count_disagrees_with_payload", "FRAME_COUNT_MISMATCH",
           encode(base, frame_count=255), "255 frames declared, 1024 payload bytes")
    reject("N01-GV-122", "payload_not_whole_frames", "FRAME_COUNT_MISMATCH",
           encode(default_fields(payload=pattern(6))), "6 bytes is one and a half frames")
    reject("N01-GV-123", "misaligned_start_frame", "MISALIGNED_START_FRAME",
           encode(default_fields(start_frame=25_601)), "start frame off the 256-frame grid")
    reject("N01-GV-124", "consume_by_after_presentation", "INVALID_TIMESTAMPS",
           encode(default_fields(consume_by_ns=500_000_001)), "deadline later than presentation")
    reject("N01-GV-125", "presentation_over_limit", "INVALID_TIMESTAMPS",
           encode(default_fields(presentation_time_ns=MAX_TS_NS + 1)), "beyond 2^62 ns")
    reject("N01-GV-126", "fec_index_without_group", "INVALID_FEC_FIELDS",
           encode(default_fields(fec_index=4, fec_group_size=0)), "index set but no coding group")
    reject("N01-GV-127", "repair_without_group", "INVALID_FEC_FIELDS",
           encode(default_fields(kind="repair", fec_group_size=0)), "repair names no coding group")
    reject("N01-GV-128", "fec_index_outside_group", "INVALID_FEC_FIELDS",
           encode(default_fields(fec_index=4, fec_group_size=4)), "index equals group size")
    reject("N01-GV-129", "fec_group_over_maximum", "INVALID_FEC_FIELDS",
           encode(default_fields(fec_index=0, fec_group_size=17)), "17 exceeds the 16 maximum")
    reject("N01-GV-130", "zero_stream_identity", "INVALID_STREAM_ID",
           encode(default_fields(stream_id=0)), "stream identity 0 is reserved as unset")
    return vectors


def scenario_frame(stream_id, epoch, seq, key=KEY, payload=None):
    fields = default_fields(
        stream_id=stream_id, epoch=epoch, seq=seq, start_frame=seq * FRAMES_PER_BLOCK,
        presentation_time_ns=1_000_000_000 + seq * 5_333_333,
        consume_by_ns=995_000_000 + seq * 5_333_333, fec_group_id=0,
        payload=payload if payload is not None else pattern(BYTES_PER_FRAME, seq & 0xFF),
    )
    return encode(fields, key)


S1 = 0xFEED000000000042
S2 = 0xFEED000000000099
FOREIGN = 0xBEEF000000000001


def build_ordering_scenario() -> dict:
    steps = []
    model = ReceiverModel(KEY, S1, 7)

    def dg(wire, note):
        steps.append({"op": "datagram", "note": note, "wire_hex": wire.hex(), "expect": model.accept(wire)})

    def frame(seq, epoch=7, stream=S1):
        return scenario_frame(stream, epoch, seq)

    dg(frame(0), "first packet")
    dg(frame(1), "in order")
    dg(frame(1), "duplicate")
    dg(frame(3), "gap of one")
    dg(frame(2), "reordered into the gap")
    dg(frame(2), "duplicate of the reordered packet")
    dg(frame(3 + MAX_FORWARD_GAP + 1), "one beyond the future window")
    dg(frame(3 + MAX_FORWARD_GAP), "exactly at the future window limit")
    dg(frame(4), "now more than 64 behind the highest")
    bad = bytearray(frame(1028))
    bad[-1] ^= 0x01
    dg(bytes(bad), "tampered copy of the next packet")
    dg(frame(1028), "the genuine copy still gets that sequence number")
    dg(frame(0, epoch=6), "stale epoch")
    dg(frame(0, epoch=8), "future epoch is not adopted from media")
    dg(frame(0, stream=FOREIGN), "different stream identity")
    steps.append({"op": "advance_epoch", "epoch": 8})
    model.advance_epoch(8)
    dg(frame(0, epoch=8), "first packet of the announced epoch")
    dg(frame(2000, epoch=7), "old epoch after the control channel moved on")
    steps.append({"op": "bind", "stream_id": S2, "epoch": 8})
    model.bind(S2, 8)
    dg(frame(5, epoch=8), "previous stream after a restart")
    dg(frame(0, epoch=8, stream=S2), "sequence 0 reused by the new stream")
    dg(scenario_frame(S2, 8, 1)[:-3], "truncated copy")
    dg(frame(1, epoch=8, stream=S2), "genuine copy afterwards")
    return {
        "id": "N01-SC-001", "name": "ordering_fencing_restart",
        "stream_id": S1, "epoch": 7, "steps": steps,
        "expect_accepted": sum(1 for s in steps if s.get("expect") == "OK"),
    }


def build_random_scenario(seed: int = 0x4E3031, length: int = 400) -> dict:
    rng = SplitMix64(seed)
    stream, epoch = S1, 3
    model = ReceiverModel(KEY, stream, epoch)
    steps = []
    next_seq = 0
    sent: list = []
    skipped: list = []

    def dg(wire, note):
        steps.append({"op": "datagram", "note": note, "wire_hex": wire.hex(), "expect": model.accept(wire)})

    for step in range(length):
        if step == 250:
            stream = S2
            steps.append({"op": "bind", "stream_id": stream, "epoch": epoch})
            model.bind(stream, epoch)
            next_seq, sent, skipped = 0, [], []
            continue
        r = rng.below(20)
        if r <= 8:
            dg(scenario_frame(stream, epoch, next_seq), "in order")
            sent.append(next_seq)
            next_seq += 1
        elif r <= 10:
            seq = sent[rng.below(len(sent))] if sent else next_seq
            dg(scenario_frame(stream, epoch, seq), "duplicate or replay")
        elif r == 11:
            gap = 1 + rng.below(3)
            skipped.extend(range(next_seq, next_seq + gap))
            seq = next_seq + gap
            dg(scenario_frame(stream, epoch, seq), "jump ahead leaving a gap")
            sent.append(seq)
            next_seq = seq + 1
        elif r == 12:
            if skipped:
                seq = skipped.pop(rng.below(len(skipped)))
                dg(scenario_frame(stream, epoch, seq), "late arrival of a skipped packet")
            else:
                dg(scenario_frame(stream, epoch, next_seq), "in order")
                sent.append(next_seq)
                next_seq += 1
        elif r == 13:
            high = model.high if model.high is not None else 0
            seq = high + MAX_FORWARD_GAP + 1 + rng.below(5)
            dg(scenario_frame(stream, epoch, seq), "beyond the future window")
        elif r == 14:
            dg(scenario_frame(stream, epoch - 1, rng.below(50)), "stale epoch")
        elif r == 15:
            dg(scenario_frame(stream, epoch + 1, rng.below(50)), "future epoch")
        elif r == 16:
            dg(scenario_frame(FOREIGN, epoch, rng.below(50)), "foreign stream")
        elif r == 17:
            bad = bytearray(scenario_frame(stream, epoch, next_seq))
            bad[-1 - rng.below(TAG_LEN)] ^= 1 << rng.below(8)
            dg(bytes(bad), "tampered tag on the next sequence number")
        elif r == 18:
            wire = scenario_frame(stream, epoch, next_seq)
            dg(wire[: len(wire) - 1 - rng.below(10)], "truncated")
        elif r == 19:
            junk = bytes(rng.next() & 0xFF for _ in range(rng.below(121)))
            dg(junk, "garbage")
    # Control-channel epoch advance, then confirm the new epoch carries traffic from sequence 0.
    steps.append({"op": "advance_epoch", "epoch": epoch + 1})
    model.advance_epoch(epoch + 1)
    epoch += 1
    for seq in range(3):
        dg(scenario_frame(stream, epoch, seq), "first packets of the advanced epoch")
    return {
        "id": "N01-SC-002", "name": "seeded_random_walk", "seed": seed,
        "stream_id": S1, "epoch": 3, "steps": steps,
        "expect_accepted": sum(1 for s in steps if s.get("expect") == "OK"),
    }


def build_document() -> dict:
    return {
        "schema": "ffw.n01.wire_vectors.v1",
        "generator": "tests/n01/reference_frames.py",
        "contract": "docs/contracts/n01.md",
        "note": "Public synthetic test material: the key and every identity below are fixed test "
                "values, not secrets and not site data.",
        "key_hex": KEY.hex(),
        "constants": {
            "header_len": HEADER_LEN, "tag_len": TAG_LEN, "max_payload": MAX_PAYLOAD,
            "max_datagram": MAX_DATAGRAM, "replay_window": REPLAY_WINDOW,
            "max_forward_seq_gap": MAX_FORWARD_GAP, "max_timestamp_ns": MAX_TS_NS,
            "auth_context": AUTH_CONTEXT.decode("ascii"),
        },
        "vectors": build_vectors(),
        "scenarios": [build_ordering_scenario(), build_random_scenario()],
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1) + "\n"


def self_verify(doc: dict) -> list:
    """Return a list of failure strings; empty when every recorded expectation holds."""
    failures = []
    for v in doc["vectors"]:
        code, fields = decode(bytes.fromhex(v["wire_hex"]))
        if code != v["expect"]:
            failures.append(f'{v["id"]} {v["name"]}: expected {v["expect"]}, decoder said {code}')
        elif code == "ACCEPT":
            if fields_json(fields) != v["fields"]:
                failures.append(f'{v["id"]}: decoded fields differ from the recorded fields')
            if encode(fields) != bytes.fromhex(v["wire_hex"]):
                failures.append(f'{v["id"]}: re-encoding the decoded fields changed the bytes')
    for sc in doc["scenarios"]:
        model = ReceiverModel(KEY, sc["stream_id"], sc["epoch"])
        accepted = 0
        for n, step in enumerate(sc["steps"]):
            if step["op"] == "advance_epoch":
                model.advance_epoch(step["epoch"])
            elif step["op"] == "bind":
                model.bind(step["stream_id"], step["epoch"])
            else:
                got = model.accept(bytes.fromhex(step["wire_hex"]))
                accepted += got == "OK"
                if got != step["expect"]:
                    failures.append(f'{sc["id"]} step {n}: expected {step["expect"]}, model said {got}')
        if accepted != sc["expect_accepted"]:
            failures.append(f'{sc["id"]}: accepted {accepted}, recorded {sc["expect_accepted"]}')
    seen_codes = {v["expect"] for v in doc["vectors"]}
    seen_codes |= {s["expect"] for sc in doc["scenarios"] for s in sc["steps"] if "expect" in s}
    missing = [c for c in RECEIVE_CODES if c not in seen_codes]
    if missing:
        failures.append("no vector or scenario step exercises: " + ", ".join(missing))
    return failures


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", nargs="?", const=str(DEFAULT_VECTORS), metavar="PATH")
    mode.add_argument("--check", nargs="?", const=str(DEFAULT_VECTORS), metavar="PATH")
    args = parser.parse_args(argv)
    doc = build_document()
    failures = self_verify(doc)
    if failures:
        print("reference self-verification FAILED:", *failures, sep="\n  ", file=sys.stderr)
        return 1
    text = render(doc)
    if args.write is not None:
        path = Path(args.write)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path} ({len(doc['vectors'])} vectors, "
              f"{sum(len(s['steps']) for s in doc['scenarios'])} scenario steps)")
        return 0
    path = Path(args.check or DEFAULT_VECTORS)
    if not path.is_file():
        print(f"missing vector file {path}; run with --write", file=sys.stderr)
        return 1
    if path.read_text(encoding="utf-8") != text:
        print(f"{path} differs from a fresh generation; regenerate with --write and review the diff",
              file=sys.stderr)
        return 1
    print(f"ok: {path} matches a fresh generation; {len(doc['vectors'])} vectors and "
          f"{sum(len(s['steps']) for s in doc['scenarios'])} scenario steps hold their expectations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
