"""Hand-built media images for U01: torn tails, flipped bits, hostile lengths, replayed frames, a legacy-schema image,
stale segments. Each case says what recovery must return. The expected states are taken from a scripted run (the state
after step N), never from the scanner under test."""
from __future__ import annotations

import struct
import zlib
from typing import Any, Dict, List, Tuple

import reference as ref
import scenarios as sc

LIM = ref.TINY


def _run(script, upto=None):
    media = ref.Media(LIM.segment_bytes)
    j, _rec = ref.Journal.open(media, LIM)
    states = [ref.state_hex(j.state)]
    frames = [(j.write_off)]  # end offset of segment 0 after the format and after every appended frame
    for step in script[:upto]:
        try:
            getattr(j, step[0])(*step[1:])
        except ref.JournalError:
            pass
        states.append(ref.state_hex(j.state))
        frames.append(j.write_off)
    return media, j, states, frames


def _segment(version: int, gen: int, first_seq: int, frames: List[Tuple[int, int, bytes]]) -> bytes:
    """A segment image: header, then (kind, seq, payload) frames, padded with 0xFF."""
    out = ref.encode_segment_header(version, gen, first_seq)
    for kind, seq, payload in frames:
        out += ref.encode_frame(kind, seq, payload)
    return out + bytes([0xFF]) * (LIM.segment_bytes - len(out))


def _image(seg0: bytes, seg1: bytes) -> bytes:
    return seg0 + seg1


def build() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    script = [("put", ref.NS_CALIBRATION, sc.b("board-a"), sc.b("cal-1")),
              ("install", sc.b("peer-1"), 1, sc.b("secret-1")),
              ("put", ref.NS_RECORDS, sc.b("voter"), sc.b("rec-1"))]
    media, j, states, ends = _run(script)
    good = bytes(media.media)
    seg = LIM.segment_bytes
    # states[0] = formatted (empty); states[i] = after script step i; ends[i] = end offset of the log after step i.
    # frame i (1-based) occupies [ends[i-1], ends[i]) of segment 0.

    def case(cid, title, image, expect):
        cases.append({"id": cid, "title": title, "image_hex": bytes(image).hex(), "expect": expect})

    case("U01-I-001", "a blank medium is formatted, not an error", bytes([0xFF]) * (2 * seg),
         {"source": "blank", "state_hex": states[0]})
    case("U01-I-002", "a clean log recovers its last committed state", good,
         {"source": "segment", "state_hex": states[3], "tail_dirty": False})

    torn = bytearray(good)
    torn[ends[3]:ends[3] + 7] = b"\xa5\x01\x00\x20\x00\x00\x00"       # the start of a frame that never finished
    case("U01-I-003", "a torn tail is ignored and the log is rewritten clean", torn,
         {"source": "segment", "state_hex": states[3], "tail_dirty": True, "compacted": True})

    flipped = bytearray(good)
    flipped[ends[1] + ref.FRAME_HEADER + 3] ^= 0x01                    # one bit inside the payload of frame 2
    case("U01-I-004", "a flipped payload bit stops the scan before that frame and everything after it", flipped,
         {"source": "segment", "state_hex": states[1], "tail_dirty": True, "compacted": True})

    hostile = bytearray(good)
    hostile[ends[1] + 2:ends[1] + 4] = b"\xff\xff"                     # a length no segment can hold
    case("U01-I-005", "a hostile frame length is rejected before anything is read or allocated", hostile,
         {"source": "segment", "state_hex": states[1], "tail_dirty": True, "compacted": True})

    f1 = good[ends[0]:ends[1]]
    f2 = good[ends[1]:ends[2]]
    replay = bytearray(good[:ends[2]]) + f1                            # a valid frame with a stale sequence number
    replay += bytes([0xFF]) * (seg - len(replay))
    case("U01-I-006", "a replayed older frame (valid checksum, wrong sequence) is not applied", replay + bytes([0xFF]) * seg,
         {"source": "segment", "state_hex": states[2], "tail_dirty": True, "compacted": True})

    garbage = bytes([0x5A]) * (2 * seg)
    case("U01-I-007", "two unreadable segments: fail closed, report unrecoverable, start empty", garbage,
         {"source": "unrecoverable", "state_hex": states[0]})

    header_only = ref.encode_segment_header(1, 1, 1)
    case("U01-I-008", "a header whose first frame never arrived is not a state",
         header_only + bytes([0xFF]) * (seg - len(header_only)) + bytes([0xFF]) * seg,
         {"source": "unrecoverable", "state_hex": states[0]})

    older = _segment(1, 1, 1, [(ref.KIND_SNAPSHOT, 1, ref.canonical(ref.empty_state()))])
    snap_new = ref.canonical(_state_of(states[3]))
    newer = _segment(1, 2, 2, [(ref.KIND_SNAPSHOT, 2, snap_new)])
    case("U01-I-009", "two valid segments: the higher generation wins and the stale one is retired", older + newer,
         {"source": "segment", "state_hex": states[3], "gen": 2, "retired_stale": True})

    torn_new = bytearray(newer)
    torn_new[ref.SEG_HEADER + ref.FRAME_HEADER + 4] ^= 0x40            # the new segment's snapshot was torn
    case("U01-I-010", "a torn compaction falls back to the still-valid old segment",
         _segment(1, 1, 1, [(ref.KIND_SNAPSHOT, 1, ref.canonical(_state_of(states[2])))]) + bytes(torn_new),
         {"source": "segment", "state_hex": states[2], "gen": 1, "retired_stale": False})

    future = ref.encode_segment_header(2, 5, 1)
    case("U01-I-011", "a newer schema than this code knows is refused, not formatted over",
         _segment(1, 4, 1, [(ref.KIND_SNAPSHOT, 1, ref.canonical(_state_of(states[1])))])
         + future + bytes([0xFF]) * (seg - len(future)),
         {"error": "unsupported_version"})

    legacy_payload = (struct.pack(">H", 2)
                      + struct.pack(">BBB", ref.T_PUT, ref.NS_CALIBRATION, 7) + b"board-a" + struct.pack(">H", 5) + b"cal-1"
                      + struct.pack(">BB", ref.T_INSTALL, 6) + b"peer-1" + struct.pack(">H", 8) + b"secret-1")
    expect_state = ref.empty_state()
    expect_state[ref.NS_CALIBRATION][b"board-a"] = b"cal-1"
    expect_state[ref.NS_CREDENTIALS][b"peer-1"] = ("live", 1, b"secret-1")
    case("U01-I-012", "a legacy schema-0 image is read (credentials get version 1) and rewritten as schema 1",
         _segment(0, 1, 1, [(ref.KIND_SNAPSHOT, 1, legacy_payload)]) + bytes([0xFF]) * seg,
         {"source": "segment", "state_hex": ref.state_hex(expect_state), "migrated_from": 0, "compacted": True})

    bad_hdr = bytearray(older)
    bad_hdr[7] ^= 0x01                                                  # the generation byte; the header checksum no longer holds
    case("U01-I-013", "a header with a bad checksum is not a segment", bytes(bad_hdr) + bytes([0xFF]) * seg,
         {"source": "unrecoverable", "state_hex": states[0]})

    first_txn = _segment(1, 1, 1, [(ref.KIND_TXN, 1, ref.encode_ops([]))])
    case("U01-I-014", "a segment whose first frame is a transaction, not a snapshot, is not a segment",
         first_txn + bytes([0xFF]) * seg, {"source": "unrecoverable", "state_hex": states[0]})

    retired = bytearray(older)
    retired[0:2] = b"\x00\x00"
    case("U01-I-015", "a retired segment (magic cleared) is ignored", bytes(retired) + newer,
         {"source": "segment", "state_hex": states[3], "gen": 2, "retired_stale": False})

    # the credential that was revoked must not come back when the current segment is damaged after the retire
    media2 = ref.Media(LIM.segment_bytes)
    j2, _ = ref.Journal.open(media2, LIM)
    for step in sc.churn(rounds=40)[:3]:
        getattr(j2, step[0])(*step[1:])
    for i in range(40):
        j2.stage_setting(b"vol", f"{i:02d}".encode())
        j2.flush_settings(100 * (i + 1))
        if j2.compactions >= 1:
            break
    j2.put(ref.NS_CALIBRATION, b"board-a", b"cal-x")                    # the next commit performs the deferred retire
    img = bytearray(media2.media)
    cur = j2.active * seg
    img[cur + 4] ^= 0xFF                                                 # damage the current segment's header
    case("U01-I-016", "the current segment is damaged after the stale one was retired: no rollback to a state before the revocation",
         bytes(img), {"source": "unrecoverable", "state_hex": states[0]})
    return cases


def _state_of(hex_text: str) -> Dict[str, Any]:
    """Decode canonical state hex back into a state (used to build images from scripted states)."""
    ops = ref.decode_ops(LIM, bytes.fromhex(hex_text), ref.FORMAT_VERSION, True)
    state = ref.empty_state()
    for op in ops:
        ref.apply_op(LIM, state, op, snapshot=True)
    return state
