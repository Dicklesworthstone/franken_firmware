#!/usr/bin/env python3
"""Independent reference for the N01 compatibility negotiation (bead ffw-ey5, fresh-eyes AC).

A second implementation of the Offer/Answer exchange in docs/contracts/n01.md section 9, written
against the contract: stdlib `hmac`/`hashlib`/`struct`, one big-endian `struct` format for the
100-byte body, and a plain dict/int model of the selection rule. It produces
crates/franken-stream/tests/vectors/n01_negotiation_vectors.json, which the Rust tests replay
byte for byte (offer, answer, transcript digest and derived media key) and against which they
check every rejection code.

Every rejection vector carries a hand-written expected code and the model must reproduce it.

    reference_negotiation.py --write [PATH]   regenerate the vector file
    reference_negotiation.py --check [PATH]   verify the committed file matches a fresh generation
                                              and that every expectation holds (default)

This tool proves nothing about the Rust code on its own; the Rust half runs under the centralized
RCH cargo test.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_frames as rf  # noqa: E402

DEFAULT_VECTORS = rf.ROOT / "crates" / "franken-stream" / "tests" / "vectors" / "n01_negotiation_vectors.json"

HELLO_MAGIC = b"FFWN"
HELLO_VERSION = 1
HELLO = struct.Struct(">4sBBBBBBHIIQQQ16sBBHI32s")
BODY_LEN = 100
TAG_LEN = 16
DATAGRAM_LEN = BODY_LEN + TAG_LEN
HELLO_AUTH_CONTEXT = b"FFWS-v1-hello"
TRANSCRIPT_CONTEXT = b"FFWS-v1-transcript"
SESSION_KEY_CONTEXT = b"FFWS-v1-session-key"
KIND_OFFER, KIND_ANSWER = 1, 2
FEATURE_XOR = 1 << 0
FEATURE_PARTIAL = 1 << 1
KNOWN_FEATURES = FEATURE_XOR | FEATURE_PARTIAL
FORMAT_PCM = 1 << 0
KNOWN_FORMATS = FORMAT_PCM
THIS_WIRE_VERSION = rf.VERSION
U32 = 0xFFFFFFFF

assert HELLO.size == BODY_LEN

NEGOTIATION_CODES = (
    "HELLO_LENGTH",
    "HELLO_BAD_MAGIC",
    "HELLO_UNSUPPORTED_VERSION",
    "HELLO_AUTH_FAILED",
    "UNKNOWN_HELLO_KIND",
    "UNKNOWN_CRITICAL_HELLO_FLAGS",
    "INVALID_CAPABILITIES",
    "INVALID_PEER_IDENTITY",
    "INVALID_NONCE",
    "MALFORMED_HELLO",
    "NO_COMMON_VERSION",
    "MANDATORY_FEATURE_MISSING",
    "NO_COMMON_FORMAT",
    "LIMITS_INCOMPATIBLE",
    "STALE_OFFER_EPOCH",
    "WRONG_HELLO_KIND",
    "STREAM_MISMATCH",
    "EPOCH_MISMATCH",
    "REFLECTED_HELLO",
    "OFFER_DIGEST_MISMATCH",
    "DOWNGRADE_DETECTED",
    "SELECTION_MISMATCH",
)
# Reachable only with firmware claims this build refuses to make (wire version above 1, a second
# format, a payload limit below one block); the Rust unit tests cover them with stand-in firmware.
NOT_VECTORED = {
    "NO_COMMON_VERSION",
    "NO_COMMON_FORMAT",
    "LIMITS_INCOMPATIBLE",
    "DOWNGRADE_DETECTED",
}

KEY = rf.KEY
SENDER_PEER = 0xAA00000000000001
RECEIVER_PEER = 0xBB00000000000002
STREAM = 0x00C0FFEE00000001
EPOCH = 7


def caps(wire_min=1, wire_max=1, formats=FORMAT_PCM, max_payload=1024, mandatory=0, optional=KNOWN_FEATURES):
    return {
        "wire_min": wire_min, "wire_max": wire_max, "formats": formats,
        "max_payload_bytes": max_payload, "mandatory_features": mandatory,
        "optional_features": optional,
    }


BASELINE = caps()
OLD_FIRMWARE = caps(optional=0)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hello_tag(psk: bytes, body: bytes) -> bytes:
    return hmac.new(psk, HELLO_AUTH_CONTEXT + body, hashlib.sha256).digest()[:TAG_LEN]


def build(psk: bytes, f: dict) -> bytes:
    sel = f["selection"]
    body = HELLO.pack(
        f.get("magic", HELLO_MAGIC), f.get("msg_version", HELLO_VERSION), f["kind"], f["flags"],
        f["caps"]["wire_min"], f["caps"]["wire_max"], f["caps"]["formats"],
        f["caps"]["max_payload_bytes"], f["caps"]["mandatory_features"],
        f["caps"]["optional_features"], f["peer"], f["stream"], f["epoch"], f["nonce"],
        sel["wire_version"], sel["format"], sel["max_payload_bytes"], sel["features"], f["digest"],
    )
    return body + hello_tag(psk, body)


ZERO_SELECTION = {"wire_version": 0, "format": 0, "max_payload_bytes": 0, "features": 0}


def offer_fields(sender_caps, peer=SENDER_PEER, stream=STREAM, epoch=EPOCH, nonce=bytes(range(0x10, 0x20))):
    return {"kind": KIND_OFFER, "flags": 0, "caps": sender_caps, "peer": peer, "stream": stream,
            "epoch": epoch, "nonce": nonce, "selection": dict(ZERO_SELECTION), "digest": bytes(32)}


def fields_of(wire: bytes) -> dict:
    (magic, msg_version, kind, flags, wmin, wmax, formats, max_payload, mandatory, optional,
     peer, stream, epoch, nonce, sv, sf, smp, sfe, digest) = HELLO.unpack(wire[:BODY_LEN])
    return {
        "magic": magic, "msg_version": msg_version, "kind": kind, "flags": flags,
        "caps": {"wire_min": wmin, "wire_max": wmax, "formats": formats, "max_payload_bytes": max_payload,
                 "mandatory_features": mandatory, "optional_features": optional},
        "peer": peer, "stream": stream, "epoch": epoch, "nonce": nonce,
        "selection": {"wire_version": sv, "format": sf, "max_payload_bytes": smp, "features": sfe},
        "digest": digest,
    }


def supported(c) -> int:
    return c["mandatory_features"] | c["optional_features"]


def caps_valid(c) -> bool:
    return (c["wire_min"] >= 1 and c["wire_min"] <= c["wire_max"] and c["formats"] != 0
            and c["max_payload_bytes"] >= 4 and c["max_payload_bytes"] % 4 == 0
            and c["mandatory_features"] & c["optional_features"] == 0)


def caps_valid_local(c) -> bool:
    return (caps_valid(c) and c["wire_max"] <= THIS_WIRE_VERSION
            and supported(c) & ~KNOWN_FEATURES & U32 == 0 and c["formats"] & ~KNOWN_FORMATS & 0xFF == 0
            and c["max_payload_bytes"] <= rf.MAX_PAYLOAD)


def select(a, b):
    if not (caps_valid(a) and caps_valid(b)):
        return "INVALID_CAPABILITIES", None
    low, high = max(a["wire_min"], b["wire_min"]), min(a["wire_max"], b["wire_max"])
    if low > high:
        return "NO_COMMON_VERSION", None
    missing = (a["mandatory_features"] & ~supported(b) & U32) | (b["mandatory_features"] & ~supported(a) & U32)
    if missing:
        return "MANDATORY_FEATURE_MISSING", None
    common = a["formats"] & b["formats"]
    if not common:
        return "NO_COMMON_FORMAT", None
    if min(a["max_payload_bytes"], b["max_payload_bytes"]) < rf.MAX_PAYLOAD:
        return "LIMITS_INCOMPATIBLE", None
    return "OK", {"wire_version": high, "format": common & -common,
                  "max_payload_bytes": rf.MAX_PAYLOAD, "features": supported(a) & supported(b)}


def parse(wire: bytes, psk: bytes):
    """Return (code, fields): checks in the contract's order."""
    if len(wire) != DATAGRAM_LEN:
        return "HELLO_LENGTH", None
    if wire[:4] != HELLO_MAGIC:
        return "HELLO_BAD_MAGIC", None
    if wire[4] != HELLO_VERSION:
        return "HELLO_UNSUPPORTED_VERSION", None
    if not hmac.compare_digest(wire[BODY_LEN:], hello_tag(psk, wire[:BODY_LEN])):
        return "HELLO_AUTH_FAILED", None
    f = fields_of(wire)
    if f["kind"] not in (KIND_OFFER, KIND_ANSWER):
        return "UNKNOWN_HELLO_KIND", None
    if f["flags"] & rf.CRITICAL_MASK:
        return "UNKNOWN_CRITICAL_HELLO_FLAGS", None
    if not caps_valid(f["caps"]):
        return "INVALID_CAPABILITIES", None
    if f["stream"] == 0 or f["peer"] == 0:
        return "INVALID_PEER_IDENTITY", None
    if f["nonce"] == bytes(16):
        return "INVALID_NONCE", None
    sel = f["selection"]
    if f["kind"] == KIND_OFFER:
        if sel != ZERO_SELECTION or f["digest"] != bytes(32):
            return "MALFORMED_HELLO", None
    else:
        well_formed = (sel["wire_version"] >= 1 and bin(sel["format"]).count("1") == 1
                       and sel["max_payload_bytes"] >= 4 and sel["max_payload_bytes"] % 4 == 0)
        if not well_formed:
            return "MALFORMED_HELLO", None
    return "OK", f


def derive(psk: bytes, offer_wire: bytes, answer_wire: bytes):
    transcript = sha256(TRANSCRIPT_CONTEXT + offer_wire + answer_wire)
    return transcript, hmac.new(psk, SESSION_KEY_CONTEXT + transcript, hashlib.sha256).digest()


def make_offer(psk, sender_caps, peer=SENDER_PEER, stream=STREAM, epoch=EPOCH, nonce=bytes(range(0x10, 0x20)),
               enforce_local=True):
    """`enforce_local=False` stands in for firmware that claims what this build does not implement."""
    if not (caps_valid_local(sender_caps) if enforce_local else caps_valid(sender_caps)):
        return "INVALID_CAPABILITIES", None
    if peer == 0:
        return "INVALID_PEER_IDENTITY", None
    if nonce == bytes(16):
        return "INVALID_NONCE", None
    return "OK", build(psk, offer_fields(sender_caps, peer, stream, epoch, nonce))


def respond(psk, local_caps, peer, min_epoch, nonce, offer_wire, enforce_local=True):
    """Return (code, (answer_wire, selection, transcript, key))."""
    if not (caps_valid_local(local_caps) if enforce_local else caps_valid(local_caps)):
        return "INVALID_CAPABILITIES", None
    if peer == 0:
        return "INVALID_PEER_IDENTITY", None
    if nonce == bytes(16):
        return "INVALID_NONCE", None
    code, offer = parse(offer_wire, psk)
    if code != "OK":
        return code, None
    if offer["kind"] != KIND_OFFER:
        return "WRONG_HELLO_KIND", None
    if offer["epoch"] < min_epoch:
        return "STALE_OFFER_EPOCH", None
    if offer["peer"] == peer or offer["nonce"] == nonce:
        return "REFLECTED_HELLO", None
    code, selection = select(offer["caps"], local_caps)
    if code != "OK":
        return code, None
    answer = {"kind": KIND_ANSWER, "flags": 0, "caps": local_caps, "peer": peer, "stream": offer["stream"],
              "epoch": offer["epoch"], "nonce": nonce, "selection": selection, "digest": sha256(offer_wire)}
    answer_wire = build(psk, answer)
    transcript, key = derive(psk, offer_wire, answer_wire)
    return "OK", (answer_wire, selection, transcript, key)


def finish(psk, offer_wire, answer_wire):
    """The initiator's checks on an answer to `offer_wire`. Return (code, (selection, transcript, key))."""
    offer = fields_of(offer_wire)
    code, answer = parse(answer_wire, psk)
    if code != "OK":
        return code, None
    if answer["kind"] != KIND_ANSWER:
        return "WRONG_HELLO_KIND", None
    if answer["stream"] != offer["stream"]:
        return "STREAM_MISMATCH", None
    if answer["epoch"] != offer["epoch"]:
        return "EPOCH_MISMATCH", None
    if answer["peer"] == offer["peer"] or answer["nonce"] == offer["nonce"]:
        return "REFLECTED_HELLO", None
    if answer["digest"] != sha256(offer_wire):
        return "OFFER_DIGEST_MISMATCH", None
    code, expected = select(offer["caps"], answer["caps"])
    if code != "OK":
        return code, None
    if answer["selection"] != expected:
        if answer["selection"]["wire_version"] < expected["wire_version"]:
            return "DOWNGRADE_DETECTED", None
        return "SELECTION_MISMATCH", None
    transcript, key = derive(psk, offer_wire, answer_wire)
    return "OK", (expected, transcript, key)


def negotiation_case(cid, name, sender_caps, receiver_caps, answer_nonce=bytes(range(0x20, 0x30))):
    offer_nonce = bytes(range(0x10, 0x20))
    code, offer_wire = make_offer(KEY, sender_caps)
    assert code == "OK", (cid, code)
    code, result = respond(KEY, receiver_caps, RECEIVER_PEER, 0, answer_nonce, offer_wire)
    assert code == "OK", (cid, code)
    answer_wire, selection, transcript, key = result
    return {
        "id": cid, "name": name, "sender_caps": sender_caps, "receiver_caps": receiver_caps,
        "sender_peer": SENDER_PEER, "receiver_peer": RECEIVER_PEER, "stream_id": STREAM, "epoch": EPOCH,
        "min_epoch": 0, "offer_nonce_hex": offer_nonce.hex(), "answer_nonce_hex": answer_nonce.hex(),
        "offer_hex": offer_wire.hex(), "answer_hex": answer_wire.hex(), "selection": selection,
        "transcript_hex": transcript.hex(), "session_key_hex": key.hex(),
    }


def build_negotiations() -> list:
    group = caps(mandatory=FEATURE_XOR, optional=FEATURE_PARTIAL)
    return [
        negotiation_case("N01-NG-001", "current_sender_with_old_firmware_receiver", BASELINE, OLD_FIRMWARE),
        negotiation_case("N01-NG-002", "current_sender_with_current_receiver", BASELINE, BASELINE),
        negotiation_case("N01-NG-003", "mandatory_feature_satisfied_by_receiver", group, BASELINE),
    ]


def build_rejections() -> list:
    out = []
    offer_nonce = bytes(range(0x10, 0x20))
    answer_nonce = bytes(range(0x20, 0x30))
    _, offer = make_offer(KEY, BASELINE)
    _, (answer, _, _, _) = respond(KEY, BASELINE, RECEIVER_PEER, 0, answer_nonce, offer)

    def respond_case(cid, name, expect, offer_wire, *, local_caps=BASELINE, local_peer=RECEIVER_PEER,
                     min_epoch=0, nonce=answer_nonce):
        code, _ = respond(KEY, local_caps, local_peer, min_epoch, nonce, offer_wire)
        out.append({"id": cid, "name": name, "op": "respond", "expect": expect, "local_caps": local_caps,
                    "local_peer": local_peer, "min_epoch": min_epoch, "nonce_hex": nonce.hex(),
                    "offer_hex": offer_wire.hex()})
        return code

    def finish_case(cid, name, expect, answer_wire):
        out.append({"id": cid, "name": name, "op": "finish", "expect": expect, "sender_caps": BASELINE,
                    "sender_peer": SENDER_PEER, "stream_id": STREAM, "epoch": EPOCH,
                    "offer_nonce_hex": offer_nonce.hex(), "answer_hex": answer_wire.hex()})

    def altered(wire, **changes):
        f = fields_of(wire)
        for k, v in changes.items():
            if k in ("caps", "selection"):
                f[k] = {**f[k], **v}
            else:
                f[k] = v
        return build(KEY, f)

    flipped = bytearray(offer)
    flipped[21] ^= 0x01
    respond_case("N01-NR-101", "offer_tampered_after_signing", "HELLO_AUTH_FAILED", bytes(flipped))
    respond_case("N01-NR-102", "offer_one_byte_short", "HELLO_LENGTH", offer[:-1])
    respond_case("N01-NR-103", "offer_one_byte_long", "HELLO_LENGTH", offer + b"\x00")
    respond_case("N01-NR-104", "bad_magic", "HELLO_BAD_MAGIC", altered(offer, magic=b"FFWX"))
    respond_case("N01-NR-105", "hello_version_2_is_not_interpreted", "HELLO_UNSUPPORTED_VERSION",
                 altered(offer, msg_version=2))
    respond_case("N01-NR-106", "answer_presented_as_offer", "WRONG_HELLO_KIND", answer)
    respond_case("N01-NR-107", "offer_for_a_superseded_epoch", "STALE_OFFER_EPOCH", offer, min_epoch=EPOCH + 1)
    respond_case("N01-NR-108", "unknown_message_kind", "UNKNOWN_HELLO_KIND", altered(offer, kind=9))
    respond_case("N01-NR-109", "unknown_critical_flag", "UNKNOWN_CRITICAL_HELLO_FLAGS", altered(offer, flags=0x10))
    respond_case("N01-NR-110", "malformed_capabilities", "INVALID_CAPABILITIES", altered(offer, caps={"wire_min": 0}))
    respond_case("N01-NR-111", "zero_peer_identity", "INVALID_PEER_IDENTITY", altered(offer, peer=0))
    respond_case("N01-NR-112", "zero_nonce_in_offer", "INVALID_NONCE", altered(offer, nonce=bytes(16)))
    respond_case("N01-NR-113", "offer_carrying_selection_content", "MALFORMED_HELLO",
                 altered(offer, selection={"wire_version": 1}))
    respond_case("N01-NR-114", "responder_reuses_the_senders_peer_identity", "REFLECTED_HELLO", offer,
                 local_peer=SENDER_PEER)
    respond_case("N01-NR-115", "responder_reuses_the_offers_nonce", "REFLECTED_HELLO", offer, nonce=offer_nonce)
    respond_case("N01-NR-116", "responder_without_a_nonce", "INVALID_NONCE", offer, nonce=bytes(16))
    respond_case("N01-NR-117", "responder_claims_a_feature_this_build_lacks", "INVALID_CAPABILITIES", offer,
                 local_caps=caps(optional=KNOWN_FEATURES | (1 << 20)))
    needs_xor = caps(mandatory=FEATURE_XOR, optional=FEATURE_PARTIAL)
    _, needs_xor_offer = make_offer(KEY, needs_xor)
    respond_case("N01-NR-118", "mandatory_feature_missing_on_the_receiver", "MANDATORY_FEATURE_MISSING",
                 needs_xor_offer, local_caps=OLD_FIRMWARE)

    # Answers judged by the initiator that sent `offer`.
    # A genuine answer, but to an earlier offer with a different nonce.
    _, other_offer = make_offer(KEY, BASELINE, nonce=bytes(range(0x50, 0x60)))
    _, (other_offer_answer, _, _, _) = respond(KEY, BASELINE, RECEIVER_PEER, 0, answer_nonce, other_offer)
    finish_case("N01-NF-201", "answer_to_a_different_offer", "OFFER_DIGEST_MISMATCH", other_offer_answer)
    tampered = bytearray(answer)
    tampered[-1] ^= 0x01
    finish_case("N01-NF-202", "answer_tampered_after_signing", "HELLO_AUTH_FAILED", bytes(tampered))
    finish_case("N01-NF-203", "offer_fed_back_as_the_answer", "WRONG_HELLO_KIND", offer)
    finish_case("N01-NF-204", "answer_for_another_stream", "STREAM_MISMATCH", altered(answer, stream=5))
    finish_case("N01-NF-205", "answer_for_another_epoch", "EPOCH_MISMATCH", altered(answer, epoch=EPOCH + 1))
    finish_case("N01-NF-206", "answer_under_the_senders_peer_identity", "REFLECTED_HELLO",
                altered(answer, peer=SENDER_PEER))
    finish_case("N01-NF-207", "answer_strips_a_negotiated_feature", "SELECTION_MISMATCH",
                altered(answer, selection={"features": KNOWN_FEATURES & ~FEATURE_XOR}))
    finish_case("N01-NF-208", "answer_with_a_malformed_selection", "MALFORMED_HELLO",
                altered(answer, selection={"format": 0b11}))
    return out


def build_document() -> dict:
    return {
        "schema": "ffw.n01.negotiation_vectors.v1",
        "generator": "tests/n01/reference_negotiation.py",
        "contract": "docs/contracts/n01.md",
        "note": "Public synthetic test material: the key, identities and nonces are fixed test values, "
                "not secrets and not site data.",
        "key_hex": KEY.hex(),
        "negotiations": build_negotiations(),
        "rejections": build_rejections(),
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1) + "\n"


def caps_of(c) -> dict:
    return {k: c[k] for k in ("wire_min", "wire_max", "formats", "max_payload_bytes",
                              "mandatory_features", "optional_features")}


def self_verify(doc: dict) -> list:
    failures = []
    key = bytes.fromhex(doc["key_hex"])
    for c in doc["negotiations"]:
        offer_nonce = bytes.fromhex(c["offer_nonce_hex"])
        code, offer = make_offer(key, caps_of(c["sender_caps"]), c["sender_peer"], c["stream_id"], c["epoch"], offer_nonce)
        if code != "OK" or offer.hex() != c["offer_hex"]:
            failures.append(f'{c["id"]}: offer does not reproduce')
            continue
        code, result = respond(key, caps_of(c["receiver_caps"]), c["receiver_peer"], c["min_epoch"],
                               bytes.fromhex(c["answer_nonce_hex"]), offer)
        if code != "OK" or result[0].hex() != c["answer_hex"]:
            failures.append(f'{c["id"]}: answer does not reproduce ({code})')
            continue
        code, done = finish(key, offer, result[0])
        if code != "OK" or done[0] != c["selection"] or done[1].hex() != c["transcript_hex"] \
                or done[2].hex() != c["session_key_hex"]:
            failures.append(f'{c["id"]}: initiator disagrees with responder ({code})')
    for r in doc["rejections"]:
        if r["op"] == "respond":
            code, _ = respond(key, caps_of(r["local_caps"]), r["local_peer"], r["min_epoch"],
                              bytes.fromhex(r["nonce_hex"]), bytes.fromhex(r["offer_hex"]))
        else:
            _, offer = make_offer(key, caps_of(r["sender_caps"]), r["sender_peer"], r["stream_id"], r["epoch"],
                                  bytes.fromhex(r["offer_nonce_hex"]))
            code, _ = finish(key, offer, bytes.fromhex(r["answer_hex"]))
        if code != r["expect"]:
            failures.append(f'{r["id"]} {r["name"]}: expected {r["expect"]}, model said {code}')
    covered = {r["expect"] for r in doc["rejections"]}
    missing = [c for c in NEGOTIATION_CODES if c not in covered and c not in NOT_VECTORED]
    if missing:
        failures.append("no rejection vector exercises: " + ", ".join(missing))
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
        print("negotiation reference self-verification FAILED:", *failures, sep="\n  ", file=sys.stderr)
        return 1
    text = render(doc)
    summary = f"{len(doc['negotiations'])} negotiations, {len(doc['rejections'])} rejections"
    if args.write is not None:
        path = Path(args.write)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path} ({summary})")
        return 0
    path = Path(args.check or DEFAULT_VECTORS)
    if not path.is_file():
        print(f"missing vector file {path}; run with --write", file=sys.stderr)
        return 1
    if path.read_text(encoding="utf-8") != text:
        print(f"{path} differs from a fresh generation; regenerate with --write and review the diff",
              file=sys.stderr)
        return 1
    print(f"ok: {path} matches a fresh generation; {summary} hold their expectations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
