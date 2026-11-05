#!/usr/bin/env python3
"""Writes the golden vectors for authenticated replies (N02 section 9.1, bead ffw-ugf).

    python3 -B -I tests/n02/gen_reply_vectors.py --check    fail if the committed file differs from this script's output
    python3 -B -I tests/n02/gen_reply_vectors.py --write    rewrite crates/franken-control/tests/vectors/n02_reply_vectors.json

What is written by hand and what is computed. The wire layout, the status and kind codes, the decode errors and every
expected verification result below are written by hand from docs/contracts/n02.md section 9.1; the Rust channel did not
produce any of them. One reply (R001) is also pinned as a hand-assembled hex literal and the encoder must reproduce it.
What is computed, with the standard library only: the HMAC-SHA256 tags (context label "FFCR-v1-reply", the peer's fixture
key) and the SHA-256 digests of the request bodies a reply is bound to (taken from the hand-written signing vectors of
n02_scenarios.json). The encoder and decoder here are an independent implementation of the specification, not a port.

Before anything is written, every tamper is checked to change exactly one signed field and to leave the base tag invalid,
every malformed input to differ from its base by the one stated fault, and every verification case to be reproduced by
the independent verifier below. Nothing here runs the Rust."""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_scenarios.json"
DEFAULT_OUT = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_reply_vectors.json"

MAGIC = b"FFCR"
VERSION = 1
REPLY_CONTEXT = b"FFCR-v1-reply"
REQUEST_CONTEXT = b"FFCP-v1-auth"
TAG_LEN = 32
MAX_PEER_LEN = 32
MAX_REPLY_LEN = 144

LANES = {"ordinary": 0, "priority": 1}
# status tag -> (name, fields). `lane` is one byte, `u64` eight bytes big-endian, `kind` one byte, `a`/`b` eight bytes each.
STATUS_TAGS = {
    "queued": 1, "already_queued": 2, "committed": 3, "withdrawn": 4,
    "cancel_applied": 5, "refused": 6, "out_of_window": 7, "rejected": 8,
}
REFUSAL_CODES = {
    "stale_epoch": 1, "epoch_ahead": 2, "revision_mismatch": 3, "stale_revision": 4, "unknown_member": 5,
    "session": 6, "internal_fault": 7, "no_lease": 8, "lease": 9, "authority_expired": 10, "expired": 11,
    "too_late_to_cancel": 12, "nothing_to_cancel": 13, "target_out_of_window": 14, "not_cancellable": 15,
}
REJECTION_CODES = {"epoch_not_bound": 1, "revision_required": 2, "rate_limited": 3, "queue_full": 4, "id_reuse": 5}
# Which of a / b a kind uses; the others must be zero on the wire. "lane" means the field is a lane code (0 or 1).
REFUSAL_FIELDS = {
    "stale_epoch": ("u64", "u64"), "epoch_ahead": ("u64", "u64"), "revision_mismatch": ("u64", "u64"),
    "stale_revision": ("u64", "u64"), "target_out_of_window": ("u64", None),
}
REJECTION_FIELDS = {
    "epoch_not_bound": ("u64", "u64"), "rate_limited": ("lane", "u64"), "queue_full": ("lane", None),
}


class ReplyError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def u64(n):
    return n.to_bytes(8, "big")


def label(text):
    raw = text.encode("ascii")
    return bytes([len(raw)]) + raw


def status_bytes(status):
    kind = status["kind"]
    out = bytes([STATUS_TAGS[kind]])
    if kind in ("queued", "already_queued"):
        out += bytes([LANES[status["lane"]]])
    elif kind == "committed":
        out += u64(status["revision"])
    elif kind == "cancel_applied":
        out += u64(status["target_seq"])
    elif kind == "out_of_window":
        out += u64(status["floor"])
    elif kind in ("refused", "rejected"):
        codes = REFUSAL_CODES if kind == "refused" else REJECTION_CODES
        out += bytes([codes[status["code"]]]) + u64(status.get("a", 0)) + u64(status.get("b", 0))
    elif kind != "withdrawn":
        raise ValueError(kind)
    return out


def signing_bytes(reply):
    return (MAGIC + bytes([VERSION]) + label(reply["peer"]) + u64(reply["seq"]) + u64(reply["epoch"])
            + u64(reply["revision"]) + bytes.fromhex(reply["request_digest_hex"]) + status_bytes(reply["status"]))


def key_for(peer):
    return f"key-{peer}-0123456789abcdef".encode("ascii")


def tag_of(key, message, context=REPLY_CONTEXT):
    return hmac.new(key, context + message, hashlib.sha256).digest()


def wire_of(reply, tag=None):
    sb = signing_bytes(reply)
    return sb + (tag if tag is not None else tag_of(key_for(reply["peer"]), sb))


# ------------------------------------------------------------------ the independent decoder and verifier

def decode(wire):
    """Parse `wire` into a reply dict, or raise ReplyError with the stable error name."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(wire):
            raise ReplyError("truncated")
        chunk = wire[pos:pos + n]
        pos += n
        return chunk

    if take(4) != MAGIC:
        raise ReplyError("bad_magic")
    if take(1)[0] != VERSION:
        raise ReplyError("bad_version")
    n = take(1)[0]
    raw = take(n)
    if not (1 <= n <= MAX_PEER_LEN):
        raise ReplyError("invalid_peer")
    text = raw.decode("latin-1")
    ok = (text[0].islower() or text[0].isdigit()) and text[0].isascii() and all(
        (c.isascii() and (c.islower() or c.isdigit())) or c in "._-" for c in text)
    if not ok:
        raise ReplyError("invalid_peer")
    seq, epoch, revision = (int.from_bytes(take(8), "big") for _ in range(3))
    if seq == 0:
        raise ReplyError("zero_sequence")
    digest = take(32)
    tag = take(1)[0]
    names = {v: k for k, v in STATUS_TAGS.items()}
    if tag not in names:
        raise ReplyError("unknown_status")
    kind = names[tag]
    status = {"kind": kind}
    if kind in ("queued", "already_queued"):
        lane = take(1)[0]
        if lane not in (0, 1):
            raise ReplyError("bad_lane")
        status["lane"] = "ordinary" if lane == 0 else "priority"
    elif kind == "committed":
        status["revision"] = int.from_bytes(take(8), "big")
    elif kind == "cancel_applied":
        status["target_seq"] = int.from_bytes(take(8), "big")
    elif kind == "out_of_window":
        status["floor"] = int.from_bytes(take(8), "big")
    elif kind in ("refused", "rejected"):
        codes = {v: k for k, v in (REFUSAL_CODES if kind == "refused" else REJECTION_CODES).items()}
        code = take(1)[0]
        if code not in codes:
            raise ReplyError("unknown_kind")
        a, b = int.from_bytes(take(8), "big"), int.from_bytes(take(8), "big")
        fields = (REFUSAL_FIELDS if kind == "refused" else REJECTION_FIELDS).get(codes[code], (None, None))
        for value, use in ((a, fields[0]), (b, fields[1])):
            if use == "lane" and value not in (0, 1):
                raise ReplyError("bad_lane")
        if (fields[0] is None and a != 0) or (fields[1] is None and b != 0):
            raise ReplyError("non_canonical")
        status.update({"code": codes[code], "a": a, "b": b})
    signing_end = pos
    mac = take(TAG_LEN)
    if pos != len(wire):
        raise ReplyError("trailing_bytes")
    return {"peer": text, "seq": seq, "epoch": epoch, "revision": revision, "request_digest_hex": digest.hex(),
            "status": status, "_signing": wire[:signing_end], "_tag": mac}


def verify(key, wire, expect):
    """The client's check. Returns "accepted" or the stable rejection name; raises ReplyError if it does not decode.
    Authenticity first, then the command, then the request, then freshness."""
    reply = decode(wire)
    if not hmac.compare_digest(tag_of(key, reply["_signing"]), reply["_tag"]):
        return "bad_tag"
    if reply["peer"] != expect["peer"] or reply["seq"] != expect["seq"]:
        return "wrong_command"
    if reply["request_digest_hex"] != expect["request_digest_hex"]:
        return "wrong_request"
    if (reply["epoch"], reply["revision"]) < (expect["seen_epoch"], expect["seen_revision"]):
        return "stale"
    return "accepted"


# ------------------------------------------------------------------ the hand-written inputs

def request_digest(vector_id):
    """SHA-256 of the signed bytes of a hand-written request signing vector."""
    doc = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    hexed = next(v["hex"] for v in doc["signing_vectors"] if v["id"] == vector_id)
    return hashlib.sha256(bytes.fromhex(hexed)).hexdigest()


LITERAL_DIGEST = bytes(range(32)).hex()  # 00 01 02 ... 1f: a digest a person can write by hand
# Hand-assembled hex of R001, written out by a person from the layout, never produced by the encoder:
#   46464352 01 | 05 63746c2d61 | 0000000000000007 | 0000000000000003 | 000000000000000d | 00..1f | 03 000000000000000d
R001_HAND_HEX = ("4646435201" "0563746c2d61" "0000000000000007" "0000000000000003" "000000000000000d"
                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "03" "000000000000000d")
LONG_PEER = "abcdefghijklmnopqrstuvwxyz012345"  # 32 characters, the longest identity
U64_MAX = 2 ** 64 - 1


def build_replies():
    d1 = request_digest("N02-W001")
    r = []

    def add(rid, what, peer, seq, epoch, revision, digest, status):
        r.append({"id": rid, "what": what, "peer": peer, "seq": seq, "epoch": epoch, "revision": revision,
                  "request_digest_hex": digest, "status": status})

    add("R001", "committed, hand-assembled hex (the request digest is the literal 00..1f)", "ctl-a", 7, 3, 13,
        LITERAL_DIGEST, {"kind": "committed", "revision": 13})
    add("R002", "queued on the ordinary lane: accepted, not committed", "ctl-a", 8, 3, 13, d1,
        {"kind": "queued", "lane": "ordinary"})
    add("R003", "a copy is already waiting, on the priority lane", "panel", 2, 10, 5, d1,
        {"kind": "already_queued", "lane": "priority"})
    add("R004", "withdrawn by a cancel before it was applied", "ctl-b", 300, 11, 20, d1, {"kind": "withdrawn"})
    add("R005", "this command was a cancel and it withdrew 298", "ctl-b", 301, 11, 20, d1,
        {"kind": "cancel_applied", "target_seq": 298})
    add("R006", "refused: a copy that outlived a restart (observed 4, floor 7)", "ctl-a", 100, 10, 7, d1,
        {"kind": "refused", "code": "stale_revision", "a": 4, "b": 7})
    add("R007", "refused with no numbers: no group lease", "ctl-a", 9, 10, 7, d1,
        {"kind": "refused", "code": "no_lease", "a": 0, "b": 0})
    add("R008", "refused: a relative step against another revision", "ctl-a", 10, 10, 9, d1,
        {"kind": "refused", "code": "revision_mismatch", "a": 5, "b": 9})
    add("R009", "refused: a cancel whose target is older than the ledger remembers", "ctl-b", 302, 11, 20, d1,
        {"kind": "refused", "code": "target_out_of_window", "a": 12, "b": 0})
    add("R010", "out of window: unknown whether it was applied, and it will not be applied now", "ctl-a", 3, 10, 400,
        d1, {"kind": "out_of_window", "floor": 250})
    add("R011", "rejected before it was accepted: rate limited on the priority lane", "panel", 5, 10, 8, d1,
        {"kind": "rejected", "code": "rate_limited", "a": 1, "b": 1500000})
    add("R012", "rejected: the key is bound to another epoch", "ctl-a", 11, 9, 8, d1,
        {"kind": "rejected", "code": "epoch_not_bound", "a": 10, "b": 9})
    add("R013", "rejected: the same number with different content", "ctl-a", 7, 3, 13, d1,
        {"kind": "rejected", "code": "id_reuse", "a": 0, "b": 0})
    add("R014", "the longest identity and the largest numbers: the longest reply on the wire", LONG_PEER, U64_MAX,
        U64_MAX, U64_MAX, d1, {"kind": "rejected", "code": "rate_limited", "a": 1, "b": U64_MAX})
    for reply in r:
        reply["signing_hex"] = signing_bytes(reply).hex()
        reply["key"] = key_for(reply["peer"]).decode("ascii")
        reply["tag_hex"] = tag_of(key_for(reply["peer"]), signing_bytes(reply)).hex()
        reply["wire_hex"] = reply["signing_hex"] + reply["tag_hex"]
    return r


def logical(reply):
    out = {k: reply[k] for k in ("peer", "seq", "epoch", "revision", "request_digest_hex")}
    out["status"] = json.dumps(reply["status"], sort_keys=True)
    return out


def changed_fields(a, b):
    fa, fb = logical(a), logical(b)
    changed = {("request digest" if k == "request_digest_hex" else k) for k in fa if fa[k] != fb[k]}
    if "status" in changed:
        sa, sb = a["status"], b["status"]
        changed.discard("status")
        if sa["kind"] != sb["kind"]:
            changed.add("status kind")
        else:
            changed |= {f"status {k}" for k in set(sa) | set(sb) if sa.get(k) != sb.get(k)}
    return changed


def flip_bit(hex_text):
    raw = bytearray(bytes.fromhex(hex_text))
    raw[0] ^= 1
    return raw.hex()


def with_status(reply, **changes):
    out = json.loads(json.dumps(reply))
    out["status"].update(changes)
    return out


def with_fields(reply, **changes):
    out = json.loads(json.dumps(reply))
    out.update(changes)
    return out


def build_tampers(replies):
    by = {r["id"]: r for r in replies}
    base = lambda rid: by[rid]  # noqa: E731
    plan = [
        ("peer", "R001", with_fields(base("R001"), peer="ctl-b")),
        ("seq", "R001", with_fields(base("R001"), seq=8)),
        ("epoch", "R001", with_fields(base("R001"), epoch=4)),
        ("revision", "R001", with_fields(base("R001"), revision=14)),
        ("request digest", "R001", with_fields(base("R001"), request_digest_hex=flip_bit(base("R001")["request_digest_hex"]))),
        ("status kind", "R001", with_fields(base("R001"), status={"kind": "withdrawn"})),
        ("committed revision", "R001", with_status(base("R001"), revision=14)),
        ("lane", "R002", with_status(base("R002"), lane="priority")),
        ("refusal code", "R006", with_status(base("R006"), code="epoch_ahead")),
        ("refusal a", "R006", with_status(base("R006"), a=5)),
        ("refusal b", "R006", with_status(base("R006"), b=8)),
        ("rejection code", "R011", with_status(base("R011"), code="queue_full", b=0)),
        ("out of window floor", "R010", with_status(base("R010"), floor=251)),
    ]
    out, problems = [], []
    for n, (field, rid, mutated) in enumerate(plan, 1):
        original = base(rid)
        tid = f"T{n:03d}"
        changed = changed_fields(original, mutated)
        want = {field} if field not in ("lane", "refusal code", "refusal a", "refusal b", "rejection code",
                                         "committed revision", "out of window floor", "status kind") else None
        if want is not None and changed != want:
            problems.append(f"{tid} ({field}): changes {sorted(changed)}, not exactly {sorted(want)}")
        if want is None and len(changed) != (2 if field == "rejection code" else 1):
            problems.append(f"{tid} ({field}): changes {sorted(changed)}")
        if signing_bytes(mutated) == signing_bytes(original):
            problems.append(f"{tid} ({field}): the signed bytes do not change")
        wire = signing_bytes(mutated) + bytes.fromhex(original["tag_hex"])
        try:
            decode(wire)
        except ReplyError as err:
            problems.append(f"{tid} ({field}): the tampered wire does not decode ({err.code}), so a replay would not reach the tag check")
        if tag_of(key_for(mutated["peer"]), signing_bytes(mutated)) == bytes.fromhex(original["tag_hex"]):
            problems.append(f"{tid} ({field}): the base tag still verifies")
        out.append({"id": tid, "reply": rid, "field": field, "wire_hex": wire.hex()})
    return out, problems


def build_malformed(replies):
    by = {r["id"]: r for r in replies}
    r001, r006, r002, r011 = (bytes.fromhex(by[i]["wire_hex"]) for i in ("R001", "R006", "R002", "R011"))
    sig001 = len(r001) - TAG_LEN
    label_end = 4 + 1 + 1 + len("ctl-a")
    digest_start = label_end + 24

    def patched(wire, offset, new):
        return wire[:offset] + new + wire[offset + len(new):]

    def retag(signing_wire):
        """A wire whose tag is genuine for its (possibly malformed) signed bytes: it must fail to decode, not to verify."""
        return signing_wire + tag_of(key_for("ctl-a"), signing_wire)

    sig006 = r006[:-TAG_LEN]
    status_at_006 = len(sig006) - 17 - 1  # the status tag byte of R006
    sig011 = r011[:-TAG_LEN]
    status_at_011 = len(sig011) - 17 - 1
    sig002 = r002[:-TAG_LEN]
    cases = [
        ("an empty input", b"", "truncated"),
        ("only the magic", r001[:4], "truncated"),
        ("cut inside the peer label", r001[:label_end - 2], "truncated"),
        ("cut inside the request digest", r001[:digest_start + 10], "truncated"),
        ("cut where the status should begin", r001[:sig001 - 9], "truncated"),
        ("the signed bytes and no tag at all", r001[:sig001], "truncated"),
        ("cut inside the tag (31 bytes)", r001[:-1], "truncated"),
        ("one byte after the tag", r001 + b"\x00", "trailing_bytes"),
        ("the request magic, not the reply magic", patched(r001, 0, b"FFCP"), "bad_magic"),
        ("version 2", patched(r001, 4, b"\x02"), "bad_version"),
        ("peer label of length zero", retag(r001[:5] + b"\x00" + r001[11:sig001]), "invalid_peer"),
        ("peer label of 33 bytes", retag(r001[:5] + b"\x21" + b"a" * 33 + r001[11:sig001]), "invalid_peer"),
        ("peer label with an upper-case letter", retag(patched(r001[:sig001], 6, b"C")), "invalid_peer"),
        ("sequence number zero", retag(patched(r001[:sig001], label_end, u64(0))), "zero_sequence"),
        ("status tag 0", retag(patched(r001[:sig001], sig001 - 9, b"\x00")), "unknown_status"),
        ("status tag 9", retag(patched(r001[:sig001], sig001 - 9, b"\x09")), "unknown_status"),
        ("lane code 2 on a queued reply", retag(patched(sig002, len(sig002) - 1, b"\x02")), "bad_lane"),
        ("refusal code 0", retag(patched(sig006, status_at_006 + 1, b"\x00")), "unknown_kind"),
        ("refusal code 16", retag(patched(sig006, status_at_006 + 1, b"\x10")), "unknown_kind"),
        ("rejection code 0", retag(patched(sig011, status_at_011 + 1, b"\x00")), "unknown_kind"),
        ("rejection code 6", retag(patched(sig011, status_at_011 + 1, b"\x06")), "unknown_kind"),
        ("lane code 2 in a rate-limit rejection", retag(patched(sig011, status_at_011 + 2, u64(2))), "bad_lane"),
        ("a number on a refusal that carries none", retag(patched(patched(sig006, status_at_006 + 1, b"\x08"), status_at_006 + 2, u64(1))), "non_canonical"),
        ("a second number on a refusal that carries one", retag(patched(patched(sig006, status_at_006 + 1, b"\x0e"), status_at_006 + 10, u64(5))), "non_canonical"),
    ]
    out, problems = [], []
    for n, (what, wire, error) in enumerate(cases, 1):
        mid = f"M{n:03d}"
        try:
            decode(wire)
            problems.append(f"{mid} ({what}): decodes, expected {error}")
        except ReplyError as err:
            if err.code != error:
                problems.append(f"{mid} ({what}): the independent decoder says {err.code}, expected {error}")
        out.append({"id": mid, "what": what, "wire_hex": wire.hex(), "error": error})
    return out, problems


def build_verify(replies):
    by = {r["id"]: r for r in replies}
    r001, r002 = by["R001"], by["R002"]
    a_key = key_for("ctl-a")
    wire001 = bytes.fromhex(r001["wire_hex"])
    sb001 = bytes.fromhex(r001["signing_hex"])
    request_tag_a001 = None
    doc = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    for a in doc["auth_vectors"]:
        if a["signing_vector"] == "N02-W001":
            request_tag_a001 = bytes.fromhex(a["tag_hex"])
    d1 = request_digest("N02-W001")

    def exp(peer="ctl-a", seq=7, digest=LITERAL_DIGEST, epoch=3, revision=10):
        return {"peer": peer, "seq": seq, "request_digest_hex": digest, "seen_epoch": epoch, "seen_revision": revision}

    b_wire = bytes.fromhex(by["R004"]["wire_hex"])
    cases = [
        ("the genuine reply to the command the client sent", wire001, a_key, exp(), "accepted"),
        ("accepted at the freshness boundary: the client has seen exactly this revision", wire001, a_key, exp(revision=13), "accepted"),
        ("accepted from a newer epoch than the client has seen", wire001, a_key, exp(epoch=2, revision=99), "accepted"),
        ("an old reply replayed: the client has seen a later revision of the same epoch", wire001, a_key, exp(revision=14), "stale"),
        ("an old reply replayed: the client has seen a later epoch", wire001, a_key, exp(epoch=4, revision=0), "stale"),
        ("a genuine reply to another command of the same peer (seq 7 answered for seq 8)", wire001, a_key, exp(seq=8), "wrong_command"),
        ("a reply whose tag is genuine under this client's key but which names another peer", sb001 + tag_of(key_for("ctl-b"), sb001),
         key_for("ctl-b"), exp(peer="ctl-b"), "wrong_command"),
        ("the same peer and number, but a different request (a reused number)", wire001, a_key, exp(digest=d1), "wrong_request"),
        ("a forged reply: the tag is all zero", sb001 + bytes(TAG_LEN), a_key, exp(), "bad_tag"),
        ("a forged reply: the tag is computed under the request context", sb001 + tag_of(a_key, sb001, REQUEST_CONTEXT), a_key, exp(), "bad_tag"),
        ("a forged reply: the tag is the request's own proof, which an attacker saw on the wire", sb001 + request_tag_a001, a_key, exp(), "bad_tag"),
        ("a genuine reply for another peer handed to this client", b_wire, a_key, exp(peer="ctl-b", seq=300, digest=d1, epoch=11, revision=0), "bad_tag"),
        ("authenticity is checked first: a forged reply to the wrong command", sb001 + bytes(TAG_LEN), a_key, exp(seq=8), "bad_tag"),
        ("authenticity is checked first: a forged reply that would also be stale", sb001 + bytes(TAG_LEN), a_key, exp(revision=14), "bad_tag"),
        ("the command is checked before the freshness: a wrong command that is also stale", wire001, a_key, exp(seq=8, revision=14), "wrong_command"),
        ("the request is checked before the freshness: a wrong request that is also stale", wire001, a_key, exp(digest=d1, revision=14), "wrong_request"),
        ("the command is checked before the request: both are wrong", wire001, a_key, exp(seq=8, digest=d1), "wrong_command"),
        ("a genuine queued reply, accepted: accepted is not committed", bytes.fromhex(r002["wire_hex"]), a_key,
         exp(seq=8, digest=d1, epoch=3, revision=13), "accepted"),
    ]
    out, problems = [], []
    for n, (what, wire, key, expect, result) in enumerate(cases, 1):
        vid = f"V{n:03d}"
        got = verify(key, wire, expect)
        if got != result:
            problems.append(f"{vid} ({what}): the independent verifier says {got}, expected {result}")
        out.append({"id": vid, "what": what, "key": key.decode("ascii"), "wire_hex": wire.hex(), "expect": expect, "result": result})
    return out, problems


def build():
    problems = []
    replies = build_replies()
    if replies[0]["signing_hex"] != R001_HAND_HEX:
        problems.append(f"R001: the hand-assembled hex differs from the encoder: {R001_HAND_HEX} vs {replies[0]['signing_hex']}")
    for reply in replies:
        decoded = decode(bytes.fromhex(reply["wire_hex"]))
        if {k: decoded[k] for k in ("peer", "seq", "epoch", "revision", "request_digest_hex", "status")} != {
                k: reply[k] for k in ("peer", "seq", "epoch", "revision", "request_digest_hex", "status")} and reply["status"].get("kind") not in ("refused", "rejected"):
            problems.append(f"{reply['id']}: the independent decoder does not give back the encoded reply")
    longest = max(len(bytes.fromhex(r["wire_hex"])) for r in replies)
    if longest != MAX_REPLY_LEN:
        problems.append(f"the longest vector is {longest} bytes, the stated bound is {MAX_REPLY_LEN}")
    kinds = {r["status"]["kind"] for r in replies}
    if kinds != set(STATUS_TAGS):
        problems.append(f"the vectors do not cover every status: missing {sorted(set(STATUS_TAGS) - kinds)}")
    tampers, p1 = build_tampers(replies)
    malformed, p2 = build_malformed(replies)
    verifies, p3 = build_verify(replies)
    problems += p1 + p2 + p3
    doc = {
        "schema": "ffw.n02.reply_vectors.v1",
        "notes": [
            "Written by tests/n02/gen_reply_vectors.py from docs/contracts/n02.md section 9.1. The layout, codes, errors and expected results are hand-written; only the HMAC tags and request digests are computed (standard library).",
            "wire = signing bytes || 32-byte tag; tag = HMAC-SHA256(key, \"FFCR-v1-reply\" || signing bytes).",
            "A tamper keeps the base reply's tag and changes exactly one signed field; the Rust replay must refuse it as bad_tag.",
            "A malformed input must fail to decode with the named error, before any tag is looked at.",
            "A verify case is a reply as the client received it, the key the client holds and what the client expects; the result is hand-written.",
        ],
        "context": REPLY_CONTEXT.decode("ascii"),
        "max_reply_len": MAX_REPLY_LEN,
        "replies": replies,
        "tampers": tampers,
        "malformed": malformed,
        "verify": verifies,
    }
    return json.dumps(doc, indent=2) + "\n", problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    text, problems = build()
    for line in problems:
        print("PROBLEM", line, file=sys.stderr)
    if problems:
        return 1
    path = Path(args.out)
    doc = json.loads(text)
    counts = f"{len(doc['replies'])} replies, {len(doc['tampers'])} tampers, {len(doc['malformed'])} malformed, {len(doc['verify'])} verify cases"
    if args.write:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {counts} to {path}")
        return 0
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        print("the committed reply vectors differ from the generator's output; run --write", file=sys.stderr)
        return 1
    print(f"N02 reply vectors: PASS ({counts})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
