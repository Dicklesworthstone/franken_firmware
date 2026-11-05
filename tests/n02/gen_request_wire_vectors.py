#!/usr/bin/env python3
"""Writes the golden vectors for the request and acknowledgement wire form (N02 section 9.3, bead ffw-ugf).

    python3 -B -I tests/n02/gen_request_wire_vectors.py --check    fail if the committed file differs from this script's output
    python3 -B -I tests/n02/gen_request_wire_vectors.py --write    rewrite crates/franken-control/tests/vectors/n02_request_wire_vectors.json

What is written by hand and what is computed. The wire layout (the signed bytes the request proof already covers, then the
32-byte tag), the decode errors, the order in which they are reported and every expected result below are written by hand
from docs/contracts/n02.md section 9.3; the Rust codec did not produce any of them. Five request signing vectors are the
hand-written ones of n02_scenarios.json (N02-W001..W005), whose tags must equal that file's independently generated auth
vectors; the others are assembled here byte by byte, and one (X001) is also pinned as a hand-assembled hex literal that the
independent encoder must reproduce. What is computed, with the standard library only: the HMAC-SHA256 tags (context label
"FFCP-v1-auth", the peer's fixture key). The decoder below is an independent implementation of the specification, not a port,
and it can be told to be sloppy in one named way so the vectors can be shown to catch each.

Before anything is written, every malformed input is checked to differ from its base by the stated fault, every valid vector to
round-trip through the independent encoder and decoder, and the longest valid vector to be exactly the stated bound. Nothing
here runs the Rust."""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_scenarios.json"
DEFAULT_OUT = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_request_wire_vectors.json"

REQUEST_MAGIC = b"FFCP"
ACK_MAGIC = b"FFCA"
VERSION = 1
AUTH_CONTEXT = b"FFCP-v1-auth"
TAG_LEN = 32
MAX_PEER_LEN = 32
MAX_MEMBER_LEN = 64
# 4 magic + 1 version + (1 + 32) peer + 8 seq + 8 epoch + (1 + 8) revision + (1 + 1 + 64 + 1) widest command + 32 tag
MAX_REQUEST_LEN = 4 + 1 + (1 + MAX_PEER_LEN) + 8 + 8 + (1 + 8) + (1 + 1 + MAX_MEMBER_LEN + 1) + TAG_LEN
MAX_ACK_LEN = 4 + 1 + (1 + MAX_PEER_LEN) + 8 + 8 + TAG_LEN
MAX_DATAGRAM_LEN = max(MAX_REQUEST_LEN, MAX_ACK_LEN)
U64_MAX = 2 ** 64 - 1

COMMAND_TAGS = {
    "set_member_volume": 1, "set_group_volume": 2, "adjust_member_volume": 3, "adjust_group_volume": 4,
    "set_member_mute": 5, "stop": 6, "cancel": 7,
}
RELATIVE = ("adjust_member_volume", "adjust_group_volume")


class WireError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def u64(n):
    return n.to_bytes(8, "big")


def label(text):
    raw = text.encode("ascii")
    return bytes([len(raw)]) + raw


def command_bytes(cmd):
    kind = cmd["kind"]
    out = bytes([COMMAND_TAGS[kind]])
    if kind == "set_member_volume":
        out += label(cmd["member"]) + bytes([cmd["volume"]])
    elif kind == "set_group_volume":
        out += bytes([cmd["volume"]])
    elif kind == "adjust_member_volume":
        out += label(cmd["member"]) + (cmd["delta"] & 0xFF).to_bytes(1, "big")
    elif kind == "adjust_group_volume":
        out += (cmd["delta"] & 0xFF).to_bytes(1, "big")
    elif kind == "set_member_mute":
        out += label(cmd["member"]) + bytes([1 if cmd["muted"] else 0])
    elif kind == "stop":
        out += u64(cmd["now_ns"]) + u64(cmd["tail_ns"])
    elif kind == "cancel":
        out += u64(cmd["target_seq"])
    else:
        raise ValueError(kind)
    return out


def signing_bytes(req):
    rev = b"\x00" if req["rev"] is None else b"\x01" + u64(req["rev"])
    return (REQUEST_MAGIC + bytes([VERSION]) + label(req["peer"]) + u64(req["seq"]) + u64(req["epoch"]) + rev
            + command_bytes(req["cmd"]))


def ack_signing_bytes(ack):
    return ACK_MAGIC + bytes([VERSION]) + label(ack["peer"]) + u64(ack["seq"]) + u64(ack["epoch"])


def key_for(peer):
    return f"key-{peer}-0123456789abcdef".encode("ascii")


def tag_of(peer, message):
    return hmac.new(key_for(peer), AUTH_CONTEXT + message, hashlib.sha256).digest()


# ------------------------------------------------------------------ the independent decoder

def decode(wire, flaws=frozenset()):
    """Parse `wire` into ("request", dict) or ("ack", dict), or raise WireError with the stable error name.

    The order is the specification's: (1) the length bound, before anything is read; (2) the magic; (3) the version; (4) the
    peer; (5) the sequence number, zero refused as soon as it and the epoch are read; (6) the revision flag; (7) the command
    tag and the command's own bytes; (8) the tag, whose absence is `truncated` and whose excess is `trailing_bytes`; and only
    then (9) the values, in this order: the command's own value, a relative command without a revision, a cancel of itself.
    `flaws` names ways this decoder can be made sloppy, so the vectors can be shown to catch each; it is empty for the real one."""
    if "length_after" not in flaws and len(wire) > MAX_DATAGRAM_LEN:
        raise WireError("too_long")
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(wire):
            raise WireError("truncated")
        chunk = wire[pos:pos + n]
        pos += n
        return chunk

    def take_tag():
        if len(wire) - pos < TAG_LEN:
            raise WireError("truncated")
        if len(wire) - pos > TAG_LEN and "trailing" not in flaws:
            raise WireError("trailing_bytes")
        return take(TAG_LEN)

    magic = take(4)
    if magic == REQUEST_MAGIC:
        kind = "request"
    elif magic == ACK_MAGIC:
        kind = "ack"
    elif "magic" in flaws:
        kind = "request"
    else:
        raise WireError("bad_magic")
    if take(1)[0] != VERSION and "version" not in flaws:
        raise WireError("bad_version")
    n = take(1)[0]
    raw = take(n)
    if "peer" not in flaws:
        text = raw.decode("latin-1")
        ok = 1 <= n <= MAX_PEER_LEN and text.isascii() and (text[0].islower() or text[0].isdigit()) and all(
            (c.islower() or c.isdigit()) or c in "._-" for c in text)
        if not ok:
            raise WireError("invalid_peer")
    peer = raw.decode("latin-1")
    seq = int.from_bytes(take(8), "big")
    epoch = int.from_bytes(take(8), "big")
    if seq == 0 and "zero_seq" not in flaws and "zero_late" not in flaws:
        raise WireError("zero_sequence")
    fields = {"peer": peer, "seq": seq, "epoch": epoch}
    if kind == "ack":
        signing_end = pos
        mac = take_tag()
        if seq == 0 and "zero_late" in flaws and "zero_seq" not in flaws:
            raise WireError("zero_sequence")
        return "ack", {**fields, "_signing": wire[:signing_end], "_tag": mac}
    flag = take(1)[0]
    if flag == 0:
        rev = None
    elif flag == 1 or ("rev_flag" in flaws and flag != 0):
        rev = int.from_bytes(take(8), "big")
    else:
        raise WireError("bad_revision_flag")
    tag = take(1)[0]
    names = {v: k for k, v in COMMAND_TAGS.items()}
    if tag not in names:
        raise WireError("unknown_command")
    ckind = names[tag]
    cmd = {"kind": ckind}
    raw_member = None
    if ckind in ("set_member_volume", "adjust_member_volume", "set_member_mute"):
        raw_member = take(take(1)[0])
        cmd["member"] = raw_member.decode("latin-1")
    if ckind in ("set_member_volume", "set_group_volume"):
        cmd["volume"] = take(1)[0]
    elif ckind in ("adjust_member_volume", "adjust_group_volume"):
        b = take(1)[0]
        cmd["delta"] = b - 256 if b >= 128 else b
    elif ckind == "set_member_mute":
        b = take(1)[0]
        if b not in (0, 1) and "bool" not in flaws:
            raise WireError("bad_bool")
        cmd["muted"] = b != 0
    elif ckind == "stop":
        cmd["now_ns"], cmd["tail_ns"] = int.from_bytes(take(8), "big"), int.from_bytes(take(8), "big")
    elif ckind == "cancel":
        cmd["target_seq"] = int.from_bytes(take(8), "big")
    signing_end = pos

    def own_value():
        if raw_member is not None and "member" not in flaws:
            ok = 1 <= len(raw_member) <= MAX_MEMBER_LEN and raw_member.isascii() and all(
                (c.islower() or c.isdigit()) or c in "._-" for c in cmd["member"])
            if not ok:
                raise WireError("invalid_member_id")
        if ckind in ("set_member_volume", "set_group_volume") and cmd["volume"] > 100 and "volume" not in flaws:
            raise WireError("volume_out_of_range")
        if ckind in RELATIVE and "delta" not in flaws and (cmd["delta"] == 0 or abs(cmd["delta"]) > 100):
            raise WireError("delta_out_of_range")
        if ckind == "cancel" and cmd["target_seq"] == 0 and "cancel_zero" not in flaws:
            raise WireError("zero_target")

    def relative():
        if ckind in RELATIVE and rev is None and "relative" not in flaws:
            raise WireError("relative_needs_revision")

    def itself():
        if ckind == "cancel" and cmd["target_seq"] == seq and "cancel_self" not in flaws:
            raise WireError("cancels_itself")

    def values():
        if "relative_first" in flaws:
            relative()
        own_value()
        relative()
        itself()

    if "values_first" in flaws:
        values()
    mac = take_tag()
    if "values_first" not in flaws:
        values()
    if seq == 0 and "zero_late" in flaws and "zero_seq" not in flaws:
        raise WireError("zero_sequence")
    return "request", {**fields, "rev": rev, "cmd": cmd, "_signing": wire[:signing_end], "_tag": mac}


# ------------------------------------------------------------------ the hand-written inputs

def scenario_vectors():
    doc = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    sign = {v["id"]: v for v in doc["signing_vectors"]}
    auth = {v["signing_vector"]: v for v in doc["auth_vectors"]}
    return sign, auth


# Hand-assembled hex of X001, written out by a person from the layout, never produced by the encoder:
#   46464350 01 | 05 63746c2d62 | 0000000000000002 | 0000000000000005 | 00 | 01 03 64656e 1e
X001_HAND_HEX = "4646435001" "0563746c2d62" "0000000000000002" "0000000000000005" "00" "01" "0364656e" "1e"
LONG_PEER = "abcdefghijklmnopqrstuvwxyz012345"  # 32 characters, the longest identity
LONG_MEMBER = "m" * MAX_MEMBER_LEN


def build_requests():
    sign, auth = scenario_vectors()
    out = []

    def from_scenario(rid, wid):
        v = sign[wid]
        cmd = dict(v["cmd"])
        out.append({"id": rid, "what": v["what"] + " (signing bytes: " + wid + ")", "peer": v["peer"], "seq": v["seq"],
                    "epoch": v["epoch"], "rev": v["rev"], "cmd": cmd, "hand_signing_hex": v["hex"],
                    "auth_vector": auth[wid]["id"], "auth_tag_hex": auth[wid]["tag_hex"]})

    for n in range(1, 6):
        from_scenario(f"X{n + 100}", f"N02-W00{n}")
    out.append({"id": "X001", "what": "absolute member volume without an expected revision, hand-assembled hex", "peer": "ctl-b",
                "seq": 2, "epoch": 5, "rev": None, "cmd": {"kind": "set_member_volume", "member": "den", "volume": 30},
                "hand_signing_hex": X001_HAND_HEX})
    out.append({"id": "X002", "what": "relative group volume step up, with the revision it was computed from", "peer": "ctl-a",
                "seq": 3, "epoch": 10, "rev": 9, "cmd": {"kind": "adjust_group_volume", "delta": 7}})
    out.append({"id": "X003", "what": "the longest request: longest identity and member id, the largest numbers, a present revision",
                "peer": LONG_PEER, "seq": U64_MAX, "epoch": U64_MAX, "rev": U64_MAX,
                "cmd": {"kind": "set_member_mute", "member": LONG_MEMBER, "muted": True}})
    out.append({"id": "X004", "what": "the shortest request: one-character identity, the smallest numbers, no revision", "peer": "a",
                "seq": 1, "epoch": 0, "rev": None, "cmd": {"kind": "set_group_volume", "volume": 0}})
    out.append({"id": "X005", "what": "relative step down by the largest allowed amount", "peer": "ctl-a", "seq": 4, "epoch": 10,
                "rev": 0, "cmd": {"kind": "adjust_member_volume", "member": "kitchen", "delta": -100}})
    for req in out:
        sb = signing_bytes(req)
        if "hand_signing_hex" in req and req["hand_signing_hex"] != sb.hex():
            raise SystemExit(f"{req['id']}: the hand-written signing bytes differ from the independent encoder")
        req["key"] = key_for(req["peer"]).decode("ascii")
        req["signing_hex"] = sb.hex()
        req["tag_hex"] = tag_of(req["peer"], sb).hex()
        req["wire_hex"] = req["signing_hex"] + req["tag_hex"]
        if "auth_tag_hex" in req and req["auth_tag_hex"] != req["tag_hex"]:
            raise SystemExit(f"{req['id']}: the tag differs from the auth vector {req['auth_vector']} of n02_scenarios.json")
    return out


def build_acks():
    acks = []
    for aid, what, peer, seq, epoch in (
            ("K001", "an acknowledgement of command 7 issued under epoch 3", "ctl-a", 7, 3),
            ("K002", "the longest identity and the largest numbers: the longest acknowledgement", LONG_PEER, U64_MAX, U64_MAX),
            ("K003", "the shortest acknowledgement", "a", 1, 0)):
        ack = {"id": aid, "what": what, "peer": peer, "seq": seq, "epoch": epoch}
        sb = ack_signing_bytes(ack)
        ack["key"] = key_for(peer).decode("ascii")
        ack["signing_hex"] = sb.hex()
        ack["tag_hex"] = tag_of(peer, sb).hex()
        ack["wire_hex"] = ack["signing_hex"] + ack["tag_hex"]
        acks.append(ack)
    # K001 as a person assembles it: FFCA 01 | 05 ctl-a | seq 7 | epoch 3
    if acks[0]["signing_hex"] != "4646434101" "0563746c2d61" "0000000000000007" "0000000000000003":
        raise SystemExit("K001: the hand-assembled hex differs from the independent encoder")
    return acks


def replace(raw, at, data):
    return raw[:at] + data + raw[at + len(data):]


def build_malformed(requests, acks):
    by_id = {r["id"]: bytes.fromhex(r["wire_hex"]) for r in requests}
    ack = bytes.fromhex(acks[0]["wire_hex"])
    base = by_id["X101"]  # ctl-a, seq 7, epoch 3, rev 12, adjust member volume "kitchen" by -5
    # Offsets in X101: magic 0..4, version 4, peer length 5, peer 6..11, seq 11..19, epoch 19..27, rev flag 27, rev 28..36,
    # command tag 36, member length 37, member 38..45, delta 45, tag 46..78.
    assert len(base) == 78 and base[27] == 1 and base[36] == 3 and base[37] == 7 and base[45] == 0xFB
    group = by_id["X002"]  # ctl-a, seq 3, epoch 10, rev 9, adjust group volume +7: command tag at 36, delta at 37
    assert group[36] == 4 and group[37] == 7
    group_no_rev = group[:27] + b"\x00" + group[36:]  # flag 0 and no revision: command tag at 28, delta at 29
    assert group_no_rev[28] == 4 and group_no_rev[29] == 7
    volume = by_id["X105"]  # set group volume 100, with a revision
    mute = by_id["X104"]  # panel, seq 2, epoch 0, no revision, mute "den" true
    cancel = by_id["X103"]  # ctl-b, seq 300, epoch 11, no revision, cancel 299
    cases = []

    def add(what, wire, error):
        cases.append({"id": f"M{len(cases) + 1:03d}", "what": what, "wire_hex": wire.hex(), "error": error})

    last_byte = len(volume) - TAG_LEN - 1  # the volume byte
    add("no bytes at all", b"", "truncated")
    add("three bytes: the magic is cut", base[:3], "truncated")
    add("a magic that is not ours", replace(base, 0, b"XFCP"), "bad_magic")
    add("the reply magic: a reply is not a request", replace(base, 0, b"FFCR"), "bad_magic")
    add("version 2", replace(base, 4, b"\x02"), "bad_version")
    add("version 0", replace(base, 4, b"\x00"), "bad_version")
    add("an empty peer id", base[:5] + b"\x00" + base[11:], "invalid_peer")
    add("a 33-byte peer id", base[:5] + b"\x21" + b"a" * 33 + base[11:], "invalid_peer")
    add("an upper-case letter in the peer id", replace(base, 6, b"C"), "invalid_peer")
    add("a peer id that starts with a dash", replace(base, 6, b"-"), "invalid_peer")
    add("a peer id that is not text", replace(base, 6, b"\xff"), "invalid_peer")
    add("a peer length of 40 and a datagram that ends first: the cut is reported before the id is judged",
        replace(base, 5, b"\x28")[:30], "truncated")
    add("sequence number zero", replace(base, 11, u64(0)), "zero_sequence")
    add("sequence number zero and nothing after the epoch: the zero is reported, not the cut",
        replace(base, 11, u64(0))[:27], "zero_sequence")
    add("a revision flag of 2", replace(base, 27, b"\x02"), "bad_revision_flag")
    add("command tag 0", replace(base, 36, b"\x00"), "unknown_command")
    add("command tag 8", replace(base, 36, b"\x08"), "unknown_command")
    add("a mute flag of 2", replace(mute, len(mute) - TAG_LEN - 1, b"\x02"), "bad_bool")
    add("group volume 101", replace(volume, last_byte, b"\x65"), "volume_out_of_range")
    add("a step of zero", replace(group, 37, b"\x00"), "delta_out_of_range")
    add("a step of +101", replace(group, 37, b"\x65"), "delta_out_of_range")
    add("a step of -101", replace(group, 37, b"\x9b"), "delta_out_of_range")
    add("a step of -128", replace(group, 37, b"\x80"), "delta_out_of_range")
    add("an empty member id", base[:37] + b"\x00" + base[45:], "invalid_member_id")
    add("an upper-case letter in the member id", replace(base, 38, b"K"), "invalid_member_id")
    add("a 65-byte member id", base[:37] + b"\x41" + b"m" * 65 + base[45:], "invalid_member_id")
    add("a member id that is not text", replace(base, 38, b"\xff"), "invalid_member_id")
    add("a relative step that names no revision", base[:27] + b"\x00" + base[36:], "relative_needs_revision")
    add("a cancel with target zero", replace(cancel, len(cancel) - TAG_LEN - 8, u64(0)), "zero_target")
    add("a cancel of itself", replace(cancel, len(cancel) - TAG_LEN - 8, u64(300)), "cancels_itself")
    add("one byte after the tag", base + b"\x00", "trailing_bytes")
    add("the tag one byte short", base[:-1], "truncated")
    add("the signed bytes only, no tag", base[:-TAG_LEN], "truncated")
    add("163 bytes: one more than the longest request, refused before it is read", by_id["X003"] + b"\x00", "too_long")
    add("a datagram of 163 zero bytes, which would not parse as anything: the length is judged first",
        b"\x00" * (MAX_DATAGRAM_LEN + 1), "too_long")
    # The order of the checks.
    add("a bad version and a bad peer: the version is reported", replace(replace(base, 4, b"\x02"), 6, b"C"), "bad_version")
    add("a bad volume and a tag one byte short: the cut is reported, not the value",
        replace(volume, last_byte, b"\x65")[:-1], "truncated")
    add("a step of zero that also names no revision: the step is reported, not the missing revision",
        replace(group_no_rev, 29, b"\x00"), "delta_out_of_range")
    add("a bad member id and a byte after the tag: the shape is reported first", replace(base, 38, b"K") + b"\x00", "trailing_bytes")
    add("a zero sequence number and an unknown command: the zero is reported",
        replace(replace(base, 11, u64(0)), 36, b"\x00"), "zero_sequence")
    # Acknowledgements.
    add("an acknowledgement under the reply magic", replace(ack, 0, b"FFCR"), "bad_magic")
    add("an acknowledgement of version 2", replace(ack, 4, b"\x02"), "bad_version")
    add("an acknowledgement of command zero", replace(ack, 11, u64(0)), "zero_sequence")
    add("an acknowledgement with one byte after the tag", ack + b"\x00", "trailing_bytes")
    add("an acknowledgement with the tag one byte short", ack[:-1], "truncated")
    add("an acknowledgement with an upper-case peer id", replace(ack, 6, b"C"), "invalid_peer")
    return cases


def build():
    problems = []
    requests = build_requests()
    acks = build_acks()
    for req in requests:
        wire = bytes.fromhex(req["wire_hex"])
        kind, got = decode(wire)
        if kind != "request" or (got["peer"], got["seq"], got["epoch"], got["rev"], got["cmd"]) != (
                req["peer"], req["seq"], req["epoch"], req["rev"], req["cmd"]):
            problems.append(f"{req['id']}: the independent decoder does not give back the encoded request")
        if got["_signing"] != bytes.fromhex(req["signing_hex"]) or got["_tag"] != bytes.fromhex(req["tag_hex"]):
            problems.append(f"{req['id']}: the decoder split the signed bytes and the tag elsewhere")
    for ack in acks:
        kind, got = decode(bytes.fromhex(ack["wire_hex"]))
        if kind != "ack" or (got["peer"], got["seq"], got["epoch"]) != (ack["peer"], ack["seq"], ack["epoch"]):
            problems.append(f"{ack['id']}: the independent decoder does not give back the encoded acknowledgement")
    longest = max(len(bytes.fromhex(r["wire_hex"])) for r in requests)
    if longest != MAX_REQUEST_LEN:
        problems.append(f"the longest request vector is {longest} bytes, the stated bound is {MAX_REQUEST_LEN}")
    longest_ack = max(len(bytes.fromhex(a["wire_hex"])) for a in acks)
    if longest_ack != MAX_ACK_LEN:
        problems.append(f"the longest acknowledgement vector is {longest_ack} bytes, the stated bound is {MAX_ACK_LEN}")
    kinds = {r["cmd"]["kind"] for r in requests}
    if kinds != set(COMMAND_TAGS):
        problems.append(f"the vectors do not cover every command: missing {sorted(set(COMMAND_TAGS) - kinds)}")
    malformed = build_malformed(requests, acks)
    for case in malformed:
        try:
            decode(bytes.fromhex(case["wire_hex"]))
            problems.append(f"{case['id']}: the independent decoder accepts it, expected {case['error']}")
        except WireError as err:
            if err.code != case["error"]:
                problems.append(f"{case['id']}: the independent decoder says {err.code}, expected {case['error']}")
    doc = {
        "schema": "ffw.n02.request_wire_vectors.v1",
        "notes": [
            "Written by tests/n02/gen_request_wire_vectors.py from docs/contracts/n02.md section 9.3. The layout, the errors, their order and every expected result are hand-written; only the HMAC tags are computed (standard library).",
            "wire = signing bytes || 32-byte tag; the signing bytes are exactly what RequestBody::signing_bytes covers, and tag = HMAC-SHA256(key, \"FFCP-v1-auth\" || signing bytes), the request's proof. An acknowledgement is the same under the magic FFCA.",
            "X101..X105 are the hand-written signing vectors N02-W001..W005 of n02_scenarios.json, whose tags equal that file's auth vectors.",
            "A malformed input must fail to decode with the named error, before any tag is looked at; where it has several faults the error is the first in the stated order.",
        ],
        "context": AUTH_CONTEXT.decode("ascii"),
        "max_request_len": MAX_REQUEST_LEN,
        "max_ack_len": MAX_ACK_LEN,
        "max_datagram_len": MAX_DATAGRAM_LEN,
        "requests": requests,
        "acks": acks,
        "malformed": malformed,
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
    counts = f"{len(doc['requests'])} requests, {len(doc['acks'])} acknowledgements, {len(doc['malformed'])} malformed"
    if args.write:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {counts} to {path}")
        return 0
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        print("the committed request wire vectors differ from the generator's output; run --write", file=sys.stderr)
        return 1
    print(f"N02 request wire vectors: PASS ({counts})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
