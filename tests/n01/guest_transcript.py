#!/usr/bin/env python3
"""Judge for the N01 vector replay transcript (bead ffw-ey5, contract section 7, "across endianness").

The Rust side (`crates/franken-stream/examples/n01_wire_guest.rs`, sharing `tests/n01_replay/mod.rs` with the
integration test) replays every committed wire and negotiation vector through the real decoder, encoder,
receiver and negotiation code, and prints one line per result. A big-endian guest runs it under QEMU; this file
judges the log WITHOUT trusting the Rust's own comparisons: every expectation is re-derived here from the vector
files and from the independent Python frame reference (`reference_frames.py`).

Transcript grammar (ASCII; one line each; the judge ignores every line that does not start with `N01-`):

    N01-GUEST v=1 endian=<big|little> pointer_bits=<n> probe_native=<hex16> probe_be=<hex16> probe_le=<hex16>
    N01-WIRE <vector id> verdict=<ACCEPT|CODE> fields=<ok|differ|na> reencode=<ok|differ|na> fnv=<hex16>
    N01-SCEN <scenario id> steps=<n> accepted=<n> outcomes_fnv=<hex16> mismatches=<n>
    N01-NEG <negotiation id> offer=<ok|differ> answer=<ok|differ> transcript=<ok|differ> selection=<ok|differ> roundtrip=<ok|differ>
    N01-NEGREJ <rejection id> op=<respond|finish> verdict=<ACCEPT|CODE>
    N01-PLANT <name> verdict=<ACCEPT|CODE>
    N01-MISMATCH <free text>                      (never expected; any such line fails the judge)
    N01-DONE wire=<n> scen=<n> neg=<n> negrej=<n> plant=<n> mismatches=<n>

    guest_transcript.py LOG [--endian big|little]      judge a log (exit 0 only if every check holds)

WHAT A PASS MEANS. With `--endian big` it means: a program that reported itself big-endian, with a byte-order probe
that agrees, produced for every committed vector exactly the verdict the vector file and the Python reference
require, re-encoded every accepted datagram byte for byte, and rejected the planted datagrams. It does not say that
the program ran on a particular machine: that is the QEMU runner's receipt (machine, kernel, ELF class), which this
judge neither produces nor sees. It also says nothing about the media key bytes of a negotiated session, which the
crate does not expose; they are checked indirectly (transcript digest, sender-to-receiver round trip).
"""

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_frames as rf  # noqa: E402

ROOT = rf.ROOT
WIRE_VECTORS = rf.DEFAULT_VECTORS
NEG_VECTORS = ROOT / "crates" / "franken-stream" / "tests" / "vectors" / "n01_negotiation_vectors.json"

PROBE_BE = "0102030405060708"
PROBE_LE = "0807060504030201"
PLANT_BASE = "N01-GV-001"
# Hand-written, from the contract: what each planted datagram must do.
PLANT_EXPECTED = {
    "untouched": "ACCEPT",
    "resigned_untouched": "ACCEPT",  # control: the re-signer reproduces a genuine tag
    "payload_bit_flipped": "AUTH_FAILED",
    "tag_bit_flipped": "AUTH_FAILED",
    # An authentic datagram whose frame count was written in little-endian order (01 00 became 00 01): the MAC is
    # valid, so only the structure can refuse it. 256 frames became 1, against a 1024-byte payload.
    "frame_count_little_endian_resigned": "FRAME_COUNT_MISMATCH",
}
NEG_FLAGS = ("offer", "answer", "transcript", "selection", "roundtrip")


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------ expectations


def plant_wires(wire_doc):
    """The five planted datagrams, built with the Python reference from the base vector."""
    key = bytes.fromhex(wire_doc["key_hex"])
    base = next(v for v in wire_doc["vectors"] if v["id"] == PLANT_BASE)
    wire = bytes.fromhex(base["wire_hex"])

    def resign(data):
        body = data[:-rf.TAG_LEN]
        return body + rf.tag(key, body[: rf.HEADER_LEN], body[rf.HEADER_LEN:])

    payload_flip = bytearray(wire)
    payload_flip[rf.HEADER_LEN] ^= 0x01
    tag_flip = bytearray(wire)
    tag_flip[-1] ^= 0x01
    swapped = bytearray(wire)
    swapped[60], swapped[61] = swapped[61], swapped[60]
    return key, {
        "untouched": wire,
        "resigned_untouched": resign(wire),
        "payload_bit_flipped": bytes(payload_flip),
        "tag_bit_flipped": bytes(tag_flip),
        "frame_count_little_endian_resigned": resign(bytes(swapped)),
    }


def derived_plant_verdicts(wire_doc):
    """What the independent Python decoder says about each planted datagram."""
    key, wires = plant_wires(wire_doc)
    return {name: rf.decode(wire, key)[0] for name, wire in wires.items()}


def scenario_outcomes(scenario):
    return [s["expect"] for s in scenario["steps"] if s["op"] == "datagram"]


def expected_lines(wire_doc, neg_doc, endian="big", pointer_bits=32):
    """The transcript a correct program must print: used to build good logs in tests and as the judge's reference."""
    native = PROBE_BE if endian == "big" else PROBE_LE
    lines = ["N01-GUEST v=1 endian=%s pointer_bits=%d probe_native=%s probe_be=%s probe_le=%s" % (
        endian, pointer_bits, native, PROBE_BE, PROBE_LE)]
    for v in wire_doc["vectors"]:
        accept = v["expect"] == "ACCEPT"
        lines.append("N01-WIRE %s verdict=%s fields=%s reencode=%s fnv=%016x" % (
            v["id"], v["expect"], "ok" if accept else "na", "ok" if accept else "na",
            fnv1a64(bytes.fromhex(v["wire_hex"]))))
    for sc in wire_doc["scenarios"]:
        outcomes = scenario_outcomes(sc)
        lines.append("N01-SCEN %s steps=%d accepted=%d outcomes_fnv=%016x mismatches=0" % (
            sc["id"], len(outcomes), sc["expect_accepted"], fnv1a64("\n".join(outcomes).encode())))
    for n in neg_doc["negotiations"]:
        lines.append("N01-NEG %s %s" % (n["id"], " ".join("%s=ok" % f for f in NEG_FLAGS)))
    for r in neg_doc["rejections"]:
        lines.append("N01-NEGREJ %s op=%s verdict=%s" % (r["id"], r["op"], r["expect"]))
    for name in PLANT_EXPECTED:
        lines.append("N01-PLANT %s verdict=%s" % (name, PLANT_EXPECTED[name]))
    lines.append("N01-DONE wire=%d scen=%d neg=%d negrej=%d plant=%d mismatches=0" % (
        len(wire_doc["vectors"]), len(wire_doc["scenarios"]), len(neg_doc["negotiations"]),
        len(neg_doc["rejections"]), len(PLANT_EXPECTED)))
    return lines


# ---------------------------------------------------------------------------------------------- parsing

LINE = re.compile(r"^\s*(N01-[A-Z]+)(?:\s+(.*?))?\s*$")


def parse(text):
    """([(tag, id or None, {key: value}, raw line)], [unreadable lines])."""
    records, bad = [], []
    for number, raw in enumerate(text.replace("\r", "").splitlines(), 1):
        match = LINE.match(raw)
        if not match:
            continue
        tag, rest = match.group(1), match.group(2) or ""
        ident, pairs, ok = None, {}, True
        for token in rest.split():
            if "=" in token:
                key, _, value = token.partition("=")
                if not key or key in pairs:
                    ok = False
                pairs[key] = value
            elif ident is None and tag != "N01-MISMATCH":
                ident = token
            elif tag != "N01-MISMATCH":
                ok = False
        if tag == "N01-MISMATCH":
            ident = None
            pairs = {"text": rest}
        if not ok:
            bad.append("line %d: unreadable `%s`" % (number, raw.strip()[:100]))
            continue
        records.append((tag, ident, pairs, raw))
    return records, bad


# ------------------------------------------------------------------------------------------------ judge


def judge(text, wire_doc, neg_doc, expect_endian=None):
    """Every problem with the log (a list of strings); empty means it passed."""
    records, problems = parse(text)
    by_tag = {}
    for tag, ident, pairs, raw in records:
        by_tag.setdefault(tag, []).append((ident, pairs))
    known = {"N01-GUEST", "N01-WIRE", "N01-SCEN", "N01-NEG", "N01-NEGREJ", "N01-PLANT", "N01-MISMATCH", "N01-DONE"}
    for tag in sorted(set(by_tag) - known):
        problems.append("unknown record kind %s" % tag)
    for _ident, pairs in by_tag.get("N01-MISMATCH", []):
        problems.append("the program reported a mismatch of its own: %s" % pairs.get("text", "")[:100])

    # 1. the byte-order probe: the program must say what it is, and the bytes must agree with what it says
    guests = by_tag.get("N01-GUEST", [])
    if len(guests) != 1:
        problems.append("expected exactly one N01-GUEST line, found %d" % len(guests))
    else:
        _, g = guests[0]
        endian = g.get("endian")
        if g.get("v") != "1":
            problems.append("transcript version %r, expected 1" % g.get("v"))
        if endian not in ("big", "little"):
            problems.append("endian=%r is neither big nor little" % endian)
        if g.get("probe_be") != PROBE_BE or g.get("probe_le") != PROBE_LE:
            problems.append("the probe's own big- and little-endian renderings are wrong: %r %r" % (
                g.get("probe_be"), g.get("probe_le")))
        want_native = {"big": PROBE_BE, "little": PROBE_LE}.get(endian)
        if want_native is not None and g.get("probe_native") != want_native:
            problems.append("the program says %s-endian but its native bytes are %s (a %s-endian machine writes %s)" % (
                endian, g.get("probe_native"), endian, want_native))
        if g.get("pointer_bits") not in ("32", "64"):
            problems.append("pointer_bits=%r" % g.get("pointer_bits"))
        if expect_endian is not None and endian != expect_endian:
            problems.append("this log is from a %s-endian run, and a %s-endian run was required" % (endian, expect_endian))

    # 2. the wire vectors, one line each
    def exactly_once(tag, wanted_ids, what):
        lines = by_tag.get(tag, [])
        seen = {}
        for ident, pairs in lines:
            if ident in seen:
                problems.append("%s %s appears more than once" % (what, ident))
            seen.setdefault(ident, pairs)
        for ident in sorted(set(wanted_ids) - set(seen)):
            problems.append("%s %s is missing" % (what, ident))
        for ident in sorted(x for x in set(seen) - set(wanted_ids) if x is not None):
            problems.append("%s %s is not in the vector file" % (what, ident))
        return seen

    wire = exactly_once("N01-WIRE", [v["id"] for v in wire_doc["vectors"]], "wire vector")
    for v in wire_doc["vectors"]:
        got = wire.get(v["id"])
        if got is None:
            continue
        accept = v["expect"] == "ACCEPT"
        if got.get("verdict") != v["expect"]:
            problems.append("%s: verdict %s, required %s" % (v["id"], got.get("verdict"), v["expect"]))
        if got.get("fields") != ("ok" if accept else "na"):
            problems.append("%s: fields=%s, required %s" % (v["id"], got.get("fields"), "ok" if accept else "na"))
        if got.get("reencode") != ("ok" if accept else "na"):
            problems.append("%s: reencode=%s, required %s" % (v["id"], got.get("reencode"), "ok" if accept else "na"))
        want_fnv = "%016x" % fnv1a64(bytes.fromhex(v["wire_hex"]))
        if got.get("fnv") != want_fnv:
            problems.append("%s: fnv=%s, the datagram in the vector file is %s" % (v["id"], got.get("fnv"), want_fnv))

    # 3. the scenarios: every step's outcome folded into one fingerprint
    scen = exactly_once("N01-SCEN", [s["id"] for s in wire_doc["scenarios"]], "scenario")
    for sc in wire_doc["scenarios"]:
        got = scen.get(sc["id"])
        if got is None:
            continue
        outcomes = scenario_outcomes(sc)
        want = {"steps": str(len(outcomes)), "accepted": str(sc["expect_accepted"]),
                "outcomes_fnv": "%016x" % fnv1a64("\n".join(outcomes).encode()), "mismatches": "0"}
        for key, value in want.items():
            if got.get(key) != value:
                problems.append("%s: %s=%s, required %s" % (sc["id"], key, got.get(key), value))

    # 4. the negotiations and their rejections
    neg = exactly_once("N01-NEG", [n["id"] for n in neg_doc["negotiations"]], "negotiation")
    for n in neg_doc["negotiations"]:
        got = neg.get(n["id"])
        if got is None:
            continue
        for flag in NEG_FLAGS:
            if got.get(flag) != "ok":
                problems.append("%s: %s=%s, required ok" % (n["id"], flag, got.get(flag)))
    negrej = exactly_once("N01-NEGREJ", [r["id"] for r in neg_doc["rejections"]], "rejection")
    for r in neg_doc["rejections"]:
        got = negrej.get(r["id"])
        if got is None:
            continue
        if got.get("verdict") != r["expect"]:
            problems.append("%s: verdict %s, required %s" % (r["id"], got.get("verdict"), r["expect"]))
        if got.get("op") != r["op"]:
            problems.append("%s: op=%s, required %s" % (r["id"], got.get("op"), r["op"]))

    # 5. the planted datagrams: the rejections and the permitted positives
    plant = exactly_once("N01-PLANT", list(PLANT_EXPECTED), "planted datagram")
    for name, want in PLANT_EXPECTED.items():
        got = plant.get(name)
        if got is not None and got.get("verdict") != want:
            problems.append("planted %s: verdict %s, required %s" % (name, got.get("verdict"), want))

    # 6. the program's own count, which must agree with what was seen
    done = by_tag.get("N01-DONE", [])
    if len(done) != 1:
        problems.append("expected exactly one N01-DONE line, found %d (a truncated run has none)" % len(done))
    else:
        _, d = done[0]
        want = {"wire": len(wire_doc["vectors"]), "scen": len(wire_doc["scenarios"]), "neg": len(neg_doc["negotiations"]),
                "negrej": len(neg_doc["rejections"]), "plant": len(PLANT_EXPECTED), "mismatches": 0}
        for key, value in want.items():
            if d.get(key) != str(value):
                problems.append("N01-DONE %s=%s, required %d" % (key, d.get(key), value))
        if records and records[-1][0] != "N01-DONE":
            problems.append("N01-DONE is not the last record")
    return problems


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    expect = None
    if "--endian" in argv:
        at = argv.index("--endian")
        if at + 1 >= len(argv) or argv[at + 1] not in ("big", "little"):
            print("usage: guest_transcript.py LOG [--endian big|little]", file=sys.stderr)
            return 2
        expect = argv[at + 1]
        del argv[at:at + 2]
    if len(argv) != 1:
        print("usage: guest_transcript.py LOG [--endian big|little]", file=sys.stderr)
        return 2
    text = Path(argv[0]).read_text(encoding="utf-8", errors="replace")
    wire_doc, neg_doc = load(WIRE_VECTORS), load(NEG_VECTORS)
    problems = judge(text, wire_doc, neg_doc, expect)
    for p in problems:
        print("FAIL", p)
    verdict = "FAIL" if problems else "PASS"
    print("N01 guest transcript: %d wire vectors, %d scenarios, %d negotiations, %d rejections, %d plants%s: %s" % (
        len(wire_doc["vectors"]), len(wire_doc["scenarios"]), len(neg_doc["negotiations"]),
        len(neg_doc["rejections"]), len(PLANT_EXPECTED),
        (", %s-endian required" % expect) if expect else "", verdict))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
