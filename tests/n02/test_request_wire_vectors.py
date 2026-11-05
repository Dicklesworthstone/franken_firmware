"""Checks on the request and acknowledgement wire vectors (N02 section 9.3, bead ffw-ugf), run by scripts/e2e/n02.

They establish that the committed vectors are exactly what the generator writes, that a decoder written independently from the
specification reproduces every expected result (the error and its place in the order of checks), that every valid datagram is
refused as `truncated` at every shorter length and as `trailing_bytes` with one byte more, and, with the unbroken decoder
shown to pass first, that each of a set of deliberately sloppy ones is caught by a named vector, so the vectors can fail an
implementation. They do not exercise the Rust code.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_request_wire_vectors as gen  # noqa: E402


def vectors():
    return json.loads(gen.DEFAULT_OUT.read_text(encoding="utf-8"))


def verdict(wire, flaws=frozenset()):
    """What a decoder says about `wire`: ("ok", kind, fields) or ("error", code)."""
    try:
        kind, fields = gen.decode(wire, flaws)
    except gen.WireError as err:
        return ("error", err.code)
    return ("ok", kind, {k: v for k, v in fields.items() if not k.startswith("_")})


# Each sloppy decoder and what it gets wrong, in the specification's words.
FLAWS = {
    "length_after": "judges the length after it has read the datagram",
    "magic": "accepts any magic",
    "version": "accepts any version",
    "peer": "does not judge the peer id",
    "zero_seq": "accepts sequence number zero",
    "zero_late": "judges a zero sequence number only after the whole datagram is read",
    "rev_flag": "reads any non-zero revision flag as present",
    "bool": "reads any mute byte as a flag",
    "member": "does not judge the member id",
    "volume": "accepts a volume above 100",
    "delta": "accepts a step of zero or beyond 100",
    "cancel_zero": "accepts a cancel of target zero",
    "relative": "accepts a relative step with no revision",
    "cancel_self": "accepts a cancel of itself",
    "trailing": "ignores bytes after the tag",
    "values_first": "judges values before it has seen the whole shape",
    "relative_first": "reports a missing revision before the command's own value",
}


class WireVectors(unittest.TestCase):
    def test_the_committed_file_is_what_the_generator_writes(self):
        text, problems = gen.build()
        self.assertEqual(problems, [])
        self.assertEqual(gen.DEFAULT_OUT.read_text(encoding="utf-8"), text)

    def test_the_bounds_are_the_sums_the_specification_gives(self):
        v = vectors()
        self.assertEqual(v["max_request_len"], 162)
        self.assertEqual(v["max_ack_len"], 86)
        self.assertEqual(v["max_datagram_len"], 162)
        self.assertEqual(max(len(bytes.fromhex(r["wire_hex"])) for r in v["requests"]), v["max_request_len"])
        self.assertEqual(max(len(bytes.fromhex(a["wire_hex"])) for a in v["acks"]), v["max_ack_len"])

    def test_the_independent_decoder_reproduces_every_valid_vector(self):
        v = vectors()
        for req in v["requests"]:
            kind, fields = gen.decode(bytes.fromhex(req["wire_hex"]))
            self.assertEqual(kind, "request", req["id"])
            self.assertEqual((fields["peer"], fields["seq"], fields["epoch"], fields["rev"], fields["cmd"]),
                             (req["peer"], req["seq"], req["epoch"], req["rev"], req["cmd"]), req["id"])
        for ack in v["acks"]:
            kind, fields = gen.decode(bytes.fromhex(ack["wire_hex"]))
            self.assertEqual((kind, fields["peer"], fields["seq"], fields["epoch"]), ("ack", ack["peer"], ack["seq"], ack["epoch"]), ack["id"])

    def test_the_independent_decoder_reproduces_every_error_and_its_place_in_the_order(self):
        for case in vectors()["malformed"]:
            self.assertEqual(verdict(bytes.fromhex(case["wire_hex"])), ("error", case["error"]), f"{case['id']} {case['what']}")

    def test_every_shorter_datagram_is_truncated_and_one_byte_more_is_trailing_or_too_long(self):
        v = vectors()
        for item in v["requests"] + v["acks"]:
            wire = bytes.fromhex(item["wire_hex"])
            for cut in range(len(wire)):
                self.assertEqual(verdict(wire[:cut]), ("error", "truncated"), f"{item['id']} cut to {cut}")
            longer = "too_long" if len(wire) + 1 > v["max_datagram_len"] else "trailing_bytes"
            self.assertEqual(verdict(wire + b"\x00"), ("error", longer), item["id"])

    def test_the_tags_are_the_requests_own_proofs_under_the_auth_context(self):
        import hashlib
        import hmac
        for req in vectors()["requests"]:
            signing = bytes.fromhex(req["signing_hex"])
            key = req["key"].encode("ascii")
            self.assertEqual(hmac.new(key, b"FFCP-v1-auth" + signing, hashlib.sha256).hexdigest(), req["tag_hex"], req["id"])
            self.assertEqual(req["wire_hex"], req["signing_hex"] + req["tag_hex"], req["id"])

    def test_the_unbroken_decoder_passes_and_each_sloppy_one_is_caught_by_a_named_vector(self):
        v = vectors()
        cases = [(c["id"], bytes.fromhex(c["wire_hex"]), ("error", c["error"])) for c in v["malformed"]]
        valid = [(r["id"], bytes.fromhex(r["wire_hex"]), verdict(bytes.fromhex(r["wire_hex"]))) for r in v["requests"] + v["acks"]]
        # The unbroken decoder passes everything first.
        for name, wire, want in cases + valid:
            self.assertEqual(verdict(wire), want, name)
        survivors, caught = [], {}
        for flaw in FLAWS:
            hits = [name for name, wire, want in cases + valid if verdict(wire, frozenset([flaw])) != want]
            caught[flaw] = hits
            if not hits:
                survivors.append(flaw)
        self.assertEqual(survivors, [], f"vectors that let a sloppy decoder through: {survivors}")
        # The two order flaws are caught by the vectors written for the order, not by a value vector.
        self.assertTrue(any(w["what"].startswith("a bad volume and a tag") for w in v["malformed"] if w["id"] in caught["values_first"]))
        self.assertTrue(any(w["what"].startswith("a step of zero that also") for w in v["malformed"] if w["id"] in caught["relative_first"]))
        self.assertTrue(any(w["what"].startswith("sequence number zero and nothing") for w in v["malformed"] if w["id"] in caught["zero_late"]))


if __name__ == "__main__":
    unittest.main()
