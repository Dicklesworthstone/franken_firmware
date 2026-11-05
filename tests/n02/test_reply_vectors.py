"""Checks on the authenticated-reply vectors (N02 section 9.1, bead ffw-ugf), run by scripts/e2e/n02.

They establish that the committed vectors are exactly what the generator writes, that a decoder and a verifier written
independently from the specification reproduce every expected result, that every tamper changes exactly one signed
field, and, with an unbroken implementation shown to pass first, that each of a set of deliberately broken ones is
caught by a named vector, so the vectors can fail an implementation. They do not exercise the Rust code.
"""

import hmac
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_reply_vectors as gen  # noqa: E402

ROOT = gen.ROOT
CHANNEL_SRC = ROOT / "crates" / "franken-control" / "src" / "channel"
CASES = Path(__file__).resolve().parent / "cases.json"


def vectors():
    return json.loads(gen.DEFAULT_OUT.read_text(encoding="utf-8"))


def expect_of(v):
    return v["expect"]


# --------------------------------------------------------------------------- implementations under test

def run_verify(vector, decode=gen.decode, order=("tag", "command", "request", "fresh"), skip=(), context=gen.REPLY_CONTEXT,
               mac_prefix_cut=0):
    """The independent verifier, with one fault applied if asked. Returns "accepted", a rejection name, or
    `error:<decode error>`. `skip` drops checks, `order` reorders them, `context` is the label the tag is computed under,
    `mac_prefix_cut` leaves that many trailing signed bytes out of the MAC."""
    key = vector["key"].encode("ascii")
    expect = expect_of(vector)
    try:
        reply = decode(bytes.fromhex(vector["wire_hex"]))
    except gen.ReplyError as err:
        return f"error:{err.code}"
    signed = reply["_signing"]
    signed = signed[:len(signed) - mac_prefix_cut] if mac_prefix_cut else signed
    checks = {
        "tag": lambda: None if hmac.compare_digest(gen.tag_of(key, signed, context), reply["_tag"]) else "bad_tag",
        "command": lambda: None if (reply["peer"], reply["seq"]) == (expect["peer"], expect["seq"]) else "wrong_command",
        "request": lambda: None if reply["request_digest_hex"] == expect["request_digest_hex"] else "wrong_request",
        "fresh": lambda: None if (reply["epoch"], reply["revision"]) >= (expect["seen_epoch"], expect["seen_revision"]) else "stale",
    }
    for name in order:
        if name in skip:
            continue
        outcome = checks[name]()
        if outcome:
            return outcome
    return "accepted"


def swallowing(*codes):
    """A decoder that lets the named errors through, as a lenient one would."""
    def decode(wire):
        try:
            return gen.decode(wire)
        except gen.ReplyError as err:
            if err.code in codes:
                # Parse what a lenient decoder would see: re-run on the signed part, ignoring the fault.
                return lenient_parse(wire, err.code)
            raise
    return decode


def lenient_parse(wire, ignored):
    """Decode `wire` as the strict decoder does, except that the named fault is not an error."""
    if ignored == "trailing_bytes":
        return gen.decode(wire[:-1])
    probe = bytearray(wire)
    if ignored == "bad_magic":
        probe[0:4] = gen.MAGIC
        return gen.decode(bytes(probe))
    if ignored == "bad_version":
        probe[4] = gen.VERSION
        return gen.decode(bytes(probe))
    # Faults deep in the body (zero sequence, non-canonical numbers, a lane code of 2): decode with the strictness lifted.
    saved = (gen.ReplyError, )
    del saved
    return decode_lenient_body(wire, ignored)


def decode_lenient_body(wire, ignored):
    """A second, deliberately sloppy decoder: it is the unbroken one with one check removed."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(wire):
            raise gen.ReplyError("truncated")
        chunk = wire[pos:pos + n]
        pos += n
        return chunk

    take(4), take(1)
    n = take(1)[0]
    text = take(n).decode("latin-1")
    seq, epoch, revision = (int.from_bytes(take(8), "big") for _ in range(3))
    if seq == 0 and ignored != "zero_sequence":
        raise gen.ReplyError("zero_sequence")
    digest = take(32)
    tag = take(1)[0]
    names = {v: k for k, v in gen.STATUS_TAGS.items()}
    kind = names[tag]
    status = {"kind": kind}
    if kind in ("queued", "already_queued"):
        status["lane"] = "ordinary" if take(1)[0] == 0 else "priority"
    elif kind == "committed":
        status["revision"] = int.from_bytes(take(8), "big")
    elif kind == "cancel_applied":
        status["target_seq"] = int.from_bytes(take(8), "big")
    elif kind == "out_of_window":
        status["floor"] = int.from_bytes(take(8), "big")
    elif kind in ("refused", "rejected"):
        take(1)
        take(16)
    end = pos
    mac = take(gen.TAG_LEN)
    return {"peer": text, "seq": seq, "epoch": epoch, "revision": revision, "request_digest_hex": digest.hex(),
            "status": status, "_signing": wire[:end], "_tag": mac}


class ReplyVectorTests(unittest.TestCase):
    def test_the_committed_file_is_what_the_generator_writes(self):
        text, problems = gen.build()
        self.assertEqual(problems, [])
        self.assertEqual(gen.DEFAULT_OUT.read_text(encoding="utf-8"), text)

    def test_the_hand_assembled_reply_is_reproduced_by_the_encoder(self):
        first = vectors()["replies"][0]
        self.assertEqual(first["id"], "R001")
        self.assertEqual(first["signing_hex"], gen.R001_HAND_HEX)
        self.assertEqual(len(bytes.fromhex(first["signing_hex"])), 76)

    def test_every_status_the_channel_can_report_has_a_vector(self):
        kinds = {r["status"]["kind"] for r in vectors()["replies"]}
        self.assertEqual(kinds, set(gen.STATUS_TAGS))
        refusals = {r["status"]["code"] for r in vectors()["replies"] if r["status"]["kind"] == "refused"}
        rejections = {r["status"]["code"] for r in vectors()["replies"] if r["status"]["kind"] == "rejected"}
        self.assertTrue(refusals <= set(gen.REFUSAL_CODES) and rejections <= set(gen.REJECTION_CODES))
        self.assertGreaterEqual(len(refusals), 4)
        self.assertGreaterEqual(len(rejections), 3)

    def test_the_codes_are_the_diagnostic_vocabulary(self):
        source = (CHANNEL_SRC / "diag.rs").read_text(encoding="utf-8")
        for name in gen.REFUSAL_CODES:
            self.assertIn(f'"{name}"', source, f"{name} is not a refusal kind in diag.rs")

    def test_the_code_numbers_are_dense_and_unique(self):
        self.assertEqual(sorted(gen.REFUSAL_CODES.values()), list(range(1, 16)))
        self.assertEqual(sorted(gen.REJECTION_CODES.values()), list(range(1, 6)))
        self.assertEqual(sorted(gen.STATUS_TAGS.values()), list(range(1, 9)))

    def test_every_tamper_changes_exactly_one_field_and_the_base_tag_fails(self):
        doc = vectors()
        by = {r["id"]: r for r in doc["replies"]}
        for t in doc["tampers"]:
            base = gen.decode(bytes.fromhex(by[t["reply"]]["wire_hex"]))
            changed = gen.decode(bytes.fromhex(t["wire_hex"]))
            self.assertNotEqual(base["_signing"], changed["_signing"], t["id"])
            self.assertEqual(base["_tag"], changed["_tag"], f"{t['id']} must keep the base tag")
            diff = {k for k in ("peer", "seq", "epoch", "revision", "request_digest_hex") if base[k] != changed[k]}
            sa, sb = base["status"], changed["status"]
            diff |= {f"status.{k}" for k in set(sa) | set(sb) if sa.get(k) != sb.get(k)}
            fields = len(diff)
            # A status-kind change is one field (the tag byte) although its payload differs; a code change with a number
            # that must be zeroed is two keys but one decision.
            self.assertTrue(fields == 1 or t["field"] in ("status kind", "rejection code"), f"{t['id']} {t['field']}: {sorted(diff)}")
            key = gen.key_for(base["peer"])
            self.assertFalse(hmac.compare_digest(gen.tag_of(key, changed["_signing"]), base["_tag"]), t["id"])

    def test_the_independent_verifier_reproduces_every_hand_written_result(self):
        for v in vectors()["verify"]:
            self.assertEqual(run_verify(v), v["result"], f"{v['id']} ({v['what']})")

    def test_the_independent_decoder_names_every_malformed_input(self):
        for m in vectors()["malformed"]:
            with self.assertRaises(gen.ReplyError, msg=m["id"]) as caught:
                gen.decode(bytes.fromhex(m["wire_hex"]))
            self.assertEqual(caught.exception.code, m["error"], f"{m['id']} ({m['what']})")

    def test_every_reply_vector_verifies_for_its_own_peer(self):
        for r in vectors()["replies"]:
            expect = {"peer": r["peer"], "seq": r["seq"], "request_digest_hex": r["request_digest_hex"], "seen_epoch": 0, "seen_revision": 0}
            self.assertEqual(gen.verify(r["key"].encode("ascii"), bytes.fromhex(r["wire_hex"]), expect), "accepted", r["id"])

    def test_a_vector_of_every_result_kind_exists(self):
        results = {v["result"] for v in vectors()["verify"]}
        self.assertEqual(results, {"accepted", "bad_tag", "wrong_command", "wrong_request", "stale"})
        errors = {m["error"] for m in vectors()["malformed"]}
        self.assertEqual(errors, {"truncated", "trailing_bytes", "bad_magic", "bad_version", "invalid_peer", "zero_sequence",
                                  "unknown_status", "unknown_kind", "bad_lane", "non_canonical"})

    # ------------------------------------------------------------ broken implementations, each caught by name

    def killers(self, **fault):
        """The ids of the verify cases an implementation with `fault` gets wrong (a verify case it judges differently)."""
        return sorted(v["id"] for v in vectors()["verify"] if run_verify(v, **fault) != v["result"])

    def test_the_unbroken_implementation_passes_before_any_fault_is_credited(self):
        self.assertEqual(self.killers(), [])
        self.assertEqual(self.decode_killers(gen.decode), [])

    def decode_killers(self, decode):
        out = []
        for m in vectors()["malformed"]:
            try:
                decode(bytes.fromhex(m["wire_hex"]))
                out.append(m["id"])  # decoded: it should have failed
            except gen.ReplyError as err:
                if err.code != m["error"]:
                    out.append(m["id"])
            except Exception:  # a sloppy decoder may fail in some other way: that is a wrong answer too
                out.append(m["id"])
        return sorted(out)

    def test_each_broken_verifier_is_caught_by_a_named_case(self):
        by_id = {v["id"]: v for v in vectors()["verify"]}
        faults = {
            "no tag check": ({"skip": ("tag",)}, "bad_tag"),
            "tag under the request context": ({"context": gen.REQUEST_CONTEXT}, "accepted"),
            "no command check": ({"skip": ("command",)}, "wrong_command"),
            "no request check": ({"skip": ("request",)}, "wrong_request"),
            "no freshness check": ({"skip": ("fresh",)}, "stale"),
            "the command checked before the tag": ({"order": ("command", "tag", "request", "fresh")}, "bad_tag"),
            "freshness checked before the tag": ({"order": ("fresh", "tag", "command", "request")}, "bad_tag"),
            "the request checked before the command": ({"order": ("tag", "request", "command", "fresh")}, "wrong_command"),
            "freshness before the command": ({"order": ("tag", "fresh", "command", "request")}, "wrong_command"),
            "a MAC that leaves out the last signed byte": ({"mac_prefix_cut": 1}, "accepted"),
        }
        for name, (fault, kind) in faults.items():
            caught = self.killers(**fault)
            self.assertTrue(caught, f"{name} survived: no verify case caught it")
            if kind != "accepted":
                self.assertTrue(any(by_id[c]["result"] == kind for c in caught), f"{name}: expected a case that expects {kind}, got {caught}")

    def test_each_lenient_decoder_is_caught_by_a_named_malformed_input(self):
        by_error = {m["id"]: m["error"] for m in vectors()["malformed"]}
        for ignored in ("trailing_bytes", "bad_magic", "bad_version", "zero_sequence"):
            caught = self.decode_killers(swallowing(ignored))
            self.assertTrue(caught, f"a decoder that ignores {ignored} survived")
            self.assertIn(ignored, {by_error[c] for c in caught})

    def test_every_tamper_is_caught_only_by_the_tag(self):
        """A verifier with no tag check accepts every tampered reply; with it, each is refused. So the tag is what catches them."""
        doc = vectors()
        by = {r["id"]: r for r in doc["replies"]}
        for t in doc["tampers"]:
            base = by[t["reply"]]
            case = {"key": base["key"], "wire_hex": t["wire_hex"],
                    "expect": {"peer": gen.decode(bytes.fromhex(t["wire_hex"]))["peer"], "seq": gen.decode(bytes.fromhex(t["wire_hex"]))["seq"],
                               "request_digest_hex": gen.decode(bytes.fromhex(t["wire_hex"]))["request_digest_hex"], "seen_epoch": 0, "seen_revision": 0}}
            self.assertEqual(run_verify(case, skip=("tag",)), "accepted", f"{t['id']}: without the tag check it would be accepted")
            self.assertEqual(run_verify(case), "bad_tag", f"{t['id']} ({t['field']})")

    def test_the_contract_states_the_wire_layout_the_vectors_use(self):
        text = (ROOT / "docs" / "contracts" / "n02.md").read_text(encoding="utf-8")
        for needle in ("FFCR", "FFCR-v1-reply", "9.1"):
            self.assertIn(needle, text, f"n02.md does not mention {needle}")
        for name in list(gen.REFUSAL_CODES) + list(gen.REJECTION_CODES):
            self.assertIn(name, text, f"n02.md does not name the code {name}")


if __name__ == "__main__":
    unittest.main()
