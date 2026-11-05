"""Checks on the N01 negotiation reference itself (bead ffw-ey5), run by scripts/e2e/n01.

They establish that the Python reference is trustworthy as an oracle for the Rust negotiation: its
selection rule matches hand-written expectations, its message bytes match a layout derived by hand
from the contract, its key derivation is recomputed here step by step, its downgrade handling
catches each attack, and its error names are the ones the Rust source declares. They do not
exercise the Rust code.
"""

import hashlib
import hmac
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_negotiation as rn  # noqa: E402

RUST_NEGOTIATION = rn.rf.ROOT / "crates" / "franken-stream" / "src" / "negotiation.rs"


def load():
    return json.loads(rn.DEFAULT_VECTORS.read_text(encoding="utf-8"))


def case(cid):
    return next(c for c in load()["negotiations"] if c["id"] == cid)


def future(wire_min=1, wire_max=3, optional=rn.KNOWN_FEATURES | (1 << 20), formats=0b11):
    return rn.caps(wire_min=wire_min, wire_max=wire_max, formats=formats, optional=optional)


def honest_pair(a, b):
    """An exchange between stand-in firmware that need not be implementable by this build."""
    _, offer = rn.make_offer(rn.KEY, a, enforce_local=False)
    code, result = rn.respond(rn.KEY, b, rn.RECEIVER_PEER, 0, bytes(range(0x20, 0x30)), offer,
                              enforce_local=False)
    assert code == "OK", code
    return offer, result[0]


class Selection(unittest.TestCase):
    def test_old_and_new_firmware_use_the_highest_common_version_and_only_common_features(self):
        code, sel = rn.select(future(), rn.OLD_FIRMWARE)
        self.assertEqual((code, sel), ("OK", {"wire_version": 1, "format": 1, "max_payload_bytes": 1024, "features": 0}))
        code, sel = rn.select(future(), rn.BASELINE)
        self.assertEqual(sel["features"], rn.KNOWN_FEATURES)
        code, sel = rn.select(future(), future())
        self.assertEqual((sel["wire_version"], sel["features"]), (3, 0x100003))

    def test_selection_is_symmetric(self):
        for a, b in [(future(), rn.OLD_FIRMWARE), (rn.BASELINE, future()), (future(), future())]:
            self.assertEqual(rn.select(a, b), rn.select(b, a))

    def test_disjoint_versions_and_adjacent_versions(self):
        self.assertEqual(rn.select(rn.OLD_FIRMWARE, rn.caps(wire_min=2, wire_max=3))[0], "NO_COMMON_VERSION")
        self.assertEqual(rn.select(rn.caps(wire_max=2), rn.caps(wire_min=2, wire_max=3))[1]["wire_version"], 2)

    def test_mandatory_features_are_fatal_in_either_direction_unless_the_other_side_has_them(self):
        needs_xor = rn.caps(mandatory=rn.FEATURE_XOR, optional=rn.FEATURE_PARTIAL)
        self.assertEqual(rn.select(needs_xor, rn.OLD_FIRMWARE)[0], "MANDATORY_FEATURE_MISSING")
        self.assertEqual(rn.select(rn.OLD_FIRMWARE, needs_xor)[0], "MANDATORY_FEATURE_MISSING")
        self.assertEqual(rn.select(rn.caps(mandatory=1 << 20, optional=0), rn.BASELINE)[0],
                         "MANDATORY_FEATURE_MISSING")
        code, sel = rn.select(needs_xor, rn.BASELINE)
        self.assertEqual((code, sel["features"]), ("OK", rn.KNOWN_FEATURES))

    def test_formats_and_limits(self):
        self.assertEqual(rn.select(rn.caps(formats=0b10), rn.OLD_FIRMWARE)[0], "NO_COMMON_FORMAT")
        self.assertEqual(rn.select(rn.caps(formats=0b11), rn.caps(formats=0b10))[1]["format"], 0b10)
        self.assertEqual(rn.select(rn.caps(formats=0b11), rn.caps(formats=0b11))[1]["format"], 0b01)
        self.assertEqual(rn.select(rn.caps(max_payload=512), rn.OLD_FIRMWARE)[0], "LIMITS_INCOMPATIBLE")
        self.assertEqual(rn.select(rn.caps(max_payload=4096), rn.caps(max_payload=4096))[1]["max_payload_bytes"], 1024)

    def test_malformed_claims(self):
        for bad in (rn.caps(wire_min=0), rn.caps(wire_min=2, wire_max=1), rn.caps(formats=0),
                    rn.caps(max_payload=6), rn.caps(max_payload=0), rn.caps(mandatory=1, optional=1)):
            self.assertEqual(rn.select(bad, rn.OLD_FIRMWARE)[0], "INVALID_CAPABILITIES", bad)


class WireAndKeys(unittest.TestCase):
    def test_offer_bytes_equal_a_layout_derived_by_hand(self):
        offer = bytes.fromhex(case("N01-NG-002")["offer_hex"])
        body = bytes.fromhex(
            "4646574e"            # magic FFWN
            "01" "01" "00"        # message version 1, kind offer, flags 0
            "01" "01" "01"        # wire 1..=1, formats PCM
            "0400"                # max payload 1024
            "00000000"            # mandatory features
            "00000003"            # optional features: XOR parity + partial final block
            "aa00000000000001"    # sender peer
            "00c0ffee00000001"    # stream
            "0000000000000007"    # epoch
            "101112131415161718191a1b1c1d1e1f"  # nonce
            "00" "00" "0000" "00000000"         # selection: all zero in an offer
            + "00" * 32           # offer digest: zero in an offer
        )
        self.assertEqual(len(body), 100)
        self.assertEqual(offer[:100], body)
        self.assertEqual(len(offer), 116)

    def test_answer_carries_the_selection_and_the_digest_of_the_exact_offer(self):
        c = case("N01-NG-002")
        offer, answer = bytes.fromhex(c["offer_hex"]), bytes.fromhex(c["answer_hex"])
        self.assertEqual(answer[60:68].hex(), "0101" "0400" "00000003")
        self.assertEqual(answer[68:100], hashlib.sha256(offer).digest())

    def test_tags_cover_a_context_and_the_whole_body(self):
        offer = bytes.fromhex(case("N01-NG-002")["offer_hex"])
        want = hmac.new(rn.KEY, b"FFWS-v1-hello" + offer[:100], hashlib.sha256).digest()[:16]
        self.assertEqual(offer[100:], want)
        self.assertNotEqual(hmac.new(rn.KEY, offer[:100], hashlib.sha256).digest()[:16], want)

    def test_media_key_is_recomputed_step_by_step_from_the_transcript(self):
        for cid in ("N01-NG-001", "N01-NG-002", "N01-NG-003"):
            c = case(cid)
            offer, answer = bytes.fromhex(c["offer_hex"]), bytes.fromhex(c["answer_hex"])
            transcript = hashlib.sha256(b"FFWS-v1-transcript" + offer + answer).digest()
            key = hmac.new(rn.KEY, b"FFWS-v1-session-key" + transcript, hashlib.sha256).digest()
            self.assertEqual(c["transcript_hex"], transcript.hex(), cid)
            self.assertEqual(c["session_key_hex"], key.hex(), cid)
            self.assertNotEqual(key, rn.KEY)

    def test_any_change_to_either_message_changes_the_key(self):
        c = case("N01-NG-002")
        offer, answer = bytes.fromhex(c["offer_hex"]), bytes.fromhex(c["answer_hex"])
        _, base_key = rn.derive(rn.KEY, offer, answer)
        for index in range(0, 116, 7):
            changed = bytearray(answer)
            changed[index] ^= 1
            self.assertNotEqual(rn.derive(rn.KEY, offer, bytes(changed))[1], base_key)


class Downgrade(unittest.TestCase):
    def test_stripping_a_higher_version_in_flight_fails_authentication(self):
        _, offer = rn.make_offer(rn.KEY, future(), enforce_local=False)
        stripped = bytearray(offer)
        stripped[8] = 1  # wire_max 3 -> 1
        code, _ = rn.respond(rn.KEY, future(), rn.RECEIVER_PEER, 0, bytes(range(0x20, 0x30)), bytes(stripped),
                             enforce_local=False)
        self.assertEqual(code, "HELLO_AUTH_FAILED")

    def test_a_re_signed_modified_offer_is_caught_by_the_initiator_through_the_digest(self):
        offer, _ = honest_pair(future(), future())
        modified = rn.fields_of(offer)
        modified["caps"] = {**modified["caps"], "wire_max": 1}
        modified_wire = rn.build(rn.KEY, modified)
        code, result = rn.respond(rn.KEY, future(), rn.RECEIVER_PEER, 0, bytes(range(0x20, 0x30)), modified_wire,
                                  enforce_local=False)
        self.assertEqual(code, "OK")
        self.assertEqual(rn.finish(rn.KEY, offer, result[0])[0], "OFFER_DIGEST_MISMATCH")

    def test_an_answer_selecting_a_lower_version_than_both_support_is_a_downgrade(self):
        two = rn.caps(wire_max=2)
        offer, answer = honest_pair(two, two)
        self.assertEqual(rn.fields_of(answer)["selection"]["wire_version"], 2)
        f = rn.fields_of(answer)
        f["selection"] = {**f["selection"], "wire_version": 1}
        self.assertEqual(rn.finish(rn.KEY, offer, rn.build(rn.KEY, f))[0], "DOWNGRADE_DETECTED")
        self.assertEqual(rn.finish(rn.KEY, offer, answer)[0], "OK")

    def test_stripped_or_inflated_selection_is_a_mismatch_not_a_downgrade(self):
        offer, answer = honest_pair(rn.BASELINE, rn.BASELINE)
        f = rn.fields_of(answer)
        stripped = {**f, "selection": {**f["selection"], "features": rn.FEATURE_PARTIAL}}
        inflated = {**f, "selection": {**f["selection"], "wire_version": 3}}
        self.assertEqual(rn.finish(rn.KEY, offer, rn.build(rn.KEY, stripped))[0], "SELECTION_MISMATCH")
        self.assertEqual(rn.finish(rn.KEY, offer, rn.build(rn.KEY, inflated))[0], "SELECTION_MISMATCH")

    def test_an_old_answer_does_not_answer_a_new_offer(self):
        _, old_answer = honest_pair(rn.BASELINE, rn.BASELINE)
        _, new_offer = rn.make_offer(rn.KEY, rn.BASELINE, nonce=bytes(range(0x30, 0x40)))
        self.assertEqual(rn.finish(rn.KEY, new_offer, old_answer)[0], "OFFER_DIGEST_MISMATCH")

    def test_a_different_transcript_gives_a_different_media_key(self):
        offer_a, answer_a = honest_pair(rn.BASELINE, rn.BASELINE)
        _, offer_b = rn.make_offer(rn.KEY, rn.BASELINE, nonce=bytes(range(0x30, 0x40)))
        code, result = rn.respond(rn.KEY, rn.BASELINE, rn.RECEIVER_PEER, 0, bytes(range(0x20, 0x30)), offer_b)
        self.assertEqual(code, "OK")
        self.assertNotEqual(rn.derive(rn.KEY, offer_a, answer_a)[1], result[3])


class GeneratedDocument(unittest.TestCase):
    def test_committed_vectors_equal_a_fresh_generation(self):
        self.assertEqual(rn.DEFAULT_VECTORS.read_text(encoding="utf-8"), rn.render(rn.build_document()))

    def test_every_recorded_expectation_holds(self):
        self.assertEqual(rn.self_verify(load()), [])

    def test_every_vectorable_rejection_code_has_a_case(self):
        covered = {r["expect"] for r in load()["rejections"]}
        self.assertEqual([c for c in rn.NEGOTIATION_CODES if c not in covered and c not in rn.NOT_VECTORED], [])

    def test_changing_any_byte_of_an_offer_or_answer_makes_it_unacceptable(self):
        for cid in ("N01-NG-001", "N01-NG-002", "N01-NG-003"):
            c = case(cid)
            offer, answer = bytes.fromhex(c["offer_hex"]), bytes.fromhex(c["answer_hex"])
            for index in range(len(offer)):
                bad = bytearray(offer)
                bad[index] ^= 0x01
                code, _ = rn.respond(rn.KEY, rn.caps_of(c["receiver_caps"]), c["receiver_peer"], 0,
                                     bytes.fromhex(c["answer_nonce_hex"]), bytes(bad))
                self.assertNotEqual(code, "OK", f"{cid} offer byte {index}")
                bad = bytearray(answer)
                bad[index] ^= 0x01
                self.assertNotEqual(rn.finish(rn.KEY, offer, bytes(bad))[0], "OK", f"{cid} answer byte {index}")


class RustSourceAgreement(unittest.TestCase):
    def source(self):
        return RUST_NEGOTIATION.read_text(encoding="utf-8")

    def test_rust_error_names_are_the_contract_names(self):
        source = self.source()
        start = source.index("pub const fn code(&self)")
        end = source.index("\n    }\n}", start)
        rust = set(re.findall(r'=> "([A-Z_]+)"', source[start:end]))
        self.assertEqual(sorted(rust ^ set(rn.NEGOTIATION_CODES)), [])

    def test_rust_wire_constants_and_contexts_match_the_reference(self):
        source = self.source()
        for pattern in (
            rf"pub const HELLO_BODY_BYTES: usize = {rn.BODY_LEN};",
            rf"pub const HELLO_TAG_BYTES: usize = {rn.TAG_LEN};",
            rf"pub const HELLO_VERSION: u8 = {rn.HELLO_VERSION};",
            r'pub const HELLO_MAGIC: \[u8; 4\] = \*b"FFWN";',
            r'const HELLO_AUTH_CONTEXT: &\[u8\] = b"FFWS-v1-hello";',
            r'const TRANSCRIPT_CONTEXT: &\[u8\] = b"FFWS-v1-transcript";',
            r'const SESSION_KEY_CONTEXT: &\[u8\] = b"FFWS-v1-session-key";',
            r"pub const FEATURE_XOR_PARITY_FEC: u32 = 0b01;",
            r"pub const FEATURE_PARTIAL_FINAL_BLOCK: u32 = 0b10;",
            r"pub const FORMAT_PCM16_BE_STEREO_48K: u8 = 0b01;",
        ):
            self.assertRegex(source, pattern)

    def test_rust_field_offsets_match_the_struct_format(self):
        source = self.source()
        offsets = {name: int(value) for name, value in re.findall(r"const (OFF_[A-Z_]+): usize = (\d+);", source)}
        expected = {
            "OFF_KIND": 5, "OFF_FLAGS": 6, "OFF_WIRE_MIN": 7, "OFF_WIRE_MAX": 8, "OFF_FORMATS": 9,
            "OFF_MAX_PAYLOAD": 10, "OFF_MANDATORY": 12, "OFF_OPTIONAL": 16, "OFF_PEER": 20,
            "OFF_STREAM": 28, "OFF_EPOCH": 36, "OFF_NONCE": 44, "OFF_SEL_VERSION": 60,
            "OFF_SEL_FORMAT": 61, "OFF_SEL_MAX_PAYLOAD": 62, "OFF_SEL_FEATURES": 64, "OFF_DIGEST": 68,
        }
        self.assertEqual(offsets, expected)
        # The reference's struct format puts each field at the same offset.
        fmt = rn.HELLO
        # Distinct values in field order: version 1, kind 2, flags 3, wire min 4, wire max 5, formats 6,
        # max payload 7, mandatory 8, optional 9, peer 10, stream 11, epoch 12, then the selection.
        probe = fmt.pack(b"FFWN", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, b"n" * 16, 13, 14, 15, 16, b"d" * 32)
        self.assertEqual((probe[4], probe[5], probe[6], probe[7], probe[8], probe[9]), (1, 2, 3, 4, 5, 6))
        self.assertEqual(int.from_bytes(probe[10:12], "big"), 7)
        self.assertEqual(int.from_bytes(probe[12:16], "big"), 8)
        self.assertEqual(int.from_bytes(probe[16:20], "big"), 9)
        self.assertEqual(int.from_bytes(probe[20:28], "big"), 10)
        self.assertEqual(int.from_bytes(probe[28:36], "big"), 11)
        self.assertEqual(int.from_bytes(probe[36:44], "big"), 12)
        self.assertEqual(probe[44:60], b"n" * 16)
        self.assertEqual((probe[60], probe[61]), (13, 14))
        self.assertEqual(int.from_bytes(probe[62:64], "big"), 15)
        self.assertEqual(int.from_bytes(probe[64:68], "big"), 16)
        self.assertEqual(probe[68:100], b"d" * 32)


if __name__ == "__main__":
    unittest.main()
