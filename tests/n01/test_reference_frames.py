"""Checks on the N01 reference itself (bead ffw-ey5), run by scripts/e2e/n01.

These establish that the Python reference is trustworthy as an oracle for the Rust crate:
its MAC primitive matches published known answers, its header matches bytes derived by hand from
the contract, its replay model agrees with hand-written expectations, and its error names are the
ones the Rust source declares. They do not exercise the Rust code.
"""

import hashlib
import hmac
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_frames as rf  # noqa: E402

RUST_LIB = rf.ROOT / "crates" / "franken-stream" / "src" / "lib.rs"
SENDER_AND_JITTER_ONLY = {
    "SEQUENCE_EXHAUSTED",
    "EPOCH_NOT_ADVANCING",
    "EXPIRED_CONSUME_BY",
    "NOT_MEDIA_PACKET",
    "PAYLOAD_FORMAT_MISMATCH",
}


def load_document():
    return json.loads(rf.DEFAULT_VECTORS.read_text(encoding="utf-8"))


class MacPrimitive(unittest.TestCase):
    def test_rfc4231_known_answers_for_hmac_sha256(self):
        cases = [
            (bytes([0x0B]) * 20, b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        ]
        for key, data, want in cases:
            self.assertEqual(hmac.new(key, data, hashlib.sha256).hexdigest(), want)

    def test_rfc4231_truncation_case_matches_the_128_bit_tag_length_used_here(self):
        # RFC 4231 test case 5: only the leftmost 128 bits are specified, which is our tag size.
        key, data = bytes([0x0C]) * 20, b"Test With Truncation"
        full = hmac.new(key, data, hashlib.sha256).digest()
        self.assertEqual(full[: rf.TAG_LEN].hex(), "a3b6167473100ee06e0c796c2955552b")


class WireLayout(unittest.TestCase):
    def test_header_format_is_exactly_64_big_endian_bytes(self):
        self.assertEqual(rf.HEADER.size, 64)
        self.assertTrue(rf.HEADER.format.startswith(">"))

    def test_probe_vector_header_equals_bytes_derived_by_hand_from_the_contract(self):
        probe = next(v for v in load_document()["vectors"] if v["name"] == "big_endian_field_probe")
        wire = bytes.fromhex(probe["wire_hex"])
        expected_header = bytes.fromhex(
            "46465753"            # magic FFWS
            "01" "02" "05" "01"   # version 1, kind repair, flags 0x05, format 1
            "0102030405060708"    # stream id
            "1112131415161718"    # epoch
            "2122232425262728"    # sequence
            "3132333435363700"    # start frame
            "0102030405060708"    # presentation time
            "0102030405060707"    # consume-by
            "abcd" "03" "04"      # fec group id, fec index, fec group size
            "0001" "0004"         # frame count, payload length
        )
        self.assertEqual(len(expected_header), 64)
        self.assertEqual(wire[:64], expected_header)
        self.assertEqual(wire[64:68], bytes([9, 8, 7, 6]))
        self.assertEqual(len(wire), 64 + 4 + 16)

    def test_tag_covers_context_header_and_payload_and_is_truncated_to_16_bytes(self):
        fields = rf.default_fields(payload=rf.pattern(8))
        wire = rf.encode(fields)
        body_end = len(wire) - rf.TAG_LEN
        want = hmac.new(rf.KEY, b"FFWS-v1-auth" + wire[:body_end], hashlib.sha256).digest()[:16]
        self.assertEqual(wire[body_end:], want)
        # A tag over the header alone, or over the payload alone, must differ.
        self.assertNotEqual(rf.tag(rf.KEY, wire[:64], b""), want)
        self.assertNotEqual(rf.tag(rf.KEY, b"", wire[64:body_end]), want)


class ReplayModel(unittest.TestCase):
    def frame(self, seq, epoch=1, stream=0xAB):
        return rf.scenario_frame(stream, epoch, seq)

    def test_reorder_depth_boundary(self):
        model = rf.ReceiverModel(rf.KEY, 0xAB, 1)
        self.assertEqual(model.accept(self.frame(100)), "OK")
        self.assertEqual(model.accept(self.frame(37)), "OK")  # 63 behind
        self.assertEqual(model.accept(self.frame(36)), "REPLAY_OR_DUPLICATE")  # 64 behind
        self.assertEqual(model.accept(self.frame(37)), "REPLAY_OR_DUPLICATE")

    def test_future_window_boundary_and_no_state_change_on_refusal(self):
        model = rf.ReceiverModel(rf.KEY, 0xAB, 1)
        self.assertEqual(model.accept(self.frame(0)), "OK")
        self.assertEqual(model.accept(self.frame(rf.MAX_FORWARD_GAP + 1)), "FUTURE_SEQUENCE")
        self.assertEqual(model.high, 0)
        self.assertEqual(model.accept(self.frame(rf.MAX_FORWARD_GAP)), "OK")

    def test_first_packet_is_bounded_by_the_origin(self):
        model = rf.ReceiverModel(rf.KEY, 0xAB, 1)
        self.assertEqual(model.accept(self.frame(rf.MAX_FORWARD_GAP + 1)), "FUTURE_SEQUENCE")
        self.assertIsNone(model.high)

    def test_media_never_adopts_a_future_epoch_only_control_does(self):
        model = rf.ReceiverModel(rf.KEY, 0xAB, 5)
        self.assertEqual(model.accept(self.frame(0, epoch=6)), "FUTURE_EPOCH")
        self.assertEqual(model.epoch, 5)
        model.advance_epoch(6)
        self.assertEqual(model.accept(self.frame(0, epoch=6)), "OK")
        model.advance_epoch(2)
        self.assertEqual(model.epoch, 6)


class GeneratedDocument(unittest.TestCase):
    def test_ordering_scenario_matches_hand_written_expectations(self):
        sc = next(s for s in load_document()["scenarios"] if s["id"] == "N01-SC-001")
        got = [s["expect"] for s in sc["steps"] if s["op"] == "datagram"]
        want = [
            "OK", "OK", "REPLAY_OR_DUPLICATE", "OK", "OK", "REPLAY_OR_DUPLICATE",
            "FUTURE_SEQUENCE", "OK", "REPLAY_OR_DUPLICATE", "AUTH_FAILED", "OK",
            "STALE_EPOCH", "FUTURE_EPOCH", "WRONG_STREAM", "OK", "STALE_EPOCH",
            "WRONG_STREAM", "OK", "TRUNCATED", "OK",
        ]
        self.assertEqual(got, want)

    def test_every_receive_rejection_has_at_least_one_case(self):
        doc = load_document()
        covered = {v["expect"] for v in doc["vectors"]}
        covered |= {s["expect"] for sc in doc["scenarios"] for s in sc["steps"] if "expect" in s}
        self.assertEqual([c for c in rf.RECEIVE_CODES if c not in covered], [])

    def test_committed_vectors_equal_a_fresh_generation(self):
        self.assertEqual(rf.DEFAULT_VECTORS.read_text(encoding="utf-8"), rf.render(rf.build_document()))

    def test_every_recorded_expectation_holds(self):
        self.assertEqual(rf.self_verify(load_document()), [])

    def test_changing_any_single_byte_of_an_accepted_vector_stops_it_being_accepted(self):
        accepted = [v for v in load_document()["vectors"] if v["expect"] == "ACCEPT"]
        self.assertGreaterEqual(len(accepted), 5)
        for vector in accepted:
            wire = bytes.fromhex(vector["wire_hex"])
            for index in range(len(wire)):
                mutated = bytearray(wire)
                mutated[index] ^= 0x01
                code, _ = rf.decode(bytes(mutated))
                self.assertNotEqual(code, "ACCEPT", f'{vector["id"]} byte {index}')

    def test_no_prefix_of_an_accepted_vector_decodes(self):
        for vector in (v for v in load_document()["vectors"] if v["expect"] == "ACCEPT"):
            wire = bytes.fromhex(vector["wire_hex"])
            for cut in range(len(wire)):
                self.assertNotEqual(rf.decode(wire[:cut])[0], "ACCEPT", f'{vector["id"]} cut {cut}')


class RustSourceAgreement(unittest.TestCase):
    def rust_codes(self):
        source = RUST_LIB.read_text(encoding="utf-8")
        start = source.index("pub const fn code(&self)")
        end = source.index("\n    }\n}", start)
        return set(re.findall(r'=> "([A-Z_]+)"', source[start:end]))

    def test_rust_error_names_are_the_contract_names(self):
        rust = self.rust_codes()
        contract = set(rf.RECEIVE_CODES) | SENDER_AND_JITTER_ONLY
        self.assertEqual(sorted(rust - contract), [], "Rust declares codes the contract lacks")
        self.assertEqual(sorted(contract - rust), [], "contract names missing from Rust")

    def test_rust_wire_constants_match_the_reference(self):
        source = RUST_LIB.read_text(encoding="utf-8")
        for name, value in {
            "HEADER_LEN_BYTES: usize": rf.HEADER_LEN,
            "AUTH_TAG_LEN_BYTES: usize": rf.TAG_LEN,
            "REPLAY_WINDOW_PACKETS: u64": rf.REPLAY_WINDOW,
            "MAX_FORWARD_SEQ_GAP: u64": rf.MAX_FORWARD_GAP,
            "MAX_FEC_GROUP_SIZE: u8": rf.MAX_FEC_GROUP,
        }.items():
            self.assertRegex(source, rf"pub const {re.escape(name)} = {value};")
        self.assertIn('pub const AUTH_CONTEXT: &[u8] = b"FFWS-v1-auth";', source)
        self.assertIn("pub const MAX_TIMESTAMP_NS: u64 = 1 << 62;", source)
        self.assertIn("pub const CRITICAL_FLAGS_MASK: u8 = 0xF0;", source)


if __name__ == "__main__":
    unittest.main()
