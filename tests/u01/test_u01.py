"""Unit tests for the U01 Python reference (stdlib unittest). The properties of the journal itself live in battery.py;
these pin the encoding and the helpers the vectors depend on, and run the battery."""
from __future__ import annotations

import os
import struct
import sys
import unittest
import zlib

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import battery  # noqa: E402
import images  # noqa: E402
import reference as ref  # noqa: E402
import scenarios as sc  # noqa: E402


class EncodingTests(unittest.TestCase):
    def test_crc32_is_the_published_ieee_check_value(self):
        self.assertEqual(zlib.crc32(b"123456789"), 0xCBF43926)

    def test_the_empty_state_is_a_zero_count(self):
        self.assertEqual(ref.canonical(ref.empty_state()), b"\x00\x00")

    def test_a_segment_header_is_sixteen_bytes_with_a_checksum_over_the_first_twelve(self):
        head = ref.encode_segment_header(1, 7, 42)
        self.assertEqual(len(head), 16)
        self.assertEqual(head[:2], b"FJ")
        self.assertEqual(struct.unpack(">I", head[12:])[0], zlib.crc32(head[:12]))
        self.assertEqual(struct.unpack(">BBII", head[2:12]), (1, 0, 7, 42))

    def test_a_frame_is_twelve_bytes_then_the_payload_and_the_checksum_covers_both(self):
        frame = ref.encode_frame(ref.KIND_TXN, 5, b"abc")
        self.assertEqual(frame[:8], bytes([0xA5, 1, 0, 3, 0, 0, 0, 5]))
        self.assertEqual(struct.unpack(">I", frame[8:12])[0], zlib.crc32(frame[:8] + b"abc"))
        self.assertEqual(frame[12:], b"abc")

    def test_every_operation_round_trips_through_the_codec(self):
        ops = [("put", ref.NS_SETTINGS, b"k", b"v"), ("delete", ref.NS_RECORDS, b"k"), ("reset", ref.NS_CALIBRATION),
               ("install", b"id", 9, b"secret"), ("revoke", b"id"), ("reset_pairing",), ("raise", b"epoch", 2 ** 63)]
        self.assertEqual(ref.decode_ops(ref.TINY, ref.encode_ops(ops), 1, False), ops)

    def test_a_tombstone_operation_is_refused_outside_a_snapshot(self):
        payload = ref.encode_ops([("tomb", b"id", 3)])
        with self.assertRaises(ref.JournalError):
            ref.decode_ops(ref.TINY, payload, 1, False)
        self.assertEqual(ref.decode_ops(ref.TINY, payload, 1, True), [("tomb", b"id", 3)])

    def test_hostile_lengths_trailing_bytes_and_truncation_are_malformed(self):
        for label, payload in (("value length", bytes([0, 1, 1, 1, 1, ord("k"), 0xFF, 0xFF])),
                               ("key length", bytes([0, 1, 1, 1, 200, ord("k")])),
                               ("count", bytes([0xFF, 0xFF])), ("trailing", ref.encode_ops([]) + b"x"),
                               ("truncated", ref.encode_ops([("put", 1, b"k", b"v")])[:-1])):
            with self.subTest(label), self.assertRaises(ref.JournalError):
                ref.decode_ops(ref.TINY, payload, 1, False)

    def test_the_canonical_form_orders_namespaces_then_keys_as_bytes(self):
        state = ref.empty_state()
        state[ref.NS_SETTINGS] = {b"b": b"2", b"a": b"1"}
        state[ref.NS_MARKS] = {b"z": 1}
        state[ref.NS_CREDENTIALS] = {b"y": ("revoked", 4), b"x": ("live", 2, b"s")}
        ops = ref.snapshot_ops(state)
        self.assertEqual([op[0] for op in ops], ["put", "put", "install", "tomb", "raise"])
        self.assertEqual([op[2] for op in ops[:2]], [b"a", b"b"])
        self.assertEqual([op[1] for op in ops[2:4]], [b"x", b"y"])


class ScenarioTests(unittest.TestCase):
    def test_a_script_survives_a_json_round_trip(self):
        for steps in sc.SCENARIOS.values():
            for step in steps:
                self.assertEqual(sc.step_from_json(sc.step_to_json(step)), step)

    def test_both_configurations_hold_their_own_worst_case(self):
        ref.TINY.validate()
        ref.STANDARD.validate()
        self.assertEqual(ref.TINY.worst_snapshot_payload(), 276)
        self.assertEqual(ref.STANDARD.worst_snapshot_payload(), 6154)

    def test_every_image_case_has_an_expectation(self):
        for case in images.build():
            self.assertIn("state_hex" if "error" not in case["expect"] else "error", case["expect"], case["id"])


class BatteryTests(unittest.TestCase):
    def test_every_property_of_the_specification_holds(self):
        for check in battery.CHECKS:
            with self.subTest(check.__name__):
                check()


if __name__ == "__main__":
    unittest.main()
