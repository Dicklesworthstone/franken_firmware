"""Archive regressions independent of the builder's own self-test."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "archive_under_test", Path(__file__).resolve().parents[1] / "src/mkinitramfs.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(name, payload=b"", mode=0o100644, major=0, minor=0):
    """Independent minimal newc fixture, without production encoding helpers."""
    fields = (1, mode, 0, 0, 1, 0, len(payload), 0, 0, major, minor,
              len(name.encode()) + 1, 0)
    header = b"070701" + b"".join(format(v, "08x").encode() for v in fields)
    header += name.encode() + b"\0"
    header += b"\0" * (-len(header) % 4)
    return header + payload + b"\0" * (-len(payload) % 4)


class ArchiveTests(unittest.TestCase):
    def test_independent_all_sixteen_alignments(self):
        for name_len in range(1, 5):
            for data_len in range(4):
                with self.subTest(name_len=name_len, data_len=data_len):
                    name = "x" * name_len
                    payload = b"z" * data_len
                    raw = fixture(name, payload) + fixture("next", b"after") + fixture("TRAILER!!!", mode=0)
                    entries = M.parse_cpio_bytes(raw)
                    self.assertEqual([(e["name"], e["data"]) for e in entries],
                                     [(name, payload), ("next", b"after"), ("TRAILER!!!", b"")])

    def test_named_alignment_counterexample(self):
        raw = fixture("ab", b"x") + fixture("TRAILER!!!", mode=0)
        self.assertEqual(raw[116:117], b"x")
        self.assertEqual(raw[120:126], b"070701")
        self.assertEqual(M.parse_cpio_bytes(raw)[0]["data"], b"x")

    def test_device_tuple_decoded_independently(self):
        raw = M.encode_newc_entry("dev/console", M.S_IFCHR | 0o600, dev=(5, 1))
        self.assertEqual(int(raw[78:86], 16), 5)
        self.assertEqual(int(raw[86:94], 16), 1)

    def test_duplicate_init_rejected(self):
        raw = fixture("init", b"first") + fixture("init", b"second") + fixture("TRAILER!!!", mode=0)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            M.parse_cpio_bytes(raw)

    def test_escaping_and_ambiguous_paths_rejected(self):
        for name in ("../init", "/init", "dev/../init", "dev//console", "./init", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.parse_cpio_bytes(fixture(name) + fixture("TRAILER!!!", mode=0))

    def test_trailer_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, "must not contain data"):
            M.parse_cpio_bytes(fixture("TRAILER!!!", b"hidden", mode=0))

    def test_device_tuple_not_silently_coerced(self):
        for dev in ((True, 1), (5.9, 1), ("5", 1), (-1, 1), (2**32, 1)):
            with self.subTest(dev=dev), self.assertRaises(ValueError):
                M.normalize_dev_tuple(dev)

    def test_valid_default_archive_remains_accepted(self):
        raw = M.build_cpio_bytes(b"synthetic init")
        result = M.verify_initramfs_bytes(raw)
        self.assertEqual(result["devices"]["dev/console"]["rdev"], [5, 1])
        self.assertEqual(result["init_size"], 14)


if __name__ == "__main__":
    unittest.main()
