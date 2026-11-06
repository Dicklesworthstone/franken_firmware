"""Archive regressions independent of the builder's own self-test."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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


def independent_boot_archive(*, random_node=(0o020600, 1, 8)):
    """A whole archive built without the production encoder or device table."""
    entries = [fixture(name, mode=0o040755)
               for name in (".", "dev", "proc", "sys", "tmp")]
    for name, mode, major, minor in (
        ("dev/console", 0o020600, 5, 1),
        ("dev/ttyS0", 0o020600, 4, 64),
        ("dev/ttyPZ0", 0o020600, 204, 192),
        ("dev/null", 0o020666, 1, 3),
        ("dev/zero", 0o020666, 1, 5),
        ("dev/urandom", 0o020666, 1, 9),
    ):
        entries.append(fixture(name, mode=mode, major=major, minor=minor))
    if random_node is not None:
        mode, major, minor = random_node
        entries.append(fixture("dev/random", mode=mode, major=major, minor=minor))
    entries.extend((fixture("init", b"synthetic init", mode=0o100755),
                    fixture("TRAILER!!!", mode=0)))
    return b"".join(entries)


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

    def test_default_archive_has_the_distinct_legacy_random_character_device(self):
        raw = M.build_cpio_bytes(b"synthetic init")
        # Decode the newc header directly, independently of the production parser.
        offset = raw.index(b"dev/random\0") - 110
        self.assertEqual(raw[offset:offset + 6], b"070701")
        self.assertEqual(int(raw[offset + 14:offset + 22], 16), 0o020600)
        self.assertEqual(int(raw[offset + 78:offset + 86], 16), 1)
        self.assertEqual(int(raw[offset + 86:offset + 94], 16), 8)
        result = M.verify_initramfs_bytes(raw)
        self.assertEqual(result["devices"]["dev/random"]["rdev"], [1, 8])
        self.assertEqual(result["devices"]["dev/urandom"]["rdev"], [1, 9])

    def test_independent_legacy_random_archive_is_accepted_but_absence_is_rejected(self):
        result = M.verify_initramfs_bytes(independent_boot_archive(), require_legacy_random=True)
        self.assertEqual(result["devices"]["dev/random"]["mode"], "0o20600")
        with self.assertRaisesRegex(ValueError, "missing required device node 'dev/random'"):
            M.verify_initramfs_bytes(independent_boot_archive(random_node=None), require_legacy_random=True)

    def test_historical_archive_without_legacy_provider_remains_verifiable(self):
        result = M.verify_initramfs_bytes(independent_boot_archive(random_node=None))
        self.assertNotIn("dev/random", result["devices"])
        self.assertEqual(result["devices"]["dev/urandom"]["rdev"], [1, 9])

    def test_new_build_requires_legacy_device_even_if_the_shared_table_loses_it(self):
        root = Path(tempfile.mkdtemp(prefix="ffw-archive-legacy-random-"))
        init = root / "synthetic-init"
        init.write_bytes(b"synthetic init")
        result = M.build(init, root / "with-random.cpio.gz")
        self.assertEqual(result["devices"]["dev/random"]["rdev"], [1, 8])
        without_random = tuple(row for row in M.DEFAULT_DEVICE_NODES if row[0] != "dev/random")
        with patch.object(M, "DEFAULT_DEVICE_NODES", without_random):
            with self.assertRaisesRegex(ValueError, "missing required device node 'dev/random'"):
                M.build(init, root / "missing-random.cpio.gz")
        self.assertFalse((root / "missing-random.cpio.gz").exists())

    def test_legacy_random_cannot_be_a_regular_file_urandom_or_another_device(self):
        for node in ((0o100600, 1, 8), (0o020600, 1, 9),
                     (0o020600, 2, 8), (0o020666, 1, 8)):
            with self.subTest(node=node), self.assertRaisesRegex(
                    ValueError, "device 'dev/random' (mode|rdev) mismatch"):
                M.verify_initramfs_bytes(independent_boot_archive(random_node=node))


if __name__ == "__main__":
    unittest.main()
