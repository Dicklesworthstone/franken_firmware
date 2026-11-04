"""Tests for inventory/image_evidence.py (bead ffw-xdi).  Offline, stdlib only.

    python3 -B -I -m unittest discover -s inventory -p 'test_image_evidence.py' -v

Images here are SYNTHETIC: a 64-byte ELF header plus filler, built in the test.  The digest oracle
is hashlib applied directly to the bytes written.  Nothing here is, or claims to be, real firmware.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("image_evidence_under_test", HERE / "image_evidence.py")
ie = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ie)
_rspec = importlib.util.spec_from_file_location("reconcile_for_ie_tests", HERE / "reconcile.py")
rc = importlib.util.module_from_spec(_rspec)
_rspec.loader.exec_module(rc)

PPC, MIPS, X86_64 = 20, 8, 62
MARKER = "PRIVATE-MARKER-7c1e"


def elf_header(machine, *, ei_class=1, ei_data=2, flags=0):
    """A 64-byte ELF header (class 1 = 32-bit, data 2 = big-endian)."""
    e = ">" if ei_data == 2 else "<"
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    if ei_class == 1:
        body = struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0, 52, 0, flags, 52, 32, 1, 40, 0, 0)
    else:
        body = struct.pack(e + "HHIQQQIHHHHHH", 2, machine, 1, 0, 64, 0, flags, 64, 56, 1, 64, 0, 0)
    return (ident + body).ljust(64, b"\x00")


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        (self.dir / ".local-real").mkdir()

    def image(self, header, name="anacapad", filler=b"x" * 5000):
        p = self.dir / name
        p.write_bytes(header + filler)
        return p

    def run_tool(self, img, *extra, out=None):
        out = out or self.dir / ".local-real" / "ev.local.json"
        argv = ["--image", str(img), "--internal-model-id", "16", "--build", "57.23-74170", "--image-name", "anacapad",
                "--provenance-source", "synthetic fixture", "--provenance-basis", "synthetic test image, not firmware",
                "--out", str(out), *extra]
        o, e = io.StringIO(), io.StringIO()
        return ie.main(argv, stdout=o, stderr=e), o.getvalue(), e.getvalue(), out

    JOIN = ("--join-model", "S5", "--join-basis", "owner-attested", "--revision", "1.2.3.4-5.6")


class TestRecords(Base):
    def test_digest_and_isa_come_from_the_bytes(self):
        """E01-IMG-MEASURED: SHA-256 equals hashlib over the exact bytes; ISA/endianness/word size come from the header; no ABI is invented for PowerPC."""
        img = self.image(elf_header(PPC))
        code, out, err, outp = self.run_tool(img)
        self.assertEqual(code, 0, err)
        rec = json.loads(outp.read_text())["records"][0]
        self.assertEqual(rec["image"]["digest"], "sha256:" + hashlib.sha256(img.read_bytes()).hexdigest())
        self.assertEqual(rec["claim"], {"machine": "powerpc", "elf_class": 32, "endianness": "big", "abi": None, "float_abi": None, "atomic_widths": None})
        self.assertEqual(rec["firmware_lines"], ["57.23"])
        self.assertEqual(rec["join"], {"model_number": None, "join_basis": "unmapped"})
        self.assertNotIn("hardware_revisions", rec)
        self.assertEqual(json.loads(outp.read_text())["schema"], rc.EVIDENCE_SCHEMA)

    def test_mips_abi_is_recorded_only_because_the_header_states_it(self):
        """E01-IMG-MIPS: the o32 flag in the header yields abi o32; without it the ABI stays unrecorded."""
        with_abi = json.loads(self.run_tool(self.image(elf_header(MIPS, flags=0x1000)))[3].read_text())["records"][0]
        self.assertEqual((with_abi["claim"]["machine"], with_abi["claim"]["abi"]), ("mips", "o32"))
        out2 = self.dir / ".local-real" / "b.local.json"
        without = json.loads(self.run_tool(self.image(elf_header(MIPS, flags=0), name="b"), out=out2)[3].read_text())["records"][0]
        self.assertIsNone(without["claim"]["abi"])

    def test_other_word_sizes_and_endianness(self):
        """E01-IMG-WIDTHS: a 64-bit little-endian header is reported as such, not coerced to 32/big."""
        rec = json.loads(self.run_tool(self.image(elf_header(X86_64, ei_class=2, ei_data=1)))[3].read_text())["records"][0]
        self.assertEqual((rec["claim"]["machine"], rec["claim"]["elf_class"], rec["claim"]["endianness"]), ("x86_64", 64, "little"))

    def test_the_image_is_only_read(self):
        """E01-IMG-READ-ONLY: the image's bytes and mtime are unchanged."""
        img = self.image(elf_header(PPC))
        before = (hashlib.sha256(img.read_bytes()).hexdigest(), os.stat(img).st_mtime_ns)
        self.assertEqual(self.run_tool(img)[0], 0)
        self.assertEqual(before, (hashlib.sha256(img.read_bytes()).hexdigest(), os.stat(img).st_mtime_ns))

    def test_expectations_cross_check_the_measurement(self):
        """E01-IMG-EXPECT: --expect-sha256 / --expect-isa pass when right and refuse (no file) when wrong."""
        img = self.image(elf_header(PPC))
        good = hashlib.sha256(img.read_bytes()).hexdigest()
        self.assertEqual(self.run_tool(img, "--expect-sha256", good, "--expect-isa", "powerpc")[0], 0)
        for flag, value, code in (("--expect-sha256", "0" * 64, "digest_mismatch"), ("--expect-isa", "mips", "isa_mismatch")):
            out = self.dir / ".local-real" / f"x-{code}.local.json"
            c, _, err, _ = self.run_tool(img, flag, value, out=out)
            self.assertEqual(c, 2, err)
            self.assertIn(f"error[{code}]", err)
            self.assertFalse(out.exists())


class TestJoinsAreExplicit(Base):
    def test_a_join_is_recorded_only_when_asserted_and_flows_through_reconcile(self):
        """E01-IMG-JOIN: an asserted join becomes an attested record; reconcile then reports the ISA and digest but keeps the unrecorded ABI as a blocker."""
        img = self.image(elf_header(PPC))
        code, _, err, outp = self.run_tool(img, *self.JOIN)
        self.assertEqual(code, 0, err)
        rec = json.loads(outp.read_text())["records"][0]
        self.assertEqual(rec["join"], {"model_number": "S5", "join_basis": "owner-attested"})
        self.assertEqual(rec["hardware_revisions"], ["1.2.3.4-5.6"])
        self.assertEqual(os.stat(outp).st_mode & 0o777, 0o600, "an attestation is written private")
        # end to end through reconcile with a synthetic S5 capture whose revision matches the join
        cap = {"devices": [{"url": "http://192.0.2.1:1400/x", "fields": {
            "serialNum": "00-00-5E-00-53-01:1", "MACAddress": "00:00:5e:00:53:01", "modelNumber": "S5", "modelName": "Sonos Play:5",
            "hardwareVersion": "1.2.3.4-5.6", "softwareVersion": "57.23-74170", "swGen": "1", "memory": "32", "flash": "32",
            "seriesid": "P100", "variant": "0"}}]}
        capf = self.dir / "cap.json"
        capf.write_text(json.dumps(cap))
        o, e = io.StringIO(), io.StringIO()
        c = rc.main(["--input", str(capf), "--evidence", str(outp), "--nominal-unit", "MB"], stdout=o, stderr=e)
        doc = json.loads(o.getvalue())
        entry = doc["profiles"][0]
        self.assertEqual(entry["target"]["isa"], {"machine": "powerpc", "elf_class": 32, "endianness": "big"})
        self.assertEqual(entry["target"]["images"], [{"name": "anacapad", "digest": hashlib.sha256(img.read_bytes()).hexdigest(), "digest_algorithm": "sha256"}])
        self.assertEqual(entry["provenance"]["target"]["join_bases"], ["owner-attested"])
        codes = {r["code"] for r in entry["reason_codes"]}
        self.assertIn("abi_not_recorded", codes, "the ABI is not stated by a PowerPC header, so the profile must stay unresolved")
        self.assertNotIn("isa_evidence_join_unattested", codes)
        self.assertNotIn("image_digest_absent", codes)
        self.assertEqual((entry["resolution"], entry["activation_eligible"], c), ("unresolved", False, 3))

    def test_the_join_covers_only_the_asserted_revision(self):
        """E01-IMG-JOIN-SCOPE: a device with another hardware revision gets isa_evidence_revision_mismatch, not the image's ISA."""
        outp = self.run_tool(self.image(elf_header(PPC)), *self.JOIN)[3]
        cap = {"devices": [{"fields": {"serialNum": "00-00-5E-00-53-02:1", "modelNumber": "S5", "modelName": "Sonos Play:5",
               "hardwareVersion": "9.9.9.9-9.9", "softwareVersion": "57.23-74170", "swGen": "1", "memory": "32", "flash": "32"}}]}
        capf = self.dir / "cap2.json"
        capf.write_text(json.dumps(cap))
        o = io.StringIO()
        rc.main(["--input", str(capf), "--evidence", str(outp), "--nominal-unit", "MB"], stdout=o, stderr=io.StringIO())
        entry = json.loads(o.getvalue())["profiles"][0]
        self.assertIsNone(entry["target"]["isa"])
        self.assertIn("isa_evidence_revision_mismatch", {r["code"] for r in entry["reason_codes"]})

    def test_incomplete_or_self_attesting_joins_are_refused(self):
        """E01-IMG-JOIN-GUARDS: no join without basis and revision, no blanket join, no name-inferred basis, and --join-basis alone is meaningless."""
        img = self.image(elf_header(PPC))
        cases = [
            (("--join-model", "S5"), 2, "usage"),
            (("--join-model", "S5", "--join-basis", "owner-attested"), 2, "usage"),
            (("--join-model", "S5", "--join-basis", "name-inferred", "--revision", "1.2.3.4-5.6"), 2, "usage"),
            (("--join-basis", "owner-attested"), 2, "usage"),
            (("--revision", "1.2.3.4-5.6"), 2, "usage"),
        ]
        for extra, want, code in cases:
            with self.subTest(extra):
                out = self.dir / ".local-real" / "g.local.json"
                c, _, err, _ = self.run_tool(img, *extra, out=out)
                self.assertEqual(c, want, err)
                self.assertIn("error[usage]", err)
                self.assertFalse(out.exists())

    def test_an_attestation_is_never_written_to_a_publishable_path(self):
        """E01-IMG-PRIVATE: a record asserting a join is refused (exit 5, nothing written) outside .local-real/ or a *.local.* name; an unmapped record may be public."""
        img = self.image(elf_header(PPC))
        public = self.dir / "ev.json"
        c, _, err, _ = self.run_tool(img, *self.JOIN, out=public)
        self.assertEqual(c, 5, err)
        self.assertIn("private_out_not_ignored", err)
        self.assertFalse(public.exists())
        self.assertEqual(self.run_tool(img, out=public)[0], 0, "an unmapped record carries no attestation")
        self.assertTrue(public.exists())
        self.assertEqual(self.run_tool(img, *self.JOIN, out=self.dir / "ok.local.json")[0], 0)


class TestHazards(Base):
    def test_non_elf_and_short_inputs_fail_without_echoing_content(self):
        """E01-IMG-HAZARDS: not-ELF, truncated and empty images exit 2 with a code and never echo their bytes."""
        for name, data in (("text", f"hello {MARKER}".encode() * 20), ("short", b"\x7fELF" + MARKER.encode()), ("empty", b"")):
            with self.subTest(name):
                p = self.dir / name
                p.write_bytes(data)
                out = self.dir / ".local-real" / f"{name}.local.json"
                c, _, err, _ = self.run_tool(p, out=out)
                self.assertEqual(c, 2, err)
                self.assertIn("error[elf_header_rejected]", err)
                self.assertNotIn(MARKER.lower(), err.lower())
                self.assertFalse(out.exists())

    def test_inconsistent_headers_are_rejected_by_the_shared_parser(self):
        """E01-IMG-INCONSISTENT: a header the shared parser calls inconsistent (e.g. ppc64-only machine in a 32-bit class) is refused, not 'fixed'."""
        c, _, err, outp = self.run_tool(self.image(elf_header(21)))  # EM_PPC64 requires a 64-bit class
        self.assertEqual(c, 2, err)
        self.assertFalse(outp.exists())

    def test_output_guards(self):
        """E01-IMG-OUTPUT: no clobbering, no overwriting the image, missing parent refused; --overwrite replaces atomically."""
        img = self.image(elf_header(PPC))
        out = self.dir / ".local-real" / "o.local.json"
        out.write_text("OLD")
        c, _, err, _ = self.run_tool(img, out=out)
        self.assertEqual((c, out.read_text()), (5, "OLD"))
        self.assertIn("output_exists", err)
        self.assertEqual(self.run_tool(img, "--overwrite", out=out)[0], 0)
        self.assertEqual(json.loads(out.read_text())["schema"], rc.EVIDENCE_SCHEMA)
        before = img.read_bytes()
        c, _, err, _ = self.run_tool(img, "--overwrite", out=img)
        self.assertEqual((c, img.read_bytes()), (5, before))
        self.assertIn("output_collides_with_input", err)
        c, _, err, _ = self.run_tool(img, out=self.dir / "missing" / "x.local.json")
        self.assertEqual(c, 5)
        self.assertIn("output_parent_missing", err)

    def test_size_limit_and_unreadable_image(self):
        """E01-IMG-BOUNDS: an image over the cap and a missing image are refused with codes."""
        img = self.image(elf_header(PPC), filler=b"y" * 200)
        old = ie.MAX_IMAGE_BYTES
        ie.MAX_IMAGE_BYTES = 100
        try:
            c, _, err, _ = self.run_tool(img)
        finally:
            ie.MAX_IMAGE_BYTES = old
        self.assertEqual(c, 2)
        self.assertIn("image_too_large", err)
        c, _, err, _ = self.run_tool(self.dir / "absent")
        self.assertEqual(c, 2)
        self.assertIn("image_unreadable", err)

    def test_registry_validation_still_applies(self):
        """E01-IMG-VALIDATED: a provenance field that looks like a URL or absolute path is refused by the shared registry validation."""
        img = self.image(elf_header(PPC))
        out = self.dir / ".local-real" / "v.local.json"
        argv = ["--image", str(img), "--internal-model-id", "16", "--build", "57.23-74170", "--image-name", "anacapad",
                "--provenance-source", "https://example.invalid/x", "--provenance-basis", "b", "--out", str(out)]
        o, e = io.StringIO(), io.StringIO()
        self.assertEqual(ie.main(argv, stdout=o, stderr=e), 2)
        self.assertIn("error[record_invalid]", e.getvalue())
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
