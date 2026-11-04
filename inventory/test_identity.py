#!/usr/bin/env python3
"""Tests for inventory/identity.py (bead E01 / ffw-xdi). Standard library only.

Run:  python3 -m unittest discover -s inventory -p 'test_identity.py' -v
  or: python3 inventory/test_identity.py

EVIDENCE CLASS: host simulation over SYNTHETIC / FABRICATED data only. Nothing here
is a real device observation, a real firmware image, or a physical board identity.

* Sources labelled ``synthetic:...`` are labelled fixtures; the module refuses to let
  them make a profile activation-eligible.
* Sources labelled ``unit-test-only/...`` carry *fabricated* data under a
  non-synthetic label purely so the eligibility logic can be exercised both ways. They
  are not evidence of anything and must never be reused outside these tests.
* Image digests are sha256 of a text label, not of any firmware image.
* Hostnames use RFC 5737 documentation ranges; serials/rooms are made up.

Every test docstring starts with a stable case id (E01-<AREA>-<NN>) so the shared Q00
runner / tests/e01 manifests can reference cases individually. Expected values are
written out literally (independent oracle), except where a test says otherwise.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import identity as I  # noqa: E402

KEY = b"synthetic-test-key-not-a-secret-0123456789"
PS = I.Pseudonymizer(KEY)
T0 = "2026-11-04T10:00:00Z"
T1 = "2026-11-05T10:00:00Z"

PID_S5_REV_A = "bp-a54934d5ce72d8e7"  # golden: S5 + 1.8.3.1-2 (computed independently of the module)
PID_S5_REV_B = "bp-592228c461a48f9b"  # golden: S5 + 1.20.1.6-2

CANARY_SERIAL = "SYN-CANARY-SERIAL-7781"
CANARY_IP = "198.51.100.77"
CANARY_ROOM = "CanaryRoomNameXyz"


# --------------------------------------------------------------------------- fixtures
def SYN(sid="synthetic:fixture-a", basis="live_description", at=T0):
    return I.Source(sid, basis, at, True)


def REAL(sid="unit-test-only/scan-a", basis="live_description", at=T0):
    """Fabricated data under a NON-synthetic label; for exercising eligibility logic only."""
    return I.Source(sid, basis, at, False)


def mkrec(serial="SYN-0001", model="S5", hw="1.8.3.1-2", sw="57.23-74170", gen="1", mem="32", flash="32",
          series="P100", room="Synthetic Room A", ip="192.0.2.10", status_gen=None, model_name=None,
          observed_at=None, extra=None):
    f = {"serialNum": serial}
    for k, v in (("modelNumber", model), ("hardwareVersion", hw), ("softwareVersion", sw), ("swGen", gen),
                 ("memory", mem), ("flash", flash), ("seriesid", series), ("roomName", room),
                 ("modelName", model_name)):
        if v is not None:
            f[k] = v
    if extra:
        f.update(extra)
    r = {"fields": f, "status": {}}
    if ip is not None:
        r["url"] = "http://%s:1400/xml/device_description.xml" % ip
    if status_gen is not None:
        r["status"]["SWGen"] = status_gen
    if observed_at is not None:
        r["observed_at"] = observed_at
    return r


def N(rec, src=None, unit=None):
    return I.normalize_record(rec, src or REAL(), PS, memory_unit=unit)


def elf(cls=1, data=2, machine=8, flags=0, etype=2, ver=1, pad=0):
    """Independent ELF header builder (does not share code with the parser)."""
    ident = b"\x7fELF" + bytes([cls, data, ver]) + b"\x00" * 9
    e = ">" if data == 2 else "<"
    if cls == 1:
        rest = struct.pack(e + "HHIIIII", etype, machine, 1, 0, 0, 0, flags) + struct.pack(e + "HHHHHH", 52, 32, 1, 40, 0, 0)
    else:
        rest = struct.pack(e + "HHIQQQI", etype, machine, 1, 0, 0, 0, flags) + struct.pack(e + "HHHHHH", 64, 56, 1, 64, 0, 0)
    return ident + rest + b"\x00" * pad


def image(tag, model="S5", imid=16, build="57.23-74170", synthetic=False, bind=True):
    """ImageRef whose digest is sha256 of a text label (not of any real image)."""
    sha = hashlib.sha256(("synthetic-image-digest/" + tag).encode()).hexdigest()
    sid = ("synthetic:" if synthetic else "unit-test-only/") + "binding-" + tag
    bs = I.Source(sid, "firmware_package_metadata", None, synthetic) if bind else None
    return I.ImageRef(sha, imid, build, model if bind else None, bs)


def elf_norm(img, machine=20, cls=1, data=2, flags=0, synthetic=False, tag=None):
    sid = ("synthetic:" if synthetic else "unit-test-only/") + "elf-" + (tag or img.image_id)
    return I.normalize_elf_header(elf(cls=cls, data=data, machine=machine, flags=flags), img,
                                  I.Source(sid, "elf_header", None, synthetic))


def attrs_norm(img, abi="sysv", fabi="hard", synthetic=False):
    sid = ("synthetic:" if synthetic else "unit-test-only/") + "attrs-" + img.image_id
    src = I.Source(sid, "elf_attributes", None, synthetic)
    sub = I.Subject.image(img.image_id)
    cl = [I.make_claim(sub, "arch.abi", abi, src, origin="elf.attrs"),
          I.make_claim(sub, "arch.float_abi", fabi, src, origin="elf.attrs")]
    return I.Normalized(claims=cl, images=[img], source=src)


def complete(model="S5", rev="1.8.3.1-2", serial="UT-0001", synthetic=False, tag="a"):
    """Everything DEFAULT_REQUIRED asks for, from non-synthetic (fabricated) sources by default."""
    S = SYN if synthetic else REAL
    pre = "synthetic:" if synthetic else "unit-test-only/"
    img = image(tag, model=model, synthetic=synthetic)
    return [
        N(mkrec(serial=serial, model=model, hw=rev, mem="32", flash="32"), S(sid=pre + "scan-" + tag), unit="MiB"),
        elf_norm(img, machine=20, synthetic=synthetic, tag=tag),
        attrs_norm(img, synthetic=synthetic),
    ]


def doc_of(batches, **kw):
    return I.resolve_fleet(batches, **kw).to_public_json()


def profile_of(doc, model="S5", rev="1.8.3.1-2"):
    ps = [p for p in doc["profiles"] if p["product_model"] == model and p["hardware_revision"] == rev]
    assert len(ps) == 1, "expected exactly one profile for %s/%s, got %d" % (model, rev, len(ps))
    return ps[0]


def dev_token(serial):
    return PS.device(serial)


class Base(unittest.TestCase):
    def assertCode(self, code, fn, *a, **kw):
        with self.assertRaises(I.IdentityError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.code, code, "got %r" % cm.exception)
        return cm.exception


# =========================================================================== pseudonyms
class TestPseudonymizer(Base):
    def test_pse_01_key_validation(self):
        """E01-PSE-01 short/non-bytes keys are rejected; 16 bytes is the floor."""
        for bad in (b"", b"x" * 15, "string-key-not-bytes-0000", None, 12345):
            self.assertCode(I.R_KEY, I.Pseudonymizer, bad)
        I.Pseudonymizer(b"x" * 16)
        I.Pseudonymizer(bytearray(b"y" * 32))

    def test_pse_02_deterministic_and_distinct(self):
        """E01-PSE-02 same serial -> same token; different serial -> different token; fixed shape."""
        a, b = PS.device("SYN-0001"), PS.device("SYN-0002")
        self.assertEqual(a, PS.device("SYN-0001"))
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^dev-[0-9a-f]{20}$")

    def test_pse_03_serial_canonicalization(self):
        """E01-PSE-03 separator/case/whitespace variants of one serial are one device; a different serial is not."""
        base = PS.device("aa:bb:cc-01")
        for v in ("AA-BB-CC-01", " aa bb cc 01 ", "AA_BB_CC_01", "aa--bb::cc 01"):
            self.assertEqual(PS.device(v), base, v)
        self.assertNotEqual(PS.device("AABBCC01"), base)

    def test_pse_04_domain_separation(self):
        """E01-PSE-04 the same text hashes differently as device, address and label."""
        t = "same-text"
        self.assertNotEqual(PS.device(t)[4:16], PS.address(t)[4:16])
        self.assertNotEqual(PS.address(t)[4:], PS.label(t)[4:])

    def test_pse_05_key_dependence(self):
        """E01-PSE-05 a different key yields different pseudonyms (no unkeyed hash of a low-entropy serial)."""
        other = I.Pseudonymizer(b"another-synthetic-key-0123456789ab")
        self.assertNotEqual(PS.device("SYN-0001"), other.device("SYN-0001"))
        self.assertNotEqual(PS.address("192.0.2.10"), other.address("192.0.2.10"))
        unkeyed = "dev-" + hashlib.sha256(b"SYN-0001").hexdigest()[:20]
        self.assertNotEqual(PS.device("SYN-0001"), unkeyed)

    def test_pse_06_repr_redacts_key(self):
        """E01-PSE-06 repr/str never reveal key material."""
        for s in (repr(PS), str(PS)):
            self.assertNotIn("synthetic-test-key", s)
            self.assertIn("redacted", s)

    def test_pse_07_invalid_serials(self):
        """E01-PSE-07 unusable serials raise DEVICE_KEY_MISSING (no silent default key)."""
        for bad in (None, "", "   ", "unknown", "N/A", 123, "x" * 65, "café-1", "A\x00B", b"bytes"):
            self.assertCode(I.R_DEVICE_KEY, PS.device, bad)

    def test_pse_08_address_normalization(self):
        """E01-PSE-08 scheme/port/path/case are not part of the address token; host is."""
        base = PS.address("192.0.2.10")
        for v in ("http://192.0.2.10:1400/xml/device_description.xml", "HTTP://192.0.2.10", "192.0.2.10:1400", " 192.0.2.10 "):
            self.assertEqual(PS.address(v), base, v)
        self.assertNotEqual(PS.address("192.0.2.11"), base)
        for bad in ("", "http://", None, 5, "x" * 600):
            self.assertCode(I.R_ADDRESS, PS.address, bad)

    def test_pse_09_from_env(self):
        """E01-PSE-09 from_env refuses a missing/empty variable and accepts a long-enough one."""
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FFW_TEST_KEY_ABSENT", None)
            self.assertCode(I.R_KEY, I.Pseudonymizer.from_env, "FFW_TEST_KEY_ABSENT")
        with mock.patch.dict(os.environ, {"FFW_TEST_KEY": ""}):
            self.assertCode(I.R_KEY, I.Pseudonymizer.from_env, "FFW_TEST_KEY")
        with mock.patch.dict(os.environ, {"FFW_TEST_KEY": "short"}):
            self.assertCode(I.R_KEY, I.Pseudonymizer.from_env, "FFW_TEST_KEY")
        with mock.patch.dict(os.environ, {"FFW_TEST_KEY": "a-long-enough-synthetic-key-123"}):
            self.assertRegex(I.Pseudonymizer.from_env("FFW_TEST_KEY").device("X1"), r"^dev-")

    def test_pse_10_label_normalization(self):
        """E01-PSE-10 room-label tokens ignore case/whitespace; empty labels are rejected."""
        self.assertEqual(PS.label("Living  Room"), PS.label(" living room "))
        self.assertNotEqual(PS.label("Living Room"), PS.label("Kitchen"))
        self.assertCode(I.R_RECORD, PS.label, "   ")
        self.assertCode(I.R_RECORD, PS.label, None)


# =========================================================================== source
class TestSource(Base):
    def test_src_01_synthetic_label_both_ways(self):
        """E01-SRC-01 synthetic sources must be labelled synthetic:, and labelled sources must be synthetic."""
        I.Source("synthetic:a", "live_description", None, True)
        I.Source("unit-test-only/a", "live_description", None, False)
        self.assertCode(I.R_SOURCE, I.Source, "unit-test-only/a", "live_description", None, True)
        self.assertCode(I.R_SOURCE, I.Source, "synthetic:a", "live_description", None, False)
        self.assertCode(I.R_SOURCE, I.Source, "synthetic:a", "live_description", None, "yes")

    def test_src_02_forbidden_bases(self):
        """E01-SRC-02 era/family/series/generation 'evidence' cannot even be constructed."""
        for b in sorted(I.FORBIDDEN_BASES):
            self.assertCode(I.R_ERA, I.Source, "unit-test-only/x", b)
        self.assertCode(I.R_BASIS_UNKNOWN, I.Source, "unit-test-only/x", "vibes")
        self.assertCode(I.R_BASIS_UNKNOWN, I.Source, "unit-test-only/x", 5)

    def test_src_03_private_looking_ids_rejected(self):
        """E01-SRC-03 a source id that looks like an address/MAC/RINCON/UUID/long hex is rejected."""
        bad = ("192.0.2.10", "00:0E:58:12:34:56", "00-0E-58-12-34-56", "RINCON_000E58123456",
               "123e4567-e89b-12d3-a456-426614174000", "scan-000e58123456", "", "a b", "x" * 65, "-lead")
        for sid in bad:
            self.assertCode(I.R_SOURCE, I.Source, sid, "live_description")
        I.Source("unit-test-only/scan-2026-11-04", "live_description")

    def test_src_04_observed_at(self):
        """E01-SRC-04 timestamps are canonicalised to UTC; naive/garbage/out-of-range are rejected."""
        a = I.Source("unit-test-only/t", "live_description", "2026-11-04T10:00:00Z")
        b = I.Source("unit-test-only/t", "live_description", "2026-11-04T12:00:00+02:00")
        c = I.Source("unit-test-only/t", "live_description", "2026-11-04T10:00:00.987+00:00")
        self.assertEqual(a.observed_at, "2026-11-04T10:00:00Z")
        self.assertEqual(b.observed_at, a.observed_at)
        self.assertEqual(c.observed_at, a.observed_at)
        for bad in ("2026-11-04T10:00:00", "yesterday", "", "1999-01-01T00:00:00Z", "2101-01-01T00:00:00Z", 5, "x" * 41):
            self.assertCode(I.R_TIME, I.Source, "unit-test-only/t", "live_description", bad)

    def test_src_05_tier(self):
        """E01-SRC-05 tiers: live=observed, vendor=declared, teardown/peer=hypothesis."""
        self.assertEqual(REAL().tier, "observed")
        self.assertEqual(REAL(basis="vendor_documentation").tier, "declared")
        self.assertEqual(REAL(basis="published_teardown").tier, "hypothesis")
        self.assertEqual(REAL(basis="peer_report").tier, "hypothesis")


# =========================================================================== field parsers
def claim(field, value, basis="live_description", kind="device", unit=None, qualifier="exact"):
    sub = {"device": I.Subject.device(dev_token("P-1")), "model": I.Subject.model("S5"),
           "image": I.Subject.image("img-" + "0" * 16)}[kind]
    return I.make_claim(sub, field, value, REAL(basis=basis), unit=unit, qualifier=qualifier)


class TestFieldParsers(Base):
    def test_fld_01_product_model(self):
        """E01-FLD-01 model tokens are upper-cased; spaces, controls, non-ASCII, overlong are rejected."""
        self.assertEqual(claim("product_model", "s12").value, "S12")
        self.assertEqual(claim("product_model", " Sub ").value, "SUB")
        self.assertCode(I.R_ABSENT, claim, "product_model", "")
        self.assertCode(I.R_PLACEHOLDER, claim, "product_model", "unknown")
        for bad in ("S 1", "S\x001", "Ｓ１", "S" * 25, 5, None, "-S1"):
            self.assertCode(I.R_MALFORMED, claim, "product_model", bad)

    def test_fld_02_hardware_revision(self):
        """E01-FLD-02 revisions are canonicalised (leading zeros) and malformed/placeholder forms rejected."""
        self.assertEqual(claim("hardware_revision", "1.8.3.1-2").value, "1.8.3.1-2")
        self.assertEqual(claim("hardware_revision", "01.008.3.1-02").value, "1.8.3.1-2")
        self.assertEqual(claim("hardware_revision", "7").value, "7")
        self.assertCode(I.R_PLACEHOLDER, claim, "hardware_revision", "N/A")
        self.assertCode(I.R_ABSENT, claim, "hardware_revision", "  ")
        for bad in ("v1.2", "1.2-", "1.2.3.4.5.6.7", "1..2", "1.2-3-4", "123456", "a.b"):
            self.assertCode(I.R_MALFORMED, claim, "hardware_revision", bad)

    def test_fld_03_software_build(self):
        """E01-FLD-03 builds need >=2 dotted components."""
        self.assertEqual(claim("software_build", "57.23-74170").value, "57.23-74170")
        self.assertEqual(claim("software_build", "086.010-0081100").value, "86.10-81100")
        for bad in ("57", "57.23-", "57.23.1.1.1", "x.y"):
            self.assertCode(I.R_MALFORMED, claim, "software_build", bad)

    def test_fld_04_software_generation_is_not_a_model(self):
        """E01-FLD-04 generation is integer 1|2; model-like tokens (S1, S12, gen1) are flagged as conflation."""
        for ok, want in ((1, 1), (2, 2), ("1", 1), (" 2 ", 2)):
            self.assertEqual(claim("software_generation", ok).value, want)
        for tok in ("S1", "S2", "S12", "gen1", "ZB100"):
            self.assertCode(I.R_GEN_MODEL, claim, "software_generation", tok)
        for bad in (0, 3, "3", True, 1.0, "one", None, "-1"):
            self.assertCode(I.R_MALFORMED, claim, "software_generation", bad)

    def test_fld_05_isa(self):
        """E01-FLD-05 ISA aliases map to a closed vocabulary; unknown ISAs are not guessed."""
        for raw, want in (("PPC", "powerpc"), ("mips32", "mips"), ("X86_64", "x86_64"), ("arm64", "aarch64"), ("i686", "x86")):
            self.assertEqual(claim("arch.isa", raw, "kernel_cpuinfo").value, want)
        self.assertCode(I.R_ISA_UNRECOGNIZED, claim, "arch.isa", "sparc", "kernel_cpuinfo")
        self.assertCode(I.R_ABSENT, claim, "arch.isa", "", "kernel_cpuinfo")

    def test_fld_06_endianness_and_width(self):
        """E01-FLD-06 endianness aliases and 32|64 widths only."""
        self.assertEqual(claim("arch.endianness", "BE", "kernel_cpuinfo").value, "big")
        self.assertEqual(claim("arch.endianness", "msb", "kernel_cpuinfo").value, "big")
        self.assertEqual(claim("arch.endianness", "little", "kernel_cpuinfo").value, "little")
        self.assertCode(I.R_MALFORMED, claim, "arch.endianness", "middle", "kernel_cpuinfo")
        self.assertEqual(claim("arch.word_bits", "64", "kernel_cpuinfo").value, 64)
        for bad in (16, 0, True, "x", 32.0):
            self.assertCode(I.R_MALFORMED, claim, "arch.word_bits", bad, "kernel_cpuinfo")

    def test_fld_07_abi_and_float_abi(self):
        """E01-FLD-07 ABI tokens are lower-case identifiers; float ABI is hard|soft|softfp."""
        self.assertEqual(claim("arch.abi", "O32", "elf_attributes", "image").value, "o32")
        self.assertCode(I.R_MALFORMED, claim, "arch.abi", "o 32", "elf_attributes", "image")
        for ok in ("hard", "SOFT", "softfp"):
            claim("arch.float_abi", ok, "elf_attributes", "image")
        self.assertCode(I.R_MALFORMED, claim, "arch.float_abi", "medium", "elf_attributes", "image")

    def test_fld_08_soc_never_an_isa_name(self):
        """E01-FLD-08 a SoC must be a part name; ISA names there mean silicon was inferred from ISA."""
        self.assertEqual(claim("arch.soc", "mpc8247", "silicon_marking").value, "MPC8247")
        self.assertEqual(claim("arch.soc", "i.MX6  ULL", "silicon_marking").value, "I.MX6 ULL")
        self.assertEqual(claim("arch.soc", "Armada 370", "silicon_marking").value, "ARMADA 370")
        for isa in ("mips", "MIPS32", "mips32r2", "ppc", "PowerPC", "powerpc32", "armv7", "aarch64", "x86_64", "RISCV", "arm"):
            self.assertCode(I.R_SOC_ISA, claim, "arch.soc", isa, "silicon_marking")
        self.assertCode(I.R_MALFORMED, claim, "arch.soc", "x", "silicon_marking")

    def test_fld_09_nominal_bytes(self):
        """E01-FLD-09 nominal sizes need an explicit unit; MB and MiB are different byte counts."""
        self.assertEqual(claim("nominal_ram_bytes", 32, unit="MiB").value, 33554432)
        self.assertEqual(claim("nominal_ram_bytes", "32", unit="MB").value, 32000000)
        self.assertNotEqual(claim("nominal_ram_bytes", 32, unit="MB").value, claim("nominal_ram_bytes", 32, unit="MiB").value)
        self.assertEqual(claim("nominal_flash_bytes", 1, unit="GiB").value, 1073741824)
        self.assertCode(I.R_UNIT_UNKNOWN, claim, "nominal_ram_bytes", 32)
        self.assertCode(I.R_UNIT_INVALID, claim, "nominal_ram_bytes", 32, unit="Mbit")
        self.assertCode(I.R_UNIT_INVALID, claim, "nominal_ram_bytes", 32, unit="mib")
        for bad in (0, -1, 32.0, True, "9" * 16, "3.5", "3 4", "three", None):
            self.assertCode(I.R_MALFORMED, claim, "nominal_ram_bytes", bad, unit="MiB")
        self.assertCode(I.R_UNIT_INVALID, claim, "nominal_ram_bytes", "3x", unit="MiB")  # number 3 + unknown unit token
        self.assertCode(I.R_MALFORMED, claim, "nominal_ram_bytes", 2 ** 40, unit="GiB")


class TestExplicitUnitStrings(Base):
    def test_fld_10_explicit_unit_strings_keep_their_unit(self):
        """E01-FLD-10 '128 MB' keeps MB (decimal), '128 MiB' keeps MiB; the stated unit beats any operator default."""
        for raw, want in (("128 MB", 128 * 10 ** 6), ("128MB", 128 * 10 ** 6), ("128 MiB", 128 * 2 ** 20), (" 64 KiB ", 64 * 1024),
                          ("1 GiB", 2 ** 30), ("512 B", 512), ("8 GB", 8 * 10 ** 9)):
            self.assertEqual(claim("nominal_ram_bytes", raw).value, want, raw)            # no operator unit needed
            self.assertEqual(claim("nominal_ram_bytes", raw, unit="MiB").value, want, raw)  # operator unit must not override
        self.assertNotEqual(claim("nominal_ram_bytes", "128 MB").value, claim("nominal_ram_bytes", "128 MiB").value)
        # bare numbers are still unknown without an operator unit
        self.assertCode(I.R_UNIT_UNKNOWN, claim, "nominal_ram_bytes", "128")
        self.assertEqual(claim("nominal_ram_bytes", "128", unit="MB").value, 128 * 10 ** 6)

    def test_fld_11_explicit_unit_string_rejections(self):
        """E01-FLD-11 unknown/wrong-case/bit units are UNIT_INVALID; non-integers, zero and oversize are MALFORMED."""
        for bad in ("128 mb", "128 Mb", "128 Mbit", "128 M", "128 MIB", "128 mib"):
            self.assertCode(I.R_UNIT_INVALID, claim, "nominal_ram_bytes", bad)
        for bad in ("1.5 GB", "0 MB", "128 megabytes", "MB", "-8 MB", "128 MB extra", "999999999999999 GB", "\uff11\uff12 MB"):
            self.assertCode(I.R_MALFORMED, claim, "nominal_ram_bytes", bad)

    def test_fld_12_unit_string_whitespace_grammar_is_explicit(self):
        """E01-FLD-12 at most one ASCII space between number and unit; tab/newline/NBSP/runs of spaces are rejected, outer whitespace trimmed."""
        want = 128 * 10 ** 6
        for ok in ("128MB", "128 MB", "  128 MB", "128 MB  ", "\t128 MB\n"):
            self.assertEqual(claim("nominal_ram_bytes", ok).value, want, repr(ok))
        for bad in ("128\tMB", "128\nMB", "128\u00a0MB", "128  MB", "128   MB", "128 \tMB", "1 28 MB", "128 M B"):
            self.assertCode(I.R_MALFORMED, claim, "nominal_ram_bytes", bad)
        # the same grammar governs the provenance label: a rejected spelling never gets a src- origin
        n = N(mkrec(mem="128\tMB", flash="64  MiB"), SYN(), unit="MiB")
        self.assertEqual([c for c in n.claims if c.field.startswith("nominal_")], [])
        self.assertEqual(sorted(f.code for f in n.findings if f.field.startswith("nominal_")), [I.R_MALFORMED, I.R_MALFORMED])
        # and a rejected spelling does not fall back to the operator unit (no guessing)
        self.assertNotIn(I.R_UNIT_UNKNOWN, [f.code for f in n.findings])

    def test_rec_13_record_keeps_unit_provenance(self):
        """E01-REC-13 a record's '128 MB' keeps its unit with no operator flag; origin says whether the unit was stated (src-) or assumed (op-)."""
        n = N(mkrec(mem="128 MB", flash="64 MiB"), SYN())
        got = {c.field: (c.value, c.origin) for c in n.claims if c.field.startswith("nominal_")}
        self.assertEqual(got, {"nominal_ram_bytes": (128 * 10 ** 6, "fields.memory:src-MB"),
                               "nominal_flash_bytes": (64 * 2 ** 20, "fields.flash:src-MiB")})
        self.assertEqual([f for f in n.findings if f.code == I.R_UNIT_UNKNOWN], [])
        # explicit unit wins over the operator default, and the origin proves which one was used
        n = N(mkrec(mem="128 MB", flash="64"), SYN(), unit="MiB")
        got = {c.field: (c.value, c.origin) for c in n.claims if c.field.startswith("nominal_")}
        self.assertEqual(got["nominal_ram_bytes"], (128 * 10 ** 6, "fields.memory:src-MB"))
        self.assertEqual(got["nominal_flash_bytes"], (64 * 2 ** 20, "fields.flash:op-MiB"))
        # an unusable unit string is a finding, not a silently assumed unit
        n = N(mkrec(mem="128 Mbit", flash=None), SYN(), unit="MiB")
        self.assertNotIn("nominal_ram_bytes", [c.field for c in n.claims])
        self.assertIn(("nominal_ram_bytes", I.R_UNIT_INVALID), [(f.field, f.code) for f in n.findings])

    def test_nom_10_stated_and_assumed_units_conflict_visibly(self):
        """E01-NOM-10 device A states '128 MB', device B is a bare 128 assumed as MiB: the profile RAM conflicts and provenance shows why."""
        d = doc_of([N(mkrec(serial="U-1", mem="128 MB"), REAL(sid="unit-test-only/s1")),
                    N(mkrec(serial="U-2", mem="128"), REAL(sid="unit-test-only/s2"), unit="MiB")])
        r = profile_of(d)["fields"]["nominal_ram_bytes"]
        self.assertEqual((r["status"], r["value"]), ("conflict", None))
        origins = sorted(s["origin"] for c in r["candidates"] for s in c["sources"])
        self.assertEqual(origins, ["fields.memory:op-MiB", "fields.memory:src-MB"])
        # same number, same unit, different provenance: agree on the value, keep both provenances
        d = doc_of([N(mkrec(serial="U-1", mem="128 MB"), REAL(sid="unit-test-only/s1")),
                    N(mkrec(serial="U-2", mem="128"), REAL(sid="unit-test-only/s2"), unit="MB")])
        r = profile_of(d)["fields"]["nominal_ram_bytes"]
        self.assertEqual((r["status"], r["value"]), ("resolved", 128 * 10 ** 6))
        self.assertEqual(sorted(s["origin"] for s in r["candidates"][0]["sources"]), ["fields.memory:op-MB", "fields.memory:src-MB"])


class TestSharedProfileId(Base):
    def test_pid_01_canonicalizes_inputs(self):
        """E01-PID-01 messy raw spellings of one (model, revision) all give the golden id; there is one formula."""
        for m, r in (("S5", "1.8.3.1-2"), ("s5", "1.8.3.1-2"), (" S5 ", "01.008.3.1-02"), ("s5", "1.8.3.1-2")):
            self.assertEqual(I.profile_id_for(m, r), PID_S5_REV_A, (m, r))
        self.assertEqual(I.profile_id_for("S5", "1.20.1.6-2"), PID_S5_REV_B)
        self.assertNotEqual(I.profile_id_for("S5", "1.8.3.1-2"), I.profile_id_for("S3", "1.8.3.1-2"))
        self.assertNotEqual(I.profile_id_for("S5", "1.8.3.1-2"), I.profile_id_for("S5", "1.8.3.1-3"))

    def test_pid_02_unresolved_inputs_raise_instead_of_hashing_garbage(self):
        """E01-PID-02 absent/placeholder/malformed model or revision never yields an id."""
        self.assertCode(I.R_ABSENT, I.profile_id_for, "S5", "")
        self.assertCode(I.R_ABSENT, I.profile_id_for, "", "1.2")
        self.assertCode(I.R_PLACEHOLDER, I.profile_id_for, "S5", "unknown")
        self.assertCode(I.R_MALFORMED, I.profile_id_for, "S5", "v1.2")
        self.assertCode(I.R_MALFORMED, I.profile_id_for, "S 5", "1.2")
        self.assertCode(I.R_MALFORMED, I.profile_id_for, None, "1.2")
        self.assertCode(I.R_MALFORMED, I.profile_id_for, "S5", None)
        self.assertCode(I.R_MALFORMED, I.profile_id_for, "S5", 12)

    def test_pid_03_independent_callers_agree_with_the_fleet_document(self):
        """E01-PID-03 a caller that hashes raw record spellings (reconcile/enrich style) gets exactly the id the resolved fleet emits, in any batch order."""
        raws = [mkrec(serial="Q-1", model=" s5 ", hw="01.8.3.1-02"), mkrec(serial="Q-2", model="S5", hw="1.20.1.6-2"),
                mkrec(serial="Q-3", model="s3", hw="2.1")]
        direct = sorted(I.profile_id_for(r["fields"]["modelNumber"], r["fields"]["hardwareVersion"]) for r in raws)
        batches = [N(r, SYN()) for r in raws]
        rng = random.Random(7)
        for _ in range(5):
            rng.shuffle(batches)
            self.assertEqual(sorted(p["profile_id"] for p in doc_of(batches)["profiles"]), direct)


# =========================================================================== claim placement
class TestClaimPlacement(Base):
    def test_clm_01_description_cannot_assert_architecture(self):
        """E01-CLM-01 the device description has no CPU information: it can't assert any arch.* field."""
        sub = I.Subject.device(dev_token("P-1"))
        vals = {"arch.isa": "mips", "arch.endianness": "big", "arch.word_bits": 32, "arch.abi": "o32",
                "arch.float_abi": "hard", "arch.soc": "MPC8247"}
        for f, v in vals.items():
            self.assertCode(I.R_BASIS_FIELD, I.make_claim, sub, f, v, REAL(basis="live_description"))

    def test_clm_02_basis_field_matrix(self):
        """E01-CLM-02 ELF headers never assert a SoC or an identity/size field; cpuinfo can name a SoC but not an ABI."""
        img = I.Subject.image("img-" + "0" * 16)
        for f, v in (("arch.soc", "MPC8247"), ("product_model", "S5"), ("nominal_ram_bytes", 1), ("hardware_revision", "1.2")):
            self.assertCode(I.R_BASIS_FIELD, I.make_claim, img, f, v, REAL(basis="elf_header"))
        dev = I.Subject.device(dev_token("P-1"))
        I.make_claim(dev, "arch.soc", "MPC8247", REAL(basis="kernel_cpuinfo"))
        self.assertCode(I.R_BASIS_FIELD, I.make_claim, dev, "arch.abi", "o32", REAL(basis="kernel_cpuinfo"))
        self.assertCode(I.R_BASIS_FIELD, I.make_claim, dev, "arch.isa", "mips", REAL(basis="silicon_marking"))
        # teardown (hypothesis) can speak to architecture/resources but not to identity axes
        self.assertCode(I.R_BASIS_FIELD, I.make_claim, dev, "product_model", "S5", REAL(basis="published_teardown"))

    def test_clm_03_subject_kinds(self):
        """E01-CLM-03 claims attach only to subject kinds both the field and the basis allow."""
        img = I.Subject.image("img-" + "0" * 16)
        mdl = I.Subject.model("S5")
        dev = I.Subject.device(dev_token("P-1"))
        self.assertCode(I.R_SUBJECT, I.make_claim, img, "product_model", "S5", REAL())
        self.assertCode(I.R_SUBJECT, I.make_claim, dev, "arch.isa", "mips", REAL(basis="elf_header"))
        self.assertCode(I.R_SUBJECT, I.make_claim, mdl, "hardware_revision", "1.2", REAL(basis="owner_attestation"))
        self.assertCode(I.R_SUBJECT, I.make_claim, img, "nominal_ram_bytes", 1, REAL(basis="published_teardown"), unit="MiB")
        I.make_claim(mdl, "arch.isa", "mips", REAL(basis="published_teardown"))

    def test_clm_04_qualifiers(self):
        """E01-CLM-04 bounds exist only for nominal resources; unknown qualifiers rejected."""
        mdl = I.Subject.model("S5")
        I.make_claim(mdl, "nominal_ram_bytes", 256, REAL(basis="vendor_documentation"), unit="MiB", qualifier="upper_bound")
        self.assertCode(I.R_QUALIFIER, I.make_claim, mdl, "arch.isa", "mips", REAL(basis="vendor_documentation"), qualifier="upper_bound")
        self.assertCode(I.R_QUALIFIER, I.make_claim, mdl, "nominal_ram_bytes", 1, REAL(basis="vendor_documentation"), unit="MiB", qualifier="approx")

    def test_clm_05_no_series_or_family_fields(self):
        """E01-CLM-05 there is no field through which series id, family or era could carry identity."""
        sub = I.Subject.device(dev_token("P-1"))
        for f in ("seriesid", "series_id", "product_family", "release_year", "era", "cpu", "arch", "arch.", "", None, 5):
            self.assertCode(I.R_FIELD_UNKNOWN, I.make_claim, sub, f, "x", REAL())

    def test_clm_06_hand_built_claims_are_validated(self):
        """E01-CLM-06 invalid or non-canonical Claim objects cannot be constructed directly."""
        sub = I.Subject.device(dev_token("P-1"))
        src = REAL()
        self.assertCode(I.R_MALFORMED, I.Claim, sub, "product_model", "s5", src)      # not canonical (lower-case)
        self.assertCode(I.R_MALFORMED, I.Claim, sub, "software_generation", "2", src)  # not canonical (str)
        self.assertCode(I.R_MALFORMED, I.Claim, sub, "hardware_revision", "01.2", src)
        self.assertCode(I.R_FIELD_UNKNOWN, I.Claim, sub, "cpu", "x", src)
        self.assertCode(I.R_RECORD, I.Claim, sub, "product_model", "S5", src, "exact", "bad origin!")
        self.assertCode(I.R_RECORD, I.Claim, "device", "product_model", "S5", src)
        ok = I.Claim(sub, "software_generation", 2, src)
        with self.assertRaises(Exception):
            ok.value = 1  # frozen

    def test_clm_07_subject_validation(self):
        """E01-CLM-07 subject refs must be well-formed pseudonyms / canonical upper-case model tokens."""
        for kind, ref in (("device", "dev-xyz"), ("device", "SYN-0001"), ("image", "img-123"), ("model", "s5"),
                          ("model", ""), ("host", "x"), ("device", None)):
            self.assertCode(I.R_SUBJECT_INVALID, I.Subject, kind, ref)
        self.assertEqual(I.Subject.model("s5").ref, "S5")

    def test_clm_09_private_looking_tokens_are_rejected_per_field(self):
        """E01-CLM-09 a MAC/RINCON/long-hex shaped model, ABI or SoC token is rejected for that field (not accepted, not allowed to poison the fleet)."""
        for field, basis, kind, bad in (
                ("product_model", "live_description", "device", "000E58123456"),
                ("product_model", "live_description", "device", "RINCON_000E58123456"[:24]),
                ("arch.abi", "elf_attributes", "image", "00-0e-58-12-34-56"),
                ("arch.abi", "elf_attributes", "image", "deadbeefcafe0123"),
                ("arch.soc", "silicon_marking", "device", "00:0E:58:12:34:56"),
                ("arch.soc", "silicon_marking", "device", "DEADBEEFCAFE0123")):
            err = self.assertCode(I.R_MALFORMED, claim, field, bad, basis, kind)
            self.assertNotIn(bad.lower(), (str(err) + json.dumps(err.detail)).lower())
        # a record carrying such a model number yields a per-field finding and the rest of the fleet still resolves
        d = doc_of([N(mkrec(serial="K-1", model="000E58123456"), REAL()), N(mkrec(serial="K-2"), REAL())])
        self.assertEqual(len(d["devices"]), 2)
        bad_dev = [x for x in d["devices"] if x["fields"]["product_model"]["status"] != "resolved"]
        self.assertEqual(len(bad_dev), 1)
        self.assertEqual(bad_dev[0]["fields"]["product_model"]["reason_codes"], [I.R_MALFORMED, I.R_NO_EVIDENCE])
        # model numbers are public pass-through fields: a plain token is retained verbatim (upper-cased)
        self.assertEqual(claim("product_model", "Sub").value, "SUB")

    def test_clm_08_keys_dedupe_and_json(self):
        """E01-CLM-08 identical claims share a key; json carries provenance."""
        a, b = claim("product_model", "S5"), claim("product_model", "S5")
        self.assertEqual(a.key(), b.key())
        self.assertNotEqual(a.key(), claim("product_model", "S3").key())
        j = a.to_json()
        self.assertEqual((j["field"], j["value"], j["qualifier"]), ("product_model", "S5", "exact"))
        self.assertEqual(j["source"]["basis"], "live_description")


# =========================================================================== ELF evidence
class TestElf(Base):
    def run_elf(self, **kw):
        img = image("e", bind=False)
        n = I.normalize_elf_header(elf(**kw), img, I.Source("unit-test-only/elf", "elf_header"))
        return {c.field: c.value for c in n.claims}, n

    def test_elf_01_mips_be_o32(self):
        """E01-ELF-01 MIPS BE ELF32 with EF_MIPS_ABI_O32 (flags 0x70001005) => mips/big/32/o32; no float ABI, no SoC."""
        got, n = self.run_elf(machine=8, data=2, cls=1, flags=0x70001005)
        self.assertEqual(got, {"arch.endianness": "big", "arch.word_bits": 32, "arch.isa": "mips", "arch.abi": "o32"})
        self.assertEqual(n.findings, [])

    def test_elf_02_ppc_be(self):
        """E01-ELF-02 PowerPC BE ELF32 => powerpc/big/32 only; the header states no ABI, so none is claimed."""
        got, _ = self.run_elf(machine=20, data=2, cls=1, flags=0)
        self.assertEqual(got, {"arch.endianness": "big", "arch.word_bits": 32, "arch.isa": "powerpc"})

    def test_elf_03_arm_le_hard_float(self):
        """E01-ELF-03 ARM EABI5 hard-float flags (0x05000400) => arm/little/32/eabi/hard; soft flag => soft; neither => unknown."""
        got, _ = self.run_elf(machine=40, data=1, cls=1, flags=0x05000400)
        self.assertEqual(got, {"arch.endianness": "little", "arch.word_bits": 32, "arch.isa": "arm",
                               "arch.abi": "eabi", "arch.float_abi": "hard"})
        got, _ = self.run_elf(machine=40, data=1, cls=1, flags=0x05000200)
        self.assertEqual(got["arch.float_abi"], "soft")
        got, _ = self.run_elf(machine=40, data=1, cls=1, flags=0x05000000)
        self.assertNotIn("arch.float_abi", got)
        got, _ = self.run_elf(machine=40, data=1, cls=1, flags=0)  # not EABI5: no ABI claim at all
        self.assertNotIn("arch.abi", got)

    def test_elf_04_64bit_and_mips_variants(self):
        """E01-ELF-04 x86_64 LE ELF64; MIPS n32 via ABI2 flag; MIPS ELF64 => n64; MIPS ELF32 with no ABI bits => unknown ABI."""
        got, _ = self.run_elf(machine=62, data=1, cls=2)
        self.assertEqual(got, {"arch.endianness": "little", "arch.word_bits": 64, "arch.isa": "x86_64"})
        got, _ = self.run_elf(machine=8, data=2, cls=1, flags=0x20)
        self.assertEqual(got["arch.abi"], "n32")
        got, _ = self.run_elf(machine=8, data=2, cls=2, flags=0)
        self.assertEqual((got["arch.abi"], got["arch.word_bits"]), ("n64", 64))
        got, _ = self.run_elf(machine=8, data=2, cls=1, flags=0x70000000)
        self.assertNotIn("arch.abi", got)

    def test_elf_05_never_emits_soc(self):
        """E01-ELF-05 across every known machine/class/endianness combo, no arch.soc claim is ever produced."""
        for machine, cls in ((3, 1), (8, 1), (8, 2), (20, 1), (21, 2), (40, 1), (62, 2), (183, 2), (243, 1)):
            for data in (1, 2):
                got, _ = self.run_elf(machine=machine, data=data, cls=cls)
                self.assertNotIn("arch.soc", got, (machine, cls, data))

    def test_elf_06_unrecognized_machine_stays_unknown(self):
        """E01-ELF-06 unknown e_machine => no ISA claim + UNRECOGNIZED_ISA finding; endianness/width still reported."""
        got, n = self.run_elf(machine=0x1234, data=2, cls=1)
        self.assertEqual(got, {"arch.endianness": "big", "arch.word_bits": 32})
        self.assertEqual([(f.field, f.code) for f in n.findings], [("arch.isa", I.R_ISA_UNRECOGNIZED)])

    def test_elf_07_malformed_headers(self):
        """E01-ELF-07 bad magic/class/data/version/type/truncation/inconsistency are rejected with codes."""
        good = elf()
        img, src = image("m", bind=False), I.Source("unit-test-only/elf", "elf_header")
        run = lambda h: I.normalize_elf_header(h, img, src)  # noqa: E731
        self.assertCode(I.R_ELF_MALFORMED, run, b"")
        self.assertCode(I.R_ELF_MALFORMED, run, b"\x7fELG" + good[4:])
        self.assertCode(I.R_ELF_MALFORMED, run, good[:51])
        self.assertCode(I.R_ELF_MALFORMED, run, elf(cls=3))
        self.assertCode(I.R_ELF_MALFORMED, run, elf(data=0))
        self.assertCode(I.R_ELF_MALFORMED, run, elf(ver=2))
        self.assertCode(I.R_ELF_MALFORMED, run, elf(etype=9))
        self.assertCode(I.R_ELF_MALFORMED, run, elf(cls=2)[:63])
        self.assertCode(I.R_ELF_MALFORMED, run, "not bytes")
        self.assertCode(I.R_ELF_INCONSISTENT, run, elf(cls=1, machine=62))   # x86_64 in ELF32
        self.assertCode(I.R_ELF_INCONSISTENT, run, elf(cls=2, machine=20))   # 32-bit PPC in ELF64
        self.assertCode(I.R_ELF_INCONSISTENT, run, elf(cls=2, machine=40))   # 32-bit ARM in ELF64

    def test_elf_08_inputs_and_types(self):
        """E01-ELF-08 bytearray/memoryview accepted; trailing bytes ignored; wrong source basis / image type rejected."""
        img, src = image("t", bind=False), I.Source("unit-test-only/elf", "elf_header")
        for h in (bytearray(elf(machine=20)), memoryview(elf(machine=20)), elf(machine=20, pad=500)):
            n = I.normalize_elf_header(h, img, src)
            self.assertEqual({c.field: c.value for c in n.claims}["arch.isa"], "powerpc")
        self.assertCode(I.R_BASIS_FIELD, I.normalize_elf_header, elf(), img, REAL(basis="live_description"))
        self.assertCode(I.R_RECORD, I.normalize_elf_header, elf(), "img", src)
        self.assertEqual(I.normalize_elf_header(elf(), img, src).images, [img])
        # all claims are image-scoped, never device-scoped
        for c in I.normalize_elf_header(elf(), img, src).claims:
            self.assertEqual(c.subject, I.Subject.image(img.image_id))

    def test_elf_09_image_ref_validation(self):
        """E01-ELF-09 ImageRef: digest shape, bounded metadata, binding needs a sourced declaration."""
        sha = "a" * 64
        I.ImageRef(sha)
        for bad in ("", "A" * 64, "a" * 63, "g" * 64, None):
            self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, bad)
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, -1)
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 70000)
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, True)
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 1, "bad build")
        # binding to a model without a source, or with a non-binding basis, or a source without a model
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 1, "1.2-3", "S5", None)
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 1, "1.2-3", "S5", REAL(basis="live_description"))
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 1, "1.2-3", None, REAL(basis="vendor_documentation"))
        self.assertCode(I.R_IMAGE_INVALID, I.ImageRef, sha, 1, "1.2-3", "s 5", REAL(basis="vendor_documentation"))
        self.assertEqual(I.ImageRef(sha, 1, "01.2-3", "s5", REAL(basis="owner_attestation")).bound_product_model, "S5")


# =========================================================================== record normalization
class TestNormalizeRecord(Base):
    def test_rec_01_full_record_expected_claims(self):
        """E01-REC-01 a complete record yields exactly the expected claims; memory/flash stay UNIT_UNKNOWN."""
        n = N(mkrec(status_gen="1"), SYN())
        got = sorted((c.field, c.value, c.origin) for c in n.claims)
        self.assertEqual(got, [
            ("hardware_revision", "1.8.3.1-2", "fields.hardwareVersion"),
            ("product_model", "S5", "fields.modelNumber"),
            ("software_build", "57.23-74170", "fields.softwareVersion"),
            ("software_generation", 1, "fields.swGen"),
            ("software_generation", 1, "status.SWGen"),
        ])
        fs = sorted((f.field, f.code, f.detail["number"]) for f in n.findings)
        self.assertEqual(fs, [("nominal_flash_bytes", I.R_UNIT_UNKNOWN, 32), ("nominal_ram_bytes", I.R_UNIT_UNKNOWN, 32)])
        self.assertEqual(n.series_hint, "P100")
        self.assertEqual(n.device, dev_token("SYN-0001"))

    def test_rec_02_memory_unit_is_explicit(self):
        """E01-REC-02 a caller-supplied unit applies to memory/flash; an invalid unit is rejected up front."""
        n = N(mkrec(mem="128", flash="64"), SYN(), unit="MiB")
        got = {c.field: c.value for c in n.claims}
        self.assertEqual((got["nominal_ram_bytes"], got["nominal_flash_bytes"]), (128 * 2 ** 20, 64 * 2 ** 20))
        self.assertEqual([f for f in n.findings if f.code == I.R_UNIT_UNKNOWN], [])
        self.assertCode(I.R_UNIT_INVALID, I.normalize_record, mkrec(), SYN(), PS, memory_unit="Mbit")

    def test_rec_03_absent_stays_absent(self):
        """E01-REC-03 a missing hardwareVersion yields an ABSENT finding and no claim; other fields are unaffected."""
        n = N(mkrec(hw=None), SYN())
        self.assertNotIn("hardware_revision", [c.field for c in n.claims])
        self.assertIn(("hardware_revision", I.R_ABSENT), [(f.field, f.code) for f in n.findings])
        self.assertIn("product_model", [c.field for c in n.claims])
        n2 = N(mkrec(hw="   "), SYN())
        self.assertIn(("hardware_revision", I.R_ABSENT), [(f.field, f.code) for f in n2.findings])

    def test_rec_04_placeholder_and_malformed(self):
        """E01-REC-04 'unknown' is a PLACEHOLDER finding; garbage is MALFORMED with shape only (never the value)."""
        n = N(mkrec(hw="unknown"), SYN())
        self.assertIn(("hardware_revision", I.R_PLACEHOLDER), [(f.field, f.code) for f in n.findings])
        secret = "SECRET-REV-XYZ"
        n = N(mkrec(hw=secret), SYN())
        f = [x for x in n.findings if x.field == "hardware_revision"]
        self.assertEqual([x.code for x in f], [I.R_MALFORMED])
        self.assertNotIn("SECRET", json.dumps([x.to_json() for x in n.findings]))
        self.assertEqual(f[0].detail["shape"], "aaaaaa-aaa-aaa")  # structure only: letters->a, '-' kept

    def test_rec_05_generation_sources_may_disagree(self):
        """E01-REC-05 fields.swGen and status.SWGen are separate claims (origins differ) so disagreement is visible."""
        n = N(mkrec(gen="1", status_gen="2"), SYN())
        gens = sorted((c.origin, c.value) for c in n.claims if c.field == "software_generation")
        self.assertEqual(gens, [("fields.swGen", 1), ("status.SWGen", 2)])

    def test_rec_06_model_token_is_not_generation(self):
        """E01-REC-06 model 'S1' with swGen '2' stays model S1 / generation 2; a model token in swGen is a finding, not a claim."""
        n = N(mkrec(model="S1", gen="2"), SYN())
        got = {c.field: c.value for c in n.claims}
        self.assertEqual((got["product_model"], got["software_generation"]), ("S1", 2))
        n = N(mkrec(model="S1", gen="S1"), SYN())
        self.assertNotIn("software_generation", [c.field for c in n.claims])
        self.assertIn(("software_generation", I.R_GEN_MODEL), [(f.field, f.code) for f in n.findings])

    def test_rec_07_structural_errors_raise(self):
        """E01-REC-07 unkeyable or structurally invalid records raise instead of being half-processed."""
        for bad_serial in (None, "", "unknown", 7):
            self.assertCode(I.R_DEVICE_KEY, N, mkrec(serial=bad_serial))
        r = mkrec()
        del r["fields"]["serialNum"]
        self.assertCode(I.R_DEVICE_KEY, N, r)
        for bad in (None, [], "x", {"fields": []}, {"fields": {"serialNum": "A1"}, "status": []}, {"status": {}}):
            self.assertCode(I.R_RECORD, N, bad)
        self.assertCode(I.R_RECORD, I.normalize_record, mkrec(), REAL(basis="elf_header"), PS)
        self.assertCode(I.R_RECORD, I.normalize_record, mkrec(), REAL(), "not-a-pseudonymizer")
        self.assertCode(I.R_RECORD, I.normalize_record, mkrec(), "src", PS)

    def test_rec_08_observation_time_inheritance(self):
        """E01-REC-08 the record's observed_at fills an undated Source; an explicit Source time wins; garbage raises."""
        undated = I.Source("unit-test-only/u", "live_description")
        n = N(mkrec(observed_at="2026-11-04T08:00:00+00:00"), undated)
        self.assertEqual(n.source.observed_at, "2026-11-04T08:00:00Z")
        n = N(mkrec(observed_at="2026-11-04T08:00:00+00:00"), REAL(at="2026-11-06T00:00:00Z"))
        self.assertEqual(n.source.observed_at, "2026-11-06T00:00:00Z")
        n = N(mkrec(), undated)
        self.assertIsNone(n.source.observed_at)
        self.assertCode(I.R_TIME, N, mkrec(observed_at="soon"), undated)

    def test_rec_09_no_raw_identifier_in_any_output(self):
        """E01-REC-09 canary serial/address/room never appear in claims, findings or tokens."""
        n = N(mkrec(serial=CANARY_SERIAL, ip=CANARY_IP, room=CANARY_ROOM), SYN())
        blob = {"claims": [c.to_json() for c in n.claims], "findings": [f.to_json() for f in n.findings],
                "tokens": [n.device, n.address_token, list(n.label_tokens), n.series_hint], "src": n.source.to_json()}
        self.assertEqual(find_private(blob), [])
        self.assertEqual(I.find_private_identifiers(blob, canaries=[CANARY_SERIAL, CANARY_IP, CANARY_ROOM]), [])
        self.assertNotIn(CANARY_SERIAL.lower(), repr(n).lower())
        self.assertNotIn(CANARY_IP, repr(n))
        self.assertNotIn(CANARY_ROOM.lower(), repr(n).lower())

    def test_rec_10_tokens(self):
        """E01-REC-10 address/label/series tokens; unknown keys are counted, not echoed; bad series is a finding."""
        r = mkrec(ip="192.0.2.10", room="Room A", extra={"mystery": "x", "other": "y"})
        r["status"]["ZoneName"] = "Room B"
        n = N(r, SYN())
        self.assertEqual(n.address_token, PS.address("192.0.2.10"))
        self.assertEqual(n.label_tokens, tuple(sorted((PS.label("Room A"), PS.label("Room B")))))
        self.assertEqual(n.ignored_keys, 2)
        n = N(mkrec(series="A 100!"), SYN())
        self.assertIsNone(n.series_hint)
        self.assertIn(("series_hint", I.R_MALFORMED), [(f.field, f.code) for f in n.findings])
        r = mkrec()
        r["url"] = "http://"  # scheme only, no host
        n = N(r, SYN())
        self.assertIsNone(n.address_token)
        self.assertIn(("address", I.R_ADDRESS), [(f.field, f.code) for f in n.findings])
        n = N(mkrec(ip=None, room=None), SYN())
        self.assertEqual((n.address_token, n.label_tokens), (None, ()))

    def test_rec_11_hostile_values(self):
        """E01-REC-11 oversize, non-string, nested and control-char values become bounded findings, never exceptions."""
        hostile = {"modelNumber": "S" * 10000, "hardwareVersion": {"a": 1}, "softwareVersion": ["1.2"],
                   "swGen": 1.5, "memory": "9" * 100, "flash": float("nan"), "seriesid": 5}
        r = mkrec()
        r["fields"].update(hostile)
        n = N(r, SYN())
        self.assertEqual(n.claims, [])  # every hostile value rejected; none half-accepted
        for f in n.findings:
            self.assertLessEqual(len(json.dumps(f.to_json())), 600)
            self.assertIn(f.code, I.REASON_CODES)
        self.assertNotIn("SSSSSSSS", json.dumps([f.to_json() for f in n.findings]))

    def test_rec_12_peer_report_records_are_hypothesis_tier(self):
        """E01-REC-12 a peer-reported record yields hypothesis-tier claims (never observed)."""
        n = N(mkrec(serial="UT-PEER-1"), REAL(sid="unit-test-only/peer", basis="peer_report"))
        self.assertTrue(n.claims)
        for c in n.claims:
            self.assertEqual(I.BASES[c.source.basis].tier, "hypothesis")


def find_private(obj):
    return I.find_private_identifiers(obj)


# =========================================================================== resolution
class TestResolution(Base):
    def test_res_01_profile_id_golden_and_unknown_not_guessed(self):
        """E01-RES-01 profile id is the golden value; with no architecture evidence arch.* stays unknown and the profile is blocked."""
        d = doc_of([N(mkrec(), SYN())])
        p = profile_of(d)
        self.assertEqual(p["profile_id"], PID_S5_REV_A)
        for f in ("arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi", "arch.soc"):
            r = p["fields"][f]
            self.assertEqual((r["status"], r["value"], r["reason_codes"]), ("unknown", None, [I.R_NO_EVIDENCE]), f)
        ram = p["fields"]["nominal_ram_bytes"]
        self.assertEqual((ram["status"], ram["value"]), ("unknown", None))
        self.assertEqual(ram["reason_codes"], [I.R_NO_EVIDENCE, I.R_UNIT_UNKNOWN])
        self.assertEqual(ram["unit_unknown_numbers"], [{"number": 32, "source_id": "synthetic:fixture-a", "consistent_with_units": []}])
        self.assertFalse(p["activation_eligible"])
        self.assertIn("arch.isa:NO_EVIDENCE", p["blocking_reasons"])
        self.assertIn("nominal_ram_bytes:UNIT_UNKNOWN", p["blocking_reasons"])
        self.assertTrue(d["synthetic"])

    def test_res_02_absent_revision_means_no_profile(self):
        """E01-RES-02 absent hardware revision => revision unknown, no profile id, no board selected."""
        d = doc_of([N(mkrec(hw=None), SYN())])
        self.assertEqual(d["profiles"], [])
        dev = d["devices"][0]
        r = dev["fields"]["hardware_revision"]
        self.assertEqual((r["status"], r["value"]), ("unknown", None))
        self.assertIn(I.R_ABSENT, r["reason_codes"])
        self.assertIsNone(dev["profile_id"])
        self.assertIn("hardware_revision:" + I.R_ABSENT, dev["unassigned_reasons"])
        self.assertEqual(d["denominators"]["devices_without_profile"], 1)
        self.assertEqual(d["models"][0]["devices_without_profile"], 1)
        # placeholder and malformed revisions behave identically (unknown, not guessed)
        for hw, code in (("unknown", I.R_PLACEHOLDER), ("v?", I.R_MALFORMED)):
            d = doc_of([N(mkrec(hw=hw), SYN())])
            self.assertEqual(d["profiles"], [])
            self.assertIn("hardware_revision:" + code, d["devices"][0]["unassigned_reasons"])

    def test_res_03_duplicate_observations_are_idempotent(self):
        """E01-RES-03 replaying the same observation (same batch twice, or two identical normalizations) changes nothing."""
        n = N(mkrec(), SYN())
        once = I.resolve_fleet([n]).to_json()
        self.assertEqual(I.resolve_fleet([n, n, n]).to_json(), once)
        self.assertEqual(I.resolve_fleet([n, N(mkrec(), SYN())]).to_json(), once)
        d = json.loads(once)
        self.assertEqual(d["devices"][0]["observation_count"], 1)

    def test_res_04_duplicate_identity_with_conflicting_model_is_not_selected(self):
        """E01-RES-04 one serial reported as S5 by one source and S3 by another => conflict, value None, no board chosen."""
        a = N(mkrec(model="S5"), REAL(sid="unit-test-only/scan-a"))
        b = N(mkrec(model="S3"), REAL(sid="unit-test-only/scan-b"))
        d = doc_of([a, b])
        self.assertEqual(len(d["devices"]), 1)
        r = d["devices"][0]["fields"]["product_model"]
        self.assertEqual((r["status"], r["value"]), ("conflict", None))
        self.assertEqual(r["reason_codes"], [I.R_CONFLICT])
        self.assertEqual([(c["value"], [s["source_id"] for s in c["sources"]]) for c in r["candidates"]],
                         [("S3", ["unit-test-only/scan-b"]), ("S5", ["unit-test-only/scan-a"])])
        self.assertEqual(d["profiles"], [])
        self.assertIsNone(d["devices"][0]["profile_id"])
        self.assertEqual(d["devices"][0]["unassigned_reasons"], ["product_model:" + I.R_CONFLICT])

    def test_res_05_agreeing_sources_merge_with_both_provenances(self):
        """E01-RES-05 two sources agreeing on the model => resolved; both sources are kept in provenance."""
        a = N(mkrec(), REAL(sid="unit-test-only/scan-a"))
        b = N(mkrec(), REAL(sid="unit-test-only/scan-b", at=T1))
        r = doc_of([a, b])["devices"][0]["fields"]["product_model"]
        self.assertEqual((r["status"], r["value"]), ("resolved", "S5"))
        self.assertEqual(len(r["candidates"]), 1)
        self.assertEqual([s["source_id"] for s in r["candidates"][0]["sources"]], ["unit-test-only/scan-a", "unit-test-only/scan-b"])

    def test_res_06_renamed_and_readdressed_device_is_one_device(self):
        """E01-RES-06 same serial, new room name and new address => one device, no conflict, both tokens visible."""
        a = N(mkrec(room="Room A", ip="192.0.2.10"), REAL(sid="unit-test-only/scan-1", at=T0))
        b = N(mkrec(room="Room B", ip="192.0.2.11"), REAL(sid="unit-test-only/scan-2", at=T1))
        d = doc_of([a, b])
        self.assertEqual(len(d["devices"]), 1)
        dev = d["devices"][0]
        self.assertEqual(dev["address_tokens"], sorted([PS.address("192.0.2.10"), PS.address("192.0.2.11")]))
        self.assertEqual(dev["label_tokens"], sorted([PS.label("Room A"), PS.label("Room B")]))
        self.assertEqual(dev["observation_count"], 2)
        self.assertEqual(dev["profile_id"], PID_S5_REV_A)
        for f in DEVICE_FIELDS:
            self.assertEqual(dev["fields"][f]["status"], "resolved", f)

    def test_res_07_conflicting_revisions_are_not_merged(self):
        """E01-RES-07 same serial, two different revisions (even at different times) => conflict; hardware does not change over time."""
        a = N(mkrec(hw="1.8.3.1-2"), REAL(sid="unit-test-only/scan-1", at=T0))
        b = N(mkrec(hw="1.20.1.6-2"), REAL(sid="unit-test-only/scan-2", at=T1))
        d = doc_of([a, b])
        r = d["devices"][0]["fields"]["hardware_revision"]
        self.assertEqual((r["status"], r["value"], r["history"]), ("conflict", None, []))
        self.assertEqual(d["profiles"], [])
        # model also immutable across time
        c = N(mkrec(model="S3"), REAL(sid="unit-test-only/scan-3", at=T1))
        r = doc_of([a, c])["devices"][0]["fields"]["product_model"]
        self.assertEqual(r["status"], "conflict")

    def test_res_08_generation_and_model_are_separate_axes(self):
        """E01-RES-08 model S1 running software generation 2 is fully resolved; S1 vs S12 are different profiles."""
        d = doc_of([N(mkrec(serial="A-1", model="S1", gen="2", model_name="Play:1"), SYN()),
                    N(mkrec(serial="A-2", model="S12", gen="2", model_name="Play:1"), SYN())])
        by = {x["fields"]["product_model"]["value"]: x for x in d["devices"]}
        self.assertEqual(by["S1"]["fields"]["software_generation"]["value"], 2)
        self.assertEqual(by["S12"]["fields"]["software_generation"]["value"], 2)
        self.assertNotEqual(by["S1"]["profile_id"], by["S12"]["profile_id"])
        self.assertEqual(sorted(p["product_model"] for p in d["profiles"]), ["S1", "S12"])

    def test_res_09_generation_disagreement_within_one_record(self):
        """E01-RES-09 fields.swGen=1 vs status.SWGen=2 at the same instant => software_generation conflict; model unaffected."""
        d = doc_of([N(mkrec(gen="1", status_gen="2"), REAL())])
        g = d["devices"][0]["fields"]["software_generation"]
        self.assertEqual((g["status"], g["value"], g["reason_codes"]), ("conflict", None, [I.R_CONFLICT]))
        self.assertEqual(d["devices"][0]["fields"]["product_model"]["status"], "resolved")
        # a software-axis conflict does not delete the board profile (hardware identity is intact) ...
        self.assertEqual(d["devices"][0]["profile_id"], PID_S5_REV_A)
        # ... but the conflict stays visible on the device
        self.assertEqual(g["candidates"][0]["value"], 1)
        self.assertEqual(g["candidates"][1]["value"], 2)

    def test_res_10_mutable_axes_keep_ordered_history(self):
        """E01-RES-10 build/generation changes across dated observations => latest wins, history kept, reason CHANGED_OVER_TIME."""
        a = N(mkrec(sw="57.23-74170", gen="1"), REAL(sid="unit-test-only/scan-1", at=T0))
        b = N(mkrec(sw="86.10-81100", gen="2"), REAL(sid="unit-test-only/scan-2", at=T1))
        for order in ([a, b], [b, a]):
            dev = doc_of(order)["devices"][0]
            sb, sg = dev["fields"]["software_build"], dev["fields"]["software_generation"]
            self.assertEqual((sb["status"], sb["value"], sb["reason_codes"]), ("resolved", "86.10-81100", [I.R_CHANGED]))
            self.assertEqual(sb["history"], [{"observed_at": T0, "values": ["57.23-74170"]},
                                             {"observed_at": T1, "values": ["86.10-81100"]}])
            self.assertEqual((sg["status"], sg["value"]), ("resolved", 2))
            self.assertEqual(sg["history"], [{"observed_at": T0, "values": [1]}, {"observed_at": T1, "values": [2]}])

    def test_res_11_undated_or_simultaneous_disagreement_is_conflict(self):
        """E01-RES-11 differing builds that cannot be ordered (undated, or same instant) => conflict."""
        und = I.Source("unit-test-only/u", "live_description")
        a = N(mkrec(sw="57.23-74170"), REAL(sid="unit-test-only/scan-1", at=T0))
        b = N(mkrec(sw="86.10-81100"), und)
        sb = doc_of([a, b])["devices"][0]["fields"]["software_build"]
        self.assertEqual((sb["status"], sb["value"]), ("conflict", None))
        self.assertEqual(sb["reason_codes"], [I.R_CONFLICT, I.R_UNORDERABLE])
        c = N(mkrec(sw="86.10-81100"), REAL(sid="unit-test-only/scan-3", at=T0))
        sb = doc_of([a, c])["devices"][0]["fields"]["software_build"]
        self.assertEqual((sb["status"], sb["value"], sb["reason_codes"]), ("conflict", None, [I.R_CONFLICT]))

    def test_res_12_series_id_is_not_identity(self):
        """E01-RES-12 Play:3, Sub and Playbar share series id A100 but are three models/profiles with no conflicts."""
        batches = [N(mkrec(serial="B-%d" % i, model=m, series="A100", hw="1.%d" % i), SYN())
                   for i, m in enumerate(("S3", "Sub", "S9"), start=1)]
        d = doc_of(batches)
        self.assertEqual([m["product_model"] for m in d["models"]], ["S3", "S9", "SUB"])
        for m in d["models"]:
            self.assertEqual(m["series_hints"], ["A100"])
            self.assertEqual(len(m["profile_ids"]), 1)
        self.assertEqual(len({p["profile_id"] for p in d["profiles"]}), 3)
        for dev in d["devices"]:
            self.assertEqual(dev["fields"]["product_model"]["status"], "resolved")

    def test_res_13_different_revision_is_a_different_profile(self):
        """E01-RES-13 same model, other revision => other profile id (golden); extra members keep the id."""
        d = doc_of([N(mkrec(serial="C-1", hw="1.8.3.1-2"), SYN()), N(mkrec(serial="C-2", hw="1.20.1.6-2"), SYN()),
                    N(mkrec(serial="C-3", hw="1.8.3.1-2"), SYN())])
        self.assertEqual(sorted(p["profile_id"] for p in d["profiles"]), sorted([PID_S5_REV_A, PID_S5_REV_B]))
        self.assertEqual(profile_of(d)["device_count"], 2)
        self.assertEqual(profile_of(d, rev="1.20.1.6-2")["device_count"], 1)
        self.assertEqual(d["models"][0]["hardware_revisions"], ["1.20.1.6-2", "1.8.3.1-2"])


DEVICE_FIELDS = I.DEVICE_FIELDS


class TestArchitectureResolution(Base):
    def test_arc_01_bound_image_resolves_isa_but_not_soc_or_missing_abi(self):
        """E01-ARC-01 a bound PPC BE image resolves isa/endianness/width; abi, float ABI and SoC stay unknown (never inferred)."""
        img = image("a")
        d = doc_of([N(mkrec(), REAL()), elf_norm(img, machine=20)])
        f = profile_of(d)["fields"]
        self.assertEqual([(k, f[k]["status"], f[k]["value"]) for k in ("arch.isa", "arch.endianness", "arch.word_bits")],
                         [("arch.isa", "resolved", "powerpc"), ("arch.endianness", "resolved", "big"), ("arch.word_bits", "resolved", 32)])
        for k in ("arch.abi", "arch.float_abi", "arch.soc"):
            self.assertEqual((f[k]["status"], f[k]["value"]), ("unknown", None), k)
        self.assertIn("arch.abi:NO_EVIDENCE", profile_of(d)["blocking_reasons"])
        self.assertEqual(f["arch.isa"]["candidates"][0]["sources"][0]["subject"], "image:" + img.image_id)

    def test_arc_02_unbound_image_is_visible_but_unused(self):
        """E01-ARC-02 an image with no sourced model binding contributes nothing to any profile and is listed as unbound."""
        img = image("u", bind=False)
        d = doc_of([N(mkrec(), REAL()), elf_norm(img, machine=8, flags=0x70001005)])
        f = profile_of(d)["fields"]
        self.assertEqual((f["arch.isa"]["status"], f["arch.isa"]["value"]), ("unknown", None))
        self.assertEqual([(u["image_id"], u["reason"]) for u in d["unbound_evidence"]], [(img.image_id, I.R_IMAGE_UNBOUND)])
        listed = {(c["field"], c["value"]) for c in d["unbound_evidence"][0]["claims"]}
        self.assertIn(("arch.isa", "mips"), listed)

    def test_arc_03_teardown_vs_elf_stays_explicit(self):
        """E01-ARC-03 teardown says PowerPC for S1, an unmapped ELF says MIPS: hypothesis_only + visible unbound evidence; once bound, observed wins and the teardown is listed as contradicted."""
        td = I.Normalized(claims=[I.make_claim(I.Subject.model("S1"), "arch.isa", "powerpc",
                                               REAL(sid="unit-test-only/teardown", basis="published_teardown"))])
        rec = N(mkrec(model="S1", series="A101"), REAL())
        unbound = image("s1", model="S1", bind=False)
        d = doc_of([rec, td, elf_norm(unbound, machine=8, flags=0x70001005)])
        isa = profile_of(d, "S1")["fields"]["arch.isa"]
        self.assertEqual((isa["status"], isa["value"], isa["reason_codes"]), ("hypothesis_only", None, [I.R_HYPOTHESIS_ONLY]))
        self.assertEqual([c["value"] for c in isa["candidates"]], ["powerpc"])
        self.assertEqual(d["unbound_evidence"][0]["reason"], I.R_IMAGE_UNBOUND)
        bound = image("s1", model="S1", bind=True)  # same digest, now with a sourced binding
        d = doc_of([rec, td, elf_norm(bound, machine=8, flags=0x70001005)])
        isa = profile_of(d, "S1")["fields"]["arch.isa"]
        self.assertEqual((isa["status"], isa["value"]), ("resolved", "mips"))
        self.assertEqual([c["value"] for c in isa["contradicted_hypotheses"]], ["powerpc"])
        self.assertEqual(d["unbound_evidence"], [])

    def test_arc_04_image_scoped_to_its_model_only(self):
        """E01-ARC-04 an image bound to S1 gives nothing to S12 (family/era is never a bridge)."""
        d = doc_of([N(mkrec(serial="F-1", model="S1", model_name="Play:1"), REAL()),
                    N(mkrec(serial="F-2", model="S12", model_name="Play:1"), REAL()),
                    elf_norm(image("f", model="S1"), machine=8, flags=0x70001005)])
        self.assertEqual(profile_of(d, "S1")["fields"]["arch.isa"]["value"], "mips")
        self.assertEqual(profile_of(d, "S12")["fields"]["arch.isa"]["status"], "unknown")

    def test_arc_05_conflicting_historical_images(self):
        """E01-ARC-05 two images bound to one model that disagree on ISA => arch.isa conflict, both candidates, profile blocked."""
        i1, i2 = image("old", build="57.23-74170"), image("new", build="86.10-81100", imid=17)
        d = doc_of([N(mkrec(), REAL()), elf_norm(i1, machine=20), elf_norm(i2, machine=8, flags=0x70001005)])
        p = profile_of(d)
        isa = p["fields"]["arch.isa"]
        self.assertEqual((isa["status"], isa["value"], isa["reason_codes"]), ("conflict", None, [I.R_CONFLICT]))
        self.assertEqual({c["value"]: c["sources"][0]["subject"] for c in isa["candidates"]},
                         {"powerpc": "image:" + i1.image_id, "mips": "image:" + i2.image_id})
        self.assertFalse(p["activation_eligible"])
        self.assertIn("arch.isa:" + I.R_CONFLICT, p["blocking_reasons"])
        # the fields they agree on are still resolved (a conflict on one axis does not erase the others)
        self.assertEqual(p["fields"]["arch.endianness"]["value"], "big")

    def test_arc_06_agreeing_historical_images_resolve(self):
        """E01-ARC-06 two builds agreeing on ISA => resolved with both images in provenance."""
        i1, i2 = image("old", build="57.23-74170"), image("new", build="86.10-81100", imid=17)
        d = doc_of([N(mkrec(), REAL()), elf_norm(i1, machine=20), elf_norm(i2, machine=20)])
        isa = profile_of(d)["fields"]["arch.isa"]
        self.assertEqual((isa["status"], isa["value"]), ("resolved", "powerpc"))
        self.assertEqual(len(isa["candidates"][0]["sources"]), 2)

    def test_arc_07_one_digest_bound_to_two_models_is_unusable(self):
        """E01-ARC-07 the same image digest bound to S5 and to S3 => IMAGE_BINDING_CONFLICT, usable by neither."""
        a, b = image("same", model="S5"), image("same", model="S3")
        self.assertEqual(a.sha256, b.sha256)
        d = doc_of([N(mkrec(serial="G-1", model="S5"), REAL()), N(mkrec(serial="G-2", model="S3"), REAL()),
                    elf_norm(a, machine=20), I.Normalized(images=[b])])
        for m in ("S5", "S3"):
            self.assertEqual(profile_of(d, m)["fields"]["arch.isa"]["status"], "unknown", m)
        self.assertIn(I.R_IMAGE_BINDING_CONFLICT, [x["code"] for x in d["image_findings"]])
        self.assertEqual(d["unbound_evidence"][0]["reason"], I.R_IMAGE_BINDING_CONFLICT)

    def test_arc_08_same_build_different_digest_blocks_profile(self):
        """E01-ARC-08 two digests claiming the same (internal model, build) => IMAGE_DIGEST_CONFLICT blocks an otherwise-eligible profile."""
        base = complete()
        ok = profile_of(doc_of(base))
        self.assertTrue(ok["activation_eligible"], ok["blocking_reasons"])
        twin = image("twin")  # same internal id 16 + build as image("a")
        d = doc_of(base + [elf_norm(twin, machine=20), attrs_norm(twin)])
        p = profile_of(d)
        self.assertFalse(p["activation_eligible"])
        self.assertEqual(p["blocking_reasons"], ["profile:" + I.R_IMAGE_DIGEST_CONFLICT])
        self.assertEqual(p["fields"]["arch.isa"]["status"], "resolved")  # evidence agrees; digests do not
        f = [x for x in d["image_findings"] if x["code"] == I.R_IMAGE_DIGEST_CONFLICT]
        self.assertEqual(len(f), 1)
        self.assertEqual(len(f[0]["image_ids"]), 2)

    def test_arc_09_image_metadata_conflict(self):
        """E01-ARC-09 one digest declared with two different internal model ids => IMAGE_METADATA_CONFLICT is reported."""
        sha = hashlib.sha256(b"synthetic-image-digest/meta").hexdigest()
        a, b = I.ImageRef(sha, 16, "57.23-74170"), I.ImageRef(sha, 12, "57.23-74170")
        d = doc_of([I.Normalized(images=[a]), I.Normalized(images=[b])])
        self.assertIn(I.R_IMAGE_META_CONFLICT, [x["code"] for x in d["image_findings"]])

    def test_arc_10_bound_model_absent_from_fleet(self):
        """E01-ARC-10 evidence bound to a model with no device in the fleet is listed, not silently dropped."""
        img = image("x", model="S9")
        d = doc_of([N(mkrec(), REAL()), elf_norm(img, machine=20)])
        self.assertEqual([(u["image_id"], u["reason"]) for u in d["unbound_evidence"]], [(img.image_id, I.R_BOUND_MODEL_ABSENT)])

    def test_arc_11_unrecognized_machine_flows_to_reasons(self):
        """E01-ARC-11 an ELF with an unknown e_machine leaves arch.isa unknown and says why."""
        img = image("q")
        d = doc_of([N(mkrec(), REAL()), elf_norm(img, machine=0x4242)])
        isa = profile_of(d)["fields"]["arch.isa"]
        self.assertEqual(isa["status"], "unknown")
        self.assertIn(I.R_ISA_UNRECOGNIZED, isa["reason_codes"])
        self.assertIn(I.R_ISA_UNRECOGNIZED, [x["code"] for x in d["image_findings"]])

    def test_arc_12_isa_field_consistency(self):
        """E01-ARC-12 internally inconsistent architecture (x86_64 big-endian) blocks the profile."""
        img = image("w")
        n = I.normalize_elf_header(elf(cls=2, data=2, machine=62), img, I.Source("unit-test-only/elf-x", "elf_header"))
        d = doc_of([N(mkrec(), REAL()), n])
        self.assertIn("arch:" + I.R_ARCH_INCONSISTENT, profile_of(d)["blocking_reasons"])

    def test_arc_13_device_level_cpu_evidence_pools_into_the_profile(self):
        """E01-ARC-13 kernel/cpuinfo-style evidence on a member device (soc) lands in the profile; conflicting socs block even when not required."""
        tok = dev_token("UT-0001")
        mk = lambda soc, sid: I.Normalized(claims=[I.make_claim(  # noqa: E731
            I.Subject.device(tok), "arch.soc", soc, REAL(sid=sid, basis="silicon_marking"))])
        d = doc_of(complete() + [mk("MPC8247", "unit-test-only/marking-a")])
        p = profile_of(d)
        self.assertEqual((p["fields"]["arch.soc"]["status"], p["fields"]["arch.soc"]["value"]), ("resolved", "MPC8247"))
        self.assertTrue(p["activation_eligible"], p["blocking_reasons"])
        d = doc_of(complete() + [mk("MPC8247", "unit-test-only/marking-a"), mk("MPC8314", "unit-test-only/marking-b")])
        p = profile_of(d)
        self.assertEqual(p["fields"]["arch.soc"]["status"], "conflict")
        self.assertFalse(p["activation_eligible"])
        self.assertIn("arch.soc:" + I.R_CONFLICT, p["blocking_reasons"])

    def test_arc_14_claims_for_unassigned_devices_are_not_pooled(self):
        """E01-ARC-14 a device without a resolved revision gets no profile; its architecture claims stay attached to it, unused."""
        tok = dev_token("UT-9")
        cl = I.make_claim(I.Subject.device(tok), "arch.isa", "mips", REAL(basis="kernel_cpuinfo"))
        d = doc_of([N(mkrec(serial="UT-9", hw=None), REAL()), I.Normalized(claims=[cl])])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(d["devices"][0]["unattached_claim_fields"], ["arch.isa"])

    def test_arc_15_device_and_model_evidence_is_scoped_to_its_own_profile(self):
        """E01-ARC-15 device-level and model-level architecture claims reach only their own profile; an unassigned device's evidence reaches none."""
        cpu = lambda serial, isa, sid: I.Normalized(claims=[I.make_claim(  # noqa: E731
            I.Subject.device(dev_token(serial)), "arch.isa", isa, REAL(sid=sid, basis="kernel_cpuinfo"))])
        vendor_s3 = I.Normalized(claims=[I.make_claim(I.Subject.model("S3"), "arch.endianness", "little",
                                                      REAL(sid="unit-test-only/vendor", basis="vendor_documentation"))])
        d = doc_of([
            N(mkrec(serial="P-1", model="S5", hw="1.8.3.1-2"), REAL()),
            N(mkrec(serial="P-2", model="S3", hw="2.1.0"), REAL()),
            N(mkrec(serial="P-3", model="S5", hw=None), REAL()),   # unassigned: revision absent
            cpu("P-1", "powerpc", "unit-test-only/c1"), cpu("P-2", "mips", "unit-test-only/c2"),
            cpu("P-3", "arm", "unit-test-only/c3"),                # must not leak into S5/1.8.3.1-2
            vendor_s3])
        s5, s3 = profile_of(d, "S5", "1.8.3.1-2"), profile_of(d, "S3", "2.1.0")
        self.assertEqual((s5["fields"]["arch.isa"]["status"], s5["fields"]["arch.isa"]["value"]), ("resolved", "powerpc"))
        self.assertEqual((s3["fields"]["arch.isa"]["status"], s3["fields"]["arch.isa"]["value"]), ("resolved", "mips"))
        self.assertEqual(s5["fields"]["arch.endianness"]["status"], "unknown")
        self.assertEqual(s3["fields"]["arch.endianness"]["value"], "little")
        self.assertEqual([c["value"] for c in s5["fields"]["arch.isa"]["candidates"]], ["powerpc"])
        self.assertEqual(s5["member_devices"], [dev_token("P-1")])
        unassigned = [x for x in d["devices"] if x["profile_id"] is None]
        self.assertEqual([x["device"] for x in unassigned], [dev_token("P-3")])
        self.assertEqual(unassigned[0]["unattached_claim_fields"], ["arch.isa"])


class TestNominalResources(Base):
    def vendor(self, value, unit, qualifier="exact", sid="unit-test-only/vendor", basis="vendor_documentation"):
        return I.Normalized(claims=[I.make_claim(I.Subject.model("S5"), "nominal_ram_bytes", value, REAL(sid=sid, basis=basis),
                                                 unit=unit, qualifier=qualifier)])

    def ram(self, d):
        return profile_of(d)["fields"]["nominal_ram_bytes"]

    def test_nom_01_unit_unknown_is_never_a_value(self):
        """E01-NOM-01 a bare XML number alone never resolves RAM, even though it looks like '32'."""
        r = self.ram(doc_of([N(mkrec(mem="32"), REAL())]))
        self.assertEqual((r["status"], r["value"]), ("unknown", None))
        self.assertIn(I.R_UNIT_UNKNOWN, r["reason_codes"])

    def test_nom_02_unit_bearing_source_resolves_and_annotates(self):
        """E01-NOM-02 a unit-bearing 32 MiB source resolves RAM; the bare '32' is annotated as consistent with MiB only (not MB)."""
        r = self.ram(doc_of([N(mkrec(mem="32"), REAL()), self.vendor(32, "MiB")]))
        self.assertEqual((r["status"], r["value"]), ("resolved", 33554432))
        self.assertEqual(r["unit_unknown_numbers"][0]["consistent_with_units"], ["MiB"])

    def test_nom_03_mb_vs_mib_is_a_conflict(self):
        """E01-NOM-03 32 MiB (vendor) vs 32 MB (second declared source) => conflict, not rounded together."""
        r = self.ram(doc_of([N(mkrec(), REAL()), self.vendor(32, "MiB"), self.vendor(32, "MB", sid="unit-test-only/vendor-2")]))
        self.assertEqual((r["status"], r["value"], r["reason_codes"]), ("conflict", None, [I.R_CONFLICT]))
        self.assertEqual(sorted(c["value"] for c in r["candidates"]), [32000000, 33554432])

    def test_nom_04_upper_bound(self):
        """E01-NOM-04 '<=256 MiB' with observed 128 MiB resolves; with observed 512 MiB it is BOUND_VIOLATED; a bound alone is unknown."""
        ub = self.vendor(256, "MiB", "upper_bound")
        ok = self.ram(doc_of([N(mkrec(mem="128"), REAL(), unit="MiB"), ub]))
        self.assertEqual((ok["status"], ok["value"]), ("resolved", 128 * 2 ** 20))
        bad = self.ram(doc_of([N(mkrec(mem="512"), REAL(), unit="MiB"), ub]))
        self.assertEqual((bad["status"], bad["value"], bad["reason_codes"]), ("conflict", None, [I.R_BOUND_VIOLATED]))
        only = self.ram(doc_of([N(mkrec(), REAL()), ub]))
        self.assertEqual((only["status"], only["value"]), ("unknown", None))
        self.assertEqual(only["candidates"][0]["qualifier"], "upper_bound")

    def test_nom_05_lower_bound_and_inconsistent_bounds(self):
        """E01-NOM-05 a lower bound is enforced; lower > upper is itself a conflict."""
        lb = self.vendor(64, "MiB", "lower_bound")
        r = self.ram(doc_of([N(mkrec(mem="32"), REAL(), unit="MiB"), lb]))
        self.assertEqual((r["status"], r["reason_codes"]), ("conflict", [I.R_BOUND_VIOLATED]))
        ub = self.vendor(32, "MiB", "upper_bound", sid="unit-test-only/vendor-2")
        r = self.ram(doc_of([N(mkrec(), REAL()), lb, ub]))
        self.assertEqual((r["status"], r["reason_codes"]), ("conflict", [I.R_BOUND_VIOLATED]))

    def test_nom_06_hypothesis_bound_never_overrides(self):
        """E01-NOM-06 a teardown's '<=64 MiB' does not override an observed 128 MiB; the contradiction is listed."""
        hb = self.vendor(64, "MiB", "upper_bound", basis="published_teardown", sid="unit-test-only/teardown")
        r = self.ram(doc_of([N(mkrec(mem="128"), REAL(), unit="MiB"), hb]))
        self.assertEqual((r["status"], r["value"]), ("resolved", 128 * 2 ** 20))
        self.assertEqual([(c["value"], c["qualifier"]) for c in r["contradicted_hypotheses"]], [(64 * 2 ** 20, "upper_bound")])

    def test_nom_07_devices_of_one_profile_must_agree(self):
        """E01-NOM-07 two members of one profile reporting 32 vs 64 MiB => profile RAM conflict, blocked."""
        d = doc_of([N(mkrec(serial="M-1", mem="32"), REAL(sid="unit-test-only/s1"), unit="MiB"),
                    N(mkrec(serial="M-2", mem="64"), REAL(sid="unit-test-only/s2"), unit="MiB")])
        p = profile_of(d)
        self.assertEqual((p["fields"]["nominal_ram_bytes"]["status"], p["fields"]["nominal_ram_bytes"]["value"]), ("conflict", None))
        self.assertIn("nominal_ram_bytes:" + I.R_CONFLICT, p["blocking_reasons"])
        self.assertEqual(p["device_count"], 2)

    def test_nom_08_teardown_sample_does_not_override_owned_unit(self):
        """E01-NOM-08 a teardown RAM sample (64 MiB) disagreeing with the owned unit (128 MiB) is listed as contradicted, not merged."""
        td = self.vendor(64, "MiB", basis="published_teardown", sid="unit-test-only/teardown")
        r = self.ram(doc_of([N(mkrec(mem="128"), REAL(), unit="MiB"), td]))
        self.assertEqual(r["value"], 128 * 2 ** 20)
        self.assertEqual([c["value"] for c in r["contradicted_hypotheses"]], [64 * 2 ** 20])

    def test_nom_09_hypothesis_alone_does_not_resolve(self):
        """E01-NOM-09 a teardown alone => hypothesis_only; disagreeing hypotheses add HYPOTHESES_DISAGREE."""
        a = self.vendor(64, "MiB", basis="published_teardown", sid="unit-test-only/t1")
        r = self.ram(doc_of([N(mkrec(), REAL()), a]))
        self.assertEqual((r["status"], r["value"], r["reason_codes"]), ("hypothesis_only", None, sorted([I.R_HYPOTHESIS_ONLY, I.R_UNIT_UNKNOWN])))
        b = self.vendor(32, "MiB", basis="community_research", sid="unit-test-only/t2")
        r = self.ram(doc_of([N(mkrec(), REAL()), a, b]))
        self.assertEqual(r["status"], "hypothesis_only")
        self.assertIn(I.R_HYPOTHESES_DISAGREE, r["reason_codes"])


class TestEligibilityAndDigests(Base):
    def test_elg_01_complete_nonsynthetic_is_eligible(self):
        """E01-ELG-01 all required fields resolved from non-synthetic sources, no conflicts => eligible (precondition only)."""
        p = profile_of(doc_of(complete()))
        self.assertEqual((p["activation_eligible"], p["blocking_reasons"]), (True, []))
        f = p["fields"]
        self.assertEqual([f[k]["value"] for k in ("arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi", "nominal_ram_bytes")],
                         ["powerpc", "big", 32, "sysv", "hard", 33554432])
        self.assertEqual(p["profile_id"], PID_S5_REV_A)

    def test_elg_02_synthetic_evidence_never_eligible(self):
        """E01-ELG-02 the same data from synthetic: sources is never eligible; each required field says SYNTHETIC_EVIDENCE_ONLY."""
        d = doc_of(complete(synthetic=True))
        p = profile_of(d)
        self.assertFalse(p["activation_eligible"])
        self.assertEqual(p["blocking_reasons"], sorted("%s:%s" % (f, I.R_SYNTHETIC_ONLY) for f in
                         ("arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi", "nominal_ram_bytes")))
        self.assertTrue(d["synthetic"])
        self.assertEqual(d["denominators"]["synthetic_only"], 1)
        self.assertEqual(d["denominators"]["independent_observation"], 0)

    def test_elg_03_synthetic_binding_taints_image_evidence(self):
        """E01-ELG-03 non-synthetic ELF evidence reached through a synthetic binding is tainted: arch blocks, nominal does not."""
        img = image("t", synthetic=True)
        batches = [N(mkrec(), REAL(), unit="MiB"), elf_norm(img, machine=20), attrs_norm(img)]
        p = profile_of(doc_of(batches))
        self.assertEqual(p["blocking_reasons"], sorted("%s:%s" % (f, I.R_SYNTHETIC_ONLY) for f in
                         ("arch.isa", "arch.endianness", "arch.word_bits", "arch.abi", "arch.float_abi")))
        src = p["fields"]["arch.isa"]["candidates"][0]["sources"][0]
        self.assertEqual((src["synthetic"], src["tainted_by_synthetic_binding"]), (True, True))
        self.assertTrue(profile_of(doc_of(complete()))["activation_eligible"])  # paired positive

    def test_elg_04_partial_synthetic_support_is_not_synthetic_only(self):
        """E01-ELG-04 a field supported by one synthetic and one non-synthetic source is not 'synthetic only'."""
        b = complete() + [N(mkrec(serial="UT-0002", mem="32"), SYN(sid="synthetic:extra"), unit="MiB")]
        p = profile_of(doc_of(b))
        self.assertTrue(p["activation_eligible"], p["blocking_reasons"])

    def test_elg_05_required_parameter(self):
        """E01-ELG-05 narrowing `required` changes eligibility; unknown names / non-sequences are rejected."""
        base = [N(mkrec(), REAL())]
        self.assertFalse(profile_of(doc_of(base))["activation_eligible"])
        d = doc_of(base, required=("product_model", "hardware_revision"))
        self.assertTrue(profile_of(d)["activation_eligible"])
        self.assertEqual(d["required_fields"], ["hardware_revision", "product_model"])
        for bad in (("software_build",), ("cpu",), "arch.isa", (1,), None):
            self.assertCode(I.R_FIELD_UNKNOWN, I.resolve_fleet, base, required=bad)

    def test_elg_06_conflicting_evidence_blocks_but_keeps_profile_id(self):
        """E01-ELG-06 adding a conflicting observed claim flips eligible->ineligible; id unchanged, evidence digest changes."""
        before = profile_of(doc_of(complete()))
        cl = I.make_claim(I.Subject.device(dev_token("UT-0001")), "arch.isa", "mips", REAL(sid="unit-test-only/cpuinfo", basis="kernel_cpuinfo"))
        after = profile_of(doc_of(complete() + [I.Normalized(claims=[cl])]))
        self.assertTrue(before["activation_eligible"])
        self.assertFalse(after["activation_eligible"])
        self.assertEqual(after["profile_id"], before["profile_id"])
        self.assertNotEqual(after["evidence_digest"], before["evidence_digest"])
        self.assertEqual(after["blocking_reasons"], ["arch.isa:" + I.R_CONFLICT])
        self.assertEqual(after["fields"]["arch.isa"]["value"], None)

    def test_elg_07_extra_members_keep_profile_id_change_digest(self):
        """E01-ELG-07 a second device in the same profile keeps the id and updates the evidence digest."""
        one = profile_of(doc_of(complete()))
        two = profile_of(doc_of(complete() + [N(mkrec(serial="UT-0002", mem="32"), REAL(sid="unit-test-only/scan-b"), unit="MiB")]))
        self.assertEqual(one["profile_id"], two["profile_id"])
        self.assertEqual((one["device_count"], two["device_count"]), (1, 2))
        self.assertNotEqual(one["evidence_digest"], two["evidence_digest"])
        self.assertTrue(two["activation_eligible"])

    def test_elg_08_hypothesis_only_required_field_blocks(self):
        """E01-ELG-08 a required field supported only by a teardown blocks with HYPOTHESIS_ONLY."""
        td = I.Normalized(claims=[I.make_claim(I.Subject.model("S5"), "arch.abi", "sysv", REAL(sid="unit-test-only/td", basis="published_teardown"))])
        base = [b for b in complete() if not (b.claims and b.claims[0].field in ("arch.abi", "arch.float_abi"))]
        base.append(I.Normalized(images=[image("a")]))  # keep the binding
        p = profile_of(doc_of(base + [td]))
        self.assertIn("arch.abi:" + I.R_HYPOTHESIS_ONLY, p["blocking_reasons"])
        self.assertFalse(p["activation_eligible"])

    def test_elg_09_digest_covers_provenance(self):
        """E01-ELG-09 changing only a provenance field (source id) changes the evidence digest and fleet digest, not the profile id."""
        a = profile_of(doc_of([N(mkrec(), REAL(sid="unit-test-only/scan-a"))]))
        b = profile_of(doc_of([N(mkrec(), REAL(sid="unit-test-only/scan-z"))]))
        self.assertEqual(a["profile_id"], b["profile_id"])
        self.assertNotEqual(a["evidence_digest"], b["evidence_digest"])


class TestDenominators(Base):
    def test_den_01_independent_vs_peer_reports(self):
        """E01-DEN-01 18 independent observations + 3 peer reports => 21 devices total but never '21 verified'."""
        batches = [N(mkrec(serial="UT-%04d" % i, ip="192.0.2.%d" % (i + 1), model="S5" if i < 8 else "S3"),
                     REAL(sid="unit-test-only/scan-1")) for i in range(18)]
        batches += [N(mkrec(serial="UT-PEER-%d" % i, ip=None, room=None, hw=None),
                      REAL(sid="unit-test-only/peer", basis="peer_report")) for i in range(3)]
        d = doc_of(batches)
        den = d["denominators"]
        self.assertEqual((den["devices_total"], den["independent_observation"], den["peer_reported_only"]), (21, 18, 3))
        self.assertEqual((den["synthetic_only"], den["other_unverified"]), (0, 0))
        self.assertEqual(den["independent_observation"] + den["peer_reported_only"] + den["synthetic_only"] + den["other_unverified"], den["devices_total"])
        peers = [x for x in d["devices"] if x["verification"] == "peer_reported_only"]
        self.assertEqual(len(peers), 3)
        for x in peers:
            self.assertIsNone(x["profile_id"])
            self.assertEqual(x["fields"]["product_model"]["status"], "hypothesis_only")
            self.assertIn("product_model:" + I.R_HYPOTHESIS_ONLY, x["unassigned_reasons"])

    def test_den_02_peer_and_independent_on_one_device(self):
        """E01-DEN-02 a peer report about an independently observed device doesn't double count; a wrong peer value is listed as contradicted."""
        own = N(mkrec(serial="UT-0001", model="S5"), REAL(sid="unit-test-only/scan-1"))
        peer = N(mkrec(serial="UT-0001", model="S3"), REAL(sid="unit-test-only/peer", basis="peer_report"))
        d = doc_of([own, peer])
        self.assertEqual(d["denominators"]["devices_total"], 1)
        self.assertEqual(d["denominators"]["independent_observation"], 1)
        r = d["devices"][0]["fields"]["product_model"]
        self.assertEqual((r["status"], r["value"]), ("resolved", "S5"))
        self.assertEqual([c["value"] for c in r["contradicted_hypotheses"]], ["S3"])

    def test_den_03_synthetic_partition(self):
        """E01-DEN-03 synthetic-only devices form their own bucket; synthetic + real is independent."""
        syn = N(mkrec(serial="UT-S1"), SYN())
        mixed_a = N(mkrec(serial="UT-M1"), SYN(sid="synthetic:m"))
        mixed_b = N(mkrec(serial="UT-M1"), REAL(sid="unit-test-only/scan-m"))
        den = doc_of([syn, mixed_a, mixed_b])["denominators"]
        self.assertEqual((den["devices_total"], den["synthetic_only"], den["independent_observation"]), (2, 1, 1))

    def test_den_04_declared_only_is_unverified(self):
        """E01-DEN-04 a device known only through an owner attestation is 'other_unverified'."""
        tok = dev_token("UT-A1")
        cl = I.make_claim(I.Subject.device(tok), "product_model", "S5", REAL(sid="unit-test-only/attest", basis="owner_attestation"))
        den = doc_of([I.Normalized(device=tok, claims=[cl])])["denominators"]
        self.assertEqual((den["devices_total"], den["other_unverified"], den["independent_observation"]), (1, 1, 0))

    def test_den_05_empty_fleet(self):
        """E01-DEN-05 an empty fleet is a valid, stable, all-zero document."""
        a, b = I.resolve_fleet([]), I.resolve_fleet(iter(()))
        self.assertEqual(a.to_json(), b.to_json())
        d = a.to_public_json()
        self.assertEqual((d["denominators"]["devices_total"], d["profiles"], d["devices"]), (0, [], []))


class TestOrderAndInput(Base):
    def mixed(self):
        i1, i2 = image("old"), image("new", build="86.10-81100", imid=17)
        td = I.Normalized(claims=[I.make_claim(I.Subject.model("S5"), "arch.soc", "MPC8247", REAL(sid="unit-test-only/td", basis="published_teardown"))])
        return [
            N(mkrec(serial="O-1", room="Room A", ip="192.0.2.10"), REAL(sid="unit-test-only/scan-1", at=T0), unit="MiB"),
            N(mkrec(serial="O-1", room="Room B", ip="192.0.2.11", sw="86.10-81100", gen="2"), REAL(sid="unit-test-only/scan-2", at=T1), unit="MiB"),
            N(mkrec(serial="O-2", model="S3", series="A100"), SYN()),
            N(mkrec(serial="O-3", hw=None), REAL(sid="unit-test-only/scan-3")),
            N(mkrec(serial="O-4", model="S5"), REAL(sid="unit-test-only/scan-4"), unit="MiB"),
            N(mkrec(serial="O-4", model="S3"), REAL(sid="unit-test-only/scan-5"), unit="MiB"),
            N(mkrec(serial="O-5", ip=None), REAL(sid="unit-test-only/peer", basis="peer_report")),
            elf_norm(i1, machine=20), elf_norm(i2, machine=8, flags=0x70001005), attrs_norm(i1), td,
        ]

    def test_ord_01_batch_order_does_not_matter(self):
        """E01-ORD-01 40 seeded shuffles of mixed batches (conflicts, peers, images, hypotheses) give byte-identical output."""
        base = self.mixed()
        want = I.resolve_fleet(base).to_json()
        rng = random.Random(20261104)
        for i in range(40):
            b = list(base)
            rng.shuffle(b)
            self.assertEqual(I.resolve_fleet(b).to_json(), want, "permutation %d" % i)

    def test_ord_02_replay_and_chunking(self):
        """E01-ORD-02 replaying every batch twice, or feeding via a generator, is identical."""
        base = self.mixed()
        want = I.resolve_fleet(base).to_json()
        self.assertEqual(I.resolve_fleet(base + base).to_json(), want)
        self.assertEqual(I.resolve_fleet(x for x in reversed(base)).to_json(), want)

    def test_ord_03_conflicts_stay_visible_in_the_mixed_fleet(self):
        """E01-ORD-03 in that mixed fleet the S5/S3 conflict, the ISA conflict and the unknown revision all remain visible and ineligible."""
        d = doc_of(self.mixed())
        dev = {x["device"]: x for x in d["devices"]}
        self.assertEqual(dev[dev_token("O-4")]["fields"]["product_model"]["status"], "conflict")
        self.assertIsNone(dev[dev_token("O-4")]["profile_id"])
        self.assertIsNone(dev[dev_token("O-3")]["profile_id"])
        p = profile_of(d)
        self.assertEqual(p["fields"]["arch.isa"]["status"], "conflict")
        self.assertFalse(p["activation_eligible"])
        self.assertEqual(p["fields"]["arch.soc"]["status"], "hypothesis_only")
        self.assertEqual(d["denominators"]["peer_reported_only"], 1)

    def test_ord_04_public_doc_is_clean_and_deepcopy_safe(self):
        """E01-ORD-04 the public document passes the privacy scan; to_public_json returns an independent copy."""
        f = I.resolve_fleet(self.mixed())
        d = f.to_public_json()
        self.assertEqual(I.find_private_identifiers(d), [])
        self.assertEqual(d["schema"], I.SCHEMA)
        d["profiles"].clear()
        d["denominators"]["devices_total"] = -1
        self.assertNotEqual(f.to_public_json()["profiles"], [])
        self.assertGreater(f.to_public_json()["denominators"]["devices_total"], 0)
        self.assertEqual(f.digest, f.to_public_json()["fleet_digest"])
        self.assertEqual(f.profile(PID_S5_REV_A)["profile_id"], PID_S5_REV_A)
        self.assertIsNone(f.profile("bp-0000000000000000"))
        self.assertEqual(f.device(dev_token("O-1"))["device"], dev_token("O-1"))
        self.assertIsNone(f.device("dev-" + "0" * 20))

    def test_agg_01_aggregate_view_has_no_per_device_data(self):
        """E01-AGG-01 the publishable view carries no devices, members, or any dev-/adr-/lbl- pseudonym, yet keeps profiles, denominators and reasons."""
        f = I.resolve_fleet(self.mixed())
        full = f.to_public_json()
        agg = f.to_aggregate_json()
        blob = json.dumps(agg, sort_keys=True)
        for needle in ("dev-", "adr-", "lbl-", "member_devices", '"devices"', "address_tokens", "label_tokens"):
            self.assertNotIn(needle, blob, needle)
        self.assertEqual(agg["view"], "aggregate")
        self.assertEqual(agg["denominators"], full["denominators"])
        self.assertEqual([p["profile_id"] for p in agg["profiles"]], [p["profile_id"] for p in full["profiles"]])
        self.assertEqual(agg["profiles"][0]["device_count"], full["profiles"][0]["device_count"])
        self.assertEqual(I.find_private_identifiers(agg, canaries=[CANARY_SERIAL, CANARY_IP, CANARY_ROOM]), [])
        # unassigned devices survive only as reason counts; worked out by hand from self.mixed():
        #   O-3 no hardwareVersion  -> hardware_revision unknown (ABSENT + NO_EVIDENCE)
        #   O-4 S5 vs S3 same instant -> product_model conflict
        #   O-5 peer report only     -> product_model and hardware_revision hypothesis_only
        self.assertEqual(agg["unassigned_reason_counts"], {
            "hardware_revision:" + I.R_ABSENT: 1, "hardware_revision:" + I.R_HYPOTHESIS_ONLY: 1,
            "hardware_revision:" + I.R_NO_EVIDENCE: 1, "product_model:" + I.R_CONFLICT: 1,
            "product_model:" + I.R_HYPOTHESIS_ONLY: 1})
        self.assertEqual(sum(1 for _ in full["devices"]) - sum(p["device_count"] for p in full["profiles"]),
                         full["denominators"]["devices_without_profile"])
        # the full view is unchanged by asking for the aggregate
        self.assertEqual(f.to_public_json(), full)

    def test_agg_02_aggregate_view_is_independent_of_the_pseudonym_key(self):
        """E01-AGG-02 same evidence under a different secret key: full documents differ, aggregate documents are byte-identical."""
        other = I.Pseudonymizer(b"a-completely-different-synthetic-key-9876")

        def build(ps):
            return [I.normalize_record(r, REAL(sid="unit-test-only/scan-%d" % (i % 2)), ps, memory_unit="MiB")
                    for i, r in enumerate([mkrec(serial="K-1", room="A", ip="192.0.2.5"), mkrec(serial="K-2", hw="1.20.1.6-2"),
                                           mkrec(serial="K-3", hw=None)])]
        a, b = I.resolve_fleet(build(PS)), I.resolve_fleet(build(other))
        self.assertNotEqual(a.to_json(), b.to_json())
        self.assertEqual(json.dumps(a.to_aggregate_json(), sort_keys=True), json.dumps(b.to_aggregate_json(), sort_keys=True))
        self.assertEqual(a.to_aggregate_json()["aggregate_digest"], b.to_aggregate_json()["aggregate_digest"])

    def test_agg_03_aggregate_view_order_independent_and_evidence_sensitive(self):
        """E01-AGG-03 shuffled input gives the same aggregate; changing profile evidence changes its aggregate digest but not its id."""
        base = self.mixed()
        want = json.dumps(I.resolve_fleet(base).to_aggregate_json(), sort_keys=True)
        rng = random.Random(99)
        for _ in range(15):
            b = list(base)
            rng.shuffle(b)
            self.assertEqual(json.dumps(I.resolve_fleet(b).to_aggregate_json(), sort_keys=True), want)
        one = I.resolve_fleet(complete()).to_aggregate_json()["profiles"][0]
        two = I.resolve_fleet(complete() + [N(mkrec(serial="UT-0002", mem="64"), REAL(sid="unit-test-only/scan-b"), unit="MiB")]).to_aggregate_json()["profiles"][0]
        self.assertEqual(one["profile_id"], two["profile_id"])
        self.assertNotEqual(one["aggregate_evidence_digest"], two["aggregate_evidence_digest"])

    def test_dig_01_digests_cover_everything_else_in_both_views(self):
        """E01-DIG-01 every digest equals sha256 of the canonical JSON of the rest of its object, recomputed here independently."""
        def h(o):
            return hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        f = I.resolve_fleet(self.mixed())
        full, agg = f.to_public_json(), f.to_aggregate_json()
        self.assertEqual(full["fleet_digest"], h({k: v for k, v in full.items() if k != "fleet_digest"}))
        for p in full["profiles"]:
            self.assertEqual(p["evidence_digest"], h({k: v for k, v in p.items() if k != "evidence_digest"}))
        self.assertEqual(agg["aggregate_digest"], h({k: v for k, v in agg.items() if k != "aggregate_digest"}))
        self.assertIn("unassigned_reason_counts", agg)  # ...and that "rest" includes the reason histogram
        for p in agg["profiles"]:
            self.assertEqual(p["aggregate_evidence_digest"], h({k: v for k, v in p.items() if k != "aggregate_evidence_digest"}))
        # tampering with any covered part is detectable: change one count, the stored digest no longer matches
        tampered = copy.deepcopy(agg)
        tampered["unassigned_reason_counts"]["product_model:" + I.R_CONFLICT] += 1
        self.assertNotEqual(tampered["aggregate_digest"], h({k: v for k, v in tampered.items() if k != "aggregate_digest"}))

    def test_ord_05_canaries_never_reach_the_document(self):
        """E01-ORD-05 canary serial/address/room planted in inputs never appear anywhere in the resolved document."""
        b = [N(mkrec(serial=CANARY_SERIAL, ip=CANARY_IP, room=CANARY_ROOM, hw="unknown"), REAL()),
             N(mkrec(serial=CANARY_SERIAL, ip=CANARY_IP, room=CANARY_ROOM, sw="86.10-81100"), REAL(sid="unit-test-only/scan-b", at=T1))]
        f = I.resolve_fleet(b)
        self.assertEqual(I.find_private_identifiers(f.to_public_json(), canaries=[CANARY_SERIAL, CANARY_IP, CANARY_ROOM]), [])
        self.assertNotIn(CANARY_SERIAL.lower(), f.to_json().lower())
        self.assertNotIn(CANARY_IP, f.to_json())
        self.assertNotIn(CANARY_ROOM.lower(), f.to_json().lower())

    def test_ord_06_input_validation_and_limits(self):
        """E01-ORD-06 non-Normalized batches, foreign members and over-limit claim counts are rejected."""
        self.assertCode(I.R_RECORD, I.resolve_fleet, ["not a batch"])
        self.assertCode(I.R_RECORD, I.resolve_fleet, [I.Normalized(claims=["nope"])])
        self.assertCode(I.R_RECORD, I.resolve_fleet, [I.Normalized(findings=[object()])])
        self.assertCode(I.R_RECORD, I.resolve_fleet, [I.Normalized(images=["x"])])
        self.assertCode(I.R_SUBJECT_INVALID, I.resolve_fleet, [I.Normalized(device="SYN-0001")])
        big = [N(mkrec(serial="L-%d" % i), REAL()) for i in range(5)]
        with mock.patch.object(I, "MAX_CLAIMS", 10):
            self.assertCode(I.R_LIMIT, I.resolve_fleet, big)
        I.resolve_fleet(big)  # under the real limit

    def test_ord_07_leak_guard_fails_closed(self):
        """E01-ORD-07 if a finding detail smuggles an address-shaped string, resolve_fleet refuses to emit the document (and does not echo it)."""
        f = I.Finding(I.Subject.device(dev_token("X-1")), "product_model", I.R_MALFORMED, "unit-test-only/x", {"origin": "192.0.2.77"})
        err = self.assertCode(I.R_LEAK, I.resolve_fleet, [I.Normalized(device=dev_token("X-1"), findings=[f])])
        self.assertNotIn("192.0.2.77", str(err) + repr(err.detail))

    def test_ord_08_all_emitted_codes_are_registered(self):
        """E01-ORD-08 every reason/blocking/finding code that appears in the mixed fleet is in REASON_CODES."""
        d = doc_of(self.mixed())
        seen = set()

        def walk(o, key=None):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in ("code",) and isinstance(v, str):
                        seen.add(v)
                    walk(v, k)
            elif isinstance(o, list):
                for v in o:
                    if key in ("reason_codes",) and isinstance(v, str):
                        seen.add(v)
                    if key in ("blocking_reasons", "unassigned_reasons") and isinstance(v, str):
                        seen.add(v.split(":", 1)[1])
                    walk(v, key)
            elif isinstance(o, str) and key in ("reason",):
                seen.add(o)
        walk(d)
        self.assertTrue(seen)
        self.assertEqual(seen - I.REASON_CODES, set())
        self.assertEqual(len(I.REASON_CODES), len([k for k in vars(I) if k.startswith("R_")]))


class TestPrivacyGuard(Base):
    def test_prv_01_detects_each_kind_without_echoing_it(self):
        """E01-PRV-01 IPv4, MAC (: and -), RINCON, UUID, long hex and canaries are flagged by path+kind only."""
        samples = {
            "ipv4": "host 192.0.2.10 down", "mac": "00:0E:58:12:34:56", "mac2": "00-0e-58-12-34-56",
            "rincon": "RINCON_000E58123456", "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "hex": "deadbeefcafe0123", "canary": "see CanaryRoom-Name here",
        }
        out = I.find_private_identifiers({k: v for k, v in samples.items()}, canaries=["canaryroomname"])
        kinds = {}
        for s in out:  # a string may legitimately trigger several kinds (RINCON/UUID contain hex runs)
            path, kind = s.split(": ")
            kinds.setdefault(path.split(".")[-1], set()).add(kind)
        self.assertEqual(set(kinds), set(samples))
        for key, want in (("ipv4", "ipv4"), ("mac", "mac"), ("mac2", "mac"), ("rincon", "rincon"), ("uuid", "uuid"),
                          ("hex", "long_hex"), ("canary", "canary")):
            self.assertIn(want, kinds[key], key)
        for s in out:
            for raw in ("192.0.2", "0E:58", "deadbeef", "RINCON_0", "123e4567"):
                self.assertNotIn(raw, s)

    def test_prv_02_dotted_revision_exemption_is_field_scoped(self):
        """E01-PRV-02 '1.8.3.1-2' is fine as a hardware revision but flagged anywhere else; MACs stay flagged even under the revision key."""
        ok = {"fields": {"hardware_revision": {"field": "hardware_revision", "value": "1.8.3.1-2",
                                               "candidates": [{"value": "1.8.3.1-2"}]}}, "software_build": "57.23-74170.1.2"}
        self.assertEqual(I.find_private_identifiers(ok), [])
        self.assertTrue(I.find_private_identifiers({"note": "1.8.3.1-2"}))
        self.assertTrue(I.find_private_identifiers({"hardware_revision": "00:0E:58:12:34:56"}))
        self.assertTrue(I.find_private_identifiers({"hardware_revisions": ["RINCON_000E58123456"]}))

    def test_prv_03_pseudonyms_and_digests_are_not_flagged(self):
        """E01-PRV-03 dev-/adr-/lbl-/img-/bp- tokens and digest-keyed hashes are fine; the same hex elsewhere is flagged."""
        toks = {"a": PS.device("X-1"), "b": PS.address("192.0.2.10"), "c": PS.label("Room"), "d": "img-" + "a" * 16,
                "e": PID_S5_REV_A, "evidence_digest": "a" * 64, "fleet_digest": "b" * 64}
        self.assertEqual(I.find_private_identifiers(toks), [])
        self.assertTrue(I.find_private_identifiers({"other": "a" * 64}))
        self.assertTrue(I.find_private_identifiers({"a" * 12: 1}))  # keys are scanned too

    def test_prv_06_digest_keys_are_explicit_and_format_checked(self):
        """E01-PRV-06 only schema-defined digest keys, and only for an exact 64-lowercase-hex value, skip the hex check; nothing else is masked."""
        h = "0123456789abcdef" * 4
        self.assertEqual(I.find_private_identifiers({"evidence_digest": h, "fleet_digest": [h, h]}), [])
        for bad in (h.upper(), h[:-1], h + "0", "token-" + h, "ref=" + h, " " + h + " x", "z" * 64):
            hit = I.find_private_identifiers({"evidence_digest": bad})
            if bad == "z" * 64:
                self.assertEqual(hit, [])  # not hex at all: not an identifier shape
            else:
                self.assertTrue(hit, bad)
        self.assertTrue(I.find_private_identifiers({"profile_digest": h}))                      # not in the default set
        self.assertEqual(I.find_private_identifiers({"profile_digest": h}, digest_keys=("profile_digest",)), [])
        self.assertTrue(I.find_private_identifiers({"profile_digest": h.upper()}, digest_keys=("profile_digest",)))
        self.assertTrue(I.find_private_identifiers({"other": h}, digest_keys=("profile_digest",)))
        # exemption is per key, not inherited: a hex value nested under a digest key's sibling/child is still scanned
        self.assertTrue(I.find_private_identifiers({"evidence_digest": {"inner": h}}))
        self.assertTrue(I.find_private_identifiers({"evidence_digest": h, "leak": h}))
        for bad_keys in (("Bad Key",), ("",), (5,), ("a" * 41,)):
            self.assertCode(I.R_RECORD, I.find_private_identifiers, {}, digest_keys=bad_keys)

    def test_prv_04_walks_nesting_and_ignores_non_strings(self):
        """E01-PRV-04 nested lists/dicts are scanned; numbers/None/bools never flag."""
        self.assertTrue(I.find_private_identifiers({"a": [{"b": ["x", ("192.0.2.1",)]}]}))
        self.assertEqual(I.find_private_identifiers({"a": [1, 2.5, None, True, {"b": 192}]}), [])
        self.assertEqual(I.find_private_identifiers([]), [])
        self.assertEqual(I.find_private_identifiers("ok"), [])

    def test_prv_05_errors_never_echo_input(self):
        """E01-PRV-05 IdentityError message/detail never contain the offending value, for every parser and a range of hostile inputs."""
        secret = "ZZ-SECRET-9d7f"
        cases = [("product_model", "device", "live_description", secret + " x"), ("hardware_revision", "device", "live_description", secret),
                 ("software_build", "device", "live_description", secret), ("software_generation", "device", "live_description", secret),
                 ("arch.isa", "device", "kernel_cpuinfo", secret), ("arch.endianness", "device", "kernel_cpuinfo", secret),
                 ("arch.word_bits", "device", "kernel_cpuinfo", secret), ("arch.soc", "device", "kernel_cpuinfo", "#" + secret),
                 ("nominal_ram_bytes", "device", "live_description", secret), ("arch.abi", "image", "elf_attributes", "O 32 " + secret),
                 ("arch.float_abi", "image", "elf_attributes", secret)]
        for field, kind, basis, val in cases:
            try:
                claim(field, val, basis, kind, unit="MiB")
            except I.IdentityError as e:
                blob = str(e) + repr(e) + json.dumps(e.detail, default=str)
                self.assertNotIn("SECRET", blob, field)
            else:
                self.fail("expected rejection for %s" % field)
        for bad_serial in (secret,):
            try:
                PS.device("")
            except I.IdentityError as e:
                self.assertNotIn(bad_serial, str(e))


class TestProperties(Base):
    """Seeded randomized invariants. Failures print the seed and case index."""

    def scenario(self, rng):
        batches = []
        models = ["S5", "S1", "S12"]
        for i in range(rng.randint(1, 5)):
            base_model = rng.choice(models)
            for _ in range(rng.randint(1, 3)):
                src = REAL(sid="unit-test-only/scan-%d" % rng.randint(0, 3), at=rng.choice([None, T0, T1]))
                rec = mkrec(serial="UT-%04d" % i, model=rng.choice([base_model, base_model, "S3"]),
                            hw=rng.choice(["1.8.3.1-2", "1.20.1.6-2", None, "unknown"]),
                            sw=rng.choice(["57.23-74170", "86.10-81100"]), gen=rng.choice(["1", "2", "S1", None]),
                            mem=rng.choice(["32", "64", None]), flash=rng.choice(["32", None]),
                            ip="192.0.2.%d" % rng.randint(1, 254), room=rng.choice(["Room A", "Room B", None]),
                            status_gen=rng.choice([None, "1", "2"]))
                batches.append(N(rec, src, unit=rng.choice([None, "MiB", "MB"])))
        for j in range(rng.randint(0, 3)):
            img = image("p%d" % j, model=rng.choice(models), imid=rng.choice([12, 16]), build=rng.choice(["57.23-74170", "86.10-81100"]),
                        bind=rng.random() < 0.7, synthetic=rng.random() < 0.2)
            batches.append(elf_norm(img, machine=rng.choice([20, 8]), flags=rng.choice([0, 0x70001005])))
        if rng.random() < 0.5:
            batches.append(I.Normalized(claims=[I.make_claim(I.Subject.model(rng.choice(models)), "nominal_ram_bytes",
                                                             rng.choice([32, 64, 128]), REAL(sid="unit-test-only/vendor", basis="vendor_documentation"),
                                                             unit="MiB", qualifier=rng.choice(["exact", "upper_bound", "lower_bound"]))]))
        return batches

    def check_invariants(self, d, label):
        statuses = {"resolved", "unknown", "conflict", "hypothesis_only"}
        required = set(d["required_fields"])

        def check_res(r):
            self.assertIn(r["status"], statuses, label)
            if r["status"] == "resolved":
                self.assertIsNotNone(r["value"], label)
                exact_binding = {json.dumps(c["value"]) for c in r["candidates"] if c["qualifier"] == "exact" and c["tier"] != "hypothesis"}
                self.assertIn(json.dumps(r["value"]), exact_binding, label)
            else:
                self.assertIsNone(r["value"], label)
                self.assertTrue(r["reason_codes"], label)
            if r["status"] == "conflict":
                self.assertTrue(set(r["reason_codes"]) & {I.R_CONFLICT, I.R_BOUND_VIOLATED}, label)
            if r["field"] not in ("software_build", "software_generation") and r["status"] == "resolved":
                vals = {json.dumps(c["value"]) for c in r["candidates"] if c["qualifier"] == "exact" and c["tier"] != "hypothesis"}
                self.assertEqual(len(vals), 1, "immutable axis resolved with several binding values: " + label)
            for c in r["candidates"]:
                self.assertTrue(c["sources"], label)
        for dev in d["devices"]:
            for r in dev["fields"].values():
                check_res(r)
            if dev["profile_id"] is None:
                self.assertTrue(dev["unassigned_reasons"], label)
            else:
                m, rv = dev["fields"]["product_model"]["value"], dev["fields"]["hardware_revision"]["value"]
                self.assertEqual(dev["profile_id"], I.profile_id_for(m, rv), label)
        for p in d["profiles"]:
            for r in p["fields"].values():
                check_res(r)
            if p["activation_eligible"]:
                self.assertEqual(p["blocking_reasons"], [], label)
                for f in required - {"product_model", "hardware_revision"}:
                    self.assertEqual(p["fields"][f]["status"], "resolved", label + f)
                    self.assertFalse(p["fields"][f]["synthetic_only"], label + f)
                for r in p["fields"].values():
                    self.assertNotEqual(r["status"], "conflict", label)
            else:
                self.assertTrue(p["blocking_reasons"], label)
        self.assertEqual(I.find_private_identifiers(d), [], label)
        den = d["denominators"]
        self.assertEqual(den["devices_total"], len(d["devices"]), label)
        self.assertEqual(den["independent_observation"] + den["peer_reported_only"] + den["synthetic_only"] + den["other_unverified"],
                         den["devices_total"], label)

    def test_prp_01_invariants_and_order_independence(self):
        """E01-PRP-01 300 seeded random fleets: invariants hold (no silent merge, conflict => value None, eligible => clean) and output is order/duplication independent."""
        seed = 424242
        rng = random.Random(seed)
        for case in range(300):
            batches = self.scenario(rng)
            label = "seed=%d case=%d " % (seed, case)
            f = I.resolve_fleet(batches)
            self.check_invariants(f.to_public_json(), label)
            shuffled = list(batches) + list(batches)
            rng.shuffle(shuffled)
            self.assertEqual(I.resolve_fleet(shuffled).to_json(), f.to_json(), label + "(order/duplication)")

    def test_prp_02_adding_conflict_never_creates_eligibility(self):
        """E01-PRP-02 for each required architecture/resource field, a conflicting observed claim turns an eligible profile ineligible with that field blamed."""
        tok = dev_token("UT-0001")
        dev = I.Subject.device(tok)
        conflicts = {
            "arch.isa": I.make_claim(dev, "arch.isa", "mips", REAL(sid="unit-test-only/c1", basis="kernel_cpuinfo")),
            "arch.endianness": I.make_claim(dev, "arch.endianness", "little", REAL(sid="unit-test-only/c2", basis="kernel_cpuinfo")),
            "arch.word_bits": I.make_claim(dev, "arch.word_bits", 64, REAL(sid="unit-test-only/c3", basis="kernel_cpuinfo")),
            "nominal_ram_bytes": I.make_claim(I.Subject.model("S5"), "nominal_ram_bytes", 16, REAL(sid="unit-test-only/c4", basis="vendor_documentation"), unit="MiB"),
        }
        before = profile_of(doc_of(complete()))
        self.assertTrue(before["activation_eligible"])
        for field, cl in conflicts.items():
            after = profile_of(doc_of(complete() + [I.Normalized(claims=[cl])]))
            self.assertFalse(after["activation_eligible"], field)
            self.assertIn("%s:%s" % (field, I.R_CONFLICT), after["blocking_reasons"], field)
            self.assertEqual(after["profile_id"], before["profile_id"], field)
            self.assertIsNone(after["fields"][field]["value"], field)


if __name__ == "__main__":
    unittest.main(verbosity=2)
