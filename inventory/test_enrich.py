#!/usr/bin/env python3
"""Tests for inventory/enrich.py (stdlib only, offline, temp directories only).

Run from the repository root:

    python3 -m unittest discover -s inventory -p 'test_enrich.py' -v

Every fixture is synthetic: RFC 5737 documentation addresses, locally
administered MACs, invented serials. None of it describes a real unit. Tests that
use the committed ``hardware-profiles.json`` exercise the real published-profile
text but say nothing about any physical device. These tests also exercise the real
sibling ``identity.py``; they are expected to change if that shared contract does.
"""

from __future__ import annotations

import ast
import contextlib
import copy
import dataclasses
import hashlib
import hmac
import io
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import enrich  # noqa: E402

SCRIPT = HERE / "enrich.py"
SALT = b"unit-test-salt-0123456789abcdef"
HOUSEHOLD = "Sonos_TESTHOUSEHOLD0000000001.TESTSUFFIX"
IDN = enrich._identity()  # the real shared module, loaded exactly as enrich loads it


def device(n: int = 1, model: str = "S5", **fields_override):
    """A synthetic capture entry shaped like scan.py output plus the /status/zp block."""
    serial = f"02-00-5E-00-00-{n:02X}:{n % 10}"
    host = f"203.0.113.{10 + n}"
    mac = f"02:00:5E:00:00:{n:02X}"
    room = f"Zebra Lounge {n}"
    fields = {
        "modelName": "Sonos Test Unit",
        "modelNumber": model,
        "hardwareVersion": "1.8.3.7-2.1",
        "softwareVersion": "57.23-74170",
        "seriesid": "P100",
        "memory": "32",
        "flash": "32",
        "serialNum": serial,
        "UDN": f"uuid:RINCON_02005E0000{n:02X}01400",
        "roomName": room,
        "displayName": room,
        "MACAddress": mac,
    }
    fields.update(fields_override)
    return {
        "url": f"http://{host}:1400/xml/device_description.xml",
        "fields": fields,
        "status": {
            "ZoneName": room,
            "SWGen": "1",
            "HardwareVersion": "1.8.3.7-2.1",  # dotted-quad version, as in real /status/zp
            "SoftwareVersion": "57.23-74170",
            "IPAddress": host,
            "SerialNumber": serial,
            "MACAddress": mac,
            "HouseholdControlID": HOUSEHOLD,
            "LocalUID": f"RINCON_02005E0000{n:02X}01400",
            "LocationId": "xx_0123456789abcdef0123456789abcdef01",
        },
    }


def private_values(n: int = 1):
    d = device(n)
    return [
        d["fields"]["serialNum"],
        d["fields"]["UDN"],
        d["fields"]["MACAddress"],
        d["fields"]["roomName"],
        d["url"],
        d["status"]["IPAddress"],
        HOUSEHOLD,
        d["status"]["LocalUID"],
        d["status"]["LocationId"],
    ]


def capture(*entries, observed_at="2026-11-04T12:00:00+00:00"):
    return {"observed_at": observed_at, "method": "synthetic test fixture", "devices": list(entries)}


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.profiles = enrich.load_profiles(enrich.DEFAULT_PROFILES)

    def write_json(self, name, obj):
        path = self.dir / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def write_bytes(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            code = enrich.main([str(a) for a in args], stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def enrich(self, *entries, salt=None, unit="MB"):
        return enrich.enrich_document(capture(*entries), self.profiles, salt, None, unit)

    def records(self, *entries, salt=None, unit="MB"):
        return self.enrich(*entries, salt=salt, unit=unit).output["devices"]

    def listing(self):
        return sorted(os.listdir(self.dir))


# ---------------------------------------------------------------------------
# import-time safety and offline guarantees
# ---------------------------------------------------------------------------


class ImportAndOfflineTests(Base):
    def test_import_reads_and_writes_nothing_and_does_not_load_the_shared_module(self):
        decoy_dir = self.dir / "inventory"
        decoy_dir.mkdir()
        decoy = decoy_dir / "devices.json"
        decoy.write_text('{"devices": "decoy private capture"}', encoding="utf-8")
        before = hashlib.sha256(decoy.read_bytes()).hexdigest()
        code = (
            "import builtins, importlib.util, os, sys\n"
            "calls = []\n"
            "real = builtins.open\n"
            "def spy(*a, **k):\n"
            "    calls.append(str(a[0])); return real(*a, **k)\n"
            "builtins.open = spy\n"
            "spec = importlib.util.spec_from_file_location('enrich_under_test', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            "builtins.open = real\n"
            "print(repr(calls)); print(repr(sorted(os.listdir('.')))); print('identity' in sys.modules)\n"
        )
        proc = subprocess.run([sys.executable, "-I", "-c", code, str(SCRIPT)], cwd=self.dir, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        calls_line, listing_line, identity_line = proc.stdout.strip().splitlines()
        self.assertEqual(calls_line, "[]", "import must not open any file")
        self.assertEqual(listing_line, "['inventory']", "import must not create files")
        self.assertEqual(identity_line, "False", "the shared module loads lazily, not at import")
        self.assertEqual(hashlib.sha256(decoy.read_bytes()).hexdigest(), before)

    def test_module_imports_stay_inside_an_offline_allowlist(self):
        # `signal` is reviewed: it only installs an in-process SIGTERM handler (see InterruptionTests).
        allowed = {"__future__", "argparse", "collections", "copy", "dataclasses", "datetime", "hashlib", "importlib", "json", "os", "pathlib", "re", "signal", "stat", "sys", "tempfile", "typing"}
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported - allowed, set(), "new import: review for network/process reach, then extend the allowlist deliberately")

    def test_source_pins_no_personal_paths_or_lan_addresses(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for pattern in (r"/Users/", r"/home/", r"/Volumes/", r"\b192\.168\.\d"):
            self.assertIsNone(re.search(pattern, source), pattern)

    def test_the_shared_module_is_found_beside_the_script_even_under_isolated_mode(self):
        # `python -I` drops the script directory from sys.path; enrich must still locate identity.py.
        cap = self.write_json("devices.json", capture(device(1, "S5")))
        run = subprocess.run([sys.executable, "-I", str(SCRIPT), "--devices", str(cap), "--dry-run", "--nominal-unit", "MB"], capture_output=True, text=True, timeout=60, cwd=self.dir)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("enriched=1", run.stdout)

    def test_a_missing_shared_module_fails_loudly_instead_of_degrading(self):
        lone = self.dir / "lone"
        lone.mkdir()
        shutil.copy(SCRIPT, lone / "enrich.py")
        shutil.copy(enrich.DEFAULT_PROFILES, lone / "hardware-profiles.json")
        cap = self.write_json("devices.json", capture(device(1, "S5")))
        before = self.listing()
        run = subprocess.run([sys.executable, "-I", str(lone / "enrich.py"), "--devices", str(cap), "--out", str(self.dir / "o.json")], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, enrich.EXIT_INPUT, run.stderr)
        self.assertIn("identity_module_unavailable", run.stderr)
        self.assertEqual(self.listing(), before, "no output without the shared engine")


# ---------------------------------------------------------------------------
# published-profile document
# ---------------------------------------------------------------------------


def valid_profile(**over):
    profile = {
        "cpu": "Example CPU (published teardown)",
        "ram": "32 MiB (published)",
        "flash": "32 MiB NAND (published)",
        "network": "10/100 Ethernet",
        "audio": "Example amplifier",
        "sources": ["https://example.org/teardown"],
        "qualification": "Published teardown; not inspection of owned units.",
    }
    profile.update(over)
    return profile


def versioned(profiles, **over):
    doc = {"schema": enrich.PROFILE_SCHEMA, "schema_version": 1, "profiles": profiles}
    doc.update(over)
    return doc


class ProfileTests(Base):
    def test_committed_legacy_profiles_load_as_unversioned_schema_zero(self):
        ps = self.profiles
        self.assertEqual(ps.schema_version, 0)
        self.assertTrue({"S5", "S3", "S1", "S12", "Sub", "S9", "ZB100"} <= set(ps.by_model))
        ids = [p["published_profile_id"] for p in ps.by_model.values()]
        self.assertEqual(len(ids), len(set(ids)))
        for model, p in ps.by_model.items():
            self.assertRegex(p["published_profile_id"], rf"^pub-{re.escape(model.lower())}-[0-9a-f]{{8}}$")
            self.assertTrue(p["sources"], model)
        again = enrich.load_profiles(enrich.DEFAULT_PROFILES)
        self.assertEqual(again.digest, ps.digest)

    def test_profile_digest_matches_an_independent_canonical_hash(self):
        raw = json.loads(enrich.DEFAULT_PROFILES.read_text(encoding="utf-8"))
        expected = hashlib.sha256(json.dumps({"model": "S5", "profile": raw["S5"]}, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        self.assertEqual(self.profiles.by_model["S5"]["profile_digest"], expected)
        self.assertEqual(self.profiles.by_model["S5"]["published_profile_id"], f"pub-s5-{expected[:8]}")

    def test_editing_one_profile_changes_only_that_profiles_id_and_the_set_digest(self):
        raw = json.loads(enrich.DEFAULT_PROFILES.read_text(encoding="utf-8"))
        edited = copy.deepcopy(raw)
        edited["S5"]["ram"] = "64 MiB (hypothetical edit)"
        a, b = self.profiles, enrich.parse_profiles(edited)
        self.assertNotEqual(a.by_model["S5"]["published_profile_id"], b.by_model["S5"]["published_profile_id"])
        self.assertEqual(a.by_model["S3"]["published_profile_id"], b.by_model["S3"]["published_profile_id"])
        self.assertNotEqual(a.digest, b.digest)

    def test_versioned_document_loads_and_honors_explicit_profile_ids(self):
        doc = versioned({"X1": dict(valid_profile(), published_profile_id="pub-x1-rev2"), "X2": valid_profile()})
        ps = enrich.parse_profiles(doc)
        self.assertEqual(ps.schema_version, 1)
        self.assertEqual(ps.by_model["X1"]["published_profile_id"], "pub-x1-rev2")
        self.assertRegex(ps.by_model["X2"]["published_profile_id"], r"^pub-x2-[0-9a-f]{8}$")
        self.assertNotEqual(ps.by_model["X1"]["profile_digest"], ps.by_model["X2"]["profile_digest"], "the digest binds the model key as well as the content")
        legacy = enrich.parse_profiles({"X2": valid_profile()})
        self.assertEqual(legacy.by_model["X2"]["profile_digest"], ps.by_model["X2"]["profile_digest"], "content digest must not depend on the document version")

    def test_rejected_profile_documents(self):
        deep = "[" * 100_000 + "]" * 100_000
        cases = [
            ("future schema version", json.dumps(versioned({"X": valid_profile()}, schema_version=2)), "profiles_unsupported_schema_version"),
            ("boolean version", json.dumps(versioned({"X": valid_profile()}, schema_version=True)), "profiles_unsupported_schema_version"),
            ("wrong schema name", json.dumps(versioned({"X": valid_profile()}, schema="something.else")), "profiles_unknown_schema"),
            ("extra top-level key", json.dumps(versioned({"X": valid_profile()}, generated_at="now")), "profiles_unexpected_top_level_key"),
            ("empty", json.dumps(versioned({})), "profiles_empty"),
            ("empty legacy", "{}", "profiles_empty"),
            ("profile asserts per-unit confirmation", json.dumps(versioned({"X": valid_profile(per_unit_silicon_confirmed=True)})), "profiles_unknown_field"),
            ("board-profile name used for a published profile", json.dumps(versioned({"X": valid_profile(profile_id="bp-0123456789abcdef")})), "profiles_unknown_field"),
            ("legacy document carrying an id", json.dumps({"X": valid_profile(published_profile_id="pub-x-1")}), "profiles_unknown_field"),
            ("missing cpu", json.dumps({"X": {k: v for k, v in valid_profile().items() if k != "cpu"}}), "profiles_bad_field"),
            ("blank qualification", json.dumps({"X": valid_profile(qualification="   ")}), "profiles_bad_field"),
            ("non-string claim", json.dumps({"X": valid_profile(ram=32)}), "profiles_bad_field"),
            ("url smuggled into a claim", json.dumps({"X": valid_profile(cpu="see https://example.org/x?t=1")}), "profiles_bad_field"),
            ("mailbox smuggled into a claim", json.dumps({"X": valid_profile(cpu="owner@example.org")}), "profiles_bad_field"),
            ("MAC inside a claim", json.dumps({"X": valid_profile(network="radio 02:00:5E:00:00:01")}), "profiles_contains_identifier"),
            ("IP literal inside a claim", json.dumps({"X": valid_profile(audio="amp at 203.0.113.9")}), "profiles_contains_identifier"),
            ("source with query string", json.dumps({"X": valid_profile(sources=["https://example.org/a?token=abc"])}), "profiles_bad_source_url"),
            ("source with userinfo", json.dumps({"X": valid_profile(sources=["https://user:pw@example.org/a"])}), "profiles_bad_source_url"),
            ("source is a file url", json.dumps({"X": valid_profile(sources=["file:///etc/hosts"])}), "profiles_bad_source_url"),
            ("source IP literal", json.dumps({"X": valid_profile(sources=["http://203.0.113.9/teardown"])}), "profiles_contains_identifier"),
            ("sources not a list", json.dumps({"X": valid_profile(sources="https://example.org/a")}), "profiles_bad_field"),
            ("sources empty", json.dumps({"X": valid_profile(sources=[])}), "profiles_bad_field"),
            ("duplicate explicit profile id", json.dumps(versioned({"A": dict(valid_profile(), published_profile_id="pub-same-1"), "B": dict(valid_profile(), published_profile_id="pub-same-1")})), "profiles_duplicate_profile_id"),
            ("malformed profile id", json.dumps(versioned({"A": dict(valid_profile(), published_profile_id="Has Spaces")})), "profiles_bad_field"),
            ("bad model key", json.dumps({"bad key!": valid_profile()}), "profiles_bad_model_key"),
            ("profile is not an object", json.dumps({"X": ["cpu"]}), "profiles_profile_not_an_object"),
            ("too many profiles", json.dumps({f"M{i}": valid_profile() for i in range(enrich.MAX_PROFILES + 1)}), "profiles_too_many"),
            ("top level list", "[]", "profiles_not_an_object"),
            ("duplicate json key", '{"X": ' + json.dumps(valid_profile()) + ', "X": ' + json.dumps(valid_profile()) + "}", "profiles_duplicate_json_key"),
            ("NaN", '{"X": NaN}', "profiles_non_finite_number"),
            ("truncated json", '{"X": {"cpu": ', "profiles_malformed_json"),
            ("nesting bomb", deep, "profiles_nesting_too_deep"),
            ("oversized", " " * (enrich.MAX_PROFILE_BYTES + 1), "profiles_too_large"),
        ]
        for name, text, code in cases:
            with self.subTest(name):
                path = self.write_bytes("profiles.json", text.encode("utf-8"))
                with self.assertRaises(enrich.EnrichError) as ctx:
                    enrich.load_profiles(path)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(ctx.exception.exit_code, enrich.EXIT_INPUT)

    def test_rejected_profile_files(self):
        with self.subTest("not utf-8"):
            with self.assertRaises(enrich.EnrichError) as ctx:
                enrich.load_profiles(self.write_bytes("p.json", b"\xff\xfe{}"))
            self.assertEqual(ctx.exception.code, "profiles_not_utf8")
        with self.subTest("directory"):
            with self.assertRaises(enrich.EnrichError) as ctx:
                enrich.load_profiles(self.dir)
            self.assertEqual(ctx.exception.code, "profiles_not_a_regular_file")
        with self.subTest("missing"):
            with self.assertRaises(enrich.EnrichError) as ctx:
                enrich.load_profiles(self.dir / "nope.json")
            self.assertEqual(ctx.exception.code, "profiles_unreadable")


# ---------------------------------------------------------------------------
# per-device enrichment
# ---------------------------------------------------------------------------


class EnrichmentTests(Base):
    def test_known_model_gets_its_profile_as_a_model_level_hint_only(self):
        (rec,) = self.records(device(1, "S5"))
        self.assertEqual(rec["status"], "enriched")
        self.assertEqual(rec["reason_codes"], [])
        self.assertEqual(rec["model_number"], "S5")
        self.assertEqual(rec["published_profile"]["published_profile_id"], self.profiles.by_model["S5"]["published_profile_id"])
        self.assertEqual(rec["published_profile"]["evidence_class"], "published_model_level")
        self.assertEqual(rec["published_profile"]["claims"]["cpu"], self.profiles.by_model["S5"]["cpu"])
        self.assertIs(rec["identity"]["per_unit_silicon_confirmed"], False)
        self.assertIs(rec["identity"]["binary_or_calibration_selection_eligible"], False)
        reported = rec["device_reported"]
        self.assertEqual(reported["evidence_class"], "device_self_report")
        self.assertEqual(reported["product_model"], "S5")
        self.assertEqual(reported["hardware_revision"], "1.8.3.7-2.1")
        self.assertEqual(reported["software_build"], "57.23-74170")
        self.assertEqual(reported["software_generation"], 1)
        self.assertEqual(reported["nominal_ram"], {"reported_number": 32, "unit": "MB", "unit_basis": "operator_asserted", "bytes": 32_000_000})
        self.assertRegex(rec["board_profile_id"], r"^bp-[0-9a-f]{16}$")

    def test_every_committed_model_resolves_only_to_its_own_profile(self):
        models = sorted(self.profiles.by_model)
        recs = self.records(*[device(i + 1, m) for i, m in enumerate(models)])
        by_model = {r["model_number"]: r for r in recs}
        self.assertEqual(sorted(by_model), models)
        for model, rec in by_model.items():
            self.assertEqual(rec["status"], "enriched", model)
            self.assertEqual(rec["published_profile"]["published_profile_id"], self.profiles.by_model[model]["published_profile_id"], model)

    def test_software_generation_never_selects_a_model_profile(self):
        # Live model "S1" (early Play:1) is a different concept from software generation S1.
        (rec,) = self.records(device(1, "S9"))
        self.assertEqual(rec["device_reported"]["software_generation"], 1)
        self.assertEqual(rec["published_profile"]["published_profile_id"], self.profiles.by_model["S9"]["published_profile_id"])
        self.assertNotEqual(rec["published_profile"]["published_profile_id"], self.profiles.by_model["S1"]["published_profile_id"])

    def test_unknown_or_near_miss_models_get_no_profile_whatever_the_era_hints(self):
        for model in ("S7", "s5", "S99", "Play5", "S5x"):
            with self.subTest(model):
                (rec,) = self.records(device(1, model, memory="32", flash="32", softwareVersion="57.23-74170"))
                self.assertEqual(rec["status"], "unknown_model")
                self.assertIsNone(rec["published_profile"])
                self.assertIn("no_published_profile_for_model", rec["reason_codes"])
                self.assertIs(rec["identity"]["per_unit_silicon_confirmed"], False)

    def test_surrounding_whitespace_in_model_number_is_normalized_not_fuzzy_matched(self):
        (rec,) = self.records(device(1, " S5 "))
        self.assertEqual(rec["model_number"], "S5")
        self.assertEqual(rec["status"], "enriched")

    def test_input_cannot_assert_silicon_confirmation_or_supply_profile_claims(self):
        entry = device(1, "S5", per_unit_silicon_confirmed=True, cpu="MPC8247 verified on this very unit", soc="confirmed")
        entry["published_hardware_profile"] = {"published_profile_id": "forged", "per_unit_silicon_confirmed": True, "cpu": "forged"}
        entry["per_unit_silicon_confirmed"] = True
        result = self.enrich(entry)
        text = json.dumps([result.output, result.ee_records])
        # NB: the needle is the planted *value* with both quotes; the output's own key
        # `per_unit_silicon_confirmed` legitimately ends in `confirmed"`.
        for needle in ("verified on this very unit", "forged", '"soc"', '"confirmed"'):
            self.assertNotIn(needle, text)
        (rec,) = result.output["devices"]
        self.assertIs(rec["identity"]["per_unit_silicon_confirmed"], False)
        self.assertEqual(rec["published_profile"]["claims"]["cpu"], self.profiles.by_model["S5"]["cpu"])
        for ee in result.ee_records:
            self.assertNotIn("confidence", ee)

    def test_each_missing_reported_field_is_incomplete_not_guessed(self):
        cases = [
            ("modelName", "model_name_missing", lambda r: r["device_reported"]["model_name"]),
            ("hardwareVersion", "hardware_revision_missing", lambda r: r["device_reported"]["hardware_revision"]),
            ("softwareVersion", "software_build_missing", lambda r: r["device_reported"]["software_build"]),
            ("seriesid", "series_id_missing", lambda r: r["device_reported"]["series_id"]),
            ("memory", "memory_missing", lambda r: r["device_reported"]["nominal_ram"]["reported_number"]),
            ("flash", "flash_missing", lambda r: r["device_reported"]["nominal_flash"]["bytes"]),
        ]
        for xml_key, reason, value_of in cases:
            with self.subTest(xml_key):
                entry = device(1, "S5")
                del entry["fields"][xml_key]
                (rec,) = self.records(entry)
                self.assertEqual(rec["status"], "enriched_incomplete")
                self.assertEqual(rec["reason_codes"], [reason])
                self.assertIsNotNone(rec["published_profile"], "the model-level profile still applies")
                self.assertIsNone(value_of(rec))
        with self.subTest("no hardware revision means no board profile id"):
            entry = device(1, "S5")
            del entry["fields"]["hardwareVersion"]
            (rec,) = self.records(entry)
            self.assertIsNone(rec["board_profile_id"])

    def test_bare_nominal_sizes_have_an_unknown_unit_unless_the_operator_asserts_one(self):
        (rec,) = self.records(device(1, "S5"), unit=None)
        self.assertEqual(rec["status"], "enriched_incomplete")
        self.assertEqual(rec["reason_codes"], ["flash_unit_unknown", "memory_unit_unknown"])
        ram = rec["device_reported"]["nominal_ram"]
        self.assertEqual(ram, {"reported_number": 32, "unit": None, "unit_basis": "unknown", "bytes": None}, "the number stays visible; no unit is assumed")
        self.assertEqual({f["code"] for f in rec["identity_findings"]}, {"UNIT_UNKNOWN"})
        for unit, factor in (("MB", 10**6), ("MiB", 2**20)):
            with self.subTest(unit):
                (rec,) = self.records(device(1, "S5"), unit=unit)
                self.assertEqual(rec["status"], "enriched")
                self.assertEqual(rec["device_reported"]["nominal_ram"], {"reported_number": 32, "unit": unit, "unit_basis": "operator_asserted", "bytes": 32 * factor})
        with self.assertRaises(enrich.EnrichError) as ctx:
            self.enrich(device(1, "S5"), unit="GB")
        self.assertEqual(ctx.exception.code, "nominal_unit_invalid")

    def test_sizes_that_state_their_own_unit_keep_it_unlike_bare_numbers(self):
        cases = [
            ("128 MB", 128, "MB", 128 * 10**6),
            ("128MB", 128, "MB", 128 * 10**6),
            ("128 MiB", 128, "MiB", 128 * 2**20),
            ("1 GB", 1, "GB", 10**9),
            ("512 KiB", 512, "KiB", 512 * 1024),
            ("64 B", 64, "B", 64),
        ]
        for raw, number, unit, nbytes in cases:
            for operator in (None, "MB", "MiB"):
                with self.subTest(raw=raw, operator=operator):
                    (rec,) = self.records(device(1, "S5", memory=raw, flash=raw), unit=operator)
                    expected = {"reported_number": number, "unit": unit, "unit_basis": "device_stated", "bytes": nbytes}
                    self.assertEqual(rec["device_reported"]["nominal_ram"], expected, "the device's own unit wins over the operator's")
                    self.assertEqual(rec["device_reported"]["nominal_flash"], expected)
                    self.assertEqual((rec["status"], rec["reason_codes"], rec["identity_findings"]), ("enriched", [], []))
        with self.subTest("a bare number beside a stated one does not inherit its unit"):
            (rec,) = self.records(device(1, "S5", memory="128 MB", flash="128"), unit=None)
            self.assertEqual(rec["reason_codes"], ["flash_unit_unknown"])
            self.assertEqual(rec["device_reported"]["nominal_ram"]["unit"], "MB")
            self.assertIsNone(rec["device_reported"]["nominal_flash"]["unit"])
            self.assertIsNone(rec["device_reported"]["nominal_flash"]["bytes"])
        with self.subTest("operator unit applies to the bare number only"):
            (rec,) = self.records(device(1, "S5", memory="128 MB", flash="128"), unit="MiB")
            self.assertEqual(rec["device_reported"]["nominal_ram"]["bytes"], 128 * 10**6)
            self.assertEqual(rec["device_reported"]["nominal_flash"], {"reported_number": 128, "unit": "MiB", "unit_basis": "operator_asserted", "bytes": 128 * 2**20})
        with self.subTest("agrees with the shared module's own unit arithmetic"):
            claim = IDN.make_claim(IDN.Subject.device(IDN.Pseudonymizer(SALT).device("x-1")), "nominal_ram_bytes", 128, IDN.Source("agree-check", "live_description"), unit="MiB")
            (rec,) = self.records(device(1, "S5", memory="128 MiB"))
            self.assertEqual(rec["device_reported"]["nominal_ram"]["bytes"], claim.value)

    def test_unit_provenance_that_cannot_be_established_fails_closed(self):
        # If a size claim ever arrives without the shared module's :src-/:op- provenance suffix,
        # the unit's origin is unknown; keep no bytes rather than guess which party supplied it.
        real = IDN.normalize_record

        def strip_origin(rec, *a, **k):
            norm = real(rec, *a, **k)
            norm.claims = [dataclasses.replace(c, origin=c.origin.split(":")[0]) for c in norm.claims]
            return norm

        with mock.patch.object(IDN, "normalize_record", side_effect=strip_origin):
            (rec,) = self.records(device(1, "S5", memory="128 MB"), unit="MiB")
        self.assertEqual(rec["status"], "enriched_incomplete")
        self.assertEqual(rec["reason_codes"], ["flash_invalid", "memory_invalid"])
        for key in ("nominal_ram", "nominal_flash"):
            self.assertEqual(rec["device_reported"][key], {"reported_number": None, "unit": None, "unit_basis": "unknown", "bytes": None})

    def test_nominal_sizes_accept_bare_integers_and_exact_unit_forms_only(self):
        for raw, expected in [("128", 128), (" 32 ", 32), (128, 128), ("1", 1), ("1048577", 1048577)]:
            with self.subTest(valid=raw):
                (rec,) = self.records(device(1, "S5", memory=raw, flash=raw))
                self.assertEqual(rec["status"], "enriched")
                self.assertEqual(rec["device_reported"]["nominal_ram"]["reported_number"], expected)
        # Lower-case/megabit spellings, stray or doubled separators, reversed order, zero and
        # non-ASCII digits are refused, never guessed: "Mb" is megabits, not megabytes.
        invalid = ["128Mb", "128 mb", "128 M", "MB 128", "12 8 MB", "0 MB", "0x80", "-1", "0", "1e3", "128.0", "٣٢", "9" * 16, 128.0, True, ["128"], {"v": 1}]
        for raw in invalid:
            for unit in ("MB", None):
                with self.subTest(invalid=raw, unit=unit):
                    (rec,) = self.records(device(1, "S5", memory=raw), unit=unit)
                    expected = ["memory_invalid"] if unit else ["flash_unit_unknown", "memory_invalid"]
                    self.assertEqual(rec["reason_codes"], expected, "a malformed number is invalid, not merely unit-unknown")
                    self.assertIsNone(rec["device_reported"]["nominal_ram"]["bytes"])
                    self.assertIsNone(rec["device_reported"]["nominal_ram"]["reported_number"])
        with self.subTest("blank"):
            (rec,) = self.records(device(1, "S5", memory="   "))
            self.assertEqual(rec["reason_codes"], ["memory_missing"])

    def test_software_generation_conflict_and_garbage_are_surfaced(self):
        entry = device(1, "S5", swGen="1")
        entry["status"]["SWGen"] = "2"
        (rec,) = self.records(entry)
        self.assertIsNone(rec["device_reported"]["software_generation"])
        self.assertEqual(rec["reason_codes"], ["software_generation_conflict"])
        entry["status"]["SWGen"] = "1"
        (rec,) = self.records(entry)
        self.assertEqual(rec["device_reported"]["software_generation"], 1)
        self.assertEqual(rec["status"], "enriched")
        entry["status"]["SWGen"] = "S2"  # a model-ish token in the generation field
        (rec,) = self.records(entry)
        self.assertEqual(rec["reason_codes"], ["software_generation_invalid"])
        self.assertIsNone(rec["device_reported"]["software_generation"])

    def test_malformed_entries_are_reported_per_entry_and_never_stop_the_run(self):
        scan_error = {"url": "http://203.0.113.50:1400/xml/device_description.xml", "error": "timed out connecting to 203.0.113.50"}
        bad = [
            (None, "entry_not_an_object"),
            ("a string", "entry_not_an_object"),
            (5, "entry_not_an_object"),
            ([], "entry_not_an_object"),
            ({}, "fields_missing"),
            ({"fields": "x"}, "fields_missing"),
            (scan_error, "scan_error_row"),
            ({"fields": {}}, "model_number_missing"),
            ({"fields": {"modelNumber": "  "}}, "model_number_missing"),
            ({"fields": {"modelNumber": 5}}, "model_number_invalid"),
            ({"fields": {"modelNumber": "S5; DROP TABLE"}}, "model_number_invalid"),
            ({"fields": {"modelNumber": "x" * 33}}, "model_number_invalid"),
            ({"fields": {"modelNumber": "A" * 30}}, "model_number_invalid"),  # passes the token gate, refused by the shared parser
            ({"fields": {"modelNumber": "none"}}, "model_number_invalid"),  # placeholder, refused by the shared parser
            ({"fields": {"modelNumber": "203.0.113.5"}}, "model_number_invalid"),
            ({"fields": {"modelNumber": ["S5"]}}, "model_number_invalid"),
        ]
        entries = [device(1, "S5")] + [b for b, _ in bad] + [device(2, "S3")]
        result = self.enrich(*entries)
        counts = result.counts
        self.assertEqual(counts["devices_in_input"], len(entries))
        self.assertEqual(counts["enriched"], 2)
        self.assertEqual(counts["invalid"], len(bad))
        self.assertEqual(sum(counts[s] for s in enrich.STATUSES), len(entries), "every input entry is accounted for")
        expected_codes = sorted(code for _, code in bad)
        invalid_codes = sorted(code for r in result.output["devices"] if r["status"] == "invalid" for code in r["reason_codes"])
        self.assertEqual(invalid_codes, expected_codes)
        self.assertNotIn("203.0.113", json.dumps(result.output), "error text from a scan row must not be echoed")

    def test_a_shared_module_rejection_marks_only_that_entry_invalid(self):
        boom = IDN.IdentityError(IDN.R_RECORD, "record")
        real = IDN.normalize_record
        calls = []

        def flaky(rec, *a, **k):
            calls.append(1)
            if len(calls) == 2:
                raise boom
            return real(rec, *a, **k)

        with mock.patch.object(IDN, "normalize_record", side_effect=flaky):
            result = self.enrich(device(1, "S5"), device(2, "S5"), device(3, "S5"))
        self.assertEqual(result.counts["invalid"], 1)
        self.assertEqual(result.counts["enriched"], 2)
        self.assertEqual(result.reason_histogram["identity_record_rejected"], 1)

    def test_oversized_or_deeply_nested_entries_are_rejected_not_walked(self):
        wide = device(1, "S5")
        wide["junk"] = {f"k{i}": "v" for i in range(enrich.MAX_ENTRY_NODES + 10)}
        deep = device(2, "S5")
        node = deep["status"]["nested"] = {}
        for _ in range(enrich.MAX_ENTRY_DEPTH + 3):
            node["n"] = {}
            node = node["n"]
        recs = {r["reason_codes"][0] for r in self.records(wide, deep)}
        self.assertEqual(recs, {"entry_too_complex"})

    def test_entries_sharing_a_serial_are_ambiguous_and_nothing_is_dropped_or_merged(self):
        a, b = device(1, "S5"), device(2, "S5")
        # the same unit seen at a changed address, written with different case and separators
        b["fields"]["serialNum"] = a["fields"]["serialNum"].lower().replace("-", ":")
        result = self.enrich(a, b, device(3, "S5"))
        statuses = sorted(r["status"] for r in result.output["devices"])
        self.assertEqual(statuses, ["ambiguous", "ambiguous", "enriched"])
        for r in result.output["devices"]:
            if r["status"] == "ambiguous":
                self.assertIn("duplicate_serial_in_input", r["reason_codes"])
                self.assertIsNone(r["published_profile"], "an ambiguous identity gets no profile")
                self.assertIsNone(r["board_profile_id"], "nor a board profile id")
        self.assertEqual(result.counts["ambiguous"], 2)
        self.assertEqual(result.counts["devices_in_input"], 3)

    def test_distinct_serials_with_identical_public_fields_stay_distinct_devices(self):
        recs = self.records(device(1, "ZB100"), device(2, "ZB100"), device(3, "ZB100"))
        self.assertEqual([r["status"] for r in recs], ["enriched"] * 3)
        self.assertEqual(len({r["device_ref"] for r in recs}), 3)

    def test_missing_or_unusable_serial_is_incomplete_but_other_fields_still_normalize(self):
        no_serial = device(1, "S5")
        del no_serial["fields"]["serialNum"]
        long_serial = device(2, "S5", serialNum="Z" * 200)
        placeholder = device(3, "S5", serialNum="unknown")
        recs = self.records(no_serial, long_serial, placeholder)
        self.assertEqual(sorted(r["reason_codes"][0] for r in recs), ["serial_invalid", "serial_invalid", "serial_missing"])
        for r in recs:
            self.assertEqual(r["status"], "enriched_incomplete")
            self.assertEqual(r["device_reported"]["hardware_revision"], "1.8.3.7-2.1")
            self.assertEqual(r["device_reported"]["nominal_ram"]["bytes"], 32_000_000)

    def test_public_fields_never_carry_identifier_shapes(self):
        cases = [
            ("modelName", "Sonos 203.0.113.9", "model_name_contains_identifier"),
            ("modelName", "Sonos 02:00:5E:00:00:01", "model_name_contains_identifier"),
            ("modelName", "Sonos 02005E000001AB", "model_name_contains_identifier"),
            ("modelName", "Sonos fe80:0:0:0:1", "model_name_contains_identifier"),
            ("modelName", "Sonos\nPLAY:5", "model_name_invalid"),
            ("seriesid", "AABBCCDDEEFF", "series_id_contains_identifier"),
            ("seriesid", "P100 <script>", "series_id_invalid"),
            ("hardwareVersion", "02005E000001A", "hardware_revision_invalid"),
            ("hardwareVersion", "unknown", "hardware_revision_invalid"),
            ("softwareVersion", "123e4567-e89b-12d3-a456-426614174000", "software_build_invalid"),
            ("softwareVersion", "02:00:5E:00:00:01", "software_build_invalid"),
        ]
        for key, value, reason in cases:
            with self.subTest(key=key, value=value):
                (rec,) = self.records(device(1, "S5", **{key: value}))
                self.assertEqual(rec["reason_codes"], [reason])
                self.assertNotIn(value.split()[-1], json.dumps(rec))

    def test_model_name_equal_to_the_rooms_name_is_withheld_but_a_model_number_may_match_a_room(self):
        (rec,) = self.records(device(1, "S5", modelName="Zebra Lounge 1"))
        self.assertEqual(rec["reason_codes"], ["model_name_contains_identifier"])
        self.assertIsNone(rec["device_reported"]["model_name"])
        # Rooms are routinely named after the product; a model number is structurally constrained and allowed to coincide.
        entry = device(2, "Sub", roomName="Sub", displayName="Sub")
        entry["status"]["ZoneName"] = "Sub"
        (rec,) = self.records(entry)
        self.assertEqual(rec["status"], "enriched")
        self.assertEqual(rec["model_number"], "Sub")

    def test_dotted_quad_revisions_are_legitimate(self):
        (rec,) = self.records(device(1, "S5", hardwareVersion="1.20.1.6-2.1"))
        self.assertEqual(rec["status"], "enriched")
        self.assertEqual(rec["device_reported"]["hardware_revision"], "1.20.1.6-2.1")

    def test_every_emitted_reason_code_is_registered(self):
        entries = [device(1, "S7"), device(2, "S5", memory="x"), device(3, "S5", modelName="1.2.3.4"), {}, None, {"fields": {}}, device(4, "S5", swGen="q")]
        d = device(5, "S5")
        del d["fields"]["serialNum"]
        entries += [d, device(6, "S5"), device(6, "S5"), device(7, "S5", hardwareVersion="x"), device(8, "S5", softwareVersion="x"), device(9, "S5", seriesid="a b")]
        emitted = set()
        for unit in ("MB", None):
            emitted |= {c for r in self.records(*entries, unit=unit) for c in r["reason_codes"]}
        self.assertTrue(emitted)
        self.assertTrue(emitted <= enrich.REASON_CODES, emitted - enrich.REASON_CODES)
        for code in enrich.REASON_CODES:
            self.assertRegex(code, r"^[a-z0-9_]+$")


# ---------------------------------------------------------------------------
# agreement with the shared identity module
# ---------------------------------------------------------------------------


class SharedIdentityTests(Base):
    def test_values_and_ids_agree_with_the_shared_module_on_the_same_capture(self):
        entry = device(1, "S5")
        pseud = IDN.Pseudonymizer(SALT)
        norm = IDN.normalize_record(entry, IDN.Source("agree-check", "live_description"), pseud, memory_unit="MiB")
        claims = {c.field: c.value for c in norm.claims}
        (rec,) = self.records(entry, salt=SALT, unit="MiB")
        reported = rec["device_reported"]
        self.assertEqual(rec["device_ref"], norm.device)
        self.assertEqual(reported["hardware_revision"], claims["hardware_revision"])
        self.assertEqual(reported["software_build"], claims["software_build"])
        self.assertEqual(reported["software_generation"], claims["software_generation"])
        self.assertEqual(reported["nominal_ram"]["bytes"], claims["nominal_ram_bytes"])
        self.assertEqual(rec["board_profile_id"], IDN.profile_id_for(claims["product_model"], claims["hardware_revision"]))

    def test_board_profile_id_is_the_shared_function_of_model_and_revision_only(self):
        (a,) = self.records(device(1, "Sub"))
        self.assertEqual(a["board_profile_id"], IDN.profile_id_for("SUB", "1.8.3.7-2.1"))
        self.assertEqual(a["board_profile_id"], IDN.profile_id_for("Sub", "1.8.3.7-2.1"), "the shared function canonicalizes its own inputs")
        (b,) = self.records(device(2, "Sub", hardwareVersion="01.008.3.7-2.1"))  # leading zeros canonicalize away
        self.assertEqual(a["board_profile_id"], b["board_profile_id"])
        (c,) = self.records(device(3, "Sub", hardwareVersion="1.8.3.7-2.2"))
        self.assertNotEqual(a["board_profile_id"], c["board_profile_id"])
        (d,) = self.records(device(4, "S5"))
        self.assertNotEqual(a["board_profile_id"], d["board_profile_id"])
        self.assertEqual(a["identity"]["board_profile_basis"], "single_observation_candidate")
        # nothing but model and revision feeds it: serial, memory, build, address and room do not
        (e,) = self.records(device(5, "Sub", memory="64", softwareVersion="99.99-99999", seriesid="Z999", roomName="Elsewhere"))
        self.assertEqual(a["board_profile_id"], e["board_profile_id"])

    def test_a_shared_module_that_rejects_the_profile_inputs_marks_only_that_entry_invalid(self):
        with mock.patch.object(IDN, "profile_id_for", side_effect=IDN.IdentityError(IDN.R_MALFORMED, "hardware_revision")):
            (rec,) = self.records(device(1, "S5"))
        self.assertEqual((rec["status"], rec["reason_codes"]), ("invalid", ["identity_record_rejected"]))

    def test_board_profile_id_is_independent_of_the_published_profile(self):
        (known,) = self.records(device(1, "S5"))
        (unknown,) = self.records(device(1, "S7"))
        self.assertEqual(unknown["status"], "unknown_model")
        self.assertIsNotNone(unknown["board_profile_id"])
        self.assertNotEqual(known["board_profile_id"], unknown["board_profile_id"])

    def test_salted_ref_matches_the_documented_keyed_construction(self):
        (rec,) = self.records(device(1, "S5"), salt=SALT)
        canonical_serial = re.sub(r"[\s:_-]+", "-", device(1)["fields"]["serialNum"].strip().upper())
        expected = "dev-" + hmac.new(SALT, b"ffw-identity/v1/device\0" + canonical_serial.encode(), hashlib.sha256).hexdigest()[:20]
        self.assertEqual(rec["device_ref"], expected)
        self.assertEqual(rec["device_ref_scope"], "salted_stable")
        self.assertNotIn(device(1)["fields"]["serialNum"], json.dumps(rec))
        self.assertNotIn(canonical_serial, json.dumps(rec))


# ---------------------------------------------------------------------------
# privacy
# ---------------------------------------------------------------------------


class PrivacyTests(Base):
    def test_no_private_value_reaches_any_sanitized_artifact_or_console_stream(self):
        entries = [device(i, m) for i, m in enumerate(["S5", "S3", "ZB100", "S7"], start=1)]
        entries.append({"url": "http://203.0.113.77:1400/xml/device_description.xml", "error": "refused by 203.0.113.77"})
        cap = self.write_json("devices.json", capture(*entries))
        salt = self.write_bytes("salt.bin", SALT)
        out, ee = self.dir / "out.json", self.dir / "ee.jsonl"
        code, stdout, stderr = self.cli("--devices", cap, "--salt-file", salt, "--nominal-unit", "MB", "--out", out, "--ee-records-out", ee)
        self.assertEqual(code, enrich.EXIT_PARTIAL, stderr)  # S7 has no published profile and the scan row is invalid
        haystack = "\n".join([out.read_text(), ee.read_text(), stdout, stderr])
        secrets = [v for i in range(1, 5) for v in private_values(i)] + ["203.0.113.77", "Zebra Lounge", "RINCON", "TESTHOUSEHOLD"]
        for secret in secrets:
            self.assertNotIn(secret, haystack, "leaked a private value")
        # the dropped keys themselves are not copied either
        for key in ("serialNum", "UDN", "roomName", "displayName", "MACAddress", "IPAddress", "HouseholdControlID", "LocalUID", "ZoneName"):
            self.assertNotIn(key, haystack)

    def test_real_status_block_shape_does_not_trigger_a_false_leak(self):
        # The /status/zp HardwareVersion is dotted-quad shaped and equals the public hardware_revision.
        cap = self.write_json("devices.json", capture(device(1, "S5")))
        code, stdout, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--out", self.dir / "out.json")
        self.assertEqual(code, enrich.EXIT_OK, stderr)
        doc = json.loads((self.dir / "out.json").read_text())
        self.assertEqual(doc["devices"][0]["device_reported"]["hardware_revision"], "1.8.3.7-2.1")

    def test_find_leaks_detects_planted_identifiers_and_ignores_trivia(self):
        serial = "02-00-5E-00-00-01:1"
        self.assertEqual(enrich.find_leaks([{"a": ["x", f"prefix {serial} suffix"]}], {serial}), 1)
        self.assertEqual(enrich.find_leaks([{"a": "clean"}], {serial}), 0)
        awkward = 'q"uote\\backé'
        self.assertEqual(enrich.find_leaks([{"a": awkward}], {awkward}), 1, "JSON-escaped forms must still be found")
        self.assertEqual(enrich.find_leaks([[{"nested": {"deep": [serial]}}]], {serial, "ab"}), 1)
        self.assertEqual(enrich.find_leaks([{"a": "abcde"}], {"abcde"}), 0, "values below the floor are not meaningful identifiers")
        self.assertEqual(enrich.find_leaks([{"a": "abcdef"}], {"abcdef"}), 1)

    def test_shared_scanner_gate_flags_patterns_and_canaries_but_not_digests_or_revisions(self):
        self.assertEqual(enrich.shared_guard_findings({"x": "radio 02:00:5E:00:00:01"}, set()), 1)
        self.assertEqual(enrich.shared_guard_findings({"x": "host 203.0.113.9"}, set()), 1)
        self.assertEqual(enrich.shared_guard_findings({"x": "0123456789ab"}, set()), 1, "12+ hex is flagged")
        digest = "a" * 64
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": digest}, set()), 0, "schema-defined digest keys are exempt")
        self.assertEqual(enrich.shared_guard_findings({"profile_set": {"set_digest": digest}, "d": [{"profile_digest": digest}]}, set()), 0)
        # ...but never generically: the same 64-hex under any other key, in the wrong format, or nested under a digest key is still a finding.
        self.assertEqual(enrich.shared_guard_findings({"note": digest}, set()), 1, "no generic masking: a secret cannot hide under arbitrary metadata")
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": "0123456789ab"}, set()), 1, "a digest key does not exempt a value that is not a sha256")
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": digest.upper()}, set()), 1, "format check: lower-case hex only")
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": [digest]}, set()), 0, "a list of exact digests under a digest key is still just digests")
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": [digest, "0123456789ab"]}, set()), 1, "...but any non-digest element in it is still a finding")
        self.assertEqual(enrich.shared_guard_findings({"input_sha256": {"inner": digest}}, set()), 1, "a nested object does not inherit the exemption")
        self.assertEqual(enrich.shared_guard_findings({"hardware_revision": "1.8.3.7-2.1"}, set()), 0, "dotted-quad revisions are exempt only under the shared key names")
        self.assertEqual(enrich.shared_guard_findings({"other_key": "1.8.3.7-2.1"}, set()), 1)
        self.assertEqual(enrich.shared_guard_findings({"x": "Sonos TESTHOUSEHOLD0000000001 TESTSUFFIX"}, {HOUSEHOLD}), 1, "canaries match case- and separator-insensitively")
        self.assertEqual(enrich.shared_guard_findings({"x": "nothing here"}, {HOUSEHOLD}), 0)

    def test_run_aborts_without_writing_when_a_private_value_would_be_published(self):
        # Pass the field validators (plain word characters) but equal a harvested household identifier.
        leaky = device(1, "S5", modelName=HOUSEHOLD)
        cap = self.write_json("devices.json", capture(leaky))
        out, ee = self.dir / "out.json", self.dir / "ee.jsonl"
        before = self.listing()
        code, stdout, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--out", out, "--ee-records-out", ee)
        self.assertEqual(code, enrich.EXIT_LEAK)
        self.assertIn("sanitized_output_would_leak_private_value", stderr)
        self.assertNotIn(HOUSEHOLD, stdout + stderr, "the aborting run must not echo the value either")
        self.assertEqual(self.listing(), before, "nothing may be written when the leak check fires")

    def test_the_two_gates_are_complementary(self):
        # Re-separated, so the exact-value check cannot see it; the shared scanner's canary match can.
        resep = device(1, "S5", modelName="Sonos TESTHOUSEHOLD0000000001 TESTSUFFIX")
        cap = self.write_json("devices.json", capture(resep))
        result = enrich.enrich_document(json.loads(cap.read_text()), self.profiles, None, None, "MB")
        self.assertEqual(enrich.find_leaks([result.output, result.ee_records], result.private_ids), 0, "premise: the exact check alone misses this")
        self.assertGreaterEqual(enrich.shared_guard_findings([result.output], result.private_ids), 1)
        code, _, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--out", self.dir / "o.json")
        self.assertEqual(code, enrich.EXIT_LEAK, stderr)
        self.assertFalse((self.dir / "o.json").exists())
        # and the reverse: a revision equal to the unit's real address is invisible to the scanner (version keys are exempt) but not to the exact check
        ip_rev = device(2, "S5", hardwareVersion="203.0.113.12")
        cap2 = self.write_json("devices2.json", capture(ip_rev))
        result2 = enrich.enrich_document(json.loads(cap2.read_text()), self.profiles, None, None, "MB")
        self.assertEqual(enrich.shared_guard_findings([result2.output], set()), 0, "premise: the scanner alone exempts this")
        code, _, stderr = self.cli("--devices", cap2, "--nominal-unit", "MB", "--out", self.dir / "o2.json")
        self.assertEqual(code, enrich.EXIT_LEAK, stderr)
        self.assertFalse((self.dir / "o2.json").exists())

    def test_private_annotated_copy_may_hold_identifiers_but_is_flagged_and_name_guarded(self):
        cap = self.write_json("devices.json", capture(device(1, "S5"), device(2, "S7")))
        refused = self.dir / "annotated.json"
        code, _, stderr = self.cli("--devices", cap, "--private-annotated-out", refused)
        self.assertEqual(code, enrich.EXIT_OUTPUT)
        self.assertIn("private_output_path_not_git_ignored", stderr)
        self.assertFalse(refused.exists())

        for name in ("annotated.local.json", ".local-real/annotated.json"):
            with self.subTest(name):
                target = self.dir / name
                target.parent.mkdir(exist_ok=True)
                code, _, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--private-annotated-out", target)
                self.assertEqual(code, enrich.EXIT_PARTIAL, stderr)
                doc = json.loads(target.read_text())
                self.assertIs(doc["contains_private_identifiers"], True)
                self.assertEqual(doc["devices"][0]["fields"]["serialNum"], device(1)["fields"]["serialNum"], "original capture content is preserved")
                ann = doc["devices"][0]["published_hardware_profile"]
                self.assertEqual(ann["published_profile_id"], self.profiles.by_model["S5"]["published_profile_id"])
                self.assertIs(ann["per_unit_silicon_confirmed"], False)
                self.assertNotIn("published_hardware_profile", doc["devices"][1], "unknown model gets no profile")
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_a_forged_annotation_in_the_input_is_overwritten_not_trusted(self):
        entry = device(1, "S5")
        entry["published_hardware_profile"] = {"per_unit_silicon_confirmed": True, "cpu": "forged"}
        cap = self.write_json("devices.json", capture(entry))
        target = self.dir / "x.local.json"
        self.assertEqual(self.cli("--devices", cap, "--nominal-unit", "MB", "--private-annotated-out", target)[0], enrich.EXIT_OK)
        ann = json.loads(target.read_text())["devices"][0]["published_hardware_profile"]
        self.assertIs(ann["per_unit_silicon_confirmed"], False)
        self.assertNotEqual(ann["cpu"], "forged")


# ---------------------------------------------------------------------------
# pseudonyms and determinism
# ---------------------------------------------------------------------------


class RefTests(Base):
    def test_unsalted_refs_are_run_local_and_say_so(self):
        recs = self.records(device(1, "S5"), device(2, "S3"))
        self.assertEqual([r["device_ref"] for r in recs], ["local-0001", "local-0002"])
        self.assertEqual({r["device_ref_scope"] for r in recs}, {"run_local"})

    def test_salt_changes_refs_and_missing_serial_falls_back_to_run_local(self):
        a = self.records(device(1, "S5"), salt=SALT)[0]["device_ref"]
        b = self.records(device(1, "S5"), salt=SALT + b"x")[0]["device_ref"]
        self.assertNotEqual(a, b)
        no_serial = device(1, "S5")
        del no_serial["fields"]["serialNum"]
        (rec,) = self.records(no_serial, salt=SALT)
        self.assertEqual(rec["device_ref_scope"], "run_local")

    def test_output_bytes_are_independent_of_input_order_in_both_modes(self):
        entries = [device(i, m) for i, m in enumerate(["S5", "S3", "ZB100", "S5", "S5", "S7", "Sub"], start=1)]
        entries.append(device(1, "S5"))  # duplicate of #1 -> ambiguous pair
        entries.append({"fields": {}})
        for salt in (None, SALT):
            texts = set()
            for seed in range(8):
                shuffled = list(entries)
                random.Random(seed).shuffle(shuffled)
                result = enrich.enrich_document(capture(*shuffled), self.profiles, salt, "0" * 64, "MB")
                texts.add(enrich._json_text(result.output) + enrich._jsonl_text(result.ee_records))
            self.assertEqual(len(texts), 1, f"salt={'yes' if salt else 'no'}: output depends on input order")

    def test_duplicate_serials_never_share_a_ref(self):
        recs = self.records(device(1, "S5"), device(1, "S5"), salt=SALT)
        refs = [r["device_ref"] for r in recs]
        self.assertEqual(len(set(refs)), 2)
        self.assertTrue(refs[1].startswith(refs[0]) or refs[0].startswith(refs[1]))
        self.assertEqual({r["status"] for r in recs}, {"ambiguous"})

    def test_salt_file_rules(self):
        cap = self.write_json("devices.json", capture(device(1, "S5")))
        short = self.write_bytes("short.bin", b"too short")
        code, _, stderr = self.cli("--devices", cap, "--salt-file", short, "--out", self.dir / "o.json")
        self.assertEqual((code, "salt_too_short" in stderr, (self.dir / "o.json").exists()), (enrich.EXIT_INPUT, True, False))
        with_newline = self.write_bytes("nl.bin", SALT + b"\n")
        without = self.write_bytes("nonl.bin", SALT)
        refs = []
        for salt_file in (with_newline, without):
            out = self.dir / f"{salt_file.stem}.json"
            self.assertEqual(self.cli("--devices", cap, "--salt-file", salt_file, "--nominal-unit", "MB", "--out", out)[0], enrich.EXIT_OK)
            refs.append(json.loads(out.read_text())["devices"][0]["device_ref"])
        self.assertEqual(refs[0], refs[1], "a trailing newline must not change the key")
        self.assertEqual(self.cli("--devices", cap, "--salt-file", self.dir / "missing.bin", "--out", self.dir / "z.json")[0], enrich.EXIT_INPUT)


# ---------------------------------------------------------------------------
# CLI behaviour, bounds, exit codes, output safety
# ---------------------------------------------------------------------------


class CliTests(Base):
    def good_capture(self, name="devices.json"):
        return self.write_json(name, capture(device(1, "S5"), device(2, "S3")))

    def test_usage_errors_exit_two_and_do_nothing(self):
        cap = self.good_capture()
        before = self.listing()
        for args in ([], ["--devices", cap], ["--out", self.dir / "o.json"], ["--dev", cap, "--dry-run"], ["--no-such-flag"], ["--devices", cap, "--dry-run", "--nominal-unit", "GB"]):
            with self.subTest(args=[str(a) for a in args]):
                self.assertEqual(self.cli(*args)[0], enrich.EXIT_USAGE)
        self.assertEqual(self.listing(), before)

    def test_fully_enriched_run_exits_zero_and_writes_exactly_the_requested_files(self):
        cap = self.good_capture()
        before = self.listing()
        out, ee = self.dir / "out.json", self.dir / "ee.jsonl"
        code, stdout, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--out", out, "--ee-records-out", ee)
        self.assertEqual((code, stderr), (enrich.EXIT_OK, ""))
        self.assertEqual(self.listing(), sorted(before + ["out.json", "ee.jsonl"]), "no stray or temporary files")
        self.assertIn("devices=2 enriched=2 enriched_incomplete=0 unknown_model=0 invalid=0 ambiguous=0", stdout)
        doc = json.loads(out.read_text())
        self.assertEqual(doc["schema"], enrich.OUTPUT_SCHEMA)
        self.assertEqual(doc["observed_at"], "2026-11-04T12:00:00+00:00")
        self.assertEqual(doc["input_sha256"], hashlib.sha256(cap.read_bytes()).hexdigest())
        self.assertEqual(doc["nominal_unit"], {"value": "MB", "basis": "operator_asserted"})
        self.assertEqual(doc["profile_set"]["set_digest"], self.profiles.digest)
        self.assertEqual(doc["denominator"]["devices_in_input"], 2)
        self.assertEqual(out.stat().st_mode & 0o777, 0o644)
        lines = ee.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            rec = json.loads(line)
            self.assertEqual(set(rec), {"content", "level", "kind", "tags", "source"})
            self.assertTrue(rec["source"].startswith("ffw-enrich://input-"), "source must be a digest URI, never a filesystem path")
            self.assertIn("NOT confirmed", rec["content"])
            self.assertIn("published-profile", rec["tags"])

    def test_without_an_asserted_unit_the_run_is_partial_and_says_why(self):
        cap = self.good_capture()
        out = self.dir / "out.json"
        code, stdout, stderr = self.cli("--devices", cap, "--out", out)
        self.assertEqual(code, enrich.EXIT_PARTIAL)
        self.assertIn("memory_unit_unknown=2", stdout)
        self.assertIn("flash_unit_unknown=2", stdout)
        doc = json.loads(out.read_text())
        self.assertEqual(doc["nominal_unit"], {"value": None, "basis": "unknown"})
        self.assertEqual(doc["denominator"]["enriched_incomplete"], 2)
        self.assertEqual(doc["devices"][0]["device_reported"]["nominal_ram"]["reported_number"], 32)

    def test_partial_run_still_writes_everything_but_exits_three(self):
        cap = self.write_json("devices.json", capture(device(1, "S5"), device(2, "S7"), {"fields": {}}))
        out, ee = self.dir / "out.json", self.dir / "ee.jsonl"
        code, stdout, stderr = self.cli("--devices", cap, "--nominal-unit", "MB", "--out", out, "--ee-records-out", ee)
        self.assertEqual(code, enrich.EXIT_PARTIAL)
        self.assertIn("not every device is fully enriched", stderr)
        self.assertIn("enriched=1", stdout)
        self.assertIn("unknown_model=1", stdout)
        self.assertIn("invalid=1", stdout)
        doc = json.loads(out.read_text())
        self.assertEqual(sum(doc["denominator"][s] for s in enrich.STATUSES), 3)
        self.assertEqual(len(ee.read_text().splitlines()), 1, "only enriched records become memory facts")

    def test_dry_run_computes_and_summarizes_but_writes_nothing(self):
        cap = self.good_capture()
        before = self.listing()
        code, stdout, _ = self.cli("--devices", cap, "--dry-run", "--nominal-unit", "MB", "--out", self.dir / "o.json")
        self.assertEqual(code, enrich.EXIT_OK)
        self.assertIn("dry-run, nothing written", stdout)
        self.assertEqual(self.listing(), before)

    def test_rerun_is_byte_identical(self):
        cap = self.good_capture()
        first, second = self.dir / "a.json", self.dir / "b.json"
        self.assertEqual(self.cli("--devices", cap, "--nominal-unit", "MB", "--out", first)[0], enrich.EXIT_OK)
        self.assertEqual(self.cli("--devices", cap, "--nominal-unit", "MB", "--out", second)[0], enrich.EXIT_OK)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_rejected_inputs_exit_four_and_write_nothing(self):
        long_list = capture(*[device(1, "S5")] * (enrich.MAX_DEVICES + 1))
        cases = {
            "malformed": b'{"devices": [',
            "duplicate key": b'{"devices": [], "devices": []}',
            "not utf-8": b"\xff\xfe\x00",
            "NaN": b'{"devices": [], "x": NaN}',
            "top-level list": b"[]",
            "devices not a list": b'{"devices": {}}',
            "no devices key": b"{}",
            "empty devices (never a fake success)": b'{"devices": []}',
            "too many devices": json.dumps(long_list).encode(),
            "oversized file": b" " * (enrich.MAX_INPUT_BYTES + 1),
            "nesting bomb": b"[" * 100_000 + b"]" * 100_000,
        }
        for name, data in cases.items():
            with self.subTest(name):
                cap = self.write_bytes("devices.json", data)
                before = self.listing()
                code, _, stderr = self.cli("--devices", cap, "--out", self.dir / "o.json", "--ee-records-out", self.dir / "e.jsonl")
                self.assertEqual(code, enrich.EXIT_INPUT, stderr)
                self.assertTrue(stderr.startswith("enrich: error: devices_"), stderr)
                self.assertEqual(self.listing(), before)
        with self.subTest("directory instead of file"):
            self.assertEqual(self.cli("--devices", self.dir, "--out", self.dir / "o.json")[0], enrich.EXIT_INPUT)
        with self.subTest("missing file"):
            self.assertEqual(self.cli("--devices", self.dir / "absent.json", "--out", self.dir / "o.json")[0], enrich.EXIT_INPUT)

    def test_json_depth_bound_is_exact_and_independent_of_interpreter_recursion_limits(self):
        limit = enrich.MAX_JSON_DEPTH
        ok = ("[" * limit + "]" * limit).encode()
        too_deep = ("[" * (limit + 1) + "]" * (limit + 1)).encode()
        self.assertIsNotNone(enrich.parse_json_bounded(ok, "devices"))
        with self.assertRaises(enrich.EnrichError) as ctx:
            enrich.parse_json_bounded(too_deep, "devices")
        self.assertEqual(ctx.exception.code, "devices_nesting_too_deep")

    def test_deep_structure_hidden_inside_a_valid_capture_is_rejected_before_any_copy_or_dump(self):
        # Without the bound, deepcopy of the annotated private copy (or json.dumps) recurses without limit.
        deep = "[" * 200_000 + "]" * 200_000
        text = '{"devices": [' + json.dumps(device(1, "S5")) + ', {"fields": {"a": ' + deep + "}}]}"
        cap = self.write_bytes("devices.json", text.encode())
        before = self.listing()
        code, _, stderr = self.cli("--devices", cap, "--out", self.dir / "o.json", "--private-annotated-out", self.dir / "a.local.json")
        self.assertEqual(code, enrich.EXIT_INPUT, stderr)
        self.assertIn("devices_nesting_too_deep", stderr)
        self.assertEqual(self.listing(), before)

    def test_bad_profiles_fail_before_any_device_is_read(self):
        cap = self.good_capture()
        bad = self.write_json("bad-profiles.json", versioned({"S5": valid_profile(per_unit_silicon_confirmed=True)}))
        code, _, stderr = self.cli("--devices", cap, "--profiles", bad, "--out", self.dir / "o.json")
        self.assertEqual(code, enrich.EXIT_INPUT)
        self.assertIn("profiles_unknown_field", stderr)
        self.assertFalse((self.dir / "o.json").exists())

    def test_custom_versioned_profiles_drive_enrichment(self):
        profiles = self.write_json("v1.json", versioned({"S5": dict(valid_profile(), published_profile_id="pub-s5-custom")}))
        cap = self.write_json("devices.json", capture(device(1, "S5"), device(2, "S3")))
        out = self.dir / "o.json"
        self.assertEqual(self.cli("--devices", cap, "--profiles", profiles, "--nominal-unit", "MB", "--out", out)[0], enrich.EXIT_PARTIAL)
        recs = {r["model_number"]: r for r in json.loads(out.read_text())["devices"]}
        self.assertEqual(recs["S5"]["published_profile"]["published_profile_id"], "pub-s5-custom")
        self.assertEqual(recs["S3"]["status"], "unknown_model", "models absent from the supplied profile set stay unknown")
        self.assertEqual(json.loads(out.read_text())["profile_set"]["schema_version"], 1)

    def test_check_profiles_validates_without_a_capture(self):
        code, stdout, _ = self.cli("--check-profiles")
        self.assertEqual(code, enrich.EXIT_OK)
        self.assertIn(f"digest={self.profiles.digest[:12]}", stdout)
        bad = self.write_json("p.json", {"X": {}})
        self.assertEqual(self.cli("--check-profiles", "--profiles", bad)[0], enrich.EXIT_INPUT)

    def test_outputs_may_never_overwrite_an_input_or_each_other(self):
        cap = self.good_capture()
        salt = self.write_bytes("salt.bin", SALT)
        profiles = self.write_json("profiles.json", {"S5": valid_profile()})
        snapshots = {p: p.read_bytes() for p in (cap, salt, profiles)}
        attempts = [
            ("--out", cap),
            ("--ee-records-out", cap),
            ("--out", profiles),
            ("--out", salt),
        ]
        for flag, target in attempts:
            with self.subTest(flag=flag, target=target.name):
                code, _, stderr = self.cli("--devices", cap, "--profiles", profiles, "--salt-file", salt, flag, target)
                self.assertEqual(code, enrich.EXIT_OUTPUT, stderr)
                self.assertIn("output_would_overwrite_input", stderr)
        with self.subTest("symlink to the input"):
            link = self.dir / "link.json"
            link.symlink_to(cap)
            code, _, stderr = self.cli("--devices", cap, "--out", link)
            self.assertEqual(code, enrich.EXIT_OUTPUT)
            self.assertIn("output_would_overwrite_input", stderr)
        with self.subTest("two outputs, one path"):
            same = self.dir / "same.json"
            code, _, stderr = self.cli("--devices", cap, "--out", same, "--ee-records-out", same)
            self.assertEqual(code, enrich.EXIT_OUTPUT)
            self.assertIn("output_paths_collide", stderr)
        for path, data in snapshots.items():
            self.assertEqual(path.read_bytes(), data, f"{path.name} was modified")

    def test_missing_output_directory_is_refused_not_created(self):
        cap = self.good_capture()
        target = self.dir / "no-such-dir" / "o.json"
        code, _, stderr = self.cli("--devices", cap, "--out", target)
        self.assertEqual(code, enrich.EXIT_OUTPUT)
        self.assertIn("output_directory_missing", stderr)
        self.assertFalse(target.parent.exists())

    def test_failed_replace_keeps_the_previous_output_and_leaves_no_temp_file(self):
        cap = self.good_capture()
        out = self.dir / "out.json"
        self.assertEqual(self.cli("--devices", cap, "--nominal-unit", "MB", "--out", out)[0], enrich.EXIT_OK)
        previous = out.read_bytes()
        cap2 = self.write_json("devices2.json", capture(device(3, "S5")))
        with mock.patch.object(enrich.os, "replace", side_effect=OSError(5, "Input/output error")):
            code, _, stderr = self.cli("--devices", cap2, "--nominal-unit", "MB", "--out", out)
        self.assertEqual(code, enrich.EXIT_OUTPUT)
        self.assertIn("output_write_failed", stderr)
        self.assertEqual(out.read_bytes(), previous)
        self.assertEqual([n for n in self.listing() if n.startswith(".enrich-")], [])

    def test_script_runs_as_a_real_process(self):
        cap = self.good_capture()
        out = self.dir / "proc.json"
        run = subprocess.run([sys.executable, "-I", str(SCRIPT), "--devices", str(cap), "--nominal-unit", "MiB", "--out", str(out)], capture_output=True, text=True, timeout=60, cwd=self.dir)
        self.assertEqual(run.returncode, 0, run.stderr)
        doc = json.loads(out.read_text())
        self.assertEqual(doc["denominator"]["enriched"], 2)
        self.assertEqual(doc["devices"][0]["device_reported"]["nominal_ram"]["bytes"], 32 * 2**20)
        bare = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, timeout=60, cwd=self.dir)
        self.assertEqual(bare.returncode, enrich.EXIT_USAGE)
        self.assertIn("--devices is required", bare.stderr)
        partial = self.write_json("p.json", capture(device(1, "S7")))
        proc = subprocess.run([sys.executable, "-I", str(SCRIPT), "--devices", str(partial), "--dry-run", "--nominal-unit", "MB"], capture_output=True, text=True, timeout=60, cwd=self.dir)
        self.assertEqual(proc.returncode, enrich.EXIT_PARTIAL, "the process exit status must carry the partial outcome")


# ---------------------------------------------------------------------------
# cancellation and restart of output publication (E01 end-to-end, concrete artifact atomicity)
# ---------------------------------------------------------------------------


class InterruptionTests(Base):
    """Three outputs are requested together; each test starts from a complete earlier publication
    of capture A and interrupts or fails a publication of capture B."""

    def setUp(self):
        super().setUp()
        self.out, self.ee, self.priv = self.dir / "out.json", self.dir / "ee.jsonl", self.dir / "x.local.json"
        self.paths = (self.out, self.ee, self.priv)
        self.cap_a = self.write_json("a.json", capture(device(1, "S5"), device(2, "S3")))
        self.cap_b = self.write_json("b.json", capture(device(3, "S5"), device(4, "ZB100"), device(5, "S9")))
        self.assertEqual(self.run3(self.cap_a)[0], enrich.EXIT_OK)
        self.old = self.snapshot()
        ref = self.dir / "ref"
        ref.mkdir()
        code, _, err = self.cli("--devices", self.cap_b, "--nominal-unit", "MB", "--out", ref / "out.json", "--ee-records-out", ref / "ee.jsonl", "--private-annotated-out", ref / "x.local.json")
        self.assertEqual(code, enrich.EXIT_OK, err)
        self.new = {p.name: (ref / p.name).read_bytes() for p in self.paths}
        self.assertTrue(all(self.new[n] != self.old[n] for n in self.old), "premise: B must differ from A in every output, or an untouched file proves nothing")

    def run3(self, cap):
        return self.cli("--devices", cap, "--nominal-unit", "MB", "--out", self.out, "--ee-records-out", self.ee, "--private-annotated-out", self.priv)

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.paths}

    def assert_no_temp_files(self):
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".enrich-")], [])

    def nth_call(self, n, exc):
        """A side_effect that passes through to the real function except on call ``n``, where it raises ``exc``."""
        calls = []

        def effect(real):
            def wrapper(*a, **k):
                calls.append(1)
                if len(calls) == n:
                    raise exc
                return real(*a, **k)
            return wrapper

        return calls, effect

    def test_interrupt_while_staging_leaves_every_previous_output_untouched(self):
        calls, effect = self.nth_call(2, KeyboardInterrupt())  # one temp file already staged when it hits
        with mock.patch.object(enrich.os, "fsync", side_effect=effect(os.fsync)):
            code, _, err = self.run3(self.cap_b)
        self.assertEqual(len(calls), 2, "premise: the interrupt fired mid-staging")
        self.assertEqual(code, enrich.EXIT_INTERRUPT)
        self.assertIn("interrupted", err)
        self.assertIn("already renamed into place: none", err)
        self.assertEqual(self.snapshot(), self.old, "no destination may change before the rename phase")
        self.assert_no_temp_files()
        # restart converges on exactly what an uninterrupted run publishes
        self.assertEqual(self.run3(self.cap_b)[0], enrich.EXIT_OK)
        self.assertEqual(self.snapshot(), self.new)

    def test_a_write_failure_while_staging_is_all_or_nothing(self):
        calls, effect = self.nth_call(2, OSError(28, "No space left on device"))
        with mock.patch.object(enrich.os, "fsync", side_effect=effect(os.fsync)):
            code, _, err = self.run3(self.cap_b)
        self.assertEqual(len(calls), 2)
        self.assertEqual(code, enrich.EXIT_OUTPUT)
        self.assertIn("output_write_failed", err)
        self.assertIn("already renamed into place: none", err)
        self.assertEqual(self.snapshot(), self.old, "the first output must not have been replaced before the second failed")
        self.assert_no_temp_files()

    def test_interrupt_between_renames_reports_exactly_what_landed_and_a_rerun_converges(self):
        calls, effect = self.nth_call(2, KeyboardInterrupt())
        with mock.patch.object(enrich.os, "replace", side_effect=effect(os.replace)):
            code, _, err = self.run3(self.cap_b)
        self.assertEqual(len(calls), 2)
        self.assertEqual(code, enrich.EXIT_INTERRUPT)
        self.assertIn("already renamed into place: out; rerun to repair", err)
        now = self.snapshot()
        self.assertEqual(now["out.json"], self.new["out.json"], "the rename that completed is whole, never partial")
        self.assertEqual((now["ee.jsonl"], now["x.local.json"]), (self.old["ee.jsonl"], self.old["x.local.json"]))
        self.assert_no_temp_files()
        self.assertEqual(self.run3(self.cap_b)[0], enrich.EXIT_OK)
        self.assertEqual(self.snapshot(), self.new, "a rerun repairs the mixed state byte-for-byte")

    def test_an_os_error_between_renames_is_reported_with_what_landed(self):
        calls, effect = self.nth_call(2, OSError(5, "Input/output error"))
        with mock.patch.object(enrich.os, "replace", side_effect=effect(os.replace)):
            code, _, err = self.run3(self.cap_b)
        self.assertEqual(code, enrich.EXIT_OUTPUT)
        self.assertIn("already renamed into place: out", err)
        self.assertEqual(self.snapshot()["out.json"], self.new["out.json"])
        self.assertEqual(self.snapshot()["x.local.json"], self.old["x.local.json"])
        self.assert_no_temp_files()

    def test_interrupt_before_publication_writes_nothing(self):
        with mock.patch.object(enrich, "enrich_document", side_effect=KeyboardInterrupt):
            code, _, err = self.run3(self.cap_b)
        self.assertEqual(code, enrich.EXIT_INTERRUPT)
        self.assertIn("interrupted: nothing was written", err)
        self.assertEqual(self.snapshot(), self.old)
        self.assert_no_temp_files()

    @unittest.skipUnless(os.name == "posix" and hasattr(signal, "SIGTERM"), "needs POSIX signals")
    def test_a_real_sigterm_in_a_real_process_takes_the_same_clean_path(self):
        # In a child process so a regression (no handler) kills the child, not the test run.
        child = (
            "import importlib.util, os, signal, sys\n"
            "spec = importlib.util.spec_from_file_location('enrich_child', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "real, n = os.fsync, [0]\n"
            "def fsync(fd):\n"
            "    n[0] += 1\n"
            "    if n[0] == 2:\n"
            "        os.kill(os.getpid(), signal.SIGTERM)\n"
            "    return real(fd)\n"
            "os.fsync = fsync\n"
            "code = mod.main(sys.argv[2:])\n"
            "print('FSYNC_CALLS', n[0]); print('HANDLER_RESTORED', signal.getsignal(signal.SIGTERM) == signal.SIG_DFL)\n"
            "sys.exit(code)\n"
        )
        run = subprocess.run(
            [sys.executable, "-I", "-c", child, str(SCRIPT), "--devices", str(self.cap_b), "--nominal-unit", "MB", "--out", str(self.out), "--ee-records-out", str(self.ee), "--private-annotated-out", str(self.priv)],
            capture_output=True, text=True, timeout=60,
        )
        # Literal on purpose: 130 is the interrupt status shared with reconcile.py, so it must not
        # move with the constant it is meant to pin.
        self.assertEqual(run.returncode, 130, (run.stdout, run.stderr))
        self.assertEqual(enrich.EXIT_INTERRUPT, 130)
        self.assertIn("FSYNC_CALLS 2", run.stdout, "premise: the signal arrived mid-staging")
        self.assertIn("HANDLER_RESTORED True", run.stdout)
        self.assertIn("interrupted", run.stderr)
        self.assertEqual(self.snapshot(), self.old)
        self.assert_no_temp_files()

    def test_a_stale_temp_file_from_a_killed_run_is_never_read_or_removed(self):
        stale = self.dir / ".enrich-killed-earlier.tmp"
        stale.write_bytes(b"half-written bytes from a run that was SIGKILLed")
        self.assertEqual(self.run3(self.cap_b)[0], enrich.EXIT_OK)
        self.assertEqual(self.snapshot(), self.new)
        self.assertEqual(stale.read_bytes(), b"half-written bytes from a run that was SIGKILLed", "a file this run did not create is left alone")


if __name__ == "__main__":
    unittest.main(verbosity=2)
