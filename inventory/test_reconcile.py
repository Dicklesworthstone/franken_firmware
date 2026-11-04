"""Unit, property and contract tests for inventory/reconcile.py (bead ffw-xdi / E01).

Run (stdlib only, offline, no network, no builds):

    python3 -B -I -m unittest discover -s inventory -p 'test_reconcile.py' -v

Every test method docstring starts with a stable case ID (E01-...).  All
identifiers here are synthetic: documentation-range MAC/serial prefix
00-00-5E-00-53-xx and TEST-NET-1 addresses 192.0.2.x.  Nothing here is, or
claims to be, real device evidence.  Expected values are written from the
contract, not produced by running the code; the profile-id goldens were
computed independently with `shasum -a 256`.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter as collections_counter
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
_spec = importlib.util.spec_from_file_location("reconcile_under_test", HERE / "reconcile.py")
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
H1, H2 = "a" * 64, "b" * 64  # the same digests as emitted: bare 64-hex plus digest_algorithm
# Independent goldens (identity.py formula): printf '{"hardware_revision":"R","kind":"board-profile-id","product_model":"M","schema":"ffw.identity/v1"}' | shasum -a 256 | cut -c1-16
GOLDEN_S5_R6 = "bp-a93b52330d511449"
GOLDEN_S5_R7 = "bp-73ff9b45059ef52d"
GOLDEN_S12_R6 = "bp-3ccaf07451b76461"
GOLDEN_SUB_R = "bp-82131944131688a1"  # model "Sub" is canonicalised to "SUB" by identity.py before hashing
# Markers that must never appear in any public output produced from the synthetic fixtures.
SYNTHETIC_MARKERS = ("00-00-5e-00-53", "00:00:5e:00:53", "00005e0053", "192.0.2.", "rincon_",
                     "test room", "syntheticHousehold".lower(), "private-marker")


# ----------------------------------------------------------------------- builders
def ident(n):
    return {"serial": f"00-00-5E-00-53-{n:02X}:1", "mac": f"00:00:5e:00:53:{n:02x}",
            "udn": f"uuid:RINCON_00005E0053{n:02X}01400_MR", "ip": f"192.0.2.{n}"}


def dev(n=1, *, model="S5", name="Sonos Play:5", series="P100", variant="0", rev="1.2.3.4-5.6",
        sw="57.23-74170", gen="1", mem="32", flash="32", room=None, ts=None, ip=None,
        over=None, status_over=None, drop=(), udn_suffix=True):
    i = ident(n)
    ip = ip or i["ip"]
    room = room or f"Test Room {n}"
    fields = {"serialNum": i["serial"], "MACAddress": i["mac"],
              "UDN": i["udn"] if udn_suffix else i["udn"].replace("_MR", ""),
              "deviceID": f"urn:example:synthetic:{i['udn']}",
              "modelNumber": model, "modelName": name, "seriesid": series, "variant": variant,
              "hardwareVersion": rev, "softwareVersion": sw, "swGen": gen, "memory": mem, "flash": flash,
              "roomName": room, "friendlyName": f"{ip} - {name}"}
    status = {"SerialNumber": i["serial"], "MACAddress": i["mac"], "IPAddress": ip,
              "HardwareVersion": rev, "SoftwareVersion": sw, "SWGen": gen, "Variant": variant,
              "SeriesID": series, "ZoneName": room, "HouseholdControlID": f"Sonos_SyntheticHousehold{n}"}
    for k in drop:
        fields.pop(k, None)
        status.pop(k, None)
    fields.update(over or {})
    status.update(status_over or {})
    rec = {"url": f"http://{ip}:1400/xml/device_description.xml", "fields": fields, "status": status}
    if ts:
        rec["observed_at"] = ts
    return rec


def batch(*devs, observed_at=None):
    b = {"method": "synthetic fixture", "devices": list(devs)}
    if observed_at:
        b["observed_at"] = observed_at
    return b


def ev(eid="ev-test-1", model="S5", basis="owner-attested", lines=("57.23",), revs=None, machine="powerpc",
       cls=32, endian="big", abi="elf32-ppc-sysv", fabi="hard", atomics=(8, 16, 32), name="anacapad",
       digest=D1):
    return {"evidence_id": eid, "join": {"model_number": model, "join_basis": basis},
            "firmware_lines": list(lines), **({"hardware_revisions": list(revs)} if revs else {}),
            "claim": {"machine": machine, "elf_class": cls, "endianness": endian, "abi": abi,
                      "float_abi": fabi, "atomic_widths": list(atomics) if atomics else None},
            "image": {"name": name, "digest": digest},
            "provenance": {"source": "synthetic fixture", "basis": "synthetic test record, not evidence"}}


def profile(cpu="synthetic cpu note", qualification="synthetic note"):
    """A published-hardware profile that enrich.load_profiles accepts."""
    return {"cpu": cpu, "ram": "synthetic ram", "flash": "synthetic flash", "network": "synthetic network",
            "audio": "synthetic audio", "qualification": qualification,
            "sources": ["https://example.invalid/synthetic-teardown"]}


def registry(*records):
    return {"schema": rc.EVIDENCE_SCHEMA, "records": list(records)}


def collect_codes(doc):
    codes = set(doc.get("diagnostics", {}))
    for e in doc["profiles"]:
        codes |= {r["code"] for r in e["reason_codes"]}
    for c in doc["conflicts"]:
        codes |= {x["code"] for x in c["codes"]}
    return codes


# --------------------------------------------------------------------------- base
class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self._seq = 0

    def write(self, obj, name=None):
        self._seq += 1
        p = self.dir / (name or f"in{self._seq}.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
        return str(p)

    def cli(self, *argv, default_exit=False):
        """Run the CLI in-process.  Most tests are about content, so they add --allow-incomplete;
        tests of the default exit policy pass default_exit=True."""
        argv = list(argv) if default_exit else [*argv, "--allow-incomplete"]
        out, err = io.StringIO(), io.StringIO()
        code = rc.main(argv, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def run_ok(self, batches, *extra, evidence=None, check_markers=True):
        """Write batches, run the CLI, assert exit 0 and universal public-output invariants."""
        args = []
        for b in batches:
            args += ["--input", self.write(b)]
        if evidence is not None:
            args += ["--evidence", self.write(evidence)]
        code, out, err = self.cli(*args, *extra)
        self.assertEqual(code, 0, msg=f"stderr={err!r}")
        doc = json.loads(out) if "--format" not in extra or "json" in extra else None
        if doc is not None:
            self.assertEqual(doc["schema"], rc.MANIFEST_SCHEMA)
            self.assertLessEqual(collect_codes(doc), set(rc.REASONS), "emitted a reason code missing from the catalog")
        if check_markers:
            low = out.lower()
            for m in SYNTHETIC_MARKERS:
                self.assertNotIn(m, low, f"synthetic private marker leaked into public output: {m!r}")
        return doc

    def run_fail(self, argv, expect_code, expect_err):
        code, out, err = self.cli(*argv)
        self.assertEqual(code, expect_code, msg=f"stdout={out[:200]!r} stderr={err!r}")
        self.assertIn(expect_err, err)
        for m in SYNTHETIC_MARKERS:
            self.assertNotIn(m, err.lower(), f"error text echoed private data: {m!r}")
        return out, err


def one(doc):
    assert len(doc["profiles"]) == 1, doc["profiles"]
    return doc["profiles"][0]


def codes_of(entry):
    return {(r["code"], r.get("field")) for r in entry["reason_codes"]}


def resolved_batch():
    return batch(dev(1))


# ------------------------------------------------------- import / offline contract
class TestImportAndOffline(unittest.TestCase):
    def test_import_has_no_side_effects(self):
        """E01-IMPORT-PURE: importing the module opens no socket, spawns nothing, writes no file."""
        code = r'''
import sys, importlib.util
events = []
def hook(ev, args):
    if ev in ("socket.__new__", "socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system"):
        events.append(ev)
    if ev == "open":
        path, mode, flags = args
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
        if (mode and any(c in str(mode) for c in "wax+")) or (isinstance(flags, int) and flags & write_flags):
            events.append("open-write")
import os
sys.addaudithook(hook)
spec = importlib.util.spec_from_file_location("r", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(len(events), events)
'''
        with tempfile.TemporaryDirectory() as cwd:
            r = subprocess.run([sys.executable, "-B", "-I", "-c", code, str(HERE / "reconcile.py")],
                               capture_output=True, text=True, timeout=30, cwd=cwd)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "0 []")
            self.assertEqual(os.listdir(cwd), [], "import created files in the working directory")

    def test_no_network_or_process_modules_imported(self):
        """E01-OFFLINE-STATIC: reconcile.py imports no networking/process module (static check)."""
        tree = ast.parse((HERE / "reconcile.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        banned = {"socket", "urllib", "http", "ftplib", "smtplib", "ssl", "subprocess", "asyncio",
                  "multiprocessing", "requests", "telnetlib", "xmlrpc", "select", "selectors"}
        self.assertEqual(imported & banned, set())

    def test_removed_env_driven_network_path(self):
        """E01-OFFLINE-ENV: the old FSONOS_PEER_IP/FSONOS_DEVICES_JSON environment switches are gone."""
        src = (HERE / "reconcile.py").read_text()
        for needle in ("FSONOS_PEER_IP", "FSONOS_DEVICES_JSON", "urlopen", "environ"):
            self.assertNotIn(needle, src)


class TestOfflineRuntime(Base):
    def test_cli_run_opens_no_socket(self):
        """E01-OFFLINE-RUNTIME: a full CLI run never touches the network stack."""
        import socket
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network used")), \
                mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns used")), \
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")):
            self.run_ok([resolved_batch()])

    def test_no_arguments_is_a_usage_error_and_reads_nothing(self):
        """E01-NO-IMPLICIT-INPUT: with no --input the tool refuses rather than discovering files."""
        with mock.patch("builtins.open", side_effect=AssertionError("file opened")):
            code, out, err = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("error[usage]", err)
        self.assertEqual(out, "")

    def test_abbreviated_flags_rejected(self):
        """E01-USAGE-STRICT: abbreviations are refused (allow_abbrev=False), unknown flags exit 2."""
        for argv in (["--inp", "x"], ["--bogus"], ["--format", "xml", "--input", "x"]):
            code, _, err = self.cli(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("error[usage]", err)

    def test_input_files_are_never_modified(self):
        """E01-INPUT-IMMUTABLE: bytes and mtime of every input are unchanged after a run (old script rewrote its input)."""
        p = self.write(batch(dev(1), dev(2)))
        reg = self.write(registry(ev()))
        priv = self.dir / ".local-real" / "r.json"
        priv.parent.mkdir()
        snap = lambda: {q: (hashlib.sha256(Path(q).read_bytes()).hexdigest(), os.stat(q).st_mtime_ns) for q in (p, reg)}
        before = snap()
        self.assertEqual(self.cli("--input", p, "--evidence", reg, "--private-out", str(priv))[0], 0)
        self.assertEqual(self.cli("--input", p, "--evidence", reg, "--out", str(self.dir / "m.json"))[0], 0)
        self.assertEqual(before, snap())

    def test_stdout_default_writes_no_files(self):
        """E01-STDOUT-DEFAULT: without --out the manifest goes to stdout and nothing is created on disk."""
        p = self.write(batch(dev(1)))
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            before = set(os.listdir(self.dir))
            code, out, _ = self.cli("--input", p)
            after = set(os.listdir(self.dir))
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0)
        self.assertEqual(before, after)
        self.assertEqual(json.loads(out)["schema"], rc.MANIFEST_SCHEMA)


# ----------------------------------------------------------------- identity merging
class TestIdentityMerge(Base):
    def test_exact_duplicates_collapse(self):
        """E01-DEDUP-EXACT: identical records in one batch and across batches are one device; duplicates are counted."""
        d = self.run_ok([batch(dev(1), dev(1)), batch(dev(1))])
        s = d["summary"]
        self.assertEqual((s["observations"], s["identity_components"], s["duplicate_observations"]), (3, 1, 2))
        self.assertEqual(one(d)["device_count"], 1)

    def test_identical_batch_supplied_twice_is_ignored(self):
        """E01-DEDUP-BATCH: the same batch given twice (replay) is counted once and reported as info."""
        b = batch(dev(1), dev(2))
        d = self.run_ok([b, copy.deepcopy(b)])
        self.assertEqual(d["summary"]["observations"], 2)
        self.assertEqual(d["diagnostics"].get("duplicate_batch_ignored"), 1)
        self.assertEqual(d["inputs"]["batches"], 1)

    def test_renamed_device_merges_without_conflict(self):
        """E01-RENAMED: same identifiers, different room/friendly names -> one device, no conflict."""
        priv = self.dir / ".local-real" / "p.json"
        priv.parent.mkdir()
        a = dev(1)
        b = dev(1, room="Other Room", over={"friendlyName": "192.0.2.1 - Renamed"}, status_over={"ZoneName": "Other Room"})
        d = self.run_ok([batch(a), batch(b)], "--private-out", str(priv))
        self.assertEqual((d["summary"]["identity_components"], d["conflicts"]), (1, []))
        rep = json.loads(priv.read_text())
        self.assertTrue(rep["devices"][0]["changes"]["renamed"])
        self.assertFalse(rep["devices"][0]["changes"]["address_changed"])

    def test_address_changed_device_merges_without_conflict(self):
        """E01-ADDR-CHANGED: same identifiers at a new address -> one device, address change visible only in the private report."""
        priv = self.dir / ".local-real" / "p.json"
        priv.parent.mkdir()
        d = self.run_ok([batch(dev(1)), batch(dev(1, ip="192.0.2.99"))], "--private-out", str(priv))
        self.assertEqual((d["summary"]["identity_components"], d["conflicts"]), (1, []))
        rep = json.loads(priv.read_text())
        self.assertTrue(rep["devices"][0]["changes"]["address_changed"])
        self.assertEqual(rep["devices"][0]["changes"]["hosts_seen"], ["192.0.2.1", "192.0.2.99"])

    def test_identity_is_transitive_through_shared_tokens(self):
        """E01-ID-TRANSITIVE: A(serial,mac) - B(mac,udn) - C(udn) are one device even though A and C share nothing directly."""
        a = dev(1, drop=("UDN",))
        b = dev(1, drop=("serialNum", "SerialNumber"))
        c = dev(1, drop=("serialNum", "SerialNumber", "MACAddress"))
        d = self.run_ok([batch(a, b, c)])
        self.assertEqual((d["summary"]["identity_components"], d["conflicts"]), (1, []))

    def test_distinct_devices_stay_distinct_and_share_a_profile(self):
        """E01-ID-DISTINCT: two devices of one model/revision -> 2 components, 1 profile, device_count 2."""
        d = self.run_ok([batch(dev(1), dev(2))])
        self.assertEqual(d["summary"]["identity_components"], 2)
        self.assertEqual(one(d)["device_count"], 2)

    def test_same_serial_different_mac_is_ambiguous_not_merged(self):
        """E01-ID-SERIAL-MAC-CONFLICT: one serial with two MACs is an identity conflict, excluded from every profile."""
        a = dev(1)
        b = dev(1, over={"MACAddress": ident(7)["mac"]}, status_over={"MACAddress": ident(7)["mac"]})
        d = self.run_ok([batch(a, b)])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(len(d["conflicts"]), 1)
        c = d["conflicts"][0]
        self.assertEqual(c["codes"], [{"code": "identity_ambiguous", "field": "mac"}])
        self.assertEqual((c["model_numbers"], c["component_count"], c["activation_eligible"]), (["S5"], 1, False))
        self.assertEqual((d["summary"]["devices_in_conflict"], d["summary"]["all_resolved"]), (1, False))

    def test_shared_mac_between_two_serials_is_ambiguous(self):
        """E01-ID-SHARED-MAC: two serials joined by one MAC are never silently merged into a device."""
        a = dev(1)
        b = dev(2, over={"MACAddress": ident(1)["mac"]}, status_over={"MACAddress": ident(1)["mac"]})
        d = self.run_ok([batch(a, b)])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(d["conflicts"][0]["codes"], [{"code": "identity_ambiguous", "field": "serial,udn"}])

    def test_record_without_any_strong_identifier_is_unidentifiable(self):
        """E01-ID-NONE: no serial/MAC/UDN -> unattributed, never guessed into a device."""
        d = self.run_ok([batch(dev(1), dev(2, drop=("serialNum", "SerialNumber", "MACAddress", "UDN")))])
        self.assertEqual(d["summary"]["unidentifiable_observations"], 1)
        self.assertEqual(d["unattributed"]["reason_codes"], [{"code": "identity_unidentifiable"}])
        self.assertEqual(d["summary"]["identity_components"], 1)
        self.assertFalse(d["summary"]["all_resolved"])

    def test_udn_subdevice_suffix_does_not_split_a_device(self):
        """E01-UDN-SUFFIX: the same speaker seen with and without the _MR UDN suffix is one device."""
        a = dev(1)
        b = dev(1, udn_suffix=False, drop=("serialNum", "SerialNumber", "MACAddress"))
        d = self.run_ok([batch(a, b)])
        self.assertEqual((d["summary"]["identity_components"], d["conflicts"]), (1, []))

    def test_mac_spellings_normalise(self):
        """E01-MAC-FORMATS: colon/dash/bare/upper MAC spellings are one identifier."""
        recs = [dev(1, drop=("serialNum", "SerialNumber", "UDN"), over={"MACAddress": m}, status_over={"MACAddress": m})
                for m in ("00:00:5E:00:53:01", "00-00-5e-00-53-01", "00005e005301")]
        d = self.run_ok([batch(*recs)])
        self.assertEqual((d["summary"]["identity_components"], d["conflicts"]), (1, []))

    def test_malformed_mac_is_ignored_for_identity(self):
        """E01-MAC-MALFORMED: a garbage MAC is dropped (info diagnostic) and the serial still identifies the device."""
        d = self.run_ok([batch(dev(1, over={"MACAddress": "zz-top"}, status_over={"MACAddress": "zz-top"}))])
        self.assertEqual(d["summary"]["identity_components"], 1)
        self.assertEqual(d["diagnostics"]["identity_mac_malformed"], 2)

    def test_device_without_serial_is_flagged_info_only(self):
        """E01-ID-NO-SERIAL: identified by MAC/UDN alone is allowed and reported as info."""
        d = self.run_ok([batch(dev(1, drop=("serialNum", "SerialNumber")))])
        self.assertEqual(d["diagnostics"]["identity_serial_absent"], 1)


# ------------------------------------------------------------ hardware field handling
class TestHardwareFields(Base):
    def test_absent_revision_blocks_and_issues_no_profile_id(self):
        """E01-REV-ABSENT: a model alone cannot select a board; no profile_id is issued."""
        d = self.run_ok([batch(dev(1, drop=("hardwareVersion", "HardwareVersion")))])
        e = one(d)
        self.assertIn(("hardware_revision_absent", None), codes_of(e))
        self.assertIsNone(e["profile_id"])
        self.assertEqual((e["resolution"], e["activation_eligible"]), ("unresolved", False))

    def test_absent_model_blocks(self):
        """E01-MODEL-ABSENT: no modelNumber -> model_absent, no profile_id, no evidence matching attempted."""
        d = self.run_ok([batch(dev(1, drop=("modelNumber",)))], evidence=registry(ev()))
        e = one(d)
        self.assertIn(("model_absent", None), codes_of(e))
        self.assertIsNone(e["profile_id"])
        self.assertFalse({c for c, _ in codes_of(e)} & {"isa_evidence_absent", "isa_evidence_join_unattested"})

    def test_immutable_field_disagreement_is_a_conflict(self):
        """E01-HW-CONFLICT: one device seen with two different seriesid values -> conflict, device excluded from profiles."""
        d = self.run_ok([batch(dev(1), dev(1, series="A999", status_over={"SeriesID": "A999"}))])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(d["conflicts"][0]["codes"], [{"code": "hardware_field_conflict", "field": "series_id"}])
        self.assertEqual(d["conflicts"][0]["model_numbers"], ["S5"])

    def test_cross_source_disagreement_within_one_record_is_a_conflict(self):
        """E01-XSOURCE-CONFLICT: description XML and status/zp disagree on hardware revision -> conflict."""
        d = self.run_ok([batch(dev(1, status_over={"HardwareVersion": "9.9.9.9-9.9"}))])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(d["conflicts"][0]["codes"], [{"code": "hardware_field_conflict", "field": "hardware_revision"}])

    def test_firmware_change_is_ordered_by_observed_at(self):
        """E01-FW-ORDERED: an upgrade between dated observations is history, not a conflict; the latest wins."""
        priv = self.dir / ".local-real" / "p.json"
        priv.parent.mkdir()
        old = dev(1, sw="57.22-70000", ts="2026-01-01T00:00:00Z")
        new = dev(1, sw="57.23-74170", ts="2026-02-01T00:00:00Z")
        for order in ((old, new), (new, old)):
            d = self.run_ok([batch(*order)], "--private-out", str(priv), "--overwrite")
            self.assertEqual((one(d)["firmware"]["line"], d["conflicts"]), ("57.23", []))
            self.assertTrue(json.loads(priv.read_text())["devices"][0]["changes"]["firmware_changed"])

    def test_undated_firmware_disagreement_is_a_conflict(self):
        """E01-FW-UNORDERED: differing firmware with one undated observation cannot be ordered -> conflict."""
        d = self.run_ok([batch(dev(1, sw="57.22-70000", ts="2026-01-01T00:00:00Z")), batch(dev(1, sw="57.23-74170"))])
        self.assertEqual(d["profiles"], [])
        self.assertEqual(d["conflicts"][0]["codes"], [{"code": "firmware_unordered_conflict", "field": "software_version"}])

    def test_equal_timestamps_with_different_firmware_conflict(self):
        """E01-FW-TIE: two firmware values at the same instant are ambiguous -> conflict."""
        ts = "2026-01-01T00:00:00Z"
        d = self.run_ok([batch(dev(1, sw="57.22-70000", ts=ts), dev(1, sw="57.23-74170", ts=ts))])
        self.assertEqual(d["conflicts"][0]["codes"][0]["code"], "firmware_unordered_conflict")

    def test_batch_level_timestamp_is_inherited(self):
        """E01-FW-BATCH-TS: records without their own observed_at inherit the batch's, so batch-dated upgrades order correctly."""
        d = self.run_ok([batch(dev(1, sw="57.22-70000"), observed_at="2026-01-01T00:00:00Z"),
                         batch(dev(1, sw="57.23-74170"), observed_at="2026-03-01T00:00:00Z")])
        self.assertEqual((one(d)["firmware"]["line"], d["conflicts"]), ("57.23", []))

    def test_bare_nominal_size_has_unknown_unit_but_stays_visible(self):
        """E01-MEM-BARE: a bare 32 is reported as 32 with unit unknown and blocks resolution; the unit is never assumed."""
        e = one(self.run_ok([batch(dev(1))]))
        self.assertEqual(e["nominal_resources"]["memory"], {"value": 32, "unit": None, "unit_basis": "unknown", "bytes": None})
        self.assertIn(("nominal_size_unit_unknown", "memory"), codes_of(e))
        self.assertIn(("nominal_size_unit_unknown", "flash"), codes_of(e))
        self.assertFalse(e["nominal_resources"]["measured"])

    def test_operator_declared_unit_is_recorded_as_such(self):
        """E01-MEM-DECLARED: --nominal-unit MB applies to bare numbers and is labelled operator_asserted (identity.py vocabulary)."""
        d = self.run_ok([batch(dev(1))], "--nominal-unit", "MB")
        e = one(d)
        self.assertEqual(e["nominal_resources"]["memory"], {"value": 32, "unit": "MB", "unit_basis": "operator_asserted", "bytes": 32000000})
        self.assertNotIn("nominal_size_unit_unknown", {c for c, _ in codes_of(e)})
        self.assertEqual(d["inputs"]["nominal_unit_declared"], "MB")

    def test_explicit_suffix_beats_declared_unit(self):
        """E01-MEM-SUFFIX: '128 MiB' / '64 MB' keep their own unit even when another unit is declared; MB and MiB differ."""
        e = one(self.run_ok([batch(dev(1, mem="128 MiB", flash="64 MB"))], "--nominal-unit", "MB"))
        self.assertEqual(e["nominal_resources"]["memory"], {"value": 128, "unit": "MiB", "unit_basis": "device_stated", "bytes": 134217728})
        self.assertEqual(e["nominal_resources"]["flash"], {"value": 64, "unit": "MB", "unit_basis": "device_stated", "bytes": 64000000})

    def test_unrecognised_unit_blocks(self):
        """E01-MEM-UNKNOWN-UNIT: '128 Mbit' is not guessed to be MB."""
        e = one(self.run_ok([batch(dev(1, mem="128 Mbit"))], "--nominal-unit", "MB"))
        self.assertIn(("nominal_size_unit_unknown", "memory"), codes_of(e))
        self.assertIsNone(e["nominal_resources"]["memory"])

    def test_invalid_nominal_sizes_block(self):
        """E01-MEM-INVALID: non-numeric, zero, negative, fractional and oversized values are invalid, not coerced."""
        for raw in ("abc", "0", "-5", "1.5", "12345678901"):
            e = one(self.run_ok([batch(dev(1, mem=raw))], "--nominal-unit", "MB"))
            self.assertIn(("nominal_size_invalid", "memory"), codes_of(e), raw)

    def test_absent_nominal_size_blocks(self):
        """E01-MEM-ABSENT: missing memory/flash is its own reason."""
        e = one(self.run_ok([batch(dev(1, drop=("memory", "flash")))], "--nominal-unit", "MB"))
        self.assertTrue({("nominal_size_absent", "memory"), ("nominal_size_absent", "flash")} <= codes_of(e))

    def test_conflicting_nominal_sizes_for_one_device(self):
        """E01-MEM-CONFLICT: 128 vs 256 for one device is a hardware conflict."""
        d = self.run_ok([batch(dev(1, mem="128"), dev(1, mem="256"))])
        self.assertEqual(d["conflicts"][0]["codes"], [{"code": "hardware_field_conflict", "field": "memory"}])

    def test_bare_number_agrees_with_same_explicit_quantity(self):
        """E01-MEM-BARE-COMPAT: '128' and '128 MB' for one device are compatible and take the stated basis."""
        d = self.run_ok([batch(dev(1, mem="128"), dev(1, mem="128 MB"))])
        self.assertEqual(d["conflicts"], [])
        self.assertEqual(one(d)["nominal_resources"]["memory"], {"value": 128, "unit": "MB", "unit_basis": "device_stated", "bytes": 128000000})

    def test_public_bound_field_must_be_a_plain_token(self):
        """E01-HW-MALFORMED: markup/odd characters in a public-bound field are withheld and flagged."""
        e = one(self.run_ok([batch(dev(1, name="Sonos Play:5 <b>"))]))
        self.assertIn(("hardware_field_malformed", "model_name"), codes_of(e))
        self.assertIsNone(e["model"]["model_name"])

    def test_sw_gen_is_public_bound_and_must_be_a_plain_token(self):
        """E01-SWGEN-MALFORMED: a software-generation value identity.py rejects is withheld, not emitted; a good one is an integer."""
        e = one(self.run_ok([batch(dev(1, gen="<x>", status_over={"SWGen": "<x>"}))]))
        self.assertIn(("hardware_field_malformed", "sw_gen"), codes_of(e))
        self.assertIsNone(e["firmware"]["sw_gen"])
        self.assertEqual(one(self.run_ok([batch(dev(1))]))["firmware"]["sw_gen"], 1)

    def test_firmware_line_unknown_for_odd_version(self):
        """E01-FW-LINE-UNKNOWN: a softwareVersion that is not <maj>.<min>-<build> yields no firmware line."""
        e = one(self.run_ok([batch(dev(1, sw="weird", status_over={"SoftwareVersion": "weird"}))]))
        self.assertIn(("firmware_line_unknown", None), codes_of(e))
        self.assertIsNone(e["firmware"]["line"])

    def test_normalisers(self):
        """E01-NORMALISERS: identifier normalisation here; value and unit grammar is identity.py's (adapter table)."""
        self.assertEqual(rc.norm_mac("00-00-5E-00-53-01"), "00:00:5e:00:53:01")
        self.assertEqual(rc.norm_mac("0000.5e00.5301"), "00:00:5e:00:53:01")
        for bad in ("", "zz", "00:00:5e:00:53", "00:00:5e:00:53:01:02"):
            self.assertIsNone(rc.norm_mac(bad), bad)
        self.assertEqual(rc.norm_udn("uuid:RINCON_00005E00530101400_MR"), "RINCON_00005E00530101400")
        self.assertEqual(rc.norm_udn("uuid:rincon_00005e00530101400"), "RINCON_00005E00530101400")
        self.assertEqual(rc.norm_serial(" ab-01:c "), "AB-01:C")
        cases = {"32": (("bare", "32"), "unknown"), "32 MB": (("ok", "32 MB"), "device_stated"),
                 "32 furlongs": (("invalid",), None),  # the shared grammar rejects an over-long unit word as malformed
                 "32 mb": (("unit_unknown",), None),
                 "128 Mbit": (("unit_unknown",), None), "0": (("invalid",), None), "abc": (("invalid",), None)}
        for raw, want in cases.items():
            self.assertEqual(rc.size_state("memory", raw, None), want, raw)
        self.assertEqual(rc.size_state("memory", "32", "MiB"), (("ok", "32 MiB"), "operator_asserted"))
        self.assertEqual(rc.size_state("flash", "32 MiB", "MB"), (("ok", "32 MiB"), "device_stated"))
        self.assertEqual(rc._norm("product_model", "s5"), ("ok", "S5"))
        self.assertEqual(rc._norm("hardware_revision", "01.008.3.1-02"), ("ok", "1.8.3.1-2"))
        self.assertEqual(rc._norm("product_model", "unknown")[0], "err")


# ---------------------------------------------------------- evidence / ISA handling
class TestEvidence(Base):
    ARGS = ("--nominal-unit", "MB")

    def entry(self, *records, dev_rec=None, extra=()):
        reg = registry(*records) if records else None
        d = self.run_ok([batch(dev_rec or dev(1))], *self.ARGS, *extra, evidence=reg)
        return d, one(d)

    def test_fully_evidenced_profile_resolves(self):
        """E01-ISA-RESOLVED: attested join + digest + ABI + declared unit -> resolved, with the independent golden profile_id."""
        d, e = self.entry(ev())
        self.assertEqual((e["resolution"], e["activation_eligible"], e["reason_codes"]), ("resolved", True, []))
        self.assertEqual(e["profile_id"], GOLDEN_S5_R6)
        self.assertEqual(e["target"]["isa"], {"machine": "powerpc", "elf_class": 32, "endianness": "big"})
        self.assertEqual((e["target"]["abi"], e["target"]["float_abi"], e["target"]["atomic_widths"]), ("elf32-ppc-sysv", "hard", [8, 16, 32]))
        self.assertEqual(e["target"]["images"], [{"name": "anacapad", "digest": H1, "digest_algorithm": "sha256"}])
        self.assertEqual(e["evidence_ids"], ["ev-test-1"])
        self.assertTrue(d["summary"]["all_resolved"])
        self.assertEqual(self.cli("--input", self.write(batch(dev(1))), "--evidence", self.write(registry(ev())), "--nominal-unit", "MB", default_exit=True)[0], 0)

    def test_evidence_digest_covers_the_whole_entry(self):
        """E01-DIGEST-COVERS: evidence_digest (bare 64-hex, a schema-defined digest key) equals an independent recomputation and moves with any entry content."""
        _, e = self.entry(ev())
        body = {k: v for k, v in e.items() if k != "evidence_digest"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        want = hashlib.sha256(("ffw.e01.evidence-digest.v1\n" + canonical).encode("ascii")).hexdigest()
        self.assertEqual(e["evidence_digest"], want)
        _, e2 = self.entry(ev(digest=D2))
        self.assertNotEqual(e["evidence_digest"], e2["evidence_digest"])
        self.assertEqual(e["profile_id"], e2["profile_id"])  # board identity is unchanged by a different image

    def test_no_evidence_means_unknown_isa(self):
        """E01-ISA-ABSENT: without a registry the ISA is unknown, never inferred from the model."""
        _, e = self.entry()
        self.assertIn(("isa_evidence_absent", None), codes_of(e))
        self.assertEqual(e["target"], {"isa": None, "abi": None, "float_abi": None, "atomic_widths": None, "images": []})

    def test_name_inferred_join_is_not_accepted(self):
        """E01-ISA-UNATTESTED: evidence joined to the model only by product name does not select a board."""
        _, e = self.entry(ev(basis="name-inferred"))
        self.assertIn(("isa_evidence_join_unattested", None), codes_of(e))
        self.assertIsNone(e["target"]["isa"])
        self.assertEqual(e["resolution"], "unresolved")

    def test_unjoined_evidence_is_never_matched(self):
        """E01-ISA-UNJOINED: a record with model_number null matches nothing and is counted as info."""
        rec = ev()
        rec["join"] = {"model_number": None, "join_basis": "unmapped"}
        d, e = self.entry(rec)
        self.assertIn(("isa_evidence_absent", None), codes_of(e))
        self.assertEqual(d["diagnostics"]["evidence_unjoined"], 1)

    def test_other_firmware_line_is_not_extrapolated(self):
        """E01-ISA-FWLINE-MISMATCH: evidence for 57.22 is not applied to a 57.23 device (no era/firmware extrapolation)."""
        _, e = self.entry(ev(lines=("57.22",)))
        self.assertIn(("isa_evidence_firmware_line_mismatch", None), codes_of(e))
        self.assertIsNone(e["target"]["isa"])

    def test_revision_scoped_evidence_must_match_revision(self):
        """E01-ISA-REV-MISMATCH: evidence scoped to another hardware revision does not apply; the right revision does."""
        _, e = self.entry(ev(revs=("9.9.9.9-9.9",)))
        self.assertIn(("isa_evidence_revision_mismatch", None), codes_of(e))
        _, e = self.entry(ev(revs=("1.2.3.4-5.6",)))
        self.assertEqual(e["resolution"], "resolved")

    def test_contradictory_evidence_conflicts_and_withholds_isa(self):
        """E01-ISA-CONFLICT: two attested records disagreeing on machine -> conflicted, ISA withheld, not eligible."""
        _, e = self.entry(ev("ev-a"), ev("ev-b", machine="mips"))
        self.assertIn(("isa_evidence_conflict", None), codes_of(e))
        self.assertEqual((e["resolution"], e["activation_eligible"], e["target"]["isa"]), ("conflicted", False, None))
        self.assertEqual(e["profile_id"], GOLDEN_S5_R6)

    def test_same_image_digest_with_two_isas_contradicts(self):
        """E01-ISA-DIGEST-CONTRADICTION: one digest cannot be both PowerPC and MIPS, even across models."""
        d, e = self.entry(ev("ev-a"), ev("ev-b", model="S1", machine="mips"))
        self.assertIn(("isa_evidence_conflict", None), codes_of(e))
        self.assertEqual(e["resolution"], "conflicted")
        self.assertEqual(d["diagnostics"]["isa_evidence_conflict"], 1)

    def test_missing_digest_blocks_but_keeps_isa(self):
        """E01-DIGEST-ABSENT: ISA is recorded but a profile without an image digest is not resolved."""
        _, e = self.entry(ev(digest=None))
        self.assertIn(("image_digest_absent", None), codes_of(e))
        self.assertEqual((e["resolution"], e["target"]["isa"]["machine"]), ("unresolved", "powerpc"))

    def test_two_digests_for_one_image_name_conflict(self):
        """E01-DIGEST-CONFLICT: conflicting historical images under one name -> conflicted."""
        _, e = self.entry(ev("ev-a", digest=D1), ev("ev-b", digest=D2))
        self.assertIn(("image_digest_conflict", None), codes_of(e))
        self.assertEqual(e["resolution"], "conflicted")

    def test_distinct_image_names_are_listed_not_conflicted(self):
        """E01-DIGEST-MULTI: different images under one profile are both listed, sorted."""
        _, e = self.entry(ev("ev-a", name="zimage", digest=D2), ev("ev-b", name="anacapad", digest=D1))
        self.assertEqual([i["name"] for i in e["target"]["images"]], ["anacapad", "zimage"])
        self.assertEqual(e["resolution"], "resolved")

    def test_unrecorded_abi_blocks_but_float_abi_and_atomics_are_info(self):
        """E01-ABI: missing ABI blocks resolution; missing float ABI / atomic widths are info only."""
        _, e = self.entry(ev(abi=None))
        self.assertIn(("abi_not_recorded", None), codes_of(e))
        self.assertEqual(e["resolution"], "unresolved")
        _, e = self.entry(ev(fabi=None, atomics=None))
        self.assertTrue({("float_abi_not_recorded", None), ("atomic_widths_not_recorded", None)} <= codes_of(e))
        self.assertEqual((e["resolution"], e["activation_eligible"]), ("resolved", True))

    def test_hypotheses_never_reach_target_selection(self):
        """E01-NO-ERA-INFERENCE: a published-teardown CPU note never becomes an ISA, and its text is not emitted."""
        hyp = self.write({"S5": profile(cpu="TESTCPU-POWERPC-603E", qualification="synthetic teardown note")})
        d = self.run_ok([batch(dev(1))], "--hypotheses", hyp)
        e = one(d)
        self.assertIsNone(e["target"]["isa"])
        ph = dict(e["published_hypothesis"])
        self.assertRegex(ph.pop("published_profile_id"), r"^pub-s5-[0-9a-f]{8}$")
        self.assertEqual(ph, {"ref": "S5", "status": "hypothesis-not-evidence", "used_for_selection": False,
                              "qualification": "synthetic teardown note"})
        self.assertNotIn("testcpu", json.dumps(d).lower())
        plain = self.run_ok([batch(dev(1))])
        a, b = copy.deepcopy(d), copy.deepcopy(plain)
        for x in (a, b):
            x["profiles"][0].pop("published_hypothesis")
            x["profiles"][0].pop("evidence_digest")
            x["inputs"].pop("hypotheses_supplied")
        self.assertEqual(a, b, "hypotheses changed something other than the published_hypothesis reference")

    def test_hypothesis_is_attached_by_exact_model_only(self):
        """E01-NO-FORCED-S5: the old code forced the S5 profile onto an extra device; now only a matching (canonical) model attaches."""
        legacy = {"published_hardware_profile": {"cpu": "LEGACY-S5-CPU-MARKER"}}
        recs = [dict(dev(1, model="S3", name="Sonos Play:3", series="A100"), **legacy),
                dict(dev(2, model="Sub", name="Sonos Sub", series="A100"), **legacy),
                dev(3)]
        d = self.run_ok([batch(*recs)], "--hypotheses", self.write({"S5": profile(cpu="LEGACY-S5-CPU-MARKER", qualification="s5 only")}))
        refs = {e["model"]["model_number"]: e["published_hypothesis"] for e in d["profiles"]}
        self.assertIsNone(refs["S3"])
        self.assertIsNone(refs["SUB"])
        self.assertEqual(refs["S5"]["ref"], "S5")
        self.assertNotIn("legacy-s5-cpu-marker", json.dumps(d).lower())
        d2 = self.run_ok([batch(*recs)], "--hypotheses", self.write({"Sub": profile(qualification="sub only")}))
        refs2 = {e["model"]["model_number"]: e["published_hypothesis"] for e in d2["profiles"]}
        self.assertEqual((refs2["S3"], refs2["S5"]), (None, None))
        self.assertEqual(refs2["SUB"]["ref"], "SUB", "a key spelled 'Sub' attaches to the canonical model SUB")

    def test_hypotheses_shapes(self):
        """E01-HYP-SHAPES: enrich.load_profiles decides the shape: legacy and versioned are accepted; unknown keys, wrong schema and non-objects exit 2."""
        versioned = {"schema": "ffw.published-hardware-profiles", "schema_version": 1, "profiles": {"S5": profile(qualification="q")}}
        for obj in ({"S5": profile(qualification="q")}, versioned):
            d = self.run_ok([batch(dev(1))], "--hypotheses", self.write(obj))
            self.assertEqual(one(d)["published_hypothesis"]["qualification"], "q")
        bad_versioned = dict(versioned, schema="something-else")
        claiming_silicon = {"S5": dict(profile(), per_unit_silicon_confirmed=True)}
        for bad in ([], {"S5": "text"}, '"x"', bad_versioned, claiming_silicon, {}):
            self.run_fail(["--input", self.write(batch(dev(1))), "--hypotheses", self.write(bad)], 2, "hypotheses_invalid")

    def test_invalid_registries_fail_closed(self):
        """E01-REGISTRY-INVALID: every malformed registry is refused with exit 2 and a record index, never partly used."""
        def mut(f):
            r = ev()
            f(r)
            return registry(r)
        bad = {
            "wrong-schema": {"schema": "other", "records": []},
            "records-not-list": {"schema": rc.EVIDENCE_SCHEMA, "records": {}},
            "digest-format": mut(lambda r: r["image"].update(digest="sha256:XYZ")),
            "machine": mut(lambda r: r["claim"].update(machine="z80")),
            "endianness": mut(lambda r: r["claim"].update(endianness="middle")),
            "elf-class": mut(lambda r: r["claim"].update(elf_class=33)),
            "elf-class-bool": mut(lambda r: r["claim"].update(elf_class=True)),
            "atomics": mut(lambda r: r["claim"].update(atomic_widths=[7])),
            "join-basis": mut(lambda r: r["join"].update(join_basis="vibes")),
            "model-null-not-unmapped": mut(lambda r: r["join"].update(model_number=None)),
            "fw-lines-empty": mut(lambda r: r.update(firmware_lines=[])),
            "fw-line-shape": mut(lambda r: r.update(firmware_lines=["57"])),
            "evidence-id": mut(lambda r: r.update(evidence_id="bad id!")),
            "provenance-url": mut(lambda r: r["provenance"].update(source="https://example.invalid/x")),
            "provenance-path": mut(lambda r: r["provenance"].update(basis="see /Users/someone/file")),
            "image-name": mut(lambda r: r["image"].update(name="../etc")),
            "duplicate-id": registry(ev(), ev()),
            "not-object": {"schema": rc.EVIDENCE_SCHEMA, "records": ["x"]},
        }
        for label, obj in bad.items():
            with self.subTest(label):
                self.run_fail(["--input", self.write(batch(dev(1))), "--evidence", self.write(obj)], 2, "error[registry_invalid]")

    def test_seed_registry_in_repo_is_valid_and_does_not_overclaim(self):
        """E01-SEED-REGISTRY: the committed seed loads, carries no digest, and cannot resolve any live profile."""
        path = HERE / "image-evidence.json"
        reg, diag = rc.load_registry([str(path)])
        self.assertEqual(len(reg["records"]), 2)
        self.assertTrue(all(r["image"]["digest"] is None for r in reg["records"]))
        self.assertEqual(diag["evidence_unjoined"], 1)
        d = self.run_ok([batch(dev(1))], "--nominal-unit", "MB", "--evidence", str(path))
        self.assertEqual(one(d)["resolution"], "unresolved")
        self.assertIn(("isa_evidence_join_unattested", None), codes_of(one(d)))


# ------------------------------------------------------------------ determinism
def make_fleet(rng, size):
    models = [("S5", "Sonos Play:5", "P100", "57.23-74170", "1", "32", "32"),
              ("S1", "Sonos Play:1", "A101", "86.10-81100", "2", "128", "64"),
              ("ZB100", "Sonos Bridge", "X999", "57.23-74170", "1", "8", "8"),
              ("S12", "Sonos Play:1", "A200", "86.10-81100", "2", "256", "256")]
    revs = ("1.2.3.4-5.6", "1.2.3.4-5.7")
    recs, tick = [], 0

    def stamp():
        nonlocal tick
        tick += 1
        return f"2026-01-01T00:{tick // 60:02d}:{tick % 60:02d}Z"

    for n in range(1, size + 1):
        m, rev = rng.choice(models), rng.choice(revs)
        kw = dict(model=m[0], name=m[1], series=m[2], sw=m[3], gen=m[4], mem=m[5], flash=m[6], rev=rev)
        recs.append(dev(n, **kw, ts=stamp()))
        for _ in range(rng.choice([0, 0, 1, 2])):
            kind = rng.choice(["dup", "rename", "addr"])
            if kind == "dup":
                recs.append(dev(n, **kw, ts=stamp()))
            elif kind == "rename":
                recs.append(dev(n, **kw, room=f"Moved {n}", ts=stamp()))
            else:
                recs.append(dev(n, **kw, ip=f"192.0.2.{100 + n}", ts=stamp()))
    if rng.random() < 0.5:  # plant one conflict
        n = rng.randint(1, size)
        m = next(r for r in recs if r["fields"]["serialNum"] == ident(n)["serial"])
        bad = copy.deepcopy(m)
        bad["fields"]["seriesid"] = "ZZ999"
        bad["status"]["SeriesID"] = "ZZ999"
        bad["observed_at"] = stamp()
        recs.append(bad)
    return recs


class TestDeterminism(Base):
    def public(self, batches, *extra, evidence=None):
        d = self.run_ok(batches, *extra, evidence=evidence)
        return d

    def raw(self, batches, *extra, evidence=None):
        args = []
        for b in batches:
            args += ["--input", self.write(b)]
        if evidence is not None:
            args += ["--evidence", self.write(evidence)]
        code, out, err = self.cli(*args, *extra)
        self.assertEqual(code, 0, err)
        return out

    def test_profile_id_goldens_and_stability(self):
        """E01-ID-STABLE: profile_id matches independent shasum goldens; extra devices/firmware do not move it; revision/model do."""
        pid = lambda *recs: {e["model"]["model_number"] + e["hardware_revision"]: e["profile_id"] for e in self.run_ok([batch(*recs)])["profiles"]}
        self.assertEqual(pid(dev(1))["S51.2.3.4-5.6"], GOLDEN_S5_R6)
        self.assertEqual(pid(dev(1, rev="1.2.3.4-5.7"))["S51.2.3.4-5.7"], GOLDEN_S5_R7)
        self.assertEqual(pid(dev(1, model="S12", name="Sonos Play:1", series="A200"))["S121.2.3.4-5.6"], GOLDEN_S12_R6)
        self.assertEqual(pid(dev(1, model="Sub", name="Sonos Sub", series="A100", rev="1.8.2.5-1.2"))["SUB1.8.2.5-1.2"], GOLDEN_SUB_R)
        self.assertEqual(pid(dev(1), dev(2), dev(3))["S51.2.3.4-5.6"], GOLDEN_S5_R6)
        self.assertEqual(pid(dev(1, sw="57.99-1", status_over={"SoftwareVersion": "57.99-1"}))["S51.2.3.4-5.6"], GOLDEN_S5_R6)
        self.assertEqual(rc.profile_id_for("S5", "1.2.3.4-5.6"), GOLDEN_S5_R6)
        self.assertIsNone(rc.profile_id_for("S5", None))
        self.assertIsNone(rc.profile_id_for(None, "1.2.3.4-5.6"))

    def test_batch_and_record_order_do_not_change_output_bytes(self):
        """E01-REORDER: 40 seeded fleets x shuffled batch order and record order -> byte-identical public output."""
        for seed in range(40):
            rng = random.Random(seed)
            recs = make_fleet(rng, rng.randint(4, 14))
            k = rng.randint(1, 4)
            parts = [recs[i::k] for i in range(k)]
            parts = [p for p in parts if p]
            base = self.raw([batch(*p) for p in parts], "--nominal-unit", "MB")
            for _ in range(5):
                shuffled = [rng.sample(p, len(p)) for p in parts]
                rng.shuffle(shuffled)
                self.assertEqual(self.raw([batch(*p) for p in shuffled], "--nominal-unit", "MB"), base, f"seed={seed}")

    def test_repartitioning_batches_does_not_change_the_manifest(self):
        """E01-REPARTITION: moving the same dated records between batches changes only inputs.batches."""
        for seed in range(30):
            rng = random.Random(1000 + seed)
            recs = make_fleet(rng, rng.randint(4, 12))
            outs = []
            for k in (1, 2, 3):
                shuffled = rng.sample(recs, len(recs))
                parts = [p for p in (shuffled[i::k] for i in range(k)) if p]
                d = json.loads(self.raw([batch(*p) for p in parts], "--nominal-unit", "MB"))
                d["inputs"].pop("batches")
                outs.append(json.dumps(d, sort_keys=True))
            self.assertEqual(len(set(outs)), 1, f"seed={seed}")

    def test_cli_input_order_does_not_matter(self):
        """E01-REPLAY-ORDER: replaying the same --input files in reverse order yields identical bytes (restart-safe)."""
        a, b, c = batch(dev(1), dev(2, sw="57.22-1", ts="2026-01-01T00:00:00Z")), batch(dev(3), dev(2, ts="2026-02-01T00:00:00Z")), batch(dev(4))
        files = [self.write(x) for x in (a, b, c)]
        outs = set()
        for order in (files, files[::-1], [files[1], files[2], files[0]]):
            args = [x for f in order for x in ("--input", f)]
            code, out, err = self.cli(*args)
            self.assertEqual(code, 0, err)
            outs.add(out)
        self.assertEqual(len(outs), 1)

    def test_private_report_ordinals_do_not_depend_on_input_order(self):
        """E01-ORDINALS: run-local ordinals are assigned from canonical identifier order, not from arrival order."""
        files = [self.write(batch(dev(5), dev(2))), self.write(batch(dev(9), dev(1), dev(2, ip="192.0.2.77"))), self.write(batch(dev(3)))]
        reports = []
        for n, order in enumerate((files, files[::-1], [files[2], files[0], files[1]])):
            priv = self.dir / ".local-real" / f"r{n}.json"
            priv.parent.mkdir(exist_ok=True)
            args = [x for f in order for x in ("--input", f)]
            self.assertEqual(self.cli(*args, "--private-out", str(priv))[0], 0)
            reports.append(priv.read_text())
        self.assertEqual(len(set(reports)), 1)
        ordinals = {tuple(d["identifiers"]["serial"]): d["ordinal"] for d in json.loads(reports[0])["devices"]}
        self.assertEqual([ordinals[(ident(n)["serial"],)] for n in (1, 2, 3, 5, 9)], [1, 2, 3, 4, 5])

    def test_same_run_twice_is_identical(self):
        """E01-IDEMPOTENT: two runs over the same inputs are byte-identical (no clocks, no randomness)."""
        p = self.write(batch(dev(1), dev(2)))
        self.assertEqual(self.cli("--input", p)[1], self.cli("--input", p)[1])

    def test_conflicts_are_monotonic(self):
        """E01-CONFLICT-MONOTONIC: adding a contradicting observation never improves a device and never touches others."""
        # Attested evidence for every model in the fleet so that resolved profiles exist to be lost.
        full = registry(*[ev(f"ev-{m}", model=m, lines=("57.23", "86.10"),
                             digest="sha256:" + hashlib.sha256(m.encode()).hexdigest())
                          for m in ("S5", "S1", "ZB100", "S12")])
        for seed in range(25):
            rng = random.Random(5000 + seed)
            recs = make_fleet(rng, 8)
            clean = [r for r in recs if r["fields"]["seriesid"] != "ZZ999"]
            before = self.public([batch(*clean)], "--nominal-unit", "MB", evidence=full)
            self.assertGreater(before["summary"]["profiles_resolved"], 0, "fixture must start with resolvable profiles")
            self.assertEqual(before["conflicts"], [], seed)
            victim = rng.choice(clean)
            bad = copy.deepcopy(victim)
            bad["fields"]["modelName"] = "Sonos Other"
            bad["observed_at"] = "2026-06-01T00:00:00Z"
            after = self.public([batch(*clean, bad)], "--nominal-unit", "MB", evidence=full)
            self.assertGreaterEqual(len(after["conflicts"]), 1, seed)
            self.assertEqual(after["summary"]["devices_in_profiles"], before["summary"]["devices_in_profiles"] - 1, seed)
            self.assertLessEqual(after["summary"]["profiles_resolved"], before["summary"]["profiles_resolved"], seed)
            self.assertFalse(after["summary"]["all_resolved"], seed)

    def test_id_formats_and_uniqueness(self):
        """E01-ID-FORMAT: ids match their formats; evidence digests are unique within a manifest and bare 64-hex."""
        rng = random.Random(77)
        d = self.public([batch(*make_fleet(rng, 14))], "--nominal-unit", "MB")
        seen = set()
        for e in d["profiles"]:
            self.assertRegex(e["evidence_digest"], r"^[0-9a-f]{64}$")
            if e["profile_id"]:
                self.assertRegex(e["profile_id"], r"^bp-[0-9a-f]{16}$")
            self.assertNotIn(e["evidence_digest"], seen)
            seen.add(e["evidence_digest"])
        for c in d["conflicts"]:
            self.assertRegex(c["conflict_id"], r"^cf-[0-9a-f]{8}$")

    def test_profile_id_is_identitys_function_and_matches_independent_goldens(self):
        """E01-ID-CROSSCHECK: reconcile delegates to identity.profile_id_for; independent shasum goldens pin the formula and the canonicalisation."""
        self.assertEqual(rc.profile_id_for("S5", "1.2.3.4-5.6"), GOLDEN_S5_R6)
        self.assertEqual(rc.profile_id_for("S5", "1.2.3.4-5.7"), GOLDEN_S5_R7)
        self.assertEqual(rc.profile_id_for("S12", "1.2.3.4-5.6"), GOLDEN_S12_R6)
        self.assertEqual(rc.profile_id_for("Sub", "1.8.2.5-1.2"), GOLDEN_SUB_R, "model is canonicalised to SUB before hashing")
        self.assertEqual(rc.profile_id_for("s5", "01.002.3.4-5.6"), GOLDEN_S5_R6)
        self.assertIsNone(rc.profile_id_for("S5", None))
        self.assertIsNone(rc.profile_id_for("unknown", "1.2.3.4-5.6"), "a placeholder model gets no id")
        idm = rc._sibling("identity")
        self.assertEqual(rc.profile_id_for("S5", "1.2.3.4-5.6"), idm.profile_id_for("S5", "1.2.3.4-5.6"))

    def test_equivalent_spellings_share_one_profile(self):
        """E01-CANON-SPELLINGS: model case and zero-padded revisions canonicalise (identity.py) to one profile and the golden id, in any order."""
        a, b = dev(1, model="s5", rev="01.002.3.4-5.6"), dev(2, model="S5", rev="1.2.3.4-5.6")
        for order in ((a, b), (b, a)):
            e = one(self.run_ok([batch(*order)]))
            self.assertEqual((e["device_count"], e["profile_id"], e["model"]["model_number"], e["hardware_revision"]),
                             (2, GOLDEN_S5_R6, "S5", "1.2.3.4-5.6"))

    def test_enrich_and_reconcile_issue_the_same_profile_ids(self):
        """E01-CROSS-CALLER: enrich.py and reconcile.py agree on profile ids for reordered equivalent observations; missing revision and unknown unit stay ineligible in both."""
        recs = [dev(1), dev(2, rev="1.2.3.4-5.7"), dev(3, model="s5", rev="01.002.3.4-5.6"), dev(4, drop=("hardwareVersion", "HardwareVersion"))]

        def enrich_devices(rs, unit):
            cap = self.write(batch(*rs))
            out = self.dir / f"enriched-{self._seq}.json"
            argv = [sys.executable, "-B", "-I", str(HERE / "enrich.py"), "--devices", cap, "--out", str(out)] + (["--nominal-unit", unit] if unit else [])
            r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            self.assertIn(r.returncode, (0, 3), r.stderr)  # 3 = some device incomplete (by design here)
            return json.loads(out.read_text())["devices"]

        def reconcile_ids(rs, unit, evidence=None):
            d = self.run_ok([batch(*rs)], *(["--nominal-unit", unit] if unit else []), evidence=evidence)
            return d, collections_counter({e["profile_id"]: e["device_count"] for e in d["profiles"] if e["profile_id"]})

        rng = random.Random(11)
        base_d, base_ids = reconcile_ids(recs, "MB", registry(ev()))
        for _ in range(5):
            shuffled = rng.sample(recs, len(recs))
            enr = enrich_devices(shuffled, "MB")
            enr_ids = collections_counter(collections_counter(r["board_profile_id"] for r in enr if r["board_profile_id"]))
            _, rec_ids = reconcile_ids(shuffled, "MB", registry(ev()))
            self.assertEqual(enr_ids, rec_ids, "enrich and reconcile disagree on profile ids / device counts")
            self.assertEqual(rec_ids, base_ids, "reordering changed the ids")
        self.assertEqual(set(base_ids), {GOLDEN_S5_R6, GOLDEN_S5_R7})
        self.assertEqual(base_ids[GOLDEN_S5_R6], 2)
        # Missing revision: no id and not eligible in either tool.
        enr = {r["model_number"] + str(i): r for i, r in enumerate(enrich_devices([recs[3]], "MB"))}
        only = next(iter(enr.values()))
        self.assertIsNone(only["board_profile_id"])
        self.assertIn("hardware_revision_missing", only["reason_codes"])
        e = [x for x in base_d["profiles"] if x["hardware_revision"] is None][0]
        self.assertEqual((e["profile_id"], e["resolution"], e["activation_eligible"]), (None, "unresolved", False))
        self.assertIn(("hardware_revision_absent", None), codes_of(e))
        # Unknown unit: both tools keep it incomplete / ineligible even with attested evidence.
        enr_nounit = enrich_devices([recs[0]], None)[0]
        self.assertEqual(enr_nounit["status"], "enriched_incomplete")
        self.assertIn("memory_unit_unknown", enr_nounit["reason_codes"])
        d_nounit = self.run_ok([batch(recs[0])], evidence=registry(ev()))
        self.assertEqual((one(d_nounit)["resolution"], one(d_nounit)["activation_eligible"]), ("unresolved", False))
        self.assertIn(("nominal_size_unit_unknown", "memory"), codes_of(one(d_nounit)))

    def test_missing_shared_module_fails_closed(self):
        """E01-IDENTITY-REQUIRED: without identity.py beside it the tool refuses (exit 2, no output) instead of using a private fallback."""
        lone = self.dir / "lone"
        lone.mkdir()
        shutil.copy(HERE / "reconcile.py", lone / "reconcile.py")
        r = subprocess.run([sys.executable, "-B", "-I", str(lone / "reconcile.py"), "--input", self.write(batch(dev(1)))],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("error[shared_module_missing]", r.stderr)
        self.assertEqual(r.stdout, "")


# ----------------------------------------------------------------- sanitisation
class TestSanitisation(Base):
    def test_public_json_and_markdown_contain_no_private_values(self):
        """E01-PUBLIC-SANITISED: serial/MAC/UDN/IP/room/household never appear in json or md output (checked independently)."""
        recs = [dev(n) for n in range(1, 6)] + [dev(2, room="Moved", ip="192.0.2.77")]
        for fmt in ("json", "md"):
            code, out, err = self.cli("--input", self.write(batch(*recs)), "--format", fmt)
            self.assertEqual(code, 0, err)
            low = out.lower()
            for m in SYNTHETIC_MARKERS:
                self.assertNotIn(m, low, (fmt, m))
        self.assertIn("| Model |", out)

    def test_markdown_is_derived_from_the_sanitised_document(self):
        """E01-MD-RENDER: the md table states resolution and blocking reasons per profile."""
        code, out, _ = self.cli("--input", self.write(batch(dev(1), dev(2, rev="1.2.3.4-5.7"))), "--format", "md")
        self.assertEqual(code, 0)
        self.assertEqual(out.count("\n| S5 |"), 2)
        self.assertIn("nominal_size_unit_unknown:memory", out)
        self.assertIn("32 (unit unknown) / 32 (unit unknown)", out)

    def test_leak_guard_rejects_identifier_in_a_public_field(self):
        """E01-LEAK-GUARD: a serial smuggled into modelName stops the run (exit 4), writes nothing, and is not echoed."""
        out_path = self.dir / "public.json"
        argv = ["--input", self.write(batch(dev(1, name=ident(1)["serial"], over={"modelName": ident(1)["serial"]}))), "--out", str(out_path)]
        code, out, err = self.cli(*argv)
        self.assertEqual(code, 4)
        self.assertIn("error[leak_guard]", err)
        self.assertIn("nothing was written", err)
        self.assertFalse(out_path.exists())
        self.assertEqual(out, "")
        self.assertNotIn("00-00-5e", err.lower())

    def test_leak_guard_rejects_each_identifier_class_in_each_public_field(self):
        """E01-LEAK-GUARD-FIELDS: MAC, IP and UDN values are caught wherever they would be emitted."""
        i = ident(1)
        # (fields key, status key or None, smuggled value).  Status is overridden too so the
        # value is consistent across sources, is emitted, and the guard (not conflict handling) must stop it.
        cases = [("seriesid", "SeriesID", i["mac"]), ("variant", "Variant", i["ip"]),
                 ("modelName", None, i["mac"].replace(":", ""))]
        for field, skey, value in cases:
            with self.subTest(field):
                rec = dev(1, over={field: value}, status_over={skey: value} if skey else {})
                code, out, err = self.cli("--input", self.write(batch(rec)))
                self.assertEqual(code, 4, (field, err))
                self.assertEqual(out, "")

    def test_shared_scanner_is_a_second_independent_gate(self):
        """E01-LEAK-SHARED: a long hex run the local guard has no rule for is still stopped by identity.find_private_identifiers (exit 4)."""
        out_path = self.dir / "public.json"
        code, out, err = self.cli("--input", self.write(batch(dev(1, over={"modelName": "ABCDEF0123456789ABCDEF"}))), "--out", str(out_path))
        self.assertEqual(code, 4, err)
        self.assertIn("shared identity scanner", err)
        self.assertFalse(out_path.exists())
        self.assertNotIn("abcdef0123456789", err.lower())

    def test_local_name_guard_catches_what_the_shared_scanner_cannot(self):
        """E01-LEAK-NAME: a room name smuggled into operator-supplied public text is stopped by the local exact-name guard (identity's scanner has no name list)."""
        out_path = self.dir / "public.json"
        hyp = self.write({"S5": profile(qualification="Test Room 1")})
        code, out, err = self.cli("--input", self.write(batch(dev(1))), "--hypotheses", hyp, "--out", str(out_path))
        self.assertEqual(code, 4, err)
        self.assertIn("kind name", err)
        self.assertFalse(out_path.exists())
        self.assertNotIn("test room", err.lower())

    def test_room_named_like_the_model_is_not_a_leak(self):
        """E01-LEAK-NAME-EXEMPT: a room whose name equals the (public) model name is not flagged; other names still are."""
        code, _, err = self.cli("--input", self.write(batch(dev(1, room="Sonos Play:5"))))
        self.assertEqual(code, 0, err)

    def test_backstop_patterns_and_revision_exemption(self):
        """E01-LEAK-PATTERNS: address/URL/path shapes are caught even for unknown values; hardware_revision may look like an IPv4."""
        def kinds(doc):
            return {k for k, _ in rc.scan_public(doc, set(), set())}
        base = {"profiles": [{"model": {}, "hardware_revision": "1.2.3.4-5.6"}]}
        self.assertEqual(kinds(base), set())
        base["profiles"][0]["hardware_revision"] = "1.2.3.4"
        self.assertEqual(kinds(base), set(), "revision field is exempt from the ipv4 backstop")
        for kind, value in (("ipv4", "host 10.0.0.9 here"), ("mac", "00:11:22:33:44:55"), ("mac", "00-11-22-33-44-55:3"),
                            ("rincon", "RINCON_000E58A1B2C301400"), ("uuid", "uuid:abc"), ("url", "http://x.invalid/"),
                            ("abs_path", "see /Users/someone/x")):
            doc = {"profiles": [{"model": {"model_name": value}, "hardware_revision": "1.2.3.4-5.6"}]}
            self.assertIn(kind, kinds(doc), value)
        self.assertEqual(kinds({"profiles": [{"model": {"model_name": "57.23-74170"}}]}), set())
        self.assertIn("ipv4", kinds({"x": "1.2.3.4"}))
        findings = rc.scan_public({"a": ["10.0.0.9"]}, set(), set())
        self.assertEqual(findings, [("ipv4", "a[0]")], "path reported, value not")

    def test_scan_reports_names_by_exact_match_and_ids_by_substring(self):
        """E01-LEAK-CLASSES: names use exact match, identifiers substring; short values are ignored."""
        doc = {"m": "xx SERIAL-123456 xx", "n": "kitchen", "o": "my kitchen sink"}
        f = rc.scan_public(doc, {"serial-123456", "ab"}, {"kitchen"})
        self.assertEqual(sorted(f), [("identifier", "m"), ("name", "n")])

    def test_errors_never_echo_input_content(self):
        """E01-ERRORS-NO-ECHO: parse/shape failures cite offsets and labels only, never file content."""
        marker = "PRIVATE-MARKER-9f3a"
        bad_inputs = {
            "json-syntax": '{"devices": [{"fields": {"serialNum": "%s"' % marker,
            "dup-key": '{"devices": [], "devices": [], "x": "%s"}' % marker,
            "shape": json.dumps({"nope": marker}),
            "not-utf8": b"\xff\xfe" + marker.encode(),
            "xml-doctype": '<!DOCTYPE a [<!ENTITY e "%s">]><root/>' % marker,
            "xml-unclosed": "<root><device><serialNum>%s</serialNum>" % marker,
            "xml-no-device": "<root><x>%s</x></root>" % marker,
            "deep": "[" * 100000 + marker,
        }
        for label, content in bad_inputs.items():
            with self.subTest(label):
                p = self.dir / f"bad-{label}.json"
                p.write_bytes(content if isinstance(content, bytes) else content.encode())
                code, out, err = self.cli("--input", str(p))
                self.assertEqual(code, 2, (label, err))
                self.assertNotIn(marker.lower(), err.lower())
                self.assertEqual(out, "")

    def test_internal_errors_do_not_leak_exception_text(self):
        """E01-INTERNAL-NO-ECHO: an unexpected exception exits 70 with class name and frames only."""
        p = self.write(batch(dev(1)))
        with mock.patch.object(rc, "reconcile", side_effect=ValueError("PRIVATE-MARKER-9f3a")):
            code, out, err = self.cli("--input", p)
        self.assertEqual(code, 70)
        self.assertIn("error[internal]: unexpected ValueError", err)
        self.assertNotIn("private-marker", err.lower())
        self.assertEqual(out, "")

    def test_unknown_input_keys_and_legacy_profile_blocks_are_ignored(self):
        """E01-IGNORE-UNKNOWN: unrecognised keys (incl. the old published_hardware_profile block) never reach output."""
        rec = dev(1)
        rec["published_hardware_profile"] = {"cpu": "UNKNOWNCPU-MARKER"}
        rec["fields"]["somethingElse"] = "UNKNOWN-KEY-MARKER"
        rec["fields"]["modelDescription"] = "Sonos Play:5 desc"
        text = json.dumps(self.run_ok([batch(rec)])).lower()
        self.assertNotIn("unknowncpu-marker", text)
        self.assertNotIn("unknown-key-marker", text)

    def test_private_report_holds_identifiers_with_run_local_ordinals(self):
        """E01-PRIVATE-REPORT: identifiers exist only in the private report; ordinals are run-local; file mode is 0600."""
        priv = self.dir / ".local-real" / "report.json"
        priv.parent.mkdir()
        d = self.run_ok([batch(dev(1), dev(2), dev(2))], "--private-out", str(priv))
        rep = json.loads(priv.read_text())
        self.assertEqual(rep["schema"], rc.PRIVATE_SCHEMA)
        self.assertEqual([x["ordinal"] for x in rep["devices"]], [1, 2])
        self.assertEqual(rep["devices"][0]["identifiers"]["serial"], [ident(1)["serial"].upper()])
        self.assertIn("run-local", rep["ordinal_scope"])
        self.assertEqual(rep["devices"][1]["duplicate_observations"], 1)
        self.assertEqual(os.stat(priv).st_mode & 0o777, 0o600)
        self.assertNotIn(ident(1)["serial"].lower(), json.dumps(d).lower())

    def test_private_report_location_is_restricted(self):
        """E01-PRIVATE-LOCATION: --private-out outside a git-ignored location is refused (exit 5); allowed spellings pass."""
        p = self.write(batch(dev(1)))
        bad = self.dir / "report.json"
        code, _, err = self.cli("--input", p, "--private-out", str(bad))
        self.assertEqual(code, 5)
        self.assertIn("private_out_not_ignored", err)
        self.assertFalse(bad.exists())
        (self.dir / ".local-real").mkdir()
        for good in (self.dir / "x.local.json", self.dir / ".local-real" / "y.json"):
            self.assertEqual(self.cli("--input", p, "--private-out", str(good))[0], 0, good)
            self.assertTrue(good.exists())


# ------------------------------------------------------------------ output safety
class TestOutputSafety(Base):
    def test_existing_output_is_not_clobbered(self):
        """E01-OUT-NOCLOBBER: an existing --out is refused (exit 5) and left intact; --overwrite replaces it."""
        p = self.write(batch(dev(1)))
        out = self.dir / "m.json"
        out.write_text("OLD")
        code, _, err = self.cli("--input", p, "--out", str(out))
        self.assertEqual((code, out.read_text()), (5, "OLD"))
        self.assertIn("output_exists", err)
        self.assertEqual(self.cli("--input", p, "--out", str(out), "--overwrite")[0], 0)
        self.assertEqual(json.loads(out.read_text())["schema"], rc.MANIFEST_SCHEMA)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o644)
        # The refusal is planned before any input is read: a missing input must not mask it.
        out.write_text("OLD")
        code, _, err = self.cli("--input", str(self.dir / "absent.json"), "--out", str(out))
        self.assertEqual((code, out.read_text()), (5, "OLD"))
        self.assertIn("output_exists", err)

    def test_output_may_never_be_an_input(self):
        """E01-OUT-NOT-INPUT: --out/--private-out equal to any input is refused, even with --overwrite (old script did this)."""
        p = self.write(batch(dev(1)))
        reg = self.write(registry(ev()))
        before = Path(p).read_bytes()
        for flag, target in (("--out", p), ("--private-out", p), ("--out", reg)):
            code, _, err = self.cli("--input", p, "--evidence", reg, flag, target, "--overwrite")
            self.assertEqual(code, 5, (flag, err))
            self.assertIn("output_collides_with_input", err)
        self.assertEqual(Path(p).read_bytes(), before)

    def test_output_path_problems(self):
        """E01-OUT-PATHS: missing parent, directory target and identical out/private paths are refused with exit 5."""
        p = self.write(batch(dev(1)))
        (self.dir / ".local-real").mkdir()
        same = str(self.dir / ".local-real" / "same.json")
        for argv, needle in (
            (["--out", str(self.dir / "nope" / "m.json")], "output_parent_missing"),
            (["--out", str(self.dir)], "output_is_directory"),
            (["--out", same, "--private-out", same], "output_collision"),
        ):
            code, _, err = self.cli("--input", p, *argv)
            self.assertEqual(code, 5, argv)
            self.assertIn(needle, err)

    def test_interrupt_during_write_leaves_no_partial_file_and_restart_works(self):
        """E01-WRITE-INTERRUPT: Ctrl-C mid-write exits 130, leaves neither output nor temp file; a rerun succeeds (cancellation + restart)."""
        p = self.write(batch(dev(1)))
        out = self.dir / "m.json"
        before = set(os.listdir(self.dir))
        with mock.patch.object(rc.os, "link", side_effect=KeyboardInterrupt):
            code, _, err = self.cli("--input", p, "--out", str(out))
        self.assertEqual(code, 130)
        self.assertIn("error[interrupted]", err)
        self.assertEqual(set(os.listdir(self.dir)), before)
        self.assertEqual(self.cli("--input", p, "--out", str(out))[0], 0)
        self.assertTrue(out.exists())

    def test_failed_overwrite_keeps_previous_output(self):
        """E01-WRITE-FAILURE: if the final rename fails, the previous file is intact and no temp file remains."""
        p = self.write(batch(dev(1)))
        out = self.dir / "m.json"
        out.write_text("PREVIOUS")
        before = set(os.listdir(self.dir))
        with mock.patch.object(rc.os, "replace", side_effect=OSError("disk full")):
            code, _, err = self.cli("--input", p, "--out", str(out), "--overwrite")
        self.assertEqual(code, 70)
        self.assertEqual(out.read_text(), "PREVIOUS")
        self.assertEqual(set(os.listdir(self.dir)), before)

    def test_leak_guard_failure_writes_nothing_even_for_private_report(self):
        """E01-LEAK-ATOMIC: when the guard trips, neither the public nor the private file is created."""
        priv = self.dir / ".local-real" / "r.json"
        priv.parent.mkdir()
        out = self.dir / "m.json"
        p = self.write(batch(dev(1, over={"modelName": ident(1)["serial"]})))
        code, _, _ = self.cli("--input", p, "--out", str(out), "--private-out", str(priv))
        self.assertEqual(code, 4)
        self.assertFalse(out.exists())
        self.assertFalse(priv.exists())


# ------------------------------------------------------------------------ inputs
class TestInputs(Base):
    def test_size_limit_boundary(self):
        """E01-BOUNDS-SIZE: a file of exactly the limit is read; one byte more is refused."""
        body = '{"devices": []}'
        with mock.patch.object(rc, "MAX_INPUT_BYTES", 200):
            ok = self.write(body + " " * (200 - len(body)))
            over = self.write(body + " " * (201 - len(body)))
            self.assertEqual(self.cli("--input", ok)[0], 0)
            self.run_fail(["--input", over], 2, "input_too_large")

    def test_record_and_batch_count_limits(self):
        """E01-BOUNDS-COUNT: record-per-batch and batch-count limits are enforced at the boundary."""
        with mock.patch.object(rc, "MAX_RECORDS_PER_BATCH", 3):
            self.assertEqual(self.cli("--input", self.write(batch(dev(1), dev(2), dev(3))))[0], 0)
            self.run_fail(["--input", self.write(batch(dev(1), dev(2), dev(3), dev(4)))], 2, "batch_too_many_records")
        with mock.patch.object(rc, "MAX_BATCHES", 2):
            files = [self.write(batch(dev(n))) for n in (1, 2, 3)]
            self.assertEqual(self.cli("--input", files[0], "--input", files[1])[0], 0)
            self.run_fail([x for f in files for x in ("--input", f)], 2, "usage")

    def test_missing_and_unreadable_inputs(self):
        """E01-INPUT-MISSING: a missing file is a clean exit-2 error that does not print the path's directory contents."""
        self.run_fail(["--input", str(self.dir / "absent.json")], 2, "input_unreadable")
        self.run_fail(["--input", self.write(batch(dev(1))), "--evidence", str(self.dir / "absent-ev.json")], 2, "input_unreadable")

    def test_malformed_records_are_skipped_and_counted(self):
        """E01-RECORD-MALFORMED: bad records are skipped with a count; good records in the same batch still count."""
        bad = ["not a dict", {"fields": "nope"}, {"fields": {"serialNum": {"nested": 1}}},
               {"fields": {"modelNumber": "S5", "memory": ["x"]}}, {"fields": {"modelNumber": "x" * 2000}},
               {"fields": {"modelNumber": "S5"}, "status": ["not", "a", "map"]}, {"fields": {"modelNumber": "S5"}, "url": 5}]
        d = self.run_ok([batch(dev(1), *bad)])
        self.assertEqual(d["diagnostics"]["record_malformed"], len(bad))
        self.assertEqual((d["summary"]["observations"], d["summary"]["identity_components"]), (1, 1))

    def test_error_only_scan_records_are_skipped(self):
        """E01-RECORD-ERROR-ONLY: scan.py failure placeholders are counted, not treated as devices."""
        d = self.run_ok([batch(dev(1), {"url": "http://192.0.2.50:1400/x", "error": "timed out"})])
        self.assertEqual((d["diagnostics"]["record_error_only"], d["summary"]["observations"]), (1, 1))

    def test_bad_timestamps_are_diagnosed_and_treated_as_undated(self):
        """E01-TS-INVALID: non-ISO or timezone-less observed_at is info-only and leaves the record undated."""
        d = self.run_ok([batch(dev(1, ts="2026-01-01T00:00:00"), dev(2, ts=12345), observed_at="yesterday")])
        self.assertEqual(d["diagnostics"]["observed_at_invalid"], 3)
        self.assertEqual(d["observation_window"], {"earliest": None, "latest": None})

    def test_observation_window_is_utc_min_max(self):
        """E01-WINDOW: earliest/latest are normalised to UTC regardless of the input offset."""
        d = self.run_ok([batch(dev(1, ts="2026-01-01T02:00:00+02:00"), dev(2, ts="2026-01-02T00:00:00Z"))])
        self.assertEqual(d["observation_window"], {"earliest": "2026-01-01T00:00:00.000000Z", "latest": "2026-01-02T00:00:00.000000Z"})

    def test_description_xml_input_is_parsed_without_network(self):
        """E01-XML-INPUT: a raw device_description.xml merges with the equivalent JSON record (nested sub-device UDNs ignored)."""
        i = ident(1)
        xml = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType><friendlyName>{i['ip']} - Sonos Play:5</friendlyName>
<modelNumber>S5</modelNumber><modelName>Sonos Play:5</modelName><softwareVersion>57.23-74170</softwareVersion><swGen>1</swGen>
<hardwareVersion>1.2.3.4-5.6</hardwareVersion><serialNum>{i['serial']}</serialNum><MACAddress>{i['mac']}</MACAddress>
<UDN>uuid:RINCON_00005E00530101400</UDN><seriesid>P100</seriesid><variant>0</variant><memory>32</memory><flash>32</flash>
<deviceList><device><UDN>uuid:RINCON_00005E00530101400_MR</UDN><modelName>nested</modelName></device></deviceList></device></root>"""
        p = self.write(xml, "d.xml")
        code, out, err = self.cli("--input", p)
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        e = one(doc)
        self.assertEqual((e["profile_id"], e["model"]["model_name"], doc["summary"]["identity_components"]), (GOLDEN_S5_R6, "Sonos Play:5", 1))
        self.assertEqual(e["provenance"]["model_number"]["sources"], ["device_description"])
        merged = self.run_ok([batch(dev(1))], "--input", p)
        self.assertEqual((merged["summary"]["identity_components"], merged["summary"]["observations"]), (1, 2))

    def test_xml_hazards_are_refused(self):
        """E01-XML-HAZARDS: DOCTYPE/ENTITY, truncated XML, missing device and conflicting repeated fields exit 2."""
        cases = {
            "doctype": '<!DOCTYPE r [<!ENTITY a "b">]><root><device><serialNum>x</serialNum></device></root>',
            "unclosed": "<root><device>",
            "no-device": "<root/>",
            "dup-field": "<root><device><serialNum>a</serialNum><serialNum>b</serialNum></device></root>",
        }
        for label, text in cases.items():
            with self.subTest(label):
                code, _, err = self.cli("--input", self.write(text, f"{label}.xml"))
                self.assertEqual(code, 2, err)

    def test_incomplete_results_exit_3_by_default(self):
        """E01-INCOMPLETE-EXIT: unresolved, conflicted, unattributed or empty results exit 3 (manifest still written); only a fully resolved fleet exits 0; --allow-incomplete opts out."""
        p = self.write(batch(dev(1)))
        reg = self.write(registry(ev()))
        full = ["--input", p, "--evidence", reg, "--nominal-unit", "MB"]
        self.assertEqual(self.cli(*full, default_exit=True)[0], 0)
        code, out, _ = self.cli("--input", p, default_exit=True)
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["summary"]["profiles_unresolved"], 1, "the manifest is still printed")
        self.assertEqual(self.cli("--input", p)[0], 0, "--allow-incomplete")
        bad = self.write(batch(dev(1), dev(1, series="A999", status_over={"SeriesID": "A999"})))
        self.assertEqual(self.cli("--input", bad, "--evidence", reg, "--nominal-unit", "MB", default_exit=True)[0], 3)
        unattributed = self.write(batch(dev(1), dev(2, drop=("serialNum", "SerialNumber", "MACAddress", "UDN"))))
        self.assertEqual(self.cli("--input", unattributed, "--evidence", reg, "--nominal-unit", "MB", default_exit=True)[0], 3)
        self.assertEqual(self.cli("--input", self.write(batch()), default_exit=True)[0], 3, "nothing to resolve is not success")
        out_path = self.dir / "m.json"
        self.assertEqual(self.cli("--input", p, "--out", str(out_path), default_exit=True)[0], 3)
        self.assertTrue(out_path.exists(), "incomplete results are still published, with exit 3")

    def test_reason_code_catalog(self):
        """E01-REASON-CATALOG: --list-reason-codes prints every code with a valid severity and summary."""
        code, out, _ = self.cli("--list-reason-codes")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["schema"], rc.REASONS_SCHEMA)
        self.assertEqual({c["code"] for c in doc["codes"]}, set(rc.REASONS))
        for c in doc["codes"]:
            self.assertIn(c["severity"], ("conflict", "blocking", "info"))
            self.assertTrue(c["summary"])

    def test_contract_document_lists_every_reason_code(self):
        """E01-DOC-SYNC: docs/contracts/e01.md documents every reason code the tool can emit."""
        doc = REPO / "docs" / "contracts" / "e01.md"
        self.assertTrue(doc.exists(), "docs/contracts/e01.md is required by the bead")
        text = doc.read_text()
        missing = [c for c in rc.REASONS if f"`{c}`" not in text]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
