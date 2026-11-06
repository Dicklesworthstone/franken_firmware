"""Checks on the SSDP model, its hand-written vectors and their mapping (G03 slice 2, bead ffw-xvv), run with the other G03 checks.

They establish that the independent model (ssdp_reference.py) passes every vector, that each deliberately broken variant is caught after the
unbroken one is shown to pass, that every SSDP invariant in cases.json names vector groups and Rust tests that exist and every Rust test in
fsonos/ssdp.rs is claimed, and that the model's constants and service list agree with the Rust text and the SOAP service table. They do not run
the Rust code."""
import dataclasses
import ipaddress
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ssdp_reference as ssdp  # noqa: E402

ROOT = ssdp.ROOT
SSDP_RS = ROOT / "crates" / "franken-control" / "src" / "fsonos" / "ssdp.rs"
SOAP_RS = ROOT / "crates" / "franken-control" / "src" / "fsonos" / "soap.rs"
CASES = Path(__file__).resolve().parent / "cases.json"
CONTRACT = ROOT / "docs" / "contracts" / "g03.md"
GROUPS = ("parse", "search", "response", "notify_alive", "notify_byebye", "description", "description_hostile", "delay", "device_reject")


def rust_tests():
    return set(re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn (\w+)", SSDP_RS.read_text(encoding="utf-8")))


def rust_const(name):
    match = re.search(r"pub const %s: [\w&' \[\];]+ = ([^;]+);" % name, SSDP_RS.read_text(encoding="utf-8"))
    assert match, name
    value = match.group(1).strip()
    return value if value.startswith('"') else value.replace("_", "")


def ssdp_invariants():
    return [i for i in json.loads(CASES.read_text(encoding="utf-8"))["invariants"] if i["id"].startswith("G03-S")]


class Baseline(unittest.TestCase):
    def test_the_unbroken_model_passes_every_ssdp_vector(self):
        self.assertEqual(ssdp.check_all(), [])

    def test_the_vector_file_is_not_hollow_and_its_ids_are_unique(self):
        v = ssdp.load()
        for group in GROUPS:
            self.assertIn(group, v)
        ids = [c["id"] for g in ("parse", "search", "device_reject") for c in v[g]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(v["parse"]), 45)
        self.assertGreaterEqual(len(v["search"]), 15)
        self.assertEqual(len(v["notify_alive"]), 7)
        self.assertEqual(len(v["notify_byebye"]), 7)
        self.assertEqual(len(v["search"][0]["expect"]), 7)
        # both the permitted behaviour and the refusals are present in the parse group
        kinds = {next(iter(c["expect"])) for c in v["parse"]}
        self.assertEqual(kinds, {"search", "other", "err"})


class Defects(unittest.TestCase):
    def test_every_deliberately_broken_variant_is_caught(self):
        self.assertEqual(ssdp.check_all(), [], "the unbroken model must pass first")
        missed = []
        for field in dataclasses.fields(ssdp.Options):
            options = ssdp.Options(**{field.name: True})
            if not ssdp.check_all(options):
                missed.append(field.name)
        self.assertEqual(missed, [], "a defect no vector catches is a vector that does not bite")

    def test_there_are_enough_distinct_defects_to_mean_something(self):
        self.assertGreaterEqual(len(dataclasses.fields(ssdp.Options)), 15)


class Invariants(unittest.TestCase):
    def test_every_ssdp_invariant_names_existing_groups_and_rust_tests(self):
        rows = ssdp_invariants()
        self.assertGreaterEqual(len(rows), 6)
        have = rust_tests()
        seen = set()
        for inv in rows:
            self.assertNotIn(inv["id"], seen)
            seen.add(inv["id"])
            self.assertTrue(inv["rust_tests"] and inv["ssdp_vectors"], f"{inv['id']} checks nothing")
            self.assertEqual(inv["vectors"], [], "the shared vectors file has no SSDP ids; SSDP groups are named in ssdp_vectors")
            for group in inv["ssdp_vectors"]:
                self.assertIn(group, GROUPS, f"{inv['id']}: no vector group {group}")
            for name in inv["rust_tests"]:
                module, _, function = name.partition("::")
                self.assertEqual(module, "ssdp", name)
                self.assertIn(function, have, f"{inv['id']}: no Rust test {name}")

    def test_every_vector_group_and_every_rust_test_is_claimed_by_an_invariant(self):
        rows = ssdp_invariants()
        claimed_groups = {g for inv in rows for g in inv["ssdp_vectors"]}
        self.assertEqual(claimed_groups, set(GROUPS))
        claimed_tests = {n.partition("::")[2] for inv in rows for n in inv["rust_tests"]}
        self.assertEqual(rust_tests() - claimed_tests, set(), "a Rust test in ssdp.rs that no invariant mentions")


class Contract(unittest.TestCase):
    def test_the_models_constants_are_the_rust_constants(self):
        pairs = {"MAX_DATAGRAM": ssdp.MAX_DATAGRAM, "MAX_LINE": ssdp.MAX_LINE, "MAX_HEADERS": ssdp.MAX_HEADERS, "MAX_TARGET": ssdp.MAX_TARGET,
                 "MAX_MX": ssdp.MAX_MX, "MAX_MX_ACCEPTED": ssdp.MAX_MX_ACCEPTED, "SSDP_PORT": ssdp.PORT}
        for name, value in pairs.items():
            self.assertEqual(int(rust_const(name)), value, name)
        for name, value in {"MULTICAST_ADDR": ssdp.MULTICAST, "DEVICE_TYPE": ssdp.DEVICE_TYPE, "SERVER": ssdp.SERVER,
                            "DESCRIPTION_PATH": ssdp.DESCRIPTION_PATH}.items():
            self.assertEqual(rust_const(name).strip('"'), value, name)
        self.assertEqual((int(rust_const("MIN_MAX_AGE")), int(rust_const("MAX_MAX_AGE")), int(rust_const("MAX_NAME_CHARS"))), (1800, 86400, 64))

    def test_the_served_services_are_exactly_the_four_and_never_the_retired_one(self):
        block = re.search(r"pub const SERVICES: \[Service; \d+\] = \[(.*?)\];", SSDP_RS.read_text(encoding="utf-8"), re.S).group(1)
        variants = re.findall(r"Service::(\w+)", block)
        self.assertEqual(variants, ["RenderingControl", "GroupRenderingControl", "AvTransport", "ZoneGroupTopology"])
        soap = SOAP_RS.read_text(encoding="utf-8")
        for name, urn, control, event in ssdp.SERVED + [ssdp.RETIRED]:
            for literal in (urn, control, event):
                self.assertIn('"%s"' % literal, soap, literal)
        self.assertNotIn("ContentDirectory", {n for n, _, _, _ in ssdp.SERVED})
        v = ssdp.load()
        self.assertNotIn("ContentDirectory", v["description"])
        for case in v["notify_alive"] + v["notify_byebye"]:
            self.assertNotIn("ContentDirectory", json.dumps(case))

    def test_nothing_in_the_vectors_is_site_data(self):
        text = ssdp.VECTORS.read_text(encoding="utf-8")
        allowed = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("239.255.255.250/32")]
        for literal in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            address = ipaddress.ip_address(literal)
            self.assertTrue(any(address in net for net in allowed), f"{literal} is not a documentation or protocol address")
        self.assertNotRegex(text, r"RINCON_")
        self.assertNotRegex(text, r"(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b")

    def test_the_contract_states_the_slice_and_what_it_does_not_claim(self):
        doc = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("## 13. SSDP discovery and the device description", doc)
        section = " ".join(doc.split("## 13. SSDP discovery and the device description")[1].split())
        for phrase in ("ContentDirectory", "no `SCPDURL`", "was run against a real controller", "the `fsonos` client accepts this description",
                       "IPv6 is not supported", "unicast `M-SEARCH` without an `MX` is refused"):
            self.assertIn(phrase, section)
        self.assertNotIn("**not started** (slice 2)", doc, "the status table still says SSDP is not started")


if __name__ == "__main__":
    unittest.main()
