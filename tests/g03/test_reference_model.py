"""Checks on the G03 reference model, its vectors and the contract (bead ffw-xvv), run by scripts/e2e/g03.

They establish that the golden vectors agree with an independently built model, that the model can
fail (every deliberately broken variant is caught, after the unbroken one is shown to pass), that each
invariant maps to vectors and Rust tests that exist, that the contract, the Rust action matrix and the
usage measurement agree, and that nothing in the adapter opens a socket or reads a clock. They do not
run the Rust code.
"""

import dataclasses
import ipaddress
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_usage as usage  # noqa: E402
import reference as ref  # noqa: E402

FSONOS = ref.ROOT / "crates" / "franken-control" / "src" / "fsonos"
CONTRACT = ref.ROOT / "docs" / "contracts" / "g03.md"
CASES = Path(__file__).resolve().parent / "cases.json"


def all_vector_ids(vectors):
    ids = [v["id"] for key in ("escape", "soap", "plan") for v in vectors[key]]
    ids += [s["id"] for s in vectors["gena"]["scenarios"]]
    return ids


def rust_test_names(module):
    text = (FSONOS / f"{module}.rs").read_text(encoding="utf-8")
    return set(re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn (\w+)", text))


def rust_matrix():
    """The rows of MATRIX in actions.rs: (service, name, sites, status, access)."""
    text = (FSONOS / "actions.rs").read_text(encoding="utf-8")
    block = text[text.index("pub const MATRIX"):text.index("/// The matrix row for")]
    rows = re.findall(r'row\(\s*(\w+),\s*"(\w+)",\s*(\d+),\s*(\w+),\s*(\w+),', block)
    names = {"AvTransport": "AVTransport"}
    return [(names.get(s, s), n, int(c), st, ac) for s, n, c, st, ac in rows]


def production_of(text):
    """The file up to its `mod tests`. Small test-only items before it (the planted adapter defects) are
    deliberately inside the checked part: they are in the test binary, but they are not tests."""
    return text.split("#[cfg(test)]\nmod tests")[0]


class Baseline(unittest.TestCase):
    def test_the_unbroken_model_passes_every_vector(self):
        failures = ref.check_all(ref.Options())
        self.assertEqual(failures, [], failures)

    def test_vector_ids_are_unique_and_the_file_is_not_hollow(self):
        vectors = ref.load()
        ids = all_vector_ids(vectors)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(vectors["soap"]), 30)
        self.assertGreaterEqual(len(vectors["plan"]), 50)
        self.assertGreaterEqual(len(vectors["gena"]["scenarios"]), 12)


class Mutants(unittest.TestCase):
    """Each deliberate defect must be caught by at least one vector. The unbroken model is checked first
    (Baseline), so a catch here means the defect was seen, not that the model was already wrong."""

    def test_every_option_is_exercised_and_caught(self):
        vectors = ref.load()
        self.assertEqual(ref.check_all(ref.Options(), vectors), [], "the baseline must be green first")
        escaped = []
        for field in dataclasses.fields(ref.Options):
            with self.subTest(defect=field.name):
                broken = ref.Options(**{field.name: True})
                failures = ref.check_all(broken, vectors)
                if not failures:
                    escaped.append(field.name)
                self.assertTrue(failures, f"no vector catches `{field.name}`")
        self.assertEqual(escaped, [])

    def test_a_defect_fails_only_where_it_should(self):
        # A defect in the SEQ counter must not disturb the XML or argument vectors.
        vectors = ref.load()
        failures = ref.check_all(ref.Options(seq_wraps_to_zero=True), vectors)
        self.assertEqual({f[0] for f in failures}, {"gena-seq-wraps-to-one-never-zero"})
        failures = ref.check_all(ref.Options(clamp_volume=True), vectors)
        self.assertTrue(all(f[0].startswith("plan-") for f in failures), failures)

    def test_refusing_second_infinite_fails_only_its_own_scenario_and_the_bare_word_still_passes(self):
        # The defect as it shipped: only the bare word `infinite` was an unbounded request, so the UPnP spelling
        # `Second-infinite` was a 400. The scenario written for it must be the one that fails, and the older
        # scenario that uses the bare word must keep passing under the same defect.
        vectors = ref.load()
        failures = ref.check_all(ref.Options(second_infinite_refused=True), vectors)
        self.assertEqual({f[0] for f in failures}, {"gena-second-infinite-is-the-upnp-unbounded-request"})
        self.assertEqual(ref.check_all(ref.Options(), vectors), [], "the fixed model passes all of them")

    def test_unicode_case_folding_of_the_word_is_caught_by_the_second_infinite_scenario_alone(self):
        # Python's (?i:) folds dotless i and dotted I to `i`, so a model written with it accepts `Second-\u0131nfinite`, which the
        # Rust (`eq_ignore_ascii_case`) refuses. The shared-rule trap: the model must be as strict as the code.
        vectors = ref.load()
        failures = ref.check_all(ref.Options(unicode_fold_infinite=True), vectors)
        self.assertEqual({f[0] for f in failures}, {"gena-second-infinite-is-the-upnp-unbounded-request"})

    def test_a_refusal_that_uses_up_a_sid_is_caught_by_the_second_infinite_scenario_alone(self):
        vectors = ref.load()
        failures = ref.check_all(ref.Options(sid_taken_before_timeout=True), vectors)
        self.assertEqual({f[0] for f in failures}, {"gena-second-infinite-is-the-upnp-unbounded-request"})


class Invariants(unittest.TestCase):
    def test_every_invariant_names_existing_vectors_and_rust_tests(self):
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        ids = set(all_vector_ids(ref.load()))
        tests = {m: rust_test_names(m) for m in ("xml", "soap", "actions", "state", "gena", "server", "replay")}
        seen = set()
        for inv in cases["invariants"]:
            self.assertNotIn(inv["id"], seen)
            seen.add(inv["id"])
            self.assertTrue(inv["vectors"] or inv["rust_tests"], f"{inv['id']} checks nothing")
            for vector_id in inv["vectors"]:
                self.assertIn(vector_id, ids, f"{inv['id']}: no vector {vector_id}")
            for name in inv["rust_tests"]:
                module, _, function = name.partition("::")
                self.assertIn(module, tests, f"{inv['id']}: {name}")
                self.assertIn(function, tests[module], f"{inv['id']}: no Rust test {name}")

    def test_every_vector_is_claimed_by_an_invariant(self):
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        claimed = {v for inv in cases["invariants"] for v in inv["vectors"]}
        unclaimed = [i for i in all_vector_ids(ref.load()) if i not in claimed]
        self.assertEqual(unclaimed, [], "a vector no invariant mentions is a vector nobody can explain")

    def test_every_rust_test_is_claimed_or_is_a_replay(self):
        cases = json.loads(CASES.read_text(encoding="utf-8"))
        claimed = {n for inv in cases["invariants"] for n in inv["rust_tests"]}
        unclaimed = []
        for module in ("xml", "soap", "actions", "state", "gena", "server"):
            for function in sorted(rust_test_names(module)):
                if f"{module}::{function}" not in claimed:
                    unclaimed.append(f"{module}::{function}")
        # A test no invariant mentions may still be a good test; the list is printed so it is a choice.
        self.assertLessEqual(len(unclaimed), 8, unclaimed)


class Contract(unittest.TestCase):
    def doc_rows(self):
        rows = {}
        for line in CONTRACT.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\| (\w+) \| `(\w+)` \| (\d+) \| (implemented|deferred)( \(relative\))? \|", line)
            if m:
                rows[(m.group(1), m.group(2))] = (int(m.group(3)), m.group(4), bool(m.group(5)))
        return rows

    def test_the_contract_table_is_the_rust_matrix(self):
        rust = {(s, n): (c, st.lower(), ac == "Relative") for s, n, c, st, ac in rust_matrix()}
        self.assertEqual(self.doc_rows(), rust)

    def test_the_rust_matrix_is_the_measured_usage(self):
        measured = {(a["service"], a["action"]): a["sites"]
                    for a in json.loads(usage.RECORDED.read_text(encoding="utf-8"))["actions"]}
        rust = {(s, n): c for s, n, c, _, _ in rust_matrix()}
        self.assertEqual(rust, measured)

    def test_the_model_and_the_rust_implement_the_same_actions(self):
        rust = {(s, n) for s, n, _, st, _ in rust_matrix() if st == "Implemented"}
        self.assertEqual(rust, ref.IMPLEMENTED)

    def test_the_recorded_usage_matrix_is_consistent(self):
        self.assertEqual(usage.check_recorded(), [])

    def test_the_contract_says_what_is_open(self):
        text = CONTRACT.read_text(encoding="utf-8")
        for phrase in ("**OPEN**", "No stand-in is presented", "pub mod fsonos;", "No server-level model",
                       "a plain-SOAP retry applies twice", "Command Outcome Unknown", "ReapplyOnRetry",
                       "SuccessAfterRetention"):
            self.assertIn(phrase, text)

    def test_ordering_in_the_matrix_is_by_measured_use(self):
        counts = [c for _, _, c, _, _ in rust_matrix()]
        self.assertEqual(counts, sorted(counts, reverse=True))


class Boundaries(unittest.TestCase):
    def sources(self):
        """Every adapter file except replay.rs, which is test code from its first line."""
        return {p.name: p.read_text(encoding="utf-8") for p in sorted(FSONOS.glob("*.rs")) if p.name != "replay.rs"}

    def test_nothing_opens_a_socket_or_reads_a_clock(self):
        forbidden = re.compile(
            r"TcpStream|TcpListener|UdpSocket|SystemTime|Instant::now|std::process|std::fs|std::env|tokio|asupersync|reqwest|hyper")
        for name, text in self.sources().items():
            self.assertIsNone(forbidden.search(production_of(text)), name)

    def test_no_unsafe_and_no_panicking_shortcuts_in_production_code(self):
        for name, text in self.sources().items():
            production = production_of(text)
            self.assertNotRegex(production, r"\bunsafe\b", name)
            self.assertNotRegex(production, r"\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unimplemented!\(", name)

    def test_nothing_in_the_adapter_or_its_fixtures_is_site_data(self):
        documentation = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32")]
        targets = [p.read_text(encoding="utf-8") for p in FSONOS.glob("*.rs")]
        targets += [ref.VECTORS.read_text(encoding="utf-8"), CONTRACT.read_text(encoding="utf-8")]
        for text in targets:
            for literal in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
                try:
                    address = ipaddress.ip_address(literal)
                except ValueError:
                    continue
                self.assertTrue(any(address in net for net in documentation) or str(address) in ("0.0.0.0",),
                                f"{literal} is not a documentation address")
            self.assertNotRegex(text, r"RINCON_", "a real device id shape")
            self.assertNotRegex(text, r"(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", "a MAC address shape")

    def test_the_module_declares_every_file_and_only_replay_is_test_only(self):
        mod = (FSONOS / "mod.rs").read_text(encoding="utf-8")
        declared = set(re.findall(r"^pub mod (\w+);", mod, flags=re.M))
        files = {p.stem for p in FSONOS.glob("*.rs")} - {"mod", "replay"}
        self.assertEqual(declared, files)
        self.assertRegex(mod, r"#\[cfg\(test\)\]\s*mod replay;")


if __name__ == "__main__":
    unittest.main()
