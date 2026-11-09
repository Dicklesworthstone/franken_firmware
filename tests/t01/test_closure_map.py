"""Tests of the T01 closure rows (bead ffw-32a, tests/t01/): the invariant-to-case map and its inapplicability statements, the five tailnet scenario rows of the profile, the agreement of the
profile and the study text with the committed X02 receipts, and the network-free T01 sources. Standard library only, offline, no cargo.

Run: python3 -B -W error -m unittest tests/t01/test_closure_map.py   (from the repository root)

Each check passes on the committed files and reports a fault planted in a copy of them, and the unplanted copy passes again. The required invariant ids and the required inapplicability ids
are held BY HAND below, from the bead's own text; they are not read from cases.json, so deleting an invariant from the map is reported instead of followed.
"""
import ast
import copy
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import run_cases as rc  # noqa: E402
import t01lib as L  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
CASES = L.load_json(L.CASES)
PROFILE = L.load_json(L.PROFILE)
LEDGER = L.load_json(L.LEDGER)

# Every invariant the bead (acceptance: "Each required invariant maps to a case; explain genuine inapplicability") asks of T01, by the id cases.json uses, written from the bead's sentences.
REQUIRED_INVARIANTS = (
    "native-class", "negative-is-not-admission", "missing-is-pending", "cell-needs-a-run", "three-states", "evidence-bound", "pinned-sources", "synthetic-only", "build-from-records",
    "figures-from-runs", "result-kind-stated", "exact-build-command-denominator", "missing-case-blocked", "failure-retains-replay", "rerun-keeps-original", "bounded-and-confined",
    "no-implicit-network", "redacted-diagnostics", "evidence-loss-is-incomplete", "independent-oracles",
)
# The bead's criteria that cannot apply to an offline feasibility study, each stated with its reason rather than left unmapped.
REQUIRED_INAPPLICABLE = ("cancellation", "restart", "seeds-and-virtual-clocks", "render-path-sink", "member-source-revision-ids")
MIN_REASON = 120


def test_index(directory=HERE):
    """Every `file::Class.method` test under the directory, from the syntax tree (nothing is imported or run)."""
    found = set()
    for name in sorted(os.listdir(directory)):
        if not (name.startswith("test_") and name.endswith(".py")):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=name)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                        found.add("%s::%s.%s" % (name, node.name, item.name))
    return found


def map_problems(doc, case_ids, tests, required=REQUIRED_INVARIANTS, required_na=REQUIRED_INAPPLICABLE):
    """What is wrong with an invariant map: a required invariant or inapplicability statement missing or unknown, an invariant that maps to nothing, a cited case the runner does not plan,
    a cited test that does not exist, or an inapplicability without a reason."""
    problems = []
    rows = doc.get("invariants", [])
    ids = [r.get("id") for r in rows]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append("invariant %s is listed twice" % dup)
    for missing in sorted(set(required) - set(ids)):
        problems.append("required invariant %s is missing from the map" % missing)
    for extra in sorted(set(ids) - set(required)):
        problems.append("invariant %s is not a required invariant (add it to the hand-held list with its bead sentence)" % extra)
    for row in rows:
        rid = row.get("id")
        cases, cited = row.get("cases", []), row.get("tests", [])
        if not isinstance(cases, list) or not isinstance(cited, list):
            problems.append("invariant %s: cases and tests must be lists" % rid)
            continue
        if not str(row.get("bead", "")).strip():
            problems.append("invariant %s quotes no bead sentence" % rid)
        if not cases and not cited:
            problems.append("invariant %s maps to no case or test" % rid)
        for case in cases:
            if case not in case_ids:
                problems.append("invariant %s names a case the runner does not plan: %s" % (rid, case))
        for test in cited:
            if test not in tests:
                problems.append("invariant %s names a test that does not exist: %s" % (rid, test))
        if "gap" in row and not str(row["gap"]).strip():
            problems.append("invariant %s has an empty gap" % rid)
    na = doc.get("inapplicable", [])
    na_ids = [r.get("id") for r in na]
    for dup in sorted({i for i in na_ids if na_ids.count(i) > 1}):
        problems.append("inapplicable %s is listed twice" % dup)
    for missing in sorted(set(required_na) - set(na_ids)):
        problems.append("required inapplicability %s is missing from the map" % missing)
    for extra in sorted(set(na_ids) - set(required_na)):
        problems.append("inapplicable %s is not a required statement" % extra)
    for row in na:
        rid = row.get("id")
        if rid in ids:
            problems.append("%s is both an invariant and an inapplicability" % rid)
        if not str(row.get("criterion", "")).strip():
            problems.append("inapplicable %s quotes no bead criterion" % rid)
        if len(str(row.get("reason", "")).strip()) < MIN_REASON:
            problems.append("inapplicable %s gives no reason (an inapplicability must say why, in at least %d characters)" % (rid, MIN_REASON))
    return problems


def orphan_cases(doc, case_ids):
    """The planned runner cases that no invariant cites: a case that holds nothing."""
    cited = {c for row in doc.get("invariants", []) for c in row.get("cases", [])}
    return sorted(set(case_ids) - cited)


def planted(problems, needle):
    return any(needle in p for p in problems)


class InvariantMap(unittest.TestCase):
    def setUp(self):
        self.doc = CASES["invariant_map"]
        self.case_ids = set(rc.planned_ids("full"))
        self.tests = test_index()

    def problems(self, mutate):
        doc = copy.deepcopy(self.doc)
        mutate(doc)
        return map_problems(doc, self.case_ids, self.tests)

    def test_the_test_index_is_not_vacuous(self):
        self.assertIn("test_t01.py::Rules.test_the_hand_written_tables_equal_the_rules", self.tests)
        self.assertIn("test_closure_map.py::InvariantMap.test_the_committed_map_holds", self.tests)
        self.assertNotIn("test_t01.py::Rules.setUp", self.tests)
        self.assertNotIn("test_t01.py::planted", self.tests)
        for name in ("test_x02_judge.py::Resources.test_unknown_is_blocked_never_a_pass", "test_x02_evidence.py::CommittedReceipts.test_each_committed_transcript_is_the_one_its_receipt_recorded"):
            self.assertIn(name, self.tests)                                                                                      # every test file is indexed, not only the first

    def test_the_committed_map_holds(self):
        self.assertEqual(map_problems(self.doc, self.case_ids, self.tests), [])
        self.assertEqual(sorted(r["id"] for r in self.doc["invariants"]), sorted(REQUIRED_INVARIANTS))
        self.assertEqual(sorted(r["id"] for r in self.doc["inapplicable"]), sorted(REQUIRED_INAPPLICABLE))

    def test_every_planned_case_holds_some_invariant(self):
        self.assertEqual(orphan_cases(self.doc, self.case_ids), [])
        doc = copy.deepcopy(self.doc)
        for row in doc["invariants"]:
            row["cases"] = [c for c in row["cases"] if c != "T01-C03-matrix"]
        self.assertEqual(orphan_cases(doc, self.case_ids), ["T01-C03-matrix"])

    def test_each_planted_fault_is_reported_and_the_unplanted_copy_passes_again(self):
        self.assertEqual(self.problems(lambda d: None), [])                                                                      # control
        self.assertTrue(planted(self.problems(lambda d: d["invariants"].pop(0)), "required invariant native-class is missing"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"].append({"id": "extra", "bead": "x", "cases": ["T01-C01-classification"]})), "not a required invariant"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"cases": [], "tests": []})), "maps to no case or test"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"cases": ["T01-C99-nothing"]})), "names a case the runner does not plan: T01-C99-nothing"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"tests": ["test_t01.py::Rules.test_nothing"]})), "names a test that does not exist"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"bead": " "})), "quotes no bead sentence"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"gap": ""})), "empty gap"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"][0].update({"cases": "T01-C01-classification"})), "must be lists"))
        self.assertTrue(planted(self.problems(lambda d: d["invariants"].append(copy.deepcopy(d["invariants"][0]))), "listed twice"))
        self.assertTrue(planted(self.problems(lambda d: d["inapplicable"].pop(0)), "required inapplicability cancellation is missing"))
        self.assertTrue(planted(self.problems(lambda d: d["inapplicable"][0].update({"reason": "does not apply"})), "gives no reason"))
        self.assertTrue(planted(self.problems(lambda d: d["inapplicable"][0].update({"criterion": ""})), "quotes no bead criterion"))
        self.assertTrue(planted(self.problems(lambda d: d["inapplicable"][0].update({"id": "native-class"})), "both an invariant and an inapplicability"))
        self.assertTrue(planted(self.problems(lambda d: d["inapplicable"].append({"id": "extra", "criterion": "x", "reason": "x" * 200})), "not a required statement"))
        self.assertEqual(self.problems(lambda d: None), [])                                                                      # and the unplanted copy passes again

    def test_a_mapped_case_cannot_be_a_stale_name_after_a_case_is_renamed(self):
        renamed = set(self.case_ids) - {"T01-X02-target-resources"} | {"T01-X02-measurements"}
        problems = map_problems(self.doc, renamed, self.tests)
        self.assertTrue(planted(problems, "names a case the runner does not plan: T01-X02-target-resources"))

    def test_a_renamed_test_is_reported_as_missing(self):
        tests = set(self.tests) - {"test_t01.py::Runner.test_the_tiers_plan_what_they_say"}
        self.assertEqual(map_problems(self.doc, self.case_ids, tests), [])                                                       # not cited, so not needed
        cited = self.doc["invariants"][0]["tests"][0]
        problems = map_problems(self.doc, self.case_ids, set(self.tests) - {cited})
        self.assertTrue(planted(problems, "names a test that does not exist: " + cited))


class ScenarioRows(unittest.TestCase):
    """The bead's tailnet resource table: identity enrollment, maps at the declared peer cap, reconnect, relay traffic and key rotation while audio runs."""

    ROWS = ("tailscale-rs-0.6.1/ppc32be_stock", "tailscale-rs-0.6.1/mips32r2be_stock", "tailscale-rs-0.6.1/ppc32be_harness", "tailscale-rs-0.6.1/mips32be_harness",
            "tailscale-go-1.104.5/ppc32be_stock", "tailscale-go-1.104.5/mips32r2be_stock", "tailscale-go-1.104.5/ppc32be_harness", "tailscale-go-1.104.5/mips32be_harness")

    def check(self, mutate):
        doc = copy.deepcopy(PROFILE)
        mutate(doc)
        return L.check_profile(doc, LEDGER)

    def test_the_five_items_are_the_beads_table(self):
        self.assertEqual(L.SCENARIO_ITEMS, ("scenario_enrollment", "scenario_maps_at_peer_cap", "scenario_reconnect", "scenario_relay_traffic", "scenario_key_rotation"))

    def test_every_row_carries_all_five_and_none_is_a_figure_or_a_pass(self):
        self.assertEqual(sorted(PROFILE["measurements"]), sorted(self.ROWS))
        self.assertEqual(L.check_profile(PROFILE, LEDGER), [])
        for key in self.ROWS:
            for name in L.SCENARIO_ITEMS:
                item = PROFILE["measurements"][key][name]
                self.assertIn(item["state"], ("pending", "not_applicable"), key + "." + name)
                self.assertNotIn("value", item, key + "." + name)
                self.assertGreater(len(item["blocker"]), 60, key + "." + name)
                self.assertIn("audio", item["what"] + item["blocker"], key + "." + name)

    def test_each_tailscale_rs_blocker_names_its_own_cause(self):
        by_scenario = {"scenario_enrollment": "registration", "scenario_maps_at_peer_cap": "peer cap", "scenario_reconnect": "loss of the control or data path",
                       "scenario_relay_traffic": "relay path", "scenario_key_rotation": "no automatic key rotation"}
        by_target = {"ppc32be_stock": "epoll_create1", "mips32r2be_stock": "2.6.35", "ppc32be_harness": "harness guest exists", "mips32be_harness": "harness guest exists"}
        for target, needle in by_target.items():
            row = PROFILE["measurements"]["tailscale-rs-0.6.1/" + target]
            for name, cause in by_scenario.items():
                self.assertIn(cause, row[name]["blocker"], target + "." + name)
                self.assertIn(needle, row[name]["blocker"], target + "." + name)
                self.assertIn("Device::new", row[name]["blocker"], target + "." + name)
                self.assertIn("not yet a committed receipt", row[name]["blocker"], target + "." + name)          # the reported hang is named as a report, never as evidence

    def test_the_go_client_has_no_port_on_powerpc_and_no_build_on_mips(self):
        for target in ("ppc32be_stock", "ppc32be_harness"):
            for name in L.SCENARIO_ITEMS:
                item = PROFILE["measurements"]["tailscale-go-1.104.5/" + target][name]
                self.assertEqual(item["state"], "not_applicable")
                self.assertIn("no Go port for 32-bit PowerPC", item["blocker"])
        for target in ("mips32r2be_stock", "mips32be_harness"):
            for name in L.SCENARIO_ITEMS:
                item = PROFILE["measurements"]["tailscale-go-1.104.5/" + target][name]
                self.assertEqual(item["state"], "pending")
                self.assertIn("official_reference", item["blocker"])

    def test_no_peer_cap_is_invented(self):
        self.assertTrue(all(v is None for v in PROFILE["budgets"]["tailnet_ram_cap_bytes"].values()))
        for key in self.ROWS[:4]:
            self.assertIn("no peer cap is declared", PROFILE["measurements"][key]["scenario_maps_at_peer_cap"]["blocker"])

    def test_each_planted_fault_is_reported_and_the_unplanted_copy_passes_again(self):
        row = "tailscale-rs-0.6.1/mips32be_harness"
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control
        self.assertTrue(planted(self.check(lambda d: d["measurements"][row].pop("scenario_key_rotation")), "lacks the tailnet scenario item scenario_key_rotation"))
        self.assertTrue(planted(self.check(lambda d: [m.pop("scenario_reconnect") for m in d["measurements"].values()]), "lacks the tailnet scenario item scenario_reconnect"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][row]["scenario_enrollment"].update({"state": "measured"})), "'measured' without a receipt"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][row]["scenario_enrollment"].update({"state": "observed_not_a_footprint"})), "a scenario figure is measured, pending or not_applicable"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][row]["scenario_relay_traffic"].pop("blocker")), "without its reason"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][row]["scenario_relay_traffic"].update({"state": "passed"})), "state 'passed'"))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_the_budget_case_is_unchanged_by_the_new_items_and_a_cap_is_still_refused(self):
        data = rc.inputs()
        self.assertEqual(rc.case_budget(data, REPO).status, "passed")                                                            # the case walks every row, new items included
        self.assertTrue(planted(self.check(lambda d: d["budgets"]["tailnet_ram_cap_bytes"].update({"mips32be_harness": 8 * 1024 * 1024})), "absent budget is pending"))
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again


class InapplicableOnlyWhereThereIsNoBuild(unittest.TestCase):
    """`not_applicable` is how a measurement hides a requirement. It is allowed only where the candidate has no build for the target at all: the official Go client on the two 32-bit PowerPC
    targets, because Go 1.27.3 has no linux/ppc port (T01-E01). A tailscale-rs row has a build path on every target, so its missing figures are `pending` with a blocker. The rule is derived from the
    profile's own facts (`L.has_no_build_for_target`); the pair of rows it admits is pinned here by hand."""

    GO_PPC_ROWS = ("tailscale-go-1.104.5/ppc32be_stock", "tailscale-go-1.104.5/ppc32be_harness")
    ITEMS_PER_ROW = ("build", "binary_bytes", "rss_peak_bytes", "cpu") + L.SCENARIO_ITEMS

    def check(self, mutate):
        doc = copy.deepcopy(PROFILE)
        mutate(doc)
        return L.check_profile(doc, LEDGER)

    def test_the_rule_admits_exactly_the_go_client_on_the_two_powerpc_targets(self):
        admitted = sorted(k for k in PROFILE["measurements"] if L.has_no_build_for_target(PROFILE, *k.split("/")))
        self.assertEqual(admitted, sorted(self.GO_PPC_ROWS))
        for key in self.GO_PPC_ROWS:
            candidate, target = key.split("/")
            self.assertIn("T01-E01", PROFILE["candidates"][candidate]["platform"][target]["evidence"])                           # the ledger entry that says Go has no 32-bit PowerPC port
            self.assertEqual(PROFILE["targets"][target]["rust_triple"], "powerpc-unknown-linux-musl")

    def test_the_committed_profile_marks_exactly_those_rows_not_applicable_and_passes(self):
        self.assertEqual(L.check_profile(PROFILE, LEDGER), [])
        marked = {k: sorted(n for n, i in row.items() if i["state"] == "not_applicable") for k, row in PROFILE["measurements"].items()}
        marked = {k: v for k, v in marked.items() if v}
        self.assertEqual(sorted(marked), sorted(self.GO_PPC_ROWS))                                                               # 2 rows
        for key, names in marked.items():
            self.assertEqual(sorted(names), sorted(self.ITEMS_PER_ROW), key)                                                     # 9 items each: 18 in all, 10 of them scenario items
            self.assertTrue(set(L.SCENARIO_ITEMS) <= set(names), key)

    def test_no_item_of_any_other_row_can_be_marked_not_applicable(self):
        for key, row in PROFILE["measurements"].items():
            if key in self.GO_PPC_ROWS:
                continue
            for name in row:
                if row[name]["state"] == "observed_not_a_footprint":
                    continue                                                                                                     # a recorded observation, not a figure that is pending
                problems = self.check(lambda d, key=key, name=name: d["measurements"][key][name].update({"state": "not_applicable", "blocker": "no figure"}))
                self.assertTrue(planted(problems, "measurement %s/%s is not_applicable" % (key, name)), key + "/" + name)

    def test_the_survivor_mutant_is_refused_and_names_the_row_and_the_item(self):
        row = "tailscale-rs-0.6.1/mips32be_harness"
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control
        problems = self.check(lambda d: d["measurements"][row]["scenario_key_rotation"].update({"state": "not_applicable"}))      # its blocker is kept, as in the reported mutant
        self.assertTrue(planted(problems, row + "/scenario_key_rotation is not_applicable"))
        self.assertTrue(planted(problems, "has a build path on that target"))
        self.assertEqual(len([p for p in problems if "is not_applicable" in p]), 1)                                              # one item changed, one problem
        self.assertEqual(self.check(lambda d: None), [])                                                                         # and the unplanted copy passes again

    def test_all_five_scenario_items_of_a_native_row_cannot_be_hidden_together(self):
        for row in ("tailscale-rs-0.6.1/ppc32be_stock", "tailscale-rs-0.6.1/mips32r2be_stock", "tailscale-rs-0.6.1/ppc32be_harness", "tailscale-rs-0.6.1/mips32be_harness"):
            def plant(d, row=row):
                for name in L.SCENARIO_ITEMS:
                    d["measurements"][row][name]["state"] = "not_applicable"
            problems = self.check(plant)
            for name in L.SCENARIO_ITEMS:
                self.assertTrue(planted(problems, "%s/%s is not_applicable" % (row, name)), row + "/" + name)

    def test_the_rule_is_derived_from_the_profile_not_listed(self):
        go_ppc = "tailscale-go-1.104.5/ppc32be_stock"
        go, ppc = "tailscale-go-1.104.5", "ppc32be_stock"
        self.assertEqual(self.check(lambda d: None), [])                                                                         # control
        # take away any one of the facts the rule reads and the Go row's items are refused
        self.assertTrue(planted(self.check(lambda d: d["candidates"][go]["platform"][ppc].update({"state": "no_evidence"})), go_ppc + "/build is not_applicable"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][go]["platform"][ppc].update({"evidence": ["T01-E06"]})), go_ppc + "/scenario_enrollment is not_applicable"))
        self.assertTrue(planted(self.check(lambda d: d["targets"][ppc].update({"rust_triple": "mips-unknown-linux-musl"})), go_ppc + "/cpu is not_applicable"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][go]["facts"].update({"language": "rust"})), go_ppc + "/binary_bytes is not_applicable"))
        # and a row the rule's facts describe passes without being named anywhere: the Go wrapper on PowerPC, given measurement rows that mark everything inapplicable
        wrapper = "tailscaled-userspace-proxy"
        self.assertEqual(PROFILE["candidates"][wrapper]["facts"]["language"], "go")

        def add_wrapper_row(d):
            d["measurements"][wrapper + "/" + ppc] = {name: {"state": "not_applicable", "blocker": "nothing to build or run: no Go port for 32-bit PowerPC (T01-E01)"} for name in self.ITEMS_PER_ROW}
        self.assertEqual(self.check(add_wrapper_row), [])
        self.assertTrue(L.has_no_build_for_target(PROFILE, wrapper, ppc))

    def test_a_native_row_cannot_borrow_the_go_rows_evidence(self):
        ts = "tailscale-rs-0.6.1"
        def plant(d):
            d["candidates"][ts]["platform"]["ppc32be_stock"]["evidence"].append("T01-E01")      # cite the Go port table on the Rust candidate
            d["measurements"][ts + "/ppc32be_stock"]["cpu"].update({"state": "not_applicable"})
        self.assertTrue(planted(self.check(plant), ts + "/ppc32be_stock/cpu is not_applicable"))                                  # the language is Rust, so the citation does not admit it
        self.assertFalse(L.has_no_build_for_target(PROFILE, ts, "ppc32be_stock"))

    def test_an_unknown_row_or_a_malformed_key_is_never_inapplicable(self):
        self.assertFalse(L.has_no_build_for_target(PROFILE, "no-such-candidate", "ppc32be_stock"))
        self.assertFalse(L.has_no_build_for_target(PROFILE, "tailscale-go-1.104.5", "no-such-target"))
        self.assertFalse(L.has_no_build_for_target({}, "tailscale-go-1.104.5", "ppc32be_stock"))
        problems = self.check(lambda d: d["measurements"].update({"no-slash-key": {"cpu": {"state": "not_applicable", "blocker": "x"}}}))
        self.assertTrue(planted(problems, "no-slash-key/cpu is not_applicable"))


class MeasuredNeedsARealReceipt(unittest.TestCase):
    """A `measured` item is the only way the profile can say a figure exists, so its `receipt` must name a real file: directly under toolchain/results/tailscale/measurements/, existing, a plain regular
    file, and parsing as a JSON object. No row is measured today, so this must hold before any is. What it does not do: judge that the file holds the figure (that is x02_judge's job; the binding of the
    figure to the receipt is tests/t01/test_figure_binding.py, so `check` here leaves its problems out: a probe receipt on a tailscale-rs row is refused there, by design)."""

    ROW = "tailscale-rs-0.6.1/mips32be_harness"
    DIR = "toolchain/results/tailscale/measurements/"
    REAL = ("x02-v3b-mips-20261108.json", "x02-v3b-powerpc-20261108.json")

    def check(self, receipt, item="cpu", repo=REPO, state="measured"):
        doc = copy.deepcopy(PROFILE)
        doc["measurements"][self.ROW][item].update({"state": state, "receipt": receipt})
        return [p for p in L.check_profile(doc, LEDGER, repo) if "but its figure" not in p]

    def test_no_row_is_measured_today_and_the_profile_passes_with_the_repository(self):
        self.assertEqual([k for k, row in PROFILE["measurements"].items() for i in row.values() if i["state"] == "measured"], [])
        self.assertEqual(L.check_profile(PROFILE, LEDGER, REPO), [])

    def test_a_real_committed_receipt_is_the_control_for_any_item(self):
        for name in self.REAL:
            self.assertTrue(os.path.isfile(os.path.join(REPO, *(self.DIR + name).split("/"))), name)
            for item in ("build", "binary_bytes", "rss_peak_bytes", "cpu") + L.SCENARIO_ITEMS:
                self.assertEqual(self.check(self.DIR + name, item), [], (name, item))

    def test_a_receipt_that_names_no_file_is_refused(self):
        for text in ("x", "measured", "n/a", "see the contract", "receipt", "toolchain/results/tailscale/measurements/", "toolchain/results/tailscale/measurements", ".json", self.DIR + ".json"):
            problems = self.check(text)
            self.assertTrue(any("measurement %s/cpu is 'measured', but its receipt names" % self.ROW in p for p in problems), repr(text))
        for item in ("build", "binary_bytes", "rss_peak_bytes", "cpu") + L.SCENARIO_ITEMS:                                       # whichever item is called measured, not only one
            self.assertTrue(any("measurement %s/%s is 'measured', but its receipt names" % (self.ROW, item) in p for p in self.check("x", item)), item)
        self.assertTrue(any("is 'measured' without a receipt" in p for p in self.check("")), "empty")                             # the earlier rule still speaks first
        self.assertTrue(any("is 'measured' without a receipt" in p for p in self.check(None)), "none")
        for odd in (7, ["a"], {"path": "x"}):
            self.assertTrue(any("but its receipt names" in p for p in self.check(odd)), repr(odd))
        self.assertEqual(self.check(self.DIR + self.REAL[0]), [])                                                                # control: the real receipt, same row and item

    def test_a_receipt_that_names_a_missing_file_is_refused_with_the_repository_and_only_its_form_checked_without(self):
        missing = self.DIR + "no-such-receipt.json"
        problems = self.check(missing)
        self.assertTrue(any("a file that does not exist or cannot be read" in p for p in problems), problems)
        self.assertEqual(self.check(missing, repo=None), [])                                                                     # the form is right, the file is the repository's to vouch for
        self.assertEqual(self.check(self.DIR + self.REAL[0]), [])                                                                # control

    def test_a_file_elsewhere_or_off_the_directory_is_refused_even_when_it_exists(self):
        for path in ("docs/tailscale/profiles.json", "toolchain/results/tailscale/builds/x01-core-powerpc-unknown-linux-musl-20261107.log", "toolchain/results/tailscale/receipts/t01-8cdc69be60fccfa2.json",
                     self.DIR + "../receipts/t01-8cdc69be60fccfa2.json", self.DIR + "sub/" + self.REAL[0], self.DIR + ".hidden.json", self.DIR + self.REAL[0] + "x", self.DIR + "x02-v3b-mips-20261108.serial.txt",
                     "/" + self.DIR + self.REAL[0], "./" + self.DIR + self.REAL[0], self.DIR.replace("/", "\\") + self.REAL[0]):
            self.assertTrue(any("but its receipt names" in p for p in self.check(path)), path)

    def test_a_file_that_is_not_a_plain_json_object_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, *self.DIR.rstrip("/").split("/"))
            os.makedirs(directory)

            def put(name, data):
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(data)
            put("good.json", b'{"schema": "x"}')
            put("not-json.json", b"this is not json\n")
            put("empty.json", b"")
            put("array.json", b"[1, 2]")
            put("string.json", b'"receipt"')
            put("bytes.json", b"\xff\xfe\x00\x00")
            put("valid-object.txt", b'{"schema": "x"}')                                                                          # parses, but it is not a .json receipt
            put(".hidden.json", b'{"schema": "x"}')                                                                              # these three exist and parse, so only the form of the name can refuse them
            put("back\\slash.json", b'{"schema": "x"}')
            os.makedirs(os.path.join(directory, "sub"))
            put("sub/nested.json", b'{"schema": "x"}')
            os.makedirs(os.path.join(directory, "a-directory.json"))
            os.symlink(os.path.join(directory, "good.json"), os.path.join(directory, "link.json"))
            self.assertEqual(self.check(self.DIR + "good.json", repo=tmp), [])                                                   # control: a plain file that parses to an object
            for name, why in (("not-json.json", "does not parse as JSON"), ("empty.json", "does not parse as JSON"), ("bytes.json", "does not parse as JSON"), ("array.json", "is not a JSON object"),
                              ("string.json", "is not a JSON object"), ("a-directory.json", "does not exist or cannot be read"), ("link.json", "does not exist or cannot be read")):
                self.assertTrue(any(why in p for p in self.check(self.DIR + name, repo=tmp)), name)
            for name in ("valid-object.txt", ".hidden.json", "back\\slash.json", "sub/nested.json"):
                self.assertTrue(any("which is not a .json file directly under" in p for p in self.check(self.DIR + name, repo=tmp)), name)
            self.assertEqual(self.check(self.DIR + "good.json", repo=tmp), [])                                                   # and the unplanted copy passes again

    def test_the_runners_profile_case_applies_it_with_the_repository(self):
        data = rc.inputs()
        self.assertEqual(rc.case_profile(data, REPO).status, "passed")
        for receipt, receipt_problem in ((self.DIR + self.REAL[0], False), (self.DIR + "no-such-receipt.json", True), ("x", True)):
            weak = copy.deepcopy(data)
            weak["profile"]["measurements"][self.ROW]["cpu"].update({"state": "measured", "receipt": receipt})
            result = rc.case_profile(weak, REPO)
            self.assertEqual(result.status, "failed", receipt)                                                                   # a tailscale-rs row is never measured by a probe receipt (see test_figure_binding.py)
            self.assertEqual("is 'measured', but its receipt" in result.detail, receipt_problem, receipt)                       # and the receipt rule speaks only where the receipt is the problem
            self.assertEqual("is 'measured', but its figure" in result.detail, not receipt_problem, receipt)

    def test_a_state_that_is_not_measured_needs_no_receipt(self):
        self.assertEqual(self.check("x", state="pending"), [])
        self.assertTrue(any("is not_applicable, but this candidate has a build path" in p for p in self.check("x", state="not_applicable")))     # refused for its own reason, not the receipt's
        self.assertFalse(any("receipt" in p for p in self.check("x", state="pending")))


class BuildOkUnrunNeedsARealReceipt(unittest.TestCase):
    """A platform state `build_ok_unrun` says a build exists, so its `receipt` must name a real record under toolchain/results/tailscale/builds/ (where run_cases.BUILD_DIR reads them): a .log or a .json
    directly in it, existing, plain, and what its suffix says. The same rule as `measured` with its own directory. No platform claims a build today. What it does not do: judge that the record is a build."""

    CAND, TARGET = "tailscale-rs-0.6.1", "mips32be_harness"
    DIR = "toolchain/results/tailscale/builds/"
    LOGS = sorted(n for n in os.listdir(os.path.join(REPO, "toolchain", "results", "tailscale", "builds")) if n.endswith(".log"))

    def check(self, receipt, cand=None, target=None, repo=REPO, state="build_ok_unrun"):
        doc = copy.deepcopy(PROFILE)
        doc["candidates"][cand or self.CAND]["platform"][target or self.TARGET].update({"state": state, "receipt": receipt})
        return L.check_profile(doc, LEDGER, repo)

    def cells(self):
        """Every candidate and target except the two rows where the profile itself marks the build inapplicable (the Go client on 32-bit PowerPC, which has measurement rows saying so; see
        test_a_build_cannot_be_claimed_where_the_profile_says_there_is_none). The Go wrapper on PowerPC has no such rows, so it stays a control."""
        return [(c, t) for c in PROFILE["candidates"] for t in PROFILE["targets"] if not (L.has_no_build_for_target(PROFILE, c, t) and c + "/" + t in PROFILE["measurements"])]

    def test_a_build_cannot_be_claimed_where_the_profile_says_there_is_none(self):
        for target in ("ppc32be_stock", "ppc32be_harness"):
            self.assertFalse(any(c == "tailscale-go-1.104.5" and t == target for c, t in self.cells()))
            problems = self.check(self.DIR + self.LOGS[0], "tailscale-go-1.104.5", target)                                      # a real record, on a cell with no Go port: its inapplicable items now contradict it
            self.assertTrue(any("tailscale-go-1.104.5/%s/build is not_applicable" % target in p for p in problems), (target, problems))
        self.assertEqual(len(self.cells()), 5 * 4 - 2)                                                                           # the two Go rows are out; the Go wrapper's PowerPC cells stay in

    def test_no_platform_claims_a_build_today_and_only_two_states_have_a_home_for_receipts(self):
        self.assertEqual([(c, t) for c, cand in PROFILE["candidates"].items() for t, p in cand["platform"].items() if p["state"] in ("build_ok_unrun", "ran_on_target")], [])
        self.assertEqual(L.check_profile(PROFILE, LEDGER, REPO), [])
        self.assertEqual(sorted(L.RECEIPT_HOMES), ["build_ok_unrun", "measured"])
        self.assertEqual(L.RECEIPT_HOMES["build_ok_unrun"], ("toolchain/results/tailscale/builds/", (".log", ".json")))
        self.assertEqual(L.BUILD_RECORD_DIR, "/".join(rc.BUILD_DIR) + "/")                                                       # the directory the runner reads its build records from

    def test_every_committed_build_record_is_the_control_for_every_platform(self):
        self.assertGreaterEqual(len(self.LOGS), 8)
        for name in self.LOGS:
            for cand, target in self.cells():
                self.assertEqual(self.check(self.DIR + name, cand, target), [], (name, cand, target))

    def test_a_receipt_that_names_no_file_is_refused_for_every_platform(self):
        for cand, target in self.cells():
            for text in ("x", "built", "n/a", "see the contract", "toolchain/results/tailscale/builds/", "toolchain/results/tailscale/builds", ".log", self.DIR + ".log", self.DIR + ".json"):
                problems = self.check(text, cand, target)
                self.assertTrue(any("candidate %s on %s: build_ok_unrun, but its receipt names" % (cand, target) in p for p in problems), (cand, target, text))
            for odd in (7, ["a"], {"path": "x"}):
                self.assertTrue(any("but its receipt names" in p for p in self.check(odd, cand, target)), (cand, target, odd))
        self.assertTrue(any("build_ok_unrun needs a receipt" in p for p in self.check("")), "empty")                                # the earlier rule still speaks first
        self.assertTrue(any("build_ok_unrun needs a receipt" in p for p in self.check(None)), "none")
        self.assertEqual(self.check(self.DIR + self.LOGS[0]), [])                                                                # control: a real record, same cell

    def test_a_missing_record_is_refused_with_the_repository_and_only_its_form_checked_without(self):
        missing = self.DIR + "no-such-record.log"
        self.assertTrue(any("a file that does not exist or cannot be read" in p for p in self.check(missing)))
        self.assertTrue(any("a file that does not exist or cannot be read" in p for p in self.check(self.DIR + "no-such-record.json")))
        self.assertEqual(self.check(missing, repo=None), [])                                                                     # the form is right; the repository vouches for the file
        self.assertEqual(self.check(self.DIR + self.LOGS[0]), [])                                                                # control

    def test_a_file_elsewhere_or_off_the_directory_is_refused_even_when_it_exists(self):
        for path in ("toolchain/results/tailscale/measurements/x02-v3b-mips-20261108.json",                                      # a guest-run receipt is not a build record
                     "toolchain/results/tailscale/receipts/t01-8cdc69be60fccfa2.json", "docs/tailscale/profiles.json", self.DIR + "../receipts/t01-8cdc69be60fccfa2.json",
                     self.DIR + "sub/" + self.LOGS[0], self.DIR + "." + self.LOGS[0], self.DIR + self.LOGS[0] + "x", self.DIR + "x01.txt", "/" + self.DIR + self.LOGS[0],
                     "./" + self.DIR + self.LOGS[0], self.DIR.replace("/", "\\") + self.LOGS[0]):
            self.assertTrue(any("but its receipt names" in p for p in self.check(path)), path)

    def test_a_record_that_is_not_what_its_suffix_says_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, *self.DIR.rstrip("/").split("/"))
            os.makedirs(os.path.join(directory, "sub"))

            def put(name, data):
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(data)
            put("good.log", b"cargo check finished\n")
            put("good.json", b'{"schema": "x"}')
            put("empty.log", b"")
            put("blank.log", b" \n\t\n")
            put("binary.log", b"\xff\xfe\x00\x00")
            put("not-json.json", b"this is not json\n")
            put("array.json", b"[1]")
            put("valid-object.txt", b'{"schema": "x"}')
            put(".hidden.log", b"text\n")
            put("back\\slash.log", b"text\n")
            put("sub/nested.log", b"text\n")
            os.makedirs(os.path.join(directory, "a-directory.log"))
            os.symlink(os.path.join(directory, "good.log"), os.path.join(directory, "link.log"))
            for name in ("good.log", "good.json"):
                self.assertEqual(self.check(self.DIR + name, repo=tmp), [], name)                                                # controls: a text log and a JSON object
            for name, why in (("empty.log", "a file that is empty"), ("blank.log", "a file that is empty"), ("binary.log", "a file that is not UTF-8 text"),
                              ("not-json.json", "does not parse as JSON"), ("array.json", "is not a JSON object"), ("a-directory.log", "does not exist or cannot be read"),
                              ("link.log", "does not exist or cannot be read"), ("valid-object.txt", "which is not a .log or .json file directly under"),
                              (".hidden.log", "which is not a .log or .json file directly under"), ("back\\slash.log", "which is not a .log or .json file directly under"),
                              ("sub/nested.log", "which is not a .log or .json file directly under")):
                self.assertTrue(any(why in p for p in self.check(self.DIR + name, repo=tmp)), name)
            self.assertEqual(self.check(self.DIR + "good.log", repo=tmp), [])                                                    # and the unplanted copy passes again

    def test_each_state_reads_only_its_own_directory(self):
        build, figure = self.DIR + self.LOGS[0], "toolchain/results/tailscale/measurements/x02-v3b-mips-20261108.json"
        self.assertIsNone(L.receipt_problem(build, REPO, "build_ok_unrun"))
        self.assertIsNone(L.receipt_problem(figure, REPO, "measured"))
        self.assertIn("not a file under toolchain/results/tailscale/measurements/", L.receipt_problem(build, REPO, "measured"))   # a build log is not a figure's receipt
        self.assertIn("not a file under toolchain/results/tailscale/builds/", L.receipt_problem(figure, REPO, "build_ok_unrun"))
        self.assertIn("not a file under toolchain/results/tailscale/measurements/", L.receipt_problem(build, REPO))             # the default state is still `measured`

    def test_the_runners_profile_case_applies_it_with_the_repository(self):
        data = rc.inputs()
        self.assertEqual(rc.case_profile(data, REPO).status, "passed")
        for receipt, status in ((self.DIR + self.LOGS[0], "passed"), (self.DIR + "no-such-record.log", "failed"), ("x", "failed")):
            weak = copy.deepcopy(data)
            weak["profile"]["candidates"][self.CAND]["platform"][self.TARGET].update({"state": "build_ok_unrun", "receipt": receipt})
            result = rc.case_profile(weak, REPO)
            self.assertEqual(result.status, status, receipt)
            if status == "failed":
                self.assertIn("build_ok_unrun, but its receipt", result.detail)

    def test_ran_on_target_is_not_touched(self):
        problems = self.check("x", state="ran_on_target")                                                                        # refused already, for the cell it makes supported, not for its receipt
        self.assertTrue(any("is supported" in p for p in problems), problems)
        self.assertFalse(any("but its receipt" in p for p in problems), problems)


class ProfileAndStudyAgreeWithTheX02Receipts(unittest.TestCase):
    """The committed X02 receipts say the probe ran once in one harness guest per architecture. The frozen profile and the study text must not say it did not."""

    OLD_PROFILE_VERSION = "t01-profile-2026-11-07.1"
    NEW_PROFILE_VERSION = "t01-profile-2026-11-09.1"
    STALE = (
        "nothing was linked or run, and X02 (on-target memory/CPU) is blocked",
        "no closure is claimed while X02 is blocked and nothing is linked or run",
        "remain blocked on measured client guest execution",
        "and the on-target figures (X02) are blocked",
        "the on-target memory/CPU figures (T01-X02) are blocked",
        "nothing was linked, run on a target, enrolled or measured",
        "its two cheapest decisive experiments are central and not yet run",
        "the existing harness guests for a CPU-only figure",
    )
    STALE_PER_TAILSCALE_RS_ROW = "a harness-guest figure would be indicative only and has not been run"       # still true for the Go rows, where no figure exists
    FEASIBILITY = os.path.join(REPO, "docs", "tailscale", "feasibility.md")
    RUN = os.path.join(REPO, "toolchain", "results", "tailscale", "RUN.md")

    def setUp(self):
        if rc.case_resources(REPO).status != "passed":
            self.skipTest("the X02 receipts are not both committed and judged, so there is nothing for the narrative to agree with")

    @classmethod
    def read(cls, path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    @classmethod
    def stale(cls, text):
        return [phrase for phrase in cls.STALE if phrase in text]

    def test_the_profile_and_the_study_do_not_say_x02_is_blocked_or_not_run(self):
        self.assertEqual(self.stale(json.dumps(PROFILE)), [])
        self.assertEqual(self.stale(self.read(self.FEASIBILITY)), [])
        for key, row in PROFILE["measurements"].items():
            if key.startswith("tailscale-rs"):
                for item in ("rss_peak_bytes", "cpu"):
                    self.assertNotIn(self.STALE_PER_TAILSCALE_RS_ROW, row[item]["blocker"], key + "." + item)
        planted_row = copy.deepcopy(PROFILE["measurements"]["tailscale-rs-0.6.1/mips32be_harness"]["cpu"]["blocker"]) + "; " + self.STALE_PER_TAILSCALE_RS_ROW
        self.assertIn(self.STALE_PER_TAILSCALE_RS_ROW, planted_row)                                                              # the per-row phrase is the one the check looks for
        self.assertIn(self.STALE_PER_TAILSCALE_RS_ROW, PROFILE["measurements"]["tailscale-go-1.104.5/mips32be_harness"]["cpu"]["blocker"])      # and it is still true of the Go row

    def test_a_stale_sentence_put_back_is_reported_and_the_unplanted_text_passes_again(self):
        text = self.read(self.FEASIBILITY)
        self.assertEqual(self.stale(text), [])                                                                                   # control
        for phrase in self.STALE:
            self.assertEqual(self.stale(text + "\n" + phrase + "\n"), [phrase])
        self.assertEqual(self.stale(text), [])                                                                                   # and the unplanted text passes again

    def test_the_profile_says_what_ran_and_what_did_not(self):
        native = PROFILE["native_requirement"]
        self.assertEqual(PROFILE["profile_version"], self.NEW_PROFILE_VERSION)
        for said in (self.OLD_PROFILE_VERSION, "t01-profile-2026-11-06.1", "toolchain/results/tailscale/RUN.md", "no existing state, evidence citation, cell or figure changed"):
            self.assertIn(said, PROFILE["frozen_note"])
        self.assertIn("INCOMPLETE", PROFILE["status"])
        self.assertIn("X02 protocol-core probe", PROFILE["status"])
        self.assertIn("ran once in one harness guest per architecture", PROFILE["status"])
        for field in ("t01_status", "study_outcome"):
            self.assertIn("harness guest per architecture", native[field], field)
            self.assertIn("not a client", native[field], field)
        self.assertIn("no negative result is recorded", native["closes_note"])
        self.assertEqual((native["status"], native["waived"], native["satisfied_by"], native["closes"]), ("required", False, [], []))

    def test_the_blockers_name_receipts_that_are_committed(self):
        for target, name in (("mips32be_harness", "x02-v3b-mips-20261108.json"), ("ppc32be_harness", "x02-v3b-powerpc-20261108.json")):
            path = "toolchain/results/tailscale/measurements/" + name
            self.assertTrue(os.path.isfile(os.path.join(REPO, path)), path)
            for item in ("rss_peak_bytes", "cpu"):
                blocker = PROFILE["measurements"]["tailscale-rs-0.6.1/" + target][item]["blocker"]
                self.assertIn(path, blocker)
                self.assertIn("not a footprint of this candidate", blocker)
                self.assertEqual(PROFILE["measurements"]["tailscale-rs-0.6.1/" + target][item]["state"], "pending")            # a probe reading is not a client figure

    def test_the_study_names_the_current_profile_and_the_probe_and_keeps_the_native_requirement(self):
        text = self.read(self.FEASIBILITY)
        self.assertIn(self.NEW_PROFILE_VERSION, text)
        for said in ("T01-X02", "harness guest", "not a client", "INCOMPLETE and pending", "The native requirement stays required"):
            self.assertIn(said, text)
        self.assertIn("does not close T02, T04 or Q06", text)

    def test_the_decision_record_exists_and_names_what_changed_and_what_did_not(self):
        text = self.read(self.RUN)
        self.assertIn("Profile version " + self.NEW_PROFILE_VERSION, text)
        section = text[text.index("Profile version " + self.NEW_PROFILE_VERSION):]
        for said in (self.OLD_PROFILE_VERSION, "x02-v3b-mips-20261108.json", "x02-v3b-powerpc-20261108.json", "scenario_enrollment", "scenario_key_rotation", "Unchanged, and tested as unchanged"):
            self.assertIn(said, section)


class NoNetworkImports(unittest.TestCase):
    """The bead: no implicit LAN discovery, provider login or physical audio. The T01 runner, library, judge and log import no module that opens a connection."""

    SOURCES = ("run_cases.py", "t01lib.py", "x02_judge.py", "case_log.py")
    NETWORK = frozenset({"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "socketserver", "asyncio", "requests"})

    @classmethod
    def network_imports(cls, source):
        found = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
        return sorted(found & cls.NETWORK)

    def test_the_t01_sources_import_no_network_module_and_a_planted_import_is_reported(self):
        for name in self.SOURCES:
            with open(os.path.join(HERE, name), encoding="utf-8") as handle:
                source = handle.read()
            self.assertEqual(self.network_imports(source), [], name)                                                             # control
            self.assertEqual(self.network_imports(source + "\nimport socket\n"), ["socket"], name)
            self.assertEqual(self.network_imports(source + "\nfrom urllib.request import urlopen\n"), ["urllib"], name)
            self.assertEqual(self.network_imports(source + "\ndef late():\n    import asyncio\n"), ["asyncio"], name)            # a nested import counts too
            self.assertEqual(self.network_imports(source + "\nfrom . import socket\n"), [], name)                                # a relative import is not the standard module
            self.assertEqual(self.network_imports(source), [], name)                                                             # and the unplanted source passes again


if __name__ == "__main__":
    unittest.main()
