#!/usr/bin/env python3
"""E05 matrix cases: every (transition, fault) cell against hand-written expected outcomes.

Case IDs are the docstring prefixes (E05-MATRIX-*).  The expected values live in cases.json and were
derived by hand from docs/contracts/e05.md section 3; nothing here computes an expectation from the
model.  Run: python3 -B -I -m unittest tests/e05/test_matrix.py  (or through scripts/e2e/e05).
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402

bm = c.bm


def _view(res, exp):
    v = res["verdict"]
    got = {"verdict": v["kind"], "boots": res["boots"]}
    for key in ("reason", "blockers"):
        if key in exp:
            got[key] = v.get(key)
    return got, {k: exp[k] for k in got}


class Coverage(unittest.TestCase):
    def test_denominator_every_declared_cell_has_a_case(self):
        """E05-MATRIX-COVERAGE: the fault table, both provision disciplines and both update faults are covered; ids unique."""
        cells = c.cases()["cells"]
        ids = [x["id"] for x in cells]
        self.assertEqual(len(ids), len(set(ids)), "duplicate cell ids")
        have = {(x["step"], x["kind"]) for x in cells}
        want = {("boot", "none")}
        for step, kinds in bm.FAULT_TABLE.items():
            want |= {(step, kind) for kind in kinds}
        for subs in bm.PROVISION_SUBS.values():
            want |= {("provision", sub) for sub in subs}
        want |= {("update", f) for f in bm.UPDATE_FAULTS}
        self.assertEqual(sorted(want - have), [], "declared cells with no case")
        self.assertEqual(sorted(have - want), [], "cases for undeclared cells")
        # Both prior states are exercised where it changes the outcome.
        self.assertTrue(any(x.get("prior") == "absent" for x in cells))
        self.assertEqual(len(cells), 34)

    def test_every_case_names_both_profiles(self):
        """E05-MATRIX-EXPECT-SHAPE: each cell carries an expectation for the benign and the 57.23 profile."""
        for cell in c.cases()["cells"]:
            self.assertEqual(sorted(cell["expect"]), ["57.23", "synthetic-benign"], cell["id"])
            for exp in cell["expect"].values():
                self.assertIn(exp["verdict"], ("STOCK_OK", "CUSTOM_OK", "FAILED", "UNQUALIFIED"))
                self.assertIn("boots", exp)
                if exp["verdict"] == "UNQUALIFIED":
                    self.assertTrue(exp["blockers"], cell["id"])


class Synthetic(unittest.TestCase):
    prof = c.profile("synthetic-benign")

    def test_cells_match_hand_written_outcomes(self):
        """E05-MATRIX-BENIGN: with every fact observed and benign, each cell ends as derived by hand and the checker finds nothing (except the planted in-place write)."""
        for cell in c.cases()["cells"]:
            with self.subTest(cell=cell["id"]):
                res = bm.run_cell(self.prof, cell)
                exp = cell["expect"]["synthetic-benign"]
                got, want = _view(res, exp)
                self.assertEqual(got, want)
                want_violations = ["partial_hook_executed"] if exp["verdict"] == "FAILED" else []
                self.assertEqual(c.violations(res, self.prof), want_violations)


class Real5723(unittest.TestCase):
    prof = c.profile("57.23")

    def test_cells_match_hand_written_outcomes(self):
        """E05-MATRIX-5723: on the extracted S1-line profile each cell is either a definite outcome or UNQUALIFIED naming the first unknown blocker."""
        for cell in c.cases()["cells"]:
            with self.subTest(cell=cell["id"]):
                res = bm.run_cell(self.prof, cell)
                exp = cell["expect"]["57.23"]
                got, want = _view(res, exp)
                self.assertEqual(got, want)
                want_violations = ["partial_hook_executed"] if exp["verdict"] == "FAILED" else []
                self.assertEqual(c.violations(res, self.prof), want_violations)

    def test_hand_written_totals(self):
        """E05-MATRIX-TOTALS: 34 cells, 7 definite (5 stock, 2 failed) and 27 unqualified; blockers 19/2/1/4/1."""
        tally, blockers = {}, {}
        for cell in c.cases()["cells"]:
            exp = cell["expect"]["57.23"]
            tally[exp["verdict"]] = tally.get(exp["verdict"], 0) + 1
            for b in exp.get("blockers", []):
                blockers[b] = blockers.get(b, 0) + 1
        self.assertEqual(tally, {"STOCK_OK": 5, "FAILED": 2, "UNQUALIFIED": 27})
        self.assertEqual(blockers, {"EXT-E05-STOP": 19, "EXT-E05-RCS": 2, "EXT-E05-WDOG": 1,
                                    "EXT-E05-FS": 4, "EXT-E05-UPDATE": 1})

    def test_no_definite_outcome_depends_on_an_unknown_fact(self):
        """E05-MATRIX-NO-GUESS: every non-UNQUALIFIED result on 57.23 depends only on observed facts."""
        observed = {f for f, v in self.prof["facts"].items() if v["status"] == "observed"}
        for cell in c.cases()["cells"]:
            res = bm.run_cell(self.prof, cell)
            if res["verdict"]["kind"] != "UNQUALIFIED":
                self.assertLessEqual(set(res["verdict"]["depends"]), observed, cell["id"])


class SecondGeneration(unittest.TestCase):
    prof = c.profile("86.10")

    def test_every_cell_is_unqualified_with_the_s2_blocker(self):
        """E05-MATRIX-S2: no S2 hook semantics are evidenced, so every cell is UNQUALIFIED [EXT-E05-S2] (cases.json s2_rule)."""
        self.assertIn("EXT-E05-S2", c.cases()["s2_rule"])
        for cell in c.cases()["cells"]:
            with self.subTest(cell=cell["id"]):
                v = bm.run_cell(self.prof, cell)["verdict"]
                self.assertEqual((v["kind"], v["blockers"]), ("UNQUALIFIED", ["EXT-E05-S2"]))


class Adverse(unittest.TestCase):
    base = c.profile("synthetic-benign")

    def test_flipped_fact_values_take_the_other_branch(self):
        """E05-MATRIX-ADVERSE: each fact value that changes a branch is exercised and ends as derived by hand."""
        for adv in c.cases()["adverse"]:
            with self.subTest(case=adv["id"]):
                prof = bm.with_facts(self.base, adv["facts"])
                res = bm.run_cell(self.base, adv)
                exp = adv["expect"]
                v = res["verdict"]
                self.assertEqual((v["kind"], v["reason"], res["boots"]), (exp["verdict"], exp["reason"], exp["boots"]))
                self.assertEqual(c.violations(res, prof), sorted(exp["violations"]))

    def test_every_fact_with_a_branch_has_an_adverse_case(self):
        """E05-MATRIX-ADVERSE-COVERAGE: all eleven facts are flipped to their other value by at least one adverse case."""
        flipped = {f for adv in c.cases()["adverse"] for f in adv["facts"]}
        self.assertEqual(flipped, set(bm.FACT_IDS))


class Contrast(unittest.TestCase):
    def test_preflight_makes_a_real_image_failure_definite(self):
        """E05-MATRIX-PREFLIGHT: on 57.23 a missing binary is STOCK_OK with preflight, UNQUALIFIED without (stock was already stopped)."""
        for con in c.cases()["contrasts"]:
            prof = c.profile(con["profile"])
            for side in ("with", "without"):
                cell = {"step": con["step"], "kind": con["kind"], "policy": con[side]["policy"]}
                v = bm.run_cell(prof, cell)["verdict"]
                exp = con[side]["expect"]
                self.assertEqual(v["kind"], exp["verdict"], side)
                for key in ("reason", "blockers"):
                    if key in exp:
                        self.assertEqual(v.get(key), exp[key], side)


if __name__ == "__main__":
    unittest.main()
