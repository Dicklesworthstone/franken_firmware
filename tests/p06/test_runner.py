"""Cases for the runner integration in tests/p06/run_cases.py (bead ffw-2nw): the tiers and their denominators, the Q00 diagnostic log, a
failure's first cause and replay command, a blocked case, a mandatory module that contributes nothing, lost critical evidence, a missing
diagnostics module, an unwritable receipts directory, and the unsupported soak tier.

They drive `run_cases.run_and_judge` on small synthetic suites, never on the discovered suite, so a run cannot recurse into itself. The
synthetic classes are built inside functions: a module-level TestCase here would be discovered and counted as a real P06 case.
The adapter itself (tests/p06/case_log.py) is exercised by tests/p06/test_case_log.py."""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RUNNER = os.path.join(HERE, "run_cases.py")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rc = load_module("p06_run_cases_under_test", RUNNER)
CASE_LOG = rc.load_case_log()[0]


def fake_tests(class_name, outcomes, module="test_fake"):
    """Real unittest cases with the given outcomes ('pass', 'fail', 'skip'), named module.class.test; not visible to discovery."""
    body = {}
    for name, outcome in outcomes.items():
        if outcome == "pass":
            body[name] = lambda self: None
        elif outcome == "fail":
            body[name] = lambda self: self.assertEqual([1, 2], [1, 3])
        else:
            body[name] = lambda self: self.skipTest("source not on this machine")
    cls = type(class_name, (unittest.TestCase,), body)
    cls.__module__ = module
    return [cls(name) for name in outcomes]


def judge(tests, tier="smoke", **kw):
    """(exit code, results, evidence, printed text, error text) of one judged run of `tests`."""
    out, err = io.StringIO(), io.StringIO()
    kw.setdefault("mandatory", ("test_fake",))
    with contextlib.redirect_stderr(err):
        code, results, evidence = rc.run_and_judge(tests, tier, stream=io.StringIO(), out=out, **kw)
    return code, results, evidence, out.getvalue(), err.getvalue()


class TheTiersAreExplicit(unittest.TestCase):
    def test_smoke_is_a_strict_subset_of_full_and_the_difference_is_exactly_the_external_cases(self):
        tests = rc.discover()
        smoke, full = rc.select(tests, "smoke"), rc.select(tests, "full")
        self.assertEqual(len(full), len(tests))
        self.assertTrue(set(smoke) < set(full))
        extra = [t for t in full if t not in set(smoke)]
        self.assertTrue(extra)
        self.assertTrue(all(rc.parts(t) in rc.FULL_ONLY for t in extra), [t.id() for t in extra])
        for pair in rc.FULL_ONLY:   # no tier rule is a dead rule: each matches a real class
            self.assertTrue([t for t in tests if rc.parts(t) == pair], pair)
        modules = {rc.parts(t)[0] for t in smoke}
        for module in rc.MANDATORY_MODULES:
            self.assertIn(module, modules, module)

    def test_list_prints_exactly_the_cases_a_tier_plans(self):
        tests = rc.discover()
        for tier in ("smoke", "full"):
            done = subprocess.run([sys.executable, "-B", "-I", RUNNER, "--list", "--tier", tier], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            ids = done.stdout.split()
            self.assertEqual(len(ids), len(rc.select(tests, tier)), tier)
            self.assertEqual(len(set(ids)), len(ids), "a case id is listed twice")
        self.assertIn("test_runner.TheTiersAreExplicit.test_list_prints_exactly_the_cases_a_tier_plans", ids)

    def test_only_runs_one_case_by_its_exact_id_and_an_unknown_id_is_a_usage_error(self):
        tests = fake_tests("Pass", {"test_a": "pass", "test_b": "pass"})
        code, results, evidence, text, _ = judge(tests, only="test_fake.Pass.test_a", check_structure=False)
        self.assertEqual((code, len(results)), (0, 1))
        self.assertIn("P06 cases: total=1 passed=1 failed=0 blocked=0", text)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rc.main(["--tier", "smoke", "--only", "no.such.case"]), 2)

    def test_the_soak_tier_does_not_run_and_exits_3_with_its_own_blocked_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run([sys.executable, "-B", "-I", RUNNER, "--tier", "soak", "--receipts", tmp], capture_output=True, text=True)
            self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
            self.assertIn("BLOCKED P06-SOAK: tier not supported", done.stdout)
            self.assertIn("P06 cases: total=1 passed=0 failed=0 blocked=1", done.stdout)
            self.assertNotIn("QUALIFIED (host", done.stdout)
            receipts = [n for n in os.listdir(tmp) if n.startswith("p06-receipt-")]
            self.assertEqual(len(receipts), 1)
            with open(os.path.join(tmp, receipts[0]), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual((doc["tier"], doc["exit_code"], doc["summary"]["blocked"]), ("soak", 3, 1))
            self.assertTrue([n for n in os.listdir(tmp) if n.startswith("p06-diag-soak-")])


class TheRunWritesItsOwnEvidence(unittest.TestCase):
    def test_a_passing_run_is_qualified_with_a_complete_log_and_a_receipt(self):
        tests = fake_tests("Pass", {"test_a": "pass", "test_b": "pass"})
        with tempfile.TemporaryDirectory() as tmp:
            code, results, evidence, text, _ = judge(tests, receipts=tmp)
            self.assertEqual(code, 0, text)
            self.assertTrue(evidence.complete, evidence.reasons)
            self.assertIn("RESULT: QUALIFIED", text)
            self.assertIn("P06 cases: total=2 passed=2 failed=0 blocked=0", text)
            names = sorted(os.listdir(tmp))
            self.assertTrue([n for n in names if re.fullmatch(r"p06-diag-smoke-[0-9a-f]+\.jsonl", n)], names)
            receipt = [n for n in names if n.startswith("p06-receipt-")]
            self.assertEqual(len(receipt), 1, names)
            with open(os.path.join(tmp, receipt[0]), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual((doc["schema"], doc["tier"], doc["exit_code"]), (rc.RECEIPT_SCHEMA, "smoke", 0))
            self.assertEqual(doc["summary"], {"planned": 2, "passed": 2, "failed": 0, "blocked": 0})
            self.assertTrue(doc["diagnostics"]["complete"])
            log = doc["diagnostics"]["log"]
            self.assertEqual((log["events"], log["dropped"], log["critical_lost"], log["truncated"]), (2 * 2 + 1, 0, False, False))
            self.assertEqual(doc["diagnostics"]["file"], [n for n in names if n.startswith("p06-diag-")][0])
            self.assertEqual(set(doc["artifacts"]), set(rc.JUDGED_ARTIFACTS))
            self.assertEqual(doc["replay"], "scripts/e2e/p06 --tier smoke")

    def test_a_failed_case_exits_1_and_keeps_its_first_cause_and_the_exact_replay(self):
        tests = fake_tests("Pass", {"test_a": "pass"}) + fake_tests("Fail", {"test_wrong": "fail"})
        code, results, evidence, text, _ = judge(tests)
        self.assertEqual(code, 1)
        self.assertTrue(evidence.complete, "a failed case is not a lost log")
        self.assertIn("RETAINED FOR REPLAY. First failed case: test_fake.Fail.test_wrong: AssertionError: Lists differ", text)
        self.assertIn("at tests/p06/test_runner.py:", text)       # the innermost frame in the repository, repository-relative
        self.assertNotIn(ROOT, text)
        self.assertIn("  replay: scripts/e2e/p06 --tier smoke --only test_fake.Fail.test_wrong", text)
        self.assertRegex(text, r"  versions: python \S+; receipt ffw\.p06-receipt\.v1; cases \S+")
        self.assertEqual(len(re.findall(r"^  artifact \S+ sha256 \S+$", text, re.M)), len(rc.JUDGED_ARTIFACTS))
        self.assertIn("RESULT: FAILED", text)
        # the pass beside it is still a pass, and the failing id replays the failing case alone
        self.assertEqual([r.status for r in results], ["passed", "failed"])

    def test_a_skipped_case_is_blocked_never_a_pass_and_the_run_exits_3(self):
        tests = fake_tests("Pass", {"test_a": "pass"}) + fake_tests("Block", {"test_skipped": "skip"})
        code, results, evidence, text, _ = judge(tests)
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED test_fake.Block.test_skipped: source not on this machine", text)
        self.assertIn("NOT QUALIFIED: 1 case(s) did not run", text)
        self.assertNotIn("RESULT: QUALIFIED", text)

    def test_a_mandatory_module_that_contributes_no_case_is_a_blocked_case_not_an_omission(self):
        tests = fake_tests("Pass", {"test_a": "pass"})
        code, results, evidence, text, _ = judge(tests, mandatory=("test_fake", "test_missing"))
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED P06-MANDATORY:test_missing: mandatory test module test_missing contributed no case", text)
        self.assertEqual(rc.summarize(results), {"planned": 2, "passed": 1, "failed": 0, "blocked": 1})
        # the control: with the module present the same run is clean
        self.assertEqual(judge(tests, mandatory=("test_fake",))[0], 0)

    def test_a_renamed_class_cannot_silently_move_a_case_between_tiers(self):
        tests = fake_tests("Pass", {"test_a": "pass"})
        _, results, _, text, _ = judge(tests, "full")
        names = [r.case_id for r in results if r.status == "blocked"]
        self.assertEqual(sorted(names), sorted("P06-TIERS:%s.%s" % pair for pair in rc.FULL_ONLY))
        self.assertIn("matches no case", text)


class TheLogIsEvidenceOrTheRunIsNotQualified(unittest.TestCase):
    def test_lost_critical_evidence_turns_a_passing_run_into_exit_1(self):
        tests = fake_tests("Pass", {"test_%d" % i: "pass" for i in range(12)})
        diag = CASE_LOG.load(ROOT)

        def tiny_disk(repo, run_id, tier, receipts, header):
            return CASE_LOG.CaseLog.open(repo, run_id, tier, receipts, target=diag.FaultableSink(capacity_bytes=1200), header_extra=header)

        code, results, evidence, text, _ = judge(tests, opener=tiny_disk)
        self.assertTrue(all(r.status == "passed" for r in results))
        self.assertFalse(evidence.complete)
        self.assertEqual(code, 1)
        self.assertIn("RESULT: NOT QUALIFIED: diagnostic evidence INCOMPLETE", text)
        # the control: the same run on a disk that holds it is complete and qualified
        def roomy(repo, run_id, tier, receipts, header):
            return CASE_LOG.CaseLog.open(repo, run_id, tier, receipts, target=diag.FaultableSink(), header_extra=header)

        code, _, evidence, _, _ = judge(tests, opener=roomy)
        self.assertEqual((code, evidence.complete), (0, True), evidence.reasons)

    def test_a_repository_without_the_diagnostics_module_is_an_unqualified_run_not_a_crash(self):
        tests = fake_tests("Pass", {"test_a": "pass"})
        with tempfile.TemporaryDirectory() as bare:
            code, results, evidence, text, _ = judge(tests, repo=bare)
        self.assertEqual(code, 1)
        self.assertFalse(evidence.complete)
        self.assertTrue(any(reason.startswith("diagnostics_unavailable") for reason in evidence.reasons), evidence.reasons)
        self.assertIn("evidence INCOMPLETE", text)

    def test_a_missing_adapter_module_is_an_unqualified_run_not_a_crash(self):
        tests = fake_tests("Pass", {"test_a": "pass"})
        with mock.patch.object(rc, "load_case_log", return_value=(None, "case_log_unavailable:ImportError")):
            code, _, evidence, text, _ = judge(tests)
        self.assertEqual(code, 1)
        self.assertEqual(evidence.reasons, ["case_log_unavailable:ImportError"])
        self.assertIn("NO LOG", text)

    def test_an_unwritable_receipts_directory_is_one_error_line_and_exit_1_not_a_traceback(self):
        tests = fake_tests("Pass", {"test_a": "pass"})
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "a-regular-file")
            with open(blocker, "w", encoding="utf-8") as fh:
                fh.write("x")
            code, results, evidence, text, err = judge(tests, receipts=os.path.join(blocker, "receipts"))
        self.assertEqual(code, 1)
        self.assertFalse(evidence.complete)
        self.assertIn("error: the receipt could not be written under", err)
        self.assertNotIn("Traceback", err + text)


INVARIANTS = {
    "P06-RUN-001": ("tiers are explicit, planned from the discovered cases, and every one of them is a real class",
                    ["test_smoke_is_a_strict_subset_of_full_and_the_difference_is_exactly_the_external_cases",
                     "test_list_prints_exactly_the_cases_a_tier_plans", "test_only_runs_one_case_by_its_exact_id_and_an_unknown_id_is_a_usage_error",
                     "test_a_renamed_class_cannot_silently_move_a_case_between_tiers"]),
    "P06-RUN-002": ("an unsupported tier does not run and is never a pass",
                    ["test_the_soak_tier_does_not_run_and_exits_3_with_its_own_blocked_case"]),
    "P06-RUN-003": ("a run writes its own bounded diagnostic log and receipt; a pass rests on a complete log",
                    ["test_a_passing_run_is_qualified_with_a_complete_log_and_a_receipt",
                     "test_lost_critical_evidence_turns_a_passing_run_into_exit_1",
                     "test_a_repository_without_the_diagnostics_module_is_an_unqualified_run_not_a_crash",
                     "test_a_missing_adapter_module_is_an_unqualified_run_not_a_crash",
                     "test_an_unwritable_receipts_directory_is_one_error_line_and_exit_1_not_a_traceback"]),
    "P06-RUN-004": ("a failure keeps its first cause, the replay command, the versions and the artifact digests; a case that did not run is blocked",
                    ["test_a_failed_case_exits_1_and_keeps_its_first_cause_and_the_exact_replay",
                     "test_a_skipped_case_is_blocked_never_a_pass_and_the_run_exits_3",
                     "test_a_mandatory_module_that_contributes_no_case_is_a_blocked_case_not_an_omission"]),
}


class TheRunnerInvariantsMapToTestsThatExist(unittest.TestCase):
    def test_every_named_test_exists_and_every_test_here_is_named(self):
        with open(os.path.join(HERE, "test_runner.py"), encoding="utf-8") as fh:
            have = set(re.findall(r"^    def (test_\w+)\(", fh.read(), re.M))
        named = {name for _, names in INVARIANTS.values() for name in names}
        mapping_test = "test_every_named_test_exists_and_every_test_here_is_named"
        self.assertEqual(named - have, set(), "an invariant names a test that does not exist")
        self.assertEqual(have - named - {mapping_test}, set(), "a test here is claimed by no invariant")
        self.assertEqual(len(INVARIANTS), len(set(INVARIANTS)))


if __name__ == "__main__":
    unittest.main()
