"""Focused tests of tests/p06/case_log.py, P06's connection to the shared Q00 diagnostic sink (bead ffw-2nw).

The adapter is a P06-named copy of the accepted D01/D03 adapters, so these tests exercise what it promises and nothing else: one real permitted
positive (a complete run is complete, named for P06, with two critical events per case and the run summary), and a control for each way the
evidence can be lost (no diagnostics module, a critical event lost to a full sink, an unwritable receipts directory, a case that never reached the
log, a rerun that must not overwrite the first run's file). Host-only and standard library only.

    python3 -B -I -m unittest discover -s tests/p06 -p 'test_case_log.py' -t tests/p06
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, "..", ".."))


def load_adapter():
    spec = importlib.util.spec_from_file_location("p06_t_case_log", os.path.join(HERE, "case_log.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adapter = load_adapter()


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def records(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


class CaseLogTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def diag(self):
        return adapter.load(ROOT)

    def three_cases(self, log):
        log.record("P06-A", "ac1", "passed", "")
        log.record("P06-B", "ac1", "blocked", "a source that was not on this machine")
        log.record("P06-C", "ac2", "failed", "expected 6 slots, observed 5")

    # ---- the permitted positive

    def test_a_complete_run_is_complete_named_for_p06_and_holds_two_critical_events_per_case_and_the_summary(self):
        receipts = os.path.join(self.dir, "receipts")
        log = adapter.CaseLog.open(ROOT, "abc123", "full", receipts=receipts)
        self.three_cases(log)
        evidence = log.finish({"passed": 1, "blocked": 1, "failed": 1})
        self.assertTrue(evidence.complete, evidence.reasons)
        self.assertEqual(evidence.reasons, [])
        self.assertEqual(os.listdir(receipts), ["p06-diag-full-abc123.jsonl"])
        self.assertEqual(evidence.path, os.path.join(receipts, "p06-diag-full-abc123.jsonl"))
        audit = self.diag().audit_log(evidence.path)  # the shared module's own re-read of the file
        self.assertTrue(audit.complete, audit.reasons)
        self.assertEqual(audit.critical_events, 2 * 3 + 1)
        self.assertEqual(evidence.log["critical_lost"], False)
        self.assertEqual(evidence.log["sha256"], sha256(evidence.path))
        self.assertIn("evidence COMPLETE", evidence.summary)
        recs = records(evidence.path)
        self.assertEqual(recs[0]["schema"], "ff.diag.v1")
        self.assertEqual(recs[0]["type"], "header")
        begins = {r["case"]: r for r in recs if r.get("kind") == "case.begin"}
        ends = {r["case"]: r for r in recs if r.get("kind") == "case.end"}
        self.assertEqual(sorted(begins), ["P06-A", "P06-B", "P06-C"])
        self.assertEqual(sorted(ends), ["P06-A", "P06-B", "P06-C"])
        for case_id in begins:
            self.assertEqual(begins[case_id]["corr"], "abc123." + case_id)
            self.assertEqual(ends[case_id]["corr"], begins[case_id]["corr"])
            self.assertTrue(begins[case_id]["critical"] and ends[case_id]["critical"])
        (summary,) = [r for r in recs if r.get("kind") == "run.summary"]
        self.assertEqual(summary["fields"], {"passed": 1, "blocked": 1, "failed": 1, "tier": "full", "cases": 3})

    # ---- the failed-case control

    def test_a_failed_case_is_written_at_level_error_and_its_status_and_detail_read_back(self):
        log = adapter.CaseLog.open(ROOT, "fail01", "smoke", receipts=os.path.join(self.dir, "r"))
        self.three_cases(log)
        evidence = log.finish({"passed": 1, "blocked": 1, "failed": 1})
        ends = {r["case"]: r for r in records(evidence.path) if r.get("kind") == "case.end"}
        self.assertEqual((ends["P06-C"]["level"], ends["P06-C"]["fields"]["status"]), ("error", "failed"))
        self.assertEqual(ends["P06-C"]["fields"]["detail"], "expected 6 slots, observed 5")
        # the controls: a pass is info and a block is warn, so the level is not constant
        self.assertEqual((ends["P06-A"]["level"], ends["P06-A"]["fields"]["status"]), ("info", "passed"))
        self.assertEqual((ends["P06-B"]["level"], ends["P06-B"]["fields"]["status"]), ("warn", "blocked"))
        # a failed case does not make the log incomplete: the log is evidence of the failure, not a loss of it
        self.assertTrue(evidence.complete, evidence.reasons)

    # ---- the diagnostics module is absent

    def test_an_absent_diagnostics_module_is_an_incomplete_log_and_nothing_raises(self):
        empty_repo = tempfile.mkdtemp(dir=self.dir)  # a tree with no scripts/test/test_support/diagnostics.py
        log = adapter.CaseLog.open(empty_repo, "gone01", "full", receipts=os.path.join(self.dir, "r"))
        self.three_cases(log)
        evidence = log.finish({"passed": 1, "blocked": 1, "failed": 1})
        self.assertFalse(evidence.complete)
        self.assertTrue(evidence.reasons[0].startswith("diagnostics_unavailable"), evidence.reasons)
        self.assertIn("NO LOG", evidence.summary)
        self.assertIsNone(evidence.path)
        self.assertIsNone(evidence.log)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "r")), "no log file was created for a log that could not be opened")
        # the control: the same calls against the real tree are complete
        ok = adapter.CaseLog.open(ROOT, "gone02", "full", receipts=os.path.join(self.dir, "r2"))
        self.three_cases(ok)
        self.assertTrue(ok.finish({"passed": 1, "blocked": 1, "failed": 1}).complete)

    # ---- a critical event is lost

    def test_a_critical_event_lost_to_a_full_sink_makes_the_log_incomplete(self):
        diag = self.diag()

        def run(capacity):
            log = adapter.CaseLog.open(ROOT, "full01", "full", target=diag.FaultableSink(capacity_bytes=capacity))
            for n in range(40):
                log.record("P06-%02d" % n, "ac1", "passed", "x" * 40)
            return log.finish({"passed": 40, "blocked": 0, "failed": 0})

        roomy = run(1 << 20)
        self.assertTrue(roomy.complete, roomy.reasons)  # the control: a sink that takes every write
        full = run(3000)  # the plant: a disk that fills long before the run ends
        self.assertFalse(full.complete)
        self.assertTrue(any("critical" in reason for reason in full.reasons), full.reasons)

    def test_a_case_that_never_reached_the_log_is_caught_by_the_independent_count(self):
        diag = self.diag()

        def run(extra_case):
            log = adapter.CaseLog.open(ROOT, "cnt01", "full", target=diag.FaultableSink())
            self.three_cases(log)
            if extra_case:
                log.cases += 1  # a case the runner decided and that wrote no events
            return log.finish({"passed": 1, "blocked": 1, "failed": 1})

        self.assertTrue(run(False).complete)  # the control
        missing = run(True)
        self.assertFalse(missing.complete)
        self.assertEqual(missing.reasons, ["critical_event_count:7_of_9"])

    # ---- the receipts directory cannot be made

    def test_an_unwritable_receipts_directory_is_receipts_unavailable_and_nothing_raises(self):
        blocker = os.path.join(self.dir, "blocker")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("a regular file, so nothing can be created under it")
        log = adapter.CaseLog.open(ROOT, "rcpt01", "full", receipts=os.path.join(blocker, "sub"))
        self.three_cases(log)
        evidence = log.finish({"passed": 1, "blocked": 1, "failed": 1})
        self.assertFalse(evidence.complete)
        self.assertTrue(evidence.reasons[0].startswith("receipts_unavailable:"), evidence.reasons)
        self.assertIsNone(evidence.path)
        # the control: a directory that can be made gives a complete log
        ok = adapter.CaseLog.open(ROOT, "rcpt02", "full", receipts=os.path.join(self.dir, "fine"))
        self.three_cases(ok)
        self.assertTrue(ok.finish({"passed": 1, "blocked": 1, "failed": 1}).complete)

    # ---- a rerun keeps the first run's evidence

    def test_a_rerun_with_the_same_run_id_does_not_overwrite_the_first_log(self):
        receipts = os.path.join(self.dir, "receipts")
        first = adapter.CaseLog.open(ROOT, "same01", "full", receipts=receipts)
        self.three_cases(first)
        kept = first.finish({"passed": 1, "blocked": 1, "failed": 1})
        self.assertTrue(kept.complete, kept.reasons)
        before = sha256(kept.path)
        second = adapter.CaseLog.open(ROOT, "same01", "full", receipts=receipts)
        second.record("P06-Z", "ac1", "passed", "")
        again = second.finish({"passed": 1, "blocked": 0, "failed": 0})
        self.assertFalse(again.complete)
        # the exclusive create fails on the first write, so everything the rerun tried to write is counted as lost
        self.assertTrue(any(reason.startswith("critical_evidence_lost") for reason in again.reasons), again.reasons)
        self.assertEqual(sha256(kept.path), before, "the first run's log is byte-identical after the rerun")
        self.assertEqual(os.listdir(receipts), ["p06-diag-full-same01.jsonl"])


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    unittest.main()
