#!/usr/bin/env python3
"""Self-tests for tests/e03/run_cases.py: the runner is the thing that decides pass/fail, so each of its
checks is fed a deliberately wrong input and must refuse it (planted negatives), next to inputs it must
accept (positives).  Stdlib only, offline, no subprocess except the CLI case."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("ffw_e03_run_cases_under_test", os.path.join(HERE, "run_cases.py"))
RC = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = RC
_spec.loader.exec_module(RC)

SYN_PW = {"op": "insert_after", "prefix": "FFW_TEST:POS_FD_SHORT_WRITE",
          "line": "FFW_TEST:PARTIAL_WRITE status=PASS bytes=4096"}
SAMPLE = "\n".join(["FFW_HELLO a", "FFW_PROBE:EPOLL status=PASS fd=4", "FFW_TEST:ERR_EBADF status=PASS errno=9", "tail"])


def real_available() -> bool:
    return all(os.path.exists(os.path.join(RC.RESULTS, f)) for f in RC.REAL.values())


class TestMutationOps(unittest.TestCase):
    def test_every_op_transforms_exactly_what_it_names(self):
        self.assertEqual(RC.mutate(SAMPLE, [{"op": "set_line", "prefix": "FFW_PROBE:EPOLL", "line": "X"}]).split("\n")[1], "X")
        out = RC.mutate(SAMPLE, [{"op": "insert_after", "prefix": "FFW_HELLO", "line": "NEW"}]).split("\n")
        self.assertEqual(out[:2], ["FFW_HELLO a", "NEW"])
        out = RC.mutate(SAMPLE, [{"op": "duplicate", "prefix": "FFW_PROBE:EPOLL"}]).split("\n")
        self.assertEqual(out.count("FFW_PROBE:EPOLL status=PASS fd=4"), 2)
        self.assertEqual(RC.mutate(SAMPLE, [{"op": "truncate_after", "prefix": "FFW_PROBE:EPOLL"}]).split("\n")[-1],
                         "FFW_PROBE:EPOLL status=PASS fd=4")
        self.assertNotIn("FFW_PROBE:EPOLL", RC.mutate(SAMPLE, [{"op": "drop", "prefix": "FFW_PROBE:EPOLL"}]))
        self.assertEqual(RC.mutate(SAMPLE, [{"op": "truncate_before_first", "prefix": "FFW_PROBE:EPOLL"}]), "FFW_HELLO a")

    def test_an_op_that_matches_nothing_is_an_error_not_a_pass(self):
        for kind in ("set_line", "insert_after", "duplicate", "truncate_after", "drop", "truncate_before_first"):
            with self.assertRaises(RC.CaseError, msg=kind):
                RC.mutate(SAMPLE, [{"op": kind, "prefix": "FFW_NOPE", "line": "x"}])

    def test_an_op_that_matches_two_lines_is_an_error(self):
        text = SAMPLE + "\nFFW_PROBE:EPOLL status=PASS fd=5"
        for kind in ("set_line", "insert_after", "duplicate", "truncate_after"):
            with self.assertRaises(RC.CaseError, msg=kind):
                RC.mutate(text, [{"op": kind, "prefix": "FFW_PROBE:EPOLL", "line": "x"}])

    def test_unknown_op_is_refused(self):
        with self.assertRaises(RC.CaseError):
            RC.mutate(SAMPLE, [{"op": "rot13", "prefix": "FFW_HELLO"}])

    def test_inline_and_unknown_sources(self):
        self.assertEqual(RC.build_text({"source": {"inline": ["a", "b"]}}), "a\nb\n")
        with self.assertRaises(RC.CaseError):
            RC.build_text({"source": {}})
        with self.assertRaises(RC.CaseError):
            RC.real_text("sparc")


class TestExpectationChecks(unittest.TestCase):
    """_check_result must raise for every field that disagrees and stay silent when everything agrees."""

    def setUp(self):
        self.res = RC.A.classify_run("", "harness-ppc-4.9", "none")     # red / unavailable-guest

    def check(self, expect, text=""):
        RC._check_result(self.res, expect, text)

    def refuses(self, expect, text=""):
        with self.assertRaises(RC.CaseError):
            self.check(expect, text)

    def test_matching_expectation_passes(self):
        self.check({"evidence": "unavailable-guest", "verdict": "red", "calibration_ok": False,
                    "probes": {"EPOLL": ["unavailable-guest", "no guest"]},
                    "all_probes": ["unavailable-guest", "no guest"], "supported_exactly": []})

    def test_each_field_refuses_a_wrong_value(self):
        self.refuses({"evidence": "matching-guest"})
        self.refuses({"verdict": "green"})
        self.refuses({"calibration_ok": True})
        self.refuses({"probes": {"EPOLL": ["supported", "pass"]}})
        self.refuses({"probes": {"EPOLL": ["unavailable-guest", "something else"]}})      # status right, reason wrong
        self.refuses({"all_probes": ["supported", "pass"]})
        self.refuses({"all_probes": ["unavailable-guest", "wrong reason"]})
        self.refuses({"supported_exactly": ["EPOLL"]})
        self.refuses({"guest_status": {"EPOLL": "supported"}})

    def test_expect_by_line_picks_the_branch_by_what_the_transcript_contains(self):
        by = {"line": "FFW_TEST:PARTIAL_WRITE",
              "absent": {"verdict": "red"}, "present": {"verdict": "green"}}
        self.check({"expect_by_line": by}, text="nothing here")                  # absent -> red -> ok
        self.refuses({"expect_by_line": by}, text="FFW_TEST:PARTIAL_WRITE status=PASS bytes=1")   # present -> green wanted
        flipped = {"line": "FFW_TEST:PARTIAL_WRITE", "absent": {"verdict": "green"}, "present": {"verdict": "red"}}
        self.refuses({"expect_by_line": flipped}, text="nothing here")
        self.check({"expect_by_line": flipped}, text="x\nFFW_TEST:PARTIAL_WRITE status=PASS bytes=1")

    def test_expect_by_line_needs_the_line_at_the_start_of_a_line(self):
        by = {"line": "FFW_TEST:PARTIAL_WRITE", "absent": {"verdict": "red"}, "present": {"verdict": "green"}}
        self.check({"expect_by_line": by}, text="echo FFW_TEST:PARTIAL_WRITE")


class TestTableHandlers(unittest.TestCase):
    def refuses(self, handler, spec):
        with self.assertRaises(RC.CaseError):
            handler(spec)

    def test_errno_table(self):
        RC.h_errno_table({"arch": "mips", "entries": [[89, "ENOSYS"], [38, None]]})
        self.refuses(RC.h_errno_table, {"arch": "mips", "entries": [[89, "EINTR"]]})
        self.refuses(RC.h_errno_table, {"arch": "mips", "entries": [[38, "ENOSYS"]]})

    def test_errno_reverse(self):
        RC.h_errno_reverse({"arch": "mips", "entries": [["ENOSYS", 89]], "unknown_names": ["EFOO"], "unknown_arches": ["arm"]})
        self.refuses(RC.h_errno_reverse, {"arch": "mips", "entries": [["ENOSYS", 38]]})
        self.refuses(RC.h_errno_reverse, {"arch": "mips", "entries": [], "unknown_names": ["ENOSYS"]})   # known name "unknown"
        self.refuses(RC.h_errno_reverse, {"arch": "mips", "entries": [], "unknown_arches": ["mips"]})    # known ABI "unknown"

    def test_int_table(self):
        RC.h_int_table({"valid": [["7", 7]], "invalid": ["07"]})
        self.refuses(RC.h_int_table, {"valid": [["7", 8]], "invalid": []})
        self.refuses(RC.h_int_table, {"valid": [["07", 7]], "invalid": []})      # a rejected valid entry
        self.refuses(RC.h_int_table, {"valid": [], "invalid": ["7"]})            # an accepted invalid entry

    def test_io_table(self):
        RC.h_io_table({"arch": "mips", "requested": 8, "entries": [[8, "full", None], [-89, "error", "ENOSYS"]],
                       "invalid_args": [[0, 1]]})
        self.refuses(RC.h_io_table, {"arch": "mips", "requested": 8, "entries": [[4, "full", None]]})
        self.refuses(RC.h_io_table, {"arch": "mips", "requested": 8, "entries": [[-89, "error", "EINTR"]]})
        self.refuses(RC.h_io_table, {"arch": "mips", "requested": 8, "entries": [], "invalid_args": [[8, 1]]})


@unittest.skipUnless(real_available(), "committed QEMU transcripts are not present")
class TestRealEvidenceHandlers(unittest.TestCase):
    def refuses(self, handler, spec):
        with self.assertRaises(RC.CaseError):
            handler(spec)

    def classify_spec(self, expect, mutations=None, profile="harness-mips-4.19"):
        return {"source": {"real": "mips"}, "profile": profile, "mutations": mutations or [SYN_PW], "expect": expect}

    def test_classify_accepts_the_right_expectation_and_refuses_a_wrong_one(self):
        RC.h_classify(self.classify_spec({"verdict": "green", "evidence": "matching-guest"}))
        self.refuses(RC.h_classify, self.classify_spec({"verdict": "red"}))
        self.refuses(RC.h_classify, self.classify_spec({"evidence": "non-matching-guest"}))

    def test_cli_accepts_the_right_exit_and_refuses_a_wrong_one(self):
        base = {"source": {"real": "mips"}, "mutations": [SYN_PW], "profile": "harness-mips-4.19", "exit": 0, "verdict": "green"}
        RC.h_cli(base)
        self.refuses(RC.h_cli, dict(base, exit=1))                      # wrong exit code
        self.refuses(RC.h_cli, dict(base, verdict="red"))               # right exit, wrong verdict
        RC.h_cli({"profile": "no-such", "exit": 2, "source": {"real": "mips"}, "mutations": []})
        self.refuses(RC.h_cli, {"profile": "harness-mips-4.19", "exit": 0, "verdict": "green", "missing_file": True})

    def test_cross_validator_refuses_a_wrong_root_or_ours_expectation(self):
        ok = {"real": "mips", "profile": "harness-mips-4.19",
              "variants": [{"name": "v", "mutations": [SYN_PW], "root": "PASS", "ours": "green"}]}
        RC.h_cross_validator(ok)
        self.refuses(RC.h_cross_validator, {**ok, "variants": [dict(ok["variants"][0], root="FAIL")]})
        self.refuses(RC.h_cross_validator, {**ok, "variants": [dict(ok["variants"][0], ours="red")]})

    def test_cross_validator_refuses_validators_that_disagree(self):
        # The stated expectations match what each side returns, so only the agreement rule can object:
        # the root validator says PASS while the (stubbed) classifier says degraded, and the reverse.
        saved = RC.A.classify_run
        try:
            RC.A.classify_run = lambda text, profile, mode="full-system": {"verdict": "degraded"}
            self.refuses(RC.h_cross_validator, {"real": "mips", "profile": "harness-mips-4.19", "variants": [
                {"name": "root passes", "mutations": [SYN_PW], "root": "PASS", "ours": "degraded"}]})
            RC.A.classify_run = lambda text, profile, mode="full-system": {"verdict": "green"}
            self.refuses(RC.h_cross_validator, {"real": "mips", "profile": "harness-mips-4.19", "variants": [
                {"name": "root fails", "mutations": [], "root": "FAIL", "ours": "green"}]})
        finally:
            RC.A.classify_run = saved

    def test_identity_follows_the_receipt_and_the_log_bytes(self):
        RC.h_identity({})
        with tempfile.TemporaryDirectory() as d:
            for f in list(RC.REAL.values()) + ["e07-e03-verification-receipt.json"]:
                shutil.copy(os.path.join(RC.RESULTS, f), os.path.join(d, f))
            saved = RC.RESULTS
            try:
                RC.RESULTS = d
                RC.h_identity({})                                         # an exact copy still agrees
                with open(os.path.join(d, RC.REAL["ppc"]), "ab") as fh:
                    fh.write(b"\nFFW_NOTE:changed\n")
                self.refuses(RC.h_identity, {})                           # one extra line changes the sha256
            finally:
                RC.RESULTS = saved


class TestMetaHandler(unittest.TestCase):
    def doc(self):
        return {"cases": [{"id": "E03-X-1", "kind": "errno_table"}, {"id": "E03-M-1", "kind": "meta"}],
                "invariants": [{"id": "I1", "text": "t", "status": "covered", "cases": ["E03-X-1"]}]}

    def refuses(self, doc):
        with self.assertRaises(RC.CaseError):
            RC.h_meta({}, doc)

    def test_a_coherent_document_passes(self):
        RC.h_meta({}, self.doc())

    def test_each_incoherence_is_refused(self):
        d = self.doc(); d["invariants"][0]["cases"] = ["E03-X-1", "E03-NOPE"]; self.refuses(d)       # names a missing case
        d = self.doc(); d["cases"].append({"id": "E03-X-2", "kind": "errno_table"}); self.refuses(d)  # covers nothing
        d = self.doc(); d["invariants"][0]["cases"] = []; self.refuses(d)                           # covered, no case
        d = self.doc(); d["invariants"][0]["status"] = "nonsense"; self.refuses(d)
        d = self.doc()
        d["invariants"].append({"id": "I2", "text": "t", "status": "inapplicable"})                  # unexplained
        self.refuses(d)
        d["invariants"][1]["note"] = "handled elsewhere"                                             # explained: fine
        RC.h_meta({}, d)


class TestKernelMatching(unittest.TestCase):
    def test_kernel_release_matching_is_exact_or_separator_bounded(self):
        m = RC.A.kernel_matches
        self.assertTrue(m("2.6.14", "2.6.14"))
        self.assertTrue(m("2.6.14-sonos", "2.6.14"))
        self.assertTrue(m("2.6.14.3", "2.6.14"))
        self.assertTrue(m("4.19.0-21-4kc-malta", "4.19.0-21-4kc-malta"))
        for release in (None, "", "2.6.140", "2.6.1", "2.6", "2.6.15", "x"):
            self.assertFalse(m(release, "2.6.14"), repr(release))
        self.assertFalse(m(None, ""))
        self.assertFalse(m("", ""))


class TestRunnerSelftestHandler(unittest.TestCase):
    """h_runner_selftest must itself refuse a failing, empty or too-small self-test run."""

    PASS3 = "import unittest\nclass T(unittest.TestCase):\n    def test_a(self): pass\n    def test_b(self): pass\n    def test_c(self): pass\n"
    FAIL1 = "import unittest\nclass T(unittest.TestCase):\n    def test_a(self): self.fail('planted')\n    def test_b(self): pass\n"
    EMPTY = "import unittest\n"

    def run_stub(self, body, min_tests):
        with tempfile.TemporaryDirectory() as d:
            if body is not None:
                with open(os.path.join(d, "test_run_cases.py"), "w", encoding="utf-8") as fh:
                    fh.write(body)
            saved = RC.HERE
            try:
                RC.HERE = d
                RC.h_runner_selftest({"min_tests": min_tests})
            finally:
                RC.HERE = saved

    def test_a_passing_run_with_enough_tests_is_accepted(self):
        self.run_stub(self.PASS3, 3)

    def test_a_failing_test_is_refused_even_when_the_count_is_enough(self):
        with self.assertRaises(RC.CaseError):
            self.run_stub(self.FAIL1, 0)

    def test_too_few_tests_is_refused(self):
        with self.assertRaises(RC.CaseError):
            self.run_stub(self.PASS3, 4)

    def test_no_tests_is_refused_even_though_unittest_calls_it_ok(self):
        with self.assertRaises(RC.CaseError):
            self.run_stub(self.EMPTY, 1)

    def test_a_missing_test_file_is_refused(self):
        with self.assertRaises(RC.CaseError):
            self.run_stub(None, 1)


class TestDocumentValidation(unittest.TestCase):
    def base(self):
        return {"schema": RC.SCHEMA, "cases": [{"id": "E03-A-1", "kind": "errno_table", "tiers": ["smoke"]}]}

    def test_a_valid_document_has_no_problems(self):
        self.assertEqual(RC.validate_doc(self.base()), [])

    def test_each_defect_is_reported(self):
        d = self.base(); d["schema"] = "other"; self.assertTrue(RC.validate_doc(d))
        self.assertTrue(RC.validate_doc([]))
        d = self.base(); d["cases"].append(dict(d["cases"][0])); self.assertTrue(RC.validate_doc(d))       # duplicate id
        d = self.base(); d["cases"][0]["kind"] = "nonsense"; self.assertTrue(RC.validate_doc(d))
        d = self.base(); d["cases"][0]["tiers"] = []; self.assertTrue(RC.validate_doc(d))
        d = self.base(); d["cases"][0]["tiers"] = ["nightly"]; self.assertTrue(RC.validate_doc(d))
        d = self.base(); d["cases"][0]["id"] = "X-1"; self.assertTrue(RC.validate_doc(d))
        d = self.base(); d["cases"][0]["kind"] = "blocked"; self.assertTrue(RC.validate_doc(d))            # no reason/owner
        d = self.base(); d["cases"][0].update(kind="blocked", reason="r"); self.assertTrue(RC.validate_doc(d))
        d = self.base(); d["cases"][0].update(kind="blocked", reason="r", owner="o"); self.assertEqual(RC.validate_doc(d), [])

    def test_strict_loads_refuses_duplicate_keys(self):
        self.assertEqual(RC.strict_loads('{"a": 1}'), {"a": 1})
        with self.assertRaises(ValueError):
            RC.strict_loads('{"a": 1, "a": 2}')
        with self.assertRaises(ValueError):
            RC.strict_loads('{"outer": {"k": 1, "k": 1}}')


class TestRunCase(unittest.TestCase):
    def test_a_crashing_handler_is_a_failure_with_its_type(self):
        res = RC.run_case({"id": "E03-C-1", "kind": "errno_table", "spec": {}}, {"cases": [], "invariants": []})
        self.assertEqual(res["status"], "failed")
        self.assertIn("KeyError", res["detail"])

    def test_a_wrong_expectation_is_a_failure(self):
        res = RC.run_case({"id": "E03-C-2", "kind": "errno_table",
                           "spec": {"arch": "mips", "entries": [[89, "EINTR"]]}}, {"cases": [], "invariants": []})
        self.assertEqual(res["status"], "failed")

    def test_blocked_is_blocked_never_passed(self):
        res = RC.run_case({"id": "E03-B-1", "kind": "blocked", "reason": "r", "owner": "o"}, {"cases": [], "invariants": []})
        self.assertEqual(res["status"], "blocked")
        self.assertIn("owner: o", res["detail"])

    def test_a_good_case_passes(self):
        res = RC.run_case({"id": "E03-P-1", "kind": "errno_table", "spec": {"arch": "mips", "entries": [[89, "ENOSYS"]]}},
                          {"cases": [], "invariants": []})
        self.assertEqual(res["status"], "passed")


class TestMainExitCodes(unittest.TestCase):
    """main() against temporary case files (RC.CASES_FILE is redirected; the real file is never touched)."""

    OK = {"id": "E03-T-1", "kind": "errno_table", "tiers": ["smoke", "full"], "title": "ok",
          "spec": {"arch": "mips", "entries": [[89, "ENOSYS"]]}}
    BAD = {"id": "E03-T-2", "kind": "errno_table", "tiers": ["smoke", "full"], "title": "bad",
           "spec": {"arch": "mips", "entries": [[89, "EINTR"]]}}
    BLK = {"id": "E03-T-3", "kind": "blocked", "tiers": ["smoke", "full"], "title": "blk", "reason": "r", "owner": "o"}
    FULL_ONLY = {"id": "E03-T-4", "kind": "errno_table", "tiers": ["full"], "title": "full only",
                 "spec": {"arch": "mips", "entries": [[89, "EINTR"]]}}

    def run_main(self, cases, argv, raw=None):
        doc = {"schema": RC.SCHEMA, "cases": cases, "invariants": []}
        d = tempfile.mkdtemp()
        saved = RC.CASES_FILE
        try:
            path = os.path.join(d, "cases.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(raw if raw is not None else json.dumps(doc))
            RC.CASES_FILE = path
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = RC.main(argv)
                except SystemExit as exc:
                    code = exc.code
            return code, out.getvalue(), err.getvalue()
        finally:
            RC.CASES_FILE = saved
            shutil.rmtree(d, ignore_errors=True)

    def test_all_passing_is_exit_0_and_qualified(self):
        code, out, _ = self.run_main([self.OK], ["--tier", "smoke"])
        self.assertEqual(code, 0)
        self.assertTrue(out.rstrip().endswith("-> QUALIFIED"), out)

    def test_a_failing_case_is_exit_1_and_not_qualified(self):
        code, out, _ = self.run_main([self.OK, self.BAD], ["--tier", "smoke"])
        self.assertEqual(code, 1)
        self.assertIn("NOT QUALIFIED", out)
        self.assertRegex(out, r"(?m)^FAIL +E03-T-2 ")

    def test_a_blocked_case_is_exit_3_and_never_qualified(self):
        code, out, _ = self.run_main([self.OK, self.BLK], ["--tier", "smoke"])
        self.assertEqual(code, 3)
        self.assertIn("NOT QUALIFIED", out)
        self.assertIn("blocked=1", out)

    def test_failure_outranks_blocked(self):
        code, _, _ = self.run_main([self.BAD, self.BLK], ["--tier", "smoke"])
        self.assertEqual(code, 1)

    def test_the_tier_selects_cases(self):
        code, out, _ = self.run_main([self.OK, self.FULL_ONLY], ["--tier", "smoke"])
        self.assertEqual(code, 0)                                         # the failing case is full-only
        code, _, _ = self.run_main([self.OK, self.FULL_ONLY], ["--tier", "full"])
        self.assertEqual(code, 1)

    def test_a_tier_is_required(self):
        code, _, _ = self.run_main([self.OK], [])
        self.assertEqual(code, 2)

    def test_a_partial_replay_is_never_qualified(self):
        code, out, _ = self.run_main([self.OK, self.BAD], ["--tier", "smoke", "--case", "E03-T-1"])
        self.assertEqual(code, 0)
        self.assertIn("NOT QUALIFIED", out)

    def test_an_unknown_case_id_is_a_usage_error(self):
        code, _, err = self.run_main([self.OK], ["--tier", "smoke", "--case", "E03-NOPE"])
        self.assertEqual(code, 2)
        self.assertIn("E03-NOPE", err)

    def test_a_malformed_or_duplicate_key_document_is_exit_2(self):
        code, _, _ = self.run_main([], ["--tier", "smoke"], raw='{"schema": "%s", "cases": [], "cases": []}' % RC.SCHEMA)
        self.assertEqual(code, 2)
        code, _, _ = self.run_main([], ["--tier", "smoke"], raw="{not json")
        self.assertEqual(code, 2)
        code, _, _ = self.run_main([{"id": "E03-Z", "kind": "bogus", "tiers": ["smoke"]}], ["--tier", "smoke"])
        self.assertEqual(code, 2)

    def test_list_does_not_run_anything(self):
        code, out, _ = self.run_main([self.BAD], ["--tier", "smoke", "--list"])
        self.assertEqual(code, 0)
        self.assertIn("E03-T-2", out)

    @unittest.skipUnless(real_available(), "committed QEMU transcripts are not present")
    def test_a_receipt_records_digests_counts_and_replays(self):
        with tempfile.TemporaryDirectory() as rd:
            code, out, _ = self.run_main([self.OK, self.BAD], ["--tier", "smoke", "--receipts", rd])
            self.assertEqual(code, 1)
            files = os.listdir(rd)
            self.assertEqual(len(files), 1)
            with open(os.path.join(rd, files[0]), encoding="utf-8") as fh:
                rec = json.load(fh)
        self.assertEqual(rec["counts"], {"passed": 1, "failed": 1, "blocked": 0})
        self.assertEqual(set(rec["replay"]), {"E03-T-2"})
        self.assertEqual(len(rec["abi_sha256"]), 64)
        self.assertEqual(set(rec["evidence_sha256"]), {"boot-mips-serial.log", "boot-ppc-serial.log"})
        self.assertIn("--case", rec["replay"]["E03-T-2"])


class TestCommittedCaseFile(unittest.TestCase):
    """The committed cases.json is loadable, valid, and keeps its blocked cases visible."""

    def setUp(self):
        with open(RC.CASES_FILE, "rb") as fh:
            self.doc = RC.strict_loads(fh.read().decode("utf-8"))

    def test_it_validates_and_is_coherent(self):
        self.assertEqual(RC.validate_doc(self.doc), [])
        RC.h_meta({}, self.doc)

    def test_both_tiers_have_blocked_cases_so_neither_can_qualify_silently(self):
        for tier in RC.TIERS:
            blocked = [c for c in self.doc["cases"] if tier in c["tiers"] and c["kind"] == "blocked"]
            self.assertGreaterEqual(len(blocked), 1, tier)

    def test_every_smoke_case_is_also_in_full(self):
        for c in self.doc["cases"]:
            if "smoke" in c["tiers"]:
                self.assertIn("full", c["tiers"], c["id"])


if __name__ == "__main__":
    unittest.main()
