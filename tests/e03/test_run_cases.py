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
import re
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

SAMPLE = "\n".join(["FFW_HELLO a", "FFW_PROBE:EPOLL status=PASS fd=4", "FFW_TEST:ERR_EBADF status=PASS errno=9", "tail"])


def real_available() -> bool:
    return all(os.path.exists(os.path.join(RC.RUN_DIR, f)) for f in RC.REAL.values())


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

    def test_a_set_line_that_writes_the_line_already_there_is_refused(self):
        # It plants nothing: the case would be a REAL one under a PLANTED label. The first real run made this
        # reachable (its MIPS GETRANDOM line is the line a planted-UNSEEDED case used to write).
        same = {"op": "set_line", "prefix": "FFW_PROBE:EPOLL", "line": "FFW_PROBE:EPOLL status=PASS fd=4"}
        with self.assertRaises(RC.CaseError) as caught:
            RC.mutate(SAMPLE, [same])
        self.assertIn("changes nothing", str(caught.exception))
        # surrounding whitespace is not a change either
        with self.assertRaises(RC.CaseError):
            RC.mutate(SAMPLE, [dict(same, line="  FFW_PROBE:EPOLL status=PASS fd=4  ")])
        # a real change is still applied
        out = RC.mutate(SAMPLE, [dict(same, line="FFW_PROBE:EPOLL status=PASS fd=5")]).split("\n")
        self.assertEqual(out[1], "FFW_PROBE:EPOLL status=PASS fd=5")

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

    def test_build_reason_and_degraded_keys_accept_the_truth_and_refuse_anything_else(self):
        # classify_run("", ..., "none"): no build line, no guest, and FUTEX (no fallback) is not supported.
        self.check({"build": {"recorded": False, "ok": False, "problem": "unrecorded", "fields": {}},
                    "reason_contains": "build identity", "degraded_contains": "no fallback"})
        self.refuses({"build": {"recorded": True}})
        self.refuses({"build": {"ok": True}})
        self.refuses({"build": {"problem": "libc:"}})                      # a problem the result does not have
        self.refuses({"build": {"fields": {"target": "mips-unknown-linux-musl"}}})   # no fields were recorded
        self.refuses({"reason_contains": "a reason nobody gave"})
        self.refuses({"degraded_contains": "a degradation nobody reported"})

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


class TestTranscriptLineExpectations(unittest.TestCase):
    """``lines_present`` / ``lines_match``: a REAL case pins the values the log itself carries."""

    TEXT = "FFW_HELLO a\nFFW_PROBE:EINTR_READ status=PASS rc=-4\n  FFW_PROBE:THREADS status=PASS tid=60  \nrest"

    def check(self, expect):
        RC._check_result({}, expect, self.TEXT)

    def refuses(self, expect):
        with self.assertRaises(RC.CaseError):
            self.check(expect)

    def test_an_exact_line_is_found_and_a_near_miss_is_not(self):
        self.check({"lines_present": ["FFW_PROBE:EINTR_READ status=PASS rc=-4"]})
        self.check({"lines_present": ["FFW_PROBE:THREADS status=PASS tid=60"]})            # surrounding space is not content
        self.refuses({"lines_present": ["FFW_PROBE:EINTR_READ status=PASS rc=0"]})         # the value is part of the line
        self.refuses({"lines_present": ["FFW_PROBE:EINTR_READ status=PASS"]})              # a prefix is not the line
        self.refuses({"lines_present": ["FFW_PROBE:EINTR_READ status=PASS rc=-4", "FFW_NOPE"]})   # every line is required

    def test_a_pattern_must_match_a_whole_line(self):
        self.check({"lines_match": [r"FFW_PROBE:THREADS status=PASS tid=[1-9][0-9]*"]})
        self.refuses({"lines_match": [r"FFW_PROBE:THREADS status=PASS tid=[1-9]"]})        # matches only a prefix of 60
        self.refuses({"lines_match": [r"FFW_PROBE:THREADS status=PASS tid=0"]})
        self.refuses({"lines_match": [r"tid=60"]})                                          # a fragment is not a line

    def test_the_recorded_guest_kernel_must_equal_the_stated_release(self):
        result = {"guest": {"kernel_release": "2.6.140"}}
        RC._check_result(result, {"kernel_release": "2.6.140"}, "")
        for wrong in ("2.6.14", "2.6.1400", "", "4.9.0"):
            with self.subTest(wrong=wrong), self.assertRaises(RC.CaseError):
                RC._check_result(result, {"kernel_release": wrong}, "")
        with self.assertRaises(RC.CaseError):                              # nothing recorded is not any release
            RC._check_result({"guest": {"kernel_release": None}}, {"kernel_release": "2.6.140"}, "")

    def test_neither_key_is_a_free_pass_when_absent(self):
        self.check({})                                       # no lines asked for, nothing to find
        self.refuses({"lines_present": ["x"], "lines_match": [r"FFW_HELLO a"]})    # one failing key fails the whole


class TestLabelGuard(unittest.TestCase):
    """The fixture-as-live-proof guard: REAL means unmodified; any added line or inline transcript says SYNTHETIC."""

    INSERT = {"op": "insert_after", "prefix": "FFW_HELLO", "line": "FFW_BUILD x"}
    CHANGE = {"op": "set_line", "prefix": "FFW_PROBE:EPOLL", "line": "FFW_PROBE:EPOLL status=FAIL fd=-89"}

    def case(self, title, mutations, kind="classify", source=None):
        return {"id": "E03-X-001", "kind": kind, "title": title, "tiers": ["full"],
                "spec": {"source": source or {"real": "mips"}, "mutations": mutations}}

    def problems(self, title, mutations, **kw):
        return RC.label_problems(self.case(title, mutations, **kw))

    def test_compliant_labels_are_accepted(self):
        self.assertEqual(self.problems("REAL mips log vs its own profile", []), [])                  # unmodified: REAL is true
        self.assertEqual(self.problems("SYNTHETIC baseline: the real mips log plus added lines", [self.INSERT]), [])
        self.assertEqual(self.problems("PLANTED one changed line in the real log", [self.CHANGE]), [])   # changed, none added
        self.assertEqual(self.problems("SYNTHETIC: no QEMU run", [], source={"inline": ["x"]}), [])

    def test_a_real_label_on_a_modified_transcript_is_refused(self):
        for mutations in ([self.CHANGE], [self.INSERT], [self.INSERT, self.CHANGE]):
            with self.subTest(n=len(mutations)):
                found = self.problems("REAL mips log with a tweak", mutations)
                self.assertTrue(any("labelled REAL" in p for p in found), found)

    def test_a_synthetic_label_on_a_case_that_adds_no_line_is_refused(self):
        # A changed or removed real line is PLANTED. SYNTHETIC on it would hide how much of the case is evidence.
        for mutations in ([], [self.CHANGE], [{"op": "drop", "prefix": "FFW_PROBE:EPOLL"}]):
            with self.subTest(n=len(mutations)):
                found = self.problems("SYNTHETIC EPOLL ENOSYS", mutations)
                self.assertTrue(any("says SYNTHETIC but adds no line" in p for p in found), found)
        self.assertEqual(self.problems("SYNTHETIC baseline: added lines", [self.INSERT]), [])      # added: true
        self.assertEqual(self.problems("SYNTHETIC: no QEMU run", [], source={"inline": ["x"]}), []) # inline: true

    def test_added_lines_without_the_synthetic_label_are_refused(self):
        found = self.problems("PLANTED ppc EPOLL -ENOSYS", [self.INSERT, self.CHANGE])
        self.assertTrue(any("does not say SYNTHETIC" in p for p in found), found)

    def test_an_inline_transcript_without_the_synthetic_label_is_refused(self):
        found = self.problems("markers only echoed", [], source={"inline": ["echo FFW_MARKER:REBOOT_REQUEST"]})
        self.assertTrue(any("does not say SYNTHETIC" in p for p in found), found)

    def test_cross_validation_variants_are_checked_by_name(self):
        def xval(*variants):
            return {"id": "E03-XVAL-9", "kind": "cross_validator", "title": "agree on the real log", "tiers": ["full"],
                    "spec": {"variants": [{"name": n, "mutations": m} for n, m in variants]}}
        self.assertEqual(RC.label_problems(xval(("committed", []), ("SYNTHETIC EPOLL ENOSYS", [self.INSERT, self.CHANGE]))), [])
        self.assertTrue(RC.label_problems(xval(("EPOLL ENOSYS", [self.INSERT]))))
        self.assertTrue(RC.label_problems(xval(("REAL committed", [self.CHANGE]))))

    def test_validate_doc_reports_a_mislabelled_case_and_accepts_the_committed_document(self):
        bad = {"schema": RC.SCHEMA, "cases": [self.case("REAL log with a tweak", [self.CHANGE])]}
        self.assertTrue(any("labelled REAL" in e for e in RC.validate_doc(bad)))
        with open(RC.CASES_FILE, "rb") as fh:
            committed = RC.strict_loads(fh.read().decode("utf-8"))
        self.assertEqual(RC.validate_doc(committed), [])

    def test_the_committed_labels_match_what_each_case_does(self):
        with open(RC.CASES_FILE, "rb") as fh:
            cases = {c["id"]: c for c in RC.strict_loads(fh.read().decode("utf-8"))["cases"]}
        for cid in ("E03-CLASS-001", "E03-CLASS-002", "E03-BUILD-001", "E03-BUILD-002", "E03-SEED-001"):
            self.assertEqual(cases[cid]["spec"]["mutations"], [], cid)               # REAL: the run, unmodified
            self.assertRegex(cases[cid]["title"], r"\bREAL\b", cid)
        for cid in ("E03-CLASS-003", "E03-CLASS-004"):                                # PLANTED: one line removed
            self.assertEqual([m["op"] for m in cases[cid]["spec"]["mutations"]], ["drop"], cid)
            self.assertIn("PLANTED", cases[cid]["title"])
            self.assertIsNone(re.search(r"\bREAL\b", cases[cid]["title"]), cid)
        for cid, case in cases.items():
            if case["kind"] in ("classify", "cli") and re.search(r"\bSYNTHETIC\b", case["title"]):
                spec = case["spec"]
                self.assertTrue("inline" in spec["source"] or any(m["op"] == "insert_after" for m in spec["mutations"]), cid)


class TestSourceTextCheck(unittest.TestCase):
    """E03-STOCK-001's check: it must pass on the real contract and source, and refuse each planted defect."""

    @classmethod
    def setUpClass(cls):
        with open(RC.CASES_FILE, "rb") as fh:
            doc = RC.strict_loads(fh.read().decode("utf-8"))
        cls.spec = next(c["spec"] for c in doc["cases"] if c["id"] == "E03-STOCK-001")
        with open(os.path.join(RC.REPO, cls.spec["doc"]), encoding="utf-8") as fh:
            cls.doc = fh.read()
        with open(os.path.join(RC.REPO, cls.spec["rust"]), encoding="utf-8") as fh:
            cls.rust = fh.read()

    def refuses(self, doc=None, rust=None, spec=None):
        with self.assertRaises(RC.CaseError):
            RC.check_source_text(self.doc if doc is None else doc, self.rust if rust is None else rust,
                                 self.spec if spec is None else spec)

    def test_the_real_contract_and_source_pass(self):
        RC.check_source_text(self.doc, self.rust, self.spec)
        header, rows = RC.contract_matrix(self.doc, "Capability")
        self.assertEqual(sum(h.startswith("Stock ") for h in header), 2)
        self.assertGreaterEqual(len(rows), self.spec["min_rows"])

    def test_an_escaped_pipe_belongs_to_its_cell_and_an_unescaped_one_splits_it(self):
        table = "| Capability | Stock PPC `2.6.14` |\n|---|---|\n| flags `A\\|B` | unqualified |\n"
        header, rows = RC.contract_matrix(table, "Capability")
        self.assertEqual(rows, [["flags `A|B`", "unqualified"]])               # two cells, the pipe kept
        ragged = table + "| flags `A|B` | unqualified |\n"                     # unescaped: three cells, not two
        _, rows = RC.contract_matrix(ragged, "Capability")
        self.assertEqual([len(r) for r in rows], [2, 3])

    def test_a_stock_cell_that_claims_a_result_is_refused(self):
        row = " | unqualified | unqualified | Required; hard boot gate |"
        self.assertIn(row, self.doc)                                        # the mutation must apply
        self.refuses(doc=self.doc.replace(row, " | observed | unqualified | Required; hard boot gate |", 1))
        self.refuses(doc=self.doc.replace(row, " | unqualified |  | Required; hard boot gate |", 1))   # empty cell

    def test_verified_wording_is_refused_in_the_contract_and_in_the_source(self):
        self.refuses(doc=self.doc + "\nVerifiedAvailable\n")
        self.refuses(rust=self.rust + "\n// VerifiedAbsent\n")

    def test_a_missing_stock_column_or_missing_table_is_refused(self):
        self.assertIn("Stock MIPS", self.doc)
        self.refuses(doc=self.doc.replace("Stock MIPS", "Harness MIPS", 1))
        self.refuses(doc=self.doc.replace("| Capability", "| Thing", 1))

    def test_a_ragged_row_and_a_too_small_matrix_are_refused(self):
        row = " | unqualified | unqualified | Required; hard boot gate |"
        self.refuses(doc=self.doc.replace(row, " | unqualified | Required; hard boot gate |", 1))   # one cell short
        self.refuses(spec=dict(self.spec, min_rows=10_000))

    def test_the_rust_gate_must_exist_be_tested_and_run_before_any_status(self):
        for needle in self.spec["rust_must_contain"]:
            self.assertIn(needle, self.rust)
            # every occurrence goes: the check is satisfied by any one that remains
            mutated = self.rust.replace(needle, needle[::-1])
            self.assertNotIn(needle, mutated)                               # the mutation really removed it
            self.refuses(rust=mutated)
        gate, statuses = self.spec["rust_order"]
        self.refuses(rust=statuses + "\n" + self.rust)                      # a status read ahead of the gate
        no_gate = self.rust.replace(gate, gate[::-1])
        self.assertNotIn(gate, no_gate)
        self.refuses(rust=no_gate)


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


@unittest.skipUnless(real_available(), "the committed central-run transcripts are not present")
class TestRealEvidenceHandlers(unittest.TestCase):
    DROP_PARTIAL = {"op": "drop", "prefix": "FFW_TEST:PARTIAL_WRITE "}
    EPOLL_ENOSYS = {"op": "set_line", "prefix": "FFW_PROBE:EPOLL", "line": "FFW_PROBE:EPOLL status=FAIL fd=-89"}
    PROFILE = {"ppc": "harness-ppc-4.9", "mips": "harness-mips-4.19"}

    def refuses(self, handler, spec):
        with self.assertRaises(RC.CaseError):
            handler(spec)

    def classify_spec(self, expect, arch="ppc", mutations=None):
        return {"source": {"real": arch}, "profile": self.PROFILE[arch], "mutations": mutations or [], "expect": expect}

    def test_classify_accepts_the_right_expectation_and_refuses_a_wrong_one(self):
        RC.h_classify(self.classify_spec({"verdict": "green", "evidence": "matching-guest"}))
        self.refuses(RC.h_classify, self.classify_spec({"verdict": "red"}))
        self.refuses(RC.h_classify, self.classify_spec({"evidence": "non-matching-guest"}))
        # The real MIPS run is degraded by its unseeded GETRANDOM, never green: the two ISAs are not interchangeable.
        RC.h_classify(self.classify_spec({"verdict": "degraded", "degraded_contains": "GETRANDOM"}, arch="mips"))
        self.refuses(RC.h_classify, self.classify_spec({"verdict": "green"}, arch="mips"))
        # A planted removal turns the run red; green is then the wrong expectation.
        RC.h_classify(self.classify_spec({"verdict": "red"}, mutations=[self.DROP_PARTIAL]))
        self.refuses(RC.h_classify, self.classify_spec({"verdict": "green"}, mutations=[self.DROP_PARTIAL]))

    def test_h_classify_distrusts_a_green_whose_build_identity_is_not_ok(self):
        # The classifier cannot return this by construction (a bad identity is a reason, so the verdict is red),
        # so the defensive invariant in h_classify is only reachable by stubbing the classifier itself.
        import copy
        from unittest import mock
        spec = self.classify_spec({"verdict": "green"})
        real = RC.A.classify_run(RC.build_text(spec), spec["profile"])
        self.assertEqual((real["verdict"], real["build"]["ok"]), ("green", True))     # the unstubbed baseline is green
        RC.h_classify(spec)
        forged = copy.deepcopy(real)
        forged["build"]["ok"] = False
        with mock.patch.object(RC.A, "classify_run", return_value=forged):
            with self.assertRaises(RC.CaseError) as caught:
                RC.h_classify(spec)
        self.assertIn("recorded build identity", str(caught.exception))

    def test_cli_accepts_the_right_exit_and_refuses_a_wrong_one(self):
        base = {"source": {"real": "ppc"}, "mutations": [], "profile": "harness-ppc-4.9", "exit": 0, "verdict": "green"}
        RC.h_cli(base)
        self.refuses(RC.h_cli, dict(base, exit=1))                      # wrong exit code
        self.refuses(RC.h_cli, dict(base, verdict="red"))               # right exit, wrong verdict
        RC.h_cli(dict(base, source={"real": "mips"}, profile="harness-mips-4.19", exit=4, verdict="degraded"))
        self.refuses(RC.h_cli, dict(base, source={"real": "mips"}, profile="harness-mips-4.19"))   # mips is not green
        RC.h_cli({"profile": "no-such", "exit": 2, "source": {"real": "mips"}, "mutations": []})
        self.refuses(RC.h_cli, {"profile": "harness-mips-4.19", "exit": 0, "verdict": "green", "missing_file": True})

    def test_cross_validator_refuses_a_wrong_root_or_ours_expectation(self):
        ok = {"real": "ppc", "profile": "harness-ppc-4.9",
              "variants": [{"name": "v", "mutations": [], "root": "PASS", "ours": "green"}]}
        RC.h_cross_validator(ok)
        self.refuses(RC.h_cross_validator, {**ok, "variants": [dict(ok["variants"][0], root="FAIL")]})
        self.refuses(RC.h_cross_validator, {**ok, "variants": [dict(ok["variants"][0], ours="red")]})

    def stub_classifier(self, verdict):
        from unittest import mock
        return mock.patch.object(RC.A, "classify_run", lambda text, profile, mode="full-system": {"verdict": verdict})

    def test_cross_validator_refuses_validators_that_disagree_on_green_or_red(self):
        # The stated expectations match what each side returns, so only the agreement rule can object.
        ppc = {"real": "ppc", "profile": "harness-ppc-4.9"}
        with self.stub_classifier("red"):          # root PASSES the unmodified run while ours says red
            self.refuses(RC.h_cross_validator, {**ppc, "variants": [
                {"name": "root passes", "mutations": [], "root": "PASS", "ours": "red"}]})
        with self.stub_classifier("green"):        # root FAILS a run with PARTIAL_WRITE removed while ours says green
            self.refuses(RC.h_cross_validator, {**ppc, "variants": [
                {"name": "root fails", "mutations": [self.DROP_PARTIAL], "root": "FAIL", "ours": "green"}]})
        # and the same two variants agree when the classifier answers what the root does
        with self.stub_classifier("green"):
            RC.h_cross_validator({**ppc, "variants": [{"name": "agree", "mutations": [], "root": "PASS", "ours": "green"}]})
        with self.stub_classifier("red"):
            RC.h_cross_validator({**ppc, "variants": [
                {"name": "agree", "mutations": [self.DROP_PARTIAL], "root": "FAIL", "ours": "red"}]})

    def test_a_degraded_verdict_is_judged_by_the_declared_root_outcome(self):
        # Degraded is a run that finished with classified gaps. The root accepts an unseeded GETRANDOM as a completed
        # run (PASS) but rejects an optional call that failed with -ENOSYS in a way it does not accept (FAIL), so
        # for degraded the declared root value is the contract, and a wrong declaration is still refused.
        mips = {"real": "mips", "profile": "harness-mips-4.19"}
        RC.h_cross_validator({**mips, "variants": [
            {"name": "REAL committed run", "mutations": [], "root": "PASS", "ours": "degraded"}]})
        RC.h_cross_validator({**mips, "variants": [
            {"name": "PLANTED EPOLL ENOSYS", "mutations": [self.EPOLL_ENOSYS], "root": "FAIL", "ours": "degraded"}]})
        self.refuses(RC.h_cross_validator, {**mips, "variants": [
            {"name": "PLANTED EPOLL ENOSYS", "mutations": [self.EPOLL_ENOSYS], "root": "PASS", "ours": "degraded"}]})
        self.refuses(RC.h_cross_validator, {**mips, "variants": [
            {"name": "REAL committed run", "mutations": [], "root": "PASS", "ours": "green"}]})

    # ---- identity: the committed run is pinned, and receipt, raw bytes and transcript must agree

    def committed_identity_spec(self):
        with open(RC.CASES_FILE, "rb") as fh:
            doc = RC.strict_loads(fh.read().decode("utf-8"))
        return [c for c in doc["cases"] if c["id"] == "E03-IDENT-001"][0]["spec"]

    @contextlib.contextmanager
    def run_copy(self):
        """A private copy of the committed run directory (same directory name, which the pin requires) with
        RC.RUN_DIR pointed at it. Yields the copy's path."""
        with tempfile.TemporaryDirectory() as scratch:
            copy = os.path.join(scratch, RC.RUN_ID)
            os.makedirs(copy)
            for name in os.listdir(RC.RUN_DIR):
                if os.path.isfile(os.path.join(RC.RUN_DIR, name)):
                    shutil.copy(os.path.join(RC.RUN_DIR, name), os.path.join(copy, name))
            saved = RC.RUN_DIR
            RC.RUN_DIR = copy
            try:
                yield copy
            finally:
                RC.RUN_DIR = saved

    def edit_receipt(self, copy, edit):
        """Apply a lie to the copy's receipt and return the new receipt digest, so the spec can be re-pinned."""
        path = os.path.join(copy, RC.RECEIPT_NAME)
        with open(path, encoding="utf-8") as fh:
            receipt = json.load(fh)
        edit(receipt)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh, indent=1, sort_keys=True)
        return RC.sha256_file(path)

    def test_identity_accepts_the_committed_run_and_an_exact_copy(self):
        spec = self.committed_identity_spec()
        RC.h_identity(spec)
        with self.run_copy():
            RC.h_identity(spec)

    def test_identity_refuses_bytes_that_differ_from_the_pin(self):
        spec = self.committed_identity_spec()
        for victim in (RC.REAL["ppc"], RC.STDOUT_CAPTURE["mips"], RC.STDERR_CAPTURE["ppc"]):
            with self.subTest(file=victim), self.run_copy() as copy:
                with open(os.path.join(copy, victim), "ab") as fh:
                    fh.write(b"\nFFW_NOTE:changed\n")
                self.refuses(RC.h_identity, spec)

    def test_identity_refuses_a_spec_that_pins_another_run_or_other_bytes(self):
        spec = self.committed_identity_spec()
        self.refuses(RC.h_identity, dict(spec, run_id="0" * 32))
        self.refuses(RC.h_identity, dict(spec, receipt_sha256="0" * 64))
        self.refuses(RC.h_identity, dict(spec, sources_sha256={}))                       # the pinned tree is part of the pin
        short = json.loads(json.dumps(spec))
        short["sources_sha256"].pop("src/e03_judge/net.rs")                              # pinning only part of it fails too
        self.refuses(RC.h_identity, short)
        for arch, key, value in (("ppc", "serial_sha256", "0" * 64), ("mips", "stdout_sha256", "0" * 64),
                                 ("mips", "unseeded", []), ("ppc", "unseeded", ["GETRANDOM"]), ("ppc", "probe_lines", 29)):
            wrong = json.loads(json.dumps(spec))
            wrong["guests"][arch][key] = value
            with self.subTest(arch=arch, key=key):
                self.refuses(RC.h_identity, wrong)

    def test_identity_refuses_an_edited_receipt_even_when_it_is_re_pinned(self):
        # Re-pinning the edited receipt's digest removes the digest objection, so only the agreement checks between
        # the receipt, the raw bytes and the transcript can refuse. Each lie must still be caught by them.
        lies = {
            "a different build identity": lambda r: r["guests"]["ppc"]["build_identity"].update(rustc="9.9.9"),
            "a hidden unseeded capability": lambda r: r["guests"]["mips"].update(unseeded_capabilities=[]),
            "an invented unsupported capability": lambda r: r["guests"]["ppc"].update(unsupported_capabilities=["FUTEX"]),
            "a different target": lambda r: r["guests"]["mips"].update(target_triple="powerpc-unknown-linux-musl"),
            "a probe line that is not the transcript's":
                lambda r: r["guests"]["ppc"]["probes"]["FFW_PROBE:TLS"].update(raw="FFW_PROBE:TLS status=PASS tp=0"),
            "a booted init that is not the built binary": lambda r: r["guests"]["mips"].update(booted_init_sha256="0" * 64),
            "a failed run called PASS": lambda r: r["guests"]["ppc"].update(qemu_exit_code=1),
            "sources not bound to the binary":
                lambda r: r["guests"]["mips"]["build_manifest"].update(sources_bound_to_binary=False),
            "a forbidden hit": lambda r: r["guests"]["ppc"].update(forbidden_hits=["panic"]),
            "a missing probe": lambda r: r["guests"]["mips"]["probes"].pop("FFW_PROBE:FUTEX"),
            "another run id": lambda r: r.update(run_id="0" * 32),
            "a kernel that is not the transcript's": lambda r: r["guests"]["mips"].update(kernel_version="Linux version 2.6.14"),
            # the gap the first central run left: a receipt that binds only part of the crate tree
            "a nested source digest dropped":
                lambda r: r["guests"]["mips"]["build_manifest"]["sources_sha256"].pop("src/e03_probes/net.rs"),
            "a source digest that is not the committed blob":
                lambda r: r["guests"]["ppc"]["build_manifest"]["sources_sha256"].update({"src/main.rs": "0" * 64}),
            "a source file nobody pinned": lambda r: r["guests"]["ppc"]["build_manifest"]["sources_sha256"].update({"src/extra.rs": "1" * 64}),
        }
        base = self.committed_identity_spec()
        for what, edit in lies.items():
            with self.subTest(lie=what), self.run_copy() as copy:
                spec = json.loads(json.dumps(base))
                spec["receipt_sha256"] = self.edit_receipt(copy, edit)
                with self.assertRaises(RC.CaseError, msg=what):
                    RC.h_identity(spec)


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
