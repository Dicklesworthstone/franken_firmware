#!/usr/bin/env python3
"""Tests for newc_case.py: the wrong-newc-alignment canaries and their paired positive.

Evidence classes: the verifier under test is the REAL root parser (toolchain/src/mkinitramfs.py);
the planted-negative verifiers are SIMULATED stand-ins (blind, over-strict, crashing, misparsing)
that prove the adapter cannot mistake a bad oracle for a detection.  CLI tests run REAL processes.

Run:  python3 -B scripts/test/test_support/test_newc_case.py
"""
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True

import newc_case as N  # noqa: E402

SCRIPT = os.path.join(HERE, "newc_case.py")
V = N.load_verifier()                      # the real parser
ORACLE_KINDS = ("sample", "state", "protocol", "timing", "property", "output")


def canon(x):
    return json.dumps(x, sort_keys=True)


def check_contract(tc, doc):
    """The documented ffw.case-result.v1 (v1.1) consistency rules, as the runner enforces them."""
    tc.assertIn(doc["verdict"], ("pass", "fail", "incomplete"))
    tc.assertIsInstance(doc["oracle"], str)
    tc.assertTrue(doc["oracle"])
    tc.assertIn(doc["oracle_kind"], ORACLE_KINDS)
    tc.assertIsInstance(doc["independent"], bool)
    tc.assertIsInstance(doc["finalized"], bool)
    for k in ("checks", "mismatches"):
        tc.assertTrue(isinstance(doc[k], int) and not isinstance(doc[k], bool) and doc[k] >= 0, k)
    tc.assertTrue(isinstance(doc["incomplete_reasons"], list) and all(isinstance(r, str) and r for r in doc["incomplete_reasons"]))
    kinds = doc["violation_kinds"]
    tc.assertTrue(isinstance(kinds, dict) and all(isinstance(k, str) and k and isinstance(v, int) and v >= 1 for k, v in kinds.items()))
    tc.assertEqual(sum(kinds.values()), doc["mismatches"], "mismatches are exactly the typed violation counts")
    tc.assertTrue(isinstance(doc["counters"], dict) and all(isinstance(v, int) and not isinstance(v, bool) for v in doc["counters"].values()))
    tc.assertIsInstance(doc["first_causal_event"], str)
    if doc["verdict"] == "pass":
        tc.assertEqual((doc["mismatches"], doc["violation_kinds"], doc["finalized"], doc["incomplete_reasons"]), (0, {}, True, []))
    elif doc["verdict"] == "fail":
        tc.assertGreaterEqual(doc["mismatches"], 1)
        tc.assertTrue(doc["violation_kinds"])
        tc.assertTrue(doc["finalized"] and not doc["incomplete_reasons"])
        tc.assertIsNotNone(doc["expected"])
        tc.assertIsNotNone(doc["observed"])
        tc.assertNotEqual(canon(doc["expected"]), canon(doc["observed"]), "a failure must say what differed")
    else:
        tc.assertEqual(doc["mismatches"], 0, "incomplete never carries manufactured mismatches")
        tc.assertTrue(doc["incomplete_reasons"] or doc["finalized"] is False)


def stub(parse=None, build=None, verify=None):
    """SIMULATED verifier."""
    ok = {"init_size": 14, "devices": {"dev/console": {"rdev": [5, 1]}}}
    return types.SimpleNamespace(
        parse_cpio_bytes=parse or (lambda raw: []),
        build_cpio_bytes=build or (lambda init: b"x"),
        verify_initramfs_bytes=verify or (lambda raw: ok))


def wanted_entries():
    return [{"name": n, "data": d} for n, d in list(N.PROBE) + [(N.TRAILER, b"")]]


def contents(entries):
    return [{"name": n, "data": d} for n, d in list(entries) + [(N.TRAILER, b"")]]


def controls():
    """{correct archive bytes: its exact parsed contents} for every archive in the sweep."""
    return {N.build_archive(e): contents(e) for _, e in N.sweep()}


def accept_everything():
    """SIMULATED blind verifier: right contents for every correct AND every planted archive."""
    table = {}
    for _, entries in N.sweep():
        for bug in [None] + list(N.DEFECTS):
            table[N.build_archive(entries, bug=bug)] = contents(entries)
    return stub(parse=lambda raw: table[raw])


class TestEncoder(unittest.TestCase):
    def test_independent_encoder_agrees_with_the_production_encoder_when_correct(self):
        def same_layout(entry):
            # Hex digits are case-insensitive in newc (the production encoder writes 81A4, this one 81a4);
            # the 110-byte header is compared case-folded and everything after it byte for byte.
            return entry[:110].lower() + entry[110:]
        for name_len in range(1, 5):
            for data_len in range(4):
                with self.subTest(name_len=name_len, data_len=data_len):
                    name, payload = "x" * name_len, b"z" * data_len
                    self.assertEqual(same_layout(N.encode_entry(name, payload)),
                                     same_layout(V.encode_newc_entry(name, 0o100644, data=payload, ino=1)))

    def test_each_defect_changes_the_layout_exactly_as_documented(self):
        # ("ab", b"x"): namesize 3, filesize 1.  Correct: data at 116, next header at 120.
        lengths = {None: 120, "align_unpadded_sum": 116, "omit_header_padding": 117, "omit_data_padding": 117,
                   "nonzero_padding": 120, "align_to_8": 128}
        for bug, length in lengths.items():
            with self.subTest(bug=bug):
                entry = N.encode_entry("ab", b"x", bug=bug)
                self.assertEqual(len(entry), length)
        self.assertEqual(N.encode_entry("ab", b"x", bug="align_unpadded_sum")[113:114], b"x", "data right after the name")
        self.assertEqual(N.encode_entry("ab", b"x")[116:117], b"x")
        wrong = N.encode_entry("ab", b"x", bug="nonzero_padding")
        self.assertEqual((wrong[113:116], wrong[117:120]), (b"\xff" * 3, b"\xff" * 3), "padding present but not zero")
        self.assertEqual(N.encode_entry("ab", b"x", bug="omit_header_padding")[113:114], b"x")
        for bug in N.DEFECTS:
            self.assertNotEqual(N.build_archive(N.PROBE, bug=bug), N.build_archive(N.PROBE), bug)

    def test_unknown_defects_are_refused(self):
        with self.assertRaises(ValueError):
            N.encode_entry("ab", b"x", bug="nonsense")


class TestAgainstTheRealParser(unittest.TestCase):
    def test_each_planted_defect_is_detected_across_the_whole_sweep_with_its_defining_kind(self):
        self.assertEqual(sorted(N.DEFECTS), ["align_to_8", "align_unpadded_sum", "nonzero_padding",
                                             "omit_data_padding", "omit_header_padding"])
        self.assertEqual(len(N.sweep()), 17, "the named probe plus all 16 alignments")
        for name, spec in N.DEFECTS.items():
            with self.subTest(defect=name):
                self.assertEqual(len(N.plan(name)), 17, "every sweep archive is changed by this defect")
                doc = N.canary_result(name, V)
                check_contract(self, doc)
                self.assertEqual((doc["verdict"], doc["oracle"], doc["mismatches"], doc["checks"]),
                                 ("fail", N.ORACLE, 17, 34))
                self.assertEqual(sum(doc["violation_kinds"].values()), 17)
                self.assertIn(spec.kind, doc["violation_kinds"])
                self.assertEqual((doc["counters"]["missed"], doc["counters"]["rejected"]), (0, 17))
                self.assertTrue(doc["first_causal_event"].startswith(name + "["))
        self.assertEqual({s.kind for s in N.DEFECTS.values()}, {"header_padding", "data_padding", "misaligned_header"})

    def test_the_paired_positive_accepts_every_correct_archive(self):
        doc = N.positive_result(V)
        check_contract(self, doc)
        self.assertEqual((doc["verdict"], doc["checks"], doc["mismatches"], doc["violation_kinds"]), ("pass", 17, 0, {}))
        self.assertEqual(len(N.positive_cases()), 16, "all 16 (namesize%4, filesize%4) combinations")

    def test_the_correct_control_is_accepted_so_a_detection_means_something(self):
        parsed = V.parse_cpio_bytes(N.build_archive(N.PROBE))
        self.assertEqual([(e["name"], e["data"]) for e in parsed], list(N.PROBE) + [(N.TRAILER, b"")])

    def test_registry_lists_exactly_the_defects_and_the_positive(self):
        ids = [cid for cid, _ in N.CANARY_CASES]
        self.assertEqual(sorted(ids), sorted([N.CANARY_PREFIX + n for n in N.DEFECTS] + [N.POSITIVE_ID]))
        self.assertEqual(len(ids), len(set(ids)))
        for cid, run in N.CANARY_CASES:
            with self.subTest(case=cid):
                doc = run()
                check_contract(self, doc)
                self.assertEqual(doc["verdict"], "pass" if cid == N.POSITIVE_ID else "fail")

    def test_every_real_parser_rejection_maps_to_a_typed_kind(self):
        good = N.build_archive(N.PROBE)
        header = N.encode_entry("a")
        cases = {
            "truncated": good[:50],
            "misaligned_header": b"X" + good[1:],
            "malformed_header": good[:6] + b"ZZZZZZZZ" + good[14:],
            "duplicate_entry": N.build_archive([("a", b"1"), ("a", b"2")]),
            "bad_path": N.build_archive([("../escape", b"1")]),
            "missing_trailer": header,
            "trailer_payload": N.encode_entry(N.TRAILER, b"hidden", mode=0),
            "trailing_garbage": good + b"junk",
            "bad_name": good[:94] + b"00000000" + good[102:],
        }
        for kind, raw in cases.items():
            with self.subTest(kind=kind), self.assertRaises(ValueError) as cm:
                V.parse_cpio_bytes(raw)
            self.assertEqual(N.classify(str(cm.exception)), kind, str(cm.exception))
        self.assertEqual(N.classify("some message nobody planned for"), "invalid_archive")


class TestAdapterCannotMistakeABadOracleForADetection(unittest.TestCase):
    """SIMULATED verifiers."""

    def test_a_blind_verifier_that_accepts_everything_misses_the_defect(self):
        blind = accept_everything()
        for name in N.DEFECTS:
            with self.subTest(defect=name):
                doc = N.canary_result(name, blind)
                check_contract(self, doc)
                self.assertEqual((doc["verdict"], doc["mismatches"], doc["violation_kinds"]), ("pass", 0, {}))
                self.assertEqual((doc["counters"]["missed"], doc["counters"]["rejected"]), (17, 0))
                self.assertIn("accepted 17 of 17", doc["first_causal_event"])

    def test_a_verifier_with_one_blind_spot_does_not_count_as_a_detection(self):
        """The reason for the sweep: rejecting the probe is not enough if one alignment slips through."""
        for label, entries, planted in N.plan("omit_data_padding"):
            with self.subTest(blind_at=label):
                table = controls()

                def parse(raw, planted=planted, entries=entries):
                    if raw == planted:
                        return contents(entries)       # accepts this one planted archive
                    if raw in table:
                        return table[raw]
                    return V.parse_cpio_bytes(raw)     # real behaviour everywhere else
                doc = N.canary_result("omit_data_padding", stub(parse=parse))
                check_contract(self, doc)
                self.assertEqual((doc["verdict"], doc["violation_kinds"]), ("pass", {}))
                self.assertEqual((doc["counters"]["missed"], doc["counters"]["rejected"]), (1, 16))
                self.assertIn(label, doc["observed"]["labels"])

    def test_a_defect_that_changes_no_archive_is_incomplete_never_a_detection_or_a_pass(self):
        with mock.patch.object(N, "sweep", return_value=[("noop", [("a", b"1234")])]):
            self.assertEqual(N.plan("omit_data_padding"), [], "payload already 4-aligned and the trailer is empty")
            doc = N.canary_result("omit_data_padding", V)
        check_contract(self, doc)
        self.assertEqual((doc["verdict"], doc["violation_kinds"]), ("incomplete", {}))
        self.assertIn("defect_never_manifested", doc["incomplete_reasons"][0])

    def test_an_over_strict_verifier_is_incomplete_not_a_detection(self):
        def reject(raw):
            raise ValueError("non-zero header padding at offset 113..116")
        doc = N.canary_result("align_unpadded_sum", stub(parse=reject))
        check_contract(self, doc)
        self.assertEqual((doc["verdict"], doc["mismatches"], doc["violation_kinds"]), ("incomplete", 0, {}))
        self.assertIn("control_rejected", doc["incomplete_reasons"][0])
        pos = N.positive_result(stub(parse=reject, build=lambda i: (_ for _ in ()).throw(ValueError("no"))))
        check_contract(self, pos)
        self.assertEqual(pos["verdict"], "fail")
        self.assertEqual(pos["violation_kinds"], {"correct_archive_rejected": 17})

    def test_a_crashing_verifier_is_incomplete_in_both_cases(self):
        def crash(raw):
            raise TypeError("boom")
        for doc in (N.canary_result("omit_data_padding", stub(parse=crash)), N.positive_result(stub(parse=crash))):
            check_contract(self, doc)
            self.assertEqual((doc["verdict"], doc["violation_kinds"], doc["finalized"]), ("incomplete", {}, False))
            self.assertIn("verifier_crashed:TypeError", doc["incomplete_reasons"])

    def test_a_verifier_that_crashes_only_on_the_planted_archive_is_incomplete(self):
        table = controls()

        def parse(raw):
            if raw in table:
                return table[raw]
            raise RuntimeError("unexpected state")
        doc = N.canary_result("align_to_8", stub(parse=parse))
        self.assertEqual(doc["verdict"], "incomplete")
        self.assertIn("verifier_crashed:RuntimeError", doc["incomplete_reasons"])

    def test_a_verifier_that_misparses_the_correct_control_is_incomplete(self):
        doc = N.canary_result("align_to_8", stub(parse=lambda raw: []))
        check_contract(self, doc)
        self.assertEqual(doc["verdict"], "incomplete")
        self.assertIn("control_misparsed", doc["incomplete_reasons"][0])

    def test_a_positive_that_parses_to_the_wrong_contents_is_a_content_mismatch(self):
        doc = N.positive_result(stub(parse=lambda raw: []))
        check_contract(self, doc)
        self.assertEqual((doc["verdict"], doc["violation_kinds"]), ("fail", {"content_mismatch": 16}))

    def test_a_production_default_archive_with_the_wrong_init_or_console_is_a_content_mismatch(self):
        good = {"init_size": 14, "devices": {"dev/console": {"rdev": [5, 1]}}}
        for label, verify in (("wrong init size", {"init_size": 13, "devices": good["devices"]}),
                              ("wrong console tuple", {"init_size": 14, "devices": {"dev/console": {"rdev": [0, 5]}}})):
            with self.subTest(label):
                doc = N.positive_result(stub(parse=lambda raw: self._echo(raw), verify=lambda raw, v=verify: v))
                check_contract(self, doc)
                self.assertEqual(doc["violation_kinds"], {"content_mismatch": 1}, doc["observed"])
        self.assertEqual(N.positive_result(stub(parse=lambda raw: self._echo(raw), verify=lambda raw: good))["verdict"], "pass")

    @staticmethod
    def _echo(raw):
        """SIMULATED parser that is right about every correct archive the positive builds."""
        entries = {N.build_archive(e): list(e) + [(N.TRAILER, b"")] for _, e in N.positive_cases()}
        return [{"name": n, "data": d} for n, d in entries[raw]]

    def test_a_rejection_for_the_wrong_reason_carries_the_wrong_kind(self):
        table = controls()

        def rejecting(message):
            def parse(raw):
                if raw in table:
                    return table[raw]
                raise ValueError(message)
            return parse
        doc = N.canary_result("align_unpadded_sum", stub(parse=rejecting("missing TRAILER!!! entry in CPIO archive")))
        self.assertEqual(doc["violation_kinds"], {"missing_trailer": 17})
        self.assertNotIn(N.DEFECTS["align_unpadded_sum"].kind, doc["violation_kinds"],
                         "the registry's expected kind is absent, so the runner fails the canary")
        unknown = N.canary_result("align_unpadded_sum", stub(parse=rejecting("novel complaint")))
        self.assertEqual(unknown["violation_kinds"], {"invalid_archive": 17})


class TestCli(unittest.TestCase):
    """REAL processes, from a working directory with spaces."""

    def run_cli(self, *args, env=None, cwd=None):
        full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        full.update(env or {})
        return subprocess.run([sys.executable, "-B", SCRIPT, *args], cwd=cwd, env=full, capture_output=True,
                              text=True, timeout=120)

    def wire(self, d, cid="q00.newc.canary.x"):
        return {"FFW_RESULT_PATH": os.path.join(d, "result.json"), "FFW_RUN_ID": "run-1", "FFW_CASE_ID": cid,
                "FFW_RESULT_NONCE": "nonce-1"}

    def test_replay_and_positive_write_a_valid_result_and_the_right_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="ffw newc ") as d:
            for args, code, verdict in ([(["replay", "--defect", n], 1, "fail") for n in sorted(N.DEFECTS)]
                                        + [(["positive"], 0, "pass")]):
                with self.subTest(args=args):
                    env = self.wire(d)
                    if os.path.exists(env["FFW_RESULT_PATH"]):
                        os.replace(env["FFW_RESULT_PATH"], env["FFW_RESULT_PATH"] + ".prev")
                    p = self.run_cli(*args, env=env, cwd=d)
                    self.assertEqual(p.returncode, code, p.stdout + p.stderr)
                    doc = json.loads(Path(env["FFW_RESULT_PATH"]).read_text(encoding="utf-8"))
                    self.assertEqual((doc["schema"], doc["run_id"], doc["case_id"], doc["nonce"], doc["verdict"]),
                                     (N.RESULT_SCHEMA, "run-1", "q00.newc.canary.x", "nonce-1", verdict))
                    check_contract(self, doc)
                    self.assertIn("NEWC ", p.stdout)

    def test_without_a_result_path_nothing_is_written_and_the_exit_code_still_reports(self):
        with tempfile.TemporaryDirectory(prefix="ffw newc ") as d:
            p = self.run_cli("replay", "--defect", "align_to_8", cwd=d)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(os.listdir(d), [])

    def test_missing_wire_variables_exit_2_and_write_nothing(self):
        with tempfile.TemporaryDirectory(prefix="ffw newc ") as d:
            for missing in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE"):
                with self.subTest(missing=missing):
                    env = self.wire(d)
                    del env[missing]
                    p = self.run_cli("positive", env=env, cwd=d)
                    self.assertEqual(p.returncode, 2)
                    self.assertIn(missing, p.stderr)
                    self.assertFalse(os.path.exists(env["FFW_RESULT_PATH"]))

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.run_cli("replay", "--defect", "nonsense").returncode, 2)
        self.assertEqual(self.run_cli("replay").returncode, 2)
        self.assertEqual(self.run_cli().returncode, 2)

    def test_a_missing_crashing_or_blind_verifier_is_never_a_detection(self):
        with tempfile.TemporaryDirectory(prefix="ffw newc ") as d:
            crash = os.path.join(d, "crash.py")
            Path(crash).write_text("def parse_cpio_bytes(raw):\n    raise TypeError('x')\n"
                                   "def build_cpio_bytes(i):\n    return b''\n"
                                   "def verify_initramfs_bytes(r):\n    return {}\n", encoding="utf-8")
            blind = os.path.join(d, "blind.py")
            Path(blind).write_text(
                "import sys\nsys.dont_write_bytecode = True\nsys.path.insert(0, %r)\nimport newc_case as N\n"
                "TABLE = {}\n"
                "for label, entries in N.sweep():\n"
                "    want = [{'name': n, 'data': d} for n, d in list(entries) + [(N.TRAILER, b'')]]\n"
                "    for bug in [None] + list(N.DEFECTS):\n"
                "        TABLE[N.build_archive(entries, bug=bug)] = want\n"
                "def parse_cpio_bytes(raw):\n    return TABLE[raw]\n"
                "def build_cpio_bytes(i):\n    return b''\n"
                "def verify_initramfs_bytes(r):\n    return {}\n" % HERE, encoding="utf-8")
            partial = os.path.join(d, "partial.py")
            Path(partial).write_text("def parse_cpio_bytes(raw):\n    return []\n", encoding="utf-8")
            cases = [("missing", os.path.join(d, "absent.py"), 2, "incomplete", "verifier_unavailable"),
                     ("crashing", crash, 2, "incomplete", "verifier_crashed:TypeError"),
                     ("missing API", partial, 2, "incomplete", "verifier_unavailable"),
                     ("blind", blind, 0, "pass", None)]
            for label, path, code, verdict, reason in cases:
                with self.subTest(label):
                    env = self.wire(d)
                    if os.path.exists(env["FFW_RESULT_PATH"]):
                        os.replace(env["FFW_RESULT_PATH"], env["FFW_RESULT_PATH"] + "." + label)
                    p = self.run_cli("replay", "--defect", "align_unpadded_sum", "--verifier", path, env=env, cwd=d)
                    self.assertEqual(p.returncode, code, p.stdout + p.stderr)
                    doc = json.loads(Path(env["FFW_RESULT_PATH"]).read_text(encoding="utf-8"))
                    check_contract(self, doc)
                    self.assertEqual(doc["verdict"], verdict)
                    if reason:
                        self.assertTrue(any(reason in r for r in doc["incomplete_reasons"]), doc["incomplete_reasons"])


if __name__ == "__main__":
    unittest.main()
