#!/usr/bin/env python3
"""Tests of the N04 runner's front door (bead ffw-nx0: "CI selects smoke/full/soak explicitly; mandatory missing cases are blocked/not-run",
"bounded redacted failure diagnostics", "critical test evidence loss marks the result incomplete"): the soak tier, refused inputs, redaction,
descriptor-bounded log reads and the diagnostic log.

    python3 -B -I -m unittest discover -s tests/n04 -p 'test_front_door.py'

Every refusal control is paired with a permitted positive run of the same entry point, so a runner that refuses everything fails here. The
credential in these tests is a synthetic canary, not a real token. Nothing here builds, boots or touches a device.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "n04")
CANARY = "ghp1234567890abcdefSECRETCANARY"
SECRET_PATH_PART = "Authorization: Bearer " + CANARY
SUMMARY = re.compile(r"total=(\d+) passed=(\d+) failed=(\d+) blocked=(\d+)")
LOG = ("running 1 test\ntest playout::tests::n04_x ... ok\n\n"
       "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n")


def _load(name):
    spec = importlib.util.spec_from_file_location("n04_fd_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, HERE)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


rc = _load("run_cases")
case_log = rc.load_case_log()
diag = case_log.load(REPO)


def call(*argv):
    done = subprocess.run([ENTRY] + list(argv), capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=180)
    return done.returncode, done.stdout, done.stderr


def in_process(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rc.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read_all(directory):
    text = ""
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), encoding="utf-8") as handle:
            text += handle.read()
    return text


def case_ends(path):
    ends = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            if rec.get("kind") == "case.end":
                ends[rec["case"]] = rec
    return ends


def write(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def files_of(directory, suffix):
    return [os.path.join(directory, n) for n in sorted(os.listdir(directory)) if n.endswith(suffix)]


class SoakIsNotRun(unittest.TestCase):
    def test_soak_says_why_exits_4_and_judges_nothing_even_with_a_missing_log(self):
        for argv in (("--tier", "soak"), ("--tier", "soak", "--judge", "/nonexistent/central.log"), ("--tier", "soak", "--list")):
            code, out, err = call(*argv)
            self.assertEqual(code, 4, (argv, out, err))
            self.assertIn("N04 soak: NOT RUN", out)
            self.assertIn("This is not a pass.", out)
            self.assertNotIn("QUALIFIED", out.replace("NOT QUALIFIED", ""))
            self.assertNotIn("N04-PROFILES", out)           # no case was planned or judged
            self.assertEqual(err, "")
        self.assertEqual(rc.TIERS, ("smoke", "full"))        # soak never selects a case

    def test_soak_keeps_a_not_run_receipt_and_a_complete_log_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = call("--tier", "soak", "--receipts", tmp)
            self.assertEqual(code, 4, out + err)
            names = sorted(os.listdir(tmp))
            self.assertEqual([re.sub(r"[0-9a-f]{12,16}", "ID", n) for n in names], ["n04-diag-soak-ID.jsonl", "n04-receipt-ID.json"])
            doc = load_json(files_of(tmp, ".json")[0])
            self.assertEqual((doc["tier"], doc["status"], doc["qualified"], doc["exit_code"], doc["results"]), ("soak", "not_run", False, 4, []))
            self.assertTrue(doc["diagnostics"]["complete"], doc["diagnostics"])
            self.assertEqual(case_ends(files_of(tmp, ".jsonl")[0])["N04-SOAK"]["fields"]["status"], "blocked")

    def test_the_other_tiers_still_judge_cases(self):
        code, out, _ = call("--tier", "smoke", "--list")
        self.assertEqual(code, 0)
        self.assertIn("N04-PROFILES", out)


class RefusedInputsAreRedacted(unittest.TestCase):
    def test_a_missing_judge_log_whose_path_holds_a_credential_is_refused_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "absent", SECRET_PATH_PART + ".log")
            keep = os.path.join(tmp, "receipts")
            code, out, err = call("--tier", "smoke", "--judge", missing, "--receipts", keep)
            self.assertEqual(code, 2, out + err)
            self.assertEqual(out, "")                       # refused before any report
            self.assertIn("no such log", err)
            self.assertIn("REDACTED", err)
            self.assertNotIn(CANARY, out + err)
            self.assertEqual([re.sub(r"[0-9a-f]{12,16}", "ID", n) for n in os.listdir(keep)], ["n04-diag-smoke-ID.jsonl"])    # a log, no receipt
            self.assertNotIn(CANARY, read_all(keep))
            path = files_of(keep, ".jsonl")[0]
            self.assertTrue(diag.audit_log(path).complete)
            end = case_ends(path)[rc.FRONT_DOOR_ID]
            self.assertEqual(end["fields"]["status"], "failed")
            self.assertIn("no such log", end["fields"]["detail"])

    def test_a_permitted_log_is_judged_by_the_same_entry_point(self):      # the positive pair of the refusal above
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = call("--tier", "smoke", "--judge", write(tmp, "central.log", LOG))
            self.assertIn(code, (0, 1, 3), out + err)
            self.assertIn("N04 cases: tier=smoke", out)
            self.assertNotIn("no such log", err)

    def test_a_credential_in_a_bad_flag_value_is_not_echoed_by_the_usage_error(self):
        code, out, err = call("--tier", SECRET_PATH_PART)
        self.assertEqual(code, 2)
        self.assertIn("usage error", err)
        self.assertNotIn(CANARY, out + err)
        self.assertEqual(call("--no-such-flag")[0], 2)

    def test_a_directory_an_oversized_log_and_too_many_logs_are_refused_before_any_read(self):
        saved = rc.MAX_LOG_BYTES, rc.MAX_LOGS, rc.Logs
        try:
            with tempfile.TemporaryDirectory() as tmp:
                small = write(tmp, "small.log", "0123456789")
                self.assertIsNone(rc.admit_logs([small]))                    # control: a regular file within the bounds
                rc.MAX_LOG_BYTES = 10
                self.assertIsNone(rc.admit_logs([small]))                    # exactly at the bound is admitted
                big = write(tmp, "big.log", "0123456789X")
                self.assertIn("exceed", rc.admit_logs([big]))
                self.assertIn("exceed", rc.admit_logs([small, small]))       # the bound is on the total
                self.assertIn("not a regular file", rc.admit_logs([tmp]))
                rc.MAX_LOGS = 2
                self.assertIn("too many", rc.admit_logs([small, small, small]))
                touched = []
                rc.Logs = lambda: touched.append("read") or None
                code, out, err = in_process("--tier", "smoke", "--judge", big)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("exceed", err)
                self.assertEqual(touched, [])                                # refused before a Logs object, so before any read
        finally:
            rc.MAX_LOG_BYTES, rc.MAX_LOGS, rc.Logs = saved

    def test_a_receipts_path_that_cannot_be_made_is_reported_without_a_traceback_or_the_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = write(tmp, "a-file", "")
            code, out, err = call("--tier", "smoke", "--receipts", os.path.join(blocker, SECRET_PATH_PART))
            self.assertNotEqual(code, 0)                     # a pass cannot rest on a log that could not be kept
            self.assertNotIn("Traceback", out + err)
            self.assertNotIn(CANARY, out + err)
            self.assertIn("evidence", out)                   # the diag line says the evidence is missing


class BoundedReads(unittest.TestCase):
    """The read of a --judge log is bounded on the OPENED descriptor, so the early path screen cannot be raced."""

    def guarded(self, seconds=20):
        def on_alarm(signum, frame):
            raise AssertionError("the read of a non-regular file blocked")
        signal.signal(signal.SIGALRM, on_alarm)
        signal.alarm(seconds)

    def tearDown(self):
        signal.alarm(0)

    def test_a_regular_log_is_read_once_and_parses_exactly_like_the_plain_reader(self):      # the positive pair of every refusal below
        with tempfile.TemporaryDirectory() as tmp:
            path = write(tmp, "central.log", LOG)
            logs = rc.Logs()
            logs.add(path)
            plain = rc.d01.Logs()
            plain.add(path)
            self.assertEqual(logs.tests, plain.tests)
            self.assertTrue(logs.tests)
            self.assertEqual(logs.files, [(path, rc.sha256_file(path))])          # the caller's path and the digest of the bytes judged
            self.assertEqual(logs.bytes_read, len(LOG.encode("utf-8")))

    def test_growth_after_the_size_check_is_refused_never_truncated_or_read_without_bound(self):
        real = os.fstat

        def stale_size(fd):                           # the file was small when it was checked and has grown since
            s = real(fd)
            return os.stat_result((s.st_mode, s.st_ino, s.st_dev, s.st_nlink, s.st_uid, s.st_gid, 10, int(s.st_atime), int(s.st_mtime), int(s.st_ctime)))

        saved = rc.MAX_LOG_BYTES
        try:
            with tempfile.TemporaryDirectory() as tmp:
                exact = write(tmp, "exact.log", "x" * 100)
                over = write(tmp, "over.log", "x" * 101)
                huge = write(tmp, "huge.log", "x" * 5000)
                rc.MAX_LOG_BYTES = 100
                os.fstat = stale_size
                try:
                    self.assertEqual(len(rc.read_log_bounded(exact, 100)), 100)              # exactly at the bound is read whole
                    for grown in (over, huge):
                        with self.assertRaises(rc.LogRefused) as caught:
                            rc.read_log_bounded(grown, 100)
                        self.assertIn("grew past", str(caught.exception))
                finally:
                    os.fstat = real
                with self.assertRaises(rc.LogRefused) as caught:                        # without the stale size the fstat size says so
                    rc.read_log_bounded(huge, 100)
                self.assertIn("exceed", str(caught.exception))
                first, second = write(tmp, "a.log", "a" * 60), write(tmp, "b.log", "b" * 60)
                logs = rc.Logs()
                logs.add(first)
                with self.assertRaises(rc.LogRefused):                                     # the bound is on all logs together
                    logs.add(second)
        finally:
            rc.MAX_LOG_BYTES = saved
            os.fstat = real

    def test_a_path_replaced_after_the_early_screen_is_refused_by_the_descriptor_without_a_read_or_a_hang(self):
        self.guarded()
        with tempfile.TemporaryDirectory() as tmp:
            for kind in ("fifo", "directory", "device"):
                path = write(tmp, kind + ".log", LOG)
                self.assertIsNone(rc.admit_logs([path]))                                  # the screen passes the regular file
                os.remove(path)
                if kind == "fifo":
                    os.mkfifo(path)
                elif kind == "directory":
                    os.mkdir(path)
                else:
                    os.symlink("/dev/zero", path)
                with self.assertRaises(rc.LogRefused, msg=kind) as caught:
                    rc.Logs().add(path)
                self.assertIn("not a regular file", str(caught.exception))

    def test_main_reports_a_late_replacement_without_a_traceback_and_still_judges_a_regular_log(self):
        self.guarded()
        saved = rc.admit_logs
        rc.admit_logs = lambda paths: None                                               # the early screen has already passed
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fifo = os.path.join(tmp, SECRET_PATH_PART + ".log")
                os.mkfifo(fifo)
                code, out, err = in_process("--tier", "smoke", "--judge", fifo)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("not a regular file", err)
                self.assertNotIn(CANARY, err)
                self.assertNotIn("Traceback", err)
                code, out, err = in_process("--tier", "smoke", "--judge", write(tmp, "central.log", LOG))
                self.assertIn(code, (0, 1, 3), out + err)
                self.assertIn("N04 cases: tier=smoke", out)
        finally:
            rc.admit_logs = saved


class DiagnosticEvidence(unittest.TestCase):
    def test_a_normal_run_writes_a_complete_log_and_a_receipt_that_agrees_with_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = call("--tier", "smoke", "--receipts", tmp)
            self.assertIn("evidence COMPLETE", out, out + err)
            names = sorted(os.listdir(tmp))
            self.assertEqual([re.sub(r"[0-9a-f]{12,16}", "ID", n) for n in names], ["n04-diag-smoke-ID.jsonl", "n04-receipt-ID.json"])
            doc = load_json(files_of(tmp, ".json")[0])
            printed = [int(v) for v in SUMMARY.search(out).groups()]
            s = doc["summary"]
            self.assertEqual(printed, [s["pass"] + s["fail"] + s["blocked"], s["pass"], s["fail"], s["blocked"]])
            self.assertEqual(doc["exit_code"], code)
            self.assertTrue(doc["diagnostics"]["complete"])
            audit = diag.audit_log(files_of(tmp, ".jsonl")[0])
            self.assertTrue(audit.complete)
            self.assertEqual(audit.critical_events, 2 * printed[0] + 1)             # a begin and an end per case, and the run summary

    def test_a_pass_cannot_rest_on_a_log_that_lost_critical_evidence(self):
        passed = [rc.Result("N04-X", "pass", "", "META")]
        healthy = diag.FaultableSink()
        good = case_log.CaseLog.open(REPO, "r1", "full", target=healthy)
        good.record("N04-X", "META", "passed", "")
        evidence = good.finish({"passed": 1})
        self.assertTrue(evidence.complete, evidence.reasons)
        self.assertEqual((rc.exit_code(passed), rc.final_exit(passed, evidence)), (0, 0))
        broken = diag.FaultableSink()
        broken.available = False
        bad = case_log.CaseLog.open(REPO, "r2", "full", target=broken)
        bad.record("N04-X", "META", "passed", "")
        lost = bad.finish({"passed": 1})
        self.assertFalse(lost.complete)
        self.assertEqual((rc.exit_code(passed), rc.final_exit(passed, lost)), (0, 1))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc.report(passed, "full", lost)
        self.assertIn("diagnostic evidence incomplete", out.getvalue())
        self.assertNotIn("-> QUALIFIED", out.getvalue())

    def test_a_receipt_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc.write_receipt(tmp, "full", [], {}, None, "same")
            with self.assertRaises(FileExistsError):
                rc.write_receipt(tmp, "full", [], {}, None, "same")

    def test_printed_and_receipted_detail_is_redacted_and_bounded_but_the_judge_text_and_ordinary_digests_are_not_changed(self):
        digest = "ab" * 32
        raw = "api_key=sk-live-1234567890abcdef; Authorization: Bearer %s; sha256 %s" % (CANARY, digest)
        result = rc.Result("N04-X", "fail", raw)
        self.assertEqual(result.detail, raw)                          # what the judge produced, for its own assertions
        shown = result.as_dict()["detail"]
        self.assertNotIn("sk-live-1234567890abcdef", shown)
        self.assertNotIn(CANARY, shown)
        self.assertIn(digest, shown)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc.report([result], "full")
        self.assertNotIn(CANARY, out.getvalue())
        self.assertIn("REDACTED", out.getvalue())
        with tempfile.TemporaryDirectory() as tmp:
            path = rc.write_receipt(tmp, "full", [result], {}, None, "red")
            self.assertNotIn(CANARY, read_all(tmp))
            self.assertEqual(load_json(path)["results"][0]["detail"], shown)
        long = rc.Result("N04-X", "fail", "word " * 3000)
        self.assertEqual(len(long.detail), 15000)
        bounded = long.as_dict()["detail"]
        self.assertLess(len(bounded), rc.OUTPUT_STR_MAX + 40)
        self.assertRegex(bounded, r"\.\.\.\[\+\d+ chars\]$")


class ReceiptNames(unittest.TestCase):
    def test_judged_log_names_in_the_receipt_are_redacted_and_ordinary_names_and_digests_are_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = write(tmp, SECRET_PATH_PART + ".log", "running 0 tests\n")
            plain = write(tmp, "central.log", "running 0 tests\n\ntest result: ok. 0 passed; 0 failed\n")
            keep = os.path.join(tmp, "receipts")
            code, out, err = call("--tier", "smoke", "--judge", secret, plain, "--receipts", keep)
            self.assertIn(code, (0, 1, 3), out + err)
            doc = load_json(files_of(keep, ".json")[0])
            names = [entry["name"] for entry in doc["logs"]]
            self.assertEqual(len(names), 2)
            self.assertTrue(any("REDACTED" in n for n in names), names)
            self.assertIn("central.log", names)                                          # an ordinary name is kept
            self.assertEqual({e["sha256"] for e in doc["logs"]}, {rc.sha256_file(secret), rc.sha256_file(plain)})
            self.assertNotIn(CANARY, out + err + read_all(keep))


if __name__ == "__main__":
    unittest.main()
