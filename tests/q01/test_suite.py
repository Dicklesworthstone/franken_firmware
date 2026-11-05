"""Tests of Q01 through the shared Q00 runner (scripts/test/q01.suite.json, scripts/test/q00/q01_case.py, q01_floor.py, tests/q01/q00_suite.py).

The logs judged here are SYNTHETIC: built in memory from the case table and the contract by test_judge.Synthetic, written only to temporary directories, and
never kept as evidence. They show that the integration passes what it should and refuses what it should; they say nothing about the Rust. The real
run-suite and the real receipts verifier run as subprocesses. Every plant is judged against the unplanted good log first, in the same run set.
"""
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import run_cases as rc  # noqa: E402
import test_judge as tj  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
TEST = os.path.join(REPO, "scripts", "test")
MANIFEST = os.path.join(TEST, "q01.suite.json")
RUNNER = os.path.join(TEST, "run-suite")
RECEIPTS = os.path.join(TEST, "test_support", "receipts.py")
SUITE = os.path.join(HERE, "q00_suite.py")
FLOOR = os.path.join(TEST, "q00", "q01_floor.py")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)
    return mod


bridge = load(os.path.join(TEST, "q00", "q01_case.py"), "q01_case_under_test")
floor = load(FLOOR, "q01_floor_under_test")


def case_outcomes(stream):
    out = {}
    with open(stream, encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            if rec.get("kind") == "case":
                out[rec["case_id"]] = rec
    return out


def run_suite(tmp, name, text):
    """The whole flow on the real runner. `text` None means no log was given. Returns (exit code, {case id: receipt record}, output)."""
    argv = [sys.executable, "-B", "-I", SUITE, "--artifact-root", os.path.join(tmp, "runs"), "--run-id", "t-" + name]
    if text is not None:
        path = os.path.join(tmp, name + ".log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        argv += ["--log", path]
    done = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    stream = os.path.join(tmp, "runs", "t-" + name, "receipts.jsonl")
    return done.returncode, (case_outcomes(stream) if os.path.exists(stream) else {}), done.stdout + done.stderr


class ManifestAndFloor(unittest.TestCase):
    def setUp(self):
        with open(MANIFEST, encoding="utf-8") as handle:
            self.manifest = json.load(handle)
        self.cases = rc.load_cases()

    def test_the_manifest_registers_exactly_the_case_table_in_order(self):
        self.assertEqual(self.manifest["schema"], "ffw.suite.v1")
        self.assertEqual(self.manifest["suite"], "q01")
        self.assertEqual([c["id"] for c in self.manifest["cases"]], [c["id"] for c in self.cases])
        self.assertEqual(self.manifest["required_cases"], {"full": [c["id"] for c in self.cases]})

    def test_every_case_is_judged_by_the_bridge_from_the_central_log_and_is_blocked_without_one(self):
        for entry, case in zip(self.manifest["cases"], self.cases):
            self.assertEqual(entry["argv"], ["{python}", "-I", "{manifest_dir}/q00/q01_case.py", case["id"]])
            self.assertEqual(entry["tiers"], ["full"])
            self.assertEqual(entry["evidence_class"], "host-simulation")
            self.assertEqual(entry["requires"], {"env": ["FFW_Q01_LOG"]})
            self.assertEqual(entry["env_inherit"], ["FFW_Q01_LOG"])
            self.assertTrue(entry["description"].startswith("[%s, %s] " % (case["group"], case["class"])), entry["id"])
            self.assertIn(case["what"], entry["description"])
            self.assertNotIn("expect", entry)  # no case is a known-defect canary: the planted faults are Rust tests that pass by naming theirs
            self.assertNotIn("blocked", entry)  # nothing is declared blocked: absence is observed, not asserted

    def test_every_requirement_the_manifest_names_is_covered_and_is_the_beads_own_wording(self):
        reqs = self.manifest["requirements"]
        self.assertEqual(set(reqs), {"Q01.AC1", "Q01.AC2", "Q01.AC3"})
        named = {r for c in self.manifest["cases"] for r in c["requirements"]}
        self.assertEqual(named, set(reqs))
        done = subprocess.run([sys.executable, "-B", "-I", RUNNER, "coverage", "--manifest", MANIFEST], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["uncovered_requirements"], [])

    def test_the_floor_is_derived_from_the_case_table_and_the_sources_not_the_manifest(self):
        expected, required = floor.build(rc)
        self.assertEqual(list(required), [c["id"] for c in self.cases])
        self.assertEqual(set(expected), set(required))
        for cid in required:
            self.assertEqual(required[cid], {"proof_class": "host-simulation", "canary": False})
            self.assertEqual(expected[cid], {"mandatory": True, "proof_class": "host-simulation", "canary": False})

    def fake(self, cases, names):
        class Judge:
            load_cases = staticmethod(lambda: cases)
            rust_test_names = staticmethod(lambda: names)
        return Judge

    def test_the_floor_refuses_a_table_that_does_not_match_the_sources(self):
        cases = [{"id": "Q01-X1", "tests": ["a::one", "a::two"]}, {"id": "Q01-X2", "tests": ["a::three"]}]
        names = ["a::one", "a::two", "a::three"]
        expected, required = floor.build(self.fake(cases, names))  # the unplanted control
        self.assertEqual(sorted(required), ["Q01-X1", "Q01-X2"])
        plants = {
            "a test no case covers": (cases, names + ["a::four"], "no case covers"),
            "a case naming a test that is gone": (cases, names[:2], "not in the sources"),
            "a test in two cases": ([cases[0], {"id": "Q01-X2", "tests": ["a::three", "a::one"]}], names, "in two cases"),
            "a duplicate case id": ([cases[0], {"id": "Q01-X1", "tests": ["a::three"]}], names, "duplicate case ids"),
            "an empty table": ([], names, "empty"),
            "no sources": (cases, [], "no unit tests"),
        }
        for label, (c, n, fragment) in plants.items():
            with self.assertRaises(floor.FloorError, msg=label) as raised:
                floor.build(self.fake(c, n))
            self.assertIn(fragment, str(raised.exception), label)

    def test_the_floor_command_never_clobbers_an_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, r = os.path.join(tmp, "e.json"), os.path.join(tmp, "r.json")
            first = subprocess.run([sys.executable, "-B", "-I", FLOOR, "emit", "--expected", e, "--required", r], capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            again = subprocess.run([sys.executable, "-B", "-I", FLOOR, "emit", "--expected", e, "--required", r], capture_output=True, text=True)
            self.assertEqual(again.returncode, 2)
            self.assertIn("cannot write", again.stderr)


class Bridge(unittest.TestCase):
    """q01_case.judge_case: what the judge observed, mapped onto the verdict fields. Pure functions; the unplanted control comes first."""

    def setUp(self):
        self.s = tj.Synthetic()
        self.rc = rc
        self.good = ("good.log", "ab" * 32, self.s.text())
        control = bridge.judge_case(rc, "Q01-C05", [self.good], [])
        self.assertEqual(control["verdict"], "pass", control)

    def judge(self, case_id, text=None, problems=(), logs=None):
        logs = logs if logs is not None else [("t.log", "cd" * 32, self.s.text() if text is None else text)]
        return bridge.judge_case(rc, case_id, logs, list(problems))

    def test_a_case_whose_tests_all_reported_ok_passes_on_positive_evidence(self):
        v = self.judge("Q01-C05")
        self.assertEqual((v["verdict"], v["finalized"], v["mismatches"], v["independent"]), ("pass", True, 0, True))
        n = len(next(c for c in rc.load_cases() if c["id"] == "Q01-C05")["tests"])
        self.assertEqual((v["checks"], v["counters"]["tests_ok"], v["counters"]["tests_absent"]), (n, n, 0))
        self.assertEqual(v["observed"]["logs"], [{"name": "t.log", "sha256": "cd" * 32}])

    def test_the_measurement_cases_count_the_records_they_re_derived(self):
        member = self.judge("Q01-M01")
        self.assertEqual((member["verdict"], member["oracle_kind"], member["counters"]["records_rederived"]), ("pass", "sample", 10))
        plant = self.judge("Q01-M02")
        self.assertEqual((plant["verdict"], plant["counters"]["records_rederived"]), ("pass", 6))

    def test_a_failed_test_fails_its_case_and_names_it(self):
        test = next(c for c in rc.load_cases() if c["id"] == "Q01-C08")["tests"][0]
        v = self.judge("Q01-C08", text=self.s.text(fail={test}))
        self.assertEqual((v["verdict"], v["violation_kinds"], v["observed"]["failed"]), ("fail", {"test_failed": 1}, [test]))
        self.assertGreaterEqual(v["mismatches"], 1)

    def test_a_record_that_does_not_re_derive_fails_the_measurement_case(self):
        records = self.s.member_records()
        next(r for r in records if r["member"] == "spk-kitchen-s12" and r["signal"] == "opposed").update(digest=1)
        v = self.judge("Q01-M01", text=self.s.text(members=records))
        self.assertEqual((v["verdict"], v["violation_kinds"]), ("fail", {"record_mismatch": 1}))
        self.assertIn("counter says silent and the digest says sound", v["first_causal_event"])

    def test_missing_dropped_or_truncated_evidence_is_incomplete_and_never_a_pass(self):
        test = next(c for c in rc.load_cases() if c["id"] == "Q01-C12")["tests"][0]
        cases = {
            "a test absent from the log": self.judge("Q01-C12", text=self.s.text(drop={test})),
            "an ignored test": self.judge("Q01-C12", text=self.s.text(drop={test}) + "test %s ... ignored\n" % test),
            "a name that never got a result": self.judge("Q01-C12", text=self.s.text(drop={test}, noise=False) + "test %s ... \n" % test),
            "no log at all": self.judge("Q01-C12", logs=[], problems=[]),
            "an unreadable log": self.judge("Q01-C12", logs=[], problems=["log_unreadable:x.log:FileNotFoundError"]),
        }
        for label, v in cases.items():
            self.assertEqual((v["verdict"], v["finalized"]), ("incomplete", False), (label, v))
            self.assertTrue(v["incomplete_reasons"], label)
            self.assertNotEqual(v["verdict"], "pass", label)
        self.assertEqual(cases["no log at all"]["incomplete_reasons"], ["no_log"])
        self.assertEqual(cases["an unreadable log"]["incomplete_reasons"], ["log_unreadable:x.log:FileNotFoundError"])
        self.assertEqual(cases["a test absent from the log"]["incomplete_reasons"], ["tests_absent:1"])

    def test_a_log_that_could_not_be_read_makes_the_case_incomplete_even_when_another_log_is_good(self):
        # The unplanted control (setUp) passes this case from the same good log; the only difference here is a second log that was asked for and is unreadable.
        v = self.judge("Q01-C05", logs=[self.good], problems=["log_unreadable:b.log:PermissionError"])
        self.assertEqual((v["verdict"], v["finalized"], v["incomplete_reasons"]), ("incomplete", False, ["log_unreadable:b.log:PermissionError"]))

    def test_read_logs_hashes_what_it_read_and_names_what_it_could_not(self):
        data = b"test a ... ok\n\xff\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.log")
            with open(path, "wb") as handle:
                handle.write(data)
            logs, problems = bridge.read_logs([path, os.path.join(tmp, "gone.log")])
        self.assertEqual(logs, [("a.log", hashlib.sha256(data).hexdigest(), "test a ... ok\n\ufffd\n")])
        self.assertEqual(problems, ["log_unreadable:gone.log:FileNotFoundError"])

    def test_a_dropped_measurement_record_fails_it_rather_than_reading_as_not_run(self):
        v = self.judge("Q01-M01", text=self.s.text(members=[]))
        self.assertEqual(v["verdict"], "fail")
        v = self.judge("Q01-M02", text=self.s.text(plants=[p for p in self.s.plant_records() if p["planted"]]))
        self.assertEqual(v["verdict"], "fail")

    def test_an_unknown_case_is_a_usage_error(self):
        with self.assertRaises(KeyError):
            self.judge("Q01-NOPE")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(bridge.main(["Q01-NOPE"]), 2)
            self.assertEqual(bridge.main([]), 2)
            self.assertEqual(bridge.main(["--help"]), 2)

    def test_the_result_file_carries_the_runners_ids_and_exit_codes_map_to_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            for label, text, want_exit, want_verdict in (("good", self.s.text(), 0, "pass"),
                                                         ("failed", self.s.text(fail={next(c for c in rc.load_cases() if c["id"] == "Q01-C05")["tests"][0]}), 1, "fail"),
                                                         ("absent", "no tests here\n", 2, "incomplete")):
                log, out = os.path.join(tmp, label + ".log"), os.path.join(tmp, label + ".json")
                with open(log, "w", encoding="utf-8") as handle:
                    handle.write(text)
                env = dict(os.environ, FFW_Q01_LOG=log, FFW_RESULT_PATH=out, FFW_RUN_ID="r1", FFW_CASE_ID="Q01-C05", FFW_RESULT_NONCE="n0nce")
                done = subprocess.run([sys.executable, "-B", "-I", os.path.join(TEST, "q00", "q01_case.py"), "Q01-C05"], env=env, capture_output=True, text=True)
                self.assertEqual(done.returncode, want_exit, (label, done.stdout, done.stderr))
                with open(out, encoding="utf-8") as handle:
                    doc = json.load(handle)
                self.assertEqual((doc["schema"], doc["run_id"], doc["case_id"], doc["nonce"], doc["verdict"]), ("ffw.case-result.v1", "r1", "Q01-C05", "n0nce", want_verdict), label)
            # protocol variables without all three ids are refused
            env = dict(os.environ, FFW_Q01_LOG=log, FFW_RESULT_PATH=os.path.join(tmp, "x.json"))
            env.pop("FFW_RUN_ID", None)
            done = subprocess.run([sys.executable, "-B", "-I", os.path.join(TEST, "q00", "q01_case.py"), "Q01-C05"], env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, 2)


class OnTheRealRunner(unittest.TestCase):
    """The whole flow (independent floor, run-suite, receipts.py re-verification) over the good log and over each negative, run once and judged here."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        s = cls.s = tj.Synthetic()
        good = s.text()
        records = s.member_records()
        next(r for r in records if r["member"] == "spk-bedroom-s1" and r["signal"] == "opposed").update(digest=12345)
        cls.failed_test = s.cases[4]["tests"][0]
        lines = good.splitlines()
        first = next(i for i, l in enumerate(lines) if l.startswith("Q01-MEMBER "))
        lines[first] = lines[first][: len(lines[first]) // 2]  # a record cut off mid-line
        cls.variants = {
            "good": good,
            "nolog": None,
            "wrong": s.text(members=records),
            "trunc": good[: int(len(good) * 0.6)],
            "failed": s.text(fail={cls.failed_test}),
            "nodrop": s.text(members=[]),
            "cutrecord": "\n".join(lines) + "\n",
        }
        cls.runs = {name: run_suite(cls.tmp.name, name, text) for name, text in cls.variants.items()}

    def outcomes(self, name):
        return {cid: rec["outcome"] for cid, rec in self.runs[name][1].items()}

    def test_a_real_simulated_campaign_log_is_a_q00_valid_record_per_required_case_and_qualifies(self):
        code, records, out = self.runs["good"]
        self.assertEqual(code, 0, out)
        self.assertEqual(set(self.outcomes("good").values()), {"pass"})
        self.assertEqual(len(records), len(rc.load_cases()))
        self.assertIn("RECEIPTS QUALIFIED", out)
        self.assertIn("Q01 SUITE: PASS", out)
        self.assertIn("required floor: %d cases dropped=0 demoted=0 altered=0" % len(rc.load_cases()), out)
        for cid, rec in records.items():
            self.assertEqual(rec["schema"], "ffw.receipt-stream/1")
            self.assertEqual((rec["proof_class"], rec["canary"], rec["process"]["exit_code"]), ("host-simulation", False, 0), cid)
            oracle = rec["oracle"]
            self.assertEqual((oracle["status"], oracle["finalized"], oracle["independent"], oracle["mismatches"]), ("passed", True, True, 0), cid)
            self.assertGreaterEqual(oracle["checks"], 1, cid)
            self.assertEqual(oracle["name"], "q01.cargo-test.%s" % cid)

    def test_a_missing_run_is_blocked_everywhere_and_is_not_a_pass(self):
        code, records, out = self.runs["nolog"]
        self.assertEqual(code, 1, out)
        self.assertEqual(set(self.outcomes("nolog").values()), {"blocked"})
        self.assertIn("RECEIPTS NOT QUALIFIED", out)
        self.assertIn("Q01 SUITE: FAIL", out)

    def non_pass(self, name):
        return {cid: o for cid, o in self.outcomes(name).items() if o != "pass"}

    def test_wrong_state_fails_exactly_the_measurement_case_that_holds_it(self):
        self.assertEqual(self.runs["wrong"][0], 1)
        self.assertEqual(self.non_pass("wrong"), {"Q01-M01": "fail"})
        self.assertIn("RECEIPTS NOT QUALIFIED", self.runs["wrong"][2])

    def test_a_failed_test_fails_exactly_its_case(self):
        case = next(c["id"] for c in rc.load_cases() if self.failed_test in c["tests"])
        self.assertEqual(self.runs["failed"][0], 1)
        self.assertEqual(self.non_pass("failed"), {case: "fail"})

    def test_a_truncated_log_never_passes_a_case_whose_evidence_was_cut_off_and_says_why(self):
        code, records, out = self.runs["trunc"]
        self.assertEqual(code, 1, out)
        lost = self.non_pass("trunc")
        self.assertTrue(lost)
        self.assertTrue(set(lost.values()) <= {"fail", "blocked"}, lost)
        for cid in lost:
            observed = records[cid]["failure"]["observed"]
            self.assertEqual(observed["oracle_status"], "incomplete", cid)
            self.assertTrue(any(r.startswith(("tests_absent", "blocked")) for r in observed["reasons"]), (cid, observed))
        # Cases whose tests all appear before the cut still pass: the integration judges what is there and refuses what is not.
        self.assertGreater(len(self.outcomes("trunc")) - len(lost), 0)
        self.assertIn("RECEIPTS NOT QUALIFIED", out)

    def test_dropped_critical_evidence_the_campaigns_own_records_fails_the_measurement_cases(self):
        self.assertEqual(self.non_pass("nodrop"), {"Q01-M01": "fail"})
        self.assertEqual(self.runs["nodrop"][0], 1)

    def test_a_record_cut_off_mid_line_fails_the_measurement_case(self):
        self.assertEqual(self.non_pass("cutrecord"), {"Q01-M01": "fail"})
        self.assertEqual(self.runs["cutrecord"][0], 1)

    def test_the_runner_path_and_the_standalone_replay_agree_case_by_case(self):
        # The same judge decides both: a case passes through the runner exactly when it passes standalone, for every variant.
        for name, text in self.variants.items():
            if text is None:
                continue
            log = rc.Log()
            log.add(text, "variant")
            standalone, _notes, _measured = rc.judge_cases(log)
            for result in standalone:
                suite_pass = self.outcomes(name)[result.case] == "pass"
                self.assertEqual(result.status == "pass", suite_pass, (name, result.case, result.status, self.outcomes(name)[result.case]))

    def test_the_standalone_replay_is_untouched_and_still_qualifies_the_good_log(self):
        path = os.path.join(self.tmp.name, "good.log")
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(rc.main(["--judge", path]), 0)
        done = subprocess.run([os.path.join(REPO, "scripts", "e2e", "q01"), "--judge", path], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_case_dropped_from_both_the_manifest_and_its_required_list_is_caught_by_the_floor(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(MANIFEST, encoding="utf-8") as handle:
                text = handle.read().replace("{manifest_dir}", TEST)
            manifest = json.loads(text)
            dropped = manifest["cases"].pop(3)["id"]
            manifest["required_cases"]["full"].remove(dropped)
            path = os.path.join(tmp, "shrunk.suite.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle)
            log = os.path.join(tmp, "good.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(self.variants["good"])
            e, r = os.path.join(tmp, "e.json"), os.path.join(tmp, "r.json")
            subprocess.run([sys.executable, "-B", "-I", FLOOR, "emit", "--expected", e, "--required", r], check=True, capture_output=True)
            env = dict(os.environ, FFW_Q01_LOG=log)
            alone = subprocess.run([sys.executable, "-B", "-I", RUNNER, "run", "--tier", "full", "--manifest", path, "--artifact-root", os.path.join(tmp, "a"), "--run-id", "alone"],
                                   capture_output=True, text=True, env=env)
            self.assertEqual(alone.returncode, 0, "the shrunk manifest passes by itself: " + alone.stdout[-300:])
            floored = subprocess.run([sys.executable, "-B", "-I", RUNNER, "run", "--tier", "full", "--manifest", path, "--floor", r, "--artifact-root", os.path.join(tmp, "b"), "--run-id", "floored"],
                                     capture_output=True, text=True, env=env)
            self.assertEqual(floored.returncode, 1, floored.stdout[-300:])
            self.assertIn("required_cases_violated:1", floored.stdout)
            self.assertIn("NOT QUALIFIED", floored.stdout)
            with open(os.path.join(tmp, "b", "floored", "receipt.json"), encoding="utf-8") as handle:
                problems = json.load(handle)["receipts"]["aggregator"]["problems"]
            self.assertEqual([p["case_id"] for p in problems], [dropped], problems)
            # The separate re-verification, which is handed the floor-derived registry, refuses the same stream and names the case as not run.
            verify = subprocess.run([sys.executable, "-B", "-I", RECEIPTS, "verify", os.path.join(tmp, "b", "floored", "receipts.jsonl"), "--expected", e, "--require", r],
                                    capture_output=True, text=True)
            self.assertEqual(verify.returncode, 1, verify.stdout)
            self.assertIn("[not_run] %s" % dropped, verify.stdout)
            self.assertIn("registry_mismatch", verify.stdout)


class EntryPoint(unittest.TestCase):
    """scripts/e2e/q01 --suite and tests/q01/q00_suite.py: what reaches the runner is only what was asked for."""

    def run_wrapper(self, tmp, name, extra, env=None):
        argv = [os.path.join(REPO, "scripts", "e2e", "q01"), "--suite", "--artifact-root", os.path.join(tmp, "runs"), "--run-id", "w-" + name] + extra
        done = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
        stream = os.path.join(tmp, "runs", "w-" + name, "receipts.jsonl")
        return done, (case_outcomes(stream) if os.path.exists(stream) else {})

    def test_the_e2e_entry_point_runs_the_good_log_through_the_runner_and_the_standalone_replay_is_still_there(self):
        s = tj.Synthetic()
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "good.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(s.text())
            done, records = self.run_wrapper(tmp, "good", ["--log", log])
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual({r["outcome"] for r in records.values()}, {"pass"})
            self.assertEqual(len(records), len(rc.load_cases()))
            self.assertIn("Q01 SUITE: PASS", done.stdout)
            replay = subprocess.run([os.path.join(REPO, "scripts", "e2e", "q01"), "--judge", log], capture_output=True, text=True)
            self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)

    def test_a_log_named_only_in_the_environment_is_not_used(self):
        s = tj.Synthetic()
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "good.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(s.text())
            done, records = self.run_wrapper(tmp, "envonly", [], env=dict(os.environ, FFW_Q01_LOG=log))
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            self.assertEqual({r["outcome"] for r in records.values()}, {"blocked"})
            self.assertIn("Q01 SUITE: FAIL", done.stdout)

    def test_a_log_that_does_not_exist_is_a_usage_error_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            done, records = self.run_wrapper(tmp, "nofile", ["--log", os.path.join(tmp, "absent.log")])
            self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
            self.assertIn("no such log", done.stderr)
            self.assertEqual(records, {})

    def test_a_run_id_that_already_has_a_floor_is_refused_rather_than_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, _ = self.run_wrapper(tmp, "again", [])
            self.assertEqual(first.returncode, 1)
            second, _ = self.run_wrapper(tmp, "again", [])
            self.assertEqual(second.returncode, 2, second.stdout + second.stderr)
            self.assertIn("cannot create", second.stderr)


class ExitCodeCombination(unittest.TestCase):
    """The flow's verdict is the conjunction of run-suite's exit and the separate re-verification's. The real runs above cannot make the two disagree,
    so this one drives q00_suite.main with the three steps scripted, to hold the combination itself: a re-verification that refuses is never swallowed."""

    def drive(self, run_exit, verify_exit, stream=True, args=()):
        suite = load(SUITE, "q00_suite_under_test")
        seen = []
        self.calls = []

        def step(label, argv, env=None):
            seen.append(label[:3])
            self.calls.append((label[:3], list(argv), env))
            if label.startswith("1/3"):
                return 0
            if label.startswith("2/3"):
                if stream:
                    stream_dir = os.path.join(root, "r")
                    os.makedirs(stream_dir)
                    with open(os.path.join(stream_dir, "receipts.jsonl"), "w", encoding="utf-8") as handle:
                        handle.write("{}\n")
                return run_exit
            return verify_exit

        suite.step = step
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as root, redirect_stdout(out):
            code = suite.main(["--artifact-root", root, "--run-id", "r"] + list(args))
        return code, out.getvalue(), seen

    def test_both_steps_clean_is_a_pass(self):
        code, out, seen = self.drive(0, 0)
        self.assertEqual((code, seen), (0, ["1/3", "2/3", "3/3"]))
        self.assertIn("Q01 SUITE: PASS", out)

    def test_a_re_verification_that_disagrees_fails_the_flow_even_when_the_runner_was_clean(self):
        for verify_exit in (1, 3, 5):
            code, out, seen = self.drive(0, verify_exit)
            self.assertEqual(code, verify_exit, out)
            self.assertIn("Q01 SUITE: FAIL", out)
            self.assertNotIn("Q01 SUITE: PASS", out)

    def test_the_runners_own_exit_code_wins_and_is_never_turned_into_a_pass(self):
        for run_exit in (1, 3, 4, 5):
            for verify_exit in (0, 1):
                code, out, _ = self.drive(run_exit, verify_exit)
                self.assertEqual(code, run_exit, (run_exit, verify_exit, out))
                self.assertIn("Q01 SUITE: FAIL", out)

    def test_the_floor_derived_in_step_one_is_what_the_runner_and_the_re_verification_are_both_held_to(self):
        self.drive(0, 0)
        (_, one, _), (_, two, _), (_, three, _) = self.calls

        def opt(argv, flag):
            return argv[argv.index(flag) + 1]

        expected, required = opt(one, "--expected"), opt(one, "--required")
        self.assertNotEqual(expected, required)
        self.assertEqual(opt(two, "--floor"), required)
        self.assertEqual((opt(two, "--manifest"), opt(two, "--tier")), (MANIFEST, "full"))
        self.assertEqual((three[1], os.path.basename(three[2])), ("verify", "receipts.jsonl"))
        self.assertEqual((opt(three, "--expected"), opt(three, "--require")), (expected, required))
        self.assertEqual(os.path.dirname(opt(two, "--floor")), os.path.dirname(expected))

    def test_only_the_log_given_on_the_command_line_reaches_the_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a.log"), os.path.join(tmp, "b.log")
            for path in (a, b):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("x\n")
            self.drive(0, 0, args=["--log", a, b])
            env = self.calls[1][2]
            self.assertEqual(env["FFW_Q01_LOG"], os.pathsep.join((a, b)))
            self.assertNotIn("FFW_Q01_LOG", self.calls[0][2] or {})
            previous = os.environ.get("FFW_Q01_LOG")
            os.environ["FFW_Q01_LOG"] = a
            try:
                self.drive(0, 0)
            finally:
                if previous is None:
                    del os.environ["FFW_Q01_LOG"]
                else:
                    os.environ["FFW_Q01_LOG"] = previous
            self.assertNotIn("FFW_Q01_LOG", self.calls[1][2])

    def test_a_runner_that_wrote_no_stream_is_a_failure_and_is_not_re_verified(self):
        code, out, seen = self.drive(0, 0, stream=False)
        self.assertEqual(code, 1, out)
        self.assertEqual(seen, ["1/3", "2/3"])
        self.assertIn("Q01 SUITE: FAIL", out)
        code, _, seen = self.drive(4, 0, stream=False)
        self.assertEqual(code, 4)


class Cancellation(unittest.TestCase):
    def test_a_cancelled_run_is_exit_4_with_no_pass_and_the_stream_is_not_qualified(self):
        s = tj.Synthetic()
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "good.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(s.text())
            marker = os.path.join(tmp, "holding")
            with open(MANIFEST, encoding="utf-8") as handle:
                manifest = json.loads(handle.read().replace("{manifest_dir}", TEST))
            # The first case is held open so the cancellation arrives while a Q01 case is running.
            manifest["cases"][0]["argv"] = [sys.executable, "-c", "import sys,time; open(sys.argv[1],'w').write('up'); time.sleep(120)", marker]
            path = os.path.join(tmp, "held.suite.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle)
            e, r = os.path.join(tmp, "e.json"), os.path.join(tmp, "r.json")
            subprocess.run([sys.executable, "-B", "-I", FLOOR, "emit", "--expected", e, "--required", r], check=True, capture_output=True)
            proc = subprocess.Popen([sys.executable, "-B", "-I", RUNNER, "run", "--tier", "full", "--manifest", path, "--floor", r, "--artifact-root", os.path.join(tmp, "runs"),
                                     "--run-id", "held"], env=dict(os.environ, FFW_Q01_LOG=log), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, stdin=subprocess.DEVNULL)
            try:
                deadline = time.time() + 30
                while not os.path.exists(marker) and time.time() < deadline:
                    time.sleep(0.05)
                self.assertTrue(os.path.exists(marker), "the held case never started")
                proc.send_signal(signal.SIGTERM)
                out, _ = proc.communicate(timeout=60)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
            self.assertEqual(proc.returncode, 4, out)
            stream = os.path.join(tmp, "runs", "held", "receipts.jsonl")
            outcomes = {cid: rec["outcome"] for cid, rec in case_outcomes(stream).items()}
            self.assertNotIn("pass", set(outcomes.values()), outcomes)
            self.assertEqual(outcomes["Q01-C01"], "cancelled")
            verify = subprocess.run([sys.executable, "-B", "-I", RECEIPTS, "verify", stream, "--expected", e, "--require", r], capture_output=True, text=True)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            self.assertIn("NOT QUALIFIED", verify.stdout)


if __name__ == "__main__":
    unittest.main()
