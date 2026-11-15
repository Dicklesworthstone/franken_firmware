"""Runner tests: synthetic libtest text tests parsing only, never Rust execution.
Actual subprocess tests exercise exit/timeout handling with Python children only.
"""
import importlib.util
import io
import hashlib
import shlex
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location("p03_runner", Path(__file__).with_name("run_owner.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def receipt_rows():
    command = shlex.join(M.command("smoke")[M.command("smoke").index("--") + 1:])
    command_hash = hashlib.sha256(command.encode()).hexdigest()
    root = {"schema": "rch.source_content_root.v1", "ordinal": 0, "project_id": "fixture",
            "local_root": str(M.ROOT), "remote_root": "/fixture/source", "root_hash": "c" * 64,
            "is_primary": True, "mode": "full", "filter_policy": {"schema": "rch.source_content_filter.v1", "include_patterns": None,
                "exclude_patterns": [], "delete_extraneous": False, "checksum_transfer": True},
            "file_count": 1, "byte_count": 1, "files": [
                {"path": "Cargo.toml", "sha256": "a" * 64, "byte_count": 1, "executable": False}]}
    root["content_root"] = hashlib.sha256(json.dumps(root, separators=(",", ":")).encode()).hexdigest()
    receipt = {"schema": "rch.source_content_receipt.v1", "worker_id": "fixture-worker",
               "build_id": "12345", "command_sha256": command_hash, "command_exit_code": 0,
               "root_count": 1, "roots": [root]}
    receipt["receipt_root"] = hashlib.sha256(json.dumps(receipt, separators=(",", ":")).encode()).hexdigest()
    terminal = {"api_version": "1.0", "command": command, "outcome": "completed", "location": "remote",
                "worker_id": "fixture-worker", "remote_exit_code": 0,
                "admission": {"terminal_acknowledged": True, "strict_remote": True,
                              "remote_build_id": "12345", "worker_id": "fixture-worker"}}
    return "[RCH] source content receipt: " + json.dumps(receipt) + "\n" + json.dumps(terminal) + "\n"


def transcript(names=M.REQUIRED):
    return ("     Running tests/journal_process.rs (target/debug/deps/journal_process-fixture)\n"
            + f"running {len(names)} tests\n" + "".join(f"test {name} ... ok\n" for name in names)
            + f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
            + receipt_rows())


class OwnerRunnerTests(unittest.TestCase):
    def setUp(self):
        self.case = M.W.Case("p03_parser_fixture", "cargo-test", M.command("smoke"), M.ROOT)
        self.loss = {"dropped_bytes": 0}

    def judge(self, text, **fields):
        return M.evaluate(self.case, M.W.Outcome(output=text, **fields), self.loss, 0)

    def test_required_positive_and_every_missing_case(self):
        self.assertEqual(self.judge(transcript())["status"], "passed")
        for omitted in M.REQUIRED:
            with self.subTest(omitted=omitted):
                result = self.judge(transcript([n for n in M.REQUIRED if n != omitted]))
                self.assertNotEqual(result["status"], "passed")
                self.assertIn(omitted, result["required_cases_missing"])

    def test_zero_tests_failure_timeout_and_missing_terminal(self):
        self.assertNotEqual(self.judge(transcript([]))["status"], "passed")
        for fields in ({"rc": 1}, {"rc": None, "timed_out": True}, {"rc": None},
                       {"capture_error": "disk full"}, {"truncated": True}):
            self.assertNotEqual(self.judge(transcript(), **fields)["status"], "passed")

    def test_actual_bounded_capture_drains_all_bytes_and_exposes_loss(self):
        data = b"real collector input\n" * 100
        output = io.BytesIO()
        loss = M.collect(io.BytesIO(data), output, cap=51)
        self.assertEqual(output.getvalue(), data[:51])
        self.assertEqual(loss["seen_bytes"], len(data))
        self.assertEqual(loss["dropped_bytes"], len(data) - 51)
        result = M.evaluate(self.case, M.W.Outcome(output=transcript()), loss, 0)
        self.assertNotEqual(result["status"], "passed")
        self.assertNotEqual(M.evaluate(self.case, M.W.Outcome(output=transcript()), None, 0)["status"], "passed")

    def test_real_python_exit_and_timeout_are_never_passes(self):
        root = Path(tempfile.mkdtemp(prefix="p03-runner-tests-"))
        for name, code, timeout in (("error", "raise SystemExit(7)", 2),
                                    ("timeout", "import time; time.sleep(.2)", .01)):
            outcome = M.W.launch([sys.executable, "-c", code], cwd=str(root), env=os.environ,
                                 timeout_s=timeout, log_dir=root, name=name)
            self.assertNotEqual(M.evaluate(self.case, outcome, self.loss, 0)["status"], "passed")
            if name == "error":
                self.assertEqual(outcome.rc, 7)
            else:
                self.assertTrue(outcome.timed_out)
                self.assertIsNotNone(outcome.recovery)
                # This own short Python child exits naturally; never kill RCH.
                deadline = time.monotonic() + 2
                while not (root / (name + ".rc")).exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue((root / (name + ".rc")).exists())

    def test_conflicting_replayed_and_wrong_count_falsifiers(self):
        good = transcript()
        row = f"test {M.REQUIRED[0]} ... ok\n"
        count = len(M.REQUIRED)
        for bad in (good.replace(row, row + row), good.replace(row, row + row.replace("ok", "FAILED")),
                    good.replace(f"{count} passed", f"{count - 1} passed"),
                    good.replace(f"running {count} tests", f"running {count + 1} tests"),
                    good.replace("tests/journal_process.rs", "tests/unrelated.rs"),
                    good.replace(row, row.replace("ok", "ignored"))):
            self.assertNotEqual(bad, good, "the planted failure must change the transcript")
            self.assertNotEqual(self.judge(bad)["status"], "passed")
        replay = ("Running tests/other.rs (target/debug/deps/other)\nrunning 1 test\n" + row
                  + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n")
        self.assertNotEqual(self.judge(good + replay)["status"], "passed")

    def test_missing_malformed_conflicting_and_unbound_receipts(self):
        good = transcript()
        for bad in (good.replace(receipt_rows(), ""), good + receipt_rows(),
                    good.replace('"build_id": "12345"', '"build_id": "12346"'),
                    good.replace('"command_exit_code": 0', '"command_exit_code": 1'),
                    good.replace('"root_count": 1', '"root_count": 0'),
                    good.replace('"strict_remote": true', '"strict_remote": false'),
                    good.replace('"roots": [', '"roots": broken[')):
            self.assertNotEqual(self.judge(bad)["status"], "passed")

    def test_mutated_nested_digest_with_recomputed_outer_is_rejected(self):
        good = transcript()
        row = next(line for line in good.splitlines() if line.startswith("[RCH] source content receipt:"))
        for mutation in ("nested_digest", "executable_type"):
            doc = json.loads(row.split(":", 1)[1])
            root = doc["roots"][0]
            if mutation == "nested_digest":
                root["content_root"] = "0" * 64
            else:
                root["files"][0]["executable"] = 0
                preimage = {key: value for key, value in root.items() if key != "content_root"}
                root["content_root"] = hashlib.sha256(json.dumps(preimage, separators=(",", ":")).encode()).hexdigest()
            preimage = {key: value for key, value in doc.items() if key != "receipt_root"}
            doc["receipt_root"] = hashlib.sha256(json.dumps(preimage, separators=(",", ":")).encode()).hexdigest()
            bad = good.replace(row, "[RCH] source content receipt: " + json.dumps(doc))
            self.assertNotEqual(self.judge(bad)["status"], "passed", mutation)

    def test_interleaved_stderr_metadata_does_not_end_stdout_block(self):
        # Sanitized shape observed in real full-v4: next Doc-tests header
        # precedes prior stdout footer; its own running/footer follows later.
        good = transcript().replace("test result: ok.", "   Doc-tests example\ntest result: ok.", 1)
        good += "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured\n"
        self.assertEqual(self.judge(good)["status"], "passed")

    def test_early_identity_is_visible_before_python_child_exit(self):
        root = Path(tempfile.mkdtemp(prefix="p03-identity-tests-"))
        code = "import time; print('JOB_FIXTURE_123', flush=True); time.sleep(.3)"
        pipeline = '\"$1\" -u -c \"$2\" | \"$1\" \"$3\" --collect \"$4\"'
        outcome = M.W.launch(["/bin/bash", "-c", pipeline, "identity-fixture", sys.executable,
                              code, str(Path(M.__file__).resolve()), str(root / "loss.json")],
                             cwd=str(root), env=os.environ, timeout_s=.15, log_dir=root, name="identity")
        self.assertTrue(outcome.timed_out)
        self.assertIn("JOB_FIXTURE_123", (root / "identity.log").read_text())
        deadline = time.monotonic() + 2
        while not (root / "identity.rc").exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual((root / "identity.rc").read_text().strip(), "0")

    def test_remote_command_and_positive_full_surface(self):
        for tier in ("smoke", "full"):
            args = M.command(tier, "worker-name")
            self.assertEqual(args[args.index("-j") + 1], "1")
            self.assertEqual(args[:4], ["rch", "exec", "--source-content-receipt", "--json"])
            self.assertIn("franken-speaker/journal-process", args)
            env = M.W.child_env({"RCH_REQUIRE_REMOTE": "0", "RCH_ENABLED": "0"}, remote=True)
            self.assertEqual(env["RCH_REQUIRE_REMOTE"], "1")
            self.assertNotIn("RCH_ENABLED", env)
        self.assertIn("journal_process", M.command("smoke"))
        self.assertIn("franken-control", M.command("full"))
        self.assertIn("--no-fail-fast", M.command("full"))


if __name__ == "__main__":
    unittest.main()
