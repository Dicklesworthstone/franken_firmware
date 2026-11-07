"""Real subprocess-bound controls using only disposable Python child processes, not Rust evidence."""
import subprocess
import sys
import time
import unittest

import capture
import remote


class CaptureControls(unittest.TestCase):
    def run_child(self, code, timeout=1.0, cap=4096, request=b"{}"):
        return capture.worker([sys.executable, "-c", code], request, timeout, cap)

    def test_permitted_small_input_and_output_really_complete(self):
        result = self.run_child("import sys; print(sys.stdin.buffer.read().decode(), flush=True)")
        self.assertIsNone(result["stop_reason"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"].strip(), b"{}")

    def test_stdout_and_stderr_are_incrementally_capped(self):
        for fd in (1, 2):
            result = self.run_child(f"import os; os.write({fd}, b'x' * 1000000)", cap=128)
            self.assertEqual(result["stop_reason"], "output_limit")
            self.assertEqual(result["retained_bytes"], 128)

    def test_exited_parent_with_pipe_holding_descendant_is_bounded(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)']); print('parent-done',flush=True)"
        start = time.monotonic()
        result = self.run_child(code, timeout=0.2)
        self.assertEqual(result["stop_reason"], "timeout")
        self.assertLess(time.monotonic() - start, 2)

    def test_timeout_reaps_own_group_and_next_child_still_runs(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            failed = self.run_child("import time; time.sleep(10)", timeout=0.1)
            self.assertEqual(failed["stop_reason"], "timeout")
            self.assertIsNone(unrelated.poll(), "cleanup must never affect another process")
            fresh = self.run_child("print('recovered',flush=True)", request=b"")
            self.assertEqual(fresh["returncode"], 0)
            self.assertIn(b"recovered", fresh["stdout"])
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=1)

    def test_raw_credential_text_is_redacted_before_echo(self):
        redacted = remote.redact("Authorization: Bearer synthetic-secret-for-test")
        self.assertNotIn("synthetic-secret-for-test", redacted)


if __name__ == "__main__":
    unittest.main()
