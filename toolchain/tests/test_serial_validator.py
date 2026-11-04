"""Independent E07 serial-evidence regressions; fixtures are not guest proof."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "src" / "run-qemu-verification.py"
SPEC = importlib.util.spec_from_file_location("ffw_serial_verifier", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

HELLO = "FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32"
ENOSYS = "FFW_TEST:ERR_ENOSYS status=PASS errno=89"
# Frozen protocol transcript, authored independently of parser patterns.
# This checks the parser only; it establishes no boot or hardware capability.
POSITIVE = """FFW_MARKER:USERSPACE_START
FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32
FFW_KERNEL_VERSION: Linux version 4.19.0-fixture
FFW_TEST:ERR_ENOENT status=PASS errno=2
FFW_TEST:ERR_EBADF status=PASS errno=9
FFW_TEST:ERR_ENOSYS status=PASS errno=89
FFW_TEST:POS_FD_SHORT_WRITE status=PASS fd=4
FFW_PROBE:CLOCK_MONOTONIC status=PASS res_ns=1
FFW_PROBE:NONBLOCK_PIPE status=PASS rc=0
FFW_PROBE:POLL status=PASS rc=1
FFW_PROBE:EPOLL status=PASS fd=4
FFW_PROBE:SOCKET_UDP status=PASS fd=4
FFW_PROBE:ENTROPY status=PASS fd=4
FFW_PROBE:ATOMICS_32 status=PASS ok=1
FFW_MARKER:TEST_SUCCESS failures=0
FFW_MARKER:REBOOT_REQUEST
"""


class SerialEvidenceTests(unittest.TestCase):
    def status(self, text):
        return VERIFIER.verify_serial_output("mips", HELLO, ENOSYS, text)["status"]

    def test_complete_transcript_passes(self):
        self.assertEqual(self.status(POSITIVE), "PASS")

    def test_missing_probe_fails(self):
        text = POSITIVE.replace("FFW_PROBE:ENTROPY status=PASS fd=4\n", "")
        self.assertEqual(self.status(text), "FAIL")

    def test_kernel_panic_fails(self):
        self.assertEqual(self.status(POSITIVE + "Kernel panic - not syncing"), "FAIL")

    def test_conflicting_probe_after_success_fails(self):
        text = POSITIVE + "FFW_PROBE:ENTROPY status=FAIL errno=5\n"
        self.assertEqual(self.status(text), "FAIL")

    def test_nonzero_failure_count_is_not_zero_prefix(self):
        self.assertEqual(self.status(POSITIVE.replace("failures=0", "failures=01")), "FAIL")

    def test_errno_prefix_is_not_exact_errno(self):
        self.assertEqual(self.status(POSITIVE.replace("errno=89", "errno=890")), "FAIL")

    def test_echoed_transcript_is_not_userspace_output(self):
        text = "\n".join("echo " + line for line in POSITIVE.splitlines())
        self.assertEqual(self.status(text), "FAIL")

    def test_duplicate_boot_transcript_fails(self):
        self.assertEqual(self.status(POSITIVE + POSITIVE), "FAIL")

    def test_probe_after_success_fails(self):
        probe = "FFW_PROBE:ENTROPY status=PASS fd=4\n"
        self.assertEqual(self.status(POSITIVE.replace(probe, "") + probe), "FAIL")

    def test_truncated_reboot_marker_fails(self):
        text = POSITIVE.replace("FFW_MARKER:REBOOT_REQUEST", "FFW_MARKER:REBOOT_REQUE")
        self.assertEqual(self.status(text), "FAIL")


class CaptureTests(unittest.TestCase):
    def capture(self, code, timeout=2, max_bytes=1024):
        return VERIFIER.capture_guest([sys.executable, "-c", code],
                                      os.environ.copy(), timeout, max_bytes)

    def test_exact_binary_streams(self):
        result = self.capture("import os; os.write(1,b'one\\r\\n\\xff'); os.write(2,b'two\\x00')")
        self.assertEqual(result["stdout"], b"one\r\n\xff")
        self.assertEqual(result["stderr"], b"two\x00")
        self.assertEqual(result["returncode"], 0)
        self.assertIsNone(result["stop_reason"])

    def test_timeout_preserves_prefix(self):
        result = self.capture("import os,time; os.write(1,b'partial'); time.sleep(10)", timeout=0.3)
        self.assertEqual(result["stdout"], b"partial")
        self.assertEqual(result["stop_reason"], "timeout")
        self.assertNotEqual(result["returncode"], 0)

    def test_unbounded_writer_is_capped(self):
        result = self.capture("import os\nwhile True: os.write(1,b'x'*4096)", max_bytes=100)
        self.assertEqual(len(result["stdout"]) + len(result["stderr"]), 100)
        self.assertEqual(result["stop_reason"], "output_limit")

    def test_nonzero_exit_preserves_stderr(self):
        result = self.capture("import os; os.write(2,b'crash detail'); raise SystemExit(7)")
        self.assertEqual(result["stderr"], b"crash detail")
        self.assertEqual(result["returncode"], 7)

    def test_child_holding_pipe_cannot_hang_capture(self):
        result = self.capture("import os,time\npid=os.fork()\nif pid==0: time.sleep(10)\nelse: os._exit(0)", timeout=0.3)
        self.assertEqual(result["stop_reason"], "timeout")

    def test_exception_receipt_replaces_incomplete(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch) / "fresh"
            with patch.object(VERIFIER, "run_verification", side_effect=RuntimeError("fixture")):
                self.assertEqual(VERIFIER.main(["--results-dir", str(output)]), 1)
            receipt = json.loads((output / "e07-e03-verification-receipt.json").read_text())
            self.assertEqual(receipt["status"], "FAIL")
            self.assertEqual(receipt["error_type"], "RuntimeError")
            self.assertTrue(receipt["run_id"])

    def test_existing_results_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as scratch:
            marker = Path(scratch) / "marker"
            marker.write_bytes(b"previous run")
            with self.assertRaises(FileExistsError):
                VERIFIER.main(["--results-dir", scratch])
            self.assertEqual(marker.read_bytes(), b"previous run")


if __name__ == "__main__":
    unittest.main()
