"""Focused tests of the U01 end-to-end runner's tiers, shared Q00 log, receipts and time bounds (tests/u01/e2e.py, case_log.py; bead ffw-mgb).

Run: python3 -B -W error -m unittest tests/u01/test_e2e.py   (from the repository root; standard library only, offline, no cargo)

The journal itself is not exercised here; that is `test_u01.py`, the battery and the central Rust run. What is exercised: the tier selection, the exit codes, the
bounded drain every child goes through (deadline, byte cap, process-group kill) including the unit tests of U01-E-001, noisy and flooding children, stderr privacy, the
runner's own error lines, the
blocked-without-a-binary behaviour, the causal text of a failed unit test, the redaction of what is printed and recorded, the receipt and its refusal to be
overwritten, the loss of critical log evidence, the deadline of every subprocess, and the SIGKILL driver, which is run for real against the Python stand-in
`fake_crash.py` (the same real signal, the same recovery oracle) and against fakes that hang, so that a hang is shown to end in a failed case with the child
dead. Each refusal is planted against a control that passes. Fakes are written only into temporary directories.
"""
import contextlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import case_log  # noqa: E402
import e2e as E  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "u01")
FAKE = os.path.join(HERE, "fake_crash.py")
SECRET = "Authorization: Bearer abcdef0123456789abcdef0123456789abcdef"


def fake_cases(passing=True, binary_case=True):
    cases = [("U01-E-001", "a host case", False, lambda _b: (E.PASS, "ok: 3 things"))]
    if not passing:
        def boom(_b):
            raise AssertionError("2 failures, 0 errors; first: t.x: AssertionError: " + SECRET)
        cases.append(("U01-E-002", "a failing host case", False, boom))
    if binary_case:
        cases.append(("U01-E-003", "a process case", True, lambda b: (E.PASS, "ran " + os.path.basename(b))))
    return cases


def run_main(argv, cases=None, smoke=("U01-E-001", "U01-E-002")):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if cases is None:
            code = E.main(argv)
        else:
            with mock.patch.object(E, "CASES", cases), mock.patch.object(E, "SMOKE", smoke):
                code = E.main(argv)
    return code, out.getvalue(), err.getvalue()


def write_executable(directory, name, source):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!%s\n" % sys.executable + textwrap.dedent(source))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(path, wait=3.0):
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                text = handle.read().strip()
            if text:
                return int(text)
        time.sleep(0.02)
    raise AssertionError("the fake never recorded its pid")


class Tiers(unittest.TestCase):
    def test_the_tiers_plan_what_they_say_and_the_default_is_the_old_behaviour(self):
        self.assertEqual([c[0] for c in E.planned("smoke", False)], ["U01-E-001", "U01-E-002"])
        self.assertEqual([c[0] for c in E.planned("full", False)], ["U01-E-00%d" % n for n in range(1, 7)])
        self.assertEqual([c[0] for c in E.planned("smoke", True)][-1], "U01-E-007")
        self.assertEqual([c[0] for c in E.planned("full", True)][-1], "U01-E-007")
        self.assertEqual([c[3] is not None for c in E.planned("full", False)], [True] * 6)
        self.assertEqual(sorted(c[0] for c in E.planned("full", False) if c[2]), ["U01-E-003", "U01-E-004", "U01-E-005", "U01-E-006"])       # the process cases
        parser_default = [a for a in ("--tier",)]
        self.assertTrue(parser_default)
        code, out, _ = run_main(["--list"])
        self.assertEqual((code, len(out.strip().splitlines())), (0, 6))
        code, out, _ = run_main(["--tier", "smoke", "--list"])
        self.assertEqual((code, len(out.strip().splitlines())), (0, 2))

    def test_soak_says_why_exits_4_and_judges_nothing_even_with_a_binary(self):
        for argv in (["--tier", "soak"], ["--tier", "soak", "--binary", FAKE]):
            code, out, _ = run_main(argv, fake_cases())
            self.assertEqual(code, 4, argv)
            self.assertIn("U01 soak: NOT RUN", out)
            self.assertIn("This is not a pass.", out)
            self.assertNotIn("QUALIFIED", out)
            self.assertNotIn("U01 cases:", out)

    def test_usage_errors_exit_2(self):
        self.assertEqual(run_main(["--case", "U01-E-999"], fake_cases())[0], 2)
        code, _, err = run_main(["--case", "U01-E-007"])
        self.assertEqual(code, 2)
        self.assertIn("U01-E-007 needs --mutants", err)
        self.assertEqual(run_main(["--tier", "smoke", "--case", "U01-E-003"], fake_cases())[0], 2)    # a full-tier case is not in the smoke tier
        self.assertEqual(run_main(["--binary", os.path.join(HERE, "nonexistent")], fake_cases())[0], 2)
        with self.assertRaises(SystemExit) as raised:
            run_main(["--tier", "nonsense"])
        self.assertEqual(raised.exception.code, 2)

    def test_the_exit_codes_pass_blocked_failed_and_the_unchanged_summary_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_main(["--receipts", tmp, "--binary", FAKE], fake_cases())
            self.assertEqual(code, 0, out)
            self.assertIn("U01 cases: total=2 passed=2 failed=0 blocked=0\n", out)                  # the line older tooling reads
            self.assertIn("U01 e2e tier=full: QUALIFIED", out)
            code, out, _ = run_main(["--receipts", tmp], fake_cases())
            self.assertEqual(code, 3, out)
            self.assertIn("BLOCKED U01-E-003", out)
            self.assertIn("never counted as passed", out)
            self.assertIn("NOT QUALIFIED", out)
            code, out, _ = run_main(["--receipts", tmp, "--binary", FAKE], fake_cases(passing=False))
            self.assertEqual(code, 1, out)
            self.assertIn("U01 cases: total=3 passed=2 failed=1 blocked=0\n", out)
            code, out, _ = run_main(["--receipts", tmp], fake_cases(passing=False))                  # a failure wins over a block
            self.assertEqual(code, 1, out)

    def test_a_smoke_run_needs_no_binary_and_a_single_case_is_never_a_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_main(["--tier", "smoke", "--receipts", tmp], fake_cases())
            self.assertEqual(code, 0, out)
            self.assertNotIn("U01-E-003", out)
            self.assertIn("U01 e2e tier=smoke: QUALIFIED", out)
            code, out, _ = run_main(["--case", "U01-E-001", "--receipts", tmp], fake_cases())
            self.assertEqual(code, 0, out)
            self.assertIn("PARTIAL (only the selected cases ran; never a qualification)", out)
            self.assertNotIn(": QUALIFIED", out)

    def test_a_process_case_without_a_binary_is_blocked_and_its_function_is_not_called(self):
        called = []
        status, detail = E.run_case(True, lambda b: called.append(b) or (E.PASS, "x"), None)
        self.assertEqual((status, called), (E.BLOCKED, []))
        self.assertIn("needs a journal_crash binary this host can run", detail)
        self.assertEqual(E.run_case(True, lambda b: called.append(b) or (E.PASS, "x"), "bin"), (E.PASS, "x"))        # control: with a binary it runs
        status, detail = E.run_case(False, lambda b: 1 / 0, None)
        self.assertEqual(status, E.FAIL)
        self.assertTrue(detail.startswith("ZeroDivisionError"))


def fake_script(directory, name, body):
    """An executable fake `journal_crash` (or any child) written into a temporary directory."""
    return write_executable(directory, name, body)


def pid_note(pidfile):
    """One line for a fake to record its own pid (the body must import os)."""
    return "open(%r, 'w').write(str(os.getpid()))" % pidfile


def wrapper(tmp, ack_sleep=0.05, noise=False, dump_bogus=False, stderr_text=""):
    """The Python stand-in behind a wrapper that paces its acknowledgements, can interleave noise lines and stderr text, can lie about the recovered state, and writes a mark
    when it stops politely (atexit or SIGTERM) - which a SIGKILL cannot."""
    marker = os.path.join(tmp, "exited-normally")
    return write_executable(tmp, "wrapped_crash", """
        import atexit, builtins, os, signal, sys, time
        sys.path.insert(0, %r)
        import fake_crash
        MARK = %r
        def note(text):
            with open(MARK, "w") as handle:
                handle.write(text)
        if sys.argv[1] == "run":          # only the long-running child: a polite stop of it would leave a mark
            atexit.register(lambda: note("atexit ran"))
            signal.signal(signal.SIGTERM, lambda *a: (note("sigterm ran"), os._exit(0)))
            if %r:
                sys.stderr.write(%r + "\\n")
                sys.stderr.flush()
        real_print = builtins.print
        def slow_print(*a, **k):
            real_print(*a, **k)
            if a and a[0] == "ack":
                time.sleep(%r)
                if %r:
                    real_print("noise: not an acknowledgement", flush=True)
        builtins.print = slow_print
        if %r and sys.argv[1] == "dump":
            real_print("state 00")
            sys.exit(0)
        sys.exit(fake_crash.main(sys.argv[1:]))
        """ % (HERE, marker, bool(stderr_text), stderr_text, ack_sleep, noise, dump_bogus)), marker


class CausalText(unittest.TestCase):
    def module(self, tmp, name, body):
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
            handle.write("import unittest\n\n" + textwrap.dedent(body))

    def test_a_failed_unit_test_says_which_test_and_what_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.module(tmp, "test_planted_failure_u01a.py", """
                class T(unittest.TestCase):
                    def test_one(self):
                        self.assertEqual(1, 2)
                """)
            self.module(tmp, "test_planted_error_u01a.py", """
                class T(unittest.TestCase):
                    def test_two(self):
                        raise ZeroDivisionError("division by zero in the planted test")
                """)
            self.module(tmp, "test_planted_both_u01a.py", """
                class T(unittest.TestCase):
                    def test_one(self):
                        self.assertEqual(1, 2)
                    def test_two(self):
                        raise ZeroDivisionError("division by zero in the planted test")
                """)
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_failure_u01a")
            text = str(raised.exception)
            self.assertIn("FAILED (failures=1)", text)
            self.assertIn("first: FAIL: test_one (test_planted_failure_u01a.T.test_one)", text)
            self.assertIn("AssertionError: 1 != 2", text)
            self.assertLessEqual(len(text), E.CAUSE_CAP)
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_error_u01a")
            self.assertIn("first: ERROR: test_two (test_planted_error_u01a.T.test_two)", str(raised.exception))
            self.assertIn("ZeroDivisionError: division by zero in the planted test", str(raised.exception))
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_both_u01a")
            self.assertIn("FAILED (failures=1, errors=1)", str(raised.exception))

    def test_a_passing_module_passes_and_a_module_with_no_tests_or_none_at_all_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.module(tmp, "test_planted_pass_u01b.py", """
                class T(unittest.TestCase):
                    def test_one(self):
                        self.assertTrue(True)
                """)
            self.module(tmp, "test_planted_empty_u01b.py", "X = 1\n")
            self.assertEqual(E.host_unit_tests(tmp, "test_planted_pass_u01b"), (E.PASS, "1 tests"))
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_empty_u01b")
            self.assertIn("no test ran", str(raised.exception))
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_nothing_matches_u01c")
            self.assertIn("No module named", str(raised.exception))

    def test_the_real_host_cases_still_pass_on_this_tree_and_u01_e_001_runs_in_the_bounded_child(self):
        with mock.patch.object(E, "run_bounded", wraps=E.run_bounded) as spy:
            status, detail = E.CASES[0][3](None)
        self.assertEqual(E.CASES[0][0], "U01-E-001")
        self.assertEqual(status, E.PASS)
        self.assertRegex(detail, r"^\d+ tests$")
        (call,) = spy.call_args_list
        self.assertEqual(call.args[0][1:], ["-B", "-m", "unittest", "test_u01"])
        self.assertEqual(call.kwargs["cwd"], E.HERE)
        self.assertEqual(E.host_vectors_current(), (E.PASS, "u01 vectors: up to date"))

    def test_a_unit_test_run_that_hangs_floods_or_is_ordinary_is_decided_by_the_bounded_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "pid")
            self.module(tmp, "test_planted_hang_u01d.py", """
                import os, time
                class T(unittest.TestCase):
                    def test_hangs(self):
                        with open(%r, "w") as handle:
                            handle.write(str(os.getpid()))
                        time.sleep(120)
                """ % pidfile)
            self.module(tmp, "test_planted_flood_u01d.py", """
                import sys
                class T(unittest.TestCase):
                    def test_floods_stdout(self):
                        print("x" * 300000)
                    def test_floods_stderr(self):
                        sys.stderr.write("y" * 300000)
                """)
            self.module(tmp, "test_planted_chatty_u01d.py", """
                class T(unittest.TestCase):
                    def test_prints_a_little(self):
                        print("ordinary output " * 100)
                """)
            started = time.monotonic()
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_hang_u01d", timeout=2)
            self.assertEqual(str(raised.exception), "the unit tests of test_planted_hang_u01d timed out after 2 s (the child was killed)")
            self.assertLess(time.monotonic() - started, 20)
            self.assertFalse(alive(read_pid(pidfile)), "the hung battery was left running")
            with self.assertRaises(AssertionError) as raised:
                E.host_unit_tests(tmp, "test_planted_flood_u01d", cap=50_000)
            self.assertRegex(str(raised.exception), r"wrote more than 50000 bytes to (stdout|stderr) \(the child was killed; an overflow is a failure, never truncated into a pass\)")
            self.assertEqual(E.host_unit_tests(tmp, "test_planted_chatty_u01d", cap=50_000), (E.PASS, "1 tests"))     # control: ordinary output within the cap passes

    def test_what_is_printed_and_recorded_is_redacted_by_the_shared_policy(self):
        self.assertNotIn("abcdef0123456789", E.safe(SECRET))
        self.assertEqual(E.safe(""), "")
        self.assertEqual(E.safe("2 failures, 0 errors"), "2 failures, 0 errors")                    # control: plain text is untouched
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_main(["--receipts", tmp, "--binary", FAKE], fake_cases(passing=False))
            self.assertEqual(code, 1)
            self.assertNotIn("abcdef0123456789", out)
            for name in os.listdir(tmp):
                self.assertNotIn("abcdef0123456789", read_text(os.path.join(tmp, name)), name)
        with mock.patch.object(case_log, "load", side_effect=RuntimeError("no diagnostics")):
            self.assertEqual(E.safe("anything"), "Diagnostic detail withheld: redaction is unavailable.")     # an unavailable sanitizer releases nothing


class BoundedOutput(unittest.TestCase):
    """One drain primitive for every child: an absolute deadline, a byte cap per stream, a failure (never a truncation) on overflow, and the whole group killed."""

    def test_ordinary_output_and_the_exit_status_are_preserved_within_the_cap(self):
        done = E.host_run([sys.executable, "-c", "import sys; print('out line'); sys.stderr.write('err line\\n'); sys.exit(3)"], 30, "control", cap=1000)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (3, "out line\n", "err line\n"))
        done = E.host_run([sys.executable, "-c", "import os; os.abort()"], 30, "aborter")
        self.assertEqual(done.returncode, -int(signal.SIGABRT))                                  # a death by signal is still a negative status
        exact = E.host_run([sys.executable, "-c", "import sys; sys.stdout.write('z' * 1000)"], 30, "exactly the cap", cap=1000)
        self.assertEqual(len(exact.stdout), 1000)                                                     # the cap itself is allowed; one byte more is not

    def test_one_byte_over_the_cap_on_either_stream_is_a_failure_with_the_child_dead(self):
        for stream in ("stdout", "stderr"):
            with tempfile.TemporaryDirectory() as tmp:
                pidfile = os.path.join(tmp, "pid")
                child = fake_script(tmp, "overflows_" + stream, "import os, sys, time\n" + pid_note(pidfile) + "\nsys.%s.write('z' * 1001)\nsys.%s.flush()\ntime.sleep(120)\n" % (stream, stream))
                with self.assertRaises(AssertionError) as raised:
                    E.host_run([child], 30, "the flooder", cap=1000)
                self.assertEqual(str(raised.exception), "the flooder wrote more than 1000 bytes to %s (the child was killed; an overflow is a failure, never truncated into a pass)" % stream)
                self.assertFalse(alive(read_pid(pidfile)))

    def test_an_endless_flood_is_cut_off_at_the_cap_not_buffered_forever(self):
        started = time.monotonic()
        with self.assertRaises(AssertionError) as raised:
            E.host_run([sys.executable, "-c", "import sys\nwhile True:\n    sys.stdout.write('x' * 4096)"], 60, "the endless flooder", cap=100_000)
        self.assertIn("wrote more than 100000 bytes to stdout", str(raised.exception))
        self.assertLess(time.monotonic() - started, 30)

    def test_a_grandchild_that_keeps_the_pipe_open_ends_in_a_timeout_and_is_killed_with_the_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "grandchild")
            child = fake_script(tmp, "spawns_a_holder", """
                import subprocess, sys
                holder = subprocess.Popen(["sleep", "120"])
                with open(%r, "w") as handle:
                    handle.write(str(holder.pid))
                sys.exit(0)
                """ % pidfile)
            with self.assertRaises(AssertionError) as raised:
                E.host_run([child], 1, "the spawner")
            self.assertEqual(str(raised.exception), "the spawner timed out after 1 s (the child was killed)")
            self.assertFalse(alive(read_pid(pidfile)), "the grandchild that held the pipe was left running")

    def test_a_binary_call_that_floods_is_a_failed_case_through_crash_and_recovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = fake_script(tmp, "flood_on_dump", "import sys\nsys.stdout.write('state ' + '0' * 5000)\n")
            with mock.patch.object(E, "OUTPUT_CAP", 2000):
                with self.assertRaises(AssertionError) as raised:
                    E.recovered(child, os.path.join(tmp, "image"))
            self.assertIn("`flood_on_dump dump` wrote more than 2000 bytes to stdout", str(raised.exception))
            ordinary = fake_script(tmp, "ordinary_dump", "print('state 00')\n")
            with mock.patch.object(E, "OUTPUT_CAP", 2000):
                self.assertEqual(E.recovered(ordinary, os.path.join(tmp, "image")), "00")


class TimeBounds(unittest.TestCase):
    def test_a_subprocess_that_hangs_is_killed_and_the_failure_says_so(self):
        started = time.monotonic()
        with self.assertRaises(AssertionError) as raised:
            E.host_run([sys.executable, "-c", "import time; time.sleep(30)"], 1, "the sleeper")
        self.assertEqual(str(raised.exception), "the sleeper timed out after 1 s (the child was killed)")
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(E.host_run([sys.executable, "-c", "print('fine')"], 30, "control").stdout.strip(), "fine")

    def test_the_vectors_check_and_the_binary_calls_have_deadlines(self):
        with self.assertRaises(AssertionError) as raised:
            E.host_vectors_current(timeout=0.0001)
        self.assertIn("make_vectors.py --check timed out", str(raised.exception))
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "pid")
            hang = fake_script(tmp, "hang_on_init", "import os, time\n" + pid_note(pidfile) + "\ntime.sleep(60)\n")
            with self.assertRaises(AssertionError) as raised:
                E.crash(hang, "init", os.path.join(tmp, "image"), timeout=1)
            self.assertIn("`hang_on_init init` timed out after 1 s", str(raised.exception))
            self.assertFalse(alive(read_pid(pidfile)))                                          # the binary was killed and reaped, not left behind

    def hang_after(self, tmp, acks):
        pidfile = os.path.join(tmp, "pid")
        path = write_executable(tmp, "hangs_after_%d" % acks, """
            import os, signal, sys, time
            if sys.argv[1] == "init":
                with open(sys.argv[2], "xb") as handle:
                    handle.write(bytes([255]) * 8)
                sys.exit(0)
            with open(%r, "w") as handle:
                handle.write(str(os.getpid()))
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            for i in range(1, %d + 1):
                print("ack", i, flush=True)
            time.sleep(120)
            """ % (pidfile, acks))
        return path, pidfile

    def test_a_child_that_goes_silent_before_the_kill_point_is_a_failed_case_with_the_child_dead(self):
        for acks in (0, 2):
            with tempfile.TemporaryDirectory() as tmp:
                binary, pidfile = self.hang_after(tmp, acks)
                started = time.monotonic()
                with self.assertRaises(AssertionError) as raised:
                    E.process_sigkill("U01-S-003", [3], ack_timeout=1)(binary)
                self.assertIn("SIGKILL after ack 3: no ack within 1 s after %d acks (other output does not extend the deadline; the child was killed)" % acks, str(raised.exception))
                self.assertLess(time.monotonic() - started, 15)
                self.assertFalse(alive(read_pid(pidfile)), "the child outlived the driver")      # owned-child cleanup, even though it ignored SIGTERM

    def test_a_driver_failure_surfaces_through_the_runner_as_a_failed_case_not_a_hang(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, pidfile = self.hang_after(tmp, 1)
            cases = [("U01-E-006", "a sigkill case", True, E.process_sigkill("U01-S-003", [3], ack_timeout=1))]
            code, out, _ = run_main(["--binary", binary, "--receipts", os.path.join(tmp, "r")], cases)
            self.assertEqual(code, 1, out)
            self.assertIn("FAIL    U01-E-006", out)
            self.assertIn("no ack within 1 s", out)
            self.assertFalse(alive(read_pid(pidfile)))

    def test_noise_does_not_extend_the_deadline_and_a_flood_of_it_is_cut_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "pid")
            slow_noise = fake_script(tmp, "slow_noise", """
                import os, sys, time
                if sys.argv[1] == "init":
                    open(sys.argv[2], "xb").close()
                    sys.exit(0)
                %s
                n = 0
                while True:
                    n += 1
                    print("noise", n, flush=True)
                    time.sleep(0.2)
                """ % pid_note(pidfile))
            started = time.monotonic()
            with self.assertRaises(AssertionError) as raised:
                E.process_sigkill("U01-S-003", [3], ack_timeout=1)(slow_noise)
            self.assertIn("no ack within 1 s after 0 acks (other output does not extend the deadline", str(raised.exception))
            self.assertLess(time.monotonic() - started, 15)                                       # a line every 0.2 s used to restart the wait for ever
            self.assertFalse(alive(read_pid(pidfile)))
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "pid")
            flood = fake_script(tmp, "flood_noise", """
                import os, sys
                if sys.argv[1] == "init":
                    open(sys.argv[2], "xb").close()
                    sys.exit(0)
                %s
                while True:
                    sys.stdout.write("noise noise noise noise\\n" * 512)
                    sys.stdout.flush()
                """ % pid_note(pidfile))
            started = time.monotonic()
            with self.assertRaises(AssertionError) as raised:
                E.process_sigkill("U01-S-003", [3], ack_timeout=60, cap=50_000)(flood)
            self.assertIn("SIGKILL after ack 3 wrote more than 50000 bytes to stdout (the child was killed; an overflow is a failure, never truncated into a pass)", str(raised.exception))
            self.assertLess(time.monotonic() - started, 30)                                       # not the 60 s deadline: the cap ended it
            self.assertFalse(alive(read_pid(pidfile)))

    def test_a_flood_on_stderr_is_cut_off_and_its_last_line_is_kept_as_the_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = os.path.join(tmp, "pid")
            child = fake_script(tmp, "flood_stderr", """
                import os, sys
                if sys.argv[1] == "init":
                    open(sys.argv[2], "xb").close()
                    sys.exit(0)
                %s
                while True:
                    sys.stderr.write("complaint\\n" * 1024)
                    sys.stderr.flush()
                """ % pid_note(pidfile))
            with self.assertRaises(AssertionError) as raised:
                E.process_sigkill("U01-S-003", [3], ack_timeout=60, cap=50_000)(child)
            self.assertIn("wrote more than 50000 bytes to stderr", str(raised.exception))
            self.assertIn("the child's last stderr line: complaint", str(raised.exception))
            self.assertFalse(alive(read_pid(pidfile)))

    def test_the_childs_stderr_never_reaches_the_terminal_and_a_secret_on_it_is_redacted_in_the_failure(self):
        harness_source = textwrap.dedent("""
            import sys
            sys.path.insert(0, %r)
            import e2e as E
            E.CASES[:] = [("U01-E-006", "a sigkill case", True, E.process_sigkill("U01-S-003", [3], ack_timeout=%r))]
            sys.exit(E.main(["--binary", sys.argv[1], "--receipts", sys.argv[2]]))
            """)
        with tempfile.TemporaryDirectory() as tmp:
            hang = write_executable(tmp, "secret_on_stderr", """
                import sys, time
                if sys.argv[1] == "init":
                    open(sys.argv[2], "xb").close()
                    sys.exit(0)
                sys.stderr.write(%r + "\\n")
                sys.stderr.flush()
                time.sleep(120)
                """ % SECRET)
            harness = os.path.join(tmp, "harness.py")
            with open(harness, "w", encoding="utf-8") as handle:
                handle.write(harness_source % (HERE, 1))
            receipts = os.path.join(tmp, "receipts")
            done = subprocess.run([sys.executable, "-B", harness, hang, receipts], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
            self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
            for where, text in (("stdout", done.stdout), ("stderr", done.stderr)):
                self.assertNotIn("abcdef0123456789", text, where)                                  # the inherited stderr used to print it raw
            self.assertIn("FAIL    U01-E-006", done.stdout)
            self.assertIn("the child's last stderr line: Authorization: [REDACTED]", done.stdout)
            for name in os.listdir(receipts):
                self.assertNotIn("abcdef0123456789", read_text(os.path.join(receipts, name)), name)
            quiet = write_executable(tmp, "quiet_hang", """
                import sys, time
                if sys.argv[1] == "init":
                    open(sys.argv[2], "xb").close()
                    sys.exit(0)
                time.sleep(120)
                """)
            done = subprocess.run([sys.executable, "-B", harness, quiet, os.path.join(tmp, "receipts2")], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
            self.assertEqual(done.returncode, 1)
            self.assertEqual(done.stderr, "")                                                      # control: nothing reaches the terminal's stderr
            self.assertNotIn("last stderr line", done.stdout)


class TheSigkillDriver(unittest.TestCase):
    """The real signal and the real recovery oracle, against the Python stand-in (`fake_crash.py`; not evidence about the Rust)."""

    def test_sigkill_after_acknowledged_steps_recovers_the_old_or_the_new_state(self):
        status, detail = E.process_sigkill("U01-S-003", [3, 17])(FAKE)
        self.assertEqual((status, detail), (E.PASS, "killed with SIGKILL after acks [3, 17]"))

    def test_the_kill_is_abrupt_sigkill_not_a_polite_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, marker = wrapper(tmp)
            self.assertEqual(E.process_sigkill("U01-S-003", [3], ack_timeout=10)(binary)[0], E.PASS)
            self.assertFalse(os.path.exists(marker), "an atexit or SIGTERM handler ran: the child was stopped, not killed with SIGKILL")
            image = os.path.join(tmp, "control-image")                                           # control: the same child left to finish does write the mark
            subprocess.run([binary, "init", image], check=True, timeout=30)
            subprocess.run([binary, "run", image, E.VECTORS, "U01-S-001"], check=True, capture_output=True, timeout=60)
            self.assertTrue(os.path.exists(marker))

    def test_a_slow_child_whose_every_ack_is_in_time_is_not_cut_off_and_noise_between_acks_is_harmless(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, _ = wrapper(tmp, ack_sleep=0.6)
            started = time.monotonic()
            self.assertEqual(E.process_sigkill("U01-S-003", [4], ack_timeout=1.2)(binary)[0], E.PASS)
            self.assertGreater(time.monotonic() - started, 1.2)                                  # longer than one deadline: each ack moves the deadline, not the process
        with tempfile.TemporaryDirectory() as tmp:
            binary, marker = wrapper(tmp, ack_sleep=0.02, noise=True)
            self.assertEqual(E.process_sigkill("U01-S-003", [3, 17], ack_timeout=10)(binary)[0], E.PASS)
            self.assertFalse(os.path.exists(marker))

    def test_a_recovery_that_is_neither_the_old_nor_the_new_state_is_still_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary, _ = wrapper(tmp, dump_bogus=True)
            with self.assertRaises(AssertionError) as raised:
                E.process_sigkill("U01-S-003", [3], ack_timeout=10)(binary)
            self.assertIn("recovered neither the state before nor after step", str(raised.exception))
            self.assertIn("SIGKILL after ack 3", str(raised.exception))

    def test_a_run_that_finishes_before_the_kill_point_is_checked_not_skipped(self):
        status, _ = E.process_sigkill("U01-S-001", [10_000])(FAKE)                                # the kill point is never reached: the run completes
        self.assertEqual(status, E.PASS)

    def test_the_byte_budget_sweep_keeps_its_oracle_and_its_arithmetic(self):
        status, detail = E.process_budget_sweep("U01-S-002", 87)(FAKE)
        self.assertEqual((status, detail), (E.PASS, "4 runs (3 killed mid-write, 1 ran to the end), stride 87, 261 bytes"))
        with tempfile.TemporaryDirectory() as tmp:
            binary, _ = wrapper(tmp, dump_bogus=True)
            with self.assertRaises(AssertionError) as raised:
                E.process_budget_sweep("U01-S-002", 87)(binary)
            self.assertIn("recovered neither the state before nor after step", str(raised.exception))


class RunnerErrors(unittest.TestCase):
    """What the runner itself says about its arguments names no path and passes the shared redaction; ordinary usage is the control of each."""

    def test_a_bad_binary_is_named_by_its_file_name_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            hidden = os.path.join(tmp, SECRET, "journal_crash_missing")
            code, out, err = run_main(["--binary", hidden], fake_cases())
            self.assertEqual(code, 2)
            self.assertIn("error: journal_crash_missing is not an executable file (the name only: a path is not echoed)", err)
            for text in (out, err):
                self.assertNotIn(tmp, text)
                self.assertNotIn("abcdef0123456789", text)
            self.assertEqual(run_main(["--binary", FAKE], fake_cases())[::2], (0, ""))                  # control: a usable binary says nothing on stderr

    def test_a_receipt_that_cannot_be_written_does_not_echo_the_receipts_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipts = os.path.join(tmp, SECRET, "receipts")
            with mock.patch.object(E, "write_receipt", side_effect=PermissionError(13, "Permission denied", receipts)):
                code, out, err = run_main(["--receipts", receipts, "--binary", FAKE], fake_cases())
            self.assertEqual(code, 1)
            self.assertIn("error: the receipt could not be written under the receipts directory: PermissionError", err)
            for text in (out, err):
                self.assertNotIn(tmp, text)
                self.assertNotIn("abcdef0123456789", text)
            fine = os.path.join(tmp, "fine")
            code, out, err = run_main(["--receipts", fine, "--binary", FAKE], fake_cases())            # control: a writable directory
            self.assertEqual((code, err), (0, ""))
            self.assertIn("receipt: ", out)

    def test_an_unknown_case_or_argument_is_redacted_like_everything_else(self):
        code, out, err = run_main(["--case", SECRET], fake_cases())
        self.assertEqual(code, 2)
        self.assertIn("error: not a case of tier full", err)
        self.assertNotIn("abcdef0123456789", err)
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured), self.assertRaises(SystemExit) as raised:
            E.main(["--bogus=" + SECRET])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("error: unrecognized arguments:", captured.getvalue())
        self.assertNotIn("abcdef0123456789", captured.getvalue())
        self.assertEqual(run_main(["--case", "U01-E-001"], fake_cases())[0], 0)                      # control: an ordinary selection


class TheLogAndReceipt(unittest.TestCase):
    def test_a_run_writes_a_complete_log_and_a_receipt_without_a_local_path_and_never_overwrites_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_main(["--receipts", tmp, "--binary", FAKE], fake_cases())
            self.assertEqual(code, 0, out)
            self.assertIn("evidence COMPLETE", out)
            names = sorted(os.listdir(tmp))
            self.assertEqual(sorted(os.path.splitext(n)[1] for n in names), [".json", ".jsonl"])
            receipt = json.loads(read_text(os.path.join(tmp, [n for n in names if n.endswith(".json")][0])))
            self.assertEqual((receipt["schema"], receipt["tier"], receipt["exit_code"], receipt["counts"]), (E.RECEIPT_SCHEMA, "full", 0, {"pass": 2, "fail": 0, "blocked": 0}))
            self.assertEqual(receipt["binary"]["name"], "fake_crash.py")
            self.assertEqual(len(receipt["binary"]["sha256"]), 64)
            self.assertTrue(receipt["diagnostics"]["complete"])
            self.assertEqual(receipt["diagnostics"]["log"]["critical_lost"], 0)
            self.assertEqual([r["case"] for r in receipt["results"]], ["U01-E-001", "U01-E-003"])
            self.assertTrue(all(isinstance(r["seconds"], float) for r in receipt["results"]))
            self.assertEqual(receipt["replay"], "scripts/e2e/u01 --tier full --binary JOURNAL_CRASH")
            self.assertEqual(set(receipt["artifacts"].values()) & {"missing"}, set())
            for name in names:
                text = read_text(os.path.join(tmp, name))
                self.assertNotIn(tmp, text, name)
                self.assertNotIn(os.path.expanduser("~"), text, name)
            with open(os.path.join(tmp, [n for n in names if n.endswith(".jsonl")][0]), encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle if line.strip()]
            kinds = [e.get("kind") for e in events if e.get("type") == "event"]
            self.assertEqual((kinds.count("case.begin"), kinds.count("case.end"), kinds.count("run.summary")), (2, 2, 1))
            with self.assertRaises(FileExistsError):
                E.write_receipt(tmp, receipt, receipt["run_id"])

    def test_without_a_receipts_directory_the_log_is_kept_in_a_fresh_directory_and_its_path_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            before, tempfile.tempdir = tempfile.tempdir, tmp
            try:
                first = run_main(["--tier", "smoke"], fake_cases())
                second = run_main(["--tier", "smoke"], fake_cases())
            finally:
                tempfile.tempdir = before
            paths = []
            for code, out, _ in (first, second):
                self.assertEqual(code, 0, out)
                (line,) = [l for l in out.splitlines() if l.startswith("diagnostic log kept: ")]
                paths.append(line.split(": ", 1)[1])
                self.assertTrue(os.path.isfile(paths[-1]))
            self.assertNotEqual(paths[0], paths[1])

    def test_lost_critical_evidence_makes_a_run_that_would_pass_not_qualified(self):
        diag = case_log.load(REPO)
        real_open = case_log.CaseLog.open

        def full_disk(repo, run_id, tier, receipts=None, **kw):
            return real_open(repo, run_id, tier, target=diag.FaultableSink(capacity_bytes=1_500))

        def whole(repo, run_id, tier, receipts=None, **kw):
            return real_open(repo, run_id, tier, target=diag.FaultableSink())

        with mock.patch.object(case_log.CaseLog, "open", staticmethod(whole)):
            code, out, _ = run_main(["--binary", FAKE], fake_cases())
        self.assertEqual(code, 0, out)                                                           # control: a sink that takes every write
        with mock.patch.object(case_log.CaseLog, "open", staticmethod(full_disk)):
            code, out, _ = run_main(["--binary", FAKE], fake_cases())
        self.assertEqual(code, 1, out)
        self.assertIn("U01 cases: total=2 passed=2 failed=0 blocked=0", out)                     # the cases did pass; the evidence did not survive
        self.assertIn("diagnostic evidence INCOMPLETE", out)
        self.assertIn("NOT QUALIFIED", out)
        with mock.patch.object(case_log.CaseLog, "open", staticmethod(full_disk)):
            code, out, _ = run_main([], fake_cases())                                            # a block is still a block
        self.assertEqual(code, 3, out)

    def test_final_exit_ranks_failed_over_blocked_over_incomplete_evidence(self):
        incomplete = mock.Mock(complete=False)
        complete = mock.Mock(complete=True)
        counts = lambda p, f, b: {E.PASS: p, E.FAIL: f, E.BLOCKED: b}  # noqa: E731
        self.assertEqual(E.final_exit(counts(3, 0, 0), complete), 0)
        self.assertEqual(E.final_exit(counts(3, 0, 0), incomplete), 1)
        self.assertEqual(E.final_exit(counts(3, 0, 1), incomplete), 3)
        self.assertEqual(E.final_exit(counts(3, 1, 1), complete), 1)

    def test_an_unavailable_receipts_directory_or_diagnostics_module_is_an_incomplete_log_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "a-file")
            with open(blocker, "w"):
                pass
            code, out, err = run_main(["--receipts", os.path.join(blocker, "under-a-file"), "--binary", FAKE], fake_cases())
            self.assertEqual(code, 1, out + err)                                                  # the cases passed; the log and receipt could not be kept
            self.assertIn("receipts_unavailable", out)
        with mock.patch.object(case_log, "load", side_effect=case_log.LogUnavailable("diagnostics.py is missing")):
            code, out, _ = run_main(["--binary", FAKE], fake_cases())
        self.assertEqual(code, 1, out)
        self.assertIn("NO LOG", out)


class TheEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()      # the logs the runner keeps by default land here, not in the system temp directory

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def call(self, *argv):
        done = subprocess.run([ENTRY, *argv], capture_output=True, text=True, stdin=subprocess.DEVNULL, env=dict(os.environ, TMPDIR=self.scratch.name), timeout=300)
        return done.returncode, done.stdout, done.stderr

    def test_soak_usage_and_the_blocked_process_cases_through_the_real_entry_point(self):
        code, out, _ = self.call("--tier", "soak")
        self.assertEqual((code, "U01 soak: NOT RUN" in out), (4, True))
        self.assertEqual(self.call("--no-such-flag")[0], 2)
        self.assertEqual(self.call("--case", "U01-E-999")[0], 2)
        code, out, _ = self.call("--case", "U01-E-003", "--case", "U01-E-006")                       # no binary: blocked, counted, never passed
        self.assertEqual(code, 3, out)
        self.assertIn("U01 cases: total=2 passed=0 failed=0 blocked=2", out)
        self.assertIn("replay: scripts/e2e/u01 --tier full --case U01-E-003 --case U01-E-006", out)

    def test_the_smoke_tier_runs_the_real_host_cases_in_seconds(self):
        started = time.monotonic()
        code, out, err = self.call("--tier", "smoke")
        self.assertEqual(code, 0, out + err)
        self.assertIn("U01 cases: total=2 passed=2 failed=0 blocked=0", out)
        self.assertIn("evidence COMPLETE", out)
        self.assertIn("U01 e2e tier=smoke: QUALIFIED", out)
        self.assertLess(time.monotonic() - started, 120)

    def test_one_real_sigkill_case_through_the_entry_point_with_the_python_stand_in(self):
        code, out, err = self.call("--case", "U01-E-006", "--binary", FAKE)
        self.assertEqual(code, 0, out + err)
        self.assertIn("PASS    U01-E-006", out)
        self.assertIn("killed with SIGKILL after acks [3, 17, 40, 41, 60, 83]", out)


if __name__ == "__main__":
    unittest.main()
