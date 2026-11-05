#!/usr/bin/env python3
"""Tests for run-workspace-verification.py: builds go only through strict-remote RCH, and a
printed test summary is never taken as proof that a job completed.

Nothing here launches rch, cargo, QEMU or a network call.  Evidence classes are labelled:

* REAL rch      - a transcript recorded from the installed ``rch`` (a refusal of a
                  non-compilation command, so no build ran).  It is the only real rch output
                  available; there is no recorded successful or unconfirmed run to replay.
* REAL process  - harmless child processes run through the real ``launch`` executor.  The
                  terminal marker text they print is taken verbatim from the strings embedded
                  in the rch binary, but the producer is a stand-in, NOT rch.
* SIMULATED     - hand-built ``Outcome`` values fed to ``judge`` / ``run_case`` / ``main``.

Each rejection has a permitted positive twin.

Run:  python3 -B scripts/test/test_run_workspace_verification.py
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "run-workspace-verification.py"

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("ffw_workspace_verification", SCRIPT)
W = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = W
_spec.loader.exec_module(W)

CLEAN_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent-home"}
UNCONFIRMED = "RCH_SCOPED_COMPLETION_UNCONFIRMED"

# REAL rch: recorded from `RCH_REQUIRE_REMOTE=1 rch exec -- echo ...` (exit status 1).
REAL_RCH_REFUSAL = (
    "  \x1b[2m2026-11-04T23:22:26.358093Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[1;33mrch::hook\x1b[0m\x1b[33m: "
    "\x1b[33mexec called with non-compilation command: echo ffw-probe-not-a-build\x1b[0m\n"
    "    \x1b[2;3mat\x1b[0m rch/src/hook.rs:3613 \x1b[2;3mon\x1b[0m ThreadId(1)\n\n"
    "[RCH] remote required; refusing local fallback [RCH-E301] (non-compilation command)\n"
)


def libtest(*binaries):
    """cargo test output.  Each binary: (kind, name, announced, passed, failed, ignored)."""
    lines = []
    for kind, name, announced, passed, failed, ignored in binaries:
        head = (f"     Running unittests src/{name}.rs (target/debug/deps/{name}-0123456789abcdef)"
                if kind == "unit" else f"   Doc-tests {name}")
        lines += [head, "", f"running {announced} tests"]
        lines += [f"test t{i} ... ok" for i in range(passed)]
        verdict = "ok" if failed == 0 else "FAILED"
        lines += ["", f"test result: {verdict}. {passed} passed; {failed} failed; {ignored} ignored; "
                      f"0 measured; 0 filtered out; finished in 0.01s", ""]
    return "\n".join(lines) + "\n"


TEST_OK = libtest(("unit", "lib", 5, 5, 0, 0))


def oc(output="", rc=0, **kw):
    """SIMULATED executor outcome."""
    return W.Outcome(rc, kw.get("timed_out", False), kw.get("pid", 4242), output, kw.get("truncated", False),
                     kw.get("undecodable", False), kw.get("capture_error"), kw.get("recovery"))


class Recorder:
    """Stands in for the executor and keeps every call it receives."""

    def __init__(self, script=None):
        self.calls = []
        self.script = script or self.default

    @staticmethod
    def default(argv):
        return oc(TEST_OK if "test" in argv else "")

    def __call__(self, argv, **kw):
        self.calls.append({"argv": list(argv), **kw})
        result = self.script(list(argv))
        if isinstance(result, BaseException):
            raise result
        return result


def case_by_id(suite, case_id, env=None):
    return next(c for c in W.suite_cases(suite, env or CLEAN_ENV) if c.case_id == case_id)


Q00 = case_by_id("q00", "q00_test_support_unit_and_canaries")


def judge(case, out, timeout_s=60):
    return W.judge(case, out, duration_ms=7, timeout_s=timeout_s)


def run_main(argv, recorder, env=None, results_dir=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(W, "git_commit_short", return_value="deadbeef"):
        rc = W.main(argv, executor=recorder, env=CLEAN_ENV if env is None else env, results_dir=results_dir)
    return rc, out.getvalue(), err.getvalue()


# Patterns that must never come back into the script.
OFFENDERS = {
    "local-bypass assignment": re.compile(r"RCH_CARGO_WRAPPER_BYPASS[\"']\s*\]\s*="),
    "personal volume": re.compile(r"/Volumes/"),
    "personal build dir": re.compile(r"trj-data"),
    "home-relative toolchain": re.compile(r"\.rustup"),
    "host triple toolchain path": re.compile(r"aarch64-apple-darwin"),
    "home-joined path": re.compile(r"Path\.home\(\)\s*/"),
    "absolute manifest path": re.compile(r"--manifest-path"),
    "local target dir": re.compile(r"--target-dir"),
}


def policy_violations(source):
    return sorted(name for name, pat in OFFENDERS.items() if pat.search(source))


# Repo-wide guard.  Narrower than OFFENDERS on purpose: flags (--manifest-path, --target-dir) are
# legitimate in other scripts, but a local-build bypass or a personal build path never is.
REPO_WIDE_OFFENDERS = {
    "local-bypass assignment": re.compile(r"RCH_CARGO_WRAPPER_BYPASS[\"']\s*\]\s*="),
    "local-bypass set to 1": re.compile(r"RCH_CARGO_WRAPPER_BYPASS\s*=\s*[\"']?1"),
    "rch disabled in env": re.compile(r"RCH_ENABLED\s*=\s*[\"']?0|RCH_ENABLED[\"']\s*\]\s*=\s*[\"']0"),
    "personal build volume": re.compile(r"/Volumes/trj-data"),
    "home toolchain cargo": re.compile(r"\.rustup/toolchains|\.rustup[\"']\s*/"),
}
SCAN_DIRS = ("scripts", "toolchain/src")
# Ephemeral / git-ignored build output. `build` is the git-ignored tree the QEMU runner syncs cargo target dirs
# into (`.gitignore: build/`); a test below fails if a TRACKED file ever lives under one of these names.
SKIP_DIRS = {"__pycache__", "target", "build", ".git"}
MAX_SCAN_BYTES = 4 << 20
SELF_REL = "scripts/test/test_run_workspace_verification.py"  # holds the patterns above as planted data


def scan_tree(root, dirs=SCAN_DIRS, exclude=()):
    """Return (hits, scanned, skipped): hits maps relpath -> [(offender, line)].

    Files that cannot be read as text, or exceed MAX_SCAN_BYTES, are returned in ``skipped``
    so a blind spot is visible rather than silent."""
    hits, skipped, scanned = {}, [], 0
    root = Path(root)
    for d in dirs:
        for cur, subdirs, files in os.walk(root / d):
            subdirs[:] = sorted(x for x in subdirs if x not in SKIP_DIRS)
            for name in sorted(files):
                path = Path(cur) / name
                rel = path.relative_to(root).as_posix()
                if rel in exclude:
                    continue
                try:
                    if path.stat().st_size > MAX_SCAN_BYTES:
                        skipped.append(rel)
                        continue
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    skipped.append(rel)
                    continue
                scanned += 1
                for off, pat in REPO_WIDE_OFFENDERS.items():
                    for m in pat.finditer(text):
                        hits.setdefault(rel, []).append((off, text.count("\n", 0, m.start()) + 1))
    return hits, scanned, skipped


class TestRemoteOnlyArgv(unittest.TestCase):
    def test_every_cargo_case_is_wrapped_in_rch_exec_and_python_cases_are_not(self):
        cases = W.suite_cases("all", CLEAN_ENV)
        cargo = [c for c in cases if c.kind != "python"]
        python = [c for c in cases if c.kind == "python"]
        self.assertEqual((len(cases), len(cargo), len(python)), (14, 11, 3))
        for c in cargo:
            self.assertEqual(c.argv[:4], ["rch", "exec", "--", "cargo"], c.case_id)
        for c in python:
            self.assertEqual(c.argv[0], sys.executable, c.case_id)
            self.assertNotIn("rch", c.argv)
            self.assertNotIn("cargo", c.argv)
        self.assertEqual(len({c.case_id for c in cases}), 14, "case ids stay unique across suites")

    def test_exact_recorded_argv_for_representative_cases(self):
        nightly_std = ["-Z", "build-std=core,alloc,std,panic_abort"]
        inc = ["--config", "build.incremental=false"]
        self.assertEqual(Q00.argv, ["rch", "exec", "--", "cargo", "test", "-p", "franken-test-support", *inc])
        self.assertEqual(case_by_id("p01", "p01_workspace_clippy_zero_warnings").argv,
                         ["rch", "exec", "--", "cargo", "clippy", "--workspace", "--all-targets", *inc,
                          "--", "-D", "warnings"])
        self.assertEqual(case_by_id("p01", "p01_workspace_cross_check_ppc_be").argv,
                         ["rch", "exec", "--", "cargo", "+nightly", "check", "--workspace", *inc,
                          "--target", "powerpc-unknown-linux-musl", *nightly_std])
        # The harness is off by default (a default speaker build has no test-support edge), so the self-test
        # must ask for it; without `--features harness` the binary exits 2.
        self.assertEqual(case_by_id("p01", "p01_virtual_house_e2e").argv,
                         ["rch", "exec", "--", "cargo", "run", "-p", "franken-speaker", "--features", "harness", *inc,
                          "--", "--self-test", "--virtual-house"])
        mips = case_by_id("p05", "p05_asupersync_check_mips_be")
        self.assertEqual(mips.argv,
                         ["rch", "exec", "--", "cargo", "+nightly", "check", "--no-default-features", "--lib", *inc,
                          "--target", "mips-unknown-linux-musl", *nightly_std])
        self.assertEqual(mips.cwd, W.REPO_ROOT.parent / "asupersync")

    def test_cargo_argv_carries_no_absolute_or_personal_paths(self):
        home = str(Path.home())
        for c in W.suite_cases("all", CLEAN_ENV):
            if c.kind == "python":
                continue
            for tok in c.argv:
                self.assertFalse(tok.startswith("/"), f"{c.case_id}: absolute path {tok}")
                self.assertNotIn(home, tok)
            self.assertNotIn("--manifest-path", c.argv)
            self.assertNotIn("--target-dir", c.argv)

    def test_per_invocation_rch_options_go_before_the_separator_only(self):
        env = dict(CLEAN_ENV, FFW_RCH_EXEC_ARGS="--worker w1 --source-content-receipt")
        argv = case_by_id("q00", "q00_test_support_unit_and_canaries", env).argv
        self.assertEqual(argv[:6], ["rch", "exec", "--worker", "w1", "--source-content-receipt", "--"])
        self.assertEqual(argv[6], "cargo")
        for bad in ("--worker w1 -- cargo", "--worker 'unterminated"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                W.suite_cases("q00", dict(CLEAN_ENV, FFW_RCH_EXEC_ARGS=bad))
        rec = Recorder()
        rc, _, err = run_main(["q00"], rec, env=dict(CLEAN_ENV, FFW_RCH_EXEC_ARGS="a -- b"))
        self.assertEqual((rc, rec.calls), (2, []), "a bad option string must stop the run before anything executes")
        self.assertIn("FFW_RCH_EXEC_ARGS", err)

    def test_nightly_toolchain_is_a_name_never_a_path(self):
        env = dict(CLEAN_ENV, FFW_NIGHTLY_TOOLCHAIN="nightly-2026-01-01")
        self.assertIn("+nightly-2026-01-01", case_by_id("p01", "p01_workspace_cross_check_mips_be", env).argv)
        self.assertIn("+nightly", case_by_id("p01", "p01_workspace_cross_check_mips_be").argv)


class TestNoLocalEscape(unittest.TestCase):
    def test_strict_remote_is_forced_and_local_escapes_are_scrubbed(self):
        hostile = dict(CLEAN_ENV, RCH_CARGO_WRAPPER_BYPASS="1", RCH_ENABLED="0", RCH_REQUIRE_REMOTE="0")
        rec = Recorder()
        rc, _, _ = run_main(["q00", "--results-dir", self._tmp()], rec, env=hostile)
        self.assertEqual(rc, 0)
        env = rec.calls[0]["env"]
        self.assertEqual(env["RCH_REQUIRE_REMOTE"], "1")
        self.assertNotIn("RCH_CARGO_WRAPPER_BYPASS", env)
        self.assertNotIn("RCH_ENABLED", env)
        self.assertEqual(env["PATH"], "/usr/bin:/bin", "ordinary environment is preserved")
        rec2 = Recorder()
        run_main(["q00", "--results-dir", self._tmp()], rec2)
        self.assertEqual(rec2.calls[0]["env"]["RCH_REQUIRE_REMOTE"], "1")

    def test_python_cases_also_never_receive_the_escapes(self):
        hostile = dict(CLEAN_ENV, RCH_CARGO_WRAPPER_BYPASS="1", RCH_ENABLED="0")
        rec = Recorder()
        run_main(["e07", "--results-dir", self._tmp()], rec, env=hostile)
        self.assertEqual(len(rec.calls), 2)
        for call in rec.calls:
            self.assertEqual(call["argv"][0], sys.executable)
            self.assertNotIn("RCH_CARGO_WRAPPER_BYPASS", call["env"])
            self.assertNotIn("RCH_ENABLED", call["env"])
            self.assertNotIn("RCH_REQUIRE_REMOTE", call["env"], "local python is not a remote build")

    def test_old_local_cargo_overrides_cannot_reintroduce_a_local_cargo(self):
        env = dict(CLEAN_ENV, FFW_STABLE_CARGO="/tmp/evil/cargo", FFW_NIGHTLY_CARGO="/tmp/evil/nightly-cargo",
                   FFW_BUILD_DIR="/tmp/evil-build")
        rec = Recorder()
        rc, _, err = run_main(["p01", "--results-dir", self._tmp()], rec, env=env)
        self.assertEqual(rc, 0)
        self.assertEqual(len(rec.calls), 5)
        for call in rec.calls:
            self.assertEqual(call["argv"][:4], ["rch", "exec", "--", "cargo"])
            self.assertNotIn("/tmp/evil", " ".join(call["argv"]))
        for name in ("FFW_STABLE_CARGO", "FFW_NIGHTLY_CARGO", "FFW_BUILD_DIR"):
            self.assertIn(name, err, "an ignored override must be reported, not silently dropped")

    def test_script_source_has_no_bypass_or_personal_defaults(self):
        self.assertEqual(policy_violations(SCRIPT.read_text(encoding="utf-8")), [])
        planted = {
            "local-bypass assignment": 'env["RCH_CARGO_WRAPPER_BYPASS"] = "1"',
            "personal volume": 'Path("/Volumes/x")',
            "personal build dir": '"trj-data"',
            "home-relative toolchain": '".rustup"',
            "host triple toolchain path": "stable-aarch64-apple-darwin",
            "home-joined path": 'Path.home() / "x"',
            "absolute manifest path": '"--manifest-path"',
            "local target dir": '"--target-dir"',
        }
        self.assertEqual(set(planted), set(OFFENDERS))
        for name, snippet in planted.items():
            self.assertEqual(policy_violations(snippet), [name], name)

    def _tmp(self):
        d = tempfile.TemporaryDirectory(prefix="ffw wsv ")
        self.addCleanup(d.cleanup)
        return d.name


class TestVerdicts(unittest.TestCase):
    def run_one(self, case, script=None, **kw):
        rec = Recorder(script)
        return W.run_case(case, executor=rec, base_env=CLEAN_ENV, **kw), rec

    def test_cargo_test_pass_counts_the_tests_cargo_reported_and_assertions_stay_null(self):
        out = "[RCH] remote w1 (build 12s)\n" + libtest(("unit", "lib", 7, 7, 0, 0), ("doc", "x", 5, 5, 0, 0),
                                                         ("unit", "empty", 0, 0, 0, 0))
        res, rec = self.run_one(Q00, lambda a: oc(out))
        self.assertEqual((res["status"], res["completion"]), ("passed", "confirmed"))
        self.assertEqual(res["tests_passed"], 12)
        self.assertIsNone(res["assertions_checked"], "a hardcoded assertion count is fabricated evidence")
        self.assertEqual(res["executor"], "rch_remote_required")
        self.assertEqual(res["rch_lines"], ["[RCH] remote w1 (build 12s)"])
        self.assertEqual(res["libtest"]["binaries_started"], 3)
        self.assertTrue(res["libtest"]["balanced"] and res["libtest"]["cross_checked"])
        self.assertEqual(len(rec.calls), 1)

    def test_non_test_cargo_cases_pass_on_exit_zero_without_a_test_count(self):
        res, _ = self.run_one(case_by_id("p01", "p01_workspace_cross_check_ppc_be"), lambda a: oc(""))
        self.assertEqual((res["status"], res["tests_passed"]), ("passed", None))

    def test_rch_refusing_to_go_remote_fails_the_case_with_no_second_attempt(self):
        res, rec = self.run_one(Q00, lambda a: oc("[RCH] remote required; refusing local fallback (no workers)", 103))
        self.assertEqual(res["status"], "failed")
        self.assertIn("exit_code=103", res["failure_reason"])
        self.assertEqual(len(rec.calls), 1, "no retry and no unwrapped fallback invocation")
        self.assertEqual(rec.calls[0]["argv"][0], "rch")

    def test_missing_rch_launcher_fails_closed_instead_of_falling_back(self):
        res, rec = self.run_one(Q00, lambda a: FileNotFoundError(2, "No such file", "rch"))
        self.assertEqual(res["status"], "failed")
        self.assertIn("launcher_missing", res["failure_reason"])
        self.assertIn("no local fallback", res["failure_reason"])
        self.assertEqual([c["argv"][0] for c in rec.calls], ["rch"], "cargo was never tried directly")

    def test_a_secret_in_output_fails_the_case_without_echoing_the_secret(self):
        leak = "connecting to 192.168.7.44 and 02:aa:bb:cc:dd:ee\n" + TEST_OK
        res, _ = self.run_one(Q00, lambda a: oc(leak))
        self.assertEqual(res["status"], "failed")
        self.assertIn("rfc1918_ip", res["failure_reason"])
        self.assertIn("mac_address", res["failure_reason"])
        self.assertNotIn("192.168.7.44", json.dumps(res))
        ok, _ = self.run_one(Q00, lambda a: oc("127.0.0.1 203.0.113.9\n" + TEST_OK))
        self.assertEqual(ok["status"], "passed", "loopback and documentation addresses are not site data")

    def test_failure_tails_carry_no_checkout_or_home_paths(self):
        home = str(Path.home())
        noisy = f"error[E0432]: in {W.REPO_ROOT}/crates/x/src/lib.rs and {home}/.cache/y\n"
        res, _ = self.run_one(case_by_id("p01", "p01_workspace_cross_check_mips_be"), lambda a: oc(noisy, 101))
        self.assertIn("<repo>/crates/x/src/lib.rs", res["failure_reason"])
        self.assertNotIn(str(W.REPO_ROOT), res["failure_reason"])
        self.assertNotIn(home + "/.cache", res["failure_reason"])

    def test_missing_asupersync_checkout_is_a_failed_prerequisite_not_a_run(self):
        with tempfile.TemporaryDirectory(prefix="ffw wsv ") as d:
            missing = os.path.join(d, "no-such-checkout")
            case = case_by_id("p05", "p05_asupersync_check_mips_be", dict(CLEAN_ENV, FFW_ASUPERSYNC_DIR=missing))
            res, rec = self.run_one(case)
            self.assertEqual(res["status"], "failed")
            self.assertIn("prerequisite_missing", res["failure_reason"])
            self.assertEqual(rec.calls, [], "nothing may execute when the working directory is absent")
            present = case_by_id("p05", "p05_asupersync_check_mips_be", dict(CLEAN_ENV, FFW_ASUPERSYNC_DIR=d))
            res2, rec2 = self.run_one(present)
            self.assertEqual(res2["status"], "passed")
            self.assertEqual(rec2.calls[0]["cwd"], d)

    def test_timeout_is_forwarded_to_the_executor(self):
        _, rec = self.run_one(Q00, timeout_s=3)
        self.assertEqual(rec.calls[0]["timeout_s"], 3)


class TestTerminalEvidence(unittest.TestCase):
    """A printed pass summary cannot yield qualified success without confirmed completion."""

    # ---- REAL rch ---------------------------------------------------------------------

    def test_real_recorded_rch_refusal_is_a_confirmed_failure_not_a_pass(self):
        res = judge(Q00, oc(REAL_RCH_REFUSAL, 1))
        self.assertEqual((res["status"], res["completion"], res["exit_code"]), ("failed", "confirmed", 1))
        self.assertEqual(res["rch_lines"],
                         ["[RCH] remote required; refusing local fallback [RCH-E301] (non-compilation command)"])
        self.assertNotIn("\x1b", res["failure_reason"], "terminal colour codes never reach the receipt")
        self.assertEqual(res["terminal_markers"], [], "an ordinary refusal carries no supervisor marker")
        self.assertEqual(W.terminal_markers(REAL_RCH_REFUSAL), [])

    # ---- REAL process, marker text from the rch binary ---------------------------------

    def test_real_process_printing_the_unconfirmed_marker_is_unconfirmed_even_with_a_pass_summary(self):
        code = ("import sys\nsys.stdout.write(%r)\nprint(%r)\nsys.exit(%d)\n")
        for rc in (255, 0):
            with self.subTest(exit=rc), tempfile.TemporaryDirectory(prefix="ffw launch ") as d:
                case = W.Case("real_marker", "cargo-test", [sys.executable, "-c", code % (TEST_OK, UNCONFIRMED, rc)],
                              Path(d))
                res = W.run_case(case, executor=W.launch, base_env=CLEAN_ENV, timeout_s=60, log_dir=Path(d) / "logs")
                self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
                self.assertEqual(res["terminal_markers"], [UNCONFIRMED])
                self.assertEqual(res["exit_code"], rc)
                self.assertIn("printed test results do not establish completion", res["failure_reason"])

    def test_real_process_that_outlives_its_timeout_is_not_killed_and_leaves_a_recovery_identity(self):
        with tempfile.TemporaryDirectory(prefix="ffw launch ") as d:
            logs = Path(d) / "logs"
            code = "import time\ntime.sleep(1.5)\nprint('late')\n"
            case = W.Case("slow_case", "python", [sys.executable, "-c", code], Path(d))
            with warnings.catch_warnings():
                # Not killing the job is the point; Python warns that the Popen object outlived its child.
                warnings.simplefilter("ignore", ResourceWarning)
                res = W.run_case(case, executor=W.launch, base_env=CLEAN_ENV, timeout_s=0.3, log_dir=logs)
                import gc
                gc.collect()
            self.assertEqual((res["status"], res["completion"], res["exit_code"]), ("failed", "unconfirmed", None))
            self.assertIn("NOT killed", res["failure_reason"])
            rec = res["recovery"]
            self.assertTrue(rec["log"].endswith("slow_case.log") and rec["rc_file"].endswith("slow_case.rc"))
            pid = rec["pid"]
            os.kill(pid, 0)  # raises if the job had been killed
            rc_file = logs / "slow_case.rc"
            deadline = time.monotonic() + 20
            while not rc_file.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(rc_file.read_text(), "0\n", "the job kept running and recorded its own exit status")
            self.assertIn("late", (logs / "slow_case.log").read_text())
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)

    def test_the_job_survives_the_checker_process_exiting_and_still_records_its_exit_status(self):
        """REAL process: a checker that times out and then exits must not take the job with it."""
        with tempfile.TemporaryDirectory(prefix="ffw launch ") as d:
            logs = Path(d) / "logs"
            child = 'import time; time.sleep(1.2); print("after")'
            driver = (
                "import importlib.util, os, sys\n"
                "sys.dont_write_bytecode = True\n"
                f"spec = importlib.util.spec_from_file_location('w', {str(SCRIPT)!r})\n"
                "w = importlib.util.module_from_spec(spec); sys.modules['w'] = w; spec.loader.exec_module(w)\n"
                f"out = w.launch([sys.executable, '-c', {child!r}], cwd={d!r}, env={{'PATH': '/usr/bin:/bin'}}, "
                f"timeout_s=0.2, log_dir={str(logs)!r}, name='orphan')\n"
                "print(out.timed_out, out.pid, flush=True)\n"
                "os._exit(0)\n")
            p = subprocess.run([sys.executable, "-B", "-c", driver], capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            timed_out, pid = p.stdout.split()
            self.assertEqual(timed_out, "True")
            rc_file = logs / "orphan.rc"
            deadline = time.monotonic() + 20
            while not rc_file.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(rc_file.read_text(), "0\n", f"job {pid} should have outlived the checker")
            self.assertIn("after", (logs / "orphan.log").read_text())

    def test_launch_is_a_faithful_executor(self):
        with tempfile.TemporaryDirectory(prefix="ffw launch ") as d:
            logs = Path(d) / "logs"
            order = "import sys\nprint('a', flush=True)\nprint('b', file=sys.stderr, flush=True)\nprint('c', flush=True)\n"
            out = W.launch([sys.executable, "-c", order], cwd=d, env=CLEAN_ENV, timeout_s=60, log_dir=logs, name="o")
            self.assertEqual((out.rc, out.timed_out, out.output), (0, False, "a\nb\nc\n"))
            self.assertEqual((logs / "o.rc").read_text(), "0\n")
            odd = W.launch([sys.executable, "-c", "import sys; print(sys.argv[1])", "x y 'z' $HOME"],
                           cwd=d, env=CLEAN_ENV, timeout_s=60, log_dir=logs, name="q")
            self.assertEqual(odd.output, "x y 'z' $HOME\n", "arguments reach the command unmangled")
            three = W.launch([sys.executable, "-c", "import sys; sys.exit(3)"], cwd=d, env=CLEAN_ENV,
                             timeout_s=60, log_dir=logs, name="r")
            self.assertEqual(three.rc, 3)
            self.assertEqual((logs / "r.rc").read_text(), "3\n")
            with self.assertRaises(FileNotFoundError):
                W.launch(["no-such-command-ffw"], cwd=d, env=CLEAN_ENV, timeout_s=60, log_dir=logs, name="m")
            with self.assertRaises(FileExistsError):
                W.launch([sys.executable, "-c", "pass"], cwd=d, env=CLEAN_ENV, timeout_s=60, log_dir=logs, name="o")
            self.assertEqual((logs / "o.rc").read_text(), "0\n", "an earlier capture is never clobbered")

    # ---- SIMULATED: terminal markers ----------------------------------------------------

    def test_supervisor_markers_override_a_zero_exit_and_a_clean_pass_summary(self):
        cases = {
            "RCH_SCOPED_COMPLETION_UNCONFIRMED": "unconfirmed",
            "RCH_EXTERNAL_DEADLINE": "confirmed",
            "RCH_SCOPED_LAUNCH_ALREADY_OWNED": "confirmed",
            "RCH_OWNERSHIP_CHECK_UNAVAILABLE": "confirmed",
            "RCH_OWNERSHIP_REPAIR_UNAVAILABLE": "confirmed",
            "RCH_REPO_UPDATER_UNAVAILABLE": "confirmed",
            "RCH_SOURCE_CLAIM_REPAIRED_EMPTY_CANCELLATION": "confirmed",
            "RCH_BUILD_IDENTITY_UNAVAILABLE": "confirmed",
        }
        for marker, completion in cases.items():
            for rc in (0, 255, 137, 125):
                with self.subTest(marker=marker, rc=rc):
                    res = judge(Q00, oc(TEST_OK + "\n" + marker + "\n", rc))
                    self.assertEqual(res["status"], "failed")
                    self.assertEqual(res["completion"], completion)
                    self.assertEqual(res["terminal_markers"], [marker])
        self.assertEqual(judge(Q00, oc(TEST_OK, 0))["status"], "passed", "the same output without a marker passes")

    def test_a_marker_is_found_through_log_prefixes_and_colour_but_not_inside_other_words(self):
        for line in (f"\x1b[31m{UNCONFIRMED}\x1b[0m", f"2026-11-04T23:00:00Z ERROR rch: {UNCONFIRMED}",
                     f"  {UNCONFIRMED}  "):
            with self.subTest(line=line):
                self.assertEqual(judge(Q00, oc(TEST_OK + line + "\n", 0))["completion"], "unconfirmed")
        for line in (f"X{UNCONFIRMED}", f"{UNCONFIRMED}_X", f"{UNCONFIRMED.lower()}", "RCH_SCOPED_COMPLETION"):
            with self.subTest(line=line):
                self.assertEqual(judge(Q00, oc(TEST_OK + line + "\n", 0))["status"], "passed")

    # ---- SIMULATED: completion not established -------------------------------------------

    def test_a_job_still_running_at_the_timeout_is_unconfirmed_whatever_it_already_printed(self):
        recovery = {"pid": 4242, "started_utc": "2026-11-04T23:00:00Z", "log": "<repo>/build/x.log",
                    "rc_file": "<repo>/build/x.rc", "note": "not killed"}
        res = judge(Q00, oc(TEST_OK, None, timed_out=True, recovery=recovery), timeout_s=5)
        self.assertEqual((res["status"], res["completion"], res["exit_code"]), ("failed", "unconfirmed", None))
        self.assertEqual(res["recovery"], recovery)
        self.assertIn("NOT killed", res["failure_reason"])
        done = judge(Q00, oc(TEST_OK, 0, recovery=recovery))
        self.assertEqual((done["status"], done["recovery"]), ("passed", None), "a confirmed case carries no recovery block")

    def test_no_recorded_exit_status_is_never_a_pass(self):
        res = judge(Q00, oc(TEST_OK, None))
        self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
        self.assertIn("no exit status", res["failure_reason"])

    def test_incomplete_capture_is_never_a_pass(self):
        for name, kw in (("truncated", {"truncated": True}), ("undecodable", {"undecodable": True}),
                         ("read error", {"capture_error": "could not read capture log: OSError"})):
            with self.subTest(name):
                res = judge(Q00, oc(TEST_OK, 0, **kw))
                self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
                self.assertIn("capture_incomplete", res["failure_reason"])
        self.assertEqual(judge(Q00, oc(TEST_OK, 0))["status"], "passed")

    # ---- SIMULATED: expected test execution ----------------------------------------------

    def test_absent_test_execution_is_never_a_pass(self):
        for name, out in (("empty output", ""), ("build only", "   Compiling x v0.1.0\n    Finished `test` profile\n"),
                          ("zero tests", libtest(("unit", "lib", 0, 0, 0, 0)))):
            with self.subTest(name):
                res = judge(Q00, oc(out, 0))
                self.assertEqual(res["status"], "failed")
                self.assertIn("no_tests_executed", res["failure_reason"])
        self.assertEqual(judge(Q00, oc(libtest(("unit", "lib", 1, 1, 0, 0)), 0))["status"], "passed")

    def test_a_test_binary_that_started_but_never_reported_is_unconfirmed(self):
        first_done = libtest(("unit", "lib", 5, 5, 0, 0))
        cut_off = first_done + "     Running unittests src/b.rs (target/debug/deps/b-0123456789abcdef)\n\nrunning 3 tests\ntest t0 ... ok\n"
        res = judge(Q00, oc(cut_off, 0))
        self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
        self.assertIn("never reported a result", res["failure_reason"])
        self.assertFalse(res["libtest"]["balanced"])
        # a start followed directly by another start is the same defect, in the middle
        middle = ("     Running unittests src/a.rs (target/debug/deps/a-0123456789abcdef)\n\nrunning 2 tests\n"
                  + first_done)
        self.assertEqual(judge(Q00, oc(middle, 0))["completion"], "unconfirmed")
        # permitted twin: every start reported
        both = libtest(("unit", "a", 2, 2, 0, 0), ("doc", "a", 1, 1, 0, 0))
        self.assertEqual(judge(Q00, oc(both, 0))["status"], "passed")

    def test_a_result_must_account_for_the_tests_it_announced(self):
        short = libtest(("unit", "lib", 5, 4, 0, 0))  # announced 5, accounted for 4
        res = judge(Q00, oc(short, 0))
        self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
        self.assertIn("does not account", res["failure_reason"])
        self.assertEqual(judge(Q00, oc(libtest(("unit", "lib", 5, 3, 0, 2)), 0))["status"], "passed",
                         "ignored tests count toward the announced total")

    def test_failed_tests_fail_the_case_even_with_a_zero_exit(self):
        out = libtest(("unit", "lib", 3, 2, 1, 0))
        res = judge(Q00, oc(out, 0))
        self.assertEqual((res["status"], res["completion"]), ("failed", "confirmed"))
        self.assertIn("tests_failed", res["failure_reason"])

    def test_a_printed_pass_summary_does_not_rescue_a_nonzero_exit(self):
        res = judge(Q00, oc(TEST_OK, 101))
        self.assertEqual((res["status"], res["completion"]), ("failed", "confirmed"))
        self.assertIn("exit_code=101", res["failure_reason"])

    def test_results_without_start_lines_pass_only_when_exit_is_zero_and_they_are_clean(self):
        bare = "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        res = judge(Q00, oc(bare, 0))
        self.assertEqual(res["status"], "passed")
        self.assertFalse(res["libtest"]["cross_checked"], "nothing to cross-check is recorded, not hidden")
        self.assertEqual(judge(Q00, oc(bare, 255))["status"], "failed")

    def test_non_test_cases_are_not_held_to_libtest_rules_but_markers_still_apply(self):
        check = case_by_id("p01", "p01_workspace_cross_check_ppc_be")
        self.assertEqual(judge(check, oc("    Finished `dev` profile\n", 0))["status"], "passed")
        res = judge(check, oc("    Finished `dev` profile\n" + UNCONFIRMED + "\n", 0))
        self.assertEqual((res["status"], res["completion"]), ("failed", "unconfirmed"))
        self.assertIsNone(res["libtest"])

    # ---- SIMULATED: the suite does not run on past an unconfirmed job ---------------------

    def test_an_unconfirmed_case_halts_the_suite_but_an_ordinary_failure_does_not(self):
        with tempfile.TemporaryDirectory(prefix="ffw wsv ") as d:
            def unconfirmed_first(argv):
                return oc(TEST_OK + UNCONFIRMED + "\n", 255) if "--workspace" in argv and "test" in argv else oc(TEST_OK)

            rec = Recorder(unconfirmed_first)
            rc, out, _ = run_main(["p01", "--results-dir", d], rec)
            receipt = json.loads(out)
            self.assertEqual(rc, 1)
            self.assertEqual(len(rec.calls), 1, "nothing may start while an earlier job's fate is unknown")
            self.assertEqual(receipt["halted_after"], "p01_workspace_unit_tests")
            self.assertEqual(receipt["counts"], {"passed": 0, "failed": 1, "not_run": 4})
            self.assertEqual([c["status"] for c in receipt["cases"]], ["failed"] + ["not_run"] * 4)
            self.assertIn("not_run: p01_workspace_unit_tests", receipt["cases"][1]["failure_reason"])
            self.assertEqual(receipt["overall_status"], "failed")

            rec2 = Recorder(lambda argv: oc("", 1) if "clippy" in argv else oc(TEST_OK if "test" in argv else ""))
            rc2, out2, _ = run_main(["p01", "--results-dir", d], rec2)
            receipt2 = json.loads(out2)
            self.assertEqual((rc2, len(rec2.calls)), (1, 5), "a confirmed failure lets the remaining cases run")
            self.assertIsNone(receipt2["halted_after"])
            self.assertEqual(receipt2["counts"], {"passed": 4, "failed": 1, "not_run": 0})

    def test_overall_success_requires_every_case_confirmed(self):
        with tempfile.TemporaryDirectory(prefix="ffw wsv ") as d:
            rc, out, _ = run_main(["p01", "--results-dir", d], Recorder())
            receipt = json.loads(out)
            self.assertEqual((rc, receipt["overall_status"], receipt["counts"]["passed"]), (0, "passed", 5))
            self.assertTrue(all(c["completion"] == "confirmed" for c in receipt["cases"]))


class TestRecovery(unittest.TestCase):
    """--recover re-judges an earlier run from its .log/.rc files and executes nothing."""

    RUN = "q00-20261104T231500Z-abc123"
    CASE = "q00_test_support_unit_and_canaries"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ffw recover ")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.logs = self.root / "logs" / self.RUN
        self.logs.mkdir(parents=True)
        self.results = self.root / "results"

    def put(self, case_id=None, log=None, rc=None, logs=None):
        d = logs or self.logs
        if log is not None:
            (d / f"{case_id or self.CASE}.log").write_text(log, encoding="utf-8")
        if rc is not None:
            (d / f"{case_id or self.CASE}.rc").write_text(rc, encoding="utf-8")

    def recover(self, logs=None, *extra):
        boom = Recorder(lambda a: AssertionError("recovery must not execute anything"))
        rc, out, err = run_main(["--recover", str(logs or self.logs), "--results-dir", str(self.results), *extra], boom)
        self.assertEqual(boom.calls, [], "recovery never launches a command")
        return rc, (json.loads(out) if out.strip() else None), err

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.logs.iterdir()}

    def test_a_finished_job_is_re_judged_to_a_pass_and_nothing_is_edited(self):
        self.put(log=TEST_OK, rc="0\n")
        before = self.snapshot()
        rc, receipt, _ = self.recover()
        self.assertEqual(rc, 0)
        case = receipt["cases"][0]
        self.assertEqual((case["status"], case["completion"], case["exit_code"], case["tests_passed"]),
                         ("passed", "confirmed", 0, 5))
        self.assertEqual((receipt["recovered_from"], receipt["suite_id"], receipt["overall_status"]),
                         (self.RUN, "q00", "passed"))
        self.assertEqual(self.snapshot(), before, "the earlier run's logs are untouched")
        self.assertEqual(len(list(self.results.glob("suite-receipt-q00-*.json"))), 1, "a new receipt was written")

    def test_a_recovered_failure_is_a_confirmed_failure(self):
        self.put(log=TEST_OK, rc="3\n")
        rc, receipt, _ = self.recover()
        self.assertEqual(rc, 1)
        self.assertEqual((receipt["cases"][0]["status"], receipt["cases"][0]["completion"]), ("failed", "confirmed"))
        self.assertIn("exit_code=3", receipt["cases"][0]["failure_reason"])

    def test_a_job_with_no_exit_status_yet_stays_unconfirmed(self):
        self.put(log=TEST_OK)  # still running, or lost: there is no .rc
        for label, rc_text in (("missing", None), ("empty", ""), ("garbage", "abc\n"), ("two lines", "0\n1\n")):
            with self.subTest(label):
                if rc_text is not None:
                    self.put(rc=rc_text)
                rc, receipt, _ = self.recover()
                case = receipt["cases"][0]
                self.assertEqual((rc, case["status"], case["completion"]), (1, "failed", "unconfirmed"))
                self.assertIn("no exit status", case["failure_reason"])
                self.assertEqual(receipt["halted_after"], self.CASE)
                self.assertIn("nothing was executed", case["recovery"]["note"])

    def test_the_same_predicate_applies_to_recovered_output(self):
        self.put(log=TEST_OK + UNCONFIRMED + "\n", rc="0\n")
        _, receipt, _ = self.recover()
        self.assertEqual((receipt["cases"][0]["status"], receipt["cases"][0]["completion"]), ("failed", "unconfirmed"))
        self.assertEqual(receipt["cases"][0]["terminal_markers"], [UNCONFIRMED])
        self.put(log=libtest(("unit", "lib", 5, 4, 0, 0)), rc="0\n")
        self.assertEqual(self.recover()[1]["cases"][0]["completion"], "unconfirmed", "short-counted tests")
        self.put(log=TEST_OK, rc="0\n")
        self.assertEqual(self.recover()[1]["cases"][0]["status"], "passed", "permitted twin")

    def test_cases_the_earlier_run_never_started_are_not_run(self):
        logs = self.root / "logs" / "p01-20261104T231500Z-abc123"
        logs.mkdir()
        self.put("p01_workspace_unit_tests", TEST_OK, "0\n", logs=logs)
        rc, receipt, _ = self.recover(logs)
        self.assertEqual(rc, 1)
        self.assertEqual([c["status"] for c in receipt["cases"]], ["passed"] + ["not_run"] * 4)
        self.assertEqual(receipt["counts"], {"passed": 1, "failed": 0, "not_run": 4})
        self.assertIn("left no capture log", receipt["cases"][1]["failure_reason"])
        self.assertEqual(receipt["overall_status"], "failed")

    def test_bad_recover_usage_exits_2_without_a_receipt(self):
        self.put(log=TEST_OK, rc="0\n")
        bad = self.root / "logs" / "not-a-run-dir"
        bad.mkdir()
        cases = [("missing directory", ["--recover", str(self.root / "nope")]),
                 ("badly named directory", ["--recover", str(bad)]),
                 ("suite disagrees", ["p01", "--recover", str(self.logs)])]
        zzz = self.root / "logs" / "zzz-20261104T231500Z-abc123"
        zzz.mkdir()
        cases.append(("unknown suite in the name", ["--recover", str(zzz)]))
        for label, argv in cases:
            with self.subTest(label):
                boom = Recorder(lambda a: AssertionError("must not execute"))
                rc, _, err = run_main(argv + ["--results-dir", str(self.results)], boom)
                self.assertEqual((rc, boom.calls), (2, []))
                self.assertIn("error:", err)
        self.assertFalse(self.results.exists())
        agree = run_main(["q00", "--recover", str(self.logs), "--results-dir", str(self.results)],
                         Recorder(lambda a: AssertionError("no")))[0]
        self.assertEqual(agree, 0, "a matching suite name is accepted (permitted twin)")

    def test_real_processes_timeout_without_a_kill_then_recover_the_real_outcome(self):
        """REAL process end to end: the stand-in job outlives the timeout, finishes on its own,
        and --recover turns its files into a confirmed verdict.  The producer is not rch."""
        code = "import sys, time\ntime.sleep(1.2)\nsys.stdout.write(%r)\n" % TEST_OK

        def slow_job(argv, **kw):
            return W.launch([sys.executable, "-c", code], **kw)

        logs_root = self.root / "e2e-logs"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            rc, out, _ = run_main(["q00", "--case-timeout-s", "0.3", "--results-dir", str(self.results),
                                   "--log-root", str(logs_root)], slow_job)
            import gc
            gc.collect()
        first = json.loads(out)
        self.assertEqual(rc, 1)
        self.assertEqual((first["cases"][0]["status"], first["cases"][0]["completion"]), ("failed", "unconfirmed"))
        pid = first["cases"][0]["recovery"]["pid"]
        (run_dir,) = list(logs_root.iterdir())
        rc_file = run_dir / f"{self.CASE}.rc"
        deadline = time.monotonic() + 20
        while not rc_file.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(rc_file.read_text(), "0\n", "the job was not killed and finished by itself")
        with contextlib.suppress(ChildProcessError):
            os.waitpid(pid, 0)
        originals = {p.name: p.read_bytes() for p in self.results.glob("*.json")}
        recovered_rc, second, _ = self.recover(run_dir)
        self.assertEqual(recovered_rc, 0)
        self.assertEqual((second["cases"][0]["status"], second["cases"][0]["completion"],
                          second["cases"][0]["tests_passed"]), ("passed", "confirmed", 5))
        self.assertEqual(second["recovered_from"], run_dir.name)
        after = {p.name: p.read_bytes() for p in self.results.glob("*.json")}
        self.assertTrue(set(originals) < set(after), "recovery added a receipt")
        for name, data in originals.items():
            self.assertEqual(after[name], data, "the original receipt is never edited")


class TestMainAndReceipts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ffw wsv ")
        self.addCleanup(tmp.cleanup)
        self.results = Path(tmp.name) / "results dir"

    def test_receipt_records_what_ran_and_exit_code_follows_the_verdict(self):
        rec = Recorder()
        rc, out, _ = run_main(["q00", "--results-dir", str(self.results)], rec)
        self.assertEqual(rc, 0)
        files = list(self.results.glob("suite-receipt-q00-*.json"))
        self.assertEqual(len(files), 1)
        receipt = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(json.loads(out), receipt)
        self.assertEqual((receipt["schema_version"], receipt["suite_id"], receipt["git_commit"],
                          receipt["remote_required"], receipt["overall_status"]), (2, "q00", "deadbeef", True, "passed"))
        case = receipt["cases"][0]
        self.assertEqual((case["executor"], case["exit_code"], case["completion"], case["tests_passed"],
                          case["assertions_checked"]), ("rch_remote_required", 0, "confirmed", 5, None))
        self.assertEqual(case["argv"][:4], ["rch", "exec", "--", "cargo"])
        rc2, _, _ = run_main(["q00", "--results-dir", str(self.results)], Recorder(lambda a: oc("refused", 1)))
        self.assertEqual(rc2, 1)
        failed = [json.loads(p.read_text(encoding="utf-8")) for p in self.results.glob("suite-receipt-q00-*.json")]
        self.assertEqual(sorted(r["overall_status"] for r in failed), ["failed", "passed"])

    def test_existing_receipts_are_never_overwritten(self):
        self.results.mkdir(parents=True)
        legacy = self.results / "suite-receipt-q00.json"
        legacy_bytes = b'{"schema_version": 1, "legacy": "local-bypass host observation"}\n'
        legacy.write_bytes(legacy_bytes)
        for _ in range(2):
            self.assertEqual(run_main(["q00", "--results-dir", str(self.results)], Recorder())[0], 0)
        self.assertEqual(legacy.read_bytes(), legacy_bytes)
        new = sorted(p.name for p in self.results.glob("suite-receipt-q00-*.json"))
        self.assertEqual(len(new), 2)
        for name in new:
            self.assertRegex(name, r"^suite-receipt-q00-\d{8}T\d{6}Z-[0-9a-f]{6}\.json$")

    def test_name_collision_picks_a_new_name_instead_of_clobbering(self):
        self.results.mkdir(parents=True)
        taken = self.results / "suite-receipt-q00-S-aaaaaa.json"
        taken.write_text("original", encoding="utf-8")
        with mock.patch.object(W.secrets, "token_hex", side_effect=["aaaaaa", "bbbbbb"]):
            path = W.write_receipt(self.results, "q00", "new", stamp="S")
        self.assertEqual(path.name, "suite-receipt-q00-S-bbbbbb.json")
        self.assertEqual(taken.read_text(encoding="utf-8"), "original")
        with mock.patch.object(W.secrets, "token_hex", return_value="aaaaaa"), self.assertRaises(OSError):
            W.write_receipt(self.results, "q00", "new", stamp="S")
        self.assertEqual(taken.read_text(encoding="utf-8"), "original")

    def test_a_run_writes_only_to_the_requested_directory(self):
        def listing(p):
            return sorted(os.listdir(p)) if p.is_dir() else []
        before = (listing(W.RESULTS_DIR), listing(W.REPO_ROOT / "build"))
        run_main(["q00", "--results-dir", str(self.results)], Recorder())
        self.assertEqual((listing(W.RESULTS_DIR), listing(W.REPO_ROOT / "build")), before)
        self.assertEqual(W.RESULTS_DIR, W.REPO_ROOT / "toolchain" / "results")
        self.assertEqual(W.LOG_ROOT, W.REPO_ROOT / "build" / "workspace-verification")

    def test_bad_invocations_exit_2_before_anything_executes(self):
        for argv in (["nosuchsuite"], ["q00", "--case-timeout-s", "0"], ["q00", "--case-timeout-s", "-5"]):
            with self.subTest(argv=argv):
                rec = Recorder()
                rc, _, _ = run_main(argv + ["--results-dir", str(self.results)], rec)
                self.assertEqual((rc, rec.calls), (2, []))
        self.assertFalse(self.results.exists(), "no receipt for a run that never started")

    def test_a_secret_in_a_receipt_blocks_the_write(self):
        leak = Recorder(lambda a: oc("ok\n" + TEST_OK))
        with mock.patch.object(W, "sanitize", side_effect=lambda t: t + " 10.1.2.3"):
            rc, _, err = run_main(["q00", "--results-dir", str(self.results)], leak)
        self.assertEqual(rc, 2)
        self.assertIn("rfc1918_ip", err)
        self.assertNotIn("10.1.2.3", err, "the leaked value is never printed, only the pattern name")
        self.assertFalse(self.results.exists())

    def test_cli_runs_from_a_foreign_cwd_and_rejects_an_unknown_suite_without_building(self):
        with tempfile.TemporaryDirectory(prefix="ffw cwd ") as d:
            p = subprocess.run([sys.executable, "-B", str(SCRIPT), "nosuchsuite", "--results-dir", d + "/r"],
                               cwd=d, capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
            self.assertIn("Unknown suite", p.stderr)
            self.assertFalse(os.path.exists(d + "/r"))
            h = subprocess.run([sys.executable, "-B", str(SCRIPT), "--help"], cwd=d, capture_output=True,
                               text=True, timeout=60)
            self.assertEqual(h.returncode, 0)


class TestRepoWidePolicy(unittest.TestCase):
    """The bypass came back once already, through an uncoordinated overwrite of run-suite."""

    PLANTED = {
        "local-bypass assignment": 'env["RCH_CARGO_WRAPPER_BYPASS"] = "1"\n',
        "local-bypass set to 1": "export RCH_CARGO_WRAPPER_BYPASS=1\n",
        "rch disabled in env": "RCH_ENABLED=0 cargo build\n",
        "personal build volume": 'BUILD = "/Volumes/trj-data/build"\n',
        "home toolchain cargo": 'CARGO = home / ".rustup" / "toolchains" / "x"\nalt = "~/.rustup/toolchains/y"\n',
    }

    def make_tree(self, files):
        tmp = tempfile.TemporaryDirectory(prefix="ffw policy ")
        self.addCleanup(tmp.cleanup)
        for rel, data in files.items():
            path = Path(tmp.name) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return tmp.name

    def test_no_script_in_the_repo_has_a_local_bypass_or_personal_build_path(self):
        hits, scanned, skipped = scan_tree(W.REPO_ROOT, exclude={SELF_REL})
        self.assertGreaterEqual(scanned, 10, "the scan must actually walk the scripts")
        self.assertEqual(hits, {}, "local-build bypass or personal build path found: " + json.dumps(hits, indent=1))
        self.assertEqual([s for s in skipped if s.endswith((".py", ".sh"))], [],
                         "a source file the guard could not read would be a blind spot")

    def test_the_scanner_reports_each_planted_offender_with_its_path_and_line(self):
        self.assertEqual(set(self.PLANTED), set(REPO_WIDE_OFFENDERS))
        files = {"scripts/clean.py": "import os\nprint('fine')\n",
                 "toolchain/src/clean.sh": "#!/bin/sh\nexport RCH_REQUIRE_REMOTE=1\n"}
        root = self.make_tree(files)
        self.assertEqual(scan_tree(root)[0], {}, "a clean tree has no hits (positive twin)")
        for name, snippet in self.PLANTED.items():
            with self.subTest(name):
                tree = self.make_tree(dict(files, **{"scripts/e2e/entry": "#!/bin/sh\n\n" + snippet}))
                hits, scanned, _ = scan_tree(tree)
                self.assertEqual(scanned, 3)
                self.assertEqual(list(hits), ["scripts/e2e/entry"], "extensionless script is scanned")
                found = {off for off, _ in hits["scripts/e2e/entry"]}
                self.assertEqual(found, {name})
                self.assertEqual(hits["scripts/e2e/entry"][0][1], 3, "reports the 1-based line")

    def test_build_output_and_bytecode_directories_are_not_scanned(self):
        bad = self.PLANTED["personal build volume"]
        root = self.make_tree({
            "toolchain/src/crate/target/.rustc_info.json": bad,
            "toolchain/src/crate/build/hello-init-target/.rustc_info.json": bad,
            "scripts/__pycache__/x.py": bad,
            "scripts/real.py": bad,
        })
        self.assertEqual(list(scan_tree(root)[0]), ["scripts/real.py"])

    def test_skipping_build_is_by_exact_directory_name_so_lookalikes_are_still_scanned(self):
        bad = self.PLANTED["personal build volume"]
        root = self.make_tree({
            "scripts/build/skipped.py": bad,
            "scripts/builder/x.py": bad,
            "scripts/rebuild/y.py": bad,
            "scripts/e2e/build.py": bad,
            "toolchain/src/crate/build.sh": bad,
        })
        self.assertEqual(sorted(scan_tree(root)[0]),
                         ["scripts/builder/x.py", "scripts/e2e/build.py", "scripts/rebuild/y.py",
                          "toolchain/src/crate/build.sh"])

    def test_no_tracked_file_hides_under_a_skipped_directory(self):
        """The scan skips SKIP_DIRS by name, so a tracked file under one would be an invisible blind spot."""
        try:
            out = subprocess.run(["git", "ls-files", "-z", "--", *SCAN_DIRS], cwd=W.REPO_ROOT,
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as err:
            self.skipTest(f"git is unavailable: {err}")
        if out.returncode != 0:
            self.skipTest(f"git ls-files failed: {out.stderr.strip()[:120]}")
        hidden = [p for p in out.stdout.split("\0") if p and (set(Path(p).parts[:-1]) & SKIP_DIRS)]
        self.assertEqual(hidden, [], "tracked files under a directory the policy scan skips would never be scanned")

    def test_unreadable_and_oversized_files_are_reported_as_skipped_not_silently_clean(self):
        root = self.make_tree({
            "scripts/blob.bin": b"\xff\xfe/Volumes/trj-data",
            "scripts/big.py": b"#" * (MAX_SCAN_BYTES + 1),
            "scripts/ok.py": "x = 1\n",
        })
        hits, scanned, skipped = scan_tree(root)
        self.assertEqual((hits, scanned), ({}, 1))
        self.assertEqual(sorted(skipped), ["scripts/big.py", "scripts/blob.bin"])

    def test_the_exclusion_is_exact_so_a_planted_offender_elsewhere_is_still_found(self):
        bad = self.PLANTED["local-bypass set to 1"]
        root = self.make_tree({SELF_REL: bad, "scripts/test/other_test.py": bad})
        self.assertEqual(list(scan_tree(root, exclude={SELF_REL})[0]), ["scripts/test/other_test.py"])


if __name__ == "__main__":
    unittest.main()
