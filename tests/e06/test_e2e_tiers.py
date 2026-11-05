"""E06 test-asset clause "CI selects smoke/full/soak explicitly": the tiers of scripts/e2e/e06, run on the REAL script.

* On the real tree: `--tier soak` is not run and exits 4, an unknown or incomplete tier exits 2, and `--tier smoke` passes with `cargo` and `rustc`
  absent from PATH (that is what makes it a smoke tier). None of these starts the full suite, so none of them recurses into this file.
* On a staged tree: the real script is copied byte for byte beside stub test modules (each records that it ran) and a stub audit.py (records its
  arguments and exits with a chosen status). That shows which modules each tier runs, that the audit runs only in the full tier, that the exit
  codes of the full tier are unchanged, and that `--tests-only` and `--audit-only` still mean what they meant. A stub, not the real suite, is what
  keeps `--tier full` from running this file again.
* Every tests/e06/test_*.py module must be assigned to the smoke list or the full-only list, so a new module cannot escape the tiers.
"""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(ROOT, "scripts", "e2e", "e06")
BASH = shutil.which("bash")
sys.dont_write_bytecode = True


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def module_lists(script_text):
    """(smoke, full_only) as the script declares them."""
    found = {}
    for name in ("SMOKE_MODULES", "FULL_ONLY_MODULES"):
        match = re.search(r"^%s=\(([^)]*)\)$" % name, script_text, re.M)
        if not match:
            raise AssertionError("scripts/e2e/e06 has no %s=(...) line" % name)
        found[name] = match.group(1).split()
    return found["SMOKE_MODULES"], found["FULL_ONLY_MODULES"]


def assignment_problems(smoke, full_only, on_disk):
    """Everything wrong with how the modules on disk are split between the tiers."""
    problems = []
    both = [m for m in smoke if m in full_only]
    if both:
        problems.append("in both lists: %s" % ", ".join(both))
    for listing, label in ((smoke, "smoke"), (full_only, "full-only")):
        if len(set(listing)) != len(listing):
            problems.append("a module is listed twice in the %s list" % label)
    missing = sorted(set(on_disk) - set(smoke) - set(full_only))
    if missing:
        problems.append("in no tier: %s" % ", ".join(missing))
    stale = sorted((set(smoke) | set(full_only)) - set(on_disk))
    if stale:
        problems.append("listed but not on disk: %s" % ", ".join(stale))
    return problems


def run_script(script, args, env=None, cwd=None):
    return subprocess.run([BASH, script] + list(args), capture_output=True, text=True, timeout=300, env=env, cwd=cwd)


@unittest.skipIf(BASH is None, "bash is not available")
class RealTreeTierTests(unittest.TestCase):
    def test_soak_is_not_run_says_why_and_exits_4_which_is_not_a_pass(self):
        proc = run_script(SCRIPT, ["--tier", "soak"])
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertIn("NOT RUN", proc.stderr)
        self.assertIn("one-shot", proc.stderr)
        self.assertIn("not a pass", proc.stderr)
        self.assertNotIn("Ran ", proc.stdout + proc.stderr, "soak must not run any test")

    def test_an_unknown_tier_a_missing_tier_and_a_tier_with_a_half_flag_exit_2_and_run_nothing(self):
        for args in (["--tier", "nightly"], ["--tier", ""], ["--tier"], ["--tier", "full", "--tests-only"], ["--tier", "smoke", "--audit-only"],
                     ["--tier", "smoke", "--json", "x"]):
            with self.subTest(args=args):
                proc = run_script(SCRIPT, args)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertNotIn("Ran ", proc.stdout + proc.stderr)
                self.assertTrue(proc.stderr.strip(), "a refusal says why")

    def test_smoke_passes_with_cargo_and_rustc_absent_and_says_it_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("dirname", "git"):
                found = shutil.which(name)
                if found:
                    os.symlink(found, os.path.join(tmp, name))
            os.symlink(os.path.realpath(sys.executable), os.path.join(tmp, "python3"))
            self.assertIsNone(shutil.which("cargo", path=tmp))
            self.assertIsNone(shutil.which("rustc", path=tmp))
            env = {"PATH": tmp, "HOME": tmp}
            proc = run_script(SCRIPT, ["--tier", "smoke"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertRegex(proc.stderr, r"Ran [1-9][0-9]* tests?")
        self.assertIn("PARTIAL", proc.stdout)
        self.assertIn("not an E06 qualification", proc.stdout)
        smoke, _ = module_lists(read(SCRIPT))
        on_disk = [n for n in os.listdir(HERE) if re.match(r"^test_.*\.py$", n)]
        self.assertIn("ran %d of %d test modules" % (len(smoke), len(on_disk)), proc.stdout)


@unittest.skipIf(BASH is None, "bash is not available")
class StagedTreeTierTests(unittest.TestCase):
    """The real script, byte for byte, over stub modules and a stub audit."""

    def stage(self, tmp):
        smoke, full_only = module_lists(read(SCRIPT))
        os.makedirs(os.path.join(tmp, "scripts", "e2e"))
        os.makedirs(os.path.join(tmp, "scripts", "e06"))
        os.makedirs(os.path.join(tmp, "tests", "e06"))
        staged = os.path.join(tmp, "scripts", "e2e", "e06")
        shutil.copyfile(SCRIPT, staged)
        os.chmod(staged, os.stat(SCRIPT).st_mode | stat.S_IXUSR)
        with open(SCRIPT, "rb") as a, open(staged, "rb") as b:
            self.assertEqual(hashlib.sha256(a.read()).hexdigest(), hashlib.sha256(b.read()).hexdigest())
        for name in smoke + full_only:
            with open(os.path.join(tmp, "tests", "e06", name), "w", encoding="utf-8") as fh:
                fh.write(
                    "import os, unittest\n"
                    "NAME = %r\n"
                    "class Stub(unittest.TestCase):\n"
                    "    def test_it(self):\n"
                    "        with open(os.environ['E06_TIER_MARK'], 'a') as fh:\n"
                    "            fh.write('module ' + NAME + '\\n')\n"
                    "        if os.environ.get('E06_TIER_SKIP') == NAME:\n"
                    "            self.skipTest(os.environ['E06_TIER_SKIP_WHY'])\n"
                    "        self.assertNotEqual(os.environ.get('E06_TIER_FAIL'), NAME)\n" % name)
        with open(os.path.join(tmp, "scripts", "e06", "audit.py"), "w", encoding="utf-8") as fh:
            fh.write(
                "import os, sys\n"
                "with open(os.environ['E06_TIER_MARK'], 'a') as fh:\n"
                "    fh.write('audit ' + ' '.join(sys.argv[1:]) + '\\n')\n"
                "sys.exit(int(os.environ.get('E06_TIER_AUDIT_EXIT', '0')))\n")
        with open(os.path.join(tmp, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write("[workspace]\n")
        return staged, smoke, full_only, os.path.join(tmp, "marks.txt")

    def run_staged(self, args, audit_exit=0, fail=None, skip=None, why=""):
        with tempfile.TemporaryDirectory() as tmp:
            staged, smoke, full_only, mark = self.stage(tmp)
            env = dict(os.environ, E06_TIER_MARK=mark, E06_TIER_AUDIT_EXIT=str(audit_exit))
            for name in ("E06_TIER_FAIL", "E06_TIER_SKIP", "E06_TIER_SKIP_WHY"):
                env.pop(name, None)
            if fail:
                env["E06_TIER_FAIL"] = fail
            if skip:
                env["E06_TIER_SKIP"], env["E06_TIER_SKIP_WHY"] = skip, why
            proc = run_script(staged, args, env=env)
            marks = [m.replace(tmp, "<root>") for m in (read(mark).splitlines() if os.path.exists(mark) else [])]
        return proc, marks, smoke, full_only

    def modules_run(self, marks):
        return sorted(m.split(" ", 1)[1] for m in marks if m.startswith("module "))

    def audits_run(self, marks):
        return [m for m in marks if m.startswith("audit")]

    def test_no_tier_and_tier_full_are_the_same_run_all_modules_then_the_audit_with_its_exit_status(self):
        for audit_exit in (0, 3, 1):
            outcomes = []
            for args in ([], ["--tier", "full"]):
                with self.subTest(args=args, audit_exit=audit_exit):
                    proc, marks, smoke, full_only = self.run_staged(args, audit_exit=audit_exit)
                    self.assertEqual(proc.returncode, audit_exit, proc.stdout + proc.stderr)
                    self.assertEqual(self.modules_run(marks), sorted(smoke + full_only))
                    self.assertEqual(len(self.audits_run(marks)), 1)
                    self.assertTrue(marks[-1].startswith("audit"), "the audit follows the tests")
                    outcomes.append((proc.returncode, sorted(marks)))
            self.assertEqual(outcomes[0], outcomes[1])

    def test_arguments_after_tier_full_reach_the_audit_as_before(self):
        _, marks, _, _ = self.run_staged(["--tier", "full", "--json", "OUT"])[:4]
        self.assertTrue(any(m.startswith("audit audit --manifest-path ") and m.endswith(" --json OUT") for m in marks), marks)

    def test_a_failing_test_stops_the_full_tier_before_the_audit_with_exit_1(self):
        for args in ([], ["--tier", "full"]):
            with self.subTest(args=args):
                proc, marks, _, _ = self.run_staged(args, fail="test_batch.py")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertEqual(self.audits_run(marks), [])
                self.assertIn("tests FAILED", proc.stderr)

    def test_smoke_runs_exactly_the_smoke_modules_and_never_the_audit(self):
        proc, marks, smoke, full_only = self.run_staged(["--tier", "smoke"], audit_exit=1)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.modules_run(marks), sorted(smoke))
        self.assertEqual(self.audits_run(marks), [])
        self.assertIn("ran %d of %d test modules" % (len(smoke), len(smoke) + len(full_only)), proc.stdout)
        self.assertIn("PARTIAL", proc.stdout)

    def test_a_failing_smoke_module_fails_the_smoke_tier_but_a_failing_full_only_module_does_not_run_there(self):
        proc, marks, smoke, full_only = self.run_staged(["--tier", "smoke"], fail=sorted(self.smoke_names())[0])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("smoke tier FAILED", proc.stderr)
        self.assertNotIn("PARTIAL", proc.stdout, "a failed smoke run claims nothing, not even a partial pass")
        proc, marks, smoke, full_only = self.run_staged(["--tier", "smoke"], fail=full_only[0])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_smoke_test_that_skips_for_want_of_cargo_or_rustc_fails_the_tier_but_another_skip_does_not(self):
        first = sorted(self.smoke_names())[0]
        for why in ("cargo is not installed", "no nightly rustc"):
            with self.subTest(why=why):
                proc, _, _, _ = self.run_staged(["--tier", "smoke"], skip=first, why=why)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("not a smoke module", proc.stderr)
                self.assertIn("smoke tier FAILED", proc.stderr)
                self.assertNotIn("PARTIAL", proc.stdout)
        proc, _, _, _ = self.run_staged(["--tier", "smoke"], skip=first, why="revision abc is not in this repository")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def smoke_names(self):
        return module_lists(read(SCRIPT))[0]

    def test_soak_runs_nothing_in_a_staged_tree_either(self):
        proc, marks, _, _ = self.run_staged(["--tier", "soak"])
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertEqual(marks, [])

    def test_tests_only_and_audit_only_mean_what_they_meant(self):
        proc, marks, smoke, full_only = self.run_staged(["--tests-only"], audit_exit=3)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.modules_run(marks), sorted(smoke + full_only))
        self.assertEqual(self.audits_run(marks), [])
        proc, marks, _, _ = self.run_staged(["--audit-only", "--json", "OUT"], audit_exit=3)
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertEqual(self.modules_run(marks), [])
        self.assertEqual(len(self.audits_run(marks)), 1)
        self.assertTrue(self.audits_run(marks)[0].endswith(" --json OUT"))


class ModuleAssignmentTests(unittest.TestCase):
    def test_every_test_module_is_assigned_to_exactly_one_tier(self):
        smoke, full_only = module_lists(read(SCRIPT))
        on_disk = [n for n in os.listdir(HERE) if re.match(r"^test_.*\.py$", n)]
        self.assertEqual(assignment_problems(smoke, full_only, on_disk), [])
        self.assertIn("test_e2e_tiers.py", full_only, "this file starts the script, so it must never be in the tier the script runs from inside it")

    def test_planted_assignment_faults_are_reported(self):
        on_disk = ["test_a.py", "test_b.py", "test_c.py"]
        self.assertEqual(assignment_problems(["test_a.py"], ["test_b.py", "test_c.py"], on_disk), [])
        self.assertTrue(any("in no tier: test_c.py" in p for p in assignment_problems(["test_a.py"], ["test_b.py"], on_disk)))
        self.assertTrue(any("in both lists: test_b.py" in p for p in assignment_problems(["test_a.py", "test_b.py"], ["test_b.py", "test_c.py"], on_disk)))
        self.assertTrue(any("listed but not on disk: test_z.py" in p for p in assignment_problems(["test_a.py", "test_z.py"], ["test_b.py", "test_c.py"], on_disk)))
        self.assertTrue(any("twice" in p for p in assignment_problems(["test_a.py", "test_a.py"], ["test_b.py", "test_c.py"], on_disk)))


if __name__ == "__main__":
    unittest.main()
