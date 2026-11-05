"""E06 test-asset clause "bounded timeouts": no child process started by scripts/e06 or tests/e06 can wait forever.

* The scan reads every .py file in those two directories (AST, so a `timeout=` on a continuation line counts and a `timeout=None` does not) and
  names each child that has no deadline. A `Popen` is a stream and has no `timeout=`; it is bounded only when its function also starts a
  `threading.Timer` (the kill) or passes a timeout to `.communicate` / `.wait`.
* The scan is itself tested with planted unbounded children, so a scan that sees nothing cannot pass for a clean tree.
* The three children in scripts/e06/batch.py that had no deadline (`audit.py plan`, the local `git` reads, `git archive`) are run for real
  against a child that never finishes, and must end in a typed refusal within their (short, test-chosen) deadline.
"""
import ast
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
SCANNED = ("scripts/e06", "tests/e06")
SPAWNERS = {"run", "call", "check_call", "check_output"}


def _is_attr(node, owner, names):
    return (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == owner and node.attr in names)


def _has_deadline(call):
    for keyword in call.keywords:
        if keyword.arg == "timeout":
            return not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None)
    return False


def unbounded_children(source, label):
    """Every child process in `source` that has no deadline, as readable strings."""
    tree = ast.parse(source)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            problems.append("%s:%d `from subprocess import` hides the spawn calls from this scan" % (label, node.lineno))
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess" and alias.asname:
                    problems.append("%s:%d `import subprocess as %s` hides the spawn calls from this scan" % (label, node.lineno, alias.asname))
    bounded_streams = set()
    for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
        timer = any(_is_attr(c.func, "threading", {"Timer"}) for c in calls)
        waits = any(isinstance(c.func, ast.Attribute) and c.func.attr in ("communicate", "wait") and _has_deadline(c) for c in calls)
        if timer or waits:
            bounded_streams.update(id(c) for c in calls)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_attr(node.func, "subprocess", SPAWNERS) and not _has_deadline(node):
            problems.append("%s:%d subprocess.%s without a timeout" % (label, node.lineno, node.func.attr))
        elif _is_attr(node.func, "subprocess", {"Popen"}) and id(node) not in bounded_streams:
            problems.append("%s:%d subprocess.Popen with no Timer and no deadline on communicate/wait" % (label, node.lineno))
        elif _is_attr(node.func, "os", {"system", "popen"}):
            problems.append("%s:%d os.%s has no deadline" % (label, node.lineno, node.func.attr))
    return problems


def scan_tree(root):
    problems = []
    for sub in SCANNED:
        base = os.path.join(root, *sub.split("/"))
        for name in sorted(os.listdir(base)):
            if name.endswith(".py"):
                with open(os.path.join(base, name), encoding="utf-8") as fh:
                    problems.extend(unbounded_children(fh.read(), "%s/%s" % (sub, name)))
    return problems


class ScanTests(unittest.TestCase):
    def test_no_child_process_in_scripts_e06_or_tests_e06_is_without_a_deadline(self):
        self.assertEqual(scan_tree(ROOT), [])

    def test_the_scan_names_planted_unbounded_children_and_passes_bounded_ones(self):
        bad = {
            "a plain run": "import subprocess\nsubprocess.run(['x'])\n",
            "a check_output": "import subprocess\nsubprocess.check_output(['x'])\n",
            "a timeout of None": "import subprocess\nsubprocess.run(['x'], timeout=None)\n",
            "a popen with nothing": "import subprocess\ndef f():\n    with subprocess.Popen(['x']) as p:\n        p.wait()\n",
            "a from-import": "from subprocess import run\nrun(['x'], timeout=5)\n",
            "an aliased import": "import subprocess as sp\nsp.run(['x'], timeout=5)\n",
            "os.system": "import os\nos.system('x')\n",
            "a multi-line call without it": "import subprocess\nsubprocess.run(\n    ['x',\n     'y'],\n    capture_output=True,\n)\n",
        }
        for name, source in bad.items():
            with self.subTest(name):
                self.assertEqual(len(unbounded_children(source, "planted")), 1, name)
        good = {
            "a run with a timeout": "import subprocess\nsubprocess.run(['x'], timeout=5)\n",
            "a timeout on a continuation line": "import subprocess\nsubprocess.run(\n    ['x'],\n    capture_output=True,\n    timeout=60,\n)\n",
            "a popen killed by a timer": "import subprocess, threading\ndef f():\n    with subprocess.Popen(['x']) as p:\n        threading.Timer(5, p.kill).start()\n",
            "a popen with a deadline on communicate": "import subprocess\ndef f():\n    p = subprocess.Popen(['x'])\n    p.communicate(timeout=5)\n",
        }
        for name, source in good.items():
            with self.subTest(name):
                self.assertEqual(unbounded_children(source, "planted"), [], name)

    def test_removing_one_deadline_from_a_real_file_is_found(self):
        with open(os.path.join(HERE, "test_evidence.py"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('capture_output=True, timeout=60)', text)
        self.assertEqual(unbounded_children(text, "t"), [])
        self.assertEqual(len(unbounded_children(text.replace('capture_output=True, timeout=60)', 'capture_output=True)', 1), "t")), 1)


def load_batch():
    spec = importlib.util.spec_from_file_location("ffw_e06_batch_deadlines", os.path.join(ROOT, "scripts", "e06", "batch.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BA = load_batch()
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
REAL_GIT = shutil.which("git")
LONG = 20          # seconds the stand-in child would run; every test must end far sooner than this
WITHIN = 10        # a deadline of 1 s must end the call well inside this


def executable(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


@unittest.skipIf(REAL_GIT is None or shutil.which("sleep") is None, "git and sleep are needed")
class BatchChildrenAreBoundedTests(unittest.TestCase):
    def git_repo(self, tmp):
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, "f.txt"), "w", encoding="utf-8") as fh:
            fh.write("x\n")
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True, timeout=60)
        subprocess.run(GIT + ["-C", repo, "add", "-A"], check=True, capture_output=True, timeout=60)
        subprocess.run(GIT + ["-C", repo, "commit", "-q", "-m", "m"], check=True, capture_output=True, timeout=60)
        rev = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=60).stdout.strip()
        return repo, rev

    def fake_git_dir(self, tmp, hang_on):
        """A `git` that hangs when any argument is in `hang_on` and is the real git otherwise."""
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        executable(os.path.join(bin_dir, "git"),
                   "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in %s) exec sleep %d ;; esac\ndone\nexec %s \"$@\"\n" % (
                       "|".join(hang_on) if hang_on else "__never__", LONG, REAL_GIT))
        return bin_dir

    def test_a_planning_child_that_never_finishes_is_refused_within_its_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            hang = os.path.join(tmp, "audit.py")
            with open(hang, "w", encoding="utf-8") as fh:
                fh.write("import time\ntime.sleep(%d)\n" % LONG)
            start = time.monotonic()
            with self.assertRaises(RuntimeError) as caught:
                BA.workspace_plan(tmp, audit_py=hang, timeout=1)
            self.assertLess(time.monotonic() - start, WITHIN)
            self.assertIn("did not finish within 1 s", str(caught.exception))

    def test_a_local_git_read_that_never_finishes_is_refused_within_its_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _ = self.git_repo(tmp)
            bin_dir = self.fake_git_dir(tmp, ["rev-parse"])
            with mock.patch.dict(os.environ, {"PATH": bin_dir + os.pathsep + os.environ["PATH"]}):
                start = time.monotonic()
                with self.assertRaises(RuntimeError) as caught:
                    BA.run_git(repo, "rev-parse", "HEAD", timeout=1)
                self.assertLess(time.monotonic() - start, WITHIN)
                self.assertIn("git rev-parse did not finish within 1 s", str(caught.exception))
                self.assertEqual(BA.run_git(repo, "cat-file", "-t", "HEAD", timeout=30), "commit", "git that answers still works")

    def test_a_git_archive_that_never_finishes_is_killed_and_refused_within_its_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, rev = self.git_repo(tmp)
            bin_dir = self.fake_git_dir(tmp, ["archive"])
            with mock.patch.dict(os.environ, {"PATH": bin_dir + os.pathsep + os.environ["PATH"]}):
                start = time.monotonic()
                with self.assertRaises(RuntimeError) as caught:
                    BA.archive_into(repo, rev, os.path.join(tmp, "out"), timeout=1)
                self.assertLess(time.monotonic() - start, WITHIN)
                self.assertIn("git archive did not finish within 1 s", str(caught.exception))

    def test_a_git_archive_that_finishes_still_extracts_the_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, rev = self.git_repo(tmp)
            dest = os.path.join(tmp, "out")
            BA.archive_into(repo, rev, dest, timeout=60)
            with open(os.path.join(dest, "f.txt"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "x\n")

    def test_a_complete_archive_with_closed_stdout_and_a_lingering_child_still_times_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, rev = self.git_repo(tmp)
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(bin_dir)
            executable(os.path.join(bin_dir, "git"),
                       "#!%s\nimport os, subprocess, sys, time\n"
                       "if 'archive' in sys.argv[1:]:\n"
                       "    rc = subprocess.run([%r] + sys.argv[1:], timeout=30).returncode\n"
                       "    if rc:\n        sys.exit(rc)\n"
                       "    os.close(1)\n    time.sleep(3)\n    sys.exit(0)\n"
                       "os.execv(%r, [%r] + sys.argv[1:])\n" % (
                           os.path.realpath(sys.executable), REAL_GIT, REAL_GIT, REAL_GIT))
            dest = os.path.join(tmp, "out")
            with mock.patch.dict(os.environ, {"PATH": bin_dir + os.pathsep + os.environ["PATH"]}):
                start = time.monotonic()
                with self.assertRaisesRegex(RuntimeError, "git archive did not finish within 0.25 s"):
                    BA.archive_into(repo, rev, dest, timeout=0.25)
                self.assertLess(time.monotonic() - start, 2)
            with open(os.path.join(dest, "f.txt"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "x\n", "the complete tar was extracted before the child lingered")

    def test_the_default_deadlines_are_finite_and_the_helpers_take_a_deadline(self):
        for value in (BA.PLAN_TIMEOUT, BA.GIT_TIMEOUT, BA.ARCHIVE_TIMEOUT):
            self.assertTrue(0 < value < 3600)
        for fn in (BA.workspace_plan, BA.run_git, BA.archive_into):
            self.assertIn("timeout", fn.__code__.co_varnames[:fn.__code__.co_argcount + fn.__code__.co_kwonlyargcount])


if __name__ == "__main__":
    unittest.main()
