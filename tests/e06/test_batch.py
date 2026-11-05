"""E06 batch tests (scripts/e06/batch.py): the manifest of open items 3 and 4, the runner, and the log-only judge.

The logs here are SYNTHETIC: built in the shape RCH prints (a worker line, the remote command with its trailing --config pair, a cargo
Finished line, a remote exit line) with documentation-range addresses and made-up paths. They show what the judge does with each kind of
log; the real run's logs are judged by running the judge on them. The runner is exercised with a stub `rch` that writes a canned log
and exits with a canned status: no build is started anywhere in this file.
"""
import copy
import importlib.util
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AU = load("ffw_e06_audit_for_batch", os.path.join(ROOT, "scripts", "e06", "audit.py"))
CK = sys.modules["checks"]
BA = load("ffw_e06_batch", os.path.join(ROOT, "scripts", "e06", "batch.py"))
UPSTREAM = os.path.join(ROOT, "toolchain", "results", "e06", "upstream")
ESC = "\x1b"
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def slurp(path, mode="r"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as fh:
        return fh.read()


def rows(out):
    """The per-line rows of the judge output: they start with two spaces and a line id, unlike PROBLEM, summary and EXIT lines."""
    return [l for l in out.splitlines() if l.startswith("  ") and not l.startswith("  PROBLEM")]


def make_repo(base):
    """A committed git repository holding a two-crate path workspace with a lock: what `gen` exports and plans."""
    repo = os.path.join(base, "ws-repo")
    write(os.path.join(repo, "Cargo.toml"), '[workspace]\nmembers = ["alpha", "beta"]\nresolver = "2"\n')
    for name in ("alpha", "beta"):
        write(os.path.join(repo, name, "Cargo.toml"), '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n' % name)
        write(os.path.join(repo, name, "src", "lib.rs"), "pub fn f() {}\n")
    subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", os.path.join(repo, "Cargo.toml")],
                   capture_output=True, text=True, check=True, timeout=120)
    subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
    subprocess.run(GIT + ["-C", repo, "add", "-A"], check=True, capture_output=True)
    subprocess.run(GIT + ["-C", repo, "commit", "-q", "-m", "fixture"], check=True, capture_output=True)
    rev = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return repo, rev


def synthetic_log(argv, rc=0, worker="trj", errors=(), finished=True, second_command=False, drop=(), address="192.0.2.7",
                  command_override=None, extra=()):
    """What `rch exec -- cargo ...` prints for `argv` (the remote cargo argv)."""
    cmd = shlex.join(command_override if command_override is not None else argv)
    cmd += " --config 'env.RCH_BUILD_SOURCE.value=\"unknown\"' --config 'env.RCH_BUILD_SOURCE.force=true'"
    out = ["[RCH] Cargo target sync active; syncing back to /private/tmp/synthetic/ws/target"]
    if "worker" not in drop:
        out.append("  %s[2m2026-11-05T04:50:55Z%s[0m INFO rch::hook: Selected worker: %s at ubuntu@%s (0 slots remaining after reservation, speed 53.0)" % (
            ESC, ESC, worker, address))
    out.append("[RCH] project path normalized: received_input=/private/tmp/synthetic/ws canonical_root_resolved=/private/tmp/synthetic")
    if "command" not in drop:
        out.append("  2026-11-05T04:51:04Z  INFO rch::hook::transfer_orchestration: Executing command remotely: " + cmd)
        if second_command:
            out.append("  2026-11-05T04:51:05Z  INFO rch::hook::transfer_orchestration: Executing command remotely: " + cmd)
    out += ["    Checking dep-a v0.1.0", "    Checking dep-b v0.2.0 (/private/tmp/synthetic/ws/dep-b)"]
    out += list(errors) + list(extra)
    if finished:
        out.append("    Finished `release` profile [optimized] target(s) in 7.22s")
    if "exit" not in drop:
        out.append("  2026-11-05T04:51:53Z  INFO rch::hook::transfer_orchestration: Remote command finished: exit=%d in 8854ms" % rc)
    out += ["[RCH] exec done: exit=%d in 8854ms" % rc, "[RCH] remote %s (59.4s)" % worker]
    return "\n".join(out) + "\n"


def log_as_predicted(line, worker="trj"):
    """A log that makes the line come out as predicted, run by `worker`."""
    e = line["expect"]
    if e["outcome"] == "pass":
        return synthetic_log(line["remote_argv"], worker=worker)
    claims = " | ".join(e["diagnostic_any"])
    if e["class"] == "build-script":
        errors = ["error: failed to run custom build command for `%s v0.0.0 (/private/tmp/synthetic/ws)`" % line["crate"], "", "Caused by:",
                  "  process didn't exit successfully", "--- stderr", "thread 'main' panicked at build.rs:1:1: %s" % claims]
    else:
        errors = ["error: %s" % claims, " --> /private/tmp/synthetic/ws/src/lib.rs:1:1",
                  "error: could not compile `%s` (lib) due to 1 previous error" % line["crate"]]
    return synthetic_log(line["remote_argv"], rc=101, errors=errors, finished=False, worker=worker)


class Fixture(unittest.TestCase):
    """One fixture repository and one generated manifest for the whole class."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = cls.tmp.name
        cls.repo, cls.rev = make_repo(cls.base)
        cls.export = os.path.join(cls.base, "export")
        cls.manifest_path = os.path.join(cls.base, "manifest.json")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = BA.main(["gen", "--workspace-repo", cls.repo, "--export-dir", cls.export, "--out", cls.manifest_path])
        assert code == 0, err.getvalue()
        cls.manifest_bytes = slurp(cls.manifest_path, "rb")
        cls.manifest = json.loads(cls.manifest_bytes)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def line(self, line_id):
        return next(l for l in self.manifest["lines"] if l["id"] == line_id)

    def logs(self, tmp, mutate=None):
        """A logs directory with every line's as-predicted log; `mutate(dir)` may then break one thing."""
        logs = os.path.join(tmp, "logs")
        os.makedirs(logs)
        for l in self.manifest["lines"]:
            write(os.path.join(logs, l["log"]), log_as_predicted(l))
        if mutate:
            mutate(logs)
        return logs

    def run_judge(self, logs, manifest=None, only=None, extra=()):
        path = self.manifest_path
        if manifest is not None:
            path = os.path.join(os.path.dirname(logs), "m.json")
            write(path, json.dumps(manifest))
        args = ["judge", "--manifest", path, "--logs-dir", logs] + [a for i in (only or ()) for a in ("--only", i)] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = BA.main(args)
        return code, out.getvalue(), err.getvalue()


class ManifestTests(Fixture):
    def test_the_manifest_binds_a_revision_derived_from_git_and_the_two_pinned_upstream_revisions(self):
        self.assertEqual(self.manifest["workspace"]["rev"], self.rev)
        self.assertEqual(self.manifest["sources"]["asupersync"]["rev"], "8940119023c0e01b4d6d3e2c1399f41417c2ad24")
        self.assertEqual(self.manifest["sources"]["frankenlibc"]["rev"], "76d7f3469f5f5251661b3662926d3d6a2b36d494")
        self.assertEqual(slurp(os.path.join(self.export, BA.SENTINEL)), "workspace %s\n" % self.rev)
        self.assertEqual(BA.validate_manifest(self.manifest), [])

    def test_there_is_one_line_per_planned_check_and_exactly_the_twenty_committed_upstream_lines(self):
        lines = self.manifest["lines"]
        workspace = [l for l in lines if l["group"] == "workspace"]
        upstream = [l for l in lines if l["group"] == "upstream"]
        self.assertEqual(sorted((l["crate"], BA.TARGETS[l["target"]]) for l in workspace),
                         [("alpha", "mips"), ("alpha", "powerpc"), ("beta", "mips"), ("beta", "powerpc")])
        self.assertEqual(len(upstream), 20)
        committed = []
        for _, _, rel in BA.UPSTREAM_PLANS:
            committed += [l.strip() for l in slurp(os.path.join(UPSTREAM, *rel.split("/"))).splitlines() if l.strip()]
        self.assertEqual(sorted(CK.plan_argv(c) and " ".join(CK.plan_argv(c)) for c in committed),
                         sorted(" ".join(l["remote_argv"]) for l in upstream))
        self.assertEqual(len({l["id"] for l in lines}), len(lines))
        self.assertEqual(len({l["log"] for l in lines}), len(lines))

    def test_every_line_is_a_direct_argv_with_locked_explicit_jobs_and_no_shell(self):
        for l in self.manifest["lines"]:
            argv = l["remote_argv"]
            self.assertEqual(argv[:4], ["cargo", "+nightly", "check", "--locked"], l["id"])
            self.assertEqual(argv[-2:], ["-j", "2"], l["id"])
            self.assertFalse(any(re.search(r"[;|&$`<>\\\n]", a) for a in argv), l["id"])
            self.assertEqual(l["env"], {"RCH_REQUIRE_REMOTE": "1", "RCH_WORKER": "trj,hz3"}, l["id"])
            self.assertEqual(l["cwd"], ".")

    def test_every_line_states_its_prediction_and_the_eight_predicted_failures_are_exactly_these(self):
        failing = sorted(l["id"] for l in self.manifest["lines"] if l["expect"]["outcome"] == "fail")
        expected = sorted(["asupersync.default.asupersync.%s" % t for t in ("mips", "powerpc")] +
                          ["frankenlibc.runtime-crates.%s.%s" % (c, t) for c in ("frankenlibc-abi", "frankenlibc-core", "frankenlibc-membrane")
                           for t in ("mips", "powerpc")])
        self.assertEqual(failing, expected)
        for l in self.manifest["lines"]:
            self.assertEqual(BA.validate_expect(l["expect"]), [], l["id"])
        self.assertEqual({l["expect"]["class"] for l in self.manifest["lines"] if l["expect"]["outcome"] == "fail"}, {"compile", "build-script"})

    def test_a_workspace_crate_not_checked_at_5b8d569_is_predicted_with_low_confidence(self):
        self.assertEqual(self.line("workspace.alpha.mips")["expect"]["confidence"], "low")
        self.assertIn("first target check", self.line("workspace.alpha.mips")["expect"]["why"])
        self.assertEqual(BA.expectation("workspace", "workspace", "", "franken-hal")["confidence"], "high")

    def test_generation_is_deterministic_and_never_overwrites_a_manifest_or_an_export(self):
        again = os.path.join(self.base, "again.json")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(BA.main(["gen", "--workspace-repo", self.repo, "--export-dir", self.export, "--out", again]), 0, err.getvalue())
            self.assertEqual(slurp(again, "rb"), self.manifest_bytes)       # an existing export carrying the right sentinel is reused
            self.assertEqual(BA.main(["gen", "--workspace-repo", self.repo, "--export-dir", self.export, "--out", again]), 2)
            stranger = os.path.join(self.base, "stranger")
            os.makedirs(stranger)
            self.assertEqual(BA.main(["gen", "--workspace-repo", self.repo, "--export-dir", stranger, "--out", os.path.join(self.base, "x.json")]), 2)

    def test_gen_also_writes_the_workspace_plan_that_audit_ingest_takes(self):
        plan = slurp(self.manifest_path + ".workspace-plan.txt").splitlines()
        self.assertEqual(plan, BA.workspace_plan(self.export))
        parsed, problems = CK.parse_plan(plan)
        self.assertEqual((len(parsed), problems), (4, []))
        workspace = [l for l in self.manifest["lines"] if l["group"] == "workspace"]
        self.assertEqual(sorted(" ".join(CK.plan_argv(p)) for p in plan), sorted(" ".join(l["remote_argv"]) for l in workspace))

    def test_a_line_without_a_prediction_cannot_be_added(self):
        with self.assertRaises(ValueError):
            BA.expectation("upstream", "asupersync", "never-heard-of-it-config-xyz", "")
            BA.expectation("upstream", "someone-else", "x", "y")

    def test_each_planted_manifest_fault_is_reported(self):
        def mutated(edit):
            m = copy.deepcopy(self.manifest)
            edit(m)
            return BA.validate_manifest(m)
        plants = {
            "an empty line list": lambda m: m.__setitem__("lines", []),
            "a duplicate id": lambda m: m["lines"][1].__setitem__("id", m["lines"][0]["id"]),
            "a log name that is not the id": lambda m: m["lines"][0].__setitem__("log", "other.log"),
            "a shell metacharacter in an argument": lambda m: m["lines"][0]["remote_argv"].__setitem__(5, "a;b"),
            "no explicit job count": lambda m: m["lines"][0]["remote_argv"].__delitem__(slice(-2, None)),
            "no --locked": lambda m: m["lines"][0]["remote_argv"].remove("--locked"),
            "a bypass worker set": lambda m: m["lines"][0]["env"].__setitem__("RCH_WORKER", "other"),
            "a missing prediction": lambda m: m["lines"][0].pop("expect"),
            "a predicted failure with no class": lambda m: m["lines"][-1]["expect"].pop("class"),
            "a predicted failure with no diagnostic": lambda m: m["lines"][-1]["expect"].__setitem__("diagnostic_any", []),
            "a prediction with no reason": lambda m: m["lines"][0]["expect"].__setitem__("why", ""),
            "a wrong workspace revision": lambda m: m["workspace"].__setitem__("rev", "xyz"),
            "an unpinned upstream revision": lambda m: m["sources"]["asupersync"].__setitem__("rev", "a" * 40),
            "the FrankenLibC edits removed": lambda m: m["sources"]["frankenlibc"].__setitem__("edits", []),
            "another schema": lambda m: m.__setitem__("schema", "v0"),
        }
        for name, edit in plants.items():
            self.assertNotEqual(mutated(edit), [], name)


class JudgeTests(Fixture):
    def test_the_unplanted_batch_comes_out_exactly_as_predicted(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.run_judge(self.logs(tmp))
        self.assertEqual((code, err), (0, ""), out)
        self.assertIn("EXIT 0", out)
        self.assertEqual(len([r for r in rows(out) if "as-predicted" in r]), len(self.manifest["lines"]))

    def test_one_check_flipped_to_fail_fails_the_judge_and_names_that_line(self):
        victim = "workspace.beta.powerpc"
        with tempfile.TemporaryDirectory() as tmp:
            flipped = synthetic_log(self.line(victim)["remote_argv"], rc=101, finished=False,
                                    errors=["error[E0432]: unresolved import `std::sync::atomic::AtomicU64`", "error: could not compile `beta` (lib)"])
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), flipped)))
        self.assertEqual(code, 3, out)
        bad = [l for l in rows(out) if "unexpected-fail" in l]
        self.assertEqual(len(bad), 1)
        self.assertIn(victim, bad[0])
        self.assertIn("[compile]", bad[0])

    def test_a_log_missing_one_line_fails_closed_and_names_it(self):
        victim = "asupersync.runtime-core-only.asupersync.mips"
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: os.remove(os.path.join(d, victim + ".log"))))
        self.assertEqual(code, 1, out)
        gone = [l for l in rows(out) if "missing" in l and victim in l]
        self.assertEqual(len(gone), 1, out)
        self.assertIn("EXIT 1", out)

    def test_swapping_two_logs_keeps_every_total_and_fails_both_lines_by_name(self):
        a, b = "workspace.alpha.mips", "workspace.beta.mips"

        def swap(d):
            x, y = slurp(os.path.join(d, a + ".log")), slurp(os.path.join(d, b + ".log"))
            write(os.path.join(d, a + ".log"), y)
            write(os.path.join(d, b + ".log"), x)
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, swap))
        self.assertEqual(code, 1, out)
        self.assertEqual(sum(1 for l in rows(out) if "malformed" in l), 2, out)

    def test_a_log_that_is_only_an_infrastructure_refusal_exit_103_is_no_result(self):
        victim = "workspace.alpha.powerpc"
        refusal = ("[RCH] Cargo target sync active\n  2026-11-05T05:04:13Z  INFO rch::hook: Selected worker: hz4 at ubuntu@192.0.2.9 (0 slots)\n"
                   "[RCH] retry: worker ts1 is not currently admissible; trying the next\n"
                   "  2026-11-05T05:04:19Z  WARN rch::hook: Remote build failed on all 1 tried worker(s); refusing local fallback\n"
                   "[RCH] remote required; refusing local fallback (remote execution failed; remote retries exhausted) — retryable\n")
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), refusal)))
        self.assertEqual(code, 1, out)
        row = [l for l in rows(out) if victim in l][0]
        self.assertIn("infra", row)
        self.assertIn("not-a-result", row)

    def test_an_infrastructure_exit_status_recorded_by_the_runner_is_no_result_even_with_an_empty_log(self):
        victim = "workspace.alpha.powerpc"

        def empty_with_103(d):
            write(os.path.join(d, victim + ".log"), "")
            write(os.path.join(d, victim + ".run.json"), json.dumps({"id": victim, "exit": 103}))
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, empty_with_103))
        self.assertEqual(code, 1, out)
        self.assertIn("infra", [l for l in rows(out) if victim in l][0])

    def test_an_rch_refusal_is_a_typed_no_result_with_its_reason(self):
        victim = "workspace.alpha.mips"
        cases = {"RCH-E301 non-compilation command refused": "rch-e301", "refused as outside canonical root /x": "outside-canonical-root",
                 "client_toolchain_unresolved": "client-toolchain-unresolved", "source namespace: conflicting alias base": "conflicting-alias-base"}
        for text, reason in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), "[RCH] %s\n" % text)))
            self.assertEqual(code, 1, text)
            self.assertIn("refused", [l for l in rows(out) if victim in l][0], text)
            self.assertIn(reason, out, text)

    def test_a_predicted_failure_that_passes_and_one_that_fails_differently_are_unexpected_not_hidden(self):
        victim = "frankenlibc.runtime-crates.frankenlibc-core.mips"
        line = self.line(victim)
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), synthetic_log(line["remote_argv"]))))
        self.assertEqual(code, 3, out)
        self.assertIn("unexpected-pass", [l for l in rows(out) if victim in l][0])
        other = synthetic_log(line["remote_argv"], rc=101, finished=False, errors=["error: something else entirely", "error: could not compile `x`"])
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), other)))
        self.assertEqual(code, 3, out)
        row = [l for l in rows(out) if victim in l][0]
        self.assertIn("unexpected-fail", row)
        self.assertIn("predicted compile", row)
        # same text, wrong class: a resolver failure is not the predicted compile_error
        resolve = synthetic_log(line["remote_argv"], rc=101, finished=False,
                                errors=["error: failed to select a version for `x`", "error: could not compile `frankenlibc-membrane` (lib)"])
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), resolve)))
        self.assertEqual(code, 3, out)
        self.assertIn("[resolve]", [l for l in rows(out) if victim in l][0])

    def test_frankenlibc_core_and_abi_are_predicted_by_the_mechanism_run3_observed_and_a_masked_gate_or_a_moved_cause_is_unexpected(self):
        # Run3 (ts1): core and abi depend on frankenlibc-membrane, cargo checks it first and it fails, so neither crate's own x86_64/aarch64-only
        # compile_error! is ever reached. The first prediction named that gate and was judged unexpected-fail. The error lines below are copied
        # from run3's logs (no path outside the crate tree, no address). Each plant has a remove-the-plant control: the observed log.
        observed = ["error[E0432]: unresolved import `std::sync::atomic::AtomicU64`", "  --> crates/frankenlibc-membrane/src/alien_cs_metrics.rs:23:25",
                    "error: could not compile `frankenlibc-membrane` (lib) due to 35 previous errors; 2 warnings emitted"]
        masked_gate_only = ["error: frankenlibc-core currently supports only target_arch = \"x86_64\" and \"aarch64\".",
                            "error: could not compile `frankenlibc-core` (lib) due to 1 previous error"]
        cause_moved = ["error[E0432]: unresolved import `std::sync::atomic::AtomicU64`", "  --> crates/frankenlibc-core/src/malloc/mod.rs:10:5",
                       "error: could not compile `frankenlibc-core` (lib) due to 3 previous errors"]
        for crate in ("frankenlibc-core", "frankenlibc-abi"):
            for target in ("mips", "powerpc"):
                victim = "frankenlibc.runtime-crates.%s.%s" % (crate, target)
                line = self.line(victim)
                self.assertEqual((line["expect"]["class"], line["expect"]["diagnostic_any"]), ("compile", ["could not compile `frankenlibc-membrane`"]), victim)
                self.assertIn("OBSERVED in run3", line["expect"]["why"], victim)
                for name, errors, verdict in (("the observed run3 log", observed, "as-predicted"),
                                              ("only the crate's own gate, membrane never failing", masked_gate_only, "unexpected-fail"),
                                              ("membrane fixed and the crate's own AtomicU64 uses failing instead", cause_moved, "unexpected-fail")):
                    text = synthetic_log(line["remote_argv"], rc=101, finished=False, errors=errors)
                    with tempfile.TemporaryDirectory() as tmp:
                        code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), text)))
                    row = [l for l in rows(out) if victim in l][0]
                    self.assertIn(verdict, row, "%s: %s" % (victim, name))
                    self.assertEqual(code, 0 if verdict == "as-predicted" else 3, "%s: %s: %s" % (victim, name, out))

    def test_logs_that_do_not_belong_to_their_line_are_malformed(self):
        victim = "workspace.alpha.mips"
        argv = self.line(victim)["remote_argv"]
        bad = {
            "another command (no --locked)": synthetic_log(argv, command_override=[a for a in argv if a != "--locked"]),
            "a worker outside the set": synthetic_log(argv, worker="vmi9"),
            "two commands in one log": synthetic_log(argv, second_command=True),
            "no worker line": synthetic_log(argv, drop=("worker",)),
            "no remote exit line": synthetic_log(argv, drop=("exit",)),
            "exit 0 with an error line": synthetic_log(argv, errors=["error: boom"]),
            "exit 0 without a Finished line": synthetic_log(argv, finished=False),
            "exit 101 with a Finished line (a flipped log)": synthetic_log(argv, rc=101),
        }
        for name, text in bad.items():
            with tempfile.TemporaryDirectory() as tmp:
                code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), text)))
            self.assertEqual(code, 1, name)
            self.assertIn("malformed", [l for l in rows(out) if victim in l][0], name)

    def test_rch_exit_status_that_disagrees_with_the_remote_command_is_malformed(self):
        victim = "workspace.alpha.mips"

        def disagree(d):
            write(os.path.join(d, victim + ".run.json"), json.dumps({"id": victim, "exit": 1}))
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, disagree))
        self.assertEqual(code, 1, out)
        self.assertIn("malformed", [l for l in rows(out) if victim in l][0])

    def test_a_log_nobody_owns_and_a_partial_judgement_are_never_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, "stray.log"), "x")))
            self.assertEqual(code, 1, out)
            self.assertIn("unplanned file", out)
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_judge(self.logs(tmp), only=["workspace.alpha.mips"])
            self.assertEqual(code, 4, out)
            self.assertIn("EXIT 4", out)
            code, _, err = self.run_judge(self.logs(os.path.join(tmp, "x") if os.makedirs(os.path.join(tmp, "x")) is None else tmp), only=["no.such.line"])
            self.assertEqual(code, 2, err)

    def test_the_judge_output_and_record_carry_no_address_or_path(self):
        victim = "workspace.alpha.mips"
        argv = self.line(victim)["remote_argv"]
        noisy = synthetic_log(argv, rc=101, finished=False, address="198.51.100.77",
                              errors=["error: cannot open /Users/someone/secret/path/lib.rs at 198.51.100.77", "error: could not compile `alpha`"])
        with tempfile.TemporaryDirectory() as tmp:
            record = os.path.join(tmp, "record.json")
            code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), noisy)), extra=["--record", record])
            self.assertEqual(code, 3, out)
            text = out + slurp(record)
            row = [r for r in json.loads(slurp(record))["lines"] if r["id"] == victim][0]
        for needle in ("198.51.100.77", "/Users/someone", "ubuntu@"):
            self.assertNotIn(needle, text, needle)
        self.assertIn("<addr>", row["diagnostic"])                       # the diagnostic is kept, redacted and bounded
        self.assertLessEqual(len(row["diagnostic"]), CK.DIAGNOSTIC_LIMIT)

    def test_the_record_binds_the_manifest_and_every_log_by_sha256_and_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = os.path.join(tmp, "record.json")
            logs = self.logs(tmp)
            self.assertEqual(self.run_judge(logs, extra=["--record", record])[0], 0)
            data = json.loads(slurp(record))
            self.assertEqual(data["schema"], BA.RECORD_SCHEMA)
            self.assertEqual(data["manifest_sha256"], BA.sha256_bytes(self.manifest_bytes))
            self.assertEqual(data["workspace_rev"], self.rev)
            self.assertEqual(len(data["lines"]), len(self.manifest["lines"]))
            first = data["lines"][0]
            self.assertEqual(first["log_sha256"], BA.sha256_bytes(slurp(os.path.join(logs, first["id"] + ".log"), "rb")))
            self.assertTrue(first["command"].startswith("RCH_REQUIRE_REMOTE=1 RCH_WORKER=trj,hz3 rch exec -- cargo +nightly check --locked"))
            code, _, err = self.run_judge(logs, extra=["--record", record])
            self.assertEqual(code, 2, err)

    def test_workspace_results_feed_the_existing_ingest_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = self.logs(tmp)
            rows = os.path.join(tmp, "results.jsonl")
            self.assertEqual(self.run_judge(logs, extra=["--results-jsonl", rows, "--rev", self.rev])[0], 0)
            plan = os.path.join(tmp, "plan.txt")
            ws = [l for l in self.manifest["lines"] if l["group"] == "workspace"]
            write(plan, "\n".join("RCH_REQUIRE_REMOTE=1 rch exec -- " + shlex.join(l["remote_argv"]) for l in ws) + "\n")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = AU.main(["ingest", "--plan-file", plan, "--results", rows, "--logs-dir", logs, "--rev", self.rev,
                                "--out", os.path.join(tmp, "checks.jsonl")])
            self.assertEqual(code, 0, out.getvalue() + err.getvalue())
            self.assertEqual(len(slurp(os.path.join(tmp, "checks.jsonl")).splitlines()), len(ws))

    def test_a_sabotaged_judge_that_passes_everything_would_fail_these_tests(self):
        # The control: replace the per-line judge with one that always says pass, and the planted flipped log is no longer caught.
        victim = "workspace.beta.powerpc"
        real = BA.judge_line
        BA.judge_line = lambda line, logs_dir, workers: dict(BA._result(line, "pass", "sabotaged"), verdict="as-predicted")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                flipped = synthetic_log(self.line(victim)["remote_argv"], rc=101, finished=False, errors=["error: boom"])
                code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), flipped)))
        finally:
            BA.judge_line = real
        self.assertEqual(code, 0, "the sabotaged judge accepted a flipped log, which is what the real judge must not do")


class ClassifyTests(unittest.TestCase):
    def test_failure_classes_follow_cargo_output(self):
        cases = {
            "error: failed to run custom build command for `x v1`\nCaused by:\n  process": "build-script",
            "error: failed to select a version for the requirement `y = \"1\"`": "resolve",
            "error: the lock file /x/Cargo.lock needs to be updated but --locked was passed": "resolve",
            "error[E0463]: can't find crate for `core`\n  = note: the `mips-unknown-linux-musl` target may not be installed": "toolchain",
            "error[E0432]: unresolved import `std::sync::atomic::AtomicU64`": "compile",
            "error: frankenlibc-core currently supports only target_arch": "compile",
            'error: "/root/.rustup/toolchains/nightly-x/lib/rustlib/src/rust/library/Cargo.lock" does not exist': "toolchain",
            "something went wrong": "unclassified",
        }
        for body, expected in cases.items():
            self.assertEqual(BA.classify_failure(body), expected, body)

    def test_a_build_script_failure_outranks_the_missing_core_it_reports(self):
        body = "error: failed to run custom build command for `asupersync v0`\n--- stderr\nerror[E0463]: can't find crate for `core`"
        self.assertEqual(BA.classify_failure(body), "build-script")


class FrankenLibcPreparationTests(unittest.TestCase):
    ROOT_TOML = 'resolver = "2"\nmembers = [\n  "crates/frankenlibc-membrane",\n  "crates/frankenlibc-core",\n  "crates/frankenlibc-abi",\n  "crates/other",\n]\n'
    MEMBRANE = ('[package]\nname = "frankenlibc-membrane"\n\n[dependencies]\nblake3 = { workspace = true }\n\n[dev-dependencies]\n'
                'asupersync-conformance = { workspace = true }\nftui-core = "0.3.1"\nftui-style = "0.3.1"\ntempfile = "3"\n')

    def tree(self, base):
        write(os.path.join(base, "Cargo.toml"), "[workspace]\n" + self.ROOT_TOML)
        write(os.path.join(base, "crates", "frankenlibc-membrane", "Cargo.toml"), self.MEMBRANE)
        return base

    def test_the_reduction_keeps_the_runtime_members_and_drops_only_the_tooling_dev_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = self.tree(tmp)
            edits = BA.reduce_frankenlibc(tree, BA.FRANKENLIBC_KEEP)
            root = slurp(os.path.join(tree, "Cargo.toml"))
            self.assertIn('members = ["crates/frankenlibc-core", "crates/frankenlibc-abi", "crates/frankenlibc-membrane"]', root)
            membrane = slurp(os.path.join(tree, "crates", "frankenlibc-membrane", "Cargo.toml"))
            self.assertNotIn("ftui-", membrane)
            self.assertNotIn("asupersync-conformance", membrane)
            self.assertIn("blake3", membrane)
            self.assertIn('tempfile = "3"', membrane)                  # a dev-dependency that is not tooling stays
            self.assertEqual([e["file"] for e in edits], ["Cargo.toml", "crates/frankenlibc-membrane/Cargo.toml"])
            self.assertTrue(all(e["sha256_before"] != e["sha256_after"] for e in edits))

    def test_the_recorded_hashes_describe_the_pinned_bytes_so_a_different_export_is_refused(self):
        # The committed edits are for the real pinned revision; a fixture tree cannot reproduce them.
        recorded = BA.edits_of(UPSTREAM)
        with tempfile.TemporaryDirectory() as tmp:
            edits = BA.reduce_frankenlibc(self.tree(tmp), BA.FRANKENLIBC_KEEP)
        self.assertNotEqual(edits, recorded)

    def test_archive_into_extracts_the_named_commit_and_refuses_anything_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, rev = make_repo(tmp)
            write(os.path.join(repo, "later.txt"), "later\n")
            subprocess.run(GIT + ["-C", repo, "add", "-A"], check=True, capture_output=True)
            subprocess.run(GIT + ["-C", repo, "commit", "-q", "-m", "later"], check=True, capture_output=True)
            dest = os.path.join(tmp, "out")
            BA.archive_into(repo, rev, dest)
            self.assertTrue(os.path.isfile(os.path.join(dest, "Cargo.toml")))
            self.assertFalse(os.path.exists(os.path.join(dest, "later.txt")), "the working copy and newer commits are not the pinned bytes")
            with self.assertRaises(RuntimeError):
                BA.archive_into(repo, "b" * 40, os.path.join(tmp, "out2"))
            with self.assertRaises(FileExistsError):
                BA.archive_into(repo, rev, dest)

    def test_a_prepared_directory_is_reused_only_with_its_sentinel_and_nothing_is_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, rev = make_repo(tmp)
            export = os.path.join(tmp, "export")
            self.assertEqual(BA.prepare_workspace(repo, rev, export), export)
            self.assertEqual(BA.prepare_workspace(repo, rev, export), export)
            other = os.path.join(tmp, "other")
            os.makedirs(other)
            write(os.path.join(other, "keep.txt"), "mine\n")
            with self.assertRaises(RuntimeError):
                BA.prepare_workspace(repo, rev, other)
            self.assertTrue(os.path.isfile(os.path.join(other, "keep.txt")))


class RunnerTests(Fixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.stubs = tempfile.TemporaryDirectory()
        stub = os.path.join(cls.stubs.name, "rch")
        write(stub, "#!%s\n" % sys.executable + """import json, os, sys
with open(os.environ["FAKE_RCH_SPEC"]) as fh:
    spec = json.load(fh)
argv = sys.argv[1:]
if argv[:2] != ["exec", "--worker"] or argv[3:4] != ["--"] or os.environ.get("RCH_REQUIRE_REMOTE") != "1":
    sys.exit(97)
key = " ".join(argv[4:])
entry = spec.get(key)
if entry is None:
    sys.exit(98)
sys.stdout.write(entry["text"] + "\\n# cwd=%s canonical=%s worker=%s worker_flag=%s\\n" % (
    os.getcwd(), os.environ.get("RCH_CANONICAL_PROJECT_ROOT"), os.environ.get("RCH_WORKER"), argv[2]))
sys.exit(entry["exit"])
""")
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
        cls.stub = stub

    @classmethod
    def tearDownClass(cls):
        cls.stubs.cleanup()
        super().tearDownClass()

    def spec(self, tmp, lines, ran_on=None):
        """What the stub prints per line: the as-predicted log, run by the line's planned worker unless `ran_on` names another."""
        path = os.path.join(tmp, "spec.json")
        ran_on = ran_on or {}
        write(path, json.dumps({" ".join(l["remote_argv"]): {
            "text": log_as_predicted(l, ran_on.get(l["id"], BA.planned_worker(self.manifest, l["id"], self.forced))),
            "exit": 0 if l["expect"]["outcome"] == "pass" else 101} for l in lines}))
        return path

    forced = None

    def run_runner(self, tmp, only, extra=(), env=None, manifest=None, export=None, ran_on=None):
        logs = os.path.join(tmp, "logs")
        args = ["run", "--manifest", manifest or self.manifest_path, "--workspace-export", export or self.export, "--work-dir", os.path.join(tmp, "work"),
                "--logs-dir", logs, "--rch", self.stub] + [a for i in only for a in ("--only", i)] + list(extra)
        saved = dict(os.environ)
        os.environ.update({"FAKE_RCH_SPEC": self.spec(tmp, [l for l in self.manifest["lines"] if l["id"] in only], ran_on)})
        os.environ.update(env or {})
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                code = BA.main(args)
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return code, out.getvalue(), err.getvalue(), logs

    def test_a_dry_run_prints_every_resolved_line_and_starts_nothing(self):
        ids = ["workspace.alpha.mips", "workspace.beta.powerpc"]
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err, logs = self.run_runner(tmp, ids, extra=["--dry-run"])
            self.assertEqual(code, 0, err)
            self.assertEqual(sorted(os.listdir(logs)) if os.path.isdir(logs) else [], [])
        for line_id in ids:
            row = [l for l in out.splitlines() if l.startswith(line_id + "  ")][0]
            self.assertIn("RCH_REQUIRE_REMOTE=1 RCH_WORKER=trj,hz3 RCH_CANONICAL_PROJECT_ROOT=", row)
            self.assertRegex(row, r"rch exec --worker (trj|hz3) -- cargo \+nightly check --locked --release -p")
            self.assertIn("-Z build-std=std,panic_abort -j 2", row)
            self.assertIn("cwd=", row)
            self.assertNotIn("&&", row)                       # a display of one command, never a shell chain

    def test_a_run_writes_one_exclusive_log_and_one_run_record_per_line_and_the_judge_accepts_them(self):
        ids = ["workspace.alpha.mips", "workspace.beta.mips"]
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err, logs = self.run_runner(tmp, ids)
            self.assertEqual(code, 0, err)
            self.assertEqual(sorted(os.listdir(logs)), sorted(i + s for i in ids for s in (".log", ".run.json")))
            record = json.loads(slurp(os.path.join(logs, ids[0] + ".run.json")))
            self.assertEqual((record["id"], record["exit"]), (ids[0], 0))
            text = slurp(os.path.join(logs, ids[0] + ".log"))
            self.assertIn("worker=trj,hz3", text)                                  # the worker set reached rch
            self.assertIn("canonical=%s" % os.path.abspath(self.export), text.replace("\\", ""))
            # a second run over the same logs is refused: nothing is overwritten
            code, _, err, _ = self.run_runner(tmp, ids)
            self.assertEqual(code, 2, err)
            self.assertIn("never overwritten", err)
            # the judge, restricted to the lines run, decides them by name
            judged, jout, _ = self.run_judge(logs, only=ids)
            self.assertEqual(judged, 4, jout)
            self.assertEqual(len([r for r in rows(jout) if "as-predicted" in r]), 2)

    def test_the_canonical_root_variable_can_be_left_out(self):
        ids = ["workspace.alpha.powerpc"]
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, logs = self.run_runner(tmp, ids, extra=["--no-canonical-root"])
            self.assertEqual(code, 0, err)
            self.assertIn("canonical=None", slurp(os.path.join(logs, ids[0] + ".log")))

    def test_the_admitted_set_is_trj_and_hz3_and_the_refused_ts1_is_not_in_it(self):
        # ts1's worker-side shim refuses strict-remote jobs (BeigeMaple 4745/4824); trj has proven nightly with rust-src. A line that ran on ts1 is
        # therefore no result, by name; the same log on trj is the remove-the-plant control. `run` also refuses ts1 before anything starts.
        self.assertEqual(BA.WORKERS, "trj,hz3")
        self.assertEqual(self.manifest["workers"], "trj,hz3")
        victim = "workspace.alpha.mips"
        argv = self.line(victim)["remote_argv"]
        for worker, verdict in (("trj", "as-predicted"), ("hz3", "as-predicted"), ("ts1", "malformed")):
            with tempfile.TemporaryDirectory() as tmp:
                code, out, _ = self.run_judge(self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), synthetic_log(argv, worker=worker))))
            row = [l for l in rows(out) if victim in l][0]
            self.assertIn(verdict, row, worker)
            if worker == "ts1":
                self.assertIn("ran on worker ts1, not one of trj,hz3", out)
                self.assertEqual(code, 1, out)
            else:
                self.assertEqual(code, 0, out)
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, logs = self.run_runner(tmp, [victim], extra=["--worker", "ts1"])
            self.assertEqual(code, 2)
            self.assertIn("not in the manifest's worker set", err)
            self.assertEqual(os.listdir(logs) if os.path.isdir(logs) else [], [])

    def test_a_manifest_generated_with_the_old_set_still_judges_from_its_own_set(self):
        # Run3's manifest carries `ts1,hz3`. The judge and the runner read the set from the manifest, never from the constant, so changing
        # the constant must not change what an old manifest means: its ts1 logs stay valid and a trj log is outside ITS set.
        old = json.loads(json.dumps(self.manifest))
        old["workers"] = "ts1,hz3"
        for l in old["lines"]:
            l["env"] = {"RCH_REQUIRE_REMOTE": "1", "RCH_WORKER": "ts1,hz3"}
        self.assertEqual(BA.validate_manifest(old), [])
        victim = "workspace.alpha.mips"
        argv = self.line(victim)["remote_argv"]
        for worker, verdict in (("ts1", "as-predicted"), ("trj", "malformed")):
            with tempfile.TemporaryDirectory() as tmp:
                logs = self.logs(tmp, lambda d: write(os.path.join(d, victim + ".log"), synthetic_log(argv, worker=worker)))
                code, out, _ = self.run_judge(logs, manifest=old)
            self.assertIn(verdict, [l for l in rows(out) if victim in l][0], worker)
            if worker == "trj":
                self.assertIn("ran on worker trj, not one of ts1,hz3", out)
        # the runner too: against the OLD manifest `--worker ts1` is accepted (it is in that manifest's set) and the pin reaches rch and the run
        # record, while `--worker trj` (the new constant's worker, not in the old set) is refused before anything starts
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "old-manifest.json")
            write(old_path, json.dumps(old))
            code, out, err, logs = self.run_runner(tmp, [victim], extra=["--worker", "ts1"], manifest=old_path, ran_on={victim: "ts1"})
            self.assertEqual(code, 0, err)
            self.assertIn("worker_flag=ts1", slurp(os.path.join(logs, victim + ".log")))
            record = json.loads(slurp(os.path.join(logs, victim + ".run.json")))
            self.assertEqual((record["planned_worker"], record["worker_set"]), ("ts1", "ts1,hz3"))
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "old-manifest.json")
            write(old_path, json.dumps(old))
            code, _, err, logs = self.run_runner(tmp, [victim], extra=["--worker", "trj"], manifest=old_path)
            self.assertEqual(code, 2)
            self.assertIn("not in the manifest's worker set ts1,hz3", err)
            self.assertEqual(os.listdir(logs) if os.path.isdir(logs) else [], [])

    def test_each_line_is_pinned_to_one_worker_of_the_set_before_the_separator_and_the_remote_argv_is_untouched(self):
        planned = [BA.planned_worker(self.manifest, l["id"]) for l in self.manifest["lines"]]
        self.assertEqual(set(planned), {"trj", "hz3"})                                     # both admitted workers are used
        self.assertTrue(all(a != b for a, b in zip(planned, planned[1:])))                  # dealt out in manifest order
        ids = [l["id"] for l in self.manifest["lines"]]
        late = ids[3]
        with tempfile.TemporaryDirectory() as tmp:
            # run ONE line from the middle of the manifest: it goes where the full run would have put it
            code, out, err, logs = self.run_runner(tmp, [late])
            self.assertEqual(code, 0, err)
            text = slurp(os.path.join(logs, late + ".log"))
            self.assertIn("worker_flag=%s" % planned[3], text)
            record = json.loads(slurp(os.path.join(logs, late + ".run.json")))
            self.assertEqual(record["argv"], ["rch", "exec", "--worker", planned[3], "--"] + self.line(late)["remote_argv"])
            self.assertEqual((record["planned_worker"], record["selected_workers"], record["worker_set"]), (planned[3], [planned[3]], "trj,hz3"))
            self.assertIn("worker planned %s (set trj,hz3), RCH selected %s: as planned" % (planned[3], planned[3]), out)
            judged, jout, _ = self.run_judge(logs, only=[late])
            self.assertEqual(judged, 4, jout)                                               # a subset, never 0
            self.assertIn("as-predicted", [l for l in rows(jout) if late in l][0])

    def test_the_runner_prints_what_rch_selected_next_to_the_plan_and_a_route_off_the_plan_is_malformed_by_name(self):
        ids = [l["id"] for l in self.manifest["lines"]][:3]
        planned = [BA.planned_worker(self.manifest, i) for i in ids]
        other_in_set = "hz3" if planned[1] == "trj" else "trj"
        ran_on = {ids[1]: other_in_set, ids[2]: "vmi9"}      # one routed to the OTHER worker of the set, one off the set altogether
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err, logs = self.run_runner(tmp, ids, ran_on=ran_on)
            self.assertEqual(code, 0, err)
            self.assertIn("RCH selected %s: as planned" % planned[0], out)
            self.assertIn("worker planned %s (set trj,hz3), RCH selected %s: OFF-PLAN" % (planned[1], other_in_set), out)
            self.assertIn("worker planned %s (set trj,hz3), RCH selected vmi9: OFF-PLAN" % planned[2], out)
            self.assertEqual(out.count("OFF-PLAN"), 2)
            judged, jout, _ = self.run_judge(logs, only=ids)
            by_line = {i: [l for l in rows(jout) if i in l][0] for i in ids}
            self.assertIn("as-predicted", by_line[ids[0]])
            self.assertIn("malformed", by_line[ids[1]])                       # on a worker of the set, but not the one it was planned for
            self.assertIn("routed off the planned worker", jout)
            self.assertIn("planned %s" % planned[1], jout)
            self.assertIn("malformed", by_line[ids[2]])                       # off the set
            self.assertIn("ran on worker vmi9", jout)
            self.assertEqual(judged, 1, jout)                                  # a no-result line makes the judge exit 1

    def test_one_worker_can_be_forced_and_an_unknown_one_is_refused_before_anything_starts(self):
        ids = [l["id"] for l in self.manifest["lines"]][:2]
        type(self).forced = "hz3"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                code, out, err, logs = self.run_runner(tmp, ids, extra=["--worker", "hz3"])
                self.assertEqual(code, 0, err)
                for i in ids:
                    self.assertIn("worker_flag=hz3", slurp(os.path.join(logs, i + ".log")))
                self.assertEqual(out.count("RCH selected hz3: as planned"), 2)
        finally:
            type(self).forced = None
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, logs = self.run_runner(tmp, ids, extra=["--worker", "vmi9"])
            self.assertEqual(code, 2)
            self.assertIn("not in the manifest's worker set", err)
            self.assertEqual(os.listdir(logs) if os.path.isdir(logs) else [], [])

    def test_a_run_record_that_names_a_worker_outside_the_set_or_another_than_the_log_ran_on_is_malformed(self):
        victim = "workspace.alpha.mips"
        argv = self.line(victim)["remote_argv"]
        for name, planned in (("a planned worker outside the set", "vmi9"), ("another worker of the set", "hz3")):
            with tempfile.TemporaryDirectory() as tmp:
                def plant(d):
                    write(os.path.join(d, victim + ".log"), synthetic_log(argv, worker="trj"))
                    write(os.path.join(d, victim + ".run.json"), json.dumps({"id": victim, "exit": 0, "planned_worker": planned}))
                code, out, _ = self.run_judge(self.logs(tmp, plant))
            self.assertEqual(code, 1, name)
            self.assertIn("malformed", [l for l in rows(out) if victim in l][0], name)
            self.assertIn("routed off the planned worker", out, name)

    def test_the_runner_refuses_a_bypass_a_stale_manifest_the_wrong_export_and_unknown_lines(self):
        ids = ["workspace.alpha.mips"]
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, _ = self.run_runner(tmp, ids, env={"RCH_CARGO_WRAPPER_BYPASS": "1"})
            self.assertEqual(code, 2)
            self.assertIn("bypass", err)
        with tempfile.TemporaryDirectory() as tmp:
            stale = copy.deepcopy(self.manifest)
            stale["workspace"]["plan_sha256"] = "0" * 64
            path = os.path.join(tmp, "stale.json")
            write(path, json.dumps(stale))
            code, _, err, _ = self.run_runner(tmp, ids, manifest=path)
            self.assertEqual(code, 2)
            self.assertIn("stale", err)
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = os.path.join(tmp, "elsewhere")
            os.makedirs(elsewhere)
            code, _, err, _ = self.run_runner(tmp, ids, export=elsewhere)
            self.assertEqual(code, 2)
            self.assertIn("not an export of the manifest's revision", err)
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, _ = self.run_runner(tmp, ["no.such.line"])
            self.assertEqual(code, 2, err)

    def test_upstream_lines_need_their_repository_and_nothing_is_started_without_it(self):
        ids = ["asupersync.default.asupersync.mips"]
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err, logs = self.run_runner(tmp, ids)
            self.assertEqual(code, 2)
            self.assertIn("--asupersync-repo is needed", err)
            self.assertFalse(os.path.isdir(logs) and os.listdir(logs))


if __name__ == "__main__":
    unittest.main()
