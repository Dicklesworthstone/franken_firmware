#!/usr/bin/env python3
"""Tests for scripts/test/run-suite (bead ffw-2qz / Q00).

Standard library only.  Almost everything here drives the real runner as a real
subprocess against real child processes (hung, crashing, chatty, leaking, forging,
cancelled...) in temp directories whose names contain spaces, from a working
directory that is not the repo root.  Every planted negative has a positive
control next to it, so a runner that simply failed everything would not pass.

Run:  python3 scripts/test/test_run_suite.py        (from anywhere)
      python3 -m unittest scripts/test/test_run_suite.py   (from the repo root)

Nothing here touches the network, a device, or the repo tree: all artifacts live
under tempfile directories that the tests create and remove themselves.

What these tests do NOT prove: that the runner is free of defects, that any
child oracle is semantically correct, or anything about real hardware.  They
check the runner's own contract: exact denominators, positive-evidence passes,
bounded/redacted output, process cleanup, cancellation, replay, and agreement
with the independent aggregator in test_support/receipts.py.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import resource
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
# RUN_SUITE_UNDER_TEST points the whole suite at another copy of the runner (used for mutation checks:
# deliberately weakened copies must make these tests fail).  A copy must sit beside a `test_support` link.
RUNNER = os.environ.get("RUN_SUITE_UNDER_TEST") or os.path.join(HERE, "run-suite")
RECEIPTS_PY = os.path.join(HERE, "test_support", "receipts.py")
RECEIPTS_PY = RECEIPTS_PY  # also used to run `receipts.py verify` in a separate process


def _load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rs = _load("run_suite_under_test", RUNNER)
rx = _load("receipts_under_test", RECEIPTS_PY)

# --------------------------------------------------------------------------- #
# the children: a library of well-behaved and deliberately broken programs
# --------------------------------------------------------------------------- #

CHILD_SRC = r'''
import json, os, random, signal, subprocess, sys, time

ENV = os.environ


def write_result(verdict="pass", oracle="test.oracle", kind="state", independent=True, checks=3,
                 mismatches=None, expected=None, observed=None, event="evt-1", nonce=None,
                 case_id=None, run_id=None, counters=None, raw=None, finalized=None, reasons=None,
                 kinds=None, violation="violation"):
    if mismatches is None:
        mismatches = 1 if verdict == "fail" else 0
    if kinds is None:
        kinds = {violation: mismatches} if verdict == "fail" else {}
    if finalized is None:
        finalized = verdict != "incomplete"
    if reasons is None:
        reasons = ["not_finalized"] if verdict == "incomplete" else []
    doc = {"schema": "ffw.case-result.v1", "run_id": run_id or ENV["FFW_RUN_ID"],
           "case_id": case_id or ENV["FFW_CASE_ID"], "nonce": nonce or ENV["FFW_RESULT_NONCE"],
           "verdict": verdict, "oracle": oracle, "oracle_kind": kind, "independent": independent,
           "finalized": finalized, "incomplete_reasons": reasons, "violation_kinds": kinds,
           "checks": checks, "mismatches": mismatches, "expected": expected, "observed": observed,
           "first_causal_event": event, "counters": counters or {}}
    data = raw if raw is not None else json.dumps(doc)
    tmp = ENV["FFW_RESULT_PATH"] + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(data)
    os.replace(tmp, ENV["FFW_RESULT_PATH"])


def good(**kw):
    write_result("pass", **kw)


def bad(oracle="test.oracle", **kw):
    kw.setdefault("expected", {"v": 1})
    kw.setdefault("observed", {"v": 2})
    write_result("fail", oracle=oracle, **kw)


def sleeper_in_group(pidfile):
    p = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(120)"])
    with open(pidfile, "w") as fh:
        fh.write(str(p.pid))


mode, arg = sys.argv[1], sys.argv[2:]

if mode == "pass":
    good()
elif mode == "pass_noresult":
    print("ALL TESTS PASSED")                     # exit 0, loud success text, no receipt
elif mode == "stale_nonce":
    good(nonce="0" * 32)
elif mode == "wrong_case":
    good(case_id="some.other.case")
elif mode == "stale_run":
    good(run_id="previous-run")
elif mode == "zero_checks":
    good(checks=0)
elif mode == "not_independent":
    good(independent=False)
elif mode == "bad_kind":
    good(kind="log")
elif mode == "verdict_fail_exit0":
    bad()
elif mode == "fail_exit1":
    bad(oracle=arg[0] if arg else "test.oracle")
    sys.exit(1)
elif mode == "pass_exit3":
    good()
    sys.exit(3)
elif mode == "exit1_noresult":
    sys.exit(1)
elif mode == "truncated_result":
    write_result(raw='{"schema": "ffw.case-result.v1", "run_id": "x", "ver')
elif mode == "oversize_result":
    write_result(raw=json.dumps({"pad": "x" * 300000}))
elif mode == "pass_with_mismatches":
    write_result("pass", mismatches=2)
elif mode == "fail_without_mismatches":
    write_result("fail", mismatches=0, expected=1, observed=2)
elif mode == "fail_same_expected_observed":
    write_result("fail", expected={"a": 1}, observed={"a": 1})
elif mode == "fail_missing_observed":
    write_result("fail", expected={"a": 1}, observed=None)
elif mode == "hang":
    time.sleep(120)
elif mode == "hang_ignore_term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open(arg[0], "w") as fh:
        fh.write(str(os.getpid()))
    time.sleep(120)
elif mode == "hang_grandchild":
    sleeper_in_group(arg[0])
    time.sleep(120)
elif mode == "leak":
    sleeper_in_group(arg[0])
    good()
elif mode == "kill_self":
    os.kill(os.getpid(), signal.SIGKILL)
elif mode == "usr1_self":
    os.kill(os.getpid(), signal.SIGUSR1)
elif mode == "exit139":
    os._exit(139)
elif mode == "result_then_kill":
    good()
    os.kill(os.getpid(), signal.SIGKILL)
elif mode == "flaky":
    if int(ENV["FFW_ATTEMPT"]) >= 2:
        good()
    else:
        bad(oracle="flaky.oracle")
        sys.exit(1)
elif mode == "always_fail":
    bad(oracle="always.oracle")
    sys.exit(1)
elif mode == "print_seed":
    seed = int(ENV["FFW_SEED"])
    r = random.Random(seed)
    print("SEED=%d" % seed)
    print("RUNSEED=%s" % ENV["FFW_RUN_SEED"])
    print("SEQ=" + ",".join(str(r.randrange(1000)) for _ in range(5)))
    good()
elif mode == "cwd":
    print("CWD=" + os.path.basename(os.getcwd()))
    good()
elif mode == "env_probe":
    print("PROBE=" + ("present" if arg[0] in ENV else "absent"))
    print("HOME_IS_SCRATCH=" + str(ENV["HOME"].startswith(ENV["FFW_CASE_DIR"])))
    good()
elif mode == "secrets":
    print("api_token=%s" % ENV["S_TOKEN"])
    print("Authorization: Bearer %s" % ENV["S_BEARER"])
    print("-----BEGIN RSA PRIVATE KEY-----")
    print(ENV["S_PEM_BODY"])
    print("-----END RSA PRIVATE KEY-----")
    print("connect to %s now" % ENV["S_IP"])
    print("mac %s" % ENV["S_MAC"])
    print("contact %s" % ENV["S_EMAIL"])
    print("jwt %s" % ENV["S_JWT"])
    print("key %s" % ENV["S_SK"])
    print("tailnet %s" % ENV["S_TSKEY"])
    print("literal %s end" % ENV["S_LITERAL"])
    print("home %s/projects" % ENV["S_HOME"])
    print("BENIGN loopback 127.0.0.1 tokens_dropped=3 serial_port=ttyS0 doc 203.0.113.9 ver 1.2.3.400")
    good()
elif mode == "bad_with_secret":
    bad(oracle="leaky.oracle", expected={"note": "api_token=%s" % ENV["S_TOKEN"]},
        observed={"note": "ip %s" % ENV["S_IP"]}, event="saw %s" % ENV["S_EMAIL"])
    sys.exit(1)
elif mode == "flood":
    line = "x" * 100
    for _ in range(int(arg[0])):
        print(line)
    good()
elif mode == "overlong":
    sys.stdout.write("y" * 200000)
    sys.stdout.flush()
    good()
elif mode == "binary":
    sys.stdout.buffer.write(b"\x00\x01\x02\xff\xfe" * 50 + b"\n")
    sys.stdout.flush()
    good()
elif mode == "partial_line":
    sys.stdout.write("no newline at the end")
    sys.stdout.flush()
    good()
elif mode == "marker":
    print("MARKER-OK 42")
    good()
elif mode == "no_marker":
    print("something else entirely")
    good()
elif mode == "slow":
    with open(arg[0], "w") as fh:
        fh.write(str(os.getpid()))
    for i in range(1200):
        print("tick", i, flush=True)
        time.sleep(0.1)
elif mode == "rendezvous":
    d, need = arg[0], int(arg[1])
    open(os.path.join(d, ENV["FFW_CASE_ID"]), "w").close()
    end = time.time() + (float(arg[2]) if len(arg) > 2 else 8)
    while len(os.listdir(d)) < need and time.time() < end:
        time.sleep(0.02)
    if len(os.listdir(d)) >= need:
        good()
    else:
        bad(oracle="rendezvous.oracle")
        sys.exit(1)
elif mode == "sentinel":
    with open(arg[0], "w") as fh:
        fh.write("ran")
    good()
elif mode == "scratch_file":
    with open(os.path.join(ENV["FFW_CASE_DIR"], "junk.bin"), "wb") as fh:
        fh.write(b"z" * 1000)
    good()
elif mode == "locked_dir":
    d = os.path.join(ENV["FFW_CASE_DIR"], "locked")
    os.mkdir(d)
    with open(os.path.join(d, "f"), "w") as fh:
        fh.write("x")
    os.chmod(d, 0)
    good()
elif mode == "canary_fire":
    # canary_fire ORACLE VIOLATION [CHECKS [INDEPENDENT(0|1)]]
    bad(oracle=arg[0], violation=arg[1], mismatches=2, checks=int(arg[2]) if len(arg) > 2 else 3,
        independent=(arg[3] != "0") if len(arg) > 3 else True)
    sys.exit(1)
elif mode == "canary_exit0":
    bad(oracle=arg[0], violation=arg[1])
    sys.exit(0)
elif mode == "incomplete":
    # an oracle that never finished; it carries the REAL oracle name and zero manufactured mismatches
    write_result("incomplete", oracle=arg[0], checks=0)
    sys.exit(2)
elif mode == "pass_unfinalized":
    write_result("pass", finalized=False)
elif mode == "pass_with_reasons":
    write_result("pass", reasons=["guard_not_exercised"])
elif mode == "incomplete_without_reason":
    write_result("incomplete", finalized=True, reasons=[])
elif mode == "incomplete_with_mismatches":
    write_result("incomplete", mismatches=1, kinds={"x": 1})
elif mode == "kinds_do_not_sum":
    write_result("fail", mismatches=3, kinds={"lost": 1}, expected=1, observed=2)
else:
    sys.exit(97)
'''

SECRETS = {
    "S_TOKEN": "supersecretvalue12345",
    "S_BEARER": "abcdef0123456789bearerXYZ",
    "S_PEM_BODY": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCpemBodyLine",
    "S_IP": "192.168.77.123",
    "S_MAC": "de:ad:be:ef:12:34",
    "S_EMAIL": "jeff.private@example-site.org",
    "S_JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXk",
    "S_SK": "sk-abcdefghijklmnopqrstuvwx",
    "S_TSKEY": "tskey-auth-kABCDEF123456",
    "S_LITERAL": "plainword-matching-no-pattern-xyz",
    "S_HOME": os.path.expanduser("~"),
}


def case(cid, mode, *args, tiers=("smoke",), timeout_s=20, **kw):
    d = {"id": cid, "argv": ["{python}", "-I", "child.py", mode] + list(args),
         "tiers": list(tiers), "timeout_s": timeout_s}
    d.update(kw)
    return d


def canary(cid, mode, oracle, violation="lost", *, exit_codes=(1,), timeout_s=20, **kw):
    return case(cid, mode, oracle, violation, timeout_s=timeout_s,
                expect={"kind": "fail", "oracle": oracle, "violation": violation,
                        "exit_codes": list(exit_codes)}, **kw)


class Result:
    def __init__(self, proc, run_dir):
        self.rc = proc.returncode
        self.out = proc.stdout
        self.err = proc.stderr
        self.run_dir = run_dir
        self.report = None
        path = os.path.join(run_dir, "receipt.json")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                self.report = json.loads(fh.read().decode("utf-8"))

    @property
    def cases(self):
        return {c["id"]: c for c in self.report["cases"]}

    @property
    def den(self):
        return self.report["denominators"]

    @property
    def agg(self):
        return self.report["receipts"]["aggregator"]

    def stream(self):
        out = []
        with open(os.path.join(self.run_dir, "receipts.jsonl"), "rb") as fh:
            for line in fh.read().decode("utf-8").splitlines():
                out.append(json.loads(line))
        return out

    def events(self):
        with open(os.path.join(self.run_dir, "events.jsonl"), "rb") as fh:
            return [json.loads(l) for l in fh.read().decode("utf-8").splitlines() if l.strip()]

    def log(self, cid, attempt=1):
        with open(os.path.join(self.run_dir, "logs", "%s.a%d.log" % (cid, attempt)), "rb") as fh:
            return fh.read().decode("utf-8", "replace")


class Workspace:
    """A temp tree with spaces in its names, a child program, and a cwd that is not the repo."""

    def __init__(self, tc):
        self.tmp = tempfile.TemporaryDirectory(prefix="ffw suite ws ")
        tc.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "my cases")
        os.mkdir(self.dir)
        with open(os.path.join(self.dir, "child.py"), "w") as fh:
            fh.write(CHILD_SRC)
        self.artifacts = os.path.join(self.tmp.name, "artifact root")
        self.elsewhere = os.path.join(self.tmp.name, "elsewhere")
        os.mkdir(self.elsewhere)
        self.shared = os.path.join(self.tmp.name, "shared sync")
        os.mkdir(self.shared)
        self._n = 0

    def path(self, *parts):
        return os.path.join(self.shared, *parts)

    def manifest(self, cases, name=None, suite="t", requirements=None, required_cases=None, extra=None, subdir=None):
        self._n += 1
        name = name or "m%d" % self._n
        doc = {"schema": "ffw.suite.v1", "suite": suite, "cases": cases}
        if requirements is not None:
            doc["requirements"] = requirements
        if required_cases is not None:
            doc["required_cases"] = required_cases
        if extra:
            doc.update(extra)
        d = self.dir if subdir is None else os.path.join(self.dir, subdir)
        os.makedirs(d, exist_ok=True)
        if subdir is not None and not os.path.exists(os.path.join(d, "child.py")):
            with open(os.path.join(d, "child.py"), "w") as fh:
                fh.write(CHILD_SRC)
        p = os.path.join(d, name + ".suite.json")
        with open(p, "w") as fh:
            json.dump(doc, fh)
        return p

    def argv(self, manifests, tier="smoke", run_id=None, extra=()):
        a = [sys.executable, RUNNER, "run", "--tier", tier, "--artifact-root", self.artifacts,
             "--kill-grace-s", "0.3"]
        for m in ([manifests] if isinstance(manifests, str) else manifests):
            a += ["--manifest", m]
        if run_id:
            a += ["--run-id", run_id]
        return a + list(extra)

    def env(self, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("FFW_")}
        env.update(extra or {})
        return env

    def run(self, manifests, tier="smoke", run_id=None, extra=(), env=None, timeout=120, preexec=None):
        run_id = run_id or "r%d" % int(time.time() * 1000000)
        proc = subprocess.run(self.argv(manifests, tier, run_id, extra), cwd=self.elsewhere, env=self.env(env),
                              capture_output=True, text=True, timeout=timeout, preexec_fn=preexec)
        return Result(proc, os.path.join(self.artifacts, run_id))

    def popen(self, manifests, run_id, extra=(), env=None, preexec=None):
        return subprocess.Popen(self.argv(manifests, "smoke", run_id, extra), cwd=self.elsewhere,
                                env=self.env(env), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                preexec_fn=preexec)

    def expected_for(self, cases):
        """The registry slice the aggregator needs, derived independently from the manifest dicts."""
        exp = {}
        for c in cases:
            ex = c.get("expect", {})
            spec = {"mandatory": c.get("mandatory", True),
                    "proof_class": c.get("evidence_class", "host-simulation"), "canary": ex.get("kind") == "fail"}
            if spec["canary"]:
                spec["oracle"], spec["violation"] = ex["oracle"], ex["violation"]
            exp[c["id"]] = spec
        return exp


def wait_for(path, seconds=30):
    end = time.time() + seconds
    while time.time() < end:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
        time.sleep(0.02)
    return False


def read_json(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def pid_dead(pid, seconds=5):
    end = time.time() + seconds
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def read_pid(path):
    with open(path) as fh:
        return int(fh.read().strip())


def tree_bytes(root):
    blobs = []
    for cur, _dirs, files in os.walk(root):
        for f in files:
            with open(os.path.join(cur, f), "rb") as fh:
                blobs.append(fh.read())
    return b"\n".join(blobs)


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def assertCase(self, res, cid, status, reason=None):
        self.assertIsNotNone(res.report, "no receipt.json; rc=%s\nstdout:\n%s\nstderr:\n%s" % (res.rc, res.out, res.err))
        c = res.cases[cid]
        self.assertEqual(c["status"], status, "%s: %s/%s %s" % (cid, c["status"], c["reason"], c.get("detail")))
        if reason is not None:
            self.assertEqual(c["reason"], reason, "%s: %s" % (cid, c.get("detail")))
        return c

    def assertNoInternal(self, res):
        self.assertNotEqual(res.rc, rs.EXIT_INTERNAL, "runner/aggregator disagreement:\n%s\n%s" % (res.out, res.err))
        self.assertEqual(res.report["receipts"]["crosscheck_mismatches"], [])

    def in_process(self, manifest, run_id, extra=()):
        """Run the CLI in this process (so a test can substitute a collaborator) and return a Result."""
        argv = ["run", "--tier", "smoke", "--manifest", manifest, "--artifact-root", self.ws.artifacts,
                "--run-id", run_id, "--kill-grace-s", "0.3"] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = rs.main(argv)
        return Result(subprocess.CompletedProcess(argv, rc, out.getvalue(), err.getvalue()),
                      os.path.join(self.ws.artifacts, run_id))


def collect(proc, run_dir, timeout=90):
    out, err = proc.communicate(timeout=timeout)
    return Result(subprocess.CompletedProcess(proc.args, proc.returncode, out, err), run_dir)


# --------------------------------------------------------------------------- #
# denominators, verdicts, exit codes
# --------------------------------------------------------------------------- #

class TestDenominatorsAndVerdicts(Base):
    def test_all_pass_is_qualified_and_exit_zero(self):
        cases = [case("p.one", "pass"), case("p.two", "pass"), case("p.three", "print_seed")]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertEqual(res.den, {"planned": 3, "executed": 3, "pass": 3, "fail": 0, "blocked": 0,
                                   "not_run": 0, "deselected": 0})
        self.assertEqual(res.report["verdict"], "pass")
        self.assertTrue(res.agg["qualified"] and res.agg["complete"])
        self.assertIn("VERDICT: PASS", res.out)
        # the test re-judges the stream itself, independently of the runner's own aggregator call
        summary = rx.aggregate_path(os.path.join(res.run_dir, "receipts.jsonl"), self.ws.expected_for(cases))
        self.assertTrue(summary["qualified"], summary["unqualified_reasons"])
        self.assertEqual(summary["counts"]["pass"], 3)

    def test_mixed_outcomes_have_exact_denominators(self):
        blocked = {"id": "m.blocked", "argv": ["definitely-not-a-real-binary-xyz"], "tiers": ["smoke"]}
        cases = [case("m.pass", "pass"), case("m.oracle_fail", "fail_exit1", "x.oracle"),
                 case("m.timeout", "hang", timeout_s=1), case("m.crash", "kill_self"), blocked]
        res = self.ws.run(self.ws.manifest(cases, required_cases=["m.never_defined"]))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertNoInternal(res)
        # planned = pass + fail + blocked + not_run ; executed = pass + fail (every launched case)
        self.assertEqual(res.den, {"planned": 6, "executed": 4, "pass": 1, "fail": 3, "blocked": 1,
                                   "not_run": 1, "deselected": 0})
        self.assertCase(res, "m.pass", "pass", "ok")
        self.assertCase(res, "m.oracle_fail", "fail", "oracle_failed")
        self.assertCase(res, "m.timeout", "fail", "timeout")
        self.assertCase(res, "m.crash", "fail", "crashed")
        self.assertCase(res, "m.blocked", "blocked", "missing_executable")
        self.assertCase(res, "m.never_defined", "not_run", "missing_mandatory_case")
        counts = res.agg["counts"]
        self.assertEqual({k: v for k, v in counts.items() if v},
                         {"pass": 1, "fail": 1, "timeout": 1, "crash": 1, "blocked": 1, "not_run": 1})
        self.assertEqual(res.agg["denominator"]["executed"], 4)
        # an independent re-judgement, with the floor, agrees
        exp = self.ws.expected_for(cases[:4])
        exp["m.blocked"] = {"mandatory": True, "proof_class": "host-simulation"}
        exp["m.never_defined"] = {"mandatory": True, "proof_class": "host-simulation"}
        summary = rx.aggregate_path(os.path.join(res.run_dir, "receipts.jsonl"), exp, required=["m.never_defined"])
        self.assertFalse(summary["qualified"])
        self.assertEqual(summary["counts"], counts)

    def test_empty_selection_is_never_a_pass(self):
        res = self.ws.run(self.ws.manifest([case("e.only_full", "pass", tiers=("full",))]))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertEqual(res.den["planned"], 0)
        self.assertEqual(res.den["deselected"], 1)
        self.assertTrue(any(b.startswith("empty_selection") for b in res.report["blocking"]))
        self.assertIn("aggregator: not run", res.out)
        # control: the same manifest under the tier it declares passes
        ok = self.ws.run(self.ws.manifest([case("e.only_full", "pass", tiers=("full",))]), tier="full")
        self.assertEqual(ok.rc, 0, ok.out + ok.err)

    def test_deselected_cases_are_counted_outside_the_denominator(self):
        cases = [case("t.s", "pass", tiers=("smoke",)), case("t.sf", "pass", tiers=("smoke", "full")),
                 case("t.f", "pass", tiers=("full",)), case("t.soak", "pass", tiers=("soak",))]
        m = self.ws.manifest(cases)
        smoke = self.ws.run(m, tier="smoke")
        self.assertEqual(smoke.den, {"planned": 2, "executed": 2, "pass": 2, "fail": 0, "blocked": 0,
                                     "not_run": 0, "deselected": 2})
        full = self.ws.run(m, tier="full")
        self.assertEqual((full.den["planned"], full.den["deselected"]), (2, 2))
        self.assertEqual(sorted(full.cases), ["t.f", "t.sf"])

    def test_tier_has_no_default(self):
        m = self.ws.manifest([case("x", "pass")])
        proc = subprocess.run([sys.executable, RUNNER, "run", "--manifest", m, "--artifact-root", self.ws.artifacts],
                              cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, rs.EXIT_USAGE)
        self.assertIn("--tier", proc.stderr)
        self.assertFalse(os.path.exists(self.ws.artifacts), "nothing may be created on a usage error")

    def test_partial_selection_is_flagged_and_unknown_case_is_refused(self):
        m = self.ws.manifest([case("s.a", "pass"), case("s.b", "fail_exit1", "b.oracle")])
        one = self.ws.run(m, extra=["--case", "s.a"])
        self.assertEqual(one.rc, 0, one.out + one.err)
        self.assertEqual((one.den["planned"], one.den["deselected"]), (1, 1))
        self.assertTrue(one.report["run"]["partial_selection"])
        bad = self.ws.run(m, extra=["--case", "s.nope"])
        self.assertEqual(bad.rc, rs.EXIT_USAGE)
        self.assertIn("s.nope", bad.err)


# --------------------------------------------------------------------------- #
# oracle integrity: absence of error text never passes
# --------------------------------------------------------------------------- #

NEGATIVES = [
    ("n.no_result", ("pass_noresult",), "result_missing"),
    ("n.stale_nonce", ("stale_nonce",), "result_stale"),
    ("n.wrong_case", ("wrong_case",), "result_stale"),
    ("n.stale_run", ("stale_run",), "result_stale"),
    ("n.zero_checks", ("zero_checks",), "vacuous_pass"),
    ("n.not_independent", ("not_independent",), "oracle_not_independent"),
    ("n.log_is_not_an_oracle", ("bad_kind",), "result_invalid"),
    ("n.verdict_fail_exit0", ("verdict_fail_exit0",), "oracle_failed"),
    ("n.fail_exit1", ("fail_exit1", "o.x"), "oracle_failed"),
    ("n.pass_but_exit3", ("pass_exit3",), "nonzero_exit"),
    ("n.exit1_no_result", ("exit1_noresult",), "nonzero_exit"),
    ("n.exit139_is_not_a_signal", ("exit139",), "nonzero_exit"),
    ("n.truncated_result", ("truncated_result",), "result_invalid"),
    ("n.oversize_result", ("oversize_result",), "result_oversize"),
    ("n.pass_with_mismatches", ("pass_with_mismatches",), "result_invalid"),
    ("n.fail_without_mismatches", ("fail_without_mismatches",), "result_invalid"),
    ("n.fail_same_expected_observed", ("fail_same_expected_observed",), "result_invalid"),
    ("n.fail_missing_observed", ("fail_missing_observed",), "result_invalid"),
    ("n.kinds_do_not_sum", ("kinds_do_not_sum",), "result_invalid"),
    ("n.incomplete_without_reason", ("incomplete_without_reason",), "result_invalid"),
    ("n.incomplete_with_mismatches", ("incomplete_with_mismatches",), "result_invalid"),
    ("n.pass_but_unfinalized", ("pass_unfinalized",), "oracle_incomplete"),
    ("n.pass_with_incomplete_reasons", ("pass_with_reasons",), "oracle_incomplete"),
    ("n.incomplete_oracle", ("incomplete", "o.x"), "oracle_incomplete"),
    ("n.result_then_killed", ("result_then_kill",), "crashed"),
]


class TestOracleIntegrity(Base):
    def test_every_planted_negative_fails_with_its_own_reason_and_the_control_passes(self):
        cases = [case(cid, *args) for cid, args, _ in NEGATIVES] + [case("n.control", "pass")]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertNoInternal(res)  # the strict aggregator accepted every record the runner wrote
        for cid, _args, reason in NEGATIVES:
            with self.subTest(case=cid):
                self.assertCase(res, cid, "fail", reason)
        self.assertCase(res, "n.control", "pass", "ok")
        self.assertEqual(res.den["pass"], 1)
        self.assertEqual(res.den["fail"], len(NEGATIVES))
        self.assertEqual(res.den["executed"], len(NEGATIVES) + 1)

    def test_incomplete_oracle_is_a_typed_non_pass_and_never_a_manufactured_failure(self):
        res = self.ws.run(self.ws.manifest([case("i.inc", "incomplete", "o.x")]))
        c = self.assertCase(res, "i.inc", "fail", "oracle_incomplete")
        self.assertIn("not_finalized", c["detail"])
        rec = [r for r in res.stream() if r.get("case_id") == "i.inc"][0]
        self.assertEqual(rec["outcome"], "fail")
        self.assertEqual(rec["failure"]["oracle"], "o.x.incomplete")  # an identity no canary can expect
        self.assertEqual(rec["failure"]["observed"]["oracle_status"], "incomplete")

    def test_pass_requires_exit_zero_and_a_receipt_together(self):
        # the two halves of the positive evidence; each alone is not enough
        res = self.ws.run(self.ws.manifest([case("h.receipt_only", "pass_exit3"),
                                            case("h.exit_only", "pass_noresult"), case("h.both", "pass")]))
        self.assertCase(res, "h.receipt_only", "fail", "nonzero_exit")
        self.assertCase(res, "h.exit_only", "fail", "result_missing")
        self.assertCase(res, "h.both", "pass", "ok")

    def test_required_stdout_marker_must_be_present_in_addition_to_the_receipt(self):
        cases = [case("k.present", "marker", required_stdout=[r"MARKER-OK \d+"]),
                 case("k.absent", "no_marker", required_stdout=[r"MARKER-OK \d+"])]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertCase(res, "k.present", "pass", "ok")
        self.assertCase(res, "k.absent", "fail", "required_marker_missing")


# --------------------------------------------------------------------------- #
# known-defect canaries
# --------------------------------------------------------------------------- #

def _canary_expect(oracle="sample-loss", violation="lost", codes=(1,)):
    return {"kind": "fail", "oracle": oracle, "violation": violation, "exit_codes": list(codes)}


class TestCanaries(Base):
    def test_planted_defects_are_detected_and_only_the_exact_defect_counts(self):
        named = [("c.sample_loss", "sample-loss", "lost"), ("c.stale_epoch", "stale-epoch", "stale"),
                 ("c.double_applied", "double-applied-command", "duplicate"), ("c.false_ready", "false-ready", "early")]
        cases = [canary(cid, "canary_fire", oracle, violation) for cid, oracle, violation in named]
        cases += [
            case("x.undetected", "pass", expect=_canary_expect("stale-epoch", "stale")),
            case("x.wrong_oracle", "canary_fire", "some-other-oracle", "lost", expect=_canary_expect()),
            case("x.wrong_violation", "canary_fire", "sample-loss", "duplicate", expect=_canary_expect()),
            case("x.wrong_exit", "canary_exit0", "sample-loss", "lost", expect=_canary_expect()),
            case("x.incomplete_same_name", "incomplete", "sample-loss", expect=_canary_expect(codes=(2,))),
            case("x.hang", "hang", timeout_s=1, expect=_canary_expect()),
            case("x.crash", "kill_self", expect=_canary_expect()),
            case("x.no_result", "pass_noresult", expect=_canary_expect()),
            case("x.vacuous", "canary_fire", "sample-loss", "lost", "0", expect=_canary_expect()),
            case("x.not_independent", "canary_fire", "sample-loss", "lost", "3", "0", expect=_canary_expect()),
        ]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertNoInternal(res)
        for cid, oracle, violation in named:
            with self.subTest(detected=cid):
                c = self.assertCase(res, cid, "pass", "canary_detected")
                self.assertEqual(c["detail"], "%s/%s" % (oracle, violation))
        expected = {
            "x.undetected": "canary_not_detected", "x.wrong_oracle": "canary_wrong_oracle",
            "x.wrong_violation": "canary_wrong_violation", "x.wrong_exit": "canary_unexpected_exit",
            "x.incomplete_same_name": "canary_oracle_incomplete", "x.hang": "canary_wrong_failure_mode",
            "x.crash": "canary_wrong_failure_mode", "x.no_result": "canary_no_result",
            "x.vacuous": "vacuous_pass", "x.not_independent": "oracle_not_independent",
        }
        for cid, reason in expected.items():
            with self.subTest(rejected=cid):
                self.assertCase(res, cid, "fail", reason)
        self.assertEqual(res.den["pass"], 4)
        self.assertEqual(res.den["fail"], len(expected))

    def test_a_detected_canary_is_recorded_as_a_failed_oracle_with_typed_violation_kinds(self):
        res = self.ws.run(self.ws.manifest([canary("c.one", "canary_fire", "sample-loss", "lost")]))
        self.assertEqual(res.rc, 0, res.out + res.err)
        rec = [r for r in res.stream() if r.get("case_id") == "c.one"][0]
        self.assertTrue(rec["canary"])
        self.assertEqual(rec["outcome"], "pass")
        self.assertEqual(rec["process"]["exit_code"], 1)  # the subject really failed
        self.assertEqual(rec["oracle"]["status"], "failed")
        self.assertEqual(rec["oracle"]["violation_kinds"], {"lost": 2})
        self.assertTrue(rec["oracle"]["finalized"])
        self.assertEqual(rec["oracle"]["incomplete_reasons"], [])

    def test_a_canary_must_name_its_violation(self):
        c = case("c.vague", "canary_fire", "sample-loss", "lost", expect={"kind": "fail", "oracle": "sample-loss"})
        res = self.ws.run(self.ws.manifest([c]))
        self.assertEqual(res.rc, rs.EXIT_USAGE)
        self.assertIn("expect.violation", res.err)


# --------------------------------------------------------------------------- #
# process control: timeouts, crashes, leaks, cancellation
# --------------------------------------------------------------------------- #

class TestProcessControl(Base):
    def test_timeout_kills_the_child_and_is_classified(self):
        res = self.ws.run(self.ws.manifest([case("t.hang", "hang", timeout_s=1), case("t.ok", "pass")]))
        self.assertEqual(res.rc, 1)
        self.assertNoInternal(res)
        c = self.assertCase(res, "t.hang", "fail", "timeout")
        att = c["attempts"][0]
        self.assertEqual(att["kill_reason"], "timeout")
        self.assertEqual(att["rc"], -signal.SIGTERM)
        self.assertGreaterEqual(att["duration_ms"], 900)
        self.assertLess(att["duration_ms"], 8000)
        self.assertIn("reason=timeout", res.log("t.hang"))  # a silent child still has an indexable log
        rec = [r for r in res.stream() if r.get("case_id") == "t.hang"][0]
        self.assertEqual(rec["outcome"], "timeout")
        self.assertTrue(rec["process"]["timed_out"])
        self.assertEqual(rec["failure"]["first_causal_event"], {"log_seq": 0, "kind": "runner.timeout"})
        self.assertCase(res, "t.ok", "pass")

    def test_a_child_that_ignores_sigterm_is_escalated_to_sigkill(self):
        pidfile = self.ws.path("ign.pid")
        res = self.ws.run(self.ws.manifest([case("t.ign", "hang_ignore_term", pidfile, timeout_s=1)]))
        c = self.assertCase(res, "t.ign", "fail", "timeout")
        self.assertEqual(c["attempts"][0]["rc"], -signal.SIGKILL)
        self.assertTrue(pid_dead(read_pid(pidfile)))

    def test_the_whole_process_group_is_killed_not_just_the_leader(self):
        pidfile = self.ws.path("grandchild.pid")
        res = self.ws.run(self.ws.manifest([case("t.group", "hang_grandchild", pidfile, timeout_s=2)]))
        self.assertCase(res, "t.group", "fail", "timeout")
        self.assertTrue(res.cases["t.group"]["attempts"][0]["group_clear"])
        self.assertTrue(pid_dead(read_pid(pidfile)), "the grandchild survived the kill")

    def test_a_leaked_background_process_fails_the_case_and_is_killed(self):
        pidfile = self.ws.path("leak.pid")
        res = self.ws.run(self.ws.manifest([case("t.leak", "leak", pidfile), case("t.control", "pass")]))
        self.assertEqual(res.rc, 1, res.out + res.err)  # a failure, not an INCOMPLETE run
        c = self.assertCase(res, "t.leak", "fail", "leaked_process")
        self.assertTrue(c["attempts"][0]["leaked"])
        self.assertTrue(pid_dead(read_pid(pidfile)))
        self.assertCase(res, "t.control", "pass")

    def test_death_by_signal_is_a_crash_and_a_valid_receipt_does_not_rescue_it(self):
        cases = [case("k.kill", "kill_self"), case("k.usr1", "usr1_self"), case("k.late", "result_then_kill"),
                 case("k.exit139", "exit139")]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertNoInternal(res)
        self.assertEqual(self.assertCase(res, "k.kill", "fail", "crashed")["detail"], "SIGKILL")
        self.assertEqual(self.assertCase(res, "k.usr1", "fail", "crashed")["detail"], "SIGUSR1")
        self.assertCase(res, "k.late", "fail", "crashed")
        self.assertCase(res, "k.exit139", "fail", "nonzero_exit")  # exit status 139 is not a signal death
        self.assertEqual(res.agg["counts"]["crash"], 3)

    def test_global_timeout_kills_the_running_case_and_marks_the_rest_not_run(self):
        cases = [case("g.%d" % i, "hang", timeout_s=30) for i in range(3)]
        res = self.ws.run(self.ws.manifest(cases), extra=["--global-timeout-s", "1.5"])
        self.assertEqual(res.rc, 1)
        self.assertNoInternal(res)
        self.assertEqual(res.den, {"planned": 3, "executed": 1, "pass": 0, "fail": 1, "blocked": 0,
                                   "not_run": 2, "deselected": 0})
        self.assertCase(res, "g.0", "fail", "global_timeout")
        self.assertCase(res, "g.1", "not_run", "global_timeout")
        self.assertCase(res, "g.2", "not_run", "global_timeout")
        self.assertEqual(res.agg["counts"]["timeout"], 1)
        self.assertEqual(res.agg["counts"]["not_run"], 2)

    def test_a_spawn_failure_is_blocked_and_never_counted_as_executed(self):
        bad = os.path.join(self.ws.dir, "bad.bin")
        with open(bad, "w") as fh:
            fh.write("this is not a program\n")
        os.chmod(bad, 0o755)
        res = self.ws.run(self.ws.manifest([{"id": "s.bad", "argv": ["./bad.bin"], "tiers": ["smoke"]},
                                            case("s.ok", "pass")]))
        self.assertCase(res, "s.bad", "blocked", "spawn_failed")
        self.assertFalse(res.cases["s.bad"]["executed"])
        self.assertEqual((res.den["executed"], res.den["blocked"]), (1, 1))
        self.assertNoInternal(res)

    def _cancel(self, sig, second=None, cases_extra=()):
        sync = self.ws.path("slow-%s.pid" % signal.Signals(sig).name)
        cases = [case("z.slow", "slow", sync, timeout_s=120), case("z.after1", "pass"), case("z.after2", "pass")]
        m = self.ws.manifest(cases + list(cases_extra))
        run_id = "cancel-%s" % signal.Signals(sig).name
        proc = self.ws.popen(m, run_id)
        self.assertTrue(wait_for(sync), "the child never started")
        proc.send_signal(sig)
        if second is not None:
            time.sleep(0.5)
            proc.send_signal(second)
        return collect(proc, os.path.join(self.ws.artifacts, run_id)), read_pid(sync)

    def test_sigterm_and_sigint_cancel_cleanly_and_still_write_valid_receipts(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signal.Signals(sig).name):
                res, child_pid = self._cancel(sig)
                self.assertEqual(res.rc, rs.EXIT_CANCELLED, res.out + res.err + (
                    json.dumps(res.agg["problems"]) if res.report else ""))
                self.assertEqual(res.report["verdict"], "cancelled")
                self.assertEqual(res.den, {"planned": 3, "executed": 1, "pass": 0, "fail": 1, "blocked": 0,
                                           "not_run": 2, "deselected": 0})
                self.assertCase(res, "z.slow", "fail", "cancelled")
                self.assertCase(res, "z.after1", "not_run", "cancelled")
                self.assertCase(res, "z.after2", "not_run", "cancelled")
                self.assertTrue(pid_dead(child_pid), "the running child outlived the cancel")
                self.assertEqual(res.agg["counts"]["cancelled"], 1)  # a launched case counts as executed
                self.assertEqual(res.agg["denominator"]["executed"], 1)
                self.assertTrue(res.agg["complete"])
                self.assertEqual(res.report["receipts"]["crosscheck_mismatches"], [])

    def test_a_second_signal_skips_the_kill_grace(self):
        pidfile = self.ws.path("ign2.pid")
        m = self.ws.manifest([case("z.ign", "hang_ignore_term", pidfile, timeout_s=120)])
        proc = self.ws.popen(m, "cancel-twice", extra=["--kill-grace-s", "30"])
        self.assertTrue(wait_for(pidfile))
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        proc.send_signal(signal.SIGTERM)
        res = collect(proc, os.path.join(self.ws.artifacts, "cancel-twice"), timeout=25)
        self.assertLess(time.monotonic() - started, 20, "the second signal did not escalate past the 30 s grace")
        self.assertEqual(res.rc, rs.EXIT_CANCELLED)
        self.assertTrue(pid_dead(read_pid(pidfile)))
        self.assertCase(res, "z.ign", "fail", "cancelled")


# --------------------------------------------------------------------------- #
# seeds, replay, retries, reruns
# --------------------------------------------------------------------------- #

class TestSeedsAndReplay(Base):
    def _seen(self, res, cid):
        log = res.log(cid)
        return (int(re.search(r"^SEED=(\d+)$", log, re.M).group(1)),
                re.search(r"^SEQ=(.*)$", log, re.M).group(1), int(re.search(r"^RUNSEED=(\d+)$", log, re.M).group(1)))

    def test_case_seeds_are_derived_per_case_and_runs_are_reproducible(self):
        m = self.ws.manifest([case("sd.a", "print_seed"), case("sd.b", "print_seed")])
        r1, r2, r3 = (self.ws.run(m, extra=["--seed", s]) for s in ("7", "7", "8"))
        for r in (r1, r2, r3):
            self.assertEqual(r.rc, 0, r.out + r.err)
        for cid in ("sd.a", "sd.b"):
            seed1, seq1, run1 = self._seen(r1, cid)
            self.assertEqual(seed1, rx.derive_case_seed(7, cid))  # the shared derivation, not a private one
            self.assertEqual(run1, 7)
            self.assertEqual(self._seen(r2, cid)[:2], (seed1, seq1), "same run seed must replay identically")
            self.assertNotEqual(self._seen(r3, cid)[1], seq1, "a different run seed must change the sequence")
            self.assertEqual(r1.cases[cid]["seed"], seed1)
        self.assertNotEqual(self._seen(r1, "sd.a")[0], self._seen(r1, "sd.b")[0])
        self.assertEqual(r1.stream()[0]["seed"], 7)

    def test_random_seed_is_recorded_and_bad_seeds_are_refused(self):
        m = self.ws.manifest([case("sr.a", "print_seed")])
        r = self.ws.run(m, extra=["--seed", "random"])
        self.assertEqual(r.rc, 0, r.out + r.err)
        chosen = r.report["run"]["seed"]
        self.assertIsInstance(chosen, int)
        self.assertEqual(self._seen(r, "sr.a")[2], chosen)
        self.assertIn(str(chosen), r.report["replay"]["suite"])
        for bad in ("-1", "nine", str(2 ** 63)):
            self.assertEqual(self.ws.run(m, extra=["--seed", bad]).rc, rs.EXIT_USAGE, bad)

    def test_the_replay_command_reproduces_the_failure_and_leaves_the_original_untouched(self):
        m = self.ws.manifest([case("rp.fail", "fail_exit1", "rp.oracle"), case("rp.ok", "pass")])
        first = self.ws.run(m, extra=["--seed", "4242"])
        self.assertEqual(first.rc, 1)
        before = sha(os.path.join(first.run_dir, "receipt.json"))
        argv = shlex.split(first.cases["rp.fail"]["replay"])
        proc = subprocess.run(argv, cwd=self.ws.elsewhere, env=self.ws.env(), capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        runs = [d for d in os.listdir(self.ws.artifacts) if d != os.path.basename(first.run_dir)]
        self.assertEqual(len(runs), 1)
        again = Result(proc, os.path.join(self.ws.artifacts, runs[0]))
        self.assertTrue(again.report["run"]["partial_selection"])
        self.assertEqual(again.den["planned"], 1)
        a, b = first.cases["rp.fail"], again.cases["rp.fail"]
        self.assertEqual((b["status"], b["reason"], b["seed"]), (a["status"], a["reason"], a["seed"]))
        self.assertEqual(sha(os.path.join(first.run_dir, "receipt.json")), before, "a replay must not touch the original")
        rec = [r for r in first.stream() if r.get("case_id") == "rp.fail"][0]
        self.assertEqual(rec["replay"]["argv"], argv)  # the stream and the report carry the same command

    def test_a_run_id_is_never_overwritten(self):
        m = self.ws.manifest([case("ow.a", "fail_exit1", "ow.oracle")])
        first = self.ws.run(m, run_id="fixed-id")
        self.assertEqual(first.rc, 1)
        digests = {f: sha(os.path.join(first.run_dir, f)) for f in ("receipt.json", "receipts.jsonl", "events.jsonl")}
        second = self.ws.run(m, run_id="fixed-id")
        self.assertEqual(second.rc, rs.EXIT_USAGE)
        self.assertIn("already exists", second.err)
        for f, d in digests.items():
            self.assertEqual(sha(os.path.join(first.run_dir, f)), d, f)

    def test_exactly_one_of_several_racing_runs_with_the_same_id_wins(self):
        m = self.ws.manifest([case("rc.a", "pass")])
        procs = [self.ws.popen(m, "race-id") for _ in range(5)]
        results = [collect(p, os.path.join(self.ws.artifacts, "race-id")) for p in procs]
        codes = sorted(r.rc for r in results)
        self.assertEqual(codes, [0, 2, 2, 2, 2], codes)
        winner = [r for r in results if r.rc == 0][0]
        self.assertTrue(winner.agg["qualified"])

    def test_a_flaky_pass_after_a_failure_is_still_a_failure_and_keeps_the_original(self):
        cases = [case("f.flaky", "flaky"), case("f.stable", "pass"), case("f.always", "always_fail")]
        res = self.ws.run(self.ws.manifest(cases), extra=["--retries", "2"])
        self.assertEqual(res.rc, 1)
        self.assertNoInternal(res)
        flaky = self.assertCase(res, "f.flaky", "fail")
        self.assertTrue(flaky["reason"].startswith("flaky_pass_after_failure:oracle_failed"), flaky["reason"])
        self.assertTrue(flaky["flaky"])
        self.assertEqual([a["status"] for a in flaky["attempts"]], ["fail", "pass"])
        self.assertEqual(flaky["original_failure"]["reason"], "oracle_failed")
        self.assertEqual(len(res.cases["f.stable"]["attempts"]), 1)
        always = self.assertCase(res, "f.always", "fail", "oracle_failed")
        self.assertEqual(len(always["attempts"]), 3)
        self.assertFalse(always["flaky"])
        summary = rx.aggregate_path(os.path.join(res.run_dir, "receipts.jsonl"), self.ws.expected_for(cases),
                                    max_attempts=3)
        self.assertEqual(summary["cases"]["f.flaky"]["verdict"], "fail")
        self.assertTrue(summary["cases"]["f.flaky"]["flaky"])
        self.assertEqual(summary["cases"]["f.flaky"]["attempt_outcomes"], ["fail", "pass"])

    def test_retries_are_bounded(self):
        m = self.ws.manifest([case("rb.a", "pass")])
        self.assertEqual(self.ws.run(m, extra=["--retries", "6"]).rc, rs.EXIT_USAGE)
        self.assertEqual(self.ws.run(m, extra=["--retries", "5"]).rc, 0)


# --------------------------------------------------------------------------- #
# isolation: cwd, paths with spaces, parallel runs, environment, scratch
# --------------------------------------------------------------------------- #

class TestIsolation(Base):
    def test_runs_from_a_non_root_cwd_with_a_relative_manifest_path_containing_spaces(self):
        m = self.ws.manifest([case("c.cwd", "cwd")])
        rel = os.path.relpath(m, self.ws.elsewhere)
        self.assertIn(" ", rel)
        proc = subprocess.run([sys.executable, RUNNER, "run", "--tier", "smoke", "--manifest", rel,
                               "--artifact-root", self.ws.artifacts, "--run-id", "relrun"],
                              cwd=self.ws.elsewhere, env=self.ws.env(), capture_output=True, text=True, timeout=120)
        res = Result(proc, os.path.join(self.ws.artifacts, "relrun"))
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertIn("CWD=my cases", res.log("c.cwd"))  # the case runs in its manifest directory, not our cwd
        self.assertNotEqual(os.path.realpath(os.getcwd()), os.path.realpath(self.ws.elsewhere))

    def test_a_case_cwd_with_spaces_is_honoured(self):
        os.mkdir(os.path.join(self.ws.dir, "sub dir"))
        c = {"id": "c.sub", "argv": ["{python}", "-I", "{manifest_dir}/child.py", "cwd"], "cwd": "sub dir",
             "tiers": ["smoke"]}
        res = self.ws.run(self.ws.manifest([c]))
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertIn("CWD=sub dir", res.log("c.sub"))

    def test_parallel_runs_with_distinct_ids_do_not_interfere(self):
        m = self.ws.manifest([case("pr.%d" % i, "print_seed") for i in range(4)])
        procs = [self.ws.popen(m, "par-%d" % k, extra=["--jobs", "2", "--seed", str(k)]) for k in range(3)]
        results = [collect(p, os.path.join(self.ws.artifacts, "par-%d" % k)) for k, p in enumerate(procs)]
        for k, res in enumerate(results):
            with self.subTest(run=k):
                self.assertEqual(res.rc, 0, res.out + res.err)
                self.assertEqual(res.report["run"]["id"], "par-%d" % k)
                self.assertEqual({r["run_id"] for r in res.stream() if "run_id" in r}, {"par-%d" % k})
                self.assertEqual(sorted(os.listdir(os.path.join(res.run_dir, "logs"))),
                                 ["pr.%d.a1.log" % i for i in range(4)])
                self.assertIn("RUNSEED=%d" % k, res.log("pr.0"))
        self.assertEqual(sorted(os.listdir(self.ws.artifacts)), ["par-0", "par-1", "par-2"])

    def test_jobs_really_run_cases_concurrently(self):
        rdv = self.ws.path("rdv-parallel")
        os.mkdir(rdv)
        par = self.ws.manifest([case("j.%d" % i, "rendezvous", rdv, "3", "20", timeout_s=40) for i in range(3)])
        res = self.ws.run(par, extra=["--jobs", "3"])
        self.assertEqual(res.rc, 0, res.out + res.err)  # all three were alive at once, or they could not pass
        # control: the same program with one job cannot meet itself
        rdv1 = self.ws.path("rdv-serial")
        os.mkdir(rdv1)
        ser = self.ws.manifest([case("k.%d" % i, "rendezvous", rdv1, "3", "1.0", timeout_s=40) for i in range(3)])
        one = self.ws.run(ser, extra=["--jobs", "1"])
        self.assertEqual((one.den["pass"], one.den["fail"]), (1, 2), one.out)

    def test_the_child_environment_is_an_allowlist_not_a_copy(self):
        cases = [case("e.default", "env_probe", "PARENT_ONLY_SECRET"),
                 case("e.inherit", "env_probe", "PARENT_ONLY_SECRET", env_inherit=["PARENT_ONLY_SECRET"]),
                 case("e.home", "env_probe", "HOME", env_inherit=["HOME"])]
        res = self.ws.run(self.ws.manifest(cases), env={"PARENT_ONLY_SECRET": "hunter2-value"})
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertIn("PROBE=absent", res.log("e.default"))
        self.assertIn("HOME_IS_SCRATCH=True", res.log("e.default"))
        self.assertIn("PROBE=present", res.log("e.inherit"))
        self.assertIn("HOME_IS_SCRATCH=False", res.log("e.home"))
        allowed = self.ws.run(self.ws.manifest([case("e.flag", "env_probe", "PARENT_ONLY_SECRET")]),
                              extra=["--env-allow", "PARENT_ONLY_SECRET"], env={"PARENT_ONLY_SECRET": "x"})
        self.assertIn("PROBE=present", allowed.log("e.flag"))

    def test_scratch_is_removed_and_a_cleanup_failure_makes_the_run_incomplete(self):
        ok = self.ws.run(self.ws.manifest([case("sc.file", "scratch_file")]))
        self.assertEqual(ok.rc, 0, ok.out + ok.err)
        self.assertFalse(os.path.exists(os.path.join(ok.run_dir, "scratch")))
        res = self.ws.run(self.ws.manifest([case("sc.locked", "locked_dir")]))
        locked = os.path.join(res.run_dir, "scratch", "sc.locked", "a1", "locked")
        self.addCleanup(lambda: os.path.exists(locked) and os.chmod(locked, 0o700))
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        self.assertEqual(res.report["verdict"], "incomplete")
        self.assertIn("scratch_cleanup_failed", res.report["evidence"]["incomplete_reasons"])
        self.assertCase(res, "sc.locked", "pass")  # the case itself passed; only its cleanup is unaccounted for


# --------------------------------------------------------------------------- #
# redaction and bounded, honest logging
# --------------------------------------------------------------------------- #

class TestLoggingAndRedaction(Base):
    def test_secrets_never_reach_any_artifact_or_stdout(self):
        m = self.ws.manifest([case("rd.secrets", "secrets", env=dict(SECRETS))])
        res = self.ws.run(m, extra=["--redact-env", "S_LITERAL"], env={"S_LITERAL": SECRETS["S_LITERAL"]})
        self.assertEqual(res.rc, 0, res.out + res.err)
        everything = tree_bytes(res.run_dir) + res.out.encode() + res.err.encode()
        for name, secret in SECRETS.items():
            with self.subTest(secret=name):
                if name == "S_HOME":  # absolute repo paths legitimately appear in receipts; logs must not carry it
                    self.assertNotIn(secret.encode(), tree_bytes(os.path.join(res.run_dir, "logs")))
                else:
                    self.assertNotIn(secret.encode(), everything)
        log = res.log("rd.secrets")
        # positive controls: harmless text survives byte for byte, redaction leaves visible markers
        self.assertIn("BENIGN loopback 127.0.0.1 tokens_dropped=3 serial_port=ttyS0 doc 203.0.113.9 ver 1.2.3.400", log)
        self.assertIn("[REDACTED", log)
        self.assertIn("[REDACTED-PRIVATE-KEY]", log)
        self.assertNotIn("BEGIN RSA", log)
        self.assertIn("literal [REDACTED] end", log)
        self.assertIn("home ~/projects", log)

    def test_secrets_in_the_childs_own_result_fields_are_redacted_too(self):
        res = self.ws.run(self.ws.manifest([case("rd.leaky", "bad_with_secret", env=dict(SECRETS))]))
        self.assertEqual(res.rc, 1)
        self.assertNoInternal(res)
        everything = tree_bytes(res.run_dir) + res.out.encode()
        for name in ("S_TOKEN", "S_IP", "S_EMAIL"):
            self.assertNotIn(SECRETS[name].encode(), everything, name)
        rec = [r for r in res.stream() if r.get("case_id") == "rd.leaky"][0]
        self.assertEqual(rec["outcome"], "fail")
        self.assertIn("[REDACTED", json.dumps(rec["failure"]))

    def test_an_output_flood_is_drained_bounded_counted_and_makes_the_run_incomplete(self):
        cases = [case("fl.flood", "flood", "30000", max_output_bytes=65536, timeout_s=60),
                 case("fl.quiet", "flood", "100", max_output_bytes=65536)]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        flood = self.assertCase(res, "fl.flood", "pass")["attempts"][0]
        self.assertTrue(flood["log"]["truncated"])
        self.assertGreaterEqual(flood["log"]["bytes_seen"], 3_000_000)  # the pipe was drained, the child never blocked
        self.assertGreater(flood["log"]["dropped_events"], 29000)
        self.assertLessEqual(os.path.getsize(os.path.join(res.run_dir, "logs", "fl.flood.a1.log")), 65536 + 1024)
        self.assertLess(flood["duration_ms"], 30000)
        self.assertIn("critical_evidence_lost", res.report["evidence"]["incomplete_reasons"])
        self.assertFalse(res.agg["complete"])
        quiet = self.assertCase(res, "fl.quiet", "pass")["attempts"][0]  # control: under the cap, nothing is lost
        self.assertFalse(quiet["log"]["truncated"])
        self.assertEqual(quiet["log"]["dropped_events"], 0)

    def test_overlong_lines_binary_payloads_and_unterminated_lines(self):
        res = self.ws.run(self.ws.manifest([case("o.long", "overlong"), case("o.bin", "binary"),
                                            case("o.partial", "partial_line")]))
        long_attempt = self.assertCase(res, "o.long", "pass")["attempts"][0]
        self.assertEqual(long_attempt["log"]["overlong_lines"], 1)
        self.assertTrue(long_attempt["log"]["truncated"])
        self.assertLess(os.path.getsize(os.path.join(res.run_dir, "logs", "o.long.a1.log")), 70000)
        self.assertIn("[line truncated]", res.log("o.long"))
        with open(os.path.join(res.run_dir, "logs", "o.bin.a1.log"), "rb") as fh:
            raw = fh.read()
        self.assertIn(b"[binary payload", raw)
        self.assertNotIn(b"\x00", raw)
        self.assertNotIn(b"\xff", raw)
        self.assertFalse(self.assertCase(res, "o.bin", "pass")["attempts"][0]["log"]["truncated"])
        self.assertIn("no newline at the end", res.log("o.partial"))  # a child that died mid-line is still captured

    def _event_lines(self, res):
        with open(os.path.join(res.run_dir, "events.jsonl"), "rb") as fh:
            return [json.loads(l) for l in fh.read().decode("utf-8").splitlines() if l.strip()]

    def test_event_log_is_the_shared_sinks_closed_versioned_and_monotonic_log(self):
        res = self.ws.run(self.ws.manifest([case("ev.%d" % i, "pass") for i in range(3)]))
        self.assertEqual(res.rc, 0, res.out + res.err)
        lines = self._event_lines(res)
        header, footer, events = lines[0], lines[-1], lines[1:-1]
        self.assertEqual((header["schema"], header["type"], header["run"]),
                         ("ff.diag.v1", "header", os.path.basename(res.run_dir)))
        self.assertEqual((footer["type"], footer["evidence_complete"], footer["reasons"]), ("footer", True, []))
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        stamps = [e["mono_ns"] for e in events]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual((events[0]["kind"], events[-1]["kind"]), ("run_start", "run_end"))
        self.assertEqual(sum(e["kind"] == "case_end" and e.get("critical") is True for e in events), 3)
        self.assertEqual(sum(e["kind"] == "case_retry" for e in events), 0, "no retry was configured")
        self.assertEqual(footer["last_seq"], len(events))
        audit = rs.diagnostics_module().audit_log(os.path.join(res.run_dir, "events.jsonl"))
        self.assertTrue(audit.complete, audit.reasons)   # an independent re-read of the file agrees
        self.assertEqual(res.report["evidence"]["events"]["audit"]["sha256"], audit.sha256)

    def test_a_retry_event_is_only_announced_when_a_retry_really_follows(self):
        m = self.ws.manifest([case("rt.fail", "always_fail")])
        res = self.ws.run(m, extra=["--retries", "2"])
        retries = [e for e in self._event_lines(res) if e.get("kind") == "case_retry"]
        self.assertEqual(len(retries), 2)   # attempts 1 and 2 are followed by a retry; attempt 3 is the last

    def test_the_event_budget_drops_only_non_critical_events_and_says_so(self):
        cases = [case("eb.%02d" % i, "pass") for i in range(60)]
        reserve = max(64 * 1024, (60 + 16) * 2048)
        small = reserve + 16 * 1024   # the smallest legal log: almost no room beyond the critical reserve
        res = self.ws.run(self.ws.manifest(cases), extra=["--event-log-bytes", str(small), "--jobs", "4"])
        self.assertEqual(res.rc, 0, res.out + res.err)   # shedding noise is exposed, it is never a failure
        info = res.report["evidence"]["events"]
        st = info["stats"]
        self.assertEqual(st["emitted"], 182)
        self.assertEqual(st["written"] + st["dropped_total"], st["emitted"])   # exact accounting, nothing unaccounted
        self.assertGreater(st["dropped_total"], 0)
        self.assertEqual(st["critical_lost"], 0)
        self.assertTrue(info["verdict"]["complete"] and info["audit"]["complete"])
        events = self._event_lines(res)
        self.assertEqual(sum(e.get("kind") == "case_end" for e in events), 60)   # every critical event survived
        self.assertLessEqual(os.path.getsize(os.path.join(res.run_dir, "events.jsonl")), small)
        roomy = self.ws.run(self.ws.manifest(cases), extra=["--jobs", "4"])   # control: the default budget sheds nothing
        self.assertEqual(roomy.report["evidence"]["events"]["stats"]["dropped_total"], 0)

    def test_the_event_log_can_never_be_too_small_for_its_own_critical_events(self):
        res = self.ws.run(self.ws.manifest([case("sm.a", "pass")]), extra=["--event-log-bytes", "4096"])
        self.assertEqual(res.rc, rs.EXIT_USAGE)
        self.assertIn("need at least", res.err)

    # --- injected-fault targets ---------------------------------------------------------------------------
    # Everything below substitutes the shared sink's FaultableSink for the real file.  Those faults are
    # INJECTED: they prove how the RUNNER reacts to a hung, slow, unavailable or full sink; they are not
    # evidence about a real disk (the RLIMIT_FSIZE test further down is the real-OS write refusal).

    def _with_target(self, target, cases, run_id, extra=()):
        diag = rs.diagnostics_module()

        def fake(diag_, run_dir, rid, t0_ns, planned, nbytes, literals):
            return diag.DiagnosticSink(target, run_id=rid, clock_ns=lambda: time.monotonic_ns() - t0_ns)

        with mock.patch.object(rs, "make_event_sink", fake):
            started = time.monotonic()
            res = self.in_process(self.ws.manifest(cases), run_id, extra)
        return res, time.monotonic() - started

    def test_the_independent_reread_of_the_event_log_can_veto_a_run_the_sink_thought_complete(self):
        diag = rs.diagnostics_module()
        with mock.patch.object(diag, "audit_log", lambda path, **kw: diag.audit_bytes(b"this is not a diagnostic log\n")):
            res = self.in_process(self.ws.manifest([case("av.a", "pass")]), "veto")
        info = res.report["evidence"]["events"]
        self.assertTrue(info["verdict"]["complete"], "the sink's own accounting was fine")
        self.assertFalse(info["audit"]["complete"], "but the file re-read was not")
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        self.assertIn("event_log_audit_failed", res.report["evidence"]["incomplete_reasons"])
        self.assertEqual(res.den["pass"], 1)

    def test_a_hung_event_target_cannot_hang_the_run_and_leaves_it_incomplete(self):
        diag = rs.diagnostics_module()
        target = diag.FaultableSink(gate_timeout_s=120)
        target.gate()   # every write blocks until permitted: a hung disk or pipe
        self.addCleanup(target.ungate)
        res, elapsed = self._with_target(target, [case("hg.%d" % i, "pass") for i in range(5)], "hung",
                                         ["--event-close-timeout-s", "1"])
        self.assertLess(elapsed, 30, "the run waited on a blocked sink")
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        self.assertEqual(res.den["pass"], 5)   # the cases themselves ran and passed; only the evidence is incomplete
        self.assertIn("event_log_incomplete", res.report["evidence"]["incomplete_reasons"])
        self.assertFalse(res.report["evidence"]["events"]["verdict"]["complete"])
        self.assertNotIn("VERDICT: PASS", res.out)

    def test_a_slow_event_target_never_slows_the_cases_and_a_too_slow_one_is_reported_incomplete(self):
        diag = rs.diagnostics_module()
        target = diag.FaultableSink(gate_timeout_s=120)
        target.gate()
        stop = threading.Event()

        def trickle():   # about 10 writes per second: far slower than the runner produces events
            while not stop.is_set():
                target.permit(1)
                time.sleep(0.1)

        t = threading.Thread(target=trickle, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), target.ungate()))
        cases = [case("sw.%02d" % i, "pass") for i in range(40)]   # ~122 events would need >12 s to drain
        res, elapsed = self._with_target(target, cases, "slow", ["--event-close-timeout-s", "0.5"])
        self.assertLess(elapsed, 10, "producers must not wait for a slow sink (draining alone would take >12 s)")
        self.assertEqual(res.den["pass"], 40)
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)   # it did not drain in time: unclosed log
        self.assertIn("event_log_incomplete", res.report["evidence"]["incomplete_reasons"])

    def test_an_event_target_that_drains_slowly_but_in_time_loses_nothing(self):
        diag = rs.diagnostics_module()
        target = diag.FaultableSink(gate_timeout_s=120)
        target.gate()
        stop = threading.Event()

        def trickle():
            while not stop.is_set():
                target.permit(4)
                time.sleep(0.02)

        t = threading.Thread(target=trickle, daemon=True)
        t.start()
        self.addCleanup(lambda: (stop.set(), target.ungate()))
        res, _ = self._with_target(target, [case("sd.%d" % i, "pass") for i in range(8)], "slowok",
                                   ["--event-close-timeout-s", "20"])
        self.assertEqual(res.rc, 0, res.out + res.err)   # control: slow is not lossy
        self.assertTrue(diag.audit_bytes(bytes(target.data)).complete)

    def test_an_unavailable_or_full_event_target_makes_the_run_incomplete_not_failed_or_passed(self):
        diag = rs.diagnostics_module()
        gone = diag.FaultableSink()
        gone.available = False   # INJECTED: every write raises EIO
        res, _ = self._with_target(gone, [case("un.%d" % i, "pass") for i in range(3)], "gone")
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        self.assertEqual(res.den["pass"], 3)
        full = diag.FaultableSink(capacity_bytes=1500)   # INJECTED: ENOSPC after the first ~1.5 KB
        res2, _ = self._with_target(full, [case("fu.%d" % i, "pass") for i in range(3)], "fullsink")
        self.assertEqual(res2.rc, rs.EXIT_INCOMPLETE, res2.out + res2.err)
        self.assertNotIn("VERDICT: PASS", res2.out)
        ok = diag.FaultableSink()   # control: a healthy injected target gives a complete log and a clean pass
        res3, _ = self._with_target(ok, [case("ok.%d" % i, "pass") for i in range(3)], "healthy")
        self.assertEqual(res3.rc, 0, res3.out + res3.err)
        self.assertTrue(diag.audit_bytes(bytes(ok.data)).complete)

    def test_a_full_disk_class_write_failure_marks_the_run_incomplete_and_never_prints_a_pass(self):
        m = self.ws.manifest([case("fd.a", "pass"), case("fd.b", "pass")])
        limit = lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (2500, 2500))  # noqa: E731
        res = self.ws.run(m, preexec=limit)
        self.assertEqual(res.rc, rs.EXIT_INCOMPLETE, res.out + res.err)
        self.assertIn("VERDICT: INCOMPLETE", res.out)
        self.assertIn("EVIDENCE INCOMPLETE", res.out)
        self.assertIn("receipt could not be written", res.out)
        self.assertNotIn("VERDICT: PASS", res.out)
        self.assertIsNone(res.report)  # no half-written receipt posing as evidence
        self.assertLessEqual(os.path.getsize(os.path.join(res.run_dir, "events.jsonl")), 2500)
        control = self.ws.run(m)
        self.assertEqual(control.rc, 0, control.out + control.err)


# --------------------------------------------------------------------------- #
# registry: manifests, requirements, required cases, evidence classes
# --------------------------------------------------------------------------- #

class TestRegistry(Base):
    def test_duplicate_case_ids_across_manifests_are_refused(self):
        a, b = self.ws.manifest([case("d.same", "pass")]), self.ws.manifest([case("d.same", "pass")])
        res = self.ws.run([a, b])
        self.assertEqual(res.rc, rs.EXIT_USAGE)
        self.assertIn("duplicate case id d.same", res.err)
        self.assertIn(os.path.basename(a), res.err)
        self.assertIn(os.path.basename(b), res.err)
        self.assertFalse(os.path.exists(self.ws.artifacts), "no run directory for a refused registry")

    def test_malformed_manifests_are_refused_with_specific_messages(self):
        table = [
            ("unknown key", case("b.1", "pass", bogus=1), "unknown keys"),
            ("per-case seed was removed", case("b.2", "pass", seed=5), "unknown keys"),
            ("exit-code oracle was removed", case("b.3", "pass", oracle="exit_code"), "unknown keys"),
            ("bad tier", case("b.4", "pass", tiers=["nightly"]), "tiers"),
            ("zero timeout", case("b.5", "pass", timeout_s=0), "timeout_s"),
            ("bad id", case("b bad", "pass"), "invalid id"),
            ("bad evidence class", case("b.7", "pass", evidence_class="cloud"), "evidence_class"),
            ("reserved env", case("b.8", "pass", env={"FFW_X": "1"}), "reserved"),
            ("no argv", {"id": "b.9", "tiers": ["smoke"]}, "argv"),
            ("bad regex", case("b.10", "pass", required_stdout=["("]), "regex"),
        ]
        for label, bad_case, fragment in table:
            with self.subTest(label):
                res = self.ws.run(self.ws.manifest([bad_case]))
                self.assertEqual(res.rc, rs.EXIT_USAGE, res.out + res.err)
                self.assertIn(fragment, res.err)
        wrong = self.ws.manifest([case("w.1", "pass")], extra={"schema": "other.v9"})
        self.assertEqual(self.ws.run(wrong).rc, rs.EXIT_USAGE)

    def test_requirement_coverage_is_enforced_per_tier(self):
        reqs = {"R1": "covered", "R2": "no case anywhere", "R3": {"text": "full tier only", "tiers": ["full"]}}
        m = self.ws.manifest([case("q.a", "pass", requirements=["R1"])], requirements=reqs)
        res = self.ws.run(m)
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertEqual(res.report["uncovered_requirements"], ["R2"])  # R3 does not apply to smoke
        self.assertIn("uncovered_requirement:R2", res.report["blocking"])
        self.assertEqual(res.den["pass"], 1)
        self.assertEqual(res.report["requirements"]["R1"]["cases"], [{"id": "q.a", "status": "pass"}])
        ok = self.ws.manifest([case("q.a", "pass", requirements=["R1", "R2"])], requirements=reqs)
        self.assertEqual(self.ws.run(ok).rc, 0)
        undefined = self.ws.manifest([case("q.b", "pass", requirements=["NOPE"])], requirements=reqs)
        refused = self.ws.run(undefined)
        self.assertEqual(refused.rc, rs.EXIT_USAGE)
        self.assertIn("undefined requirement NOPE", refused.err)

    def test_coverage_command_lists_uncovered_requirements(self):
        reqs = {"R1": "covered", "R2": "uncovered"}
        m = self.ws.manifest([case("cv.a", "pass", requirements=["R1"])], requirements=reqs)
        proc = subprocess.run([sys.executable, RUNNER, "coverage", "--manifest", m], cwd=self.ws.elsewhere,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["uncovered_requirements"], ["R2"])
        self.assertEqual(doc["requirements"]["R1"]["cases"], ["cv.a"])
        full = self.ws.manifest([case("cv.a", "pass", requirements=["R1", "R2"])], requirements=reqs)
        ok = subprocess.run([sys.executable, RUNNER, "coverage", "--manifest", full], cwd=self.ws.elsewhere,
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(ok.returncode, 0)

    def test_required_cases_cannot_silently_vanish_from_the_denominator(self):
        m = self.ws.manifest([case("r.in_other_tier", "pass", tiers=("full",)), case("r.ok", "pass")],
                             required_cases={"smoke": ["r.in_other_tier"]}, extra=None)
        res = self.ws.run(m)
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertCase(res, "r.in_other_tier", "not_run", "required_case_not_in_tier")
        self.assertEqual((res.den["planned"], res.den["not_run"], res.den["pass"]), (2, 1, 1))
        undefined = self.ws.run(self.ws.manifest([case("r.ok", "pass")], required_cases=["r.never"]))
        self.assertCase(undefined, "r.never", "not_run", "missing_mandatory_case")
        self.assertEqual(undefined.den["planned"], 2)
        self.assertNoInternal(undefined)

    def test_manifest_dir_discovers_a_registry_split_across_directories(self):
        self.ws.manifest([case("sp.a", "pass")], name="alpha", subdir="a")
        self.ws.manifest([case("sp.b", "pass")], name="beta", subdir=os.path.join("b", "c"))
        res = self.ws.run([], extra=["--manifest-dir", self.ws.dir])
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertEqual(sorted(res.cases), ["sp.a", "sp.b"])
        self.assertEqual(len(res.report["manifests"]), 2)
        empty = os.path.join(self.ws.tmp.name, "empty dir")
        os.mkdir(empty)
        none = self.ws.run([], extra=["--manifest-dir", empty])
        self.assertEqual(none.rc, rs.EXIT_USAGE)
        self.assertIn("no *.suite.json", none.err)

    def test_external_evidence_classes_are_blocked_never_executed_and_never_laundered(self):
        phys, svc = self.ws.path("phys.ran"), self.ws.path("svc.ran")
        cases = [case("ex.phys", "sentinel", phys, evidence_class="physical"),
                 case("ex.svc", "sentinel", svc, evidence_class="real-service"), case("ex.sim", "pass")]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertNoInternal(res)
        self.assertCase(res, "ex.phys", "blocked", "external_evidence_required")
        self.assertCase(res, "ex.svc", "blocked", "external_evidence_required")
        self.assertFalse(os.path.exists(phys) or os.path.exists(svc), "an external-class case must never be launched")
        self.assertEqual((res.den["executed"], res.den["blocked"], res.den["not_run"]), (1, 2, 0))
        by = res.report["by_evidence_class"]
        self.assertEqual((by["physical"]["blocked"], by["real-service"]["blocked"], by["host-simulation"]["pass"]),
                         (1, 1, 1))
        self.assertEqual({k: v for k, v in res.agg["counts"].items() if v}, {"pass": 1, "blocked": 2})
        for rec in res.stream():  # explicit typed records: local origin, no authorization, a reason
            if rec.get("case_id") in ("ex.phys", "ex.svc"):
                self.assertEqual((rec["outcome"], rec["origin"]), ("blocked", "local"))
                self.assertNotIn("external", rec)
                self.assertTrue(rec["reason"].startswith("external_evidence_required"))

    def test_optional_cases_may_be_blocked_but_never_fail_silently(self):
        absent = {"id": "op.blocked", "argv": ["definitely-not-a-real-binary-xyz"], "tiers": ["smoke"],
                  "mandatory": False}
        ok = self.ws.run(self.ws.manifest([case("op.ok", "pass"), absent]))
        self.assertEqual(ok.rc, 0, ok.out + ok.err)  # an optional blocked case is reported, not fatal
        self.assertEqual((ok.den["blocked"], ok.den["pass"]), (1, 1))
        failing = self.ws.run(self.ws.manifest([case("op.ok", "pass"),
                                                case("op.fail", "fail_exit1", "o.x", mandatory=False)]))
        self.assertEqual(failing.rc, 1)  # but an optional case that RAN and failed still fails the run
        self.assertCase(failing, "op.fail", "fail", "oracle_failed")

    def test_list_command_prints_the_plan_without_running_anything(self):
        sentinel = self.ws.path("list.ran")
        m = self.ws.manifest([case("ls.a", "sentinel", sentinel), case("ls.b", "pass", tiers=("full",))],
                             required_cases=["ls.missing"])
        proc = subprocess.run([sys.executable, RUNNER, "list", "--tier", "smoke", "--manifest", m, "--json"],
                              cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual((doc["planned"], doc["deselected"]), (2, 1))
        self.assertEqual([c["id"] for c in doc["cases"]], ["ls.a", "ls.missing"])
        self.assertFalse(os.path.exists(sentinel))


# --------------------------------------------------------------------------- #
# the independent floor: derived from oracles.DEFECTS, consumed by the runner and the e2e entry
# --------------------------------------------------------------------------- #

REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
# FLOOR_UNDER_TEST / UNITTEST_CASE_UNDER_TEST / RUN_SUITE_UNDER_TEST point the suite at a deliberately weakened copy
# (mutation checks): the weakened copy must make these tests fail.
FLOOR_PY = os.environ.get("FLOOR_UNDER_TEST") or os.path.join(HERE, "q00", "floor.py")
E2E_Q00 = os.path.join(REPO_ROOT, "scripts", "e2e", "q00")
ORACLES_PY = os.path.join(HERE, "test_support", "oracles.py")
NEWC_PY = os.path.join(HERE, "test_support", "newc_case.py")
MKINITRAMFS_PY = os.path.join(REPO_ROOT, "toolchain", "src", "mkinitramfs.py")

FAKE_ORACLES = '''
from collections import namedtuple
Spec = namedtuple("Spec", "name scenario oracle kind description")
DEFECTS = {"alpha": Spec("alpha", "s", "orc-a", "lost", "d"), "beta": Spec("beta", "s", "orc-b", "dup", "d")}
CANARY_CASES = [
    ("q00.oracle.canary.alpha", None),
    ("q00.oracle.canary.beta", None),
    ("q00.oracle.positive.orc-a", None),
]
'''

FAKE_NEWC = '''
from collections import namedtuple
Spec = namedtuple("Spec", "name scenario oracle kind description")
CANARY_PREFIX = "q00.newc.canary."
POSITIVE_ID = "q00.newc.positive.fake"
DEFECTS = {"gamma": Spec("gamma", "s", "fake-newc", "bad_thing", "d")}
CANARY_CASES = [
    ("q00.newc.canary.gamma", None),
    ("q00.newc.positive.fake", None),
]
'''
FAKE_NEWC_IDS = ["q00.newc.canary.gamma", "q00.newc.positive.fake"]


class TestFloor(Base):
    def _units_dir(self, *stems):
        """A directory of (empty) test_<stem>.py files: the disk source the full-tier floor scans."""
        d = os.path.join(self.ws.tmp.name, "units %s" % "-".join(stems or ("none",)))
        os.makedirs(d, exist_ok=True)
        for stem in stems:
            with open(os.path.join(d, "test_%s.py" % stem), "w") as fh:
                fh.write("import unittest\n")
        return d

    def _fake_newc(self, source=FAKE_NEWC, name="fake_newc.py"):
        path = os.path.join(self.ws.dir, name)
        with open(path, "w") as fh:
            fh.write(source)
        return path

    def _emit(self, source=FAKE_ORACLES, name="fake_oracles.py", tier="smoke", units=None, newc=None):
        mod = os.path.join(self.ws.dir, name)
        with open(mod, "w") as fh:
            fh.write(source)
        exp, req = self.ws.path(name + "." + tier + ".expected.json"), self.ws.path(name + "." + tier + ".required.json")
        proc = subprocess.run([sys.executable, FLOOR_PY, "emit", "--tier", tier, "--oracles", mod,
                               "--newc", newc or self._fake_newc(), "--unit-root", units or self._units_dir(),
                               "--expected", exp, "--required", req],
                              cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        return proc, exp, req

    def _registry(self, **tweaks):
        """The synthetic Q00-shaped registry; `tweaks` edit it the way a careless or hostile author could."""
        cases = {
            "alpha": canary("q00.oracle.canary.alpha", "canary_fire", "orc-a", "lost"),
            "beta": canary("q00.oracle.canary.beta", "canary_fire", "orc-b", "dup"),
            "pos": case("q00.oracle.positive.orc-a", "pass"),
            "nc": canary("q00.newc.canary.gamma", "canary_fire", "fake-newc", "bad_thing"),
            "np": case("q00.newc.positive.fake", "pass"),
        }
        dropped = tweaks.pop("drop", None)
        if "beta_as" in tweaks:
            cases["beta"] = tweaks.pop("beta_as")
        if dropped:
            del cases[dropped]
        # The manifest keeps its OWN required_cases consistent with whatever it now contains.  A demoted or
        # altered case is also removed from required_cases: that is exactly what a careless author would do.
        hidden = tweaks.pop("unrequire", None)
        ids = [c["id"] for k, c in cases.items() if k != hidden]
        return self.ws.manifest(list(cases.values()), required_cases=ids)

    def _print(self, tier):
        proc = subprocess.run([sys.executable, FLOOR_PY, "print", "--tier", tier], cwd=self.ws.elsewhere,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_the_floor_is_derived_from_the_real_oracles_and_the_files_on_disk_for_each_tier(self):
        oracles = _load("oracles_under_test", ORACLES_PY)
        smoke, full = self._print("smoke"), self._print("full")
        want = {"q00.oracle.canary." + n: (d.oracle, d.kind) for n, d in oracles.DEFECTS.items()}
        got = {cid: (v["oracle"], v["violation"]) for cid, v in smoke["required"].items()
               if v["canary"] and cid.startswith("q00.oracle.")}
        self.assertEqual(got, want)
        self.assertEqual(len(got), len(oracles.DEFECTS))
        positives = sorted(cid for cid, v in smoke["required"].items() if not v["canary"] and cid.startswith("q00.oracle."))
        self.assertEqual(positives, sorted(cid for cid, _ in oracles.CANARY_CASES if cid.startswith("q00.oracle.positive.")))
        # the newc-alignment cases come from the adapter's own planted-defect table, with exact identities
        newc = _load("newc_under_test", NEWC_PY)
        want_newc = {newc.CANARY_PREFIX + n: (d.oracle, d.kind) for n, d in newc.DEFECTS.items()}
        got_newc = {cid: (v["oracle"], v["violation"]) for cid, v in smoke["required"].items()
                    if v["canary"] and cid.startswith("q00.newc.")}
        self.assertEqual(got_newc, want_newc)
        self.assertGreaterEqual(len(got_newc), 3)
        self.assertEqual([cid for cid, v in smoke["required"].items() if cid.startswith("q00.newc.") and not v["canary"]],
                         [newc.POSITIVE_ID])
        # smoke has no unit modules (one of them runs the smoke acceptance itself); full adds exactly the files on disk
        self.assertFalse([c for c in smoke["required"] if c.startswith("q00.unit.")])
        on_disk = sorted("q00.unit." + n[:-3] for d in (HERE, os.path.join(HERE, "test_support"),
                                                         os.path.join(REPO_ROOT, "toolchain", "tests"))
                         for n in os.listdir(d) if n.startswith("test_") and n.endswith(".py"))
        self.assertGreaterEqual(len(on_disk), 7)
        self.assertEqual(sorted(c for c in full["required"] if c.startswith("q00.unit.")), on_disk)
        self.assertEqual(sorted(set(full["required"]) - set(on_disk)), sorted(smoke["required"]))
        for doc in (smoke, full):
            for cid, spec in doc["expected"].items():   # expected and required describe the same cases and agree
                self.assertTrue(spec["mandatory"])
                self.assertEqual({k: spec[k] for k in doc["required"][cid]}, doc["required"][cid])
        # the shipped manifest equals the floor, tier by tier: nothing missing, nothing extra, identities equal
        shipped = read_json(os.path.join(HERE, "q00.suite.json"))
        for tier, doc in (("smoke", smoke), ("full", full)):
            by_id = {c["id"]: c for c in shipped["cases"] if tier in c["tiers"]}
            self.assertEqual(sorted(by_id), sorted(doc["required"]), tier)
            self.assertEqual(sorted(shipped["required_cases"][tier]), sorted(doc["required"]), tier)
            for cid, c in by_id.items():
                exp = c.get("expect", {})
                self.assertEqual(exp.get("kind") == "fail", doc["required"][cid]["canary"], cid)
                if exp:
                    self.assertEqual((exp["oracle"], exp["violation"]),
                                     (doc["required"][cid]["oracle"], doc["required"][cid]["violation"]), cid)

    def test_a_unit_module_dropped_from_both_cases_and_required_cases_is_caught_by_the_disk_floor(self):
        units = self._units_dir("alpha", "beta")
        proc, exp, req = self._emit(tier="full", units=units, name="fake_full.py")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(sorted(read_json(req)), FAKE_NEWC_IDS + ["q00.oracle.canary.alpha", "q00.oracle.canary.beta",
                                                                   "q00.oracle.positive.orc-a", "q00.unit.test_alpha",
                                                                   "q00.unit.test_beta"])
        smoke_proc, _, smoke_req = self._emit(tier="smoke", units=units, name="fake_full.py")
        self.assertFalse([c for c in read_json(smoke_req) if c.startswith("q00.unit.")])   # tier-aware
        oracle_cases = [canary("q00.oracle.canary.alpha", "canary_fire", "orc-a", "lost", tiers=("smoke", "full")),
                        canary("q00.oracle.canary.beta", "canary_fire", "orc-b", "dup", tiers=("smoke", "full")),
                        case("q00.oracle.positive.orc-a", "pass", tiers=("smoke", "full")),
                        canary("q00.newc.canary.gamma", "canary_fire", "fake-newc", "bad_thing", tiers=("smoke", "full")),
                        case("q00.newc.positive.fake", "pass", tiers=("smoke", "full"))]
        unit = lambda stem: case("q00.unit.test_" + stem, "pass", tiers=("full",))   # noqa: E731
        both = oracle_cases + [unit("alpha"), unit("beta")]
        ids = lambda cs: [c["id"] for c in cs]   # noqa: E731
        ok = self.ws.run(self.ws.manifest(both, required_cases={"full": ids(both)}), tier="full", extra=["--floor", req])
        self.assertEqual(ok.rc, 0, ok.out + ok.err)   # control: the intact registry satisfies the full floor
        shrunk = oracle_cases + [unit("alpha")]   # test_beta.py is still on disk, but its case is gone from the manifest
        manifest = self.ws.manifest(shrunk, required_cases={"full": ids(shrunk)})
        alone = self.ws.run(manifest, tier="full")
        self.assertEqual(alone.rc, 0, "manifest-only checks cannot see a dropped unit module: " + alone.out)
        guarded = self.ws.run(manifest, tier="full", extra=["--floor", req])
        self.assertEqual(guarded.rc, 1, guarded.out + guarded.err)
        self.assertEqual(guarded.report["receipts"]["floor"]["violations"]["dropped"], 1)

    def test_an_incoherent_oracles_module_is_refused_not_turned_into_a_smaller_floor(self):
        cases = {
            "empty defects": ("from collections import namedtuple\nDEFECTS = {}\nCANARY_CASES = []\n", "empty"),
            "defect without a canary case": (FAKE_ORACLES.replace(
                '    ("q00.oracle.canary.beta", None),\n', ""), "no canary case"),
            "canary for an unknown defect": (FAKE_ORACLES.replace(
                'canary.beta', 'canary.gamma'), "no 'gamma'"),
            "unrecognised id": (FAKE_ORACLES.replace('q00.oracle.positive.orc-a', 'mystery.case'), "unrecognised"),
            "duplicate id": (FAKE_ORACLES.replace('("q00.oracle.positive.orc-a", None)',
                                                  '("q00.oracle.canary.alpha", None)'), "duplicate"),
            "import error": ("raise RuntimeError('boom')\n", "failed to import"),
            "no DEFECTS attribute": ("CANARY_CASES = []\n", "lacks DEFECTS"),
        }
        for label, (src, fragment) in cases.items():
            with self.subTest(label):
                proc, exp, req = self._emit(src, name="bad_%d.py" % abs(hash(label)))
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(fragment, proc.stderr)
                self.assertFalse(os.path.exists(req), "no floor file may be written from an incoherent source")
        ok, exp, req = self._emit()
        self.assertEqual(ok.returncode, 0, ok.stderr)  # control: the coherent module yields a floor
        self.assertEqual(sorted(read_json(req)), FAKE_NEWC_IDS + ["q00.oracle.canary.alpha", "q00.oracle.canary.beta",
                                                                   "q00.oracle.positive.orc-a"])

    def test_an_incoherent_newc_module_is_refused_not_turned_into_a_smaller_floor(self):
        cases = {
            "empty defects": (FAKE_NEWC.replace('DEFECTS = {"gamma": Spec("gamma", "s", "fake-newc", "bad_thing", "d")}',
                                                "DEFECTS = {}"), "empty"),
            "defect without a canary case": (FAKE_NEWC.replace('    ("q00.newc.canary.gamma", None),\n', ""), "no canary case"),
            "no positive control": (FAKE_NEWC.replace('    ("q00.newc.positive.fake", None),\n', ""), "no positive control"),
            "id outside the newc namespace": (FAKE_NEWC.replace('"q00.newc.positive.fake", None', '"q00.oracle.positive.x", None'),
                                              "must start with"),
            "canary for an unknown defect": (FAKE_NEWC.replace('q00.newc.canary.gamma", None', 'q00.newc.canary.delta", None'),
                                             "has no 'delta'"),
            "missing the case table": ("DEFECTS = {}\n", "lacks"),
        }
        for label, (src, fragment) in cases.items():
            with self.subTest(label):
                path = self._fake_newc(src, name="bad_newc_%d.py" % abs(hash(label)))
                proc, exp, req = self._emit(name="ok_oracles_%d.py" % abs(hash(label)), newc=path)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(fragment, proc.stderr)
                self.assertFalse(os.path.exists(req), "no floor file may be written from an incoherent source")

    def test_emit_never_overwrites_an_existing_floor_file(self):
        _, exp, req = self._emit()
        before = sha(req)
        mod = os.path.join(self.ws.dir, "fake_oracles.py")
        again = subprocess.run([sys.executable, FLOOR_PY, "emit", "--tier", "smoke", "--oracles", mod,
                                "--newc", self._fake_newc(), "--unit-root", self._units_dir(),
                                "--expected", exp, "--required", req],
                               cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(again.returncode, 2)
        self.assertEqual(sha(req), before)

    def test_a_case_dropped_from_both_cases_and_required_cases_passes_alone_and_fails_with_the_floor(self):
        proc, exp, req = self._emit()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        full = self._registry()
        control = self.ws.run(full, extra=["--floor", req])
        self.assertEqual(control.rc, 0, control.out + control.err)  # the intact registry satisfies the floor
        self.assertEqual(control.report["receipts"]["floor"]["cases"], 3)
        self.assertEqual(control.report["receipts"]["floor"]["violations"],
                         {"count": 3, "dropped": 0, "demoted": 0, "altered": 0})

        # THE HOLE: remove a canary from `cases` AND `required_cases`.  Every check that reads only the manifest passes.
        shrunk = self._registry(drop="beta")
        alone = self.ws.run(shrunk)
        self.assertEqual(alone.rc, 0, "without an independent floor the silent drop is invisible: " + alone.out)
        self.assertEqual(alone.den["planned"], 2)
        # THE FIX: the same manifest under the independent floor fails, and says exactly what vanished.
        guarded = self.ws.run(shrunk, extra=["--floor", req])
        self.assertEqual(guarded.rc, 1, guarded.out + guarded.err)
        self.assertEqual(guarded.report["receipts"]["floor"]["violations"]["dropped"], 1)
        self.assertTrue(any("required_cases_violated:1" in b for b in guarded.report["blocking"]), guarded.report["blocking"])
        self.assertNoInternal(guarded)
        # and the independent re-verification the e2e entry uses agrees, from the finished stream alone
        verify = subprocess.run([sys.executable, RECEIPTS_PY, "verify", os.path.join(guarded.run_dir, "receipts.jsonl"),
                                 "--expected", exp, "--require", req], capture_output=True, text=True, timeout=60)
        self.assertEqual(verify.returncode, 1, verify.stdout)
        # judged against the INDEPENDENT registry the vanished canary is not merely "dropped": it never ran
        self.assertIn("not_run=1", verify.stdout)
        self.assertIn("registry_mismatch", verify.stdout)

    def test_demoting_or_altering_a_floor_case_is_also_caught(self):
        _, exp, req = self._emit()
        demoted = self._registry(beta_as=canary("q00.oracle.canary.beta", "canary_fire", "orc-b", "dup", mandatory=False),
                                 unrequire="beta")
        self.assertEqual(self.ws.run(demoted).rc, 0, "an optional canary slips past manifest-only checks")
        d = self.ws.run(demoted, extra=["--floor", req])
        self.assertEqual(d.rc, 1, d.out + d.err)
        self.assertEqual(d.report["receipts"]["floor"]["violations"]["demoted"], 1)
        # altered: the case still passes, but it now plants a different violation than the floor demands
        altered = self._registry(beta_as=canary("q00.oracle.canary.beta", "canary_fire", "orc-b", "other"),
                                 unrequire="beta")
        self.assertEqual(self.ws.run(altered).rc, 0)
        a = self.ws.run(altered, extra=["--floor", req])
        self.assertEqual(a.rc, 1, a.out + a.err)
        self.assertGreaterEqual(a.report["receipts"]["floor"]["violations"]["altered"], 1)
        self.assertNoInternal(a)

    def test_the_floor_cannot_be_silently_skipped_or_malformed(self):
        _, exp, req = self._emit()
        m = self._registry()
        partial = self.ws.run(m, extra=["--floor", req, "--case", "q00.oracle.positive.orc-a"])
        self.assertEqual(partial.rc, rs.EXIT_USAGE)
        self.assertIn("--floor cannot be combined with --case", partial.err)
        for label, content in (("empty object", "{}"), ("not json", "{oops"), ("a list", '["a"]'),
                               ("bad constraint", '{"x": {"nonsense": 1}}')):
            with self.subTest(label):
                bad = self.ws.path("bad-floor.json")
                if os.path.exists(bad):
                    os.unlink(bad)   # this test's own scratch file
                with open(bad, "w") as fh:
                    fh.write(content)
                res = self.ws.run(m, extra=["--floor", bad])
                self.assertEqual(res.rc, rs.EXIT_USAGE, res.out + res.err)
                self.assertIn("--floor", res.err)
        missing = self.ws.run(m, extra=["--floor", self.ws.path("does-not-exist.json")])
        self.assertEqual(missing.rc, rs.EXIT_USAGE)

    def test_the_acceptance_entry_runs_the_floor_the_runner_and_the_second_verifier_consistently(self):
        root = os.path.join(self.ws.tmp.name, "e2e root")
        proc = subprocess.run([sys.executable, E2E_Q00, "--tier", "smoke", "--artifact-root", root, "--run-id", "e2e1"],
                              cwd=self.ws.elsewhere, env=self.ws.env(), capture_output=True, text=True, timeout=300)
        out = proc.stdout
        self.assertIn("floor[smoke]: 19 cases (13 canaries, 6 positives, 0 unit modules)", out)   # oracles + newc
        self.assertIn("run-suite smoke tier with --floor", out)
        self.assertIn("independent re-verification with receipts.py", out)   # step 3 ran as a separate process
        report = read_json(os.path.join(root, "e2e1", "receipt.json"))
        self.assertEqual(report["receipts"]["floor"]["cases"], 19)
        self.assertEqual(report["receipts"]["floor"]["violations"]["dropped"], 0)
        self.assertEqual(report["denominators"]["planned"], 19)
        # one verdict, three steps: exit 0 only when run-suite AND the second verifier both say so
        self.assertEqual(proc.returncode == 0, "Q00 ACCEPTANCE: PASS" in out, out)
        self.assertEqual(proc.returncode == 0, report["verdict"] == "pass")
        # exclusive artifacts: a rerun with the same id is refused, and the earlier floor is untouched
        again = subprocess.run([sys.executable, E2E_Q00, "--tier", "smoke", "--artifact-root", root, "--run-id", "e2e1"],
                               cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(again.returncode, 2)
        # a tier is mandatory here too
        notier = subprocess.run([sys.executable, E2E_Q00, "--artifact-root", root], cwd=self.ws.elsewhere,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(notier.returncode, 2)


class TestNewcCanaries(Base):
    """The wrong-newc-alignment canaries through the runner: the real parser detects every planted defect and accepts
    correct archives, and a parser that is blind, over-strict or lax can never read as a detection."""

    SHIPPED = os.path.join(HERE, "q00.suite.json")

    def _newc(self):
        return _load("newc_under_test_cases", NEWC_PY)

    def _case_ids(self):
        return [cid for cid, _ in self._newc().CANARY_CASES]

    def test_the_real_parser_detects_every_planted_alignment_defect_and_accepts_correct_archives(self):
        ids = self._case_ids()
        argv = []
        for cid in ids:
            argv += ["--case", cid]
        res = self.ws.run(self.SHIPPED, extra=argv)
        self.assertEqual(res.rc, 0, res.out + res.err)
        self.assertNoInternal(res)
        newc = self._newc()
        for name, d in newc.DEFECTS.items():
            with self.subTest(defect=name):
                c = self.assertCase(res, newc.CANARY_PREFIX + name, "pass", "canary_detected")
                self.assertEqual(c["detail"], "%s/%s" % (d.oracle, d.kind))   # the exact expected identity
        self.assertCase(res, newc.POSITIVE_ID, "pass", "ok")
        self.assertEqual(res.den["pass"], len(ids))

    def _mutant(self, tag, edits=(), append=""):
        src = open(MKINITRAMFS_PY, encoding="utf-8").read()
        for old, new in edits:
            self.assertEqual(src.count(old), 1, "anchor drifted in the production parser: %r" % old)
            src = src.replace(old, new)
        path = os.path.join(self.ws.dir, "parser_%s.py" % tag)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src + append)
        return path

    def _run_against(self, parser_path):
        newc = self._newc()
        cases = [{"id": newc.CANARY_PREFIX + n, "tiers": ["smoke"], "timeout_s": 60,
                  "argv": ["{python}", "-I", NEWC_PY, "replay", "--defect", n, "--verifier", parser_path],
                  "expect": {"kind": "fail", "oracle": d.oracle, "violation": d.kind, "exit_codes": [1]}}
                 for n, d in newc.DEFECTS.items()]
        cases.append({"id": newc.POSITIVE_ID, "tiers": ["smoke"], "timeout_s": 60,
                      "argv": ["{python}", "-I", NEWC_PY, "positive", "--verifier", parser_path]})
        return self.ws.run(self.ws.manifest(cases)), newc

    def test_a_parser_that_stops_checking_padding_does_not_read_as_a_detection(self):
        lax = self._mutant("lax", edits=[
            ('if raw[name_end:dataoff] != b"\0" * (dataoff - name_end):', "if False:"),
            ('if raw[data_end:next_off] != b"\0" * (next_off - data_end):', "if False:")])
        res, newc = self._run_against(lax)
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertNoInternal(res)
        for name in newc.DEFECTS:
            with self.subTest(defect=name):   # either it accepts the planted archive, or it rejects it for the wrong reason
                c = res.cases[newc.CANARY_PREFIX + name]
                self.assertEqual(c["status"], "fail")
                self.assertIn(c["reason"], ("canary_not_detected", "canary_wrong_violation"), c["reason"])
        self.assertCase(res, newc.POSITIVE_ID, "pass", "ok")   # control: it still accepts correct archives

    def test_a_blind_or_over_strict_parser_is_incomplete_never_a_detection(self):
        blind = self._mutant("blind", append="\n\ndef parse_cpio_bytes(raw):\n    return []\n")
        strict = self._mutant("strict", append="\n\ndef parse_cpio_bytes(raw):\n"
                                              "    raise ValueError('non-zero header padding: rejects everything')\n")
        for label, path in (("blind", blind), ("over-strict", strict)):
            with self.subTest(parser=label):
                res, newc = self._run_against(path)
                self.assertEqual(res.rc, 1, res.out + res.err)
                for name in newc.DEFECTS:
                    # an over-strict parser "rejects" the planted archive too, but it rejects the CORRECT one as
                    # well, so the rejection proves nothing: the canary must not be credited
                    self.assertCase(res, newc.CANARY_PREFIX + name, "fail", "canary_oracle_incomplete")
                self.assertEqual(res.den["pass"], 0)

    def test_dropping_a_newc_canary_from_the_manifest_is_caught_by_the_real_floor(self):
        newc = self._newc()
        victim = newc.CANARY_PREFIX + sorted(newc.DEFECTS)[0]
        exp, req = self.ws.path("real.expected.json"), self.ws.path("real.required.json")
        emit = subprocess.run([sys.executable, FLOOR_PY, "emit", "--tier", "smoke", "--expected", exp, "--required", req],
                              cwd=self.ws.elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(emit.returncode, 0, emit.stderr)
        self.assertIn(victim, read_json(req))
        doc = read_json(self.SHIPPED)
        text = json.dumps(doc).replace("{manifest_dir}", HERE)   # the copy lives elsewhere: make its paths absolute

        def write(name, drop=None):
            d = json.loads(text)
            if drop:
                d["cases"] = [c for c in d["cases"] if c["id"] != drop]
                d["required_cases"] = {t: [i for i in ids if i != drop] for t, ids in d["required_cases"].items()}
            path = os.path.join(self.ws.dir, name + ".suite.json")
            with open(path, "w") as fh:
                json.dump(d, fh)
            return path

        control = self.ws.run(write("intact"), extra=["--floor", req])
        self.assertEqual(control.rc, 0, control.out + control.err)   # the intact copy satisfies the floor
        shrunk = write("shrunk", drop=victim)
        alone = self.ws.run(shrunk)
        self.assertEqual(alone.rc, 0, "manifest-only checks cannot see the dropped canary: " + alone.out)
        guarded = self.ws.run(shrunk, extra=["--floor", req])
        self.assertEqual(guarded.rc, 1, guarded.out + guarded.err)
        self.assertEqual(guarded.report["receipts"]["floor"]["violations"]["dropped"], 1)


class TestProducerConformance(Base):
    """The real producer (oracles.py) against the runner's contract.  This is the integration gate:
    it is RED until oracles.py emits the v1.1 fields, and green is the only way to a real Q00 pass."""

    def test_real_oracle_results_are_accepted_by_the_runner(self):
        names = ["sample_loss", "stale_epoch", "double_apply", "false_ready_early"]
        for defect in names:
            with self.subTest(defect=defect):
                scratch = os.path.join(self.ws.tmp.name, "prod-" + defect)
                os.mkdir(scratch)
                result = os.path.join(scratch, "result.json")
                env = self.ws.env({"FFW_RUN_ID": "R", "FFW_CASE_ID": "q00.oracle.canary." + defect,
                                   "FFW_RESULT_NONCE": "N", "FFW_RESULT_PATH": result, "FFW_SEED": "1"})
                proc = subprocess.run([sys.executable, "-I", ORACLES_PY, "replay", "--defect", defect], env=env,
                                      cwd=scratch, capture_output=True, text=True, timeout=120)
                self.assertEqual(proc.returncode, 1, proc.stdout[:300] + proc.stderr[:300])
                parsed, err = rs.read_case_result(result, "R", "q00.oracle.canary." + defect, "N", rs.Redactor(),
                                                  rx.ORACLE_KINDS)
                self.assertIsNone(err, "oracles.py output is rejected by contract v1.1: %s" % err)
                self.assertEqual(parsed["verdict"], "fail")
                self.assertGreaterEqual(parsed["mismatches"], 1)


# --------------------------------------------------------------------------- #
# the unittest adapter: existing test modules become registry cases, judged by what unittest observed
# --------------------------------------------------------------------------- #

UNITTEST_CASE = os.environ.get("UNITTEST_CASE_UNDER_TEST") or os.path.join(HERE, "q00", "unittest_case.py")
_UT_HEAD = "import unittest\n\n\nclass T(unittest.TestCase):\n"
UT_MODULES = {
    "pass": _UT_HEAD + "    def test_a(self):\n        self.assertEqual(1, 1)\n\n    def test_b(self):\n        self.assertTrue(True)\n",
    "fail": _UT_HEAD + "    def test_a(self):\n        self.assertEqual(1, 1)\n\n    def test_b(self):\n        self.assertEqual(1, 2)\n",
    "error": _UT_HEAD + "    def test_a(self):\n        self.assertEqual(1, 1)\n\n    def test_b(self):\n        raise RuntimeError('boom')\n",
    "unexpected": _UT_HEAD + "    def test_a(self):\n        self.assertEqual(1, 1)\n\n    @unittest.expectedFailure\n    def test_x(self):\n        pass\n",
    "skip": _UT_HEAD + "    def test_a(self):\n        self.assertEqual(1, 1)\n\n    @unittest.skip('needs a Linux-only feature')\n    def test_s(self):\n        pass\n",
    "allskip": _UT_HEAD + "    @unittest.skip('needs a Linux-only feature')\n    def test_s(self):\n        pass\n",
    "empty": "import unittest\n",
    "hermetic": _UT_HEAD + "    def test_no_runner_protocol_variables_leak_in(self):\n"
                "        import os\n"
                "        self.assertEqual([k for k in os.environ if k.startswith('FFW_')], [])\n",
    "import": "raise RuntimeError('cannot import this module')\n",
}


class TestUnittestAdapter(Base):
    def _module(self, kind):
        path = os.path.join(self.ws.dir, "t_%s.py" % kind)
        with open(path, "w") as fh:
            fh.write(UT_MODULES[kind])
        return path

    def _case(self, cid, module, *flags, **kw):
        c = {"id": cid, "argv": ["{python}", "-I", UNITTEST_CASE, module] + list(flags), "tiers": ["smoke"],
             "timeout_s": 60}
        c.update(kw)
        return c

    def test_every_outcome_is_typed_and_only_real_execution_passes(self):
        cases = [self._case("u.pass", self._module("pass")),
                 self._case("u.skip_allowed", self._module("skip"), "--allow-skip", "needs a Linux-only"),
                 self._case("u.fail", self._module("fail")),
                 self._case("u.error", self._module("error")),
                 self._case("u.unexpected_success", self._module("unexpected")),
                 self._case("u.import_error", self._module("import")),
                 self._case("u.unallowed_skip", self._module("skip")),
                 self._case("u.all_skipped", self._module("allskip"), "--allow-skip", "needs a Linux-only"),
                 self._case("u.no_tests", self._module("empty")),
                 self._case("u.missing_module", os.path.join(self.ws.dir, "t_nothing.py"))]
        res = self.ws.run(self.ws.manifest(cases))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertNoInternal(res)   # the strict aggregator accepted every record the adapter produced
        want = {"u.pass": ("pass", "ok"), "u.skip_allowed": ("pass", "ok"),
                "u.fail": ("fail", "oracle_failed"), "u.error": ("fail", "oracle_failed"),
                "u.unexpected_success": ("fail", "oracle_failed"), "u.import_error": ("fail", "oracle_failed"),
                "u.unallowed_skip": ("fail", "oracle_incomplete"), "u.all_skipped": ("fail", "oracle_incomplete"),
                "u.no_tests": ("fail", "oracle_incomplete"), "u.missing_module": ("fail", "nonzero_exit")}
        for cid, (status, reason) in want.items():
            with self.subTest(case=cid):
                self.assertCase(res, cid, status, reason)

        def result(cid):
            return res.cases[cid]["attempts"][0]["result"]

        self.assertEqual((result("u.pass")["checks"], result("u.pass")["mismatches"]), (2, 0))
        self.assertEqual((result("u.fail")["violation_kinds"], result("u.fail")["mismatches"], result("u.fail")["checks"]),
                         ({"test_failure": 1}, 1, 2))
        self.assertEqual(result("u.error")["violation_kinds"], {"test_error": 1})
        self.assertEqual(result("u.unexpected_success")["violation_kinds"], {"unexpected_success": 1})
        self.assertEqual(result("u.import_error")["violation_kinds"], {"import_error": 1})
        self.assertIn("test_b", result("u.fail")["first_causal_event"])   # the first causal test is named
        self.assertEqual(result("u.unallowed_skip")["incomplete_reasons"], ["unexpected_skip:1"])
        self.assertIn("no_tests_executed", result("u.no_tests")["incomplete_reasons"])
        # an allowed skip is counted and printed, never silent
        self.assertEqual(result("u.skip_allowed")["counters"]["skipped_allowed"], 1)
        self.assertIn("SKIPPED", res.log("u.skip_allowed"))
        self.assertEqual(res.den["pass"], 2)
        self.assertEqual(res.den["fail"], 8)

    def test_the_module_under_test_never_inherits_the_runners_protocol_environment(self):
        # Found by running the real test_oracles under the runner: its own `replay` test fails if FFW_RESULT_PATH leaks in.
        module = self._module("hermetic")
        res = self.ws.run(self.ws.manifest([self._case("u.hermetic", module)]))
        self.assertEqual(res.rc, 0, res.out + res.err)   # the adapter scrubbed FFW_* before importing the module
        self.assertCase(res, "u.hermetic", "pass", "ok")
        # control: the same module fails when the variables ARE present, so the check above is not vacuous
        proc = subprocess.run([sys.executable, "-B", "-m", "unittest", "t_hermetic"], cwd=self.ws.dir,
                              env=self.ws.env({"FFW_RESULT_PATH": "x", "FFW_SEED": "1"}), capture_output=True,
                              text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, "without the adapter's scrub the module sees FFW_* and fails")

    def test_the_adapter_reports_through_its_exit_code_when_run_by_hand(self):
        def run(kind, *flags):
            return subprocess.run([sys.executable, "-B", UNITTEST_CASE, self._module(kind)] + list(flags),
                                  cwd=self.ws.elsewhere, env=self.ws.env(), capture_output=True, text=True, timeout=60)

        self.assertEqual(run("pass").returncode, 0)
        self.assertEqual(run("fail").returncode, 1)
        self.assertEqual(run("skip").returncode, 2)   # an unallowed skip is incomplete, not a pass
        self.assertEqual(run("skip", "--allow-skip", "Linux-only").returncode, 0)
        self.assertEqual(run("empty").returncode, 2)
        self.assertEqual(run("pass", "--allow-skip", "(").returncode, 2)   # a malformed allowance is refused
        env = self.ws.env({"FFW_RESULT_PATH": self.ws.path("r.json")})   # ids missing: refuse rather than fake a result
        proc = subprocess.run([sys.executable, "-B", UNITTEST_CASE, self._module("pass")], cwd=self.ws.elsewhere,
                              env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("required when FFW_RESULT_PATH is set", proc.stderr)
        self.assertFalse(os.path.exists(self.ws.path("r.json")))


# --------------------------------------------------------------------------- #
# guards the registry depends on
# --------------------------------------------------------------------------- #

class TestOfflineFoundation(Base):
    def test_a_run_in_which_nothing_launched_is_never_a_pass_on_the_runners_own_say_so(self):
        recs = [{"id": "o.%d" % i, "status": "blocked", "reason": "missing_executable", "mandatory": False,
                 "executed": False, "attempts": []} for i in range(2)]
        d = rs.denominators(recs, 0)
        verdict, blocking = rs.compute_verdict(recs, d, [], False, [])   # pure function: no aggregator involved
        self.assertEqual(verdict, "fail")
        self.assertTrue(any(b.startswith("nothing_executed") for b in blocking), blocking)
        # control: the same optional-and-blocked case beside one that really ran is fine
        ok = recs + [{"id": "r", "status": "pass", "reason": "ok", "mandatory": True, "executed": True, "attempts": [{}]}]
        self.assertEqual(rs.compute_verdict(ok, rs.denominators(ok, 0), [], False, [])[0], "pass")
        # and end to end: every case optional and blocked exits non-zero with that reason
        absent = lambda i: {"id": "n.%d" % i, "argv": ["definitely-not-a-real-binary-xyz"], "tiers": ["smoke"],
                            "mandatory": False}   # noqa: E731
        res = self.ws.run(self.ws.manifest([absent(0), absent(1)]))
        self.assertEqual(res.rc, 1, res.out + res.err)
        self.assertEqual((res.den["planned"], res.den["executed"], res.den["blocked"]), (2, 0, 2))
        self.assertTrue(any(b.startswith("nothing_executed") for b in res.report["blocking"]), res.report["blocking"])

    def test_the_foundation_runs_with_no_rust_toolchain_rch_or_hardware_tool_available(self):
        poison = os.path.join(self.ws.tmp.name, "poisoned path")
        os.mkdir(poison)
        sentinel = os.path.join(self.ws.tmp.name, "tool-was-invoked")
        for tool in ("cargo", "rustc", "rustup", "rch", "qemu-system-mips", "qemu-system-ppc", "cross"):
            exe = os.path.join(poison, tool)
            with open(exe, "w") as fh:
                fh.write("#!/bin/sh\necho %s >> '%s'\nexit 99\n" % (tool, sentinel))
            os.chmod(exe, 0o755)
        path = poison + os.pathsep + os.environ.get("PATH", "")
        root = os.path.join(self.ws.tmp.name, "offline root")
        proc = subprocess.run([sys.executable, E2E_Q00, "--tier", "smoke", "--artifact-root", root, "--run-id", "offline"],
                              cwd=self.ws.elsewhere, env=self.ws.env({"PATH": path}), capture_output=True, text=True,
                              timeout=300)
        self.assertFalse(os.path.exists(sentinel), "a build or emulation tool was invoked: " + (
            open(sentinel).read() if os.path.exists(sentinel) else ""))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)   # and the Q00 foundation still passes
        self.assertIn("Q00 ACCEPTANCE: PASS", proc.stdout)
        # control: the poison is real; a case that asks for one of the tools is refused or fails, and trips the sentinel
        res = self.ws.run(self.ws.manifest([{"id": "p.cargo", "argv": ["cargo", "--version"], "tiers": ["smoke"]}]),
                          env={"PATH": path})
        self.assertTrue(os.path.exists(sentinel), "control: the poisoned cargo should have been reached")
        self.assertEqual(res.rc, 1)


# --------------------------------------------------------------------------- #
# in-process unit tests of the pure pieces
# --------------------------------------------------------------------------- #

def mk_case(**over):
    base = dict(id="u.c", suite="u", manifest="/m.suite.json", argv=["x"], cwd="/", tiers=["smoke"], requirements=[],
                timeout_s=5.0, mandatory=True, evidence_class="host-simulation", env={}, env_inherit=[],
                expect_kind="pass", expect_oracle=None, expect_violation=None, expect_exit_codes=[1],
                required_stdout=[], requires_exe=[], requires_env=[], requires_files=[], artifacts=[],
                blocked_reason=None, max_output_bytes=1024, description="")
    base.update(over)
    return rs.Case(**base)


def mk_result(**over):
    base = dict(verdict="pass", oracle="o", oracle_kind="state", independent=True, finalized=True,
                incomplete_reasons=[], violation_kinds={}, checks=3, mismatches=0, expected=None, observed=None,
                first_causal_event=None, counters={})
    base.update(over)
    return base


def mk_facts(**over):
    base = dict(rc=0, kill_reason=None, signal_name=None, leaked=False, result=mk_result(), result_error=None,
                markers_missing=[])
    base.update(over)
    return rs.Facts(**base)


class TestUnits(unittest.TestCase):
    def test_redactor_removes_every_secret_shape_and_keeps_benign_text(self):
        r = rs.Redactor([SECRETS["S_LITERAL"]], scrub_home=True)
        lines = ["api_token=%s" % SECRETS["S_TOKEN"], '{"password": "%s"}' % SECRETS["S_TOKEN"],
                 "Authorization: Bearer %s" % SECRETS["S_BEARER"], "x connect %s y" % SECRETS["S_IP"],
                 "mac %s" % SECRETS["S_MAC"], "mail %s" % SECRETS["S_EMAIL"], "jwt %s" % SECRETS["S_JWT"],
                 "k %s" % SECRETS["S_SK"], "t %s" % SECRETS["S_TSKEY"], "l %s" % SECRETS["S_LITERAL"],
                 "serial_number: SN123456789", "fe80::1c2d:3e4f:5a6b:7c8d"]
        secrets_in = [SECRETS["S_TOKEN"], SECRETS["S_TOKEN"], SECRETS["S_BEARER"], SECRETS["S_IP"],
                      SECRETS["S_MAC"], SECRETS["S_EMAIL"], SECRETS["S_JWT"], SECRETS["S_SK"],
                      SECRETS["S_TSKEY"], SECRETS["S_LITERAL"], "SN123456789", "1c2d:3e4f"]
        for line, secret in zip(lines, secrets_in):
            with self.subTest(line=line[:30]):
                self.assertNotIn(secret, r.redact_line(line))
        for benign in ["loopback 127.0.0.1", "tokens_dropped=3", "serial_port=ttyS0", "doc 203.0.113.9",
                       "ver 1.2.3.400", "std::io::Error at src/main.rs:12:5", "12:34:56 elapsed 0.5s",
                       "checks=3 mismatches=0 token_count=9"]:
            with self.subTest(benign=benign):
                self.assertEqual(r.redact_line(benign), benign)

    def test_redactor_pem_blocks_span_lines_and_end_cleanly(self):
        r = rs.Redactor()
        out = [r.redact_line(l) for l in ["before", "-----BEGIN EC PRIVATE KEY-----", "AAAA", "BBBB",
                                          "-----END EC PRIVATE KEY-----", "after"]]
        self.assertEqual(out, ["before", "[REDACTED-PRIVATE-KEY]", "[REDACTED-PRIVATE-KEY]",
                               "[REDACTED-PRIVATE-KEY]", "[REDACTED-PRIVATE-KEY]", "after"])
        self.assertNotIn("AAAA", r.redact_text("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\nok"))

    def test_classify_precedence_and_canary_identity(self):
        c = mk_case()
        self.assertEqual(rs.classify(c, mk_facts())[:2], ("pass", "ok"))
        # being killed or crashing outranks any receipt the child managed to write first
        self.assertEqual(rs.classify(c, mk_facts(rc=-15, kill_reason="timeout"))[:2], ("fail", "timeout"))
        self.assertEqual(rs.classify(c, mk_facts(rc=-9, signal_name="SIGKILL"))[:2], ("fail", "crashed"))
        # an unfinished oracle outranks the exit code and can never pass
        inc = mk_result(verdict="incomplete", finalized=False, incomplete_reasons=["x"])
        self.assertEqual(rs.classify(c, mk_facts(rc=2, result=inc))[:2], ("fail", "oracle_incomplete"))
        self.assertEqual(rs.classify(c, mk_facts(result=mk_result(finalized=False)))[:2], ("fail", "oracle_incomplete"))
        # a canary needs the exact oracle AND violation kind
        k = mk_case(expect_kind="fail", expect_oracle="o", expect_violation="lost")
        hit = mk_result(verdict="fail", violation_kinds={"lost": 1}, mismatches=1, expected=1, observed=2)
        self.assertEqual(rs.classify(k, mk_facts(rc=1, result=hit))[:2], ("pass", "canary_detected"))
        for label, over, reason in [
            ("other violation", dict(violation_kinds={"dup": 1}), "canary_wrong_violation"),
            ("other oracle", dict(oracle="p"), "canary_wrong_oracle"),
            ("incomplete same oracle", dict(verdict="incomplete", finalized=False, incomplete_reasons=["x"],
                                             mismatches=0, violation_kinds={}), "canary_oracle_incomplete"),
            ("vacuous", dict(checks=0), "vacuous_pass"),
            ("not independent", dict(independent=False), "oracle_not_independent"),
        ]:
            with self.subTest(label):
                self.assertEqual(rs.classify(k, mk_facts(rc=1, result=dict(hit, **over)))[1], reason)
        self.assertEqual(rs.classify(k, mk_facts(rc=0, result=hit))[1], "canary_unexpected_exit")

    def test_read_case_result_enforces_identity_size_and_consistency(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            good = {"schema": rs.RESULT_SCHEMA, "run_id": "R", "case_id": "C", "nonce": "N", "verdict": "pass",
                    "oracle": "o", "oracle_kind": "state", "independent": True, "finalized": True,
                    "incomplete_reasons": [], "violation_kinds": {}, "checks": 2, "mismatches": 0,
                    "expected": None, "observed": None, "first_causal_event": None, "counters": {}}

            def read(doc=None, raw=None):
                with open(path, "w") as fh:
                    fh.write(raw if raw is not None else json.dumps(doc))
                return rs.read_case_result(path, "R", "C", "N", rs.Redactor(), rx.ORACLE_KINDS)

            res, err = read(good)
            self.assertIsNone(err)
            self.assertEqual((res["verdict"], res["checks"]), ("pass", 2))
            self.assertEqual(rs.read_case_result(os.path.join(d, "nope"), "R", "C", "N", rs.Redactor(),
                                                 rx.ORACLE_KINDS)[1], "result_missing")
            for label, over, reason in [("nonce", dict(nonce="X"), "result_stale"), ("run", dict(run_id="X"), "result_stale"),
                                        ("case", dict(case_id="X"), "result_stale"),
                                        ("schema", dict(schema="v0"), "result_invalid"),
                                        ("kind", dict(oracle_kind="log"), "result_invalid"),
                                        ("bool checks", dict(checks=True), "result_invalid"),
                                        ("negative", dict(checks=-1), "result_invalid"),
                                        ("name too long", dict(oracle="x" * 129), "result_invalid")]:
                with self.subTest(label):
                    self.assertEqual(read(dict(good, **over))[1], reason)
            self.assertEqual(read(raw="{not json")[1], "result_invalid")
            self.assertEqual(read(raw="[]")[1], "result_invalid")
            self.assertEqual(read(raw=" " * (rs.MAX_RESULT_BYTES + 5))[1], "result_oversize")

    def test_denominator_invariants_reject_inconsistent_bookkeeping(self):
        recs = [{"id": "a", "status": "pass", "executed": True, "attempts": [{}]},
                {"id": "b", "status": "blocked", "executed": False, "attempts": []}]
        d = rs.denominators(recs, 0)
        rs.check_invariants(recs, d)  # control: consistent records are accepted
        self.assertEqual((d["planned"], d["executed"]), (2, 1))
        with self.assertRaises(rs.InternalError):
            rs.check_invariants(recs, dict(d, executed=2))
        with self.assertRaises(rs.InternalError):
            rs.check_invariants([dict(recs[0], executed=False), recs[1]], rs.denominators(recs, 0))
        with self.assertRaises(rs.InternalError):
            rs.check_invariants([dict(recs[0], status="weird"), recs[1]], d)

    def test_make_event_sink_scales_the_critical_reserve_and_refuses_an_unusable_log(self):
        diag = rs.diagnostics_module()
        with tempfile.TemporaryDirectory() as d:
            sink = rs.make_event_sink(diag, d, "u1", time.monotonic_ns(), 1000, None, [])
            lim = sink.stats()["limits"]
            self.assertEqual(lim["critical_reserve_bytes"], (1000 + 16) * 2048)   # grows with the plan
            self.assertGreaterEqual(lim["max_file_bytes"], lim["critical_reserve_bytes"] + lim["max_event_bytes"])
            sink.close(timeout=2)
            with self.assertRaises(rs.UsageError) as cm:
                rs.make_event_sink(diag, d, "u2", time.monotonic_ns(), 1000, 4096, [])
            self.assertIn("need at least", str(cm.exception))
        # The log is created O_EXCL: an existing file is never overwritten.  The collision shows up as an unusable
        # (incomplete) log when the sink is closed, not as silent data loss in the old file.
        with tempfile.TemporaryDirectory() as d2:
            precious = os.path.join(d2, "events.jsonl")
            with open(precious, "w") as fh:
                fh.write("PRECIOUS\n")
            clash = rs.make_event_sink(diag, d2, "u3", time.monotonic_ns(), 1, None, [])
            clash.emit_event("x", critical=True)
            self.assertFalse(clash.close(timeout=2).complete)
            with open(precious) as fh:
                self.assertEqual(fh.read(), "PRECIOUS\n")

    def test_capture_bounds_lines_counts_every_line_and_annotates_after_the_cap(self):
        with tempfile.TemporaryDirectory() as d:
            r, w = os.pipe()
            log = os.path.join(d, "c.log")
            cap = rs.Capture(r, log, 2048, rs.Redactor(), [r"needle \d+"])
            cap.start()
            os.write(w, b"A" * (rs.MAX_LINE_BYTES + 500) + b"\nsecond\n")
            for i in range(200):
                os.write(w, ("line %03d %s\n" % (i, "x" * 90)).encode())
            os.write(w, b"needle 42\nno newline")
            os.close(w)
            cap.join(10)
            os.close(r)
            self.assertFalse(cap.is_alive())
            st = cap.stats()
            self.assertEqual(st["lines"], 204)  # 1 overlong + "second" + 200 + "needle 42" + the unterminated tail
            self.assertEqual(st["overlong_lines"], 1)
            self.assertTrue(st["truncated"])
            self.assertTrue(cap.marker_hit[0], "markers are matched on the stream, not on what survived the cap")
            self.assertEqual(st["events"] - 1 + st["dropped_events"], st["lines"])  # the -1 is the truncation marker
            self.assertLessEqual(os.path.getsize(log), 2048 + 256)
            seq = cap.annotate("[run-suite] verdict line")
            self.assertEqual(seq, st["events"] + st["dropped_events"])
            with open(log) as fh:
                self.assertEqual(fh.read().splitlines()[-1], "[run-suite] verdict line")


# --------------------------------------------------------------------------- #
# the independent aggregator catches defects planted in the RUNNER itself
# --------------------------------------------------------------------------- #

class TestCrossCheckCatchesRunnerBugs(Base):
    def _in_process(self, manifest, run_id):
        argv = ["run", "--tier", "smoke", "--manifest", manifest, "--artifact-root", self.ws.artifacts,
                "--run-id", run_id, "--kill-grace-s", "0.3"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = rs.main(argv)
        return rc, out.getvalue(), err.getvalue(), os.path.join(self.ws.artifacts, run_id)

    def test_control_the_unpatched_runner_agrees_with_the_aggregator(self):
        m = self.ws.manifest([case("x.ok", "pass"), case("x.bad", "always_fail")])
        rc, out, err, _ = self._in_process(m, "ctl")
        self.assertEqual(rc, 1, out + err)  # an honest failure, not an internal error

    def test_a_runner_that_lies_about_its_own_predictions_is_exit_5(self):
        m = self.ws.manifest([case("x.ok", "pass"), case("x.bad", "always_fail")])
        with mock.patch.object(rs, "predicted_verdict", lambda base: "pass"):
            rc, out, err, run_dir = self._in_process(m, "lie")
        self.assertEqual(rc, rs.EXIT_INTERNAL, out + err)
        self.assertIn("disagreement", out + err)
        self.assertIn("VERDICT: INTERNAL_ERROR", out)
        self.assertNotIn("VERDICT: PASS", out)

    def test_a_runner_that_writes_a_failure_as_a_pass_is_caught_by_the_aggregator(self):
        m = self.ws.manifest([case("x.ok", "pass"), case("x.bad", "always_fail")])
        with mock.patch.object(rs, "attempt_outcome", lambda rec: "pass"):
            rc, out, err, run_dir = self._in_process(m, "mislabel")
        self.assertEqual(rc, rs.EXIT_INTERNAL, out + err)
        summary = rx.aggregate_path(os.path.join(run_dir, "receipts.jsonl"),
                                    self.ws.expected_for([case("x.ok", "pass"), case("x.bad", "always_fail")]))
        self.assertEqual(summary["cases"]["x.bad"]["verdict"], "invalid")  # the strict validator, not the runner
        self.assertEqual(summary["cases"]["x.ok"]["verdict"], "pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
