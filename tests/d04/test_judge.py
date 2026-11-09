#!/usr/bin/env python3
"""Self-test of the D04 central-log judge (`--judge`, case D04-RUST-CENTRAL in tests/d04/run_cases.py).

The fabricated logs here are SYNTHETIC: they have the form of a real cargo log (worker id and pool hash invented) and prove that
the judge passes a complete log and sees each kind of bad one. They say nothing about the Rust, which this runner never builds.
The two committed central logs under toolchain/results are REAL bytes and pin what the synthetic ones assume: the binary stem
`franken_speaker`, the `render::tests::` and `render_log::tests::` name prefixes, and both log layouts (plain, and RCH's split
stderr/stdout).

    python3 -B -I -m unittest discover -s tests/d04 -p 'test_judge.py'
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("d04_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = _load("run_cases")
REAL_LOGS = (
    "toolchain/results/n04/20261107-acb7a3d/host-tests.log",   # RCH layout: stdout sections first, stderr headers after
    "toolchain/results/n03/media-path-20261106/tests.txt",      # plain layout: each header followed by its section
)
# The exact-source RED and GREEN central logs committed with the mute-ordering repair (sanitized: no addresses, no host paths). Their
# verdicts below are derived from what the logs contain, so they stay true when a later change adds a test to the registry.
D04_LOGS = {
    "green": "toolchain/results/d04/20261109-mute-ordering/green-speaker.txt",  # the whole package, RCH layout
    "red": "toolchain/results/d04/20261109-mute-ordering/red-render.txt",       # `render::` only, two tests FAILED
}
HEADER = "     Running unittests src/lib.rs (.rch-target-w0-pool-0123456789abcdef/debug/deps/%s-0123456789abcdef)"
PANIC = "assertion `left == right` failed: the loop did not stay Running"


def required():
    return [name for _, name in rc.cargo_names()]


def _section(lines, passed, failed_names=()):
    body = ["", "running %d test%s" % (len(lines), "" if len(lines) == 1 else "s")] + list(lines)
    if failed_names:
        body += ["", "failures:", ""]
        for name in failed_names:
            body += ["---- %s stdout ----" % name,
                     "thread '%s' panicked at crates/franken-speaker/src/render.rs:1234:9:" % name, PANIC, ""]
        body += ["failures:"] + ["    " + name for name in failed_names]
    verdict = "FAILED" if failed_names else "ok"
    body += ["", "test result: %s. %d passed; %d failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s"
             % (verdict, passed, len(failed_names))]
    return body


def build_log(skip=(), failed=(), ignored=(), rename=None, stem="franken_speaker", layout="classic", noise=(),
              noise_failed=(), headers=True, cut_before=None, extra_headerless=()):
    """A cargo test log: a franken_hal section (so attribution is not accidental), then the `stem` section holding every
    required name except `skip`, with `failed` / `ignored` ones marked, `rename` applied, `noise` names added (tests that are
    not D04's; those in `noise_failed` FAILED). `layout` "rch" puts every stdout section before the stderr headers. `cut_before`
    drops the log from that test's line on (a truncated log). `extra_headerless` are more sections without a header."""
    rename = rename or {}
    hal = ["test session::tests::a_one ... ok", "test session::tests::a_two ... ok"]
    lines = []
    bad = [rename.get(n, n) for n in failed]
    for name in [rename.get(n, n) for n in required() if n not in skip] + list(noise):
        status = "FAILED" if (name in bad or name in noise_failed) else "ignored" if name in ignored else "ok"
        lines.append("test %s ... %s" % (name, status))
    if cut_before is not None:
        target = "test %s ... " % cut_before
        lines = lines[:next(i for i, l in enumerate(lines) if l.startswith(target))]
    passed = sum(1 for l in lines if l.endswith("... ok"))
    failing = [l.split()[1] for l in lines if l.endswith("... FAILED")]
    sections = [(HEADER % "franken_hal", _section(hal, 2)), (HEADER % stem, _section(lines, passed, failing))]
    for names in extra_headerless:
        sections.append((None, _section(["test %s ... ok" % n for n in names], len(names))))
    out = ["   Compiling franken-speaker v0.1.0", "    Finished `test` profile"]
    if not headers:
        sections = [(None, body) for _, body in sections]
    if layout == "classic":
        for header, body in sections:
            out += ([header] if header else []) + body
    else:
        for _, body in sections:
            out += body
        out += [h for h, _ in sections if h]
    if cut_before is not None:
        out = [l for l in out if not l.startswith("test result:")]
    return "\n".join(out) + "\n"


def parse(*texts):
    """The parsed logs, each text a separate file (the temp dir goes away; the parser has read the bytes by then)."""
    with tempfile.TemporaryDirectory() as d:
        logs = rc.load_logs([_write(d, i, t) for i, t in enumerate(texts)])
    return logs


def _write(directory, i, text):
    path = os.path.join(directory, "cargo%d.log" % i)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def judge(*texts):
    status, detail = rc.judge_rust(parse(*texts))
    return status, detail


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def run_main(argv):
    """(exit code, stdout, stderr) of the runner's main."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rc.main(argv)
    return code, out.getvalue(), err.getvalue()


def summary(stdout):
    m = re.search(r"(\d+) case\(s\): (\d+) passed, (\d+) failed, (\d+) blocked -- (.*)", stdout)
    return tuple(int(m.group(i)) for i in (1, 2, 3, 4)) + (m.group(5),)


def case_line(stdout, case_id):
    return next(l for l in stdout.splitlines() if l.split()[1:2] == [case_id])


class JudgeSelfTest(unittest.TestCase):
    def test_a_complete_log_passes_in_both_layouts_and_says_what_it_did_not_judge(self):
        """D04-JUDGE-GOOD: every required name ok qualifies the case, plain or RCH-split, and the pass names its limit."""
        for layout in ("classic", "rch"):
            status, detail = judge(build_log(layout=layout))
            self.assertEqual(status, rc.PASS, (layout, detail))
            self.assertIn("all %d required Rust tests ok" % len(required()), detail)
            self.assertIn("tests only", detail)
            self.assertIn("clippy", detail)

    def test_each_plant_is_seen_and_the_control_is_green(self):
        """D04-JUDGE-PLANTS: a missing, ignored or failed test, tests in another binary, tests outside `mod tests`, an old
        registry and a truncated log are each not a pass, with the right class of verdict. The control is the same log
        without the plant."""
        names = required()
        newest = names[-4:]
        plants = [
            ("missing", dict(skip={names[3]}), rc.BLOCKED, names[3]),
            ("ignored", dict(ignored={names[5]}), rc.BLOCKED, names[5]),
            ("failed", dict(failed={names[7]}), rc.FAIL, names[7]),
            ("another binary", dict(stem="franken_hal"), rc.BLOCKED, names[0]),
            ("outside mod tests", dict(rename={n: n.replace("::tests::", "::") for n in names}), rc.BLOCKED, names[0]),
            ("old registry", dict(skip=set(newest)), rc.BLOCKED, newest[0]),
            ("truncated", dict(cut_before=names[-1]), rc.BLOCKED, names[-1]),
        ]
        for layout in ("classic", "rch"):
            self.assertEqual(judge(build_log(layout=layout))[0], rc.PASS, "control, " + layout)
            for label, kwargs, want, mentioned in plants:
                status, detail = judge(build_log(layout=layout, **kwargs))
                self.assertEqual(status, want, (layout, label, detail))
                self.assertIn(mentioned, detail, (layout, label))

    def test_a_failed_test_carries_its_first_causal_event(self):
        """D04-JUDGE-CAUSE: a FAILED test is reported with cargo's panic location and message, not just its name."""
        name = required()[2]
        status, detail = judge(build_log(failed={name}))
        self.assertEqual(status, rc.FAIL)
        self.assertIn("first causal event", detail)
        self.assertIn("panicked at", detail)
        self.assertIn(PANIC, detail)

    def test_a_failure_outranks_a_missing_test(self):
        """D04-JUDGE-FAIL-OUTRANKS: one FAILED and one missing is a FAIL that still counts the missing one."""
        names = required()
        status, detail = judge(build_log(failed={names[1]}, skip={names[2]}))
        self.assertEqual(status, rc.FAIL)
        self.assertIn("1 of %d required Rust test(s) FAILED" % len(names), detail)
        self.assertIn("1 more not shown ok", detail)

    def test_two_logs_that_disagree_fail_and_two_that_agree_do_not(self):
        """D04-JUDGE-CONFLICT: ok in one log and FAILED in another is a FAIL; the same log twice is read once."""
        name = required()[4]
        good, bad = build_log(), build_log(failed={name})
        status, detail = judge(good, bad)
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("CONFLICT", detail)
        logs = parse(good, good)
        self.assertEqual(len(logs.files), 1)
        self.assertEqual(rc.judge_rust(logs)[0], rc.PASS)

    def test_a_log_that_cannot_say_which_binary_ran_a_test_does_not_pass_a_duplicate(self):
        """D04-JUDGE-AMBIGUOUS: with no Running headers a name seen in two sections is ambiguous and stays BLOCKED; the same
        names once each are matched by exact name and the pass says the pairing was missing."""
        first = required()[0]
        status, detail = judge(build_log(headers=False, extra_headerless=[[first]]))
        self.assertEqual(status, rc.BLOCKED, detail)
        self.assertIn("cannot say which binary", detail)
        status, detail = judge(build_log(headers=False))
        self.assertEqual(status, rc.PASS, detail)
        self.assertIn("no Running-header pairing", detail)

    def test_other_failures_in_the_binary_are_noted_not_judged(self):
        """D04-JUDGE-OTHERS: a test that is not D04's failing does not fail D04's case, but the pass says it happened."""
        status, detail = judge(build_log(noise=["harness::tests::not_d04"], noise_failed={"harness::tests::not_d04"}))
        self.assertEqual(status, rc.PASS, detail)
        self.assertIn("1 other test(s) FAILED in the log, not D04's", detail)

    def test_an_empty_registry_is_not_a_vacuous_pass(self):
        """D04-JUDGE-NONEMPTY: with no #[test] found there is nothing to judge, which is a FAIL and not a pass."""
        real = rc.all_rust_tests
        rc.all_rust_tests = lambda: []
        try:
            status, detail = judge(build_log())
        finally:
            rc.all_rust_tests = real
        self.assertEqual(status, rc.FAIL)
        self.assertIn("nothing to judge", detail)
        self.assertEqual(judge(build_log())[0], rc.PASS)


class RealLogs(unittest.TestCase):
    """The assumptions the synthetic logs make, held against the real central logs committed in toolchain/results."""

    def test_real_logs_read_ok_by_the_names_the_registry_uses_and_are_never_a_pass(self):
        """D04-JUDGE-REAL: in both real logs every required name that a plain regex finds as `... ok` reads ok through the
        parser under the franken_speaker stem (in the RCH-split layout too), and the verdict is BLOCKED naming exactly the
        required names the regex did not find: those logs predate the newest tests, so a pass would be a false one."""
        names = set(required())
        for rel in REAL_LOGS:
            path = os.path.join(rc.REPO, rel)
            self.assertTrue(os.path.isfile(path), "the real control log is missing: " + rel)
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            found = {m.group(1) for m in re.finditer(r"^test ((?:render|render_log)::tests::\S+) \.\.\. ok\s*$", text, re.M)} & names
            self.assertGreaterEqual(len(found), 40, "the control would be vacuous: " + rel)
            logs = rc.load_logs([path])
            for name in sorted(found):
                self.assertEqual(logs.test_status(rc.LIB_STEM, name), "ok", (rel, name))
            status, detail = rc.judge_rust(logs)
            self.assertEqual(status, rc.BLOCKED, (rel, detail))
            absent = names - found
            self.assertIn("%d of %d required Rust test(s) not shown ok" % (len(absent), len(names)), detail, rel)
            # The verdict lists the first MAX_SHOWN missing names in registry order, which is not sorted order, so the check is on the
            # set: how many are shown, and that every one shown really is absent from the log.
            shown = re.findall(r"((?:render|render_log)::tests::\w+): not reported", detail)
            self.assertEqual(len(shown), min(len(absent), rc.MAX_SHOWN), rel)
            self.assertTrue(set(shown) <= absent, rel)

    def test_a_real_log_plus_the_missing_names_is_a_pass_and_without_one_is_not(self):
        """D04-JUDGE-REAL-COMPLETED: the real n03 log completed with the names it lacks, as a second log, passes; leaving one of
        them out does not. This is the real bytes' attribution carrying a verdict, not only a lookup."""
        path = os.path.join(rc.REPO, REAL_LOGS[1])
        base = rc.load_logs([path])
        lacking = [n for n in required() if base.test_status(rc.LIB_STEM, n) != "ok"]
        self.assertTrue(lacking, "the real log already holds every name; the control is vacuous")
        with tempfile.TemporaryDirectory() as d:
            whole = _write(d, 0, build_log(skip=set(n for n in required() if n not in lacking)))
            partial = _write(d, 1, build_log(skip=set(n for n in required() if n not in lacking[1:])))
            self.assertEqual(rc.judge_rust(rc.load_logs([path, whole]))[0], rc.PASS)
            status, detail = rc.judge_rust(rc.load_logs([path, partial]))
            self.assertEqual(status, rc.BLOCKED)
            self.assertIn(lacking[0], detail)


class CommittedD04Logs(unittest.TestCase):
    """The committed exact-source central logs of the render loop, judged by what they hold."""

    def _real(self, key):
        path = os.path.join(rc.REPO, D04_LOGS[key])
        self.assertTrue(os.path.isfile(path), "the real control log is missing: " + D04_LOGS[key])
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    def _judge_text(self, text, completion=None):
        with tempfile.TemporaryDirectory() as d:
            paths = [_write(d, 0, text)] + ([_write(d, 1, completion)] if completion else [])
            return rc.judge_rust(rc.load_logs(paths))

    def test_the_green_whole_package_log_passes_once_complete_and_a_planted_change_to_its_own_bytes_is_seen(self):
        """D04-JUDGE-REAL-GREEN: the real green log, completed with any names it predates, passes (the control). The same real
        bytes with one result line dropped are BLOCKED naming it, and with one made FAILED are a FAIL naming it."""
        text = self._real("green")
        names = required()
        held = [n for n in names if re.search(r"^test %s \.\.\. ok\s*$" % re.escape(n), text, re.M)]
        self.assertGreaterEqual(len(held), 50, "the control would be vacuous")
        lacking = [n for n in names if n not in held]
        completion = build_log(skip=set(held)) if lacking else None  # the names this log predates, as a second log
        status, detail = self._judge_text(text, completion)
        self.assertEqual(status, rc.PASS, detail)
        victim = held[len(held) // 2]
        line = re.compile(r"^(test %s \.\.\. )ok(\s*)$" % re.escape(victim), re.M)
        status, detail = self._judge_text(line.sub("", text, count=1), completion)
        self.assertEqual(status, rc.BLOCKED, detail)
        self.assertIn(victim, detail)
        status, detail = self._judge_text(line.sub(r"\1FAILED\2", text, count=1), completion)
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn(victim, detail)

    def test_the_red_render_log_fails_on_exactly_the_tests_it_shows_failed(self):
        """D04-JUDGE-REAL-RED: the real red log is a FAIL naming each test it shows FAILED, with cargo's panic line as the first
        causal event. The control is the same bytes with those results made ok: the log holds only `render::`, so that is BLOCKED,
        never FAIL and never a pass."""
        text = self._real("red")
        names = required()
        failed = [n for n in names if re.search(r"^test %s \.\.\. FAILED\s*$" % re.escape(n), text, re.M)]
        self.assertTrue(failed, "the control would be vacuous")
        status, detail = self._judge_text(text)
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("%d of %d required Rust test(s) FAILED" % (len(failed), len(names)), detail)
        for name in failed:
            self.assertIn(name, detail)
        self.assertIn("first causal event", detail)
        self.assertIn("panicked at", detail)
        healed = re.sub(r"^(test (?:render|render_log)::tests::\S+ \.\.\. )FAILED(\s*)$", r"\1ok\2", text, flags=re.M)
        status, detail = self._judge_text(healed)
        self.assertEqual(status, rc.BLOCKED, detail)


class RegistryIsWhole(unittest.TestCase):
    def test_the_judge_requires_every_test_of_both_files(self):
        """D04-JUDGE-REGISTRY: the names the judge requires are exactly every #[test] of render.rs and render_log.rs, counted here from
        the `#[test]` lines and the `fn` under each, and not through all_rust_tests(). Without this, a registry that dropped one file's
        tests would still pass every log that holds the other's: with render_log's 16 dropped, the `render::`-only log reads as complete,
        and only a size floor in another test noticed, which stops working once render.rs holds enough tests."""
        expected = {}
        for rel, module in (("crates/franken-speaker/src/render.rs", "render"), ("crates/franken-speaker/src/render_log.rs", "render_log")):
            with open(os.path.join(rc.REPO, rel), encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            found = set()
            for i, line in enumerate(lines):
                if line.strip() == "#[test]":
                    after = next(l for l in lines[i + 1:] if l.strip() and not l.strip().startswith(("#[", "//")))
                    found.add("%s::tests::%s" % (module, re.match(r"\s*fn (\w+)", after).group(1)))
            self.assertTrue(found, "the control would be vacuous: no #[test] found in " + rel)
            expected[module] = found
        required = {name for _, name in rc.cargo_names()}
        self.assertEqual(required, expected["render"] | expected["render_log"])
        self.assertEqual({n for n in required if n.startswith("render_log::")}, expected["render_log"])
        self.assertEqual(len(rc.cargo_names()), len(required), "a required name is listed twice")


class RunnerSurface(unittest.TestCase):
    def test_the_case_is_central_rust_and_the_other_blocked_cases_are_unchanged(self):
        """D04-JUDGE-CASES: only D04-RUST-CENTRAL changed kind; the board, process-death and P03 cases stay blocked."""
        kinds = {c["id"]: c["kind"] for c in rc.all_cases()}
        self.assertEqual(kinds[rc.RUST_CENTRAL], "central_rust")
        self.assertIn("central_rust", rc.KINDS)
        self.assertEqual({k for k, v in kinds.items() if v == "blocked"}, {"D04-EXT-BOARD", "D04-EXT-PROCDEATH", "D04-OPEN-P03"})
        text = next(c for c in rc.all_cases() if c["id"] == rc.RUST_CENTRAL)["needs"]
        self.assertIn("tests only", text)

    def test_the_full_tier_without_and_with_a_log(self):
        """D04-JUDGE-TIER: no log: the case is blocked and the run exits 3. A good log: the case passes, the run is still NOT
        QUALIFIED (three cases stay blocked) and exits 3. A bad log: exit 1."""
        code, out, _ = run_main(["--tier", "full"])
        planned, passed, failed, blocked, verdict = summary(out)
        self.assertEqual((code, failed, verdict), (3, 0, "NOT QUALIFIED"))
        self.assertTrue(case_line(out, rc.RUST_CENTRAL).startswith("BLOCKED"))
        self.assertIn("No log was supplied", case_line(out, rc.RUST_CENTRAL))
        with tempfile.TemporaryDirectory() as d:
            green = _write(d, 0, build_log())
            red = _write(d, 1, build_log(failed={required()[0]}))
            code2, out2, _ = run_main(["--tier", "full", "--judge", green])
            self.assertEqual(summary(out2), (planned, passed + 1, 0, blocked - 1, "NOT QUALIFIED"))
            self.assertEqual(code2, 3)
            self.assertTrue(case_line(out2, rc.RUST_CENTRAL).startswith("PASS"))
            self.assertIn("tests only", case_line(out2, rc.RUST_CENTRAL))
            code3, out3, _ = run_main(["--tier", "full", "--judge", red])
            self.assertEqual(code3, 1)
            self.assertEqual(summary(out3)[2], 1)
            self.assertTrue(case_line(out3, rc.RUST_CENTRAL).startswith("FAIL"))

    def test_one_selected_case_is_never_reported_as_qualified(self):
        """D04-JUDGE-ONE-CASE: a lone passing case printed QUALIFIED before; with the judge it would read as the run's
        verdict. It now says it is one case, and the receipt records qualified false."""
        with tempfile.TemporaryDirectory() as d:
            green = _write(d, 0, build_log())
            code, out, _ = run_main(["--tier", "full", "--case", rc.RUST_CENTRAL, "--judge", green, "--receipts", d])
            self.assertEqual(code, 0)
            self.assertNotIn("QUALIFIED (host", out)
            self.assertEqual(summary(out)[4], "ONE CASE SELECTED, NOT A QUALIFICATION")
            with open(os.path.join(d, "d04-full.json"), encoding="utf-8") as handle:
                self.assertIs(json.load(handle)["qualified"], False)
        code, out, _ = run_main(["--tier", "full", "--case", "D04-TIM-002"])
        self.assertEqual((code, summary(out)[4]), (0, "ONE CASE SELECTED, NOT A QUALIFICATION"))

    def test_smoke_still_qualifies_and_a_log_that_is_not_used_says_so(self):
        """D04-JUDGE-SMOKE: the smoke tier does not hold the central case, still qualifies and retains nothing; a log given to
        it is reported as unused, never silently ignored."""
        code, out, _ = run_main(["--tier", "smoke"])
        self.assertEqual((code, summary(out)[4]), (0, "QUALIFIED (host simulation only)"))
        self.assertNotIn("replay:", out)
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = run_main(["--tier", "smoke", "--judge", _write(d, 0, build_log())])
        self.assertEqual(code, 0)
        self.assertIn("the log was not used", out)

    def test_a_missing_log_is_a_usage_error(self):
        """D04-JUDGE-USAGE: a log path that does not exist exits 2 with the path named, and judges nothing."""
        code, out, err = run_main(["--tier", "full", "--judge", "/no/such/cargo.log"])
        self.assertEqual(code, 2)
        self.assertIn("/no/such/cargo.log", err)
        self.assertNotIn("PASS", out)

    def test_a_non_pass_retains_the_replay_command_and_the_digests_of_what_it_judged(self):
        """D04-JUDGE-RETAIN: a run that is not a pass prints how to replay it and the sha256 of the log and of the sources
        judged; the receipt carries the same and says what the judge covered."""
        with tempfile.TemporaryDirectory() as d:
            log = _write(d, 0, build_log(skip={required()[0]}))
            digest = sha(log)
            out_dir = os.path.join(d, "receipts")
            code, out, _ = run_main(["--tier", "full", "--judge", log, "--receipts", out_dir])
            self.assertEqual(code, 3)
            self.assertIn("replay: scripts/e2e/d04 --tier full --judge " + log, out)
            self.assertIn("judged log sha256 %s  cargo0.log" % digest, out)
            render = sha(os.path.join(rc.REPO, "crates/franken-speaker/src/render.rs"))
            self.assertIn("artifact sha256 %s  crates/franken-speaker/src/render.rs" % render, out)
            with open(os.path.join(out_dir, "d04-full.json"), encoding="utf-8") as handle:
                receipt = json.load(handle)
            self.assertEqual(receipt["kind"], "host_check_and_central_rust_log_judged")
            self.assertEqual(receipt["judged_logs"], [{"name": "cargo0.log", "sha256": digest}])
            self.assertEqual(receipt["artifacts"]["crates/franken-speaker/src/render.rs"], render)
            self.assertIn("tests only", receipt["judged_scope"])
            self.assertFalse(receipt["qualified"])
            self.assertEqual({c["id"]: c["status"] for c in receipt["cases"]}[rc.RUST_CENTRAL], rc.BLOCKED)
            code, _, _ = run_main(["--tier", "full", "--receipts", out_dir])
            with open(os.path.join(out_dir, "d04-full.json"), encoding="utf-8") as handle:
                plain = json.load(handle)
            self.assertEqual((plain["kind"], plain["judged_logs"], plain["judged_scope"]), ("host_check_only_rust_not_run", [], None))


if __name__ == "__main__":
    unittest.main()
