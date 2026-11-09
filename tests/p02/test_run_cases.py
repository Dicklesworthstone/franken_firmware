"""Tests of the P02 tiered runner and its diagnostic receipt (tests/p02/run_cases.py, case_log.py; bead ffw-jub, the "owned test assets" and "Logging" clauses).

The cargo logs judged here are SYNTHETIC, built in memory from the test names the sources define and written only to temporary directories. They show
that the runner passes what it should and refuses what it should; they say nothing about the Rust. The Python subprocess is replaced by a scripted runner
so the suite stays fast and cannot recurse into itself (the runner's Python case excludes this file for the same reason); the entry point is run for
real in the last class. Every refusal is planted against the clean log of the same run set (a control that passes), and the sweep plants each of P02's
own tests as missing, failed and ignored in turn.
"""
import contextlib
import glob
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import case_log  # noqa: E402
import run_cases as rc  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "p02")
PLAN, GROUPS = rc.case_plan()
EVERY = [n for g in ("platform", "linux", "speaker") for n in GROUPS[g]]
RUST_IDS = [i for i, _d, _n in PLAN]
ALL_IDS = ["P02-META-MAP", "P02-REF-PYTHON"] + RUST_IDS
NOISE = ("[RCH] Selected worker: example-worker (slots remaining 1)\n"
         "test other_crate::tests::something_unrelated ... ok\n"
         "test other_crate::tests::a_soak_that_is_ignored_on_purpose ... ignored\n")

# These modules have tests but belong to P06 (net/durable) or N07 (datagram routing), not P02.
EXCLUDED_PLATFORM_TEST_MODULES = frozenset({
    "crates/franken-platform/src/net.rs",
    "crates/franken-platform/src/durable.rs",
    "crates/franken-platform/src/datagram.rs",
    "crates/franken-platform-linux/src/datagram_route.rs",
})


def platform_test_modules():
    """Actual test-bearing platform source files, independent of the runner's module list."""
    modules = set()
    for path in glob.glob(os.path.join(REPO, "crates", "franken-platform*", "src", "*.rs")):
        with open(path, encoding="utf-8") as handle:
            if rc.test_functions(handle.read()):
                modules.add(os.path.relpath(path, REPO).replace(os.sep, "/"))
    return modules


def uncovered_platform_test_modules(groups):
    grouped = {rel for files in groups.values() for rel in files}
    return platform_test_modules() - grouped - EXCLUDED_PLATFORM_TEST_MODULES


def good_log(skip=(), failed=(), ignored=(), unfinished=(), panics=None, summary=True, noise=NOISE):
    """What a green central run prints for P02's own tests: every name ok, noise from other crates, a `test result:` line at the end."""
    lines = ["running %d tests" % len(EVERY)]
    for name in EVERY:
        if name in skip:
            continue
        if name in unfinished:
            lines.append("test %s ... " % name)
            continue
        lines.append("test %s ... %s" % (name, "FAILED" if name in failed else "ignored" if name in ignored else "ok"))
    text = "\n".join(lines) + "\n" + noise
    for name, message in (panics or {}).items():
        text += "thread '%s' panicked at crates/x/src/y.rs:1:2:\n%s\n" % (name, message)
    if summary:
        text += "\ntest result: ok. %d passed; 0 failed; 1 ignored\n" % len(EVERY)
    return text


def logs_of(*texts):
    logs = rc.Logs()
    for text in texts:
        logs.add_text(text)
    return logs


def scripted(code=0, unit="Ran 137 tests in 0.2s\n\nOK\n"):
    calls = []

    def runner(argv, cwd, timeout):
        calls.append(argv)
        return code, unit
    runner.calls = calls
    return runner


def outcome(results):
    return {r.case_id: r.status for r in results}


def judged(log, **kw):
    results, _ = rc.run("full", log, scripted(**kw))
    return results


class Plan(unittest.TestCase):
    def test_every_test_bearing_platform_module_is_judged_or_explicitly_excluded(self):
        modules = platform_test_modules()
        self.assertTrue(modules)
        self.assertTrue(EXCLUDED_PLATFORM_TEST_MODULES <= modules, "an exclusion names no actual test-bearing module")
        grouped = {rel for files in rc.GROUPS.values() for rel in files}
        self.assertFalse(grouped & EXCLUDED_PLATFORM_TEST_MODULES, "a judged module is also excluded")
        self.assertEqual(uncovered_platform_test_modules(rc.GROUPS), set())

    def test_removing_either_wait_module_is_rejected_by_the_source_coverage_check(self):
        self.assertEqual(uncovered_platform_test_modules(rc.GROUPS), set())  # permitted control
        for group, module in (("platform", "crates/franken-platform/src/wait.rs"),
                              ("linux", "crates/franken-platform-linux/src/wait_route.rs")):
            with self.subTest(module=module):
                self.assertIn(module, rc.GROUPS[group])
                groups = {name: list(files) for name, files in rc.GROUPS.items()}
                groups[group].remove(module)
                self.assertEqual(uncovered_platform_test_modules(groups), {module})

    def test_the_clause_map_is_whole_on_this_tree_and_names_the_beads_criteria(self):
        result = rc.meta_map(PLAN, GROUPS)
        self.assertEqual((result.status, result.detail), ("passed", ""))
        for needed in ("P02-AC-ENTROPY", "P02-AC-NO-FAKE-SUCCESS", "P02-AC-ABSENT", "P02-AC-EINTR", "P02-AC-ACCEPT-FCNTL", "P02-AC-WALL-TIME"):
            self.assertIn(needed, RUST_IDS)
        floor = dict((i, n) for i, _d, n in PLAN)[rc.ALL_CASE[0]]
        self.assertEqual(sorted(floor), sorted(EVERY))
        self.assertTrue(floor)
        for case_id, _d, names in PLAN:
            self.assertTrue(set(names) <= set(floor), case_id)

    def test_each_planted_flaw_of_the_map_is_refused_for_its_own_reason(self):
        def planted(mutate, workspace=None, repo=REPO):
            plan = [(i, d, list(n)) for i, d, n in PLAN]
            mutate(plan)
            return rc.meta_map(plan, GROUPS, repo, workspace)

        self.assertEqual(planted(lambda p: None).status, "passed")                                           # control
        gone = planted(lambda p: p[0][2].append("entropy::tests::a_test_that_does_not_exist"))
        self.assertEqual(gone.status, "failed")
        self.assertIn("not in P02's files", gone.detail)
        twice = planted(lambda p: p[0][2].append(p[0][2][0]))
        self.assertIn("twice", twice.detail)
        empty = planted(lambda p: p[1][2].clear())
        self.assertIn("names no test", empty.detail)
        missing_case = planted(lambda p: p.pop(0))
        self.assertIn("P02-AC-ENTROPY has no case", missing_case.detail)
        clash = dict(rc.workspace_definitions())
        victim = EVERY[0]
        clash[victim] = clash[victim] + ["crates/other/src/lib.rs"]
        ambiguous = planted(lambda p: None, workspace=clash)
        self.assertEqual(ambiguous.status, "failed")
        self.assertIn("more than one file of the workspace", ambiguous.detail)
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            os.makedirs(os.path.join(tmp, "docs", "contracts"))
            with open(os.path.join(tmp, "docs", "contracts", "p02.md"), "w", encoding="utf-8") as handle:
                handle.write("## Something else\n")
            undocumented = planted(lambda p: None, repo=tmp)
            self.assertIn("has no section 'Accept and fcntl: concurrency implications'", undocumented.detail)
            with open(os.path.join(tmp, "docs", "contracts", "p02.md"), "w", encoding="utf-8") as handle:
                handle.write('## Accept and fcntl: concurrency implications (the rules; their policy is below)\n')
            self.assertEqual(planted(lambda p: None, repo=tmp).status, "passed")                              # control: a longer heading is the heading

    def test_the_tiers_plan_what_they_say_and_soak_plans_nothing(self):
        self.assertEqual(rc.planned_ids("smoke"), ["P02-META-MAP", "P02-REF-PYTHON"])
        self.assertEqual(rc.planned_ids("full"), ALL_IDS)
        self.assertEqual(sorted(rc.descriptions()), sorted(ALL_IDS))
        with self.assertRaises(ValueError):
            rc.run("soak", None)
        self.assertEqual(rc.SOAK_EXIT, 4)

    def test_the_python_case_never_runs_the_runner_s_own_tests_and_runs_every_other_module(self):
        runner = scripted()
        rc.run("smoke", None, runner)
        (argv,) = runner.calls
        self.assertEqual(argv[1:4], ["-B", "-m", "unittest"])
        modules = argv[4:]
        self.assertNotIn("test_run_cases", modules)
        on_disk = sorted(f[:-3] for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py") and f != "test_run_cases.py")
        self.assertEqual(modules, on_disk)
        self.assertTrue(modules)

    def test_the_rust_names_are_the_ones_cargo_prints_for_nested_and_root_modules(self):
        text = "#[test]\nfn at_root() {}\nmod tests {\n    #[test]\n    fn inside() {}\n    mod deeper {\n        #[test]\n        fn deepest() {}\n    }\n}\n"
        self.assertEqual(rc.tests_of(text, "crates/c/src/lib.rs"), ["at_root", "tests::inside", "tests::deeper::deepest"])
        self.assertEqual(rc.tests_of(text, "crates/c/src/wake.rs"), ["wake::at_root", "wake::tests::inside", "wake::tests::deeper::deepest"])
        self.assertEqual(rc.tests_of(text, "crates/c/src/a/mod.rs"), ["a::at_root", "a::tests::inside", "a::tests::deeper::deepest"])
        self.assertEqual(rc.tests_of(text, "crates/c/tests/it.rs"), ["at_root", "tests::inside", "tests::deeper::deepest"])
        self.assertEqual(rc.tests_of("// #[test]\nfn not_a_test() {}\n", "crates/c/src/lib.rs"), [])
        self.assertTrue(all("::" in n for n in GROUPS["speaker"] if n not in rc.CLI_TESTS))
        self.assertTrue(rc.CLI_TESTS.issubset(GROUPS["speaker"]))
        self.assertFalse(any(n.startswith(("net::", "durable::")) for n in EVERY))                        # P06's modules are not P02's
        wall = [n for n in EVERY if n.startswith("wall_clock::")]
        self.assertTrue(wall)                                                                              # wall_clock.rs is P02's original AC6
        self.assertEqual(dict((i, n) for i, _d, n in PLAN)["P02-AC-WALL-TIME"], wall)


class ReadingTheLog(unittest.TestCase):
    def test_the_word_may_sit_alone_on_a_later_line_after_other_tests_output(self):
        logs = logs_of("test a::tests::x ... \nsome output from another thread\nok\ntest a::tests::y ... ok\n")
        self.assertEqual((logs.status("a::tests::x"), logs.status("a::tests::y")), ("ok", "ok"))

    def test_colour_codes_are_stripped_and_a_name_with_no_result_is_never_ok(self):
        logs = logs_of("\x1b[32mtest a::tests::x ... ok\x1b[0m\ntest a::tests::y ... \n")
        self.assertEqual((logs.status("a::tests::x"), logs.status("a::tests::y")), ("ok", None))
        self.assertEqual(logs.unterminated, ["a::tests::y"])

    def test_two_different_results_are_a_conflict_in_either_order(self):
        for first, second in (("ok", "FAILED"), ("FAILED", "ok"), ("ok", "ignored")):
            logs = logs_of("test a::tests::x ... %s\n" % first, "test a::tests::x ... %s\n" % second)
            self.assertEqual(logs.status("a::tests::x"), "conflict", (first, second))
        self.assertEqual(logs_of("test a::tests::x ... ok\n", "test a::tests::x ... ok\n").status("a::tests::x"), "ok")

    def test_an_ignored_test_with_a_reason_is_ignored_and_a_panic_is_kept_with_its_location_and_message(self):
        logs = logs_of("test a::tests::x ... ignored, needs a board\n")
        self.assertEqual(logs.status("a::tests::x"), "ignored")
        logs = logs_of("thread 'a::tests::x' (123) panicked at crates/c/src/lib.rs:9:5:\nassertion `left == right` failed\n  left: 1\n note: run with RUST_BACKTRACE=1\n")
        self.assertEqual(logs.panics["a::tests::x"][0], "crates/c/src/lib.rs:9:5:")
        self.assertIn("assertion `left == right` failed", logs.panics["a::tests::x"])
        self.assertTrue(all("RUST_BACKTRACE" not in line for line in logs.panics["a::tests::x"]))


class JudgingNames(unittest.TestCase):
    def test_a_complete_green_log_passes_every_rust_case_and_no_log_blocks_every_one(self):
        results = judged(logs_of(good_log()))
        self.assertEqual(outcome(results), {i: "passed" for i in ALL_IDS})
        self.assertEqual(set(outcome(judged(None)).values()), {"passed", "blocked"})
        self.assertEqual({i: s for i, s in outcome(judged(None)).items() if s == "blocked"}, {i: "blocked" for i in RUST_IDS})

    def test_unrelated_noise_in_the_log_changes_no_verdict(self):
        noisy = good_log(noise=NOISE + "test other_crate::tests::x ... FAILED\ntest net::tests::a_p06_test ... FAILED\ntest wall_clock::tests::b ... ignored\n")
        self.assertEqual(set(outcome(judged(logs_of(noisy))).values()), {"passed"})

    def test_the_sweep_every_p02_test_missing_failed_or_ignored_stops_exactly_the_cases_that_name_it(self):
        naming = {name: {i for i, _d, n in PLAN if name in n} for name in EVERY}
        for name in EVERY:
            self.assertIn(rc.ALL_CASE[0], naming[name])
            for plant, status in (("skip", "blocked"), ("failed", "failed"), ("ignored", "failed")):
                log = logs_of(good_log(**{plant: (name,)}))
                got = {i: rc.judge_names(i, "rust", names, log).status for i, _d, names in PLAN}
                bad = {i for i, s in got.items() if s != "passed"}
                self.assertEqual(bad, naming[name], (name, plant))
                self.assertEqual({got[i] for i in bad}, {status}, (name, plant))

    def test_a_failed_test_names_its_first_causal_event(self):
        name = EVERY[0]
        results = judged(logs_of(good_log(failed=(name,), panics={name: "assertion `left == right` failed"})))
        case = next(r for r in results if r.case_id == rc.ALL_CASE[0])
        self.assertEqual(case.status, "failed")
        self.assertIn("cargo reported FAILED", case.detail)
        self.assertIn("first causal event: crates/x/src/y.rs:1:2: | assertion `left == right` failed", case.detail)

    def test_an_ignored_required_test_is_a_failure_with_its_own_sentence_not_missing_evidence(self):
        name = [n for n in EVERY if n.startswith("entropy::")][0]
        got = {r.case_id: r for r in judged(logs_of(good_log(ignored=(name,))))}
        self.assertEqual(got[rc.ALL_CASE[0]].status, "failed")
        self.assertIn("reported ignored (a required test is switched off)", got[rc.ALL_CASE[0]].detail)
        self.assertNotIn("blocked", {r.status for r in got.values()})                                         # not read as missing evidence anywhere

    def test_a_cut_off_log_blocks_and_says_so_and_a_name_with_no_result_is_counted(self):
        name = EVERY[0]
        cut = next(r for r in judged(logs_of(good_log(summary=False, unfinished=(name,)))) if r.case_id == rc.ALL_CASE[0])
        self.assertEqual(cut.status, "blocked")
        self.assertIn("1 with a name and no result", cut.detail)
        self.assertIn("no `test result:` line", cut.detail)
        whole = next(r for r in judged(logs_of(good_log(unfinished=(name,)))) if r.case_id == rc.ALL_CASE[0])
        self.assertEqual(whole.status, "blocked")
        self.assertNotIn("no `test result:` line", whole.detail)

    def test_a_test_ok_in_one_log_and_failed_in_the_other_is_failed_whichever_log_comes_first(self):
        name = EVERY[3]
        for order in ((good_log(), good_log(skip=EVERY, noise="") + "test %s ... FAILED\n" % name), (good_log(skip=EVERY, noise="") + "test %s ... FAILED\n" % name, good_log())):
            got = outcome(judged(logs_of(*order)))
            self.assertEqual(got[rc.ALL_CASE[0]], "failed")
            self.assertIn("failed", {got[i] for i, _d, n in PLAN if name in n})
        agreeing = outcome(judged(logs_of(good_log(), good_log())))
        self.assertEqual(set(agreeing.values()), {"passed"})                                                  # control: two logs that agree

    def test_two_logs_together_complete_what_each_lacks_but_the_same_name_in_another_module_does_not_count(self):
        half = len(EVERY) // 2
        first, second = good_log(skip=EVERY[half:]), good_log(skip=EVERY[:half])
        self.assertEqual(set(outcome(judged(logs_of(first, second))).values()), {"passed"})
        self.assertIn("blocked", outcome(judged(logs_of(first))).values())
        name = EVERY[0]
        wrong_module = good_log(skip=(name,)) + "test elsewhere::%s ... ok\n" % name
        self.assertEqual(outcome(judged(logs_of(wrong_module)))[rc.ALL_CASE[0]], "blocked")


class WholeRuns(unittest.TestCase):
    def test_a_green_log_and_a_green_python_run_qualify_the_full_tier_and_the_smoke_tier_needs_no_log(self):
        results, meta = rc.run("full", logs_of(good_log()), scripted())
        self.assertEqual((rc.exit_code(results), meta["planned"]), (0, len(ALL_IDS)))
        smoke, _ = rc.run("smoke", None, scripted())
        self.assertEqual((outcome(smoke), rc.exit_code(smoke)), ({"P02-META-MAP": "passed", "P02-REF-PYTHON": "passed"}, 0))

    def test_with_no_log_the_rust_cases_are_blocked_the_host_cases_pass_and_the_exit_is_3(self):
        results, _ = rc.run("full", None, scripted())
        self.assertEqual(rc.exit_code(results), 3)
        self.assertEqual(rc.summarize(results), {"passed": 2, "failed": 0, "blocked": len(RUST_IDS)})

    def test_a_failure_wins_over_a_block(self):
        results = judged(logs_of(good_log(skip=(EVERY[0],), failed=(EVERY[-1],))))
        self.assertEqual(rc.exit_code(results), 1)

    def test_a_python_run_that_fails_or_runs_nothing_is_a_failure_that_names_why(self):
        bad = next(r for r in rc.run("smoke", None, scripted(code=1, unit="FAILED (failures=2)\nRan 137 tests in 0.2s\n"))[0] if r.case_id == "P02-REF-PYTHON")
        self.assertEqual(bad.status, "failed")
        self.assertIn("exit 1, ran 137", bad.detail)
        nothing = next(r for r in rc.run("smoke", None, scripted(code=0, unit="OK\n"))[0] if r.case_id == "P02-REF-PYTHON")
        self.assertEqual(nothing.status, "failed")
        self.assertIn("ran nothing", nothing.detail)
        zero = next(r for r in rc.run("smoke", None, scripted(code=0, unit="Ran 0 tests in 0.0s\n\nOK\n"))[0] if r.case_id == "P02-REF-PYTHON")
        self.assertEqual(zero.status, "failed")

    def test_a_subprocess_that_hangs_is_cut_off_with_a_sentence(self):
        code, out = rc.run_process([sys.executable, "-c", "import time; time.sleep(30)"], HERE, 1)
        self.assertEqual((code, out), (124, "timed out after 1 s"))


class TheDiagnosticReceipt(unittest.TestCase):
    def test_distinct_external_logs_with_equal_basenames_have_unambiguous_replay_names(self):
        logs = rc.Logs()
        logs.files = [("/fixture-a/central.log", "a" * 64), ("/fixture-b/central.log", "b" * 64)]
        command = rc.replay_command("full", logs)
        self.assertIn("p02-log-" + "a" * 64 + ".txt", command)
        self.assertIn("p02-log-" + "b" * 64 + ".txt", command)
        self.assertNotIn("fixture-a", command)
        self.assertNotIn("fixture-b", command)

    def test_repo_relative_judged_log_keeps_its_directory_in_the_replay_command(self):
        rel = "toolchain/results/p02/socket-memory-review-20261106/tests.txt"
        logs = rc.Logs()
        logs.add(os.path.join(REPO, rel))
        self.assertIn("--judge " + rel, rc.replay_command("full", logs))
        self.assertTrue(os.path.isfile(os.path.join(REPO, rc.replay_log_name(logs.files[0][0]))))

    def test_external_artifact_replay_explains_its_setup_without_a_private_path(self):
        logs = rc.Logs()
        logs.files = [(os.path.join(os.path.expanduser("~"), "fixture-logs", "central.log"), "0" * 64)]
        meta = {"versions": rc.versions(), "artifacts": {}}
        lines = rc.retained_lines([rc.Result("P02-FIXTURE", "failed", "fixture cause")], "full", logs, meta)
        self.assertTrue(any("replay setup:" in line for line in lines))
        self.assertTrue(all(os.path.expanduser("~") not in line for line in lines))

    def test_panic_secrets_and_home_paths_are_redacted_in_human_and_json_receipts(self):
        sentinel = "fixture-secret-redaction-canary"
        name = EVERY[0]
        panic = "token=" + sentinel + " at " + os.path.join(os.path.expanduser("~"), "fixture.rs")
        results = judged(logs_of(good_log(failed=(name,), panics={name: panic})))
        meta = {"versions": rc.versions(), "artifacts": {}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc.report(results, "full", None, meta)
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-privacy-")) as tmp:
            receipt = rc.write_receipt(tmp, "full", results, meta, None, "privacy", None)
            with open(receipt, encoding="utf-8") as handle:
                text = output.getvalue() + handle.read()
        self.assertNotIn(sentinel, text)
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertIn("REDACTED", text)
        self.assertIn("first causal event", text)
        self.assertIn("fixture.rs", text)

    def evidence(self, results, **open_kw):
        log = case_log.CaseLog.open(REPO, open_kw.pop("run_id", "t1"), "full", **open_kw)
        for r in results:
            log.record(r.case_id, r.group, r.status, r.detail)
        return log.finish(rc.summarize(results))

    def test_a_normal_run_writes_a_complete_log_and_a_receipt_without_a_local_path(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            results, meta = rc.run("full", logs_of(good_log()), scripted())
            meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
            evidence = self.evidence(results, receipts=tmp, run_id="r1")
            self.assertTrue(evidence.complete, evidence.reasons)
            path = rc.write_receipt(tmp, "full", results, meta, logs_of(good_log()), "r1", evidence)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            doc = json.loads(text)
            self.assertEqual((doc["schema"], doc["tier"], doc["exit_code"]), (rc.RECEIPT_SCHEMA, "full", 0))
            self.assertEqual(doc["counts"], {"passed": len(ALL_IDS), "failed": 0, "blocked": 0})
            self.assertTrue(doc["diagnostics"]["complete"])
            self.assertEqual(doc["diagnostics"]["log"]["critical_lost"], 0)
            self.assertEqual([r["case"] for r in doc["results"]], ALL_IDS)
            self.assertEqual(sorted(os.listdir(tmp)), ["p02-diag-full-r1.jsonl", "p02-r1.json"])
            self.assertNotIn(tmp, text)
            self.assertNotIn(os.path.expanduser("~"), text)                                                 # no home directory either
            with open(os.path.join(tmp, "p02-diag-full-r1.jsonl"), encoding="utf-8") as handle:
                records = [json.loads(line) for line in handle if line.strip()]
            kinds = [r.get("kind") for r in records if r.get("type") == "event"]
            self.assertEqual(kinds.count("case.begin"), len(ALL_IDS))
            self.assertEqual(kinds.count("case.end"), len(ALL_IDS))
            self.assertEqual(kinds.count("run.summary"), 1)
            with self.assertRaises(FileExistsError):
                rc.write_receipt(tmp, "full", results, meta, None, "r1", evidence)                                  # an earlier run's receipt is never overwritten

    def test_without_a_receipts_directory_the_log_is_kept_in_a_fresh_directory_and_never_deleted(self):
        results = judged(logs_of(good_log()))
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            before, tempfile.tempdir = tempfile.tempdir, tmp          # the kept directory lands under this test's own directory
            try:
                evidence = self.evidence(results, run_id="k1")
                again = self.evidence(results, run_id="k1")
            finally:
                tempfile.tempdir = before
            self.assertTrue(evidence.complete, evidence.reasons)
            for kept in (evidence, again):
                self.assertTrue(kept.path and os.path.isfile(kept.path), kept.path)
                self.assertTrue(os.path.realpath(kept.path).startswith(os.path.realpath(tmp)))
            self.assertNotEqual(evidence.path, again.path)             # a rerun never reuses or overwrites the first run's directory
            with open(evidence.path, encoding="utf-8") as handle:
                self.assertEqual(sum(1 for line in handle if '"case.end"' in line), len(ALL_IDS))

    def test_a_case_status_reaches_its_case_end_event(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            results = judged(logs_of(good_log(skip=(EVERY[0],), failed=(EVERY[-1],))))
            self.assertTrue(self.evidence(results, receipts=tmp, run_id="r2").complete)
            with open(os.path.join(tmp, "p02-diag-full-r2.jsonl"), encoding="utf-8") as handle:
                ends = [json.loads(l) for l in handle if '"case.end"' in l]
            by_case = {e["case"]: e["fields"]["status"] for e in ends}
            self.assertEqual(by_case, outcome(results))
            self.assertEqual({"failed", "blocked", "passed"}, set(by_case.values()))

    def test_lost_critical_evidence_makes_a_run_that_would_pass_not_qualified(self):
        results = judged(logs_of(good_log()))
        self.assertEqual(rc.exit_code(results), 0)
        diag = case_log.load(REPO)
        whole = self.evidence(results, target=diag.FaultableSink(), run_id="t2")
        self.assertTrue(whole.complete, whole.reasons)                                                          # control: a sink that takes every write
        self.assertEqual(rc.final_exit(results, whole), 0)
        full = self.evidence(results, target=diag.FaultableSink(capacity_bytes=6_000), run_id="t3")           # the plant: a disk that fills long before the run ends
        self.assertFalse(full.complete)
        self.assertTrue(any("critical" in reason for reason in full.reasons), full.reasons)
        self.assertEqual(rc.final_exit(results, full), 1)
        down = diag.FaultableSink()
        down.available = False                                                                                  # the plant: a sink that is unavailable from the start
        gone = self.evidence(results, target=down, run_id="t4")
        self.assertFalse(gone.complete)
        self.assertEqual(rc.final_exit(results, gone), 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc.report(results, "full", None, {"versions": rc.versions(), "artifacts": rc.artifact_digests()}, full)
        self.assertIn("NOT QUALIFIED", out.getvalue())
        self.assertIn("diagnostic evidence INCOMPLETE", out.getvalue())
        failing = [rc.Result("P02-X", "failed", "x", "rust")] + results                                         # a failure is still a failure, whole log or not
        self.assertEqual((rc.final_exit(failing, full), rc.final_exit(failing, whole)), (1, 1))
        blocked = [rc.Result("P02-X", "blocked", "x", "rust")] + results
        self.assertEqual((rc.final_exit(blocked, full), rc.final_exit(blocked, whole)), (3, 3))

    def test_a_case_that_wrote_no_events_is_caught_by_the_independent_count_not_only_by_the_sinks_own_accounting(self):
        diag = case_log.load(REPO)

        def evidence(extra):
            log = case_log.CaseLog.open(REPO, "t5", "full", target=diag.FaultableSink())
            for n in range(3):
                log.record("P02-X-%d" % n, "rust", "passed", "")
            if extra:
                log.cases += 1                                                                                   # a case the judge decided and that never reached the log
            return log.finish({"passed": 4, "failed": 0, "blocked": 0})

        self.assertTrue(evidence(False).complete)                                                                # control
        missing = evidence(True)
        self.assertFalse(missing.complete)
        self.assertEqual(missing.reasons, ["critical_event_count:7_of_9"])

    def test_an_unavailable_diagnostics_module_or_receipts_directory_is_an_incomplete_log_not_a_crash(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            empty = os.path.join(tmp, "empty-repo")
            os.makedirs(empty)
            log = case_log.CaseLog.open(empty, "t6", "full")
            log.record("P02-X", "rust", "passed", "")
            evidence = log.finish({"passed": 1, "failed": 0, "blocked": 0})
            self.assertFalse(evidence.complete)
            self.assertTrue(evidence.reasons[0].startswith("diagnostics_unavailable"), evidence.reasons)
            blocker = os.path.join(tmp, "a-file")
            open(blocker, "w").close()
            results = [rc.Result("P02-X", "passed", "", "rust")]
            kept = self.evidence(results, receipts=os.path.join(blocker, "under-a-file"), run_id="t7")
            self.assertFalse(kept.complete)
            self.assertEqual((rc.exit_code(results), rc.final_exit(results, kept), rc.final_exit(results, evidence)), (0, 1, 1))

    def test_a_non_pass_prints_how_to_replay_it_and_the_digest_of_everything_judged(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            path = os.path.join(tmp, "central.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(good_log(skip=(EVERY[0],)))
            logs = rc.Logs()
            logs.add(path)
            results, meta = rc.run("full", logs, scripted())
            meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
            lines = rc.retained_lines(results, "full", logs, meta)
        self.assertTrue(lines[0].startswith("RETAINED FOR REPLAY. First blocked case: "), lines[0])
        expected = "p02-log-%s.txt" % logs.files[0][1]
        self.assertEqual(lines[1], "  replay: scripts/e2e/p02 --tier full --judge " + expected)
        self.assertTrue(any(l.startswith("  judged log " + expected + " sha256 ") for l in lines))
        self.assertTrue(any(l.startswith("  artifact crates/franken-platform/src/entropy.rs sha256 ") for l in lines))
        self.assertTrue(all(tmp not in l for l in lines))
        self.assertEqual(rc.retained_lines([rc.Result("P02-X", "passed")], "full", None, meta), [])             # a pass retains nothing
        first_fail = rc.retained_lines([rc.Result("P02-A", "blocked", "b"), rc.Result("P02-B", "failed", "f")], "full", None, meta)[0]
        self.assertIn("First failed case: P02-B", first_fail)                                                   # a failure is named before a block

    def test_the_judged_artifacts_are_the_files_the_sources_and_the_adapter_are_made_of(self):
        digests = rc.artifact_digests()
        self.assertEqual(set(digests.values()) & {"missing"}, set())
        for rel in ("tests/p02/run_cases.py", "tests/p02/case_log.py", "scripts/test/test_support/diagnostics.py", "docs/contracts/p02.md",
                    "crates/franken-platform/src/socket.rs", "crates/franken-platform-linux/src/numbers.rs", "crates/franken-speaker/src/platform_start.rs"):
            self.assertIn(rel, digests)
        self.assertEqual(len(rc.artifact_set_digest(digests)), 64)
        changed = dict(digests, **{"tests/p02/run_cases.py": "0" * 64})
        self.assertNotEqual(rc.artifact_set_digest(changed), rc.artifact_set_digest(digests))


class TheEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp(prefix="ffw-p02-entry-")  # retain test artifacts for replay

    @classmethod
    def tearDownClass(cls):
        pass  # keep the files; the case logger itself closes its threads and descriptors

    def call(self, *argv, env=None):
        done = subprocess.run([ENTRY] + list(argv), capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=rc.UNIT_TIMEOUT_S, env=dict(env or os.environ, TMPDIR=self.scratch))
        return done.returncode, done.stdout, done.stderr

    def test_soak_says_why_and_exits_4_and_judges_nothing_even_with_a_log(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            log = os.path.join(tmp, "x.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(good_log())
            for argv in (("--tier", "soak"), ("--tier", "soak", "--judge", log)):
                code, out, _ = self.call(*argv)
                self.assertEqual(code, 4, argv)
                self.assertIn("P02 soak: NOT RUN", out)
                self.assertIn("This is not a pass.", out)
                self.assertNotIn("QUALIFIED", out)

    def test_smoke_passes_with_no_log_full_without_one_is_blocked_and_a_bad_invocation_is_a_usage_error(self):
        code, out, err = self.call("--tier", "smoke")
        self.assertEqual(code, 0, out + err)
        self.assertIn("P02 e2e tier=smoke: QUALIFIED  planned=2 passed=2 failed=0 blocked=0", out)
        self.assertIn("evidence COMPLETE", out)
        kept = [l for l in out.splitlines() if l.startswith("diagnostic log kept: ")]
        self.assertEqual(len(kept), 1)
        self.assertTrue(os.path.isfile(kept[0].split(": ", 1)[1]))
        code, out, _ = self.call("--tier", "full")
        self.assertEqual(code, 3, out)
        self.assertIn("NOT QUALIFIED", out)
        self.assertIn("BLOCKED  P02-AC-ENTROPY", out)
        code, out, _ = self.call("--tier", "full", "--list")
        self.assertEqual((code, len(out.strip().splitlines())), (0, len(ALL_IDS)))
        code, _, err = self.call("--judge", "/nonexistent/central.log")
        self.assertEqual(code, 2)
        self.assertIn("log not found", err)
        self.assertEqual(self.call("--no-such-flag")[0], 2)
        self.assertEqual(self.call("--tier", "nonsense")[0], 2)

    def test_a_judged_log_and_a_receipts_directory_work_through_the_entry_point(self):
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="ffw-p02-unit-")) as tmp:
            green, red = os.path.join(tmp, "green.log"), os.path.join(tmp, "red.log")
            with open(green, "w", encoding="utf-8") as handle:
                handle.write(good_log())
            with open(red, "w", encoding="utf-8") as handle:
                handle.write(good_log(failed=(EVERY[0],)))
            receipts = os.path.join(tmp, "receipts")
            code, out, err = self.call("--tier", "full", "--judge", green, "--receipts", receipts)
            self.assertEqual(code, 0, out + err)
            self.assertIn("P02 e2e tier=full: QUALIFIED  planned=%d passed=%d failed=0 blocked=0" % (len(ALL_IDS), len(ALL_IDS)), out)
            self.assertEqual(sorted(os.path.splitext(n)[1] for n in os.listdir(receipts)), [".json", ".jsonl"])
            code, out, _ = self.call("--tier", "full", "--judge", red, "--receipts", receipts)
            self.assertEqual(code, 1, out)
            self.assertIn("FAIL     P02-RUST-ALL", out)
            self.assertIn("RETAINED FOR REPLAY", out)
            self.assertEqual(len(os.listdir(receipts)), 4)                                                        # the second run kept its own pair

    def test_the_plan_and_the_unit_test_mode_are_still_reachable_through_the_same_entry_point(self):
        code, out, _ = self.call("--plan")
        self.assertEqual(code, 0)
        self.assertIn("RCH_REQUIRE_REMOTE=1", out)
        self.assertIn("cargo +nightly-2026-08-31 check", out)
        self.assertNotIn("RCH_WORKERS=", out)
        env = dict(os.environ, FFW_RCH_WORKERS="w1,w2", FFW_RCH_TOOLCHAIN="nightly-test")
        code, out, _ = self.call("--plan", env=env)
        self.assertEqual(code, 0)
        self.assertIn("RCH_WORKERS=w1,w2 rch exec", out)
        self.assertIn("cargo +nightly-test check", out)


if __name__ == "__main__":
    unittest.main()
