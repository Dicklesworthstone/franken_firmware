"""Tests of the N01 tiered runner and its diagnostic receipt (tests/n01/run_cases.py, case_log.py; contract section 12).

The central cargo logs judged here are SYNTHETIC, built in memory from the test names the sources define and written only to temporary
directories. They show that the runner passes what it should and refuses what it should; they say nothing about the Rust, which no log
of this kind has run since the bind_stream change. The reference and unit-test subprocesses are replaced by a scripted runner so the
suite stays fast and cannot recurse into itself; the entry point itself is run for real in the last class. Each refusal is planted
against the clean log in the same run set.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import case_log  # noqa: E402
import run_cases as rc  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "n01")
PLAN, GROUPS = rc.case_plan()
EVERY = [n for names in GROUPS.values() for n in names]
ALL_IDS = ["N01-META-MAP", "N01-REF-FRAMES", "N01-REF-NEGOTIATION", "N01-REF-UNITTESTS", "N01-FUZZ-RECORD"] + [i for i, _d, _n in PLAN]
RUST_IDS = [i for i, _d, _n in PLAN]


def good_log(skip=(), failed=(), ignored=(), extra=""):
    """What a green central run prints for N01's own tests: every name ok, a `test result:` line at the end."""
    lines = ["running %d tests" % len(EVERY)]
    for name in EVERY:
        if name in skip:
            continue
        lines.append("test %s ... %s" % (name, "FAILED" if name in failed else "ignored" if name in ignored else "ok"))
    lines += ["", "test result: ok. %d passed; 0 failed; 0 ignored" % len(EVERY)]
    return "\n".join(lines) + "\n" + extra


def logs_of(*texts):
    logs = rc.Logs()
    for text in texts:
        logs.add_text(text)
    return logs


def scripted(code=0, unit="Ran 9 tests in 0.1s\n\nOK\n"):
    calls = []

    def runner(argv, cwd, timeout):
        calls.append(argv)
        return (code, unit if "unittest" in argv else "ok: fresh\n")
    runner.calls = calls
    return runner


def outcome(results):
    return {r.case_id: r.status for r in results}


class Plan(unittest.TestCase):
    def test_the_clause_map_is_whole_on_this_tree_and_each_planted_flaw_is_refused_for_its_own_reason(self):
        self.assertEqual(rc.meta_map(PLAN, GROUPS).status, "passed")
        base = [(i, d, list(n)) for i, d, n in PLAN]
        planted = [
            ("a test that is not in the sources", [(base[0][0], base[0][1], base[0][2] + ["tests::no_such_test"])] + base[1:], "not in the sources"),
            ("a case that names nothing", [(base[0][0], base[0][1], [])] + base[1:], "names no test"),
            ("a test listed twice", [(base[0][0], base[0][1], base[0][2] + base[0][2][:1])] + base[1:], "twice"),
        ]
        for label, plan, needle in planted:
            with self.subTest(label):
                result = rc.meta_map(plan, GROUPS)
                self.assertEqual(result.status, "failed")
                self.assertIn(needle, result.detail)
        doubled = {k: list(v) for k, v in GROUPS.items()}
        doubled["loopback"].append(doubled["lib"][0])
        self.assertIn("more than once", rc.meta_map(PLAN, doubled).detail)

    def test_every_clause_the_acceptance_names_has_a_case_and_the_new_bind_tests_are_in_the_floor(self):
        for needed in ("N01-W-LAYOUT", "N01-W-OVERSIZE", "N01-W-REPLAY", "N01-W-EPOCH", "N01-W-CRITICAL", "N01-W-MUTATION", "N01-W-UNTRUSTED", "N01-W-BIND"):
            self.assertIn(needed, RUST_IDS)
        everything = dict((i, n) for i, _d, n in PLAN)["N01-RUST-ALL"]
        for name in ("tests::rebinding_the_current_stream_does_not_reopen_its_replay_window",
                     "tests::binding_the_current_stream_to_another_epoch_is_only_an_epoch_announcement"):
            self.assertIn(name, everything)
        self.assertEqual(len(everything), len(GROUPS["lib"]) + len(GROUPS["negotiation"]) + 1 + 7)

    def test_the_tiers_plan_what_they_say_and_soak_plans_nothing(self):
        self.assertEqual(rc.planned_ids("smoke"), ["N01-META-MAP", "N01-REF-FRAMES", "N01-REF-NEGOTIATION"])
        self.assertEqual(rc.planned_ids("full"), ALL_IDS)
        self.assertEqual(sorted(rc.descriptions()), sorted(ALL_IDS))
        smoke, _ = rc.run("smoke", None, scripted())
        self.assertEqual([r.case_id for r in smoke], rc.planned_ids("smoke"))
        full, meta = rc.run("full", None, scripted())
        self.assertEqual([r.case_id for r in full], ALL_IDS)
        self.assertEqual(meta["rust_tests_required"], len(EVERY))
        with self.assertRaises(ValueError):
            rc.run("soak", None, scripted())

    def test_the_unit_test_case_never_runs_the_runner_s_own_tests(self):
        self.assertNotIn("test_run_cases", rc.unit_modules())
        self.assertIn("test_reference_frames", rc.unit_modules())
        runner = scripted()
        rc.run("full", None, runner)
        self.assertTrue(any("unittest" in argv for argv in runner.calls))
        self.assertFalse(any("test_run_cases" in " ".join(argv) for argv in runner.calls))


class ReadingTheLog(unittest.TestCase):
    NAME = "tests::a_name"

    def test_the_word_may_sit_alone_on_a_later_line_after_other_tests_output(self):
        logs = logs_of("test %s ... other test's output on the open line\nmore output\nok\ntest b ... ok\n" % self.NAME)
        self.assertEqual((logs.status(self.NAME), logs.status("b"), logs.unterminated), ("ok", "ok", []))

    def test_colour_codes_are_stripped_and_a_name_with_no_result_is_never_ok(self):
        logs = logs_of("\x1b[0mtest %s ... \x1b[32mok\x1b[0m\ntest lost ... \ntest next ... ok\n" % self.NAME)
        self.assertEqual((logs.status(self.NAME), logs.status("lost"), logs.unterminated), ("ok", None, ["lost"]))

    def test_two_different_results_are_a_conflict_in_either_order(self):
        for first, second in (("ok", "FAILED"), ("FAILED", "ok")):
            logs = logs_of("test x ... %s\n" % first, "test x ... %s\n" % second)
            self.assertEqual(logs.status("x"), "conflict", (first, second))
        self.assertEqual(logs_of("test x ... ok\n", "test x ... ok\n").status("x"), "ok")

    def test_a_panic_is_kept_with_its_location_and_message_with_or_without_a_thread_id(self):
        for head in ("thread 'tests::boom' panicked at crates/f/src/lib.rs:9:5:", "thread 'tests::boom' (4821) panicked at crates/f/src/lib.rs:9:5:"):
            logs = logs_of("%s\nthe left side was 1\nnote: run with `RUST_BACKTRACE=1`\ntest tests::boom ... FAILED\n" % head)
            self.assertEqual(logs.panics["tests::boom"], ["crates/f/src/lib.rs:9:5:", "the left side was 1"], head)
            self.assertEqual(logs.status("tests::boom"), "FAILED")

    def test_a_panic_printed_while_another_test_is_between_its_name_and_its_word_costs_neither(self):
        logs = logs_of("test a ... thread 'b' panicked at x.rs:1:1:\nboom\nok\ntest b ... FAILED\n")
        self.assertEqual((logs.status("a"), logs.status("b"), logs.unterminated, logs.panics["b"]), ("ok", "FAILED", [], ["x.rs:1:1:", "boom"]))


class JudgingNames(unittest.TestCase):
    def judged(self, **kw):
        return outcome([rc.judge_names(i, "rust", n, logs_of(good_log(**kw))) for i, _d, n in PLAN])

    def test_a_complete_green_log_passes_every_rust_case_and_no_log_blocks_every_one(self):
        self.assertEqual(set(self.judged().values()), {"passed"})
        for case_id, _d, names in PLAN:
            self.assertEqual(rc.judge_names(case_id, "rust", names, None).status, "blocked", case_id)

    def test_a_failed_test_fails_exactly_the_cases_that_name_it_with_its_first_causal_event(self):
        victim = "tests::a_tampered_datagram_never_consumes_a_sequence_number"
        panic = "thread '%s' panicked at crates/franken-stream/src/lib.rs:1500:9:\nassertion `left == right` failed\n" % victim
        logs = logs_of(panic + good_log(failed=(victim,)))
        results = {i: rc.judge_names(i, "rust", n, logs) for i, _d, n in PLAN}
        self.assertEqual({i for i, r in results.items() if r.status == "failed"}, {"N01-W-MUTATION", "N01-RUST-ALL"})
        self.assertEqual({r.status for i, r in results.items() if i not in ("N01-W-MUTATION", "N01-RUST-ALL")}, {"passed"})
        detail = results["N01-W-MUTATION"].detail
        self.assertIn(victim, detail)
        self.assertIn("first causal event: crates/franken-stream/src/lib.rs:1500:9: | assertion `left == right` failed", detail)
        no_cause = rc.judge_names("N01-W-MUTATION", "rust", dict((i, n) for i, _d, n in PLAN)["N01-W-MUTATION"], logs_of(good_log(failed=(victim,))))
        self.assertNotIn("first causal event", no_cause.detail)         # a FAILED with no panic line claims no cause

    def test_missing_ignored_or_unfinished_evidence_blocks_and_is_never_a_failure_or_a_pass(self):
        victim = "tests::replay_window_edges_reorder_depth_and_the_future_bound"
        for label, text in (("missing", good_log(skip=(victim,))), ("ignored", good_log(ignored=(victim,))),
                            ("unfinished", good_log(skip=(victim,)) + "test %s ... \n" % victim)):
            got = self.judged_text(text)
            self.assertEqual({i for i, s in got.items() if s == "blocked"}, {"N01-W-REPLAY", "N01-RUST-ALL"}, label)
            self.assertNotIn("failed", got.values(), label)
        cut = rc.judge_names("N01-W-REPLAY", "rust", [victim], logs_of("test %s ... \n" % victim))
        self.assertEqual(cut.status, "blocked")
        self.assertIn("no `test result:` line", cut.detail)
        self.assertIn("1 with a name and no result", cut.detail)

    def judged_text(self, text):
        logs = logs_of(text)
        return outcome([rc.judge_names(i, "rust", n, logs) for i, _d, n in PLAN])

    def test_a_test_ok_in_one_log_and_failed_in_the_other_is_failed_whichever_log_comes_first(self):
        victim = "tests::arbitrary_garbage_never_panics_and_never_authenticates"
        for order in ((good_log(), good_log(failed=(victim,))), (good_log(failed=(victim,)), good_log())):
            result = rc.judge_names("N01-W-UNTRUSTED", "rust", dict((i, n) for i, _d, n in PLAN)["N01-W-UNTRUSTED"], logs_of(*order))
            self.assertEqual(result.status, "failed")
            self.assertIn("conflicting results", result.detail)


class WholeRuns(unittest.TestCase):
    def test_a_green_log_and_green_subprocesses_qualify_the_full_tier_and_the_smoke_tier_needs_no_log(self):
        results, _ = rc.run("full", logs_of(good_log()), scripted())
        self.assertEqual(set(outcome(results).values()), {"passed"})
        self.assertEqual(rc.exit_code(results), 0)
        smoke, _ = rc.run("smoke", None, scripted())
        self.assertEqual((rc.exit_code(smoke), set(outcome(smoke).values())), (0, {"passed"}))

    def test_with_no_log_the_rust_cases_are_blocked_the_reference_cases_pass_and_the_exit_is_3(self):
        results, _ = rc.run("full", None, scripted())
        got = outcome(results)
        self.assertEqual({got[i] for i in RUST_IDS}, {"blocked"})
        self.assertEqual({got[i] for i in ("N01-META-MAP", "N01-REF-FRAMES", "N01-REF-NEGOTIATION", "N01-REF-UNITTESTS", "N01-FUZZ-RECORD")}, {"passed"})
        self.assertEqual(rc.exit_code(results), 3)

    def test_a_reference_check_or_a_unit_run_that_fails_is_a_failure_that_names_why(self):
        results, _ = rc.run("full", logs_of(good_log()), scripted(code=1))
        got = {r.case_id: r for r in results}
        self.assertEqual(got["N01-REF-FRAMES"].status, "failed")
        self.assertIn("reference_frames.py --check exit 1", got["N01-REF-FRAMES"].detail)
        self.assertEqual(got["N01-REF-UNITTESTS"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)
        silent = rc.unit_case(lambda argv, cwd, timeout: (0, "no summary printed\n"))
        self.assertEqual(silent.status, "failed")        # exit 0 with nothing run is not a pass

    def test_the_fuzz_record_passes_with_a_warning_when_the_source_moved_and_fails_when_it_disagrees_with_itself(self):
        result = rc.judge_fuzz_record()
        self.assertEqual(result.status, "passed", result.detail)
        fr = rc.load_fuzz_record()
        record, crash = fr.load(fr.cited_records(REPO)[0])
        self.assertEqual(fr.record_problems(record, crash, REPO, fr.cited_records(REPO)[0].name), [])
        if result.detail:
            self.assertIn("WARNING", result.detail)

    def test_a_subprocess_that_hangs_is_cut_off_with_a_sentence(self):
        code, text = rc.run_process([sys.executable, "-c", "import time; time.sleep(30)"], HERE, 1)
        self.assertEqual((code, text), (124, "timed out after 1 s"))


class TheDiagnosticReceipt(unittest.TestCase):
    def test_raw_panic_secrets_are_redacted_before_human_and_json_receipt_output(self):
        sentinel = "fixture-secret-redaction-canary"
        name = EVERY[0]
        panic = "thread '%s' panicked at %s:1:2:\ntoken=%s\n" % (name, os.path.join(os.path.expanduser("~"), "fixture.rs"), sentinel)
        logs = logs_of(good_log(failed=(name,), extra=panic))
        results, meta = rc.run("full", logs, scripted())
        meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
        output = io.StringIO()
        with redirect_stdout(output):
            rc.report(results, "full", logs, meta)
        tmp = tempfile.mkdtemp(prefix="ffw-n01-privacy-")  # retain failure artifacts
        path = rc.write_receipt(tmp, "full", results, meta, logs, "privacy", None)
        with open(path, encoding="utf-8") as handle:
            text = output.getvalue() + handle.read()
        self.assertNotIn(sentinel, text)
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertIn("REDACTED", text)
        self.assertIn("first causal event", text)
        self.assertIn("fixture.rs", text)

    def test_a_normal_run_writes_a_complete_log_and_a_receipt_without_a_local_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            results, meta = rc.run("full", logs_of(good_log()), scripted())
            meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
            log = case_log.CaseLog.open(REPO, "r1", "full", tmp)
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            evidence = log.finish(rc.summarize(results))
            self.assertTrue(evidence.complete, evidence.reasons)
            path = rc.write_receipt(tmp, "full", results, meta, logs_of(good_log()), "r1", evidence)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            doc = json.loads(text)
            self.assertEqual((doc["schema"], doc["tier"], doc["exit_code"], doc["counts"]), (rc.RECEIPT_SCHEMA, "full", 0, {"passed": 16, "failed": 0, "blocked": 0}))
            self.assertTrue(doc["diagnostics"]["complete"])
            self.assertEqual(sorted(os.listdir(tmp)), ["n01-diag-full-r1.jsonl", "n01-r1.json"])
            self.assertNotIn(tmp, text)
            with self.assertRaises(FileExistsError):
                rc.write_receipt(tmp, "full", results, meta, None, "r1", evidence)      # an earlier run's receipt is never overwritten

    def test_a_pass_cannot_rest_on_a_log_that_could_not_be_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "a-file")
            open(blocker, "w").close()
            log = case_log.CaseLog.open(REPO, "r2", "full", os.path.join(blocker, "under-a-file"))
            results = [rc.Result("N01-X", "passed", "", "reference")]
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            evidence = log.finish(rc.summarize(results))
            self.assertFalse(evidence.complete)
            self.assertEqual((rc.exit_code(results), rc.final_exit(results, evidence)), (0, 1))

    def test_a_non_pass_prints_how_to_replay_it_and_the_digest_of_everything_judged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "central.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(good_log(skip=("tests::keys_and_payloads_never_appear_in_diagnostics",)))
            logs = rc.Logs()
            logs.add(path)
            results, meta = rc.run("full", logs, scripted())
            meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
            lines = rc.retained_lines(results, "full", logs, meta)
        self.assertTrue(lines[0].startswith("RETAINED FOR REPLAY. First blocked case: N01-W-UNTRUSTED"))
        self.assertEqual(lines[1], "  replay: scripts/e2e/n01 --tier full --judge central.log")
        self.assertTrue(any(l.startswith("  judged log central.log sha256 ") for l in lines))
        self.assertTrue(any(l.startswith("  artifact crates/franken-stream/src/lib.rs sha256 ") for l in lines))
        self.assertEqual(rc.retained_lines([rc.Result("N01-X", "passed")], "full", None, meta), [])        # a pass retains nothing


class TheEntryPoint(unittest.TestCase):
    def call(self, *argv):
        done = subprocess.run([ENTRY] + list(argv), capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=rc.UNIT_TIMEOUT_S)
        return done.returncode, done.stdout, done.stderr

    def test_soak_says_why_and_exits_4_and_judges_nothing_even_with_a_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "x.log")
            with open(log, "w", encoding="utf-8") as handle:
                handle.write(good_log())
            for argv in (("--tier", "soak"), ("--tier", "soak", "--judge", log)):
                code, out, _ = self.call(*argv)
                self.assertEqual(code, 4, argv)
                self.assertIn("N01 soak: NOT RUN", out)
                self.assertIn("This is not a pass.", out)
                self.assertNotIn("QUALIFIED", out)

    def test_smoke_passes_with_no_log_list_names_the_cases_and_a_missing_log_is_a_usage_error(self):
        code, out, err = self.call("--tier", "smoke")
        self.assertEqual(code, 0, out + err)
        self.assertIn("N01 e2e tier=smoke: QUALIFIED  planned=3 passed=3 failed=0 blocked=0", out)
        self.assertIn("evidence COMPLETE", out)
        code, out, _ = self.call("--tier", "full", "--list")
        self.assertEqual((code, len(out.strip().splitlines())), (0, 16))
        code, _, err = self.call("--judge", "/nonexistent/central.log")
        self.assertEqual(code, 2)
        self.assertIn("log not found", err)
        self.assertEqual(self.call("--no-such-flag")[0], 2)

    def test_the_older_modes_are_still_reachable_through_the_same_entry_point(self):
        code, out, _ = self.call("--verify-fuzz-record")
        self.assertEqual(code, 0, out)
        self.assertIn('"problems": []', out)
        code, _, err = self.call("--judge-guest")
        self.assertEqual(code, 2)
        self.assertIn("usage: scripts/e2e/n01 --judge-guest", err)


if __name__ == "__main__":
    unittest.main()
