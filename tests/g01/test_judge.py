"""Checks on the judge of the G01 Rust log (bead ffw-kh0), run by scripts/e2e/g01.

The judge must pass a log shaped like the real cargo output of the replay, and must fail it when
anything is wrong: a missing, duplicated, unknown or mismatching scenario, a schedule count that
differs from the model by one, a run that failed, a planted fault that broke nothing or the wrong
scenarios, a replay that cannot show it reports corruption, a vector file that is not this one, or
cargo itself reporting fewer tests, a failure, or no run of the target at all.

The good log is synthesised from the vectors and the model. That is the right fixture for a judge
(it is what a correct Rust run must print); it says nothing about whether the Rust prints it.
"""

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import judge  # noqa: E402
import reference as ref  # noqa: E402

DOC = ref.load()
TESTS = judge.expected_tests()
# cargo runs the tests of a target in name order when --test-threads=1
ORDER = sorted(TESTS)


def good_records():
    scenarios = [
        {"kind": "scenario", "id": s["id"], "steps": len(ref.expand(s["steps"])), "mismatches": []}
        for s in DOC["scenarios"]
    ]
    schedule = [
        {"kind": "schedule", "seed": r["seed"], "u": r["u"], "max_offset": r["max_offset"],
         "skew_holder": r["skew_holder"], "counts": dict(r["counts"]), "error": None, "matches": True}
        for r in DOC["schedule"]["runs"]
    ]
    plants = [{"kind": "plant", "name": p["name"], "broken": list(p["fails"]), "predicted": list(p["fails"])}
              for p in DOC["plants"]]
    corrupted = [{"kind": "corrupted", "wrong_number_reported": True, "wrong_code_reported": True}]
    vectors = [{"kind": "vectors", "scenarios": len(DOC["scenarios"]),
                "step_entries": sum(len(s["steps"]) for s in DOC["scenarios"]),
                "schedule_runs": len(DOC["schedule"]["runs"]), "plants": len(DOC["plants"])}]
    return {
        "every_golden_scenario_matches_the_engine": scenarios,
        "the_seeded_schedule_reproduces_the_models_counts_exactly": schedule,
        "a_planted_fault_breaks_exactly_the_scenarios_the_model_predicts": plants + corrupted,
        "the_vector_file_is_the_one_this_replay_understands": vectors,
    }


def log_of(groups, result="test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s",
           running=True, tests=None, extra=""):
    """A log in the shape of `cargo test --test g01_replay -- --nocapture --test-threads=1`: each test's
    first output lands on the `test NAME ... ` line, and `ok` follows its last."""
    tests = ORDER if tests is None else tests
    lines = ["   Compiling franken-session v0.1.0 (/work/crates/franken-session)"]
    if running:
        lines.append("     Running tests/g01_replay.rs (target/debug/deps/g01_replay-0123456789abcdef)")
        lines.append("")
        lines.append("running %d tests" % len(tests))
    for name in tests:
        records = groups.get(name, [])
        for index, record in enumerate(records):
            prefix = "test %s ... " % name if index == 0 else ""
            lines.append(prefix + "G01-OBSERVED " + json.dumps(record))
        if not records:
            lines.append("test %s ... " % name)
        lines.append("ok")
    lines.append("")
    lines.append(result % len(tests) if "%d" in result else result)
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def problems_of(groups=None, **kwargs):
    return judge.judge(DOC, [log_of(groups if groups is not None else good_records(), **kwargs)], TESTS)


def flat(groups):
    return [r for name in ORDER for r in groups.get(name, [])]


class Judge(unittest.TestCase):
    def test_a_log_shaped_like_the_real_one_passes(self):
        self.assertEqual(problems_of(), [])

    def test_records_after_the_test_name_on_the_same_line_are_found(self):
        records, bad = judge.parse(log_of(good_records()))
        self.assertEqual(bad, [])
        self.assertEqual(len(records), len(flat(good_records())))

    def test_a_missing_duplicated_or_unknown_scenario_fails(self):
        key = "every_golden_scenario_matches_the_engine"
        g = good_records()
        del g[key][5]
        self.assertTrue(any("was not reported" in p for p in problems_of(g)))
        g = good_records()
        g[key].append(copy.deepcopy(g[key][0]))
        self.assertTrue(any("reported 2 times" in p for p in problems_of(g)))
        g = good_records()
        g[key].append({"kind": "scenario", "id": "G01-S999", "steps": 1, "mismatches": []})
        self.assertTrue(any("not in the vector file" in p for p in problems_of(g)))

    def test_a_mismatch_or_a_short_run_of_steps_fails(self):
        key = "every_golden_scenario_matches_the_engine"
        g = good_records()
        g[key][2]["mismatches"] = ["step 3 (commit): wanted MISSING_ACKS"]
        self.assertTrue(any("the engine disagrees" in p for p in problems_of(g)))
        g = good_records()
        g[key][2]["steps"] -= 1
        self.assertTrue(any("steps" in p for p in problems_of(g)))

    def test_one_schedule_count_off_by_one_fails_and_names_the_field(self):
        key = "the_seeded_schedule_reproduces_the_models_counts_exactly"
        g = good_records()
        g[key][7]["counts"]["takeovers"] += 1
        found = problems_of(g)
        self.assertTrue(any("takeovers" in p and "differ" in p for p in found), found)

    def test_a_failed_driver_a_missing_run_or_an_unreported_match_fails(self):
        key = "the_seeded_schedule_reproduces_the_models_counts_exactly"
        g = good_records()
        g[key][0]["error"] = "two nodes won epoch 3"
        g[key][0]["counts"] = None
        self.assertTrue(any("driver failed" in p for p in problems_of(g)))
        g = good_records()
        del g[key][-1]
        self.assertTrue(any("was not reported" in p for p in problems_of(g)))
        g = good_records()
        g[key][3]["matches"] = False
        self.assertTrue(any("did not report a match" in p for p in problems_of(g)))

    def test_a_plant_that_breaks_nothing_or_the_wrong_scenarios_or_is_missing_fails(self):
        key = "a_planted_fault_breaks_exactly_the_scenarios_the_model_predicts"
        g = good_records()
        g[key][0]["broken"] = []
        self.assertTrue(any("cannot fail" in p for p in problems_of(g)))
        g = good_records()
        g[key][1]["broken"] = g[key][1]["broken"][:-1]
        self.assertTrue(any("the model predicts" in p for p in problems_of(g)))
        g = good_records()
        del g[key][2]
        self.assertTrue(any("was not reported" in p for p in problems_of(g)))

    def test_a_replay_that_cannot_show_it_reports_corruption_fails(self):
        key = "a_planted_fault_breaks_exactly_the_scenarios_the_model_predicts"
        for field in ("wrong_number_reported", "wrong_code_reported"):
            g = good_records()
            next(r for r in g[key] if r["kind"] == "corrupted")[field] = False
            self.assertTrue(any("corrupted expectation" in p for p in problems_of(g)), field)
        g = good_records()
        g[key] = [r for r in g[key] if r["kind"] != "corrupted"]
        self.assertTrue(any("corrupted expectation" in p for p in problems_of(g)))

    def test_a_different_vector_file_fails(self):
        key = "the_vector_file_is_the_one_this_replay_understands"
        g = good_records()
        g[key][0]["step_entries"] += 1
        self.assertTrue(any("differs from this one" in p for p in problems_of(g)))

    def test_cargo_reporting_a_failure_fewer_tests_or_no_run_fails(self):
        self.assertTrue(any("FAILED" in p or "failure" in p for p in problems_of(
            result="test result: FAILED. %d passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")))
        self.assertTrue(any("cargo reported" in p for p in problems_of(
            result="test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")))
        self.assertTrue(any("cargo reported" in p for p in problems_of(
            result="test result: ok. %d passed; 0 failed; 1 ignored; 0 measured; 0 filtered out")))
        self.assertTrue(any("Running tests/g01_replay.rs" in p for p in problems_of(running=False)))
        self.assertTrue(any("panicked" in p for p in problems_of(extra="thread 'x' panicked at src/lib.rs:1:1")))

    def test_a_test_cargo_did_not_run_fails(self):
        fewer = ORDER[:-1]
        found = problems_of(tests=fewer)
        self.assertTrue(any("cargo ran %d tests" % len(fewer) in p for p in found), found)
        g = good_records()
        text = log_of(g).replace("test %s ... " % ORDER[0], "test something_else ... ")
        self.assertTrue(any("did not run the test %s" % ORDER[0] in p for p in judge.judge(DOC, [text], TESTS)))

    def test_an_unreadable_record_fails(self):
        text = log_of(good_records()) + "G01-OBSERVED {not json\n"
        self.assertTrue(any("unreadable" in p for p in judge.judge(DOC, [text], TESTS)))

    def test_the_other_targets_of_the_crate_are_not_mistaken_for_the_replay(self):
        text = log_of(good_records(), running=False)
        text = "     Running unittests src/lib.rs (target/debug/deps/franken_session-0)\n\nrunning 43 tests\n" \
               "test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n" + text
        self.assertTrue(any("Running tests/g01_replay.rs" in p for p in judge.judge(DOC, [text], TESTS)))

    def test_the_command_line_exits_zero_on_a_good_log_and_one_on_a_bad_one(self):
        with tempfile.TemporaryDirectory() as folder:
            good = Path(folder) / "good.log"
            good.write_text(log_of(good_records()), encoding="utf-8")
            bad_groups = good_records()
            bad_groups["every_golden_scenario_matches_the_engine"][0]["mismatches"] = ["x"]
            bad = Path(folder) / "bad.log"
            bad.write_text(log_of(bad_groups), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(judge.main([str(good)]), 0)
                self.assertEqual(judge.main([str(bad)]), 1)
                self.assertEqual(judge.main([str(Path(folder) / "missing.log")]), 1)


if __name__ == "__main__":
    unittest.main()
