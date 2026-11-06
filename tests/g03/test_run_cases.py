"""Checks on the G03 judge itself (tests/g03/run_cases.py, bead ffw-xvv), run by `python3 -B -m unittest discover -s tests/g03 -p test_run_cases.py`.

A judge that cannot fail proves nothing, so every way a run must NOT qualify has a test here, and each is paired with its control (the same run
without the defect, which qualifies or is merely blocked): no Rust evidence at all, a missing, ignored, failed or conflicting test, a log from
other sources or another binary, a test file that no `mod` declares, a claimed test the sources do not define, a malformed invariant map, an
offline check that fails, hangs or runs no test, lost diagnostics, an unwritable receipts directory, and the soak tier. The Rust tests are
never run here; the logs are synthetic, written in cargo's form from the names the sources define. Standard library only, no network.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, "..", ".."))


def load_runner():
    spec = importlib.util.spec_from_file_location("g03_t_run_cases", os.path.join(HERE, "run_cases.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = load_runner()
FSONOS = os.path.join(ROOT, rc.FSONOS_REL)


def section(names, failed=(), ignored=()):
    body = ["", "running %d test%s" % (len(names), "" if len(names) == 1 else "s")]
    for name in names:
        body.append("test %s ... %s" % (name, "FAILED" if name in failed else "ignored" if name in ignored else "ok"))
    passed = sum(1 for n in names if n not in failed and n not in ignored)
    verdict = "FAILED" if failed else "ok"
    body += ["", "test result: %s. %d passed; %d failed; %d ignored; 0 measured; 0 filtered out; finished in 0.01s"
             % (verdict, passed, len(failed), len(ignored))]
    return body


def cargo_log(names, failed=(), ignored=(), skip=(), stem=None, layout="classic", extra=(), tail=()):
    """A cargo-test log of the same FORM as the central ones (worker id and pool hash invented). `layout` "rch" puts the stdout section first
    and the stderr `Running` header after it, which is how the central logs arrive."""
    stem = stem or rc.STEM
    shown = [n for n in list(names) + list(extra) if n not in skip]
    header = "     Running unittests src/lib.rs (.rch-target-trj-pool-0123456789abcdef/debug/deps/%s-0123456789abcdef)" % stem
    body = section(shown, failed, ignored)
    lines = ["   Compiling franken-control v0.1.0", "    Finished `test` profile [unoptimized + debuginfo] target(s) in 1s"]
    lines += ([header] + body) if layout == "classic" else (body + [header])
    lines += list(tail)
    return "\n".join(lines) + "\n"


def all_names(repo=ROOT):
    return sorted(rc.derive_tests(repo))


def judge_logs(*texts, tier="full", repo=ROOT):
    """Judge one or more logs (each text is a separate file). The offline subprocess checks are a different test class's business."""
    with tempfile.TemporaryDirectory() as d:
        logs = rc.Logs()
        for i, text in enumerate(texts):
            path = os.path.join(d, "cargo%d.log" % i)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            logs.add(path)
        results, meta = rc.run(tier, logs if texts else None, repo, offline=False)
    return {r.case_id: r for r in results}, results, meta


def not_passed(results):
    return [(r.case_id, r.status, r.detail[:160]) for r in results if r.status != "passed"]


def invariants(repo=ROOT):
    with open(os.path.join(repo, rc.CASES_REL), encoding="utf-8") as fh:
        return json.load(fh)["invariants"]


def claiming(claim, repo=ROOT):
    return sorted(inv["id"] for inv in invariants(repo) if claim in inv["rust_tests"])


class Positive(unittest.TestCase):
    def test_a_complete_log_qualifies_every_rust_case_in_either_log_layout(self):
        for layout in ("classic", "rch"):
            for tier in ("smoke", "full"):
                by, results, meta = judge_logs(cargo_log(all_names(), layout=layout, extra=("channel::x::tests::unrelated",)), tier=tier)
                self.assertEqual(rc.exit_code(results), 0, (layout, tier, not_passed(results)))
                for inv in invariants():
                    self.assertEqual(by[inv["id"]].status, "passed", inv["id"])
                self.assertEqual(by["G03-REPLAY"].status, "passed")
                self.assertEqual(meta["rust_tests_ok"], meta["planned_rust_tests"])

    def test_nothing_the_sources_define_is_left_unjudged(self):
        """Every `#[test]` under fsonos/ is required by some case: an invariant names it, it is the Rust replay, or it is the catch-all."""
        _, results, meta = judge_logs(cargo_log(all_names()))
        self.assertEqual(meta["planned_rust_tests"], len(all_names()))
        cases = rc.registry(rc.load_cases()[0], rc.derive_tests())
        self.assertEqual(sorted({n for c in cases for n in c["tests"]}), all_names())
        self.assertGreaterEqual(len(all_names()), 100, "the sources hold the fsonos unit tests this judge exists for")

    def test_the_derived_names_follow_cargos_naming(self):
        names = set(all_names())
        self.assertTrue(all(n.startswith("fsonos::") for n in names))
        self.assertTrue(any("::tests::" in n for n in names))
        self.assertTrue(any(n.startswith("fsonos::replay::") and "::tests::" not in n for n in names), "replay.rs is test code from its first line")

    def test_a_later_slice_may_append_invariants_under_its_own_letter(self):
        doc = {"schema": rc.CASES_SCHEMA, "bead": rc.BEAD, "invariants": [
            {"id": "G03-I01", "statement": "a", "vectors": [], "rust_tests": ["xml::a"]},
            {"id": "G03-S01", "statement": "b", "vectors": [], "rust_tests": ["ssdp::b"]}]}
        self.assertEqual(rc.cases_problems(doc), [])
        doc["invariants"][1]["id"] = "G03-I01"            # the control: the same map with a repeated id is refused
        self.assertTrue(any("duplicate id" in p for p in rc.cases_problems(doc)), rc.cases_problems(doc))

    def test_derive_tests_names_a_synthetic_tree_exactly(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, rc.FSONOS_REL))
            put(d, rc.FSONOS_REL + "/alpha.rs", "pub fn f() {}\n#[test]\nfn before() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn one() {}\n"
                "    #[test]\n    #[ignore = \"slow\"]\n    fn two() {}\n}\n")
            put(d, rc.FSONOS_REL + "/replay.rs", "#[test]\nfn replays() {}\n")
            put(d, rc.FSONOS_REL + "/mod.rs", "#[cfg(test)]\nmod tests {\n    #[test]\n    fn top() {}\n}\n")
            put(d, rc.FSONOS_REL + "/notes.txt", "#[test]\nfn not_rust() {}\n")
            got = rc.derive_tests(d)
        self.assertEqual(sorted(got), ["fsonos::alpha::before", "fsonos::alpha::tests::one", "fsonos::alpha::tests::two",
                                       "fsonos::replay::replays", "fsonos::tests::top"])
        self.assertEqual((got["fsonos::alpha::tests::one"]["ignored"], got["fsonos::alpha::tests::two"]["ignored"]), (False, True))
        self.assertEqual(got["fsonos::replay::replays"]["module"], "replay")


class Blocked(unittest.TestCase):
    """Missing Rust evidence BLOCKS: counted, named, nonzero, never a pass."""

    def test_no_log_blocks_every_rust_case_and_exits_nonzero(self):
        by, results, meta = judge_logs()
        rust = [i["id"] for i in invariants()] + ["G03-REPLAY"]
        for case_id in rust:
            self.assertEqual(by[case_id].status, "blocked", case_id)
            self.assertIn("no cargo test log supplied", by[case_id].detail)
        self.assertEqual(rc.exit_code(results), 3)
        self.assertEqual(meta["rust_tests_ok"], 0)
        # the control: the structure checks do not depend on a log and still pass
        self.assertEqual((by["G03-META-CASES"].status, by["G03-META-WIRED"].status), ("passed", "passed"))

    def test_a_missing_test_blocks_exactly_the_cases_that_name_it(self):
        info = rc.derive_tests()
        name = next(n for n, i in sorted(info.items()) if claiming("%s::%s" % (i["module"], i["function"])))
        claim = "%s::%s" % (info[name]["module"], info[name]["function"])
        by, results, _ = judge_logs(cargo_log(all_names(), skip=(name,)))
        want = claiming(claim)
        self.assertEqual(sorted(c for c, r in by.items() if r.status == "blocked"), want)
        self.assertIn(name + ": not reported", by[want[0]].detail)
        self.assertEqual(rc.exit_code(results), 3)
        self.assertEqual(rc.exit_code(judge_logs(cargo_log(all_names()))[1]), 0)  # the control: the same log with the test

    def test_an_ignored_test_is_not_run_and_blocks(self):
        info = rc.derive_tests()
        name = next(n for n, i in sorted(info.items()) if claiming("%s::%s" % (i["module"], i["function"])))
        by, results, _ = judge_logs(cargo_log(all_names(), ignored=(name,)))
        blocked = [r for r in results if r.status == "blocked"]
        self.assertTrue(blocked)
        self.assertTrue(all("ignored (not run)" in r.detail for r in blocked), [r.detail for r in blocked])
        self.assertEqual(rc.exit_code(results), 3)

    def test_ignored_in_one_log_and_ok_in_another_is_not_a_conflict(self):
        names = all_names()
        _, results, _ = judge_logs(cargo_log(names, ignored=tuple(names[:3])), cargo_log(names))
        self.assertEqual(rc.exit_code(results), 0, not_passed(results))
        _, results, _ = judge_logs(cargo_log(names), cargo_log(names, ignored=tuple(names[:3])))
        self.assertEqual(rc.exit_code(results), 0, not_passed(results))

    def test_the_right_names_from_another_binary_are_not_this_binarys_tests(self):
        by, results, _ = judge_logs(cargo_log(all_names(), stem="some_other_crate"))
        self.assertEqual(rc.exit_code(results), 3)
        self.assertTrue(all(r.status == "blocked" for r in results if r.group in ("invariant", "replay")), not_passed(results))
        # the control: the same names under the franken_control binary
        self.assertEqual(rc.exit_code(judge_logs(cargo_log(all_names()))[1]), 0)

    def test_a_name_in_two_sections_that_cannot_be_attributed_stays_blocked(self):
        names = all_names()
        two = "\n".join(section(names) + section(names[:2])) + "\n"   # no `Running` headers at all: attribution is unavailable
        by, results, _ = judge_logs(two)
        ambiguous = [r for r in results if r.status == "blocked" and "more than one test section" in r.detail]
        self.assertTrue(ambiguous, not_passed(results))
        self.assertEqual(rc.exit_code(results), 3)
        once = "\n".join(section(names)) + "\n"                          # the control: each name once passes without headers
        self.assertEqual(rc.exit_code(judge_logs(once)[1]), 0)

    def test_a_filtered_run_that_reports_only_some_modules_blocks_the_rest(self):
        server = [n for n in all_names() if n.startswith("fsonos::server::")]
        by, results, _ = judge_logs(cargo_log(server))
        self.assertEqual(rc.exit_code(results), 3)
        self.assertEqual(by["G03-REPLAY"].status, "blocked")
        self.assertEqual(rc.exit_code(judge_logs(cargo_log(all_names()))[1]), 0)    # the control: the whole run qualifies


class Failed(unittest.TestCase):
    def a_claimed_test(self):
        info = rc.derive_tests()
        name = next(n for n, i in sorted(info.items()) if claiming("%s::%s" % (i["module"], i["function"])))
        return name, claiming("%s::%s" % (info[name]["module"], info[name]["function"]))

    def test_a_failed_test_fails_its_cases_and_exits_one(self):
        name, cases = self.a_claimed_test()
        by, results, _ = judge_logs(cargo_log(all_names(), failed=(name,)))
        self.assertEqual(sorted(c for c, r in by.items() if r.status == "failed" and r.group == "invariant"), cases)
        self.assertIn(name + ": FAILED", by[cases[0]].detail)
        self.assertEqual(rc.exit_code(results), 1)

    def test_a_failure_outranks_a_block(self):
        name, _ = self.a_claimed_test()
        other = next(n for n in all_names() if n != name and n.startswith("fsonos::replay::"))
        _, results, _ = judge_logs(cargo_log(all_names(), failed=(name,), skip=(other,)))
        self.assertTrue(any(r.status == "blocked" for r in results))
        self.assertEqual(rc.exit_code(results), 1)

    def test_conflicting_results_across_logs_fail_both_the_case_and_the_logs_check(self):
        name, cases = self.a_claimed_test()
        by, results, _ = judge_logs(cargo_log(all_names()), cargo_log(all_names(), failed=(name,)))
        self.assertEqual(by[cases[0]].status, "failed")
        self.assertIn("CONFLICT", by[cases[0]].detail)
        self.assertEqual(by["G03-META-LOGS-CONSISTENT"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)

    def test_the_same_log_given_twice_is_read_once_and_is_not_a_conflict(self):
        text = cargo_log(all_names())
        by, results, _ = judge_logs(text, text)
        self.assertEqual(rc.exit_code(results), 0, not_passed(results))
        self.assertIn("repeated log input read once", by["G03-META-LOGS-CONSISTENT"].detail)

    def test_a_log_that_reports_a_test_these_sources_do_not_have_is_a_log_from_other_sources(self):
        foreign = "fsonos::ssdp_not_in_these_sources::tests::a_test_from_a_later_revision"
        by, results, _ = judge_logs(cargo_log(all_names(), extra=(foreign,)))
        self.assertEqual(by["G03-META-LOG-BELONGS"].status, "failed")
        self.assertIn(foreign, by["G03-META-LOG-BELONGS"].detail)
        self.assertEqual(rc.exit_code(results), 1)
        by, results, _ = judge_logs(cargo_log(all_names()))          # the control
        self.assertEqual(by["G03-META-LOG-BELONGS"].status, "passed")
        # tests outside fsonos:: are other crates' business and never make a log foreign
        by, _, _ = judge_logs(cargo_log(all_names(), extra=("channel::x::tests::unrelated",)))
        self.assertEqual(by["G03-META-LOG-BELONGS"].status, "passed")

    def test_a_failed_test_names_its_first_causal_event_in_both_log_shapes(self):
        name, cases = self.a_claimed_test()
        other = next(n for n in all_names() if n != name)
        base = cargo_log(all_names(), failed=(name,))
        loc = "crates/franken-control/src/fsonos/xml.rs:9:9:"
        want_at = "thread '%s' panicked at %s" % (name, loc)
        block = ["", "failures:", "", "---- %s stdout ----" % name, "thread '%s' panicked at %s" % (name, loc),
                 "assertion `left == right` failed", "  left: 1", " right: 2", "", "failures:", "    %s" % name, ""]
        live = ["thread '%s' (4242) panicked at %s" % (name, loc), "assertion `left == right` failed", "  left: 1", " right: 2",
                "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"]
        lines = base.split("\n")

        def detail(text):
            by, _, _ = judge_logs(text)
            self.assertEqual(by[cases[0]].status, "failed")
            return by[cases[0]].detail

        shapes = (("failure block", base + "\n".join(block) + "\n"),                  # cargo's report, no --nocapture
                  ("live, between lines", "\n".join(lines[:5] + live + lines[5:])),   # --nocapture, stderr as it happens
                  ("live, separate stream", base + "\n".join(live) + "\n"))           # RCH delivers stderr apart
        for label, text in shapes:
            got = detail(text)
            self.assertIn("first causal event ", got, label)
            self.assertIn(want_at, got, label)
            self.assertIn("assertion `left == right` failed", got, label)
            self.assertNotIn("RUST_BACKTRACE", got, label)
        wrong = "\n".join(lines[:5] + [l.replace(name, other) for l in live] + lines[5:])   # another test's panic is not this test's cause
        self.assertNotIn("first causal event", detail(wrong))
        self.assertNotIn("first causal event", detail(base))                          # the control: no panic in the log, no cause claimed


def put(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def read(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


class SourceMap(unittest.TestCase):
    """The map between the sources, the invariants and the crate: each defect found without any log, each paired with its control."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = os.path.join(self._tmp.name, "repo")
        os.makedirs(os.path.join(self.repo, rc.FSONOS_REL))
        os.makedirs(os.path.join(self.repo, "tests", "g03"))
        shutil.copyfile(os.path.join(ROOT, rc.CASES_REL), os.path.join(self.repo, rc.CASES_REL))
        for name in rc.fsonos_files(ROOT):
            shutil.copyfile(os.path.join(FSONOS, name), os.path.join(self.repo, rc.FSONOS_REL, name))
        put(self.repo, rc.LIB_REL, "pub mod channel;\npub mod fsonos;\npub mod logfile;\n")

    def judge(self, *texts):
        return judge_logs(*texts, repo=self.repo)

    def test_the_copied_tree_is_a_valid_baseline(self):
        by, results, _ = self.judge(cargo_log(all_names(self.repo)))
        self.assertEqual(rc.exit_code(results), 0, not_passed(results))
        self.assertEqual(rc.exit_code(self.judge()[1]), 3)       # and with no log it is blocked, not failed

    def test_a_claimed_test_that_the_sources_do_not_define_fails_the_claiming_case_even_with_no_log(self):
        info = rc.derive_tests(self.repo)
        name = next(n for n, i in sorted(info.items()) if claiming("%s::%s" % (i["module"], i["function"]), self.repo))
        module, function = info[name]["module"], info[name]["function"]
        rel = "%s/%s.rs" % (rc.FSONOS_REL, module)
        text = read(self.repo, rel)
        self.assertEqual(text.count("fn %s(" % function), 1)
        put(self.repo, rel, text.replace("fn %s(" % function, "fn %s_renamed(" % function))
        by, results, _ = self.judge()
        hit = claiming("%s::%s" % (module, function), self.repo)
        for case_id in hit:
            self.assertEqual(by[case_id].status, "failed", case_id)
            self.assertIn("map defect", by[case_id].detail)
            self.assertIn("%s::%s" % (module, function), by[case_id].detail)
        self.assertEqual(rc.exit_code(results), 1)
        # the renamed test is not lost: no invariant names it, so the catch-all requires it
        catch_all = next(c for c in rc.registry(rc.load_cases(self.repo)[0], rc.derive_tests(self.repo)) if c["id"] == "G03-UNCLAIMED-UNIT")
        self.assertIn(name + "_renamed", catch_all["tests"])

    def test_a_test_file_no_mod_declares_is_never_compiled_and_fails_the_wiring_check(self):
        put(self.repo, rc.FSONOS_REL + "/extra.rs", "#[cfg(test)]\nmod tests {\n    #[test]\n    fn extra_one() {}\n}\n")
        by, results, _ = self.judge(cargo_log(all_names(self.repo)))
        self.assertEqual(by["G03-META-WIRED"].status, "failed")
        self.assertIn("extra.rs is not declared in mod.rs", by["G03-META-WIRED"].detail)
        self.assertEqual(rc.exit_code(results), 1)
        # the control: declared, the file is wired, and its test is judged without anyone editing the judge
        mod = read(self.repo, rc.FSONOS_REL + "/mod.rs")
        put(self.repo, rc.FSONOS_REL + "/mod.rs", mod.replace("pub mod actions;", "pub mod actions;\npub mod extra;"))
        names = all_names(self.repo)
        self.assertIn("fsonos::extra::tests::extra_one", names)
        by, results, _ = self.judge(cargo_log([n for n in names if n != "fsonos::extra::tests::extra_one"]))
        self.assertEqual(by["G03-META-WIRED"].status, "passed")
        self.assertEqual(by["G03-UNCLAIMED-UNIT"].status, "blocked")
        self.assertIn("fsonos::extra::tests::extra_one: not reported", by["G03-UNCLAIMED-UNIT"].detail)
        by, results, _ = self.judge(cargo_log(names))
        self.assertEqual(rc.exit_code(results), 0, not_passed(results))
        by, results, _ = self.judge(cargo_log(names, failed=("fsonos::extra::tests::extra_one",)))
        self.assertEqual(by["G03-UNCLAIMED-UNIT"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)

    def test_a_commented_out_mod_line_does_not_declare_a_file(self):
        mod = read(self.repo, rc.FSONOS_REL + "/mod.rs")
        self.assertIn("pub mod soap;", mod)
        put(self.repo, rc.FSONOS_REL + "/mod.rs", mod.replace("pub mod soap;", "// pub mod soap;"))
        by, _, _ = self.judge()
        self.assertEqual(by["G03-META-WIRED"].status, "failed")
        self.assertIn("soap.rs", by["G03-META-WIRED"].detail)

    def test_the_crate_must_declare_the_fsonos_module(self):
        for text in ("pub mod channel;\n", "pub mod channel;\n// pub mod fsonos;\n", ""):
            put(self.repo, rc.LIB_REL, text)
            by, results, _ = self.judge()
            self.assertEqual(by["G03-META-WIRED"].status, "failed", repr(text))
            self.assertIn("pub mod fsonos;", by["G03-META-WIRED"].detail)
            self.assertEqual(rc.exit_code(results), 1)
        put(self.repo, rc.LIB_REL, "pub mod fsonos;\n")                       # the control
        self.assertEqual(self.judge()[0]["G03-META-WIRED"].status, "passed")
        os.remove(os.path.join(self.repo, rc.LIB_REL))
        by, _, _ = self.judge()
        self.assertEqual(by["G03-META-WIRED"].status, "failed")
        self.assertIn("unreadable", by["G03-META-WIRED"].detail)

    def test_a_replay_file_with_no_test_cannot_pass_as_the_rust_replay(self):
        put(self.repo, rc.FSONOS_REL + "/replay.rs", "// the replay was emptied\n")
        by, results, _ = self.judge(cargo_log(all_names(self.repo)))
        self.assertEqual(by["G03-REPLAY"].status, "failed")
        self.assertIn("map defect", by["G03-REPLAY"].detail)
        self.assertEqual(rc.exit_code(results), 1)

    def test_a_source_tree_with_no_test_at_all_is_not_a_pass(self):
        for name in rc.fsonos_files(self.repo):
            put(self.repo, rc.FSONOS_REL + "/" + name, "// emptied\n")
        by, results, _ = self.judge(cargo_log([]))
        self.assertEqual(by["G03-META-WIRED"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)

    def test_every_way_the_invariant_map_can_be_unfit_is_a_failed_meta_case_and_plans_no_rust_case(self):
        good = json.loads(read(self.repo, rc.CASES_REL))
        self.assertEqual(rc.cases_problems(good), [])

        def mutated(fn):
            doc = json.loads(json.dumps(good))
            fn(doc)
            return rc.cases_problems(doc)

        first = lambda d: d["invariants"][0]
        plants = [
            ("wrong schema", lambda d: d.update(schema="ffw.g03.cases.v0"), "schema is"),
            ("wrong bead", lambda d: d.update(bead="ffw-other"), "bead is"),
            ("no invariants", lambda d: d.update(invariants=[]), "no invariants"),
            ("not a list", lambda d: d.update(invariants={}), "no invariants"),
            ("duplicate id", lambda d: d["invariants"].append(dict(first(d))), "duplicate id"),
            ("malformed id", lambda d: first(d).update(id="I01"), "is not G03-<letter><nn>"),
            ("id with no number", lambda d: first(d).update(id="G03-S"), "is not G03-<letter><nn>"),
            ("no statement", lambda d: first(d).update(statement="  "), "no statement"),
            ("no rust test", lambda d: first(d).update(rust_tests=[]), "names no Rust test"),
            ("rust tests missing", lambda d: first(d).pop("rust_tests"), "names no Rust test"),
            ("malformed claim", lambda d: first(d).update(rust_tests=["just_a_function"]), "is not module::function"),
            ("listed twice", lambda d: first(d).update(rust_tests=first(d)["rust_tests"][:1] * 2), "lists a Rust test twice"),
            ("not an object", lambda d: d["invariants"].append("x"), "is not an object"),
        ]
        for label, plant, expected in plants:
            problems = mutated(plant)
            self.assertTrue(any(expected in p for p in problems), (label, problems))
        # through the runner: a malformed file fails G03-META-CASES and no invariant case is planned (so none can pass)
        doc = json.loads(json.dumps(good))
        doc["invariants"][0]["rust_tests"] = []
        put(self.repo, rc.CASES_REL, json.dumps(doc))
        by, results, meta = self.judge(cargo_log(all_names(self.repo)))
        self.assertEqual(by["G03-META-CASES"].status, "failed")
        self.assertFalse([r for r in results if r.group == "invariant"])
        self.assertEqual(rc.exit_code(results), 1)
        put(self.repo, rc.CASES_REL, "{ not json")
        self.assertEqual(self.judge()[0]["G03-META-CASES"].status, "failed")
        os.remove(os.path.join(self.repo, rc.CASES_REL))
        self.assertEqual(self.judge()[0]["G03-META-CASES"].status, "failed")
        shutil.copyfile(os.path.join(ROOT, rc.CASES_REL), os.path.join(self.repo, rc.CASES_REL))   # the control
        self.assertEqual(self.judge()[0]["G03-META-CASES"].status, "passed")


class Offline(unittest.TestCase):
    """The Python side runs as bounded subprocesses: a failure, a hang and a check that ran nothing are failures, never passes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def script(self, name, body):
        return put(self.dir, name, body)

    def check(self, argv, tier="smoke", **extra):
        return dict(id="G03-META-STUB", tier=tier, argv=[sys.executable, "-B", "-I"] + argv, what="a stub", **extra)

    def test_exit_zero_passes_and_its_last_line_is_the_detail(self):
        path = self.script("ok.py", "print('model: PASS (106/106 vectors)')\n")
        result = rc.judge_offline(self.check([path]), self.dir, "smoke")
        self.assertEqual((result.status, result.detail), ("passed", "model: PASS (106/106 vectors)"))

    def test_a_nonzero_exit_fails_and_keeps_the_fail_lines_and_the_last_lines(self):
        path = self.script("bad.py", "import sys\nprint('FAIL: vector v7: expected 3 got 4')\nprint('FAIL: vector v9: expected 1 got 2')\n"
                                     "print('noise'); print('G03 reference model: FAIL (2/106 vectors)')\nsys.exit(1)\n")
        result = rc.judge_offline(self.check([path]), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        for text in ("exit 1", "FAIL: vector v7", "FAIL: vector v9", "FAIL (2/106 vectors)"):
            self.assertIn(text, result.detail)

    def test_a_hang_is_killed_and_fails_within_the_bound(self):
        path = self.script("hang.py", "import time\nprint('started', flush=True)\ntime.sleep(60)\n")
        with mock.patch.dict(rc.OFFLINE_TIMEOUT_S, {"smoke": 1}):
            result = rc.judge_offline(self.check([path]), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        self.assertIn("timed out after 1s", result.detail)
        self.assertIn("started", result.detail)

    def test_output_is_bounded(self):
        path = self.script("loud.py", "import sys\nprint('FAIL: ' + 'x' * 100000)\nfor i in range(20000):\n    print('line', i)\nsys.exit(2)\n")
        result = rc.judge_offline(self.check([path]), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        self.assertLess(len(result.detail), rc.DETAIL_CHARS + 120)
        self.assertIn("more chars]", result.detail)

    def test_a_judge_started_by_an_offline_check_refuses_to_start_more_checks(self):
        path = self.script("env.py", "import os\nprint('child=' + os.environ.get(%r, 'unset'))\n" % rc.CHILD_ENV)
        self.assertEqual(rc.judge_offline(self.check([path]), self.dir, "smoke").detail, "child=1")   # every check runs marked as a child
        with mock.patch.dict(os.environ, {rc.CHILD_ENV: "1"}):
            result = rc.judge_offline(self.check([path]), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        self.assertIn("recursion", result.detail)

    def test_a_check_that_cannot_start_fails(self):
        result = rc.judge_offline(dict(id="G03-META-STUB", tier="smoke", argv=[os.path.join(self.dir, "nope"), "x"], what="x"), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        self.assertIn("cannot run", result.detail)

    def test_a_unittest_run_that_ran_no_tests_is_not_a_pass(self):
        silent = self.script("none.py", "import sys\nsys.stderr.write('Ran 0 tests in 0.000s\\n\\nNO TESTS RAN\\n')\n")
        result = rc.judge_offline(self.check([silent], unittest=True), self.dir, "smoke")
        self.assertEqual(result.status, "failed")
        self.assertIn("ran no tests", result.detail)
        some = self.script("some.py", "import sys\nsys.stderr.write('Ran 3 tests in 0.001s\\n\\nOK\\n')\n")
        self.assertEqual(rc.judge_offline(self.check([some], unittest=True), self.dir, "smoke").status, "passed")   # the control

    def test_the_re_measurement_must_equal_the_recorded_matrix(self):
        recorded = {"actions": [{"service": "AVTransport", "action": "Play", "sites": 3}]}
        put(self.dir, "tests/g03/usage_matrix.json", json.dumps(recorded))
        same = self.script("same.py", "import json\nprint(json.dumps(%r))\n" % (recorded,))
        other = self.script("other.py", "import json\nprint(json.dumps({'actions': []}))\n")
        junk = self.script("junk.py", "print('not json')\n")
        self.assertEqual(rc.judge_offline(self.check([same], remeasure="x"), self.dir, "smoke").status, "passed")
        for path, why in ((other, "differs"), (junk, "did not print JSON")):
            result = rc.judge_offline(self.check([path], remeasure="x"), self.dir, "smoke")
            self.assertEqual(result.status, "failed")
            self.assertIn(why, result.detail)

    def test_checks_are_discovered_from_the_directory_and_the_judges_own_tests_are_left_out(self):
        g03 = os.path.join(self.dir, "tests", "g03")
        for name in ("test_alpha_model.py", "test_beta.py", rc.SELF_TEST, "helper.py", "notes.txt"):
            put(g03, name, "")
        ids = [c["id"] for c in rc.offline_checks(self.dir)]
        self.assertEqual(ids, ["G03-META-USAGE-RECORDED", "G03-META-REFERENCE", "G03-META-UNIT-ALPHA-MODEL", "G03-META-UNIT-BETA"])
        tiers = {c["id"]: c["tier"] for c in rc.offline_checks(self.dir)}
        self.assertEqual((tiers["G03-META-REFERENCE"], tiers["G03-META-UNIT-BETA"]), ("smoke", "full"))
        self.assertIn("G03-META-USAGE-REMEASURED", [c["id"] for c in rc.offline_checks(self.dir, measure="/some/checkout")])
        self.assertNotIn("G03-META-USAGE-REMEASURED", ids)

    def tree_with_stubs(self, unit_body):
        repo = os.path.join(self.dir, "repo")
        g03 = os.path.join(repo, "tests", "g03")
        put(g03, "measure_usage.py", "print('usage ok')\n")
        put(g03, "reference.py", "print('reference ok')\n")
        put(g03, "test_stub_model.py", unit_body)
        shutil.copyfile(os.path.join(ROOT, rc.CASES_REL), os.path.join(g03, "cases.json"))
        os.makedirs(os.path.join(repo, rc.FSONOS_REL))
        for name in rc.fsonos_files(ROOT):
            shutil.copyfile(os.path.join(FSONOS, name), os.path.join(repo, rc.FSONOS_REL, name))
        put(repo, rc.LIB_REL, "pub mod fsonos;\n")
        return repo

    def test_smoke_runs_the_vector_and_usage_checks_and_full_adds_every_model_check(self):
        passing = "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertTrue(True)\n"
        repo = self.tree_with_stubs(passing)
        good = cargo_log(all_names(repo))
        for tier, ids in (("smoke", ["G03-META-USAGE-RECORDED", "G03-META-REFERENCE"]),
                          ("full", ["G03-META-USAGE-RECORDED", "G03-META-REFERENCE", "G03-META-UNIT-STUB-MODEL"])):
            with tempfile.TemporaryDirectory() as d:
                path = put(d, "c.log", good)
                logs = rc.Logs()
                logs.add(path)
                results, _ = rc.run(tier, logs, repo)
            offline = [r.case_id for r in results if r.group == "offline"]
            self.assertEqual(offline, ids, tier)
            self.assertEqual(rc.exit_code(results), 0, not_passed(results))

    def test_a_failing_model_check_fails_the_run_at_full_and_the_rust_half_cannot_hide_it(self):
        failing = "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertEqual(1, 2)\n"
        repo = self.tree_with_stubs(failing)
        with tempfile.TemporaryDirectory() as d:
            logs = rc.Logs()
            logs.add(put(d, "c.log", cargo_log(all_names(repo))))
            smoke, _ = rc.run("smoke", logs, repo)
            full, _ = rc.run("full", logs, repo)
        self.assertEqual(rc.exit_code(smoke), 0, "the model check is the full tier's, and the control passes smoke")
        by = {r.case_id: r for r in full}
        self.assertEqual(by["G03-META-UNIT-STUB-MODEL"].status, "failed")
        self.assertIn("FAIL: test_x", by["G03-META-UNIT-STUB-MODEL"].detail)
        self.assertEqual(rc.exit_code(full), 1)

    def test_the_real_checks_pass_in_the_real_tree(self):
        by = {c["id"]: c for c in rc.offline_checks(ROOT)}
        for case_id in ("G03-META-USAGE-RECORDED", "G03-META-REFERENCE"):
            result = rc.judge_offline(by[case_id], ROOT, "smoke")
            self.assertEqual((result.case_id, result.status), (case_id, "passed"), result.detail)
        self.assertIn("G03-META-UNIT-REFERENCE-MODEL", by)
        self.assertNotIn("G03-META-UNIT-RUN-CASES", by)


class Entry(unittest.TestCase):
    """main(): tiers, exit codes, the log next to the receipt, the open gate and what a non-pass keeps."""

    # Written out by hand, so that a file silently dropped from the judge's own list is noticed: the verdict rests on these bytes.
    MUST_BIND = (
        "tests/g03/cases.json", "tests/g03/reference.py", "tests/g03/measure_usage.py", "tests/g03/usage_matrix.json",
        "tests/g03/run_cases.py", "tests/g03/case_log.py", "tests/g03/test_reference_model.py", "tests/g03/test_run_cases.py",
        "tests/d01/run_cases.py", "scripts/test/test_support/diagnostics.py", "docs/contracts/g03.md", "Cargo.lock", "rust-toolchain.toml",
        "crates/franken-control/Cargo.toml", "crates/franken-control/src/lib.rs", "crates/franken-control/src/fsonos/mod.rs",
        "crates/franken-control/src/fsonos/xml.rs", "crates/franken-control/src/fsonos/soap.rs", "crates/franken-control/src/fsonos/actions.rs",
        "crates/franken-control/src/fsonos/state.rs", "crates/franken-control/src/fsonos/gena.rs", "crates/franken-control/src/fsonos/server.rs",
        "crates/franken-control/src/fsonos/replay.rs", "crates/franken-control/tests/vectors/g03_vectors.json",
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name
        self.good = put(self.dir, "good.log", cargo_log(all_names()))

    @staticmethod
    def sha(path):
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def diag(self):
        return rc.case_log.load(ROOT)

    # ---- tiers and exit codes

    def test_the_default_tier_with_no_rust_evidence_exits_three_and_says_why(self):
        code, out, err = self.run_main([])
        self.assertEqual(code, 3, out)
        self.assertEqual(err, "")
        self.assertIn("BLOCKED  G03-I01  no cargo test log supplied", out)
        self.assertIn("NOT QUALIFIED", out)
        self.assertIn("RETAINED FOR REPLAY. First blocked case: ", out)
        self.assertIn("  replay: scripts/e2e/g03 --tier full\n", out)

    def test_a_good_log_qualifies_at_smoke_and_full_and_always_reports_the_actual_client_gate_open(self):
        for tier in ("smoke", "full"):
            code, out, _ = self.run_main(["--tier", tier, "--judge", self.good])
            self.assertEqual(code, 0, out)
            self.assertIn("QUALIFIED", out)
            self.assertNotIn("NOT QUALIFIED", out)
            self.assertIn("OPEN     actual_fsonos_client: no actual fsonos controller has been run against this endpoint", out)
            self.assertIn("the actual-client gate stays OPEN", out)
            self.assertNotIn("RETAINED", out)
        code, out, _ = self.run_main(["--tier", "full"])          # blocked runs say it too
        self.assertIn("OPEN     actual_fsonos_client", out)

    def test_the_soak_tier_is_not_run_exits_four_and_writes_nothing(self):
        receipts = os.path.join(self.dir, "receipts")
        code, out, _ = self.run_main(["--tier", "soak", "--judge", self.good, "--receipts", receipts])
        self.assertEqual(code, 4)
        self.assertIn("G03 soak: NOT RUN", out)
        self.assertIn("This is not a pass.", out)
        self.assertFalse(os.path.exists(receipts))
        self.assertNotIn("QUALIFIED", out.replace("NOT RUN", ""))

    def test_usage_errors_exit_two(self):
        self.assertEqual(self.run_main(["--judge", os.path.join(self.dir, "missing.log")])[0], 2)
        self.assertEqual(self.run_main(["--tier", "nightly"])[0], 2)
        self.assertEqual(self.run_main(["--no-such-flag"])[0], 2)

    def test_list_names_every_planned_case_and_runs_nothing(self):
        code, out, _ = self.run_main(["--list"])
        self.assertEqual(code, 0)
        ids = out.split()
        for want in ("G03-META-CASES", "G03-META-WIRED", "G03-META-REFERENCE", "G03-META-UNIT-REFERENCE-MODEL", "G03-REPLAY"):
            self.assertIn(want, ids)
        self.assertEqual([i for i in ids if rc.INVARIANT_ID.match(i)], [inv["id"] for inv in invariants()])
        smoke = self.run_main(["--list", "--tier", "smoke"])[1].split()
        self.assertNotIn("G03-META-UNIT-REFERENCE-MODEL", smoke)
        self.assertEqual(self.run_main(["--list", "--tier", "soak"])[0], 4)

    # ---- what a run keeps

    def test_every_run_writes_a_complete_jsonl_log_next_to_its_receipt_and_the_header_binds_the_artifacts(self):
        receipts = os.path.join(self.dir, "receipts")
        code, out, _ = self.run_main(["--tier", "full", "--judge", self.good, "--receipts", receipts])
        self.assertEqual(code, 0, out)
        names = sorted(os.listdir(receipts))
        (receipt_name,) = [n for n in names if n.endswith(".json")]
        (diag_name,) = [n for n in names if n.endswith(".jsonl")]
        with open(os.path.join(receipts, receipt_name), encoding="utf-8") as fh:
            receipt = json.load(fh)
        run_id = receipt["run_id"]
        self.assertEqual(diag_name, "g03-diag-full-%s.jsonl" % run_id)
        path = os.path.join(receipts, diag_name)
        audit = self.diag().audit_log(path)                 # the shared module's own re-read of the file
        cases = len(receipt["results"])
        self.assertTrue(audit.complete, audit.reasons)
        self.assertEqual(audit.critical_events, 2 * cases + 1)
        self.assertEqual(receipt["diagnostics"]["log"]["sha256"], self.sha(path))
        self.assertEqual((receipt["diagnostics"]["complete"], receipt["exit_code"]), (True, 0))
        self.assertEqual([g["item"] for g in receipt["open_gates"]][0], "actual_fsonos_client")
        self.assertEqual(receipt["open_gates"][0]["status"], "OPEN")
        self.assertEqual(receipt["judged_logs"], [{"path": "good.log", "sha256": self.sha(self.good)}])
        self.assertEqual(receipt["replay"], "scripts/e2e/g03 --tier full --judge good.log")
        self.assertEqual(receipt["versions"], {"python": sys.version.split()[0], "receipt_schema": rc.RECEIPT_SCHEMA,
                                               "cases_schema": rc.CASES_SCHEMA})
        self.assertEqual(receipt["planned_rust_tests"], len(all_names()))
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual(records[0]["schema"], "ff.diag.v1")
        want_set = hashlib.sha256("".join("%s %s\n" % (rel, self.sha(os.path.join(ROOT, rel)))
                                          for rel in sorted(receipt["artifacts"])).encode()).hexdigest()
        self.assertEqual(records[0]["extra"]["artifact_set_sha256"], want_set)
        self.assertEqual(records[0]["extra"]["cases_sha256"], self.sha(os.path.join(ROOT, rc.CASES_REL)))
        begins = {r["case"]: r for r in records if r.get("kind") == "case.begin"}
        ends = {r["case"]: r for r in records if r.get("kind") == "case.end"}
        self.assertEqual((len(begins), set(begins)), (cases, set(ends)))
        by_id = {r["id"]: r for r in receipt["results"]}
        for case_id, end in ends.items():
            self.assertEqual(end["corr"], begins[case_id]["corr"])
            self.assertEqual(end["fields"]["status"], by_id[case_id]["status"], case_id)
        # a rerun never overwrites the first run's evidence
        self.assertEqual(self.run_main(["--tier", "full", "--judge", self.good, "--receipts", receipts])[0], 0)
        self.assertEqual(len([n for n in os.listdir(receipts) if n.endswith(".jsonl")]), 2)

    def test_lost_critical_evidence_makes_a_run_that_would_pass_not_qualified(self):
        _, results, meta = judge_logs(cargo_log(all_names()))
        self.assertEqual(rc.exit_code(results), 0)
        diag = self.diag()

        def evidence(target):
            log = rc.case_log.CaseLog.open(ROOT, "t1", "full", target=target)
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            return log.finish(rc.summarize(results))

        whole = evidence(diag.FaultableSink())
        self.assertTrue(whole.complete, whole.reasons)                       # control: a sink that takes every write
        self.assertEqual(rc.final_exit(results, whole), 0)
        full = evidence(diag.FaultableSink(capacity_bytes=6000))             # the plant: a disk that fills long before the run ends
        self.assertFalse(full.complete)
        self.assertTrue(any("critical" in reason for reason in full.reasons), full.reasons)
        self.assertEqual(rc.final_exit(results, full), 1)
        meta["versions"], meta["artifacts"] = rc.versions(), rc.artifact_digests()
        shown = self._report(results, meta, full)
        self.assertIn("NOT QUALIFIED  planned", shown)
        self.assertIn("diagnostic evidence INCOMPLETE", shown)
        self.assertIn("QUALIFIED (offline side", self._report(results, meta, whole))
        failing = [rc.Result("G03-X", "failed", "x", "meta")] + results      # a failure is a failure whatever the log says
        self.assertEqual((rc.final_exit(failing, full), rc.final_exit(failing, whole)), (1, 1))

    def _report(self, results, meta, evidence):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc.report(results, "full", None, meta, evidence)
        return out.getvalue()

    def test_a_case_that_wrote_no_events_is_caught_by_the_independent_count(self):
        diag = self.diag()

        def evidence(extra_case):
            log = rc.case_log.CaseLog.open(ROOT, "t3", "full", target=diag.FaultableSink())
            for n in range(3):
                log.record("G03-X-%d" % n, "meta", "passed", "")
            if extra_case:
                log.cases += 1                     # a case the judge decided and that never reached the log
            return log.finish({"passed": 4, "failed": 0, "blocked": 0})

        self.assertTrue(evidence(False).complete)  # control
        missing = evidence(True)
        self.assertFalse(missing.complete)
        self.assertEqual(missing.reasons, ["critical_event_count:7_of_9"])

    def test_an_unavailable_diagnostics_module_is_an_incomplete_log_not_a_crash(self):
        empty_repo = tempfile.mkdtemp(dir=self.dir)      # a tree with no scripts/test/test_support/diagnostics.py
        log = rc.case_log.CaseLog.open(empty_repo, "t2", "full")
        log.record("G03-X", "meta", "passed", "")
        evidence = log.finish({"passed": 1, "failed": 0, "blocked": 0})
        self.assertFalse(evidence.complete)
        self.assertTrue(evidence.reasons[0].startswith("diagnostics_unavailable"), evidence.reasons)
        _, results, _ = judge_logs(cargo_log(all_names()))
        self.assertEqual(rc.final_exit(results, evidence), 1)

    def test_an_unwritable_receipts_directory_is_a_verdict_not_a_traceback(self):
        blocker = put(self.dir, "blocker", "a regular file, so nothing can be created under it")
        code, out, err = self.run_main(["--tier", "full", "--judge", self.good, "--receipts", os.path.join(blocker, "sub")])
        self.assertEqual(code, 1)
        self.assertIn("NOT QUALIFIED", out)
        self.assertIn("receipts_unavailable:", out)
        self.assertIn("the receipt could not be written", err)
        code, out, err = self.run_main(["--tier", "full", "--judge", self.good, "--receipts", os.path.join(self.dir, "fine")])   # control
        self.assertEqual((code, err), (0, ""))

    def test_main_exits_one_when_the_log_lost_critical_evidence_even_though_every_case_passed(self):
        real_open = rc.case_log.CaseLog.open
        sink = self.diag().FaultableSink

        def tiny_disk(repo, run_id, tier, receipts=None, **kw):       # the plant: a log target that fills long before the run ends
            return real_open(repo, run_id, tier, target=sink(capacity_bytes=3000), **kw)

        with mock.patch.object(rc.case_log.CaseLog, "open", staticmethod(tiny_disk)):
            code, out, _ = self.run_main(["--tier", "full", "--judge", self.good])
        self.assertEqual(code, 1, out)
        self.assertIn("diagnostic evidence INCOMPLETE", out)
        self.assertIn("NOT QUALIFIED", out)
        self.assertEqual(self.run_main(["--tier", "full", "--judge", self.good])[0], 0)   # the control: the same run with a sound log

    def test_a_receipt_that_cannot_be_written_after_a_passing_run_is_a_failure_not_a_pass(self):
        receipts = os.path.join(self.dir, "receipts")
        with mock.patch.object(rc, "write_receipt", side_effect=OSError("disk full")):
            code, out, err = self.run_main(["--tier", "full", "--judge", self.good, "--receipts", receipts])
        self.assertEqual(code, 1, out)
        self.assertIn("the receipt could not be written", err)
        self.assertEqual(self.run_main(["--tier", "full", "--judge", self.good, "--receipts", receipts])[0], 0)   # the control

    def test_a_failing_run_prints_the_replay_command_the_versions_and_digests_that_equal_the_files(self):
        name = next(n for n in all_names() if n.startswith("fsonos::xml::"))
        bad = put(self.dir, "corrupt.log", cargo_log(all_names(), failed=(name,)))
        code, out, _ = self.run_main(["--tier", "full", "--judge", bad])
        self.assertEqual(code, 1)
        lines = out.splitlines()
        (first,) = [l for l in lines if l.startswith("RETAINED FOR REPLAY.")]
        self.assertTrue(first.startswith("RETAINED FOR REPLAY. First failed case: G03-I"), first)
        self.assertIn(name + ": FAILED", first)
        self.assertIn("  replay: scripts/e2e/g03 --tier full --judge corrupt.log", lines)
        self.assertIn("  judged log corrupt.log sha256 %s" % self.sha(bad), lines)
        self.assertIn("  versions: python %s; receipt %s; cases %s" % (sys.version.split()[0], rc.RECEIPT_SCHEMA, rc.CASES_SCHEMA), lines)
        shown = {l.split()[1]: l.split()[3] for l in lines if l.startswith("  artifact ")}
        self.assertEqual(set(shown), set(rc.artifact_digests()))
        self.assertTrue(set(self.MUST_BIND) <= set(shown), sorted(set(self.MUST_BIND) - set(shown)))
        for rel, digest in shown.items():
            self.assertEqual(digest, self.sha(os.path.join(ROOT, rel)), rel)          # recomputed here from the files
        self.assertNotIn(ROOT, out, "a retained path is relative to the repository root")
        code, out, _ = self.run_main(["--tier", "full", "--judge", self.good])        # the control: nothing to keep
        self.assertEqual(code, 0)
        self.assertNotIn("RETAINED", out)

    def test_printed_output_is_bounded_however_many_cases_are_blocked(self):
        code, out, _ = self.run_main([])
        self.assertEqual(code, 3)
        rows = [l for l in out.splitlines() if l.startswith("BLOCKED")]
        self.assertEqual(len(rows), rc.MAX_PRINTED + 1)
        self.assertRegex(rows[-1], r"\.\.\. and \d+ more blocked case\(s\)")
        self.assertLess(len(out.splitlines()), 120)


class EntryScript(unittest.TestCase):
    """scripts/e2e/g03 is the entry point the supervisor runs: with no arguments it must not exit zero without Rust evidence."""

    def run_script(self, *argv):
        script = os.path.join(ROOT, "scripts", "e2e", "g03")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if os.environ.get(rc.CHILD_ENV):          # under a judge (a regression): keep the recursion guard through the script
            env[rc.CHILD_ENV] = "1"
        done = subprocess.run(["bash", script] + list(argv), cwd=tempfile.gettempdir(), capture_output=True, text=True, timeout=300, env=env)
        return done.returncode, done.stdout, done.stderr

    def test_with_no_arguments_the_entry_point_blocks_with_a_nonzero_exit(self):
        code, out, err = self.run_script()
        self.assertEqual(code, 3, out + err)
        self.assertIn("BLOCKED  G03-I01", out)
        self.assertIn("OPEN     actual_fsonos_client", out)
        self.assertNotIn("PASS (Rust half not run", out)

    def test_the_soak_tier_and_a_missing_log_have_their_own_exit_codes(self):
        self.assertEqual(self.run_script("--tier", "soak")[0], 4)
        self.assertEqual(self.run_script("--judge", os.path.join(tempfile.gettempdir(), "no-such-g03-log"))[0], 2)

    def test_the_entry_point_is_executable_and_judges_a_log_it_is_given(self):
        self.assertTrue(os.access(os.path.join(ROOT, "scripts", "e2e", "g03"), os.X_OK))
        with tempfile.TemporaryDirectory() as d:
            good = put(d, "good.log", cargo_log(all_names()))
            code, out, err = self.run_script("--tier", "full", "--judge", good)
            self.assertEqual(code, 0, out + err)
            self.assertIn("QUALIFIED", out)
            bad = put(d, "bad.log", cargo_log(all_names(), failed=(all_names()[0],)))
            self.assertEqual(self.run_script("--tier", "full", "--judge", bad)[0], 1)


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    unittest.main()
