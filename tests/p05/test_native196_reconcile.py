"""Unit tests for native196_reconcile.py. Pure Python: no cargo, no network, no RCH.

    cd tests/p05 && python3 -B -m unittest -v test_native196_reconcile

Each planted negative has its remove-the-plant control: the same builder, un-planted, must be `complete` (see `assert_control`).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

import native196_reconcile as rec

HERE = Path(__file__).resolve().parent
REPO = rec.find_repo(os.environ.get("FFW_REPO"))
NAMES = rec.load_registry()
TARGETS = HERE / "native196_targets.tsv"
TARGETS_SHA256 = "cd2ae7d69bf0e52aba9fcc1c3189e87878b54a70b07f2bfa159d21ce3c74473c"
FILTERS = ("runtime::blocking_pool::admission::tests::", "io::stdio::tests::", "cx::scoped_race::tests::",
           "cx::scoped_timeout::tests::", "cx::scoped_first_ok::tests::", "cx::scoped_quorum::tests::",
           "runtime::legacy_profile::tests::", "runtime::spawn_blocking::tests::", "net::resolve::tests::")
FILTER_COUNTS = (51, 20, 10, 17, 15, 9, 26, 37, 11)
HEADER = "     Running unittests src/lib.rs (target/debug/deps/asupersync-0123456789abcdef)"


def libtest(names, *, results=None, declared=None, summary=True, filtered=27259, header=False, extra_lines=(), passed=None,
            failed=0, ignored=0, verdict="ok"):
    """A libtest stdout for `--lib -- <filters> --nocapture --test-threads=1`: sorted, one result per line."""
    results = results or {}
    lines = ([HEADER] if header else []) + ["", f"running {len(names) if declared is None else declared} tests"]
    for name in sorted(names):
        lines.append(f"test {name} ... {results.get(name, 'ok')}")
    lines += list(extra_lines)
    if summary:
        done = len(names) - failed - ignored if passed is None else passed
        lines += ["", f"test result: {verdict}. {done} passed; {failed} failed; {ignored} ignored; 0 measured; {filtered} filtered out; "
                      "finished in 1.52s", ""]
    return "\n".join(lines) + "\n"


class Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.count = 0

    def write(self, text: str) -> Path:
        self.count += 1
        path = self.dir / f"run{self.count}.stdout"
        path.write_text(text, encoding="utf-8")
        return path

    def judge(self, *runs, names=NAMES):
        return rec.reconcile(list(names), [rec.Run(self.write(text), code) for text, code in runs], REPO)

    def assert_control(self, names=NAMES):
        """Remove the plant: the same shape, un-planted, is complete. A negative is only credited against this."""
        report = self.judge((libtest(names), 0), names=names)
        self.assertTrue(report.complete, report.problems)
        self.assertEqual(report.ok_names, len(names))

    def assert_incomplete(self, report, *fragments):
        self.assertFalse(report.complete, "a planted defect was accepted")
        joined = "\n".join(report.problems)
        for fragment in fragments:
            self.assertIn(fragment, joined)


class RegistryAndTable(Case):
    def test_registry_is_the_frozen_196_and_is_the_digest_the_record_names(self):
        self.assertEqual(len(NAMES), 196)
        self.assertEqual(len(set(NAMES)), 196)
        self.assertEqual(hashlib.sha256(rec.REGISTRY_FILE.read_bytes()).hexdigest(), rec.REGISTRY_SHA256)
        record = (REPO / "toolchain/results/p05/20261107-byte-admission/native196.txt").read_text(encoding="utf-8")
        self.assertIn(rec.REGISTRY_SHA256, record, "the committed native196 record must name this registry digest")
        self.assertIn("Predeclared required cases: 196", record)

    def test_a_changed_registry_is_refused(self):
        path = self.dir / "names.txt"
        path.write_text("\n".join(NAMES[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            rec.load_registry(path)
        path.write_text("\n".join(NAMES + NAMES[:1]) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            rec.load_registry(path, expected_sha256=None)       # a duplicate is refused even without the digest

    def test_the_nine_filters_select_exactly_the_196_each_name_by_one_filter(self):
        per_filter = [sum(1 for name in NAMES if f in name) for f in FILTERS]
        self.assertEqual(tuple(per_filter), FILTER_COUNTS)
        self.assertEqual(sum(per_filter), 196)
        for name in NAMES:
            self.assertEqual(sum(1 for f in FILTERS if f in name), 1, name)

    def test_the_target_table_covers_the_registry_once_each_as_one_lib_target_and_graph(self):
        raw = TARGETS.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), TARGETS_SHA256)
        rows = [line.split("\t") for line in raw.decode("utf-8").splitlines() if not line.startswith("#")]
        self.assertEqual([row[0] for row in rows], NAMES)
        for row in rows:
            name, package, target, features, defined_at = row[:5]
            self.assertEqual((package, target, features), ("asupersync", "lib", "default"), name)
            self.assertRegex(defined_at, r"^src/.+\.rs:\d+$", name)
            self.assertIn(name.split("::")[-1], "".join(row[:1]))

    def test_the_parser_reads_a_real_committed_libtest_capture(self):
        """The 98-case capture committed with the byte-admission record: 98 prefixes, one real result line."""
        text = (REPO / "toolchain/results/p05/20261107-byte-admission/lint-fixed-native.txt").read_text(encoding="utf-8")
        section = text.split("Selected actual output: build 30099060530610835")[0]
        self.assertEqual(len(rec.PREFIX.findall(section)), 98)
        result = rec.RESULT.search(section)
        self.assertEqual(result.groups(), ("ok", "98", "0", "0", "0", "27283"))


class Reconcile(Case):
    def test_positive_one_clean_run_is_complete_and_reports_filtered_out(self):
        report = self.judge((libtest(NAMES), 0))
        self.assertTrue(report.complete, report.problems)
        self.assertEqual((report.ok_names, report.registry), (196, 196))
        self.assertEqual(report.runs[0][1]["filtered_out"], 27259)
        self.assertEqual(report.runs[0][1]["passed"], 196)

    def test_positive_with_a_cargo_running_header_and_stderr_lines(self):
        text = libtest(NAMES, header=True, extra_lines=())
        self.assertTrue(self.judge((text, 0)).complete)

    def test_positive_an_ansi_coloured_rch_log_is_read_after_stripping(self):
        text = "\x1b[32m  INFO rch::hook\x1b[0m: Remote command finished: exit=0 in 100ms\n" + libtest(NAMES)
        self.assertTrue(self.judge((text, 0)).complete)

    def test_positive_several_runs_that_partition_the_registry(self):
        half = len(NAMES) // 2
        report = self.judge((libtest(NAMES[:half]), 0), (libtest(NAMES[half:]), 0))
        self.assertTrue(report.complete, report.problems)
        self.assertEqual(len(report.runs), 2)

    def test_an_interrupted_result_in_a_serial_log_is_not_credited_so_the_run_is_incomplete(self):
        """`test X ... ` then a foreign line then `ok`, in a log that reports in sorted order (one test thread)."""
        names = sorted(NAMES)
        lines = ["running 196 tests"]
        for index, name in enumerate(names):
            if index in (3, 100):
                lines += [f"test {name} ... ", "FFW_RECORD something=1", "ok"]
            else:
                lines.append(f"test {name} ... ok")
        lines += ["", "test result: ok. 196 passed; 0 failed; 0 ignored; 0 measured; 27259 filtered out; finished in 1.52s", ""]
        report = self.judge(("\n".join(lines), 0))
        # In a log that reports in sorted order D01 deliberately declines to attribute an interrupted prefix (it is the test's own
        # output under one thread). That is the conservative reading: the two split tests are not credited, so the run is incomplete.
        self.assertFalse(report.complete)
        self.assertIn("not attributed", "\n".join(report.problems))

    # ---- planted negatives, each with its control ----------------------------------------------------------------------

    def test_negative_a_missing_name(self):
        gone = NAMES[57]
        report = self.judge((libtest([n for n in NAMES if n != gone], passed=195), 0))
        self.assert_incomplete(report, "never reported", gone)
        self.assertEqual(report.ok_names, 195)
        self.assert_control()

    def test_negative_a_duplicate_in_one_log(self):
        dup = NAMES[10]
        report = self.judge((libtest(NAMES, extra_lines=[f"test {dup} ... ok"], declared=196), 0))
        self.assert_incomplete(report, dup)
        self.assert_control()

    def test_negative_a_duplicate_across_two_runs(self):
        dup = NAMES[0]
        report = self.judge((libtest(NAMES[:100]), 0), (libtest(NAMES[99:]), 0))     # NAMES[99] is in both
        self.assert_incomplete(report, NAMES[99], "reported by 2 runs")
        self.assertNotIn(dup, "\n".join(report.problems))
        self.assert_control()

    def test_negative_an_unknown_extra_name(self):
        extra = "runtime::spawn_blocking::tests::a_test_nobody_registered"
        report = self.judge((libtest(NAMES + [extra]), 0))
        self.assert_incomplete(report, "outside the registry", extra)
        self.assert_control()

    def test_negative_a_failed_line(self):
        victim = NAMES[120]
        report = self.judge((libtest(NAMES, results={victim: "FAILED"}, failed=1, verdict="FAILED"), 1))
        self.assert_incomplete(report, victim, "FAILED")
        self.assertEqual(report.ok_names, 195)
        self.assert_control()

    def test_negative_an_ignored_test_is_not_a_pass(self):
        victim = NAMES[33]
        report = self.judge((libtest(NAMES, results={victim: "ignored"}, ignored=1), 0))
        self.assert_incomplete(report, victim, "ignored")
        self.assert_control()

    def test_negative_a_truncated_stdout_without_its_summary_line(self):
        cut = libtest(NAMES[:150], summary=False, declared=196)
        report = self.judge((cut, 0))
        self.assert_incomplete(report, "no `test result:` line", "never reported")
        self.assert_control()

    def test_negative_a_summary_that_accounts_for_fewer_tests_than_announced(self):
        report = self.judge((libtest(NAMES, passed=190), 0))
        self.assert_incomplete(report, "announced 196", "accounted for 190")
        self.assert_control()

    def test_negative_a_nonzero_exit_status_taken_from_outside_the_log(self):
        report = self.judge((libtest(NAMES), 137))
        self.assert_incomplete(report, "the command exited 137")
        self.assert_control()

    def test_negative_a_second_libtest_section_such_as_doc_tests(self):
        text = libtest(NAMES) + "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        report = self.judge((text, 0))
        self.assert_incomplete(report, "2 `running N tests` sections")
        self.assert_control()

    def test_negative_an_rch_external_deadline_or_unconfirmed_completion(self):
        report = self.judge(("RCH_EXTERNAL_DEADLINE fired\n" + libtest(NAMES), 0))
        self.assert_incomplete(report, "external deadline")
        report = self.judge(("remote execution completion is unconfirmed\n" + libtest(NAMES), 0))
        self.assert_incomplete(report, "completion unconfirmed")
        self.assert_control()

    def test_cli_reports_complete_only_when_complete_and_the_exit_code_follows(self):
        good, bad = self.write(libtest(NAMES)), self.write(libtest(NAMES[:-1], passed=195))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rec.main(["--run", str(good), "0", "--repo", str(REPO)]), 0)
            self.assertIn("COMPLETE: 196/196", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rec.main(["--run", str(bad), "0", "--repo", str(REPO)]), 1)
        self.assertIn("INCOMPLETE: 195/196", out.getvalue())
        self.assertNotIn("COMPLETE: 196", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            registry = self.dir / "names.txt"
            registry.write_text("x::y\n", encoding="utf-8")
            self.assertEqual(rec.main(["--run", str(good), "0", "--registry", str(registry), "--repo", str(REPO)]), 2)


# ---- the 38-name registry of the P05 runtime probe -----------------------------------------------------------------------------
# Stacked over the patch that adds `native_runtime38_names.txt` (11c74124): this module fails at import, loudly, if the list is absent.

LIST38 = rec.RUNTIME38_FILE
LIST38_SHA256 = "94be74e65f47711951368d6776a4516699d761333338db5057f881867c679ba1"      # the digest the central run is qualified against
NAMES38, PIN38 = rec.load_pinned(LIST38)
RECORDED = REPO / "toolchain/results/p05/20261108-runtime-probe"
HEADER38 = "     Running unittests src/main.rs (target/debug/deps/ffw_p05_runtime-0123456789abcdef)"
# The tests that print their transcript: under `--nocapture` their output lands between `test <name> ... ` and the token, as in the
# recorded run (native-tests.stdout.txt: native_runtime_exercises_all_phases_and_drains and two more).
PRINTERS = frozenset({
    "tests::native_runtime_exercises_all_phases_and_drains",
    "tests::single_owner_runtime_exercises_the_supported_phases_and_types_the_unsupported_one",
    "tests::the_counters_count_what_was_recorded_and_the_exit_code_never_hides_a_failure",
    "tests::a_partial_or_unknown_result_is_never_counted_as_a_pass",
})


def nocapture(names, *, printers=PRINTERS, results=None, inside=None, header=False, summary=True, declared=None, passed=None,
              failed=0, ignored=0, verdict="ok"):
    """A libtest stdout for `--nocapture --test-threads=1`: sorted; a printer's output sits between its prefix and its own-line token."""
    results, inside = results or {}, inside or {}
    lines = ([HEADER38] if header else []) + ["", f"running {len(names) if declared is None else declared} tests"]
    for name in sorted(names):
        token = results.get(name, "ok")
        if name in printers:
            lines += [f"test {name} ... FFW_P05_RUNTIME:BEGIN status=start pid=1", "FFW_P05_RUNTIME:END status=done ops=1",
                      *inside.get(name, []), token]
        else:
            lines.append(f"test {name} ... {token}")
    if summary:
        done = len(names) - failed - ignored if passed is None else passed
        lines += ["", f"test result: {verdict}. {done} passed; {failed} failed; {ignored} ignored; 0 measured; 0 filtered out; "
                      "finished in 1.52s", ""]
    return "\n".join(lines) + "\n"


class Runtime38(Case):
    def judge38(self, *runs, names=NAMES38, pinned=PIN38):
        return rec.reconcile(list(names), [rec.Run(self.write(text), code) for text, code in runs], REPO, pinned)

    def assert_control38(self, names=NAMES38):
        """Remove the plant: the same builder, un-planted, is complete with every name credited."""
        report = self.judge38((nocapture(names), 0), names=names)
        self.assertTrue(report.complete, report.problems)
        self.assertEqual(report.ok_names, len(names))

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rec.main([*argv, "--repo", str(REPO)])
        return code, out.getvalue()

    def test_the_38_registry_is_pinned_by_the_digest_the_central_run_is_qualified_against(self):
        self.assertEqual(len(NAMES38), 38)
        self.assertEqual(len(set(NAMES38)), 38)
        self.assertEqual(hashlib.sha256(LIST38.read_bytes()).hexdigest(), LIST38_SHA256)
        self.assertEqual(rec.RUNTIME38_SHA256, LIST38_SHA256)
        self.assertEqual((PIN38.label, PIN38.size, PIN38.serial_closure), ("native_runtime38", 38, True))
        self.assertLessEqual(PRINTERS, set(NAMES38), "a printer name must be a registry name")
        names196, pin196 = rec.load_pinned(rec.REGISTRY_FILE)
        self.assertEqual((names196, pin196.label, pin196.serial_closure), (NAMES, "native196", False))

    def test_positive_a_complete_38_nocapture_log_is_complete_through_the_command_line(self):
        log = self.write(nocapture(NAMES38))
        code, out = self.cli("--registry", str(LIST38), "--run", str(log), "0")
        self.assertEqual(code, 0, out)
        self.assertIn("native_runtime38: COMPLETE: 38/38 names `ok` exactly once across 1 run(s)", out)
        self.assertIn("passed=38 failed=0 ignored=0 measured=0 filtered_out=0 credited_by_closure=4", out)
        self.assert_control38()

    def test_positive_a_quiet_log_with_the_probes_own_binary_header_needs_no_credit(self):
        report = self.judge38((nocapture(NAMES38, printers=(), header=True), 0))
        self.assertTrue(report.complete, report.problems)
        self.assertNotIn("credited_by_closure", report.runs[0][1])

    def test_the_real_recorded_nocapture_log_is_refused_by_the_196_rules_and_complete_by_closure(self):
        """native-tests.stdout.txt is a real `--test-threads=1 --nocapture` log of 25 tests, 3 of which print. Without the closure credit
        the reconciler does not attribute them, so a plain registry swap would refuse a real log; with it the same log is complete."""
        names25 = rec.load_registry(RECORDED / "native-required-tests.txt", expected_sha256=None)
        runs = [rec.Run(RECORDED / "native-tests.stdout.txt", 0)]
        plain = rec.reconcile(names25, runs, REPO)
        self.assert_incomplete(plain, "result(s) found only by the open-prefix rule were not attributed", "never reported")
        self.assertEqual(plain.ok_names, 22)
        credited = rec.reconcile(names25, runs, REPO, rec.Pinned("recorded25", "-", 25, rec.RUNTIME38_STEMS, True))
        self.assertTrue(credited.complete, credited.problems)
        self.assertEqual((credited.ok_names, credited.runs[0][1]["credited_by_closure"]), (25, 3))

    # ---- planted negatives, each with its control ----------------------------------------------------------------------------

    def test_negative_a_log_missing_one_name_is_refused(self):
        for gone in (NAMES38[5], sorted(PRINTERS)[0]):          # a quiet test, then one of the printers
            with self.subTest(gone=gone):
                log = self.write(nocapture([n for n in NAMES38 if n != gone]))
                code, out = self.cli("--registry", str(LIST38), "--run", str(log), "0")
                self.assertEqual(code, 1, out)
                self.assertIn("native_runtime38: INCOMPLETE: 37/38", out)
                self.assertIn("never reported", out)
                self.assertIn(gone, out)
                self.assertNotIn("COMPLETE: 38", out)
        self.assert_control38()

    def test_negative_a_list_with_one_name_altered_is_refused_by_the_digest_before_anything_is_reconciled(self):
        log = self.write(nocapture(NAMES38))
        good = LIST38.read_bytes()
        self.assertEqual(self.cli("--registry", str(LIST38), "--run", str(log), "0")[0], 0)        # the control: the pinned bytes
        altered = good.replace(NAMES38[7].encode(), (NAMES38[7] + "_x").encode(), 1)
        plants = {
            "one name altered": altered,
            "one name dropped": b"".join(good.splitlines(keepends=True)[1:]),
            "two names swapped": b"".join(self.swap(good.splitlines(keepends=True), 3, 4)),
            "a blank line appended": good + b"\n",
            "CRLF line ends": good.replace(b"\n", b"\r\n"),
            "an empty file": b"",
            "the recorded 25-name list": (RECORDED / "native-required-tests.txt").read_bytes(),
            "the 196 list with one name altered": rec.REGISTRY_FILE.read_bytes().replace(NAMES[0].encode(), b"x::" + NAMES[0].encode(), 1),
        }
        for what, data in plants.items():
            with self.subTest(plant=what):
                self.assertNotEqual(data, good)
                path = self.dir / "planted.txt"
                path.write_bytes(data)
                code, out = self.cli("--registry", str(path), "--run", str(log), "0")
                self.assertEqual(code, 2, out)
                self.assertIn("is not a pinned registry", out)
                self.assertNotIn("COMPLETE", out)

    @staticmethod
    def swap(items, a, b):
        items[a], items[b] = items[b], items[a]
        return items

    def test_negative_a_printing_test_that_failed_is_not_credited(self):
        victim = sorted(PRINTERS)[1]
        text = nocapture(NAMES38, results={victim: "FAILED"}, failed=1, verdict="FAILED")
        code, out = self.cli("--registry", str(LIST38), "--run", str(self.write(text)), "101")
        self.assertEqual(code, 1, out)
        self.assertIn("1 failed", out)
        self.assertIn("the command exited 101", out)
        self.assertNotIn("credited_by_closure", out)
        self.assert_control38()

    def test_negative_totals_that_do_not_close_around_the_started_tests_credit_nothing(self):
        """38 `running`, 38 passed, but only 37 tests ever printed a prefix: libtest's totals do not close around the names, so the
        interrupted results stay unattributed and the run is incomplete (the note is kept, nothing is credited)."""
        gone = NAMES38[5]
        report = self.judge38((nocapture([n for n in NAMES38 if n != gone], declared=38, passed=38), 0))
        self.assert_incomplete(report, "were not attributed", "never reported", gone)
        self.assertNotIn("credited_by_closure", report.runs[0][1])
        self.assert_control38()

    def test_negative_a_printer_whose_output_looks_like_a_second_open_prefix_is_not_credited(self):
        victim, other = sorted(PRINTERS)[0], NAMES38[2]
        plant = {victim: [f"test {other} ... FFW_P05_RUNTIME:something"]}
        report = self.judge38((nocapture(NAMES38, inside=plant), 0))
        self.assert_incomplete(report, "neither is attributed")
        self.assertNotIn("credited_by_closure", report.runs[0][1])
        self.assert_control38()

    def test_negative_an_unregistered_name_that_printed_is_not_credited_as_a_registry_name(self):
        stranger = "tests::a_printing_test_nobody_registered"
        names = [n if n != sorted(PRINTERS)[2] else stranger for n in NAMES38]
        report = self.judge38((nocapture(names, printers=PRINTERS | {stranger}), 0))
        self.assert_incomplete(report, "outside the registry", stranger, "never reported")
        self.assert_control38()

    def test_negative_a_nonzero_exit_status_from_outside_the_log_is_refused_even_when_the_totals_close(self):
        report = self.judge38((nocapture(NAMES38), 101))
        self.assert_incomplete(report, "the command exited 101")
        self.assertNotIn("credited_by_closure", report.runs[0][1])
        self.assert_control38()

    def test_negative_a_truncated_log_without_its_summary_is_refused(self):
        report = self.judge38((nocapture(NAMES38[:30], summary=False, declared=38), 0))
        self.assert_incomplete(report, "no `test result:` line", "never reported")
        self.assert_control38()

    def test_negative_the_binary_must_be_the_probes_for_the_38_and_asupersyncs_for_the_196(self):
        wrong = nocapture(NAMES38, printers=(), header=True).replace("ffw_p05_runtime", "asupersync")
        self.assert_incomplete(self.judge38((wrong, 0)), "not the probe test binary")
        self.assertTrue(self.judge38((nocapture(NAMES38, printers=(), header=True), 0)).complete)       # the control
        crossed = libtest(NAMES, header=True).replace("asupersync", "ffw_p05_runtime")
        self.assert_incomplete(self.judge((crossed, 0)), "not the library test binary")
        self.assert_control()

    def test_the_closure_credit_requires_every_total_on_its_own(self):
        """`credit_by_closure` called directly: the control closes and credits; each deviation, one at a time, credits nothing and leaves
        the problems and statuses exactly as they were (so the credit does not rest on the caller's other checks)."""
        note = ("log.txt: log.txt: a section of 38 tests reports in sorted order, which is how libtest runs with one test thread; "
                "{k} result(s) found only by the open-prefix rule were not attributed")

        def case(*, k=2, attributed=36, interrupted=("p1", "p2"), twice=(), **summary_patch):
            statuses = {f"t{i}": "ok" for i in range(attributed)}
            counts = Counter({name: 1 for name in [*statuses, *interrupted]})
            for name in twice:
                counts[name] = 2
            summary = {"declared": [38], "results": 1, "passed": 38, "failed": 0, "ignored": 0, "measured": 0}
            summary.update(summary_patch)
            return {"problems": [note.format(k=k)], "statuses": statuses, "counts": counts, "summary": summary}

        control = case()
        self.assertEqual(rec.credit_by_closure(**control), 2)
        self.assertEqual(control["problems"], [])
        self.assertEqual((control["statuses"]["p1"], control["statuses"]["p2"], len(control["statuses"])), ("ok", "ok", 38))
        plants = {
            "another problem is present": {**case(), "problems": [note.format(k=2), "log.txt: 1 failed; every one of the 38 must be ok"]},
            "there is no unattributed-result note": {**case(), "problems": []},
            "the note counts no unattributed result": case(k=0, attributed=38, interrupted=()),
            "the note counts fewer results than there are unattributed prefixes": case(interrupted=("p1", "p2", "p3")),
            "an unattributed prefix is seen twice": case(twice=("p1",)),
            "there are two result lines": case(results=2),
            "there are two sections": case(declared=[38, 0]),
            "a test failed": case(failed=1),
            "a test was ignored": case(ignored=1),
            "a test was measured": case(measured=1),
            "passed differs from the announced count": case(passed=37),
            "passed differs from attributed plus unattributed": case(attributed=35),
        }
        for what, plant in plants.items():
            with self.subTest(plant=what):
                before = (list(plant["problems"]), dict(plant["statuses"]))
                self.assertEqual(rec.credit_by_closure(**plant), 0)
                self.assertEqual((plant["problems"], plant["statuses"]), before)

    def test_a_pinned_registry_whose_file_has_another_number_of_names_is_refused(self):
        digest = hashlib.sha256(LIST38.read_bytes()).hexdigest()
        wrong_size = (rec.Pinned("test", digest, 37, rec.RUNTIME38_STEMS, True),)
        with mock.patch.object(rec, "PINNED", wrong_size):
            with self.assertRaises(ValueError) as caught:
                rec.load_pinned(LIST38)
        self.assertIn("38 names, but the pinned test registry has 37", str(caught.exception))
        right_size = (rec.Pinned("test", digest, 38, rec.RUNTIME38_STEMS, True),)
        with mock.patch.object(rec, "PINNED", right_size):
            self.assertEqual(len(rec.load_pinned(LIST38)[0]), 38)

    def test_the_196_registry_never_credits_an_interrupted_result_through_the_command_line(self):
        names = sorted(NAMES)
        lines = ["running 196 tests"]
        for index, name in enumerate(names):
            lines += [f"test {name} ... ", "FFW_RECORD something=1", "ok"] if index in (3, 100) else [f"test {name} ... ok"]
        lines += ["", "test result: ok. 196 passed; 0 failed; 0 ignored; 0 measured; 27259 filtered out; finished in 1.52s", ""]
        code, out = self.cli("--run", str(self.write("\n".join(lines))), "0")
        self.assertEqual(code, 1, out)
        self.assertIn("native196: INCOMPLETE: 194/196", out)
        self.assertIn("not attributed", out)
        self.assertNotIn("credited_by_closure", out)


if __name__ == "__main__":
    unittest.main()
