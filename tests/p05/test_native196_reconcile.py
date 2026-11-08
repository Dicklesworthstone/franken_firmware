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
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
