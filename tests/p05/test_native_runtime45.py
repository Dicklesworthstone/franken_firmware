"""Tests for the 45-name native registry of the P05 runtime probe with its caller-driven profile. Pure Python: no cargo, no network.

    cd tests/p05 && python3 -B -m unittest -v test_native_runtime45

The registry is `native_runtime38_names.txt` unchanged and in order, then the 7 tests the caller-driven profile adds. It is pinned by the
digest of its bytes in `native196_reconcile.py`, next to the 38 and the 196. These tests show what that pin decides: the right bytes are
accepted, every altered list is a usage error, a complete 45-name log is complete, and a log of the other probe is not. Each planted
negative has its remove-the-plant control: the same builder, un-planted, is complete. The logs are built here, not recorded; the printing
tests below are a MODEL of which tests print under `--nocapture`, and the reconciler credits by libtest's own totals, so a real log's
`credited_by_closure` is whatever the central run shows and nothing here predicts it.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import os
import unittest
from pathlib import Path

import native196_reconcile as rec
from test_native196_reconcile import PRINTERS, Case, nocapture

HERE = Path(__file__).resolve().parent
REPO = rec.find_repo(os.environ.get("FFW_REPO"))
LIST45 = HERE / "native_runtime45_names.txt"
LIST45_SHA256 = "52f277cd4bdc68e2682795c65ebe060ca25de1aa87216cbc1c4184cc86219703"
LIST38 = rec.RUNTIME38_FILE
NAMES38, PIN38 = rec.load_pinned(LIST38)
NAMES45, PIN45 = rec.load_pinned(LIST45)

# Written by hand, not read from the list: the 7 names the caller-driven profile adds to the 38, in source order.
NEW_NAMES = (
    "tests::caller_driven_runtime_runs_every_phase_on_the_caller_thread_and_holds_the_thread_count",
    "tests::the_caller_driven_profile_row_is_judged_from_the_profile_alone",
    "tests::the_caller_driven_runtime_row_passes_only_for_tasks_on_the_caller_within_the_start_count",
    "tests::the_caller_driven_blocking_and_handle_spawn_rows_are_judged_from_observations",
    "tests::only_the_exact_argument_or_marker_selects_the_caller_driven_run_and_single_owner_wins",
    "tests::a_runtime_that_ignores_the_caller_driven_choice_fails_the_runtime_row_and_the_audit",
    "tests::a_runtime_with_a_thread_of_its_own_runs_handle_spawned_work_by_itself_and_fails_that_row",
)
# The model of the printers: the existing four, and the real caller-driven run, which prints its whole transcript.
PRINTERS45 = PRINTERS | {NEW_NAMES[0]}


class Runtime45(Case):
    def judge45(self, *runs, names=NAMES45, pinned=PIN45):
        return rec.reconcile(list(names), [rec.Run(self.write(text), code) for text, code in runs], REPO, pinned)

    def assert_control45(self, names=NAMES45):
        """Remove the plant: the same builder, un-planted, is complete with every name credited."""
        report = self.judge45((nocapture(names, printers=PRINTERS45), 0), names=names)
        self.assertTrue(report.complete, report.problems)
        self.assertEqual(report.ok_names, len(names))

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rec.main([*argv, "--repo", str(REPO)])
        return code, out.getvalue()

    # ---- the pin ---------------------------------------------------------------------------------------------------------------

    def test_the_45_registry_is_the_38_unchanged_then_the_seven_and_is_pinned_by_its_digest(self):
        self.assertEqual((len(NAMES45), len(set(NAMES45))), (45, 45))
        self.assertEqual(hashlib.sha256(LIST45.read_bytes()).hexdigest(), LIST45_SHA256)
        self.assertEqual(rec.RUNTIME45_SHA256, LIST45_SHA256)
        self.assertEqual((PIN45.label, PIN45.size, PIN45.serial_closure), ("native_runtime45", 45, True))
        self.assertEqual(PIN45.stems, rec.RUNTIME38_STEMS, "the probe's own binary, never Asupersync's")
        self.assertEqual(NAMES45[:38], NAMES38, "the 38 are unchanged and in order")
        self.assertEqual(tuple(NAMES45[38:]), NEW_NAMES)
        self.assertEqual(LIST45.read_bytes()[: len(LIST38.read_bytes())], LIST38.read_bytes())
        self.assertNotEqual(LIST45_SHA256, rec.RUNTIME38_SHA256)

    def test_the_38_pin_is_untouched_by_the_45_pin(self):
        self.assertEqual((PIN38.label, PIN38.size, PIN38.sha256), ("native_runtime38", 38, rec.RUNTIME38_SHA256))
        self.assertEqual(rec.RUNTIME38_SHA256, "94be74e65f47711951368d6776a4516699d761333338db5057f881867c679ba1")
        self.assertEqual([pinned.label for pinned in rec.PINNED], ["native196", "native_runtime38", "native_runtime45"])

    # ---- positive --------------------------------------------------------------------------------------------------------------

    def test_positive_a_complete_45_nocapture_log_is_complete_through_the_command_line(self):
        log = self.write(nocapture(NAMES45, printers=PRINTERS45))
        code, out = self.cli("--registry", str(LIST45), "--run", str(log), "0")
        self.assertEqual(code, 0, out)
        self.assertIn("native_runtime45: COMPLETE: 45/45 names `ok` exactly once across 1 run(s)", out)
        self.assertIn(f"passed=45 failed=0 ignored=0 measured=0 filtered_out=0 credited_by_closure={len(PRINTERS45)}", out)
        self.assert_control45()

    def test_positive_a_quiet_log_with_the_probes_own_binary_header_needs_no_credit(self):
        report = self.judge45((nocapture(NAMES45, printers=(), header=True), 0))
        self.assertTrue(report.complete, report.problems)
        self.assertNotIn("credited_by_closure", report.runs[0][1])

    # ---- planted negatives, each with its control ------------------------------------------------------------------------------

    def test_negative_a_log_whose_binary_is_asupersyncs_and_not_the_probes_is_refused(self):
        asupersync = nocapture(NAMES45, printers=(), header=True).replace("ffw_p05_runtime-", "asupersync-")
        self.assertNotEqual(asupersync, nocapture(NAMES45, printers=(), header=True))
        report = self.judge45((asupersync, 0))
        self.assertFalse(report.complete)
        self.assertIn("not the probe test binary", "\n".join(report.problems))
        self.assert_control45()

    def test_negative_a_log_missing_one_new_name_is_refused(self):
        for gone in NEW_NAMES:
            with self.subTest(gone=gone):
                log = self.write(nocapture([n for n in NAMES45 if n != gone], printers=PRINTERS45))
                code, out = self.cli("--registry", str(LIST45), "--run", str(log), "0")
                self.assertEqual(code, 1, out)
                self.assertIn("native_runtime45: INCOMPLETE: 44/45", out)
                self.assertIn("never reported", out)
                self.assertIn(gone, out)
                self.assertNotIn("COMPLETE: 45", out)
        self.assert_control45()

    def test_negative_a_log_of_the_38_name_probe_is_not_complete_against_the_45_registry_and_the_reverse(self):
        short = self.write(nocapture(NAMES38))
        code, out = self.cli("--registry", str(LIST45), "--run", str(short), "0")
        self.assertEqual(code, 1, out)
        self.assertIn("native_runtime45: INCOMPLETE: 38/45", out)
        self.assertIn("7 registry name(s) never reported", out)       # the report counts and shows three; the count is the claim
        longer = self.write(nocapture(NAMES45, printers=PRINTERS45))
        code, out = self.cli("--registry", str(LIST38), "--run", str(longer), "0")
        self.assertEqual(code, 1, out)
        self.assertIn("native_runtime38: INCOMPLETE", out)
        self.assertIn("7 reported name(s) outside the registry", out)
        # Controls: each log against its own registry.
        for registry, log, label in ((LIST38, short, "native_runtime38: COMPLETE: 38/38"),
                                     (LIST45, longer, "native_runtime45: COMPLETE: 45/45")):
            code, out = self.cli("--registry", str(registry), "--run", str(log), "0")
            self.assertEqual(code, 0, out)
            self.assertIn(label, out)

    def test_negative_a_list_with_one_byte_changed_is_refused_by_the_digest_before_anything_is_reconciled(self):
        log = self.write(nocapture(NAMES45, printers=PRINTERS45))
        good = LIST45.read_bytes()
        self.assertEqual(self.cli("--registry", str(LIST45), "--run", str(log), "0")[0], 0)      # the control: the pinned bytes
        lines = good.splitlines(keepends=True)
        swapped = list(lines)
        swapped[40], swapped[41] = swapped[41], swapped[40]
        plants = {
            "a new name altered": good.replace(NEW_NAMES[2].encode(), (NEW_NAMES[2] + "_x").encode(), 1),
            "the last name dropped": b"".join(lines[:-1]),
            "two new names swapped": b"".join(swapped),
            "a blank line appended": good + b"\n",
            "CRLF line ends": good.replace(b"\n", b"\r\n"),
            "an empty file": b"",
            "the 38 list with the seven appended in reverse": LIST38.read_bytes() + "".join(f"{n}\n" for n in reversed(NEW_NAMES)).encode(),
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

    def test_negative_a_new_test_that_failed_is_not_credited_and_the_exit_status_is_taken_from_outside_the_log(self):
        victim = NEW_NAMES[5]
        text = nocapture(NAMES45, printers=PRINTERS45, results={victim: "FAILED"}, failed=1, verdict="FAILED")
        code, out = self.cli("--registry", str(LIST45), "--run", str(self.write(text)), "101")
        self.assertEqual(code, 1, out)
        self.assertIn("1 failed", out)
        self.assertIn("the command exited 101", out)
        report = self.judge45((nocapture(NAMES45, printers=PRINTERS45), 101))
        self.assertFalse(report.complete)
        self.assertIn("the command exited 101", "\n".join(report.problems))
        self.assert_control45()

    def test_negative_a_new_name_outside_the_registry_is_refused(self):
        stranger = "tests::a_test_nobody_registered"
        names = [n if n != NEW_NAMES[6] else stranger for n in NAMES45]
        report = self.judge45((nocapture(names, printers=PRINTERS45), 0))
        self.assertFalse(report.complete)
        joined = "\n".join(report.problems)
        self.assertIn("outside the registry", joined)
        self.assertIn(stranger, joined)
        self.assertIn("never reported", joined)
        self.assert_control45()


if __name__ == "__main__":
    unittest.main()
