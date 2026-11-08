"""Tests for the P05 single-owner contract text, the e2e header and the 38-name native list. Pure Python: no cargo, no network.

    cd tests/p05 && python3 -B -m unittest -v test_runtime_contract

Each planted omission has its remove-the-plant control: the same text, unplanted, is clean. The plants run through the SAME functions
P05-META-005 uses (`run_cases.doc_problems`, `run_cases.run_meta_doc`), so a green here is a statement about that case.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import native196_reconcile as rec
import run_cases

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DOC = REPO / "docs" / "contracts" / "p05.md"
SCRIPT = REPO / "scripts" / "e2e" / "p05"
LIST = HERE / "native_runtime38_names.txt"
LIST_SHA256 = "94be74e65f47711951368d6776a4516699d761333338db5057f881867c679ba1"
FROZEN = REPO / "toolchain" / "results" / "p05" / "20261108-runtime-probe" / "native-required-tests.txt"
FROZEN_SHA256 = "76eb41f06710e0a23406f204250dd54f5771a826067a396d6ab31f1df5603608"
SECTION = "## The runtime probe and its single-owner profile"

# Written by hand, not read from the list: the 13 names the single-owner run adds to the recorded 25, in source order.
NEW_NAMES = (
    "tests::single_owner_runtime_exercises_the_supported_phases_and_types_the_unsupported_one",
    "tests::the_single_owner_exit_code_is_zero_only_for_exactly_the_declared_unsupported_row",
    "tests::the_declared_reason_is_the_start_of_the_caller_driven_detail_the_exit_code_looks_for",
    "tests::a_profile_that_claims_single_owner_but_has_worker_threads_is_refused",
    "tests::the_single_owner_run_refuses_a_threaded_profile_before_building_a_runtime",
    "tests::the_caller_driven_mode_is_unsupported_unknown_or_failed_and_never_ok",
    "tests::the_single_owner_runtime_row_passes_only_for_one_carried_worker_and_one_task_thread",
    "tests::first_use_of_the_blocking_pool_is_judged_from_its_counters_and_the_os_thread_count",
    "tests::the_byte_budget_run_refuses_an_oversized_charge_and_leaves_the_runtime_usable",
    "tests::only_the_exact_single_owner_argument_selects_the_single_owner_run",
    "tests::the_marker_selects_the_single_owner_run_only_when_it_is_exactly_the_word",
    "tests::the_marker_read_is_bounded_and_an_oversized_marker_is_not_the_word",
    "tests::the_argument_or_the_marker_selects_the_single_owner_run_and_the_supervisors_argv_alone_does_not",
)
HEADER_TERMS = ("--runtime run|analyze [ARGS] --profile single-owner", "CALLER_DRIVEN_CURRENT_THREAD",
                "accepted_with_declared_unsupported", "never PASSED", "exit 4", "docs/contracts/p05.md",
                "rejects it as an unrecognized argument")


def libtest(names, *, results=None, summary=True, passed=None, extra=()):
    results = results or {}
    lines = ["", f"running {len(names)} tests"]
    for name in sorted(names):
        lines.append(f"test {name} ... {results.get(name, 'ok')}")
    lines += list(extra)
    if summary:
        done = len(names) if passed is None else passed
        lines += ["", f"test result: ok. {done} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.52s", ""]
    return "\n".join(lines) + "\n"


class ContractDocTests(unittest.TestCase):
    def test_the_real_documentation_satisfies_meta_005_and_the_case_passes(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertEqual(run_cases.doc_problems(text), [])
        self.assertEqual(run_cases.run_meta_doc({"id": "P05-META-005"}), (run_cases.PASS, ""))

    def test_the_section_and_every_required_term_are_required_by_meta_005(self):
        self.assertIn(SECTION, run_cases.DOC_HEADINGS)
        self.assertEqual(len(run_cases.DOC_RUNTIME_TERMS), len(set(run_cases.DOC_RUNTIME_TERMS)))
        section = run_cases.runtime_section(DOC.read_text(encoding="utf-8"))
        self.assertTrue(section.startswith(SECTION))
        for term in run_cases.DOC_RUNTIME_TERMS:
            self.assertIn(term, section)

    def test_a_term_must_be_inside_the_section_and_a_mention_elsewhere_does_not_stand_in_for_it(self):
        text = DOC.read_text(encoding="utf-8")
        section = run_cases.runtime_section(text)
        self.assertNotIn("\n## ", section[len(SECTION):], "the section ends at the next heading")
        start = text.index(section)
        before, after = text[:start], text[start + len(section):]
        for term in run_cases.DOC_RUNTIME_TERMS:
            with self.subTest(removed_from_the_section_only=term):
                problems = run_cases.doc_problems(before + section.replace(term, "OMITTED") + after)
                self.assertTrue(any(term in problem for problem in problems), problems)
        shared = [term for term in run_cases.DOC_RUNTIME_TERMS if term in before + after]
        self.assertTrue(shared, "some term is also mentioned outside the section (the open-items bullet), so the plant is real")
        for term in shared:
            with self.subTest(removed_outside_only=term):
                planted = before.replace(term, "OMITTED") + section + after.replace(term, "OMITTED")
                self.assertEqual(run_cases.doc_problems(planted), [], "control: the section alone satisfies the check")

    def test_omitting_the_section_or_any_term_makes_meta_005_red(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertEqual(run_cases.doc_problems(text), [], "control: the unplanted text is clean")
        for term in (SECTION, *run_cases.DOC_RUNTIME_TERMS):
            with self.subTest(omitted=term):
                problems = run_cases.doc_problems(text.replace(term, "OMITTED"))
                self.assertTrue(problems, "an omission was accepted")
                self.assertTrue(any(term in problem for problem in problems), problems)

    def test_the_whole_case_function_is_red_on_a_planted_copy_and_green_on_the_control(self):
        text = DOC.read_text(encoding="utf-8")
        original = run_cases.DOC_FILE
        try:
            with tempfile.TemporaryDirectory() as directory:
                for name, planted in (("control", text), ("no section", text.replace(SECTION, "## Something else")),
                                      ("no declaration line", text.replace("declaration, not a pass", "a declaration")),
                                      ("no exit 4", text.replace("the command-line exit is 4", "the exit code is nonzero"))):
                    path = Path(directory) / (name.replace(" ", "_") + ".md")
                    path.write_text(planted, encoding="utf-8")
                    run_cases.DOC_FILE = str(path)
                    status, detail = run_cases.run_meta_doc({"id": "P05-META-005"})
                    if name == "control":
                        self.assertEqual((status, detail), (run_cases.PASS, ""))
                    else:
                        self.assertEqual(status, run_cases.FAIL, name)
                        self.assertTrue(detail, name)
        finally:
            run_cases.DOC_FILE = original

    def test_an_omission_that_already_mattered_is_still_red(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertTrue(run_cases.doc_problems(text.replace("## No-claim line", "## Other")))
        self.assertTrue(run_cases.doc_problems(text.replace(run_cases.DOC_NO_CLAIM, "does not claim")))

    def test_the_section_never_states_a_pass_for_the_declared_row(self):
        text = DOC.read_text(encoding="utf-8")
        section = text[text.index(SECTION):text.index("## Open items")]
        self.assertIn("never counted `ok`", section)
        self.assertIn("never a plain pass", section)
        self.assertIn("Not claimed", section)
        for forbidden in ("single-owner profile passed", "single-owner run passed", "AC item 2 is closed"):
            self.assertNotIn(forbidden, section)


class ScriptHeaderTests(unittest.TestCase):
    @staticmethod
    def header():
        lines = []
        for line in SCRIPT.read_text(encoding="utf-8").splitlines()[1:]:
            if not line.startswith("#"):
                break
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def header_problems(header):
        return [f"the header does not mention {term!r}" for term in HEADER_TERMS if term not in header]

    def test_the_header_documents_the_profile_the_declared_row_and_exit_4(self):
        self.assertEqual(self.header_problems(self.header()), [])

    def test_removing_any_header_term_is_noticed_and_named(self):
        header = self.header()
        self.assertEqual(self.header_problems(header), [], "control: the real header is clean")
        for term in HEADER_TERMS:
            with self.subTest(omitted=term):
                problems = self.header_problems(header.replace(term, ""))
                self.assertTrue(any(repr(term) in problem for problem in problems), problems)

    def test_the_script_itself_still_routes_runtime_arguments_through_unchanged(self):
        body = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('exec python3 -B "$ROOT/toolchain/src/measure-p05-target.py" "$RUNTIME_COMMAND" "$@"', body)


class RequiredNamesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.names = rec.load_registry(LIST, expected_sha256=LIST_SHA256)
        self.count = 0

    def write(self, text):
        self.count += 1
        path = self.dir / f"run{self.count}.stdout"
        path.write_text(text, encoding="utf-8")
        return path

    def judge(self, text, status=0, names=None):
        return rec.reconcile(list(names or self.names), [rec.Run(self.write(text), status)], REPO)

    def test_the_list_is_the_38_names_the_recorded_25_then_the_13_new_ones(self):
        self.assertEqual(hashlib.sha256(LIST.read_bytes()).hexdigest(), LIST_SHA256)
        self.assertEqual(len(self.names), 38)
        self.assertEqual(len(set(self.names)), 38)
        frozen = [line for line in FROZEN.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(hashlib.sha256(FROZEN.read_bytes()).hexdigest(), FROZEN_SHA256, "the recorded first-run list is frozen")
        self.assertEqual(len(frozen), 25)
        self.assertEqual(self.names[:25], frozen, "the recorded 25 are kept verbatim and in order")
        self.assertEqual(tuple(self.names[25:]), NEW_NAMES)
        for name in self.names:
            self.assertRegex(name, r"^tests::[a-z][a-z0-9_]*$")

    def test_the_existing_reconciler_takes_the_list_as_its_registry(self):
        report = self.judge(libtest(self.names))
        self.assertTrue(report.complete, report.problems)
        self.assertEqual(report.ok_names, 38)

    def test_each_planted_defect_is_refused_by_the_same_reconciler(self):
        control = self.judge(libtest(self.names))
        self.assertTrue(control.complete, control.problems)
        short = self.names[:-1]
        missing = self.judge(libtest(short))
        self.assertFalse(missing.complete)
        self.assertIn("never reported", "\n".join(missing.problems))
        extra = self.judge(libtest(self.names + ["tests::a_name_outside_the_list"]))
        self.assertFalse(extra.complete)
        self.assertIn("outside the registry", "\n".join(extra.problems))
        duplicate = self.judge(libtest(self.names, extra=[f"test {self.names[0]} ... ok"]))
        self.assertFalse(duplicate.complete)
        failed = self.judge(libtest(self.names, results={self.names[30]: "FAILED"}, passed=37).replace(
            "test result: ok.", "test result: FAILED.").replace("0 failed", "1 failed"))
        self.assertFalse(failed.complete)
        self.assertFalse(self.judge(libtest(self.names), status=101).complete, "a nonzero exit status from outside the log")
        self.assertFalse(self.judge(libtest(self.names, summary=False)).complete, "a truncated log with no summary line")

    def test_the_old_25_name_list_does_not_satisfy_the_38_and_the_38_does_not_satisfy_the_old_25(self):
        old = self.names[:25]
        short = self.judge(libtest(old))
        self.assertFalse(short.complete)
        self.assertIn("never reported", "\n".join(short.problems))
        wide = self.judge(libtest(self.names), names=old)
        self.assertFalse(wide.complete)
        self.assertIn("outside the registry", "\n".join(wide.problems))

    def test_a_changed_list_is_refused_by_its_digest_and_a_duplicate_by_the_loader(self):
        path = self.dir / "names.txt"
        path.write_text("\n".join(self.names[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            rec.load_registry(path, expected_sha256=LIST_SHA256)
        path.write_text("\n".join(self.names + self.names[:1]) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            rec.load_registry(path, expected_sha256=None)


if __name__ == "__main__":
    unittest.main()
