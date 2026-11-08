"""P02 platform step of the franken-speaker smoke (`ffw-jub`): the judge, the verifier, the controls and the runner.

Everything here checks the judge, the verifier and the runner's plumbing against transcripts built from the committed marker
examples (`crates/franken-speaker/tests/vectors/p02_platform_markers.json`). No guest booted and no speaker ran: these are not
guest proof, and a host build of the speaker cannot print these lines at all (exit 2). Each negative plants exactly one fault
next to an unplanted baseline of the same shape that must itself pass, so a test cannot pass by failing for an unrelated reason.
The expected problems are written out by hand from docs/contracts/p02.md and never read back from the judge.
"""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))
import test_serial_validator as base  # noqa: E402  (a module, not re-exported: its TestCases are not collected here)
import test_speaker_smoke as smoke  # noqa: E402  (likewise)
import platform_expect as P  # noqa: E402
import speaker_expect as E  # noqa: E402

VERIFIER = base.VERIFIER
REPO = HERE.parents[1]
GRAMMAR = P.load_grammar(REPO)
PLATFORM = {"grammar": GRAMMAR}
SPEAKER = smoke.CTX
EXAMPLES = GRAMMAR["examples"]

ARCH = {
    "mips": (base.HELLO, base.ENOSYS, base.MIPS_TRIPLE),
    "ppc": (base.PPC_HELLO, base.PPC_ENOSYS, base.PPC_TRIPLE),
}


def lines_of(name):
    return list(EXAMPLES[name]["lines"])


def as_bytes(lines):
    return ("\n".join(lines) + "\n").encode("ascii")


def judge(lines, arch):
    return P.judge_output(as_bytes(lines) if isinstance(lines, list) else lines, arch, GRAMMAR)


def platform_block(lines, status, crlf=True, exit_line=None):
    """The console view of the platform step: BEGIN, the forwarded bytes (CRLF if the console did that), EXIT."""
    data = as_bytes(lines)
    body = data.decode("ascii").replace("\n", "\r\n" if crlf else "\n")
    sealed = f"{P.STEP_EXIT_KEY} status={status} stdout_bytes={len(data)} stdout_fnv1a64={E.fnv1a64(data):016x}"
    return P.STEP_BEGIN_LINE + "\n" + body + (exit_line or sealed) + "\n"


def transcript(block, arch, catalog=smoke.GOOD_BLOCK):
    """base.POSITIVE with the catalog step and then the platform step before the summary, as the guest prints them."""
    return smoke.transcript(catalog + block, ppc=arch == "ppc")


def verify(text, arch, speaker=SPEAKER, platform=PLATFORM):
    hello, enosys, triple = ARCH[arch]
    return VERIFIER.verify_serial_output(arch, hello, enosys, text, triple, speaker=speaker, platform=platform)


# The baselines: a healthy run per guest, and the one degraded outcome the contract allows. Each is the unplanted control of the
# plants below, and each must itself pass.
HEALTHY = {"ppc": (lines_of("powerpc_all_pass"), 0), "mips": (lines_of("mips_all_pass"), 0)}
DEGRADED = (lines_of("mips_entropy_not_seeded"), 3)


def good_text(arch):
    lines, status = HEALTHY[arch]
    return transcript(platform_block(lines, status), arch)


def replaced(lines, index, new):
    out = list(lines)
    out[index] = new
    return out


# ---- the grammar file ----------------------------------------------------------------------------------------------


class GrammarFileTests(unittest.TestCase):
    def test_the_judge_relies_on_exactly_these_facts_about_the_file(self):
        g, r = GRAMMAR["grammar"], GRAMMAR["reasons"]
        self.assertEqual(GRAMMAR["schema"], "ffw.p02.platform-markers.v2")
        self.assertEqual(g["lines"], ["BEGIN", "KERNEL", "CLOCK", "ENTROPY", "WAKE", "END"])
        self.assertEqual(set(g["status"]), {"PASS", "REFUSED", "NOT_RUN"})
        self.assertEqual(set(g["provenance"]), {"kernel", "simulated", "none"})
        self.assertEqual(set(g["mechanism"]), {"eventfd", "self_pipe", "none"})
        self.assertEqual(set(g["abi"]), {"mips32", "powerpc32", "none"})
        self.assertEqual(set(g["evidence"]), {"harness-mips-4.19", "harness-ppc-4.9", "none"})
        # The one degraded cell exists in the closed set, and no reason names a kernel release (it is never compared).
        self.assertIn("not_seeded", r["entropy"])
        for capability, reasons in r.items():
            self.assertFalse([x for x in reasons if "release" in x or "version" in x], capability)
        self.assertEqual(set(r), {"kernel", "clock", "entropy", "wake"})

    def test_the_hash_of_the_file_is_recorded_so_a_receipt_names_the_grammar_it_used(self):
        data = (REPO / P.VECTORS).read_bytes()
        import hashlib
        self.assertEqual(GRAMMAR["sha256"], hashlib.sha256(data).hexdigest())

    def test_a_missing_or_wrong_grammar_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(P.PlatformGrammarError):
                P.load_grammar(root)
            path = root / P.VECTORS
            path.parent.mkdir(parents=True)
            good = json.loads((REPO / P.VECTORS).read_text())
            for label, change in {
                "wrong schema": lambda d: d.update(schema="ffw.p02.platform-markers.v1"),
                "no grammar": lambda d: d.pop("grammar"),
                "no reason codes": lambda d: d.pop("reason_codes"),
                "no entropy reasons": lambda d: d["reason_codes"].pop("entropy"),
                "an empty status set": lambda d: d["grammar"].update(status=[]),
                "lines reordered": lambda d: d["grammar"].update(lines=["BEGIN", "CLOCK", "KERNEL", "ENTROPY", "WAKE", "END"]),
            }.items():
                bad = json.loads(json.dumps(good))
                change(bad)
                path.write_text(json.dumps(bad))
                with self.assertRaises(P.PlatformGrammarError, msg=label):
                    P.load_grammar(root)
            path.write_text("{not json")
            with self.assertRaises(P.PlatformGrammarError):
                P.load_grammar(root)
            path.write_text(json.dumps(good))
            P.load_grammar(root)   # the control: the unplanted file loads


# ---- the committed examples, per guest -----------------------------------------------------------------------------


WRONG_ABI = {
    "mips": "platform_abi:powerpc32_harness-ppc-4.9_for_mips",
    "ppc": "platform_abi:mips32_harness-mips-4.19_for_ppc",
}
# (example, guest) -> (verdict, problems), from the contract text: PowerPC every line PASS is green; MIPS entropy not_seeded is
# degraded; everything else refused or simulated is red with a name; an example for the other ISA fails on its ABI.
EXPECTED = {
    ("powerpc_all_pass", "ppc"): ("green", []),
    ("powerpc_all_pass", "mips"): ("red", [WRONG_ABI["mips"]]),
    ("mips_all_pass", "mips"): ("green", []),
    ("mips_all_pass", "ppc"): ("red", [WRONG_ABI["ppc"]]),
    ("mips_entropy_not_seeded", "mips"): ("degraded", []),
    ("mips_entropy_not_seeded", "ppc"): ("red", [WRONG_ABI["ppc"]]),
    ("simulated_backend_refused", "mips"): ("red", ["platform_backend_simulated"]),
    ("simulated_backend_refused", "ppc"): ("red", ["platform_backend_simulated"]),
    ("stock_kernel_release_recorded_not_refused", "ppc"): ("green", []),
    ("stock_kernel_release_recorded_not_refused", "mips"): ("red", [WRONG_ABI["mips"]]),
    ("unreadable_kernel_release_recorded_as_invalid", "ppc"): ("green", []),
    ("unreadable_kernel_release_recorded_as_invalid", "mips"): ("red", [WRONG_ABI["mips"]]),
    ("wake_source_absent_powerpc", "ppc"): ("red", ["platform_not_started:kernel:wake_open_failed"]),
    ("wake_source_absent_powerpc", "mips"): ("red", [WRONG_ABI["mips"]]),
    ("clock_absent_powerpc", "ppc"): ("red", ["platform_not_started:clock:absent"]),
    ("clock_absent_powerpc", "mips"): ("red", [WRONG_ABI["mips"]]),
    ("wake_not_observed_powerpc", "ppc"): ("red", ["platform_not_started:wake:not_observed"]),
    ("wake_not_observed_powerpc", "mips"): ("red", [WRONG_ABI["mips"]]),
}


class ExampleVerdictTests(unittest.TestCase):
    def test_every_committed_example_has_an_expectation_and_the_table_names_no_other(self):
        # A new example in the file with no expectation here fails: a mandatory case missing is not a pass.
        self.assertEqual({name for name, _ in EXPECTED}, set(EXAMPLES))
        self.assertEqual(len(EXPECTED), 2 * len(EXAMPLES))

    def test_each_example_gets_the_verdict_the_contract_gives_it_on_each_guest(self):
        for (name, arch), (verdict, problems) in EXPECTED.items():
            record = judge(lines_of(name), arch)
            self.assertEqual((record["verdict"], record["problems"]), (verdict, problems), (name, arch))

    def test_the_guests_exit_status_must_agree_with_the_end_line(self):
        for name, example in EXAMPLES.items():
            record = judge(example["lines"], "mips" if "mips" in name else "ppc")
            if record["started"] is None:
                continue
            self.assertEqual(P.judge_exit_status(record, example["exit"]), [], name)
            wrong = 3 if example["exit"] == 0 else 0
            self.assertEqual(P.judge_exit_status(record, wrong),
                             [f"platform_exit_status_disagrees:status={wrong}_started={int(record['started'])}"], name)

    def test_the_kernel_release_is_recorded_and_never_changes_the_verdict(self):
        healthy = lines_of("powerpc_all_pass")
        verdicts = set()
        for release in ("4.9.0-0.bpo.6-powerpc", "2.6.14.7", "invalid", "a", "9" * 64, "5.15.0+rc1_x-y.z"):
            lines = replaced(healthy, 0, f"FFW_PLATFORM:BEGIN abi=powerpc32 evidence=harness-ppc-4.9 backend=kernel kernel={release}")
            record = judge(lines, "ppc")
            verdicts.add((record["verdict"], tuple(record["problems"])))
            self.assertEqual(record["kernel_release"], release)
        self.assertEqual(verdicts, {("green", ())})
        # The paired negatives: a value outside the declared charset or length is a named problem, not a verdict change.
        for bad, problem in {
            "9" * 65: "platform_value:BEGIN:kernel=" + "9" * 37 + "...",
            "4.9;0": "platform_value:BEGIN:kernel=4.9;0",
            "4.9é": None,
        }.items():
            line = f"FFW_PLATFORM:BEGIN abi=powerpc32 evidence=harness-ppc-4.9 backend=kernel kernel={bad}"
            if problem is None:
                data = b"\n".join([line.encode("utf-8")] + [l.encode("ascii") for l in healthy[1:]]) + b"\n"
                self.assertEqual(P.judge_output(data, "ppc", GRAMMAR)["problems"], ["platform_not_ascii"])
            else:
                self.assertEqual(judge(replaced(healthy, 0, line), "ppc")["problems"], [problem])

    def test_the_degraded_cell_is_exactly_one_cell(self):
        mips = lines_of("mips_all_pass")
        ppc = lines_of("powerpc_all_pass")

        def refused_entropy(lines, reason):
            return replaced(replaced(lines, 3, f"FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason={reason}"),
                            5, f"FFW_PLATFORM:END started=0 refused=entropy:{reason}")

        # The cell itself.
        self.assertEqual(judge(refused_entropy(mips, "not_seeded"), "mips")["verdict"], "degraded")
        # Another entropy reason on MIPS is not excused.
        record = judge(refused_entropy(mips, "failed"), "mips")
        self.assertEqual((record["verdict"], record["problems"]), ("red", ["platform_not_started:entropy:failed"]))
        # The same reason on PowerPC (whose pool was seeded in the E03 run) is not excused either.
        record = judge(refused_entropy(ppc, "not_seeded"), "ppc")
        self.assertEqual((record["verdict"], record["problems"]), ("red", ["platform_not_started:entropy:not_seeded"]))
        # A second refusal beside the degraded one is not degraded: KERNEL, CLOCK and WAKE must pass.
        two = replaced(refused_entropy(mips, "not_seeded"), 2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel reason=absent")
        two = replaced(two, 5, "FFW_PLATFORM:END started=0 refused=clock:absent")
        record = judge(two, "mips")
        self.assertEqual(record["verdict"], "red")
        self.assertEqual(record["problems"], ["platform_not_started:clock:absent", "platform_not_started:entropy:not_seeded"])
        # A second refusal AFTER the degraded one is not degraded either: the degraded cell is the ONLY refusal. (Here the first
        # refusal is the allowed cell, so only the "everything else passes" clause can make this red.)
        later = replaced(refused_entropy(mips, "not_seeded"), 4,
                         "FFW_PLATFORM:WAKE status=REFUSED provenance=kernel mechanism=eventfd reason=sys")
        record = judge(later, "mips")
        self.assertEqual((record["verdict"], record["problems"]),
                         ("red", ["platform_not_started:entropy:not_seeded", "platform_not_started:wake:sys"]))
        # The paired positive control: the unplanted output on the same guest is green.
        self.assertEqual(judge(mips, "mips")["verdict"], "green")


# ---- one change to a healthy output, every time --------------------------------------------------------------------


NAMES = ["BEGIN", "KERNEL", "CLOCK", "ENTROPY", "WAKE", "END"]


class MutationMatrixTests(unittest.TestCase):
    """Every mutation is of the healthy PowerPC output judged for the PowerPC guest, whose unplanted verdict (green) is
    asserted first: the plant is the only difference between the control and the case."""

    def setUp(self):
        self.healthy = lines_of("powerpc_all_pass")
        self.assertEqual((judge(self.healthy, "ppc")["verdict"], judge(self.healthy, "ppc")["problems"]), ("green", []))

    def problems(self, lines):
        record = judge(lines, "ppc")
        self.assertEqual(record["verdict"], "red")
        return record["problems"]

    def test_dropping_each_line_is_a_named_missing_line_or_a_truncated_run(self):
        for i, name in enumerate(NAMES):
            lines = self.healthy[:i] + self.healthy[i + 1:]
            expected = ["platform_truncated:after:WAKE"] if name == "END" else [f"platform_missing:{name}"]
            self.assertEqual(self.problems(lines), expected, name)

    def test_duplicating_each_line_is_a_named_duplicate(self):
        for i, name in enumerate(NAMES):
            lines = self.healthy[: i + 1] + self.healthy[i:]
            self.assertEqual(self.problems(lines), [f"platform_duplicate:{name}"], name)

    def test_swapping_each_adjacent_pair_names_the_line_that_is_out_of_order(self):
        for i in range(5):
            lines = list(self.healthy)
            lines[i], lines[i + 1] = lines[i + 1], lines[i]
            expected = [f"platform_order:{NAMES[i]}"]
            if i == 4:                                  # END moved before WAKE: WAKE is now output after END
                expected = ["platform_after_end", "platform_order:WAKE"]
            self.assertEqual(self.problems(lines), expected, (NAMES[i], NAMES[i + 1]))

    def test_output_after_end_whole_line_or_a_stray_byte(self):
        self.assertEqual(self.problems(self.healthy + ["FFW_PLATFORM:CLOCK status=PASS provenance=kernel"]),
                         ["platform_after_end", "platform_duplicate:CLOCK", "platform_order:CLOCK"])
        self.assertEqual(self.problems(self.healthy + ["hello"]), ["platform_foreign_line:6", "platform_after_end"])
        record = P.judge_output(as_bytes(self.healthy) + b"x", "ppc", GRAMMAR)
        self.assertEqual(record["problems"],
                         ["platform_not_newline_terminated", "platform_foreign_line:6", "platform_after_end"])

    def test_the_shape_of_the_bytes(self):
        self.assertEqual(P.judge_output(b"", "ppc", GRAMMAR)["problems"], ["platform_empty_output"])
        self.assertEqual(P.judge_output(as_bytes(self.healthy)[:-1], "ppc", GRAMMAR)["problems"],
                         ["platform_not_newline_terminated"])
        self.assertEqual(P.judge_output(as_bytes(self.healthy).replace(b"PASS", b"P\xc3\x84SS", 1), "ppc", GRAMMAR)["problems"],
                         ["platform_not_ascii"])
        blank = self.healthy[:3] + [""] + self.healthy[3:]
        self.assertEqual(self.problems(blank), ["platform_blank_line:3"])
        self.assertEqual(self.problems(self.healthy[:2] + ["not a marker"] + self.healthy[2:]), ["platform_foreign_line:2"])
        self.assertEqual(self.problems(self.healthy[:2] + ["FFW_PLATFORM:ODD x=1"] + self.healthy[2:]), ["platform_unknown_line:ODD"])

    def test_a_pass_flipped_to_refused_with_the_end_line_left_alone(self):
        lines = replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel reason=absent")
        self.assertEqual(self.problems(lines), ["platform_end_disagrees:started_but_a_capability_did_not_pass"])
        # And the other way: an END that says refused over four passes.
        lines = replaced(self.healthy, 5, "FFW_PLATFORM:END started=0 refused=clock:absent")
        self.assertEqual(self.problems(lines), ["platform_end_disagrees:refused_but_every_capability_passed"])
        self.assertEqual(self.problems(replaced(self.healthy, 5, "FFW_PLATFORM:END started=0")), ["platform_fields:END:started"])

    def test_provenance_that_is_not_kernel(self):
        clock = "FFW_PLATFORM:CLOCK status=PASS provenance=%s"
        self.assertEqual(self.problems(replaced(self.healthy, 2, clock % "simulated")), ["platform_simulated:CLOCK"])
        self.assertEqual(self.problems(replaced(self.healthy, 2, clock % "none")), ["platform_provenance:CLOCK:PASS_with_none"])
        self.assertEqual(self.problems(replaced(self.healthy, 2, clock % "double")), ["platform_value:CLOCK:provenance=double"])
        self.assertEqual(self.problems(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=kernel")),
                         ["platform_provenance:CLOCK:NOT_RUN_with_kernel", "platform_not_run_unexplained:CLOCK",
                          "platform_end_disagrees:started_but_a_capability_did_not_pass"])
        # A simulated backend admitted at BEGIN.
        self.assertEqual(self.problems(replaced(self.healthy, 0, self.healthy[0].replace("backend=kernel", "backend=simulated"))),
                         ["platform_backend_simulated"])

    def test_reasons_outside_the_closed_set_and_reasons_in_the_wrong_place(self):
        lines = replaced(replaced(self.healthy, 3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=made_up"),
                         5, "FFW_PLATFORM:END started=0 refused=entropy:made_up")
        self.assertEqual(self.problems(lines), ["platform_value:ENTROPY:reason=made_up", "platform_value:END:refused=entropy:made_up"])
        # A reason that exists, for another capability, is not that capability's.
        lines = replaced(replaced(self.healthy, 3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=absent"),
                         5, "FFW_PLATFORM:END started=0 refused=entropy:absent")
        self.assertEqual(judge(lines, "ppc")["verdict"], "red")      # `absent` is an entropy reason too: red by policy, not grammar
        self.assertEqual(self.problems(lines), ["platform_not_started:entropy:absent"])
        self.assertEqual(self.problems(replaced(self.healthy, 2, self.healthy[2] + " reason=absent")),
                         ["platform_fields:CLOCK:status,provenance,reason"])
        self.assertEqual(self.problems(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel")),
                         ["platform_fields:CLOCK:status,provenance"])
        # A release-based refusal is not in the closed set.
        lines = replaced(self.healthy, 1, "FFW_PLATFORM:KERNEL status=REFUSED reason=kernel_release_mismatch")
        self.assertIn("platform_value:KERNEL:reason=kernel_release_mismatch", self.problems(lines))

    def test_a_not_run_needs_an_earlier_refusal_and_nothing_runs_after_a_refused_kernel(self):
        lines = replaced(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"), 5, "FFW_PLATFORM:END started=0")
        self.assertEqual(self.problems(lines), ["platform_fields:END:started"])
        lines = replaced(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"),
                         5, "FFW_PLATFORM:END started=0 refused=wake:sys")
        self.assertEqual(self.problems(lines), ["platform_not_run_unexplained:CLOCK", "platform_end_disagrees:refusal_not_shown"])
        # A NOT_RUN placed before the REFUSED that would explain it.
        lines = replaced(replaced(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=NOT_RUN provenance=none"),
                                  4, "FFW_PLATFORM:WAKE status=REFUSED provenance=kernel mechanism=eventfd reason=sys"),
                         5, "FFW_PLATFORM:END started=0 refused=wake:sys")
        self.assertEqual(self.problems(lines), ["platform_not_run_unexplained:CLOCK"])
        # KERNEL refused but a capability ran after it.
        lines = replaced(replaced(self.healthy, 1, "FFW_PLATFORM:KERNEL status=REFUSED reason=abi_mismatch"),
                         5, "FFW_PLATFORM:END started=0 refused=kernel:abi_mismatch")
        self.assertEqual(self.problems(lines), ["platform_ran_after_kernel_refusal:CLOCK", "platform_ran_after_kernel_refusal:ENTROPY",
                                                "platform_ran_after_kernel_refusal:WAKE"])

    def test_an_end_that_names_the_wrong_refusal(self):
        lines = replaced(replaced(self.healthy, 2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel reason=absent"),
                         5, "FFW_PLATFORM:END started=0 refused=entropy:absent")
        self.assertEqual(self.problems(lines),
                         ["platform_end_disagrees:names_entropy:absent_but_the_first_refusal_is_clock:absent"])

    def test_malformed_lines(self):
        for label, index, line, problem in [
            ("a trailing space", 1, self.healthy[1] + " ", "platform_malformed:KERNEL"),
            ("a double space", 2, self.healthy[2].replace(" provenance", "  provenance"), "platform_malformed:CLOCK"),
            ("a lowercase status", 1, self.healthy[1].replace("PASS", "pass"), "platform_value:KERNEL:status=pass"),
            ("a clock value leaked", 2, self.healthy[2] + " ns=123456", "platform_fields:CLOCK:status,provenance,ns"),
            ("keys in the wrong order", 2, "FFW_PLATFORM:CLOCK provenance=kernel status=PASS", "platform_fields:CLOCK:provenance,status"),
            ("BEGIN without kernel=", 0, self.healthy[0].rsplit(" kernel=", 1)[0], "platform_fields:BEGIN:abi,evidence,backend"),
            ("kernel= empty", 0, self.healthy[0].rsplit("=", 1)[0] + "=", "platform_malformed:BEGIN"),
            ("no fields at all", 1, "FFW_PLATFORM:KERNEL", "platform_fields:KERNEL:none"),
            ("a token with no equals", 1, "FFW_PLATFORM:KERNEL PASS", "platform_malformed:KERNEL"),
        ]:
            self.assertEqual(self.problems(replaced(self.healthy, index, line)), [problem], label)

    def test_the_wrong_guest_names_the_abi(self):
        self.assertEqual(judge(self.healthy, "mips")["problems"], [WRONG_ABI["mips"]])
        wrong_evidence = replaced(self.healthy, 0, self.healthy[0].replace("harness-ppc-4.9", "harness-mips-4.19"))
        self.assertEqual(judge(wrong_evidence, "ppc")["problems"], ["platform_abi:powerpc32_harness-mips-4.19_for_ppc"])
        with self.assertRaises(ValueError):
            judge(self.healthy, "arm")


# ---- two independently written judges over one file ----------------------------------------------------------------


def load_reference_judge():
    path = REPO / "tests" / "p02" / "test_platform_markers.py"
    spec = importlib.util.spec_from_file_location("yellowbrook_reference_judge", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CrossJudgeTests(unittest.TestCase):
    """The reference judge in tests/p02 (YellowBrook's, written from the same contract) and this one must agree, on every
    committed example and on every line-level plant: `judge_for_guest(...) == []` exactly when the verdict is not red. A
    disagreement is a bug in one of them, not a difference of taste."""

    @classmethod
    def setUpClass(cls):
        path = REPO / "tests" / "p02" / "test_platform_markers.py"
        if not path.is_file():                  # fail closed: a missing reference judge is not a skipped cross-check
            raise AssertionError(f"the reference judge is missing: {path}")
        cls.ref = load_reference_judge()
        cls.reasons = GRAMMAR["reasons"]

    # Where the reference judge is MORE LENIENT than the contract, found by this very matrix: its provenance rule covers PASS
    # and NOT_RUN, not REFUSED, so it accepts `ENTROPY status=REFUSED provenance=simulated|none reason=not_seeded` as the MIPS
    # degraded outcome, while the contract says red on "any provenance=simulated" on either guest and a tried capability's
    # provenance is the layer's (kernel). Allowed only for these exact cases and only where this judge says red; the reference
    # judge's owner has the fix (a REFUSED line needs provenance=kernel). If it is fixed the two simply agree and nothing here
    # changes. Any other disagreement fails.
    KNOWN_REFERENCE_GAPS = {
        ("mips_degraded line 3 provenance=kernel->provenance=simulated", "mips"),
        ("mips_degraded line 3 provenance=kernel->provenance=none", "mips"),
    }

    def agree(self, lines, label):
        for arch in ("mips", "ppc"):
            theirs = self.ref.judge_for_guest(list(lines), arch, self.reasons)
            mine = judge(list(lines), arch)
            if (not theirs) == (mine["verdict"] != "red"):
                continue
            self.assertIn((label, arch), self.KNOWN_REFERENCE_GAPS, (label, arch, theirs, mine["problems"]))
            self.assertEqual((theirs, mine["verdict"]), ([], "red"), (label, arch))

    def test_they_agree_on_every_committed_example(self):
        for name in EXAMPLES:
            self.agree(lines_of(name), name)

    def test_they_agree_on_every_line_level_mutation(self):
        healthy = {"ppc": lines_of("powerpc_all_pass"), "mips": lines_of("mips_all_pass")}
        degraded = lines_of("mips_entropy_not_seeded")
        count = 0
        for base_name, lines in [*healthy.items(), ("mips_degraded", degraded)]:
            for i in range(len(lines)):
                self.agree(lines[:i] + lines[i + 1:], f"{base_name} drop {i}")
                self.agree(lines[: i + 1] + lines[i:], f"{base_name} duplicate {i}")
                count += 2
            for i in range(len(lines) - 1):
                swapped = list(lines)
                swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
                self.agree(swapped, f"{base_name} swap {i}")
                count += 1
            for i, line in enumerate(lines):
                for old, new in [("provenance=kernel", "provenance=simulated"), ("provenance=kernel", "provenance=none"),
                                 ("provenance=kernel", "provenance=double"), ("status=PASS", "status=REFUSED"),
                                 ("status=PASS", "status=NOT_RUN"), ("status=REFUSED", "status=PASS"),
                                 ("reason=", "reason=made_up_"), ("started=1", "started=0"), ("started=0", "started=1"),
                                 ("backend=kernel", "backend=simulated"), ("PASS", "pass"), (" provenance", "  provenance")]:
                    if old in line:
                        self.agree(replaced(lines, i, line.replace(old, new, 1)), f"{base_name} line {i} {old}->{new}")
                        count += 1
        self.assertGreater(count, 100, "the matrix must be broad enough to mean something")


# ---- the verifier on full console transcripts ----------------------------------------------------------------------


class VerifierTests(unittest.TestCase):
    def test_the_unplanted_transcripts_pass_and_record_their_verdicts(self):
        for arch in ("mips", "ppc"):
            result = verify(good_text(arch), arch)
            self.assertEqual((result["status"], result["validation_errors"], result["missing_markers"]), ("PASS", [], []), arch)
            platform = result["platform"]
            self.assertEqual((platform["verdict"], platform["outcome"], platform["problems"]), ("green", "exited_0", []), arch)
            self.assertEqual(platform["outcomes"], {"kernel": "PASS", "clock": "PASS", "entropy": "PASS", "wake": "PASS"})
            self.assertTrue(platform["started"])
            self.assertEqual(platform["grammar"]["sha256"], GRAMMAR["sha256"])
            self.assertEqual(platform["console_region"], platform["reported"])
        degraded = verify(transcript(platform_block(*DEGRADED), "mips"), "mips")
        self.assertEqual((degraded["status"], degraded["validation_errors"]), ("PASS", []))
        self.assertEqual((degraded["platform"]["verdict"], degraded["platform"]["degraded_because"], degraded["platform"]["outcome"]),
                         ("degraded", "entropy:not_seeded", "exited_3"))
        self.assertFalse(degraded["platform"]["started"])

    def test_the_other_guests_output_is_red_on_its_abi(self):
        result = verify(transcript(platform_block(*HEALTHY["ppc"]), "mips"), "mips")
        self.assertEqual((result["status"], result["validation_errors"]), ("FAIL", [WRONG_ABI["mips"]]))

    def test_without_the_platform_step_enabled_its_lines_are_unknown_markers(self):
        result = verify(good_text("ppc"), "ppc", platform=None)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"invalid:{P.STEP_BEGIN_KEY}", result["validation_errors"])
        self.assertIn("invalid:FFW_PLATFORM:BEGIN", result["validation_errors"])
        self.assertNotIn("platform", result)
        # The control: the speaker-only transcript is exactly what it was.
        plain = verify(smoke.GOOD_TEXT, "mips", platform=None)
        self.assertEqual((plain["status"], plain["validation_errors"]), ("PASS", []))

    def test_the_platform_step_is_the_speaker_smokes_second_child(self):
        with self.assertRaises(ValueError):
            verify(good_text("ppc"), "ppc", speaker=None)

    def test_a_guest_that_never_ran_the_step_lacks_both_markers(self):
        result = verify(smoke.GOOD_TEXT, "mips")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(sorted(result["missing_markers"]), sorted([P.STEP_BEGIN_KEY, P.STEP_EXIT_KEY]))
        self.assertEqual(result["platform"]["verdict"], "not_run")

    def test_the_step_failure_forms_are_named_and_status_three_with_output_is_not_one(self):
        lines, _ = HEALTHY["ppc"]
        data = as_bytes(lines)
        pair = f"stdout_bytes={len(data)} stdout_fnv1a64={E.fnv1a64(data):016x}"
        for form, named in {
            "spawn=exec errno=2": "spawn=exec errno=2",
            "spawn=pipe errno=24": "spawn=pipe errno=24",
            f"signal=11 {pair}": f"signal=11 {pair}",
            f"status=1 {pair}": f"status=1 {pair}",
            f"status=2 {pair}": f"status=2 {pair}",
            f"status=127 {pair}": f"status=127 {pair}",
            # Exit 2 is the speaker's "no kernel backend" (a build that is not the device build): it prints to stderr and nothing
            # to stdout, so it is a named failure of the step, not a silent pass and not "no kernel" (YellowBrook 4792, point 5).
            "status=2 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325": "status=2 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325",
            f"read_error=5 {pair}": f"read_error=5 {pair}",
            f"wait_status=4991 {pair}": f"wait_status=4991 {pair}",
            "status=3 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325": "status=3 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325",
            "status=0 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325": "status=0 stdout_bytes=0 stdout_fnv1a64=cbf29ce484222325",
        }.items():
            block = platform_block(lines, 0, exit_line=f"{P.STEP_EXIT_KEY} {form}")
            result = verify(transcript(block, "ppc"), "ppc")
            self.assertEqual(result["status"], "FAIL", form)
            self.assertIn(f"platform_step_failed:{named}", result["validation_errors"], form)
            self.assertEqual(result["platform"]["outcome"], "failed", form)
        # Status 3 with output is the refused form: it ran, and the judge decides.
        self.assertIsNotNone(P.STEP_EXIT_OK.fullmatch(f"{P.STEP_EXIT_KEY} status=3 {pair}"))
        self.assertIsNone(P.STEP_EXIT_FAILURE.fullmatch(f"{P.STEP_EXIT_KEY} status=3 {pair}"))
        # A garbled exit line is invalid, not a named failure.
        block = platform_block(lines, 0, exit_line=f"{P.STEP_EXIT_KEY} status=0 {pair} extra")
        result = verify(transcript(block, "ppc"), "ppc")
        self.assertIn(f"invalid:{P.STEP_EXIT_KEY}", result["validation_errors"])
        self.assertEqual(result["platform"]["outcome"], "invalid")

    def test_the_guests_exit_status_must_agree_with_the_lines(self):
        lines, _ = HEALTHY["ppc"]
        result = verify(transcript(platform_block(lines, 3), "ppc"), "ppc")
        self.assertEqual(result["validation_errors"], ["platform_exit_status_disagrees:status=3_started=1"])
        self.assertEqual((result["status"], result["platform"]["verdict"]), ("FAIL", "red"))
        degraded, _ = DEGRADED
        result = verify(transcript(platform_block(degraded, 0), "mips"), "mips")
        self.assertEqual(result["validation_errors"], ["platform_exit_status_disagrees:status=0_started=0"])
        self.assertEqual((result["status"], result["platform"]["verdict"]), ("FAIL", "red"))

    def test_the_console_must_equal_what_the_guest_measured(self):
        lines, status = HEALTHY["ppc"]
        data = as_bytes(lines)
        # One byte of the child's output changed on the console, the guest's numbers left alone.
        block = platform_block(lines, status)
        altered = block.replace("provenance=kernel", "provenance=kernels", 1)
        result = verify(transcript(altered, "ppc"), "ppc")
        self.assertIn("platform_stdout_mismatch:bytes", result["validation_errors"])
        self.assertIn("platform_stdout_mismatch:fnv1a64", result["validation_errors"])
        # Same length, different bytes: only the digest catches it.
        same_length = block.replace("provenance=kernel", "provenance=kernex", 1)
        result = verify(transcript(same_length, "ppc"), "ppc")
        self.assertIn("platform_stdout_mismatch:fnv1a64", result["validation_errors"])
        self.assertNotIn("platform_stdout_mismatch:bytes", result["validation_errors"])
        # A kernel printk inside the region is caught by the measurement and named by the judge.
        noisy = P.STEP_BEGIN_LINE + "\n" + "\r\n".join(lines[:2] + ["[    1.234567] random: crng init done"] + lines[2:]) + "\r\n" \
            + f"{P.STEP_EXIT_KEY} status=0 stdout_bytes={len(data)} stdout_fnv1a64={E.fnv1a64(data):016x}\n"
        result = verify(transcript(noisy, "ppc"), "ppc")
        self.assertIn("platform_stdout_mismatch:bytes", result["validation_errors"])
        self.assertIn("platform_foreign_line:2", result["validation_errors"])

    def test_order_duplicates_and_placement(self):
        lines, status = HEALTHY["ppc"]
        block = platform_block(lines, status)
        # The platform step before the catalog step.
        reversed_text = smoke.transcript(block + smoke.GOOD_BLOCK, ppc=True)
        self.assertIn("platform_order:before_catalog", verify(reversed_text, "ppc")["validation_errors"])
        # A second step.
        twice = verify(transcript(block + block, "ppc"), "ppc")
        self.assertIn(f"duplicate:{P.STEP_BEGIN_KEY}", twice["validation_errors"])
        self.assertIn("platform_region:begin_or_exit_not_exactly_once", twice["validation_errors"])
        # A line of the family outside the step is judged by nothing else, so it is an error of its own.
        stray = transcript(block, "ppc").replace("FFW_MARKER:USERSPACE_START\n", "FFW_MARKER:USERSPACE_START\nFFW_PLATFORM:CLOCK status=PASS provenance=kernel\n", 1)
        self.assertIn("platform_outside_step", verify(stray, "ppc")["validation_errors"])
        self.assertNotIn("platform_outside_step", verify(good_text("ppc"), "ppc")["validation_errors"])
        # The guest's own TEST_FAILURE after a step that failed is the usual consequence, as for the speaker step.
        failed = verify(transcript(platform_block(lines, 0, exit_line=f"{P.STEP_EXIT_KEY} spawn=exec errno=2"), "ppc").replace(
            "FFW_MARKER:TEST_SUCCESS failures=0\n", "FFW_MARKER:TEST_FAILURE failures=1\n"), "ppc")
        self.assertEqual(failed["validation_errors"], ["platform_step_failed:spawn=exec errno=2", "invalid:FFW_MARKER:TEST_FAILURE"])

    def test_a_platform_line_that_claims_provenance_double_fails_by_name(self):
        lines, status = HEALTHY["ppc"]
        planted = replaced(lines, 2, lines[2].replace("provenance=kernel", "provenance=double"))
        result = verify(transcript(platform_block(planted, status), "ppc"), "ppc")
        self.assertEqual((result["status"], result["validation_errors"]), ("FAIL", ["platform_value:CLOCK:provenance=double"]))
        self.assertEqual(result["platform"]["verdict"], "red")
        # The remove-the-plant control: the same transcript without the plant passes.
        self.assertEqual(verify(good_text("ppc"), "ppc")["status"], "PASS")


# ---- the controls: planted transcripts, each against an unplanted baseline of the same guest ------------------------


BASELINES = {
    "ppc green": ("ppc", HEALTHY["ppc"]),
    "mips green": ("mips", HEALTHY["mips"]),
    "mips degraded": ("mips", DEGRADED),
}


class ControlTests(unittest.TestCase):
    def test_the_planted_set_is_the_agreed_one(self):
        # BeigeMaple 4778 named three (a transcript claiming provenance=double, a missing capability, a truncated run);
        # YellowBrook 4792 added the two values a double really prints. `double` is not a value of the grammar, so it is
        # named as an unknown value; `simulated` is a value of the grammar, so it is named as a simulation. Different faults.
        self.assertEqual(set(P.PLANTS), {"provenance_double", "provenance_simulated", "backend_simulated",
                                         "missing_capability", "truncated"})
        self.assertNotEqual(P.PLANTS["provenance_double"]["expected"], P.PLANTS["provenance_simulated"]["expected"])

    def test_every_plant_fails_for_its_own_reason_and_no_other_against_each_baseline(self):
        for label, (arch, (lines, status)) in BASELINES.items():
            text = transcript(platform_block(lines, status), arch)
            baseline = verify(text, arch)
            self.assertEqual((baseline["status"], baseline["platform"]["verdict"] in ("green", "degraded")), ("PASS", True), label)
            for plant, spec in P.PLANTS.items():
                planted = P.plant_transcript(text, plant)
                self.assertNotEqual(planted, text, (label, plant))
                result = verify(planted, arch)
                self.assertEqual((result["status"], result["validation_errors"]), ("FAIL", spec["expected"]), (label, plant))
                judged = VERIFIER.judge_platform_control(result, plant)
                self.assertTrue(judged["caught"], (label, plant, judged["checks"]))

    def test_a_plant_is_resealed_so_the_measurement_is_not_what_catches_it(self):
        lines, status = HEALTHY["ppc"]
        text = good_text("ppc")
        for plant in P.PLANTS:
            planted = P.plant_transcript(text, plant)
            platform = verify(planted, "ppc")["platform"]
            self.assertEqual(platform["console_region"], platform["reported"], plant)

    def test_the_planted_transcript_keeps_the_consoles_line_endings(self):
        for crlf in (True, False):
            lines, status = HEALTHY["ppc"]
            text = transcript(platform_block(lines, status, crlf=crlf), "ppc")
            for plant in P.PLANTS:
                planted = P.plant_transcript(text, plant)
                result = verify(planted, "ppc")
                self.assertEqual(result["validation_errors"], P.PLANTS[plant]["expected"], (crlf, plant))
                region = planted.split(P.STEP_BEGIN_KEY, 1)[1].split(P.STEP_EXIT_KEY, 1)[0]
                self.assertEqual("\r" in region, crlf, (crlf, plant))

    def test_a_plant_that_cannot_be_applied_is_an_error_not_a_pass(self):
        with self.assertRaises(ValueError):
            P.plant_transcript(smoke.GOOD_TEXT, "truncated")          # no platform step in the log
        with self.assertRaises(ValueError):
            P.plant_transcript(good_text("ppc"), "nonexistent")
        lines, _ = DEGRADED
        no_clock = replaced(lines, 2, "FFW_PLATFORM:CLOCK status=PASS provenance=none")
        with self.assertRaises(ValueError):
            P.plant_transcript(transcript(platform_block(no_clock, 3), "mips"), "provenance_double")

    def test_a_judge_that_passes_everything_is_not_credited_by_the_controls(self):
        text = good_text("ppc")
        blind = {"verdict": "green", "problems": [], "lines": [], "outcomes": {}, "started": True, "kernel_release": None}
        with patch.object(P, "judge_output", return_value=blind):
            for plant in P.PLANTS:
                result = verify(P.plant_transcript(text, plant), "ppc")
                self.assertFalse(VERIFIER.judge_platform_control(result, plant)["caught"], plant)
        # The control: the real judge catches the same plants.
        for plant in P.PLANTS:
            self.assertTrue(VERIFIER.judge_platform_control(verify(P.plant_transcript(text, plant), "ppc"), plant)["caught"], plant)

    def test_a_plant_caught_for_a_different_reason_is_not_caught(self):
        # `truncated` expects exactly one named problem. A transcript with an additional defect fails the "only" check.
        text = good_text("ppc").replace("FFW_PROBE:POLL status=PASS rc=1\n", "FFW_PROBE:POLL status=PASS rc=2\n")
        result = verify(P.plant_transcript(text, "truncated"), "ppc")
        self.assertFalse(VERIFIER.judge_platform_control(result, "truncated")["caught"])
        self.assertIn("platform_truncated:after:CLOCK", result["validation_errors"])

    def test_run_platform_controls_returns_every_plant_caught_on_a_good_baseline(self):
        cfg = {"hello": base.HELLO, "enosys": base.ENOSYS, "triple": base.MIPS_TRIPLE}
        controls = VERIFIER.run_platform_controls(good_text("mips"), "mips", cfg, SPEAKER, PLATFORM)
        self.assertEqual(sorted(controls), sorted(P.PLANTS))
        for name, record in controls.items():
            self.assertTrue(record["caught"], (name, record))
            self.assertEqual(record["observed"], record["expected"])
        # A log with no platform step: every plant is reported as not applied, none as caught.
        none = VERIFIER.run_platform_controls(smoke.GOOD_TEXT, "mips", cfg, SPEAKER, PLATFORM)
        self.assertTrue(all("not_applied" in record and not record["caught"] for record in none.values()))


# ---- the runner end to end, with patched guests --------------------------------------------------------------------


class RunnerPlatformTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.mips_speaker = self.root / "speaker-mips"
        self.ppc_speaker = self.root / "speaker-ppc"
        self.mips_speaker.write_bytes(base.elf32(8) + b"mips-speaker")
        self.ppc_speaker.write_bytes(base.elf32(20) + b"ppc-speaker")
        self.runs = 0

    @staticmethod
    def capture(text):
        return {"stdout": text.encode(), "stderr": b"", "returncode": 0, "stop_reason": None}

    def lay_out(self, target_name):
        target = self.root / target_name
        for triple, machine in ((base.MIPS_TRIPLE, 8), (base.PPC_TRIPLE, 20)):
            binary = target / triple / "release/ffw-hello-init"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(base.elf32(machine))
        for kernel in ("kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta", "kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc"):
            (self.root / kernel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / kernel).write_bytes(b"synthetic-kernel-not-executed")
        return target

    def run_main(self, captures, argv, target_name="target", explicit_target=True, build=False, real_rch=False):
        self.builds = []

        def fake_run(cmd, **kwargs):
            self.builds.append((list(cmd), kwargs))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        target = self.lay_out(target_name)
        self.runs += 1
        output = self.output = self.root / f"result{self.runs}"            # never reused
        full = ["--results-dir", str(output), *argv] if build else ["--skip-build", "--results-dir", str(output), *argv]
        if explicit_target:
            full += ["--target-dir", str(target)]
        with patch.object(VERIFIER.mkinitramfs, "resolve_default_build_dir", return_value=self.root), \
             patch.object(VERIFIER, "capture_guest", side_effect=captures), \
             contextlib.ExitStack() as stack:
            if build and not real_rch:
                stack.enter_context(patch.object(VERIFIER.subprocess, "run", side_effect=fake_run))
                stack.enter_context(patch.object(VERIFIER, "admit_before_build", return_value={"attempts": 1, "recommendation": "offload", "observation": "observed", "worker": "trj", "reason": None}))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            result = VERIFIER.main(full)
        return result, json.loads((output / "e07-e03-verification-receipt.json").read_text())

    def argv(self, *extra):
        return ["--speaker-mips", str(self.mips_speaker), "--speaker-ppc", str(self.ppc_speaker), *extra]

    def captures(self, mips=None, ppc=None):
        """The real run of each guest, in call order. The default is what the contract expects: MIPS degraded, PowerPC green."""
        return [self.capture(mips if mips is not None else transcript(platform_block(*DEGRADED), "mips")),
                self.capture(ppc if ppc is not None else good_text("ppc"))]

    def test_a_clean_run_records_green_and_degraded_and_every_control_caught(self):
        result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform", "--platform-controls"))
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        step = receipt["platform_step"]
        self.assertEqual(step["verdicts"], {"mips": "degraded", "ppc": "green"})
        self.assertEqual((step["feature"], step["controls_requested"], step["argv"]),
                         ("speaker-platform", True, ["/franken-speaker", "--platform-startup"]))
        self.assertEqual(step["grammar"], {"source": P.VECTORS, "sha256": GRAMMAR["sha256"]})
        for arch, verdict in (("mips", "degraded"), ("ppc", "green")):
            guest = receipt["guests"][arch]
            self.assertEqual((guest["status"], guest["validation_errors"]), ("PASS", []), arch)
            platform = guest["platform"]
            self.assertEqual(platform["verdict"], verdict)
            self.assertIn("Sonos silicon", platform["qualification_boundary"])
            self.assertEqual(sorted(platform["controls"]), sorted(P.PLANTS))
            for name, control in platform["controls"].items():
                self.assertTrue(control["caught"], (arch, name, control))
            self.assertEqual(guest["build_manifest"].get("features"), ["speaker-smoke", "speaker-platform"])
        self.assertEqual(receipt["guests"]["mips"]["platform"]["kernel_release"], "4.19.0-21-4kc-malta")
        self.assertEqual(receipt["guests"]["mips"]["platform"]["degraded_because"], "entropy:not_seeded")

    def test_a_red_platform_fails_the_run_and_the_controls_are_not_credited(self):
        lines, status = HEALTHY["mips"]
        simulated = replaced(lines, 2, lines[2].replace("provenance=kernel", "provenance=simulated"))
        bad = transcript(platform_block(simulated, status), "mips")
        result, receipt = self.run_main(self.captures(mips=bad), self.argv("--speaker-platform", "--platform-controls"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        mips = receipt["guests"]["mips"]
        self.assertEqual(mips["platform"]["verdict"], "red")
        self.assertEqual(mips["platform"]["controls"], {n: {"skipped": "baseline_failed"} for n in P.PLANTS})
        self.assertEqual(mips["validation_errors"][0], "platform_simulated:CLOCK")
        self.assertEqual(sorted(e for e in mips["validation_errors"] if e.startswith("platform_control")),
                         [f"platform_control_not_run:{n}" for n in sorted(P.PLANTS)])
        self.assertEqual(receipt["guests"]["ppc"]["status"], "PASS")
        self.assertEqual(receipt["platform_step"]["verdicts"], {"mips": "red", "ppc": "green"})

    def test_a_judge_that_accepts_everything_fails_the_run_through_its_controls(self):
        blind = {"verdict": "green", "problems": [], "lines": [], "outcomes": {}, "started": True, "kernel_release": None}
        # Both baselines are healthy runs (started, exit 0): a judge that always says "started" must not disagree with the
        # guest's own exit status, or the baseline would be red and the controls skipped for that reason instead.
        captures = self.captures(mips=good_text("mips"))
        with patch.object(P, "judge_output", return_value=blind):
            result, receipt = self.run_main(captures, self.argv("--speaker-platform", "--platform-controls"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        for arch in ("mips", "ppc"):
            errors = receipt["guests"][arch]["validation_errors"]
            self.assertEqual(sorted(e for e in errors if e.startswith("platform_control_not_caught")),
                             [f"platform_control_not_caught:{n}" for n in sorted(P.PLANTS)], arch)

    def test_a_guest_whose_step_never_ran_fails_with_both_markers_missing(self):
        result, receipt = self.run_main([self.capture(smoke.GOOD_TEXT), self.capture(base.ppc_transcript(smoke.GOOD_TEXT))],
                                        self.argv("--speaker-platform"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        self.assertEqual(sorted(receipt["guests"]["mips"]["missing_markers"]), sorted([P.STEP_BEGIN_KEY, P.STEP_EXIT_KEY]))

    def test_without_the_flag_the_run_is_the_speaker_smoke_it_was(self):
        result, receipt = self.run_main([self.capture(smoke.GOOD_TEXT), self.capture(base.ppc_transcript(smoke.GOOD_TEXT))], self.argv())
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertNotIn("platform_step", receipt)
        self.assertNotIn("platform", receipt["guests"]["mips"])
        # And a transcript that does print the platform step is, without the flag, a failing guest.
        result, receipt = self.run_main(self.captures(), self.argv())
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))

    def test_the_build_command_carries_both_features_and_the_platform_target_directory(self):
        result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform", "--jobs", "2"), build=True)
        ran = [cmd for cmd, _ in self.builds if cmd[:1] == ["rch"]]
        self.assertEqual(len(ran), 2)
        for triple, cmd in zip((base.MIPS_TRIPLE, base.PPC_TRIPLE), ran):
            self.assertEqual(cmd, ["rch", "exec", "--source-content-receipt", "--", "cargo", "+nightly", "build", "--release",
                                   "--target", triple, "-Z", "build-std=core,panic_abort",
                                   "--features", "speaker-smoke,speaker-platform", "-j", "2"])
        # With no --target-dir the platform build has its own directory, so the speaker-smoke build products are never overwritten.
        result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform"), target_name="hello-init-platform-target",
                                        explicit_target=False)
        self.assertEqual((result, receipt["status"]), (0, "PASS"))

    def test_bad_arguments_are_refused_with_a_reason(self):
        for argv, fragment in [
            (["--speaker-platform"], "need --speaker-mips and --speaker-ppc"),
            (self.argv("--platform-controls"), "--platform-controls needs --speaker-platform"),
            (["--check-catalog", str(self.root / "x"), "--speaker-platform"], "stands alone"),
        ]:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                VERIFIER.main(["--skip-build", "--results-dir", str(self.root / "unused"), *argv])
            self.assertEqual(raised.exception.code, 2, argv)
            self.assertIn(fragment, err.getvalue(), argv)
        self.assertFalse((self.root / "unused").exists(), "a refused argument list runs nothing and writes nothing")

    def test_a_missing_grammar_file_is_refused_before_any_guest(self):
        empty = self.root / "empty-repo"
        empty.mkdir()
        err = io.StringIO()
        with patch.object(VERIFIER, "REPO_ROOT", empty), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            VERIFIER.main(["--skip-build", "--results-dir", str(self.root / "unused2"), *self.argv("--speaker-platform")])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--speaker-platform: cannot read", err.getvalue())
        self.assertFalse((self.root / "unused2").exists())

    # ---- the explicit legacy provider: `--entropy-provider` ----

    PROVIDER_ARGV = ("--speaker-platform", "--platform-controls", "--entropy-provider", "legacy-dev-random-test-environment")

    def provider_captures(self, mips=None, ppc=None):
        """The provider run of each guest: MIPS green (a blocking read that returned), PowerPC green, unless a case gives its own."""
        return [self.capture(mips if mips is not None else provider_text("mips", *PROVIDER_BASELINES["mips green"][1:])),
                self.capture(ppc if ppc is not None else provider_text("ppc", *PROVIDER_BASELINES["ppc green"][1:]))]

    def test_a_provider_run_records_its_provider_and_every_control_caught(self):
        result, receipt = self.run_main(self.provider_captures(), self.argv(*self.PROVIDER_ARGV))
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        step = receipt["platform_step"]
        self.assertEqual(step["verdicts"], {"mips": "green", "ppc": "green"})
        self.assertEqual((step["feature"], step["provider"], step["provider_feature"]),
                         ("speaker-platform", PROV, "speaker-platform-legacy-test-env"))
        self.assertEqual(step["argv"], ["/franken-speaker", "--platform-startup", PROV_ARG])
        scripts = {name: VERIFIER.sha256_file(VERIFIER.SCRIPT_DIR / name) for name in ("boot-mips.sh", "boot-ppc.sh")}
        self.assertEqual(step["entropy_injection_checked"], scripts)
        for arch, verdict in (("mips", "green"), ("ppc", "green")):
            guest = receipt["guests"][arch]
            self.assertEqual((guest["status"], guest["validation_errors"]), ("PASS", []), arch)
            platform = guest["platform"]
            self.assertEqual((platform["verdict"], platform["provider"]), (verdict, PROV), arch)
            self.assertEqual(platform["argv"], ["/franken-speaker", "--platform-startup", PROV_ARG])
            self.assertIn("no positive", platform["claim"])
            self.assertIn("Sonos silicon", platform["qualification_boundary"])
            boundary = platform["qualification_boundary"]
            self.assertIn("static text check", boundary)
            self.assertIn("does not show that the pool was not credited some other way", boundary)
            self.assertNotIn("nothing fed", boundary)                     # the sentence a text check cannot establish
            self.assertEqual(sorted(platform["controls"]), sorted(P.plants_for(PROV)))
            for name, control in platform["controls"].items():
                self.assertTrue(control["caught"], (arch, name, control))
            self.assertEqual(guest["build_manifest"].get("features"),
                             ["speaker-smoke", "speaker-platform", "speaker-platform-legacy-test-env"])
        self.assertIn("blocks until the pool is ready", receipt["guests"]["mips"]["platform"]["claim"])      # the receipt says which kind of read it saw
        self.assertIn("EAGAIN", receipt["guests"]["ppc"]["platform"]["claim"])

    def test_an_unseeded_pool_is_degraded_on_powerpc_and_red_on_mips_and_never_green(self):
        both = self.provider_captures(ppc=provider_text("ppc", *PROVIDER_BASELINES["ppc degraded"][1:]))
        result, receipt = self.run_main(both, self.argv(*self.PROVIDER_ARGV))
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertEqual(receipt["platform_step"]["verdicts"], {"mips": "green", "ppc": "degraded"})
        self.assertNotEqual(receipt["guests"]["ppc"]["platform"]["verdict"], "green")
        self.assertFalse(receipt["guests"]["ppc"]["platform"]["started"])
        # The MIPS kernel cannot give that refusal: a MIPS transcript that says so fails the run, with both problems named.
        refused = provider_text("mips", legacy("legacy_test_environment_not_seeded_mips"), 3)
        result, receipt = self.run_main(self.provider_captures(mips=refused), self.argv(*self.PROVIDER_ARGV))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        mips = receipt["guests"]["mips"]
        self.assertEqual((mips["platform"]["verdict"], mips["validation_errors"][:2]), ("red", MIPS_NOT_SEEDED_RED))   # the controls are then not run
        self.assertTrue(all(e.startswith("platform_control_not_run:") for e in mips["validation_errors"][2:]))
        self.assertNotIn("degraded_because", mips["platform"])

    def test_a_missing_device_node_fails_the_provider_run_by_name(self):
        absent = provider_text("mips", legacy("legacy_device_absent_mips"), 3)
        result, receipt = self.run_main(self.provider_captures(mips=absent), self.argv(*self.PROVIDER_ARGV))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        mips = receipt["guests"]["mips"]
        self.assertEqual(mips["platform"]["verdict"], "red")
        self.assertEqual(mips["validation_errors"][0], "platform_not_started:entropy:absent")
        self.assertEqual(mips["platform"]["controls"], {n: {"skipped": "baseline_failed"} for n in P.plants_for(PROV)})
        self.assertEqual(receipt["guests"]["ppc"]["status"], "PASS")

    def test_a_provider_run_whose_guest_ran_the_default_step_fails_on_both_counts(self):
        result, receipt = self.run_main(self.captures(), self.argv(*self.PROVIDER_ARGV))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        for arch in ("mips", "ppc"):
            errors = receipt["guests"][arch]["validation_errors"]
            self.assertIn(f"invalid:{P.STEP_BEGIN_KEY}", errors, arch)               # the BEGIN line lacks the provider argument
            self.assertIn("platform_provider_missing:ENTROPY", errors, arch)         # and the child printed no provider=

    def test_a_default_run_rejects_a_guest_that_selected_a_provider(self):
        result, receipt = self.run_main(self.provider_captures(), self.argv("--speaker-platform"))
        self.assertEqual((result, receipt["status"]), (1, "FAIL"))
        for arch in ("mips", "ppc"):
            errors = receipt["guests"][arch]["validation_errors"]
            self.assertIn(f"invalid:{P.STEP_BEGIN_KEY}", errors, arch)
            self.assertTrue(any(e.startswith("platform_fields:ENTROPY:status,provenance,provider") for e in errors), (arch, errors))

    def test_a_default_receipt_has_exactly_the_shape_it_had(self):
        result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform", "--platform-controls"))
        self.assertEqual(result, 0)
        self.assertEqual(sorted(receipt["platform_step"]), ["argv", "controls_requested", "feature", "grammar", "verdicts"])
        for arch in ("mips", "ppc"):
            platform = receipt["guests"][arch]["platform"]
            self.assertNotIn("provider", platform)
            self.assertNotIn("claim", platform)
            self.assertEqual(platform["qualification_boundary"], VERIFIER.PLATFORM_BOUNDARY)
            self.assertEqual(platform["argv"], ["/franken-speaker", "--platform-startup"])

    def test_the_provider_build_command_and_directory(self):
        result, receipt = self.run_main(self.provider_captures(), self.argv(*self.PROVIDER_ARGV, "--jobs", "2"), build=True)
        ran = [cmd for cmd, _ in self.builds if cmd[:1] == ["rch"]]
        self.assertEqual(len(ran), 2)
        for triple, cmd in zip((base.MIPS_TRIPLE, base.PPC_TRIPLE), ran):
            self.assertEqual(cmd, ["rch", "exec", "--source-content-receipt", "--", "cargo", "+nightly", "build", "--release",
                                   "--target", triple, "-Z", "build-std=core,panic_abort",
                                   "--features", "speaker-smoke,speaker-platform,speaker-platform-legacy-test-env", "-j", "2"])
        # With no --target-dir the provider build has its own directory: neither the default platform build nor the speaker
        # smoke build products are overwritten by it.
        result, receipt = self.run_main(self.provider_captures(), self.argv(*self.PROVIDER_ARGV),
                                        target_name="hello-init-platform-legacy-target", explicit_target=False)
        self.assertEqual((result, receipt["status"]), (0, "PASS"))

    def test_provider_arguments_are_refused_with_a_reason(self):
        for argv, fragment in [
            (self.argv("--entropy-provider", "legacy-dev-random-test-environment"), "--entropy-provider needs --speaker-platform"),
            (self.argv("--speaker-platform", "--entropy-provider", "urandom"), "invalid choice"),
            (self.argv("--speaker-platform", "--entropy-provider", "legacy_dev_random_test_environment"), "invalid choice"),
            (["--check-catalog", str(self.root / "x"), "--entropy-provider", "legacy-dev-random-test-environment"], "stands alone"),
        ]:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                VERIFIER.main(["--skip-build", "--results-dir", str(self.root / "unused3"), *argv])
            self.assertEqual(raised.exception.code, 2, argv)
            self.assertIn(fragment, err.getvalue(), argv)
        self.assertFalse((self.root / "unused3").exists(), "a refused argument list runs nothing and writes nothing")

    def test_a_boot_script_that_names_an_rng_device_refuses_the_provider_run_before_any_guest(self):
        err = io.StringIO()
        with patch.object(VERIFIER, "entropy_injection_problems", return_value=["boot-mips.sh:names_an_rng_device"]), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            VERIFIER.main(["--skip-build", "--results-dir", str(self.root / "unused4"), *self.argv(*self.PROVIDER_ARGV)])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("fails the entropy-injection text check: boot-mips.sh:names_an_rng_device", err.getvalue())
        self.assertFalse((self.root / "unused4").exists())
        # The control: a default platform run never asks the question (the boot scripts are the same files).
        with patch.object(VERIFIER, "entropy_injection_problems", side_effect=AssertionError("asked")):
            result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform"))
        self.assertEqual((result, receipt["status"]), (0, "PASS"))

    # ---- a positive admission before EACH guest build (BeigeMaple 6773/6789): a PATH-stubbed `rch`, no network ----

    OFFLOAD = {"recommendation": "offload", "observation": "observed",
               "selection": {"worker": {"id": "trj", "host": "ubuntu@host.invalid"}, "reason": "fastest"}}
    BUSY = {"recommendation": "queue", "observation": "observed",
            "selection": {"worker": {"id": "trj", "host": "ubuntu@host.invalid"}, "reason": "all_workers_busy"}}
    STALE = {"recommendation": "queue", "observation": "observed", "selection": {"reason": "capacity_sample_expired"}}
    # What a real `rch admit --json` printed when its preview timed out (a dict reason, no recommendation).
    TIMED_OUT = {"recommendation": None, "observation": "unknown",
                 "selection": {"reason": {"selection_error": "admission_preview_timed_out"}}}

    def stub_run(self, plan, argv=("--speaker-platform",), label="r1", workers=None, tries=3, captures=None, build=True, spacing=0.0,
                 call_timeout=None):
        """The runner's build path against a stub `rch` on PATH that answers `workers capabilities`, `admit` (the next verdict of
        `plan[target]`, the last one repeating) and `exec` (rc 0), and logs every call as one JSON line. Returns (result, receipt,
        events, stderr)."""
        stub_dir = self.root / "rchstub"
        stub_dir.mkdir(exist_ok=True)
        stub = stub_dir / "rch"
        if not stub.exists():
            stub.write_text(RCH_STUB.replace("@PYTHON@", sys.executable), encoding="utf-8")
            stub.chmod(0o755)
        (stub_dir / f"plan-{label}.json").write_text(json.dumps(plan), encoding="utf-8")
        env = {"PATH": str(stub_dir) + os.pathsep + os.environ.get("PATH", ""), "RCH_STUB_DIR": str(stub_dir), "RCH_STUB_RUN": label}
        err = io.StringIO()
        with patch.dict(os.environ, env), patch.object(VERIFIER, "ADMISSION_SPACING_S", spacing), \
                patch.object(VERIFIER, "ADMISSION_TRIES", tries), contextlib.redirect_stderr(err), \
                patch.object(VERIFIER, "ADMISSION_CALL_TIMEOUT_S", call_timeout or VERIFIER.ADMISSION_CALL_TIMEOUT_S):
            for name in ("RCH_WORKERS", "RCH_WORKER"):
                os.environ.pop(name, None)
            if workers is not None:
                os.environ["RCH_WORKERS"] = workers
            result, receipt = self.run_main(captures if captures is not None else self.captures(), self.argv(*argv), build=build,
                                            real_rch=True)
        log = stub_dir / f"events-{label}.log"
        events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
        return result, receipt, events, err.getvalue()

    @staticmethod
    def kinds(events):
        return [(event["ev"], event.get("target")) for event in events]

    def test_a_guest_is_built_only_after_a_fresh_sample_and_a_positive_admission(self):
        # (a) queue, then offload: each guest is built once, after its own sample and its own admission.
        result, receipt, events, _ = self.stub_run({"mips": [self.STALE, self.OFFLOAD], "powerpc": [self.OFFLOAD]})
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertEqual(self.kinds(events), [
            ("capabilities", None), ("admit", "mips"), ("capabilities", None), ("admit", "mips"), ("exec-begin", "mips"), ("exec-end", "mips"),
            ("capabilities", None), ("admit", "powerpc"), ("exec-begin", "powerpc"), ("exec-end", "powerpc")])
        self.assertEqual(sum(1 for event in events if event["ev"] == "exec-begin"), 2)
        for event in events:
            if event["ev"] == "capabilities":
                self.assertEqual(event["args"], ["workers", "capabilities", "--refresh", "--json"])
            if event["ev"] == "admit":
                self.assertEqual(event["args"], ["admit", "--json", "--"])
        self.assertEqual(receipt["build_admission"], {
            "mips": {"attempts": 2, "refresh_exit_codes": [0, 0], "recommendation": "offload", "observation": "observed", "worker": "trj",
                     "reason": "fastest"},
            "ppc": {"attempts": 1, "refresh_exit_codes": [0], "recommendation": "offload", "observation": "observed", "worker": "trj",
                    "reason": "fastest"}})

    def test_a_busy_pool_is_rchs_own_queued_wait_and_the_build_goes_ahead(self):
        result, receipt, events, _ = self.stub_run({"mips": [self.BUSY], "powerpc": [self.BUSY]})
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertEqual([r["attempts"] for r in receipt["build_admission"].values()], [1, 1])
        self.assertEqual(sum(1 for event in events if event["ev"] == "exec-begin"), 2)

    def test_a_guest_that_is_never_admitted_is_refused_by_name_and_nothing_is_built(self):
        # (b) The answer rch really gave when its preview timed out. The first guest is refused: no exec for it, and none for the second.
        result, receipt, events, stderr = self.stub_run({"mips": [self.TIMED_OUT], "powerpc": [self.OFFLOAD]}, tries=3)
        self.assertEqual((result, receipt["status"], receipt["error_type"]), (1, "FAIL", "AdmissionRefused"))
        self.assertEqual(self.kinds(events), [("capabilities", None), ("admit", "mips")] * 3)
        self.assertFalse([event for event in events if event["ev"].startswith("exec")])
        self.assertEqual(receipt["build_admission"], {"mips": {
            "attempts": 3, "refresh_exit_codes": [0, 0, 0], "recommendation": None, "observation": "unknown", "worker": None,
            "reason": "selection_error=admission_preview_timed_out", "refused": True}})
        self.assertNotIn("guests", receipt)                                    # nothing was booted
        # The host address is in rch's answer and in its stderr: the receipt never has it, the runner's stderr keeps rch's own text.
        self.assertNotIn("host.invalid", json.dumps(receipt))
        self.assertIn("stub admit stderr: worker ubuntu@host.invalid", stderr)

    def test_retries_are_spaced_and_a_hung_rch_is_a_refusal_not_a_hang(self):
        slept = []
        with patch.object(VERIFIER.time, "sleep", side_effect=slept.append):
            result, receipt, _, _ = self.stub_run({"mips": [self.TIMED_OUT]}, tries=3, spacing=VERIFIER.ADMISSION_SPACING_S)
        self.assertEqual((result, receipt["error_type"]), (1, "AdmissionRefused"))
        # subprocess polls with short sleeps of its own while it waits on a timed call; the gate's are the 15 s ones.
        self.assertEqual([s for s in slept if s >= 1.0], [15.0, 15.0])           # between the tries, not before the first or after the last
        # A call that outlives its timeout is killed and counted as no answer; the run does not wait for it.
        result, receipt, events, stderr = self.stub_run({"mips": [{"__sleep__": 5}]}, label="hang", tries=2, call_timeout=0.4)
        self.assertEqual((result, receipt["error_type"]), (1, "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"]["observation"], "rc=-1")
        self.assertIn("timed out", stderr)
        self.assertFalse([event for event in events if event["ev"].startswith("exec")])

    def test_the_second_guests_admission_comes_after_the_first_build_returns(self):
        # (c)
        _, receipt, events, _ = self.stub_run({"mips": [self.OFFLOAD], "powerpc": [self.OFFLOAD]})
        kinds = self.kinds(events)
        first_build_done = kinds.index(("exec-end", "mips"))
        second_admission = kinds.index(("admit", "powerpc"))
        self.assertGreater(second_admission, first_build_done)
        self.assertEqual(kinds[first_build_done + 1], ("capabilities", None))       # a fresh sample after the release, before the admit
        self.assertEqual(kinds[second_admission - 1], ("capabilities", None))
        self.assertLess(kinds.index(("exec-begin", "mips")), kinds.index(("admit", "powerpc")))

    def test_the_admission_uses_the_builds_own_cargo_argv_environment_and_directory(self):
        _, receipt, events, _ = self.stub_run({"mips": [self.OFFLOAD], "powerpc": [self.OFFLOAD]}, argv=("--speaker-platform", "--jobs", "2"))
        for target in ("mips", "powerpc"):
            admit = next(e for e in events if e["ev"] == "admit" and e["target"] == target)
            build = next(e for e in events if e["ev"] == "exec-begin" and e["target"] == target)
            self.assertEqual(admit["argv"], build["argv"], target)                  # the exact cargo argv after the `--`
            self.assertEqual(admit["argv"][:3], ["cargo", "+nightly", "build"], target)
            self.assertIn("--features", admit["argv"], target)
            for key in ("cwd", "target_dir", "remote"):
                self.assertEqual(admit[key], build[key], (target, key))
            self.assertEqual(admit["remote"], "1")
            self.assertTrue(admit["cwd"].endswith("ffw-hello-init"), admit["cwd"])
            self.assertTrue(admit["target_dir"].endswith("hello-init-platform-target") or admit["target_dir"].endswith("/target"), admit["target_dir"])

    def test_the_admitted_worker_must_be_in_the_requested_set(self):
        plan = {"mips": [self.OFFLOAD], "powerpc": [self.OFFLOAD]}
        result, receipt, events, _ = self.stub_run(plan, label="r1", workers="hz3", tries=2)
        self.assertEqual((result, receipt["status"], receipt["error_type"]), (1, "FAIL", "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"]["worker"], "trj")
        self.assertFalse([event for event in events if event["ev"].startswith("exec")])
        # The controls: the same answer is a positive admission when its worker is requested, and when no worker is requested.
        for label, workers in (("r2", "trj,hz3"), ("r3", None)):
            result, receipt, _, _ = self.stub_run(plan, label=label, workers=workers, tries=2)
            self.assertEqual((result, receipt["status"]), (0, "PASS"), workers)

    def test_an_answer_that_is_not_json_is_not_an_admission(self):
        result, receipt, events, _ = self.stub_run({"mips": [{"__raw__": "garbage, not json", "__rc__": 3}]}, tries=2)
        self.assertEqual((result, receipt["status"], receipt["error_type"]), (1, "FAIL", "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"],
                         {"attempts": 2, "refresh_exit_codes": [0, 0], "recommendation": "unparsed", "observation": "rc=3", "worker": None,
                          "reason": None, "refused": True})
        self.assertFalse([event for event in events if event["ev"].startswith("exec")])

    def test_a_missing_rch_refuses_at_once_and_a_run_that_builds_nothing_asks_for_nothing(self):
        env = {"PATH": str(self.root / "nowhere")}
        with patch.dict(os.environ, env), patch.object(VERIFIER, "ADMISSION_SPACING_S", 0.0), contextlib.redirect_stderr(io.StringIO()):
            result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform"), build=True, real_rch=True)
        self.assertEqual((result, receipt["status"], receipt["error_type"]), (1, "FAIL", "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"]["observation"], "rch_not_runnable:FileNotFoundError")
        self.assertEqual(receipt["build_admission"]["mips"]["refused"], True)
        # --skip-build issues no build and so asks for no admission: the stub is never called and the receipt has no such record.
        result, receipt, events, _ = self.stub_run({"mips": [self.OFFLOAD]}, label="skip", build=False)
        self.assertEqual((result, receipt["status"], events), (0, "PASS", []))
        self.assertNotIn("build_admission", receipt)

    def test_the_gate_admits_exactly_what_the_instruction_says(self):
        offload = {"recommendation": "offload", "observation": "observed", "worker": "trj", "reason": "fastest"}
        table = [
            (offload, ["trj"], True), (offload, [], True), (offload, ["hz3", "ts1"], False),
            ({**offload, "worker": None}, [], False), ({**offload, "observation": "unknown"}, [], False),
            ({**offload, "observation": "cached"}, [], False), ({**offload, "recommendation": "local"}, [], False),
            ({**offload, "recommendation": "defer"}, [], False), ({**offload, "recommendation": None}, [], False),
            ({**offload, "recommendation": "queue", "reason": "all_workers_busy"}, ["hz3"], True),
            ({**offload, "recommendation": "queue", "reason": "capacity_sample_expired"}, [], False),
            ({**offload, "recommendation": "queue", "reason": None}, [], False),
            ({**offload, "recommendation": "queue", "observation": "unknown", "reason": "all_workers_busy"}, [], False),
            ({**offload, "reason": "all_workers_busy"}, ["hz3"], False),                 # busy is a queue answer, not an offload to a stranger
        ]
        for verdict, requested, expected in table:
            self.assertEqual(VERIFIER.verdict_admits(verdict, requested), expected, (verdict, requested))
        self.assertEqual(VERIFIER.requested_workers({"RCH_WORKERS": "trj, hz3,,", "RCH_WORKER": "ts1"}), ["trj", "hz3"])
        self.assertEqual(VERIFIER.requested_workers({"RCH_WORKER": "ts1,hz3"}), ["ts1", "hz3"])
        self.assertEqual(VERIFIER.requested_workers({}), [])
        self.assertEqual((VERIFIER.ADMISSION_TRIES, VERIFIER.ADMISSION_SPACING_S), (8, 15.0))
        for stdout, expected in [("garbage", ("unparsed", "rc=7", None, None)), ("[]", ("unparsed", "rc=7", None, None)),
                                 (json.dumps({"data": self.TIMED_OUT}),
                                  (None, "unknown", None, "selection_error=admission_preview_timed_out")),
                                 (json.dumps(self.BUSY), ("queue", "observed", "trj", "all_workers_busy"))]:
            verdict = VERIFIER.admission_verdict(stdout, 7)
            self.assertEqual((verdict["recommendation"], verdict["observation"], verdict["worker"], verdict["reason"]), expected, stdout)
            self.assertNotIn("host.invalid", json.dumps(verdict), "the host address is never read")

    # ---- review of the gate (YellowBrook): the receipt's attempt count is true, and free text from rch never reaches it ----

    def test_a_refusal_records_the_attempts_that_were_made(self):
        # rch could not be run on the first try: one attempt, not ADMISSION_TRIES.
        with patch.dict(os.environ, {"PATH": str(self.root / "nowhere")}), patch.object(VERIFIER, "ADMISSION_SPACING_S", 0.0), \
                contextlib.redirect_stderr(io.StringIO()):
            result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform"), build=True, real_rch=True)
        self.assertEqual(receipt["build_admission"]["mips"]["observation"], "rch_not_runnable:FileNotFoundError")
        self.assertEqual(receipt["build_admission"]["mips"]["attempts"], 1)
        # The control: a run refused after every one of its tries records all of them.
        result, receipt, _, _ = self.stub_run({"mips": [self.TIMED_OUT]}, label="tries", tries=3)
        self.assertEqual((result, receipt["build_admission"]["mips"]["attempts"]), (1, 3))

    def test_free_text_from_rch_is_recorded_only_when_it_is_identifier_shaped(self):
        for value, expected in [("all_workers_busy", "all_workers_busy"), ("ovh-a", "ovh-a"), ("trj", "trj"),
                                ({"selection_error": "admission_preview_timed_out"}, "selection_error=admission_preview_timed_out"),
                                ("ubuntu@host.invalid", "unrecognized"), ("worker ubuntu@host.invalid refused", "unrecognized"), ("ubuntu@trj", "unrecognized"),
                                ("all workers busy", "unrecognized"),
                                ("192.0.2.10", "unrecognized"), ("host.invalid", "unrecognized"), ("a/b", "unrecognized"),
                                ({"detail": "ubuntu@host.invalid"}, "unrecognized"), ("x" * 200, "unrecognized"),
                                (7, "7"), (True, "True"), ({}, None), (None, None), (["list"], None)]:
            self.assertEqual(VERIFIER._verdict_text(value), expected, value)
        # Through the whole run: a reason and a worker id that carry a host reach neither the receipt nor its error record.
        leaky = {"recommendation": None, "observation": "unknown", "selection": {"reason": "worker ubuntu@host.invalid refused the preview"}}
        result, receipt, _, _ = self.stub_run({"mips": [leaky]}, label="leakyreason", tries=2)
        self.assertEqual((result, receipt["error_type"]), (1, "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"]["reason"], "unrecognized")
        self.assertNotIn("host.invalid", json.dumps(receipt))
        odd = {"recommendation": "offload", "observation": "observed", "selection": {"worker": {"id": "ubuntu@host.invalid"}, "reason": "fastest"}}
        result, receipt, _, _ = self.stub_run({"mips": [odd], "powerpc": [odd]}, label="leakyworker", tries=2, workers="trj")
        self.assertEqual((result, receipt["error_type"]), (1, "AdmissionRefused"))      # an unrecognized id is never in the requested set
        self.assertNotIn("host.invalid", json.dumps(receipt))
        # The controls: the same shapes with benign words are recorded as they are.
        benign = {"recommendation": None, "observation": "unknown", "selection": {"reason": "preview_timed_out"}}
        result, receipt, _, _ = self.stub_run({"mips": [benign]}, label="benign", tries=2)
        self.assertEqual(receipt["build_admission"]["mips"]["reason"], "preview_timed_out")

    def test_the_exit_code_of_every_refresh_is_recorded_and_gates_nothing(self):
        # V30: the gate takes a fresh sample before each admit and used to discard how that call ended. The code of every try is now in the
        # receipt, one integer per try; it is only recorded. A refresh that fails or hangs does not stop the admit that follows.
        # (a) Refreshes that fail (7, 0, 3 in call order) and a stale first answer: both guests are still admitted and built, and the codes are
        # per guest and in order.
        plan = {"mips": [self.STALE, self.OFFLOAD], "powerpc": [self.OFFLOAD], "__refresh_rc__": [7, 0, 3]}
        result, receipt, events, stderr = self.stub_run(plan, label="rcs")
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertEqual(sum(1 for event in events if event["ev"] == "exec-begin"), 2)
        self.assertEqual([receipt["build_admission"][arch]["refresh_exit_codes"] for arch in ("mips", "ppc")], [[7, 0], [3]])
        self.assertEqual([receipt["build_admission"][arch]["attempts"] for arch in ("mips", "ppc")], [2, 1])
        # The refresh's stderr is kept on the runner's stderr and is not in the receipt.
        self.assertIn("stub capabilities stderr: worker ubuntu@host.invalid", stderr)
        self.assertNotIn("host.invalid", json.dumps(receipt))
        # (b) A refused guest records one code per try, in order, and builds nothing.
        result, receipt, events, _ = self.stub_run({"mips": [self.TIMED_OUT], "__refresh_rc__": [1, 2, 3]}, label="rcs-refused", tries=3)
        self.assertEqual((result, receipt["error_type"]), (1, "AdmissionRefused"))
        self.assertEqual(receipt["build_admission"]["mips"]["refresh_exit_codes"], [1, 2, 3])
        self.assertEqual(receipt["build_admission"]["mips"]["attempts"], 3)
        self.assertFalse([event for event in events if event["ev"].startswith("exec")])
        # (c) A refresh that outlives its timeout is killed and recorded as -1; the admit that follows still decides.
        hang = {"mips": [self.OFFLOAD], "powerpc": [self.OFFLOAD], "__refresh_sleep__": 20}
        result, receipt, _, stderr = self.stub_run(hang, label="rcs-hang", call_timeout=1.5)
        self.assertEqual((result, receipt["status"]), (0, "PASS"))
        self.assertEqual([receipt["build_admission"][arch]["refresh_exit_codes"] for arch in ("mips", "ppc")], [[-1], [-1]])
        self.assertIn("timed out", stderr)
        # (d) With no rch at all there is no refresh to record: an empty list, and the refusal still counts its one attempt.
        env = {"PATH": str(self.root / "nowhere")}
        with patch.dict(os.environ, env), patch.object(VERIFIER, "ADMISSION_SPACING_S", 0.0), contextlib.redirect_stderr(io.StringIO()):
            result, receipt = self.run_main(self.captures(), self.argv("--speaker-platform"), build=True, real_rch=True)
        self.assertEqual((receipt["build_admission"]["mips"]["refresh_exit_codes"], receipt["build_admission"]["mips"]["attempts"]), ([], 1))


# The stub `rch` of the admission tests: answers `workers capabilities`, `admit` and `exec` and logs each call as one JSON line.
# `admit` answers with the next verdict of plan[target] (the last repeats); `{"__raw__": text, "__rc__": n}` prints text and exits n.
RCH_STUB = r'''#!@PYTHON@
import json
import os
import sys
import time

directory, run = os.environ["RCH_STUB_DIR"], os.environ["RCH_STUB_RUN"]
args = sys.argv[1:]
after = args[args.index("--") + 1:] if "--" in args else []
target = next((a.split("-")[0] for a in after if a.endswith("-unknown-linux-musl")), None)


def log(event, **fields):
    with open(os.path.join(directory, f"events-{run}.log"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ev": event, "target": target, **fields}) + "\n")


where = {"cwd": os.getcwd(), "target_dir": os.environ.get("CARGO_TARGET_DIR"), "remote": os.environ.get("RCH_REQUIRE_REMOTE")}
if args[:2] == ["workers", "capabilities"]:
    log("capabilities", args=args)
    everything = json.load(open(os.path.join(directory, f"plan-{run}.json"), encoding="utf-8"))
    counter = os.path.join(directory, f"caps-{run}.txt")
    seen = int(open(counter).read()) if os.path.exists(counter) else 0
    open(counter, "w").write(str(seen + 1))
    if "__refresh_sleep__" in everything:
        time.sleep(everything["__refresh_sleep__"])
    codes = everything.get("__refresh_rc__", [0])
    code = codes[min(seen, len(codes) - 1)]
    if code:
        sys.stderr.write("stub capabilities stderr: worker ubuntu@host.invalid\n")
    print("{}")
    sys.exit(code)
elif args[:1] == ["admit"]:
    plan = json.load(open(os.path.join(directory, f"plan-{run}.json"), encoding="utf-8"))[target]
    counter = os.path.join(directory, f"count-{run}-{target}.txt")
    seen = int(open(counter).read()) if os.path.exists(counter) else 0
    open(counter, "w").write(str(seen + 1))
    log("admit", args=args[:3], argv=after, try_number=seen + 1, **where)
    verdict = plan[min(seen, len(plan) - 1)]
    sys.stderr.write("stub admit stderr: worker ubuntu@host.invalid\n")
    if "__sleep__" in verdict:
        time.sleep(verdict["__sleep__"])
    if "__raw__" in verdict:
        print(verdict["__raw__"])
        sys.exit(verdict["__rc__"])
    print(json.dumps({"api_version": "1.0", "command": "admit", "success": True, "data": verdict}))
elif args[:1] == ["exec"]:
    log("exec-begin", argv=after, **where)
    log("exec-end")
else:
    log("unexpected", args=args)
    sys.exit(9)
'''


# ---- the guest source, held to the grammar that judges it ----------------------------------------------------------


GUEST = REPO / "toolchain" / "src" / "ffw-hello-init"


class GuestSourceTests(unittest.TestCase):
    """The guest is Rust, built and run centrally. These read its source and hold it to the Python grammar that judges its
    output, so the two cannot drift apart unseen. They compile and run nothing: the Rust unit tests in `speaker_judge.rs` are
    central work, and no guest has run the step."""

    @classmethod
    def setUpClass(cls):
        cls.judge_rs = (GUEST / "src" / "speaker_judge.rs").read_text()
        cls.smoke_rs = (GUEST / "src" / "speaker_smoke.rs").read_text()
        cls.main_rs = (GUEST / "src" / "main.rs").read_text()
        cls.cargo = (GUEST / "Cargo.toml").read_text()

    def test_the_feature_implies_the_speaker_step_is_off_by_default_and_is_the_one_the_runner_builds(self):
        self.assertIn('speaker-platform = ["speaker-smoke"]', self.cargo)
        self.assertEqual(VERIFIER.PLATFORM_FEATURE, "speaker-platform")
        self.assertNotRegex(self.cargo, r"(?m)^default\s*=")

    def test_the_wrapper_lines_and_the_argument_are_the_ones_the_judge_expects(self):
        self.assertEqual(P.STEP_BEGIN_LINE, f"{P.STEP_BEGIN_KEY} path={P.STEP_PATH} argv={P.STEP_ARG}")
        self.assertIn(f'b"{P.STEP_BEGIN_KEY} path="', self.smoke_rs)
        self.assertIn(f'c"{P.STEP_ARG}"', self.smoke_rs)
        self.assertIn(f'c"{P.STEP_PATH}"', self.smoke_rs)
        self.assertIn(f'b"{P.STEP_EXIT_KEY} "', self.judge_rs)
        # The catalog step keeps its own names.
        self.assertIn('b"FFW_SPEAKER_EXIT "', self.judge_rs)
        self.assertIn(f'c"{E.SPEAKER_ARG}"', self.smoke_rs)
        self.assertNotEqual(P.STEP_EXIT_KEY, "FFW_SPEAKER_EXIT")

    def test_the_rust_unit_tests_assert_the_example_lines_the_python_grammar_classifies(self):
        pair = "stdout_bytes=17812 stdout_fnv1a64=0123456789abcdef"
        examples = {
            f"{P.STEP_EXIT_KEY} status=0 {pair}": "ran",
            f"{P.STEP_EXIT_KEY} status=3 {pair}": "ran",
            f"{P.STEP_EXIT_KEY} spawn=exec errno=2": "failed",
            f"{P.STEP_EXIT_KEY} signal=11 {pair}": "failed",
        }
        for line, kind in examples.items():
            self.assertIn(line, self.judge_rs, line)
            ran, failed = P.STEP_EXIT_OK.fullmatch(line), P.STEP_EXIT_FAILURE.fullmatch(line)
            self.assertEqual((ran is not None, failed is not None), (kind == "ran", kind == "failed"), line)

    def test_the_platform_step_accepts_exit_zero_and_three_in_rust_exactly_as_the_judge_does(self):
        self.assertEqual(P.STEP_RAN_STATUSES, (0, 3))
        self.assertIn("code: 0 | 3,", self.judge_rs)    # the exact or-pattern, rustfmt's trailing comma included
        # ...and the catalog step still accepts exit 0 only.
        self.assertIn("(Step::Catalog, Self::Exited { code: 0, output })", self.judge_rs)

    def test_main_runs_the_platform_step_after_the_catalog_step_and_only_under_its_feature(self):
        run_at = self.main_rs.index("speaker_smoke::run(console_fd)")
        platform_at = self.main_rs.index("speaker_smoke::run_platform(console_fd)")
        self.assertLess(run_at, platform_at)
        self.assertIn('#[cfg(feature = "speaker-platform")]', self.main_rs[run_at:platform_at])
        self.assertIn('#[cfg(feature = "speaker-platform")]\npub fn run_platform', self.smoke_rs)

    def test_the_provider_feature_implies_the_platform_step_and_is_the_one_the_runner_builds(self):
        self.assertIn('speaker-platform-legacy-test-env = ["speaker-platform"]', self.cargo)
        self.assertEqual(VERIFIER.PROVIDER_FEATURES, {PROV: "speaker-platform-legacy-test-env"})
        self.assertNotRegex(self.cargo, r"(?m)^default\s*=")

    def test_the_guest_passes_exactly_the_argument_the_judge_expects_and_only_under_the_feature(self):
        self.assertEqual(P.provider_arg(PROV), PROV_ARG)
        self.assertIn(f'Some(c"{PROV_ARG}")', self.smoke_rs)
        flat = " ".join(self.smoke_rs.split())          # rustfmt may break these lines; the tokens are what matter
        self.assertIn('#[cfg(all( feature = "speaker-platform", feature = "speaker-platform-legacy-test-env" ))] '
                      "const PLATFORM_EXTRA: Option<&CStr> = Some(", flat)
        self.assertIn('#[cfg(all( feature = "speaker-platform", not(feature = "speaker-platform-legacy-test-env") ))] '
                      "const PLATFORM_EXTRA: Option<&CStr> = None;", flat)
        # The catalog step and the default platform step run the child exactly as before: no extra argument.
        self.assertIn("spawn_and_collect(console_fd, ARG_CATALOG, None)", self.smoke_rs)
        self.assertIn("spawn_and_collect(console_fd, ARG_PLATFORM, PLATFORM_EXTRA)", self.smoke_rs)
        # The BEGIN line reports the extra argument after the first one, space separated, as `platform_expect.step_begin_line` does.
        self.assertRegex(self.smoke_rs, r"begin\.push\(ARG_PLATFORM\.to_bytes\(\)\);\n    if let Some\(extra\) = PLATFORM_EXTRA \{\n"
                                       r"        begin\.push\(b\" \"\);\n        begin\.push\(extra\.to_bytes\(\)\);")
        self.assertEqual(P.step_begin_line(PROV), f"{P.STEP_BEGIN_KEY} path={P.STEP_PATH} argv={P.STEP_ARG} {PROV_ARG}")

    def test_the_execve_argv_has_room_for_the_extra_argument_and_still_ends_at_the_first_null(self):
        self.assertIn("fn sys_execve(argv: &[usize; 4], envp: &[usize; 1]) -> isize", self.smoke_rs)
        self.assertIn("let extra_ptr = extra.map_or(0usize, |extra| extra.as_ptr() as usize);", self.smoke_rs)
        flat = " ".join(self.smoke_rs.split())
        self.assertIn("let argv = [ PATH.as_ptr() as usize, arg.as_ptr() as usize, extra_ptr, 0usize, ];", flat)


# ---- the explicit legacy provider ----------------------------------------------------------------------------------
#
# `docs/contracts/p02.md` ("The legacy provider"): `--platform-startup --entropy-provider legacy-dev-random-test-environment` prints
# `provider=` on the ENTROPY line alone. The examples are the speaker's own (`p02_legacy_entropy_markers.json`); every expectation below
# is written out by hand from the contract and the policy in `platform_expect.py`'s docstring, never read back from the judge.

PROV = "legacy_dev_random_test_environment"
PROV_ARG = "--entropy-provider=legacy-dev-random-test-environment"
LEGACY_FILE = REPO / "crates" / "franken-speaker" / "tests" / "vectors" / "p02_legacy_entropy_markers.json"
LEGACY_DOC = json.loads(LEGACY_FILE.read_text(encoding="utf-8"))
LEGACY = LEGACY_DOC["examples"]
PROVIDER_PLATFORM = {"grammar": GRAMMAR, "provider": PROV}
PROV_ENTROPY_NOT_SEEDED = f"FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel provider={PROV} reason=not_seeded"


def legacy(name):
    return list(LEGACY[name]["lines"])


def pjudge(lines, arch, provider=PROV):
    return P.judge_output(as_bytes(lines) if isinstance(lines, list) else lines, arch, GRAMMAR, provider=provider)


def ppc_not_seeded_provider_lines():
    lines = replaced(legacy("legacy_test_environment_all_pass_powerpc"), 3, PROV_ENTROPY_NOT_SEEDED)
    return replaced(lines, 5, "FFW_PLATFORM:END started=0 refused=entropy:not_seeded")


def mips_provider_green_lines():
    """The six lines the MIPS guest of run 2a405e88 printed for the provider step (a blocking `/dev/random` read that returned): the committed MIPS vector
    with the ENTROPY line the vectors file shows for a pass and `END started=1`. `MipsProviderGreenIsTheRetainedTranscript` ties it to the serial log."""
    lines = replaced(legacy("legacy_test_environment_not_seeded_mips"), 3, legacy("legacy_test_environment_all_pass_powerpc")[3])
    return replaced(lines, 5, "FFW_PLATFORM:END started=1")


# The provider baselines: (guest, lines, the guest's exit status). The first of each kind must itself pass. MIPS has no degraded baseline: its 4.19.249
# kernel blocks the read until the pool is ready and then returns bytes, so it cannot refuse `not_seeded` (p02.md, "The harness kernels do not answer alike").
PROVIDER_BASELINES = {
    "ppc green": ("ppc", legacy("legacy_test_environment_all_pass_powerpc"), 0),
    "mips green": ("mips", mips_provider_green_lines(), 0),
    "ppc degraded": ("ppc", ppc_not_seeded_provider_lines(), 3),
}
MIPS_NOT_SEEDED_RED = ["platform_not_started:entropy:not_seeded", "platform_unreachable_refusal:entropy:not_seeded"]


def provider_block(lines, status, provider=PROV):
    """The console view of a provider run's platform step: the BEGIN line names both arguments."""
    return platform_block(lines, status).replace(P.STEP_BEGIN_LINE, P.step_begin_line(provider), 1)


def provider_text(arch, lines, status):
    return transcript(provider_block(lines, status), arch)


def pverify(text, arch):
    return verify(text, arch, platform=PROVIDER_PLATFORM)


# What the contract and the policy give each legacy example, for the run that selected the test-environment provider.
PROVIDER_EXPECTED = {
    ("legacy_test_environment_all_pass_powerpc", "ppc"): ("green", []),
    ("legacy_test_environment_not_seeded_mips", "mips"): ("red", ["platform_not_started:entropy:not_seeded", "platform_unreachable_refusal:entropy:not_seeded"]),
    ("legacy_evidence_qualified_unavailable_powerpc", "ppc"): ("red", ["platform_value:ENTROPY:provider=legacy_dev_random"]),
    ("legacy_device_absent_mips", "mips"): ("red", ["platform_not_started:entropy:absent"]),
    ("legacy_selected_with_a_simulated_backend_refused", "ppc"): ("red", ["platform_backend_simulated"]),
}


class LegacyProviderJudgeTests(unittest.TestCase):
    def test_every_legacy_example_has_an_expectation_and_the_table_names_no_other(self):
        self.assertEqual({name for name, _ in PROVIDER_EXPECTED}, set(LEGACY))
        self.assertEqual(LEGACY_DOC["provider_values"], ["legacy_dev_random", PROV])

    def test_each_legacy_example_gets_the_verdict_the_contract_gives_it_and_names_its_provider(self):
        for (name, arch), (verdict, problems) in PROVIDER_EXPECTED.items():
            record = pjudge(legacy(name), arch)
            self.assertEqual((record["verdict"], record["problems"]), (verdict, problems), name)
            self.assertEqual(record["provider"], PROV, name)
            self.assertIn("test environment", record["claim"], name)

    def test_the_degraded_cell_for_a_provider_run_is_not_seeded_on_powerpc_and_nothing_else(self):
        # PowerPC only: its 4.9 kernel answers a nonblocking /dev/random read with EAGAIN while the pool is empty. No positive is shown.
        record = pjudge(PROVIDER_BASELINES["ppc degraded"][1], "ppc")
        self.assertEqual((record["verdict"], record["problems"], record["started"]), ("degraded", [], False))
        self.assertEqual(record["degraded_because"], "entropy:not_seeded")
        # MIPS cannot give that refusal (its 4.19.249 kernel blocks the read, then returns bytes): the same transcript is red, with both problems named.
        record = pjudge(legacy("legacy_test_environment_not_seeded_mips"), "mips")
        self.assertEqual((record["verdict"], record["problems"], record["started"]), ("red", MIPS_NOT_SEEDED_RED, False))
        self.assertNotIn("degraded_because", record)
        # The control: the same shape without a provider is still red on PowerPC under the default judge (E03 seeded its pool).
        plain = replaced(replaced(lines_of("powerpc_all_pass"), 3, "FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded"),
                         5, "FFW_PLATFORM:END started=0 refused=entropy:not_seeded")
        self.assertEqual(judge(plain, "ppc")["problems"], ["platform_not_started:entropy:not_seeded"])
        # Every other reason is red on both guests, with the reason named.
        for arch, healthy in (("mips", legacy("legacy_test_environment_not_seeded_mips")), ("ppc", legacy("legacy_test_environment_all_pass_powerpc"))):
            for reason in ("absent", "unavailable", "failed", "no_progress", "invalid", "malformed", "zero_length", "interrupted",
                           "degenerate", "over_long"):
                lines = replaced(replaced(healthy, 3, f"FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel provider={PROV} reason={reason}"),
                                 5, f"FFW_PLATFORM:END started=0 refused=entropy:{reason}")
                record = pjudge(lines, arch)
                self.assertEqual((record["verdict"], record["problems"]), ("red", [f"platform_not_started:entropy:{reason}"]), (arch, reason))
        # A second refusal beside the degraded one is not degraded.
        two = replaced(replaced(PROVIDER_BASELINES["ppc degraded"][1], 2, "FFW_PLATFORM:CLOCK status=REFUSED provenance=kernel reason=absent"),
                       5, "FFW_PLATFORM:END started=0 refused=clock:absent")
        self.assertEqual(pjudge(two, "ppc")["problems"], ["platform_not_started:clock:absent", "platform_not_started:entropy:not_seeded"])

    def test_the_default_judge_rejects_the_token_and_a_provider_run_rejects_its_absence(self):
        fields = {"PASS": "status,provenance,provider", "REFUSED": "status,provenance,provider,reason", "NOT_RUN": "status,provenance,provider"}
        for name, example in LEGACY.items():
            arch = "mips" if "mips" in name else "ppc"
            status = next(l for l in example["lines"] if l.startswith("FFW_PLATFORM:ENTROPY ")).split("status=")[1].split(" ")[0]
            self.assertEqual(judge(example["lines"], arch)["problems"], [f"platform_fields:ENTROPY:{fields[status]}"], name)
        for name in EXAMPLES:
            arch = "mips" if "mips" in name else "ppc"
            record = pjudge(lines_of(name), arch)
            self.assertEqual((record["verdict"], record["problems"]), ("red", ["platform_provider_missing:ENTROPY"]), name)
        # The controls: the same two judgments of the right kind of example are accepted.
        self.assertEqual(judge(lines_of("powerpc_all_pass"), "ppc")["verdict"], "green")
        self.assertEqual(pjudge(legacy("legacy_test_environment_all_pass_powerpc"), "ppc")["verdict"], "green")

    def test_a_faulty_provider_token_is_named_against_a_green_baseline(self):
        healthy = legacy("legacy_test_environment_all_pass_powerpc")
        self.assertEqual((pjudge(healthy, "ppc")["verdict"], pjudge(healthy, "ppc")["problems"]), ("green", []))
        refused = PROVIDER_BASELINES["ppc degraded"][1]
        plants = {
            "empty value": (replaced(healthy, 3, healthy[3].replace(f"provider={PROV}", "provider=")), ["platform_malformed:ENTROPY"]),
            "the other provider": (replaced(healthy, 3, healthy[3].replace(PROV, "legacy_dev_random")),
                                   ["platform_value:ENTROPY:provider=legacy_dev_random"]),
            "an unknown provider": (replaced(healthy, 3, healthy[3].replace(PROV, "urandom")), ["platform_value:ENTROPY:provider=urandom"]),
            "an uppercase value": (replaced(healthy, 3, healthy[3].replace(PROV, PROV.upper())),
                                   [f"platform_value:ENTROPY:provider={PROV.upper()}"]),
            "the token before provenance": (replaced(healthy, 3, f"FFW_PLATFORM:ENTROPY status=PASS provider={PROV} provenance=kernel"),
                                            ["platform_fields:ENTROPY:status,provider,provenance"]),
            "the token after the reason": (replaced(refused, 3, f"FFW_PLATFORM:ENTROPY status=REFUSED provenance=kernel reason=not_seeded provider={PROV}"),
                                           ["platform_fields:ENTROPY:status,provenance,reason,provider"]),
            "the token twice": (replaced(healthy, 3, healthy[3] + f" provider={PROV}"),
                                ["platform_fields:ENTROPY:status,provenance,provider,provider"]),
            "the token on CLOCK": (replaced(healthy, 2, healthy[2] + f" provider={PROV}"),
                                   ["platform_fields:CLOCK:status,provenance,provider"]),
            "the token on WAKE": (replaced(healthy, 4, healthy[4].replace(" mechanism", f" provider={PROV} mechanism")),
                                  ["platform_fields:WAKE:status,provenance,provider,mechanism"]),
            "the token on END": (replaced(healthy, 5, healthy[5] + f" provider={PROV}"), ["platform_fields:END:started,provider"]),
            "the token dropped": (replaced(healthy, 3, healthy[3].replace(f" provider={PROV}", "")), ["platform_provider_missing:ENTROPY"]),
            "simulated provenance": (replaced(healthy, 3, healthy[3].replace("provenance=kernel", "provenance=simulated")),
                                     ["platform_simulated:ENTROPY"]),
        }
        for label, (lines, problems) in plants.items():
            record = pjudge(lines, "ppc")
            self.assertEqual((record["verdict"], record["problems"]), ("red", problems), label)

    def test_the_texts_do_not_say_that_no_read_was_ever_observed(self):
        # BrightLion's one-shot (6575) read /dev/random on PowerPC and got not_seeded, and run 2a405e88's MIPS guest read bytes after its blocking read
        # returned: the true statement is that no SEEDED NONBLOCKING read exists.
        for label, path in (("platform_expect.py", Path(P.__file__)), ("SPEAKER_SMOKE.md", REPO / "toolchain" / "SPEAKER_SMOKE.md")):
            text = " ".join(path.read_text(encoding="utf-8").replace("# ", " ").split())
            self.assertNotRegex(text, r"(?i)\bno `/dev/random` read has been observed", label)
            self.assertNotRegex(text, r"(?i)\bno seeded `/dev/random` read has been observed", label)       # the MIPS start of run 2a405e88 did read bytes
            self.assertRegex(text, r"(?i)\bno seeded nonblocking `/dev/random` read has been observed in any guest", label)

    def test_a_provider_the_judge_does_not_know_raises_like_an_unknown_guest(self):
        for provider in ("legacy_dev_random", "urandom", "", "LEGACY_DEV_RANDOM_TEST_ENVIRONMENT"):
            with self.assertRaises(ValueError, msg=provider):
                pjudge(legacy("legacy_test_environment_all_pass_powerpc"), "ppc", provider=provider)
            with self.assertRaises(ValueError, msg=provider):
                P.step_begin_line(provider)
        with self.assertRaises(ValueError):
            P.plants_for("legacy_dev_random")

    def test_the_default_judge_and_its_constants_are_what_they_were(self):
        self.assertEqual(P.STEP_BEGIN_LINE, "FFW_PLATFORM_STEP_BEGIN path=/franken-speaker argv=--platform-startup")
        self.assertEqual(P.step_argv(), ["--platform-startup"])
        self.assertEqual(P.step_begin_line(), P.STEP_BEGIN_LINE)
        self.assertEqual(P.plants_for(), P.PLANTS)
        self.assertEqual(sorted(P.plants_for(PROV)),
                         sorted(["provenance_double", "provenance_simulated", "backend_simulated", "missing_capability", "truncated",
                                 "provider_missing", "provider_other", "provider_unknown"]))
        self.assertEqual(P.DEGRADED, frozenset({("mips", "entropy", "not_seeded")}))
        default, provider = judge(lines_of("powerpc_all_pass"), "ppc"), pjudge(legacy("legacy_test_environment_all_pass_powerpc"), "ppc")
        self.assertEqual(set(provider) - set(default), {"provider", "claim"})
        self.assertEqual(set(default) - set(provider), set())
        self.assertEqual(P.plant_spec("truncated"), P.PLANTS["truncated"])
        self.assertEqual(P.plant_spec("provider_missing"), P.PROVIDER_PLANTS["provider_missing"])
        with self.assertRaises(KeyError):
            P.plant_spec("nonexistent")


class LegacyProviderCrossJudgeTests(unittest.TestCase):
    """The reference judge in tests/p02 (YellowBrook's) already holds the legacy lines to the speaker's grammar. This judge and that
    one must agree on every plant YellowBrook's test applies to a healthy legacy output: it reports a fault exactly when this one
    says red. The unplanted output is the control: both accept it."""

    @classmethod
    def setUpClass(cls):
        cls.ref = load_reference_judge()
        cls.reasons = GRAMMAR["reasons"]
        cls.healthy = legacy("legacy_test_environment_all_pass_powerpc")

    def test_both_accept_the_healthy_output_and_every_legacy_example_is_well_formed_to_the_reference(self):
        self.assertEqual(self.ref.judge(list(self.healthy), self.reasons), [])
        self.assertEqual(pjudge(self.healthy, "ppc")["verdict"], "green")
        for name in LEGACY:
            self.assertEqual(self.ref.judge(legacy(name), self.reasons), [], name)

    def test_they_agree_on_every_plant_of_the_reference_suite(self):
        h = self.healthy
        plants = {
            "an unknown provider value": replaced(h, 3, h[3].replace(PROV, "urandom")),
            "an empty provider value": replaced(h, 3, h[3].replace(f"provider={PROV}", "provider=")),
            "an uppercase provider value": replaced(h, 3, h[3].replace(PROV, "LEGACY_DEV_RANDOM")),
            "the token on the CLOCK line": replaced(h, 2, h[2] + " provider=legacy_dev_random"),
            "the token on the WAKE line": replaced(h, 4, h[4].replace(" mechanism=eventfd", " provider=legacy_dev_random mechanism=eventfd")),
            "the token twice": replaced(h, 3, h[3] + " provider=legacy_dev_random"),
            "the token before the provenance": replaced(h, 3, "FFW_PLATFORM:ENTROPY status=PASS provider=legacy_dev_random provenance=kernel"),
            "a simulated provenance on a legacy PASS": replaced(h, 3, h[3].replace("provenance=kernel", "provenance=simulated")),
        }
        for label, lines in plants.items():
            self.assertNotEqual(self.ref.judge(lines, self.reasons), [], label)
            self.assertEqual(pjudge(lines, "ppc")["verdict"], "red", label)


class LegacyProviderVerifierTests(unittest.TestCase):
    def test_the_provider_baselines_pass_and_record_their_verdicts_provider_and_argv(self):
        for label, (arch, lines, status) in PROVIDER_BASELINES.items():
            result = pverify(provider_text(arch, lines, status), arch)
            self.assertEqual((result["status"], result["validation_errors"], result["missing_markers"]), ("PASS", [], []), label)
            platform = result["platform"]
            self.assertEqual(platform["verdict"], "green" if status == 0 else "degraded", label)
            self.assertEqual((platform["provider"], platform["argv"]), (PROV, ["/franken-speaker", "--platform-startup", PROV_ARG]), label)
            self.assertEqual(platform["console_region"], platform["reported"], label)

    def test_a_default_guest_is_not_a_provider_guest_and_the_reverse(self):
        # The default guest, judged as a provider run: the BEGIN line and the child's ENTROPY line both say it is the wrong step.
        result = pverify(good_text("ppc"), "ppc")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["validation_errors"], [f"invalid:{P.STEP_BEGIN_KEY}", "platform_provider_missing:ENTROPY"])
        # The provider guest, judged as a default run.
        result = verify(provider_text("ppc", *PROVIDER_BASELINES["ppc green"][1:]), "ppc")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["validation_errors"][0], f"invalid:{P.STEP_BEGIN_KEY}")
        self.assertIn("platform_fields:ENTROPY:status,provenance,provider", result["validation_errors"])
        # The controls: each is accepted by its own kind of run.
        self.assertEqual(verify(good_text("ppc"), "ppc")["status"], "PASS")
        self.assertEqual(pverify(provider_text("ppc", *PROVIDER_BASELINES["ppc green"][1:]), "ppc")["status"], "PASS")

    def test_every_provider_plant_fails_for_its_own_reason_and_no_other_against_each_baseline(self):
        for label, (arch, lines, status) in PROVIDER_BASELINES.items():
            text = provider_text(arch, lines, status)
            self.assertEqual(pverify(text, arch)["status"], "PASS", label)
            for plant, spec in P.plants_for(PROV).items():
                planted = P.plant_transcript(text, plant)
                self.assertNotEqual(planted, text, (label, plant))
                result = pverify(planted, arch)
                self.assertEqual((result["status"], result["validation_errors"]), ("FAIL", spec["expected"]), (label, plant))
                self.assertTrue(VERIFIER.judge_platform_control(result, plant)["caught"], (label, plant))
                platform = result["platform"]
                self.assertEqual(platform["console_region"], platform["reported"], (label, plant))     # resealed

    def test_run_platform_controls_catches_every_plant_of_a_provider_run_and_a_blind_judge_is_not_credited(self):
        cfg = {"hello": base.HELLO, "enosys": base.ENOSYS, "triple": base.MIPS_TRIPLE}
        text = provider_text("mips", *PROVIDER_BASELINES["mips green"][1:])
        controls = VERIFIER.run_platform_controls(text, "mips", cfg, SPEAKER, PROVIDER_PLATFORM)
        self.assertEqual(sorted(controls), sorted(P.plants_for(PROV)))
        for name, record in controls.items():
            self.assertTrue(record["caught"], (name, record))
            self.assertEqual(record["observed"], record["expected"])
        blind = {"verdict": "green", "problems": [], "lines": [], "outcomes": {}, "started": False, "kernel_release": None,
                 "provider": PROV, "claim": P.PROVIDER_CLAIM}
        with patch.object(P, "judge_output", return_value=blind):
            for plant in P.plants_for(PROV):
                result = pverify(P.plant_transcript(text, plant), "mips")
                self.assertFalse(VERIFIER.judge_platform_control(result, plant)["caught"], plant)

    def test_the_provider_plants_need_a_provider_token_to_plant_in(self):
        for plant in ("provider_missing", "provider_other", "provider_unknown"):
            with self.assertRaises(ValueError, msg=plant):
                P.plant_transcript(good_text("ppc"), plant)                    # a default transcript has no provider= to change


RUN_2A405E88 = REPO / "toolchain" / "results" / "runs" / "2a405e88bb10497b98b85abeae7dffaf"


class LegacyProviderKernelSemanticsTests(unittest.TestCase):
    """The harness kernels do not answer a `/dev/random` read alike (docs/contracts/p02.md, "The harness kernels do not answer alike"): the PowerPC 4.9.88
    kernel answers `EAGAIN` while its blocking pool is empty, the MIPS 4.19.249 kernel ignores `O_NONBLOCK` and blocks the read until the pool is ready,
    then returns bytes. The judge classifies each accordingly; a kernel-source reading, not a measurement of the read."""

    # What the judge held before this fix: MIPS "refuses not_seeded", degraded like PowerPC.
    OLD_CELLS = frozenset({("mips", "entropy", "not_seeded"), ("ppc", "entropy", "not_seeded")})

    def honest_classification(self):
        """Every part of the honest classification; raises AssertionError when any is false."""
        green = pjudge(mips_provider_green_lines(), "mips")
        self.assertEqual((green["verdict"], green["problems"], green["started"]), ("green", [], True))
        self.assertIn("blocks until the pool is ready and then returns bytes", green["claim"])
        self.assertIn("not an observation of nonblocking semantics", green["claim"])
        refused = pjudge(legacy("legacy_test_environment_not_seeded_mips"), "mips")
        self.assertEqual((refused["verdict"], refused["problems"], refused["started"]), ("red", MIPS_NOT_SEEDED_RED, False))
        self.assertNotIn("degraded_because", refused)
        ppc = pjudge(PROVIDER_BASELINES["ppc degraded"][1], "ppc")
        self.assertEqual((ppc["verdict"], ppc["problems"], ppc["degraded_because"]), ("degraded", [], "entropy:not_seeded"))
        self.assertIn("EAGAIN", ppc["claim"])
        self.assertNotIn("blocks until", ppc["claim"])
        self.assertEqual(P.DEGRADED_PROVIDER, frozenset({("ppc", "entropy", "not_seeded")}))
        self.assertEqual(P.UNREACHABLE_PROVIDER_REFUSAL, frozenset({("mips", "entropy", "not_seeded")}))

    def test_the_honest_classification_holds(self):
        self.honest_classification()

    def test_the_old_expectation_that_mips_refuses_not_seeded_is_refuted(self):
        refused = pjudge(legacy("legacy_test_environment_not_seeded_mips"), "mips")
        with self.assertRaises(AssertionError):
            self.assertEqual(refused["verdict"], "degraded")               # the old expectation, stated directly, fails
        self.assertEqual(refused["verdict"], "red")

    def test_each_old_expectation_planted_back_fails_the_honest_test_and_removing_the_plant_restores_it(self):
        self.honest_classification()                                         # the control: the unplanted judge passes
        plants = {
            "MIPS not_seeded degraded again": patch.object(P, "DEGRADED_PROVIDER", self.OLD_CELLS),
            "the unreachable cell dropped": patch.object(P, "UNREACHABLE_PROVIDER_REFUSAL", frozenset()),
            "the MIPS claim says the old thing": patch.dict(P.PROVIDER_READ, {"mips": "this guest's kernel answers a nonblocking /dev/random read with "
                                                                                  "EAGAIN while its pool is empty"}),
            "the PowerPC claim says it blocks": patch.dict(P.PROVIDER_READ, {"ppc": "this guest's kernel blocks until the pool is ready"}),
        }
        for label, plant in plants.items():
            with plant:
                with self.assertRaises(AssertionError, msg=label):
                    self.honest_classification()
            self.honest_classification()                                     # and with the plant removed it is green again
        # With the old cells planted, the OLD expectation passes, which is exactly why the honest test must fail.
        with patch.object(P, "DEGRADED_PROVIDER", self.OLD_CELLS):
            self.assertEqual(pjudge(legacy("legacy_test_environment_not_seeded_mips"), "mips")["verdict"], "degraded")

    def test_the_default_run_is_untouched(self):
        self.assertEqual(P.DEGRADED, frozenset({("mips", "entropy", "not_seeded")}))
        self.assertEqual(judge(lines_of("mips_entropy_not_seeded"), "mips")["verdict"], "degraded")

    REVISIT = ("Revisit this cell if the MIPS harness kernel image (`kernel_sha256` `3803357e`) is replaced, or if a provider-side wait bound is added")
    # (document, phrase, exactly once): every phrase the texts must carry. `exactly once` means a second copy elsewhere could not keep the pin green
    # after the sentence it guards is deleted.
    TEXT_NEEDLES = (
        ("contract", "The harness kernels do not answer alike", False), ("contract", "random_read_iter", False), ("contract", "wait_for_random_bytes", False),
        ("contract", "it has no deadline", False), ("contract", "blocks until the pool is ready and then returns bytes", False),
        ("contract", "platform_unreachable_refusal:entropy:not_seeded", False), ("contract", "no wait bound", False), ("contract", "_random_read", False),
        ("contract", "red on the MIPS guest", False),
        ("smoke", "blocks until the pool is ready and then returns", False), ("smoke", "platform_unreachable_refusal:entropy:not_seeded", False),
        ("smoke", "no wait bound", False), ("smoke", "not established", False), ("smoke", "timed_out", False),
        # review of v1 (YellowLantern F1/F2/F3/F4): the statements that no test pinned
        ("contract", "a reading of kernel source and of the booted image, not a measurement of the read", True),
        ("contract", "and do not agree with this one", True), ("smoke", "and they do not agree with the retained one", True),
        ("contract", "every committed MIPS boot capture that carries the `GETRANDOM` probe", True),
        ("contract", "Six other committed MIPS runs carry the earlier seven-probe set", True),
        # review of v1a (CrimsonMouse 16264): the count is over the committed tree, and a "capture" is a serial log or a stdout capture
        ("contract", "`22637af0` keeps no serial log", True), ("contract", "so a \"capture\" here means either file", True),
        ("contract", "is not committed and is not counted", True), ("contract", "Which MIPS runs committed at `bc32b0a` carry that line", False),
        # review of v1b (CrimsonMouse 16294): the totals are scoped to a revision, and the check is soundness only
        ("contract", "Of the MIPS runs committed at `bc32b0a`, twelve in all", True), ("contract", "it does not require this list to stay complete", True),
        ("contract", "a MIPS run committed after `bc32b0a` is not counted here", True),
        ("contract", REVISIT, True), ("smoke", REVISIT, True), ("judge", REVISIT, True),
        ("contract", "One hypothesis, not a finding and not measured", True), ("smoke", "One hypothesis, not a finding and not measured", True),
    )
    TEXT_STALE = ("`not_seeded` is `degraded` on both guests", "degraded on both guests", "degraded on both guests:", "is not stable from run to run",
                  "credits by itself (the 4.19 MIPS guest", "every committed MIPS run prints",
                  # v1a's wording, which counted working-tree files (an ignored log, and a missed stdout-capture run) instead of the committed tree
                  "every committed MIPS boot log that carries", "the other seven MIPS logs that reach userspace", "runs `1412ac47`, `570cd370`, `2a405e88` and `f0a91e7b`",
                  # v1b's wording: an unscoped total, and a check that required the list to be complete
                  "There are twelve committed MIPS runs", "re-derives every number and id below from the tracked files", "Which committed MIPS runs carry that line")

    @staticmethod
    def pinned_texts():
        def flat(text):
            return " ".join(text.replace("**", "").replace("# ", " ").split())
        return {"contract": flat((REPO / "docs" / "contracts" / "p02.md").read_text(encoding="utf-8")),
                "smoke": flat((REPO / "toolchain" / "SPEAKER_SMOKE.md").read_text(encoding="utf-8")),
                "judge": flat(Path(P.__file__).read_text(encoding="utf-8"))}

    def check_texts(self, texts):
        """Every needle present (once, where it says so) and no stale phrase anywhere; raises AssertionError otherwise."""
        for doc, needle, once in self.TEXT_NEEDLES:
            self.assertIn(needle, texts[doc], (doc, needle))
            if once:
                self.assertEqual(texts[doc].count(needle), 1, (doc, needle))
        for stale in self.TEXT_STALE:
            for doc, text in texts.items():
                self.assertNotIn(stale, text, (doc, stale))

    def test_the_texts_say_what_the_kernels_do_and_that_no_wait_bound_exists(self):
        self.check_texts(self.pinned_texts())

    def test_each_pinned_phrase_is_needed_deleting_it_fails_and_restoring_it_passes(self):
        texts = self.pinned_texts()
        self.check_texts(texts)                                              # the control: the real texts pass
        for doc, needle, once in self.TEXT_NEEDLES:
            deleted = dict(texts, **{doc: texts[doc].replace(needle, "")})   # the plant: the phrase is gone from that document
            with self.assertRaises(AssertionError, msg=(doc, needle)):
                self.check_texts(deleted)
            self.check_texts(dict(deleted, **{doc: texts[doc]}))             # and with the plant removed it passes again
            if once:                                                         # a second copy elsewhere in the same document must fail too
                doubled = dict(texts, **{doc: texts[doc] + " " + needle})
                with self.assertRaises(AssertionError, msg=("twice", doc, needle)):
                    self.check_texts(doubled)
        for stale in self.TEXT_STALE:                                        # the old wording planted back into each document
            for doc in texts:
                with self.assertRaises(AssertionError, msg=(doc, stale)):
                    self.check_texts(dict(texts, **{doc: texts[doc] + " " + stale}))

    NUMBER_WORDS = ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen",
                    "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty")

    @staticmethod
    def short_id(run):
        dated = re.match(r"\d{8}-\d{4}", run)
        return dated[0] if dated else run[:8]

    @staticmethod
    def tracked_mips_captures(runs_root=None):
        """{run directory: [capture file names]}: the MIPS boot captures (serial log, stdout capture, control-boot stdout captures) git TRACKS under
        toolchain/results/runs. `git ls-files` decides, so an ignored local log is never counted; a tree without .git (an export) is all tracked files.
        `runs_root` names a COPY of the runs directory (a test's own tree): every file in it counts and git is not asked."""
        root = REPO / "toolchain" / "results" / "runs"
        if runs_root is not None:
            listed = [f"toolchain/results/runs/{path.relative_to(runs_root)}" for path in Path(runs_root).rglob("*") if path.is_file()]
        else:
            try:
                listed = subprocess.run(["git", "ls-files", "-z", "--", "toolchain/results/runs"], cwd=REPO, capture_output=True, timeout=30, check=True
                                        ).stdout.decode("utf-8").split("\0")
            except (OSError, subprocess.SubprocessError):
                listed = [str(path.relative_to(REPO)) for path in root.rglob("*") if path.is_file()]
        captures = {}
        for rel in listed:
            parts = rel.split("/")
            if len(parts) == 5 and re.fullmatch(r"boot-mips-(?:serial\.log|stdout\.bin|control-[a-z_]+-stdout\.bin)", parts[-1]):
                captures.setdefault(parts[3], []).append(parts[-1])
        return {run: sorted(names) for run, names in sorted(captures.items())}

    @staticmethod
    def read_tracked_capture(run, name):
        return (REPO / "toolchain" / "results" / "runs" / run / name).read_bytes().decode("utf-8", errors="replace")

    def classify_mips_runs(self, captures, read=None):
        """{short id: {"kind": "with_probe" | "seven" | "none", "serial": bool}} for the given MIPS runs: whether their captures carry the GETRANDOM probe
        (the 25-probe set), only the earlier seven-probe set, or no probe at all. `read(run, name)` returns a capture's text (the tracked file by default).
        The quantified claim is checked here, on EVERY capture it is given: a capture that carries the probe prints exactly `status=UNSEEDED rc=-11`."""
        read = read or self.read_tracked_capture
        out = {}
        for run, names in captures.items():
            kinds = set()
            for name in names:
                text = read(run, name)
                if "FFW_PROBE:GETRANDOM" in text:
                    self.assertEqual(re.findall(r"FFW_PROBE:GETRANDOM[^\r\n]*", text), ["FFW_PROBE:GETRANDOM status=UNSEEDED rc=-11"], (run, name))
                    kinds.add("with_probe")
                else:
                    kinds.add("seven" if "FFW_PROBE:" in text else "none")
            self.assertEqual(len(kinds), 1, f"the captures of run {run} disagree ({sorted(kinds)}): the paragraph needs its own sentence for it")
            out[self.short_id(run)] = {"kind": kinds.pop(), "serial": "boot-mips-serial.log" in names}
        return out

    def listed_mips_runs(self, contract):
        """The ids and the number words the contract paragraph states, parsed from its exact phrases (which the needles pin)."""
        text = contract.lower()

        def found(pattern):
            match = re.search(pattern, text)
            self.assertIsNotNone(match, pattern)
            return match

        def ids(group):
            return re.findall(r"`([^`]+)`", group)

        def number(word):
            self.assertIn(word, self.NUMBER_WORDS, word)
            return self.NUMBER_WORDS.index(word)

        probe = found(r"committed at `bc32b0a`, (\w+) in all, (\w+) carry the `getrandom` probe: ([^;]*);")
        seven = found(r"(\w+) other committed mips runs carry the earlier seven-probe set, which has no such line: ([^.]*)\.")
        none = found(r"(`[^`]+`) never reaches userspace")
        serial = found(r"only (\w+) of the (\w+) keep a `boot-mips-serial\.log` \(([^)]*)\)")
        return {"stated": {"total": number(probe[1]), "probe": number(probe[2]), "seven": number(seven[1]), "serial": number(serial[1]), "serial_of": number(serial[2])},
                "with_probe": ids(probe[3]), "seven": ids(seven[2]), "none": ids(none[1]), "serial": ids(serial[3])}

    def check_listed(self, contract, classified):
        """Soundness only: every run the paragraph lists is classified as it says, and the paragraph's own arithmetic holds. It does not ask that the
        paragraph list every run, so a MIPS run committed later cannot fail it."""
        listed = self.listed_mips_runs(contract)
        for category in ("with_probe", "seven", "none"):
            for run in listed[category]:
                self.assertIn(run, classified, f"{run} is listed but is not a tracked MIPS run")
                self.assertEqual(classified[run]["kind"], category, run)
        for run in listed["serial"]:
            self.assertIn(run, classified, f"{run} is listed but is not a tracked MIPS run")
            self.assertTrue(classified[run]["serial"], f"{run} is listed as keeping a serial log and does not")
        stated, every = listed["stated"], listed["with_probe"] + listed["seven"] + listed["none"]
        self.assertEqual((stated["probe"], stated["seven"], stated["serial"]), (len(listed["with_probe"]), len(listed["seven"]), len(listed["serial"])))
        self.assertEqual((stated["total"], stated["serial_of"]), (len(every), len(every)))
        self.assertEqual(len(set(every)), len(every), "a run is listed twice")

    def test_every_listed_mips_run_is_classified_as_the_contract_states_and_every_tracked_probe_line_is_unseeded(self):
        classified = self.classify_mips_runs(self.tracked_mips_captures())      # also checks the quantified claim on every tracked capture
        self.check_listed(self.pinned_texts()["contract"], classified)

    def test_a_wrong_list_or_a_count_over_uncommitted_files_fails_the_soundness_check_and_the_control_passes(self):
        contract = self.pinned_texts()["contract"]
        classified = self.classify_mips_runs(self.tracked_mips_captures())
        self.check_listed(contract, classified)                                   # the control: the real paragraph is sound
        probe_list = "`1412ac47`, `22637af0`, `2a405e88`, `570cd370` and `f0a91e7b`; every capture"
        doc_plants = {                                                            # (old, new) edits of the paragraph
            "v1a's four-run list (says five, lists four)": [(probe_list, "`1412ac47`, `570cd370`, `2a405e88` and `f0a91e7b`; every capture")],
            "a working-tree log counted as a seventh seven-probe run": [
                ("`6e4d408c` and `d0b4edb6`.", "`6e4d408c`, `d0b4edb6` and `toplevel`."), ("Six other committed", "Seven other committed"),
                ("twelve in all", "thirteen in all"), ("of the twelve keep", "of the thirteen keep")],
            "an id nobody committed in the probe list": [(probe_list, "`1412ac47`, `22637af0`, `2a405e88`, `570cd370` and `deadbeef`; every capture")],
            "a run listed twice": [("`6e4d408c` and `d0b4edb6`.", "`6e4d408c` and `5e6b9868`.")],
            # a count word that disagrees with its own list while the total still adds up: only the per-list arithmetic can see these
            "the probe count says six while five are listed": [("twelve in all, five carry", "twelve in all, six carry")],
            "the seven-probe count says five while six are listed": [("Six other committed", "Five other committed")],
            "the serial-log count says six while five are listed": [("Only five of the twelve", "Only six of the twelve")],
            "a serial log claimed for a stdout-only run": [("(`1412ac47`, `20261104-2208`,", "(`1412ac47`, `22637af0`,")],
        }
        for label, edits in doc_plants.items():
            planted = contract
            for old, new in edits:
                self.assertEqual(planted.count(old), 1, (label, old))
                planted = planted.replace(old, new)
            with self.assertRaises(AssertionError, msg=label):
                self.check_listed(planted, classified)
            self.check_listed(contract, classified)                               # and with the plant removed it passes again
        class_plants = {                                                          # the same paragraph against a tree that says otherwise
            "the no-userspace run called a probe run": ("44a32b95", "kind", "with_probe"),
            "a seven-probe run moved to the probe list": ("20261104-2158", "kind", "with_probe"),
            "a probe run moved to the seven-probe list": ("2a405e88", "kind", "seven"),
            "a listed serial log that the tree does not have": ("2a405e88", "serial", False),
        }
        for label, (run, key, value) in class_plants.items():
            with self.assertRaises(AssertionError, msg=label):
                self.check_listed(contract, {**classified, run: {**classified[run], key: value}})
            self.check_listed(contract, classified)

    def test_a_synthetic_thirteenth_run_passes_with_the_unseeded_line_fails_with_another_status_and_does_not_make_the_list_incomplete(self):
        contract = self.pinned_texts()["contract"]
        captures = self.tracked_mips_captures()
        carrying = self.read_tracked_capture("2a405e88bb10497b98b85abeae7dffaf", "boot-mips-stdout.bin")
        unseeded = "FFW_PROBE:GETRANDOM status=UNSEEDED rc=-11"
        self.assertIn(unseeded, carrying)

        def with_a_thirteenth(text, names=("boot-mips-stdout.bin",), second=None):
            extended = {**captures, "feedface0013": list(names)}

            def read(run, name):
                if run != "feedface0013":
                    return self.read_tracked_capture(run, name)
                return text if second is None or name == names[0] else second

            return self.classify_mips_runs(extended, read)

        # Passes: a new committed run that carries the probe and prints UNSEEDED. The paragraph does not list it and stays sound.
        classified = with_a_thirteenth(carrying)
        self.assertEqual(classified["feedface"], {"kind": "with_probe", "serial": False})
        self.check_listed(contract, classified)
        # Fails: the same run printing another status, or the line twice, contradicts the quantified claim.
        for other in ("FFW_PROBE:GETRANDOM status=PASS rc=16", "FFW_PROBE:GETRANDOM status=UNSEEDED rc=0", "FFW_PROBE:GETRANDOM status=UNSEEDED"):
            with self.assertRaises(AssertionError, msg=other):
                with_a_thirteenth(carrying.replace(unseeded, other))
        with self.assertRaises(AssertionError, msg="the line printed twice"):
            with_a_thirteenth(carrying.replace(unseeded, unseeded + "\n" + unseeded))
        # Another new run without the probe is simply another run; two captures of one run that disagree need their own sentence.
        self.assertEqual(with_a_thirteenth(carrying.replace(unseeded, "FFW_PROBE:CLOCK status=PASS"))["feedface"]["kind"], "seven")
        self.assertEqual(with_a_thirteenth("nothing here")["feedface"]["kind"], "none")
        with self.assertRaises(AssertionError, msg="captures that disagree"):
            with_a_thirteenth(carrying, names=("boot-mips-stdout.bin", "boot-mips-serial.log"), second="FFW_PROBE:CLOCK status=PASS")
        self.check_listed(contract, with_a_thirteenth(carrying))                  # the control, restored

    def test_in_a_copy_of_the_runs_tree_a_thirteenth_run_with_the_unseeded_line_passes_and_one_with_another_status_fails(self):
        contract = self.pinned_texts()["contract"]
        unseeded = b"FFW_PROBE:GETRANDOM status=UNSEEDED rc=-11"
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "runs"                                             # a copy of the tracked MIPS captures, as files
            tracked = self.tracked_mips_captures()
            for run, names in tracked.items():
                for name in names:
                    target = copy / run / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes((REPO / "toolchain" / "results" / "runs" / run / name).read_bytes())
            carrying = (copy / "2a405e88bb10497b98b85abeae7dffaf" / "boot-mips-stdout.bin").read_bytes()
            self.assertIn(unseeded, carrying)
            thirteenth = copy / "feedface0013" / "boot-mips-stdout.bin"            # the synthetic thirteenth committed run
            thirteenth.parent.mkdir()

            def judge_the_copy():
                captures = self.tracked_mips_captures(runs_root=copy)
                self.assertEqual(len(captures), len(tracked) + 1)
                return self.classify_mips_runs(captures, lambda run, name: (copy / run / name).read_bytes().decode("utf-8", errors="replace"))

            thirteenth.write_bytes(carrying)                                      # carries the probe and prints UNSEEDED: passes
            self.check_listed(contract, judge_the_copy())
            thirteenth.write_bytes(carrying.replace(unseeded, b"FFW_PROBE:GETRANDOM status=PASS rc=16"))     # a different status: fails
            with self.assertRaises(AssertionError):
                judge_the_copy()
            thirteenth.write_bytes(carrying)                                      # the control, restored: passes again
            self.check_listed(contract, judge_the_copy())

    def test_the_baselines_are_the_transcripts_the_retained_run_printed(self):
        for arch, expected in (("mips", mips_provider_green_lines()), ("ppc", PROVIDER_BASELINES["ppc degraded"][1])):
            log = (RUN_2A405E88 / f"boot-{arch}-serial.log").read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
            printed = [line for line in log.split("\n") if line.startswith("FFW_PLATFORM:")]
            self.assertEqual(printed, expected, arch)


class EntropyInjectionGuardTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def script(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_real_boot_scripts_name_no_rng_device(self):
        scripts = [VERIFIER.SCRIPT_DIR / name for name in VERIFIER.BOOT_SCRIPT_NAMES]
        self.assertEqual(VERIFIER.BOOT_SCRIPT_NAMES, ("boot-mips.sh", "boot-ppc.sh"))
        self.assertEqual(VERIFIER.entropy_injection_problems(scripts), [])

    def test_every_way_of_feeding_the_guest_host_entropy_is_named(self):
        clean = self.script("clean.sh", "exec qemu-system-mips -M malta -m 64M -append 'console=ttyS0'\n")
        self.assertEqual(VERIFIER.entropy_injection_problems([clean]), [])
        for text in ("exec qemu-system-mips -device virtio-rng-pci\n",
                     "exec qemu-system-mips -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0\n",
                     "exec qemu-system-ppc -object RNG-BUILTIN,id=r\n",
                     "exec qemu-system-ppc -device virtio-rng\n"):
            path = self.script("bad.sh", text)
            self.assertEqual(VERIFIER.entropy_injection_problems([path]), ["bad.sh:names_an_rng_device"], text)

    def test_a_random_kernel_parameter_is_named_and_a_comment_that_says_rng_fails_closed(self):
        for text in ("exec qemu-system-ppc -append 'console=ttyPZ0 random.trust_cpu=on'\n",
                     'exec qemu-system-mips -append "random.trust_bootloader=on rdinit=/init"\n'):
            self.assertEqual(VERIFIER.entropy_injection_problems([self.script("param.sh", text)]),
                             ["param.sh:names_a_random_kernel_parameter"], text)
        both = self.script("both.sh", "exec qemu -device virtio-rng-pci -append 'random.trust_cpu=on'\n")
        self.assertEqual(VERIFIER.entropy_injection_problems([both]),
                         ["both.sh:names_an_rng_device", "both.sh:names_a_random_kernel_parameter"])
        # Not parameters: the device node's name, a longer word, and a word that merely contains `random.`.
        for text in ("exec qemu -append 'rdinit=/init panic=-1' # the guest reads /dev/random\n",
                     "exec qemu -append 'randomize_kstack_offset=on'\n", "echo prandom.x=1\n"):
            self.assertEqual(VERIFIER.entropy_injection_problems([self.script("fine.sh", text)]), [], text)
        # A comment that says `rng` is flagged on purpose: the check is a text search and fails closed.
        self.assertEqual(VERIFIER.entropy_injection_problems([self.script("comment.sh", "# there is no rng device here\nexec qemu\n")]),
                         ["comment.sh:names_an_rng_device"])

    def test_an_unreadable_script_is_a_problem_not_a_pass(self):
        self.assertEqual(VERIFIER.entropy_injection_problems([self.root / "missing.sh"]), ["missing.sh:unreadable"])
        self.script("binary.sh", "ok")
        (self.root / "binary.sh").write_bytes(b"\xff\xfe\x00 not utf-8")
        self.assertEqual(VERIFIER.entropy_injection_problems([self.root / "binary.sh"]), ["binary.sh:unreadable"])


if __name__ == "__main__":
    unittest.main()
