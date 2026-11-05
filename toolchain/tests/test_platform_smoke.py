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
from pathlib import Path
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

    def run_main(self, captures, argv, target_name="target", explicit_target=True, build=False):
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
            if build:
                stack.enter_context(patch.object(VERIFIER.subprocess, "run", side_effect=fake_run))
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


if __name__ == "__main__":
    unittest.main()
