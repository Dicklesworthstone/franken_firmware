"""D02 target CPU cost measurement (ffw-7s0): the ruler, the transcript parser, the gates, the ELF scan, the control
patch and the snapshot preparation.

Everything here checks the HOST side against synthetic transcripts. No guest booted and no instruction was counted by
QEMU; these fixtures are not measurements and the numbers in them are invented round figures. Each negative plants
exactly one fault next to an unplanted positive baseline of the same shape, so a test cannot pass by failing for an
unrelated reason.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "toolchain" / "src" / "measure-d02-cost.py"


def load():
    spec = importlib.util.spec_from_file_location("measure_d02_cost_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


m = load()

SLOPE, INTERCEPT = 0.1, 12.0   # a synthetic ruler: 10 instructions per Count tick, 12 ticks of fixed overhead
FRAMES = 256 * 8
# name: (channels, sections, noise f64, noise f32, silence f64, silence f32); invented round figures per frame
COSTS = {
    "S1": (2, 2, 2900.0, 2400.0, None, None),
    "S5": (5, 3, 6400.0, 5050.0, 4000.0, 3500.0),
    "S5-max": (5, 14, 11000.0, 5400.0, 7000.0, 3700.0),
}


def ticks(instructions):
    return round(INTERCEPT + SLOPE * instructions)


SPIN3 = (1_300_000, 5_000_000, 12_000_000, 20_000_000)
SPIN5 = (800_000, 3_000_000, 7_200_000, 12_000_000)


def ruler_lines(phase, slope=SLOPE, intercept=INTERCEPT):
    lines = []
    for _ in range(2):
        for shape, sizes in ((3, SPIN3), (5, SPIN5)):
            for iterations in sizes:
                lines.append(f"FFW_D02COST_RULER phase={phase} shape={shape} iterations={iterations} "
                             f"ticks={round(intercept + slope * shape * iterations)}")
    return lines


def transcript(variant="f64", costs=COSTS, bits=None, mutate=None, phase_b_slope=SLOPE):
    """A consistent transcript in the order the guest prints it: boot noise, ALIVE, BEGIN, the self-test, the empty
    floor, ruler A, the D02 phase, ruler B, END; runs whose ticks follow `costs`."""
    column = 0 if variant == "f64" else 1
    bits = m.selftest_expectation()[variant] if bits is None else bits
    lines = ["[    0.000000] Linux version 4.19.0-21-4kc-malta", "[    0.512000] Freeing unused kernel memory: 280K",
             "FFW_D02COST_ALIVE",
             "FFW_D02COST_BEGIN version=2 block_frames=256 blocks_per_rep=8 reps=5 warmup_blocks=6 ruler_reps=2",
             f"FFW_D02COST_SELFTEST section=lp120_step127 bits={bits:08x}",
             "FFW_D02COST_EMPTY ticks=[3, 3, 3, 3, 3, 3, 3, 3]"]
    lines += ruler_lines("A")
    for name, (channels, sections, *per_frame) in costs.items():
        lines.append(f"FFW_D02COST_CONFIG name={name} channels={channels} sections={sections} admitted=1 status=Active")
        for input_kind, cost in (("noise", per_frame[column]), ("silence", per_frame[2 + column])):
            if cost is None:
                continue
            lines.append(f"FFW_D02COST_WARM name={name} input={input_kind} applied_gain=1.000000")
            for rep in range(5):
                lines.append(f"FFW_D02COST_RUN name={name} input={input_kind} rep={rep} frames={FRAMES} "
                             f"ticks={ticks(cost * FRAMES)} min_channel_peak={812 if input_kind == 'noise' else 0}")
    lines += ruler_lines("B", slope=phase_b_slope)
    lines.append("FFW_D02COST_END")
    if mutate:
        lines = mutate(lines)
    return "\r\n".join(lines) + "\r\n"


def make_elf(words, fp_abi=None, machine=8, data=2):
    """A minimal ELF32 with an executable .text of the given 32-bit words (and optionally .MIPS.abiflags)."""
    text = b"".join(struct.pack(">I", w) for w in words)
    abiflags = bytes([0, 0, 0, 0, 0, 0, 0, fp_abi, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) if fp_abi is not None else b""
    names = b"\0.text\0" + (b".MIPS.abiflags\0" if abiflags else b"") + b".shstrtab\0"
    text_name = 1
    abi_name = 7 if abiflags else 0
    str_name = names.index(b".shstrtab")
    body = text + abiflags + names
    text_off, abi_off = 52, 52 + len(text)
    names_off = abi_off + len(abiflags)
    shoff = 52 + len(body)
    headers = [struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
               struct.pack(">IIIIIIIIII", text_name, 1, 0x6, 0x400000, text_off, len(text), 0, 0, 4, 0)]
    if abiflags:
        headers.append(struct.pack(">IIIIIIIIII", abi_name, 0x70000000 + 0x2A, 0x2, 0, abi_off, len(abiflags), 0, 0, 8, 24))
    headers.append(struct.pack(">IIIIIIIIII", str_name, 3, 0, 0, names_off, len(names), 0, 0, 1, 0))
    ident = b"\x7fELF" + bytes([1, data, 1]) + bytes(9)
    header = struct.pack(">16sHHIIIIIHHHHHH", ident, 2, machine, 1, 0x400000, 0, shoff, 0x70001000, 52, 32, 0, 40,
                         len(headers), len(headers) - 1)
    return header + body + b"".join(headers)


CLEAN_WORDS = [0x27BDFFE8, 0xAFBF0014, 0x00851021, 0x03E00008, 0x27BD0018]  # addiu, sw, addu, jr, addiu: no FPU
LWC1_WORD = 0xC4400000                                                         # lwc1 $f0, 0($2): opcode 0x31


def write(directory, name, data):
    path = pathlib.Path(directory) / name
    path.write_bytes(data) if isinstance(data, bytes) else path.write_text(data)
    return path


def judged(f64_text=None, f32_text=None, f64_elf=None, f32_elf=None):
    return m.judge(f64_text if f64_text is not None else transcript("f64"),
                   f32_text if f32_text is not None else transcript("f32"), f64_elf, f32_elf)


def clean_elf_info():
    with tempfile.TemporaryDirectory() as d:
        return m.read_elf(write(d, "x.elf", make_elf(CLEAN_WORDS, fp_abi=3)))


class SectionSelfTest(unittest.TestCase):
    def test_the_two_realizations_are_told_apart_by_values_observed_on_the_real_rust_code(self):
        expectation = m.selftest_expectation()
        as_float = lambda bits: struct.unpack(">f", struct.pack(">I", bits))[0]
        # Central batch 9 ran the f32-state build and printed 0.7229906916618347 at this sample (vector D02-RESP-004).
        self.assertEqual(as_float(expectation["f32"]), 0.7229906916618347)
        # The reference (f64 direct form I on the same stored coefficients) says 0.7229395337242748 there.
        self.assertEqual(expectation["f64"], m._bits(m._f32(0.7229395337242748)))
        self.assertNotEqual(expectation["f64"], expectation["f32"])


class Ruler(unittest.TestCase):
    def points(self, slope=SLOPE, intercept=INTERCEPT, noise=None):
        out = []
        for _ in range(3):
            for shape, sizes in ((3, (100_000, 200_000, 400_000, 800_000, 1_600_000)),
                                 (5, (60_000, 120_000, 240_000, 480_000, 960_000))):
                for iterations in sizes:
                    out.append((shape, iterations, round(intercept + slope * shape * iterations)))
        if noise:
            out.append((3, 400_000, round(INTERCEPT + SLOPE * 3 * 400_000) + noise))  # a stray interrupt: only adds
        return out

    def test_a_perfect_ruler_is_recovered_and_a_stray_interrupt_does_not_move_it(self):
        clean = m.fit_ruler(self.points())
        self.assertAlmostEqual(clean["slope"], SLOPE, places=6)
        self.assertAlmostEqual(clean["intercept"], INTERCEPT, delta=1.0)
        self.assertAlmostEqual(clean["instructions_per_tick"], 10.0, places=3)
        self.assertEqual(m.ruler_problems(clean), [])
        noisy = m.fit_ruler(self.points(noise=900))     # the minimum over repetitions is used
        self.assertAlmostEqual(noisy["slope"], clean["slope"], places=9)

    def test_two_loop_shapes_that_disagree_are_refused(self):
        baseline = m.ruler_problems(m.fit_ruler(self.points()))
        skewed = [(s, i, t if s == 3 else round(INTERCEPT + 1.2 * SLOPE * s * i)) for s, i, t in self.points()]
        self.assertEqual(baseline, [])
        self.assertTrue(any("loop shapes disagree" in p for p in m.ruler_problems(m.fit_ruler(skewed))))

    def test_a_ruler_that_is_not_linear_is_refused(self):
        baseline = self.points()
        bent = [(s, i, t + (4000 if (s, i) == (3, 800_000) else 0)) for s, i, t in baseline]
        self.assertEqual(m.ruler_problems(m.fit_ruler(baseline)), [])
        problems = m.ruler_problems(m.fit_ruler([p for p in bent if p[2] > 0]))
        self.assertTrue(problems and any("not linear" in p or "disagree" in p for p in problems), problems)

    def test_too_few_sizes_cannot_calibrate(self):
        with self.assertRaises(m.MeasurementError):
            m.fit_ruler([(3, 100_000, 30_012), (3, 200_000, 60_012), (5, 60_000, 30_012), (5, 120_000, 60_012)])


class RulerPhases(unittest.TestCase):
    def points(self, slope_b=SLOPE, skip_b=False):
        out = []
        for phase, slope in (("A", SLOPE), ("B", slope_b)):
            if skip_b and phase == "B":
                continue
            for _ in range(2):
                for shape, sizes in ((3, SPIN3), (5, SPIN5)):
                    for iterations in sizes:
                        out.append((phase, shape, iterations, round(INTERCEPT + slope * shape * iterations)))
        return out

    def test_a_ruler_that_holds_still_while_d02_runs_is_accepted(self):
        analysis = m.ruler_analysis(self.points())
        self.assertEqual(m.ruler_problems(analysis), [])
        self.assertLess(analysis["phase_drift"], 1e-6)

    def test_a_scale_that_drifts_between_before_and_after_is_refused(self):
        drifted = m.ruler_analysis(self.points(slope_b=SLOPE * 1.02))
        self.assertGreater(drifted["phase_drift"], 0.019)
        self.assertTrue(any("drifted" in p for p in m.ruler_problems(drifted)))

    def test_a_ruler_run_only_once_cannot_show_drift_and_is_refused(self):
        problems = m.ruler_problems(m.ruler_analysis(self.points(skip_b=True)))
        self.assertTrue(any("before (A) and after (B)" in p for p in problems), problems)


class RealQemuRuler(unittest.TestCase):
    """The tick counts below are REAL: a hand-assembled big-endian MIPS probe, run as /init under qemu-system-mips
    11.1.2 (-icount shift=0,align=off,sleep=off) with the Debian 4.19 Malta kernel, three repetitions of five loop
    sizes per shape, printed after all measurements. The two boots disagree on the scale (4.45 and 5.18 instructions
    per tick) and boot 0's early repetitions are inflated up to 2.2x; the gates must accept the floor of both."""
    SIZES = [(3, n) for n in (100_000, 400_000, 1_600_000, 6_400_000, 16_000_000)] + \
            [(5, n) for n in (60_000, 240_000, 960_000, 3_840_000, 9_600_000)]
    BOOT0 = [149401, 531345, 2360155, 9426055, 23484432, 175159, 544644, 2381430, 9165836, 10801693,   # repetition 0
             67808, 268039, 1080012, 4324214, 10799509, 66384, 266809, 1075697, 4308013, 10773097,     # repetition 1
             68298, 270203, 1075966, 4311345, 10776100, 66418, 272382, 1077536, 4320946, 10795934]     # repetition 2
    BOOT1 = [58129, 230177, 930915, 3707569, 9269727, 58556, 230711, 927507, 3708563, 9268344,
             57192, 232269, 926846, 3707392, 9258211, 57153, 234031, 926661, 3704682, 9258426,
             59136, 232087, 925422, 3706010, 9270240, 57203, 232200, 926314, 3709646, 9267909]

    def fit(self, boot):
        points = []
        for repetition in range(3):
            for (shape, n), ticks in zip(self.SIZES, boot[repetition * 10:(repetition + 1) * 10]):
                points.append((shape, n, ticks))
        return m.fit_ruler(points)

    def test_both_real_boots_pass_the_gates_with_their_own_scale(self):
        for name, boot, expected in (("boot 0", self.BOOT0, 4.454), ("boot 1", self.BOOT1, 5.184)):
            fit = self.fit(boot)
            self.assertEqual(m.ruler_problems(fit), [], name)
            self.assertAlmostEqual(fit["instructions_per_tick"], expected, delta=0.005, msg=name)
            self.assertLess(fit["shape_disagreement"], 0.001, name)

    def test_the_scale_is_not_a_constant_so_no_constant_may_be_assumed(self):
        a, b = self.fit(self.BOOT0)["instructions_per_tick"], self.fit(self.BOOT1)["instructions_per_tick"]
        self.assertGreater(abs(a - b) / b, 0.10)          # 4.45 versus 5.18: a 14 % difference between two boots

    def test_the_inflated_early_repetitions_do_not_move_the_floor(self):
        # Repetition 0 of boot 0 is 2x inflated at every size; the minimum over repetitions ignores it.
        clean_only = m.fit_ruler([(s, n, t) for rep in (1, 2) for (s, n), t in zip(self.SIZES, self.BOOT0[rep * 10:(rep + 1) * 10])])
        with_inflated = self.fit(self.BOOT0)
        self.assertAlmostEqual(clean_only["slope"], with_inflated["slope"], delta=with_inflated["slope"] * 0.002)


class Parsing(unittest.TestCase):
    def test_a_consistent_transcript_parses_with_kernel_noise_and_crlf(self):
        parsed = m.parse_transcript(transcript())
        self.assertEqual(parsed["begin"]["blocks_per_rep"], 8)
        self.assertTrue(parsed["alive"])
        self.assertEqual(len(parsed["ruler"]), 32)                       # 2 phases x 2 reps x (4 + 4) loops
        self.assertEqual({p[0] for p in parsed["ruler"]}, {"A", "B"})
        self.assertEqual(set(parsed["configs"]), {"S1", "S5", "S5-max"})
        self.assertTrue(parsed["end"])
        self.assertEqual(len(parsed["runs"]), 5 * 5)  # S1 noise, S5 noise+silence, S5-max noise+silence

    def test_a_corrupted_marker_line_is_an_error_not_a_skipped_line(self):
        baseline = transcript()
        m.parse_transcript(baseline)
        corrupted = baseline.replace("min_channel_peak=812", "min_channel_peak=81[ 12.5] kernel text", 1)
        with self.assertRaises(m.MeasurementError):
            m.parse_transcript(corrupted)

    def test_unknown_and_duplicate_markers_are_errors(self):
        with self.assertRaises(m.MeasurementError):
            m.parse_transcript(transcript(mutate=lambda ls: ls + ["FFW_D02COST_SURPRISE x=1"]))
        with self.assertRaises(m.MeasurementError):
            m.parse_transcript(transcript(mutate=lambda ls: [ls[3]] + ls))   # a second BEGIN
        first_config = next(i for i, l in enumerate(transcript(mutate=None).split("\r\n")) if "CONFIG name=S1" in l)
        with self.assertRaises(m.MeasurementError):
            m.parse_transcript(transcript(mutate=lambda ls: ls + [ls[first_config]]))  # a config line twice

    def test_a_refused_config_keeps_its_reason(self):
        text = transcript(mutate=lambda ls: ls + ["FFW_D02COST_CONFIG name=S9-max channels=9 sections=27 admitted=0 "
                                                  "status=FailMuted(IntermediateRangeExceeded { channel: 3 })"])
        refused = m.parse_transcript(text)["configs"]["S9-max"]
        self.assertFalse(refused["admitted"])
        self.assertIn("IntermediateRangeExceeded", refused["status"])


class Judging(unittest.TestCase):
    def test_the_baseline_passes_and_the_numbers_follow_from_the_ticks(self):
        report = judged(f64_elf=clean_elf_info(), f32_elf=clean_elf_info())
        self.assertTrue(report["ok"], report["problems"])
        s5 = report["rows"]["S5/noise"]
        self.assertAlmostEqual(s5["f64_per_frame"], 6400.0, delta=0.5)
        self.assertAlmostEqual(s5["f32_per_frame"], 5050.0, delta=0.5)
        self.assertAlmostEqual(s5["delta_per_frame"], 1350.0, delta=1.0)
        self.assertAlmostEqual(s5["delta_per_section_per_frame"], 450.0, delta=1.0)   # 1350 / 3 sections
        self.assertAlmostEqual(report["rows"]["S5-max/noise"]["delta_per_section_per_frame"], (11000.0 - 5400.0) / 14, delta=1.0)
        self.assertAlmostEqual(s5["f64_minstr_per_second"], 6400.0 * 48000 / 1e6, delta=0.05)
        self.assertIn("S5/silence", report["rows"])
        self.assertNotIn("S1/silence", report["rows"])

    def refuses(self, **kwargs):
        report = judged(**kwargs)
        self.assertFalse(report["ok"])
        self.assertEqual(report["rows"], {}, "a failed gate must not leave numbers behind")
        return " | ".join(report["problems"])

    def test_a_binary_supplied_under_the_wrong_label_is_refused(self):
        self.assertTrue(judged()["ok"])
        self.assertIn("measured the f32 section, but was supplied as the f64 build",
                      self.refuses(f64_text=transcript("f32")))

    def test_a_self_test_that_matches_neither_realization_is_refused(self):
        self.assertIn("match neither", self.refuses(f64_text=transcript("f64", bits=0x3F000000)))

    def test_a_chain_that_never_ran_is_refused_rather_than_reported_cheap(self):
        dead = transcript("f64", mutate=lambda ls: [l.replace("min_channel_peak=812", "min_channel_peak=0") if "S5 " in l else l for l in ls])
        self.assertIn("chain may not have been live", self.refuses(f64_text=dead))

    def test_output_on_digital_silence_is_refused(self):
        leaky = transcript("f64", mutate=lambda ls: [l.replace("min_channel_peak=0", "min_channel_peak=3") if "name=S5 input=silence" in l else l for l in ls])
        self.assertIn("produced output on digital silence", self.refuses(f64_text=leaky))

    def test_a_board_that_was_not_at_full_gain_is_refused(self):
        low = transcript("f64", mutate=lambda ls: [l.replace("applied_gain=1.000000", "applied_gain=0.400000") if "name=S1" in l else l for l in ls])
        self.assertIn("not at full gain", self.refuses(f64_text=low))

    def reps(self, pattern):
        """Rewrite the S1 noise repetitions so their ticks are `pattern` times the baseline's."""
        def mutate(lines):
            out = []
            for line in lines:
                found = re.search(r"name=S1 input=noise rep=(\d) ", line)
                if found:
                    line = re.sub(r"ticks=(\d+) min", lambda g: f"ticks={round(int(g.group(1)) * pattern[int(found.group(1))])} min", line)
                out.append(line)
            return out
        return transcript("f64", mutate=mutate)

    def test_a_stable_floor_is_read_even_when_other_repetitions_were_inflated(self):
        baseline = judged()
        self.assertTrue(baseline["ok"], baseline["problems"])
        # Boot-time kernel work inflated the FIRST repetitions up to 2.2x in a real probe; interrupts only add ticks.
        for pattern in ((2.2, 2.0, 1, 1, 1), (1, 1, 1, 1, 2.0), (1, 1.6, 1, 1.0004, 1.3)):
            report = judged(f64_text=self.reps(pattern))
            self.assertTrue(report["ok"], (pattern, report["problems"]))
            row = report["analyses"]["f64"]["measurements"]["S1/noise"]
            self.assertAlmostEqual(row["instructions_per_frame"]["min"], 2900.0, delta=0.5)   # the floor, not the mean
            self.assertEqual(row["inflated_reps"], sum(1 for p in pattern if p > 1.02))

    def test_no_stable_floor_is_refused(self):
        self.assertTrue(judged()["ok"])
        self.assertIn("no stable floor", self.refuses(f64_text=self.reps((1, 1.5, 2, 2, 2))))
        self.assertIn("no stable floor", self.refuses(f64_text=self.reps((1.0, 1.02, 1.5, 1.6, 1.7))))

    def test_too_few_repetitions_and_wrong_frame_counts_are_refused(self):
        few = transcript("f64", mutate=lambda ls: [l for l in ls if not ("name=S1 input=noise" in l and any(f"rep={r} " in l for r in (2, 3, 4)))])
        self.assertIn("need 3+", self.refuses(f64_text=few))
        wrong = transcript("f64", mutate=lambda ls: [l.replace(f"frames={FRAMES}", "frames=9000") if "name=S1" in l else l for l in ls])
        self.assertIn("frames other than", self.refuses(f64_text=wrong))

    def test_an_incomplete_transcript_gives_no_numbers(self):
        cut = transcript("f64", mutate=lambda ls: ls[:-1])   # END missing: the guest died or the log was truncated
        report = judged(f64_text=cut)
        self.assertFalse(report["ok"])
        self.assertEqual(report["rows"], {})
        self.assertIn("incomplete", report["problems"][0])

    def test_a_refused_configuration_is_reported_not_hidden_and_does_not_block_the_others(self):
        refused = ("FFW_D02COST_CONFIG name=S9-max channels=9 sections=27 admitted=0 "
                   "status=FailMuted(IntermediateRangeExceeded { channel: 3 })")
        report = judged(f64_text=transcript("f64", mutate=lambda ls: ls[:-1] + [refused, ls[-1]]),
                        f32_text=transcript("f32", mutate=lambda ls: ls[:-1] + [refused, ls[-1]]))
        self.assertTrue(report["ok"], report["problems"])
        self.assertTrue(report["rows"]["S9-max"]["refused_or_missing"])
        self.assertIn("S5/noise", report["rows"])
        self.assertIn("refused by admission", m.render(report, "abc"))

    def test_fpu_opcodes_or_a_hard_float_abi_in_either_binary_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            clean = m.read_elf(write(d, "clean.elf", make_elf(CLEAN_WORDS, fp_abi=3)))
            fpu = m.read_elf(write(d, "fpu.elf", make_elf(CLEAN_WORDS + [LWC1_WORD], fp_abi=3)))
            hard = m.read_elf(write(d, "hard.elf", make_elf(CLEAN_WORDS, fp_abi=1)))
        self.assertTrue(judged(f64_elf=clean, f32_elf=clean)["ok"])
        self.assertIn("soft-float is NOT proven", self.refuses(f64_elf=fpu, f32_elf=clean))
        self.assertIn("not 3 (soft)", self.refuses(f64_elf=clean, f32_elf=hard))

    def test_the_report_states_what_the_numbers_are_not(self):
        text = m.render(judged(), "abc123")
        for phrase in ("INSTRUCTIONS EXECUTED", "not\ncycles on a real 24K core", "no CPU clock for any MIPS board",
                       "synthetic fixtures", "abc123"):
            self.assertIn(phrase, text)
        failed = m.render(m.judge(transcript("f32"), transcript("f32"), None, None), None)
        self.assertIn("NO HEADLINE NUMBER", failed)
        self.assertNotIn("f64 instr/frame", failed)


class ElfScan(unittest.TestCase):
    def test_fpu_words_are_found_and_integer_code_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            clean = m.read_elf(write(d, "a.elf", make_elf(CLEAN_WORDS, fp_abi=3)))
            fpu = m.read_elf(write(d, "b.elf", make_elf(CLEAN_WORDS + [LWC1_WORD, 0x46200000], fp_abi=3)))
        self.assertEqual(clean["fpu_words"], [])
        self.assertEqual(clean["fp_abi"], 3)
        self.assertEqual(clean["exec_words"], len(CLEAN_WORDS))
        self.assertEqual([(name, kind) for name, _off, kind, _w in fpu["fpu_words"]], [(".text", "LWC1"), (".text", "COP1")])

    def test_only_a_32_bit_big_endian_mips_elf_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            for name, kwargs in (("le", {"data": 1}), ("ppc", {"machine": 20})):
                with self.assertRaises(m.MeasurementError):
                    m.read_elf(write(d, name, make_elf(CLEAN_WORDS, **kwargs)))
            with self.assertRaises(m.MeasurementError):
                m.read_elf(write(d, "junk", b"not an elf"))


class ControlPatch(unittest.TestCase):
    PATH = "crates/franken-dsp/src/protection/runtime.rs"

    def test_the_patch_turns_the_section_into_the_f32_realization_and_touches_nothing_else(self):
        patch = REPO / m.PATCH_REL
        self.assertEqual(re.findall(r"^\+\+\+ b/(\S+)", patch.read_text(), re.M), [self.PATH])
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / self.PATH
            target.parent.mkdir(parents=True)
            shutil.copy2(REPO / self.PATH, target)
            before = target.read_text()
            subprocess.run(["git", "apply", "-p1", str(patch)], cwd=d, check=True)
            after = target.read_text()
        section = lambda text: text[text.index("pub struct Section"):text.index("impl Section")]
        self.assertIn("z1: f64", section(before))        # shipped: f64 state
        self.assertIn("z1: f32", section(after))         # control: f32 state
        self.assertNotIn("f64", section(after))
        process = lambda text: text[text.index("pub fn process(&mut self, x: f32) -> f32 {"):][:260]
        self.assertIn("f64::from(x)", process(before))
        self.assertNotIn("f64::from(x)", process(after))
        # everything outside Section's four methods and its test hook is byte-for-byte unchanged
        outside = lambda text: text[text.index("pub struct DcRejector"):]
        self.assertEqual(outside(before).replace("runtime.sections[0].z1 = f64::from(z1);", ""),
                         outside(after).replace("runtime.sections[0].z1 = z1;", ""))


class Prepare(unittest.TestCase):
    def make_repo(self, root):
        for rel in ("Cargo.lock", "toolchain/linker/zig-cc-mips-be", "crates/franken-dsp/src/protection/runtime.rs"):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, target)
        bench = root / m.BENCH_REL
        shutil.copytree(REPO / m.BENCH_REL, bench)
        env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", *env, "commit", "-q", "-m", "fixture"], cwd=root, check=True)

    def test_two_snapshots_differ_only_by_the_patch_and_the_commands_are_central_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "repo"
            root.mkdir()
            self.make_repo(root)
            original_repo = m.REPO
            m.REPO = root
            try:
                work = pathlib.Path(d) / "work"
                output = m.prepare(work)
                plain, control = work / "plain", work / "control-f32"
                runtime = "crates/franken-dsp/src/protection/runtime.rs"
                self.assertIn("z1: f64", (plain / runtime).read_text())
                self.assertIn("z1: f32", (control / runtime).read_text())
                self.assertTrue((plain / m.BENCH_REL / "Cargo.lock").is_file())
                for needle in ("RCH_REQUIRE_REMOTE=1", "rch exec -- cargo +nightly build", "--offline", "--release",
                               "-Z build-std=core,alloc,std,panic_abort", "-j 2", "RCH_CANONICAL_PROJECT_ROOT=",
                               "target-feature=+crt-static", "zig-cc-mips-be", f"--manifest-path {m.BENCH_REL}/Cargo.toml"):
                    self.assertIn(needle, output)
                self.assertEqual(output.count("rch exec -- cargo +nightly build"), 2)
                with self.assertRaises(m.MeasurementError):     # nothing is ever deleted or overwritten
                    m.prepare(work)
            finally:
                m.REPO = original_repo


class RulerProbe(unittest.TestCase):
    """The hand-assembled probe (toolchain/src/d02-cost/ruler_probe.py): its encodings against the MIPS32 manual."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("ruler_probe_under_test", REPO / m.BENCH_REL / "ruler_probe.py")
        cls.p = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.p
        spec.loader.exec_module(cls.p)

    def test_encodings_match_the_architecture_manual(self):
        p = self.p
        for word, expected, text in (
                (p.addiu("t1", "t1", -1), 0x2529FFFF, "addiu $t1,$t1,-1"),
                (p.bne("t1", "zero", -2), 0x1520FFFE, "bne $t1,$zero,-2"),
                (p.lui("t1", 0x0123), 0x3C090123, "lui $t1,0x0123"),
                (p.subu("t3", "t2", "t0"), 0x01485823, "subu $t3,$t2,$t0"),
                (p.rdhwr("t0", 2), 0x7C08103B, "rdhwr $t0,$2"),
                (p.sw("t3", 36, "sp"), 0xAFAB0024, "sw $t3,36($sp)"),
                (p.lw("t3", 36, "sp"), 0x8FAB0024, "lw $t3,36($sp)"),
                (p.sltiu("t7", "t6", 10), 0x2DCF000A, "sltiu $t7,$t6,10"),
                (p.sb("t6", 3, "sp"), 0xA3AE0003, "sb $t6,3($sp)"),
                (p.SYSCALL, 0x0000000C, "syscall")):
            self.assertEqual(word, expected, f"{text}: {word:#010x} != {expected:#010x}")

    def test_the_loops_have_exactly_the_stated_instruction_counts(self):
        p = self.p
        for shape in (3, 5):
            code = p.spin(1000, shape)
            first, last = (i for i, w in enumerate(code) if w == p.rdhwr("t0", 2) or w == p.rdhwr("t2", 2))
            body = code[first + 1:last]
            self.assertEqual(len(body), shape, f"the shape-{shape} loop body")
            branch = next(i for i, w in enumerate(body) if w >> 26 == 5)
            self.assertEqual(body[branch + 1], p.NOP)                       # the delay slot is explicit
            offset = body[branch] & 0xFFFF
            offset -= 0x10000 if offset & 0x8000 else 0
            self.assertEqual(branch + 1 + offset, 0, "the branch returns to the first instruction of the body")

    def test_the_elf_is_a_big_endian_mips_executable_with_one_loadable_segment(self):
        image = self.p.elf(self.p.program(self.p.SIZES))
        self.assertEqual(image[:4], b"\x7fELF")
        self.assertEqual((image[4], image[5]), (1, 2))                      # 32-bit, big-endian
        e_type, machine = struct.unpack(">HH", image[16:20])
        self.assertEqual((e_type, machine), (2, 8))                         # EXEC, MIPS
        entry, phoff = struct.unpack(">II", image[24:32])
        self.assertEqual((entry, phoff), (0x400054, 52))

    def test_results_are_kept_in_memory_and_printed_only_after_the_last_measurement(self):
        p = self.p
        code = p.program(p.SIZES)
        reads = [i for i, w in enumerate(code) if w == p.rdhwr("t2", 2)]
        writes = [i for i, w in enumerate(code) if w == p.SYSCALL]
        self.assertEqual(len(reads), len(p.SIZES))
        self.assertGreater(min(writes), max(reads), "no write(2) may happen before the last timed loop has ended")

    def test_measurements_are_read_back_from_a_noisy_serial_log(self):
        log = "[    0.5] kernel\r\n0000C350\r\nsome text\r\n0001D4C0\r\nXYZ12345\r\n"
        self.assertEqual(self.p.measurements(log), [0xC350, 0x1D4C0])

    def test_the_probe_needs_a_fresh_log_directory_and_a_kernel_cache(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "occupied").write_text("x")
            old = dict(__import__("os").environ)
            try:
                __import__("os").environ["FFW_BUILD_DIR"] = d
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(self.p.main(["--log-dir", d]), 2)
                self.assertIn("not empty", err.getvalue())
                __import__("os").environ.pop("FFW_BUILD_DIR")
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(self.p.main(["--log-dir", str(pathlib.Path(d) / "fresh")]), 2)
                self.assertIn("FFW_BUILD_DIR", err.getvalue())
            finally:
                __import__("os").environ.clear()
                __import__("os").environ.update(old)


class Discipline(unittest.TestCase):
    def test_the_runner_never_builds_and_never_deletes(self):
        source = SCRIPT.read_text()
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        for forbidden in ("rmtree", ".unlink(", "os.remove", "os.rmdir", "shutil.move"):
            self.assertNotIn(forbidden, code, forbidden)
        self.assertIsNone(re.search(r"subprocess\.\w+\(\s*\[\s*[\"']cargo", code), "the runner must not run cargo")
        self.assertIsNone(re.search(r"subprocess\.\w+\(\s*\[\s*[\"']rch", code), "builds are requested, not run, here")

    def test_the_guest_program_reads_no_clock_it_cannot_calibrate(self):
        guest = (REPO / m.BENCH_REL / "src" / "main.rs").read_text()
        self.assertIn('"rdhwr {0}, $2"', guest)
        self.assertNotIn("Instant", guest)           # wall time is not what is measured
        self.assertIn("Exactly `3 * iterations` instructions", guest)
        self.assertIn("Exactly `5 * iterations` instructions", guest)
        self.assertEqual(guest.count("unsafe {"), 4)  # the counter, the two loops, and the power-off call: no other unsafe

    def test_the_guest_prints_nothing_while_it_measures_and_settles_first(self):
        guest = (REPO / m.BENCH_REL / "src" / "main.rs").read_text()
        for function in ("fn ruler_phase", "fn run_config", "fn noise_blocks", "fn section_selftest"):
            body = guest[guest.index(function):]
            body = body[:body.index("\n}\n")]
            self.assertNotIn("println!", body, f"{function} must not print: serial transmit interrupts would land in a timed region")
        self.assertEqual(guest.count("println!("), 4)    # ALIVE, the final dump loop, REBOOT_FAILED, HOST_BUILD
        settle = int(re.search(r"SETTLE: Duration = Duration::from_millis\((\d+)\)", guest).group(1))
        self.assertGreaterEqual(settle, 1000)
        self.assertLess(guest.index("std::thread::sleep(SETTLE)"), guest.rindex("section_selftest()"))   # the call in main, not the definition
        self.assertLess(guest.index('ruler_phase("A")'), guest.index("run_config(config"))
        self.assertLess(guest.index("run_config(config"), guest.index('ruler_phase("B")'))

    def test_the_benchmark_crate_matches_the_device_release_profile(self):
        bench = (REPO / m.BENCH_REL / "Cargo.toml").read_text()
        root = (REPO / "Cargo.toml").read_text()
        profile = lambda text: dict(re.findall(r"^(opt-level|lto|codegen-units|panic)\s*=\s*(\S+)", text.split("[profile.release]")[1], re.M))
        self.assertEqual(profile(bench), profile(root))
        self.assertIn("[workspace]", bench)


class CommandLine(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = m.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_analyze_prints_the_table_for_a_consistent_pair_and_no_number_for_a_failed_gate(self):
        with tempfile.TemporaryDirectory() as d:
            elf = write(d, "x.elf", make_elf(CLEAN_WORDS, fp_abi=3))
            good64, good32 = write(d, "a64.log", transcript("f64")), write(d, "a32.log", transcript("f32"))
            args = ["analyze", "--elf-f64", str(elf), "--elf-f32", str(elf), "--log-f64", str(good64), "--log-f32", str(good32)]
            code, out, _ = self.run_main(args)
            self.assertEqual(code, 0, out)
            self.assertIn("S5/noise", out)
            self.assertIn("0 FPU opcode word(s)", out)
            swapped = ["analyze", "--elf-f64", str(elf), "--elf-f32", str(elf), "--log-f64", str(good32), "--log-f32", str(good32)]
            code, out, _ = self.run_main(swapped)
            self.assertEqual(code, 1)
            self.assertIn("NO HEADLINE NUMBER", out)
            self.assertNotIn("S5/noise", out)

    def test_run_without_a_kernel_cache_is_a_clear_error_not_a_guess(self):
        with tempfile.TemporaryDirectory() as d, unittest.mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("FFW_BUILD_DIR", None)
            elf = write(d, "x.elf", make_elf(CLEAN_WORDS, fp_abi=3))
            code, _out, err = self.run_main(["run", "--elf-f64", str(elf), "--elf-f32", str(elf), "--log-dir", str(pathlib.Path(d) / "logs")])
            self.assertEqual(code, 2)
            self.assertIn("FFW_BUILD_DIR", err)


if __name__ == "__main__":
    unittest.main()
