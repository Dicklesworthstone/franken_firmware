#!/usr/bin/env python3
"""Self-test of the N03 target-ISA judge (toolchain/src/measure-n03-target.py). SYNTHETIC: the transcripts here are fabricated
from the independent Python reference to prove the judge qualifies a good transcript and catches each kind of bad one,
including the planted negatives (replayed or canned records tied to a per-run seed, a truncated dump, one record that
differs) and a gate that must not pass vacuously. They say nothing about the Rust or the MIPS guest, neither of which has
been built or run.

    python3 -B -I -m unittest discover -s toolchain/tests -p 'test_measure_n03_target.py'
"""
import functools
import importlib.util
import json
import os
import re
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
SRC = os.path.join(HERE, "..", "src")
REPO = os.path.realpath(os.path.join(HERE, "..", ".."))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


m = _load(os.path.join(SRC, "measure-n03-target.py"), "measure_n03_target_under_test")
with open(os.path.join(REPO, "tests", "n03", "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

# The reference re-runs every world on each judge call; share one result per world (it is a pure function of the world).
_expect_for = m.N.gen.expect_for
_expect_cache = {}


def _cached_expect_for(wdef):
    key = wdef["id"]
    if key not in _expect_cache:
        _expect_cache[key] = _expect_for(wdef)
    return _expect_cache[key]


m.N.gen.expect_for = _cached_expect_for

WANTED = list(VEC["worlds"]) + [mm["world"] for mm in VEC["mixed"]["members"]]
SEED_A, SEED_B = 4_611_686_018_427_387_903, 123_456_789_012_345
IPT, INTERCEPT = 5.0, 40            # synthetic ruler: 5 instructions per tick, 40 ticks of read overhead
EXCH_INSTR, GATE_INSTR = 150_000, 60_000
JITTER = (0, 30, 10, 60, 5)         # extra ticks per repetition: strays only ever add
WARM, EXCH, GATE_CALLS, REPS = 100, 100, 400, 5


def ticks(instructions):
    return int(round(INTERCEPT + instructions / IPT))


def compact(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


@functools.lru_cache(maxsize=None)
def world_block(wid, flip=None):
    """STEP lines and the WEND line of one world, as the guest prints them. `flip` replaces the first Locked status."""
    wdef = next(w for w in WANTED if w["id"] == wid)
    steps = [{k: v for k, v in rec.items() if k != "tol"} for rec in m.N.gen.expect_for(wdef)]
    encoded = [compact(rec) for rec in steps]
    checks = max_err = max_unc = 0
    min_margin = None
    for op, rec in zip(wdef["ops"], steps):
        if op["op"] == "check" and "truth_group" in op and "group_ns" in rec and "uncertainty_ns" in rec:
            err = abs(op["truth_group"] - rec["group_ns"])
            checks += 1
            max_err, max_unc = max(max_err, err), max(max_unc, rec["uncertainty_ns"])
            margin = rec["uncertainty_ns"] - err
            min_margin = margin if min_margin is None else min(min_margin, margin)
    end = (f"FFW_N03T_WEND id={wid} steps={len(encoded)} fnv={m.fnv1a64_lines(encoded):016x} checks={checks} max_err={max_err} "
           f"max_unc={max_unc} min_margin={'none' if min_margin is None else min_margin}")
    lines = [f"FFW_N03T_STEP id={wid} i={i} {enc}" for i, enc in enumerate(encoded)] + [end]
    return tuple(lines)


def opt(v):
    return "none" if v is None else str(v)


def sim_lines(seed):
    out = []
    for index, shape in enumerate(m.SIM_SHAPES):
        r = m.sim_counted(m.sim_seed(seed, index), *shape)
        out.append(f"FFW_N03T_SIM idx={index} run_seed={seed} seed32={r['seed32']} probes={r['probes']} lost={r['lost']} "
                   f"rejected={r['rejected']} checks={r['checks']} violations={r['violations']} max_err={r['max_err']} "
                   f"max_unc={r['max_unc']} min_margin={opt(r['min_margin'])} locked={int(r['locked'])} resets={r['resets']}")
    return out


def ruler_lines():
    out = []
    for phase in "AB":
        for _ in range(2):
            for n in (1_300_000, 5_000_000, 12_000_000, 20_000_000):
                out.append(f"FFW_N03T_RULER phase={phase} shape=3 iterations={n} ticks={ticks(3 * n)}")
            for n in (800_000, 3_000_000, 7_200_000, 12_000_000):
                out.append(f"FFW_N03T_RULER phase={phase} shape=5 iterations={n} ticks={ticks(5 * n)}")
    return out


def cpu_lines():
    out = [f"FFW_N03T_WARM region=exchange exchanges={WARM} accepted={WARM}", f"FFW_N03T_WARM region=gate calls={GATE_CALLS} mapped=1"]
    for region, ops, per_op in (("exchange", EXCH, EXCH_INSTR), ("gate", GATE_CALLS, GATE_INSTR)):
        for rep, jitter in enumerate(JITTER):
            out.append(f"FFW_N03T_RUN region={region} rep={rep} ops={ops} done={ops} ticks={ticks(per_op * ops) + jitter}")
    out.append(f"FFW_N03T_STATS accepted={WARM + REPS * EXCH} probes_sent={WARM + REPS * EXCH} resets=0")
    return out


def good_transcript(seed=SEED_A, sims_seed=None):
    lines = ["FFW_N03T_ALIVE",
             f"FFW_N03T_BEGIN version=1 warm_exchanges={WARM} exchanges_per_rep={EXCH} gate_calls_per_rep={GATE_CALLS} reps={REPS} "
             f"ruler_reps=2 sims=2",
             f"FFW_N03T_SEED value={seed}", "FFW_N03T_EMPTY ticks=[3, 3, 3, 3, 3, 3, 3, 3]"]
    ruler = ruler_lines()
    lines += ruler[:16] + cpu_lines() + ruler[16:]
    for w in WANTED:
        lines += list(world_block(w["id"]))
    lines += sim_lines(seed if sims_seed is None else sims_seed)
    lines.append("FFW_N03T_END")
    return "\n".join(["Linux version 4.19.0 (kernel chatter is ignored)"] + lines) + "\n"


def host_log(text=None):
    out = []
    for w in WANTED:
        block = world_block(w["id"])
        end = block[-1]
        fnv = re.search(r"fnv=([0-9a-f]+)", end).group(1)
        out.append("N03-TARGET-HOST " + json.dumps({"id": w["id"], "steps": len(block) - 1, "fnv": fnv}))
    return "\n".join(out) + "\n"


def minimal_elf(words=(0x24020001, 0x03E00008), fp_abi=None, big_endian=True):
    """A tiny ELF32 big-endian MIPS file with a .text section (and optionally .MIPS.abiflags)."""
    text = b"".join(struct.pack(">I", w) for w in words)
    names = b"\0.text\0.shstrtab\0.MIPS.abiflags\0"
    abi = bytes(7) + bytes([fp_abi if fp_abi is not None else 0]) + bytes(16)
    body = text + names + (abi if fp_abi is not None else b"")
    off_text, off_names = 52, 52 + len(text)
    off_abi = off_names + len(names)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (1, 1, 6, 0, off_text, len(text), 0, 0, 4, 0),
                (7, 3, 0, 0, off_names, len(names), 0, 0, 1, 0)]
    if fp_abi is not None:
        sections.append((names.index(b".MIPS.abiflags"), 0x7000002A, 2, 0, off_abi, 24, 0, 0, 8, 24))
    shoff = 52 + len(body)
    header = struct.pack(">16sHHIIIIIHHHHHH", b"\x7fELF" + bytes([1, 2 if big_endian else 1, 1]) + bytes(9), 2, 8, 1, 0, 0,
                         shoff, 0x70001001, 52, 0, 0, 40, len(sections), 2)
    return header + body + b"".join(struct.pack(">IIIIIIIIII", *s) for s in sections)


def read_elf_bytes(data):
    import pathlib
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "guest.elf")
        with open(path, "wb") as fh:
            fh.write(data)
        return m.D.read_elf(pathlib.Path(path))


GOOD = good_transcript()
HOST = host_log()
CLEAN_ELF = read_elf_bytes(minimal_elf(fp_abi=3))


def judge(text=GOOD, seed=SEED_A, host=HOST, elf=CLEAN_ELF):
    report = m.judge(text, elf, seed, host, VEC)
    return {g.gate_id: g for g in report["gates"]}, report


class SourceMirrorTest(unittest.TestCase):
    """The Python mirrors equal the Rust source text and the host test's pins, so the judge and the guest cannot drift."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SRC, "n03-target", "src", "cases.rs"), encoding="utf-8") as fh:
            cls.cases = fh.read()
        # The host test is held outside any cargo target until its first green central compile (tests/n03/pending/); once it
        # is committed at its final path, that path is read.
        candidates = [os.path.join(REPO, "crates", "franken-clock", "tests", "n03_target_worlds.rs"),
                      os.path.join(REPO, "tests", "n03", "pending", "n03_target_worlds.rs")]
        path = next(p for p in candidates if os.path.isfile(p))
        with open(path, encoding="utf-8") as fh:
            cls.host_test = fh.read()

    def test_sim_shapes_match_the_rust_source(self):
        block = re.search(r"pub const SIM_SHAPES: \[[^\]]*\] = \[(.*?)\];", self.cases, re.S).group(1)
        rows = re.findall(r"\(\s*(-?[0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+)\s*,?\)", block)
        parsed = tuple(tuple(int(x.replace("_", "")) for x in row) for row in rows)
        self.assertEqual(parsed, m.SIM_SHAPES)

    def test_seed_derivation_constant_matches_the_rust_source(self):
        found = re.search(r"sim_seed.*?0x([0-9A-Fa-f_]+) \| index", self.cases, re.S)
        self.assertIsNotNone(found)
        self.assertEqual(int(found.group(1).replace("_", ""), 16), 0x4E30335300000000)
        self.assertIn("run_seed ^", self.cases)
        self.assertIn(">> 32", self.cases)

    def test_the_host_tests_seed_pins_equal_the_judges_derivation(self):
        rows = re.findall(r"\(\s*(0x[0-9A-Fa-f_]+|[0-9_]+),\s*([01]),\s*([0-9_]+)\s*,?\s*\)", self.host_test.split("let known")[1].split("];")[0])
        self.assertEqual(len(rows), 6)
        for seed, index, expected in rows:
            seed, index, expected = int(seed.replace("_", ""), 0), int(index), int(expected.replace("_", ""))
            self.assertEqual(m.sim_seed(seed, index), expected, (seed, index))
        self.assertEqual(m.splitmix64(0), 0xE220A8397B1DCDAF)

    def test_the_host_tests_seeded_figure_pins_equal_the_mirror(self):
        body = self.host_test.split("let pins")[1].split("];")[0]
        rows = re.findall(r"\(\s*(0x[0-9A-Fa-f_]+|[0-9_]+),\s*([01]),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+),\s*([0-9_]+)\s*,?\s*\)", body)
        self.assertEqual(len(rows), 6)
        for row in rows:
            seed = int(row[0].replace("_", ""), 0)
            index = int(row[1])
            probes, lost, checks, max_err, max_unc, min_margin = (int(x.replace("_", "")) for x in row[2:])
            got = m.sim_counted(m.sim_seed(seed, index), *m.SIM_SHAPES[index])
            self.assertEqual((got["probes"], got["lost"], got["checks"], got["max_err"], got["max_unc"], got["min_margin"]),
                             (probes, lost, checks, max_err, max_unc, min_margin), (seed, index))
            self.assertEqual((got["rejected"], got["violations"], got["resets"], got["locked"]), (0, 0, 0, True))

    def test_the_counted_mirror_equals_the_reference_on_the_fixed_worlds(self):
        for seed, shape in ((2, m.SIM_SHAPES[0]), (4, m.SIM_SHAPES[1])):
            got, want = m.sim_counted(seed, *shape), m.ref.sim_run(seed, *shape)
            self.assertEqual((got["probes"], got["lost"], got["checks"], got["max_err"], got["max_unc"], got["min_margin"], got["locked"]),
                             (want["probes"], want["lost"], want["checks"], want["max_err_ns"], want["max_unc_ns"],
                              want["min_margin_ns"], want["locked"]), seed)

    def test_the_guests_regions_match_the_judges_ruler_range(self):
        with open(os.path.join(SRC, "n03-target", "src", "main.rs"), encoding="utf-8") as fh:
            main = fh.read()
        spin3 = [int(x.replace("_", "")) for x in re.search(r"SPIN3_ITERATIONS: \[u32; 4\] = \[(.*?)\]", main).group(1).split(",")]
        spin5 = [int(x.replace("_", "")) for x in re.search(r"SPIN5_ITERATIONS: \[u32; 4\] = \[(.*?)\]", main).group(1).split(",")]
        self.assertEqual(min(3 * n for n in spin3), m.RULER_LO_INSTR)
        self.assertEqual(max(max(3 * n for n in spin3), max(5 * n for n in spin5)), m.RULER_HI_INSTR)
        for name, value in (("WARM_EXCHANGES", WARM), ("EXCHANGES_PER_REP", EXCH), ("GATE_CALLS_PER_REP", GATE_CALLS), ("REPS", REPS)):
            found = re.search(rf"const {name}: usize = ([0-9_]+);", main)
            self.assertEqual(int(found.group(1).replace("_", "")), value, name)


class GoodTranscriptTest(unittest.TestCase):
    def test_a_good_transcript_passes_every_gate(self):
        gates, report = judge()
        self.assertEqual({g.status for g in gates.values()}, {"passed"}, {k: (g.status, g.detail) for k, g in gates.items()})
        self.assertTrue(report["ok"])
        self.assertEqual(m.exit_code(report), 0)
        self.assertEqual(set(gates), {"N03T-TRANSCRIPT", "N03T-ELF", "N03T-CPU", "N03T-WORLDS", "N03T-SEEDED", "N03T-HOST-BYTES"})
        self.assertEqual(report["worlds"]["worlds"], 34)

    def test_the_report_has_the_numbers_and_the_boundary_line(self):
        _, report = judge()
        text = m.render(report, "deadbeef")
        self.assertIn("exchange", text)
        self.assertIn("gate", text)
        self.assertIn("no board clock", text)
        self.assertIn("real DAC or acoustic", text)
        self.assertAlmostEqual(report["cpu"]["exchange"]["instructions_per_op"]["min"], EXCH_INSTR, delta=EXCH_INSTR * 0.001)
        self.assertAlmostEqual(report["cpu"]["gate"]["instructions_per_op"]["min"], GATE_INSTR, delta=GATE_INSTR * 0.01)

    def test_without_a_host_log_the_byte_comparison_is_blocked_not_passed(self):
        gates, report = judge(host=None)
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "blocked")
        self.assertEqual(m.exit_code(report), 3)

    def test_without_an_elf_the_soft_float_claim_is_blocked(self):
        gates, report = judge(elf=None)
        self.assertEqual(gates["N03T-ELF"].status, "blocked")
        self.assertEqual(m.exit_code(report), 3)


class PlantedNegativeTest(unittest.TestCase):
    def test_records_from_another_run_are_caught_by_the_seed(self):
        """N03T-PLANT-REPLAY: seed A's transcript judged as seed B's run. The worlds are fixed, so they and the host
        digests still pass: only the seeded worlds can tell."""
        gates, report = judge(GOOD, seed=SEED_B)
        self.assertEqual(gates["N03T-SEEDED"].status, "failed")
        self.assertIn("echoed seed", gates["N03T-SEEDED"].detail)
        self.assertEqual(gates["N03T-WORLDS"].status, "passed")
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "passed")
        self.assertEqual(m.exit_code(report), 1)

    def test_a_forged_seed_echo_does_not_save_replayed_records(self):
        """N03T-PLANT-FORGED-ECHO: the guest prints seed B, its seeded worlds are seed A's."""
        forged = GOOD.replace(f"FFW_N03T_SEED value={SEED_A}", f"FFW_N03T_SEED value={SEED_B}")
        gates, _ = judge(forged, seed=SEED_B)
        self.assertEqual(gates["N03T-SEEDED"].status, "failed")
        self.assertNotIn("echoed seed", gates["N03T-SEEDED"].detail)
        self.assertIn("the guest used run seed", gates["N03T-SEEDED"].detail)

    def test_forging_the_seeds_too_still_fails_on_the_figures(self):
        """N03T-PLANT-FORGED-SEEDS: echo, run seed and LCG seed all claim seed B; only the figures are A's."""
        forged = good_transcript(seed=SEED_B, sims_seed=SEED_A)
        for index in range(2):
            forged = forged.replace(f"run_seed={SEED_A} seed32={m.sim_seed(SEED_A, index)}",
                                    f"run_seed={SEED_B} seed32={m.sim_seed(SEED_B, index)}")
        gates, _ = judge(forged, seed=SEED_B)
        self.assertEqual(gates["N03T-SEEDED"].status, "failed")
        self.assertRegex(gates["N03T-SEEDED"].detail, r"figures differ from the reference's for this run's seed")

    def test_canned_worlds_without_the_seeded_worlds_are_caught(self):
        """N03T-PLANT-CANNED: the fixed worlds (judged and host-identical) and no seeded world at all."""
        lines = [ln for ln in GOOD.split("\n") if "FFW_N03T_SIM" not in ln]
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["N03T-SEEDED"].status, "failed")
        self.assertIn("no SIM line", gates["N03T-SEEDED"].detail)
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "passed")      # which is exactly why the seed exists

    def test_a_dump_cut_short_is_caught(self):
        for fraction in (0.1, 0.6, 0.97):
            with self.subTest(fraction=fraction):
                cut = m.truncate_dump(GOOD, fraction)
                self.assertNotIn("FFW_N03T_END", cut)
                gates, report = judge(cut)
                self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
                self.assertEqual(m.exit_code(report), 1)

    def test_lines_missing_from_a_world_with_a_complete_ending_are_caught(self):
        wid = "S01-SYMMETRIC"
        lines = GOOD.split("\n")
        idx = [i for i, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=" in ln]
        # a gap in the middle breaks the print order and is refused when the transcript is read
        gates, _ = judge("\n".join(ln for i, ln in enumerate(lines) if i != idx[len(idx) // 2]))
        self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
        self.assertIn(f"of {wid} is out of order", gates["N03T-TRANSCRIPT"].detail)
        # records missing at the tail leave a complete ending that claims more than was printed
        for label, drop in (("the last record", {idx[-1]}), ("eight at the tail", set(idx[-8:]))):
            with self.subTest(label):
                gates, _ = judge("\n".join(ln for i, ln in enumerate(lines) if i not in drop))
                self.assertEqual(gates["N03T-WORLDS"].status, "failed")
                self.assertRegex(gates["N03T-WORLDS"].detail, rf"{wid}: .*(truncated or has gaps|do not hash)")

    def test_a_short_dump_whose_digest_matches_what_was_printed_is_still_short(self):
        """The cleverest cut: fewer records than the world has ops, a matching digest, contiguous indices and a WEND line
        that claims all of them. Only the count against the world's ops can tell."""
        wid = "S04-DRIFT-FAST"
        block = list(world_block(wid))
        steps = block[:-1]
        keep = steps[:-5]
        encoded = [ln.split(" ", 3)[3] for ln in keep]
        end = re.sub(r"fnv=[0-9a-f]+", f"fnv={m.fnv1a64_lines(encoded):016x}", block[-1])
        lines = GOOD.split("\n")
        first = next(i for i, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=0 " in ln)
        last = next(i for i, ln in enumerate(lines) if ln.startswith(f"FFW_N03T_WEND id={wid} "))
        lines[first:last + 1] = keep + [end]
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["N03T-WORLDS"].status, "failed")
        self.assertIn("truncated or has gaps", gates["N03T-WORLDS"].detail)
        self.assertNotIn("do not hash", gates["N03T-WORLDS"].detail)

    def test_two_records_swapped_in_place_fail_the_digest_check(self):
        """N03T-PLANT-REORDER: the contents of two consecutive records of a world are swapped under their own indices, and
        every digest and count is left as printed."""
        wid = "S04-DRIFT-FAST"
        lines = GOOD.split("\n")
        first = next(i for i, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=10 " in ln)
        a, b = lines[first], lines[first + 1]
        lines[first] = a.split(" ", 3)[0] + " " + a.split(" ", 3)[1] + " " + a.split(" ", 3)[2] + " " + b.split(" ", 3)[3]
        lines[first + 1] = b.split(" ", 3)[0] + " " + b.split(" ", 3)[1] + " " + b.split(" ", 3)[2] + " " + a.split(" ", 3)[3]
        self.assertNotEqual(lines[first], a)
        gates, report = judge("\n".join(lines))
        self.assertEqual(gates["N03T-WORLDS"].status, "failed")
        self.assertIn(f"{wid}: the printed records do not hash to the WEND digest", gates["N03T-WORLDS"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_two_swapped_records_with_a_matching_digest_fail_against_the_reference(self):
        """The same reorder with the digest recomputed to agree: only the independent reference can tell."""
        wid = "S04-DRIFT-FAST"
        block = list(world_block(wid))
        steps = [ln.split(" ", 3)[3] for ln in block[:-1]]
        i = next(k for k in range(10, len(steps) - 1) if steps[k] != steps[k + 1])
        steps[i], steps[i + 1] = steps[i + 1], steps[i]
        rebuilt = [f"FFW_N03T_STEP id={wid} i={k} {enc}" for k, enc in enumerate(steps)]
        rebuilt.append(re.sub(r"fnv=[0-9a-f]+", f"fnv={m.fnv1a64_lines(steps):016x}", block[-1]))
        lines = GOOD.split("\n")
        first = next(k for k, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=0 " in ln)
        last = next(k for k, ln in enumerate(lines) if ln.startswith(f"FFW_N03T_WEND id={wid} "))
        lines[first:last + 1] = rebuilt
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["N03T-WORLDS"].status, "failed")
        self.assertRegex(gates["N03T-WORLDS"].detail, rf"{wid}: .*\(reported, not adjusted\)")
        self.assertNotIn("do not hash", gates["N03T-WORLDS"].detail)

    def test_record_lines_printed_out_of_order_are_refused(self):
        """N03T-PLANT-OUT-OF-ORDER: the lines themselves are reordered, indices kept. A transcript that is not in the order
        the guest printed it in is an anomaly, not a transcript."""
        wid = "S04-DRIFT-FAST"
        lines = GOOD.split("\n")
        first = next(i for i, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=10 " in ln)
        lines[first], lines[first + 1] = lines[first + 1], lines[first]
        gates, report = judge("\n".join(lines))
        self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
        self.assertIn("out of order", gates["N03T-TRANSCRIPT"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_one_changed_record_fails_the_digest_check(self):
        """N03T-PLANT-DIVERGENCE: a record differs and every digest and count is left as printed."""
        gates, report = judge(m.corrupt_one_step(GOOD))
        self.assertEqual(gates["N03T-WORLDS"].status, "failed")
        self.assertIn("do not hash to the WEND digest", gates["N03T-WORLDS"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_a_changed_record_with_a_matching_digest_fails_against_the_reference(self):
        """The same divergence with the digest recomputed to agree: only the independent reference can tell."""
        wid = "S01-SYMMETRIC"
        block = list(world_block(wid))
        target = next(i for i, ln in enumerate(block[:-1]) if '"status":"Locked"' in ln)
        block[target] = block[target].replace('"status":"Locked"', '"status":"Holdover"', 1)
        encoded = [ln.split(" ", 3)[3] for ln in block[:-1]]
        block[-1] = re.sub(r"fnv=[0-9a-f]+", f"fnv={m.fnv1a64_lines(encoded):016x}", block[-1])
        lines = GOOD.split("\n")
        first = next(i for i, ln in enumerate(lines) if f"FFW_N03T_STEP id={wid} i=0 " in ln)
        last = next(i for i, ln in enumerate(lines) if ln.startswith(f"FFW_N03T_WEND id={wid} "))
        lines[first:last + 1] = block
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["N03T-WORLDS"].status, "failed")
        self.assertRegex(gates["N03T-WORLDS"].detail, rf"{wid}: .*\(reported, not adjusted\)")
        self.assertNotIn("do not hash", gates["N03T-WORLDS"].detail)

    def test_a_world_the_host_disagrees_on_but_the_reference_agrees_on_is_a_finding(self):
        """The finding path: the guest equals the reference, the host digest differs. WORLDS passes, HOST-BYTES fails and
        says so."""
        rows = HOST.strip().split("\n")
        rec = json.loads(rows[3].split(" ", 1)[1])
        rec["fnv"] = "0" * 16
        rows[3] = "N03-TARGET-HOST " + json.dumps(rec)
        gates, report = judge(host="\n".join(rows) + "\n")
        self.assertEqual(gates["N03T-WORLDS"].status, "passed")
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "failed")
        self.assertIn(f"{rec['id']}: the target-ISA records DIFFER from the host build's", gates["N03T-HOST-BYTES"].detail)
        self.assertIn("finding about the target ISA", gates["N03T-HOST-BYTES"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_a_world_that_fails_its_checks_is_not_read_as_identical_to_the_host(self):
        """N03T-HOST-NOT-VACUOUS: the byte gate must say a rejected world was not compared."""
        gates, _ = judge(m.corrupt_one_step(GOOD))
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "failed")
        self.assertIn("not compared with the host build", gates["N03T-HOST-BYTES"].detail)

    def test_a_host_log_missing_a_world_does_not_pass(self):
        partial = "\n".join(HOST.strip().split("\n")[:-1]) + "\n"
        gates, _ = judge(host=partial)
        self.assertEqual(gates["N03T-HOST-BYTES"].status, "failed")
        self.assertIn("no host-build record", gates["N03T-HOST-BYTES"].detail)

    def test_two_different_host_records_for_one_world_are_refused(self):
        rec = json.loads(HOST.strip().split("\n")[0].split(" ", 1)[1])
        with self.assertRaises(m.MeasurementError):
            m.parse_host_log(HOST + "N03-TARGET-HOST " + json.dumps(dict(rec, fnv="f" * 16)) + "\n")

    def test_the_replay_helper_extracts_only_the_world_and_seeded_lines(self):
        replay = m.replay_lines_of(GOOD)
        self.assertTrue(all(re.search(r"FFW_N03T_(STEP|WEND|SIM)", ln) for ln in replay.strip().split("\n")))
        self.assertNotIn("FFW_N03T_RUN", replay)
        self.assertNotIn("FFW_N03T_SEED", replay)


class CpuGateTest(unittest.TestCase):
    def cpu(self, text):
        gates, report = judge(text)
        return gates["N03T-CPU"], report

    def mutate(self, old, new):
        self.assertIn(old, GOOD)
        return GOOD.replace(old, new, 1)

    def test_ruler_drift_between_before_and_after_fails_the_whole_cpu_result(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(r"(FFW_N03T_RULER phase=B shape=\d iterations=\d+ ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{int(int(found.group(2)) * 1.02)}" if found else ln)
        gate, report = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("drifted", gate.detail)
        self.assertIn("NO CPU HEADLINE NUMBER", m.render(report, None))

    def test_a_ruler_whose_two_shapes_disagree_fails(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(r"(FFW_N03T_RULER phase=\w shape=5 iterations=\d+ ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{int(int(found.group(2)) * 1.05)}" if found else ln)
        gate, _ = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("disagree", gate.detail)

    def test_no_stable_floor_fails(self):
        base = ticks(EXCH_INSTR * EXCH)
        text = GOOD
        for rep, jitter in enumerate(JITTER):
            text = text.replace(f"region=exchange rep={rep} ops={EXCH} done={EXCH} ticks={base + jitter}",
                                f"region=exchange rep={rep} ops={EXCH} done={EXCH} ticks={base + (0 if rep == 0 else 60_000 * rep)}")
        gate, _ = self.cpu(text)
        self.assertEqual(gate.status, "failed")
        self.assertIn("no stable floor", gate.detail)

    def test_a_repetition_that_did_not_complete_every_operation_fails(self):
        gate, _ = self.cpu(self.mutate(f"region=gate rep=2 ops={GATE_CALLS} done={GATE_CALLS}", f"region=gate rep=2 ops={GATE_CALLS} done=1999"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("did not complete every operation", gate.detail)

    def test_a_clock_that_refused_exchanges_fails(self):
        gate, _ = self.cpu(self.mutate(f"FFW_N03T_STATS accepted={WARM + REPS * EXCH}", f"FFW_N03T_STATS accepted={WARM + REPS * EXCH - 3}"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("accepted", gate.detail)

    def test_a_reset_during_the_regions_fails(self):
        gate, _ = self.cpu(self.mutate("probes_sent=600 resets=0", "probes_sent=600 resets=1"))
        self.assertEqual(gate.status, "failed")

    def test_an_unlocked_clock_before_the_gate_region_fails(self):
        gate, _ = self.cpu(self.mutate(f"region=gate calls={GATE_CALLS} mapped=1", f"region=gate calls={GATE_CALLS} mapped=0"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("not locked", gate.detail)

    def test_a_warm_up_that_refused_exchanges_fails(self):
        gate, _ = self.cpu(self.mutate(f"exchanges={WARM} accepted={WARM}", f"exchanges={WARM} accepted={WARM - 1}"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("warm-up", gate.detail)

    def test_a_region_outside_the_rulers_calibrated_range_fails(self):
        """The ruler spans 3.9 to 60 M instructions; a region far below it would be an extrapolation."""
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(rf"(FFW_N03T_RUN region=gate rep=\d+ ops={GATE_CALLS} done={GATE_CALLS} ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{ticks(300 * GATE_CALLS)}" if found else ln)
        gate, _ = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("extrapolated", gate.detail)

    def test_an_implausibly_cheap_operation_fails(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(rf"(FFW_N03T_RUN region=exchange rep=\d+ ops={EXCH} done={EXCH} ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{ticks(100 * EXCH)}" if found else ln)
        gate, _ = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("the region or the ruler is wrong", gate.detail)

    def test_a_missing_region_fails(self):
        gate, _ = self.cpu("\n".join(ln for ln in GOOD.split("\n") if "region=gate rep" not in ln))
        self.assertEqual(gate.status, "failed")
        self.assertIn("gate has repetitions", gate.detail)


class TranscriptAndElfTest(unittest.TestCase):
    def test_a_host_build_transcript_is_refused(self):
        gates, report = judge("FFW_N03T_HOST_BUILD counts are meaningless off the MIPS target\n")
        self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
        self.assertEqual(m.exit_code(report), 1)

    def test_a_malformed_marker_line_is_an_error_not_a_guess(self):
        gates, _ = judge(GOOD.replace("FFW_N03T_SEED value=", "FFW_N03T_SEED valu=", 1))
        self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
        self.assertIn("malformed", gates["N03T-TRANSCRIPT"].detail)
        gates, _ = judge(GOOD.replace("FFW_N03T_ALIVE", "FFW_N03T_ALIVE\nFFW_N03T_MYSTERY x=1", 1))
        self.assertIn("unknown marker", gates["N03T-TRANSCRIPT"].detail)

    def test_a_record_or_world_that_appears_twice_is_refused(self):
        first = next(ln for ln in GOOD.split("\n") if "FFW_N03T_STEP id=S01-SYMMETRIC i=0 " in ln)
        gates, _ = judge(GOOD + first + "\n")
        self.assertEqual(gates["N03T-TRANSCRIPT"].status, "failed")
        self.assertIn("appears twice", gates["N03T-TRANSCRIPT"].detail)

    def test_an_elf_with_fpu_opcodes_does_not_prove_soft_float(self):
        lwc1 = (0x31 << 26) | 0x1234
        gates, report = judge(elf=read_elf_bytes(minimal_elf(words=(0x24020001, lwc1, 0x03E00008), fp_abi=3)))
        self.assertEqual(gates["N03T-ELF"].status, "failed")
        self.assertIn("soft-float is NOT proven", gates["N03T-ELF"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_an_elf_marked_hard_float_fails(self):
        gates, _ = judge(elf=read_elf_bytes(minimal_elf(fp_abi=1)))
        self.assertEqual(gates["N03T-ELF"].status, "failed")
        self.assertIn("not 3 (soft)", gates["N03T-ELF"].detail)

    def test_the_central_build_command_is_the_d03_one_for_this_crate(self):
        import pathlib
        text = m.central_commands(pathlib.Path("/snap"), "label")
        for needle in ("RCH_REQUIRE_REMOTE=1", "rch exec --", "cargo +nightly build --offline --release",
                       "--manifest-path toolchain/src/n03-target/Cargo.toml", "--target mips-unknown-linux-musl",
                       "-Z build-std=core,alloc,std,panic_abort", "-j 2", "zig-cc-mips-be", "crt-static",
                       "/snap/build/n03-target-target/mips-unknown-linux-musl/release/ffw-n03-target"):
            self.assertIn(needle, text)

    def test_the_guest_crate_is_its_own_workspace_with_two_dependencies(self):
        with open(os.path.join(SRC, "n03-target", "Cargo.toml"), encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("\n[workspace]\n", manifest)
        deps = manifest.split("[dependencies]")[1].split("[profile.release]")[0]
        self.assertEqual(sorted(re.findall(r"^([a-z0-9_-]+) = ", deps, re.M)), ["franken-clock", "serde_json"])
        self.assertIn('opt-level = "z"', manifest)


if __name__ == "__main__":
    unittest.main()
