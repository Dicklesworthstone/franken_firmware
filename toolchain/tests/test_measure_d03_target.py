#!/usr/bin/env python3
"""Self-test of the D03 target-ISA judge (toolchain/src/measure-d03-target.py). SYNTHETIC: the transcripts here are
fabricated from the double-precision reference to prove the judge qualifies a good transcript and catches each kind of
bad one, including the planted negatives the task demands: a replayed or copied sample dump (tied to a per-run seed so
the replay is detectable) and a truncated dump. They say nothing about the Rust or the MIPS guest, neither of which has
been built or run.

    python3 -B -I -m unittest discover -s toolchain/tests -p 'test_measure_d03_target.py'
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


m = _load(os.path.join(SRC, "measure-d03-target.py"), "measure_d03_target_under_test")
with open(os.path.join(REPO, "tests", "d03", "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

# The reference interpolations take seconds; every test shares one cached copy of each. The judge looks the names up
# in the module at call time, so patching the module is enough.
_orig_canonical, _orig_seeded = m.reference_canonical, m.reference_seeded


@functools.lru_cache(maxsize=None)
def _cached_canonical(hz, ppb, n):
    return tuple(_orig_canonical(hz, ppb, n))


@functools.lru_cache(maxsize=None)
def _cached_seeded(hz, seed, n):
    phase, y = _orig_seeded(hz, seed, n)
    return phase, tuple(y)


_orig_fit = m.fit_window


@functools.lru_cache(maxsize=None)
def _cached_fit(samples, hz, ppb, skip, n_meas):
    return _orig_fit(list(samples), hz, ppb, skip, n_meas)


_orig_fnv, _orig_chunks = m.fnv1a64, m.chunk_digests
_cached_fnv = functools.lru_cache(maxsize=None)(_orig_fnv)


@functools.lru_cache(maxsize=None)
def _cached_chunks(samples):
    return _orig_chunks(list(samples))


m.reference_canonical, m.reference_seeded = _cached_canonical, _cached_seeded
m.fnv1a64 = _cached_fnv
m.chunk_digests = lambda samples: _cached_chunks(tuple(samples))
m.fit_window = lambda samples, hz, ppb, skip, n_meas: _cached_fit(tuple(samples), hz, ppb, skip, n_meas)

SEED_A, SEED_B = 4_611_686_018_427_387_903, 123_456_789_012_345
IPT, INTERCEPT = 5.0, 40            # synthetic ruler: 5 instructions per tick, 40 ticks of read overhead
FRAMES = 2048
N_OUT = VEC["quality"]["cases"][0]["n_out"]
SEEDED_FRAMES = 4096
INSTR_PER_FRAME = {"nominal/noise": 1500, "nominal/silence": 900, "fast500/noise": 1510, "fast500/silence": 905,
                   "slow500/noise": 1490, "slow500/silence": 895, "slewing/noise": 1505}
JITTER = (0, 30, 10, 60, 5)         # extra ticks per repetition: strays only ever add


def ticks(instructions):
    return int(round(INTERCEPT + instructions / IPT))


def dump(tag, cid, extra, samples):
    lines = [f"FFW_D03T_{tag}BEGIN id={cid} frames={len(samples)} {extra}"]
    words = [struct.pack(">f", s).hex() for s in samples]
    for i in range(0, len(words), m.SAMPLES_PER_LINE):
        lines.append(f"FFW_D03T_{tag}DATA id={cid} off={i} {''.join(words[i:i + m.SAMPLES_PER_LINE])}")
    raw = b"".join(struct.pack(">f", s) for s in samples)
    lines.append(f"FFW_D03T_{tag}END id={cid} frames={len(samples)} fnv={m.fnv1a64(raw):016x} "
                 f"chunks={','.join(m.chunk_digests(list(samples)))}")
    return lines


def ramped(values):
    return [m._f32(v * (min(i, 64) / 64.0)) for i, v in enumerate(values)]


def canonical_samples(hz, ppb, kind="catmull_rom"):
    if kind == "catmull_rom":
        return ramped(m.reference_canonical(hz, ppb, N_OUT))
    x = m.rotation_input(hz, m.START_S, m.START_C, N_OUT + m.INPUT_MARGIN)
    return ramped(m.ref.interpolate(kind, x, m.ref.quality_positions(N_OUT, ppb)))


def seeded_samples(hz, seed):
    _phase, y = m.reference_seeded(hz, seed, SEEDED_FRAMES)
    return [m._f32(v) for v in y]


def ruler_lines():
    out = []
    for phase in "AB":
        for _ in range(2):
            for n in (1_300_000, 5_000_000, 12_000_000, 20_000_000):
                out.append(f"FFW_D03T_RULER phase={phase} shape=3 iterations={n} ticks={ticks(3 * n)}")
            for n in (800_000, 3_000_000, 7_200_000, 12_000_000):
                out.append(f"FFW_D03T_RULER phase={phase} shape=5 iterations={n} ticks={ticks(5 * n)}")
    return out


def cpu_lines():
    out = []
    ratios = {"nominal": 0, "fast500": 500_000, "slow500": -500_000}
    for key, ipf in INSTR_PER_FRAME.items():
        name, kind = key.split("/")
        if name == "slewing":
            out.append(f"FFW_D03T_WARM name={name} input={kind} ramp_left=0 ratio_ppb=12000 target_ppb=500000")
        else:
            out.append(f"FFW_D03T_WARM name={name} input={kind} ramp_left=0 ratio_ppb={ratios[name]} target_ppb={ratios[name]}")
        for rep, jitter in enumerate(JITTER):
            ratio = 28_000 + 8_000 * rep if name == "slewing" else ratios[name]
            peak = "0.000000" if kind == "silence" else "0.249300"
            out.append(f"FFW_D03T_RUN name={name} input={kind} rep={rep} frames={FRAMES} "
                       f"ticks={ticks(ipf * FRAMES) + jitter} peak={peak} ratio_ppb={ratio}")
    return out


def good_transcript(seed=SEED_A, canonical_kind="catmull_rom", kind_by_hz=None):
    lines = ["FFW_D03T_ALIVE",
             f"FFW_D03T_BEGIN version=1 block_frames=256 blocks_per_rep=8 reps=5 warmup_blocks=6 ruler_reps=2 skip=192 "
             f"n_meas=32768 seeded_frames={SEEDED_FRAMES}",
             f"FFW_D03T_SEED value={seed}", "FFW_D03T_EMPTY ticks=[3, 3, 3, 3, 3, 3, 3, 3]"]
    lines += ruler_lines()[:16] + cpu_lines() + ruler_lines()[16:]
    for cid, hz, ppb in m.CANONICAL:
        kind = (kind_by_hz or {}).get(hz, canonical_kind)
        lines += dump("Q", cid, f"hz={hz} ppb={ppb}", canonical_samples(hz, ppb, kind))
    for cid, hz in m.SEEDED:
        lines += dump("S", cid, f"hz={hz} ppb={m.SEEDED_PPB} phase_bits={m.f64_bits(m.seeded_phase(seed, hz)):016x}",
                      seeded_samples(hz, seed))
    lines.append("FFW_D03T_END")
    return "\n".join(["Linux version 4.19.0 (kernel chatter is ignored)"] + lines) + "\n"


def host_log(text):
    """What the host build prints for the canonical cases: here, the digests of the same fabricated samples."""
    t = m.parse_transcript(text)
    out = []
    for cid, hz, ppb in m.CANONICAL:
        case = t["cases"][("Q", cid)]
        samples, _ = m.decode_case(case)
        out.append("D03-TARGET-HOST " + json.dumps({"id": cid, "hz": hz, "ppb": ppb, "frames": len(samples),
                                                    "fnv": f"{case['end']['fnv']:016x}",
                                                    "chunks": ",".join(m.chunk_digests(samples)), "head": ""}))
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
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "guest.elf")
        with open(path, "wb") as fh:
            fh.write(data)
        import pathlib
        return m.read_elf(pathlib.Path(path))


GOOD = good_transcript()
HOST = host_log(GOOD)
CLEAN_ELF = read_elf_bytes(minimal_elf(fp_abi=3))


def judge(text=GOOD, seed=SEED_A, host=HOST, elf=CLEAN_ELF):
    report = m.judge(text, elf, seed, host, VEC)
    return {g.gate_id: g for g in report["gates"]}, report


class SourceMirrorTest(unittest.TestCase):
    """The Python mirrors equal the Rust source text, so the judge and the guest cannot drift apart unnoticed."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SRC, "d03-target", "src", "cases.rs"), encoding="utf-8") as fh:
            cls.cases = fh.read()
        with open(os.path.join(REPO, "crates", "franken-dsp", "tests", "d03_target_samples.rs"), encoding="utf-8") as fh:
            cls.host_test = fh.read()

    def const(self, name):
        found = re.search(rf"pub const {name}: [a-z0-9]+ = ([-0-9_.]+);", self.cases)
        self.assertIsNotNone(found, name)
        text = found.group(1).replace("_", "")
        return float(text) if "." in text else int(text)

    def tone(self, name):
        found = re.search(rf"pub const {name}: Tone = Tone \{{\s*hz: ([0-9_]+),\s*cos_w: ([0-9_.]+),\s*sin_w: ([0-9_.]+),\s*\}};",
                          self.cases)
        self.assertIsNotNone(found, name)
        return int(found.group(1).replace("_", "")), float(found.group(2).replace("_", "")), float(found.group(3).replace("_", ""))

    def test_constants_match_the_rust_source(self):
        self.assertEqual(self.const("AMP"), m.ref.QUALITY_AMP)
        self.assertEqual(self.const("START_S"), m.START_S)
        self.assertEqual(self.const("START_C"), m.START_C)
        self.assertEqual(m.START_S, m.ref.QUALITY_AMP * m.math.sin(0.25))
        self.assertEqual(m.START_C, m.ref.QUALITY_AMP * m.math.cos(0.25))
        self.assertEqual(self.const("SKIP"), VEC["quality"]["skip"])
        self.assertEqual(self.const("N_MEAS"), VEC["quality"]["n_meas"])
        self.assertEqual(self.const("SKIP") + self.const("N_MEAS"), N_OUT)   # N_OUT = SKIP + N_MEAS in the source
        self.assertIn("pub const N_OUT: usize = SKIP + N_MEAS;", self.cases)
        self.assertEqual(self.const("SEEDED_FRAMES"), SEEDED_FRAMES)
        self.assertEqual(self.const("SEEDED_PPB"), m.SEEDED_PPB)
        self.assertEqual(self.const("CHUNK"), m.CHUNK)
        self.assertEqual(self.const("SAMPLES_PER_LINE"), m.SAMPLES_PER_LINE)
        self.assertEqual(self.const("INPUT_MARGIN"), m.INPUT_MARGIN)

    def test_tone_rotation_constants_match_the_rust_source_and_the_angle(self):
        for name, hz in (("TONE_1K", 1000), ("TONE_10K", 10_000)):
            rust_hz, cos_w, sin_w = self.tone(name)
            w = 2 * m.math.pi * hz / 48_000
            self.assertEqual(rust_hz, hz)
            self.assertEqual(cos_w, m.COS_W[hz])
            self.assertEqual(sin_w, m.SIN_W[hz])
            self.assertEqual(cos_w, m.math.cos(w))
            self.assertEqual(sin_w, m.math.sin(w))

    def test_canonical_table_matches_the_rust_source_and_the_vectors(self):
        rust = re.findall(r'id: "([^"]+)",\s*tone: (TONE_\w+),\s*ppb: (-?[0-9_]+),', self.cases)
        hz = {"TONE_1K": 1000, "TONE_10K": 10_000}
        self.assertEqual([(i, hz[t], int(p.replace("_", ""))) for i, t, p in rust], list(m.CANONICAL))
        by_id = {c["id"]: c for c in VEC["quality"]["cases"]}
        for cid, tone_hz, ppb in m.CANONICAL:
            self.assertEqual((by_id[cid]["f0_hz"], by_id[cid]["ppb"]), (tone_hz, ppb))
            self.assertTrue(by_id[cid]["must_pass"])
        seeded = re.findall(r'\("(seed-[0-9]+)", (TONE_\w+)\)', self.cases)
        self.assertEqual([(i, hz[t]) for i, t in seeded], list(m.SEEDED))

    def test_splitmix_known_answers_agree_with_the_host_test(self):
        rows = re.findall(r"\(\s*(0x[0-9A-Fa-f_]+|[0-9_]+),\s*([0-9_]+),\s*(0x[0-9A-Fa-f_]+),?\s*\)", self.host_test)
        self.assertEqual(len(rows), 6)
        for seed, hz, expected in rows:
            seed, hz, expected = (int(x.replace("_", ""), 0) for x in (seed, hz, expected))
            self.assertEqual(m.splitmix64(seed ^ hz), expected, (seed, hz))
        self.assertEqual(m.splitmix64(0), 0xE220A8397B1DCDAF)
        self.assertEqual(m.splitmix64(0), 16294208416658607535)   # SplitMix64's published first output for state 0

    def test_phase_is_a_pure_function_of_seed_and_tone(self):
        self.assertNotEqual(m.seeded_phase(1, 1000), m.seeded_phase(2, 1000))
        self.assertNotEqual(m.seeded_phase(1, 1000), m.seeded_phase(1, 10_000))
        self.assertTrue(all(0.0 <= m.seeded_phase(s, 1000) < 2 * m.math.pi for s in range(200)))


class GoodTranscriptTest(unittest.TestCase):
    def test_a_good_transcript_passes_every_gate(self):
        gates, report = judge()
        self.assertEqual({g.status for g in gates.values()}, {"passed"}, {k: (g.status, g.detail) for k, g in gates.items()})
        self.assertTrue(report["ok"])
        self.assertEqual(m.exit_code(report), 0)
        self.assertEqual(set(gates), {"D03T-TRANSCRIPT", "D03T-ELF", "D03T-CPU", "D03T-QUALITY", "D03T-SEEDED", "D03T-HOST-BYTES"})

    def test_the_report_has_the_numbers_and_the_boundary_line(self):
        _, report = judge()
        text = m.render(report, "deadbeef")
        self.assertIn("nominal/noise", text)
        self.assertIn("instructions executed".lower(), text.lower())
        self.assertIn("no board clock", text)
        self.assertIn("real DAC", text)
        for cid, *_ in m.CANONICAL:
            self.assertIn(cid, text)
        self.assertAlmostEqual(report["cpu"]["nominal/noise"]["instructions_per_frame"]["min"], 1500, delta=2)
        self.assertAlmostEqual(report["ruler"]["instructions_per_tick"], IPT, delta=0.01)

    def test_without_a_host_log_the_byte_comparison_is_blocked_not_passed(self):
        gates, report = judge(host=None)
        self.assertEqual(gates["D03T-HOST-BYTES"].status, "blocked")
        self.assertEqual(m.exit_code(report), 3)
        self.assertFalse(report["ok"])

    def test_without_an_elf_the_soft_float_claim_is_blocked(self):
        gates, report = judge(elf=None)
        self.assertEqual(gates["D03T-ELF"].status, "blocked")
        self.assertEqual(m.exit_code(report), 3)


class PlantedNegativeTest(unittest.TestCase):
    """The negatives the task demands. Each must FAIL the judge, and the gate that catches it is named."""

    def test_a_transcript_from_another_run_is_caught_by_the_seed(self):
        """D03T-PLANT-REPLAY: seed A's transcript, judged as seed B's run."""
        gates, report = judge(GOOD, seed=SEED_B)
        self.assertEqual(gates["D03T-SEEDED"].status, "failed")
        self.assertIn("echoed seed", gates["D03T-SEEDED"].detail)
        self.assertEqual(m.exit_code(report), 1)
        # the canonical dump of a replayed run is legitimate, so those gates still pass: only the seed tells
        self.assertEqual(gates["D03T-QUALITY"].status, "passed")
        self.assertEqual(gates["D03T-HOST-BYTES"].status, "passed")

    def test_a_forged_seed_echo_does_not_save_replayed_samples(self):
        """D03T-PLANT-FORGED-ECHO: the guest prints seed B but its samples are seed A's."""
        forged = GOOD.replace(f"FFW_D03T_SEED value={SEED_A}", f"FFW_D03T_SEED value={SEED_B}")
        gates, _ = judge(forged, seed=SEED_B)
        self.assertEqual(gates["D03T-SEEDED"].status, "failed")
        self.assertNotIn("echoed seed", gates["D03T-SEEDED"].detail)
        self.assertIn("not computed from this run's seed", gates["D03T-SEEDED"].detail)

    def test_forging_both_the_echo_and_the_phase_still_fails_on_the_samples(self):
        """D03T-PLANT-FORGED-PHASE: seed and phase both claim seed B; only the samples are A's."""
        forged = GOOD.replace(f"FFW_D03T_SEED value={SEED_A}", f"FFW_D03T_SEED value={SEED_B}")
        for _cid, hz in m.SEEDED:
            old, new = f"{m.f64_bits(m.seeded_phase(SEED_A, hz)):016x}", f"{m.f64_bits(m.seeded_phase(SEED_B, hz)):016x}"
            self.assertIn(old, forged)
            forged = forged.replace(old, new)
        gates, _ = judge(forged, seed=SEED_B)
        self.assertEqual(gates["D03T-SEEDED"].status, "failed")
        self.assertRegex(gates["D03T-SEEDED"].detail, r"seed-1000: sample \d+ is .* from the reference for this run's seed")

    def test_a_wrong_phase_echo_alone_is_caught(self):
        """D03T-PLANT-PHASE-ONLY: the samples are right for seed B, the phase echoed is seed A's: only the echo is wrong."""
        text = good_transcript(seed=SEED_B)
        for _cid, hz in m.SEEDED:
            old, new = f"{m.f64_bits(m.seeded_phase(SEED_B, hz)):016x}", f"{m.f64_bits(m.seeded_phase(SEED_A, hz)):016x}"
            self.assertIn(old, text)
            text = text.replace(old, new)
        gates, _ = judge(text, seed=SEED_B)
        self.assertEqual(gates["D03T-SEEDED"].status, "failed")
        self.assertIn("is not the one this run's seed derives", gates["D03T-SEEDED"].detail)
        self.assertNotIn("from the reference for this run's seed", gates["D03T-SEEDED"].detail)

    def test_host_samples_without_the_seeded_section_are_caught(self):
        """D03T-PLANT-HOST-ONLY: a guest that emits the canonical (host-identical) samples and nothing seeded."""
        lines = [ln for ln in GOOD.split("\n") if "FFW_D03T_S" not in ln or "FFW_D03T_SEED" in ln]
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["D03T-SEEDED"].status, "failed")
        self.assertIn("no seeded dump", gates["D03T-SEEDED"].detail)
        self.assertEqual(gates["D03T-HOST-BYTES"].status, "passed")   # which is exactly why the seed exists

    def test_a_dump_cut_short_is_caught(self):
        """D03T-PLANT-TRUNCATED: the transcript ends partway through the sample dump."""
        for fraction in (0.1, 0.6, 0.97):
            with self.subTest(fraction=fraction):
                cut = m.truncate_dump(GOOD, fraction)
                self.assertNotIn("FFW_D03T_END", cut)
                gates, report = judge(cut)
                self.assertEqual(gates["D03T-TRANSCRIPT"].status, "failed")
                self.assertEqual(m.exit_code(report), 1)

    def test_a_dump_with_lines_missing_but_a_complete_ending_is_caught(self):
        """The cleverer truncation: END is present, data lines are gone. Gap, count and digest checks each fire."""
        data = [i for i, ln in enumerate(GOOD.split("\n")) if "FFW_D03T_QDATA id=q-steady-1000-p500" in ln]
        lines = GOOD.split("\n")
        for label, drop in (("middle line", data[len(data) // 2]), ("last line", data[-1])):
            with self.subTest(label):
                cut = "\n".join(ln for i, ln in enumerate(lines) if i != drop)
                gates, _ = judge(cut)
                self.assertEqual(gates["D03T-QUALITY"].status, "failed")
                self.assertRegex(gates["D03T-QUALITY"].detail, r"gap|truncated")
        tail_gone = "\n".join(ln for i, ln in enumerate(lines) if i not in data[-8:])
        gates, _ = judge(tail_gone)
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertIn("truncated", gates["D03T-QUALITY"].detail)

    def test_a_short_dump_whose_digest_matches_what_was_printed_is_still_short(self):
        """The cleverest truncation: the guest prints fewer samples than it promised, with a matching digest, a
        contiguous offset run and an END line. Only the promised-versus-printed count can tell."""
        cid = "q-steady-10000-p500"
        t = m.parse_transcript(GOOD)
        samples, _ = m.decode_case(t["cases"][("Q", cid)])
        short = list(samples[:-64])
        lines = GOOD.split("\n")
        start = next(i for i, ln in enumerate(lines) if f"FFW_D03T_QBEGIN id={cid}" in ln)
        stop = next(i for i, ln in enumerate(lines) if f"FFW_D03T_QEND id={cid}" in ln)
        rebuilt = dump("Q", cid, "hz=10000 ppb=500000", short)
        rebuilt[0] = rebuilt[0].replace(f"frames={len(short)}", f"frames={len(samples)}")                   # the promise
        rebuilt[-1] = rebuilt[-1].replace(f"frames={len(short)}", f"frames={len(samples)}")                  # the END claim
        lines[start:stop + 1] = rebuilt
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertIn("the dump is truncated", gates["D03T-QUALITY"].detail)
        self.assertNotIn("does not hash", gates["D03T-QUALITY"].detail)
        self.assertNotIn("a gap", gates["D03T-QUALITY"].detail)

    def test_a_corrupted_sample_fails_the_digest_check(self):
        lines = GOOD.split("\n")
        i = next(k for k, ln in enumerate(lines) if "FFW_D03T_QDATA id=q-steady-10000-m500 off=640 " in ln)
        head, words = lines[i].rsplit(" ", 1)
        other = "00000000" if words[:8] != "00000000" else "00000001"
        lines[i] = f"{head} {other}{words[8:]}"
        gates, _ = judge("\n".join(lines))
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertIn("does not hash to the END digest", gates["D03T-QUALITY"].detail)

    def test_the_real_replay_helper_extracts_only_the_quality_lines(self):
        replay = m.quality_lines_of(GOOD)
        self.assertTrue(all(re.search(r"FFW_D03T_[QS](BEGIN|DATA|END)", ln) for ln in replay.strip().split("\n")))
        self.assertNotIn("FFW_D03T_RUN", replay)
        self.assertNotIn("FFW_D03T_SEED", replay)


class QualityBandTest(unittest.TestCase):
    def test_a_linear_interpolator_on_the_target_misses_the_declared_bands_and_is_reported_not_moved(self):
        text = good_transcript(canonical_kind="linear")
        gates, report = judge(text, host=host_log(text))
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertIn("MISSED", gates["D03T-QUALITY"].detail)
        self.assertIn("(reported, not moved)", gates["D03T-QUALITY"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_linear_interpolation_at_10_khz_is_rejected_by_the_gain_band_not_the_q_floor(self):
        """The erratum, on the target: the 10 kHz linear plant clears the Q floor by ~0.3 dB; only gain rejects it."""
        text = good_transcript(kind_by_hz={10_000: "linear"})
        gates, _ = judge(text, host=host_log(text))
        detail = gates["D03T-QUALITY"].detail
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertIn("MISSED the declared gain band", detail)
        self.assertNotIn("MISSED the declared Q band", detail)
        self.assertNotIn("q-steady-1000-", detail)   # the 1 kHz cases are untouched

    def test_a_nearest_neighbour_interpolator_misses_by_a_wide_margin(self):
        text = good_transcript(canonical_kind="nearest")
        gates, _ = judge(text, host=host_log(text))
        self.assertEqual(gates["D03T-QUALITY"].status, "failed")
        self.assertRegex(gates["D03T-QUALITY"].detail, r"MISSED the declared Q band")

    def test_the_bands_come_from_the_vectors_not_from_the_transcript(self):
        gates, _ = judge()
        for cid, row in m.quality_analysis(m.parse_transcript(GOOD), VEC, None)["rows"].items():
            band = VEC["quality"]["bands"][str(row["hz"])]
            self.assertEqual((row["band_q_db"], row["gain_lo_db"], row["gain_hi_db"]),
                             (band["q_floor_db"], band["gain_lo_db"], band["gain_hi_db"]))
            self.assertGreaterEqual(row["q_db"], row["band_q_db"])


class HostByteComparisonTest(unittest.TestCase):
    def test_one_flipped_bit_on_the_target_is_a_finding_localised_to_its_chunk(self):
        """The guest's own digests are consistent with its data, but one sample differs from the host build's by one
        ulp: the quality gate still passes (Q is unaffected) and the byte comparison FAILS, naming the chunk."""
        t = m.parse_transcript(GOOD)
        samples, _ = m.decode_case(t["cases"][("Q", "q-steady-1000-p500")])
        samples = list(samples)
        samples[5000] = struct.unpack(">f", struct.pack(">I", struct.unpack(">I", struct.pack(">f", samples[5000]))[0] ^ 1))[0]
        lines = GOOD.split("\n")
        start = next(i for i, ln in enumerate(lines) if "FFW_D03T_QBEGIN id=q-steady-1000-p500" in ln)
        stop = next(i for i, ln in enumerate(lines) if "FFW_D03T_QEND id=q-steady-1000-p500" in ln)
        lines[start:stop + 1] = dump("Q", "q-steady-1000-p500", "hz=1000 ppb=500000", samples)
        gates, report = judge("\n".join(lines))
        self.assertEqual(gates["D03T-QUALITY"].status, "passed", gates["D03T-QUALITY"].detail)
        self.assertEqual(gates["D03T-HOST-BYTES"].status, "failed")
        self.assertIn("first differing chunk 4 (samples 4096..5119)", gates["D03T-HOST-BYTES"].detail)
        self.assertIn("finding about the target ISA", gates["D03T-HOST-BYTES"].detail)
        self.assertEqual(m.exit_code(report), 1)
        self.assertEqual(report["quality"]["q-steady-1000-p500"]["host"], "DIFFERS")

    def test_a_host_log_that_misses_a_case_does_not_pass(self):
        partial = "\n".join(HOST.strip().split("\n")[:-1]) + "\n"
        gates, _ = judge(host=partial)
        self.assertEqual(gates["D03T-HOST-BYTES"].status, "failed")
        self.assertIn("no host-build record", gates["D03T-HOST-BYTES"].detail)

    def test_two_different_host_records_for_one_case_are_refused(self):
        rec = json.loads(HOST.strip().split("\n")[0].split(" ", 1)[1])
        rec2 = dict(rec, fnv="0" * 16)
        bad = HOST + "D03-TARGET-HOST " + json.dumps(rec2) + "\n"
        with self.assertRaises(m.MeasurementError):
            m.parse_host_log(bad)


class CpuGateTest(unittest.TestCase):
    def mutate(self, old, new, count=1):
        self.assertIn(old, GOOD)
        return GOOD.replace(old, new, count)

    def cpu(self, text):
        gates, report = judge(text)
        return gates["D03T-CPU"], report

    def test_ruler_drift_between_before_and_after_fails_the_whole_cpu_result(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(r"(FFW_D03T_RULER phase=B shape=\d iterations=\d+ ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{int(int(found.group(2)) * 1.02)}" if found else ln)
        gate, report = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("drifted", gate.detail)
        self.assertIn("NO CPU HEADLINE NUMBER", m.render(report, None))

    def test_a_ruler_whose_two_shapes_disagree_fails(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(r"(FFW_D03T_RULER phase=\w shape=5 iterations=\d+ ticks=)(\d+)$", ln)
            lines.append(f"{found.group(1)}{int(int(found.group(2)) * 1.05)}" if found else ln)
        gate, _ = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("disagree", gate.detail)

    def test_no_stable_floor_fails(self):
        base = ticks(INSTR_PER_FRAME["nominal/noise"] * FRAMES)
        text = GOOD
        for rep, jitter in enumerate(JITTER):
            text = text.replace(f"name=nominal input=noise rep={rep} frames={FRAMES} ticks={base + jitter} ",
                                f"name=nominal input=noise rep={rep} frames={FRAMES} ticks={base + (0 if rep == 0 else 20_000 * rep)} ")
        gate, _ = self.cpu(text)
        self.assertEqual(gate.status, "failed")
        self.assertIn("no stable floor", gate.detail)

    def test_a_dry_source_or_short_loop_fails(self):
        gate, _ = self.cpu(self.mutate(f"name=fast500 input=noise rep=2 frames={FRAMES}", "name=fast500 input=noise rep=2 frames=1900"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("frames other than", gate.detail)

    def test_still_in_the_fade_in_after_warmup_fails(self):
        gate, _ = self.cpu(self.mutate("name=nominal input=noise ramp_left=0", "name=nominal input=noise ramp_left=17"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("fade-in", gate.detail)

    def test_a_silent_noise_run_means_the_chain_was_not_live(self):
        gate, _ = self.cpu(self.mutate("peak=0.249300 ratio_ppb=-500000", "peak=0.000000 ratio_ppb=-500000"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("chain may not have been live", gate.detail)

    def test_output_on_digital_silence_fails(self):
        gate, _ = self.cpu(self.mutate("peak=0.000000 ratio_ppb=0", "peak=0.001000 ratio_ppb=0"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("output on digital silence", gate.detail)

    def test_a_ratio_that_was_not_the_one_asked_for_fails(self):
        gate, _ = self.cpu(self.mutate("peak=0.249300 ratio_ppb=500000", "peak=0.249300 ratio_ppb=499000"))
        self.assertEqual(gate.status, "failed")
        self.assertIn("was not at 500000 ppb", gate.detail)

    def test_a_slew_that_never_slewed_fails(self):
        text = GOOD
        for rep in range(5):
            text = re.sub(rf"(name=slewing input=noise rep={rep} .*ratio_ppb=)\d+", r"\g<1>28000", text)
        gate, _ = self.cpu(text)
        self.assertEqual(gate.status, "failed")
        self.assertIn("was not slewing", gate.detail)

    def test_an_implausible_figure_below_the_float_op_count_fails(self):
        lines = []
        for ln in GOOD.split("\n"):
            found = re.match(r"(FFW_D03T_RUN name=nominal input=silence rep=\d+ frames=2048 ticks=)(\d+)(.*)$", ln)
            lines.append(f"{found.group(1)}{ticks(20 * FRAMES) + int(found.group(2)) % 7}{found.group(3)}" if found else ln)
        gate, _ = self.cpu("\n".join(lines))
        self.assertEqual(gate.status, "failed")
        self.assertIn("the region or the ruler is wrong", gate.detail)

    def test_a_missing_cpu_case_fails(self):
        text = "\n".join(ln for ln in GOOD.split("\n") if "name=slow500" not in ln)
        gate, _ = self.cpu(text)
        self.assertEqual(gate.status, "failed")
        self.assertIn("slow500", gate.detail)


class TranscriptAndElfTest(unittest.TestCase):
    def test_a_host_build_transcript_is_refused(self):
        gates, report = judge("FFW_D03T_HOST_BUILD counts are meaningless off the MIPS target\n")
        self.assertEqual(gates["D03T-TRANSCRIPT"].status, "failed")
        self.assertEqual(m.exit_code(report), 1)

    def test_a_malformed_marker_line_is_an_error_not_a_guess(self):
        gates, _ = judge(GOOD.replace("FFW_D03T_SEED value=", "FFW_D03T_SEED valu=", 1))
        self.assertEqual(gates["D03T-TRANSCRIPT"].status, "failed")
        self.assertIn("malformed", gates["D03T-TRANSCRIPT"].detail)
        gates, _ = judge(GOOD.replace("FFW_D03T_ALIVE", "FFW_D03T_ALIVE\nFFW_D03T_MYSTERY x=1", 1))
        self.assertIn("unknown marker", gates["D03T-TRANSCRIPT"].detail)

    def test_a_case_that_appears_twice_is_refused(self):
        gates, _ = judge(GOOD + "FFW_D03T_QBEGIN id=q-steady-1000-p500 frames=3 hz=1000 ppb=500000\n")
        self.assertEqual(gates["D03T-TRANSCRIPT"].status, "failed")
        self.assertIn("appears twice", gates["D03T-TRANSCRIPT"].detail)

    def test_an_elf_with_fpu_opcodes_does_not_prove_soft_float(self):
        lwc1 = (0x31 << 26) | 0x1234
        elf = read_elf_bytes(minimal_elf(words=(0x24020001, lwc1, 0x03E00008), fp_abi=3))
        gates, report = judge(elf=elf)
        self.assertEqual(gates["D03T-ELF"].status, "failed")
        self.assertIn("soft-float is NOT proven", gates["D03T-ELF"].detail)
        self.assertEqual(m.exit_code(report), 1)

    def test_an_elf_marked_hard_float_fails(self):
        gates, _ = judge(elf=read_elf_bytes(minimal_elf(fp_abi=1)))
        self.assertEqual(gates["D03T-ELF"].status, "failed")
        self.assertIn("not 3 (soft)", gates["D03T-ELF"].detail)

    def test_a_little_endian_or_non_mips_file_is_refused(self):
        with self.assertRaises(m.MeasurementError):
            read_elf_bytes(minimal_elf(big_endian=False))
        with self.assertRaises(m.MeasurementError):
            read_elf_bytes(b"not an elf at all")


class PrepareTest(unittest.TestCase):
    def test_the_central_build_command_is_the_d02_one_for_this_crate(self):
        text = m.central_commands(__import__("pathlib").Path("/snap"), "label")
        for needle in ("RCH_REQUIRE_REMOTE=1", "rch exec --", "cargo +nightly build --offline --release",
                       "--manifest-path toolchain/src/d03-target/Cargo.toml", "--target mips-unknown-linux-musl",
                       "-Z build-std=core,alloc,std,panic_abort", "-j 2", "zig-cc-mips-be", "crt-static",
                       "/snap/build/d03-target-target/mips-unknown-linux-musl/release/ffw-d03-target"):
            self.assertIn(needle, text)

    def test_the_guest_crate_is_its_own_workspace_and_uses_only_the_dsp_crate(self):
        with open(os.path.join(SRC, "d03-target", "Cargo.toml"), encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("\n[workspace]\n", manifest)
        deps = manifest.split("[dependencies]")[1].split("[profile.release]")[0]
        self.assertEqual(re.findall(r"^([a-z-]+) = ", deps, re.M), ["franken-dsp"])
        self.assertIn('opt-level = "z"', manifest)


if __name__ == "__main__":
    unittest.main()
