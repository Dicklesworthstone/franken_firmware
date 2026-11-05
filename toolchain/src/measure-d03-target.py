#!/usr/bin/env python3
"""Measure D03's drift resampler on the soft-float big-endian MIPS device target, under QEMU.

Bead ffw-j9r, the open item "Measure quality and CPU on target ISA". The guest (`toolchain/src/d03-target`, PID 1 of
the existing Debian/Malta guest) prints `FFW_D03T_*` lines; this script runs it and JUDGES the transcript. Two
questions are answered, and both are bounded by what a QEMU guest can say:

  CPU      guest INSTRUCTIONS per output frame of `DriftResampler::render` at the shipped ratio (0 ppb), at the
           drift limits (+/-500 ppm) and while a slew is in progress, on noise and on digital silence. Read from the
           CP0 Count through a ruler calibrated in the same boot against loops of known instruction count (before AND
           after the D03 phase), after a settling sleep, with nothing printed until everything is measured. A drift
           gate fails the whole CPU result if the ruler scale moved while D03 ran.
  QUALITY  the resampled f32 samples of the host quality tones (+/-500 ppm, 1 kHz and 10 kHz) as hex. They are judged
           HERE, by an independent least-squares carrier fit, against the bands declared in docs/contracts/d03.md
           section 4.1 BEFORE any Rust ran, are compared sample by sample with the double-precision reference
           (`tests/d03/reference.py`), and are byte-compared (digests) with the host build of the same source file
           (`crates/franken-dsp/tests/d03_target_samples.rs`). Equal is the expected result; a difference is a finding.

REPLAY DEFENCE. The host picks a per-run seed and packs it into the initramfs. The guest derives a start phase from it
(SplitMix64, mirrored below bit for bit) and renders two SEEDED cases. A transcript from another run, a guest that
prints canned samples, or samples copied from the host build cannot carry the right phase echo or the right samples.
`run --plant replay` boots a guest that replays an earlier run's quality lines and requires this judge to fail it;
`--plant truncate` cuts a good transcript's sample dump short and requires the same.

WHAT THE NUMBERS ARE. Instructions executed under QEMU TCG with `-icount shift=0` on QEMU's 24Kf model. Not cycles on a
real core: no cache, pipeline, memory latency or multiplier timing is modelled, soft-float helper calls count as the
instructions they execute, and no board clock is involved (the repository records none for any MIPS board). Nothing
here says anything about the real DAC path. The ruler/gate discipline is a copy of `measure-d02-cost.py`'s; the D02
files are not imported or edited.

    measure-d03-target.py prepare --work-dir DIR        snapshot HEAD + the guest crate; print the central commands
    measure-d03-target.py run --elf E --log-dir D [--seed N] [--host-log L] [--plant replay|truncate]
    measure-d03-target.py analyze --log L --elf E --seed N [--host-log L]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import pathlib
import re
import secrets
import shutil
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BENCH_REL = "toolchain/src/d03-target"
TARGET = "mips-unknown-linux-musl"
KERNEL_NAME = "vmlinux-4.19.0-21-4kc-malta"
KERNEL_SHA256_PREFIX = "3803357e"  # the digest every committed E07/E03 receipt records
FP_ABI_SOFT = 3  # Val_GNU_MIPS_ABI_FP_SOFT in .MIPS.abiflags
SAMPLE_RATE_HZ = 48_000
S_IFREG_644 = 0o100644

# Gates. Thresholds are stated here so a reader can argue with them. The ruler ones are the D02 cost guest's.
RULER_SHAPE_AGREEMENT = 0.005    # the two loop shapes must give the same ticks-per-instruction within 0.5 %
RULER_PHASE_DRIFT = 0.005        # ... and so must the ruler run before and after the D03 phase
RULER_RESIDUAL_FRACTION = 0.001  # largest residual of the fit, as a fraction of the largest tick count
RULER_RESIDUAL_FLOOR = 2.0       # ... or this many ticks, whichever is larger
FLOOR_AGREEMENT_LIMIT = 0.01     # the two lowest repetitions of one measurement must agree within 1 %
INFLATED_REP = 0.02              # a repetition this much above the lowest is reported as inflated (never used)
NOISE_MIN_PEAK = 0.05            # the noise input is +/-0.25: a quieter output means the chain was not live
MIN_REPS = 3
MIN_RULER_POINTS = 4
FLOAT_OPS_PER_FRAME = 35         # D03's own hand count; each is at least one instruction, so a figure below it is bogus
MAX_PLAUSIBLE_INSTR_PER_FRAME = 200_000
SAMPLE_TOLERANCE = 2.0e-6        # |guest - double reference| per sample: f32 dot-product rounding is ~2e-7
SAMPLES_PER_LINE = 64
CHUNK = 1024
SEEDED_PPB = 137_000

# What the guest's cases.rs holds. tests/test_measure_d03_target.py parses cases.rs and fails if these drift from it.
CANONICAL = (("q-steady-1000-p500", 1000, 500_000), ("q-steady-1000-m500", 1000, -500_000),
             ("q-steady-10000-p500", 10_000, 500_000), ("q-steady-10000-m500", 10_000, -500_000))
SEEDED = (("seed-1000", 1000), ("seed-10000", 10_000))
COS_W = {1000: 0.9914448613738104, 10_000: 0.25881904510252074}
SIN_W = {1000: 0.13052619222005157, 10_000: 0.9659258262890683}
START_S, START_C = 0.22049901078359654, 0.8635441048190514
INPUT_MARGIN = 64
CPU_EXPECT = {  # name -> (ratio_ppb at the RUN lines, slewing target or None, inputs)
    "nominal": (0, None, ("noise", "silence")),
    "fast500": (500_000, None, ("noise", "silence")),
    "slow500": (-500_000, None, ("noise", "silence")),
    "slewing": (None, 500_000, ("noise",)),
}


def _load(path: pathlib.Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load(REPO / "tests" / "d03" / "reference.py", "d03_reference_for_target")


class MeasurementError(Exception):
    """The transcript cannot be trusted; the message says why."""


# ---- bit-exact mirrors of cases.rs ---------------------------------------------------------------------------------

_M64 = (1 << 64) - 1


def splitmix64(state: int) -> int:
    z = (state + 0x9E3779B97F4A7C15) & _M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _M64
    return z ^ (z >> 31)


def seeded_phase(seed: int, hz: int) -> float:
    return (splitmix64(seed ^ hz) >> 11) / 9007199254740992.0 * (2.0 * math.pi)


def f64_bits(value: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", value))[0]


def _f32(x: float) -> float:
    return struct.unpack(">f", struct.pack(">f", x))[0]


def rotation_input(hz: int, s0: float, c0: float, n: int) -> list[float]:
    """cases.rs `tone_input`: the same IEEE operations in the same order, so the same bits."""
    cw, sw = COS_W[hz], SIN_W[hz]
    s, c = s0, c0
    out = []
    for _ in range(n):
        out.append(_f32(s))
        s, c = s * cw + c * sw, c * cw - s * sw
    return out


def reference_canonical(hz: int, ppb: int, n_out: int) -> list[float]:
    x = rotation_input(hz, START_S, START_C, n_out + INPUT_MARGIN)
    return ref.interpolate("catmull_rom", x, ref.quality_positions(n_out, ppb))


def reference_seeded(hz: int, seed: int, n_out: int) -> tuple[float, list[float]]:
    phase = seeded_phase(seed, hz)
    amp = ref.QUALITY_AMP
    x = rotation_input(hz, amp * math.sin(phase), amp * math.cos(phase), n_out + INPUT_MARGIN)
    y = ref.interpolate("catmull_rom", x, ref.quality_positions(n_out, SEEDED_PPB))
    return phase, [v * (min(i, 64) / 64.0) for i, v in enumerate(y)]  # the 64-frame fade-in: gain i / 64


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & _M64
    return h


# ---- the transcript ------------------------------------------------------------------------------------------------

MARKER = re.compile(r"FFW_D03T_([A-Z_0-9]+)(?: (.*))?$")
PAIRS = re.compile(r"(\w+)=(\[[^\]]*\]|\S+)")
HOST = re.compile(r"D03-TARGET-HOST (\{.*\})\s*$")


def _pairs(rest: str) -> dict[str, str]:
    return {key: value for key, value in PAIRS.findall(rest or "")}


def parse_transcript(text: str) -> dict[str, Any]:
    """Strict parse of the `FFW_D03T_*` lines. Kernel chatter is ignored; a marker line that does not parse is an
    error, never a guess."""
    out: dict[str, Any] = {"alive": False, "begin": None, "seed": "absent", "empty": None, "ruler": [], "warm": {},
                           "runs": [], "cases": {}, "end": False, "reboot_failed": False, "host_build": False,
                           "replay_missing": False}
    for raw in text.replace("\r", "").split("\n"):
        found = MARKER.search(raw)
        if not found:
            continue
        kind, rest = found.group(1), found.group(2) or ""
        try:
            if kind == "ALIVE":
                out["alive"] = True
            elif kind == "BEGIN":
                if out["begin"] is not None:
                    raise MeasurementError("two BEGIN lines")
                out["begin"] = {k: int(v) for k, v in _pairs(rest).items()}
            elif kind == "SEED":
                value = _pairs(rest)["value"]
                out["seed"] = None if value == "none" else int(value)
            elif kind == "EMPTY":
                out["empty"] = [int(v) for v in re.findall(r"\d+", _pairs(rest)["ticks"])]
            elif kind == "RULER":
                p = _pairs(rest)
                out["ruler"].append((p["phase"], int(p["shape"]), int(p["iterations"]), int(p["ticks"])))
            elif kind == "WARM":
                p = _pairs(rest)
                out["warm"][(p["name"], p["input"])] = {"ramp_left": int(p["ramp_left"]),
                                                        "ratio_ppb": int(p["ratio_ppb"]),
                                                        "target_ppb": int(p["target_ppb"])}
            elif kind == "RUN":
                p = _pairs(rest)
                out["runs"].append({"name": p["name"], "input": p["input"], "rep": int(p["rep"]),
                                    "frames": int(p["frames"]), "ticks": int(p["ticks"]), "peak": float(p["peak"]),
                                    "ratio_ppb": int(p["ratio_ppb"])})
            elif kind in ("QBEGIN", "SBEGIN"):
                p = _pairs(rest)
                key = (kind[0], p["id"])
                if key in out["cases"]:
                    raise MeasurementError(f"case {p['id']} appears twice")
                begin = {"hz": int(p["hz"]), "ppb": int(p["ppb"]), "frames": int(p["frames"])}
                if kind == "SBEGIN":
                    begin["phase_bits"] = int(p["phase_bits"], 16)
                out["cases"][key] = {"begin": begin, "data": [], "end": None}
            elif kind in ("QDATA", "SDATA"):
                p = _pairs(rest)
                case = out["cases"].get((kind[0], p["id"]))
                if case is None:
                    raise MeasurementError(f"data for {p['id']} before its BEGIN")
                words = rest.split()[-1]
                if not re.fullmatch(r"([0-9a-f]{8})+", words):
                    raise MeasurementError("data line is not whole 8-digit hex words")
                case["data"].append((int(p["off"]), words))
            elif kind in ("QEND", "SEND"):
                p = _pairs(rest)
                case = out["cases"].get((kind[0], p["id"]))
                if case is None:
                    raise MeasurementError(f"END for {p['id']} before its BEGIN")
                case["end"] = {"frames": int(p["frames"]), "fnv": int(p["fnv"], 16), "chunks": p["chunks"].split(",")}
            elif kind == "END":
                out["end"] = True
            elif kind == "REBOOT_FAILED":
                out["reboot_failed"] = True
            elif kind == "HOST_BUILD":
                out["host_build"] = True
            elif kind == "REPLAY_MISSING":
                out["replay_missing"] = True
            else:
                raise MeasurementError(f"unknown marker FFW_D03T_{kind}")
        except (KeyError, ValueError) as exc:
            raise MeasurementError(f"malformed FFW_D03T_{kind} line {raw.strip()[:120]!r}: {exc!r}") from exc
    return out


def parse_host_log(text: str) -> dict[str, dict[str, Any]]:
    """The host build's `D03-TARGET-HOST {json}` records, by case id."""
    records: dict[str, dict[str, Any]] = {}
    for raw in text.replace("\r", "").split("\n"):
        found = HOST.search(raw)
        if found:
            rec = json.loads(found.group(1))
            if rec["id"] in records and records[rec["id"]] != rec:
                raise MeasurementError(f"the host log has two different records for {rec['id']}")
            records[rec["id"]] = rec
    return records


def decode_case(case: dict[str, Any]) -> tuple[list[float], list[str]]:
    """The samples a case printed, and the structural problems with the dump (truncation, gaps, bad counts)."""
    problems: list[str] = []
    begin, end = case["begin"], case["end"]
    words: list[str] = []
    expected_off = 0
    for off, hexline in case["data"]:
        if off != expected_off:
            problems.append(f"data line at offset {off}, expected {expected_off}: a gap or a reordering")
            break
        words.append(hexline)
        expected_off += len(hexline) // 8
    blob = "".join(words)
    samples = [struct.unpack(">f", bytes.fromhex(blob[i:i + 8]))[0] for i in range(0, len(blob), 8)]
    if end is None:
        problems.append("the dump has no END line: it was cut short")
    else:
        if end["frames"] != begin["frames"]:
            problems.append(f"END says {end['frames']} frames, BEGIN said {begin['frames']}")
        if fnv1a64(bytes.fromhex(blob)) != end["fnv"]:
            problems.append("the printed data does not hash to the END digest: corrupted or truncated data")
    if len(samples) != begin["frames"]:
        problems.append(f"{len(samples)} samples printed, {begin['frames']} promised: the dump is truncated")
    return samples, problems


def chunk_digests(samples: list[float]) -> list[str]:
    out = []
    for i in range(0, len(samples), CHUNK):
        raw = b"".join(struct.pack(">f", s) for s in samples[i:i + CHUNK])
        out.append(f"{fnv1a64(raw):016x}")
    return out


# ---- the ruler (a copy of measure-d02-cost.py's) -------------------------------------------------------------------


def _linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float]:
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        raise MeasurementError("the ruler has a single point")
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return slope, my - slope * mx


def fit_ruler(points: list[tuple[int, int, int]]) -> dict[str, Any]:
    """ticks = intercept + slope * instructions, per loop shape and pooled. The minimum over repetitions is used at
    each size: a timer interrupt or any other stray work only adds ticks."""
    shapes: dict[int, dict[int, list[int]]] = {}
    for shape, iterations, ticks in points:
        shapes.setdefault(shape, {}).setdefault(iterations, []).append(ticks)
    per_shape: dict[int, dict[str, float]] = {}
    pooled_x: list[float] = []
    pooled_y: list[float] = []
    for shape, sizes in sorted(shapes.items()):
        if len(sizes) < MIN_RULER_POINTS:
            raise MeasurementError(f"the shape-{shape} ruler has {len(sizes)} sizes, need {MIN_RULER_POINTS}")
        xs = [float(shape * iterations) for iterations in sorted(sizes)]
        ys = [float(min(sizes[iterations])) for iterations in sorted(sizes)]
        slope, intercept = _linear_fit(xs, ys)
        residual = max(abs(y - (intercept + slope * x)) for x, y in zip(xs, ys))
        per_shape[shape] = {"slope": slope, "intercept": intercept, "residual": residual, "max_ticks": max(ys)}
        pooled_x += xs
        pooled_y += ys
    slope, intercept = _linear_fit(pooled_x, pooled_y)
    slopes = [v["slope"] for v in per_shape.values()]
    return {"per_shape": per_shape, "slope": slope, "intercept": intercept,
            "shape_disagreement": (max(slopes) - min(slopes)) / (sum(slopes) / len(slopes)),
            "instructions_per_tick": 1.0 / slope if slope > 0 else float("inf")}


def ruler_analysis(points: list[tuple[str, int, int, int]]) -> dict[str, Any]:
    """The ruler fitted over all points, and separately for the phase run before (A) and after (B) the D03
    measurements, so a change in the interrupt environment while D03 ran shows up as phase drift."""
    pooled = fit_ruler([(shape, iterations, ticks) for _phase, shape, iterations, ticks in points])
    phases = {}
    for phase in sorted({p[0] for p in points}):
        phases[phase] = fit_ruler([(s, i, t) for ph, s, i, t in points if ph == phase])
    pooled["phases"] = phases
    slopes = [fit["slope"] for fit in phases.values()]
    pooled["phase_drift"] = (max(slopes) - min(slopes)) / (sum(slopes) / len(slopes)) if len(slopes) > 1 else None
    return pooled


def ruler_problems(ruler: dict[str, Any]) -> list[str]:
    problems = []
    if not ruler["slope"] > 0:
        problems.append("the ruler slope is not positive")
    phases = ruler.get("phases")
    if phases is not None:
        if sorted(phases) != ["A", "B"]:
            problems.append(f"the ruler must be run before (A) and after (B) the D03 phase, found {sorted(phases)}")
        elif ruler["phase_drift"] > RULER_PHASE_DRIFT:
            problems.append(f"the ruler scale drifted {ruler['phase_drift']:.3%} between before and after the D03 phase "
                            f"(limit {RULER_PHASE_DRIFT:.1%}): the interrupt environment changed while D03 ran")
    if ruler["shape_disagreement"] > RULER_SHAPE_AGREEMENT:
        problems.append(f"the two loop shapes disagree by {ruler['shape_disagreement']:.4%} "
                        f"(limit {RULER_SHAPE_AGREEMENT:.2%}): the counter is not a clean instruction ruler")
    for shape, fit in ruler["per_shape"].items():
        limit = max(RULER_RESIDUAL_FLOOR, RULER_RESIDUAL_FRACTION * fit["max_ticks"])
        if fit["residual"] > limit:
            problems.append(f"shape-{shape} ruler is not linear: residual {fit['residual']:.1f} ticks > {limit:.1f}")
    return problems


# ---- the ELF -------------------------------------------------------------------------------------------------------

COP1_OPCODES = {0x11: "COP1", 0x13: "COP1X", 0x31: "LWC1", 0x35: "LDC1", 0x39: "SWC1", 0x3D: "SDC1"}


def read_elf(path: pathlib.Path) -> dict[str, Any]:
    """Header facts, the soft-float marker if present, and a scan of every executable word for FPU opcodes."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise MeasurementError(f"{path.name} is not an ELF file")
    if data[4] != 1 or data[5] != 2:
        raise MeasurementError(f"{path.name} is not a 32-bit big-endian ELF (class {data[4]}, data {data[5]})")
    (_ident, e_type, machine, _ver, _entry, _phoff, shoff, flags, _ehsize, _phentsize, _phnum, shentsize, shnum,
     shstrndx) = struct.unpack(">16sHHIIIIIHHHHHH", data[:52])
    info: dict[str, Any] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "e_type": e_type,
                            "machine": machine, "e_flags": flags, "fp_abi": None, "exec_words": 0, "fpu_words": []}
    if machine != 8:
        raise MeasurementError(f"{path.name} is not MIPS (e_machine {machine})")
    sections = []
    for index in range(shnum):
        raw = data[shoff + index * shentsize: shoff + (index + 1) * shentsize]
        if len(raw) < 40:
            raise MeasurementError(f"{path.name}: section header {index} is truncated")
        sections.append(struct.unpack(">IIIIIIIIII", raw[:40]))
    if not sections:
        raise MeasurementError(f"{path.name} has no section headers: it cannot be scanned for FPU opcodes")
    names = sections[shstrndx]
    string_table = data[names[4]: names[4] + names[5]]
    for name_off, sh_type, sh_flags, _addr, offset, size, *_rest in sections:
        name = string_table[name_off: string_table.index(b"\0", name_off)].decode("ascii", "replace")
        if name == ".MIPS.abiflags" and size >= 8:
            info["fp_abi"] = data[offset + 7]
        if sh_type == 1 and sh_flags & 0x4:  # SHT_PROGBITS with SHF_EXECINSTR
            for word_offset in range(offset, offset + size - 3, 4):
                (word,) = struct.unpack(">I", data[word_offset: word_offset + 4])
                info["exec_words"] += 1
                opcode = word >> 26
                if opcode in COP1_OPCODES:
                    info["fpu_words"].append((name, word_offset - offset, COP1_OPCODES[opcode], word))
    return info


# ---- the gates -----------------------------------------------------------------------------------------------------


class Gate:
    def __init__(self, gate_id: str, status: str, detail: str):
        self.gate_id, self.status, self.detail = gate_id, status, detail


def _summary(values: list[float]) -> dict[str, float]:
    return {"min": min(values), "median": statistics.median(values), "max": max(values),
            "spread": (max(values) - min(values)) / min(values) if min(values) > 0 else float("inf")}


def cpu_analysis(t: dict[str, Any]) -> tuple[list[str], dict[str, Any], dict[str, Any] | None]:
    """(problems, per-measurement table, ruler)."""
    problems: list[str] = []
    ruler = ruler_analysis(t["ruler"])
    problems += ruler_problems(ruler)
    begin = t["begin"]
    expected_frames = begin["block_frames"] * begin["blocks_per_rep"]
    table: dict[str, Any] = {}
    seen_names = {r["name"] for r in t["runs"]}
    for missing in sorted(set(CPU_EXPECT) - seen_names):
        problems.append(f"CPU case {missing} is missing from the transcript")
    for name, (want_ratio, want_target, want_inputs) in CPU_EXPECT.items():
        for input_kind in want_inputs:
            key = f"{name}/{input_kind}"
            runs = sorted((r for r in t["runs"] if r["name"] == name and r["input"] == input_kind), key=lambda r: r["rep"])
            if not runs:
                problems.append(f"{key} has no runs")
                continue
            if len(runs) < MIN_REPS or [r["rep"] for r in runs] != list(range(len(runs))):
                problems.append(f"{key} has repetitions {[r['rep'] for r in runs]}, need {MIN_REPS}+ in order")
                continue
            if any(r["frames"] != expected_frames for r in runs):
                problems.append(f"{key} produced frames other than {expected_frames}: the input ran dry, or the loop is short")
                continue
            warm = t["warm"].get((name, input_kind))
            if warm is None:
                problems.append(f"{key} has no WARM line")
                continue
            if warm["ramp_left"] != 0:
                problems.append(f"{key} was still in the fade-in after warm-up (ramp_left {warm['ramp_left']})")
            if want_ratio is not None:
                if warm["ratio_ppb"] != want_ratio or any(r["ratio_ppb"] != want_ratio for r in runs):
                    problems.append(f"{key} was not at {want_ratio} ppb throughout")
            else:
                ratios = [r["ratio_ppb"] for r in runs]
                if warm["target_ppb"] != want_target or not (0 < ratios[0] < want_target) or ratios != sorted(ratios) \
                        or ratios[-1] <= ratios[0]:
                    problems.append(f"{key} was not slewing toward {want_target} ppb (ratios {ratios})")
            peaks = [r["peak"] for r in runs]
            if input_kind == "noise" and min(peaks) < NOISE_MIN_PEAK:
                problems.append(f"{key} peaks at {min(peaks)} on noise: the chain may not have been live, "
                                f"so its cost would be understated")
            if input_kind == "silence" and max(peaks) != 0.0:
                problems.append(f"{key} produced output on digital silence ({max(peaks)})")
            ticks = [r["ticks"] for r in runs]
            per_frame = [(tk - ruler["intercept"]) / ruler["slope"] / expected_frames for tk in ticks]
            if min(per_frame) <= FLOAT_OPS_PER_FRAME or max(per_frame) > MAX_PLAUSIBLE_INSTR_PER_FRAME:
                problems.append(f"{key} reads {min(per_frame):.1f}..{max(per_frame):.1f} instructions per frame, outside "
                                f"{FLOAT_OPS_PER_FRAME}..{MAX_PLAUSIBLE_INSTR_PER_FRAME}: the region or the ruler is wrong")
            lowest = sorted(ticks)[:2]
            floor_gap = (lowest[1] - lowest[0]) / lowest[0] if lowest[0] > 0 else float("inf")
            if floor_gap > FLOOR_AGREEMENT_LIMIT:
                problems.append(f"{key} the two lowest repetitions differ by {floor_gap:.2%} "
                                f"(limit {FLOOR_AGREEMENT_LIMIT:.0%}): no stable floor to read")
            summary = _summary(per_frame)
            table[key] = {"instructions_per_frame": summary, "floor_gap": floor_gap, "frames": expected_frames,
                          "inflated_reps": sum(1 for tk in ticks if tk > lowest[0] * (1 + INFLATED_REP)),
                          "minstr_per_second": {k: v * SAMPLE_RATE_HZ / 1e6 for k, v in summary.items() if k != "spread"}}
    return problems, table, ruler


def fit_window(samples: list[float], hz: int, ppb: int, skip: int, n_meas: int) -> tuple[float, float]:
    w = 2 * math.pi * hz / SAMPLE_RATE_HZ * ref.step_q32(ppb) / ref.Q32
    return ref.fit_metrics(samples[skip:skip + n_meas], w)


def max_deviation(samples: list[float], expected: list[float], start: int = 0) -> tuple[float, int]:
    worst, at = 0.0, start
    for i in range(start, min(len(samples), len(expected))):
        d = abs(samples[i] - expected[i])
        if d > worst:
            worst, at = d, i
    return worst, at


def quality_analysis(t: dict[str, Any], vec: dict[str, Any], host: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """Per canonical case: structure, bands, agreement with the reference, sample deviation, host byte comparison."""
    q = vec["quality"]
    by_id = {c["id"]: c for c in q["cases"]}
    rows: dict[str, Any] = {}
    problems: list[str] = []
    host_problems: list[str] = []
    for cid, hz, ppb in CANONICAL:
        case = t["cases"].get(("Q", cid))
        if case is None:
            problems.append(f"{cid}: no quality dump in the transcript")
            continue
        v = by_id[cid]
        begin = case["begin"]
        if (begin["hz"], begin["ppb"]) != (hz, ppb) or begin["frames"] != v["n_out"]:
            problems.append(f"{cid}: BEGIN says hz {begin['hz']} ppb {begin['ppb']} frames {begin['frames']}, "
                            f"expected {hz} {ppb} {v['n_out']}")
            continue
        samples, structural = decode_case(case)
        if structural:
            problems += [f"{cid}: {s}" for s in structural]
            continue
        if not all(math.isfinite(s) and abs(s) <= 1.0 for s in samples):
            problems.append(f"{cid}: non-finite or out-of-range samples")
            continue
        qd, g = fit_window(samples, hz, ppb, v["skip"], v["n_meas"])
        row = {"hz": hz, "ppb": ppb, "q_db": qd, "gain_db": g, "band_q_db": v["band_q_db"],
               "gain_lo_db": v["gain_lo_db"], "gain_hi_db": v["gain_hi_db"], "expect_q_db": v["expect_q_db"],
               "expect_gain_db": v["expect_gain_db"]}
        if qd < v["band_q_db"]:
            problems.append(f"{cid}: MISSED the declared Q band on the target ISA: {qd:.3f} dB against a floor of "
                            f"{v['band_q_db']} dB (reported, not moved)")
        if not v["gain_lo_db"] <= g <= v["gain_hi_db"]:
            problems.append(f"{cid}: MISSED the declared gain band on the target ISA: {g:.5f} dB against "
                            f"{v['gain_lo_db']}..{v['gain_hi_db']} dB (reported, not moved)")
        if abs(qd - v["expect_q_db"]) > q["tol_q_db"]:
            problems.append(f"{cid}: Q {qd:.3f} dB disagrees with the reference {v['expect_q_db']:.3f} dB "
                            f"(tolerance {q['tol_q_db']})")
        if abs(g - v["expect_gain_db"]) > q["tol_gain_db"]:
            problems.append(f"{cid}: gain {g:.5f} dB disagrees with the reference {v['expect_gain_db']:.5f} dB")
        expected = reference_canonical(hz, ppb, v["n_out"])
        dev, at = max_deviation(samples, expected, start=64)
        row["max_dev_vs_reference"], row["max_dev_at"] = dev, at
        if dev > SAMPLE_TOLERANCE:
            problems.append(f"{cid}: sample {at} is {dev:.2e} from the double-precision reference (limit {SAMPLE_TOLERANCE:.0e})")
        guest_chunks = chunk_digests(samples)
        row["fnv"] = f"{case['end']['fnv']:016x}"
        if host is None:
            row["host"] = "not compared"
        else:
            h = host.get(cid)
            if h is None:
                row["host"] = "not compared"
                host_problems.append(f"{cid}: no host-build record in the host log")
            elif h["frames"] == len(samples) and h["fnv"] == row["fnv"] and h["chunks"] == ",".join(guest_chunks):
                row["host"] = "identical"
            else:
                host_chunks = h["chunks"].split(",")
                first = next((i for i, (a, b) in enumerate(zip(host_chunks, guest_chunks)) if a != b), None)
                row["host"] = "DIFFERS"
                where = f"first differing chunk {first} (samples {first * CHUNK}..{first * CHUNK + CHUNK - 1})" \
                    if first is not None else f"frame counts {h['frames']} vs {len(samples)}"
                host_problems.append(
                    f"{cid}: the target-ISA samples DIFFER from the host build's ({where}); guest digest {row['fnv']}, "
                    f"host digest {h['fnv']}. The guest agrees with the double-precision reference to {dev:.2e}. "
                    f"This is a finding about the target ISA's float behaviour, not something to adjust.")
        rows[cid] = row
    if host is not None:
        # A case whose dump failed the checks above has no row and so was never compared. The byte gate must not read
        # that as "identical": it passes only when every canonical case was compared and matched.
        for cid, _hz, _ppb in CANONICAL:
            if cid not in rows:
                host_problems.append(f"{cid}: not compared with the host build, its dump failed the quality checks")
    return {"rows": rows, "problems": problems, "host_problems": host_problems}


def seeded_analysis(t: dict[str, Any], seed: int | None) -> dict[str, Any]:
    problems: list[str] = []
    rows: dict[str, Any] = {}
    if seed is None:
        return {"rows": rows, "problems": ["no --seed was given: the seeded cases cannot be judged"]}
    if t["seed"] != seed:
        problems.append(f"the guest echoed seed {t['seed']!r}, this run's seed is {seed}: a transcript from another run, "
                        f"or a guest that did not see the seed")
    for cid, hz in SEEDED:
        case = t["cases"].get(("S", cid))
        if case is None:
            problems.append(f"{cid}: no seeded dump in the transcript")
            continue
        begin = case["begin"]
        want_phase = seeded_phase(seed, hz)
        if begin["phase_bits"] != f64_bits(want_phase):
            problems.append(f"{cid}: the phase the guest used ({begin['phase_bits']:016x}) is not the one this run's seed "
                            f"derives ({f64_bits(want_phase):016x}): the samples were not computed from this run's seed")
        if (begin["hz"], begin["ppb"]) != (hz, SEEDED_PPB) or begin["frames"] != ref_seeded_frames(t):
            problems.append(f"{cid}: BEGIN says hz {begin['hz']} ppb {begin['ppb']} frames {begin['frames']}")
            continue
        samples, structural = decode_case(case)
        if structural:
            problems += [f"{cid}: {s}" for s in structural]
            continue
        _phase, expected = reference_seeded(hz, seed, begin["frames"])
        dev, at = max_deviation(samples, expected)
        rows[cid] = {"max_dev_vs_reference": dev, "max_dev_at": at, "hz": hz}
        if dev > SAMPLE_TOLERANCE:
            problems.append(f"{cid}: sample {at} is {dev:.2e} from the reference for this run's seed (limit "
                            f"{SAMPLE_TOLERANCE:.0e}): the samples were not computed from this run's seed")
    return {"rows": rows, "problems": problems}


def ref_seeded_frames(t: dict[str, Any]) -> int:
    return t["begin"]["seeded_frames"]


def transcript_problems(t: dict[str, Any]) -> list[str]:
    problems = []
    if t["host_build"]:
        problems.append("the binary reported a host build; counts off the MIPS target are meaningless")
    if t["begin"] is None or not t["end"]:
        problems.append(f"transcript is incomplete (BEGIN {t['begin'] is not None}, END {t['end']})")
    if t["replay_missing"]:
        problems.append("the guest was asked to replay and had nothing to replay")
    if t["reboot_failed"]:
        problems.append("the guest could not power off (the measurement itself completed)")
    if t["empty"] is None:
        problems.append("EMPTY line is missing")
    return problems


def judge(text: str, elf: dict[str, Any] | None, seed: int | None, host_text: str | None, vec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse and judge a transcript. Every gate is reported; `ok` is true only if none failed or is blocked."""
    vec = vec or json.loads((REPO / "tests" / "d03" / "vectors.json").read_text())
    gates: list[Gate] = []
    try:
        t = parse_transcript(text)
    except MeasurementError as exc:
        return {"ok": False, "gates": [Gate("D03T-TRANSCRIPT", "failed", str(exc))], "cpu": {}, "quality": {}, "seeded": {},
                "ruler": None}
    tp = transcript_problems(t)
    gates.append(Gate("D03T-TRANSCRIPT", "failed" if tp else "passed", "; ".join(tp) or "complete: ALIVE, BEGIN, END"))
    if tp and (t["begin"] is None or not t["end"]):
        return {"ok": False, "gates": gates, "cpu": {}, "quality": {}, "seeded": {}, "ruler": None}
    if elf is None:
        gates.append(Gate("D03T-ELF", "blocked", "no --elf: soft-float is not proven"))
    else:
        ep = []
        if elf["fpu_words"]:
            ep.append(f"{len(elf['fpu_words'])} FPU opcode word(s) in executable sections (first: {elf['fpu_words'][0]}); "
                      f"soft-float is NOT proven")
        if elf["fp_abi"] is not None and elf["fp_abi"] != FP_ABI_SOFT:
            ep.append(f".MIPS.abiflags fp_abi is {elf['fp_abi']}, not {FP_ABI_SOFT} (soft)")
        gates.append(Gate("D03T-ELF", "failed" if ep else "passed",
                          "; ".join(ep) or f"32-bit big-endian MIPS, {elf['exec_words']} executable words, no FPU opcodes"))
    try:
        cp, cpu, ruler = cpu_analysis(t)
    except MeasurementError as exc:
        cp, cpu, ruler = [str(exc)], {}, None
    gates.append(Gate("D03T-CPU", "failed" if cp else "passed",
                      "; ".join(cp) or "ruler gates held; every configuration has a stable floor"))
    quality = quality_analysis(t, vec, parse_host_log(host_text) if host_text is not None else None)
    gates.append(Gate("D03T-QUALITY", "failed" if quality["problems"] else "passed",
                      "; ".join(quality["problems"]) or "all four target-ISA dumps meet the declared bands and the reference"))
    seeded = seeded_analysis(t, seed)
    gates.append(Gate("D03T-SEEDED", "failed" if seeded["problems"] else "passed",
                      "; ".join(seeded["problems"]) or "the seeded cases carry this run's phase and match its reference"))
    if host_text is None:
        gates.append(Gate("D03T-HOST-BYTES", "blocked", "no --host-log: the host build's digests were not supplied"))
    else:
        gates.append(Gate("D03T-HOST-BYTES", "failed" if quality["host_problems"] else "passed",
                          "; ".join(quality["host_problems"]) or "every canonical case is byte-identical to the host build"))
    ok = all(g.status == "passed" for g in gates)
    return {"ok": ok, "gates": gates, "cpu": cpu, "quality": quality["rows"], "seeded": seeded["rows"], "ruler": ruler}


def exit_code(report: dict[str, Any]) -> int:
    statuses = {g.status for g in report["gates"]}
    return 1 if "failed" in statuses else 3 if "blocked" in statuses else 0


# ---- reporting -----------------------------------------------------------------------------------------------------

HONEST_FOOTER = (
    "These are INSTRUCTIONS EXECUTED under QEMU TCG (-icount shift=0) on QEMU's 24Kf model, read through a ruler\n"
    "calibrated in the guest, not cycles on a real core: no cache, pipeline, memory latency or multiplier timing is\n"
    "modelled, and no board clock is involved. The quality rows are the resampler's f32 output on the target ISA, judged\n"
    "against bands declared before any Rust ran; they say nothing about the real DAC path.")


def render(report: dict[str, Any], revision: str | None) -> str:
    lines: list[str] = []
    ruler = report.get("ruler")
    if ruler:
        lines.append(f"ruler: {ruler['instructions_per_tick']:.4f} instructions per Count tick (shapes disagree by "
                     f"{ruler['shape_disagreement']:.4%}, before/after drift {(ruler.get('phase_drift') or 0.0):.4%}, "
                     f"intercept {ruler['intercept']:.1f} ticks)")
    for g in report["gates"]:
        lines.append(f"{g.status.upper():8s} {g.gate_id:16s} {g.detail}")
    cpu_ok = next((g.status == "passed" for g in report["gates"] if g.gate_id == "D03T-CPU"), False)
    if report["cpu"] and cpu_ok:
        lines += ["", f"build revision: {revision or 'unrecorded'}", "",
                  f"{'case/input':18s} {'instr/frame min':>16s} {'median':>9s} {'max':>9s} {'Minstr/s (min)':>15s}"]
        for key, row in sorted(report["cpu"].items()):
            s = row["instructions_per_frame"]
            lines.append(f"{key:18s} {s['min']:16.1f} {s['median']:9.1f} {s['max']:9.1f} {row['minstr_per_second']['min']:15.1f}")
        lines += ["", f"Minstr/s is instructions per frame x {SAMPLE_RATE_HZ} frames/s: what a core must retire per "
                      "second to keep up, before cache or pipeline effects."]
    elif report["cpu"]:
        lines += ["", "NO CPU HEADLINE NUMBER: a CPU gate failed."]
    if report["quality"]:
        lines += ["", f"{'case':22s} {'Q dB':>9s} {'floor':>6s} {'gain dB':>10s} {'gain band':>16s} {'max dev':>9s} {'host':>12s}"]
        for cid, r in report["quality"].items():
            lines.append(f"{cid:22s} {r['q_db']:9.3f} {r['band_q_db']:6.1f} {r['gain_db']:10.5f} "
                         f"{r['gain_lo_db']:>7}..{r['gain_hi_db']:<7} {r['max_dev_vs_reference']:9.2e} {r['host']:>12s}")
    lines += ["", HONEST_FOOTER]
    return "\n".join(lines)


# ---- QEMU ----------------------------------------------------------------------------------------------------------


def kernel_path() -> pathlib.Path:
    import os
    build = os.environ.get("FFW_BUILD_DIR")
    if not build:
        raise MeasurementError("FFW_BUILD_DIR is not set; it must contain kernels/xm/boot/ (the committed receipts "
                               f"record kernel digest {KERNEL_SHA256_PREFIX}...)")
    return pathlib.Path(build) / "kernels" / "xm" / "boot" / KERNEL_NAME


def run_guest(elf: pathlib.Path, work: pathlib.Path, label: str, timeout: float, extra_files: list[tuple[str, int, bytes]]
              ) -> tuple[str, dict[str, Any]]:
    """Pack `elf` as the guest's /init (plus `extra_files`), boot it under QEMU with -icount, return the transcript."""
    kernel = kernel_path()
    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if not digest.startswith(KERNEL_SHA256_PREFIX):
        raise MeasurementError(f"kernel digest {digest[:16]}... is not the committed {KERNEL_SHA256_PREFIX}...")
    mkinitramfs = _load(HERE / "mkinitramfs.py", "mkinitramfs_for_d03_target")
    initramfs = work / f"{label}.cpio.gz"
    mkinitramfs.build(elf, initramfs, extra_files=extra_files)
    command = ["qemu-system-mips", "-M", "malta", "-cpu", "24Kf", "-m", "64M", "-nographic", "-no-reboot",
               "-icount", "shift=0,align=off,sleep=off", "-kernel", str(kernel), "-initrd", str(initramfs),
               "-append", "console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3"]
    version = subprocess.run(["qemu-system-mips", "--version"], capture_output=True, text=True, check=False).stdout
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout,
                                   stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        text = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
        raise MeasurementError(f"{label}: QEMU did not finish within {timeout:.0f}s; last output: {text[-400:]!r}") from exc
    return completed.stdout, {"command": command, "qemu": version.splitlines()[0] if version else "unknown",
                              "kernel_sha256": digest, "exit_code": completed.returncode}


def quality_lines_of(text: str) -> str:
    """The `QBEGIN..SEND` lines of a transcript, for the replay plant."""
    keep = [ln for ln in text.replace("\r", "").split("\n") if re.search(r"FFW_D03T_[QS](BEGIN|DATA|END)\b", ln)]
    return "\n".join(keep) + "\n"


def truncate_dump(text: str, fraction: float = 0.6) -> str:
    """The planted truncation: the transcript cut off partway through the sample dump."""
    lines = text.replace("\r", "").split("\n")
    data = [i for i, ln in enumerate(lines) if "FFW_D03T_QDATA" in ln or "FFW_D03T_SDATA" in ln]
    cut = data[int(len(data) * fraction)]
    return "\n".join(lines[:cut]) + "\n"


# ---- prepare -------------------------------------------------------------------------------------------------------


def central_commands(snapshot: pathlib.Path, label: str) -> str:
    target_dir = snapshot / "build" / "d03-target-target"
    config_linker = f'target.{TARGET}.linker="{snapshot}/toolchain/linker/zig-cc-mips-be"'
    config_flags = f'target.{TARGET}.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
    return (f"cd {snapshot} && RCH_CANONICAL_PROJECT_ROOT={snapshot} RCH_REQUIRE_REMOTE=1 "
            f"RCH_WORKER=hz4,hz3,ts1 CARGO_TARGET_DIR={target_dir} rch exec -- cargo +nightly build --offline --release "
            f"--manifest-path {BENCH_REL}/Cargo.toml --target {TARGET} -Z build-std=core,alloc,std,panic_abort "
            f"--config '{config_linker}' --config '{config_flags}' -j 2"
            f"   # {label}; ELF: {target_dir}/{TARGET}/release/ffw-d03-target")


def prepare(work_dir: pathlib.Path) -> str:
    """Snapshot HEAD plus the guest crate (it may be uncommitted yet). Nothing is built; nothing is deleted."""
    if work_dir.exists() and any(work_dir.iterdir()):
        raise MeasurementError(f"{work_dir} exists and is not empty; choose a fresh directory (nothing is deleted)")
    plain = work_dir / "plain"
    plain.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=REPO, capture_output=True, check=True)
    with tempfile.TemporaryFile() as handle:
        handle.write(archive.stdout)
        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:") as tar:
            tar.extractall(plain, filter="data")
    shutil.copytree(REPO / BENCH_REL, plain / BENCH_REL, dirs_exist_ok=True)
    shutil.copy2(REPO / "Cargo.lock", plain / BENCH_REL / "Cargo.lock")      # a pin; cargo prunes it on the build
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
    return "\n".join([
        f"snapshot of HEAD {head} plus {BENCH_REL}: {plain}",
        "",
        "Central guest build (RCH only; run from the snapshot root):",
        central_commands(plain, "D03 target guest"),
        "",
        "Host digests (the same cases.rs on the build host; run from the repository root of the same revision):",
        "  RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp --test d03_target_samples -- --nocapture",
        "",
        "Then:  FFW_BUILD_DIR=<kernel cache> python3 toolchain/src/measure-d03-target.py run --elf <ELF> "
        "--log-dir <fresh dir> --host-log <the cargo test log> --revision " + head])


# ---- command line --------------------------------------------------------------------------------------------------


def _elf_summary(info: dict[str, Any]) -> str:
    return (f"ELF sha256 {info['sha256'][:16]}... {info['bytes']} bytes, e_flags {info['e_flags']:#010x}, "
            f"fp_abi {info['fp_abi']}, {info['exec_words']} executable words scanned, {len(info['fpu_words'])} FPU opcode word(s)")


def _plant_report(label: str, report: dict[str, Any], want_gates: tuple[str, ...]) -> bool:
    failed = {g.gate_id for g in report["gates"] if g.status == "failed"}
    caught = bool(failed & set(want_gates))
    print(f"PLANT {label}: {'CAUGHT' if caught else 'NOT CAUGHT'} (failed gates: {sorted(failed) or 'none'}; "
          f"wanted one of {list(want_gates)})")
    return caught


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--work-dir", type=pathlib.Path, required=True)
    for name in ("run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--elf", type=pathlib.Path, required=True)
        p.add_argument("--host-log", type=pathlib.Path, help="the central `cargo test --test d03_target_samples` output")
        p.add_argument("--revision", help="the git revision the ELF was built from (recorded in the output)")
        p.add_argument("--json", action="store_true", help="also print the judged result as JSON on stdout")
        if name == "run":
            p.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial logs")
            p.add_argument("--timeout", type=float, default=900.0)
            p.add_argument("--seed", type=int, help="the run's seed (default: random)")
            p.add_argument("--plant", choices=("replay", "truncate"), help="also run a planted negative and require it to fail")
        else:
            p.add_argument("--log", type=pathlib.Path, required=True)
            p.add_argument("--seed", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            print(prepare(args.work_dir))
            return 0
        elf = read_elf(args.elf)
        print(_elf_summary(elf))
        host_text = args.host_log.read_text(errors="replace") if args.host_log else None
        if args.command == "run":
            if args.log_dir.exists() and any(args.log_dir.iterdir()):
                raise MeasurementError(f"{args.log_dir} is not empty; choose a fresh directory (nothing is deleted)")
            args.log_dir.mkdir(parents=True, exist_ok=True)
            seed = args.seed if args.seed is not None else secrets.randbits(62)
            with tempfile.TemporaryDirectory() as scratch:
                text, meta = run_guest(args.elf, pathlib.Path(scratch), "run", args.timeout,
                                       [("ffw_seed", S_IFREG_644, f"{seed}\n".encode())])
                (args.log_dir / "d03-target.serial.log").write_text(text)
                (args.log_dir / "seed.txt").write_text(f"{seed}\n")
                print(f"{meta['qemu']}; kernel {meta['kernel_sha256'][:8]}...; exit {meta['exit_code']}; "
                      f"{len(text.splitlines())} serial lines; seed {seed}")
                report = judge(text, elf, seed, host_text)
                plants_ok = True
                if args.plant == "truncate":
                    cut = truncate_dump(text)
                    (args.log_dir / "plant-truncate.serial.log").write_text(cut)
                    plants_ok = _plant_report("truncated dump", judge(cut, elf, seed, host_text),
                                              ("D03T-TRANSCRIPT", "D03T-QUALITY", "D03T-SEEDED"))
                if args.plant == "replay":
                    other = secrets.randbits(62)
                    replay_text, _ = run_guest(args.elf, pathlib.Path(scratch), "replay", args.timeout, [
                        ("ffw_seed", S_IFREG_644, f"{other}\n".encode()), ("plant-replay", S_IFREG_644, b"1\n"),
                        ("replay", S_IFREG_644, quality_lines_of(text).encode())])
                    (args.log_dir / "plant-replay.serial.log").write_text(replay_text)
                    plants_ok = _plant_report(f"replayed samples under seed {other}", judge(replay_text, elf, other, host_text),
                                              ("D03T-SEEDED",))
        else:
            text = args.log.read_text(errors="replace")
            report, plants_ok = judge(text, elf, args.seed, host_text), True
    except (MeasurementError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(report, getattr(args, "revision", None)))
    if getattr(args, "json", False):
        print(json.dumps({"ok": report["ok"], "gates": [vars(g) for g in report["gates"]], "cpu": report["cpu"],
                          "quality": report["quality"], "seeded": report["seeded"]}, indent=1, sort_keys=True, default=str))
    code = exit_code(report)
    return code if plants_ok else 1


if __name__ == "__main__":
    sys.exit(main())
