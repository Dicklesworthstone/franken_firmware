#!/usr/bin/env python3
"""Measure D02's per-frame protection cost on the soft-float MIPS device target, in instructions, under QEMU.

Bead ffw-7s0, the open item "D02 f64 target CPU cost". Two binaries are compared: the shipped D02 (f64 section
state) and a CONTROL whose only difference is an f32 section state (`d02-cost/section-f32-control.patch`, the
realization D02 had before commit 4e2c68c). Everything else is identical, so the difference is attributable.

    measure-d02-cost.py prepare --work-dir DIR           snapshot the tree twice (plain, patched) and print the
                                                         central build commands; nothing is built here
    measure-d02-cost.py run --elf-f64 P --elf-f32 P --log-dir D    boot each ELF as PID 1 under QEMU, then judge
    measure-d02-cost.py analyze --log-f64 L --log-f32 L --elf-f64 P --elf-f32 P    judge existing transcripts
    measure-d02-cost.py compare --elf-before P --elf-after P --log-dir D    the saving ONE source change made, with the
                                                         same section state in both builds: boot each, judge before - after
    measure-d02-cost.py compare --elf-before P --elf-after P --log-before L --log-after L    judge existing transcripts

WHAT THE NUMBERS ARE. Instructions executed under QEMU TCG with `-icount shift=0`, read from the guest's CP0 Count
through a ruler that is calibrated in the guest against loops of known instruction count. They are NOT cycles on a
real 24K core: no cache, pipeline, memory latency, branch or multiplier timing is modelled beyond the instructions
themselves, and soft-float helper calls are counted as the instructions they execute, nothing more. The synthetic
fixture calibrations are not a driver model, and the board CPU clock is not in the repository for any MIPS board, so
no percentage-of-CPU is claimed: the output is instructions per frame and the instructions per second that implies.

THE GATES. A headline number is printed only if every gate passes; otherwise the failing gates are listed and no
figure is given. Raw serial transcripts are written to --log-dir and are the evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
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
BENCH_REL = "toolchain/src/d02-cost"
PATCH_REL = f"{BENCH_REL}/section-f32-control.patch"
TARGET = "mips-unknown-linux-musl"
KERNEL_NAME = "vmlinux-4.19.0-21-4kc-malta"
KERNEL_SHA256_PREFIX = "3803357e"  # the digest every committed E07/E03 receipt records
SAMPLE_RATE_HZ = 48_000
FP_ABI_SOFT = 3  # Val_GNU_MIPS_ABI_FP_SOFT in .MIPS.abiflags; the speaker's own ELF carries it

# Gates (thresholds are stated here so a reader can argue with them, not buried in code).
RULER_SHAPE_AGREEMENT = 0.005   # the two loop shapes must give the same ticks-per-instruction within 0.5 %
RULER_PHASE_DRIFT = 0.005        # ... and so must the ruler run before and after the D02 phase
RULER_RESIDUAL_FRACTION = 0.001  # largest residual of the fit, as a fraction of the largest tick count
RULER_RESIDUAL_FLOOR = 2.0       # ... or this many ticks, whichever is larger
FLOOR_AGREEMENT_LIMIT = 0.01     # the two lowest repetitions of one measurement must agree within 1 %
INFLATED_REP = 0.02              # a repetition this much above the lowest is reported as inflated (never used)
NOISE_MIN_PEAK = 20              # every channel must carry signal on noise input: the chain really ran
MIN_REPS = 3
MIN_RULER_POINTS = 4

COP1_OPCODES = {0x11: "COP1", 0x13: "COP1X", 0x31: "LWC1", 0x35: "LDC1", 0x39: "SWC1", 0x3D: "SDC1"}


def _load(path: pathlib.Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ---- which Section is in the binary -------------------------------------------------------------------------------


def _f32(x: float) -> float:
    return struct.unpack(">f", struct.pack(">f", x))[0]


def _bits(x: float) -> int:
    return struct.unpack(">I", struct.pack(">f", x))[0]


def lowpass_coefficients(cutoff_hz: float, fs_hz: float) -> list[float]:
    """Second-order Butterworth low-pass, bilinear transform (the formula in calibration.rs), stored as f32."""
    k = math.tan(math.pi * cutoff_hz / fs_hz)
    sqrt2 = math.sqrt(2.0)
    norm = 1.0 / (1.0 + sqrt2 * k + k * k)
    b0 = k * k * norm
    return [_f32(v) for v in (b0, 2.0 * b0, b0, 2.0 * (k * k - 1.0) * norm, (1.0 - sqrt2 * k + k * k) * norm)]


def selftest_expectation() -> dict[str, int]:
    """The f32 bits of sample 127 of the 120 Hz low-pass step response for each realization, computed here."""
    b0, b1, b2, a1, a2 = lowpass_coefficients(120.0, SAMPLE_RATE_HZ)
    z1 = z2 = 0.0  # f64 arithmetic and state on the f32-stored coefficients (shipped D02)
    for _ in range(128):
        y = b0 * 1.0 + z1
        z1 = b1 * 1.0 - a1 * y + z2
        z2 = b2 * 1.0 - a2 * y
    f64_bits = _bits(_f32(y))
    z1 = z2 = 0.0  # f32 arithmetic and state, operation by operation (the control)
    for _ in range(128):
        y = _f32(_f32(b0 * 1.0) + z1)
        z1 = _f32(_f32(_f32(b1 * 1.0) - _f32(a1 * y)) + z2)
        z2 = _f32(_f32(b2 * 1.0) - _f32(a2 * y))
    return {"f64": f64_bits, "f32": _bits(y)}


# ---- the transcript ------------------------------------------------------------------------------------------------


class MeasurementError(Exception):
    """The transcript cannot be trusted; the message says why."""


MARKER = re.compile(r"FFW_D02COST_([A-Z_]+)(?: (.*))?$")
CONFIG = re.compile(r"name=(\S+) channels=(\d+) sections=(\d+) admitted=([01]) status=(.*)$")
PAIRS = re.compile(r"(\w+)=(\[[^\]]*\]|\S+)")


def _pairs(rest: str) -> dict[str, str]:
    return {key: value for key, value in PAIRS.findall(rest or "")}


def parse_transcript(text: str) -> dict[str, Any]:
    """Strict parse of the `FFW_D02COST_*` lines. Kernel chatter is ignored; a marker line that does not parse is an
    error, never a guess."""
    out: dict[str, Any] = {"alive": False, "begin": None, "selftest_bits": None, "empty": None, "ruler": [],
                           "configs": {}, "warm": {}, "runs": [], "end": False, "reboot_failed": False,
                           "host_build": False}
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
            elif kind == "SELFTEST":
                out["selftest_bits"] = int(_pairs(rest)["bits"], 16)
            elif kind == "EMPTY":
                out["empty"] = [int(v) for v in re.findall(r"\d+", _pairs(rest)["ticks"])]
            elif kind == "RULER":
                p = _pairs(rest)
                out["ruler"].append((p["phase"], int(p["shape"]), int(p["iterations"]), int(p["ticks"])))
            elif kind == "CONFIG":
                m = CONFIG.match(rest)
                if not m:
                    raise MeasurementError(f"unparsable CONFIG: {rest!r}")
                name = m.group(1)
                if name in out["configs"]:
                    raise MeasurementError(f"config {name} appears twice")
                out["configs"][name] = {"channels": int(m.group(2)), "sections": int(m.group(3)),
                                        "admitted": m.group(4) == "1", "status": m.group(5)}
            elif kind == "WARM":
                p = _pairs(rest)
                out["warm"][(p["name"], p["input"])] = float(p["applied_gain"])
            elif kind == "RUN":
                p = _pairs(rest)
                out["runs"].append({"name": p["name"], "input": p["input"], "rep": int(p["rep"]),
                                    "frames": int(p["frames"]), "ticks": int(p["ticks"]),
                                    "min_channel_peak": int(p["min_channel_peak"])})
            elif kind == "END":
                out["end"] = True
            elif kind == "REBOOT_FAILED":
                out["reboot_failed"] = True
            elif kind == "HOST_BUILD":
                out["host_build"] = True
            else:
                raise MeasurementError(f"unknown marker FFW_D02COST_{kind}")
        except (KeyError, ValueError) as exc:
            raise MeasurementError(f"malformed FFW_D02COST_{kind} line {raw.strip()!r}: {exc!r}") from exc
    return out


# ---- the ruler -----------------------------------------------------------------------------------------------------


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
    """The ruler fitted over all points, and separately for the phase run before (A) and after (B) the D02
    measurements, so a change in the interrupt environment while D02 ran shows up as phase drift."""
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
            problems.append(f"the ruler must be run before (A) and after (B) the D02 phase, found {sorted(phases)}")
        elif ruler["phase_drift"] > RULER_PHASE_DRIFT:
            problems.append(f"the ruler scale drifted {ruler['phase_drift']:.3%} between before and after the D02 phase "
                            f"(limit {RULER_PHASE_DRIFT:.1%}): the interrupt environment changed while D02 ran")
    if ruler["shape_disagreement"] > RULER_SHAPE_AGREEMENT:
        problems.append(f"the two loop shapes disagree by {ruler['shape_disagreement']:.4%} "
                        f"(limit {RULER_SHAPE_AGREEMENT:.2%}): the counter is not a clean instruction ruler")
    for shape, fit in ruler["per_shape"].items():
        limit = max(RULER_RESIDUAL_FLOOR, RULER_RESIDUAL_FRACTION * fit["max_ticks"])
        if fit["residual"] > limit:
            problems.append(f"shape-{shape} ruler is not linear: residual {fit['residual']:.1f} ticks > {limit:.1f}")
    return problems


# ---- the ELF -------------------------------------------------------------------------------------------------------


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


# ---- analysis ------------------------------------------------------------------------------------------------------


def _summary(values: list[float]) -> dict[str, float]:
    return {"min": min(values), "median": statistics.median(values), "max": max(values),
            "spread": (max(values) - min(values)) / min(values) if min(values) > 0 else float("inf")}


def analyze_one(label: str, transcript: dict[str, Any], elf: dict[str, Any] | None) -> dict[str, Any]:
    """Everything the gates need about one binary's transcript. Raises MeasurementError for a transcript that is
    structurally unusable; returns `problems` for anything a human should see but that is still parseable."""
    problems: list[str] = []
    if transcript["host_build"]:
        raise MeasurementError(f"{label}: the binary reported a host build; counts off the MIPS target are meaningless")
    if transcript["begin"] is None or not transcript["end"]:
        raise MeasurementError(f"{label}: transcript is incomplete (BEGIN {transcript['begin'] is not None}, "
                               f"END {transcript['end']})")
    if transcript["reboot_failed"]:
        problems.append(f"{label}: the guest could not power off (the measurement itself completed)")
    if transcript["selftest_bits"] is None or transcript["empty"] is None:
        raise MeasurementError(f"{label}: SELFTEST or EMPTY line is missing")
    ruler = ruler_analysis(transcript["ruler"])
    problems += [f"{label}: {p}" for p in ruler_problems(ruler)]

    expectation = selftest_expectation()
    variant = next((v for v, bits in expectation.items() if bits == transcript["selftest_bits"]), None)
    if variant is None:
        problems.append(f"{label}: the section self-test bits {transcript['selftest_bits']:08x} match neither "
                        f"realization (f64 {expectation['f64']:08x}, f32 {expectation['f32']:08x})")

    begin = transcript["begin"]
    expected_frames = begin["block_frames"] * begin["blocks_per_rep"]
    measurements: dict[str, dict[str, Any]] = {}
    for name, cfg in transcript["configs"].items():
        if not cfg["admitted"]:
            measurements[name] = {"config": cfg, "refused": True}
            continue
        for input_kind in sorted({r["input"] for r in transcript["runs"] if r["name"] == name}):
            runs = sorted((r for r in transcript["runs"] if r["name"] == name and r["input"] == input_kind),
                          key=lambda r: r["rep"])
            key = f"{name}/{input_kind}"
            if len(runs) < MIN_REPS or [r["rep"] for r in runs] != list(range(len(runs))):
                problems.append(f"{label}: {key} has repetitions {[r['rep'] for r in runs]}, need {MIN_REPS}+ in order")
                continue
            if any(r["frames"] != expected_frames for r in runs):
                problems.append(f"{label}: {key} reports frames other than {expected_frames}")
                continue
            warm = transcript["warm"].get((name, input_kind))
            if warm is None or abs(warm - 1.0) > 1e-6:
                problems.append(f"{label}: {key} was not at full gain after warm-up ({warm})")
            peaks = [r["min_channel_peak"] for r in runs]
            if input_kind == "noise" and min(peaks) < NOISE_MIN_PEAK:
                problems.append(f"{label}: {key} has a channel that peaks at {min(peaks)} on noise: the chain may not "
                                f"have been live, so its cost would be understated")
            if input_kind == "silence" and max(peaks) != 0:
                problems.append(f"{label}: {key} produced output on digital silence ({max(peaks)})")
            ticks = [r["ticks"] for r in runs]
            instructions = [(t - ruler["intercept"]) / ruler["slope"] for t in ticks]
            per_frame = [i / expected_frames for i in instructions]
            summary = _summary(per_frame)
            lowest = sorted(ticks)[:2]
            floor_gap = (lowest[1] - lowest[0]) / lowest[0] if lowest[0] > 0 else float("inf")
            if floor_gap > FLOOR_AGREEMENT_LIMIT:
                problems.append(f"{label}: {key} the two lowest repetitions differ by {floor_gap:.2%} "
                                f"(limit {FLOOR_AGREEMENT_LIMIT:.0%}): no stable floor to read")
            inflated = sum(1 for t in ticks if t > lowest[0] * (1 + INFLATED_REP))
            measurements[key] = {"config": cfg, "ticks": ticks, "frames": expected_frames, "floor_gap": floor_gap,
                                 "inflated_reps": inflated, "instructions_per_frame": summary,
                                 "required_minstr_per_second": {k: v * SAMPLE_RATE_HZ / 1e6 for k, v in summary.items()
                                                                if k != "spread"}}
    if elf is not None:
        if elf["fpu_words"]:
            problems.append(f"{label}: {len(elf['fpu_words'])} FPU opcode word(s) in executable sections "
                            f"(first: {elf['fpu_words'][0]}); soft-float is NOT proven")
        if elf["fp_abi"] is not None and elf["fp_abi"] != FP_ABI_SOFT:
            problems.append(f"{label}: .MIPS.abiflags fp_abi is {elf['fp_abi']}, not {FP_ABI_SOFT} (soft)")
    return {"label": label, "variant": variant, "ruler": ruler, "measurements": measurements, "problems": problems,
            "empty_floor_ticks": transcript["empty"], "alive": transcript["alive"]}


def compare(f64: dict[str, Any], f32: dict[str, Any]) -> dict[str, Any]:
    """The attributable difference, per configuration and input, plus the cost per section."""
    rows = {}
    for key, measured in f64["measurements"].items():
        other = f32["measurements"].get(key)
        if measured.get("refused") or other is None or other.get("refused"):
            rows[key] = {"refused_or_missing": True}
            continue
        a, b = measured["instructions_per_frame"]["min"], other["instructions_per_frame"]["min"]
        sections = measured["config"]["sections"]
        rows[key] = {"f64_per_frame": a, "f32_per_frame": b, "delta_per_frame": a - b, "ratio": a / b,
                     "sections": sections, "channels": measured["config"]["channels"],
                     "delta_per_section_per_frame": (a - b) / sections if sections else None,
                     "f64_minstr_per_second": a * SAMPLE_RATE_HZ / 1e6, "f32_minstr_per_second": b * SAMPLE_RATE_HZ / 1e6}
    return rows


def judge(f64_text: str, f32_text: str, f64_elf: dict[str, Any] | None, f32_elf: dict[str, Any] | None) -> dict[str, Any]:
    """Parse, analyze and compare. `ok` is true only if no gate failed; `rows` is empty otherwise."""
    results = {}
    problems: list[str] = []
    for label, text, elf, want in (("f64", f64_text, f64_elf, "f64"), ("f32", f32_text, f32_elf, "f32")):
        try:
            analysis = analyze_one(label, parse_transcript(text), elf)
        except MeasurementError as exc:
            return {"ok": False, "problems": [str(exc)], "rows": {}, "analyses": results}
        if analysis["variant"] != want:
            analysis["problems"].append(f"{label}: the binary measured the {analysis['variant']} section, "
                                        f"but was supplied as the {want} build")
        results[label] = analysis
        problems += analysis["problems"]
    rows = compare(results["f64"], results["f32"]) if not problems else {}
    return {"ok": not problems, "problems": problems, "rows": rows, "analyses": results}


def judge_conversion(before_text: str, after_text: str, before_elf: dict[str, Any] | None,
                     after_elf: dict[str, Any] | None) -> dict[str, Any]:
    """The saving one source change made to a build whose Section state did not change: instructions per frame in the
    `before` build minus the `after` build, per configuration and input. Both builds pass the same gates as `judge`.
    They must measure the same section realization (otherwise the difference would include the section change),
    must be different binaries (a build compared with itself has nothing to attribute), and must have measured the
    same configurations. Each row carries the larger of the two builds' floor gaps as `noise_fraction`: a saving
    that is not clearly larger than that is not a result."""
    results: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for label, text, elf in (("before", before_text, before_elf), ("after", after_text, after_elf)):
        try:
            analysis = analyze_one(label, parse_transcript(text), elf)
        except MeasurementError as exc:
            return {"ok": False, "problems": [str(exc)], "rows": {}, "analyses": results}
        results[label] = analysis
        problems += analysis["problems"]
    before, after = results["before"], results["after"]
    if before["variant"] != after["variant"]:
        problems.append(f"the builds measured different section realizations (before {before['variant']}, after "
                        f"{after['variant']}): the difference would include the section change, not one source change")
    if before_elf is not None and after_elf is not None and before_elf["sha256"] == after_elf["sha256"]:
        problems.append("the two ELFs are identical: there is no change to attribute a difference to")
    if set(before["measurements"]) != set(after["measurements"]):
        only = sorted(set(before["measurements"]) ^ set(after["measurements"]))
        problems.append(f"the builds measured different configurations or inputs ({only}): rows would not pair up")
    rows: dict[str, dict[str, Any]] = {}
    if not problems:
        for key, measured in sorted(before["measurements"].items()):
            other = after["measurements"][key]
            if measured.get("refused") or other.get("refused"):
                rows[key] = {"refused_or_missing": True}
                continue
            a, b = measured["instructions_per_frame"]["min"], other["instructions_per_frame"]["min"]
            channels, sections = measured["config"]["channels"], measured["config"]["sections"]
            rows[key] = {"before_per_frame": a, "after_per_frame": b, "saving_per_frame": a - b,
                         "saving_fraction": (a - b) / a, "channels": channels, "sections": sections,
                         "saving_per_channel_per_frame": (a - b) / channels if channels else None,
                         "noise_fraction": max(measured["floor_gap"], other["floor_gap"]),
                         "before_minstr_per_second": a * SAMPLE_RATE_HZ / 1e6,
                         "after_minstr_per_second": b * SAMPLE_RATE_HZ / 1e6,
                         "saving_minstr_per_second": (a - b) * SAMPLE_RATE_HZ / 1e6}
    return {"ok": not problems, "problems": problems, "rows": rows, "analyses": results}


# ---- reporting -----------------------------------------------------------------------------------------------------

HONEST_FOOTER = (
    "These are INSTRUCTIONS EXECUTED under QEMU TCG (-icount shift=0), read through a ruler calibrated in the guest, not\n"
    "cycles on a real 24K core: no cache, pipeline, memory latency or multiplier timing is modelled. The calibrations are\n"
    "synthetic fixtures, not a driver model. The repository records no CPU clock for any MIPS board (the clocks it does\n"
    "record, 300 MHz and 266 MHz, belong to PowerPC boards, which are hard-float), so no percentage of a CPU is claimed.")


def render(report: dict[str, Any], revision: str | None) -> str:
    lines: list[str] = []
    for label in ("f64", "f32"):
        analysis = report["analyses"].get(label)
        if analysis:
            ruler = analysis["ruler"]
            lines.append(f"[{label}] section realization seen by the guest: {analysis['variant']}; ruler: "
                         f"{ruler['instructions_per_tick']:.4f} instructions per Count tick "
                         f"(shapes disagree by {ruler['shape_disagreement']:.4%}, before/after drift "
                         f"{(ruler.get('phase_drift') or 0.0):.4%}, intercept {ruler['intercept']:.1f} ticks)")
    if not report["ok"]:
        lines.append("")
        lines.append("NO HEADLINE NUMBER: a gate failed.")
        lines += [f"  GATE FAILED: {p}" for p in report["problems"]]
        lines.append("")
        lines.append(HONEST_FOOTER)
        return "\n".join(lines)
    lines.append(f"build revision: {revision or 'unrecorded'}; frames per repetition and reps are in the transcripts")
    lines.append("")
    lines.append(f"{'config/input':16s} {'ch':>3s} {'sect':>4s} {'f64 instr/frame':>16s} {'f32 instr/frame':>16s} "
                 f"{'delta':>9s} {'ratio':>6s} {'delta/section':>14s} {'f64 Minstr/s':>13s} {'f32 Minstr/s':>13s}")
    for key, row in sorted(report["rows"].items()):
        if row.get("refused_or_missing"):
            lines.append(f"{key:16s}  refused by admission or missing from one transcript (reported, not hidden)")
            continue
        per_section = f"{row['delta_per_section_per_frame']:.1f}" if row["delta_per_section_per_frame"] is not None else "-"
        lines.append(f"{key:16s} {row['channels']:3d} {row['sections']:4d} {row['f64_per_frame']:16.1f} "
                     f"{row['f32_per_frame']:16.1f} {row['delta_per_frame']:9.1f} {row['ratio']:6.3f} {per_section:>14s} "
                     f"{row['f64_minstr_per_second']:13.1f} {row['f32_minstr_per_second']:13.1f}")
    lines.append("")
    lines.append(f"Minstr/s is instructions per frame x {SAMPLE_RATE_HZ} frames/s: what a core must retire per second "
                 "to keep up, before cache or pipeline effects.")
    lines.append("")
    lines.append(HONEST_FOOTER)
    return "\n".join(lines)


def render_saving(report: dict[str, Any], revision_before: str | None, revision_after: str | None) -> str:
    """The table for `judge_conversion`. A figure is printed only if every gate passed."""
    lines: list[str] = []
    for label in ("before", "after"):
        analysis = report["analyses"].get(label)
        if analysis:
            ruler = analysis["ruler"]
            lines.append(f"[{label}] section realization seen by the guest: {analysis['variant']}; ruler: "
                         f"{ruler['instructions_per_tick']:.4f} instructions per Count tick "
                         f"(shapes disagree by {ruler['shape_disagreement']:.4%}, before/after drift "
                         f"{(ruler.get('phase_drift') or 0.0):.4%}, intercept {ruler['intercept']:.1f} ticks)")
    if not report["ok"]:
        lines.append("")
        lines.append("NO HEADLINE NUMBER: a gate failed.")
        lines += [f"  GATE FAILED: {p}" for p in report["problems"]]
        lines.append("")
        lines.append(HONEST_FOOTER)
        return "\n".join(lines)
    lines.append(f"before revision: {revision_before or 'unrecorded'}; after revision: {revision_after or 'unrecorded'}; "
                 "frames per repetition and reps are in the transcripts")
    lines.append("")
    lines.append(f"{'config/input':16s} {'ch':>3s} {'sect':>4s} {'before instr/frame':>19s} {'after instr/frame':>18s} "
                 f"{'saving':>9s} {'saving %':>9s} {'per channel':>12s} {'noise %':>8s} {'before Minstr/s':>16s} "
                 f"{'after Minstr/s':>15s}")
    for key, row in sorted(report["rows"].items()):
        if row.get("refused_or_missing"):
            lines.append(f"{key:16s}  refused by admission or missing from one transcript (reported, not hidden)")
            continue
        per_channel = f"{row['saving_per_channel_per_frame']:.1f}" if row["saving_per_channel_per_frame"] is not None else "-"
        lines.append(f"{key:16s} {row['channels']:3d} {row['sections']:4d} {row['before_per_frame']:19.1f} "
                     f"{row['after_per_frame']:18.1f} {row['saving_per_frame']:9.1f} {row['saving_fraction']:9.2%} "
                     f"{per_channel:>12s} {row['noise_fraction']:8.3%} {row['before_minstr_per_second']:16.1f} "
                     f"{row['after_minstr_per_second']:15.1f}")
    lines.append("")
    lines.append("saving = before - after, instructions per frame, with the SAME section state in both builds, so it is "
                 "what the one source change between them removed.")
    lines.append("noise % is the larger of the two builds' floor gaps (how closely their two lowest repetitions agreed); a "
                 "saving that is not clearly larger than it is not a result.")
    lines.append(f"Minstr/s is instructions per frame x {SAMPLE_RATE_HZ} frames/s: what a core must retire per second "
                 "to keep up, before cache or pipeline effects.")
    lines.append("")
    lines.append(HONEST_FOOTER)
    return "\n".join(lines)


# ---- QEMU ----------------------------------------------------------------------------------------------------------


def kernel_path() -> pathlib.Path:
    build = os.environ.get("FFW_BUILD_DIR")
    if not build:
        raise MeasurementError("FFW_BUILD_DIR is not set; it must contain kernels/xm/boot/ (the committed receipts "
                               f"record kernel digest {KERNEL_SHA256_PREFIX}...)")
    return pathlib.Path(build) / "kernels" / "xm" / "boot" / KERNEL_NAME


def run_guest(elf: pathlib.Path, work: pathlib.Path, label: str, timeout: float) -> tuple[str, dict[str, Any]]:
    """Pack `elf` as the guest's /init, boot it under QEMU with -icount, and return the serial transcript."""
    kernel = kernel_path()
    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if not digest.startswith(KERNEL_SHA256_PREFIX):
        raise MeasurementError(f"kernel digest {digest[:16]}... is not the committed {KERNEL_SHA256_PREFIX}...")
    mkinitramfs = _load(HERE / "mkinitramfs.py", "mkinitramfs_for_d02_cost")
    initramfs = work / f"{label}.cpio.gz"
    mkinitramfs.build(elf, initramfs)
    command = ["qemu-system-mips", "-M", "malta", "-cpu", "24Kf", "-m", "64M", "-nographic", "-no-reboot",
               "-icount", "shift=0,align=off,sleep=off", "-kernel", str(kernel), "-initrd", str(initramfs),
               "-append", "console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3"]
    version = subprocess.run(["qemu-system-mips", "--version"], capture_output=True, text=True, check=False).stdout
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout,
                                   stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or b"")
        text = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
        raise MeasurementError(f"{label}: QEMU did not finish within {timeout:.0f}s; last output: {text[-400:]!r}") from exc
    return completed.stdout, {"command": command, "qemu": version.splitlines()[0] if version else "unknown",
                              "kernel_sha256": digest, "exit_code": completed.returncode}


# ---- prepare -------------------------------------------------------------------------------------------------------


def central_commands(snapshot: pathlib.Path, label: str) -> str:
    target_dir = snapshot / "build" / "d02-cost-target"
    config_linker = f'target.{TARGET}.linker="{snapshot}/toolchain/linker/zig-cc-mips-be"'
    config_flags = f'target.{TARGET}.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
    return (f"cd {snapshot} && RCH_CANONICAL_PROJECT_ROOT={snapshot} RCH_REQUIRE_REMOTE=1 "
            f"RCH_WORKER=hz4,hz3,ts1 CARGO_TARGET_DIR={target_dir} rch exec -- cargo +nightly build --offline --release "
            f"--manifest-path {BENCH_REL}/Cargo.toml --target {TARGET} -Z build-std=core,alloc,std,panic_abort "
            f"--config '{config_linker}' --config '{config_flags}' -j 2"
            f"   # {label}; ELF: {target_dir}/{TARGET}/release/ffw-d02-cost")


def prepare(work_dir: pathlib.Path) -> str:
    """Create two snapshots of HEAD plus the benchmark crate, one with the control patch applied. Nothing is built,
    and nothing is deleted: an existing non-empty directory is refused."""
    if work_dir.exists() and any(work_dir.iterdir()):
        raise MeasurementError(f"{work_dir} exists and is not empty; choose a fresh directory (nothing is deleted)")
    plain, control = work_dir / "plain", work_dir / "control-f32"
    plain.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=REPO, capture_output=True, check=True)
    with tempfile.TemporaryFile() as handle:
        handle.write(archive.stdout)
        handle.seek(0)
        with tarfile.open(fileobj=handle, mode="r:") as tar:
            tar.extractall(plain, filter="data")
    shutil.copytree(REPO / BENCH_REL, plain / BENCH_REL, dirs_exist_ok=True)  # the crate may be uncommitted yet
    shutil.copy2(REPO / "Cargo.lock", plain / BENCH_REL / "Cargo.lock")      # a pin; cargo prunes it on the build
    shutil.copytree(plain, control)
    subprocess.run(["git", "apply", "-p1", str(plain / PATCH_REL)], cwd=control, check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
    return "\n".join([
        f"snapshots of HEAD {head} plus {BENCH_REL}:",
        f"  plain   (f64 section state, as shipped): {plain}",
        f"  control (f32 section state, patch applied): {control}",
        "",
        "Central build commands (RCH only; run each from its snapshot root, which this prints):",
        central_commands(plain, "f64"),
        central_commands(control, "f32 control"),
        "",
        "Also record the compiler the soft-float helpers come from:",
        f"  cd {plain} && RCH_CANONICAL_PROJECT_ROOT={plain} RCH_REQUIRE_REMOTE=1 rch exec -- rustc +nightly -vV",
        "",
        "Then:  FFW_BUILD_DIR=<kernel cache> python3 toolchain/src/measure-d02-cost.py run "
        "--elf-f64 <plain ELF> --elf-f32 <control ELF> --log-dir <fresh dir> --revision " + head])


# ---- command line --------------------------------------------------------------------------------------------------


def _elf_summary(label: str, info: dict[str, Any]) -> str:
    return (f"[{label}] ELF sha256 {info['sha256'][:16]}... {info['bytes']} bytes, e_flags {info['e_flags']:#010x}, "
            f"fp_abi {info['fp_abi']}, {info['exec_words']} executable words scanned, {len(info['fpu_words'])} FPU opcode word(s)")


def _compare_command(args: argparse.Namespace) -> int:
    """`compare`: boot (or read the transcripts of) a build before and after one source change, judge before - after."""
    run_mode = args.log_dir is not None
    any_log = args.log_before is not None or args.log_after is not None
    both_logs = args.log_before is not None and args.log_after is not None
    if not ((run_mode and not any_log) or (not run_mode and both_logs)):
        print("error: give either --log-dir (boot both ELFs) or both --log-before and --log-after (judge existing "
              "transcripts), not a mixture and not one log alone", file=sys.stderr)
        return 2
    try:
        elfs = {"before": read_elf(args.elf_before), "after": read_elf(args.elf_after)}
        for label, info in elfs.items():
            print(_elf_summary(label, info))
        if run_mode:
            if args.log_dir.exists() and any(args.log_dir.iterdir()):
                raise MeasurementError(f"{args.log_dir} is not empty; choose a fresh directory (nothing is deleted)")
            args.log_dir.mkdir(parents=True, exist_ok=True)
            texts = {}
            with tempfile.TemporaryDirectory() as scratch:
                for label, elf in (("before", args.elf_before), ("after", args.elf_after)):
                    text, meta = run_guest(elf, pathlib.Path(scratch), label, args.timeout)
                    (args.log_dir / f"d02-cost-{label}.serial.log").write_text(text)
                    print(f"[{label}] {meta['qemu']}; kernel {meta['kernel_sha256'][:8]}...; exit {meta['exit_code']}; "
                          f"{len(text.splitlines())} serial lines")
                    texts[label] = text
        else:
            texts = {"before": args.log_before.read_text(errors="replace"),
                     "after": args.log_after.read_text(errors="replace")}
        report = judge_conversion(texts["before"], texts["after"], elfs["before"], elfs["after"])
    except (MeasurementError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render_saving(report, args.revision_before, args.revision_after))
    if args.json:
        print(json.dumps({k: v for k, v in report.items() if k != "analyses"}, indent=1, sort_keys=True, default=str))
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--work-dir", type=pathlib.Path, required=True)
    p = sub.add_parser("compare", help="the saving one source change made, with the same section state in both builds")
    p.add_argument("--elf-before", type=pathlib.Path, required=True)
    p.add_argument("--elf-after", type=pathlib.Path, required=True)
    p.add_argument("--revision-before", help="the git revision (or description) the before ELF was built from")
    p.add_argument("--revision-after", help="the git revision (or description) the after ELF was built from")
    p.add_argument("--json", action="store_true", help="also print the judged result as JSON on stdout")
    p.add_argument("--log-dir", type=pathlib.Path, help="fresh directory for the raw serial logs; boots both ELFs")
    p.add_argument("--timeout", type=float, default=900.0)
    p.add_argument("--log-before", type=pathlib.Path, help="judge an existing transcript instead of booting")
    p.add_argument("--log-after", type=pathlib.Path, help="judge an existing transcript instead of booting")
    for name in ("run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--elf-f64", type=pathlib.Path, required=True)
        p.add_argument("--elf-f32", type=pathlib.Path, required=True)
        p.add_argument("--revision", help="the git revision both ELFs were built from (recorded in the output)")
        p.add_argument("--json", action="store_true", help="also print the judged result as JSON on stdout")
        if name == "run":
            p.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial logs")
            p.add_argument("--timeout", type=float, default=900.0)
        else:
            p.add_argument("--log-f64", type=pathlib.Path, required=True)
            p.add_argument("--log-f32", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            print(prepare(args.work_dir))
            return 0
        if args.command == "compare":
            return _compare_command(args)
        elfs = {"f64": read_elf(args.elf_f64), "f32": read_elf(args.elf_f32)}
        for label, info in elfs.items():
            print(_elf_summary(label, info))
        if args.command == "run":
            if args.log_dir.exists() and any(args.log_dir.iterdir()):
                raise MeasurementError(f"{args.log_dir} is not empty; choose a fresh directory (nothing is deleted)")
            args.log_dir.mkdir(parents=True, exist_ok=True)
            texts = {}
            with tempfile.TemporaryDirectory() as scratch:
                for label, elf in (("f64", args.elf_f64), ("f32", args.elf_f32)):
                    text, meta = run_guest(elf, pathlib.Path(scratch), label, args.timeout)
                    (args.log_dir / f"d02-cost-{label}.serial.log").write_text(text)
                    print(f"[{label}] {meta['qemu']}; kernel {meta['kernel_sha256'][:8]}...; exit {meta['exit_code']}; "
                          f"{len(text.splitlines())} serial lines")
                    texts[label] = text
        else:
            texts = {"f64": args.log_f64.read_text(errors="replace"), "f32": args.log_f32.read_text(errors="replace")}
        report = judge(texts["f64"], texts["f32"], elfs["f64"], elfs["f32"])
    except (MeasurementError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(report, getattr(args, "revision", None)))
    if getattr(args, "json", False):
        print(json.dumps({k: v for k, v in report.items() if k != "analyses"}, indent=1, sort_keys=True, default=str))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
