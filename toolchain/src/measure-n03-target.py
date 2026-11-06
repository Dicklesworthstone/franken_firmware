#!/usr/bin/env python3
"""Measure and judge N03's group clock on the soft-float big-endian MIPS device target, under QEMU.

Bead ffw-u07: the clock does 64-bit and 128-bit integer arithmetic, a rational least-squares rate fit and `f64` on a 32-bit
big-endian soft-float target, which is where host-green code can differ, and `docs/contracts/n03.md` listed "the clock on
the target ISA" as not measured. The guest (`toolchain/src/n03-target`, PID 1 of the existing Debian/Malta guest) prints
`FFW_N03T_*` lines; this script runs it and JUDGES the transcript. Three questions, all bounded by what a QEMU guest can say:

  WORLDS   the 32 scripted worlds of tests/n03/vectors.json and the two members of the mixed-generation join, one record per
           op, compared with the INDEPENDENT Python reference (`tests/n03/reference.py`, through the N03 runner's own
           `judge_world`, which re-derives the expectation now) and byte-for-byte (a digest per world) with the host build of
           the same source file (`crates/franken-clock/tests/n03_target_worlds.rs`). Equal is the expected result; a
           difference is a finding about the target ISA, reported as such and not adjusted.
  SEEDED   two simulated worlds (coordinator clock, member clock with offset, skew and resolution, seeded asymmetric delay,
           jitter and loss) whose LCG seeds are derived from a per-run seed the host packs into the initramfs. The figures
           are re-derived here by a mirror of the reference's `Sim`, so a transcript from another run, canned records or
           records copied from the host build cannot carry the right ones.
  CPU      guest INSTRUCTIONS for a steady stream of exchanges (`next_probe` + `on_response`) and for the per-block gate path
           (`tick`, `local_for_group`, `output`), through the D02/D03 ruler discipline: calibrated in the same boot against
           loops of known instruction count before AND after, after a settling sleep, with nothing printed until everything
           is measured, with a drift gate that fails the whole CPU result.

REPLAY DEFENCE. `run --plant replay` boots the same ELF under a NEW seed with the first run's world and seeded-world lines in
a `/replay` file; the judge must fail it on `N03T-SEEDED`. `--plant truncate` cuts a good transcript short and requires the same.

WHAT THE NUMBERS ARE. Instructions executed under QEMU TCG with `-icount shift=0` on QEMU's 24Kf model. Not cycles on a real
core: no cache, pipeline, memory latency or multiplier timing is modelled, soft-float helper calls count as the instructions
they execute, and no board clock is involved (the repository records none for any MIPS board). Nothing here says anything
about the real DAC or acoustic path: the clock fit is a network-clock fit only. The ruler/gate code is the D03 judge's
(`measure-d03-target.py`, imported, not edited).

    measure-n03-target.py prepare --work-dir DIR        snapshot HEAD + the guest crate; print the central commands
    measure-n03-target.py run --elf E --log-dir D [--seed N] [--host-log L] [--plant replay|truncate]
    measure-n03-target.py analyze --log L --elf E --seed N [--host-log L]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import shlex
import pathlib
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BENCH_REL = "toolchain/src/n03-target"
TARGET = "mips-unknown-linux-musl"
SAMPLE_RATE_HZ = 48_000
BLOCK_NS = 16_000_000 / 3          # one 256-frame block at 48 kHz
EXCHANGE_EVERY_BLOCKS = 32        # the harness's probe cadence (about 170 ms)

# Gates. Thresholds are stated here so a reader can argue with them.
RULER_LO_INSTR = 3 * 1_300_000     # the smallest and largest regions the guest's ruler calibrates (spin3 and spin5)
RULER_HI_INSTR = 5 * 12_000_000
RANGE_SLACK = 0.1                  # a timed region may sit this far outside the calibrated range before it is called extrapolated
MIN_INSTR_PER_OP = 200             # an exchange or a gate call below this did not run the clock
MAX_INSTR_PER_OP = 20_000_000


def _load(path: pathlib.Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


D = _load(HERE / "measure-d03-target.py", "d03_target_judge_for_n03")   # ruler, ELF reader, QEMU run, Gate: reused as they are
N = _load(REPO / "tests" / "n03" / "run_cases.py", "n03_runner_for_target")  # judge_world, the reference and its generator
ref = N.ref
MeasurementError = D.MeasurementError
Gate = D.Gate
splitmix64 = D.splitmix64


# ---- bit-exact mirrors of cases.rs ---------------------------------------------------------------------------------

SIM_SHAPES = ((90_000, 100, 300, 0, 10, 300), (25_000, 200, 800, 400, 20, 600))
NS = 10 ** 9


def sim_seed(run_seed: int, index: int) -> int:
    return splitmix64(run_seed ^ (0x4E30335300000000 | index)) >> 32


def fnv1a64_lines(lines: list[str]) -> int:
    h = 0xCBF29CE484222325
    for line in lines:
        for b in line.encode("utf-8") + b"\n":
            h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def sim_counted(seed32: int, skew: int, base: int, jitter: int, asym: int, loss: int, seconds: int) -> dict[str, Any]:
    """The simulated world of `cases.rs::run_sim`, run through the reference's own `Sim` and `Model` and counted instead of
    asserted. On the five fixed worlds of the host test it equals `ref.sim_run` (tests/test_measure_n03_target.py)."""
    sim = ref.Sim(seed32, skew)
    model = ref.Model(None, 1, 7, seed32 << 20)
    run: dict[str, Any] = {"seed32": seed32, "probes": 0, "lost": 0, "rejected": 0, "checks": 0, "violations": 0,
                           "max_err": 0, "max_unc": 0, "min_margin": None, "locked": False, "resets": 0}
    for k in range(seconds):
        ts = k * NS + sim.rand() % 5_000_000
        req = model.next_probe(sim.local(ts))
        run["probes"] += 1
        if sim.rand() % 100 < loss:
            run["lost"] += 1
            continue
        df = (base + sim.rand() % (jitter + 1) + asym) * 1000
        dr = (base + sim.rand() % (jitter + 1)) * 1000
        dwell = 40_000
        resp = {"epoch": req["epoch"], "leader": 7, "seq": req["seq"], "t1_echo": req["t1"],
                "t2": sim.group(ts + df), "t3": sim.group(ts + df + dwell)}
        t_end = ts + df + dwell + dr
        verdict, _info = model.on_response(resp, sim.local(t_end))
        if verdict != "ok":
            run["rejected"] += 1
            continue
        t_now = t_end + 1_500_000
        now = sim.local(t_now)
        anchor = model._anchor(now)
        if anchor is not None:
            err = abs(ref.group_at(anchor["sample"], now, anchor["ratio"]) - sim.group(t_now))
            if err > anchor["unc"]:
                run["violations"] += 1
            run["checks"] += 1
            run["max_err"] = max(run["max_err"], err)
            run["max_unc"] = max(run["max_unc"], anchor["unc"])
            margin = max(anchor["unc"] - err, 0)
            run["min_margin"] = margin if run["min_margin"] is None else min(run["min_margin"], margin)
    run["locked"] = model.status(sim.local(seconds * NS)) != "Unlocked"
    run["resets"] = model.stats["resets"]
    return run


# ---- the transcript ------------------------------------------------------------------------------------------------

MARKER = re.compile(r"FFW_N03T_([A-Z_0-9]+)(?: (.*))?$")
STEP = re.compile(r"id=(\S+) i=(\d+) (\{.*\})$")
PAIRS = re.compile(r"(\w+)=(\[[^\]]*\]|\S+)")
HOST = re.compile(r"N03-TARGET-HOST (\{.*\})\s*$")


def _pairs(rest: str) -> dict[str, str]:
    return {key: value for key, value in PAIRS.findall(rest or "")}


def _opt_int(text: str) -> int | None:
    return None if text == "none" else int(text)


def parse_transcript(text: str) -> dict[str, Any]:
    """Strict parse of the `FFW_N03T_*` lines. Kernel chatter is ignored; a marker line that does not parse is an error."""
    out: dict[str, Any] = {"alive": False, "begin": None, "seed": "absent", "empty": None, "ruler": [], "warm": {}, "runs": [],
                           "stats": None, "worlds": {}, "sims": {}, "end": False, "reboot_failed": False, "host_build": False,
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
                out["warm"][p["region"]] = {k: int(v) for k, v in p.items() if k != "region"}
            elif kind == "RUN":
                p = _pairs(rest)
                out["runs"].append({"region": p["region"], "rep": int(p["rep"]), "ops": int(p["ops"]), "done": int(p["done"]),
                                    "ticks": int(p["ticks"])})
            elif kind == "STATS":
                out["stats"] = {k: int(v) for k, v in _pairs(rest).items()}
            elif kind == "STEP":
                m = STEP.match(rest)
                if not m:
                    raise MeasurementError("unparsable STEP")
                world = out["worlds"].setdefault(m.group(1), {"steps": {}, "end": None})
                index = int(m.group(2))
                if index in world["steps"]:
                    raise MeasurementError(f"step {index} of {m.group(1)} appears twice")
                if index != len(world["steps"]):
                    raise MeasurementError(f"step {index} of {m.group(1)} is out of order (the next record is {len(world['steps'])})")
                world["steps"][index] = m.group(3)
            elif kind == "WEND":
                p = _pairs(rest)
                world = out["worlds"].setdefault(p["id"], {"steps": {}, "end": None})
                if world["end"] is not None:
                    raise MeasurementError(f"world {p['id']} ends twice")
                world["end"] = {"steps": int(p["steps"]), "fnv": int(p["fnv"], 16), "checks": int(p["checks"]),
                                "max_err": int(p["max_err"]), "max_unc": int(p["max_unc"]), "min_margin": _opt_int(p["min_margin"])}
            elif kind == "SIM":
                p = _pairs(rest)
                idx = int(p["idx"])
                if idx in out["sims"]:
                    raise MeasurementError(f"seeded world {idx} appears twice")
                out["sims"][idx] = {"run_seed": int(p["run_seed"]), "seed32": int(p["seed32"]), "probes": int(p["probes"]),
                                    "lost": int(p["lost"]), "rejected": int(p["rejected"]), "checks": int(p["checks"]),
                                    "violations": int(p["violations"]), "max_err": int(p["max_err"]), "max_unc": int(p["max_unc"]),
                                    "min_margin": _opt_int(p["min_margin"]), "locked": p["locked"] == "1", "resets": int(p["resets"])}
            elif kind == "END":
                out["end"] = True
            elif kind == "REBOOT_FAILED":
                out["reboot_failed"] = True
            elif kind == "HOST_BUILD":
                out["host_build"] = True
            elif kind == "REPLAY_MISSING":
                out["replay_missing"] = True
            else:
                raise MeasurementError(f"unknown marker FFW_N03T_{kind}")
        except (KeyError, ValueError) as exc:
            raise MeasurementError(f"malformed FFW_N03T_{kind} line {raw.strip()[:120]!r}: {exc!r}") from exc
    return out


def parse_host_log(text: str) -> dict[str, dict[str, Any]]:
    """The host build's `N03-TARGET-HOST {json}` records, by world id."""
    records: dict[str, dict[str, Any]] = {}
    for raw in text.replace("\r", "").split("\n"):
        found = HOST.search(raw)
        if found:
            rec = json.loads(found.group(1))
            if rec["id"] in records and records[rec["id"]] != rec:
                raise MeasurementError(f"the host log has two different records for {rec['id']}")
            records[rec["id"]] = rec
    return records


# ---- the gates -----------------------------------------------------------------------------------------------------


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


def cpu_analysis(t: dict[str, Any]) -> tuple[list[str], dict[str, Any], dict[str, Any] | None]:
    """(problems, per-region table, ruler)."""
    problems: list[str] = []
    ruler = D.ruler_analysis(t["ruler"])
    problems += D.ruler_problems(ruler)
    begin = t["begin"]
    reps, warm_n = begin["reps"], begin["warm_exchanges"]
    want_ops = {"exchange": begin["exchanges_per_rep"], "gate": begin["gate_calls_per_rep"]}
    table: dict[str, Any] = {}
    warm = t["warm"].get("exchange")
    if warm is None or warm.get("exchanges") != warm_n or warm.get("accepted") != warm_n:
        problems.append(f"the warm-up did not accept all {warm_n} exchanges ({warm})")
    gate_warm = t["warm"].get("gate")
    if gate_warm is None or gate_warm.get("mapped") != 1:
        problems.append(f"the clock was not locked and mapping presentation times before the gate region ({gate_warm})")
    stats = t["stats"]
    if stats is None:
        problems.append("the STATS line is missing")
    elif stats["accepted"] != warm_n + reps * want_ops["exchange"] or stats["resets"] != 0:
        problems.append(f"the clock accepted {stats['accepted']} exchanges with {stats['resets']} resets; expected "
                        f"{warm_n + reps * want_ops['exchange']} and none")
    for region, ops_per_rep in want_ops.items():
        runs = sorted((r for r in t["runs"] if r["region"] == region), key=lambda r: r["rep"])
        if len(runs) < D.MIN_REPS or [r["rep"] for r in runs] != list(range(len(runs))):
            problems.append(f"{region} has repetitions {[r['rep'] for r in runs]}, need {D.MIN_REPS}+ in order")
            continue
        if any(r["ops"] != ops_per_rep or r["done"] != ops_per_rep for r in runs):
            problems.append(f"{region}: a repetition did not complete every operation "
                            f"({[(r['ops'], r['done']) for r in runs]}): the work was not all real")
            continue
        ticks = [r["ticks"] for r in runs]
        instructions = [(tk - ruler["intercept"]) / ruler["slope"] for tk in ticks]
        per_op = [i / ops_per_rep for i in instructions]
        if min(per_op) < MIN_INSTR_PER_OP or max(per_op) > MAX_INSTR_PER_OP:
            problems.append(f"{region} reads {min(per_op):.0f}..{max(per_op):.0f} instructions per operation, outside "
                            f"{MIN_INSTR_PER_OP}..{MAX_INSTR_PER_OP}: the region or the ruler is wrong")
        lo, hi = RULER_LO_INSTR * (1 - RANGE_SLACK), RULER_HI_INSTR * (1 + RANGE_SLACK)
        if not lo <= min(instructions) or not max(instructions) <= hi:
            problems.append(f"{region}: a repetition runs {min(instructions) / 1e6:.2f}..{max(instructions) / 1e6:.2f} M "
                            f"instructions, outside the ruler's calibrated {RULER_LO_INSTR / 1e6:.1f}..{RULER_HI_INSTR / 1e6:.0f} M: "
                            f"the figure would be extrapolated (change the repetition size and re-run)")
        lowest = sorted(ticks)[:2]
        floor_gap = (lowest[1] - lowest[0]) / lowest[0] if lowest[0] > 0 else float("inf")
        if floor_gap > D.FLOOR_AGREEMENT_LIMIT:
            problems.append(f"{region}: the two lowest repetitions differ by {floor_gap:.2%} "
                            f"(limit {D.FLOOR_AGREEMENT_LIMIT:.0%}): no stable floor to read")
        summary = D._summary(per_op)
        table[region] = {"instructions_per_op": summary, "ops_per_rep": ops_per_rep, "floor_gap": floor_gap,
                         "inflated_reps": sum(1 for tk in ticks if tk > lowest[0] * (1 + D.INFLATED_REP))}
    if "exchange" in table and "gate" in table:
        ex, ga = table["exchange"]["instructions_per_op"]["min"], table["gate"]["instructions_per_op"]["min"]
        blocks_per_s = SAMPLE_RATE_HZ / 256
        table["per_second_of_audio"] = {"minstr": (ga * blocks_per_s + ex * blocks_per_s / EXCHANGE_EVERY_BLOCKS) / 1e6,
                                        "assumes": f"one gate call per 256-frame block and one exchange per {EXCHANGE_EVERY_BLOCKS} blocks"}
    return problems, table, ruler


def worlds_analysis(t: dict[str, Any], vec: dict[str, Any], host: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    """Every world: complete, internally consistent, equal to the reference, and equal to the host build."""
    problems: list[str] = []
    host_problems: list[str] = []
    failed: list[str] = []
    wanted = list(vec["worlds"]) + [m["world"] for m in vec["mixed"]["members"]]
    known = {w["id"] for w in wanted}
    for extra in sorted(set(t["worlds"]) - known):
        problems.append(f"{extra}: a world the vectors do not have")
    compared = 0
    for wdef in wanted:
        wid = wdef["id"]
        world = t["worlds"].get(wid)
        if world is None:
            problems.append(f"{wid}: no records in the transcript")
            failed.append(wid)
            continue
        end, steps = world["end"], world["steps"]
        if end is None:
            problems.append(f"{wid}: the world has no WEND line: it was cut short")
            failed.append(wid)
            continue
        if sorted(steps) != list(range(len(wdef["ops"]))) or end["steps"] != len(wdef["ops"]):
            problems.append(f"{wid}: {len(steps)} records printed, {end['steps']} claimed, {len(wdef['ops'])} ops in the world: "
                            "the dump is truncated or has gaps")
            failed.append(wid)
            continue
        lines = [steps[i] for i in range(len(steps))]
        if fnv1a64_lines(lines) != end["fnv"]:
            problems.append(f"{wid}: the printed records do not hash to the WEND digest: corrupted or truncated data")
            failed.append(wid)
            continue
        try:
            records = [json.loads(line) for line in lines]
        except ValueError as exc:
            problems.append(f"{wid}: a record is not JSON ({exc})")
            failed.append(wid)
            continue
        rec = {"kind": "world", "id": wid, "steps": records,
               "truth": {"checks": end["checks"], "max_err_ns": end["max_err"], "max_unc_ns": end["max_unc"],
                         "min_margin_ns": end["min_margin"]}}
        verdict = N.judge_world(rec, wdef)
        if verdict:
            problems.append(f"{wid}: {verdict} (reported, not adjusted)")
            failed.append(wid)
            continue
        if host is None:
            continue
        h = host.get(wid)
        if h is None:
            host_problems.append(f"{wid}: no host-build record in the host log")
        elif h["steps"] == end["steps"] and int(h["fnv"], 16) == end["fnv"]:
            compared += 1
        else:
            host_problems.append(f"{wid}: the target-ISA records DIFFER from the host build's (guest digest {end['fnv']:016x}, host "
                                 f"{h['fnv']}); the guest agrees with the independent reference. This is a finding about the target "
                                 "ISA, not something to adjust.")
    if host is not None:
        # A world whose records failed the checks above was never compared: the byte gate must not read that as identical.
        host_problems += [f"{wid}: not compared with the host build, its records failed the checks" for wid in failed]
    return {"problems": problems, "host_problems": host_problems, "compared": compared, "worlds": len(wanted)}


def seeded_analysis(t: dict[str, Any], seed: int | None) -> dict[str, Any]:
    problems: list[str] = []
    rows: dict[str, Any] = {}
    if seed is None:
        return {"rows": rows, "problems": ["no --seed was given: the seeded worlds cannot be judged"]}
    if t["seed"] != seed:
        problems.append(f"the guest echoed seed {t['seed']!r}, this run's seed is {seed}: a transcript from another run, "
                        "or a guest that did not see the seed")
    for index, shape in enumerate(SIM_SHAPES):
        got = t["sims"].get(index)
        if got is None:
            problems.append(f"seeded world {index}: no SIM line in the transcript")
            continue
        want_seed32 = sim_seed(seed, index)
        if got["run_seed"] != seed or got["seed32"] != want_seed32:
            problems.append(f"seeded world {index}: the guest used run seed {got['run_seed']} / LCG seed {got['seed32']}, this run's "
                            f"seed derives {seed} / {want_seed32}: the records were not computed from this run's seed")
            continue
        want = sim_counted(want_seed32, *shape)
        diffs = [f"{k} {got[k]} against {want[k]}" for k in want if got.get(k) != want[k]]
        rows[f"seed-{index}"] = {"shape": shape, "seed32": want_seed32, "got": got, "match": not diffs}
        if diffs:
            problems.append(f"seeded world {index}: figures differ from the reference's for this run's seed ({'; '.join(diffs[:4])}): "
                            "the records were not computed from this run's seed, or the target decides differently")
    return {"rows": rows, "problems": problems}


def judge(text: str, elf: dict[str, Any] | None, seed: int | None, host_text: str | None, vec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse and judge a transcript. Every gate is reported; `ok` is true only if none failed or is blocked."""
    vec = vec or json.loads((REPO / "tests" / "n03" / "vectors.json").read_text())
    gates: list[Gate] = []
    try:
        t = parse_transcript(text)
    except MeasurementError as exc:
        return {"ok": False, "gates": [Gate("N03T-TRANSCRIPT", "failed", str(exc))], "cpu": {}, "worlds": {}, "seeded": {}, "ruler": None}
    tp = transcript_problems(t)
    gates.append(Gate("N03T-TRANSCRIPT", "failed" if tp else "passed", "; ".join(tp) or "complete: ALIVE, BEGIN, END"))
    if tp and (t["begin"] is None or not t["end"]):
        return {"ok": False, "gates": gates, "cpu": {}, "worlds": {}, "seeded": {}, "ruler": None}
    if elf is None:
        gates.append(Gate("N03T-ELF", "blocked", "no --elf: soft-float is not proven"))
    else:
        ep = []
        if elf["fpu_words"]:
            ep.append(f"{len(elf['fpu_words'])} FPU opcode word(s) in executable sections (first: {elf['fpu_words'][0]}); soft-float is NOT proven")
        if elf["fp_abi"] is not None and elf["fp_abi"] != D.FP_ABI_SOFT:
            ep.append(f".MIPS.abiflags fp_abi is {elf['fp_abi']}, not {D.FP_ABI_SOFT} (soft)")
        gates.append(Gate("N03T-ELF", "failed" if ep else "passed",
                          "; ".join(ep) or f"32-bit big-endian MIPS, {elf['exec_words']} executable words, no FPU opcodes"))
    try:
        cp, cpu, ruler = cpu_analysis(t)
    except MeasurementError as exc:
        cp, cpu, ruler = [str(exc)], {}, None
    gates.append(Gate("N03T-CPU", "failed" if cp else "passed", "; ".join(cp) or "ruler gates held; every region has a stable floor"))
    host = parse_host_log(host_text) if host_text is not None else None
    worlds = worlds_analysis(t, vec, host)
    gates.append(Gate("N03T-WORLDS", "failed" if worlds["problems"] else "passed",
                      "; ".join(worlds["problems"][:6]) or f"all {worlds['worlds']} worlds equal the independent reference, record by record"))
    seeded = seeded_analysis(t, seed)
    gates.append(Gate("N03T-SEEDED", "failed" if seeded["problems"] else "passed",
                      "; ".join(seeded["problems"]) or "the seeded worlds carry this run's seed and match the reference's figures"))
    if host_text is None:
        gates.append(Gate("N03T-HOST-BYTES", "blocked", "no --host-log: the host build's digests were not supplied"))
    else:
        gates.append(Gate("N03T-HOST-BYTES", "failed" if worlds["host_problems"] else "passed",
                          "; ".join(worlds["host_problems"][:6]) or f"every one of the {worlds['worlds']} worlds is byte-identical to the host build"))
    ok = all(g.status == "passed" for g in gates)
    return {"ok": ok, "gates": gates, "cpu": cpu, "worlds": worlds, "seeded": seeded["rows"], "ruler": ruler}


def exit_code(report: dict[str, Any]) -> int:
    statuses = {g.status for g in report["gates"]}
    return 1 if "failed" in statuses else 3 if "blocked" in statuses else 0


# ---- reporting -----------------------------------------------------------------------------------------------------

HONEST_FOOTER = (
    "These are INSTRUCTIONS EXECUTED under QEMU TCG (-icount shift=0) on QEMU's 24Kf model, read through a ruler\n"
    "calibrated in the guest, not cycles on a real core: no cache, pipeline, memory latency or multiplier timing is\n"
    "modelled, and no board clock is involved. The world records are the clock's decisions on the target ISA, judged against\n"
    "the independent reference; the clock is a network-clock fit only and says nothing about the real DAC or acoustic path.")


def render(report: dict[str, Any], revision: str | None) -> str:
    lines: list[str] = []
    ruler = report.get("ruler")
    if ruler:
        lines.append(f"ruler: {ruler['instructions_per_tick']:.4f} instructions per Count tick (shapes disagree by "
                     f"{ruler['shape_disagreement']:.4%}, before/after drift {(ruler.get('phase_drift') or 0.0):.4%}, "
                     f"intercept {ruler['intercept']:.1f} ticks)")
    for g in report["gates"]:
        lines.append(f"{g.status.upper():8s} {g.gate_id:16s} {g.detail}")
    cpu_ok = next((g.status == "passed" for g in report["gates"] if g.gate_id == "N03T-CPU"), False)
    if report["cpu"] and cpu_ok:
        lines += ["", f"build revision: {revision or 'unrecorded'}", "",
                  f"{'region':10s} {'instr/op min':>14s} {'median':>10s} {'max':>10s}"]
        for region in ("exchange", "gate"):
            row = report["cpu"].get(region)
            if row:
                s = row["instructions_per_op"]
                lines.append(f"{region:10s} {s['min']:14.1f} {s['median']:10.1f} {s['max']:10.1f}")
        extra = report["cpu"].get("per_second_of_audio")
        if extra:
            lines += ["", f"about {extra['minstr']:.2f} Minstr/s of one member's clock work ({extra['assumes']}), before cache or pipeline effects."]
    elif report["cpu"]:
        lines += ["", "NO CPU HEADLINE NUMBER: a CPU gate failed."]
    lines += ["", HONEST_FOOTER]
    return "\n".join(lines)


# ---- QEMU ----------------------------------------------------------------------------------------------------------


def replay_lines_of(text: str) -> str:
    """The world and seeded-world lines of a transcript, for the replay plant."""
    keep = [ln for ln in text.replace("\r", "").split("\n") if re.search(r"FFW_N03T_(STEP|WEND|SIM)\b", ln)]
    return "\n".join(keep) + "\n"


def truncate_dump(text: str, fraction: float = 0.6) -> str:
    """The planted truncation: the transcript cut off partway through the world records."""
    lines = text.replace("\r", "").split("\n")
    steps = [i for i, ln in enumerate(lines) if "FFW_N03T_STEP" in ln]
    cut = steps[int(len(steps) * fraction)]
    return "\n".join(lines[:cut]) + "\n"


def corrupt_one_step(text: str) -> str:
    """The planted divergence: one record of one world differs (a status flipped), every digest and count left as printed."""
    lines = text.replace("\r", "").split("\n")
    for i, ln in enumerate(lines):
        if "FFW_N03T_STEP" in ln and '"status":"Locked"' in ln:
            lines[i] = ln.replace('"status":"Locked"', '"status":"Holdover"', 1)
            return "\n".join(lines)
    raise MeasurementError("no Locked status record to corrupt")


# ---- prepare -------------------------------------------------------------------------------------------------------


def central_commands(snapshot: pathlib.Path, label: str) -> str:
    target_dir = snapshot / "build" / "n03-target-target"
    config_linker = f'target.{TARGET}.linker="toolchain/linker/zig-cc-mips-be"'
    config_flags = f'target.{TARGET}.rustflags=["-C","target-feature=+crt-static","-C","link-self-contained=no"]'
    source_arg = shlex.quote(str(snapshot))
    return (f"cd {source_arg} && RCH_CANONICAL_PROJECT_ROOT={source_arg} RCH_REQUIRE_REMOTE=1 "
            f"RCH_BUILD_SLOTS=1 CARGO_TARGET_DIR={shlex.quote(str(target_dir))} "
            f"rch exec --source-content-receipt -- cargo +nightly-2026-08-31 build --locked --offline --release "
            f"--manifest-path {BENCH_REL}/Cargo.toml --bin ffw-n03-target --target {TARGET} "
            f"-Z build-std=core,alloc,std,panic_abort --config '{config_linker}' --config '{config_flags}' "
            f"--message-format=json -j 1"
            f"   # {label}; ELF: {str(target_dir / TARGET / 'release' / 'ffw-n03-target')!r}")


def copy_guest_snapshot(source_repo: pathlib.Path, destination: pathlib.Path) -> None:
    """Preserve the guest's resolved lock; a workspace lock would be rewritten by Cargo during the build."""
    guest = source_repo / BENCH_REL
    if not (guest / "Cargo.lock").is_file():
        raise MeasurementError("the standalone N03 guest Cargo.lock is missing; resolve it before preparing an immutable build")
    shutil.copytree(guest, destination / BENCH_REL, dirs_exist_ok=True)


def prepare(work_dir: pathlib.Path) -> str:
    """Snapshot HEAD plus the guest crate (it may be uncommitted yet). Nothing is built; nothing is deleted."""
    work_dir = work_dir.resolve()
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
    copy_guest_snapshot(REPO, plain)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
    return "\n".join([
        f"snapshot of HEAD {head} plus {BENCH_REL}: {plain}",
        "",
        "Central guest build (RCH only; run from the snapshot root):",
        central_commands(plain, "N03 target guest"),
        "",
        "Host digests (the same cases.rs; run from this prepared snapshot):",
        f"  cd {shlex.quote(str(plain))} && RCH_REQUIRE_REMOTE=1 RCH_TEST_SLOTS=1 rch exec -- "
        "cargo +nightly-2026-08-31 test --locked -p franken-clock --test n03_target_worlds -j 1 -- --nocapture",
        "",
        "Then:  FFW_BUILD_DIR=<kernel cache> python3 toolchain/src/measure-n03-target.py run --elf <ELF> "
        "--log-dir <fresh dir> --host-log <the cargo test log>",
        "Add --revision only after verifying that the live guest overlay is committed unchanged; HEAD above is the archive base."])


# ---- command line --------------------------------------------------------------------------------------------------


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
        p.add_argument("--host-log", type=pathlib.Path, help="the central `cargo test --test n03_target_worlds` output")
        p.add_argument("--revision", help="the git revision the ELF was built from (recorded in the output)")
        p.add_argument("--json", action="store_true", help="also print the judged result as JSON on stdout")
        if name == "run":
            p.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial logs")
            p.add_argument("--timeout", type=float, default=1200.0)
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
        elf = D.read_elf(args.elf)
        print(D._elf_summary(elf))
        host_text = args.host_log.read_text(errors="replace") if args.host_log else None
        plants_ok = True
        if args.command == "run":
            if args.log_dir.exists() and any(args.log_dir.iterdir()):
                raise MeasurementError(f"{args.log_dir} is not empty; choose a fresh directory (nothing is deleted)")
            args.log_dir.mkdir(parents=True, exist_ok=True)
            seed = args.seed if args.seed is not None else secrets.randbits(62)
            with tempfile.TemporaryDirectory() as scratch:
                text, meta = D.run_guest(args.elf, pathlib.Path(scratch), "run", args.timeout,
                                         [("ffw_seed", D.S_IFREG_644, f"{seed}\n".encode())])
                (args.log_dir / "n03-target.serial.log").write_text(text)
                (args.log_dir / "seed.txt").write_text(f"{seed}\n")
                print(f"{meta['qemu']}; kernel {meta['kernel_sha256'][:8]}...; exit {meta['exit_code']}; "
                      f"{len(text.splitlines())} serial lines; seed {seed}")
                report = judge(text, elf, seed, host_text)
                if args.plant == "truncate":
                    cut = truncate_dump(text)
                    (args.log_dir / "plant-truncate.serial.log").write_text(cut)
                    plants_ok = _plant_report("truncated dump", judge(cut, elf, seed, host_text), ("N03T-TRANSCRIPT", "N03T-WORLDS"))
                if args.plant == "replay":
                    other = secrets.randbits(62)
                    replay_text, _ = D.run_guest(args.elf, pathlib.Path(scratch), "replay", args.timeout, [
                        ("ffw_seed", D.S_IFREG_644, f"{other}\n".encode()), ("plant-replay", D.S_IFREG_644, b"1\n"),
                        ("replay", D.S_IFREG_644, replay_lines_of(text).encode())])
                    (args.log_dir / "plant-replay.serial.log").write_text(replay_text)
                    plants_ok = _plant_report(f"replayed records under seed {other}", judge(replay_text, elf, other, host_text),
                                              ("N03T-SEEDED",))
        else:
            text = args.log.read_text(errors="replace")
            report = judge(text, elf, args.seed, host_text)
    except (MeasurementError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(report, getattr(args, "revision", None)))
    if getattr(args, "json", False):
        print(json.dumps({"ok": report["ok"], "gates": [vars(g) for g in report["gates"]], "cpu": report["cpu"],
                          "seeded": report["seeded"]}, indent=1, sort_keys=True, default=str))
    code = exit_code(report)
    return code if plants_ok else 1


if __name__ == "__main__":
    sys.exit(main())
