#!/usr/bin/env python3
"""G02 slice 2 (ffw-ld0) end-to-end runner and judge: known PCM through D02 while the controls change.

    pcm_run.py [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds nothing. Same contract as the other judges:

* META  - reference self-checks (FNV-1a and LCG test vectors, the ramp step), the committed
          ``pcm_vectors.json`` equals a fresh generation, every invariant is cited by a case.
* JUDGE - reads the ``cargo test`` output of the centrally run suite (``--judge LOG``) and, for every
          ``G02PCM-OBSERVED`` line, (1) compares it with the reference simulation FRAME BY FRAME and
          (2) checks properties on the raw PCM with arithmetic of its own, so the verdict does not
          rest on the same-author model: linearity against the unity-gain output, exact silence, the
          limiter/thermal certificate, non-vacuous channels, role pairs, bounds on the gain.

Anything with no Rust observation is ``blocked`` (never passed). Exit codes: 0 qualified, 1 a case
failed, 3 only blocked cases stand in the way, 2 usage/malformed.

The central command (RCH only), run together with the slice 1 and workspace suites:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp --test g02_pcm -- --nocapture

NUMERICAL TESTS DO NOT PROVE PHYSICAL BEHAVIOR. Nothing here touches a device or a speaker.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(HERE, "pcm_vectors.json")
D01_RUNNER = os.path.join(REPO, "tests", "d01", "run_cases.py")

HARNESS_TEST = ("g02_pcm", "g02_pcm_vectors_match_the_independent_reference")
GAIN_TOLERANCE = 1e-7
# 0.5 (rounding B) + 0.5 (rounding A scaled by a ratio <= 1) + 0.01 (f32 products at <= 16384 LSB).
LINEAR_TOLERANCE_LSB = 1.01
MIN_REFERENCE_PEAK_LSB = 50
MAX_OUTPUT_LSB = 26_214  # 0.8 of full scale: the limiter threshold
AUDIBLE_GAIN = 0.2


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pr = _load(os.path.join(HERE, "pcm_reference.py"), "g02pcm_run_reference")
gen = _load(os.path.join(HERE, "pcm_generate.py"), "g02pcm_run_generate")

# Reuse D01's cargo-log parser (RCH-shape aware, deduplicated inputs) on a PRIVATE instance of that
# module, retargeted at this slice's observation tag and source. D01's own file is untouched.
d01 = _load(D01_RUNNER, "g02pcm_private_d01_runner")
d01.OBSERVED = re.compile(r"G02PCM-OBSERVED (\{.*\})\s*$")
d01.RUST_SOURCES = [("crates/franken-dsp/tests/g02_pcm.rs", "g02_pcm", "")]
Logs = d01.Logs
Result = d01.Result
summarize = d01.summarize
exit_code = d01.exit_code
sha256_file = d01.sha256_file


def derive_rust_tests() -> List[Tuple[str, str]]:
    return d01.derive_rust_tests(REPO)


# ---- reference self-checks ----------------------------------------------------------------------------


def reference_problems() -> List[str]:
    problems: List[str] = []
    if pr.fnv1a64(b"") != 0xCBF29CE484222325 or pr.fnv1a64(b"a") != 0xAF63DC4C8601EC8C:
        problems.append("FNV-1a 64 does not match its published test vectors")
    # Worked on paper: 1 * 1664525 + 1013904223 = 1015568748; >> 16 = 15496; 15496 / 131072.
    stream = pr.lcg_stream(1, 3)
    if stream != [15496 / 131072.0, 24200 / 131072.0, -32490 / 131072.0]:
        problems.append(f"LCG stream {stream} differs from the hand-derived first samples")
    if abs(pr.ref.ramp_step() - 1.0 / 480.0) > 1e-9:
        problems.append("the ramp step is not 1/480")
    return problems


# ---- judging ----------------------------------------------------------------------------------------------


def _chunks(values: List[int], width: int) -> List[List[int]]:
    return [values[i:i + width] for i in range(0, len(values), width)]


def structure_problem(case: dict, obs: dict) -> Optional[str]:
    n, channels = case["frames"], pr.BOARDS[case["board"]]["channels"]
    if obs.get("frames") != n or obs.get("channels") != channels:
        return f"observed {obs.get('frames')} frames x {obs.get('channels')} channels, expected {n} x {channels}"
    for key, want in (("gain_a", n), ("gain_b", n), ("out_a", n * channels), ("out_b", n * channels)):
        if len(obs[key]) != want:
            return f"{key} has {len(obs[key])} entries, expected {want}"
    return None


def reference_problem(case: dict, obs: dict, sim: dict) -> Optional[str]:
    """The observation against the reference simulation, frame by frame."""
    if obs["input_fnv"] != pr.input_fnv(case):
        return f"the board was fed fingerprint {obs['input_fnv']}, the documented stream is {pr.input_fnv(case)}"
    if obs["results"] != sim["results"]:
        for got, want in zip(obs["results"], sim["results"]):
            if got != want:
                return f"operation result {got}, the reference says {want}"
        return f"{len(obs['results'])} operation results, the reference says {len(sim['results'])}"
    for key in ("a", "b"):
        for frame, (got, want) in enumerate(zip(obs["gain_" + key], sim["gain_" + key])):
            if abs(got - want) > GAIN_TOLERANCE:
                return f"frame {frame}: board {key.upper()} applied gain {got!r}, the reference says {want!r}"
    return None


def gain_problem(case: dict, obs: dict) -> Optional[str]:
    """Bounds on the observed gain trajectory, with arithmetic of the judge's own."""
    step = pr.ref.ramp_step()
    gain = obs["gain_b"]
    bound = pr.ref.bounded_ceiling(case["ceiling"])
    fixed = not any(op[1] in ("ceiling", "fault_ceiling") for op in case["schedule"])
    previous = 0.0
    for frame, g in enumerate(gain):
        if not 0.0 <= g <= 1.0:
            return f"frame {frame}: applied gain {g!r} is outside 0..1"
        if abs(g - previous) > step + 2.0 ** -24:
            return f"frame {frame}: the applied gain stepped {previous!r} -> {g!r}, more than one ramp step"
        if fixed and g > 1.0 and g > bound + GAIN_TOLERANCE:
            return f"frame {frame}: applied gain {g!r} exceeds the ceiling {bound!r}"
        previous = g
    if fixed and bound < 1.0 and max(gain) > bound + GAIN_TOLERANCE:
        return f"applied gain peaks at {max(gain)!r}, above the ceiling {bound!r}"
    # Mute in flight: while a mute reason holds, the gain only falls.
    state: Dict[int, Optional[str]] = {}
    for frame, _name, _result, mute in obs["results"]:
        state[frame] = mute
    frames = sorted(state)
    for index, start in enumerate(frames):
        end = frames[index + 1] if index + 1 < len(frames) else case["frames"]
        if state[start] is not None:
            for frame in range(start + 1, end):
                if gain[frame] > gain[frame - 1] + GAIN_TOLERANCE:
                    return f"frame {frame}: the gain rose while the room was muted ({state[start]})"
    return None


def linearity_problem(case: dict, obs: dict) -> Optional[str]:
    channels = pr.BOARDS[case["board"]]["channels"]
    lanes_a, lanes_b = _chunks(obs["out_a"], channels), _chunks(obs["out_b"], channels)
    for frame, (lane_a, lane_b, ga, gb) in enumerate(zip(lanes_a, lanes_b, obs["gain_a"], obs["gain_b"])):
        ratio = gb / ga
        for channel, (a, b) in enumerate(zip(lane_a, lane_b)):
            if abs(b - a * ratio) > LINEAR_TOLERANCE_LSB:
                return (f"frame {frame} channel {channel}: output {b}, unity output {a} x ratio {ratio:.6f} "
                        f"= {a * ratio:.3f} (bound {LINEAR_TOLERANCE_LSB} LSB)")
    return None


def silence_problem(case: dict, obs: dict, sim: dict) -> Optional[str]:
    channels = pr.BOARDS[case["board"]]["channels"]
    lanes_b = _chunks(obs["out_b"], channels)
    zero_gain = [frame for frame, g in enumerate(obs["gain_b"]) if g == 0.0]
    for frame in zero_gain:
        if any(lanes_b[frame]):
            return f"frame {frame}: the applied gain is 0 but a channel is not silent: {lanes_b[frame]}"
    if len(zero_gain) != case["expect"]["silent_frames"]:
        return f"{len(zero_gain)} frames at zero gain, the vector says {case['expect']['silent_frames']}"
    if len(zero_gain) != sum(1 for g in sim["gain_b"] if g == 0.0):
        return "the zero-gain frames differ from the reference simulation"
    return None


def regime_problem(case: dict, obs: dict) -> Optional[str]:
    regime = obs["regime"]
    if regime["limiter_min"] != 1.0 or regime["thermal_scaled"] != 0 or regime["clipped"] != 0:
        return f"the linear regime is not certified: {regime}"
    loudest = max(abs(s) for s in obs["out_a"] + obs["out_b"])
    return f"an output of {loudest} LSB is too close to the limiter" if loudest > MAX_OUTPUT_LSB else None


def coverage_problem(case: dict, obs: dict) -> Optional[str]:
    """Non-vacuity: the signal really reaches every driver channel, in the reference and the controlled run."""
    channels = pr.BOARDS[case["board"]]["channels"]
    lanes_a, lanes_b = _chunks(obs["out_a"], channels), _chunks(obs["out_b"], channels)
    for channel in range(channels):
        peak = max(abs(lane[channel]) for lane in lanes_a)
        if peak < MIN_REFERENCE_PEAK_LSB:
            return f"channel {channel} peaks at {peak} LSB in the reference run: its checks would be vacuous"
        audible = [abs(lane[channel]) for lane, g in zip(lanes_b, obs["gain_b"]) if g >= AUDIBLE_GAIN]
        if not audible or max(audible) < 0.2 * MIN_REFERENCE_PEAK_LSB:
            return f"channel {channel} never carried signal in the controlled run while the gain was audible"
    return None


def pairs_problem(case: dict, obs: dict) -> Optional[str]:
    expect = case.get("pair_expect")
    if expect is None:
        return None
    channels = pr.BOARDS[case["board"]]["channels"]
    lanes_a = _chunks(obs["out_a"], channels)
    for i, j in case["pairs"]:
        differing = sum(1 for lane in lanes_a if lane[i] != lane[j])
        if expect == "equal" and differing:
            return f"channels {i} and {j} differ in {differing} frames, but a {case['role']} room plays one channel on both"
        if expect == "differ" and differing <= case["frames"] // 4:
            return f"channels {i} and {j} differ in only {differing} frames: the stereo control is vacuous"
    return None


def judge_case(case: dict, obs: dict) -> Optional[str]:
    problem = structure_problem(case, obs)
    if problem:
        return "structure: " + problem
    sim = pr.simulate(case)
    problem = reference_problem(case, obs, sim)
    if problem:
        return "against the reference: " + problem
    if obs["role_mismatches"] != 0:
        return f"property: the role-mapped stream and the pre-mapped stream differ in {obs['role_mismatches']} samples"
    for name, check in (("regime", lambda: regime_problem(case, obs)), ("coverage", lambda: coverage_problem(case, obs)),
                        ("gain", lambda: gain_problem(case, obs)), ("linearity", lambda: linearity_problem(case, obs)),
                        ("silence", lambda: silence_problem(case, obs, sim)), ("roles", lambda: pairs_problem(case, obs))):
        problem = check()
        if problem:
            return f"property ({name}): {problem}"
    return None


# ---- the run -------------------------------------------------------------------------------------------------


def run(logs: Optional[Any]) -> Tuple[List[Any], dict]:
    results: List[Any] = []
    try:
        with open(VECTORS, encoding="utf-8") as handle:
            text = handle.read()
        doc: Optional[dict] = json.loads(text)
    except (OSError, ValueError):
        text, doc = "", None
    fresh = gen.build()
    fresh_text = gen.dumps(fresh)

    problems = reference_problems()
    results.append(Result("G02PCM-META-REFERENCE", "failed" if problems else "passed", "; ".join(problems[:3]), "meta"))
    if doc is None:
        results.append(Result("G02PCM-META-VECTORS-FRESH", "failed", "tests/g02/pcm_vectors.json is missing (run --write-vectors)", "meta"))
        doc = fresh
    elif text != fresh_text:
        results.append(Result("G02PCM-META-VECTORS-FRESH", "failed", "pcm_vectors.json differs from a fresh generation: run --write-vectors", "meta"))
    else:
        results.append(Result("G02PCM-META-VECTORS-FRESH", "passed", "", "meta"))

    cases: List[dict] = doc["cases"]
    covered = {i for c in cases for i in c["invariants"]}
    declared = set(doc["invariants"])
    uncovered, unknown = sorted(declared - covered), sorted(covered - declared)
    results.append(Result("G02PCM-META-INVARIANT-MAP", "failed" if uncovered or unknown else "passed",
                          f"uncovered={uncovered} unknown={unknown}" if uncovered or unknown else "", "meta"))

    for case in cases:
        if logs is None or case["id"] not in logs.observed:
            results.append(Result(case["id"], "blocked", "no Rust observation (central cargo log not supplied or the case did not run)", "vector"))
            continue
        if case["id"] in logs.conflicting_observations:
            results.append(Result(case["id"], "failed", "the logs hold conflicting observations of this case", "vector"))
            continue
        try:
            problem = judge_case(case, logs.observed[case["id"]])
        except (KeyError, IndexError, TypeError, ValueError, ZeroDivisionError) as exc:
            problem = f"observation is missing data the judge needs ({type(exc).__name__}: {exc})"
        results.append(Result(case["id"], "failed" if problem else "passed", problem or "", "vector"))

    required = derive_rust_tests()
    for stem, name in required:
        case_id = f"RUST:{stem}::{name}"
        status = logs.test_status(stem, name) if logs is not None else None
        if status == "ok":
            results.append(Result(case_id, "passed", "", "rust"))
        elif status in ("FAILED", "CONFLICT"):
            results.append(Result(case_id, "failed", "cargo reported FAILED" if status == "FAILED" else "conflicting statuses", "rust"))
        else:
            results.append(Result(case_id, "blocked", {"ignored": "reported ignored", "AMBIGUOUS": "ambiguous name in the logs"}.get(status or "", "not reported in the supplied logs"), "rust"))
    meta = {"vectors_sha256": sha256_file(VECTORS) if os.path.isfile(VECTORS) else None,
            "planned_vectors": len(cases), "planned_rust_tests": len(required)}
    return results, meta


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="G02 slice 2 PCM end-to-end runner and judge (ffw-ld0)")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--write-vectors", action="store_true")
    parser.add_argument("--judge", nargs="+", metavar="LOG")
    parser.add_argument("--receipts", metavar="DIR")
    args = parser.parse_args(argv)
    if args.write_vectors:
        with open(VECTORS, "w", encoding="utf-8") as handle:
            handle.write(gen.dumps(gen.build()))
        print(f"wrote {os.path.relpath(VECTORS, REPO)} ({sha256_file(VECTORS)[:16]}...)")
        return 0
    logs = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                print(f"error: log not found: {path}", file=sys.stderr)
                return 2
            logs.add(path)
    results, meta = run(logs)
    if args.list:
        for r in results:
            print(r.case_id)
        return 0
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:12]:
            print(f"{label:8s} {r.case_id}  {r.detail}")
        if len(rows) > 12:
            print(f"{label:8s} ... and {len(rows) - 12} more {status} case(s)")
    verdict = "QUALIFIED" if exit_code(results) == 0 else "NOT QUALIFIED"
    print(f"G02 PCM e2e: {verdict}  planned={len(results)} passed={counts['passed']} "
          f"failed={counts['failed']} blocked={counts['blocked']}")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        path = os.path.join(args.receipts, f"g02-pcm-{(meta['vectors_sha256'] or 'none')[:12]}-{counts['passed']}p.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"schema": "ffw.g02.pcm.receipt.v1", "counts": counts, "exit_code": exit_code(results),
                       "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
                       "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
                       "unattributed_logs": list(logs.unattributed_logs) if logs else [],
                       **meta, "results": [r.as_dict() for r in results]}, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print("receipt:", path)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
