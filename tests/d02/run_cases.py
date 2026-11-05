#!/usr/bin/env python3
"""D02 (ffw-7s0) end-to-end runner and judge.

    run_cases.py [--tier smoke|full] [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds nothing. Same contract as D01's judge:

* META  - reference self-checks (analytic Butterworth properties and closed forms vs simulation),
          the committed ``vectors.json`` equals a fresh generation, every invariant is covered by a
          vector or a named Rust test, and every named Rust test exists in the sources.
* JUDGE - reads the ``cargo test`` output of the centrally run suites (``--judge LOG``), compares each
          ``D02-OBSERVED`` line with the independent reference, and requires every Rust test to be ``ok``.

Anything with no Rust observation is ``blocked`` (counted, named, never passed, never dropped).
Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.

The central commands (RCH only):

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-alloc-probe

NUMERICAL TESTS DO NOT PROVE PHYSICAL PROTECTION. Calibration here is synthetic.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(HERE, "vectors.json")
TIERS = ("smoke", "full")
D01_RUNNER = os.path.join(REPO, "tests", "d01", "run_cases.py")

PACKAGE_BINARIES = {"franken-dsp": ("franken_dsp", "d02_vectors"), "franken-alloc-probe": ("protection_no_alloc",)}
HARNESS_TEST = ("d02_vectors", "d02_vectors_match_the_independent_reference")


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load(os.path.join(HERE, "reference.py"), "d02_reference")
gen = _load(os.path.join(HERE, "generate.py"), "d02_generate")

# Reuse D01's cargo-log parser (RCH-shape aware: ordinal header/section pairing, deduplicated
# inputs) on a PRIVATE instance of that module, retargeted at D02's observation tag and sources.
# D01's own file and behaviour are untouched.
d01 = _load(D01_RUNNER, "d02_private_d01_runner")
d01.OBSERVED = re.compile(r"D02-OBSERVED (\{.*\})\s*$")
d01.RUST_SOURCES = [
    ("crates/franken-dsp/src/protection/tests.rs", "franken_dsp", "protection::tests::"),
    ("crates/franken-dsp/tests/d02_vectors.rs", "d02_vectors", ""),
    ("crates/franken-alloc-probe/tests/protection_no_alloc.rs", "protection_no_alloc", ""),
]
Logs = d01.Logs
Result = d01.Result
summarize = d01.summarize
exit_code = d01.exit_code
sha256_file = d01.sha256_file


def derive_rust_tests() -> List[Tuple[str, str]]:
    return d01.derive_rust_tests(REPO)


# ---- reference self-checks ----------------------------------------------------------------------------


def reference_problems() -> List[str]:
    """Analytic properties the reference must satisfy, independent of any Rust output."""
    problems: List[str] = []
    for fc in (120.0, 300.0, 2000.0, 2200.0):
        lp, hp = ref.stored(ref.butterworth("lp", fc)), ref.stored(ref.butterworth("hp", fc))
        # Butterworth: unity DC gain (LP), zero at DC (HP), and -3.0103 dB at the corner for both.
        dc = sum(lp[:3]) / (1 + lp[3] + lp[4])
        if abs(dc - 1.0) > 1e-3:
            problems.append(f"LP {fc}: DC gain {dc}")
        if abs(sum(hp[:3])) > 1e-9:
            problems.append(f"HP {fc}: no zero at DC")
        for name, c in (("LP", lp), ("HP", hp)):
            m = ref.magnitude([c], fc)
            if abs(m - 1.0 / math.sqrt(2.0)) > 2e-3:
                problems.append(f"{name} {fc}: |H(fc)| = {m}")
    # closed forms vs simulation
    r = math.exp(-2 * math.pi * 5.0 / ref.FS)
    sim = []
    y1, x1 = 0.0, 0.0
    for _ in range(50):
        y = 0.5 - x1 + r * y1
        sim.append(y)
        x1, y1 = 0.5, y
    if max(abs(a - b) for a, b in zip(sim, ref.dc_response(5.0, 0.5, 50))) > 1e-12:
        problems.append("DC closed form disagrees with its recursion")
    gains, _ = ref.limiter_response(0.5, 1.0, 50.0, [(1.0, 300)])
    a = ref.smoothing(1.0)
    if abs(gains[299] - (0.5 + 0.5 * (1 - a) ** 300)) > 1e-12:
        problems.append("limiter attack closed form disagrees with its recursion")
    v, tau = ref.nyquist_drive_level(0.6), 0.05
    level, n = 0.0, 0
    alpha = ref.smoothing(tau * 1000.0)
    while level < 0.2:
        level += alpha * (v * v - level)
        n += 1
    if abs(n - ref.samples_to_reach(0.2, v, tau)) > 1.0:
        problems.append(f"thermal crossing: simulation {n} vs closed form {ref.samples_to_reach(0.2, v, tau)}")
    return problems


# ---- judging ----------------------------------------------------------------------------------------------


def _first_diff(got: List[float], want: List[float], tol: float) -> Optional[str]:
    if len(got) != len(want):
        return f"length {len(got)} != {len(want)}"
    for i, (g, w) in enumerate(zip(got, want)):
        if not abs(g - w) <= tol:
            return f"first divergence at sample {i}: expected {w!r}, observed {g!r} (tolerance {tol})"
    return None


def _close(a: float, b: float, rel: float) -> bool:
    return abs(a - b) <= rel * max(abs(b), 1e-12)


def judge_scenario(case: dict, obs: dict) -> Optional[str]:
    trace, check = obs.get("trace", []), case["check"]
    if len(trace) != len(case["ops"]):
        return f"trace has {len(trace)} entries for {len(case['ops'])} ops"
    return SCENARIO_CHECKS[check](case, trace)


def _blocks(entry: dict) -> List[dict]:
    return entry["blocks"]


def _peaks_zero(block: dict) -> bool:
    return all(p == 0 for p in block["peak"])


def check_persistence(case: dict, t: List[dict]) -> Optional[str]:
    v = ref.nyquist_drive_level(0.9)
    want = ref.thermal_after(0.0, v, 2.0, 6 * 256)
    if not _close(t[2]["thermal"][0], want, 0.02):
        return f"thermal after 1536 samples: expected {want:.6g} (closed form), observed {t[2]['thermal'][0]:.6g}"
    steady = 0.8 / v
    if abs(t[2]["limiter"][0] - steady) > 2e-3:
        return f"limiter gain: expected {steady:.5f} (threshold/|v|), observed {t[2]['limiter'][0]:.5f}"
    for e in (3, 5, 7):
        before, after = t[e - 1], t[e]
        for key in ("thermal", "limiter", "status", "user_gain", "muted"):
            if before[key] != after[key]:
                return f"event op {e} changed {key}: {before[key]!r} -> {after[key]!r}"
        block = _blocks(t[e + 1])[0]
        if abs(block["source_fade"] - 256 / 960) > 2e-3:
            return f"after event op {e} the fade-in should be {256 / 960:.4f}, observed {block['source_fade']:.4f}"
        if block["peak"][0] >= _blocks(t[2])[-1]["peak"][0]:
            return f"after event op {e} the output did not fade in from silence"
        if t[e + 1]["limiter"][0] >= 0.95:
            return f"after event op {e} the limiter history was lost ({t[e + 1]['limiter'][0]})"
        if t[e + 1]["thermal"][0] < 0.9 * after["thermal"][0]:
            return f"after event op {e} the thermal level fell from {after['thermal'][0]} to {t[e + 1]['thermal'][0]}"
    return None


def check_thermal_cycle(case: dict, t: List[dict]) -> Optional[str]:
    cal = case["calibration"]["channels"][0]["thermal"]
    v = ref.nyquist_drive_level(0.6)
    blocks = _blocks(t[2])
    fault_at = next((i for i, b in enumerate(blocks) if b["status"].startswith("faulted")), None)
    if fault_at is None:
        return "sustained overdrive never latched a thermal fault"
    expect_block = int(ref.samples_to_reach(cal["hard_ms"], v, cal["tau_s"])) // 256
    if abs(fault_at - expect_block) > 1:
        return f"fault in block {fault_at}, closed form says block {expect_block}"
    if blocks[fault_at]["status"] != "faulted:thermal_hard:0":
        return f"fault was {blocks[fault_at]['status']}, expected faulted:thermal_hard:0"
    soft_block = int(ref.samples_to_reach(cal["soft_ms"], v, cal["tau_s"])) // 256
    first_scaled = next((i for i, b in enumerate(blocks) if b["scaled"] > 0), None)
    if first_scaled is None or abs(first_scaled - soft_block) > 1:
        return f"thermal scaling began in block {first_scaled}, closed form says block {soft_block}"
    if any(not _peaks_zero(b) for b in blocks[fault_at + 1:]) or any(not _peaks_zero(b) for b in _blocks(t[3])):
        return "a faulted board produced audio"
    if blocks[-1]["applied_gain"] != 0.0:
        return "a faulted board did not ramp its gain to zero"
    if t[4]["result"] != "unmute_refused":
        return f"unmute of a faulted board returned {t[4]['result']!r}"
    if t[5]["result"] != "not_cooled":
        return f"clear_fault while hot returned {t[5]['result']!r}"
    if not t[5]["thermal"][0] > cal["soft_ms"]:
        return f"board reported hot but thermal level {t[5]['thermal'][0]} is not above soft {cal['soft_ms']}"
    cooled = t[5]["thermal"][0] * (1.0 - ref.smoothing(cal["tau_s"] * 1000.0)) ** (20 * 256)
    if not _close(t[6]["thermal"][0], cooled, 0.03):
        return f"cooling: expected {cooled:.6g} (exponential decay), observed {t[6]['thermal'][0]:.6g}"
    if t[7]["result"] != "ok" or t[7]["status"] != "active":
        return f"clear_fault after cooling returned {t[7]['result']!r} / {t[7]['status']!r}"
    if t[7]["thermal"] != t[6]["thermal"]:
        return "clearing a fault changed the thermal history"
    if not any(not _peaks_zero(b) for b in _blocks(t[8])) or _blocks(t[8])[-1]["status"] != "active":
        return "the board did not resume after the fault was cleared"
    return None


def check_switch_valid(case: dict, t: List[dict]) -> Optional[str]:
    if t[3]["result"] != "ok" or not t[3]["pending"]:
        return f"valid switch request: result {t[3]['result']!r}, pending {t[3]['pending']}"
    blocks = _blocks(t[4])
    if abs(blocks[0]["applied_gain"] - (1.0 - 256 / 480)) > 0.01:
        return f"drain: applied gain after one block should be {1.0 - 256 / 480:.3f}, observed {blocks[0]['applied_gain']:.3f}"
    if t[4]["pending"]:
        return "the switch never completed"
    if blocks[-1]["applied_gain"] < 0.99 or blocks[-1]["status"] != "active":
        return "the board did not ramp back up after the swap"
    if t[4]["thermal"][0] < 0.5 * t[2]["thermal"][0]:
        return f"thermal history was lost across the switch: {t[2]['thermal'][0]} -> {t[4]['thermal'][0]}"
    return None


def check_switch_unsafe(case: dict, t: List[dict]) -> Optional[str]:
    if t[3]["result"] != "unstable" or t[3]["status"] != "fail_muted:unstable":
        return f"unsafe switch: result {t[3]['result']!r}, status {t[3]['status']!r}"
    after = _blocks(t[4])
    if any(not _peaks_zero(b) for b in after[1:]) or any(b["status"] != "fail_muted:unstable" for b in after):
        return "an unsafe profile produced audio after its ramp to silence"
    if t[5]["result"] != "unmute_refused":
        return f"unmute of a fail-muted board returned {t[5]['result']!r}"
    if t[6]["result"] != "ok":
        return f"valid re-admission returned {t[6]['result']!r}"
    last = _blocks(t[7])
    if last[-1]["status"] != "active" or not any(not _peaks_zero(b) for b in last) or last[-1]["applied_gain"] < 0.99:
        return "the board did not resume after a valid profile was admitted"
    if t[7]["thermal"][0] < 0.5 * t[2]["thermal"][0]:
        return f"thermal history was lost across fail-mute and re-admission: {t[2]['thermal'][0]} -> {t[7]['thermal'][0]}"
    return None


def _check_stays_muted(expected_status: str) -> Callable[[dict, List[dict]], Optional[str]]:
    def check(case: dict, t: List[dict]) -> Optional[str]:
        for i in (0, 3):
            if t[i]["result"] != "unmute_refused":
                return f"op {i}: unmute returned {t[i]['result']!r}"
        if any(entry["status"] != expected_status for entry in t):
            return f"status was not {expected_status!r} throughout"
        if any(not _peaks_zero(b) for b in _blocks(t[2])):
            return "a fail-muted board produced audio"
        return None
    return check


SCENARIO_CHECKS: Dict[str, Callable[[dict, List[dict]], Optional[str]]] = {
    "persistence": check_persistence,
    "thermal_cycle": check_thermal_cycle,
    "switch_valid": check_switch_valid,
    "switch_unsafe": check_switch_unsafe,
    "unknown_board": _check_stays_muted("fail_muted:unknown_board"),
    "no_calibration": _check_stays_muted("fail_muted:no_calibration"),
}


def judge_case(case: dict, obs: dict) -> Optional[str]:
    kind = case["kind"]
    if kind == "design":
        for key, want in case["expect"].items():
            got = obs["coefficients"][key]
            if abs(got - want) > 1e-12 * max(abs(want), 1.0):
                return f"coefficient {key}: expected {want!r}, observed {got!r}"
        return None
    if kind in ("section_response", "dc_response"):
        return _first_diff(obs["y"], case["expect"], case["tolerance"])
    if kind == "limiter_response":
        return (_first_diff(obs["gain"], case["expect_gain"], case["tolerance"])
                or _first_diff(obs["out"], case["expect_out"], case["tolerance"]))
    if kind == "validation":
        got = {k: v for k, v in obs.items() if k not in ("id", "kind")}
        return None if got == case["expect"] else f"expected {case['expect']}, observed {got}"
    if kind == "scenario":
        return judge_scenario(case, obs)
    return f"unknown case kind {kind}"


# ---- the run -------------------------------------------------------------------------------------------------


def smoke_ids(cases: List[dict]) -> List[str]:
    chosen, seen = [], set()
    for case in cases:
        if case["kind"] not in seen:
            seen.add(case["kind"])
            chosen.append(case["id"])
        if case["kind"] == "scenario":
            chosen.append(case["id"])
    return list(dict.fromkeys(chosen))


def run(tier: str, logs: Optional[Any]) -> Tuple[List[Any], dict]:
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
    results.append(Result("D02-META-REFERENCE", "failed" if problems else "passed", "; ".join(problems[:3]), "meta"))
    if doc is None:
        results.append(Result("D02-META-VECTORS-FRESH", "failed", "tests/d02/vectors.json is missing (run --write-vectors)", "meta"))
        doc = fresh
    elif text != fresh_text:
        results.append(Result("D02-META-VECTORS-FRESH", "failed", "vectors.json differs from a fresh generation: run --write-vectors", "meta"))
    else:
        results.append(Result("D02-META-VECTORS-FRESH", "passed", "", "meta"))

    cases: List[dict] = doc["cases"]
    covered = {i for c in cases for i in c["invariants"]}
    external = doc.get("external", {})
    declared = set(doc["invariants"])
    uncovered = sorted(declared - covered - {k for k, v in external.items() if v})
    unknown = sorted(covered - declared)
    results.append(Result("D02-META-INVARIANT-MAP", "failed" if uncovered or unknown else "passed",
                          f"uncovered={uncovered} unknown={unknown}" if uncovered or unknown else "", "meta"))

    required = derive_rust_tests()
    external_pairs: List[Tuple[str, str]] = []
    missing: List[str] = []
    for names in external.values():
        for entry in names:
            package, name = entry.split("::", 1)
            found = [(s, name) for s in PACKAGE_BINARIES.get(package, ()) if (s, name) in required]
            if found:
                external_pairs.extend(found)
            else:
                missing.append(entry)
    results.append(Result("D02-META-EXTERNAL-TESTS-EXIST", "failed" if missing else "passed",
                          f"named in the invariant map but not found in the Rust sources: {sorted(missing)}" if missing else "", "meta"))

    selected = {c["id"] for c in cases} if tier == "full" else set(smoke_ids(cases))
    for case in cases:
        if case["id"] not in selected:
            continue
        if logs is None or case["id"] not in logs.observed:
            results.append(Result(case["id"], "blocked", "no Rust observation (central cargo log not supplied or the case did not run)", "vector"))
            continue
        if case["id"] in logs.conflicting_observations:
            results.append(Result(case["id"], "failed", "the logs hold conflicting observations of this case", "vector"))
            continue
        try:
            problem = judge_case(case, logs.observed[case["id"]])
        except (KeyError, IndexError, TypeError) as exc:
            problem = f"observation is missing data the judge needs ({type(exc).__name__}: {exc})"
        results.append(Result(case["id"], "failed" if problem else "passed", problem or "", "vector"))

    needed = required if tier == "full" else [HARNESS_TEST] + external_pairs
    for stem, name in needed:
        case_id = f"RUST:{stem}::{name}"
        status = logs.test_status(stem, name) if logs is not None else None
        if status == "ok":
            results.append(Result(case_id, "passed", "", "rust"))
        elif status in ("FAILED", "CONFLICT"):
            results.append(Result(case_id, "failed", "cargo reported FAILED" if status == "FAILED" else "conflicting statuses", "rust"))
        else:
            results.append(Result(case_id, "blocked", {"ignored": "reported ignored", "AMBIGUOUS": "ambiguous name in the logs"}.get(status or "", "not reported in the supplied logs"), "rust"))
    meta = {"vectors_sha256": sha256_file(VECTORS) if os.path.isfile(VECTORS) else None,
            "planned_vectors": len(selected), "planned_rust_tests": len(needed)}
    return results, meta


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="D02 end-to-end runner and judge (ffw-7s0)")
    parser.add_argument("--tier", choices=TIERS, default="full")
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
    results, meta = run(args.tier, logs)
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
    print(f"D02 e2e tier={args.tier}: {verdict}  planned={len(results)} passed={counts['passed']} "
          f"failed={counts['failed']} blocked={counts['blocked']}")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        path = os.path.join(args.receipts, f"d02-{(meta['vectors_sha256'] or 'none')[:12]}-{counts['passed']}p.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"schema": "ffw.d02.receipt.v1", "tier": args.tier, "counts": counts, "exit_code": exit_code(results),
                       "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
                       "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
                       "unattributed_logs": list(logs.unattributed_logs) if logs else [],
                       **meta, "results": [r.as_dict() for r in results]}, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print("receipt:", path)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
