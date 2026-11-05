#!/usr/bin/env python3
"""G02 (ffw-ld0) end-to-end runner and judge.

    run_cases.py [--tier smoke|full] [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds nothing. Same contract as D01's and D02's judges:

* META  - reference self-checks (closed forms vs the model), the committed ``vectors.json`` equals a
          fresh generation, every invariant is covered by a vector or a named Rust test, and every
          named Rust test exists in the sources.
* JUDGE - reads the ``cargo test`` output of the centrally run suites (``--judge LOG``), compares each
          ``G02-OBSERVED`` line with the reference model's expectation AND checks properties directly
          on the observation with arithmetic of its own (so the verdict does not rest on the model
          alone), and requires every Rust test to be ``ok``.

Anything with no Rust observation is ``blocked`` (counted, named, never passed, never dropped).
Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.

The central command (RCH only):

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp -- --nocapture

NUMERICAL TESTS DO NOT PROVE PHYSICAL BEHAVIOR. Nothing here touches a device or a speaker.
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

PACKAGE_BINARIES = {"franken-dsp": ("franken_dsp", "g02_vectors"), "franken-speaker": ("franken_speaker",)}
HARNESS_TEST = ("g02_vectors", "g02_vectors_match_the_independent_reference")
TOLERANCE = 1e-7
SMOKE = ("G02-GAIN-001", "G02-ROLE-001", "G02-MAP-001", "G02-MBR-003", "G02-MBR-012", "G02-MBR-013", "G02-GRP-001")


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load(os.path.join(HERE, "reference.py"), "g02_reference")
gen = _load(os.path.join(HERE, "generate.py"), "g02_generate")

# Reuse D01's cargo-log parser (RCH-shape aware: ordinal header/section pairing, deduplicated
# inputs) on a PRIVATE instance of that module, retargeted at G02's observation tag and sources.
# D01's own file and behaviour are untouched.
d01 = _load(D01_RUNNER, "g02_private_d01_runner")
d01.OBSERVED = re.compile(r"G02-OBSERVED (\{.*\})\s*$")
d01.RUST_SOURCES = [
    ("crates/franken-dsp/src/volume/tests.rs", "franken_dsp", "volume::tests::"),
    ("crates/franken-dsp/src/volume/outcome_tests.rs", "franken_dsp", "volume::outcome_tests::"),
    ("crates/franken-dsp/src/volume/progress_tests.rs", "franken_dsp", "volume::progress_tests::"),
    ("crates/franken-dsp/src/volume/local_mute_tests.rs", "franken_dsp", "volume::local_mute_tests::"),
    ("crates/franken-speaker/src/button_adapter/tests.rs", "franken_speaker", "button_adapter::tests::"),
    ("crates/franken-dsp/tests/g02_vectors.rs", "g02_vectors", ""),
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
    """Closed forms the model must satisfy, independent of any Rust output."""
    problems: List[str] = []
    step = ref.ramp_step()
    if abs(step - 1.0 / 480.0) > 1e-9:
        problems.append(f"ramp step {step} is not 1/480")
    # A fresh 0 -> 1 ramp rises by `step` per sample: after n frames it is n/480 (f32 accumulation
    # error is at most n half-ulps, about n*3e-8).
    dsp = ref.Dsp(active=True, bugs=frozenset())
    dsp.set_user_gain(1.0)
    dsp.set_muted(False)
    done = dsp.ramp(300)
    if abs(done["max_applied"] - 300 / 480.0) > 300 * 3.0e-8 + 1e-9:
        problems.append(f"ramp after 300 frames is {done['max_applied']}, closed form {300 / 480.0}")
    if dsp.ramp(300)["max_applied"] != 1.0:
        problems.append("the ramp did not snap exactly to its target")
    # Gain composition: the f32 model equals the f64 closed form to within f32 rounding.
    for volume in (0, 1, 33, 50, 99, 100):
        for trim in (0, 1, 333, 1000, 2000):
            for ceiling in (1.0, 0.5):
                member = ref.Member(ceiling)
                member.declare(1)
                member.complete_join()
                member.volume, member.trim = volume, trim
                want = min(volume / 100.0 * trim / 1000.0, ceiling)
                if abs(member.unmuted() - want) > 2e-7:
                    problems.append(f"gain {volume}x{trim} ceiling {ceiling}: model {member.unmuted()} vs closed form {want}")
    # Mute reasons are reported in the declared priority order.
    member = ref.Member(1.0)
    member.declare(1)
    member.flags.update({"fault": True, "local": True, "join": True, "group": True})
    order = []
    while member.mute():
        order.append(member.mute())
        member.flags[member.mute()] = False
    if order != list(ref.MUTE_ORDER):
        problems.append(f"mute priority order is {order}")
    return problems


# ---- judging ----------------------------------------------------------------------------------------------


def diff(path: str, want: Any, got: Any) -> Optional[str]:
    """Deep comparison; numbers within TOLERANCE, everything else exact (a bool is never a number)."""
    if isinstance(want, bool) or isinstance(got, bool):
        return None if (isinstance(want, bool) and isinstance(got, bool) and want == got) else f"{path}: expected {want!r}, observed {got!r}"
    if isinstance(want, (int, float)) and isinstance(got, (int, float)):
        return None if abs(want - got) <= TOLERANCE else f"{path}: expected {want!r}, observed {got!r}"
    if isinstance(want, dict) and isinstance(got, dict):
        if set(want) != set(got):
            return f"{path}: keys differ, expected {sorted(want)}, observed {sorted(got)}"
        for key in sorted(want):
            problem = diff(f"{path}.{key}", want[key], got[key])
            if problem:
                return problem
        return None
    if isinstance(want, list) and isinstance(got, list):
        if len(want) != len(got):
            return f"{path}: expected {len(want)} items, observed {len(got)}"
        for index, (w, g) in enumerate(zip(want, got)):
            problem = diff(f"{path}[{index}]", w, g)
            if problem:
                return problem
        return None
    return None if want == got else f"{path}: expected {want!r}, observed {got!r}"


def _numeric_ceiling(value: Any) -> float:
    x = float(value)
    return 0.0 if not math.isfinite(x) else min(1.0, max(0.0, x))


def gain_properties(case: dict, obs: dict) -> Optional[str]:
    """f64 closed form, independent of the model: gain = min(volume/100 * trim/1000, bound)."""
    rows, gains = case["rows"], obs["gains"]
    if len(rows) != len(gains):
        return f"{len(gains)} gains for {len(rows)} rows"
    bound = _numeric_ceiling(case["protection_ceiling"])
    if case["fault_ceiling"] is not None:
        bound = min(bound, _numeric_ceiling(case["fault_ceiling"]))
    for (volume, trim), gain in zip(rows, gains):
        want = min(1.0, max(0.0, min(volume / 100.0 * trim / 1000.0, bound)))
        if abs(gain - want) > 2e-7:
            return f"volume {volume} trim {trim}: observed {gain!r}, closed form {want!r}"
        if gain > bound + 2e-7:
            return f"volume {volume} trim {trim}: gain {gain!r} exceeds its ceiling {bound!r}"
    return None


def _initial_member(case: dict) -> Dict[str, Any]:
    start = case.get("start", "new")
    if start == "new":
        return {"mute": "join", "desired": 0, "trim": 1000, "epoch": None, "revision": 0, "applied": 0.0}
    stored = start["restore"]
    return {"mute": "local" if stored["local_mute"] else "join", "desired": min(stored["volume"], 100),
            "trim": min(stored["trim"], 2000), "epoch": None, "revision": 0, "applied": 0.0}


VOLUME_COMMANDS = ("set_volume", "adjust_volume", "set_trim", "reset_trim")


def _state_key(entry: dict) -> tuple:
    return (entry["desired"], entry["trim"], entry["revision"], entry["epoch"], entry["mute"])


def member_properties(case: dict, obs: dict) -> Optional[str]:
    """Contract properties read straight off the trace, with arithmetic of the judge's own."""
    trace, step = obs["trace"], ref.ramp_step()
    ops = case["ops"]
    if len(trace) != len(ops):
        return f"trace has {len(trace)} entries for {len(ops)} ops"
    fixed_ceiling = None
    if not any(op[0] in ("ceiling", "fault_ceiling") for op in ops):
        fixed_ceiling = _numeric_ceiling(case["ceiling"])
    prev = _initial_member(case)
    for index, (op, entry) in enumerate(zip(ops, trace)):
        name, result = op[0], entry["result"]
        where = f"op {index} {name}"
        before = (prev["desired"], prev["trim"], prev["revision"], prev["epoch"], prev["mute"])
        # -- always
        if entry["desired"] > 100 or entry["trim"] > 2000:
            return f"{where}: desired volume {entry['desired']} / trim {entry['trim']} is out of range"
        if entry["mute"] is not None and entry["gain"] != 0.0:
            return f"{where}: muted ({entry['mute']}) but the target gain is {entry['gain']!r}"
        if not 0.0 <= entry["unmuted"] <= 1.0:
            return f"{where}: bounded gain {entry['unmuted']!r} is outside 0..1"
        if entry["epoch"] is None and entry["unmuted"] != 0.0:
            return f"{where}: no declared authority but the bounded gain is {entry['unmuted']!r}"
        if fixed_ceiling is not None and entry["unmuted"] > fixed_ceiling + TOLERANCE:
            return f"{where}: bounded gain {entry['unmuted']!r} exceeds the ceiling {fixed_ceiling!r}"
        # -- commands: a refusal changes nothing; an acceptance advances the revision once; a replay does not apply
        if name == "cmd":
            kind = op[3][0]
            if result != "ok":
                if _state_key(entry) != before:
                    return f"{where}: refused with {result} but the state changed {before} -> {_state_key(entry)}"
            else:
                if entry["epoch"] != prev["epoch"]:
                    return f"{where}: a command changed the epoch {prev['epoch']} -> {entry['epoch']}"
                if entry["duplicate"]:
                    if _state_key(entry) != before:
                        return f"{where}: a replay was applied again"
                elif not (entry["revision"] == op[2] and op[2] > prev["revision"]):
                    return f"{where}: accepted revision {op[2]} but the state holds {entry['revision']} (was {prev['revision']})"
                if kind in VOLUME_COMMANDS and entry["mute"] != prev["mute"]:
                    return f"{where}: a {kind} command changed the mute {prev['mute']} -> {entry['mute']}"
                if kind in ("set_volume", "adjust_volume") and entry["trim"] != prev["trim"]:
                    return f"{where}: a group volume change altered the room trim {prev['trim']} -> {entry['trim']}"
                if kind == "set_group_mute" and not op[3][1] and prev["mute"] in ("fault", "local", "join") \
                        and entry["mute"] != prev["mute"]:
                    return f"{where}: a group unmute cleared the {prev['mute']} mute"
        if name == "local_trim" and entry["mute"] != prev["mute"]:
            return f"{where}: a local trim button changed the mute {prev['mute']} -> {entry['mute']}"
        if name == "board":
            if (op[1] != "active") != (entry["mute"] == "fault"):
                return f"{where}: board status {op[1]!r} but the mute is {entry['mute']!r}"
        if name == "reconnect":
            if result == "ok":
                if (entry["desired"], entry["epoch"], entry["revision"]) != (op[3], op[1], op[2]):
                    return f"{where}: did not take the group's snapshot {op[1:4]}: {_state_key(entry)}"
                if entry["mute"] is None or entry["gain"] != 0.0:
                    return f"{where}: a reconnect must leave the member silent, not {entry['mute']!r} / {entry['gain']!r}"
            elif _state_key(entry) != before:
                return f"{where}: refused with {result} but the state changed"
        # -- the board
        dsp = entry.get("dsp")
        if dsp is not None:
            if name != "ramp" and abs(dsp["applied"] - prev["applied"]) > TOLERANCE:
                return f"{where}: a control operation stepped the output {prev['applied']!r} -> {dsp['applied']!r}"
            if fixed_ceiling is not None and dsp["applied"] > fixed_ceiling + TOLERANCE:
                return f"{where}: applied gain {dsp['applied']!r} exceeds the ceiling {fixed_ceiling!r}"
            if name == "sync" and result == "ok" and entry["mute"] is not None and not dsp["muted"]:
                return f"{where}: the member is muted ({entry['mute']}) but the board was left unmuted"
            if name == "ramp":
                # Two f32 values near 1.0 differ by step +- half an ulp (2**-25); 2**-24 is twice that.
                if entry["max_step"] > step + 2.0 ** -24:
                    return f"{where}: the applied gain moved {entry['max_step']!r} in one sample, more than {step!r}"
                if entry["direction_changes"]:
                    return f"{where}: the ramp reversed direction {entry['direction_changes']} time(s)"
                if entry["mute"] is not None and dsp["applied"] > prev["applied"] + TOLERANCE:
                    return f"{where}: muted ({entry['mute']}) but the applied gain rose"
            prev["applied"] = dsp["applied"]
        prev.update(mute=entry["mute"], desired=entry["desired"], trim=entry["trim"],
                    epoch=entry["epoch"], revision=entry["revision"])
    return None


def group_properties(case: dict, obs: dict) -> Optional[str]:
    trace, ops = obs["trace"], case["ops"]
    if len(trace) != len(ops):
        return f"trace has {len(trace)} entries for {len(ops)} ops"
    present: Dict[int, bool] = {}
    for index, (op, entry) in enumerate(zip(ops, trace)):
        name, result = op[0], entry["result"]
        where = f"op {index} {name}"
        for member_id, desired, mute, gain, _epoch in entry["state"]:
            if mute is not None and gain != 0.0:
                return f"{where}: member {member_id} is muted ({mute}) with gain {gain!r}"
            if desired > 100:
                return f"{where}: member {member_id} holds volume {desired}"
        if result != "ok" and "members" in entry:
            return f"{where}: a refused group command fanned out"
        if name == "add" and result == "ok":
            present[op[1]] = True
        elif name == "present" and result == "ok":
            present[op[1]] = op[2]
        elif name == "rejoin" and result == "ok":
            present[op[1]] = True
        elif name == "gcmd" and result == "ok":
            for member_id, status in entry["members"]:
                if present.get(member_id, False) == (status == "missing"):
                    return (f"{where}: member {member_id} is "
                            f"{'present' if present.get(member_id) else 'absent'} but was reported {status!r}")
    return None


def role_properties(case: dict, obs: dict) -> Optional[str]:
    """The refusal reasons must be consistent with the layout, derived here from first principles."""
    layout = case["layout"]
    routing, hardware = layout["routing"], layout["hardware_channels"]
    results = obs["results"]
    if hardware == 0 or not routing:
        want = {role: "no_audio_output" for role in results}
    elif len(routing) != hardware:
        want = {role: "invalid_layout" for role in results}
    else:
        subs = sum(1 for r in routing if r == "subwoofer_lfe")
        if subs == 0:
            want = {"stereo": "ok", "left": "ok", "right": "ok", "sub": "no_subwoofer_path"}
        elif subs == len(routing):
            want = {"stereo": "subwoofer_only", "left": "subwoofer_only", "right": "subwoofer_only", "sub": "ok"}
        else:
            want = {role: "mixed_sub_layout" for role in results}
    return None if results == want else f"roles {results} but the layout {routing} implies {want}"


def map_properties(case: dict, obs: dict) -> Optional[str]:
    for index, (left, right) in enumerate(case["samples"]):
        mid = 0.5 * (left + right)
        want = {"stereo": [left, right], "left": [left, left], "right": [right, right], "sub": [mid, mid]}
        for role, pair in want.items():
            if any(abs(a - b) > TOLERANCE for a, b in zip(obs["mapped"][role][index], pair)):
                return f"sample {index} role {role}: observed {obs['mapped'][role][index]}, expected {pair}"
    return None


PROPERTIES: Dict[str, Callable[[dict, dict], Optional[str]]] = {
    "gain_grid": gain_properties,
    "roles": role_properties,
    "role_map": map_properties,
    "member_script": member_properties,
    "group_script": group_properties,
}


def judge_case(case: dict, obs: dict) -> Optional[str]:
    core = {k: v for k, v in obs.items() if k not in ("id", "kind")}
    problem = diff("", case["expect"], core)
    if problem:
        return "against the reference model: " + problem
    problem = PROPERTIES[case["kind"]](case, core)
    return ("property: " + problem) if problem else None


# ---- the run -------------------------------------------------------------------------------------------------


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
    results.append(Result("G02-META-REFERENCE", "failed" if problems else "passed", "; ".join(problems[:3]), "meta"))
    if doc is None:
        results.append(Result("G02-META-VECTORS-FRESH", "failed", "tests/g02/vectors.json is missing (run --write-vectors)", "meta"))
        doc = fresh
    elif text != fresh_text:
        results.append(Result("G02-META-VECTORS-FRESH", "failed", "vectors.json differs from a fresh generation: run --write-vectors", "meta"))
    else:
        results.append(Result("G02-META-VECTORS-FRESH", "passed", "", "meta"))

    cases: List[dict] = doc["cases"]
    covered = {i for c in cases for i in c["invariants"]}
    external = doc.get("external", {})
    declared = set(doc["invariants"])
    uncovered = sorted(declared - covered - {k for k, v in external.items() if v})
    unknown = sorted(covered - declared)
    results.append(Result("G02-META-INVARIANT-MAP", "failed" if uncovered or unknown else "passed",
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
    results.append(Result("G02-META-EXTERNAL-TESTS-EXIST", "failed" if missing else "passed",
                          f"named in the invariant map but not found in the Rust sources: {sorted(missing)}" if missing else "", "meta"))

    selected = {c["id"] for c in cases} if tier == "full" else {i for i in SMOKE if any(c["id"] == i for c in cases)}
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
        except (KeyError, IndexError, TypeError, ValueError) as exc:
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
    parser = argparse.ArgumentParser(description="G02 end-to-end runner and judge (ffw-ld0)")
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
    print(f"G02 e2e tier={args.tier}: {verdict}  planned={len(results)} passed={counts['passed']} "
          f"failed={counts['failed']} blocked={counts['blocked']}")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        path = os.path.join(args.receipts, f"g02-{(meta['vectors_sha256'] or 'none')[:12]}-{counts['passed']}p.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"schema": "ffw.g02.receipt.v1", "tier": args.tier, "counts": counts, "exit_code": exit_code(results),
                       "judged_logs": [{"path": os.path.basename(p), "sha256": h} for p, h in (logs.files if logs else [])],
                       "repeated_inputs_skipped": list(logs.repeated_inputs) if logs else [],
                       "unattributed_logs": list(logs.unattributed_logs) if logs else [],
                       **meta, "results": [r.as_dict() for r in results]}, handle, indent=1, sort_keys=True)
            handle.write("\n")
        print("receipt:", path)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
