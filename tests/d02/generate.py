"""Deterministic D02 vector generator (ffw-7s0). Expected values come only from reference.py.

Writes tests/d02/vectors.json (via run_cases.py --write-vectors). The committed file must equal a
fresh generation; the runner checks that on every run.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
from typing import Any, Callable, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d02_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
SCHEMA = "ffw.d02.vectors.v1"

INVARIANTS: Dict[str, str] = {
    "D02-INV-DESIGN": "crossover coefficient designs match an independent bilinear-transform calculation",
    "D02-INV-GOLDEN-RESPONSE": "golden impulse and step responses of the admitted realization match an independent f64 reference",
    "D02-INV-DC": "DC rejection follows y[n] = x * R^n",
    "D02-INV-LIMITER": "limiter attack and release follow their one-pole closed forms",
    "D02-INV-MAX-GAIN": "gain ceiling caps trim * user gain",
    "D02-INV-OUTPUT-CEILING": "the hard output ceiling bounds a limiter overshoot and counts it",
    "D02-INV-MALFORMED": "malformed or unstable calibration is refused with the exact reason and the board stays muted",
    "D02-INV-ADMITTED-REALIZATION": "coefficients are judged on the stored f32 values, with exact gain and intermediate-range bounds",
    "D02-INV-BAND-POLICY": "tweeter, woofer and sub roles must meet their stop-band guards",
    "D02-INV-UNKNOWN-BOARD": "an unknown board or a missing calibration comes up fail-muted and never unmutes",
    "D02-INV-PERSISTENCE": "thermal and limiter history survive seek, reconnect, source replacement and profile switch",
    "D02-INV-FAIL-MUTED-UNSAFE": "an unsafe profile switch leaves the board muted until a valid profile is admitted",
    "D02-INV-FAULT-LATCH": "a thermal fault ramps to silence, stays latched, and clears only after cooling",
    "D02-INV-NO-ALLOC": "rendering a block performs no allocator calls",
}

EXTERNAL: Dict[str, List[str]] = {
    "D02-INV-MAX-GAIN": ["franken-dsp::protection::tests::the_gain_ceiling_caps_trim_times_user_gain"],
    "D02-INV-OUTPUT-CEILING": ["franken-dsp::protection::tests::the_hard_output_ceiling_catches_a_limiter_overshoot_and_counts_it"],
    "D02-INV-ADMITTED-REALIZATION": ["franken-dsp::protection::tests::coefficients_are_judged_on_the_stored_f32_value"],
    "D02-INV-NO-ALLOC": [
        "franken-alloc-probe::protection_render_into_does_not_allocate",
        "franken-alloc-probe::protection_error_and_fault_paths_do_not_allocate",
    ],
}


def spec_of(kind: str, fc: float) -> dict:
    return ref.butterworth(kind, fc)


def design_cases() -> List[dict]:
    cases = []
    for i, (kind, fc) in enumerate([("lp", 120), ("lp", 300), ("lp", 2000), ("hp", 2200), ("hp", 3000), ("hp", 100)], 1):
        cases.append({"id": f"D02-DESIGN-{i:03d}", "kind": "design", "invariants": ["D02-INV-DESIGN"],
                      "filter": kind, "fc_hz": float(fc), "expect": spec_of(kind, fc)})
    return cases


def section_response_cases() -> List[dict]:
    peaking = {"b0": 1.0, "b1": -1.2, "b2": 0.5, "a1": -0.9, "a2": 0.3}
    specs = [("LP300", spec_of("lp", 300)), ("LP120", spec_of("lp", 120)), ("HP2200", spec_of("hp", 2200)),
             ("HP3000", spec_of("hp", 3000)), ("EQ", peaking)]
    cases, n = [], 0
    for name, spec in specs:
        for drive in ("impulse", "step"):
            n += 1
            xs = [1.0] + [0.0] * 511 if drive == "impulse" else [1.0] * 512
            cases.append({"id": f"D02-RESP-{n:03d}", "kind": "section_response",
                          "invariants": ["D02-INV-GOLDEN-RESPONSE"], "title": f"{name} {drive}",
                          # 1e-6: the realization keeps f64 state, so only the final rounding of the
                          # output to f32 (about 6e-8) remains. 5e-5 would let an f32 state back in.
                          "spec": spec, "drive": drive, "length": 512, "tolerance": 1e-6,
                          "expect": ref.df1(ref.stored(spec), xs)})
    return cases


def dc_cases() -> List[dict]:
    return [{"id": f"D02-DC-{i:03d}", "kind": "dc_response", "invariants": ["D02-INV-DC"],
             "hz": hz, "x": 0.5, "length": 200, "tolerance": 2e-5, "expect": ref.dc_response(hz, 0.5, 200)}
            for i, hz in enumerate((5.0, 20.0), 1)]


def limiter_cases() -> List[dict]:
    rows = [(0.5, 1.0, 50.0, [(0.25, 100), (1.0, 400), (0.0, 2000)]),
            (0.8, 0.2, 5.0, [(0.9, 300), (0.5, 300)]),
            (0.3, 5.0, 200.0, [(0.0, 50), (0.6, 600), (-0.6, 600), (0.1, 1500)])]
    cases = []
    for i, (thr, att, rel, segments) in enumerate(rows, 1):
        gains, outs = ref.limiter_response(thr, att, rel, segments)
        cases.append({"id": f"D02-LIM-{i:03d}", "kind": "limiter_response", "invariants": ["D02-INV-LIMITER"],
                      "threshold": thr, "attack_ms": att, "release_ms": rel, "segments": [list(s) for s in segments],
                      "tolerance": 3e-4, "expect_gain": gains, "expect_out": outs})
    return cases


Mutation = Callable[[dict], None]


def validation_cases() -> List[dict]:
    def hp(fc):
        return spec_of("hp", fc)

    def lp(fc):
        return spec_of("lp", fc)

    def setv(path_fn: Callable[[dict], Any], key: Any, value: Any) -> Mutation:
        def apply(cal: dict) -> None:
            path_fn(cal)[key] = value
        return apply

    chan = lambda i: (lambda cal: cal["channels"][i])
    rows: List[Any] = [
        # (name, fixture, mutation, invariants)
        ("positive S5", "S5", None, ["D02-INV-MALFORMED"]),
        ("positive S3", "S3", None, ["D02-INV-MALFORMED"]),
        ("positive S1", "S1", None, ["D02-INV-MALFORMED"]),
        ("positive Sub", "Sub", None, ["D02-INV-MALFORMED"]),
        ("schema", "S5", lambda c: c.__setitem__("schema", "ffw.d02.calibration.v0"), ["D02-INV-MALFORMED"]),
        ("measured provenance in host simulation", "S5", lambda c: c["provenance"].__setitem__("kind", "owner_measured"), ["D02-INV-MALFORMED"]),
        ("sample rate", "S5", lambda c: c.__setitem__("sample_rate_hz", 44100), ["D02-INV-MALFORMED"]),
        ("ramp too short", "S5", lambda c: c.__setitem__("ramp_ms", 0.5), ["D02-INV-MALFORMED"]),
        ("fault ramp too long", "S5", lambda c: c.__setitem__("fault_ramp_ms", 200.0), ["D02-INV-MALFORMED"]),
        ("source ramp too long", "S5", lambda c: c.__setitem__("source_ramp_ms", 5000.0), ["D02-INV-MALFORMED"]),
        ("channel count", "S5", lambda c: c["channels"].pop(), ["D02-INV-MALFORMED"]),
        ("role", "S5", setv(lambda c: c["channels"][0], "role", "tweeter_right"), ["D02-INV-MALFORMED"]),
        ("trim zero", "S5", setv(chan(1), "trim", 0.0), ["D02-INV-MALFORMED"]),
        ("trim above range", "S5", setv(chan(1), "trim", 5.0), ["D02-INV-MALFORMED"]),
        ("max gain", "S5", setv(chan(1), "max_gain", 0.001), ["D02-INV-MALFORMED"]),
        ("ceiling", "S5", setv(chan(1), "ceiling", 1.5), ["D02-INV-MALFORMED"]),
        ("dc corner", "S5", setv(chan(1), "dc_block_hz", 0.5), ["D02-INV-MALFORMED"]),
        ("limiter threshold above ceiling", "S5", lambda c: c["channels"][1]["limiter"].__setitem__("threshold", 0.99), ["D02-INV-MALFORMED"]),
        ("limiter attack", "S5", lambda c: c["channels"][1]["limiter"].__setitem__("attack_ms", 0.01), ["D02-INV-MALFORMED"]),
        ("limiter release", "S5", lambda c: c["channels"][1]["limiter"].__setitem__("release_ms", 0.5), ["D02-INV-MALFORMED"]),
        ("thermal tau", "S5", lambda c: c["channels"][1]["thermal"].__setitem__("tau_s", 0.01), ["D02-INV-MALFORMED"]),
        ("thermal soft", "S5", lambda c: c["channels"][1]["thermal"].__setitem__("soft_ms", 0.0), ["D02-INV-MALFORMED"]),
        ("thermal hard not above soft", "S5", lambda c: c["channels"][1]["thermal"].__setitem__("hard_ms", 0.30), ["D02-INV-MALFORMED"]),
        ("five sections", "S5", lambda c: c["channels"][0]["sections"].extend([copy.deepcopy(c["channels"][0]["sections"][0]) for _ in range(4)]), ["D02-INV-MALFORMED"]),
        ("coefficient overflows f32", "S5", lambda c: c["channels"][0]["sections"][0].__setitem__("b0", 1.0e39), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("coefficient above 8", "S5", lambda c: c["channels"][0]["sections"][0].__setitem__("b2", 9.0), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("pole product on the unit circle", "S5", lambda c: c["channels"][0]["sections"][0].__setitem__("a2", 1.0), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("poles outside the unit circle", "S5", lambda c: c["channels"][0]["sections"][0].update({"a1": 2.5, "a2": 0.5}), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("high-Q resonator", "S5", lambda c: c["channels"][0].__setitem__("sections", [{"b0": 0.001, "b1": 0.0, "b2": 0.0, "a1": -1.998, "a2": 0.9981}]), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        # A converged one-sample section isolates the NUMERIC gain limit: bound = 2 * L1 = 2 * |b0|.
        ("converged gain 6 is under the limit of 8", "S5", lambda c: c["channels"][2].__setitem__("sections", [{"b0": 3.0, "b1": 0.0, "b2": 0.0, "a1": 0.0, "a2": 0.0}]), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("converged gain 10 is over the limit of 8", "S5", lambda c: c["channels"][2].__setitem__("sections", [{"b0": 5.0, "b1": 0.0, "b2": 0.0, "a1": 0.0, "a2": 0.0}]), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("intermediate range only", "S5", lambda c: c["channels"][2].__setitem__("sections", [{"b0": 1.0, "b1": -2.0, "b2": 1.0, "a1": -1.7196056842803955, "a2": 0.81}]), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("100 Hz high-pass trips the intermediate bound", "S5", lambda c: c["channels"][2].__setitem__("sections", [hp(100)]), ["D02-INV-MALFORMED", "D02-INV-ADMITTED-REALIZATION"]),
        ("tweeter with no crossover", "S5", lambda c: c["channels"][0].__setitem__("sections", []), ["D02-INV-BAND-POLICY"]),
        ("tweeter with a low-pass", "S5", lambda c: c["channels"][0].__setitem__("sections", [lp(2000)]), ["D02-INV-BAND-POLICY"]),
        ("woofer with a high-pass", "S5", lambda c: c["channels"][4].__setitem__("sections", [hp(2200)]), ["D02-INV-BAND-POLICY"]),
        ("sub with no low-pass", "Sub", lambda c: c["channels"][0].__setitem__("sections", []), ["D02-INV-BAND-POLICY"]),
        ("tweeter with a 3 kHz high-pass is fine", "S3", lambda c: c["channels"][2].__setitem__("sections", [hp(3000)]), ["D02-INV-BAND-POLICY"]),
        ("order: parameter before section", "S5", lambda c: (c["channels"][0].__setitem__("trim", 0.0), c["channels"][0]["sections"][0].__setitem__("a2", 1.0)), ["D02-INV-MALFORMED"]),
        ("order: lower channel first", "S5", lambda c: (c["channels"][1].__setitem__("trim", 0.0), c["channels"][0]["sections"][0].__setitem__("a2", 1.0)), ["D02-INV-MALFORMED"]),
    ]
    cases = []
    for n, (name, fixture, mutate, invariants) in enumerate(rows, 1):
        cal = ref.synthetic_calibration(fixture)
        if mutate is not None:
            mutate(cal)
        try:
            ref.validate_calibration(cal, fixture)
            expect: dict = {"status": "active"}
        except ref.RefError as e:
            expect = {"status": "fail_muted", **e.as_dict()}
        cases.append({"id": f"D02-VAL-{n:03d}", "kind": "validation", "title": name, "invariants": invariants,
                      "fixture": fixture, "calibration": cal, "expect": expect})
    # structurally malformed documents (planted; expected by construction)
    base = ref.synthetic_calibration("S3")
    unknown = copy.deepcopy(base)
    unknown["unexpected_field"] = 1
    wrong_type = copy.deepcopy(base)
    wrong_type["ramp_ms"] = "fast"
    missing = copy.deepcopy(base)
    del missing["channels"]
    for k, (name, doc) in enumerate((("unknown field", unknown), ("wrong type", wrong_type), ("missing field", missing)), len(rows) + 1):
        cases.append({"id": f"D02-VAL-{k:03d}", "kind": "validation", "title": name, "invariants": ["D02-INV-MALFORMED"],
                      "fixture": "S3", "calibration": doc,
                      "expect": {"status": "fail_muted", "error": "malformed_calibration", "channel": None, "section": None, "parameter": None}})
    return cases


def _drive(kind: str, amplitude: float, blocks: int) -> list:
    return ["drive", kind, amplitude, blocks]


def scenario_cases() -> List[dict]:
    s3 = ref.synthetic_calibration("S3")
    thermal = ref.synthetic_calibration("S3")
    thermal["channels"][0]["thermal"] = {"tau_s": 0.05, "soft_ms": 0.05, "hard_ms": 0.2}
    switch_valid = copy.deepcopy(s3)
    switch_valid["channels"][2]["sections"] = [spec_of("hp", 3000)]
    switch_unsafe = copy.deepcopy(s3)
    switch_unsafe["channels"][2]["sections"][0]["a2"] = 1.5

    def scenario(case_id, title, check, invariants, calibration, ops, alternates=None, admission="host", present=True):
        return {"id": case_id, "kind": "scenario", "title": title, "check": check, "invariants": invariants,
                "fixture": "S3", "admission": admission, "calibration_present": present, "calibration": calibration,
                "alternates": alternates or {}, "ops": ops}

    settle = [["unmute"], _drive("silence", 0.0, 4)]
    return [
        scenario("D02-SCN-001", "history survives seek, reconnect and source replacement", "persistence",
                 ["D02-INV-PERSISTENCE"], s3,
                 settle + [_drive("nyquist_left", 0.9, 6), ["event", "seek"], _drive("nyquist_left", 0.9, 1),
                           ["event", "reconnect"], _drive("nyquist_left", 0.9, 1),
                           ["event", "source_replaced"], _drive("nyquist_left", 0.9, 1)]),
        scenario("D02-SCN-002", "thermal overdrive faults, stays muted, cools, clears and resumes", "thermal_cycle",
                 ["D02-INV-FAULT-LATCH", "D02-INV-PERSISTENCE"], thermal,
                 settle + [_drive("nyquist_left", 0.6, 16), _drive("silence", 0.0, 2), ["unmute"], ["clear_fault"],
                           _drive("silence", 0.0, 20), ["clear_fault"], _drive("nyquist_left", 0.3, 3)]),
        scenario("D02-SCN-003", "a valid profile switch drains to silence and carries history", "switch_valid",
                 ["D02-INV-PERSISTENCE"], s3,
                 settle + [_drive("nyquist_left", 0.5, 5), ["switch", "valid"], _drive("nyquist_left", 0.5, 8)],
                 {"valid": switch_valid}),
        scenario("D02-SCN-004", "an unsafe profile switch leaves the board muted until a valid one is admitted", "switch_unsafe",
                 ["D02-INV-FAIL-MUTED-UNSAFE", "D02-INV-PERSISTENCE"], s3,
                 settle + [_drive("nyquist_left", 0.5, 4), ["switch", "unsafe"], _drive("nyquist_left", 0.5, 3), ["unmute"],
                           ["switch", "valid"], _drive("nyquist_left", 0.5, 6)],
                 {"valid": s3, "unsafe": switch_unsafe}),
        scenario("D02-SCN-005", "a fixture board is refused in production and stays muted", "unknown_board",
                 ["D02-INV-UNKNOWN-BOARD"], s3,
                 [["unmute"], ["gain", 1.0], _drive("nyquist_left", 0.5, 3), ["unmute"]], admission="production"),
        scenario("D02-SCN-006", "a board without a calibration stays muted", "no_calibration",
                 ["D02-INV-UNKNOWN-BOARD"], None,
                 [["unmute"], ["gain", 1.0], _drive("nyquist_left", 0.5, 3), ["unmute"]], present=False),
    ]


def build() -> dict:
    cases = (design_cases() + section_response_cases() + dc_cases() + limiter_cases() + validation_cases()
             + scenario_cases())
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    return {"schema": SCHEMA, "generator": "tests/d02/generate.py (reference: tests/d02/reference.py)",
            "invariants": INVARIANTS, "external": EXTERNAL, "cases": cases}


def dumps(doc: dict) -> str:
    def j(x: Any) -> str:
        return json.dumps(x, sort_keys=True, separators=(",", ":"))

    head = {k: v for k, v in doc.items() if k != "cases"}
    lines = [j(head)[:-1] + ',"cases":[']
    for i, case in enumerate(doc["cases"]):
        lines.append("  " + j(case) + ("," if i + 1 < len(doc["cases"]) else ""))
    lines.append("]}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    text = dumps(build())
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
