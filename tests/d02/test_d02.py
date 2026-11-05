"""Tests for the D02 reference, vectors and judge (ffw-7s0). Host-only, standard library only.

    python3 -B -I tests/d02/test_d02.py

SCOPE. The observations built here come from the reference's own expectations and from traces
constructed out of closed forms. They exercise the JUDGE (accept a consistent log, reject a
perturbed one, refuse to pass what was not observed). They say nothing about the Rust code; that
evidence is the centrally run cargo log fed to ``run_cases.py --judge``.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import sys
import tempfile
import unittest
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d02_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
gen = _load("generate")
runner = _load("run_cases")
rc = _load("realized_chain")
model = _load("loop_history_model")


# ---- constructed observations ----------------------------------------------------------------------


def observed_for(case: dict) -> Optional[dict]:
    kind, base = case["kind"], {"id": case["id"], "kind": case["kind"]}
    if kind == "design":
        return {**base, "coefficients": case["expect"]}
    if kind in ("section_response", "dc_response"):
        return {**base, "y": case["expect"]}
    if kind == "limiter_response":
        return {**base, "gain": case["expect_gain"], "out": case["expect_out"]}
    if kind == "validation":
        return {**base, **case["expect"]}
    return None


def entry(op: str, **kw: Any) -> dict:
    out = {"op": op, "result": "ok", "status": "active", "thermal": [0.0, 0.0, 0.0], "limiter": [1.0, 1.0, 1.0],
           "applied_gain": 1.0, "user_gain": 1.0, "muted": False, "pending": False, "blocks": []}
    out.update(kw)
    return out


def block(peak0: int = 20000, status: str = "active", gain: float = 1.0, fade: float = 1.0, scaled: int = 0) -> dict:
    return {"status": status, "applied_gain": gain, "source_fade": fade, "peak": [peak0, 0, 0],
            "thermal_max": 0.0, "limiter_min": 1.0, "clipped": 0, "scaled": scaled}


def good_persistence(case: dict) -> List[dict]:
    v = ref.nyquist_drive_level(0.9)
    th = ref.thermal_after(0.0, v, 2.0, 6 * 256)
    lim = 0.8 / v
    steady = dict(thermal=[th, 0.0, 0.0], limiter=[lim, 1.0, 1.0])
    t = [entry("unmute"), entry("drive", blocks=[block(0)] * 4),
         entry("drive", blocks=[block(29000)] * 6, **steady)]
    for event in ("seek", "reconnect", "source_replaced"):
        t.append(entry("event", **steady))
        steady = dict(thermal=[steady["thermal"][0] * 1.0001, 0.0, 0.0], limiter=[0.896, 1.0, 1.0])
        t.append(entry("drive", blocks=[block(8000, fade=256 / 960)], **steady))
    return t


def good_thermal_cycle(case: dict) -> List[dict]:
    cal = case["calibration"]["channels"][0]["thermal"]
    v = ref.nyquist_drive_level(0.6)
    fault = int(ref.samples_to_reach(cal["hard_ms"], v, cal["tau_s"])) // 256
    soft = int(ref.samples_to_reach(cal["soft_ms"], v, cal["tau_s"])) // 256
    drive = []
    for i in range(16):
        if i < fault:
            drive.append(block(19000, scaled=1 if i >= soft else 0))
        elif i == fault:
            drive.append(block(19000, status="faulted:thermal_hard:0", scaled=1))
        else:
            drive.append(block(0, status="faulted:thermal_hard:0", gain=0.0))
    drive[-1]["applied_gain"] = 0.0
    hot = 0.15
    cooled = hot * (1.0 - ref.smoothing(cal["tau_s"] * 1000.0)) ** (20 * 256)
    faulted = "faulted:thermal_hard:0"
    return [entry("unmute"), entry("drive", blocks=[block(0)] * 4), entry("drive", blocks=drive, status=faulted),
            entry("drive", blocks=[block(0, status=faulted, gain=0.0)] * 2, status=faulted),
            entry("unmute", result="unmute_refused", status=faulted),
            entry("clear_fault", result="not_cooled", status=faulted, thermal=[hot, 0.0, 0.0]),
            entry("drive", blocks=[block(0, status=faulted, gain=0.0)] * 20, status=faulted, thermal=[cooled, 0.0, 0.0]),
            entry("clear_fault", thermal=[cooled, 0.0, 0.0]),
            entry("drive", blocks=[block(0, gain=0.3), block(4000, gain=0.9), block(9000)])]


def good_switch_valid(case: dict) -> List[dict]:
    return [entry("unmute"), entry("drive", blocks=[block(0)] * 4),
            entry("drive", blocks=[block(15000)] * 5, thermal=[0.004, 0.0, 0.0]),
            entry("switch", pending=True, thermal=[0.004, 0.0, 0.0]),
            entry("drive", blocks=[block(9000, gain=1.0 - 256 / 480)] + [block(9000, gain=1.0)] * 7, thermal=[0.0045, 0.0, 0.0])]


def good_switch_unsafe(case: dict) -> List[dict]:
    muted = "fail_muted:unstable"
    return [entry("unmute"), entry("drive", blocks=[block(0)] * 4),
            entry("drive", blocks=[block(15000)] * 4, thermal=[0.004, 0.0, 0.0]),
            entry("switch", result="unstable", status=muted),
            entry("drive", blocks=[block(2000, status=muted, gain=0.0), block(0, status=muted, gain=0.0),
                                   block(0, status=muted, gain=0.0)], status=muted),
            entry("unmute", result="unmute_refused", status=muted),
            entry("switch"),
            entry("drive", blocks=[block(100, gain=0.5)] + [block(15000, gain=1.0)] * 5, thermal=[0.0045, 0.0, 0.0])]


def good_stays_muted(status: str) -> Callable[[dict], List[dict]]:
    def build(case: dict) -> List[dict]:
        refused = dict(result="unmute_refused", status=status)
        return [entry("unmute", **refused), entry("gain", status=status),
                entry("drive", blocks=[block(0, status=status, gain=0.0)] * 3, status=status),
                entry("unmute", **refused)]
    return build


GOOD: Dict[str, Callable[[dict], List[dict]]] = {
    "persistence": good_persistence, "thermal_cycle": good_thermal_cycle, "switch_valid": good_switch_valid,
    "switch_unsafe": good_switch_unsafe, "unknown_board": good_stays_muted("fail_muted:unknown_board"),
    "no_calibration": good_stays_muted("fail_muted:no_calibration"),
}


# ---- an RCH-shaped cargo log (headers up front, then the sections) --------------------------------------


def cargo_log(doc: dict, drop_tests: tuple = (), drop_cases: tuple = (), perturb: Optional[dict] = None) -> str:
    required = runner.derive_rust_tests()
    by_stem: Dict[str, List[str]] = {}
    for stem, name in required:
        by_stem.setdefault(stem, []).append(name)
    observed: List[str] = []
    for case in doc["cases"]:
        if case["id"] in drop_cases:
            continue
        obs = observed_for(case)
        if obs is None:
            obs = {"id": case["id"], "kind": "scenario", "trace": GOOD[case["check"]](case)}
        if perturb and case["id"] in perturb:
            obs = perturb[case["id"]](copy.deepcopy(obs))
        observed.append("D02-OBSERVED " + json.dumps(obs))
    stems = ["franken_dsp", "d02_vectors", "protection_no_alloc", "d02_protection_history"]

    def header(stem: str) -> str:
        h = hashlib.sha256(stem.encode()).hexdigest()[:16]
        return f"     Running tests (.rch-target-vmi0000000-pool-{'0' * 32}/debug/build/x/{h}/out/{stem}-{h})"

    lines = [header(s) for s in stems]
    for stem in stems:
        names = [n for n in by_stem.get(stem, []) if n not in drop_tests]
        body = [f"test {n} ... ok" for n in names]
        extra = observed if stem == "d02_vectors" else []
        lines += [f"running {len(names)} test{'' if len(names) == 1 else 's'}"] + body[:1] + extra + body[1:]
        lines += ["", f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s", ""]
    return "\n".join(lines) + "\n"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.doc = json.load(handle)

    def judge(self, text: str, tier: str = "full") -> List[Any]:
        path = os.path.join(self.tmp.name, "cargo.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        logs = runner.Logs()
        logs.add(path)
        return runner.run(tier, logs)[0]

    def by(self, results: List[Any], status: str) -> List[str]:
        return [r.case_id for r in results if r.status == status]


class ReferenceAndVectors(Base):
    def test_reference_self_checks_hold(self) -> None:
        self.assertEqual(runner.reference_problems(), [])

    def test_committed_vectors_equal_a_fresh_generation(self) -> None:
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.assertTrue(handle.read() == gen.dumps(gen.build()), "vectors.json is stale: --write-vectors")

    def test_every_invariant_is_covered_and_ids_are_unique(self) -> None:
        ids = [c["id"] for c in self.doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        covered = {i for c in self.doc["cases"] for i in c["invariants"]}
        external = {k for k, v in self.doc["external"].items() if v}
        self.assertEqual(set(self.doc["invariants"]) - covered - external, set())

    def test_the_validator_reproduces_the_hand_derived_planted_cases(self) -> None:
        want = {"boost +24 dB then trim: middle node over the limit": ("intermediate_range_exceeded", 2),
                "high-Q resonator": ("gain_bound_exceeded", 0),
                "converged gain 10 is over the limit of 8": ("gain_bound_exceeded", 2),
                "woofer with a high-pass": ("band_policy_violated", 4),
                "order: lower channel first": ("unstable", 0)}
        seen = {c["title"]: c["expect"] for c in self.doc["cases"] if c["kind"] == "validation"}
        for title, (code, channel) in want.items():
            self.assertEqual((seen[title]["error"], seen[title]["channel"]), (code, channel), title)
        # The positive controls: designs the product bound refused (or that sit just inside a limit) are admitted.
        for title in ("positive S5", "old intermediate-range design is admitted under the exact bound",
                      "100 Hz high-pass is admitted under the exact bound",
                      "60 Hz high-pass with a 1 Hz DC corner is admitted (long tail)",
                      "boost +20 dB then trim: middle node within the limit",
                      "converged gain 6 is under the limit of 8"):
            self.assertEqual(seen[title]["status"], "active", title)

    def test_section_vectors_reject_an_f32_state_realization_and_accept_the_f64_one(self) -> None:
        """The b9 defect: an f32 direct-form-II-transposed state drifted from an exact evaluation of
        the same stored coefficients. Emulate both realizations op for op."""
        r = ref.q32

        def f32_state(c: List[float], xs: List[float]) -> List[float]:
            b0, b1, b2, a1, a2 = c
            z1 = z2 = 0.0
            out = []
            for x in xs:
                y = r(r(b0 * x) + z1)
                z1 = r(r(r(b1 * x) - r(a1 * y)) + z2)
                z2 = r(r(b2 * x) - r(a2 * y))
                out.append(y)
            return out

        def f64_state(c: List[float], xs: List[float]) -> List[float]:
            b0, b1, b2, a1, a2 = c
            z1 = z2 = 0.0
            out = []
            for x in xs:
                y = b0 * x + z1
                z1 = b1 * x - a1 * y + z2
                z2 = b2 * x - a2 * y
                out.append(r(y))  # the sample leaves the section as f32
            return out

        cases = [c for c in self.doc["cases"] if c["kind"] == "section_response"]
        self.assertEqual(len(cases), 10)
        failing_f32 = []
        for case in cases:
            xs = [1.0] + [0.0] * 511 if case["drive"] == "impulse" else [1.0] * 512
            stored = ref.stored(case["spec"])
            worst64 = max(abs(a - b) for a, b in zip(f64_state(stored, xs), case["expect"]))
            worst32 = max(abs(a - b) for a, b in zip(f32_state(stored, xs), case["expect"]))
            self.assertLess(worst64, case["tolerance"], f"{case['title']}: the f64 realization must pass")
            if worst32 > case["tolerance"]:
                failing_f32.append(case["id"])
        self.assertTrue({"D02-RESP-002", "D02-RESP-004"} <= set(failing_f32), failing_f32)
        self.assertLessEqual(max(c["tolerance"] for c in cases), 1e-6, "the tolerance must not be widened")

    def test_vectors_distinguish_classic_wrong_rules(self) -> None:
        with open(runner.VECTORS, encoding="utf-8") as handle:
            committed = handle.read()
        gref = gen.ref  # the generator loads its own copy of the reference: mutate THAT one
        self.assertTrue(gen.dumps(gen.build()) == committed, "baseline must be green before mutating")
        saved = (gref.STABILITY_MARGIN, gref.MAX_INTERMEDIATE, gref.smoothing, gref.MAX_L1_GAIN)
        try:
            for name, mutate in (
                ("margin 1e-3 rejects a 120 Hz low-pass", lambda: setattr(gref, "STABILITY_MARGIN", 1e-3)),
                ("intermediate limit loosened", lambda: setattr(gref, "MAX_INTERMEDIATE", 30.0)),
                ("gain limit loosened", lambda: setattr(gref, "MAX_L1_GAIN", 80.0)),
                ("limiter time constants doubled", lambda: setattr(gref, "smoothing", lambda ms: 1.0 - (1.0 - saved[2](ms)) ** 2)),
            ):
                mutate()
                with self.subTest(wrong_rule=name):
                    self.assertTrue(gen.dumps(gen.build()) != committed, f"vectors do not detect: {name}")
                gref.STABILITY_MARGIN, gref.MAX_INTERMEDIATE, gref.smoothing, gref.MAX_L1_GAIN = saved
        finally:
            gref.STABILITY_MARGIN, gref.MAX_INTERMEDIATE, gref.smoothing, gref.MAX_L1_GAIN = saved
        self.assertTrue(gen.dumps(gen.build()) == committed, "reference restored")


# Bounds from the reference at the DC corner named in DESIGNS (5 Hz unless the name says 1 Hz); copied into the Rust test
# `the_exact_bound_matches_the_independent_reference_on_pinned_designs`.
PINNED_BOUNDS = {
    "LP120": (1.900829189887, 2.0),
    "HP100": (2.483242705140, 2.483242705140),
    "HP60": (2.510871557174, 2.510871557174),
    "boost +20 dB then trim": (3.368107524692, 13.472430098766),
    "gain 3": (6.0, 6.0),
    "HP60, 1 Hz DC corner": (3.295743724244, 5.549311119716),
}
PINNED_REFUSED_BOOST = (3.085408878402, 20.569391705325)


class ExactBound(Base):
    """The admitted intermediate bound against the realized chain (D02 acceptance: intermediate-state ranges).

    ``realized_chain`` drives an operation-for-operation emulation of the renderer with the input that maximises each
    quantity, so these tests compare the bound with what the real filter reaches, not with another formula."""

    RUN = 2 * ref.L1_HORIZON
    _rows: Optional[Dict[str, List[dict]]] = None

    @classmethod
    def rows(cls) -> Dict[str, List[dict]]:
        if cls._rows is None:
            cls._rows = {name: rc.measure(specs, dc_hz, cls.RUN) for name, dc_hz, specs in rc.DESIGNS}
        return cls._rows

    @staticmethod
    def secs(specs: List[dict]) -> List[List[float]]:
        return [ref.quantize_section(s, 0, k) for k, s in enumerate(specs)]

    def test_step_one_the_harness_measures_correctly_against_the_old_product_bound(self) -> None:
        """Before anything moves: the realized peak of every quantity of every committed design is at most the old product
        bound, equals the independent exact L1 norm, and the check can fail (it catches a halved product bound)."""
        bitten = False
        for name, rows in self.rows().items():
            for row in rows:
                with self.subTest(design=name, stage=row["stage"], q=row["q"]):
                    self.assertLessEqual(row["realized"], row["product"] * (1 + 1e-6))
                    self.assertAlmostEqual(row["realized"], row["exact_run"], delta=1e-5 * row["exact_run"] + 1e-12)
                bitten = bitten or row["realized"] > 0.5 * row["product"] * (1 + 1e-6)
        self.assertTrue(bitten, "no row would have been caught by a halved bound: the check does not bite")

    def test_step_two_the_exact_bound_is_sound_against_the_realized_chain_with_room_to_spare(self) -> None:
        for name, rows in self.rows().items():
            for row in rows:
                with self.subTest(design=name, stage=row["stage"], q=row["q"]):
                    self.assertLessEqual(row["realized"], row["bound"] * (1 + 1e-6), "the bound fell below a value the filter reaches")
                    self.assertLessEqual(row["bound"], row["product"] * (1 + 1e-12), "never looser than the product bound")
                    if row["bound"] < row["product"] - 1e-9 and row["realized"] > 0.0:
                        # Exact path active: the explicit margin is spare on top of the allowance for the part past the
                        # horizon, and f32 rounding (measured at under 2e-7 of the exact value) is 50000 times smaller.
                        self.assertGreaterEqual(row["bound"], row["realized"] * (1 + ref.BOUND_MARGIN / 2))
                        if "1 Hz" not in name:
                            self.assertLessEqual(row["bound"], row["realized"] * 1.10, "a bound 10% above the realized peak is loose")

    def test_the_long_tail_case_is_covered_by_the_remainder_allowance(self) -> None:
        """A 1 Hz DC corner leaves R^8191 = 0.34 of the rejector's response past the horizon: the sum over the horizon alone
        is low by up to 0.33, and the remainder allowance has to cover it."""
        for name in ("HP60, 1 Hz DC corner", "LP120, 1 Hz DC corner"):
            rows = [row for row in self.rows()[name] if row["realized"] > 0.0]
            self.assertGreater(max(row["exact_run"] - row["exact_horizon"] for row in rows), 0.15,
                               f"{name}: the part past the horizon is not the long-tail case it is meant to be")
            for row in rows:
                with self.subTest(design=name, stage=row["stage"], q=row["q"]):
                    self.assertLessEqual(row["exact_horizon"], row["realized"] + 1e-9)
                    self.assertGreaterEqual(row["bound"], row["realized"] * (1 + ref.BOUND_MARGIN / 2))

    def test_the_exact_bound_is_never_stricter_than_the_product_bound(self) -> None:
        """Pure relaxation by construction (the bound is the minimum of the two), checked over a design grid and the
        committed designs at three DC corners: no design admitted before is refused now, and the converged flag is unchanged."""
        designs = [(f"{kind}{fc}", [ref.butterworth(kind, float(fc))] * reps)
                   for kind in ("hp", "lp") for fc in (20, 60, 100, 300, 1000, 2200, 8000, 16000) for reps in (1, 2)]
        designs += [(name, specs) for name, _, specs in rc.DESIGNS]
        designs.append(("refused boost", rc.REFUSED_BOOST))
        newly_admitted = 0
        for hz in (1.0, 5.0, 100.0):
            dc_r = ref.dc_pole(hz)
            for name, specs in designs:
                secs = self.secs(specs)
                new, old = ref.chain_bounds(dc_r, secs), ref.product_bounds(secs)
                with self.subTest(design=name, dc_hz=hz):
                    self.assertEqual(new["converged"], old["converged"])
                    for stage, product in zip(new["stages"], old["stages"]):
                        for value, limit in zip(stage, product):
                            self.assertLessEqual(value, limit * (1 + 1e-12))
                    old_ok = old["converged"] and (old["stages"][-1][0] if secs else 2.0) <= ref.MAX_L1_GAIN \
                        and max([2.0] + [v for s in old["stages"] for v in s]) <= ref.MAX_INTERMEDIATE
                    new_ok = new["converged"] and new["gain"] <= ref.MAX_L1_GAIN and new["worst"] <= ref.MAX_INTERMEDIATE
                    if old_ok:
                        self.assertTrue(new_ok, "a design the product bound admitted is refused")
                    newly_admitted += int(new_ok and not old_ok)
        self.assertGreater(newly_admitted, 30, "the exact bound should admit the ordinary high-pass designs")

    def test_the_refusal_is_warranted_the_refused_boost_really_overflows_and_the_admitted_one_does_not(self) -> None:
        refused = rc.measure(rc.REFUSED_BOOST, 5.0, self.RUN)
        peak = max(row["realized"] for row in refused if row["stage"] == 0)
        self.assertGreater(peak, ref.MAX_INTERMEDIATE, "the refused design never exceeds the limit: the refusal is over-conservative")
        admitted = max(row["realized"] for row in self.rows()["boost +20 dB then trim"])
        self.assertLess(admitted, ref.MAX_INTERMEDIATE)
        high_pass = max(row["realized"] for name in ("HP100", "HP60", "HP60, 1 Hz DC corner") for row in self.rows()[name])
        self.assertLess(high_pass, 0.2 * ref.MAX_INTERMEDIATE, "60 and 100 Hz high-passes sit far inside the limit")

    def test_the_section_tail_allowance_covers_slow_converged_sections(self) -> None:
        """Sections that have only just converged (tail peak under the 1e-6 threshold, poles near 0.999) still have a
        response past the horizon; its L1 norm must be under the allowance the bound adds for it (tail * max(H, 1/(1-rho)))."""
        horizon, run = ref.L1_HORIZON, 1 << 18
        cases = 0
        for radius in (0.998, 0.9983, 0.9988, 0.9992):
            for theta_deg in (1.0, 20.0, 90.0):
                theta = math.radians(theta_deg)
                a1, a2 = -2.0 * radius * math.cos(theta), radius * radius
                scale = 1.0
                for _ in range(40):
                    c = [ref.q32(scale), 0.0, 0.0, ref.q32(a1), ref.q32(a2)]
                    _, tail = ref.section_l1(c)
                    if tail <= 0.9e-6:
                        break
                    scale *= 0.5 * 0.9e-6 / tail if tail > 0 else 1.0
                self.assertLessEqual(tail, ref.CONVERGED_TAIL)
                x1 = x2 = y1 = y2 = 0.0
                inside = outside = 0.0
                for n in range(run):
                    x = 1.0 if n == 0 else 0.0
                    y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2
                    if n < horizon:
                        inside += abs(y)
                    else:
                        outside += abs(y)
                    x2, x1, y2, y1 = x1, x, y1, y
                allowance = tail * max(float(horizon), 1.0 / (1.0 - ref.pole_radius(c)))
                with self.subTest(radius=radius, theta_deg=theta_deg):
                    self.assertLessEqual(outside, allowance, "the response past the horizon exceeds the tail allowance")
                    self.assertLess(outside, 0.2 * allowance, "less than a fifth of the allowance is used: spare to spare")
                    self.assertGreater(tail, 1.0e-8, "the case is not near the convergence threshold")
                cases += 1
        self.assertEqual(cases, 12)

    def test_pinned_numbers_for_the_rust_test(self) -> None:
        for name, (gain, worst) in PINNED_BOUNDS.items():
            dc_hz, specs = next((dc, s) for n, dc, s in rc.DESIGNS if n == name)
            got = ref.chain_bounds(ref.dc_pole(dc_hz), self.secs(specs))
            with self.subTest(design=name):
                self.assertAlmostEqual(got["gain"], gain, delta=1e-9 * gain)
                self.assertAlmostEqual(got["worst"], worst, delta=1e-9 * worst)
        got = ref.chain_bounds(ref.dc_pole(5.0), self.secs(rc.REFUSED_BOOST))
        self.assertAlmostEqual(got["gain"], PINNED_REFUSED_BOOST[0], delta=1e-9 * PINNED_REFUSED_BOOST[0])
        self.assertAlmostEqual(got["worst"], PINNED_REFUSED_BOOST[1], delta=1e-9 * PINNED_REFUSED_BOOST[1])
        self.assertGreater(got["worst"], ref.MAX_INTERMEDIATE)
        self.assertLessEqual(got["gain"], ref.MAX_L1_GAIN)

    def test_single_term_mutants_of_the_bound_are_killed_or_named_unkillable(self) -> None:
        """Plant each defect in the reference's bound and look for a killer among: soundness against the realized peaks
        (``sound``), the explicit spare (``spare``), the pinned numbers (``pin``) and pure relaxation (``relax``)."""
        killers: Dict[str, set] = {}
        for fault in ref.FAULTS:
            found = set()
            for name, dc_hz, specs in rc.DESIGNS:
                secs = self.secs(specs)
                dc_r = ref.dc_pole(dc_hz)
                mutant = ref.chain_bounds(dc_r, secs, fault)
                for k, rows in enumerate(self.rows()[name]):
                    stage, q = divmod(k, 3)
                    bound, product = mutant["stages"][stage][q], mutant["product"][stage][q]
                    if rows["realized"] > bound * (1 + 1e-6):
                        found.add("sound")
                    if bound < product - 1e-9 and rows["realized"] > 0.0 and bound < rows["realized"] * (1 + ref.BOUND_MARGIN / 2):
                        found.add("spare")
                    if bound > product * (1 + 1e-12):
                        found.add("relax")
                if name in PINNED_BOUNDS:
                    gain, worst = PINNED_BOUNDS[name]
                    if abs(mutant["gain"] - gain) > 1e-9 * gain or abs(mutant["worst"] - worst) > 1e-9 * worst:
                        found.add("pin")
            killers[fault] = found
        must = {"signed_sum": "sound", "no_states": "sound", "dc_l1_one": "sound", "no_dc_remainder": "sound",
                "no_margin": "spare", "worst_from_last_stage": "pin", "no_product_cap": "relax"}
        for fault, killer in must.items():
            self.assertIn(killer, killers[fault], f"{fault}: not killed by {killer}: {killers[fault]}")
        # Honest limit: on every committed design the sections' tail peak is far below the convergence threshold (below
        # 1e-30), so the tail term is zero and removing the tail allowance changes nothing the tests can see. A section that
        # has converged only just adds at most 8192e-6 * product / 2, comparable to the 1% margin (docs/contracts/d02.md).
        self.assertEqual(killers["no_tail"], set())
        self.assertEqual(set(killers) - set(must) - {"no_tail"}, set(), "a planted fault with no stated killer")


class JudgeBehavior(Base):
    def test_a_consistent_log_is_qualified(self) -> None:
        results = self.judge(cargo_log(self.doc))
        self.assertEqual(self.by(results, "failed"), [])
        self.assertEqual(self.by(results, "blocked"), [])
        self.assertEqual(runner.exit_code(results), 0)
        self.assertEqual(len(results), len(runner.run("full", None)[0]))

    def test_no_log_blocks_everything_rust_backed(self) -> None:
        results, _ = runner.run("full", None)
        self.assertEqual(runner.exit_code(results), 3)
        passed = [r.case_id for r in results if r.status == "passed"]
        self.assertTrue(all(i.startswith("D02-META-") for i in passed), passed)

    def test_a_missing_case_and_a_missing_rust_test_stay_blocked(self) -> None:
        name = "protection::tests::the_gain_ceiling_caps_trim_times_user_gain"
        results = self.judge(cargo_log(self.doc, drop_cases=("D02-SCN-003",), drop_tests=(name,)))
        self.assertEqual(sorted(self.by(results, "blocked")), sorted(["D02-SCN-003", f"RUST:franken_dsp::{name}"]))
        self.assertEqual(self.by(results, "failed"), [])
        self.assertEqual(runner.exit_code(results), 3)

    def test_numeric_divergences_are_reported_with_the_first_sample(self) -> None:
        def bend(obs: dict) -> dict:
            obs["y"][100] += 1e-3
            return obs
        results = self.judge(cargo_log(self.doc, perturb={"D02-RESP-001": bend}))
        failed = [r for r in results if r.status == "failed"]
        self.assertEqual([r.case_id for r in failed], ["D02-RESP-001"])
        self.assertIn("sample 100", failed[0].detail)

    def test_a_wrong_validation_outcome_fails_its_case(self) -> None:
        def accept(obs: dict) -> dict:
            return {"id": obs["id"], "kind": "validation", "status": "active"}
        results = self.judge(cargo_log(self.doc, perturb={"D02-VAL-027": accept}))
        self.assertEqual(self.by(results, "failed"), ["D02-VAL-027"])

    def test_every_scenario_judge_accepts_a_consistent_trace_and_rejects_a_perturbed_one(self) -> None:
        cases = {c["check"]: c for c in self.doc["cases"] if c["kind"] == "scenario"}
        self.assertEqual(set(cases), set(GOOD), "every scenario check has a constructed trace")
        perturbations = {
            "persistence": lambda t: t[3].__setitem__("thermal", [0.0, 0.0, 0.0]),   # an event reset the history
            "thermal_cycle": lambda t: t[2]["blocks"][12].__setitem__("peak", [900, 0, 0]),  # audio while faulted
            "switch_valid": lambda t: t[4]["blocks"][0].__setitem__("applied_gain", 1.0),    # no drain
            "switch_unsafe": lambda t: t[4]["blocks"][2].__setitem__("peak", [500, 0, 0]),   # audio while muted
            "unknown_board": lambda t: t[0].__setitem__("result", "ok"),                     # unmute allowed
            "no_calibration": lambda t: t[2]["blocks"][1].__setitem__("peak", [7, 0, 0]),
        }
        for check, case in cases.items():
            with self.subTest(check=check):
                good = GOOD[check](case)
                self.assertIsNone(runner.judge_case(case, {"trace": good}), "a consistent trace is accepted")
                bad = copy.deepcopy(good)
                perturbations[check](bad)
                self.assertIsNotNone(runner.judge_case(case, {"trace": bad}), "a perturbed trace is rejected")

    def test_a_closed_form_violation_in_a_trace_is_named(self) -> None:
        case = next(c for c in self.doc["cases"] if c.get("check") == "thermal_cycle")
        trace = good_thermal_cycle(case)
        trace[6]["thermal"] = [trace[5]["thermal"][0], 0.0, 0.0]  # no cooling at all
        self.assertIn("cooling", runner.judge_case(case, {"trace": trace}))
        trace = good_thermal_cycle(case)
        for b in trace[2]["blocks"]:
            b["status"] = "active"  # never faulted
        self.assertIn("never latched", runner.judge_case(case, {"trace": trace}))

    def test_d01_log_parser_reuse_leaves_d01_untouched(self) -> None:
        d01 = _load_d01()
        self.assertEqual(d01.OBSERVED.pattern, r"D01-OBSERVED (\{.*\})\s*$")
        self.assertEqual(runner.d01.OBSERVED.pattern, r"D02-OBSERVED (\{.*\})\s*$")
        self.assertIsNot(d01, runner.d01)


def _load_d01() -> Any:
    spec = importlib.util.spec_from_file_location("d02_t_pristine_d01", os.path.join(HERE, "..", "d01", "run_cases.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HISTORY_TESTS = (
    "history_survives_a_reconnect_through_the_real_loop",
    "history_survives_an_ingress_loss_discontinuity_epoch_through_the_real_loop",
    "history_survives_a_stop_and_restart_through_the_real_loop",
    "history_survives_a_profile_switch_through_the_real_loop",
    "a_latched_fault_survives_recover_and_every_loop_call_until_it_is_cooled_and_cleared",
    "a_loop_that_unlatched_the_board_at_recover_is_caught",
)
HISTORY_STEM = "d02_protection_history"


class LoopHistoryJudge(Base):
    """The speaker integration test is part of the D02 denominator: absent from the logs it is blocked."""

    def test_the_six_loop_tests_are_required_and_judged(self) -> None:
        required = sorted(n for s, n in runner.derive_rust_tests() if s == HISTORY_STEM)
        self.assertEqual(required, sorted(HISTORY_TESTS))
        passed = self.by(self.judge(cargo_log(self.doc)), "passed")
        for name in HISTORY_TESTS:
            self.assertIn(f"RUST:{HISTORY_STEM}::{name}", passed)

    def test_without_their_log_they_are_blocked_never_passed(self) -> None:
        results = self.judge(cargo_log(self.doc, drop_tests=HISTORY_TESTS))
        self.assertEqual(sorted(self.by(results, "blocked")), sorted(f"RUST:{HISTORY_STEM}::{n}" for n in HISTORY_TESTS))
        self.assertEqual(self.by(results, "failed"), [])
        self.assertEqual(runner.exit_code(results), 3)

    def test_a_failed_loop_test_fails_the_run(self) -> None:
        name = HISTORY_TESTS[0]
        text = cargo_log(self.doc)
        self.assertIn(f"test {name} ... ok", text)
        results = self.judge(text.replace(f"test {name} ... ok", f"test {name} ... FAILED"))
        self.assertEqual(self.by(results, "failed"), [f"RUST:{HISTORY_STEM}::{name}"])
        self.assertEqual(runner.exit_code(results), 1)


class LoopHistorySource(unittest.TestCase):
    """Guards on the Rust test's shape: the control and the plant are both run, and nothing was loosened. Heuristic
    source checks, not a proof about the compiled test."""

    def setUp(self) -> None:
        with open(model.RUST, encoding="utf-8") as handle:
            self.text = handle.read()

    def test_every_event_test_runs_the_control_and_the_plant(self) -> None:
        helper = re.search(r"fn assert_survives_and_the_plant_is_caught\(event: Event\) \{(.*?)\n\}\n", self.text, re.S)
        self.assertIsNotNone(helper)
        body = helper.group(1)
        for needle in ("run_event(event, false)", "run_event(event, true)", "control.is_empty()", "!planted.is_empty()"):
            self.assertIn(needle, body)
        calls = re.findall(r"assert_survives_and_the_plant_is_caught\(Event::(\w+)\)", self.text)
        self.assertEqual(sorted(calls), ["IngressLossEpoch", "ProfileSwitch", "Reconnect", "StopThenStart"])

    def test_the_fault_case_runs_the_control_and_the_plant(self) -> None:
        for needle in ("run_latch(false)", "run_latch(true)", "!planted.is_empty()", "control.is_empty()"):
            self.assertIn(needle, self.text)

    def test_nothing_is_allowed_ignored_or_loosened(self) -> None:
        self.assertNotIn("#[allow", self.text)
        self.assertNotIn("#[ignore", self.text)
        self.assertEqual(self.text.count("*l.dsp_mut() ="), 1, "the one planted defect is the board replacement")
        self.assertLessEqual(model.rust_constants()["slack"], 1e-2, "a loose slack would hide a partial loss")

    def test_the_event_is_shown_to_have_happened_in_both_runs(self) -> None:
        self.assertIn("began no resampler epoch", self.text)
        self.assertIn("the switch never installed", self.text)


class LoopHistoryModel(Base):
    """The Rust test's numeric preconditions and its two laws, checked on a model of the chain (the Rust is not run)."""

    def setUp(self) -> None:
        super().setUp()
        self.k = model.rust_constants()

    def test_the_heater_builds_state_with_margin(self) -> None:
        woofer, tweeter = model.heated(self.k["warm"], self.k["amplitude"], self.k["heat"])
        self.assertGreater(woofer.level, 3 * 0.05, "the Rust test asserts a level above 0.05")
        self.assertGreater(1 - woofer.gain, 10 * 0.01, "the Rust test asserts a gain below 0.99")
        self.assertGreater(tweeter.level, 5 * self.k["thermal_floor"], "the quiet channel is also asked for history")
        for ch in (woofer, tweeter):
            self.assertIsNone(ch.hard_at, "the warming spec must never latch")
            self.assertLess(ch.level, self.k["warm"][1], "and must never thermally scale")

    def test_the_latching_spec_latches_and_cools_inside_the_rust_bounds(self) -> None:
        tau, soft, hard = self.k["latching"]
        frames = model.frames_to_latch(self.k["latching"], self.k["amplitude"], 40000)
        self.assertIsNotNone(frames, "overdrive must reach the hard limit")
        blocks = frames / 64.0
        self.assertLess(blocks, 150 / 3.0, "the loop is ticked 150 * 4 times; a block takes 4 ticks: 3x headroom")
        self.assertLess(model.cooling_blocks(hard, soft, tau), 200 / 10.0, "the cooling loop allows 200 blocks: 10x headroom")
        self.assertGreater(hard, 0.15, "the Rust test asserts a level above 0.15 at the latch")

    def test_the_laws_hold_for_every_event_and_a_rebuilt_board_breaks_them(self) -> None:
        kw = dict(slack=self.k["slack"], thermal_floor=self.k["thermal_floor"], limiter_floor=self.k["limiter_floor"])
        for event in model.EVENTS:
            with self.subTest(event=event):
                before, after, frames, tau = model.run_event(event, self.k["warm"], self.k["amplitude"], self.k["heat"])
                self.assertEqual(model.law_violations(before, after, frames, tau, **kw), [], "the control passes")
                rebuilt = [{"level": 0.0, "gain": 1.0} for _ in before]
                planted = model.law_violations(before, rebuilt, frames, tau, **kw)
                kinds = {("thermal" if "thermal" in p else "limiter") for p in planted}
                self.assertEqual(kinds, {"thermal", "limiter"}, "a rebuilt board breaks both laws")

    def test_a_partial_loss_is_caught_by_the_law_it_breaks(self) -> None:
        before, after, frames, tau = model.run_event("reconnect", self.k["warm"], self.k["amplitude"], self.k["heat"])
        half_thermal = [{"level": a["level"] * 0.5, "gain": a["gain"]} for a in after]
        found = model.law_violations(before, half_thermal, frames, tau, slack=self.k["slack"])
        self.assertTrue(found and all("thermal" in p for p in found), found)
        limiter_only = [{"level": a["level"], "gain": 1.0} for a in after]
        found = model.law_violations(before, limiter_only, frames, tau, slack=self.k["slack"])
        self.assertTrue(found and all("limiter" in p for p in found), found)

    def test_the_thermal_law_is_tight_to_the_time_constant(self) -> None:
        # A law built on a time constant ten times too long would call the control a loss: the law is not so loose
        # that any constant passes.
        before, after, frames, tau = model.run_event("reconnect", self.k["warm"], self.k["amplitude"], self.k["heat"])
        self.assertTrue(model.law_violations(before, after, frames, tau * 10.0, slack=self.k["slack"]))
        self.assertEqual(model.law_violations(before, after, frames, tau, slack=self.k["slack"]), [])


class AcceptanceMap(unittest.TestCase):
    """The acceptance map in docs/contracts/d02.md cites only tests, identifiers and case ids that exist in the tree."""

    DOC = "docs/contracts/d02.md"
    VECTORS = ("tests/d02/vectors.json",)
    PREFIXES = ("D02",)

    def setUp(self) -> None:
        import pathlib

        self.repo = pathlib.Path(__file__).resolve().parents[2]
        text = (self.repo / self.DOC).read_text(encoding="utf-8")
        self.assertIn("## Acceptance map", text)
        self.section = text.split("## Acceptance map", 1)[1]

    def corpus(self) -> str:
        import os
        import pathlib

        parts = []
        for top in ("crates", "tests", "scripts"):
            for root, dirs, files in os.walk(self.repo / top):
                dirs[:] = [d for d in dirs if d not in ("target", "__pycache__", ".git", "build")]
                for name in files:
                    if name.endswith((".rs", ".py")) or "." not in name:
                        parts.append((pathlib.Path(root) / name).read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)

    def test_every_cited_identifier_exists_in_the_tree(self) -> None:
        tokens = set(re.findall(r"`([A-Za-z0-9_:]+)`", self.section))
        corpus = self.corpus()
        missing = []
        for token in sorted(tokens):
            name = token.split("::")[-1]
            if name.count("_") >= 2 and name.islower() and name not in corpus:
                missing.append(token)
        self.assertEqual(missing, [], "the map cites identifiers that are not in the tree")

    def expand(self, prefix: str, family: str, numbers: str) -> List[str]:
        ids = []
        width = len(re.match(r"\d+", numbers).group(0))
        for piece in numbers.split("/"):
            if ".." in piece:
                low, high = (int(p) for p in piece.split(".."))
                ids += [f"{prefix}{family}-{n:0{width}d}" for n in range(low, high + 1)]
            else:
                ids.append(f"{prefix}{family}-{int(piece):0{width}d}")
        return ids

    def test_every_cited_case_and_invariant_exists(self) -> None:
        ids, invariants = set(), set()
        for path in self.VECTORS:
            doc = json.loads((self.repo / path).read_text(encoding="utf-8"))
            ids |= {case["id"] for case in doc["cases"]}
            invariants |= set(doc["invariants"])
        problems = []
        for prefix in self.PREFIXES:
            for family, numbers in re.findall(prefix + r"-([A-Z]+)-(\*|\d+(?:(?:\.\.|/)\d+)*)", self.section):
                if numbers == "*":
                    if not any(i.startswith(f"{prefix}-{family}-") for i in ids):
                        problems.append(f"{prefix}-{family}-*")
                else:
                    problems += [i for i in self.expand(prefix + "-", family, numbers) if i not in ids]
            for name in re.findall(prefix + r"-INV-[A-Z-]*[A-Z]", self.section):
                if name not in invariants:
                    problems.append(name)
        self.assertEqual(problems, [], "the map cites case ids or invariants that do not exist")

    def test_every_row_has_a_status_and_the_open_rows_say_what_they_need(self) -> None:
        rows = [l for l in self.section.splitlines() if l.startswith("| ") and not l.startswith("| Clause") and not l.startswith("|---")]
        self.assertGreater(len(rows), 10)
        for row in rows:
            cells = [c.strip() for c in row.strip("|").split("|")]
            self.assertEqual(len(cells), 3, row)
            status = cells[1].lower()
            self.assertTrue(any(w in status for w in ("covered", "partly", "open", "not ")), row)
            if "open" in status or "partly" in status:
                self.assertTrue("code" in row.lower() or "waits" in row.lower() or "not a code" in row.lower(), "an open or partial row must say code or waits: " + row)


if __name__ == "__main__":
    unittest.main(verbosity=1)
