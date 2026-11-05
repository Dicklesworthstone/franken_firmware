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
    stems = ["franken_dsp", "d02_vectors", "protection_no_alloc"]

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
        want = {"intermediate range only": ("intermediate_range_exceeded", 2),
                "100 Hz high-pass trips the intermediate bound": ("intermediate_range_exceeded", 2),
                "high-Q resonator": ("gain_bound_exceeded", 0), "woofer with a high-pass": ("band_policy_violated", 4),
                "order: lower channel first": ("unstable", 0)}
        seen = {c["title"]: c["expect"] for c in self.doc["cases"] if c["kind"] == "validation"}
        for title, (code, channel) in want.items():
            self.assertEqual((seen[title]["error"], seen[title]["channel"]), (code, channel), title)
        self.assertEqual(seen["positive S5"]["status"], "active")

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
