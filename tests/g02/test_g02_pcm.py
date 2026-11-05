"""Tests for the G02 slice 2 reference, vectors and judge (ffw-ld0). Host-only, standard library only.

    python3 -B -I tests/g02/test_g02_pcm.py

SCOPE. The observations built here come from a TOY BOARD defined in this file, not from D02: a
per-channel filter that does not depend on the gain, followed by the applied gain, with simple
one-pole filters of its own. It has the one structural property the slice 2 oracle relies on (the
filtered signal is independent of the controls), so it can stand in for D02 to exercise the JUDGE:
accept a consistent log, reject a perturbed one, catch every planted defect, refuse to pass what was
not observed. These tests say nothing about the Rust code; that evidence is the centrally run cargo
log fed to ``pcm_run.py --judge``.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import tempfile
import unittest
from typing import Any, Dict, FrozenSet, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("g02pcm_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pr = _load("pcm_reference")
gen = _load("pcm_generate")
runner = _load("pcm_run")
ref = pr.ref


# ---- a toy board: gain-independent filters, then the gain -------------------------------------------------


def _channel_filter(kind: str, samples: List[float]) -> List[float]:
    """One-pole filters of the toy's own (NOT D02's): enough to make every channel's signal different."""
    out, state = [], 0.0
    for x in samples:
        if kind == "low":
            state += 0.05 * (x - state)
            out.append(state)
        elif kind == "high":
            state += 0.5 * (x - state)
            out.append(x - state)
        else:
            out.append(x)
    return out


TOY_FILTERS = {"S5": ["high", "high", "none", "none", "low"], "Sub": ["low"]}


def _quantize(value: float) -> int:
    return max(-32768, min(32767, round(value * 32768.0)))  # Python's round is ties-to-even


def toy_observation(case: dict, bugs: FrozenSet[str] = frozenset(), pcm: FrozenSet[str] = frozenset()) -> dict:
    """What a board with the slice 2 structure reports for ``case``, optionally with planted defects."""
    board, frames = pr.BOARDS[case["board"]], case["frames"]
    sim = pr.simulate(case, bugs)
    seed_left = case["seed_left"] + (1 if "pcm_wrong_seed" in pcm else 0)
    left = pr.lcg_stream(seed_left, frames)
    right = pr.lcg_stream(case["seed_right"], frames)
    role = "right" if ("pcm_role_swap" in pcm and case["role"] == "left") else case["role"]
    fed = [ref.role_map(role, l, r) for l, r in zip(left, right)]
    fnv = pr.FNV_OFFSET
    for l, r in fed:
        fnv = pr.fnv1a64(struct.pack("<ff", l, r), fnv)
    routes = {"left": [f[0] for f in fed], "right": [f[1] for f in fed],
              "mid": [ref.q32(0.5 * (f[0] + f[1])) for f in fed]}
    base = [_channel_filter(kind, routes[source]) for kind, source in zip(TOY_FILTERS[case["board"]], board["sources"])]
    if "pcm_pair_broken" in pcm and case["board"] == "S5":
        base[1] = [x + 0.001 for x in base[1]]
    if "pcm_dead_channel" in pcm and case["board"] == "S5":
        base[2] = [0.0] * frames
    gain_b = sim["gain_b"]
    gain_out = list(gain_b)
    if "pcm_output_ignores_ramp" in pcm:  # the output jumps ahead of the reported ramp
        gain_out = [gain_b[min(n + 240, frames - 1)] for n in range(frames)]
    if "pcm_late_gain" in pcm:  # the output uses the previous frame's gain
        gain_out = [0.0] + gain_b[:-1]
    out_a, out_b = [], []
    for n in range(frames):
        for c, channel in enumerate(base):
            out_a.append(_quantize(channel[n] * sim["gain_a"][n]))
            value = channel[n] * gain_out[n] * (0.97 if ("pcm_channel_gain_error" in pcm and c == 3) else 1.0)
            quantized = _quantize(value)
            if "pcm_mute_leak" in pcm and gain_b[n] == 0.0:
                quantized = 1
            out_b.append(quantized)
    regime = {"limiter_min": 0.9 if "pcm_limiter_engaged" in pcm else 1.0, "thermal_scaled": 0, "clipped": 0}
    return {"id": case["id"], "kind": "pcm_script", "frames": frames, "channels": board["channels"],
            "input_fnv": f"{fnv:016x}", "gain_a": sim["gain_a"], "gain_b": gain_b, "out_a": out_a, "out_b": out_b,
            "results": sim["results"], "role_mismatches": 0, "regime": regime}


def cargo_log(doc: dict, drop_tests: tuple = (), drop_cases: tuple = (), perturb: Optional[dict] = None) -> str:
    """An RCH-shaped cargo log: the `Running` headers first (stderr), then the sections (stdout)."""
    required = runner.derive_rust_tests()
    names = [n for stem, n in required if stem == "g02_pcm" and n not in drop_tests]
    observed = []
    for case in doc["cases"]:
        if case["id"] in drop_cases:
            continue
        obs = toy_observation(case)
        if perturb and case["id"] in perturb:
            obs = perturb[case["id"]](copy.deepcopy(obs))
        observed.append("G02PCM-OBSERVED " + json.dumps(obs))
    h = hashlib.sha256(b"g02_pcm").hexdigest()[:16]
    header = f"     Running tests (.rch-target-vmi0000000-pool-{'0' * 32}/debug/build/x/{h}/out/g02_pcm-{h})"
    body = [f"test {n} ... ok" for n in names]
    lines = [header, f"running {len(names)} tests"] + body[:1] + observed + body[1:]
    lines += ["", f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s", ""]
    return "\n".join(lines) + "\n"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.doc = json.load(handle)
        self.cases = {c["id"]: c for c in self.doc["cases"]}

    def judge(self, text: str) -> List[Any]:
        path = os.path.join(self.tmp.name, "cargo.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        logs = runner.Logs()
        logs.add(path)
        return runner.run(logs)[0]

    def by(self, results: List[Any], status: str) -> List[str]:
        return [r.case_id for r in results if r.status == status]


class ReferenceAndVectors(Base):
    def test_reference_self_checks_hold(self) -> None:
        self.assertEqual(runner.reference_problems(), [])

    def test_committed_vectors_equal_a_fresh_generation(self) -> None:
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), gen.dumps(gen.build()))

    def test_ids_are_unique_every_invariant_is_cited_and_the_plan_is_fixed(self) -> None:
        ids = [c["id"] for c in self.doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(self.doc["invariants"]) - {i for c in self.doc["cases"] for i in c["invariants"]}, set())
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(runner.run(None)[0]), 3 + 8 + 3)  # 3 meta + 8 cases + 3 Rust tests

    def test_every_operation_is_inside_its_stream_and_the_streams_are_long_enough_to_ramp(self) -> None:
        for case in self.doc["cases"]:
            self.assertTrue(all(0 <= op[0] < case["frames"] for op in case["schedule"]), case["id"])
            self.assertGreaterEqual(case["frames"], 2400, case["id"])  # a full-scale ramp is 480 frames

    def test_the_documented_input_is_the_hand_derived_stream(self) -> None:
        # 1 * 1664525 + 1013904223 = 1015568748 and 1015568748 >> 16 = 15496; the next raw values are 24200 and -32490.
        self.assertEqual(pr.lcg_stream(1, 3), [15496 / 131072.0, 24200 / 131072.0, -32490 / 131072.0])
        self.assertEqual(pr.fnv1a64(b""), 0xCBF29CE484222325)
        self.assertEqual(pr.fnv1a64(b"a"), 0xAF63DC4C8601EC8C)
        a, b = pr.lcg_stream(9, 50), pr.lcg_stream(10, 50)
        self.assertNotEqual(a, b)
        self.assertTrue(all(abs(x) <= 0.25 for x in a + b))
        self.assertEqual(len({case["seed_left"] for case in self.doc["cases"]} | {case["seed_right"] for case in self.doc["cases"]}),
                         16)  # every stream is distinct


class ContractMatchesVectors(Base):
    """docs/contracts/g02-pcm.md must cite the evidence the vectors provide, and each citation must be earned."""

    def setUp(self) -> None:
        super().setUp()
        with open(os.path.join(REPO, "docs", "contracts", "g02-pcm.md"), encoding="utf-8") as handle:
            self.text = handle.read()

    def test_the_invariant_map_equals_what_the_vectors_cite(self) -> None:
        cited: Dict[str, set] = {}
        for case in self.doc["cases"]:
            for invariant in case["invariants"]:
                cited.setdefault(invariant, set()).add(case["id"])
        table = self.text.split("| Invariant | Evidence |", 1)[1].split("\n## ", 1)[0]
        documented: Dict[str, set] = {}
        for row in table.splitlines():
            m = re.match(r"\| `(G02PCM-INV-[A-Z-]+)` \| `G02PCM-([0-9/]+)` \|$", row)
            if m:
                documented[m.group(1)] = {f"G02PCM-{n}" for n in m.group(2).split("/")}
        self.assertEqual(set(documented), set(self.doc["invariants"]))
        for invariant, ids in documented.items():
            self.assertEqual(ids, cited[invariant], f"{invariant}: contract and vectors disagree")

    def test_every_citation_is_earned_by_what_the_case_actually_does(self) -> None:
        def ops(case: dict) -> set:
            return {entry[1] for entry in case["schedule"]}

        def commands(case: dict) -> set:
            return {entry[4][0] for entry in case["schedule"] if entry[1] == "cmd"}

        def has_mute(case: dict) -> bool:
            mutes = case["expect"]["results"]
            return any(row[3] is not None for row in mutes)

        earned = {
            "G02PCM-INV-CEILING": lambda c: bool({"ceiling", "fault_ceiling"} & ops(c)) or c["ceiling"] < 1.0,
            "G02PCM-INV-EXACT-SILENCE": lambda c: c["expect"]["silent_frames"] > 0,
            "G02PCM-INV-MUTE-IN-FLIGHT": lambda c: has_mute(c) and "set_volume" in commands(c),
            "G02PCM-INV-RECONNECT-NO-SPIKE": lambda c: "reconnect" in ops(c) and "join" in ops(c),
            "G02PCM-INV-ROLE-ROUTING": lambda c: c["role"] != "stereo" or c["pair_expect"] == "differ",
            "G02PCM-INV-FRAME-EXACT-GAIN": lambda c: len(c["schedule"]) > 3,
        }
        for case in self.doc["cases"]:
            for invariant, test in earned.items():
                if invariant in case["invariants"]:
                    self.assertTrue(test(case), f"{case['id']} cites {invariant} but does not exercise it")

    def test_local_buttons_are_exercised_including_while_locally_muted(self) -> None:
        # The reported mute is the state AFTER the operation: a local button that leaves the room muted
        # for the local reason was pressed while it was locally muted, and must not have unmuted it.
        case = self.cases["G02PCM-008"]
        pressed_while_muted = [row for row in case["expect"]["results"] if row[1] == "local_trim" and row[3] == "local"]
        self.assertTrue(pressed_while_muted, "no local button press lands while the room is locally muted")

    def test_the_contract_states_the_plan_and_the_limits(self) -> None:
        self.assertIn("plans 14 cases: 3 meta, 8 vectors and 3 Rust tests", self.text)
        self.assertIn("Numerical tests do not prove physical behavior", self.text)
        self.assertIn("This does not test D02's filters", self.text)
        self.assertIn("One frame per `render_into` call", self.text)
        self.assertIn("1.01 LSB", self.text)
        self.assertIn("scripts/e2e/g02-pcm --judge", self.text)


class HandDerivedPins(Base):
    """Numbers worked out on paper from the ramp rate (1/480 per frame) and the schedule."""

    def gain(self, case_id: str) -> List[float]:
        return pr.simulate(self.cases[case_id])["gain_b"]

    def test_a_retarget_continues_from_where_the_gain_is(self) -> None:
        g = self.gain("G02PCM-001")
        step = 1 / 480.0
        self.assertEqual(g[699], 1.0)
        self.assertAlmostEqual(g[700], 1.0 - step, places=6)         # the first frame of the fall to 0.4
        self.assertAlmostEqual(g[899], 1.0 - 200 * step, delta=200 * 2 ** -24)  # 200 f32 steps, each rounded to <= 2**-24
        # at 900 the target jumps to 0.9: the gain turns around from 0.5833, it does not restart
        self.assertGreater(g[901], g[899] - 1e-9)
        self.assertTrue(all(abs(g[i] - g[i - 1]) <= step + 2 ** -24 for i in range(1, len(g))))
        q = ref.q32  # the applied gain is an f32
        self.assertEqual(g[1400], q(0.9))
        self.assertEqual(g[2200], q(0.7))
        # trim 500 at 2300 halves 0.7 over 168 frames: frame 2400 is its 101st step, and it is done by 2470
        self.assertAlmostEqual(g[2400], 0.7 - 101 * step, delta=101 * 2 ** -24 + 1e-7)
        self.assertEqual(g[2480], q(0.7) * 0.5)
        self.assertEqual(g[2999], q(0.7))                             # local trim +500 restores unity trim

    def test_mute_in_flight_only_falls_and_reaches_exact_silence(self) -> None:
        case = self.cases["G02PCM-002"]
        g = self.gain("G02PCM-002")
        self.assertTrue(all(g[i] <= g[i - 1] + 1e-9 for i in range(701, 1100)))     # the volume commands at 760 and 900 do not lift it
        self.assertEqual(g[1100], 0.0)
        self.assertEqual(g[1599], 0.0)
        self.assertAlmostEqual(g[1600], 1 / 480.0, places=6)                          # the unmute lands before frame 1600: its first step
        self.assertEqual(g[2000], ref.q32(0.8))                                       # volume 60 -> 100 -> 80
        self.assertEqual(g[2700], 0.0)                                                # group mute, silent until 2800
        self.assertEqual(g[3000], ref.q32(0.3))                                       # volume 30 stored under the mute
        self.assertTrue(case["expect"]["silent_frames"] > 800)

    def test_reconnect_silences_and_the_rejoin_only_reaches_the_groups_level(self) -> None:
        g = self.gain("G02PCM-003")
        self.assertEqual(g[1500], 0.0)
        self.assertTrue(all(x <= 0.2 + 1e-7 for x in g[1800:2200]))                    # the group is at 20 %
        self.assertEqual(g[2150], ref.q32(0.2))
        self.assertEqual(g[2500], 0.0)                                                 # a group-mute snapshot holds it silent after the join
        self.assertEqual(g[2999], 0.0)
        self.assertEqual(g[3290], ref.q32(0.5))                                        # group unmute at 3000: the snapshot's volume 50, reached by 3240
        # frames 3300..3309 fall (10 steps: the reconnect), 3310..3400 rise (91 steps: the join), net +81
        self.assertAlmostEqual(g[3400], 0.5 + 81 / 480.0, delta=101 * 2 ** -24 + 1e-7)
        self.assertEqual(g[3599], ref.q32(0.8))                                        # the last rejoin: volume 80

    def test_silent_frame_counts_follow_from_the_ramp_arithmetic(self) -> None:
        # Left room: volume 50 at 700 (done by 940), local mute at 1200 fades 0.5 -> 0 in 240 frames (silent from
        # about 1440), unmute at 1500: 60 silent frames. The sub: mute at 1000 from 0.3 -> 0 in 144 frames, unmute at 1400: 256.
        self.assertIn(self.cases["G02PCM-004"]["expect"]["silent_frames"], (59, 60, 61))
        self.assertIn(self.cases["G02PCM-006"]["expect"]["silent_frames"], (255, 256, 257))
        # Ceilings: the NaN ceiling at 2400 fades 0.5 -> 0 in 240 frames, silent until 3000.
        self.assertIn(self.cases["G02PCM-007"]["expect"]["silent_frames"], (359, 360, 361))

    def test_ceilings_bound_the_trajectory(self) -> None:
        g = self.gain("G02PCM-007")
        self.assertEqual(g[1000], 0.5)           # volume 100 x trim 2.0 = 2.0, bounded at the 0.5 ceiling
        self.assertEqual(g[1700], 0.25)          # a fault ceiling lowers it
        self.assertEqual(g[2300], 0.5)           # removing it restores the protection ceiling
        self.assertEqual(g[2900], 0.0)           # a NaN ceiling fails closed
        self.assertEqual(g[3599], 1.0)           # ceiling 1.0 again: 2.0 bounded at unity

    def test_the_reference_board_is_a_plain_unity_ramp(self) -> None:
        a = pr.simulate(self.cases["G02PCM-001"])["gain_a"]
        self.assertAlmostEqual(a[0], 1 / 480.0, places=6)
        self.assertEqual(a[600], 1.0)
        self.assertEqual(set(a[480:]), {1.0})


class ToyBaseline(Base):
    def test_the_toy_board_is_judged_clean_on_every_case(self) -> None:
        for case in self.doc["cases"]:
            self.assertIsNone(runner.judge_case(case, toy_observation(case)), case["id"])

    def test_the_toy_actually_has_the_structure_the_oracle_relies_on(self) -> None:
        case = self.cases["G02PCM-001"]
        obs = toy_observation(case)
        self.assertTrue(any(abs(a) > 1000 for a in obs["out_a"]))
        # Every channel really carries signal, and the pairs differ for a stereo room.
        lanes = [obs["out_a"][i:i + 5] for i in range(0, len(obs["out_a"]), 5)]
        self.assertTrue(all(max(abs(l[c]) for l in lanes) >= runner.MIN_REFERENCE_PEAK_LSB for c in range(5)))
        self.assertGreater(sum(1 for l in lanes if l[0] != l[1]), case["frames"] // 4)


class PlantedDefects(Base):
    """Each planted defect must fail at least one case; the unmutated control must stay green."""

    PCM_BUGS = ("pcm_output_ignores_ramp", "pcm_late_gain", "pcm_mute_leak", "pcm_channel_gain_error", "pcm_role_swap",
                "pcm_wrong_seed", "pcm_pair_broken", "pcm_limiter_engaged", "pcm_dead_channel")
    CONTROL_BUGS = ("mute_unmutes_on_volume", "group_unmute_clears_local", "no_clamp_before_ramp", "reconnect_keeps_stored",
                    "reconnect_no_join_mute", "trim_reset_on_volume", "ramp_restarts", "local_trim_unmutes")

    def failing(self, bugs: FrozenSet[str] = frozenset(), pcm: FrozenSet[str] = frozenset()) -> Dict[str, str]:
        out = {}
        for case in self.doc["cases"]:
            problem = runner.judge_case(case, toy_observation(case, bugs, pcm))
            if problem:
                out[case["id"]] = problem
        return out

    def test_the_baseline_is_green_before_any_defect_is_credited(self) -> None:
        self.assertEqual(self.failing(), {})

    def test_every_pcm_path_defect_is_caught_and_removing_it_restores_green(self) -> None:
        for bug in self.PCM_BUGS:
            with self.subTest(bug=bug):
                self.assertTrue(self.failing(pcm=frozenset({bug})), f"{bug} was not caught")
                self.assertEqual(self.failing(), {}, f"{bug}: the control is not green")

    def test_every_control_defect_is_caught_at_the_pcm_level(self) -> None:
        for bug in self.CONTROL_BUGS:
            with self.subTest(bug=bug):
                self.assertTrue(self.failing(bugs=frozenset({bug})), f"{bug} was not caught")
                self.assertEqual(self.failing(), {}, f"{bug}: the control is not green")

    def test_pcm_defects_are_caught_by_the_named_property_not_by_the_reference_comparison(self) -> None:
        # These defects leave the reported gains and results untouched, so only a property of the raw PCM can see them.
        expected = {"pcm_output_ignores_ramp": "linearity", "pcm_late_gain": "linearity", "pcm_mute_leak": "silence",
                    "pcm_channel_gain_error": "linearity", "pcm_pair_broken": "roles", "pcm_limiter_engaged": "regime",
                    "pcm_dead_channel": "coverage"}
        for bug, prop in expected.items():
            with self.subTest(bug=bug):
                problems = self.failing(pcm=frozenset({bug}))
                self.assertTrue(problems)
                self.assertTrue(all(f"property ({prop})" in p for p in problems.values()), problems)

    def test_input_defects_are_caught_by_the_fingerprint(self) -> None:
        for bug in ("pcm_wrong_seed", "pcm_role_swap"):
            with self.subTest(bug=bug):
                problems = self.failing(pcm=frozenset({bug}))
                self.assertTrue(problems)
                self.assertTrue(all("fingerprint" in p for p in problems.values()), problems)

    def test_ramp_restarts_is_caught_by_the_gain_trajectory(self) -> None:
        problems = self.failing(bugs=frozenset({"ramp_restarts"}))
        self.assertTrue(problems)
        self.assertTrue(all("against the reference" in p or "stepped" in p for p in problems.values()), problems)

    def test_the_stereo_control_is_not_vacuous(self) -> None:
        # If a stereo room's pair were identical, the Left/Right equality property would prove nothing.
        case = copy.deepcopy(self.cases["G02PCM-001"])
        case["seed_right"] = case["seed_left"]            # L == R, so every pair of channels matches
        self.assertIn("vacuous", runner.judge_case(case, toy_observation(case)))


class JudgeBehavior(Base):
    def test_a_consistent_log_is_qualified(self) -> None:
        results = self.judge(cargo_log(self.doc))
        self.assertEqual(self.by(results, "failed"), [])
        self.assertEqual(self.by(results, "blocked"), [])
        self.assertEqual(runner.exit_code(results), 0)
        self.assertEqual(len(results), 14)

    def test_no_log_blocks_everything_rust_backed(self) -> None:
        results, _ = runner.run(None)
        self.assertEqual(runner.exit_code(results), 3)
        self.assertTrue(all(r.case_id.startswith("G02PCM-META-") for r in results if r.status == "passed"))

    def test_a_missing_case_and_a_missing_rust_test_stay_blocked(self) -> None:
        name = "a_planted_defect_in_the_pcm_path_is_detected"
        results = self.judge(cargo_log(self.doc, drop_cases=("G02PCM-006",), drop_tests=(name,)))
        self.assertEqual(sorted(self.by(results, "blocked")), sorted(["G02PCM-006", f"RUST:g02_pcm::{name}"]))
        self.assertEqual(self.by(results, "failed"), [])

    def test_a_divergence_names_the_frame_and_channel(self) -> None:
        def bend(obs: dict) -> dict:
            obs["out_b"][1000 * 5 + 3] += 4
            return obs

        results = self.judge(cargo_log(self.doc, perturb={"G02PCM-001": bend}))
        self.assertEqual(self.by(results, "failed"), ["G02PCM-001"])
        detail = next(r.detail for r in results if r.case_id == "G02PCM-001")
        self.assertIn("frame 1000 channel 3", detail)

    def test_a_reported_gain_that_leaves_the_reference_is_named_by_frame(self) -> None:
        def bend(obs: dict) -> dict:
            obs["gain_b"][1500] += 0.01
            return obs

        results = self.judge(cargo_log(self.doc, perturb={"G02PCM-002": bend}))
        detail = next(r.detail for r in results if r.case_id == "G02PCM-002")
        self.assertIn("frame 1500: board B applied gain", detail)

    def test_a_truncated_observation_is_a_structure_failure_not_a_pass(self) -> None:
        def cut(obs: dict) -> dict:
            obs["out_b"] = obs["out_b"][:-5]
            return obs

        results = self.judge(cargo_log(self.doc, perturb={"G02PCM-004": cut}))
        self.assertEqual(self.by(results, "failed"), ["G02PCM-004"])

    def test_the_tolerances_are_not_widened(self) -> None:
        self.assertEqual(runner.LINEAR_TOLERANCE_LSB, 1.01)   # 0.5 + 0.5 + 0.01, derived in the contract
        self.assertLessEqual(runner.GAIN_TOLERANCE, 1e-7)

    def test_d01_log_parser_reuse_leaves_d01_untouched(self) -> None:
        spec = importlib.util.spec_from_file_location("g02pcm_t_pristine_d01", os.path.join(REPO, "tests", "d01", "run_cases.py"))
        pristine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = pristine
        spec.loader.exec_module(pristine)
        self.assertEqual(pristine.OBSERVED.pattern, r"D01-OBSERVED (\{.*\})\s*$")
        self.assertEqual(runner.d01.OBSERVED.pattern, r"G02PCM-OBSERVED (\{.*\})\s*$")
        self.assertIsNot(pristine, runner.d01)


class HarnessAgreement(Base):
    """The Rust harness must implement what the vectors use, with the same constants as the judge."""

    def setUp(self) -> None:
        super().setUp()
        with open(os.path.join(REPO, "crates", "franken-dsp", "tests", "g02_pcm.rs"), encoding="utf-8") as handle:
            self.rust = handle.read()

    def number(self, name: str) -> float:
        match = re.search(rf"const {name}: [a-z0-9]+ = ([0-9_.e-]+);", self.rust)
        self.assertIsNotNone(match, name)
        return float(match.group(1).replace("_", ""))

    def test_the_harness_and_the_judge_share_their_constants(self) -> None:
        self.assertEqual(self.number("LINEAR_TOLERANCE_LSB"), runner.LINEAR_TOLERANCE_LSB)
        self.assertEqual(self.number("GAIN_TOLERANCE"), runner.GAIN_TOLERANCE)
        self.assertEqual(self.number("MIN_REFERENCE_PEAK_LSB"), runner.MIN_REFERENCE_PEAK_LSB)
        self.assertEqual(self.number("MAX_OUTPUT_LSB"), runner.MAX_OUTPUT_LSB)
        self.assertEqual(self.number("AMPLITUDE"), pr.AMPLITUDE)
        self.assertIn("wrapping_mul(1_664_525).wrapping_add(1_013_904_223)", self.rust)
        self.assertEqual((pr.LCG_MUL, pr.LCG_ADD), (1664525, 1013904223))
        self.assertIn("0xcbf2_9ce4_8422_2325", self.rust)
        self.assertIn("0x0100_0000_01b3", self.rust)
        self.assertEqual((pr.FNV_OFFSET, pr.FNV_PRIME), (0xCBF29CE484222325, 0x100000001B3))

    def test_every_operation_command_board_and_role_in_the_vectors_exists_in_the_harness(self) -> None:
        ops, commands, boards, roles = set(), set(), set(), set()
        for case in self.doc["cases"]:
            boards.add(case["board"])
            roles.add(case["role"])
            for entry in case["schedule"]:
                ops.add(entry[1])
                commands |= {a[0] for a in entry[2:] if isinstance(a, list) and a and isinstance(a[0], str)}
        have = set(re.findall(r'"([a-z_0-9]+)"', self.rust))
        for label, needed in (("operations", ops), ("commands", commands), ("roles", roles)):
            self.assertEqual(sorted(needed - have), [], f"vector {label} the Rust harness does not implement")
        self.assertEqual(boards, {"S5", "Sub"})

    def test_the_harness_emits_every_key_the_judge_reads(self) -> None:
        for key in ("frames", "channels", "input_fnv", "gain_a", "gain_b", "out_a", "out_b", "results", "role_mismatches",
                    "regime", "limiter_min", "thermal_scaled", "clipped"):
            self.assertIn(f'"{key}"', self.rust, f"observation key {key!r} is never emitted by the harness")

    def test_the_synthetic_calibration_assumption_is_asserted_by_the_harness(self) -> None:
        self.assertIn("channel.trim == 1.0 && channel.max_gain == 1.0", self.rust)

    def test_the_slice_1_files_are_only_read_not_written(self) -> None:
        # Slice 2 loads slice 1's reference through a loader; no code here opens a slice 1 file for writing.
        for name in ("pcm_reference.py", "pcm_generate.py", "pcm_run.py"):
            with open(os.path.join(HERE, name), encoding="utf-8") as handle:
                text = handle.read()
            self.assertNotRegex(text, r"open\([^)]*(reference|generate|run_cases|vectors)\.[a-z]+[^)]*,\s*\"w\"", name)
        self.assertEqual(runner.VECTORS, os.path.join(HERE, "pcm_vectors.json"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
