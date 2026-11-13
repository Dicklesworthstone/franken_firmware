"""Tests for the G02 reference, vectors and judge (ffw-ld0). Host-only, standard library only.

    python3 -B -I tests/g02/test_g02.py

SCOPE. The observations built here come from the reference model itself (correct or deliberately
wrong). They exercise the JUDGE: accept a consistent log, reject a perturbed one, refuse to pass what
was not observed, and catch every planted defect. They say nothing about the Rust code; that evidence
is the centrally run cargo log fed to ``run_cases.py --judge``.

The model is a second implementation of the contract by the same author, so the HAND-DERIVED PINS
below are the check on the model: each number is worked out on paper from docs/contracts/g02.md.
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
from typing import Any, Dict, List, Optional
from unittest.mock import patch

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("g02_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
gen = _load("generate")
runner = _load("run_cases")


def observed_for(case: dict, bugs: frozenset = frozenset()) -> dict:
    return {"id": case["id"], "kind": case["kind"], **ref.observe(case, bugs)}


def cargo_log(doc: dict, drop_tests: tuple = (), drop_cases: tuple = (), perturb: Optional[dict] = None) -> str:
    """An RCH-shaped cargo log: all `Running` headers first (stderr), then the sections (stdout)."""
    required = runner.derive_rust_tests()
    by_stem: Dict[str, List[str]] = {}
    for stem, name in required:
        by_stem.setdefault(stem, []).append(name)
    observed: List[str] = []
    for case in doc["cases"]:
        if case["id"] in drop_cases:
            continue
        obs = observed_for(case)
        if perturb and case["id"] in perturb:
            obs = perturb[case["id"]](copy.deepcopy(obs))
        observed.append("G02-OBSERVED " + json.dumps(obs))
    stems = ["franken_dsp", "g02_vectors", "franken_speaker"]

    def header(stem: str) -> str:
        h = hashlib.sha256(stem.encode()).hexdigest()[:16]
        return f"     Running tests (.rch-target-vmi0000000-pool-{'0' * 32}/debug/build/x/{h}/out/{stem}-{h})"

    lines = [header(s) for s in stems]
    for stem in stems:
        names = [n for n in by_stem.get(stem, []) if n not in drop_tests]
        body = [f"test {n} ... ok" for n in names]
        extra = observed if stem == "g02_vectors" else []
        lines += [f"running {len(names)} test{'' if len(names) == 1 else 's'}"] + body[:1] + extra + body[1:]
        lines += ["", f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s", ""]
    return "\n".join(lines) + "\n"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.doc = json.load(handle)
        self.cases = {c["id"]: c for c in self.doc["cases"]}

    def judge(self, text: str, tier: str = "full") -> List[Any]:
        path = os.path.join(self.tmp.name, "cargo.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        logs = runner.Logs()
        logs.add(path)
        return runner.run(tier, logs)[0]

    def by(self, results: List[Any], status: str) -> List[str]:
        return [r.case_id for r in results if r.status == status]

    def trace(self, case_id: str) -> List[dict]:
        return self.cases[case_id]["expect"]["trace"]


class ReferenceAndVectors(Base):
    def test_reference_self_checks_hold(self) -> None:
        self.assertEqual(runner.reference_problems(), [])

    def test_committed_vectors_equal_a_fresh_generation(self) -> None:
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), gen.dumps(gen.build()))

    def test_every_invariant_is_covered_and_ids_are_unique(self) -> None:
        ids = [c["id"] for c in self.doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        covered = {i for c in self.doc["cases"] for i in c["invariants"]}
        external = {k for k, v in self.doc["external"].items() if v}
        self.assertEqual(set(self.doc["invariants"]) - covered - external, set())
        self.assertEqual(len(ids), 51)

    def test_the_tolerance_is_not_widened(self) -> None:
        # f32 is emulated operation by operation, so one ulp near 1.0 (1.2e-7) is the most that can differ.
        self.assertLessEqual(runner.TOLERANCE, 1.0e-7)
        with open(os.path.join(REPO, "crates", "franken-dsp", "tests", "g02_vectors.rs"), encoding="utf-8") as handle:
            rust = float(re.search(r"const TOLERANCE: f64 = ([0-9.e-]+);", handle.read()).group(1))
        self.assertEqual(rust, runner.TOLERANCE, "the Rust harness and the judge must use one tolerance")


class ContractMatchesVectors(Base):
    """docs/contracts/g02.md must cite the evidence the vectors actually provide."""

    def setUp(self) -> None:
        super().setUp()
        with open(os.path.join(REPO, "docs", "contracts", "g02.md"), encoding="utf-8") as handle:
            self.text = handle.read()

    def test_the_invariant_map_equals_what_the_vectors_cite(self) -> None:
        cited: Dict[str, set] = {}
        for case in self.doc["cases"]:
            for invariant in case["invariants"]:
                cited.setdefault(invariant, set()).add(case["id"])
        table = self.text.split("| Invariant | Evidence |", 1)[1].split("\n## ", 1)[0]
        documented: Dict[str, set] = {}
        for row in table.splitlines():
            m = re.match(r"\| `(G02-INV-[A-Z-]+)` \| (.+) \|$", row)
            if not m:
                continue
            ids = set()
            for family, numbers in re.findall(r"`(G02-[A-Z]+)-([0-9/]+)`", m.group(2)):
                ids |= {f"{family}-{n}" for n in numbers.split("/")}
            documented[m.group(1)] = ids
        for invariant in self.doc["invariants"]:
            self.assertIn(invariant, documented, f"{invariant} is missing from the contract's invariant map")
            if invariant in cited:
                self.assertEqual(documented[invariant], cited[invariant], f"{invariant}: contract and vectors disagree")
            else:  # an external Rust test: the doc names it, and it exists
                self.assertTrue(self.doc["external"][invariant])
                for name in self.doc["external"][invariant]:
                    self.assertIn(name.split("::", 1)[1], self.text)

    def test_the_contract_states_the_plan_and_the_limits(self) -> None:
        self.assertIn("152 cases: 4 meta, 51 vectors and 97 Rust tests", self.text)
        self.assertIn("Numerical tests do not prove physical behavior", self.text)
        self.assertIn("second implementation of this contract by the same author", self.text)
        self.assertIn("scripts/e2e/g02 --tier full --judge", self.text)
        planned = len(runner.run("full", None)[0])
        self.assertEqual(planned, 152)


class HandDerivedPins(Base):
    """Numbers worked out on paper from the contract, not read back from the model."""

    def gains(self, case_id: str) -> Dict[tuple, float]:
        case = self.cases[case_id]
        return {tuple(r): g for r, g in zip(case["rows"], case["expect"]["gains"])}

    def test_gain_composition_by_hand(self) -> None:
        unit = self.gains("G02-GAIN-001")
        self.assertAlmostEqual(unit[(75, 0)], 0.0, places=9)        # zero trim silences the room
        self.assertAlmostEqual(unit[(50, 1500)], 0.75, places=7)    # 0.50 * 1.5
        self.assertAlmostEqual(unit[(25, 500)], 0.125, places=7)    # 0.25 * 0.5
        self.assertAlmostEqual(unit[(100, 2000)], 1.0, places=9)    # 2.0 boost clamped to unity
        self.assertAlmostEqual(unit[(75, 2000)], 1.0, places=9)     # 1.5 clamped
        self.assertAlmostEqual(unit[(99, 1000)], 0.99, places=7)
        half = self.gains("G02-GAIN-002")
        self.assertAlmostEqual(half[(100, 1000)], 0.5, places=9)    # protection ceiling
        self.assertAlmostEqual(half[(25, 1000)], 0.25, places=7)    # below the ceiling: untouched
        self.assertAlmostEqual(half[(100, 2000)], 0.5, places=9)
        fault = self.gains("G02-GAIN-003")
        self.assertAlmostEqual(fault[(100, 1000)], 0.3, places=7)   # fault ceiling 0.3
        self.assertAlmostEqual(fault[(25, 1000)], 0.25, places=7)
        both = self.gains("G02-GAIN-004")
        self.assertAlmostEqual(both[(100, 1000)], 0.4, places=7)    # protection 0.4 beats fault 0.9
        for case_id in ("G02-GAIN-005", "G02-GAIN-006", "G02-GAIN-007"):
            self.assertEqual(set(self.gains(case_id).values()), {0.0}, case_id)  # non-finite fails closed

    def test_mute_priority_is_fault_local_join_group(self) -> None:
        self.assertEqual(list(ref.MUTE_ORDER), ["fault", "local", "join", "group"])
        t = self.trace("G02-MBR-004")
        # 0 declare, 1 join, 2 vol 60, 3 group mute, 4 vol 90, 5 local mute, 6 group unmute,
        # 7 local unmute, 8 group mute, 9 board fail_muted, 10 group unmute, 11 board active
        self.assertEqual(t[0]["mute"], "join")                         # a new member starts silent
        self.assertEqual(t[1]["mute"], None)
        self.assertEqual(t[3]["mute"], "group")                        # group mute applies
        self.assertEqual(t[4]["desired"], 90)                          # a volume command is stored, never unmutes
        self.assertEqual(t[4]["mute"], "group")
        self.assertEqual(t[5]["mute"], "local")                        # local outranks group
        self.assertEqual(t[6]["mute"], "local")                        # a group unmute cannot clear it
        self.assertEqual(t[7]["mute"], None)                           # only the local control does
        self.assertEqual((t[9]["mute"], t[10]["mute"]), ("fault", "fault"))  # fault outranks, and survives a group unmute
        self.assertEqual(t[11]["mute"], None)                          # back to Active clears it
        self.assertAlmostEqual(t[11]["gain"], 0.9, places=7)           # to the stored target, then D02 ramps

    def test_authority_by_hand(self) -> None:
        t = self.trace("G02-MBR-007")
        self.assertEqual([e["result"] for e in t],
                         ["ok", "ok", "ok", "ok", "stale_revision", "stale_revision", "stale_epoch", "undeclared_epoch",
                          "ok", "stale_epoch", "ok", "ok", "stale_epoch", "ok"])
        self.assertEqual([e["desired"] for e in t],
                         [0, 0, 50, 60, 60, 60, 60, 60, 70, 70, 70, 70, 70, 5])
        self.assertEqual([e["epoch"] for e in t][-3:], [8, 8, 8])      # only declare_epoch moves the epoch
        self.assertEqual(t[11]["revision"], 0)                         # a newer epoch starts its revisions again
        none = self.trace("G02-MBR-008")
        self.assertEqual([e["result"] for e in none], ["ok", "no_authority", "ok", "ok"])

    def test_retries_and_overflow_by_hand(self) -> None:
        t = self.trace("G02-MBR-009")
        self.assertEqual([e["desired"] for e in t], [0, 0, 50, 60, 60, 60, 60, 60, 70])  # +10 applied once
        self.assertEqual([e.get("duplicate") for e in t], [None, None, False, False, True, True, True, None, False])
        self.assertEqual(t[7]["result"], "revision_conflict")
        o = self.trace("G02-MBR-010")
        self.assertEqual([e["desired"] for e in o[2:9]], [95, 100, 5, 0, 100, 0, 40])
        self.assertEqual([e["result"] for e in o[9:17]],
                         ["step_out_of_range"] * 4 + ["volume_out_of_range"] * 2 + ["trim_out_of_range"] * 2)
        self.assertEqual((o[17]["result"], o[17]["desired"]), ("ok", 41))  # the refusals did not consume revision 8
        self.assertEqual({e["revision"] for e in o[10:18]} - {7, 8}, set())

    def test_roles_by_hand(self) -> None:
        want = {
            "G02-ROLE-001": ("ok", "ok", "ok", "no_subwoofer_path"),         # S5
            "G02-ROLE-005": ("subwoofer_only",) * 3 + ("ok",),              # the Sub
            "G02-ROLE-006": ("no_audio_output",) * 4,                         # the Bridge
            "G02-ROLE-007": ("invalid_layout",) * 4,                          # 3 channels, 2 routes
            "G02-ROLE-008": ("mixed_sub_layout",) * 4,                        # sub among mids
            "G02-ROLE-009": ("no_audio_output",) * 4,                         # 0 channels
            "G02-ROLE-010": ("no_audio_output",) * 4,                         # no routing
            "G02-ROLE-011": ("subwoofer_only",) * 3 + ("ok",),              # two subs are still sub-only
        }
        for case_id, results in want.items():
            got = self.cases[case_id]["expect"]["results"]
            self.assertEqual((got["stereo"], got["left"], got["right"], got["sub"]), results, case_id)
        l, r = ref.role_map("sub", 0.75, -0.5)
        self.assertEqual((l, r), (0.125, 0.125))                         # 0.5 * (0.75 - 0.5)
        self.assertEqual(ref.role_map("left", 0.75, -0.5), (0.75, 0.75))
        self.assertEqual(ref.role_map("right", 0.75, -0.5), (-0.5, -0.5))
        self.assertEqual(ref.role_map("stereo", 0.75, -0.5), (0.75, -0.5))

    def test_the_ramp_reaches_its_bound_in_about_240_frames_and_never_passes_it(self) -> None:
        t = self.trace("G02-MBR-001")
        ramps = [e for op, e in zip(self.cases["G02-MBR-001"]["ops"], t) if op[0] == "ramp"]
        self.assertAlmostEqual(ramps[0]["dsp"]["applied"], 100 / 480.0, places=5)   # 100 frames at 1/480
        self.assertAlmostEqual(ramps[1]["dsp"]["applied"], 200 / 480.0, places=5)
        self.assertEqual(ramps[2]["dsp"]["applied"], 0.5)                           # snapped exactly at 240 +- 1
        self.assertTrue(all(e["max_applied"] <= 0.5 for e in ramps))               # never above the bound
        dsp = ref.Dsp(True, frozenset())
        dsp.set_user_gain(0.5)
        dsp.set_muted(False)
        frames = next(n for n in range(1, 400) if (dsp.frame() == 0.5))
        self.assertIn(frames, (239, 240, 241))

    def test_reconnect_and_restart_are_silent_by_hand(self) -> None:
        t = self.trace("G02-MBR-012")
        ops = self.cases["G02-MBR-012"]["ops"]
        reconnect = next(e for op, e in zip(ops, t) if op[0] == "reconnect")
        self.assertEqual((reconnect["desired"], reconnect["mute"], reconnect["gain"]), (20, "join", 0.0))
        ramps = [e for op, e in zip(ops, t) if op[0] == "ramp"]
        self.assertAlmostEqual(ramps[0]["dsp"]["applied"], 0.9, places=6)           # was loud
        self.assertEqual(ramps[1]["dsp"]["applied"], 0.0)                           # silent before the new level
        self.assertAlmostEqual(ramps[2]["dsp"]["applied"], 0.2, places=7)           # then only the group's 20
        self.assertLessEqual(ramps[2]["max_applied"], 0.2 + 1e-7)
        r = self.trace("G02-MBR-013")
        self.assertEqual(r[0]["unmuted"], 0.0)                                      # stored 95 produces no gain
        self.assertEqual(r[1]["max_applied"], 0.0)
        final = [e for op, e in zip(self.cases["G02-MBR-013"]["ops"], r) if op[0] == "ramp"][-1]
        self.assertLessEqual(final["max_applied"], 0.2 + 1e-7)                      # the stored 95 was never audible

    def test_a_rejoin_keeps_its_own_state_and_refuses_a_stale_snapshot_by_hand(self) -> None:
        def rows(case_id: str, op_name: str) -> List[dict]:
            return [e for op, e in zip(self.cases[case_id]["ops"], self.trace(case_id)) if op[0] == op_name]

        # 020: the member has applied revisions 1 (volume 80) and 2 (volume 30). A snapshot at revision 1 carries the stale 80.
        # It is refused and the member stays at 30 / revision 2. A snapshot AT revision 2 is the same state and is taken (35),
        # a newer one (revision 9, volume 60) is taken, and one at revision 8 is old again, relative to the member's latest.
        r = rows("G02-MBR-020", "reconnect")
        self.assertEqual([e["result"] for e in r], ["stale_revision", "ok", "ok", "stale_revision"])
        self.assertEqual([(e["desired"], e["revision"]) for e in r], [(30, 2), (35, 3), (60, 9), (60, 9)])
        self.assertEqual([e["mute"] for e in r], [None, "join", "join", None])        # a refusal does not even start a join
        c = rows("G02-MBR-020", "cmd")
        self.assertEqual([e["result"] for e in c], ["ok", "ok", "ok", "revision_conflict", "ok", "stale_revision", "ok"])
        self.assertTrue(c[2]["duplicate"])                                          # the retry of revision 2 is still a duplicate
        self.assertEqual([e["desired"] for e in c], [80, 30, 30, 30, 35, 60, 45])
        # 021: a newer epoch's snapshot is taken at revision 1 although the member was at revision 5; inside the new epoch
        # revision 1 is old again; an older epoch is refused as an old epoch however high its revision.
        r = rows("G02-MBR-021", "reconnect")
        self.assertEqual([e["result"] for e in r], ["ok", "stale_revision", "stale_epoch"])
        self.assertEqual([(e["epoch"], e["revision"], e["desired"]) for e in r], [(8, 1, 60), (8, 2, 40), (8, 2, 40)])
        # 022: fault, then local, then join, then group: the reason follows the priority through the whole sequence.
        # board fail_muted, reconnect, join, group unmute -> fault; board active -> none; local mute on -> local;
        # reconnect -> local; board fail_muted, join -> fault; board active -> local; join -> local; local off -> none.
        mutes = [e["mute"] for e in self.trace("G02-MBR-022")][3:]
        self.assertEqual(mutes, ["fault"] * 4 + [None, "local", "local", "fault", "fault", "local", "local", None])
        # 023: a group at 100 plays the 0.25 ceiling; the rejoin to a group at 80 fades out, the join brings it back to the
        # ceiling and not to 0.8, and only removing the ceiling reaches 0.8. The bounded target is 0.25 during the rejoin.
        ramps = rows("G02-MBR-023", "ramp")
        for got, want in zip((e["dsp"]["applied"] for e in ramps), (0.25, 0.0, 0.25, 0.8)):
            self.assertAlmostEqual(got, want, places=6)
        self.assertLessEqual(max(e["max_applied"] for e in ramps[:3]), 0.25 + 1e-7)
        reconnect = rows("G02-MBR-023", "reconnect")[0]
        self.assertEqual((reconnect["desired"], reconnect["mute"], reconnect["gain"]), (80, "join", 0.0))
        self.assertAlmostEqual(reconnect["unmuted"], 0.25, places=7)
        # 024: the restart rejoins a group at 20 on a board that is not Active: fault-muted throughout, silent throughout,
        # holding the group's 20 (target 0.2) and never the stored 95.
        t = self.trace("G02-MBR-024")
        self.assertEqual({e["mute"] for e in t}, {"fault"})
        self.assertEqual({e["max_applied"] for op, e in zip(self.cases["G02-MBR-024"]["ops"], t) if op[0] == "ramp"}, {0.0})
        self.assertEqual(t[-1]["desired"], 20)
        self.assertAlmostEqual(t[-1]["unmuted"], 0.2, places=7)
        # 025: the member has applied revisions 1 (80) and 2 (30). A snapshot with a volume of 101 is out of range, and that is
        # the answer whether it is also from the older epoch (6, revision 9) or from the member's own epoch at the older
        # revision 1. The same two with a valid volume keep their own names. None of the four changes anything (30, revision 2,
        # no join started); the next command is taken (35) and so is a current snapshot (40, join-muted).
        r = rows("G02-MBR-025", "reconnect")
        self.assertEqual([e["result"] for e in r], ["volume_out_of_range", "volume_out_of_range", "stale_epoch", "stale_revision", "ok"])
        self.assertEqual([(e["desired"], e["revision"]) for e in r], [(30, 2)] * 4 + [(40, 3)])
        self.assertEqual([e["mute"] for e in r], [None] * 4 + ["join"])
        self.assertEqual([e["desired"] for e in rows("G02-MBR-025", "cmd")], [80, 30, 35])

    def test_group_by_hand(self) -> None:
        t = self.trace("G02-GRP-001")
        ops = self.cases["G02-GRP-001"]["ops"]
        i = next(n for n, op in enumerate(ops) if op[0] == "rejoin")
        self.assertEqual(t[i]["state"][1], [2, 80, "join", 0.0, 3])                 # the group's 80, join-muted, never its stale 40
        self.assertEqual([m[1] for m in t[i - 1]["members"]], ["accepted", "missing", "accepted"])
        self.assertEqual([s[1] for s in t[-1]["state"]], [85, 85, 85])             # +5 once, despite the retry
        self.assertEqual(t[-1]["result"], "stale_revision")
        self.assertNotIn("members", t[-1])                                          # a refusal fans out to nobody


class PairedNegativesAndPositives(Base):
    """Every refusal sits beside the permitted behaviour it must not break."""

    def test_fault_mute_overrides_the_unmute_but_the_same_commands_are_audible_on_an_active_board(self) -> None:
        fail, live = self.trace("G02-MBR-005"), self.trace("G02-MBR-006")
        self.assertEqual(self.cases["G02-MBR-005"]["ops"], self.cases["G02-MBR-006"]["ops"])
        self.assertNotEqual(self.cases["G02-MBR-005"]["board"], self.cases["G02-MBR-006"]["board"])
        self.assertEqual((fail[-1]["mute"], fail[-1]["dsp"]["muted"], fail[-1]["max_applied"]), ("fault", True, 0.0))
        self.assertEqual((live[-1]["mute"], live[-1]["dsp"]["muted"]), (None, False))
        self.assertGreater(live[-1]["dsp"]["applied"], 0.0)

    def test_a_restart_is_silent_on_a_board_that_is_not_active_and_audible_only_to_the_groups_volume_on_a_live_one(self) -> None:
        failed, live = self.trace("G02-MBR-024"), self.trace("G02-MBR-013")
        self.assertEqual(self.cases["G02-MBR-024"]["ops"], self.cases["G02-MBR-013"]["ops"])
        self.assertEqual(self.cases["G02-MBR-024"]["start"], self.cases["G02-MBR-013"]["start"])
        self.assertEqual((self.cases["G02-MBR-024"]["board"], self.cases["G02-MBR-013"]["board"]), ("fail_muted", "active"))
        self.assertEqual((failed[-1]["mute"], failed[-1]["dsp"]["applied"], failed[-1]["max_applied"]), ("fault", 0.0, 0.0))
        self.assertEqual(live[-1]["mute"], None)
        self.assertAlmostEqual(live[-1]["dsp"]["applied"], 0.2, places=6)             # the group's 20, never the stored 95

    def test_the_stale_snapshot_is_refused_beside_the_equal_newer_and_new_epoch_ones_that_are_taken(self) -> None:
        for case_id in ("G02-MBR-020", "G02-MBR-021"):
            results = [e["result"] for op, e in zip(self.cases[case_id]["ops"], self.trace(case_id)) if op[0] == "reconnect"]
            self.assertIn("stale_revision", results)
            self.assertIn("ok", results)
        # the same snapshot revision is refused or taken depending only on the member's revision: 8 after 9, 9 after 9
        t = self.trace("G02-MBR-020")
        ops = self.cases["G02-MBR-020"]["ops"]
        by = [(op[2], e["result"]) for op, e in zip(ops, t) if op[0] == "reconnect"]
        self.assertEqual(by, [(1, "stale_revision"), (3, "ok"), (9, "ok"), (8, "stale_revision")])

    def test_refusals_are_followed_by_accepted_commands(self) -> None:
        for case_id in ("G02-MBR-007", "G02-MBR-008", "G02-MBR-009", "G02-MBR-010", "G02-MBR-016", "G02-MBR-020", "G02-MBR-021",
                        "G02-MBR-025", "G02-GRP-002", "G02-GRP-004"):
            results = [e["result"] for e in self.trace(case_id)]
            first_refusal = next(i for i, r in enumerate(results) if r not in ("ok",))
            self.assertIn("ok", results[first_refusal + 1:], f"{case_id}: nothing legitimate after the first refusal")

    def test_a_per_room_command_is_refused_but_a_group_command_with_the_same_revision_still_works(self) -> None:
        t = self.trace("G02-GRP-002")
        self.assertEqual([e["result"] for e in t[-3:]], ["not_group_wide", "not_group_wide", "ok"])
        self.assertEqual(t[-1]["snapshot"]["revision"], 2)


class PlantedDefects(Base):
    """Each planted defect must fail at least one vector; the unmutated control must stay green."""

    def judge_all(self, bugs: frozenset, neutralize_model: bool = False) -> List[str]:
        failed = []
        for case in self.doc["cases"]:
            obs = observed_for(case, bugs)
            if neutralize_model:  # make the model comparison pass by construction: properties only
                case = {**case, "expect": {k: v for k, v in obs.items() if k not in ("id", "kind")}}
            if runner.judge_case(case, obs):
                failed.append(case["id"])
        return failed

    def test_the_baseline_is_green_before_any_defect_is_credited(self) -> None:
        self.assertEqual(self.judge_all(frozenset()), [])
        self.assertEqual(self.judge_all(frozenset(), neutralize_model=True), [])

    def test_every_planted_defect_is_caught_and_removing_it_restores_green(self) -> None:
        self.assertEqual(len(ref.BUGS), len(set(ref.BUGS)))
        for bug in ref.BUGS:
            with self.subTest(bug=bug):
                failed = self.judge_all(frozenset({bug}))
                self.assertTrue(failed, f"{bug} was not caught by any vector")
                # remove-the-plant control: the same cases pass without it
                self.assertEqual(self.judge_all(frozenset()), [], f"{bug}: the control is not green")

    def test_every_planted_defect_is_also_caught_by_the_properties_alone(self) -> None:
        """The verdict must not rest on the model: with its expectations neutralized, properties still bite."""
        for bug in ref.BUGS:
            with self.subTest(bug=bug):
                failed = self.judge_all(frozenset({bug}), neutralize_model=True)
                self.assertTrue(failed, f"{bug} is invisible to the model-independent properties")

    REJOIN_PLANTS = {
        # the plant -> the cases that must fail while it is in: the check each one exercises
        "reconnect_accepts_older_revision": {"G02-MBR-020", "G02-MBR-021"},   # a snapshot older than the member's own revision
        "reconnect_clears_local": {"G02-MBR-019", "G02-MBR-022"},             # a rejoin must not undo a local mute
        "reconnect_clears_fault": {"G02-MBR-022", "G02-MBR-024"},             # a rejoin must not undo a fault mute
        "reconnect_drops_fault_ceiling": {"G02-MBR-023"},                     # a rejoin must not lift a fault ceiling
    }

    def test_each_rejoin_plant_fails_the_cases_that_exercise_its_check_and_its_removal_restores_green(self) -> None:
        for bug, expected in self.REJOIN_PLANTS.items():
            self.assertIn(bug, ref.BUGS)
            with self.subTest(bug=bug):
                with_model = set(self.judge_all(frozenset({bug})))
                alone = set(self.judge_all(frozenset({bug}), neutralize_model=True))
                self.assertTrue(expected <= with_model, f"{bug}: {sorted(expected - with_model)} did not fail with the model")
                self.assertTrue(expected <= alone, f"{bug}: {sorted(expected - alone)} did not fail on the properties alone")
                self.assertEqual(self.judge_all(frozenset()), [], f"{bug}: the control is not green")

    @staticmethod
    def reconnect_checking(order: tuple):
        """`Member.reconnect` with its three refusals judged in `order` instead of range, epoch, revision."""
        def reconnect(self, epoch: int, revision: int, volume: int, group_mute: bool) -> str:
            for check in order:
                if check == "range" and volume > ref.MAX_VOLUME:
                    return "volume_out_of_range"
                if check == "epoch" and self.epoch is not None and epoch < self.epoch:
                    return "stale_epoch"
                if check == "revision" and self.epoch == epoch and revision < self.last_rev:
                    return "stale_revision"
            self.adopt(epoch, revision, volume, group_mute)
            return "ok"
        return reconnect

    def test_the_place_of_the_range_check_among_the_refusals_is_pinned_and_its_control_is_green(self) -> None:
        correct = ("range", "epoch", "revision")
        with patch.object(ref.Member, "reconnect", self.reconnect_checking(correct)):
            self.assertEqual(self.judge_all(frozenset()), [], "control: the contract's order is green")
        # The range check anywhere but first changes the answer for a snapshot that fails it and a staleness check. Epoch and
        # revision staleness exclude each other, so those two never need an order between them.
        for order, why in ((("epoch", "revision", "range"), "range last: both snapshots are named for their staleness"),
                           (("epoch", "range", "revision"), "range after the epoch check: the older-epoch snapshot is named stale_epoch"),
                           (("revision", "range", "epoch"), "range after the revision check: the older-revision snapshot is named stale_revision")):
            with self.subTest(order=order, why=why):
                with patch.object(ref.Member, "reconnect", self.reconnect_checking(order)):
                    self.assertEqual(self.judge_all(frozenset()), ["G02-MBR-025"])
        with patch.object(ref.Member, "reconnect", self.reconnect_checking(correct)):
            self.assertEqual(self.judge_all(frozenset()), [], "the plant removed: green again")
        self.assertEqual(self.judge_all(frozenset()), [], "unpatched: green")

    def test_the_rejoin_plants_do_not_fail_cases_that_never_rejoin(self) -> None:
        rejoining = {c["id"] for c in self.doc["cases"] if any(op[0] in ("reconnect", "rejoin") for op in c.get("ops", []))}
        for bug in self.REJOIN_PLANTS:
            with self.subTest(bug=bug):
                stray = set(self.judge_all(frozenset({bug}))) - rejoining
                self.assertEqual(stray, set(), f"{bug} fails a case that never rejoins")

    def test_two_defects_together_are_still_caught(self) -> None:
        self.assertTrue(self.judge_all(frozenset({"reconnect_keeps_stored", "fault_ignored"})))


class JudgeBehavior(Base):
    def test_a_consistent_log_is_qualified(self) -> None:
        results = self.judge(cargo_log(self.doc))
        self.assertEqual(self.by(results, "failed"), [])
        self.assertEqual(self.by(results, "blocked"), [])
        self.assertEqual(runner.exit_code(results), 0)
        self.assertEqual(len(results), 4 + 51 + len(runner.derive_rust_tests()))

    def test_no_log_blocks_everything_rust_backed(self) -> None:
        results, _ = runner.run("full", None)
        self.assertEqual(runner.exit_code(results), 3)
        self.assertTrue(all(r.case_id.startswith("G02-META-") for r in results if r.status == "passed"))

    def test_a_missing_case_and_a_missing_rust_test_stay_blocked(self) -> None:
        name = "volume::tests::the_view_keeps_desired_bounded_and_applied_gain_apart_and_explains_a_silent_unmute"
        results = self.judge(cargo_log(self.doc, drop_cases=("G02-MBR-003",), drop_tests=(name,)))
        self.assertEqual(sorted(self.by(results, "blocked")), sorted(["G02-MBR-003", f"RUST:franken_dsp::{name}"]))
        self.assertEqual(self.by(results, "failed"), [])

    def test_owned_role_and_button_cases_are_required_and_missing_logs_block(self) -> None:
        names = (
            "network_render::tests::controller_events::role_integration::admitted_roles_match_manual_per_channel_protected_oracle_through_finite_eof",
            "network_render::tests::controller_events::button_integration::local_button_mute_survives_clock_failure_and_reports_real_drain_custody",
        )
        required = set(runner.derive_rust_tests())
        for name in names:
            with self.subTest(name=name):
                self.assertIn(("franken_speaker", name), required)
                result = self.judge(cargo_log(self.doc, drop_tests=(name,)))
                self.assertEqual(self.by(result, "blocked"), [f"RUST:franken_speaker::{name}"])
                self.assertEqual(self.by(result, "failed"), [])
                self.assertEqual(runner.exit_code(result), 3)

    def test_failed_owned_render_cases_cannot_pass_the_judge(self) -> None:
        names = (
            "network_render::tests::controller_events::role_integration::admitted_roles_match_manual_per_channel_protected_oracle_through_finite_eof",
            "network_render::tests::controller_events::button_integration::local_button_mute_survives_clock_failure_and_reports_real_drain_custody",
        )
        for name in names:
            with self.subTest(name=name):
                text = cargo_log(self.doc)
                before = f"test {name} ... ok"
                self.assertEqual(text.count(before), 1)
                result = self.judge(text.replace(before, f"test {name} ... FAILED"))
                self.assertEqual(self.by(result, "failed"), [f"RUST:franken_speaker::{name}"])
                self.assertEqual(runner.exit_code(result), 1)

    def test_missing_required_owned_source_cannot_shrink_the_plan(self) -> None:
        rel = "crates/franken-speaker/src/network_render/tests/controller_events/button_integration.rs"
        real_isfile = os.path.isfile
        missing = os.path.join(runner.REPO, rel)
        with patch.object(runner.os.path, "isfile", side_effect=lambda path: False if path == missing else real_isfile(path)):
            with self.assertRaisesRegex(ValueError, re.escape(rel)):
                runner.derive_rust_tests()

    def test_a_divergence_is_reported_with_the_path_to_the_first_difference(self) -> None:
        def bend(obs: dict) -> dict:
            obs["trace"][4]["unmuted"] += 0.01
            return obs

        results = self.judge(cargo_log(self.doc, perturb={"G02-MBR-001": bend}))
        self.assertEqual(self.by(results, "failed"), ["G02-MBR-001"])
        detail = next(r.detail for r in results if r.case_id == "G02-MBR-001")
        self.assertIn("[4].unmuted", detail)

    def test_a_wrong_refusal_name_fails_its_case(self) -> None:
        def rename(obs: dict) -> dict:
            obs["results"]["sub"] = "ok"
            return obs

        results = self.judge(cargo_log(self.doc, perturb={"G02-ROLE-001": rename}))
        self.assertEqual(self.by(results, "failed"), ["G02-ROLE-001"])

    def test_properties_alone_fail_a_case_whose_expectation_was_made_to_match(self) -> None:
        case = copy.deepcopy(self.cases["G02-MBR-003"])
        obs = observed_for(case)
        for entry in obs["trace"]:
            if "max_step" in entry:
                entry["max_step"] = 0.05                    # a 24x step in one sample
        case["expect"] = {k: v for k, v in obs.items() if k not in ("id", "kind")}
        problem = runner.judge_case(case, obs)
        self.assertIn("property", problem)
        self.assertIn("one sample", problem)

    def test_diff_is_strict_about_types_and_keys(self) -> None:
        d = runner.diff
        self.assertIsNone(d("", 1, 1.0))
        self.assertIsNotNone(d("", True, 1))                 # a bool is never a number
        self.assertIsNotNone(d("", 0, False))
        self.assertIsNone(d("", 0.5, 0.5 + 5e-8))
        self.assertIsNotNone(d("", 0.5, 0.5 + 5e-7))
        self.assertIn("keys differ", d("", {"a": 1}, {"a": 1, "b": 2}))
        self.assertIn("expected 2 items", d("", [1, 2], [1]))
        self.assertIn(".x[1]", d("", {"x": [1, 2]}, {"x": [1, 3]}))
        self.assertIsNotNone(d("", None, 0))

    def test_d01_log_parser_reuse_leaves_d01_untouched(self) -> None:
        spec = importlib.util.spec_from_file_location("g02_t_pristine_d01", os.path.join(REPO, "tests", "d01", "run_cases.py"))
        pristine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = pristine
        spec.loader.exec_module(pristine)
        self.assertEqual(pristine.OBSERVED.pattern, r"D01-OBSERVED (\{.*\})\s*$")
        self.assertEqual(runner.d01.OBSERVED.pattern, r"G02-OBSERVED (\{.*\})\s*$")
        self.assertIsNot(pristine, runner.d01)


class HarnessAgreement(Base):
    """The Rust harness must implement every operation the vectors use (cross-language drift)."""

    def setUp(self) -> None:
        super().setUp()
        with open(os.path.join(REPO, "crates", "franken-dsp", "tests", "g02_vectors.rs"), encoding="utf-8") as handle:
            self.rust = handle.read()

    def literals(self) -> set:
        return set(re.findall(r'"([a-z_]+)"', self.rust))

    def test_every_kind_op_command_and_board_in_the_vectors_exists_in_the_harness(self) -> None:
        kinds, ops, commands, boards = set(), set(), set(), set()
        for case in self.doc["cases"]:
            kinds.add(case["kind"])
            if case["kind"] in ("member_script", "group_script"):
                for op in case["ops"]:
                    ops.add(op[0])
                    for item in op[1:]:
                        if isinstance(item, list) and item and isinstance(item[0], str):
                            commands.add(item[0])
                    if op[0] == "board":
                        boards.add(op[1])
                if case.get("board"):
                    boards.add(case["board"])
        have = self.literals()
        for label, needed in (("kinds", kinds), ("operations", ops), ("commands", commands), ("boards", boards)):
            self.assertEqual(sorted(needed - have), [], f"vector {label} the Rust harness does not implement")

    def test_the_harness_emits_the_same_observation_keys_as_the_model(self) -> None:
        keys = set()
        for case in self.doc["cases"]:
            if case["kind"] == "member_script":
                for entry in case["expect"]["trace"]:
                    keys |= set(entry) | set(entry.get("dsp", {}))
            elif case["kind"] == "group_script":
                for entry in case["expect"]["trace"]:
                    keys |= set(entry) | set(entry["snapshot"])
        for key in keys | {"gains", "results", "mapped", "trace"}:
            self.assertIn(f'"{key}"', self.rust, f"observation key {key!r} is never emitted by the harness")

    def test_every_refusal_code_in_the_vectors_is_a_stable_rust_code(self) -> None:
        with open(os.path.join(REPO, "crates", "franken-dsp", "src", "volume.rs"), encoding="utf-8") as handle:
            source = handle.read()
        rust_codes = set(re.findall(r'=> "([a-z_]+)",', source))
        seen = set()
        for case in self.doc["cases"]:
            if case["kind"] in ("member_script", "group_script"):
                for entry in case["expect"]["trace"]:
                    seen.add(entry["result"])
                    seen |= {m[1] for m in entry.get("members", [])}
            elif case["kind"] == "roles":
                seen |= set(case["expect"]["results"].values())
        # "ok", "accepted", "duplicate" and "missing" are harness words; ProtectionError codes come from D02.
        harness_words = {"ok", "accepted", "duplicate", "missing", "unmute_refused"}
        self.assertEqual(sorted(seen - rust_codes - harness_words), [], "vectors name codes that volume.rs does not define")


class AcceptanceMap(unittest.TestCase):
    """The acceptance map in docs/contracts/g02.md cites only tests, identifiers and case ids that exist in the tree."""

    DOC = "docs/contracts/g02.md"
    VECTORS = ("tests/g02/vectors.json",)
    PREFIXES = ("G02",)

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
        pcm_ids = {c['id'] for c in json.loads((self.repo / 'tests/g02/pcm_vectors.json').read_text(encoding='utf-8'))['cases']}
        for ids_cited in re.findall(r'G02PCM-(\d+(?:(?:\.\.|/)\d+)*)', self.section):
            problems += [i for i in self.expand('G02PCM', '', ids_cited) if i not in pcm_ids]
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
