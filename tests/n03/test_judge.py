#!/usr/bin/env python3
"""Self-test of the N03 judge (tests/n03/run_cases.py).  SYNTHETIC: the logs here are fabricated from the
reference's own expected values to prove the judge qualifies a good log and catches each kind of bad one.
They say nothing about the Rust, which has not been run.

    python3 -B -I -m unittest discover -s tests/n03 -p 'test_judge.py'
"""
import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("n03_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = _load("run_cases")
ref, gen = rc.ref, rc.gen
with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

ALL_WORLDS = VEC["worlds"] + [m["world"] for m in VEC["mixed"]["members"]]


def truth_summary(wdef, steps):
    checks = max_err = max_unc = 0
    min_margin = None
    for op, g in zip(wdef["ops"], steps):
        if op["op"] == "check" and "truth_group" in op:
            err = abs(g["group_ns"] - op["truth_group"])
            checks += 1
            max_err, max_unc = max(max_err, err), max(max_unc, g["uncertainty_ns"])
            margin = g["uncertainty_ns"] - err
            min_margin = margin if min_margin is None else min(min_margin, margin)
    return {"checks": checks, "max_err_ns": max_err, "max_unc_ns": max_unc, "min_margin_ns": min_margin}


def good_records():
    D = ref.DEFAULTS
    recs = [{"kind": "defaults", "id": "n03-defaults", "params": dict(D)}]
    cfg = rc._cfg
    recs.append({"kind": "exchanges", "id": "n03-exchanges",
                 "cases": {c["id"]: ref.sample(c["t1"], c["t2"], c["t3"], c["t4"], cfg(c["cfg"])) for c in VEC["exchanges"]}})
    recs.append({"kind": "transforms", "id": "n03-transforms",
                 "cases": {c["id"]: {"group_ns": ref.group_at(c["sample"], c["now"], c["ratio_ppb"]),
                                     "local_for_group": ref.local_of(c["sample"], c["group_target"], c["ratio_ppb"])}
                           for c in VEC["transforms"]}})
    sel = {}
    for c in VEC["selections"]:
        i, u = ref.select(c["samples"], c["now"], c["ratio_unc_ppb"], D)
        sel[c["id"]] = {"index": i, "uncertainty_ns": u}
    recs.append({"kind": "selections", "id": "n03-selections", "cases": sel})
    hold = {}
    for c in VEC["holdovers"]:
        until, binding = ref.holdover(c["sample"], c["ratio_unc_ppb"], cfg(c["cfg"]), c["authority"], c["buffer"])
        hold[c["id"]] = {"until": until, "binding": binding}
    recs.append({"kind": "holdovers", "id": "n03-holdovers", "cases": hold})
    plans = {}
    for c in VEC["plans"]:
        r = ref.plan_start(c["sample"], c["ratio_ppb"], c["ratio_unc_ppb"], cfg(c["cfg"]), now=c["now"], epoch=c["epoch"],
                           sched_epoch=c["sched_epoch"], sched_start_group_ns=c["start_group_ns"], status=c["status"],
                           authority_until=c["authority"], buffer_until=c["buffer"])
        plans[c["id"]] = r if r.get("ok") else {"reject": r["reject"]}
    recs.append({"kind": "plans", "id": "n03-plans", "cases": plans})
    for w in ALL_WORLDS:
        steps = [{k: v for k, v in r.items() if k != "tol"} for r in gen.expect_for(w)]
        recs.append({"kind": "world", "id": w["id"], "steps": steps, "truth": truth_summary(w, steps)})
    members, audible, unc = [], [], 0
    for m in VEC["mixed"]["members"]:
        admit = next(r for r in gen.expect_for(m["world"]) if r["op"] == "admit")
        members.append({"id": m["world"]["id"], "start_local_ns": admit["start_local_ns"],
                        "uncertainty_at_start_ns": admit["uncertainty_at_start_ns"]})
        audible.append(rc.true_instant_of_local(m["world"]["clocks"], admit["start_local_ns"]) + m["world"]["cfg"].get("output_delay_ns", 0))
        unc += admit["uncertainty_at_start_ns"]
    recs.append({"kind": "mixed", "id": "n03-mixed", "members": members, "skew_ns": abs(audible[0] - audible[1]),
                 "bound_ns": unc, "gate_ns": 2_000_000})
    sims = []
    for args in ref.SIM_WORLDS:
        r = ref.sim_run(*args)
        r.pop("locked")
        r["seed"], r["skew_ppb"] = args[0], args[1]
        sims.append(r)
    recs.append({"kind": "sim", "id": "n03-sim", "worlds": sims})
    recs.append({"kind": "property", "id": "n03-property", "audible": 900, "resets_checked": 150})
    recs.append(dict(ref.ring_scenario(), kind="events", id="n03-events"))
    recs.append({"kind": "log_lines", "id": "n03-log-lines", "lines": ref.log_scenario()})
    return recs


GOOD = good_records()


def build_log(records, skip_tests=(), failed_tests=(), ignored_tests=(), layout="classic", extra_sections=()):
    """A cargo-test log of the same FORM as the real ones. layout "rch": the stdout sections come first and the
    stderr ``Running`` headers arrive afterwards (the shape through RCH)."""
    names = sorted({name for case in rc.registry(VEC) for _, name in case["tests"]})
    shown = [n for n in names if n.rsplit("::", 1)[-1] not in skip_tests]
    body = ["", "running %d tests" % len(shown)]
    for n in shown:
        bare = n.rsplit("::", 1)[-1]
        body.append("test %s ... %s" % (n, "FAILED" if bare in failed_tests else "ignored" if bare in ignored_tests else "ok"))
    not_passing = set(failed_tests) | set(ignored_tests)
    passed = sum(1 for n in shown if n.rsplit("::", 1)[-1] not in not_passing)
    body += ["", "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s" % passed]
    header = "     Running unittests src/lib.rs (.rch-target-w0-pool-0123456789abcdef/debug/deps/franken_clock-0123456789abcdef)"
    sections = [(header, body)]
    for extra in extra_sections:
        sections.append((None, ["", "running %d tests" % len(extra)] + ["test %s ... ok" % n for n in extra]
                         + ["", "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s" % len(extra)]))
    lines = ["   Compiling franken-clock v0.1.0", "    Finished `test` profile"]
    if layout == "classic":
        for h, b in sections:
            lines += ([h] if h else []) + b
    else:
        for _, b in sections:
            lines += b
        lines += [h for h, _ in sections if h]
    lines += ["N03-OBSERVED " + json.dumps(r) for r in records]
    return "\n".join(lines) + "\n"


def judge(*texts, tier="full"):
    with tempfile.TemporaryDirectory() as d:
        logs = rc.Logs()
        for i, text in enumerate(texts):
            path = os.path.join(d, "cargo%d.log" % i)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            logs.add(path)
        results, _ = rc.run(tier, logs)
    return {r.case_id: r for r in results}, results


def tampered(rid, mutate):
    recs = copy.deepcopy(GOOD)
    rec = next(r for r in recs if r["id"] == rid)
    mutate(rec)
    return recs


def first_step(rec, op, **where):
    return next(s for s in rec["steps"] if s["op"] == op and all(s.get(k) == v for k, v in where.items()))


class JudgeSelfTest(unittest.TestCase):
    def failing(self, records, case_id, layout="classic"):
        by_id, _ = judge(build_log(records, layout=layout))
        self.assertEqual(by_id[case_id].status, "failed", (case_id, by_id[case_id].as_dict()))
        return by_id

    def test_a_good_log_qualifies_in_either_layout_at_either_tier(self):
        """N03-JUDGE-GOOD"""
        for layout in ("classic", "rch"):
            for tier in rc.TIERS:
                _, results = judge(build_log(GOOD, layout=layout), tier=tier)
                self.assertEqual(rc.exit_code(results), 0, (layout, tier, [r.as_dict() for r in results if r.status != "passed"]))

    def test_the_whole_log_twice_changes_nothing(self):
        text = build_log(GOOD)
        _, results = judge(text, text)
        self.assertEqual(rc.exit_code(results), 0)
        self.assertEqual(len(results), len(judge(text)[1]))

    def test_no_log_blocks_every_rust_backed_case_and_passes_none(self):
        """N03-JUDGE-BLOCKED"""
        results, _ = rc.run("full", None)
        rust = [r for r in results if not r.case_id.startswith("N03-META")]
        self.assertTrue(rust)
        self.assertTrue(all(r.status == "blocked" for r in rust))
        self.assertEqual(rc.exit_code(results), 3 if not any(r.status == "failed" for r in results) else 1)

    def test_a_test_that_is_missing_stays_blocked_not_failed_and_not_passed(self):
        by_id, results = judge(build_log(GOOD, skip_tests=("n03_world_s11_admission",)))
        self.assertEqual(by_id["N03-ADMISSION"].status, "blocked")
        self.assertEqual(rc.exit_code(results), 3)

    def test_a_failed_test_fails_its_case(self):
        by_id, results = judge(build_log(GOOD, failed_tests=("n03_world_s13_reboot",)))
        self.assertEqual(by_id["N03-REBOOT"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)

    def test_an_ignored_test_is_blocked(self):
        by_id, _ = judge(build_log(GOOD, ignored_tests=("n03_world_s15_soak_3h",)))
        self.assertEqual(by_id["N03-SOAK"].status, "blocked")

    def test_a_missing_observation_blocks(self):
        recs = [r for r in GOOD if r["id"] != "S12-OUTSTANDING-BOUND"]
        by_id, _ = judge(build_log(recs))
        self.assertEqual(by_id["N03-ADMISSION"].status, "blocked")

    def test_a_name_that_appears_in_two_sections_cannot_be_attributed(self):
        by_id, _ = judge(build_log(GOOD, layout="rch", extra_sections=[["group::tests::n03_world_s01_symmetric"]]))
        self.assertIn(by_id["N03-LOCK"].status, ("blocked", "failed"))
        self.assertNotEqual(by_id["N03-LOCK"].status, "passed")

    def test_conflicting_observations_fail_the_log_check(self):
        other = copy.deepcopy(GOOD)
        next(r for r in other if r["id"] == "n03-property")["audible"] = 901
        text = build_log(GOOD) + "".join("N03-OBSERVED " + json.dumps(r) + "\n" for r in other if r["id"] == "n03-property")
        by_id, _ = judge(text)
        self.assertEqual(by_id["N03-META-LOGS-CONSISTENT"].status, "failed")

    # ---- tampering: each is a loosened or wrong Rust the judge must catch --------------------------

    def test_wrong_defaults(self):
        self.failing(tampered("n03-defaults", lambda r: r["params"].update(lock_uncertainty_ns=4_000_000)), "N03-PARAMS")

    def test_wrong_exchange_result(self):
        def m(r):
            r["cases"]["symmetric"]["delay"] += 1
        self.failing(tampered("n03-exchanges", m), "N03-EXCHANGE")

    def test_an_exchange_that_should_be_rejected_but_was_accepted(self):
        def m(r):
            r["cases"]["t3-before-t2"] = {"delay": 1, "local_mid": 1, "group_mid": 1, "offset": 0}
        self.failing(tampered("n03-exchanges", m), "N03-EXCHANGE")

    def test_wrong_transform(self):
        def m(r):
            r["cases"]["fast-forward"]["group_ns"] += 1
        self.failing(tampered("n03-transforms", m), "N03-TRANSFORM")

    def test_wrong_selection(self):
        def m(r):
            r["cases"]["tie-goes-to-newer-mid"]["index"] ^= 1
        self.failing(tampered("n03-selections", m), "N03-SELECT")

    def test_wrong_holdover_binding(self):
        def m(r):
            r["cases"]["authority-buffer-tie"]["binding"] = "Buffer"
        self.failing(tampered("n03-holdovers", m), "N03-HOLDOVER-MIN")

    def test_wrong_plan(self):
        def m(r):
            r["cases"]["too-late"] = {"ok": True, "start_local_ns": 1, "deadline_local_ns": 1, "uncertainty_at_start_ns": 1,
                                      "valid_until_local_ns": 2, "binding": "Uncertainty"}
        self.failing(tampered("n03-plans", m), "N03-PLAN-TABLE")

    def test_a_world_step_that_differs_from_the_reference(self):
        def m(r):
            first_step(r, "raw")["result"] = "ok"
        self.failing(tampered("S10-LEADER-CHANGE", m), "N03-LEADER-CHANGE")

    def test_an_unlocked_member_that_is_audible_is_caught(self):
        def m(r):
            first_step(r, "tick", output="Muted")["output"] = "Audible"
        self.failing(tampered("S17-UNLOCKED-CANNOT-OUTPUT", m), "N03-UNLOCKED-MUTED")

    def test_a_stale_epoch_accepted_is_caught(self):
        def m(r):
            first_step(r, "raw", result="StaleEpoch")["result"] = "ok"
        self.failing(tampered("S10-LEADER-CHANGE", m), "N03-LEADER-CHANGE")

    def test_a_clock_jump_that_does_not_mute_is_caught(self):
        def m(r):
            first_step(r, "probe", result="Discontinuity")["result"] = "ok"
        self.failing(tampered("S08A-JUMP-LOCAL-SUSPEND", m), "N03-JUMP")

    def test_a_world_with_fewer_steps_is_caught(self):
        def m(r):
            r["steps"].pop()
        self.failing(tampered("S01-SYMMETRIC", m), "N03-LOCK")

    def test_the_truth_leaving_the_reported_uncertainty_is_caught_even_if_the_steps_agree(self):
        def m(r):
            chk = next(s for s in r["steps"] if s["op"] == "check")
            chk["group_ns"] += chk["uncertainty_ns"] + 1
        self.failing(tampered("S01-SYMMETRIC", m), "N03-LOCK")

    def test_a_truth_summary_that_does_not_match_the_steps_is_caught(self):
        def m(r):
            r["truth"]["min_margin_ns"] += 1
        self.failing(tampered("S01-SYMMETRIC", m), "N03-LOCK")

    def test_the_float_tolerance_is_bounded(self):
        """A rate-bearing check may differ by the stated tolerance and not by one more."""
        w = next(x for x in ALL_WORLDS if x["id"] == "S04-DRIFT-FAST")
        want = gen.expect_for(w)
        idx = next(i for i, r in enumerate(want) if r["op"] == "check" and "tol" in r)
        tol = want[idx]["tol"]["uncertainty_ns"]

        def shift(by):
            def m(r):
                r["steps"][idx]["uncertainty_ns"] += by
            return m
        by_id, _ = judge(build_log(tampered("S04-DRIFT-FAST", shift(tol))))
        self.assertEqual(by_id["N03-DRIFT"].status, "passed", by_id["N03-DRIFT"].as_dict())
        self.failing(tampered("S04-DRIFT-FAST", shift(tol + 1)), "N03-DRIFT")

    def test_a_ratio_that_is_off_by_one_ppb_is_caught_because_it_is_exact(self):
        w = next(x for x in ALL_WORLDS if x["id"] == "S04-DRIFT-FAST")
        want = gen.expect_for(w)
        idx = next(i for i, r in enumerate(want) if r["op"] == "check" and "ratio_ppb" in r and r["rate_in_force"])

        def m(r):
            r["steps"][idx]["ratio_ppb"] += 1
        self.failing(tampered("S04-DRIFT-FAST", m), "N03-DRIFT")

    def test_a_mixed_start_skew_over_the_gate_is_caught(self):
        def m(r):
            r["skew_ns"] = 2_000_001
        self.failing(tampered("n03-mixed", m), "N03-MIXED-PROFILE")

    def test_a_member_start_that_differs_is_caught(self):
        def m(r):
            r["members"][0]["start_local_ns"] += 1
        self.failing(tampered("n03-mixed", m), "N03-MIXED-PROFILE")

    def test_the_independent_world_leaving_its_bound_is_caught(self):
        def m(r):
            r["worlds"][2]["max_err_ns"] += 1
        self.failing(tampered("n03-sim", m), "N03-TRUTH-SIM")

    def test_buffer_accounting_that_loses_a_critical_event_silently_is_caught(self):
        def m(r):
            r["final"]["critical_lost"] = 0
        self.failing(tampered("n03-events", m), "N03-DIAGNOSTICS")

    def test_a_rate_limit_that_does_not_count_is_caught(self):
        def m(r):
            r["rate"]["rate_limited"] = 0
        self.failing(tampered("n03-events", m), "N03-DIAGNOSTICS")

    def test_an_unavailable_log_that_hides_its_losses_is_caught(self):
        def m(r):
            r["unavailable"]["critical_lost"] = 0
        self.failing(tampered("n03-events", m), "N03-DIAGNOSTICS")

    def test_a_log_line_that_differs_from_the_reference_is_caught(self):
        def m(r):
            r["lines"][3] = r["lines"][3].replace("accepted=4/4", "accepted=3/4")
        self.failing(tampered("n03-log-lines", m), "N03-DIAGNOSTICS")

    def test_a_log_line_that_leaks_a_field_or_drops_the_claim_is_caught(self):
        def m(r):
            r["lines"][0] = r["lines"][0].replace("network-clock-fit-only: not DAC or acoustic alignment", "ok")
        self.failing(tampered("n03-log-lines", m), "N03-DIAGNOSTICS")

    def test_a_dropped_count_that_does_not_add_up_is_caught(self):
        def m(r):
            r["after_rejections"]["dropped"] = 0
        self.failing(tampered("n03-events", m), "N03-DIAGNOSTICS")

    def test_a_world_whose_events_differ_from_the_reference_is_caught(self):
        def m(r):
            step = first_step(r, "probe", result="Discontinuity")
            step["events"] = [e for e in step["events"] if not e.startswith("n03.reset")]
        self.failing(tampered("S08A-JUMP-LOCAL-SUSPEND", m), "N03-JUMP")

    def test_a_lock_that_is_not_logged_is_caught(self):
        def m(r):
            step = next(s for s in r["steps"] if "n03.status.locked" in s["events"])
            step["events"] = [e for e in step["events"] if e != "n03.status.locked"]
        self.failing(tampered("S01-SYMMETRIC", m), "N03-LOCK")

    def test_a_thin_property_run_is_caught(self):
        def m(r):
            r["audible"] = 3
        self.failing(tampered("n03-property", m), "N03-PROPERTY")

    def test_a_property_record_alone_cannot_stand_in_for_a_test_that_did_not_run(self):
        by_id, _ = judge(build_log(GOOD, skip_tests=("n03_audible_output_always_rests_on_a_locked_clock_a_valid_authority_and_an_admitted_start",)))
        self.assertEqual(by_id["N03-PROPERTY"].status, "blocked")


class ReferenceSelfTest(unittest.TestCase):
    def test_every_world_asserts_the_central_claim_against_truth(self):
        """N03-TRUTH-GENERATOR: the generator already refused any world that broke the claim; check it ran."""
        truth = VEC["truth"]
        self.assertGreaterEqual(len(truth), 10)
        for wid, t in truth.items():
            self.assertGreater(t["checks"], 0, wid)
            self.assertGreaterEqual(t["min_margin_ns"], 0, wid)

    def test_the_vectors_are_fresh(self):
        with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), gen.render(gen.build()))


if __name__ == "__main__":
    unittest.main()
