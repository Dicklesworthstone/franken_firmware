#!/usr/bin/env python3
"""E05 invariant cases: the six named invariants, hook-presence-is-not-success, planted defects, the
independent checker's own rules on handcrafted traces, and seeded property sweeps.

Each invariant is judged by trace_check.py (which never imports the model).  Every rule is shown to
fire on a planted defect or a handcrafted trace, and to stay quiet on the paired good behaviour.
Case IDs are the docstring prefixes.
"""
import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402

bm, tc = c.bm, c.tc
BENIGN = c.profile("synthetic-benign")
R5723 = c.profile("57.23")
CASES = c.cases()
CELL = {x["id"]: x for x in CASES["cells"]}
ADV = {x["id"]: x for x in CASES["adverse"]}
DEF = {x["id"]: x for x in CASES["defects"]}


def cell(step, kind, **extra):
    d = {"step": step, "kind": kind}
    d.update(extra)
    return d


def defect(did):
    d = DEF[did]
    prof = c.profile(d["profile"])
    res = bm.run_cell(prof, d)
    return d, prof, res, c.violations(res, prof)


def ev(n, boot, step, event, owners=("STOCK",), audible=False, **kw):
    rec = {"n": n, "boot": boot, "step": step, "event": event, "owners": list(owners), "audible": audible}
    rec.update(kw)
    return rec


def trace(events, kind="UNQUALIFIED", depends=(), boots=1, **verdict):
    v = {"kind": kind, "reason": "x", "depends": list(depends)}
    v.update(verdict)
    return {"events": events, "verdict": v, "boots": boots}


class Inv1OneOwner(unittest.TestCase):
    def test_every_safe_cell_has_one_owner_at_a_time(self):
        """E05-INV-1: in every benign cell no event has two owners or audible output with no owner, and each ok verdict ends with exactly one audible owner."""
        for x in CASES["cells"]:
            res = bm.run_cell(BENIGN, x)
            for e in res["events"]:
                self.assertLessEqual(len(e["owners"]), 1, (x["id"], e["event"]))
                self.assertFalse(e["audible"] and not e["owners"], (x["id"], e["event"]))
            last = res["events"][-1]
            if res["verdict"]["kind"] in ("STOCK_OK", "CUSTOM_OK"):
                self.assertTrue(last["audible"], x["id"])
                self.assertEqual(len(last["owners"]), 1, x["id"])

    def test_two_owners_when_stop_is_not_acknowledged(self):
        """E05-INV-1-NEG-ACK: starting custom without the stock-stop acknowledgement shares the device."""
        d, prof, res, viol = defect("E05-DEF-01")
        self.assertEqual(viol, d["expect"]["violations"])
        self.assertIn(["STOCK", "CUSTOM"], [e["owners"] for e in res["events"]])
        good = bm.run_cell(prof, cell(d["step"], d["kind"]))      # same fault, safe policy
        self.assertEqual((good["verdict"]["kind"], c.violations(good, prof)), ("STOCK_OK", []))

    def test_audible_before_ready(self):
        """E05-INV-1-NEG-EARLY: unmuting at start is audible before the binary reports ready."""
        d, prof, res, viol = defect("E05-DEF-02")
        self.assertEqual(viol, d["expect"]["violations"])
        good = bm.run_cell(prof, cell("boot", "none"))
        self.assertEqual((good["verdict"]["kind"], c.violations(good, prof)), ("CUSTOM_OK", []))

    def test_stock_that_will_not_stay_stopped_is_yielded_to(self):
        """E05-INV-1-RESPAWN: if stock respawns after being stopped the launcher yields (STOCK_OK) rather than share the device."""
        res = bm.run_cell(BENIGN, ADV["E05-ADV-06"])
        self.assertEqual(res["verdict"]["reason"], "stock_respawn_detected")
        self.assertEqual(res["events"][-1]["owners"], ["STOCK"])


class Inv2Recovery(unittest.TestCase):
    def test_missing_recovery_path_is_a_failed_case(self):
        """E05-INV-2: with no watchdog coverage or no daemon restart the model reports FAILED(no_recovery_path) and the checker flags it."""
        for aid in ("E05-ADV-03", "E05-ADV-04", "E05-ADV-05"):
            with self.subTest(case=aid):
                a = ADV[aid]
                prof = bm.with_facts(BENIGN, a["facts"])
                res = bm.run_cell(BENIGN, a)
                self.assertEqual((res["verdict"]["kind"], res["verdict"]["reason"]), ("FAILED", "no_recovery_path"))
                self.assertEqual(c.violations(res, prof), ["no_recovery_path"])
                self.assertEqual(res["events"][-1]["owners"], [])          # fail-muted, not silently audible
                self.assertFalse(res["events"][-1]["audible"])

    def test_no_rollback_policy_is_detected(self):
        """E05-INV-2-NEG-ROLLBACK: a launcher with no rollback leaves the unit muted forever; the safe policy recovers from the same fault."""
        d, prof, res, viol = defect("E05-DEF-06")
        self.assertEqual((res["verdict"]["kind"], viol), ("FAILED", ["no_recovery_path"]))
        good = bm.run_cell(prof, cell(d["step"], d["kind"]))
        self.assertEqual((good["verdict"]["kind"], good["verdict"]["reason"], c.violations(good, prof)),
                         ("STOCK_OK", "binary_exit", []))

    def test_every_safe_failure_ends_in_a_defined_state(self):
        """E05-INV-2-TERMINAL: in every benign cell the run ends STOCK_OK or CUSTOM_OK (or the planted in-place write), never stalled or unqualified."""
        for x in CASES["cells"]:
            kind = bm.run_cell(BENIGN, x)["verdict"]["kind"]
            self.assertIn(kind, ("STOCK_OK", "CUSTOM_OK", "FAILED"), x["id"])
            if kind == "FAILED":
                self.assertEqual(x["expect"]["synthetic-benign"]["reason"], "partial_hook_executed")


class Inv3BoundedLoops(unittest.TestCase):
    def test_hung_hook_is_bounded_by_the_attempt_cap(self):
        """E05-INV-3-HANG: a hook that hangs every boot is reset by the watchdog and stops being tried after the cap."""
        res = bm.run_cell(BENIGN, CELL["E05-CELL-08"])
        self.assertEqual((res["boots"], res["verdict"]["reason"]), (4, "attempt_cap"))
        starts = [e["counter"] for e in res["events"] if e["event"] == "hook_started"]
        self.assertEqual(starts, [1, 2, 3])
        self.assertEqual(c.violations(res, BENIGN), [])

    def test_crash_loop_backs_off_stays_silent_then_rolls_back(self):
        """E05-INV-3-CRASH: custom crashing after ready restarts with growing delays, is never audible, and rolls back at the cap with a reason."""
        res = bm.run_cell(BENIGN, CELL["E05-CELL-21"])
        delays = [e["delay"] for e in res["events"] if e["event"] == "restart_scheduled"]
        self.assertEqual(delays, [1, 2])
        self.assertEqual([e for e in res["events"] if e["event"] == "unmuted"], [])
        self.assertEqual((res["verdict"]["kind"], res["verdict"]["reason"]), ("STOCK_OK", "restart_cap"))
        for e in res["events"]:
            if e["event"] in ("custom_crashed", "restart_scheduled", "rollback"):
                self.assertTrue(e.get("reason"), e["event"])
        self.assertEqual(c.violations(res, BENIGN), [])

    def test_loop_with_nothing_to_bound_it_is_detected(self):
        """E05-INV-3-NEG-UNBOUNDED: a fatal unreadable hook is never counted, so the reboot loop is unbounded and reported."""
        a = ADV["E05-ADV-02"]
        prof = bm.with_facts(BENIGN, a["facts"])
        res = bm.run_cell(BENIGN, a)
        self.assertEqual((res["verdict"]["reason"], res["boots"]), ("restart_loop_unbounded", 8))
        self.assertEqual(c.violations(res, prof), ["unbounded_restarts"])

    def test_hot_restart_loop_is_detected(self):
        """E05-INV-3-NEG-HOT: no cap and no backoff restarts at once without end."""
        d, prof, res, viol = defect("E05-DEF-04")
        self.assertEqual(viol, sorted(d["expect"]["violations"]))
        self.assertEqual(res["verdict"]["reason"], "restart_loop_unbounded")

    def test_unmuting_at_ready_repeats_audible_activation(self):
        """E05-INV-3-NEG-AUDIBLE: unmuting at ready makes every crash-loop restart audible; unmuting after stable never does."""
        d, prof, res, viol = defect("E05-DEF-03")
        self.assertEqual(viol, d["expect"]["violations"])
        self.assertEqual(sum(1 for e in res["events"] if e["event"] == "unmuted"), 3)


class Inv4TornWrite(unittest.TestCase):
    def test_atomic_discipline_never_executes_a_half_hook(self):
        """E05-INV-4: under the atomic discipline no write cut yields a partial hook; every cut boots to a defined outcome."""
        for x in CASES["cells"]:
            if x["step"] == "provision" and x["kind"] in bm.PROVISION_SUBS["atomic"]:
                res = bm.run_cell(BENIGN, x)
                self.assertNotIn("hook_partial_executed", [e["event"] for e in res["events"]], x["id"])
                after = [e["hook_after"] for e in res["events"] if e["event"] == "provision_power_loss"]
                self.assertIn(after[0], ("absent", "valid"), x["id"])
                self.assertIn(res["verdict"]["kind"], ("STOCK_OK", "CUSTOM_OK"), x["id"])

    def test_in_place_rewrite_executes_a_half_hook(self):
        """E05-INV-4-NEG-INPLACE: rewriting the hook in place and losing power mid-write runs a partial script; the checker flags it. Paired with the atomic write above."""
        d, prof, res, viol = defect("E05-DEF-05")
        self.assertEqual((res["verdict"]["reason"], viol), ("partial_hook_executed", ["partial_hook_executed"]))
        self.assertEqual(res["events"][-1]["owners"], [])

    def test_non_atomic_rename_defeats_the_atomic_discipline(self):
        """E05-INV-4-FS: if rename is not atomic on the filesystem, even temp-file-then-rename can leave a half hook."""
        a = ADV["E05-ADV-09"]
        res = bm.run_cell(BENIGN, a)
        self.assertEqual(res["verdict"]["reason"], "partial_hook_executed")

    def test_unknown_rename_atomicity_is_unqualified_on_the_real_image(self):
        """E05-INV-4-UNQ: with rename atomicity unknown on 57.23 the atomic-write claim is UNQUALIFIED [EXT-E05-FS], not assumed."""
        v = bm.run_cell(R5723, CELL["E05-CELL-26"])["verdict"]
        self.assertEqual((v["kind"], v["blockers"]), ("UNQUALIFIED", ["EXT-E05-FS"]))


class Inv5Reasons(unittest.TestCase):
    def test_every_path_change_carries_a_reason(self):
        """E05-INV-5: in every benign cell each transition that changes the path, each rollback and the verdict carry a reason; a rollback repeats it as rollback_reason."""
        for x in CASES["cells"]:
            res = bm.run_cell(BENIGN, x)
            self.assertEqual([v for v in tc.check_trace(res, BENIGN) if v["kind"] == "missing_reason"], [], x["id"])
            self.assertTrue(res["events"][-1].get("reason"), x["id"])
            for e in res["events"]:
                if e["event"] == "rollback":
                    self.assertEqual(e["rollback_reason"], e["reason"], x["id"])

    def test_silent_transitions_are_detected(self):
        """E05-INV-5-NEG: a launcher that logs no reasons is flagged on the rollback, its rollback_reason and the verdict."""
        d, prof, res, viol = defect("E05-DEF-07")
        self.assertEqual(viol, ["missing_reason"])
        flagged = [v["detail"] for v in tc.check_trace(res, prof) if v["kind"] == "missing_reason"]
        self.assertTrue(any("rollback carries no rollback_reason" in f for f in flagged))
        self.assertTrue(any(f.startswith("verdict") for f in flagged))


class Inv6UnknownIsNotOk(unittest.TestCase):
    def test_unknown_resolves_to_unqualified_never_ok(self):
        """E05-INV-6: with strict resolution no cell on 57.23 or 86.10 reports an ok verdict that depends on an unknown fact."""
        for prof in (R5723, c.profile("86.10")):
            for x in CASES["cells"]:
                res = bm.run_cell(prof, x)
                if res["verdict"]["kind"] in ("STOCK_OK", "CUSTOM_OK"):
                    for fid in res["verdict"]["depends"]:
                        self.assertEqual(prof["facts"][fid]["status"], "observed", (prof["image"], x["id"]))

    def test_reading_unknown_as_fine_is_detected(self):
        """E05-INV-6-NEG: a resolver that treats an unknown fact as fine reaches CUSTOM_OK on 57.23; the checker flags the dependence."""
        d, prof, res, viol = defect("E05-DEF-09")
        self.assertEqual((res["verdict"]["kind"], viol), ("CUSTOM_OK", ["unknown_resolved_ok"]))
        strict = bm.run_cell(prof, cell("boot", "none"))
        self.assertEqual(strict["verdict"]["kind"], "UNQUALIFIED")

    def test_blockers_name_the_missing_evidence(self):
        """E05-INV-6-BLOCKERS: an UNQUALIFIED verdict lists the unknown facts and their blockers, and the trace ends with an 'unqualified' event."""
        res = bm.run_cell(R5723, cell("boot", "none"))
        v = res["verdict"]
        self.assertEqual((v["facts"], v["blockers"]), (["stock_stop_effective"], ["EXT-E05-STOP"]))
        self.assertEqual(res["events"][-1]["event"], "unqualified")


class PredicatesAreSeparate(unittest.TestCase):
    def claims(self, res):
        return [e["claims"] for e in res["events"] if e["event"] == "status_report"][-1]

    def test_presence_is_not_readable_executed_or_started(self):
        """E05-PRED-SEPARATE: with the hook present and executed but the binary failing, only present/readable/executed hold; exited_ok and service_started do not."""
        res = bm.run_cell(BENIGN, CELL["E05-CELL-18"])
        self.assertEqual(self.claims(res), {"present": True, "readable": True, "executed": True,
                                            "exited_ok": False, "service_started": False})
        names = [e["event"] for e in res["events"]]
        self.assertIn("hook_present", names)
        self.assertNotIn("custom_ready", names)

    def test_each_predicate_is_established_by_its_own_event(self):
        """E05-PRED-SCALE: absent hook claims nothing; a clean boot claims all five."""
        none = self.claims(bm.run_cell(BENIGN, CELL["E05-CELL-03"]))
        self.assertEqual(set(none.values()), {False})
        full = self.claims(bm.run_cell(BENIGN, CELL["E05-CELL-01"]))
        self.assertEqual(set(full.values()), {True})

    def test_predicates_do_not_survive_a_reboot(self):
        """E05-PRED-PER-BOOT: after the attempt cap the last boot never started the hook, so it claims present and readable only."""
        res = bm.run_cell(BENIGN, CELL["E05-CELL-08"])
        self.assertEqual(self.claims(res), {"present": True, "readable": True, "executed": False,
                                            "exited_ok": False, "service_started": False})

    def test_claiming_success_from_presence_is_detected(self):
        """E05-PRED-NEG: a reporter that says 'started' because the hook exists is flagged for the claims it cannot back."""
        d, prof, res, viol = defect("E05-DEF-08")
        self.assertEqual(viol, ["unsupported_claim"])
        detail = " ".join(v["detail"] for v in tc.check_trace(res, prof))
        self.assertIn("exited_ok", detail)
        self.assertIn("service_started", detail)

    def test_no_claim_can_stand_for_installation_access(self):
        """E05-PRED-NO-ACCESS: the vocabulary has no 'writable' or 'installed' claim; asserting one is unsupported by construction."""
        self.assertEqual(set(tc.CLAIM_EVIDENCE), {"present", "readable", "executed", "exited_ok", "service_started"})
        t = trace([ev(0, 1, "hook_gate", "hook_present"),
                   ev(1, 1, "hook_gate", "status_report", claims={"writable": True, "installed": True})])
        self.assertEqual(sorted({v["kind"] for v in tc.check_trace(t, BENIGN)}), ["unsupported_claim"])


class CheckerRules(unittest.TestCase):
    """Each rule of trace_check.py fires on a handcrafted trace and stays quiet on its good twin."""

    def kinds(self, t, prof=BENIGN):
        return sorted({v["kind"] for v in tc.check_trace(t, prof)})

    def test_step_order(self):
        """E05-CHK-ORDER: a later step followed by an earlier one in the same boot is flagged."""
        bad = trace([ev(0, 1, "hook_run", "hook_started"), ev(1, 1, "hook_gate", "hook_present")])
        good = trace([ev(0, 1, "hook_gate", "hook_present"), ev(1, 1, "hook_run", "hook_started")])
        self.assertEqual(self.kinds(bad), ["step_order"])
        self.assertEqual(self.kinds(good), [])
        again = trace([ev(0, 1, "hook_run", "hook_started"), ev(1, 2, "hook_gate", "hook_present")])
        self.assertEqual(self.kinds(again), [])        # a new boot restarts the order

    def test_ownership_rules(self):
        """E05-CHK-OWNERS: two owners, audible with no owner, audible custom before ready, and a wrong terminal owner."""
        self.assertEqual(self.kinds(trace([ev(0, 1, "custom_start", "custom_started", owners=("STOCK", "CUSTOM"))])), ["two_owners"])
        self.assertEqual(self.kinds(trace([ev(0, 1, "custom_start", "x", owners=(), audible=True)])), ["audible_unowned"])
        early = trace([ev(0, 1, "custom_start", "unmuted", owners=("CUSTOM",), audible=True)])
        self.assertEqual(self.kinds(early), ["audible_before_ready"])
        late = trace([ev(0, 1, "custom_ready", "custom_ready", owners=("CUSTOM",)),
                      ev(1, 1, "owner_commit", "unmuted", owners=("CUSTOM",), audible=True)])
        self.assertEqual(self.kinds(late), [])
        wrong = trace([ev(0, 1, "hook_gate", "verdict", owners=(), audible=False, reason="r")], kind="STOCK_OK")
        self.assertEqual(self.kinds(wrong), ["bad_terminal_owner"])
        right = trace([ev(0, 1, "hook_gate", "verdict", owners=("STOCK",), audible=True, reason="r")], kind="STOCK_OK")
        self.assertEqual(self.kinds(right), [])

    def test_loop_rules(self):
        """E05-CHK-LOOPS: restart count, backoff shape, repeated audible activation and boot count bounds."""
        def restarts(delays, boot=1):
            return [ev(i, boot, "owner_commit", "restart_scheduled", reason="r", delay=d) for i, d in enumerate(delays)]
        self.assertEqual(self.kinds(trace(restarts([1, 2, 4, 8, 16]))), [])
        self.assertEqual(self.kinds(trace(restarts([1, 2, 4, 8, 16, 32]))), ["unbounded_restarts"])
        self.assertEqual(self.kinds(trace(restarts([2, 1]))), ["no_backoff"])
        self.assertEqual(self.kinds(trace(restarts([0]))), ["no_backoff"])
        two = trace([ev(0, 1, "owner_commit", "unmuted", owners=("CUSTOM",), audible=True),
                     ev(1, 1, "owner_commit", "unmuted", owners=("CUSTOM",), audible=True)] )
        self.assertIn("repeated_audible_activation", self.kinds(two))
        split = trace([ev(0, 1, "owner_commit", "unmuted", owners=("CUSTOM",), audible=True),
                       ev(1, 2, "owner_commit", "unmuted", owners=("CUSTOM",), audible=True)])
        self.assertNotIn("repeated_audible_activation", self.kinds(split))
        self.assertEqual(self.kinds(trace([], boots=6)), [])
        self.assertEqual(self.kinds(trace([], boots=7)), ["unbounded_restarts"])

    def test_reason_rule_covers_every_path_event(self):
        """E05-CHK-REASONS: each event name in REASON_REQUIRED is flagged without a reason and clean with one."""
        for name in sorted(tc.REASON_REQUIRED):
            bare = trace([ev(0, 1, "hook_gate", name, rollback_reason="r")])
            self.assertIn("missing_reason", self.kinds(bare), name)
            ok = trace([ev(0, 1, "hook_gate", name, reason="r", rollback_reason="r")])
            self.assertNotIn("missing_reason", self.kinds(ok), name)

    def test_claim_rule_covers_every_predicate(self):
        """E05-CHK-CLAIMS: each of the five claims needs its own earlier event in the same boot."""
        for claim, needed in tc.CLAIM_EVIDENCE.items():
            bare = trace([ev(0, 1, "hook_gate", "status_report", claims={claim: True})])
            self.assertEqual(self.kinds(bare), ["unsupported_claim"], claim)
            other_boot = trace([ev(0, 1, "hook_gate", needed), ev(1, 2, "hook_gate", "status_report", claims={claim: True})])
            self.assertEqual(self.kinds(other_boot), ["unsupported_claim"], claim)
            backed = trace([ev(0, 1, "hook_gate", needed), ev(1, 1, "hook_gate", "status_report", claims={claim: True})])
            self.assertEqual(self.kinds(backed), [], claim)

    def test_unknown_dependence_and_partial_hook(self):
        """E05-CHK-UNKNOWN: an ok verdict depending on an unknown fact is flagged, on an observed fact is not; a partial hook event is flagged."""
        dep_unknown = trace([], kind="CUSTOM_OK", depends=["stock_stop_effective"])
        self.assertEqual(self.kinds(dep_unknown, R5723), ["unknown_resolved_ok"])
        dep_known = trace([], kind="CUSTOM_OK", depends=["jffs_noexec"])
        self.assertEqual(self.kinds(dep_known, R5723), [])
        self.assertEqual(self.kinds(trace([], kind="UNQUALIFIED", depends=["stock_stop_effective"]), R5723), [])
        self.assertEqual(self.kinds(trace([ev(0, 1, "hook_run", "hook_partial_executed", reason="r")], kind="FAILED")),
                         ["partial_hook_executed"])


class Properties(unittest.TestCase):
    FLAT = [(s, k) for s, ks in bm.FAULT_TABLE.items() for k in ks]
    SEEDS = range(300)

    @classmethod
    def scenario(cls, seed):
        rng = random.Random(seed)
        picks = rng.sample(cls.FLAT, rng.choice((1, 2, 3)))
        faults = [{"kind": k, "step": s} for s, k in picks]
        kw = {"prior": rng.choice(("absent", "valid"))}
        if rng.random() < 0.25:
            kw["provision"] = rng.choice(bm.PROVISION_SUBS["atomic"])
        return faults, kw

    def test_safe_policy_on_a_benign_image_is_always_clean(self):
        """E05-PROP-SAFE: 300 seeded multi-fault schedules on the benign profile end STOCK_OK/CUSTOM_OK within the boot bound with no violation."""
        for seed in self.SEEDS:
            faults, kw = self.scenario(seed)
            res = bm.simulate(BENIGN, bm.Policy(), faults, **kw)
            where = "seed=%d %s %s" % (seed, faults, kw)
            self.assertIn(res["verdict"]["kind"], ("STOCK_OK", "CUSTOM_OK"), where)
            self.assertLessEqual(res["boots"], 6, where)
            self.assertEqual(c.violations(res, BENIGN), [], where)

    def test_real_image_never_guesses(self):
        """E05-PROP-NO-GUESS: the same 300 schedules on 57.23 are clean, and any ok verdict depends only on observed facts."""
        observed = {f for f, v in R5723["facts"].items() if v["status"] == "observed"}
        unq = 0
        for seed in self.SEEDS:
            faults, kw = self.scenario(seed)
            res = bm.simulate(R5723, bm.Policy(), faults, **kw)
            where = "seed=%d" % seed
            self.assertEqual(c.violations(res, R5723), [], where)
            if res["verdict"]["kind"] == "UNQUALIFIED":
                unq += 1
            else:
                self.assertLessEqual(set(res["verdict"]["depends"]), observed, where)
        self.assertGreater(unq, 0)

    def test_replay_is_deterministic(self):
        """E05-PROP-REPLAY: the same scenario twice gives byte-identical traces."""
        for seed in range(40):
            faults, kw = self.scenario(seed)
            a = json.dumps(bm.simulate(BENIGN, bm.Policy(), faults, **kw), sort_keys=True)
            b = json.dumps(bm.simulate(BENIGN, bm.Policy(), faults, **kw), sort_keys=True)
            self.assertEqual(a, b, seed)

    def test_every_planted_defect_is_caught_by_its_named_rule(self):
        """E05-PROP-DEFECTS: all nine planted defects produce exactly their expected verdict and violation set, each on a rule no other defect covers alone."""
        seen = set()
        for did, d in DEF.items():
            _, _, res, viol = defect(did)
            self.assertEqual((res["verdict"]["kind"], viol), (d["expect"]["verdict"], sorted(d["expect"]["violations"])), did)
            seen |= set(viol)
        self.assertEqual(seen, {"two_owners", "audible_before_ready", "repeated_audible_activation", "no_backoff",
                                "unbounded_restarts", "partial_hook_executed", "no_recovery_path",
                                "missing_reason", "unsupported_claim", "unknown_resolved_ok"})


if __name__ == "__main__":
    unittest.main()
