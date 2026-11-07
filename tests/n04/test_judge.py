#!/usr/bin/env python3
"""Self-test of the N04 judge (tests/n04/run_cases.py).  SYNTHETIC: the logs here are fabricated from the reference's
own expected values to prove the judge qualifies a good log and catches each kind of bad one. They say nothing about
the Rust, which has not been run.

    python3 -B -I -m unittest discover -s tests/n04 -p 'test_judge.py'
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
    spec = importlib.util.spec_from_file_location("n04_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = _load("run_cases")
ref, gen = rc.ref, rc.gen
with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)

CASE_IDS = [c["id"] for c in rc.registry()]
WORLD_IDS = [w["id"] for w in VEC["worlds"]]


def good_records():
    recs = list(rc.expected_records(VEC).values())
    worlds = []
    for w in VEC["worlds"]:
        results = gen.world_results(w)
        has_change = any(o[0] == "change" for o in w["ops"])
        admits = 0 if has_change else sum(1 for o, r in zip(w["ops"], results) if o[0] == "packet" and r.get("r") == "admitted")
        worlds.append({"id": w["id"], "decisions": sum(1 for r in results if r.get("poll") == "decision"), "admits_checked": admits})
    recs.append({"id": "n04-properties", "worlds": worlds})
    for wid in ("W16-SEEDED-MUSIC", "W17-SEEDED-REALTIME"):
        w = next(x for x in VEC["worlds"] if x["id"] == wid)
        recs.append({"id": "n04-accounting-" + wid.lower(), "packets": sum(1 for o in w["ops"] if o[0] == "packet"),
                     "decided": gen.world_results(w)[-1]["cursor"]})
    by_id = {w["id"]: w for w in VEC["worlds"]}
    ops = sum(len(w["ops"]) for w in VEC["worlds"]) + sum(len(by_id[c["world"]]["ops"]) for c in VEC["log_scenarios"])
    recs.append({"id": "n04-log-accounting", "ops_checked": ops, "unaccounted": 0, "critical_over_dropped": 0})
    w16 = by_id["W16-SEEDED-MUSIC"]
    recs.append({"id": "n04-group-clock", "statuses_seen": ["Expired", "Holdover", "Locked"], "holdover_usable": True,
                 "holdover_decision": "pending", "expired_poll": "clock_unusable", "expired_admission": "clock_unusable",
                 "expired_cursor": 0, "unlocked_with_reading_poll": "clock_unusable", "no_reading_poll": "clock_unusable",
                 "uncertainty_locked_ns": 201_300, "uncertainty_holdover_ns": 640_000})
    recs.append({"id": "n04-no-alloc", "probe_active": True, "control_allocations": 1, "construction_allocations": 5,
                 "construction_bytes": 163_000, "measured": {"allocations": 0, "reallocations": 0, "deallocations": 0},
                 "ops": 1100, "decided": 400, "log_emitted": 700, "paths_reached": True})
    recs.append({"id": "n04-capacity", "slot_bytes": 1028, "inline_bytes": 2300, "music_queue_bytes": 96_632, "realtime_queue_bytes": 9_252,
                 "zero_horizon_queue_bytes": 1028, "music_resident_bytes": 98_932, "realtime_resident_bytes": 11_552,
                 "admitted_at_budget": True, "refused_one_byte_short": {"needed_bytes": 98_932, "budget_bytes": 98_931, "code": "capacity"},
                 "config_error_wins_at_zero_budget": "work_ns", "realtime_budget_refuses_music": True})
    recs.append({"id": "n04-log-blocking", "world": "W16-SEEDED-MUSIC", "ops": len(w16["ops"]), "decision_path_offers": 0,
                 "decision_path_virtual_ns": 0, "results_digest": gen.digest(gen.world_results(w16)), "drain_budget": 3,
                 "drain_offers": 3, "drain_virtual_ns": 3_000_000_000, "queued_before_drain_nonzero": True})
    return recs


GOOD = good_records()


def build_log(records, skip_tests=(), failed_tests=(), ignored_tests=(), layout="classic"):
    """A cargo-test log of the same FORM as the real ones. layout "rch": the stdout section first, then the stderr
    ``Running`` header (the shape through RCH)."""
    stems = []
    for case in rc.registry():
        for stem, name in case["tests"]:
            if stem not in stems:
                stems.append(stem)
    lines = ["   Compiling franken-stream v0.1.0", "    Finished `test` profile"]
    headers, bodies = [], []
    bad = set(failed_tests) | set(ignored_tests)
    for stem in stems:
        names = sorted({name for case in rc.registry() for s, name in case["tests"] if s == stem})
        shown = [n for n in names if n.rsplit("::", 1)[-1] not in skip_tests]
        body = ["", "running %d tests" % len(shown)]
        for n in shown:
            bare = n.rsplit("::", 1)[-1]
            body.append("test %s ... %s" % (n, "FAILED" if bare in failed_tests else "ignored" if bare in ignored_tests else "ok"))
        passed = sum(1 for n in shown if n.rsplit("::", 1)[-1] not in bad)
        body += ["", "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s" % passed]
        where = "unittests src/lib.rs" if stem == "franken_stream" else "tests/%s.rs" % stem
        headers.append("     Running %s (.rch-target-w0-pool-0123456789abcdef/debug/deps/%s-0123456789abcdef)" % (where, stem))
        bodies.append(body)
        if layout == "classic":
            lines += [headers[-1]] + body
    if layout != "classic":
        for body in bodies:
            lines += body
        lines += headers
    lines += ["N04-OBSERVED " + json.dumps(r) for r in records]
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
    return {r.case_id: r for r in results}


def tampered(rid, mutate):
    recs = copy.deepcopy(GOOD)
    mutate(next(r for r in recs if r["id"] == rid))
    return recs


def without(rid):
    return [r for r in GOOD if r["id"] != rid]


def op_index(wid, kind, nth=0):
    w = next(x for x in VEC["worlds"] if x["id"] == wid)
    return [i for i, o in enumerate(w["ops"]) if o[0] == kind][nth]


class JudgeTests(unittest.TestCase):
    def statuses(self, results):
        return {cid: results[cid].status for cid in CASE_IDS}

    def test_a_good_log_qualifies_every_rust_backed_case_in_both_layouts(self):
        for layout in ("classic", "rch"):
            with self.subTest(layout=layout):
                results = judge(build_log(GOOD, layout=layout))
                self.assertEqual(set(self.statuses(results).values()), {"pass"}, {c: r.detail for c, r in results.items() if r.status != "pass"
                                                                                  and c in CASE_IDS})

    def test_without_a_log_every_rust_backed_case_is_blocked_never_passed(self):
        results, _ = rc.run("full", None)
        by = {r.case_id: r.status for r in results}
        self.assertEqual({by[c] for c in CASE_IDS}, {"blocked"})
        self.assertEqual(rc.exit_code([r for r in results if r.case_id in CASE_IDS]), 3)

    def test_the_smoke_tier_leaves_out_exactly_the_full_cases(self):
        results = judge(build_log(GOOD), tier="smoke")
        self.assertNotIn("N04-SEEDED", results)
        self.assertIn("N04-ONTIME", results)

    # -- a divergent result is named by operation -------------------------------------------------------------------

    def test_a_flipped_result_fails_its_case_and_names_the_first_divergent_op(self):
        index = op_index("W02-CUTOFF-BOUNDARY", "packet", 1)          # the packet that arrives exactly at the cutoff

        def flip(rec):
            rec["results"][index]["r"] = "admitted"                   # Rust claims it was admitted
        results = judge(build_log(tampered("W02-CUTOFF-BOUNDARY", flip)))
        self.assertEqual(results["N04-CUTOFF-BOUNDARY"].status, "fail")
        self.assertIn("first divergence at op %d" % index, results["N04-CUTOFF-BOUNDARY"].detail)
        self.assertEqual(results["N04-ONTIME"].status, "pass")        # no other case is dragged down
        # The unplanted baseline passes.
        self.assertEqual(judge(build_log(GOOD))["N04-CUTOFF-BOUNDARY"].status, "pass")

    def test_every_kind_of_world_divergence_is_caught(self):
        decide = op_index("W05-BURST-MUSIC", "decide", 12)
        cases = {
            "a concealed block that is not (outcome)": ("W05-BURST-MUSIC", lambda r: r["results"][decide]["d"].update(outcome="real")),
            "a wrong payload (fnv)": ("W01-ONTIME", lambda r: r["results"][op_index("W01-ONTIME", "decide", 3)]["d"].update(fnv="0" * 16)),
            "a gap not reported": ("W12-LATENCY-UP", lambda r: r["results"][op_index("W12-LATENCY-UP", "decide", 10)]["d"].update(gap_before=0)),
            "a counter off by one": ("W04-REORDER-DUPLICATE", lambda r: r["results"][-1]["stats"].update(duplicate=0)),
            "a missing result": ("W07-EPOCH", lambda r: r["results"].pop()),
            "a wrong digest only": ("W10-CLOCK", lambda r: r.update(digest="0" * 64)),
        }
        for label, (wid, mutate) in cases.items():
            with self.subTest(label):
                results = judge(build_log(tampered(wid, mutate)))
                failed = [c for c in CASE_IDS if results[c].status == "fail"]
                self.assertEqual(len(failed), 1, (label, failed))
                self.assertIn(wid, results[failed[0]].detail)

    def test_a_table_row_that_disagrees_with_the_reference_fails(self):
        cases = {
            "N04-CUTOFF-FORMULA": ("n04-frames-to-ns", lambda r: r["rows"][2].__setitem__(1, r["rows"][2][1] + 1)),
            "N04-ADVICE": ("n04-advice", lambda r: r["rows"][5].update(blocks=r["rows"][5]["blocks"] + 1)),
            "N04-LOSS-CONCEAL": ("n04-conceal-blocks", lambda r: r["rows"][0].update(fnv="0" * 16)),
            "N04-PROFILES": ("n04-configs", lambda r: r["rows"][0].update(bad="work_ns")),
            "N04-CUTOFF-BOUNDARY": ("n04-sender-consume-by", lambda r: r.update(cutoff=r["cutoff"] + 1)),
        }
        for case, (rid, mutate) in cases.items():
            with self.subTest(case):
                results = judge(build_log(tampered(rid, mutate)))
                self.assertEqual(results[case].status, "fail", results[case].detail)
                self.assertIn(rid, results[case].detail)

    # -- absence and fabrication -------------------------------------------------------------------------------------

    def test_a_missing_observation_or_test_is_blocked_not_passed(self):
        results = judge(build_log(without("W07-EPOCH")))
        self.assertEqual(results["N04-EPOCH"].status, "blocked")
        self.assertIn("no observation for W07-EPOCH", results["N04-EPOCH"].detail)
        results = judge(build_log(GOOD, skip_tests=("n04_world_w10_clock",)))
        self.assertEqual(results["N04-CLOCK"].status, "blocked")
        results = judge(build_log(GOOD, ignored_tests=("n04_world_w10_clock",)))
        self.assertEqual(results["N04-CLOCK"].status, "blocked")

    def test_a_failed_test_fails_the_case_even_with_a_perfect_observation(self):
        results = judge(build_log(GOOD, failed_tests=("n04_world_w11_overdue",)))
        self.assertEqual(results["N04-OVERDUE"].status, "fail")
        self.assertIn("n04_world_w11_overdue reported FAILED", results["N04-OVERDUE"].detail)

    def test_conflicting_observations_fail_and_identical_repeats_do_not(self):
        other = copy.deepcopy(next(r for r in GOOD if r["id"] == "W01-ONTIME"))
        other["digest"] = "f" * 64
        results = judge(build_log(GOOD) + "N04-OBSERVED " + json.dumps(other) + "\n")
        self.assertEqual(results["N04-ONTIME"].status, "fail")
        self.assertIn("conflicting", results["N04-ONTIME"].detail)
        repeat = "N04-OBSERVED " + json.dumps(next(r for r in GOOD if r["id"] == "W01-ONTIME")) + "\n"
        self.assertEqual(judge(build_log(GOOD) + repeat)["N04-ONTIME"].status, "pass")

    def test_the_same_log_twice_does_not_change_the_denominator(self):
        text = build_log(GOOD)
        results = judge(text, text)
        self.assertEqual(self.statuses(results), self.statuses(judge(text)))

    # -- the property and accounting records must not be thin ----------------------------------------------------------------

    def test_a_thin_property_run_or_wrong_accounting_fails(self):
        def thin(rec):
            rec["worlds"][-1]["decisions"] = 0
        self.assertEqual(judge(build_log(tampered("n04-properties", thin)))["N04-PROPERTIES"].status, "fail")

        def fewer(rec):
            rec["worlds"].pop()
        self.assertEqual(judge(build_log(tampered("n04-properties", fewer)))["N04-PROPERTIES"].status, "fail")

        def no_admits(rec):
            rec["worlds"][0]["admits_checked"] = 0
        self.assertEqual(judge(build_log(tampered("n04-properties", no_admits)))["N04-PROPERTIES"].status, "fail")

        def off(rec):
            rec["decided"] += 1
        results = judge(build_log(tampered("n04-accounting-w16-seeded-music", off)))
        self.assertEqual(results["N04-PROPERTIES"].status, "fail")
        self.assertIn("accounting", results["N04-PROPERTIES"].detail)

    # -- diagnostics: the planted negatives ----------------------------------------------------------------------------------

    def test_a_log_line_that_differs_from_the_reference_is_named(self):
        rid = "n04-log-w02-cutoff-boundary"
        results = judge(build_log(tampered(rid, lambda r: r["delivered_fnv"].__setitem__(3, "0" * 16))))
        self.assertEqual(results["N04-LOG-LINES"].status, "fail")
        self.assertIn("delivered_fnv: line 3", results["N04-LOG-LINES"].detail)
        self.assertEqual(judge(build_log(GOOD))["N04-LOG-LINES"].status, "pass")      # the unplanted baseline

    def test_a_dropped_record_that_goes_uncounted_fails(self):
        # The ring of four with no drain keeps 4 of 7 and drops 3. A Rust that dropped one without counting it would show
        # emitted 7 = delivered 0 + queued 4 + dropped 2 + one unexplained, and fewer lines than the reference.
        rid = "n04-logscn-ls-ring-4-no-drain"
        for label, mutate in {
            "dropped_full one short": lambda r: r["stats"].update(dropped_full=r["stats"]["dropped_full"] - 1),
            "a queued line missing": lambda r: (r["rest_fnv"].pop(), r["stats"].update(queued=r["stats"]["queued"] - 1)),
            "critical loss not counted": lambda r: r["stats"].update(critical_lost=0),
            "evidence claimed complete": lambda r: r.update(complete=True),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered(rid, mutate)))
                self.assertEqual(results["N04-LOG-LOSS"].status, "fail", label)
                self.assertIn(rid, results["N04-LOG-LOSS"].detail)

    def test_a_sink_that_changed_a_decision_fails(self):
        rid = "n04-logscn-ls-flapping-music"
        results = judge(build_log(tampered(rid, lambda r: r.update(results_digest="0" * 64))))
        self.assertEqual(results["N04-LOG-LOSS"].status, "fail")
        self.assertIn("results_digest", results["N04-LOG-LOSS"].detail)

    def test_a_sink_called_on_the_decision_path_fails(self):
        for label, mutate in {
            "an offer on the decision path": lambda r: r.update(decision_path_offers=1),
            "virtual time spent on the decision path": lambda r: r.update(decision_path_virtual_ns=1_000_000_000),
            "a drain that exceeds its budget": lambda r: r.update(drain_offers=4, drain_virtual_ns=4_000_000_000),
            "nothing was queued to offer": lambda r: r.update(queued_before_drain_nonzero=False),
            "a different world": lambda r: r.update(results_digest="0" * 64),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered("n04-log-blocking", mutate)))
                self.assertEqual(results["N04-LOG-NONBLOCKING"].status, "fail", label)
        self.assertEqual(judge(build_log(GOOD))["N04-LOG-NONBLOCKING"].status, "pass")

    def test_a_thin_or_failing_accounting_check_fails(self):
        for label, mutate in {
            "an unaccounted record": lambda r: r.update(unaccounted=1),
            "critical lost above dropped": lambda r: r.update(critical_over_dropped=2),
            "fewer ops checked than the vectors have": lambda r: r.update(ops_checked=r["ops_checked"] - 1),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered("n04-log-accounting", mutate)))
                self.assertEqual(results["N04-LOG-LOSS"].status, "fail", label)

    def test_a_missing_scenario_leaves_its_case_blocked(self):
        results = judge(build_log(without("n04-logscn-ls-unavailable")))
        self.assertEqual(results["N04-LOG-LOSS"].status, "blocked")
        self.assertIn("no observation for n04-logscn-ls-unavailable", results["N04-LOG-LOSS"].detail)
        results = judge(build_log(GOOD, failed_tests=("n04_log_loss_is_counted_when_the_sink_is_slow_full_or_unavailable",)))
        self.assertEqual(results["N04-LOG-LOSS"].status, "fail")

    def test_the_scenarios_cover_each_sink_condition_and_each_loss_path(self):
        by = {c["id"]: c for c in VEC["log_scenarios"]}
        replies = {r for c in VEC["log_scenarios"] for r in c["plan"]["replies"]}
        self.assertEqual(replies, {"taken", "full", "unavailable"})
        self.assertTrue(any(c["stats"]["dropped_oversize"] for c in by.values()), "an oversize drop")
        self.assertTrue(any(c["stats"]["dropped_full"] and c["stats"]["critical_lost"] for c in by.values()), "a critical loss")
        self.assertTrue(any(c["stats"]["dropped_full"] and not c["stats"]["critical_lost"] for c in by.values()), "an ordinary loss")
        self.assertTrue(any(c["stats"]["sink_full_polls"] for c in by.values()))
        self.assertTrue(any(c["stats"]["sink_unavailable_polls"] for c in by.values()))
        self.assertTrue(any(c["stats"]["delivered"] and c["stats"]["queued"] for c in by.values()), "partly drained")
        self.assertTrue(all(c["stats"]["emitted"] == c["stats"]["delivered"] + c["stats"]["queued"] + c["stats"]["dropped_full"]
                            + c["stats"]["dropped_oversize"] for c in by.values()), "the vectors' own counts add up")

    # -- the two dev-only edges: a real clock through the seam, and the allocation probe -------------------------------------

    def test_a_group_clock_observation_that_misses_a_behaviour_fails(self):
        for label, mutate in {
            "expired clock still polled as usable": lambda r: r.update(expired_poll="decision"),
            "expired clock admitted a packet": lambda r: r.update(expired_admission="admitted"),
            "a block was consumed on an unusable clock": lambda r: r.update(expired_cursor=1),
            "holdover refused": lambda r: r.update(holdover_usable=False),
            "holdover never seen": lambda r: r.update(statuses_seen=["Expired", "Locked"]),
            "a constant uncertainty": lambda r: r.update(uncertainty_holdover_ns=r["uncertainty_locked_ns"]),
            "an uncertainty below what one exchange cannot know": lambda r: r.update(uncertainty_locked_ns=1000),
            "an uncertainty above the lock threshold in Holdover": lambda r: r.update(uncertainty_holdover_ns=2_000_001),
            "an unlocked clock with a reading was used": lambda r: r.update(unlocked_with_reading_poll="pending"),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered("n04-group-clock", mutate)))
                self.assertEqual(results["N04-GROUP-CLOCK"].status, "fail", label)
        self.assertEqual(judge(build_log(GOOD))["N04-GROUP-CLOCK"].status, "pass")

    def test_an_engine_that_allocates_or_a_probe_that_is_not_live_fails(self):
        for label, mutate in {
            "one allocation after construction": lambda r: r["measured"].update(allocations=1),
            "one reallocation": lambda r: r["measured"].update(reallocations=1),
            "one free": lambda r: r["measured"].update(deallocations=1),
            "the counting allocator was not active": lambda r: r.update(probe_active=False),
            "the control allocation was not counted": lambda r: r.update(control_allocations=0),
            "construction was not seen": lambda r: r.update(construction_allocations=0, construction_bytes=0),
            "the script was thin": lambda r: r.update(ops=10, decided=2, log_emitted=1),
            "the script missed its paths": lambda r: r.update(paths_reached=False),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered("n04-no-alloc", mutate)))
                self.assertEqual(results["N04-NO-ALLOC"].status, "fail", label)
        self.assertEqual(judge(build_log(GOOD))["N04-NO-ALLOC"].status, "pass")

    def test_a_capacity_observation_that_breaks_a_rule_fails(self):
        for label, mutate in {
            "a slot of 1032 bytes": lambda r: r.update(slot_bytes=1032),
            "a music queue of 94 x 1024": lambda r: r.update(music_queue_bytes=96_256),
            "a realtime queue that is one slot short": lambda r: r.update(realtime_queue_bytes=8_224),
            "a zero horizon that builds no slot": lambda r: r.update(zero_horizon_queue_bytes=0),
            "a resident size that leaves out the struct": lambda r: r.update(music_resident_bytes=r["music_queue_bytes"]),
            "an engine struct smaller than what it holds": lambda r: r.update(
                inline_bytes=1000, music_resident_bytes=1000 + r["music_queue_bytes"], realtime_resident_bytes=1000 + r["realtime_queue_bytes"]),
            "an engine refused at its exact budget": lambda r: r.update(admitted_at_budget=False),
            "a refusal at the budget instead of one byte short": lambda r: r["refused_one_byte_short"].update(budget_bytes=r["music_resident_bytes"]),
            "a refusal that names no needed bytes": lambda r: r["refused_one_byte_short"].update(needed_bytes=0),
            "a refusal that is not the capacity code": lambda r: r["refused_one_byte_short"].update(code="work_ns"),
            "the budget judged before the configuration": lambda r: r.update(config_error_wins_at_zero_budget="capacity"),
            "a smaller profile substituted for the one that did not fit": lambda r: r.update(realtime_budget_refuses_music=False),
        }.items():
            with self.subTest(label):
                results = judge(build_log(tampered("n04-capacity", mutate)))
                self.assertEqual(results["N04-CAPACITY"].status, "fail", label)
        self.assertEqual(judge(build_log(GOOD))["N04-CAPACITY"].status, "pass")

    def test_the_probe_binary_is_attributed_by_its_own_header_in_both_layouts(self):
        for layout in ("classic", "rch"):
            with self.subTest(layout=layout):
                results = judge(build_log(GOOD, layout=layout, skip_tests=("n04_playout_engine_consume_path_does_not_allocate_after_construction",)))
                self.assertEqual(results["N04-NO-ALLOC"].status, "blocked")
                self.assertEqual(results["N04-GROUP-CLOCK"].status, "pass")

    # -- meta ---------------------------------------------------------------------------------------------------------------

    def test_meta_checks_pass_on_the_committed_vectors(self):
        meta = {r.case_id: r for r in rc.meta_results(VEC, "")}
        for cid in ("N04-META-ANCHORS", "N04-META-VECTORS-FRESH", "N04-META-WORLDS-ALL-JUDGED", "N04-META-MAP-COMPLETE"):
            self.assertEqual(meta[cid].status, "pass", meta[cid].detail)

    def test_meta_catches_a_stale_vector_file_and_an_unjudged_world(self):
        stale = copy.deepcopy(VEC)
        stale["worlds"][0]["ops"][1][1] += 1
        self.assertEqual({r.case_id: r.status for r in rc.meta_results(stale, "")}["N04-META-VECTORS-FRESH"], "fail")
        extra = copy.deepcopy(VEC)
        extra["worlds"].append(dict(extra["worlds"][0], id="W99-UNJUDGED"))
        meta = {r.case_id: r for r in rc.meta_results(extra, "")}
        self.assertEqual(meta["N04-META-WORLDS-ALL-JUDGED"].status, "fail")
        self.assertIn("W99-UNJUDGED", meta["N04-META-WORLDS-ALL-JUDGED"].detail)

    def test_every_case_id_is_unique_and_every_world_has_a_case(self):
        self.assertEqual(len(CASE_IDS), len(set(CASE_IDS)))
        judged = {oid for c in rc.registry() for oid in c["observed"]}
        self.assertEqual(set(WORLD_IDS) - judged, set())


if __name__ == "__main__":
    unittest.main()
