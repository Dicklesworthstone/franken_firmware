#!/usr/bin/env python3
"""Self-test of the D03 judge (tests/d03/run_cases.py).  SYNTHETIC: the logs here are fabricated from the
reference's own expected values to prove the judge qualifies a good log and catches each kind of bad one.
They say nothing about the Rust, which has not been run.

    python3 -B -I -m unittest discover -s tests/d03 -p 'test_judge.py'
"""
import copy
import importlib.util
import json
import math
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("d03_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = _load("run_cases")
with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as _fh:
    VEC = json.load(_fh)


def good_records():
    recs = []
    for t in VEC["tones"]:
        recs.append({"id": t["id"], "kind": "tone", "snr_db": t["snr_floor_db"] + 5.0, "freq_dev_hz": 0.0,
                     "consumed": t["expect_inputs_pulled"], "produced": t["n_out"]})
    for e in VEC["estimator"]:
        recs.append({"id": e["id"], "kind": "estimator", "ratio_ppb": e["expect_ratio_ppb"],
                     "uncertainty_ppb": math.ceil(e["expect_uncertainty_ppb"]), "status": e["status"],
                     "correction_ppb": e["correction_ppb"], "wraps": e["expect_wraps"]})
    for d in VEC["discontinuities"]:
        recs.append({"id": d["id"], "kind": "discontinuity", "reason": d["reason"], "dropped": 16, "to_epoch": 1})
    longest = max(VEC["pulled"], key=lambda p: (p["n_out"], p["ppb"]))
    recs.append({"id": "d03-pulled-longest", "kind": "count", "ppb": longest["ppb"], "n_out": longest["n_out"],
                 "pulled": longest["expect_inputs_pulled"]})
    recs.append({"id": "d03-slew-bound", "kind": "slew", "max_change_per_256_ppb": 2000, "max_step_ppb": 250})
    recs.append({"id": "d03-history-ramp", "kind": "history", "max_abs_error": 1e-7})
    recs.append({"id": "d03-split-invariance", "kind": "split", "outputs": 12000, "splits_compared": 8})
    p = VEC["params"]
    recs.append({"id": "d03-ops", "kind": "ops", "float_ops_per_output_frame": p["float_ops_per_output_frame"],
                 "float_ops_per_256_block": 256 * p["float_ops_per_output_frame"],
                 "cpu_on_target": "not measured: needs BE guest or hardware"})
    for c in VEC["closed_loop"]:
        recs.append({"id": c["id"], "kind": "closed_loop", "controlled": True,
                     "max_deviation_frames": c["occupancy_bound_frames"] // 2, "bound_frames": c["occupancy_bound_frames"],
                     "underruns": 0, "final_ratio_ppb": c["drift_ppb"], "drift_ppb": c["drift_ppb"], "wraps": c["expect_wraps"],
                     "outputs": c["expect_total_outputs"], "inputs_pulled": 1, "estimator_discontinuities": 0, "resets": 0,
                     "virtual_seconds": c["virtual_seconds"]})
    j = VEC["closed_loop_jump"]
    recs.append({"id": j["id"], "kind": "closed_loop", "controlled": True, "max_deviation_frames": 10,
                 "bound_frames": j["occupancy_bound_frames"], "underruns": 0, "final_ratio_ppb": j["drift_ppb"],
                 "drift_ppb": j["drift_ppb"], "wraps": 0, "outputs": j["expect_total_outputs"], "inputs_pulled": 1,
                 "estimator_discontinuities": 1, "resets": j["expect_resets"], "virtual_seconds": j["virtual_seconds"]})
    first = VEC["closed_loop"][0]
    recs.append({"id": "d03-loop-uncontrolled", "kind": "closed_loop", "controlled": False,
                 "max_deviation_frames": 10 * first["occupancy_bound_frames"], "bound_frames": first["occupancy_bound_frames"],
                 "underruns": 0, "final_ratio_ppb": 0, "drift_ppb": first["drift_ppb"], "wraps": 0,
                 "outputs": first["expect_total_outputs"], "inputs_pulled": 1, "estimator_discontinuities": 0, "resets": 0,
                 "virtual_seconds": first["virtual_seconds"]})
    recs += quality_records()
    return recs


def quality_records():
    """What a correct Rust run would print for the quality cases: the reference's own predictions."""
    q = VEC["quality"]
    recs = []
    for c in q["cases"]:
        qd = c["expect_q_db"] if c["expect_q_db"] <= q["q_cap_db"] else q["q_cap_db"] + 30.0
        g = c["expect_gain_db"]
        meets = qd >= c["band_q_db"] and (g is None or c["gain_lo_db"] <= g <= c["gain_hi_db"])
        recs.append({"id": c["id"], "kind": "quality", "interp": c["interp"], "scenario": c["scenario"],
                     "f0_hz": c["f0_hz"], "ppb": c["ppb"], "q_db": qd, "gain_db": g, "band_q_db": c["band_q_db"],
                     "gain_lo_db": c["gain_lo_db"], "gain_hi_db": c["gain_hi_db"], "meets_band": meets})
    by_id = {c["id"]: c for c in q["cases"]}
    for c in q["cases"]:
        if c["must_pass"]:
            continue
        real = next(r for r in q["cases"] if r["scenario"] == "steady" and r["interp"] == "catmull_rom"
                    and r["f0_hz"] == c["f0_hz"] and r["ppb"] == c["ppb"])
        recs.append({"id": c["id"] + "-pair", "kind": "quality_pair", "plant_id": c["id"], "real_id": real["id"],
                     "plant_q_db": c["expect_q_db"], "real_q_db": real["expect_q_db"],
                     "plant_gain_db": c["expect_gain_db"], "real_gain_db": real["expect_gain_db"]})
    assert by_id
    return recs


def build_log(records, skip_tests=(), failed_tests=(), ignored_tests=(), layout="classic", only_stems=None,
              extra_sections=()):
    """A cargo-test log of the same FORM as the real ones (worker id and pool hash invented).

    layout "classic": each ``Running`` header is immediately followed by its own section (plain cargo).
    layout "rch": the shape seen through RCH: the stdout sections come first and the stderr ``Running``
    headers arrive afterwards, in the same order (b6d's dsp.log has its sections at lines 29-72 and its
    two headers at lines 63-64).  ``extra_sections`` are header-less sections (tuples of test names),
    which break the header/section pairing.
    """
    by_stem = {}
    for case in rc.registry(VEC):
        for stem, name in case["tests"]:
            by_stem.setdefault(stem, []).append(name)
    sections = []                                     # (header, stdout lines)
    for stem, names in by_stem.items():
        if only_stems is not None and stem not in only_stems:
            continue
        shown = [n for n in names if n.rsplit("::", 1)[-1] not in skip_tests]   # registry names carry a module prefix
        body = ["", "running %d test%s" % (len(shown), "" if len(shown) == 1 else "s")]
        for n in shown:
            bare = n.rsplit("::", 1)[-1]
            status = "FAILED" if bare in failed_tests else "ignored" if bare in ignored_tests else "ok"
            body.append("test %s ... %s" % (n, status))
        not_passing = set(failed_tests) | set(ignored_tests)
        passed = sum(1 for n in shown if n.rsplit("::", 1)[-1] not in not_passing)
        body += ["", "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s" % passed]
        header = "     Running tests/x.rs (.rch-target-w0-pool-0123456789abcdef/debug/deps/%s-0123456789abcdef)" % stem
        sections.append((header, body))
    for names in extra_sections:
        body = ["", "running %d tests" % len(names)] + ["test %s ... ok" % n for n in names]
        body += ["", "test result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s" % len(names)]
        sections.append((None, body))
    lines = ["   Compiling franken-xx v0.1.0", "    Finished `test` profile"]
    if layout == "classic":
        for header, body in sections:
            lines += ([header] if header else []) + body
    else:
        for _, body in sections:
            lines += body
        lines += [h for h, _ in sections if h]
    lines += ["D03-OBSERVED " + json.dumps(r) for r in records]
    return "\n".join(lines) + "\n"


def judge(*texts, tier="soak"):
    """Judge one or more logs (each text is a separate file)."""
    with tempfile.TemporaryDirectory() as d:
        logs = rc.Logs()
        for i, text in enumerate(texts):
            path = os.path.join(d, "cargo%d.log" % i)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            logs.add(path)
        results, _ = rc.run(tier, logs)
    return {r.case_id: r for r in results}, results


class JudgeSelfTest(unittest.TestCase):
    def test_a_good_log_qualifies_at_every_tier(self):
        """D03-JUDGE-GOOD: a complete, correct log qualifies smoke, full and soak, in either log layout."""
        for layout in ("classic", "rch"):
            for tier in rc.TIERS:
                _, results = judge(build_log(good_records(), layout=layout), tier=tier)
                self.assertEqual(rc.exit_code(results), 0, (layout, tier, [r.as_dict() for r in results if r.status != "passed"]))

    def test_rch_header_order_is_attributed_by_ordinal_pairing(self):
        """D03-JUDGE-RCH-ORDER: with every Running header AFTER the stdout sections (as RCH writes them, the
        shape that left 9 cases blocked), tests are still attributed to the right binary and all cases pass."""
        text = build_log(good_records(), layout="rch")
        lines = text.splitlines()
        first_test = next(i for i, l in enumerate(lines) if l.startswith("test "))
        first_header = next(i for i, l in enumerate(lines) if "Running tests" in l)
        self.assertLess(first_test, first_header, "fixture must put the headers after the sections")
        by, results = judge(text, tier="soak")
        self.assertEqual(rc.exit_code(results), 0, [r.as_dict() for r in results if r.status != "passed"])
        self.assertEqual(by["D03-SPECTRA"].status, "passed")

    def test_the_rch_fixture_reproduces_the_original_defect(self):
        """D03-JUDGE-FIXTURE: the fixture is only worth having if the old attribution fails on it. A parser that
        gives each test to the nearest PRECEDING Running header gets every test right in the classic layout and
        none right in the RCH layout, which is what left 9 cases blocked on a green central run."""
        running = re.compile(r"Running .*\(.*?([A-Za-z0-9_]+)-[0-9a-f]{6,}\)")
        test_line = re.compile(r"\btest (\S+) \.\.\. (ok|FAILED|ignored)\b")

        def nearest_preceding_header(text):
            stem, seen = None, set()
            for line in text.splitlines():
                m = running.search(line)
                if m:
                    stem = m.group(1)
                    continue
                t = test_line.search(line)
                if t:
                    seen.add((stem, t.group(1)))
            return seen

        want = {(s, n) for case in rc.registry(VEC) for s, n in case["tests"]}
        self.assertEqual(len(want), 50)
        self.assertEqual(want - nearest_preceding_header(build_log(good_records(), layout="classic")), set())
        self.assertEqual(want & nearest_preceding_header(build_log(good_records(), layout="rch")), set())

    def test_rch_order_still_blocks_a_genuinely_missing_test(self):
        """D03-JUDGE-RCH-STRICT: the ordinal pairing must not make the judge lenient: a test that is really
        missing stays BLOCKED, a failed one FAILS, in the RCH layout."""
        text = build_log(good_records(), layout="rch", skip_tests={"d03_history_is_carried_across_short_blocks_exactly"})
        by, results = judge(text, tier="full")
        self.assertEqual(by["D03-HISTORY"].status, "blocked")
        self.assertEqual(rc.exit_code(results), 3)
        by, results = judge(build_log(good_records(), layout="rch", failed_tests={"d03_plan_equals_render"}), tier="full")
        self.assertEqual(by["D03-COUNTS"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)

    def test_an_ambiguous_test_name_stays_blocked(self):
        """D03-JUDGE-AMBIGUOUS: a name that appears in two sections, when headers cannot be paired to sections,
        cannot be attributed to a binary; the case is blocked, not passed."""
        dup = ("resample::tests::d03_tone_quality_matches_independent_reference",)
        by, results = judge(build_log(good_records(), layout="rch", extra_sections=[dup]), tier="full")
        self.assertEqual(by["D03-SPECTRA"].status, "blocked", by["D03-SPECTRA"].detail)
        self.assertEqual(rc.exit_code(results), 3)

    def test_ignored_in_one_log_and_ok_in_another_is_not_a_conflict(self):
        """D03-JUDGE-IGNORED: the soak test is ignored in a normal run and ok under --ignored. That must
        pass (in either order); ignored alone is blocked; ok against FAILED is a conflict."""
        soak = {"d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap"}
        recs = good_records()
        normal = build_log([r for r in recs if r["id"] != "d03-loop-25h-soak"], layout="rch", ignored_tests=soak)
        only_soak = build_log([r for r in recs if r["id"] == "d03-loop-25h-soak"], layout="rch",
                              only_stems={"d03_closed_loop"}, skip_tests={n.rsplit("::", 1)[-1] for case in rc.registry(VEC)
                                                                          for s, n in case["tests"]
                                                                          if s == "d03_closed_loop"} - soak)
        for texts in ((normal, only_soak), (only_soak, normal)):
            by, results = judge(*texts, tier="soak")
            self.assertEqual(by["D03-LOOP-SOAK"].status, "passed", by["D03-LOOP-SOAK"].detail)
            self.assertEqual(rc.exit_code(results), 0, [r.as_dict() for r in results if r.status != "passed"])
        by, _ = judge(normal, tier="soak")
        self.assertEqual(by["D03-LOOP-SOAK"].status, "blocked")
        self.assertIn("ignored", by["D03-LOOP-SOAK"].detail)

    def test_conflicting_statuses_and_observations_fail(self):
        """D03-JUDGE-CONFLICT: two logs that disagree (ok vs FAILED; two different values for one record)
        fail the owning case and the log-consistency check. An identical repeat, or the same log twice, does not
        change the denominator or the verdict."""
        good = build_log(good_records(), layout="rch")
        by, results = judge(good, build_log(good_records(), layout="rch", failed_tests={"d03_plan_equals_render"}), tier="full")
        self.assertEqual(by["D03-COUNTS"].status, "failed")
        self.assertEqual(by["D03-META-LOGS-CONSISTENT"].status, "failed")
        recs = self.mutate("d03-slew-bound", max_change_per_256_ppb=1000)
        by, results = judge(good, build_log(recs, layout="rch"), tier="full")
        self.assertEqual(by["D03-SLEW"].status, "failed")
        self.assertEqual(by["D03-META-LOGS-CONSISTENT"].status, "failed")
        by_once, res_once = judge(good, tier="full")
        by_twice, res_twice = judge(good, good, tier="full")
        self.assertEqual(len(res_once), len(res_twice), "a repeated log must not add cases")
        self.assertEqual(rc.exit_code(res_twice), 0)
        self.assertEqual(by_twice["D03-META-LOGS-CONSISTENT"].status, "passed")

    def test_no_log_blocks_every_rust_backed_case(self):
        """D03-JUDGE-BLOCKED: without a log nothing Rust-backed passes."""
        results, _ = rc.run("full", None)
        blocked = [r for r in results if r.status == "blocked"]
        self.assertGreaterEqual(len(blocked), 17)
        self.assertEqual(rc.exit_code(results), 3)

    def test_a_failed_rust_test_fails_its_case(self):
        """D03-JUDGE-FAILED-TEST: one FAILED test fails exactly the case that owns it."""
        by, results = judge(build_log(good_records(), failed_tests={"d03_plan_equals_render"}), tier="full")
        self.assertEqual(by["D03-COUNTS"].status, "failed")
        self.assertEqual(rc.exit_code(results), 1)
        self.assertEqual(by["D03-SLEW"].status, "passed")

    def test_a_missing_test_blocks_not_passes(self):
        """D03-JUDGE-MISSING-TEST: a test that never ran is blocked, never passed."""
        by, _ = judge(build_log(good_records(), skip_tests={"d03_history_is_carried_across_short_blocks_exactly"}), tier="full")
        self.assertEqual(by["D03-HISTORY"].status, "blocked")

    def mutate(self, rid, **changes):
        recs = good_records()
        for r in recs:
            if r["id"] == rid:
                r.update(changes)
        return recs

    def test_each_kind_of_wrong_observation_is_caught(self):
        """D03-JUDGE-BAD-RECORDS: tampering with an observed value fails the owning case."""
        t0, e0, c0 = VEC["tones"][0], VEC["estimator"][0], VEC["closed_loop"][0]
        cases = [
            ("SNR below floor", t0["id"], dict(snr_db=t0["snr_floor_db"] - 1), "D03-SPECTRA"),
            ("frequency off", t0["id"], dict(freq_dev_hz=t0["freq_tol_hz"] * 3), "D03-SPECTRA"),
            ("input count off by one", t0["id"], dict(consumed=t0["expect_inputs_pulled"] + 1), "D03-SPECTRA"),
            ("ratio off by one ppb", e0["id"], dict(ratio_ppb=e0["expect_ratio_ppb"] + 1), "D03-RATIO-DRIFT"),
            ("wrong status", e0["id"], dict(status="Clamped" if e0["status"] != "Clamped" else "Valid"), "D03-RATIO-DRIFT"),
            ("wrong reason", VEC["discontinuities"][0]["id"], dict(reason="PositionJump"), "D03-DISCONTINUITY"),
            ("pulled count off", "d03-pulled-longest", dict(pulled=1), "D03-COUNTS"),
            ("slew too fast", "d03-slew-bound", dict(max_change_per_256_ppb=2001), "D03-SLEW"),
            ("history error", "d03-history-ramp", dict(max_abs_error=1e-3), "D03-HISTORY"),
            ("too few splits", "d03-split-invariance", dict(splits_compared=3), "D03-SHORT-BLOCKS"),
            ("ops claimed measured", "d03-ops", dict(cpu_on_target="1.2 ms"), "D03-DIAGNOSTICS"),
            ("queue past bound", c0["id"], dict(max_deviation_frames=c0["occupancy_bound_frames"] + 1), "D03-LOOP-FAST"),
            ("underrun", c0["id"], dict(underruns=1), "D03-LOOP-FAST"),
            ("output count off", c0["id"], dict(outputs=c0["expect_total_outputs"] - 256), "D03-LOOP-FAST"),
            ("ratio never converged", c0["id"], dict(final_ratio_ppb=0), "D03-LOOP-FAST"),
            ("wrap undetected", VEC["closed_loop"][2]["id"], dict(wraps=0), "D03-LOOP-WRAP"),
            ("reset on clean data", c0["id"], dict(resets=1), "D03-LOOP-FAST"),
            ("uncontrolled stayed in bound", "d03-loop-uncontrolled", dict(max_deviation_frames=1), "D03-LOOP-UNCONTROLLED"),
            ("jump not reset", "d03-loop-jump", dict(resets=0), "D03-LOOP-JUMP"),
        ]
        for label, rid, change, case in cases:
            with self.subTest(label):
                by, results = judge(build_log(self.mutate(rid, **change), layout="rch"), tier="soak")
                self.assertEqual(by[case].status, "failed", (label, by[case].detail))
                self.assertEqual(rc.exit_code(results), 1)

    def test_a_real_kernel_that_misses_a_declared_band_fails_and_the_band_does_not_move(self):
        """D03-JUDGE-QUALITY-MISS: a figure under its band is reported as a failure; so is a record that lowers the
        band it was judged against, or that claims a verdict its own figures do not support."""
        q = VEC["quality"]
        c1 = next(c for c in q["cases"] if c["id"] == "q-steady-1000-p500")
        c10 = next(c for c in q["cases"] if c["id"] == "q-steady-10000-m100")
        cases = [
            ("1 kHz Q under the floor", c1["id"], dict(q_db=c1["band_q_db"] - 0.5, meets_band=False)),
            ("10 kHz Q under the floor", c10["id"], dict(q_db=c10["band_q_db"] - 0.5, meets_band=False)),
            ("10 kHz gain outside its band", c10["id"], dict(gain_db=c10["gain_lo_db"] - 0.2, meets_band=False)),
            ("Q far from the first-principles prediction", c1["id"], dict(q_db=c1["expect_q_db"] + 2.0)),
            ("the band lowered in the record", c1["id"], dict(band_q_db=c1["band_q_db"] - 10.0)),
            ("a verdict the figures do not support", c1["id"], dict(meets_band=False)),
            ("no Q figure", c1["id"], dict(q_db=None)),
        ]
        for label, rid, change in cases:
            with self.subTest(label):
                by, results = judge(build_log(self.mutate(rid, **change), layout="rch"), tier="full")
                self.assertEqual(by["D03-QUALITY"].status, "failed", (label, by["D03-QUALITY"].detail))
                self.assertEqual(rc.exit_code(results), 1)

    def test_a_planted_interpolator_that_meets_the_band_is_caught_and_a_clear_miss_is_not(self):
        """D03-JUDGE-QUALITY-PLANT: a plant must miss on Q by 3 dB or on gain by 0.1 dB. The 10 kHz linear plant
        clears the Q floor by 0.3 dB and is rejected on gain: it must pass the judge as a plant, and fail it the moment
        its gain also sits inside the band."""
        q = VEC["quality"]
        lin = next(c for c in q["cases"] if c["id"] == "q-linear-10000-p100")
        self.assertGreaterEqual(lin["expect_q_db"], lin["band_q_db"], "the erratum: Q alone does not reject this plant")
        self.assertLess(lin["expect_gain_db"], lin["gain_lo_db"] - q["plant_gain_margin_db"])
        by, _ = judge(build_log(good_records(), layout="rch"), tier="full")
        self.assertEqual(by["D03-QUALITY-NEGATIVE"].status, "passed", by["D03-QUALITY-NEGATIVE"].detail)
        for label, rid, change in [
            ("a plant that meets both figures", lin["id"], dict(gain_db=-0.1, meets_band=True)),
            ("a plant that misses by less than the margin", "q-nearest-10000-p500",
             dict(q_db=21.0, gain_db=-0.2, meets_band=False)),
            ("a plant with no Q figure", "q-linear-1000-p100", dict(q_db=None)),
        ]:
            with self.subTest(label):
                by, results = judge(build_log(self.mutate(rid, **change), layout="rch"), tier="full")
                self.assertEqual(by["D03-QUALITY-NEGATIVE"].status, "failed", (label, by["D03-QUALITY-NEGATIVE"].detail))

    def test_a_pair_whose_real_kernel_misses_is_caught(self):
        """D03-JUDGE-QUALITY-PAIR: the plant's miss only counts if the real kernel meets the band beside it."""
        recs = good_records()
        pair = next(r for r in recs if r["kind"] == "quality_pair")
        pair["real_q_db"] = 10.0
        by, _ = judge(build_log(recs, layout="rch"), tier="full")
        self.assertEqual(by["D03-QUALITY-NEGATIVE"].status, "failed")

    def test_at_zero_ratio_a_plant_must_pass_because_every_interpolator_is_exact(self):
        """D03-JUDGE-QUALITY-CONTROL: the 0 ppm rows are controls; one that does not read as exact fails."""
        by, _ = judge(build_log(self.mutate("q-linear-10000-0", q_db=15.0, meets_band=False), layout="rch"), tier="full")
        self.assertEqual(by["D03-QUALITY-NEGATIVE"].status, "failed")

    def test_a_missing_quality_record_blocks(self):
        recs = [r for r in good_records() if r["id"] != "q-slewed-1000"]
        by, _ = judge(build_log(recs, layout="rch"), tier="full")
        self.assertEqual(by["D03-QUALITY"].status, "blocked")

    def test_a_band_edited_in_the_contract_without_a_new_row_fails_the_meta_check(self):
        """D03-JUDGE-BANDS-FROZEN: the declared table, the reference and the vectors must agree; moving one of them
        alone (the move the declaration forbids) is a META failure."""
        with open(rc.CONTRACT, encoding="utf-8") as fh:
            text = fh.read()
        moved = text.replace("| 10000 | 22.0 | -0.60 | 0.05 |", "| 10000 | 18.0 | -0.60 | 0.05 |")
        self.assertNotEqual(moved, text)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "d03.md")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(moved)
            saved, rc.CONTRACT = rc.CONTRACT, path
            try:
                results, _ = rc.run("smoke", None)
            finally:
                rc.CONTRACT = saved
        by = {r.case_id: r for r in results}
        self.assertEqual(by["D03-META-BANDS-DECLARED"].status, "failed")
        by_ok = {r.case_id: r for r in rc.run("smoke", None)[0]}
        self.assertEqual(by_ok["D03-META-BANDS-DECLARED"].status, "passed")

    def test_a_missing_record_is_blocked_and_an_identical_repeat_is_harmless(self):
        """D03-JUDGE-RECORD-INTEGRITY: no record -> blocked; an identical repeated record -> ignored."""
        recs = [r for r in good_records() if r["id"] != "d03-history-ramp"]
        by, _ = judge(build_log(recs), tier="full")
        self.assertEqual(by["D03-HISTORY"].status, "blocked")
        recs = good_records() + [copy.deepcopy(good_records()[0])]
        by, results = judge(build_log(recs), tier="full")
        self.assertEqual(by["D03-META-LOGS-CONSISTENT"].status, "passed")
        self.assertEqual(rc.exit_code(results), 0)

    def test_soak_case_is_required_only_in_the_soak_tier(self):
        """D03-JUDGE-TIERS: the 25.5-hour case is not required below the soak tier and is when asked for."""
        recs = [r for r in good_records() if r["id"] != "d03-loop-25h-soak"]
        skip = {"d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap"}
        by_full, res_full = judge(build_log(recs, skip_tests=skip), tier="full")
        self.assertNotIn("D03-LOOP-SOAK", by_full)
        self.assertEqual(rc.exit_code(res_full), 0)
        by_soak, res_soak = judge(build_log(recs, skip_tests=skip), tier="soak")
        self.assertEqual(by_soak["D03-LOOP-SOAK"].status, "blocked")
        self.assertEqual(rc.exit_code(res_soak), 3)

    def test_cpu_is_always_reported_as_not_measured(self):
        """D03-JUDGE-CPU: the not-measured line is part of every report and receipt."""
        self.assertEqual(rc.NOT_MEASURED[0]["status"], "not measured: needs BE guest or hardware")
        with tempfile.TemporaryDirectory() as d:
            results, meta = rc.run("smoke", None)
            path = rc.write_receipt(d, "smoke", results, meta, None)
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertEqual(doc["not_measured"][0]["status"], "not measured: needs BE guest or hardware")
        self.assertEqual(doc["evidence_class"], "host-simulation")


if __name__ == "__main__":
    unittest.main()
