#!/usr/bin/env python3
"""D03 (ffw-j9r) end-to-end runner and judge.

    run_cases.py [--tier smoke|full|soak] [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds and boots nothing.

* META  - the reference agrees with itself (anchors.py), the committed vectors.json equals a fresh
          generation, every Rust ``d03_`` test in the sources is mapped to a named case, and the
          contract names every case.
* JUDGE - reads the ``cargo test`` output of the centrally run Rust suites (``--judge LOG``). Every
          required Rust test must report ``ok`` AND every ``D03-OBSERVED`` record is re-checked here
          against the independent reference (SNR floor, frequency tolerance, exact counts, occupancy
          bound, final ratio, discontinuity reason), so a loosened assertion in the Rust cannot hide.

A case with no Rust observation is ``blocked``: counted, named, and the run is not qualified. It is
never passed and never dropped. CPU time on the target ISA cannot be measured here and is reported as
``not measured: needs BE guest or hardware`` with the per-block operation count instead.

The Rust suites run only through the centralized RCH path:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-dsp resample -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-clock -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-speaker --test d03_closed_loop -- --nocapture
    # soak tier (25.5 virtual hours, ignored by default):
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-speaker --test d03_closed_loop -- --ignored --nocapture

The franken-clock estimator and the franken-speaker closed-loop test are held out of the build until the first
green compile (docs/contracts/d03.md section 8); until they are wired their cases stay blocked.

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(HERE, "vectors.json")
CONTRACT = os.path.join(REPO, "docs", "contracts", "d03.md")
TIERS = ("smoke", "full", "soak")
RECEIPT_SCHEMA = "ffw.d03.receipt.v1"
MAX_PRINTED = 12
NOT_MEASURED = [{"item": "cpu_on_target_isa", "status": "not measured: needs BE guest or hardware",
                 "recorded_instead": "float operations per output frame and per 256-frame block"}]

# (path, binary stem, module prefix in cargo's test names)
RUST_SOURCES = [
    ("crates/franken-clock/src/rate.rs", "franken_clock", "rate::tests::"),
    ("crates/franken-dsp/src/resample/tests.rs", "franken_dsp", "resample::tests::"),
    ("crates/franken-speaker/tests/d03_closed_loop.rs", "d03_closed_loop", ""),
    ("crates/franken-dsp/tests/d03_quality.rs", "d03_quality", ""),
]
# Files held outside any cargo target until the first green central compile: final path -> quarantine path.
PENDING = {"crates/franken-speaker/tests/d03_closed_loop.rs": "tests/d03/pending/d03_closed_loop.rs"}
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+(d03_[A-Za-z0-9_]+)")
OBSERVED = re.compile(r"D03-OBSERVED (\{.*\})\s*$")

R, C, L = "franken_dsp", "franken_clock", "d03_closed_loop"
QL = "d03_quality"
BANDS_BLOCK = re.compile(r"<!-- d03-quality-bands -->(.*?)<!-- /d03-quality-bands -->", re.S)
RS, RT = "resample::tests::", "rate::tests::"


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d03_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref, gen, anchors = _load("reference"), _load("generate"), _load("anchors")


def _load_d01_parser() -> Any:
    """D01's runner, for its cargo-log parser. Through RCH the ``Running`` headers (stderr) and the test
    sections (stdout) arrive as separate streams, so a test cannot be attributed to the nearest preceding
    header; D01's ``Logs`` pairs the n-th header with the n-th section and keeps exact-name matching as the
    fallback. D03 reuses it rather than carrying a second copy."""
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        sys.stderr.write("run_cases: D01's runner (%s) is required for its cargo-log parser\n" % path)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location("d01_run_cases_for_d03", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


d01 = _load_d01_parser()


def T(stem: str, prefix: str, *names: str) -> List[Tuple[str, str]]:
    return [(stem, prefix + n) for n in names]


# Case registry: the invariant -> case map. ``tests`` are required Rust tests, ``observed`` are record ids
# that must appear and pass the reference check.  ``tier`` is the first tier that requires the case.
def registry(vec: dict) -> List[dict]:
    tones = [t["id"] for t in vec["tones"]]
    ests = [e["id"] for e in vec["estimator"]]
    discs = [d["id"] for d in vec["discontinuities"]]
    return [
        dict(id="D03-RATIO-DRIFT", group="AC1", tier="smoke",
             what="positive and negative drift recovered by the estimator and applied by the resampler",
             tests=T(C, RT, "d03_estimator_matches_independent_least_squares",
                     "d03_perfect_drifting_sources_are_recovered_in_both_directions",
                     "d03_perfect_nominal_source_has_zero_drift_and_zero_uncertainty",
                     "d03_estimator_offers_nothing_until_warm", "d03_window_slides_and_never_exceeds_its_bound"),
             observed=ests),
        dict(id="D03-RATIO-LIMIT", group="AC1", tier="smoke",
             what="ratio limit: estimator correction clamp / rejoin flag, resampler target clamp and config bounds",
             tests=T(C, RT, "d03_correction_is_clamped_and_rejoin_is_flagged", "d03_config_is_validated",
                     "d03_rate_defaults_match_contract")
             + T(R, RS, "d03_ratio_target_is_clamped_to_the_limit", "d03_config_is_validated", "d03_params_match_contract")),
        dict(id="D03-SPECTRA", group="AC1", tier="smoke",
             what="tone frequency and SNR against the independent Catmull-Rom response bound",
             tests=T(R, RS, "d03_tone_quality_matches_independent_reference"), observed=tones),
        dict(id="D03-COUNTS", group="AC1", tier="smoke",
             what="exact output and input frame counts, including the 24-hour case, plan == render",
             tests=T(R, RS, "d03_output_counts_from_inputs_match_closed_form",
                     "d03_input_counts_for_outputs_match_closed_form", "d03_slew_counts_and_convergence_match",
                     "d03_plan_equals_render"),
             observed=["d03-pulled-longest"]),
        dict(id="D03-SLEW", group="AC1", tier="smoke",
             what="bounded slew: per-quantum schedule, <= 2 ppm per 256 output frames under random targets",
             tests=T(R, RS, "d03_slew_schedule_matches_per_quantum", "d03_slew_is_bounded_under_random_targets"),
             observed=["d03-slew-bound"]),
        dict(id="D03-SHORT-BLOCKS", group="AC1", tier="smoke",
             what="short, zero-length and split blocks; underrun and exact resume; refused oversize blocks",
             tests=T(R, RS, "d03_output_does_not_depend_on_block_splitting", "d03_zero_length_blocks_change_nothing",
                     "d03_underrun_resumes_exactly", "d03_oversize_and_mismatched_blocks_are_refused"),
             observed=["d03-split-invariance"]),
        dict(id="D03-HISTORY", group="AC1", tier="smoke",
             what="nonzero history carried across blocks (exact linear-ramp oracle)",
             tests=T(R, RS, "d03_history_is_carried_across_short_blocks_exactly"), observed=["d03-history-ramp"]),
        dict(id="D03-SAMPLE-SAFETY", group="AC1", tier="smoke",
             what="non-finite and out-of-range input contained; output clamped and counted; fade-in",
             tests=T(R, RS, "d03_non_finite_and_out_of_range_input_is_contained", "d03_output_is_clamped_and_counted",
                     "d03_fade_in_follows_start_and_reset")),
        dict(id="D03-WRAP", group="AC1", tier="smoke",
             what="u32 timeline wrap absorbed without a reset",
             tests=T(C, RT, "d03_wrap_is_absorbed_and_changes_nothing")),
        dict(id="D03-DISCONTINUITY", group="AC1", tier="smoke",
             what="clock jump / timeline step / gap / implausible rate / position jump reject and park until an explicit epoch",
             tests=T(C, RT, "d03_discontinuities_reject_and_park_until_an_explicit_epoch"), observed=discs),
        dict(id="D03-EPOCH-RESET", group="AC1", tier="smoke",
             what="reset clears only source-local history, keeps config/counters/ratio, records the reason, epochs advance",
             tests=T(C, RT, "d03_reset_touches_only_its_own_estimator", "d03_epochs_must_advance_and_compare_in_wrapping_order",
                     "d03_reset_log_is_bounded_and_ordered")
             + T(R, RS, "d03_epoch_reset_clears_history_and_keeps_ratio", "d03_epochs_must_advance")
             + T(L, "", "d03_resampler_epochs_must_advance_in_the_glue_too")),
        dict(id="D03-DIAGNOSTICS", group="AC3", tier="smoke",
             what="correction ratio, uncertainty with age, holdover bound, reset reason, operation counts recorded",
             tests=T(C, RT, "d03_uncertainty_grows_with_age_and_holdover_is_bounded")
             + T(R, RS, "d03_operation_counts_are_accounted", "d03_level_trim_is_proportional_and_bounded"),
             observed=["d03-ops"]),
        dict(id="D03-LOOP-FAST", group="AC2", tier="full",
             what="10 virtual minutes, fast source: bounded queue, exact output count, ratio converges",
             tests=T(L, "", "d03_closed_loop_holds_the_queue_for_ten_minutes_fast_source"), observed=["d03-loop-10min-pos"]),
        dict(id="D03-LOOP-SLOW", group="AC2", tier="full",
             what="10 virtual minutes, slow source",
             tests=T(L, "", "d03_closed_loop_holds_the_queue_for_ten_minutes_slow_source"), observed=["d03-loop-10min-neg"]),
        dict(id="D03-LOOP-WRAP", group="AC2", tier="full",
             what="20 virtual minutes across the u32 counter wrap; no reset",
             tests=T(L, "", "d03_closed_loop_absorbs_the_u32_timeline_wrap"), observed=["d03-loop-wrap-20min"]),
        dict(id="D03-LOOP-UNCONTROLLED", group="AC2", tier="full",
             what="negative control: without the loop the same drift overruns the bound",
             tests=T(L, "", "d03_without_the_loop_the_same_drift_overruns_the_bound"), observed=["d03-loop-uncontrolled"]),
        dict(id="D03-LOOP-JUMP", group="AC2", tier="full",
             what="mid-run source-counter jump: one explicit epoch each side, ratio held, no output gap",
             tests=T(L, "", "d03_source_counter_jump_resets_only_source_local_history_at_an_explicit_epoch"),
             observed=["d03-loop-jump"]),
        dict(id="D03-LOOP-SOAK", group="AC2", tier="soak",
             what="25.5 virtual hours crossing the 24.86 h u32 wrap",
             tests=T(L, "", "d03_closed_loop_soak_25_5_hours_crosses_the_counter_wrap"), observed=["d03-loop-25h-soak"]),
        dict(id="D03-QUALITY", group="AC3", tier="smoke",
             what="THD+N and carrier gain of 1 kHz and 10 kHz sines at -1 dBFS through the resampler (ratios 0, +/-100, "
                  "+/-500 ppm; after an epoch reset; settled after a slew) meet the bands declared before the run and the "
                  "reference's first-principles figures",
             tests=T(QL, "", "d03_quality_bands_are_the_declared_ones",
                     "d03_quality_metric_reads_a_known_tone_and_a_known_error",
                     "d03_quality_steady_ratios_meet_the_declared_bands",
                     "d03_quality_after_an_epoch_reset_meets_the_declared_bands",
                     "d03_quality_settled_after_a_slew_meets_the_declared_bands"),
             observed=[c["id"] for c in vec["quality"]["cases"] if c["must_pass"] and not c["control"]]),
        dict(id="D03-QUALITY-NEGATIVE", group="AC3", tier="smoke",
             what="planted nearest-neighbour and linear interpolators miss the bands (paired with the real kernel meeting "
                  "them); at zero ratio every interpolator is exact, so that row is shown not to be an interpolation test",
             tests=T(QL, "", "d03_quality_planted_nearest_and_linear_interpolators_miss_the_bands",
                     "d03_quality_at_zero_ratio_every_interpolator_is_exact_so_that_row_is_not_an_interpolation_test"),
             observed=[c["id"] for c in vec["quality"]["cases"] if not c["must_pass"] or c["control"]]
             + [c["id"] + "-pair" for c in vec["quality"]["cases"] if not c["must_pass"]]),
    ]


class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, detail, group

    def as_dict(self) -> dict:
        return {"id": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- source scan ----------------------------------------------------------------------------------


def source_path(rel: str, repo: str = REPO) -> Optional[str]:
    """The source file for ``rel``: its final path, or the quarantine path while the franken-clock wiring
    has not yet been applied (see docs/contracts/d03.md section 8)."""
    for candidate in (rel, PENDING.get(rel, "")):
        if candidate and os.path.isfile(os.path.join(repo, candidate)):
            return os.path.join(repo, candidate)
    return None


def derive_rust_tests(repo: str = REPO) -> List[Tuple[str, str, bool]]:
    """(binary stem, cargo test name, ignored) for every ``d03_`` ``#[test]`` in the sources."""
    found: List[Tuple[str, str, bool]] = []
    for rel, stem, prefix in RUST_SOURCES:
        path = source_path(rel, repo)
        if path is None:
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for attrs, name in TEST_FN.findall(text):
            found.append((stem, prefix + name, "ignore" in attrs))
    return found


# ---- log parsing ----------------------------------------------------------------------------------


class Logs(d01.Logs):
    """D01's parser (header/section ordinal pairing; ambiguous names stay ambiguous; a conflicting status or
    observation is reported, an identical repeat is not), reading ``D03-OBSERVED`` records instead of D01's."""

    def _record_test(self, stem: Optional[str], name: str, status: str) -> None:
        """``ignored`` means "not run in this invocation" and says nothing about the test, so it yields to
        a real result from another log (the soak test is ``ignored`` in a normal run and ``ok`` under
        ``--ignored``) and never replaces one. ``ok`` against ``FAILED`` is still a conflict."""
        key = (stem, name)
        previous = self.tests.get(key)
        if previous == "ignored" and status != "ignored":
            self.tests[key] = status
            return
        if status == "ignored" and previous is not None:
            return
        super()._record_test(stem, name, status)

    def add(self, path: str) -> None:
        saved = d01.OBSERVED
        d01.OBSERVED = OBSERVED          # the parser looks the pattern up in its own module
        try:
            super().add(path)
        finally:
            d01.OBSERVED = saved


# ---- judging an observed record against the reference ---------------------------------------------


def _by_id(items: List[dict]) -> Dict[str, dict]:
    return {i["id"]: i for i in items}


def quality_verdict(case: dict, q: dict, qd: Any, g: Any) -> Optional[str]:
    """None when ``(Q, gain)`` is what the case demands: a real case meets its declared band; a planted case misses
    it by the stated margin on at least one figure. Always judged from the figures, never from the record's own verdict."""
    if not isinstance(qd, (int, float)):
        return "no Q figure"
    meets = qd >= case["band_q_db"] and (g is None or case["gain_lo_db"] <= g <= case["gain_hi_db"])
    if case["must_pass"]:
        return None if meets else "MISSED its declared band: Q %.3f dB against %.1f, gain %s against %.2f..%.2f" % (
            qd, case["band_q_db"], g, case["gain_lo_db"], case["gain_hi_db"])
    q_miss = case["band_q_db"] - qd
    g_miss = -math.inf if g is None else max(case["gain_lo_db"] - g, g - case["gain_hi_db"])
    if q_miss >= q["plant_q_margin_db"] or g_miss >= q["plant_gain_margin_db"]:
        return None
    return "the planted interpolator does not clearly miss its band (Q short by %.3f dB, gain out by %.4f dB)" % (q_miss, g_miss)


def quality_agrees(case: dict, q: dict, qd: float, g: Any) -> Optional[str]:
    """The measured figures agree with the reference's first-principles prediction (above the f32 floor: at least it)."""
    if case["expect_q_db"] > q["q_cap_db"]:
        if qd < q["q_cap_db"]:
            return "Q %.3f dB is below the f32 floor %.1f dB, reference %.3f" % (qd, q["q_cap_db"], case["expect_q_db"])
    elif abs(qd - case["expect_q_db"]) > q["tol_q_db"]:
        return "Q %.3f dB, reference %.3f dB (tolerance %.2f)" % (qd, case["expect_q_db"], q["tol_q_db"])
    eg = case.get("expect_gain_db")
    if eg is not None and (g is None or abs(g - eg) > q["tol_gain_db"]):
        return "gain %s dB, reference %s dB (tolerance %s)" % (g, eg, q["tol_gain_db"])
    return None


def contract_bands(text: str) -> Dict[int, Dict[str, float]]:
    """The declared band table from docs/contracts/d03.md section 4.1."""
    m = BANDS_BLOCK.search(text)
    rows: Dict[int, Dict[str, float]] = {}
    if not m:
        return rows
    for line in m.group(1).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].isdigit():
            rows[int(cells[0])] = {"q_floor_db": float(cells[1]), "gain_lo_db": float(cells[2]),
                                   "gain_hi_db": float(cells[3])}
    return rows


def judge_observed(rec: dict, vec: dict) -> Optional[str]:
    kind, rid = rec.get("kind"), rec.get("id")
    if kind == "quality":
        q = vec["quality"]
        case = _by_id(q["cases"]).get(rid)
        if case is None:
            return "no such quality case"
        for key in ("interp", "scenario", "f0_hz", "ppb", "band_q_db", "gain_lo_db", "gain_hi_db"):
            if rec.get(key) != case[key]:
                return "%s is %r in the record and %r in the vectors (the case or its declared band moved)" % (
                    key, rec.get(key), case[key])
        qd, g = rec.get("q_db"), rec.get("gain_db")
        problem = None if not isinstance(qd, (int, float)) else quality_agrees(case, q, qd, g)
        problem = problem or quality_verdict(case, q, qd, g)
        if problem:
            return problem
        meets = qd >= case["band_q_db"] and (g is None or case["gain_lo_db"] <= g <= case["gain_hi_db"])
        if rec.get("meets_band") != meets:
            return "the record's meets_band disagrees with its own figures"
        return None
    if kind == "quality_pair":
        q = vec["quality"]
        cases = _by_id(q["cases"])
        plant, real = cases.get(rec.get("plant_id")), cases.get(rec.get("real_id"))
        if plant is None or real is None or plant["must_pass"] or not real["must_pass"] or real["interp"] != "catmull_rom":
            return "a pair must be a planted case and a real steady case"
        if (plant["f0_hz"], plant["ppb"]) != (real["f0_hz"], real["ppb"]):
            return "the pair is not at the same tone and ratio"
        for tag, case in (("plant", plant), ("real", real)):
            qd, g = rec.get(tag + "_q_db"), rec.get(tag + "_gain_db")
            problem = None if not isinstance(qd, (int, float)) else quality_agrees(case, q, qd, g)
            problem = problem or quality_verdict(case, q, qd, g)
            if problem:
                return "%s: %s" % (tag, problem)
        return None
    if kind == "tone":
        t = _by_id(vec["tones"]).get(rid)
        if t is None:
            return "no such tone vector"
        if rec["snr_db"] < t["snr_floor_db"]:
            return "SNR %.2f dB below the reference floor %.2f dB" % (rec["snr_db"], t["snr_floor_db"])
        if abs(rec["freq_dev_hz"]) > t["freq_tol_hz"]:
            return "frequency off by %.5f Hz (tolerance %.5f)" % (rec["freq_dev_hz"], t["freq_tol_hz"])
        if rec["consumed"] != t["expect_inputs_pulled"] or rec["produced"] != t["n_out"]:
            return "consumed %s / produced %s, expected %s / %s" % (
                rec["consumed"], rec["produced"], t["expect_inputs_pulled"], t["n_out"])
        return None
    if kind == "estimator":
        e = _by_id(vec["estimator"]).get(rid)
        if e is None:
            return "no such estimator vector"
        if rec["ratio_ppb"] != e["expect_ratio_ppb"]:
            return "ratio_ppb %s, reference %s" % (rec["ratio_ppb"], e["expect_ratio_ppb"])
        tol = max(1.0, e["expect_uncertainty_ppb"] * 1e-6) + 1.0
        if abs(rec["uncertainty_ppb"] - math.ceil(e["expect_uncertainty_ppb"])) > tol:
            return "uncertainty %s, reference %.1f" % (rec["uncertainty_ppb"], e["expect_uncertainty_ppb"])
        if (rec["status"], rec["correction_ppb"], rec["wraps"]) != (e["status"], e["correction_ppb"], e["expect_wraps"]):
            return "status/correction/wraps %s differ from the reference" % [rec["status"], rec["correction_ppb"], rec["wraps"]]
        return None
    if kind == "discontinuity":
        d = _by_id(vec["discontinuities"]).get(rid)
        if d is None:
            return "no such discontinuity vector"
        if rec["reason"] != d["reason"] or rec["to_epoch"] != 1:
            return "reason %s / epoch %s, expected %s / 1" % (rec["reason"], rec["to_epoch"], d["reason"])
        return None
    if kind == "count":
        rows = [p for p in vec["pulled"] if p["n_out"] == rec["n_out"] and p["ppb"] == rec["ppb"]]
        if not rows:
            return "no reference row for ppb=%s n_out=%s" % (rec["ppb"], rec["n_out"])
        if rows[0]["expect_inputs_pulled"] != rec["pulled"]:
            return "pulled %s, reference %s (n_out=%s)" % (rec["pulled"], rows[0]["expect_inputs_pulled"], rec["n_out"])
        if rec["n_out"] != max(p["n_out"] for p in vec["pulled"]):
            return "the longest (24-hour) case was not the one reported"
        return None
    if kind == "slew":
        if rec["max_change_per_256_ppb"] > 2 * 1000 or rec["max_step_ppb"] > vec["params"]["slew_ppb_per_quantum"]:
            return "slew %s ppb per 256 frames / step %s ppb exceeds the contract" % (
                rec["max_change_per_256_ppb"], rec["max_step_ppb"])
        return None
    if kind == "history":
        return None if rec["max_abs_error"] < 2e-6 else "history error %.3g" % rec["max_abs_error"]
    if kind == "split":
        return None if rec["splits_compared"] == 8 else "only %s splits compared" % rec["splits_compared"]
    if kind == "ops":
        p = vec["params"]
        if rec["float_ops_per_output_frame"] != p["float_ops_per_output_frame"]:
            return "ops per frame %s, reference %s" % (rec["float_ops_per_output_frame"], p["float_ops_per_output_frame"])
        if rec["float_ops_per_256_block"] != 256 * p["float_ops_per_output_frame"]:
            return "ops per block %s" % rec["float_ops_per_256_block"]
        if not str(rec.get("cpu_on_target", "")).startswith("not measured"):
            return "CPU on target must be reported as not measured"
        return None
    if kind == "closed_loop":
        pool = {c["id"]: c for c in vec["closed_loop"]}
        pool[vec["closed_loop_jump"]["id"]] = vec["closed_loop_jump"]
        if rid == "d03-loop-uncontrolled":
            c = vec["closed_loop"][0]
            if rec["max_deviation_frames"] <= 5 * c["occupancy_bound_frames"]:
                return "uncontrolled deviation %s did not exceed 5x the bound %s" % (
                    rec["max_deviation_frames"], c["occupancy_bound_frames"])
            return None
        c = pool.get(rid)
        if c is None:
            return "no such closed-loop vector"
        if rec["max_deviation_frames"] > c["occupancy_bound_frames"]:
            return "queue moved %s frames, bound %s" % (rec["max_deviation_frames"], c["occupancy_bound_frames"])
        if rec["underruns"] != 0 or rec["outputs"] != c["expect_total_outputs"]:
            return "underruns %s / outputs %s, expected 0 / %s" % (rec["underruns"], rec["outputs"], c["expect_total_outputs"])
        if "final_ratio_tolerance_ppb" in c:
            if abs(rec["final_ratio_ppb"] - rec["drift_ppb"]) > c["final_ratio_tolerance_ppb"]:
                return "final ratio %s vs drift %s" % (rec["final_ratio_ppb"], rec["drift_ppb"])
            if rec["wraps"] != c["expect_wraps"] or rec["resets"] != 0 or rec["estimator_discontinuities"] != 0:
                return "wraps %s / resets %s / discontinuities %s" % (
                    rec["wraps"], rec["resets"], rec["estimator_discontinuities"])
        else:
            if rec["resets"] != c["expect_resets"] or rec["estimator_discontinuities"] != 1:
                return "resets %s / discontinuities %s, expected %s / 1" % (
                    rec["resets"], rec["estimator_discontinuities"], c["expect_resets"])
        return None
    return "unknown record kind %r" % (kind,)


# ---- run ------------------------------------------------------------------------------------------


_ANCHOR_CACHE: List[Any] = []


def meta_results(vec: Optional[dict]) -> List[Result]:
    out: List[Result] = []
    if not _ANCHOR_CACHE:                      # the brute-force anchors take seconds; compute once per process
        _ANCHOR_CACHE.append(anchors.check())
    failed = [name for name, ok, _ in _ANCHOR_CACHE[0] if not ok]
    out.append(Result("D03-META-ANCHORS", "failed" if failed else "passed",
                      ("failed: " + "; ".join(failed[:MAX_PRINTED])) if failed else "reference agrees with a naive simulation", "AC4"))
    try:
        with open(CONTRACT, encoding="utf-8") as handle:
            declared = contract_bands(handle.read())
    except OSError:
        declared = {}
    in_ref = {int(f): dict(b) for f, b in ref.QUALITY_BANDS.items()}
    in_vec = {int(f): dict(b) for f, b in (vec or {}).get("quality", {}).get("bands", {}).items()} if vec else in_ref
    bands_ok = bool(declared) and declared == in_ref == in_vec
    out.append(Result("D03-META-BANDS-DECLARED", "passed" if bands_ok else "failed",
                      "the band table in docs/contracts/d03.md equals the reference's and the vectors'" if bands_ok else
                      "the declared bands differ: contract %s, reference %s, vectors %s (a band is moved by adding a dated "
                      "row, not by editing one)" % (declared, in_ref, in_vec), "AC4"))
    fresh = gen.render()
    try:
        with open(VECTORS, encoding="utf-8") as handle:
            same = handle.read() == fresh
    except OSError:
        same = False
    out.append(Result("D03-META-VECTORS-FRESH", "passed" if same else "failed",
                      "vectors.json equals a fresh generation" if same else "vectors.json is stale or missing; run --write-vectors", "AC4"))
    if vec is None:
        return out
    mapped = {(stem, name) for case in registry(vec) for stem, name in case["tests"]}
    unmapped = [n for stem, n, _ in derive_rust_tests() if (stem, n) not in mapped]
    out.append(Result("D03-META-MAP-COMPLETE", "failed" if unmapped else "passed",
                      ("unmapped Rust tests: " + ", ".join(unmapped[:MAX_PRINTED])) if unmapped else
                      "every d03_ Rust test belongs to a named case", "AC4"))
    present = {(s, n) for s, n, _ in derive_rust_tests()}
    missing = sorted(n for (s, n) in mapped if (s, n) not in present)
    out.append(Result("D03-META-TESTS-EXIST", "failed" if missing else "passed",
                      ("required Rust tests not found in the sources: " + ", ".join(missing[:MAX_PRINTED])) if missing else
                      "every required Rust test exists in the sources", "AC4"))
    try:
        with open(CONTRACT, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = ""
    absent = [c["id"] for c in registry(vec) if c["id"] not in text]
    out.append(Result("D03-META-CONTRACT-NAMES-CASES", "failed" if absent else "passed",
                      ("docs/contracts/d03.md does not name: " + ", ".join(absent)) if absent else
                      "docs/contracts/d03.md names every case", "AC4"))
    return out


def run(tier: str, logs: Optional[Logs]) -> Tuple[List[Result], dict]:
    vec: Optional[dict] = None
    try:
        with open(VECTORS, encoding="utf-8") as handle:
            vec = json.load(handle)
    except (OSError, ValueError):
        pass
    results = meta_results(vec)
    meta: dict = {"vectors_sha256": sha256_file(VECTORS) if os.path.isfile(VECTORS) else None}
    if vec is None:
        return results, meta
    for case in registry(vec):
        if TIERS.index(case["tier"]) > TIERS.index(tier):
            continue
        if logs is None:
            results.append(Result(case["id"], "blocked", "no cargo test log supplied (--judge); " + case["what"], case["group"]))
            continue
        # A test or record that really is missing, ambiguous or not run stays BLOCKED; one that ran and is
        # wrong or contradictory FAILS. Neither is ever a pass.
        failed_why: List[str] = []
        blocked_why: List[str] = []
        for stem, name in case["tests"]:
            status = logs.test_status(stem, name)
            if status == "ok":
                continue
            where = "%s %s" % (stem, name)
            if status in ("FAILED", "CONFLICT"):
                failed_why.append("%s: %s" % (where, status))
            elif status == "AMBIGUOUS":
                blocked_why.append("%s: in more than one test section and the log cannot say which binary ran it" % where)
            elif status == "ignored":
                blocked_why.append("%s: ignored (not run)" % where)
            else:
                blocked_why.append("%s: not reported" % where)
        for rid in case.get("observed", []):
            if rid in logs.conflicting_observations:
                failed_why.append("%s: the logs hold conflicting observations" % rid)
                continue
            rec = logs.observed.get(rid)
            if rec is None:
                blocked_why.append("no D03-OBSERVED record for %s" % rid)
                continue
            problem = judge_observed(rec, vec)
            if problem:
                failed_why.append("%s: %s" % (rid, problem))
        if failed_why:
            results.append(Result(case["id"], "failed", "; ".join((failed_why + blocked_why)[:MAX_PRINTED]), case["group"]))
        elif blocked_why:
            results.append(Result(case["id"], "blocked", "; ".join(blocked_why[:3]), case["group"]))
        else:
            results.append(Result(case["id"], "passed", case["what"], case["group"]))
    if logs is not None:
        bad_obs = sorted(logs.conflicting_observations)
        bad_tests = sorted(str(k) for k in logs.conflicting_tests)
        notes = []
        if logs.repeated_inputs:
            notes.append("repeated log input read once: " + ", ".join(logs.repeated_inputs))
        if logs.identical_repeats:
            notes.append("%d identical repeated observation(s) ignored" % logs.identical_repeats)
        if logs.unattributed_logs:
            notes.append("no header pairing, exact names used: " + "; ".join(logs.unattributed_logs))
        if bad_obs or bad_tests:
            detail = "conflicting records: " + ", ".join(bad_obs + bad_tests)
        else:
            detail = "no conflicting test status or observation" + ("; " + "; ".join(notes) if notes else "")
        results.append(Result("D03-META-LOGS-CONSISTENT", "failed" if (bad_obs or bad_tests) else "passed", detail, "AC4"))
    return results, meta


def summarize(results: List[Result]) -> Dict[str, int]:
    out = {"planned": len(results), "passed": 0, "failed": 0, "blocked": 0}
    for r in results:
        out[r.status] = out.get(r.status, 0) + 1
    return out


def exit_code(results: List[Result]) -> int:
    s = summarize(results)
    if s["failed"]:
        return 1
    return 3 if s["blocked"] else 0


def report(results: List[Result], tier: str) -> None:
    print("D03 tier=%s" % tier)
    for r in results:
        label = {"passed": "PASS", "failed": "FAIL", "blocked": "BLOCKED"}.get(r.status, r.status)
        print("%-8s %-34s %s" % (label, r.case_id, r.detail if r.status != "passed" else ""))
    s = summarize(results)
    print("planned=%d passed=%d failed=%d blocked=%d" % (s["planned"], s["passed"], s["failed"], s["blocked"]))
    for item in NOT_MEASURED:
        print("NOT MEASURED  %s: %s (recorded instead: %s)" % (item["item"], item["status"], item["recorded_instead"]))
    code = exit_code(results)
    print("RESULT: " + ("QUALIFIED (host simulation; no device claim)" if code == 0 else
                        "NOT QUALIFIED: blocked cases are not passes" if code == 3 else "FAILED"))


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs]) -> str:
    os.makedirs(directory, exist_ok=True)
    doc = {
        "schema": RECEIPT_SCHEMA, "tier": tier, "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "run_id": secrets.token_hex(6), "summary": summarize(results), "results": [r.as_dict() for r in results],
        "not_measured": NOT_MEASURED, "evidence_class": "host-simulation", "meta": meta,
        "logs": [{"path": os.path.basename(p), "sha256": d} for p, d in (logs.files if logs else [])],
        "sources": {rel: sha256_file(path) for rel, _, _ in RUST_SOURCES
                    for path in [source_path(rel)] if path},
        "replay": "scripts/e2e/d03 --tier " + tier + (" --judge <cargo-test-log>..." if logs else ""),
    }
    path = os.path.join(directory, "d03-receipt-%s.json" % doc["run_id"])
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="D03 end-to-end runner and judge (ffw-j9r)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true", help="print the planned case ids")
    parser.add_argument("--write-vectors", action="store_true", help="regenerate vectors.json from the Python reference")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="cargo test output file(s) to judge")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt here")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.write_vectors:
        with open(VECTORS, "w", encoding="utf-8") as handle:
            handle.write(gen.render())
        print("wrote " + VECTORS)
        return 0
    if args.list:
        vec = json.load(open(VECTORS, encoding="utf-8"))
        for case in registry(vec):
            if TIERS.index(case["tier"]) <= TIERS.index(args.tier):
                print(case["id"])
        return 0
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                sys.stderr.write("run_cases: no such log %s\n" % path)
                return 2
            logs.add(path)
    results, meta = run(args.tier, logs)
    report(results, args.tier)
    if args.receipts:
        print("receipt: " + write_receipt(args.receipts, args.tier, results, meta, logs))
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
