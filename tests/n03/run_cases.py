#!/usr/bin/env python3
"""N03 (ffw-u07) end-to-end runner and judge.

    run_cases.py [--tier smoke|full] [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds and boots nothing.

* META  - the reference agrees with itself (anchors.py), the committed vectors.json equals a fresh generation,
          every Rust ``n03_`` test in the sources is mapped to a named case, every world in the vectors is judged
          by some case, and the contract names every case.
* JUDGE - reads the ``cargo test`` output of the centrally run franken-clock suite (``--judge LOG``). Every
          required Rust test must report ``ok`` AND every ``N03-OBSERVED`` record is re-derived here from the
          independent Python reference (the whole member model re-run on each scripted world, the pure tables
          recomputed, the Rust-side independent world re-simulated) and compared with what the Rust printed, so a
          loosened assertion in the Rust cannot hide.

A case with no Rust observation is ``blocked``: counted, named, never passed, never dropped. The Rust is wired in
only after the first green central compile (docs/contracts/n03.md section 9); until then every Rust-backed case is
blocked.

The suite runs only through the centralized RCH path:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-clock -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy -p franken-clock --all-targets -- -D warnings

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VECTORS = os.path.join(HERE, "vectors.json")
CONTRACT = os.path.join(REPO, "docs", "contracts", "n03.md")
TIERS = ("smoke", "full")
RECEIPT_SCHEMA = "ffw.n03.receipt.v1"
MAX_PRINTED = 12
NOT_MEASURED = [
    {"item": "dac_or_acoustic_alignment", "status": "not measured: needs BE guest or hardware",
     "recorded_instead": "a network-clock fit with an explicit uncertainty; every report states claim=network-clock-fit-only"},
    {"item": "cpu_on_target_isa", "status": "not measured: needs BE guest or hardware",
     "recorded_instead": "none; the module does integer arithmetic per probe and per query"},
]

RUST_SOURCES = [("crates/franken-clock/src/group/tests.rs", "franken_clock", "group::tests::")]
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+(n03_[A-Za-z0-9_]+)")
WORLD_MACRO = re.compile(r"world_test!\(\s*(n03_[a-z0-9_]+)\s*,")
OBSERVED = re.compile(r"N03-OBSERVED (\{.*\})\s*$")

C = "franken_clock"
P = "group::tests::"


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("n03_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref, gen, anchors = _load("reference"), _load("generate"), _load("anchors")


def _load_d01_parser() -> Any:
    """D01's runner, for its cargo-log parser (header/section ordinal pairing for RCH logs). N03 reuses it, as D03
    does, rather than carrying another copy."""
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        sys.stderr.write("run_cases: D01's runner (%s) is required for its cargo-log parser\n" % path)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location("d01_run_cases_for_n03", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


d01 = _load_d01_parser()


def world_test_name(world_id: str) -> str:
    return "n03_world_" + world_id.lower().replace("-", "_")


def T(*names: str) -> List[Tuple[str, str]]:
    return [(C, P + n) for n in names]


def WT(*ids: str) -> List[Tuple[str, str]]:
    return [(C, P + world_test_name(i)) for i in ids]


def _case(cid: str, group: str, tier: str, what: str, tests: List[Tuple[str, str]], observed: List[str]) -> dict:
    return dict(id=cid, group=group, tier=tier, what=what, tests=tests, observed=observed)


def registry(vec: dict) -> List[dict]:
    del vec                                                    # the case list is fixed; the vectors supply the data
    return [
        _case("N03-PARAMS", "AC-THRESHOLD", "smoke",
              "defaults equal the reference (the explicit 2 ms lock threshold among them); invalid configs refused; board terms converted",
              T("n03_defaults_equal_the_reference_parameters", "n03_invalid_configurations_are_refused_field_by_field",
                "n03_board_profile_terms_are_converted_from_microseconds"), ["n03-defaults"]),
        _case("N03-EXCHANGE", "AC-REJECT", "smoke",
              "four-timestamp exchange: exact midpoints, every sample-level reject at its boundary, check order",
              T("n03_a_symmetric_exchange_has_the_hand_derived_midpoints", "n03_exchange_table_matches_the_reference",
                "n03_every_probe_reject_code_is_distinct_and_counted_in_its_own_slot"), ["n03-exchanges"]),
        _case("N03-TRANSFORM", "AC-OUTPUTS", "smoke",
              "clock transform in both directions with a ratio, floor rounding, round trip; frame counter wrap arithmetic",
              T("n03_transform_table_matches_the_reference_and_the_two_directions_are_consistent",
                "n03_frame_position_wraps_at_two_to_the_32_frames"), ["n03-transforms"]),
        _case("N03-SELECT", "AC-NO-NTP", "smoke",
              "anchor selection by smallest uncertainty at the query time, ties to the newer midpoint",
              T("n03_selection_table_matches_the_reference"), ["n03-selections"]),
        _case("N03-HOLDOVER-MIN", "AC-HOLDOVER", "smoke",
              "holdover limit is min(authority, buffer, uncertainty horizon) with the named binding and tie order",
              T("n03_holdover_table_matches_the_reference"), ["n03-holdovers"]),
        _case("N03-PLAN-TABLE", "AC-OUTPUTS", "smoke",
              "admissible-start decision: check order and every limit, with start, deadline, uncertainty at start and expiry",
              T("n03_start_plan_table_matches_the_reference"), ["n03-plans"]),
        _case("N03-LOCK", "AC-THRESHOLD", "smoke",
              "symmetric path: unlocked until the fourth exchange, then locked; truth inside the reported uncertainty",
              WT("S01-SYMMETRIC"), ["S01-SYMMETRIC"]),
        _case("N03-ASYMMETRIC", "AC-NO-NTP", "smoke",
              "asymmetric delay: the offset is biased by exactly (df-dr)/2, inside the uncertainty; a path too wide to trust never locks or sounds",
              WT("S02-ASYMMETRIC-LOCKABLE", "S03-ASYMMETRIC-TOO-WIDE"), ["S02-ASYMMETRIC-LOCKABLE", "S03-ASYMMETRIC-TOO-WIDE"]),
        _case("N03-DRIFT", "AC-FAULTS", "smoke",
              "+/-80 ppm skew with seeded jitter: the rate estimate comes into force and the truth stays inside the uncertainty; sparse probes restart only the rate fit",
              WT("S04-DRIFT-FAST", "S05-DRIFT-SLOW", "S14-SPARSE-PROBES"),
              ["S04-DRIFT-FAST", "S05-DRIFT-SLOW", "S14-SPARSE-PROBES"]),
        _case("N03-WRAP", "AC-WRAP", "smoke",
              "group counter wraps mid-run without a reset; half-range and one-counter-period group jumps are discontinuities, not silent aliases",
              WT("S06-WRAP", "S08C-JUMP-HALF-RANGE", "S08D-JUMP-WRAP-ALIAS"),
              ["S06-WRAP", "S08C-JUMP-HALF-RANGE", "S08D-JUMP-WRAP-ALIAS"]),
        _case("N03-HOLDOVER", "AC-HOLDOVER", "smoke",
              "probes stop: audible through holdover, muted at the bound set by uncertainty / authority / buffer (and the tie); recovery is muted until re-admitted",
              WT("S07A-HOLDOVER-UNCERTAINTY", "S07B-HOLDOVER-AUTHORITY", "S07C-HOLDOVER-BUFFER", "S07D-HOLDOVER-TIE"),
              ["S07A-HOLDOVER-UNCERTAINTY", "S07B-HOLDOVER-AUTHORITY", "S07C-HOLDOVER-BUFFER", "S07D-HOLDOVER-TIE"]),
        _case("N03-JUMP", "AC-FAULTS", "smoke",
              "suspend, group-clock step, counter reset and local regression each clear the fit and mute; the step boundary pair; relock is muted",
              WT("S08A-JUMP-LOCAL-SUSPEND", "S08B-JUMP-GROUP-STEP", "S08E-JUMP-COUNTER-RESET", "S08F-JUMP-LOCAL-REGRESSION",
                 "S09A-STEP-AT-BOUND", "S09B-STEP-PAST-BOUND"),
              ["S08A-JUMP-LOCAL-SUSPEND", "S08B-JUMP-GROUP-STEP", "S08E-JUMP-COUNTER-RESET", "S08F-JUMP-LOCAL-REGRESSION",
               "S09A-STEP-AT-BOUND", "S09B-STEP-PAST-BOUND"]),
        _case("N03-LEADER-CHANGE", "AC-STALE", "smoke",
              "leader change: old-epoch probes are inert, the new leader's timebase is not the old one, stale schedules refused, relock muted",
              WT("S10-LEADER-CHANGE"), ["S10-LEADER-CHANGE"]),
        _case("N03-ADMISSION", "AC-REJECT", "smoke",
              "stale / future epoch, unadmitted leader, unsolicited, replayed, wrong echo, malformed, expired, excessive, regressed: each paired with an accepted exchange; outstanding table bounded",
              WT("S11-ADMISSION", "S12-OUTSTANDING-BOUND"), ["S11-ADMISSION", "S12-OUTSTANDING-BOUND"]),
        _case("N03-REBOOT", "AC-STALE", "smoke",
              "reboot: nothing survives, recorded answers are unsolicited, the member is muted until it locks and is admitted again",
              WT("S13-REBOOT"), ["S13-REBOOT"]),
        _case("N03-JOIN", "AC-OUTPUTS", "smoke",
              "synchronized join: admissible start at its exact limits, audible only at the start, authority expiry mutes, uncertainty at the start, board output delay",
              WT("S16-JOIN", "S18-START-UNCERTAINTY", "S19-OUTPUT-DELAY"),
              ["S16-JOIN", "S18-START-UNCERTAINTY", "S19-OUTPUT-DELAY"]),
        _case("N03-UNLOCKED-MUTED", "AC-STALE", "smoke",
              "an unlocked member cannot output (paired with the positive join); a platform clock fault mutes; no samples means no reading",
              WT("S17-UNLOCKED-CANNOT-OUTPUT")
              + T("n03_a_member_with_no_samples_has_no_reading_and_cannot_plan",
                  "n03_the_platform_clock_fault_clears_the_fit_and_names_itself"),
              ["S17-UNLOCKED-CANNOT-OUTPUT"]),
        _case("N03-API", "AC-REJECT", "smoke",
              "report has no side effects and states the claim; request numbering wraps; a response answers only its own request",
              T("n03_report_has_no_side_effects_and_always_states_the_claim",
                "n03_requests_are_numbered_from_the_base_and_wrap_without_panicking",
                "n03_a_response_for_an_older_request_does_not_answer_a_newer_one_with_the_same_send_time",
                "n03_every_world_in_the_vectors_has_a_test_above"), []),
        _case("N03-MIXED-PROFILE", "AC-MIXED", "full",
              "two members with different skews and board profiles join one future start within their summed uncertainty and the provisional 2 ms gate",
              T("n03_mixed_profile_members_begin_within_their_summed_uncertainty"),
              ["n03-mixed", "M-A-hz3", "M-B-ts1"]),
        _case("N03-TRUTH-SIM", "AC-NOT-DAC", "full",
              "an independent world generator written in the Rust test: truth inside the uncertainty at every probe across five seeds (re-simulated here)",
              T("n03_an_independent_world_keeps_the_truth_inside_the_reported_uncertainty"), ["n03-sim"]),
        _case("N03-SOAK", "AC-WRAP", "full",
              "3 hours at 10 s probes, 10% lost, jitter, drift, across the u32 group counter wrap: no reset, truth inside the uncertainty",
              WT("S15-SOAK-3H"), ["S15-SOAK-3H"]),
        _case("N03-PROPERTY", "AC-STALE", "full",
              "audible only on a locked/holdover clock within the threshold, a valid authority, an admitted start and the lock count; never right after a reset",
              T("n03_audible_output_always_rests_on_a_locked_clock_a_valid_authority_and_an_admitted_start"),
              ["n03-property"]),
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


def derive_rust_tests(repo: str = REPO) -> List[Tuple[str, str, bool]]:
    """(binary stem, cargo test name, ignored) for every ``n03_`` test in the sources, including those the
    ``world_test!`` macro defines."""
    found: List[Tuple[str, str, bool]] = []
    for rel, stem, prefix in RUST_SOURCES:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for attrs, name in TEST_FN.findall(text):
            found.append((stem, prefix + name, "ignore" in attrs))
        for name in WORLD_MACRO.findall(text):
            found.append((stem, prefix + name, False))
    return found


# ---- log parsing ----------------------------------------------------------------------------------


class Logs(d01.Logs):
    """D01's parser, reading ``N03-OBSERVED`` records. ``ignored`` yields to a real result from another log."""

    def _record_test(self, stem: Optional[str], name: str, status: str) -> None:
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
        d01.OBSERVED = OBSERVED
        try:
            super().add(path)
        finally:
            d01.OBSERVED = saved


# ---- judging an observed record against the reference ---------------------------------------------


def _by_id(items: List[dict]) -> Dict[str, dict]:
    return {i["id"]: i for i in items}


def _cfg(over: Optional[dict]) -> Dict[str, int]:
    c = dict(ref.DEFAULTS)
    c.update(over or {})
    return c


def compare_record(index: int, want: dict, got: dict) -> Optional[str]:
    """Exact, except for the fields the reference gives a tolerance for (the rate estimator's float uncertainty)."""
    tol = want.get("tol", {})
    wk = sorted(k for k in want if k != "tol")
    gk = sorted(got)
    if wk != gk:
        return "op %d: fields differ: reference %s, observed %s" % (index, wk, gk)
    for key in wk:
        w, g = want[key], got[key]
        if key in tol:
            if not isinstance(g, int) or abs(w - g) > tol[key]:
                return "op %d %s: observed %s, reference %s, tolerance %s" % (index, key, g, w, tol[key])
        elif w != g:
            return "op %d %s: observed %r, reference %r" % (index, key, g, w)
    return None


def true_instant_of_local(clocks: dict, local_ns: int) -> int:
    """The first true time at which the member's local clock reads ``local_ns`` (the clock is monotone)."""
    w = ref.World(clocks["skew_ppb"], clocks["local0"], clocks["group0"], clocks["res_ns"])
    lo, hi = 0, 200 * ref.NS
    while lo < hi:
        mid = (lo + hi) // 2
        if w.local(mid) < local_ns:
            lo = mid + 1
        else:
            hi = mid
    return lo


def judge_world(rec: dict, wdef: dict) -> Optional[str]:
    want = gen.expect_for(wdef)                          # re-derived now, not read from the vectors file
    got = rec.get("steps")
    if not isinstance(got, list) or len(got) != len(want):
        return "observed %s steps, reference %d" % (len(got) if isinstance(got, list) else got, len(want))
    for i, (w, g) in enumerate(zip(want, got)):
        problem = compare_record(i, w, g)
        if problem:
            return problem
    # the central claim, against the world's known truth, computed here from what the Rust reported
    checks = max_err = max_unc = 0
    min_margin: Optional[int] = None
    for i, (op, g) in enumerate(zip(wdef["ops"], got)):
        if op["op"] == "check" and "truth_group" in op:
            err = abs(g["group_ns"] - op["truth_group"])
            if err > g["uncertainty_ns"]:
                return "op %d: error %d ns exceeds the reported uncertainty %d ns" % (i, err, g["uncertainty_ns"])
            checks += 1
            max_err, max_unc = max(max_err, err), max(max_unc, g["uncertainty_ns"])
            margin = g["uncertainty_ns"] - err
            min_margin = margin if min_margin is None else min(min_margin, margin)
        if op["op"] == "probe" and "truth_offset" in op:
            res = wdef["clocks"]["res_ns"]
            if abs(g["offset"] - op["truth_offset"] - op["bias_ns"]) > res:
                return "op %d: offset error %d ns, the path bias is %d ns" % (i, g["offset"] - op["truth_offset"], op["bias_ns"])
    truth = rec.get("truth", {})
    if (truth.get("checks"), truth.get("max_err_ns"), truth.get("max_unc_ns"), truth.get("min_margin_ns")) != (
            checks, max_err, max_unc, min_margin):
        return "truth summary %s differs from the one derived from the steps %s" % (
            truth, (checks, max_err, max_unc, min_margin))
    if any(op["op"] == "check" and "truth_group" in op for op in wdef["ops"]) and checks == 0:
        return "no truth check was observed"
    return None


def judge_observed(rec: dict, vec: dict) -> Optional[str]:
    kind, rid = rec.get("kind"), rec.get("id")
    if kind == "defaults":
        return None if rec.get("params") == ref.DEFAULTS else "parameters %s differ from the reference %s" % (rec.get("params"), ref.DEFAULTS)
    if kind == "exchanges":
        seen = rec.get("cases", {})
        if sorted(seen) != sorted(c["id"] for c in vec["exchanges"]):
            return "the observed case ids differ from the vectors"
        for c in vec["exchanges"]:
            want = ref.sample(c["t1"], c["t2"], c["t3"], c["t4"], _cfg(c["cfg"]))
            if seen[c["id"]] != want:
                return "%s: observed %s, reference %s" % (c["id"], seen[c["id"]], want)
        return None
    if kind == "transforms":
        seen = rec.get("cases", {})
        for c in vec["transforms"]:
            g = ref.group_at(c["sample"], c["now"], c["ratio_ppb"])
            lo = ref.local_of(c["sample"], c["group_target"], c["ratio_ppb"])
            if seen.get(c["id"]) != {"group_ns": g, "local_for_group": lo}:
                return "%s: observed %s, reference %s" % (c["id"], seen.get(c["id"]), {"group_ns": g, "local_for_group": lo})
        return None
    if kind == "selections":
        seen = rec.get("cases", {})
        for c in vec["selections"]:
            i, u = ref.select(c["samples"], c["now"], c["ratio_unc_ppb"], ref.DEFAULTS)
            if seen.get(c["id"]) != {"index": i, "uncertainty_ns": u}:
                return "%s: observed %s, reference %s" % (c["id"], seen.get(c["id"]), (i, u))
        return None
    if kind == "holdovers":
        seen = rec.get("cases", {})
        for c in vec["holdovers"]:
            until, binding = ref.holdover(c["sample"], c["ratio_unc_ppb"], _cfg(c["cfg"]), c["authority"], c["buffer"])
            if seen.get(c["id"]) != {"until": until, "binding": binding}:
                return "%s: observed %s, reference %s" % (c["id"], seen.get(c["id"]), (until, binding))
        return None
    if kind == "plans":
        seen = rec.get("cases", {})
        for c in vec["plans"]:
            r = ref.plan_start(c["sample"], c["ratio_ppb"], c["ratio_unc_ppb"], _cfg(c["cfg"]), now=c["now"], epoch=c["epoch"],
                               sched_epoch=c["sched_epoch"], sched_start_group_ns=c["start_group_ns"], status=c["status"],
                               authority_until=c["authority"], buffer_until=c["buffer"])
            want = r if r.get("ok") else {"reject": r["reject"]}
            if seen.get(c["id"]) != want:
                return "%s: observed %s, reference %s" % (c["id"], seen.get(c["id"]), want)
        return None
    if kind == "world":
        worlds = _by_id(vec["worlds"] + [m["world"] for m in vec["mixed"]["members"]])
        wdef = worlds.get(rid)
        if wdef is None:
            return "no such world in the vectors"
        return judge_world(rec, wdef)
    if kind == "mixed":
        members = vec["mixed"]["members"]
        audible, unc = [], 0
        starts = []
        for m in members:
            fresh = gen.expect_for(m["world"])
            admit = next(r for r in fresh if r["op"] == "admit")
            if admit.get("result") != "ok":
                return "the reference does not admit %s" % m["world"]["id"]
            audible.append(true_instant_of_local(m["world"]["clocks"], admit["start_local_ns"])
                           + m["world"]["cfg"].get("output_delay_ns", 0))
            unc += admit["uncertainty_at_start_ns"]
            starts.append({"id": m["world"]["id"], "start_local_ns": admit["start_local_ns"],
                           "uncertainty_at_start_ns": admit["uncertainty_at_start_ns"]})
        if rec.get("members") != starts:
            return "observed member starts %s, reference %s" % (rec.get("members"), starts)
        skew = abs(audible[0] - audible[1])
        if (rec.get("skew_ns"), rec.get("bound_ns"), rec.get("gate_ns")) != (skew, unc, 2 * ref.NS // 1000):
            return "skew/bound/gate %s, reference %s" % ((rec.get("skew_ns"), rec.get("bound_ns"), rec.get("gate_ns")), (skew, unc, 2_000_000))
        if skew > unc or skew > 2_000_000:
            return "start skew %d ns exceeds the summed uncertainty %d ns or the 2 ms gate" % (skew, unc)
        return None
    if kind == "sim":
        seen = rec.get("worlds", [])
        if len(seen) != len(ref.SIM_WORLDS):
            return "observed %d worlds, reference %d" % (len(seen), len(ref.SIM_WORLDS))
        for obs, args in zip(seen, ref.SIM_WORLDS):
            want = ref.sim_run(*args)
            for key in ("probes", "lost", "checks", "max_err_ns"):
                if obs.get(key) != want[key]:
                    return "seed %d %s: observed %s, reference %s" % (args[0], key, obs.get(key), want[key])
            for key in ("max_unc_ns", "min_margin_ns"):
                if abs(obs.get(key, 1 << 62) - want[key]) > 100:           # the rate estimator's float sigma: +/-3 ppb x age
                    return "seed %d %s: observed %s, reference %s (tolerance 100 ns)" % (args[0], key, obs.get(key), want[key])
            if obs.get("min_margin_ns", -1) < 0 or obs.get("max_err_ns", 1 << 62) > obs.get("max_unc_ns", 0):
                return "seed %d: the truth left the reported uncertainty" % args[0]
        return None
    if kind == "property":
        if rec.get("audible", 0) < 100 or rec.get("resets_checked", 0) < 20:
            return "the property run was too thin: %s" % ({k: rec.get(k) for k in ("audible", "resets_checked")},)
        return None
    return "unknown record kind %r" % (kind,)


# ---- run ------------------------------------------------------------------------------------------


_ANCHOR_CACHE: List[Any] = []


def meta_results(vec: Optional[dict]) -> List[Result]:
    out: List[Result] = []
    if not _ANCHOR_CACHE:
        _ANCHOR_CACHE.append(anchors.check())
    failed = [name for name, ok, _ in _ANCHOR_CACHE[0] if not ok]
    out.append(Result("N03-META-ANCHORS", "failed" if failed else "passed",
                      ("failed: " + "; ".join(failed[:MAX_PRINTED])) if failed else "reference agrees with hand-derived values and brute force", "AC-META"))
    fresh = gen.render(gen.build())
    try:
        with open(VECTORS, encoding="utf-8") as handle:
            same = handle.read() == fresh
    except OSError:
        same = False
    out.append(Result("N03-META-VECTORS-FRESH", "passed" if same else "failed",
                      "vectors.json equals a fresh generation" if same else "vectors.json is stale or missing; run --write-vectors", "AC-META"))
    if vec is None:
        return out
    cases = registry(vec)
    mapped = {(stem, name) for case in cases for stem, name in case["tests"]}
    unmapped = [n for stem, n, _ in derive_rust_tests() if (stem, n) not in mapped]
    out.append(Result("N03-META-MAP-COMPLETE", "failed" if unmapped else "passed",
                      ("unmapped Rust tests: " + ", ".join(unmapped[:MAX_PRINTED])) if unmapped else
                      "every n03_ Rust test belongs to a named case", "AC-META"))
    present = {(s, n) for s, n, _ in derive_rust_tests()}
    missing = sorted(n for (s, n) in mapped if (s, n) not in present)
    out.append(Result("N03-META-TESTS-EXIST", "failed" if missing else "passed",
                      ("required Rust tests not found in the sources: " + ", ".join(missing[:MAX_PRINTED])) if missing else
                      "every required Rust test exists in the sources", "AC-META"))
    judged = {rid for case in cases for rid in case["observed"]}
    all_worlds = [w["id"] for w in vec["worlds"]] + [m["world"]["id"] for m in vec["mixed"]["members"]]
    unjudged = [w for w in all_worlds if w not in judged]
    out.append(Result("N03-META-WORLDS-ALL-JUDGED", "failed" if unjudged else "passed",
                      ("worlds no case judges: " + ", ".join(unjudged)) if unjudged else
                      "all %d worlds in the vectors are judged by a case" % len(all_worlds), "AC-META"))
    try:
        with open(CONTRACT, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = ""
    absent = [c["id"] for c in cases if c["id"] not in text]
    out.append(Result("N03-META-CONTRACT-NAMES-CASES", "failed" if absent else "passed",
                      ("docs/contracts/n03.md does not name: " + ", ".join(absent)) if absent else
                      "docs/contracts/n03.md names every case", "AC-META"))
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
                blocked_why.append("no N03-OBSERVED record for %s" % rid)
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
        bad_obs = sorted(str(k) for k in logs.conflicting_observations)
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
        results.append(Result("N03-META-LOGS-CONSISTENT", "failed" if (bad_obs or bad_tests) else "passed", detail, "AC-META"))
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
    print("N03 tier=%s" % tier)
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
        "sources": {rel: sha256_file(os.path.join(REPO, rel)) for rel, _, _ in RUST_SOURCES
                    if os.path.isfile(os.path.join(REPO, rel))},
        "replay": "scripts/e2e/n03 --tier " + tier + (" --judge <cargo-test-log>..." if logs else ""),
    }
    path = os.path.join(directory, "n03-receipt-%s.json" % doc["run_id"])
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="N03 end-to-end runner and judge (ffw-u07)")
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
            handle.write(gen.render(gen.build()))
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
