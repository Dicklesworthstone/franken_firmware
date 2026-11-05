#!/usr/bin/env python3
"""N04 (ffw-nx0) end-to-end runner and judge.

    run_cases.py [--tier smoke|full] [--list] [--write-vectors] [--judge LOG [LOG ...]] [--receipts DIR]

Offline, standard library only; it builds and boots nothing.

* META  - the reference agrees with the hand-derived anchors (anchors.py), the committed vectors.json equals a fresh
          generation, every Rust ``n04_`` test in the sources is mapped to a named case, every world in the vectors is
          judged by some case, and the contract names every case.
* JUDGE - reads the ``cargo test`` output of the centrally run franken-stream suite (``--judge LOG``). Every required
          Rust test must report ``ok`` AND every ``N04-OBSERVED`` record is re-derived here from the independent Python
          reference (each scripted world is re-run, every table recomputed) and compared with what the Rust printed, op
          by op, so a loosened assertion in the Rust cannot hide.

A case with no Rust observation is ``blocked``: counted, named, never passed, never dropped. The module is wired into
franken-stream/src/lib.rs only after the first green central compile (docs/contracts/n04.md section 11); until then
every Rust-backed case is blocked.

The suite runs only through the centralized RCH path:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-stream -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy -p franken-stream --all-targets -- -D warnings

Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage/malformed.
"""
from __future__ import annotations

import argparse
import datetime
import functools
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
CONTRACT = os.path.join(REPO, "docs", "contracts", "n04.md")
TIERS = ("smoke", "full")
RECEIPT_SCHEMA = "ffw.n04.receipt.v1"
MAX_PRINTED = 12
NOT_MEASURED = [
    {"item": "dac_or_acoustic_presentation", "status": "not measured: needs a BE guest or hardware",
     "recorded_instead": "decisions against a group-clock cutoff with an explicit downstream guard"},
    {"item": "concealment_listening_quality", "status": "not evaluated: no listening test exists",
     "recorded_instead": "bit-exact attenuated repetition of the last played block, bounded to a stated maximum, then silence"},
    {"item": "cpu_and_memory_on_target_isa", "status": "not measured: needs a BE guest or hardware",
     "recorded_instead": "fixed slot storage (profile horizon x 1 KiB), no allocation after construction (structural, not probed)"},
    {"item": "real_network_loss_and_jitter", "status": "not measured: scripted and seeded schedules only",
     "recorded_instead": "seeded independent loss, jitter, reorder, duplicate and burst schedules over 700 blocks"},
]

RUST_SOURCES = [("crates/franken-stream/src/playout/tests.rs", "franken_stream", "playout::tests::"),
                ("crates/franken-stream/src/playout/log/tests.rs", "franken_stream", "playout::log::tests::")]
TEST_FN = re.compile(r"#\[test\]\s*((?:#\[[^\]]*\]\s*)*)fn\s+(n04_[A-Za-z0-9_]+)")
WORLD_MACRO = re.compile(r"world_test!\(\s*(n04_[a-z0-9_]+)\s*,")
OBSERVED = re.compile(r"N04-OBSERVED (\{.*\})\s*$")

C = "franken_stream"
P = "playout::tests::"
PL = "playout::log::tests::"


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("n04_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, HERE)                   # reference.py imports by plain name, as generate.py does
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


ref, gen, anchors = _load("reference"), _load("generate"), _load("anchors")


def _load_d01_parser() -> Any:
    """D01's runner, for its cargo-log parser (header/section ordinal pairing for RCH logs), as N03 reuses it."""
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    if not os.path.isfile(path):
        sys.stderr.write("run_cases: D01's runner (%s) is required for its cargo-log parser\n" % path)
        raise SystemExit(2)
    spec = importlib.util.spec_from_file_location("d01_run_cases_for_n04", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


d01 = _load_d01_parser()


@functools.lru_cache(maxsize=None)
def _results_for(key: str) -> list:
    return gen.world_results(json.loads(key))


def world_results(doc: dict) -> list:
    """The reference's results for a world, memoised on the world's content (a pure function of it). The callers
    compare and never mutate the returned list."""
    return _results_for(json.dumps(doc, sort_keys=True))


@functools.lru_cache(maxsize=None)
def _fresh_vectors() -> str:
    return json.dumps(gen.build(), sort_keys=True)


def world_test_name(world_id: str) -> str:
    return "n04_world_" + world_id.lower().replace("-", "_")


def T(*names: str) -> List[Tuple[str, str]]:
    return [(C, P + n) for n in names]


def LT(*names: str) -> List[Tuple[str, str]]:
    return [(C, PL + n) for n in names]


def log_world_id(world_id: str) -> str:
    return "n04-log-" + world_id.lower()


def log_scenario_id(scenario_id: str) -> str:
    return "n04-logscn-" + scenario_id.lower()


def WT(*ids: str) -> List[Tuple[str, str]]:
    return [(C, P + world_test_name(i)) for i in ids]


def _case(cid: str, group: str, tier: str, what: str, tests: List[Tuple[str, str]], observed: List[str]) -> dict:
    return dict(id=cid, group=group, tier=tier, what=what, tests=tests, observed=observed)


def registry() -> List[dict]:
    return [
        _case("N04-PROFILES", "AC-CAPS", "smoke",
              "music and realtime policies are the frozen table (horizon, conceal maximum, notice, step, net cap); invalid configs refused",
              T("n04_profiles_are_the_frozen_table", "n04_invalid_configurations_are_refused_field_by_field"),
              ["n04-profiles", "n04-configs"]),
        _case("N04-CUTOFF-FORMULA", "AC-CUTOFF", "smoke",
              "frame-to-time mapping and consume_by = presentation - work - lead - uncertainty, clamped at zero, against hand-derived anchors",
              T("n04_frames_to_ns_table_matches_the_reference_and_the_hand_derived_anchors",
                "n04_consume_by_table_matches_the_reference_and_the_hand_derived_anchors"),
              ["n04-frames-to-ns", "n04-consume-by"]),
        _case("N04-CUTOFF-BOUNDARY", "AC-CUTOFF", "smoke",
              "arrival 1 ns before the cutoff plays, at it and after it is late; uncertainty from the clock report moves the cutoff; the sender's consume_by never extends it",
              WT("W02-CUTOFF-BOUNDARY", "W03-UNCERTAINTY-MOVES-CUTOFF") + T("n04_the_senders_consume_by_never_extends_a_deadline"),
              ["W02-CUTOFF-BOUNDARY", "W03-UNCERTAINTY-MOVES-CUTOFF", "n04-sender-consume-by"]),
        _case("N04-ONTIME", "AC-ONCE", "smoke",
              "in-order on-time blocks are all real, bytes identical to what arrived, with submission deadline and presentation time",
              WT("W01-ONTIME"), ["W01-ONTIME"]),
        _case("N04-REORDER-DUP", "AC-ORDER", "smoke",
              "reordered arrivals play in frame order; duplicates (identical and conflicting) never play twice; a late copy of a concealed block is late",
              WT("W04-REORDER-DUPLICATE"), ["W04-REORDER-DUPLICATE"]),
        _case("N04-LOSS-CONCEAL", "AC-CONCEAL", "smoke",
              "a 100 ms burst: concealed up to the stated maximum then muted (never extrapolated), then real again; gains and concealed bytes against hand-derived samples",
              WT("W05-BURST-MUSIC", "W06-BURST-REALTIME")
              + T("n04_conceal_gains_are_round_0_7_pow_n_in_q15", "n04_conceal_blocks_match_the_reference_and_the_hand_derived_samples"),
              ["W05-BURST-MUSIC", "W06-BURST-REALTIME", "n04-conceal-gains", "n04-conceal-blocks"]),
        _case("N04-EPOCH", "AC-STALE", "smoke",
              "unbound, stale, future and restarted epochs: nothing a stale packet does changes the stream; a refused restart changes nothing",
              WT("W07-EPOCH"), ["W07-EPOCH"]),
        _case("N04-WINDOW-INPUT", "AC-CAPS", "smoke",
              "the admissible window ends exactly at the horizon; malformed inputs; timeline tolerance boundary pair; partial final block",
              WT("W08-WINDOW-AND-INPUT"), ["W08-WINDOW-AND-INPUT"]),
        _case("N04-REPAIR", "AC-REPAIR", "smoke",
              "a repair is judged by the media cutoff: late repair discarded even before the DAC presentation time; duplicate repair; repair for a played block",
              WT("W09-REPAIR", "W09B-REPAIR-BEFORE-DAC"), ["W09-REPAIR", "W09B-REPAIR-BEFORE-DAC"]),
        _case("N04-CLOCK", "AC-CLOCK", "smoke",
              "an unusable or regressing clock admits nothing, decides nothing and consumes no block",
              WT("W10-CLOCK"), ["W10-CLOCK"]),
        _case("N04-OVERDUE", "AC-CUTOFF", "smoke",
              "a decision taken at or after the presentation time cannot play: dropped, muted, the loop catches up one block per call; the boundary pair",
              WT("W11-OVERDUE", "W11B-OVERDUE-BOUNDARY"), ["W11-OVERDUE", "W11B-OVERDUE-BOUNDARY"]),
        _case("N04-LATENCY-UP", "AC-LATENCY", "smoke",
              "a coordinated latency increase: every refusal paired with the accepted change, a mapping mismatch refused, the silent gap reported on the first block after it; the step limit boundary pair",
              WT("W12-LATENCY-UP", "W12B-STEP-LIMIT", "W12C-STEP-LIMIT"),
              ["W12-LATENCY-UP", "W12B-STEP-LIMIT", "W12C-STEP-LIMIT"]),
        _case("N04-LATENCY-DOWN", "AC-LATENCY", "smoke",
              "a coordinated latency decrease skips whole blocks so the sample clock never rewinds; an exact fit skips no extra block and leaves no gap",
              WT("W13-LATENCY-DOWN", "W13B-LATENCY-DOWN-EXACT"), ["W13-LATENCY-DOWN", "W13B-LATENCY-DOWN-EXACT"]),
        _case("N04-LATENCY-CAP", "AC-CAPS", "smoke",
              "net latency shift is capped: repeated increases cannot grow without bound, the cap boundary pair",
              WT("W12D-NET-CAP"), ["W12D-NET-CAP"]),
        _case("N04-BACKPRESSURE", "AC-BACKPRESSURE", "smoke",
              "positive downstream cost: delivered only if the ring takes the block by its submission deadline; abandoning a delivery does not undo a decision",
              WT("W14-BACKPRESSURE"), ["W14-BACKPRESSURE"]),
        _case("N04-ADVICE", "AC-LATENCY", "smoke",
              "latency advice from arrival margins: filling, isolated late, repeated late, cap reached (unhealthy), quiet; the boundary table",
              WT("W15-ADVICE", "W15B-ADVICE-QUIET") + T("n04_advice_table_matches_the_reference"),
              ["W15-ADVICE", "W15B-ADVICE-QUIET", "n04-advice"]),
        _case("N04-SEEDED", "AC-FAULTS", "full",
              "seeded loss, jitter, reorder, duplicate, slow and burst schedules (700 blocks each) in both policies, every decision re-derived by the reference",
              WT("W16-SEEDED-MUSIC", "W17-SEEDED-REALTIME"), ["W16-SEEDED-MUSIC", "W17-SEEDED-REALTIME"]),
        _case("N04-PROPERTIES", "AC-ONCE", "smoke",
              "on every world, with the test file's own arithmetic: queue never above the horizon, one decision per block in order, played bytes are the admitted bytes, nothing admitted at or after its cutoff, every packet has one fate",
              T("n04_properties_hold_on_every_world", "n04_counters_account_for_every_packet_and_every_decision",
                "n04_every_world_in_the_vectors_has_a_test"),
              ["n04-properties", "n04-accounting-w16-seeded-music", "n04-accounting-w17-seeded-realtime"]),
    ] + log_cases()


def log_cases() -> List[dict]:
    """Section 15: the diagnostics. The observed ids are the vectors' worlds and sink scenarios, so a world or scenario
    added to the vectors without a Rust record for it leaves its case blocked."""
    vec, _ = load_vectors()
    worlds = [log_world_id(w["id"]) for w in vec["worlds"]] if vec else []
    scenarios = [log_scenario_id(c["id"]) for c in vec.get("log_scenarios", [])] if vec else []
    return [
        _case("N04-LOG-LINES", "AC-LOG", "smoke",
              "with a sink that keeps up, every decision and every refusal (and every start, change and delivery) is one bounded ffw.log.v1 line, "
              "byte for byte the reference's; each line is a valid shared event; the decisions are the ones taken with no log",
              T("n04_log_keeps_up_logs_every_decision_and_refusal") + LT("n04_log_golden_lines_are_the_hand_assembled_ones",
                                                                         "n04_log_a_record_is_a_valid_ffw_log_v1_event_and_round_trips_byte_for_byte",
                                                                         "n04_log_the_member_and_group_appear_only_as_pseudonyms",
                                                                         "n04_log_timestamps_never_go_backwards",
                                                                         "n04_log_no_peer_supplied_text_reaches_a_record"),
              worlds),
        _case("N04-LOG-LOSS", "AC-LOG", "smoke",
              "a slow, full or unavailable sink, or a ring that is too small, loses records only with a count: emitted = delivered + queued + dropped; "
              "a lost critical record marks the evidence incomplete; an over-long line is dropped whole; the decisions do not change",
              T("n04_log_loss_is_counted_when_the_sink_is_slow_full_or_unavailable",
                "n04_log_accounting_holds_after_every_op") + LT("n04_log_an_over_long_line_is_dropped_whole_and_counted",
                                                                 "n04_log_stats_summary_line"),
              scenarios + ["n04-log-accounting"]),
        _case("N04-LOG-NONBLOCKING", "AC-LOG", "smoke",
              "the decision path never calls the sink: a sink that would block is offered nothing until a drain, and a drain makes at most its budget of offers",
              T("n04_log_a_blocking_sink_is_never_called_on_the_decision_path"), ["n04-log-blocking"]),
        _case("N04-LOG-CONFIG", "AC-LOG", "smoke",
              "labels, pseudonyms, capacity and line bound are validated; a raw identifier is never accepted as a pseudonym; diagnostics off means nothing is offered",
              LT("n04_log_config_validates_labels_pseudonyms_capacity_and_bound",
                 "n04_log_off_means_nothing_is_offered"), []),
    ]


# ---- log parsing --------------------------------------------------------------------------------------------------


class Logs(d01.Logs):
    """D01's parser, reading ``N04-OBSERVED`` records. ``ignored`` yields to a real result from another log."""

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


# ---- the reference's expected records -----------------------------------------------------------------------------


def expected_records(vec: dict) -> Dict[str, dict]:
    """Every record the Rust must print, re-derived from the reference (never from what the Rust printed)."""
    out: Dict[str, dict] = {}
    for w in vec["worlds"]:
        results = world_results(w)
        out[w["id"]] = {"id": w["id"], "digest": gen.digest(results), "results": results}
    t = vec["tables"]
    out["n04-profiles"] = {"id": "n04-profiles", "profile_version": ref.PROFILE_VERSION}
    out["n04-frames-to-ns"] = {"id": "n04-frames-to-ns", "rows": [[f, ref.frames_to_ns(f)] for f, _ in t["frames_to_ns"]]}
    out["n04-consume-by"] = {"id": "n04-consume-by", "rows": [[p, w, l, u, ref.consume_by(p, w, l, u)] for p, w, l, u, _ in t["consume_by"]]}
    out["n04-conceal-gains"] = {"id": "n04-conceal-gains", "gains": list(ref.CONCEAL_GAIN_Q15)}
    rows = []
    for r in t["conceal_blocks"]:
        blk = ref.conceal_block(ref.synth_payload(r["seed"], r["frames"]), r["run"])
        rows.append({"seed": r["seed"], "run": r["run"], "frames": r["frames"], "fnv": "%016x" % ref.fnv1a64(blk)})
    out["n04-conceal-blocks"] = {"id": "n04-conceal-blocks", "rows": rows}
    out["n04-configs"] = {"id": "n04-configs", "rows": [{"cfg": r["cfg"], "bad": ref.validate_config(ref.PROFILES["music"], r["cfg"])}
                                                          for r in t["configs"]]}
    out["n04-advice"] = {"id": "n04-advice", "rows": [ref.advice(r["margins"], r["net_shift_ns"], ref.PROFILES[r["profile"]])
                                                        for r in t["advice"]]}
    out.update(expected_log_records(vec))
    cfg = vec["defaults"]
    out["n04-sender-consume-by"] = {"id": "n04-sender-consume-by",
                                    "cutoff": ref.consume_by(2_000_000_000, cfg["work_ns"], cfg["lead_ns"], 200_000)}
    return out


@functools.lru_cache(maxsize=None)
def _sinked(key: str) -> Tuple[list, Any]:
    d = json.loads(key)
    w = d["world"]
    return ref.run_world_sinked(dict(id=w["id"], profile=w["profile"], cfg=w["cfg"], ops=[gen._op_dict(o) for o in w["ops"]]),
                                gen.LOG, d["plan"])


def log_observation(world: dict, plan: dict) -> dict:
    """The record the Rust must print for a world and a sink plan, re-derived from the reference."""
    results, ring = _sinked(json.dumps(dict(world=world, plan=plan), sort_keys=True))
    return {"results_digest": gen.digest(results), "stats": ring.stats(), "complete": ring.critical_lost == 0,
            "delivered_fnv": ["%016x" % ref.fnv1a64(l.encode("ascii")) for l in ring.delivered],
            "rest_fnv": ["%016x" % ref.fnv1a64(l.encode("ascii")) for l in ring.queue]}


def expected_log_records(vec: dict) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    by_id = {w["id"]: w for w in vec["worlds"]}
    for w in vec["worlds"]:
        out[log_world_id(w["id"])] = dict(id=log_world_id(w["id"]), **log_observation(w, vec["keeps_up"]))
    for c in vec["log_scenarios"]:
        out[log_scenario_id(c["id"])] = dict(id=log_scenario_id(c["id"]), **log_observation(by_id[c["world"]], c["plan"]))
    return out


def check_log_accounting(vec: dict, got: dict) -> Optional[str]:
    """The Rust re-checked emitted = delivered + queued + dropped after EVERY op of every world and scenario; the count
    of ops it says it checked must be the vectors' own."""
    ops = sum(len(w["ops"]) for w in vec["worlds"]) + sum(
        len(next(w for w in vec["worlds"] if w["id"] == c["world"])["ops"]) for c in vec["log_scenarios"])
    if got.get("ops_checked") != ops:
        return "checked %s ops, the vectors have %d across worlds and scenarios" % (got.get("ops_checked"), ops)
    if got.get("unaccounted") != 0:
        return "%s record(s) were neither delivered, queued nor counted as dropped" % got.get("unaccounted")
    if got.get("critical_over_dropped") != 0:
        return "critical_lost exceeded the dropped count %s times" % got.get("critical_over_dropped")
    return None


def check_log_blocking(vec: dict, got: dict) -> Optional[str]:
    """A sink that costs one second of (virtual) wall time per offer. The decision path must cost none of it."""
    ops = sum(len(w["ops"]) for w in vec["worlds"] if w["id"] == "W16-SEEDED-MUSIC")
    want = {"world": "W16-SEEDED-MUSIC", "ops": ops, "decision_path_offers": 0, "decision_path_virtual_ns": 0,
            "results_digest": gen.digest(world_results(next(w for w in vec["worlds"] if w["id"] == "W16-SEEDED-MUSIC"))),
            "drain_budget": 3, "drain_offers": 3, "drain_virtual_ns": 3_000_000_000, "queued_before_drain_nonzero": True}
    for key, value in want.items():
        if got.get(key) != value:
            return "%s: observed %s, expected %s" % (key, json.dumps(got.get(key))[:120], json.dumps(value)[:120])
    return None


def _describe_op(world: dict, index: int) -> str:
    op = world["ops"][index]
    return "op %d %s" % (index, json.dumps(op, separators=(",", ":"))[:160])


def compare_world(world: dict, want: dict, got: dict) -> Optional[str]:
    rw, rg = want["results"], got.get("results")
    if not isinstance(rg, list):
        return "no results list in the observation"
    if len(rw) != len(rg):
        return "observed %d results, reference has %d" % (len(rg), len(rw))
    for i, (a, b) in enumerate(zip(rw, rg)):
        if a != b:
            return "first divergence at %s: reference %s, observed %s" % (
                _describe_op(world, i), json.dumps(a, sort_keys=True)[:200], json.dumps(b, sort_keys=True)[:200])
    if got.get("digest") != want["digest"]:
        return "digest %s != reference %s although every result agrees" % (got.get("digest"), want["digest"])
    return None


def check_properties(vec: dict, want_ids: List[str], got: dict) -> Optional[str]:
    """The Rust property run must not be thin: every world, every decision. What it asserted is Rust-side."""
    worlds = got.get("worlds")
    if not isinstance(worlds, list) or [w.get("id") for w in worlds] != want_ids:
        return "worlds checked %r, expected %r" % ([w.get("id") for w in worlds or []], want_ids)
    for w, doc in zip(worlds, vec["worlds"]):
        decisions = sum(1 for r in world_results(doc) if r.get("poll") == "decision")
        if w.get("decisions") != decisions:
            return "%s: checked %s decisions, the reference decides %d" % (w["id"], w.get("decisions"), decisions)
        packets = [o for o in doc["ops"] if o[0] == "packet"]
        if packets and not any(o[0] == "change" for o in doc["ops"]) and w.get("admits_checked", 0) == 0:
            return "%s: no admission was checked against its cutoff" % w["id"]
    return None


def check_accounting(vec: dict, wid: str, got: dict) -> Optional[str]:
    doc = next(w for w in vec["worlds"] if w["id"] == wid)
    results = world_results(doc)
    packets = sum(1 for o in doc["ops"] if o[0] == "packet")
    decided = results[-1]["cursor"]
    if got.get("packets") != packets or got.get("decided") != decided:
        return "accounting packets=%s decided=%s, reference %d and %d" % (got.get("packets"), got.get("decided"), packets, decided)
    return None


def compare_log(oid: str, want: dict, got: dict) -> Optional[str]:
    for key in ("results_digest", "stats", "complete"):
        if got.get(key) != want[key]:
            return "%s: observed %s, reference %s" % (key, json.dumps(got.get(key))[:200], json.dumps(want[key])[:200])
    for key in ("delivered_fnv", "rest_fnv"):
        a, b = want[key], got.get(key)
        if a != b:
            if not isinstance(b, list):
                return "%s: not a list" % key
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    return "%s: line %d is %s, the reference writes %s" % (key, i, y, x)
            return "%s: %d lines observed, the reference has %d" % (key, len(b), len(a))
    return None


def compare_record(vec: dict, oid: str, want: dict, got: dict) -> Optional[str]:
    if oid.startswith(("n04-log-w", "n04-logscn-")):
        return compare_log(oid, want, got)
    if "results" in want:
        world = next(w for w in vec["worlds"] if w["id"] == oid)
        return compare_world(world, want, got)
    if got != want:
        for key in sorted(set(want) | set(got)):
            if want.get(key) != got.get(key):
                return "%s: observed %s, reference %s" % (key, json.dumps(got.get(key))[:200], json.dumps(want.get(key))[:200])
    return None


# ---- judging ------------------------------------------------------------------------------------------------------


class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, detail, group

    def as_dict(self) -> dict:
        return {"id": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def sha256_file(path: str) -> str:
    return d01.sha256_file(path)


def load_vectors() -> Tuple[Optional[dict], str]:
    if not os.path.isfile(VECTORS):
        return None, "tests/n04/vectors.json is missing (scripts/e2e/n04 --write-vectors)"
    with open(VECTORS, encoding="utf-8") as handle:
        return json.load(handle), ""


def derive_rust_tests() -> List[Tuple[str, str, bool]]:
    """(binary stem, cargo test name, ignored) for every ``n04_`` test in the sources, macro-made ones included."""
    found: List[Tuple[str, str, bool]] = []
    for rel, stem, prefix in RUST_SOURCES:
        path = os.path.join(REPO, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for attrs, name in TEST_FN.findall(source):
            found.append((stem, prefix + name, "ignore" in attrs))
        for name in WORLD_MACRO.findall(source):
            found.append((stem, prefix + name, False))
    return found


def meta_results(vec: Optional[dict], note: str) -> List[Result]:
    out: List[Result] = []

    def add(cid: str, ok: bool, detail: str) -> None:
        out.append(Result(cid, "pass" if ok else "fail", detail, "META"))

    problems = anchors.check()
    add("N04-META-ANCHORS", not problems, "; ".join(problems[:MAX_PRINTED]) or "the reference agrees with %d hand-derived anchors" % (
        len(anchors.FRAMES_TO_NS) + len(anchors.CONSUME_BY) + len(anchors.CONCEAL) + len(anchors.ADVICE)))
    if vec is None:
        out.append(Result("N04-META-VECTORS-FRESH", "fail", note, "META"))
        return out
    fresh = json.loads(_fresh_vectors())
    add("N04-META-VECTORS-FRESH", fresh == vec, "vectors.json equals a fresh generation" if fresh == vec
        else "tests/n04/vectors.json is stale: run scripts/e2e/n04 --write-vectors")

    cases = registry()
    mapped = {(stem, name) for case in cases for stem, name in case["tests"]}
    derived = {(stem, name) for stem, name, _ in derive_rust_tests()}
    src_present = bool(derived)
    missing_in_map = sorted(n for _, n in derived - mapped)
    missing_in_src = sorted(n for _, n in mapped - derived) if src_present else []
    add("N04-META-MAP-COMPLETE", not missing_in_map and not missing_in_src,
        "every Rust n04_ test is mapped to a case and every mapped test exists" if not (missing_in_map or missing_in_src)
        else "unmapped: %s; mapped but absent from the sources: %s" % (missing_in_map[:6], missing_in_src[:6]))
    observed_ids = {oid for case in cases for oid in case["observed"]}
    unjudged = sorted(w["id"] for w in vec["worlds"] if w["id"] not in observed_ids)
    add("N04-META-WORLDS-ALL-JUDGED", not unjudged, "every world in the vectors is judged by a case" if not unjudged
        else "worlds no case judges: %s" % unjudged)
    if os.path.isfile(CONTRACT):
        with open(CONTRACT, encoding="utf-8") as handle:
            contract = handle.read()
        absent = [c["id"] for c in cases if c["id"] not in contract]
        add("N04-META-CONTRACT-NAMES-CASES", not absent, "docs/contracts/n04.md names every case" if not absent
            else "cases the contract does not name: %s" % absent)
    else:
        out.append(Result("N04-META-CONTRACT-NAMES-CASES", "fail", "docs/contracts/n04.md is missing", "META"))
    return out


def judge_case(case: dict, vec: dict, want: Dict[str, dict], logs: Optional[Logs]) -> Result:
    cid, group = case["id"], case["group"]
    if logs is None:
        return Result(cid, "blocked", "no cargo test log supplied (--judge); the Rust has not been run", group)
    blocked: List[str] = []
    for stem, name in case["tests"]:
        status = logs.test_status(stem, name)
        short = name.rsplit("::", 1)[-1]
        if status in (None, "ignored"):
            blocked.append("test %s did not run" % short)
        elif status != "ok":
            return Result(cid, "fail", "test %s reported %s" % (short, status), group)
    for oid in case["observed"]:
        if oid in logs.conflicting_observations:
            return Result(cid, "fail", "conflicting observations for %s in the logs" % oid, group)
        got = logs.observed.get(oid)
        if got is None:
            blocked.append("no observation for %s" % oid)
            continue
        if oid == "n04-properties":
            why = check_properties(vec, [w["id"] for w in vec["worlds"]], got)
        elif oid == "n04-log-accounting":
            why = check_log_accounting(vec, got)
        elif oid == "n04-log-blocking":
            why = check_log_blocking(vec, got)
        elif oid.startswith("n04-accounting-"):
            why = check_accounting(vec, oid[len("n04-accounting-"):].upper(), got)
        else:
            why = compare_record(vec, oid, want[oid], got)
        if why:
            return Result(cid, "fail", "%s: %s" % (oid, why), group)
    if blocked:
        return Result(cid, "blocked", "; ".join(blocked[:MAX_PRINTED]), group)
    return Result(cid, "pass", "%d tests ok, %d records re-derived from the reference" % (len(case["tests"]), len(case["observed"])), group)


def run(tier: str, logs: Optional[Logs]) -> Tuple[List[Result], dict]:
    vec, note = load_vectors()
    results = meta_results(vec, note)
    meta = {"vectors_sha256": sha256_file(VECTORS) if vec is not None else None, "profile_version": ref.PROFILE_VERSION}
    if vec is None:
        return results, meta
    want = expected_records(vec)
    for case in registry():
        if tier == "smoke" and case["tier"] == "full":
            continue
        results.append(judge_case(case, vec, want, logs))
    if logs is not None:
        for stem, name, ignored in derive_rust_tests():
            if ignored:
                continue
            if logs.test_status(stem, name) is None:
                results.append(Result("N04-META-TESTS-EXIST:" + name.rsplit("::", 1)[-1], "blocked",
                                      "not present in any supplied log", "META"))
    return results, meta


def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "blocked")}


def exit_code(results: List[Result]) -> int:
    s = summarize(results)
    return 1 if s["fail"] else 3 if s["blocked"] else 0


def report(results: List[Result], tier: str) -> None:
    for r in results:
        print("%-8s %-34s %s" % (r.status.upper(), r.case_id, r.detail))
    s = summarize(results)
    verdict = "QUALIFIED" if exit_code(results) == 0 else "NOT QUALIFIED"
    print("N04 cases: tier=%s total=%d passed=%d failed=%d blocked=%d -> %s" % (
        tier, len(results), s["pass"], s["fail"], s["blocked"], verdict))
    for item in NOT_MEASURED:
        print("NOT MEASURED  %s: %s" % (item["item"], item["status"]))


def write_receipt(directory: str, tier: str, results: List[Result], meta: dict, logs: Optional[Logs]) -> str:
    os.makedirs(directory, exist_ok=True)
    run_id = secrets.token_hex(8)
    doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier,
           "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "summary": summarize(results), "meta": meta, "not_measured": NOT_MEASURED,
           "logs": [{"name": os.path.basename(p), "sha256": d} for p, d in (logs.files if logs else [])],
           "results": [r.as_dict() for r in results]}
    path = os.path.join(directory, "n04-receipt-%s.json" % run_id)
    with open(path, "x", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--write-vectors", action="store_true")
    parser.add_argument("--judge", nargs="+", metavar="LOG")
    parser.add_argument("--receipts", metavar="DIR")
    args = parser.parse_args(argv)
    if args.write_vectors:
        doc = gen.build()
        with open(VECTORS, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        print("wrote %s (%d worlds, sha256 %s)" % (VECTORS, len(doc["worlds"]), sha256_file(VECTORS)))
        return 0
    if args.list:
        for case in registry():
            print("%-24s %-6s %s" % (case["id"], case["tier"], case["what"]))
        return 0
    logs: Optional[Logs] = None
    if args.judge:
        logs = Logs()
        for path in args.judge:
            if not os.path.isfile(path):
                sys.stderr.write("run_cases: no such log: %s\n" % path)
                return 2
            logs.add(path)
    results, meta = run(args.tier, logs)
    report(results, args.tier)
    if args.receipts:
        print("receipt:", write_receipt(args.receipts, args.tier, results, meta, logs))
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
