#!/usr/bin/env python3
"""Anchors for the N03 reference: numbers worked out by hand (in the comments), and brute-force cross-checks
that use a different route from the reference's own formulas.  If the reference were wrong, a Rust
implementation that copied it would agree with it, so the reference itself is checked here.

    python3 -B -I tests/n03/anchors.py        # exit 0 when every anchor holds
"""
from __future__ import annotations

import importlib.util
import os
import sys
from typing import Callable, List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str):
    spec = importlib.util.spec_from_file_location("n03_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
D = ref.DEFAULTS
NS = ref.NS
S = NS


def _sample(delay: int, local_mid: int, group_mid: int = 0):
    return {"delay": delay, "local_mid": local_mid, "group_mid": group_mid}


def a_hand_exchange() -> Tuple[bool, str]:
    # t1=1.000000000 s t2=5.000200000 s t3=5.000250000 s t4=1.000450000 s:
    # rtt=450000, dwell=50000, delay=400000; local_mid=1000000000+225000; group_mid=5000200000+25000.
    s = ref.sample(1_000_000_000, 5_000_200_000, 5_000_250_000, 1_000_450_000, D)
    want = {"delay": 400_000, "local_mid": 1_000_225_000, "group_mid": 5_000_225_000, "offset": 4_000_000_000}
    return s == want, "%s" % (s,)


def a_hand_odd_halves() -> Tuple[bool, str]:
    # t1=1 t2=10 t3=13 t4=6: rtt=5, dwell=3, delay=2; local_mid=1+5//2=3; group_mid=10+3//2=11.
    s = ref.sample(1, 10, 13, 6, D)
    return s == {"delay": 2, "local_mid": 3, "group_mid": 11, "offset": 8}, "%s" % (s,)


def a_hand_rejections() -> Tuple[bool, str]:
    cases = [
        (ref.sample(5, 0, 0, 5, D), "LocalClockRegression"),
        (ref.sample(5, 0, 0, 4, D), "LocalClockRegression"),
        (ref.sample(0, 0, 0, D["request_ttl_ns"] + 1, D), "ExpiredRequest"),
        (ref.sample(0, 9, 8, 100, D), "Malformed"),
        (ref.sample(0, (1 << 62) + 1, (1 << 62) + 1, 100, D), "Malformed"),
        (ref.sample(0, 0, 101, 100, D), "Malformed"),
        (ref.sample(0, 0, 0, 50_000_001, D), "ExcessiveDelay"),
    ]
    bad = [(g, w) for g, w in cases if g != w]
    ok_edges = [ref.sample(0, 0, 0, 50_000_000, D), ref.sample(0, 1 << 62, 1 << 62, 100, D)]
    return not bad and all(isinstance(e, dict) for e in ok_edges), "mismatches %s" % (bad,)


def a_hand_uncertainty() -> Tuple[bool, str]:
    # delay 400000: half is 200000, plus 1000 resolution, plus 0 calibration = 201000.
    # age 6 ms at 100 ppm (100000 ppb) = 6e6*1e5/1e9 = 600 ns; one ns at 1 ppb rounds UP to 1.
    s = _sample(400_000, 1_000_000_000)
    got = (ref.base_ns(400_000, D), ref.unc_at(s, s["local_mid"] + 6_000_000, 100_000, D),
           ref.unc_at(s, s["local_mid"] + 1, 1, D), ref.unc_at(s, s["local_mid"] - 5, 100_000, D))
    return got == (201_000, 201_600, 201_001, 201_000), "%s" % (got,)


def a_hand_odd_delay_rounds_up() -> Tuple[bool, str]:
    # an odd delay 401: half is 200.5 -> 201 (ceil), so the bound never shrinks below the true asymmetry bound
    return ref.base_ns(401, D) == 201 + 1000, "%d" % ref.base_ns(401, D)


def a_hand_transform() -> Tuple[bool, str]:
    # +80 ppm over 5 s: 5e9 * 1.00008 = 5 000 400 000 ns past the anchor; the inverse recovers 5e9 exactly.
    s = _sample(0, 10 * S, 9_000 * S)
    g = ref.group_at(s, 15 * S, 80_000)
    back = ref.local_of(s, g, 80_000)
    # -80 ppm backwards 5 s: floor(-5e9 * 0.99992) = -4 999 600 000 exactly
    g2 = ref.group_at(s, 5 * S, -80_000)
    # floor on a fraction: 999 999 999 ns at 333 333 ppb = 999 999 999 + 999 999 999*333 333/1e9 = 999 999 999 + 333 332.67
    # = 1 000 333 331.67 -> floor 1 000 333 331
    g3 = ref.group_at(s, 10 * S + 999_999_999, 333_333) - s["group_mid"]
    # the group clock never goes below zero
    g4 = ref.group_at(_sample(0, 1_000, 100), 0, 0)
    got = (g, back, g2, g3, g4)
    want = (9_000 * S + 5_000_400_000, 15 * S, 9_000 * S - 4_999_600_000, 1_000_333_331, 0)
    return got == want, "%s" % (got,)


def a_hand_holdover() -> Tuple[bool, str]:
    # delay 400000: base 201000; headroom to the 2 ms threshold = 1 799 000 ns; at 100 ppm that takes
    # 1 799 000 * 1e9 / 1e5 = 17 990 000 000 ns; the first instant over is one ns later:
    # 100 s + 17.99 s + 1 ns = 117 990 000 001.
    s = _sample(400_000, 100 * S)
    a = ref.holdover(s, 100_000, D, None, None)
    b = ref.holdover(s, 100_000, D, 105 * S, 110 * S)          # authority is the smaller
    c = ref.holdover(s, 100_000, D, 120 * S, 103 * S)          # buffer is the smaller
    d = ref.holdover(s, 100_000, D, 104 * S, 104 * S)          # a tie: authority wins
    e = ref.holdover(s, 0, D, None, None)                      # a perfectly known ratio never expires on uncertainty
    got = (a, b, c, d, e)
    want = ((117_990_000_001, "Uncertainty"), (105 * S, "Authority"), (103 * S, "Buffer"), (104 * S, "Authority"),
            (ref.U64_MAX, "Uncertainty"))
    return got == want, "%s" % (got,)


def a_hand_plan() -> Tuple[bool, str]:
    # anchor: local_mid 100 s, group_mid 8000 s, ratio 0. now = 101 s -> group now = 8001 s. A start 2 s ahead is
    # group 8003 s = local 103 s; the member must be ready 0.1 s earlier (deadline 102.9 s). Uncertainty at the
    # start: 201000 + ceil(3 s * 100 ppm) = 201000 + 300000 = 501000. Holdover limit 117.99 s > 103 s.
    s = _sample(400_000, 100 * S, 8_000 * S)
    r = ref.plan_start(s, 0, 100_000, D, now=101 * S, epoch=5, sched_epoch=5, sched_start_group_ns=8_003 * S,
                       status="Locked", authority_until=None, buffer_until=None)
    want = {"ok": True, "start_local_ns": 103 * S, "deadline_local_ns": 102_900_000_000,
            "uncertainty_at_start_ns": 501_000, "valid_until_local_ns": 117_990_000_001, "binding": "Uncertainty"}
    # a 1.85 ms output delay moves the local start earlier by exactly that
    r2 = ref.plan_start(s, 0, 100_000, dict(D, output_delay_ns=1_850_000), now=101 * S, epoch=5, sched_epoch=5,
                        sched_start_group_ns=8_003 * S, status="Locked", authority_until=None, buffer_until=None)
    return r == want and r2["start_local_ns"] == 103 * S - 1_850_000, "%s | %s" % (r, r2)


def a_plan_check_order() -> Tuple[bool, str]:
    s = _sample(400_000, 100 * S, 8_000 * S)

    def go(**kw):
        a = dict(now=101 * S, epoch=5, sched_epoch=5, sched_start_group_ns=8_003 * S, status="Locked",
                 authority_until=None, buffer_until=None)
        a.update(kw)
        return ref.plan_start(s, 0, 100_000, D, **a).get("reject", "ok")
    got = [go(sched_epoch=4, status="Unlocked"), go(sched_epoch=6, status="Unlocked"), go(status="Holdover"),
           go(sched_start_group_ns=8_001 * S + D["max_future_ns"] + 1), go(sched_start_group_ns=8_001 * S + D["catchup_ns"] - 1),
           go(authority_until=102 * S)]
    want = ["StaleEpoch", "FutureEpoch", "NotLocked", "TooFarAhead", "TooLate", "ExpiresBeforeStart"]
    return got == want, "%s" % (got,)


def a_hand_frame_position() -> Tuple[bool, str]:
    # 1 s is 48 000 frames. 2^32 frames at 48 kHz = 89 478 485 333.33 s (24.86 h).
    wrap_ns = (1 << 32) * NS // 48_000
    got = (ref.frame_position(NS), ref.frame_position(wrap_ns - 1), ref.frame_position(wrap_ns + 1_000),
           ref.frame_position(5 * S), ref.frame_position(5 * S + wrap_ns), wrap_ns)
    return got == (48_000, 0xFFFFFFFF, 0, 240_000, 239_999, 89_478_485_333_333), "%s" % (got,)


def a_asymmetry_bias() -> Tuple[bool, str]:
    # forward 3 ms, return 0.5 ms: the four timestamps put the midpoint (3.5 ms)/2 = 1.75 ms into the exchange but
    # the request was received at 3 ms: the estimate is high by 1.25 ms = (3.0 - 0.5)/2.
    g = ref.World(0, 1_000_000_000, 5_000_000_000_000, 1)
    t1, t2, t3, t4 = g.exchange(0, 3_000_000, 50_000, 500_000)
    s = ref.sample(t1, t2, t3, t4, D)
    true_offset = 5_000_000_000_000 - 1_000_000_000
    return s["offset"] - true_offset == ref.asymmetry_bias_ns(3_000_000, 500_000) == 1_250_000, "%d" % (s["offset"] - true_offset)


def b_selection_matches_a_naive_sort() -> Tuple[bool, str]:
    g = ref.lcg(5)
    for trial in range(300):
        n = 1 + next(g) % 8
        samples = [_sample(next(g) % 3_000_000, next(g) % (10 * S), 0) for _ in range(n)]
        for i, s in enumerate(samples):
            s["group_mid"] = i                                                   # make every sample distinguishable
        now = next(g) % (12 * S)
        ru = (0, 6_000, 100_000)[next(g) % 3]
        want = sorted(range(n), key=lambda i: (ref.unc_at(samples[i], now, ru, D), -samples[i]["local_mid"], -i))[0]
        got, unc = ref.select(samples, now, ru, D)
        if got != want or unc != ref.unc_at(samples[want], now, ru, D):
            return False, "trial %d: %s vs %s" % (trial, got, want)
    return True, "300 random sets"


def b_holdover_edge_is_exactly_where_uncertainty_crosses() -> Tuple[bool, str]:
    g = ref.lcg(6)
    for trial in range(300):
        delay = next(g) % 3_800_000
        s = _sample(delay, 50 * S + next(g) % S)
        ru = 1 + next(g) % 400_000
        until, binding = ref.holdover(s, ru, D, None, None)
        if ref.base_ns(delay, D) > D["lock_uncertainty_ns"]:
            continue                                                             # no headroom at all
        edge_ok = ref.unc_at(s, until - 1, ru, D) <= D["lock_uncertainty_ns"] < ref.unc_at(s, until, ru, D)
        if binding != "Uncertainty" or (until > s["local_mid"] and not edge_ok):
            return False, "trial %d delay=%d ru=%d until=%d" % (trial, delay, ru, until)
    return True, "300 random cases: last allowed instant and first refused instant bracket the threshold"


def b_transform_round_trip_and_monotone() -> Tuple[bool, str]:
    g = ref.lcg(7)
    worst = 0
    for _ in range(500):
        s = _sample(0, 10 * S + next(g) % S, 9_000 * S + next(g) % S)
        ratio = int(next(g) % 1_000_001) - 500_000
        t = s["local_mid"] + int(next(g) % (30 * S))
        gg = ref.group_at(s, t, ratio)
        back = ref.local_of(s, gg, ratio)
        worst = max(worst, abs(back - t))
        if ref.group_at(s, t + 1, ratio) < gg:
            return False, "group_at is not monotone"
    return worst <= 1, "worst round trip %d ns" % worst


def c_model_hand_sequence() -> Tuple[bool, str]:
    # Eight symmetric probes one second apart, 200 us each way, 50 us dwell. Hand-derived expectations:
    # statuses Unlocked x3 then Locked (the 4th accepted probe reaches min_probes_for_lock = 4); the 8th probe has 8
    # observations over 7 s so a rate estimate (an exact line: ratio 0, sigma 0) is in force, ratio_unc = 0*3 + 6000.
    w = ref.World(0, 5_000_000_000, 9_000_000_000_000, 1000)
    ops = []
    for k in range(8):
        t1, t2, t3, t4 = w.exchange(k * S, 200_000, 50_000, 200_000)
        ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4})
    now = w.local(7 * S + 500 * 1_000_000)
    ops.append({"op": "check", "now": now})
    r = ref.run_script(None, 1, 7, 1000, ops)
    statuses = [x["status"] for x in r[:8]]
    chk = r[8]
    ok = (statuses == ["Unlocked"] * 3 + ["Locked"] * 5 and r[7]["rate_in_force"] and not r[6]["rate_in_force"]
          and chk["ratio_ppb"] == 0 and chk["ratio_unc_ppb"] == 6000
          and chk["group_ns"] == w.group(7 * S + 500_000_000) and chk["mute"] == "NotAdmitted")
    # uncertainty: base 201000 + ceil(age * 6000 ppb); age = now - local_mid of the 8th probe
    mid = r and ops[7]["t1"] + (ops[7]["t4"] - ops[7]["t1"]) // 2
    ok = ok and chk["uncertainty_ns"] == 201_000 + -(-(now - mid) * 6000 // NS)
    return ok, "%s %s" % (statuses, {k: chk[k] for k in ("uncertainty_ns", "ratio_ppb", "ratio_unc_ppb", "group_ns")})


def c_model_unlocked_cannot_output() -> Tuple[bool, str]:
    w = ref.World(0, 5_000_000_000, 9_000_000_000_000, 1000)
    ops = []
    for k in range(3):
        t1, t2, t3, t4 = w.exchange(k * S, 200_000, 50_000, 200_000)
        ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4})
    n = ops[-1]["t4"] + 1_000_000
    ops.append({"op": "admit", "now": n, "sched": {"epoch": 1, "start_group_ns": w.group(5 * S)}})
    ops.append({"op": "tick", "now": w.local(5 * S) + 1_000_000})
    r = ref.run_script(None, 1, 7, 1000, ops)
    # events, by hand: the refused admission is logged with its cause; the first tick logs the muted output
    return (r[3]["result"] == "NotLocked" and r[3]["events"] == ["n03.admit.rejected:NotLocked"]
            and r[4] == {"op": "tick", "output": "Muted", "mute": "NotLocked", "rate_in_force": False,
                         "events": ["n03.output.muted:NotLocked"]}), "%s" % (r[3:],)


def c_model_stale_and_replay() -> Tuple[bool, str]:
    m = ref.Model(None, 2, 7, 10)
    req = m.next_probe(1_000)
    resp = {"epoch": 1, "leader": 7, "seq": req["seq"], "t1_echo": 1_000, "t2": 5_000, "t3": 5_050}
    first = m.on_response(dict(resp, epoch=1), 1_450)                              # stale epoch
    second = m.on_response(dict(resp, epoch=3), 1_450)                             # future epoch
    third = m.on_response(dict(resp, epoch=2, leader=9), 1_450)                    # unadmitted leader
    fourth = m.on_response(dict(resp, epoch=2), 1_450)                             # accepted
    fifth = m.on_response(dict(resp, epoch=2), 1_460)                              # replay of the accepted one
    return (first, second, third, fifth) == (("reject", "StaleEpoch"), ("reject", "FutureEpoch"),
                                               ("reject", "UnadmittedLeader"), ("reject", "UnsolicitedOrReplayed")) and fourth[0] == "ok", \
        "%s %s %s %s %s" % (first, second, third, fourth, fifth)


def d_truth_bound_in_a_noisy_world() -> Tuple[bool, str]:
    # The central claim, once more, against the Python port of the Rust-side independent world.
    runs = [ref.sim_run(*w) for w in ref.SIM_WORLDS]
    return all(r["checks"] > 100 and r["locked"] and r["min_margin_ns"] >= 0 for r in runs), \
        "min margins %s ns" % [r["min_margin_ns"] for r in runs]


def e_rate_estimator_model_matches_the_d03_reference() -> Tuple[bool, str]:
    # An exact line of 9 observations 1 s apart: ratio 0 and zero uncertainty from the D03 reference's own fit.
    d03 = ref.load_d03_reference()
    obs = [(48_000 * k, 1_000_000_000 + k * 1_000_000) for k in range(9)]
    ratio, unc = d03.ls_fit(obs)
    r = ref.RateModel()
    for pos, us in obs:
        r.observe(pos & 0xFFFFFFFF, us)
    e = r.estimate
    return (ratio, unc) == (0, 0.0) and e is not None and e["ratio_ppb"] == 0 and e["status"] == "Valid", "%s %s" % (ratio, e)


def f_event_sequence_by_hand() -> Tuple[bool, str]:
    # Four good exchanges: the relock progress counts 1/4 .. 4/4 and the fourth also logs the lock. A replayed
    # answer logs its rejection only. A 2 s step of the group clock logs the rejection, the reset and the fall to
    # unlocked, in that order. The progress then starts again from 1/4.
    w = ref.World(0, 5_000_000_000, 9_000_000_000_000, 1000)
    ops = []
    for k in range(4):
        t1, t2, t3, t4 = w.exchange(k * S, 200_000, 50_000, 200_000)
        ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4})
    ops.append({"op": "replay", "of": 3, "t4": ops[3]["t4"] + 1_000})
    w2 = ref.World(0, 5_000_000_000, 9_000_000_000_000 + 2 * S, 1000)
    t1, t2, t3, t4 = w2.exchange(5 * S, 200_000, 50_000, 200_000)
    ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4})
    t1, t2, t3, t4 = w2.exchange(6 * S, 200_000, 50_000, 200_000)
    ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4})
    r = ref.run_script(None, 1, 7, 1000, ops)
    got = [x["events"] for x in r]
    want = [["n03.probe.accepted@1/4"], ["n03.probe.accepted@2/4"], ["n03.probe.accepted@3/4"],
            ["n03.probe.accepted@4/4", "n03.status.locked"],
            ["n03.probe.rejected:UnsolicitedOrReplayed"],
            ["n03.probe.rejected:Discontinuity", "n03.reset:Discontinuity", "n03.status.unlocked"],
            ["n03.probe.accepted@1/4"]]
    return got == want, "%s" % (got,)


def f_event_ring_accounting_by_hand() -> Tuple[bool, str]:
    # 100 unsolicited responses into a 64-event ring: 64 pending, 36 dropped. Then 70 critical epoch events: the
    # first 64 each evict one ordinary event (dropped +64 -> 100), the ring is then all critical, so the last 6 are
    # dropped and counted lost: emitted 170 = 64 pending + 106 dropped, critical_lost 6.
    got = ref.ring_scenario()

    def stats(**kw):
        base = {"emitted": 0, "delivered": 0, "dropped_ordinary": 0, "evicted_ordinary": 0, "lost_critical": 0,
                "rate_limited": 0, "unavailable_drops": 0, "regression_drops": 0, "dropped": 0, "critical_lost": 0,
                "pending": 0}
        base.update(kw)
        return base
    # rate: 100 responses 1 us apart in one 1 s window with 32 admitted per window: 32 stored, 68 refused.
    # unavailable: 10 ordinary + 3 critical events offered to a down log: all 13 dropped, the 3 critical ones lost.
    want = {"after_rejections": stats(emitted=100, dropped=36, dropped_ordinary=36, pending=64),
            "final": stats(emitted=170, dropped=106, dropped_ordinary=36, evicted_ordinary=64, lost_critical=6,
                           critical_lost=6, pending=64),
            "pending_kinds": ["n03.epoch.begin"],
            "rate": stats(emitted=100, dropped=68, rate_limited=68, pending=32),
            "unavailable": stats(emitted=13, dropped=13, unavailable_drops=13, critical_lost=3)}
    return got == want, "%s" % (got,)


def f_truth_events_by_hand() -> Tuple[bool, str]:
    # An exact world: the estimate equals the truth (error 0, within); a truth one nanosecond outside the reported
    # uncertainty is a violation with the signed error.
    w = ref.World(0, 5_000_000_000, 9_000_000_000_000, 1000)
    m = ref.Model(None, 1, 7, 1000)
    for k in range(4):
        t1, t2, t3, t4 = w.exchange(k * S, 200_000, 50_000, 200_000)
        req = m.next_probe(t1)
        m.on_response({"epoch": 1, "leader": 7, "seq": req["seq"], "t1_echo": t1, "t2": t2, "t3": t3}, t4)
    m.drain_events()
    now = w.local(3 * S + 2_000_000)
    exact = w.group(3 * S + 2_000_000)
    e0 = m.note_truth(now, exact)
    unc = m._anchor(now)["unc"]
    e1 = m.note_truth(now, exact + unc + 1)
    kinds = [ev["kind"] for ev in m.drain_events()]
    return (e0 == 0 and e1 == -(unc + 1) and kinds == ["n03.truth.within", "n03.truth.violated"]), "%s %s %s" % (e0, e1, kinds)


ANCHORS: List[Tuple[str, Callable[[], Tuple[bool, str]]]] = [
    ("hand exchange", a_hand_exchange),
    ("hand odd halves", a_hand_odd_halves),
    ("hand rejections and edges", a_hand_rejections),
    ("hand uncertainty", a_hand_uncertainty),
    ("odd delay rounds up", a_hand_odd_delay_rounds_up),
    ("hand transform", a_hand_transform),
    ("hand holdover", a_hand_holdover),
    ("hand plan", a_hand_plan),
    ("plan check order", a_plan_check_order),
    ("hand frame position", a_hand_frame_position),
    ("asymmetry bias is (df-dr)/2", a_asymmetry_bias),
    ("selection equals a naive sort", b_selection_matches_a_naive_sort),
    ("holdover edge brackets the threshold", b_holdover_edge_is_exactly_where_uncertainty_crosses),
    ("transform round trip", b_transform_round_trip_and_monotone),
    ("model hand sequence", c_model_hand_sequence),
    ("unlocked cannot output", c_model_unlocked_cannot_output),
    ("stale epoch, replay, unadmitted leader", c_model_stale_and_replay),
    ("truth bound in the noisy world", d_truth_bound_in_a_noisy_world),
    ("rate model agrees with the D03 reference", e_rate_estimator_model_matches_the_d03_reference),
    ("event sequence by hand", f_event_sequence_by_hand),
    ("event ring accounting by hand", f_event_ring_accounting_by_hand),
    ("truth events by hand", f_truth_events_by_hand),
]


def check() -> List[Tuple[str, bool, str]]:
    out = []
    for name, fn in ANCHORS:
        try:
            ok, detail = fn()
        except Exception as exc:                               # an anchor that raises is a failed anchor
            ok, detail = False, "raised %r" % (exc,)
        out.append((name, bool(ok), detail))
    return out


def main() -> int:
    results = check()
    for name, ok, detail in results:
        print("%-5s %-44s %s" % ("PASS" if ok else "FAIL", name, "" if ok else detail))
    bad = [n for n, ok, _ in results if not ok]
    print("%d anchors, %d failed" % (len(results), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
