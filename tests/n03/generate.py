#!/usr/bin/env python3
"""N03 vector generator: builds tests/n03/vectors.json from the independent reference only.

    python3 -B -I tests/n03/generate.py [--check]

``--check`` exits 1 if the committed file differs from a fresh generation (a stale or hand-edited file
fails).  Deterministic: fixed seeds, sorted keys, no clock, no environment.

Every world is simulated with known truth.  After a world's script has run through the reference model,
this generator asserts the contract's central claim against that truth: wherever the member reports a group
time and an uncertainty, the true group time is within the uncertainty.  A world that breaks the claim is a
generator failure, not a vector.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
VECTORS = os.path.join(HERE, "vectors.json")


def _ref():
    spec = importlib.util.spec_from_file_location("n03_reference", os.path.join(HERE, "reference.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _ref()
NS = ref.NS
S = NS                                   # one second
MS = 1_000_000
US = 1_000
D = ref.DEFAULTS
WRAP_NS = (1 << 32) * NS // 48_000       # group time at which the u32 frame counter wraps (24.86 h)

# ---- op builders ---------------------------------------------------------------------------------


def probe(w: "ref.World", ts: int, df: int, wd: int, dr: int, **extra: Any) -> Dict[str, Any]:
    t1, t2, t3, t4 = w.exchange(ts, df, wd, dr)
    op = {"op": "probe", "t1": t1, "t2": t2, "t3": t3, "t4": t4}
    op.update(extra)
    return op


def exact(t1: int, goff: int, df: int, wd: int, dr: int, **extra: Any) -> Dict[str, Any]:
    """An exchange in a world with no skew and no quantization: group = local + goff."""
    t2 = t1 + df + goff
    op = {"op": "probe", "t1": t1, "t2": t2, "t3": t2 + wd, "t4": t1 + df + wd + dr}
    op.update(extra)
    return op


def check(now: int, truth: Optional[int] = None, **extra: Any) -> Dict[str, Any]:
    op: Dict[str, Any] = {"op": "check", "now": now}
    if truth is not None:
        op["truth_group"] = truth
    op.update(extra)
    return op


def tcheck(w: "ref.World", now: int, **extra: Any) -> Dict[str, Any]:
    """A check carrying the true group time at the instant the (skew-free) local reading ``now`` was taken."""
    assert w.skew == 0, "tcheck inverts the local clock exactly only without skew"
    return check(now, w.group(now - w.local0), **extra)


def world_def(wid: str, ops: List[Dict[str, Any]], *, cfg: Optional[Dict[str, int]] = None, epoch: int = 1,
              leader: int = 7, seq_base: int = 1000, tags: Optional[List[str]] = None, note: str = "",
              world: Optional["ref.World"] = None) -> Dict[str, Any]:
    d: Dict[str, Any] = {"id": wid, "cfg": cfg or {}, "epoch": epoch, "leader": leader, "seq_base": seq_base,
                         "ops": ops, "tags": tags or [], "note": note}
    if world is not None:
        d["clocks"] = {"skew_ppb": world.skew, "local0": world.local0, "group0": world.group0, "res_ns": world.res}
    return d


def tol_for(rec: Dict[str, Any], op: Dict[str, Any]) -> Dict[str, int]:
    """Tolerances for the fields that depend on the rate estimator's float uncertainty (+/-1 ppb x sigma multiple).
    Only when a rate estimate is in force; otherwise every field is exact."""
    if not rec.get("rate_in_force") or "uncertainty_ns" not in rec:
        return {}
    age = max(0, op.get("now", 0) - rec["anchor_local_mid"])
    tol = {"uncertainty_ns": -(-age * 4 // NS) + 2, "ratio_unc_ppb": 4}
    if "holdover_until" in rec:
        span = max(0, rec["holdover_until"] - rec["anchor_local_mid"])
        tol["holdover_until"] = span * 4 // max(1, rec["ratio_unc_ppb"]) + 2
    return tol


def expect_for(wdef: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = ref.run_script(wdef["cfg"], wdef["epoch"], wdef["leader"], wdef["seq_base"], wdef["ops"])
    for rec, op in zip(results, wdef["ops"]):
        if op["op"] == "check":
            t = tol_for(rec, op)
            if t:
                rec["tol"] = t
    return results


def assert_truth(wdef: Dict[str, Any], results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The central claim, against known truth."""
    worst = {"checks": 0, "max_err_ns": 0, "max_unc_ns": 0, "min_margin_ns": None}
    for op, rec in zip(wdef["ops"], results):
        if op["op"] == "check" and "truth_group" in op:
            assert "group_ns" in rec, (wdef["id"], op, rec)
            err = abs(rec["group_ns"] - op["truth_group"])
            assert err <= rec["uncertainty_ns"], (wdef["id"], "error %d exceeds uncertainty %d at now=%d" % (
                err, rec["uncertainty_ns"], op["now"]))
            margin = rec["uncertainty_ns"] - err
            worst["checks"] += 1
            worst["max_err_ns"] = max(worst["max_err_ns"], err)
            worst["max_unc_ns"] = max(worst["max_unc_ns"], rec["uncertainty_ns"])
            worst["min_margin_ns"] = margin if worst["min_margin_ns"] is None else min(worst["min_margin_ns"], margin)
    return worst


# ---- the worlds ----------------------------------------------------------------------------------

G0 = 9_000_000_000_000        # an arbitrary group-clock base: 2.5 hours
L0 = 5_000_000_000


def sym_world(skew: int = 0, group0: int = G0, local0: int = L0) -> "ref.World":
    return ref.World(skew, local0, group0)


def worlds() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    # ---- S01 symmetric path: lock at the fourth probe, truth within uncertainty ---------------------
    w = sym_world()
    ops = [probe(w, k * S, 200 * US, 50 * US, 200 * US) for k in range(12)]
    ops.insert(3, check(w.local(3 * S + 450 * US), w.group(3 * S + 450 * US)))        # before the 4th probe ends
    ops.insert(5, check(w.local(3 * S + 600 * US), w.group(3 * S + 600 * US)))
    ops += [check(w.local(11 * S + 700 * US), w.group(11 * S + 700 * US)),
            check(w.local(11 * S + 900 * MS), w.group(11 * S + 900 * MS))]
    out.append(world_def("S01-SYMMETRIC", ops, world=w, tags=["positive:join", "lock-time"],
                         note="symmetric 200 us paths, no skew: unlocked until the fourth exchange, then locked"))

    # ---- S02 asymmetric but lockable: the bias is exactly (df-dr)/2 and is inside the uncertainty -----
    w = sym_world()
    df, dr = 3 * MS, 500 * US
    bias = ref.asymmetry_bias_ns(df, dr)
    ops = []
    for k in range(8):
        ts = k * S
        tm = ts + (df + 50 * US + dr) // 2                       # true midpoint of the exchange
        ops.append(probe(w, ts, df, 50 * US, dr, truth_offset=w.group(tm) - w.local(tm), bias_ns=bias))
    ops += [check(w.local(7 * S + 5 * MS), w.group(7 * S + 5 * MS)),
            check(w.local(8 * S + 800 * MS), w.group(8 * S + 800 * MS))]
    out.append(world_def("S02-ASYMMETRIC-LOCKABLE", ops, world=w, tags=["asymmetric-delay"],
                         note="forward 3 ms, return 0.5 ms: offset error is exactly 1.25 ms; the uncertainty covers it"))

    # ---- S03 asymmetric and too wide to trust: never locks, never audible --------------------------
    w = sym_world()
    df, dr = 7 * MS, 1 * MS
    ops = [probe(w, k * S, df, 50 * US, dr) for k in range(10)]
    ops += [check(w.local(9 * S + 9 * MS), w.group(9 * S + 9 * MS)),
            {"op": "tick", "now": w.local(9 * S + 9 * MS)},
            {"op": "admit", "now": w.local(9 * S + 9 * MS),
             "sched": {"epoch": 1, "start_group_ns": w.group(11 * S)}}]
    out.append(world_def("S03-ASYMMETRIC-TOO-WIDE", ops, world=w, tags=["negative:no-promise-from-offset-alone"],
                         note="8 ms round trip: error is 3 ms but the uncertainty (4 ms) is above the 2 ms threshold"))

    # ---- S04/S05 drift with jitter: the rate estimate comes into force, and truth stays inside ----------
    for sid, skew, seed in (("S04-DRIFT-FAST", 80_000, 11), ("S05-DRIFT-SLOW", -80_000, 12)):
        w = sym_world(skew)
        g = ref.lcg(seed)

        def jit() -> int:
            return 150 * US + next(g) % (400 * US)
        ops = []
        for k in range(40):
            ts = k * S + 3 * MS * (k % 3)
            p = probe(w, ts, jit(), 50 * US, jit())
            ops.append(p)
            t_true = ts + 2 * MS + 2 * MS                      # a little after the exchange ended (< 1.2 ms)
            ops.append(check(w.local(t_true), w.group(t_true)))
        for t_true in (40 * S + 300 * MS, 41 * S + 900 * MS):
            ops.append(check(w.local(t_true), w.group(t_true)))
        out.append(world_def(sid, ops, world=w, tags=["drift"],
                             note="skew %+d ppb, 150-550 us seeded jitter per direction, probe each second" % skew))

    # ---- S06 the group frame counter wraps mid-run; the rate estimate is unaffected ------------------
    w = sym_world(50_000, group0=WRAP_NS - 15 * S)
    g = ref.lcg(21)

    def jit2() -> int:
        return 50 * US + next(g) % (100 * US)
    ops = []
    for k in range(40):
        ts = k * S
        ops.append(probe(w, ts, jit2(), 30 * US, jit2()))
        t_true = ts + 2 * MS
        ops.append(check(w.local(t_true), w.group(t_true)))
    out.append(world_def("S06-WRAP", ops, world=w, tags=["wrap", "positive:wrap-accepted"],
                         note="group time crosses 2^32 frames (24.86 h) after 15 s; +50 ppm skew"))

    # ---- S07 probes stop: holdover is min(buffer, authority, uncertainty); expiry mutes; recovery is muted --
    def good_prefix(w: "ref.World", n: int = 8) -> List[Dict[str, Any]]:
        return [probe(w, k * S, 200 * US, 50 * US, 200 * US) for k in range(n)]

    for sid, variant in (("S07A-HOLDOVER-UNCERTAINTY", "unc"), ("S07B-HOLDOVER-AUTHORITY", "auth"),
                         ("S07C-HOLDOVER-BUFFER", "buf"), ("S07D-HOLDOVER-TIE", "tie")):
        w = sym_world()
        ops = good_prefix(w)
        last_t4 = ops[-1]["t4"]
        start_group = w.group(9 * S)
        ops.append({"op": "authority", "epoch": 1, "expires": last_t4 + 20 * S if variant in ("auth", "tie") else last_t4 + 900 * S,
                    "now": last_t4})
        if variant in ("buf", "tie"):
            ops.append({"op": "buffer", "until": last_t4 + (10 * S if variant == "buf" else 20 * S)})
        ops.append({"op": "admit", "now": last_t4, "sched": {"epoch": 1, "start_group_ns": start_group}})
        ops.append({"op": "tick", "now": w.local(8 * S)})                       # armed, before the start
        ops.append({"op": "tick", "now": w.local(10 * S)})                      # audible
        wd = world_def(sid, ops, world=w, tags=["holdover", variant])
        # evaluate with the reference to learn the holdover limit, then add the instants around it
        partial = ref.run_script(wd["cfg"], 1, 7, 1000, ops + [check(last_t4 + 5 * S)])
        until = partial[-1]["holdover_until"]
        assert partial[-1]["binding"] == {"unc": "Uncertainty", "auth": "Authority", "buf": "Buffer",
                                          "tie": "Authority"}[variant], (sid, partial[-1])
        ops += [{"op": "tick", "now": last_t4 + 2 * S},                         # fresh (< 3 s since the last probe)
                {"op": "tick", "now": last_t4 + 5 * S},                         # holdover: still audible
                tcheck(w, until - 1), {"op": "tick", "now": until - 1},
                tcheck(w, until), {"op": "tick", "now": until}]                     # expired: muted
        # probes resume after the gap: the clock is locked again at once, but the start must be admitted again
        t0 = until + 5 * S
        for k in range(2):
            ts_true = 7 * S + (t0 - last_t4) + k * S                          # the world's clocks keep running
            ops.append(probe(w, ts_true, 200 * US, 50 * US, 200 * US))
        ops.append({"op": "tick", "now": ops[-1]["t4"] + 1 * MS})                # locked, NOT audible: muted
        renew = ops[-2]["t4"] + 2 * MS
        ops.append({"op": "authority", "epoch": 1, "expires": renew + 900 * S, "now": renew})
        ops.append({"op": "buffer"})                                            # buffer bound cleared
        ops.append({"op": "tick", "now": renew + 1 * MS})                       # still not admitted
        ops.append({"op": "admit", "now": renew + 2 * MS,
                    "sched": {"epoch": 1, "start_group_ns": w.group(ts_true + 3 * S)}})
        ops.append({"op": "tick", "now": w.local(ts_true + 3 * S) + 1 * MS})    # audible only after the new start
        wd["ops"] = ops
        out.append(wd)

    # ---- S08 clock jumps mid-session: each is a discontinuity and forces a muted relock --------------
    def jump_world(wid: str, mutate: str) -> Dict[str, Any]:
        goff = 8_995_000_000_000
        ops = [exact(10 * S + k * S, goff, 200 * US, 50 * US, 200 * US) for k in range(8)]
        last_t4 = ops[-1]["t4"]
        ops.append({"op": "authority", "epoch": 1, "expires": last_t4 + 900 * S, "now": last_t4})
        ops.append({"op": "admit", "now": last_t4,
                    "sched": {"epoch": 1, "start_group_ns": last_t4 + goff + 500 * MS}})
        ops.append({"op": "tick", "now": last_t4 + 700 * MS})                      # audible: the positive join
        if mutate == "local-suspend":                                              # monotonic clock lost 30 s
            nxt = exact(19 * S, goff - 30 * S, 200 * US, 50 * US, 200 * US)
        elif mutate == "group-step":                                               # the coordinator stepped 2 s
            nxt = exact(19 * S, goff + 2 * S, 200 * US, 50 * US, 200 * US)
        elif mutate == "half-range":                                               # +13 h: beyond half the counter
            nxt = exact(19 * S, goff + 13 * 3600 * S, 200 * US, 50 * US, 200 * US)
        elif mutate == "wrap-alias":                                               # exactly one counter period
            nxt = exact(19 * S, goff + WRAP_NS, 200 * US, 50 * US, 200 * US)
        elif mutate == "counter-reset":                                            # group time went back 5 s
            nxt = exact(19 * S, goff - 5 * S, 200 * US, 50 * US, 200 * US)
        elif mutate == "local-regression":                                         # t4 earlier than the last t4
            nxt = exact(16 * S + 500 * MS, goff, 200 * US, 50 * US, 200 * US)
        else:
            raise ValueError(mutate)
        ops.append(nxt)
        ops.append({"op": "tick", "now": max(nxt["t4"], last_t4) + 1 * MS})       # muted: discontinuity
        # relock on the new timeline: four more good exchanges, then admission again
        new_goff = {"local-suspend": goff - 30 * S, "group-step": goff + 2 * S, "half-range": goff + 13 * 3600 * S,
                    "wrap-alias": goff + WRAP_NS, "counter-reset": goff - 5 * S,
                    "local-regression": goff}[mutate]
        t0 = 20 * S if mutate != "local-regression" else 21 * S
        if mutate == "local-regression":
            new_goff = goff
        for k in range(4):
            ops.append(exact(t0 + k * S, new_goff, 200 * US, 50 * US, 200 * US))
        t_last = ops[-1]["t4"]
        ops.append({"op": "tick", "now": t_last + 1 * MS})                         # locked but not admitted
        ops.append({"op": "authority", "epoch": 1, "expires": t_last + 900 * S, "now": t_last + 1 * MS})
        ops.append({"op": "admit", "now": t_last + 2 * MS,
                    "sched": {"epoch": 1, "start_group_ns": t_last + new_goff + 600 * MS}})
        ops.append({"op": "tick", "now": t_last + 800 * MS})
        return world_def(wid, ops, tags=["clock-jump", mutate])

    for sid, kind in (("S08A-JUMP-LOCAL-SUSPEND", "local-suspend"), ("S08B-JUMP-GROUP-STEP", "group-step"),
                      ("S08C-JUMP-HALF-RANGE", "half-range"), ("S08D-JUMP-WRAP-ALIAS", "wrap-alias"),
                      ("S08E-JUMP-COUNTER-RESET", "counter-reset"), ("S08F-JUMP-LOCAL-REGRESSION", "local-regression")):
        out.append(jump_world(sid, kind))

    # ---- S09 the discontinuity boundary: a step equal to what the fit allows is noise; one more is a jump --
    goff = 8_995_000_000_000
    for sid, delta_extra, expect_ok in (("S09A-STEP-AT-BOUND", 0, True), ("S09B-STEP-PAST-BOUND", 1, False)):
        ops = [exact(10 * S + k * S, goff, 200 * US, 50 * US, 200 * US) for k in range(5)]
        m = ref.Model(None, 1, 7, 1000)
        for op in ops:
            r = m.next_probe(op["t1"])
            m.on_response({"epoch": 1, "leader": 7, "seq": r["seq"], "t1_echo": r["t1"], "t2": op["t2"], "t3": op["t3"]}, op["t4"])
        t1 = 15 * S
        delay = 400 * US
        t4 = t1 + 450 * US
        a = m._anchor(t4)
        s_local_mid = t1 + (t4 - t1) // 2
        allowed = (ref.unc_at(a["sample"], s_local_mid, a["ratio_unc"], m.cfg, a["ratio"]) + ref.ceil_div(delay, 2)
                   + m.cfg["prediction_slack_ns"])
        predicted = ref.group_at(a["sample"], s_local_mid, a["ratio"])
        want_group_mid = predicted + allowed + delta_extra
        # build t2,t3 so that group_mid == want_group_mid with dwell 50 us (even), delay = 450-50 = 400 us
        t2 = want_group_mid - 25 * US
        ops.append({"op": "probe", "t1": t1, "t2": t2, "t3": t2 + 50 * US, "t4": t4})
        ops.append(check(t4 + 1 * MS))
        out.append(world_def(sid, ops, tags=["clock-jump", "boundary", "positive" if expect_ok else "negative"],
                             note="allowed step = anchor uncertainty + delay/2 + prediction slack = %d ns" % allowed))
        r = expect_for(out[-1])
        assert (r[5]["result"] == "ok") == expect_ok, (sid, r[5])

    # ---- S10 leader change: old-epoch probes are inert; the new leader's timebase is not the old one ----
    goff = 8_995_000_000_000
    ops = [exact(10 * S + k * S, goff, 200 * US, 50 * US, 200 * US) for k in range(6)]
    last_t4 = ops[-1]["t4"]
    ops += [{"op": "authority", "epoch": 1, "expires": last_t4 + 900 * S, "now": last_t4},
            {"op": "admit", "now": last_t4, "sched": {"epoch": 1, "start_group_ns": last_t4 + goff + 500 * MS}},
            {"op": "tick", "now": last_t4 + 700 * MS},
            {"op": "begin_epoch", "epoch": 2, "leader": 8},
            {"op": "begin_epoch", "epoch": 2, "leader": 9},                            # does not advance
            {"op": "tick", "now": last_t4 + 800 * MS},
            check(last_t4 + 800 * MS)]
    stale = exact(16 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append({"op": "raw", "t4": stale["t4"] + 900 * MS, "resp": {"epoch": 1, "leader": 7, "seq": 1006, "t1_echo": stale["t1"],
                                                                   "t2": stale["t2"], "t3": stale["t3"]}})
    ops.append({"op": "raw", "t4": stale["t4"] + 910 * MS, "resp": {"epoch": 3, "leader": 8, "seq": 1006, "t1_echo": stale["t1"],
                                                                   "t2": stale["t2"], "t3": stale["t3"]}})
    # a probe in epoch 2 answered by the old leader
    ops.append({"op": "probe", "t1": 17 * S, "t2": 17 * S + goff + 200 * US, "t3": 17 * S + goff + 250 * US,
                "t4": 17 * S + 450 * US, "ovr": {"leader": 7}})
    new_goff = goff + 7 * MS                                                              # the new leader's timebase
    for k in range(4):
        ops.append(exact(18 * S + k * S, new_goff, 200 * US, 50 * US, 200 * US))
    t_last = ops[-1]["t4"]
    ops += [check(t_last + 1 * MS), {"op": "tick", "now": t_last + 1 * MS},
            {"op": "admit", "now": t_last + 2 * MS, "sched": {"epoch": 1, "start_group_ns": t_last + new_goff + 600 * MS}},
            {"op": "authority", "epoch": 2, "expires": t_last + 900 * S, "now": t_last + 2 * MS},
            {"op": "authority", "epoch": 1, "expires": t_last + 900 * S, "now": t_last + 2 * MS},
            {"op": "admit", "now": t_last + 3 * MS, "sched": {"epoch": 3, "start_group_ns": t_last + new_goff + 600 * MS}},
            {"op": "admit", "now": t_last + 4 * MS, "sched": {"epoch": 2, "start_group_ns": t_last + new_goff + 600 * MS}},
            {"op": "tick", "now": t_last + 700 * MS}]
    out.append(world_def("S10-LEADER-CHANGE", ops, tags=["leader-change", "negative:stale-epoch", "positive:join"],
                         note="epoch 1 leader 7 -> epoch 2 leader 8 whose group clock is 7 ms ahead"))

    # ---- S11 admission: replay, unsolicited, wrong leader, malformed, expired, excessive, regression --
    goff = 8_995_000_000_000
    ops = [exact(10 * S, goff, 200 * US, 50 * US, 200 * US)]                                    # 0 good
    ops.append({"op": "replay", "of": 0, "t4": 11 * S})                                         # 1 replay
    ops.append({"op": "raw", "t4": 11 * S + 1 * MS, "resp": {"epoch": 1, "leader": 7, "seq": 777, "t1_echo": 5,
                                                              "t2": goff, "t3": goff}})         # 2 unsolicited
    ops.append({"op": "next", "t1": 12 * S})                                                    # 3 request seq 1001
    ops.append({"op": "raw", "t4": 12 * S + 450 * US, "resp": {"epoch": 1, "leader": 7, "seq": 1001, "t1_echo": 12 * S + 1,
                                                                "t2": 12 * S + goff + 200 * US, "t3": 12 * S + goff + 250 * US}})  # 4 wrong t1 echo
    ops.append({"op": "raw", "t4": 12 * S + 450 * US, "resp": {"epoch": 1, "leader": 7, "seq": 1001, "t1_echo": 12 * S,
                                                                "t2": 12 * S + goff + 200 * US, "t3": 12 * S + goff + 250 * US}})  # 5 right: ok
    e = exact(13 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(e, ovr={"leader": 99}))                                                     # 6 wrong leader
    ops.append({"op": "raw", "t4": e["t4"], "resp": {"epoch": 1, "leader": 7, "seq": 1002, "t1_echo": e["t1"],
                                                      "t2": e["t2"], "t3": e["t3"]}})            # 7 right: ok
    f = exact(14 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(f, t3=f["t2"] - 1))                                                         # 8 t3 < t2
    g = exact(15 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(g, t2=(1 << 62) + 1, t3=(1 << 62) + 2))                                     # 9 beyond 2^62
    h = exact(16 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(h, t3=h["t2"] + 451 * US))                                                  # 10 dwell > rtt
    j = exact(18 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append({"op": "probe", "t1": j["t1"], "t2": j["t2"], "t3": j["t3"], "t4": j["t1"] + D["request_ttl_ns"] + 1})  # 12 expired
    k_ = exact(19 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append({"op": "probe", "t1": k_["t1"], "t2": k_["t2"], "t3": k_["t2"] + 1_960 * MS,
                "t4": k_["t1"] + D["request_ttl_ns"]})                                          # 13 rtt == ttl, delay 40 ms: ok
    l = exact(30 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(l, t4=l["t1"] + 50 * MS + 50 * US))                                         # 14 delay == max (50 ms): ok
    m_ = exact(31 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(m_, t4=m_["t1"] + 50 * MS + 51 * US))                                       # 15 delay == max + 1: excessive
    n_ = exact(32 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(n_, t4=n_["t1"]))                                                           # 16 t4 == t1
    ops.append(check(33 * S))
    # exactly 2^62 is well-formed (not Malformed): the sample rules pass it and the fit calls it a jump
    i = exact(34 * S, goff, 200 * US, 50 * US, 200 * US)
    ops.append(dict(i, t2=(1 << 62), t3=(1 << 62)))                                             # 17: Discontinuity
    ops.append(check(35 * S))
    out.append(world_def("S11-ADMISSION", ops, tags=["negative:replay", "negative:unadmitted-leader", "negative:malformed",
                                                    "boundary", "positive:accepted"],
                         note="every rejection reason once, paired with the exchange that is accepted"))

    # ---- S12 outstanding-request table is bounded -------------------------------------------------
    goff = 8_995_000_000_000
    ops = [{"op": "next", "t1": 10 * S + k * MS} for k in range(10)]                           # seqs 1000..1009; 1000, 1001 evicted
    ops.append({"op": "raw", "t4": 11 * S, "resp": {"epoch": 1, "leader": 7, "seq": 1000, "t1_echo": 10 * S,
                                                     "t2": 10 * S + goff + 200 * US, "t3": 10 * S + goff + 250 * US}})   # evicted
    ops.append({"op": "raw", "t4": 10 * S + 2 * MS + 450 * US, "resp": {"epoch": 1, "leader": 7, "seq": 1002, "t1_echo": 10 * S + 2 * MS,
                                                                        "t2": 10 * S + 2 * MS + goff + 200 * US, "t3": 10 * S + 2 * MS + goff + 250 * US}})  # held: ok
    ops.append({"op": "next", "t1": 10 * S + 3 * S})                                           # prunes the ttl-expired ones
    ops.append({"op": "raw", "t4": 13 * S + 1 * MS, "resp": {"epoch": 1, "leader": 7, "seq": 1003, "t1_echo": 10 * S + 3 * MS,
                                                              "t2": 10 * S + 3 * MS + goff + 200 * US, "t3": 10 * S + 3 * MS + goff + 250 * US}})  # pruned
    ops.append(check(13 * S + 2 * MS))
    out.append(world_def("S12-OUTSTANDING-BOUND", ops, tags=["bounded", "negative:replay"],
                         note="8 outstanding requests at most; a request older than the 2 s lifetime is dropped"))

    # ---- S13 reboot: nothing survives, recorded answers are unsolicited ---------------------------------
    w = sym_world()
    ops = good_prefix(w, 6)
    last_t4 = ops[-1]["t4"]
    ops += [{"op": "authority", "epoch": 1, "expires": last_t4 + 900 * S, "now": last_t4},
            {"op": "admit", "now": last_t4, "sched": {"epoch": 1, "start_group_ns": w.group(7 * S)}},
            {"op": "tick", "now": w.local(8 * S)},
            tcheck(w, w.local(8 * S) + 500 * US),
            {"op": "reboot", "seq_base": 9000},
            {"op": "tick", "now": w.local(8 * S) + 1 * MS},
            check(w.local(8 * S) + 2 * MS),
            {"op": "replay", "of": 5, "t4": w.local(8 * S) + 3 * MS},
            {"op": "replay", "of": 0, "t4": w.local(8 * S) + 4 * MS}]
    for k in range(4):
        ops.append(probe(w, 9 * S + k * S, 200 * US, 50 * US, 200 * US))
    t_last = ops[-1]["t4"]
    ops += [{"op": "tick", "now": t_last + 1 * MS},
            {"op": "authority", "epoch": 1, "expires": t_last + 900 * S, "now": t_last + 1 * MS},
            {"op": "admit", "now": t_last + 2 * MS, "sched": {"epoch": 1, "start_group_ns": w.group(14 * S)}},
            {"op": "tick", "now": w.local(14 * S) + 1 * MS}]
    out.append(world_def("S13-REBOOT", ops, world=w, tags=["reboot", "negative:replay", "positive:join"],
                         note="a restarted member is unlocked and muted; recorded answers from before are unsolicited"))

    # ---- S14 sparse probes: the rate fit restarts, the offset fit does not -----------------------------
    goff = 8_995_000_000_000
    ops = [exact(10 * S + k * 12 * S, goff, 200 * US, 50 * US, 200 * US) for k in range(10)]
    ops += [check(10 * S + 9 * 12 * S + 5 * S)]
    out.append(world_def("S14-SPARSE-PROBES", ops, tags=["rate-restart"],
                         note="a probe every 12 s (> the rate estimator's 10 s gap): the frequency fit restarts, the clock stays locked"))

    # ---- S15 a long soak: 3 h, 10% loss, jitter, drift, across the group counter wrap --------------------
    w = sym_world(37_000, group0=WRAP_NS - 5400 * S)
    g = ref.lcg(31)

    def jit3() -> int:
        return 100 * US + next(g) % (700 * US)
    ops = []
    k = 0
    for step in range(1080):
        ts = step * 10 * S + 1 * S
        r = next(g) % 100
        if r < 10:
            ops.append({"op": "next", "t1": w.local(ts)})                                       # lost probe
            continue
        ops.append(probe(w, ts, jit3(), 60 * US, jit3()))
        k += 1
        if k % 30 == 0:
            t_true = ts + 3 * MS
            ops.append(check(w.local(t_true), w.group(t_true)))
    out.append(world_def("S15-SOAK-3H", ops, world=w, tags=["soak", "wrap", "drift"],
                         note="3 h at 10 s probes, 10% lost, 100-800 us jitter, +37 ppm, group counter wraps at 1.5 h"))

    # ---- S16 admission and the admissible start (join) -------------------------------------------------
    goff = 8_995_000_000_000
    ops = [exact(10 * S + k * S, goff, 250 * US, 50 * US, 250 * US) for k in range(8)]
    n = ops[-1]["t4"] + 1 * MS                                       # "now"
    gnow = n + goff
    sch = lambda dt, e=1: {"epoch": e, "start_group_ns": gnow + dt}
    ops += [
        {"op": "plan", "now": n, "sched": sch(1 * S, 0)},                           # stale epoch
        {"op": "plan", "now": n, "sched": sch(1 * S, 2)},                           # future epoch
        {"op": "plan", "now": n, "sched": sch(5 * S + 1)},                          # too far ahead
        {"op": "plan", "now": n, "sched": sch(D["max_future_ns"])},                 # at the limit: ok
        {"op": "plan", "now": n, "sched": sch(D["catchup_ns"] - 1)},                # too late
        {"op": "plan", "now": n, "sched": sch(D["catchup_ns"])},                    # at the limit: ok
        {"op": "plan", "now": n, "sched": sch(2 * S)},
        {"op": "tick", "now": n},                                                   # not admitted yet: muted
        {"op": "admit", "now": n, "sched": sch(0, 0)},                              # refused: stays muted
        {"op": "tick", "now": n},
        {"op": "admit", "now": n, "sched": sch(1 * S)},                             # admitted
        {"op": "tick", "now": n},
        {"op": "tick", "now": n + 999 * MS},
        {"op": "tick", "now": n + 1 * S},                                           # audible at the start
        {"op": "authority", "epoch": 1, "expires": n + 1 * S + 500 * MS, "now": n + 1 * S},
        {"op": "tick", "now": n + 1 * S + 499 * MS},
        {"op": "tick", "now": n + 1 * S + 500 * MS},                                # authority expired: muted
        {"op": "plan", "now": n + 1 * S + 501 * MS, "sched": sch(2 * S)},           # ExpiresBeforeStart (authority)
    ]
    out.append(world_def("S16-JOIN", ops, tags=["join", "positive:join", "negative:stale-epoch", "boundary"],
                         note="admissible-start decisions at their exact limits; audible only at the start; authority expiry mutes"))

    # an unlocked member must not become audible: two probes only
    ops = [exact(10 * S + k * S, goff, 250 * US, 50 * US, 250 * US) for k in range(2)]
    n = ops[-1]["t4"] + 1 * MS
    ops += [{"op": "admit", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 1 * S}},
            {"op": "tick", "now": n + 2 * S},
            exact(13 * S, goff, 250 * US, 50 * US, 250 * US),
            exact(14 * S, goff, 250 * US, 50 * US, 250 * US)]
    n2 = ops[-1]["t4"] + 1 * MS
    ops += [{"op": "admit", "now": n2, "sched": {"epoch": 1, "start_group_ns": n2 + goff + 1 * S}},
            {"op": "tick", "now": n2 + 1 * S}]
    out.append(world_def("S17-UNLOCKED-CANNOT-OUTPUT", ops, tags=["negative:unlocked-output", "positive:join"],
                         note="two probes: admission refused and output muted; after the fourth the same request is admitted"))

    # uncertainty at the start is too large: a wide path leaves little headroom
    ops = [exact(10 * S + k * S, goff, 3 * MS, 50 * US, 500 * US) for k in range(5)]
    n = ops[-1]["t4"] + 1 * MS
    ops += [{"op": "plan", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 2 * S}},      # ok
            {"op": "plan", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 4 * S}},      # too uncertain by then
            {"op": "authority", "epoch": 1, "expires": n + 1 * S, "now": n},
            {"op": "plan", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 500 * MS}},  # ok: authority outlasts
            {"op": "plan", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 1500 * MS}}] # authority ends first
    out.append(world_def("S18-START-UNCERTAINTY", ops, tags=["join", "negative:uncertainty", "boundary"],
                         note="3.5 ms path leaves 249 us of headroom: a start 4 s out is refused, and one past the authority is refused"))

    # board profile: output delay moves the local start
    ops = [exact(10 * S + k * S, goff, 250 * US, 50 * US, 250 * US) for k in range(8)]
    n = ops[-1]["t4"] + 1 * MS
    ops += [{"op": "plan", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 2 * S}},
            {"op": "admit", "now": n, "sched": {"epoch": 1, "start_group_ns": n + goff + 2 * S}},
            {"op": "tick", "now": n + 2 * S - 1_850_001},
            {"op": "tick", "now": n + 2 * S - 1_850_000}]
    out.append(world_def("S19-OUTPUT-DELAY", ops, cfg={"output_delay_ns": 1_850_000, "calibration_uncertainty_ns": 150_000},
                         tags=["join", "board-profile"],
                         note="a 1.85 ms calibrated output delay: the member begins that much earlier than the group start"))
    return out


# ---- mixed profiles --------------------------------------------------------------------------------


def mixed_profiles() -> Dict[str, Any]:
    """Two members with different clocks, skews and board profiles join the same future start.  The true instants
    at which they begin must agree within the sum of their uncertainties (and the provisional 2 ms gate)."""
    members = []
    start_true = 24 * S                                          # the coordinator's start, in true time
    for name, skew, local0, res, cfg, seed in (
        ("A-hz3", 60_000, 4_000_000_000, 1000, {"output_delay_ns": 1_850_000, "calibration_uncertainty_ns": 150_000}, 41),
        ("B-ts1", -40_000, 17_000_000_000, 1000, {"output_delay_ns": 1_400_000, "calibration_uncertainty_ns": 200_000}, 42),
    ):
        w = ref.World(skew, local0, G0)
        g = ref.lcg(seed)

        def jit() -> int:
            return 100 * US + next(g) % (500 * US)
        ops = []
        for k in range(20):
            ops.append(probe(w, k * S, jit(), 50 * US, jit()))
        t_now_true = 20 * S + 5 * MS
        n = w.local(t_now_true)
        sched = {"epoch": 1, "start_group_ns": w.group(start_true)}
        ops.append(check(n, w.group(t_now_true)))
        ops.append({"op": "admit", "now": n, "sched": sched})
        ops.append({"op": "tick", "now": n})
        wd = world_def("M-" + name, ops, cfg=cfg, world=w, tags=["mixed-profile"])
        res_ = expect_for(wd)
        plan = res_[-2]
        assert plan["result"] == "ok", (name, plan)
        # the true instant at which this member's local clock reads start_local (+ its output delay)
        lo, hi = 0, 80 * S
        while lo < hi:
            mid = (lo + hi) // 2
            if w.local(mid) < plan["start_local_ns"]:
                lo = mid + 1
            else:
                hi = mid
        audible_true = lo + cfg["output_delay_ns"]
        members.append({"world": wd, "audible_true_ns": audible_true, "unc_at_start_ns": plan["uncertainty_at_start_ns"],
                        "start_true_ns": start_true})
    a, b = members
    skew_ns = abs(a["audible_true_ns"] - b["audible_true_ns"])
    bound = a["unc_at_start_ns"] + b["unc_at_start_ns"]
    assert skew_ns <= bound, ("mixed profile start skew %d > summed uncertainty %d" % (skew_ns, bound))
    assert skew_ns <= 2 * MS, "provisional room-group gate: p99 <= 2 ms"
    return {"members": members, "skew_ns": skew_ns, "bound_ns": bound, "gate_ns": 2 * MS}


# ---- pure tables ------------------------------------------------------------------------------------


def exchange_cases() -> List[Dict[str, Any]]:
    cfg = dict(D)
    cases = []

    def add(cid: str, t1: int, t2: int, t3: int, t4: int, **ov: int) -> None:
        c = dict(cfg)
        c.update(ov)
        cases.append({"id": cid, "t1": t1, "t2": t2, "t3": t3, "t4": t4, "cfg": ov, "expect": ref.sample(t1, t2, t3, t4, c)})

    add("symmetric", 1_000_000_000, 5_000_200_000, 5_000_250_000, 1_000_450_000)
    add("asymmetric", 1_000_000_000, 5_003_000_000, 5_003_050_000, 1_003_550_000)
    add("odd-halves", 1_000_000_001, 5_000_200_001, 5_000_250_002, 1_000_450_004)
    add("zero-delay", 100, 200, 300, 400)
    # Equal readings are a sub-resolution exchange (delay 0) while the dwell is below twice the declared resolution (1000 here),
    # and a stalled clock (LocalClockRegression) from there on, or on a clock declared exact; one reading earlier is backwards time.
    add("t4-equals-t1", 100, 200, 2_300, 100)
    add("t4-equals-t1-sub-resolution", 100, 200, 300, 100)
    add("t4-equals-t1-dwell-zero", 100, 200, 200, 100)
    add("t4-equals-t1-dwell-below-the-bound", 100, 200, 2_200, 100)           # dwell 2 000 < 2 * 1000 + ceil(1000 * 100 ppm) = 2 001
    add("t4-equals-t1-dwell-at-the-bound", 100, 200, 2_201, 100)              # dwell 2 001
    add("t4-equals-t1-exact-clock", 100, 200, 200, 100, timer_resolution_ns=0)
    add("t4-equals-t1-coarse-clock", 5_000_000_000, 9_000_000_000_000, 9_000_001_000_000, 5_000_000_000, timer_resolution_ns=1_700_000)
    add("t4-equals-t1-coarse-dwell-below-the-bound", 5_000_000_000, 9_000_000_000_000, 9_000_003_400_169, 5_000_000_000,
        timer_resolution_ns=1_700_000)
    add("t4-equals-t1-coarse-dwell-at-the-bound", 5_000_000_000, 9_000_000_000_000, 9_000_003_400_170, 5_000_000_000,
        timer_resolution_ns=1_700_000)
    add("t4-equals-t1-t3-before-t2", 100, 200, 199, 100)
    add("t4-equals-t1-past-limit", 100, (1 << 62) + 1, (1 << 62) + 1, 100)
    # A dwell that exceeds the round trip is a rounding, not an impossibility, while the excess is below 2R plus the rate allowance
    # ceil(rtt * oscillator_bound / 1e9): the delay is clamped to 0, equal readings or not.  (This vector used to be Malformed.)
    add("t4-one-past-t1-dwell-over-rtt-within-rounding", 100, 200, 300, 101)
    add("coarse-step-reading", 5_000_000_000, 9_000_000_000_000, 9_000_001_000_000, 5_001_700_000, timer_resolution_ns=1_700_000)
    add("t4-before-t1", 100, 200, 300, 99)
    add("t4-before-t1-coarse-clock", 5_001_700_000, 9_000_000_000_000, 9_000_000_000_000, 5_000_000_000, timer_resolution_ns=1_700_000)
    add("rtt-at-ttl", 1_000, 2_000, 2_000 + 1_960_000_000, 1_000 + D["request_ttl_ns"])
    add("rtt-past-ttl", 1_000, 2_000, 2_000 + 1_960_000_000, 1_000 + D["request_ttl_ns"] + 1)
    add("t3-before-t2", 1_000, 5_000, 4_999, 2_000_000)
    add("t2-at-limit", 1_000, 1 << 62, 1 << 62, 450_000)
    add("t2-past-limit", 1_000, (1 << 62) + 1, (1 << 62) + 1, 450_000)
    add("t3-past-limit", 1_000, 1 << 62, (1 << 62) + 1, 450_000)
    add("dwell-equals-rtt", 1_000, 5_000, 5_000 + 449_000, 450_000)
    # rtt 449 000: rate allowance ceil(449 000 * 100 ppm) = 45, so the bound is 2 * 1000 + 45 = 2 045.  (The id `dwell-past-rtt` used to
    # carry dwell = rtt + 1 and expect Malformed: a false rejection, now admitted with the delay clamped to 0.)
    add("dwell-one-over-rtt", 1_000, 5_000, 5_000 + 449_001, 450_000)
    add("dwell-below-the-rounding-bound", 1_000, 5_000, 5_000 + 449_000 + 2_044, 450_000)
    add("dwell-at-the-rounding-bound", 1_000, 5_000, 5_000 + 449_000 + 2_045, 450_000)
    # the review's physical witness: local grid 3 ms, group grid 4 ms, declared R 4 ms; send true 2.5 ms (t1 = 0), arrive 2.6 ms (t2 = 0),
    # leave 4.1 ms (t3 = 4 ms), receive 4.2 ms (t4 = 3 ms): the true dwell 1.5 ms is below the true round trip 1.7 ms, the readings say
    # round trip 3 ms and dwell 4 ms
    add("grids-3ms-and-4ms-negative-measured-delay", 0, 0, 4_000_000, 3_000_000, timer_resolution_ns=4_000_000)
    add("negative-delay-at-the-bound-coarse-clock", 0, 0, 3_000_000 + 8_000_700, 3_000_000, timer_resolution_ns=4_000_000)
    add("negative-delay-below-the-bound-coarse-clock", 0, 0, 3_000_000 + 8_000_699, 3_000_000, timer_resolution_ns=4_000_000)
    # the slow-clock witness: R 4 ms, local 80 ppm slow, true group t + 3 999 980 ns, both floored to R: send 0 (t1 = 0), arrive 10 ns
    # (t2 = 0), leave 4 000 110 (t3 = 8 000 000), receive 4 000 120 (t4 = 0 because L = 3 999 799.99). The true dwell 4 000 100 is below the
    # true round trip; the readings say round trip 0 and dwell 2R. Bound 2R + ceil((0 + R) * 100 ppm) = 8 000 400.
    add("slow-clock-reads-zero-across-a-tick", 0, 0, 8_000_000, 0, timer_resolution_ns=4_000_000)
    add("slow-clock-stall-at-the-bound", 0, 0, 8_000_400, 0, timer_resolution_ns=4_000_000)
    add("delay-at-max", 1_000, 5_000, 5_050, 1_000 + 50_000_050)
    add("delay-past-max", 1_000, 5_000, 5_050, 1_000 + 50_000_051)
    add("tight-max", 1_000, 5_000, 5_050, 1_000 + 1_050, max_delay_ns=1_000)
    add("tight-max-past", 1_000, 5_000, 5_050, 1_000 + 1_051, max_delay_ns=1_000)
    add("group-before-local", 9_000_000_000_000, 100, 150, 9_000_000_000_450)
    add("order-regression-before-expired", 1_000, 5_000, 4_000, 1_000 + D["request_ttl_ns"] + 5)
    add("order-expired-before-malformed", 1_000, 5_000, 4_000, 1_000 + D["request_ttl_ns"] + 5)
    add("order-malformed-before-excessive", 1_000, 5_000, 4_000, 1_000 + 80_000_000)
    return cases


def transform_cases() -> List[Dict[str, Any]]:
    cases = []
    base = {"delay": 400_000, "local_mid": 10_000_225_000, "group_mid": 9_005_000_225_000}
    for cid, ratio, now_dt, grp_dt in (
        ("zero-ratio-forward", 0, 5 * S + 17, 5 * S - 3),
        ("fast-forward", 80_000, 5 * S + 17, 5 * S - 3),
        ("slow-forward", -80_000, 5 * S + 17, 5 * S - 3),
        ("fast-backward", 80_000, -5 * S - 17, -5 * S - 3),
        ("slow-backward", -80_000, -5 * S - 17, -5 * S - 3),
        ("max-ratio", 500_000, 3 * S + 1, 3 * S + 1),
        ("odd-floor", 333_333, 999_999_999, 999_999_999),
        ("at-anchor", 123_456, 0, 0),
    ):
        now = base["local_mid"] + now_dt
        grp = base["group_mid"] + grp_dt
        cases.append({"id": cid, "sample": base, "ratio_ppb": ratio, "now": now, "group_ns": ref.group_at(base, now, ratio),
                      "group_target": grp, "local_for_group": ref.local_of(base, grp, ratio)})
    # clamped at zero
    s0 = {"delay": 0, "local_mid": 1_000, "group_mid": 100}
    cases.append({"id": "clamp-zero", "sample": s0, "ratio_ppb": 0, "now": 0, "group_ns": ref.group_at(s0, 0, 0),
                  "group_target": 0, "local_for_group": ref.local_of(s0, 0, 0)})
    return cases


def select_cases() -> List[Dict[str, Any]]:
    def smp(delay: int, local_mid: int, extra: int = 0) -> Dict[str, int]:
        return {"delay": delay, "local_mid": local_mid, "group_mid": local_mid + 1_000_000 + extra}
    cases = []
    sets = [
        ("newest-wins-equal-delay", [smp(400_000, 1 * S), smp(400_000, 2 * S), smp(400_000, 3 * S)], 4 * S, 6_000),
        ("low-delay-old-beats-new-slow", [smp(100_000, 1 * S), smp(900_000, 3 * S)], 3 * S + 1, 6_000),
        ("old-low-delay-loses-to-aging", [smp(100_000, 1 * S), smp(180_000, 120 * S)], 121 * S, 100_000),
        ("tie-goes-to-newer-mid", [smp(400_000, 2 * S), smp(400_001, 2 * S + 1_000)], 3 * S, 0),
        ("tie-same-mid-later-index", [smp(400_000, 2 * S), smp(400_000, 2 * S, 7)], 3 * S, 6_000),
        ("single", [smp(400_000, 2 * S)], 2 * S + 5, 100_000),
        ("future-sample-no-negative-age", [smp(400_000, 5 * S)], 2 * S, 100_000),
    ]
    for cid, samples, now, ru in sets:
        i, u = ref.select(samples, now, ru, D)
        cases.append({"id": cid, "samples": samples, "now": now, "ratio_unc_ppb": ru, "index": i, "uncertainty_ns": u})
    return cases


def holdover_cases() -> List[Dict[str, Any]]:
    s = {"delay": 400_000, "local_mid": 100 * S, "group_mid": 200 * S}
    cases = []
    for cid, ru, auth, buf, cfg in (
        ("uncertainty-only", 100_000, None, None, {}),
        ("uncertainty-only-tight", 6_000, None, None, {}),
        ("authority-binds", 100_000, 105 * S, 110 * S, {}),
        ("buffer-binds", 100_000, 120 * S, 103 * S, {}),
        ("authority-buffer-tie", 100_000, 104 * S, 104 * S, {}),
        ("buffer-uncertainty-tie", 100_000, None, None, {"__tie_buffer_with_uncertainty": True}),
        ("zero-ratio-uncertainty", 0, None, None, {}),
        ("zero-ratio-buffer", 0, None, 130 * S, {}),
        ("no-headroom", 100_000, None, None, {"lock_uncertainty_ns": 201_000}),
        ("negative-headroom", 100_000, None, None, {"lock_uncertainty_ns": 100_000}),
        ("calibration-eats-headroom", 100_000, None, None, {"calibration_uncertainty_ns": 1_000_000}),
        ("authority-in-the-past", 100_000, 50 * S, None, {}),
    ):
        cfg = dict(cfg)
        if cfg.pop("__tie_buffer_with_uncertainty", False):
            u_until, _ = ref.holdover(s, ru, D, None, None)
            buf = u_until
        c = dict(D)
        c.update(cfg)
        until, binding = ref.holdover(s, ru, c, auth, buf)
        cases.append({"id": cid, "sample": s, "ratio_unc_ppb": ru, "cfg": cfg, "authority": auth, "buffer": buf,
                      "until": until, "binding": binding})
    return cases


def plan_cases() -> List[Dict[str, Any]]:
    s = {"delay": 400_000, "local_mid": 100 * S, "group_mid": 8_000 * S}
    cases = []
    now = 101 * S

    def add(cid: str, **kw: Any) -> None:
        a = {"ratio_ppb": 0, "ratio_unc_ppb": 100_000, "epoch": 5, "sched_epoch": 5, "status": "Locked", "auth": None,
             "buf": None, "cfg": {}, "now": now, "start_dt": 2 * S}
        a.update(kw)
        c = dict(D)
        c.update(a["cfg"])
        gnow = ref.group_at(s, a["now"], a["ratio_ppb"])
        sg = a["start_abs"] if "start_abs" in a else gnow + a["start_dt"]
        res = ref.plan_start(s, a["ratio_ppb"], a["ratio_unc_ppb"], c, now=a["now"], epoch=a["epoch"],
                             sched_epoch=a["sched_epoch"], sched_start_group_ns=sg, status=a["status"],
                             authority_until=a["auth"], buffer_until=a["buf"])
        if not res.get("ok"):
            res = {"reject": res["reject"]}
        cases.append({"id": cid, "sample": s, "ratio_ppb": a["ratio_ppb"], "ratio_unc_ppb": a["ratio_unc_ppb"],
                      "epoch": a["epoch"], "sched_epoch": a["sched_epoch"], "status": a["status"], "authority": a["auth"],
                      "buffer": a["buf"], "cfg": a["cfg"], "now": a["now"], "start_group_ns": sg, "expect": res})

    add("ok")
    add("ok-with-ratio", ratio_ppb=-80_000, start_dt=3 * S)
    add("ok-output-delay", cfg={"output_delay_ns": 1_850_000})
    add("stale-epoch", sched_epoch=4)
    add("future-epoch", sched_epoch=6)
    add("stale-before-status", sched_epoch=4, status="Unlocked")
    add("unlocked", status="Unlocked")
    add("holdover-is-not-locked", status="Holdover")
    add("expired-is-not-locked", status="Expired")
    add("far-limit-ok", start_dt=D["max_future_ns"])
    add("too-far", start_dt=D["max_future_ns"] + 1)
    add("late-limit-ok", start_dt=D["catchup_ns"])
    add("too-late", start_dt=D["catchup_ns"] - 1)
    add("in-the-past", start_dt=-1 * S)
    add("late-with-output-delay", start_dt=D["catchup_ns"] + 1_000_000, cfg={"output_delay_ns": 2_000_000})
    add("uncertainty-limit", ratio_unc_ppb=100_000, start_dt=D["max_future_ns"], cfg={"max_future_ns": 60 * S})
    add("uncertainty-past-limit", ratio_unc_ppb=100_000, start_dt=18 * S, cfg={"max_future_ns": 60 * S})
    add("expires-authority", start_dt=2 * S, auth=now + 1 * S)
    add("authority-at-start-expires", start_dt=2 * S, auth=ref.local_of(s, ref.group_at(s, now, 0) + 2 * S, 0))
    add("authority-after-start-ok", start_dt=2 * S, auth=ref.local_of(s, ref.group_at(s, now, 0) + 2 * S, 0) + 1)
    add("expires-buffer", start_dt=2 * S, buf=now + 1 * S)
    add("ties-report-authority", start_dt=2 * S, auth=now + 10 * S, buf=now + 10 * S)
    return cases


# ---- assembly ------------------------------------------------------------------------------------


def build() -> Dict[str, Any]:
    ws = worlds()
    truth: Dict[str, Any] = {}
    for wdef in ws:
        wdef["expect"] = expect_for(wdef)
        if "clocks" in wdef:
            truth[wdef["id"]] = assert_truth(wdef, wdef["expect"])
    mixed = mixed_profiles()
    for m in mixed["members"]:
        m["world"]["expect"] = expect_for(m["world"])
        truth[m["world"]["id"]] = assert_truth(m["world"], m["world"]["expect"])
    # structural facts about the worlds that a vector file should state, not leave to be inferred
    return {
        "version": 1,
        "units": "nanoseconds unless a name says otherwise",
        "params": dict(D),
        "frame_rate_hz": ref.FRAME_RATE_HZ,
        "max_timestamp_ns": ref.MAX_TIMESTAMP_NS,
        "wrap_group_ns": WRAP_NS,
        "exchanges": exchange_cases(),
        "transforms": transform_cases(),
        "selections": select_cases(),
        "holdovers": holdover_cases(),
        "plans": plan_cases(),
        "worlds": ws,
        "mixed": mixed,
        "truth": truth,
    }


def render(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=1, sort_keys=True) + "\n"


def main(argv: List[str]) -> int:
    text = render(build())
    if "--check" in argv:
        try:
            with open(VECTORS) as fh:
                have = fh.read()
        except OSError:
            print("vectors.json missing")
            return 1
        if have != text:
            print("vectors.json is stale or hand-edited; run tests/n03/generate.py")
            return 1
        print("vectors.json is current")
        return 0
    with open(VECTORS, "w") as fh:
        fh.write(text)
    data = json.loads(text)
    print("wrote %s: %d worlds, %d bytes" % (VECTORS, len(data["worlds"]), len(text)))
    for wid, t in sorted(data["truth"].items()):
        print("  %-28s truth checks %3d  max error %8d ns  max uncertainty %8d ns  min margin %8d ns" % (
            wid, t["checks"], t["max_err_ns"], t["max_unc_ns"], t["min_margin_ns"] if t["min_margin_ns"] is not None else 0))
    print("  mixed-profile start skew %d ns (bound %d, gate %d)" % (data["mixed"]["skew_ns"], data["mixed"]["bound_ns"], data["mixed"]["gate_ns"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
