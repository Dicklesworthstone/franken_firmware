#!/usr/bin/env python3
"""N03 (ffw-u07) independent reference: expected values for the group clock and synchronized join.

Stdlib only.  Nothing here calls, imports or is generated from the Rust.  Every function restates a
rule of docs/contracts/n03.md in exact integer arithmetic (Python ints are unbounded, the Rust uses
i128/u128), so a disagreement is a finding on one side, not a rounding artefact.

Units: nanoseconds throughout.  t1 and t4 are the member's LOCAL monotonic readings (send, receive);
t2 and t3 are the coordinator's GROUP-clock readings (receive, transmit).  "mid" is the exchange midpoint.
"""
from __future__ import annotations

import importlib.util
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

NS = 10**9
MAX_TIMESTAMP_NS = 1 << 62          # N01's wire limit
U64_MAX = (1 << 64) - 1
FRAME_RATE_HZ = 48_000

# Defaults (the Rust GroupClockConfig::default must equal these; vectors["params"] carries them)
DEFAULTS = {
    "max_delay_ns": 50_000_000,
    "request_ttl_ns": 2_000_000_000,
    "min_probes_for_lock": 4,
    "lock_uncertainty_ns": 2_000_000,
    "fresh_ns": 3_000_000_000,
    "oscillator_bound_ppb": 100_000,
    "rate_sigma_multiple": 3,
    "wander_ppb": 6_000,
    "timer_resolution_ns": 1_000,
    "calibration_uncertainty_ns": 0,
    "output_delay_ns": 0,
    "prediction_slack_ns": 500_000,
    "rate_delay_slack_ns": 500_000,
    "catchup_ns": 100_000_000,
    "max_future_ns": 5_000_000_000,
    "window": 16,
    "max_outstanding": 8,
}


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


# ---- one exchange ----------------------------------------------------------------------------------


def sample(t1: int, t2: int, t3: int, t4: int, cfg: Dict[str, int]) -> Any:
    """The accepted sample, or the rejection code.  Check order is part of the contract."""
    if t4 <= t1:
        return "LocalClockRegression"
    rtt = t4 - t1
    if rtt > cfg["request_ttl_ns"]:
        return "ExpiredRequest"
    if t3 < t2 or t2 > MAX_TIMESTAMP_NS or t3 > MAX_TIMESTAMP_NS:
        return "Malformed"
    dwell = t3 - t2
    if dwell > rtt:
        return "Malformed"
    delay = rtt - dwell
    if delay > cfg["max_delay_ns"]:
        return "ExcessiveDelay"
    local_mid = t1 + rtt // 2
    group_mid = t2 + dwell // 2
    return {"delay": delay, "local_mid": local_mid, "group_mid": group_mid, "offset": group_mid - local_mid}


# ---- uncertainty, anchor, transform ----------------------------------------------------------------


def base_ns(delay: int, cfg: Dict[str, int]) -> int:
    """What a sample cannot know about itself: half its delay (asymmetry), the timer resolution, the board term."""
    return ceil_div(delay, 2) + cfg["timer_resolution_ns"] + cfg["calibration_uncertainty_ns"]


def unc_at(s: Dict[str, int], at: int, ratio_unc_ppb: int, cfg: Dict[str, int]) -> int:
    age = max(0, at - s["local_mid"])
    return base_ns(s["delay"], cfg) + ceil_div(age * ratio_unc_ppb, NS)


def select(samples: Sequence[Dict[str, int]], now: int, ratio_unc_ppb: int, cfg: Dict[str, int]) -> Tuple[int, int]:
    """(index, uncertainty_ns) of the sample with the smallest uncertainty at ``now``; ties go to the newer
    midpoint, then to the later index."""
    best: Optional[Tuple[int, int, int, int]] = None      # (u, -local_mid, -index, index)
    for i, s in enumerate(samples):
        u = unc_at(s, now, ratio_unc_ppb, cfg)
        key = (u, -s["local_mid"], -i, i)
        if best is None or key < best:
            best = key
    assert best is not None
    return best[3], best[0]


def group_at(s: Dict[str, int], now: int, ratio_ppb: int) -> int:
    return max(0, s["group_mid"] + ((now - s["local_mid"]) * (NS + ratio_ppb)) // NS)


def local_of(s: Dict[str, int], group_ns: int, ratio_ppb: int) -> int:
    return max(0, s["local_mid"] + ((group_ns - s["group_mid"]) * NS) // (NS + ratio_ppb))


# ---- holdover --------------------------------------------------------------------------------------

BINDING_ORDER = ("Authority", "Buffer", "Uncertainty")


def holdover(s: Dict[str, int], ratio_unc_ppb: int, cfg: Dict[str, int],
             authority_until: Optional[int], buffer_until: Optional[int]) -> Tuple[int, str]:
    """(first local instant at which holdover is NOT allowed, which bound set it): the minimum of the three
    bounds, ties resolved Authority > Buffer > Uncertainty."""
    headroom = max(0, cfg["lock_uncertainty_ns"] - base_ns(s["delay"], cfg))
    if ratio_unc_ppb == 0:
        unc_until = U64_MAX
    else:
        unc_until = min(U64_MAX, s["local_mid"] + (headroom * NS) // ratio_unc_ppb + 1)
    cands = {"Authority": authority_until, "Buffer": buffer_until, "Uncertainty": unc_until}
    present = [(v, BINDING_ORDER.index(k), k) for k, v in cands.items() if v is not None]
    until, _, binding = min(present)
    return until, binding


# ---- admissible start ------------------------------------------------------------------------------


def plan_start(s: Dict[str, int], ratio_ppb: int, ratio_unc_ppb: int, cfg: Dict[str, int], *, now: int,
               epoch: int, sched_epoch: int, sched_start_group_ns: int, status: str,
               authority_until: Optional[int], buffer_until: Optional[int]) -> Dict[str, Any]:
    """The decision for a scheduled future start.  Check order is part of the contract."""
    if sched_epoch < epoch:
        return {"reject": "StaleEpoch"}
    if sched_epoch > epoch:
        return {"reject": "FutureEpoch"}
    if status != "Locked":
        return {"reject": "NotLocked"}
    group_now = group_at(s, now, ratio_ppb)
    if sched_start_group_ns > group_now + cfg["max_future_ns"]:
        return {"reject": "TooFarAhead"}
    start_local = max(0, local_of(s, sched_start_group_ns, ratio_ppb) - cfg["output_delay_ns"])
    deadline = max(0, start_local - cfg["catchup_ns"])
    if now > deadline:
        return {"reject": "TooLate", "start_local_ns": start_local, "deadline_local_ns": deadline}
    u_start = unc_at(s, start_local, ratio_unc_ppb, cfg)
    if u_start > cfg["lock_uncertainty_ns"]:
        return {"reject": "UncertaintyAtStart", "uncertainty_at_start_ns": u_start}
    until, binding = holdover(s, ratio_unc_ppb, cfg, authority_until, buffer_until)
    if start_local >= until:
        return {"reject": "ExpiresBeforeStart", "valid_until_local_ns": until, "binding": binding}
    return {"ok": True, "start_local_ns": start_local, "deadline_local_ns": deadline,
            "uncertainty_at_start_ns": u_start, "valid_until_local_ns": until, "binding": binding}


# ---- group time as a wrapping frame counter (what the D03 rate estimator is fed) --------------------


def frame_position(group_ns: int) -> int:
    """Group time as a wrapping u32 frame counter at 48 kHz: wraps near 24.86 hours."""
    return (group_ns * FRAME_RATE_HZ // NS) & 0xFFFFFFFF


_D03: Any = None


def load_d03_reference() -> Any:
    global _D03
    if _D03 is not None:
        return _D03
    here = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(os.path.dirname(here), "d03", "reference.py")
    spec = importlib.util.spec_from_file_location("d03_reference_for_n03", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _D03 = module
    return module


# ---- closed forms for a noise-free world -----------------------------------------------------------


def asymmetry_bias_ns(df_ns: int, dr_ns: int) -> int:
    """Exact error of a symmetric-path offset estimate: (forward - return) / 2.  Not detectable from the
    four timestamps, so it can only be bounded (by delay/2), never corrected."""
    return (df_ns - dr_ns) // 2


def lock_not_before_ns(min_probes: int, interval_ns: int, delay_ns: int) -> int:
    """Earliest local time (from the first send) at which min_probes exchanges can have completed."""
    return (min_probes - 1) * interval_ns + delay_ns


# =====================================================================================================
# The member model: the whole contract restated as one executable state machine, independently of the
# Rust.  Scripts (lists of ops) run against it to produce the expected result of every step.
# =====================================================================================================

RATE_DEFAULTS = {
    "nominal": 48_000, "max_correction_ppm": 500, "rejoin_ppm": 2000, "max_instant_ppm": 50_000,
    "max_gap_us": 10_000_000, "max_residual_frames": 480, "min_observations": 8,
    "min_span_us": 4_000_000, "max_uncertainty_ppb": 50_000, "window": 64,
}


def _round_nearest(a: int, b: int) -> int:
    return (2 * a + b) // (2 * b) if a >= 0 else -((-2 * a + b) // (2 * b))


def _sums(window: Sequence[Tuple[int, int]]) -> Tuple[int, int, int, int, int, int, int]:
    n = len(window)
    x0, y0 = window[0][1], window[0][0]
    xs = [w[1] - x0 for w in window]
    ys = [w[0] - y0 for w in window]
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    syy = sum(y * y for y in ys)
    return n, sx, sy, sxx, sxy, syy, x0 * 0 + y0


class RateModel:
    """D03's estimator as the group clock uses it (its contract, docs/contracts/d03.md), restated.  Positions are
    kept unwrapped; the raw wrapping u32 is what the group clock feeds."""

    def __init__(self) -> None:
        self.window: List[Tuple[int, int, int]] = []        # (unwrapped, local_us, raw)
        self.estimate: Optional[Dict[str, Any]] = None
        self.epoch = 0
        self.restarts = 0

    def begin_epoch(self) -> None:
        self.window = []
        self.estimate = None
        self.epoch += 1
        self.restarts += 1

    def _jumped(self, unwrapped: int, local_us: int) -> bool:
        if len(self.window) < RATE_DEFAULTS["min_observations"]:
            return False
        pts = [(w[0], w[1]) for w in self.window]
        n, sx, sy, sxx, sxy, _syy, _ = _sums(pts)
        dx = n * sxx - sx * sx
        if dx <= 0:
            return False
        from fractions import Fraction
        slope = Fraction(n * sxy - sx * sy, dx)
        xbar, ybar = Fraction(sx, n), Fraction(sy, n)
        x = local_us - pts[0][1]
        y = unwrapped - pts[0][0]
        predicted = ybar + slope * (x - xbar)
        return abs(y - predicted) > RATE_DEFAULTS["max_residual_frames"]

    def observe(self, raw: int, local_us: int) -> Optional[str]:
        """None when accepted, else the discontinuity reason (the window is left untouched)."""
        unwrapped = raw
        if self.window:
            prev_un, prev_us, prev_raw = self.window[-1]
            if local_us <= prev_us:
                return "LocalClockRegression"
            delta = (raw - prev_raw) & 0xFFFFFFFF
            if delta >= (1 << 31):
                return "SourceTimelineAmbiguous"
            dt = local_us - prev_us
            if dt > RATE_DEFAULTS["max_gap_us"]:
                return "ObservationGap"
            nominal = RATE_DEFAULTS["nominal"]
            dev = abs(delta * 1_000_000 - nominal * dt) * 1_000_000
            if dev > RATE_DEFAULTS["max_instant_ppm"] * nominal * dt:
                return "ImplausibleRate"
            unwrapped = prev_un + delta
            if self._jumped(unwrapped, local_us):
                return "PositionJump"
        self.window.append((unwrapped, local_us, raw))
        if len(self.window) > RATE_DEFAULTS["window"]:
            self.window.pop(0)
        self._refit()
        return None

    def _refit(self) -> None:
        self.estimate = None
        n = len(self.window)
        if n < 3:
            return
        pts = [(w[0], w[1]) for w in self.window]
        span = pts[-1][1] - pts[0][1]
        if n < RATE_DEFAULTS["min_observations"] or span < RATE_DEFAULTS["min_span_us"]:
            return
        d03 = load_d03_reference()
        ratio, unc = d03.ls_fit(pts)
        unc_ppb = 0 if unc < 1e-3 else int(-(-unc // 1))
        cap = RATE_DEFAULTS["max_correction_ppm"] * 1000
        if abs(ratio) > RATE_DEFAULTS["rejoin_ppm"] * 1000:
            status, corr = "RejoinRequired", max(-cap, min(cap, ratio))
        elif unc_ppb > RATE_DEFAULTS["max_uncertainty_ppb"]:
            status, corr = "Noisy", 0
        elif abs(ratio) > cap:
            status, corr = "Clamped", max(-cap, min(cap, ratio))
        else:
            status, corr = "Valid", ratio
        self.estimate = {"ratio_ppb": ratio, "correction_ppb": corr, "uncertainty_ppb": unc_ppb, "status": status,
                         "observations": n, "span_us": span}


class Model:
    """One group-clock member.  Every method mirrors the Rust method of the same name."""

    def __init__(self, cfg: Optional[Dict[str, int]] = None, epoch: int = 1, leader: int = 7, seq_base: int = 1000):
        self.cfg = dict(DEFAULTS)
        if cfg:
            self.cfg.update(cfg)
        self.epoch, self.leader, self.next_seq = epoch, leader, seq_base
        self.outstanding: List[Dict[str, int]] = []
        self.samples: List[Dict[str, int]] = []
        self.rate = RateModel()
        self.last_fed_us: Optional[int] = None
        self.accepted_in_epoch = 0
        self.last_accept: Optional[int] = None
        self.last_t4: Optional[int] = None
        self.lock_seen = False
        self.authority_until: Optional[int] = None
        self.buffer_until: Optional[int] = None
        self.armed: Optional[int] = None
        self.mute = "NotLocked"
        self.stats = {"probes_sent": 0, "probes_lost": 0, "accepted": 0, "resets": 0, "rate_restarts": 0,
                      "epochs": 0, "rejected": {}}

    # ---- bookkeeping --------------------------------------------------------------------------
    def _clear(self, mute: str) -> None:
        self.samples, self.outstanding = [], []
        self.accepted_in_epoch = 0
        self.last_accept = self.last_t4 = self.last_fed_us = None
        self.lock_seen = False
        self.armed = None
        self.mute = mute
        self.rate = RateModel()

    def _reject(self, code: str) -> str:
        self.stats["rejected"][code] = self.stats["rejected"].get(code, 0) + 1
        return code

    def _reset(self, code: str) -> str:
        self._clear("Discontinuity")
        self.stats["resets"] += 1
        return self._reject(code)

    def begin_epoch(self, epoch: int, leader: int) -> str:
        if epoch <= self.epoch:
            return "EpochNotAdvanced"
        self.epoch, self.leader = epoch, leader
        self.authority_until = None
        self._clear("EpochChange")
        self.stats["epochs"] += 1
        return "ok"

    def report_clock_fault(self) -> str:
        self._clear("ClockFault")
        self.stats["resets"] += 1
        return "ok"

    def set_authority(self, epoch: int, expires: int, now: int) -> str:
        if epoch != self.epoch:
            return "WrongEpoch"
        self._settle(now)
        self.authority_until = expires
        return "ok"

    def set_buffer_until(self, until: Optional[int]) -> str:
        self.buffer_until = until
        return "ok"

    # ---- probes -------------------------------------------------------------------------------
    def next_probe(self, now: int) -> Dict[str, int]:
        before = len(self.outstanding)
        ttl = self.cfg["request_ttl_ns"]
        self.outstanding = [r for r in self.outstanding if max(0, now - r["t1"]) <= ttl]
        lost = before - len(self.outstanding)
        while len(self.outstanding) >= self.cfg["max_outstanding"]:
            self.outstanding.pop(0)
            lost += 1
        self.stats["probes_lost"] += lost
        req = {"epoch": self.epoch, "seq": self.next_seq, "t1": now}
        self.next_seq = (self.next_seq + 1) & U64_MAX
        self.outstanding.append(req)
        self.stats["probes_sent"] += 1
        return req

    def on_response(self, resp: Dict[str, int], t4: int) -> Any:
        """('ok', info) or ('reject', code)."""
        if resp["epoch"] < self.epoch:
            return ("reject", self._reject("StaleEpoch"))
        if resp["epoch"] > self.epoch:
            return ("reject", self._reject("FutureEpoch"))
        if resp["leader"] != self.leader:
            return ("reject", self._reject("UnadmittedLeader"))
        pos = next((i for i, r in enumerate(self.outstanding)
                    if r["seq"] == resp["seq"] and r["t1"] == resp["t1_echo"]), None)
        if pos is None:
            return ("reject", self._reject("UnsolicitedOrReplayed"))
        req = self.outstanding.pop(pos)
        if self.last_t4 is not None and t4 < self.last_t4:
            return ("reject", self._reset("LocalClockRegression"))
        self._settle(t4)
        s = sample(req["t1"], resp["t2"], resp["t3"], t4, self.cfg)
        if isinstance(s, str):
            return ("reject", self._reject(s))
        a = self._anchor(t4)
        if a is not None:
            predicted = group_at(a["sample"], s["local_mid"], a["ratio"])
            allowed = (unc_at(a["sample"], s["local_mid"], a["ratio_unc"], self.cfg)
                       + ceil_div(s["delay"], 2) + self.cfg["prediction_slack_ns"])
            if abs(s["group_mid"] - predicted) > allowed:
                return ("reject", self._reset("Discontinuity"))
        if len(self.samples) >= self.cfg["window"]:
            self.samples.pop(0)
        self.samples.append(s)
        self.accepted_in_epoch += 1
        self.last_accept = self.last_t4 = t4
        self.stats["accepted"] += 1
        self._feed_rate(s)
        status = self.status(t4)
        if status == "Locked":
            self.lock_seen = True
        return ("ok", {"delay": s["delay"], "offset": s["offset"], "status": status})

    def _feed_rate(self, s: Dict[str, int]) -> None:
        best = min(x["delay"] for x in self.samples)
        local_us = s["local_mid"] // 1000
        advances = self.last_fed_us is None or local_us > self.last_fed_us
        if not advances or s["delay"] > best + self.cfg["rate_delay_slack_ns"]:
            return
        raw = frame_position(s["group_mid"])
        if self.rate.observe(raw, local_us) is None:
            self.last_fed_us = local_us
            return
        self.last_fed_us = None
        self.rate.begin_epoch()
        self.stats["rate_restarts"] += 1
        if self.rate.observe(raw, local_us) is None:
            self.last_fed_us = local_us

    # ---- the fit ------------------------------------------------------------------------------
    def ratio_state(self) -> Tuple[int, int]:
        e = self.rate.estimate
        if e is not None and e["status"] == "Valid":
            return e["correction_ppb"], e["uncertainty_ppb"] * self.cfg["rate_sigma_multiple"] + self.cfg["wander_ppb"]
        return 0, self.cfg["oscillator_bound_ppb"]

    def rate_in_force(self) -> bool:
        e = self.rate.estimate
        return e is not None and e["status"] == "Valid"

    def _anchor(self, now: int) -> Optional[Dict[str, Any]]:
        if not self.samples:
            return None
        ratio, ratio_unc = self.ratio_state()
        i, u = select(self.samples, now, ratio_unc, self.cfg)
        return {"sample": self.samples[i], "ratio": ratio, "ratio_unc": ratio_unc, "unc": u, "index": i}

    def status(self, now: int) -> str:
        c = self.cfg
        if self.accepted_in_epoch < c["min_probes_for_lock"]:
            return "Unlocked"
        a = self._anchor(now)
        if a is None:
            return "Unlocked"
        if a["unc"] > c["lock_uncertainty_ns"]:
            return "Expired" if self.lock_seen else "Unlocked"
        age = max(0, now - (self.last_accept or 0))
        if age <= c["fresh_ns"]:
            return "Locked"
        if not self.lock_seen:
            return "Unlocked"
        until, _ = holdover(a["sample"], a["ratio_unc"], c, self.authority_until, self.buffer_until)
        return "Holdover" if now < until else "Expired"

    def group_ns(self, now: int) -> Optional[int]:
        a = self._anchor(now)
        return None if a is None else group_at(a["sample"], now, a["ratio"])

    def holdover_of(self, now: int) -> Optional[Tuple[int, str]]:
        a = self._anchor(now)
        if a is None:
            return None
        return holdover(a["sample"], a["ratio_unc"], self.cfg, self.authority_until, self.buffer_until)

    # ---- joining ------------------------------------------------------------------------------
    def plan_start(self, sched: Dict[str, int], now: int) -> Dict[str, Any]:
        status = self.status(now)
        a = self._anchor(now)
        if a is None:
            return {"reject": "NotLocked"}
        return plan_start(a["sample"], a["ratio"], a["ratio_unc"], self.cfg, now=now, epoch=self.epoch,
                          sched_epoch=sched["epoch"], sched_start_group_ns=sched["start_group_ns"],
                          status=status, authority_until=self.authority_until, buffer_until=self.buffer_until)

    def admit(self, sched: Dict[str, int], now: int) -> Dict[str, Any]:
        self._settle(now)
        plan = self.plan_start(sched, now)
        if plan.get("ok"):
            self.armed = sched["start_group_ns"]
        return plan

    def _settle(self, now: int) -> str:
        status = self.status(now)
        if status == "Unlocked":
            self.armed = None
        elif status == "Expired":
            self.armed = None
            self.mute = "ClockExpired"
        else:
            if self.authority_until is not None and now >= self.authority_until:
                self.armed = None
                self.mute = "AuthorityExpired"
            elif self.armed is None:
                self.mute = "NotAdmitted"
        return status

    def output_at(self, status: str, now: int) -> Dict[str, Any]:
        if status == "Unlocked":
            return {"output": "Muted",
                    "mute": self.mute if self.mute in ("Discontinuity", "EpochChange", "ClockFault") else "NotLocked"}
        if status == "Expired":
            return {"output": "Muted", "mute": "ClockExpired"}
        if self.authority_until is not None and now >= self.authority_until:
            return {"output": "Muted", "mute": "AuthorityExpired"}
        if self.armed is None:
            return {"output": "Muted", "mute": "NotAdmitted"}
        group_now = self.group_ns(now) or 0
        target = max(0, self.armed - self.cfg["output_delay_ns"])
        if group_now < target:
            return {"output": "Armed", "starts_in_ns": target - group_now}
        return {"output": "Audible"}

    def tick(self, now: int) -> Dict[str, Any]:
        status = self._settle(now)
        return self.output_at(status, now)

    def snapshot(self, now: int) -> Dict[str, Any]:
        """What Rust's report() plus group_ns says, without side effects."""
        status = self.status(now)
        out = self.output_at(status, now)
        a = self._anchor(now)
        h = self.holdover_of(now)
        rec: Dict[str, Any] = {"status": status, "output": out["output"], "samples": len(self.samples),
                               "accepted": self.stats["accepted"], "resets": self.stats["resets"],
                               "rate_restarts": self.stats["rate_restarts"],
                               "rejected_total": sum(self.stats["rejected"].values()),
                               "mute": out.get("mute")}
        if "starts_in_ns" in out:
            rec["starts_in_ns"] = out["starts_in_ns"]
        if a is not None:
            rec.update({"uncertainty_ns": a["unc"], "ratio_ppb": a["ratio"], "ratio_unc_ppb": a["ratio_unc"],
                        "group_ns": group_at(a["sample"], now, a["ratio"]),
                        "anchor_local_mid": a["sample"]["local_mid"]})
        if h is not None:
            rec["holdover_until"], rec["binding"] = h
        return rec


# ---- scripts -------------------------------------------------------------------------------------


def resp_for(op: Dict[str, Any], req: Dict[str, int], model: Model) -> Dict[str, int]:
    r = {"epoch": req["epoch"], "leader": model.leader, "seq": req["seq"], "t1_echo": req["t1"],
         "t2": op["t2"], "t3": op["t3"]}
    r.update(op.get("ovr", {}))
    return r


def run_script(cfg: Optional[Dict[str, int]], epoch: int, leader: int, seq_base: int,
               ops: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Execute ``ops`` and return one result record per op.  The Rust test engine implements the same ops."""
    model = Model(cfg, epoch, leader, seq_base)
    sent: List[Optional[Dict[str, int]]] = []           # the response built for each op (for replay)
    out: List[Dict[str, Any]] = []
    for op in ops:
        kind = op["op"]
        rec: Dict[str, Any] = {"op": kind}
        sent.append(None)
        if kind in ("probe", "raw", "replay"):
            if kind == "probe":
                req = model.next_probe(op["t1"])
                rec["seq"] = req["seq"]
                resp = resp_for(op, req, model)
                t4 = op["t4"]
            elif kind == "raw":
                resp = dict(op["resp"])
                t4 = op["t4"]
            else:
                resp = dict(sent[op["of"]] or {})
                t4 = op["t4"]
            sent[-1] = resp
            verdict, info = model.on_response(resp, t4)
            rec["result"] = "ok" if verdict == "ok" else info
            if verdict == "ok":
                rec["delay"], rec["offset"] = info["delay"], info["offset"]
            rec["status"] = model.status(t4)
        elif kind == "next":
            rec["seq"] = model.next_probe(op["t1"])["seq"]
        elif kind == "check":
            rec.update(model.snapshot(op["now"]))
        elif kind == "tick":
            rec.update(model.tick(op["now"]))
        elif kind in ("admit", "plan"):
            plan = model.admit(op["sched"], op["now"]) if kind == "admit" else model.plan_start(op["sched"], op["now"])
            rec["result"] = "ok" if plan.get("ok") else plan["reject"]
            if plan.get("ok"):
                for k, v in plan.items():
                    if k != "ok":
                        rec[k] = v
        elif kind == "begin_epoch":
            rec["result"] = model.begin_epoch(op["epoch"], op["leader"])
        elif kind == "authority":
            rec["result"] = model.set_authority(op["epoch"], op["expires"], op["now"])
        elif kind == "buffer":
            rec["result"] = model.set_buffer_until(op.get("until"))
        elif kind == "fault":
            rec["result"] = model.report_clock_fault()
        elif kind == "reboot":
            model = Model(cfg, op.get("epoch", model.epoch), op.get("leader", model.leader), op["seq_base"])
            rec["result"] = "ok"
        else:
            raise ValueError("unknown op %r" % kind)
        rec["rate_in_force"] = model.rate_in_force()
        out.append(rec)
    return out


# ---- the simulated world: ground truth for every claim -------------------------------------------


def lcg(seed: int):
    state = seed & 0xFFFFFFFF
    while True:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        yield state


class World:
    """True time ``t`` (ns) drives two clocks.  The coordinator's group clock reads ``group0 + t``; the member's
    local clock reads ``local0 + t * (1 + skew)``.  Both are floored to ``res_ns``.  Nothing in a script can see
    ``t``: it exists to be compared with at the end."""

    def __init__(self, skew_ppb: int, local0: int, group0: int, res_ns: int = 1000):
        self.skew, self.local0, self.group0, self.res = skew_ppb, local0, group0, res_ns

    def _q(self, v: int) -> int:
        return v - v % self.res

    def local(self, t: int) -> int:
        return self._q(self.local0 + t + (t * self.skew) // NS)

    def group(self, t: int) -> int:
        return self._q(self.group0 + t)

    def exchange(self, ts: int, df: int, w: int, dr: int) -> Tuple[int, int, int, int]:
        return self.local(ts), self.group(ts + df), self.group(ts + df + w), self.local(ts + df + w + dr)


# ---- the independent world of crates/franken-clock/src/group/tests.rs, ported exactly ---------------------


class Sim:
    """Mirror of ``Sim`` in group/tests.rs: same LCG, same clocks, same draw order, so the judge can re-derive what
    the Rust printed instead of trusting it."""

    def __init__(self, seed: int, skew_ppb: int, local0: int = 3_000_000_000, group0: int = 40_000_000_000_000):
        self.seed, self.skew, self.local0, self.group0, self.res = seed, skew_ppb, local0, group0, 1000

    def rand(self) -> int:
        self.seed = (self.seed * 1664525 + 1013904223) & 0xFFFFFFFF
        return self.seed >> 8

    def _q(self, v: int) -> int:
        return v - v % self.res

    def local(self, t: int) -> int:
        return self._q(self.local0 + t + (t * self.skew) // NS)

    def group(self, t: int) -> int:
        return self._q(self.group0 + t)


def sim_run(seed: int, skew_ppb: int, base_us: int, jitter_us: int, asym_us: int, loss_pct: int,
            seconds: int) -> Dict[str, Any]:
    sim = Sim(seed, skew_ppb)
    model = Model(None, 1, 7, seed << 20)
    run = {"probes": 0, "lost": 0, "checks": 0, "max_err_ns": 0, "max_unc_ns": 0, "min_margin_ns": None}
    for k in range(seconds):
        ts = k * NS + sim.rand() % 5_000_000
        req = model.next_probe(sim.local(ts))
        run["probes"] += 1
        if sim.rand() % 100 < loss_pct:
            run["lost"] += 1
            continue
        df = (base_us + sim.rand() % (jitter_us + 1) + asym_us) * 1000
        dr = (base_us + sim.rand() % (jitter_us + 1)) * 1000
        dwell = 40_000
        resp = {"epoch": req["epoch"], "leader": 7, "seq": req["seq"], "t1_echo": req["t1"],
                "t2": sim.group(ts + df), "t3": sim.group(ts + df + dwell)}
        t_end = ts + df + dwell + dr
        verdict, info = model.on_response(resp, sim.local(t_end))
        assert verdict == "ok", ("sim exchange rejected", seed, k, info)
        t_now = t_end + 1_500_000
        now = sim.local(t_now)
        a = model._anchor(now)
        if a is not None:
            err = abs(group_at(a["sample"], now, a["ratio"]) - sim.group(t_now))
            assert err <= a["unc"], ("truth outside uncertainty", seed, k, err, a["unc"])
            run["checks"] += 1
            run["max_err_ns"] = max(run["max_err_ns"], err)
            run["max_unc_ns"] = max(run["max_unc_ns"], a["unc"])
            margin = a["unc"] - err
            run["min_margin_ns"] = margin if run["min_margin_ns"] is None else min(run["min_margin_ns"], margin)
    run["locked"] = model.status(sim.local(seconds * NS)) != "Unlocked"
    assert model.stats["resets"] == 0, ("clean world reset", seed)
    return run


SIM_WORLDS = [
    # (seed, skew ppb, base delay us, jitter us, forward asymmetry us, loss percent, seconds)
    (1, 0, 150, 0, 0, 0, 120),
    (2, 90_000, 100, 300, 0, 10, 300),
    (3, -90_000, 100, 300, 200, 10, 300),
    (4, 25_000, 200, 800, 400, 20, 600),
    (5, -3_000, 50, 100, 900, 5, 300),
]
