#!/usr/bin/env python3
"""Independent oracle for the E02 baseline analyzer (bead ffw-za4). Standard library only.

This re-derives the report for each synthetic capture from the RULES in docs/contracts/e02.md, using
Python's arbitrary-precision integers and a different program structure from the Rust crate. It does
not import or run the Rust analyzer. `--check` compares the oracle's result with the hand-written
expected files; the Rust integration test compares the real binary with the same files. Agreement of
all three (hand computation, this oracle, the Rust analyzer) is the evidence; any one alone is not.

    oracle.py --check            inventory checks, then every series/memory case against its expected file
    oracle.py --print FILE       print the oracle's report for one capture (debugging)

It does NOT run the Rust implementation, so a pass here says nothing about franken-baseline by itself.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = 1_000_000_000
NS_HOUR_X1000 = 3_600_000_000_000_000


class OracleError(Exception):
    pass


# ------------------------------------------------------------------------------------------------
# capture parsing (valid inputs only; malformed-input behaviour is the Rust parser's, tested there)

def _kv(tokens):
    out = {}
    for tok in tokens:
        key, _, val = tok.partition("=")
        out[key] = val
    return out


def parse_capture(text):
    meta = None
    counters, gauges, samples = [], [], []
    header = False
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not header:
            if line != "ffw.baseline.capture.v1":
                raise OracleError("bad header")
            header = True
            continue
        tag, *toks = line.split()
        kv = _kv(toks)
        if tag == "meta":
            meta = {
                "evidence": kv["evidence"],
                "profile": kv["profile"],
                "cadence_ns": int(kv["cadence_ms"]) * 1_000_000,
                "declared_ns": int(kv["declared_ms"]) * 1_000_000,
                "hole_pct": int(kv.get("hole_factor_pct", 150)),
                "playout_ns": int(kv.get("playout_ms", 0)) * 1_000_000,
                "wall_step_ns": int(kv.get("wall_step_ms", 1000)) * 1_000_000,
                "spike_factor": int(kv.get("spike_factor", 8)),
                "device_rate_hz": int(kv["device_rate_hz"]) if "device_rate_hz" in kv else None,
                "device_width": int(kv.get("device_width", 64)),
                "stall_frames": int(kv["device_stall_frames"]) if "device_stall_frames" in kv else None,
                "min_cov_ppm": int(kv["min_coverage_ppm"]) if "min_coverage_ppm" in kv else None,
                "max_dropouts": int(kv["max_dropout_intervals"]) if "max_dropout_intervals" in kv else None,
            }
        elif tag == "counter":
            counters.append({
                "name": kv["name"], "role": kv["role"], "width": int(kv["width"]),
                "max_rate": int(kv.get("max_rate_per_s", 0)),
            })
        elif tag == "gauge":
            role = kv["role"]
            gauges.append({
                "name": kv["name"], "role": role,
                "max": 1 if role == "playing" else int(kv["max"]),
            })
        elif tag == "sample":
            vals = {k: int(v) for k, v in kv.items() if k not in ("mono_ns", "wall_ns", "dev_frames")}
            samples.append({
                "line": no, "mono": int(kv["mono_ns"]),
                "wall": int(kv["wall_ns"]) if "wall_ns" in kv else None,
                "dev": int(kv["dev_frames"]) if "dev_frames" in kv else None,
                "vals": vals,
            })
        else:
            raise OracleError("unknown tag " + tag)
    if meta is None or not samples:
        raise OracleError("incomplete capture")
    return {"meta": meta, "counters": counters, "gauges": gauges, "samples": samples}


# ------------------------------------------------------------------------------------------------
# series analysis

def classify_delta(prev, cur, width, max_rate, dt):
    """('plain'|'wrap'|'reset', events). A fall is a wrap only if physically possible at max_rate."""
    if cur >= prev:
        return "plain", cur - prev
    if width == 32 and max_rate > 0:
        wrapped = (1 << 32) + cur - prev
        if wrapped * SEC <= max_rate * dt:
            return "wrap", wrapped
    return "reset", cur


def nearest_rank(sorted_vals, num, den):
    n = len(sorted_vals)
    rank = max(1, -(-num * n // den))  # ceil(num * n / den)
    return sorted_vals[min(rank, n) - 1]


def analyze_series(cap):
    m = cap["meta"]
    cad, pct = m["cadence_ns"], m["hole_pct"]
    findings = []

    def is_hole(dt):
        return dt * 100 > cad * pct

    acc, rejected = [], 0
    for s in cap["samples"]:
        if acc and s["mono"] <= acc[-1]["mono"]:
            rejected += 1
            findings.append({"kind": "non_monotonic_clock",
                             "values": {"mono_ns": s["mono"], "previous_mono_ns": acc[-1]["mono"]}})
            continue
        acc.append(s)
    n = len(acc)

    holes, observed_ns, censored_ns = [], 0, 0
    for e in range(1, n):
        dt = acc[e]["mono"] - acc[e - 1]["mono"]
        if is_hole(dt):
            censored_ns += dt
            holes.append({"from_ns": acc[e - 1]["mono"], "to_ns": acc[e]["mono"], "dt_ns": dt,
                          "missing_samples_est": max(0, (dt + cad // 2) // cad - 1)})
        else:
            observed_ns += dt

    first, last = acc[0]["mono"], acc[-1]["mono"]
    end = first + m["declared_ns"]
    truncated = None
    if end > last and (end - last) * 100 > cad * pct:
        truncated = {"missing_ns": end - last}
    coverage = min(1_000_000, observed_ns * 1_000_000 // m["declared_ns"])

    # counters
    cinfo = {}
    counter_reports = []
    for c in cap["counters"]:
        wmax = (1 << 32) - 1 if c["width"] == 32 else (1 << 64) - 1
        pts = []
        for i, s in enumerate(acc):
            if c["name"] in s["vals"]:
                v = s["vals"][c["name"]]
                if v > wmax:
                    findings.append({"kind": "value_out_of_width",
                                     "values": {"value": v, "width_bits": c["width"]}})
                else:
                    pts.append((i, v))
        rep = {"name": c["name"], "role": c["role"], "width": c["width"], "points": len(pts),
               "missing_values": n - len(pts), "observed_events": 0, "observed_ns": 0,
               "per_hour_milli": None, "censored_spans": 0, "censored_ns": 0,
               "unlocated_events_min": 0, "resets": 0, "wraps": 0}
        by = [None] * n
        spans = []
        for (i0, v0), (i1, v1) in zip(pts, pts[1:]):
            dt = acc[i1]["mono"] - acc[i0]["mono"]
            kind, ev = classify_delta(v0, v1, c["width"], c["max_rate"], dt)
            cens = kind == "reset" or is_hole(dt)
            if kind == "reset":
                rep["resets"] += 1
                findings.append({"kind": "counter_reset", "values": {"from": v0, "to": v1}})
            elif kind == "wrap":
                rep["wraps"] += 1
                findings.append({"kind": "counter_wrap", "values": {"from": v0, "to": v1}})
            if cens:
                rep["censored_spans"] += 1
                rep["censored_ns"] += dt
                rep["unlocated_events_min"] += ev
            else:
                rep["observed_events"] += ev
                rep["observed_ns"] += dt
                if i1 == i0 + 1:
                    by[i1] = ev
            spans.append((i0, i1, kind, ev, cens))
        if rep["observed_ns"] > 0:
            rep["per_hour_milli"] = rep["observed_events"] * NS_HOUR_X1000 // rep["observed_ns"]
        counter_reports.append(rep)
        cinfo[c["name"]] = {"role": c["role"], "carried": len(pts) >= 2, "by": by, "spans": spans}

    # gauges
    gauge_reports, playing = [], None
    for g in cap["gauges"]:
        vals, implausible, at = [], 0, [None] * n
        for i, s in enumerate(acc):
            if g["name"] in s["vals"]:
                v = s["vals"][g["name"]]
                if v > g["max"]:
                    implausible += 1
                    findings.append({"kind": "implausible_value", "values": {"value": v, "max": g["max"]}})
                    continue
                vals.append(v)
                if g["role"] == "playing":
                    at[i] = (v == 1)
        rep = {"name": g["name"], "role": g["role"], "points": len(vals), "implausible": implausible}
        if g["role"] == "playing":
            rep["playing_samples"] = sum(1 for x in at if x is True)
            rep["idle_samples"] = sum(1 for x in at if x is False)
            if vals and playing is None:
                playing = at
        else:
            if vals:
                sv = sorted(vals)
                p50 = nearest_rank(sv, 50, 100)
                rep["stats"] = {"n": len(sv), "min": sv[0], "max": sv[-1], "p50": p50,
                                "p99": nearest_rank(sv, 99, 100),
                                "spikes": sum(1 for v in sv if p50 > 0 and v > p50 * m["spike_factor"])}
            else:
                rep["stats"] = None
        gauge_reports.append(rep)

    # wall clock
    wall = {"carried": any(s["wall"] is not None for s in acc), "steps": []}
    for e in range(1, n):
        a, b = acc[e - 1], acc[e]
        if a["wall"] is not None and b["wall"] is not None:
            step = (b["wall"] - a["wall"]) - (b["mono"] - a["mono"])
            if abs(step) > m["wall_step_ns"]:
                wall["steps"].append({"at_mono_ns": b["mono"], "delta_ns": step})
                findings.append({"kind": "wall_step", "values": {"delta_ns": step}})

    # device clock
    dpts = [(i, s["dev"]) for i, s in enumerate(acc) if s["dev"] is not None]
    dev = {"carried": False, "rate_hz": m["device_rate_hz"], "expected_frames": 0, "observed_frames": 0,
           "drift_ppm": None, "resets": 0, "wraps": 0, "stall_intervals": 0}
    stall = [None] * n
    rate = m["device_rate_hz"]
    if rate is not None and len(dpts) >= 2:
        dev["carried"] = True
        for (i0, v0), (i1, v1) in zip(dpts, dpts[1:]):
            dt = acc[i1]["mono"] - acc[i0]["mono"]
            kind, ev = classify_delta(v0, v1, m["device_width"], 2 * rate, dt)
            if kind == "reset":
                dev["resets"] += 1
                findings.append({"kind": "device_clock_reset", "values": {"from": v0, "to": v1}})
                continue
            if kind == "wrap":
                dev["wraps"] += 1
            if is_hole(dt):
                continue
            expected = dt * rate // SEC
            dev["expected_frames"] += expected
            dev["observed_frames"] += ev
            if (m["stall_frames"] is not None and i1 == i0 + 1 and expected >= ev
                    and expected - ev >= m["stall_frames"]):
                stall[i1] = expected - ev
                dev["stall_intervals"] += 1
        if dev["expected_frames"] > 0:
            diff = dev["observed_frames"] - dev["expected_frames"]
            # truncate toward zero, as the Rust i128 division does
            q = abs(diff) * 1_000_000 // dev["expected_frames"]
            dev["drift_ppm"] = -q if diff < 0 else q
    elif dpts and rate is None:
        findings.append({"kind": "device_rate_missing", "values": {"points": len(dpts)}})

    # dropouts
    def role(r):
        for name, info in cinfo.items():
            if info["role"] == r:
                return info
        return None

    under = role("dev_underruns")
    carried_under = bool(under and under["carried"])
    carried_stall = m["stall_frames"] is not None and dev["carried"]
    known = carried_under or carried_stall
    observed, censored = [], []

    def window(e):
        start = acc[e - 1]["mono"]
        w, k = [e], e - 1
        while k >= 1 and acc[k]["mono"] + m["playout_ns"] >= start:
            w.append(k)
            k -= 1
        return w

    def counter_ev(info, w, sig):
        if not info or not info["carried"]:
            return None, {"signal": sig, "why": "not_carried"}
        total = 0
        for e in w:
            if info["by"][e] is None:
                return None, {"signal": sig, "why": "incomplete_in_window"}
            total += info["by"][e]
        return total > 0, None

    def source_ev(w):
        info, missing = role("source_bytes"), []
        ok_c = bool(info and info["carried"])
        if not ok_c:
            missing.append({"signal": "source_bytes", "why": "not_carried"})
        elif any(info["by"][e] is None for e in w):
            missing.append({"signal": "source_bytes", "why": "incomplete_in_window"})
        if playing is None:
            missing.append({"signal": "playing_state", "why": "not_carried"})
        elif any(playing[e] is None or playing[e - 1] is None for e in w):
            missing.append({"signal": "playing_state", "why": "incomplete_in_window"})
        if missing:
            return None, missing
        return any(info["by"][e] == 0 and playing[e - 1] and playing[e] for e in w), None

    if known:
        for e in range(1, n):
            ev = (under["by"][e] or 0) if carried_under else 0
            st = stall[e]
            if ev > 0 or st is not None:
                w = window(e)
                present, unobs = [], []
                fired, miss = source_ev(w)
                if miss:
                    unobs.extend(miss)
                elif fired:
                    present.append("source_outage")
                for r, sig, cls in (("late_packets", "late_packets", "network_lateness"),
                                    ("cpu_misses", "cpu_misses", "cpu_deadline_miss")):
                    fired, miss = counter_ev(role(r), w, sig)
                    if miss:
                        unobs.append(miss)
                    elif fired:
                        present.append(cls)
                if len(present) == 1:
                    cause = {"class": present[0], "unexcluded": unobs}
                elif len(present) >= 2:
                    cause = {"class": "ambiguous", "present": present}
                elif unobs:
                    cause = {"class": "undetermined", "missing": unobs}
                elif ev > 0:
                    cause = {"class": "output_underrun"}
                else:
                    cause = {"class": "undetermined",
                             "missing": [{"signal": "dev_underruns", "why": "not_carried"}]}
                observed.append({"from_ns": acc[e - 1]["mono"], "to_ns": acc[e]["mono"],
                                 "underrun_events": ev, "stall_deficit_frames": st, "cause": cause})
        if carried_under:
            for (i0, i1, kind, ev, cens) in under["spans"]:
                if cens and ev > 0:
                    censored.append({"from_ns": acc[i0]["mono"], "to_ns": acc[i1]["mono"],
                                     "events_min": ev, "reason": "reset" if kind == "reset" else "hole"})

    classes = ["source_outage", "network_lateness", "cpu_deadline_miss", "output_underrun",
               "ambiguous", "undetermined"]
    totals = {"intervals": len(observed),
              "underrun_events": sum(o["underrun_events"] for o in observed),
              "censored_spans": len(censored),
              "censored_events_min": sum(c["events_min"] for c in censored)}
    for cls in classes:
        totals[cls] = sum(1 for o in observed if o["cause"]["class"] == cls)

    # absolute verdict
    reasons = []
    if m["min_cov_ppm"] is not None and coverage < m["min_cov_ppm"]:
        reasons.append({"kind": "coverage_below_min", "have_ppm": coverage, "min_ppm": m["min_cov_ppm"]})
    if m["max_dropouts"] is not None:
        if not known:
            reasons.append({"kind": "dropouts_unknown"})
        elif len(observed) + len(censored) > m["max_dropouts"]:
            reasons.append({"kind": "dropouts_exceed_max", "have": len(observed) + len(censored),
                            "max": m["max_dropouts"]})
    assessed = m["min_cov_ppm"] is not None or m["max_dropouts"] is not None
    verdict = "not_assessed" if not assessed else ("qualified" if not reasons else "not_qualified")

    return {
        "schema": "ffw.baseline.series-report.v1",
        "evidence": m["evidence"], "profile": m["profile"],
        "measured_on_device": m["evidence"] == "physical",
        "denominators": {
            "declared_ns": m["declared_ns"], "cadence_ns": cad,
            "expected_samples": m["declared_ns"] // cad + 1,
            "samples_total": len(cap["samples"]), "samples_accepted": n,
            "samples_rejected_non_monotonic": rejected,
            "intervals_total": n - 1, "intervals_observed": (n - 1) - len(holes),
            "intervals_censored": len(holes), "observed_ns": observed_ns,
            "censored_ns": censored_ns, "coverage_ppm": coverage},
        "holes": holes, "truncated": truncated, "wall_clock": wall, "device_clock": dev,
        "counters": counter_reports, "gauges": gauge_reports,
        "dropouts": {"known": known,
                     "missing": [] if known else ["dev_underruns", "device_clock"],
                     "observed": observed, "censored": censored, "totals": totals},
        "findings": findings, "findings_dropped": 0,
        "absolute": {"thresholds": {"min_coverage_ppm": m["min_cov_ppm"],
                                    "max_dropout_intervals": m["max_dropouts"]},
                     "verdict": verdict, "reasons": reasons},
    }


# ------------------------------------------------------------------------------------------------
# memory

def _kib(body, key):
    for line in body.splitlines():
        if line.startswith(key + ":"):
            parts = line.split(":", 1)[1].split()
            if len(parts) != 2 or parts[1] != "kB":
                raise OracleError("bad unit for " + key)
            return int(parts[0])
    return None


def parse_memory(text):
    page, reserve = None, None
    snaps = []
    sec = None  # [kind, pid, body] while a section is open

    def close():
        nonlocal sec
        if sec is not None:
            kind, pid, body = sec
            if kind == "meminfo":
                snaps[-1]["meminfo"] = body
            else:
                snaps[-1]["procs"].setdefault(pid, {})[kind] = body
            sec = None

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if page is None:
            if not line:
                continue
            toks = line.split()
            if toks[0] != "ffw.baseline.memory.v1":
                raise OracleError("bad header")
            kv = _kv(toks[1:])
            page = int(kv["page_size"])
            reserve = int(kv["reserve_kib"]) if "reserve_kib" in kv else None
        elif line.startswith("snapshot "):
            close()
            kv = _kv(line.split()[1:])
            snaps.append({"label": kv["label"], "at": int(kv["at_mono_ns"]), "meminfo": None, "procs": {}})
        elif line.startswith("---"):
            close()
            toks = line.split()
            pid = int(_kv(toks[2:])["pid"]) if len(toks) > 2 else 0
            sec = [toks[1], pid, ""]
        elif sec is not None:
            sec[2] += raw + "\n"
    close()
    return {"page": page, "reserve": reserve, "snaps": snaps}


def account_memory(cap):
    page_kib = cap["page"] // 1024
    out_snaps, max_used, max_pss, max_hwm = [], None, None, None
    for snap in cap["snaps"]:
        findings = []
        procs = []
        for pid in sorted(snap["procs"]):
            secs = snap["procs"][pid]
            st, ro, sm = secs.get("status"), secs.get("smaps_rollup"), secs.get("statm")
            name = ""
            vm_rss = hwm = None
            if st is not None:
                for line in st.splitlines():
                    if line.startswith("Name:"):
                        name = line.split(":", 1)[1].strip()
                vm_rss, hwm = _kib(st, "VmRSS"), _kib(st, "VmHWM")
            rss_ro = _kib(ro, "Rss") if ro is not None else None
            statm_rss = int(sm.split()[1]) * page_kib if sm is not None else None
            if rss_ro is not None:
                rss, src = rss_ro, "smaps_rollup"
            elif vm_rss is not None:
                rss, src = vm_rss, "status"
            elif statm_rss is not None:
                rss, src = statm_rss, "statm"
            else:
                rss, src = None, "none"
            kthread = rss is None and st is not None
            if kthread:
                findings.append({"kind": "kernel_thread", "subject": "pid=%d" % pid})
            elif rss is None:
                findings.append({"kind": "no_rss_source", "subject": "pid=%d" % pid})
            if rss is not None:
                for label, other in (("status", vm_rss), ("statm", statm_rss)):
                    if other is not None and src != label and other != rss:
                        findings.append({"kind": "rss_source_mismatch", "subject": "pid=%d vs=%s" % (pid, label),
                                         "values": {"chosen_kib": rss, "other_kib": other}})
            pss = uss = shared = None
            if ro is not None:
                sc, sd = _kib(ro, "Shared_Clean"), _kib(ro, "Shared_Dirty")
                pc, pd = _kib(ro, "Private_Clean"), _kib(ro, "Private_Dirty")
                pss, uss, shared = _kib(ro, "Pss"), pc + pd, sc + sd
                if shared + uss != rss_ro:
                    findings.append({"kind": "rollup_rss_mismatch", "subject": "pid=%d" % pid,
                                     "values": {"rss_kib": rss_ro, "parts_kib": shared + uss}})
                if not (uss <= pss <= rss_ro):
                    findings.append({"kind": "pss_out_of_range", "subject": "pid=%d" % pid,
                                     "values": {"uss_kib": uss, "pss_kib": pss, "rss_kib": rss_ro}})
            if st is not None:
                a, f, s, tot = (_kib(st, "RssAnon"), _kib(st, "RssFile"), _kib(st, "RssShmem"), vm_rss)
                if None not in (a, f, s, tot) and a + f + s != tot:
                    findings.append({"kind": "rss_breakdown_mismatch", "subject": "pid=%d" % pid,
                                     "values": {"vm_rss_kib": tot, "parts_kib": a + f + s}})
                if hwm is not None and vm_rss is not None and hwm < vm_rss:
                    findings.append({"kind": "hwm_below_rss", "subject": "pid=%d" % pid, "values": {"hwm_kib": hwm, "rss_kib": vm_rss}})
            procs.append({"pid": pid, "name": name, "rss_kib": rss, "rss_source": src, "pss_kib": pss,
                          "uss_kib": uss, "shared_kib": shared, "hwm_kib": hwm, "kernel_thread": kthread})
            if hwm is not None:
                max_hwm = hwm if max_hwm is None else max(max_hwm, hwm)

        system = None
        if snap["meminfo"] is not None:
            mi = snap["meminfo"]
            total, free = _kib(mi, "MemTotal"), _kib(mi, "MemFree")
            used = total - free if total >= free else None
            if used is None:
                findings.append({"kind": "free_exceeds_total", "subject": "meminfo",
                                 "values": {"mem_total_kib": total, "mem_free_kib": free}})
            naive = sum(p["rss_kib"] for p in procs if p["rss_kib"] is not None)
            complete = all(p["rss_kib"] is None or p["pss_kib"] is not None for p in procs)
            pss_sum = sum(p["pss_kib"] for p in procs if p["pss_kib"] is not None) if complete else None
            dc = None
            if pss_sum is not None:
                if naive >= pss_sum:
                    dc = naive - pss_sum
                else:
                    findings.append({"kind": "pss_exceeds_rss", "subject": "system",
                                     "values": {"rss_sum_kib": naive, "pss_sum_kib": pss_sum}})
            slab, ks, pt = _kib(mi, "Slab"), _kib(mi, "KernelStack"), _kib(mi, "PageTables")
            kernel = slab + ks + pt if None not in (slab, ks, pt) else None
            cached, mapped = _kib(mi, "Cached"), _kib(mi, "Mapped")
            unmapped = None
            if cached is not None and mapped is not None:
                if cached >= mapped:
                    unmapped = cached - mapped
                else:
                    findings.append({"kind": "mapped_exceeds_cached", "subject": "meminfo",
                                     "values": {"cached_kib": cached, "mapped_kib": mapped}})
            buffers = _kib(mi, "Buffers")
            unattr = None
            if None not in (used, pss_sum, kernel, unmapped, buffers):
                unattr = used - pss_sum - kernel - unmapped - buffers
                if unattr < 0:
                    findings.append({"kind": "over_attributed", "subject": "system", "values": {"by_kib": -unattr}})
            system = {"mem_total_kib": total, "mem_free_kib": free, "used_kib": used,
                      "process_rss_naive_sum_kib": naive, "process_pss_sum_kib": pss_sum,
                      "double_counted_kib": dc, "kernel_reported_kib": kernel,
                      "unmapped_cache_kib": unmapped, "buffers_kib": buffers, "unattributed_kib": unattr}
            if used is not None and (max_used is None or used > max_used[0]):
                max_used = (used, total)
            if pss_sum is not None:
                max_pss = pss_sum if max_pss is None else max(max_pss, pss_sum)
        out_snaps.append({"label": snap["label"], "at_mono_ns": snap["at"], "processes": procs,
                          "system": system, "findings": findings, "findings_dropped": 0})

    reserve_have = (max_used[1] - max_used[0]) if max_used and max_used[1] >= max_used[0] else None
    if cap["reserve"] is not None and reserve_have is not None:
        verdict = "pass" if reserve_have >= cap["reserve"] else "fail"
    else:
        verdict = "not_assessed"
    return {"schema": "ffw.baseline.memory-report.v1", "page_size_bytes": cap["page"],
            "snapshots": out_snaps,
            "peaks": {"max_used_kib": max_used[0] if max_used else None,
                      "max_process_pss_sum_kib": max_pss, "max_vm_hwm_kib": max_hwm},
            "headroom": {"required_reserve_kib": cap["reserve"], "reserve_kib": reserve_have,
                         "verdict": verdict}}


# ------------------------------------------------------------------------------------------------
# comparison and inventory

def subset_diff(path, expected, actual):
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key, ev in expected.items():
            if key not in actual:
                return "%s.%s: missing from the oracle report" % (path, key)
            d = subset_diff("%s.%s" % (path, key), ev, actual[key])
            if d:
                return d
        return None
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return "%s: expected %d elements, oracle has %d" % (path, len(expected), len(actual))
        for i, (ev, av) in enumerate(zip(expected, actual)):
            d = subset_diff("%s[%d]" % (path, i), ev, av)
            if d:
                return d
        return None
    if type(expected) is bool or type(actual) is bool or expected is None or actual is None:
        return None if expected is actual else "%s: expected %r, oracle has %r" % (path, expected, actual)
    return None if expected == actual else "%s: expected %r, oracle has %r" % (path, expected, actual)


def load_json(rel):
    with open(os.path.join(HERE, rel), encoding="utf-8") as fh:
        return json.load(fh)


def oracle_report(args):
    if len(args) == 2 and args[0] == "series":
        with open(os.path.join(HERE, args[1]), encoding="utf-8") as fh:
            return analyze_series(parse_capture(fh.read()))
    if len(args) == 2 and args[0] == "memory":
        with open(os.path.join(HERE, args[1]), encoding="utf-8") as fh:
            return account_memory(parse_memory(fh.read()))
    return None  # compare / error cases are the Rust CLI's own behaviour


def check_inventory(cases):
    problems = []
    ids = [c["id"] for c in cases["cases"]]
    if len(ids) != len(set(ids)):
        problems.append("duplicate case ids")
    referenced = set()
    for c in cases["cases"]:
        for a in c["args"]:
            if a.startswith("captures/"):
                referenced.add(a)
        if "expect" in c:
            referenced.add(c["expect"])
    for rel in sorted(referenced):
        if not os.path.isfile(os.path.join(HERE, rel)):
            problems.append("%s is referenced but missing" % rel)
    for sub in ("captures", "expected"):
        for name in sorted(os.listdir(os.path.join(HERE, sub))):
            if "%s/%s" % (sub, name) not in referenced:
                problems.append("%s/%s is not used by any case" % (sub, name))
    covered = set()
    for inv in cases["invariants"]:
        has_cases, has_why = "cases" in inv, "inapplicable" in inv
        if has_cases == has_why:
            problems.append("%s needs exactly one of cases/inapplicable" % inv["id"])
        elif has_cases:
            for cid in inv["cases"]:
                if cid not in ids:
                    problems.append("%s names unknown case %s" % (inv["id"], cid))
                covered.add(cid)
        elif len(inv["inapplicable"]) <= 20:
            problems.append("%s: explain the inapplicability" % inv["id"])
    for cid in ids:
        if cid not in covered:
            problems.append("case %s covers no invariant" % cid)
    return problems


def check():
    cases = load_json("cases.json")
    problems = check_inventory(cases)
    checked = 0
    for c in cases["cases"]:
        if "expect" not in c:
            continue  # malformed-input cases: the Rust parser's error text is what they pin
        report = oracle_report(c["args"])
        if report is None:
            continue  # compare cases: the Rust CLI's own refusal logic
        checked += 1
        diff = subset_diff("$", load_json(c["expect"]), report)
        if diff:
            problems.append("%s: %s" % (c["id"], diff))
    # Planted negatives for this checker: a mutated expectation must be rejected.
    probe = {"a": {"b": 1}, "c": [1, {"d": "x"}], "e": None}
    for bad in ({"a": {"b": 2}}, {"a": {"z": 1}}, {"c": [1]}, {"c": [1, {"d": "y"}]}, {"e": 0}):
        if subset_diff("$", bad, probe) is None:
            problems.append("subset matcher accepted a planted difference: %r" % (bad,))
    if checked == 0:
        problems.append("no series/memory case was checked: a vacuous pass")
    for p in problems:
        print("FAIL:", p)
    print("oracle: %d series/memory cases compared with their expected files, %d problem(s)"
          % (checked, len(problems)))
    return 0 if not problems else 1


def main(argv):
    if argv[:1] == ["--check"]:
        return check()
    if len(argv) == 2 and argv[0] == "--print":
        kind = "memory" if os.path.basename(argv[1]).startswith("mem") else "series"
        print(json.dumps(oracle_report([kind, argv[1]]), indent=1, sort_keys=False))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
