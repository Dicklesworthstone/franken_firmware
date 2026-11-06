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

It also checks the redaction rules (an independent classifier against tests/e02/redaction_vectors.json, the planted identifiers, the
modelled diagnostics and remove-the-plant controls) and the human-run recipe in docs/contracts/e02.md (its two scripts are linted and, if
clean, run against scripted stand-in /proc files in every POSIX shell present; their output must be the recipe-shaped fixtures).
"""
import contextlib
import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

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
                        name = bounded_py(line.split(":", 1)[1].strip())
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
# redaction (independent of the Rust crate/src/redact.rs: written from the rules in docs/contracts/e02.md, with regular
# expressions, where the Rust walks bytes run by run). The shapes are tried in order; the first names the class.

HOST_SUFFIXES = ("local", "lan", "home", "internal", "localdomain", "arpa")
_HEX = "0-9A-Fa-f"


def classify_text(s):
    if re.search(r"[%s]{2}([:-])(?:[%s]{2}\1){4}[%s]{2}" % (_HEX, _HEX, _HEX), s) \
            or re.search(r"(?<![0-9A-Za-z])[%s]{12}(?![0-9A-Za-z])" % _HEX, s):
        return "mac"
    if re.search(r"(?<![0-9.])\.*[0-9]{1,3}(?:\.[0-9]{1,3}){3}\.*(?![0-9.])", s):
        return "ipv4"
    for run in re.findall(r"[%s:]+" % _HEX, s):
        if run.count(":") >= 2 and all(len(g) <= 4 for g in run.split(":")) and re.search("[%s]" % _HEX, run):
            return "ipv6"
    for run in re.findall(r"[A-Za-z0-9.-]+", s):
        *front, last = run.split(".")
        if any(front) and last.lower() in HOST_SUFFIXES:
            return "hostname"
    for run in re.findall(r"[A-Za-z0-9]+", s):
        if len(run) >= 8 and len(re.findall("[0-9]", run)) >= 3 and len(re.findall("[A-Za-z]", run)) >= 3:
            return "serial"
    return None


def bounded_py(s):
    """What a diagnostic or report repeats of input text: its class when it has an identifier's shape, else at most 32 characters."""
    cls = classify_text(s)
    return "<redacted:%s>" % cls if cls else s[:32]


def first_error(kind, text):
    """The first error among those this oracle models, worded as the Rust CLI words it (`line N: Kind ...`), or None. Only what the
    redaction and bound cases need is modelled: the line limit, an unknown first token, an undeclared series name, and a profile,
    series name or snapshot label with an identifier's shape."""
    declared, header_seen = set(), False
    for no, raw in enumerate(text.splitlines(), 1):
        if len(raw.encode("utf-8")) > 4096:
            return "line %d: LineTooLong" % no
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        if kind == "series":
            if not header_seen:
                if line != "ffw.baseline.capture.v1":
                    return "line %d: BadHeader" % no
                header_seen = True
                continue
            tag, kv = toks[0], _kv(toks[1:])
            if tag == "meta":
                hit = classify_text(kv.get("profile", ""))
                if hit:
                    return 'line %d: SiteIdentifier { field: "profile", class: "%s" }' % (no, hit)
            elif tag in ("counter", "gauge"):
                hit = classify_text(kv.get("name", ""))
                if hit:
                    return 'line %d: SiteIdentifier { field: "name", class: "%s" }' % (no, hit)
                declared.add(kv.get("name"))
            elif tag == "sample":
                for key in kv:
                    if key not in ("mono_ns", "wall_ns", "dev_frames") and key not in declared:
                        return 'line %d: UndeclaredSeries("%s")' % (no, bounded_py(key))
            else:
                return 'line %d: UnknownTag("%s")' % (no, bounded_py(tag))
        elif toks[0] == "snapshot":
            hit = classify_text(_kv(toks[1:]).get("label", ""))
            if hit:
                return 'line %d: SiteIdentifier { field: "label", class: "%s" }' % (no, hit)
    return None


def fixture_text(args):
    out = ""
    for a in args:
        if a.startswith("synthetic/"):
            with open(os.path.join(HERE, a), encoding="utf-8") as fh:
                out += fh.read()
    return out


# The checks, as small pure functions so that each can be shown to refuse a planted fault (selfcheck_redaction below).

def plant_problems(cid, needles, text):
    """The planted strings must really be in the capture, or "never echoed" passes vacuously."""
    return ["%s: %r is not in the capture, so 'never echoed' would be vacuous" % (cid, n) for n in needles if n not in text]


def echo_problems(cid, needles, output, what):
    return ["%s: the oracle's %s repeats %r" % (cid, what, n) for n in needles if n in output]


def refusal_problems(case, text):
    """A refusal case: the modelled diagnostic is the one the case expects, repeats no planted string, and (the remove-the-plant control)
    the same file with every planted string swapped for a plain word is no longer refused or redacted."""
    cid, kind, planted = case["id"], case["args"][0], case.get("stderr_lacks", [])
    problems = []
    modelled = first_error(kind, text)
    if modelled is None or case["stderr_contains"] not in modelled:
        problems.append("%s: the oracle models %r, the case expects %r" % (cid, modelled, case["stderr_contains"]))
    problems += echo_problems(cid, planted, modelled or "", "modelled diagnostic")
    clean = text
    for needle in planted:
        clean = clean.replace(needle, "plain-word-v1")
    control = first_error(kind, clean)
    if control is not None and ("SiteIdentifier" in control or "<redacted" in control):
        problems.append("%s: with the plant removed the oracle still refuses: %r" % (cid, control))
    return problems


def positive_problems(name, body):
    """Permitted positives: nothing an existing capture names, labels or profiles is refused, and no process name is redacted."""
    problems = []
    for m in re.finditer(r"\b(?:name|profile|label)=(\S+)", body):
        if classify_text(m.group(1)):
            problems.append("%s: %s would be refused as a site identifier" % (name, m.group(0)))
    for m in re.finditer(r"^Name:[ \t]*(.*)$", body, re.M):
        if classify_text(m.group(1).strip()):
            problems.append("%s: process name %r would be redacted" % (name, m.group(1)))
    return problems


def check_redaction(cases, problems):
    """Vectors, planted strings, modelled diagnostics, and the remove-the-plant controls. Returns the number of things compared."""
    compared = 0
    vectors = load_json("redaction_vectors.json")["vectors"]
    if len(vectors) < 20:
        problems.append("redaction_vectors.json has too few vectors to mean anything")
    for v in vectors:
        compared += 1
        if classify_text(v["text"]) != v["class"]:
            problems.append("redaction vector %r: the oracle says %r, the vector says %r" % (v["text"], classify_text(v["text"]), v["class"]))
    for name in sorted(os.listdir(os.path.join(HERE, "synthetic"))):
        if name.startswith(("redact_", "bounded_", "longline")):
            continue  # the planted fixtures: refused or redacted on purpose
        with open(os.path.join(HERE, "synthetic", name), encoding="utf-8") as fh:
            problems += positive_problems(name, fh.read())
        compared += 1
    for c in cases["cases"]:
        outs, errs = c.get("stdout_lacks", []), c.get("stderr_lacks", [])
        if not (outs or errs):
            continue
        compared += 1
        text = fixture_text(c["args"])
        problems += plant_problems(c["id"], outs + errs, text)
        if outs:
            problems += echo_problems(c["id"], outs, json.dumps(oracle_report(c["args"])), "report")
        if errs and "stderr_contains" in c:  # a refusal or diagnostic case; a summary case only names strings its summary must lack
            problems += refusal_problems(c, text)
    # The bound cases: what the Rust CLI must print, modelled.
    for cid, want in (("E02-E-BOUNDED-DIAG", 'UnknownTag("' + "x" * 32 + '")'), ("E02-E-LONGLINE", "LineTooLong")):
        case = next(c for c in cases["cases"] if c["id"] == cid)
        compared += 1
        got = first_error(case["args"][0], fixture_text(case["args"]))
        if got is None or want not in got:
            problems.append("%s: the oracle models %r, wanted %r" % (cid, got, want))
    return compared


def selfcheck_redaction(problems):
    """Planted negatives for the redaction checks above: each must refuse a planted fault, and accept a correct input."""
    probe = {"id": "probe", "args": ["series", "synthetic/x.cap"],
             "stderr_contains": 'line 3: SiteIdentifier { field: "profile", class: "ipv4" }', "stderr_lacks": ["192.0.2.17"]}
    good = ("ffw.baseline.capture.v1\n# c\nmeta evidence=synthetic profile=192.0.2.17 cadence_ms=1000 declared_ms=2000\n"
            "sample mono_ns=1\n")
    # a second identifier that the plant's removal does not cure
    two = good.replace("sample mono_ns=1\n", "counter name=SN0000EXAMPLE role=other width=32\nsample mono_ns=1\n")
    for what, bad, expect_problem in (
            ("a correct refusal", refusal_problems(probe, good), False),
            ("a refusal that removing the plant does not cure", refusal_problems(probe, two), True),
            ("a plant that is not in the capture", plant_problems("probe", ["192.0.2.17"], "nothing planted here\n"), True),
            ("a plant that is in the capture", plant_problems("probe", ["192.0.2.17"], good), False),
            ("a report that repeats a planted string", echo_problems("probe", ["192.0.2.17"], '{"profile":"192.0.2.17"}', "report"), True),
            ("a report that does not", echo_problems("probe", ["192.0.2.17"], '{"profile":"<redacted:ipv4>"}', "report"), False),
            ("a capture that names an address", positive_problems("f.cap", "meta evidence=synthetic profile=192.0.2.17 x\n"), True),
            ("a process named by a serial", positive_problems("f.txt", "Name:\tSN0000EXAMPLE\n"), True),
            ("an ordinary capture", positive_problems("f.cap", "meta evidence=synthetic profile=plain-v1 x\nName:\tplayer\n"), False)):
        if bool(bad) != expect_problem:
            problems.append("self-check: %s %s" % (what, "was accepted" if expect_problem else "was flagged: %r" % (bad,)))


# ------------------------------------------------------------------------------------------------
# the recipe: the two scripts in docs/contracts/e02.md are extracted, linted, and (only if the lint is clean) run against scripted
# stand-in /proc files; their output must be byte for byte the recipe-shaped fixtures. Nothing here touches a device or the real /proc.

DOC = os.path.join(HERE, "..", "..", "docs", "contracts", "e02.md")
FORBIDDEN_WORDS = re.compile(
    r"(?<![\w-])(curl|wget|nc|ncat|netcat|ssh|scp|telnet|ping|ifconfig|iwconfig|iw|route|iptables|tc|reboot|poweroff|halt|shutdown|dd|"
    r"mount|umount|insmod|rmmod|modprobe|sysctl|fw_setenv|nvram|rm|mv|cp|chmod|chown|kill|killall|systemctl|service|su|sudo|eval|exec|"
    r"tee|sed|awk|grep)(?![\w-])")

SERIES_ROWS = [("100.00", 1700000000, 0, 0, 0, 0, 1), ("101.01", 1700000001, 0, 0, 0, 192000, 1), ("102.00", 1700000002, 0, 0, 0, 384000, 1),
               ("103.02", 1700000003, 0, 0, 0, 576000, 1), ("104.01", 1700000004, 0, 0, 0, 768000, 1), ("105.00", 1700000005, 0, 0, 0, 960000, 1)]
MEMINFO = ("MemTotal:       30000 kB\nMemFree:        20000 kB\nMemAvailable:   24000 kB\nBuffers:          500 kB\nCached:          7000 kB\n"
           "Mapped:          3000 kB\nShmem:            400 kB\nSlab:            1500 kB\nKernelStack:      100 kB\nPageTables:       200 kB\n"
           "AnonPages:       4000 kB\n")
PROCS = {
    "100": ("Name:\tplayer\nVmHWM:\t    3000 kB\nVmRSS:\t    2500 kB\n",
            "Rss:                2500 kB\nPss:                1800 kB\nShared_Clean:        900 kB\nShared_Dirty:          0 kB\n"
            "Private_Clean:       500 kB\nPrivate_Dirty:      1100 kB\n", "2000 625 150 100 0 400 0\n"),
    "200": ("Name:\tnetd\nVmHWM:\t    1300 kB\nVmRSS:\t    1200 kB\n",
            "Rss:                1200 kB\nPss:                 700 kB\nShared_Clean:        800 kB\nShared_Dirty:          0 kB\n"
            "Private_Clean:       100 kB\nPrivate_Dirty:      300 kB\n", "1000 300 100 50 0 200 0\n"),
}


def extract_scripts():
    with open(DOC, encoding="utf-8") as fh:
        md = fh.read()
    return dict(re.findall(r"<!-- e02-recipe:(\S+) -->\n```sh\n(.*?)\n```", md, re.S))


def lint_script(name, text):
    """A lint, not a proof: no command that could affect a device or the network, writes only to $OUT or $MEMOUT, reads /proc only."""
    problems = []
    for no, raw in enumerate(text.splitlines(), 1):
        code = re.sub(r"(^|\s)#.*$", "", raw)  # a comment starts at a # after whitespace, not at ${var#...}
        m = FORBIDDEN_WORDS.search(re.sub(r"'[^']*'|\"[^\"]*\"", "", code))
        if m:
            problems.append("%s:%d uses %r" % (name, no, m.group(1)))
        for mm in re.finditer(r"(?<![0-9<$(])(>>?)\s*(\"[^\"]*\"|\S+)", code):
            if mm.group(2) not in ('"$OUT"', '"$MEMOUT"'):
                problems.append("%s:%d writes to %s" % (name, no, mm.group(2)))
        for mm in re.finditer(r"(?<![<(])<\s*(\"[^\"]*\"|\S+)", code):
            if mm.group(1) not in ('"$PROC/uptime"', '"$1"'):
                problems.append("%s:%d reads %s with a redirect" % (name, no, mm.group(1)))
        for mm in re.finditer(r"\bcat\s+(\"[^\"]*\"|\S+)", code):
            if not mm.group(1).startswith('"$PROC/'):
                problems.append("%s:%d cats %s" % (name, no, mm.group(1)))
    return problems


def run_recipe_command(argv, env=None, timeout=60):
    """Bound only a local recipe's owned process group; timeout remains a meaningful failure, never a traceback."""
    child = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        try:
            out, err = child.communicate(timeout=timeout)
            return subprocess.CompletedProcess(argv, child.returncode, out, err)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = child.communicate()
            return subprocess.CompletedProcess(argv, 124, out, "TIMED OUT after %ss; local recipe group killed; %s" % (timeout, err[:200]))
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def run_sampler(shell, script_path, work):
    d = os.path.join(work, "series-" + shell)
    os.makedirs(d)

    def put(rel, text):
        with open(os.path.join(d, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    put("table", "".join("%s %s %d %d %d %d %d\n" % r for r in SERIES_ROWS))
    put("i", "1")
    put("tick.sh", 'i=$(cat "$F/i"); i=$((i + 1)); printf "%s" "$i" > "$F/i"\nn=0\n'
        "while read -r up now xr late cpu src play; do\n    n=$((n + 1))\n"
        '    if [ "$n" -eq "$i" ]; then\n'
        '        printf "%s 400.00\\n" "$up" > "$F/uptime"; printf "%s\\n" "$now" > "$F/now"\n'
        '        printf "%s\\n" "$xr" > "$F/xruns"; printf "%s\\n" "$late" > "$F/late"; printf "%s\\n" "$cpu" > "$F/cpu"\n'
        '        printf "%s\\n" "$src" > "$F/src"; printf "%s\\n" "$play" > "$F/play"\n    fi\ndone < "$F/table"\n')
    first = SERIES_ROWS[0]
    put("uptime", "%s 400.00\n" % first[0])
    put("now", "%d\n" % first[1])
    for nm, v in zip(("xruns", "late", "cpu", "src", "play"), first[2:]):
        put(nm, "%d\n" % v)
    env = dict(os.environ, PROC=d, OUT=os.path.join(d, "out.cap"), F=d, PROFILE="recipe-example-v1", EVIDENCE="synthetic", COUNT="6",
               CADENCE_MS="1000", TICK="sh %s" % os.path.join(d, "tick.sh"), NOW="cat %s/now" % d, PLAYOUT_MS="500",
               MIN_COVERAGE_PPM="950000", MAX_DROPOUT_INTERVALS="0",
               NOTE="SYNTHETIC. Written by the recipe's sampler from scripted stand-in files; it says nothing about any device.",
               COUNTERS="xruns dev_underruns 32 %s/xruns late late_packets 32 %s/late cpu cpu_misses 32 %s/cpu src source_bytes 64 %s/src" % ((d,) * 4),
               GAUGES="play playing %s/play 1" % d)
    done = run_recipe_command([shell, script_path], env=env)
    if done.returncode != 0 or done.stderr:
        return None, "%s sampler: exit %d, stderr %r" % (shell, done.returncode, done.stderr[:200])
    with open(env["OUT"], encoding="utf-8") as fh:
        return fh.read(), None


def run_snapshot(shell, script_path, work):
    d = os.path.join(work, "memory-" + shell)
    os.makedirs(d)

    def put(rel, text):
        with open(os.path.join(d, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    put("uptime", "1.00 2.00\n")
    put("meminfo", MEMINFO)
    for pid, (status, rollup, statm) in PROCS.items():
        os.makedirs(os.path.join(d, pid))
        put(os.path.join(pid, "status"), status)
        put(os.path.join(pid, "smaps_rollup"), rollup)
        put(os.path.join(pid, "statm"), statm)
    env = dict(os.environ, PROC=d, MEMOUT=os.path.join(d, "memory.txt"), PAGE_SIZE="4096", RESERVE_KIB="4096")
    done = run_recipe_command([shell, script_path, "recipe-example", "100", "200"], env=env)
    if done.returncode != 0 or done.stderr:
        return None, "%s snapshot: exit %d, stderr %r" % (shell, done.returncode, done.stderr[:200])
    with open(env["MEMOUT"], encoding="utf-8") as fh:
        return fh.read(), None


def compare_problem(shell, what, got, err, want):
    """The script's output must be byte for byte the fixture."""
    if err:
        return err
    if got != want:
        return "%s: the recipe's %s does not write the recipe-shaped fixture" % (shell, what)
    return None


def control_problem(what, got, err, want):
    """Remove-the-plant control: a script with one rule changed must NOT reproduce the fixture, or the comparison proves nothing."""
    if err is None and got == want:
        return "recipe control: dropping %s still reproduces the fixture" % what
    return None


def selfcheck_recipe(problems):
    """Planted negatives for the recipe checks: each must refuse a planted fault and accept a correct input."""
    for what, got, expect_problem in (
            ("output that differs from the fixture", compare_problem("sh", "sampler", "x\n", None, "y\n"), True),
            ("output that equals the fixture", compare_problem("sh", "sampler", "y\n", None, "y\n"), False),
            ("a script that failed to run", compare_problem("sh", "sampler", None, "sh sampler: exit 1", "y\n"), True),
            ("a changed script that still reproduces the fixture", control_problem("a rule", "y\n", None, "y\n"), True),
            ("a changed script that no longer reproduces it", control_problem("a rule", "x\n", None, "y\n"), False)):
        if bool(got) != expect_problem:
            problems.append("self-check: %s %s" % (what, "was accepted" if expect_problem else "was flagged: %r" % (got,)))
    clean = "printf '%s' \"$x\" > \"$OUT\"\ncat \"$PROC/meminfo\"\nread -r up _ < \"$PROC/uptime\"\n"
    if lint_script("probe", clean):
        problems.append("self-check: the lint flagged a clean script: %r" % (lint_script("probe", clean),))
    for planted in ("curl http://192.0.2.1/", "echo 1 > /proc/sys/x", "cat /etc/passwd", "read -r x < /etc/hosts"):
        if not lint_script("probe", clean + planted + "\n"):
            problems.append("self-check: the recipe lint accepted a planted %r" % planted)
    # a script the lint rejects must never be handed to a shell: a stub stands in for the execution
    ran = []
    found = []
    check_recipe(found, scripts={"sample.sh": clean + "curl http://192.0.2.1/\n", "snapshot.sh": clean},
                 execute=lambda scripts, problems: ran.append(1) or [])
    if ran or not found:
        problems.append("self-check: a recipe script the lint rejected was %s" % ("executed" if ran else "not reported"))
    found, ran = [], []
    check_recipe(found, scripts={"sample.sh": clean, "snapshot.sh": clean}, execute=lambda scripts, problems: ran.append(1) or [])
    if not ran or found:
        problems.append("self-check: a clean pair of recipe scripts was not executed or was flagged: %r" % (found,))
    slow = run_recipe_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.02)
    if slow.returncode != 124 or "TIMED OUT" not in slow.stderr:
        problems.append("self-check: a recipe timeout lost its bounded failure diagnostic")
    fast = run_recipe_command([sys.executable, "-c", "print('recipe-positive')"], timeout=2)
    if fast.returncode != 0 or fast.stdout != "recipe-positive\n" or fast.stderr:
        problems.append("self-check: a bounded successful recipe was not preserved")


def check_recipe(problems, scripts=None, execute=None):
    scripts = extract_scripts() if scripts is None else scripts
    execute = execute_recipe if execute is None else execute
    if sorted(scripts) != ["sample.sh", "snapshot.sh"]:
        problems.append("the recipe in docs/contracts/e02.md must carry exactly sample.sh and snapshot.sh, found %s" % sorted(scripts))
        return []
    lint = []
    for name, text in scripts.items():
        lint += lint_script(name, text)
    problems += lint
    if lint:
        return []  # a script the lint rejects is never executed here
    return execute(scripts, problems)


def execute_recipe(scripts, problems):
    shells = [s for s in ("sh", "dash", "bash") if shutil.which(s)]
    if not shells:
        problems.append("no POSIX shell found to run the recipe scripts: the recipe is not exercised")
        return []
    with open(os.path.join(HERE, "synthetic", "recipe_series.cap"), encoding="utf-8") as fh:
        want_series = fh.read()
    with open(os.path.join(HERE, "synthetic", "recipe_memory.txt"), encoding="utf-8") as fh:
        want_memory = fh.read()
    with tempfile.TemporaryDirectory() as work:
        paths = {}
        for name, text in scripts.items():
            paths[name] = os.path.join(work, name)
            with open(paths[name], "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        for shell in shells:
            syntax = [run_recipe_command([shell, "-n", paths[n]]) for n in sorted(paths)]
            if any(s.returncode for s in syntax):
                problems.append("%s -n rejects a recipe script: %s" % (shell, " ".join(s.stderr for s in syntax)))
                continue
            for what, runner, name, want in (("sampler", run_sampler, "sample.sh", want_series), ("snapshot script", run_snapshot, "snapshot.sh", want_memory)):
                got, err = runner(shell, paths[name], work)
                found = compare_problem(shell, what, got, err, want)
                if found:
                    problems.append(found)
        shell = shells[0]
        mutants = (("sample.sh", "0000000'", "000000'", "the nanosecond padding", run_sampler, want_series),
                   ("sample.sh", "wall_ns=${w}000000000", "wall_ns=${w}0000000", "the wall padding", run_sampler, want_series),
                   ("snapshot.sh", "cat \"$PROC/$pid/statm\"", "true", "the statm section", run_snapshot, want_memory))
        for i, (name, old, new, what, runner, want) in enumerate(mutants):
            if scripts[name].count(old) != 1:
                problems.append("recipe control: %s occurs %d times in %s" % (what, scripts[name].count(old), name))
                continue
            mutant_path = os.path.join(work, "mutant%d.sh" % i)
            with open(mutant_path, "w", encoding="utf-8") as fh:
                fh.write(scripts[name].replace(old, new) + "\n")
            mwork = os.path.join(work, "m%d" % i)
            os.makedirs(mwork)
            got, err = runner(shell, mutant_path, mwork)
            found = control_problem(what, got, err, want)
            if found:
                problems.append(found)
    return shells


# ------------------------------------------------------------------------------------------------
# the summary line: derived here, independently, from this oracle's own report (for compare, from the hand-written expected report),
# from the wording in docs/contracts/e02.md ("The summary line"); the case file carries the line written by hand.

CAUSE_ORDER = ("source_outage", "network_lateness", "cpu_deadline_miss", "output_underrun", "ambiguous", "undetermined")


def summary_line(kind, r):
    if kind == "series":
        reasons = []
        for x in r["absolute"]["reasons"]:
            if x["kind"] == "coverage_below_min":
                reasons.append("coverage_below_min: have %d ppm, min %d ppm" % (x["have_ppm"], x["min_ppm"]))
            elif x["kind"] == "dropouts_exceed_max":
                reasons.append("dropouts_exceed_max: have %d, max %d" % (x["have"], x["max"]))
            else:
                reasons.append(x["kind"])
        den, drop = r["denominators"], r["dropouts"]
        if drop["known"]:
            tot = drop["totals"]
            dropouts = str(tot["intervals"]) + (", %d censored" % tot["censored_spans"] if tot["censored_spans"] > 0 else "")
            causes = ", ".join("%s %d" % (c, tot[c]) for c in CAUSE_ORDER if tot.get(c, 0) > 0) or "none"
        else:
            dropouts = causes = "unknown"
        truncated = "no" if r["truncated"] is None else "%d ns missing" % r["truncated"]["missing_ns"]
        return ("ffw-baseline series: verdict %s%s; evidence %s, %s on a device; coverage %d ppm (%d of %d intervals observed, %d censored); "
                "holes %d; truncated %s; dropouts %s; causes %s; findings %d, %d dropped" % (
                    r["absolute"]["verdict"], " (%s)" % "; ".join(reasons) if reasons else "", r["evidence"],
                    "measured" if r["measured_on_device"] else "not measured", den["coverage_ppm"], den["intervals_observed"],
                    den["intervals_total"], den["intervals_censored"], len(r["holes"]), truncated, dropouts, causes,
                    len(r["findings"]), r["findings_dropped"]))
    if kind == "memory":
        def kib(v, null_word):
            return null_word if v is None else "%d KiB" % v
        snaps, peaks, head = r["snapshots"], r["peaks"], r["headroom"]
        return ("ffw-baseline memory: snapshots %d; peak used %s; max PSS sum %s; max VmHWM %s; headroom %s (reserve %s, required %s); "
                "findings %d, %d dropped" % (
                    len(snaps), kib(peaks["max_used_kib"], "unknown"), kib(peaks["max_process_pss_sum_kib"], "unknown"),
                    kib(peaks["max_vm_hwm_kib"], "unknown"), head["verdict"], kib(head["reserve_kib"], "unknown"),
                    kib(head["required_reserve_kib"], "not declared"), sum(len(s["findings"]) for s in snaps),
                    sum(s["findings_dropped"] for s in snaps)))
    if kind == "compare":
        if r["claim"] == "made":
            c = r["comparison"]
            return ("ffw-baseline compare: claim made, %s; baseline_per_hour_milli %d, current_per_hour_milli %d, margin %d pct; "
                    "current evidence %s" % (c["verdict"], c["baseline_per_hour_milli"], c["current_per_hour_milli"], c["margin_pct"],
                                             r["current_evidence"]))
        return "ffw-baseline compare: claim refused (%s); current evidence %s" % (r["reason"], r["current_evidence"])
    raise OracleError("no summary for " + kind)


def summary_problems(cid, want, got):
    """The hand-written line must be the line the oracle derives, and a short, plain, single line."""
    problems = []
    if want != got:
        problems.append("%s: the case's hand-written summary is %r, the oracle derives %r" % (cid, want, got))
    if "\n" in want or len(want) > 400 or not want.isascii() or not want.startswith("ffw-baseline "):
        problems.append("%s: the summary is not one short plain line" % cid)
    return problems


def check_summaries(cases, problems):
    """Every case with a `summary`: hand-written line against the oracle's derivation, planted strings absent and really planted, and
    the doc's example lines are the cases' own lines. Returns the number of summaries compared."""
    compared, by_id = 0, {c["id"]: c for c in cases["cases"]}
    for c in cases["cases"]:
        if "summary" not in c:
            continue
        compared += 1
        report = oracle_report(c["args"])
        if report is None:  # compare: the hand-written expected report, never an analyzer's output
            report = load_json(c["expect"])
        got = summary_line(c["args"][0], report)
        problems += summary_problems(c["id"], c["summary"], got)
        needles = c.get("stderr_lacks", [])
        problems += plant_problems(c["id"], needles, fixture_text(c["args"]))
        problems += echo_problems(c["id"], needles, got, "summary line")
    with open(DOC, encoding="utf-8") as fh:
        doc = fh.read()
    for cid in ("E02-SUM-QUALIFIED", "E02-SUM-MEMORY"):
        if by_id[cid]["summary"] not in doc:
            problems.append("docs/contracts/e02.md does not show the %s summary line verbatim" % cid)
    return compared


def selfcheck_summary(problems):
    """Planted negatives for the summary checks: a wrong hand-written line must be reported, a right one must not."""
    right = "ffw-baseline compare: claim refused (no_baseline); current evidence synthetic"
    probe = {"claim": "refused", "reason": "no_baseline", "current_evidence": "synthetic"}
    for what, found, expect_problem in (
            ("the derived line", summary_problems("probe", right, summary_line("compare", probe)), False),
            ("a hand-written line with a wrong reason", summary_problems("probe", right.replace("no_baseline", "bad_margin"), summary_line("compare", probe)), True),
            ("a hand-written line with a wrong number", summary_problems("probe", "ffw-baseline memory: snapshots 2", "ffw-baseline memory: snapshots 3"), True),
            ("a measured series that says it was measured on a device", summary_problems("probe", 'ffw-baseline series: verdict qualified; evidence physical, measured on a device; coverage 1000000 ppm (10 of 10 intervals observed, 0 censored); holes 0; truncated no; dropouts 0; causes none; findings 0, 0 dropped', summary_line("series", json.loads('{"absolute": {"verdict": "qualified", "reasons": []}, "evidence": "physical", "measured_on_device": true, "denominators": {"coverage_ppm": 1000000, "intervals_observed": 10, "intervals_total": 10, "intervals_censored": 0}, "holes": [], "truncated": null, "dropouts": {"known": true, "totals": {"intervals": 0, "censored_spans": 0}}, "findings": [], "findings_dropped": 0}'))), False),
            ("a memory line that sums findings over every snapshot", summary_problems("probe", 'ffw-baseline memory: snapshots 2; peak used 1 KiB; max PSS sum 2 KiB; max VmHWM 3400 KiB; headroom not_assessed (reserve 17000 KiB, required 4096 KiB); findings 7, 7 dropped', summary_line("memory", json.loads('{"snapshots": [{"findings": [1, 2, 3], "findings_dropped": 2}, {"findings": [1, 2, 3, 4], "findings_dropped": 5}], "peaks": {"max_used_kib": 1, "max_process_pss_sum_kib": 2, "max_vm_hwm_kib": 3400}, "headroom": {"required_reserve_kib": 4096, "reserve_kib": 17000, "verdict": "not_assessed"}}'))), False),
            ("a two-line summary", summary_problems("probe", right + "\nextra", right + "\nextra"), True),
            ("a summary that is not concise", summary_problems("probe", "ffw-baseline " + "x" * 400, "ffw-baseline " + "x" * 400), True)):
        if bool(found) != expect_problem:
            problems.append("self-check: %s %s" % (what, "was accepted" if expect_problem else "was flagged: %r" % (found,)))
    # a summary that carried a planted site string must be reported
    if not echo_problems("probe", ["192.0.2.17"], "ffw-baseline series: profile 192.0.2.17", "summary line"):
        problems.append("self-check: a summary that repeats a planted string was accepted")


# ------------------------------------------------------------------------------------------------
# what a failure retains (acceptance, "Owned test assets": "Each failure retains replay command, versions/profile/artifact digests, expected
# versus observed oracle and first causal event. Reruns retain original failure; bounded retries do not launder flaky success."). Each problem
# line already states the case, the path and the first difference between expected and observed. `failure_block` adds the rest. Nothing in the
# E02 test assets reruns or retries anything, so a failure stays as it first happened, and every subprocess here is bounded by a timeout.

def digest_of(rel):
    try:
        with open(os.path.join(HERE, rel), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError as exc:
        return "unavailable (%s)" % type(exc).__name__


def crate_version():
    with open(os.path.join(HERE, "..", "..", "Cargo.toml"), encoding="utf-8") as fh:
        found = re.search(r"^\[workspace\.package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", fh.read(), re.M | re.S)
    return found.group(1) if found else "unknown"


def doc_invariant_problems(doc_text, cases):
    """Every invariant the contract names (not a wildcard such as INV-LOG-*) must be a row of cases.json."""
    known = {i["id"] for i in cases["invariants"]}
    names = sorted(set(re.findall(r"INV-[A-Z0-9]+(?:-[A-Z0-9]+)*(?![A-Za-z0-9*-])", doc_text)))
    return ["docs/contracts/e02.md names %s, which is not an invariant in cases.json" % n for n in names if n not in known]


def capture_kind(rel):
    """`memory` or `series`, from the capture's own header line (not its file name, which is why --print once misread recipe_memory.txt)."""
    with open(os.path.join(HERE, rel), encoding="utf-8") as fh:
        return "memory" if fh.readline().startswith("ffw.baseline.memory.v1") else "series"


def print_failures(cases, problems):
    """Every problem, then (only if there is one) the block that lets it be replayed."""
    for p in problems:
        print("FAIL:", p)
    if problems:
        print(failure_block(cases, problems))


def replay_commands(c):
    """The exact commands that reproduce a case: the analyzer's, and (for a series or memory capture) this oracle's own report."""
    cmds = [("the analyzer", "(cd tests/e02 && ffw-baseline %s)" % " ".join(shlex.quote(a) for a in c["args"]))]
    if c["args"][0] in ("series", "memory"):
        cmds.append(("this oracle's report", "python3 -B -I tests/e02/oracle.py --print %s" % shlex.quote(c["args"][1])))
    return cmds


def failure_block(cases, problems):
    """The retained context of a failing run, for the cases its problems name. Paths are relative to the repository root."""
    by_id = {c["id"]: c for c in cases["cases"]}
    named = []
    for p in problems:
        for cid, case in by_id.items():
            files = [a for a in case["args"] if a.startswith("synthetic/")]
            files += [case["expect"]] if "expect" in case else []
            if (re.search(r"(?<![A-Z0-9-])" + re.escape(cid) + r"(?![A-Z0-9-])", p)
                    or any(rel in p or os.path.basename(rel) in p for rel in files)) and cid not in named:
                named.append(cid)
    lines = ["RETAINED FOR REPLAY. First failure: %s" % problems[0], "  replay the whole local half: scripts/e2e/e02 --fixtures-only",
             "  versions: python %s; franken-baseline %s" % (platform.python_version(), crate_version())]
    for rel in ("tests/e02/cases.json", "tests/e02/oracle.py", "docs/contracts/e02.md", "tests/e02/redaction_vectors.json", "scripts/e2e/e02"):
        lines.append("  artifact %s sha256 %s" % (rel, digest_of(os.path.join("..", "..", rel))))
    if any("recipe" in p or "sampler" in p or "snapshot" in p for p in problems):
        for rel in ("synthetic/recipe_series.cap", "synthetic/recipe_memory.txt", "expected/recipe_series.json", "expected/recipe_memory.json"):
            lines.append("  recipe artifact %s sha256 %s" % (rel, digest_of(rel)))
        lines.append("  recipe context: series/memory report v1; capture v1; profile recipe-example-v1; replay scripts/e2e/e02 --fixtures-only")
    if not named:
        lines.append("  global/orphan diagnostic: no single case applies; report schema/capture/profile are not observed")
    for rel in sorted(set(re.findall(r"(?:synthetic|expected)/[A-Za-z0-9_.-]+", "\n".join(problems)))):
        lines.append("  applicable artifact %s sha256 %s" % (rel, digest_of(rel)))
    for cid in named:
        c = by_id[cid]
        lines.append("  case %s" % cid)
        for who, cmd in replay_commands(c):
            lines.append("    replay (%s): %s" % (who, cmd))
        captures = [a for a in c["args"] if a.startswith("synthetic/")]
        for a in captures:
            lines.append("    capture %s sha256 %s" % (a, digest_of(a)))
        schema = "n/a"
        if "expect" in c:
            lines.append("    expected %s sha256 %s" % (c["expect"], digest_of(c["expect"])))
            try:
                schema = load_json(c["expect"]).get("schema", "n/a")
            except (OSError, ValueError):
                schema = "unavailable"
        header = "n/a"
        if captures:
            try:
                with open(os.path.join(HERE, captures[0]), encoding="utf-8") as fh:
                    header = (fh.readline().split() or ["n/a"])[0]
            except OSError:
                header = "unavailable"
        lines.append("    report schema %s; capture format %s%s" % (schema, header, observed_profile(c)))
    return "\n".join(lines)


def observed_profile(c):
    """`; profile NAME` when the case has an observed report (a case that expects a report: the analyzer refused nothing), else nothing. A
    refusal case has no report, so a planted identifier in its capture is never copied into the block."""
    if "expect" not in c:
        return ""
    try:
        report = oracle_report(c["args"])
    except (OSError, ValueError, OracleError):
        return "; profile unavailable (report not derived)"
    if report is None or not isinstance(report.get("profile"), str):
        return ""
    return "; profile %s" % report["profile"]


def retention_problems(block, c, first):
    """What a retained block lacks: the first failure, each replay command exactly, and next to each capture and expected path the file's own
    sha256, worked out here directly with hashlib. A block that is not a failure's block is reported too."""
    problems = []
    if first not in block:
        problems.append("the first failure is not in the block")
    for who, cmd in replay_commands(c):
        if "replay (%s): %s" % (who, cmd) not in block:
            problems.append("the %s replay command is not in the block" % who)
    for rel in [a for a in c["args"] if a.startswith("synthetic/")] + ([c["expect"]] if "expect" in c else []):
        with open(os.path.join(HERE, rel), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        if "%s sha256 %s" % (rel, digest) not in block:
            problems.append("the sha256 of %s is not in the block, or is not the file's" % rel)
    if "franken-baseline %s" % crate_version() not in block:
        problems.append("the crate version is not in the block")
    if "report schema " not in block or "capture format " not in block:
        problems.append("the report schema or the capture format is not in the block")
    if "expect" in c and isinstance(load_json(c["expect"]).get("profile"), str):  # the profile, read from the hand-written expected file
        if "; profile %s" % load_json(c["expect"])["profile"] not in block:
            problems.append("the profile of the report is not in the block")
    if os.path.abspath(HERE) in block:
        problems.append("the block names an absolute path")
    return problems


def planted_failure_problems(cases, cid, plant):
    """Plant one wrong number in case `cid`'s hand-written expectation (`plant` edits a copy), run the oracle's own comparison, and check what
    the failure retains. With no failure there is nothing to retain, and that is a problem too: the check must be able to fail."""
    c = next(x for x in cases["cases"] if x["id"] == cid)
    expected = json.loads(json.dumps(load_json(c["expect"])))
    plant(expected)
    diff = subset_diff("$", expected, oracle_report(c["args"]))
    if diff is None:
        return ["%s: the expected file matched, so there is no failure to retain" % cid]
    first = "%s: %s" % (cid, diff)
    return retention_problems(failure_block(cases, [first]), c, first)


def selfcheck_failure_retention(problems):
    cases = load_json("cases.json")

    def wrong_number(report):
        report["denominators"]["coverage_ppm"] += 1  # E02-RECIPE-SERIES: 1000000 becomes 1000001

    def no_plant(report):
        pass

    for what, found, expect_problem in (
            ("a planted wrong number in an expected file", planted_failure_problems(cases, "E02-RECIPE-SERIES", wrong_number), False),
            ("the same case with the plant removed", planted_failure_problems(cases, "E02-RECIPE-SERIES", no_plant), True)):
        if bool(found) != expect_problem:
            problems.append("self-check: %s %s" % (what, "was accepted" if expect_problem else "did not retain what it must: %r" % (found,)))
    # a block with one thing missing or wrong must be reported
    c = next(x for x in cases["cases"] if x["id"] == "E02-RECIPE-SERIES")
    first = "E02-RECIPE-SERIES: $.denominators.coverage_ppm: expected 1000001, oracle has 1000000"
    block = failure_block(cases, [first])
    digest = digest_of("synthetic/recipe_series.cap")
    for what, bad in (("a block without the analyzer's replay command", block.replace("replay (the analyzer)", "replay (x)")),
                      ("a block without the oracle's replay command", block.replace("replay (this oracle's report)", "replay (x)")),
                      ("a block with a wrong capture digest", block.replace(digest, "0" * 64)),
                      ("a block with a wrong expected digest", block.replace(digest_of("expected/recipe_series.json"), "0" * 64)),
                      ("a block without the crate version", block.replace("franken-baseline %s" % crate_version(), "franken-baseline ?")),
                      ("a block without the first failure", block.replace(first, "")),
                      ("a block without the report schema", block.replace("report schema ", "schema ")),
                      ("a block without the profile", block.replace("; profile recipe-example-v1", "")),
                      ("a block with another profile", block.replace("; profile recipe-example-v1", "; profile other-v1")),
                      ("a block that names an absolute path", block.replace("artifact tests/e02/cases.json", "artifact " + os.path.join(os.path.abspath(HERE), "cases.json")))):
        if not retention_problems(bad, c, first):
            problems.append("self-check: %s was accepted" % what)
    if retention_problems(block, c, first):
        problems.append("self-check: a complete block was flagged: %r" % (retention_problems(block, c, first),))
    # the profile, written out by hand; and a refusal case has no observed report, so its planted profile (an address) is never in the block
    if "report schema ffw.baseline.series-report.v1; capture format ffw.baseline.capture.v1; profile recipe-example-v1" not in block:
        problems.append("self-check: the block for E02-RECIPE-SERIES lacks its schema, capture format and profile line: %r" % (block,))
    refusal = failure_block(cases, ["E02-R-PROFILE-IP: first failure"])
    if "192.0.2.17" in refusal or "profile" in refusal.split("capture format")[-1] or "case E02-R-PROFILE-IP" not in refusal:
        problems.append("self-check: the block for a refusal case echoes a planted profile or does not name the case: %r" % (refusal,))
    # the replay commands, written out by hand: the check must not move with the function that builds them
    if replay_commands(c) != [("the analyzer", "(cd tests/e02 && ffw-baseline series synthetic/recipe_series.cap)"),
                              ("this oracle's report", "python3 -B -I tests/e02/oracle.py --print synthetic/recipe_series.cap")]:
        problems.append("self-check: the replay commands for E02-RECIPE-SERIES are not the exact commands: %r" % (replay_commands(c),))
    nob = next(x for x in cases["cases"] if x["id"] == "E02-C-NOBASELINE")
    if replay_commands(nob) != [("the analyzer", "(cd tests/e02 && ffw-baseline compare synthetic/clean.cap)")]:
        problems.append("self-check: the replay command for E02-C-NOBASELINE is not the exact command: %r" % (replay_commands(nob),))
    # the doc may name only invariants that exist
    if doc_invariant_problems("see INV-LOG-STRUCTURED and INV-LOG-* and INV-NO-SUCH-THING.", cases) != [
            "docs/contracts/e02.md names INV-NO-SUCH-THING, which is not an invariant in cases.json"]:
        problems.append("self-check: the doc's invariant references are not checked")
    # printing: a failure prints its FAIL line and then the block; a run with no failure prints neither
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_failures(cases, [first])
    printed = buf.getvalue()
    if not printed.startswith("FAIL: " + first + "\n") or retention_problems(printed, c, first):
        problems.append("self-check: a failure did not print its FAIL line and the retained block: %r" % (printed[:120],))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_failures(cases, [])
    if buf.getvalue():
        problems.append("self-check: a run with no failure printed a retained block")
    # the replay command reads a capture's kind from its header, and the crate version is checked against a second reading
    if (capture_kind("synthetic/recipe_memory.txt"), capture_kind("synthetic/clean.cap")) != ("memory", "series"):
        problems.append("self-check: a capture's kind is not read from its header")
    with open(os.path.join(HERE, "..", "..", "Cargo.toml"), encoding="utf-8") as fh:
        second = re.search(r'^version = "([^"]+)"', fh.read(), re.M)
    if not second or crate_version() != second.group(1):
        problems.append("self-check: the crate version is not the workspace version")
    unknown_test = json.loads(json.dumps(cases))
    row = next(i for i in unknown_test["invariants"] if i["id"] == "INV-LOG-FAILURE-RETENTION")
    row["test_functions"].append("rust:missing_retention_test")
    if not any("names unknown test function rust:missing_retention_test" in p for p in check_inventory(unknown_test)):
        problems.append("self-check: a nonexistent retention test was accepted by the invariant map")
    # File-associated and unanchored failures must retain their actual case, not just global metadata.
    for first in ("synthetic/recipe_series.cap is referenced but missing", "self-check: E02-RECIPE-SERIES first failure"):
        found = retention_problems(failure_block(cases, [first]), c, first)
        if found:
            problems.append("self-check: identifiable failure lost case context: %r" % found)
    missing = json.loads(json.dumps(cases))
    missing["cases"][0]["args"] = ["series", "synthetic/not-present.cap"]
    block = failure_block(missing, ["synthetic/not-present.cap is referenced but missing"])
    if "unavailable (FileNotFoundError)" not in block or "case " + missing["cases"][0]["id"] not in block:
        problems.append("self-check: missing capture did not retain unavailable evidence and its case")
    for first, artifact in (("redaction vector disagreement", "tests/e02/redaction_vectors.json"),
                            ("sh sampler: TIMED OUT", "synthetic/recipe_series.cap"),
                            ("synthetic/orphan.cap is not used by any case", "synthetic/orphan.cap")):
        block = failure_block(cases, [first])
        if artifact not in block or "global/orphan diagnostic" not in block:
            problems.append("self-check: global/orphan failure lost applicable artifact context")


# ------------------------------------------------------------------------------------------------
# the end-to-end script: scripts/e2e/e02 is run, copied into a throwaway tree whose oracle and `rch` are stubs, so that its tiers, its exit
# codes and its caps are checked on the real script text without running anything real and without recursion. A hung stand-in oracle proves
# the local cap: the script must return a failure that says TIMED OUT, and the hung child must be gone. For the Rust half the cap is RCH's own
# deadline: the stand-in rch shows that the script sets it (RCH_TEST_TIMEOUT_SEC) and never signals `rch exec`. Nothing here proves that rch's
# deadline fires or that a remote job shuts down: the stand-in is only what this check can see of rch, and only a central run exercises the real one.

SCRIPT = os.path.join(HERE, "..", "..", "scripts", "e2e", "e02")
STUB_ORACLE = chr(10).join([
    "import os, sys, time, subprocess",
    "with open(os.environ['E02_STUB_LOG'], 'a') as fh:",
    "    print('oracle', *sys.argv[1:], file=fh)",
    "mode = os.environ.get('E02_STUB_ORACLE', 'ok')",
    "if mode == 'hang-grandchild':",
    "    child = subprocess.Popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(20)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
    "    with open(os.environ['E02_STUB_CHILD'], 'w') as fh: fh.write(str(child.pid))",
    "    mode = 'hang'",
    "if mode == 'hang':",
    "    with open(os.environ['E02_STUB_PID'], 'w') as fh:",
    "        fh.write(str(os.getpid()))",
    "    time.sleep(20)",
    "print('oracle: stub', mode)",
    "sys.exit(1 if mode == 'fail' else 0)",
]) + chr(10)
STUB_RCH = chr(10).join([
    "#!/bin/sh",
    'echo rch "$RCH_REQUIRE_REMOTE" "$RCH_TEST_TIMEOUT_SEC" "$@" >> "$E02_STUB_LOG"',
    'trap \'echo signalled >> "$E02_STUB_SIGNALS"; exit 143\' TERM INT HUP',
    'case "${E02_STUB_RCH:-ok}" in',
    '  deadline) echo "RCH-E303: the test deadline passed (stand-in)" >&2; exit 1 ;;',
    "  fail) exit 1 ;;",
    "  slow) sleep 3 & wait $! ;;",
    "esac",
    "exit 0",
]) + chr(10)

WATCHDOG_CAP = str(86400 + os.getpid())  # a cap no other process uses (a day and this check's pid): the scenario below looks for a sleep of exactly this length left behind by the script's own watchdog


def call_line(name, extra):
    """The exact command each half must run, as its stand-in logs it: the oracle in --check mode, and rch with RCH_REQUIRE_REMOTE=1 and the cap as
    RCH_TEST_TIMEOUT_SEC (1800 unless the scenario sets E02_RUST_TIMEOUT) running the cargo test line the contract names."""
    if name == "oracle":
        return "oracle --check"
    return "rch 1 %s exec -- cargo test -p franken-baseline" % extra.get("E02_RUST_TIMEOUT", "1800")


# (name, arguments, extra environment, wanted exit, wanted stub calls, text the output must contain, text it must not contain)
SCRIPT_SCENARIOS = (
    ("soak", ["--tier", "soak"], {}, 3, [], ("NOT RUN", "This is not a pass"), ("PASS",)),
    ("smoke", ["--tier", "smoke"], {}, 0, ["oracle"], ("smoke: PASS", "Rust analyzer was NOT run", "not a qualification"), ("both halves",)),
    ("smoke-oracle-fails", ["--tier", "smoke"], {"E02_STUB_ORACLE": "fail"}, 1, ["oracle"], ("E02: FAIL",), ("PASS",)),
    ("full", ["--tier", "full"], {}, 0, ["oracle", "rch"], ("E02 full: PASS (both halves",), ()),
    ("full-no-rch", ["--tier", "full"], {"E02_TEST_NO_RCH": "1"}, 3, ["oracle"], ("BLOCKED",), ("PASS",)),
    ("caller-cannot-replace-rch-with-true", ["--rust-only"], {"E02_RCH": "true", "E02_STUB_RCH": "fail"}, 1, ["rch"], ("E02: FAIL",), ("PASS",)),
    ("full-oracle-fails", ["--tier", "full"], {"E02_STUB_ORACLE": "fail"}, 1, ["oracle", "rch"], ("E02: FAIL",), ("PASS",)),
    ("full-rch-fails", ["--tier", "full"], {"E02_STUB_RCH": "fail"}, 1, ["oracle", "rch"], ("E02: FAIL", "never signals rch exec"), ("PASS",)),
    ("no-tier", [], {}, 0, ["oracle", "rch"], ("E02: PASS (both halves",), ("full:",)),
    ("fixtures-only", ["--fixtures-only"], {}, 0, ["oracle"], ("E02 local half: PASS",), ()),
    ("rust-only", ["--rust-only"], {}, 0, ["rch"], ("E02 Rust half: PASS",), ()),
    ("usage-bad-tier", ["--tier", "bogus"], {}, 2, [], ("usage:",), ()),
    ("usage-no-tier", ["--tier"], {}, 2, [], ("usage:",), ()),
    ("usage-tier-and-half", ["--tier", "smoke", "--rust-only"], {}, 2, [], ("usage:",), ()),
    ("usage-unknown", ["--bogus"], {}, 2, [], ("usage:",), ()),
    ("usage-extra-argument", ["--fixtures-only", "x"], {}, 2, [], ("usage:",), ()),
    ("a-cap-that-is-not-seconds-is-refused", ["--tier", "smoke"], {"E02_FIXTURES_TIMEOUT": "abc"}, 2, [], ("E02_FIXTURES_TIMEOUT must be a whole number",), ("PASS",)),
    ("a-zero-cap-is-refused", ["--rust-only"], {"E02_RUST_TIMEOUT": "0"}, 2, [], ("E02_RUST_TIMEOUT must be a whole number",), ("PASS",)),
    ("hung-oracle-times-out", ["--tier", "smoke"], {"E02_STUB_ORACLE": "hang", "E02_FIXTURES_TIMEOUT": "1"}, 1, ["oracle"],
     ("TIMED OUT", "never a skip"), ("PASS",)),
    ("hung-descendant-times-out", ["--tier", "smoke"], {"E02_STUB_ORACLE": "hang-grandchild", "E02_FIXTURES_TIMEOUT": "1"}, 1, ["oracle"],
     ("TIMED OUT", "never a skip"), ("PASS",)),
    ("interrupt-oracle", ["--tier", "full"], {"E02_STUB_ORACLE": "hang"}, 130, ["oracle"], ("interrupted",), ("PASS",)),
    ("a-cap-does-not-hurt-a-fast-oracle", ["--tier", "smoke"], {"E02_FIXTURES_TIMEOUT": "1"}, 0, ["oracle"], ("smoke: PASS",), ("TIMED OUT",)),
    ("the-rust-cap-is-rchs-own-deadline", ["--rust-only"], {"E02_RUST_TIMEOUT": "77"}, 0, ["rch"], ("Rust half: PASS",), ("TIMED OUT",)),
    ("the-script-never-signals-rch", ["--rust-only"], {"E02_STUB_RCH": "slow", "E02_RUST_TIMEOUT": "1"}, 0, ["rch"], ("Rust half: PASS",), ("TIMED OUT",)),
    ("a-deadline-rch-reports-is-a-failure", ["--rust-only"], {"E02_STUB_RCH": "deadline"}, 1, ["rch"],
     ("RCH-E303", "never a skip", "rch jobs recover"), ("PASS",)),
    ("no-watchdog-is-left-after-a-fast-oracle", ["--tier", "smoke"], {"E02_FIXTURES_TIMEOUT": WATCHDOG_CAP}, 0, ["oracle"], ("smoke: PASS",), ("TIMED OUT",)),
)


def script_problems(script_text, names=None):
    """Run the scenarios (all, or those in `names`) against `script_text` and report every way the script differs from what they expect."""
    problems = []
    with tempfile.TemporaryDirectory() as root:
        for sub in (("scripts", "e2e"), ("tests", "e02"), ("stub",), ("no-rch",)):
            os.makedirs(os.path.join(root, *sub))
        script = os.path.join(root, "scripts", "e2e", "e02")
        rch = os.path.join(root, "stub", "rch")
        for path, text in ((script, script_text), (os.path.join(root, "tests", "e02", "oracle.py"), STUB_ORACLE), (rch, STUB_RCH)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        os.chmod(script, 0o755)
        os.chmod(rch, 0o755)
        for name, executable in (("python3", sys.executable), ("dirname", shutil.which("dirname"))):
            os.symlink(executable, os.path.join(root, "no-rch", name))
        log = os.path.join(root, "calls.log")
        for n, (name, args, extra, want_rc, want_calls, contains, absent) in enumerate(SCRIPT_SCENARIOS):
            if names is not None and name not in names:
                continue
            pidfile = os.path.join(root, "pid-%d" % n)
            childfile = os.path.join(root, "child-%d" % n)
            with open(log, "w", encoding="utf-8"):
                pass
            signals = os.path.join(root, "signals-%d" % n)
            # the caller's own RCH_* and E02_* settings must not reach the script: it has to set what it needs itself
            env = {k: v for k, v in os.environ.items() if not k.startswith(("RCH_", "E02_"))}
            env.update(E02_STUB_LOG=log, E02_STUB_PID=pidfile, E02_STUB_CHILD=childfile, E02_STUB_SIGNALS=signals,
                       PATH=os.path.join(root, "stub") + os.pathsep + env.get("PATH", ""))
            env.update(extra)
            if extra.get("E02_TEST_NO_RCH"):
                env["PATH"] = os.path.join(root, "no-rch")
            started = time.monotonic()
            rc, out = None, ""
            try:
                if name == "interrupt-oracle":
                    child = subprocess.Popen([shutil.which("bash"), script] + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                    deadline = time.monotonic() + 3
                    while not os.path.exists(pidfile) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    os.killpg(child.pid, signal.SIGINT)
                    stdout, stderr = child.communicate(timeout=6)
                    done = subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)
                else:
                    done = subprocess.run([shutil.which("bash"), script] + args, env=env, capture_output=True, text=True, timeout=12)
                rc, out = done.returncode, done.stdout + done.stderr
            except subprocess.TimeoutExpired:
                problems.append("%s: the script did not return within 12 s" % name)
            elapsed = time.monotonic() - started
            with open(log, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            calls = [line.split()[0] for line in lines]
            if rc is not None and (rc != want_rc or calls != want_calls):
                problems.append("%s: exit %r with stub calls %r, wanted %r with %r" % (name, rc, calls, want_rc, want_calls))
            elif rc is not None and lines != [call_line(w, extra) for w in want_calls]:
                problems.append("%s: the stand-ins were run as %r, wanted %r" % (name, lines, [call_line(w, extra) for w in want_calls]))
            if os.path.exists(signals):
                problems.append("%s: the script signalled rch exec" % name)
            for text in contains:
                if rc is not None and text not in out:
                    problems.append("%s: the output lacks %r" % (name, text))
            for text in absent:
                if text in out:
                    problems.append("%s: the output has %r" % (name, text))
            if name.startswith("no-watchdog"):
                scan = run_recipe_command(["ps", "-axo", "command"], timeout=30)
                if scan.returncode:
                    problems.append("%s: process scan failed: %s" % (name, scan.stderr[:200]))
                listing = scan.stdout
                if any(row.strip() in ("sleep " + WATCHDOG_CAP, "/bin/sleep " + WATCHDOG_CAP) for row in listing.splitlines()):
                    problems.append("%s: the script left its watchdog (sleep %s) running" % (name, WATCHDOG_CAP))
                    run_recipe_command(["pkill", "-f", "^(/bin/)?sleep " + WATCHDOG_CAP + "$"], timeout=30)  # the stray sleep is this check's own
            if name == "hung-descendant-times-out":
                if not os.path.exists(childfile):
                    problems.append("%s: descendant did not record its pid" % name)
                else:
                    with open(childfile, encoding="utf-8") as fh:
                        descendant = int(fh.read())
                    state = run_recipe_command(["ps", "-p", str(descendant), "-o", "stat="], timeout=2).stdout.strip()
                    if state and not state.startswith("Z"):
                        problems.append("%s: owned descendant was left running" % name)
                        os.kill(descendant, signal.SIGKILL)  # only this scenario's recorded owned child
            if name.startswith(("hung", "interrupt")):
                if elapsed > 6:  # a one-second cap, then TERM: well under the 12 s limit above, which only catches a script that never returns
                    problems.append("%s: the cap did not fire promptly (%.1f s)" % (name, elapsed))
                try:
                    with open(pidfile, encoding="utf-8") as fh:
                        pid = int(fh.read())
                except (OSError, ValueError):
                    problems.append("%s: the stub never recorded its pid" % name)
                    continue
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                problems.append("%s: the hung child %d was left running" % (name, pid))
                os.kill(pid, 9)  # it is this check's own stub
    return problems


def selfcheck_script():
    """The real script passes every scenario; a liveness probe that sees live and gone processes; and planted faults in the script, each
    reported by the scenario made for it (the unmutated script is their control)."""
    problems = []
    with open(SCRIPT, encoding="utf-8") as fh:
        real = fh.read()
    problems.extend("scripts/e2e/e02: " + p for p in script_problems(real))
    probe = subprocess.Popen(["sleep", "20"])
    try:
        os.kill(probe.pid, 0)
    except ProcessLookupError:
        problems.append("self-check: the liveness probe cannot see a live process")
    probe.terminate()
    probe.wait()
    try:
        os.kill(probe.pid, 0)
        problems.append("self-check: the liveness probe still sees a process that is gone")
    except ProcessLookupError:
        pass
    nl = chr(10)
    for what, old, new, names in (
            ("a soak tier that exits as a pass", 'This is not a pass." >&2' + nl + "  exit 3", 'This is not a pass." >&2' + nl + "  exit 0", ("soak",)),
            ("a timeout counted as a skip", 'A timeout is a failure, never a skip." >&2' + nl + "    return 1",
             'A timeout is a failure, never a skip." >&2' + nl + "    return 0", ("hung-oracle-times-out",)),
            ("a smoke tier that also runs the Rust half", "smoke) mode=fixtures ;;", "smoke) mode=all ;;", ("smoke",)),
            ("a local deadline that fires late", '    code = proc.wait(timeout=int(sys.argv[1]))',
             '    code = proc.wait(timeout=int(sys.argv[1]) + 8)', ("hung-oracle-times-out",)),
            ("cleanup that kills only the parent PID", '    try: os.killpg(proc.pid, signal.SIGKILL)',
             '    try: os.kill(proc.pid, signal.SIGKILL)', ("hung-descendant-times-out",)),
            ("a Rust half capped by killing the rch wrapper", 'if ! (cd "$ROOT" && env RCH_REQUIRE_REMOTE=1',
             'if ! (cd "$ROOT" && run_half Rust "$RUST_TIMEOUT" env RCH_REQUIRE_REMOTE=1', ("the-script-never-signals-rch",))):
        if real.count(old) != 1:
            problems.append("self-check: %s: its anchor occurs %d times in the script" % (what, real.count(old)))
        elif not script_problems(real.replace(old, new), names=names):
            problems.append("self-check: %s was accepted" % what)
    return problems


# ------------------------------------------------------------------------------------------------
# the oracle's own FAIL print loop in check(): `--check` is run on a throwaway copy of this tree, once with one hand-written number planted wrong and
# once as it is. The inner run skips the checks that would run it again (E02_ORACLE_INNER).

def copy_tree(root):
    for rel in (os.path.join("tests", "e02"), os.path.join("docs", "contracts", "e02.md"), "Cargo.toml", os.path.join("scripts", "e2e", "e02"),
                os.path.join("crates", "franken-baseline", "tests", "e02_cases.rs")):
        src, dst = os.path.join(HERE, "..", "..", rel), os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, dst)


def inner_check(root):
    env = dict(os.environ, E02_ORACLE_INNER="1")
    done = run_recipe_command([sys.executable, "-B", "-I", os.path.join(root, "tests", "e02", "oracle.py"), "--check"], env=env, timeout=120)
    return done.returncode, done.stdout + done.stderr


def selfcheck_check_output():
    problems = []
    first = "E02-RECIPE-SERIES: $.denominators.coverage_ppm: expected 1000001, oracle has 1000000"
    with tempfile.TemporaryDirectory() as planted, tempfile.TemporaryDirectory() as clean:
        for root in (planted, clean):
            copy_tree(root)
        expected = os.path.join(planted, "tests", "e02", "expected", "recipe_series.json")
        with open(expected, encoding="utf-8") as fh:
            text = fh.read()
        if text.count('"coverage_ppm": 1000000') != 1:
            return ["self-check: the planted number is not in expected/recipe_series.json exactly once"]
        with open(expected, "w", encoding="utf-8") as fh:
            fh.write(text.replace('"coverage_ppm": 1000000', '"coverage_ppm": 1000001'))
        rc, out = inner_check(planted)
        digests = {}
        for rel, base in (("synthetic/recipe_series.cap", planted), ("expected/recipe_series.json", planted)):
            with open(os.path.join(base, "tests", "e02", rel), "rb") as fh:
                digests[rel] = hashlib.sha256(fh.read()).hexdigest()
        wants = ["FAIL: " + first, "RETAINED FOR REPLAY. First failure: " + first,
                 "replay (the analyzer): (cd tests/e02 && ffw-baseline series synthetic/recipe_series.cap)",
                 "replay (this oracle's report): python3 -B -I tests/e02/oracle.py --print synthetic/recipe_series.cap",
                 "synthetic/recipe_series.cap sha256 " + digests["synthetic/recipe_series.cap"],
                 "expected/recipe_series.json sha256 " + digests["expected/recipe_series.json"],
                 "report schema ffw.baseline.series-report.v1; capture format ffw.baseline.capture.v1; profile recipe-example-v1",
                 "franken-baseline " + crate_version()]
        if rc != 1:
            problems.append("self-check: --check on a tree with a planted wrong number exited %d, not 1" % rc)
        problems.extend("self-check: the failing --check output lacks %r" % w for w in wants if w not in out)
        if "FAIL: " + first in out and "RETAINED FOR REPLAY" in out and out.index("RETAINED FOR REPLAY") < out.index("FAIL: " + first):
            problems.append("self-check: the retained block is printed before the FAIL line")
        if planted in out or clean in out:
            problems.append("self-check: the failing --check output names a temporary path")
        rc, out = inner_check(clean)
        if rc != 0 or "FAIL" in out or "RETAINED" in out:
            problems.append("self-check: --check on an unplanted copy exited %d or printed a failure: %r" % (rc, out[-300:]))
    return problems


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


def oracle_report(args):  # the series and memory reports only; first_error models the diagnostics
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
            if a.startswith("synthetic/"):
                referenced.add(a)
        if "expect" in c:
            referenced.add(c["expect"])
    for rel in sorted(referenced):
        if not os.path.isfile(os.path.join(HERE, rel)):
            problems.append("%s is referenced but missing" % rel)
    for sub in ("synthetic", "expected"):
        for name in sorted(os.listdir(os.path.join(HERE, sub))):
            if "%s/%s" % (sub, name) not in referenced:
                problems.append("%s/%s is not used by any case" % (sub, name))
    covered = set()
    for inv in cases["invariants"]:
        has_cases, has_why, has_tests = "cases" in inv, "inapplicable" in inv, "test_functions" in inv
        if sum((has_cases, has_why, has_tests)) != 1:
            problems.append("%s needs exactly one of cases/test_functions/inapplicable" % inv["id"])
        elif has_cases:
            for cid in inv["cases"]:
                if cid not in ids:
                    problems.append("%s names unknown case %s" % (inv["id"], cid))
                covered.add(cid)
        elif has_tests:
            if not inv["test_functions"]:
                problems.append("%s has no test functions" % inv["id"])
            with open(os.path.join(HERE, "..", "..", "crates", "franken-baseline", "tests", "e02_cases.rs"), encoding="utf-8") as fh:
                rust = fh.read()
            for ref in inv["test_functions"]:
                kind, _, name = ref.partition(":")
                found = (kind == "python" and callable(globals().get(name))) or (kind == "rust" and re.search(r"^fn " + re.escape(name) + r"\(", rust, re.M))
                if not found:
                    problems.append("%s names unknown test function %s" % (inv["id"], ref))
        elif len(inv["inapplicable"]) <= 20:
            problems.append("%s: explain the inapplicability" % inv["id"])
    for cid in ids:
        if cid not in covered:
            problems.append("case %s covers no invariant" % cid)
    return problems


def check():
    cases = load_json("cases.json")
    problems = check_inventory(cases)
    if any("referenced but missing" in p for p in problems):
        print_failures(cases, problems)
        print("oracle: INCOMPLETE; required fixture unavailable; analyzer comparisons NOT RUN")
        return 1
    checked = 0
    for c in cases["cases"]:
        if "expect" not in c:
            continue  # malformed-input cases: the Rust parser's error text is what they pin
        try:
            report = oracle_report(c["args"])
            expected = load_json(c["expect"])
        except (OSError, ValueError, OracleError) as exc:
            problems.append("%s: cannot derive or read fixture (%s)" % (c["id"], type(exc).__name__))
            continue
        if report is None:
            continue  # compare cases: the Rust CLI's own refusal logic
        checked += 1
        diff = subset_diff("$", expected, report)
        if diff:
            problems.append("%s: %s" % (c["id"], diff))
    compared_redaction = check_redaction(cases, problems)
    compared_summaries = check_summaries(cases, problems)
    shells = check_recipe(problems)
    selfcheck_redaction(problems)
    selfcheck_recipe(problems)
    selfcheck_summary(problems)
    selfcheck_failure_retention(problems)
    if not os.environ.get("E02_ORACLE_INNER"):
        problems.extend(selfcheck_script())
        problems.extend(selfcheck_check_output())
    with open(DOC, encoding="utf-8") as fh:
        problems.extend(doc_invariant_problems(fh.read(), cases))
    # Planted negatives for this checker: a mutated expectation must be rejected.
    probe = {"a": {"b": 1}, "c": [1, {"d": "x"}], "e": None}
    for bad in ({"a": {"b": 2}}, {"a": {"z": 1}}, {"c": [1]}, {"c": [1, {"d": "y"}]}, {"e": 0}):
        if subset_diff("$", bad, probe) is None:
            problems.append("subset matcher accepted a planted difference: %r" % (bad,))
    if checked == 0:
        problems.append("no series/memory case was checked: a vacuous pass")
    print_failures(cases, problems)
    print("oracle: %d series/memory cases compared with their expected files; %d redaction/diagnostic checks; "
          "%d summary lines; recipe scripts run under %s; %d problem(s)" % (checked, compared_redaction, compared_summaries, ", ".join(shells) or "no shell", len(problems)))
    return 0 if not problems else 1


def main(argv):
    if argv[:1] == ["--check"]:
        return check()
    if len(argv) == 2 and argv[0] == "--print":
        kind = capture_kind(argv[1])
        print(json.dumps(oracle_report([kind, argv[1]]), indent=1, sort_keys=False))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
