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
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

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
    done = subprocess.run([shell, script_path], env=env, capture_output=True, text=True, timeout=60)
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
    done = subprocess.run([shell, script_path, "recipe-example", "100", "200"], env=env, capture_output=True, text=True, timeout=60)
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
            syntax = [subprocess.run([shell, "-n", paths[n]], capture_output=True, text=True) for n in sorted(paths)]
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
    compared_redaction = check_redaction(cases, problems)
    compared_summaries = check_summaries(cases, problems)
    shells = check_recipe(problems)
    selfcheck_redaction(problems)
    selfcheck_recipe(problems)
    selfcheck_summary(problems)
    # Planted negatives for this checker: a mutated expectation must be rejected.
    probe = {"a": {"b": 1}, "c": [1, {"d": "x"}], "e": None}
    for bad in ({"a": {"b": 2}}, {"a": {"z": 1}}, {"c": [1]}, {"c": [1, {"d": "y"}]}, {"e": 0}):
        if subset_diff("$", bad, probe) is None:
            problems.append("subset matcher accepted a planted difference: %r" % (bad,))
    if checked == 0:
        problems.append("no series/memory case was checked: a vacuous pass")
    for p in problems:
        print("FAIL:", p)
    print("oracle: %d series/memory cases compared with their expected files; %d redaction/diagnostic checks; "
          "%d summary lines; recipe scripts run under %s; %d problem(s)" % (checked, compared_redaction, compared_summaries, ", ".join(shells) or "no shell", len(problems)))
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
