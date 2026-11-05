"""Independent model of the D04 diagnostics log (ffw-5h5): the events the render loop reports -> `ffw.log.v1` lines.

Written from docs/contracts/d04.md ("Diagnostics"), not from the Rust. The Rust (crates/franken-speaker/src/render_log.rs)
and this file must both reproduce tests/d04/log_golden.json, whose expected lines were typed by hand. Nothing here runs
the render loop, builds anything or touches a device. Evidence: model, host simulation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "ffw.log.v1"
MAX_ID_CHARS = 64
MAX_MESSAGE_CHARS = 160
FIELD_ORDER = ("schema_version", "timestamp_mono_ns", "run_id", "case_id", "correlation_id", "member_id", "group_id",
               "source_epoch", "state_revision", "event_kind", "message", "queue_depth", "latency_us", "fault", "cause")

ROOT_CAUSE = {
    "session_faulted": "hal_session_fault",
    "device_lost": "device_gone",
    "drain_timed_out": "flush_not_acknowledged",
    "watchdog_tripped": "consecutive_cpu_misses",
    "protection_fault": "protection_dsp_inactive",
    "render_internal": "resampler_refused_block",
}


def safe_id(raw: str) -> str:
    """Letters, digits and . _ : - only, 1..64 characters, and not a bare dotted quad."""
    ok = 0 < len(raw) <= MAX_ID_CHARS and re.fullmatch(r"[A-Za-z0-9._:\-]+", raw) is not None
    parts = raw.split(".")
    quad = len(parts) == 4 and all(p.isdigit() and p.isascii() for p in parts)
    return raw if ok and not quad else "invalid_id"


def admit_label(faults: Dict[str, bool]) -> Optional[str]:
    names = [f"admit_{k}" for k in ("start", "cancel", "drain", "reconnect") if faults.get(k)]
    return "+".join(names) if names else None


def is_critical(kind: Dict[str, Any]) -> bool:
    return kind["kind"] == "fault" or (kind["kind"] == "state" and kind["to"] == "faulted")


DEFECTS = ("revision_frozen", "latency_not_scaled", "epoch_ignored", "schedule_dropped", "critical_not_priority")


class Log:
    """`defect` names one deliberately wrong rule, used only to prove the golden notices it."""

    def __init__(self, identity: Dict[str, Any], defect: Optional[str] = None):
        self.defect = defect
        self.run_id = safe_id(identity["run_id"])
        self.case_id = safe_id(identity["case_id"])
        self.member_id = safe_id(identity.get("member_id", "none"))
        self.group_id = safe_id(identity.get("group_id", "none"))
        self.tick_us = identity.get("tick_us", 0)
        self.capacity = max(1, identity["capacity"])
        self.admit: Optional[str] = None
        self.revision = 0
        self.upstream_lost_critical = 0
        self.queue: List[tuple] = []  # (critical, line)
        self.emitted = self.dropped = self.evicted = self.lost = 0

    def set_admit_faults(self, faults: Dict[str, bool]) -> None:
        self.admit = None if self.defect == "schedule_dropped" else admit_label(faults)

    def _enqueue(self, tick: int, correlation: str, d: Dict[str, Any]) -> None:
        tick_ns = max(1, self.tick_us * 1000)
        values = {
            "schema_version": SCHEMA_VERSION, "timestamp_mono_ns": tick * tick_ns, "run_id": self.run_id,
            "case_id": self.case_id, "correlation_id": correlation, "member_id": self.member_id,
            "group_id": self.group_id, "source_epoch": d["epoch"], "state_revision": self.revision,
            "event_kind": d["kind"], "message": d["message"][:MAX_MESSAGE_CHARS], "queue_depth": d["depth"],
            "latency_us": d["latency_us"],
        }
        if d.get("fault") is not None:
            values["fault"] = d["fault"]
        if d.get("cause") is not None:
            values["cause"] = d["cause"]
        line = json.dumps({k: values[k] for k in FIELD_ORDER if k in values}, separators=(",", ":"))
        self.emitted += 1
        if len(self.queue) < self.capacity:
            self.queue.append((d["critical"], line))
        elif not d["critical"] or self.defect == "critical_not_priority":
            self.dropped += 1
        else:
            for i, (crit, _) in enumerate(self.queue):
                if not crit:
                    del self.queue[i]
                    self.queue.append((True, line))
                    self.evicted += 1
                    break
            else:
                self.lost += 1

    def event(self, event: Dict[str, Any], counters: Dict[str, int], in_flight: int) -> None:
        self.upstream_lost_critical = max(self.upstream_lost_critical, counters.get("events_lost_critical", 0))
        tick, kind = event["tick"], event["kind"]
        correlation = f"tick-{tick}"
        d: Dict[str, Any] = {"kind": "d04_state", "message": "", "epoch": counters.get("epoch_resets", 0),
                             "depth": in_flight, "latency_us": 0, "fault": self.admit, "cause": None,
                             "critical": is_critical(kind)}
        which = kind["kind"]
        if self.defect == "epoch_ignored":
            d["epoch"] = 0
        if which == "state":
            if self.defect != "revision_frozen":
                self.revision += 1
            d["message"] = f"state {kind['from']} to {kind['to']}"
        elif which == "block":
            index, outcome = kind["index"], kind["outcome"]
            correlation = f"block-{index}"
            d["kind"] = "d04_block"
            o = outcome["outcome"]
            late_ticks = 0
            if o == "on_time":
                d["message"] = f"block {index} on_time"
            elif o == "starved":
                d["message"] = f"block {index} starved {outcome['cause']} silence_frames={outcome['silence_frames']}"
                d["cause"] = outcome["cause"]
            elif o == "cpu_miss":
                late_ticks = outcome["late_by"]
                d["message"] = f"block {index} cpu_miss late_by_ticks={late_ticks}"
                d["cause"] = "cpu_miss"
            elif o == "capacity_rejected":
                d["message"] = f"block {index} capacity_rejected logical"
                d["cause"] = "capacity_rejected"
            elif o == "short_write":
                d["message"] = f"block {index} short_write discarded_frames={outcome['discarded_frames']}"
                d["cause"] = "short_write"
            else:
                raise ValueError(o)
            d["latency_us"] = late_ticks if self.defect == "latency_not_scaled" else late_ticks * self.tick_us
        elif which == "driver_underrun":
            d["kind"] = "d04_driver_underrun"
            d["message"] = f"driver_underruns={counters.get('driver_underruns', 0)} explained={counters.get('underruns_explained', 0)}"
            d["cause"] = "driver"
        elif which == "control_rejected":
            d["kind"] = "d04_control_rejected"
            d["message"] = "control queue full"
            d["cause"] = "queue_full"
        elif which == "fault":
            d["kind"] = "d04_fault"
            d["message"] = f"fault {kind['reason']}"
            d["fault"] = kind["reason"]
            d["cause"] = ROOT_CAUSE[kind["reason"]]
        else:
            raise ValueError(which)
        self._enqueue(tick, correlation, d)

    def summary(self, tick: int, counters: Dict[str, int], in_flight: int) -> None:
        self.upstream_lost_critical = max(self.upstream_lost_critical, counters.get("events_lost_critical", 0))
        c = lambda name: counters.get(name, 0)  # noqa: E731
        message = (f"n={c('blocks_started')} ok={c('blocks_on_time')} ing={c('ingress_loss_blocks')} "
                   f"dec={c('decode_delay_blocks')} cpu={c('cpu_miss_blocks')} cap={c('capacity_rejected_blocks')} "
                   f"sw={c('short_write_blocks')} ur={c('driver_underruns')} evd={c('events_dropped')} "
                   f"eve={c('events_evicted')} evc={c('events_lost_critical')} ld={self.dropped + self.evicted} "
                   f"lc={self.lost} admit={self.admit or 'none'}")
        self._enqueue(tick, f"tick-{tick}", {"kind": "d04_summary", "message": message, "epoch": c("epoch_resets"),
                                              "depth": in_flight, "latency_us": 0, "fault": self.admit, "cause": None,
                                              "critical": True})

    def evidence_complete(self) -> bool:
        return self.lost == 0 and self.upstream_lost_critical == 0

    def drain(self) -> List[str]:
        out = [line for _, line in self.queue]
        self.queue = []
        return out


def run(golden: Dict[str, Any], defect: Optional[str] = None) -> List[str]:
    log = Log(golden["identity"], defect)
    for step in golden["steps"]:
        if "set_admit_faults" in step:
            log.set_admit_faults(step["set_admit_faults"])
        elif "summary" in step:
            log.summary(step["summary"]["tick"], step["counters"], step["in_flight"])
        else:
            log.event(step["event"], step["counters"], step["in_flight"])
    return log.drain()


def run_bounded(golden: Dict[str, Any], defect: Optional[str] = None) -> Dict[str, Any]:
    """Ten ordinary blocks then one fault into a log of `capacity`: which correlation ids survive, and the stats."""
    b = golden["bounded"]
    log = Log({"run_id": "r", "case_id": "c", "capacity": b["capacity"]}, defect)
    for i in range(b["blocks"]):
        log.event({"tick": i, "kind": {"kind": "block", "index": i, "outcome": {"outcome": "on_time"}}}, {}, 0)
    log.event({"tick": b["fault_tick"], "kind": {"kind": "fault", "reason": "device_lost"}}, {}, 0)
    kept = [json.loads(line)["correlation_id"] for line in log.drain()]
    return {"kept": kept, "stats": {"emitted": log.emitted, "dropped_ordinary": log.dropped,
                                    "evicted_ordinary": log.evicted, "lost_critical": log.lost}}
