"""Reference model of the E04 DMA ownership simulator, written in Python.

This re-implements the semantics in docs/contracts/e04.md without reading crates/franken-hal. It
replays the same hand-written trace file (sim_cases.json) as the Rust simulator, so the two
implementations and the hand-written expectations must all agree. It is written by the same author
as the Rust one, so agreement is a cross-check and not independence from a second author.

``defects`` plants known bugs on purpose. The runner requires every planted defect to be caught by
at least one case, and the unmodified model to pass all of them, so the cases cannot pass vacuously.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

SLOT_CAP = 64

# defect name -> what it breaks
DEFECTS = {
    "second_owner": "a second acquire replaces the owner instead of being refused",
    "release_while_dma_owned": "a buffer the driver owns can be released",
    "release_with_quarantine": "the device can be released with quarantined slots outstanding",
    "no_flush_ack_needed": "the device can be released while still draining, before a flush acknowledgment",
    "mute_failure_ignored": "an unacknowledged mute is treated as acknowledged",
    "start_after_mute_failure": "start is allowed while the mute is unacknowledged",
    "power_save_with_dma": "power-save is allowed while a buffer is in flight",
    "trust_counter": "the consumed-frame counter may claim more than is in flight",
    "forgive_overclaim": "a driver that accepts more than offered is clamped instead of flagged",
    "daemon_not_orphaned": "replacing the daemon leaves its radio duties held",
    "skip_amp_order": "an amplifier step is accepted out of the contract's order",
    "ignore_min_delay": "an amplifier step is accepted before its minimum delay has passed",
    "start_without_sequence": "start is allowed before the startup sequence and the rate are done",
    "unsupported_rate_accepted": "a sample rate the contract does not list is accepted",
    "partial_frame_accepted": "a byte count that is not a whole number of frames is accepted",
    "clocks_off_unmuted_allowed": "the clocks can be cut while the amplifier is not known muted",
}

OK = {"result": "ok"}


def refused(reason: str) -> Dict[str, Any]:
    return {"result": "refused", "reason": reason}


def anomaly(kind: str) -> Dict[str, Any]:
    return {"result": "anomaly", "kind": kind}


class Sim:
    def __init__(self, start_counter: int = 0, defects: Iterable[str] = (),
                 model: Optional[Dict[str, Any]] = None) -> None:
        unknown = set(defects) - set(DEFECTS)
        if unknown:
            raise ValueError(f"unknown defects {sorted(unknown)}")
        self.defects = set(defects)
        self.owner: Optional[str] = None
        self.phase = "closed"
        self.amp = "muted"
        self.slots: List[str] = []
        self.now = 0
        self.deadline: Optional[int] = None
        self.submitted = 0
        self.consumed = 0
        self.start_counter = start_counter
        self.last_counter = start_counter
        self.replaced = False
        self.duties: Dict[str, List[Any]] = {}  # duty -> [owner or None, state]
        # the channel map, rates and amplifier sequence the trace runs against (None: no model)
        self.model = model
        self.rate_hz: Optional[int] = None
        self.amp_progress = 0           # startup steps done before the final unmute
        self.last_amp_at = 0
        self.clocks_on = False

    # ---- public
    def apply(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        return getattr(self, "_" + ev["type"])(ev)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "phase": self.phase, "amp": self.amp, "owner": self.owner, "slots": list(self.slots),
            "submitted": self.submitted, "consumed": self.consumed,
            "radio": {d: v[1] for d, v in self.duties.items()},
            "rate_hz": self.rate_hz, "amp_progress": self.amp_progress, "clocks_on": self.clocks_on,
        }

    # ---- helpers
    def _has(self, state: str) -> bool:
        return state in self.slots

    # ---- events
    def _acquire(self, ev):
        if self.owner is not None and "second_owner" not in self.defects:
            return refused("busy")
        self.owner = ev["owner"]
        return OK

    def _prepare(self, ev):
        if self.owner is None:
            return refused("not_owner")
        if self.phase != "closed":
            return refused("wrong_phase")
        n = ev["slots"]
        if n == 0 or n > SLOT_CAP:
            return refused("bad_slot_count")
        self.slots = ["free"] * n
        self.phase, self.amp, self.deadline = "prepared", "muted", None
        self.rate_hz, self.amp_progress, self.clocks_on = None, 0, False
        return OK

    def _start(self, ev):
        if self.phase != "prepared":
            return refused("wrong_phase")
        if self.amp == "mute_failed" and "start_after_mute_failure" not in self.defects:
            return refused("mute_not_acknowledged")
        if self.model is not None and "start_without_sequence" not in self.defects:
            if self.rate_hz is None:
                return refused("rate_not_set")
            startup = self.model["startup"]
            last = len(startup) - 1
            if self.amp_progress < last:
                return refused("amp_sequence_incomplete")
            if (self.amp_progress > 0 and "ignore_min_delay" not in self.defects
                    and self.now - self.last_amp_at < startup[last]["min_delay_ticks"]):
                return refused("amp_step_too_early")
        self.amp, self.phase = "unmuted", "running"
        self.amp_progress = 0
        return OK

    def _submit_preflight(self, i):
        if self.phase not in ("prepared", "running"):
            return refused("wrong_phase")
        if i >= len(self.slots):
            return refused("bad_slot")
        if self.slots[i] != "free":
            return refused("slot_not_free")
        return None

    def _submit(self, ev):
        early = self._submit_preflight(ev["slot"])
        if early is not None:
            return early
        return self._submit_frames(ev["slot"], ev["frames"], ev["accepted"])

    def _submit_bytes(self, ev):
        if self.model is None:
            return refused("no_model")
        early = self._submit_preflight(ev["slot"])
        if early is not None:
            return early
        frame_bytes = self.model["channels"] * self.model["bytes_per_sample"] or 1
        offered, taken = ev["bytes"], ev["accepted_bytes"]
        if offered == 0:
            return refused("empty_submit")
        lenient = "partial_frame_accepted" in self.defects
        if offered % frame_bytes and not lenient:
            return refused("partial_frame")
        if taken > offered:
            return anomaly("accepted_more_than_offered")
        if taken % frame_bytes and not lenient:
            return anomaly("accepted_partial_frame")
        return self._submit_frames(ev["slot"], offered // frame_bytes, taken // frame_bytes)

    def _set_rate(self, ev):
        if self.model is None:
            return refused("no_model")
        if self.owner is None:
            return refused("not_owner")
        if self.phase != "prepared":
            return refused("wrong_phase")
        if ev["hz"] not in self.model["rates_hz"] and "unsupported_rate_accepted" not in self.defects:
            return refused("rate_not_supported")
        self.rate_hz = ev["hz"]
        return OK

    def _amp_step(self, ev):
        if self.model is None:
            return refused("no_model")
        if self.owner is None:
            return refused("not_owner")
        action = ev["action"]
        if action == "disable_clocks":
            if self.amp != "muted" and "clocks_off_unmuted_allowed" not in self.defects:
                return refused("clocks_off_while_unmuted")
            self.clocks_on, self.amp_progress = False, 0
            return OK
        if self.phase != "prepared":
            return refused("wrong_phase")
        startup = self.model["startup"]
        if self.amp_progress >= len(startup) - 1:
            return refused("amp_step_out_of_order")
        expected = startup[self.amp_progress]
        if action != expected["action"] and "skip_amp_order" not in self.defects:
            return refused("amp_step_out_of_order")
        if (self.amp_progress > 0 and "ignore_min_delay" not in self.defects
                and self.now - self.last_amp_at < expected["min_delay_ticks"]):
            return refused("amp_step_too_early")
        self.amp_progress += 1
        self.last_amp_at = self.now
        if action == "enable_clocks":
            self.clocks_on = True
        return OK

    def _submit_frames(self, i, frames, accepted):
        if frames == 0:
            return refused("empty_submit")
        if accepted > frames:
            if "forgive_overclaim" not in self.defects:
                return anomaly("accepted_more_than_offered")
            accepted = frames
        if accepted == 0:
            return {"result": "partial", "remainder": frames}
        self.slots[i] = "dma_owned"
        self.submitted += accepted
        if accepted < frames:
            return {"result": "partial", "remainder": frames - accepted}
        return OK

    def _completion(self, ev):
        i = ev["slot"]
        state = self.slots[i] if i < len(self.slots) else None
        if state == "dma_owned":
            self.slots[i] = "free"
            return OK
        if state == "quarantined":
            return anomaly("completion_for_quarantined_slot")
        return anomaly("spurious_completion")

    def _release_slot(self, ev):
        i = ev["slot"]
        if i >= len(self.slots):
            return refused("bad_slot")
        state = self.slots[i]
        if state == "dma_owned" and "release_while_dma_owned" not in self.defects:
            return refused("release_while_dma_owned")
        if state == "quarantined":
            return refused("slot_quarantined")
        if state == "released":
            return refused("already_released")
        self.slots[i] = "released"
        return OK

    def _drain(self, ev):
        if self.phase not in ("running", "prepared"):
            return refused("wrong_phase")
        self.phase, self.amp = "draining", "muted"
        self.deadline = self.now + ev["max_wait_ticks"]
        self.amp_progress = 0
        return OK

    def _tick(self, ev):
        self.now += ev["ticks"]
        if self.phase == "draining" and self.deadline is not None and self.now >= self.deadline:
            self.slots = ["quarantined" if s == "dma_owned" else s for s in self.slots]
            self.phase, self.deadline = "faulted", None
            return {"result": "drain_timed_out"}
        return OK

    def _flush_ack(self, ev):
        if self.phase != "draining":
            return anomaly("flush_ack_outside_drain")
        self.slots = ["free" if s == "dma_owned" else s for s in self.slots]
        self.phase, self.deadline = "prepared", None
        return OK

    def _abort_mute(self, ev):
        if self.phase == "closed":
            return refused("wrong_phase")
        self.amp_progress = 0
        if ev["ack"] or "mute_failure_ignored" in self.defects:
            self.amp = "muted"
            if self.phase != "faulted":
                self.phase = "draining"
            return OK
        self.amp, self.phase, self.deadline = "mute_failed", "faulted", None
        return {"result": "mute_failed"}

    def _device_reset(self, ev):
        if self.owner is None:
            return refused("not_owner")
        if not ev["ack"]:
            return anomaly("reset_unacknowledged")
        self.slots = ["free" if s in ("dma_owned", "quarantined") else s for s in self.slots]
        if self.phase in ("faulted", "draining"):
            self.phase = "prepared"
        self.deadline = None
        self.amp_progress = 0
        return OK

    def _device_loss(self, ev):
        self.slots = ["quarantined" if s == "dma_owned" else s for s in self.slots]
        self.amp, self.phase, self.deadline = "mute_failed", "faulted", None
        self.amp_progress = 0
        return OK

    def _power_save(self, ev):
        if ev["enter"]:
            if self.owner is None:
                return refused("not_owner")
            if self.phase != "prepared":
                return refused("wrong_phase")
            if self.amp != "muted":
                return refused("power_save_needs_mute")
            busy = self._has("dma_owned") or self._has("quarantined")
            if busy and "power_save_with_dma" not in self.defects:
                return refused("power_save_needs_idle")
            self.phase = "power_save"
            return OK
        if self.phase != "power_save":
            return refused("not_in_power_save")
        self.phase = "prepared"
        return OK

    def _consumed_counter(self, ev):
        value = ev["value"]
        delta = (value - self.last_counter) % (1 << 32)
        in_flight = max(self.submitted - self.consumed, 0)
        if delta > in_flight and "trust_counter" not in self.defects:
            return anomaly("counter_exceeds_in_flight")
        self.consumed += delta
        self.last_counter = value
        return OK

    def _release_device(self, ev):
        if self.owner != ev["owner"]:
            return refused("not_owner")
        if self.amp == "mute_failed":
            return refused("mute_not_acknowledged")
        if self._has("dma_owned"):
            return refused("dma_owned_slots")
        if self._has("quarantined") and "release_with_quarantine" not in self.defects:
            return refused("quarantined_slots")
        allowed = ("closed", "prepared") + (("draining",) if "no_flush_ack_needed" in self.defects else ())
        if self.phase not in allowed:
            return refused("wrong_phase")
        self.owner, self.phase, self.amp = None, "closed", "muted"
        self.slots, self.deadline = [], None
        self.rate_hz, self.amp_progress, self.clocks_on = None, 0, False
        self.submitted = self.consumed = 0
        self.last_counter = self.start_counter
        return OK

    def _declare_duty(self, ev):
        owner = ev.get("owner")
        if owner == "kernel_driver":
            state = "held_kernel_driver"
        elif owner == "chip_firmware":
            state = "held_chip_firmware"
        elif owner == "daemon":
            state = "orphaned" if self.replaced else "held_daemon"
        else:
            state = "owner_unknown"
        self.duties[ev["duty"]] = [owner, state]
        return OK

    def _daemon_replaced(self, ev):
        self.replaced = True
        if "daemon_not_orphaned" not in self.defects:
            for rec in self.duties.values():
                if rec[1] == "held_daemon":
                    rec[1] = "orphaned"
        return OK

    def _adopt_duty(self, ev):
        rec = self.duties.get(ev["duty"])
        if rec is None:
            return refused("duty_not_declared")
        if rec[0] != "daemon":
            return refused("not_daemon_owned")
        if not self.replaced:
            return refused("daemon_not_replaced")
        rec[1] = "adopted"
        return OK


def replay(case: Dict[str, Any], defects: Iterable[str] = ()) -> Optional[Dict[str, Any]]:
    """Replay one case. Returns None when every step and the final state match the hand-written
    expectation, otherwise a description of the first disagreement."""
    sim = Sim(case.get("start_counter", 0), defects, case.get("model"))
    for index, step in enumerate(case["steps"]):
        observed = sim.apply(step["ev"])
        if observed != step["expect"]:
            return {"case": case["id"], "step": index, "event": step["ev"],
                    "expected": step["expect"], "observed": observed}
    final = dict(case["final"])
    final.setdefault("radio", {})
    final.setdefault("rate_hz", None)
    final.setdefault("amp_progress", 0)
    final.setdefault("clocks_on", False)
    snap = sim.snapshot()
    if snap != final:
        return {"case": case["id"], "step": None, "expected": final, "observed": snap}
    return None
