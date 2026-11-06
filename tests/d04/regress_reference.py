"""Independent model of the D04 render loop's reaction to a driver counter regress (ffw-5h5).

Written from docs/contracts/d04.md ("A driver counter that goes backwards"), not from the Rust. It models the HAL
session's classification of a consumed-position report and the loop's reaction to it, at the level the contract states:
what the report is called, which state the loop ends in, whether the presentation mapping is still valid, what is held,
what is credited, and which events the loop reports. It does not tick a render loop, build anything or touch a device.
The Rust (crates/franken-hal/src/session.rs, crates/franken-speaker/src/render.rs) must agree with the hand-typed
expectations in tests/d04/regress_golden.json; each scenario there names the Rust test that pins the same boundary.

Evidence: model, host simulation. This is the fake device's counter. The real driver's counter semantics are unknown.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

SCHEMA = "ffw.d04.regress_golden.v1"
MASK = 0xFFFFFFFF  # the driver's consumed counter is 32 bits and wraps
HALF = 0x80000000  # a step of exactly half the range is ambiguous and is read as ahead
BLOCK_FRAMES = 64
RING = 4
STOP_DEADLINE = 8

FINAL_KEYS = ("phase", "fault", "mapping_valid", "consumed", "quarantined", "free", "tail", "tail_trusted", "events")

DEFECTS = (
    "regress_as_session_fault",  # today's behaviour: a regress is an ordinary session fault, mapping untouched
    "mapping_kept_valid",  # the fault is named but the old mapping is still used
    "baseline_kept",  # the old counter baseline survives the reset
    "released_on_timeout",  # held buffers are freed because time passed
    "half_is_regress",  # the ambiguous half-range step is read as a regress
    "double_reaction",  # the reaction is reported twice
    "regress_credits_the_step",  # the step back is credited as progress
)


def classify(last: int, counter: int, in_flight: int, defect: Optional[str] = None):
    """How a consumed-position report is read against the last one and the frames still in flight."""
    step = (counter - last) & MASK
    if step <= in_flight:
        return "clean", step
    behind = step >= HALF if defect == "half_is_regress" else step > HALF
    return ("regress" if behind else "overclaim"), step


class Loop:
    """The session and the loop together, with `held` blocks the device never completes."""

    def __init__(self, defect: Optional[str] = None):
        self.defect = defect
        self.phase = "ready"
        self.mapping_valid = True
        self.rebaseline = True
        self.last = 0
        self.accepted = 0
        self.consumed = 0
        self.discarded = 0
        self.held = 0
        self.quarantined = 0
        self.fault: Optional[str] = None
        self.tail = 0
        self.tail_trusted = True
        self.since_fault = 0
        self.events: List[str] = []

    def _state(self, to: str) -> None:
        if self.phase != to:
            self.events.append(f"state {self.phase}->{to}")
            self.phase = to

    def in_flight(self) -> int:
        return self.accepted - self.consumed - self.discarded

    def apply(self, step: Dict[str, Any]) -> str:
        ((key, arg),) = step.items()
        return getattr(self, "do_" + key)(arg)

    def do_start(self, _: Any) -> str:
        if self.phase not in ("ready", "stopped"):
            return f"wrong_state:{self.phase}"
        if not self.mapping_valid:
            return "presentation_mapping_invalidated"
        self.fault = None
        self._state("running")
        return "ok"

    def do_hold(self, blocks: int) -> str:
        if self.phase not in ("running", "muted", "draining"):
            return f"wrong_state:{self.phase}"
        self.accepted += BLOCK_FRAMES * blocks
        self.held += blocks
        return "ok"

    def do_mute(self, _: Any) -> str:
        if self.phase != "running":
            return f"wrong_state:{self.phase}"
        self._state("muted")
        return "ok"

    def do_stop(self, _: Any) -> str:
        if self.phase not in ("running", "muted"):
            return f"wrong_state:{self.phase}"
        self.tail = self.accepted - self.consumed
        self.tail_trusted = True
        self._state("draining")
        return "ok"

    def do_position(self, counter: int) -> str:
        if self.phase not in ("running", "muted", "draining"):
            return "ignored"
        if self.rebaseline:
            self.last = counter
            self.rebaseline = False
            return "baseline"
        kind, step = classify(self.last, counter, self.in_flight(), self.defect)
        if kind == "clean":
            self.consumed += step
            self.last = counter
            return "clean"
        regress = kind == "regress"
        named = regress and self.defect != "regress_as_session_fault"
        if regress and self.defect == "regress_credits_the_step":
            self.consumed += step
        reason = "counter_regress" if named else "session_faulted"
        # Everything the device may still read is held, never freed by the fault itself.
        self.quarantined = self.held
        self.held = 0
        if named:
            if self.defect != "mapping_kept_valid":
                self.mapping_valid = False
            self.tail_trusted = False
        self.fault = reason
        self.since_fault = 0
        self.events.append(f"fault {reason}")
        if self.defect == "double_reaction" and named:
            self.events.append(f"fault {reason}")
        self._state("faulted")
        return kind

    def do_wait(self, ticks: int) -> str:
        if self.phase == "faulted":
            self.since_fault += ticks
            # A timeout alone frees nothing; only an acknowledged reset does.
            if self.defect == "released_on_timeout" and self.since_fault >= STOP_DEADLINE:
                self.quarantined = 0
        return "ok"

    def do_recover(self, _: Any) -> str:
        if self.phase != "faulted":
            return f"wrong_state:{self.phase}"
        # The acknowledged reset frees what was held, discards what was in flight, and takes a new baseline.
        self.discarded += self.in_flight()
        self.quarantined = 0
        self.rebaseline = self.defect != "baseline_kept"
        self.fault = None
        self._state("ready")
        return "ok"

    def do_reinstall(self, _: Any) -> str:
        if self.phase != "ready":
            return f"wrong_state:{self.phase}"
        self.mapping_valid = True
        return "ok"

    def final(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "fault": self.fault,
            "mapping_valid": self.mapping_valid,
            "consumed": self.consumed,
            "quarantined": self.quarantined,
            "free": RING - self.held - self.quarantined,
            "tail": self.tail,
            "tail_trusted": self.tail_trusted,
            "events": list(self.events),
        }


def simulate(scenario: Dict[str, Any], defect: Optional[str] = None) -> Dict[str, Any]:
    loop = Loop(defect)
    results = [loop.apply(step) for step in scenario["steps"]]
    return {"results": results, "final": loop.final()}
