"""P04 (ffw-0bh): an independent model of the optional silence-priming gate in HalSession::start.

It mirrors the rules written in docs/contracts/p04.md ("Silence priming"), not the Rust code, and is replayed
against hand-traced scenarios in priming_vectors.json. The Rust tests in crates/franken-hal/src/session.rs
drive the real HalSession through the same scenarios by name; this file only says what each scenario must
produce, and carries the planted defects the scenarios have to catch.

Steps a scenario can take, and what each returns:

    ["submit", kind, take]   hand the session one block; returns "primed=N"
                             kind: tone | silence | short_silence | almost_silence
                             take: all | half | none  (how much of it the device accepts)
    ["start"]                "started", "refused P/R" (P blocks primed of R required), or "wrong_phase"
    ["drain"]                a stop the device acknowledges; "prepared primed=N"
    ["abort"]                a mute and a flush the device never acknowledges; "draining"
    ["reset"]                an acknowledged reset (from draining or faulted); "prepared primed=N", or
                             "wrong_phase" from anywhere else
    ["fault"]                an unexpected completion: the session faults muted; "faulted primed=N"
    ["lose"]                 the device vanishes; "lost primed=N"
"""
from __future__ import annotations

from typing import Any, Dict, List, Type

BLOCK_BYTES = 16
KINDS = ("tone", "silence", "short_silence", "almost_silence")
TAKES = ("all", "half", "none")


class Gate:
    """The rule under test: required blocks of silence before the first unmute, counted only when whole."""

    def __init__(self, required: int) -> None:
        self.required = required
        self.primed = 0
        self.phase = "prepared"
        self.amp = "muted"
        self.unmute_calls = 0

    # --- the rule, one method per decision, so a defect overrides exactly one thing

    def counts(self, kind: str, take: str) -> bool:
        """Does this submit add one to the count? Only a whole all-zero block, taken in full, while prepared
        (a prepared session is never unmuted, so the amplifier needs no check of its own)."""
        return self.phase == "prepared" and kind == "silence" and take == "all"

    def refuses(self) -> bool:
        """Is start refused for want of priming?"""
        return self.primed < self.required

    def on_unmute(self) -> None:
        self.primed = 0

    def on_stop(self) -> None:
        self.primed = 0

    def on_fault(self) -> None:
        self.primed = 0

    def on_loss(self) -> None:
        self.primed = 0

    def on_reset(self) -> None:
        self.primed = 0

    # --- the steps

    def submit(self, kind: str, take: str) -> str:
        if kind not in KINDS or take not in TAKES:
            raise ValueError(f"unknown block {kind!r}/{take!r}")
        if self.counts(kind, take):
            self.primed += 1
        return f"primed={self.primed}"

    def start(self) -> str:
        if self.phase != "prepared":
            return "wrong_phase"
        if self.refuses():
            return f"refused {self.primed}/{self.required}"
        self.unmute_calls += 1
        self.phase, self.amp = "running", "unmuted"
        self.on_unmute()
        return "started"

    def drain(self) -> str:
        self.phase, self.amp = "prepared", "muted"
        self.on_stop()
        return f"prepared primed={self.primed}"

    def abort(self) -> str:
        self.phase, self.amp = "draining", "muted"
        return "draining"

    def reset(self) -> str:
        if self.phase not in ("draining", "faulted"):
            return "wrong_phase"
        self.phase, self.amp = "prepared", "muted"
        self.on_reset()
        return f"prepared primed={self.primed}"

    def fault(self) -> str:
        self.phase, self.amp = "faulted", "muted"
        self.on_fault()
        return f"faulted primed={self.primed}"

    def lose(self) -> str:
        self.phase, self.amp = "faulted", "unknown"
        self.on_loss()
        return f"lost primed={self.primed}"


def replay(required: int, steps: List[List[Any]], model: Type[Gate] = Gate) -> Dict[str, Any]:
    """Run a scenario; the outputs of its steps and the state it ends in."""
    gate = model(required)
    outputs = []
    for step in steps:
        name, args = step[0], step[1:]
        outputs.append(getattr(gate, name)(*args))
    return {
        "outputs": outputs,
        "final": {"phase": gate.phase, "amp": gate.amp, "unmute_calls": gate.unmute_calls, "primed": gate.primed},
    }


# ------------------------------------------------------------------------------------ planted defects
# Each is one wrong decision. The scenarios must see every one of them.

class GateMissing(Gate):
    """start never asks whether the device was primed."""

    def refuses(self) -> bool:
        return False


class CountsTone(Gate):
    """Any whole block the device took counts, silence or not."""

    def counts(self, kind: str, take: str) -> bool:
        return self.phase == "prepared" and kind in ("silence", "tone") and take == "all"


class ChecksFirstSampleOnly(Gate):
    """Silence is judged from the start of the block, so a non-zero sample later on is missed."""

    def counts(self, kind: str, take: str) -> bool:
        return self.phase == "prepared" and kind in ("silence", "almost_silence") and take == "all"


class CountsShortBlocks(Gate):
    """An all-zero submit counts even if it is not a whole block."""

    def counts(self, kind: str, take: str) -> bool:
        return self.phase == "prepared" and kind in ("silence", "short_silence") and take == "all"


class CountsPartialTakes(Gate):
    """A block the device took only half of still counts."""

    def counts(self, kind: str, take: str) -> bool:
        return self.phase == "prepared" and kind == "silence" and take in ("all", "half")


class CountsRefusedTakes(Gate):
    """A block the device took none of still counts (a zero take is counted like a full one, but a half take is
    not, so only the zero-take step can see this)."""

    def counts(self, kind: str, take: str) -> bool:
        return self.phase == "prepared" and kind == "silence" and take in ("all", "none")


class CountsWhileUnmuted(Gate):
    """Silence submitted to a running, unmuted session is counted as priming."""

    def counts(self, kind: str, take: str) -> bool:
        return kind == "silence" and take == "all"


class SurvivesStop(Gate):
    """A flush acknowledgment leaves the count alone."""

    def on_stop(self) -> None:
        pass


class SurvivesFault(Gate):
    """A fault leaves the count alone."""

    def on_fault(self) -> None:
        pass


class SurvivesReset(Gate):
    """An acknowledged reset leaves the count alone."""

    def on_reset(self) -> None:
        pass


class SurvivesDeviceLoss(Gate):
    """A vanished device leaves the count alone."""

    def on_loss(self) -> None:
        pass


class OffByOneGate(Gate):
    """start is refused only while the device is more than one block short."""

    def refuses(self) -> bool:
        return self.primed + 1 < self.required


class UnmuteKeepsTheCount(Gate):
    """The unmute does not spend the count."""

    def on_unmute(self) -> None:
        pass


DEFECTS: Dict[str, Type[Gate]] = {
    "gate_missing": GateMissing,
    "counts_tone_blocks": CountsTone,
    "checks_only_the_first_sample": ChecksFirstSampleOnly,
    "counts_short_blocks": CountsShortBlocks,
    "counts_partial_takes": CountsPartialTakes,
    "counts_refused_takes": CountsRefusedTakes,
    "counts_while_unmuted": CountsWhileUnmuted,
    "survives_stop": SurvivesStop,
    "survives_fault": SurvivesFault,
    "survives_reset": SurvivesReset,
    "survives_device_loss": SurvivesDeviceLoss,
    "off_by_one_gate": OffByOneGate,
    "unmute_keeps_the_count": UnmuteKeepsTheCount,
}
