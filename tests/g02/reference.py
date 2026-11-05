"""Independent reference model for G02 (ffw-ld0): group volume, trim, mute, roles.

Written from docs/contracts/g02.md, not from the Rust source. It is a *second implementation of the
same contract by the same author*: it catches transcription mistakes and regressions, not a
misreading of the contract itself. Hand-derived pins in test_g02.py are the check on the model.

Arithmetic that reaches the output is emulated in f32 (``q32`` after every operation) so the model
agrees with the Rust code to the last bit, including the sample on which D02's ramp snaps to its
target. Rust double-rounding is innocuous here (+,-,*,/ in f64 then one rounding to f32 equals the
f32 operation, because 53 >= 2*24+2).

``bugs`` switch on named planted defects. They exist only so the tests can show that the vectors
catch each one; every mutant is paired with the unmutated control that must stay green.
"""
from __future__ import annotations

import math
import struct
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

MAX_VOLUME = 100
TRIM_UNITY = 1000
MAX_TRIM = 2000
MAX_REL_STEP = 100
MAX_LOCAL_TRIM_STEP = 500
FS = 48_000.0
RAMP_MS = 10.0  # the synthetic calibration D02 supplies (tests/d02 pins it)

BUGS = (
    "mute_unmutes_on_volume",
    "group_unmute_clears_local",
    "adopt_epoch",
    "retry_reapplies",
    "stale_applies",
    "no_clamp_before_ramp",
    "reconnect_keeps_stored",
    "reconnect_no_join_mute",
    "fault_ignored",
    "trim_reset_on_volume",
    "restore_armed",
    "adjust_no_saturate",
    "sub_gets_left",
    "role_always_ok",
    "missing_applies",
    "ramp_restarts",
    "local_trim_unmutes",
    "invalid_consumes_revision",
)


def q32(x: float) -> float:
    return struct.unpack(">f", struct.pack(">f", x))[0]


def ramp_step() -> float:
    """D02's per-sample slew: ``(1 / (ms * 1e-3 * fs)).min(1.0) as f32``."""
    return q32(min(1.0, 1.0 / (RAMP_MS * 1.0e-3 * FS)))


def bounded_ceiling(value: Any) -> float:
    """A ceiling input is a number or the strings "nan"/"inf" (JSON has no non-finite numbers)."""
    x = q32(float(value)) if not isinstance(value, str) else float(value)
    if not math.isfinite(x):
        return 0.0
    return q32(min(1.0, max(0.0, x)))


def command_gain(volume: int, trim: int) -> float:
    return q32(q32(volume / 100.0) * q32(trim / 1000.0))


# ---- the D02 side: only the part G02 drives -------------------------------------------------------


class Dsp:
    """What G02 needs from D02: a gain, a mute, a status, and a per-sample slew with an exact snap."""

    def __init__(self, active: bool, bugs: FrozenSet[str]) -> None:
        self.bugs = bugs
        self.active = active
        self.applied = 0.0
        self.user: Optional[float] = None  # unobserved until the first sync
        self.muted = True
        self.step = ramp_step()

    def set_user_gain(self, gain: float) -> None:
        new = gain if math.isfinite(gain) else 0.0
        new = min(1.0, max(0.0, new))
        if "ramp_restarts" in self.bugs and self.user is not None and new != self.user:
            self.applied = 0.0
        self.user = new

    def set_muted(self, muted: bool) -> str:
        if not muted and not self.active:
            return "unmute_refused"
        self.muted = muted
        return "ok"

    def frame(self) -> float:
        target = (self.user or 0.0) if (self.active and not self.muted) else 0.0
        diff = q32(target - self.applied)
        if abs(diff) <= self.step:
            self.applied = target
        elif diff > 0.0:
            self.applied = q32(self.applied + self.step)
        else:
            self.applied = q32(self.applied - self.step)
        return self.applied

    def ramp(self, frames: int) -> Dict[str, Any]:
        previous = self.applied
        values: List[float] = []
        deltas: List[float] = []
        for _ in range(frames):
            now = self.frame()
            values.append(now)
            deltas.append(now - previous)
            previous = now
        signs = [1 if d > 0 else -1 for d in deltas if d != 0.0]
        changes = sum(1 for a, b in zip(signs, signs[1:]) if a != b)
        return {
            "max_step": max((abs(d) for d in deltas), default=0.0),
            "direction_changes": changes,
            "max_applied": max(values, default=self.applied),
            "min_applied": min(values, default=self.applied),
        }


# ---- one room -----------------------------------------------------------------------------------------


MUTE_ORDER = ("fault", "local", "join", "group")


class Member:
    def __init__(self, ceiling: Any, bugs: FrozenSet[str] = frozenset(), persisted: Optional[dict] = None) -> None:
        self.bugs = bugs
        self.epoch: Optional[int] = None
        self.last_rev = 0
        self.last_cmd: Optional[Tuple[int, tuple]] = None
        self.volume = 0
        self.trim = TRIM_UNITY
        self.flags = {"fault": False, "local": False, "join": True, "group": False}
        self.pc = bounded_ceiling(ceiling)
        self.fc: Optional[float] = None
        if persisted is not None:
            self.volume = min(persisted["volume"], MAX_VOLUME)
            self.trim = min(persisted["trim"], MAX_TRIM)
            self.flags["local"] = persisted["local_mute"]

    # -- derived
    def mute(self) -> Optional[str]:
        return next((name for name in MUTE_ORDER if self.flags[name]), None)

    def ceiling(self) -> float:
        return self.pc if self.fc is None else min(self.fc, self.pc)

    def unmuted(self) -> float:
        if self.epoch is None and "restore_armed" not in self.bugs:
            return 0.0
        linear = command_gain(self.volume, self.trim)
        bound = 1.0 if "no_clamp_before_ramp" in self.bugs else self.ceiling()
        return min(1.0, max(0.0, min(linear, bound)))

    def gain(self) -> float:
        return 0.0 if self.mute() else self.unmuted()

    # -- authority
    def declare(self, epoch: int) -> str:
        if self.epoch is not None and epoch < self.epoch:
            return "stale_epoch"
        if self.epoch != epoch:
            self.epoch, self.last_rev, self.last_cmd = epoch, 0, None
        return "ok"

    def apply(self, epoch: int, revision: int, command: tuple) -> Tuple[str, bool]:
        """(result, duplicate). A refusal changes nothing."""
        if self.epoch is None:
            return "no_authority", False
        if epoch < self.epoch:
            return "stale_epoch", False
        if epoch > self.epoch:
            if "adopt_epoch" not in self.bugs:
                return "undeclared_epoch", False
            self.epoch, self.last_rev, self.last_cmd = epoch, 0, None
        replay = self.last_cmd is not None and self.last_cmd[0] == revision
        if replay:
            if self.last_cmd[1] != command:
                return "revision_conflict", False
            if "retry_reapplies" not in self.bugs:
                return "ok", True
        elif revision <= self.last_rev and "stale_applies" not in self.bugs:
            return "stale_revision", False
        kind = command[0]
        if kind == "set_volume" and command[1] > MAX_VOLUME:
            return self._invalid(revision, command, "volume_out_of_range")
        if kind == "adjust_volume" and not -MAX_REL_STEP <= command[1] <= MAX_REL_STEP:
            return self._invalid(revision, command, "step_out_of_range")
        if kind == "set_trim" and command[1] > MAX_TRIM:
            return self._invalid(revision, command, "trim_out_of_range")
        if kind == "set_volume":
            self.volume = command[1]
            if "mute_unmutes_on_volume" in self.bugs:
                self.flags["local"] = self.flags["group"] = False
            if "trim_reset_on_volume" in self.bugs:
                self.trim = TRIM_UNITY
        elif kind == "adjust_volume":
            total = self.volume + command[1]
            self.volume = total % 256 if "adjust_no_saturate" in self.bugs else min(MAX_VOLUME, max(0, total))
            if "mute_unmutes_on_volume" in self.bugs:
                self.flags["local"] = self.flags["group"] = False
        elif kind == "set_trim":
            self.trim = command[1]
        elif kind == "reset_trim":
            self.trim = TRIM_UNITY
        elif kind == "set_group_mute":
            self.flags["group"] = bool(command[1])
            if "group_unmute_clears_local" in self.bugs and not command[1]:
                self.flags["local"] = False
        self.last_rev, self.last_cmd = revision, (revision, command)
        return "ok", False

    def _invalid(self, revision: int, command: tuple, code: str) -> Tuple[str, bool]:
        if "invalid_consumes_revision" in self.bugs:
            self.last_rev, self.last_cmd = revision, (revision, command)
        return code, False

    # -- the room's own controls and the board
    def local_mute(self, muted: bool) -> None:
        self.flags["local"] = muted

    def local_trim(self, delta: int) -> str:
        if not -MAX_LOCAL_TRIM_STEP <= delta <= MAX_LOCAL_TRIM_STEP:
            return "step_out_of_range"
        self.trim = min(MAX_TRIM, max(0, self.trim + delta))
        if "local_trim_unmutes" in self.bugs:
            self.flags["local"] = False
        return "ok"

    def observe_board(self, active: bool) -> None:
        if "fault_ignored" not in self.bugs:
            self.flags["fault"] = not active

    def set_protection_ceiling(self, value: Any) -> None:
        self.pc = bounded_ceiling(value)

    def set_fault_ceiling(self, value: Any) -> None:
        self.fc = None if value is None else bounded_ceiling(value)

    def reconnect(self, epoch: int, revision: int, volume: int, group_mute: bool) -> str:
        if volume > MAX_VOLUME:
            return "volume_out_of_range"
        if self.epoch is not None and epoch < self.epoch:
            return "stale_epoch"
        self.adopt(epoch, revision, volume, group_mute)
        return "ok"

    def adopt(self, epoch: int, revision: int, volume: int, group_mute: bool) -> None:
        self.epoch, self.last_rev, self.last_cmd = epoch, revision, None
        if "reconnect_keeps_stored" not in self.bugs:
            self.volume = volume
        self.flags["group"] = group_mute
        if "reconnect_no_join_mute" not in self.bugs:
            self.flags["join"] = True

    def complete_join(self) -> None:
        self.flags["join"] = False

    # -- D02 hand-off
    def sync(self, dsp: Dsp) -> str:
        self.observe_board(dsp.active)
        dsp.set_user_gain(self.unmuted())
        return dsp.set_muted(self.mute() is not None)

    def state(self) -> Dict[str, Any]:
        return {"mute": self.mute(), "desired": self.volume, "trim": self.trim, "epoch": self.epoch,
                "revision": self.last_rev, "unmuted": self.unmuted(), "gain": self.gain()}


def as_command(raw: list) -> tuple:
    return tuple(raw)


# ---- scripted scenarios: one observation per operation ----------------------------------------------------


def run_member_script(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    start = case.get("start", "new")
    persisted = None if start == "new" else start["restore"]
    member = Member(case["ceiling"], bugs, persisted)
    board = case.get("board")
    dsp = Dsp(active=(board == "active"), bugs=bugs) if board else None
    synced = False
    trace: List[Dict[str, Any]] = []
    for op in case["ops"]:
        name, args = op[0], op[1:]
        extra: Dict[str, Any] = {}
        result = "ok"
        duplicate: Optional[bool] = None
        if name == "declare":
            result = member.declare(args[0])
        elif name == "join":
            member.complete_join()
        elif name == "cmd":
            result, duplicate = member.apply(args[0], args[1], as_command(args[2]))
        elif name == "local_mute":
            member.local_mute(args[0])
        elif name == "local_trim":
            result = member.local_trim(args[0])
        elif name == "board":
            member.observe_board(args[0] == "active")
        elif name == "ceiling":
            member.set_protection_ceiling(args[0])
        elif name == "fault_ceiling":
            member.set_fault_ceiling(args[0])
        elif name == "reconnect":
            result = member.reconnect(*args)
        elif name == "sync":
            result = member.sync(dsp)
            synced = True
        elif name == "ramp":
            extra = dsp.ramp(args[0])
        else:
            raise ValueError(f"unknown member op {name}")
        entry: Dict[str, Any] = {"op": name, "result": result, **member.state()}
        if duplicate is not None and result == "ok":  # a refusal has no receipt, so no `duplicate`
            entry["duplicate"] = duplicate
        if dsp is not None:
            entry["dsp"] = {"applied": dsp.applied, "muted": dsp.muted, "user": dsp.user if synced else None}
        entry.update(extra)
        trace.append(entry)
    return {"trace": trace}


class Group:
    def __init__(self, epoch: int, bugs: FrozenSet[str]) -> None:
        self.bugs = bugs
        self.authority = Member(1.0, bugs)
        self.authority.epoch = epoch
        self.authority.flags["join"] = False
        self.members: List[dict] = []

    def snapshot(self) -> Dict[str, Any]:
        a = self.authority
        return {"epoch": a.epoch if a.epoch is not None else 0, "revision": a.last_rev, "volume": a.volume,
                "group_mute": a.mute() == "group"}

    def find(self, member_id: int) -> Optional[dict]:
        return next((m for m in self.members if m["id"] == member_id), None)

    def add(self, member_id: int, ceiling: Any) -> str:
        if self.find(member_id):
            return "duplicate_member"
        member = Member(ceiling, self.bugs)
        s = self.snapshot()
        member.adopt(s["epoch"], s["revision"], s["volume"], s["group_mute"])
        self.members.append({"id": member_id, "present": True, "m": member})
        return "ok"

    def apply(self, epoch: int, revision: int, command: tuple) -> Tuple[str, List[list]]:
        if command[0] in ("set_trim", "reset_trim"):
            return "not_group_wide", []
        result, _ = self.authority.apply(epoch, revision, command)
        if result != "ok":
            return result, []
        out = []
        for entry in self.members:
            if entry["present"] or "missing_applies" in self.bugs:
                code, duplicate = entry["m"].apply(epoch, revision, command)
                out.append([entry["id"], ("duplicate" if duplicate else "accepted") if code == "ok" else code])
            else:
                out.append([entry["id"], "missing"])
        return "ok", out

    def state(self) -> List[list]:
        return [[e["id"], e["m"].volume, e["m"].mute(), e["m"].gain(), e["m"].epoch] for e in self.members]


def run_group_script(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    group = Group(case["epoch"], bugs)
    trace: List[Dict[str, Any]] = []
    for op in case["ops"]:
        name, args = op[0], op[1:]
        result = "ok"
        members: Optional[List[list]] = None
        if name == "add":
            result = group.add(args[0], args[1])
        elif name == "join":
            entry = group.find(args[0])
            if entry:
                entry["m"].complete_join()
            else:
                result = "unknown_member"
        elif name == "present":
            entry = group.find(args[0])
            if entry:
                entry["present"] = args[1]
            else:
                result = "unknown_member"
        elif name == "gcmd":
            result, fanout = group.apply(args[0], args[1], as_command(args[2]))
            members = fanout if result == "ok" else None  # a refusal fans out to nobody
        elif name == "rejoin":
            entry = group.find(args[0])
            if entry is None:
                result = "unknown_member"
            else:
                s = group.snapshot()
                result = entry["m"].reconnect(s["epoch"], s["revision"], s["volume"], s["group_mute"])
                if result == "ok":
                    entry["present"] = True
        elif name == "declare_member":
            entry = group.find(args[0])
            result = entry["m"].declare(args[1]) if entry else "unknown_member"
        elif name == "local_mute":
            entry = group.find(args[0])
            if entry:
                entry["m"].local_mute(args[1])
            else:
                result = "unknown_member"
        else:
            raise ValueError(f"unknown group op {name}")
        entry_obs: Dict[str, Any] = {"op": name, "result": result, "snapshot": group.snapshot(), "state": group.state()}
        if members is not None:
            entry_obs["members"] = members
        trace.append(entry_obs)
    return {"trace": trace}


# ---- gain grid and roles -----------------------------------------------------------------------------------------


def run_gain_grid(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    member = Member(case["protection_ceiling"], bugs)
    member.declare(1)
    member.complete_join()
    if case["fault_ceiling"] is not None:
        member.set_fault_ceiling(case["fault_ceiling"])
    gains = []
    for volume, trim in case["rows"]:
        member.volume, member.trim = volume, trim
        gains.append(member.unmuted())
    return {"gains": gains}


def role_result(role: str, hardware_channels: int, routing: list, bugs: FrozenSet[str] = frozenset()) -> str:
    if "role_always_ok" in bugs:
        return "ok"
    if hardware_channels == 0 or not routing:
        return "no_audio_output"
    if len(routing) != hardware_channels:
        return "invalid_layout"
    subs = sum(1 for r in routing if r == "subwoofer_lfe")
    none_sub, all_sub = subs == 0, subs == len(routing)
    if role == "sub":
        return "ok" if all_sub else ("no_subwoofer_path" if none_sub else "mixed_sub_layout")
    return "ok" if none_sub else ("subwoofer_only" if all_sub else "mixed_sub_layout")


def run_roles(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    layout = case["layout"]
    return {"results": {role: role_result(role, layout["hardware_channels"], layout["routing"], bugs)
                        for role in ("stereo", "left", "right", "sub")}}


def role_map(role: str, left: float, right: float, bugs: FrozenSet[str] = frozenset()) -> Tuple[float, float]:
    if role == "stereo":
        return left, right
    if role == "left":
        return left, left
    if role == "right":
        return right, right
    mid = left if "sub_gets_left" in bugs else q32(0.5 * q32(left + right))
    return mid, mid


def run_role_map(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    return {"mapped": {role: [list(role_map(role, l, r, bugs)) for l, r in case["samples"]]
                       for role in ("stereo", "left", "right", "sub")}}


OBSERVERS = {
    "gain_grid": run_gain_grid,
    "roles": run_roles,
    "role_map": run_role_map,
    "member_script": run_member_script,
    "group_script": run_group_script,
}


def observe(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    """What a correct (or, with ``bugs``, a deliberately wrong) implementation reports for ``case``."""
    return OBSERVERS[case["kind"]](case, bugs)
