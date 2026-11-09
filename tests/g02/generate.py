"""Deterministic G02 vector generator (ffw-ld0). Expected values come only from reference.py.

Writes tests/g02/vectors.json (via run_cases.py --write-vectors). The committed file must equal a
fresh generation; the runner checks that on every run.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("g02_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
SCHEMA = "ffw.g02.vectors.v1"
EPOCH = 7

INVARIANTS: Dict[str, str] = {
    "G02-INV-GAIN-COMPOSITION": "the target gain is min(volume/100 * trim/1000, protection ceiling, fault ceiling), exact in f32",
    "G02-INV-BOUND-BEFORE-RAMP": "the target handed to the ramp never exceeds its ceilings, so the applied gain never exceeds them",
    "G02-INV-ATOMIC-RAMP": "a change is one ramp; a new target retargets from the current applied gain with no restart or reversal",
    "G02-INV-MUTE-PRIORITY": "mute wins over every volume command, including one in flight; each mute reason has one owner",
    "G02-INV-AUTHORITY": "stale, undeclared and conflicting commands are refused with nothing changed; an epoch is never adopted from a command",
    "G02-INV-IDEMPOTENT-RETRY": "a replay of the last command is a duplicate and a relative command is applied exactly once",
    "G02-INV-OVERFLOW": "volume, trim and steps saturate or are refused at the type extremes; nothing wraps",
    "G02-INV-RECONNECT-SILENT": "a rejoining or restored member is silent, holds the group's current volume and ramps up from silence",
    "G02-INV-ROLES": "stereo, left, right and sub map onto the admitted layout; a role the board lacks is refused by name",
    "G02-INV-MISSING-MEMBERS": "absent members are skipped and rejoin from a fresh snapshot; unknown and duplicate members are refused",
    "G02-INV-UI-VIEW": "the desired volume, the bounded target and the applied gain are reported separately, with the effective mute reason",
    "G02-INV-REJOIN-KEEPS-OWN": "a rejoin never restores a volume older than the member's own state, and never undoes a local mute, a fault mute or a fault ceiling",
}

EXTERNAL: Dict[str, List[str]] = {
    "G02-INV-UI-VIEW": [
        "franken-dsp::volume::tests::the_view_keeps_desired_bounded_and_applied_gain_apart_and_explains_a_silent_unmute"
    ],
}

# Synthetic fixture layouts, stated here independently of the Rust catalog. The Rust harness checks
# every fixture entry against the real catalog, so a drifted fixture makes the vector fail, not pass.
LAYOUTS: Dict[str, dict] = {
    "S1": {"hardware_channels": 2, "routing": ["woofer_mono", "tweeter_mono"]},
    "S3": {"hardware_channels": 3, "routing": ["mid_left", "mid_right", "tweeter_mono"]},
    "S5": {"hardware_channels": 5,
           "routing": ["tweeter_left", "tweeter_right", "mid_left", "mid_right", "woofer_center"]},
    "Sub": {"hardware_channels": 1, "routing": ["subwoofer_lfe"]},
    "S9": {"hardware_channels": 9,
           "routing": [{"array_mid_woofer": i} for i in range(6)] + [{"array_tweeter": i} for i in range(3)]},
    "BR100": {"hardware_channels": 0, "routing": []},
}


def C(revision: int, *command: Any) -> list:
    return ["cmd", EPOCH, revision, list(command)]


def case(case_id: str, title: str, kind: str, invariants: List[str], **fields: Any) -> dict:
    body = {"id": case_id, "title": title, "kind": kind, "invariants": invariants, **fields}
    body["expect"] = ref.observe(body)
    return body


def gain_cases() -> List[dict]:
    rows = [[v, t] for v in (0, 1, 25, 50, 75, 99, 100) for t in (0, 250, 500, 1000, 1500, 2000)]
    few = [[100, 1000], [50, 500], [100, 2000]]
    inv = ["G02-INV-GAIN-COMPOSITION", "G02-INV-BOUND-BEFORE-RAMP"]
    spec = [
        ("001", "no ceiling beyond unity: volume x trim, boost clamped at 1", 1.0, None, rows),
        ("002", "protection ceiling 0.5 clamps the product", 0.5, None, rows),
        ("003", "fault ceiling 0.3 lowers it further", 1.0, 0.3, rows),
        ("004", "a fault ceiling above the protection ceiling never raises the bound", 0.4, 0.9, rows),
        ("005", "a NaN protection ceiling fails closed", "nan", None, few),
        ("006", "an infinite protection ceiling fails closed", "inf", None, few),
        ("007", "a NaN fault ceiling fails closed", 1.0, "nan", few),
    ]
    return [case(f"G02-GAIN-{n}", title, "gain_grid", inv, protection_ceiling=pc, fault_ceiling=fc, rows=r)
            for n, title, pc, fc, r in spec]


def role_cases() -> List[dict]:
    inv = ["G02-INV-ROLES"]
    out = []
    for i, (model, title) in enumerate((
        ("S5", "S5 has tweeters, mids and a woofer: stereo/left/right yes, sub refused"),
        ("S3", "S3 supports stereo/left/right, sub refused"),
        ("S1", "S1 supports stereo/left/right, sub refused"),
        ("S9", "S9 (9 array channels) supports stereo/left/right, sub refused"),
        ("Sub", "the Sub is sub-only: stereo/left/right refused"),
        ("BR100", "the Bridge has no audio output: every role refused by that name"),
    ), start=1):
        out.append(case(f"G02-ROLE-{i:03d}", title, "roles", inv, layout={"fixture": model, **LAYOUTS[model]}))
    synthetic = [
        ("a routing list shorter than the channel count is an invalid layout",
         "S3", {"hardware_channels": 3, "routing": ["mid_left", "mid_right"]}),
        ("a subwoofer mixed with other drivers cannot be given a role by an input remap",
         "S3", {"hardware_channels": 3, "routing": ["mid_left", "mid_right", "subwoofer_lfe"]}),
        ("zero channels with a non-empty routing list is still no audio output",
         "S3", {"hardware_channels": 0, "routing": ["mid_left"]}),
        ("a non-zero channel count with no routing is no audio output",
         "S3", {"hardware_channels": 2, "routing": []}),
        ("two subwoofer paths are still sub-only",
         "Sub", {"hardware_channels": 2, "routing": ["subwoofer_lfe", "subwoofer_lfe"]}),
    ]
    for j, (title, base, layout) in enumerate(synthetic, start=len(out) + 1):
        out.append(case(f"G02-ROLE-{j:03d}", title, "roles", inv, layout={"fixture": None, "base": base, **layout}))
    return out


def map_cases() -> List[dict]:
    inv = ["G02-INV-ROLES"]
    return [
        case("G02-MAP-001", "role remap on dyadic samples, including full scale and silence", "role_map", inv,
             samples=[[0.5, -0.25], [1.0, 1.0], [0.0, 0.75], [-1.0, 0.5], [0.125, 0.375], [0.0, 0.0]]),
        case("G02-MAP-002", "an asymmetric pair shows left, right and the mono mix are all different", "role_map", inv,
             samples=[[0.75, -0.5], [-0.875, 0.25]]),
    ]


def member_cases() -> List[dict]:
    AUTH = ["G02-INV-AUTHORITY"]
    out: List[dict] = []

    def add(n: int, title: str, invariants: List[str], ops: list, ceiling: Any = 1.0, board: Any = None,
            start: Any = "new") -> None:
        out.append(case(f"G02-MBR-{n:03d}", title, "member_script", invariants, ceiling=ceiling, board=board,
                        start=start, ops=ops))

    setup = [["declare", EPOCH], ["join"]]
    add(1, "volume x trim above the ceiling is bounded before the ramp, and the ramp ends exactly on the bound",
        ["G02-INV-BOUND-BEFORE-RAMP", "G02-INV-GAIN-COMPOSITION"],
        setup + [C(1, "set_volume", 100), C(2, "set_trim", 2000), ["sync"], ["ramp", 100], ["ramp", 100], ["ramp", 100], ["ramp", 100]],
        ceiling=0.5, board="active")
    add(2, "a new target mid-ramp continues from the current gain: up, then up further, then down, never restarting",
        ["G02-INV-ATOMIC-RAMP"],
        setup + [C(1, "set_volume", 100), ["sync"], ["ramp", 100], C(2, "set_volume", 40), ["sync"], ["ramp", 150],
                 C(3, "set_volume", 10), ["sync"], ["ramp", 100]],
        board="active")
    add(3, "mute wins over volume commands that arrive while the ramp is running, and unmute ramps up from silence",
        ["G02-INV-MUTE-PRIORITY", "G02-INV-ATOMIC-RAMP"],
        setup + [C(1, "set_volume", 100), ["sync"], ["ramp", 200], ["local_mute", True], ["sync"], ["ramp", 50],
                 C(2, "set_volume", 100), C(3, "adjust_volume", 100), ["sync"], ["ramp", 300],
                 ["local_mute", False], ["sync"], ["ramp", 10]],
        board="active")
    add(4, "each mute reason has one owner: a group unmute cannot clear local or fault, and the reported reason follows priority",
        ["G02-INV-MUTE-PRIORITY"],
        setup + [C(1, "set_volume", 60), C(2, "set_group_mute", True), C(3, "set_volume", 90), ["local_mute", True],
                 C(4, "set_group_mute", False), ["local_mute", False], C(5, "set_group_mute", True),
                 ["board", "fail_muted"], C(6, "set_group_mute", False), ["board", "active"]])
    unmute_ops = setup + [C(1, "set_volume", 100), C(2, "set_group_mute", False), ["sync"], ["ramp", 100],
                          C(3, "set_group_mute", False), ["sync"], ["ramp", 50]]
    add(5, "on a fail-muted board a requested unmute is overridden by the fault and the output stays silent",
        ["G02-INV-MUTE-PRIORITY"], unmute_ops, board="fail_muted")
    add(6, "the identical commands on an active board are audible (the permitted behaviour paired with the refusal above)",
        ["G02-INV-MUTE-PRIORITY"], unmute_ops, board="active")
    add(7, "stale revision, stale epoch and undeclared epoch are refused with nothing changed; the next legitimate command works",
        AUTH,
        setup + [C(1, "set_volume", 50), C(2, "set_volume", 60),
                 C(1, "set_volume", 99), ["cmd", EPOCH, 0, ["set_volume", 99]],
                 ["cmd", EPOCH - 1, 9, ["set_volume", 99]], ["cmd", EPOCH + 2, 9, ["set_volume", 99]],
                 C(3, "set_volume", 70),
                 ["declare", EPOCH - 1], ["declare", EPOCH], ["declare", EPOCH + 1],
                 ["cmd", EPOCH, 5, ["set_volume", 5]], ["cmd", EPOCH + 1, 1, ["set_volume", 5]]])
    add(8, "a member with no declared epoch has no authority and refuses every command, then works once declared",
        AUTH, [["join"], C(1, "set_volume", 50), ["declare", EPOCH], C(1, "set_volume", 50)])
    add(9, "retries are idempotent: three replays of a relative command apply it once; a changed payload is a conflict",
        ["G02-INV-IDEMPOTENT-RETRY", "G02-INV-AUTHORITY"],
        setup + [C(1, "set_volume", 50), C(2, "adjust_volume", 10), C(2, "adjust_volume", 10), C(2, "adjust_volume", 10),
                 C(2, "adjust_volume", 10), C(2, "adjust_volume", 20), C(3, "adjust_volume", 10)])
    add(10, "saturation and overflow: the ends hold, out-of-range payloads are refused without consuming the revision",
        ["G02-INV-OVERFLOW"],
        setup + [C(1, "set_volume", 95), C(2, "adjust_volume", 20), C(3, "set_volume", 5), C(4, "adjust_volume", -20),
                 C(5, "adjust_volume", 100), C(6, "adjust_volume", -100), C(7, "set_volume", 40),
                 C(8, "adjust_volume", 101), C(8, "adjust_volume", -101), C(8, "adjust_volume", 32767),
                 C(8, "adjust_volume", -32768), C(8, "set_volume", 101), C(8, "set_volume", 255),
                 C(8, "set_trim", 2001), C(8, "set_trim", 65535), C(8, "set_volume", 41)])
    add(11, "trim survives group volume changes until reset; local buttons clamp, refuse extremes and never unmute",
        ["G02-INV-GAIN-COMPOSITION", "G02-INV-OVERFLOW", "G02-INV-MUTE-PRIORITY"],
        setup + [C(1, "set_trim", 600), C(2, "set_volume", 50), C(3, "adjust_volume", 10), C(4, "reset_trim"),
                 ["local_mute", True], ["local_trim", 100], ["local_trim", 500], ["local_trim", 500],
                 ["local_trim", -500], ["local_trim", -500], ["local_trim", -500], ["local_trim", -500],
                 ["local_trim", -500], ["local_trim", 501], ["local_trim", -501], ["local_trim", 32767],
                 ["local_trim", -32768]])
    add(12, "a live member that rejoins a quieter group ramps to silence first and never exceeds the group's volume",
        ["G02-INV-RECONNECT-SILENT", "G02-INV-ATOMIC-RAMP"],
        setup + [C(1, "set_volume", 90), ["sync"], ["ramp", 600], ["reconnect", EPOCH, 5, 20, False], ["sync"],
                 ["ramp", 600], ["join"], ["sync"], ["ramp", 600]],
        board="active")
    add(13, "a restarted member holds a stale loud volume but stays silent until it rejoins, then reaches only the group's volume",
        ["G02-INV-RECONNECT-SILENT"],
        [["sync"], ["ramp", 300], ["reconnect", EPOCH, 1, 20, False], ["join"], ["sync"], ["ramp", 600]],
        board="active", start={"restore": {"volume": 95, "trim": 1000, "local_mute": False}})
    add(14, "a restored local mute survives the restart and the rejoin",
        ["G02-INV-RECONNECT-SILENT", "G02-INV-MUTE-PRIORITY"],
        [["reconnect", EPOCH, 1, 50, False], ["join"], ["sync"], ["ramp", 100]],
        board="active", start={"restore": {"volume": 95, "trim": 1500, "local_mute": True}})
    add(15, "a restored member with no rejoin accepts no command and its stored volume produces no gain",
        ["G02-INV-RECONNECT-SILENT", "G02-INV-AUTHORITY"],
        [C(1, "set_volume", 50), ["join"], ["reconnect", EPOCH, 1, 30, False], ["join"]],
        start={"restore": {"volume": 95, "trim": 2000, "local_mute": False}})
    add(16, "a reconnect snapshot from an older epoch or with an invalid volume changes nothing; a group mute snapshot is honoured",
        ["G02-INV-RECONNECT-SILENT", "G02-INV-AUTHORITY"],
        setup + [C(1, "set_volume", 40), ["reconnect", EPOCH - 1, 5, 20, False], ["reconnect", EPOCH, 5, 101, False],
                 ["reconnect", EPOCH, 5, 20, True], ["join"]])
    add(17, "protection and fault ceilings: the tighter one wins, removing the fault ceiling restores the other, non-finite fails closed",
        ["G02-INV-GAIN-COMPOSITION", "G02-INV-BOUND-BEFORE-RAMP"],
        setup + [C(1, "set_volume", 100), C(2, "set_trim", 1500), ["ceiling", 0.6], ["fault_ceiling", 0.3],
                 ["fault_ceiling", 0.9], ["fault_ceiling", None], ["ceiling", "nan"], ["ceiling", 1.0],
                 ["fault_ceiling", "inf"], ["fault_ceiling", None]])
    add(18, "a board that stops being Active fault-mutes the member and only its return to Active restores the stored volume",
        ["G02-INV-MUTE-PRIORITY"],
        setup + [C(1, "set_volume", 80), ["board", "fail_muted"], C(2, "set_group_mute", False), C(3, "set_volume", 100),
                 ["board", "active"]])
    add(19, "a rejoin keeps the room's own mute and trim while replacing the volume with the group's",
        ["G02-INV-RECONNECT-SILENT", "G02-INV-MUTE-PRIORITY"],
        setup + [C(1, "set_volume", 95), C(2, "set_trim", 800), ["local_mute", True],
                 ["reconnect", EPOCH, 9, 20, False], ["local_mute", False], ["join"]])
    REJOIN = ["G02-INV-REJOIN-KEEPS-OWN"]
    add(20, "a snapshot older than what the member has applied is refused with nothing changed, a retry stays a duplicate, and an equal or newer snapshot is taken",
        REJOIN + ["G02-INV-RECONNECT-SILENT", "G02-INV-AUTHORITY"],
        setup + [C(1, "set_volume", 80), C(2, "set_volume", 30), ["reconnect", EPOCH, 1, 80, False],
                 C(2, "set_volume", 30), C(2, "set_volume", 95), C(3, "set_volume", 35),
                 ["reconnect", EPOCH, 3, 35, False], ["join"], ["reconnect", EPOCH, 9, 60, False], ["join"],
                 ["reconnect", EPOCH, 8, 99, False], C(9, "set_volume", 99), C(10, "set_volume", 45)])
    add(21, "a newer epoch's snapshot is taken at any revision and an older epoch's is refused at any revision",
        REJOIN + ["G02-INV-AUTHORITY"],
        setup + [C(1, "set_volume", 80), C(5, "adjust_volume", -10), ["reconnect", EPOCH + 1, 1, 60, False], ["join"],
                 ["cmd", EPOCH + 1, 2, ["set_volume", 40]], ["reconnect", EPOCH + 1, 1, 90, False],
                 ["reconnect", EPOCH, 99, 90, False], ["cmd", EPOCH + 1, 3, ["set_volume", 41]]])
    add(22, "a rejoin cannot clear a fault mute, the join cannot, a group unmute cannot; the board returning to Active does, and leaves the room's own mute",
        REJOIN + ["G02-INV-MUTE-PRIORITY"],
        setup + [C(1, "set_volume", 80), ["board", "fail_muted"], ["reconnect", EPOCH, 3, 60, False], ["join"],
                 C(4, "set_group_mute", False), ["board", "active"], ["local_mute", True],
                 ["reconnect", EPOCH, 6, 40, False], ["board", "fail_muted"], ["join"], ["board", "active"],
                 ["join"], ["local_mute", False]])
    add(23, "a rejoin keeps the fault ceiling: the ramp fades out, comes back to the ceiling and not the group's volume, and only removing it goes higher",
        REJOIN + ["G02-INV-BOUND-BEFORE-RAMP", "G02-INV-RECONNECT-SILENT"],
        setup + [["fault_ceiling", 0.25], C(1, "set_volume", 100), ["sync"], ["ramp", 600],
                 ["reconnect", EPOCH, 3, 80, False], ["sync"], ["ramp", 600], ["join"], ["sync"], ["ramp", 600],
                 ["fault_ceiling", None], ["sync"], ["ramp", 600]],
        board="active")
    add(24, "a restarted member rejoining on a fail-muted board stays silent and does not arm the stored volume (the same steps as G02-MBR-013 on a board that is not Active)",
        REJOIN + ["G02-INV-RECONNECT-SILENT", "G02-INV-MUTE-PRIORITY"],
        [["sync"], ["ramp", 300], ["reconnect", EPOCH, 1, 20, False], ["join"], ["sync"], ["ramp", 600]],
        board="fail_muted", start={"restore": {"volume": 95, "trim": 1000, "local_mute": False}})
    add(25, "a snapshot that is out of range and also stale is refused as out of range, whichever way it is stale; the same staleness with a valid volume keeps its own name; nothing changes",
        REJOIN + ["G02-INV-AUTHORITY"],
        setup + [C(1, "set_volume", 80), C(2, "set_volume", 30),
                 ["reconnect", EPOCH - 1, 9, 101, False], ["reconnect", EPOCH, 1, 101, False],
                 ["reconnect", EPOCH - 1, 9, 20, False], ["reconnect", EPOCH, 1, 20, False],
                 C(3, "set_volume", 35), ["reconnect", EPOCH, 3, 40, False], ["join"]])
    return out


def group_cases() -> List[dict]:
    inv = ["G02-INV-MISSING-MEMBERS"]
    out: List[dict] = []

    def add(n: int, title: str, invariants: List[str], epoch: int, ops: list) -> None:
        out.append(case(f"G02-GRP-{n:03d}", title, "group_script", invariants, epoch=epoch, ops=ops))

    def G(revision: int, *command: Any, epoch: int = 3) -> list:
        return ["gcmd", epoch, revision, list(command)]

    three = [["add", 1, 1.0], ["add", 2, 1.0], ["add", 3, 1.0], ["join", 1], ["join", 2], ["join", 3]]
    add(1, "an absent member misses commands, rejoins with the group's current volume, and a retry changes nothing",
        inv + ["G02-INV-IDEMPOTENT-RETRY", "G02-INV-RECONNECT-SILENT"], 3,
        three + [G(1, "set_volume", 40), ["present", 2, False], G(2, "set_volume", 80), ["rejoin", 2], ["join", 2],
                 G(3, "adjust_volume", 5), G(3, "adjust_volume", 5), G(2, "set_volume", 5)])
    add(2, "a per-room command is refused at the group level without consuming its revision",
        inv + ["G02-INV-AUTHORITY"], 3,
        three + [G(1, "set_volume", 40), G(2, "set_trim", 500), G(2, "reset_trim"), G(2, "set_volume", 60)])
    add(3, "members validate independently: one told about a newer epoch refuses the old one",
        inv + ["G02-INV-AUTHORITY"], 3,
        three + [["declare_member", 3, 4], G(1, "set_volume", 60)])
    add(4, "unknown and duplicate members are refused by name, and a late member holds the group's current volume",
        inv, 1,
        [["add", 1, 1.0], ["join", 1], G(1, "set_volume", 70, epoch=1), ["add", 1, 0.2], ["present", 9, False],
         ["rejoin", 9], ["join", 9], ["local_mute", 9, True], ["add", 2, 1.0]])
    add(5, "a group mute issued while a member was away reaches it through the rejoin snapshot",
        inv + ["G02-INV-MUTE-PRIORITY"], 1,
        [["add", 1, 1.0], ["join", 1], G(1, "set_volume", 70, epoch=1), ["present", 1, False],
         G(2, "set_group_mute", True, epoch=1), ["rejoin", 1], ["join", 1]])
    add(6, "a group unmute cannot clear a room's own mute",
        inv + ["G02-INV-MUTE-PRIORITY"], 1,
        [["add", 1, 1.0], ["add", 2, 1.0], ["join", 1], ["join", 2], G(1, "set_volume", 50, epoch=1),
         ["local_mute", 1, True], G(2, "set_group_mute", True, epoch=1), G(3, "set_group_mute", False, epoch=1)])
    return out


def build() -> dict:
    cases = gain_cases() + role_cases() + map_cases() + member_cases() + group_cases()
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in cases:
        unknown = set(c["invariants"]) - set(INVARIANTS)
        assert not unknown, f"{c['id']} cites unknown invariants {unknown}"
    return {"schema": SCHEMA, "generator": "tests/g02/generate.py (reference: tests/g02/reference.py)",
            "invariants": INVARIANTS, "external": EXTERNAL, "cases": cases}


def dumps(doc: dict) -> str:
    def j(x: Any) -> str:
        return json.dumps(x, sort_keys=True, separators=(",", ":"))

    head = {k: v for k, v in doc.items() if k != "cases"}
    lines = [j(head)[:-1] + ',"cases":[']
    for i, c in enumerate(doc["cases"]):
        lines.append("  " + j(c) + ("," if i + 1 < len(doc["cases"]) else ""))
    lines.append("]}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    text = dumps(build())
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
