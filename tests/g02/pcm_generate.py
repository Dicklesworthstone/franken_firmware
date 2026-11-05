"""Deterministic G02 slice 2 vector generator (ffw-ld0). Expected values come only from pcm_reference.py.

Writes tests/g02/pcm_vectors.json (via pcm_run.py --write-vectors). The committed file must equal a
fresh generation; the runner checks that on every run.

A case is a frame-exact schedule: ``[frame, operation...]`` lands before that frame is rendered. The
vector pins the input fingerprint, the operation results and the applied-gain trajectory at
checkpoints; the judge recomputes every frame from the reference at judge time.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("g02pcm_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pr = _load("pcm_reference")
SCHEMA = "ffw.g02.pcm.vectors.v1"
EPOCH = 7

INVARIANTS: Dict[str, str] = {
    "G02PCM-INV-KNOWN-INPUT": "the board is fed the documented LCG stream, proven by a fingerprint of the samples actually fed",
    "G02PCM-INV-FRAME-EXACT-GAIN": "the applied gain at every frame equals the independent model's and never steps",
    "G02PCM-INV-PCM-LINEAR": "at every frame the output of every driver channel equals the unity-gain output scaled by the applied-gain ratio, within the stated quantization bound",
    "G02PCM-INV-EXACT-SILENCE": "while the applied gain is 0 every driver channel is exactly 0",
    "G02PCM-INV-MUTE-IN-FLIGHT": "mute wins over volume commands that land mid-ramp: the gain only falls until the mute is released",
    "G02PCM-INV-RECONNECT-NO-SPIKE": "a reconnect silences the member and the level after the join never exceeds the group's",
    "G02PCM-INV-ROLE-ROUTING": "a Left or Right room plays one channel on every driver pair, Stereo does not, and the role-mapped stream is bit-identical to the pre-mapped one",
    "G02PCM-INV-CEILING": "gain and output stay under the protection and fault ceilings while streaming, and a non-finite ceiling fails closed",
    "G02PCM-INV-LINEAR-REGIME": "the linearity check is only valid below the limiter and thermal models, which the run certifies on both boards",
}


def at(frame: int, *op: Any) -> list:
    return [frame, *op]


def C(frame: int, revision: int, *command: Any) -> list:
    return [frame, "cmd", EPOCH, revision, list(command)]


SETUP = [at(0, "declare", EPOCH), at(0, "join"), C(0, 1, "set_volume", 100)]
ALL = list(INVARIANTS)
PAIRS = [[0, 1], [2, 3]]


def case(case_id: str, title: str, board: str, role: str, frames: int, schedule: list, seeds: tuple,
         invariants: List[str], ceiling: Any = 1.0, pair_expect: Any = None) -> dict:
    body = {"id": case_id, "title": title, "kind": "pcm_script", "invariants": invariants, "board": board,
            "role": role, "frames": frames, "ceiling": ceiling, "seed_left": seeds[0], "seed_right": seeds[1],
            "schedule": SETUP + schedule, "pairs": PAIRS if board == "S5" else [], "pair_expect": pair_expect}
    body["expect"] = pr.expectation(body)
    return body


CORE = ["G02PCM-INV-KNOWN-INPUT", "G02PCM-INV-FRAME-EXACT-GAIN", "G02PCM-INV-PCM-LINEAR", "G02PCM-INV-LINEAR-REGIME"]


def build() -> dict:
    cases = [
        case("G02PCM-001", "volume ramps with retargets that land mid-ramp (down, then up, then down, then up)",
             "S5", "stereo", 3000,
             [C(700, 2, "set_volume", 40), C(900, 3, "set_volume", 90), C(1500, 4, "adjust_volume", -50),
              C(1700, 5, "adjust_volume", 30), C(2300, 6, "set_trim", 500), at(2500, "local_trim", 500)],
             (1, 2), CORE, pair_expect="differ"),
        case("G02PCM-002", "mute wins over volume commands that land mid-fade; unmute, group mute and a brief re-mute ramp from where the output is",
             "S5", "stereo", 3600,
             [C(600, 2, "set_volume", 60), at(700, "local_mute", True), C(760, 3, "set_volume", 100),
              C(900, 4, "adjust_volume", -20), at(1600, "local_mute", False), C(2100, 5, "set_group_mute", True),
              C(2250, 6, "set_volume", 30), C(2800, 7, "set_group_mute", False), at(3100, "local_mute", True),
              at(3110, "local_mute", False)],
             (5, 6), CORE + ["G02PCM-INV-EXACT-SILENCE", "G02PCM-INV-MUTE-IN-FLIGHT"], pair_expect="differ"),
        case("G02PCM-003", "membership churn: reconnects fade the room out, the join brings it back to the group's level only, a group-mute snapshot holds it silent",
             "S5", "stereo", 3600,
             [at(700, "reconnect", EPOCH, 5, 20, False), at(1800, "join"), at(2200, "reconnect", EPOCH, 9, 50, True),
              at(2300, "join"), C(3000, 10, "set_group_mute", False), at(3300, "reconnect", EPOCH, 12, 80, False),
              at(3310, "join")],
             (7, 8), CORE + ["G02PCM-INV-EXACT-SILENCE", "G02PCM-INV-RECONNECT-NO-SPIKE"], pair_expect="differ"),
        case("G02PCM-004", "a Left room plays the left channel on every driver, through volume changes and a local mute",
             "S5", "left", 2400,
             [C(700, 2, "set_volume", 50), at(1200, "local_mute", True), at(1500, "local_mute", False),
              C(1800, 3, "set_volume", 100)],
             (9, 10), CORE + ["G02PCM-INV-ROLE-ROUTING", "G02PCM-INV-EXACT-SILENCE"], pair_expect="equal"),
        case("G02PCM-005", "a Right room plays the right channel on every driver, through the same schedule",
             "S5", "right", 2400,
             [C(700, 2, "set_volume", 50), at(1200, "local_mute", True), at(1500, "local_mute", False),
              C(1800, 3, "set_volume", 100)],
             (11, 12), CORE + ["G02PCM-INV-ROLE-ROUTING", "G02PCM-INV-EXACT-SILENCE"], pair_expect="equal"),
        case("G02PCM-006", "the Sub board takes the sub role: volume, a local mute and a relative step",
             "Sub", "sub", 2400,
             [C(600, 2, "set_volume", 30), at(1000, "local_mute", True), at(1400, "local_mute", False),
              C(1800, 3, "adjust_volume", 40)],
             (13, 14), CORE + ["G02PCM-INV-ROLE-ROUTING", "G02PCM-INV-EXACT-SILENCE"]),
        case("G02PCM-007", "ceilings while streaming: a 2.0x trim is bounded at 0.5, a fault ceiling lowers it, a NaN ceiling fails closed to exact silence",
             "S5", "stereo", 3600,
             [C(0, 2, "set_trim", 2000), at(1200, "fault_ceiling", 0.25), at(1800, "fault_ceiling", None),
              at(2400, "ceiling", "nan"), at(3000, "ceiling", 1.0)],
             (15, 16), CORE + ["G02PCM-INV-CEILING", "G02PCM-INV-EXACT-SILENCE"], ceiling=0.5, pair_expect="differ"),
        case("G02PCM-008", "everything at once: group volume, local buttons, group and local mute, and membership interleaved on one stream",
             "S5", "stereo", 4800,
             [C(600, 2, "set_volume", 70), at(780, "local_trim", -300), C(900, 3, "set_group_mute", True),
              C(1000, 4, "set_volume", 90), C(1300, 5, "set_group_mute", False),
              at(1450, "reconnect", EPOCH, 8, 60, False), at(1500, "local_mute", True), at(1560, "join"),
              at(2100, "local_mute", False), at(2400, "local_trim", 300), C(2600, 9, "adjust_volume", -20),
              C(3000, 10, "set_group_mute", True), at(3200, "local_mute", True), at(3300, "local_trim", 200),
              C(3400, 11, "set_group_mute", False), at(3700, "local_mute", False), at(4000, "reconnect", EPOCH, 14, 100, False), at(4005, "join"),
              C(4300, 15, "set_volume", 50)],
             (17, 18), [i for i in ALL if i != "G02PCM-INV-CEILING"], pair_expect="differ"),
    ]
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in cases:
        unknown = set(c["invariants"]) - set(INVARIANTS)
        assert not unknown, f"{c['id']} cites unknown invariants {unknown}"
        assert all(0 <= op[0] < c["frames"] for op in c["schedule"]), f"{c['id']}: an operation is outside the stream"
    return {"schema": SCHEMA, "generator": "tests/g02/pcm_generate.py (reference: tests/g02/pcm_reference.py)",
            "invariants": INVARIANTS, "cases": cases}


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
