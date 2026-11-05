"""G02 slice 2 reference: known PCM through the driver channels while the controls change.

Reads slice 1's ``reference.py`` (the controls model) without editing it, and adds what slice 2 needs:

* the KNOWN INPUT: two integer LCG streams, exactly reproducible in Python and Rust (every sample is
  ``i16 / 32768 * 0.25``, a dyadic rational, exact in f32), and an FNV-1a 64-bit fingerprint of the
  stream actually fed to the board, so the judge can prove the Rust run used these samples;
* the frame-exact schedule: which control operation lands before which frame, and the applied-gain
  trajectory of the controlled board and of the unity-gain reference board, frame by frame.

It models CONTROLS, not filters. The D02 filters cancel out of the slice 2 oracle (see
docs/contracts/g02-pcm.md): the controlled output must equal the unity-gain output scaled by the
applied-gain ratio, at every frame, whatever the filters do.
"""
from __future__ import annotations

import importlib.util
import os
import struct
import sys
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(path: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load(os.path.join(HERE, "reference.py"), "g02pcm_slice1_reference")

LCG_MUL = 1664525
LCG_ADD = 1013904223
AMPLITUDE = 0.25
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF
CHECKPOINT_STRIDE = 25
CHECKPOINT_HALO = 2

# The two boards the cases use. `sources` is each driver channel's route (D02 synthetic calibration:
# tweeter/mid pairs follow left/right, the woofer and the sub follow the mono mix).
BOARDS: Dict[str, dict] = {
    "S5": {"channels": 5, "sources": ["left", "right", "left", "right", "mid"],
           "names": ["tweeter_left", "tweeter_right", "mid_left", "mid_right", "woofer_center"]},
    "Sub": {"channels": 1, "sources": ["mid"], "names": ["subwoofer_lfe"]},
}


def fnv1a64(data: bytes, state: int = FNV_OFFSET) -> int:
    for byte in data:
        state = ((state ^ byte) * FNV_PRIME) & MASK64
    return state


def lcg_stream(seed: int, count: int, amplitude: float = AMPLITUDE) -> List[float]:
    """``state = state * 1664525 + 1013904223 (mod 2^32)``; the sample is ``(state >> 16)`` as an i16."""
    out: List[float] = []
    state = seed & 0xFFFFFFFF
    for _ in range(count):
        state = (state * LCG_MUL + LCG_ADD) & 0xFFFFFFFF
        raw = state >> 16
        raw = raw - 65536 if raw >= 32768 else raw
        out.append(ref.q32(raw / 32768.0 * amplitude))
    return out


def fed_stream(case: dict) -> List[Tuple[float, float]]:
    """What the board is fed after the role remap, frame by frame."""
    left = lcg_stream(case["seed_left"], case["frames"])
    right = lcg_stream(case["seed_right"], case["frames"])
    return [ref.role_map(case["role"], l, r) for l, r in zip(left, right)]


def input_fnv(case: dict) -> str:
    state = FNV_OFFSET
    for l, r in fed_stream(case):
        state = fnv1a64(struct.pack("<ff", l, r), state)
    return f"{state:016x}"


def apply_op(member: Any, op: list) -> str:
    """One scheduled control operation on the member; returns its result code."""
    name, args = op[0], op[1:]
    if name == "declare":
        return member.declare(args[0])
    if name == "join":
        member.complete_join()
    elif name == "cmd":
        return member.apply(args[0], args[1], tuple(args[2]))[0]
    elif name == "local_mute":
        member.local_mute(args[0])
    elif name == "local_trim":
        return member.local_trim(args[0])
    elif name == "ceiling":
        member.set_protection_ceiling(args[0])
    elif name == "fault_ceiling":
        member.set_fault_ceiling(args[0])
    elif name == "reconnect":
        return member.reconnect(*args)
    else:
        raise ValueError(f"unknown scheduled operation {name}")
    return "ok"


def schedule_by_frame(case: dict) -> Dict[int, List[list]]:
    by_frame: Dict[int, List[list]] = {}
    for frame, *op in case["schedule"]:
        by_frame.setdefault(frame, []).append(op)
    return by_frame


def simulate(case: dict, bugs: FrozenSet[str] = frozenset()) -> Dict[str, Any]:
    """Per-frame applied gain of the controlled board (B) and the unity reference board (A)."""
    member = ref.Member(case["ceiling"], bugs)
    board_b = ref.Dsp(True, bugs)
    board_a = ref.Dsp(True, frozenset())
    board_a.set_user_gain(1.0)
    board_a.set_muted(False)
    by_frame = schedule_by_frame(case)
    results: List[list] = []
    gain_a: List[float] = []
    gain_b: List[float] = []
    for frame in range(case["frames"]):
        ops = by_frame.get(frame, [])
        for op in ops:
            results.append([frame, op[0], apply_op(member, op), member.mute()])
        if ops:
            member.sync(board_b)
        gain_b.append(board_b.frame())
        gain_a.append(board_a.frame())
    return {"results": results, "gain_a": gain_a, "gain_b": gain_b}


def checkpoint_frames(case: dict) -> List[int]:
    """Every STRIDE-th frame and a halo around each operation, so a vector pins the trajectory where it bends."""
    frames = set(range(0, case["frames"], CHECKPOINT_STRIDE)) | {case["frames"] - 1}
    for frame, *_ in case["schedule"]:
        frames |= {f for f in range(frame - CHECKPOINT_HALO, frame + CHECKPOINT_HALO + 1) if 0 <= f < case["frames"]}
    return sorted(frames)


def expectation(case: dict) -> Dict[str, Any]:
    sim = simulate(case)
    return {
        "input_fnv": input_fnv(case),
        "results": sim["results"],
        "checkpoints": [[f, sim["gain_a"][f], sim["gain_b"][f]] for f in checkpoint_frames(case)],
        "silent_frames": sum(1 for g in sim["gain_b"] if g == 0.0),
    }
