"""A model of the S1 board's two channels under D02's documented per-sample rules, used to check the numeric
PRECONDITIONS of ``crates/franken-speaker/tests/d02_protection_history.rs`` and the two laws it asserts.

Consumer: ``tests/d02/test_d02.py`` (``LoopHistoryModel``). Defect class: a Rust test whose heater builds no state,
whose latch never happens within its tick bound, or whose laws are wrong, so that it passes or fails for the wrong
reason and nobody can run Rust here to find out. Delete it when the central log shows the Rust test's own
preconditions held (they are asserted in the test and fail loudly), or if the Rust test is removed.

What it is: the woofer (2 kHz low-pass) and tweeter (2.2 kHz high-pass) of fixture S1, both fed from ``mid``, per
``synthetic_calibration_for``: DC rejector at 5 Hz, one stored-f32 Butterworth section, gain, leaky-integrator
thermal model, peak limiter. The loop's resampler is taken as identity. What it is not: the Rust (a transcription
error there is invisible here), and not a driver or an amplifier. Numerical tests do not prove physical protection.
"""
from __future__ import annotations

import importlib.util
import math
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RUST = os.path.join(REPO, "crates", "franken-speaker", "tests", "d02_protection_history.rs")


def _load_reference():
    spec = importlib.util.spec_from_file_location("d02_loop_model_reference", os.path.join(HERE, "reference.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load_reference()
FS = ref.FS
RAMP_SAMPLES = 480.0  # unmute ramp: 10 ms at 48 kHz (``ramp_ms`` in the synthetic calibration)
SOURCE_RAMP_SAMPLES = 960.0  # source fade-in: 20 ms (``source_ramp_ms``)
THRESHOLD, ATTACK_MS, RELEASE_MS = 0.8, 1.0, 80.0  # the synthetic limiter


class Channel:
    def __init__(self, kind: str, fc: float, tau_s: float, soft: float, hard: float):
        self.c = ref.stored(ref.butterworth(kind, fc))  # [b0, b1, b2, a1, a2]
        self.r = ref.dc_pole(5.0)
        self.x1 = self.y1 = self.z1 = self.z2 = 0.0
        self.alpha = ref.smoothing(tau_s * 1000.0)
        self.attack, self.release = ref.smoothing(ATTACK_MS), ref.smoothing(RELEASE_MS)
        self.soft, self.hard = soft, hard
        self.level, self.gain = 0.0, 1.0
        self.hard_at: Optional[int] = None

    def step(self, mid: float, user: float, fade: float, n: int) -> None:
        y = mid - self.x1 + self.r * self.y1
        self.x1, self.y1 = mid, y
        b0, b1, b2, a1, a2 = self.c
        out = b0 * y + self.z1
        self.z1 = b1 * y - a1 * out + self.z2
        self.z2 = b2 * y - a2 * out
        v = out * user * fade
        self.level += self.alpha * (v * v - self.level)
        if self.hard_at is None and self.level >= self.hard:
            self.hard_at = n
        if self.level > self.soft:
            v *= math.sqrt(self.soft / self.level)
        a = abs(v)
        target = THRESHOLD / a if a > THRESHOLD and a > 0 else 1.0
        coef = self.attack if target < self.gain else self.release
        self.gain += (target - self.gain) * coef

    def reset_signal_state(self) -> None:
        self.x1 = self.y1 = self.z1 = self.z2 = 0.0


def board(tau_s: float, soft: float, hard: float) -> List[Channel]:
    return [Channel("lp", 2000.0, tau_s, soft, hard), Channel("hp", 2200.0, tau_s, soft, hard)]


def drive(chans: List[Channel], n0: int, frames: int, amplitude: float, tone: bool = True, user=lambda k: 1.0,
          fade=lambda k: 1.0) -> int:
    for k in range(frames):
        n = n0 + k
        mid = amplitude * math.sin(2 * math.pi * (n % 48) / 48.0) if tone else 0.0
        for ch in chans:
            ch.step(mid, user(k), fade(k), n)
    return n0 + frames


def unmute_ramp(k: int) -> float:
    return min(1.0, (k + 1) / RAMP_SAMPLES)


def snap(chans: List[Channel]) -> List[Dict[str, float]]:
    return [{"level": c.level, "gain": c.gain} for c in chans]


def heated(spec: Tuple[float, float, float], amplitude: float, frames: int) -> List[Channel]:
    chans = board(*spec)
    drive(chans, 0, frames, amplitude, user=unmute_ramp)
    return chans


def frames_to_latch(spec: Tuple[float, float, float], amplitude: float, limit: int) -> Optional[int]:
    """The first frame at which any channel's level reaches its hard limit, or None within ``limit`` frames."""
    chans = board(*spec)
    drive(chans, 0, limit, amplitude, user=unmute_ramp)
    hits = [c.hard_at for c in chans if c.hard_at is not None]
    return min(hits) if hits else None


def cooling_blocks(level: float, soft: float, tau_s: float, block: int = 256, limit: int = 1000) -> int:
    """Silent blocks until the level is at or below ``soft``: the level falls by (1 - alpha) per frame."""
    alpha = ref.smoothing(tau_s * 1000.0)
    blocks = 0
    while level > soft and blocks < limit:
        level *= (1.0 - alpha) ** block
        blocks += 1
    return blocks


# ---- the two laws the Rust test asserts ----------------------------------------------------------------------


def law_violations(before: List[Dict[str, float]], after: List[Dict[str, float]], frames: int, tau_s: float,
                   slack: float = 2e-3, thermal_floor: float = 1e-3, limiter_floor: float = 1e-2,
                   release_ms: float = RELEASE_MS) -> List[str]:
    out: List[str] = []
    for i, (b, a) in enumerate(zip(before, after)):
        if b["level"] > thermal_floor:
            floor = b["level"] * math.exp(-frames / (tau_s * FS))
            if a["level"] < floor * (1 - slack):
                out.append(f"channel {i}: thermal level {a['level']:.6f} below {floor:.6f}")
        deficit_before, deficit_after = 1 - b["gain"], 1 - a["gain"]
        if deficit_before > limiter_floor:
            floor = deficit_before * math.exp(-frames / (release_ms * 1e-3 * FS))
            if deficit_after < floor * (1 - slack):
                out.append(f"channel {i}: limiter reduction {deficit_after:.6f} below {floor:.6f}")
    return out


def fresh_board_reading(chans: List[Channel]) -> List[Dict[str, float]]:
    return [{"level": 0.0, "gain": 1.0} for _ in chans]


def run_event(event: str, spec: Tuple[float, float, float], amplitude: float, heat: int):
    """The (before, after, frames, tau_s) of one event, driven the way the Rust test drives the loop."""
    chans = heated(spec, amplitude, heat)
    before, n = snap(chans), heat
    ramp_down = lambda k: max(0.0, 1.0 - (k + 1) / RAMP_SAMPLES)  # noqa: E731
    source_fade = lambda k: min(1.0, (k + 1) / SOURCE_RAMP_SAMPLES)  # noqa: E731
    frames = 0
    if event == "reconnect":
        drive(chans, n, 128, amplitude, fade=source_fade)
        frames = 128
    elif event == "ingress_loss":
        n = drive(chans, n, 192, amplitude, tone=False)
        drive(chans, n, 192, amplitude, fade=source_fade)
        frames = 384
    elif event in ("stop_start", "profile_switch"):
        n = drive(chans, n, 480, amplitude, user=ramp_down)
        if event == "profile_switch":
            for ch in chans:
                ch.reset_signal_state()  # the chain is swapped at silence; history is carried
        drive(chans, n, 128, amplitude, user=unmute_ramp)
        frames = 608
    else:
        raise ValueError(event)
    return before, snap(chans), frames, spec[0]


EVENTS = ("reconnect", "ingress_loss", "stop_start", "profile_switch")


# ---- constants read from the Rust test, so the model follows an edit rather than hiding it ---------------------


def rust_constants(text: Optional[str] = None) -> Dict[str, object]:
    if text is None:
        with open(RUST, encoding="utf-8") as handle:
            text = handle.read()

    def number(name: str, ty: str) -> float:
        match = re.search(rf"const {name}: {ty} = ([0-9_.eE+-]+);", text)
        if not match:
            raise ValueError(f"const {name} not found in the Rust test")
        return float(match.group(1).replace("_", ""))

    def spec(name: str) -> Tuple[float, float, float]:
        match = re.search(rf"const {name}: ThermalSpec = ThermalSpec \{{\s*tau_s: ([0-9.]+),\s*soft_ms: ([0-9.]+),\s*"
                          rf"hard_ms: ([0-9.]+),\s*\}};", text)
        if not match:
            raise ValueError(f"const {name} not found in the Rust test")
        return tuple(float(g) for g in match.groups())  # type: ignore[return-value]

    return {"amplitude": number("AMPLITUDE", "f32"), "heat": int(number("HEAT_FRAMES", "u64")),
            "warm": spec("WARM"), "latching": spec("LATCHING"), "slack": number("SLACK", "f64"),
            "thermal_floor": number("THERMAL_FLOOR", "f64"), "limiter_floor": number("LIMITER_FLOOR", "f64")}
