"""Independent reference for D02 (ffw-7s0): board protection DSP.

Written from docs/contracts/d02.md with the standard library only. It shares no code with the Rust
implementation: filters run in f64 direct form I on the f32-STORED coefficients (the Rust
realization is f64 direct form II transposed on those same stored coefficients, so the two differ
only by the final rounding of the output to f32), the limiter and thermal responses are closed
forms, and the calibration validator is a separate implementation of the same rules, in the same
order.

NUMERICAL TESTS DO NOT PROVE PHYSICAL PROTECTION. Everything here is synthetic.
"""
from __future__ import annotations

import copy
import math
import struct
from typing import Dict, List, Optional, Tuple

FS = 48_000.0
SCHEMA = "ffw.d02.calibration.v1"
MAX_SECTIONS = 4
MAX_COEFF = 8.0
STABILITY_MARGIN = 1.0e-6
MAX_L1_GAIN = 8.0
MAX_INTERMEDIATE = 16.0
L1_HORIZON = 8192
GUARD_MAX = 0.1
GUARDS: Dict[str, Optional[Tuple[float, float]]] = {
    "tweeter_left": (500.0, GUARD_MAX), "tweeter_right": (500.0, GUARD_MAX), "tweeter_mono": (500.0, GUARD_MAX),
    "woofer_center": (8000.0, GUARD_MAX), "woofer_mono": (8000.0, GUARD_MAX), "subwoofer_lfe": (2000.0, GUARD_MAX),
    "mid_left": None, "mid_right": None,
}
# Channel roles of the synthetic fixture boards, as the board-profile crate defines them. The Rust
# harness checks these against the real fixture catalog, so drift is caught there.
FIXTURE_ROLES: Dict[str, List[str]] = {
    "S5": ["tweeter_left", "tweeter_right", "mid_left", "mid_right", "woofer_center"],
    "S3": ["mid_left", "mid_right", "tweeter_mono"],
    "S1": ["woofer_mono", "tweeter_mono"],
    "Sub": ["subwoofer_lfe"],
}


class RefError(Exception):
    def __init__(self, code: str, channel: Optional[int] = None, section: Optional[int] = None,
                 parameter: Optional[str] = None):
        super().__init__(code)
        self.code, self.channel, self.section, self.parameter = code, channel, section, parameter

    def as_dict(self) -> dict:
        return {"error": self.code, "channel": self.channel, "section": self.section, "parameter": self.parameter}


def q32(x: float) -> float:
    """Round to the nearest f32 (raises OverflowError past f32 range)."""
    return struct.unpack(">f", struct.pack(">f", x))[0]


def smoothing(time_ms: float) -> float:
    samples = time_ms * 1e-3 * FS
    if not (math.isfinite(samples) and samples > 0):
        return 1.0
    return 1.0 - math.exp(-1.0 / samples)


# ---- designs ------------------------------------------------------------------------------------


def butterworth(kind: str, fc: float, fs: float = FS) -> Dict[str, float]:
    k = math.tan(math.pi * fc / fs)
    norm = 1.0 / (1.0 + math.sqrt(2.0) * k + k * k)
    a1, a2 = 2.0 * (k * k - 1.0) * norm, (1.0 - math.sqrt(2.0) * k + k * k) * norm
    if kind == "lp":
        b0 = k * k * norm
        return {"b0": b0, "b1": 2.0 * b0, "b2": b0, "a1": a1, "a2": a2}
    return {"b0": norm, "b1": -2.0 * norm, "b2": norm, "a1": a1, "a2": a2}


def peaking(fc: float, gain_db: float, q: float, fs: float = FS) -> Dict[str, float]:
    """RBJ peaking equaliser (a boost at ``fc``); used to build cascades whose middle node is large."""
    a = 10.0 ** (gain_db / 40.0)
    w0 = 2.0 * math.pi * fc / fs
    alpha = math.sin(w0) / (2.0 * q)
    a0 = 1.0 + alpha / a
    return {"b0": (1.0 + alpha * a) / a0, "b1": -2.0 * math.cos(w0) / a0, "b2": (1.0 - alpha * a) / a0,
            "a1": -2.0 * math.cos(w0) / a0, "a2": (1.0 - alpha / a) / a0}


def gain_section(gain: float) -> Dict[str, float]:
    return {"b0": gain, "b1": 0.0, "b2": 0.0, "a1": 0.0, "a2": 0.0}


def coeffs(spec: dict) -> List[float]:
    return [spec["b0"], spec["b1"], spec["b2"], spec["a1"], spec["a2"]]


# ---- filter responses (f64, direct form I) ---------------------------------------------------------


def df1(c: List[float], xs: List[float]) -> List[float]:
    x1 = x2 = y1 = y2 = 0.0
    out = []
    for x in xs:
        y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2
        out.append(y)
        x2, x1, y2, y1 = x1, x, y1, y
    return out


def stored(spec: dict) -> List[float]:
    """The f32-stored coefficients the Rust section holds (it widens them to f64 for arithmetic)."""
    return [q32(v) for v in coeffs(spec)]


def dc_response(hz: float, x: float, n: int) -> List[float]:
    """Closed form for a constant input: y[n] = x * R^n with R = exp(-2*pi*f/fs)."""
    r = math.exp(-2.0 * math.pi * hz / FS)
    return [x * r ** i for i in range(n)]


def limiter_response(threshold: float, attack_ms: float, release_ms: float,
                     segments: List[Tuple[float, int]]) -> Tuple[List[float], List[float]]:
    """(gain trace, output trace). Per sample: target = thr/|v| above the threshold else 1;
    gain moves toward target by the attack coefficient when falling, the release one otherwise."""
    a_att, a_rel = smoothing(attack_ms), smoothing(release_ms)
    gain, gains, outs = 1.0, [], []
    for value, count in segments:
        for _ in range(count):
            a = abs(value)
            target = threshold / a if a > threshold and a > 0 else 1.0
            gain += (target - gain) * (a_att if target < gain else a_rel)
            gains.append(gain)
            outs.append(value * gain)
    return gains, outs


# ---- calibration validation (a second implementation of the contract's rules) -----------------------


def quantize_section(spec: dict, channel: int, section: int) -> List[float]:
    bad = RefError("coefficient_invalid", channel, section)
    out = []
    for v in coeffs(spec):
        if not math.isfinite(v):
            raise bad
        try:
            f = q32(v)
        except OverflowError:
            raise bad
        if not math.isfinite(f) or abs(f) > MAX_COEFF:
            raise bad
        out.append(f)
    a1, a2 = out[3], out[4]
    if not (1 + a1 + a2 > STABILITY_MARGIN and 1 - a1 + a2 > STABILITY_MARGIN and 1 - a2 > STABILITY_MARGIN):
        raise RefError("unstable", channel, section)
    return out


CONVERGED_TAIL = 1.0e-6
# Relative margin on the exact bound. It covers the f32 rounding of the DC rejector (measured at under
# 2e-7 of the exact value, tests/d02/realized_chain.py) by a factor of tens of thousands.
BOUND_MARGIN = 0.01
DC_L1 = 2.0


def dc_pole(hz: float) -> float:
    """The DC rejector pole as the renderer stores it (f32)."""
    return q32(math.exp(-2.0 * math.pi * hz / FS))


def section_l1(c: List[float]) -> Tuple[float, float]:
    """L1 norm of one section's unit-impulse response over the horizon (direct form I, f64), and the
    peak of that response over the last 256 samples of the horizon."""
    x1 = x2 = y1 = y2 = 0.0
    total, tail = 0.0, 0.0
    for n in range(L1_HORIZON):
        x = 1.0 if n == 0 else 0.0
        y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2
        total += abs(y)
        if n >= L1_HORIZON - 256:
            tail = max(tail, abs(y))
        x2, x1, y2, y1 = x1, x, y1, y
    return total, tail


def pole_radius(c: List[float]) -> float:
    """Radius of the slowest pole of 1 + a1 z^-1 + a2 z^-2."""
    a1, a2 = c[3], c[4]
    disc = a1 * a1 - 4.0 * a2
    return math.sqrt(a2) if disc < 0.0 else (abs(a1) + math.sqrt(disc)) / 2.0


def product_bounds(sections: List[List[float]]) -> dict:
    """The original rigorous but loose bound: the L1 norms of the sections multiply (submultiplicativity),
    starting from the DC rejector's L1 of 2, and each state is bounded term by term."""
    x_bound = DC_L1
    stages, converged, tail_peak, rho = [], True, 0.0, 0.0
    for c in sections:
        l1, tail = section_l1(c)
        converged = converged and tail <= CONVERGED_TAIL
        tail_peak, rho = max(tail_peak, tail), max(rho, pole_radius(c))
        y = l1 * x_bound
        z2 = abs(c[2]) * x_bound + abs(c[4]) * y
        z1 = abs(c[1]) * x_bound + abs(c[3]) * y + z2
        stages.append((y, z1, z2))
        x_bound = y
    return {"stages": stages, "converged": converged, "tail_peak": tail_peak, "rho": rho}


FAULTS = ("signed_sum", "no_states", "dc_l1_one", "no_dc_remainder", "no_tail", "no_margin",
          "worst_from_last_stage", "no_product_cap")


def chain_bounds(dc_r: float, sections: List[List[float]], fault: Optional[str] = None) -> dict:
    """Bounds on the DC rejector and every section (output ``y`` and the two states ``z1``, ``z2``) for
    ``|input| <= 1``, as the Rust ``chain_bounds`` computes them:

        bound = min(product bound, (exact L1 over the horizon + allowance) * (1 + BOUND_MARGIN))
        allowance = (product bound / 2) * (R^(H-1) + tail_peak * max(H, 1 / (1 - rho)))

    The exact L1 norm of the impulse response from the chain input to a quantity is the largest value
    that quantity can reach for ``|input| <= 1`` (the input that attains it is the sign of the
    time-reversed response). ``R^(H-1)`` is the L1 norm of the DC rejector's response past the horizon,
    which a following cascade can amplify by at most its product bound; the tail term covers the sections'
    own responses past the horizon under the same convergence rule as before. ``fault`` is a test hook that
    plants one defect (``FAULTS``); production passes ``None``."""
    prod = product_bounds(sections)
    if fault == "dc_l1_one":
        x_bound, shrunk = 1.0, []
        for c in sections:
            l1, _ = section_l1(c)
            y = l1 * x_bound
            z2 = abs(c[2]) * x_bound + abs(c[4]) * y
            shrunk.append((y, abs(c[1]) * x_bound + abs(c[3]) * y + z2, z2))
            x_bound = y
        prod["stages"] = shrunk
    n = L1_HORIZON
    signal = [0.0] * n
    signal[0] = 1.0
    signal[1] = dc_r - 1.0
    for i in range(2, n):
        signal[i] = dc_r * signal[i - 1]
    dc_remainder = dc_r ** (n - 1)
    tail_peak, rho = prod["tail_peak"], prod["rho"]
    tail_factor = max(float(n), 1.0 / max(1.0 - rho, 1.0e-12))
    exact, final = [], []
    for c, p in zip(sections, prod["stages"]):
        z1 = z2 = 0.0
        out = [0.0] * n
        sums = [0.0, 0.0, 0.0]
        for i, x in enumerate(signal):
            y = c[0] * x + z1
            z1 = c[1] * x - c[3] * y + z2
            z2 = c[2] * x - c[4] * y
            out[i] = y
            if fault == "signed_sum":
                sums[0] += y
                sums[1] += z1
                sums[2] += z2
            else:
                sums[0] += abs(y)
                sums[1] += abs(z1)
                sums[2] += abs(z2)
        signal = out
        exact.append(tuple(sums))
        bound = []
        for k, (p_q, e_q) in enumerate(zip(p, sums)):
            rem = 0.0 if fault == "no_dc_remainder" else dc_remainder
            tail = 0.0 if fault == "no_tail" else tail_peak * tail_factor
            margin = 0.0 if fault == "no_margin" else BOUND_MARGIN
            value = (e_q + (p_q / DC_L1) * (rem + tail)) * (1.0 + margin)
            if fault != "no_product_cap":
                value = min(p_q, value)
            if fault == "no_states" and k > 0:
                value = 0.0
            bound.append(value)
        final.append(tuple(bound))
    gain = final[-1][0] if final else DC_L1
    scan = final[-1:] if fault == "worst_from_last_stage" else final
    worst = max([DC_L1] + [v for stage in scan for v in stage])
    return {"gain": gain, "worst": worst, "converged": prod["converged"], "stages": final,
            "product": prod["stages"], "exact": exact, "dc_remainder": dc_remainder,
            "tail_peak": tail_peak, "tail_factor": tail_factor}


def magnitude(sections: List[List[float]], hz: float) -> float:
    w = 2.0 * math.pi * hz / FS
    m = 1.0
    for c in sections:
        br = c[0] + c[1] * math.cos(w) + c[2] * math.cos(2 * w)
        bi = -(c[1] * math.sin(w) + c[2] * math.sin(2 * w))
        ar = 1 + c[3] * math.cos(w) + c[4] * math.cos(2 * w)
        ai = -(c[3] * math.sin(w) + c[4] * math.sin(2 * w))
        m *= math.sqrt((br * br + bi * bi) / (ar * ar + ai * ai))
    return m


def _rng(v, lo, hi) -> bool:
    return isinstance(v, (int, float)) and math.isfinite(v) and lo <= v <= hi


def validate_calibration(cal: dict, fixture: str) -> None:
    """Host-simulation validation (the profile gate and binding are exercised by Rust unit tests).
    Raises RefError with the first problem in the contract's fixed order."""
    roles = FIXTURE_ROLES[fixture]
    if cal["schema"] != SCHEMA:
        raise RefError("schema_mismatch")
    if cal["provenance"]["kind"] != "synthetic":
        raise RefError("provenance_refused")
    if cal["sample_rate_hz"] != 48000:
        raise RefError("invalid_parameter", None, None, "sample_rate")
    if not _rng(cal["ramp_ms"], 1.0, 1000.0):
        raise RefError("invalid_parameter", None, None, "ramp")
    if not _rng(cal["fault_ramp_ms"], 0.1, 100.0):
        raise RefError("invalid_parameter", None, None, "fault_ramp")
    if not _rng(cal["source_ramp_ms"], 1.0, 1000.0):
        raise RefError("invalid_parameter", None, None, "source_ramp")
    if len(cal["channels"]) != len(roles):
        raise RefError("channel_count_mismatch")
    for i, (ch, role) in enumerate(zip(cal["channels"], roles)):
        if ch["role"] != role:
            raise RefError("role_mismatch", i)
    for i, ch in enumerate(cal["channels"]):
        def bad(p):
            return RefError("invalid_parameter", i, None, p)
        if not _rng(ch["trim"], 0.01, 4.0):
            raise bad("trim")
        if not _rng(ch["max_gain"], 0.01, 4.0):
            raise bad("max_gain")
        if not _rng(ch["ceiling"], 0.01, 1.0):
            raise bad("ceiling")
        if not _rng(ch["dc_block_hz"], 1.0, 100.0):
            raise bad("dc_block_hz")
        lim, th = ch["limiter"], ch["thermal"]
        if not _rng(lim["threshold"], 0.01, ch["ceiling"]):
            raise bad("limiter_threshold")
        if not _rng(lim["attack_ms"], 0.05, 100.0):
            raise bad("limiter_attack")
        if not _rng(lim["release_ms"], 1.0, 5000.0):
            raise bad("limiter_release")
        if not _rng(th["tau_s"], 0.05, 600.0):
            raise bad("thermal_tau")
        if not _rng(th["soft_ms"], 0.001, 1.0):
            raise bad("thermal_soft")
        if not (_rng(th["hard_ms"], 0.001, 4.0) and th["hard_ms"] > th["soft_ms"]):
            raise bad("thermal_hard")
        if len(ch["sections"]) > MAX_SECTIONS:
            raise RefError("too_many_sections", i)
        secs = [quantize_section(s, i, j) for j, s in enumerate(ch["sections"])]
        bounds = chain_bounds(dc_pole(ch["dc_block_hz"]), secs)
        if not bounds["converged"] or bounds["gain"] > MAX_L1_GAIN:
            raise RefError("gain_bound_exceeded", i)
        if bounds["worst"] > MAX_INTERMEDIATE:
            raise RefError("intermediate_range_exceeded", i)
        guard = GUARDS.get(ch["role"])
        if guard is not None and magnitude(secs, guard[0]) > guard[1]:
            raise RefError("band_policy_violated", i)


# ---- synthetic calibrations ---------------------------------------------------------------------------


def synthetic_calibration(fixture: str) -> dict:
    """A SYNTHETIC calibration with placeholder profile binding ("@profile_id"/"@profile_digest",
    substituted by the Rust harness from the fixture catalog)."""
    def hp(fc):
        return butterworth("hp", fc)

    def lp(fc):
        return butterworth("lp", fc)
    design = {"tweeter_left": ("left", [hp(2200)]), "tweeter_right": ("right", [hp(2200)]),
              "tweeter_mono": ("mid", [hp(2200)]), "mid_left": ("left", []), "mid_right": ("right", []),
              "woofer_center": ("mid", [lp(300)]), "woofer_mono": ("mid", [lp(2000)]),
              "subwoofer_lfe": ("mid", [lp(120)])}
    channels = []
    for role in FIXTURE_ROLES[fixture]:
        source, sections = design[role]
        channels.append({
            "role": role, "source": source, "trim": 1.0, "max_gain": 1.0, "ceiling": 0.95, "dc_block_hz": 5.0,
            "sections": copy.deepcopy(sections),
            "limiter": {"threshold": 0.8, "attack_ms": 1.0, "release_ms": 80.0},
            "thermal": {"tau_s": 2.0, "soft_ms": 0.30, "hard_ms": 0.90},
        })
    return {"schema": SCHEMA, "profile_id": "@profile_id", "profile_digest": "@profile_digest",
            "provenance": {"kind": "synthetic", "reference": "synthetic-fixture:d02-v1", "acoustic_qualification": None},
            "sample_rate_hz": 48000, "ramp_ms": 10.0, "fault_ramp_ms": 2.0, "source_ramp_ms": 20.0,
            "channels": channels}


# ---- closed forms used by the scenario judge -----------------------------------------------------------


def nyquist_drive_level(amplitude: float, dc_block_hz: float = 5.0) -> float:
    """Steady-state |v| of a +-a Nyquist square after DC rejection (gain 1): 2a / (1 + R)."""
    r = math.exp(-2.0 * math.pi * dc_block_hz / FS)
    return amplitude * 2.0 / (1.0 + r)


def thermal_after(level0: float, v: float, tau_s: float, samples: int) -> float:
    """Leaky mean-square level after `samples` of constant |v| starting from `level0`."""
    keep = (1.0 - smoothing(tau_s * 1000.0)) ** samples
    return v * v * (1.0 - keep) + level0 * keep


def samples_to_reach(level_target: float, v: float, tau_s: float) -> float:
    """Samples of constant |v| from zero until the thermal level reaches `level_target`."""
    return math.log(1.0 - level_target / (v * v)) / math.log(1.0 - smoothing(tau_s * 1000.0))
