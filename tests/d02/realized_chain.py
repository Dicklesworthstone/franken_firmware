"""Realized-chain check for D02's admitted intermediate bound.

The bound the validator computes (``reference.chain_bounds``, mirrored by ``calibration.rs``) says how large the
DC rejector, every section output and both direct-form-II-transposed states can get for ``|input| <= 1``. This
module measures the same thing: it drives an operation-for-operation emulation of the Rust renderer (``DcRejector``
in f32, ``Section`` with f64 state and an f32 output) with the input that maximises one chosen quantity, namely
the sign of the time-reversed impulse response from the chain input to that quantity (computed independently in
direct form I from the stored coefficients), and records the largest value the real chain reaches.

``python3 -B -I tests/d02/realized_chain.py`` prints the evidence table cited in docs/contracts/d02.md.
Synthetic designs only; numerical tests do not prove physical protection.
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import reference as ref  # noqa: E402

QUANTITIES = ("y", "z1", "z2")


def f32(x: float) -> float:
    return struct.unpack("<f", struct.pack("<f", x))[0]


def exact_responses(dc_r: float, secs: List[List[float]], n: int) -> List[Dict[str, List[float]]]:
    """Independent f64 impulse responses from the chain input to each section's ``y``, ``z1`` and ``z2``.

    Direct form I gives ``y``; the DF2T states follow from the identities
    ``z2[n] = b2 x[n] - a2 y[n]`` and ``z1[n] = b1 x[n] - a1 y[n] + z2[n-1]``."""
    signal = [0.0] * n
    signal[0] = 1.0
    signal[1] = dc_r - 1.0
    for i in range(2, n):
        signal[i] = dc_r * signal[i - 1]
    out = []
    for c in secs:
        x1 = x2 = y1 = y2 = 0.0
        ys, z1s, z2s = [0.0] * n, [0.0] * n, [0.0] * n
        for i, x in enumerate(signal):
            y = c[0] * x + c[1] * x1 + c[2] * x2 - c[3] * y1 - c[4] * y2
            ys[i] = y
            z2s[i] = c[2] * x - c[4] * y
            z1s[i] = c[1] * x - c[3] * y + (z2s[i - 1] if i else 0.0)
            x2, x1, y2, y1 = x1, x, y1, y
        out.append({"y": ys, "z1": z1s, "z2": z2s})
        signal = ys
    return out


def adversarial(response: List[float]) -> List[float]:
    """The input in [-1, 1] that makes the last output equal the L1 norm of ``response``."""
    n = len(response)
    return [1.0 if response[n - 1 - i] >= 0.0 else -1.0 for i in range(n)]


def realize(dc_r: float, secs: List[List[float]], xs: List[float]) -> List[Dict[str, float]]:
    """Largest ``|y|`` (the f32 section output), ``|z1|`` and ``|z2|`` per section over the run."""
    x_prev = y_prev = 0.0
    state = [[0.0, 0.0] for _ in secs]
    peaks = [{"y": 0.0, "z1": 0.0, "z2": 0.0} for _ in secs]
    for x in xs:
        v = f32(f32(x - x_prev) + f32(dc_r * y_prev))  # DcRejector::process, f32 throughout
        x_prev, y_prev = x, v
        for k, c in enumerate(secs):
            y = c[0] * v + state[k][0]
            z1 = c[1] * v - c[3] * y + state[k][1]
            z2 = c[2] * v - c[4] * y
            state[k] = [z1, z2]
            v = f32(y)
            p = peaks[k]
            p["y"], p["z1"], p["z2"] = max(p["y"], abs(v)), max(p["z1"], abs(z1)), max(p["z2"], abs(z2))
    return peaks


# name, DC corner (Hz), sections. The first six are the D02-DESIGN cases; HP60 at a 1 Hz corner is the long tail:
# the DC rejector has not settled by the end of the 8192-sample horizon (R^8191 = 0.34).
DESIGNS: List[Tuple[str, float, List[dict]]] = [
    ("LP120", 5.0, [ref.butterworth("lp", 120)]),
    ("LP300", 5.0, [ref.butterworth("lp", 300)]),
    ("LP2000", 5.0, [ref.butterworth("lp", 2000)]),
    ("HP2200", 5.0, [ref.butterworth("hp", 2200)]),
    ("HP3000", 5.0, [ref.butterworth("hp", 3000)]),
    ("HP100", 5.0, [ref.butterworth("hp", 100)]),
    ("HP60", 5.0, [ref.butterworth("hp", 60)]),
    ("HP20", 5.0, [ref.butterworth("hp", 20)]),
    ("LR4 LP1000", 5.0, [ref.butterworth("lp", 1000)] * 2),
    ("HP60 + LP2000", 5.0, [ref.butterworth("hp", 60), ref.butterworth("lp", 2000)]),
    ("boost +20 dB then trim", 5.0, [ref.peaking(1000.0, 20.0, 1.0), ref.gain_section(0.25)]),
    ("gain 3", 5.0, [ref.gain_section(3.0)]),
    ("HP60, 1 Hz DC corner", 1.0, [ref.butterworth("hp", 60)]),
    ("LP120, 1 Hz DC corner", 1.0, [ref.butterworth("lp", 120)]),
]
# The refused counterpart of the boost design: +24 dB at 500 Hz, Q 2, then a 0.15 trim.
REFUSED_BOOST: List[dict] = [ref.peaking(500.0, 24.0, 2.0), ref.gain_section(0.15)]


def measure(specs: List[dict], dc_hz: float, run: int, fault: Optional[str] = None) -> List[dict]:
    """One row per (section, quantity): the bounds, the exact L1 over the run, and the realized peak."""
    secs = [ref.quantize_section(s, 0, k) for k, s in enumerate(specs)]
    dc_r = ref.dc_pole(dc_hz)
    bounds = ref.chain_bounds(dc_r, secs, fault)
    exact = exact_responses(dc_r, secs, run)
    rows = []
    for k in range(len(secs)):
        for qi, q in enumerate(QUANTITIES):
            h = exact[k][q]
            peak = realize(dc_r, secs, adversarial(h))[k][q]
            rows.append({"stage": k, "q": q, "product": bounds["product"][k][qi], "bound": bounds["stages"][k][qi],
                         "exact_horizon": bounds["exact"][k][qi], "exact_run": sum(abs(v) for v in h), "realized": peak})
    return rows


def main() -> int:
    run = int(sys.argv[1]) if len(sys.argv) > 1 else 4 * ref.L1_HORIZON
    print("run length %d samples, horizon %d. Peaks are the largest value each quantity reaches under its own worst-case input." % (run, ref.L1_HORIZON))
    print("%-24s %5s %3s | %9s | %8s | %9s %9s %10s | %9s | %s" % (
        "design", "stage", "q", "product", "bound", "exact(H)", "exact(run)", "past H", "realized", "spare"))
    f32_effect, thinnest = 0.0, (float("inf"), "")
    for name, dc_hz, specs in DESIGNS:
        for row in measure(specs, dc_hz, run):
            spare = "n/a" if row["realized"] == 0.0 else "%.2f%%" % (100.0 * (row["bound"] / row["realized"] - 1.0))
            print("%-24s %5d %3s | %9.3f | %8.3f | %9.4f %9.4f %10.2e | %9.4f | %s" % (
                name, row["stage"], row["q"], row["product"], row["bound"], row["exact_horizon"], row["exact_run"],
                row["exact_run"] - row["exact_horizon"], row["realized"], spare))
            if row["exact_run"] > 0.0:
                f32_effect = max(f32_effect, abs(row["realized"] - row["exact_run"]) / row["exact_run"])
            if row["bound"] < row["product"] - 1e-9 and row["realized"] > 0.0:
                thinnest = min(thinnest, (row["bound"] / row["realized"] - 1.0, "%s stage %d %s" % (name, row["stage"], row["q"])))
    print("largest |realized - exact(run)| / exact(run), the effect of f32 rounding: %.2e" % f32_effect)
    print("thinnest spare where the exact path is active: %.2f%% (%s)" % (100.0 * thinnest[0], thinnest[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
