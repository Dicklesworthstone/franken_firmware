#!/usr/bin/env python3
"""D03 anchors: the reference's closed forms agree with a naive step-by-step simulation, and a few
numbers are checked against hand arithmetic.  A reference that disagrees with itself cannot judge
the Rust.  Run by tests/d03/run_cases.py as the META tier; also usable alone:

    python3 -B -I tests/d03/anchors.py
"""
from __future__ import annotations

import importlib.util
import math
import os
import sys
from typing import List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))


def _ref():
    spec = importlib.util.spec_from_file_location("d03_reference", os.path.join(HERE, "reference.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _ref()
Q32 = ref.Q32


def simulate_pulls(n_out: int, ratios: List[int]) -> int:
    """Naive model of the pull-driven accumulator: ratios[i] is the ppb used by output i."""
    pending, frac, pulled = ref.PRIME, 0, 0
    for i in range(n_out):
        pulled += pending
        pending = 0
        total = frac + ref.step_q32(ratios[i])
        pending, frac = total >> 32, total & (Q32 - 1)
    return pulled


def simulate_outputs(n_in: int, ppb: int) -> int:
    """Outputs produced before the source of ``n_in`` frames runs dry (lazy pulls, as the render loop)."""
    pending, frac, pulled, out = ref.PRIME, 0, 0, 0
    while True:
        if pulled + pending > n_in:
            return out
        pulled += pending
        pending = 0
        out += 1
        total = frac + ref.step_q32(ppb)
        pending, frac = total >> 32, total & (Q32 - 1)


def schedule_ratios(n_out: int, start: int, target: int, slew: int) -> List[int]:
    sched = ref.ratio_schedule(start, target, slew, n_out // ref.UPDATE_QUANTUM + 2)
    return [sched[i // ref.UPDATE_QUANTUM] for i in range(n_out)]


def _generate():
    spec = importlib.util.spec_from_file_location("d03_generate_for_anchors", os.path.join(HERE, "generate.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ideal_tone_deviation_hz(tone: dict, hann: bool) -> float:
    """The Rust test's frequency measurement (half-vs-half phase slope, optionally Hann-weighted) applied to
    an IDEAL tone sampled at the exact output positions: no resampler, no float32.  A perfect implementation
    reads this value, so the vector tolerance must be at least this large (unweighted) or this method must
    be near zero (weighted)."""
    rate = ref.SAMPLE_RATE_HZ
    n_out, skip = tone["n_out"], tone["skip_ramp_frames"]
    s = tone["step_q32"] / Q32
    w = 2 * math.pi * tone["f0_hz"] / rate
    w_exp = 2 * math.pi * tone["expect_out_hz"] / rate
    half = (n_out - skip) // 2

    def demod(a: int, b: int) -> float:
        re = im = 0.0
        for i in range(a, b):
            g = 0.5 * (1 - math.cos(2 * math.pi * (i - a + 0.5) / (b - a))) if hann else 1.0
            y = 0.5 * math.sin(w * (i * s) + 0.25)
            re += g * y * math.cos(w_exp * i)
            im -= g * y * math.sin(w_exp * i)
        return math.atan2(im, re)

    d = demod(skip + half, skip + 2 * half) - demod(skip, skip + half)
    while d > math.pi:
        d -= 2 * math.pi
    while d <= -math.pi:
        d += 2 * math.pi
    return d / (2 * math.pi * half) * rate


def check() -> List[Tuple[str, bool, str]]:
    out: List[Tuple[str, bool, str]] = []

    def ok(name: str, cond: bool, detail: str = "") -> None:
        out.append((name, bool(cond), detail))

    # hand arithmetic
    ok("unity step is exactly 2^32", ref.step_q32(0) == Q32)
    ok("+500 ppm step", ref.step_q32(500_000) == Q32 + (500_000 * Q32) // 10**9)
    ok("negative ppb truncates toward zero", ref.step_q32(-1) == Q32 - 4, str(ref.step_q32(-1) - Q32))
    ok("unity: N inputs give N-2 outputs", all(ref.outputs_from_inputs(n, Q32) == n - 2 for n in range(3, 300)))
    ok("unity: n outputs pull n+2 inputs", all(ref.inputs_pulled(n, Q32) == n + 2 for n in range(1, 300)))
    ok("fewer than three inputs give no output", all(ref.outputs_from_inputs(n, Q32) == 0 for n in range(0, 3)))
    ok("slew per quantum is 250 ppb at 2 ppm/block", ref.slew_ppb_per_quantum(2) == 250)
    ok("float ops per output frame", ref.OPS_PER_OUTPUT == 35, str(ref.OPS_PER_OUTPUT))

    # closed forms against the naive accumulator
    for ppb in (0, 1, -1, 500_000, -500_000, 123_456, -77_777, 10_000_000, -10_000_000):
        bad = [n for n in list(range(0, 80)) + [255, 256, 257, 1000, 4097]
               if simulate_pulls(n, [ppb] * n) != ref.inputs_pulled(n, ref.step_q32(ppb))]
        ok("closed-form pulls == simulation (ppb=%d)" % ppb, not bad, str(bad[:3]))
        bad = [n for n in list(range(0, 40)) + [255, 256, 257, 1000, 4097]
               if simulate_outputs(n, ppb) != ref.outputs_from_inputs(n, ref.step_q32(ppb))]
        ok("closed-form outputs == simulation (ppb=%d)" % ppb, not bad, str(bad[:3]))
    for start, target in ((0, 4000), (0, -3000), (2000, -2000), (0, 500_000), (500_000, -500_000)):
        bad = [n for n in (1, 2, 31, 32, 33, 64, 100, 1000, 5000, 70_000, 130_000)
               if simulate_pulls(n, schedule_ratios(n, start, target, 250)) !=
               ref.inputs_pulled_with_slew(n, start, target, 250)]
        ok("slew pulls == simulation (%d->%d)" % (start, target), not bad, str(bad[:3]))

    # slew shape
    s = ref.ratio_schedule(0, 500_000, 250, 2100)
    ok("slew reaches target in |d|/slew quanta", s.index(500_000) == 2000)
    ok("slew never exceeds the limit", all(abs(b - a) <= 250 for a, b in zip(s, s[1:])))

    # kernel: exact at integer positions, partition of unity, error shrinks with frequency
    w0, w1 = ref.catmull_rom_weights(0.0), ref.catmull_rom_weights(0.999999999)
    ok("weights at t=0 pick the centre tap", w0 == (0.0, 1.0, 0.0, 0.0))
    ok("weights sum to one", all(abs(sum(ref.catmull_rom_weights(k / 97)) - 1) < 1e-12 for k in range(97)))
    ok("weights at t->1 pick the next tap", abs(w1[2] - 1) < 1e-8)
    f = [ref.snr_floor_db(x) for x in (440, 1000, 4000, 10_000)]
    ok("snr floor falls with frequency", f[0] > f[1] > f[2] > f[3], str(f))
    ok("snr floor at 1 kHz is the 3rd-order figure", 80 < f[1] < 95, str(f[1]))

    # the frequency measurement itself: a perfect tone must pass it (this check was missing once, and the
    # unweighted method failed three of five tones on an ideal sine)
    tones = _generate().build()["tones"]
    worst_weighted = max(abs(ideal_tone_deviation_hz(t, True)) for t in tones)
    ok("Hann-weighted frequency method reads an ideal tone to under 1e-4 Hz", worst_weighted < 1e-4, "%.3g" % worst_weighted)
    bad = [t["id"] for t in tones if abs(ideal_tone_deviation_hz(t, True)) > t["freq_tol_hz"]]
    ok("an ideal tone is inside every vector frequency tolerance", not bad, str(bad))
    shifted = [t for t in tones if abs(t["expect_out_hz"] - t["f0_hz"]) > 0]
    ok("every nonzero frequency shift is at least 6x its tolerance",
       all(abs(t["expect_out_hz"] - t["f0_hz"]) >= 6 * t["freq_tol_hz"] for t in shifted),
       str([(t["id"], round(abs(t["expect_out_hz"] - t["f0_hz"]) / t["freq_tol_hz"], 1)) for t in shifted]))
    unweighted = [abs(ideal_tone_deviation_hz(t, False)) for t in tones if t["freq_tol_hz"] <= 0.002 + 1e-9]
    ok("the unweighted method would have failed (documents the defect)", any(u > 0.002 for u in unweighted),
       str([round(u, 5) for u in unweighted]))

    # estimator: a perfect line is recovered exactly
    obs = [(100 + (i * 48_000), 1_000_000_000 + i * 1_000_000) for i in range(20)]
    ratio, unc = ref.ls_fit(obs)
    ok("perfect nominal line has zero drift", ratio == 0 and unc == 0.0, "%s %s" % (ratio, unc))
    obs = [(i * 48_048, i * 1_000_000) for i in range(20)]              # +1000 ppm exactly
    ratio, _ = ref.ls_fit(obs)
    ok("perfect +1000 ppm line", ratio == 1_000_000, str(ratio))
    ok("round half away from zero", ref.div_round_nearest(5, 2) == 3 and ref.div_round_nearest(-5, 2) == -3
       and ref.div_round_nearest(4, 2) == 2 and ref.div_round_nearest(-1, 3) == 0)
    return out


def main() -> int:
    results = check()
    failed = [r for r in results if not r[1]]
    for name, passed, detail in results:
        print(("PASS  " if passed else "FAIL  ") + name + ("" if passed or not detail else "  [" + detail + "]"))
    print("anchors: %d checks, %d failed" % (len(results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
