#!/usr/bin/env python3
"""D03 (ffw-j9r) independent reference: expected values for the clock-rate estimator and resampler.

Stdlib only.  Nothing here calls, imports or is generated from the Rust.  Every expected number is
derived from a specification in docs/contracts/d03.md by a different route from the implementation:

* kernel quality     - the Catmull-Rom frequency response evaluated with complex arithmetic over a fine
                       grid of fractional positions (the implementation uses Horner-style weights on
                       32-bit floats and never evaluates a response);
* output counts      - closed forms in exact integers (the implementation accumulates a phase);
* ratio slew         - the contract's per-quantum rule restated as an integer loop over quanta;
* estimator          - exact rational least squares (the implementation uses 128-bit integer sums);
* occupancy bound    - a first-order analysis of the control loop, not a simulation.
"""
from __future__ import annotations

import cmath
import math
from fractions import Fraction
from typing import Iterator, List, Sequence, Tuple

Q32 = 1 << 32
SAMPLE_RATE_HZ = 48_000
BLOCK_FRAMES = 256
UPDATE_QUANTUM = 32
RAMP_FRAMES = 64
TAPS = 4
LOOKAHEAD = 2
PRIME = 3                           # frames pulled before the first output
DEFAULT_MAX_RATIO_PPM = 500
HARD_MAX_RATIO_PPM = 10_000
DEFAULT_SLEW_PPM_PER_BLOCK = 2
HARD_MAX_SLEW_PPM_PER_BLOCK = 50
SNR_CAP_DB = 110.0                  # float32 arithmetic floor; no bound is claimed above it
SNR_MARGIN_DB = 1.0

# hand count of float operations per stereo output frame (docs/contracts/d03.md section 4)
OPS_WEIGHTS = 15                    # h, t2, t3h, w0..w3
OPS_T_CONVERSION = 2                # shift/convert, scale
OPS_DOT_STEREO = 14                 # 2 channels x (4 mul + 3 add)
OPS_CLAMP_STEREO = 4                # 2 channels x 2 compares
OPS_PER_OUTPUT = OPS_WEIGHTS + OPS_T_CONVERSION + OPS_DOT_STEREO + OPS_CLAMP_STEREO
OPS_RAMP_EXTRA = 2


def slew_ppb_per_quantum(slew_ppm_per_block: int) -> int:
    """ppm per 256-frame block -> ppb per 32-frame update quantum (eight quanta per block)."""
    return slew_ppm_per_block * 1000 * UPDATE_QUANTUM // BLOCK_FRAMES


def step_q32(ppb: int) -> int:
    """Input frames consumed per output frame, Q32, truncating toward zero like the implementation."""
    return Q32 + int(Fraction(ppb * Q32, 10**9))


# ---- counts ---------------------------------------------------------------------------------------


def inputs_pulled(n_out: int, step: int) -> int:
    """Input frames pulled once ``n_out`` outputs exist at a constant step: 3 + floor((n-1)*S/2^32)."""
    return 0 if n_out == 0 else PRIME + ((n_out - 1) * step) // Q32


def outputs_from_inputs(n_in: int, step: int) -> int:
    """Outputs obtainable from ``n_in`` frames at a constant step: ceil((N-2)*2^32 / S), zero below 3."""
    return 0 if n_in < PRIME else -((-(n_in - LOOKAHEAD) * Q32) // step)


def ratio_schedule(start_ppb: int, target_ppb: int, slew: int, quanta: int) -> List[int]:
    """Ratio used by quantum j (outputs 32j..32j+31): r_0 = start, r_{j+1} = r_j + clamp(target-r_j, +-slew)."""
    out, r = [], start_ppb
    for _ in range(quanta):
        out.append(r)
        d = max(-slew, min(slew, target_ppb - r))
        r += d
    return out


def inputs_pulled_with_slew(n_out: int, start_ppb: int, target_ppb: int, slew: int) -> int:
    """Exact inputs pulled after ``n_out`` outputs when the ratio slews from start to target."""
    if n_out == 0:
        return 0
    steps_needed = n_out - 1                     # the final output's advance is not pulled yet
    total, done, r, q = 0, 0, start_ppb, 0
    while done < steps_needed:
        if r == target_ppb:                      # converged: the rest is one closed-form span
            total += (steps_needed - done) * step_q32(r)
            done = steps_needed
            break
        take = min(UPDATE_QUANTUM, steps_needed - done)
        total += take * step_q32(r)
        done += take
        r += max(-slew, min(slew, target_ppb - r))
        q += 1
    return PRIME + total // Q32


# ---- kernel quality --------------------------------------------------------------------------------


def catmull_rom_weights(t: float) -> Tuple[float, float, float, float]:
    """Standard Catmull-Rom spline weights for taps x[-1], x[0], x[1], x[2] at fractional position t."""
    t2, t3 = t * t, t * t * t
    return (0.5 * (-t3 + 2 * t2 - t),
            0.5 * (3 * t3 - 5 * t2 + 2),
            0.5 * (-3 * t3 + 4 * t2 + t),
            0.5 * (t3 - t2))


def kernel_max_error(omega: float, grid: int = 4096) -> float:
    """max over t of |H(omega, t) - exp(j*omega*t)|: the worst relative error of interpolating a tone."""
    worst = 0.0
    for k in range(grid):
        t = k / grid
        w = catmull_rom_weights(t)
        h = sum(w[j] * cmath.exp(1j * omega * (j - 1)) for j in range(TAPS))
        worst = max(worst, abs(h - cmath.exp(1j * omega * t)))
    return worst


def snr_floor_db(f0_hz: float, rate_hz: int = SAMPLE_RATE_HZ) -> float:
    """Guaranteed SNR for a unit tone: -20 log10 of the worst-case interpolation error, minus a margin,
    capped at the float32 floor.  Rigorous for any fractional-position sequence."""
    err = kernel_max_error(2 * math.pi * f0_hz / rate_hz)
    bound = SNR_CAP_DB if err <= 0 else -20 * math.log10(err)
    return round(min(SNR_CAP_DB, bound) - SNR_MARGIN_DB, 2)


def freq_tolerance_hz(f0_hz: float, n_measured: int, rate_hz: int = SAMPLE_RATE_HZ) -> float:
    """Allowed error of the half-vs-half phase-slope frequency measurement.  Interpolation error bends the
    phase by at most asin(err) in each half, so the slope is off by at most 2*err / (2*pi*half) cycles per
    sample; scaled by 1.5 and floored at 2 mHz for float32 arithmetic.  The measurement Hann-weights each
    half: unweighted, the real sine's negative-frequency image biases it by about 1/(half*sin(w)) radians
    (3.7 mHz on an ideal 440 Hz tone), which would exceed the floor; anchors.py proves the weighted method
    reads an ideal tone to under 0.1 mHz."""
    err = kernel_max_error(2 * math.pi * f0_hz / rate_hz)
    half = n_measured // 2
    return round(max(0.002, 1.5 * 2 * err * rate_hz / (2 * math.pi * half)), 6)


def expected_out_hz(f0_hz: float, ppb: int) -> float:
    """Output tone frequency: the source's real-time frequency, f0 * (1 + ppb/1e9)."""
    return float(Fraction(f0_hz) * (10**9 + ppb) / 10**9)


# ---- control-loop analysis -------------------------------------------------------------------------


def occupancy_bound_frames(drift_ppm: int, warmup_frames: int, kp_ppb_per_frame: int, slew_ppm: int,
                           resid_ppb: int, extra: int = 32) -> int:
    """Worst queue excursion from the target level, from a first-order analysis (not a simulation).

    * warm-up: before the estimator is valid the ratio is 0, so the level moves by drift * warmup;
    * slew: closing a rate error r takes r/slew_q quanta; the level moves by half that triangle;
    * steady: a residual rate error resid is balanced by the level trim at resid / kp frames.
    The sum is multiplied by 3 so a passing run is not a statement about tight margins.
    """
    warm = Fraction(drift_ppm, 10**6) * warmup_frames
    slew_q = slew_ppb_per_quantum(slew_ppm)
    quanta = Fraction(abs(drift_ppm) * 1000, slew_q)
    triangle = Fraction(abs(drift_ppm), 10**6) * quanta * UPDATE_QUANTUM / 2
    steady = Fraction(resid_ppb, kp_ppb_per_frame)
    return int(math.ceil(3 * (abs(warm) + triangle + steady))) + extra


# ---- estimator (exact rational least squares) -----------------------------------------------------


def lcg(seed: int) -> Iterator[int]:
    state = seed & 0xFFFFFFFF
    while True:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        yield state


def synth_observations(true_ppb: int, n: int, spacing_us: int, jitter_us: int, pos0: int, seed: int,
                       nominal: int = SAMPLE_RATE_HZ, t0_us: int = 1_000_000_000) -> List[Tuple[int, int]]:
    """(unwrapped position, local_us): a source running at nominal*(1+ppb/1e9).  The position is the true
    one at the ideal time; the recorded local timestamp carries the jitter (timestamp noise)."""
    g = lcg(seed)
    out = []
    for i in range(n):
        jit = (next(g) % (2 * jitter_us + 1)) - jitter_us if jitter_us else 0
        ideal = i * spacing_us
        frames = (ideal * nominal * (10**9 + true_ppb)) // (10**15)
        out.append((pos0 + frames, t0_us + ideal + jit))
    return out


def div_round_nearest(a: int, b: int) -> int:
    """Nearest integer, halves away from zero, b > 0 (the exact rule the implementation uses)."""
    return (2 * a + b) // (2 * b) if a >= 0 else -((-2 * a + b) // (2 * b))


def ls_fit(obs: Sequence[Tuple[int, int]], nominal: int = SAMPLE_RATE_HZ) -> Tuple[int, float]:
    """(ratio_ppb, uncertainty_ppb as an exact-rational float) of the least-squares rate over ``obs``."""
    n = len(obs)
    x0, y0 = obs[0][1], obs[0][0]
    xs = [o[1] - x0 for o in obs]
    ys = [o[0] - y0 for o in obs]
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    syy = sum(y * y for y in ys)
    dx, dxy, dy = n * sxx - sx * sx, n * sxy - sx * sy, n * syy - sy * sy
    ppb = div_round_nearest((dxy * 10**6 - nominal * dx) * 10**9, nominal * dx)
    var = Fraction(dy * dx - dxy * dxy, (n - 2) * dx * dx)       # variance of the slope, (frames/us)^2
    unc = math.sqrt(var) * 10**15 / nominal if var > 0 else 0.0
    return ppb, unc


# ---- resampler quality: THD+N and gain of a driven sine (docs/contracts/d03.md section 4.1) ---------------
#
# The expected figures are computed from first principles: double-precision interpolation at the exact Q32
# positions of the contract (`i * step` at a constant ratio, the integer quantum schedule when slewing), then the
# same least-squares carrier fit the test applies to the emitted samples.  Nothing here reads a Rust result.

QUALITY_AMP_DBFS = -1.0
QUALITY_AMP = 10 ** (QUALITY_AMP_DBFS / 20)
QUALITY_PHASE = 0.25
QUALITY_N_MEAS = 32768
QUALITY_SKIP = 192                  # the 64-frame fade-in plus margin
QUALITY_Q_CAP_DB = 110.0            # the float32 floor: nothing above it is claimed
QUALITY_TOL_Q_DB = 0.25
QUALITY_TOL_GAIN_DB = 0.002
QUALITY_PLANT_MARGIN_DB = 3.0       # a planted interpolator must miss Q by at least this much ...
QUALITY_PLANT_GAIN_MARGIN_DB = 0.1  # ... or the gain band by at least this much
# Declared in docs/contracts/d03.md section 4.1 BEFORE any figure was measured; the judge compares them with the
# contract's table, so moving one here without moving it there (and leaving the old row) fails the META check.
QUALITY_BANDS = {
    1000: {"q_floor_db": 85.0, "gain_lo_db": -0.01, "gain_hi_db": 0.01},
    10000: {"q_floor_db": 22.0, "gain_lo_db": -0.60, "gain_hi_db": 0.05},
}
QUALITY_TONES = (1000, 10000)
QUALITY_STEADY_PPM = (0, 100, -100, 500, -500)
QUALITY_PLANT_PPM = (100, -100, 500, -500)
QUALITY_SEG_A_OUT = 2048            # outputs before the epoch reset in the epoch scenario
QUALITY_SLEW_TARGET_PPB = 500_000
QUALITY_SLEW_SETTLED_AT = 70_000    # outputs; the slew ends at 64 000 (500 000 ppb / 250 ppb per 32-frame quantum)
QUALITY_PHASE_B = 1.1


def _f32(v: float) -> float:
    import struct
    return struct.unpack("f", struct.pack("f", v))[0]


def tone_input(f0_hz: float, phase: float, n: int) -> List[float]:
    """The driven signal, rounded to float32 the way the test hands it to the resampler."""
    w = 2 * math.pi * f0_hz / SAMPLE_RATE_HZ
    return [_f32(QUALITY_AMP * math.sin(w * m + phase)) for m in range(n)]


def quality_positions(n_out: int, ppb: int, slew_to_ppb: int = None) -> List[int]:
    """Q32 position of each output: ``i * step`` at a constant ratio; when slewing, the cumulative sum of the
    per-quantum steps (output k uses the ratio of quantum k // 32)."""
    if slew_to_ppb is None:
        step = step_q32(ppb)
        return [i * step for i in range(n_out)]
    quanta = n_out // UPDATE_QUANTUM + 2
    ratios = ratio_schedule(ppb, slew_to_ppb, slew_ppb_per_quantum(DEFAULT_SLEW_PPM_PER_BLOCK), quanta)
    pos, acc = [], 0
    for k in range(n_out):
        pos.append(acc)
        acc += step_q32(ratios[k // UPDATE_QUANTUM])
    return pos



def interpolate(kind: str, x: Sequence[float], positions: Sequence[int]) -> List[float]:
    """Interpolate ``x`` at Q32 ``positions``.  ``x[-1]`` is the zero history of a fresh stream."""
    out = []
    n = len(x)

    def tap(k: int) -> float:
        return x[k] if 0 <= k < n else 0.0
    for pos in positions:
        m, frac = pos >> 32, pos & 0xFFFFFFFF
        if kind == "catmull_rom":
            t = (frac >> 8) / 16777216.0
            w = catmull_rom_weights(t)
            out.append(w[0] * tap(m - 1) + w[1] * tap(m) + w[2] * tap(m + 1) + w[3] * tap(m + 2))
        elif kind == "linear":
            t = (frac >> 8) / 16777216.0
            out.append(tap(m) * (1.0 - t) + tap(m + 1) * t)
        elif kind == "nearest":
            out.append(tap(m + 1) if frac >= (1 << 31) else tap(m))
        else:
            raise ValueError(kind)
    return out


def fit_metrics(y: Sequence[float], w_per_sample: float, amp: float = QUALITY_AMP) -> Tuple[float, float]:
    """(Q dB, gain dB): least-squares carrier ``a cos(wn) + b sin(wn)``, Q = carrier power over residual power."""
    n = len(y)
    scc = sss = scs = syc = sys_ = 0.0
    cs = [(math.cos(w_per_sample * i), math.sin(w_per_sample * i)) for i in range(n)]
    for (c, s_), v in zip(cs, y):
        scc += c * c
        sss += s_ * s_
        scs += c * s_
        syc += v * c
        sys_ += v * s_
    det = scc * sss - scs * scs
    a = (syc * sss - sys_ * scs) / det
    b = (sys_ * scc - syc * scs) / det
    resid = sum((v - a * c - b * s_) ** 2 for (c, s_), v in zip(cs, y))
    pf = (a * a + b * b) / 2
    pr = max(resid / n, 1e-300)
    return 10 * math.log10(pf / pr), 20 * math.log10(math.sqrt(a * a + b * b) / amp)


def ramp_snr_db(y: Sequence[float], ideal: Sequence[float]) -> float:
    """Error-to-signal over the fade-in: ``y`` against the ideal tone scaled by the ramp (i / 64), outputs 1..63."""
    sig = sum((ideal[i] * i / RAMP_FRAMES) ** 2 for i in range(1, RAMP_FRAMES))
    err = sum((y[i] - ideal[i] * i / RAMP_FRAMES) ** 2 for i in range(1, RAMP_FRAMES))
    return 10 * math.log10(sig / max(err, 1e-300))


def quality_case_ids() -> List[str]:
    ids = []
    for f in QUALITY_TONES:
        for ppm in QUALITY_STEADY_PPM:
            ids.append("q-steady-%d-%s" % (f, _ppm_token(ppm)))
    for f in QUALITY_TONES:
        ids += ["q-epoch-ramp-%d" % f, "q-epoch-steady-%d" % f, "q-slewed-%d" % f]
    for kind in ("linear", "nearest"):
        for f in QUALITY_TONES:
            for ppm in QUALITY_PLANT_PPM + (0,):          # the 0 ppm rows are controls: every interpolator is exact
                ids.append("q-%s-%d-%s" % (kind, f, _ppm_token(ppm)))
    return ids


def _ppm_token(ppm: int) -> str:
    return "0" if ppm == 0 else ("p%d" % ppm if ppm > 0 else "m%d" % -ppm)


def quality_case(cid: str) -> dict:
    """Describe one case and compute its expected figures from first principles."""
    parts = cid.split("-")
    kind_tag = parts[1]
    if kind_tag == "steady":
        f0, ppm = int(parts[2]), _ppm_value(parts[3])
        scenario, interp = "steady", "catmull_rom"
    elif kind_tag in ("linear", "nearest"):
        f0, ppm = int(parts[2]), _ppm_value(parts[3])
        scenario, interp = "steady", kind_tag
    elif kind_tag == "epoch":
        f0, ppm = int(parts[3]), 500
        scenario, interp = ("epoch_ramp" if parts[2] == "ramp" else "epoch_steady"), "catmull_rom"
    elif kind_tag == "slewed":
        f0, ppm = int(parts[2]), 500
        scenario, interp = "slewed", "catmull_rom"
    else:
        raise ValueError(cid)
    ppb = ppm * 1000
    band = QUALITY_BANDS[f0]
    case = {"id": cid, "scenario": scenario, "interp": interp, "f0_hz": f0, "ppb": ppb,
            "band_q_db": band["q_floor_db"], "gain_lo_db": band["gain_lo_db"], "gain_hi_db": band["gain_hi_db"],
            "must_pass": interp == "catmull_rom" or ppm == 0, "control": interp != "catmull_rom" and ppm == 0}
    w0 = 2 * math.pi * f0 / SAMPLE_RATE_HZ
    if scenario == "steady":
        n_out = QUALITY_SKIP + QUALITY_N_MEAS
        pos = quality_positions(n_out, ppb)
        step = step_q32(ppb)
        n_in = inputs_pulled(n_out, step)
        x = tone_input(f0, QUALITY_PHASE, n_in + 8)
        y = interpolate(interp, x, pos)[QUALITY_SKIP:]
        q, g = fit_metrics(y, w0 * step / Q32)
        case.update(step_q32=step, n_out=n_out, n_in=n_in, skip=QUALITY_SKIP, n_meas=QUALITY_N_MEAS)
    elif scenario in ("epoch_ramp", "epoch_steady"):
        n_out = QUALITY_SKIP + QUALITY_N_MEAS
        pos = quality_positions(n_out, ppb)
        step = step_q32(ppb)
        n_in = inputs_pulled(n_out, step)
        x = tone_input(f0, QUALITY_PHASE_B, n_in + 8)
        y = interpolate("catmull_rom", x, pos)
        y = [v * (i / RAMP_FRAMES if i < RAMP_FRAMES else 1.0) for i, v in enumerate(y)]
        if scenario == "epoch_ramp":
            ideal = [QUALITY_AMP * math.sin(w0 * (p / Q32) + QUALITY_PHASE_B) for p in pos[:RAMP_FRAMES]]
            q, g = ramp_snr_db(y, ideal), None
            case.update(n_meas=RAMP_FRAMES - 1)
        else:
            q, g = fit_metrics(y[QUALITY_SKIP:], w0 * step / Q32)
            case.update(n_meas=QUALITY_N_MEAS)
        case.update(step_q32=step, n_out=n_out, n_in=n_in, skip=QUALITY_SKIP, seg_a_out=QUALITY_SEG_A_OUT,
                    n_in_a=inputs_pulled(QUALITY_SEG_A_OUT, step) + 8, phase_a=QUALITY_PHASE, phase_b=QUALITY_PHASE_B)
    else:
        n_out = QUALITY_SLEW_SETTLED_AT + QUALITY_N_MEAS
        pos = quality_positions(n_out, 0, QUALITY_SLEW_TARGET_PPB)
        n_in = inputs_pulled_with_slew(n_out, 0, QUALITY_SLEW_TARGET_PPB, slew_ppb_per_quantum(DEFAULT_SLEW_PPM_PER_BLOCK))
        x = tone_input(f0, QUALITY_PHASE, n_in + 8)
        y = interpolate("catmull_rom", x, pos)[QUALITY_SLEW_SETTLED_AT:]
        step = step_q32(QUALITY_SLEW_TARGET_PPB)
        q, g = fit_metrics(y, w0 * step / Q32)
        case.update(step_q32=step, n_out=n_out, n_in=n_in, skip=QUALITY_SLEW_SETTLED_AT, n_meas=QUALITY_N_MEAS,
                    target_ppb=QUALITY_SLEW_TARGET_PPB)
    case["expect_q_db"] = round(q, 4)
    case["expect_gain_db"] = None if g is None else round(g, 6)
    return case


def _ppm_value(tok: str) -> int:
    if tok == "0":
        return 0
    return int(tok[1:]) if tok[0] == "p" else -int(tok[1:])
