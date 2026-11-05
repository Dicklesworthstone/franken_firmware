#!/usr/bin/env python3
"""D03 vector generator: builds tests/d03/vectors.json from the independent reference only.

    python3 -B -I tests/d03/generate.py [--check]

``--check`` exits 1 if the committed file differs from a fresh generation (a stale or hand-edited
file fails).  Deterministic: fixed seeds, sorted keys, no clock, no environment.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))
VECTORS = os.path.join(HERE, "vectors.json")


def _ref():
    spec = importlib.util.spec_from_file_location("d03_reference", os.path.join(HERE, "reference.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _ref()
HALF = 1 << 31
WRAP = 1 << 32

# estimator defaults at 48 kHz (docs/contracts/d03.md section 2); the Rust defaults must equal these
RATE_DEFAULTS = {
    "nominal_rate_hz": 48000, "max_correction_ppm": 500, "rejoin_ppm": 2000, "max_instant_ppm": 50000,
    "max_gap_us": 10_000_000, "max_residual_frames": 480, "min_observations": 8, "min_span_us": 4_000_000,
    "max_uncertainty_ppb": 50_000, "aging_ppb_per_s": 100, "max_holdover_us": 60_000_000, "window": 64,
}


def status_for(ratio_ppb: int, unc_ppb: int, cfg: Dict[str, int]) -> Dict[str, Any]:
    """The contract's status rule restated: rejoin > noisy > clamped > valid."""
    cap = cfg["max_correction_ppm"] * 1000
    if abs(ratio_ppb) > cfg["rejoin_ppm"] * 1000:
        return {"status": "RejoinRequired", "correction_ppb": max(-cap, min(cap, ratio_ppb)), "clamped": True}
    if unc_ppb > cfg["max_uncertainty_ppb"]:
        return {"status": "Noisy", "correction_ppb": 0, "clamped": False}
    if abs(ratio_ppb) > cap:
        return {"status": "Clamped", "correction_ppb": max(-cap, min(cap, ratio_ppb)), "clamped": True}
    return {"status": "Valid", "correction_ppb": ratio_ppb, "clamped": False}


def estimator_case(cid: str, ppb: int, n: int, spacing: int, jitter: int, pos0: int, seed: int,
                   take_last: int = 64) -> Dict[str, Any]:
    unwrapped = ref.synth_observations(ppb, n, spacing, jitter, pos0, seed)
    window = unwrapped[-take_last:]
    ratio, unc = ref.ls_fit(window)
    unc_ceil = int(-(-unc // 1))
    case = {"id": cid, "true_ppb": ppb,
            "observations": [[p % WRAP, t] for p, t in unwrapped],
            "window_len": len(window), "expect_ratio_ppb": ratio, "expect_uncertainty_ppb": unc,
            "expect_wraps": sum(1 for a, b in zip(unwrapped, unwrapped[1:]) if (a[0] % WRAP) > (b[0] % WRAP)),
            "span_us": window[-1][1] - window[0][1]}
    case.update(status_for(ratio, unc_ceil, RATE_DEFAULTS))
    return case


def discontinuity_cases() -> List[Dict[str, Any]]:
    base = ref.synth_observations(100_000, 16, 1_000_000, 200, 5_000_000, 77)
    last_pos, last_t = base[-1]
    cases = []

    def add(cid: str, reason: str, pos: int, local: int) -> None:
        cases.append({"id": cid, "reason": reason, "prefix": [[p % WRAP, t] for p, t in base],
                      "event": [pos % WRAP, local]})

    nxt = last_t + 1_000_000
    on_track = last_pos + 48_004                               # +100 ppm over one second
    add("d03-disc-local-regression", "LocalClockRegression", on_track, last_t - 10)
    add("d03-disc-local-equal", "LocalClockRegression", on_track, last_t)
    add("d03-disc-timeline-backward", "SourceTimelineAmbiguous", last_pos - 100, nxt)
    add("d03-disc-half-range", "SourceTimelineAmbiguous", last_pos + HALF, nxt)
    add("d03-disc-just-under-half-range", "ImplausibleRate", last_pos + HALF - 1, nxt)
    gap_t = last_t + 11_000_000
    add("d03-disc-gap", "ObservationGap", last_pos + 11 * 48_000 + 53, gap_t)
    add("d03-disc-implausible-rate", "ImplausibleRate", last_pos + 52_800, nxt)
    add("d03-disc-position-jump", "PositionJump", on_track + 1000, nxt)
    return cases


def build() -> Dict[str, Any]:
    q = ref.step_q32
    slew = ref.slew_ppb_per_quantum(ref.DEFAULT_SLEW_PPM_PER_BLOCK)

    tones = []
    for f0, ppb in ((440, 500_000), (1000, -500_000), (4000, 137_000), (10_000, -250_000), (1000, 0)):
        n_out = 8192
        tones.append({"id": "d03-tone-%d-%+d" % (f0, ppb), "f0_hz": f0, "ppb": ppb, "n_out": n_out,
                      "step_q32": q(ppb), "expect_out_hz": ref.expected_out_hz(f0, ppb),
                      "expect_inputs_pulled": ref.inputs_pulled(n_out, q(ppb)),
                      "snr_floor_db": ref.snr_floor_db(f0), "skip_ramp_frames": ref.RAMP_FRAMES,
                      "freq_tol_hz": ref.freq_tolerance_hz(f0, n_out - ref.RAMP_FRAMES)})

    pulled = []
    for ppb in (0, 500_000, -500_000, 1, -1, 123_456, -77_777):
        for n_out in (0, 1, 2, 3, 31, 32, 33, 255, 256, 257, 1000, 48_000, 4_147_200_000):
            pulled.append({"ppb": ppb, "n_out": n_out, "expect_inputs_pulled": ref.inputs_pulled(n_out, q(ppb))})
    outputs = []
    for ppb in (0, 500_000, -500_000, 123_456, -77_777):
        for n_in in (0, 1, 2, 3, 4, 5, 255, 256, 257, 1000, 48_000, 262_144):
            outputs.append({"ppb": ppb, "n_in": n_in, "expect_outputs": ref.outputs_from_inputs(n_in, q(ppb))})

    schedules = []
    for cid, start, target, quanta in (("up-small", 0, 4000, 20), ("down-small", 0, -3000, 16),
                                       ("reverse", 2000, -2000, 24)):
        schedules.append({"id": "d03-slew-" + cid, "start_ppb": start, "target_ppb": target,
                          "slew_ppb_per_quantum": slew, "schedule": ref.ratio_schedule(start, target, slew, quanta)})
    slew_counts = []
    for start, target, n_out in ((0, 500_000, 300_000), (500_000, -500_000, 600_000), (-123_456, 321_000, 400_001),
                                 (0, 500_000, 10_000_000), (250_000, 250_000, 7_777_777)):
        slew_counts.append({"start_ppb": start, "target_ppb": target, "n_out": n_out, "slew_ppb_per_quantum": slew,
                            "expect_inputs_pulled": ref.inputs_pulled_with_slew(n_out, start, target, slew),
                            "quanta_to_converge": -(-abs(target - start) // slew)})

    closed = []
    kp, trim_limit, level_target = 100, 100_000, 2400
    warm = 7 * ref.SAMPLE_RATE_HZ
    for cid, drift_ppm, seconds, pos0, jitter, seed in (
            ("d03-loop-10min-pos", 300, 600, 0, 200, 21),
            ("d03-loop-10min-neg", -450, 600, 0, 200, 22),
            ("d03-loop-wrap-20min", 500, 1200, WRAP - 600 * ref.SAMPLE_RATE_HZ, 200, 23),
            ("d03-loop-25h-soak", -280, int(25.5 * 3600), 0, 200, 24)):
        closed.append({"id": cid, "drift_ppb": drift_ppm * 1000, "virtual_seconds": seconds, "pos0": pos0,
                       "jitter_us": jitter, "seed": seed, "kp_ppb_per_frame": kp, "trim_limit_ppb": trim_limit,
                       "slew_ppm_per_block": ref.DEFAULT_SLEW_PPM_PER_BLOCK, "level_target_frames": level_target,
                       "warmup_frames": warm, "resid_ppb_assumed": 2000,
                       "occupancy_bound_frames": ref.occupancy_bound_frames(
                           drift_ppm, warm, kp, ref.DEFAULT_SLEW_PPM_PER_BLOCK, 2000),
                       "final_ratio_tolerance_ppb": 10_000,
                       "expect_total_outputs": seconds * ref.SAMPLE_RATE_HZ // ref.BLOCK_FRAMES * ref.BLOCK_FRAMES,
                       "expect_wraps": (pos0 + seconds * ref.SAMPLE_RATE_HZ * (10**9 + drift_ppm * 1000) // 10**9) // WRAP})

    jump = {"id": "d03-loop-jump", "drift_ppb": 200_000, "virtual_seconds": 400, "pos0": 0, "jitter_us": 200,
            "seed": 25, "kp_ppb_per_frame": kp, "trim_limit_ppb": trim_limit,
            "slew_ppm_per_block": ref.DEFAULT_SLEW_PPM_PER_BLOCK, "level_target_frames": level_target,
            "warmup_frames": warm, "resid_ppb_assumed": 2000,
            # the source's reported counter jumps this far ahead at jump_at_s; delivered audio is unaffected
            "jump_at_s": 200, "jump_frames": 1_000_000, "expect_reason": "ImplausibleRate",
            "expect_resets": 1, "hold_check_after_s": 5, "hold_ratio_tolerance_ppb": 20_000,
            "occupancy_bound_frames": ref.occupancy_bound_frames(
                200, warm, kp, ref.DEFAULT_SLEW_PPM_PER_BLOCK, 2000),
            "expect_total_outputs": 400 * ref.SAMPLE_RATE_HZ // ref.BLOCK_FRAMES * ref.BLOCK_FRAMES}

    est = [
        estimator_case("d03-est-pos", 320_000, 32, 1_000_000, 200, 100_000, 11),
        estimator_case("d03-est-neg", -410_000, 32, 1_000_000, 200, 100_000, 12),
        estimator_case("d03-est-clamp", 800_000, 32, 1_000_000, 200, 100_000, 13),
        estimator_case("d03-est-rejoin", 3_000_000, 32, 1_000_000, 200, 100_000, 14),
        estimator_case("d03-est-wrap", -150_000, 40, 1_000_000, 200, WRAP - 15 * ref.SAMPLE_RATE_HZ, 15),
        estimator_case("d03-est-slide", 60_000, 80, 1_000_000, 200, 100_000, 16, take_last=64),
        estimator_case("d03-est-noisy", 90_000, 16, 1_000_000, 5_000, 100_000, 17),
    ]
    warm_cases = [
        {"id": "d03-est-too-few", "observations": [[p % WRAP, t] for p, t in
                                                   ref.synth_observations(50_000, 7, 1_000_000, 200, 1000, 31)]},
        {"id": "d03-est-too-short", "observations": [[p % WRAP, t] for p, t in
                                                     ref.synth_observations(50_000, 8, 100_000, 50, 1000, 32)]},
    ]

    return {
        "schema": "ffw.d03.vectors.v1",
        "params": {
            "sample_rate_hz": ref.SAMPLE_RATE_HZ, "block_frames": ref.BLOCK_FRAMES,
            "update_quantum_frames": ref.UPDATE_QUANTUM, "ramp_frames": ref.RAMP_FRAMES, "taps": ref.TAPS,
            "lookahead_frames": ref.LOOKAHEAD, "prime_frames": ref.PRIME,
            "default_max_ratio_ppm": ref.DEFAULT_MAX_RATIO_PPM, "hard_max_ratio_ppm": ref.HARD_MAX_RATIO_PPM,
            "default_slew_ppm_per_block": ref.DEFAULT_SLEW_PPM_PER_BLOCK,
            "hard_max_slew_ppm_per_block": ref.HARD_MAX_SLEW_PPM_PER_BLOCK,
            "slew_ppb_per_quantum": slew,
            "float_ops_per_output_frame": ref.OPS_PER_OUTPUT, "ramp_extra_float_ops": ref.OPS_RAMP_EXTRA,
            "snr_cap_db": ref.SNR_CAP_DB, "rate_defaults": RATE_DEFAULTS,
        },
        "tones": tones, "pulled": pulled, "outputs": outputs, "schedules": schedules, "slew_counts": slew_counts,
        "estimator": est, "estimator_warmup": warm_cases, "discontinuities": discontinuity_cases(),
        "closed_loop": closed, "closed_loop_jump": jump,
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


def main(argv: List[str]) -> int:
    text = render()
    if "--check" in argv:
        try:
            with open(VECTORS, encoding="utf-8") as fh:
                return 0 if fh.read() == text else 1
        except OSError:
            return 1
    with open(VECTORS, "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
