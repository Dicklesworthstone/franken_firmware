#!/usr/bin/env python3
"""Independent reference and quality judge for the 160/147 rate bridge (S02 / ffw-6dh).

What is independent of the Rust:

* The reference computes every output from the CLOSED FORM (`m = floor(n * 147 / 160)`, `r = n * 147 mod 160`,
  `y[n] = round_half_up_q30(sum_k C[r][k] * x[m - k])`) with numpy int64 gathers. The Rust advances (m, r) incrementally per input frame and keeps a
  ring buffer. They share only the coefficient table, which this file parses out of the shipped `rate_table.rs` (so it judges the table that
  ships), and the table is checked separately below against the filter it is meant to be, by frequency response.
* The vectors are exact: integer samples in, integer samples out, FNV-1a 64 over the big-endian i32 output. No tolerance is involved.
* The QUALITY judge measures the table's response and the bridge's output with a least-squares sinusoid fit and a Blackman-Harris FFT, and
  cross-checks against `scipy.signal.resample_poly` (a different implementation with a different filter). All thresholds are written below and
  were fixed before any Rust ran.

    bridge_reference.py --write-vectors PATH     create the vector file (exclusive create)
    bridge_reference.py --check-vectors PATH     exit 0 only when PATH equals a fresh derivation
    bridge_reference.py --quality                run the table and tone judges; exit 0 pass, 1 fail, 3 blocked (numpy/scipy missing)
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from typing import Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import oracle  # noqa: E402

L, M, K, Q = 160, 147, 64, 30
Q23_MAX, Q23_MIN = 8_388_607, -8_388_608
IN_RATE, OUT_RATE = 44_100, 48_000
DELAY_IN_FRAMES = K // 2
DEFAULT_TABLE = os.path.join(HERE, "..", "..", "crates", "franken-codec", "src", "rate_table.rs")

# Pre-registered quality thresholds (fixed before any Rust ran).
GAIN_TOLERANCE = 0.0035           # |gain - 1| for a pass-band tone (0.03 dB)
PHASE_TOLERANCE_RAD = 0.003       # measured phase against the stated 32-input-frame delay
SPUR_LIMIT_DB = -66.0             # everything outside +-8 bins of the tone, relative to the tone, Blackman-Harris window
TABLE_PASSBAND_HZ = 19_000.0      # pass-band edge the table is judged to
TABLE_PASSBAND_DEV = 0.0008       # |H/L - 1| up to the edge
TABLE_STOPBAND_HZ = 22_050.0      # stop-band edge (the input Nyquist)
TABLE_STOPBAND_DB = -68.0         # |H/L| beyond the edge
SCIPY_RMS_TOLERANCE = 0.003       # rms(mine - scipy) / rms(signal) on a multi-tone band-limited signal
TONES_HZ = (1000.0, 5000.0, 10000.0, 15000.0, 18000.0)
TONE_FRAMES = 8192
TONE_VECTOR_FRAMES = 2048
TONE_AMPLITUDE = 1 << 22


def load_table(path: str = DEFAULT_TABLE) -> List[int]:
    with open(path, encoding="ascii") as f:
        text = f.read()
    body = text.split("COEFFS: [i32; %d] = [" % (L * K), 1)[1].split("];", 1)[0]
    values = [int(tok) for tok in re.findall(r"-?\d+", body)]
    if len(values) != L * K:
        raise ValueError("table has %d values, expected %d" % (len(values), L * K))
    for r in range(L):
        if sum(values[r * K:(r + 1) * K]) != 1 << Q:
            raise ValueError("phase %d does not sum to 2^30" % r)
    return values


def outputs_after(frames: int) -> int:
    return -(-frames * L // M)


def bridge(table: List[int], channels: List[List[int]], flush: bool = False) -> Tuple[List[List[int]], int]:
    """Closed-form reference. `channels` is a list of per-channel integer sample lists (Q23). Returns (per-channel outputs, clipped count)."""
    import numpy as np

    coef = np.array(table, dtype=np.int64).reshape(L, K)
    outs = []
    clipped = 0
    for samples in channels:
        x = np.array(samples + ([0] * K if flush else []), dtype=np.int64)
        frames = len(x)
        count = outputs_after(frames)
        n = np.arange(count, dtype=np.int64)
        u = n * M
        m = u // L
        r = u % L
        assert int(m.max()) <= frames - 1
        xpad = np.concatenate([np.zeros(K - 1, dtype=np.int64), x])
        idx = (m[:, None] - np.arange(K, dtype=np.int64)[None, :]) + (K - 1)
        acc = (coef[r] * xpad[idx]).sum(axis=1)
        y = (acc + (1 << (Q - 1))) >> Q
        clipped += int(((y > Q23_MAX) | (y < Q23_MIN)).sum())
        y = np.clip(y, Q23_MIN, Q23_MAX)
        outs.append([int(v) for v in y])
    return outs, clipped


def interleave(channels: List[List[int]]) -> List[int]:
    out = []
    for frame in zip(*channels):
        out.extend(frame)
    return out


def be_i32(values: List[int]) -> bytes:
    import struct

    return struct.pack(">%di" % len(values), *values)


def tone_samples(freq: float, phase: float, frames: int = TONE_FRAMES, amplitude: int = TONE_AMPLITUDE) -> List[int]:
    return [int(round(amplitude * math.sin(2.0 * math.pi * freq * n / IN_RATE + phase))) for n in range(frames)]


def make_input(spec: Dict[str, object]) -> List[List[int]]:
    kind = spec["kind"]
    frames = int(spec.get("frames", 0))
    if kind in ("tri", "mono_tri"):
        pairs = oracle.signal(frames, int(spec["seed_a"]), int(spec["seed_b"]), 0, 16)
        left = [a << 8 for a, _ in pairs]
        right = [b << 8 for _, b in pairs]
        return [left] if kind == "mono_tri" else [left, right]
    if kind == "dc":
        return [[int(spec["value"])] * frames] * 2
    if kind == "impulse":
        x = [0] * frames
        x[int(spec["at"])] = int(spec["amplitude"])
        return [x, list(x)]
    if kind == "square":
        half, amp = int(spec["half_period"]), int(spec["amplitude"])
        x = [amp if (n // half) % 2 == 0 else -amp for n in range(frames)]
        return [x, list(x)]
    if kind == "silence":
        return [[0] * frames, [0] * frames]
    if kind == "explicit":
        return [list(spec["left"]), list(spec["right"])]
    raise ValueError(kind)


def case_specs() -> List[Dict[str, object]]:
    cases: List[Dict[str, object]] = [
        {"id": "noise_tri", "flush": False, "input": {"kind": "tri", "frames": 2000, "seed_a": 12345, "seed_b": 67890}},
        {"id": "noise_tri_flushed", "flush": True, "input": {"kind": "tri", "frames": 700, "seed_a": 424242, "seed_b": 31337}},
        {"id": "mono_noise_tri", "flush": False, "input": {"kind": "mono_tri", "frames": 900, "seed_a": 99, "seed_b": 100}},
        {"id": "dc", "flush": False, "input": {"kind": "dc", "frames": 300, "value": 1000 << 8}},
        {"id": "dc_negative", "flush": False, "input": {"kind": "dc", "frames": 300, "value": -(777 << 8)}},
        {"id": "impulse", "flush": True, "input": {"kind": "impulse", "frames": 300, "at": 100, "amplitude": 1 << 22}},
        {"id": "square_full_scale", "flush": False, "input": {"kind": "square", "frames": 600, "half_period": 7, "amplitude": Q23_MAX}},
        {"id": "silence", "flush": False, "input": {"kind": "silence", "frames": 500}},
        {"id": "one_frame", "flush": False, "input": {"kind": "impulse", "frames": 1, "at": 0, "amplitude": 1 << 22}},
    ]
    for freq in TONES_HZ:
        left = tone_samples(freq, 0.0, TONE_VECTOR_FRAMES)
        right = tone_samples(freq, math.pi / 2.0, TONE_VECTOR_FRAMES)
        cases.append({"id": "tone_%d" % int(freq), "flush": False, "input": {"kind": "explicit", "frames": TONE_VECTOR_FRAMES, "left": left, "right": right}})
    return cases


def derive(table: List[int]) -> Dict[str, object]:
    cases = []
    for spec in case_specs():
        channels = make_input(spec["input"])
        outs, clipped = bridge(table, channels, bool(spec["flush"]))
        inter = interleave(outs)
        data = be_i32(inter)
        entry = {
            "id": spec["id"],
            "channels": len(channels),
            "flush": spec["flush"],
            "input": spec["input"],
            "frames_in": len(channels[0]),
            "frames_out": len(outs[0]),
            "clipped": clipped,
            "out_fnv1a64": "0x%016x" % oracle.fnv1a64(data),
            "out_sha256": oracle.sha256(data),
            "head": inter[:16],
            "tail": inter[-16:],
        }
        cases.append(entry)
    import hashlib

    with open(DEFAULT_TABLE, "rb") as f:
        table_sha = hashlib.sha256(f.read()).hexdigest()
    return {
        "schema": "ffw.s02.bridge_vectors.v1",
        "note": "Exact integer vectors for the 160/147 bridge, derived by tests/s02/bridge_reference.py from the closed form. Inputs of kind tri/dc/impulse/square/silence are regenerated by the Rust test from the written rule; kind explicit carries its samples.",
        "up": L, "down": M, "taps": K, "delay_in_frames": DELAY_IN_FRAMES, "q": Q,
        "table_file_sha256": table_sha,
        "cases": cases,
    }


def judge_table(table: List[int]) -> Dict[str, object]:
    import numpy as np

    h = np.zeros(L * K, dtype=np.float64)
    for r in range(L):
        for k in range(K):
            h[L * k + r] = table[r * K + k] / float(1 << Q)
    nfft = 1 << 19
    spec = np.abs(np.fft.rfft(h, nfft)) / L
    freqs = np.arange(len(spec)) * (IN_RATE * L / nfft)
    pb = freqs <= TABLE_PASSBAND_HZ
    sb = freqs >= TABLE_STOPBAND_HZ
    pass_dev = float(np.max(np.abs(spec[pb] - 1.0)))
    stop_db = 20.0 * math.log10(float(np.max(spec[sb])))
    return {
        "passband_max_deviation": pass_dev,
        "passband_limit": TABLE_PASSBAND_DEV,
        "stopband_max_db": stop_db,
        "stopband_limit_db": TABLE_STOPBAND_DB,
        "ok": pass_dev <= TABLE_PASSBAND_DEV and stop_db <= TABLE_STOPBAND_DB,
    }


def blackman_harris(n: int):
    import numpy as np

    k = np.arange(n)
    a = (0.35875, 0.48829, 0.14128, 0.01168)
    return a[0] - a[1] * np.cos(2 * np.pi * k / (n - 1)) + a[2] * np.cos(4 * np.pi * k / (n - 1)) - a[3] * np.cos(6 * np.pi * k / (n - 1))


def judge_tone(table: List[int], freq: float, phase: float) -> Dict[str, object]:
    import numpy as np

    x = tone_samples(freq, phase)
    outs, _ = bridge(table, [x])
    y = np.array(outs[0], dtype=np.float64)
    skip = 512
    seg = y[skip:]
    n = np.arange(skip, len(y), dtype=np.float64)
    w = 2.0 * math.pi * freq / OUT_RATE
    design = np.stack([np.sin(w * n), np.cos(w * n), np.ones_like(n)], axis=1)
    coef, *_ = np.linalg.lstsq(design, seg, rcond=None)
    amp = math.hypot(coef[0], coef[1])
    gain = amp / TONE_AMPLITUDE
    measured_phase = math.atan2(coef[1], coef[0])
    expected_phase = phase - 2.0 * math.pi * freq * DELAY_IN_FRAMES / IN_RATE
    dphase = (measured_phase - expected_phase + math.pi) % (2.0 * math.pi) - math.pi
    window = blackman_harris(4096)
    tail = seg[-4096:]
    spectrum = np.abs(np.fft.rfft(tail * window))
    bin_hz = OUT_RATE / 4096.0
    centre = int(round(freq / bin_hz))
    peak = float(np.max(spectrum[max(centre - 4, 0):centre + 5]))
    mask = np.ones(len(spectrum), dtype=bool)
    mask[max(centre - 8, 0):centre + 9] = False
    spur_db = 20.0 * math.log10(float(np.max(spectrum[mask])) / peak)
    ok = abs(gain - 1.0) <= GAIN_TOLERANCE and abs(dphase) <= PHASE_TOLERANCE_RAD and spur_db <= SPUR_LIMIT_DB
    return {"freq_hz": freq, "gain": gain, "phase_error_rad": dphase, "spur_db": spur_db, "ok": ok}


def judge_scipy(table: List[int]) -> Dict[str, object]:
    import numpy as np
    from scipy.signal import resample_poly

    freqs = (440.0, 2500.0, 7000.0, 13000.0)
    frames = 6000
    base = np.zeros(frames)
    for f in freqs:
        base += np.array([int(round((1 << 20) * math.sin(2.0 * math.pi * f * n / IN_RATE + 0.3))) for n in range(frames)], dtype=np.float64)
    x_int = [int(v) for v in base]
    mine = np.array(bridge(table, [x_int])[0][0], dtype=np.float64)
    # Delay the input by the bridge's stated 32 frames; the reference then lands on the same output grid as the bridge.
    shifted = np.concatenate([np.zeros(DELAY_IN_FRAMES), base])
    theirs = resample_poly(shifted, L, M)[:len(mine)]
    lo, hi = 512, len(mine) - 512
    diff = mine[lo:hi] - theirs[lo:hi]
    rel = float(np.sqrt(np.mean(diff ** 2)) / np.sqrt(np.mean(mine[lo:hi] ** 2)))
    return {"rms_relative_difference": rel, "limit": SCIPY_RMS_TOLERANCE, "ok": rel <= SCIPY_RMS_TOLERANCE}


def quality() -> Tuple[int, Dict[str, object]]:
    try:
        import numpy  # noqa: F401
        import scipy  # noqa: F401
    except Exception as err:  # numpy/scipy missing: BLOCKED, never a pass
        return 3, {"blocked": "numpy/scipy unavailable: %s" % err}
    table = load_table()
    report: Dict[str, object] = {"table": judge_table(table), "tones": [], "scipy": judge_scipy(table)}
    for freq in TONES_HZ:
        for phase in (0.0, math.pi / 2.0):
            report["tones"].append(judge_tone(table, freq, phase))
    exact_dc = bridge(table, [[1000 << 8] * 200])[0][0]
    steady = exact_dc[(outputs_after(K)):]
    report["dc_exact"] = {"ok": bool(steady) and all(v == 1000 << 8 for v in steady), "checked": len(steady)}
    ok = report["table"]["ok"] and report["scipy"]["ok"] and all(t["ok"] for t in report["tones"]) and report["dc_exact"]["ok"]
    return (0 if ok else 1), report


def render(doc: Dict[str, object]) -> str:
    """Compact JSON, one case per line (the explicit tone inputs would otherwise make a very long file)."""
    def compact(value: object) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    parts = []
    for key in sorted(doc):
        if key == "cases":
            parts.append('"cases":[\n' + ",\n".join(compact(case) for case in doc["cases"]) + "\n]")
        else:
            parts.append(json.dumps(key) + ":" + compact(doc[key]))
    return "{\n" + ",\n".join(parts) + "\n}\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write-vectors")
    g.add_argument("--check-vectors")
    g.add_argument("--quality", action="store_true")
    args = ap.parse_args()
    if args.quality:
        rc, report = quality()
        print(json.dumps(report, indent=1, sort_keys=True))
        return rc
    try:
        import numpy  # noqa: F401
    except Exception as err:
        print("BLOCKED: numpy unavailable: %s" % err, file=sys.stderr)
        return 3
    doc = derive(load_table())
    text = render(doc)
    if args.write_vectors:
        with open(args.write_vectors, "x", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote %s (%d bytes, %d cases)" % (args.write_vectors, len(text), len(doc["cases"])))
        return 0
    with open(args.check_vectors, encoding="utf-8") as f:
        have = f.read()
    if have != text:
        print("DIFFERENT from a fresh derivation", file=sys.stderr)
        return 1
    print("identical to a fresh derivation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
