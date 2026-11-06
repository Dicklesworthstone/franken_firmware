#!/usr/bin/env python3
"""A line-by-line Python transliteration of `RateBridge::process`/`emit` in crates/franken-codec/src/rate_bridge.rs (ring buffer, incremental (m, r),
wrapping index arithmetic, per-sample rounding). It exists because the Rust is delivered UNCOMPILED: it shows that THE ALGORITHM AS WRITTEN reproduces the
closed-form reference vectors, so a central failure would point at Rust syntax or typing, not at the index logic. It is not the reference and not
evidence the Rust ran. Run it: bridge_mirror.py [vectors.json]"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import bridge_reference as ref  # noqa: E402

UP, DOWN, TAPS, Q = 160, 147, 64, 30
MASK64 = (1 << 64) - 1
Q23_MAX, Q23_MIN = 8_388_607, -8_388_608


class Bridge:
    def __init__(self, channels: int, table):
        self.ch = channels
        self.table = table
        self.ring = [0] * (TAPS * 2)
        self.m = 0
        self.r = 0
        self.in_frames = 0
        self.out_frames = 0
        self.clipped = 0

    def emit(self):
        ch = self.ch
        base = self.r * TAPS
        dst = []
        for c in range(ch):
            acc = 0
            for k in range(TAPS):
                idx = (((self.m - k) & MASK64) & (TAPS - 1)) * ch + c
                acc += self.table[base + k] * self.ring[idx]
            rounded = (acc + (1 << (Q - 1))) >> Q
            if rounded > Q23_MAX:
                self.clipped += 1
                rounded = Q23_MAX
            elif rounded < Q23_MIN:
                self.clipped += 1
                rounded = Q23_MIN
            dst.append(rounded)
        return dst

    def process(self, frames_in):
        out = []
        for frame in frames_in:
            j = self.in_frames
            slot = (j & (TAPS - 1)) * self.ch
            self.ring[slot:slot + self.ch] = frame
            self.in_frames += 1
            while self.m == j:
                out.extend(self.emit())
                self.out_frames += 1
                self.r += DOWN
                if self.r >= UP:
                    self.r -= UP
                    self.m += 1
        return out


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "crates", "franken-codec", "tests", "vectors", "s02_bridge_vectors.json")
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    table = ref.load_table()
    bad = 0
    for case in doc["cases"]:
        chans = ref.make_input(case["input"])
        frames = list(zip(*chans))
        frames = [list(f) for f in frames]
        if case["flush"]:
            frames += [[0] * len(chans) for _ in range(TAPS)]
        bridge = Bridge(len(chans), table)
        out = bridge.process(frames)
        h = "0x%016x" % ref.oracle.fnv1a64(ref.be_i32(out))
        ok = (h == case["out_fnv1a64"] and bridge.out_frames == case["frames_out"] and bridge.clipped == case["clipped"])
        print(("ok   " if ok else "FAIL ") + case["id"], bridge.out_frames, bridge.clipped)
        bad += 0 if ok else 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
