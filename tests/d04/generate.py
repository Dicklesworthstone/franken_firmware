#!/usr/bin/env python3
"""Write tests/d04/scenarios.json: the scripted runs and what the independent model says happens.

    python3 -B -I tests/d04/generate.py            # rewrite the file
    python3 -B -I tests/d04/generate.py --check    # exit 1 if the committed file differs

The Rust test replays every scenario through the real render loop and compares block by block, so
the expected values here come from reference.py and from nothing the Rust produced.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import reference  # noqa: E402

OUT = os.path.join(HERE, "scenarios.json")
SCHEMA = "ffw.d04.scenarios.v1"

CONFIG: Dict[str, int] = {
    "block_frames": 64, "frame_bytes": 4, "period": 4, "window": 3, "reserve_percent": 25,
    "reserve_slots": 1, "ring_depth": 4, "attempts": 2, "watchdog_misses": 3,
}

#: id, what, and the script. Costs, delays and starvation are keyed by block index.
SCRIPTS: List[Dict[str, Any]] = [
    {"id": "D04-TIM-001", "what": "steady state: every block is released on the period and finishes in one tick",
     "ticks": 24},
    {"id": "D04-TIM-002", "what": "deadline boundary pair: a render ending exactly on its deadline is on time, one tick later is dropped",
     "ticks": 10, "costs": {"0": 3, "1": 4}},
    {"id": "D04-TIM-003", "what": "timer delay: a late wake-up that still meets the deadline is on time, one that does not is a CPU miss",
     "ticks": 10, "delays": {"0": 2, "1": 3}},
    {"id": "D04-TIM-004", "what": "a render longer than the period delays the next block instead of overlapping it",
     "ticks": 10, "costs": {"0": 6}},
    {"id": "D04-TIM-005", "what": "three consecutive CPU misses trip the watchdog; later ticks do nothing",
     "ticks": 22, "costs": {"0": 6, "1": 6, "2": 6}},
    {"id": "D04-SRC-001", "what": "ingress loss and decode delay are counted apart; only lost content starts a new epoch",
     "ticks": 24, "starve": {"1": "ingress_loss", "2": "ingress_loss", "4": "decode_delay"}},
    {"id": "D04-SRC-002", "what": "a single lost block and then the stream returns: one new epoch, no other effect",
     "ticks": 16, "starve": {"1": "ingress_loss"}},
    {"id": "D04-CAP-001", "what": "slow completions fill the ordinary share of the ring; the reserve slot is never spent and capacity returns as completions do",
     "ticks": 40, "completion_delay": 20},
    {"id": "D04-SUB-001", "what": "a device that takes 16 frames per call takes 32 of a 64-frame block in two attempts; the rest is discarded",
     "ticks": 6, "accept_limit": 64},
    {"id": "D04-SUB-002", "what": "a device that takes half a block per call takes all of it in two attempts",
     "ticks": 6, "accept_limit": 128},
    {"id": "D04-MIX-001", "what": "a late render, a decode delay, lost content and a late wake-up in one run",
     "ticks": 40, "costs": {"2": 4}, "starve": {"4": "decode_delay", "5": "ingress_loss"}, "delays": {"7": 1}},
    {"id": "D04-MIX-002", "what": "slow completions and a short-writing device together: capacity rejection and a discarded remainder",
     "ticks": 30, "completion_delay": 20, "accept_limit": 128},
]


def build() -> Dict[str, Any]:
    scenarios = []
    for script in SCRIPTS:
        scenario = reference.Scenario(script)
        result = reference.simulate(CONFIG, scenario)
        problems = reference.identities_hold(result, CONFIG["block_frames"])
        if problems:
            raise SystemExit(f"{script['id']}: the model breaks its own identities: {problems}")
        entry = dict(script)
        entry["expect"] = {
            "finished": result["finished"],
            "counters": result["counters"],
            "state": result["state"],
            "now": result["now"],
        }
        scenarios.append(entry)
    return {"schema": SCHEMA,
            "note": "Scripted runs and the outcome the independent model in reference.py gives them. "
                    "The Rust test in crates/franken-speaker/src/render.rs replays each through the real loop.",
            "config": CONFIG, "scenarios": scenarios}


def render(doc: Dict[str, Any]) -> str:
    lines = ['{', f' "schema": {json.dumps(doc["schema"])},', f' "note": {json.dumps(doc["note"])},',
             f' "config": {json.dumps(doc["config"])},', ' "scenarios": [']
    last = len(doc["scenarios"]) - 1
    for i, sc in enumerate(doc["scenarios"]):
        lines.append("  " + json.dumps(sc, separators=(", ", ": ")) + ("," if i != last else ""))
    lines += [" ]", "}", ""]
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    text = render(build())
    if "--check" in argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            current = ""
        if current != text:
            print("tests/d04/scenarios.json differs from what reference.py produces", file=sys.stderr)
            return 1
        print("scenarios.json matches the model")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {OUT} ({len(SCRIPTS)} scenarios)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
