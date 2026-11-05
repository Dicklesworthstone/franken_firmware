"""Independent model of the D04 render loop's timing, classification and accounting.

Written from docs/contracts/d04.md without reading crates/franken-speaker/src/render.rs. It models
only what the contract says is decided by ticks and counters: when a block starts, whether it meets
its deadline, how it ends, what is in flight, and when the watchdog trips. It does not model audio
samples (see the contract: the sample path is checked by a differential test and is stated there as
not independently modelled here).

The model and the Rust loop share an author. Agreement shows the arithmetic was done twice by two
routes; it does not show the contract is right.

Everything is integers and ticks. Standard library only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

#: The counters a scenario pins, in the order the contract lists them.
COUNTER_KEYS = (
    "blocks_started", "blocks_on_time", "ingress_loss_blocks", "decode_delay_blocks",
    "cpu_miss_blocks", "capacity_rejected_blocks", "short_write_blocks", "late_wakes",
    "reserve_breaches", "frames_generated", "frames_submitted", "frames_dropped_late",
    "frames_dropped_capacity", "frames_discarded_short", "silence_frames_ingress",
    "silence_frames_decode", "max_cost_ticks", "max_late_ticks", "epoch_resets",
)

#: Planted defects the runner must be able to see (each is a wrong rule, switched on by name).
DEFECTS = (
    "deadline_off_by_one",   # a block finishing exactly on its deadline is called late
    "submit_late_blocks",    # a late block is submitted instead of dropped
    "start_while_busy",      # the next block starts at its release even while the previous is rendering
    "merge_causes",          # ingress loss and decode delay share one counter
    "reserve_spendable",     # ordinary blocks may use the cleanup reserve slot
    "no_resync",             # content lost on the way in does not start a new epoch
)


class Scenario:
    """A scripted run. All keys are optional except ``ticks``."""

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.ticks: int = raw["ticks"]
        self.default_cost: int = raw.get("default_cost", 1)
        self.costs: Dict[int, int] = {int(k): v for k, v in raw.get("costs", {}).items()}
        self.delays: Dict[int, int] = {int(k): v for k, v in raw.get("delays", {}).items()}
        # block index -> cause, applied when that block starts
        self.starve: Dict[int, str] = {int(k): v for k, v in raw.get("starve", {}).items()}
        self.completion_delay: int = raw.get("completion_delay", 2)
        self.accept_limit: Optional[int] = raw.get("accept_limit")


def outcome_name(kind: str, **kw: int) -> str:
    """The encoding scenarios.json uses for a block outcome."""
    if kind == "cpu_miss":
        return f"cpu_miss:{kw['late_by']}"
    if kind == "short_write":
        return f"short_write:{kw['discarded']}"
    if kind == "starved":
        return f"starved:{kw['cause']}:{kw['silence']}"
    return kind


def simulate(cfg: Dict[str, int], scenario: Scenario, defect: Optional[str] = None) -> Dict[str, Any]:
    """Run the scripted scenario and return {finished, counters, state, fault, now}.

    ``finished`` is a list of [block, tick, outcome-name]. A block is released at ``1 + k * period``
    and must be submitted by ``release + window``; the one CPU does one block at a time; a block
    that finishes after its deadline is dropped, not submitted.
    """
    assert defect is None or defect in DEFECTS, defect
    period, window = cfg["period"], cfg["window"]
    frames = cfg["block_frames"]
    frame_bytes = cfg["frame_bytes"]
    ring_depth, reserve = cfg["ring_depth"], cfg["reserve_slots"]
    reserve_percent = cfg["reserve_percent"]
    attempts_max, watchdog = cfg["attempts"], cfg["watchdog_misses"]

    ordinary_cap = ring_depth if defect == "reserve_spendable" else ring_depth - reserve
    counters = {k: 0 for k in COUNTER_KEYS}
    finished: List[List[Any]] = []
    due: List[int] = []                 # completion tick of each slot the device holds
    now = 0
    state, fault = "running", None
    next_index = 0
    scheduled = False
    next_start = 0
    next_delay = 0
    busy: Optional[Dict[str, Any]] = None
    resync_pending = False
    consecutive_misses = 0

    def release(k: int) -> int:
        return 1 + k * period

    def deadline(k: int) -> int:
        return release(k) + window

    def finish(block: Dict[str, Any]) -> None:
        nonlocal consecutive_misses, state, fault, resync_pending
        late_by = max(0, now - block["deadline"])
        if defect == "deadline_off_by_one":
            late_by = max(late_by, 1 if now >= block["deadline"] else 0)
        n = block["frames"]
        outcome: Optional[str] = None
        if late_by > 0 and defect != "submit_late_blocks":
            counters["cpu_miss_blocks"] += 1
            counters["frames_dropped_late"] += n
            counters["max_late_ticks"] = max(counters["max_late_ticks"], late_by)
            consecutive_misses += 1
            outcome = outcome_name("cpu_miss", late_by=late_by)
        else:
            consecutive_misses = 0
            outcome = submit(block)
        finished.append([block["index"], now, outcome])
        if consecutive_misses >= watchdog:
            state, fault = "faulted", "watchdog_tripped"

    def submit(block: Dict[str, Any]) -> str:
        n = block["frames"]
        in_flight = len(due)
        if in_flight >= ordinary_cap:
            counters["capacity_rejected_blocks"] += 1
            counters["frames_dropped_capacity"] += n
            return "capacity_rejected"
        total = n * frame_bytes
        offset = 0
        for _ in range(attempts_max):
            if offset >= total:
                break
            take = total - offset
            if scenario.accept_limit is not None:
                take = min(take, scenario.accept_limit)
            if take > 0:
                due.append(now + scenario.completion_delay)
                offset += take
        counters["frames_submitted"] += offset // frame_bytes
        if offset < total:
            discarded = (total - offset) // frame_bytes
            counters["short_write_blocks"] += 1
            counters["frames_discarded_short"] += discarded
            return outcome_name("short_write", discarded=discarded)
        starved = block["starved"]
        if starved is not None:
            cause, silence = starved
            if cause == "ingress_loss" or defect == "merge_causes":
                counters["ingress_loss_blocks"] += 1
                counters["silence_frames_ingress"] += silence
            else:
                counters["decode_delay_blocks"] += 1
                counters["silence_frames_decode"] += silence
            return outcome_name("starved", cause=cause, silence=silence)
        counters["blocks_on_time"] += 1
        return "on_time"

    def start(k: int, delay: int) -> None:
        nonlocal busy, next_index, scheduled, resync_pending
        cause = scenario.starve.get(k)
        if resync_pending and cause is None and defect != "no_resync":
            counters["epoch_resets"] += 1
            resync_pending = False
        starved = None
        if cause is not None:
            starved = (cause, frames)
            if cause == "ingress_loss":
                resync_pending = True
        cost = scenario.costs.get(k, scenario.default_cost)
        block = {"index": k, "complete": now + cost, "deadline": deadline(k), "frames": frames,
                 "starved": starved}
        counters["blocks_started"] += 1
        counters["frames_generated"] += frames
        counters["max_cost_ticks"] = max(counters["max_cost_ticks"], cost)
        if delay > 0:
            counters["late_wakes"] += 1
        if cost * 100 > window * (100 - reserve_percent):
            counters["reserve_breaches"] += 1
        next_index += 1
        scheduled = False
        busy = block
        if cost == 0:
            busy = None
            finish(block)

    for _ in range(scenario.ticks):
        if state != "running":
            break
        now += 1
        due[:] = [d for d in due if d > now]            # completions the device reported this tick
        if busy is not None and now >= busy["complete"]:
            block, busy = busy, None
            finish(block)
            if state != "running":
                break
        if busy is None or defect == "start_while_busy":
            if not scheduled:
                next_delay = scenario.delays.get(next_index, 0)
                next_start = release(next_index) + next_delay
                scheduled = True
            if now >= next_start:
                start(next_index, next_delay)
    return {"finished": finished, "counters": counters, "state": state, "fault": fault, "now": now}


def identities_hold(result: Dict[str, Any], block_frames: int) -> List[str]:
    """The two partitions every run must satisfy once no block is in progress."""
    c = result["counters"]
    problems = []
    outcomes = (c["blocks_on_time"] + c["ingress_loss_blocks"] + c["decode_delay_blocks"]
                + c["cpu_miss_blocks"] + c["capacity_rejected_blocks"] + c["short_write_blocks"])
    if outcomes != len(result["finished"]):
        problems.append(f"outcomes {outcomes} != finished blocks {len(result['finished'])}")
    frames = (c["frames_submitted"] + c["frames_dropped_late"] + c["frames_dropped_capacity"]
              + c["frames_discarded_short"])
    finished_frames = len(result["finished"]) * block_frames
    if frames != finished_frames:
        problems.append(f"frames accounted {frames} != frames of finished blocks {finished_frames}")
    return problems
