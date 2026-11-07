"""One frozen arrival/fault schedule replayed unchanged under both N04 policies.

This is an additive control, not a replacement for any world in vectors.json. Expected
results come from the independent Python engine; the Rust replays the committed ops.
"""
from __future__ import annotations

import functools
import json

import generate as gen

SEED = 0x4E30_5041
BLOCKS = 700
PROFILES = ("music", "realtime")


def schedule(seed: int = SEED) -> list:
    """Reuse the existing xorshift schedule, then settle every output with a fixed backpressure pattern."""
    world = gen.seeded("PAIRED", "music", seed, BLOCKS, 50_000_000, 35_000_000,
                       10, 300, 19, 30, 30, 30).doc()
    ops = []
    block = 0
    for op in world["ops"]:
        ops.append(op)
        if op[0] == "decide":
            deadline = gen.P(block) - gen.CFG["lead_ns"]
            # A ring-full refusal, a one-nanosecond late submission, and a permitted on-deadline submission.
            accepted_at = None if block % 23 == 0 else deadline + (1 if block % 17 == 0 else 0)
            ops.append(["deliver", accepted_at])
            block += 1
    assert block == BLOCKS
    return ops


def world(profile: str, ops: list) -> dict:
    return dict(profile=profile, cfg=dict(gen.CFG), ops=ops)


@functools.lru_cache(maxsize=1)
def fixture() -> dict:
    ops = schedule()
    digests = {profile: gen.digest(gen.world_results(world(profile, ops))) for profile in PROFILES}
    return dict(schema="ffw.n04.paired-trace.v1", seed=SEED, blocks=BLOCKS, cfg=dict(gen.CFG),
                ops=ops, trace_digest=gen.digest(ops), expected_digests=digests)


@functools.lru_cache(maxsize=1)
def expected_record() -> dict:
    doc = fixture()
    policies = []
    for profile in PROFILES:
        results = gen.world_results(world(profile, doc["ops"]))
        decisions = [result["d"] for result in results if result.get("poll") == "decision"]
        # Own arithmetic over model output: one ordered decision for each 256-frame input position; no pending poll.
        assert [decision["block"] for decision in decisions] == list(range(BLOCKS))
        assert sum(op[0] == "decide" for op in doc["ops"]) == len(decisions)
        assert all(decision["frames"] == (256 if decision["outcome"] in ("real", "concealed") else 0)
                   for decision in decisions)
        outcomes = {decision["outcome"] for decision in decisions}
        assert {"real", "concealed", "muted_gap"} <= outcomes
        assert {result.get("delivery") for result in results} >= {"delivered", "abandoned"}
        assert max(decision.get("run", 0) for decision in decisions) == (8 if profile == "music" else 3)
        policies.append(dict(profile=profile, trace_digest=doc["trace_digest"],
                             digest=gen.digest(results), results=results))
    return dict(id="n04-paired-seeded", seed=SEED, blocks=BLOCKS, trace_digest=doc["trace_digest"], policies=policies)


def compare_record(want: dict, got: dict) -> str | None:
    """Keep a changed trace distinct from a policy result error and name the first causal operation."""
    for field in ("id", "seed", "blocks", "trace_digest"):
        if got.get(field) != want[field]:
            return "paired trace identity %s differs: observed %r, expected %r" % (field, got.get(field), want[field])
    policies = got.get("policies")
    if not isinstance(policies, list) or len(policies) != len(PROFILES):
        return "paired policies must contain music and realtime exactly once, in order"
    for expected, actual in zip(want["policies"], policies):
        if not isinstance(actual, dict):
            return "paired policy result is not an object"
        profile = expected["profile"]
        for field in ("profile", "trace_digest"):
            if actual.get(field) != expected[field]:
                return "%s paired trace identity %s differs" % (profile, field)
        results = actual.get("results")
        if not isinstance(results, list) or len(results) != len(expected["results"]):
            return "%s paired result count differs" % profile
        for index, (observed, reference) in enumerate(zip(results, expected["results"])):
            if observed != reference:
                return "%s paired op %d (%s): observed %r, reference %r" % (
                    profile, index, fixture()["ops"][index][0], observed, reference)
        if actual.get("digest") != expected["digest"]:
            return "%s paired result digest differs" % profile
    return None


if __name__ == "__main__":
    # Redirect only this additive fixture; generating it never rewrites the original vectors or their goldens.
    print(json.dumps(fixture(), sort_keys=True, separators=(",", ":")))
