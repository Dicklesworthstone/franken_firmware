"""Realtime profile boundaries, each probed at the edge and one step past it, through the real engine and the independent reference.

An additive control (root 8979), not a replacement for any world in vectors.json and not part of the paired trace. The music profile's edges are
already worlds (W08 horizon +93/+94, W12 notice, W12B/C step); the realtime profile's were only in the frozen table (n04_profiles_are_the_frozen_table),
so a realtime horizon, notice or step that drifted would not have moved any engine result. Three tiny realtime worlds, each probing ONE rule:

* B01 horizon: a packet for block cursor+8 (the last of the 9 slots) is admitted and plays; cursor+9 is refused ``too_far_ahead`` and never queued.
* B02 notice: a change effective at exactly cursor+2 blocks is accepted; at cursor+1 it is refused ``too_soon``.
* B03 step: a step of exactly 4 blocks is accepted; 4 blocks and one nanosecond, and 5 blocks, are refused ``transition_too_large``.

The expectations (``expect``) are written here from the contract, not read from the reference; the reference then has to agree with them
(``expected_record``), and the Rust replays the same ops and checks the same expectations.
"""
from __future__ import annotations

import functools
import json

import generate as gen

R = gen.R
SCHEMA = "ffw.n04.realtime-boundaries.v1"
RECORD_ID = "n04-realtime-boundaries"


def horizon() -> "gen.W":
    w = gen.W("B01-REALTIME-HORIZON", "realtime",
              "cursor+8 is the last slot of the 9-block realtime horizon and plays; cursor+9 is too far ahead and is never queued",
              ["boundary", "window"])
    w.begin()
    t0 = gen.P(0) - gen.EARLY["realtime"]
    w.packet(t0, 8, label="last-slot")
    w.packet(t0 + 1, 9, label="one-past")
    for b in range(10):
        w.decide_at_cutoff(b, label="d%d" % b)
    w.add(["stats"], "stats")
    w.ex("last-slot", "r", "admitted")
    w.ex("one-past", "r", "too_far_ahead")
    w.ex("d0", "d.outcome", "muted_nohistory")           # nothing has played yet, so there is nothing to conceal with
    w.ex("d7", "d.outcome", "muted_nohistory")
    w.ex("d8", "d.outcome", "real")                       # the permitted edge block really plays
    w.ex("d9", "d.outcome", "concealed")                  # the refused block was never queued: block 9 is concealed, not played
    w.ex("stats", "stats.admitted", 1)
    w.ex("stats", "stats.too_far_ahead", 1)
    return w


def _anchor(effective_block: int, delta_ns: int) -> int:
    """The new anchor of a change at ``effective_block`` that moves the timeline by ``delta_ns`` (the stream began at frame 0, ns ANCHOR)."""
    return gen.ANCHOR + R.frames_to_ns(effective_block * 256) + delta_ns


def notice() -> "gen.W":
    w = gen.W("B02-REALTIME-NOTICE", "realtime",
              "a coordinated change must take effect at least 2 blocks ahead: exactly 2 is accepted, 1 is too soon",
              ["boundary", "latency"])
    w.begin()
    w.add(["change", 1, 1, 1 * 256, _anchor(1, gen.BNS)], "ch-1-block")     # eb 1 < cursor 0 + notice 2
    w.add(["change", 1, 1, 2 * 256, _anchor(2, gen.BNS)], "ch-2-blocks")    # eb 2 == cursor 0 + notice 2; a refusal consumed no change id
    w.add(["stats"], "stats")
    w.ex("ch-1-block", "ok", False)
    w.ex("ch-1-block", "reason", "too_soon")
    w.ex("ch-2-blocks", "ok", True)
    w.ex("ch-2-blocks", "reason", "accepted")
    w.ex("ch-2-blocks", "delta_ns", gen.BNS)
    w.ex("stats", "stats.changes_applied", 1)
    return w


def step() -> "gen.W":
    w = gen.W("B03-REALTIME-STEP", "realtime",
              "the largest single step is exactly 4 blocks: 4 is accepted, 4 blocks and one nanosecond and 5 blocks are refused",
              ["boundary", "latency"])
    w.begin()
    fe = 4                                                    # inside the notice (>= 2) and the horizon (<= 9), so only the step rule is in play
    limit = R.frames_to_ns(4 * 256)
    w.add(["change", 1, 1, fe * 256, _anchor(fe, R.frames_to_ns(5 * 256))], "ch-5-blocks")
    w.add(["change", 1, 1, fe * 256, _anchor(fe, limit + 1)], "ch-4-blocks-plus-1ns")
    w.add(["change", 1, 1, fe * 256, _anchor(fe, limit)], "ch-4-blocks")
    w.add(["stats"], "stats")
    w.ex("ch-5-blocks", "ok", False)
    w.ex("ch-5-blocks", "reason", "transition_too_large")
    w.ex("ch-4-blocks-plus-1ns", "ok", False)
    w.ex("ch-4-blocks-plus-1ns", "reason", "transition_too_large")
    w.ex("ch-4-blocks", "ok", True)
    w.ex("ch-4-blocks", "reason", "accepted")
    w.ex("ch-4-blocks", "delta_ns", limit)
    w.ex("stats", "stats.changes_applied", 1)
    return w


def _dig(value, path: str):
    for part in path.split("."):
        value = value[part]
    return value


@functools.lru_cache(maxsize=1)
def fixture() -> dict:
    docs = [world.doc() for world in (horizon(), notice(), step())]
    worlds = [dict(id=d["id"], profile=d["profile"], cfg=d["cfg"], note=d["note"], ops=d["ops"], labels=d["labels"], expect=d["expect"])
              for d in docs]
    digests = {d["id"]: gen.digest(gen.world_results(dict(profile=d["profile"], cfg=d["cfg"], ops=d["ops"]))) for d in docs}
    return dict(schema=SCHEMA, worlds=worlds, trace_digest=gen.digest([w["ops"] for w in worlds]), expected_digests=digests)


def check_world(world: dict) -> list:
    """Run one fixture world through the reference and hold it to its hand-written expectations (AssertionError otherwise); returns the results."""
    results = gen.world_results(dict(profile=world["profile"], cfg=world["cfg"], ops=world["ops"]))
    for e in world["expect"]:
        got = _dig(results[world["labels"][e["label"]]], e["key"])
        assert got == e["value"], "%s: %s.%s is %r, the contract says %r" % (world["id"], e["label"], e["key"], got, e["value"])
    return results


@functools.lru_cache(maxsize=1)
def expected_record() -> dict:
    doc = fixture()
    profile = R.PROFILES["realtime"]
    # The edges above are derived from this table; if it changes, the fixture must be rethought, not silently re-aimed.
    assert (profile["horizon"], profile["notice"], profile["max_step"]) == (9, 2, 4), profile
    worlds = []
    for world in doc["worlds"]:
        results = check_world(world)
        worlds.append(dict(id=world["id"], digest=gen.digest(results), results=results))
    return dict(id=RECORD_ID, trace_digest=doc["trace_digest"], worlds=worlds)


def compare_record(want: dict, got: dict) -> str | None:
    """Keep a changed fixture distinct from a changed result and name the first divergent operation of the first divergent world."""
    for field in ("id", "trace_digest"):
        if got.get(field) != want[field]:
            return "boundary fixture identity %s differs: observed %r, expected %r" % (field, got.get(field), want[field])
    worlds = got.get("worlds")
    ids = [w.get("id") if isinstance(w, dict) else None for w in worlds] if isinstance(worlds, list) else None
    if ids != [w["id"] for w in want["worlds"]]:
        return "boundary worlds must be %r, in order; observed %r" % ([w["id"] for w in want["worlds"]], ids)
    ops = {w["id"]: w["ops"] for w in fixture()["worlds"]}
    for expected, actual in zip(want["worlds"], worlds):
        results = actual.get("results")
        if not isinstance(results, list) or len(results) != len(expected["results"]):
            return "%s result count differs" % expected["id"]
        for index, (observed, reference) in enumerate(zip(results, expected["results"])):
            if observed != reference:
                return "%s op %d (%s): observed %r, reference %r" % (expected["id"], index, ops[expected["id"]][index][0], observed, reference)
        if actual.get("digest") != expected["digest"]:
            return "%s result digest differs" % expected["id"]
    return None


if __name__ == "__main__":
    # Generating this additive fixture never rewrites vectors.json or paired_trace.json.
    print(json.dumps(fixture(), sort_keys=True, separators=(",", ":")))
