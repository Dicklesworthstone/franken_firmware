#!/usr/bin/env python3
"""Tests for oracles.py (Q00 / ffw-2qz).  Standard library `unittest` only.

Run:  python3 -m unittest -v test_oracles          (from this directory)
  or: python3 test_oracles.py

Independence of these tests from the code they check:
* oracle-level cases use hand-written literal traces and a ramp reference whose
  expected values are plain arithmetic written here, not produced by oracles.py;
* the SplitMix64 and reference-signal checks use published known-answer vectors
  and a second, sequential code path;
* mutation tests plant a defect whose kind and position are known from how the
  test built it, then require the oracle to report exactly that;
* meta tests swap in oracles that cannot complain (or always complain) and
  require the canary harness to report failure.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

_HERE = Path(__file__).resolve().parent
try:  # package context (after P01 integration)
    from . import oracles
except ImportError:  # script / top-level discovery
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    import oracles

ORACLES_PY = _HERE / "oracles.py"


def ev(kind: str, t: int, **fields):
    event = {"kind": kind, "t_ns": t}
    event.update(fields)
    return event


def drive(oracle, events, end_t=None):
    for event in events:
        oracle.observe(event)
    return oracle.finalize(end_t_ns=end_t)


class RampReference(oracles.ReferenceSignal):
    """Literal reference: sample(frame, channel) = 100 * frame + channel."""

    def __init__(self, channels: int = 2) -> None:
        self.channels = channels
        self.stream = "ramp"

    def sample(self, frame: int, channel: int) -> int:
        return 100 * frame + channel


def ramp_samples(start: int, frames: int, channels: int = 2):
    return [100 * f + c for f in range(start, start + frames) for c in range(channels)]


def blk(t: int, start: int, frames: int, samples=None, **extra):
    return ev("audio_block", t, start_frame=start, channels=2,
              samples=ramp_samples(start, frames) if samples is None else samples, **extra)


ORACLE_CLASSES = {
    "sample": oracles.SampleOracle,
    "epoch": oracles.EpochOracle,
    "command": oracles.CommandOracle,
    "readiness": oracles.ReadinessOracle,
    "priority_stop": oracles.PriorityStopOracle,
}


def swapped_factory(oracle_name, cls):
    """Oracle factory that replaces one standard oracle with `cls`, built with the same configuration."""

    def factory(arg):
        if oracle_name == "priority_stop":
            return [cls(sample_rate_hz=arg.sample_rate_hz, deadline_ns=arg.deadline_ns)]
        p = arg.profile
        builders = {
            "sample": lambda: cls(oracles.ReferenceSignal(arg.seed, "main", p.channels),
                                  expected_total_frames=p.blocks * p.block_frames,
                                  permitted_gaps=arg.dropped_ranges()),
            "epoch": lambda: cls(require_stale_exercised=True),
            "command": lambda: cls(require_duplicate_exercised=True),
            "readiness": lambda: cls(withdraw_deadline_ns=p.withdraw_deadline_ns,
                                     announce_deadline_ns=p.announce_deadline_ns),
        }
        return [builders[oracle_name]() if o.name == oracle_name else o for o in oracles.build_house_oracles(arg)]

    return factory


def kinds_of(verdict):
    return set(verdict["violation_kinds"])


# ---------------------------------------------------------------------------
class TestRandomness(unittest.TestCase):
    def test_splitmix64_published_vectors(self):
        # Vigna's reference splitmix64.c, seed 0.
        g = oracles.SplitMix64(0)
        self.assertEqual([g.next_u64() for _ in range(4)],
                         [0xE220A8397B1DCDAF, 0x6E789E6AA1B965F4, 0x06C45D188009454F, 0xF88BB8A8724C81EC])
        # rand_xoshiro SplitMix64::seed_from_u64(1234567).
        g = oracles.SplitMix64(1234567)
        self.assertEqual([g.next_u64() for _ in range(5)],
                         [6457827717110365317, 3203168211198807973, 9817491932198370423,
                          4593380528125082431, 16408922859458223821])

    def test_below_and_chance_bounds(self):
        g = oracles.SplitMix64(9)
        self.assertTrue(all(0 <= g.below(7) < 7 for _ in range(500)))
        with self.assertRaises(ValueError):
            g.below(0)
        h = oracles.SplitMix64(9)
        self.assertFalse(any(h.chance_bps(0) for _ in range(500)))
        h = oracles.SplitMix64(9)
        self.assertTrue(all(h.chance_bps(10_000) for _ in range(500)))

    def test_derive_seed_is_stable_and_domain_separated(self):
        self.assertEqual(oracles.derive_seed(5, "audio"), oracles.derive_seed(5, "audio"))
        self.assertNotEqual(oracles.derive_seed(5, "audio"), oracles.derive_seed(5, "commands"))
        self.assertNotEqual(oracles.derive_seed(5, "audio"), oracles.derive_seed(6, "audio"))
        for bad in (-1, True, 1.5, "7"):
            with self.assertRaises(ValueError):
                oracles.derive_seed(bad, "x")

    def test_reference_signal_matches_sequential_generator(self):
        # Second code path: walk the generator sequentially and compare with
        # the random-access function the oracle depends on.
        ref = oracles.ReferenceSignal(321, "main", 2)
        gen = oracles.SplitMix64(oracles.derive_seed(321, "signal:main"))
        for frame in range(40):
            for ch in range(2):
                raw = gen.next_u64() >> 48
                self.assertEqual(ref.sample(frame, ch), raw - 65536 if raw >= 32768 else raw)

    def test_reference_signal_properties(self):
        ref = oracles.ReferenceSignal(1, "main", 2)
        block = ref.block(0, 256)
        self.assertEqual(len(block), 512)
        self.assertTrue(all(oracles.INT16_MIN <= s <= oracles.INT16_MAX for s in block))
        self.assertGreater(len(set(block)), 400, "reference must not be near-constant")
        self.assertNotEqual(block, oracles.ReferenceSignal(2, "main", 2).block(0, 256))
        self.assertNotEqual(block, oracles.ReferenceSignal(1, "other", 2).block(0, 256))
        self.assertEqual(ref.block(10, 5), block[20:30], "random access must agree with offset slicing")
        self.assertTrue(any(ref.block(f, 1) != [0, 0] for f in range(8)))
        with self.assertRaises(ValueError):
            oracles.ReferenceSignal(1, "main", 0)


# ---------------------------------------------------------------------------
class TestOracleBase(unittest.TestCase):
    def setUp(self):
        self.make = lambda: oracles.SampleOracle(RampReference(), expected_total_frames=3)

    def test_time_must_not_go_backwards(self):
        o = self.make()
        o.observe(blk(10, 0, 3))
        with self.assertRaises(oracles.OracleUsageError):
            o.observe(ev("noise", 9))

    def test_envelope_is_validated(self):
        o = self.make()
        for bad in ({"t_ns": 1}, {"kind": "", "t_ns": 1}, {"kind": "x"}, {"kind": "x", "t_ns": -1},
                    {"kind": "x", "t_ns": True}, {"kind": "x", "t_ns": 1.5}, "not-a-mapping"):
            with self.assertRaises(oracles.OracleUsageError, msg=repr(bad)):
                o.observe(bad)

    def test_observe_after_finalize_is_refused(self):
        o = self.make()
        drive(o, [blk(1, 0, 3)])
        with self.assertRaises(oracles.OracleUsageError):
            o.observe(ev("noise", 5))

    def test_end_time_may_not_precede_last_event(self):
        o = self.make()
        o.observe(blk(10, 0, 3))
        with self.assertRaises(oracles.OracleUsageError):
            o.finalize(end_t_ns=5)

    def test_unfinalized_oracle_is_never_passed(self):
        o = self.make()
        o.observe(blk(1, 0, 3))
        v = o.verdict()
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("not_finalized", v["incomplete_reasons"])
        self.assertEqual(o.finalize()["status"], oracles.PASSED)
        self.assertEqual(o.finalize()["status"], oracles.PASSED, "finalize is idempotent")

    def test_empty_trace_is_incomplete_not_passed(self):
        v = drive(self.make(), [])
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("no_evidence", v["incomplete_reasons"])
        self.assertEqual(v["receipt_outcome"], "blocked")
        v = drive(oracles.SampleOracle(RampReference(), expected_total_frames=3, allow_empty=True), [])
        self.assertEqual(v["status"], oracles.PASSED, "an explicit opt-out is the only way to accept an empty trace")

    def test_irrelevant_events_alone_are_not_evidence(self):
        v = drive(self.make(), [ev("noise", 1), ev("noise", 2)])
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertEqual(v["events_ignored"], 2)

    def test_duplicate_oracle_names_are_refused(self):
        with self.assertRaises(oracles.OracleUsageError):
            oracles.evaluate([], [oracles.EpochOracle(), oracles.EpochOracle()])

    def test_failed_outranks_incomplete_and_overall_status(self):
        self.assertEqual(oracles.overall_status([oracles.PASSED, oracles.INCOMPLETE]), oracles.INCOMPLETE)
        self.assertEqual(oracles.overall_status([oracles.PASSED, oracles.INCOMPLETE, oracles.FAILED]), oracles.FAILED)
        self.assertEqual(oracles.overall_status([oracles.PASSED]), oracles.PASSED)
        self.assertEqual(oracles.overall_status([]), oracles.INCOMPLETE)

    def test_malformed_dut_event_is_a_violation_not_a_crash(self):
        v = drive(self.make(), [ev("audio_block", 1, samples=[1, 2])])
        self.assertEqual(v["status"], oracles.FAILED)
        self.assertIn("malformed_event", kinds_of(v))


# ---------------------------------------------------------------------------
class TestSampleOracle(unittest.TestCase):
    def oracle(self, total=9, **kw):
        return oracles.SampleOracle(RampReference(), expected_total_frames=total, **kw)

    def test_contiguous_correct_blocks_pass(self):
        v = drive(self.oracle(), [blk(1, 0, 3), blk(2, 3, 3), blk(3, 6, 3)])
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["frames_accounted"], 9)

    def test_lost_block_is_reported_with_exact_gap(self):
        v = drive(self.oracle(), [blk(1, 0, 3), blk(2, 6, 3)])
        self.assertEqual(v["status"], oracles.FAILED)
        first = v["violations"][0]
        self.assertEqual((first["kind"], first["event_index"]), ("lost_samples", 1))
        self.assertEqual(first["expected"], {"next_frame": 3})
        self.assertEqual(first["observed"], {"start_frame": 6, "missing_frames": 3})
        self.assertEqual(kinds_of(v), {"lost_samples"})

    def test_correct_frame_counters_with_wrong_values_are_caught(self):
        # Frame numbering is perfectly continuous; only the content is wrong.
        bad = blk(2, 3, 3, samples=ramp_samples(0, 3))
        v = drive(self.oracle(), [blk(1, 0, 3), bad, blk(3, 6, 3)])
        self.assertEqual(kinds_of(v), {"wrong_samples"})
        first = v["violations"][0]
        self.assertEqual(first["expected"], {"frame": 3, "channel": 0, "value": 300})
        self.assertEqual(first["observed"]["value"], 0)
        self.assertEqual(first["observed"]["mismatched_samples"], 6)

    def test_single_off_by_one_sample_is_caught_with_position(self):
        samples = ramp_samples(3, 3)
        samples[3] += 1  # frame 4, channel 1
        v = drive(self.oracle(), [blk(1, 0, 3), blk(2, 3, 3, samples=samples), blk(3, 6, 3)])
        first = v["violations"][0]
        self.assertEqual((first["kind"], first["expected"]["frame"], first["expected"]["channel"]), ("wrong_samples", 4, 1))
        self.assertEqual((first["expected"]["value"], first["observed"]["value"]), (401, 402))

    def test_sample_values_can_be_withheld_from_diagnostics(self):
        samples = ramp_samples(0, 3)
        samples[0] = 7
        v = drive(self.oracle(total=3, include_sample_values=False), [blk(1, 0, 3, samples=samples)])
        self.assertNotIn("value", v["violations"][0]["expected"])
        self.assertNotIn("value", v["violations"][0]["observed"])
        self.assertEqual(v["violations"][0]["kind"], "wrong_samples")

    def test_repeated_block_is_reported(self):
        v = drive(self.oracle(), [blk(1, 0, 3), blk(2, 3, 3), blk(3, 3, 3), blk(4, 6, 3)])
        self.assertEqual(kinds_of(v), {"repeated_samples"})
        self.assertEqual(v["violations"][0]["observed"], {"start_frame": 3, "overlap_frames": 3})
        self.assertEqual(v["violations"][0]["event_index"], 2)

    def test_truncated_tail_is_reported_at_finalize(self):
        events = [blk(1, 0, 3), blk(2, 3, 3)]
        v = drive(self.oracle(), events)
        self.assertEqual(kinds_of(v), {"truncated_stream"})
        first = v["violations"][0]
        self.assertEqual(first["observed"], {"accounted_frames": 6, "missing_frames": 3})
        self.assertEqual(first["event_index"], len(events))
        self.assertIsNone(first["cause"])

    def test_overrun_is_reported(self):
        v = drive(self.oracle(total=6), [blk(1, 0, 3), blk(2, 3, 3), blk(3, 6, 3)])
        self.assertEqual(kinds_of(v), {"overrun_stream"})

    def test_announced_permitted_gap_is_accepted(self):
        o = self.oracle(permitted_gaps=[(3, 3)])
        v = drive(o, [blk(1, 0, 3), ev("audio_gap", 2, start_frame=3, frame_count=3, reason="network_loss"), blk(3, 6, 3)])
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["gap_frames"], 3)

    def test_gap_that_spans_adjacent_permitted_ranges_is_accepted(self):
        o = self.oracle(permitted_gaps=[(3, 1), (4, 2)])
        v = drive(o, [blk(1, 0, 3), ev("audio_gap", 2, start_frame=3, frame_count=3, reason="x"), blk(3, 6, 3)])
        self.assertEqual(v["status"], oracles.PASSED, v)

    def test_gap_over_frames_the_scenario_never_lost_is_rejected(self):
        # Laundering a DUT-side discard as "concealment".
        o = self.oracle(permitted_gaps=[(6, 3)])
        v = drive(o, [blk(1, 0, 3), ev("audio_gap", 2, start_frame=3, frame_count=3, reason="x"), blk(3, 6, 3)])
        self.assertEqual(kinds_of(v), {"unpermitted_gap"})

    def test_permitted_but_unannounced_loss_still_fails(self):
        o = self.oracle(permitted_gaps=[(3, 3)])
        v = drive(o, [blk(1, 0, 3), blk(2, 6, 3)])
        self.assertEqual(kinds_of(v), {"lost_samples"})

    def test_malformed_blocks(self):
        cases = {
            "out_of_range": ev("audio_block", 1, start_frame=0, channels=2, samples=[0, 1, 2, 40000, 4, 5]),
            "bool_sample": ev("audio_block", 1, start_frame=0, channels=2, samples=[0, 1, 2, True, 4, 5]),
            "partial_frame": ev("audio_block", 1, start_frame=0, channels=2, samples=[0, 1, 2]),
            "empty": ev("audio_block", 1, start_frame=0, channels=2, samples=[]),
            "channels": ev("audio_block", 1, start_frame=0, channels=1, samples=[0, 1, 2]),
            "not_sequence": ev("audio_block", 1, start_frame=0, channels=2, samples="abc"),
        }
        for label, event in cases.items():
            v = drive(self.oracle(total=3), [event])
            self.assertEqual(v["status"], oracles.FAILED, label)
            self.assertIn("malformed_block", kinds_of(v), label)

    def test_other_streams_are_ignored(self):
        o = self.oracle(total=3)
        v = drive(o, [blk(1, 0, 3), blk(2, 0, 3, stream="aux")])
        self.assertEqual(v["status"], oracles.PASSED)
        self.assertEqual(v["events_ignored"], 1)

    def test_unknown_total_cannot_pass(self):
        v = drive(oracles.SampleOracle(RampReference(), expected_total_frames=None), [blk(1, 0, 3)])
        self.assertEqual(v["status"], oracles.INCOMPLETE)

    def test_retained_violations_are_bounded_but_counted(self):
        o = self.oracle(total=100_000, max_violations=5)
        events = [blk(i, i * 10, 3) for i in range(1000)]
        v = drive(o, events)
        self.assertEqual(v["violation_count"], 999 + 1)  # 999 gaps + truncated tail
        self.assertEqual(v["violations_retained"], 5)
        self.assertEqual(v["violations_dropped"], 995)
        self.assertEqual(len(v["violations"]), 5)

    def test_planted_mutations_match_ground_truth(self):
        frames, nblk = 8, 8
        total = frames * nblk
        rng = random.Random(0xC0FFEE)

        def stream(blocks):
            return [blk(i * 10, s, frames, samples=smp) for i, (s, smp) in enumerate(blocks)]

        good = [(i * frames, ramp_samples(i * frames, frames)) for i in range(nblk)]
        positive = drive(self.oracle(total=total), stream(good))
        self.assertEqual(positive["status"], oracles.PASSED, "unmutated stream must be accepted")
        seen = set()
        for _ in range(150):
            kind = rng.choice(["drop", "dup", "corrupt", "truncate", "swap"])
            k = rng.randrange(1, nblk - 2)
            blocks = list(good)
            if kind == "drop":
                del blocks[k]
                expect_first, expect_idx, expect_kinds = "lost_samples", k, {"lost_samples"}
            elif kind == "dup":
                blocks.insert(k + 1, blocks[k])
                expect_first, expect_idx, expect_kinds = "repeated_samples", k + 1, {"repeated_samples"}
            elif kind == "corrupt":
                s, smp = blocks[k]
                smp = list(smp)
                pos = rng.randrange(len(smp))
                smp[pos] += 1
                blocks[k] = (s, smp)
                expect_first, expect_idx, expect_kinds = "wrong_samples", k, {"wrong_samples"}
            elif kind == "truncate":
                m = rng.randrange(1, 4)
                blocks = blocks[:-m]
                expect_first, expect_idx, expect_kinds = "truncated_stream", len(blocks), {"truncated_stream"}
            else:
                blocks[k], blocks[k + 1] = blocks[k + 1], blocks[k]
                expect_first, expect_idx, expect_kinds = "lost_samples", k, {"lost_samples", "repeated_samples"}
            v = drive(self.oracle(total=total), stream(blocks))
            seen.add(kind)
            self.assertEqual(v["status"], oracles.FAILED, kind)
            self.assertEqual((v["violations"][0]["kind"], v["violations"][0]["event_index"]), (expect_first, expect_idx), kind)
            self.assertEqual(kinds_of(v), expect_kinds, kind)
            if kind == "corrupt":
                self.assertEqual(v["violations"][0]["expected"]["frame"], blocks[k][0] + pos // 2)
                self.assertEqual(v["violations"][0]["expected"]["channel"], pos % 2)
        self.assertEqual(seen, {"drop", "dup", "corrupt", "truncate", "swap"}, "every mutation class must be exercised")


# ---------------------------------------------------------------------------
class TestEpochOracle(unittest.TestCase):
    def base(self):
        return [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 10, command_id="c1", scope="s", epoch=1),
            ev("authority_epoch", 20, scope="s", epoch=2),
            ev("command_delivered", 30, command_id="c1"),
        ]

    def test_stale_command_applied_is_reported(self):
        events = self.base() + [ev("command_applied", 30, command_id="c1")]
        v = drive(oracles.EpochOracle(), events)
        self.assertEqual(v["status"], oracles.FAILED)
        first = v["violations"][0]
        self.assertEqual((first["kind"], first["event_index"]), ("stale_epoch_applied", 4))
        self.assertEqual(first["expected"], {"scope": "s", "min_epoch": 2})
        self.assertEqual(first["observed"], {"command_id": "c1", "command_epoch": 1})

    def test_dut_cannot_launder_the_epoch_by_claiming_a_current_one(self):
        events = self.base() + [ev("command_applied", 30, command_id="c1", epoch=2, scope="s")]
        v = drive(oracles.EpochOracle(), events)
        self.assertEqual(kinds_of(v), {"stale_epoch_applied"})

    def test_rejecting_a_stale_command_is_permitted_and_counted(self):
        events = self.base() + [ev("command_rejected", 30, command_id="c1", reason="stale_epoch")]
        v = drive(oracles.EpochOracle(require_stale_exercised=True), events)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual((v["stats"]["stale_deliveries"], v["stats"]["stale_rejected"]), (1, 1))

    def test_silently_ignoring_a_stale_command_is_permitted(self):
        v = drive(oracles.EpochOracle(require_stale_exercised=True), self.base())
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["stale_rejected"], 0)

    def test_fresh_command_applied_is_permitted(self):
        events = [
            ev("authority_epoch", 0, scope="s", epoch=2),
            ev("command_issued", 10, command_id="c1", scope="s", epoch=2),
            ev("command_delivered", 20, command_id="c1"),
            ev("command_applied", 20, command_id="c1"),
        ]
        self.assertEqual(drive(oracles.EpochOracle(), events)["status"], oracles.PASSED)

    def test_fence_never_exercised_is_incomplete_when_required(self):
        events = [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 10, command_id="c1", scope="s", epoch=1),
            ev("command_delivered", 20, command_id="c1"),
            ev("command_applied", 20, command_id="c1"),
        ]
        v = drive(oracles.EpochOracle(require_stale_exercised=True), events)
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("fence_not_exercised", v["incomplete_reasons"])
        self.assertEqual(drive(oracles.EpochOracle(), events)["status"], oracles.PASSED)

    def test_scopes_are_independent(self):
        events = [
            ev("authority_epoch", 0, scope="a", epoch=1),
            ev("authority_epoch", 0, scope="b", epoch=1),
            ev("command_issued", 10, command_id="c1", scope="a", epoch=1),
            ev("authority_epoch", 20, scope="b", epoch=2),
            ev("command_delivered", 30, command_id="c1"),
            ev("command_applied", 30, command_id="c1"),
        ]
        self.assertEqual(drive(oracles.EpochOracle(), events)["status"], oracles.PASSED)

    def test_authority_change_wins_a_timestamp_tie(self):
        events = [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 5, command_id="c1", scope="s", epoch=1),
            ev("authority_epoch", 30, scope="s", epoch=2),
            ev("command_delivered", 30, command_id="c1"),
            ev("command_applied", 30, command_id="c1"),
        ]
        self.assertEqual(kinds_of(drive(oracles.EpochOracle(), events)), {"stale_epoch_applied"})

    def test_future_epoch_and_unknown_scope(self):
        future = [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 5, command_id="c1", scope="s", epoch=3),
            ev("command_delivered", 6, command_id="c1"),
            ev("command_applied", 6, command_id="c1"),
        ]
        self.assertEqual(kinds_of(drive(oracles.EpochOracle(), future)), {"future_epoch_applied"})
        unknown = future[1:]
        self.assertEqual(kinds_of(drive(oracles.EpochOracle(), unknown)), {"unknown_scope"})

    def test_harness_bugs_are_usage_errors(self):
        regress = [ev("authority_epoch", 0, scope="s", epoch=2), ev("authority_epoch", 1, scope="s", epoch=1)]
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.EpochOracle(), regress)
        twice = [ev("command_issued", 1, command_id="c", scope="s", epoch=1)] * 2
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.EpochOracle(), twice)
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.EpochOracle(), [ev("authority_epoch", 0, scope="s", epoch="1")])

    def test_tracking_overflow_is_incomplete(self):
        events = [ev("authority_epoch", 0, scope="s", epoch=1)] + [
            ev("command_issued", 1 + i, command_id=f"c{i}", scope="s", epoch=1) for i in range(3)
        ]
        v = drive(oracles.EpochOracle(max_tracked_commands=2), events)
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("tracking_overflow", v["incomplete_reasons"])


# ---------------------------------------------------------------------------
class TestCommandOracle(unittest.TestCase):
    def head(self, n=1):
        events = [ev("authority_epoch", 0, scope="s", epoch=1)]
        events += [ev("command_issued", 1, command_id=f"c{i}", scope="s", epoch=1) for i in range(n)]
        return events

    def test_double_application_is_reported(self):
        events = self.head() + [
            ev("command_delivered", 10, command_id="c0"),
            ev("command_applied", 10, command_id="c0"),
            ev("command_delivered", 11, command_id="c0"),
            ev("command_applied", 11, command_id="c0"),
        ]
        v = drive(oracles.CommandOracle(), events)
        self.assertEqual(kinds_of(v), {"double_applied"})
        first = v["violations"][0]
        self.assertEqual(first["event_index"], 5)
        self.assertEqual(first["observed"], {"command_id": "c0", "applications": 2, "deliveries": 2})

    def test_suppressed_duplicate_delivery_is_the_permitted_positive_case(self):
        events = self.head() + [
            ev("command_delivered", 10, command_id="c0"),
            ev("command_applied", 10, command_id="c0"),
            ev("command_delivered", 11, command_id="c0"),
        ]
        v = drive(oracles.CommandOracle(require_duplicate_exercised=True), events)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["duplicate_deliveries"], 1)
        self.assertEqual(v["stats"]["applications"], 1)

    def test_duplicates_never_exercised_is_incomplete_when_required(self):
        events = self.head() + [ev("command_delivered", 10, command_id="c0"), ev("command_applied", 10, command_id="c0")]
        v = drive(oracles.CommandOracle(require_duplicate_exercised=True), events)
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("duplicates_not_exercised", v["incomplete_reasons"])

    def test_phantom_command(self):
        v = drive(oracles.CommandOracle(), self.head() + [ev("command_applied", 5, command_id="ghost")])
        self.assertEqual(kinds_of(v), {"phantom_command"})

    def test_applied_before_any_delivery(self):
        v = drive(oracles.CommandOracle(), self.head() + [ev("command_applied", 5, command_id="c0")])
        self.assertIn("applied_without_delivery", kinds_of(v))

    def test_lost_command_reported_at_finalize(self):
        events = self.head(2) + [
            ev("command_delivered", 10, command_id="c0"),
            ev("command_delivered", 10, command_id="c1"),
            ev("command_applied", 10, command_id="c1"),
        ]
        v = drive(oracles.CommandOracle(), events)
        self.assertEqual(kinds_of(v), {"lost_command"})
        self.assertEqual(v["violations"][0]["observed"]["command_id"], "c0")
        self.assertEqual(v["violations"][0]["event_index"], len(events))

    def test_command_only_delivered_while_stale_is_not_lost(self):
        events = [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 1, command_id="c0", scope="s", epoch=1),
            ev("authority_epoch", 5, scope="s", epoch=2),
            ev("command_delivered", 10, command_id="c0"),
        ]
        self.assertEqual(drive(oracles.CommandOracle(), events)["status"], oracles.PASSED)

    def test_overflow_is_incomplete_not_passed(self):
        events = self.head(3) + [ev("command_delivered", 10, command_id="c0"), ev("command_applied", 10, command_id="c0")]
        v = drive(oracles.CommandOracle(max_tracked_commands=2), events)
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("tracking_overflow", v["incomplete_reasons"])

    def test_harness_bugs_are_usage_errors(self):
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.CommandOracle(), self.head() + [ev("command_delivered", 5, command_id="never-issued")])
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.CommandOracle(), self.head() + [self.head()[1]])


# ---------------------------------------------------------------------------
A, B, C = oracles.DEFAULT_REQUIRED


class TestReadinessOracle(unittest.TestCase):
    def sat(self, t, name, value=True):
        return ev("prereq_state", t, name=name, satisfied=value)

    def ready_events(self):
        return [self.sat(10, A), self.sat(20, B), self.sat(30, C), ev("ready_announced", 40)]

    def test_ready_after_every_prerequisite_is_permitted(self):
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), self.ready_events(), end_t=100)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["announcements"], 1)

    def test_ready_with_a_prerequisite_missing_is_false_ready(self):
        events = [self.sat(10, A), self.sat(20, B), ev("ready_announced", 25)]
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), events, end_t=30)
        self.assertEqual(kinds_of(v), {"false_ready"})
        self.assertEqual(v["violations"][0]["observed"], {"missing_prerequisites": [C]})
        self.assertEqual(v["violations"][0]["event_index"], 2)

    def test_ready_with_no_probe_evidence_at_all_is_false_ready(self):
        v = drive(oracles.ReadinessOracle(), [ev("ready_announced", 5)], end_t=10)
        self.assertEqual(v["violations"][0]["observed"]["missing_prerequisites"], list(oracles.DEFAULT_REQUIRED))

    def test_dut_claims_about_its_own_prerequisites_are_ignored(self):
        events = [ev("ready_announced", 5, prerequisites={A: True, B: True, C: True}, clock_locked=True)]
        v = drive(oracles.ReadinessOracle(), events, end_t=10)
        self.assertEqual(kinds_of(v), {"false_ready"})

    def test_timely_withdrawal_is_permitted_including_the_boundary(self):
        for withdraw_t in (120, 150):  # lost at 100, deadline 50 -> 150 is still in time
            events = self.ready_events() + [self.sat(100, C, False), ev("ready_withdrawn", withdraw_t)]
            v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), events, end_t=200)
            self.assertEqual(v["status"], oracles.PASSED, (withdraw_t, v))

    def test_late_withdrawal_is_reported_against_the_causal_loss_event(self):
        events = self.ready_events() + [self.sat(100, C, False), ev("ready_withdrawn", 151)]
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), events, end_t=200)
        self.assertEqual(kinds_of(v), {"ready_not_withdrawn"})
        first = v["violations"][0]
        self.assertEqual((first["event_index"], first["t_ns"]), (4, 150))
        self.assertEqual(first["expected"]["prerequisite"], C)

    def test_never_withdrawn_is_found_at_the_end_time_and_needs_it(self):
        events = self.ready_events() + [self.sat(100, C, False)]
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), list(events), end_t=1000)
        self.assertEqual(kinds_of(v), {"ready_not_withdrawn"})
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), list(events))
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("end_time_required_for_pending_deadline", v["incomplete_reasons"])

    def test_ready_after_relock_is_permitted(self):
        events = self.ready_events() + [
            self.sat(100, C, False), ev("ready_withdrawn", 110), self.sat(200, C), ev("ready_announced", 210),
        ]
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50, announce_deadline_ns=50), events, end_t=300)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual((v["stats"]["announcements"], v["stats"]["withdrawals"]), (2, 1))

    def test_refusal_only_dut_fails_the_announce_deadline(self):
        events = [self.sat(10, A), self.sat(20, B), self.sat(30, C), ev("noise", 200)]
        v = drive(oracles.ReadinessOracle(announce_deadline_ns=50), events, end_t=300)
        self.assertEqual(kinds_of(v), {"ready_not_announced"})
        self.assertEqual(v["violations"][0]["event_index"], 2)
        # Without a deadline there is nothing to hold the DUT to.
        self.assertEqual(drive(oracles.ReadinessOracle(), events, end_t=300)["status"], oracles.PASSED)

    def test_announce_deadline_boundary(self):
        def run(announce_t):
            events = [self.sat(10, A), self.sat(20, B), self.sat(30, C), ev("ready_announced", announce_t)]
            return drive(oracles.ReadinessOracle(announce_deadline_ns=50), events, end_t=announce_t + 10)
        self.assertEqual(run(80)["status"], oracles.PASSED)
        self.assertEqual(kinds_of(run(81)), {"ready_not_announced"})

    def test_redundant_and_unknown_events_do_not_create_violations(self):
        events = self.ready_events() + [ev("ready_announced", 45), self.sat(50, "unrelated_probe"), ev("ready_withdrawn", 60),
                                        ev("ready_withdrawn", 70)]
        v = drive(oracles.ReadinessOracle(withdraw_deadline_ns=50), events, end_t=100)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["redundant_ready_events"], 2)
        self.assertEqual(v["stats"]["ignored_unknown_prerequisites"], 1)

    def test_bad_probe_event_and_bad_config(self):
        with self.assertRaises(oracles.OracleUsageError):
            drive(oracles.ReadinessOracle(), [ev("prereq_state", 1, name=A, satisfied="yes")])
        for kwargs in ({"required": []}, {"required": ["a", "a"]}, {"withdraw_deadline_ns": -1}, {"announce_deadline_ns": -5}):
            with self.assertRaises(ValueError):
                oracles.ReadinessOracle(**kwargs)


# ---------------------------------------------------------------------------
class TestPriorityStopOracle(unittest.TestCase):
    SR, DEADLINE, STOP = 1000, 2_000_000, 10_000_000  # 1 frame per ms

    def oracle(self):
        return oracles.PriorityStopOracle(sample_rate_hz=self.SR, deadline_ns=self.DEADLINE)

    def out(self, t, samples, **extra):
        return ev("audio_block", t, channels=1, samples=samples, **extra)

    def test_silent_after_deadline_is_permitted_with_evidence(self):
        events = [ev("stop_requested", self.STOP), self.out(self.STOP, [5, 5, 0, 0])]
        v = drive(self.oracle(), events, end_t=self.STOP + 10_000_000)
        self.assertEqual(v["status"], oracles.PASSED, v)
        self.assertEqual(v["stats"]["silent_frames_after_deadline"], 2)

    def test_audible_after_deadline_is_reported_with_exact_frame_time(self):
        events = [ev("stop_requested", self.STOP), self.out(self.STOP, [5, 5, 5, 5], cause="out-1")]
        v = drive(self.oracle(), events, end_t=self.STOP + 10_000_000)
        self.assertEqual(kinds_of(v), {"audible_after_deadline"})
        first = v["violations"][0]
        self.assertEqual(first["observed"]["first_audible_frame_t_ns"], 12_000_000)
        self.assertEqual(first["observed"]["audible_samples"], 2)
        self.assertEqual((first["event_index"], first["cause"]), (1, "out-1"))

    def test_block_that_straddles_the_stop_is_still_judged(self):
        events = [self.out(8_000_000, [5] * 6), ev("stop_requested", self.STOP)]
        v = drive(self.oracle(), events, end_t=self.STOP + 10_000_000)
        self.assertEqual(kinds_of(v), {"audible_after_deadline"})
        self.assertEqual(v["violations"][0]["event_index"], 0)

    def test_stopping_output_without_proof_of_silence_is_incomplete(self):
        events = [self.out(0, [5, 5]), ev("stop_requested", self.STOP)]
        v = drive(self.oracle(), events, end_t=self.STOP + 10_000_000)
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("no_evidence_of_silence", v["incomplete_reasons"])

    def test_stop_never_requested_is_incomplete(self):
        v = drive(self.oracle(), [self.out(0, [5, 5])])
        self.assertEqual(v["status"], oracles.INCOMPLETE)
        self.assertIn("stop_not_exercised", v["incomplete_reasons"])

    def test_malformed_output_cannot_establish_silence(self):
        v = drive(self.oracle(), [ev("stop_requested", 0), ev("audio_block", 1, channels=0, samples=[0])])
        self.assertIn("malformed_block", kinds_of(v))


# ---------------------------------------------------------------------------
class TestTraceIntegrity(unittest.TestCase):
    def good_run(self, seed=3):
        sched = oracles.build_schedule(seed)
        trace = oracles.simulate_house(sched)
        return sched, trace

    def evaluate(self, sched, trace):
        return oracles.evaluate(trace, oracles.build_house_oracles(sched), end_t_ns=sched.end_t_ns)

    def test_good_trace_passes_every_oracle_with_evidence(self):
        sched, trace = self.good_run()
        report = self.evaluate(sched, trace)
        self.assertEqual(report["status"], oracles.PASSED, report)
        for name, verdict in report["oracles"].items():
            self.assertGreater(verdict["events_relevant"], 0, name)

    def test_every_proper_prefix_of_a_good_trace_fails_to_pass(self):
        # A log that ends early must never read as success.
        sched, trace = self.good_run()
        for cut in list(range(0, len(trace), 23)) + [len(trace) - 1]:
            report = self.evaluate(sched, trace[:cut])
            self.assertNotEqual(report["status"], oracles.PASSED, f"prefix of {cut}/{len(trace)} events passed")

    def test_stripping_the_independent_truth_events_cannot_pass(self):
        sched, trace = self.good_run()
        truth_kinds = {"authority_epoch", "command_issued", "command_delivered", "prereq_state"}
        dut_only = [e for e in trace if e["kind"] not in truth_kinds]
        report = self.evaluate(sched, dut_only)
        self.assertNotEqual(report["status"], oracles.PASSED)

    def test_jsonl_round_trip_preserves_the_digest_and_verdict(self):
        sched, trace = self.good_run()
        again = oracles.trace_from_jsonl(oracles.trace_to_jsonl(trace))
        self.assertEqual(oracles.trace_digest(trace), oracles.trace_digest(again))
        self.assertEqual(self.evaluate(sched, again)["status"], oracles.PASSED)

    def test_truncated_jsonl_is_detected_not_ignored(self):
        _, trace = self.good_run()
        text = oracles.trace_to_jsonl(trace)
        cut = text.index("\n", len(text) // 2) - 3  # strictly inside a line, closing braces removed
        with self.assertRaises(oracles.OracleUsageError):
            oracles.trace_from_jsonl(text[:cut])
        with self.assertRaises(oracles.OracleUsageError):
            oracles.trace_from_jsonl("[1, 2, 3]\n")

    def test_simulation_is_deterministic_and_defect_changes_only_the_trace(self):
        sched = oracles.build_schedule(8)
        a = oracles.trace_digest(oracles.simulate_house(sched))
        b = oracles.trace_digest(oracles.simulate_house(oracles.build_schedule(8)))
        self.assertEqual(a, b)
        self.assertNotEqual(a, oracles.trace_digest(oracles.simulate_house(sched, ["sample_loss"])))
        report_good = oracles.run_house(8)
        report_bad = oracles.run_house(8, ["sample_loss"])
        self.assertEqual(report_good["schedule_digest"], report_bad["schedule_digest"])
        self.assertNotEqual(report_good["trace_digest"], report_bad["trace_digest"])

    def test_defect_scenario_mismatch_is_refused(self):
        with self.assertRaises(ValueError):
            oracles.simulate_house(oracles.build_schedule(1), ["stop_behind_queue"])
        with self.assertRaises(ValueError):
            oracles.simulate_stop(oracles.build_stop_scenario(1), ["sample_loss"])
        with self.assertRaises(ValueError):
            oracles.simulate_house(oracles.build_schedule(1), ["no_such_defect"])


# ---------------------------------------------------------------------------
class TestSchedule(unittest.TestCase):
    def test_same_seed_same_schedule_different_seed_different(self):
        a, b = oracles.build_schedule(42), oracles.build_schedule(42)
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(oracles.canonical_json(a.to_dict()), oracles.canonical_json(b.to_dict()))
        self.assertNotEqual(a.digest, oracles.build_schedule(43).digest)
        self.assertNotEqual(a.digest, oracles.build_schedule(42, oracles.ScheduleProfile(loss_bps=900)).digest)

    def test_digest_covers_the_content(self):
        s = oracles.build_schedule(5)
        body = s.to_dict()
        digest = body.pop("digest")
        self.assertEqual(digest, oracles.sha256_hex(oracles.canonical_json(body)))

    def test_domains_are_separated(self):
        a = oracles.build_schedule(7, oracles.ScheduleProfile(random_commands=3))
        b = oracles.build_schedule(7, oracles.ScheduleProfile(random_commands=11))
        self.assertEqual(a.audio, b.audio)
        strip = lambda s: [{k: v for k, v in e.items() if k != "id"} for e in s.truth if e["kind"] == "prereq_state"]
        self.assertEqual(strip(a), strip(b))

    def test_truth_is_ordered_with_unique_ids(self):
        s = oracles.build_schedule(9)
        times = [e["t_ns"] for e in s.truth]
        self.assertEqual(times, sorted(times))
        ids = [e["id"] for e in s.truth]
        self.assertEqual(len(ids), len(set(ids)))
        ranks = [(e["t_ns"], oracles._TRUTH_RANK[e["kind"]]) for e in s.truth]
        self.assertEqual(ranks, sorted(ranks))

    def test_every_seed_contains_the_events_that_trigger_the_defects(self):
        for seed in range(150):
            s = oracles.build_schedule(seed)
            self.assertTrue(any(a["dropped"] for a in s.audio), seed)
            self.assertGreaterEqual(s.target_block(), 3)
            self.assertFalse(s.audio[s.target_block()]["dropped"])
            # Recompute staleness here, independently of oracles.py.
            authority, issued, stale, deliveries = {}, {}, 0, {}
            for e in s.truth:
                if e["kind"] == "authority_epoch":
                    authority[e["scope"]] = e["epoch"]
                elif e["kind"] == "command_issued":
                    issued[e["command_id"]] = (e["scope"], e["epoch"])
                elif e["kind"] == "command_delivered":
                    sc, ep = issued[e["command_id"]]
                    stale += ep < authority[sc]
                    deliveries[e["command_id"]] = deliveries.get(e["command_id"], 0) + 1
            self.assertGreaterEqual(stale, 1, seed)
            self.assertGreaterEqual(max(deliveries.values()), 2, seed)
            probes = [e for e in s.truth if e["kind"] == "prereq_state"]
            self.assertEqual(sum(1 for e in probes if e["satisfied"]), 4, seed)
            self.assertEqual(sum(1 for e in probes if not e["satisfied"]), 1, seed)

    def test_burst_loss_blocks_are_consecutive_and_loss_rate_is_plausible(self):
        dropped_independent = total = 0
        for seed in range(100):
            s = oracles.build_schedule(seed)
            runs, current = [], 0
            for i, a in enumerate(s.audio):
                if a["burst"]:
                    current += 1
                    self.assertTrue(a["dropped"])
                    continue
                if current:
                    runs.append((i - current, current))
                    current = 0
                total += 1
                dropped_independent += a["dropped"]
            if current:
                runs.append((len(s.audio) - current, current))
            self.assertTrue(runs, f"seed {seed} has no burst loss")
            for start, length in runs:
                if start > 0 and start + length < len(s.audio):  # not clipped by the stream edge
                    self.assertEqual(length, s.profile.burst_len_blocks, (seed, start, length))
        rate = dropped_independent / total
        self.assertTrue(0.02 <= rate <= 0.06, f"independent loss rate {rate:.4f} should be near the configured 4%")

    def test_profile_validation(self):
        bad = [{"playout_delay_ns": 1, "max_jitter_ns": 400_000}, {"blocks": 5}, {"channels": 0}, {"loss_bps": 10_001},
               {"burst_len_blocks": 20}, {"scopes": ()}, {"scopes": ("a", "a")}, {"withdraw_deadline_ns": 100_000},
               {"sample_rate_hz": 0}]
        for overrides in bad:
            with self.assertRaises(ValueError, msg=repr(overrides)):
                oracles.ScheduleProfile.from_overrides(overrides)
        with self.assertRaises(TypeError):
            oracles.ScheduleProfile.from_overrides({"unknown_knob": 1})
        with self.assertRaises(ValueError):
            oracles.build_schedule(1, oracles.ScheduleProfile(blocks=20))  # timeline too short for the dip
        with self.assertRaises(ValueError):
            oracles.build_schedule(1, oracles.ScheduleProfile(loss_bps=10_000))  # nothing left to deliver

    def test_stop_scenario(self):
        a, b = oracles.build_stop_scenario(3), oracles.build_stop_scenario(3)
        self.assertEqual(a.digest, b.digest)
        self.assertNotEqual(a.digest, oracles.build_stop_scenario(4).digest)
        with self.assertRaises(ValueError):
            oracles.build_stop_scenario(3, queue_blocks=2)


# ---------------------------------------------------------------------------
class TestCanaries(unittest.TestCase):
    EXTRA_SEEDS = tuple(range(100, 108)) + (0, 2**63, 2**64 - 1, 0xDEADBEEFCAFEF00D)

    def test_all_four_required_defect_classes_are_planted(self):
        wanted = {"sample": "lost_samples", "epoch": "stale_epoch_applied", "command": "double_applied", "readiness": "false_ready"}
        planted = {(d.oracle, d.kind) for d in oracles.DEFECTS.values()}
        for pair in wanted.items():
            self.assertIn(pair, planted)
        self.assertEqual(len(oracles.DEFECTS), 10)

    def test_each_defect_fails_exactly_its_oracle_and_the_good_run_passes(self):
        for name, spec in oracles.DEFECTS.items():
            for seed in oracles.CANARY_SEEDS + self.EXTRA_SEEDS:
                with self.subTest(defect=name, seed=seed):
                    good = oracles.run_stop(seed) if spec.scenario == "stop" else oracles.run_house(seed)
                    bad = (oracles.run_stop(seed, [name]) if spec.scenario == "stop"
                           else oracles.run_house(seed, [name]))
                    self.assertEqual(good["status"], oracles.PASSED, good)
                    self.assertEqual(bad["status"], oracles.FAILED)
                    for oname, verdict in bad["oracles"].items():
                        if oname == spec.oracle:
                            self.assertEqual(verdict["status"], oracles.FAILED)
                            self.assertEqual(verdict["violations"][0]["kind"], spec.kind)
                        else:
                            self.assertEqual(verdict["status"], oracles.PASSED, (oname, verdict["violation_kinds"]))

    def test_failures_retain_first_causal_event_and_replay_command(self):
        for name, spec in oracles.DEFECTS.items():
            result = oracles.run_canary(name, 4242)
            with self.subTest(defect=name):
                self.assertEqual(result["status"], oracles.PASSED, result)
                first = result["first_causal_event"]
                self.assertEqual((first["oracle"], first["kind"]), (spec.oracle, spec.kind))
                if name == "truncate_tail":
                    self.assertIsNone(first["cause"])  # raised at finalize: there is no causal event, only absence
                else:
                    self.assertIsInstance(first["cause"], str)
                self.assertEqual(result["replay_argv"][-2:], ["--defect", name])
                self.assertEqual(len(result["schedule_digest"]), 64)

    def test_canary_harness_catches_an_oracle_that_cannot_complain(self):
        # Meta test: if an oracle is blinded, its canary must fail loudly.
        for name, spec in oracles.DEFECTS.items():
            blind_cls = type("Blind", (ORACLE_CLASSES[spec.oracle],), {"_violate": lambda self, *a, **k: None})
            with self.subTest(defect=name):
                result = oracles.run_canary(name, 11, oracle_factory=swapped_factory(spec.oracle, blind_cls))
                self.assertEqual(result["status"], oracles.FAILED, "a blinded oracle must not satisfy its canary")
                self.assertFalse(result["checks"]["defect_failed_corresponding_oracle"])
                self.assertTrue(result["checks"]["positive_passed"], "the blinded oracle still passes the good run")

    def test_canary_harness_catches_an_oracle_that_always_complains(self):
        class Paranoid(oracles.EpochOracle):
            def _on_finalize(self, end_t_ns):
                self._violate("always", expected={}, observed={}, detail="cries wolf", event_index=0, t_ns=0, cause=None)

        def factory(sched):
            return [Paranoid() if o.name == "epoch" else o for o in oracles.build_house_oracles(sched)]

        result = oracles.run_canary("sample_loss", 11, oracle_factory=factory)
        self.assertEqual(result["status"], oracles.FAILED)
        self.assertFalse(result["checks"]["positive_passed"])
        self.assertFalse(result["checks"]["other_oracles_stayed_passed"])

    def test_positive_cases_demand_evidence_that_the_scenario_exercised_the_guard(self):
        for name in oracles.ORACLE_NAMES:
            with self.subTest(oracle=name):
                self.assertEqual(oracles.run_positive(name)["status"], oracles.PASSED)
        # A case that ran nothing has proven nothing, so it must not pass.
        empty = oracles.run_positive("sample", seeds=())
        self.assertEqual(empty["status"], oracles.FAILED)
        self.assertIn("nothing ran", empty["problems"][0])
        self.assertEqual(oracles.run_canary_all_seeds("sample_loss", seeds=())["status"], oracles.FAILED)
        with self.assertRaises(ValueError):
            oracles.run_positive("no_such_oracle")

    def test_positive_case_rejects_a_pass_that_never_exercised_the_guard(self):
        # An oracle that stays green because the scenario never tested anything is not evidence.
        for name in oracles.ORACLE_NAMES:
            vacuous_cls = type("Vacuous", (ORACLE_CLASSES[name],), {"_stats": lambda self: {}})
            with self.subTest(oracle=name):
                result = oracles.run_positive(name, (11,), oracle_factory=swapped_factory(name, vacuous_cls))
                self.assertEqual(result["status"], oracles.FAILED)
                self.assertTrue(any("did not exercise" in p for p in result["problems"]), result["problems"])

    def test_incomplete_evidence_cannot_satisfy_an_expected_failure_canary(self):
        # The oracle neither passes nor fails: it cannot reach a conclusion.
        for name, spec in oracles.DEFECTS.items():
            def _finalize(self, end_t_ns):
                self._add_incomplete("synthetic_missing_evidence")

            incomplete_cls = type("Incomplete", (ORACLE_CLASSES[spec.oracle],),
                                  {"_violate": lambda self, *a, **k: None, "_on_finalize": _finalize})
            with self.subTest(defect=name):
                result = oracles.run_canary(name, 11, oracle_factory=swapped_factory(spec.oracle, incomplete_cls))
                self.assertEqual(result["status"], oracles.FAILED)
                self.assertEqual(result["observed"]["oracle_status"], oracles.INCOMPLETE)
                self.assertFalse(result["checks"]["defect_failed_corresponding_oracle"])
                self.assertFalse(result["checks"]["defect_kind_observed"])

    def test_registry_is_complete_unique_and_runnable(self):
        ids = [case_id for case_id, _ in oracles.CANARY_CASES]
        self.assertEqual(len(ids), len(set(ids)))
        expected = {f"q00.oracle.canary.{n}" for n in oracles.DEFECTS} | {f"q00.oracle.positive.{n}" for n in oracles.ORACLE_NAMES}
        self.assertEqual(set(ids), expected)
        for case_id, fn in oracles.CANARY_CASES:
            result = fn()
            self.assertEqual(result["status"], oracles.PASSED, (case_id, result))
            self.assertEqual(result["case_id"], case_id)


# ---------------------------------------------------------------------------
class TestFoundationBoundary(unittest.TestCase):
    def test_imports_are_a_pinned_standard_library_allowlist(self):
        tree = ast.parse(ORACLES_PY.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "no relative imports: the module must stand alone")
                imported.add((node.module or "").split(".")[0])
        self.assertTrue(imported <= set(sys.stdlib_module_names), imported)
        # Pinned: growing the surface (network, processes, hardware, ctypes) is a deliberate edit to this test.
        self.assertEqual(imported, {"__future__", "argparse", "dataclasses", "hashlib", "json", "os", "sys", "typing"})
        self.assertFalse([m for m in imported if "franken" in m or "ffw" in m])

    def test_os_use_is_limited_to_env_and_atomic_result_write(self):
        tree = ast.parse(ORACLES_PY.read_text(encoding="utf-8"))
        used = {n.attr for n in ast.walk(tree)
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os"}
        self.assertEqual(used, {"environ", "getpid", "replace", "fsync", "unlink"}, "no process, path-walking or network use of os")

    def test_module_source_pins_no_absolute_personal_paths(self):
        source = ORACLES_PY.read_text(encoding="utf-8")
        for needle in ("/Users/", "/home/", "C:\\"):
            self.assertNotIn(needle, source)


# ---------------------------------------------------------------------------
RESULT_KEYS = {"schema", "run_id", "case_id", "nonce", "verdict", "oracle", "oracle_kind", "independent", "checks",
               "mismatches", "expected", "observed", "first_causal_event", "counters",
               "finalized", "incomplete_reasons", "violation_kinds"}


def contract_problems(r):
    """The consistency rules the runner enforces on a v1.1 result (from the contract message), as a list of problems."""
    problems = []
    kinds, reasons, mism = r["violation_kinds"], r["incomplete_reasons"], r["mismatches"]
    if not (isinstance(kinds, dict) and all(isinstance(v, int) and not isinstance(v, bool) and v >= 1 for v in kinds.values())):
        problems.append("violation_kinds must map kind -> count >= 1")
    elif sum(kinds.values()) != mism:
        problems.append("sum(violation_kinds) != mismatches")
    if not (isinstance(reasons, list) and all(isinstance(x, str) and x for x in reasons)):
        problems.append("incomplete_reasons must be a list of non-empty strings")
    if not isinstance(r["finalized"], bool):
        problems.append("finalized must be a bool")
    v = r["verdict"]
    if v == "pass" and (mism != 0 or kinds or r["finalized"] is not True or reasons or r["checks"] < 1):
        problems.append("pass needs 0 mismatches, no kinds, finalized, no reasons, checks >= 1")
    if v == "fail" and (mism < 1 or not kinds or r["expected"] == r["observed"]):
        problems.append("fail needs mismatches >= 1, a kind, and expected != observed")
    if v == "incomplete" and (mism != 0 or not (reasons or r["finalized"] is False)):
        problems.append("incomplete needs 0 mismatches and reasons or finalized false")
    if v not in ("pass", "fail", "incomplete"):
        problems.append("unknown verdict")
    return problems


class TestRunnerContract(unittest.TestCase):
    """The ffw.case-result.v1 file a runner consumes (wire contract agreed on the Q00 thread)."""

    IDS = dict(run_id="run-1", case_id="q00.oracle.canary.x", nonce="n0nce")

    def verdict_of(self, oracle, events, **kw):
        return drive(oracle, events, **kw)

    def incomplete_verdict(self):
        return drive(oracles.SampleOracle(RampReference(), expected_total_frames=3), [])

    def failed_verdict(self):
        return drive(oracles.SampleOracle(RampReference(), expected_total_frames=9), [blk(1, 0, 3), blk(2, 6, 3)])

    def test_incomplete_is_its_own_typed_verdict_with_no_manufactured_mismatch(self):
        verdict = self.incomplete_verdict()
        self.assertEqual(verdict["status"], oracles.INCOMPLETE)
        result = oracles.build_case_result("sample", verdict, context={}, expect={"oracle": "sample", "kind": "lost_samples"}, **self.IDS)
        self.assertEqual(set(result), RESULT_KEYS)
        self.assertEqual((result["verdict"], result["oracle"]), ("incomplete", "sample"))
        self.assertEqual((result["mismatches"], result["violation_kinds"]), (0, {}))
        self.assertEqual(result["incomplete_reasons"], ["no_evidence"])
        self.assertTrue(result["finalized"])
        self.assertTrue(result["observed"].startswith("oracle incomplete: no_evidence"))
        self.assertEqual(contract_problems(result), [])

    def test_unfinalized_oracle_is_incomplete_with_finalized_false(self):
        oracle = oracles.SampleOracle(RampReference(), expected_total_frames=3)
        oracle.observe(blk(1, 0, 3))  # never finalized: the case "never reached its final summary"
        verdict = oracle.verdict()
        result = oracles.build_case_result("sample", verdict, context={}, **self.IDS)
        self.assertEqual((result["verdict"], result["finalized"]), ("incomplete", False))
        self.assertEqual(result["incomplete_reasons"], ["not_finalized"])
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(contract_problems(result), [])

    def test_a_failure_that_is_also_incomplete_keeps_both_facts(self):
        # Real violation found, but tracking overflowed: the runner must see the reason and downgrade it to non-canary-match.
        events = [
            ev("authority_epoch", 0, scope="s", epoch=1),
            ev("command_issued", 1, command_id="c1", scope="s", epoch=1),
            ev("command_issued", 2, command_id="c2", scope="s", epoch=1),  # beyond max_tracked_commands
            ev("authority_epoch", 3, scope="s", epoch=2),
            ev("command_delivered", 4, command_id="c1"),
            ev("command_applied", 4, command_id="c1"),
        ]
        verdict = drive(oracles.EpochOracle(max_tracked_commands=1), events)
        self.assertEqual(verdict["status"], oracles.FAILED)
        result = oracles.build_case_result("epoch", verdict, context={}, expect={"oracle": "epoch", "kind": "stale_epoch_applied"}, **self.IDS)
        self.assertEqual((result["verdict"], result["oracle"], result["mismatches"]), ("fail", "epoch", 1))
        self.assertEqual(result["violation_kinds"], {"stale_epoch_applied": 1})
        self.assertEqual(result["incomplete_reasons"], ["tracking_overflow"])
        self.assertEqual(contract_problems(result), [])

    def test_failure_with_the_wrong_defect_identity_is_not_a_canary_match(self):
        verdict = self.failed_verdict()
        ok = oracles.build_case_result("sample", verdict, context={}, expect={"oracle": "sample", "kind": "lost_samples"}, **self.IDS)
        self.assertEqual((ok["verdict"], ok["oracle"]), ("fail", "sample"))
        self.assertGreaterEqual(ok["mismatches"], 1)
        wrong = oracles.build_case_result("sample", verdict, context={}, expect={"oracle": "sample", "kind": "wrong_samples"}, **self.IDS)
        self.assertEqual((wrong["verdict"], wrong["oracle"]), ("fail", "sample.identity_mismatch"))
        self.assertNotEqual(wrong["expected"], wrong["observed"])
        self.assertEqual(contract_problems(ok) + contract_problems(wrong), [])
        self.assertIn("lost_samples", wrong["violation_kinds"], "the runner's own expect.violation check sees the real kinds")

    def test_pass_result_requires_evidence(self):
        verdict = drive(oracles.SampleOracle(RampReference(), expected_total_frames=3), [blk(1, 0, 3)])
        result = oracles.build_case_result("sample", verdict, context={"seed": 1}, **self.IDS)
        self.assertEqual((result["verdict"], result["mismatches"], result["oracle"]), ("pass", 0, "sample"))
        self.assertGreaterEqual(result["checks"], 1)
        self.assertEqual((result["finalized"], result["incomplete_reasons"], result["violation_kinds"]), (True, [], {}))
        self.assertEqual(contract_problems(result), [])
        vacuous = drive(oracles.SampleOracle(RampReference(), expected_total_frames=3, allow_empty=True), [])
        self.assertEqual(vacuous["status"], oracles.PASSED)
        result = oracles.build_case_result("sample", vacuous, context={}, **self.IDS)
        self.assertEqual(result["verdict"], "incomplete", "a pass with zero checks must not be reported as a pass")
        self.assertEqual((result["oracle"], result["incomplete_reasons"], result["mismatches"]), ("sample", ["no_evidence"], 0))
        self.assertEqual(contract_problems(result), [])

    def test_missed_defect_is_reported_as_a_pass_not_as_the_expected_failure(self):
        blind = type("Blind", (oracles.EpochOracle,), {"_violate": lambda self, *a, **k: None})
        spec, report, verdict, collateral = oracles.defect_verdict(11, "stale_epoch", oracle_factory=swapped_factory("epoch", blind))
        result = oracles.build_case_result(spec.oracle, verdict, context={}, expect={"oracle": spec.oracle, "kind": spec.kind}, **self.IDS)
        self.assertEqual(result["verdict"], "pass")

    def test_incomplete_defect_run_is_incomplete_not_caught(self):
        def _finalize(self, end_t_ns):
            self._add_incomplete("synthetic")
        cls = type("Inc", (oracles.CommandOracle,), {"_violate": lambda self, *a, **k: None, "_on_finalize": _finalize})
        spec, report, verdict, collateral = oracles.defect_verdict(11, "double_apply", oracle_factory=swapped_factory("command", cls))
        self.assertEqual(verdict["status"], oracles.INCOMPLETE)
        result = oracles.build_case_result(spec.oracle, verdict, context={}, expect={"oracle": spec.oracle, "kind": spec.kind}, **self.IDS)
        # Same oracle name as the canary expects -- the typed verdict, not the name, is what keeps it from matching.
        self.assertEqual((result["verdict"], result["oracle"], result["mismatches"]), ("incomplete", "command", 0))
        self.assertEqual(result["incomplete_reasons"], ["synthetic"])
        self.assertEqual(contract_problems(result), [])

    def test_oracle_kinds_are_receipt_kinds(self):
        self.assertEqual(set(oracles.ORACLE_KIND), set(oracles.ORACLE_NAMES))
        self.assertTrue(set(oracles.ORACLE_KIND.values()) <= {"sample", "state", "protocol", "timing", "property", "output"})
        self.assertEqual(oracles.RECEIPT_OUTCOME, {"passed": "pass", "failed": "fail", "incomplete": "blocked"})

    def test_result_is_staged_in_a_temp_file_then_renamed_into_place(self):
        seen = {}
        real_replace = os.replace

        def spy(src, dst):
            seen["src_exists"] = os.path.exists(src)
            seen["dst_exists_before"] = os.path.exists(dst)
            seen["staged_is_complete_json"] = json.loads(Path(src).read_text())["nonce"] == "n0nce"
            seen["same"] = src == dst
            real_replace(src, dst)

        with tempfile.TemporaryDirectory() as tmp:
            target = str(Path(tmp) / "r.json")
            with mock.patch.object(oracles.os, "replace", spy):
                oracles.write_case_result(target, {"nonce": "n0nce"})
            self.assertEqual(seen, {"src_exists": True, "dst_exists_before": False, "staged_is_complete_json": True, "same": False})
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["r.json"])

    def test_failed_rename_leaves_no_partial_result_and_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            with mock.patch.object(oracles.os, "replace", side_effect=OSError("disk gone")):
                with self.assertRaises(OSError):
                    oracles.write_case_result(str(target), {"nonce": "x"})
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_oversized_result_is_refused_not_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            with self.assertRaises(ValueError):
                oracles.write_case_result(str(target), {"observed": "x" * (256 * 1024)})
            self.assertEqual(list(Path(tmp).iterdir()), [])
            oracles.write_case_result(str(target), {"observed": "x" * 1000})
            self.assertTrue(target.exists())

    def run_main_with(self, argv, patches):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            env = {"FFW_RUN_ID": "r", "FFW_CASE_ID": "c", "FFW_RESULT_NONCE": "n", "FFW_RESULT_PATH": str(path)}
            with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.ExitStack() as stack:
                for name, value in patches.items():
                    stack.enter_context(mock.patch.object(oracles, name, return_value=value))
                code = oracles.main(argv)
            return code, json.loads(path.read_text())

    def test_incomplete_defect_replay_exits_2_and_is_typed_incomplete_under_the_expected_oracle_name(self):
        def _finalize(self, end_t_ns):
            self._add_incomplete("synthetic_missing_evidence")
        cls = type("Inc", (oracles.CommandOracle,), {"_violate": lambda self, *a, **k: None, "_on_finalize": _finalize})
        spec, report, verdict, collateral = oracles.defect_verdict(11, "double_apply", oracle_factory=swapped_factory("command", cls))
        code, result = self.run_main_with(["replay", "--defect", "double_apply", "--seed", "11"],
                                          {"defect_verdict": (spec, report, verdict, collateral)})
        self.assertEqual(code, 2, "exit 2 is outside a canary's expected exit_codes [1]")
        self.assertEqual((result["verdict"], result["oracle"], result["mismatches"]), ("incomplete", "command", 0))
        self.assertEqual(result["incomplete_reasons"], ["synthetic_missing_evidence"])
        self.assertEqual(contract_problems(result), [])

    def test_incomplete_positive_exits_2_and_is_typed_incomplete(self):
        verdict = self.incomplete_verdict()
        report = {"trace_digest": "d" * 64, "schedule_digest": "e" * 64}
        code, result = self.run_main_with(["positive", "--oracle", "sample", "--seed", "1"], {"positive_verdict": (verdict, report)})
        self.assertEqual(code, 2)
        self.assertEqual((result["verdict"], result["oracle"]), ("incomplete", "sample"))
        self.assertEqual(contract_problems(result), [])

    def test_defect_exit_code_follows_the_corresponding_oracle_not_the_overall_report(self):
        # The corresponding oracle missed the defect (passed) while a *different* oracle failed.
        blind = type("Blind", (oracles.EpochOracle,), {"_violate": lambda self, *a, **k: None})
        spec, report, verdict, collateral = oracles.defect_verdict(11, "stale_epoch", oracle_factory=swapped_factory("epoch", blind))
        report = dict(report, status=oracles.FAILED)  # overall FAILED, e.g. collateral damage elsewhere
        self.assertEqual(verdict["status"], oracles.PASSED)
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            env = {"FFW_RUN_ID": "r", "FFW_CASE_ID": "c", "FFW_RESULT_NONCE": "n", "FFW_RESULT_PATH": str(Path(tmp) / "r.json")}
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(oracles, "defect_verdict", return_value=(spec, report, verdict, collateral)), \
                    contextlib.redirect_stdout(out):
                code = oracles.main(["replay", "--defect", "stale_epoch", "--seed", "11"])
            result = json.loads((Path(tmp) / "r.json").read_text())
        self.assertEqual(code, 0, "a missed defect must not look like the expected failure (exit 1)")
        self.assertEqual(result["verdict"], "pass")

    # -- through the real command line ---------------------------------------
    def run_cli(self, args, tmp, *, env_extra=None, result_name="result.json", with_result=True):
        env = {"PATH": "/usr/bin:/bin", "FFW_RUN_ID": "run-7", "FFW_CASE_ID": "case.under test", "FFW_ATTEMPT": "1",
               "FFW_SEED": "123", "FFW_RESULT_NONCE": "abc123"}
        result = Path(tmp) / result_name
        if with_result:
            env["FFW_RESULT_PATH"] = str(result)
        env.update(env_extra or {})
        env = {k: v for k, v in env.items() if v is not None}
        proc = subprocess.run([sys.executable, "-I", str(ORACLES_PY), *args], cwd=tmp, env=env, capture_output=True,
                              text=True, timeout=120, check=False)
        return proc, result

    def test_every_planted_defect_replays_as_a_canary_match_with_the_exact_result_shape(self):
        for name, spec in oracles.DEFECTS.items():
            with self.subTest(defect=name), tempfile.TemporaryDirectory(prefix="res dir ") as tmp:
                proc, path = self.run_cli(["replay", "--defect", name], tmp)  # seed comes from FFW_SEED
                self.assertEqual(proc.returncode, 1, proc.stderr)
                result = json.loads(path.read_text())
                self.assertEqual(set(result), RESULT_KEYS)
                self.assertEqual((result["schema"], result["run_id"], result["case_id"], result["nonce"]),
                                 ("ffw.case-result.v1", "run-7", "case.under test", "abc123"))
                self.assertEqual((result["verdict"], result["oracle"]), ("fail", spec.oracle))
                self.assertEqual(result["oracle_kind"], oracles.ORACLE_KIND[spec.oracle])
                self.assertIs(result["independent"], True)
                self.assertGreaterEqual(result["mismatches"], 1)
                self.assertGreaterEqual(result["checks"], 1)
                self.assertNotEqual(result["expected"], result["observed"])
                self.assertIn(spec.kind, result["first_causal_event"])
                self.assertEqual(result["expected"]["defect_identity"], {"oracle": spec.oracle, "kind": spec.kind})
                self.assertTrue(all(isinstance(v, int) and not isinstance(v, bool) for v in result["counters"].values()))
                self.assertEqual((result["finalized"], result["incomplete_reasons"]), (True, []))
                self.assertIn(spec.kind, result["violation_kinds"])
                self.assertEqual(sum(result["violation_kinds"].values()), result["mismatches"])
                self.assertEqual(contract_problems(result), [])
                self.assertLessEqual(path.stat().st_size, 256 * 1024)
                self.assertEqual([p.name for p in Path(tmp).iterdir()], ["result.json"], "no temp file left behind")

    def test_every_oracle_has_a_positive_case_that_passes_with_evidence(self):
        for name in oracles.ORACLE_NAMES:
            with self.subTest(oracle=name), tempfile.TemporaryDirectory() as tmp:
                proc, path = self.run_cli(["positive", "--oracle", name], tmp)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                result = json.loads(path.read_text())
                self.assertEqual((result["verdict"], result["oracle"], result["mismatches"]), ("pass", name, 0))
                self.assertGreaterEqual(result["checks"], 1)
                self.assertEqual(set(result), RESULT_KEYS)
                self.assertEqual((result["finalized"], result["incomplete_reasons"], result["violation_kinds"]), (True, [], {}))
                self.assertEqual(contract_problems(result), [])

    def test_result_file_is_deterministic_for_the_same_environment(self):
        outs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmp:
                _, path = self.run_cli(["replay", "--defect", "false_ready_early"], tmp)
                outs.append(path.read_bytes())
        self.assertEqual(outs[0], outs[1])

    def test_seed_flag_and_environment_agree_and_one_is_required(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            a, pa = self.run_cli(["replay", "--defect", "sample_loss"], t1)
            b, pb = self.run_cli(["replay", "--defect", "sample_loss", "--seed", "123"], t2, env_extra={"FFW_SEED": None})
            self.assertEqual((a.returncode, b.returncode), (1, 1))
            self.assertEqual(pa.read_bytes(), pb.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            proc, path = self.run_cli(["replay", "--defect", "sample_loss"], tmp, env_extra={"FFW_SEED": None})
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(path.exists())
            proc, path = self.run_cli(["replay", "--defect", "sample_loss"], tmp, env_extra={"FFW_SEED": "12x"})
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(path.exists())

    def test_ffw_seed_must_be_a_plain_decimal_integer(self):
        # int() is looser than the contract: it takes "1_000", " 12", "+5" and non-ASCII digits.
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ("1_000", " 12", "+5", "-5", "\u0661\u0662\u0663", "0x10", "", "1.5"):
                proc, path = self.run_cli(["replay", "--defect", "sample_loss"], tmp, env_extra={"FFW_SEED": bad})
                self.assertEqual(proc.returncode, 2, repr(bad))
                self.assertFalse(path.exists(), repr(bad))
            for good in ("0", "123", str(2**64 - 1)):
                proc, path = self.run_cli(["replay", "--defect", "sample_loss"], tmp, env_extra={"FFW_SEED": good})
                self.assertEqual(proc.returncode, 1, (good, proc.stderr))
                self.assertEqual(json.loads(path.read_text())["oracle"], "sample")

    def test_cannot_produce_a_valid_result_so_no_result_and_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            for missing in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE"):
                proc, path = self.run_cli(["replay", "--defect", "sample_loss"], tmp, env_extra={missing: None})
                self.assertEqual(proc.returncode, 2, missing)
                self.assertFalse(path.exists(), missing)
            proc, path = self.run_cli(["replay"], tmp)  # no single oracle to judge
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(path.exists())
            proc, _ = self.run_cli(["replay", "--defect", "sample_loss"], tmp,
                                   env_extra={"FFW_RESULT_PATH": str(Path(tmp) / "no such dir" / "r.json")})
            self.assertEqual(proc.returncode, 2, "an unwritable result path must not look like success")
            self.assertEqual([p.name for p in Path(tmp).iterdir()], [])

    def test_without_a_result_path_the_command_line_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, _ = self.run_cli(["positive", "--oracle", "epoch"], tmp, with_result=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], "passed")
            self.assertEqual(list(Path(tmp).iterdir()), [])


# ---------------------------------------------------------------------------
class TestCommandLine(unittest.TestCase):
    def run_script(self, script, args, cwd, timeout=120):
        return subprocess.run([sys.executable, "-I", str(script), *args], cwd=str(cwd), capture_output=True,
                              text=True, timeout=timeout, check=False)

    def test_replay_from_a_cwd_with_spaces_using_a_copied_script(self):
        with tempfile.TemporaryDirectory(prefix="oracle cli ") as tmp:
            workdir = Path(tmp) / "work dir with spaces"
            script_dir = Path(tmp) / "script dir"
            workdir.mkdir()
            script_dir.mkdir()
            script = script_dir / "oracles.py"
            shutil.copyfile(ORACLES_PY, script)  # proves the module has no sibling imports
            good = self.run_script(script, ["replay", "--seed", "5"], workdir)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(json.loads(good.stdout)["status"], "passed")
            bad = self.run_script(script, ["replay", "--seed", "5", "--defect", "stale_epoch"], workdir)
            self.assertEqual(bad.returncode, 1, bad.stderr)
            self.assertEqual(json.loads(bad.stdout)["status"], "failed")
            self.assertNotIn(tmp, good.stdout + bad.stdout, "output must not embed local paths")

    def test_reported_replay_argv_reproduces_the_exact_trace(self):
        in_process = oracles.run_house(21, ["double_apply"])
        argv = in_process["replay_argv"]
        self.assertTrue(argv[0].endswith("scripts/test/test_support/oracles.py"))
        with tempfile.TemporaryDirectory() as tmp:
            out = self.run_script(ORACLES_PY, argv[1:], tmp)
        self.assertEqual(out.returncode, 1, out.stderr)
        replayed = json.loads(out.stdout)["reports"][0]
        self.assertEqual(replayed["trace_digest"], in_process["trace_digest"])
        self.assertEqual(replayed["schedule_digest"], in_process["schedule_digest"])

    def test_parallel_runs_in_separate_cwds_are_isolated_and_identical(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            cmd = [sys.executable, "-I", str(ORACLES_PY), "replay", "--seed", "77", "--defect", "false_ready_early"]
            p1 = subprocess.Popen(cmd, cwd=t1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            p2 = subprocess.Popen(cmd, cwd=t2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out1, _ = p1.communicate(timeout=120)
            out2, _ = p2.communicate(timeout=120)
        self.assertEqual((p1.returncode, p2.returncode), (1, 1))
        self.assertEqual(out1, out2)

    def test_canaries_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.run_script(ORACLES_PY, ["canaries", "--seeds", "11", "12"], tmp)
        self.assertEqual(out.returncode, 0, out.stderr)
        summary = json.loads(out.stdout)
        self.assertEqual((summary["status"], summary["denominator"], summary["passed"], summary["failed"]),
                         ("passed", 15, 15, 0))

    def test_usage_errors_exit_two_and_never_look_like_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            for args in (["replay", "--seed", "1", "--defect", "nope"], ["replay"], ["bogus"],
                         ["replay", "--seed", "1", "--profile-json", "[1]"],
                         ["replay", "--seed", "1", "--profile-json", "{\"blocks\": 5}"],
                         ["replay", "--seed", "1", "--profile-json", "{not json"],
                         ["replay", "--seed", "1", "--profile-json", "{\"unknown_knob\": 1}"]):
                out = self.run_script(ORACLES_PY, args, tmp)
                self.assertEqual(out.returncode, 2, (args, out.stdout, out.stderr))

    def test_profile_override_changes_the_schedule(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.run_script(ORACLES_PY, ["replay", "--seed", "3", "--defect", "sample_loss"], tmp)
            b = self.run_script(ORACLES_PY, ["replay", "--seed", "3", "--defect", "sample_loss",
                                             "--profile-json", "{\"blocks\": 100}"], tmp)
        self.assertEqual((a.returncode, b.returncode), (1, 1))
        da, db = json.loads(a.stdout)["reports"][0], json.loads(b.stdout)["reports"][0]
        self.assertNotEqual(da["schedule_digest"], db["schedule_digest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
