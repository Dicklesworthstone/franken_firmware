#!/usr/bin/env python3
"""Tests for diagnostics.py (Q00 / ffw-2qz): bounded, nonblocking, redacting diagnostic sink.

Standard library only. Offline. No network, no device, no production crate.

Run directly or via unittest (both work from any cwd, including paths with
spaces, because this file puts its own directory on ``sys.path``)::

    python3 -I scripts/test/test_support/test_diagnostics.py
    python3 -m unittest discover -s scripts/test/test_support -p test_diagnostics.py

It is also a runner child case: when the suite runner sets ``FFW_RESULT_PATH``
(wire contract ``ffw.case-result.v1``) it runs the subset named by
``--case ID`` / ``FFW_CASE_ID`` and writes the result file. ``--canary NAME``
plants a known defect and reports a *fail* from the oracle that must catch it.

Evidence labelling - read before trusting a green run:

* Tests whose name contains ``INJECTED`` use ``FaultableSink``, an in-memory
  target that raises scripted errors. They prove the sink's *reaction* to a
  failure, not the behaviour of a real disk.
* ``test_real_os_*`` make the operating system itself refuse writes, in a
  child process (``RLIMIT_FSIZE``) or against ``/dev/full`` (Linux only). A test
  that cannot run on the host SKIPS with a reason; a skip is not a pass and
  the child-case reporter counts skipped tests separately.
* Nothing here asserts wall-clock latency (not deterministic). "Nonblocking" is
  asserted as: a producer finishes while the target is blocked and never
  released, and a deliberately blocking mutant is shown to fail the same harness.
* None of this qualifies the on-device render path (Q02/Q03).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import diagnostics as d  # noqa: E402  (path set up above)

HANG_GUARD_S = 30.0  # only ever a guard against a hung test, never a timing assertion
# The only host limitation a manifest may declare with --allow-skip. The skip decorator and the manifest check below
# share this string, so the declaration cannot drift away from the text unittest actually reports.
DEV_FULL_SKIP_REASON = "/dev/full does not exist on this host (Linux only)"
# Reason prefixes that must stay UNDECLARED: skipping a real-OS write-refusal test is a check that did not happen.
NEVER_DECLARABLE_SKIPS = ("RLIMIT_FSIZE is not enforced on this host",)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

class FakeClock:
    """Deterministic ns clock: only moves when the test says so."""

    def __init__(self, start: int = 1_000_000_000) -> None:
        self.t = start

    def __call__(self) -> int:
        return self.t

    def advance_ms(self, ms: float) -> None:
        self.t += int(ms * 1_000_000)


def lim(**kw):
    base = dict(max_queue_events=8, max_queue_bytes=1 << 16, max_event_bytes=2048, max_file_bytes=1 << 17,
                critical_reserve_bytes=1 << 14, footer_reserve_bytes=2048, max_events_per_sec=None,
                burst_events=100, drain_batch=4, failure_threshold=3, retry_interval_s=0.5,
                critical_max_attempts=3, close_timeout_s=2.0)
    base.update(kw)
    return d.SinkLimits(**base)


def make(target=None, *, limits=None, clock=None, run_id="t1", threaded=False, redaction=None, **kw):
    clock = clock if clock is not None else FakeClock()
    target = target if target is not None else d.FaultableSink()
    sink = d.DiagnosticSink(target, run_id=run_id, limits=limits or lim(), clock_ns=clock,
                            pseudonym_key=b"unit-test-key", threaded=threaded, redaction=redaction, **kw)
    return sink, target, clock


def events_of(target):
    return [r for r in target.records() if r.get("type") == "event"]


def wait_thread(name_prefix, timeout=HANG_GUARD_S):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        live = [t for t in threading.enumerate() if t.name.startswith(name_prefix) and t.is_alive()]
        if not live:
            return True
        live[0].join(0.05)
    return False


def run_in_thread(fn, timeout=HANG_GUARD_S):
    """Run fn in a thread; return (finished, result_or_exception)."""
    box = {}

    def go():
        try:
            box["r"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["e"] = exc
    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(timeout)
    return (not th.is_alive()), box.get("e", box.get("r"))


def secret(prefix: str, n: int, ch: str = "k") -> str:
    # Built at runtime so the test source never contains a literal that looks like a real credential.
    return prefix + ch * n


class ClosureMixin:
    def assertClosed(self, st):
        self.assertEqual(sum(st["dropped"].values()), st["dropped_total"], "per-reason drops must sum to the total")
        self.assertEqual(st["queued"], 0)
        self.assertEqual(st["inflight"], 0)
        self.assertEqual(st["emitted"], st["written"] + st["dropped_total"],
                         "every emit() must end as exactly one of written or dropped-with-reason")


# --------------------------------------------------------------------------- #
# envelope, determinism, API shape
# --------------------------------------------------------------------------- #

class EnvelopeTests(ClosureMixin, unittest.TestCase):
    def test_header_events_footer_and_full_envelope(self):
        sink, tgt, _ = make()
        sink.pump()
        ok = sink.emit("case.begin", level="WARNING", critical=True, case_id="q00.unit.x", correlation_id="corr-1",
                       member="speaker-living-room", group="house-1", source_epoch=7, command_rev=41, state_rev=99,
                       counters={"queue_depth": 3, "latency_us": 12.5, "bad": "text", "flag": True},
                       fault={"id": "f1", "kind": "slow_sink"}, cause=[{"type": "E", "msg": "boom"}],
                       fields={"note": "hello"})
        self.assertTrue(ok)
        v = sink.close()
        self.assertTrue(v.complete, v)
        recs = tgt.records()
        self.assertEqual([r["type"] for r in recs], ["header", "event", "footer"])
        hdr, ev, ftr = recs
        self.assertEqual(hdr["schema"], d.SCHEMA)
        self.assertEqual(hdr["timebase"]["clock"], "monotonic_ns")
        self.assertEqual(hdr["pseudonym"], {"scheme": "hmac-sha256/12", "key_source": "provided"})
        self.assertEqual(hdr["redaction"]["policy"], d.REDACTION_POLICY_ID)
        self.assertEqual(ev["level"], "warn")
        self.assertEqual((ev["seq"], ev["run"], ev["case"], ev["corr"]), (1, "t1", "q00.unit.x", "corr-1"))
        self.assertEqual((ev["epoch"], ev["cmd_rev"], ev["state_rev"]), (7, 41, 99))
        self.assertEqual(ev["counters"], {"queue_depth": 3, "latency_us": 12.5})  # non-numeric / bool rejected
        self.assertEqual(sink.stats()["invalid_counters"], 2)
        self.assertEqual(ev["fault"], {"id": "f1", "kind": "slow_sink"})
        self.assertEqual(ev["cause"], [{"type": "E", "msg": "boom"}])
        self.assertTrue(ev["critical"])
        # raw member/group identifiers never reach the file; pseudonyms do
        text = tgt.text()
        self.assertNotIn("speaker-living-room", text)
        self.assertNotIn("house-1", text)
        self.assertTrue(ev["member"].startswith("m-") and ev["group"].startswith("g-"))
        self.assertEqual(ftr["stats"]["emitted"], 1)
        self.assertTrue(d.audit_bytes(bytes(tgt.data)).complete)
        self.assertClosed(sink.stats())

    def test_pseudonyms_are_stable_keyed_and_kind_separated(self):
        a = d.pseudonymize(b"k1", "member", "x")
        self.assertEqual(a, d.pseudonymize(b"k1", "member", "x"))
        self.assertNotEqual(a, d.pseudonymize(b"k2", "member", "x"))
        self.assertNotEqual(a[2:], d.pseudonymize(b"k1", "group", "x")[2:])      # kind is part of the keyed input
        sink, _, _ = make()
        self.assertEqual(sink.pseudonym("member", "x"), d.pseudonymize(b"unit-test-key", "member", "x"))
        r1, _, _ = make(); r2, _, _ = make()
        self.assertEqual(r1.pseudonym("member", "x"), r2.pseudonym("member", "x"))
        rnd = d.DiagnosticSink(d.FaultableSink(), run_id="r", threaded=False)
        self.assertNotEqual(rnd.pseudonym("member", "x"), r1.pseudonym("member", "x"))
        rnd.close()

    def test_mono_ns_never_regresses_even_if_the_clock_does(self):
        sink, tgt, clock = make()
        sink.pump()
        sink.emit("a")
        clock.t -= 500_000_000  # clock jumps backwards
        sink.emit("b")
        clock.t += 700_000_000
        sink.emit("c")
        sink.close()
        ns = [e["mono_ns"] for e in events_of(tgt)]
        self.assertEqual(ns, sorted(ns))
        self.assertEqual(sink.stats()["clock_regressions"], 1)
        self.assertTrue(d.audit_bytes(bytes(tgt.data)).complete)

    def test_broken_clock_is_counted_and_never_raises(self):
        calls = {"n": 0}

        def clock():
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("clock exploded")
            return 5

        sink = d.DiagnosticSink(d.FaultableSink(), run_id="clk", clock_ns=clock, threaded=False)
        self.assertTrue(sink.emit("x"))
        self.assertGreaterEqual(sink.stats()["clock_errors"], 1)
        sink.close()

    def test_bound_emitter_and_runner_style_emit_event(self):
        sink, tgt, _ = make()
        sink.pump()
        b = sink.bind(case_id="c1", fields={"a": 1}).bind(correlation_id="k")
        b.emit("one", fields={"b": 2})
        sink.emit_event("run_start", critical=True, tier="smoke", planned=3, corr="rc", case_id="c2", level="info")
        sink.close()
        e1, e2 = events_of(tgt)
        self.assertEqual((e1["case"], e1["corr"], e1["fields"]), ("c1", "k", {"a": 1, "b": 2}))
        self.assertEqual((e2["kind"], e2["case"], e2["corr"], e2["fields"], e2["critical"]),
                         ("run_start", "c2", "rc", {"tier": "smoke", "planned": 3}, True))

    def test_limits_and_ids_are_validated(self):
        for kw in ({"max_queue_events": 1}, {"max_event_bytes": 100}, {"footer_reserve_bytes": 10},
                   {"max_queue_bytes": 100}, {"max_file_bytes": 100}, {"max_events_per_sec": 0},
                   {"failure_threshold": 0}, {"critical_max_attempts": 0}):
            with self.assertRaises(ValueError, msg=str(kw)):
                d.SinkLimits(**kw)
        with self.assertRaises(ValueError):
            d.RedactionPolicy(max_str_len=100, raw_str_cap=10)
        for bad in ("", "has space", "a/b", "x" * 65, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                d.DiagnosticSink(d.FaultableSink(), run_id=bad, threaded=False)

    def test_garbage_arguments_never_raise_and_are_accounted(self):
        sink, tgt, _ = make()
        sink.pump()
        self.assertFalse(sink.emit("bad", counters=5))              # .items() on an int -> internal error
        self.assertTrue(sink.emit(object(), fields=5, cause="boom", level=object()))
        self.assertTrue(sink.emit(None, fields=[object(), {1: 2}, {b"k": b"v"}]))
        st = sink.stats()
        self.assertEqual(st["dropped"]["internal_error"], 1)
        self.assertIn("AttributeError", st["last_internal_error"])
        sink.close()
        self.assertClosed(sink.stats())


# --------------------------------------------------------------------------- #
# bounds and exact loss accounting
# --------------------------------------------------------------------------- #

class BoundsAndLossTests(ClosureMixin, unittest.TestCase):
    def test_queue_event_bound_exact_and_loss_marker_range(self):
        sink, tgt, _ = make(limits=lim(max_queue_events=8))
        sink.pump()                                   # header out of the queue
        accepted = [sink.emit("n", fields={"i": i}) for i in range(20)]
        self.assertEqual(accepted, [True] * 8 + [False] * 12)
        st = sink.stats()
        self.assertEqual((st["accepted"], st["queued"], st["dropped"]["queue_full"]), (8, 8, 12))
        self.assertLessEqual(st["queue_peak_events"], 8)
        sink.close()
        st = sink.stats()
        self.assertEqual((st["written"], st["dropped_total"]), (8, 12))
        self.assertClosed(st)
        marks = [r for r in tgt.records() if r["type"] == "loss"]
        self.assertEqual(len(marks), 1)
        self.assertEqual(marks[0]["dropped"], {"queue_full": 12})
        self.assertEqual((marks[0]["first_dropped_seq"], marks[0]["last_dropped_seq"]), (9, 20))
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(audit.complete, audit.reasons)  # non-critical loss is visible but not evidence loss
        self.assertEqual((audit.events, audit.dropped_total, audit.loss_markers), (8, 12, 1))

    def test_loss_before_the_first_write_never_puts_a_marker_ahead_of_the_header(self):
        sink, tgt, _ = make(limits=lim(max_queue_events=4))
        results = [sink.emit("n", fields={"i": i}) for i in range(10)]     # header still queued: 3 fit, 7 dropped
        self.assertEqual(results, [True] * 3 + [False] * 7)
        sink.close()
        types = [r["type"] for r in tgt.records()]
        self.assertEqual(types[0], "header")
        self.assertEqual(types.count("loss"), 1)
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(audit.complete, audit.reasons)
        self.assertEqual((audit.events, audit.dropped_total), (3, 7))

    def test_queue_byte_bound_is_never_exceeded(self):
        sink, _, _ = make(limits=lim(max_queue_events=512, max_queue_bytes=3000, max_event_bytes=1024))
        sink.pump()
        for i in range(100):
            sink.emit("n", fields={"pad": "p" * 200, "i": i})
            self.assertLessEqual(sink.stats()["queued_bytes"], 3000)
        st = sink.stats()
        self.assertGreater(st["dropped"]["queue_bytes"], 0)
        self.assertEqual(st["accepted"] + st["dropped"]["queue_bytes"], 100)
        self.assertLessEqual(st["queue_peak_bytes"], 3000)
        sink.close()
        self.assertClosed(sink.stats())

    def test_event_rate_limit_token_bucket_exact_with_critical_bypass(self):
        sink, tgt, clock = make(limits=lim(max_queue_events=64, max_events_per_sec=1000.0, burst_events=3))
        sink.pump()
        self.assertEqual([sink.emit("n") for _ in range(5)], [True, True, True, False, False])
        self.assertTrue(sink.emit("c", critical=True))             # evidence is never rate limited
        clock.advance_ms(1)                                        # exactly one token at 1000/s
        self.assertEqual([sink.emit("n") for _ in range(2)], [True, False])
        clock.advance_ms(1000)                                     # refill is capped at the burst
        self.assertEqual([sink.emit("n") for _ in range(5)], [True, True, True, False, False])
        st = sink.stats()
        self.assertEqual(st["dropped"]["rate_limited"], 2 + 1 + 2)
        sink.close()
        self.assertClosed(sink.stats())

    def test_oversize_event_shrinks_and_is_flagged_not_silently_cut(self):
        sink, tgt, _ = make(limits=lim(max_event_bytes=2048))
        sink.pump()
        big = {"k%02d" % i: "x" * 1000 for i in range(32)}
        self.assertTrue(sink.emit("big", fields=big))
        sink.close()
        (ev,) = events_of(tgt)
        self.assertEqual(ev["fields"], {"_dropped": "oversize"})
        self.assertTrue(ev["truncated"])
        self.assertEqual(sink.stats()["truncated_events"], 1)
        for line in bytes(tgt.data).split(b"\n"):
            self.assertLessEqual(len(line) + 1, 2048 if b'"type":"event"' in line else 1 << 20)

    def test_unshrinkable_event_is_dropped_and_a_critical_one_invalidates(self):
        sink, tgt, _ = make(limits=lim(max_event_bytes=512, max_queue_bytes=4096, max_file_bytes=1 << 15,
                                       critical_reserve_bytes=4096))
        sink.pump()
        long_ids = dict(case_id="c" * 200, correlation_id="r" * 200)
        self.assertFalse(sink.emit("k" * 100, **long_ids))
        self.assertEqual(sink.stats()["dropped"]["oversize"], 1)
        self.assertEqual(sink.stats()["critical_lost"], 0)
        self.assertFalse(sink.emit("k" * 100, critical=True, **long_ids))
        self.assertEqual(sink.stats()["critical_lost"], 1)
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertIn("critical_evidence_lost:1", v.reasons)
        self.assertClosed(sink.stats())

    def test_real_file_stays_within_disk_budget_and_reserve_serves_critical(self):
        with tempfile.TemporaryDirectory(prefix="diag budget ") as td:
            path = os.path.join(td, "diag.jsonl")
            limits = lim(max_queue_events=512, max_event_bytes=1024, max_file_bytes=12288,
                         critical_reserve_bytes=4096, footer_reserve_bytes=2048)
            sink = d.DiagnosticSink.to_file(path, run_id="disk", limits=limits, clock_ns=FakeClock(),
                                            pseudonym_key=b"k", threaded=False)
            for i in range(100):
                sink.emit("n", fields={"i": i})
            for i in range(3):
                self.assertTrue(sink.emit("c", critical=True, case_id="c%d" % i))
            v = sink.close()
            st = sink.stats()
            self.assertGreater(st["dropped"]["disk_budget"], 0)
            self.assertEqual(st["written_critical"], 3)
            self.assertTrue(v.complete, v)
            self.assertLessEqual(os.path.getsize(path), 12288)
            self.assertClosed(st)
            audit = d.audit_log(path)
            self.assertTrue(audit.complete, audit.reasons)
            self.assertEqual(audit.dropped_total, st["dropped_total"])
            self.assertEqual(audit.critical_events, 3)

    def test_critical_flood_exhausting_the_reserve_invalidates_and_still_bounds_the_file(self):
        with tempfile.TemporaryDirectory(prefix="diag budget ") as td:
            path = os.path.join(td, "diag.jsonl")
            limits = lim(max_queue_events=1024, max_event_bytes=1024, max_file_bytes=12288,
                         critical_reserve_bytes=4096, footer_reserve_bytes=2048)
            sink = d.DiagnosticSink.to_file(path, run_id="disk2", limits=limits, clock_ns=FakeClock(),
                                            pseudonym_key=b"k", threaded=False)
            results = [sink.emit("c", critical=True, case_id="c%d" % (i % 3), fields={"i": i}) for i in range(200)]
            self.assertFalse(all(results))
            v = sink.close()
            self.assertFalse(v.complete)
            self.assertTrue(any(r.startswith("critical_evidence_lost") for r in v.reasons), v.reasons)
            self.assertLessEqual(os.path.getsize(path), 12288)
            audit = d.audit_log(path)
            self.assertFalse(audit.complete)
            self.assertTrue(any(r.startswith("critical_evidence_lost") for r in audit.reasons), audit.reasons)
            self.assertEqual(audit.critical_lost, sink.stats()["critical_lost"])
            self.assertClosed(sink.stats())

    def test_randomized_scenarios_close_exactly_agree_with_the_independent_audit_and_replay_identically(self):
        def scenario(seed):
            rng = random.Random(seed)
            clock, tgt = FakeClock(), d.FaultableSink()
            sink = d.DiagnosticSink(tgt, run_id="rand", clock_ns=clock, pseudonym_key=b"k", threaded=False,
                                    limits=lim(max_queue_events=12, max_events_per_sec=2000.0, burst_events=20,
                                               max_file_bytes=1 << 16, critical_reserve_bytes=1 << 13))
            for step in range(400):
                op = rng.random()
                if op < 0.55:
                    sink.emit("n", fields={"i": step, "pad": "x" * rng.randrange(0, 300)})
                elif op < 0.65:
                    sink.emit("c", critical=True, case_id="c%d" % rng.randrange(3), fields={"i": step})
                elif op < 0.70:
                    sink.emit("big", fields={"blob": "y" * rng.randrange(0, 5000), "k": list(range(rng.randrange(0, 40)))})
                elif op < 0.85:
                    sink.pump(rng.randrange(1, 6))
                elif op < 0.90:
                    clock.advance_ms(rng.randrange(0, 700))
                elif op < 0.93:
                    tgt.available = not tgt.available
                elif op < 0.96:
                    tgt.capacity_bytes = None if rng.random() < 0.5 else len(tgt.data) + rng.randrange(0, 400)
                else:
                    tgt.fail_next(rng.randrange(1, 3))
            tgt.available, tgt.capacity_bytes = True, None
            tgt.fail_next(0)
            verdict = sink.close(timeout=5)
            return sink.stats(), bytes(tgt.data), verdict

        integrity = {"event_count_mismatch", "critical_count_mismatch", "loss_accounting_mismatch",
                     "seq_not_monotonic", "mono_ns_regressed", "last_seq_mismatch", "duplicate_header",
                     "duplicate_footer", "records_after_footer", "loss_marker_overcount", "critical_loss_hidden",
                     "footer_stats_invalid", "run_mismatch", "seq_beyond_footer", "missing_footer"}
        saw_loss = saw_incomplete = False
        for seed in range(1, 13):
            st, data, verdict = scenario(seed)
            self.assertClosed(st)
            audit = d.audit_bytes(data)
            bad = integrity & set(audit.reasons)
            self.assertFalse(bad, "seed %d: %s" % (seed, bad))
            self.assertEqual(verdict.complete, audit.complete,
                             "seed %d: producer verdict %s vs independent audit %s" % (seed, verdict.reasons, audit.reasons))
            self.assertEqual(audit.dropped_total, st["dropped_total"])
            st2, data2, _ = scenario(seed)
            self.assertEqual(data, data2, "seed %d did not replay byte-identically" % seed)
            self.assertEqual(st, st2)
            saw_loss |= st["dropped_total"] > 0
            saw_incomplete |= not verdict.complete
        self.assertTrue(saw_loss, "scenarios must actually exercise loss")
        self.assertTrue(saw_incomplete, "scenarios must actually exercise evidence loss")


# --------------------------------------------------------------------------- #
# critical-evidence semantics
# --------------------------------------------------------------------------- #

class CriticalEvidenceTests(ClosureMixin, unittest.TestCase):
    def test_critical_event_evicts_queued_noncritical_events(self):
        sink, tgt, _ = make(limits=lim(max_queue_events=8))
        sink.pump()
        for i in range(8):
            self.assertTrue(sink.emit("n", fields={"i": i}))
        self.assertFalse(sink.emit("n", fields={"i": 99}))                  # full: non-critical dropped
        self.assertTrue(sink.emit("stop", critical=True, case_id="c"))      # critical evicts the oldest non-critical
        st = sink.stats()
        self.assertEqual((st["dropped"]["queue_full"], st["dropped"]["evicted_for_critical"]), (1, 1))
        v = sink.close()
        self.assertTrue(v.complete)
        kinds = [e["kind"] for e in events_of(tgt)]
        self.assertEqual(kinds.count("stop"), 1)
        self.assertEqual(kinds.count("n"), 7)
        self.assertEqual(kinds[-1], "stop")
        self.assertClosed(sink.stats())

    def test_lost_critical_event_invalidates_qualification_everywhere(self):
        sink, tgt, _ = make(limits=lim(max_queue_events=4))
        sink.pump()
        for i in range(4):
            self.assertTrue(sink.emit("c", critical=True, case_id="caseA"))
        self.assertFalse(sink.emit("c", critical=True, case_id="caseA"))   # queue is all evidence and full
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertEqual((v.critical_lost, v.critical_lost_cases), (1, ("caseA",)))
        self.assertIn("critical_evidence_lost:1", v.reasons)
        with self.assertRaises(d.EvidenceIncomplete) as cm:
            v.require_complete()
        self.assertIs(cm.exception.verdict, v)
        self.assertEqual(d.downgrade_pass_if_incomplete("pass", v), "incomplete")
        self.assertEqual(d.downgrade_pass_if_incomplete("fail", v), "fail")      # a failure is never hidden
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertFalse(audit.complete)
        self.assertEqual(d.downgrade_pass_if_incomplete("pass", audit), "incomplete")
        block = audit.receipt_log_block()
        self.assertTrue(block["critical_lost"])
        self.assertEqual(set(block), {"sha256", "events", "dropped", "bytes", "truncated", "critical_lost"})

    def test_positive_twin_complete_evidence_passes(self):
        sink, tgt, _ = make()
        sink.pump()
        sink.emit("case.begin", critical=True, case_id="c")
        sink.emit("case.end", critical=True, case_id="c")
        v = sink.close()
        self.assertTrue(v.complete)
        self.assertIs(v.require_complete(), v)
        self.assertEqual(d.downgrade_pass_if_incomplete("pass", v), "pass")
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(audit.complete)
        block = audit.receipt_log_block()
        self.assertEqual((block["truncated"], block["critical_lost"], block["events"], block["dropped"]), (False, False, 2, 0))

    def test_case_verdict_isolates_cases_but_run_level_loss_invalidates_all(self):
        sink, _, _ = make(limits=lim(max_queue_events=3))
        sink.pump()
        for _ in range(3):
            sink.emit("c", critical=True, case_id="A")
        self.assertFalse(sink.emit("c", critical=True, case_id="A"))
        sink.pump()
        self.assertFalse(sink.case_verdict("A").complete)
        self.assertEqual(sink.case_verdict("A").critical_lost, 1)
        self.assertTrue(sink.case_verdict("B").complete)
        self.assertTrue(sink.emit("c", critical=True, case_id="B"))
        self.assertIn("pending_unflushed", sink.case_verdict("B").reasons)     # queued, not yet durable
        sink.pump()
        self.assertTrue(sink.case_verdict("B").complete)
        for _ in range(3):
            sink.emit("c", critical=True, case_id="B")
        self.assertFalse(sink.emit("c", critical=True))                         # run-level evidence, no case id
        sink.pump()
        self.assertFalse(sink.case_verdict("B").complete)
        self.assertFalse(sink.case_verdict("anything").complete)
        sink.close()

    def test_absence_of_error_is_not_a_pass(self):
        # (a) never closed: no footer, so not complete even though nothing failed
        sink, tgt, _ = make()
        sink.pump()
        sink.emit("case.end", critical=True)
        sink.pump()
        self.assertEqual(sink.verdict().reasons, ("not_closed", "footer_not_written"))
        self.assertFalse(d.audit_bytes(bytes(tgt.data)).complete)
        # (b) sink dies after the events but before the footer
        sink, tgt, _ = make()
        sink.pump()
        sink.emit("case.end", critical=True)
        sink.pump()
        tgt.available = False
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertIn("footer_not_written", v.reasons)
        self.assertEqual(d.downgrade_pass_if_incomplete("pass", v), "incomplete")
        self.assertIn("missing_footer", d.audit_bytes(bytes(tgt.data)).reasons)
        # (c) nothing critical was ever emitted, but the sink was dead from the start: still not complete
        dead = d.FaultableSink()
        dead.available = False
        sink, _, _ = make(dead)
        sink.emit("note")
        v = sink.close()
        self.assertEqual(v.critical_lost, 0)
        self.assertFalse(v.complete)
        self.assertIn("header_not_written", v.reasons)

    def test_emit_after_close_is_counted_loss_and_a_late_critical_invalidates(self):
        sink, tgt, _ = make()
        v = sink.close()
        self.assertTrue(v.complete)
        size = len(tgt.data)
        self.assertFalse(sink.emit("late"))
        self.assertTrue(sink.verdict().complete)
        self.assertFalse(sink.emit("late.evidence", critical=True, case_id="z"))
        self.assertFalse(sink.verdict().complete)
        self.assertEqual(sink.stats()["dropped"]["closed"], 2)
        self.assertEqual(len(tgt.data), size, "nothing may be written after close")
        self.assertIs(sink.close().complete, False)                  # idempotent, and reflects the late loss

    def test_close_with_zero_timeout_does_not_mistake_an_idle_healthy_writer_for_a_hung_one(self):
        tgt = d.FaultableSink()
        sink = d.DiagnosticSink(tgt, run_id="zero1", limits=lim(), clock_ns=FakeClock(), pseudonym_key=b"k", threaded=True)
        self.assertTrue(sink.emit("case.end", critical=True, case_id="c"))
        self.assertTrue(sink.flush(HANG_GUARD_S))
        v = sink.close(timeout=0)
        self.assertTrue(v.complete, v.reasons)
        self.assertFalse(sink.stats()["writer_hung"])
        self.assertTrue(wait_thread("ff-diag-writer-zero1"))

    def test_target_close_error_is_surfaced(self):
        tgt = d.FaultableSink()
        tgt.close_error = OSError(5, "injected close failure")
        sink, _, _ = make(tgt)
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertIn("sink_close_error", v.reasons)


# --------------------------------------------------------------------------- #
# slow / full / unavailable sinks
# --------------------------------------------------------------------------- #

class SinkFaultTests(ClosureMixin, unittest.TestCase):
    def test_INJECTED_unavailable_sink_recovers_without_loss_inside_the_attempt_budget(self):
        tgt = d.FaultableSink()
        tgt.available = False
        sink, _, clock = make(tgt, limits=lim(max_queue_events=32))
        for i in range(3):
            sink.emit("n", fields={"i": i})
        sink.emit("c", critical=True, case_id="c1")
        self.assertEqual(sink.pump(), 0)
        st = sink.stats()
        self.assertEqual((st["sink_state"], st["write_errors"], st["written"]), ("degraded", 1, 0))
        self.assertEqual(sink.pump(), 0, "retries are spaced by retry_interval_s, not immediate")
        self.assertEqual(sink.stats()["write_errors"], 1)
        clock.advance_ms(500)
        tgt.available = True                                        # outage shorter than the attempt budget
        self.assertGreater(sink.pump(), 0)
        v = sink.close()
        st = sink.stats()
        self.assertTrue(v.complete, v.reasons)
        self.assertEqual((st["written"], st["dropped_total"], st["sink_state"]), (4, 0, "ok"))
        self.assertTrue(d.audit_bytes(bytes(tgt.data)).complete)
        self.assertClosed(st)

    def test_INJECTED_outage_longer_than_the_attempt_budget_loses_evidence_and_says_so(self):
        tgt = d.FaultableSink()
        tgt.available = False
        sink, _, clock = make(tgt, limits=lim(max_queue_events=32))
        sink.emit("c", critical=True, case_id="c1")
        sink.emit("n")
        for _ in range(3):                                          # header exhausts critical_max_attempts
            sink.pump()
            clock.advance_ms(500)
        st = sink.stats()
        self.assertEqual(st["sink_state"], "unavailable")
        self.assertFalse(st["header_written"])
        for _ in range(4):                                          # the critical event behind it also exhausts
            sink.pump()
            clock.advance_ms(500)
        st = sink.stats()
        self.assertEqual(st["critical_lost_by_reason"], {"sink_error": 1})
        tgt.available = True                                        # recovery cannot resurrect lost evidence
        sink.emit("after")
        sink.pump()
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertIn("header_not_written", v.reasons)
        self.assertIn("critical_evidence_lost:1", v.reasons)
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertFalse(audit.complete)
        self.assertIn("missing_header", audit.reasons)
        self.assertClosed(sink.stats())

    def test_INJECTED_full_sink_noncritical_loss_leaves_a_torn_line_that_is_resynced(self):
        sink, tgt, clock = make()
        sink.pump()
        for i in range(3):
            sink.emit("n", fields={"i": i})
        sink.pump()
        tgt.capacity_bytes = len(tgt.data) + 40                     # only 40 bytes of the next line fit
        sink.emit("lost.noncritical")
        sink.pump()
        torn = bytes(tgt.data).rsplit(b"\n", 1)[-1]
        self.assertTrue(0 < len(torn) <= 40)
        with self.assertRaises(ValueError):
            json.loads(torn)
        self.assertEqual(sink.stats()["dropped"]["sink_error"], 1)
        tgt.capacity_bytes = None
        clock.advance_ms(500)
        sink.emit("after")
        sink.pump()
        v = sink.close()
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(v.complete and audit.complete, (v.reasons, audit.reasons))
        self.assertEqual(audit.warnings, ["corrupt_lines:1"])
        self.assertEqual((audit.events, audit.dropped_total, audit.loss_markers), (4, 1, 1))
        self.assertEqual([e["kind"] for e in events_of(tgt)], ["n", "n", "n", "after"])
        self.assertClosed(sink.stats())

    def test_INJECTED_full_sink_critical_event_survives_by_retry_after_space_returns(self):
        sink, tgt, clock = make()
        sink.pump()
        sink.emit("n")
        sink.pump()
        tgt.capacity_bytes = len(tgt.data) + 40
        sink.emit("case.end", critical=True, case_id="c")
        sink.pump()
        self.assertEqual(sink.stats()["written_critical"], 0)
        self.assertEqual(sink.stats()["critical_lost"], 0, "retried, not yet lost")
        tgt.capacity_bytes = None
        clock.advance_ms(500)
        sink.pump()
        v = sink.close()
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(v.complete and audit.complete, (v.reasons, audit.reasons))
        self.assertEqual(audit.critical_events, 1)
        self.assertEqual(audit.warnings, ["corrupt_lines:1"])

    def test_INJECTED_record_torn_exactly_before_its_newline_is_not_resurrected_as_written(self):
        # Regression: a cut that stores the whole JSON object but not its newline leaves a valid-looking line.
        # Resyncing with a bare "\n" would have "completed" it into a record the sink had already counted lost.
        sink, tgt, clock = make()
        sink.pump()
        sink.emit("n", fields={"i": 0})
        sink.pump()
        sink.emit("lost", fields={"pad": "x" * 40})
        line_len = sink.stats()["queued_bytes"]
        tgt.capacity_bytes = len(tgt.data) + line_len - 1               # everything except the trailing newline
        sink.pump()
        torn = bytes(tgt.data).rsplit(b"\n", 1)[-1]
        self.assertEqual(json.loads(torn)["kind"], "lost", "the torn tail must be complete JSON for this test to bite")
        self.assertEqual(sink.stats()["dropped"]["sink_error"], 1)
        tgt.capacity_bytes = None
        clock.advance_ms(500)
        sink.emit("after")
        sink.pump()
        v = sink.close()
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(v.complete and audit.complete, (v.reasons, audit.reasons))
        self.assertEqual(audit.events, 2, "the torn 'lost' record must not be counted as written")
        self.assertEqual([e["kind"] for e in events_of(tgt)], ["n", "after"])
        self.assertEqual(audit.warnings, ["corrupt_lines:1"])

    def test_INJECTED_loss_marker_that_landed_in_a_failed_write_is_not_recorded_twice(self):
        # Regression (found by the randomized scenarios): marker + record shared one write; a full device kept
        # the marker but tore the record, the marker stayed pending, and the retry wrote the same losses again.
        sink, tgt, clock = make(limits=lim(max_queue_events=3))
        sink.pump()
        for i in range(5):                                               # 3 accepted, 2 dropped -> pending marker
            sink.emit("n", fields={"i": i, "pad": "x" * 300})
        self.assertEqual(sink.stats()["dropped"]["queue_full"], 2)
        tgt.capacity_bytes = len(tgt.data) + 300                         # marker (~150 B) fits; marker + record does not
        sink.pump()
        self.assertEqual([r["type"] for r in tgt.records()], ["header", "loss"], "marker landed, first record torn")
        self.assertEqual(sink.stats()["dropped"]["sink_error"], 1)
        tgt.capacity_bytes = None
        clock.advance_ms(500)
        sink.pump()
        v = sink.close()
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(v.complete and audit.complete, (v.reasons, audit.reasons))
        marks = [r for r in tgt.records() if r["type"] == "loss"]
        self.assertEqual(sum(sum(m["dropped"].values()) for m in marks), audit.dropped_total)
        self.assertEqual(audit.dropped_total, 3)

    def test_INJECTED_full_sink_that_never_recovers_invalidates_via_footer_and_critical_loss(self):
        tgt = d.FaultableSink(capacity_bytes=3000)
        sink, _, clock = make(tgt, limits=lim(max_queue_events=64, retry_interval_s=0.0))
        for i in range(30):
            sink.emit("n", fields={"i": i, "pad": "p" * 50})
        sink.emit("case.end", critical=True, case_id="c")
        sink.pump()
        v = sink.close()
        self.assertFalse(v.complete)
        self.assertTrue(any(r.startswith("critical_evidence_lost") for r in v.reasons), v.reasons)
        self.assertIn("footer_not_written", v.reasons)
        self.assertLessEqual(len(tgt.data), 3000)
        self.assertFalse(d.audit_bytes(bytes(tgt.data)).complete)
        self.assertClosed(sink.stats())

    def test_INJECTED_slow_sink_never_blocks_emit_and_critical_events_still_get_through(self):
        tgt = d.FaultableSink()
        tgt.gate()
        sink = d.DiagnosticSink(tgt, run_id="slow1", limits=lim(max_queue_events=8), clock_ns=FakeClock(),
                                pseudonym_key=b"k", threaded=True)
        try:
            self.assertTrue(tgt.entered.wait(HANG_GUARD_S), "writer should be blocked inside the target")
            results = {}

            def producer():
                for i in range(3000):
                    sink.emit("n", fields={"i": i})
                results["crit"] = [sink.emit("c", critical=True, case_id="c%d" % i) for i in range(5)]
                return True

            finished, _ = run_in_thread(producer)
            self.assertTrue(finished, "emit() blocked on a stalled sink")
            self.assertEqual(results["crit"], [True] * 5)
            st = sink.stats()
            self.assertEqual(st["emitted"], 3005)
            self.assertEqual(st["dropped"]["queue_full"], 2992)
            self.assertEqual(st["dropped"]["evicted_for_critical"], 5)
            self.assertEqual((st["queued"], st["queue_peak_events"]), (8, 8))
            self.assertEqual(st["written"], 0)
        finally:
            tgt.ungate()
        v = sink.close(timeout=HANG_GUARD_S)
        st = sink.stats()
        self.assertTrue(v.complete, v.reasons)
        self.assertEqual((st["written"], st["written_critical"], st["dropped_total"]), (8, 5, 2997))
        self.assertClosed(st)
        audit = d.audit_bytes(bytes(tgt.data))
        self.assertTrue(audit.complete, audit.reasons)
        self.assertEqual(audit.critical_events, 5)
        self.assertTrue(wait_thread("ff-diag-writer-slow1"))

    def test_INJECTED_hung_writer_makes_close_bounded_and_incomplete(self):
        tgt = d.FaultableSink()
        tgt.gate()
        sink = d.DiagnosticSink(tgt, run_id="hung1", limits=lim(max_queue_events=16), clock_ns=FakeClock(),
                                pseudonym_key=b"k", threaded=True)
        try:
            self.assertTrue(tgt.entered.wait(HANG_GUARD_S))
            for i in range(3):
                sink.emit("n", fields={"i": i})
            for i in range(2):
                sink.emit("c", critical=True, case_id="c%d" % i)
            t0 = time.monotonic()
            v = sink.close(timeout=0.3)
            self.assertLess(time.monotonic() - t0, 10, "close() must be bounded")
            self.assertFalse(v.complete)
            self.assertIn("writer_hung", v.reasons)
            self.assertIn("footer_not_written", v.reasons)
            st = sink.stats()
            self.assertEqual((st["dropped"]["lost_at_close"], st["critical_lost"]), (5, 2))
            self.assertTrue(st["writer_hung"])
        finally:
            tgt.ungate()
        self.assertTrue(wait_thread("ff-diag-writer-hung1"), "writer thread must exit once the target returns")
        self.assertNotIn(b'"type":"footer"', bytes(tgt.data), "a hung sink must never be written to concurrently")
        self.assertFalse(d.audit_bytes(bytes(tgt.data)).complete)

    def test_real_unavailable_directory_is_loss_not_a_crash(self):
        with tempfile.TemporaryDirectory(prefix="diag nodir ") as td:
            path = os.path.join(td, "missing subdir", "diag.jsonl")
            sink = d.DiagnosticSink.to_file(path, run_id="nodir", clock_ns=FakeClock(), pseudonym_key=b"k",
                                            threaded=False, limits=lim(retry_interval_s=0.0))
            accepted = [sink.emit("n", fields={"i": i}) for i in range(20)]
            self.assertEqual(sum(accepted), 7, "queue of 8 holds the unwritten header plus 7 events")
            self.assertTrue(sink.emit("case.end", critical=True, case_id="c"))

            sink.pump()
            v = sink.close(timeout=2)
            st = sink.stats()
            self.assertFalse(v.complete)
            self.assertIn("header_not_written", v.reasons)
            self.assertGreater(st["write_errors"], 0)
            self.assertIn("FileNotFoundError", st["last_error"])
            self.assertIsNotNone(sink.open_error)
            self.assertFalse(os.path.exists(path))
            self.assertClosed(st)
            self.assertFalse(d.audit_log(path).complete)

    def test_existing_log_is_never_clobbered_or_appended_to(self):
        with tempfile.TemporaryDirectory(prefix="diag excl ") as td:
            path = os.path.join(td, "diag.jsonl")
            original = b'{"original":"failure evidence"}\n'
            with open(path, "wb") as f:
                f.write(original)
            sink = d.DiagnosticSink.to_file(path, run_id="excl", clock_ns=FakeClock(), pseudonym_key=b"k",
                                            threaded=False, limits=lim(retry_interval_s=0.0))
            sink.emit("case.end", critical=True)
            v = sink.close(timeout=2)
            self.assertFalse(v.complete)
            self.assertIn("FileExistsError", sink.stats()["last_error"])
            with open(path, "rb") as f:
                self.assertEqual(f.read(), original, "a rerun must keep the original evidence")

    def test_real_os_write_refusal_via_rlimit_fsize_in_a_child_process(self):
        probe = (
            "import os,sys,signal,resource,tempfile\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "resource.setrlimit(resource.RLIMIT_FSIZE,(64,64))\n"
            "fd,p=tempfile.mkstemp()\n"
            "try:\n"
            "    n=os.write(fd,b'x'*200)\n"
            "    n+=os.write(fd,b'x'*200)\n"
            "    print('NOT_ENFORCED')\n"
            "except OSError as e:\n"
            "    print('ENFORCED', e.errno)\n"
            "finally:\n"
            "    os.close(fd); os.unlink(p)\n")
        r = subprocess.run([sys.executable, "-B", "-I", "-c", probe], capture_output=True, text=True, timeout=60)
        if "ENFORCED" not in r.stdout or "NOT_ENFORCED" in r.stdout:
            self.skipTest("RLIMIT_FSIZE is not enforced on this host (%r)" % (r.stdout + r.stderr)[:120])
        child = (
            "import sys, json, signal, resource\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import diagnostics as d\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "limit = int(sys.argv[3])\n"
            "resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))\n"
            "t = [0]\n"
            "def clk():\n"
            "    t[0] += 1000\n"
            "    return t[0]\n"
            "lim = d.SinkLimits(max_queue_events=64, max_events_per_sec=None, max_file_bytes=1 << 20,\n"
            "                   critical_reserve_bytes=1 << 16, footer_reserve_bytes=1 << 12,\n"
            "                   failure_threshold=2, critical_max_attempts=2, retry_interval_s=0.0)\n"
            "sink = d.DiagnosticSink.to_file(sys.argv[2], run_id='rl', clock_ns=clk, pseudonym_key=b'k',\n"
            "                                threaded=False, limits=lim)\n"
            "for i in range(80):\n"
            "    sink.emit('n', fields={'i': i, 'pad': 'p' * 100})\n"
            "    sink.pump()\n"
            "sink.emit('case.end', critical=True, case_id='c')\n"
            "sink.pump()\n"
            "v = sink.close(timeout=2)\n"
            "print(json.dumps({'verdict': v.as_dict(), 'stats': sink.stats()}))\n")
        with tempfile.TemporaryDirectory(prefix="diag rlimit ") as td:
            path = os.path.join(td, "diag.jsonl")
            r = subprocess.run([sys.executable, "-B", "-I", "-c", child, HERE, path, "4096"],
                               capture_output=True, text=True, timeout=120, cwd=td)
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            st, verdict = out["stats"], out["verdict"]
            self.assertLessEqual(os.path.getsize(path), 4096)
            self.assertGreater(st["write_errors"], 0, "the OS refused writes; the sink must have seen it")
            self.assertIn("File too large", st["last_error"])
            self.assertFalse(verdict["complete"])
            self.assertGreaterEqual(st["critical_lost"], 1)
            self.assertEqual(sum(st["dropped"].values()), st["dropped_total"])
            self.assertEqual(st["emitted"], st["written"] + st["dropped_total"], "closure must hold under a real OS refusal too")
            audit = d.audit_log(path)
            self.assertFalse(audit.complete)
            self.assertTrue(audit.truncated_tail or "missing_footer" in audit.reasons, audit.reasons)
            block = audit.receipt_log_block()
            self.assertTrue(block["truncated"] or block["critical_lost"])

    @unittest.skipUnless(os.path.exists("/dev/full"), DEV_FULL_SKIP_REASON)
    def test_real_os_dev_full_returns_enospc(self):
        sink = d.DiagnosticSink(d.FileSink("/dev/full", exclusive=False, fsync_on_close=False), run_id="full1",
                                clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False,
                                limits=lim(retry_interval_s=0.0))
        sink.emit("n")
        sink.emit("case.end", critical=True)
        sink.pump()
        v = sink.close(timeout=2)
        self.assertFalse(v.complete)
        self.assertIn("No space left", sink.stats()["last_error"])
        self.assertGreater(sink.stats()["write_errors"], 0)


# --------------------------------------------------------------------------- #
# render-path independence (sink contract, not on-device qualification)
# --------------------------------------------------------------------------- #

def render_loop(emit, periods=2000, stop_at=1500):
    """Deterministic stand-in for a render path with its own *independent* state oracle.

    The result depends only on the loop itself. The sink may be slow, full or
    gone; ``emit`` is the only thing that varies. The digest and ``stopped_at``
    are the oracle: they are computed here, never read back from a log.
    """
    x = 0x2545F4914F6CDD1D
    digest = hashlib.sha256()
    stopped_at = None
    for i in range(periods):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        sample = x & 0xFFFF
        digest.update(sample.to_bytes(2, "big"))
        emit("render.period", counters={"period": i, "sample": sample, "queue_depth": i % 7})
        if i == stop_at:
            stopped_at = i
            emit("priority.stop", critical=True, case_id="stop", counters={"period": i})
    return digest.hexdigest(), periods, stopped_at


class RenderPathIndependenceTests(unittest.TestCase):
    def test_INJECTED_render_result_is_identical_with_healthy_slow_full_and_unavailable_sinks(self):
        baseline = render_loop(lambda *a, **k: None)
        conditions = {}

        # healthy
        sink, tgt, _ = make(limits=lim(max_queue_events=64, drain_batch=64))
        conditions["healthy"] = render_loop(lambda *a, **k: (sink.emit(*a, **k), sink.pump()))
        sink.close()
        # full (injected ENOSPC) - the sink is hammered while every write fails
        tgt_full = d.FaultableSink(capacity_bytes=2500)
        sink_full, _, _ = make(tgt_full, limits=lim(max_queue_events=16, retry_interval_s=0.0))
        conditions["full"] = render_loop(lambda *a, **k: (sink_full.emit(*a, **k), sink_full.pump()))
        v_full = sink_full.close(timeout=2)
        # unavailable (injected EIO)
        tgt_dead = d.FaultableSink()
        tgt_dead.available = False
        sink_dead, _, _ = make(tgt_dead, limits=lim(max_queue_events=16, retry_interval_s=0.0))
        conditions["unavailable"] = render_loop(lambda *a, **k: (sink_dead.emit(*a, **k), sink_dead.pump()))
        v_dead = sink_dead.close(timeout=2)
        # slow: writer stalled for the whole loop, on a separate thread so a blocking emit() would hang it
        tgt_slow = d.FaultableSink()
        tgt_slow.gate()
        sink_slow = d.DiagnosticSink(tgt_slow, run_id="rend1", limits=lim(max_queue_events=16), clock_ns=FakeClock(),
                                     pseudonym_key=b"k", threaded=True)
        try:
            self.assertTrue(tgt_slow.entered.wait(HANG_GUARD_S))
            finished, res = run_in_thread(lambda: render_loop(sink_slow.emit))
            self.assertTrue(finished, "render loop blocked on a stalled sink")
            conditions["slow"] = res
        finally:
            tgt_slow.ungate()
        v_slow = sink_slow.close(timeout=HANG_GUARD_S)

        for name, got in conditions.items():
            self.assertEqual(got, baseline, "render result changed under a %s sink" % name)
        self.assertEqual(baseline[2], 1500)
        # the sink *reports* the damage honestly instead of hiding it
        self.assertFalse(v_dead.complete)
        self.assertFalse(v_full.complete)
        self.assertGreater(sink_dead.stats()["dropped_total"], 0)
        self.assertGreater(sink_full.stats()["dropped_total"], 0)
        # priority stop survived queue saturation on the slow sink because it is critical evidence
        self.assertTrue(v_slow.complete, v_slow.reasons)
        stops = [e for e in events_of(tgt_slow) if e["kind"] == "priority.stop"]
        self.assertEqual(len(stops), 1)

    def test_a_blocking_emit_mutant_fails_the_same_harness(self):
        """Planted defect: emit() writes inline. The harness above must catch it (so it has teeth)."""
        tgt = d.FaultableSink()
        tgt.gate()

        class InlineSink(d.DiagnosticSink):
            def emit(self, kind, **kw):          # defect: synchronous I/O in the caller
                self._target.write(b"x\n")
                return True

        sink = InlineSink(tgt, run_id="mut1", limits=lim(), clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False)
        try:
            finished, _ = run_in_thread(lambda: render_loop(sink.emit, periods=50), timeout=0.5)
            self.assertFalse(finished, "the blocking mutant should have hung the producer")
        finally:
            tgt.ungate()


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #

class RedactionTests(unittest.TestCase):
    def test_sensitive_key_names_are_redacted_but_lookalikes_and_counters_survive(self):
        src = {"token": "t", "Password": "p", "api_key": "k", "apiKey": "k2", "Authorization": "a", "client_secret": "s",
               "household_id": "HH", "serial": "S1", "ssid": "net", "mac": "m", "account": "acct", "email": "e",
               "private_key": "pk", "key": "plain", "session_key": "sk", "tokens": ["a", "b"], "userId": "u1",
               "access_token": {"nested": "x"}}
        out = d.redact_value(src)
        for k in src:
            self.assertEqual(out[k], "[REDACTED]", k)
        keep = {"token_count": 5, "max_tokens": 100, "monkey": "banana", "author": "bob", "keyboard": "us",
                "token": 7, "password": None, "secret": True, "authorized": "yes", "primary_key_count": 3}
        self.assertEqual(d.redact_value(keep), keep)

    def test_value_patterns_cover_tokens_keys_identifiers_and_keep_non_secrets(self):
        jwt = "eyJ" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10
        gh = secret("ghp_", 36, "A")
        aws = "AKIA" + "ABCDEFGHIJKLMNOP"
        ts = secret("tskey-auth-", 12)
        sk = secret("sk-", 24, "z")
        pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIB" + "x" * 40 + "\n-----END RSA PRIVATE KEY-----"
        opaque = "AbC123xyZ" * 5
        cases = [
            ("jwt", jwt, jwt), ("github", "tok " + gh, gh), ("aws", aws, aws), ("tailscale", ts, ts), ("sk", sk, sk),
            ("pem", "before " + pem + " after", "MIIB"), ("opaque", "t=" + opaque, opaque),
            ("bearer", "Authorization: Bearer " + "q" * 20, "q" * 20),
            ("userinfo+query", "https://user:p4ss@example.test/x?token=" + "t" * 12 + "&ok=1", "p4ss"),
            ("kv json", '{"password": "hunter2hunter2"}', "hunter2"), ("kv prefixed", "my_client_secret=abc123456", "abc123456"),
            ("mac", "dev 00:0E:58:AB:CD:EF up", "00:0E:58:AB:CD:EF"), ("ipv4", "peer 10.20.30.40 ok", "10.20.30.40"),
            ("tailnet ipv4", "peer 100.101.102.103", "100.101.102.103"),
            ("ipv6", "peer fd7a:115c:a1e0::1234 ok", "fd7a:115c:a1e0::1234"), ("email", "mail a.b@example.org now", "a.b@example.org"),
        ]
        for name, text, forbidden in cases:
            out = d.redact_text(text)
            self.assertNotIn(forbidden, out, name)
            self.assertIn("[REDACTED", out, name)
        keep = ["loopback 127.0.0.1", "doc range 192.0.2.55", "v6 loopback ::1", "doc v6 2001:db8::1",
                "digest " + "ab" * 32, "version 1.2.3.999", "plain lowercase_long_identifier_without_any_capitals_1234567",
                "time 12:34:56", "ok=1&token_count=5", "std::fmt::Display"]
        for text in keep:
            self.assertEqual(d.redact_text(text), text)

    def test_identifier_fields_are_not_mangled_by_the_opaque_token_heuristic(self):
        cid = "Q00_Diag_Case_Name_With_Digits_1234567890123"
        sink, tgt, _ = make()
        sink.pump()
        sink.emit(cid, case_id=cid, correlation_id=cid)
        sink.close()
        (ev,) = events_of(tgt)
        self.assertEqual((ev["kind"], ev["case"], ev["corr"]), (cid, cid, cid))

    def test_exact_literals_and_home_directory(self):
        lit = "swordfish-literal-9"
        pol = d.RedactionPolicy(literals=(lit, "ab"))      # "ab" is too short to be treated as a secret
        out = d.redact_value({"a": "x %s y" % lit, "n": ["ab", lit]}, pol)
        self.assertNotIn(lit, json.dumps(out))
        self.assertIn("ab", json.dumps(out))
        self.assertEqual(d.RedactionPolicy(literals=(lit,)).public()["literals"], 1)
        self.assertNotIn(lit, json.dumps(d.RedactionPolicy(literals=(lit,)).public()))
        home = os.path.expanduser("~")
        if len(home) > 1:
            self.assertEqual(d.redact_text(home + "/work/f"), "~/work/f")
            self.assertEqual(d.redact_text(home + "/work/f", d.RedactionPolicy(scrub_home=False)), home + "/work/f")

    def test_audio_and_binary_payloads_never_reach_the_log(self):
        out = d.redact_value({"raw": b"\x00\x01" * 50, "ba": bytearray(10), "mv": memoryview(b"abcd"),
                              "pcm": [1, 2, 3] * 10, "samples": 480, "audio_device": "hw:0", "audio": "A" * 100,
                              "long": list(range(100)), "short": [1, 2, 3], "waveform": {"a": [1, 2]}})
        self.assertEqual(out["raw"], {"redacted": "binary", "len": 100})
        self.assertEqual(out["ba"], {"redacted": "binary", "len": 10})
        self.assertEqual(out["mv"], {"redacted": "binary", "len": 4})
        self.assertEqual(out["pcm"], {"redacted": "audio_payload", "len": 30})
        self.assertEqual(out["samples"], 480)                         # a count, not a payload
        self.assertEqual(out["audio_device"], "hw:0")
        self.assertEqual(out["audio"], {"redacted": "audio_payload", "len": 100})
        self.assertEqual(out["long"], [{"redacted": "numeric_sequence", "len": 100}])
        self.assertEqual(out["short"], [1, 2, 3])
        self.assertEqual(out["waveform"], {"redacted": "audio_payload", "len": 1})

    def test_secret_straddling_a_truncation_boundary_cannot_leak_a_prefix(self):
        pol = d.RedactionPolicy(max_str_len=64, raw_str_cap=64)
        s = "x " * 25 + "Bearer " + "S" * 30
        self.assertNotIn("SSSS", d.redact_text(s, pol))                 # cut before matching, at a word boundary
        pol2 = d.RedactionPolicy(max_str_len=16, raw_str_cap=4096)
        out = d.redact_text("Bearer " + "S" * 30, pol2)                 # redacted first, truncated after
        self.assertNotIn("SSSS", out)
        self.assertTrue(out.startswith("Bearer [REDACTED"))

    def test_structures_are_bounded_depth_items_nodes_and_cycles(self):
        cyc = {}
        cyc["self"] = cyc
        out = d.redact_value(cyc)
        self.assertIn("[DEPTH_LIMIT]", json.dumps(out))
        deep = cur = {}
        for _ in range(100):
            cur["n"] = {}
            cur = cur["n"]
        self.assertIn("[DEPTH_LIMIT]", json.dumps(d.redact_value(deep)))
        big_dict = d.redact_value({str(i): i for i in range(10000)})
        self.assertEqual(len(big_dict), 32 + 1)
        self.assertEqual(big_dict["_clipped_items"], 10000 - 32)
        big_list = d.redact_value(["s%d" % i for i in range(10000)])
        self.assertEqual(len(big_list), 32 + 1)
        self.assertEqual(big_list[-1], "[+9968 more]")
        wide = [[[[["leaf"] * 32] * 32] * 32] * 32] * 32                 # 32**5 leaves if unbounded
        t0 = time.monotonic()
        out = json.dumps(d.redact_value(wide))
        self.assertLess(len(out), 20000)
        self.assertIn("[NODE_LIMIT]", out)
        self.assertLess(time.monotonic() - t0, HANG_GUARD_S)

    def test_non_json_values_become_safe_json(self):
        class Weird:
            def __repr__(self):
                raise RuntimeError("no repr for you")

        out = d.redact_value({"nan": float("nan"), "inf": float("inf"), "ninf": float("-inf"), "set": {3, 1, 2},
                              "fs": frozenset({"b", "a"}), "huge": 10 ** 100, b"bytes-key": 1, 7: "int-key",
                              "weird": Weird(), "exc": ValueError("bad value token=" + "z" * 12)})
        text = json.dumps(out, allow_nan=False)
        self.assertEqual((out["nan"], out["inf"], out["ninf"]), ("NaN", "Infinity", "-Infinity"))
        self.assertEqual((out["set"], out["fs"]), ([1, 2, 3], ["a", "b"]))
        self.assertEqual(out["huge"], "<int:333bits>")
        self.assertIn("unprintable", out["weird"])
        self.assertEqual(out["exc"]["type"], "ValueError")
        self.assertNotIn("z" * 12, text)

    def test_no_secret_reaches_the_file_end_to_end_and_redactions_are_counted(self):
        gh, ts = secret("ghp_", 36, "A"), secret("tskey-auth-", 12)
        err = ValueError("inner failed with password=hunter2hunter2")
        try:
            try:
                raise err
            except ValueError as inner:
                raise RuntimeError("outer saw %s" % gh) from inner
        except RuntimeError as outer:
            chain = d.exception_chain(outer)
        sink, tgt, _ = make(redaction=d.RedactionPolicy(literals=("household-77-literal",)),
                            header_extra={"profile": "ci", "api_key": "hdrsecretvalue"})
        sink.pump()
        sink.emit("note" , case_id="c1", member="room", group="household-77-literal",
                  counters={"tskey": 1}, fault={"auth": ts}, cause=chain,
                  fields={"msg": "see https://u:pw@host.test/?access_token=abcdefgh1234 and 10.9.8.7",
                          "serial": "SN-000", "mac": "00:0E:58:AB:CD:EF", "pcm": [1] * 40, "bin": b"\x01" * 9,
                          "note": "fine", "digest": "cd" * 32})
        sink.close()
        text = tgt.text()
        for leaked in (gh, ts, "hunter2", "pw@", "abcdefgh1234", "10.9.8.7", "SN-000", "00:0E:58", "household-77-literal",
                       "hdrsecretvalue", "room"):
            self.assertNotIn(leaked, text, leaked)
        for kept in ("fine", "cd" * 32, "RuntimeError", "ValueError", '"profile":"ci"'):
            self.assertIn(kept, text, kept)
        reds = sink.stats()["redactions"]
        for cls in ("token", "secret", "ip", "audio", "site"):
            self.assertGreater(reds.get(cls, 0), 0, cls)
        self.assertEqual([c["type"] for c in chain], ["RuntimeError", "ValueError"])

    def test_INJECTED_target_error_text_is_redacted_in_stats(self):
        tgt = d.FaultableSink()
        tgt.fail_next(1, OSError(5, "device said token=" + "z" * 12 + " from 10.1.2.3"))
        sink, _, _ = make(tgt)
        sink.pump()
        err = sink.stats()["last_error"]
        self.assertNotIn("z" * 12, err)
        self.assertNotIn("10.1.2.3", err)
        sink.close()


# --------------------------------------------------------------------------- #
# independent audit of the written file
# --------------------------------------------------------------------------- #

def good_log(n_events=6, critical=2):
    sink, tgt, _ = make(limits=lim(max_queue_events=64, drain_batch=64))
    sink.pump()
    for i in range(n_events):
        sink.emit("n", fields={"i": i}, case_id="c")
    for i in range(critical):
        sink.emit("case.end", critical=True, case_id="c%d" % i)
    sink.close()
    return bytes(tgt.data)


class AuditTests(unittest.TestCase):
    def test_every_strict_prefix_of_a_good_log_is_incomplete_and_receipt_blocked(self):
        data = good_log()
        self.assertTrue(d.audit_bytes(data).complete)
        for k in range(len(data)):
            audit = d.audit_bytes(data[:k])
            self.assertFalse(audit.complete, "prefix of %d bytes must not audit complete" % k)
            block = audit.receipt_log_block()
            self.assertTrue(block["truncated"] or block["critical_lost"], k)
        full = d.audit_bytes(data).receipt_log_block()
        self.assertEqual((full["truncated"], full["critical_lost"]), (False, False))

    def test_tampering_is_detected_from_the_file_alone(self):
        data = good_log()
        lines = data.split(b"\n")[:-1]
        ev_idx = [i for i, l in enumerate(lines) if b'"type":"event"' in l]
        footer_idx = len(lines) - 1

        def audit(ls):
            return d.audit_bytes(b"\n".join(ls) + b"\n")

        self.assertTrue(audit(lines).complete)
        dropped_mid = lines[:ev_idx[2]] + lines[ev_idx[2] + 1:]
        r = audit(dropped_mid).reasons
        self.assertTrue({"event_count_mismatch", "loss_accounting_mismatch"} <= set(r), r)
        self.assertIn("seq_not_monotonic", audit(lines[:ev_idx[2] + 1] + lines[ev_idx[2]:]).reasons)        # duplicated record
        swapped = list(lines)
        swapped[ev_idx[1]], swapped[ev_idx[2]] = swapped[ev_idx[2]], swapped[ev_idx[1]]
        self.assertIn("seq_not_monotonic", audit(swapped).reasons)
        self.assertIn("missing_footer", audit(lines[:footer_idx]).reasons)
        self.assertIn("missing_header", audit(lines[1:]).reasons)
        self.assertIn("duplicate_footer", audit(lines + [lines[footer_idx]]).reasons)
        self.assertIn("records_after_footer", audit(lines + [lines[ev_idx[0]]]).reasons)
        self.assertIn("duplicate_header", audit([lines[0]] + lines).reasons)
        foreign = json.loads(lines[ev_idx[0]])
        foreign["run"] = "other-run"
        forged = list(lines)
        forged[ev_idx[0]] = json.dumps(foreign, separators=(",", ":")).encode()
        self.assertIn("run_mismatch", audit(forged).reasons)
        # footer edited to hide a drop
        footer = json.loads(lines[footer_idx])
        footer["stats"]["dropped_total"] = 5
        edited = list(lines)
        edited[footer_idx] = json.dumps(footer, separators=(",", ":")).encode()
        self.assertIn("loss_accounting_mismatch", audit(edited).reasons)

    def test_footer_cannot_hide_a_critical_loss_that_an_inband_marker_recorded(self):
        sink, tgt, _ = make(limits=lim(max_queue_events=3))
        sink.pump()
        for _ in range(3):
            sink.emit("c", critical=True, case_id="A")
        self.assertFalse(sink.emit("c", critical=True, case_id="A"))
        sink.close()
        data = bytes(tgt.data)
        honest = d.audit_bytes(data)
        self.assertIn("critical_evidence_lost:1", honest.reasons)
        lines = data.split(b"\n")[:-1]
        footer = json.loads(lines[-1])
        footer["stats"]["critical_lost"] = 0
        footer["evidence_complete"] = True
        forged = lines[:-1] + [json.dumps(footer, separators=(",", ":")).encode()]
        audit = d.audit_bytes(b"\n".join(forged) + b"\n")
        self.assertFalse(audit.complete)
        self.assertIn("critical_loss_hidden", audit.reasons)

    def test_unreadable_empty_garbage_and_overlong_inputs_are_incomplete_not_exceptions(self):
        with tempfile.TemporaryDirectory(prefix="diag audit ") as td:
            self.assertEqual(d.audit_log(os.path.join(td, "nope")).reasons, ["log_unreadable:ENOENT"])
            self.assertTrue(d.audit_log(td).reasons[0].startswith("log_unreadable:"))
            empty = os.path.join(td, "empty")
            open(empty, "wb").close()
            self.assertIn("empty_log", d.audit_log(empty).reasons)
        self.assertFalse(d.audit_bytes(b"\x00\xff garbage\n{not json}\n[1,2]\n").complete)
        long_line = b"x" * 5000
        audit = d.audit_bytes(good_log() + long_line, max_line_bytes=4096)
        self.assertFalse(audit.complete)
        self.assertTrue(audit.truncated_tail)

    def test_two_runs_concatenated_are_not_one_complete_log(self):
        self.assertFalse(d.audit_bytes(good_log() + good_log()).complete)

    def test_summary_record_and_human_summary(self):
        with tempfile.TemporaryDirectory(prefix="diag summary ") as td:
            path = os.path.join(td, "diag.jsonl")
            sink = d.DiagnosticSink.to_file(path, run_id="sum1", clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False)
            sink.emit("case.end", critical=True, case_id="c")
            sink.close()
            rec = sink.summary_record()
            with open(path, "rb") as f:
                raw = f.read()
            self.assertEqual(rec["schema"], d.SUMMARY_SCHEMA)
            self.assertTrue(rec["evidence_complete"])
            self.assertEqual(rec["log"], {"name": "diag.jsonl", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            audit = d.audit_log(path)
            self.assertEqual(audit.sha256, rec["log"]["sha256"])
            self.assertIn("COMPLETE", d.format_summary(audit))
            self.assertNotIn("INCOMPLETE", d.format_summary(audit))
            self.assertIn("COMPLETE", d.format_summary(sink.stats()))
            self.assertNotIn("INCOMPLETE", d.format_summary(sink.stats()))
        bad = d.audit_bytes(good_log()[:-30])
        self.assertIn("INCOMPLETE", d.format_summary(bad))
        sink, _, _ = make()
        self.assertIn("INCOMPLETE", d.format_summary(sink.stats()))

    def test_audit_cli_exit_codes_from_a_different_cwd(self):
        with tempfile.TemporaryDirectory(prefix="diag cli ") as td:
            good, bad = os.path.join(td, "good log.jsonl"), os.path.join(td, "bad log.jsonl")
            data = good_log()
            with open(good, "wb") as f:
                f.write(data)
            with open(bad, "wb") as f:
                f.write(data[:-20])
            script = os.path.join(HERE, "diagnostics.py")

            def run(*args):
                return subprocess.run([sys.executable, "-B", "-I", script, *args], cwd=td, capture_output=True, text=True, timeout=60)

            r = run("audit", good)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(json.loads(r.stdout)["complete"])
            r = run("audit", bad)
            self.assertEqual(r.returncode, 1)
            self.assertFalse(json.loads(r.stdout)["complete"])
            self.assertIn("INCOMPLETE", r.stderr)
            self.assertEqual(run().returncode, 2)
            self.assertEqual(run("audit", os.path.join(td, "missing")).returncode, 1)


# --------------------------------------------------------------------------- #
# isolation, cwd, concurrency, cleanup
# --------------------------------------------------------------------------- #

class IsolationTests(ClosureMixin, unittest.TestCase):
    def test_relative_path_from_a_non_root_cwd_with_spaces_survives_a_later_chdir(self):
        with tempfile.TemporaryDirectory(prefix="diag cwd ") as td:
            work = os.path.join(td, "dir with spaces")
            other = os.path.join(td, "elsewhere")
            os.mkdir(work)
            os.mkdir(other)
            old = os.getcwd()
            try:
                os.chdir(work)
                sink = d.DiagnosticSink.to_file("diag.jsonl", run_id="cwd1", clock_ns=FakeClock(),
                                                pseudonym_key=b"k", threaded=False)
                self.assertTrue(os.path.isabs(sink.path))
                sink.emit("a", critical=True)
                sink.pump()
                os.chdir(other)                                  # a test that chdirs must not redirect the log
                sink.emit("b", critical=True)
                v = sink.close()
            finally:
                os.chdir(old)
            self.assertTrue(v.complete)
            self.assertEqual(os.listdir(other), [])
            self.assertTrue(d.audit_log(os.path.join(work, "diag.jsonl")).complete)

    def test_parallel_runs_are_isolated_by_run_id_and_file(self):
        with tempfile.TemporaryDirectory(prefix="diag parallel ") as td:
            n = 6
            paths = [os.path.join(td, "run %d" % i, "diag.jsonl") for i in range(n)]
            for p in paths:
                os.mkdir(os.path.dirname(p))
            barrier = threading.Barrier(n)
            verdicts = [None] * n

            def worker(i):
                sink = d.DiagnosticSink.to_file(paths[i], run_id="par-%d" % i, pseudonym_key=b"k")
                barrier.wait(HANG_GUARD_S)
                for j in range(300):
                    sink.emit("n", case_id="c%d" % i, fields={"j": j, "who": i})
                sink.emit("case.end", critical=True, case_id="c%d" % i)
                verdicts[i] = sink.close(timeout=HANG_GUARD_S)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(HANG_GUARD_S * 2)
                self.assertFalse(t.is_alive())
            for i, p in enumerate(paths):
                self.assertTrue(verdicts[i].complete, verdicts[i].reasons)
                audit = d.audit_log(p)
                self.assertTrue(audit.complete, audit.reasons)
                self.assertEqual(audit.run, "par-%d" % i)
                with open(p, "r", encoding="ascii") as f:
                    for line in f:
                        rec = json.loads(line)
                        if rec["type"] == "event":
                            self.assertEqual(rec["run"], "par-%d" % i)
                            self.assertEqual(rec["case"], "c%d" % i)
            for i in range(n):
                self.assertTrue(wait_thread("ff-diag-writer-par-%d" % i))

    def test_concurrent_producers_on_one_sink_keep_the_closure_identity(self):
        tgt = d.FaultableSink()
        sink = d.DiagnosticSink(tgt, run_id="conc1", clock_ns=time.monotonic_ns, pseudonym_key=b"k",
                                limits=lim(max_queue_events=16, drain_batch=8, max_events_per_sec=None))
        barrier = threading.Barrier(9)

        def producer(i):
            barrier.wait(HANG_GUARD_S)
            for j in range(400):
                sink.emit("n", fields={"p": i, "j": j})

        threads = [threading.Thread(target=producer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        barrier.wait(HANG_GUARD_S)
        for t in threads:
            t.join(HANG_GUARD_S)
            self.assertFalse(t.is_alive())
        for i in range(3):
            self.assertTrue(sink.emit("case.end", critical=True, case_id="c%d" % i), "critical evidence must evict, not drop")
        v = sink.close(timeout=HANG_GUARD_S)
        st = sink.stats()
        self.assertEqual(st["emitted"], 8 * 400 + 3)
        self.assertClosed(st)
        audit = d.audit_bytes(bytes(tgt.data))
        integrity = {"event_count_mismatch", "loss_accounting_mismatch", "seq_not_monotonic", "mono_ns_regressed", "last_seq_mismatch"}
        self.assertFalse(integrity & set(audit.reasons), audit.reasons)
        self.assertEqual(v.complete, audit.complete)
        seqs = [e["seq"] for e in events_of(tgt)]
        self.assertEqual(seqs, sorted(set(seqs)))

    def test_cleanup_context_manager_closes_fd_thread_and_writes_footer_on_exception(self):
        with tempfile.TemporaryDirectory(prefix="diag cleanup ") as td:
            path = os.path.join(td, "diag.jsonl")
            holder = {}
            with self.assertRaises(KeyError):
                with d.DiagnosticSink.to_file(path, run_id="clean1", pseudonym_key=b"k") as sink:
                    holder["sink"] = sink
                    sink.emit("case.begin", critical=True, case_id="c")
                    raise KeyError("body failed")
            self.assertIsNone(holder["sink"]._target._fd, "fd must be closed")
            self.assertTrue(wait_thread("ff-diag-writer-clean1"))
            audit = d.audit_log(path)
            self.assertTrue(audit.complete, audit.reasons)
            self.assertEqual(audit.critical_events, 1)

    def test_importing_the_module_pulls_in_no_network_or_native_modules(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import diagnostics\n"
                "bad = [m for m in ('socket','ssl','http','urllib','ctypes','subprocess','asyncio','multiprocessing') if m in sys.modules]\n"
                "print(','.join(bad))\n")
        r = subprocess.run([sys.executable, "-B", "-I", "-c", code, HERE], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "")


# --------------------------------------------------------------------------- #
# planted defects the independent audit must catch (also runner canaries)
# --------------------------------------------------------------------------- #

def canary_silent_critical_loss():
    """Defect: the producer fails to count a lost critical event. The audit must still flag it."""
    class Silent(d.DiagnosticSink):
        def _drop_locked(self, reason, critical, case_key, seq):
            if critical:
                return False                # defect: loss neither counted nor marked
            return super()._drop_locked(reason, critical, case_key, seq)

    tgt = d.FaultableSink()
    sink = Silent(tgt, run_id="can1", limits=lim(max_queue_events=3), clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False)
    sink.pump()
    for _ in range(4):
        sink.emit("c", critical=True, case_id="A")
    verdict = sink.close()
    audit = d.audit_bytes(bytes(tgt.data))
    return {"producer_claims_complete": verdict.complete, "audit_complete": audit.complete,
            "audit_reasons": audit.reasons}, audit.complete is False and "loss_accounting_mismatch" in audit.reasons


def canary_footer_lies_about_loss():
    """Defect: the footer reports no loss although events were dropped."""
    class Liar(d.DiagnosticSink):
        def _footer_locked(self):
            f = super()._footer_locked()
            f["evidence_complete"], f["reasons"] = True, []
            f["stats"].update(dropped_total=0, dropped={}, critical_lost=0)
            return f

    tgt = d.FaultableSink()
    sink = Liar(tgt, run_id="can2", limits=lim(max_queue_events=3), clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False)
    sink.pump()
    for _ in range(5):
        sink.emit("n")
    sink.pump()
    for _ in range(4):
        sink.emit("c", critical=True)
    sink.close()
    audit = d.audit_bytes(bytes(tgt.data))
    return {"audit_complete": audit.complete, "audit_reasons": audit.reasons}, \
        audit.complete is False and {"loss_accounting_mismatch", "critical_loss_hidden"} & set(audit.reasons) != set()


def canary_naive_absence_of_error_passes_a_truncated_log():
    """Defect: a checker that passes whenever no 'error' text appears. The audit must refuse the truncated log."""
    data = good_log()[:-300]
    naive_pass = b"error" not in data.lower()
    audit = d.audit_bytes(data)
    return {"naive_checker_passes": naive_pass, "audit_complete": audit.complete, "audit_reasons": audit.reasons}, \
        naive_pass and audit.complete is False


def canary_blocking_emit():
    """Defect: emit() performs inline I/O. The nonblocking harness must see the producer hang."""
    tgt = d.FaultableSink()
    tgt.gate()

    class Inline(d.DiagnosticSink):
        def emit(self, kind, **kw):
            self._target.write(b"x\n")
            return True

    sink = Inline(tgt, run_id="can4", limits=lim(), clock_ns=FakeClock(), pseudonym_key=b"k", threaded=False)
    try:
        finished, _ = run_in_thread(lambda: render_loop(sink.emit, periods=20), timeout=0.5)
    finally:
        tgt.ungate()
    return {"producer_finished_while_sink_stalled": finished}, finished is False


# name -> (oracle id, violation kind that oracle must report, scenario). The oracle and violation are declared HERE,
# in code, because they are the floor's source of truth: the manifest must agree with them, never the reverse.
CANARIES = {
    "silent_critical_loss": ("diag.audit.loss_accounting", "loss_accounting_mismatch", canary_silent_critical_loss),
    "footer_lies_about_loss": ("diag.audit.loss_accounting", "loss_accounting_mismatch", canary_footer_lies_about_loss),
    "naive_absence_of_error": ("diag.audit.truncation", "missing_footer", canary_naive_absence_of_error_passes_a_truncated_log),
    "blocking_emit": ("diag.nonblocking.emit", "producer_blocked_on_sink", canary_blocking_emit),
}


class CanaryTests(unittest.TestCase):
    def test_every_planted_defect_is_detected_by_its_oracle(self):
        for name, (oracle, violation, fn) in CANARIES.items():
            observed, detected = fn()
            self.assertTrue(detected, "%s (%s) was NOT detected: %r" % (name, oracle, observed))
            self.assertIn(violation, _canary_kinds(name, observed),
                          "%s: the declared violation %r is not among what the oracle reported" % (name, violation))

    def test_an_oracle_blind_to_the_defect_would_be_caught_by_the_positive_twin(self):
        # The same audit on an undamaged log must say complete, otherwise "detected" above proves nothing.
        self.assertTrue(d.audit_bytes(good_log()).complete)


# --------------------------------------------------------------------------- #
# case registry, code-derived floor, and the case-result adapter
# --------------------------------------------------------------------------- #

CASES = {
    "q00.diag.envelope": [EnvelopeTests],
    "q00.diag.bounds_and_loss": [BoundsAndLossTests],
    "q00.diag.critical_evidence": [CriticalEvidenceTests],
    "q00.diag.sink_faults": [SinkFaultTests],
    "q00.diag.render_independence": [RenderPathIndependenceTests],
    "q00.diag.redaction": [RedactionTests],
    "q00.diag.audit": [AuditTests],
    "q00.diag.isolation": [IsolationTests],
    "q00.diag.canaries": [CanaryTests],
    "q00.diag.registry": [],      # filled below: FloorTests + CaseAdapterTests are defined after the helpers they use
}
CANARY_ID_PREFIX = "q00.diag.canary."
PROOF_CLASS = "host-simulation"   # in-process models; nothing here touches a guest, device or provider


def floor_entries():
    """The independent floor for this suite: ``{case_id: {proof_class, canary[, oracle, violation]}}``.

    Same shape as ``scripts/test/q00/floor.py``'s ``required`` map. It is derived from ``CASES`` and ``CANARIES``
    in THIS FILE'S CODE and reads no manifest, receipt or run directory, so a case dropped from both the
    manifest and its ``required_cases`` is still visible to whoever merges this into the floor.
    """
    out = {cid: {"proof_class": PROOF_CLASS, "canary": False} for cid in CASES}
    for name, (oracle, violation, _fn) in CANARIES.items():
        out[CANARY_ID_PREFIX + name] = {"proof_class": PROOF_CLASS, "canary": True, "oracle": oracle,
                                        "violation": violation}
    return out


def _argv_names(argv, flag, value):
    return any(a == flag and i + 1 < len(argv) and argv[i + 1] == value for i, a in enumerate(argv))


def manifest_floor_problems(doc, floor):
    """Every way a loaded manifest disagrees with the code-derived floor (an empty list means it agrees)."""
    problems = []
    raw = doc.get("cases", []) if isinstance(doc, dict) else []
    cases = {c.get("id"): c for c in raw if isinstance(c, dict)}
    req = doc.get("required_cases", []) if isinstance(doc, dict) else []
    required = set(req) if isinstance(req, list) else set()
    for cid, want in sorted(floor.items()):
        c = cases.get(cid)
        if c is None:
            problems.append("%s: missing from the manifest" % cid)
            continue
        if cid not in required:
            problems.append("%s: not in required_cases" % cid)
        if c.get("mandatory", True) is not True:
            problems.append("%s: not mandatory" % cid)
        if c.get("blocked"):
            problems.append("%s: blocked in the manifest" % cid)
        if c.get("evidence_class", "host-simulation") != want["proof_class"]:
            problems.append("%s: evidence_class %r != %r" % (cid, c.get("evidence_class"), want["proof_class"]))
        expect = c.get("expect") or {"kind": "pass"}
        argv = c.get("argv") if isinstance(c.get("argv"), list) else []
        if want["canary"]:
            if expect.get("kind") != "fail":
                problems.append("%s: not a canary (expect.kind != fail)" % cid)
            for key in ("oracle", "violation"):
                if expect.get(key) != want[key]:
                    problems.append("%s: expect.%s %r != %r" % (cid, key, expect.get(key), want[key]))
            if not _argv_names(argv, "--canary", cid[len(CANARY_ID_PREFIX):]):
                problems.append("%s: argv does not run --canary %s" % (cid, cid[len(CANARY_ID_PREFIX):]))
        else:
            if expect.get("kind", "pass") != "pass":
                problems.append("%s: a positive case is declared as a canary" % cid)
            if not _argv_names(argv, "--case", cid):
                problems.append("%s: argv does not run --case %s" % (cid, cid))
    for cid in sorted(c for c in cases if isinstance(c, str) and c.startswith("q00.diag.") and c not in floor):
        problems.append("%s: manifest case has no code-derived floor entry" % cid)
    for cid in sorted(r for r in required if isinstance(r, str) and r.startswith("q00.diag.") and r not in floor):
        problems.append("%s: required_cases names a case this file does not define" % cid)
    return problems


def manifest_skip_problems(doc):
    """Problems with the ``--allow-skip`` declarations in a manifest (empty = exactly the one permitted declaration)."""
    problems = []
    for c in doc.get("cases", []):
        argv = c.get("argv") if isinstance(c.get("argv"), list) else []
        regexes = [argv[i + 1] for i, a in enumerate(argv) if a == "--allow-skip" and i + 1 < len(argv)]
        for rx in regexes:
            try:
                compiled = re.compile(rx)
            except re.error:
                problems.append("%s: --allow-skip %r is not a valid regex" % (c.get("id"), rx))
                continue
            if not compiled.search(DEV_FULL_SKIP_REASON):
                problems.append("%s: --allow-skip %r matches no known host limitation" % (c.get("id"), rx))
            for forbidden in NEVER_DECLARABLE_SKIPS + ("unrelated: the network is down", "RLIMIT_FSIZE"):
                if compiled.search(forbidden):
                    problems.append("%s: --allow-skip %r is too broad: it also excuses %r" % (c.get("id"), rx, forbidden))
        has = any(re.search(rx, DEV_FULL_SKIP_REASON) for rx in regexes if _valid_regex(rx))
        if c.get("id") == "q00.diag.sink_faults" and not has:
            problems.append("q00.diag.sink_faults: does not declare the /dev/full host limitation")
        if c.get("id") != "q00.diag.sink_faults" and regexes:
            problems.append("%s: only q00.diag.sink_faults may declare a skip" % c.get("id"))
    return problems


def _valid_regex(rx):
    try:
        re.compile(rx)
        return True
    except re.error:
        return False


def _write_result(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True)
    os.replace(tmp, path)


def _run_classes(classes, stream):
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in classes)
    return unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)


# Same meaning as scripts/test/q00/unittest_case.py: 0 pass, 1 fail, 2 incomplete (never a pass).
EXIT_CODES = {"pass": 0, "fail": 1, "incomplete": 2}


def _report(case_id, result, oracle, allow=()):
    """Build the ``ffw.case-result.v1`` document for a unittest run (contract v1.1).

    * ``fail``       any failure/error (typed ``test_failure`` / ``test_error``).
    * ``incomplete`` nothing executed, or a skip the manifest did not declare with ``--allow-skip``. A skip is a
                     check that did not happen, so an undeclared one is never a pass and never a manufactured failure.
    * ``pass``       >= 1 check executed, no failure, and every skip declared.
    Declared skips stay visible in ``counters.skipped_allowed``.
    """
    skips = list(result.skipped)
    undeclared = [(t.id(), r) for t, r in skips if not any(rx.search(r) for rx in allow)]
    checks = max(result.testsRun - len(skips), 0)
    bad = list(result.failures) + list(result.errors)
    env = os.environ
    kinds = {}
    if result.failures:
        kinds["test_failure"] = len(result.failures)
    if result.errors:
        kinds["test_error"] = len(result.errors)
    doc = {"schema": "ffw.case-result.v1", "run_id": env.get("FFW_RUN_ID"), "case_id": env.get("FFW_CASE_ID", case_id),
           "nonce": env.get("FFW_RESULT_NONCE"), "oracle": oracle, "oracle_kind": "property", "independent": True,
           "finalized": True, "checks": checks, "incomplete_reasons": [], "violation_kinds": kinds,
           "counters": {"tests_run": result.testsRun, "tests_skipped": len(skips),
                        "skipped_allowed": len(skips) - len(undeclared), "skipped_unexpected": len(undeclared),
                        "failures": len(result.failures), "errors": len(result.errors)}}
    if bad:
        test, tb = bad[0]
        doc.update(verdict="fail", mismatches=sum(kinds.values()), expected={"failures": 0, "errors": 0},
                   observed={"failures": len(result.failures), "errors": len(result.errors)},
                   first_causal_event=("%s: %s" % (test.id(), tb.strip().splitlines()[-1]))[:400])
    elif checks == 0 or undeclared:
        reasons = ["no_checks_executed"] if checks == 0 else []
        reasons += [("unexpected_skip:%s" % tid)[:200] for tid, _r in undeclared[:15]]
        doc.update(verdict="incomplete", mismatches=0, incomplete_reasons=reasons[:16],
                   expected={"unexpected_skips": 0, "checks": ">=1"},
                   observed={"unexpected_skips": len(undeclared), "checks": checks},
                   first_causal_event=(reasons[0] if reasons else "incomplete")[:300])
    else:
        doc.update(verdict="pass", mismatches=0, expected={"failures": 0, "errors": 0},
                   observed={"failures": 0, "errors": 0},
                   first_causal_event="no mismatch in %d checks; %d declared skip(s)" % (checks, len(skips)))
    return doc


def _canary_kinds(name, observed):
    """Typed violation kinds the oracle observed for a planted defect (name -> count)."""
    if name == "blocking_emit":
        return {"producer_blocked_on_sink": 1}
    return {r.split(":", 1)[0]: 1 for r in observed.get("audit_reasons", [])}


def check_v11(doc):
    """Standing guard for the runner's result contract (a mirror of its invariants, not an import of them)."""
    errs = []
    if doc.get("schema") != "ffw.case-result.v1":
        errs.append("schema")
    if doc.get("verdict") not in ("pass", "fail", "incomplete"):
        errs.append("verdict")
    kinds, mism = doc.get("violation_kinds"), doc.get("mismatches")
    if not (isinstance(kinds, dict) and all(isinstance(k, str) and k and isinstance(v, int) and not isinstance(v, bool)
                                            and v >= 1 for k, v in kinds.items())):
        errs.append("violation_kinds")
    elif not isinstance(mism, int) or sum(kinds.values()) != mism:
        errs.append("mismatches != sum(violation_kinds)")
    for key in ("finalized", "independent"):
        if not isinstance(doc.get(key), bool):
            errs.append(key)
    reasons = doc.get("incomplete_reasons")
    if not (isinstance(reasons, list) and len(reasons) <= 16 and all(isinstance(x, str) and x for x in reasons)):
        errs.append("incomplete_reasons")
    if not (isinstance(doc.get("counters"), dict) and all(isinstance(v, int) and not isinstance(v, bool)
                                                         for v in doc["counters"].values())):
        errs.append("counters")
    v = doc.get("verdict")
    if v == "pass" and (mism != 0 or kinds):
        errs.append("pass with mismatches")
    if v == "pass" and (reasons or doc.get("finalized") is False):
        errs.append("pass while unfinalized or with incomplete reasons")
    if v == "fail" and (not isinstance(mism, int) or mism < 1 or not kinds):
        errs.append("fail without a typed violation")
    if v == "fail" and doc.get("expected") == doc.get("observed"):
        errs.append("fail with expected == observed")
    if v == "incomplete" and (mism != 0 or not (reasons or doc.get("finalized") is False)):
        errs.append("incomplete must carry reasons and no mismatches")
    if isinstance(doc.get("checks"), bool) or not isinstance(doc.get("checks"), int) or doc["checks"] < 0:
        errs.append("checks")
    return errs


# --------------------------------------------------------------------------- #
# tests of the registry floor and of the case-result adapter
# --------------------------------------------------------------------------- #

MANIFEST_PATH = os.path.join(HERE, "diagnostics.suite.json")


def load_manifest():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class FloorTests(unittest.TestCase):
    def test_the_real_manifest_equals_the_code_derived_floor(self):
        floor = floor_entries()
        self.assertEqual(manifest_floor_problems(load_manifest(), floor), [])
        self.assertEqual(len(floor), len(CASES) + len(CANARIES))
        self.assertEqual(sum(1 for v in floor.values() if v["canary"]), len(CANARIES))
        for cid, v in floor.items():
            self.assertEqual(set(v), {"proof_class", "canary", "oracle", "violation"} if v["canary"] else {"proof_class", "canary"}, cid)
            self.assertEqual(v["proof_class"], "host-simulation")

    def test_the_floor_is_derived_from_code_and_reads_no_file(self):
        import unittest.mock as mock
        with mock.patch("builtins.open", side_effect=AssertionError("floor_entries() must not read any file")):
            self.assertTrue(floor_entries())

    def test_every_planted_disagreement_between_manifest_and_floor_is_reported(self):
        base = load_manifest()
        self.assertEqual(manifest_floor_problems(base, floor_entries()), [], "control must be clean before any mutation")
        canary_id, positive_id = CANARY_ID_PREFIX + "blocking_emit", "q00.diag.audit"

        def case(doc, cid):
            return next(c for c in doc["cases"] if c["id"] == cid)

        def drop_from_both(doc):
            doc["cases"] = [c for c in doc["cases"] if c["id"] != positive_id]
            doc["required_cases"].remove(positive_id)

        def drop_required_only(doc):
            doc["required_cases"].remove(positive_id)

        def alter_violation(doc):
            case(doc, canary_id)["expect"]["violation"] = "something_else"

        def alter_oracle(doc):
            case(doc, canary_id)["expect"]["oracle"] = "diag.other"

        def canary_to_positive(doc):
            del case(doc, canary_id)["expect"]

        def positive_to_canary(doc):
            case(doc, positive_id)["expect"] = {"kind": "fail", "oracle": "x", "violation": "y", "exit_codes": [1]}

        def not_mandatory(doc):
            case(doc, positive_id)["mandatory"] = False

        def blocked(doc):
            case(doc, positive_id)["blocked"] = "pretend this needs hardware"

        def wrong_class(doc):
            case(doc, positive_id)["evidence_class"] = "physical"

        def extra_mandatory(doc):
            doc["cases"].append(dict(copy.deepcopy(case(doc, positive_id)), id="q00.diag.unregistered"))

        def phantom_required(doc):
            doc["required_cases"].append("q00.diag.phantom")

        def swapped_positive_argv(doc):
            case(doc, positive_id)["argv"] = [a.replace("q00.diag.audit", "q00.diag.envelope") for a in case(doc, positive_id)["argv"]]

        def swapped_argv(doc):
            case(doc, canary_id)["argv"] = [a.replace("blocking_emit", "silent_critical_loss") for a in case(doc, canary_id)["argv"]]

        planted = [
            (drop_from_both, positive_id, "missing from the manifest"),
            (drop_required_only, positive_id, "not in required_cases"),
            (alter_violation, canary_id, "expect.violation"),
            (alter_oracle, canary_id, "expect.oracle"),
            (canary_to_positive, canary_id, "not a canary"),
            (positive_to_canary, positive_id, "declared as a canary"),
            (not_mandatory, positive_id, "not mandatory"),
            (blocked, positive_id, "blocked in the manifest"),
            (wrong_class, positive_id, "evidence_class"),
            (extra_mandatory, "q00.diag.unregistered", "no code-derived floor entry"),
            (phantom_required, "q00.diag.phantom", "does not define"),
            (swapped_argv, canary_id, "argv does not run"),
            (swapped_positive_argv, positive_id, "argv does not run --case"),
        ]
        for mutate, cid, needle in planted:
            doc = copy.deepcopy(base)
            mutate(doc)
            problems = manifest_floor_problems(doc, floor_entries())
            self.assertTrue(any(cid in p and needle in p for p in problems),
                            "%s was not reported (%r): %s" % (mutate.__name__, needle, problems))

    def test_skip_declarations_are_exactly_the_one_permitted_host_limitation(self):
        base = load_manifest()
        self.assertEqual(manifest_skip_problems(base), [], "control must be clean")
        sf = next(c for c in base["cases"] if c["id"] == "q00.diag.sink_faults")
        i = sf["argv"].index("--allow-skip")
        self.assertRegex(DEV_FULL_SKIP_REASON, sf["argv"][i + 1])

        def with_argv(doc, cid, fn):
            c = next(x for x in doc["cases"] if x["id"] == cid)
            c["argv"] = fn(list(c["argv"]))

        planted = [
            ("declaration removed", "q00.diag.sink_faults", lambda a: a[:a.index("--allow-skip")], "does not declare"),
            ("declares everything", "q00.diag.sink_faults", lambda a: a[:-1] + [".*"], "too broad"),
            ("declares the RLIMIT limitation", "q00.diag.sink_faults", lambda a: a + ["--allow-skip", "RLIMIT_FSIZE is not enforced"], "too broad"),
            ("declares an unknown limitation", "q00.diag.sink_faults", lambda a: a[:-1] + ["something else entirely"], "matches no known"),
            ("invalid regex", "q00.diag.sink_faults", lambda a: a[:-1] + ["("], "not a valid regex"),
            ("another case declares a skip", "q00.diag.audit", lambda a: a + ["--allow-skip", "/dev/full does not exist"], "only q00.diag.sink_faults"),
        ]
        for label, cid, fn, needle in planted:
            doc = copy.deepcopy(base)
            with_argv(doc, cid, fn)
            problems = manifest_skip_problems(doc)
            self.assertTrue(any(needle in p for p in problems), "%s was not reported (%r): %s" % (label, needle, problems))

    def test_the_bullet_two_requirement_ids_are_defined_once_and_really_referenced(self):
        doc = load_manifest()
        wanted = {"Q00.AC2.full_slow_log_sink", "Q00.AC2.secret_redaction", "Q00.AC2.parallel_isolation", "Q00.AC2.non_root_cwd"}
        self.assertTrue(wanted <= set(doc["requirements"]))
        referenced = {r for c in doc["cases"] for r in c.get("requirements", [])}
        self.assertTrue(wanted <= referenced, sorted(wanted - referenced))
        self.assertTrue(referenced <= set(doc["requirements"]), "a case references an undefined requirement")
        covers = {rid: [c["id"] for c in doc["cases"] if rid in c.get("requirements", [])] for rid in wanted}
        self.assertIn("q00.diag.isolation", covers["Q00.AC2.parallel_isolation"])
        self.assertIn("q00.diag.isolation", covers["Q00.AC2.non_root_cwd"])
        self.assertIn("q00.diag.redaction", covers["Q00.AC2.secret_redaction"])
        self.assertIn("q00.diag.sink_faults", covers["Q00.AC2.full_slow_log_sink"])


def _probe(*fns):
    """Run real unittest tests built from callables and return the real TestResult."""
    Probe = type("Probe", (unittest.TestCase,), {"test_%d" % i: fn for i, fn in enumerate(fns)})
    return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(Probe))


def _passes(self):
    self.assertTrue(True)


@unittest.skip("probe: needs /dev/full")
def _skips(self):
    raise AssertionError("never runs")


def _fails(self):
    self.fail("planted failure")


def _errors(self):
    raise RuntimeError("planted error")


class CaseAdapterTests(unittest.TestCase):
    ALLOW = [re.compile("needs /dev/full")]

    def report(self, result, allow=()):
        doc = _report("q00.diag.x", result, "diag.x", allow)
        self.assertEqual(check_v11(doc), [], doc)
        return doc

    def test_a_clean_run_passes(self):
        doc = self.report(_probe(_passes, _passes))
        self.assertEqual((doc["verdict"], doc["checks"], doc["mismatches"]), ("pass", 2, 0))

    def test_an_undeclared_skip_is_incomplete_never_a_pass_and_never_a_manufactured_failure(self):
        doc = self.report(_probe(_passes, _skips))
        self.assertEqual((doc["verdict"], doc["mismatches"], doc["violation_kinds"]), ("incomplete", 0, {}))
        self.assertEqual(doc["counters"]["skipped_unexpected"], 1)
        self.assertTrue(doc["incomplete_reasons"] and doc["incomplete_reasons"][0].startswith("unexpected_skip:"))

    def test_a_declared_skip_passes_and_stays_visible(self):
        doc = self.report(_probe(_passes, _skips), self.ALLOW)
        self.assertEqual(doc["verdict"], "pass")
        self.assertEqual((doc["counters"]["skipped_allowed"], doc["counters"]["skipped_unexpected"]), (1, 0))

    def test_a_declaration_that_does_not_match_the_skip_does_not_excuse_it(self):
        doc = self.report(_probe(_passes, _skips), [re.compile("some other limitation")])
        self.assertEqual(doc["verdict"], "incomplete")

    def test_failures_and_errors_outrank_any_skip_policy(self):
        for fn, kind in ((_fails, "test_failure"), (_errors, "test_error")):
            doc = self.report(_probe(_passes, _skips, fn), self.ALLOW)
            self.assertEqual((doc["verdict"], doc["violation_kinds"]), ("fail", {kind: 1}))
            self.assertNotEqual(doc["expected"], doc["observed"])

    def test_nothing_executed_is_incomplete_even_if_every_skip_is_declared(self):
        for result, allow in ((_probe(_skips), self.ALLOW), (_probe(), ())):
            doc = self.report(result, allow)
            self.assertEqual(doc["verdict"], "incomplete")
            self.assertIn("no_checks_executed", doc["incomplete_reasons"])

    def test_the_contract_guard_rejects_doctored_results(self):
        good = self.report(_probe(_passes))
        for name, edit in (("pass_with_mismatch", lambda d: d.update(mismatches=1)),
                           ("fail_expected_equals_observed", lambda d: d.update(verdict="fail", mismatches=1, violation_kinds={"x": 1}, observed=d["expected"])),
                           ("fail_without_kind", lambda d: d.update(verdict="fail", mismatches=1)),
                           ("kinds_not_summing", lambda d: d.update(violation_kinds={"x": 2})),
                           ("incomplete_without_reason", lambda d: d.update(verdict="incomplete")),
                           ("pass_but_unfinalized", lambda d: d.update(finalized=False)),
                           ("float_counter", lambda d: d["counters"].update(tests_run=1.5))):
            doc = copy.deepcopy(good)
            edit(doc)
            self.assertNotEqual(check_v11(doc), [], name)

    def test_exit_codes_never_let_an_incomplete_case_look_like_a_pass(self):
        self.assertEqual(EXIT_CODES, {"pass": 0, "fail": 1, "incomplete": 2})
        self.assertEqual(len(set(EXIT_CODES.values())), 3)

    def test_a_canary_detected_as_the_wrong_violation_is_reported_as_not_detected(self):
        import unittest.mock as mock
        name = "naive_absence_of_error"
        oracle, violation, fn = CANARIES[name]
        with tempfile.TemporaryDirectory(prefix="diag canary ") as td:
            path = os.path.join(td, "r.json")
            stderr, sys.stderr = sys.stderr, io.StringIO()      # _canary_main echoes the document; keep the test log quiet
            try:
                rc_ok = _canary_main(name, path)
                good = json.load(open(path))
                os.unlink(path)
                with mock.patch.dict(CANARIES, {name: (oracle, "a_violation_the_oracle_never_reports", fn)}):
                    rc_bad = _canary_main(name, path)
                bad = json.load(open(path))
            finally:
                sys.stderr = stderr
        self.assertEqual((rc_ok, good["verdict"], violation in good["violation_kinds"]), (1, "fail", True))
        self.assertEqual((rc_bad, bad["verdict"], bad["violation_kinds"]), (0, "pass", {}), "wrong violation must read as undetected")
        self.assertEqual(check_v11(good) + check_v11(bad), [])

    def run_cli(self, *args, result_path=None, case_id="q00.diag.envelope"):
        env = {k: v for k, v in os.environ.items() if not k.startswith("FFW_")}
        if result_path:
            env.update(FFW_RESULT_PATH=result_path, FFW_RUN_ID="r1", FFW_CASE_ID=case_id, FFW_RESULT_NONCE="n0nce")
        return subprocess.run([sys.executable, "-B", "-I", os.path.abspath(__file__), *args], env=env, capture_output=True,
                              text=True, timeout=300)

    def test_the_cli_writes_a_valid_result_that_echoes_the_runner_identity(self):
        with tempfile.TemporaryDirectory(prefix="diag cli result ") as td:
            path = os.path.join(td, "result.json")
            r = self.run_cli("--case", "q00.diag.envelope", result_path=path)
            self.assertEqual(r.returncode, 0, r.stderr[-400:])
            doc = json.load(open(path))
            self.assertEqual((doc["run_id"], doc["case_id"], doc["nonce"], doc["verdict"]), ("r1", "q00.diag.envelope", "n0nce", "pass"))
            self.assertEqual(check_v11(doc), [])

    def test_the_cli_enforces_the_skip_policy_on_the_real_sink_faults_case(self):
        host_has_dev_full = os.path.exists("/dev/full")
        with tempfile.TemporaryDirectory(prefix="diag cli skip ") as td:
            undeclared, declared = os.path.join(td, "a.json"), os.path.join(td, "b.json")
            r1 = self.run_cli("--case", "q00.diag.sink_faults", result_path=undeclared, case_id="q00.diag.sink_faults")
            r2 = self.run_cli("--case", "q00.diag.sink_faults", "--allow-skip", "/dev/full does not exist on this host",
                              result_path=declared, case_id="q00.diag.sink_faults")
            d1, d2 = json.load(open(undeclared)), json.load(open(declared))
        self.assertEqual(check_v11(d1) + check_v11(d2), [])
        if host_has_dev_full:     # nothing is skipped, so the declaration is irrelevant and both pass
            self.assertEqual((r1.returncode, d1["verdict"], r2.returncode, d2["verdict"]), (0, "pass", 0, "pass"))
        else:                     # the Linux-only test is skipped: undeclared -> incomplete (exit 2), declared -> pass
            self.assertEqual((r1.returncode, d1["verdict"]), (2, "incomplete"))
            self.assertEqual((r2.returncode, d2["verdict"], d2["counters"]["skipped_allowed"]), (0, "pass", 1))

    def test_the_cli_prints_the_floor_and_rejects_bad_usage(self):
        r = self.run_cli("--floor")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout), floor_entries())
        self.assertEqual(self.run_cli("--allow-skip", "x").returncode, 2)                       # needs --case
        self.assertEqual(self.run_cli("--case", "q00.diag.nope").returncode, 2)
        self.assertEqual(self.run_cli("--case", "q00.diag.envelope", "--allow-skip", "(").returncode, 2)   # bad regex
        self.assertEqual(self.run_cli("--canary", "nope").returncode, 2)


CASES["q00.diag.registry"] = [FloorTests, CaseAdapterTests]


# --------------------------------------------------------------------------- #
# runner child-case entry point (wire contract ffw.case-result.v1, v1.1)
# --------------------------------------------------------------------------- #

def _canary_main(name, result_path):
    oracle, violation, fn = CANARIES[name]
    observed, detected = fn()
    env = os.environ
    kinds = _canary_kinds(name, observed) if detected else {}
    common = {"schema": "ffw.case-result.v1", "run_id": env.get("FFW_RUN_ID"),
              "case_id": env.get("FFW_CASE_ID", CANARY_ID_PREFIX + name), "nonce": env.get("FFW_RESULT_NONCE"),
              "oracle": oracle, "oracle_kind": "property", "independent": True, "finalized": True, "checks": 1,
              "incomplete_reasons": [], "counters": {"detected": int(detected)}}
    if detected and violation in kinds:   # the oracle caught the planted defect: the defective subject FAILS, as the canary expects
        doc = dict(common, verdict="fail", mismatches=sum(kinds.values()), violation_kinds=kinds,
                   expected={"oracle_flags_defect": False}, observed=dict(observed, oracle_flags_defect=True),
                   first_causal_event="planted defect %s detected by %s: %s" % (name, oracle, ",".join(sorted(kinds))))
    else:                                 # undetected, or detected as the WRONG violation: report a pass so the runner records canary_not_detected
        doc = dict(common, verdict="pass", mismatches=0, violation_kinds={}, expected=observed, observed=observed,
                   first_causal_event="planted defect %s was NOT detected as %s" % (name, violation))
    if result_path:
        _write_result(result_path, doc)
    sys.stderr.write(json.dumps(doc, sort_keys=True)[:600] + "\n")
    return 1 if doc["verdict"] == "fail" else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="test_diagnostics.py", description="diagnostics tests / runner child cases")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="print case ids and canaries")
    mode.add_argument("--floor", action="store_true", help="print the code-derived floor as JSON")
    mode.add_argument("--case", metavar="ID", help="run one registered case (runner child case)")
    mode.add_argument("--canary", metavar="NAME", help="run one planted-defect canary")
    ap.add_argument("--allow-skip", action="append", default=[], metavar="REGEX",
                    help="declare a known host limitation (matched against skip reasons); an undeclared skip makes a case incomplete")
    args = ap.parse_args(argv)
    result_path = os.environ.get("FFW_RESULT_PATH")
    if args.allow_skip and not args.case:
        ap.error("--allow-skip only applies to --case")
    try:
        allow = [re.compile(rx) for rx in args.allow_skip]
    except re.error as exc:
        ap.error("bad --allow-skip regex: %s" % exc)
    if args.list:
        print("\n".join(list(CASES) + ["canary:" + n for n in CANARIES]))
        return 0
    if args.floor:
        print(json.dumps(floor_entries(), sort_keys=True))
        return 0
    if args.canary is not None:
        if args.canary not in CANARIES:
            ap.error("unknown canary %r; try --list" % args.canary)
        return _canary_main(args.canary, result_path)
    case = args.case
    if case is None and result_path and os.environ.get("FFW_CASE_ID") in CASES:
        case = os.environ["FFW_CASE_ID"]
    if case is not None:
        if case not in CASES:
            ap.error("unknown case %r; try --list" % case)
        result = _run_classes(CASES[case], sys.stderr)
        doc = _report(case, result, "diag." + case.rsplit(".", 1)[-1], allow)
        if result_path:
            _write_result(result_path, doc)
        return EXIT_CODES[doc["verdict"]]
    result = _run_classes([c for cs in CASES.values() for c in cs], sys.stderr)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
