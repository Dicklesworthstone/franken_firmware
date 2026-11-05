"""Checks on the N02 reference model and its vectors (bead ffw-ugf), run by scripts/e2e/n02.

They establish that the golden scenarios are consistent with an independently built model, that the
model can fail (several deliberately broken variants are caught, after the unbroken one is shown to
pass), that its rate limiter agrees with the token-bucket formulation the Rust uses, that the
signing-bytes vectors match a layout derived by hand, and that every invariant maps to scenarios and
to Rust tests that exist. They do not exercise the Rust code.
"""

import json
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as ref  # noqa: E402

CHANNEL_SRC = ref.ROOT / "crates" / "franken-control" / "src" / "channel"
CONTRACT = ref.ROOT / "docs" / "contracts" / "n02.md"
CASES = Path(__file__).resolve().parent / "cases.json"


def doc():
    return ref.load()


def scenario(doc_, sid):
    return next(s for s in doc_["scenarios"] if s["id"] == sid)


class TokenBucket:
    """The formulation the Rust limiter uses: a bucket refilled in whole intervals, with the time
    spent full earning nothing. Written here only to be compared with the model's GCRA."""

    def __init__(self, burst, interval, now):
        self.burst, self.interval, self.tokens, self.last = burst, interval, burst, now

    def take(self, now):
        if now > self.last:
            intervals = (now - self.last) // self.interval
            if intervals:
                if intervals >= self.burst - self.tokens:
                    self.tokens, self.last = self.burst, now
                else:
                    self.tokens += intervals
                    self.last += intervals * self.interval
        if self.tokens > 0:
            self.tokens -= 1
            return None
        return max(self.last + self.interval - now, 1)


class Scenarios(unittest.TestCase):
    def test_every_golden_scenario_matches_the_independent_model(self):
        d = doc()
        for s in d["scenarios"]:
            with self.subTest(s["id"]):
                self.assertEqual(ref.replay(d, s), [])

    def test_the_file_has_the_scenarios_the_contract_promises(self):
        d = doc()
        ids = [s["id"] for s in d["scenarios"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 20)
        for s in d["scenarios"]:
            self.assertTrue(s["invariants"], s["id"])
            self.assertTrue(s["title"], s["id"])
            self.assertIn("final", s)
            for step in s["steps"]:
                self.assertIn(step["op"], {"submit", "step", "session_epoch", "rebind", "revoke"})

    def test_the_replay_reports_a_wrong_expectation(self):
        d = doc()
        s = json.loads(json.dumps(scenario(d, "N02-S001")))
        s["steps"][0]["expect"] = "rejected:id_reuse"
        self.assertTrue(any("expected" in p for p in ref.replay(d, s)))
        s = json.loads(json.dumps(scenario(d, "N02-S001")))
        s["final"]["kitchen"] = 61
        self.assertTrue(any("final" in p for p in ref.replay(d, s)))

    def test_every_scenario_balances_its_counters(self):
        d = doc()
        for s in d["scenarios"]:
            with self.subTest(s["id"]):
                model = ref.Model(ref.config_for(d, s))
                for step in s["steps"]:
                    if step["op"] == "submit":
                        for _ in range(step.get("repeat", 1)):
                            model.submit(step["at_ms"], step["peer"], step["seq"], step["epoch"],
                                         step["rev"], step["cmd"], forged=step.get("proof") == "forged")
                    elif step["op"] == "step":
                        model.step(step["at_ms"])
                    elif step["op"] == "session_epoch":
                        model.force_epoch(step["epoch"])
                    elif step["op"] == "rebind":
                        model.rebind(step["peer"], step["epoch"])
                    elif step["op"] == "revoke":
                        model.revoke(step["peer"])
                self.assertEqual(model.accounted(), model.stats["received"])


# Deliberately broken channels. Each must be caught by the vectors; the unbroken model must pass them
# first, or a "catch" would only be a model that was already wrong.


class NoLedger(ref.Model):
    """Forgets every outcome at once, so a retry is queued and applied again."""

    def _remember(self, item, outcome, now):
        return None


class RateBeforeAuth(ref.Model):
    """Spends the named peer's allowance before checking who is calling."""

    def submit(self, now, peer, seq, epoch, rev, cmd, forged=False):
        if peer in self.peers:
            self._rate(peer, ref.LANE[cmd["kind"]], now)
        return super().submit(now, peer, seq, epoch, rev, cmd, forged)


class FifoOnly(ref.Model):
    """One queue in arrival order: stop and mute wait behind ordinary work."""

    def _next(self):
        both = sorted(self.queues["priority"] + self.queues["ordinary"], key=lambda q: q["accepted"])
        if not both:
            return None
        pick = both[0]
        self.queues[pick["lane"]].remove(pick)
        return pick


class IgnoresEpoch(ref.Model):
    """Applies a controller's command whatever epoch it names."""

    def _execute(self, item, withdrawn):
        item = dict(item, epoch=self.epoch)
        return super()._execute(item, withdrawn)


class NoRevisionCheck(ref.Model):
    def _execute(self, item, withdrawn):
        return super()._execute(dict(item, rev=None), withdrawn)


class ForgetsFloor(ref.Model):
    """Keeps no floor, so a forgotten number looks new and is queued again."""

    def _forget(self, record):
        self.records.remove(record)


class UnboundedQueue(ref.Model):
    def _room(self, lane, role):
        return True


class NoExpiry(ref.Model):
    def step(self, now):
        cfg = dict(self.cfg, pending_ttl_ms=10**12)
        saved, self.cfg = self.cfg, cfg
        try:
            return super().step(now)
        finally:
            self.cfg = saved


class Mutations(unittest.TestCase):
    def failing(self, model_class):
        d = doc()
        return {s["id"] for s in d["scenarios"] if ref.replay(d, s, model_class)}

    def test_the_unbroken_model_is_the_green_baseline(self):
        self.assertEqual(self.failing(ref.Model), set())

    def test_each_broken_variant_is_caught_by_the_scenario_built_for_it(self):
        expected = {
            NoLedger: "N02-S001",
            RateBeforeAuth: "N02-S011",
            FifoOnly: "N02-S012",
            IgnoresEpoch: "N02-S005",
            NoRevisionCheck: "N02-S007",
            ForgetsFloor: "N02-S003",
            UnboundedQueue: "N02-S009",
            NoExpiry: "N02-S016",
        }
        for broken, sid in expected.items():
            with self.subTest(broken.__name__):
                self.assertIn(sid, self.failing(broken))


class Limiter(unittest.TestCase):
    def test_gcra_agrees_with_the_token_bucket_on_random_schedules(self):
        # Both start at the first request, as the channel creates a bucket when a peer first speaks.
        rng = random.Random(0x4E3032)
        waits_seen = 0
        for case in range(300):
            burst, interval = rng.randint(1, 6), rng.randint(1, 50)
            now = rng.randint(0, 20)
            gcra, bucket = ref.Gcra(burst, interval), TokenBucket(burst, interval, now)
            for _ in range(60):
                got = gcra.take(now), bucket.take(now)
                self.assertEqual(got[0], got[1], (case, burst, interval, now))
                waits_seen += got[0] is not None
                now += rng.choice([0, 0, 0, 1, 3, interval, interval * 2, interval * 7, rng.randint(0, 100)])
        self.assertGreater(waits_seen, 1000, "the schedules must actually exercise refusals")

    def test_the_hand_computed_table(self):
        # burst 2, interval 100: two at once, then a wait that shrinks as time passes, then one back.
        g = ref.Gcra(2, 100)
        got = [g.take(0), g.take(0), g.take(0), g.take(40), g.take(99), g.take(100), g.take(100)]
        self.assertEqual(got, [None, None, 100, 60, 1, None, 100])


class WireLayout(unittest.TestCase):
    def test_vectors_match_the_encoder_and_have_the_derived_lengths(self):
        d = doc()
        lengths = {"N02-W001": 46, "N02-W002": 45, "N02-W003": 37, "N02-W004": 34, "N02-W005": 38}
        self.assertEqual(ref.check_vectors(d), [])
        for v in d["signing_vectors"]:
            self.assertEqual(len(v["hex"]) // 2, lengths[v["id"]], v["id"])
            self.assertTrue(v["hex"].startswith("46464350" "01"), "magic FFCP then version 1")

    def test_every_signed_field_changes_the_bytes(self):
        base = ref.signing_bytes("ctl-a", 7, 3, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5})
        variants = [
            ref.signing_bytes("ctl-b", 7, 3, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}),
            ref.signing_bytes("ctl-a", 8, 3, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}),
            ref.signing_bytes("ctl-a", 7, 4, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}),
            ref.signing_bytes("ctl-a", 7, 3, 13, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}),
            ref.signing_bytes("ctl-a", 7, 3, None, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}),
            ref.signing_bytes("ctl-a", 7, 3, 12, {"kind": "adjust_member_volume", "member": "den", "delta": -5}),
            ref.signing_bytes("ctl-a", 7, 3, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": 5}),
        ]
        self.assertEqual(len({base, *variants}), len(variants) + 1)

    def test_a_present_revision_of_zero_differs_from_an_absent_one(self):
        cmd = {"kind": "set_group_volume", "volume": 1}
        self.assertNotEqual(ref.signing_bytes("p", 1, 1, 0, cmd), ref.signing_bytes("p", 1, 1, None, cmd))

    def test_every_command_kind_has_its_own_tag(self):
        kinds = [
            {"kind": "set_member_volume", "member": "m", "volume": 1},
            {"kind": "set_group_volume", "volume": 1},
            {"kind": "adjust_member_volume", "member": "m", "delta": 1},
            {"kind": "adjust_group_volume", "delta": 1},
            {"kind": "set_member_mute", "member": "m", "muted": True},
            {"kind": "stop", "now_ns": 1, "tail_ns": 1},
            {"kind": "cancel", "target_seq": 1},
        ]
        # magic 4 + version 1 + peer (1 + 1) + seq 8 + epoch 8 + revision (1 + 8) = 32: the tag is next.
        tags = [ref.signing_bytes("p", 2, 1, 1, c)[32] for c in kinds]
        self.assertEqual(tags, [1, 2, 3, 4, 5, 6, 7])


class Restart(unittest.TestCase):
    """What a restart does to the guarantees (contract section 7 and row 13 of section 14). These are
    characterizations of a known limit, not requirements the design meets."""

    CMD70 = {"kind": "set_group_volume", "volume": 70}
    CMD40 = {"kind": "set_group_volume", "volume": 40}

    def model(self):
        return ref.Model(ref.config_for(doc(), {}))

    def test_an_absolute_command_delivered_late_after_a_restart_is_applied_again(self):
        m = self.model()
        m.submit(0, "ctl-a", 1, 10, None, self.CMD70)
        m.step(0)
        m.submit(0, "ctl-b", 1, 10, None, self.CMD40)
        m.step(0)
        self.assertEqual(m.group, 40)
        m.restart()
        self.assertEqual(m.submit(0, "ctl-a", 1, 10, None, self.CMD70), "queued:ordinary")
        m.step(0)
        self.assertEqual(m.group, 70, "the late duplicate reverted a newer change: a known limit")

    def test_the_same_late_duplicate_without_a_restart_is_answered_not_applied(self):
        m = self.model()
        m.submit(0, "ctl-a", 1, 10, None, self.CMD70)
        m.step(0)
        m.submit(0, "ctl-b", 1, 10, None, self.CMD40)
        m.step(0)
        self.assertEqual(m.submit(0, "ctl-a", 1, 10, None, self.CMD70), "settled:committed:3")
        m.step(0)
        self.assertEqual(m.group, 40)

    def test_a_relative_command_delivered_late_after_a_restart_is_fenced_by_its_revision(self):
        m = self.model()
        rel = {"kind": "adjust_member_volume", "member": "kitchen", "delta": 10}
        m.submit(0, "ctl-a", 1, 10, 2, rel)
        m.step(0)
        m.restart()
        self.assertEqual(m.submit(0, "ctl-a", 1, 10, 2, rel), "queued:ordinary")
        self.assertEqual(m.step(0), ["ctl-a#1=refused:revision_mismatch"])
        self.assertEqual(m.members["kitchen"]["volume"], 60, "one delta, not two")


class Mapping(unittest.TestCase):
    def cases(self):
        return json.loads(CASES.read_text(encoding="utf-8"))

    def test_invariants_scenarios_and_rust_tests_line_up(self):
        d, c = doc(), self.cases()
        declared = {i["id"] for i in c["invariants"]}
        self.assertEqual(len(declared), len(c["invariants"]), "duplicate invariant id")
        scenario_ids = {s["id"] for s in d["scenarios"]}
        used = set()
        for s in d["scenarios"]:
            used.update(s["invariants"])
        self.assertEqual(used - declared, set(), "scenario names an undeclared invariant")
        self.assertEqual(declared - used, set(), "declared invariant has no scenario")
        for inv in c["invariants"]:
            self.assertTrue(inv["claim"] and inv["rust_tests"] and inv["scenarios"], inv["id"])
            for sid in inv["scenarios"]:
                self.assertIn(sid, scenario_ids, inv["id"])
                self.assertIn(inv["id"], scenario(d, sid)["invariants"], f"{sid} does not list {inv['id']}")
        for s in d["scenarios"]:
            for i in s["invariants"]:
                listed = next(x for x in c["invariants"] if x["id"] == i)["scenarios"]
                self.assertIn(s["id"], listed, f"{i} does not list {s['id']}")

    def test_every_named_rust_test_exists(self):
        source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(CHANNEL_SRC.glob("*.rs")))
        names = {n for i in self.cases()["invariants"] for n in i["rust_tests"]}
        for group in self.cases()["other_rust_checks"].values():
            names.update(group)
        missing = sorted(n for n in names if not re.search(rf"#\[test\]\s*fn {n}\(", source))
        self.assertEqual(missing, [])

    def test_the_contract_mentions_every_invariant(self):
        text = CONTRACT.read_text(encoding="utf-8")
        missing = [i["id"] for i in self.cases()["invariants"] if i["id"] not in text]
        self.assertEqual(missing, [])

    def test_the_rust_replay_handles_every_operation_the_file_uses(self):
        source = (CHANNEL_SRC / "replay.rs").read_text(encoding="utf-8")
        for op in {step["op"] for s in doc()["scenarios"] for step in s["steps"]}:
            self.assertIn(f'"{op}"', source, op)

    def test_the_rust_replay_builds_the_same_peers_the_model_uses(self):
        source = (CHANNEL_SRC / "replay.rs").read_text(encoding="utf-8")
        for name, (role, bound) in ref.PEERS.items():
            kind = "LocalUser" if role == "local" else "Controller"
            bound_text = "None" if bound is None else f"Some({'EPOCH' if bound == 10 else bound})"
            self.assertRegex(source, rf'\("{name}", PeerRole::{kind}, {re.escape(bound_text)}\)')


if __name__ == "__main__":
    unittest.main()
