"""Checks on the N02 reference model and its vectors (bead ffw-ugf), run by scripts/e2e/n02.

They establish that the golden scenarios are consistent with an independently built model, that the
model can fail (several deliberately broken variants are caught, after the unbroken one is shown to
pass), that its rate limiter agrees with the token-bucket formulation the Rust uses, that the
signing-bytes vectors match a layout derived by hand, and that every invariant maps to scenarios and
to Rust tests that exist. They do not exercise the Rust code.
"""

import hashlib
import hmac
import json
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_auth_vectors as gen  # noqa: E402
import gen_log_vectors as genlog  # noqa: E402
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
        self.assertGreaterEqual(len(ids), 35)
        for s in d["scenarios"]:
            self.assertTrue(s["invariants"], s["id"])
            self.assertTrue(s["title"], s["id"])
            self.assertIn("final", s)
            for step in s["steps"]:
                self.assertIn(step["op"], {"submit", "step", "session_epoch", "rebind", "revoke", "restart", "external_command",
                                           "lease", "foreign_lease", "advance_epoch"})

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
                    ref.run_step(model, step)
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


class SessionFaultVisible(ref.Model):
    """Reports a session-side number collision to the sender as an ordinary session refusal."""

    def _execute(self, item, withdrawn):
        out = super()._execute(item, withdrawn)
        return "refused:session" if out == "refused:internal_fault" else out


class NoRestartFence(ref.Model):
    """Has no revision floor, so a copy composed before a restart is applied."""

    def step(self, now):
        self.floor = 0
        return super().step(now)


class StrictAbsolute(ref.Model):
    """Holds absolute commands to the exact current revision, as relative ones are."""

    def _execute(self, item, withdrawn):
        controller = item["role"] == "controller" and item["cmd"]["kind"] != "cancel"
        if controller and item["epoch"] == self.epoch and item["rev"] is not None and item["rev"] != self.revision:
            return "refused:revision_mismatch"
        return super()._execute(item, withdrawn)


class RestartAtBase(ref.Model):
    """Counts session numbers from the counter alone, so a restart meets numbers already used."""

    def _mint(self):
        number = self.next_seq
        self.next_seq += 1
        return number


class NoRevisionRequired(ref.Model):
    """Fills in a missing revision for a controller instead of turning the request away."""

    def submit(self, now, peer, seq, epoch, rev, cmd, forged=False):
        if rev is None and cmd["kind"] in ref.NEEDS_REVISION and peer in ("ctl-a", "ctl-b"):
            rev = self.revision
        return super().submit(now, peer, seq, epoch, rev, cmd, forged)


class NoLeaseGate(ref.Model):
    """Applies group-changing commands whatever the lease says."""

    def _lease_gate(self, item):
        return None


class GatesSilencing(ref.Model):
    """Holds a local stop and mute-on to the lease as well."""

    def _lease_gate(self, item):
        return super()._lease_gate(dict(item, role="controller"))


class RecordsLeaseRefusals(ref.Model):
    """Remembers a lease refusal as the command's outcome, so a resend after renewal is answered
    "refused" from memory instead of being applied."""

    @staticmethod
    def _transient(outcome):
        return False


class InstallUnchecked(ref.Model):
    """Accepts any token as the lease."""

    def install_lease(self, token, at_ms):
        self.lease = {"epoch": token["epoch"], "expires_ms": token["expires_ms"]}
        return "installed"


class LeaseIgnoresExpiry(ref.Model):
    def _lease_gate(self, item):
        refused = super()._lease_gate(item)
        return None if refused == "refused:lease:authority_expired" else refused


class IgnoresMargin(ref.Model):
    """Judges the lease against its plain expiry, as if the clocks agreed exactly."""

    def __init__(self, config):
        super().__init__(dict(config, lease_margin_ms=0))


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
            SessionFaultVisible: "N02-S024",
            NoRestartFence: "N02-S025",
            StrictAbsolute: "N02-S027",
            RestartAtBase: "N02-S026",
            NoRevisionRequired: "N02-S028",
            NoLeaseGate: "N02-S029",
            GatesSilencing: "N02-S029",
            RecordsLeaseRefusals: "N02-S030",
            InstallUnchecked: "N02-S032",
            LeaseIgnoresExpiry: "N02-S031",
            IgnoresMargin: "N02-S035",
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
    """What a channel restart does to the guarantees (contract sections 7 and 8, row 13 of section 14).
    The session is kept; the channel's queues, outcomes, limiters, floor and counter are not."""

    ABS70 = {"kind": "set_group_volume", "volume": 70}
    ABS40 = {"kind": "set_group_volume", "volume": 40}
    REL = {"kind": "adjust_member_volume", "member": "kitchen", "delta": 10}

    @staticmethod
    def relase(m):
        """The owner installs a lease on the new incarnation, as it must: a restarted channel has none."""
        token = {"group_ok": True, "issuer_ok": True, "epoch": m.epoch, "expires_ms": 1_000_000}
        assert m.install_lease(token, 0) == "installed"

    def history(self):
        m = ref.Model(ref.config_for(doc(), {}))
        m.submit(0, "ctl-a", 1, 10, 2, self.ABS70)
        self.assertEqual(m.step(0), ["ctl-a#1=committed:3"])
        m.submit(0, "ctl-b", 1, 10, 3, self.ABS40)
        self.assertEqual(m.step(0), ["ctl-b#1=committed:4"])
        m.submit(0, "ctl-a", 2, 10, 4, self.REL)
        self.assertEqual(m.step(0), ["ctl-a#2=committed:5"])
        return m

    def test_without_a_restart_a_late_copy_is_answered_from_memory_and_changes_nothing(self):
        m = self.history()
        self.assertEqual(m.submit(0, "ctl-a", 1, 10, 2, self.ABS70), "settled:committed:3")
        self.assertEqual(m.step(0), [])
        self.assertEqual(m.group, 40)

    def test_after_a_restart_late_absolute_and_relative_copies_are_refused(self):
        m = self.history()
        m.restart()
        self.relase(m)
        self.assertEqual(m.submit(0, "ctl-a", 1, 10, 2, self.ABS70), "queued:ordinary")
        self.assertEqual(m.submit(0, "ctl-a", 2, 10, 4, self.REL), "queued:ordinary")
        self.assertEqual(m.step(0), ["ctl-a#1=refused:stale_revision", "ctl-a#2=refused:revision_mismatch"])
        self.assertEqual((m.group, m.members["kitchen"]["volume"], m.revision), (40, 60, 5))

    def test_after_a_restart_a_command_composed_after_it_is_applied(self):
        m = self.history()
        m.restart()
        self.relase(m)
        m.submit(0, "ctl-a", 3, 10, 5, {"kind": "set_group_volume", "volume": 55})
        self.assertEqual(m.step(0), ["ctl-a#3=committed:6"])
        self.assertEqual(m.group, 55)

    def test_the_first_commands_after_a_restart_are_not_session_faults(self):
        m = self.history()
        m.restart()
        self.relase(m)
        for seq in range(3, 9):
            m.submit(0, "ctl-a", seq, 10, 5, {"kind": "set_group_volume", "volume": 50 + seq})
        got = m.step(0) + m.step(0)
        self.assertEqual(len(got), 6)
        self.assertTrue(all("committed" in g for g in got), got)

    def test_a_number_taken_by_another_caller_is_one_fault_and_then_clears(self):
        m = ref.Model(ref.config_for(doc(), {}))
        m.external_command(1003)
        for seq in range(1, 4):
            m.submit(0, "ctl-a", seq, 10, 3, {"kind": "set_group_volume", "volume": 60 + seq})
        self.assertEqual(
            m.step(0), ["ctl-a#1=refused:internal_fault", "ctl-a#2=committed:4", "ctl-a#3=committed:5"]
        )


class Authentication(unittest.TestCase):
    def test_the_standard_library_agrees_with_the_published_hmac_vectors(self):
        # RFC 4231 test cases 1 and 2: the primitive the vectors are computed with is the real one.
        self.assertEqual(
            hmac.new(bytes([0x0B]) * 20, b"Hi There", hashlib.sha256).hexdigest(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )
        self.assertEqual(
            hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )

    def test_every_signing_vector_has_an_auth_vector_with_its_peers_fixture_key(self):
        d = doc()
        covered = {a["signing_vector"] for a in d["auth_vectors"]}
        self.assertEqual(covered, {v["id"] for v in d["signing_vectors"]})
        peers = {v["id"]: v["peer"] for v in d["signing_vectors"]}
        for a in d["auth_vectors"]:
            self.assertEqual(a["key"], f"key-{peers[a['signing_vector']]}-0123456789abcdef")
            self.assertEqual(len(bytes.fromhex(a["tag_hex"])), 32)
            self.assertGreaterEqual(len(a["key"]), 16)

    def test_the_tampers_cover_every_kind_of_signed_field(self):
        d = doc()
        fields = {t["field"] for t in d["tamper_vectors"]}
        self.assertEqual(
            fields,
            {"peer", "seq", "epoch", "expected revision value", "expected revision presence", "member",
             "delta", "command kind", "stop now_ns", "stop tail_ns", "cancel target_seq", "mute flag",
             "expected revision zero versus absent"},
        )

    def test_the_context_label_and_the_message_both_matter(self):
        d = doc()
        a = d["auth_vectors"][0]
        message = bytes.fromhex(next(v for v in d["signing_vectors"] if v["id"] == a["signing_vector"])["hex"])
        key = a["key"].encode("ascii")
        bare = hmac.new(key, message, hashlib.sha256).hexdigest()
        self.assertNotEqual(bare, a["tag_hex"], "the context label is part of what is authenticated")
        self.assertEqual(ref.proof(key, message).hex(), a["tag_hex"])


class WellFormedness(unittest.TestCase):
    """The Rust refuses to build a request that breaks the contract's form rules, so a vector that
    breaks one can never reach the tag check. b10n failed on exactly that (a relative command with no
    revision in a tamper vector) while this side said PASS, because it did not know the rule."""

    def test_the_rules_catch_every_kind_of_malformed_request(self):
        adj = {"kind": "adjust_member_volume", "member": "kitchen", "delta": 5}
        self.assertIsNone(ref.malformed(7, 12, adj))
        self.assertIn("relative", ref.malformed(7, None, adj))
        self.assertIn("relative", ref.malformed(7, None, {"kind": "adjust_group_volume", "delta": 5}))
        self.assertIn("zero sequence", ref.malformed(0, 1, adj))
        self.assertIn("delta", ref.malformed(7, 12, {**adj, "delta": 0}))
        self.assertIn("delta", ref.malformed(7, 12, {**adj, "delta": 101}))
        self.assertIn("delta", ref.malformed(7, 12, {**adj, "delta": -101}))
        self.assertIsNone(ref.malformed(7, 12, {**adj, "delta": -100}))
        self.assertIn("volume", ref.malformed(1, 1, {"kind": "set_group_volume", "volume": 101}))
        self.assertIn("member", ref.malformed(1, 1, {**adj, "member": "Kitchen"}))
        self.assertIn("member", ref.malformed(1, 1, {**adj, "member": ""}))
        self.assertIn("member", ref.malformed(1, 1, {**adj, "member": "x" * 65}))
        self.assertIn("cancel", ref.malformed(5, None, {"kind": "cancel", "target_seq": 5}))
        self.assertIn("cancel", ref.malformed(5, None, {"kind": "cancel", "target_seq": 0}))
        self.assertIsNone(ref.malformed(5, None, {"kind": "cancel", "target_seq": 4}))
        # A volume or mute setter without a revision is buildable: the channel, not the body, asks for it.
        self.assertIsNone(ref.malformed(1, None, {"kind": "set_group_volume", "volume": 5}))

    def test_every_vector_and_every_scenario_request_is_buildable(self):
        d = doc()
        for v in list(d["signing_vectors"]) + list(d["tamper_vectors"]):
            self.assertIsNone(ref.malformed(v["seq"], v["rev"], v["cmd"]), v["id"])
        for s in d["scenarios"]:
            for step in s["steps"]:
                if step["op"] == "submit":
                    self.assertIsNone(ref.malformed(step["seq"], step["rev"], step["cmd"]), s["id"])

    def test_a_vector_the_rust_could_not_build_is_reported(self):
        d = json.loads(json.dumps(doc()))
        bad = next(t for t in d["tamper_vectors"] if t["field"] == "member")
        bad["rev"] = None  # a relative command with no revision: the b10n failure
        self.assertTrue(any("constructor refuses" in p for p in ref.check_vectors(d)))
        s = json.loads(json.dumps(scenario(d, "N02-S007")))
        s["steps"][0]["rev"] = None
        self.assertTrue(any("constructor refuses" in p for p in ref.replay(d, s)))


class GeneratedVectors(unittest.TestCase):
    def test_the_file_holds_exactly_what_the_generator_produces(self):
        d = doc()
        text, problems = gen.build(d)
        self.assertEqual(problems, [])
        current = ref.DEFAULT_VECTORS.read_text(encoding="utf-8")
        self.assertEqual(current[current.index(gen.START_MARK):current.index(gen.END_MARK)], text)
        self.assertEqual(gen.main(["--check"]), 0)

    def test_each_tamper_changes_exactly_one_signed_field(self):
        d = doc()
        signing = {v["id"]: v for v in d["signing_vectors"]}
        auth = {a["id"]: a for a in d["auth_vectors"]}
        for t in d["tamper_vectors"]:
            base = signing[auth[t["auth_vector"]]["signing_vector"]]
            changed = gen.changed_fields(
                (base["peer"], base["seq"], base["epoch"], base["rev"], base["cmd"]),
                (t["peer"], t["seq"], t["epoch"], t["rev"], t["cmd"]),
            )
            self.assertEqual(len(changed), 1, f"{t['id']} ({t['field']}): {sorted(changed)}")

    def test_the_guard_reports_a_tamper_that_changes_two_fields(self):
        base = ("ctl-a", 7, 3, 12, {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5})
        two = ("ctl-a", 8, 4, 12, base[4])
        self.assertEqual(gen.changed_fields(base, two), {"seq", "epoch"})
        self.assertEqual(gen.changed_fields(base, base), set())

    def test_the_command_kind_tamper_changes_only_the_tag_byte(self):
        d = doc()
        tamper = next(t for t in d["tamper_vectors"] if t["field"] == "command kind")
        base = next(v for v in d["signing_vectors"]
                    if v["id"] == next(a for a in d["auth_vectors"] if a["id"] == tamper["auth_vector"])["signing_vector"])
        a, b = bytes.fromhex(base["hex"]), ref.request_bytes(tamper)
        self.assertEqual(len(a), len(b))
        differing = [i for i in range(len(a)) if a[i] != b[i]]
        self.assertEqual(len(differing), 1, "only the command tag byte differs")
        self.assertEqual((a[differing[0]], b[differing[0]]), (2, 4))

    def test_a_revision_of_zero_is_not_the_same_as_none(self):
        d = doc()
        tamper = next(t for t in d["tamper_vectors"] if t["field"] == "expected revision zero versus absent")
        self.assertEqual(tamper["rev"], 0)
        self.assertIsNone(next(v for v in d["signing_vectors"] if v["peer"] == tamper["peer"] and v["cmd"]["kind"] == "stop")["rev"])

    def test_the_presence_tamper_removes_a_revision_from_a_command_that_can_be_built_without_one(self):
        d = doc()
        tamper = next(t for t in d["tamper_vectors"] if t["field"] == "expected revision presence")
        self.assertIsNone(tamper["rev"])
        self.assertNotIn(tamper["cmd"]["kind"], ref.RELATIVE)


class LogVectors(unittest.TestCase):
    """The JSONL diagnostics are produced by the Rust only; these vectors are computed here with
    hashlib and json so that the keyed pseudonyms and the exact bytes of a line are pinned by an
    independent implementation. The Rust replays them (diag.rs)."""

    FIELD_ORDER = ["schema_version", "timestamp_mono_ns", "run_id", "case_id", "correlation_id", "member_id",
                   "group_id", "source_epoch", "state_revision", "event_kind", "message", "queue_depth", "latency_us"]

    def vectors(self):
        return json.loads(genlog.DEFAULT_OUT.read_text(encoding="utf-8"))

    def test_the_file_is_what_the_generator_produces(self):
        self.assertEqual(genlog.main(["--check"]), 0)

    def test_pseudonyms_are_recomputed_keyed_unique_and_well_formed(self):
        v = self.vectors()
        key = bytes.fromhex(v["pseudonym_key_hex"])
        self.assertEqual(len(key), 32)
        seen = set()
        for entry in v["pseudonyms"]:
            ident = entry["id"].encode()
            full = hashlib.sha256(b"ffw.pseudonym.v1" + key + len(ident).to_bytes(8, "big") + ident).hexdigest()
            self.assertEqual(entry["pseudonym"], "p-" + full[:16], entry["id"])
            self.assertRegex(entry["pseudonym"], r"^p-[0-9a-f]{16}$")
            seen.add(entry["pseudonym"])
        self.assertEqual(len(seen), len(v["pseudonyms"]))
        # A different key gives different pseudonyms: they are keyed, not a plain hash of the id.
        other = hashlib.sha256(b"ffw.pseudonym.v1" + bytes(32) + (5).to_bytes(8, "big") + b"ctl-a").hexdigest()
        self.assertNotEqual("p-" + other[:16], next(p["pseudonym"] for p in v["pseudonyms"] if p["id"] == "ctl-a"))

    def test_golden_lines_follow_the_shared_schema_and_carry_no_raw_identifier(self):
        v = self.vectors()
        raw = [p["id"] for p in v["pseudonyms"]]
        self.assertGreaterEqual(len(v["golden_lines"]), 4)
        for g in v["golden_lines"]:
            record = json.loads(g["line"])
            keys = list(record)
            self.assertEqual(keys[: len(self.FIELD_ORDER)], self.FIELD_ORDER, g["id"])
            self.assertIn(keys[len(self.FIELD_ORDER):], ([], ["cause"]), g["id"])
            self.assertEqual(record["schema_version"], "ffw.log.v1")
            self.assertLessEqual(len(g["line"]), 1024)
            self.assertEqual(record["latency_us"], g["fact"]["waited_ns"] // 1000, g["id"])
            self.assertEqual(record["state_revision"], g["fact"]["revision"], g["id"])
            for ident in raw:
                self.assertNotIn(ident, g["line"], f"{g['id']} echoes {ident}")
            self.assertRegex(record["correlation_id"], r"^p-[0-9a-f]{16}#[0-9]+$")
            self.assertRegex(record["group_id"], r"^p-[0-9a-f]{16}$")
            self.assertRegex(record["member_id"], r"^(p-[0-9a-f]{16})?$")
            self.assertEqual(g["line"], json.dumps(record, separators=(",", ":")), "compact, field order kept")

    def test_acknowledgement_lines_follow_the_schema_correlate_and_carry_no_raw_identifier(self):
        v = self.vectors()
        raw = [p["id"] for p in v["pseudonyms"]]
        steps = {json.loads(g["line"])["correlation_id"] for g in v["golden_lines"]}
        self.assertGreaterEqual(len(v["ack_golden_lines"]), 6)
        kinds = set()
        for g in v["ack_golden_lines"]:
            record = json.loads(g["line"])
            keys = list(record)
            self.assertEqual(keys[: len(self.FIELD_ORDER)], self.FIELD_ORDER, g["id"])
            self.assertIn(keys[len(self.FIELD_ORDER):], ([], ["cause"]), g["id"])
            self.assertEqual("cause" in record, g["fact"]["cause"] is not None, g["id"])
            self.assertEqual(record["schema_version"], "ffw.log.v1")
            self.assertRegex(record["event_kind"], r"^n02\.ack\.(on_time|late|superseded|rejected\.[a-z_]+)$")
            self.assertEqual(record["member_id"], "", g["id"])
            self.assertLessEqual(len(g["line"]), 1024)
            self.assertEqual(record["latency_us"], g["fact"]["age_ns"] // 1000, g["id"])
            self.assertEqual(record["state_revision"], g["fact"]["revision"], g["id"])
            self.assertRegex(record["correlation_id"], r"^p-[0-9a-f]{16}#[0-9]+$")
            for ident in raw:
                self.assertNotIn(ident, g["line"], f"{g['id']} echoes {ident}")
            kinds.add(record["event_kind"])
        # An acknowledgement of a command joins that command's own step record by correlation id.
        on_time = next(g for g in v["ack_golden_lines"] if g["id"] == "N02-A001")
        self.assertIn(json.loads(on_time["line"])["correlation_id"], steps)
        self.assertGreaterEqual(len(kinds), 6, "every kind is distinct")

    def test_a_cause_appears_only_where_the_fact_has_one(self):
        for g in self.vectors()["golden_lines"]:
            self.assertEqual("cause" in json.loads(g["line"]), g["fact"]["cause"] is not None, g["id"])


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
        no_scenario = {i["id"] for i in c["invariants"] if i.get("scenario_inapplicable")}
        self.assertEqual(declared - used - no_scenario, set(), "declared invariant has no scenario and no stated reason")
        for inv in c["invariants"]:
            self.assertTrue(inv["claim"] and inv["rust_tests"] and (inv["scenarios"] or inv.get("scenario_inapplicable")), inv["id"])
            if inv.get("scenario_inapplicable"):
                self.assertEqual(inv["scenarios"], [], f"{inv['id']} states that no scenario applies, so it lists none")
            for sid in inv["scenarios"]:
                self.assertIn(sid, scenario_ids, inv["id"])
                self.assertIn(inv["id"], scenario(d, sid)["invariants"], f"{sid} does not list {inv['id']}")
        for s in d["scenarios"]:
            for i in s["invariants"]:
                listed = next(x for x in c["invariants"] if x["id"] == i)["scenarios"]
                self.assertIn(s["id"], listed, f"{i} does not list {s['id']}")

    def test_every_named_rust_test_exists(self):
        source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(CHANNEL_SRC.rglob("*.rs")))
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
