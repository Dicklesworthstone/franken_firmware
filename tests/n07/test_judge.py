"""Tests of the N07 model and judge (docs/contracts/n07.md section 5). Nothing here runs Rust, a socket or the network.

Three layers. Anchors: the model's numbers are checked against values derived by hand from the contract (so the model is not
only compared with itself), against the Rust unit tests' hand-written tables and against N01's own SplitMix64. Positives and
planted-bad logs: a log built from the model's own records is judged qualified, and each planted flaw (a missing, failed or
duplicated test, a duplicated or absent observation, a number altered in each family of counters, a broken ledger, a sample
mismatch) is refused for its own reason. Mutation: each rule of the judge is switched off in memory and some planted log must
then get through, on a baseline where none does.
"""
import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
JUDGE_PATH = os.path.join(HERE, "run_cases.py")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rc = load("n07_run_cases", JUDGE_PATH)
model = rc.load_model()
sys.path.insert(0, os.path.join(REPO, "tests", "n01"))
import reference_frames as n01  # noqa: E402

SCENARIOS = {s["id"]: s for s in model.scenarios()}
EXPECTED = {sid: model.expected(s) for sid, s in SCENARIOS.items()}
S1, S2, S3, S4, S5, S6, S7 = ("N07-S1-zero-loss-paced", "N07-S2-slow-peer-isolated", "N07-S3-saturation-control-priority",
                              "N07-S4-epoch-fence", "N07-S5-mtu-admission-address-family", "N07-S6-link-and-address-change",
                              "N07-S7-loss-and-reorder")


def speaker_record(world):
    """A valid record of one speaker world (what the Rust prints, with every counter consistent)."""
    counters = {"media_submitted_packets": 10, "media_submitted_bytes": 11040, "media_sent_packets": 10, "media_sent_bytes": 11040,
                "queue_delay_ns_max": 0, "queue_delay_ns_total": 0}
    counters.update({"media_dropped_%s_%s" % (kind, unit): 0 for kind in rc.DROP_KINDS for unit in ("packets", "bytes")})
    n01 = {"datagrams_seen": 10, "accepted": 10, "mac_verifications": 10}
    n01.update({"rejected_%s" % name: 0 for name in ("structure", "authentication", "replay", "stale_epoch", "wrong_stream")})
    return {"case": world, "seed": 7, "provenance": "simulated_host_loopback", "blocks": 10, "steps": 1000, "fault_schedule": [[3, "drop"]],
            "link_log": ["0:Resume"], "carrier": {}, "port_faults": {}, "largest_datagram_bytes": 1104, "cpu_memory": "not_measured",
            "extra": {}, "rooms": [{"peer": 1, "heard_real": 10, "heard_concealed": 0, "quiet_decisions": 0, "sender_side": counters,
                                    "queued_packets": 0, "queued_bytes": 0, "receiver": {"media_read": 10, "media_accepted": 10},
                                    "sink": {"admitted": 10, "refused": 0, "backpressure": 0}, "n01": n01, "engine": {}, "verdicts": {}}]}


SPEAKER_RECORDS = {world: speaker_record(world) for _, world, _, _ in rc.SPEAKER_WORLDS}


def log_text(observations=None, skip_tests=(), failed=(), extra="", speakers=None):
    """What a green central run would print, built from the model's own records."""
    observations = EXPECTED if observations is None else observations
    lines = ["running tests"]
    for case in rc.CASES:
        for test in case["tests"]:
            if test in skip_tests:
                continue
            lines.append("test %s ... %s" % (test, "FAILED" if test in failed else "ok"))
    lines.append("test result: ok.")
    for record in observations if isinstance(observations, list) else observations.values():
        lines.append("N07-OBSERVED " + json.dumps(record, sort_keys=True))
    for record in (SPEAKER_RECORDS if speakers is None else speakers).values():
        lines.append("N07-OBSERVED " + json.dumps(record, sort_keys=True))
    return "\n".join(lines) + "\n" + extra


def judged(module, text):
    results, _, _ = module.judge(model, [text])
    return results


def failures(results):
    return {cid: why for cid, (status, why) in results.items() if status == "failed"}


def edited(sid, fn):
    records = copy.deepcopy(EXPECTED)
    fn(records[sid])
    return records


class Anchors(unittest.TestCase):
    """Values derived by hand from the contract, not read back from the model."""

    def test_the_first_pump_of_the_zero_loss_world_sends_a_burst_of_seven_and_names_its_deadline(self):
        # burst 8192 B. Control goes first and is charged to the same bucket: 16 + 28 = 44 B, leaving 8148 B. Each datagram costs
        # 1024 + 80 + 28 = 1132 B; 7 * 1132 = 7924 <= 8148 < 8 * 1132. Round robin from peer 1: 1, 2, 1, 2, 1, 2, 1 -> four to
        # peer 1, three to peer 2. 224 B are left; the 8th needs 908 B more at 500,000 B/s: 908 / 500000 s = 1,816,000 ns.
        world = model.World(copy.deepcopy(SCENARIOS[S1]))
        world.apply(SCENARIOS[S1]["ops"][0])   # control
        world.apply(SCENARIOS[S1]["ops"][1])   # 16 blocks
        report = world.pump_and_deliver()
        self.assertEqual((report["control_sent"], report["media_sent"], report["pace_limited"], report["next_send_ns"]),
                         (1, 7, True, 1_816_000))
        sent = {p.id: p.counters["media_sent_packets"] for p in world.sender.peers}
        self.assertEqual(sent, {1: 4, 2: 3})

    def test_control_is_charged_to_both_budgets_however_often_the_pump_is_called(self):
        # Control's share: burst 4 * (512 + 48) = 2240 B, refilled at 1,760,000 / 8 = 220,000 B/s. A scripted control datagram
        # costs 16 + 28 = 44 B, so one instant affords floor(2240 / 44) = 50 of them (50 * 44 = 2200 <= 2240 < 2244), however
        # many times the pump is called: 13 pumps of 4, and then nothing.
        world = model.World({"id": "anchor", "limits": {}, "peers": [{"peer": 1, "mtu": 1500}], "ops": []})
        sender, sent = world.sender, 0
        for _ in range(40):
            for tag in range(8):
                sender.submit_control(1, tag)
            sent += sender.pump(0)["control_sent"]
        self.assertEqual((sent, sender.control_spent), (50, 2200))
        self.assertGreater(sender.control_pace_limited_pumps, 0)
        # the same 2200 B came out of the interface bucket: 8192 - 2200 = 5992 B affords 5 datagrams of 1132 (5660), not 7
        for block in range(8):
            sender.submit_media(1, block, 10_000_000, 0)
        self.assertEqual(sender.pump(0)["media_sent"], 5)
        # 10 ms refills control's share by 2200 B (to its 2240 B cap) and the bucket to 8192 B
        self.assertEqual(sender.pump(10_000_000)["control_sent"], 4)

    def test_a_control_flood_leaves_media_the_rest_of_the_interface(self):
        # 100,000 B/s, one block and four control datagrams per millisecond for 100 ms. Supply: the 8192 B burst plus 99 refills
        # of 100 B = 18,092 B. Control may spend its burst (2240 B) plus 1/8 of the rate over the 99 refills (12.5 B/ms,
        # at most 1250 B): at most 3490 B. Media gets what is left, less one datagram of slack: more than
        # 18,092 - 3490 - 1132 = 13,470 B, so at least 12 datagrams of 1132 B.
        lim = dict(model.BASELINE_LIMITS, pace_bytes_per_sec=100_000, peer_load_bytes_per_sec=100_000, window_packets=256)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        media = 0
        for ms in range(1, 101):
            now = ms * 1_000_000
            sender.submit_media(1, ms, now + 2_000_000_000, now)
            for tag in range(4):
                sender.submit_control(1, tag)
            media += sender.pump(now)["media_sent"]
        self.assertLessEqual(sender.control_spent, 3490)
        self.assertGreaterEqual(media, 12)
        self.assertGreater(media * 1132 + sender.control_spent + 1132, 18_092)

    def test_a_full_window_is_probed_once_per_interval_with_its_newest_datagram_and_a_report_reopens_it(self):
        # window 16, burst 65,536 B: one pump sends 16 blocks (18,112 B) and the window is full at t = 0, so the first probe is
        # due at 250,000,000 ns. A probe is the sixteenth datagram again (number 15, block 15, 1104 B + 28 B of headers): it
        # allocates no number, holds no place, and is counted as a probe and not as media.
        lim = dict(model.BASELINE_LIMITS, pace_burst_bytes=65_536)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        for block in range(20):
            sender.submit_media(1, block, 2_000_000_000, 0)
        self.assertEqual(sender.pump(0)["media_sent"], 16)
        self.assertEqual(sender.pump(249_999_999)["media_sent"], 0)
        self.assertEqual(sender.probes_sent, 0)
        self.assertEqual(sender.pump(250_000_000)["media_sent"], 0, "a probe is not media")
        self.assertEqual((sender.probes_sent, sender.probe_bytes), (1, 1132))
        self.assertEqual(sender.probe_emitted, [(1, 1, 15, 15, 1104)], "the newest datagram, under its own number")
        sender.pump(250_000_001)
        sender.pump(499_999_999)
        self.assertEqual(sender.probes_sent, 1)
        sender.pump(500_000_000)
        self.assertEqual((sender.probes_sent, sender.probe_bytes), (2, 2264))
        peer = sender.peer(1)
        self.assertEqual((peer.sent_next, len(peer.inflight), peer.counters["media_sent_packets"]), (16, 16, 16))
        # a report of 16 (the receiver admitted number 15 from the probe; N01 admits it, it is within 1024 of nothing) covers the window
        self.assertTrue(sender.on_report(1, 16, 0, 1))
        self.assertEqual(len(peer.inflight), 0)
        self.assertEqual(sender.pump(500_000_001)["media_sent"], 4, "the four blocks still queued go at once")
        self.assertEqual(peer.sent_next, 20)

    def test_a_probe_needs_something_waiting_and_something_to_send_again(self):
        lim = dict(model.BASELINE_LIMITS, pace_burst_bytes=65_536)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        for block in range(16):
            sender.submit_media(1, block, 2_000_000_000, 0)
        self.assertEqual(sender.pump(0)["media_sent"], 16)
        # the window is full but nothing is queued behind it: no probe, however long the peer is silent
        sender.pump(250_000_000)
        sender.pump(10_000_000_000)
        self.assertEqual(sender.probes_sent, 0)
        sender.submit_media(1, 16, 20_000_000_000, 10_000_000_000)
        sender.pump(10_000_000_001)
        self.assertEqual(sender.probes_sent, 1, "now a block is waiting for room")

    def test_the_sequence_budget_keeps_every_number_within_the_receivers_reach(self):
        # N01 admits a first packet at most 1024 beyond origin 0 and later ones at most 1024 beyond the highest admitted, and a
        # receiver's highest admitted number is at least `reported - 1`. A sender that allocates only below `reported + 1000` can
        # always be admitted (24 spare). The window is a separate limiter: up to 4096 may be configured, and above 1000 the budget
        # is what holds.
        fresh = model.ReplayWindow(1)
        self.assertEqual((fresh.check(1, 1025), fresh.check(1, 1024)), ("rejected_future_sequence", None))
        later = model.ReplayWindow(1)
        later.check(1, 500)
        self.assertEqual((later.check(1, 500 + 1025), later.check(1, 500 + 1024)), ("rejected_future_sequence", None))
        # the pair the S8 observer rests on, for a warmed world's protected number (reported + 999, say 1029): an origin-0 receiver
        # refuses it, and one that has heard the stream a little before accepts the same number
        cold, warm = model.ReplayWindow(1), model.ReplayWindow(1)
        warm.check(1, 40)
        self.assertEqual((cold.check(1, 1029), warm.check(1, 1029)), ("rejected_future_sequence", None))
        self.assertTrue(model.SEQ_AHEAD_LIMIT < model.MAX_FORWARD_GAP)
        self.assertEqual((model.MAX_WINDOW, model.SEQ_AHEAD_LIMIT, model.MAX_FORWARD_GAP), (4096, 1000, 1024))
        # a peer whose numbers 0..999 are all allocated and unreported may send nothing new; a report lifts it
        sender = model.Sender(dict(model.BASELINE_LIMITS), 1)
        sender.add_peer(1, "ok", 1500)
        peer = sender.peer(1)
        peer.sent_next = peer.next_seq = 1000
        sender.submit_media(1, 0, 2_000_000_000, 0)
        self.assertTrue(peer.sequence_blocked() and peer.waiting(16))
        self.assertEqual(sender.pump(0)["media_sent"], 0)
        self.assertEqual(sender.pump(1_000_000_000)["media_sent"], 0, "no probe: nothing was ever transmitted to send again")
        peer.reported_next = 1
        peer.on_reported(16)
        self.assertFalse(peer.sequence_blocked())
        self.assertEqual(sender.pump(1_000_000_001)["media_sent"], 1)
        self.assertEqual(peer.sent_next, 1001)
        # and the window itself is bounded, at the configured maximum and not at the budget
        model.Sender(dict(model.BASELINE_LIMITS, window_packets=4096), 1)
        with self.assertRaises(AssertionError):
            model.Sender(dict(model.BASELINE_LIMITS, window_packets=4097), 1)

    def test_a_window_larger_than_the_budget_is_supported_and_the_budget_is_what_holds(self):
        lim = dict(model.BASELINE_LIMITS, window_packets=4096, pace_bytes_per_sec=1_000_000_000, pace_burst_bytes=1_000_000)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        now = 0
        for block in range(1_100):
            now += 1_000_000
            sender.submit_media(1, block, now + 2_000_000_000, now)
            sender.pump(now)
        peer = sender.peer(1)
        self.assertEqual((peer.sent_next, len(peer.inflight)), (model.SEQ_AHEAD_LIMIT, model.SEQ_AHEAD_LIMIT))
        self.assertFalse(peer.stalled(4096))
        self.assertTrue(peer.sequence_blocked())
        # a report of everything it sent reopens the budget, and the next block is number 1000
        self.assertTrue(sender.on_report(1, model.SEQ_AHEAD_LIMIT, 0, 1))
        self.assertFalse(peer.sequence_blocked())
        self.assertGreaterEqual(sender.pump(now + 1_000_000)["media_sent"], 1)
        self.assertEqual(sender.emitted[0][2], model.SEQ_AHEAD_LIMIT)

    def test_one_pump_makes_no_more_attempts_than_the_cap_and_a_probe_is_an_attempt(self):
        # Two peers whose windows hold one datagram, one attempt per pump: the first two pumps send one datagram each. At 250 ms
        # both probes are due, and a pump may make only one of them (the v3 model made both: media_sent 0, cap untouched).
        lim = dict(model.BASELINE_LIMITS, window_packets=1, max_sends_per_pump=1, pace_burst_bytes=65_536)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        sender.add_peer(2, "ok", 1500)
        for block in range(4):
            sender.submit_media(1, block, 2_000_000_000, 0)
        self.assertEqual([sender.pump(0)["media_sent"], sender.pump(0)["media_sent"]], [1, 1])
        first = sender.pump(250_000_000)
        self.assertEqual((first["media_sent"], first["send_cap_hit"], sender.probes_sent), (0, True, 1))
        self.assertEqual([e[0] for e in sender.probe_emitted], [1])
        second = sender.pump(250_000_001)
        self.assertEqual((second["send_cap_hit"], sender.probes_sent), (True, 2))
        self.assertEqual([e[0] for e in sender.probe_emitted], [2], "the next pump served the other peer")
        idle = sender.pump(250_000_002)
        self.assertEqual((idle["send_cap_hit"], sender.probes_sent), (False, 2))
        # the permitted positive: a cap of two lets both go in one pump
        lim = dict(lim, max_sends_per_pump=2)
        sender = model.Sender(lim, 1)
        sender.add_peer(1, "ok", 1500)
        sender.add_peer(2, "ok", 1500)
        for block in range(4):
            sender.submit_media(1, block, 2_000_000_000, 0)
        self.assertEqual(sender.pump(0)["media_sent"], 2)
        both = sender.pump(250_000_000)
        self.assertEqual((both["media_sent"], both["send_cap_hit"], sender.probes_sent), (0, True, 2))

    def test_a_scripted_world_that_probes_is_refused_until_it_can_deliver_the_copy(self):
        scenario = {"id": "probe", "limits": {"pace_burst_bytes": 65_536}, "peers": [{"peer": 1, "mtu": 1500}],
                    "ops": [{"op": "consumer", "peer": 1, "active": False},
                            {"op": "submit", "first_block": 0, "blocks": 20, "deadline_ns": 20_000_000_000},
                            {"op": "pump"}, {"op": "advance", "ns": 250_000_000}]}
        world = model.World(scenario)
        for op in scenario["ops"][:3]:
            world.apply(op)
        world.apply(scenario["ops"][3])
        with self.assertRaises(AssertionError):
            world.pump_and_deliver()

    def test_the_overhead_of_a_zero_loss_stream_is_framing_plus_headers(self):
        record = EXPECTED[S1]
        summary = rc.overhead_summary(record)
        self.assertEqual(summary["media_packets_sent"], 32)
        self.assertEqual(summary["wire_overhead_bytes"], 32 * 80)          # 64-byte header + 16-byte tag, per datagram
        self.assertEqual(80 + 28, 108)                                     # plus IPv4 and UDP headers on the link

    def test_a_slow_peer_gets_its_window_then_nothing_old_and_the_others_lose_nothing(self):
        record = EXPECTED[S2]
        slow = record["peers"]["2"]["delivered"]
        self.assertEqual([d[2] for d in slow[:8]], list(range(8)), "the eight packets of its window, in order")
        # Recovery happens at the pump of block 40 (t = 40 blocks). A 30 ms deadline is 5.625 blocks, so blocks 0..34 are late.
        self.assertTrue(all(d[2] >= 35 for d in slow[8:]), "nothing queued before the stall is replayed")
        for pid in ("1", "3"):
            self.assertEqual([d[2] for d in record["peers"][pid]["delivered"]], list(range(60)))
            self.assertEqual(record["peers"][pid]["view"]["counters"]["queue_delay_ns_max"], 0)
        self.assertGreater(record["peers"]["2"]["view"]["counters"]["window_stalled_pumps"], 0)

    def test_control_goes_first_and_the_burst_is_not_charged_for_it(self):
        world = model.World(copy.deepcopy(SCENARIOS[S3]))
        world.apply(SCENARIOS[S3]["ops"][0])   # 40 blocks, all at once
        world.apply(SCENARIOS[S3]["ops"][1])   # one control datagram for peer 3
        pump = world.apply(SCENARIOS[S3]["ops"][2])["pump"]
        self.assertEqual((pump["control_sent"], pump["media_sent"]), (1, 7))
        self.assertEqual(EXPECTED[S3]["peers"]["3"]["control_received"], [9, 10])

    def test_an_epoch_change_drops_exactly_what_was_queued_and_restarts_the_sequence(self):
        record = EXPECTED[S4]
        # 12 blocks queued per peer, the first pump sends 4 to peer 1 and 3 to peer 2; the rest (8, 9) are fenced.
        self.assertEqual(record["peers"]["1"]["view"]["counters"]["media_dropped_fenced_packets"], 8)
        self.assertEqual(record["peers"]["2"]["view"]["counters"]["media_dropped_fenced_packets"], 9)
        self.assertEqual([t["code"] for t in record["trace"] if t["name"] == "stale_submit"], ["STALE_EPOCH"])
        after = [d for d in record["peers"]["2"]["delivered"] if d[0] == 2]
        self.assertEqual(after[0][1], 0, "the sequence restarts at zero in the new epoch")
        self.assertEqual(record["peers"]["2"]["receiver"]["stream"]["rejected_stale_epoch"], 1, "the replayed old-epoch datagram")
        self.assertEqual(record["peers"]["1"]["receiver"]["stream"]["rejected_future_epoch"], 6, "the late receiver refuses epoch 2")
        self.assertGreater(record["stats"]["reports_stale_epoch"], 0)

    def test_admission_refusals_come_in_the_contracts_order_and_a_path_fence_is_one_peers(self):
        record = EXPECTED[S5]
        codes = [t["code"] for t in record["trace"] if t["name"] == "add_peer"]
        self.assertEqual(codes, ["PATH_MTU_TOO_SMALL", "OVER_BUDGET", "NOT_LOOPBACK", "UNSUPPORTED_ADDRESS_FAMILY", "DUPLICATE_PEER"])
        self.assertEqual((record["stats"]["mtu_fences"], record["stats"]["mtu_unfences"], record["stats"]["admissions_rejected"]), (1, 1, 5))
        self.assertEqual(record["peers"]["2"]["view"]["counters"]["media_dropped_fenced_packets"], 12, "the 12 blocks of the fence")
        self.assertEqual(len(record["peers"]["1"]["delivered"]), 36, "the other peer lost nothing")

    def test_a_link_down_ages_audio_out_and_an_address_change_refuses_the_old_path(self):
        record = EXPECTED[S6]
        # Link down for blocks 6..17; at the pump of block 18 a 30 ms deadline (5.625 blocks) leaves 6..12 late: 7 per peer.
        for pid in ("1", "2"):
            self.assertEqual(record["peers"][pid]["view"]["counters"]["media_dropped_late_packets"], 7)
        self.assertEqual((record["stats"]["path_changes"], record["stats"]["reports_unknown_source"]), (1, 1))
        self.assertEqual(record["stats"]["link_down_pumps"], 12)

    def test_loss_and_reorder_leave_the_clean_peer_alone_and_account_for_every_datagram(self):
        record = EXPECTED[S7]
        relay = record["peers"]["1"]["relay"]
        self.assertEqual(relay["lost"] + relay["forwarded"], 60)
        self.assertGreater(relay["reordered"], 0)
        self.assertEqual(len(record["peers"]["1"]["delivered"]), relay["forwarded"])
        self.assertEqual([d[2] for d in record["peers"]["2"]["delivered"]], list(range(60)))

    def test_the_models_random_numbers_are_the_repositorys_splitmix64(self):
        for seed in (0, 7, 0x4E3031):
            a, b = model.SplitMix64(seed), n01.SplitMix64(seed)
            self.assertEqual([a.next() for _ in range(10)], [b.next() for _ in range(10)])

    def test_the_sizing_table_and_baseline_agree_with_the_rust(self):
        results = dict((cid, (ok, why)) for cid, ok, why in rc.meta(model))
        for cid in ("META-SCENARIOS", "META-TESTS", "META-COUNTERS", "META-DEFAULTS", "META-SIZING", "META-E04", "META-CONTRACT"):
            self.assertTrue(results[cid][0], (cid, results[cid][1]))

    def test_every_scenario_balances_its_books_and_matches_the_sample_oracle(self):
        for sid, record in EXPECTED.items():
            self.assertIsNone(rc.accounting(record), sid)


class Positives(unittest.TestCase):
    def test_a_log_built_from_the_models_records_qualifies_every_case(self):
        results = judged(rc, log_text())
        self.assertEqual(failures(results), {})
        self.assertEqual(len(results), len(rc.CASES))

    def test_the_command_line_exits_0_on_a_good_log_1_on_a_bad_one_and_3_on_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad, receipts = (os.path.join(tmp, n) for n in ("good.log", "bad.log", "receipts"))
            with open(good, "w", encoding="utf-8") as handle:
                handle.write(log_text())
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write(log_text(failed=(rc.CASES[0]["tests"][0],)))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(rc.main(["--judge", good, "--revision", "abc123", "--receipts", receipts]), 0)
                self.assertEqual(rc.main(["--judge", bad]), 1)
                self.assertEqual(rc.main([]), 3)
            with open(os.path.join(receipts, "receipt.json"), encoding="utf-8") as handle:
                receipt = json.load(handle)
            self.assertEqual((receipt["schema"], receipt["revision"], receipt["first_failure"]), (rc.RECEIPT_SCHEMA, "abc123", None))
            s7 = next(c for c in receipt["cases"] if c["id"] == "N07-E07")
            self.assertEqual(s7["observed"]["seeds"], [7])
            self.assertEqual(len(receipt["log_sha256"][0]), 64)
            self.assertIn("dropped_late_bytes", next(c for c in receipt["cases"] if c["id"] == "N07-E06")["observed"])


def alter(sid, path, value):
    def fn(record):
        node = record
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return edited(sid, fn)


def log_plants():
    """(label, log text, case id that must fail, required substring)."""
    first_unit, loopback = rc.UNIT_TESTS[0], rc.CASES[7]["tests"][0]
    e = EXPECTED
    dup = copy.deepcopy(e)
    two = [e[S2], e[S2]] + [r for sid, r in e.items() if sid != S2]
    return [
        ("a unit test missing from the log", log_text(skip_tests=(first_unit,)), "N07-U01", "is not in the log"),
        ("an e2e test missing from the log", log_text(skip_tests=(loopback,)), "N07-E08", "is not in the log"),
        ("a test that failed", log_text(failed=(rc.CASES[2]["tests"][0],)), "N07-E03", "reported FAILED"),
        ("a unit test that failed", log_text(failed=(first_unit,)), "N07-U01", "reported FAILED"),
        ("an observation that is missing", log_text({k: v for k, v in e.items() if k != S4}), "N07-E04", "0 N07-OBSERVED"),
        ("an observation printed twice", log_text(two), "N07-E02", "2 N07-OBSERVED"),
        ("a truncated log", "\n".join(log_text().splitlines()[:6]), "N07-E08", "is not in the log"),
        ("sent packets that are one too many", log_text(alter(S1, ["peers", "1", "view", "counters", "media_sent_packets"], 17)), "N07-E01", "media_sent_packets"),
        ("a dropped-late byte count that is wrong", log_text(alter(S6, ["peers", "2", "view", "counters", "media_dropped_late_bytes"], 0)), "N07-E06", "media_dropped_late_bytes"),
        ("a delivered block out of order", log_text(edited(S7, lambda r: r["peers"]["2"]["delivered"].reverse())), "N07-E07", "delivered"),
        ("a slow peer given an old block", log_text(alter(S2, ["peers", "2", "delivered", 9], [1, 99, 12])), "N07-E02", "delivered"),
        ("a control datagram that never arrived", log_text(alter(S3, ["peers", "3", "control_received"], [9])), "N07-E03", "control_received"),
        ("an admission code that is wrong", log_text(edited(S5, lambda r: r["trace"][0].update(code="OK"))), "N07-E05", "trace"),
        ("an epoch fence that dropped nothing", log_text(alter(S4, ["peers", "1", "view", "counters", "media_dropped_fenced_packets"], 0)), "N07-E04", "media_dropped_fenced_packets"),
        ("a carrier statistic that is wrong", log_text(alter(S6, ["stats", "reports_unknown_source"], 0)), "N07-E06", "reports_unknown_source"),
        ("the end time that is wrong", log_text(alter(S1, ["final_now_ns"], 1)), "N07-E01", "final_now_ns"),
        ("a receiver counter that is wrong", log_text(alter(S4, ["peers", "2", "receiver", "stream", "rejected_stale_epoch"], 0)), "N07-E04", "rejected_stale_epoch"),
        ("a relay that lost nothing", log_text(alter(S7, ["peers", "1", "relay", "lost"], 0)), "N07-E07", "relay"),
        ("a peer that is missing from the record", log_text(edited(S2, lambda r: r["peers"].pop("3"))), "N07-E02", "peers"),
        ("an extra key in the record", log_text(edited(S1, lambda r: r.update(extra=1))), "N07-E01", "extra"),
        ("a number that is a float", log_text(alter(S1, ["final_now_ns"], float(EXPECTED[S1]["final_now_ns"]))), "N07-E01", "final_now_ns"),
    ]


LOG_PLANTS = log_plants()


def accounting_plants():
    """(label, record, required substring) for the checks that need no model."""
    def e(sid, fn):
        return edited(sid, fn)[sid]

    def counters(r):
        return r["peers"]["1"]["view"]["counters"]

    def twice(r):
        peer = r["peers"]["1"]
        peer["delivered"].append(list(peer["delivered"][0]))
        peer["samples_checked"] += 1      # a duplicate the oracle also matched, so only the duplicate is wrong

    return [
        ("a ledger that is short a packet", e(S1, lambda r: counters(r).update(media_submitted_packets=counters(r)["media_submitted_packets"] + 1)), "submitted packets"),
        ("a ledger that is short a byte", e(S1, lambda r: counters(r).update(media_submitted_bytes=counters(r)["media_submitted_bytes"] + 1)), "submitted bytes"),
        ("a sample mismatch", e(S1, lambda r: r["peers"]["1"].update(sample_mismatches=1)), "sample oracle"),
        ("fewer samples checked than delivered", e(S1, lambda r: r["peers"]["1"].update(samples_checked=1)), "sample oracle"),
        ("a receiver that lost a datagram", e(S1, lambda r: r["peers"]["1"]["receiver"]["stream"].update(accepted=r["peers"]["1"]["receiver"]["stream"]["accepted"] - 1)), "account for every datagram"),
        ("a receiver that read more than it saw", e(S1, lambda r: r["peers"]["1"]["receiver"]["stats"].update(media_read=99)), "account for every datagram"),
        ("a packet delivered twice", e(S1, twice), "delivered twice"),
    ]


ACCOUNTING_PLANTS = accounting_plants()


class Negatives(unittest.TestCase):
    def test_each_planted_log_is_refused_for_its_own_reason(self):
        for label, text, case, needle in LOG_PLANTS:
            with self.subTest(label):
                found = failures(judged(rc, text))
                self.assertIn(case, found, label)
                self.assertIn(needle, found[case], "%s: %r" % (label, found[case]))

    def test_each_planted_log_leaves_the_untouched_cases_qualified(self):
        for label, text, case, _ in LOG_PLANTS:
            if label in ("a truncated log",):
                continue
            with self.subTest(label):
                self.assertEqual(set(failures(judged(rc, text))), {case}, label)

    def test_each_broken_ledger_or_oracle_is_refused_by_the_accounting_alone(self):
        for label, record, needle in ACCOUNTING_PLANTS:
            with self.subTest(label):
                why = rc.accounting(record)
                self.assertIsNotNone(why, label)
                self.assertIn(needle, why)

    def test_there_are_enough_planted_cases_each_with_its_own_label(self):
        labels = [p[0] for p in LOG_PLANTS] + [p[0] for p in ACCOUNTING_PLANTS]
        self.assertGreaterEqual(len(labels), 27)
        self.assertEqual(len(set(labels)), len(labels))


class Mutations(unittest.TestCase):
    """Switch off one rule of the judge in memory; some planted log or record must then get through. The baseline is green."""

    MUTANTS = [
        ("a failed test is a failure", 'elif verdict != "ok":', "elif False:"),
        ("exactly one observation", "if len(records) != 1:", "if False:"),
        ("the observation is compared with the model", 'why = first_difference("", record, want) or accounting(record)', "why = accounting(record)"),
        ("the books are balanced", 'return "peer %s: submitted packets are not sent + dropped + queued" % pid', "pass"),
        ("the byte books are balanced", 'return "peer %s: submitted bytes are not sent + dropped + queued" % pid', "pass"),
        ("samples must match the oracle", "if peer[\"sample_mismatches\"] != 0 or peer[\"samples_checked\"] != len(peer[\"delivered\"]):", "if False:"),
        ("the receiver accounts for every datagram", "if rx[\"datagrams_seen\"] != rs[\"media_read\"] or", "if False and"),
        ("no packet is delivered twice", "if len({(d[0], d[1]) for d in peer[\"delivered\"]}) != len(peer[\"delivered\"]):", "if False:"),
        ("types matter in the comparison", "return None if got == want and type(got) is type(want) else", "return None if got == want else"),
        ("a missing key is a difference", 'return "%s/%s: missing from the observed record" % (path, key)', "continue"),
        ("an extra key is a difference", 'return "%s/%s: not in the expected record" % (path, extra[0]) if extra else None', "return None"),
        ("list lengths are compared", "if len(want) != len(got):", "if False:"),
    ]

    @staticmethod
    def mutated(old, new):
        with open(JUDGE_PATH, encoding="utf-8") as handle:
            source = handle.read()
        if source.count(old) != 1:
            raise AssertionError("the mutant anchor occurs %d times: %r" % (source.count(old), old[:70]))
        namespace = {"__name__": "n07_mutant", "__file__": JUDGE_PATH}
        exec(compile(source.replace(old, new), "mutant.py", "exec"), namespace)  # noqa: S102 - a planted mutant, run in memory
        return types.SimpleNamespace(**namespace)

    @staticmethod
    def undetected(module):
        missed = []
        for label, text, case, needle in LOG_PLANTS:
            try:
                found = failures(judged(module, text)).get(case)
                ok = found is not None and needle in found
            except Exception:  # noqa: BLE001 - a mutated judge may fail in any way
                ok = False
            if not ok:
                missed.append(label)
        for label, record, needle in ACCOUNTING_PLANTS:
            try:
                why = module.accounting(record)
                ok = why is not None and needle in why
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                missed.append(label)
        return missed

    def test_the_baseline_judge_misses_nothing(self):
        self.assertEqual(self.undetected(rc), [])

    def test_each_rule_switched_off_lets_something_through(self):
        self.assertGreaterEqual(len(self.MUTANTS), 12)
        for label, old, new in self.MUTANTS:
            with self.subTest(label):
                self.assertNotEqual(self.undetected(self.mutated(old, new)), [], label)


def speakers_with(world, fn):
    records = copy.deepcopy(SPEAKER_RECORDS)
    fn(records[world])
    return records


class SpeakerWorlds(unittest.TestCase):
    """The speaker's end-to-end worlds are judged on their own terms: a record that says what it is, with its books balanced."""
    CASE = {world: cid for cid, world, _, _ in rc.SPEAKER_WORLDS}

    def judged_failure(self, world, fn):
        return failures(judged(rc, log_text(speakers=speakers_with(world, fn)))).get(self.CASE[world])

    def test_a_consistent_record_for_every_world_qualifies(self):
        self.assertEqual(failures(judged(rc, log_text())), {})

    def test_each_inconsistency_is_refused_for_its_own_reason(self):
        def edit(path, value):
            def fn(record):
                node = record
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
            return fn
        plants = [
            ("not labelled host-only", edit(["provenance"], "kernel"), "host-only"),
            ("claims a cpu figure", edit(["cpu_memory"], "3 percent"), "CPU or memory"),
            ("packets do not balance", edit(["rooms", 0, "sender_side", "media_sent_packets"], 11), "submitted packets"),
            ("bytes do not balance", edit(["rooms", 0, "sender_side", "media_dropped_late_bytes"], 5), "submitted bytes"),
            ("the sink lost a datagram", edit(["rooms", 0, "sink", "admitted"], 9), "sink did not account"),
            ("accepted differs from admitted", edit(["rooms", 0, "receiver", "media_accepted"], 9), "accepted media"),
            ("n01 does not account", edit(["rooms", 0, "n01", "datagrams_seen"], 11), "N01 receiver did not account"),
            ("n01 saw a different number", edit(["rooms", 0, "n01", "rejected_replay"], 1), "N01 receiver did not account"),
            ("no rooms", edit(["rooms"], []), "no rooms"),
            ("a field is missing", lambda record: record.pop("seed"), "lacks"),
        ]
        for label, fn, needle in plants:
            with self.subTest(label):
                why = self.judged_failure("S4", fn)
                self.assertIsNotNone(why, label)
                self.assertIn(needle, why)

    def test_a_missing_or_duplicated_record_or_test_is_refused(self):
        records = copy.deepcopy(SPEAKER_RECORDS)
        del records["S2"]
        self.assertIn("0 N07-OBSERVED", failures(judged(rc, log_text(speakers=records)))["N07-E12"])
        text = log_text() + "N07-OBSERVED " + json.dumps(SPEAKER_RECORDS["S3"], sort_keys=True) + "\n"
        self.assertIn("2 N07-OBSERVED", failures(judged(rc, text))["N07-E13"])
        test = rc.P + "n07_s7_seeded_loss_and_reorder_are_concealed_and_every_sample_matches_the_oracle"
        self.assertIn("not in the log", failures(judged(rc, log_text(skip_tests=(test,))))["N07-E18"])
        self.assertIn("FAILED", failures(judged(rc, log_text(failed=(test,))))["N07-E18"].upper())

    def test_the_receipt_names_the_seed_the_fault_schedule_and_the_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "good.log")
            with open(good, "w", encoding="utf-8") as handle:
                handle.write(log_text())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(rc.main(["--judge", good, "--revision", "r1", "--receipts", tmp]), 0)
            with open(os.path.join(tmp, "receipt.json"), encoding="utf-8") as handle:
                receipt = json.load(handle)
            seven = next(c for c in receipt["cases"] if c["id"] == "N07-E18")["observed"]
            self.assertEqual((seven["seed"], seven["fault_schedule"], seven["provenance"]), (7, [[3, "drop"]], "simulated_host_loopback"))
            self.assertIn("dropped_late_bytes", seven)

    def test_switching_the_ledger_rule_off_lets_the_broken_books_through(self):
        broken = speakers_with("S1", lambda r: r["rooms"][0]["sender_side"].update(media_sent_packets=11))
        self.assertIn("N07-E11", failures(judged(rc, log_text(speakers=broken))))
        original = rc.speaker_accounting
        try:
            rc.speaker_accounting = lambda record: None
            self.assertEqual(failures(judged(rc, log_text(speakers=broken))), {})
        finally:
            rc.speaker_accounting = original


if __name__ == "__main__":
    unittest.main()
