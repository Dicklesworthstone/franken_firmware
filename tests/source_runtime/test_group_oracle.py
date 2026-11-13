"""Planted controls for the group capture oracle; no speaker binary is run."""
import json
import copy
import struct
import tempfile
import unittest
from pathlib import Path

from run_group import compare_group, require_peer_drained, sender_views
from run_loopback import OracleError, track_spec


class GroupOracleTests(unittest.TestCase):
    def test_final_peer_credit_is_required_before_early_group_end_permission(self):
        blocks = (600 + 255) // 256
        counts = {"reports_accepted": 2, "media_submitted_packets": blocks, "media_sent_packets": blocks,
                  "media_dropped_overflow_packets": 0, "media_dropped_aggregate_packets": 0,
                  "media_dropped_late_packets": 0, "media_dropped_fenced_packets": 0,
                  "media_dropped_send_error_packets": 0}
        event = {"event": "peer_drained", "peer_id": 1, "published_frames": 600,
                 "anchor_ns": 1_000_000_000,
                 "peer": {"peer": 1, "fence": None, "queued_packets": 0, "queued_bytes": 0,
                          "in_flight": 0, "sent_next": blocks, "reported_next": blocks, "counters": counts}}
        require_peer_drained(event, 1, 600, 1_000_000_000)
        lost_last = copy.deepcopy(event)
        lost_last["peer"].update(in_flight=1, reported_next=blocks - 1)
        # Earlier valid reports are still present: that cannot authorize END.
        with self.assertRaisesRegex(OracleError, "unacknowledged final media"):
            require_peer_drained(lost_last, 1, 600, 1_000_000_000)
        for field, bad in (("queued_packets", 1), ("queued_bytes", 1), ("reported_next", blocks + 1),
                           ("fence", "mtu"), ("peer", 2)):
            broken = copy.deepcopy(event)
            broken["peer"][field] = bad
            with self.subTest(field=field), self.assertRaises(OracleError):
                require_peer_drained(broken, 1, 600, 1_000_000_000)
        for field, bad in (("media_sent_packets", blocks - 1), ("reports_accepted", 0),
                           ("media_dropped_late_packets", 1)):
            broken = copy.deepcopy(event)
            broken["peer"]["counters"][field] = bad
            with self.subTest(field=field), self.assertRaises(OracleError):
                require_peer_drained(broken, 1, 600, 1_000_000_000)
        require_peer_drained(event, 1, 600, 1_000_000_000)

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="ffw-group-oracle-"))
        self.track = track_spec("vorbis_48000")
        self.anchor = 1_000_000_000
        reference = self.track["_reference_bytes"]
        wire = b"".join(struct.pack(">h", value) for (value,) in struct.iter_unpack("<h", reference))
        self.records = []
        for start in range(0, self.track["expected_frames"], 256):
            frames = min(256, self.track["expected_frames"] - start)
            self.records.append({"start_frame": start, "frames": frames,
                                 "presentation_ns": self.anchor + start * 1_000_000_000 // 48000,
                                 "pcm_be16_hex": wire[start * 4:(start + frames) * 4].hex()})
        self.paths = {i: self.directory / f"member-{i}.jsonl" for i in (1, 2, 3)}
        for path in self.paths.values():
            self.write(path, self.records)

    @staticmethod
    def write(path, records):
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records))

    def compare(self):
        return compare_group(self.paths, (1, 2, 3), self.track, self.anchor)

    def test_three_full_reference_captures_pass(self):
        result = self.compare()
        self.assertEqual(set(result), {"1", "2", "3"})
        self.assertTrue(all(row["frames"] == 24000 and row["peak_lsb"] == 0
                            for row in result.values()))

    def test_missing_member_and_aliased_capture_fail(self):
        with self.assertRaises(OracleError):
            compare_group({1: self.paths[1], 2: self.paths[2]}, (1, 2, 3), self.track, self.anchor)
        with self.assertRaises(OracleError):
            compare_group({1: self.paths[1], 2: self.paths[1], 3: self.paths[3]},
                          (1, 2, 3), self.track, self.anchor)

    def test_missing_tail_and_shifted_time_fail(self):
        for mutation in ("tail", "time"):
            with self.subTest(mutation=mutation):
                records = [dict(row) for row in self.records]
                if mutation == "tail":
                    records.pop()
                else:
                    records[1]["presentation_ns"] += 1
                self.write(self.paths[2], records)
                with self.assertRaises(OracleError):
                    self.compare()
                self.write(self.paths[2], self.records)

    def test_even_in_tolerance_member_sample_difference_is_not_equal(self):
        records = [dict(row) for row in self.records]
        block = bytearray.fromhex(records[0]["pcm_be16_hex"])
        sample = struct.unpack_from(">h", block)[0]
        struct.pack_into(">h", block, 0, sample + (1 if sample < 32767 else -1))
        records[0]["pcm_be16_hex"] = block.hex()
        self.write(self.paths[2], records)
        with self.assertRaisesRegex(OracleError, "receiver captures differ"):
            self.compare()

    def test_sender_diagnostics_require_every_distinct_active_peer(self):
        def view(peer):
            return {"peer": peer, "counters": {"media_sent_packets": 1, "reports_accepted": 1}}
        summary = {"published_frames": 24000, "anchor_ns": self.anchor,
                   "peers": [view(1), view(2), view(3)]}
        self.assertEqual(set(sender_views(summary, (1, 2, 3), 24000, self.anchor)), {1, 2, 3})
        for views in ([view(1), view(2)], [view(1), view(2), view(2)],
                      [view(1), view(2), {"peer": 3, "counters": {"media_sent_packets": 0,
                                                                     "reports_accepted": 0}}]):
            with self.subTest(views=views), self.assertRaises(OracleError):
                sender_views({**summary, "peers": views}, (1, 2, 3), 24000, self.anchor)


if __name__ == "__main__":
    unittest.main()
