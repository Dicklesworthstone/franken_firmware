"""Parser/oracle controls. Synthetic anchors here are never native receipts."""
import contextlib
import copy
import io
import json
import unittest

import reference
import run_cases


class Controls(unittest.TestCase):
    def test_independent_pcm_and_signed_q15_hand_anchors(self):
        self.assertEqual(reference.pcm(0)[:4], bytes([181, 192, 203, 214]))
        self.assertEqual(reference.pcm(3)[:2], bytes([41, 52]))
        self.assertEqual(reference.attenuate(reference.pcm(3), 1)[:2], bytes([0x1c, 0xd8]))
        for mode, losses in (("baseline", [4, 5, 12, 13]), ("hybrid", []), ("overload", [4, 5])):
            self.assertEqual([row["block"] for row in reference.expected(mode) if row["outcome"] != "real"], losses)

    def test_owned_source_registry_and_pending_integration_are_explicit(self):
        run_cases.source_registry()
        self.assertEqual(len({name for rows in run_cases.CASES.values() for _, name in rows}), 33)
        self.assertEqual(set(run_cases.PENDING), {"N06-CARRIER", "N06-PACED-SENDER"})

    def test_missing_native_never_shrinks_denominator_or_qualifies(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = run_cases.main([])
        summary = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(result, 3)
        self.assertEqual((summary["expected"], summary["passed"], summary["blocked"]), (13, 0, 13))
        self.assertFalse(summary["qualified"])

    def test_soak_is_not_run(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run_cases.main(["--tier", "soak"]), 4)

    def test_fleet_and_relock_oracles_reject_missing_members_wrong_pcm_and_reset_origin(self):
        # Synthetic parser controls only; no record here can qualify native code.
        import hashlib
        fleet = {"schema": "n06.fleet.v1", "profile": reference.PROFILE, "group_members": 6,
                 "fleet_cap": 21, "checks": 6, "check_limit": 7,
                 "request_masks": [1, 1, 1, 1, 8, 8], "reply_esis": [0, 3],
                 "charged_work": 69584, "output": [
                     {"member": member, "block": block, "outcome": "real", "pcm_sha256": hashlib.sha256(reference.pcm(block)).hexdigest()}
                     for member in range(6) for block in range(4)]}
        reference.check_fleet(fleet)
        for mutate in (lambda row: row["output"].pop(),
                       lambda row: row["output"][0].update(pcm_sha256="00" * 32),
                       lambda row: row.update(checks=1),
                       lambda row: row.update(charged_work=8192)):
            broken = copy.deepcopy(fleet)
            mutate(broken)
            with self.assertRaises(AssertionError):
                reference.check_fleet(broken)
        relock = {"schema": "n06.relock.v1", "profile": reference.PROFILE, "epoch": 1,
                  "origin_before": 100550000000, "origin_after": 100550000000, "healthy_origin": 100550000000,
                  "window": 32, "anchor_frame": 32768, "joined_cursor": 130, "healthy_cursor": 130,
                  "output": []}
        for slot in range(2):
            probe = hashlib.sha256(b"FFWR-N06-v1-source" + bytes(64) + bytes([91 + slot]) * 4096).hexdigest()
            for member in ("healthy", "relocked"):
                relock["output"].append({"member": member, "block": 128 + slot, "outcome": "real", "pcm_probe_sha256": probe})
        reference.check_relock(relock)
        relock["origin_after"] += 1
        with self.assertRaises(AssertionError):
            reference.check_relock(relock)

    def test_replay_protocol_has_positive_sensor_and_rejects_real_output_corruption(self):
        # Hand-populated protocol input exercises oracle checks only. Neither
        # this fabricated record nor a passing Python test enters native proof.
        rows = []
        for mode, recovered in (("baseline", 0), ("hybrid", 4), ("overload", 2)):
            rows.append({"schema": "n06.replay.v1", "profile": reference.PROFILE, "mode": mode,
                         "source_epoch": 1, "seed": reference.SEED, "frames": 256, "blocks": 32,
                         "evidence_class": "offline-host-synthetic", "production_fec_profile_admitted": False,
                         "channel_trace_sha256": reference.trace_digest(), "output": reference.expected(mode),
                         "injected_other_work_units": 1 if mode == "overload" else 0,
                         "lost_feedback": int(mode == "overload"), "status": {"production_fec_profile_admitted": False,
                         "chosen_strategy": "hybrid", "retained_windows": 8, "authenticated_symbols": 60,
                         "counters": {"diagnostics_dropped": 0, "work_refused": int(mode == "overload"),
                         "recovered": recovered, "decode_attempts": 0, "decode_work": 0}}})
        reference.check_replays(rows)
        bad = copy.deepcopy(rows)
        bad[1]["output"][0]["pcm_sha256"] = "00" * 32
        with self.assertRaisesRegex(AssertionError, "PCM divergence"):
            reference.check_replays(bad)
        with self.assertRaises(AssertionError):
            reference.check_replays(rows[:-1])

    def test_missing_critical_observations_and_truncation_are_not_green(self):
        for case_id in ("N06-REPLAY", "N06-REFERENCE", "N06-CONSUMER", "N06-DEADLINE", "N06-TAIL"):
            with self.assertRaises(run_cases.shared.MissingEvidence):
                run_cases.evidence(case_id, "")
        with self.assertRaises(ValueError):
            run_cases.records('N06-REPLAY {"schema":', "N06-REPLAY")


if __name__ == "__main__":
    unittest.main()
