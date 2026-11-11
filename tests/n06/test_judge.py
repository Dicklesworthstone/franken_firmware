"""Parser/oracle controls. Synthetic anchors here are never native receipts."""
import contextlib
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch

import reference
import run_cases
from test_future_observation import row as future_row
from test_ready_observation import row as ready_row


def ready_rows():
    return {
        *(("N06-CONSUMER", "franken_control", "channel::fec_negotiation::tests::" + name) for name in run_cases.READY_CONTROL_TESTS),
        *(("N06-CONSUMER", "franken_control", "channel::owner::tests::" + name) for name in run_cases.READY_OWNER_TESTS),
        *(("N06-CONSUMER", "franken_control", "channel::peer::tests::" + name) for name in run_cases.READY_PEER_TESTS),
        *(("N06-CONSUMER", "franken_stream", "tests::" + name) for name in run_cases.READY_STREAM_TESTS),
        *(("N06-CONSUMER", "franken_speaker", run_cases.SPEAKER + name) for name in run_cases.READY_SPEAKER_TESTS),
        *(("N06-CONSUMER", "n06_control_proof_heap", name) for name in run_cases.READY_HEAP_TESTS),
    }


def ready_names():
    return {name for _, _, name in ready_rows()}


class Controls(unittest.TestCase):
    def test_independent_pcm_and_signed_q15_hand_anchors(self):
        self.assertEqual(reference.pcm(0)[:4], bytes([181, 192, 203, 214]))
        self.assertEqual(reference.pcm(3)[:2], bytes([41, 52]))
        self.assertEqual(reference.attenuate(reference.pcm(3), 1)[:2], bytes([0x1c, 0xd8]))
        for mode, losses in (("baseline", [4, 5, 12, 13]), ("hybrid", []), ("overload", [4, 5])):
            self.assertEqual([row["block"] for row in reference.expected(mode) if row["outcome"] != "real"], losses)

    def test_owned_source_registry_and_pending_integration_are_explicit(self):
        run_cases.source_registry()
        all_names = {name for rows in run_cases.CASES.values() for _, name in rows}
        self.assertEqual(len(all_names), 89 + 7 + 1 + 1 + 1 + 4 + 3)
        self.assertEqual(set(run_cases.PENDING), {"N06-CARRIER", "N06-PACED-SENDER"})

    def test_new_native_requirements_preserve_all_82_original_case_mappings(self):
        added = {
            *(('N06-CONSUMER', 'franken_control', 'channel::fec_negotiation::tests::' + name)
              for name in run_cases.VERIFIED_PROPOSAL_TESTS),
            *(('N06-CONSUMER', 'franken_control', 'channel::owner::tests::' + name)
              for name in run_cases.OWNER_PROPOSAL_TESTS),
            *(('N06-CONSUMER', 'franken_speaker', run_cases.SPEAKER + name)
              for name in run_cases.FUTURE_TESTS),
        }
        self.assertEqual((len(run_cases.VERIFIED_PROPOSAL_TESTS),
                          len(run_cases.OWNER_PROPOSAL_TESTS), len(run_cases.FUTURE_TESTS)), (2, 1, 4))
        rows = [(case, stem, name) for case, tests in run_cases.CASES.items() for stem, name in tests]
        self.assertEqual(len(rows), len(set(rows)))
        self.assertTrue(added.issubset(rows))
        original = sorted(set(rows) - added - ready_rows())
        self.assertEqual(len(original), 82)
        digest = hashlib.sha256(json.dumps(original, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(digest, '83199f12253a471e90d7b847038fc3374d4c50d882952b2e31f6cea97b3eb23f')
        with patch.dict(run_cases.CASES, {"N06-AUTH": run_cases.CASES["N06-AUTH"][1:]}):
            with self.assertRaisesRegex(AssertionError, "missing/stale"):
                run_cases.source_registry()

    def test_durable_owner_names_are_required_by_existing_consumer_case(self):
        required = {(stem, name) for stem, name in run_cases.CASES["N06-CONSUMER"]
                    if stem == "franken_control" and name.rsplit("::", 1)[-1] in run_cases.OWNER_TESTS}
        self.assertEqual(required, {
            ("franken_control", "channel::owner::tests::" + name)
            for name in run_cases.OWNER_TESTS
        })
        self.assertEqual(len(required), 9)
        # The added native checks cannot displace the existing 65 requirements.
        all_names = {name for rows in run_cases.CASES.values() for _, name in rows}
        preflight = {run_cases.SPEAKER + name for name in run_cases.PREFLIGHT_TESTS}
        new = ({"channel::fec_negotiation::tests::" + name for name in run_cases.VERIFIED_PROPOSAL_TESTS}
               | {"channel::owner::tests::" + name for name in run_cases.OWNER_PROPOSAL_TESTS}
               | {run_cases.SPEAKER + name for name in run_cases.FUTURE_TESTS})
        self.assertEqual(len(all_names - {name for _, name in required} - preflight - new - ready_names()), 65)

    def test_preflight_names_extend_without_displacing_existing_native_requirements(self):
        preflight = {("franken_speaker", run_cases.SPEAKER + name)
                     for name in run_cases.PREFLIGHT_TESTS}
        self.assertEqual(len(preflight), 8)
        self.assertTrue(preflight.issubset(set(run_cases.CASES["N06-CONSUMER"])))
        all_names = {name for rows in run_cases.CASES.values() for _, name in rows}
        new = ({"channel::fec_negotiation::tests::" + name for name in run_cases.VERIFIED_PROPOSAL_TESTS}
               | {"channel::owner::tests::" + name for name in run_cases.OWNER_PROPOSAL_TESTS}
               | {run_cases.SPEAKER + name for name in run_cases.FUTURE_TESTS})
        self.assertEqual(len(all_names - {name for _, name in preflight} - new - ready_names()), 74)

    def test_ready_preserves_89_existing_mappings_and_all_actual_names(self):
        rows = [(case, stem, name) for case, tests in run_cases.CASES.items() for stem, name in tests]
        self.assertEqual(len(rows), len(set(rows)))
        added = ready_rows()
        self.assertEqual(len(added), 7 + 1 + 1 + 1 + 4 + 3)
        self.assertTrue(added.issubset(rows))
        original = sorted(set(rows) - added)
        self.assertEqual(len(original), 89)
        digest = hashlib.sha256(json.dumps(original, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(digest, 'af41d9663f4b8cc176dd39cd98638a34ffef0de5460433568dd8c413e8d3d183')

    def test_rev4_extends_all_104_prior_case_mappings(self):
        added = {
            ("N06-CONSUMER", "franken_control", "channel::fec_negotiation::tests::n06_trusted_ingress_expiry_rollback_and_rate_limited_rollback_latch"),
            ("N06-CONSUMER", "franken_control", "channel::owner::tests::fleet_owner_trusted_time_on_ordinary_control_fences_existing_prepare"),
        }
        rows = [(case, stem, name) for case, tests in run_cases.CASES.items() for stem, name in tests]
        self.assertEqual(len(rows), len(set(rows)))
        self.assertTrue(added.issubset(rows))
        original = sorted(set(rows) - added)
        self.assertEqual(len(original), 104)
        digest = hashlib.sha256(json.dumps(original, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        self.assertEqual(digest, 'b203ffe13b41d2ecce0dfb2c547fc8e80794933e61b88b40ea7ade9d77cb03c3')

    def test_ready_heap_markers_accept_only_bounded_real_sensor_shape(self):
        heap = {"schema": "n06.ready-proof-heap.v1", "iterations": 512, "verified": 512,
                "allocations": 0, "reallocations": 0, "deallocations": 0, "bytes_requested": 0}
        sensor = {"schema": "n06.ready-proof-sensor.v1", "allocations": 1, "bytes_requested": 10}
        run_cases.check_ready_heap(heap, sensor)
        for field, value in (("verified", 511), ("allocations", 1), ("reallocations", 1),
                             ("deallocations", 1), ("bytes_requested", 1), ("iterations", True)):
            bad = dict(heap, **{field: value})
            with self.subTest(field=field), self.assertRaises(AssertionError):
                run_cases.check_ready_heap(bad, sensor)
        for field, value in (("allocations", 0), ("bytes_requested", 0), ("allocations", True)):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                run_cases.check_ready_heap(heap, dict(sensor, **{field: value}))
        for bad in (dict(heap, extra=1), {k: v for k, v in heap.items() if k != "verified"}):
            with self.assertRaises(AssertionError):
                run_cases.check_ready_heap(bad, sensor)

    def test_consumer_requires_one_valid_future_observation(self):
        consumer = {"profile": reference.PROFILE, "authentication_once": True, "typed_sequence": 7,
                    "cursor": 1, "status": {"counters": {"recovered": 2},
                                             "production_fec_profile_admitted": False}}
        fresh = {"schema": "n06.fresh-clock.v1", "profile": reference.PROFILE,
                 "faulted": True, "recovered": 0, "repairs_seen": 0, "queued": 2, "clock_faults": 1}
        heap = {"schema": "n06.ready-proof-heap.v1", "iterations": 512, "verified": 512,
                "allocations": 0, "reallocations": 0, "deallocations": 0, "bytes_requested": 0}
        sensor = {"schema": "n06.ready-proof-sensor.v1", "allocations": 1, "bytes_requested": 10}
        observations = {"N06-CONSUMER": [consumer], "N06-RELOCK": [{}],
                        "N06-FRESH-CLOCK": [fresh], "N06-FUTURE": [future_row()],
                        "N06-READY": [ready_row()], "N06-READY-PROOF-HEAP": [heap],
                        "N06-READY-PROOF-SENSOR": [sensor]}
        def synthetic_log():
            return "\n".join(tag + " " + json.dumps(row) for tag, rows in observations.items() for row in rows)

        with patch.object(run_cases, "check_relock"):
            run_cases.evidence("N06-CONSUMER", synthetic_log())
            observations["N06-FUTURE"] = []
            with self.assertRaises(run_cases.shared.MissingEvidence):
                run_cases.evidence("N06-CONSUMER", synthetic_log())
            observations["N06-FUTURE"] = [future_row(), future_row()]
            with self.assertRaises(AssertionError):
                run_cases.evidence("N06-CONSUMER", synthetic_log())
            broken = future_row()
            broken["recovered"] = 0
            observations["N06-FUTURE"] = [broken]
            with self.assertRaises(AssertionError):
                run_cases.evidence("N06-CONSUMER", synthetic_log())
            with self.assertRaises(ValueError):
                run_cases.evidence("N06-CONSUMER", synthetic_log() + '\nN06-FUTURE {"schema":')
            observations["N06-FUTURE"] = [future_row()]
            for tag in ("N06-READY", "N06-READY-PROOF-HEAP", "N06-READY-PROOF-SENSOR"):
                valid = observations[tag][0]
                observations[tag] = []
                with self.subTest(missing=tag), self.assertRaises(run_cases.shared.MissingEvidence):
                    run_cases.evidence("N06-CONSUMER", synthetic_log())
                observations[tag] = [valid, valid]
                with self.subTest(duplicate=tag), self.assertRaises(AssertionError):
                    run_cases.evidence("N06-CONSUMER", synthetic_log())
                observations[tag] = [valid]
                with self.subTest(malformed=tag), self.assertRaises(ValueError):
                    run_cases.evidence("N06-CONSUMER", synthetic_log() + '\n' + tag + ' {"schema":')
            bad = ready_row()
            bad["ready_assertions"] = 1
            observations["N06-READY"] = [bad]
            with self.assertRaises(AssertionError):
                run_cases.evidence("N06-CONSUMER", synthetic_log())

    def test_missing_native_never_shrinks_denominator_or_qualifies(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = run_cases.main([])
        summary = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(result, 3)
        self.assertEqual((summary["expected"], summary["passed"], summary["blocked"]), (13, 0, 13))
        self.assertFalse(summary["qualified"])

    def test_new_native_requirement_missing_ignored_or_failed_cannot_qualify(self):
        target = "channel::fec_negotiation::tests::" + run_cases.VERIFIED_PROPOSAL_TESTS[0]
        for status, failed, blocked in ((None, 0, 3), ("ignored", 0, 3),
                                        ("AMBIGUOUS", 0, 3), ("FAILED", 1, 2)):
            class SyntheticTests:
                def test_status(self, stem, name):
                    return status if (stem, name) == ("franken_control", target) else "ok"

            output = io.StringIO()
            with self.subTest(status=status), patch.object(run_cases.shared, "parsed_tests", return_value=SyntheticTests()), \
                 patch.object(run_cases, "evidence"), contextlib.redirect_stdout(output):
                result = run_cases.main([])
            summary = json.loads(output.getvalue().splitlines()[-1])
            self.assertEqual((summary["expected"], summary["failed"], summary["blocked"]), (13, failed, blocked))
            self.assertEqual(result, 1 if failed else 3)
            self.assertFalse(summary["qualified"])

    def test_each_ready_native_requirement_is_required(self):
        # Synthetic statuses exercise the gate only; they never represent native proof.
        for _, target_stem, target_name in ready_rows():
            for status in (None, "ignored", "AMBIGUOUS", "FAILED"):
                class SyntheticTests:
                    def test_status(self, stem, name):
                        return status if (stem, name) == (target_stem, target_name) else "ok"

                output = io.StringIO()
                with self.subTest(name=target_name, status=status), \
                     patch.object(run_cases.shared, "parsed_tests", return_value=SyntheticTests()), \
                     patch.object(run_cases, "evidence"), contextlib.redirect_stdout(output):
                    result = run_cases.main([])
                summary = json.loads(output.getvalue().splitlines()[-1])
                self.assertEqual(summary["expected"], 13)
                self.assertEqual(summary["failed"], int(status == "FAILED"))
                self.assertEqual(summary["blocked"], 2 if status == "FAILED" else 3)
                self.assertEqual(result, 1 if status == "FAILED" else 3)
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
