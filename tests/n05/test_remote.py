"""Protocol/judge controls only. Synthetic log text here is never live worker proof."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import remote
import run_cases


class RemoteJudgeControls(unittest.TestCase):
    def test_passing_status_requires_the_named_test(self):
        remote.require_unit("test positive ... ok\n", "positive")
        with self.assertRaises(remote.MissingEvidence):
            remote.require_unit("test repair_study::tests::other ... ok\n", "positive")

    def test_failed_ignored_missing_and_duplicate_status_never_pass(self):
        for status in ("FAILED", "ignored"):
            with self.assertRaises((remote.MissingEvidence, AssertionError)):
                remote.require_unit(f"test positive ... {status}\n", "positive")
        with self.assertRaises(remote.MissingEvidence):
            remote.require_unit("", "positive")
        with self.assertRaises(remote.MissingEvidence):
            remote.require_unit("test positive ... okFAILED\n", "positive")
        with self.assertRaises((AssertionError, remote.MissingEvidence)):
            remote.require_unit("test positive ... ok\ntest positive ... ok\n", "positive")

    def test_truncated_observation_is_an_error(self):
        with self.assertRaises(ValueError):
            remote.extract('N05-OBSERVED {"schema":', "N05-OBSERVED")

    def test_complete_self_report_without_worker_observations_is_blocked(self):
        campaign = remote.common("a" * 64)
        begin = dict(campaign, monotonic_ns=1, case_ids=list(run_cases.CASES))
        end = dict(campaign, monotonic_ns=2, case_ids=list(run_cases.CASES),
                   failed=0, critical_evidence_lost=0, observed_cases=9, observations=37)
        log = "N05-RUN-BEGIN " + json.dumps(begin) + "\nN05-RUN-END " + json.dumps(end) + "\n"
        with self.assertRaises(remote.MissingEvidence):
            remote.read_campaign(log, list(run_cases.CASES), run_cases.CASES)
        for changed in (dict(end, failed=1), dict(end, qualified=True), dict(end, critical_evidence_lost=1)):
            with self.assertRaises(AssertionError):
                remote.read_campaign("N05-RUN-BEGIN " + json.dumps(begin) + "\nN05-RUN-END " + json.dumps(changed), list(run_cases.CASES), run_cases.CASES)

    def test_judge_mode_never_invokes_a_local_rust_worker(self):
        # Sentinel only: this tests a forbidden call, never substitutes for a positive worker.
        with tempfile.TemporaryDirectory(prefix="n05-judge-control-") as directory:
            log = Path(directory) / "empty-central.log"
            log.write_text("running 0 tests\ntest result: ok. 0 passed\n")
            with patch.object(run_cases, "invoke", side_effect=AssertionError("local Rust execution forbidden")) as forbidden:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = run_cases.main(["--judge", str(log)])
                forbidden.assert_not_called()
            receipt = json.loads(output.getvalue())
            self.assertEqual(code, 3)
            self.assertEqual(receipt["expected"], 12)
            self.assertEqual(receipt["blocked"], 12)
            self.assertEqual(receipt["passed"], 0)

    def test_observe_only_cannot_take_qualification_inputs(self):
        for extra in (("--unit-log", "proof.log"), ("--receipts", "receipts")):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                run_cases.main(["--observe-only", "--worker", "unused-worker", *extra])
            self.assertEqual(error.exception.code, 2)

    def test_all_original_positive_and_allocator_names_remain_mandatory(self):
        names = {name for entries in remote.SCENARIO_UNITS.values() for name in entries}
        names.update(name for entries in run_cases.RUST_CASES.values() for name in entries)
        self.assertEqual(names, {
            "n05_same_media_trace_packetization_cutoffs_and_allowance",
            "n05_rfc6330_positive_two_erasure_recovery_and_zero_loss_cost",
            "n05_entire_coding_window_is_unrecoverable_not_a_fec_win",
            "n05_late_and_exhausted_repairs_never_starve_the_next_block",
            "n05_actual_decoded_bytes_rejected_after_consume_before_dac",
            "n05_malformed_metadata_does_not_enter_the_coder",
            "n05_restart_reproduces_trace_without_retaining_cancelled_window",
            "n05_actual_decode_peak_heap_upper_bound_includes_temporary_allocations",
            "n05_invalid_decode_symbols_refuse_before_matrix_allocation",
            "n05_partial_salvage_keeps_the_still_live_block_and_n04_counts_late",
            "n05_inline_overrun_control_exposes_why_work_admission_matters",
            "n05_host_reserve_violation_never_retimes_trace",
            "n05_gate_deadline_and_allowance_boundaries_preserve_permitted_work",
            "n05_render_work_is_protected_through_the_permitted_end_boundary",
            "n05_hybrid_executes_fec_then_a_bounded_tail_for_remaining_originals",
            "n05_hybrid_deadline_work_cancel_and_restart_keep_real_recovery",
            "n05_hybrid_tail_has_a_permitted_path_and_zero_side_effect_refusals",
            "n05_hybrid_tail_uses_only_the_observed_prefix_not_future_deliveries",
            "n05_retransmit_and_hybrid_tail_share_the_same_admission_ledger",
            "n05_hybrid_tail_actual_late_and_duplicate_use_n04_admission",
        })
        self.assertIn(remote.HYBRID_CORE, remote.SCENARIO_UNITS["N05-INDEPENDENT"])
        self.assertIn(remote.HYBRID_PREFIX, remote.SCENARIO_UNITS["N05-INDEPENDENT"])

    def test_causal_and_tail_control_records_require_nonvacuous_native_branches(self):
        # Synthetic protocol anchors exercise the parser only, never native capability.
        prefix = {"schema": "n05.prefix-control.v1", "prefix_symbols": 1, "admitted": 3,
                  "earlier_requests_equal": True, "later_prefixes_differ": True,
                  "wrong_collector_rejected": True}
        remote.check_prefix_control("N05-PREFIX-OBSERVED " + json.dumps(prefix))
        for key, value in (("prefix_symbols", 0), ("admitted", 0), ("wrong_collector_rejected", False)):
            with self.assertRaises(AssertionError):
                remote.check_prefix_control("N05-PREFIX-OBSERVED " + json.dumps(dict(prefix, **{key: value})))
        late = {"schema": "n05.tail-control.v1", "kind": "late", "next_block_real": True,
                "unrecovered_blocks": [4, 5], "accounting": {"admitted": 2, "received": 2,
                "admitted_to_playout": 0, "late": 2, "duplicate": 0}}
        duplicate = {"schema": "n05.tail-control.v1", "kind": "duplicate", "next_block_real": True,
                     "unrecovered_blocks": [19], "accounting": {"received": 32,
                     "admitted_to_playout": 16, "late": 0, "duplicate": 16}}
        def log(records):
            return "\n".join("N05-TAIL-OBSERVED " + json.dumps(item) for item in records)
        remote.check_tail_controls(log([late, duplicate]))
        for records in ([], [late]):
            with self.assertRaises(AssertionError):
                remote.check_tail_controls(log(records))
        empty_branch = copy.deepcopy(duplicate)
        empty_branch["accounting"] = {"received": 0, "admitted_to_playout": 0, "late": 0, "duplicate": 0}
        with self.assertRaises(AssertionError):
            remote.check_tail_controls(log([late, empty_branch]))

    def test_allocator_record_arithmetic_and_nonzero_sensor_controls(self):
        # Hand-derived parser anchor, explicitly not an actual allocator observation.
        row = {"rank_deficit": 0, "status": "recovered", "allocation_calls": 10,
               "deallocation_calls": 9, "cumulative_decode_requested_bytes": 8192,
               "retained_input_heap_bytes": 100, "decode_peak_heap_upper_bound_bytes": 8292}
        patterns = [dict(row, mask=mask, received_symbols=mask.bit_count()) for mask in range(256) if mask.bit_count() >= 4]
        memory = {"schema": "n05.decode-memory.v2", "profile": remote.PROFILE,
                  "seed": remote.SEED, "expected_subsets": 163, "observed_subsets": 163,
                  "recovered_subsets": 163, "rank_deficient_subsets": 0, "patterns": patterns,
                  "decode_peak_heap_upper_bound_bytes": 8292, "limit_bytes": 1024 ** 2}
        self.assertEqual(remote.check_memory("N05-DECODE-MEMORY " + json.dumps(memory)), memory)
        for key, value in (("observed_subsets", 162), ("recovered_subsets", 0),
                           ("decode_peak_heap_upper_bound_bytes", 8291), ("limit_bytes", 1024 ** 3)):
            changed = copy.deepcopy(memory)
            changed[key] = value
            with self.assertRaises(AssertionError):
                remote.check_memory("N05-DECODE-MEMORY " + json.dumps(changed))
        for key in ("allocation_calls", "deallocation_calls"):
            changed = copy.deepcopy(memory)
            changed["patterns"][0][key] = 0
            with self.assertRaises(AssertionError):
                remote.check_memory("N05-DECODE-MEMORY " + json.dumps(changed))

    def test_split_nocapture_result_uses_shared_d01_attribution(self):
        name = "n05_invalid_decode_symbols_refuse_before_matrix_allocation"
        log = ("Running tests/n05_decode_memory.rs (target/debug/deps/n05_decode_memory-0123456789abcdef)\n"
               "running 1 test\n" + f"test {name} ... N05-CONTROL {{}}\nok\n"
               "test result: ok. 1 passed; 0 failed\n")
        remote.require_unit(log, name)

    def test_source_test_registry_has_no_unmapped_named_test(self):
        remote.map_complete(run_cases.RUST_CASES)


if __name__ == "__main__":
    unittest.main()
