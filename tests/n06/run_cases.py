#!/usr/bin/env python3
"""N06-specific adapter over the existing D01/N05 Cargo-log parser; never builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from reference import PROFILE, check_replays, check_fleet, check_relock, check_future, check_ready

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/n05"))
import remote as shared  # Existing bounded log reader and D01 attribution, not N05 qualification.

CORE = "fec::tests::"
SPEAKER = "media_playout::tests::"
CASES = {
    "N06-AUTH": [("franken_stream", CORE + "n06_shape_identity_epoch_and_symbol_fuzz_are_bounded_before_state_commit"), ("franken_stream", CORE + "n06_authenticated_future_bounds_and_zero_budget_cancel_are_paired_with_positive_paths"), ("franken_stream", CORE + "n06_stored_source_retries_after_horizon_and_old_alias_cannot_evict_newer")],
    "N06-CORRUPTION": [("franken_stream", CORE + "n06_corrupt_authenticated_equations_and_source_digest_never_publish_recovery")],
    "N06-OVERLOAD": [("franken_stream", CORE + "n06_conservative_work_refusal_and_render_protection_keep_following_real")],
    "N06-STORM": [("franken_stream", CORE + "n06_duplicate_and_packet_storm_caps_leave_fixed_state_and_later_recovery"), ("franken_stream", CORE + "n06_distinct_forgery_work_exhaustion_and_targeted_pair_denial_have_live_recovery")],
    "N06-CANCEL": [("franken_stream", CORE + "n06_cancel_releases_reservation_and_next_window_and_restart_really_recover"), ("franken_stream", CORE + "n06_earliest_window_failed_transition_and_idle_cancel_preserve_recovery")],
    "N06-DEADLINE": [("franken_stream", CORE + "n06_inflight_expiry_cannot_publish_over_committed_concealment"), ("franken_stream", CORE + "n06_render_end_preserves_late_before_dac_and_still_live_positive_recovery"), ("franken_stream", CORE + "n06_protected_retry_overdue_render_and_typed_credit_have_real_boundaries")],
    "N06-RESTART": [("franken_stream", CORE + "n06_stop_and_control_epoch_transition_release_and_rebind_real_recovery"), ("franken_stream", CORE + "n06_pre_roll_rebind_retains_sources_and_complete_credit_identity_changes_with_origin")],
    "N06-TAIL": [("franken_stream", CORE + "n06_no_information_hybrid_tail_really_recovers_and_is_one_attempt"), ("franken_stream", CORE + "n06_authenticated_feedback_corruption_deadline_and_storm_cannot_amplify"), ("franken_stream", CORE + "n06_two_receivers_different_losses_share_bounded_broadcast_tail")],
    "N06-REFERENCE": [("n06_fec_profile", "tests::n06_generator_and_every_gf_product_match_actual_pinned_asup"), ("n06_fec_profile", "tests::n06_all163_subsets_match_actual_asup_and_independent_raptorq"), ("n06_fec_profile", "tests::n06_real_ingress_scalar_decode_and_cancel_allocate_no_packet_heap")],
    "N06-CONSUMER": [("franken_stream", CORE + "n06_authenticated_recovery_reaches_the_real_n04_consumer_once"), ("franken_speaker", SPEAKER + "n06_media_consumer_selects_budgeted_fec_and_returns_authenticated_typed_sequence"), ("franken_speaker", SPEAKER + "n06_media_baseline_remains_n01_and_unselected_fec_cannot_change_it"), ("franken_speaker", SPEAKER + "n06_media_clock_fault_mute_relock_and_readmission_resume_real_recovery")],
    "N06-REPLAY": [("franken_stream", CORE + "n06_replay_baseline_hybrid_and_decode_overload_use_independent_pcm_observations")],
}
CASES["N06-TAIL"].append(("franken_stream", CORE + "n06_six_member_feedback_is_fair_at_the_fleet_cap_and_one_broadcast_is_final"))
CASES["N06-RESTART"].extend([
    ("franken_stream", CORE + "n06_rebind_preserves_pair_quota_until_next_interval"),
    ("franken_stream", CORE + "n06_epoch_transition_preserves_work_cap_and_next_interval_recovers"),
    ("franken_stream", CORE + "n06_epoch_new_leader_clock_rebases_work_without_refund_or_stranding"),
    ("franken_stream", CORE + "n06_rebase_cannot_refund_work_spent_in_the_same_aligned_interval"),
    ("franken_stream", CORE + "n06_rebase_accounts_for_publication_in_the_fresh_clock_interval"),
])
CASES["N06-CONSUMER"].extend([
    ("franken_speaker", SPEAKER + "n06_media_relock_catches_up_absolute_window_without_restarting_the_healthy_group"),
    ("franken_speaker", SPEAKER + "n06_media_ready_second_platform_read_fault_retires_without_publication"),
])
# Existing typed carrier ingress and real feedback transport tests. These are
# native test names, not a substitute for the independent observations below.
SPEAKER_CARRIER = "net_carrier::fec_tests::"
SENDER_CARRIER = "carrier::fec_tests::"
CASES["N06-CONSUMER"].extend(("franken_speaker", SPEAKER_CARRIER + name) for name in (
    "n06_carrier_credits_selected_n06_at_authenticated_sequences_and_decodes_to_exact_pcm",
    "n06_carrier_credit_is_bounded_by_the_fec_receivers_authenticated_window_range",
    "n06_carrier_render_protection_leaves_datagrams_in_the_port_and_credits_them_next_poll",
    "n06_carrier_protection_that_begins_between_the_check_and_the_offer_drops_one_as_backpressure",
    "n06_carrier_a_media_epoch_the_carrier_does_not_report_earns_no_credit",
    "n06_carrier_a_moved_fec_origin_restarts_credit_and_a_refused_start_changes_nothing",
    "n06_carrier_baseline_asks_no_clock_for_readiness_and_credits_the_authenticated_n01_sequence",
    "n06_carrier_reads_the_datagram_length_the_sink_declares_and_no_more",
    "n06_carrier_a_start_admitted_behind_the_endpoint_restarts_credit_at_the_next_poll",
    "n06_carrier_credit_is_refused_unless_stream_epoch_origin_and_format_all_match",
    "n06_carrier_bind_stream_swaps_streams_and_ends_a_selected_fec_session",
    "n06_carrier_restart_stream_swaps_media_and_carrier_together_and_credit_restarts_from_zero",
))
CASES["N06-TAIL"].extend(("franken_speaker", SPEAKER_CARRIER + "feedback::" + name) for name in (
    "n06_endpoint_feedback_reaches_real_tail_and_prepares_missing_pcm",
    "n06_endpoint_actual_paced_sender_feedback_roundtrip_recovers_missing_pcm",
    "n06_endpoint_feedback_retries_same_bytes_without_regenerating_or_busy_spinning",
))
CASES["N06-DEADLINE"].extend(("franken_speaker", SPEAKER_CARRIER + "feedback::" + name) for name in (
    "n06_endpoint_feedback_expires_before_a_tail_could_reach_its_cutoff",
    "n06_endpoint_feedback_clock_fault_cannot_release_a_retained_request",
    "n06_endpoint_feedback_one_shot_readiness_clock_error_is_not_swallowed",
    "n06_endpoint_ingress_readiness_clock_fault_keeps_wire_until_relock",
    "n06_endpoint_feedback_retry_waits_out_the_protected_render_interval",
))
CASES["N06-RESTART"].extend(("franken_speaker", SPEAKER_CARRIER + "feedback::" + name) for name in (
    "n06_endpoint_feedback_cancel_and_new_stream_retire_pending_authority",
    "n06_endpoint_feedback_origin_change_retires_old_bytes_and_can_send_new_window",
    "n06_endpoint_feedback_combined_poll_cancel_retires_queued_transport",
))
CASES["N06-TAIL"].extend(("franken_stream", SENDER_CARRIER + name) for name in (
    "n06_paced_sender_lost_source_feedback_and_actual_pcm",
    "n06_retired_feedback_cannot_displace_live_window_recovery",
    "n06_feedback_send_checks_receiver_identity_and_transport_fault",
))
CASES["N06-DEADLINE"].append(("franken_stream", SENDER_CARRIER + "n06_paced_sender_admission_clock_deadline_and_cancel_are_bounded"))
CASES["N06-DEADLINE"].append(("franken_stream", SENDER_CARRIER + "n06_paced_parity_after_first_cutoff_recovers_later_live_pcm"))
CASES["N06-STORM"].append(("franken_stream", SENDER_CARRIER + "n06_pacer_attempt_limit_retry_and_backward_clock_fence"))
CASES["N06-RESTART"].append(("franken_stream", SENDER_CARRIER + "n06_rebind_clears_fec_authority_and_old_queued_symbols"))
CASES["N06-CONSUMER"].extend(("franken_speaker", SPEAKER_CARRIER + "selection::" + name) for name in (
    "n06_sender_selection_consumes_encoded_all_member_agreement_and_preserves_n01_on_refusal",
    "n06_sender_selection_revalidates_revocation_and_stream_binding_before_mutation",
))
OWNER_TESTS = (
    "fleet_owner_restores_33_credentials_and_requires_21_real_signed_member_acks",
    "fleet_owner_revoke_and_rebind_survive_boot_without_resurrection",
    "fleet_owner_new_round_cannot_refill_endpoint_fec_work_budget",
    "fleet_owner_reserves_marks_before_unrelated_capacity_is_consumed",
    "fleet_owner_rejects_corrupt_peer_state_and_exhausted_proposal_ids",
    "fleet_owner_refuses_existing_counterless_media_instead_of_reusing_round_ids",
    "fleet_owner_g03_commit_retry_and_restart_use_the_same_durable_authority",
    "fleet_owner_legacy_identity_cannot_bypass_durable_control_through_raw_wire",
    "fleet_owner_failed_proposal_persistence_preserves_local_silence",
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::owner::tests::" + name) for name in OWNER_TESTS
)
PREFLIGHT_TESTS = (
    "n06_preflight_capacity_binding_and_abort_preserve_real_n01_audio",
    "n06_preflight_aba_refuses_then_commits_and_recovers_authenticated_pcm",
    "n06_preflight_progress_epoch_and_cross_owner_invalidate_without_effect",
    "n06_preflight_rechecks_budget_and_same_timeline_rebind",
    "n06_preflight_generation_exhaustion_refuses_without_wrap",
    "n06_reenable_reuses_retained_receiver_at_exact_budget_and_recovers_pcm",
    "n06_endpoint_preflight_rejects_carrier_aba_and_preserves_n01_credit",
    "n06_endpoint_prepared_commit_delivers_recovered_pcm_over_loopback",
)
CASES["N06-CONSUMER"].extend(
    ("franken_speaker", SPEAKER + name) for name in PREFLIGHT_TESTS
)
VERIFIED_PROPOSAL_TESTS = (
    "n06_verified_proposal_requires_authenticated_ingress_but_not_member_acks",
    "n06_verified_proposal_rejects_stale_session_round_profile_and_peer",
)
OWNER_PROPOSAL_TESTS = (
    "fleet_owner_verified_proposal_context_requires_real_ingress_and_current_round",
)
FUTURE_TESTS = (
    "n06_future_candidate_prefetches_real_pcm_while_old_n01_drains",
    "n06_future_candidate_rejects_stale_binding_budget_and_unauthorized_proposal",
    "n06_future_candidate_epoch_and_generation_exhaustion_fail_closed",
    "n06_future_endpoint_prefetch_keeps_old_credit_and_rejects_restart",
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::fec_negotiation::tests::" + name)
    for name in VERIFIED_PROPOSAL_TESTS
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::owner::tests::" + name) for name in OWNER_PROPOSAL_TESTS
)
CASES["N06-CONSUMER"].extend(
    ("franken_speaker", SPEAKER + name) for name in FUTURE_TESTS
)
READY_CONTROL_TESTS = (
    "n06_prepare_ready_uses_authenticated_endpoint_and_rejects_stale",
    "n06_prepare_rejects_wrong_target_timeline_key_and_rate_limit",
    "n06_two_members_prepare_distinct_streams_and_keys_in_one_round",
    "n06_authenticated_retries_preserve_binding_deadline_and_admit_other_member",
    "n06_prepare_time_observations_latch_expiry_and_in_range_rollback",
    "n06_prepare_maximum_labels_fit_bounded_nonallocating_encoders",
    "n06_trusted_ingress_expiry_rollback_and_rate_limited_rollback_latch",
)
READY_OWNER_TESTS = ("fleet_owner_trusted_time_on_ordinary_control_fences_existing_prepare",)
READY_PEER_TESTS = ("fixed_request_proof_uses_real_current_directory_and_exact_handle",)
READY_STREAM_TESTS = ("n06_prepare_key_commitment_binds_key_and_context",)
READY_SPEAKER_TESTS = (
    "n06_future_owner_key_revoke_and_identical_reinstall_stales_candidate_preserves_audio",
    "n06_ready_two_authenticated_targets_keep_old_pcm_and_reject_cross_binding",
    "n06_ready_reinstall_and_target_role_change_refuse_emission",
    "n06_ready_second_clock_read_expiry_clears_output_after_old_real_pcm",
)
READY_HEAP_TESTS = (
    "n06_fixed_proof_valid_sign_verify_allocate_no_heap",
    "n06_fixed_proof_refusals_and_legacy_unknown_preserve_no_heap",
    "n06_fixed_proof_allocator_sensor_observes_real_legacy_auth",
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::fec_negotiation::tests::" + name) for name in READY_CONTROL_TESTS
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::owner::tests::" + name) for name in READY_OWNER_TESTS
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::peer::tests::" + name) for name in READY_PEER_TESTS
)
CASES["N06-CONSUMER"].extend(("franken_stream", "tests::" + name) for name in READY_STREAM_TESTS)
CASES["N06-CONSUMER"].extend(("franken_speaker", SPEAKER + name) for name in READY_SPEAKER_TESTS)
CASES["N06-CONSUMER"].extend(("n06_control_proof_heap", name) for name in READY_HEAP_TESTS)
TYPED_CLOCK_OWNER_TESTS = (
    "fleet_owner_typed_future_clock_accepts_real_admitted_prepare_and_ready",
    "fleet_owner_typed_clock_rejects_wrong_unlocked_expired_and_fences_round",
    "fleet_owner_typed_clock_first_prepare_checks_the_authenticated_start",
)
TYPED_CLOCK_FEC_TESTS = (
    "n06_first_typed_prepare_mismatch_leaves_round_and_clock_unmodified",
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::owner::tests::" + name) for name in TYPED_CLOCK_OWNER_TESTS
)
CASES["N06-CONSUMER"].extend(
    ("franken_control", "channel::fec_negotiation::tests::" + name) for name in TYPED_CLOCK_FEC_TESTS
)
# Concrete integration gaps named by root: these remain full acceptance blockers.
# No invented Rust test, disabled requirement, or refusal-only qualification.
PENDING = {
    "N06-CARRIER": "typed ingress exists; authenticated peer selection and end-to-end carrier qualification remain pending",
    "N06-PACED-SENDER": "paced FEC sender candidate exists; combined native and original acceptance qualification remain pending",
}


def source_registry():
    actual = set()
    for relative in ("crates/franken-stream/src/fec/tests.rs", "crates/franken-speaker/src/media_playout.rs", "toolchain/n06-fec-profile/src/lib.rs", "crates/franken-stream/src/carrier/fec_tests.rs", "crates/franken-speaker/src/net_carrier/fec_tests.rs", "crates/franken-speaker/src/net_carrier/fec_tests/feedback.rs", "crates/franken-speaker/src/net_carrier/fec_tests/selection.rs", "crates/franken-control/src/channel/fec_negotiation.rs", "crates/franken-stream/src/lib.rs", "crates/franken-alloc-probe/tests/n06_control_proof_heap.rs"):
        actual.update(re.findall(r"fn\s+(n06_[A-Za-z0-9_]+)\s*\(", (ROOT / relative).read_text()))
    actual.update(re.findall(
        r"fn\s+(fleet_owner_[A-Za-z0-9_]+)\s*\(",
        (ROOT / "crates/franken-control/src/channel/owner.rs").read_text(),
    ))
    actual.update(re.findall(
        r"fn\s+(fixed_request_proof_uses_real_current_directory_and_exact_handle)\s*\(",
        (ROOT / "crates/franken-control/src/channel/peer.rs").read_text(),
    ))
    mapped = {name.rsplit("::", 1)[-1] for tests in CASES.values() for _, name in tests}
    assert actual == mapped, "missing/stale N06 native test consumer"


def records(log, prefix):
    return shared.extract(log, prefix)


def check_ready_heap(heap, sensor):
    heap_fields = {"schema", "iterations", "verified", "allocations", "reallocations", "deallocations", "bytes_requested"}
    sensor_fields = {"schema", "allocations", "bytes_requested"}
    assert type(heap) is dict and set(heap) == heap_fields, "READY heap schema differs"
    assert type(sensor) is dict and set(sensor) == sensor_fields, "READY sensor schema differs"
    assert heap["schema"] == "n06.ready-proof-heap.v1" and sensor["schema"] == "n06.ready-proof-sensor.v1"
    for row in (heap, sensor):
        for key, value in row.items():
            if key != "schema":
                assert type(value) is int and 0 <= value < 2**64, "invalid READY heap integer"
    assert heap["iterations"] == heap["verified"] == 512
    assert all(heap[key] == 0 for key in ("allocations", "reallocations", "deallocations", "bytes_requested"))
    assert sensor["allocations"] > 0 and sensor["bytes_requested"] > 0, "READY allocator sensor inactive"


def evidence(case_id, log):
    if case_id == "N06-REPLAY":
        found = records(log, "N06-REPLAY")
        if not found:
            raise shared.MissingEvidence("native replay observations missing")
        check_replays(found)
    elif case_id == "N06-REFERENCE":
        generator, subsets, allocation = (records(log, tag) for tag in ("N06-GENERATOR", "N06-SUBSETS", "N06-ALLOCATION"))
        if not generator or not subsets or not allocation:
            raise shared.MissingEvidence("actual generator/subset/allocator observation missing")
        assert len(generator) == len(subsets) == len(allocation) == 1
        g, s, a = generator[0], subsets[0], allocation[0]
        assert all(item["profile"] == PROFILE for item in (g, s, a))
        assert g["gf_products"] == 65536 and g["basis_encodes"] == 4
        assert s["expected"] == s["observed"] == s["recovered"] == 163 and 0 < s["maximum_work"] + s["includes_publication_reserve"] <= s["limit_work"] == 120000
        assert a["sensor_calls"] > 0 and a["sensor_bytes"] >= 1024
        assert a["packet_allocation_calls"] == a["packet_requested_bytes"] == 0 and a["recovered"] == 2 and a["fixed_receiver_bytes"] > 65536
    elif case_id == "N06-CONSUMER":
        found = records(log, "N06-CONSUMER")
        if not found:
            raise shared.MissingEvidence("real selected media-consumer observation missing")
        assert len(found) == 1
        row = found[0]
        assert row["profile"] == PROFILE and row["authentication_once"] is True and row["typed_sequence"] == 7 and row["cursor"] == 1
        assert row["status"]["counters"]["recovered"] == 2 and row["status"]["production_fec_profile_admitted"] is False
        relock = records(log, "N06-RELOCK")
        fresh = records(log, "N06-FRESH-CLOCK")
        if not relock or not fresh:
            raise shared.MissingEvidence("absolute-window relock or actual second-read fault observation missing")
        assert len(relock) == len(fresh) == 1
        check_relock(relock[0])
        fault = fresh[0]
        assert fault["schema"] == "n06.fresh-clock.v1" and fault["profile"] == PROFILE and fault["faulted"] is True
        assert fault["recovered"] == fault["repairs_seen"] == 0 and fault["queued"] == 2 and fault["clock_faults"] == 1
        future = records(log, "N06-FUTURE")
        if not future:
            raise shared.MissingEvidence("actual future candidate observation missing")
        assert len(future) == 1, "duplicate future candidate observation"
        check_future(future[0])
        ready = records(log, "N06-READY")
        heap = records(log, "N06-READY-PROOF-HEAP")
        sensor = records(log, "N06-READY-PROOF-SENSOR")
        if not ready or not heap or not sensor:
            raise shared.MissingEvidence("actual READY or proof allocation observation missing")
        assert len(ready) == len(heap) == len(sensor) == 1, "duplicate READY observation"
        check_ready(ready[0])
        check_ready_heap(heap[0], sensor[0])
    elif case_id == "N06-TAIL":
        fleet = records(log, "N06-FLEET")
        if not fleet:
            raise shared.MissingEvidence("actual six-member differing-loss feedback observation missing")
        assert len(fleet) == 1
        check_fleet(fleet[0])
    elif case_id == "N06-DEADLINE":
        found = records(log, "N06-LATE")
        if not found:
            raise shared.MissingEvidence("actual expired/live N04 publication observation missing")
        assert len(found) == 1
        row = found[0]
        assert row["profile"] == PROFILE and row["consume_by_ns"] < row["completed_ns"] < row["presentation_ns"]
        assert row["late"] == row["recovered"] == 1 and row["cursor"] == 3


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier", choices=("smoke", "full", "soak"), default="full")
    parser.add_argument("--judge", action="append", type=Path, default=[])
    parser.add_argument("--receipts", type=Path)
    args = parser.parse_args(argv)
    if args.tier == "soak":
        print(json.dumps({"passed": 0, "not_run": "N06 soak not executed"}))
        return 4
    selected = list(CASES) + list(PENDING) if args.tier == "full" else ["N06-AUTH", "N06-CONSUMER", "N06-DEADLINE"]
    passed = failed = blocked = 0
    try:
        source_registry()
        log = "\n".join(shared.read_log(path) for path in args.judge)
        tests = shared.parsed_tests(log)
    except (AssertionError, OSError, ValueError) as error:
        print(json.dumps({"expected": len(selected), "passed": 0, "failed": len(selected), "blocked": 0, "reason": shared.redact(str(error))[:512]}))
        return 1
    diagnostics = []
    for case_id in selected:
        state, cause = "passed", None
        try:
            if case_id in PENDING:
                raise shared.MissingEvidence(PENDING[case_id])
            for stem, name in CASES[case_id]:
                status = tests.test_status(stem, name)
                if status in (None, "ignored", "AMBIGUOUS"):
                    raise shared.MissingEvidence(f"native test missing/ignored/ambiguous: {name}")
                assert status == "ok", f"native test failed: {name}"
            assert "test result: FAILED" not in log, "central batch failed"
            evidence(case_id, log)
            passed += 1
        except shared.MissingEvidence as error:
            blocked += 1
            state, cause = "blocked", shared.redact(str(error))
        except (AssertionError, ValueError, TypeError, KeyError) as error:
            failed += 1
            state, cause = "failed", shared.redact(str(error))
        diagnostics.append({"schema": "n06.diagnostics.v1", "case_id": case_id, "correlation_id": case_id, "source_epoch": 1, "state": state, "first_causal_event": cause, "monotonic_ns": time.monotonic_ns(), "profile": PROFILE})
        print(f"{case_id}: {state}" + (f" ({cause[:512]})" if cause else ""))
    summary = {"schema": "n06.receipt.v1", "profile": PROFILE, "tier": args.tier, "expected": len(selected), "passed": passed, "failed": failed, "blocked": blocked, "not_run": 0, "diagnostics_dropped": 0, "evidence_class": "offline-host-synthetic", "production_fec_profile_admitted": False, "qualified": passed == len(selected) and args.tier == "full", "log_sha256": hashlib.sha256(log.encode()).hexdigest()}
    if args.receipts:
        try:
            args.receipts.mkdir(parents=True, exist_ok=True)
            artifact = json.dumps({"summary": summary, "cases": diagnostics}, sort_keys=True).encode()
            assert len(artifact) <= 128 * 1024
            (args.receipts / f"n06-{time.time_ns()}.json").write_bytes(artifact)
        except (AssertionError, OSError) as error:
            print(f"critical N06 evidence unavailable: {type(error).__name__}")
            return 1
    print(json.dumps(summary, sort_keys=True))
    return 1 if failed else (3 if blocked else 0)


if __name__ == "__main__":
    raise SystemExit(main())
