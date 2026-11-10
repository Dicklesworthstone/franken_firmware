#!/usr/bin/env python3
"""N06-specific adapter over the existing D01/N05 Cargo-log parser; never builds."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from reference import PROFILE, check_replays, check_fleet, check_relock

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
# Concrete integration gaps named by root: these remain full acceptance blockers.
# No invented Rust test, disabled requirement, or refusal-only qualification.
PENDING = {
    "N06-CARRIER": "peer format selection/negotiation and N07 typed selected-format ingress are not integrated/qualified",
    "N06-PACED-SENDER": "CarrierSender still encodes N01; paced authenticated FEC transmission is not implemented/qualified",
}


def source_registry():
    actual = set()
    for relative in ("crates/franken-stream/src/fec/tests.rs", "crates/franken-speaker/src/media_playout.rs", "toolchain/n06-fec-profile/src/lib.rs"):
        actual.update(re.findall(r"fn\s+(n06_[A-Za-z0-9_]+)\s*\(", (ROOT / relative).read_text()))
    mapped = {name.rsplit("::", 1)[-1] for tests in CASES.values() for _, name in tests}
    assert actual == mapped, "missing/stale N06 native test consumer"


def records(log, prefix):
    return shared.extract(log, prefix)


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
