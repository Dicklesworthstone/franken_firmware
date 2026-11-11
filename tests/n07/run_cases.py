#!/usr/bin/env python3
"""N07 (ffw-ybr) end-to-end judge: holds the centrally run carrier tests to an independent model.

    run_cases.py [--list] [--judge LOG [LOG ...]] [--revision REV] [--receipts DIR]

Offline, standard library only; it builds and runs nothing. The Rust runs only through the centralized RCH path:

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-stream --lib carrier -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-stream --test n07_carrier -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy -p franken-stream --all-targets -- -D warnings

* META  - the scenario file equals a fresh generation from model.py; every Rust ``n07_`` test is mapped to a case and every
          mapped test exists; the Rust defaults and counter lists equal the model's; the contract names every case.
* JUDGE - reads the ``cargo test`` output. Every mapped test must report ``ok``, and every ``N07-OBSERVED`` record (one per
          scripted world, printed by the Rust over real loopback sockets) is compared with the record the model derives from
          the script, key for key, and checked on its own terms: per peer, submitted = sent + dropped + still queued in packets
          and in bytes, every received block matched the independent sample oracle, and the receiver accounted for every
          datagram it read.

A case with no log is ``blocked``: counted, named, never passed. Exit 0 qualified, 1 a case failed, 3 only blocked cases stand
in the way, 2 usage or an unreadable file. The log's sha256, the revision (``--revision``), each scripted world's seeds and fault
schedule, and the dropped and late bytes are written to a receipt with ``--receipts``; the first failure is printed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CRATE = os.path.join(REPO, "crates", "franken-stream")
CONTRACT = os.path.join(REPO, "docs", "contracts", "n07.md")
SPEAKER = os.path.join(REPO, "crates", "franken-speaker")
RUST_SOURCES = [os.path.join(CRATE, "src", "carrier", "tests.rs"), os.path.join(CRATE, "tests", "n07_carrier.rs"),
                os.path.join(CRATE, "src", "link", "tests.rs"), os.path.join(CRATE, "tests", "n07_ownership.rs"),
                os.path.join(SPEAKER, "src", "net_carrier", "tests.rs")]
LINK_SOURCE = os.path.join(CRATE, "src", "link.rs")
E04_MATRIX = os.path.join(REPO, "tests", "e04", "matrix_audiodev_m16.json")
CARRIER = os.path.join(CRATE, "src", "carrier.rs")
RECEIPT_SCHEMA = "ffw.n07.receipt.v1"

U = "carrier::tests::"
UNIT_TESTS = [U + "n07_payload_sizing_accounts_for_every_header_and_never_exceeds_a_block",
              U + "n07_the_pacer_starts_full_spends_exactly_and_names_its_next_deadline",
              U + "n07_a_report_round_trips_and_every_flaw_is_named",
              U + "n07_the_baseline_limits_are_valid_and_each_bound_is_checked",
              U + "n07_retained_totals_saturate_at_extreme_valid_limits_without_allocating",
              U + "n07_addresses_outside_the_declared_profile_are_refused_before_any_socket_is_used"]
C, L, P = "carrier::tests::", "link::tests::", "net_carrier::tests::"
CARRIER_PORT_TESTS = [C + name for name in (
    "n07_a_sender_over_any_port_signs_with_the_n01_sender_and_the_n01_receiver_admits_it",
    "n07_a_report_that_names_its_peer_needs_no_source_address_and_an_unnamed_one_is_refused",
    "n07_a_send_fault_is_classified_counted_and_a_refused_datagram_is_retried_then_given_up_on",
    "n07_a_rebind_is_checked_against_the_profile_and_is_all_or_nothing",
    "n07_a_receiver_over_any_port_names_its_peer_and_follows_a_new_sender_address",
    "n07_a_media_sink_that_admits_names_the_sequence_and_a_refusal_or_backpressure_earns_no_credit",
    "n07_a_consumed_unusable_datagram_is_counted_and_reading_goes_on",
    "n07_a_message_too_long_send_fences_that_peers_path_and_recovers_when_the_mtu_does",
    "n07_control_is_charged_to_the_interface_pacer_and_to_its_own_share_however_often_pump_is_called",
    "n07_a_control_flood_cannot_starve_media_and_media_saturation_cannot_starve_a_stop",
    "n07_a_refused_send_never_burns_the_window_and_cannot_run_the_sequence_ahead",
    "n07_a_refused_datagram_keeps_its_bytes_and_number_until_it_goes_or_is_given_up_on",
    "n07_a_window_full_of_lost_datagrams_is_probed_once_per_interval_and_reopens_on_the_answer",
    "n07_an_address_change_invents_no_credit_and_the_probe_finds_the_new_path",
    "n07_the_window_limit_is_bounded_so_the_unreported_list_is",
    "n07_a_long_refusal_cannot_run_the_sequence_out_of_the_receivers_reach_and_the_peer_recovers_against_n01",
    "n07_a_peer_that_never_answers_costs_one_probe_per_interval_through_a_thousand_intervals_and_then_recovers",
    "n07_the_datagram_that_holds_the_last_number_is_never_dropped_aged_evicted_or_fenced_away",
    "n07_a_refused_probe_burns_no_number_and_a_too_long_probe_fences_the_peer",
    "n07_a_held_datagram_counts_in_the_peer_cap_and_is_never_the_one_evicted",
    "n07_the_byte_cap_counts_the_held_datagram_too_and_a_peer_holding_only_that_refuses_the_newcomer",
    "n07_held_datagrams_count_in_the_aggregate_cap_and_the_longest_queue_pays_for_a_newcomer",
    "n07_an_aggregate_full_of_held_datagrams_refuses_the_newcomer_and_loses_nothing",
    "n07_a_window_larger_than_the_sequence_budget_is_supported_and_the_budget_is_what_holds",
    "n07_every_media_lane_attempt_counts_against_the_pump_cap_probes_and_refusals_included",
    "n07_the_cached_datagram_and_every_other_retained_byte_is_accounted_and_bounded",
    "n07_a_move_onto_a_family_with_more_header_overhead_is_checked_against_the_path_mtu",
    "n07_retained_allocation_stays_in_the_report_when_only_the_logical_length_shrinks",
    "n07_two_groups_draw_on_one_interface_bucket_and_one_work_cap",
    "n07_a_group_is_admitted_against_the_budget_every_group_shares_and_leaving_returns_it",
    "n07_the_aggregate_cap_is_the_interfaces_and_the_longest_queue_pays_in_whichever_group_it_is",
    "n07_advancing_one_groups_epoch_fences_only_that_group_and_a_stale_submit_is_refused_by_group",
    "n07_a_report_is_checked_with_the_key_of_the_stream_it_names_and_credits_only_that_streams_peer",
    "n07_a_source_restart_takes_a_fresh_stream_and_a_newer_epoch_and_touches_nothing_else",
    "n07_a_receiver_follows_a_source_restart_reports_the_new_stream_from_zero_and_refuses_the_old",
    "n07_group_membership_is_bounded_and_each_refusal_changes_nothing",
    "n07_all_peer_n01_backpressure_preserves_queues_then_delivers_each_pcm_once",
    "n07_all_peer_n01_invalid_stale_cancel_and_membership_refuse_before_mutation",
    "n07_all_peer_n01_respects_profile_sequence_headroom_and_live_path",
    "n07_all_peer_n01_membership_change_and_unfenced_small_mtu_are_checked",
    "n07_all_peer_n01_repair_refused_and_overlap_capacity_exact_boundary",
    "n07_all_peer_n01_deadline_uses_separate_group_and_interface_clocks",
    "n07_all_peer_snapshot_fences_foreign_sender_and_same_id_aba",
    "n07_clocked_n01_pump_uses_group_deadline_and_delivers_real_pcm",
    "n07_clocked_n01_rejects_missing_wrong_duplicate_and_late_views",
    "n07_clocked_n01_held_retry_respects_group_cutoff",
    "n07_clocked_n01_backward_view_fences_until_fresh_epoch",
    "n07_all_peer_admission_observes_retry_time_and_latches_rollback",
    "n07_clocked_n01_after_cutoff_never_sends_queued_media",
    "n07_clocked_n01_last_sequence_recovery_is_not_stale_playback",
    "n07_clocked_n01_missing_view_allows_only_existing_stall_probe",
    "n07_n01_unrelated_group_change_retains_lifetime_fence_authority",
    "n07_n01_predecode_eligibility_tracks_live_capacity_and_snapshot",
    "n07_n01_predecode_checks_actual_full_block_not_configured_floor",
    "n07_n01_exclusive_source_blocks_competitors_and_pump_bypass",
    "n07_n01_claim_blocks_legacy_queue_held_and_cached_probe_bypass",
    "n07_n01_selected_pump_never_sends_other_selected_group",
    "n07_n01_selected_source_continues_after_unrelated_group_changes_and_rollback",
    "n07_selected_pump_cannot_emit_unclaimed_other_group_protected_probe",
    "n07_n01_selected_same_group_route_change_invalidates_and_fences",
    "n07_n01_selected_fence_survives_unrelated_group_mutation",
    "n07_n01_source_claim_rejects_old_protected_state",
    "n07_isolated_retry_cooldown_cannot_steal_healthy_peer_capacity",
    "n07_isolated_fanout_continues_healthy_peer_and_never_replays_skipped_pcm",
    "n07_isolated_fanout_all_unavailable_waits_then_expired_skips_once",
    "n07_isolated_fanout_partial_capacity_rotates_and_validates_every_profile",
    "n07_clocked_n01_lifetime_bound_fence_blocks_queued_media_until_new_epoch",
    "n07_all_peer_same_snapshot_recovers_link_fence_and_mtu_backpressure",
    "n07_all_peer_audio_survives_legacy_and_fec_aggregate_pressure",
    "n07_clocked_n01_mixed_queues_preserve_each_deadline_domain",
    "n07_clocked_n01_missing_view_preserves_legacy_progress_and_blocks_protected",
    "n07_all_peer_accepted_queue_is_fenced_on_route_and_membership_change")]
LINK_TESTS =[L + name for name in (
    "n07_the_ownership_matrix_is_consistent_and_claims_nothing_e04_does_not_know",
    "n07_every_profile_stays_unqualified_and_wireless_is_tracked_as_required",
    "n07_an_interface_cycle_on_the_same_address_resumes_without_a_rebind",
    "n07_an_address_change_rebinds_releases_the_stale_path_and_a_lost_address_forces_a_rebind",
    "n07_a_failed_rebind_backs_off_by_the_schedule_and_spends_a_bounded_budget",
    "n07_the_backoff_never_decreases_never_exceeds_the_cap_and_replays_from_its_seed",
    "n07_an_address_of_an_undeclared_family_is_refused_and_never_disturbs_the_path_in_use",
    "n07_wan_and_resolver_events_change_nothing_and_a_lapsed_lease_stops_sending",
    "n07_the_wait_for_an_address_is_bounded_and_a_late_address_starts_over",
    "n07_a_stale_rebind_result_is_ignored_and_the_current_one_applies",
    "n07_seeded_random_event_sequences_keep_every_invariant",
    "n07_a_speaker_keeps_its_identity_and_handle_when_its_address_moves",
    "n07_every_transport_reason_has_a_stable_code_and_never_names_the_wan",
    "n07_a_lease_that_ended_during_an_outage_is_never_resumed_and_a_short_outage_is",
    "n07_a_rebind_that_finishes_after_the_lease_ended_does_not_resume")]
OWNERSHIP_TESTS = ["n07_the_ownership_matrix_carries_the_committed_e04_radio_duties_exactly",
                   "n07_the_two_e04_radio_blockers_are_the_ones_the_matrix_names",
                   "n07_the_radio_duties_the_bead_requires_to_stay_tracked_are_all_present"]
PORT_TESTS = [P + name for name in (
    "n07_the_p02_port_carries_datagrams_and_names_the_sender_through_the_boundary",
    "n07_the_p02_port_reports_an_oversize_datagram_as_cut_with_its_sender",
    "n07_a_send_errno_is_classified_by_the_abis_own_numbers",
    "n07_a_peer_address_round_trips_through_the_platform_key_in_both_families",
    "n07_a_rebind_keeps_the_configured_ports_closes_the_old_sockets_and_a_failure_keeps_them",
    "n07_the_carrier_gate_starts_with_the_link_manager_and_opens_only_when_the_link_is_up",
    "n07_the_freshness_oracle_flags_pcm_decided_at_or_after_its_presentation_time",
    "n07_the_expected_path_generation_is_counted_from_the_script_and_not_from_the_manager",
    "n07_a_stale_authentic_datagram_and_its_copy_through_the_real_endpoint_advance_credit_and_render_nothing",
    "n07_the_source_oracle_gives_every_block_its_own_bytes_and_the_old_pattern_did_not")]
# The speaker's end-to-end worlds: the real carrier, N01 framers, link manager and N04 playout over a SIMULATED host kernel.
SPEAKER_WORLDS = [
    ("N07-E11", "S1", "n07_s1_zero_loss_paced_delivery_into_the_playout_path",
     "zero loss into MediaPlayout: every block equals the source oracle, block 0 prepared while armed, overhead measured"),
    ("N07-E12", "S2", "n07_s2_a_slow_peer_is_isolated_bounded_and_recovers_with_fresh_audio_only",
     "a stalled room: bounded sender state, the others lose nothing, recovery hears fresh audio only"),
    ("N07-E13", "S3", "n07_s3_control_is_sent_first_under_media_saturation_and_media_still_flows",
     "saturated pacer: a stop goes out in the pump it was submitted, a control flood is bounded, media still flows"),
    ("N07-E14", "S4", "n07_s4_interface_and_address_events_keep_identity_resume_muted_and_refuse_stale_paths",
     "link down/up, sender address change with a real rebind, a room moving, a refused address: identity kept, no old audio"),
    ("N07-E15", "S4b", "n07_s4b_a_spent_reconnect_budget_is_reported_to_the_readiness_state_and_a_good_address_recovers",
     "a spent reconnect budget is reported once, shown as a local degraded state, and a good address recovers"),
    ("N07-E16", "S5", "n07_s5_an_epoch_restart_fences_stale_sends_stale_packets_and_stale_reports",
     "epoch restart: stale send refused, queued audio fenced, stale packet and stale report refused, audio resumes muted"),
    ("N07-E17", "S6", "n07_s6_an_mtu_change_fences_a_peer_without_fragmenting_and_recovers",
     "MTU drop and an EMSGSIZE from the kernel fence a peer; nothing is fragmented; recovery on the MTU's word"),
    ("N07-E18", "S7", "n07_s7_seeded_loss_and_reorder_are_concealed_and_every_sample_matches_the_oracle",
     "seeded loss and reorder below the carrier: exactly the undropped blocks are heard, the lost ones concealed"),
    ("N07-E19", "S2b", "n07_s2b_a_stalled_network_side_with_a_live_renderer_plays_what_it_holds_and_then_nothing_old",
     "a stalled network side with a live renderer: it plays what it holds, then silence; the backlog it reads on return is late and unplayed"),
    ("N07-E20", "S8", "n07_s8_a_long_outage_is_recovered_through_the_real_endpoint_with_credit_and_no_stale_pcm",
     "a refusal spends the sequence budget; the expired protected datagram's first copy is late through the real endpoint, earns credit, renders nothing; fresh audio follows"),
    ("N07-E21", "S8b", "n07_s8b_when_the_protected_datagram_arrives_its_probes_are_replays_that_change_nothing",
     "the protected datagram arrives late and earns the credit; both probes are replays that change no credit and render nothing"),
]
CASES = [
    {"id": "N07-E01", "scenario": "N07-S1-zero-loss-paced", "tests": ["n07_s1_zero_loss_paced"],
     "what": "zero loss, two peers, paced: every block in order, control ahead, overhead measured"},
    {"id": "N07-E02", "scenario": "N07-S2-slow-peer-isolated", "tests": ["n07_s2_slow_peer_isolated"],
     "what": "a peer that stops reporting is isolated: bounded state, fresh audio on recovery, the others untouched"},
    {"id": "N07-E03", "scenario": "N07-S3-saturation-control-priority", "tests": ["n07_s3_saturation_control_priority"],
     "what": "saturated pacer and aggregate cap: control first in its pump, media keeps its share"},
    {"id": "N07-E04", "scenario": "N07-S4-epoch-fence", "tests": ["n07_s4_epoch_fence"],
     "what": "epoch fence: queued audio dropped, stale sends and stale reports refused"},
    {"id": "N07-E05", "scenario": "N07-S5-mtu-admission-address-family", "tests": ["n07_s5_mtu_admission_address_family"],
     "what": "MTU, admission budget and address family refuse or fence without fragmenting"},
    {"id": "N07-E06", "scenario": "N07-S6-link-and-address-change", "tests": ["n07_s6_link_and_address_change"],
     "what": "simulated link-down ages audio out; address change keeps identity and refuses the old path"},
    {"id": "N07-E07", "scenario": "N07-S7-loss-and-reorder", "tests": ["n07_s7_loss_and_reorder"],
     "what": "seeded loss and reorder on one hop: the replay window and reports cope, the clean peer is unaffected"},
    {"id": "N07-E08", "scenario": None,
     "tests": ["n07_the_carrier_binds_loopback_only_and_refuses_anything_else_before_a_socket_is_used",
               "n07_a_report_that_is_not_authentic_or_not_from_the_peer_moves_nothing",
               "n07_idle_fec_expectations_reject_nonzero_missing_mistyped_and_unknown_fields"],
     "what": "loopback-only binding; unauthentic reports move nothing (and the peer's own does); idle FEC telemetry is exact, not ignored"},
    {"id": "N07-U01", "scenario": None, "tests": UNIT_TESTS,
     "what": "unit: payload sizing, the pacer's deadlines, the report codec, the limit bounds, address policy"},
    {"id": "N07-U02", "scenario": None, "tests": CARRIER_PORT_TESTS,
     "what": "unit over an in-memory port: N01 signing, report attribution, send faults and retries, control and media budgets, window credit, retransmission probes, the sequence budget and long-outage recovery against a genuine N01 receiver, the held datagram in every queue bound, rebind, media sink, discards, MTU fence, several streams on one interface under one bucket, one admission sum, one work cap and one aggregate cap, reports routed by stream, a source restart on sender and receiver"},
    {"id": "N07-U03", "scenario": None, "tests": LINK_TESTS,
     "what": "unit and seeded property: link lifecycle, backoff, address families, lease guard (also across an outage), WAN decoupling, identity directory"},
    {"id": "N07-E09", "scenario": None, "tests": OWNERSHIP_TESTS,
     "what": "the ownership matrix carries E04's seven radio duties and blockers verbatim and claims nothing E04 does not know"},
    {"id": "N07-E10", "scenario": None, "tests": PORT_TESTS,
     "what": "the P02 port over the platform datagram boundary on a simulated host kernel, and the carrier gate (host-only evidence)"},
] + [{"id": cid, "scenario": None, "speaker": world, "tests": [P + test], "what": what} for cid, world, test, what in SPEAKER_WORLDS] + [
    {"id": "N07-E22", "scenario": None,
     "tests": [P + "n07_s9_a_source_restart_under_a_new_stream_identity_is_followed_through_the_real_endpoint"],
     "what": "a source restart under a new stream identity (fresh id, newer epoch) is followed through the real endpoint, loopback sockets and N04: the old queue is dropped, an old-stream datagram is refused, audio resumes muted, credit restarts"}]
OBSERVED = re.compile(r"N07-OBSERVED (\{.*\})\s*$")
STDOUT_BANNER = re.compile(r"^---- (\S+) stdout ----\s*$")


def load_d01():
    path = os.path.join(REPO, "tests", "d01", "run_cases.py")
    spec = importlib.util.spec_from_file_location("n07_d01_parser", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


d01 = load_d01()


def expected_binary(name):
    if name.startswith((C, L)):
        return "franken_stream"
    if name.startswith(P):
        return "franken_speaker"
    return "n07_ownership" if name in OWNERSHIP_TESTS else "n07_carrier"


def observation_test(record):
    key = record.get("id") or record.get("case")
    matches = [case["tests"][0] for case in CASES
               if (case.get("scenario") == key or case.get("speaker") == key)
               and key is not None and len(case["tests"]) == 1]
    return matches[0] if len(matches) == 1 else None


def header_origins(data):
    """Collect exact target labels in D01 header order, including non-N07 targets."""
    headers = []
    with io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace") as lines:
        for line in lines:
            matched = d01.RUNNING.match(line)
            if matched:
                stem = matched.group(1)
                if stem in ("franken_stream", "franken_speaker"):
                    expected = "unittests src/lib.rs"
                elif stem in ("n07_carrier", "n07_ownership"):
                    expected = "tests/%s.rs" % stem
                else:
                    expected = None
                valid = expected is not None and re.match(
                    r"^\s*Running\s+" + re.escape(expected) + r"\s+\(", line) is not None
                headers.append((stem, valid))
            elif re.match(r"^\s*Running\b", line):
                return None
            else:
                doc = d01.DOC_TESTS.match(line)
                if doc:
                    headers.append(("doc:" + doc.group(1), False))
    return headers


class N07Logs(d01.Logs):
    """D01's counted ordinal sections with strict verdict and observation origins."""
    def __init__(self, headers):
        super().__init__()
        self.headers = headers
        self.header_index = 0
        self.n07_tests = []
        self.n07_observations = []
        self.current_origin = None
        self.closed_section = None
        self.stdout_test = None

    def _section_line(self, section, line):
        if line.startswith("---- "):
            banner = STDOUT_BANNER.match(line)
            target = section if section is not None else self.closed_section
            name = banner.group(1) if banner else ""
            if section is not None:
                section["n07_active_banner"] = name
            else:
                self.stdout_test = name if target is not None else None
            if target is not None:
                counts = target.setdefault("n07_banners", {})
                counts[name] = counts.get(name, 0) + 1
            return
        match = OBSERVED.search(line)
        if not match:
            return
        try:
            record = json.loads(match.group(1))
        except ValueError:
            return
        if not isinstance(record, dict):
            return
        if section is None:
            if self.closed_section is not None and self.stdout_test is not None:
                self.closed_section.setdefault("n07_post_observations", []).append((self.stdout_test, record))
            else:
                self.n07_observations.append((None, record))
        else:
            section.setdefault("n07_observations", []).append((section.get("n07_active_banner"), record))

    def _section_closed(self, section):
        section["n07_closed"] = True
        self.closed_section = section
        self.stdout_test = None

    def _section_attributed(self, stem, section):
        header = (self.headers[self.header_index]
                  if self.headers is not None and self.header_index < len(self.headers) else None)
        self.header_index += 1
        self.current_origin = (stem if stem is not None and header == (stem, True)
                               and section.get("n07_closed") else None)
        def valid_banner(name, record):
            if name is None:
                return True
            matches = [status for test, status in section["tests"] if test == name]
            return (matches == ["ok"] and observation_test(record) == name
                    and section.get("n07_banners", {}).get(name) == 1)
        for name, record in section.get("n07_observations", []) + section.get("n07_post_observations", []):
            self.n07_observations.append((self.current_origin if valid_banner(name, record) else None, record))

    def _record_test(self, stem, name, status):
        origin = stem if stem is not None and stem == self.current_origin else None
        self.n07_tests.append((origin, name, status))


def load_model():
    spec = importlib.util.spec_from_file_location("n07_model", os.path.join(HERE, "model.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def first_difference(path, got, want):
    if isinstance(want, dict) and isinstance(got, dict):
        for key in want:
            if key not in got:
                return "%s/%s: missing from the observed record" % (path, key)
            found = first_difference("%s/%s" % (path, key), got[key], want[key])
            if found:
                return found
        extra = [key for key in got if key not in want]
        return "%s/%s: not in the expected record" % (path, extra[0]) if extra else None
    if isinstance(want, list) and isinstance(got, list):
        if len(want) != len(got):
            return "%s: %d entries observed, %d expected" % (path, len(got), len(want))
        for index, (g, w) in enumerate(zip(got, want)):
            found = first_difference("%s[%d]" % (path, index), g, w)
            if found:
                return found
        return None
    return None if got == want and type(got) is type(want) else "%s: observed %r, expected %r" % (path, got, want)


def accounting(record):
    """Checks on one observed record that need no model: the books balance and the samples matched."""
    for pid, peer in record["peers"].items():
        c, view = peer["view"]["counters"], peer["view"]
        dropped_packets = sum(c["media_dropped_%s_packets" % k] for k in ("overflow", "aggregate", "late", "fenced", "send_error"))
        dropped_bytes = sum(c["media_dropped_%s_bytes" % k] for k in ("overflow", "aggregate", "late", "fenced", "send_error"))
        if c["media_submitted_packets"] != c["media_sent_packets"] + dropped_packets + view["queued_packets"]:
            return "peer %s: submitted packets are not sent + dropped + queued" % pid
        if c["media_submitted_bytes"] != c["media_sent_bytes"] + dropped_bytes + view["queued_bytes"]:
            return "peer %s: submitted bytes are not sent + dropped + queued" % pid
        if peer["sample_mismatches"] != 0 or peer["samples_checked"] != len(peer["delivered"]):
            return "peer %s: a received block did not match the sample oracle (%d mismatches, %d checked of %d)" % (
                pid, peer["sample_mismatches"], peer["samples_checked"], len(peer["delivered"]))
        rs, rx = peer["receiver"]["stats"], peer["receiver"]["stream"]
        if rx["datagrams_seen"] != rs["media_read"] or rx["datagrams_seen"] != rx["accepted"] + sum(
                v for k, v in rx.items() if k.startswith("rejected_")):
            return "peer %s: the receiver did not account for every datagram it read" % pid
        if len({(d[0], d[1]) for d in peer["delivered"]}) != len(peer["delivered"]):
            return "peer %s: a packet was delivered twice" % pid
    return None


DROP_KINDS = ("overflow", "aggregate", "late", "fenced", "send_error")


def speaker_accounting(record):
    """Checks on one speaker-world record that need no model: it says what it is, the books balance, the counters agree."""
    if record.get("provenance") != "simulated_host_loopback":
        return "the record does not label itself host-only simulated evidence"
    if record.get("cpu_memory") != "not_measured":
        return "the record claims a CPU or memory figure this slice does not measure"
    missing = [k for k in ("seed", "fault_schedule", "link_log", "carrier", "port_faults", "rooms", "blocks") if k not in record]
    if missing:
        return "the record lacks %s" % missing
    if not record["rooms"]:
        return "the record has no rooms"
    for room in record["rooms"]:
        peer, c = room["peer"], room["sender_side"]
        if c is None:
            return "peer %s: the sender has no counters for it" % peer
        dropped_packets = sum(c["media_dropped_%s_packets" % k] for k in DROP_KINDS)
        dropped_bytes = sum(c["media_dropped_%s_bytes" % k] for k in DROP_KINDS)
        if c["media_submitted_packets"] != c["media_sent_packets"] + dropped_packets + room["queued_packets"]:
            return "peer %s: submitted packets are not sent + dropped + queued" % peer
        if c["media_submitted_bytes"] != c["media_sent_bytes"] + dropped_bytes + room["queued_bytes"]:
            return "peer %s: submitted bytes are not sent + dropped + queued" % peer
        rx, sink, n01 = room["receiver"], room["sink"], room["n01"]
        if sink["admitted"] + sink["refused"] + sink["backpressure"] != rx["media_read"]:
            return "peer %s: the sink did not account for every media datagram read" % peer
        if rx["media_accepted"] != sink["admitted"]:
            return "peer %s: accepted media is not what the sink admitted" % peer
        rejected = sum(v for k, v in n01.items() if k.startswith("rejected_"))
        if n01["datagrams_seen"] != n01["accepted"] + rejected:
            return "peer %s: the N01 receiver did not account for every datagram it saw" % peer
        if n01["datagrams_seen"] != rx["media_read"] - sink["backpressure"]:
            return "peer %s: the N01 receiver saw a different number of datagrams than the carrier read" % peer
    return None


def speaker_summary(record):
    return {"seed": record["seed"], "fault_schedule": record["fault_schedule"], "link_log": record["link_log"][:16],
            "largest_datagram_bytes": record.get("largest_datagram_bytes"), "provenance": record["provenance"],
            "dropped_late_bytes": {str(r["peer"]): {k: v for k, v in r["sender_side"].items() if k.endswith("_bytes") and "dropped" in k}
                                   for r in record["rooms"]},
            "queue_delay_ns_max": {str(r["peer"]): r["sender_side"]["queue_delay_ns_max"] for r in record["rooms"]},
            "heard_real": {str(r["peer"]): r["heard_real"] for r in record["rooms"]}, "not_measured": record["cpu_memory"]}


def overhead_summary(record):
    sent_bytes = sum(p["view"]["counters"]["media_sent_bytes"] for p in record["peers"].values())
    packets = sum(p["view"]["counters"]["media_sent_packets"] for p in record["peers"].values())
    return {"media_packets_sent": packets, "media_wire_bytes_sent": sent_bytes,
            "payload_bytes_sent": packets * 1024, "wire_overhead_bytes": sent_bytes - packets * 1024}


def read(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def meta(model):
    out = []

    def check(cid, ok, why):
        out.append((cid, ok, why))

    fresh = model.render(model.document())
    try:
        committed = read(model.SCENARIOS)
    except OSError:
        committed = None
    check("META-SCENARIOS", committed == fresh, "the scenario file equals a fresh generation from model.py" if committed == fresh
          else "the scenario file differs from a fresh generation: run model.py --write")
    sources = "\n".join(read(p) for p in RUST_SOURCES)
    found = set(re.findall(r"#\[test\]\s*fn\s+(n07_[A-Za-z0-9_]+)", sources))
    mapped = {t.split("::")[-1] for case in CASES for t in case["tests"]}
    check("META-TESTS", found == mapped, "every Rust n07_ test is mapped to a case and every mapped test exists" if found == mapped
          else "unmapped Rust tests %s, mapped but missing %s" % (sorted(found - mapped), sorted(mapped - found)))
    carrier = read(CARRIER)

    def struct_fields(name):
        body = re.search(r"pub struct %s \{(.*?)\n\}" % name, carrier, re.S).group(1)
        return re.findall(r"pub (\w+): u64", body)

    lists = {"PeerCounters": model.OBSERVED_PEER_COUNTERS, "CarrierStats": model.OBSERVED_CARRIER_STATS,
             "ReceiverStats": model.RECEIVER_STATS}
    bad = [n for n, want in lists.items() if struct_fields(n) != want]
    check("META-COUNTERS", not bad, "the model's counter lists equal the Rust structs' fields, in order" if not bad
          else "counter lists differ from the Rust for %s" % bad)

    limits_rust = defaults_for(carrier, "CarrierLimits")
    check("META-DEFAULTS", limits_rust == model.BASELINE_LIMITS and defaults_for(carrier, "ReceiverLimits") == model.BASELINE_RECEIVER,
          "the Rust baseline limits equal the model's" if limits_rust == model.BASELINE_LIMITS else
          "the Rust baseline limits differ from the model's: %s" % sorted(k for k in model.BASELINE_LIMITS if limits_rust.get(k) != model.BASELINE_LIMITS[k]))
    unit = read(RUST_SOURCES[0])
    table = re.findall(r"\((\d+), (true|false), (Some\((\d+)\)|None)\),", unit)
    rows = [(int(m), v == "true", None if w == "None" else int(n)) for m, v, w, n in table]
    check("META-SIZING", len(rows) == 11 and all(model.max_payload_for_path_mtu(m, v) == want for m, v, want in rows),
          "the Rust unit test's hand-written sizing table equals the model's, %d rows" % len(rows))
    try:
        e04 = json.loads(read(E04_MATRIX))
        link_source = read(LINK_SOURCE)
        ids = [record["id"] for record in e04["radio"]]
        absent = [i for i in ids if 'Some("%s")' % i not in link_source]
        ok = e04["schema"] == "ffw.e04.contract_matrix.v1" and len(ids) == 7 and not absent
        check("META-E04", ok, "link.rs carries all %d committed E04 radio duties by id" % len(ids) if ok
              else "link.rs does not carry E04 radio duties %s (or the E04 schema changed)" % absent)
    except (OSError, ValueError, KeyError):
        check("META-E04", False, "the committed E04 matrix or link.rs could not be read")
    try:
        contract = read(CONTRACT)
        missing = [c["id"] for c in CASES if c["id"] not in contract]
        check("META-CONTRACT", not missing, "the contract names every case" if not missing else "the contract does not name %s" % missing)
    except OSError:
        check("META-CONTRACT", False, "docs/contracts/n07.md is missing")
    return out


def defaults_for(carrier, struct):
    fn = "baseline"
    impl = re.search(r"impl %s \{(.*?)\n\}" % struct, carrier, re.S).group(1)
    body = re.search(r"fn %s\(\) -> Self \{\s*Self \{(.*?)\n        \}" % fn, impl, re.S).group(1)
    values = {}
    for key, raw in re.findall(r"(\w+): ([^,\n]+),", body):
        raw = raw.strip()
        if raw in ("true", "false"):
            values[key] = raw == "true"
        elif raw == "MAX_PAYLOAD_BYTES":
            values[key] = 1024
        else:
            values[key] = int(raw.replace("_", ""))
    return values


def judge(model, texts):
    """Results per case id, from D01's ordinal-attributed captured sections."""
    results, observed = {}, {}
    tests, origins, observed_origins = {}, {}, {}
    for index, value in enumerate(texts):
        data = value if isinstance(value, bytes) else value.encode("utf-8")
        parser = N07Logs(header_origins(data))
        parser.add_captured("capture-%d.log" % index, data)
        for stem, name, verdict in parser.n07_tests:
            tests[name] = verdict if name not in tests else "ambiguous"
            origins.setdefault(name, []).append(stem)
        for stem, record in parser.n07_observations:
            key = record.get("id") or record.get("case")
            observed.setdefault(key, []).append(record)
            observed_origins.setdefault(key, []).append(stem)
    scenarios = {s["id"]: s for s in model.scenarios()}
    for case in CASES:
        why = None
        for test in case["tests"]:
            verdict = tests.get(test)
            if verdict is None:
                why = "test %s is not in the log" % test
            elif verdict != "ok":
                why = "test %s reported %s" % (test, verdict)
            elif origins[test] != [expected_binary(test)]:
                why = "test %s has wrong or ambiguous binary attribution" % test
            if why:
                break
        if why is None and case.get("speaker"):
            records = observed.get(case["speaker"], [])
            if len(records) == 0 or len(records) >= 2:
                why = "%d N07-OBSERVED records for world %s, expected exactly 1" % (len(records), case["speaker"])
            elif observed_origins[case["speaker"]] != ["franken_speaker"]:
                why = "N07-OBSERVED world %s has wrong or ambiguous binary attribution" % case["speaker"]
            else:
                why = speaker_accounting(records[0])
        if why is None and case["scenario"]:
            records = observed.get(case["scenario"], [])
            if len(records) != 1:
                why = "%d N07-OBSERVED records for %s, expected exactly 1" % (len(records), case["scenario"])
            elif observed_origins[case["scenario"]] != ["n07_carrier"]:
                why = "N07-OBSERVED %s has wrong or ambiguous binary attribution" % case["scenario"]
            else:
                record = records[0]
                want = model.expected_observation(scenarios[case["scenario"]])
                why = first_difference("", record, want) or accounting(record)
                if why:
                    why = "observation disagrees with the model: " + why if first_difference("", record, want) else why
        results[case["id"]] = ("failed", why) if why else ("passed", "")
    return results, observed, tests


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--judge", nargs="+", metavar="LOG")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--revision", default="unrecorded")
    ap.add_argument("--receipts")
    args = ap.parse_args(argv)
    if args.list:
        for case in CASES:
            print("%s  %s" % (case["id"], case["what"]))
        return 0
    model = load_model()
    results, failed = [], 0
    for cid, ok, why in meta(model):
        print("%-7s %s  %s" % ("PASS" if ok else "FAIL", cid, why))
        failed += not ok
    if not args.judge:
        for case in CASES:
            print("BLOCKED %s  %s (no cargo log given)" % (case["id"], case["what"]))
        print("N07: %d meta checks failed, %d cases blocked" % (failed, len(CASES)))
        return 1 if failed else 3
    texts = []
    for path in args.judge:
        try:
            with open(path, "rb") as handle:
                texts.append(handle.read())
        except OSError as exc:
            print("cannot read %s: %s" % (path, exc), file=sys.stderr)
            return 2
    outcome, observed, tests = judge(model, texts)
    first_failure = None
    for case in CASES:
        status, why = outcome[case["id"]]
        print("%-7s %s  %s%s" % (status.upper(), case["id"], case["what"], "" if not why else "\n          first failure: " + why))
        if status == "failed" and first_failure is None:
            first_failure = (case["id"], why)
    n_failed = sum(1 for s, _ in outcome.values() if s == "failed")
    print("N07: %d cases, %d passed, %d failed, %d meta checks failed" % (len(CASES), len(CASES) - n_failed, n_failed, failed))
    if args.receipts:
        cases = []
        for case in CASES:
            entry = {"id": case["id"], "status": outcome[case["id"]][0], "first_failure": outcome[case["id"]][1] or None}
            if case.get("speaker") and observed.get(case["speaker"]):
                entry["observed"] = speaker_summary(observed[case["speaker"]][0])
            if case["scenario"] and observed.get(case["scenario"]):
                rec = observed[case["scenario"]][0]
                scenario = next(s for s in model.scenarios() if s["id"] == case["scenario"])
                entry["observed"] = {
                    "seeds": [p["relay"]["seed"] for p in scenario["peers"] if p.get("relay")],
                    "fault_schedule": scenario["ops"], **overhead_summary(rec),
                    "dropped_late_bytes": {pid: {k: v for k, v in p["view"]["counters"].items() if k.endswith("_bytes") and "dropped" in k}
                                           for pid, p in rec["peers"].items()},
                    "queue_delay_ns_max": {pid: p["view"]["counters"]["queue_delay_ns_max"] for pid, p in rec["peers"].items()}}
            cases.append(entry)
        receipt = {"schema": RECEIPT_SCHEMA, "revision": args.revision, "log_sha256": [hashlib.sha256(t).hexdigest() for t in texts],
                   "not_measured": ["cpu", "memory", "physical radio", "interfaces, leases and resolvers (simulated or absent)"],
                   "first_failure": first_failure, "cases": cases}
        os.makedirs(args.receipts, exist_ok=True)
        with open(os.path.join(args.receipts, "receipt.json"), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
    return 1 if failed or n_failed else 0


if __name__ == "__main__":
    sys.exit(main())
