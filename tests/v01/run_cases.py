#!/usr/bin/env python3
"""Judge the actual V01 Rust integration-test trace, without running a build.

The caller retains the RCH command/source receipt with the log. This judge
admits only host-simulation observations, never physical/video qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LIMIT = 8 * 1024 * 1024
MARKER = "FFW_V01_CASE "
CASES = (
    "V01-SERIAL", "V01-OVERLAP", "V01-GAPS", "V01-NESTED",
    "V01-OCCUPANCY", "V01-REPLACE", "V01-INVALIDATION",
    "V01-TRANSFORM", "V01-ARITHMETIC", "V01-VIDEO-BOUNDS",
)
QUEUE_TESTS = (
    "events::tests::hal_critical_queue_policy_vector_and_recovery",
    "events::tests::every_seven_step_policy_schedule_matches_independent_deque",
    "events::tests::critical_bypasses_ordinary_rate_limit_but_loss_is_explicit",
    "events::tests::saturation_never_wraps_evidence_loss_to_zero",
)
TIMELINE_TESTS = (
    "injected_delays_match_independent_expected_values",
    "overlap_matches_discrete_occupancy_for_every_small_interval_pair",
    "order_and_queue_replacement_do_not_accumulate_latency",
    "missing_unknown_and_stale_route_never_report_exact_latency",
    "checked_affine_transform_rounds_outward_and_propagates_uncertainty",
    "invalid_and_overflow_values_are_errors_and_preserve_last_observation",
    "video_advice_uses_uncertainty_bounds_and_does_not_claim_percentiles",
)
ADAPTER_TESTS = (
    "emitted_events_round_trip_through_shared_schema_on_control_side",
    "full_slow_and_unavailable_consumers_do_not_change_estimates",
    "refusal_events_keep_cause_and_do_not_hide_missing_stages",
    "shared_buffer_rate_windows_wraparound_and_disabled_capacity",
    "clock_regression_is_counted_and_does_not_change_refusal",
    "stale_route_error_survives_sink_loss_and_later_recovery",
)


def missing_named_tests(text, names):
    return [name for name in names if len(re.findall(
        r"^test " + re.escape(name) + r" \.\.\. ok$", text, re.MULTILINE)) != 1]


def select_section(raw, kind):
    """Retain an authentic Rust binary section from a combined Cargo log.

    Summary bytes are never synthesized. A failed parent invocation cannot be
    laundered by choosing its successful child. Returned ranges bind the slice.
    """
    if len(raw) > LIMIT:
        raise ValueError("parent_log_exceeds_8_mib")
    summaries = re.findall(rb"(?m)^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw)
    if any(state != b"ok" or failed != b"0" or ignored != b"0" for state, _, failed, ignored in summaries):
        raise ValueError("parent_contains_failed_or_ignored_tests")
    selectors = {
        "timeline": (MARKER.encode(),),
        "event_adapter": (b"FFW_V01_EVENT ",),
        "event_queue": tuple(name.encode() for name in QUEUE_TESTS),
        "allocation_probe": (b"test latency_and_event_operations_do_not_allocate_but_control_serialization_does ... ok",),
    }[kind]
    selected = []
    starts = list(re.finditer(rb"(?m)^running (\d+) tests?\r?\n", raw))
    for index, match in enumerate(starts):
        limit = starts[index + 1].start() if index + 1 < len(starts) else len(raw)
        summary = re.search(rb"(?m)^test result: .*", raw[match.end():limit])
        if summary is None:
            raise ValueError("truncated_test_section")
        end = match.end() + summary.end()
        section = raw[match.start():end]
        if all(marker in section for marker in selectors):
            selected.append((section, {"parent_sha256": hashlib.sha256(raw).hexdigest(),
                                      "byte_start": match.start(), "byte_end": end,
                                      "parent_section_tests": int(match.group(1))}))
    if len(selected) != 1:
        raise ValueError("required_section_missing_or_ambiguous")
    return selected[0]


def judge(raw):
    errors = []
    events = {}
    if len(raw) > LIMIT:
        return {"status": "INCOMPLETE", "expected": len(CASES), "observed": 0,
                "rust_tests_expected": 7, "errors": ["log_exceeds_8_mib"]}
    text = raw.decode("utf-8", errors="strict")
    for line in text.splitlines():
        if MARKER not in line:
            continue
        payload = line.split(MARKER, 1)[1]
        if len(payload) > 8192:
            errors.append("event_exceeds_8_kib")
            continue
        try:
            event = json.loads(payload)
        except (ValueError, TypeError):
            errors.append("malformed_event")
            continue
        if not isinstance(event, dict):
            errors.append("event_not_object")
            continue
        case_id = event.get("case_id")
        if case_id not in CASES or case_id in events:
            errors.append("unknown_or_duplicate_case")
            continue
        events[case_id] = event
        expected_header = {
            "schema": "ffw.v01.case.v1", "run_id": "v01-deterministic",
            "correlation_id": "snapshot-19", "timebase": "virtual_monotonic_ns",
            "monotonic_ns": 1000, "source_epoch": 3, "route_revision": 2,
            "evidence_class": "host_simulation", "dropped_events": 0,
        }
        if any(event.get(k) != v for k, v in expected_header.items()):
            errors.append(f"{case_id}:bad_header_or_evidence_loss")
        if not isinstance(event.get("details"), dict):
            errors.append(f"{case_id}:missing_details")
    missing = sorted(set(CASES) - events.keys())
    errors.extend(f"missing:{case_id}" for case_id in missing)

    def require(case_id, expected):
        if case_id not in events:
            return
        details = events[case_id].get("details")
        if not isinstance(details, dict):
            return
        for key, value in expected.items():
            if details.get(key) != value:
                errors.append(f"{case_id}:{key}:expected={value!r}:observed={details.get(key)!r}")

    # Independently fixed expected outputs, not regenerated from Rust output.
    for case_id, elapsed, accounted in [
        ("V01-SERIAL", 80, 80), ("V01-OVERLAP", 80, 80),
        ("V01-GAPS", 80, 45), ("V01-NESTED", 80, 60),
    ]:
        require(case_id, {"effective_ns": elapsed, "accounted_ns": accounted,
                          "unaccounted_ns": elapsed - accounted})
    require("V01-OCCUPANCY", {"pairs": 441})
    require("V01-REPLACE", {"effective_ns": 80, "accounted_ns": 74, "unaccounted_ns": 6})
    require("V01-INVALIDATION", {"rejected_context_changes": 4, "freshness_bound_ns": 100})
    require("V01-TRANSFORM", {"interval": {"start_ns": 1000, "end_ns": 1015}, "uncertainty_ns": 9})
    require("V01-ARITHMETIC", {"last_good_latency_ns": 10})
    require("V01-VIDEO-BOUNDS", {"requested_delay_ns": 60_000_000,
                                "residual_min_ns": 0, "residual_max_ns": 0,
                                "within_40ms_bound": True})
    # Exact integration-test denominator; fixtures alone cannot satisfy it.
    summaries = re.findall(
        r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
        text,
    )
    if summaries != [("ok", "7", "0", "0", "0", "0")]:
        errors.append("missing_or_unexpected_rust_test_summary")
    errors.extend(f"timeline_case_missing_or_ambiguous:{name}"
                  for name in missing_named_tests(text, TIMELINE_TESTS))
    return {"schema": "ffw.v01.judgment.v1",
            "status": "HOST_SIMULATION_PASSED" if not errors else "INCOMPLETE",
            "expected": len(CASES), "observed": len(events), "rust_tests_expected": 7,
            "evidence_class": "host_simulation", "errors": errors,
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "source_binding": "caller_must_retain_central_build_receipt",
            "no_claim": "No Sonos hardware, provider, analog output or complete V01 qualification."}


def judge_supplement(raw, expected_tests, *, queue_unit=False, events=False):
    """Check a separate, named central test invocation, not fabricated counts."""
    if len(raw) > LIMIT:
        return ["supplement_log_too_large"]
    text = raw.decode("utf-8", errors="strict")
    summaries = re.findall(
        r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", text)
    errors = []
    if len(summaries) != 1:
        errors.append("supplement_summary_missing_or_ambiguous")
    else:
        state, passed, failed, ignored, measured, filtered = summaries[0]
        count_ok = int(passed) >= expected_tests if queue_unit else int(passed) == expected_tests
        if not count_ok or (state, failed, ignored, measured) != ("ok", "0", "0", "0"):
            errors.append("supplement_test_outcome_mismatch")
        if not queue_unit and filtered != "0":
            errors.append("supplement_cases_filtered")
    if queue_unit:
        errors.extend(f"queue_case_missing_or_ambiguous:{name}"
                      for name in missing_named_tests(text, QUEUE_TESTS))
    if events:
        errors.extend(f"adapter_case_missing_or_ambiguous:{name}"
                      for name in missing_named_tests(text, ADAPTER_TESTS))
        records = []
        for line in text.splitlines():
            if "FFW_V01_EVENT " in line:
                payload = line.split("FFW_V01_EVENT ", 1)[1]
                if len(payload) > 8192:
                    errors.append("event_exceeds_8_kib")
                    continue
                try:
                    records.append(json.loads(payload))
                except ValueError:
                    errors.append("event_json_malformed")
        if (len(records) != 3 or any(not isinstance(r, dict) or r.get("schema_version") != "ffw.log.v1" for r in records)):
            errors.append("event_schema_or_count_mismatch")
        else:
            kinds = [r.get("event_kind") for r in records]
            if kinds.count("latency_estimated") != 2 or kinds.count("latency_refused") != 1:
                errors.append("event_positive_negative_pair_missing")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-log", required=True, type=Path)
    parser.add_argument("--tier", choices=("smoke", "full", "soak"), default="smoke")
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--event-unit-log", type=Path)
    parser.add_argument("--allocation-log", type=Path)
    args = parser.parse_args()
    try:
        with args.rust_log.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        section, source = select_section(raw, "timeline")
        result = judge(section)
        result["source_sections"] = {"timeline": source}
        result["tier"] = args.tier
        if args.tier != "smoke":
            for label, path, count, options in [
                ("event_adapter", args.event_log, 6, {"events": True}),
                ("event_queue", args.event_unit_log, 4, {"queue_unit": True}),
                ("allocation_probe", args.allocation_log, 1, {}),
            ]:
                if path is None:
                    result["errors"].append(f"{label}:not_run")
                    continue
                try:
                    with path.open("rb") as stream:
                        supplement = stream.read(LIMIT + 1)
                    section, source = select_section(supplement, label)
                    result["source_sections"][label] = source
                    failures = judge_supplement(section, count, **options)
                except (OSError, UnicodeError, ValueError) as error:
                    failures = [str(error) if isinstance(error, ValueError) else type(error).__name__]
                result["errors"].extend(f"{label}:{error}" for error in failures)
            result["rust_tests_expected"] = 18
        if args.tier == "soak":
            result["errors"].append("soak_campaign_not_yet_implemented")
        if result["errors"]:
            result["status"] = "INCOMPLETE"
    except (OSError, UnicodeError, ValueError) as error:
        result = {"status": "INCOMPLETE", "expected": len(CASES), "observed": 0,
                  "tier": args.tier, "rust_tests_expected": 7 if args.tier == "smoke" else 18,
                  "errors": [str(error) if isinstance(error, ValueError) else type(error).__name__]}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "HOST_SIMULATION_PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
