"""Synthetic judge canaries only; these do not execute or qualify Rust."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("v01_run", Path(__file__).with_name("run_cases.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


def synthetic_events():
    details = {
        "V01-SERIAL": {"effective_ns": 80, "accounted_ns": 80, "unaccounted_ns": 0},
        "V01-OVERLAP": {"effective_ns": 80, "accounted_ns": 80, "unaccounted_ns": 0},
        "V01-GAPS": {"effective_ns": 80, "accounted_ns": 45, "unaccounted_ns": 35},
        "V01-NESTED": {"effective_ns": 80, "accounted_ns": 60, "unaccounted_ns": 20},
        "V01-OCCUPANCY": {"pairs": 441},
        "V01-REPLACE": {"effective_ns": 80, "accounted_ns": 74, "unaccounted_ns": 6},
        "V01-INVALIDATION": {"rejected_context_changes": 4, "freshness_bound_ns": 100},
        "V01-TRANSFORM": {"interval": {"start_ns": 1000, "end_ns": 1015}, "uncertainty_ns": 9},
        "V01-ARITHMETIC": {"last_good_latency_ns": 10},
        "V01-VIDEO-BOUNDS": {"requested_delay_ns": 60_000_000, "residual_min_ns": 0,
                             "residual_max_ns": 0, "within_40ms_bound": True},
    }
    return [{"schema": "ffw.v01.case.v1", "case_id": case_id,
             "run_id": "v01-deterministic", "correlation_id": "snapshot-19",
             "timebase": "virtual_monotonic_ns", "monotonic_ns": 1000,
             "source_epoch": 3, "route_revision": 2, "evidence_class": "host_simulation",
             "dropped_events": 0, "details": details[case_id]} for case_id in RUN.CASES]


def log(events, summary="ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"):
    names = "".join(f"test {name} ... ok\n" for name in RUN.TIMELINE_TESTS)
    return (names + "\n".join(RUN.MARKER + json.dumps(event) for event in events)
            + "\ntest result: " + summary + "\n").encode()


class JudgeCanaries(unittest.TestCase):
    def test_consistent_synthetic_input_is_accepted_by_judge(self):
        self.assertEqual(RUN.judge(log(synthetic_events()))["status"], "HOST_SIMULATION_PASSED")

    def test_every_missing_case_stays_in_denominator(self):
        events = synthetic_events()
        for index in range(len(events)):
            result = RUN.judge(log(events[:index] + events[index + 1:]))
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["expected"], 10)
            self.assertEqual(result["observed"], 9)

    def test_double_counted_overlap_is_rejected(self):
        events = synthetic_events()
        events[1]["details"]["accounted_ns"] = 165
        self.assertEqual(RUN.judge(log(events))["status"], "INCOMPLETE")

    def test_lost_logs_or_evidence_upgrade_is_rejected(self):
        for field, value in [("dropped_events", 1), ("evidence_class", "physical"),
                             ("source_epoch", 4), ("timebase", "wall_clock")]:
            events = synthetic_events()
            events[0][field] = value
            self.assertEqual(RUN.judge(log(events))["status"], "INCOMPLETE")

    def test_failed_filtered_ignored_or_zero_test_summary_is_rejected(self):
        for summary in ["ok. 0 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out",
                        "FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
                        "ok. 6 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out", ""]:
            self.assertEqual(RUN.judge(log(synthetic_events(), summary))["status"], "INCOMPLETE")

    def test_duplicate_or_malformed_event_is_rejected(self):
        events = synthetic_events()
        events.append(copy.deepcopy(events[0]))
        self.assertEqual(RUN.judge(log(events))["status"], "INCOMPLETE")
        for extra in [b"FFW_V01_CASE {\n", b"FFW_V01_CASE []\n"]:
            self.assertEqual(RUN.judge(log(synthetic_events()) + extra)["status"], "INCOMPLETE")

    def test_input_and_event_size_are_bounded(self):
        self.assertEqual(RUN.judge(b"x" * (RUN.LIMIT + 1))["status"], "INCOMPLETE")
        self.assertEqual(RUN.judge(log(synthetic_events()) + RUN.MARKER.encode() + b"x" * 8193)["status"], "INCOMPLETE")

    def test_empty_log_is_incomplete(self):
        result = RUN.judge(b"")
        self.assertEqual((result["expected"], result["observed"], result["status"]), (10, 0, "INCOMPLETE"))

    def test_supplement_test_counts_cannot_be_reduced(self):
        good = b"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        self.assertEqual(RUN.judge_supplement(good, 6), [])
        self.assertTrue(RUN.judge_supplement(good.replace(b"6 passed", b"5 passed"), 6))
        self.assertTrue(RUN.judge_supplement(good.replace(b"0 failed", b"1 failed"), 6))
        self.assertTrue(RUN.judge_supplement(good + good, 6))
        self.assertTrue(RUN.judge_supplement(b"", 6))

    def test_only_the_named_queue_unit_invocation_allows_unrelated_filters(self):
        raw = b"test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out\n"
        raw += "".join(f"test {name} ... ok\n" for name in RUN.QUEUE_TESTS).encode()
        self.assertEqual(RUN.judge_supplement(raw, 4, queue_unit=True), [])
        self.assertTrue(RUN.judge_supplement(raw, 4))

    def test_broader_library_log_requires_every_named_queue_case(self):
        raw = b"test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        self.assertTrue(RUN.judge_supplement(raw, 4, queue_unit=True))
        cases = "".join(f"test {name} ... ok\n" for name in RUN.QUEUE_TESTS).encode()
        self.assertEqual(RUN.judge_supplement(raw + cases, 4, queue_unit=True), [])
        self.assertTrue(RUN.judge_supplement(raw + cases.replace(b" ... ok", b" ... FAILED", 1), 4, queue_unit=True))
        self.assertTrue(RUN.judge_supplement(raw.replace(b"0 failed", b"1 failed") + cases, 4, queue_unit=True))

    def test_event_supplement_requires_positive_and_refusal_records(self):
        summary = b"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        summary += "".join(f"test {name} ... ok\n" for name in RUN.ADAPTER_TESTS).encode()
        def event(kind):
            return ("FFW_V01_EVENT " + json.dumps({"schema_version": "ffw.log.v1", "event_kind": kind}) + "\n").encode()
        raw = summary + event("latency_estimated") * 2 + event("latency_refused")
        self.assertEqual(RUN.judge_supplement(raw, 6, events=True), [])
        self.assertTrue(RUN.judge_supplement(summary, 6, events=True))
        self.assertTrue(RUN.judge_supplement(summary + event("latency_estimated") * 3, 6, events=True))

    def test_every_timeline_test_result_line_is_required(self):
        raw = log(synthetic_events())
        for name in RUN.TIMELINE_TESTS:
            altered = raw.replace(f"test {name} ... ok\n".encode(), b"")
            self.assertEqual(RUN.judge(altered)["status"], "INCOMPLETE")

    def test_every_adapter_test_result_line_is_required(self):
        raw = b"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        raw += "".join(f"test {name} ... ok\n" for name in RUN.ADAPTER_TESTS).encode()
        for kind in ["latency_estimated", "latency_estimated", "latency_refused"]:
            raw += ("FFW_V01_EVENT " + json.dumps({"schema_version": "ffw.log.v1", "event_kind": kind}) + "\n").encode()
        self.assertEqual(RUN.judge_supplement(raw, 6, events=True), [])
        for name in RUN.ADAPTER_TESTS:
            altered = raw.replace(f"test {name} ... ok\n".encode(), b"")
            self.assertTrue(RUN.judge_supplement(altered, 6, events=True))

    def test_combined_log_selection_preserves_original_summary_and_ranges(self):
        prefix = b"running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        body = b"running 7 tests\n" + log(synthetic_events())
        raw = prefix + body
        section, provenance = RUN.select_section(raw, "timeline")
        self.assertEqual(section, body.rstrip(b"\n"))
        self.assertEqual(section, raw[provenance["byte_start"]:provenance["byte_end"]])
        self.assertEqual(RUN.judge(section)["status"], "HOST_SIMULATION_PASSED")
        with self.assertRaises(ValueError):
            RUN.select_section(raw + body, "timeline")

    def test_combined_log_never_hides_failed_parent_or_truncated_sections(self):
        body = b"running 7 tests\n" + log(synthetic_events())
        failed = b"running 1 test\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
        with self.assertRaises(ValueError):
            RUN.select_section(failed + body, "timeline")
        with self.assertRaises(ValueError):
            RUN.select_section(body + b"running 2 tests\n", "timeline")


if __name__ == "__main__":
    unittest.main()
