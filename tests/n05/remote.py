"""N05-only remote observation protocol and independent Cargo-log judge."""
import hashlib
import os
import stat
import functools
import importlib.util
import json
from pathlib import Path
import re
import time
import sys
import tempfile

from oracle import SEED, STRATEGIES, check_result

PROFILE = "n05.rfc6330.k4-r4.v4"
LIBRARY = "asupersync@14032b8f2c832ee7ef1946404f5efb18162af045"
REMOTE_TEST = "n05_remote_worker_observations_complete"
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
SCENARIO_UNITS = {
    "N05-CLEAN": ("n05_rfc6330_positive_two_erasure_recovery_and_zero_loss_cost",),
    "N05-INDEPENDENT": ("n05_same_media_trace_packetization_cutoffs_and_allowance", "n05_host_reserve_violation_never_retimes_trace"),
    "N05-BURST": ("n05_same_media_trace_packetization_cutoffs_and_allowance", "n05_entire_coding_window_is_unrecoverable_not_a_fec_win", "n05_host_reserve_violation_never_retimes_trace"),
    "N05-CODING-WINDOW-OUTAGE": ("n05_entire_coding_window_is_unrecoverable_not_a_fec_win",),
    "N05-POSITIVE-RECOVERY": ("n05_rfc6330_positive_two_erasure_recovery_and_zero_loss_cost",),
    "N05-LATE-REPAIR": ("n05_late_and_exhausted_repairs_never_starve_the_next_block",),
    "N05-PARTIAL-SALVAGE": ("n05_partial_salvage_keeps_the_still_live_block_and_n04_counts_late",),
    "N05-WORK-EXHAUSTED": ("n05_late_and_exhausted_repairs_never_starve_the_next_block", "n05_inline_overrun_control_exposes_why_work_admission_matters", "n05_gate_deadline_and_allowance_boundaries_preserve_permitted_work"),
    "N05-CANCELLED": ("n05_late_and_exhausted_repairs_never_starve_the_next_block", "n05_restart_reproduces_trace_without_retaining_cancelled_window"),
}
GATE_BOUNDARY = "n05_gate_deadline_and_allowance_boundaries_preserve_permitted_work"
RENDER_BOUNDARY = "n05_render_work_is_protected_through_the_permitted_end_boundary"
HYBRID_CORE = "n05_hybrid_executes_fec_then_a_bounded_tail_for_remaining_originals"
HYBRID_FAILURE = "n05_hybrid_deadline_work_cancel_and_restart_keep_real_recovery"
HYBRID_REFUSAL = "n05_hybrid_tail_has_a_permitted_path_and_zero_side_effect_refusals"
HYBRID_PREFIX = "n05_hybrid_tail_uses_only_the_observed_prefix_not_future_deliveries"
REQUEST_PARITY = "n05_retransmit_and_hybrid_tail_share_the_same_admission_ledger"
TAIL_ADMISSION = "n05_hybrid_tail_actual_late_and_duplicate_use_n04_admission"
for case_id in ("N05-CLEAN", "N05-INDEPENDENT", "N05-POSITIVE-RECOVERY", "N05-BURST", "N05-CODING-WINDOW-OUTAGE"):
    SCENARIO_UNITS[case_id] += (HYBRID_CORE, HYBRID_PREFIX)
for case_id in ("N05-LATE-REPAIR", "N05-PARTIAL-SALVAGE", "N05-WORK-EXHAUSTED"):
    SCENARIO_UNITS[case_id] = tuple(dict.fromkeys(SCENARIO_UNITS[case_id] +
        (GATE_BOUNDARY, RENDER_BOUNDARY, HYBRID_REFUSAL, HYBRID_FAILURE)))
SCENARIO_UNITS["N05-CANCELLED"] += (HYBRID_FAILURE, HYBRID_REFUSAL, HYBRID_PREFIX)
for case_id in SCENARIO_UNITS:
    SCENARIO_UNITS[case_id] += (REQUEST_PARITY,)
for case_id in ("N05-BURST", "N05-LATE-REPAIR", "N05-PARTIAL-SALVAGE", "N05-WORK-EXHAUSTED"):
    SCENARIO_UNITS[case_id] += (TAIL_ADMISSION,)


class MissingEvidence(Exception):
    """A required observation/test did not execute or its evidence was lost."""


REPO = Path(__file__).resolve().parents[2]


@functools.lru_cache(maxsize=2)
def shared_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def redact(text):
    return shared_module("n05_shared_diagnostics", "scripts/test/test_support/diagnostics.py").redact_text(text)


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_log(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOG_BYTES:
            raise ValueError("central log must be a regular file no larger than 8MiB")
        data = source.read(MAX_LOG_BYTES + 1)
    assert len(data) <= MAX_LOG_BYTES, "central log grew beyond bound"
    return data.decode("utf-8")


@functools.lru_cache(maxsize=2)
def parsed_tests(log):
    # Reuse D01/N04's header/section and split --nocapture attribution, over a private
    # snapshot of the bounded bytes judged. No ad-hoc terminal-name regex can qualify.
    parser = shared_module("n05_d01_logs", "tests/d01/run_cases.py").Logs()
    with tempfile.TemporaryDirectory(prefix="n05-log-parser-") as directory:
        snapshot = Path(directory) / "central.log"
        snapshot.write_text(log, encoding="utf-8")
        parser.add(str(snapshot))
    return parser


def emit(prefix, record):
    print(prefix + " " + json.dumps(record, sort_keys=True), flush=True)


def common(worker_digest):
    return {"schema": "n05.observation-run.v1", "mode": "observe-only", "qualified": False,
            "run_id": str(time.time_ns()), "profile": PROFILE, "library": LIBRARY,
            "seed": SEED, "worker_sha256": worker_digest}


def observation(run, case_id, role, result):
    return {"schema": "n05.observation.v1", "run_id": run["run_id"],
            "worker_sha256": run["worker_sha256"], "case_id": case_id, "role": role, "result": result}


def extract(log, prefix):
    records = []
    for line in log.splitlines():
        at = line.find(prefix + " ")
        if at >= 0:
            body = line[at + len(prefix) + 1:]
            assert len(body.encode()) <= MAX_LINE_BYTES, "critical observation line exceeds cap"
            records.append(json.loads(body))
    return records


def require_unit(log, name):
    if re.search(r"\btest \S+ \.\.\. (?:okFAILED|FAILEDok|ignoredok|okignored)\b", log):
        raise MissingEvidence("ambiguous concatenated Rust result tokens")
    parser = parsed_tests(log)
    if name == REMOTE_TEST:
        stem, full = "n05_remote_observations", name
    elif name in ("n05_actual_decode_peak_heap_upper_bound_includes_temporary_allocations", "n05_invalid_decode_symbols_refuse_before_matrix_allocation"):
        stem, full = "n05_decode_memory", name
    elif name.startswith("n05_"):
        prefix = "model::boundary_tests::" if name in (GATE_BOUNDARY, RENDER_BOUNDARY, HYBRID_REFUSAL, HYBRID_PREFIX) else "tests::"
        stem, full = "n05_repair_study", prefix + name
    else:  # parser-only controls, not qualification names
        stem, full = "n05_repair_study", name
    status = parser.test_status(stem, full)
    if status is None:
        raise MissingEvidence(f"missing required Rust case: {name}")
    if status in ("ignored", "AMBIGUOUS"):
        raise MissingEvidence(f"ignored required Rust case: {name}")
    assert status == "ok", f"failed required Rust case: {name}"


def map_complete(rust_cases):
    mapped = {name for names in SCENARIO_UNITS.values() for name in names}
    mapped.update(name for names in rust_cases.values() for name in names)
    mapped.add(REMOTE_TEST)
    actual = set()
    for relative in ("src/tests.rs", "src/model.rs", "tests/n05_decode_memory.rs", "tests/n05_remote_observations.rs"):
        text = (REPO / "toolchain/n05-repair-study" / relative).read_text(encoding="utf-8")
        actual.update(re.findall(r"fn\s+(n05_[A-Za-z0-9_]+)\s*\(", text))
    assert actual == mapped, "N05 named Rust test registry is incomplete or stale"


def check_process(result):
    process = result["process_observation"]
    assert process["host_elapsed_ns"] > 0 and process["host_child_cpu_ns"] > 0
    assert process["address_space_limit_bytes"] == 1024 ** 3
    assert process["cpu_limit_seconds"] == 5 and process["wall_limit_seconds"] == 10
    assert process["retained_output_bytes"] <= 256 * 1024 and process["stderr_bytes"] == 0
    # Whole-study process RSS is never added to the allocator-derived decoder heap bound.
    assert result["resources"]["decode_process_peak_rss_bytes"] > 0, "host RSS observation missing"


def check_memory(log):
    records = extract(log, "N05-DECODE-MEMORY")
    if not records:
        raise MissingEvidence("actual decoder allocation observation missing")
    assert len(records) == 1, "decoder allocation observation duplicated"
    memory = records[0]
    assert memory["schema"] == "n05.decode-memory.v2" and memory["profile"] == PROFILE
    assert memory["seed"] == SEED and memory["expected_subsets"] == memory["observed_subsets"] == 163
    patterns = memory["patterns"]
    assert [item["mask"] for item in patterns] == [mask for mask in range(256) if mask.bit_count() >= 4]
    recovered = deficient = 0
    for item in patterns:
        assert item["received_symbols"] == item["mask"].bit_count()
        assert item["allocation_calls"] > 0 and item["deallocation_calls"] > 0 and item["cumulative_decode_requested_bytes"] > 4096
        assert item["decode_peak_heap_upper_bound_bytes"] == item["retained_input_heap_bytes"] + item["cumulative_decode_requested_bytes"]
        assert item["decode_peak_heap_upper_bound_bytes"] <= 1024 ** 2
        if item["rank_deficit"] == 0:
            assert item["status"] == "recovered"
            recovered += 1
        else:
            assert item["rank_deficit"] > 0 and item["status"] == "rank_deficient"
            deficient += 1
    assert memory["recovered_subsets"] == recovered and memory["rank_deficient_subsets"] == deficient
    assert memory["decode_peak_heap_upper_bound_bytes"] == max(item["decode_peak_heap_upper_bound_bytes"] for item in patterns)
    assert memory["limit_bytes"] == 1024 ** 2
    return memory


def check_gate_control(log):
    controls = extract(log, "N05-GATE-OBSERVED")
    assert len(controls) == 2 and {item["strategy"] for item in controls} == {"retransmit", "raptorq"}
    for item in controls:
        assert item["schema"] == "n05.gate-control.v1"
        assert item["planted_virtual_job_ns"] == 600000000 > item["shared_window_allowance_ns"] == 20000000
        assert item["guarded_next_outcome"] == "real" and item["guarded_next_late_ns"] == 0
        assert item["bypassed_next_outcome"] == "muted_overdue" and item["bypassed_next_late_ns"] > 100000000


def read_campaign(log, selected, cases):
    begins, ends = extract(log, "N05-RUN-BEGIN"), extract(log, "N05-RUN-END")
    if not begins or not ends:
        raise MissingEvidence("complete remote observation campaign missing")
    assert len(begins) == len(ends) == 1, "multiple campaigns cannot launder a failed run"
    begin, end = begins[0], ends[0]
    for entry in (begin, end):
        assert entry["schema"] == "n05.observation-run.v1" and entry["mode"] == "observe-only"
        assert entry["qualified"] is False, "collector attempted self-qualification"
        assert entry["profile"] == PROFILE and entry["library"] == LIBRARY and entry["seed"] == SEED
        assert re.fullmatch("[0-9a-f]{64}", entry["worker_sha256"])
    assert begin["run_id"] == end["run_id"] and begin["worker_sha256"] == end["worker_sha256"]
    assert begin["monotonic_ns"] <= end["monotonic_ns"]
    campaign_cases = begin["case_ids"]
    assert isinstance(campaign_cases, list) and len(campaign_cases) == len(set(campaign_cases))
    assert campaign_cases == end["case_ids"] and all(case_id in cases for case_id in campaign_cases)
    if not all(case_id in campaign_cases for case_id in selected):
        raise MissingEvidence("remote campaign omitted required named cases")
    assert end["failed"] == end["critical_evidence_lost"] == 0, "remote worker or critical evidence failed"
    assert end["observed_cases"] == len(campaign_cases)
    observations = extract(log, "N05-OBSERVED")
    expected = len(STRATEGIES) * len(campaign_cases) + (1 if "N05-CANCELLED" in campaign_cases else 0)
    if len(observations) < expected:
        raise MissingEvidence("mandatory actual worker observation missing")
    assert len(observations) == end["observations"] == expected, "duplicate or unexpected worker observation"
    by_case = {case_id: {} for case_id in campaign_cases}
    for item in observations:
        assert item["schema"] == "n05.observation.v1"
        assert item["run_id"] == begin["run_id"] and item["worker_sha256"] == begin["worker_sha256"]
        case_id, role, result = item["case_id"], item["role"], item["result"]
        assert case_id in by_case and role in ("strategy", "restart")
        key = result["input"]["strategy"] if role == "strategy" else "restart"
        assert key not in by_case[case_id], "duplicate strategy observation"
        assert role != "restart" or case_id == "N05-CANCELLED"
        assert result["input"]["scenario"] == ("positive_recovery" if role == "restart" else cases[case_id])
        assert result["input"]["seed"] == SEED
        by_case[case_id][key] = result
    diagnostics = extract(log, "N05-DIAGNOSTIC")
    assert len(diagnostics) == len(campaign_cases) * 2, "critical begin/end diagnostic missing or duplicated"
    for case_id in campaign_cases:
        pair = [item for item in diagnostics if item["case_id"] == case_id]
        assert len(pair) == 2 and [item["event"] for item in pair] == ["begin", "end"]
        assert all(item["schema"] == "n05.diagnostics.v1" and item["run_id"] == begin["run_id"] and item["source_epoch"] == 1 for item in pair)
        assert pair[0]["monotonic_ns"] <= pair[1]["monotonic_ns"]
        assert pair[1]["state"] == "observed" and pair[1]["first_causal_event"] is None
    require_unit(log, REMOTE_TEST)
    return begin["worker_sha256"], by_case, observations, diagnostics


def check_observed_case(case_id, observed):
    results = [observed[strategy] for strategy in STRATEGIES]
    for result in results:
        check_result(result)  # Independent PCM/timeline/repair oracle re-executed locally.
        check_process(result)
    assert len({item["source_trace_sha256"] for item in results}) == 1
    assert len({item["payload_sha256"] for item in results}) == 1
    if case_id == "N05-POSITIVE-RECOVERY":
        assert results[0]["resources"]["concealed_blocks"] == 2
        assert results[2]["resources"]["concealed_blocks"] == 0
    if case_id == "N05-CANCELLED":
        if "restart" not in observed:
            raise MissingEvidence("actual restarted worker observation missing")
        restarted = observed["restart"]
        assert restarted["input"] == {"scenario": "positive_recovery", "strategy": "raptorq", "seed": SEED}
        check_result(restarted)
        check_process(restarted)
        assert restarted["repair"]["admitted"] == 2
    corrupted = json.loads(json.dumps(results[0]))
    corrupted["output"][0]["payload_sha256"] = "00" * 32
    try:
        check_result(corrupted)
    except AssertionError as error:
        assert "audio block=0" in str(error)
    else:
        raise AssertionError("independent oracle accepted planted byte corruption")


def check_render_control(log):
    controls = extract(log, "N05-RENDER-OBSERVED")
    assert len(controls) == 1
    control = controls[0]
    assert control["schema"] == "n05.render-control.v1" and control["reserved_ns"] == 2000000
    assert control["guarded_end_ns"] == control["reserved_end_ns"]
    assert control["unguarded_decision_late_ns"] == 0
    assert control["unguarded_render_late_ns"] > 0, "counterexample must expose the decision-only gap"


def check_prefix_control(log):
    controls = extract(log, "N05-PREFIX-OBSERVED")
    assert len(controls) == 1
    proof = controls[0]
    assert proof["schema"] == "n05.prefix-control.v1"
    assert proof["prefix_symbols"] > 0 and proof["admitted"] > 0
    assert proof["earlier_requests_equal"] is True and proof["later_prefixes_differ"] is True
    assert proof["wrong_collector_rejected"] is True, "the real planning seam must reject a future-reading collector"


def check_tail_controls(log):
    controls = extract(log, "N05-TAIL-OBSERVED")
    assert len(controls) == 2 and {item["kind"] for item in controls} == {"late", "duplicate"}
    for proof in controls:
        assert proof["schema"] == "n05.tail-control.v1" and proof["next_block_real"] is True
        counts = proof["accounting"]
        assert counts["received"] == counts["admitted_to_playout"] + counts["late"] + counts["duplicate"]
        if proof["kind"] == "late":
            assert (counts["admitted"], counts["received"], counts["admitted_to_playout"], counts["late"], counts["duplicate"]) == (2, 2, 0, 2, 0)
            assert proof["unrecovered_blocks"] == [4, 5]
        else:
            assert (counts["received"], counts["admitted_to_playout"], counts["late"], counts["duplicate"]) == (32, 16, 0, 16)
            assert proof["unrecovered_blocks"] == [19]


def judge(path, selected, rust_selected, cases, rust_cases, receipts):
    all_cases = selected + rust_selected
    passed = failed = blocked = 0
    observations, diagnostics, worker_digest = [], [], None
    try:
        map_complete(rust_cases)
        log = read_log(path)
        worker_digest, by_case, observations, diagnostics = read_campaign(log, selected, cases)
    except MissingEvidence as error:
        print(json.dumps({"expected": len(all_cases), "passed": 0, "failed": 0, "blocked": len(all_cases), "not_run": 0, "reason": str(error)}))
        return 3
    except (AssertionError, ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"expected": len(all_cases), "passed": 0, "failed": len(all_cases), "blocked": 0, "not_run": 0, "reason": str(error)[:1024]}))
        return 1
    for case_id in all_cases:
        try:
            assert "test result: FAILED" not in log, "central Cargo batch failed"
            if case_id in cases:
                check_observed_case(case_id, by_case[case_id])
                names = SCENARIO_UNITS[case_id]
            else:
                names = rust_cases[case_id]
            for name in names:
                require_unit(log, name)
            if case_id == "N05-DECODE-MEMORY":
                observations.append({"decode_memory_observation": check_memory(log)})
            if case_id == "N05-WORK-EXHAUSTED":
                check_gate_control(log)
            if case_id in ("N05-LATE-REPAIR", "N05-PARTIAL-SALVAGE", "N05-WORK-EXHAUSTED"):
                check_render_control(log)
            if HYBRID_PREFIX in names:
                check_prefix_control(log)
            if TAIL_ADMISSION in names:
                check_tail_controls(log)
            passed += 1
            print(f"{case_id}: passed")
        except MissingEvidence as error:
            blocked += 1
            print(f"{case_id}: blocked ({str(error)[:1024]})")
        except (AssertionError, ValueError, KeyError, TypeError) as error:
            failed += 1
            print(f"{case_id}: failed ({str(error)[:1024]})")
    summary = {"schema": "n05.receipt.v1", "mode": "central-log-judge", "seed": SEED,
               "build_recipe": "n05.host-test-o3-d0.v1",
               "observed_build_profile": by_case[selected[0]].get("concealment", {}).get("build_profile"),
               "worker_sha256": worker_digest, "central_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
               "expected": len(all_cases), "passed": passed, "failed": failed, "blocked": blocked, "not_run": 0,
               "diagnostics_dropped": 0, "evidence_class": "offline-host-synthetic", "profile_admission": "pending"}
    if receipts:
        try:
            artifact = json.dumps({"summary": summary, "observations": observations}, sort_keys=True).encode() + b"\n"
            evidence = b"".join(json.dumps(item, sort_keys=True).encode() + b"\n" for item in diagnostics)
            assert len(artifact) <= 2 * 1024 ** 2 and len(evidence) <= 2 * 1024 ** 2
            receipts.mkdir(parents=True, exist_ok=True)
            suffix = str(time.time_ns())
            (receipts / f"n05-{suffix}.json").write_bytes(artifact)
            (receipts / f"n05-{suffix}.jsonl").write_bytes(evidence)
        except (AssertionError, OSError) as error:
            print(f"N05 critical judge evidence unavailable: {type(error).__name__}")
            return 1
    print(json.dumps(summary, sort_keys=True))
    return 1 if failed else (3 if blocked else 0)
