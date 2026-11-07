#!/usr/bin/env python3
"""N05 focused offline experiment driver. Never compiles, contacts devices, or admits FEC."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import SCENARIOS, SEED, STRATEGIES, check_result
import remote
import capture

CASES = {f"N05-{scenario.replace('_', '-').upper()}": scenario for scenario in SCENARIOS}
RUST_CASES = {
    "N05-DECODE-MEMORY": ("n05_actual_decode_peak_heap_upper_bound_includes_temporary_allocations",),
    "N05-MALFORMED-SYMBOLS": ("n05_malformed_metadata_does_not_enter_the_coder", "n05_invalid_decode_symbols_refuse_before_matrix_allocation"),
    "N05-LATE-DECODED-BEFORE-DAC": ("n05_actual_decoded_bytes_rejected_after_consume_before_dac",),
}
MAX_RESULT_BYTES = 256 * 1024
MAX_DIAGNOSTIC_BYTES = 2 * 1024 * 1024
WALL_LIMIT_SECONDS = 10
CPU_LIMIT_SECONDS = 5
ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def invoke(worker, scenario, strategy):
    request = {"scenario": scenario, "strategy": strategy, "seed": SEED}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    bounded = capture.worker([str(worker)], json.dumps(request).encode(), WALL_LIMIT_SECONDS,
                             MAX_RESULT_BYTES, preexec=limits)
    stdout, stderr = bounded["stdout"], bounded["stderr"]
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if stderr:
        sys.stderr.write(remote.redact(stderr.decode("utf-8", errors="replace"))[:4096])
    assert bounded["stop_reason"] is None, "worker capture failed: " + str(bounded["stop_reason"])
    assert len(stdout) <= MAX_RESULT_BYTES and len(stderr) <= MAX_RESULT_BYTES, "critical evidence size cap exceeded"
    assert bounded["returncode"] == 0, f"worker failed exit={bounded['returncode']}"
    result = json.loads(stdout)
    result["process_observation"] = {
        "host_elapsed_ns": time.monotonic_ns() - started,
        "host_child_cpu_ns": int(((after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)) * 1_000_000_000),
        "address_space_limit_bytes": ADDRESS_SPACE_BYTES,
        "cpu_limit_seconds": CPU_LIMIT_SECONDS,
        "wall_limit_seconds": WALL_LIMIT_SECONDS,
        "retained_output_bytes": bounded["retained_bytes"],
        "stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "measurement": "isolated-host-worker; process CPU includes sender and receiver; not board CPU",
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--worker", type=Path)
    source.add_argument("--judge", type=Path, help="judge one remote Cargo log without executing Rust locally")
    parser.add_argument("--observe-only", action="store_true", help="collect real worker observations; cannot qualify")
    parser.add_argument("--unit-log", type=Path, help="central Rust test log including franken-alloc-probe")
    parser.add_argument("--tier", choices=("smoke", "full", "soak"), default="full")
    parser.add_argument("--receipts", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    selected = list(CASES) if args.tier != "smoke" else ["N05-CLEAN", "N05-POSITIVE-RECOVERY", "N05-CODING-WINDOW-OUTAGE"]
    rust_selected = list(RUST_CASES) if args.tier != "smoke" else ["N05-DECODE-MEMORY"]
    if args.list:
        print("\n".join(selected + rust_selected))
        return 0
    if args.tier == "soak":
        print("N05 soak NOT RUN: short offline experiment is not the 24-hour baseline or board qualification")
        return 4
    if args.observe_only and (args.worker is None or args.unit_log is not None or args.receipts is not None):
        parser.error("observe-only requires --worker and emits observations only, without unit-proof or qualification receipts")
    if args.judge is not None:
        if args.unit_log is not None:
            parser.error("--judge requires all observations and unit proof from the same Cargo log")
        return remote.judge(args.judge, selected, rust_selected, CASES, RUST_CASES, args.receipts)
    if args.worker is None:
        print(json.dumps({"passed": 0, "failed": 0, "blocked": len(selected + rust_selected), "not_run": 0,
                          "cases": selected + rust_selected, "reason": "remote Cargo --judge log or admitted Linux --worker is required"}))
        return 3
    if sys.platform != "linux":
        parser.error("direct worker execution requires an admitted Linux host; use --judge on this host")
    worker = args.worker.resolve()
    if not worker.is_file() or not os.access(worker, os.X_OK):
        parser.error("worker must be an existing executable regular file")
    worker_digest = remote.file_digest(worker)
    unit_log = None
    if args.unit_log is not None:
        unit_log = remote.read_log(args.unit_log)
    records = []
    diagnostics = []
    passed = failed = blocked = 0
    observation_run = remote.common(worker_digest)
    raw_observations = 0
    if args.observe_only:
        remote.emit("N05-RUN-BEGIN", dict(observation_run, monotonic_ns=time.monotonic_ns(), case_ids=selected))
    for case_id in selected:
        scenario = CASES[case_id]
        diagnostics.append({"schema": "n05.diagnostics.v1", "case_id": case_id, "correlation_id": case_id,
                            "source_epoch": 1, "run_id": observation_run["run_id"], "event": "begin", "monotonic_ns": time.monotonic_ns()})
        if args.observe_only:
            remote.emit("N05-DIAGNOSTIC", diagnostics[-1])
        try:
            results = []
            for strategy in STRATEGIES:
                result = invoke(worker, scenario, strategy)
                records.append(result)
                results.append(result)
                if args.observe_only:
                    remote.emit("N05-OBSERVED", remote.observation(observation_run, case_id, "strategy", result))
                    raw_observations += 1
            for result in results:
                check_result(result)
                remote.check_process(result)
            assert len({result["source_trace_sha256"] for result in results}) == 1, "strategies used different loss schedules"
            assert len({result["payload_sha256"] for result in results}) == 1, "strategies used different content"
            if scenario == "positive_recovery":
                assert results[0]["resources"]["concealed_blocks"] == 2
                assert results[2]["resources"]["concealed_blocks"] == 0
            if scenario == "cancelled":
                # New process/new decoder has no cancelled-window residue; actual recovery is required.
                restart = invoke(worker, "positive_recovery", "raptorq")
                records.append(restart)
                if args.observe_only:
                    remote.emit("N05-OBSERVED", remote.observation(observation_run, case_id, "restart", restart))
                    raw_observations += 1
                check_result(restart)
                remote.check_process(restart)
                assert restart["repair"]["admitted"] == 2
            # Plant a causal byte-output corruption and require the independent oracle to reject it.
            corrupted = json.loads(json.dumps(results[0]))
            corrupted["output"][0]["payload_sha256"] = "00" * 32
            try:
                check_result(corrupted)
            except AssertionError as error:
                assert "audio block=0" in str(error)
            else:
                raise AssertionError("independent oracle accepted planted byte corruption")
            if not args.observe_only:
                if unit_log is None:
                    raise remote.MissingEvidence("central Rust unit/allocation log missing")
                for name in remote.SCENARIO_UNITS[case_id]:
                    remote.require_unit(unit_log, name)
                assert "test result: FAILED" not in unit_log, "central Cargo batch failed"
                if case_id == "N05-WORK-EXHAUSTED":
                    remote.check_gate_control(unit_log)
                if case_id in ("N05-LATE-REPAIR", "N05-PARTIAL-SALVAGE", "N05-WORK-EXHAUSTED"):
                    remote.check_render_control(unit_log)
                if remote.HYBRID_PREFIX in remote.SCENARIO_UNITS[case_id]:
                    remote.check_prefix_control(unit_log)
                if remote.TAIL_ADMISSION in remote.SCENARIO_UNITS[case_id]:
                    remote.check_tail_controls(unit_log)
            passed += 1
            state, cause = "observed" if args.observe_only else "passed", None
        except remote.MissingEvidence as error:
            blocked += 1
            state, cause = "blocked", str(error)[:1024]
        except (AssertionError, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
            failed += 1
            state, cause = "failed", str(error)[:1024]
        diagnostics.append({"schema": "n05.diagnostics.v1", "case_id": case_id, "correlation_id": case_id,
                            "source_epoch": 1, "run_id": observation_run["run_id"], "event": "end", "state": state, "first_causal_event": cause,
                            "monotonic_ns": time.monotonic_ns(), "replay": f"scripts/e2e/n05 --tier {args.tier} --worker <same-binary>",
                            "profile": "n05.rfc6330.k4-r4.v4", "worker_sha256": worker_digest})
        if args.observe_only:
            remote.emit("N05-DIAGNOSTIC", diagnostics[-1])
        print(f"{case_id}: {state}" + (f" ({cause})" if cause else ""))
    if args.observe_only:
        remote.emit("N05-RUN-END", dict(observation_run, monotonic_ns=time.monotonic_ns(),
                    case_ids=selected, observations=raw_observations, observed_cases=passed, failed=failed,
                    critical_evidence_lost=0, expected_qualification_cases=len(selected + rust_selected),
                    passed=0, blocked=len(selected + rust_selected)))
        # Collection success is not qualification: passed=0, qualified=false, all cases blocked.
        return 1 if failed or blocked else 0
    for case_id in rust_selected:
        if unit_log is None:
            blocked += 1
            print(f"{case_id}: blocked (central Rust unit/allocation log missing)")
            continue
        try:
            for name in RUST_CASES[case_id]:
                remote.require_unit(unit_log, name)
            assert "test result: FAILED" not in unit_log, "central Cargo batch failed"
            if case_id == "N05-DECODE-MEMORY":
                memory = remote.check_memory(unit_log)
                records.append({"decode_memory_observation": memory})
            passed += 1
            print(f"{case_id}: passed")
        except remote.MissingEvidence as error:
            blocked += 1
            print(f"{case_id}: blocked ({str(error)[:1024]})")
        except (AssertionError, ValueError, KeyError, TypeError) as error:
            failed += 1
            print(f"{case_id}: failed ({str(error)[:1024]})")
    summary = {"schema": "n05.receipt.v1", "tier": args.tier, "seed": SEED, "worker_sha256": worker_digest,
               "build_recipe": "n05.host-test-o3-d0.v1",
               "command": ["scripts/e2e/n05", "--tier", args.tier, "--worker", "<sha256-bound-binary>"],
               "expected": len(selected + rust_selected), "passed": passed, "failed": failed, "blocked": blocked, "not_run": 0,
               "diagnostics_dropped": 0, "evidence_class": "offline-host-synthetic", "profile_admission": "pending",
               "external_not_measured": ["board CPU", "kernel/driver/DMA memory", "physical DAC", "acoustics", "provider", "deployment", "24-hour baseline"]}
    if args.receipts:
        # Evidence writes are after all playout decisions. Slow/full/unavailable sinks cannot
        # alter deadlines; any write failure fails this run instead of inventing a receipt.
        try:
            args.receipts.mkdir(parents=True, exist_ok=True)
            artifact = json.dumps({"summary": summary, "results": records}, sort_keys=True).encode() + b"\n"
            log = b"".join(json.dumps(item, sort_keys=True).encode() + b"\n" for item in diagnostics)
            assert len(artifact) <= MAX_DIAGNOSTIC_BYTES and len(log) <= MAX_DIAGNOSTIC_BYTES, "critical diagnostic cap exceeded"
            # Unique run suffix prevents a rerun from overwriting an earlier failure.
            suffix = str(time.time_ns())
            (args.receipts / f"n05-{suffix}.json").write_bytes(artifact)
            (args.receipts / f"n05-{suffix}.jsonl").write_bytes(log)
        except (OSError, AssertionError) as error:
            print(f"N05 critical evidence unavailable: {type(error).__name__}", file=sys.stderr)
            return 1
    print(json.dumps(summary, sort_keys=True))
    return 1 if failed else (3 if blocked else 0)


if __name__ == "__main__":
    raise SystemExit(main())
