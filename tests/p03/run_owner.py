#!/usr/bin/env python3
"""Run P03's real host child-process owner tests through strict remote RCH.

This is host/loopback execution only, not BE fit, hardware, or provider proof.
Reuses the workspace runner's launch, timeout recovery, and libtest judge.
Combined stdout/stderr is drained continuously, capped at 8 MiB; any lost byte
fails qualification. Timeout leaves RCH alive with its existing recovery identity.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts/test/run-workspace-verification.py").is_file())
SPEC = importlib.util.spec_from_file_location("workspace_runner", ROOT / "scripts/test/run-workspace-verification.py")
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)
CAP = 8 << 20
REQUIRED = (
    "actual_stalled_child_yields_and_reactor_wakes_commit_before_file_reopen",
    "actual_cancelled_child_request_retains_custody_and_quiesces_before_recovery",
    "settled_owner_real_child_commit_and_stop_drain_custody_handoff",
    "normal_http_route_uses_real_pollable_journal_and_services_stop",
    "accepted_http_retires_after_original_mailbox_drop_without_consuming_replacement",
    "normal_owner_turn_drains_authenticated_datagrams_with_real_child_and_stop_fence",
)


def collect(source, sink, cap=CAP):
    """Drain even after the capture limit; return exact byte-loss accounting."""
    total = kept = 0
    digest = hashlib.sha256()
    read = getattr(source, "read1", source.read)
    while chunk := read(65536):
        total += len(chunk)
        digest.update(chunk)
        prefix = chunk[:max(0, cap - kept)]
        sink.write(prefix)
        sink.flush()
        kept += len(prefix)
    sink.flush()
    return {"seen_bytes": total, "retained_bytes": kept, "dropped_bytes": total - kept,
            "complete_stream_sha256": digest.hexdigest()}


def command(tier, worker=None):
    args = ["rch", "exec", "--source-content-receipt", "--json"]
    if worker:
        args += ["--worker", worker]
    args += ["--", "cargo", "test", "--locked", "-j", "1", "-p", "franken-speaker"]
    if tier == "full":
        args += ["-p", "franken-control", "--no-fail-fast"]
    else:
        args += ["--test", "journal_process"]
    return args + ["--features", "franken-speaker/journal-process", "--", "--test-threads=1"]


def libtest_blocks(text):
    # Cargo stderr metadata can arrive before or after stdout footers. Both
    # streams preserve their own order; pair metadata and complete blocks by
    # ordinal, never terminate a stdout block on an asynchronous header.
    headers, blocks, problems = [], [], []
    current = None
    outside = []
    for line in W._ANSI.sub("", text).splitlines():
        if re.match(r"^\s*(Running|Doc-tests)\s", line):
            headers.append(line.strip())
        start = re.fullmatch(r"running (\d+) tests?", line)
        row = re.fullmatch(r"test (.+?) \.\.\. (ok|FAILED|ignored.*)", line)
        footer = re.match(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured", line)
        if start:
            if current is not None:
                problems.append("unfinished stdout test block")
            current = {"announced": int(start[1]), "rows": []}
        elif row:
            if current is None:
                outside.append(row[1])
            else:
                current["rows"].append(row.groups())
        elif footer:
            if current is None:
                problems.append("footer without test start")
                continue
            current["counts"] = list(map(int, footer.groups()[1:]))
            rows = current["rows"]
            names = [name for name, _ in rows]
            counts = [sum(state == "ok" for _, state in rows), sum(state == "FAILED" for _, state in rows),
                      sum(state.startswith("ignored") for _, state in rows), 0]
            if (current["announced"] != len(rows) or len(names) != len(set(names))
                    or current["counts"] != counts or footer[1] != "ok"):
                problems.append("test lines, status, announcement or footer disagree")
            blocks.append(current)
            current = None
    if current is not None or len(headers) != len(blocks) or outside:
        problems.append("incomplete or ambiguous libtest block attribution")
    for block, header in zip(blocks, headers):
        block["header"] = header
    return blocks, problems


def journal_cases(text):
    blocks, problems = libtest_blocks(text)
    journal = [block for block in blocks if re.match(r"Running tests/journal_process\.rs \(", block.get("header", ""))]
    if len(journal) != 1:
        return list(REQUIRED), problems + ["journal_process invocation missing or repeated"]
    rows = journal[0]["rows"]
    missing = [name for name in REQUIRED if rows.count((name, "ok")) != 1]
    for block in blocks:
        if block is not journal[0] and any(name in REQUIRED for name, _ in block["rows"]):
            problems.append("required test name replayed outside journal_process")
    return missing, problems


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def source_receipt(text, argv, exit_code):
    """Observed receipt integrity/binding, NOT comparison to frozen source hashes."""
    lines = W._ANSI.sub("", text).splitlines()
    receipts = [line.split(":", 1)[1].strip() for line in lines
                if line.startswith("[RCH] source content receipt:")]
    terminal = []
    for line in lines:
        if line.startswith('{"api_version"'):
            terminal.append(json.loads(line, object_pairs_hook=unique_json))
    if len(receipts) != 1 or len(terminal) != 1:
        raise ValueError("requires exactly one source receipt and terminal RCH result")
    receipt = json.loads(receipts[0], object_pairs_hook=unique_json)
    done = terminal[0]
    fields = ("schema", "worker_id", "build_id", "command_sha256", "command_exit_code", "root_count", "roots")
    preimage = {key: receipt[key] for key in fields}
    digest = hashlib.sha256(json.dumps(preimage, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    admission = done["admission"]
    planned = argv[argv.index("--") + 1:]
    if (set(receipt) != set(fields) | {"receipt_root"}
            or receipt["schema"] != "rch.source_content_receipt.v1"
            or receipt["receipt_root"] != digest
            or done["api_version"] != "1.0" or done["location"] != "remote" or done["outcome"] != "completed"
            or type(receipt["command_exit_code"]) is not int or receipt["command_exit_code"] != exit_code
            or done["remote_exit_code"] != exit_code
            or admission["terminal_acknowledged"] is not True or admission["strict_remote"] is not True
            or receipt["build_id"] != admission["remote_build_id"]
            or receipt["worker_id"] != admission["worker_id"] or receipt["worker_id"] != done["worker_id"]
            or not re.fullmatch(r"[1-9][0-9]*", receipt["build_id"])
            or shlex.split(done["command"]) != planned
            or receipt["command_sha256"] != hashlib.sha256(done["command"].encode()).hexdigest()):
        raise ValueError("source receipt command/job/exit/integrity mismatch")
    roots = receipt["roots"]
    if not isinstance(roots, list) or not roots or type(receipt["root_count"]) is not int or receipt["root_count"] != len(roots):
        raise ValueError("invalid source root denominator")
    primary = []
    root_fields = ("schema", "ordinal", "project_id", "local_root", "remote_root", "root_hash",
                   "is_primary", "mode", "filter_policy", "file_count", "byte_count", "files")
    for ordinal, root in enumerate(roots):
        root_preimage = {key: root[key] for key in root_fields}
        root_digest = hashlib.sha256(json.dumps(root_preimage, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        files = root["files"]
        policy = root["filter_policy"]
        if (not isinstance(policy, dict) or policy.get("schema") != "rch.source_content_filter.v1"
                or type(policy.get("delete_extraneous")) is not bool
                or type(policy.get("checksum_transfer")) is not bool
                or any(policy.get(key) is not None and (not isinstance(policy[key], list)
                       or any(not isinstance(item, str) for item in policy[key]))
                       for key in ("include_patterns", "exclude_patterns"))):
            raise ValueError("invalid source filter witness")
        if (set(root) != set(root_fields) | {"content_root"}
                or root_digest != root["content_root"]
                or type(root["ordinal"]) is not int or root["ordinal"] != ordinal
                or type(root["is_primary"]) is not bool
                or type(root["file_count"]) is not int or type(root["byte_count"]) is not int
                or not isinstance(root["project_id"], str) or not root["project_id"]
                or not isinstance(root["local_root"], str) or not root["local_root"].startswith("/")
                or not isinstance(root["remote_root"], str) or not root["remote_root"].startswith("/")
                or not re.fullmatch(r"[0-9a-f]{64}", root["root_hash"])
                or root["schema"] != "rch.source_content_root.v1" or root["mode"] != "full"
                or not isinstance(files, list) or root["file_count"] != len(files)
                or root["byte_count"] != sum(f["byte_count"] for f in files)
                or len({f["path"] for f in files}) != len(files)
                or not re.fullmatch(r"[0-9a-f]{64}", root["content_root"])):
            raise ValueError("invalid source root witness")
        for entry in files:
            path = entry["path"]
            if (not isinstance(path, str) or path.startswith("/") or ".." in path.split("/")
                    or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                    or type(entry["byte_count"]) is not int or entry["byte_count"] < 0
                    or type(entry["executable"]) is not bool
                    or set(entry) != {"path", "sha256", "byte_count", "executable"}):
                raise ValueError("invalid source file witness")
        if root["is_primary"] is True:
            primary.append(root)
    if len(primary) != 1 or primary[0]["local_root"] != str(ROOT):
        raise ValueError("primary source root does not match invocation checkout")
    return {"receipt_root": digest, "command_sha256": receipt["command_sha256"],
            "source_content_roots": [root["content_root"] for root in roots],
            "qualification": "internal consistency only; not trusted-origin proof or frozen-source verification"}


def evaluate(case, outcome, loss, elapsed, argv=None, timeout_s=7200):
    # Reuse launch/transport judgment only; the generic parser mistakes Cargo's
    # asynchronous stderr headers for stdout test boundaries (observed full-v4).
    transport = case._replace(kind="cargo")
    result = W.judge(transport, outcome, duration_ms=elapsed, timeout_s=timeout_s)
    blocks, block_problems = libtest_blocks(outcome.output)
    result["tests_passed"] = sum(block["counts"][0] for block in blocks)
    if not result["tests_passed"]:
        block_problems.append("zero tests executed")
    missing, problems = journal_cases(outcome.output)
    problems += block_problems
    try:
        source = source_receipt(outcome.output, argv or case.argv, outcome.rc)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        source = None
        problems.append("missing, malformed, or unbound source receipt")
    result["required_cases_missing"] = missing
    result["protocol_problems"] = problems
    result["source_observation"] = source
    result["output_accounting"] = loss
    result["test_execution"] = "executed" if result.get("tests_passed", 0) else "not_run"
    if result["status"] == "passed" and (missing or problems or loss is None or loss.get("dropped_bytes") != 0):
        result.update(status="failed", completion="unconfirmed",
                      failure_reason="missing required executed cases, unbound source, or incomplete capture")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--worker")
    parser.add_argument("--timeout", type=float, default=7200)
    parser.add_argument("--collect", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.collect is not None:
        loss = collect(sys.stdin.buffer, sys.stdout.buffer)
        with args.collect.open("x") as output:
            json.dump(loss, output)
        return 0
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be positive and finite")
    root = ROOT / "build/p03-owner"
    root.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    cargo = command(args.tier, args.worker)
    loss_path = run / "output-accounting.json"
    # pipefail preserves a collector failure; PIPESTATUS also preserves the real
    # RCH exit. The workspace launcher owns .rc and timeout/recovery custody.
    pipeline = 'set -o pipefail; collector=$1; loss=$2; py=$3; shift 3; "$@" 2>&1 | "$py" "$collector" --collect "$loss"; exit $?'
    wrapped = ["/bin/bash", "-c", pipeline, "p03-owner", str(Path(__file__).resolve()),
               str(loss_path), sys.executable, *cargo]
    case = W.Case("p03_owner_" + args.tier, "cargo-test", wrapped, ROOT)
    env = W.child_env(os.environ, remote=True)
    started = time.monotonic()
    try:
        outcome = W.launch(wrapped, cwd=str(ROOT), env=env, timeout_s=args.timeout,
                           log_dir=run, name=case.case_id)
    except OSError as error:
        outcome = W.Outcome(rc=None, capture_error=f"launcher: {error}")
    try:
        loss = json.loads(loss_path.read_text())
    except (OSError, ValueError):
        loss = None
    result = evaluate(case, outcome, loss, int((time.monotonic() - started) * 1000), cargo, args.timeout)
    result["recovery_guidance"] = (
        "The recorded PID is the local wrapper, not the native remote job. "
        "Read the retained RCH job identity and use rch jobs --help for supported same-ID recovery; "
        "do not relaunch or kill the client. This adapter has no --recover command. "
        "Reanalyze only after terminal ACK/source custody release and the same .rc appears."
    )
    result.update(scope="host-loopback-only", tier=args.tier, remote_required=True,
                  command=cargo,
                  git_head=W.git_commit_short(), log_dir=str(run),
                  full_p03_qualified=False)
    text = json.dumps(result, indent=2) + "\n"
    (run / "result.json").write_text(text)
    # Full recovery paths stay in the ignored local result. Public stdout has
    # only an explicit safe subset, never worker identities or absolute paths.
    public = {key: result[key] for key in ("status", "completion", "tests_passed", "test_execution",
              "required_cases_missing", "protocol_problems", "source_observation", "output_accounting",
              "scope", "tier", "remote_required", "full_p03_qualified")}
    public["logs"] = "build/p03-owner/" + run.name
    print(json.dumps(public, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
