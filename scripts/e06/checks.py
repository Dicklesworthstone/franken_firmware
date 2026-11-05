#!/usr/bin/env python3
"""E06 (bead ffw-unk): verify and redact the central ``cargo check`` results.  Stdlib only, offline.

A results file (JSON lines: crate, target, status, evidence, note) is a CLAIM by whoever ran the planned checks.
``audit.py audit --build-results`` folds such claims into the report by crate, target and status alone, so a row
that says ``pass`` is believed.  This module is what makes the claim checkable before it is folded in:

* it reads the raw per-line log each row points at and requires the log to say the same thing: the command RCH ran
  on the worker is exactly the planned command (RCH's own ``--config env.RCH_*`` trailer and independently bound
  source-pair output-directory overrides aside), the remote exit
  status is the row's ``rc`` and is 0 exactly when the row says ``pass``, a ``Finished`` line is present, and the
  worker and revision in the row's note are the log's and the expected revision;
* it requires the denominator to match: every planned check has exactly one result and no result is for a check
  that was not planned;
* it writes a REDACTED record per check and never copies a log line.  Raw RCH logs carry the worker's network
  address, the local absolute paths of the machine that ran them and the worker's home directory, none of which
  may be committed to this public repository.  The record keeps what a reader needs (the exact command, the exit
  status, the elapsed time, how many units were type-checked, warning and error counts) and the sha256 and size of
  the raw log, so the log can be produced later and shown to be the one that was summarized.

What a ``pass`` here means is narrow and stated in docs/contracts/e06.md: ``cargo check`` type-checks the pinned
graph for the target; it does not link, run or boot anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCHEMA = "ffw.e06.checks.v1"
MAX_LOG_BYTES = 2 * 1024 * 1024               # a log larger than this is refused, not read
PLAN_PREFIX = ["RCH_REQUIRE_REMOTE=1", "rch", "exec", "--"]
PLAN_LINE = re.compile(r"^RCH_REQUIRE_REMOTE=1 rch exec -- cargo \+nightly check --locked --release "
                       r"-p (?P<crate>[A-Za-z0-9_][A-Za-z0-9_.-]*)"
                       r"(?P<flags>(?: --no-default-features)?(?: --features [A-Za-z0-9_][A-Za-z0-9_./+,-]*)?) "
                       r"--target (?P<target>\S+) -Z build-std=(?P<std>\S+)(?: -j (?P<jobs>\d+))?$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
WORKER = re.compile(r"Selected worker: (?P<alias>\S+) at ")
EXECUTING = re.compile(r"Executing command remotely: (?P<command>.+)$")
FINISHED_REMOTE = re.compile(r"Remote command finished: exit=(?P<rc>-?\d+) in (?P<ms>\d+)ms")
# cargo prints "in 7.22s" and, past a minute, "in 1m 02s" (and "in 1h 02m 03s" past an hour).
FINISHED_CARGO = re.compile(r"^\s*Finished `(?P<profile>[^`]+)` profile .* in "
                            r"(?:(?P<h>\d+)h )?(?:(?P<m>\d+)m )?(?P<s>[0-9.]+)s\s*$")
NOTE_RC = re.compile(r"\brc=(-?\d+)")
NOTE_WORKER = re.compile(r"\bworker=(\S+)")
NOTE_REV = re.compile(r"\brev=([0-9a-f]{40})\b")
TARGET_REWRITE = re.compile(r"Rewriting CARGO_TARGET_DIR for remote execution \(worker-scoped path\): .+ -> (?P<path>\S+)$")
SOURCE_RECEIPT = "[RCH] source content receipt: "
POOL_PATH = re.compile(r"(?P<base>/[A-Za-z0-9_./-]+)/(?P<project>[A-Za-z0-9_.-]+)/"
                       r"\.rch-target-(?P<worker>[A-Za-z0-9_-]+)-pool-(?P<pool>[0-9a-f]{32})")
SOURCE_PATH = re.compile(r"(?P<base>/[A-Za-z0-9_./-]+)/source-content-pair-(?P<pool>[0-9a-f]{32})"
                         r"/projects(?:/[A-Za-z0-9_.-]+)*")
RECEIPT_FIELDS = ("schema", "worker_id", "build_id", "command_sha256", "command_exit_code", "root_count", "roots")
# Things a diagnostic line must never carry into a committed record.
_ABS_PATH = re.compile(r"(?:/Users|/home|/private|/tmp|/var|/Volumes|/opt)/[^\s'\"`)\]]+")
_ADDRESS = re.compile(r"\b[\w.-]+@\d{1,3}(?:\.\d{1,3}){3}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b")
DIAGNOSTIC_LIMIT = 160


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text)


def redact(text: str) -> str:
    """A line fit to commit: absolute paths and network addresses replaced, length bounded."""
    text = _ADDRESS.sub("<addr>", _ABS_PATH.sub("<path>", text))
    return text.strip()[:DIAGNOSTIC_LIMIT]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_log(text: str) -> Dict[str, Any]:
    """Facts from one raw RCH log.  Only the first worker / command / exit line counts, and a second one is a
    ``problems`` entry, so a log that concatenates two runs cannot vouch for either."""
    text = strip_ansi(text)
    workers, commands, exits, finished, target_rewrites, receipts = [], [], [], [], [], []
    checked = warnings = 0
    errors: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        m = WORKER.search(line)
        if m:
            workers.append(m.group("alias"))
        m = EXECUTING.search(line)
        if m:
            commands.append(m.group("command"))
        m = FINISHED_REMOTE.search(line)
        if m:
            exits.append((int(m.group("rc")), int(m.group("ms"))))
        if "Rewriting CARGO_TARGET_DIR for remote execution (worker-scoped path): " in line:
            m = TARGET_REWRITE.search(line)
            target_rewrites.append(m.group("path") if m else "")
        if line.startswith(SOURCE_RECEIPT):
            receipts.append(line[len(SOURCE_RECEIPT):])
        m = FINISHED_CARGO.match(raw)
        if m:
            seconds = int(m.group("h") or 0) * 3600 + int(m.group("m") or 0) * 60 + float(m.group("s"))
            finished.append((m.group("profile"), seconds))
        if re.match(r"^(Checking|Compiling) ", line):
            checked += 1
        if line.startswith("warning"):
            warnings += 1
        if line.startswith("error"):
            errors.append(line)
    problems = []
    for name, found in (("worker", workers), ("command", commands), ("exit", exits)):
        if len(found) != 1:
            problems.append("the log has %d %s lines, expected exactly 1" % (len(found), name))
    argv: Optional[List[str]] = None
    if len(commands) == 1:
        try:
            argv = remote_argv(commands[0])
            cargo = argv[:argv.index("--")] if "--" in argv else argv
            if any(token.startswith("build.build-dir=") for token in cargo):
                target = _managed_output_target(workers, exits, target_rewrites, receipts)
                argv = remote_argv(commands[0], managed_target=target)
        except ValueError as exc:
            argv = None
            problems.append("the remote command cannot be read: %s" % exc)
    return {"worker": workers[0] if len(workers) == 1 else None, "argv": argv,
            "rc": exits[0][0] if len(exits) == 1 else None, "remote_ms": exits[0][1] if len(exits) == 1 else None,
            "finished": finished[0] if finished else None, "units": checked, "warnings": warnings,
            "errors": errors, "problems": problems}


def _unique_json_object(pairs: List[Tuple[str, Any]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate field in source receipt")
        result[name] = value
    return result


def _literal_absolute_path(path: Any) -> bool:
    return (isinstance(path, str) and path.startswith("/")
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is not None
            and all(part not in ("", ".", "..") for part in path.split("/")[1:]))


def _managed_output_target(workers: List[str], exits: list, rewrites: List[str], receipts: List[str]) -> str:
    """Bind the output-only rewrite to the same log's worker, target and source-pair receipt.

    RCH's cargo_target_dir.rs inserts build.build-dir and --target-dir before Cargo's `--`;
    dependency_closure.rs binds their pool key to source-content-pair-<key>/projects.
    Receipt integrity follows source_fidelity.rs::SourceContentReceiptPreimage. This does NOT
    establish source-file fidelity or equate command_sha256 with a reconstructed command string;
    the caller still compares the resulting argv against its independently supplied plan.
    """
    if any(len(values) != 1 for values in (workers, exits, rewrites, receipts)):
        raise ValueError("managed output override needs exactly one worker, exit, target rewrite and source receipt")
    target = rewrites[0]
    pool = POOL_PATH.fullmatch(target) if _literal_absolute_path(target) else None
    if pool is None or pool.group("worker") != workers[0]:
        raise ValueError("managed output target is not the selected worker's literal pool path")
    try:
        receipt = json.loads(receipts[0], object_pairs_hook=_unique_json_object)
        if not isinstance(receipt, dict) or set(receipt) != set(RECEIPT_FIELDS) | {"receipt_root"}:
            raise ValueError("invalid source receipt fields")
        preimage = {name: receipt[name] for name in RECEIPT_FIELDS}
        digest = sha256_bytes(json.dumps(preimage, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        roots = receipt["roots"]
        if (receipt["schema"] != "rch.source_content_receipt.v1"
                or receipt["worker_id"] != workers[0]
                or not isinstance(receipt["build_id"], str) or re.fullmatch(r"[1-9][0-9]*", receipt["build_id"]) is None
                or not isinstance(receipt["command_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", receipt["command_sha256"]) is None
                or type(receipt["command_exit_code"]) is not int or receipt["command_exit_code"] != exits[0][0]
                or type(receipt["root_count"]) is not int or not isinstance(roots, list)
                or receipt["root_count"] != len(roots) or not roots
                or digest != receipt["receipt_root"]):
            raise ValueError("source receipt identity, status, denominator or digest mismatch")
        for root in roots:
            if (not isinstance(root, dict) or root.get("schema") != "rch.source_content_root.v1"
                    or type(root.get("is_primary")) is not bool or not _literal_absolute_path(root.get("remote_root"))):
                raise ValueError("invalid source root witness")
            source = SOURCE_PATH.fullmatch(root["remote_root"])
            if source is None or (source.group("base"), source.group("pool")) != (pool.group("base"), pool.group("pool")):
                raise ValueError("source root does not bind the managed output pool")
        primary = [root for root in roots if root["is_primary"]]
        if len(primary) != 1 or primary[0].get("project_id") != pool.group("project"):
            raise ValueError("source receipt does not name exactly one matching primary project")
    except (TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid source receipt") from exc
    return target


def remote_argv(command: str, managed_target: Optional[str] = None) -> List[str]:
    """The cargo argv RCH ran, minus its env.RCH trailer before Cargo's `--`.

    Only parse_log's independently bound managed_target permits removing the exact adjacent
    build.build-dir/--target-dir suffix. Every other config/flag and all passthrough argv stay.
    """
    argv = shlex.split(command)
    # RCH's debug-pressure defaults are logged as an env prefix. Only the
    # observed fixed values are equivalent to the planned release command;
    # compiler flags, config overrides and other env variables are not.
    if argv and (argv[0] == "env" or "=" in argv[0]):
        allowed = {"CARGO_PROFILE_DEV_DEBUG=line-tables-only", "CARGO_PROFILE_TEST_DEBUG=line-tables-only"}
        seen = set()
        i = 1 if argv[0] == "env" else 0
        while i < len(argv) and argv[i] != "cargo":
            if argv[i] not in allowed or argv[i] in seen:
                raise ValueError("unrecognized or repeated remote environment override")
            seen.add(argv[i])
            i += 1
        if not seen or i == len(argv):
            raise ValueError("remote environment prefix has no cargo command")
        argv = argv[i:]
    end = argv.index("--") if "--" in argv else len(argv)
    cargo, passthrough = argv[:end], argv[end:]
    while len(cargo) >= 2 and cargo[-2] == "--config" and cargo[-1].startswith("env.RCH_"):
        cargo = cargo[:-2]
    if managed_target is not None:
        suffix = ["--config", 'build.build-dir="%s"' % managed_target, "--target-dir", managed_target]
        if cargo[-4:] != suffix:
            raise ValueError("managed output options are not the exact paired Cargo suffix")
        cargo = cargo[:-4]
        if any(token.startswith("build.build-dir=") or token == "--target-dir" or token.startswith("--target-dir=")
               for token in cargo):
            raise ValueError("repeated managed output option")
    return cargo + passthrough


def plan_argv(line: str) -> List[str]:
    argv = shlex.split(line)
    if argv[: len(PLAN_PREFIX)] != PLAN_PREFIX:
        raise ValueError("a plan line must start with %s" % " ".join(PLAN_PREFIX))
    return argv[len(PLAN_PREFIX):]


def parse_plan(lines: Sequence[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    plan, problems, seen = [], [], set()
    for number, line in enumerate((ln.strip() for ln in lines), 1):
        if not line:
            continue
        m = PLAN_LINE.match(line)
        if m is None:
            problems.append("plan line %d is not a planned cargo check: %s" % (number, redact(line)))
            continue
        key = (m.group("crate"), m.group("target"))
        if key in seen:
            problems.append("plan line %d repeats %s/%s" % (number, key[0], key[1]))
            continue
        seen.add(key)
        plan.append({"crate": key[0], "target": key[1], "command": line})
    if not plan and not problems:
        problems.append("the plan is empty: there is nothing to verify")
    return plan, problems


def _read_log(logs_dir: str, evidence: Any) -> Tuple[Optional[bytes], Optional[str]]:
    if not isinstance(evidence, str) or not evidence:
        return None, "the row names no evidence log"
    path = os.path.join(logs_dir, os.path.basename(evidence))
    try:
        size = os.path.getsize(path)
        if size > MAX_LOG_BYTES:
            return None, "the log is %d bytes, over the %d byte limit" % (size, MAX_LOG_BYTES)
        with open(path, "rb") as fh:
            return fh.read(), None
    except OSError as exc:
        return None, "the log cannot be read (%s)" % exc.__class__.__name__


def verify(plan: Sequence[Dict[str, str]], results: Sequence[dict], logs_dir: str,
           rev: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    """(records, problems).  ``problems`` are claims the logs do not support or a denominator that does not match;
    a check that genuinely failed, with a log that says so, is a record and not a problem."""
    problems: List[str] = []
    planned = {(p["crate"], p["target"]): p for p in plan}
    by_key: Dict[Tuple[str, str], List[dict]] = {}
    for r in results:
        key = (str(r.get("crate")), str(r.get("target")))
        if key not in planned:
            problems.append("%s/%s: a result for a check that is not in the plan" % key)
            continue
        by_key.setdefault(key, []).append(r)
    records: List[Dict[str, Any]] = []
    for p in plan:
        key = (p["crate"], p["target"])
        label = "%s/%s" % key
        got = by_key.get(key, [])
        if not got:
            problems.append("%s: planned, but no result was supplied (not-run is never a pass)" % label)
            continue
        if len(got) > 1:
            problems.append("%s: %d results were supplied for one planned check" % (label, len(got)))
            continue
        row = got[0]
        status = row.get("status")
        if status not in ("pass", "fail"):
            problems.append("%s: status must be pass or fail" % label)
            continue
        raw, why = _read_log(logs_dir, row.get("evidence"))
        if raw is None:
            problems.append("%s: %s" % (label, why))
            continue
        facts = parse_log(raw.decode("utf-8", errors="replace"))
        bad = list(facts["problems"])
        if facts["argv"] is not None and facts["argv"] != plan_argv(p["command"]):
            bad.append("the command in the log is not the planned command: %s" % redact(" ".join(facts["argv"])))
        note = str(row.get("note") or "")
        for name, pattern, actual in (("rc", NOTE_RC, None if facts["rc"] is None else str(facts["rc"])),
                                      ("worker", NOTE_WORKER, facts["worker"]), ("rev", NOTE_REV, rev)):
            m = pattern.search(note)
            if m is None:
                bad.append("the note has no %s=" % name)
            elif actual is not None and m.group(1) != actual:
                bad.append("the note says %s=%s but the %s is %s" % (
                    name, redact(m.group(1)), "log" if name != "rev" else "expected revision", redact(actual)))
        if facts["rc"] is not None:
            if status == "pass" and facts["rc"] != 0:
                bad.append("the row says pass but the remote exit status is %d" % facts["rc"])
            if status == "fail" and facts["rc"] == 0:
                bad.append("the row says fail but the remote exit status is 0")
        if status == "pass" and facts["finished"] is None:
            bad.append("the row says pass but the log has no Finished line")
        if status == "pass" and facts["errors"]:
            bad.append("the row says pass but the log has %d error line(s)" % len(facts["errors"]))
        if bad:
            problems.extend("%s: %s" % (label, b) for b in bad)
            continue
        record: Dict[str, Any] = {
            "crate": p["crate"], "target": p["target"], "status": status,
            "command": p["command"], "rc": facts["rc"], "worker": facts["worker"], "rev": rev,
            "remote_ms": facts["remote_ms"], "profile": facts["finished"][0] if facts["finished"] else None,
            "cargo_seconds": facts["finished"][1] if facts["finished"] else None,
            "units": facts["units"], "warnings": facts["warnings"], "errors": len(facts["errors"]),
            "raw_log_sha256": sha256_bytes(raw), "raw_log_bytes": len(raw),
            "evidence": "raw RCH log not committed (it carries a worker address and local paths); sha256 %s"
                        % sha256_bytes(raw),
            "note": note,
        }
        if status == "fail":
            record["diagnostic"] = redact(facts["errors"][0]) if facts["errors"] else None
        records.append(record)
    return records, problems


def render(records: Sequence[Dict[str, Any]], problems: Sequence[str]) -> str:
    counts = {s: sum(1 for r in records if r["status"] == s) for s in ("pass", "fail")}
    out = ["E06 central check ingest  schema=%s  verified=%d pass=%d fail=%d problems=%d" % (
        SCHEMA, len(records), counts["pass"], counts["fail"], len(problems))]
    out.extend("  PROBLEM %s" % p for p in problems[:30])
    if len(problems) > 30:
        out.append("  ... %d more" % (len(problems) - 30))
    return "\n".join(out) + "\n"


def write_records(path: str, records: Sequence[Dict[str, Any]]) -> None:
    """One JSON object per line, sorted keys, a new file only."""
    with open(path, "x", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
