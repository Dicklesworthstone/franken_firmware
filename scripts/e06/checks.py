#!/usr/bin/env python3
"""E06 (bead ffw-unk): verify and redact the central ``cargo check`` results.  Stdlib only, offline.

A results file (JSON lines: crate, target, status, evidence, note) is a CLAIM by whoever ran the planned checks.
``audit.py audit --build-results`` folds such claims into the report by crate, target and status alone, so a row
that says ``pass`` is believed.  This module is what makes the claim checkable before it is folded in:

* it reads the raw per-line log each row points at and requires the log to say the same thing: the command RCH ran
  on the worker is exactly the planned command (RCH's own ``--config env.RCH_*`` trailer aside), the remote exit
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
EXECUTING = re.compile(r"Executing command remotely: (?P<command>cargo .*)$")
FINISHED_REMOTE = re.compile(r"Remote command finished: exit=(?P<rc>-?\d+) in (?P<ms>\d+)ms")
# cargo prints "in 7.22s" and, past a minute, "in 1m 02s" (and "in 1h 02m 03s" past an hour).
FINISHED_CARGO = re.compile(r"^\s*Finished `(?P<profile>[^`]+)` profile .* in "
                            r"(?:(?P<h>\d+)h )?(?:(?P<m>\d+)m )?(?P<s>[0-9.]+)s\s*$")
NOTE_RC = re.compile(r"\brc=(-?\d+)")
NOTE_WORKER = re.compile(r"\bworker=(\S+)")
NOTE_REV = re.compile(r"\brev=([0-9a-f]{40})\b")
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
    workers, commands, exits, finished = [], [], [], []
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
        except ValueError as exc:
            problems.append("the remote command cannot be read: %s" % exc)
    return {"worker": workers[0] if len(workers) == 1 else None, "argv": argv,
            "rc": exits[0][0] if len(exits) == 1 else None, "remote_ms": exits[0][1] if len(exits) == 1 else None,
            "finished": finished[0] if finished else None, "units": checked, "warnings": warnings,
            "errors": errors, "problems": problems}


def remote_argv(command: str) -> List[str]:
    """The cargo argv RCH ran, with RCH's own trailing ``--config env.RCH_...`` pairs removed.  Any other
    ``--config`` stays, so a build that quietly changed cargo's configuration does not match the plan."""
    argv = shlex.split(command)
    while len(argv) >= 2 and argv[-2] == "--config" and argv[-1].startswith("env.RCH_"):
        argv = argv[:-2]
    return argv


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
