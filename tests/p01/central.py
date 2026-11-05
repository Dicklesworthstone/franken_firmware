"""Evidence of a central run: ingest raw rch logs into a sanitized, revision-bound receipt, and judge that receipt.

The raw logs of a central run name the worker's address and the operator's paths, so they are never committed (the
E06 precedent). `build_evidence` reads them once and keeps only what is safe and checkable: the revision, the worker's
NAME, the remote command with every path under the export replaced by `<repo>`, its exit status, the SHA-256 of the raw
log (so whoever holds the log can check it), the toolchain facts, the test totals, and the identity of the artifacts
the run produced, read from the built bytes. Each step is verified against the plan it was meant to run: the command
the worker ran must equal the planned command (after the `--config env.RCH_*` trailer that rch itself appends is
removed), it must have run remotely, and it must have exited 0.

`judge` holds committed evidence to the CURRENT plan and contract. Evidence for a different plan or contract, or with a
step that never ran, is not wrong, it is stale: the verdict is `blocked`, named, never `pass` and never silently
dropped. Evidence with a failed step or an inconsistent record is `fail`. Only evidence that matches the current plan
and contract, with every step in scope run and green, is `pass`.

What this proves, so it is not over-read: a supervisor ran these commands on a worker at that revision and they exited
0, and the artifact files had these digests. It is not an attestation of the compiler, and it says nothing about a
guest, a boot or a device.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
from typing import Any, Dict, List, Optional, Sequence, Tuple

import plan as plan_mod
import reference as ref

EVIDENCE_SCHEMA = "ffw.p01.central_evidence.v1"
# P01-BLK-001: build and test from another directory, offline, locked, on the central path. The two device speaker
# builds are BLK-002's.
BLK001_STEPS = ("toolchain", "toolchain-default", "workspace-test", "build-franken-speaker-host",
                "build-ffw-hello-init-mips_be", "build-ffw-hello-init-powerpc_be")
EVIDENCE_GLOB_DIR = os.path.join("toolchain", "results", "p01")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_EXEC = re.compile(r"Executing command remotely: (.*)$", re.M)
_DONE = re.compile(r"Remote command finished: exit=(-?\d+) in (\d+)ms")
_WORKER = re.compile(r"Selected worker: (\S+) at ")
_TEST = re.compile(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", re.M)
_STAMP = re.compile(r"\b(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = "<repo>"


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def parse_remote_log(text: str) -> Dict[str, Any]:
    """What an rch log says about one remote command: worker name, the command, its exit status and duration. A log
    with no command line, more than one, no exit line, or a local fallback has `problems` and is never ok."""
    clean = strip_ansi(text)
    execs, dones, workers = _EXEC.findall(clean), _DONE.findall(clean), _WORKER.findall(clean)
    problems: List[str] = []
    if len(execs) != 1:
        problems.append(f"{len(execs)} remote command lines, expected 1")
    if len(dones) != 1:
        problems.append(f"{len(dones)} remote exit lines, expected 1")
    if "[RCH] local" in clean:
        problems.append("rch ran the command locally")
    if "[RCH] remote" not in clean:
        problems.append("no remote completion marker")
    try:
        command = shlex.split(execs[0]) if execs else []
    except ValueError:
        command = []
        problems.append("the remote command line cannot be split")
    stamps = _STAMP.findall(clean)
    return {"worker": workers[0] if workers else "", "command": command,
            "exit": int(dones[0][0]) if len(dones) == 1 else None,
            "millis": int(dones[0][1]) if len(dones) == 1 else None,
            "first_stamp": min(stamps) if stamps else "", "problems": problems}


def strip_rch_trailer(tokens: Sequence[str]) -> List[str]:
    """Remove the `--config env.RCH_...` pairs rch appends to a cargo command before running it."""
    out: List[str] = []
    skip = False
    for i, tok in enumerate(tokens):
        if skip:
            skip = False
            continue
        if tok == "--config" and i + 1 < len(tokens) and tokens[i + 1].startswith("env.RCH_"):
            skip = True
            continue
        out.append(tok)
    return out


def normalize(tokens: Sequence[str], roots: Sequence[str]) -> List[str]:
    """Replace the repository root (any spelling given) in every token with `<repo>`, so a command is the same
    whichever directory the run was exported to."""
    ordered = sorted({r.rstrip("/") for r in roots if r}, key=len, reverse=True)
    out = []
    for tok in tokens:
        for root in ordered:
            if tok == root:
                tok = PLACEHOLDER
                break
            if tok.startswith(root + "/"):
                tok = PLACEHOLDER + tok[len(root):]
                break
        else:
            # a `--config key="<root>/path"` token carries the root after an opening quote
            for root in ordered:
                tok = tok.replace('"' + root + '/', '"' + PLACEHOLDER + '/')
        out.append(tok)
    return out


def planned_command(step: Dict[str, Any], roots: Sequence[str]) -> List[str]:
    return normalize(plan_mod.inner_command(step["argv"]), roots)


def roots_for(path: str) -> List[str]:
    return sorted({path, os.path.realpath(path)})


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def build_evidence(contract: Dict[str, Any], planned: Sequence[Dict[str, Any]], logs: Dict[str, str], revision: str,
                   lock_sha256: str, export_root: str, rows: List[Dict[str, Any]], missing: List[str],
                   sizes: Dict[str, int], attested_env: Dict[str, Dict[str, str]],
                   tree: str = "clean git archive export of the revision") -> Dict[str, Any]:
    """The sanitized, revision-bound receipt of a central run. Pure: the caller reads the logs and the built files."""
    roots = roots_for(export_root)
    steps: List[Dict[str, Any]] = []
    toolchain: Dict[str, str] = {}
    toolchain_default: Dict[str, str] = {}
    tests: Dict[str, int] = {}
    stamps: List[str] = []
    workers: List[str] = []
    for step in planned:
        sid = step["id"]
        want = planned_command(step, roots)
        if sid not in logs:
            steps.append({"id": sid, "kind": step["kind"], "status": "not_run", "planned_command": want})
            continue
        parsed = parse_remote_log(logs[sid])
        got = normalize(strip_rch_trailer(parsed["command"]), roots)
        problems = list(parsed["problems"])
        if got != want:
            problems.append("the command the worker ran differs from the planned command")
        status = "ok" if parsed["exit"] == 0 and not problems else "failed"
        steps.append({"id": sid, "kind": step["kind"], "status": status, "exit": parsed["exit"],
                      "millis": parsed["millis"], "worker": parsed["worker"], "command": got,
                      "matches_plan": got == want, "problems": problems,
                      "log_sha256": _sha256_text(logs[sid])})
        if parsed["first_stamp"]:
            stamps.append(parsed["first_stamp"])
        if parsed["worker"]:
            workers.append(parsed["worker"])
        clean = strip_ansi(logs[sid])
        if step["kind"] == "toolchain":
            toolchain = plan_mod.parse_rustc_vv(clean)
        if step["kind"] == "toolchain_default":
            toolchain_default = plan_mod.parse_rustc_vv(clean)
        if step["kind"] == "test":
            found = _TEST.findall(clean)
            tests = {"result_blocks": len(found), "passed": sum(int(a) for a, _, _ in found),
                     "failed": sum(int(b) for _, b, _ in found), "ignored": sum(int(c) for _, _, c in found)}
    pairs = ref.verify_observed(contract, rows, require_all=False)
    return {
        "schema": EVIDENCE_SCHEMA, "kind": "central_run", "revision": revision, "tree": tree,
        "ran_at_utc": (min(stamps) + "Z") if stamps else "", "workers": sorted(set(workers)),
        "contract_digest": ref.digest(contract), "lock_sha256": lock_sha256,
        "steps": steps, "toolchain": toolchain, "toolchain_default": toolchain_default, "tests": tests,
        "artifacts": rows, "artifact_sizes": dict(sorted(sizes.items())), "missing": sorted(missing),
        "verification": {"codes": ref.codes(pairs), "pairs": [list(p) for p in pairs]},
        "attested_env": attested_env,
        "boundary": ("A supervisor ran these commands on a worker at this revision; each step was checked against the "
                     "plan from its raw log, which is not committed (it names the worker's address and local paths). "
                     "Not an attestation of the compiler. Says nothing about a guest, a boot or a device."),
    }


def judge(evidence: Dict[str, Any], contract_now: Dict[str, Any], planned_now: Sequence[Dict[str, Any]],
          roots_now: Sequence[str], scope: Sequence[str] = BLK001_STEPS) -> Tuple[str, str]:
    """('pass' | 'blocked' | 'fail', detail). See the module docstring for what each verdict means."""
    if evidence.get("schema") != EVIDENCE_SCHEMA or evidence.get("kind") != "central_run":
        return "fail", f"not a {EVIDENCE_SCHEMA} central_run record"
    revision = evidence.get("revision", "")
    if not _HEX40.match(str(revision)):
        return "fail", "the record is not bound to a full 40-hex revision"
    digest = evidence.get("contract_digest", "")
    if not ref.is_hex64(str(digest)):
        return "fail", "the record carries no contract digest"
    for key in ("steps", "artifacts"):
        if not isinstance(evidence.get(key), list):
            return "fail", f"the record has no {key} list"
    rec_steps = {s.get("id"): s for s in evidence["steps"] if isinstance(s, dict)}
    for row in evidence["artifacts"]:
        if row.get("contract_digest") != digest:
            return "fail", f"artifact row {row.get('id')} is bound to a different contract digest than the record"
    failed = [f"{sid} (exit {rec_steps[sid].get('exit')})" for sid in scope
              if sid in rec_steps and rec_steps[sid].get("status") == "failed"]
    if failed:
        return "fail", "a step failed centrally: " + ", ".join(failed)
    tests = evidence.get("tests") or {}
    if tests.get("failed"):
        return "fail", f"{tests['failed']} workspace test(s) failed centrally"
    current = {s["id"]: s for s in planned_now}
    stale: List[str] = []
    if digest != ref.digest(contract_now):
        stale.append(f"contract digest {str(digest)[:12]} is not the current {ref.digest(contract_now)[:12]}")
    for sid in scope:
        if sid not in current:
            continue
        rec = rec_steps.get(sid)
        if rec is None or rec.get("status") == "not_run":
            stale.append(f"step {sid} has not run")
        elif rec.get("command") != planned_command(current[sid], roots_now):
            stale.append(f"step {sid} ran a different command than the current plan")
    head = f"revision {revision[:12]}"
    in_scope = [sid for sid in scope if sid in current]
    matched = [sid for sid in in_scope if rec_steps.get(sid, {}).get("status") == "ok"
               and rec_steps[sid].get("command") == planned_command(current[sid], roots_now)]
    if stale:
        return "blocked", (f"{head}: {len(matched)} of {len(in_scope)} steps ran the current plan and exited 0, but the "
                           "evidence is stale: " + "; ".join(stale[:5]) + (" ..." if len(stale) > 5 else ""))
    pairs = ref.verify_observed(contract_now, evidence["artifacts"], require_all=False)
    if pairs:
        return "fail", "artifact identity fails the contract: " + ", ".join(sorted({c for c, _ in pairs}))
    ran = [sid for sid in scope if sid in current]
    return "pass", (f"{head}, worker {','.join(evidence.get('workers', []))}: {len(ran)} steps ran the current plan and "
                    f"exited 0; {tests.get('passed', 0)} workspace tests passed, {tests.get('failed', 0)} failed, "
                    f"{tests.get('ignored', 0)} ignored; {len(evidence['artifacts'])} artifact rows verified")


def find_evidence(repo: str) -> List[str]:
    """Paths of committed evidence records (the caller orders them by the run time inside each)."""
    base = os.path.join(repo, EVIDENCE_GLOB_DIR)
    if not os.path.isdir(base):
        return []
    found = [os.path.join(base, d, "receipt.json") for d in sorted(os.listdir(base))
             if d.startswith("rev-") and os.path.isfile(os.path.join(base, d, "receipt.json"))]
    return found
