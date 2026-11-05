#!/usr/bin/env python3
"""E06 (bead ffw-unk) open items 3 and 4 as ONE runnable batch, with its judge.  Stdlib only.

Item 4: the workspace's minimal-graph `cargo check` lines (one per workspace crate per big-endian target) at a closing revision.
Item 3: the 20 upstream check lines for Asupersync, `franken_kernel`/`franken_evidence`/`franken_decision` and FrankenLibC, each
run in a clean export of the pinned revision.  Every line is in the manifest with its exact argv, its source root, its worker set,
its log name and the outcome PREDICTED BEFORE THE RUN (with the reason).  A failure that was predicted is a finding for E06, not a
defect to fix.

    batch.py gen    --workspace-repo REPO [--workspace-rev REV] --export-dir DIR --out MANIFEST
                    export the revision with git archive (a new directory), write the manifest (a new file)
    batch.py run    --manifest M --workspace-export DIR ...     prepare the pinned sources, run every line, write logs
    batch.py judge  --manifest M --logs-dir DIR [--record OUT] [--results-jsonl OUT --rev SHA]

`run` is the only subcommand that starts a build, and it starts each one as `rch exec -- cargo ...` with no shell in between (RCH
refuses shell chains), writing the merged output to the line's own log.  `judge` reads nothing but the manifest and the logs: it
does not trust a results file, decides each line BY NAME, and fails closed on a missing log, a log that is only an infrastructure
refusal (exit 103) or a log that does not match its line.  Nothing is decided on totals.

Judge exit status: 0 every line resolved and every outcome was the predicted one; 3 every line resolved but at least one outcome
was not the predicted one (read it before anything else); 1 a line is missing, infrastructure-only, refused by RCH or malformed
(no result); 4 a subset was judged (`--only`), so the batch is not judged; 2 usage.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import checks  # noqa: E402

SCHEMA = "ffw.e06.batch.v1"
RECORD_SCHEMA = "ffw.e06.batch-record.v1"
WORKERS = "trj,hz3"                       # nightly -Z build-std lines go on the workers that have rust-src (ts1 removed: its shim refuses strict-remote jobs)
JOBS = 2
# Deadlines (seconds) for the local children this tool starts, so none of them can wait forever. `audit.py plan` resolves three platforms
# (each `cargo metadata` has its own 180 s bound there); a local git read or archive of a pinned revision ends in seconds.
PLAN_TIMEOUT = 900.0
GIT_TIMEOUT = 120.0
ARCHIVE_TIMEOUT = 600.0
TARGETS = {"mips-unknown-linux-musl": "mips", "powerpc-unknown-linux-musl": "powerpc"}
EVIDENCE_REL = os.path.join("toolchain", "results", "e06", "upstream")
BYPASS_ENV = ("RCH_CARGO_WRAPPER_BYPASS", "RCH_ENABLED")
MAX_LOG_BYTES = checks.MAX_LOG_BYTES
SHELL_META = re.compile(r"[;|&$`<>\n\\]")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SENTINEL = ".ffw-batch-source"
CLASSES = ("compile", "build-script", "resolve", "toolchain")
EXPECT_OUTCOMES = ("pass", "fail")
CONFIDENCES = ("high", "medium", "low")

# (source, config, plan file under the committed upstream evidence directory)
UPSTREAM_PLANS = (
    ("asupersync", "default", "asupersync-8940119023c0/plan-default.txt"),
    ("asupersync", "no-default-features", "asupersync-8940119023c0/plan-no-default-features.txt"),
    ("asupersync", "runtime-core-only", "asupersync-8940119023c0/plan-runtime-core-only.txt"),
    ("asupersync", "runtime-core-and-native-runtime", "asupersync-8940119023c0/plan-runtime-core-and-native-runtime.txt"),
    ("asupersync", "franken-support-crates", "asupersync-8940119023c0/plan-franken-support-crates.txt"),
    ("frankenlibc", "runtime-crates", "frankenlibc-76d7f3469f5f/plan-runtime-crates.txt"),
)
UPSTREAM_REVS = {
    "asupersync": "8940119023c0e01b4d6d3e2c1399f41417c2ad24",
    "frankenlibc": "76d7f3469f5f5251661b3662926d3d6a2b36d494",
}
FRANKENLIBC_KEEP = ("frankenlibc-core", "frankenlibc-abi", "frankenlibc-membrane")
FRANKENLIBC_EVIDENCE = "frankenlibc-76d7f3469f5f"
# The twelve workspace crates that type-checked clean for both targets at 5b8d5696 (24 of 24, 2026-11-05).
KNOWN_AT_5B8D569 = frozenset((
    "franken-alloc-probe", "franken-baseline", "franken-board-profile", "franken-clock", "franken-control", "franken-dsp",
    "franken-hal", "franken-platform", "franken-session", "franken-speaker", "franken-stream", "franken-test-support"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------------------------------ predictions
def expectation(group: str, source: str, config: str, crate: str) -> Dict[str, Any]:
    """The outcome predicted for one line BEFORE it runs, and why.  Evidence for each is in toolchain/results/e06/upstream/README.md
    and the scans quoted here; a prediction that proves wrong is reported as unexpected, never silently absorbed."""
    if group == "workspace":
        if crate in KNOWN_AT_5B8D569:
            return {"outcome": "pass", "confidence": "high",
                    "why": "type-checked clean for both big-endian targets at 5b8d5696 (24 of 24); a failure now is a regression since then"}
        return {"outcome": "pass", "confidence": "low",
                "why": "not among the 12 crates checked at 5b8d5696: the first target check of this crate, and its Rust may not have "
                       "been compiled before this run; a failure is a first-compile finding for its owner"}
    if source == "asupersync" and config == "franken-support-crates":
        return {"outcome": "pass", "confidence": "high",
                "why": "three small crates over serde/serde_json (10 linked packages); no build script that runs a compiler, no direct "
                       "64-bit atomic import in them or in the packages they link (scanned), no C"}
    if source == "asupersync" and config == "default":
        return {"outcome": "fail", "class": "build-script", "confidence": "medium",
                "diagnostic_any": ["Try-trait probe failed", "failed to run custom build command for `asupersync"],
                "why": "the default features include nightly-outcome-try, whose build.rs runs its own `rustc --target <triple>` probe; under "
                       "-Z build-std rustc's sysroot has no prebuilt core for a tier-3 target, so the probe fails with something other than "
                       "E0554 and the script panics on purpose (build.rs: 'any other failure fails the build'). If cargo supplies a sysroot "
                       "for build scripts the line passes, and that is the finding"}
    if source == "asupersync":
        return {"outcome": "pass", "confidence": "medium",
                "why": "no direct 64-bit atomic import in the asupersync crate outside its portable-atomic facade, and every dependency's is gated on "
                       "target_has_atomic (scanned: crossbeam-queue, crossbeam-utils, bincode-next, serde); signal-hook's C build is not enabled "
                       "(no extended-siginfo-raw); no nightly-outcome-try probe in this configuration. NOT established: 32-bit width assumptions "
                       "in about 3000 source files that have no big-endian 32-bit history; a failure is a finding for P05"}
    if source == "frankenlibc" and crate in ("frankenlibc-core", "frankenlibc-abi"):
        # CORRECTED after run3 (BeigeMaple 4802). The first version predicted each crate's own x86_64/aarch64-only compile_error! (core lib.rs:63-69,
        # abi lib.rs:42-48). Both crates depend on frankenlibc-membrane, cargo type-checks it first, and it fails: neither crate's own source was
        # ever compiled in run3 and neither gate was reached. The prediction is now the mechanism run3 observed, and only that mechanism.
        return {"outcome": "fail", "class": "compile", "confidence": "high",
                "diagnostic_any": ["could not compile `frankenlibc-membrane`"],
                "why": "OBSERVED in run3 on both targets (identical logs): %s depends on frankenlibc-membrane, cargo checks that first, and it fails "
                       "with 35 errors, the first `error[E0432]: unresolved import std::sync::atomic::AtomicU64` at "
                       "crates/frankenlibc-membrane/src/alien_cs_metrics.rs:23:25; this crate's own compile_error! (an x86_64/aarch64-only gate) is "
                       "masked and cannot be reached at the pinned revision. The first version of this prediction named that gate and was judged "
                       "unexpected-fail for frankenlibc-core. If membrane ever compiles, a failure here that no longer names it is a changed cause "
                       "and is reported as unexpected" % crate}
    if source == "frankenlibc" and crate == "frankenlibc-membrane":
        return {"outcome": "fail", "class": "compile", "confidence": "medium",
                "diagnostic_any": ["AtomicU64", "AtomicI64"],
                "why": "356 uses of std::sync::atomic::AtomicU64/AtomicI64 with no target_has_atomic gate anywhere in the crate, and neither "
                       "big-endian target has 64-bit atomics (E03 ATOMIC_WIDTH bits=32): the E0432 'no AtomicU64 in sync::atomic' failure. "
                       "Medium because a nightly feature (allocator_api, btreemap_alloc) could fail first on the worker's newer nightly"}
    raise ValueError("no expectation written for %s/%s/%s: a line without a prediction is not added" % (source, config, crate))


# ------------------------------------------------------------------------------------------------------------------ manifest
def short_target(target: str) -> str:
    if target not in TARGETS:
        raise ValueError("unknown target %r" % target)
    return TARGETS[target]


def make_line(group: str, source: str, config: str, item: Dict[str, str]) -> Dict[str, Any]:
    argv = checks.plan_argv(item["command"])
    if argv[-2:] != ["-j", str(JOBS)]:
        raise ValueError("%s: the planned line has no explicit -j %d" % (item["command"], JOBS))
    parts = [source] if group == "upstream" else ["workspace"]
    if group == "upstream":
        parts.append(config)
    parts += [item["crate"], short_target(item["target"])]
    line_id = ".".join(parts)
    return {
        "id": line_id, "group": group, "source": source, "config": config if group == "upstream" else None,
        "crate": item["crate"], "target": item["target"], "cwd": ".", "log": line_id + ".log",
        "env": {"RCH_REQUIRE_REMOTE": "1", "RCH_WORKER": WORKERS},
        "remote_argv": argv, "expect": expectation(group, source, config, item["crate"]),
    }


def workspace_plan(export: str, audit_py: Optional[str] = None, timeout: float = PLAN_TIMEOUT) -> List[str]:
    """The planned workspace lines for an export, from audit.py plan (a resolver read: cargo metadata --locked --offline)."""
    audit_py = audit_py or os.path.join(HERE, "audit.py")
    try:
        proc = subprocess.run([sys.executable, "-B", "-I", audit_py, "plan", "--manifest-path", os.path.join(export, "Cargo.toml"),
                               "--jobs", str(JOBS)], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("audit.py plan did not finish within %g s" % timeout) from None
    if proc.returncode != 0:
        raise RuntimeError("audit.py plan refused (exit %d): %s" % (proc.returncode, checks.redact(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "")))
    return [line for line in proc.stdout.splitlines() if line.strip()]


def edits_of(evidence_dir: str) -> List[Dict[str, Any]]:
    data = json.loads(read_bytes(os.path.join(evidence_dir, FRANKENLIBC_EVIDENCE, "export-edits.json")).decode("utf-8"))
    return [{"file": e["file"], "sha256_before": e["sha256_before"], "sha256_after": e["sha256_after"]} for e in data["edits"]]


def build_manifest(workspace_export: str, workspace_rev: str, evidence_dir: Optional[str] = None,
                   audit_py: Optional[str] = None) -> Dict[str, Any]:
    if not HEX40.match(workspace_rev):
        raise ValueError("the workspace revision must be a 40-hex commit")
    evidence_dir = evidence_dir or os.path.join(ROOT, EVIDENCE_REL)
    lines: List[Dict[str, Any]] = []
    plan, problems = checks.parse_plan(workspace_plan(workspace_export, audit_py))
    if problems:
        raise RuntimeError("the workspace plan is not usable: %s" % "; ".join(problems))
    order = {t: i for i, t in enumerate(TARGETS)}
    for item in sorted(plan, key=lambda p: (p["crate"], order[p["target"]])):
        lines.append(make_line("workspace", "workspace", "", item))
    for source, config, rel in UPSTREAM_PLANS:
        text = read_bytes(os.path.join(evidence_dir, *rel.split("/"))).decode("utf-8")
        upstream, problems = checks.parse_plan(text.splitlines())
        if problems:
            raise RuntimeError("%s: %s" % (rel, "; ".join(problems)))
        for item in sorted(upstream, key=lambda p: (p["crate"], order[p["target"]])):
            lines.append(make_line("upstream", source, config, item))
    lock_rel = FRANKENLIBC_EVIDENCE + "/Cargo.lock.generated"
    manifest = {
        "schema": SCHEMA,
        "workers": WORKERS,
        "workspace": {"rev": workspace_rev, "plan_sha256": sha256_bytes("\n".join(workspace_plan(workspace_export, audit_py)).encode("utf-8"))},
        "sources": {
            "asupersync": {"rev": UPSTREAM_REVS["asupersync"],
                           "archive": "git -C <asupersync repository> archive --format=tar %s | tar -x -C <work dir>/asupersync-%s" % (
                               UPSTREAM_REVS["asupersync"], UPSTREAM_REVS["asupersync"][:12])},
            "frankenlibc": {"rev": UPSTREAM_REVS["frankenlibc"],
                            "archive": "git -C <frankenlibc repository> archive --format=tar %s | tar -x -C <work dir>/frankenlibc-%s" % (
                                UPSTREAM_REVS["frankenlibc"], UPSTREAM_REVS["frankenlibc"][:12]),
                            "keep_members": list(FRANKENLIBC_KEEP),
                            "edits": edits_of(evidence_dir),
                            "lock": {"source": "%s/%s" % (EVIDENCE_REL.replace(os.sep, "/"), lock_rel),
                                     "sha256": sha256_bytes(read_bytes(os.path.join(evidence_dir, *lock_rel.split("/")))),
                                     "note": "generated OFFLINE from one machine's registry cache: not an upstream pin"}},
        },
        "lines": lines,
    }
    problems = validate_manifest(manifest)
    if problems:
        raise RuntimeError("the manifest this tool just built is invalid: %s" % "; ".join(problems))
    return manifest


def validate_manifest(m: Any) -> List[str]:
    """Problems with a manifest (empty = usable).  The judge and the runner both refuse a manifest that has any."""
    problems: List[str] = []
    if not isinstance(m, dict) or m.get("schema") != SCHEMA:
        return ["the manifest is not schema %s" % SCHEMA]
    workers = m.get("workers")
    if not isinstance(workers, str) or not re.fullmatch(r"[a-z0-9]+(,[a-z0-9]+)*", workers):
        problems.append("workers must be a comma-separated list of worker aliases")
    ws = m.get("workspace")
    if not isinstance(ws, dict) or not HEX40.match(str(ws.get("rev"))) or not re.fullmatch(r"[0-9a-f]{64}", str(ws.get("plan_sha256"))):
        problems.append("workspace needs a 40-hex rev and a 64-hex plan_sha256")
    lines = m.get("lines")
    if not isinstance(lines, list) or not lines:
        return problems + ["the manifest has no lines"]
    seen_ids, seen_logs, seen_cmds = set(), set(), set()
    sources_needed = set()
    for number, line in enumerate(lines, 1):
        label = "line %d" % number
        if not isinstance(line, dict):
            problems.append("%s is not an object" % label)
            continue
        line_id = line.get("id")
        if not isinstance(line_id, str) or not ID_RE.match(line_id):
            problems.append("%s: the id is not a safe name" % label)
            continue
        label = line_id
        if line_id in seen_ids:
            problems.append("%s: the id is repeated" % label)
        seen_ids.add(line_id)
        log = line.get("log")
        if log != line_id + ".log" or log in seen_logs:
            problems.append("%s: the log must be <id>.log and unique" % label)
        seen_logs.add(log)
        if line.get("group") not in ("workspace", "upstream") or line.get("source") not in ("workspace", "asupersync", "frankenlibc"):
            problems.append("%s: group or source is not known" % label)
        if line.get("group") == "upstream":
            sources_needed.add(line.get("source"))
        if line.get("cwd") != ".":
            problems.append("%s: cwd must be the source root ('.')" % label)
        if line.get("env") != {"RCH_REQUIRE_REMOTE": "1", "RCH_WORKER": workers}:
            problems.append("%s: env must be exactly RCH_REQUIRE_REMOTE=1 and RCH_WORKER=<workers>" % label)
        argv = line.get("remote_argv")
        if (not isinstance(argv, list) or not all(isinstance(a, str) and a for a in argv)
                or argv[:4] != ["cargo", "+nightly", "check", "--locked"] or argv[-2:] != ["-j", str(JOBS)]):
            problems.append("%s: remote_argv must be cargo +nightly check --locked ... -j %d" % (label, JOBS))
        else:
            if any(SHELL_META.search(a) for a in argv):
                problems.append("%s: an argument contains a shell metacharacter (RCH refuses shell chains)" % label)
            target = argv[argv.index("--target") + 1] if "--target" in argv and argv.index("--target") + 1 < len(argv) else None
            if target not in TARGETS or "-p" not in argv or not any(a.startswith("build-std=") for a in argv):
                problems.append("%s: needs -p, --target <big-endian musl> and -Z build-std=" % label)
            key = tuple(argv)
            if key in seen_cmds and line.get("group") == "workspace":
                problems.append("%s: repeats another line's command" % label)
            seen_cmds.add(key)
        problems.extend("%s: %s" % (label, p) for p in validate_expect(line.get("expect")))
    sources = m.get("sources")
    for needed in sorted(sources_needed):
        entry = sources.get(needed) if isinstance(sources, dict) else None
        if not isinstance(entry, dict) or not HEX40.match(str(entry.get("rev"))):
            problems.append("sources.%s needs a 40-hex rev" % needed)
        elif entry["rev"] != UPSTREAM_REVS.get(needed):
            problems.append("sources.%s.rev is not the pinned revision E06 records" % needed)
    if "frankenlibc" in sources_needed and isinstance(sources, dict) and isinstance(sources.get("frankenlibc"), dict):
        fl = sources["frankenlibc"]
        if not isinstance(fl.get("edits"), list) or not fl["edits"] or not re.fullmatch(r"[0-9a-f]{64}", str((fl.get("lock") or {}).get("sha256"))):
            problems.append("sources.frankenlibc needs its recorded edits and the lock sha256")
    return problems


def validate_expect(e: Any) -> List[str]:
    if not isinstance(e, dict):
        return ["expect is missing"]
    problems = []
    if e.get("outcome") not in EXPECT_OUTCOMES:
        problems.append("expect.outcome must be pass or fail")
    if e.get("confidence") not in CONFIDENCES:
        problems.append("expect.confidence must be high, medium or low")
    if not isinstance(e.get("why"), str) or len(e["why"].strip()) < 20:
        problems.append("expect.why must state a reason")
    if e.get("outcome") == "fail":
        if e.get("class") not in CLASSES:
            problems.append("a predicted failure must name its class (%s)" % ", ".join(CLASSES))
        diag = e.get("diagnostic_any")
        if not isinstance(diag, list) or not diag or not all(isinstance(d, str) and d for d in diag):
            problems.append("a predicted failure must name at least one diagnostic substring")
    elif e.get("outcome") == "pass" and ("class" in e or "diagnostic_any" in e):
        problems.append("a predicted pass has no class or diagnostic")
    return problems


# ------------------------------------------------------------------------------------------------------------------ the judge
INFRA_MARKERS = ("refusing local fallback", "remote retries exhausted", "Remote build failed on all", "is not currently admissible",
                 "no workers available", "timed out waiting for a worker")
REFUSALS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"RCH-E(\d{3})"), "rch-e"),
    (re.compile(r"outside (?:of )?(?:the )?canonical", re.I), "outside-canonical-root"),
    (re.compile(r"client_toolchain_unresolved"), "client-toolchain-unresolved"),
    (re.compile(r"conflicting alias base"), "conflicting-alias-base"),
)
RESOLVE = re.compile(r"failed to select a version|failed to resolve|the lock file .* needs to be updated|failed to load source for dependency|"
                     r"failed to get `|unable to update|failed to parse lock")
TOOLCHAIN = re.compile(r"can't find crate for `(?:std|core|alloc)`|may not be installed|rust-src|no matching package named `(?:std|core|alloc)`|"
                       r"rustlib/src/rust/library/Cargo\.lock\"? does not exist")


def remote_body(text: str) -> str:
    """The text between RCH's 'Executing command remotely' line and its 'Remote command finished' line: cargo's own output."""
    out, inside = [], False
    for raw in text.splitlines():
        if checks.EXECUTING.search(raw):
            inside = True
            continue
        if checks.FINISHED_REMOTE.search(raw):
            break
        if inside:
            out.append(raw)
    return "\n".join(out)


def classify_failure(body: str) -> str:
    if "failed to run custom build command for" in body:
        return "build-script"
    if RESOLVE.search(body):
        return "resolve"
    if TOOLCHAIN.search(body) and not re.search(r"^error\[E0(?!463)", body, re.M):
        return "toolchain"
    if re.search(r"^error(\[E\d+\])?:", body, re.M):
        return "compile"
    return "unclassified"


def _result(line: Dict[str, Any], observed: str, reason: str, **extra: Any) -> Dict[str, Any]:
    out = {"id": line["id"], "observed": observed, "reason": reason, "verdict": "not-a-result", "class": None, "diagnostic": None,
           "rc": None, "worker": None, "remote_ms": None, "cargo_seconds": None, "log_sha256": None, "log_bytes": None,
           "expected": line["expect"]["outcome"]}
    out.update(extra)
    return out


def judge_line(line: Dict[str, Any], logs_dir: str, workers: Sequence[str]) -> Dict[str, Any]:
    """Decide one line from its own log.  `observed` is pass, fail, or one of the no-result states: missing, infra, refused, malformed."""
    path = os.path.join(logs_dir, os.path.basename(line["log"]))
    if not os.path.isfile(path):
        return _result(line, "missing", "no log file named %s" % line["log"])
    size = os.path.getsize(path)
    if size > MAX_LOG_BYTES:
        return _result(line, "malformed", "the log is %d bytes, over the %d byte limit" % (size, MAX_LOG_BYTES))
    raw = read_bytes(path)
    digest = {"log_sha256": sha256_bytes(raw), "log_bytes": len(raw)}
    text = checks.strip_ansi(raw.decode("utf-8", errors="replace"))
    facts = checks.parse_log(text)
    sidecar = None
    side_path = os.path.join(logs_dir, os.path.basename(line["log"])[:-4] + ".run.json")
    if os.path.isfile(side_path):
        try:
            sidecar = json.loads(read_bytes(side_path).decode("utf-8"))
        except ValueError:
            return _result(line, "malformed", "the run record next to the log is not JSON", **digest)
    has_exit = facts["rc"] is not None
    side_exit = sidecar.get("exit") if isinstance(sidecar, dict) else None
    if not has_exit:
        for marker in INFRA_MARKERS:
            if marker in text:
                return _result(line, "infra", "RCH never ran the command: %s" % marker, **digest)
        if side_exit in (103, 255):
            return _result(line, "infra", "RCH exited %s without a remote command" % side_exit, **digest)
        for pattern, name in REFUSALS:
            m = pattern.search(text)
            if m:
                code = name + m.group(1) if name == "rch-e" else name
                return _result(line, "refused", "RCH refused the command (%s)" % code, **digest)
    if facts["problems"]:
        return _result(line, "malformed", checks.redact("; ".join(facts["problems"])), **digest)
    if facts["argv"] != line["remote_argv"]:
        return _result(line, "malformed", "the command in the log is not this line's: %s" % checks.redact(" ".join(facts["argv"] or [])), **digest)
    if facts["worker"] not in workers:
        return _result(line, "malformed", "ran on worker %s, not one of %s" % (checks.redact(str(facts["worker"])), ",".join(workers)), **digest)
    planned = sidecar.get("planned_worker") if isinstance(sidecar, dict) else None
    if planned is not None and facts["worker"] != planned:
        return _result(line, "malformed", "routed off the planned worker: the run record planned %s (set %s) and RCH ran it on %s" % (
            checks.redact(str(planned)), ",".join(workers), checks.redact(str(facts["worker"]))), **digest)
    rc = facts["rc"]
    if rc in (103, 255):
        return _result(line, "infra", "the remote command itself reported exit %d" % rc, rc=rc, worker=facts["worker"], **digest)
    if side_exit is not None and side_exit != rc:
        return _result(line, "malformed", "rch exited %s but the remote command exited %s" % (side_exit, rc), rc=rc, worker=facts["worker"], **digest)
    common = {"rc": rc, "worker": facts["worker"], "remote_ms": facts["remote_ms"],
              "cargo_seconds": facts["finished"][1] if facts["finished"] else None, **digest}
    if rc == 0:
        if facts["finished"] is None:
            return _result(line, "malformed", "exit 0 but no cargo Finished line", **common)
        if facts["errors"]:
            return _result(line, "malformed", "exit 0 but the log has %d error line(s)" % len(facts["errors"]), **common)
        return _verdict(line, _result(line, "pass", "exit 0 with a Finished line", **common), "")
    if facts["finished"] is not None:
        return _result(line, "malformed", "exit %d but the log also has a cargo Finished line" % rc, **common)
    body = remote_body(text)
    klass = classify_failure(body)
    first = facts["errors"][0] if facts["errors"] else None
    result = _result(line, "fail", "exit %d" % rc, **common)
    result["class"] = klass
    result["diagnostic"] = checks.redact(first) if first else None
    return _verdict(line, result, body)


def _verdict(line: Dict[str, Any], result: Dict[str, Any], body: str) -> Dict[str, Any]:
    exp = line["expect"]
    if exp["outcome"] == "pass":
        result["verdict"] = "as-predicted" if result["observed"] == "pass" else "unexpected-fail"
    elif result["observed"] == "pass":
        result["verdict"] = "unexpected-pass"
    else:
        matches = result["class"] == exp["class"] and any(d in body for d in exp["diagnostic_any"])
        result["verdict"] = "as-predicted" if matches else "unexpected-fail"
        if not matches:
            result["reason"] += "; predicted %s with one of %s" % (exp["class"], exp["diagnostic_any"])
    return result


def judge(manifest: Dict[str, Any], logs_dir: str, only: Optional[Sequence[str]] = None) -> Tuple[List[Dict[str, Any]], List[str], int]:
    """(per-line results, batch problems, exit status).  Batch problems are things no line can explain: an invalid manifest, a log
    that no line owns."""
    problems = validate_manifest(manifest)
    if problems:
        return [], ["manifest: " + p for p in problems], 1
    workers = manifest["workers"].split(",")
    lines = manifest["lines"]
    if only:
        wanted = set(only)
        unknown = wanted - {l["id"] for l in lines}
        if unknown:
            return [], ["--only names no line: %s" % ", ".join(sorted(unknown))], 2
        lines = [l for l in lines if l["id"] in wanted]
    results = [judge_line(l, logs_dir, workers) for l in lines]
    owned = {l["log"] for l in manifest["lines"]}
    owned |= {l["log"][:-4] + ".run.json" for l in manifest["lines"]}
    if os.path.isdir(logs_dir):
        for name in sorted(os.listdir(logs_dir)):
            if name.endswith((".log", ".run.json")) and name not in owned:
                problems.append("unplanned file in the logs directory: %s" % checks.redact(name))
    if problems or any(r["verdict"] == "not-a-result" for r in results):
        return results, problems, 1
    if only:
        return results, problems, 4
    if any(r["verdict"] != "as-predicted" for r in results):
        return results, problems, 3
    return results, problems, 0


def render(manifest: Dict[str, Any], results: Sequence[Dict[str, Any]], problems: Sequence[str], status: int) -> str:
    out = ["E06 batch judge  schema=%s  lines=%d  workspace_rev=%s" % (SCHEMA, len(results), manifest.get("workspace", {}).get("rev", "?")[:12])]
    width = max([len(r["id"]) for r in results] + [10])
    for r in results:
        detail = r["reason"] if r["verdict"] != "as-predicted" else (r["diagnostic"] or "")
        klass = "[%s] " % r["class"] if r["class"] else ""
        out.append("  %-*s  %-9s expected %-4s  %-15s %s%s" % (width, r["id"], r["observed"], r["expected"], r["verdict"], klass, checks.redact(detail)))
    out.extend("  PROBLEM %s" % p for p in problems)
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    out.append("by verdict (information only; the exit status is decided per line): " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    meaning = {0: "every line resolved and was the predicted outcome", 3: "every line resolved; some outcome was NOT the predicted one",
               1: "no result for at least one line (missing, infrastructure, refused or malformed): fail closed",
               4: "a subset was judged; the batch is not judged", 2: "usage"}
    out.append("EXIT %d: %s" % (status, meaning[status]))
    return "\n".join(out) + "\n"


def write_new(path: str, text: str) -> None:
    with open(path, "x", encoding="utf-8") as fh:
        fh.write(text)


def record_of(manifest: Dict[str, Any], manifest_bytes: bytes, results: Sequence[Dict[str, Any]], status: int) -> Dict[str, Any]:
    """The redacted record: per line the outcome, class, expectation, verdict, command and the log's sha256; no log line but one
    bounded, redacted diagnostic.  Raw RCH logs carry worker addresses and local paths and are not committed."""
    by_id = {l["id"]: l for l in manifest["lines"]}
    rows = []
    for r in results:
        line = by_id[r["id"]]
        rows.append({k: r[k] for k in ("id", "observed", "class", "expected", "verdict", "reason", "rc", "worker", "remote_ms",
                                       "cargo_seconds", "log_sha256", "log_bytes", "diagnostic")}
                    | {"command": "RCH_REQUIRE_REMOTE=1 RCH_WORKER=%s rch exec -- %s" % (manifest["workers"], shlex.join(line["remote_argv"])),
                       "expect": line["expect"]})
    return {"schema": RECORD_SCHEMA, "manifest_sha256": sha256_bytes(manifest_bytes), "workspace_rev": manifest["workspace"]["rev"],
            "sources": {k: v["rev"] for k, v in manifest["sources"].items()}, "exit": status, "lines": rows}


def results_rows(manifest: Dict[str, Any], results: Sequence[Dict[str, Any]], rev: str) -> List[Dict[str, Any]]:
    """Rows in the shape `audit.py ingest --results` takes, for the workspace lines that have a result.  Ingest then re-verifies each
    row against its raw log, so this file is a convenience and not evidence."""
    by_id = {l["id"]: l for l in manifest["lines"]}
    rows = []
    for r in results:
        line = by_id[r["id"]]
        if line["group"] != "workspace" or r["observed"] not in ("pass", "fail"):
            continue
        rows.append({"crate": line["crate"], "target": line["target"], "status": r["observed"], "evidence": line["log"],
                     "note": "rc=%d worker=%s rev=%s" % (r["rc"], r["worker"], rev)})
    return rows


# ------------------------------------------------------------------------------------------------------------------ the runner
def run_git(repo: str, *args: str, timeout: float = GIT_TIMEOUT) -> str:
    try:
        proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("git %s did not finish within %g s in %s" % (args[0], timeout, os.path.basename(os.path.abspath(repo)))) from None
    if proc.returncode != 0:
        raise RuntimeError("git %s failed in %s" % (args[0], os.path.basename(os.path.abspath(repo))))
    return proc.stdout.strip()


def archive_into(repo: str, rev: str, dest: str, timeout: float = ARCHIVE_TIMEOUT) -> None:
    """Extract `git archive rev` of `repo` into the new directory `dest`: the pinned bytes, never a working copy.  The archive is a stream,
    which `subprocess` cannot put a deadline on, so a timer kills `git archive` when `timeout` passes: the stream ends and the extraction
    fails as a timeout, not as a wait."""
    if run_git(repo, "cat-file", "-t", rev) != "commit" or run_git(repo, "rev-parse", rev + "^{commit}") != rev:
        raise RuntimeError("%s is not a commit of %s" % (rev[:12], os.path.basename(os.path.abspath(repo))))
    os.makedirs(dest)
    expired = threading.Event()
    with subprocess.Popen(["git", "-C", repo, "archive", "--format=tar", rev], stdout=subprocess.PIPE) as proc:
        def stop() -> None:
            expired.set()
            proc.kill()
        watchdog = threading.Timer(timeout, stop)
        watchdog.start()
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
                try:
                    tf.extractall(dest, filter="data")
                except TypeError:                   # Python before 3.12 has no extraction filters
                    tf.extractall(dest)
        except (tarfile.TarError, EOFError):
            if not expired.is_set():
                raise
        finally:
            # EOF only establishes that the archive stream ended. Keep the
            # watchdog active while waiting for a child that may still be alive.
            try:
                proc.wait()
            finally:
                watchdog.cancel()
    if expired.is_set():
        raise RuntimeError("git archive did not finish within %g s" % timeout)
    if proc.returncode != 0:
        raise RuntimeError("git archive failed")


def reduce_frankenlibc(tree: str, keep: Sequence[str]) -> List[Dict[str, Any]]:
    """Edit the SCRATCH EXPORT (never the upstream repository) so it resolves: only the runtime crates are members, and the dev-
    dependencies that are only needed by tooling (asupersync-conformance, ftui-*) are removed from the membrane's manifest."""
    edits = []
    root = os.path.join(tree, "Cargo.toml")
    before = sha256_bytes(read_bytes(root))
    text = read_bytes(root).decode("utf-8")
    match = re.search(r"members = \[[^\]]*\]", text)
    if not match:
        raise RuntimeError("no workspace members list in the FrankenLibC export")
    with open(root, "w", encoding="utf-8") as fh:
        fh.write(text.replace(match.group(0), "members = [" + ", ".join('"crates/%s"' % c for c in keep) + "]", 1))
    edits.append({"file": "Cargo.toml", "sha256_before": before, "sha256_after": sha256_bytes(read_bytes(root))})
    manifest = os.path.join(tree, "crates", "frankenlibc-membrane", "Cargo.toml")
    before = sha256_bytes(read_bytes(manifest))
    kept, in_dev = [], False
    for line in read_bytes(manifest).decode("utf-8").splitlines(keepends=True):
        header = re.match(r"^\[(.+)\]", line)
        if header:
            in_dev = header.group(1) == "dev-dependencies"
        if in_dev and re.match(r"^(asupersync-conformance|ftui-[a-z-]+)\b", line):
            continue
        kept.append(line)
    with open(manifest, "w", encoding="utf-8") as fh:
        fh.write("".join(kept))
    edits.append({"file": "crates/frankenlibc-membrane/Cargo.toml", "sha256_before": before, "sha256_after": sha256_bytes(read_bytes(manifest))})
    return edits


def prepare_source(name: str, manifest: Dict[str, Any], repo: str, work_dir: str, evidence_dir: str) -> str:
    """The directory the `name` lines run in.  A directory that already exists is accepted only if its sentinel names this source and
    revision; nothing is ever deleted or overwritten."""
    src = manifest["sources"][name]
    dest = os.path.join(work_dir, "%s-%s" % (name, src["rev"][:12]))
    sentinel = os.path.join(dest, SENTINEL)
    stamp = "%s %s\n" % (name, src["rev"])
    if os.path.exists(dest):
        if not os.path.isfile(sentinel) or read_bytes(sentinel).decode("utf-8") != stamp:
            raise RuntimeError("%s exists but is not this prepared source (no matching %s): use a new work dir" % (dest, SENTINEL))
        return dest
    archive_into(repo, src["rev"], dest)
    if name == "frankenlibc":
        edits = reduce_frankenlibc(dest, src["keep_members"])
        if edits != src["edits"]:
            raise RuntimeError("the FrankenLibC edits do not reproduce the recorded hashes: the pinned bytes are not the bytes E06 audited")
        lock_path = os.path.join(evidence_dir, FRANKENLIBC_EVIDENCE, "Cargo.lock.generated")
        data = read_bytes(lock_path)
        if sha256_bytes(data) != src["lock"]["sha256"]:
            raise RuntimeError("the generated Cargo.lock is not the one the manifest records")
        with open(os.path.join(dest, "Cargo.lock"), "wb") as fh:
            fh.write(data)
    with open(sentinel, "w", encoding="utf-8") as fh:
        fh.write(stamp)
    return dest


def prepare_workspace(repo: str, rev: str, export_dir: str) -> str:
    """The workspace export at `rev`: made with git archive, or an existing directory whose sentinel says it IS that revision."""
    stamp = "workspace %s\n" % rev
    sentinel = os.path.join(export_dir, SENTINEL)
    if os.path.exists(export_dir):
        if not os.path.isfile(sentinel) or read_bytes(sentinel).decode("utf-8") != stamp:
            raise RuntimeError("%s exists but is not an export of %s (no matching %s)" % (export_dir, rev[:12], SENTINEL))
        return export_dir
    archive_into(repo, rev, export_dir)
    with open(sentinel, "w", encoding="utf-8") as fh:
        fh.write(stamp)
    return export_dir


def planned_worker(manifest: Dict[str, Any], line_id: str, override: Optional[str] = None) -> str:
    """The ONE worker `run` pins a line to with `rch exec --worker`.  The environment's worker set is not enough: a source export can ship its own
    `.rch/config.toml` whose `preferred_workers` RCH merges with `RCH_WORKER` (the Asupersync export at 8940119023c0 does, and 9 of its first 13 lines landed on
    a worker with no nightly rust-src).  `--worker` overrides both.  Without `override` the manifest's set is dealt out by the line's position in the manifest,
    so a partial rerun (`--only`) puts a line on the worker the full run would have."""
    workers = manifest["workers"].split(",")
    if override is not None:
        if override not in workers:
            raise ValueError("--worker %s is not in the manifest's worker set %s" % (override, manifest["workers"]))
        return override
    ids = [l["id"] for l in manifest["lines"]]
    return workers[ids.index(line_id) % len(workers)]


def selected_workers(log_path: str) -> List[str]:
    """Every worker RCH says it selected in a log, in order (a retry makes more than one).  Empty when the log has none."""
    with open(log_path, "rb") as fh:
        text = checks.strip_ansi(fh.read(MAX_LOG_BYTES).decode("utf-8", errors="replace"))
    return [m.group("alias") for m in checks.WORKER.finditer(text)]


def printable(line: Dict[str, Any], root: str, manifest: Dict[str, Any], canonical: bool, worker: str) -> str:
    env = ["RCH_REQUIRE_REMOTE=1", "RCH_WORKER=%s" % manifest["workers"]]
    if canonical:
        env.append("RCH_CANONICAL_PROJECT_ROOT=%s" % shlex.quote(root))
    # Display only: the runner starts `rch` directly with this working directory and environment; there is no shell and no chain.
    # `--worker` sits BEFORE `--`, so the remote argv the judge compares is untouched.
    return "cwd=%s  %s rch exec --worker %s -- %s" % (shlex.quote(root), " ".join(env), worker, shlex.join(line["remote_argv"]))


def run_batch(args: argparse.Namespace) -> int:
    set_bypass = [k for k in BYPASS_ENV if k in os.environ]
    if set_bypass:
        print("batch.py run: refusing to run with %s set (a bypass would manufacture a pass)" % ", ".join(set_bypass), file=sys.stderr)
        return 2
    manifest_bytes = read_bytes(args.manifest)
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    problems = validate_manifest(manifest)
    if problems:
        print("batch.py run: the manifest is invalid: %s" % "; ".join(problems[:5]), file=sys.stderr)
        return 2
    sentinel = os.path.join(args.workspace_export, SENTINEL)
    stamp = "workspace %s\n" % manifest["workspace"]["rev"]
    if not os.path.isfile(sentinel) or read_bytes(sentinel).decode("utf-8") != stamp:
        print("batch.py run: the workspace export is not an export of the manifest's revision %s (its %s does not say so): "
              "make one with `batch.py gen`" % (manifest["workspace"]["rev"][:12], SENTINEL), file=sys.stderr)
        return 2
    try:
        current = workspace_plan(args.workspace_export)
    except RuntimeError as exc:
        print("batch.py run: %s" % exc, file=sys.stderr)
        return 2
    if sha256_bytes("\n".join(current).encode("utf-8")) != manifest["workspace"]["plan_sha256"]:
        print("batch.py run: the workspace export's plan differs from the manifest's: the manifest is stale, regenerate it", file=sys.stderr)
        return 2
    if args.worker is not None and args.worker not in manifest["workers"].split(","):
        print("batch.py run: --worker %s is not in the manifest's worker set %s" % (args.worker, manifest["workers"]), file=sys.stderr)
        return 2
    selected = [l for l in manifest["lines"] if not args.only or l["id"] in args.only]
    if args.only and len(selected) != len(set(args.only)):
        print("batch.py run: --only names a line the manifest does not have", file=sys.stderr)
        return 2
    os.makedirs(args.logs_dir, exist_ok=True)
    clashes = [l["log"] for l in selected if os.path.exists(os.path.join(args.logs_dir, l["log"]))]
    if clashes:
        print("batch.py run: logs already exist and are never overwritten: %s" % ", ".join(clashes[:4]), file=sys.stderr)
        return 2
    evidence_dir = args.evidence_dir or os.path.join(ROOT, EVIDENCE_REL)
    roots = {"workspace": os.path.abspath(args.workspace_export)}
    repos = {"asupersync": args.asupersync_repo, "frankenlibc": args.frankenlibc_repo}
    try:
        for source in sorted({l["source"] for l in selected if l["group"] == "upstream"}):
            if not repos[source]:
                print("batch.py run: --%s-repo is needed for the %s lines" % (source, source), file=sys.stderr)
                return 2
            if args.dry_run and not os.path.exists(os.path.join(args.work_dir, "%s-%s" % (source, manifest["sources"][source]["rev"][:12]))):
                roots[source] = os.path.join(args.work_dir, "%s-%s" % (source, manifest["sources"][source]["rev"][:12]))
            else:
                roots[source] = prepare_source(source, manifest, repos[source], args.work_dir, evidence_dir)
    except (RuntimeError, OSError) as exc:
        print("batch.py run: %s" % exc, file=sys.stderr)
        return 2
    for line in selected:
        root = roots[line["source"]]
        worker = planned_worker(manifest, line["id"], args.worker)
        text = printable(line, root, manifest, not args.no_canonical_root, worker)
        print("%s  %s" % (line["id"], text), flush=True)
        if args.dry_run:
            continue
        env = dict(os.environ)
        env.update(line["env"])
        if not args.no_canonical_root:
            env["RCH_CANONICAL_PROJECT_ROOT"] = root
        argv = [args.rch, "exec", "--worker", worker, "--"] + line["remote_argv"]
        started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        log_path = os.path.join(args.logs_dir, line["log"])
        with open(log_path, "xb") as log:
            try:
                proc = subprocess.run(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
                code: Any = proc.returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
        ended = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        chosen = selected_workers(log_path)
        with open(os.path.join(args.logs_dir, line["log"][:-4] + ".run.json"), "x", encoding="utf-8") as fh:
            json.dump({"id": line["id"], "exit": code, "started": started, "ended": ended,
                       "argv": ["rch", "exec", "--worker", worker, "--"] + line["remote_argv"],
                       "worker_set": manifest["workers"], "planned_worker": worker, "selected_workers": chosen}, fh, sort_keys=True)
            fh.write("\n")
        # What RCH actually did, next to what was planned: a line that did not run on its planned worker is named here and is `malformed` in the judge.
        verdict = "as planned" if chosen == [worker] else ("OFF-PLAN" if chosen else "no worker line in the log")
        print("   -> exit %s; worker planned %s (set %s), RCH selected %s: %s" % (
            code, worker, manifest["workers"], ",".join(chosen) if chosen else "none", verdict), flush=True)
    return 0


# ------------------------------------------------------------------------------------------------------------------ command line
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="E06 open items 3 and 4 as one runnable batch with its judge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen", help="write the manifest for a workspace export (a new file)")
    g.add_argument("--workspace-repo", required=True, help="the repository whose revision the workspace lines are for")
    g.add_argument("--workspace-rev", default=None, help="a commit of it (default HEAD); the full 40-hex id is recorded, never typed")
    g.add_argument("--export-dir", required=True, help="where the git archive export is made (a new directory)")
    g.add_argument("--out", required=True)
    g.add_argument("--evidence-dir", default=None)
    r = sub.add_parser("run", help="prepare the sources and run the lines (the only subcommand that starts builds)")
    r.add_argument("--manifest", required=True)
    r.add_argument("--workspace-export", required=True, help="the export `batch.py gen` made; its sentinel must name the manifest's revision")
    r.add_argument("--asupersync-repo", default=None, help="the Asupersync repository; the pinned revision is extracted with git archive")
    r.add_argument("--frankenlibc-repo", default=None, help="the FrankenLibC repository; the pinned revision is extracted with git archive")
    r.add_argument("--work-dir", required=True, help="where the upstream exports are made (new directories only)")
    r.add_argument("--logs-dir", required=True)
    r.add_argument("--only", action="append", default=None, metavar="ID")
    r.add_argument("--dry-run", action="store_true", help="print every resolved line and start nothing")
    r.add_argument("--no-canonical-root", action="store_true", help="do not set RCH_CANONICAL_PROJECT_ROOT (exports under the canonical root)")
    r.add_argument("--worker", default=None, metavar="ALIAS",
                   help="pin every selected line to this one worker of the manifest's set (default: the set is dealt out by line position)")
    r.add_argument("--rch", default="rch")
    r.add_argument("--timeout", type=int, default=3600, help="seconds per line")
    r.add_argument("--evidence-dir", default=None)
    j = sub.add_parser("judge", help="decide each line from its log (reads only the manifest and the logs)")
    j.add_argument("--manifest", required=True)
    j.add_argument("--logs-dir", required=True)
    j.add_argument("--only", action="append", default=None, metavar="ID")
    j.add_argument("--record", default=None, metavar="OUT", help="write the redacted record here (a new file)")
    j.add_argument("--results-jsonl", default=None, metavar="OUT", help="write audit.py-ingest rows for the workspace lines (needs --rev)")
    j.add_argument("--rev", default=None)
    args = ap.parse_args(argv)
    if args.cmd == "gen":
        plan_out = args.out + ".workspace-plan.txt"
        for existing in (args.out, plan_out):
            if os.path.exists(existing):
                print("batch.py gen: %s exists; manifests are never overwritten" % existing, file=sys.stderr)
                return 2
        try:
            rev = run_git(args.workspace_repo, "rev-parse", (args.workspace_rev or "HEAD") + "^{commit}")
            export = prepare_workspace(args.workspace_repo, rev, args.export_dir)
            manifest = build_manifest(export, rev, args.evidence_dir)
        except (RuntimeError, ValueError, OSError) as exc:
            print("batch.py gen: %s" % exc, file=sys.stderr)
            return 2
        write_new(args.out, json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        # The workspace lines in `audit.py plan` format, for `audit.py ingest --plan-file` (the redacted committed record of item 4).
        write_new(plan_out, "\n".join(workspace_plan(export)) + "\n")
        print("wrote %s: %d lines for workspace revision %s" % (os.path.basename(args.out), len(manifest["lines"]), rev))
        return 0
    if args.cmd == "run":
        return run_batch(args)
    if (args.results_jsonl is None) != (args.rev is None):
        ap.error("--results-jsonl and --rev go together")
    if args.rev is not None and not HEX40.match(args.rev):
        ap.error("--rev must be a 40-hex commit")
    for out in (args.record, args.results_jsonl):
        if out and os.path.exists(out):
            print("batch.py judge: %s exists; records are never overwritten" % out, file=sys.stderr)
            return 2
    try:
        manifest_bytes = read_bytes(args.manifest)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, ValueError):
        print("batch.py judge: the manifest cannot be read as JSON", file=sys.stderr)
        return 2
    results, problems, status = judge(manifest, args.logs_dir, args.only)
    if status == 2:
        print("batch.py judge: %s" % "; ".join(problems), file=sys.stderr)
        return 2
    if not results and problems:
        print("batch.py judge: " + "; ".join(problems[:5]), file=sys.stderr)
        return 1
    sys.stdout.write(render(manifest, results, problems, status))
    if status in (0, 3):
        if args.record:
            write_new(args.record, json.dumps(record_of(manifest, manifest_bytes, results, status), indent=1, sort_keys=True) + "\n")
        if args.results_jsonl:
            write_new(args.results_jsonl, "".join(json.dumps(row, sort_keys=True) + "\n" for row in results_rows(manifest, results, args.rev)))
    return status


if __name__ == "__main__":
    sys.exit(main())
