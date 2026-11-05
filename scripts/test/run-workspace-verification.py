#!/usr/bin/env python3
"""
Workspace & Cross-Architecture Verification Runner (`scripts/test/run-workspace-verification.py`).

Runs unit, property, cross-compile, initramfs, QEMU full-system boot, and virtual-house
verification suites for FrankenFirmware, scans all outputs for forbidden identifiers
(RFC1918 IPs, MAC addresses, RINCON_ UUIDs, household IDs, tokens), and writes a
SuiteReceipt JSON file.

Execution policy (AGENTS.md: all builds use ``RCH_REQUIRE_REMOTE=1 rch exec``):

* Every cargo invocation is run as ``rch exec [FFW_RCH_EXEC_ARGS] -- cargo ...`` with
  ``RCH_REQUIRE_REMOTE=1``.  There is no local cargo path, no local toolchain default and no
  bypass: ``RCH_CARGO_WRAPPER_BYPASS`` / ``RCH_ENABLED`` are removed from the child
  environment, and the former ``FFW_STABLE_CARGO`` / ``FFW_NIGHTLY_CARGO`` / ``FFW_BUILD_DIR``
  overrides are ignored (with a warning).  If ``rch`` is missing or refuses to go remote the
  case FAILS; it never falls back.
* Pure-Python cases (initramfs self-test, QEMU boot verification) are not builds and run
  locally.
* ``FFW_RCH_EXEC_ARGS`` (empty by default) carries per-invocation rch options such as
  ``--worker NAME --source-content-receipt``.  ``FFW_ASUPERSYNC_DIR`` overrides the sibling
  ``asupersync`` checkout used by the p05 suite.

What counts as success.  Printed text is never evidence of completion.  A case passes only if
ALL of these hold; any one failing makes it ``failed`` and, where completion itself could not be
established, ``completion: "unconfirmed"``:

1. A terminal exit status was observed (the launcher wrapper records it in a ``.rc`` file) and
   it is 0.  A case that is still running when the timeout expires is NOT killed: killing the
   local ``rch exec`` client would cancel or orphan the remote job.  It is recorded as
   ``unconfirmed`` with its recovery identity (pid, log, ``.rc`` file) and the suite stops, since
   an unconfirmed job may still hold source/target locks.
2. No rch terminal non-success marker appears in the output
   (``RCH_SCOPED_COMPLETION_UNCONFIRMED``, ``RCH_EXTERNAL_DEADLINE``, ``*_IDENTITY_UNAVAILABLE``,
   ownership/launch refusals).  These are emitted by rch's remote supervisor, which can print
   real test output before it loses the job; the marker overrides an exit status of 0.
3. Capture is complete: the whole output was read back, within ``MAX_CAPTURE_BYTES``, and decoded
   without loss.
4. For ``cargo test`` cases, every started test binary (``Running`` / ``Doc-tests``) reported a
   ``test result:`` line, each result accounts for exactly the tests its ``running N tests``
   line announced, none failed, and at least one test passed.
5. No forbidden identifier appears in the output.

Recovery.  ``--recover <log-dir>`` re-judges an earlier run from the ``.log`` / ``.rc`` files it
left behind, with the same ``judge`` and WITHOUT executing anything, and writes a new receipt
marked ``recovered_from``.  A case whose ``.rc`` is still missing stays ``unconfirmed``; a case
with no log stays ``not_run``.  The original receipt and logs are never edited.

Receipt (``schema_version`` 2).  A new file ``suite-receipt-<suite>-<utc>-<rand>.json`` is
created for every run with exclusive-create semantics, so earlier receipts are never
overwritten.  Raw capture logs go under the git-ignored ``build/workspace-verification/``.  The
legacy ``suite-receipt-<suite>.json`` files were produced with the local bypass and a hardcoded
``assertions_checked: 1``; they stay as host observations and must not qualify acceptance.
``assertions_checked`` is always ``null`` (cargo does not report assertions); ``tests_passed`` is
parsed from cargo's own ``test result:`` lines.  This script reports what ran; it does not close
or qualify any bead.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = REPO_ROOT / "toolchain" / "results"
LOG_ROOT = REPO_ROOT / "build" / "workspace-verification"  # git-ignored
SCHEMA_VERSION = 2
DEFAULT_CASE_TIMEOUT_S = 7200.0
MAX_CAPTURE_BYTES = 16 << 20

RCH = "rch"
# Variables that could turn a strict-remote build into a local one: never passed to a child.
RCH_LOCAL_ESCAPES = ("RCH_CARGO_WRAPPER_BYPASS", "RCH_ENABLED")
# Former local-cargo knobs.  They are ignored so they cannot reintroduce a local build.
IGNORED_LOCAL_CARGO_OVERRIDES = ("FFW_STABLE_CARGO", "FFW_NIGHTLY_CARGO", "FFW_BUILD_DIR")

FORBIDDEN_PATTERNS = [
    ("rfc1918_ip", re.compile(r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("rincon_uuid", re.compile(r"RINCON_[0-9A-Fa-f]+")),
    ("household_id", re.compile(r"Sonos_[A-Za-z0-9_-]{20,}")),
]

# Terminal non-success markers printed by rch's remote supervisor (strings in the rch binary).
# Each is emitted on its own line; matching is token-based so a log prefix cannot hide one.
UNCONFIRMED_MARKERS = ("RCH_SCOPED_COMPLETION_UNCONFIRMED",)
DEADLINE_MARKERS = ("RCH_EXTERNAL_DEADLINE",)
REFUSAL_MARKERS = (
    "RCH_SCOPED_LAUNCH_ALREADY_OWNED",
    "RCH_OWNERSHIP_CHECK_UNAVAILABLE",
    "RCH_OWNERSHIP_REPAIR_UNAVAILABLE",
    "RCH_REPO_UPDATER_UNAVAILABLE",
    "RCH_SOURCE_CLAIM_REPAIRED_EMPTY_CANCELLATION",
)
_IDENTITY_UNAVAILABLE = re.compile(r"(?<![A-Z0-9_])[A-Z][A-Z0-9_]*_IDENTITY_UNAVAILABLE(?![A-Z0-9_])")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_RUNNING = re.compile(r"^\s*(?:Running|Doc-tests)\s+\S")
_ANNOUNCE = re.compile(r"^running (\d+) tests?$")
_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured")

# kind: "cargo-test" | "cargo" run through rch exec; "python" runs locally (not a build).
Case = collections.namedtuple("Case", "case_id kind argv cwd")
# What an executor reports about one finished or still-running command.
Outcome = collections.namedtuple(
    "Outcome", "rc timed_out pid output truncated undecodable capture_error recovery",
    defaults=(0, False, None, "", False, False, None, None))


def scan_for_secrets(text: str) -> list[str]:
    """Names of the forbidden patterns found in ``text``.  Never the matched value."""
    return [name for name, pat in FORBIDDEN_PATTERNS if pat.search(text)]


def sanitize(text: str) -> str:
    """Replace the checkout and home directory so receipts carry no personal paths."""
    out = text
    try:
        home = str(Path.home())
    except RuntimeError:
        home = ""
    for raw, repl in ((str(REPO_ROOT), "<repo>"), (home, "~")):
        if raw and raw != os.sep:
            out = out.replace(raw, repl)
    return out


def display_argv(argv: list[str]) -> list[str]:
    return ["python3" if a == sys.executable else sanitize(a) for a in argv]


def git_commit_short() -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def rch_exec_args(env) -> list[str]:
    """Per-invocation rch options from FFW_RCH_EXEC_ARGS (empty by default)."""
    raw = env.get("FFW_RCH_EXEC_ARGS", "")
    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        raise ValueError(f"FFW_RCH_EXEC_ARGS is not valid shell syntax: {exc}")
    if "--" in tokens:
        raise ValueError("FFW_RCH_EXEC_ARGS must not contain '--'; the command separator is added for you")
    return tokens


def child_env(base_env, *, remote: bool) -> dict:
    """Environment for one child: strict remote for builds, no local-escape variables."""
    env = {k: v for k, v in dict(base_env).items() if k not in RCH_LOCAL_ESCAPES}
    if remote:
        env["RCH_REQUIRE_REMOTE"] = "1"
        env.setdefault("RCH_VISIBILITY", "summary")
    return env


def suite_cases(suite: str, env=None) -> list[Case]:
    env = os.environ if env is None else env
    exec_args = rch_exec_args(env)
    nightly = "+" + (env.get("FFW_NIGHTLY_TOOLCHAIN") or "nightly")
    asupersync = Path(env.get("FFW_ASUPERSYNC_DIR") or REPO_ROOT.parent / "asupersync")
    no_incremental = ["--config", "build.incremental=false"]
    build_std = ["-Z", "build-std=core,alloc,std,panic_abort"]

    def cargo(case_id, toolchain, args, cwd=REPO_ROOT, kind="cargo"):
        tc = [toolchain] if toolchain else []
        return Case(case_id, kind, [RCH, "exec", *exec_args, "--", "cargo", *tc, *args], cwd)

    def cargo_test(case_id, *args):
        return cargo(case_id, None, ["test", *args, *no_incremental], kind="cargo-test")

    def py(case_id, script, *args):
        return Case(case_id, "python", [sys.executable, str(REPO_ROOT / "toolchain" / "src" / script), *args], REPO_ROOT)

    def cross_check(case_id, target, cwd=REPO_ROOT, extra=()):
        return cargo(case_id, nightly, ["check", *extra, *no_incremental, "--target", target, *build_std], cwd=cwd)

    cases_by_suite = {
        "q00": [cargo_test("q00_test_support_unit_and_canaries", "-p", "franken-test-support")],
        "e01": [cargo_test("e01_board_profile_catalog_and_reconciliation", "-p", "franken-board-profile")],
        "e07": [
            py("e07_mkinitramfs_self_test", "mkinitramfs.py", "--self-test"),
            py("e07_qemu_mips_and_ppc_boot_verification", "run-qemu-verification.py", "--skip-build"),
        ],
        "e03": [
            cargo_test("e03_platform_capability_matrix_unit", "-p", "franken-platform"),
            py("e03_qemu_kernel_abi_probes", "run-qemu-verification.py", "--skip-build"),
        ],
        "p01": [
            cargo_test("p01_workspace_unit_tests", "--workspace"),
            cargo("p01_workspace_clippy_zero_warnings", None,
                  ["clippy", "--workspace", "--all-targets", *no_incremental, "--", "-D", "warnings"]),
            cross_check("p01_workspace_cross_check_ppc_be", "powerpc-unknown-linux-musl", extra=["--workspace"]),
            cross_check("p01_workspace_cross_check_mips_be", "mips-unknown-linux-musl", extra=["--workspace"]),
            # The Virtual House harness is behind the off-by-default `harness` feature (it links test-support, which a
            # default speaker build must not). Without the feature this command exits 2 by design.
            cargo("p01_virtual_house_e2e", None,
                  ["run", "-p", "franken-speaker", "--features", "harness", *no_incremental,
                   "--", "--self-test", "--virtual-house"]),
        ],
        "p05": [
            cargo_test("p05_platform_portable_atomic_tests", "-p", "franken-platform"),
            cross_check("p05_asupersync_check_powerpc_be", "powerpc-unknown-linux-musl", cwd=asupersync,
                        extra=["--no-default-features", "--lib"]),
            cross_check("p05_asupersync_check_mips_be", "mips-unknown-linux-musl", cwd=asupersync,
                        extra=["--no-default-features", "--lib"]),
        ],
    }

    if suite == "all":
        combined = []
        seen = set()
        for k in ["q00", "e01", "e07", "e03", "p01", "p05"]:
            for case in cases_by_suite[k]:
                if case.case_id not in seen:
                    seen.add(case.case_id)
                    combined.append(case)
        return combined
    if suite not in cases_by_suite:
        raise ValueError(f"Unknown suite '{suite}'. Valid suites: {sorted(list(cases_by_suite.keys()) + ['all'])}")
    return cases_by_suite[suite]


# ------------------------------------------------------------------ evidence analysis


def terminal_markers(text: str) -> list[tuple[str, str]]:
    """rch terminal non-success markers found in ``text``, as (marker, class), in order.

    class: ``unconfirmed`` | ``deadline`` | ``refused``.  Token-based, not whole-line, so an
    ANSI colour or a log prefix cannot hide one; a stray occurrence only ever fails a case."""
    found, seen = [], set()
    for line in _ANSI.sub("", text).splitlines():
        for table, cls in ((UNCONFIRMED_MARKERS, "unconfirmed"), (DEADLINE_MARKERS, "deadline"),
                           (REFUSAL_MARKERS, "refused")):
            for marker in table:
                if re.search(r"(?<![A-Z0-9_])" + marker + r"(?![A-Z0-9_])", line) and marker not in seen:
                    seen.add(marker)
                    found.append((marker, cls))
        for m in _IDENTITY_UNAVAILABLE.finditer(line):
            if m.group(0) not in seen:
                seen.add(m.group(0))
                found.append((m.group(0), "refused"))
    return found


def analyze_libtest(text: str) -> dict:
    """What cargo's libtest output proves about execution.

    ``balanced`` is False if a test binary started (``Running`` / ``Doc-tests``) without
    reporting a ``test result:`` before the next one started or the output ended.
    ``count_mismatch`` is True if a result does not account for exactly the number of tests its
    ``running N tests`` line announced.  Neither can be shown by a printed pass summary alone."""
    starts = 0
    pending = False
    announced = None
    unbalanced = False
    totals = {"passed": 0, "failed": 0, "ignored": 0, "measured": 0}
    results = 0
    failed_line = False
    mismatch = False
    for raw in _ANSI.sub("", text).splitlines():
        line = raw.strip()
        if _RUNNING.match(raw):
            if pending:
                unbalanced = True
            pending, announced = True, None
            starts += 1
            continue
        m = _ANNOUNCE.match(line)
        if m:
            announced = int(m.group(1))
            continue
        m = _RESULT.match(line)
        if m:
            results += 1
            passed, failed, ignored, measured = (int(m.group(i)) for i in (2, 3, 4, 5))
            totals["passed"] += passed
            totals["failed"] += failed
            totals["ignored"] += ignored
            totals["measured"] += measured
            failed_line = failed_line or m.group(1) != "ok"
            if announced is not None and announced != passed + failed + ignored + measured:
                mismatch = True
            pending, announced = False, None
    return {
        "binaries_started": starts,
        "results": results,
        **totals,
        "failed_line": failed_line,
        "balanced": not unbalanced and not pending,
        "count_mismatch": mismatch,
        "cross_checked": starts > 0,
    }


def _result(case: Case, *, status, reason, duration_ms=0, exit_code=None, completion="confirmed",
            tests_passed=None, rch_lines=(), markers=(), libtest=None, capture=None, recovery=None) -> dict:
    return {
        "case_id": case.case_id,
        "status": status,
        "executor": "local_python" if case.kind == "python" else "rch_remote_required",
        "argv": display_argv(case.argv),
        "exit_code": exit_code,
        "completion": completion,
        "duration_ms": duration_ms,
        "assertions_checked": None,  # cargo reports tests, not assertions; never hardcoded
        "tests_passed": tests_passed,
        "libtest": libtest,
        "terminal_markers": [m for m, _ in markers],
        "capture": capture,
        "recovery": recovery,
        "rch_lines": list(rch_lines),
        "failure_reason": reason,
    }


def judge(case: Case, out: Outcome, *, duration_ms: int, timeout_s: float) -> dict:
    """Turn one Outcome into a verdict.  Pass is the last branch, not the default."""
    text = _ANSI.sub("", out.output or "")
    markers = terminal_markers(text)
    classes = {c for _, c in markers}
    hits = scan_for_secrets(text)
    lt = analyze_libtest(text) if case.kind == "cargo-test" else None
    rch_lines = [sanitize(ln.strip())[:200] for ln in text.splitlines() if ln.startswith("[RCH]")][:5]
    capture = {"bytes": len((out.output or "").encode("utf-8", "replace")), "truncated": bool(out.truncated),
               "undecodable": bool(out.undecodable), "error": out.capture_error}
    recovery = out.recovery

    completion, reason = "confirmed", None
    if out.timed_out:
        completion = "unconfirmed"
        reason = (f"completion_unconfirmed: no terminal outcome within {timeout_s:g}s; the job was NOT killed "
                  f"(pid {out.pid}); recover it from the recorded log and .rc file")
    elif "unconfirmed" in classes:
        completion = "unconfirmed"
        reason = (f"completion_unconfirmed: {', '.join(m for m, c in markers if c == 'unconfirmed')} "
                  f"(exit {out.rc}); printed test results do not establish completion")
    elif out.rc is None:
        completion = "unconfirmed"
        reason = "completion_unconfirmed: no exit status was recorded"
    elif out.capture_error or out.truncated or out.undecodable:
        completion = "unconfirmed"
        why = out.capture_error or ("output exceeded the capture limit" if out.truncated else "output was not valid UTF-8")
        reason = f"capture_incomplete: {why}"
    elif "deadline" in classes:
        reason = f"deadline_exceeded: {', '.join(m for m, c in markers if c == 'deadline')} (exit {out.rc})"
    elif "refused" in classes:
        reason = f"rch_refused_or_setup_failed: {', '.join(m for m, c in markers if c == 'refused')} (exit {out.rc})"
    elif out.rc != 0:
        reason = f"exit_code={out.rc}: {sanitize(text[-400:].strip())}"
    elif lt is not None:
        if lt["failed"] or lt["failed_line"]:
            reason = f"tests_failed: {lt['failed']} failed"
        elif not lt["balanced"]:
            completion = "unconfirmed"
            reason = "test_execution_incomplete: a test binary started but never reported a result"
        elif lt["count_mismatch"]:
            completion = "unconfirmed"
            reason = "test_execution_incomplete: a result does not account for the tests it announced"
        elif lt["passed"] < 1:
            reason = "no_tests_executed: cargo test exited 0 but reported no passed tests"
    if hits:
        note = f"secret_leak_detected={hits}"
        reason = note if reason is None else f"{reason}; {note}"

    status = "passed" if reason is None else "failed"
    return _result(case, status=status, reason=reason, duration_ms=duration_ms, exit_code=out.rc,
                   completion=completion, tests_passed=lt["passed"] if lt else None, rch_lines=rch_lines,
                   markers=markers, libtest=lt, capture=capture,
                   recovery=recovery if completion == "unconfirmed" else None)


# ------------------------------------------------------------------ execution

# Runs the command, then records its exit status in $FFW_RC_FILE even if nobody is waiting any
# more.  That file is the recovery identity of a job that outlived its timeout.
_WRAPPER = '"$@"; rc=$?; printf "%s\\n" "$rc" > "$FFW_RC_FILE"; exit "$rc"'


def _read_log(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_CAPTURE_BYTES + 1)
    except OSError as exc:
        return "", False, False, f"could not read capture log: {exc.__class__.__name__}"
    truncated = len(data) > MAX_CAPTURE_BYTES
    text = data[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    return text, truncated, "�" in text, None


def launch(argv, *, cwd, env, timeout_s, log_dir, name) -> Outcome:
    """Run ``argv`` with output going to a log file and its exit status to a ``.rc`` file.

    On timeout the process is deliberately left running: killing a local ``rch exec`` client
    can cancel or orphan the remote job.  The returned Outcome has ``rc=None, timed_out=True``
    and a ``recovery`` identity (pid, started time, log path, rc file)."""
    if shutil.which(argv[0], path=env.get("PATH")) is None:
        raise FileNotFoundError(2, "executable not found", argv[0])
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path, rc_path = log_dir / f"{name}.log", log_dir / f"{name}.rc"
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(log_path, "xb") as log_f:  # never clobbers an earlier capture
        proc = subprocess.Popen(
            ["/bin/sh", "-c", _WRAPPER, "ffw-launch", *argv], cwd=cwd, env=dict(env, FFW_RC_FILE=str(rc_path)),
            stdin=subprocess.DEVNULL, stdout=log_f, stderr=subprocess.STDOUT)
    recovery = {"pid": proc.pid, "started_utc": started, "log": sanitize(str(log_path)),
                "rc_file": sanitize(str(rc_path)),
                "note": "not killed; completion is unconfirmed until the rc_file exists and holds the exit status"}
    try:
        proc.wait(timeout=timeout_s)
        rc, timed_out = proc.returncode, False
    except subprocess.TimeoutExpired:
        rc, timed_out = None, True  # intentionally NOT killed
    text, truncated, undecodable, error = _read_log(log_path)
    return Outcome(rc, timed_out, proc.pid, text, truncated, undecodable, error, recovery)


def run_case(case: Case, *, executor=launch, base_env=None, timeout_s: float = DEFAULT_CASE_TIMEOUT_S,
             log_dir=None) -> dict:
    base_env = os.environ if base_env is None else base_env
    if not case.cwd.is_dir():
        return _result(case, status="failed", completion="confirmed",
                       reason=f"prerequisite_missing: working directory {sanitize(str(case.cwd))} does not exist")
    env = child_env(base_env, remote=case.kind != "python")
    t0 = time.monotonic()
    try:
        out = executor(case.argv, cwd=str(case.cwd), env=env, timeout_s=timeout_s,
                       log_dir=log_dir or LOG_ROOT / "adhoc", name=case.case_id)
    except FileNotFoundError:
        return _result(case, status="failed", completion="confirmed", duration_ms=int((time.monotonic() - t0) * 1000),
                       reason=(f"launcher_missing: {sanitize(case.argv[0])} not found; builds run only through "
                               f"'rch exec' and there is no local fallback"))
    return judge(case, out, duration_ms=int((time.monotonic() - t0) * 1000), timeout_s=timeout_s)


def not_run_result(case: Case, because: str) -> dict:
    return _result(case, status="not_run", completion=None,
                   reason=f"not_run: {because} completion is unconfirmed; recover that job before running more")


_RUN_DIR = re.compile(r"^(?P<suite>[a-z0-9]+)-\d{8}T\d{6}Z-[0-9a-f]{6}$")


def recovered_outcome(log_dir: Path, case_id: str):
    """Outcome rebuilt from the files an earlier run left behind; None if the case never started."""
    log_path, rc_path = log_dir / f"{case_id}.log", log_dir / f"{case_id}.rc"
    if not log_path.is_file():
        return None
    text, truncated, undecodable, error = _read_log(log_path)
    rc = None
    if rc_path.is_file():
        try:
            rc = int(rc_path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            rc = None  # an unreadable status is no status
    recovery = {"log": sanitize(str(log_path)), "rc_file": sanitize(str(rc_path)),
                "note": "re-judged from files left by an earlier run; nothing was executed"}
    return Outcome(rc, False, None, text, truncated, undecodable, error, recovery)


def recover_cases(log_dir: Path, cases, timeout_s: float) -> list:
    results, halted = [], None
    for case in cases:
        out = recovered_outcome(log_dir, case.case_id)
        if out is None:
            results.append(_result(case, status="not_run", completion=None,
                                   reason="not_run: the earlier run left no capture log for this case"))
            continue
        res = judge(case, out, duration_ms=0, timeout_s=timeout_s)
        results.append(res)
        if res["completion"] == "unconfirmed" and halted is None:
            halted = case.case_id
    return results


def write_receipt(results_dir: Path, suite: str, text: str, stamp: str | None = None) -> Path:
    """Create a new receipt file; an existing receipt is never overwritten."""
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = stamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for _ in range(8):
        path = results_dir / f"suite-receipt-{suite}-{stamp}-{secrets.token_hex(3)}.json"
        try:
            with open(path, "x", encoding="utf-8") as fh:
                fh.write(text)
            return path
        except FileExistsError:
            continue
    raise OSError("could not create a unique receipt file name")


def main(argv=None, *, executor=launch, env=None, results_dir=None, log_root=None) -> int:
    parser = argparse.ArgumentParser(description="Run FrankenFirmware workspace verification suite and emit receipt.")
    parser.add_argument("suite", nargs="?", default=None, help="Suite ID (q00, e01, e07, e03, p01, p05, all)")
    parser.add_argument("--recover", metavar="LOG_DIR", default=None,
                        help="re-judge an earlier run from its .log/.rc files; executes nothing")
    parser.add_argument("--seed", type=int, default=0x5F3759DF, help="Deterministic PRNG seed")
    parser.add_argument("--case-timeout-s", type=float, default=DEFAULT_CASE_TIMEOUT_S,
                        help="per-case limit in seconds; a case still running is NOT killed (default %(default)g)")
    parser.add_argument("--results-dir", default=None, help="receipt directory (default: toolchain/results)")
    parser.add_argument("--log-root", default=None, help="raw capture logs (default: build/workspace-verification)")
    args = parser.parse_args(argv)
    if not args.case_timeout_s > 0:
        print("error: --case-timeout-s must be > 0", file=sys.stderr)
        return 2

    base_env = os.environ if env is None else env
    recover_dir = Path(args.recover) if args.recover else None
    if recover_dir is not None:
        m = _RUN_DIR.match(recover_dir.name)
        if not recover_dir.is_dir() or not m:
            print("error: --recover needs an existing <suite>-<utc>-<rand> log directory from an earlier run",
                  file=sys.stderr)
            return 2
        if args.suite not in (None, m.group("suite")):
            print(f"error: suite '{args.suite}' does not match the recovered run '{m.group('suite')}'", file=sys.stderr)
            return 2
        args.suite = m.group("suite")
    args.suite = args.suite or "all"
    try:
        cases = suite_cases(args.suite, base_env)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for name in IGNORED_LOCAL_CARGO_OVERRIDES:
        if name in base_env:
            print(f"warning: {name} is ignored; cargo runs only through 'rch exec' with RCH_REQUIRE_REMOTE=1",
                  file=sys.stderr)

    results, halted = [], None
    if recover_dir is not None:
        results = recover_cases(recover_dir, cases, args.case_timeout_s)
        halted = next((r["case_id"] for r in results if r["completion"] == "unconfirmed"), None)
    else:
        run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        log_dir = Path(log_root or args.log_root or LOG_ROOT) / f"{args.suite}-{run_id}"
        for case in cases:
            if halted:
                results.append(not_run_result(case, halted))
                continue
            res = run_case(case, executor=executor, base_env=base_env, timeout_s=args.case_timeout_s, log_dir=log_dir)
            results.append(res)
            if res["completion"] == "unconfirmed":
                halted = case.case_id
    overall_passed = bool(results) and all(r["status"] == "passed" and r["completion"] == "confirmed" for r in results)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "suite_id": args.suite,
        "seed": args.seed,
        "git_commit": git_commit_short(),
        "remote_required": True,
        "overall_status": "passed" if overall_passed else "failed",
        "halted_after": halted,
        **({"recovered_from": recover_dir.name} if recover_dir is not None else {}),
        "counts": {s: sum(1 for r in results if r["status"] == s) for s in ("passed", "failed", "not_run")},
        "cases": results,
    }

    receipt_json = json.dumps(receipt, indent=2) + "\n"
    secret_hits = scan_for_secrets(receipt_json)
    if secret_hits:
        print(f"FATAL: Secret leak in receipt: {secret_hits}", file=sys.stderr)
        return 2

    out_dir = Path(results_dir or args.results_dir or RESULTS_DIR)
    path = write_receipt(out_dir, args.suite, receipt_json)
    print(receipt_json, end="")
    print(f"receipt: {sanitize(str(path))}", file=sys.stderr)
    return 0 if overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
