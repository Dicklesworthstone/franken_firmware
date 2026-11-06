#!/usr/bin/env python3
"""U01 end-to-end runner (offline, stdlib only; it builds nothing).

    e2e.py                       the full tier: host checks; the process-restart cases are BLOCKED (counted, never skipped)
    e2e.py --tier smoke          only the host checks (seconds)
    e2e.py --tier soak           NOT RUN, with the reason: exit 4, never a pass
    e2e.py --binary PATH         also run the process-restart cases against an example binary this host can run
    e2e.py --mutants             also run the mutation canary (about a minute)
    e2e.py --case ID             run only this case (repeatable; the replay of one case)
    e2e.py --receipts DIR        keep the JSONL diagnostic log and a JSON receipt under DIR
    e2e.py --list                list the cases of the tier

The process-restart cases kill a REAL process mid-write and recover. They need the `journal_crash` example as a binary THIS
host can execute. A binary built by central RCH is a Linux executable on a worker and is not brought back to a macOS
orchestrator, so the central form of these cases is `tests/u01_process.rs` inside `cargo test -p franken-journal`, judged by test
name with `tests/u01/judge_log.py`; here they are BLOCKED unless --binary names a binary this host can run.
Exit codes: 0 every case passed, none is blocked and the diagnostic log is complete; 1 a case failed or the log lost critical evidence;
3 only blocked cases stand in the way; 4 --tier soak; 2 usage.

Tiers are explicit (`full` is the default, so the older invocations mean what they always meant). Every decided case writes a CRITICAL begin and end event
through the shared Q00 `DiagnosticSink` (`case_log.py`); a run whose log lost critical evidence is NOT QUALIFIED, and a log that cannot be kept never turns
a failure into a pass. Without --receipts the log is kept in a fresh `mkdtemp` directory whose path is printed; the runner never deletes it. Each case's
detail passes the sink's redaction before it is printed or recorded. Every subprocess is bounded in time and the one long-lived child (the SIGKILL driver)
has a deadline for each acknowledgement and is killed and reaped on any exit path, so a hung `journal_crash` is a failed case with a sentence, not a hang.
No child can make this runner allocate without bound either: every child (the unit tests of U01-E-001 included) runs in its own session under an absolute deadline with
at most OUTPUT_CAP bytes kept from each of its streams, a larger output is a failed case (never a truncation into a pass), and the whole process group is killed and
reaped on any exit path. The child's stderr is captured through the same bound, never inherited, so nothing it prints reaches the terminal unredacted; the runner's own
error lines name no path and pass the same redaction.

What a pass shows: after the process dies at any byte of a scripted run (abort inside the write or erase that crosses the
N-th byte, or SIGKILL at an arbitrary moment), reopening the file image yields exactly the state before or exactly the
state after the step that was running, as the Python reference computed it. A process kill keeps bytes already handed to
the OS, so this is the prefix-of-unsynced-writes experiment on a real file; the cut-point oracle covers the power cut.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import case_log  # noqa: E402
import reference as ref  # noqa: E402
import scenarios as sc  # noqa: E402

VECTORS = os.path.join(REPO, "crates", "franken-journal", "tests", "vectors", "u01_vectors.json")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
TIERS = ("smoke", "full", "soak")
SMOKE = ("U01-E-001", "U01-E-002")                      # the host checks; every other case is the full tier's
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "U01 soak: NOT RUN. The process experiments already kill a real process at every byte of two scenarios, at every 29th byte of the compacting one and by SIGKILL at "
    "six acknowledged steps; a soak would be a long randomized kill campaign against the centrally built example, which nothing here implements or schedules. "
    "This is not a pass.")
RECEIPT_SCHEMA = "ffw.u01.receipt.v1"
CRASH_TIMEOUT_S = 60       # one init, run or dump of the example binary
VECTORS_TIMEOUT_S = 120    # make_vectors.py --check
MUTANTS_TIMEOUT_S = 900    # the mutation canary
ACK_TIMEOUT_S = 30         # the longest the SIGKILL driver waits for the child's next line
REAP_TIMEOUT_S = 10        # the longest it waits for a killed child to end its output and be reaped
HOST_UNIT_TIMEOUT_S = 300  # the Python unit tests and the verification battery of U01-E-001
OUTPUT_CAP = 1 << 20       # bytes kept from each of a child's streams; one byte more is a failure, never a truncation into a pass
CAUSE_CAP = 400            # characters of a failure's causal text
JUDGED_ARTIFACTS = ("tests/u01/e2e.py", "tests/u01/case_log.py", "tests/u01/reference.py", "tests/u01/scenarios.py", "tests/u01/battery.py", "tests/u01/images.py",
                    "tests/u01/make_vectors.py", "crates/franken-journal/tests/vectors/u01_vectors.json", "scripts/test/test_support/diagnostics.py", "docs/contracts/u01.md")


class Counting(ref.Media):
    """The reference medium that also counts the bytes a script programs and erases: the budget the crash driver spends."""

    def __init__(self, segment_bytes: int) -> None:
        super().__init__(segment_bytes)
        self.issued = 0

    def program(self, offset: int, data: bytes) -> None:
        super().program(offset, data)
        self.issued += len(data)

    def erase(self, index: int) -> None:
        super().erase(index)
        self.issued += self.seg


def script_bytes(steps) -> int:
    media = Counting(ref.TINY.segment_bytes)
    ref.run_script(ref.TINY, steps, media)
    return media.issued


def vector(script_id: str) -> Dict:
    with open(VECTORS, encoding="utf-8") as f:
        doc = json.load(f)
    return next(s for s in doc["scripts"] if s["id"] == script_id)


class Pump:
    """One pipe of a child, drained on a thread into at most `cap` bytes. The moment more would be kept it stops reading and sets `overflowed`; the owner kills the child."""

    def __init__(self, stream: Any, cap: int, wake: threading.Event) -> None:
        self.stream, self.cap, self.wake = stream, cap, wake
        self.data = bytearray()
        self.overflowed = False
        self.done = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        fd = self.stream.fileno()
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                room = self.cap - len(self.data)
                if len(chunk) > room:
                    self.data += chunk[:room]
                    self.overflowed = True
                    break
                self.data += chunk
                self.wake.set()
        except OSError:   # the pipe was closed under the reader
            pass
        finally:
            self.done = True
            self.wake.set()

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


def spawn(argv: List[str], cap: Optional[int], cwd: Optional[str] = None) -> Tuple["subprocess.Popen[bytes]", Pump, Pump, threading.Event]:
    """A child in its own session (so its whole group can be killed), stdin closed, both output streams drained through bounded pumps."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, start_new_session=True)
    wake = threading.Event()
    limit = OUTPUT_CAP if cap is None else cap
    return proc, Pump(proc.stdout, limit, wake), Pump(proc.stderr, limit, wake), wake


def reap(proc: "subprocess.Popen[bytes]", pumps: List[Pump]) -> None:
    """Whatever happened, no child of this driver outlives it: kill the child's whole group while it runs or still holds a pipe, reap it, let the readers end
    (all bounded)."""
    if proc.poll() is None or any(not p.done for p in pumps):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except OSError:
                pass
    try:
        proc.wait(timeout=REAP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"the child did not end within {REAP_TIMEOUT_S} s of SIGKILL") from None
    for pump in pumps:
        pump.thread.join(timeout=REAP_TIMEOUT_S)
        if pump.thread.is_alive():
            raise AssertionError(f"the child's output did not end within {REAP_TIMEOUT_S} s of its death (something else holds the pipe)")
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()


def overflow_text(what: str, cap: int, pump_name: str) -> str:
    return f"{what} wrote more than {cap} bytes to {pump_name} (the child was killed; an overflow is a failure, never truncated into a pass)"


def run_bounded(argv: List[str], timeout: float, what: str, cap: Optional[int] = None, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run a child to completion under one absolute monotonic deadline, keeping at most `cap` bytes of each stream (OUTPUT_CAP by default). A timeout and an
    overflow are failures with a sentence, and the child's group is killed and reaped either way. The result is an ordinary CompletedProcess of decoded text."""
    limit = OUTPUT_CAP if cap is None else cap
    proc, out, err, wake = spawn(argv, limit, cwd)
    deadline = time.monotonic() + timeout
    problem = ""
    try:
        while not (out.done and err.done):
            if out.overflowed or err.overflowed:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                problem = f"{what} timed out after {timeout:g} s (the child was killed)"
                break
            wake.wait(min(remaining, 0.25))
            wake.clear()
        if not problem and (out.overflowed or err.overflowed):
            problem = overflow_text(what, limit, "stdout" if out.overflowed else "stderr")
        if not problem:
            try:
                proc.wait(timeout=max(deadline - time.monotonic(), 0.001))
            except subprocess.TimeoutExpired:
                problem = f"{what} timed out after {timeout:g} s (the child was killed)"
    finally:
        reap(proc, [out, err])
    if problem:
        raise AssertionError(problem)
    return subprocess.CompletedProcess(argv, proc.returncode, out.text(), err.text())


def host_run(argv: List[str], timeout: float, what: str, cap: Optional[int] = None) -> subprocess.CompletedProcess:
    """A bounded subprocess (time and bytes): see `run_bounded`."""
    return run_bounded(argv, timeout, what, cap)


def crash(binary: str, *args: str, timeout: int = CRASH_TIMEOUT_S) -> subprocess.CompletedProcess:
    return host_run([binary, *args], timeout, f"`{' '.join([os.path.basename(binary), *args[:1]])}`")


def acks(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if line.startswith("ack "))


def recovered(binary: str, image: str) -> str:
    out = crash(binary, "dump", image)
    if out.returncode != 0:
        raise AssertionError(f"dump failed: {out.stderr.strip()[:200]}")
    for line in out.stdout.splitlines():
        if line.startswith("state "):
            return line.split(" ", 1)[1]
    raise AssertionError("dump printed no state")


def check_old_or_new(states: List[str], done_acks: int, finished: bool, got: str, where: str) -> None:
    allowed = {states[done_acks]} if finished else {states[done_acks], states[min(done_acks + 1, len(states) - 1)]}
    if got not in allowed:
        raise AssertionError(f"{where}: recovered neither the state before nor after step {done_acks + 1}")


# --------------------------------------------------------------------------- cases

def last_line(text: str) -> str:
    for line in reversed(text.strip().splitlines()):
        if line.strip():
            return line.strip()
    return ""


def unit_cause(report: str) -> str:
    """What failed, not only that something did: unittest's own summary line, the first FAIL or ERROR header (which names the test) and the last line of its
    traceback. Bounded; the caller redacts it."""
    lines = report.splitlines()
    summary = next((l.strip() for l in reversed(lines) if l.startswith(("FAILED (", "OK"))), "")
    at = next((i for i, l in enumerate(lines) if l.startswith(("FAIL: ", "ERROR: "))), None)
    if at is None:
        return (summary + "; " if summary else "") + last_line(report)[:CAUSE_CAP] if report.strip() else "the unit tests failed and printed nothing"
    block = []
    for line in lines[at + 1:]:
        if line.startswith(("======", "Ran ")):
            break
        if line.strip() and set(line.strip()) not in ({"-"}, {"="}):
            block.append(line)
    return f"{summary}; first: {lines[at].strip()}: {last_line(chr(10).join(block))}"[:CAUSE_CAP]


def host_unit_tests(directory: str = HERE, module: str = "test_u01", timeout: float = HOST_UNIT_TIMEOUT_S, cap: Optional[int] = None) -> Tuple[str, str]:
    """The unit tests of one module in an owned child (own session, absolute deadline, bounded output; killed and reaped on any exit path), so a hang or a flood in
    the battery is a failed case with a sentence and the first failing test with its cause is kept."""
    out = run_bounded([sys.executable, "-B", "-m", "unittest", module], timeout, f"the unit tests of {module}", cap, cwd=directory)
    report = out.stderr + out.stdout   # unittest reports on stderr
    ran = re.search(r"^Ran (\d+) tests?", report, re.M)
    if ran and int(ran.group(1)) == 0:
        raise AssertionError(f"no test ran ({module} in {os.path.basename(directory)})")
    if out.returncode != 0 or not ran:
        raise AssertionError(unit_cause(report))
    return PASS, f"{ran.group(1)} tests"


def host_vectors_current(timeout: int = VECTORS_TIMEOUT_S) -> Tuple[str, str]:
    out = host_run([sys.executable, "-B", os.path.join(HERE, "make_vectors.py"), "--check"], timeout, "make_vectors.py --check")
    if out.returncode != 0:
        raise AssertionError((out.stdout.strip() or last_line(out.stderr) or f"make_vectors.py exited {out.returncode}")[:CAUSE_CAP])
    return PASS, out.stdout.strip()


def host_mutants(timeout: int = MUTANTS_TIMEOUT_S) -> Tuple[str, str]:
    out = host_run([sys.executable, "-B", os.path.join(HERE, "mutate.py")], timeout, "the mutation canary")
    last = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()
    if out.returncode != 0:
        raise AssertionError(last)
    return PASS, last


def process_budget_sweep(sid: str, stride: int) -> Callable[[Optional[str]], Tuple[str, str]]:
    def run(binary: Optional[str]) -> Tuple[str, str]:
        assert binary
        script = vector(sid)
        states = script["states_hex"]
        steps = len(script["steps"])
        total = script_bytes([sc.step_from_json(s) for s in script["steps"]])
        died = finished = 0
        for budget in range(0, total + 1, stride):
            with tempfile.TemporaryDirectory(prefix="u01-crash-") as tmp:
                image = os.path.join(tmp, "journal.img")
                if crash(binary, "init", image).returncode != 0:
                    raise AssertionError("init failed")
                out = crash(binary, "run", image, VECTORS, sid, "--die-after-bytes", str(budget))
                done = acks(out.stdout)
                completed = out.returncode == 0 and "done" in out.stdout
                if not completed and out.returncode >= 0:
                    raise AssertionError(f"budget {budget}: the process exited {out.returncode} instead of dying: {out.stderr.strip()[:160]}")
                check_old_or_new(states, done if not completed else steps, completed, recovered(binary, image), f"budget {budget}")
                died += not completed
                finished += completed
        return PASS, f"{died + finished} runs ({died} killed mid-write, {finished} ran to the end), stride {stride}, {total} bytes"
    return run


def stderr_note(err: Pump) -> str:
    line = last_line(err.text())
    return f"; the child's last stderr line: {line[:200]}" if line else ""


def process_sigkill(sid: str, kill_at: List[int], ack_timeout: float = ACK_TIMEOUT_S, cap: Optional[int] = None) -> Callable[[Optional[str]], Tuple[str, str]]:
    def run(binary: Optional[str]) -> Tuple[str, str]:
        assert binary
        states = vector(sid)["states_hex"]
        for target in kill_at:
            with tempfile.TemporaryDirectory(prefix="u01-kill-") as tmp:
                image = os.path.join(tmp, "journal.img")
                if crash(binary, "init", image).returncode != 0:
                    raise AssertionError("init failed")
                proc, out, err, wake = spawn([binary, "run", image, VECTORS, sid], cap)
                limit = OUTPUT_CAP if cap is None else cap
                where = f"SIGKILL after ack {target}"
                try:
                    seen, offset, rest, killed = 0, 0, "", False
                    deadline = time.monotonic() + ack_timeout   # one absolute deadline per expected ack: only an ack moves it, other output does not
                    while True:
                        data = bytes(out.data)
                        while not killed:
                            newline = data.find(b"\n", offset)
                            if newline < 0:
                                if not (out.done and offset < len(data)):
                                    break
                                end = len(data)   # a last line without its newline
                            else:
                                end = newline + 1
                            line, offset = data[offset:end], end
                            if line.startswith(b"ack "):
                                seen += 1
                                deadline = time.monotonic() + ack_timeout
                                if seen >= target:
                                    proc.send_signal(signal.SIGKILL)
                                    killed = True
                        if out.overflowed or err.overflowed:
                            raise AssertionError(overflow_text(where, limit, "stdout" if out.overflowed else "stderr") + stderr_note(err))
                        if killed or (out.done and offset >= len(data)):
                            break
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise AssertionError(f"{where}: no ack within {ack_timeout:g} s after {seen} acks (other output does not extend the deadline; the child was killed)"
                                                 + stderr_note(err))
                        wake.wait(min(remaining, 0.25))
                        wake.clear()
                    if killed:
                        reap_deadline = time.monotonic() + REAP_TIMEOUT_S
                        while not out.done:
                            remaining = reap_deadline - time.monotonic()
                            if remaining <= 0:
                                raise AssertionError(f"{where}: the child's output did not end within {REAP_TIMEOUT_S} s of SIGKILL")
                            wake.wait(min(remaining, 0.25))
                            wake.clear()
                        if out.overflowed:
                            raise AssertionError(overflow_text(where, limit, "stdout"))
                        rest = bytes(out.data)[offset:].decode("utf-8", errors="replace")
                    try:
                        proc.wait(timeout=REAP_TIMEOUT_S)
                    except subprocess.TimeoutExpired:
                        raise AssertionError(f"{where}: the child did not end within {REAP_TIMEOUT_S} s") from None
                finally:
                    reap(proc, [out, err])
                total_acks = seen + acks(rest)
                finished = "done" in rest and proc.returncode == 0
                check_old_or_new(states, total_acks, finished, recovered(binary, image), where)
        return PASS, f"killed with SIGKILL after acks {kill_at}"
    return run


CASES: List[Tuple[str, str, bool, Callable]] = [
    ("U01-E-001", "the Python unit tests and the verification battery hold", False, lambda _b: host_unit_tests()),
    ("U01-E-002", "the shared vectors are current", False, lambda _b: host_vectors_current()),
    ("U01-E-003", "a process killed at every byte of the 'credentials' scenario recovers the old or the new state", True,
     process_budget_sweep("U01-S-002", 1)),
    ("U01-E-004", "a process killed at every byte of the 'namespaces' scenario recovers the old or the new state", True,
     process_budget_sweep("U01-S-001", 1)),
    ("U01-E-005", "a process killed at every 29th byte of the compacting 'churn' scenario recovers the old or the new state", True,
     process_budget_sweep("U01-S-003", 29)),
    ("U01-E-006", "SIGKILL at arbitrary moments of the 'churn' scenario recovers the old or the new state", True,
     process_sigkill("U01-S-003", [3, 17, 40, 41, 60, 83])),
]


MUTANT_CASE = ("U01-E-007", "breaking any one rule of the reference is noticed by the battery", False, lambda _b: host_mutants())


def planned(tier: str, mutants: bool) -> List[Tuple[str, str, bool, Callable]]:
    cases = [c for c in CASES if tier == "full" or c[0] in SMOKE]
    return cases + [MUTANT_CASE] if mutants else cases


def run_case(needs_binary: bool, fn: Callable, binary: Optional[str]) -> Tuple[str, str]:
    if needs_binary and not binary:
        return BLOCKED, "needs a journal_crash binary this host can run (see --help; central form: tests/u01_process.rs + judge_log.py); never counted as passed"
    try:
        return fn(binary)
    except Exception as err:  # noqa: BLE001 - a crashing case is a failed case
        return FAIL, f"{type(err).__name__}: {err}"


def safe(text: str) -> str:
    """The shared Q00 redaction policy, before any human or receipt output (not only the JSONL log). An unavailable sanitizer releases nothing."""
    if not text:
        return ""
    try:
        return case_log.load(REPO).redact_text(text)
    except Exception:  # noqa: BLE001
        return "Diagnostic detail withheld: redaction is unavailable."


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def final_exit(counts: Dict[str, int], evidence: Any) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = 1 if counts[FAIL] else 3 if counts[BLOCKED] else 0
    return 1 if code == 0 and evidence is not None and not evidence.complete else code


def replay_command(tier: str, mutants: bool, ids: List[str], binary: Optional[str]) -> str:
    return "scripts/e2e/u01 --tier %s" % tier + (" --mutants" if mutants else "") + "".join(" --case " + i for i in ids) + (" --binary JOURNAL_CRASH" if binary else "")


def write_receipt(directory: str, doc: Dict[str, Any], run_id: str) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "u01-%s.json" % run_id)
    with open(path, "x", encoding="utf-8") as handle:  # never overwrites an earlier run's receipt
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> "Any":   # argparse echoes the offending argument: that text passes the shared redaction like everything else
        self.print_usage(sys.stderr)
        self.exit(2, safe(f"{self.prog}: error: {message}") + "\n")


def main(argv: List[str]) -> int:
    ap = Parser(description="U01 end-to-end runner", epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tier", choices=TIERS, default="full", help="smoke: the host checks; full (default): and the process cases; soak: not run")
    ap.add_argument("--binary", help="the centrally built `journal_crash` example binary")
    ap.add_argument("--mutants", action="store_true", help="also run the mutation canary")
    ap.add_argument("--case", action="append", metavar="ID", help="run only this case (repeatable)")
    ap.add_argument("--receipts", metavar="DIR", help="keep the JSONL diagnostic log and a JSON receipt here")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    if args.tier == "soak":
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    cases = planned(args.tier, args.mutants)
    if args.case:
        unknown = sorted(set(args.case) - {c[0] for c in cases})
        if unknown:
            print(safe(f"error: not a case of tier {args.tier}{' with these options' if args.mutants else ' (U01-E-007 needs --mutants)'}: {', '.join(unknown)}"), file=sys.stderr)
            return 2
        cases = [c for c in cases if c[0] in args.case]
    if args.list:
        for cid, title, needs_binary, _fn in cases:
            print(f"{cid}  {'process' if needs_binary else 'host   '}  {title}")
        return 0
    if args.binary and not os.access(args.binary, os.X_OK):
        print(safe(f"error: {os.path.basename(args.binary)} is not an executable file (the name only: a path is not echoed)"), file=sys.stderr)
        return 2
    counts = {PASS: 0, FAIL: 0, BLOCKED: 0}
    artifacts = {rel: (sha256_file(os.path.join(REPO, rel)) if os.path.isfile(os.path.join(REPO, rel)) else "missing") for rel in JUDGED_ARTIFACTS}
    run_id = secrets.token_hex(8)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": sys.version.split()[0], "tier": args.tier, "artifact_count": len(artifacts),
        "artifact_set_sha256": hashlib.sha256("".join("%s %s\n" % kv for kv in sorted(artifacts.items())).encode("utf-8")).hexdigest()})
    rows: List[Dict[str, Any]] = []
    for cid, title, needs_binary, fn in cases:
        started = time.monotonic()
        status, detail = run_case(needs_binary, fn, args.binary)
        detail = safe(detail)
        counts[status] += 1
        rows.append({"case": cid, "status": status, "detail": detail, "group": "process" if needs_binary else "host", "seconds": round(time.monotonic() - started, 2)})
        print(f"{status.upper():<8}{cid}  {title} -- {detail}")
        log.record(cid, rows[-1]["group"], status, detail)
    print(f"U01 cases: total={len(cases)} passed={counts[PASS]} failed={counts[FAIL]} blocked={counts[BLOCKED]}")
    evidence = log.finish({"passed": counts[PASS], "failed": counts[FAIL], "blocked": counts[BLOCKED]})
    print(evidence.summary)
    if not evidence.complete:
        print("[diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]")
    if evidence.path and not args.receipts:
        print("diagnostic log kept:", evidence.path)
    code = final_exit(counts, evidence)
    replay = replay_command(args.tier, args.mutants, [c[0] for c in cases] if args.case else [], args.binary)
    bad = [r for r in rows if r["status"] == FAIL] or [r for r in rows if r["status"] == BLOCKED]
    if bad:
        print(f"RETAINED FOR REPLAY. First {bad[0]['status']} case: {bad[0]['case']}: {bad[0]['detail']}")
        print("  replay: " + replay)
    verdict = "NOT QUALIFIED" if code else "PARTIAL (only the selected cases ran; never a qualification)" if args.case else "QUALIFIED"
    print(f"U01 e2e tier={args.tier}: {verdict}")
    if args.receipts:
        doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": args.tier,
               "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "counts": counts, "exit_code": code, "replay": replay,
               "binary": {"name": os.path.basename(args.binary), "sha256": sha256_file(args.binary)} if args.binary else None,
               "artifacts": artifacts, "results": rows,
               "diagnostics": {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log,
                               "file": os.path.basename(evidence.path) if evidence.path else None}}
        try:
            print("receipt:", write_receipt(args.receipts, doc, run_id))
        except OSError as err:
            print(safe(f"error: the receipt could not be written under the receipts directory: {type(err).__name__}"), file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
