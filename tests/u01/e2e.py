#!/usr/bin/env python3
"""U01 end-to-end runner (offline, stdlib only; it builds nothing).

    e2e.py                       host checks; the process-restart cases are BLOCKED (counted, never skipped)
    e2e.py --binary PATH         also run the process-restart cases against an example binary this host can run
    e2e.py --mutants             also run the mutation canary (about a minute)
    e2e.py --list                list the cases

The process-restart cases kill a REAL process mid-write and recover. They need the `journal_crash` example as a binary THIS
host can execute. A binary built by central RCH is a Linux executable on a worker and is not brought back to a macOS
orchestrator, so the central form of these cases is `tests/u01_process.rs` inside `cargo test -p franken-journal`, judged by test
name with `tests/u01/judge_log.py`; here they are BLOCKED unless --binary names a binary this host can run.
Exit codes: 0 every case passed and none is blocked; 1 a case failed; 3 only blocked cases stand in the way; 2 usage.

What a pass shows: after the process dies at any byte of a scripted run (abort inside the write or erase that crosses the
N-th byte, or SIGKILL at an arbitrary moment), reopening the file image yields exactly the state before or exactly the
state after the step that was running, as the Python reference computed it. A process kill keeps bytes already handed to
the OS, so this is the prefix-of-unsynced-writes experiment on a real file; the cut-point oracle covers the power cut.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from typing import Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import reference as ref  # noqa: E402
import scenarios as sc  # noqa: E402

VECTORS = os.path.join(REPO, "crates", "franken-journal", "tests", "vectors", "u01_vectors.json")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"


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


def crash(binary: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)


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

def host_unit_tests() -> Tuple[str, str]:
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_u01.py")
    result = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise AssertionError(f"{len(result.failures)} failures, {len(result.errors)} errors")
    return PASS, f"{result.testsRun} tests"


def host_vectors_current() -> Tuple[str, str]:
    out = subprocess.run([sys.executable, "-B", os.path.join(HERE, "make_vectors.py"), "--check"], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(out.stdout.strip())
    return PASS, out.stdout.strip()


def host_mutants() -> Tuple[str, str]:
    out = subprocess.run([sys.executable, "-B", os.path.join(HERE, "mutate.py")], capture_output=True, text=True, timeout=900)
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


def process_sigkill(sid: str, kill_at: List[int]) -> Callable[[Optional[str]], Tuple[str, str]]:
    def run(binary: Optional[str]) -> Tuple[str, str]:
        assert binary
        states = vector(sid)["states_hex"]
        for target in kill_at:
            with tempfile.TemporaryDirectory(prefix="u01-kill-") as tmp:
                image = os.path.join(tmp, "journal.img")
                if crash(binary, "init", image).returncode != 0:
                    raise AssertionError("init failed")
                proc = subprocess.Popen([binary, "run", image, VECTORS, sid], stdout=subprocess.PIPE, text=True)
                seen = 0
                assert proc.stdout is not None
                for line in proc.stdout:
                    if line.startswith("ack "):
                        seen += 1
                        if seen >= target:
                            proc.send_signal(signal.SIGKILL)
                            break
                rest = proc.stdout.read()
                proc.wait()
                total_acks = seen + acks(rest)
                finished = "done" in rest and proc.returncode == 0
                check_old_or_new(states, total_acks, finished, recovered(binary, image), f"SIGKILL after ack {target}")
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


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="U01 end-to-end runner", epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", help="the centrally built `journal_crash` example binary")
    ap.add_argument("--mutants", action="store_true", help="also run the mutation canary")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    cases = list(CASES)
    if args.mutants:
        cases.append(("U01-E-007", "breaking any one rule of the reference is noticed by the battery", False, lambda _b: host_mutants()))
    if args.list:
        for cid, title, needs_binary, _fn in cases:
            print(f"{cid}  {'process' if needs_binary else 'host   '}  {title}")
        return 0
    if args.binary and not os.access(args.binary, os.X_OK):
        print(f"error: {args.binary} is not an executable file", file=sys.stderr)
        return 2
    counts = {PASS: 0, FAIL: 0, BLOCKED: 0}
    for cid, title, needs_binary, fn in cases:
        if needs_binary and not args.binary:
            status, detail = BLOCKED, "needs a journal_crash binary this host can run (see --help; central form: tests/u01_process.rs + judge_log.py); never counted as passed"
        else:
            try:
                status, detail = fn(args.binary)
            except Exception as err:  # noqa: BLE001 - a crashing case is a failed case
                status, detail = FAIL, f"{type(err).__name__}: {err}"
        counts[status] += 1
        print(f"{status.upper():<8}{cid}  {title} -- {detail}")
    print(f"U01 cases: total={len(cases)} passed={counts[PASS]} failed={counts[FAIL]} blocked={counts[BLOCKED]}")
    if counts[FAIL]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
