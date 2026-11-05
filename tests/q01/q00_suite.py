#!/usr/bin/env python3
"""Q01 through the shared Q00 runner and receipt path (bead ffw-gmq): independent floor -> run-suite -> independent re-verification.

    scripts/e2e/q01 --suite [--log LOG [LOG ...]] [--artifact-root DIR] [--run-id ID] [--seed N]

Each Q01 case is a run-suite case (scripts/test/q01.suite.json) judged by scripts/test/q00/q01_case.py from the log of the centrally run
speaker lib tests (``-- --nocapture``), the same judge the standalone replay (`scripts/e2e/q01 --judge LOG`) uses. Without ``--log`` every case is
reported blocked (the manifest requires FFW_Q01_LOG) and the run is not a pass: a missing run is never translated into one.

The steps mirror scripts/e2e/q00: the floor is derived from tests/q01/cases.json and the Rust sources, run-suite runs the manifest against that floor
and writes receipts.jsonl, and scripts/test/test_support/receipts.py re-verifies the finished stream in a separate process.

Exit codes are run-suite's (0 every case passed, evidence complete; 1 a case failed, was blocked or not run; 3 evidence incomplete; 4 cancelled; ...),
or receipts.py's when the run-suite exit was 0 and the re-verification disagreed.
"""
from __future__ import annotations

import argparse
import datetime
import os
import secrets
import subprocess
import sys
from typing import List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TEST = os.path.join(REPO, "scripts", "test")
RUNNER = os.path.join(TEST, "run-suite")
FLOOR = os.path.join(TEST, "q00", "q01_floor.py")
RECEIPTS = os.path.join(TEST, "test_support", "receipts.py")
MANIFEST = os.path.join(TEST, "q01.suite.json")
LOG_ENV = "FFW_Q01_LOG"


def step(label: str, argv: List[str], env: Optional[dict] = None) -> int:
    print("== %s" % label, flush=True)
    rc = subprocess.run([sys.executable, "-B"] + argv, stdin=subprocess.DEVNULL, env=env).returncode
    print("== %s -> exit %d" % (label, rc), flush=True)
    return rc


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Q01 acceptance through the Q00 runner: independent floor -> run-suite -> independent re-verification")
    ap.add_argument("--log", nargs="+", default=[], metavar="LOG", help="the centrally run `cargo test ... -- --nocapture` log(s); without one every case is blocked")
    ap.add_argument("--artifact-root", default=os.environ.get("FFW_ARTIFACT_ROOT") or os.path.join(REPO, "build", "test-runs"))
    ap.add_argument("--run-id", default="q01-%s-%s" % (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(3)))
    ap.add_argument("--seed", default="0")
    args = ap.parse_args(argv)

    env = dict(os.environ)
    env.pop(LOG_ENV, None)  # only what was given on the command line counts
    if args.log:
        missing = [p for p in args.log if not os.path.isfile(p)]
        if missing:
            print("q01 suite: no such log: %s" % ", ".join(os.path.basename(p) for p in missing), file=sys.stderr)
            return 2
        env[LOG_ENV] = os.pathsep.join(os.path.abspath(p) for p in args.log)

    root = os.path.abspath(args.artifact_root)
    floor_dir = os.path.join(root, args.run_id + ".floor")
    try:
        os.makedirs(root, exist_ok=True)
        os.mkdir(floor_dir, 0o700)  # exclusive: a rerun never overwrites an earlier floor
    except OSError as error:
        print("q01 suite: cannot create %s: %s" % (floor_dir, error), file=sys.stderr)
        return 2
    expected, required = os.path.join(floor_dir, "expected.json"), os.path.join(floor_dir, "required.json")

    if step("1/3 derive the independent floor (tests/q01/cases.json and the Rust sources)", [FLOOR, "emit", "--expected", expected, "--required", required]) != 0:
        print("Q01 SUITE: FAIL (no floor)")
        return 1
    rc_run = step("2/3 run-suite full tier with --floor", [RUNNER, "run", "--tier", "full", "--manifest", MANIFEST, "--floor", required,
                                                           "--artifact-root", root, "--run-id", args.run_id, "--seed", args.seed], env=env)
    stream = os.path.join(root, args.run_id, "receipts.jsonl")
    if not os.path.exists(stream):
        print("Q01 SUITE: FAIL (run-suite produced no receipt stream; exit %d)" % rc_run)
        return rc_run or 1
    rc_verify = step("3/3 independent re-verification with receipts.py", [RECEIPTS, "verify", stream, "--expected", expected, "--require", required])
    ok = rc_run == 0 and rc_verify == 0
    print("Q01 SUITE: %s  (run-suite exit %d, receipts verify exit %d)  artifacts: %s" % ("PASS" if ok else "FAIL", rc_run, rc_verify, os.path.join(root, args.run_id)))
    return 0 if ok else (rc_run or rc_verify or 1)


if __name__ == "__main__":
    sys.exit(main())
