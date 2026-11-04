#!/usr/bin/env python3
"""Run one stdlib unittest module as a run-suite case (result contract ffw.case-result.v1, v1.1).

    unittest_case.py MODULE.py [--allow-skip REGEX ...]

This only lets the registry *name* the existing test modules as cases (so `run-suite coverage`
can see what covers each requirement); it adds no test logic of its own.  A module is judged by
what unittest observed, never by absence of error text:

  pass        >= 1 test actually executed, no failure, no error, no unexpected success, and no skip
              that the manifest did not explicitly allow
  fail        any failure / error / unexpected success (typed: test_failure, test_error,
              unexpected_success), or the module could not be imported (import_error)
  incomplete  no test executed, or a skip nobody allowed (for example a platform limitation not
              declared in the manifest).  Never a pass, never a manufactured failure.

``--allow-skip REGEX`` documents a known platform limitation (for example the Linux-only
`/dev/full` test on macOS).  Allowed skips are still counted and printed in the case log; they are
not silent.  Exit codes: 0 pass, 1 fail, 2 incomplete or usage error.

When FFW_RESULT_PATH is set the result is written atomically with the run id, case id and nonce
the runner supplied; without it the module is simply run and the exit code reports the verdict.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import traceback
import unittest
from typing import Any, Dict, List, Optional

RESULT_SCHEMA = "ffw.case-result.v1"
MAX_RESULT_BYTES = 256 * 1024


def _write_result(path: str, doc: Dict[str, Any]) -> None:
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n"
    if len(data.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds the 256 KiB limit")
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "x", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)   # our own scratch file only
        except OSError:
            pass
        raise


def _first_line(text: str) -> str:
    for line in reversed(text.strip().splitlines()):
        if line.strip():
            return line.strip()[:300]
    return ""


def judge(stem: str, module_error: Optional[str], result: Optional[unittest.TestResult],
          allow: List["re.Pattern[str]"]) -> Dict[str, Any]:
    """Map what unittest observed onto the verdict fields of the result file (pure; unit-tested)."""
    oracle = ("unittest." + stem)[:128]
    base: Dict[str, Any] = {"oracle": oracle, "oracle_kind": "property", "independent": True}
    if module_error is not None:
        return dict(base, verdict="fail", finalized=True, incomplete_reasons=[], checks=0, mismatches=1,
                    violation_kinds={"import_error": 1}, expected={"module": "imports"},
                    observed={"import_error": module_error}, first_causal_event=module_error,
                    counters={"tests_run": 0})
    assert result is not None
    ran = result.testsRun
    skipped = list(result.skipped)
    unexpected = [(str(t), r) for t, r in skipped if not any(p.search(r) for p in allow)]
    executed = max(ran - len(skipped), 0)
    failures, errors = len(result.failures), len(result.errors)
    unexpected_success = len(result.unexpectedSuccesses)
    counters = {"tests_run": ran, "executed": executed, "failures": failures, "errors": errors,
                "skipped_allowed": len(skipped) - len(unexpected), "skipped_unexpected": len(unexpected),
                "expected_failures": len(result.expectedFailures), "unexpected_successes": unexpected_success}
    bad = failures + errors + unexpected_success
    if bad:
        kinds = {k: v for k, v in (("test_failure", failures), ("test_error", errors),
                                   ("unexpected_success", unexpected_success)) if v}
        first = (result.failures + result.errors)[0] if (result.failures or result.errors) else None
        cause = ("%s: %s" % (first[0].id(), _first_line(first[1]))) if first else "unexpected success"
        return dict(base, verdict="fail", finalized=True, incomplete_reasons=[], checks=executed, mismatches=bad,
                    violation_kinds=kinds, expected={"failures": 0, "errors": 0, "unexpected_successes": 0},
                    observed={"failures": failures, "errors": errors, "unexpected_successes": unexpected_success},
                    first_causal_event=cause, counters=counters)
    reasons: List[str] = []
    if executed == 0:
        reasons.append("no_tests_executed")
    if unexpected:
        reasons.append("unexpected_skip:%d" % len(unexpected))
    if reasons:
        return dict(base, verdict="incomplete", finalized=False, incomplete_reasons=reasons, checks=executed,
                    mismatches=0, violation_kinds={}, expected=None, observed=None,
                    first_causal_event=", ".join(reasons), counters=counters)
    return dict(base, verdict="pass", finalized=True, incomplete_reasons=[], checks=executed, mismatches=0,
                violation_kinds={}, expected={"failures": 0, "errors": 0}, observed={"executed": executed},
                first_causal_event="none: no failure", counters=counters)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run one unittest module as a run-suite case")
    ap.add_argument("module", help="path to a unittest module file")
    ap.add_argument("--allow-skip", action="append", default=[], metavar="REGEX",
                    help="a skip whose reason matches is a documented platform limitation (counted, printed, not silent)")
    args = ap.parse_args(argv)
    path = os.path.abspath(args.module)
    if not os.path.isfile(path):
        print("unittest_case: no such module: %s" % args.module, file=sys.stderr)
        return 2
    try:
        allow = [re.compile(p) for p in args.allow_skip]
    except re.error as exc:
        print("unittest_case: bad --allow-skip regex: %s" % exc, file=sys.stderr)
        return 2

    target = None
    if os.environ.get("FFW_RESULT_PATH"):
        ids = {k: os.environ.get(k) for k in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE")}
        missing = [k for k, v in ids.items() if not v]
        if missing:
            print("unittest_case: %s required when FFW_RESULT_PATH is set" % ", ".join(missing), file=sys.stderr)
            return 2
        target = (os.environ["FFW_RESULT_PATH"], ids)

    # The runner's protocol variables belong to this adapter, not to the module under test.  A unit module is
    # a test subject, so it must not inherit a result path, nonce or seed that would change what its own
    # command-line tests do (for example `oracles.py replay` refuses to run when a result file is requested).
    for name in [k for k in os.environ if k.startswith("FFW_")]:
        del os.environ[name]

    stem = os.path.splitext(os.path.basename(path))[0]
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.dirname(path))   # as if the module had been run as a script
    module_error: Optional[str] = None
    result: Optional[unittest.TestResult] = None
    try:
        spec = importlib.util.spec_from_file_location(stem, path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot load %s" % path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[stem] = mod
        spec.loader.exec_module(mod)
        suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(suite)
    except Exception as exc:   # an import failure is a typed failure, never a crash that reads as "no result"
        module_error = "%s: %s" % (type(exc).__name__, _first_line(str(exc)) or traceback.format_exc()[-200:])

    verdict = judge(stem, module_error, result, allow)
    c = verdict["counters"]
    print("UNITTEST %s: verdict=%s executed=%s failures=%s errors=%s skipped_allowed=%s skipped_unexpected=%s" % (
        stem, verdict["verdict"], c.get("executed", 0), c.get("failures", 0), c.get("errors", 0),
        c.get("skipped_allowed", 0), c.get("skipped_unexpected", 0)), flush=True)
    if result is not None:
        for test, reason in result.skipped:   # a skip is never silent
            print("SKIPPED %s: %s" % (test, reason), flush=True)
    if target is not None:
        path_out, ids = target
        doc = dict(verdict, schema=RESULT_SCHEMA, run_id=ids["FFW_RUN_ID"], case_id=ids["FFW_CASE_ID"],
                   nonce=ids["FFW_RESULT_NONCE"])
        _write_result(path_out, doc)
    return {"pass": 0, "fail": 1}.get(verdict["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
