#!/usr/bin/env python3
"""Independent Q01 registry floor, derived from the case table and the Rust sources (never from the run-suite manifest).

A run-suite manifest lists its own cases and its own ``required_cases``, so a case dropped from BOTH passes every check that reads only the
manifest. This module derives the floor from two other sources: ``tests/q01/cases.json`` (the case table the standalone judge also uses) and
the unit tests actually present in the Rust sources of ``franken-speaker``'s harness and control adapter. A test that no case covers, a case
that names a test that is gone, or a test in two cases is a floor violation, so the registry cannot shrink or drift unnoticed.

    q01_floor.py emit  --expected E.json --required R.json
    q01_floor.py print

``expected`` is the registry slice ``receipts.py verify --expected`` judges a stream against; ``required`` is the floor ``run-suite run --floor`` and
``receipts.py verify --require`` enforce. Stdlib only, offline, no network or device. This shows the registry cannot shrink; it says nothing about
whether the Rust oracles are right.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import q01_case  # noqa: E402  (the shared loader for tests/q01/run_cases.py)

PROOF_CLASS = "host-simulation"  # the campaign is a simulation; nothing here is a guest, a provider or a device


class FloorError(Exception):
    """The case table and the Rust sources do not describe a coherent floor."""


def build(rc: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    cases = rc.load_cases()
    if not cases:
        raise FloorError("the case table is empty; an empty floor would pass anything")
    ids = [c["id"] for c in cases]
    if len(set(ids)) != len(ids):
        raise FloorError("duplicate case ids in the case table")
    mapped = [t for c in cases for t in c["tests"]]
    if len(mapped) != len(set(mapped)):
        raise FloorError("a test is in two cases")
    names = rc.rust_test_names()
    if not names:
        raise FloorError("no unit tests found in the Rust sources")
    ghosts = sorted(set(mapped) - set(names))
    if ghosts:
        raise FloorError("cases name tests that are not in the sources: %s" % ghosts[:3])
    uncovered = sorted(set(names) - set(mapped))
    if uncovered:
        raise FloorError("unit tests that no case covers: %s" % uncovered[:3])
    expected = {cid: {"mandatory": True, "proof_class": PROOF_CLASS, "canary": False} for cid in ids}
    required = {cid: {"proof_class": PROOF_CLASS, "canary": False} for cid in ids}
    return expected, required


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="q01_floor.py", description="Derive the independent Q01 registry floor from the case table and the Rust sources")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("print")
    emit = sub.add_parser("emit")
    emit.add_argument("--expected", required=True, help="output JSON for receipts.py --expected")
    emit.add_argument("--required", required=True, help="output JSON for run-suite --floor / receipts.py --require")
    args = p.parse_args(argv)
    try:
        expected, required = build(q01_case.load_judge())
    except (FloorError, ImportError, OSError, ValueError, KeyError) as error:
        sys.stderr.write("q01_floor.py: %s\n" % error)
        return 2
    if args.cmd == "print":
        print(json.dumps({"expected": expected, "required": required}, indent=1, sort_keys=True))
        return 0
    for path, doc in ((args.expected, expected), (args.required, required)):
        try:
            with open(path, "x", encoding="utf-8") as fh:  # never clobber an existing file
                fh.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        except OSError as error:
            sys.stderr.write("q01_floor.py: cannot write %s: %s\n" % (path, error))
            return 2
    print("floor[full]: %d Q01 cases (host-simulation, none a canary: the planted-fault cases are Rust tests that pass by naming their fault)" % len(required))
    return 0


if __name__ == "__main__":
    sys.exit(main())
