#!/usr/bin/env python3
"""Independent Q00 registry floor, derived from the oracles themselves.

A run-suite manifest lists its own cases and its own ``required_cases``, so a case
dropped from BOTH passes every check that reads only the manifest.  This module
derives the floor from a different source: the planted-defect table that
``test_support/oracles.py`` owns (``DEFECTS`` and ``CANARY_CASES``).  Nothing here
reads a manifest, a receipt or a run directory.

    floor.py emit  --expected E.json --required R.json [--oracles PATH]
    floor.py print [--oracles PATH]

``expected`` is the registry slice ``receipts.py`` judges a stream against;
``required`` is the floor ``receipts.aggregate(..., required=)`` enforces.  Both are
derived: a canary must name the oracle and the violation kind its defect produces; a
positive control is a mandatory non-canary.  ``run-suite run --floor R.json`` feeds the
floor to the aggregator, and ``scripts/e2e/q00`` re-verifies the finished stream with
``receipts.py verify --expected E.json --require R.json``.

Stdlib only, offline, no network or device.  This proves the registry cannot shrink
unnoticed; it says nothing about whether the oracles are right.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from typing import Any, Dict, Tuple

CANARY_PREFIX = "q00.oracle.canary."
POSITIVE_PREFIX = "q00.oracle.positive."
PROOF_CLASS = "host-simulation"   # the oracles run against in-process models, not a guest or a device

HERE = os.path.dirname(os.path.realpath(__file__))
DEFAULT_ORACLES = os.path.join(os.path.dirname(HERE), "test_support", "oracles.py")


class FloorError(Exception):
    """The oracles module does not describe a coherent floor."""


def load_oracles(path: str) -> Any:
    """Import oracles.py by explicit path (no sys.path edits, no bytecode written next to it)."""
    if not os.path.isfile(path):
        raise FloorError("oracles module not found: %s" % path)
    sys.dont_write_bytecode = True
    name = "ffw_floor_oracles_%d" % abs(hash(os.path.realpath(path)))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FloorError("cannot load %s" % path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # a broken oracle module must be loud, never an empty floor
        raise FloorError("%s failed to import: %r" % (path, exc))
    return mod


def build(mod: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Return (expected, required) derived from ``mod.DEFECTS`` and ``mod.CANARY_CASES``."""
    for attr in ("DEFECTS", "CANARY_CASES"):
        if not hasattr(mod, attr):
            raise FloorError("oracles module lacks %s" % attr)
    defects = mod.DEFECTS
    if not defects:
        raise FloorError("DEFECTS is empty; an empty floor would pass anything")
    expected: Dict[str, Dict[str, Any]] = {}
    required: Dict[str, Dict[str, Any]] = {}
    seen_defects = set()
    for item in mod.CANARY_CASES:
        cid = item[0]
        if cid in expected:
            raise FloorError("duplicate case id %s in CANARY_CASES" % cid)
        if cid.startswith(CANARY_PREFIX):
            name = cid[len(CANARY_PREFIX):]
            spec = defects.get(name)
            if spec is None:
                raise FloorError("CANARY_CASES names %s but DEFECTS has no %r" % (cid, name))
            expected[cid] = {"mandatory": True, "proof_class": PROOF_CLASS, "canary": True,
                             "oracle": spec.oracle, "violation": spec.kind}
            required[cid] = {"proof_class": PROOF_CLASS, "canary": True, "oracle": spec.oracle,
                             "violation": spec.kind}
            seen_defects.add(name)
        elif cid.startswith(POSITIVE_PREFIX):
            expected[cid] = {"mandatory": True, "proof_class": PROOF_CLASS, "canary": False}
            required[cid] = {"proof_class": PROOF_CLASS, "canary": False}
        else:
            raise FloorError("unrecognised CANARY_CASES id %r (want %s* or %s*)" % (cid, CANARY_PREFIX, POSITIVE_PREFIX))
    missing = sorted(set(defects) - seen_defects)
    if missing:
        # DEFECTS is the source of truth: a defect with no canary case is itself a floor violation.
        raise FloorError("DEFECTS entries with no canary case in CANARY_CASES: %s" % ", ".join(missing))
    return expected, required


def main(argv: Any = None) -> int:
    p = argparse.ArgumentParser(prog="floor.py", description="Derive the independent Q00 registry floor from oracles.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("emit", "print"):
        sp = sub.add_parser(name)
        sp.add_argument("--oracles", default=DEFAULT_ORACLES, help="path to oracles.py (default: test_support/oracles.py)")
        if name == "emit":
            sp.add_argument("--expected", required=True, help="output JSON for receipts.py --expected")
            sp.add_argument("--required", required=True, help="output JSON for run-suite --floor / receipts.py --require")
    args = p.parse_args(argv)
    try:
        expected, required = build(load_oracles(args.oracles))
    except FloorError as exc:
        sys.stderr.write("floor.py: %s\n" % exc)
        return 2
    if args.cmd == "print":
        print(json.dumps({"expected": expected, "required": required}, indent=1, sort_keys=True))
        return 0
    for path, doc in ((args.expected, expected), (args.required, required)):
        try:
            with open(path, "x", encoding="utf-8") as fh:   # never clobber an existing file
                fh.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        except OSError as exc:
            sys.stderr.write("floor.py: cannot write %s: %s\n" % (path, exc))
            return 2
    print("floor: %d cases (%d canaries, %d positives)" % (
        len(required), sum(1 for v in required.values() if v["canary"]), sum(1 for v in required.values() if not v["canary"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
