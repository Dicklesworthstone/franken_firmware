#!/usr/bin/env python3
"""Independent Q00 registry floor, derived from the oracles themselves.

A run-suite manifest lists its own cases and its own ``required_cases``, so a case
dropped from BOTH passes every check that reads only the manifest.  This module
derives the floor from a different source: the planted-defect table that
``test_support/oracles.py`` owns (``DEFECTS`` and ``CANARY_CASES``).  Nothing here
reads a manifest, a receipt or a run directory.

    floor.py emit  --tier smoke|full --expected E.json --required R.json [--oracles PATH] [--unit-root DIR ...]
    floor.py print --tier smoke|full [--oracles PATH] [--unit-root DIR ...]

Three sources, none of them a manifest: the oracles' planted-defect table and the newc adapter's own defect table
(both every tier), and the ``test_*.py`` files on disk (the full tier, where each module must be a registered case).

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
from typing import Any, Dict, List, Sequence, Tuple

CANARY_PREFIX = "q00.oracle.canary."
POSITIVE_PREFIX = "q00.oracle.positive."
UNIT_PREFIX = "q00.unit."
PROOF_CLASS = "host-simulation"   # the oracles run against in-process models, not a guest or a device
TIERS = ("smoke", "full")
# Unit-test modules are registered only in the full tier: one of them (test_run_suite) itself runs the smoke
# acceptance, so a smoke registration would recurse.
UNIT_TIERS = ("full",)

HERE = os.path.dirname(os.path.realpath(__file__))
TEST_DIR = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(TEST_DIR))
DEFAULT_ORACLES = os.path.join(TEST_DIR, "test_support", "oracles.py")
DEFAULT_NEWC = os.path.join(TEST_DIR, "test_support", "newc_case.py")
NEWC_PREFIX = "q00.newc."
# root's independent archive/serial tests live beside the toolchain they test; the full-tier floor lists them too
DEFAULT_UNIT_ROOTS = (TEST_DIR, os.path.join(TEST_DIR, "test_support"), os.path.join(REPO, "toolchain", "tests"))


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


def discover_units(roots: Sequence[str]) -> List[str]:
    """Case ids for every ``test_*.py`` module on disk under ``roots`` (non-recursive, sorted).

    The files themselves are the source: a unit module cannot be dropped from the registry without
    either deleting the file (a visible change) or failing the floor.  Two roots may not offer the
    same module name."""
    ids: Dict[str, str] = {}
    for root in roots:
        if not os.path.isdir(root):
            raise FloorError("unit-test root not found: %s" % root)
        for name in sorted(os.listdir(root)):
            if name.startswith("test_") and name.endswith(".py") and os.path.isfile(os.path.join(root, name)):
                cid = UNIT_PREFIX + name[:-3]
                if cid in ids:
                    raise FloorError("test module %s appears under both %s and %s" % (name, ids[cid], root))
                ids[cid] = root
    return sorted(ids)


def newc_entries(newc: Any) -> Dict[str, Dict[str, Any]]:
    """The newc-alignment cases, derived from the adapter's own planted-defect table (code, not a manifest).

    Same shape as the oracles: ``DEFECTS`` names each planted defect with the oracle and violation kind it must
    produce, and ``CANARY_CASES`` lists the case ids (one canary per defect plus the paired positive)."""
    for attr in ("DEFECTS", "CANARY_CASES", "CANARY_PREFIX", "POSITIVE_ID"):
        if not hasattr(newc, attr):
            raise FloorError("newc module lacks %s" % attr)
    if not newc.DEFECTS:
        raise FloorError("newc DEFECTS is empty; an empty floor would pass anything")
    entries: Dict[str, Dict[str, Any]] = {}
    seen = set()
    for item in newc.CANARY_CASES:
        cid = item[0]
        if cid in entries:
            raise FloorError("duplicate case id %s in newc CANARY_CASES" % cid)
        if not cid.startswith(NEWC_PREFIX):
            raise FloorError("newc case id %r must start with %s" % (cid, NEWC_PREFIX))
        if cid == newc.POSITIVE_ID:
            entries[cid] = {"proof_class": PROOF_CLASS, "canary": False}
        elif cid.startswith(newc.CANARY_PREFIX):
            name = cid[len(newc.CANARY_PREFIX):]
            spec = newc.DEFECTS.get(name)
            if spec is None:
                raise FloorError("newc CANARY_CASES names %s but DEFECTS has no %r" % (cid, name))
            entries[cid] = {"proof_class": PROOF_CLASS, "canary": True, "oracle": spec.oracle,
                            "violation": spec.kind}
            seen.add(name)
        else:
            raise FloorError("unrecognised newc case id %r" % cid)
    if newc.POSITIVE_ID not in entries:
        raise FloorError("newc CANARY_CASES has no positive control (%s)" % newc.POSITIVE_ID)
    missing = sorted(set(newc.DEFECTS) - seen)
    if missing:
        raise FloorError("newc DEFECTS entries with no canary case: %s" % ", ".join(missing))
    return entries


def build(mod: Any, tier: str, unit_roots: Sequence[str], newc: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Return (expected, required) for ``tier``.

    Oracle cases come from ``mod.DEFECTS`` / ``mod.CANARY_CASES`` and the newc-alignment cases from the adapter's
    defect table; both apply to every tier.  Unit-test cases come from the ``test_*.py`` files found under
    ``unit_roots`` and apply only to the tiers in ``UNIT_TIERS``."""
    if tier not in TIERS:
        raise FloorError("tier must be one of %s" % ", ".join(TIERS))
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
    for cid, spec in newc_entries(newc).items():
        if cid in expected:
            raise FloorError("newc case id %s collides with another case" % cid)
        expected[cid] = dict(spec, mandatory=True)
        required[cid] = dict(spec)
    if tier in UNIT_TIERS:
        for cid in discover_units(unit_roots):
            if cid in expected:
                raise FloorError("unit case id %s collides with an oracle case" % cid)
            expected[cid] = {"mandatory": True, "proof_class": PROOF_CLASS, "canary": False}
            required[cid] = {"proof_class": PROOF_CLASS, "canary": False}
    return expected, required


def main(argv: Any = None) -> int:
    p = argparse.ArgumentParser(prog="floor.py", description="Derive the independent Q00 registry floor from oracles.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("emit", "print"):
        sp = sub.add_parser(name)
        sp.add_argument("--tier", required=True, choices=TIERS, help="explicit; the full tier adds the unit-test modules")
        sp.add_argument("--oracles", default=DEFAULT_ORACLES, help="path to oracles.py (default: test_support/oracles.py)")
        sp.add_argument("--newc", default=DEFAULT_NEWC, help="path to the newc adapter (default: test_support/newc_case.py)")
        sp.add_argument("--unit-root", action="append", default=None, metavar="DIR",
                        help="directory scanned for test_*.py (repeatable; default: scripts/test and scripts/test/test_support)")
        if name == "emit":
            sp.add_argument("--expected", required=True, help="output JSON for receipts.py --expected")
            sp.add_argument("--required", required=True, help="output JSON for run-suite --floor / receipts.py --require")
    args = p.parse_args(argv)
    try:
        expected, required = build(load_oracles(args.oracles), args.tier,
                                   args.unit_root if args.unit_root is not None else DEFAULT_UNIT_ROOTS,
                                   load_oracles(args.newc))
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
    units = sum(1 for cid in required if cid.startswith(UNIT_PREFIX))
    print("floor[%s]: %d cases (%d canaries, %d positives, %d unit modules)" % (
        args.tier, len(required), sum(1 for v in required.values() if v["canary"]),
        sum(1 for cid, v in required.items() if not v["canary"] and not cid.startswith(UNIT_PREFIX)), units))
    return 0


if __name__ == "__main__":
    sys.exit(main())
