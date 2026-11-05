#!/usr/bin/env python3
"""Reconcile the GENERATED planning files to the LIVE Beads (P01 acceptance, fresh-eyes refinement 2026-11-04).

The generated side (docs/planning: task-catalog.json, bead-map.json, beads-snapshot.json) can stay internally consistent while
the tracker moves on: later tasks (Q00, UX01, Q07, E07, N07) never reach the catalog, acceptance_criteria never reach the
snapshot, and edges are added with br only. Generated validation is therefore not whole-project proof until the two sides are
compared field by field. This module compares them and reports every difference as a stable code and a subject. It writes
nothing, never invokes br, and never edits a generated or a live field.

    planning_reconcile.py --live PATH [--planning DIR] [--json]

PATH is the live data: the local export `.beads/issues.jsonl` (one issue per line, with typed dependency edges), or a JSON
document with an `issues` list and optional pagination keys (`total`, `limit`, `offset`, `has_more`) such as `br list --json`
output merged with each issue's dependencies. Exit 0: no difference; 1: differences; 2: usage or unreadable input.

What is compared, and the code of each difference:
  live_export_incomplete          the live document says it is paginated or partial (has_more, offset, total, no issues)
  live_export_stale               a live issue is OLDER than the generated copy of the same issue
  task_absent_from_catalog        a live issue the catalog and alias map do not have (a required task nobody generated)
  catalog_task_not_live           an alias-mapped issue the live data does not have
  alias_unmapped_key              a catalog key with no alias-map entry
  alias_stale_key                 an alias-map key the catalog does not have
  alias_not_unique                two keys mapped to one issue
  title_differs                   live title is not `KEY: catalog title`
  description_differs             live description is not the generated snapshot's
  snapshot_missing_issue          the generated snapshot lacks an alias-mapped issue (its fields cannot be compared)
  acceptance_criteria_differs     live acceptance_criteria differ from the generated snapshot's
  acceptance_criteria_absent_from_generated   live has acceptance_criteria, the generated snapshot has no such field
  design_package_alias_differs    live `Mapped design packages:` line differs from the catalog's design_packages (no line = no packages)
  blocking_edge_missing_in_live   the catalog depends on a task through an edge live does not have (a gate edge removed)
  edge_type_differs               the live edge between the same two tasks has another type than `blocks`
  live_edge_not_in_generated      a live edge (any type) the catalog does not have

Not compared, by design: status, priority, labels, comments and timestamps other than the staleness test, because they move
with ordinary tracker work. A required-feature registry is NOT compared: no generated planning file and no live field carries
one (the only machine-readable registry is the `features` list of the P01 workspace contract, which has no mapping to tasks).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PLANNING_DIR = os.path.join(REPO, "docs", "planning")
STANDALONE = "canonical standalone task"
Finding = Tuple[str, str]


class InputError(Exception):
    pass


# ------------------------------------------------------------------------------------------------------- input

def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as err:
        raise InputError(f"cannot read {path}: {err.strerror or err}") from err


def parse_live(text: str) -> Dict[str, Any]:
    """The live document as {"issues": [...], "envelope": {...} | None}. JSON (an object with `issues`, or a list) or JSONL."""
    stripped = text.strip()
    if not stripped:
        return {"issues": [], "envelope": None}
    try:
        doc = json.loads(stripped)
    except ValueError:
        doc = None
    if isinstance(doc, dict) and isinstance(doc.get("issues"), list):
        return {"issues": doc["issues"], "envelope": {k: doc[k] for k in ("total", "limit", "offset", "has_more") if k in doc}}
    if isinstance(doc, list):
        return {"issues": doc, "envelope": None}
    issues = []
    for number, line in enumerate(stripped.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            issues.append(json.loads(line))
        except ValueError as err:
            raise InputError(f"live data line {number} is not JSON: {err}") from err
    return {"issues": issues, "envelope": None}


def load_live(path: str) -> Dict[str, Any]:
    return parse_live(_read_text(path))


def load_generated(directory: str = PLANNING_DIR) -> Dict[str, Any]:
    def read(name: str) -> Any:
        try:
            return json.loads(_read_text(os.path.join(directory, name)))
        except ValueError as err:
            raise InputError(f"{name} is not JSON: {err}") from err

    snapshot = read("beads-snapshot.json")
    rows = snapshot["issues"] if isinstance(snapshot, dict) else snapshot
    return {"catalog": read("task-catalog.json"), "map": read("bead-map.json"), "snapshot": rows}


# ---------------------------------------------------------------------------------------------------- reconcile

def _design_packages(description: str) -> Optional[List[str]]:
    match = re.search(r"^Mapped design packages: (.*?)\.?\s*$", description or "", re.M)
    if not match:
        return None
    text = match.group(1).strip()
    return [] if text == STANDALONE else sorted(part.strip() for part in text.split(",") if part.strip())


def reconcile(live: Dict[str, Any], generated: Dict[str, Any]) -> List[Finding]:
    """Every difference between the live data and the generated planning files, sorted, as (code, subject) pairs."""
    found: set = set()

    def add(code: str, subject: str) -> None:
        found.add((code, subject))

    issues = live.get("issues") or []
    envelope = live.get("envelope") or {}
    if (not issues or envelope.get("has_more") or envelope.get("offset", 0) not in (0, None)
            or ("total" in envelope and envelope["total"] != len(issues))):
        add("live_export_incomplete", f"{len(issues)} issues" + (f" of {envelope['total']}" if "total" in envelope else ""))
    live_by_id = {issue["id"]: issue for issue in issues}

    catalog = {task["key"]: task for task in generated["catalog"]}
    alias = generated["map"]
    snapshot = {row["id"]: row for row in generated["snapshot"]}
    by_id: Dict[str, List[str]] = {}
    for key, issue_id in alias.items():
        by_id.setdefault(issue_id, []).append(key)
    key_of = {issue_id: keys[0] for issue_id, keys in by_id.items()}

    def label(issue_id: str) -> str:
        return key_of.get(issue_id, issue_id)

    for key in catalog:
        if key not in alias:
            add("alias_unmapped_key", key)
    for key in alias:
        if key not in catalog:
            add("alias_stale_key", key)
    for issue_id, keys in by_id.items():
        if len(keys) > 1:
            add("alias_not_unique", issue_id + "=" + ",".join(sorted(keys)))

    for issue_id in live_by_id:
        if issue_id not in by_id:
            add("task_absent_from_catalog", issue_id)
    for issue_id in by_id:
        if issue_id not in live_by_id:
            add("catalog_task_not_live", label(issue_id))

    for key, issue_id in alias.items():
        issue, task, row = live_by_id.get(issue_id), catalog.get(key), snapshot.get(issue_id)
        if issue is None or task is None:
            continue
        if issue.get("title") != f"{key}: {task['title']}":
            add("title_differs", key)
        packages = _design_packages(issue.get("description", ""))
        # a live body with no `Mapped design packages:` line (a free-form bead) maps to no package: the catalog may claim none, no more
        if (packages if packages is not None else []) != sorted(task.get("design_packages", [])):
            add("design_package_alias_differs", key)
        if row is None:
            add("snapshot_missing_issue", key)
            continue
        if issue.get("description") != row.get("description"):
            add("description_differs", key)
        live_acceptance = issue.get("acceptance_criteria") or ""
        if "acceptance_criteria" not in row:
            if live_acceptance:
                add("acceptance_criteria_absent_from_generated", key)
        elif live_acceptance != (row.get("acceptance_criteria") or ""):
            add("acceptance_criteria_differs", key)
        stamp, generated_stamp = issue.get("updated_at"), row.get("updated_at")
        if stamp and generated_stamp and stamp < generated_stamp:
            add("live_export_stale", f"{key} {stamp} < {generated_stamp}")

    wanted: set = set()
    for key, task in catalog.items():
        for dep in task.get("deps", []):
            if key in alias and dep in alias:
                wanted.add((alias[key], alias[dep]))
    live_edges: Dict[Tuple[str, str], set] = {}
    for issue in issues:
        for edge in issue.get("dependencies") or []:
            live_edges.setdefault((issue["id"], edge["depends_on_id"]), set()).add(edge.get("type", "blocks"))
    for pair in sorted(wanted):
        types = live_edges.get(pair, set())
        if "blocks" in types:
            continue
        subject = f"{label(pair[0])}->{label(pair[1])}"
        add("edge_type_differs" if types else "blocking_edge_missing_in_live", subject)
    for pair, types in live_edges.items():
        if pair not in wanted:
            for kind in sorted(types):
                add("live_edge_not_in_generated", f"{label(pair[0])}->{label(pair[1])}:{kind}")
    return sorted(found)


def codes(findings: Iterable[Finding]) -> List[str]:
    return sorted({code for code, _ in findings})


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for code, _ in findings:
        counts[code] = counts.get(code, 0) + 1
    return dict(sorted(counts.items()))


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Reconcile generated planning files to live Beads (read-only)",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--live", required=True, metavar="PATH", help="the local export .beads/issues.jsonl, or a JSON document with issues")
    ap.add_argument("--planning", default=PLANNING_DIR, metavar="DIR", help="the generated planning directory (default docs/planning)")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    args = ap.parse_args(argv)
    try:
        live, generated = load_live(args.live), load_generated(args.planning)
        findings = reconcile(live, generated)
    except (InputError, KeyError, TypeError) as err:
        print(f"error: {type(err).__name__}: {err}", file=sys.stderr)
        return 2
    result = {"status": "pass" if not findings else "fail", "live_issues": len(live["issues"]),
              "generated_tasks": len(generated["catalog"]), "counts": summarize(findings),
              "findings": [{"code": c, "subject": s} for c, s in findings]}
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print(f"planning reconcile: {result['status']} ({result['live_issues']} live issues, {result['generated_tasks']} catalog tasks)")
        for code, count in result["counts"].items():
            print(f"  {code}: {count}")
        for code, subject in findings:
            print(f"    {code}  {subject}")
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
