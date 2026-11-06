#!/usr/bin/env python3
"""Regenerate the planning files from the LIVE Beads export. Data flows one way: `.beads/issues.jsonl` -> the files below.

    python3 docs/planning/generate_from_beads.py [--live .beads/issues.jsonl] [--root DIR]

Reads only the live export (one issue per line, typed dependency edges). Never runs `br`, never writes under `.beads/`, and never
reads an earlier generated file, so a stale generated value cannot reach the output: a live field always wins. Writes, under
`DIR/docs/planning/` (DIR defaults to the repository):

  task-catalog.json     one row per live issue: key, title, deps (live blocking edges), and for a templated body its scope, acceptance,
                        design packages, inputs, owned outputs, evidence and detailed contract, parsed from the body
  bead-map.json         key -> issue id
  bead-manifest.json    key, title, deps, body path, priority (live)
  beads-snapshot.json   the live fields `check_planning.py` and `tests/p01/planning_reconcile.py` read, including acceptance_criteria
                        (no account handle: `created_by` is not copied)
  bead-bodies/KEY.md    the live description, byte for byte

The key is the part of the live title before the first `: `. A body that follows the generated template (`# KEY: title`, Goal, Scope,
Why, Inputs, Owned outputs, Acceptance, Evidence, Authority, Failure/closure, Mapped design packages, Detailed implementation and
validation contract) is parsed into `"form": "template"`; a body with no `# KEY: ` heading and none of the lines only the template has
(`Goal:`, `Scope:`, `Why:`, `Owned outputs:`, `Mapped design packages:`, the contract marker) is `"form": "freeform"` and carries no
parsed fields. A body that starts like the template but does not parse, or that has the template's own lines without the heading, is
refused, naming the issue: nothing is guessed and nothing quietly becomes freeform. Not written: comments, notes, the assignee, `created_by` (an account handle), `source_repo_path` (an absolute local path), close
reasons. Not compared by the reconcile either: status, priority, labels, comments and timestamps (see planning_reconcile.py), so a
later comment or status change on a bead cannot fail it; a changed title, description, acceptance_criteria, a new bead or a changed
edge can, until this is run again. Edges of a type other than `blocks` are listed on stderr and are not in the catalog.

This supersedes `render_planning.py` for these files: that script rebuilds them from docs/SLIM_SPEAKER_PLAN.md, the opposite
direction, and would overwrite what is live. Nothing is deleted: a body file whose issue is gone stays on disk and the reconcile says so.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
DEFAULT_ROOT = os.path.dirname(os.path.dirname(HERE))
STANDALONE = "canonical standalone task"
DEFAULT_INPUT = "Owner scope, sanitized inventory and existing evidence registry."
CONTRACT_MARKER = "Detailed implementation and validation contract:"
TEMPLATE_LABELS = ("Goal: ", "Scope: ", "Why: ", "Inputs:", "Owned outputs: ", "Acceptance: ", "Evidence: ", "Authority: ",
                   "Failure/closure: ", "Mapped design packages: ", CONTRACT_MARKER)
_TITLE = re.compile(r"^([A-Z]+[0-9]+): (.+)$", re.S)
_TEMPLATE = re.compile(
    r"\A# (?P<key>[A-Z]+[0-9]+): (?P<title>[^\n]+)\n\n"
    r"Goal: (?P<goal>.+?)\n\n"
    r"Scope: (?P<scope>.+?)\n\n"
    r"Why: (?P<why>.+?)\n\n"
    r"Inputs:\n(?P<inputs>.+?)\n\n"
    r"Owned outputs: (?P<output_path>.+?)\n\n"
    r"Acceptance: (?P<acceptance>.+?)\n\n"
    r"Evidence: (?P<evidence_status>.+?)\n\n"
    r"Authority: (?P<authority>.+?)\n\n"
    r"Failure/closure: (?P<failure>.+?)\n\n"
    r"Mapped design packages: (?P<packages>[^\n]+?)\.\n\n"
    + re.escape(CONTRACT_MARKER) + r"\n\n(?P<detailed_contract>.*)\Z", re.S)
OUTPUTS = ("task-catalog.json", "bead-map.json", "bead-manifest.json", "beads-snapshot.json")
SNAPSHOT_FIELDS = ("id", "title", "description", "acceptance_criteria", "status", "priority", "issue_type", "created_at",
                   "updated_at", "external_ref", "source_repo", "compaction_level", "original_size", "labels")


class GenerateError(Exception):
    pass


def _key_order(key: str) -> Tuple[str, int]:
    letters = re.match(r"[A-Z]+", key).group(0)
    return letters, int(key[len(letters):])


def parse_live(text: str) -> List[Dict[str, Any]]:
    issues = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            issue = json.loads(line)
        except ValueError as err:
            raise GenerateError(f"live export line {number} is not JSON: {err}") from err
        if not isinstance(issue, dict) or not isinstance(issue.get("id"), str):
            raise GenerateError(f"live export line {number} is not an issue with an id")
        issues.append(issue)
    if not issues:
        raise GenerateError("the live export holds no issues; refusing to write empty planning files")
    ids = [i["id"] for i in issues]
    if len(ids) != len(set(ids)):
        raise GenerateError("the live export has a duplicate issue id")
    return issues


def parse_body(issue_id: str, key: str, title: str, body: str) -> Dict[str, Any]:
    """The catalog fields a templated body carries, or {"form": "freeform"} for one with none of the template's labelled lines."""
    present = [label for label in TEMPLATE_LABELS if re.search(r"^" + re.escape(label), body, re.M)]
    if not body.startswith(f"# {key}: "):
        # A free-form body may use `Acceptance:`, `Inputs:` or `Evidence:` as ordinary headings; it may not carry the labelled lines that
        # only the template has, or it is a damaged template and is refused rather than waved through as free-form.
        template_only = [label.strip() for label in present if label not in ("Acceptance: ", "Inputs:", "Evidence: ")]
        if template_only:
            raise GenerateError(f"{issue_id} ({key}): the body has no `# {key}: ` heading but carries the template's own lines "
                                f"({', '.join(template_only)}); fix the bead or this parser, nothing is guessed")
        return {"form": "freeform"}
    match = _TEMPLATE.match(body)
    if not match or match.group("key") != key or match.group("title") != title:
        missing = [label.strip() for label in TEMPLATE_LABELS if label not in present]
        raise GenerateError(f"{issue_id} ({key}): the body follows the template only in part (has {len(present)} of {len(TEMPLATE_LABELS)} "
                            f"labelled lines; absent: {', '.join(missing) or 'none, but they are not in the template order'}); "
                            "fix the bead or this parser, nothing is guessed")
    inputs = [line[2:] for line in match.group("inputs").split("\n")]
    if any(not line.startswith("- ") for line in match.group("inputs").split("\n")):
        raise GenerateError(f"{issue_id} ({key}): the Inputs section is not a bullet list")
    packages = match.group("packages").strip()
    return {"form": "template", "scope": match.group("scope"), "acceptance": match.group("acceptance"),
            "design_packages": [] if packages == STANDALONE else [p.strip() for p in packages.split(",") if p.strip()],
            "detailed_contract": match.group("detailed_contract"),
            "inputs": [] if inputs == [DEFAULT_INPUT] else inputs, "output_path": match.group("output_path"),
            "evidence_status": match.group("evidence_status")}


def build(live_text: str) -> Tuple[Dict[str, bytes], List[str]]:
    """({relative path under docs/planning: bytes}, warnings) for a live export. Pure: reads and writes nothing else."""
    issues = parse_live(live_text)
    keyed: Dict[str, Dict[str, Any]] = {}
    key_of: Dict[str, str] = {}
    for issue in issues:
        match = _TITLE.match(issue.get("title") or "")
        if not match:
            raise GenerateError(f"{issue['id']}: the title {issue.get('title')!r} does not start with a task key and `: `")
        key, title = match.group(1), match.group(2)
        if key in keyed:
            raise GenerateError(f"{issue['id']} and {keyed[key]['issue']['id']} both claim the key {key}")
        keyed[key] = {"issue": issue, "title": title}
        key_of[issue["id"]] = key
    warnings: List[str] = []
    order = sorted(keyed, key=_key_order)
    catalog, manifest, alias, bodies = [], [], {}, {}
    dependents: Dict[str, int] = {issue["id"]: 0 for issue in issues}
    deps_of: Dict[str, List[str]] = {}
    for key in order:
        issue = keyed[key]["issue"]
        deps = []
        for edge in issue.get("dependencies") or []:
            target = edge.get("depends_on_id")
            if target not in key_of:
                raise GenerateError(f"{issue['id']} ({key}) depends on {target}, which the live export does not hold")
            if edge.get("type", "blocks") != "blocks":
                warnings.append(f"{key} -> {key_of[target]}: edge type {edge.get('type')!r} is not in the catalog (only blocking edges are)")
                continue
            if key_of[target] not in deps:
                deps.append(key_of[target])
                dependents[target] += 1
        deps_of[key] = deps
    for key in order:
        issue, title = keyed[key]["issue"], keyed[key]["title"]
        body = issue.get("description")
        if not isinstance(body, str) or not body:
            raise GenerateError(f"{issue['id']} ({key}): the live description is empty")
        row: Dict[str, Any] = {"key": key, "title": title, "deps": deps_of[key]}
        parsed = parse_body(issue["id"], key, title, body)
        order_template = ("scope", "acceptance", "design_packages", "detailed_contract", "inputs", "output_path", "evidence_status")
        for field in order_template:
            if field in parsed:
                row[field] = parsed[field]
        row["form"] = parsed["form"]
        catalog.append(row)
        alias[key] = issue["id"]
        bodies[f"bead-bodies/{key}.md"] = body.encode("utf-8")
        manifest.append({"key": key, "title": title, "deps": deps_of[key], "body": f"docs/planning/bead-bodies/{key}.md",
                         "priority": issue.get("priority")})
    snapshot = []
    for key in order:
        issue = keyed[key]["issue"]
        row = {field: issue[field] for field in SNAPSHOT_FIELDS if field in issue}
        row["dependency_count"] = len(deps_of[key])
        row["dependent_count"] = dependents[issue["id"]]
        snapshot.append(row)
    files = {
        "task-catalog.json": (json.dumps(catalog, indent=2) + "\n").encode("utf-8"),
        "bead-map.json": (json.dumps(alias, indent=2) + "\n").encode("utf-8"),
        "bead-manifest.json": (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
        "beads-snapshot.json": (json.dumps({"issues": snapshot, "total": len(snapshot), "limit": 0, "offset": 0, "has_more": False},
                                           separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"),
    }
    files.update(bodies)
    return files, warnings


def write(root: str, files: Dict[str, bytes]) -> List[str]:
    """Write `files` under root/docs/planning, creating bead-bodies/; returns the paths that changed. Never touches anything else."""
    base = os.path.realpath(os.path.join(root, "docs", "planning"))
    changed = []
    for rel, data in sorted(files.items()):
        if os.path.islink(os.path.join(base, rel)):
            raise GenerateError(f"refusing to write through a symlink: {rel}")
        path = os.path.realpath(os.path.join(base, rel))
        if os.path.commonpath([base, path]) != base:
            raise GenerateError(f"refusing to write outside docs/planning: {rel}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "rb") as f:
                if f.read() == data:
                    continue
        except OSError:
            pass
        with open(path, "wb") as f:
            f.write(data)
        changed.append(rel)
    return changed


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Regenerate docs/planning from the live Beads export (one way; never runs br)")
    ap.add_argument("--root", default=DEFAULT_ROOT, help="the repository root (default: this repository)")
    ap.add_argument("--live", default=None, help="the live export (default: ROOT/.beads/issues.jsonl)")
    args = ap.parse_args(argv)
    root = os.path.realpath(args.root)
    live = os.path.realpath(args.live or os.path.join(root, ".beads", "issues.jsonl"))
    if os.path.commonpath([os.path.join(root, "docs", "planning"), live]) == os.path.join(root, "docs", "planning"):
        print("error: the live export must not be inside docs/planning", file=sys.stderr)
        return 2
    try:
        with open(live, encoding="utf-8") as f:
            text = f.read()
        files, warnings = build(text)
        changed = write(root, files)
    except (OSError, GenerateError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    forms = {}
    for rel, data in files.items():
        if rel == "task-catalog.json":
            for row in json.loads(data):
                forms[row["form"]] = forms.get(row["form"], 0) + 1
    print(f"generated from {os.path.basename(live)} ({len(text.splitlines())} issues): {len(files)} files, {len(changed)} changed; "
          f"forms {dict(sorted(forms.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
