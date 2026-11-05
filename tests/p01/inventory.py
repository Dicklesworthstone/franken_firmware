"""P01-BLK-005: E06's committed inventory against the CURRENT Cargo.lock. Read-only, stdlib only.

P01 names E06 (`ffw-unk`) as an input: the pinned per-target dependency / unsafe / license / feature inventory. E06 writes it as
`toolchain/results/e06/{rev,audit}-<rev12>/audit.json` (`scripts/e06/audit.py audit`, schema `ffw.e06.audit.v1`). This module asks the one
question P01 can answer offline: is that inventory OF THE LOCKFILE THE WORKSPACE HAS NOW, and does it agree with it?

    judge(audit, lock_bytes) -> (verdict, findings, detail)       verdict: pass | blocked | fail

* **blocked** (`audit_lock_stale`): the audit binds another lockfile (`lock.sha256`). It is not wrong, it is stale: the delta is named
  (workspace crates added or removed since, pins no longer in the lock, packages in the lock with no pin), because the features cargo
  enables and the unsafe and licence findings of a graph are facts of THAT graph. It becomes a pass only when E06 re-audits a clean
  export of the revision and commits the new `audit.json`; nothing here re-derives E06's findings.
* **fail**: the audit claims the current lock and is inconsistent with it: a pin whose version, source or checksum differs from the
  lock, a locked package no platform pins, a pin for a package the lock lacks, a workspace crate with no record, a package record
  without its `unsafe` or `license` fact, a missing platform, a wrong entry count, an unknown schema, or blockers in the audit's own
  summary. An audit that was edited to claim a lock it was not made from is caught here, not accepted.
* **pass**: every external package of the lock is pinned (exact version, source, checksum) on at least one platform, every pin is in
  the lock, every workspace crate has a record, and every package record carries its `unsafe` and `license`.

What a pass does not show: that any dependency is admitted (the audit's `review` items are human decisions, counted, not judged
here), that the unsafe or licence findings are right (that is E06's tool and tests), or anything about a build, a link or a device.

    python3 tests/p01/inventory.py AUDIT.json [--lock Cargo.lock]      exit 0 pass, 3 blocked, 1 fail, 2 unreadable
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Sequence, Set, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.exit("python 3.11+ is required (tomllib)")

AUDIT_SCHEMA = "ffw.e06.audit.v1"
PLATFORMS = ("host", "mips", "powerpc")
AUDIT_DIR = os.path.join("toolchain", "results", "e06")
Finding = Tuple[str, str]
Verdict = Tuple[str, List[Finding], str]


class InputError(Exception):
    """The audit or the lock cannot be read as what it should be."""


def parse_lock(lock: bytes) -> Tuple[Dict[str, Tuple[str, str]], Set[str], int]:
    """(external packages as `name@version` -> (source, checksum), workspace crate names, total package count)."""
    try:
        data = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise InputError(f"Cargo.lock cannot be read: {err}") from err
    external: Dict[str, Tuple[str, str]] = {}
    workspace: Set[str] = set()
    packages = data.get("package", [])
    for pkg in packages:
        if "source" in pkg:
            external[f"{pkg['name']}@{pkg['version']}"] = (pkg["source"], pkg.get("checksum", ""))
        else:
            workspace.add(pkg["name"])
    return external, workspace, len(packages)


AUDIT_PREFIXES = ("rev-", "audit-")


def find_audits(repo: str) -> List[str]:
    """Paths of the committed audits: `toolchain/results/e06/rev-*/audit.json` (the first audit, whose directory holds E06's run
    records) and `toolchain/results/e06/audit-*/audit.json` (a re-audit kept apart from a directory whose files are pinned), sorted
    by directory name. No other directory holds an audit."""
    base = os.path.join(repo, AUDIT_DIR)
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, d, "audit.json") for d in sorted(os.listdir(base))
            if d.startswith(AUDIT_PREFIXES) and os.path.isfile(os.path.join(base, d, "audit.json"))]


def _shape(audit: Any) -> List[Finding]:
    """What the rest of the judgement reads, checked once; anything else is reported and nothing further is judged."""
    out: List[Finding] = []
    if not isinstance(audit, dict):
        return [("audit_shape", "not an object")]
    if audit.get("schema") != AUDIT_SCHEMA:
        out.append(("audit_shape", f"schema {audit.get('schema')!r}, want {AUDIT_SCHEMA}"))
    lock = audit.get("lock")
    if not (isinstance(lock, dict) and isinstance(lock.get("sha256"), str) and len(lock["sha256"]) == 64
            and isinstance(lock.get("entries"), int)):
        out.append(("audit_shape", "lock.sha256 / lock.entries"))
    pins = audit.get("pins")
    for plat in PLATFORMS:
        rows = pins.get(plat, {}).get("rows") if isinstance(pins, dict) and isinstance(pins.get(plat), dict) else None
        if not isinstance(rows, list) or not all(isinstance(r, dict) and isinstance(r.get("package"), str) for r in rows):
            out.append(("audit_shape", f"pins.{plat}.rows"))
    packages = audit.get("packages")
    if not (isinstance(packages, list) and all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in packages)):
        out.append(("audit_shape", "packages"))
    counts = audit.get("summary", {}).get("counts") if isinstance(audit.get("summary"), dict) else None
    if not (isinstance(counts, dict) and isinstance(counts.get("blocker"), int)):
        out.append(("audit_shape", "summary.counts.blocker"))
    return out


def judge(audit: Any, lock: bytes) -> Verdict:
    external, workspace, total = parse_lock(lock)
    shape = _shape(audit)
    if shape:
        return "fail", sorted(shape), "the audit is not an ffw.e06.audit.v1 record: " + "; ".join(s for _, s in shape)
    pinned: Dict[str, Set[Tuple[str, str]]] = {}
    for plat in PLATFORMS:
        for row in audit["pins"][plat]["rows"]:
            if row.get("source") == "workspace":    # a member row: the workspace's own crate, recorded in `packages`, not a pin
                continue
            pinned.setdefault(row["package"], set()).add((row.get("source", ""), row.get("checksum", "")))
    audited_ws = {p["name"] for p in audit["packages"] if p.get("source_kind") == "workspace"}
    bound = hashlib.sha256(lock).hexdigest()
    claimed = audit["lock"]["sha256"]
    findings: List[Finding] = []
    if claimed != bound:
        findings.append(("audit_lock_stale", f"{claimed[:8]}->{bound[:8]}"))
        findings += [("stale_workspace_crate_not_audited", n) for n in sorted(workspace - audited_ws)]
        findings += [("stale_workspace_crate_removed", n) for n in sorted(audited_ws - workspace)]
        findings += [("stale_pin_not_in_lock", k) for k in sorted(set(pinned) - set(external))]
        findings += [("stale_lock_package_not_pinned", k) for k in sorted(set(external) - set(pinned))]
        delta = [f"{label}: {', '.join(sorted(s for c, s in findings if c == code))}"
                 for code, label in (("stale_workspace_crate_not_audited", "workspace crates added since"),
                                     ("stale_workspace_crate_removed", "workspace crates removed since"),
                                     ("stale_pin_not_in_lock", "pinned but no longer in the lock"),
                                     ("stale_lock_package_not_pinned", "in the lock but never pinned"))
                 if any(c == code for c, _ in findings)]
        return "blocked", sorted(findings), (f"the audit binds lock {claimed[:8]}… ({audit['lock']['entries']} entries), the workspace's "
                                              f"is {bound[:8]}… ({total}): " + ("; ".join(delta) or "the same packages, a different file")
                                              + ". Re-audit a clean export of the revision (E06) and commit its audit.json")
    for key, want in sorted(external.items()):
        if key not in pinned:
            findings.append(("lock_package_not_pinned", key))
        elif pinned[key] != {want}:     # EVERY platform's row for it must be the lock's entry, not just one of them
            findings.append(("pin_differs", key))
    findings += [("pin_not_in_lock", k) for k in sorted(set(pinned) - set(external))]
    findings += [("crate_not_audited", n) for n in sorted(workspace - audited_ws)]
    findings += [("audited_crate_not_in_lock", n) for n in sorted(audited_ws - workspace)]
    if audit["lock"]["entries"] != total:
        findings.append(("lock_entries_differs", f"{audit['lock']['entries']} vs {total}"))
    records = {p.get("key"): p for p in audit["packages"]}
    for key in sorted(external):
        rec = records.get(key)
        for field in ("unsafe", "license"):
            if rec is None or field not in rec:
                findings.append(("package_field_missing", f"{key}:{field}"))
    if audit["summary"]["counts"]["blocker"]:
        findings.append(("audit_has_blockers", str(audit["summary"]["counts"]["blocker"])))
    if findings:
        return "fail", sorted(set(findings)), ("the audit claims the current lock and disagrees with it: "
                                               + ", ".join(sorted({f"{c}[{s}]" for c, s in findings})[:6]))
    review = audit["summary"]["counts"].get("review", 0)
    return "pass", [], (f"the audit binds the current lock {bound[:8]}…: {len(external)} external packages pinned (version, source, checksum) "
                        f"on {'/'.join(PLATFORMS)}, {len(workspace)} workspace crates recorded, each package with its unsafe and licence "
                        f"fact; {review} review item(s) remain, which are human decisions and not judged here")


def codes(findings: Sequence[Finding]) -> List[str]:
    return sorted({c for c, _ in findings})


def main(argv: List[str]) -> int:
    here = os.path.dirname(os.path.realpath(__file__))
    ap = argparse.ArgumentParser(description="Judge an E06 audit.json against Cargo.lock")
    ap.add_argument("audit")
    ap.add_argument("--lock", default=os.path.join(os.path.dirname(os.path.dirname(here)), "Cargo.lock"))
    args = ap.parse_args(argv)
    try:
        with open(args.audit, encoding="utf-8") as f:
            audit = json.load(f)
        with open(args.lock, "rb") as f:
            lock = f.read()
        verdict, findings, detail = judge(audit, lock)
    except (OSError, ValueError, InputError) as err:
        print(f"cannot judge: {err}", file=sys.stderr)
        return 2
    for code, subject in findings:
        print(f"{code} [{subject}]")
    print(f"{verdict}: {detail}")
    return {"pass": 0, "blocked": 3, "fail": 1}[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
