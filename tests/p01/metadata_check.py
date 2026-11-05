"""Hold `cargo metadata` output to the contract's rule that a default build carries no test-only crate.

`cargo metadata --format-version 1` prints a `resolve` graph for the features it was asked about. This module reads two
such documents (the default features, and `--features franken-speaker/harness`) and checks, from the resolve graph and
not from the manifests, that:

* in the default resolve, the speaker's NORMAL dependency closure does not contain `franken-test-support`, directly or
  through any other crate (a dev-dependency edge is not part of a build and is ignored); and
* in the harness resolve it does contain it, so the gate is a real switch and not an absent dependency.

It never runs cargo. The documents are produced by the central operator on the rch path; until then the real check
is a blocked case, and this module is exercised on documents that are written by hand.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Set, Tuple

Pair = Tuple[str, str]


class MetadataError(Exception):
    pass


def build_metadata(spec: Dict[str, Any]) -> Dict[str, Any]:
    """A minimal `cargo metadata` document from a compact hand-written spec:
    {"packages": [names], "deps": {name: [[dep, "normal"|"dev"|"build"], ...]}}."""
    ident = {name: f"path+file:///ws/{name}#0.1.0" for name in spec["packages"]}
    nodes = []
    for name in spec["packages"]:
        deps = []
        for dep, kind in spec.get("deps", {}).get(name, []):
            deps.append({"name": dep.replace("-", "_"), "pkg": ident[dep],
                         "dep_kinds": [{"kind": None if kind == "normal" else kind, "target": None}]})
        nodes.append({"id": ident[name], "deps": deps, "dependencies": [d["pkg"] for d in deps], "features": []})
    return {"packages": [{"id": ident[n], "name": n, "version": "0.1.0"} for n in spec["packages"]],
            "resolve": {"nodes": nodes, "root": None}, "workspace_members": list(ident.values()), "version": 1}


def normal_closure(meta: Dict[str, Any], crate: str) -> Set[str]:
    """Package names reachable from `crate` through normal dependency edges only."""
    try:
        names = {p["id"]: p["name"] for p in meta["packages"]}
        nodes = {names[n["id"]]: n for n in meta["resolve"]["nodes"]}
    except (KeyError, TypeError) as err:
        raise MetadataError(f"not a cargo metadata document with a resolve graph: {err!r}") from err
    if crate not in nodes:
        raise MetadataError(f"{crate} is not in the resolve graph")
    seen: Set[str] = set()
    stack = [crate]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        for dep in nodes[name].get("deps", []):
            if any(kind.get("kind") is None for kind in dep.get("dep_kinds", [])) and dep["pkg"] in names:
                stack.append(names[dep["pkg"]])
    return seen


def check(default_meta: Any, harness_meta: Any, crate: str = "franken-speaker",
          forbidden: str = "franken-test-support") -> List[Pair]:
    """(code, subject) pairs; empty means the gate behaves as the contract says."""
    errs: Set[Pair] = set()
    try:
        in_default = normal_closure(default_meta, crate)
    except MetadataError:
        errs.add(("metadata_malformed", "default"))
        in_default = set()
    try:
        in_harness = normal_closure(harness_meta, crate)
    except MetadataError:
        errs.add(("metadata_malformed", "harness"))
        in_harness = set()
    if not any(code == "metadata_malformed" and subject == "default" for code, subject in errs):
        if forbidden in in_default:
            errs.add(("metadata_default_has_edge", f"{crate}->{forbidden}"))
    if not any(code == "metadata_malformed" and subject == "harness" for code, subject in errs):
        if forbidden not in in_harness:
            errs.add(("metadata_harness_missing_edge", f"{crate}->{forbidden}"))
        missing = sorted(in_default - in_harness)
        if missing:
            errs.add(("metadata_harness_dropped_dependency", ",".join(missing)))
    return sorted(errs)


def load(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def codes(pairs: Iterable[Pair]) -> List[str]:
    return sorted({code for code, _ in pairs})
