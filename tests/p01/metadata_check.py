"""Hold `cargo metadata` output to the contract's rule that a default build carries no test-only crate.

`cargo metadata --format-version 1` prints a `resolve` graph for the features it was asked about. This module reads two
such documents (the default features, and `--features franken-speaker/harness`) and checks, from the resolve graph and
not from the manifests, that:

* in the default resolve, the speaker's NORMAL dependency closure does not contain `franken-test-support`, directly or
  through any other crate (a dev-dependency edge is not part of a build and is ignored); and
* in the harness resolve it does contain it, so the gate is a real switch and not an absent dependency.

It never runs cargo. The documents are produced by the central operator on the rch path. `check` is the gate alone and
is what `scripts/e2e/p01 check-metadata` runs. `judge` is what the e2e's P01-BLK-007 runs on the real documents: the
gate, plus proof that the documents describe THIS tree (same workspace members, same workspace edges as the manifests
give by an independent static resolve, the gating feature resolved in the harness document and not in the default one,
and every package from this Cargo.lock), so a stale or swapped document cannot pass for the committed tree.

`PLANTS` (nine) are faults injected into copies of the supplied documents; the judgement passes only if the unplanted
documents are clean AND every planted fault is caught with its expected code.
"""
from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

import facts as facts_mod

Pair = Tuple[str, str]
GATE_CRATE, FORBIDDEN, GATE_FEATURE = "franken-speaker", "franken-test-support", "harness"


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


def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ------------------------------------------------------------------------------ binding a document to this tree

def _index(meta: Any) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]], Set[str], Set[Tuple[str, str]]]:
    try:
        names = {p["id"]: p["name"] for p in meta["packages"]}
        nodes = {names[n["id"]]: n for n in meta["resolve"]["nodes"]}
        members = {names[i] for i in meta["workspace_members"]}
        versions = {(p["name"], p["version"]) for p in meta["packages"]}
    except (KeyError, TypeError) as err:
        raise MetadataError(f"not a cargo metadata document with a resolve graph: {err!r}") from err
    return names, nodes, members, versions


def lock_packages(lock_path: str) -> Set[Tuple[str, str]]:
    """(name, version) of every package in a Cargo.lock."""
    with open(lock_path, "rb") as f:
        data = tomllib.load(f)
    return {(p["name"], p["version"]) for p in data.get("package", [])}


def _bounded(items: Iterable[str], limit: int = 6) -> str:
    ordered = sorted(items)
    return (",".join(ordered[:limit]) + (f",+{len(ordered) - limit} more" if len(ordered) > limit else "")) or "-"


def bind_to_tree(label: str, meta: Any, tree: Dict[str, Any], lock: Optional[Set[Tuple[str, str]]], gate_on: bool,
                 crate: str = GATE_CRATE, gate_feature: str = GATE_FEATURE) -> Set[Pair]:
    """Pairs for a document that does not describe the tree: `tree` is facts.extract output, `gate_on` says whether the
    document was asked for `crate`'s gating feature. Subjects are bounded and carry no paths."""
    try:
        _names, nodes, members, versions = _index(meta)
    except MetadataError:
        return {("metadata_malformed", label)}
    errs: Set[Pair] = set()
    tree_members = {m["name"] for m in tree["members"]}
    if members != tree_members:
        errs.add(("metadata_members_differ_from_tree",
                  f"{label}:only_in_document={_bounded(members - tree_members)};"
                  f"only_in_tree={_bounded(tree_members - members)}"))
    wrong = []
    for member in sorted(members & tree_members):
        flags = [gate_feature] if (gate_on and member == crate) else []
        want = facts_mod.resolve_normal_closure(tree, member, flags)
        got = {name for name in normal_closure(meta, member) if name in members}
        if want != got:
            wrong.append(member)
    for member in wrong[:8]:
        errs.add(("metadata_closure_differs_from_manifests", f"{label}:{member}"))
    if len(wrong) > 8:
        errs.add(("metadata_closure_differs_from_manifests", f"{label}:+{len(wrong) - 8} more"))
    if crate in nodes:
        resolved = gate_feature in set(nodes[crate].get("features", []))
        if gate_on and not resolved:
            errs.add(("metadata_feature_not_resolved", f"{label}:{crate}/{gate_feature}"))
        if not gate_on and resolved:
            errs.add(("metadata_feature_resolved_by_default", f"{label}:{crate}/{gate_feature}"))
    if lock is not None:
        stray = versions - lock
        if stray:
            errs.add(("metadata_not_from_this_lock", f"{label}:" + _bounded(f"{n} {v}" for n, v in stray)))
    return errs


def judge(default_meta: Any, harness_meta: Any, tree: Dict[str, Any], lock: Optional[Set[Tuple[str, str]]] = None,
          crate: str = GATE_CRATE, forbidden: str = FORBIDDEN, gate_feature: str = GATE_FEATURE) -> List[Pair]:
    """The gate (`check`) plus proof that both documents describe `tree` and `lock`. Empty means judged clean."""
    errs = set(check(default_meta, harness_meta, crate, forbidden))
    errs |= bind_to_tree("default", default_meta, tree, lock, False, crate, gate_feature)
    errs |= bind_to_tree("harness", harness_meta, tree, lock, True, crate, gate_feature)
    return sorted(errs)


# ------------------------------------------------------------------------------ planted faults


class Plant(NamedTuple):
    name: str
    expect: Tuple[str, ...]
    apply: Callable[[Any, Any, Dict[str, str]], Tuple[Any, Any]]
    why: str


def _node(meta: Any, name: str) -> Dict[str, Any]:
    names, nodes, _members, _versions = _index(meta)
    if name not in nodes:
        raise MetadataError(f"{name} is not in the resolve graph")
    return nodes[name]


def _pkg_id(meta: Any, name: str) -> str:
    for p in meta["packages"]:
        if p["name"] == name:
            return p["id"]
    raise MetadataError(f"{name} is not a package of the document")


def add_normal_edge(meta: Any, src: str, dst: str) -> None:
    """Add a normal edge the way cargo prints it: onto an existing dependency entry as one more `dep_kinds` row (a crate
    that is also a dev-dependency shares its entry), otherwise as a new entry."""
    node, pid = _node(meta, src), _pkg_id(meta, dst)
    row = {"kind": None, "target": None}
    for dep in node["deps"]:
        if dep["pkg"] == pid:
            if not any(k.get("kind") is None for k in dep["dep_kinds"]):
                dep["dep_kinds"].append(row)
            break
    else:
        node["deps"].append({"name": dst.replace("-", "_"), "pkg": pid, "dep_kinds": [dict(row)]})
    if pid not in node.get("dependencies", []):
        node.setdefault("dependencies", []).append(pid)


def remove_normal_edge(meta: Any, src: str, dst: str) -> None:
    node, pid = _node(meta, src), _pkg_id(meta, dst)
    kept = []
    for dep in node["deps"]:
        if dep["pkg"] == pid:
            dep["dep_kinds"] = [k for k in dep["dep_kinds"] if k.get("kind") is not None]
            if not dep["dep_kinds"]:
                continue
        kept.append(dep)
    node["deps"] = kept
    node["dependencies"] = [d for d in node.get("dependencies", []) if d != pid or any(x["pkg"] == pid for x in kept)]


def _direct_normal(meta: Any, crate: str) -> Set[str]:
    names = {p["id"]: p["name"] for p in meta["packages"]}
    return {names[d["pkg"]] for d in _node(meta, crate)["deps"]
            if d["pkg"] in names and any(k.get("kind") is None for k in d["dep_kinds"])}


def _workspace_closure(meta: Any, crate: str) -> Set[str]:
    members = _index(meta)[2]
    return {name for name in normal_closure(meta, crate) if name in members}


def _intermediate(meta: Any, crate: str, forbidden: str) -> str:
    """A workspace crate the gated crate reaches through normal edges, other than itself and the forbidden one; one it
    does not depend on directly when there is such a crate, so the leak really is transitive."""
    others = sorted(_workspace_closure(meta, crate) - {crate, forbidden})
    if not others:
        raise MetadataError(f"{crate} has no workspace dependency to plant a transitive leak through")
    indirect = [name for name in others if name not in _direct_normal(meta, crate)]
    return (indirect or others)[0]


def _droppable_edge(meta: Any, crate: str, forbidden: str) -> str:
    """A direct normal WORKSPACE dependency of `crate` whose edge, once removed, really shrinks the crate's workspace
    closure (the dependency is not also reached some other way), so removing it is a visible change and not a no-op.
    Only workspace edges are bound to the manifests, so only they can be stale in a way the judgement can see."""
    members = _index(meta)[2]
    before = _workspace_closure(meta, crate)
    for dep in sorted((_direct_normal(meta, crate) & members) - {forbidden}):
        trial = copy.deepcopy(meta)
        remove_normal_edge(trial, crate, dep)
        if _workspace_closure(trial, crate) != before:
            return dep
    raise MetadataError(f"{crate} has no workspace dependency whose removal changes its closure")


def _plant_leak_direct(d, h, ctx):
    add_normal_edge(d, ctx["crate"], ctx["forbidden"])
    return d, h


def _plant_leak_transitive(d, h, ctx):
    add_normal_edge(d, _intermediate(d, ctx["crate"], ctx["forbidden"]), ctx["forbidden"])
    return d, h


def _plant_harness_without_edge(d, h, ctx):
    remove_normal_edge(h, ctx["crate"], ctx["forbidden"])
    return d, h


def _plant_swapped(d, h, ctx):
    return h, d


def _plant_member_missing(d, h, ctx):
    names, _nodes, members, _versions = _index(d)
    candidates = sorted(members - {ctx["crate"], ctx["forbidden"]})
    if not candidates:
        raise MetadataError("the document has no workspace member other than the gated and forbidden crates to drop")
    victim = candidates[0]
    d["workspace_members"] = [i for i in d["workspace_members"] if names[i] != victim]
    return d, h


def _plant_stale_edge(d, h, ctx):
    remove_normal_edge(d, ctx["crate"], _droppable_edge(d, ctx["crate"], ctx["forbidden"]))
    return d, h


def _plant_feature_not_resolved(d, h, ctx):
    node = _node(h, ctx["crate"])
    node["features"] = [f for f in node.get("features", []) if f != ctx["feature"]]
    return d, h


def _plant_default_resolved_harness(d, h, ctx):
    node = _node(d, ctx["crate"])
    node["features"] = sorted(set(node.get("features", [])) | {ctx["feature"]})
    return d, h


def _plant_stale_lock(d, h, ctx):
    _names, _nodes, members, _versions = _index(d)
    victim = next((p for p in d["packages"] if p["name"] not in members), None)
    if victim is None:
        raise MetadataError("the document has no non-workspace package whose version could be changed")
    victim["version"] = "0.0.0-planted"
    return d, h


PLANTS: List[Plant] = [
    Plant("leak_direct", ("metadata_default_has_edge",), _plant_leak_direct,
          "the harness-only crate becomes a normal dependency of the gated crate in the default build"),
    Plant("leak_transitive", ("metadata_default_has_edge",), _plant_leak_transitive,
          "the harness-only crate leaks into the default build through another normal dependency"),
    Plant("harness_without_edge", ("metadata_harness_missing_edge",), _plant_harness_without_edge,
          "the harness build lost the edge, so the gate would not be a switch"),
    Plant("swapped_arguments", ("metadata_default_has_edge", "metadata_harness_missing_edge"), _plant_swapped,
          "the two documents given in the wrong order"),
    Plant("member_missing", ("metadata_members_differ_from_tree",), _plant_member_missing,
          "a document from a tree with a different set of workspace members"),
    Plant("stale_edge", ("metadata_closure_differs_from_manifests",), _plant_stale_edge,
          "a document from older manifests: a workspace edge the manifests still have is gone"),
    Plant("feature_not_resolved", ("metadata_feature_not_resolved",), _plant_feature_not_resolved,
          "a harness document that was not produced with the feature on"),
    Plant("default_resolved_harness", ("metadata_feature_resolved_by_default",), _plant_default_resolved_harness,
          "a default document that was produced with the feature on"),
    Plant("stale_lock", ("metadata_not_from_this_lock",), _plant_stale_lock,
          "a document resolved against a different Cargo.lock"),
]


def run_plants(default_meta: Any, harness_meta: Any, tree: Dict[str, Any], lock: Optional[Set[Tuple[str, str]]],
               crate: str = GATE_CRATE, forbidden: str = FORBIDDEN,
               gate_feature: str = GATE_FEATURE) -> List[str]:
    """Problems found by planting each fault in a copy of the documents; empty means every plant was caught with its
    expected code. The caller has already shown the unplanted documents are clean (the remove-the-plant control)."""
    ctx = {"crate": crate, "forbidden": forbidden, "feature": gate_feature}
    problems = []
    for plant in PLANTS:
        try:
            planted = plant.apply(copy.deepcopy(default_meta), copy.deepcopy(harness_meta), ctx)
        except MetadataError as err:
            problems.append(f"{plant.name}: could not be planted: {err}")
            continue
        got = codes(judge(planted[0], planted[1], tree, lock, crate, forbidden, gate_feature))
        missing = [c for c in plant.expect if c not in got]
        if missing:
            problems.append(f"{plant.name}: not caught, expected {missing}, got {got}")
    return problems


def codes(pairs: Iterable[Pair]) -> List[str]:
    return sorted({code for code, _ in pairs})
