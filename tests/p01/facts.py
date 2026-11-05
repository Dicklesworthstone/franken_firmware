"""What the repository actually says about its own workspace, and how that is held to the declared contract.

`extract(root)` reads Cargo.toml, every member and excluded manifest, Cargo.lock and the directory tree with
tomllib and the filesystem only. It never runs cargo, so it is a host-only, offline check. Every path in the
result is relative to `root`, which makes the result (and its digest) independent of the working directory the
tool is started from.

`compare(contract, facts)` returns the drift between the declared contract (the typed contract's data file) and
those facts as sorted (code, subject) pairs. A pending or excluded crate is allowed only when the contract
declares it; nothing is tolerated silently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tomllib
from typing import Any, Dict, Iterable, List, Set, Tuple

Pair = Tuple[str, str]

# Cargo profile names the contract uses -> where their values are read from.
PROFILE_SOURCES = {"release": ("workspace", "release"), "bootstrap_release": ("ffw-hello-init", "release")}


def _load(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _dep_tables(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """normal/dev/build dependency tables, target-specific ones merged into their kind."""
    out: Dict[str, Dict[str, Any]] = {"normal": {}, "dev": {}, "build": {}}
    for key, kind in (("dependencies", "normal"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        out[kind].update(manifest.get(key, {}))
    for table in manifest.get("target", {}).values():
        if not isinstance(table, dict):
            continue
        for key, kind in (("dependencies", "normal"), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
            out[kind].update(table.get(key, {}))
    return out


def _bool_or_str(value: Any) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def _profile_values(table: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "opt_level": _bool_or_str(table.get("opt-level", "")),
        "lto": _bool_or_str(table.get("lto", "")),
        "codegen_units": table.get("codegen-units", None),
        "panic": _bool_or_str(table.get("panic", "")),
        "strip": _bool_or_str(table.get("strip", "")),
    }


def _crate_facts(root: str, rel: str, workspace_deps: Dict[str, Any]) -> Dict[str, Any]:
    manifest = _load(os.path.join(root, rel, "Cargo.toml"))
    package = manifest.get("package", {})
    name = package.get("name", "")
    internal: Dict[str, Set[str]] = {"normal": set(), "optional": set(), "dev": set(), "build": set()}
    for kind, table in _dep_tables(manifest).items():
        for key, spec in table.items():
            real = spec.get("package", key) if isinstance(spec, dict) else key
            ws = workspace_deps.get(key)
            has_path = isinstance(spec, dict) and "path" in spec
            ws_internal = isinstance(ws, dict) and "path" in ws
            if has_path or ws_internal:
                is_optional = kind == "normal" and isinstance(spec, dict) and spec.get("optional") is True
                internal["optional" if is_optional else kind].add(real)
    # `dep:NAME` entries of [features] gate an optional dependency; the feature names that do are its flags.
    gates: Dict[str, Set[str]] = {}
    for fname, entries in manifest.get("features", {}).items():
        for entry in entries:
            if isinstance(entry, str) and entry.startswith("dep:"):
                gates.setdefault(entry[4:], set()).add(fname)
    lints = manifest.get("lints", {})
    if lints.get("workspace") is True:
        lint = "workspace"
    else:
        lint = str(lints.get("rust", {}).get("unsafe_code", "none"))
    bins = {b.get("name", "") for b in manifest.get("bin", [])}
    if os.path.isfile(os.path.join(root, rel, "src", "main.rs")):
        bins.add(name)
    return {
        "name": name, "path": rel, "lints": lint,
        "deps": {k: sorted(v) for k, v in internal.items()},
        "features": sorted(manifest.get("features", {}).keys()),
        "feature_table": {k: list(v) for k, v in sorted(manifest.get("features", {}).items())},
        "optional_gates": {dep: sorted(v) for dep, v in sorted(gates.items())},
        "bins": sorted(b for b in bins if b),
        "profile_tables": sorted(manifest.get("profile", {}).keys()),
        "profile_release": _profile_values(manifest.get("profile", {}).get("release", {})),
    }


def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def extract(root: str) -> Dict[str, Any]:
    root = os.path.realpath(root)
    manifest = _load(os.path.join(root, "Cargo.toml"))
    ws = manifest.get("workspace", {})
    workspace_deps = ws.get("dependencies", {})
    members = [_crate_facts(root, rel, workspace_deps) for rel in ws.get("members", [])]
    excluded = []
    for rel in ws.get("exclude", []):
        if os.path.isfile(os.path.join(root, rel, "Cargo.toml")):
            excluded.append(_crate_facts(root, rel, workspace_deps))
        else:
            excluded.append({"name": "", "path": rel, "missing": True})

    on_disk = []
    crates_dir = os.path.join(root, "crates")
    if os.path.isdir(crates_dir):
        for entry in sorted(os.listdir(crates_dir)):
            manifest_path = os.path.join(crates_dir, entry, "Cargo.toml")
            if os.path.isfile(manifest_path):
                on_disk.append({"path": f"crates/{entry}", "name": _load(manifest_path)["package"]["name"]})
    tests = []
    tests_dir = os.path.join(root, "tests")
    if os.path.isdir(tests_dir):
        tests = [f"tests/{e}" for e in sorted(os.listdir(tests_dir))
                 if os.path.isdir(os.path.join(tests_dir, e)) and not e.startswith((".", "__"))]

    lock = {"present": False, "sha256": "", "packages": {}}
    lock_path = os.path.join(root, "Cargo.lock")
    if os.path.isfile(lock_path):
        data = _load(lock_path)
        internal_names = {p["name"] for p in data.get("package", []) if "source" not in p}
        packages = {}
        for pkg in data.get("package", []):
            if "source" in pkg:
                continue
            deps = {d.split(" ")[0] for d in pkg.get("dependencies", [])}
            packages[pkg["name"]] = sorted(deps & internal_names)
        lock = {"present": True, "sha256": _sha256_file(lock_path), "packages": packages}

    return {
        "members": sorted(members, key=lambda c: c["path"]),
        "excluded": sorted(excluded, key=lambda c: c["path"]),
        "on_disk": sorted(on_disk, key=lambda c: c["path"]),
        "tests_dirs": tests,
        "lock": lock,
        "workspace_lints_unsafe": str(manifest.get("workspace", {}).get("lints", {}).get("rust", {})
                                      .get("unsafe_code", "none")),
        "profile_release": _profile_values(manifest.get("profile", {}).get("release", {})),
        "toolchain_pin": {
            "rust-toolchain": os.path.isfile(os.path.join(root, "rust-toolchain")),
            "rust-toolchain.toml": os.path.isfile(os.path.join(root, "rust-toolchain.toml")),
            ".cargo/config.toml": os.path.isfile(os.path.join(root, ".cargo", "config.toml")),
        },
    }


def facts_digest(facts: Dict[str, Any]) -> str:
    text = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cycles(graph: Dict[str, Set[str]]) -> List[Tuple[str, ...]]:
    reach: Dict[str, Set[str]] = {}
    for start, first in graph.items():
        seen: Set[str] = set()
        stack = list(first)
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(graph.get(node, ()))
        reach[start] = seen
    found: Set[Tuple[str, ...]] = set()
    for node, out in reach.items():
        group = [o for o in out if o != node and node in reach.get(o, ())]
        if group:
            found.add(tuple(sorted(group + [node])))
    return sorted(found)


def resolve_normal_closure(facts: Dict[str, Any], crate: str, features: Iterable[str] = (),
                           default_features: bool = True) -> Set[str]:
    """Workspace crates in `crate`'s normal-dependency closure when `features` (Cargo feature names of `crate`) are
    enabled. A static re-derivation from the manifests, not a `cargo metadata` run. Plain dependencies are always in;
    an optional dependency is in only if an enabled feature lists `dep:NAME` or `NAME/feature`; a feature implies
    the features it lists, in its own crate or (as `NAME/feature`) in a dependency; a weak `NAME?/feature` applies
    once NAME is in. Dev- and build-dependencies are not in a normal closure. Evaluated to a fixed point."""
    members = {c["name"]: c for c in facts["members"]}
    active: Set[str] = set()
    enabled: Set[Tuple[str, str]] = set()

    def activate(name: str) -> bool:
        if name in members and name not in active:
            active.add(name)
            return True
        return False

    def enable(owner: str, feature: str) -> bool:
        if owner in members and (owner, feature) not in enabled:
            enabled.add((owner, feature))
            return True
        return False

    activate(crate)
    for feature in features:
        enable(crate, feature)
    if default_features and crate in members and "default" in members[crate]["feature_table"]:
        enable(crate, "default")
    changed = True
    while changed:
        changed = False
        for name in sorted(active):
            for dep in members[name]["deps"]["normal"]:
                changed |= activate(dep)
        for owner, feature in sorted(enabled):
            for entry in members[owner]["feature_table"].get(feature, []):
                if entry.startswith("dep:"):
                    changed |= activate(entry[4:])
                elif "/" in entry:
                    dep, _, sub = entry.partition("/")
                    weak = dep.endswith("?")
                    dep = dep.rstrip("?")
                    if not weak:
                        changed |= activate(dep)
                    if dep in active:
                        changed |= enable(dep, sub)
                else:
                    changed |= enable(owner, entry)
    return active


def compare(contract: Dict[str, Any], facts: Dict[str, Any], root: str = "") -> List[Pair]:
    """Drift between the declared contract and the repository, as sorted unique (code, subject) pairs."""
    errs: Set[Pair] = set()
    declared = {c["name"]: c for c in contract["crates"]}
    pending = {p["name"]: p for p in contract["pending_members"]}
    members = {c["name"]: c for c in facts["members"]}

    for name in sorted(set(members) - set(declared)):
        errs.add(("member_not_in_contract", name))
    for name in sorted(set(declared) - set(members)):
        errs.add(("contract_crate_not_member", name))
    for name in sorted(set(members) & set(declared)):
        if members[name]["path"] != declared[name]["path"]:
            errs.add(("crate_path_mismatch", name))

    # crates on disk must be a member or a declared pending member
    disk_names = {d["name"]: d for d in facts["on_disk"]}
    for name, rec in disk_names.items():
        if name not in members and name not in pending:
            errs.add(("crate_dir_unaccounted", name))
        if name in pending and pending[name]["path"] != rec["path"]:
            errs.add(("pending_path_mismatch", name))
    for name in pending:
        if name in members:
            errs.add(("pending_but_member", name))
        elif name not in disk_names:
            errs.add(("pending_missing_dir", name))

    # excluded crates
    want_ex = {e["path"]: e for e in contract["excluded"]}
    have_ex = {e["path"]: e for e in facts["excluded"]}
    for path in sorted(set(want_ex) ^ set(have_ex)):
        errs.add(("excluded_mismatch", path))
    for path in sorted(set(want_ex) & set(have_ex)):
        if have_ex[path].get("missing"):
            errs.add(("excluded_mismatch", path))
        elif have_ex[path]["name"] != want_ex[path]["name"]:
            errs.add(("excluded_name_mismatch", path))

    # dependency edges, both directions, per kind
    flags = {f["name"]: f["cargo_feature"] for f in contract["features"]}
    for name in sorted(set(members) & set(declared)):
        have = members[name]["deps"]
        opt = declared[name].get("optional_deps", [])
        want = {"normal": set(declared[name]["deps"]), "optional": {o["dep"] for o in opt},
                "dev": set(declared[name]["dev_deps"])}
        for kind in ("normal", "optional", "dev"):
            for dep in sorted(set(have[kind]) ^ want[kind]):
                errs.add(("dep_edge_mismatch", f"{kind}:{name}->{dep}"))
        for dep in have.get("build", []):
            errs.add(("dep_edge_mismatch", f"build:{name}->{dep}"))
        # an optional dependency is gated, in the manifest, by the flag the contract names
        for o in opt:
            flag = flags.get(o["feature"], "")
            if flag and o["dep"] in have["optional"] and flag not in members[name]["optional_gates"].get(o["dep"], []):
                errs.add(("optional_gate_mismatch", f"{name}->{o['dep']}"))

    # the real graph, independent of what the contract says
    actual = {n: (set(c["deps"]["normal"]) | set(c["deps"]["optional"])) & set(members) for n, c in members.items()}
    for comp in _cycles(actual):
        errs.add(("actual_dependency_cycle", ",".join(comp)))

    # the lockfile agrees with the manifests
    lock = facts["lock"]
    if not lock["present"]:
        errs.add(("lock_missing", "Cargo.lock"))
    else:
        for name in sorted(members):
            if name not in lock["packages"]:
                errs.add(("lock_package_missing", name))
                continue
            want_edges = set(members[name]["deps"]["normal"]) | set(members[name]["deps"]["optional"]) \
                | set(members[name]["deps"]["dev"]) | set(members[name]["deps"]["build"])
            want_edges &= set(members)
            for dep in sorted(set(lock["packages"][name]) ^ want_edges):
                errs.add(("lock_edge_mismatch", f"{name}->{dep}"))
        known = set(members) | {e["name"] for e in facts["excluded"] if e.get("name")}
        for name in sorted(set(lock["packages"]) - known):
            errs.add(("lock_package_extra", name))

    # unsafe policy
    for name in sorted(set(members) & set(declared)):
        policy = declared[name]["unsafe_policy"]
        lint = members[name]["lints"]
        ok = (policy == "forbid" and lint == "workspace" and facts["workspace_lints_unsafe"] == "forbid") or \
             (policy == "deny_with_scoped_allow" and lint == "deny")
        if not ok:
            errs.add(("unsafe_policy_drift", name))

    # cargo profiles
    for prof in contract["cargo_profiles"]:
        source = PROFILE_SOURCES.get(prof["name"])
        if source is None:
            errs.add(("cargo_profile_unverified", prof["name"]))
            continue
        where, _ = source
        if where == "workspace":
            have = facts["profile_release"]
        else:
            ex = next((e for e in facts["excluded"] if e.get("name") == where), None)
            have = ex["profile_release"] if ex else None
        if have is None:
            errs.add(("cargo_profile_unverified", prof["name"]))
            continue
        for field in ("opt_level", "lto", "codegen_units", "panic", "strip"):
            if have[field] != prof[field]:
                errs.add(("cargo_profile_drift", f"{prof['name']}.{field}"))
    for name, rec in members.items():
        if rec["profile_tables"]:
            errs.add(("profile_in_member_manifest", name))

    # features the contract says are gated by a cargo flag, and binaries the artifacts name
    for feat in contract["features"]:
        if feat["cargo_feature"] and (feat["owner_crate"] not in members
                                      or feat["cargo_feature"] not in members[feat["owner_crate"]]["features"]):
            errs.add(("feature_flag_missing", feat["name"]))
    bins = {n: set(c["bins"]) for n, c in members.items()}
    bins.update({e["name"]: set(e["bins"]) for e in facts["excluded"] if e.get("name")})
    for art in contract["artifacts"]:
        if art["bin"] and art["bin"] not in bins.get(art["crate"], set()):
            errs.add(("bin_missing", art["id"]))

    # ownership coverage of what is on disk, and no phantom assets
    asset_paths = {a["path"] for a in contract["assets"]}
    for rec in facts["on_disk"]:
        if rec["path"] not in asset_paths:
            errs.add(("asset_uncovered", rec["path"]))
    for path in facts["tests_dirs"]:
        if path not in asset_paths:
            errs.add(("asset_uncovered", path))
    if root:
        for a in contract["assets"]:
            if not os.path.exists(os.path.join(root, a["path"])):
                errs.add(("asset_path_missing", a["path"]))
    return sorted(errs)


def codes(pairs: Iterable[Pair]) -> List[str]:
    return sorted({c for c, _ in pairs})


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Print the workspace facts (or their digest) for a repository root")
    ap.add_argument("--root", required=True)
    ap.add_argument("--digest", action="store_true", help="print only the SHA-256 of the canonical facts")
    args = ap.parse_args(argv)
    facts = extract(args.root)
    print(facts_digest(facts) if args.digest else json.dumps(facts, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
