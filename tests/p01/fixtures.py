"""A tiny synthetic Cargo workspace for the drift and plan cases.

`materialize(root, spec)` writes the files; `mini_contract(spec)` returns the matching declared contract fields
(only the ones facts.compare reads). The baseline spec is consistent with its contract, so a planted defect is
the only thing that can change a result. Everything here is synthetic: no real crate, host or device.
"""
from __future__ import annotations

import copy
import os
from typing import Any, Dict

BASE_SPEC: Dict[str, Any] = {
    "members": {
        "a": {"deps": [], "dev": [], "lints": "workspace", "features": [], "bin": False},
        "b": {"deps": ["a"], "dev": [], "lints": "workspace", "features": ["gate"], "bin": True},
    },
    "extra_dirs": [],          # crates/<name> directories that are not workspace members
    "exclude": [],             # excluded crate directories (relative)
    "release": {"opt-level": "z", "lto": True, "codegen-units": 1, "panic": "abort", "strip": "symbols"},
    "lock": {"a": [], "b": ["a"]},
    "lock_present": True,
    "tests": ["x"],
    "workspace_unsafe": "forbid",
    "member_profile_table": False,
}


def base_spec() -> Dict[str, Any]:
    return copy.deepcopy(BASE_SPEC)


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def materialize(root: str, spec: Dict[str, Any]) -> None:
    members = spec["members"]
    rel = spec["release"]
    root_toml = ['[workspace]', 'resolver = "2"',
                 "members = [" + ", ".join(f'"crates/{n}"' for n in members) + "]",
                 "exclude = [" + ", ".join(f'"{p}"' for p in spec["exclude"]) + "]", "",
                 "[workspace.lints.rust]", f'unsafe_code = "{spec["workspace_unsafe"]}"', "",
                 "[workspace.dependencies]"]
    root_toml += [f'{n} = {{ path = "crates/{n}" }}' for n in members]
    root_toml += ["", "[profile.release]"]
    for key, val in rel.items():
        root_toml.append(f"{key} = {str(val).lower() if isinstance(val, bool) else (repr(val) if isinstance(val, int) else chr(34) + val + chr(34))}")
    _write(os.path.join(root, "Cargo.toml"), "\n".join(root_toml) + "\n")
    for name, rec in members.items():
        lines = ["[package]", f'name = "{name}"', 'version = "0.1.0"', 'edition = "2024"', ""]
        if rec["lints"] == "workspace":
            lines += ["[lints]", "workspace = true", ""]
        elif rec["lints"] != "none":
            lines += ["[lints.rust]", f'unsafe_code = "{rec["lints"]}"', ""]
        lines.append("[dependencies]")
        lines += [f"{d}.workspace = true" for d in rec["deps"]]
        lines += ["", "[dev-dependencies]"]
        lines += [f"{d}.workspace = true" for d in rec["dev"]]
        if rec["features"]:
            lines += ["", "[features]"] + [f"{f} = []" for f in rec["features"]]
        if spec["member_profile_table"] and name == "b":
            lines += ["", "[profile.release]", 'opt-level = 3']
        _write(os.path.join(root, "crates", name, "Cargo.toml"), "\n".join(lines) + "\n")
        _write(os.path.join(root, "crates", name, "src", "main.rs" if rec["bin"] else "lib.rs"), "")
    for extra in spec["extra_dirs"]:
        _write(os.path.join(root, "crates", extra, "Cargo.toml"),
               f'[package]\nname = "{extra}"\nversion = "0.1.0"\nedition = "2024"\n')
    for path in spec["exclude"]:
        _write(os.path.join(root, path, "Cargo.toml"),
               '[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\n\n[profile.release]\n'
               'opt-level = "z"\nlto = true\ncodegen-units = 1\npanic = "abort"\nstrip = true\n')
    for name in spec["tests"]:
        _write(os.path.join(root, "tests", name, "keep"), "")
    if spec["lock_present"]:
        lock = ["version = 4", ""]
        for name, deps in spec["lock"].items():
            lock += ["[[package]]", f'name = "{name}"', 'version = "0.1.0"']
            if deps:
                lock.append("dependencies = [" + ", ".join(f'"{d}"' for d in deps) + "]")
            lock.append("")
        _write(os.path.join(root, "Cargo.lock"), "\n".join(lock))


def mini_contract(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The declared contract that matches `spec` exactly (the fields facts.compare reads)."""
    crates = []
    for layer, (name, rec) in enumerate(spec["members"].items(), start=1):
        crates.append({"name": name, "path": f"crates/{name}", "owner": f"T{layer}", "role": "library",
                       "layer": layer, "unsafe_policy": "forbid" if rec["lints"] == "workspace" else "deny_with_scoped_allow",
                       "deps": list(rec["deps"]), "dev_deps": list(rec["dev"])})
    assets = [{"path": f"crates/{n}", "owner": f"T{i}", "kind": "crate"}
              for i, n in enumerate(spec["members"], start=1)]
    assets += [{"path": f"tests/{t}", "owner": "T1", "kind": "fixture"} for t in spec["tests"]]
    rel = spec["release"]
    return {
        "cargo_profiles": [{"name": "release", "opt_level": str(rel["opt-level"]).lower(),
                            "lto": str(rel["lto"]).lower(), "codegen_units": rel["codegen-units"],
                            "panic": rel["panic"], "strip": str(rel["strip"]).lower()}],
        "crates": crates, "excluded": [], "pending_members": [], "assets": assets,
        "features": [{"name": "f", "kind": "core", "requirement": "optional", "owner_crate": "b",
                      "cargo_feature": "gate", "requires": [], "accepted_evidence": ["host_simulation"]}],
        "artifacts": [{"id": "b-host", "crate": "b", "bin": "b", "target": "host"}],
    }
