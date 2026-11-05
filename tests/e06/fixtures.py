"""Hand-written, cargo-metadata-shaped fixture graphs for the E06 audit tests.

Nothing here calls the analyzer.  A ``Crate`` is described by hand (its sources, license, links, edges and which
platforms an edge exists on); ``Fixture`` writes the files to disk and emits (a) per-platform metadata in the
shape ``cargo metadata`` produces, (b) a Cargo.lock text.  The expected inventories live in the tests, written
independently of the code under test.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "ab" * 32


class Dep:
    """An edge.  ``only`` limits it to those platform keys (None: every platform)."""

    def __init__(self, name: str, kind: Optional[str] = None, target: Optional[str] = None,
                 only: Optional[Iterable[str]] = None, version: Optional[str] = None):
        self.name, self.kind, self.target, self.version = name, kind, target, version
        self.only: Optional[Set[str]] = None if only is None else set(only)


class Crate:
    def __init__(self, name: str, version: str = "1.0.0", *, where: str = "registry", src: str = "",
                 files: Optional[Dict[str, str]] = None, kinds: Sequence[str] = ("lib",),
                 license: Optional[str] = "MIT", license_file: Optional[str] = None, links: Optional[str] = None,
                 build_rs: Optional[str] = None, deps: Sequence[Dep] = (), source: Optional[str] = "default",
                 checksum: Optional[str] = CHECKSUM, in_lock: bool = True, workspace_lints: bool = False,
                 own_lints: Optional[str] = None, features: Optional[Dict[str, Sequence[str]]] = None,
                 write_sources: bool = True):
        self.name, self.version, self.where = name, version, where
        self.src, self.files, self.kinds = src, dict(files or {}), tuple(kinds)
        self.license, self.license_file, self.links, self.build_rs = license, license_file, links, build_rs
        self.deps = list(deps)
        self.checksum, self.in_lock = checksum, in_lock
        self.workspace_lints, self.own_lints = workspace_lints, own_lints
        self.features = {k: list(v) for k, v in (features or {}).items()}      # platform key -> enabled features
        self.write_sources = write_sources
        if source == "default":
            source = {"registry": REGISTRY, "workspace": None, "external": None}[where]
        self.source = source
        self.dir = ""                                                         # set by Fixture

    @property
    def key(self) -> str:
        return "%s@%s" % (self.name, self.version)


class Fixture:
    def __init__(self, root: str, outside: str, members: Sequence[str]):
        self.root, self.outside, self.members = root, outside, list(members)
        self.crates: Dict[str, Crate] = {}

    def add(self, *crates: Crate) -> "Fixture":
        for c in crates:
            self.crates[c.key] = c
            base = {"workspace": os.path.join(self.root, "crates"), "external": self.outside,
                    "registry": os.path.join(self.root, ".registry")}[c.where]
            c.dir = os.path.join(base, "%s-%s" % (c.name, c.version) if c.where == "registry" else c.name)
        return self

    # -- disk
    def write(self, workspace_unsafe_lint: str = "forbid") -> None:
        os.makedirs(self.root, exist_ok=True)
        with open(os.path.join(self.root, "Cargo.toml"), "w") as fh:
            fh.write('[workspace]\nmembers = []\n[workspace.lints.rust]\nunsafe_code = "%s"\n' % workspace_unsafe_lint)
        with open(os.path.join(self.root, "LICENSE"), "w") as fh:
            fh.write("fixture license text\n")
        for c in self.crates.values():
            os.makedirs(os.path.join(c.dir, "src"), exist_ok=True)
            manifest = '[package]\nname = "%s"\nversion = "%s"\n' % (c.name, c.version)
            if c.workspace_lints:
                manifest += "[lints]\nworkspace = true\n"
            elif c.own_lints:
                manifest += '[lints.rust]\nunsafe_code = "%s"\n' % c.own_lints
            with open(os.path.join(c.dir, "Cargo.toml"), "w") as fh:
                fh.write(manifest)
            if not c.write_sources:
                continue
            root_file = "src/main.rs" if "bin" in c.kinds and "lib" not in c.kinds else "src/lib.rs"
            with open(os.path.join(c.dir, root_file), "w") as fh:
                fh.write(c.src)
            for rel, text in c.files.items():
                os.makedirs(os.path.dirname(os.path.join(c.dir, rel)), exist_ok=True)
                with open(os.path.join(c.dir, rel), "w") as fh:
                    fh.write(text)
            if c.build_rs is not None:
                with open(os.path.join(c.dir, "build.rs"), "w") as fh:
                    fh.write(c.build_rs)

    # -- cargo-shaped output
    def _id(self, c: Crate) -> str:
        head = c.source if c.source else "path+file://" + c.dir
        return "%s#%s@%s" % (head, c.name, c.version)

    def _resolve_dep(self, parent: Crate, dep: Dep) -> Crate:
        matches = [c for c in self.crates.values() if c.name == dep.name and (dep.version in (None, c.version))]
        if len(matches) != 1:
            raise LookupError("fixture dependency %s of %s is ambiguous or missing: %s" % (dep.name, parent.key, matches))
        return matches[0]

    def metadata(self, platform: str, workspace_root: Optional[str] = None) -> Dict[str, Any]:
        members = [self.crates[k] for k in self.members]
        reach: Dict[str, Crate] = {c.key: c for c in members}
        todo = list(members)
        while todo:
            cur = todo.pop()
            for d in cur.deps:
                if d.only is not None and platform not in d.only:
                    continue
                child = self._resolve_dep(cur, d)
                if child.key not in reach:
                    reach[child.key] = child
                    todo.append(child)
        packages = []
        for c in self.crates.values():
            targets = []
            for kind in c.kinds:
                src_name = "main.rs" if kind == "bin" else "lib.rs"
                targets.append({"kind": [kind], "name": c.name.replace("-", "_"),
                                "src_path": os.path.join(c.dir, "src", src_name)})
            if c.build_rs is not None or c.links:
                targets.append({"kind": ["custom-build"], "name": "build-script-build",
                                "src_path": os.path.join(c.dir, "build.rs")})
            packages.append({
                "id": self._id(c), "name": c.name, "version": c.version, "source": c.source,
                "license": c.license, "license_file": c.license_file, "links": c.links,
                "manifest_path": os.path.join(c.dir, "Cargo.toml"), "targets": targets,
                "dependencies": [{"name": d.name, "kind": d.kind, "target": d.target, "optional": False}
                                 for d in c.deps],
            })
        nodes = []
        for c in reach.values():
            deps = []
            for d in c.deps:
                if d.only is not None and platform not in d.only:
                    continue
                child = self._resolve_dep(c, d)
                deps.append({"name": child.name.replace("-", "_"), "pkg": self._id(child),
                             "dep_kinds": [{"kind": d.kind, "target": d.target}]})
            nodes.append({"id": self._id(c), "features": list(c.features.get(platform, [])), "deps": deps})
        return {"packages": packages, "workspace_members": [self._id(c) for c in members],
                "workspace_root": workspace_root or self.root, "resolve": {"nodes": nodes}}

    def lock_text(self) -> str:
        out = ["version = 4\n"]
        for c in sorted(self.crates.values(), key=lambda c: (c.name, c.version)):
            if not c.in_lock:
                continue
            out.append('[[package]]\nname = "%s"\nversion = "%s"\n' % (c.name, c.version))
            if c.source:
                out.append('source = "%s"\n' % c.source)
                if c.checksum and c.source.startswith("registry+"):
                    out.append('checksum = "%s"\n' % c.checksum)
            out.append("\n")
        return "".join(out)
