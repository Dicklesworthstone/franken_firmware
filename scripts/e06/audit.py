#!/usr/bin/env python3
"""E06 (bead ffw-unk): audit dependency features and target availability.  Stdlib only, offline.

Reads the resolver (``cargo metadata --locked --offline --filter-platform <triple>``), ``Cargo.lock`` and the
dependency sources already in the local registry cache, and reports FACTS per package and per target:

* pin: exact version, source and checksum from Cargo.lock, plus the features cargo enabled per target.  A lock entry that no
  platform graph links (a gated dependency inactive everywhere) is still pinned and inventoried, from its cargo source after
  the cached archive is proved to be the locked one, and labelled ``unlinked``; a source that cannot be proved is a blocker;
* native code signals: ``links``, a build script, native build tooling, link directives in the script;
* unsafe: counted from the crate's OWN source tokens, and which mechanism (crate attribute, manifest lint,
  workspace lint) declares forbid/deny.  A parent crate's ``forbid(unsafe_code)`` is not an input to any
  dependency's classification, so no dependency can be admitted because its parent forbids unsafe;
* std / alloc / no_std, per target, with the features cargo enabled for that target;
* duplicate versions, license-metadata omissions, target-cfg-gated dependencies and where they are active;
* floating point: the compiler's own target spec (soft-float or not) and which crates use floats.

It never says "admitted".  Findings are ``blocker`` (the audit cannot stand: unpinned source, missing
checksum, a target cargo cannot resolve, ...), ``review`` (a human decision is required: unsafe or native code
in a linked dependency, duplicate version, ...) or ``info``.  Exit codes: 0 nothing to review, 3 only review
items, 1 blockers, 2 usage.  Missing target support is its own outcome and is never folded into a pass.

Limits, stated so they are not mistaken for coverage (see docs/contracts/e06.md): macro-generated unsafe is
invisible; ``cfg``-off unsafe is counted; cargo reports one feature set per package per platform, which can
union what a build-dependency and a normal dependency would each get under resolver 2; hardware FPU presence is
not something a compiler target spec can establish.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import zlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import checks  # noqa: E402
import rustscan  # noqa: E402

SCHEMA = "ffw.e06.audit.v1"
DEFAULT_TARGETS = {"mips": "mips-unknown-linux-musl", "powerpc": "powerpc-unknown-linux-musl"}
SEVERITIES = ("blocker", "review", "info")
REFERENCE_PLATFORMS = {"host"}
CODE_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin"}
SKIP_DIRS = {"tests", "benches", "examples", "target", ".git"}
# Build dependencies that bring native code; autocfg only probes the compiler, so it is listed apart.
NATIVE_TOOLING_DEPS = {"cc", "cmake", "pkg-config", "bindgen", "vcpkg", "make", "bindgen-cli"}
COMPILER_PROBE_DEPS = {"autocfg", "rustc_version", "version_check"}
# Crates that may hold unsafe, by policy input (bead section 2: the platform layer is "the only userspace crate
# permitted to reach raw device handles").  Since P02 stage 2 (6ab9020) `franken-platform` itself forbids unsafe and the
# syscall unsafe lives in its Linux leaf, so the leaf is the one name here; tests/e06/test_live.py pins that its unsafe
# stays in `src/sys.rs` and that a crate which gains an unsafe token is flagged.  An input, not a discovered fact;
# override with --unsafe-allowed.  Add a name only together with the review that says why.
DEFAULT_UNSAFE_ALLOWED = ("franken-platform-linux",)

CANDIDATES: List[Dict[str, Any]] = [
    {"name": "asupersync", "category": "runtime", "match": ["asupersync"],
     "evaluate_with": "Add it as a pinned dependency (registry version or git rev) of a scratch workspace crate with the exact "
                      "feature set proposed for the slim profile, then run this audit on that Cargo.lock. Also audit what a "
                      "feature named runtime-core actually excludes (a feature name is not proof), its background and blocking "
                      "worker threads, and its u64 atomics (the BE targets have no atomic64): contract E03 section 4."},
    {"name": "franken_kernel", "category": "no_std type substrate", "match": ["franken_kernel", "franken-kernel"],
     "evaluate_with": "Pin it the same way and read the std/alloc columns at the exact revision: its transitive no_std and alloc "
                      "choices must be validated, not assumed (no_std is not no allocation)."},
    {"name": "libc candidates", "category": "libc", "match": ["frankenlibc", "franken_libc", "franken-libc"],
     "evaluate_with": "FrankenLibC reuse is admitted function by function after target review (contract E03 section 4): pin the "
                      "revision, audit its closure with this tool, and review each function against the target ABI. The Rust `libc` "
                      "crate is not a candidate for this row: it is an FFI binding table, reported on its own row below."},
    {"name": "libc crate (Rust FFI binding table)", "category": "ffi binding table", "match": ["libc"], "informational": True,
     "evaluate_with": "The Rust `libc` crate declares C types and functions for FFI. It is not a libc and nothing to admit: its "
                      "presence on a big-endian target graph means code there can call C functions through it, so review which "
                      "functions are called against the target ABI (contract E03 section 4). A presence on the host reference "
                      "platform only is the build machine's, not the firmware's."},
    {"name": "codecs", "category": "codecs", "match": [],
     "evaluate_with": "No codec crate is named anywhere in this repository. Name candidates first (S02 codec profile qualification), "
                      "then audit each pinned closure, including its floating-point use on the soft-float MIPS target."},
]


# ------------------------------------------------------------------------------------------------ inputs

class PlatformInput:
    """What was learned about one platform; ``metadata`` is None unless ``outcome == 'resolved'``."""

    def __init__(self, key: str, triple: str, outcome: str, detail: str = "", metadata: Optional[dict] = None,
                 target_spec: Optional[dict] = None, spec_outcome: str = "unavailable"):
        self.key, self.triple, self.outcome, self.detail = key, triple, outcome, detail
        self.metadata, self.target_spec, self.spec_outcome = metadata, target_spec, spec_outcome


_UNKNOWN_TARGET = re.compile(r"could not find specification for target|error loading target specification|"
                             r"unknown target triple", re.I)


class LockedSources:
    """Cargo's own listing of every package the lock resolves, with no platform filter.  A platform-filtered read omits the
    lock entries that no platform graph links (a gated dependency that is inactive everywhere), so this is the one place
    their registry cache paths can be found.  ``outcome`` is ``resolved`` or a resolver failure; ``metadata`` is None unless
    resolved."""

    def __init__(self, outcome: str, metadata: Optional[dict] = None, detail: str = ""):
        self.outcome, self.metadata, self.detail = outcome, metadata, detail


class PlatformList(list):
    """The platform inputs, plus the lock-wide source listing that ``gather`` read beside them.  A plain list in every other
    respect, so code that only iterates the platforms is unchanged."""

    locked: Optional[LockedSources] = None


def run_cargo_metadata(manifest: str, triple: Optional[str], timeout: float = 180.0,
                       cargo_args: Sequence[str] = ()) -> Tuple[str, Optional[dict], str]:
    """(outcome, metadata, detail).  A resolver read, not a build: --locked --offline, one target filter (none when
    ``triple`` is None: the lock-wide listing).  ``cargo_args`` is only ever the feature selection built by
    ``feature_args`` (never free text)."""
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline",
           *(["--filter-platform", triple] if triple is not None else []),
           "--manifest-path", manifest, *cargo_args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "resolver-failed", None, "%s: %s" % (type(exc).__name__, str(exc)[:200])
    if proc.returncode == 0:
        return "resolved", json.loads(proc.stdout), ""
    return ("target-unsupported" if _UNKNOWN_TARGET.search(proc.stderr) else "resolver-failed"), None, \
        scrub_paths(error_headline(proc.stderr), [os.path.dirname(os.path.abspath(manifest))])


FEATURE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./+-]*$")


def feature_args(no_default: bool, features: Optional[str]) -> List[str]:
    """The only cargo flags this tool forwards, validated: a feature selection, nothing else.  Raises ValueError."""
    out: List[str] = []
    if no_default:
        out.append("--no-default-features")
    if features:
        names = features.split(",")
        if not all(FEATURE_NAME.match(f) for f in names):               # an empty segment is a typo, not a no-op
            raise ValueError("--features needs a comma-separated list of feature names, got %r" % features)
        out += ["--features", ",".join(names)]
    return out


def feature_suffix(cargo_args: Sequence[str]) -> str:
    """The same selection as it appears in a planned cargo check line (after ``-p <crate>``)."""
    return "".join(" " + a for a in cargo_args)


def scrub_paths(text: str, roots: Sequence[str]) -> str:
    """Cargo's messages embed absolute paths (the workspace, the home directory).  A report is committed evidence and
    must not carry them, so the workspace root becomes ``<workspace>`` and the home directory ``~``."""
    def swap(value: str, token: str, subject: str) -> str:
        # Only at a path boundary: "/r/ws" must not eat the start of the unrelated directory "/r/ws2".
        return re.sub(re.escape(value) + r"(?![\w.\-])", token, subject)

    for root in sorted({r for r in roots if r}, key=len, reverse=True):
        for variant in sorted({os.path.realpath(root), root}, key=len, reverse=True):
            text = swap(variant, "<workspace>", text)
    home = os.path.expanduser("~")
    return swap(home, "~", text) if home and home != "/" else text


_HEADLINE = re.compile(r"could not find specification for target|lock file|does not exist|offline|no matching package|"
                       r"failed to parse|failed to load", re.I)


def error_headline(stderr: str) -> str:
    """The sentence that says what went wrong.  Cargo wraps it in a long rustc command line, so truncating the
    head of stderr keeps the noise and drops the cause."""
    lines = [" ".join(line.split()) for line in stderr.splitlines() if line.strip()]
    for line in lines:
        if _HEADLINE.search(line) and not line.startswith("process didn't exit"):
            return line[:300]
    for line in lines:
        if line.startswith("error"):
            return line[:300]
    return (lines[0] if lines else "no output")[:300]


def capture_target_spec(triple: str, rustc: str = "rustc") -> Tuple[str, Optional[dict]]:
    """The compiler's own description of the target (needs a nightly rustc for -Z unstable-options)."""
    cmd = [rustc, "--print", "target-spec-json", "-Z", "unstable-options", "--target", triple]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable", None
    if proc.returncode != 0:
        return "unavailable", None
    try:
        return "captured", json.loads(proc.stdout)
    except ValueError:
        return "unavailable", None


def host_triple(rustc: str = "rustc") -> Optional[str]:
    try:
        out = subprocess.run([rustc, "-vV"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"^host:\s*(\S+)", out, re.M)
    return m.group(1) if m else None


# ------------------------------------------------------------------------------------------------ helpers

def _read(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rs_files(root: str, package_root: str) -> List[str]:
    """Every .rs file under ``root``; when ``root`` is the package root, tests/benches/examples are skipped."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.realpath(dirpath) == os.path.realpath(package_root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        dirnames.sort()
        out.extend(os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith(".rs"))
    return out


def _source_kind(pkg: dict, workspace_root: str) -> str:
    src = pkg.get("source")
    if src is None:
        inside = os.path.realpath(pkg["manifest_path"]).startswith(os.path.realpath(workspace_root) + os.sep)
        return "workspace" if inside else "path-external"
    if src.startswith("registry+") or src.startswith("sparse+"):
        return "registry"
    if src.startswith("git+"):
        return "git"
    return "other"


def _license(pkg: dict) -> Dict[str, Any]:
    expr, lfile = pkg.get("license"), pkg.get("license_file")
    if expr:
        return {"status": "declared", "expression": expr, "file": lfile}
    if lfile:
        exists = os.path.exists(os.path.join(os.path.dirname(pkg["manifest_path"]), lfile))
        return {"status": "file-only" if exists else "file-missing", "expression": None, "file": lfile}
    return {"status": "missing", "expression": None, "file": None}


def _pkg_names(packages: Iterable[dict]) -> Dict[str, str]:
    """id -> unique display key ``name@version`` (a path-source suffix when two packages would collide)."""
    plist = list(packages)
    seen: Dict[str, int] = {}
    for p in plist:
        seen[f"{p['name']}@{p['version']}"] = seen.get(f"{p['name']}@{p['version']}", 0) + 1
    names = {}
    for p in plist:
        base = f"{p['name']}@{p['version']}"
        names[p["id"]] = base if seen[base] == 1 else "%s[%s]" % (base, os.path.basename(os.path.dirname(p["manifest_path"])))
    return names


# ------------------------------------------------------------------------------------------------ lock

def parse_lock(text: str) -> Dict[Tuple[str, str, Optional[str]], dict]:
    data = tomllib.loads(text) if tomllib is not None else {"package": []}
    return {(p["name"], p["version"], p.get("source")): p for p in data.get("package", [])}


_GIT_SHA = re.compile(r"#([0-9a-f]{40})$")


# ------------------------------------------------------------------------------------------------ graph

def classify_platform(meta: dict, scope: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Which packages end up in the target binary and which only run on the host, for ONE platform.

    ``scope`` names the workspace crates that are the roots; None means every member.  A third-party workspace has
    members for wasm, test harnesses and tooling whose closures would swamp the closure of the one crate a slim
    profile would use, so the roots can be named.

    ``linked``: workspace members plus everything reachable from them over normal edges, never entering a
    proc-macro crate.  ``host_only``: proc-macro crates, build-dependencies and member dev-dependencies and
    everything beneath them: compiled and run on the host, not linked into the target."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    pkgs = {p["id"]: p for p in meta["packages"]}
    members = [m for m in meta["workspace_members"] if m in nodes]
    if scope is not None:
        members = [m for m in members if pkgs[m]["name"] in set(scope)]
    edges: Dict[str, Dict[str, Set[str]]] = {}
    for nid, node in nodes.items():
        out: Dict[str, Set[str]] = {}
        for dep in node["deps"]:
            out[dep["pkg"]] = {("normal" if dk["kind"] is None else dk["kind"]) for dk in dep["dep_kinds"]}
        edges[nid] = out
    proc = {pid for pid, p in pkgs.items() if any("proc-macro" in t["kind"] for t in p["targets"])}
    linked: Set[str] = set(members)
    host_roots: Dict[str, str] = {}
    stack = list(members)
    while stack:
        cur = stack.pop()
        for dep, kinds in sorted(edges.get(cur, {}).items()):
            if "build" in kinds:
                host_roots.setdefault(dep, "build-dependency of %s" % pkgs[cur]["name"])
            if "dev" in kinds and cur in members:
                host_roots.setdefault(dep, "dev-dependency of %s" % pkgs[cur]["name"])
            if "normal" in kinds:
                if dep in proc:
                    host_roots.setdefault(dep, "proc-macro used by %s" % pkgs[cur]["name"])
                elif dep not in linked:
                    linked.add(dep)
                    stack.append(dep)
    host_only: Dict[str, str] = {}
    stack = [(r, why) for r, why in sorted(host_roots.items())]
    while stack:
        cur, why = stack.pop()
        if cur in host_only:
            continue
        host_only[cur] = why
        stack.extend((d, why) for d in sorted(edges.get(cur, {})) if d not in host_only)
    dependents: Dict[str, Set[str]] = {}
    for src in linked:
        for dep, kinds in edges.get(src, {}).items():
            if "normal" in kinds and dep in linked:
                dependents.setdefault(dep, set()).add(src)

    def closure(root: str) -> Set[str]:
        seen: Set[str] = set()
        todo = [root]
        while todo:
            cur = todo.pop()
            if cur in seen:
                continue
            seen.add(cur)
            todo.extend(d for d, k in edges.get(cur, {}).items() if "normal" in k and d not in proc)
        return seen

    return {"nodes": nodes, "pkgs": pkgs, "members": members, "edges": edges, "linked": linked,
            "host_only": {k: v for k, v in host_only.items() if k not in linked}, "also_host": linked & set(host_only),
            "dependents": dependents, "closure": closure}


# ------------------------------------------------------------------------------------------------ per-package scan

def _manifest_lint(pkg: dict, workspace_root: str) -> Dict[str, Optional[str]]:
    """The unsafe_code level the MANIFEST lint table sets for this package, and where it came from."""
    if tomllib is None:
        return {"level": None, "source": None}
    text = _read(pkg["manifest_path"])
    if text is None:
        return {"level": None, "source": None}
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {"level": None, "source": None}

    def level_of(table: Any) -> Optional[str]:
        value = (table or {}).get("rust", {}).get("unsafe_code")
        return value.get("level") if isinstance(value, dict) else value

    lints = manifest.get("lints", {})
    if lints.get("workspace") is True:
        ws_text = _read(os.path.join(workspace_root, "Cargo.toml"))
        try:
            ws = tomllib.loads(ws_text) if ws_text else {}
        except tomllib.TOMLDecodeError:
            ws = {}
        return {"level": level_of(ws.get("workspace", {}).get("lints")), "source": "workspace"}
    own = level_of(lints)
    return {"level": own, "source": "package" if own else None}


def scan_package(pkg: dict, workspace_root: str) -> Dict[str, Any]:
    """Platform-independent facts read from the package's own files."""
    mdir = os.path.dirname(pkg["manifest_path"])
    code_roots = [t for t in pkg["targets"] if set(t["kind"]) & CODE_KINDS]
    build_targets = [t for t in pkg["targets"] if "custom-build" in t["kind"]]
    files: List[str] = []
    for t in code_roots:
        for f in _rs_files(os.path.dirname(t["src_path"]), mdir):
            if f not in files:
                files.append(f)
    per_file: Dict[str, int] = {}
    uses_float, uses_alloc, scanned = False, False, 0
    lib_facts: Optional[rustscan.SourceFacts] = None
    root_file = next((t["src_path"] for t in code_roots if set(t["kind"]) & {"lib", "rlib", "dylib", "cdylib",
                                                                                "staticlib", "proc-macro"}),
                     code_roots[0]["src_path"] if code_roots else None)
    attr_lints: List[Tuple[str, str, Optional[Any]]] = []
    for path in files:
        text = _read(path)
        if text is None:
            continue
        scanned += 1
        facts = rustscan.scan_source(text)
        if facts.unsafe_lines:
            per_file[os.path.relpath(path, mdir)] = len(facts.unsafe_lines)
        uses_float |= facts.uses_float
        uses_alloc |= facts.uses_alloc
        if path == root_file:
            lib_facts = facts
            attr_lints = facts.lints
    build: Dict[str, Any] = {"present": bool(build_targets), "links": pkg.get("links"), "unsafe_tokens": 0,
                             "link_directives": [], "spawns_process": False, "native_tooling_paths": [],
                             "scanned": False}
    for t in build_targets:
        text = _read(t["src_path"])
        if text is None:
            continue
        build["scanned"] = True
        sig = rustscan.scan_build_script(text)
        build["link_directives"] = sorted(set(build["link_directives"]) | set(sig.link_directives))
        build["spawns_process"] |= sig.spawns_process
        build["native_tooling_paths"] = sorted(set(build["native_tooling_paths"]) | set(sig.native_tooling))
        build["unsafe_tokens"] += len(rustscan.scan_source(text).unsafe_lines)
    build_deps = sorted(d["name"] for d in pkg.get("dependencies", []) if d.get("kind") == "build")
    build["native_tooling_deps"] = [d for d in build_deps if d in NATIVE_TOOLING_DEPS]
    build["compiler_probe_deps"] = [d for d in build_deps if d in COMPILER_PROBE_DEPS]

    declared: List[Dict[str, Any]] = []
    for level, lint, cond in attr_lints:
        if lint == "unsafe_code" and level in ("forbid", "deny"):
            declared.append({"mechanism": "crate-attribute" if cond is None else "crate-attribute (conditional)",
                             "level": level, "condition": None if cond is None else rustscan.cfg_text(cond)})
    manifest_lint = _manifest_lint(pkg, workspace_root)
    if manifest_lint["level"] in ("forbid", "deny"):
        declared.append({"mechanism": "manifest-lint (%s)" % manifest_lint["source"], "level": manifest_lint["level"],
                         "condition": None})
    tokens = sum(per_file.values())
    return {
        "scanned_files": scanned,
        "unsafe": {"basis": "own-source-token-scan", "status": ("unscanned" if scanned == 0 else
                                                              ("present" if tokens else "none")),
                   "tokens": tokens, "files": dict(sorted(per_file.items())), "declared": declared},
        "uses_float": uses_float,
        "uses_alloc": uses_alloc,
        "root_facts": lib_facts,
        "build_script": build,
        "is_proc_macro": any("proc-macro" in t["kind"] for t in pkg["targets"]),
        "target_kinds": sorted({k for t in pkg["targets"] for k in t["kind"]}),
    }


def std_mode(facts: Optional[rustscan.SourceFacts], features: Set[str], proc_macro: bool) -> Tuple[str, str]:
    """(mode, why) with mode in std | no_std | proc-macro | unknown, for the features cargo enabled."""
    if proc_macro:
        return "proc-macro", "host-side procedural macro"
    if facts is None:
        return "unknown", "crate root source not available"
    if facts.no_std:
        mode, why = "no_std", "#![no_std]"
    elif facts.cfg_no_std:
        results = [(rustscan.eval_cfg(e, features), rustscan.cfg_text(e)) for e in facts.cfg_no_std]
        if any(v is True for v, _ in results):
            text = next(t for v, t in results if v is True)
            mode, why = "no_std", "#![cfg_attr(%s, no_std)] holds for the enabled features" % text
        elif all(v is False for v, _ in results):
            return "std", "#![cfg_attr(%s, no_std)] does not hold for the enabled features" % results[0][1]
        else:
            return "unknown", "#![cfg_attr(%s, no_std)] depends on a predicate this audit does not model" % results[0][1]
    else:
        return "std", "no #![no_std] attribute"
    # A no_std crate can bring std back with `[#[cfg(gate)]] extern crate std;` (thiserror, serde_json, memchr do,
    # under their `std` feature): #![no_std] alone does not decide what is linked.
    for gate in facts.extern_std:
        value = True if gate is None else rustscan.eval_cfg(gate, features)
        text = "unconditional" if gate is None else "under #[cfg(%s)]" % rustscan.cfg_text(gate)
        if value is True:
            return "std", "%s, but `extern crate std` %s holds for the enabled features" % (why, text)
        if value is None:
            return "unknown", "%s, and `extern crate std` %s depends on a predicate this audit does not model" % (why, text)
    return mode, why


# ------------------------------------------------------------------------------------------------ analysis

class _Findings:
    def __init__(self) -> None:
        self._by_key: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    def add(self, kind: str, severity: str, package: Optional[str], platform: Optional[str], detail: str) -> None:
        # The host is a reference platform, not firmware: a REVIEW item that exists only there informs, it does not
        # ask for a decision.  Blockers (an unresolvable platform, a missing checksum) are never lowered.
        if severity == "review" and platform in REFERENCE_PLATFORMS:
            severity = "info"
        key = (kind, severity, package or "", detail)
        entry = self._by_key.setdefault(key, {"kind": kind, "severity": severity, "package": package, "platforms": [],
                                              "detail": detail})
        if platform and platform not in entry["platforms"]:
            entry["platforms"].append(platform)

    def all(self) -> List[Dict[str, Any]]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        out = list(self._by_key.values())
        for f in out:
            f["platforms"].sort()
        return sorted(out, key=lambda f: (order[f["severity"]], f["kind"], f["package"] or "", f["detail"]))


# ------------------------------------------------------------------------------------------------ locked, linked nowhere

CRATE_READ_LIMIT = 64 << 20            # bytes of the cached .crate archive itself: a registry crate is small
INFLATE_LIMIT = 64 << 20               # bytes the archive may inflate to (the whole tar stream, so also all its members together)
MAX_ARCHIVE_MEMBERS = 20000            # entries, files and directories, in one archive
# Chosen conservative cap on extracted entries of every kind (files, directories, marker). This is an admission limit,
# not a theorem about every valid archive: one archived filename can imply several parent directories.
MAX_TREE_ENTRIES = 2 * MAX_ARCHIVE_MEMBERS + 1
EXTRACTION_MARKERS = {".cargo-ok"}     # the one file cargo itself writes beside an extracted crate


def _list_tree(root: str) -> Tuple[Optional[Set[str]], Optional[str]]:
    """(plain files of the extracted tree by relative name, None) or (None, why). By name and type only: nothing is opened.

    A lazy, iterative ``scandir`` traversal that counts EVERY entry (file, directory, marker) as it is produced and stops at the first one over
    ``MAX_TREE_ENTRIES``; it never lists a whole directory at once (``os.walk`` does) and never recurses, so a directory of a million entries, a
    thousand nested empty directories or a storm of extra files costs at most the cap before it is refused. A symbolic link of any kind, a
    device, a pipe or any other special file is refused where it stands, before the rest is read."""
    files: Set[str] = set()
    pending = [root]
    count = 0
    try:
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_TREE_ENTRIES:
                        return None, "the extracted source holds more than %d entries" % MAX_TREE_ENTRIES
                    rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
                    if entry.is_symlink():
                        return None, ("the extracted source holds a symbolic link to a directory" if entry.is_dir()
                                      else "%s in the extracted source is a symbolic link" % rel)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        files.add(rel)
                    else:
                        return None, "%s in the extracted source is not a plain file" % rel
    except OSError:
        return None, "the extracted source cannot be listed"
    return files, None


def _plain_file(path: str) -> Optional[Any]:
    """The regular file at ``path`` opened for reading, or None. Never through a symbolic link (``O_NOFOLLOW`` where the system has it, a
    link test everywhere), and never a device, pipe or directory: that is checked on the open descriptor, which is opened without blocking."""
    if os.path.islink(path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            return os.fdopen(fd, "rb")
    except OSError:
        pass
    os.close(fd)
    return None


def verify_registry_source(pkg: dict, checksum: str) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, str]]]:
    """(facts, None) when the cargo-cache source of a registry package is exactly what the lock pins, else (None, (kind, why)).

    The ``.crate`` archive cargo cached beside the extracted directory must hash to the lock's checksum, and that directory
    must hold exactly the archive's files, byte for byte (cargo's own ``.cargo-ok`` marker aside) and nothing else: no symbolic
    link anywhere in it, no device or pipe, no extra or missing file. Only then is anything read from it; for one that cannot be
    proved this way nothing is invented.

    Every step is bounded before it reads on: the archive's own size, the extracted tree's entry count (files, directories and the
    marker, enumerated lazily and stopped at the cap), the archive's inflation (read with a size, never all at once), its entry
    count, its member names (a duplicate is refused) and their declared sizes. The tar is parsed header by header, never
    listed whole, and every stream opened here is closed. The cached archive and every extracted file are opened by the one plain-file opener."""
    differs = "lock-entry-source-differs"
    root = os.path.dirname(pkg.get("manifest_path") or "")
    index_dir = os.path.dirname(root)
    src_dir = os.path.dirname(index_dir)
    registry = os.path.dirname(src_dir)
    if (os.path.basename(src_dir) != "src" or os.path.basename(registry) != "registry" or not os.path.isdir(root)
            or os.path.basename(root) != "%s-%s" % (pkg["name"], pkg["version"])):
        return None, ("lock-entry-source-missing", "its source is not a directory of cargo's registry cache")
    if os.path.islink(root):
        return None, (differs, "the extracted source directory is a symbolic link")
    crate = os.path.join(registry, "cache", os.path.basename(index_dir), os.path.basename(root) + ".crate")
    # The archive is as mutable an input as the tree: it is opened by the same plain-file opener (no link followed, no blocking on a pipe,
    # regular by the descriptor's own type), never by a blocking open that a pipe in its place could hang before the size cap applies.
    handle = _plain_file(crate)
    if handle is None:
        if not os.path.lexists(crate):
            return None, ("lock-entry-source-missing", "the cached .crate archive is not there, so the source cannot be tied to the lock checksum")
        return None, (differs, "the cached .crate archive is not a plain file (a link, pipe, device or directory)")
    try:
        with handle:
            blob = handle.read(CRATE_READ_LIMIT + 1)
    except OSError:
        return None, ("lock-entry-source-missing", "the cached .crate archive cannot be read, so the source cannot be tied to the lock checksum")
    if len(blob) > CRATE_READ_LIMIT:
        return None, (differs, "the cached .crate archive is larger than the %d-byte read limit" % CRATE_READ_LIMIT)
    digest = hashlib.sha256(blob).hexdigest()
    if digest != checksum.lower():
        return None, ("lock-entry-checksum-mismatch",
                      "the cached .crate archive hashes to %s..., the lock pins %s..." % (digest[:16], checksum[:16]))

    # 1. The extracted tree, by name and type only (nothing is opened): no link of any kind, no special file.
    on_disk, why = _list_tree(root)                                   # lazy, counted and capped; see _list_tree
    if on_disk is None:
        return None, (differs, why or "the extracted source cannot be listed")

    # 2. The archive: inflated with a bound, then read header by header with a bound on count, names and declared sizes.
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob), mode="rb") as stream:
            tar_bytes = stream.read(INFLATE_LIMIT + 1)
        if len(tar_bytes) > INFLATE_LIMIT:
            return None, (differs, "the cached .crate archive inflates to more than the %d-byte limit" % INFLATE_LIMIT)
        prefix = os.path.basename(root) + "/"
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            files: List[tarfile.TarInfo] = []
            names: Set[str] = set()
            total = 0
            for member in archive:                                     # one header at a time; no member's data is read here
                if len(names) >= MAX_ARCHIVE_MEMBERS:
                    return None, (differs, "the archive holds more than %d entries" % MAX_ARCHIVE_MEMBERS)
                key = member.name.rstrip("/")
                if key in names:
                    return None, (differs, "the archive names %r more than once" % member.name[:60])
                names.add(key)
                parts = member.name.split("/")
                if ".." in parts or "" in parts[:-1] or not (key == prefix[:-1] or key.startswith(prefix)):
                    return None, (differs, "the archive holds an entry outside the crate (%r)" % member.name[:60])
                if member.type == tarfile.DIRTYPE:
                    continue
                if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or key == prefix[:-1]:
                    return None, (differs, "the archive holds an entry that is not a plain file of the crate (%r)" % member.name[:60])
                total += member.size
                if total > INFLATE_LIMIT or member.offset_data + member.size > len(tar_bytes):
                    return None, (differs, "the archive declares a member larger than the %d-byte limit or than the data it holds" % INFLATE_LIMIT)
                files.append(member)
            expected = {m.name[len(prefix):] for m in files}
            for rel in sorted(on_disk - expected - EXTRACTION_MARKERS):
                return None, (differs, "%s is in the extracted source but not in the archive" % rel)
            for rel in sorted(expected - on_disk):
                return None, (differs, "%s is in the archive but not in the extracted source" % rel)

            # 3. Contents, only now: every file opened without following a link, every stream closed.
            for member in files:
                rel = member.name[len(prefix):]
                handle = _plain_file(os.path.join(root, rel))
                if handle is None:
                    return None, (differs, "%s is in the archive but is not a plain file of the extracted source" % rel)
                with handle:
                    on_disk_bytes = handle.read(member.size + 1)
                with archive.extractfile(member) as member_stream:     # type: ignore[union-attr]
                    data = member_stream.read()
                if on_disk_bytes != data:
                    return None, (differs, "%s in the extracted source differs from the archive" % rel)
    except (tarfile.TarError, OSError, EOFError, zlib.error):
        return None, (differs, "the cached .crate archive is not a readable gzip tar")
    return {"archive_sha256": digest, "files_in_archive": len(files), "files_compared": len(files)}, None


def inventory_unlinked(unused: Sequence[Tuple[str, str, Optional[str]]], lock: Dict[Tuple[str, str, Optional[str]], dict],
                       locked: LockedSources, workspace_root: str, platform_keys: Sequence[str], taken: Set[str]
                       ) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str, str, str]]]:
    """Inventory the Cargo.lock entries that no resolved platform graph links (a gated dependency inactive on every audited
    platform, for instance): ``unused`` are their lock keys.  Returns ``(items, notes)``.

    Each item is ``{"pid", "rec"}``: a package record with the same fields as any other, built from the SAME source scan and
    from that source's own manifest, but only after ``verify_registry_source`` proved the source is the one the lock pins.
    Its role on every platform is ``absent`` and it carries an ``unlinked`` object: it is not marked linked, host-only or
    reachable anywhere, and the label is derived from the graphs of this run alone, so an entry a later graph links is an
    ordinary record there.  A notes tuple is ``(kind, severity, package, detail)``.  An entry whose source is missing,
    differs from its checksum or cannot be located is a BLOCKER and gets no record at all: nothing is fabricated for it."""
    index: Dict[Tuple[str, str, Optional[str]], dict] = {}
    if locked.outcome == "resolved" and locked.metadata:
        for p in locked.metadata.get("packages", []):
            index.setdefault((p["name"], p["version"], p.get("source")), p)
    items: List[Dict[str, Any]] = []
    notes: List[Tuple[str, str, str, str]] = []
    taken = set(taken)
    for key3 in unused:
        name, version, source = key3
        label = "%s@%s" % (name, version)
        if source is None:
            continue                                  # a workspace or path entry: not an external pin
        if not source.startswith(("registry+", "sparse+")):
            notes.append(("lock-entry-unsupported-source", "blocker", label,
                          "locked, linked on no platform, from a %s source: only a registry crate can be tied to its lock checksum "
                          "from the cargo cache" % source.split("+", 1)[0]))
            continue
        checksum = lock[key3].get("checksum")
        if not checksum:
            notes.append(("lock-missing-checksum", "blocker", label, "registry package has no checksum in Cargo.lock"))
            continue
        pkg = index.get(key3)
        if pkg is None:
            why = ("cargo's lock-wide listing could not be read (%s: %s)" % (locked.outcome, locked.detail or "no detail")
                   if locked.outcome != "resolved" else "cargo's lock-wide listing does not name it")
            notes.append(("lock-entry-not-located", "blocker", label,
                          "locked, linked on no platform, and its source cannot be located: %s (nothing is inventoried for it)" % why))
            continue
        facts, problem = verify_registry_source(pkg, checksum)
        if problem is not None:
            notes.append((problem[0], "blocker", label,
                          "locked, linked on no platform; %s (nothing is inventoried for it)" % problem[1]))
            continue
        scan = scan_package(pkg, workspace_root)
        rec_key = label if label not in taken else "%s[%s]" % (label, os.path.basename(os.path.dirname(pkg["manifest_path"])))
        taken.add(rec_key)
        rec = {
            "name": name, "version": version, "key": rec_key, "source_kind": "registry",
            "pin": {"source": source, "checksum": checksum, "in_lock": True},
            "license": _license(pkg), "target_kinds": scan["target_kinds"], "links": pkg.get("links"),
            "build_script": scan["build_script"], "unsafe": scan["unsafe"], "uses_float": scan["uses_float"],
            "references_alloc": scan["uses_alloc"], "scanned_files": scan["scanned_files"],
            "platforms": {k: {"role": "absent"} for k in platform_keys},
            "gated_dependencies": [], "declared_features": None,
            "unlinked": {"reason": "in Cargo.lock and in no resolved platform graph (the host and each audited target)",
                         "source_verified": facts},
        }
        items.append({"pid": pkg["id"], "rec": rec})
        u, lic, b = scan["unsafe"], rec["license"], scan["build_script"]
        notes.append(("unlinked-locked-package", "info", rec_key,
                      "locked and linked on no audited platform, so nothing here links, builds or reaches it; read from its cargo source, "
                      "whose archive sha256 equals the lock's and whose %d files equal the archive's: license %s; %s; build script %s%s"
                      % (facts["files_compared"] if facts else 0,
                         lic["expression"] or lic["file"] or "none declared",
                         ("%d unsafe token(s) in %s" % (u["tokens"], ", ".join(u["files"])) if u["status"] == "present"
                          else "no unsafe token" if u["status"] == "none" else "unsafe %s" % u["status"]),
                         "present" if b["present"] else "absent",
                         "; links = %r" % pkg["links"] if pkg.get("links") else "")))
    return items, notes


def analyze(platforms: Sequence[PlatformInput], lock_text: str, workspace_root: str,
            unsafe_allowed: Iterable[str] = DEFAULT_UNSAFE_ALLOWED, build_results: Optional[List[dict]] = None,
            candidates: Optional[List[Dict[str, Any]]] = None, jobs: Optional[int] = None,
            subject: str = "own", cargo_args: Sequence[str] = (), lock_origin: str = "repository",
            plan_crates: Optional[Sequence[str]] = None, scope_crates: Optional[Sequence[str]] = None,
            locked: Optional[LockedSources] = None) -> Dict[str, Any]:
    """The audit.  Pure with respect to its arguments (it reads source files named by the metadata).

    ``subject`` is ``own`` (this project's workspace, held to its P01 unsafe rule) or ``upstream`` (a third party's
    pinned revision, audited read-only: its crates' unsafe is a fact to review, never a violation of a rule it never
    agreed to).  ``lock_origin`` is ``repository`` (a committed Cargo.lock) or ``generated-offline``.

    ``locked`` is the lock-wide source listing (``gather`` attaches it to the platform list it returns).  With it, every
    registry entry of an ``own`` workspace's Cargo.lock that NO platform graph links is inventoried from its verified cargo
    source (see ``inventory_unlinked``); without it each such entry is a blocker (``lock-entry-not-located``) and gets no record or pin.
    An ``upstream`` or scoped audit is unchanged, and so is any audit with no unused registry entry."""
    if locked is None:
        locked = getattr(platforms, "locked", None)
    allowed = set(unsafe_allowed)
    findings = _Findings()
    lock = parse_lock(lock_text)
    resolved = [p for p in platforms if p.outcome == "resolved"]

    plat_report: Dict[str, Any] = {}
    for p in platforms:
        spec = p.target_spec or {}
        feats = [f for f in str(spec.get("features", "")).split(",") if f]
        soft = "+soft-float" in feats
        plat_report[p.key] = {
            "triple": p.triple, "outcome": p.outcome, "detail": p.detail, "spec_outcome": p.spec_outcome,
            "target_spec": ({k: spec.get(k) for k in ("llvm-target", "arch", "cpu", "features", "max-atomic-width",
                                                       "target-endian", "target-pointer-width", "llvm-abiname")
                             if k in spec} if p.target_spec else None),
            "float": (None if not p.target_spec else
                      ("soft-float" if soft else "no soft-float feature in the compiler's target spec")),
        }
        if p.outcome != "resolved":
            findings.add(p.outcome, "blocker", None, p.key,
                         "cargo cannot resolve %s: %s" % (p.triple, p.detail or "no detail"))

    if scope_crates is not None and resolved:
        known = {pkg["name"] for p in resolved for pkg in (p.metadata or {}).get("packages", [])
                 if pkg["id"] in (p.metadata or {}).get("workspace_members", [])}
        unknown = sorted(set(scope_crates) - known)
        if unknown:
            raise ValueError("--scope-crates names no workspace crate: %s" % ", ".join(unknown))
    graphs = {p.key: classify_platform(p.metadata, scope_crates) for p in resolved}       # type: ignore[arg-type]
    all_pkgs: Dict[str, dict] = {}
    for p in resolved:
        for pkg in p.metadata["packages"]:                                  # type: ignore[index]
            all_pkgs.setdefault(pkg["id"], pkg)
    names = _pkg_names(all_pkgs.values())
    in_graph = {pid for g in graphs.values() for pid in g["nodes"]}
    # With named roots, cargo's resolve still lists every workspace member and everything under it. What is not
    # reachable from the roots (linked, or under a host-only edge) is not in this audit's graph: it is absent, never
    # a host-only package. Without a scope every resolve node is reachable and nothing changes.
    reach: Optional[Dict[str, Set[str]]] = None
    if scope_crates is not None:
        reach = {k: set(g["members"]) | set(g["linked"]) | set(g["host_only"]) for k, g in graphs.items()}
        in_graph = {pid for r in reach.values() for pid in r}

    scans = {pid: scan_package(all_pkgs[pid], workspace_root) for pid in sorted(in_graph, key=lambda i: names[i])}

    # --- per-package records
    records: Dict[str, Dict[str, Any]] = {}
    for pid in sorted(in_graph, key=lambda i: names[i]):
        pkg, scan = all_pkgs[pid], scans[pid]
        kind = _source_kind(pkg, workspace_root)
        lock_entry = lock.get((pkg["name"], pkg["version"], pkg.get("source")))
        per: Dict[str, Any] = {}
        for key, g in graphs.items():
            if pid not in g["nodes"] or (reach is not None and pid not in reach[key]):
                per[key] = {"role": "absent"}
                continue
            feats = set(g["nodes"][pid]["features"])
            mode, why = std_mode(scan["root_facts"], feats, scan["is_proc_macro"])
            role = ("member" if pid in g["members"] else "linked" if pid in g["linked"] else "host-only")
            per[key] = {"role": role, "features": sorted(feats), "std": mode, "std_why": why,
                        "host_only_reason": g["host_only"].get(pid), "also_host": pid in g["also_host"],
                        "dependents": sorted(names[d] for d in g["dependents"].get(pid, ()))}
        gated = []
        for dep in pkg.get("dependencies", []):
            if not dep.get("target"):
                continue
            if dep.get("kind") == "dev" and kind != "workspace":
                continue            # cargo never resolves a dependency's dev-dependencies, so there is nothing to report
            active = {}
            for key, g in graphs.items():
                active[key] = any(
                    dk["target"] == dep["target"] and (dk["kind"] or "normal") == (dep.get("kind") or "normal")
                    for child, e in g["edges"].get(pid, {}).items() if g["pkgs"][child]["name"] == dep["name"]
                    for dk in next((d["dep_kinds"] for d in g["nodes"][pid]["deps"] if d["pkg"] == child), []))
            for p in platforms:
                active.setdefault(p.key, None)
            gated.append({"dependency": dep["name"], "kind": dep.get("kind") or "normal", "gate": dep["target"],
                          "optional": bool(dep.get("optional")), "active_on": dict(sorted(active.items()))})
        records[pid] = {
            "name": pkg["name"], "version": pkg["version"], "key": names[pid], "source_kind": kind,
            "pin": {"source": pkg.get("source"), "checksum": (lock_entry or {}).get("checksum"),
                    "in_lock": lock_entry is not None},
            "license": _license(pkg), "target_kinds": scan["target_kinds"], "links": pkg.get("links"),
            "build_script": scan["build_script"], "unsafe": scan["unsafe"], "uses_float": scan["uses_float"],
            "references_alloc": scan["uses_alloc"], "scanned_files": scan["scanned_files"],
            "platforms": per, "gated_dependencies": gated,
            # What each declared feature enables, for workspace crates (cargo's own `features` map). An EMPTY list is a
            # marker: `runtime-core = []` enables nothing in Cargo.toml, so the name alone excludes no dependency.
            "declared_features": ({k: list(v) for k, v in sorted(pkg.get("features", {}).items())}
                                  if kind == "workspace" else None),
        }

    # --- effective std per platform (a crate is std if any linked dependency is)
    for key, g in graphs.items():
        memo: Dict[str, Tuple[str, str]] = {}

        def effective(pid: str) -> Tuple[str, str]:
            if pid in memo:
                return memo[pid]
            memo[pid] = ("unknown", "cycle")
            own = records[pid]["platforms"][key]
            result = (own["std"], names[pid]) if own["std"] != "no_std" else ("no_std", "")
            if own["std"] == "no_std":
                for dep, kinds in sorted(g["edges"].get(pid, {}).items()):
                    if "normal" in kinds and dep in g["linked"]:
                        mode, because = effective(dep)
                        if mode != "no_std":
                            result = (mode, because)
                            break
            memo[pid] = result
            return result

        for pid in g["linked"]:
            mode, because = effective(pid)
            records[pid]["platforms"][key]["effective_std"] = mode
            records[pid]["platforms"][key]["effective_std_because"] = because

    # --- findings
    float_users: Dict[str, Dict[str, List[str]]] = {}
    for pid, rec in records.items():
        for key, st in rec["platforms"].items():
            role = st["role"]
            if role not in ("member", "linked"):
                continue
            k = rec["key"]
            u = rec["unsafe"]
            if rec["source_kind"] == "workspace" and subject == "upstream":
                declared = [d for d in u["declared"] if "conditional" not in d["mechanism"]]
                if u["tokens"]:
                    findings.add("upstream-crate-unsafe", "review", k, key,
                                 "%d unsafe token(s) in %s (declared: %s)" % (
                                     u["tokens"], ", ".join(list(u["files"])[:6]) + (" ..." if len(u["files"]) > 6 else "") or "?",
                                     ", ".join("%s via %s" % (d["level"], d["mechanism"]) for d in declared) or "no forbid/deny"))
                elif not declared and u["status"] != "unscanned":
                    findings.add("upstream-crate-no-unsafe-declaration", "review", k, key,
                                 "no forbid/deny of unsafe_code by crate attribute or manifest lint")
                if u["tokens"] and any(d["level"] == "forbid" and "conditional" not in d["mechanism"] for d in u["declared"]):
                    findings.add("forbid-contradicted-by-source", "review", k, key,
                                 "forbid(unsafe_code) is declared yet %d unsafe token(s) exist (cfg-off or macro text): %s"
                                 % (u["tokens"], ", ".join(u["files"])))
            elif rec["source_kind"] == "workspace":
                declared = [d for d in u["declared"] if "conditional" not in d["mechanism"]]
                if u["tokens"] and rec["name"] in allowed:
                    findings.add("workspace-unsafe-permitted", "info", k, key,
                                 "%d unsafe token(s); %s is in the unsafe-allowed policy input" % (u["tokens"], rec["name"]))
                elif u["tokens"]:
                    members_depending = [n for n in st["dependents"] if n.split("@")[0] in
                                         {r["name"] for r in records.values() if r["source_kind"] == "workspace"}]
                    sev = "blocker" if members_depending else "review"
                    findings.add("workspace-unsafe-linked" if members_depending else "workspace-unsafe-test-only", sev, k, key,
                                 "%d unsafe token(s) in %s (declared: %s); %s" % (
                                     u["tokens"], ", ".join(u["files"]) or "?",
                                     ", ".join("%s via %s" % (d["level"], d["mechanism"]) for d in declared) or "no forbid/deny",
                                     "depended on by %s" % ", ".join(members_depending) if members_depending
                                     else "no workspace crate depends on it"))
                elif not declared and rec["name"] not in allowed and u["status"] != "unscanned":
                    findings.add("workspace-unsafe-undeclared", "blocker", k, key,
                                 "no forbid/deny of unsafe_code by crate attribute or manifest lint")
                if u["tokens"] and any(d["level"] == "forbid" and "conditional" not in d["mechanism"] for d in u["declared"]):
                    findings.add("forbid-contradicted-by-source", "review", k, key,
                                 "forbid(unsafe_code) is declared yet %d unsafe token(s) exist (cfg-off or macro text): %s"
                                 % (u["tokens"], ", ".join(u["files"])))
            else:
                if u["status"] == "present":
                    parents = st["dependents"]
                    forbidding = sorted(p for p in parents if any(
                        d["level"] == "forbid" for r in records.values() if r["key"] == p for d in r["unsafe"]["declared"]))
                    findings.add("unsafe-in-dependency", "review", k, key,
                                 "%d unsafe token(s) in its own source (%s); pulled in by %s%s" % (
                                     u["tokens"], ", ".join(u["files"]), ", ".join(parents) or "no linked crate",
                                     "; the forbid(unsafe_code) of %s does not cover this crate" % ", ".join(forbidding)
                                     if forbidding else ""))
                elif u["status"] == "unscanned":
                    findings.add("unsafe-unscanned", "review", k, key,
                                 "no source files could be read, so unsafe can be neither confirmed nor ruled out")
            b = rec["build_script"]
            native = []
            if rec["links"]:
                native.append("links = %r" % rec["links"])
            if b["link_directives"]:
                native.append("build script emits %s" % "/".join(b["link_directives"]))
            if b["native_tooling_deps"]:
                native.append("build-dependency on %s" % ", ".join(b["native_tooling_deps"]))
            if b["native_tooling_paths"]:
                native.append("build script uses %s" % ", ".join(b["native_tooling_paths"]))
            if native:
                findings.add("native-links" if rec["links"] else "native-build-signal", "review", k, key, "; ".join(native))
            elif b["present"]:
                findings.add("build-script", "info", k, key,
                             "build script present, no native signal found%s%s" % (
                                 "; spawns a process" if b["spawns_process"] else "",
                                 "; probes the compiler via %s" % ", ".join(b["compiler_probe_deps"])
                                 if b["compiler_probe_deps"] else ""))
            lic = rec["license"]["status"]
            if lic in ("missing", "file-missing"):
                findings.add("license-missing" if lic == "missing" else "license-file-missing", "review", k, key,
                             "no license expression or license file declared" if lic == "missing"
                             else "license-file %s does not exist" % rec["license"]["file"])
            if rec["uses_float"]:
                float_users.setdefault(key, {"workspace": [], "dependency": []})[
                    "workspace" if rec["source_kind"] == "workspace" else "dependency"].append(k)
            if st.get("effective_std") == "unknown":
                findings.add("std-mode-undecided", "review", k, key,
                             "std/no_std depends on something this audit cannot decide (%s)" % st["std_why"])
        # source / pin findings apply to anything resolved on any platform
    for pid, rec in records.items():
        roles = {st["role"] for st in rec["platforms"].values()}
        if not roles & {"member", "linked", "host-only"}:
            continue
        plats = sorted(k for k, st in rec["platforms"].items() if st["role"] != "absent")
        linked_here = [k for k in plats if rec["platforms"][k]["role"] in ("member", "linked")]
        pin = rec["pin"]
        for plat in plats:
            if rec["source_kind"] == "registry":
                if not pin["in_lock"]:
                    findings.add("lock-missing-entry", "blocker", rec["key"], plat, "resolved package has no Cargo.lock entry")
                elif not pin["checksum"]:
                    findings.add("lock-missing-checksum", "blocker", rec["key"], plat, "registry package has no checksum in Cargo.lock")
            elif rec["source_kind"] == "git":
                sha = _GIT_SHA.search(pin["source"] or "")
                if sha:
                    findings.add("git-pinned", "info", rec["key"], plat, "pinned to commit %s" % sha.group(1))
                else:
                    findings.add("unpinned-git", "blocker", rec["key"], plat, "git source without a 40-hex commit: %s" % pin["source"])
            elif rec["source_kind"] == "path-external" and plat in linked_here:
                findings.add("external-path-dependency", "blocker", rec["key"], plat,
                             "path dependency outside the workspace: its content is not pinned by Cargo.lock")
            elif rec["source_kind"] == "other":
                findings.add("unrecognized-source", "blocker", rec["key"], plat, "source %r" % pin["source"])
        for g in rec["gated_dependencies"]:
            findings.add("gated-dependency", "info", rec["key"], None,
                         "%s dependency %s gated by %s; active on %s" % (
                             g["kind"], g["dependency"], g["gate"],
                             ", ".join("%s=%s" % (k, {True: "yes", False: "no", None: "unknown"}[v])
                                       for k, v in g["active_on"].items())))
    # duplicates, per platform
    for key, g in graphs.items():
        by_name: Dict[str, List[str]] = {}
        for pid in g["nodes"]:
            by_name.setdefault(all_pkgs[pid]["name"], []).append(pid)
        for name, pids in sorted(by_name.items()):
            if len(pids) < 2:
                continue
            linked_versions = sorted(all_pkgs[p]["version"] for p in pids if p in g["linked"])
            versions = sorted(all_pkgs[p]["version"] for p in pids)
            if len(linked_versions) >= 2:
                findings.add("duplicate-version", "review", name, key, "linked at %s" % ", ".join(linked_versions))
            else:
                findings.add("duplicate-version-host", "info", name, key,
                             "versions %s; at most one is linked into the target" % ", ".join(versions))
    # floating point: one decision-level item per platform instead of one line per crate
    for key, users in sorted(float_users.items()):
        if key in REFERENCE_PLATFORMS:
            continue                    # the host is not firmware: its FPU says nothing about the boards
        fl = plat_report[key]["float"]
        listing = "workspace: %s; dependencies: %s" % (", ".join(sorted(users["workspace"])) or "none",
                                                       ", ".join(sorted(users["dependency"])) or "none")
        if fl == "soft-float":
            findings.add("float-on-soft-float", "review" if users["workspace"] else "info", None, key,
                         "%s is soft-float, so every f32/f64 operation below is software; the crates that use floats are %s; "
                         "a measured render budget decides whether that is acceptable" % (plat_report[key]["triple"], listing))
        elif fl:
            findings.add("float-usage", "info", None, key,
                         "%s: %s; crates using f32/f64: %s" % (plat_report[key]["triple"], fl, listing))
    # fp / atomics facts per platform
    for p in platforms:
        info = plat_report[p.key]
        if p.key in REFERENCE_PLATFORMS or p.outcome != "resolved":
            continue
        if not p.target_spec:
            findings.add("float-spec-unavailable", "info", None, p.key,
                         "the compiler's target spec for %s could not be captured, so its floating-point ISA is not established" % p.triple)
        if p.target_spec and info["float"] and info["float"] != "soft-float":
            findings.add("fp-isa-hardware-unknown", "info", None, p.key,
                         "%s: %s; whether the board's CPU has an FPU is not established by this repository" % (p.triple, info["float"]))
        if p.target_spec and p.target_spec.get("max-atomic-width", 64) < 64:
            findings.add("no-native-atomic64", "info", None, p.key,
                         "%s has max-atomic-width %s: classify each shared u64 by semantics (contract E03 section 4)"
                         % (p.triple, p.target_spec["max-atomic-width"]))

    # --- the lock entries that no platform graph links: inventoried from their verified cargo source, or a blocker
    resolved_keys = {(all_pkgs[pid]["name"], all_pkgs[pid]["version"], all_pkgs[pid].get("source")) for pid in in_graph}
    unused_lock = sorted("%s@%s" % (n, v) for (n, v, s) in lock if (n, v, s) not in resolved_keys)
    unlinked: List[Dict[str, Any]] = []
    if unused_lock and subject == "own" and reach is None and all(p.outcome == "resolved" for p in platforms):
        # An own, unscoped audit owes a record and a pin for EVERY locked registry entry. Without the lock-wide listing their sources cannot
        # be located, and that is a blocker for each of them, never a quiet pass over a report that lacks them. "Linked on no platform" is only
        # a claim once EVERY audited platform resolved: when one did not, the audit is already blocked for that and says no more about the lock.
        sources = locked if locked is not None else LockedSources("missing", None, "no lock-wide source listing was supplied to the audit")
        unused_keys = sorted((k for k in lock if k not in resolved_keys), key=lambda k: (k[0], k[1], k[2] or ""))
        unlinked, notes = inventory_unlinked(unused_keys, lock, sources, workspace_root, list(graphs),
                                             {r["key"] for r in records.values()})
        for kind, severity, package, detail in notes:
            findings.add(kind, severity, package, None, detail)

    # --- pins
    pins: Dict[str, Any] = {}
    for key, g in graphs.items():
        rows = []
        for pid in sorted(g["nodes"] if reach is None else reach[key], key=lambda i: names[i]):
            rec = records[pid]
            rows.append({"package": rec["key"], "source": rec["pin"]["source"] or rec["source_kind"],
                         "checksum": rec["pin"]["checksum"], "role": rec["platforms"][key]["role"],
                         "features": rec["platforms"][key]["features"]})
        if unlinked:
            # Locked here, resolved for no platform: a row of its own role, never one of the graph's roles.
            rows += [{"package": u["rec"]["key"], "source": u["rec"]["pin"]["source"], "checksum": u["rec"]["pin"]["checksum"],
                      "role": "unlinked", "features": []} for u in unlinked]
            rows.sort(key=lambda r: r["package"])
        pins[key] = {"rows": rows, "digest": _sha256(json.dumps(rows, sort_keys=True))}
    if unused_lock:
        findings.add("lock-unused-entries", "info", None, None,
                     "%d Cargo.lock entr%s not in %s: %s" % (
                         len(unused_lock), "y is" if len(unused_lock) == 1 else "ies are",
                         "any resolved platform graph" if reach is None else "the graph reachable from the scoped roots",
                         ", ".join(unused_lock[:8])))

    if lock_origin != "repository":
        findings.add("lock-generated-not-an-upstream-pin", "review", None, None,
                     "this revision has no Cargo.lock: the %d package versions below were generated offline from this "
                     "machine's registry cache (lock sha256 %s), not pinned by the repository, so a different machine or "
                     "date can resolve them differently" % (len(lock), _sha256(lock_text)[:16]))

    # --- candidates
    cand_report = []
    for c in (candidates if candidates is not None else CANDIDATES):
        # Present means in a platform's resolved graph with a role other than absent.  Where it is present matters:
        # linked into a big-endian target is the firmware's graph; a host-only (build-time) role is not linked; and the
        # host reference platform is the build machine.  A name that matches only on the host is not "in the graph".
        on: Dict[str, List[str]] = {}
        roles: Dict[str, Set[str]] = {}
        for rec in records.values():
            if rec["name"] not in c["match"]:
                continue
            for key, plat in rec["platforms"].items():
                role = plat.get("role")
                if role and role != "absent":
                    on.setdefault(key, []).append(rec["key"])
                    roles.setdefault(key, set()).add(role)
        found = sorted({pkg for pkgs in on.values() for pkg in pkgs})
        be_linked = sorted(k for k in on if k not in REFERENCE_PLATFORMS and roles[k] & {"member", "linked"})
        be_build_host = sorted(k for k in on if k not in REFERENCE_PLATFORMS and k not in be_linked)
        reference = sorted(k for k in on if k in REFERENCE_PLATFORMS)
        if be_linked:
            status = "linked into the firmware graph of: %s (see packages)" % ", ".join(be_linked)
        elif be_build_host:
            status = "present on %s only as a build-host dependency, not linked into the firmware" % ", ".join(be_build_host)
        elif reference:
            status = "present only on the reference platform (%s); absent from every big-endian target graph" % ", ".join(reference)
        else:
            status = "not in graph; unevaluated"
        cand_report.append({"name": c["name"], "category": c["category"], "in_graph": found,
                            "on_platforms": {k: sorted(v) for k, v in sorted(on.items())}, "status": status,
                            "evaluate_with": c["evaluate_with"]})
        if not found:
            if not c.get("informational"):
                findings.add("candidate-not-in-graph", "info", c["name"], None, "not in graph; unevaluated")
        elif be_linked:
            kind, severity = (("ffi-binding-table-linked", "review") if c.get("informational")
                              else ("candidate-in-graph", "info"))
            for key in be_linked:
                findings.add(kind, severity, c["name"], key, status + ": " + ", ".join(sorted(set(on[key]))))
        else:
            findings.add("candidate-not-linked-on-firmware", "info", c["name"], None, status)

    # --- build checks (supplied results; the analyzer never runs a build)
    declared_features: Dict[str, Set[str]] = {}
    for p in resolved:
        for pkg in (p.metadata or {}).get("packages", []):
            declared_features.setdefault(pkg["name"], set()).update(pkg.get("features", {}))
    plan = (build_plan(records, graphs, platforms, names, jobs, cargo_args=cargo_args, only=plan_crates,
                       declared_features=declared_features) if graphs else [])
    requested_features = [f for a in cargo_args if a not in ("--no-default-features", "--features") for f in a.split(",")]
    if requested_features and plan_crates is None and graphs:
        members = {records[m]["name"] for g in graphs.values() for m in g["members"]}
        left_out = sorted(members - {p["crate"] for p in plan})
        if left_out:
            findings.add("plan-narrowed-by-features", "info", None, None,
                         "not planned, because they do not declare %s: %s (name crates with --plan-crates to plan others)"
                         % (", ".join(requested_features), ", ".join(left_out)))
    checks = fold_build_results(plan, build_results, findings)

    # The unlinked entries join the package list last: every graph-derived pass above (roles, findings, the build plan,
    # the candidates) has already run over the graphs alone, so nothing in them can see an entry that is in no graph.
    for u in unlinked:
        records[u["pid"]] = u["rec"]
        names[u["pid"]] = u["rec"]["key"]

    flist = findings.all()
    counts = {s: sum(1 for f in flist if f["severity"] == s) for s in SEVERITIES}
    return {
        "schema": SCHEMA,
        "lock": {"sha256": _sha256(lock_text), "entries": len(lock), "origin": lock_origin},
        "platforms": plat_report,
        "packages": [records[pid] for pid in sorted(records, key=lambda i: names[i])],
        "pins": pins,
        "build_checks": checks,
        "candidates": cand_report,
        "policy_inputs": {"unsafe_allowed": sorted(allowed), "subject": subject, "cargo_args": list(cargo_args),
                          "scope_crates": None if scope_crates is None else sorted(scope_crates)},
        "findings": flist,
        "summary": {"counts": counts,
                    "linked": {k: sorted(records[p]["key"] for p in g["linked"]) for k, g in graphs.items()},
                    "host_only": {k: sorted(records[p]["key"] for p in g["host_only"]) for k, g in graphs.items()}},
    }


# ------------------------------------------------------------------------------------------------ build plan

def build_plan(records: Dict[str, Dict[str, Any]], graphs: Dict[str, Any], platforms: Sequence[PlatformInput],
               names: Dict[str, str], jobs: Optional[int] = None, cargo_args: Sequence[str] = (),
               only: Optional[Sequence[str]] = None,
               declared_features: Optional[Dict[str, Set[str]]] = None) -> List[Dict[str, Any]]:
    """One ``cargo check`` per workspace crate per big-endian target.  A crate whose every linked dependency
    is no_std gets the core+alloc set; anything else needs std.  Proposed, not proven: the first run decides."""
    triples = {p.key: p.triple for p in platforms}
    plan = []
    suffix = feature_suffix(cargo_args)
    wanted = [a for a in cargo_args if a not in ("--no-default-features", "--features")]
    requested = [f for arg in wanted for f in arg.split(",")]
    members = {records[m]["name"] for g in graphs.values() for m in g["members"] if records[m]["source_kind"] == "workspace"}
    if only is not None:
        unknown = sorted(set(only) - members)
        if unknown:
            raise ValueError("--plan-crates names no workspace crate: %s" % ", ".join(unknown))
    for key, g in sorted(graphs.items()):
        if key == "host":
            continue
        for mid in sorted(g["members"], key=lambda i: names[i]):
            rec = records[mid]
            if rec["source_kind"] != "workspace":
                continue
            if only is not None and rec["name"] not in only:
                continue
            missing = [f for f in requested if declared_features is not None and f not in declared_features.get(rec["name"], set())]
            if missing and only is None:
                continue                   # not asked for by name: left out, and the audit says so (see analyze)
            if missing:
                raise ValueError("%s does not declare feature(s) %s, so a planned check with them would not run; "
                                 "narrow the plan with --plan-crates" % (rec["name"], ", ".join(missing)))
            eff = rec["platforms"][key].get("effective_std", "unknown")
            std_set = "core,alloc" if eff == "no_std" else "std,panic_abort"
            plan.append({"crate": rec["name"], "target": triples[key], "platform": key, "effective_std": eff,
                         # RCH admits a build against a worker's slot count using its own core estimate (it ignores
                         # CARGO_BUILD_JOBS), so a job count has to be part of the command: see --jobs.
                         "command": "RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p %s%s "
                                    "--target %s -Z build-std=%s%s" % (rec["name"], suffix, triples[key], std_set,
                                                                       "" if jobs is None else " -j %d" % jobs)})
    return plan


def fold_build_results(plan: List[Dict[str, Any]], results: Optional[List[dict]], findings: _Findings) -> Dict[str, Any]:
    """Match supplied results to the plan.  An entry that is missing is ``not-run``, never ``pass``; two entries
    that disagree are ``conflicting``; an entry for something not in the plan is ``rejected``."""
    by_key: Dict[Tuple[str, str], List[dict]] = {}
    rejected: List[str] = []
    planned = {(p["crate"], p["target"]) for p in plan}
    for r in results or []:
        key = (str(r.get("crate")), str(r.get("target")))
        if key not in planned or r.get("status") not in ("pass", "fail"):
            rejected.append("%s/%s: %s" % (key[0], key[1], "not in the plan" if key not in planned else
                                           "status must be pass or fail"))
            continue
        by_key.setdefault(key, []).append(r)
    rows = []
    for p in plan:
        got = by_key.get((p["crate"], p["target"]), [])
        statuses = {g["status"] for g in got}
        status = "not-run" if not got else ("conflicting" if len(statuses) > 1 else next(iter(statuses)))
        rows.append({"crate": p["crate"], "target": p["target"], "status": status, "command": p["command"],
                     "evidence": got[-1].get("evidence") if got else None, "note": got[-1].get("note") if got else None})
        if status == "fail":
            findings.add("does-not-build", "blocker", p["crate"], p["platform"],
                         "cargo check for %s failed: %s" % (p["target"], (got[-1].get("note") or "see evidence")[:200]))
        elif status == "conflicting":
            findings.add("build-check-conflicting", "blocker", p["crate"], p["platform"], "pass and fail were both supplied")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("pass", "fail", "not-run", "conflicting")}
    if counts["not-run"]:
        findings.add("build-check-not-run", "info", None, None,
                     "%d of %d planned minimal-graph checks have no result" % (counts["not-run"], len(rows)))
    return {"planned": len(rows), "counts": counts, "rejected_results": rejected, "rows": rows}


# ------------------------------------------------------------------------------------------------ CLI

def generate_lock(manifest: str) -> Tuple[str, str]:
    """(outcome, detail).  Generate a Cargo.lock OFFLINE next to ``manifest`` when it has none.  This writes a file, so it
    refuses anything that is not a plain export: a directory with a ``.git`` entry is somebody's work tree, and a
    third-party repository is never edited."""
    root = os.path.dirname(os.path.abspath(manifest))
    if os.path.exists(os.path.join(root, ".git")):
        return "refused", "%s is a git work tree; export the revision first (git archive) and audit the export" % "the manifest directory"
    if os.path.exists(os.path.join(root, "Cargo.lock")):
        return "present", "a Cargo.lock is already there; it is used as it is"
    try:
        proc = subprocess.run(["cargo", "+nightly", "generate-lockfile", "--offline", "--manifest-path", manifest],
                              capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "failed", "%s: %s" % (type(exc).__name__, str(exc)[:160])
    if proc.returncode != 0:
        return "failed", scrub_paths(error_headline(proc.stderr), [root])
    return "generated", ""


def gather(manifest: str, targets: Dict[str, str], host: Optional[str],
           cargo_args: Sequence[str] = ()) -> Tuple[List[PlatformInput], str, str]:
    root = os.path.dirname(os.path.abspath(manifest))
    triples = dict(targets)
    triples["host"] = host or host_triple() or "host"
    platforms = PlatformList()
    for key, triple in sorted(triples.items()):
        outcome, meta, detail = run_cargo_metadata(manifest, triple, cargo_args=cargo_args)
        spec_outcome, spec = capture_target_spec(triple)
        platforms.append(PlatformInput(key, triple, outcome, detail, meta, spec, spec_outcome))
    if any(p.outcome == "resolved" for p in platforms):
        # The same resolver read with no platform filter: the only listing that locates a lock entry no platform links.
        outcome, meta, detail = run_cargo_metadata(manifest, None, cargo_args=cargo_args)
        platforms.locked = LockedSources(outcome, meta, detail)
    workspace_root = next((p.metadata["workspace_root"] for p in platforms if p.metadata), root)   # type: ignore[index]
    lock_path = os.path.join(workspace_root, "Cargo.lock")
    return platforms, _read(lock_path) or "", workspace_root


INVENTORY_SCHEMA = "ffw.e06.inventory.v1"
FINDING_DETAIL_LIMIT = 240


def inventory(report: Dict[str, Any], subject_name: str, subject_rev: str) -> Dict[str, Any]:
    """A compact, committable per-package record of one audit: exact revision, lock digest and origin, the feature
    selection, each platform's outcome, and for every package its pin, license, own-unsafe count, native signals and,
    per platform, its role, std mode and enabled features.  The full report keeps per-file detail (1.4 MB for a
    477-package graph); this keeps what a reader needs to decide, and the findings, with their details bounded."""
    rows = []
    for p in report["packages"]:
        rows.append({
            "name": p["name"], "version": p["version"], "key": p["key"], "source_kind": p["source_kind"],
            "source": p["pin"]["source"], "checksum": p["pin"]["checksum"], "in_lock": p["pin"]["in_lock"],
            "license": p["license"]["expression"] or p["license"]["file"], "license_status": p["license"]["status"],
            "unsafe_tokens": p["unsafe"]["tokens"], "unsafe_status": p["unsafe"]["status"],
            "unsafe_declared": [d["level"] + " via " + d["mechanism"] for d in p["unsafe"]["declared"]],
            "links": p["links"], "build_script": p["build_script"]["present"],
            "native_tooling": sorted(set(p["build_script"]["native_tooling_deps"])),
            "link_directives": len(p["build_script"]["link_directives"]), "references_alloc": p["references_alloc"],
            "uses_float": bool(p.get("uses_float")),
            **({"unlinked": True} if p.get("unlinked") else {}),        # locked, linked on no platform (see inventory_unlinked)
            "declared_features": p.get("declared_features"),
            # A package absent from a platform's graph has only {"role": "absent"}: no std mode, no features.
            "platforms": {k: {"role": v["role"], "std": v.get("std"), "effective_std": v.get("effective_std"),
                              "features": v.get("features")}
                          for k, v in sorted(p["platforms"].items())},
        })
    return {
        "schema": INVENTORY_SCHEMA, "subject": {"name": subject_name, "rev": subject_rev},
        "lock": report["lock"], "policy_inputs": report["policy_inputs"],
        "platforms": {k: {"triple": v["triple"], "outcome": v["outcome"], "float": v["float"]}
                      for k, v in sorted(report["platforms"].items())},
        "summary": report["summary"]["counts"], "candidates": [
            {"name": c["name"], "status": c["status"], "in_graph": c["in_graph"]} for c in report["candidates"]],
        "linked": report["summary"]["linked"], "host_only": report["summary"]["host_only"],
        "packages": rows,
        "findings": [{"kind": f["kind"], "severity": f["severity"], "package": f["package"], "platforms": f["platforms"],
                      "detail": f["detail"][:FINDING_DETAIL_LIMIT]} for f in report["findings"]],
        "build_checks": {"planned": report["build_checks"]["planned"], "counts": report["build_checks"]["counts"]},
    }


def render(report: Dict[str, Any]) -> str:
    out = ["E06 dependency audit  schema=%s  Cargo.lock sha256=%s (%d entries, %s)" % (
        report["schema"], report["lock"]["sha256"][:16], report["lock"]["entries"], report["lock"].get("origin", "repository"))]
    for key, p in sorted(report["platforms"].items()):
        out.append("  %-8s %-34s %s%s" % (key, p["triple"], p["outcome"], "  [%s]" % p["float"] if p["float"] else ""))
    c = report["summary"]["counts"]
    out.append("findings: %d blocker, %d review, %d info" % (c["blocker"], c["review"], c["info"]))
    for f in report["findings"]:
        if f["severity"] == "info":
            continue
        out.append("  %-8s %-26s %-28s %s" % (f["severity"].upper(), f["kind"], f["package"] or "-", f["detail"][:150]))
    bc = report["build_checks"]
    out.append("minimal-graph build checks: planned=%d %s" % (bc["planned"], " ".join(
        "%s=%d" % kv for kv in bc["counts"].items())))
    out.append("not admitted by this tool: it reports facts; a human decides each review item.")
    return "\n".join(out) + "\n"


def plan_lines(report: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(commands, refusals).  A plan is either complete or refused: an empty plan, or one built while any platform
    failed to resolve, is NOT a plan, and printing it quietly with exit 0 would let an empty or half-empty list stand
    for "nothing to check".  Each refusal states the platform and the cause."""
    refusals = []
    for key, p in sorted(report["platforms"].items()):
        if p["outcome"] != "resolved":
            hint = (" (Cargo.lock does not match the manifests in this tree: plan from a clean export, or regenerate "
                    "the lock first)" if "lock file" in p["detail"] else "")
            refusals.append("%s (%s) is %s: %s%s" % (key, p["triple"], p["outcome"], p["detail"] or "no detail", hint))
    lines = [row["command"] for row in report["build_checks"]["rows"]]
    if not refusals and not lines:
        refusals.append("the plan is empty: no workspace crate was found in the resolved graph, so there is nothing to check")
    return ([] if refusals else lines), refusals


def exit_code(report: Dict[str, Any]) -> int:
    c = report["summary"]["counts"]
    return 1 if c["blocker"] else (3 if c["review"] else 0)


def _parse_targets(values: Sequence[str]) -> Dict[str, str]:
    if not values:
        return dict(DEFAULT_TARGETS)
    out = {}
    for v in values:
        key, _, triple = v.partition("=")
        if not key or not triple:
            raise ValueError("--target needs KEY=TRIPLE, got %r" % v)
        out[key] = triple
    return out


def run_ingest(args: argparse.Namespace) -> int:
    """Verify centrally produced ``cargo check`` results against their raw logs and write the redacted record.
    Nothing is written unless every claim is supported: a partial record would read as a complete one."""
    if os.path.exists(args.out):
        print("audit.py ingest: %s already exists; records are never overwritten" % args.out, file=sys.stderr)
        return 2
    plan_text, results_text = _read(args.plan_file), _read(args.results)
    if plan_text is None or results_text is None:
        print("audit.py ingest: cannot read the plan file or the results file", file=sys.stderr)
        return 2
    if args.rev is not None and not re.fullmatch(r"[0-9a-f]{40}", args.rev):
        print("audit.py ingest: --rev must be a 40-hex commit", file=sys.stderr)
        return 2
    try:
        results = [json.loads(line) for line in results_text.splitlines() if line.strip()]
    except ValueError as exc:
        print("audit.py ingest: the results are not JSON lines: %s" % exc, file=sys.stderr)
        return 2
    plan, problems = checks.parse_plan(plan_text.splitlines())
    records: List[Dict[str, Any]] = []
    if not problems:
        records, problems = checks.verify(plan, results, args.logs_dir, args.rev)
    sys.stdout.write(checks.render(records, problems))
    if problems:
        return 1
    try:
        checks.write_records(args.out, records)
    except OSError as exc:
        print("audit.py ingest: cannot write %s: %s" % (args.out, exc.__class__.__name__), file=sys.stderr)
        return 2
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="E06 dependency, feature and target audit (offline, resolver reads only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="verify central cargo-check results against their raw logs; write a redacted record")
    ing.add_argument("--plan-file", required=True, help="the planned cargo-check lines (audit.py plan output)")
    ing.add_argument("--results", required=True, help="JSON lines: crate, target, status, evidence, note")
    ing.add_argument("--logs-dir", required=True, help="where the raw per-check logs the rows name are")
    ing.add_argument("--rev", default=None, help="the 40-hex revision the checks ran against")
    ing.add_argument("--out", required=True, help="the redacted record (a new file)")
    for name in ("audit", "plan"):
        s = sub.add_parser(name)
        if name == "audit":
            s.add_argument("--inventory", default=None, metavar="OUT",
                           help="write the compact per-package inventory here (a new file); needs --subject-name/--subject-rev")
            s.add_argument("--subject-name", default=None, help="the repository or crate audited (recorded in the inventory)")
            s.add_argument("--subject-rev", default=None, help="the 40-hex revision audited (recorded in the inventory)")
        s.add_argument("--manifest-path", default=os.path.join(os.path.dirname(os.path.dirname(HERE)), "Cargo.toml"))
        s.add_argument("--target", action="append", default=[], metavar="KEY=TRIPLE",
                       help="big-endian targets to audit (default mips and powerpc musl); the host is always added")
        s.add_argument("--host-triple", default=None)
        s.add_argument("--unsafe-allowed", default=",".join(DEFAULT_UNSAFE_ALLOWED),
                       help="workspace crates permitted to contain unsafe (a policy input)")
        s.add_argument("--build-results", default=None, help="JSON lines: crate, target, status pass|fail, evidence, note")
        s.add_argument("--jobs", type=int, default=None, metavar="N",
                       help="append -j N to every planned cargo check (RCH admits against a worker's slot count)")
        s.add_argument("--json", default=None, metavar="OUT", help="write the full report here (a new file)")
        s.add_argument("--features", default=None, metavar="LIST", help="cargo features to activate (comma-separated)")
        s.add_argument("--no-default-features", action="store_true", help="do not activate default features")
        s.add_argument("--plan-crates", default=None, metavar="LIST",
                       help="plan only these workspace crates (comma-separated); each must declare every --features name")
        s.add_argument("--scope-crates", default=None, metavar="LIST",
                       help="treat only these workspace crates as the roots of the graph (comma-separated); default: every member")
        s.add_argument("--subject", choices=("own", "upstream"), default="own",
                       help="own: this workspace, held to its P01 unsafe rule; upstream: a third party's pinned revision "
                            "audited read-only (its unsafe is reviewed, not a violation)")
        s.add_argument("--generate-lock", action="store_true",
                       help="when the manifest's directory has no Cargo.lock, generate one OFFLINE there (refused inside a "
                            "git work tree: audit an export); the report says the lock is not an upstream pin")
    args = ap.parse_args(argv)
    if args.cmd == "ingest":
        return run_ingest(args)
    try:
        targets = _parse_targets(args.target)
    except ValueError as exc:
        print("audit.py: %s" % exc, file=sys.stderr)
        return 2
    if args.jobs is not None and not 1 <= args.jobs <= 256:
        print("audit.py: --jobs must be between 1 and 256", file=sys.stderr)
        return 2
    try:
        cargo_args = feature_args(args.no_default_features, args.features)
    except ValueError as exc:
        print("audit.py: %s" % exc, file=sys.stderr)
        return 2
    if getattr(args, "inventory", None) and (not args.subject_name or not re.fullmatch(r"[0-9a-f]{40}", args.subject_rev or "")):
        print("audit.py: --inventory needs --subject-name and a 40-hex --subject-rev", file=sys.stderr)
        return 2
    if getattr(args, "inventory", None) and os.path.exists(args.inventory):
        print("audit.py: %s already exists; inventories are never overwritten" % args.inventory, file=sys.stderr)
        return 2
    if getattr(args, "json", None) and os.path.exists(args.json):
        print("audit.py: %s already exists; reports are never overwritten" % args.json, file=sys.stderr)
        return 2
    results = None
    if args.build_results:
        text = _read(args.build_results)
        if text is None:
            print("audit.py: cannot read %s" % args.build_results, file=sys.stderr)
            return 2
        try:
            results = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError as exc:
            print("audit.py: build results are not JSON lines: %s" % exc, file=sys.stderr)
            return 2
    lock_origin = "repository"
    if args.generate_lock:
        outcome, detail = generate_lock(args.manifest_path)
        if outcome in ("refused", "failed"):
            print("audit.py: --generate-lock %s: %s" % (outcome, detail), file=sys.stderr)
            return 2
        if outcome == "generated":
            lock_origin = "generated-offline"
    plan_crates = [c for c in args.plan_crates.split(",") if c] if args.plan_crates else None
    scope_crates = [c for c in args.scope_crates.split(",") if c] if args.scope_crates else None
    platforms, lock_text, workspace_root = gather(args.manifest_path, targets, args.host_triple, cargo_args)
    try:
        report = analyze(platforms, lock_text, workspace_root, [s for s in args.unsafe_allowed.split(",") if s], results,
                         jobs=args.jobs, subject=args.subject, cargo_args=cargo_args, lock_origin=lock_origin,
                         plan_crates=plan_crates, scope_crates=scope_crates)
    except ValueError as exc:
        print("audit.py: %s" % exc, file=sys.stderr)
        return 2
    if args.cmd == "plan":
        lines, refusals = plan_lines(report)
        if refusals:
            for why in refusals:
                print("audit.py plan: %s" % why, file=sys.stderr)
            return 1                       # nothing on stdout: a half plan piped into a runner looks complete
        for line in lines:
            print(line)
        return 0
    if args.json:
        try:
            with open(args.json, "x", encoding="utf-8") as fh:
                json.dump(report, fh, indent=1, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            print("audit.py: cannot write %s: %s" % (args.json, exc.__class__.__name__), file=sys.stderr)
            return 2
    if getattr(args, "inventory", None):
        try:
            with open(args.inventory, "x", encoding="utf-8") as fh:
                json.dump(inventory(report, args.subject_name, args.subject_rev), fh, indent=1, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            print("audit.py: cannot write %s: %s" % (args.inventory, exc.__class__.__name__), file=sys.stderr)
            return 2
    sys.stdout.write(render(report))
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
