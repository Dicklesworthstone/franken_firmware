"""Independent reference for the P01 build/target/profile contract (bead ffw-h3g).

This re-implements, from the rules in docs/contracts/p01.md, what the Rust module
crates/franken-board-profile/src/build_contract.rs enforces. It is not generated from the Rust and
shares no code with it; the two meet only in the stable error codes below and in the shared vectors
(crates/franken-board-profile/tests/vectors/p01_contract_vectors.json), whose expected values are written by
hand. One author wrote both, so agreement is a cross-check and not a second author.

Stdlib only. Nothing here builds, boots or reads a network.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCHEMA_VERSION = "ffw.build_contract.v1"

# target -> (triple, isa label, ELF e_machine, is_device)
TARGETS: Dict[str, Tuple[str, str, int, bool]] = {
    "host": ("host", "", 0, False),
    "mips_be": ("mips-unknown-linux-musl", "mips32_be", 8, True),
    "powerpc_be": ("powerpc-unknown-linux-musl", "powerpc32_be", 20, True),
}

ENUMS: Dict[str, Set[str]] = {
    "target": set(TARGETS),
    "role": {"library", "platform", "application", "test_support", "host_tool"},
    "unsafe": {"forbid", "deny_with_scoped_allow", "bootstrap_probe"},
    "asset_kind": {"crate", "interface", "fixture"},
    "feature_kind": {"core", "native_service"},
    "requirement": {"required", "optional"},
    "evidence": {"host_simulation", "guest_execution", "real_service", "physical_output"},
    "state": {"enabled", "disabled"},
    "scope": {"full_product", "named_narrow"},
    "status": {"unqualified", "qualified"},
    "float_abi": {"soft", "hard"},
}

# Field grammar: "str" | "u32" | "bool" | ("enum", name) | ("list", spec) | ("obj", {field: spec}).
_EVIDENCE_BINDING = ("obj", {
    "kind": ("enum", "evidence"), "artifact_sha256": "str", "target": ("enum", "target"),
    "profile": "str", "receipt_id": "str",
})
CONTRACT_SPEC = ("obj", {
    "schema_version": "str",
    "cargo_profiles": ("list", ("obj", {
        "name": "str", "opt_level": "str", "lto": "str", "codegen_units": "u32", "panic": "str",
        "strip": "str"})),
    "crates": ("list", ("obj", {
        "name": "str", "path": "str", "owner": "str", "role": ("enum", "role"), "layer": "u32",
        "unsafe_policy": ("enum", "unsafe"), "deps": ("list", "str"),
        "optional_deps": ("list", ("obj", {"dep": "str", "feature": "str"})),
        "dev_deps": ("list", "str")})),
    "excluded": ("list", ("obj", {
        "name": "str", "path": "str", "owner": "str", "reason": "str",
        "unsafe_policy": ("enum", "unsafe"), "targets": ("list", ("enum", "target"))})),
    "pending_members": ("list", ("obj", {"name": "str", "path": "str", "owner": "str", "reason": "str"})),
    "assets": ("list", ("obj", {"path": "str", "owner": "str", "kind": ("enum", "asset_kind")})),
    "test_support_exceptions": ("list", ("obj", {"from": "str", "to": "str", "reason": "str"})),
    "unsafe_exceptions": ("list", ("obj", {"from": "str", "to": "str", "reason": "str"})),
    "features": ("list", ("obj", {
        "name": "str", "kind": ("enum", "feature_kind"), "requirement": ("enum", "requirement"),
        "owner_crate": "str", "cargo_feature": "str", "requires": ("list", "str"),
        "accepted_evidence": ("list", ("enum", "evidence"))})),
    "profiles": ("list", ("obj", {
        "name": "str", "cargo_profile": "str", "scope": ("enum", "scope"), "narrow_reason": "str",
        "features": ("list", ("obj", {"feature": "str", "state": ("enum", "state"),
                                      "disabled_reason": "str"}))})),
    "linkers": ("list", ("obj", {
        "target": ("enum", "target"), "crates": ("list", "str"), "wrapper": "str", "wrapper_sha256": "str",
        "zig_version": "str", "zig_target": "str", "isa_revision": "str", "float_abi": ("enum", "float_abi"),
        "abi_measured": "bool"})),
    "artifacts": ("list", ("obj", {
        "id": "str", "crate": "str", "bin": "str", "target": ("enum", "target"), "triple": "str",
        "isa": "str", "profile": "str", "runs_on": ("list", ("enum", "target")),
        "status": ("enum", "status"), "sha256": "str",
        "qualifications": ("list", ("obj", {"feature": "str", "evidence": _EVIDENCE_BINDING}))})),
})
OBSERVED_SPEC = ("list", ("obj", {
    "id": "str", "target": ("enum", "target"), "triple": "str", "profile": "str", "sha256": "str",
    "elf_machine": "u32", "elf_class": "u32", "elf_big_endian": "bool", "contract_digest": "str",
    "elf_dynamic": "bool", "isa_revision": "str", "fp_abi": "str"}))


class ParseError(Exception):
    """A document that does not fit the schema: unknown or missing field, wrong type or enum value."""


def _shape(value: Any, spec: Any, where: str) -> None:
    if spec == "str":
        if not isinstance(value, str):
            raise ParseError(f"{where}: expected a string")
    elif spec == "u32":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2 ** 32:
            raise ParseError(f"{where}: expected a u32")
    elif spec == "bool":
        if not isinstance(value, bool):
            raise ParseError(f"{where}: expected a bool")
    elif spec[0] == "enum":
        if not isinstance(value, str) or value not in ENUMS[spec[1]]:
            raise ParseError(f"{where}: {value!r} is not a {spec[1]}")
    elif spec[0] == "list":
        if not isinstance(value, list):
            raise ParseError(f"{where}: expected a list")
        for index, item in enumerate(value):
            _shape(item, spec[1], f"{where}[{index}]")
    elif spec[0] == "obj":
        if not isinstance(value, dict):
            raise ParseError(f"{where}: expected an object")
        fields = spec[1]
        extra = sorted(set(value) - set(fields))
        missing = sorted(set(fields) - set(value))
        if extra:
            raise ParseError(f"{where}: unknown field(s) {extra}")
        if missing:
            raise ParseError(f"{where}: missing field(s) {missing}")
        for key, sub in fields.items():
            _shape(value[key], sub, f"{where}.{key}")
    else:  # pragma: no cover - a bug in this table, not in a document
        raise AssertionError(spec)


def parse_contract(doc: Any) -> Dict[str, Any]:
    _shape(doc, CONTRACT_SPEC, "contract")
    return doc


def parse_observed(rows: Any) -> List[Dict[str, Any]]:
    _shape(rows, OBSERVED_SPEC, "observed")
    return rows


# ------------------------------------------------------------------------------ canonical form

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(doc: Any) -> str:
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()


def is_hex64(text: str) -> bool:
    return len(text) == 64 and all(c in "0123456789abcdef" for c in text)


# ------------------------------------------------------------------------------ graph helpers

Graph = Dict[str, Set[str]]


def _reach(graph: Graph) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for start, first in graph.items():
        seen: Set[str] = set()
        stack = list(first)
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(graph.get(node, ()))
        out[start] = seen
    return out


def cycles(graph: Graph) -> Set[Tuple[str, ...]]:
    """Mutually reachable groups of two or more nodes. A self-loop is not a cycle (own code)."""
    reach = _reach(graph)
    found: Set[Tuple[str, ...]] = set()
    for node, from_node in reach.items():
        group = [o for o in from_node if o != node and node in reach.get(o, ())]
        if group:
            found.add(tuple(sorted(group + [node])))
    return found


def closure(graph: Graph, start: str) -> Set[str]:
    seen: Set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(graph.get(node, ()))
    return seen


Pair = Tuple[str, str]


def _binding_matches(art: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    return (art["sha256"] != "" and ev["artifact_sha256"] == art["sha256"]
            and ev["target"] == art["target"] and ev["profile"] == art["profile"])


# ------------------------------------------------------------------------------ validation

def validate(doc: Dict[str, Any]) -> List[Pair]:
    """All violations of a parsed contract as sorted, unique (code, subject) pairs."""
    errs: Set[Pair] = set()
    members = {c["name"]: c for c in doc["crates"]}
    features = {f["name"]: f for f in doc["features"]}
    profiles = {p["name"]: p for p in doc["profiles"]}
    cargo_profiles = {p["name"]: p for p in doc["cargo_profiles"]}
    excluded = {e["name"]: e for e in doc["excluded"]}

    if doc["schema_version"] != SCHEMA_VERSION:
        errs.add(("schema_version_mismatch", "contract"))

    # --- names that must be unique
    seen: Set[str] = set()
    for name in ([c["name"] for c in doc["crates"]] + [e["name"] for e in doc["excluded"]]
                 + [p["name"] for p in doc["pending_members"]]):
        if name in seen:
            errs.add(("duplicate_crate", name))
        seen.add(name)
    for key, code in (("cargo_profiles", "duplicate_cargo_profile"), ("features", "duplicate_feature"),
                      ("profiles", "duplicate_profile")):
        seen = set()
        for item in doc[key]:
            if item["name"] in seen:
                errs.add((code, item["name"]))
            seen.add(item["name"])
    ids: Set[str] = set()
    idents: Set[Tuple[str, str, str]] = set()
    for art in doc["artifacts"]:
        if art["id"] in ids:
            errs.add(("duplicate_artifact", art["id"]))
        ids.add(art["id"])
        ident = (art["crate"], art["target"], art["profile"])
        if ident in idents:
            errs.add(("duplicate_artifact", "/".join(ident)))
        idents.add(ident)

    # --- the crate graph
    normal: Graph = {c["name"]: set() for c in doc["crates"]}
    union: Graph = {c["name"]: set() for c in doc["crates"]}
    for c in doc["crates"]:
        for dep, is_dev in ([(d, False) for d in c["deps"]] + [(o["dep"], False) for o in c["optional_deps"]]
                            + [(d, True) for d in c["dev_deps"]]):
            edge = f"{c['name']}->{dep}"
            if dep == c["name"]:
                errs.add(("self_dependency", c["name"]))
                continue
            if dep not in members:
                errs.add(("unknown_dependency", edge))
                continue
            union[c["name"]].add(dep)
            if not is_dev:
                normal[c["name"]].add(dep)
                if members[dep]["layer"] >= c["layer"]:
                    errs.add(("layer_violation", edge))
    normal_cycles = cycles(normal)
    for comp in normal_cycles:
        errs.add(("dependency_cycle", ",".join(comp)))
    for comp in cycles(union):
        if comp not in normal_cycles:
            errs.add(("dev_dependency_cycle", ",".join(comp)))

    # --- ownership: one owner per crate, interface and fixture
    by_path: Dict[str, List[Dict[str, Any]]] = {}
    for asset in doc["assets"]:
        by_path.setdefault(asset["path"], []).append(asset)
        if asset["owner"].strip() == "":
            errs.add(("owner_missing", asset["path"]))
    for path, group in by_path.items():
        if len(group) > 1:
            code = "asset_conflicting_owners" if len({a["owner"] for a in group}) > 1 else "asset_duplicate"
            errs.add((code, path))
    for rec in list(doc["crates"]) + list(doc["excluded"]) + list(doc["pending_members"]):
        if rec["owner"].strip() == "":
            errs.add(("owner_missing", rec["name"]))
        group = by_path.get(rec["path"])
        if not group:
            errs.add(("asset_unowned", rec["name"]))
        elif group[0]["owner"] != rec["owner"] or group[0]["kind"] != "crate":
            errs.add(("asset_owner_mismatch", rec["name"]))

    # --- unsafe policy
    for c in doc["crates"]:
        ok = (c["unsafe_policy"] == "forbid"
              or (c["unsafe_policy"] == "deny_with_scoped_allow" and c["role"] in ("host_tool", "test_support", "platform")))
        if not ok:
            errs.add(("unsafe_policy_not_permitted", c["name"]))
    for e in doc["excluded"]:
        if e["unsafe_policy"] != "bootstrap_probe":
            errs.add(("unsafe_policy_not_permitted", e["name"]))

    # --- the feature registry
    fgraph: Graph = {}
    for f in doc["features"]:
        fgraph.setdefault(f["name"], set())
        if f["owner_crate"] not in members:
            errs.add(("feature_owner_unknown", f["name"]))
        if not f["accepted_evidence"]:
            errs.add(("evidence_policy_empty", f["name"]))
        for req in f["requires"]:
            edge = f"{f['name']}->{req}"
            if req == f["name"]:
                errs.add(("feature_cycle", f["name"]))
                continue
            other = features.get(req)
            if other is None:
                errs.add(("unknown_feature", edge))
                continue
            fgraph[f["name"]].add(req)
            if f["kind"] == "native_service" and other["kind"] == "native_service":
                errs.add(("native_feature_requires_native", edge))
            elif f["kind"] == "core" and other["kind"] == "native_service":
                errs.add(("core_feature_requires_native", edge))
    for comp in cycles(fgraph):
        errs.add(("feature_cycle", ",".join(comp)))

    # --- an optional dependency is gated by a feature with a real Cargo flag that its own crate owns
    for c in doc["crates"]:
        for opt in c["optional_deps"]:
            subject = f"{c['name']}->{opt['dep']}"
            gate = features.get(opt["feature"])
            if gate is None:
                errs.add(("unknown_feature", subject))
                continue
            if gate["cargo_feature"] == "":
                errs.add(("optional_dep_without_flag", subject))
            if gate["owner_crate"] != c["name"]:
                errs.add(("optional_dep_wrong_owner", subject))

    # --- build profiles select features
    for p in doc["profiles"]:
        if p["cargo_profile"] not in cargo_profiles:
            errs.add(("unknown_cargo_profile", p["name"]))
        if p["scope"] == "named_narrow" and p["narrow_reason"].strip() == "":
            errs.add(("narrow_profile_without_reason", p["name"]))
        selected: Set[str] = set()
        for sel in p["features"]:
            subject = f"{p['name']}:{sel['feature']}"
            spec = features.get(sel["feature"])
            if spec is None:
                errs.add(("unknown_feature", subject))
                continue
            if sel["feature"] in selected:
                errs.add(("duplicate_feature_selection", subject))
            selected.add(sel["feature"])
            if sel["state"] == "disabled":
                if sel["disabled_reason"].strip() == "":
                    errs.add(("disabled_without_reason", subject))
                if spec["requirement"] == "required" and p["scope"] == "full_product":
                    errs.add(("full_profile_disables_required", subject))
        for f in doc["features"]:
            if f["requirement"] == "required" and f["name"] not in selected:
                errs.add(("required_feature_missing", f"{p['name']}:{f['name']}"))

    # --- linkers: the wrapper that links a device artifact, and the ABI the linked file must show
    covered: Set[str] = set()
    for ln in doc["linkers"]:
        parts = ln["wrapper"].split("/")
        if (not TARGETS[ln["target"]][3] or not ln["crates"] or ln["wrapper"] == "" or ln["wrapper"].startswith("/")
                or "\\" in ln["wrapper"] or ".." in parts or "" in parts or not is_hex64(ln["wrapper_sha256"])
                or any(ln[key].strip() == "" for key in ("zig_version", "zig_target", "isa_revision"))):
            errs.add(("linker_malformed", ln["target"]))
        for crate in ln["crates"]:
            key = f"{ln['target']}:{crate}"
            if crate not in members:
                errs.add(("linker_unknown_crate", key))
            if key in covered:
                errs.add(("linker_duplicate", key))
            covered.add(key)
    for art in doc["artifacts"]:
        if TARGETS[art["target"]][3] and art["crate"] in members and f"{art['target']}:{art['crate']}" not in covered:
            errs.add(("device_artifact_without_linker", art["id"]))

    # --- artifacts
    for art in doc["artifacts"]:
        aid = art["id"]
        triple, isa, _machine, is_device = TARGETS[art["target"]]
        if art["crate"] in excluded:
            if art["target"] not in excluded[art["crate"]]["targets"]:
                errs.add(("artifact_target_not_declared", aid))
        elif art["crate"] not in members:
            errs.add(("unknown_artifact_crate", aid))
        if art["runs_on"] != [art["target"]]:
            errs.add(("universal_artifact_claim", aid))
        if art["triple"] != triple:
            errs.add(("triple_target_mismatch", aid))
        if art["isa"] != isa:
            errs.add(("isa_target_mismatch", aid))
        if art["sha256"] != "" and not is_hex64(art["sha256"]):
            errs.add(("bad_digest", aid))
        profile = profiles.get(art["profile"])
        if profile is None:
            errs.add(("unknown_profile", aid))
            continue
        cargo = cargo_profiles.get(profile["cargo_profile"])
        if is_device and cargo is not None and cargo["panic"] != "abort":
            errs.add(("device_profile_not_abort", aid))
        for q in art["qualifications"]:
            subject = f"{aid}:{q['feature']}"
            spec = features.get(q["feature"])
            if spec is None:
                errs.add(("unknown_feature", subject))
                continue
            if not any(s["feature"] == q["feature"] and s["state"] == "enabled" for s in profile["features"]):
                errs.add(("qualified_while_disabled", subject))
            if q["evidence"]["kind"] not in spec["accepted_evidence"]:
                errs.add(("evidence_kind_insufficient", subject))
            if q["evidence"]["receipt_id"].strip() == "":
                errs.add(("evidence_receipt_missing", subject))
            if not _binding_matches(art, q["evidence"]):
                errs.add(("stale_evidence", subject))
        if art["status"] == "qualified":
            adm = admission(doc, aid)
            if adm is not None and not adm["qualified"]:
                errs.add(("qualification_not_supported", aid))

    # --- test-only and host-only crates stay out of device artifacts
    for exc in doc["test_support_exceptions"]:
        subject = f"{exc['from']}->{exc['to']}"
        is_edge = exc["to"] in normal.get(exc["from"], ())
        to_ok = exc["to"] in members and members[exc["to"]]["role"] == "test_support"
        if not is_edge or not to_ok:
            errs.add(("stale_exception", subject))
        if exc["reason"].strip() == "":
            errs.add(("exception_without_reason", subject))
    for exc in doc["unsafe_exceptions"]:
        subject = f"{exc['from']}->{exc['to']}"
        is_edge = exc["to"] in normal.get(exc["from"], ())
        to_ok = exc["to"] in members and members[exc["to"]]["unsafe_policy"] == "deny_with_scoped_allow"
        if not is_edge or not to_ok:
            errs.add(("stale_unsafe_exception", subject))
        if exc["reason"].strip() == "":
            errs.add(("unsafe_exception_without_reason", subject))
    for art in doc["artifacts"]:
        if not TARGETS[art["target"]][3] or art["crate"] not in members:
            continue
        active = active_graph(doc, art, members)
        reach = closure(active, art["crate"])
        for member in reach:
            spec = members[member]
            subject = f"{art['id']}:{member}"
            # Every edge into the crate that this artifact's build activates must be listed: one listed edge does not
            # excuse a second, unlisted one, and the artifact's own crate (no incoming edge) is never excused.
            incoming = {f for f in reach if member in active.get(f, ())}
            if spec["role"] == "test_support":
                listed = {e["from"] for e in doc["test_support_exceptions"] if e["to"] == member}
                if not incoming or not incoming <= listed:
                    errs.add(("test_support_in_device_closure", subject))
            if spec["role"] == "host_tool":
                errs.add(("host_tool_in_device_closure", subject))
            if spec["unsafe_policy"] == "deny_with_scoped_allow":
                listed = {e["from"] for e in doc["unsafe_exceptions"] if e["to"] == member}
                if not incoming or not incoming <= listed:
                    errs.add(("unsafe_in_device_closure", subject))
    return sorted(errs)


def active_graph(doc: Dict[str, Any], art: Dict[str, Any], members: Dict[str, Any]) -> Graph:
    """The normal edges live in one artifact's build: every plain dependency, and an optional one only when the
    artifact's profile enables the feature that activates it."""
    profile = next((p for p in doc["profiles"] if p["name"] == art["profile"]), None)
    enabled = {s["feature"] for s in profile["features"] if s["state"] == "enabled"} if profile else set()
    graph: Graph = {c["name"]: set() for c in doc["crates"]}
    for c in doc["crates"]:
        for dep in c["deps"]:
            if dep != c["name"] and dep in members:
                graph[c["name"]].add(dep)
        for opt in c["optional_deps"]:
            if opt["dep"] != c["name"] and opt["dep"] in members and opt["feature"] in enabled:
                graph[c["name"]].add(opt["dep"])
    return graph


def codes(pairs: Iterable[Pair]) -> List[str]:
    return sorted({code for code, _ in pairs})


def subjects(pairs: Iterable[Pair]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for code, subject in pairs:
        out.setdefault(code, []).append(subject)
    return {code: sorted(vals) for code, vals in sorted(out.items())}


# ------------------------------------------------------------------------------ admission

def admission(doc: Dict[str, Any], artifact_id: str) -> Optional[Dict[str, Any]]:
    """The computed qualification of an artifact. There is no other route to 'qualified'."""
    art = next((a for a in doc["artifacts"] if a["id"] == artifact_id), None)
    if art is None:
        return None
    profile = next((p for p in doc["profiles"] if p["name"] == art["profile"]), None)
    blocks: List[str] = []
    for spec in doc["features"]:
        if spec["requirement"] != "required":
            continue
        name = spec["name"]
        sel = None
        if profile is not None:
            sel = next((s for s in profile["features"] if s["feature"] == name), None)
        if sel is None:
            blocks.append(f"required_feature_missing:{name}")
            continue
        if sel["state"] == "disabled":
            blocks.append(f"required_feature_disabled:{name}")
            continue
        qual = next((q for q in art["qualifications"] if q["feature"] == name), None)
        if qual is None:
            blocks.append(f"required_feature_unqualified:{name}")
        elif qual["evidence"]["kind"] not in spec["accepted_evidence"]:
            blocks.append(f"evidence_kind_insufficient:{name}")
        elif not _binding_matches(art, qual["evidence"]):
            blocks.append(f"stale_evidence:{name}")
    blocks.sort()
    return {"artifact": artifact_id, "qualified": not blocks, "blocks": blocks}


# ------------------------------------------------------------------------------ observed identity

def linker_for(doc: Dict[str, Any], art: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The declared linker that covers a device artifact's crate and target, if any (the bootstrap probe has none)."""
    for ln in doc["linkers"]:
        if ln["target"] == art["target"] and art["crate"] in ln["crates"]:
            return ln
    return None


def verify_observed(doc: Dict[str, Any], observed: Sequence[Dict[str, Any]], require_all: bool = False) -> List[Pair]:
    errs: Set[Pair] = set()
    want = digest(doc)
    declared = {a["id"]: a for a in doc["artifacts"]}
    digests_by_id: Dict[str, Set[str]] = {}
    targets_by_digest: Dict[str, Set[str]] = {}
    for row in observed:
        rid = row["id"]
        if row["contract_digest"] != want:
            errs.add(("contract_digest_mismatch", rid))
        if not is_hex64(row["sha256"]):
            errs.add(("bad_digest", rid))
        digests_by_id.setdefault(rid, set()).add(row["sha256"])
        targets_by_digest.setdefault(row["sha256"], set()).add(row["target"])
        spec = declared.get(rid)
        if spec is None:
            errs.add(("unknown_artifact", rid))
            continue
        if row["target"] != spec["target"]:
            errs.add(("observed_target_mismatch", rid))
        if row["triple"] != spec["triple"]:
            errs.add(("triple_target_mismatch", rid))
        if row["profile"] != spec["profile"]:
            errs.add(("observed_profile_mismatch", rid))
        if spec["sha256"] != "" and spec["sha256"] != row["sha256"]:
            errs.add(("observed_digest_mismatch", rid))
        _triple, _isa, machine, is_device = TARGETS[spec["target"]]
        if is_device:
            if row["elf_machine"] != machine:
                errs.add(("elf_machine_mismatch", rid))
            if row["elf_class"] != 1 or not row["elf_big_endian"]:
                errs.add(("elf_not_32bit_big_endian", rid))
            ln = linker_for(doc, spec)
            if ln is not None:
                if row["elf_dynamic"]:
                    errs.add(("artifact_not_static", rid))
                # A declaration the ELF can show (MIPS .MIPS.abiflags) must be matched by the file; one it cannot show
                # (PowerPC has no marker) is not checked, but a marker that IS present must still agree.
                if row["isa_revision"] != ln["isa_revision"] and (ln["abi_measured"] or row["isa_revision"] != ""):
                    errs.add(("isa_revision_mismatch", rid))
                if row["fp_abi"] != ln["float_abi"] and (ln["abi_measured"] or row["fp_abi"] != ""):
                    errs.add(("float_abi_mismatch", rid))
    for rid, shas in digests_by_id.items():
        if len(shas) > 1:
            errs.add(("artifact_digest_conflict", rid))
    for sha, tgts in targets_by_digest.items():
        if len(tgts) > 1:
            errs.add(("universal_artifact_claim", sha))
    if require_all:
        seen = {row["id"] for row in observed}
        for rid in declared:
            if rid not in seen:
                errs.add(("artifact_not_observed", rid))
    return sorted(errs)


# ------------------------------------------------------------------------------ vector mutations

def _unescape(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def _step(node: Any, segment: str) -> Any:
    """One path step. `key=value` selects the list element whose field `key` equals `value`."""
    seg = _unescape(segment)
    if isinstance(node, dict):
        if seg not in node:
            raise ValueError(f"no key {seg!r}")
        return node[seg]
    if isinstance(node, list):
        if "=" in seg:
            key, _, val = seg.partition("=")
            for item in node:
                if isinstance(item, dict) and item.get(key) == val:
                    return item
            raise ValueError(f"no element with {key}={val!r}")
        index = int(seg)
        return node[index]
    raise ValueError(f"cannot step into {type(node).__name__}")


def _walk(doc: Any, segments: Sequence[str]) -> Any:
    node = doc
    for seg in segments:
        node = _step(node, seg)
    return node


def apply_op(doc: Any, op: Dict[str, Any]) -> None:
    kind = op["op"]
    segs = [s for s in op["path"].split("/") if s != ""]
    if kind == "push":
        target = _walk(doc, segs)
        if not isinstance(target, list):
            raise ValueError("push target is not a list")
        target.append(op["value"])
        return
    parent = _walk(doc, segs[:-1])
    last = segs[-1]
    if kind == "set":
        if isinstance(parent, dict):
            parent[_unescape(last)] = op["value"]
        elif isinstance(parent, list):
            if "=" in last:
                key, _, val = _unescape(last).partition("=")
                for index, item in enumerate(parent):
                    if isinstance(item, dict) and item.get(key) == val:
                        parent[index] = op["value"]
                        return
                raise ValueError(f"no element with {key}={val!r}")
            parent[int(last)] = op["value"]
        else:
            raise ValueError("set parent is not a container")
    elif kind == "remove":
        if isinstance(parent, dict):
            del parent[_unescape(last)]
        elif isinstance(parent, list):
            if "=" in last:
                key, _, val = _unescape(last).partition("=")
                for index, item in enumerate(parent):
                    if isinstance(item, dict) and item.get(key) == val:
                        del parent[index]
                        return
                raise ValueError(f"no element with {key}={val!r}")
            del parent[int(last)]
        else:
            raise ValueError("remove parent is not a container")
    else:
        raise ValueError(f"unknown op {kind!r}")


def apply_ops(doc: Any, ops: Iterable[Dict[str, Any]]) -> Any:
    import copy
    out = copy.deepcopy(doc)
    for op in ops:
        apply_op(out, op)
    return out
