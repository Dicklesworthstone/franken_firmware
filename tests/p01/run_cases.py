#!/usr/bin/env python3
"""P01 (ffw-h3g) host-side case runner: the build-identity half.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]

Runs the shared contract vectors and the named cases in cases.json and prints one line per case and an exact
denominator. Exit codes: 0 qualified, 1 a case failed, 3 only blocked cases stand in the way, 2 usage or a malformed
case file.

What a pass means, so it is not over-read:
* This is a HOST check. It reads Cargo.toml, Cargo.lock and the tree; it never runs cargo, rch, QEMU or a device.
  The command plan it builds and checks is NOT executed here; running it needs the central rch path (see BLK-001).
* reference.py re-implements, from docs/contracts/p01.md, the rules the Rust module
  crates/franken-board-profile/src/build_contract.rs enforces. The Rust replays the same vectors under central
  verification. The expected values are hand-written. One author wrote both, so agreement is a cross-check.
* A case of kind ``blocked`` is a required invariant nothing here can verify. It is counted, named with its owner
  and blocker, and makes the run NOT QUALIFIED.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import central  # noqa: E402
import facts as facts_mod  # noqa: E402
import fixtures  # noqa: E402
import inventory  # noqa: E402
import inventory_fixtures  # noqa: E402
import metadata_check  # noqa: E402
import plan as plan_mod  # noqa: E402
import planning_fixtures  # noqa: E402
import planning_reconcile  # noqa: E402
import reference as ref  # noqa: E402

VEC_DIR = os.path.join(REPO, "crates", "franken-board-profile", "tests", "vectors")
CONTRACT_FILE = os.path.join(VEC_DIR, "p01_workspace_contract.json")
VECTORS_FILE = os.path.join(VEC_DIR, "p01_contract_vectors.json")
RUST_FILE = os.path.join(REPO, "crates", "franken-board-profile", "src", "build_contract.rs")
CASES_FILE = os.path.join(HERE, "cases.json")
SCHEMA = "ffw.p01.cases.v1"
TIERS = ("smoke", "full")
PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
Result = Tuple[str, str]


class CaseError(Exception):
    pass


def load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as err:
        raise CaseError(f"cannot read {os.path.relpath(path, REPO)}: {err}") from err


def contract() -> Dict[str, Any]:
    return load_json(CONTRACT_FILE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------ shared vectors

def eval_vector(vec: Dict[str, Any], base: Dict[str, Any], base_digest: str) -> None:
    """Raise CaseError unless the reference gives exactly what the vector's hand-written expectation says."""
    doc = ref.apply_ops(base, vec["ops"])
    kind = vec["kind"]
    if kind == "parse":
        try:
            ref.parse_contract(doc)
        except ref.ParseError:
            return
        raise CaseError("expected parse_error but the document parsed")
    try:
        ref.parse_contract(doc)
    except ref.ParseError as err:
        raise CaseError(f"unexpected parse_error: {err}") from err
    if kind == "digest":
        got = ref.digest(doc)
        if "expect_digest" in vec and got != vec["expect_digest"]:
            raise CaseError(f"digest {got}, want {vec['expect_digest']}")
        if vec.get("expect_changed") and got == base_digest:
            raise CaseError("digest did not change")
        return
    if kind == "admission":
        adm = ref.admission(doc, vec["artifact"])
        _check_admission(adm, vec["expect"])
        return
    if kind == "validate":
        pairs = ref.validate(doc)
        _check_codes(pairs, vec)
        if "expect_admission" in vec:
            _check_admission(ref.admission(doc, vec["expect_admission"]["artifact"]), vec["expect_admission"])
        return
    if kind == "observed":
        rows = ref.parse_observed(vec["rows"])
        _check_codes(ref.verify_observed(doc, rows, vec["require_all"]), vec)
        return
    raise CaseError(f"unknown vector kind {kind!r}")


def _check_codes(pairs: List[Tuple[str, str]], vec: Dict[str, Any]) -> None:
    got = ref.codes(pairs)
    if got != vec["expect_codes"]:
        raise CaseError(f"codes {got}, want {vec['expect_codes']}")
    subs = ref.subjects(pairs)
    for code, want in vec.get("expect_subjects", {}).items():
        if subs.get(code) != sorted(want):
            raise CaseError(f"subjects of {code}: {subs.get(code)}, want {sorted(want)}")


def _check_admission(adm: Optional[Dict[str, Any]], want: Dict[str, Any]) -> None:
    if adm is None:
        raise CaseError("unknown artifact")
    if adm["qualified"] != want["qualified"] or adm["blocks"] != want["blocks"]:
        raise CaseError(f"admission {adm['qualified']} {adm['blocks']}, want {want['qualified']} {want['blocks']}")


def run_vector(c) -> Result:
    vectors = load_json(VECTORS_FILE)
    eval_vector(c["vector"], contract(), vectors["base_digest"])
    return PASS, ""


# ------------------------------------------------------------------------------ declared contract

def run_contract_valid(c) -> Result:
    doc = contract()
    ref.parse_contract(doc)
    pairs = ref.validate(doc)
    if pairs:
        raise CaseError(f"the declared contract has violations: {pairs}")
    vectors = load_json(VECTORS_FILE)
    if ref.digest(doc) != vectors["base_digest"]:
        raise CaseError("the contract digest differs from the pin in the shared vectors; run make_vectors.py")
    for art in doc["artifacts"]:
        adm = ref.admission(doc, art["id"])
        if adm is None or adm["qualified"]:
            raise CaseError(f"{art['id']} is claimed qualified but no evidence exists")
    return PASS, f"{len(doc['crates'])} crates, {len(doc['artifacts'])} artifacts, digest {ref.digest(doc)[:12]}"


def run_drift_real(c) -> Result:
    pairs = facts_mod.compare(contract(), facts_mod.extract(REPO), root=REPO)
    if pairs:
        raise CaseError("the repository has drifted from the declared contract: "
                        + "; ".join(f"{code}[{subject}]" for code, subject in pairs))
    return PASS, ""


def run_facts_cwd(c) -> Result:
    expected = facts_mod.facts_digest(facts_mod.extract(REPO))
    script = os.path.join(HERE, "facts.py")
    seen = set()
    with tempfile.TemporaryDirectory() as elsewhere:
        for cwd in (REPO, elsewhere, os.path.join(REPO, "crates")):
            out = subprocess.run([sys.executable, "-B", "-I", script, "--root", REPO, "--digest"], cwd=cwd,
                                 capture_output=True, text=True, timeout=60)
            if out.returncode != 0:
                raise CaseError(f"facts.py failed from {cwd}: {out.stderr.strip()[:200]}")
            seen.add(out.stdout.strip())
    if seen != {expected}:
        raise CaseError(f"facts digest depends on the working directory: {sorted(seen)} vs {expected}")
    return PASS, f"digest {expected[:12]} from three working directories"


def run_drift_planted(c) -> Result:
    spec = fixtures.base_spec()
    mini = fixtures.mini_contract(spec)
    with tempfile.TemporaryDirectory() as tmp:
        fixtures.materialize(tmp, spec)
        base = facts_mod.compare(mini, facts_mod.extract(tmp), root=tmp)
    if base:
        raise CaseError(f"the unmutated synthetic workspace already drifts: {base}")
    spec2 = ref.apply_ops(fixtures.base_spec(), c.get("spec_ops", []))
    mini2 = ref.apply_ops(fixtures.mini_contract(fixtures.base_spec()), c.get("contract_ops", []))
    with tempfile.TemporaryDirectory() as tmp:
        fixtures.materialize(tmp, spec2)
        pairs = facts_mod.compare(mini2, facts_mod.extract(tmp), root=tmp)
    got = facts_mod.codes(pairs)
    if got != c["expect_codes"]:
        raise CaseError(f"codes {got}, want {c['expect_codes']}")
    subs = ref.subjects(pairs)
    for code, want in c.get("expect_subjects", {}).items():
        if subs.get(code) != sorted(want):
            raise CaseError(f"subjects of {code}: {subs.get(code)}, want {sorted(want)}")
    return PASS, ""


def run_static_resolve(c) -> Result:
    """The gate is a real switch: from the manifests alone, a default speaker build has no edge onto the test-only crate
    and a `harness` build has exactly that one more. Then, per artifact, the contract's own idea of the closure must
    equal the manifests' closure for the Cargo flags that artifact's profile turns on."""
    doc = contract()
    data = facts_mod.extract(REPO)
    members = {x["name"]: x for x in doc["crates"]}
    default = facts_mod.resolve_normal_closure(data, "franken-speaker")
    harness = facts_mod.resolve_normal_closure(data, "franken-speaker", ["harness"])
    if "franken-test-support" in default:
        raise CaseError("a default franken-speaker build still has franken-test-support in its normal closure")
    if harness - default != {"franken-test-support"} or default - harness:
        raise CaseError(f"harness adds {sorted(harness - default)} and drops {sorted(default - harness)}; "
                        "expected exactly franken-test-support added")
    for art in doc["artifacts"]:
        if art["crate"] not in members:
            continue
        profile = next(p for p in doc["profiles"] if p["name"] == art["profile"])
        enabled = {sel["feature"] for sel in profile["features"] if sel["state"] == "enabled"}
        flags = sorted(f["cargo_feature"] for f in doc["features"]
                       if f["cargo_feature"] and f["owner_crate"] == art["crate"] and f["name"] in enabled)
        from_manifests = facts_mod.resolve_normal_closure(data, art["crate"], flags)
        from_contract = ref.closure(ref.active_graph(doc, art, members), art["crate"])
        if from_manifests != from_contract:
            raise CaseError(f"{art['id']}: manifests give {sorted(from_manifests)}, "
                            f"the contract gives {sorted(from_contract)}")
    return PASS, f"default closure {len(default)} crates, harness closure {len(harness)}"


def run_resolve_planted(c) -> Result:
    spec = ref.apply_ops(fixtures.base_spec(), c.get("spec_ops", []))
    with tempfile.TemporaryDirectory() as tmp:
        fixtures.materialize(tmp, spec)
        data = facts_mod.extract(tmp)
    for label, args in (("default", {}), ("no_default", {"default_features": False}), ("gate", {"features": ["gate"]})):
        if label not in c["expect"]:
            continue
        got = sorted(facts_mod.resolve_normal_closure(data, "b", **args))
        if got != c["expect"][label]:
            raise CaseError(f"{label}: closure {got}, want {c['expect'][label]}")
    return PASS, ""


def run_metadata(c) -> Result:
    def load(key):
        return c[key + "_raw"] if (key + "_raw") in c else metadata_check.build_metadata(c[key])
    pairs = metadata_check.check(load("default"), load("harness"))
    got = metadata_check.codes(pairs)
    if got != c["expect_codes"]:
        raise CaseError(f"codes {got}, want {c['expect_codes']}")
    subs = ref.subjects(pairs)
    for code, want in c.get("expect_subjects", {}).items():
        if subs.get(code) != sorted(want):
            raise CaseError(f"subjects of {code}: {subs.get(code)}, want {sorted(want)}")
    return PASS, ""


def run_metadata_real(c) -> Result:
    """Judge the two centrally produced `cargo metadata` documents named by --metadata-default/--metadata-harness.

    Absent: BLOCKED, counted and named, never skipped and never a pass. Present: PASS only if (1) the gate holds in
    both resolve graphs, (2) both documents describe THIS tree and Cargo.lock (members, workspace edges by an
    independent static resolve, the gating feature resolved or not, every package in the lockfile), and (3) each
    fault planted in a copy of them is caught with its expected code. (3) is the remove-the-plant control: it is
    meaningful because (1) and (2) just showed the unplanted documents are clean."""
    given = c.get("_inputs") or {}
    if not given.get("default") and not given.get("harness"):
        return BLOCKED, f"{c['reason']} [owner: {c['owner']}]"
    try:
        default_meta, harness_meta = metadata_check.load(given["default"]), metadata_check.load(given["harness"])
        digests = (metadata_check.sha256_file(given["default"]), metadata_check.sha256_file(given["harness"]))
    except (OSError, ValueError, KeyError) as err:
        raise CaseError(f"cannot read the supplied metadata documents: {type(err).__name__}: {err}")
    tree = facts_mod.extract(REPO)
    lock = metadata_check.lock_packages(os.path.join(REPO, "Cargo.lock"))
    pairs = metadata_check.judge(default_meta, harness_meta, tree, lock)
    if pairs:
        shown = "; ".join(f"{code} [{subject}]" for code, subject in pairs[:6])
        raise CaseError(f"the supplied documents fail ({len(pairs)}): {shown}" + (" ..." if len(pairs) > 6 else ""))
    problems = metadata_check.run_plants(default_meta, harness_meta, tree, lock)
    if problems:
        raise CaseError("the judgement missed planted faults: " + "; ".join(problems[:4]))
    crate = metadata_check.GATE_CRATE
    sizes = (len(metadata_check.normal_closure(default_meta, crate)),
             len(metadata_check.normal_closure(harness_meta, crate)))
    return PASS, (f"{crate} normal closure {sizes[0]} packages by default, {sizes[1]} with the harness; "
                  f"{len(metadata_check.PLANTS)} planted faults caught; "
                  f"documents sha256 {digests[0][:12]}/{digests[1][:12]}")


# ------------------------------------------------------------------------------ the command plan

def _plan(cwd_rel: str = "crates/franken-board-profile"):
    root = os.path.realpath(REPO)
    target_dir = os.path.join(tempfile.gettempdir(), "p01-plan-target")
    cwd = os.path.join(root, cwd_rel) if cwd_rel else root
    return root, target_dir, plan_mod.plan_steps(root, cwd, target_dir, contract())


def run_plan_exact(c) -> Result:
    root, target_dir, steps = _plan()
    by_id = {s["id"]: s for s in steps}

    def fill(argv):
        return [a.replace("<ROOT>", root).replace("<TARGET_DIR>", target_dir) for a in argv]
    for sid, want in c["expect_argv"].items():
        got = by_id.get(sid)
        if got is None:
            raise CaseError(f"no step {sid}")
        if got["argv"] != fill(want):
            raise CaseError(f"step {sid}: argv {got['argv']}, want {fill(want)}")
    if sorted(by_id) != sorted(c["expect_step_ids"]):
        raise CaseError(f"step ids {sorted(by_id)}, want {sorted(c['expect_step_ids'])}")
    if "expect_root_cwd" in c:
        at_root = sorted(s["id"] for s in steps if os.path.realpath(s["cwd"]) == root)
        if at_root != sorted(c["expect_root_cwd"]):
            raise CaseError(f"steps run from the repository root: {at_root}, want {sorted(c['expect_root_cwd'])}")
    if "expect_foreign_on" in c:
        carrying = sorted(s["id"] for s in steps if plan_mod.FOREIGN_ARTIFACTS_ENV in s["env"])
        if carrying != sorted(c["expect_foreign_on"]):
            raise CaseError(f"{plan_mod.FOREIGN_ARTIFACTS_ENV} is on {carrying}, want {sorted(c['expect_foreign_on'])}")
    for s in steps:
        if s["env"]["RCH_REQUIRE_REMOTE"] != "1" or s["env"]["CARGO_TARGET_DIR"] != target_dir:
            raise CaseError(f"step {s['id']}: environment {s['env']}")
        if os.path.realpath(s["cwd"]) == root and s["id"] not in c.get("expect_root_cwd", []):
            raise CaseError(f"step {s['id']} runs in the repository root")
    return PASS, f"{len(steps)} steps"


def run_plan_rules(c) -> Result:
    root, _target_dir, steps = _plan()
    doc = contract()
    if plan_mod.check_plan(steps, root, doc):
        raise CaseError(f"the unmutated plan already violates a rule: {plan_mod.check_plan(steps, root, doc)}")
    mutated = copy.deepcopy(steps)
    target = next(s for s in mutated if s["id"] == c["step"])
    kind, arg = c["plant"]["op"], c["plant"].get("arg")
    if kind == "drop_arg":
        target["argv"] = [a for a in target["argv"] if a != arg]
    elif kind == "replace_arg":
        target["argv"] = [c["plant"]["to"] if a == arg else a for a in target["argv"]]
    elif kind == "drop_with_value":
        i = target["argv"].index(arg)
        del target["argv"][i:i + 2]
    elif kind in ("drop_config", "replace_config", "drop_all_config"):
        argv = target["argv"]
        out, i = [], 0
        while i < len(argv):
            pair = argv[i] == "--config" and i + 1 < len(argv)
            if pair and kind == "drop_all_config":
                i += 2
                continue
            if pair and argv[i + 1].startswith(arg):
                if kind == "replace_config":
                    out += ["--config", c["plant"]["to"]]
                i += 2
                continue
            out.append(argv[i])
            i += 1
        target["argv"] = out
    elif kind == "relative_manifest":
        i = target["argv"].index("--manifest-path")
        target["argv"][i + 1] = "Cargo.toml"
    elif kind == "cwd_root":
        target["cwd"] = root
    elif kind == "cwd_board":
        target["cwd"] = os.path.join(root, "crates", "franken-board-profile")
    elif kind == "cwd_missing":
        target["cwd"] = os.path.join(root, "no-such-directory")
    elif kind == "set_env":
        target["env"][arg] = c["plant"]["value"]
    elif kind == "drop_env":
        target["env"].pop(arg, None)
    elif kind == "no_rch":
        target["argv"] = target["argv"][target["argv"].index("--") + 1:]
    else:
        raise CaseError(f"unknown plant {kind!r}")
    pairs = plan_mod.check_plan(mutated, root, doc)
    got = sorted({code for code, _ in pairs})
    if got != c["expect_codes"]:
        raise CaseError(f"codes {got}, want {c['expect_codes']}")
    if any(sid != c["step"] for _, sid in pairs):
        raise CaseError(f"a rule fired on a step other than {c['step']}: {pairs}")
    return PASS, ""


def run_plan_sharing(c) -> Result:
    root, _t, steps = _plan()
    doc = contract()
    shared = [s for s in steps if len(s["artifacts"]) > 1]
    want = {tuple(sorted(x)) for x in c["expect_shared"]}
    got = {tuple(sorted(s["artifacts"])) for s in shared}
    if got != want:
        raise CaseError(f"shared builds {sorted(got)}, want {sorted(want)}")
    for aid, expected in c["expect_unbacked"].items():
        art = next(a for a in doc["artifacts"] if a["id"] == aid)
        if plan_mod.unbacked_disabled_features(doc, art) != expected:
            raise CaseError(f"{aid}: unbacked {plan_mod.unbacked_disabled_features(doc, art)}, want {expected}")
    # a feature that has a Cargo flag reaches the command line exactly when the profile enables it
    flagged = copy.deepcopy(doc)
    next(f for f in flagged["features"] if f["name"] == "artwork")["cargo_feature"] = "artwork"
    on = plan_mod.plan_steps(root, os.path.join(root, "crates"), "/t", flagged)
    argv_on = next(s for s in on if s["artifacts"] == ["speaker-host-full"])["argv"]
    argv_min = next(s for s in on if "speaker-mips-min" in s["artifacts"])["argv"]
    if "franken-control/artwork" not in argv_on[argv_on.index("--features") + 1].split(","):
        raise CaseError("an enabled feature with a Cargo flag is missing from --features")
    if "--features" in argv_min and "franken-control/artwork" in argv_min[argv_min.index("--features") + 1]:
        raise CaseError("a disabled feature leaked into --features")
    return PASS, ""


# ------------------------------------------------------------------------------ receipts

def fake_elf(machine: int, payload: bytes, big: bool = True, klass: int = 1, dynamic: bool = False,
             mips_abi: Optional[Tuple[int, int, int]] = None) -> bytes:
    """A 32-bit ELF header with a program header table when asked: a PT_INTERP segment for a dynamic link, a
    PT_MIPS_ABIFLAGS segment for (ISA level, ISA revision, FP ABI) = `mips_abi`. No compiler is run; this is the shape
    `plan.elf_identity` reads."""
    order = "big" if big else "little"
    segments: List[Tuple[int, bytes]] = []
    if dynamic:
        segments.append((3, b"/lib/ld-musl-mips.so.1\0"))
    if mips_abi is not None:
        level, rev, fp = mips_abi
        segments.append((0x70000003, bytes([0, 0, level, rev, 1, 1, 0, fp]) + bytes(16)))
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = klass
    header[5] = 2 if big else 1
    header[18:20] = machine.to_bytes(2, order)
    table, blobs = bytearray(), bytearray()
    offset = 52 + 32 * len(segments)
    for p_type, blob in segments:
        entry = bytearray(32)
        entry[0:4] = p_type.to_bytes(4, order)
        entry[4:8] = offset.to_bytes(4, order)
        entry[16:20] = len(blob).to_bytes(4, order)
        table += entry
        blobs += blob
        offset += len(blob)
    if segments:
        header[28:32] = (52).to_bytes(4, order)
        header[42:44] = (32).to_bytes(2, order)
        header[44:46] = len(segments).to_bytes(2, order)
    return bytes(header) + bytes(table) + bytes(blobs) + payload


RUSTC_VV_DEFAULT = ("rustc 1.90.0 (1159e78c4 2025-09-14)\nbinary: rustc\ncommit-hash: 1159e78c4747b02ef996e55082b704c09b970588"
                    "\ncommit-date: 2025-09-14\nhost: x86_64-unknown-linux-gnu\nrelease: 1.90.0\nLLVM version: 20.1.8\n")
RUSTC_VV = ("rustc 1.101.0-nightly (48f4b0553 2026-10-23)\nbinary: rustc\ncommit-hash: 48f4b05538c0a2ce7a5d9c4f5f2b1e"
            "0e9d8c7b6a\ncommit-date: 2026-10-23\nhost: x86_64-unknown-linux-gnu\nrelease: 1.101.0-nightly\n"
            "LLVM version: 23.1.0\n")


def make_executor(target_dir: str, doc: Dict[str, Any], scenario: str, steps: List[Dict[str, Any]]):
    """A stand-in for the central rch executor that writes synthetic ELF files. It runs no compiler."""
    by_id = {a["id"]: a for a in doc["artifacts"]}
    calls: List[str] = []

    def executor(argv, cwd, env, timeout):
        step = next(s for s in steps if s["argv"] == argv)
        calls.append(step["id"])
        if scenario == "cancel" and len(calls) == 4:
            raise KeyboardInterrupt
        if step["kind"] == "toolchain":
            return 0, RUSTC_VV
        if step["kind"] == "toolchain_default":
            return 0, RUSTC_VV_DEFAULT
        if step["kind"] == "test":
            return 0, "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n"
        if scenario == "build_fails" and step["id"].endswith("powerpc_be") and "speaker" in step["id"]:
            return 101, "error: could not compile\n"
        for aid in step["artifacts"]:
            art = by_id[aid]
            path = plan_mod.artifact_path(target_dir, art)
            if scenario == "missing_artifact" and art["target"] == "mips_be":
                continue
            machine = ref.TARGETS[art["target"]][2]
            payload = f"{art['crate']}:{art['target']}".encode()
            if scenario == "wrong_isa" and art["target"] == "powerpc_be" and art["crate"] == "franken-speaker":
                machine = 8
            # the speaker is linked static through the declared wrapper; MIPS states its ABI in .MIPS.abiflags
            abi = (32, 2, 3) if art["target"] == "mips_be" and art["crate"] == "franken-speaker" else None
            dynamic = False
            if scenario == "universal" and art["crate"] == "franken-speaker" and art["target"] != "host":
                machine, payload, abi = 8, b"identical-bytes", (32, 2, 3)
            if scenario == "dynamic" and art["target"] == "mips_be" and art["crate"] == "franken-speaker":
                dynamic = True
            if scenario == "hard_float" and art["target"] == "mips_be" and art["crate"] == "franken-speaker":
                abi = (32, 2, 1)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(fake_elf(machine, payload, dynamic=dynamic, mips_abi=abi) if art["target"] != "host"
                        else b"\xcf\xfa\xed\xfe" + payload)
        return 0, "Finished release\n"
    return executor, calls


def _run_scenario(scenario: str, receipts_dir: str, target_dir: str):
    root = os.path.realpath(REPO)
    doc = contract()
    steps = plan_mod.plan_steps(root, os.path.join(root, "crates", "franken-board-profile"), target_dir, doc)
    executor, calls = make_executor(target_dir, doc, scenario, steps)
    code, path, receipt = plan_mod.execute(steps, doc, root, target_dir, receipts_dir, executor, lock_sha256="0" * 64)
    return doc, steps, code, path, receipt, calls


def run_receipt(c) -> Result:
    scenario = c["scenario"]
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = os.path.join(tmp, "target")
        receipts = os.path.join(tmp, "receipts")
        doc, steps, code, path, receipt, calls = _run_scenario(scenario, receipts, target_dir)
        want = c["expect"]
        if code != want["exit"]:
            raise CaseError(f"exit {code}, want {want['exit']}")
        if receipt["status"] != want["status"]:
            raise CaseError(f"status {receipt['status']}, want {want['status']}")
        if "codes" in want and receipt["verification"]["codes"] != want["codes"]:
            raise CaseError(f"verification codes {receipt['verification']['codes']}, want {want['codes']}")
        if "subjects" in want:
            got = ref.subjects([tuple(p) for p in receipt["verification"]["pairs"]])
            for code_, subs in want["subjects"].items():
                if got.get(code_) != sorted(subs):
                    raise CaseError(f"subjects of {code_}: {got.get(code_)}, want {sorted(subs)}")
        if "failed_steps" in want:
            failed = sorted(s["id"] for s in receipt["steps"] if s["status"] != "ok")
            if failed != sorted(want["failed_steps"]):
                raise CaseError(f"failed steps {failed}, want {sorted(want['failed_steps'])}")
        if want.get("identity"):
            _check_identity(doc, receipt, target_dir, path)
        if scenario == "cancel":
            _check_restart(receipts, target_dir, path, receipt)
        return PASS, f"{len(receipt['steps'])} steps run, {len(receipt['artifacts'])} artifact rows"


def _check_identity(doc, receipt, target_dir, path) -> None:
    """Independent of plan.py: hash the files the executor wrote and compare with what the receipt says."""
    on_disk = json.loads(_read_text(path))
    if on_disk != receipt:
        raise CaseError("the receipt on disk differs from the one returned")
    if receipt["contract_digest"] != sha256_bytes(ref.canonical_json(doc).encode("utf-8")):
        raise CaseError("receipt contract_digest is not the canonical digest of the contract")
    if (receipt["toolchain"].get("release"), receipt["toolchain_default"].get("release")) != \
            ("1.101.0-nightly", "1.90.0"):
        raise CaseError("the nightly and the default toolchain must be recorded separately: "
                        f"{receipt['toolchain']} / {receipt['toolchain_default']}")
    by_id = {a["id"]: a for a in doc["artifacts"]}
    seen = set()
    for row in receipt["artifacts"]:
        art = by_id[row["id"]]
        seen.add(row["id"])
        triple = {"host": "host", "mips_be": "mips-unknown-linux-musl",
                  "powerpc_be": "powerpc-unknown-linux-musl"}[art["target"]]
        leaf = art["bin"]
        built = os.path.join(target_dir, "release", leaf) if triple == "host" else \
            os.path.join(target_dir, triple, "release", leaf)
        with open(built, "rb") as f:
            data = f.read()
        if row["sha256"] != hashlib.sha256(data).hexdigest():
            raise CaseError(f"{row['id']}: receipt digest is not the digest of the built file")
        if (row["target"], row["triple"], row["profile"]) != (art["target"], triple, art["profile"]):
            raise CaseError(f"{row['id']}: target/triple/profile did not propagate: {row}")
        if art["target"] != "host":
            want_machine = {"mips_be": 8, "powerpc_be": 20}[art["target"]]
            if (row["elf_machine"], row["elf_class"], row["elf_big_endian"]) != (want_machine, 1, True):
                raise CaseError(f"{row['id']}: ELF identity wrong: {row}")
    if seen != {a["id"] for a in doc["artifacts"] if a["bin"]}:
        raise CaseError(f"rows cover {sorted(seen)}")
    shas = {}
    for row in receipt["artifacts"]:
        shas.setdefault(row["sha256"], set()).add(row["target"])
    if any(len(t) > 1 for t in shas.values()):
        raise CaseError("one digest is reported for more than one target")
    if receipt["toolchain"].get("release") != "1.101.0-nightly" or "host" not in receipt["toolchain"]:
        raise CaseError(f"toolchain not recorded from the executor's rustc -vV: {receipt['toolchain']}")
    if receipt["unbacked_disabled_features"]["speaker-mips-min"] != \
            ["airplay2", "alexa_bridge", "artwork", "spotify_connect", "tailnet_native"]:
        raise CaseError("the receipt hides that the minimal profile's disabled features have no Cargo flag")


def _check_restart(receipts_dir, target_dir, first_path, first_receipt) -> None:
    """After a cancelled run, a restart writes a new receipt and leaves the cancelled one exactly as it was."""
    before = _read_bytes(first_path)
    if first_receipt["status"] != "incomplete" or [s["id"] for s in first_receipt["steps"]] != \
            ["toolchain", "toolchain-default", "workspace-test"]:
        raise CaseError(f"the cancelled receipt is not an honest partial: {first_receipt['status']}")
    doc, steps, code, path2, receipt2, _ = _run_scenario("ok", receipts_dir, target_dir)
    if path2 == first_path or code != 0 or receipt2["status"] != "complete":
        raise CaseError("the restart did not produce a separate complete receipt")
    if _read_bytes(first_path) != before:
        raise CaseError("the restart overwrote the original receipt")


def run_receipt_tamper(c) -> Result:
    with tempfile.TemporaryDirectory() as tmp:
        doc, _steps, code, _path, receipt, _ = _run_scenario("ok", os.path.join(tmp, "r"), os.path.join(tmp, "t"))
        if code != 0 or plan_mod.check_receipt(doc, receipt):
            raise CaseError("the unmutated receipt does not verify")
        bad = ref.apply_ops(receipt, c["ops"])
        pairs = plan_mod.check_receipt(doc, bad)
    got = sorted({code_ for code_, _ in pairs})
    if got != c["expect_codes"]:
        raise CaseError(f"codes {got}, want {c['expect_codes']}")
    return PASS, ""


# ------------------------------------------------------------------------------ meta

def expand(patterns: List[str], ids: List[str]) -> List[str]:
    out: List[str] = []
    for pattern in patterns:
        if pattern.endswith("*"):
            out += [i for i in ids if i.startswith(pattern[:-1])]
        else:
            out.append(pattern)
    return out


def run_meta_invariants(c) -> Result:
    cases = all_cases()
    ids = [x["id"] for x in cases]
    doc = load_json(CASES_FILE)
    problems = []
    covered_ids = set()
    for inv in doc["invariants"]:
        if inv["status"] not in ("covered", "partial", "blocked", "inapplicable"):
            problems.append(f"{inv['id']}: unknown status {inv['status']}")
        if inv["status"] == "inapplicable" and not inv.get("note"):
            problems.append(f"{inv['id']}: inapplicable without an explanation")
        names = expand(inv.get("cases", []), ids)
        if inv["status"] != "inapplicable" and not names:
            problems.append(f"{inv['id']}: {inv['status']} but names no case")
        for name in names:
            if name not in ids:
                problems.append(f"{inv['id']}: names missing case {name}")
        covered_ids.update(names)
    for x in cases:
        if x["kind"] not in ("meta",) and not x["id"].startswith("P01-META") and x["id"] not in covered_ids:
            problems.append(f"case {x['id']} covers no invariant")
    if problems:
        raise CaseError("; ".join(problems[:6]))
    return PASS, f"{len(doc['invariants'])} invariants, {len(ids)} cases"


def run_meta_codes(c) -> Result:
    """Every error code the Rust module can emit is exercised by at least one shared vector."""
    text = _read_text(RUST_FILE)
    block = text[text.index("pub mod code {"):]
    block = block[:block.index("\n}\n")]
    rust_codes = set(re.findall(r'pub const [A-Z0-9_]+: &str = "([a-z0-9_]+)";', block))
    used = set()
    for vec in load_json(VECTORS_FILE)["vectors"]:
        used.update(vec.get("expect_codes", []))
        used.update(vec.get("expect_subjects", {}).keys())
    unused = sorted(rust_codes - used - set(c.get("not_vector_covered", [])))
    if unused:
        raise CaseError(f"error codes no vector exercises: {unused}")
    unknown = sorted(used - rust_codes)
    if unknown:
        raise CaseError(f"vectors expect codes the Rust module does not define: {unknown}")
    return PASS, f"{len(rust_codes)} codes"


def run_meta_hygiene(c) -> Result:
    patterns = [("rfc1918_ip", re.compile(r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                                          r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")),
                ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
                ("rincon_uuid", re.compile(r"RINCON_[0-9A-Fa-f]+")),
                ("household_id", re.compile(r"Sonos_[A-Za-z0-9_-]{20,}"))]
    files = [os.path.join(HERE, n) for n in sorted(os.listdir(HERE)) if n.endswith((".py", ".json"))]
    files += [CONTRACT_FILE, VECTORS_FILE, RUST_FILE]
    hits = []
    for path in files:
        text = _read_text(path)
        for name, pat in patterns:
            if pat.search(text):
                hits.append(f"{os.path.relpath(path, REPO)}: {name}")
    if hits:
        raise CaseError("; ".join(hits))
    return PASS, f"{len(files)} files"


def run_meta_vectors_current(c) -> Result:
    out = subprocess.run([sys.executable, "-B", os.path.join(HERE, "make_vectors.py"), "--check"],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise CaseError(out.stdout.strip() or out.stderr.strip()[:200])
    return PASS, ""


def run_mutation_canary(c) -> Result:
    """Break one rule at a time in a copy of reference.py; the vectors must notice every break."""
    source = _read_text(os.path.join(HERE, "reference.py"))
    vectors = load_json(VECTORS_FILE)
    base = contract()
    caught, missed = [], []
    for name, old, new in c["mutants"]:
        if source.count(old) != 1:
            raise CaseError(f"mutant {name!r}: the target text occurs {source.count(old)} times")
        namespace: Dict[str, Any] = {"__name__": "reference_mutant"}
        exec(compile(source.replace(old, new), f"<mutant:{name}>", "exec"), namespace)
        failures = 0
        for vec in vectors["vectors"]:
            try:
                _eval_with(namespace, vec, base, vectors["base_digest"])
            except Exception:  # noqa: BLE001 - any divergence from the hand-written expectation counts
                failures += 1
        (caught if failures else missed).append(name)
    if missed:
        raise CaseError(f"vectors do not notice these broken rules: {missed}")
    return PASS, f"{len(caught)} mutants caught"


def _eval_with(namespace: Dict[str, Any], vec: Dict[str, Any], base, base_digest: str) -> None:
    doc = namespace["apply_ops"](base, vec["ops"])
    kind = vec["kind"]
    if kind == "parse":
        try:
            namespace["parse_contract"](doc)
        except namespace["ParseError"]:
            return
        raise CaseError("parsed")
    namespace["parse_contract"](doc)
    if kind == "digest":
        got = namespace["digest"](doc)
        if "expect_digest" in vec and got != vec["expect_digest"]:
            raise CaseError("digest")
        return
    if kind == "admission":
        a = namespace["admission"](doc, vec["artifact"])
        if (a["qualified"], a["blocks"]) != (vec["expect"]["qualified"], vec["expect"]["blocks"]):
            raise CaseError("admission")
        return
    if kind == "validate":
        pairs = namespace["validate"](doc)
        if namespace["codes"](pairs) != vec["expect_codes"]:
            raise CaseError("codes")
        if "expect_admission" in vec:
            a = namespace["admission"](doc, vec["expect_admission"]["artifact"])
            if (a["qualified"], a["blocks"]) != (vec["expect_admission"]["qualified"], vec["expect_admission"]["blocks"]):
                raise CaseError("admission")
        return
    rows = namespace["parse_observed"](vec["rows"])
    if namespace["codes"](namespace["verify_observed"](doc, rows, vec["require_all"])) != vec["expect_codes"]:
        raise CaseError("observed")


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


# The two unit tests that skip when the checkout has no git history, which is what a `git archive` export (the central
# snapshot) is: they need `git rev-parse HEAD`. A skip of any other test, for any other reason, or in a tree that HAS history,
# is a defect and not an export artifact.
EXPORT_SKIPS = {
    "test_the_ingest_command_writes_one_record_and_refuses_to_overwrite_it": ("git is unavailable", "no git history here"),
    "test_ingest_records_the_replay_tests_by_name_from_the_log_and_binds_them_to_the_files":
        ("git is unavailable", "no git history here"),
}
_SKIPPED_LINE = re.compile(r"^(\w+) \([\w.]+\) \.\.\. skipped '(.*)'\s*$", re.M)
_OK_SUMMARY = re.compile(r"^OK(?: \(skipped=(\d+)\))?\s*$", re.M)


def judge_selftest(returncode: int, stderr: str, min_tests: int, history_present: bool) -> str:
    """The verdict on one `python -m unittest -v test_p01` run, as a detail string, or CaseError. `history_present` is whether
    this checkout answers `git rev-parse HEAD`; only without it may the two EXPORT_SKIPS tests skip."""
    match = re.search(r"^Ran (\d+) tests?", stderr, re.M)
    ran = int(match.group(1)) if match else 0
    summary = _OK_SUMMARY.search(stderr)
    if returncode != 0 or summary is None:
        raise CaseError("unit tests failed: " + " ".join(stderr.split())[-200:])
    declared = int(summary.group(1) or 0)
    seen = _SKIPPED_LINE.findall(stderr)
    if len(seen) != declared:
        raise CaseError(f"the summary declares {declared} skipped tests but {len(seen)} skip lines were read")
    for name, reason in seen:
        if name not in EXPORT_SKIPS:
            raise CaseError(f"unit test {name} was skipped ({reason!r}); only {sorted(EXPORT_SKIPS)} may skip")
        if reason not in EXPORT_SKIPS[name]:
            raise CaseError(f"unit test {name} was skipped for an undocumented reason {reason!r}")
        if history_present:
            raise CaseError(f"unit test {name} was skipped ({reason!r}) in a checkout that has git history")
    if ran < min_tests:
        raise CaseError(f"only {ran} unit tests ran, expected at least {min_tests}")
    executed = ran - declared
    return f"{ran} unit tests" if not declared else f"{ran} unit tests ({executed} executed, {declared} skipped: no git history in this export)"


def _git_history_here() -> bool:
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return head.returncode == 0


def run_runner_selftest(c) -> Result:
    out = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v", "test_p01"], cwd=HERE, capture_output=True,
                         text=True, timeout=300)
    return PASS, judge_selftest(out.returncode, out.stderr, c["min_tests"], _git_history_here())


def _revision_is_here(revision: str) -> Optional[bool]:
    """True/False when this checkout can say whether `revision` is one of its commits; None when it has no git."""
    if not os.path.exists(os.path.join(REPO, ".git")):
        return None
    try:
        out = subprocess.run(["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=REPO, capture_output=True,
                             timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.returncode == 0


def run_central_evidence(c) -> Result:
    """P01-BLK-001/002/003: the plan ran on the central path (`judge` steps), the device speakers it built are static
    and carry the declared ABI (`device_artifacts`), and the typed contract replayed the shared vectors (`replay`).
    Judged from committed, sanitized evidence records (`scripts/e2e/p01 ingest`), newest run first, against the CURRENT
    plan, contract and replay tests. No record: BLOCKED. A record for another plan or contract, or with a step that never
    ran, or a replay of other tests or other vectors: BLOCKED and named. A failed step, a failed replay test, a dynamic or
    mismatched device artifact, or an inconsistent record: FAIL. Never skipped, never a pass on stale evidence."""
    owner = f" [owner: {c['owner']}]"
    records = []
    for path in central.find_evidence(REPO):
        try:
            records.append((load_json(path), path))
        except CaseError as err:
            raise CaseError(f"unreadable evidence record: {err}")
    if not records:
        return BLOCKED, f"no central-run evidence is committed under toolchain/results/p01. {c['reason']}{owner}"
    records.sort(key=lambda r: str(r[0].get("ran_at_utc", "")))
    evidence, _path = records[-1]
    root, _target_dir, steps = _plan()
    doc = contract()
    judgement = c.get("judge", "steps")
    if judgement == "steps":
        kwargs: Dict[str, Any] = {}
    elif judgement == "device_artifacts":
        kwargs = {"scope": central.BLK002_STEPS, "artifacts": central.device_std_artifacts(doc)}
    elif judgement == "replay":
        try:
            now = {"test_file_sha256": metadata_check.sha256_file(os.path.join(REPO, *central.REPLAY_TEST_FILE.split("/"))),
                   "vectors_sha256": metadata_check.sha256_file(os.path.join(REPO, *central.REPLAY_VECTORS_FILE.split("/")))}
        except OSError as err:
            raise CaseError(f"cannot read the replay files: {err}")
        kwargs = {"scope": central.BLK003_STEPS, "replay": now}
    else:
        raise CaseError(f"unknown judgement {judgement!r}")
    verdict, detail = central.judge(evidence, doc, steps, central.roots_for(root), **kwargs)
    here = _revision_is_here(str(evidence.get("revision", "")))
    if here is False:
        raise CaseError(f"the evidence names revision {str(evidence.get('revision'))[:12]}, which is not a commit of this repository")
    if here is None:
        detail += " (revision not checkable here: no git)"
    if verdict == "pass":
        return PASS, detail
    if verdict == "blocked":
        return BLOCKED, detail + owner
    raise CaseError(detail)


def run_planning_plants(c) -> Result:
    """P01-REC-001..006: the planning reconcile check on synthetic worlds: the permitted positive passes, and every planted
    negative fails with exactly its hand-written codes (see planning_fixtures.py)."""
    try:
        if c["group"] == "permitted_positive":
            return PASS, planning_fixtures.judge_positive()
        return PASS, planning_fixtures.judge_group(c["group"])
    except AssertionError as err:
        raise CaseError(str(err)) from err


def run_planning_real(c) -> Result:
    """P01-REC-007: the real generated planning files against the real live Beads export. Read-only. Not a pass until they agree,
    and BLOCKED, never skipped, while they do not: the generated validation is not whole-project proof until reconciled."""
    owner = f" [owner: {c['owner']}]"
    path = os.environ.get("FFW_BEADS_EXPORT") or os.path.join(REPO, ".beads", "issues.jsonl")
    if not os.path.isfile(path):
        return BLOCKED, ("no live Beads export to compare with: .beads/issues.jsonl is git-ignored, so a git-archive export has "
                         "none; set FFW_BEADS_EXPORT to a JSONL or JSON export of the live Beads" + owner)
    try:
        findings = planning_reconcile.reconcile(planning_reconcile.load_live(path), planning_reconcile.load_generated())
    except (planning_reconcile.InputError, KeyError, TypeError) as err:
        raise CaseError(f"the planning files or the live export cannot be read: {type(err).__name__}: {err}") from err
    if not findings:
        return PASS, "the generated planning files and the live Beads agree in every compared field"
    counts = ", ".join(f"{code}={n}" for code, n in planning_reconcile.summarize(findings).items())
    shown = os.path.relpath(path, REPO) if path.startswith(REPO + os.sep) else "<the export you supplied>"
    return BLOCKED, (f"{len(findings)} differences between the generated planning files and the live Beads ({counts}); run "
                     f"`python3 tests/p01/planning_reconcile.py --live {shown}` for the list" + owner)


def run_inventory_plants(c) -> Result:
    """P01-INV-001..004: the E06-inventory judgement on synthetic worlds: every permitted positive passes, and every planted
    negative (a stale audit, an audit inconsistent with its lock, an audit edited to claim a lock it was not made from) gets
    exactly its verdict and codes (see inventory_fixtures.py)."""
    try:
        if c["group"] == "permitted_positive":
            return PASS, inventory_fixtures.judge_positive()
        return PASS, inventory_fixtures.judge_group(c["group"])
    except AssertionError as err:
        raise CaseError(str(err)) from err


def run_e06_inventory(c) -> Result:
    """P01-BLK-005: the pinned per-target dependency / unsafe / licence inventory E06 committed
    (`toolchain/results/e06/rev-*/audit.json` or `audit-*/audit.json`) judged against the CURRENT Cargo.lock (see inventory.py). No
    audit: BLOCKED. An audit that binds another lock: BLOCKED, with the delta named (stale, not wrong). An audit that binds this
    lock and disagrees with it: FAIL. Only an audit of this lock, consistent with it, passes. WHICH AUDIT WINS when several are
    committed: one that binds the current lock beats any that does not (an older audit beside a current one never blocks it); among
    those, a pass is the result, and a failing audit of the same lock beside it is named, not hidden; with none current, the
    audit with the smallest delta is the one reported. It admits no dependency and says nothing about a build."""
    owner = f" [owner: {c['owner']}]"
    paths = inventory.find_audits(REPO)
    if not paths:
        return BLOCKED, f"no E06 audit is committed under toolchain/results/e06/{{rev,audit}}-*/audit.json. {c['reason']}{owner}"
    try:
        with open(os.path.join(REPO, "Cargo.lock"), "rb") as f:
            lock = f.read()
    except OSError as err:
        raise CaseError(f"cannot read Cargo.lock: {err}") from err
    judged = []
    for path in paths:
        try:
            judged.append((path, *inventory.judge(load_json(path), lock)))
        except inventory.InputError as err:
            raise CaseError(str(err)) from err
    named = lambda path: os.path.relpath(os.path.dirname(path), REPO)  # noqa: E731
    current = [j for j in judged if "audit_lock_stale" not in inventory.codes(j[2])]
    if current:
        passing = [j for j in current if j[1] == "pass"]
        if passing:
            failing = [named(j[0]) for j in current if j[1] != "pass"]
            also = f"; also binding this lock but failing: {', '.join(failing)}" if failing else ""
            return PASS, f"{named(passing[0][0])}: {passing[0][3]}{also}"
        raise CaseError(f"{named(current[0][0])}: {current[0][3]}")
    best = min(judged, key=lambda j: (len(j[2]), j[0]))
    return BLOCKED, f"{named(best[0])}: {best[3]}{owner}"


def run_blocked(c) -> Result:
    return BLOCKED, f"{c['reason']} [owner: {c['owner']}]"


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "vector": run_vector, "contract_valid": run_contract_valid, "drift_real": run_drift_real,
    "facts_cwd": run_facts_cwd, "drift_planted": run_drift_planted, "static_resolve": run_static_resolve,
    "resolve_planted": run_resolve_planted, "metadata": run_metadata, "metadata_real": run_metadata_real,
    "central_evidence": run_central_evidence, "plan_exact": run_plan_exact,
    "plan_rules": run_plan_rules, "plan_sharing": run_plan_sharing, "receipt": run_receipt,
    "receipt_tamper": run_receipt_tamper, "inventory_plants": run_inventory_plants, "e06_inventory": run_e06_inventory, "meta_invariants": run_meta_invariants, "meta_codes": run_meta_codes,
    "meta_hygiene": run_meta_hygiene, "meta_vectors_current": run_meta_vectors_current,
    "mutation_canary": run_mutation_canary, "runner_selftest": run_runner_selftest, "blocked": run_blocked,
    "planning_plants": run_planning_plants, "planning_real": run_planning_real,
}


# ------------------------------------------------------------------------------ selection and running

def all_cases() -> List[Dict[str, Any]]:
    doc = load_json(CASES_FILE)
    if doc.get("schema") != SCHEMA:
        raise CaseError(f"cases.json schema {doc.get('schema')!r}, expected {SCHEMA!r}")
    cases = [dict(c) for c in doc["cases"]]
    for vec in load_json(VECTORS_FILE)["vectors"]:
        cases.append({"id": vec["id"], "kind": "vector", "title": vec["title"], "tiers": ["smoke", "full"],
                      "vector": vec})
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise CaseError("duplicate case id")
    for c in cases:
        if c["kind"] not in HANDLERS:
            raise CaseError(f"{c['id']}: unknown kind {c['kind']!r}")
    return cases


def select(cases, tier: str, only: Optional[str]):
    if only:
        picked = [c for c in cases if c["id"] == only]
        if not picked:
            raise CaseError(f"no case {only}")
        return picked
    return [c for c in cases if tier in c.get("tiers", TIERS)]


def _metadata_receipt(inputs: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Identify the metadata documents a run judged by content digest, never by path; null when none were supplied."""
    if not inputs:
        return None
    out = {}
    for key, path in sorted(inputs.items()):
        try:
            out[key + "_sha256"] = metadata_check.sha256_file(path)
        except OSError:
            out[key + "_sha256"] = "unreadable"
    return out


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="P01 host-side case runner",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--tier", required=True, choices=TIERS, help="explicit; there is no default")
    ap.add_argument("--case", metavar="ID", help="replay one case")
    ap.add_argument("--list", action="store_true", help="list the selected cases and exit")
    ap.add_argument("--receipts", metavar="DIR", help="write a JSON receipt into DIR (a new file; never overwrites)")
    ap.add_argument("--metadata-default", metavar="FILE",
                    help="`cargo metadata --format-version 1 --locked --offline` output for the default features")
    ap.add_argument("--metadata-harness", metavar="FILE",
                    help="the same with `--features franken-speaker/harness`; both or neither: P01-BLK-007 is judged "
                         "from the pair, and stays BLOCKED (counted, not skipped) without them")
    args = ap.parse_args(argv)
    if bool(args.metadata_default) != bool(args.metadata_harness):
        print("error: --metadata-default and --metadata-harness go together; one alone cannot be judged and is not "
              "silently ignored", file=sys.stderr)
        return 2
    metadata_inputs = ({"default": args.metadata_default, "harness": args.metadata_harness}
                       if args.metadata_default else {})
    try:
        selected = select(all_cases(), args.tier, args.case)
        invariants = load_json(CASES_FILE)["invariants"]
    except CaseError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.list:
        for c in selected:
            print(f"{c['id']}  {c['kind']:<18} {c['title']}")
        return 0
    results: List[Dict[str, Any]] = []
    for c in selected:
        if c["kind"] == "metadata_real":
            c = dict(c, _inputs=metadata_inputs)
        try:
            status, detail = HANDLERS[c["kind"]](c)
        except CaseError as err:
            status, detail = FAIL, str(err)
        except Exception as err:  # noqa: BLE001 - a crashing case is a failed case, never a pass
            status, detail = FAIL, f"{type(err).__name__}: {err}"
        results.append({"id": c["id"], "kind": c["kind"], "status": status, "detail": detail})
        label = {PASS: "PASS", FAIL: "FAIL", BLOCKED: "BLOCKED"}[status]
        print(f"{label:<8}{c['id']:<14} {c['title']}" + (f" -- {detail}" if detail else ""))
    passed = sum(r["status"] == PASS for r in results)
    failed = sum(r["status"] == FAIL for r in results)
    blocked = sum(r["status"] == BLOCKED for r in results)
    counts: Dict[str, int] = {}
    for inv in invariants:
        counts[inv["status"]] = counts.get(inv["status"], 0) + 1
    qualified = failed == 0 and blocked == 0 and not args.case
    print(f"P01 cases: tier={args.tier} total={len(results)} passed={passed} failed={failed} blocked={blocked} | "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
          + (" -> QUALIFIED" if qualified else " -> NOT QUALIFIED"))
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        run_id = f"{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
        path = os.path.join(args.receipts, f"p01-cases-{args.tier}-{run_id}.json")
        doc = contract()
        receipt = {
            "schema": "ffw.p01.case_receipt.v1", "kind": "host_check", "run_id": run_id, "tier": args.tier,
            "command": [sys.executable, "tests/p01/run_cases.py", "--tier", args.tier]
            + (["--case", args.case] if args.case else []),
            "contract_digest": ref.digest(doc), "vectors_digest": sha256_bytes(_read_bytes(VECTORS_FILE)),
            "facts_digest": facts_mod.facts_digest(facts_mod.extract(REPO)),
            "python": sys.version.split()[0],
            "metadata_inputs": _metadata_receipt(metadata_inputs),
            "totals": {"total": len(results), "passed": passed, "failed": failed, "blocked": blocked},
            "results": results,
            "boundary": "host check: reads manifests, the lockfile and the tree; builds, boots and contacts nothing",
        }
        with open(path, "x", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"receipt: {path}")
    if failed:
        return 1
    if blocked:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
