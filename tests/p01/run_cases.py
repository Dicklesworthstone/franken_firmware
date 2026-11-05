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

import facts as facts_mod  # noqa: E402
import fixtures  # noqa: E402
import plan as plan_mod  # noqa: E402
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
    for s in steps:
        if s["env"]["RCH_REQUIRE_REMOTE"] != "1" or s["env"]["CARGO_TARGET_DIR"] != target_dir:
            raise CaseError(f"step {s['id']}: environment {s['env']}")
        if os.path.realpath(s["cwd"]) == root:
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
    elif kind == "relative_manifest":
        i = target["argv"].index("--manifest-path")
        target["argv"][i + 1] = "Cargo.toml"
    elif kind == "cwd_root":
        target["cwd"] = root
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

def fake_elf(machine: int, payload: bytes, big: bool = True, klass: int = 1) -> bytes:
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = klass
    header[5] = 2 if big else 1
    header[18:20] = machine.to_bytes(2, "big" if big else "little")
    return bytes(header) + payload


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
        if scenario == "cancel" and len(calls) == 3:
            raise KeyboardInterrupt
        if step["kind"] == "toolchain":
            return 0, RUSTC_VV
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
            if scenario == "universal" and art["crate"] == "franken-speaker" and art["target"] != "host":
                machine, payload = 8, b"identical-bytes"
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(fake_elf(machine, payload) if art["target"] != "host" else b"\xcf\xfa\xed\xfe" + payload)
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
    on_disk = json.load(open(path, encoding="utf-8"))
    if on_disk != receipt:
        raise CaseError("the receipt on disk differs from the one returned")
    if receipt["contract_digest"] != sha256_bytes(ref.canonical_json(doc).encode("utf-8")):
        raise CaseError("receipt contract_digest is not the canonical digest of the contract")
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
    before = open(first_path, "rb").read()
    if first_receipt["status"] != "incomplete" or [s["id"] for s in first_receipt["steps"]] != \
            ["toolchain", "workspace-test"]:
        raise CaseError(f"the cancelled receipt is not an honest partial: {first_receipt['status']}")
    doc, steps, code, path2, receipt2, _ = _run_scenario("ok", receipts_dir, target_dir)
    if path2 == first_path or code != 0 or receipt2["status"] != "complete":
        raise CaseError("the restart did not produce a separate complete receipt")
    if open(first_path, "rb").read() != before:
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
    text = open(RUST_FILE, encoding="utf-8").read()
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
        text = open(path, encoding="utf-8").read()
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
    source = open(os.path.join(HERE, "reference.py"), encoding="utf-8").read()
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


def run_runner_selftest(c) -> Result:
    out = subprocess.run([sys.executable, "-B", "-m", "unittest", "test_p01"], cwd=HERE, capture_output=True,
                         text=True, timeout=300)
    match = re.search(r"^Ran (\d+) tests?", out.stderr, re.M)
    ran = int(match.group(1)) if match else 0
    if out.returncode != 0 or not re.search(r"^OK\s*$", out.stderr, re.M):
        raise CaseError("unit tests failed: " + " ".join(out.stderr.split())[-200:])
    if ran < c["min_tests"]:
        raise CaseError(f"only {ran} unit tests ran, expected at least {c['min_tests']}")
    return PASS, f"{ran} unit tests"


def run_blocked(c) -> Result:
    return BLOCKED, f"{c['reason']} [owner: {c['owner']}]"


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "vector": run_vector, "contract_valid": run_contract_valid, "drift_real": run_drift_real,
    "facts_cwd": run_facts_cwd, "drift_planted": run_drift_planted, "plan_exact": run_plan_exact,
    "plan_rules": run_plan_rules, "plan_sharing": run_plan_sharing, "receipt": run_receipt,
    "receipt_tamper": run_receipt_tamper, "meta_invariants": run_meta_invariants, "meta_codes": run_meta_codes,
    "meta_hygiene": run_meta_hygiene, "meta_vectors_current": run_meta_vectors_current,
    "mutation_canary": run_mutation_canary, "runner_selftest": run_runner_selftest, "blocked": run_blocked,
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


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="P01 host-side case runner",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--tier", required=True, choices=TIERS, help="explicit; there is no default")
    ap.add_argument("--case", metavar="ID", help="replay one case")
    ap.add_argument("--list", action="store_true", help="list the selected cases and exit")
    ap.add_argument("--receipts", metavar="DIR", help="write a JSON receipt into DIR (a new file; never overwrites)")
    args = ap.parse_args(argv)
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
            "contract_digest": ref.digest(doc), "vectors_digest": sha256_bytes(open(VECTORS_FILE, "rb").read()),
            "facts_digest": facts_mod.facts_digest(facts_mod.extract(REPO)),
            "python": sys.version.split()[0],
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
