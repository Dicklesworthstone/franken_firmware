"""The P01 build-identity pipeline: a command plan, artifact identity extraction, and receipts.

Nothing in this module runs cargo by itself. `plan_steps` builds the exact command lines a central run
executes (`RCH_REQUIRE_REMOTE=1 rch exec -- cargo ...`, `--locked --offline`, an absolute `--manifest-path`,
a working directory that is not the repository root). `check_plan` holds a plan to those rules. `execute` runs a
plan through an injected executor and writes a versioned receipt that carries the contract digest and, per
artifact, the exact target, triple, profile, SHA-256 and ELF identity read from the built bytes. `check_receipt`
re-verifies a receipt against the contract with the independent reference.

What a receipt proves, so it is not over-read: it records what was built and what the files contain. It is not
an attestation of the remote compiler; the toolchain block is whatever `rustc -vV` printed on the build host.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import reference as ref

RCH = "rch"
BYPASS_ENV = ("RCH_CARGO_WRAPPER_BYPASS", "RCH_ENABLED")
RECEIPT_SCHEMA = "ffw.p01.receipt.v1"
HELLO_REL = "toolchain/src/ffw-hello-init"
WORKSPACE_BUILD_STD = "build-std=core,alloc,std,panic_abort"
HELLO_BUILD_STD = "build-std=core,panic_abort"

Step = Dict[str, Any]
Pair = Tuple[str, str]
Executor = Callable[[List[str], str, Dict[str, str], float], Tuple[int, str]]


def _manifest_for(root: str, crate: str, contract: Dict[str, Any]) -> Tuple[str, str]:
    """(manifest path, directory) of a crate: a member under crates/, or an excluded crate by its path."""
    for rec in list(contract["crates"]) + list(contract["excluded"]):
        if rec["name"] == crate:
            directory = os.path.join(root, rec["path"])
            return os.path.join(directory, "Cargo.toml"), directory
    raise KeyError(crate)


def artifact_path(target_dir: str, artifact: Dict[str, Any]) -> str:
    triple = ref.TARGETS[artifact["target"]][0]
    leaf = artifact["bin"] or artifact["crate"]
    if triple == "host":
        return os.path.join(target_dir, "release", leaf)
    return os.path.join(target_dir, triple, "release", leaf)


def _cargo_features(contract: Dict[str, Any], artifact: Dict[str, Any]) -> List[str]:
    """Cargo flags for the features this artifact's profile enables. A feature with no flag contributes none."""
    profile = next(p for p in contract["profiles"] if p["name"] == artifact["profile"])
    flags = []
    for sel in profile["features"]:
        spec = next((f for f in contract["features"] if f["name"] == sel["feature"]), None)
        if spec and sel["state"] == "enabled" and spec["cargo_feature"]:
            flags.append(f"{spec['owner_crate']}/{spec['cargo_feature']}")
    return sorted(set(flags))


def unbacked_disabled_features(contract: Dict[str, Any], artifact: Dict[str, Any]) -> List[str]:
    """Features the artifact's profile disables that have no Cargo flag: the build cannot actually omit them."""
    profile = next(p for p in contract["profiles"] if p["name"] == artifact["profile"])
    out = []
    for sel in profile["features"]:
        spec = next((f for f in contract["features"] if f["name"] == sel["feature"]), None)
        if spec and sel["state"] == "disabled" and not spec["cargo_feature"]:
            out.append(sel["feature"])
    return sorted(out)


def plan_steps(root: str, cwd: str, target_dir: str, contract: Dict[str, Any]) -> List[Step]:
    """The central command plan. Builds are shared by artifacts that need the identical cargo invocation."""
    root = os.path.realpath(root)
    env = {"RCH_REQUIRE_REMOTE": "1", "CARGO_TARGET_DIR": target_dir}
    steps: List[Step] = [{
        "id": "toolchain", "kind": "toolchain", "artifacts": [], "cwd": cwd, "env": dict(env),
        "argv": [RCH, "exec", "--", "rustc", "+nightly", "-vV"],
    }]
    workspace_manifest = os.path.join(root, "Cargo.toml")
    steps.append({
        "id": "workspace-test", "kind": "test", "artifacts": [], "cwd": cwd, "env": dict(env),
        "argv": [RCH, "exec", "--", "cargo", "test", "--locked", "--offline", "--manifest-path",
                 workspace_manifest, "--workspace", "--config", "build.incremental=false"],
    })
    builds: Dict[Tuple[Any, ...], Step] = {}
    for art in contract["artifacts"]:
        if not art["bin"]:
            continue
        manifest, directory = _manifest_for(root, art["crate"], contract)
        triple, _isa, _machine, is_device = ref.TARGETS[art["target"]]
        is_hello = os.path.relpath(directory, root) == HELLO_REL
        features = _cargo_features(contract, art)
        key = (art["crate"], art["target"], tuple(features))
        if key in builds:
            builds[key]["artifacts"].append(art["id"])
            continue
        argv = [RCH, "exec", "--", "cargo"]
        if is_device:
            argv.append("+nightly")
        argv += ["build", "--locked", "--offline", "--manifest-path", manifest, "--release"]
        if not is_hello:
            argv += ["-p", art["crate"]]
        else:
            # Cargo finds .cargo/config.toml from the working directory, not from the manifest. From another
            # directory the bootstrap probe's linker and flags would be silently dropped, so name the file.
            argv += ["--config", os.path.join(directory, ".cargo", "config.toml")]
        if is_device:
            argv += ["--target", triple, "-Z", HELLO_BUILD_STD if is_hello else WORKSPACE_BUILD_STD]
        if features:
            argv += ["--features", ",".join(features)]
        step = {"id": f"build-{art['crate']}-{art['target']}", "kind": "build", "artifacts": [art["id"]],
                "cwd": cwd, "env": dict(env), "argv": argv}
        builds[key] = step
        steps.append(step)
    return steps


def check_plan(steps: Sequence[Step], root: str, contract: Dict[str, Any]) -> List[Pair]:
    """Rule violations of a plan as sorted (code, step id) pairs. An empty list means the plan is acceptable."""
    root = os.path.realpath(root)
    errs = set()
    by_id = {a["id"]: a for a in contract["artifacts"]}
    for step in steps:
        sid = step["id"]
        argv = step["argv"]
        if argv[:2] != [RCH, "exec"] or "--" not in argv:
            errs.add(("plan_not_remote", sid))
            continue
        inner = argv[argv.index("--") + 1:]
        env = step["env"]
        if env.get("RCH_REQUIRE_REMOTE") != "1":
            errs.add(("plan_require_remote_missing", sid))
        if any(k in env for k in BYPASS_ENV):
            errs.add(("plan_bypass_env", sid))
        cwd = step["cwd"]
        if not os.path.isdir(cwd):
            errs.add(("plan_cwd_missing", sid))
        elif os.path.realpath(cwd) == root:
            errs.add(("plan_cwd_is_root", sid))
        if not inner or inner[0] != "cargo":
            continue
        if "--locked" not in inner:
            errs.add(("plan_missing_locked", sid))
        if "--offline" not in inner:
            errs.add(("plan_missing_offline", sid))
        manifest = inner[inner.index("--manifest-path") + 1] if "--manifest-path" in inner else ""
        if not manifest or not os.path.isabs(manifest) or not os.path.realpath(manifest).startswith(root + os.sep):
            errs.add(("plan_manifest_not_absolute", sid))
        if step["kind"] != "build":
            continue
        for aid in step["artifacts"]:
            art = by_id.get(aid)
            if art is None:
                continue
            if ref.TARGETS[art["target"]][3]:
                triple = ref.TARGETS[art["target"]][0]
                if "--target" not in inner or inner[inner.index("--target") + 1] != triple:
                    errs.add(("plan_device_without_target", sid))
                if "-Z" not in inner or not inner[inner.index("-Z") + 1].startswith("build-std="):
                    errs.add(("plan_device_without_build_std", sid))
        manifest_dir = os.path.dirname(manifest)
        if os.path.isabs(manifest) and os.path.isfile(os.path.join(manifest_dir, ".cargo", "config.toml")):
            wanted = os.path.join(manifest_dir, ".cargo", "config.toml")
            if "--config" not in inner or wanted not in inner:
                errs.add(("plan_config_not_explicit", sid))
    return sorted(errs)


# ------------------------------------------------------------------------------ identity from bytes

def elf_identity(path: str) -> Dict[str, Any]:
    """SHA-256 of the file and, if it is an ELF, its class, byte order and e_machine read from the header."""
    with open(path, "rb") as f:
        data = f.read()
    out: Dict[str, Any] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                           "elf_machine": 0, "elf_class": 0, "elf_big_endian": False}
    if len(data) >= 20 and data[:4] == b"\x7fELF":
        big = data[5] == 2
        out["elf_class"] = data[4]
        out["elf_big_endian"] = big
        out["elf_machine"] = int.from_bytes(data[18:20], "big" if big else "little")
    return out


def observed_row(contract: Dict[str, Any], artifact: Dict[str, Any], ident: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": artifact["id"], "target": artifact["target"], "triple": ref.TARGETS[artifact["target"]][0],
            "profile": artifact["profile"], "sha256": ident["sha256"], "elf_machine": ident["elf_machine"],
            "elf_class": ident["elf_class"], "elf_big_endian": ident["elf_big_endian"],
            "contract_digest": ref.digest(contract)}


def parse_rustc_vv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            if key in ("release", "commit-hash", "host", "LLVM version"):
                out[key] = val.strip()
    return out


# ------------------------------------------------------------------------------ receipts

def _utc(now: Optional[float] = None) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))


def _write_new(receipts_dir: str, run_id: str) -> str:
    os.makedirs(receipts_dir, exist_ok=True)
    path = os.path.join(receipts_dir, f"p01-{run_id}.json")
    with open(path, "xb"):  # exclusive create: an earlier receipt is never overwritten
        pass
    return path


def _save(path: str, receipt: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def execute(steps: Sequence[Step], contract: Dict[str, Any], root: str, target_dir: str, receipts_dir: str,
            executor: Executor, lock_sha256: str = "", timeout: float = 7200.0,
            now: Callable[[], float] = time.time) -> Tuple[int, str, Dict[str, Any]]:
    """Run a plan, write the receipt after every step, and verify the artifacts it produced.

    Returns (exit code, receipt path, receipt). Exit 0 only when every step succeeded and the artifact identities
    verify against the contract. A cancelled run leaves a receipt marked `incomplete` and exits 130."""
    run_id = f"{_utc(now())}-{secrets.token_hex(4)}"
    path = _write_new(receipts_dir, run_id)
    by_id = {a["id"]: a for a in contract["artifacts"]}
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA, "kind": "build_identity", "run_id": run_id, "status": "incomplete",
        "contract_digest": ref.digest(contract), "lock_sha256": lock_sha256,
        "plan": [{"id": s["id"], "kind": s["kind"], "argv": list(s["argv"]), "artifacts": list(s["artifacts"])}
                 for s in steps],
        "steps": [], "toolchain": {}, "artifacts": [], "unbacked_disabled_features": {},
        "verification": {"codes": [], "pairs": []},
        "boundary": ("Records what a build host built and what the files contain. Not an attestation of the "
                     "remote compiler; evidence kind is a build, not a guest execution or a physical result."),
    }
    _save(path, receipt)
    code = 0
    try:
        for step in steps:
            started = now()
            rc, output = executor(list(step["argv"]), step["cwd"], dict(step["env"]), timeout)
            record = {"id": step["id"], "rc": rc, "seconds": round(now() - started, 3),
                      "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
                      "status": "ok" if rc == 0 else "failed"}
            receipt["steps"].append(record)
            if step["kind"] == "toolchain" and rc == 0:
                receipt["toolchain"] = parse_rustc_vv(output)
            if step["kind"] == "build" and rc == 0:
                for aid in step["artifacts"]:
                    art = by_id[aid]
                    built = artifact_path(target_dir, art)
                    if not os.path.isfile(built):
                        record["status"] = "failed"
                        record["note"] = "build reported success but the artifact file is absent"
                        continue
                    receipt["artifacts"].append(observed_row(contract, art, elf_identity(built)))
                    receipt["unbacked_disabled_features"][aid] = unbacked_disabled_features(contract, art)
            _save(path, receipt)
            if record["status"] != "ok":
                code = 1
        pairs = ref.verify_observed(contract, receipt["artifacts"], require_all=False)
        receipt["verification"] = {"codes": ref.codes(pairs), "pairs": [list(p) for p in pairs]}
        complete = (code == 0 and not pairs and {a["id"] for a in contract["artifacts"] if a["bin"]}
                    == {r["id"] for r in receipt["artifacts"]})
        receipt["status"] = "complete" if complete else "failed"
        if not complete:
            code = code or 1
        _save(path, receipt)
        return code, path, receipt
    except KeyboardInterrupt:
        receipt["status"] = "incomplete"
        receipt["interrupted_after"] = [s["id"] for s in receipt["steps"]]
        _save(path, receipt)
        return 130, path, receipt


def check_receipt(contract: Dict[str, Any], receipt: Dict[str, Any]) -> List[Pair]:
    """Re-verify a receipt against the contract. Sorted (code, subject) pairs; empty means it holds up."""
    errs = set()
    if receipt.get("schema") != RECEIPT_SCHEMA:
        errs.add(("receipt_schema", "receipt"))
        return sorted(errs)
    if receipt.get("contract_digest") != ref.digest(contract):
        errs.add(("receipt_digest_mismatch", "receipt"))
    try:
        rows = ref.parse_observed(receipt.get("artifacts", []))
    except ref.ParseError:
        errs.add(("receipt_row_incomplete", "artifacts"))
        return sorted(errs)
    pairs = ref.verify_observed(contract, rows, require_all=False)
    errs.update(pairs)
    if receipt.get("verification", {}).get("codes") != ref.codes(pairs):
        errs.add(("receipt_verification_stale", "verification"))
    if receipt.get("status") == "complete":
        failed = [s["id"] for s in receipt.get("steps", []) if s.get("rc") != 0 or s.get("status") != "ok"]
        if failed or pairs:
            errs.add(("receipt_status_inconsistent", "status"))
        wanted = {a["id"] for a in contract["artifacts"] if a["bin"]}
        if wanted != {r["id"] for r in rows}:
            errs.add(("receipt_status_inconsistent", "artifacts"))
    return sorted(errs)
