#!/usr/bin/env python3
"""The P01 build-identity pipeline CLI (bead ffw-h3g).

    pipeline.py print-plan [--cwd DIR] [--target-dir DIR]
    pipeline.py collect    --target-dir DIR [--receipts DIR]
    pipeline.py execute    [--cwd DIR] [--target-dir DIR] [--receipts DIR] [--timeout SECONDS]
    pipeline.py check-metadata --default FILE --harness FILE

print-plan   Print the central command plan as JSON and check it against the plan rules. Runs nothing.
collect      Read the artifacts a central build already produced under --target-dir, extract their identity from
             the bytes (SHA-256, ELF class, byte order, machine), verify it against the contract, write a receipt.
             Runs no cargo.
execute      Run the plan: every step is `RCH_REQUIRE_REMOTE=1 rch exec -- ...`; there is no local-cargo path and
             no bypass. Then collect and verify. A step that outlives --timeout is NOT killed (killing the local rch
             client would orphan or cancel the remote job); it is recorded as failed with its pid and left running.

check-metadata  Read two `cargo metadata --format-version 1` documents produced centrally (default features, and
             `--features franken-speaker/harness`) and check the gate from their resolve graphs: no normal edge onto
             `franken-test-support` by default, and exactly that edge added with the harness. Runs no cargo.

Exit codes: 0 receipt complete; 1 a step or an identity check failed; 3 collect found only some artifacts
(incomplete, never reported as complete); 130 cancelled (a partial receipt is left); 2 usage error.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import secrets
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import facts as facts_mod  # noqa: E402
import metadata_check  # noqa: E402
import plan as plan_mod  # noqa: E402
import reference as ref  # noqa: E402

CONTRACT_FILE = os.path.join(REPO, "crates", "franken-board-profile", "tests", "vectors", "p01_workspace_contract.json")
DEFAULT_TARGET_DIR = os.path.join(REPO, "build", "p01-target")
DEFAULT_RECEIPTS = os.path.join(REPO, "build", "p01-receipts")


def load_contract() -> Dict[str, Any]:
    with open(CONTRACT_FILE, encoding="utf-8") as f:
        doc = json.load(f)
    ref.parse_contract(doc)
    return doc


def default_cwd() -> str:
    """A working directory inside the repository that is not its root: the point is that nothing may depend on cwd."""
    return os.path.join(REPO, "crates", "franken-board-profile")


def lock_sha(root: str) -> str:
    return facts_mod.extract(root)["lock"]["sha256"]


def subprocess_executor(logs_dir: str):
    os.makedirs(logs_dir, exist_ok=True)

    def run(argv: List[str], cwd: str, env: Dict[str, str], timeout: float) -> Tuple[int, str]:
        merged = {k: v for k, v in os.environ.items() if k not in plan_mod.BYPASS_ENV}
        merged.update(env)
        log_path = os.path.join(logs_dir, f"{secrets.token_hex(4)}.log")
        try:
            with open(log_path, "wb") as log:
                proc = subprocess.Popen(argv, cwd=cwd, env=merged, stdout=log, stderr=subprocess.STDOUT)
                try:
                    rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    return 124, f"timed out after {timeout}s; pid {proc.pid} left running, log {log_path}"
        except FileNotFoundError as err:
            return 127, f"cannot start {argv[0]!r}: {err}"
        with open(log_path, "rb") as log:
            return rc, log.read().decode("utf-8", "replace")
    return run


def cmd_print_plan(args) -> int:
    doc = load_contract()
    cwd = os.path.realpath(args.cwd or default_cwd())
    steps = plan_mod.plan_steps(REPO, cwd, os.path.realpath(args.target_dir or DEFAULT_TARGET_DIR), doc)
    problems = plan_mod.check_plan(steps, REPO, doc)
    print(json.dumps({"contract_digest": ref.digest(doc), "steps": steps,
                      "violations": [list(p) for p in problems]}, indent=1))
    return 1 if problems else 0


def cmd_collect(args) -> int:
    doc = load_contract()
    target_dir = os.path.realpath(args.target_dir or DEFAULT_TARGET_DIR)
    rows, missing, unbacked = [], [], {}
    for art in doc["artifacts"]:
        if not art["bin"]:
            continue
        path = plan_mod.artifact_path(target_dir, art)
        if not os.path.isfile(path):
            missing.append(art["id"])
            continue
        rows.append(plan_mod.observed_row(doc, art, plan_mod.elf_identity(path)))
        unbacked[art["id"]] = plan_mod.unbacked_disabled_features(doc, art)
    pairs = ref.verify_observed(doc, rows, require_all=False)
    status = "failed" if pairs else ("incomplete" if missing else "complete")
    receipt = {
        "schema": plan_mod.RECEIPT_SCHEMA, "kind": "build_identity", "run_id": "", "status": status,
        "contract_digest": ref.digest(doc), "lock_sha256": lock_sha(REPO), "plan": [], "steps": [],
        "toolchain": {}, "artifacts": rows, "unbacked_disabled_features": unbacked, "missing": missing,
        "verification": {"codes": ref.codes(pairs), "pairs": [list(p) for p in pairs]},
        "boundary": "Collected from existing files; no build was run by this command. Not an attestation of how or "
                    "where they were built, and not a guest-execution or physical result.",
    }
    run_id = f"{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
    receipt["run_id"] = run_id
    path = plan_mod._write_new(args.receipts or DEFAULT_RECEIPTS, run_id)
    plan_mod._save(path, receipt)
    print(f"collect: {len(rows)} artifact(s) read, {len(missing)} missing {missing}, status {status}")
    for code, subject in pairs:
        print(f"  {code} [{subject}]")
    print(f"receipt: {path}")
    return 1 if pairs else (3 if missing else 0)


def cmd_execute(args) -> int:
    doc = load_contract()
    cwd = os.path.realpath(args.cwd or default_cwd())
    target_dir = os.path.realpath(args.target_dir or DEFAULT_TARGET_DIR)
    steps = plan_mod.plan_steps(REPO, cwd, target_dir, doc)
    problems = plan_mod.check_plan(steps, REPO, doc)
    if problems:
        print("refusing to run a plan that breaks its own rules:", file=sys.stderr)
        for code, subject in problems:
            print(f"  {code} [{subject}]", file=sys.stderr)
        return 1
    receipts = args.receipts or DEFAULT_RECEIPTS
    code, path, receipt = plan_mod.execute(steps, doc, REPO, target_dir, receipts,
                                           subprocess_executor(os.path.join(receipts, "logs")),
                                           lock_sha256=lock_sha(REPO), timeout=args.timeout)
    print(f"execute: status {receipt['status']}, {len(receipt['steps'])} step(s), "
          f"{len(receipt['artifacts'])} artifact row(s), verification {receipt['verification']['codes']}")
    print(f"receipt: {path}")
    return code


def cmd_check_metadata(args) -> int:
    try:
        pairs = metadata_check.check(metadata_check.load(args.default), metadata_check.load(args.harness))
    except (OSError, ValueError) as err:
        print(f"cannot read the metadata documents: {err}", file=sys.stderr)
        return 2
    for code, subject in pairs:
        print(f"{code} [{subject}]")
    print("check-metadata: " + ("the gate holds in both resolve graphs" if not pairs else f"{len(pairs)} violation(s)"))
    return 1 if pairs else 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="P01 build-identity pipeline", epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("print-plan", "collect", "execute"):
        p = sub.add_parser(name)
        p.add_argument("--target-dir")
        if name != "collect":
            p.add_argument("--cwd")
        if name != "print-plan":
            p.add_argument("--receipts")
        if name == "execute":
            p.add_argument("--timeout", type=float, default=7200.0)
    meta = sub.add_parser("check-metadata")
    meta.add_argument("--default", required=True)
    meta.add_argument("--harness", required=True)
    args = ap.parse_args(argv)
    try:
        return {"print-plan": cmd_print_plan, "collect": cmd_collect, "execute": cmd_execute,
                "check-metadata": cmd_check_metadata}[args.command](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
