#!/usr/bin/env python3
"""The P01 build-identity pipeline CLI (bead ffw-h3g).

    pipeline.py print-plan [--cwd DIR] [--target-dir DIR]
    pipeline.py collect    --target-dir DIR [--receipts DIR]
    pipeline.py execute    [--cwd DIR] [--target-dir DIR] [--receipts DIR] [--timeout SECONDS]
    pipeline.py check-metadata --default FILE --harness FILE
    pipeline.py ingest     --revision REV --export-root DIR --target-dir DIR --step ID=LOG [--step ...] [--out DIR]

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

ingest       Turn the raw rch logs of a central run into a sanitized evidence record bound to a revision (the logs
             name the worker's address and local paths and are never committed). Each step's remote command is checked
             against the plan, its exit status and the toolchain, test totals and artifact identity are read from the
             logs and the built files. Writes toolchain/results/p01/rev-<rev12>/receipt.json exclusively. Runs no cargo.

Exit codes: 0 receipt complete; 1 a step or an identity check failed; 3 collect found only some artifacts
(incomplete, never reported as complete); 130 cancelled (a partial receipt is left); 2 usage error.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
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

import central  # noqa: E402
import facts as facts_mod  # noqa: E402
import metadata_check  # noqa: E402
import plan as plan_mod  # noqa: E402
import reference as ref  # noqa: E402

CONTRACT_REL = "crates/franken-board-profile/tests/vectors/p01_workspace_contract.json"
CONTRACT_FILE = os.path.join(REPO, *CONTRACT_REL.split("/"))
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


def _git_show(revision: str, path: str) -> bytes:
    out = subprocess.run(["git", "show", f"{revision}:{path}"], cwd=REPO, capture_output=True, timeout=60)
    if out.returncode != 0:
        raise OSError(f"git show {revision[:12]}:{path} failed: {out.stderr.decode('utf-8', 'replace').strip()[:160]}")
    return out.stdout


def cmd_ingest(args) -> int:
    try:
        resolved = subprocess.run(["git", "rev-parse", "--verify", f"{args.revision}^{{commit}}"], cwd=REPO,
                                  capture_output=True, text=True, timeout=60)
        if resolved.returncode != 0:
            raise OSError(f"{args.revision} is not a commit of this repository")
        revision = resolved.stdout.strip()
        doc = json.loads(_git_show(revision, CONTRACT_REL).decode("utf-8"))
        ref.parse_contract(doc)
        lock_sha256 = hashlib.sha256(_git_show(revision, "Cargo.lock")).hexdigest()
        # The replay tests are recorded BY NAME from the workspace-test log, bound to the test file and the vectors as they
        # were at this revision, so P01-BLK-003 can tell a run of the current replay from a run of an older one.
        test_source = _git_show(revision, central.REPLAY_TEST_FILE)
        replay_sources = {"names": central.rust_test_names(test_source.decode("utf-8")),
                          "test_file_sha256": hashlib.sha256(test_source).hexdigest(),
                          "vectors_sha256": hashlib.sha256(_git_show(revision, central.REPLAY_VECTORS_FILE)).hexdigest()}
    except (OSError, ValueError, ref.ParseError) as err:
        print(f"cannot bind the evidence to {args.revision}: {err}", file=sys.stderr)
        return 2
    export_root = os.path.realpath(args.export_root)
    target_dir = os.path.realpath(args.target_dir)
    steps = plan_mod.plan_steps(export_root, os.path.join(export_root, "crates", "franken-board-profile"),
                                target_dir, doc)
    known = {s["id"] for s in steps}
    logs = {}
    for spec in args.step:
        sid, _, path = spec.partition("=")
        if sid not in known or not path:
            print(f"--step {spec!r}: expected ID=LOGFILE with ID one of {sorted(known)}", file=sys.stderr)
            return 2
        if sid in logs:
            print(f"--step {sid} given twice", file=sys.stderr)
            return 2
        try:
            with open(path, "rb") as f:
                logs[sid] = f.read().decode("utf-8", "replace")
        except OSError as err:
            print(f"cannot read the log for {sid}: {err}", file=sys.stderr)
            return 2
    attested: Dict[str, Dict[str, str]] = {}
    for spec in args.attest_env:
        sid, _, pair = spec.partition("=")
        key, eq, value = pair.partition("=")
        if sid not in known or not eq or not key:
            print(f"--attest-env {spec!r}: expected STEP=KEY=VALUE", file=sys.stderr)
            return 2
        attested.setdefault(sid, {})[key] = value
    rows, missing, sizes = [], [], {}
    for art in doc["artifacts"]:
        if not art["bin"]:
            continue
        built = plan_mod.artifact_path(target_dir, art)
        if not os.path.isfile(built):
            missing.append(art["id"])
            continue
        ident = plan_mod.elf_identity(built)
        rows.append(plan_mod.observed_row(doc, art, ident))
        sizes[art["id"]] = ident["size"]
    evidence = central.build_evidence(doc, steps, logs, revision, lock_sha256, export_root, rows, missing, sizes,
                                      attested, replay_sources=replay_sources)
    out_dir = os.path.join(args.out or os.path.join(REPO, central.EVIDENCE_GLOB_DIR), f"rev-{revision[:12]}")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "receipt.json")
    try:
        with open(path, "x", encoding="utf-8") as f:
            json.dump(evidence, f, indent=1, sort_keys=True)
            f.write("\n")
    except FileExistsError:
        print(f"refusing to overwrite an earlier record: {path}", file=sys.stderr)
        return 2
    bad = [s for s in evidence["steps"] if s["status"] == "failed"]
    print(f"ingest: revision {revision[:12]}, {sum(s['status'] == 'ok' for s in evidence['steps'])} ok, "
          f"{len(bad)} failed, {sum(s['status'] == 'not_run' for s in evidence['steps'])} not run; "
          f"{len(rows)} artifact(s), {len(missing)} missing; verification {evidence['verification']['codes']}")
    for s in bad:
        print(f"  FAILED {s['id']}: exit {s.get('exit')}; {'; '.join(s.get('problems', []))}")
    print(f"record: {path}")
    return 1 if bad or evidence["verification"]["codes"] else 0


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
    ing = sub.add_parser("ingest")
    ing.add_argument("--revision", required=True)
    ing.add_argument("--export-root", required=True, help="the directory the run exported the revision to")
    ing.add_argument("--target-dir", required=True, help="the CARGO_TARGET_DIR the run used")
    ing.add_argument("--step", action="append", default=[], metavar="ID=LOG", help="a plan step id and its raw rch log")
    ing.add_argument("--attest-env", action="append", default=[], metavar="STEP=KEY=VALUE",
                     help="an environment variable the supervisor set for a step; logs do not show the environment")
    ing.add_argument("--out", help="directory holding rev-<rev12>/receipt.json (default: toolchain/results/p01)")
    meta = sub.add_parser("check-metadata")
    meta.add_argument("--default", required=True)
    meta.add_argument("--harness", required=True)
    args = ap.parse_args(argv)
    try:
        return {"print-plan": cmd_print_plan, "collect": cmd_collect, "execute": cmd_execute,
                "check-metadata": cmd_check_metadata, "ingest": cmd_ingest}[args.command](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
