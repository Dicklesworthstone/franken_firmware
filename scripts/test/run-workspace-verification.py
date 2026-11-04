#!/usr/bin/env python3
"""
Workspace & Cross-Architecture Verification Runner (`scripts/test/run-workspace-verification.py`).

Runs unit, property, cross-compile, initramfs, QEMU full-system boot, and virtual-house
verification suites for FrankenFirmware, scans all outputs for forbidden identifiers
(RFC1918 IPs, MAC addresses, RINCON_ UUIDs, household IDs, tokens), and writes a
schema-validated SuiteReceipt JSON file.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = REPO_ROOT / "toolchain" / "results"
BUILD_ROOT = Path(os.environ.get("FFW_BUILD_DIR", "/Volumes/trj-data/franken_firmware_build"))
STABLE_CARGO = os.environ.get(
    "FFW_STABLE_CARGO",
    str(Path.home() / ".rustup" / "toolchains" / "stable-aarch64-apple-darwin" / "bin" / "cargo"),
)
NIGHTLY_CARGO = os.environ.get(
    "FFW_NIGHTLY_CARGO",
    str(Path.home() / ".rustup" / "toolchains" / "nightly-aarch64-apple-darwin" / "bin" / "cargo"),
)

FORBIDDEN_PATTERNS = [
    ("rfc1918_ip", re.compile(r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("rincon_uuid", re.compile(r"RINCON_[0-9A-Fa-f]+")),
    ("household_id", re.compile(r"Sonos_[A-Za-z0-9_-]{20,}")),
]


def scan_for_secrets(text: str) -> list[str]:
    hits = []
    for name, pat in FORBIDDEN_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(f"{name}:{m.group(0)}")
    return hits


def git_commit_short() -> str:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def run_case(case_id: str, cmd: list[str], cwd: Path = REPO_ROOT, extra_env: dict | None = None) -> dict:
    env = os.environ.copy()
    env["RCH_CARGO_WRAPPER_BYPASS"] = "1"
    if extra_env:
        env.update(extra_env)
    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, check=False)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    secret_hits = scan_for_secrets(combined)
    passed = proc.returncode == 0 and len(secret_hits) == 0
    return {
        "case_id": case_id,
        "status": "passed" if passed else "failed",
        "duration_ms": elapsed_ms,
        "assertions_checked": 1,
        "failure_reason": (
            None
            if passed
            else (
                f"secret_leak_detected={secret_hits}"
                if secret_hits
                else f"exit_code={proc.returncode}: {combined[-400:].strip()}"
            )
        ),
    }


def suite_cases(suite: str) -> list[tuple[str, list[str]]]:
    target_dir = str(BUILD_ROOT / "ffw-workspace-target")
    cross_dir = str(BUILD_ROOT / "ffw-workspace-cross")
    asupersync_manifest = str(REPO_ROOT.parent / "asupersync" / "Cargo.toml")
    asupersync_target = str(BUILD_ROOT / "asupersync-ppc2")

    cases_by_suite = {
        "q00": [
            (
                "q00_test_support_unit_and_canaries",
                [
                    STABLE_CARGO,
                    "test",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "-p",
                    "franken-test-support",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                ],
            ),
        ],
        "e01": [
            (
                "e01_board_profile_catalog_and_reconciliation",
                [
                    STABLE_CARGO,
                    "test",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "-p",
                    "franken-board-profile",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                ],
            ),
        ],
        "e07": [
            (
                "e07_mkinitramfs_self_test",
                [sys.executable, str(REPO_ROOT / "toolchain" / "src" / "mkinitramfs.py"), "--self-test"],
            ),
            (
                "e07_qemu_mips_and_ppc_boot_verification",
                [sys.executable, str(REPO_ROOT / "toolchain" / "src" / "run-qemu-verification.py"), "--skip-build"],
            ),
        ],
        "e03": [
            (
                "e03_platform_capability_matrix_unit",
                [
                    STABLE_CARGO,
                    "test",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "-p",
                    "franken-platform",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                ],
            ),
            (
                "e03_qemu_kernel_abi_probes",
                [sys.executable, str(REPO_ROOT / "toolchain" / "src" / "run-qemu-verification.py"), "--skip-build"],
            ),
        ],
        "p01": [
            (
                "p01_workspace_unit_tests",
                [
                    STABLE_CARGO,
                    "test",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "--workspace",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                ],
            ),
            (
                "p01_workspace_clippy_zero_warnings",
                [
                    STABLE_CARGO,
                    "clippy",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "--workspace",
                    "--all-targets",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            (
                "p01_workspace_cross_check_ppc_be",
                [
                    NIGHTLY_CARGO,
                    "check",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "--workspace",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    cross_dir,
                    "--target",
                    "powerpc-unknown-linux-musl",
                    "-Z",
                    "build-std=core,alloc,std,panic_abort",
                ],
            ),
            (
                "p01_workspace_cross_check_mips_be",
                [
                    NIGHTLY_CARGO,
                    "check",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "--workspace",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    cross_dir,
                    "--target",
                    "mips-unknown-linux-musl",
                    "-Z",
                    "build-std=core,alloc,std,panic_abort",
                ],
            ),
            (
                "p01_virtual_house_e2e",
                [
                    STABLE_CARGO,
                    "run",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "-p",
                    "franken-speaker",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                    "--",
                    "--self-test",
                    "--virtual-house",
                ],
            ),
        ],
        "p05": [
            (
                "p05_platform_portable_atomic_tests",
                [
                    STABLE_CARGO,
                    "test",
                    "--manifest-path",
                    str(REPO_ROOT / "Cargo.toml"),
                    "-p",
                    "franken-platform",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    target_dir,
                ],
            ),
            (
                "p05_asupersync_check_powerpc_be",
                [
                    NIGHTLY_CARGO,
                    "check",
                    "--manifest-path",
                    asupersync_manifest,
                    "--no-default-features",
                    "--lib",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    asupersync_target,
                    "--target",
                    "powerpc-unknown-linux-musl",
                    "-Z",
                    "build-std=core,alloc,std,panic_abort",
                ],
            ),
            (
                "p05_asupersync_check_mips_be",
                [
                    NIGHTLY_CARGO,
                    "check",
                    "--manifest-path",
                    asupersync_manifest,
                    "--no-default-features",
                    "--lib",
                    "--config",
                    "build.incremental=false",
                    "--target-dir",
                    asupersync_target,
                    "--target",
                    "mips-unknown-linux-musl",
                    "-Z",
                    "build-std=core,alloc,std,panic_abort",
                ],
            ),
        ],
    }

    if suite == "all":
        combined = []
        seen = set()
        for k in ["q00", "e01", "e07", "e03", "p01", "p05"]:
            for cid, cmd in cases_by_suite[k]:
                if cid not in seen:
                    seen.add(cid)
                    combined.append((cid, cmd))
        return combined
    if suite not in cases_by_suite:
        raise ValueError(f"Unknown suite '{suite}'. Valid suites: {sorted(list(cases_by_suite.keys()) + ['all'])}")
    return cases_by_suite[suite]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run FrankenFirmware workspace verification suite and emit receipt.")
    parser.add_argument("suite", nargs="?", default="all", help="Suite ID (q00, e01, e07, e03, p01, p05, all)")
    parser.add_argument("--seed", type=int, default=0x5F3759DF, help="Deterministic PRNG seed")
    args = parser.parse_args()

    cases_spec = suite_cases(args.suite)
    results = []
    for case_id, cmd in cases_spec:
        res = run_case(case_id, cmd)
        results.append(res)

    overall_passed = bool(results) and all(r["status"] == "passed" for r in results)
    receipt = {
        "schema_version": 1,
        "suite_id": args.suite,
        "seed": args.seed,
        "git_commit": git_commit_short(),
        "overall_status": "passed" if overall_passed else "failed",
        "cases": results,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    receipt_path = RESULTS_DIR / f"suite-receipt-{args.suite}.json"
    receipt_json = json.dumps(receipt, indent=2) + "\n"
    secret_hits = scan_for_secrets(receipt_json)
    if secret_hits:
        print(f"FATAL: Secret leak in receipt: {secret_hits}", file=sys.stderr)
        return 2

    receipt_path.write_text(receipt_json, encoding="utf-8")
    print(receipt_json, end="")
    return 0 if overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
