#!/usr/bin/env python3
"""Build, boot, and verify BE-MIPS and BE-PowerPC initramfs images under QEMU.

Covers:
- E07 (ffw-ll1): Repair and qualify reusable BE bootstrap and initramfs test harness
- E03 (ffw-q2p): Legacy kernel ABI capability matrix probes inside full-system guests
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid
from typing import Any

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
import mkinitramfs  # noqa: E402


FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "Warning: unable to open an initial console.",
    "FFW_PANIC",
    "FFW_MARKER:TEST_FAILURE",
    "Kernel panic - not syncing",
)


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_version(cmd: list[str]) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        return (res.stdout or res.stderr).strip().splitlines()[0]
    except Exception as exc:
        return f"unavailable ({exc})"


def capture_guest(command: list[str], env: dict[str, str], timeout: float,
                  max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    """Bound both runtime and retained bytes; kill only our process group.

    Timeout/output-limit prefixes remain diagnostic evidence, never a pass.
    Separate byte streams preserve CRLF and invalid UTF-8 without pretending
    their concatenation establishes ordering between stdout and stderr.
    """
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError("positive capture limits required")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    reason = None
    proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_bytes - sum(map(len, streams.values()))
                    streams[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        reason = "output_limit"
                        break
                if reason:
                    break
            if reason is None:
                try:
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
        finally:
            # On timeout, overflow or interruption terminate the isolated
            # group before reaping its leader. Never signal a reaped PID,
            # which the OS could already have reused for an unrelated job.
            if proc.returncode is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()
    return {"stdout": bytes(streams["stdout"]), "stderr": bytes(streams["stderr"]),
            "returncode": proc.returncode, "stop_reason": reason}


def verify_serial_output(arch: str, expected_hello: str, expected_enosys: str, raw_log: str) -> dict[str, Any]:
    lines = [line.strip() for line in raw_log.splitlines()]
    forbidden_hits = [bad for bad in FORBIDDEN_SUBSTRINGS if bad in raw_log]
    # Parse the exact v1 transcript. Substring matching accepts errno=890 as
    # errno=89, failures=01 as zero, and even shell-echoed markers as execution.
    patterns = {
        "FFW_MARKER:USERSPACE_START": r"FFW_MARKER:USERSPACE_START",
        "FFW_HELLO": re.escape(expected_hello),
        "FFW_KERNEL_VERSION:": r"FFW_KERNEL_VERSION: Linux version \S.*",
        "FFW_TEST:ERR_ENOENT": r"FFW_TEST:ERR_ENOENT status=PASS errno=2",
        "FFW_TEST:ERR_EBADF": r"FFW_TEST:ERR_EBADF status=PASS errno=9",
        "FFW_TEST:ERR_ENOSYS": re.escape(expected_enosys),
        "FFW_TEST:POS_FD_SHORT_WRITE": r"FFW_TEST:POS_FD_SHORT_WRITE status=PASS fd=[0-9]+",
        "FFW_PROBE:CLOCK_MONOTONIC": r"FFW_PROBE:CLOCK_MONOTONIC status=PASS res_ns=[1-9][0-9]*",
        "FFW_PROBE:NONBLOCK_PIPE": r"FFW_PROBE:NONBLOCK_PIPE status=PASS rc=0",
        "FFW_PROBE:POLL": r"FFW_PROBE:POLL status=PASS rc=1",
        "FFW_PROBE:EPOLL": r"FFW_PROBE:EPOLL status=PASS fd=[0-9]+",
        "FFW_PROBE:SOCKET_UDP": r"FFW_PROBE:SOCKET_UDP status=PASS fd=[0-9]+",
        "FFW_PROBE:ENTROPY": r"FFW_PROBE:ENTROPY status=PASS fd=[0-9]+",
        "FFW_PROBE:ATOMICS_32": r"FFW_PROBE:ATOMICS_32 status=PASS ok=1",
        "FFW_MARKER:TEST_SUCCESS": r"FFW_MARKER:TEST_SUCCESS failures=0",
        "FFW_MARKER:REBOOT_REQUEST": r"FFW_MARKER:REBOOT_REQUEST",
    }
    positions: dict[str, int] = {}
    errors = []
    probes = {}
    for idx, line in enumerate(lines):
        if not line.startswith("FFW_"):
            continue
        key = line.split()[0]
        if key in positions:
            errors.append(f"duplicate:{key}")
        else:
            positions[key] = idx
        pattern = patterns.get(key)
        if pattern is None or re.fullmatch(pattern, line) is None:
            errors.append(f"invalid:{key}")
        if line.startswith("FFW_TEST:") or line.startswith("FFW_PROBE:"):
            probes[key] = {
                "raw": line,
                "status": "PASS" if pattern and re.fullmatch(pattern, line) else "FAIL",
            }

    missing = [key for key in patterns if key not in positions]
    idx_start = positions.get("FFW_MARKER:USERSPACE_START", -1)
    idx_success = positions.get("FFW_MARKER:TEST_SUCCESS", -1)
    idx_reboot = positions.get("FFW_MARKER:REBOOT_REQUEST", -1)
    control_markers = {
        "FFW_MARKER:USERSPACE_START", "FFW_MARKER:TEST_SUCCESS", "FFW_MARKER:REBOOT_REQUEST"
    }
    order_ok = 0 <= idx_start < idx_success < idx_reboot and all(
        idx_start < idx < idx_success
        for key, idx in positions.items() if key not in control_markers
    )

    kernel_version = None
    for line in lines:
        if line.startswith("FFW_KERNEL_VERSION: "):
            kernel_version = line[len("FFW_KERNEL_VERSION: ") :]
            break

    passed = (not forbidden_hits) and (not missing) and (not errors) and order_ok
    return {
        "arch": arch,
        "status": "PASS" if passed else "FAIL",
        "kernel_version": kernel_version,
        "forbidden_hits": forbidden_hits,
        "missing_markers": missing,
        "validation_errors": errors,
        "marker_order_ok": order_ok,
        "probes": probes,
    }


def run_verification(args: argparse.Namespace, results_dir: pathlib.Path) -> int:
    build_dir = mkinitramfs.resolve_default_build_dir(REPO_ROOT)

    self_test_receipt = mkinitramfs.self_test()

    hello_crate = SCRIPT_DIR / "ffw-hello-init"
    target_dir = args.target_dir or build_dir / "hello-init-target"

    targets = {
        "mips": {
            "triple": "mips-unknown-linux-musl",
            "hello": "FFW_HELLO arch=mips-be endian=0x01020304 pid=1 ptr_bits=32",
            "enosys": "FFW_TEST:ERR_ENOSYS status=PASS errno=89",
            "boot_script": SCRIPT_DIR / "boot-mips.sh",
            "kernel_path": build_dir / "kernels" / "xm" / "boot" / "vmlinux-4.19.0-21-4kc-malta",
            "qemu_bin": "qemu-system-mips",
        },
        "ppc": {
            "triple": "powerpc-unknown-linux-musl",
            "hello": "FFW_HELLO arch=powerpc-be endian=0x01020304 pid=1 ptr_bits=32",
            "enosys": "FFW_TEST:ERR_ENOSYS status=PASS errno=38",
            "boot_script": SCRIPT_DIR / "boot-ppc.sh",
            "kernel_path": build_dir / "kernels" / "x" / "boot" / "vmlinux-4.9.0-0.bpo.6-powerpc",
            "qemu_bin": "qemu-system-ppc",
        },
    }

    if not args.skip_build:
        for arch, cfg in targets.items():
            cmd = [
                "rch",
                "exec",
                "--source-content-receipt",
                "--",
                "cargo",
                "+nightly",
                "build",
                "--release",
                "--target",
                cfg["triple"],
                "-Z",
                "build-std=core,panic_abort",
            ]
            env = os.environ.copy()
            env["CARGO_TARGET_DIR"] = str(target_dir)
            env["RCH_REQUIRE_REMOTE"] = "1"
            subprocess.run(cmd, cwd=str(hello_crate), env=env, check=True, timeout=3600)

    archive_receipts = {}
    guest_results = {}
    overall_pass = True

    for arch, cfg in targets.items():
        bin_path = target_dir / cfg["triple"] / "release" / "ffw-hello-init"
        initrd_path = results_dir / f"initramfs-{arch}.cpio.gz"
        archive_receipts[arch] = mkinitramfs.build(bin_path, initrd_path)

        t0 = time.monotonic()
        env = os.environ.copy()
        env["FFW_BUILD_DIR"] = str(build_dir)
        env["FFW_INITRAMFS"] = str(initrd_path.resolve())
        capture = capture_guest([str(cfg["boot_script"])], env, args.timeout)
        stdout, stderr, returncode = capture["stdout"], capture["stderr"], capture["returncode"]
        timed_out = capture["stop_reason"] == "timeout"
        elapsed_s = round(time.monotonic() - t0, 3)
        # Preserve exact bytes, including invalid UTF-8 and CRLF, separately.
        # Concatenation below is a parser view, not a cross-stream ordering claim.
        for stream, data in (("stdout", stdout), ("stderr", stderr)):
            with (results_dir / f"boot-{arch}-{stream}.bin").open("xb") as output:
                output.write(data)
        raw_combined = stdout + stderr
        combined = raw_combined.decode("utf-8", errors="replace")
        log_path = results_dir / f"boot-{arch}-serial.log"
        with log_path.open("xb") as output:
            output.write(raw_combined)

        verification = verify_serial_output(arch, cfg["hello"], cfg["enosys"], combined)
        verification.update(
            {
                "qemu_exit_code": returncode,
                "timed_out": timed_out,
                "capture_stop_reason": capture["stop_reason"],
                "capture_byte_limit": 8 * 1024 * 1024,
                "elapsed_seconds": elapsed_s,
                "binary_sha256": sha256_file(bin_path),
                "binary_bytes": bin_path.stat().st_size,
                "initramfs_sha256": archive_receipts[arch]["archive_sha256"],
                "kernel_sha256": sha256_file(cfg["kernel_path"]),
                "serial_log_path": log_path.name,
                "serial_log_sha256": hashlib.sha256(raw_combined).hexdigest(),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "capture_layout": "stdout-then-stderr; separate raw streams retained",
                "qualification_boundary": (
                    "Full-system Debian QEMU guest (Linux 4.19 Malta / Linux 4.9 g3beige); "
                    "proves ISA, endianness, static ELF startup, initramfs device nodes, and "
                    "syscall ABI probes; does not substitute for stock Sonos 2.4/2.6 kernel or "
                    "proprietary audio driver qualification."
                ),
            }
        )
        if capture["stop_reason"] or returncode != 0 or verification["status"] != "PASS":
            verification["status"] = "FAIL"
            overall_pass = False
        guest_results[arch] = verification

    receipt = {
        "schema_version": "ffw.e07_e03.receipt.v1",
        "run_id": args.run_id,
        "status": "PASS" if overall_pass else "FAIL",
        "build_provenance": {
            "status": "not_attested_by_this_boot_runner",
            "note": "Binary hashes bind this boot. Compiler identity requires the separate build receipt; local rustc is not the remote compiler.",
        },
        "local_inspection_tools": {
            "host_rustc_nightly": cmd_version(["rustc", "+nightly", "--version"]),
            "host_lld": cmd_version(["ld.lld", "--version"]),
            "qemu_mips": cmd_version(["qemu-system-mips", "--version"]),
            "qemu_ppc": cmd_version(["qemu-system-ppc", "--version"]),
            "bootstrap_policy_note": (
                "Nightly -Z build-std=core,panic_abort and asm_experimental_arch are scoped "
                "strictly to the freestanding PID-1 bootstrap probe; production application, "
                "protocol, and DSP crates target stable Rust with #![forbid(unsafe_code)]."
            ),
        },
        "mkinitramfs_self_test": self_test_receipt,
        "guests": guest_results,
    }

    receipt_path = results_dir / "e07-e03-verification-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if overall_pass else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Use existing artifacts; do not compile")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-guest QEMU timeout in seconds")
    parser.add_argument("--target-dir", type=pathlib.Path, help="Directory containing target-triple/release artifacts")
    parser.add_argument("--results-dir", type=pathlib.Path, help="New output directory; existing directories are refused")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 3600:
        parser.error("timeout must be positive, finite and no greater than 3600 seconds")
    run_id = args.run_id = uuid.uuid4().hex
    results_dir = args.results_dir or REPO_ROOT / "toolchain" / "results" / "runs" / run_id
    results_dir.mkdir(parents=True, exist_ok=False)
    receipt_path = results_dir / "e07-e03-verification-receipt.json"
    receipt = {"schema_version": "ffw.e07_e03.receipt.v1", "run_id": run_id, "status": "INCOMPLETE"}
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    try:
        return run_verification(args, results_dir)
    except (Exception, KeyboardInterrupt) as exc:
        receipt.update(status="FAIL", error_type=type(exc).__name__)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n")
        print(json.dumps(receipt), file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1


if __name__ == "__main__":
    sys.exit(main())
