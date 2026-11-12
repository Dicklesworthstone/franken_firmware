#!/usr/bin/env python3
"""Run an already-built S02 probe offline; qualify guest function, not CPU fit.

No Cargo or network is invoked. The input ELF/kernel are frozen into a fresh
output directory and all logs, including failed/timeout runs, are retained.
The independent transcript check deliberately emits no instruction count while
the guest reports unresolved counter wrap. See --help for explicit inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

KERNEL_SHA = "3803357ef7821dbf691c901105fb9b2b00382abf67fce8a4be2a0d592267dc61"
MARKER = b"ffw-s02-qemu-only-v1\n"
MAX_FILE = 64 * 1024 * 1024
MAX_LOG = 2 * 1024 * 1024
SPINS = {3: (1300000, 5000000, 12000000, 20000000),
         5: (800000, 3000000, 7200000, 12000000)}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def read_input(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FILE:
            raise ValueError("input must be a bounded nonempty regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1  # The file object now owns the descriptor, including on error.
            data = stream.read(MAX_FILE + 1)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
                raise ValueError("input changed during capture")
            return data
    finally:
        if fd >= 0:
            os.close(fd)


def frozen(path: Path, data: bytes) -> str:
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o444)
    return hashlib.sha256(data).hexdigest()


def require_static_mips(data: bytes) -> None:
    if len(data) < 52 or data[:6] != b"\x7fELF\x01\x02":
        raise ValueError("truncated or non-BE ELF32 header")
    header = struct.unpack(">16sHHIIIIIHHHHHH", data[:52])
    if header[1:4] != (2, 8, 1) or header[8] != 52:
        raise ValueError("not an executable MIPS ELF version 1")
    offset, stride, count = header[5], header[9], header[10]
    if not 1 <= count <= 1024 or stride != 32 or offset + stride * count > len(data):
        raise ValueError("invalid program header table")
    for index in range(count):
        kind, start, _, _, size, _, _, _ = struct.unpack_from(">IIIIIIII", data, offset + stride * index)
        if kind == 3:
            raise ValueError("dynamic interpreter is not in the initramfs")
        if start + size > len(data):
            raise ValueError("truncated ELF segment")


def pairs(text: str) -> dict[str, str]:
    found = list(re.finditer(r"(\w+)=(\[[^\]]*\]|\S+)", text))
    out: dict[str, str] = {}
    cursor = 0
    for match in found:
        if text[cursor:match.start()].strip() or match[1] in out:
            raise ValueError("malformed or duplicate field")
        out[match[1]] = match[2]
        cursor = match.end()
    if text[cursor:].strip():
        raise ValueError("unparsed marker text")
    return out


def number(value: str, maximum: int = (1 << 64) - 1) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("noncanonical unsigned integer")
    result = int(value)
    if result > maximum:
        raise ValueError("integer outside bound")
    return result


def check_transcript(stdout: str, stderr: str, exit_code: int) -> dict:
    if exit_code != 0:
        raise ValueError(f"QEMU exit {exit_code}")
    if any(token in stdout + stderr for token in (
            "Kernel panic", "Attempted to kill init", "FFW_S02COST_FAIL",
            "FFW_S02COST_REFUSED", "FFW_S02COST_FLUSH_FAILED", "FFW_S02COST_REBOOT_FAILED")):
        raise ValueError("guest failure marker")
    # Guest observations must come from its serial stdout, never stderr.
    if "FFW_S02COST_" in stderr:
        raise ValueError("S02 marker on unexpected stream")
    phase = "start"
    empty: dict[str, list[int]] = {}
    rulers: set[tuple[str, int, int, int]] = set()
    runs: list[dict] = []
    ended_at = -1
    for index, raw in enumerate(stdout.splitlines()):
        if "FFW_S02COST_" not in raw:
            continue
        match = re.fullmatch(r"FFW_S02COST_([A-Z_]+)(?: (.*))?", raw.strip())
        if not match:
            raise ValueError("malformed or prefixed S02 marker")
        kind, rest = match[1], match[2] or ""
        fields = pairs(rest)
        if kind == "ALIVE" and phase == "start" and not fields:
            phase = "alive"
        elif kind == "BEGIN" and phase == "alive" and fields == {
                "version": "1", "codec": "mp3_48000", "frames_expected": "24000", "reps": "3",
                "input_fnv": "da1589c2833424c5", "reference_fnv": "46a8dd21d7b5b39e"}:
            phase = "measurements"
        elif kind == "EMPTY" and phase == "measurements" and set(fields) == {"phase", "ticks"}:
            name = fields["phase"]
            if name not in ("before", "after") or name in empty:
                raise ValueError("duplicate or invalid empty-read phase")
            ticks = json.loads(fields["ticks"])
            if not isinstance(ticks, list) or len(ticks) != 8 or any(
                    type(x) is not int or not 0 <= x <= 0xffffffff for x in ticks):
                raise ValueError("invalid empty-read samples")
            empty[name] = ticks
        elif kind == "RULER" and phase == "measurements" and set(fields) == {
                "phase", "rep", "shape", "iterations", "ticks"}:
            key = (fields["phase"], number(fields["rep"], 1), number(fields["shape"], 5),
                   number(fields["iterations"], 20000000))
            if key not in {(p, r, s, n) for p in ("before", "after") for r in range(2)
                           for s, sizes in SPINS.items() for n in sizes} or key in rulers:
                raise ValueError("duplicate or invalid ruler")
            if number(fields["ticks"], 0xffffffff) == 0:
                raise ValueError("zero ruler ticks")
            rulers.add(key)
        elif kind == "RUN" and phase == "measurements" and set(fields) == {
                "rep", "frames", "blocks", "pull_ticks_sum", "pull_ticks_max", "eof_ticks",
                "peak_lsb", "sum_sq_lsb", "samples"}:
            run = {k: number(v) for k, v in fields.items()}
            if run["rep"] != len(runs) or run["rep"] > 2:
                raise ValueError("missing, duplicate or unordered run")
            if run["frames"] != 24000 or run["samples"] != 48000 or not 0 < run["blocks"] < 1000:
                raise ValueError("incomplete decode")
            if run["peak_lsb"] > 4 or run["sum_sq_lsb"] * 4 > run["samples"] * 9:
                raise ValueError("PCM oracle failed")
            if not 0 < run["pull_ticks_max"] <= 0xffffffff or not (
                    run["pull_ticks_max"] <= run["pull_ticks_sum"] <= run["blocks"] * 0xffffffff
                    and run["eof_ticks"] <= 0xffffffff):
                raise ValueError("invalid raw counter samples")
            runs.append(run)
        elif kind == "END" and phase == "measurements" and fields == {
                "checked_reps": "3", "counter_wrap_unresolved": "1", "stack_unmeasured": "1",
                "allocator_unmeasured": "1"}:
            phase, ended_at = "ended", index
        else:
            raise ValueError("unexpected, contradictory or repeated S02 record")
    if phase != "ended" or len(runs) != 3 or set(empty) != {"before", "after"} or len(rulers) != 32:
        raise ValueError("incomplete guest evidence")
    if not any(re.fullmatch(r"(?:\[\s*[0-9]+(?:\.[0-9]+)?\]\s*)?(?:reboot: )?Restarting system\.?", line.strip())
               for line in stdout.splitlines()[ended_at + 1:]):
        raise ValueError("no observed kernel restart after END")
    return {"functional_passed": True, "runs": runs, "ruler_records": len(rulers),
            "instruction_count_qualified": False, "counter_wrap_unresolved": True,
            "not_qualified": ["Sonos hardware", "provider sessions", "CPU/RAM/stack budgets",
                              "real-time deadlines", "instruction count"]}


def capture(command: list[str], output: Path, timeout: float) -> tuple[int, str]:
    """Bound bytes and wall time; own and terminate only this QEMU process group."""
    if not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        raise ValueError("safe non-reaping child observation requires waitid/WNOWAIT")
    started = time.monotonic()
    reason = "completed"
    with (output / "serial.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        selector = None
        try:
            selector = selectors.DefaultSelector()
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            sizes = {stdout: 0, stderr: 0}
            while selector.get_map():
                if time.monotonic() - started >= timeout:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(0.1, timeout)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = MAX_LOG - sizes[key.data]
                    key.data.write(data[:remaining])
                    sizes[key.data] += min(len(data), remaining)
                    if len(data) > remaining:
                        reason = "output_limit"
                        break
                if reason != "completed":
                    break
            if reason == "completed":
                # Keep even an exited leader unreaped until its group is
                # retired. Otherwise its numeric PID/PGID could be reused.
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    if time.monotonic() - started >= timeout:
                        reason = "timeout"
                        break
                    time.sleep(.01)
        finally:
            if selector is not None:
                selector.close()
            # Pipes can close after the leader exits while an owned descendant
            # remains. Retire our whole isolated group on every completion path.
            retirement_failed = False
            try:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Darwin returns EPERM for a group containing only zombies.
                    # The unreaped leader pins the ID. Accept this case only
                    # after a bounded OS snapshot proves EVERY member is dead;
                    # dead members cannot fork between the snapshot and reap.
                    if sys.platform != "darwin" or os.waitid(
                            os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                        raise
                    observation = subprocess.run(
                        ["/bin/ps", "-g", str(process.pid), "-o", "pid=,pgid=,stat="],
                        capture_output=True, text=True, timeout=2, check=False)
                    members = [line.split() for line in observation.stdout.splitlines()]
                    if observation.returncode or not members or not any(
                            row[0] == str(process.pid) for row in members) or any(
                            len(row) != 3 or row[1] != str(process.pid) or not row[2].startswith("Z")
                            for row in members):
                        raise
            except OSError:
                retirement_failed = True
                raise
            finally:
                try:
                    if retirement_failed:
                        # The leader has not been reaped; direct fallback may
                        # target only this owned child, never a recycled PID.
                        try:
                            os.kill(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                finally:
                    try:
                        process.wait(timeout=2)
                    finally:
                        if process.stdout is not None:
                            process.stdout.close()
                        if process.stderr is not None:
                            process.stderr.close()
    return process.returncode, reason


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True, help="frozen source checkout for existing ELF/initramfs helpers")
    parser.add_argument("--output-dir", type=Path, required=True, help="must not exist")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--qemu", default="qemu-system-mips")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("timeout must be between one and 600 seconds")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    result = {"schema": "ffw.s02-guest-functional.v1", "functional_passed": False}
    try:
        elf_bytes, kernel_bytes = read_input(args.elf), read_input(args.kernel)
        result["elf_sha256"] = frozen(args.output_dir / "init", elf_bytes)
        result["kernel_sha256"] = frozen(args.output_dir / "kernel", kernel_bytes)
        require_static_mips(elf_bytes)
        if result["kernel_sha256"] != KERNEL_SHA:
            raise ValueError("kernel does not match retained full digest")
        helper = args.repo / "toolchain/src/measure-d02-cost.py"
        builder = args.repo / "toolchain/src/mkinitramfs.py"
        result["helper_sha256"] = frozen(args.output_dir / "elf-helper.py", read_input(helper))
        result["builder_sha256"] = frozen(args.output_dir / "archive-helper.py", read_input(builder))
        d02 = load(args.output_dir / "elf-helper.py", "s02_d02_elf")
        try:
            elf = d02.read_elf(args.output_dir / "init")
        except d02.MeasurementError as error:
            raise ValueError("ELF helper refused input: " + str(error)) from error
        if elf["fp_abi"] != 3 or elf["fpu_words"] or elf["e_type"] != 2:
            raise ValueError("probe must be ELF32 BE MIPS executable with soft-float ABI and no FPU opcodes")
        mk = load(args.output_dir / "archive-helper.py", "s02_initramfs")
        archive = args.output_dir / "initramfs.cpio.gz"
        result["archive"] = mk.build(args.output_dir / "init", archive,
                                     extra_files=[("ffw-s02-qemu-pid1", 0o100644, MARKER)], exclusive=True)
        version = subprocess.run([args.qemu, "--version"], capture_output=True, text=True,
                                 timeout=5, check=True)
        result["qemu_version"] = version.stdout.splitlines()[0]
        command = [args.qemu, "-M", "malta", "-cpu", "24Kf", "-m", "64M", "-nographic",
                   "-no-reboot", "-nic", "none", "-icount", "shift=0,align=off,sleep=off",
                   "-kernel", str(args.output_dir / "kernel"), "-initrd", str(archive),
                   "-append", "console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3"]
        result["command"] = command
        code, reason = capture(command, args.output_dir, args.timeout)
        result.update(exit_code=code, completion_reason=reason)
        for name in ("serial.log", "stderr.log"):
            result[name + "_sha256"] = hashlib.sha256((args.output_dir / name).read_bytes()).hexdigest()
        if reason != "completed":
            raise ValueError("QEMU " + reason)
        result.update(check_transcript((args.output_dir / "serial.log").read_text(errors="strict"),
                                      (args.output_dir / "stderr.log").read_text(errors="strict"), code))
    except (OSError, ValueError, IndexError, KeyError, struct.error, subprocess.SubprocessError) as error:
        result["error"] = str(error)[:1500]
    with (args.output_dir / "result.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result))
    return 0 if result["functional_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
