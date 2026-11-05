#!/usr/bin/env python3
"""Check the instruction ruler under QEMU WITHOUT building anything: a hand-assembled big-endian MIPS32 ELF.

The D02 cost measurement (toolchain/src/measure-d02-cost.py) rests on three claims about the guest, and this probe
tests them on the real kernel and QEMU, in about a minute, with no compiler: it writes ~700 machine-code words by
hand from the MIPS32 instruction formats, packs them as the guest's /init, and boots it.

  1. `rdhwr $2` (the CP0 Count) works from user space on the Debian 4.19 Malta kernel.
  2. With `-icount shift=0`, ticks are proportional to instructions executed (loops of exactly 3 and 5 instructions
     per iteration give the same ticks per instruction), once the loops are long enough (about 5 M instructions).
  3. The scale (instructions per tick) is NOT a constant: it differs from boot to boot, so it must be calibrated in
     the same boot as the measurement.

It measures first and prints last, because the guest's slow serial port otherwise raises transmit interrupts that land
inside the next timed loop. The ruler loops here are the same shapes as the guest benchmark's. Nothing about D02 is
measured here.

    FFW_BUILD_DIR=<kernel cache> python3 toolchain/src/d02-cost/ruler_probe.py --log-dir <fresh dir> [--boots 2]
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent

R = {"zero": 0, "v0": 2, "a0": 4, "a1": 5, "a2": 6, "t0": 8, "t1": 9, "t2": 10, "t3": 11, "t6": 14, "t7": 15, "t8": 24,
     "sp": 29}
NOP = 0x00000000
SYSCALL = 0x0000000C


def _i(op: int, rs: str, rt: str, imm: int) -> int:
    return (op << 26) | (R[rs] << 21) | (R[rt] << 16) | (imm & 0xFFFF)


def _r(rs: str, rt: str, rd: str, sa: int, funct: int) -> int:
    return (R[rs] << 21) | (R[rt] << 16) | (R[rd] << 11) | (sa << 6) | funct


def addiu(rt, rs, imm): return _i(0x09, rs, rt, imm)
def lui(rt, imm): return _i(0x0F, "zero", rt, imm)
def ori(rt, rs, imm): return _i(0x0D, rs, rt, imm)
def andi(rt, rs, imm): return _i(0x0C, rs, rt, imm)
def xori(rt, rs, imm): return _i(0x0E, rs, rt, imm)
def sltiu(rt, rs, imm): return _i(0x0B, rs, rt, imm)
def sb(rt, off, base): return _i(0x28, base, rt, off)
def sw(rt, off, base): return _i(0x2B, base, rt, off)
def lw(rt, off, base): return _i(0x23, base, rt, off)
def bne(rs, rt, off_words): return _i(0x05, rs, rt, off_words)
def subu(rd, rs, rt): return _r(rs, rt, rd, 0, 0x23)
def addu(rd, rs, rt): return _r(rs, rt, rd, 0, 0x21)
def srl(rd, rt, sa): return _r("zero", rt, rd, sa, 0x02)
def sll(rd, rt, sa): return _r("zero", rt, rd, sa, 0x00)
def rdhwr(rt, hwr): return 0x7C00003B | (R[rt] << 16) | (hwr << 11)


def spin(iterations: int, shape: int) -> list[int]:
    """Read the Count, run a loop of exactly `shape * iterations` instructions, read it again; leave the delta in $t3."""
    code = [lui("t1", iterations >> 16), ori("t1", "t1", iterations & 0xFFFF), rdhwr("t0", 2)]
    if shape == 3:      # addiu, bne, and the nop in its delay slot
        code += [addiu("t1", "t1", -1), bne("t1", "zero", -2), NOP]
    else:               # addiu, two cancelling addiu, bne, nop
        code += [addiu("t1", "t1", -1), addiu("t7", "t7", 1), addiu("t7", "t7", -1), bne("t1", "zero", -4), NOP]
    return code + [rdhwr("t2", 2), subu("t3", "t2", "t0")]


def print_word(k: int) -> list[int]:
    """Print the k-th stored delta as 8 hex digits and a newline with write(1, ...)."""
    code = [lw("t3", 32 + 4 * k, "sp")]
    for i in range(8):
        code += [srl("t6", "t3", 28 - 4 * i), andi("t6", "t6", 0xF), sltiu("t7", "t6", 10), xori("t7", "t7", 1),
                 sll("t8", "t7", 3), subu("t8", "t8", "t7"), addu("t6", "t6", "t8"), addiu("t6", "t6", 0x30),
                 sb("t6", i, "sp")]
    return code + [addiu("t6", "zero", 10), sb("t6", 8, "sp"), addiu("v0", "zero", 4004), addiu("a0", "zero", 1),
                   addu("a1", "sp", "zero"), addiu("a2", "zero", 9), SYSCALL]


def program(sizes: list[tuple[int, int]]) -> list[int]:
    """Measure everything first (results kept on the stack), print afterwards, then power the guest off."""
    code = [addiu("sp", "sp", -(32 + 4 * len(sizes) + 8))]
    for k, (shape, iterations) in enumerate(sizes):
        code += spin(iterations, shape) + [sw("t3", 32 + 4 * k, "sp")]
    for k in range(len(sizes)):
        code += print_word(k)
    return code + [lui("a0", 0xFEE1), ori("a0", "a0", 0xDEAD), lui("a1", 0x2812), ori("a1", "a1", 0x1969),
                   lui("a2", 0x0123), ori("a2", "a2", 0x4567), addiu("v0", "zero", 4088), SYSCALL, bne("zero", "zero", 0), NOP]


def elf(code: list[int]) -> bytes:
    """A static ELF32 big-endian MIPS executable with one RWX segment holding `code`."""
    text = b"".join(struct.pack(">I", word) for word in code)
    base, entry_offset = 0x400000, 52 + 32
    header = struct.pack(">16sHHIIIIIHHHHHH", b"\x7fELF" + bytes([1, 2, 1]) + bytes(9), 2, 8, 1, base + entry_offset, 52, 0,
                         0x70001000, 52, 32, 1, 40, 0, 0)
    segment = struct.pack(">IIIIIIII", 1, 0, base, base, entry_offset + len(text), entry_offset + len(text), 7, 0x1000)
    return header + segment + text


# Three repetitions of five sizes per shape: 0.3 to 48 million instructions, 441 M in all.
SIZES = [(shape, n) for _ in range(3) for shape, sizes in ((3, (100_000, 400_000, 1_600_000, 6_400_000, 16_000_000)),
                                                         (5, (60_000, 240_000, 960_000, 3_840_000, 9_600_000)))
         for n in sizes]


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def boot(initramfs: pathlib.Path, kernel: pathlib.Path, timeout: float) -> str:
    command = ["qemu-system-mips", "-M", "malta", "-cpu", "24Kf", "-m", "64M", "-nographic", "-no-reboot",
               "-icount", "shift=0,align=off,sleep=off", "-kernel", str(kernel), "-initrd", str(initramfs),
               "-append", "console=ttyS0,38400 rdinit=/init panic=-1 loglevel=3"]
    done = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout,
                          stdin=subprocess.DEVNULL, check=False)
    return done.stdout


def measurements(serial: str) -> list[int]:
    lines = (line.strip() for line in serial.replace("\r", "").split("\n"))
    return [int(line, 16) for line in lines if len(line) == 8 and all(c in "0123456789ABCDEF" for c in line)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--log-dir", type=pathlib.Path, required=True, help="fresh directory for the raw serial logs")
    parser.add_argument("--boots", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args(argv)
    build = os.environ.get("FFW_BUILD_DIR")
    if not build:
        print("error: FFW_BUILD_DIR must contain kernels/xm/boot/", file=sys.stderr)
        return 2
    if args.log_dir.exists() and any(args.log_dir.iterdir()):
        print(f"error: {args.log_dir} is not empty; choose a fresh directory (nothing is deleted)", file=sys.stderr)
        return 2
    args.log_dir.mkdir(parents=True, exist_ok=True)
    kernel = pathlib.Path(build) / "kernels" / "xm" / "boot" / "vmlinux-4.19.0-21-4kc-malta"
    mkinitramfs = _load("mkinitramfs_for_probe", SRC / "mkinitramfs.py")
    runner = _load("measure_d02_cost_for_probe", SRC / "measure-d02-cost.py")
    status = 0
    with tempfile.TemporaryDirectory() as scratch:
        probe = pathlib.Path(scratch) / "probe.elf"
        probe.write_bytes(elf(program(SIZES)))
        packed = pathlib.Path(scratch) / "probe.cpio.gz"
        mkinitramfs.build(probe, packed)
        for index in range(args.boots):
            serial = boot(packed, kernel, args.timeout)
            (args.log_dir / f"ruler-probe-boot{index}.serial.log").write_text(serial)
            ticks = measurements(serial)
            if len(ticks) != len(SIZES):
                print(f"boot {index}: {len(ticks)} measurements, expected {len(SIZES)}; the guest did not finish")
                status = 1
                continue
            fit = runner.fit_ruler([(shape, n, t) for (shape, n), t in zip(SIZES, ticks)])
            problems = runner.ruler_problems(fit)
            print(f"boot {index}: {fit['instructions_per_tick']:.4f} instructions per tick; loop shapes disagree by "
                  f"{fit['shape_disagreement']:.4%}; gates: {'pass' if not problems else problems}")
            status = status or (1 if problems else 0)
    print("the scale differs from boot to boot, which is why the benchmark calibrates in the boot it measures in")
    return status


if __name__ == "__main__":
    sys.exit(main())
