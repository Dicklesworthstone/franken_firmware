#!/usr/bin/env python3
"""E04 (ffw-25l): a SECOND, independent derivation of the audioctl and i2c ioctl handler facts.

    anchor_crosscheck.py [ARTIFACT]            exit 0 if the facts agree with tests/e04/anchors/audiodev_m16.json

`anchor_extract.py` decodes the object file's words itself. This script shares no code with it: it reads the text
`llvm-objdump` prints (disassembly and relocations) and recomputes the same facts with its own parser, so a bug in
one decoder cannot make the other agree. It runs only `llvm-objdump` (never the artifact), prints nothing but
agreements, differences and counts, and needs the git-ignored capture, so it is a hand-run tool for whoever holds
it, not part of the offline runner.

The facts compared: the audioctl command-word constants (size clamp, number base and bound), the dispatch table,
the handled and default numbers, and for every handled number the functions its code reaches and the payload words
it touches through the stack frame; and what the i2c stub does.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FACTS = os.path.join(HERE, "anchors", "audiodev_m16.json")
RELATIVE_PATH = os.path.join("captures", "firmware", "57.23-74170-1-16", "rootfs-extracted", "modules", "audiodev.o")
TRIPLE = "--triple=powerpc"

INSN = re.compile(r"^\s+([0-9a-f]+):\s+([A-Za-z_.][\w.]*)\s*(.*)$")
FRAME = re.compile(r"^(\d+),\s*(-?\d+)\(1\)$")
TARGET = re.compile(r"0x([0-9a-f]+)\s*(?:<([^>]*)>)?")
LOADS = {"lwz": 4, "lwzu": 4, "lbz": 1, "lbzu": 1, "lhz": 2, "lhzu": 2, "lha": 2, "lhau": 2}
STORES = {"stw": 4, "stwu": 4, "stb": 1, "stbu": 1, "sth": 2, "sthu": 2}


def objdump() -> str:
    for cand in (os.environ.get("LLVM_OBJDUMP"), shutil.which("llvm-objdump"), "/opt/homebrew/opt/llvm/bin/llvm-objdump"):
        if cand and os.path.isfile(cand):
            return cand
    raise SystemExit("llvm-objdump not found; set LLVM_OBJDUMP")


def run(args: List[str]) -> str:
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(r.stderr)
    return r.stdout


def default_artifact() -> Optional[str]:
    roots = [os.environ.get("FFW_FRANKENSONOS_DIR"), os.path.join(os.path.dirname(REPO), "frankensonos")]
    for root in roots:
        if root and os.path.isfile(os.path.join(root, RELATIVE_PATH)):
            return os.path.join(root, RELATIVE_PATH)
    return None


class Function:
    """The text of one function: address -> (mnemonic, operands, relocation symbol on that address)."""

    def __init__(self, text: str):
        self.insns: Dict[int, Tuple[str, str]] = {}
        self.reloc: Dict[int, str] = {}
        for line in text.splitlines():
            m = INSN.match(line)
            if not m:
                continue
            addr, mnem, rest = int(m.group(1), 16), m.group(2), m.group(3).strip()
            if mnem.startswith("R_PPC_"):
                self.reloc[addr] = rest.split()[-1] if rest else ""
            else:
                self.insns[addr] = (mnem, rest)
        self.order = sorted(self.insns)
        self.lo = self.order[0]

    def callee(self, addr: int, operands: str) -> str:
        if addr in self.reloc:
            sym = self.reloc[addr]
            if sym.startswith("."):
                raise SystemExit(f"a call at {addr:#x} goes through a section symbol {sym}; not modelled")
            return sym
        m = TARGET.search(operands)
        if not m or not m.group(2):
            raise SystemExit(f"a call at {addr:#x} has no symbol: {operands!r}")
        return m.group(2).split("+")[0]

    def walk(self, entry: int) -> Tuple[Set[int], Set[str]]:
        seen: Set[int] = set()
        calls: Set[str] = set()
        todo = [entry]
        while todo:
            pc = todo.pop()
            if pc in seen or pc not in self.insns:
                continue
            seen.add(pc)
            mnem, ops = self.insns[pc]
            tgt = TARGET.search(ops)
            if mnem in ("bl", "bla"):
                calls.add(self.callee(pc, ops))
                todo.append(pc + 4)
            elif mnem in ("b", "ba"):
                if pc in self.reloc:
                    calls.add(self.callee(pc, ops))
                else:
                    todo.append(int(tgt.group(1), 16))
            elif mnem in ("blr", "bctr"):
                pass
            elif mnem in ("bt", "bf", "bc", "bdnz", "bdz", "bdnzt", "bdnzf", "bdzt", "bdzf"):
                todo.append(int(tgt.group(1), 16))
                if not (mnem == "bc" and ops.split(",")[0].strip() in ("20", "21")):
                    todo.append(pc + 4)
            elif mnem.endswith("lr") and mnem.startswith("b"):  # a conditional return: bnelr, beqlr, ...
                todo.append(pc + 4)
            else:
                todo.append(pc + 4)
        return seen, calls

    def frame(self, pcs: Set[int]) -> Tuple[List[str], List[int]]:
        acc, taken = set(), set()
        for pc in pcs:
            mnem, ops = self.insns[pc]
            if mnem in LOADS or mnem in STORES:
                m = FRAME.match(ops)
                if m and 16 <= int(m.group(2)) < 48:
                    width = LOADS.get(mnem) or STORES[mnem]
                    acc.add((int(m.group(2)) - 16, width, "load" if mnem in LOADS else "store"))
            elif mnem == "addi":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 3 and parts[1] == "1" and 16 <= int(parts[2]) < 48:
                    taken.add(int(parts[2]) - 16)
        return [f"{k}{w}@{o}" for o, w, k in sorted(acc)], sorted(taken)


def first(fn: Function, mnem: str, pattern: str, below: int) -> int:
    for addr in fn.order:
        if addr - fn.lo >= below:
            break
        m, ops = fn.insns[addr]
        if m == mnem:
            hit = re.fullmatch(pattern, ops)
            if hit:
                return int(hit.group(1))
    raise SystemExit(f"no `{mnem} {pattern}` in the first {below:#x} bytes")


def main(argv: List[str]) -> int:
    path = argv[0] if argv else default_artifact()
    if not path or not os.path.isfile(path):
        print("artifact not found; pass its path or set FFW_FRANKENSONOS_DIR", file=sys.stderr)
        return 2
    tool = objdump()
    dis = lambda sym: run([tool, "-d", "-r", TRIPLE, "--no-show-raw-insn", f"--disassemble-symbols={sym}", path])
    committed = json.load(open(FACTS, encoding="utf-8"))
    ac, i2c_committed = committed["audioctl_ioctl"], committed["i2c_ioctl"]
    problems: List[str] = []

    # ---- i2c: the whole function is two instructions
    i2c = Function(dis("i2c_device_ioctl"))
    got = [i2c.insns[a] for a in i2c.order]
    if got != [("li", "3, 0"), ("blr", "")] or i2c.reloc:
        problems.append(f"i2c_device_ioctl is {got} with relocations {i2c.reloc}, not `li 3, 0; blr`")
    elif i2c_committed["derived"]["returns_constant"] != 0 or i2c_committed["derived"]["relocations_in_handler"] != 0:
        problems.append("committed i2c facts disagree with li 3, 0; blr")

    # ---- audioctl: constants, table, per-number facts
    fn = Function(dis("audioctl_device_ioctl"))
    clamp = first(fn, "cmplwi", r"7,\s*30,\s*(\d+)", 0x40)
    base = first(fn, "addi", r"0,\s*31,\s*-(\d+)", 0xA0)
    bound = first(fn, "cmplwi", r"7,\s*0,\s*(\d+)", 0xA0)
    want = ac["derived"]
    for name, got_v, exp in (("copy size clamp", clamp, want["copy_size_limit_bytes"]),
                             ("number base", base, want["number_base"]),
                             ("number bound", bound, want["number_window_high"] - want["number_window_low"])):
        if got_v != exp:
            problems.append(f"{name}: llvm-objdump says {got_v}, committed {exp}")

    rodata = run([tool, "-r", TRIPLE, path])
    section = rodata.split("RELOCATION RECORDS FOR [.rodata]:")[1].split("RELOCATION RECORDS FOR")[0]
    rel32 = {int(m.group(1), 16): int(m.group(2), 16) for m in
             re.finditer(r"^([0-9a-f]+)\s+R_PPC_REL32\s+\.text\+0x([0-9a-f]+)\s*$", section, re.M)}
    # The table's address is the nearest `.rodata+0x..` relocation (not `.rodata.str..`) before the one indirect jump.
    indirect = [a for a in fn.order if fn.insns[a][0] == "bctr"]
    if len(indirect) != 1:
        problems.append(f"expected one bctr, found {len(indirect)}")
        indirect = indirect[:1] or [fn.order[-1]]
    before = sorted(a for a, v in fn.reloc.items() if a < indirect[0] and re.fullmatch(r"\.rodata\+0x[0-9a-f]+", v))
    if not before:
        raise SystemExit("no .rodata relocation before the indirect jump")
    table_off = int(fn.reloc[before[-1]].split("+0x")[1], 16)
    entries = bound + 1
    targets = [rel32[table_off + 4 * k] - 4 * k for k in range(entries)]
    mode: Dict[int, int] = {}
    for t in targets:
        mode[t] = mode.get(t, 0) + 1
    default = max(mode, key=lambda t: (mode[t], -t))
    if fn.insns[default] != ("li", "3, -1"):
        problems.append(f"the default target is {fn.insns[default]}, not li 3, -1")

    tail_entry = min(a for a in fn.order if fn.insns[a][0] == "neg" and fn.insns[a][1] == "0, 30")
    tail_pcs, tail_calls = fn.walk(tail_entry)
    handled = []
    for k, target in enumerate(targets):
        if target == default:
            continue
        pcs, calls = fn.walk(target)
        acc, taken = fn.frame(pcs - tail_pcs)
        handled.append(dict(nr=base + k, target=target, calls=sorted(calls - tail_calls), frame_accesses=acc,
                            payload_address_taken_at=taken))
    committed_handled = ac["dispatch"]["handled"]
    if [h["nr"] for h in handled] != [h["nr"] for h in committed_handled]:
        problems.append(f"handled numbers differ: {[h['nr'] for h in handled]} vs {[h['nr'] for h in committed_handled]}")
    else:
        for mine, theirs in zip(handled, committed_handled):
            if mine != theirs:
                problems.append(f"nr {mine['nr']}: llvm-objdump derivation {mine} differs from committed {theirs}")
    if sorted(tail_calls) != ac["common_tail"]["calls"]:
        problems.append(f"common-tail calls {sorted(tail_calls)} vs {ac['common_tail']['calls']}")
    if [base + k for k, t in enumerate(targets) if t == default] != ac["dispatch"]["default_nrs"]:
        problems.append("default numbers differ")

    if problems:
        for p in problems:
            print("DISAGREE:", p, file=sys.stderr)
        return 1
    print(f"agree: i2c stub; audioctl clamp {clamp}, numbers {base}..{base + bound}, {len(handled)} handled "
          f"on {len({h['target'] for h in handled})} distinct targets, {len(targets) - len(handled)} default; "
          f"per-number calls and payload accesses identical to the committed facts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
