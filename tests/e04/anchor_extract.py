#!/usr/bin/env python3
"""E04 (ffw-25l) anchor-fact extractor for the retained model-16 audiodev.o.

    anchor_extract.py ARTIFACT [--write FACTS.json | --check FACTS.json]

Reads the artifact offline (never executes it) and prints the facts the E04 contract rests on:
the artifact digest and section sizes, the ioctl handler symbols, the dsp ioctl dispatch table, and
the decoded fields of the few instructions that fix the argument layout (size field, size clamp,
direction bits, number bound). Output is numbers, names and offsets only. No firmware bytes are
written: an instruction is reported as the numbers it decodes to, never as its encoding.

The artifact is a git-ignored capture in the owner's frankensonos checkout. Its location comes from
the command line or the FFW_FRANKENSONOS_DIR environment variable; nothing here pins a path.

For the other two handlers it reports: `i2c_device_ioctl` (what its two instructions do), and for
`audioctl_device_ioctl` the same command-word facts as `dsp`, its dispatch table, and for every handled
number the external functions its code reaches and the payload words it touches directly through the stack
frame. Those last two come from a control-flow walk over decoded branch instructions; the function names are
the object file's own symbol names. They are evidence about WHAT CODE a number reaches, never a statement of
what it means.

What the facts do NOT establish: which ioctl implements which HAL operation, any per-command
payload layout (the stack-frame accesses are a lower bound: a payload reached through a pointer held in a
register is not seen), or any behavior on a real board. Those stay unknown in the contract matrix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from typing import Any, Dict, List, Tuple

SCHEMA = "ffw.e04.anchor_facts.v1"
EXPECTED_SHA256 = "14c202fa115ffde39dcdfa5a6505ea1ead9ed41b89429c9dd319b47a61939bd2"
RELATIVE_PATH = os.path.join("captures", "firmware", "57.23-74170-1-16", "rootfs-extracted", "modules", "audiodev.o")

R_PPC_ADDR16_LO = 4
R_PPC_REL24 = 10
R_PPC_REL32 = 26


class AnchorError(Exception):
    pass


def default_artifact_path(repo: str) -> str | None:
    """The sibling frankensonos checkout's capture, if FFW_FRANKENSONOS_DIR or ../frankensonos has it."""
    candidates = []
    env = os.environ.get("FFW_FRANKENSONOS_DIR")
    if env:
        candidates.append(env)
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(repo)), "frankensonos"))
    for root in candidates:
        path = os.path.join(root, RELATIVE_PATH)
        if os.path.isfile(path):
            return path
    return None


def parse_elf32_be(data: bytes) -> Dict[str, Any]:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 2:
        raise AnchorError("not an ELF32 big-endian file")
    (e_type, e_machine, _ver, _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum,
     shentsize, shnum, shstrndx) = struct.unpack(">HHIIIIIHHHHHH", data[16:52])
    if e_machine != 20:
        raise AnchorError(f"e_machine {e_machine} is not PowerPC (20)")
    sections: List[Dict[str, Any]] = []
    for i in range(shnum):
        base = shoff + i * shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack(">IIIIIIIIII", data[base:base + 40])
        sections.append(dict(index=i, name_off=name, type=typ, flags=flags, offset=off, size=size,
                             link=link, info=info, entsize=entsize))
    shstr = sections[shstrndx]

    def cstr(table_off: int, rel: int) -> str:
        start = table_off + rel
        return data[start:data.index(b"\0", start)].decode("ascii")

    for s in sections:
        s["name"] = cstr(shstr["offset"], s["name_off"])
    by_name = {s["name"]: s for s in sections if s["name"]}
    symbols: List[Dict[str, Any]] = []
    symtab = by_name[".symtab"]
    strtab = sections[symtab["link"]]
    for k in range(symtab["size"] // 16):
        base = symtab["offset"] + 16 * k
        st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack(">IIIBBH", data[base:base + 16])
        symbols.append(dict(name=cstr(strtab["offset"], st_name), value=st_value, size=st_size,
                            info=st_info, shndx=st_shndx))
    relocs: Dict[str, List[Tuple[int, int, int, int]]] = {}
    for s in sections:
        if s["type"] != 4:  # SHT_RELA
            continue
        target = sections[s["info"]]["name"]
        out = []
        for k in range(s["size"] // 12):
            r_offset, r_info, r_addend = struct.unpack(">IIi", data[s["offset"] + 12 * k:s["offset"] + 12 * k + 12])
            out.append((r_offset, r_info & 0xFF, r_info >> 8, r_addend))
        relocs[target] = out
    return dict(sections=sections, by_name=by_name, symbols=symbols, relocs=relocs)


def word_at(data: bytes, elf: Dict[str, Any], section: str, offset: int) -> int:
    s = elf["by_name"][section]
    if offset < 0 or offset + 4 > s["size"]:
        raise AnchorError(f"{section}+{offset:#x} is outside the section")
    return struct.unpack(">I", data[s["offset"] + offset:s["offset"] + offset + 4])[0]


def decode(word: int) -> Dict[str, int | str]:
    """Decode only the instruction forms the layout claims rest on, into field numbers."""
    op = word >> 26
    if op == 11:  # cmpi
        return dict(op="cmpwi", crf=(word >> 23) & 7, ra=(word >> 16) & 31, imm=_s16(word))
    if op == 10:  # cmpli
        return dict(op="cmplwi", crf=(word >> 23) & 7, ra=(word >> 16) & 31, imm=word & 0xFFFF)
    if op == 21:  # rlwinm
        return dict(op="rlwinm", rs=(word >> 21) & 31, ra=(word >> 16) & 31, sh=(word >> 11) & 31,
                    mb=(word >> 6) & 31, me=(word >> 1) & 31)
    if op == 29:  # andis.
        return dict(op="andis.", rs=(word >> 21) & 31, ra=(word >> 16) & 31, imm=word & 0xFFFF)
    if op == 14:  # addi
        return dict(op="addi", rt=(word >> 21) & 31, ra=(word >> 16) & 31, imm=_s16(word))
    if op == 16:  # bc
        bd = word & 0xFFFC
        if bd & 0x8000:
            bd -= 0x10000
        return dict(op="bc", bo=(word >> 21) & 31, bi=(word >> 16) & 31, disp=bd, aa=(word >> 1) & 1)
    if op == 31 and ((word >> 1) & 0x3FF) == 444:  # or / mr
        return dict(op="or", rs=(word >> 21) & 31, ra=(word >> 16) & 31, rb=(word >> 11) & 31)
    if op == 31 and ((word >> 1) & 0x3FF) == 104:  # neg
        return dict(op="neg", rt=(word >> 21) & 31, ra=(word >> 16) & 31)
    if op == 19 and ((word >> 1) & 0x3FF) == 16:  # bclr / blr
        return dict(op="bclr", bo=(word >> 21) & 31, bi=(word >> 16) & 31, lk=word & 1)
    return dict(op=f"opcode{op}")


def _s16(word: int) -> int:
    v = word & 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


# Checkpoints inside dsp_device_ioctl: (offset from the symbol, the decoded fields it must have).
# Each is one instruction the argument layout rests on; the extractor refuses to emit facts if any
# differs, so a different build of the driver cannot silently inherit these numbers.
DSP_CHECKPOINTS: List[Tuple[str, int, Dict[str, int | str]]] = [
    ("cmd_is_negative_test", 0x00, dict(op="cmpwi", crf=7, ra=5, imm=0)),
    ("cmd_register_copy", 0x1C, dict(op="or", rs=5, ra=31, rb=5)),
    ("arg_register_copy", 0x24, dict(op="or", rs=6, ra=30, rb=6)),
    ("skip_copy_in_unless_negative", 0x38, dict(op="bc", bo=4, bi=28, disp=0x5C, aa=0)),
    ("copy_in_size_field", 0x3C, dict(op="rlwinm", rs=31, ra=5, sh=16, mb=19, me=31)),
    ("copy_in_size_clamp", 0x40, dict(op="cmplwi", crf=7, ra=5, imm=16)),
    ("number_bound", 0x94, dict(op="cmplwi", crf=7, ra=28, imm=41)),
    ("read_bit_test", 0x14C, dict(op="andis.", rs=31, ra=0, imm=0x4000)),
    ("copy_out_size_field", 0x190, dict(op="rlwinm", rs=31, ra=0, sh=16, mb=19, me=31)),
    ("copy_out_size_clamp_default", 0x194, dict(op="addi", rt=5, ra=0, imm=16)),
]
JUMP_TABLE_RELOC_OFFSET = 0xA2  # the R_PPC_ADDR16_LO that loads the table address, from the symbol
JUMP_TABLE_ENTRIES = 42  # number_bound + 1

# Checkpoints inside audioctl_device_ioctl, same rule as above: each is an instruction a fact rests on, and the
# extractor refuses to emit facts if one differs. Offsets are from the symbol.
AUDIOCTL_CHECKPOINTS: List[Tuple[str, int, Dict[str, int | str]]] = [
    ("cmd_is_negative_test", 0x00, dict(op="cmpwi", crf=7, ra=5, imm=0)),
    ("number_is_low_byte", 0x1C, dict(op="rlwinm", rs=5, ra=31, sh=0, mb=24, me=31)),
    ("skip_copy_in_unless_negative", 0x24, dict(op="bc", bo=4, bi=28, disp=0x60, aa=0)),
    ("copy_in_size_field", 0x28, dict(op="rlwinm", rs=5, ra=30, sh=16, mb=19, me=31)),
    ("copy_in_size_clamp", 0x2C, dict(op="cmplwi", crf=7, ra=30, imm=32)),
    ("number_base", 0x84, dict(op="addi", rt=0, ra=31, imm=-6)),
    ("number_bound", 0x88, dict(op="cmplwi", crf=7, ra=0, imm=149)),
    ("no_copy_in_size_default", 0x8C, dict(op="addi", rt=30, ra=0, imm=32)),
    ("out_of_range_to_default", 0x90, dict(op="bc", bo=12, bi=29, disp=0x48, aa=0)),
    ("common_tail_entry", 0x20C, dict(op="neg", rt=0, ra=30)),
    ("read_bit_test", 0x214, dict(op="rlwinm", rs=26, ra=9, sh=2, mb=31, me=31)),
    ("copy_out_size_field", 0x220, dict(op="rlwinm", rs=26, ra=4, sh=16, mb=19, me=31)),
    ("copy_out_size_clamp", 0x224, dict(op="addi", rt=30, ra=0, imm=32)),
]
AUDIOCTL_TABLE_RELOC_OFFSET = 0x9A  # the R_PPC_ADDR16_LO that loads the table address, from the symbol
AUDIOCTL_DEFAULT_CHECK = dict(op="addi", rt=3, ra=0, imm=-1)  # the block every unhandled number goes to: li 3, -1
FRAME_PAYLOAD_LO, FRAME_PAYLOAD_HI = 16, 48  # r1 + 16 .. r1 + 48: the copied-in payload (clamp 32)
I2C_EXPECTED = [dict(op="addi", rt=3, ra=0, imm=0), dict(op="bclr", bo=20, bi=0, lk=0)]  # li 3, 0 ; blr

# D-form loads and stores: opcode -> (width in bytes, kind).
FRAME_ACCESS_OPS = {32: (4, "load"), 33: (4, "load"), 34: (1, "load"), 35: (1, "load"), 40: (2, "load"),
                    41: (2, "load"), 42: (2, "load"), 43: (2, "load"), 36: (4, "store"), 37: (4, "store"),
                    38: (1, "store"), 39: (1, "store"), 44: (2, "store"), 45: (2, "store")}


def flow(word: int) -> Dict[str, Any]:
    """How an instruction moves control: only the branch forms; everything else falls through."""
    op = word >> 26
    if op == 18:  # b, bl, ba, bla
        li = word & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
        return dict(kind="call" if word & 1 else "jump", disp=li, absolute=bool((word >> 1) & 1))
    if op == 16:  # bc, bcl
        bd = word & 0xFFFC
        if bd & 0x8000:
            bd -= 0x10000
        return dict(kind="cond", disp=bd, absolute=bool((word >> 1) & 1), link=bool(word & 1),
                    always=((word >> 21) & 31) in (20, 21))
    if op == 19:
        xo, bo = (word >> 1) & 0x3FF, (word >> 21) & 31
        if xo == 16:  # bclr
            return dict(kind="return" if bo == 20 else "cond_return")
        if xo == 528:  # bcctr
            return dict(kind="indirect")
    return dict(kind="seq")


def containing_function(elf: Dict[str, Any], addr: int) -> str:
    """The name of the .text function symbol that contains the .text offset `addr`."""
    text = elf["by_name"][".text"]["index"]
    best = None
    for s in elf["symbols"]:
        if s["name"] and s["shndx"] == text and (s["info"] & 0xF) == 2 and s["value"] <= addr < s["value"] + max(s["size"], 1):
            best = s["name"]
    if best is None:
        raise AnchorError(f".text+{addr:#x} is inside no function symbol")
    return best


class Handler:
    """One function in .text: its instruction words, its relocations, and a walk over its control flow."""

    def __init__(self, data: bytes, elf: Dict[str, Any], sym: Dict[str, Any]):
        self.elf, self.lo, self.hi = elf, sym["value"], sym["value"] + sym["size"]
        self.words = {pc: word_at(data, elf, ".text", pc) for pc in range(self.lo, self.hi, 4)}
        self.rel24 = {r[0]: r for r in elf["relocs"][".text"] if self.lo <= r[0] < self.hi and r[1] == R_PPC_REL24}

    def callee(self, pc: int, disp: int, absolute: bool) -> str:
        if pc in self.rel24:
            _off, _typ, idx, addend = self.rel24[pc]
            name = self.elf["symbols"][idx]["name"]
            return name if name else containing_function(self.elf, addend)
        return containing_function(self.elf, disp if absolute else pc + disp)

    def walk(self, entry: int) -> Tuple[set, set]:
        """(reached instruction offsets, names of the functions called on the way) from `entry`, within the function."""
        seen, calls, todo = set(), set(), [entry]
        while todo:
            pc = todo.pop()
            if pc in seen or not (self.lo <= pc < self.hi):
                continue
            seen.add(pc)
            f = flow(self.words[pc])
            kind = f["kind"]
            if kind == "call":
                calls.add(self.callee(pc, f["disp"], f["absolute"]))
                todo.append(pc + 4)
            elif kind == "jump":
                if pc in self.rel24:  # a tail call to another function
                    calls.add(self.callee(pc, f["disp"], f["absolute"]))
                else:
                    todo.append(f["disp"] if f["absolute"] else pc + f["disp"])
            elif kind == "cond":
                if f["link"]:
                    raise AnchorError(f"a conditional call at .text+{pc:#x} is not modelled")
                todo.append(f["disp"] if f["absolute"] else pc + f["disp"])
                if not f["always"]:
                    todo.append(pc + 4)
            elif kind == "cond_return":
                todo.append(pc + 4)
            elif kind in ("return", "indirect"):
                pass
            else:
                todo.append(pc + 4)
        return seen, calls

    def frame_accesses(self, pcs: set) -> Tuple[List[str], List[int]]:
        """Direct loads and stores through r1 into the copied-in payload, and where its address is taken."""
        acc, taken = set(), set()
        for pc in pcs:
            w = self.words[pc]
            op, ra, d = w >> 26, (w >> 16) & 31, _s16(w)
            if ra == 1 and FRAME_PAYLOAD_LO <= d < FRAME_PAYLOAD_HI:
                if op in FRAME_ACCESS_OPS:
                    width, kind = FRAME_ACCESS_OPS[op]
                    acc.add((d - FRAME_PAYLOAD_LO, width, kind))
                elif op == 14:  # addi rt, r1, d: the payload's address is passed on or kept
                    taken.add(d - FRAME_PAYLOAD_LO)
        return [f"{kind}{width}@{off}" for off, width, kind in sorted(acc)], sorted(taken)


def extract_i2c(data: bytes, elf: Dict[str, Any], sym: Dict[str, Any]) -> Dict[str, Any]:
    if sym["size"] != 8:
        raise AnchorError(f"i2c_device_ioctl is {sym['size']} bytes, expected the 8-byte stub")
    got = [decode(word_at(data, elf, ".text", sym["value"] + 4 * k)) for k in range(2)]
    for k, (g, want) in enumerate(zip(got, I2C_EXPECTED)):
        for field, value in want.items():
            if g.get(field) != value:
                raise AnchorError(f"i2c_device_ioctl+{4 * k:#x}: {field} is {g.get(field)!r}, expected {value!r}")
    # Registers the two instructions read: `addi` reads its base register unless that is r0 (which means zero);
    # `bclr` reads the link register, not a general register. Arguments arrive in r3..r6.
    read = sorted({g["ra"] for g in got if g["op"] == "addi" and g["ra"] != 0})
    relocs = [r for r in elf["relocs"][".text"] if sym["value"] <= r[0] < sym["value"] + sym["size"]]
    return dict(
        instructions=[dict(offset=sym["value"] + 4 * k, **g) for k, g in enumerate(got)],
        derived=dict(returns_constant=got[0]["imm"], size_bytes=sym["size"], relocations_in_handler=len(relocs),
                     general_registers_read=read, reads_argument_registers=any(3 <= r <= 6 for r in read)),
    )


def extract_audioctl(data: bytes, elf: Dict[str, Any], sym: Dict[str, Any]) -> Dict[str, Any]:
    base = sym["value"]
    checks = {}
    for name, rel, expected in AUDIOCTL_CHECKPOINTS:
        got = decode(word_at(data, elf, ".text", base + rel))
        for field, want in expected.items():
            if got.get(field) != want:
                raise AnchorError(f"audioctl_device_ioctl+{rel:#x} ({name}): {field} is {got.get(field)!r}, expected {want!r}")
        checks[name] = dict(offset=base + rel, **{k: v for k, v in got.items()})
    number_base = -checks["number_base"]["imm"]
    bound = checks["number_bound"]["imm"]
    entries = bound + 1

    lo = [r for r in elf["relocs"][".text"] if r[0] == base + AUDIOCTL_TABLE_RELOC_OFFSET]
    if len(lo) != 1 or lo[0][1] != R_PPC_ADDR16_LO or elf["symbols"][lo[0][2]]["shndx"] != elf["by_name"][".rodata"]["index"]:
        raise AnchorError("the audioctl jump-table address relocation is not where the layout expects")
    table_off = lo[0][3]
    rel32 = {r[0]: r[3] for r in elf["relocs"][".rodata"] if r[1] == R_PPC_REL32}
    targets = []
    for k in range(entries):
        addend = rel32.get(table_off + 4 * k)
        if addend is None:
            raise AnchorError(f"audioctl jump-table entry {k} has no relocation")
        targets.append(addend - 4 * k)
    counts: Dict[int, int] = {}
    for t in targets:
        counts[t] = counts.get(t, 0) + 1
    default = max(counts, key=lambda t: (counts[t], -t))
    got = decode(word_at(data, elf, ".text", default))
    for field, want in AUDIOCTL_DEFAULT_CHECK.items():
        if got.get(field) != want:
            raise AnchorError(f"the audioctl default target is not `li 3, -1`: {field} is {got.get(field)!r}")

    handler = Handler(data, elf, sym)
    tail_pcs, tail_calls = handler.walk(base + AUDIOCTL_CHECKPOINTS[9][1])
    handled = []
    for k, target in enumerate(targets):
        if target == default:
            continue
        pcs, calls = handler.walk(target)
        own = pcs - tail_pcs
        accesses, taken = handler.frame_accesses(own)
        handled.append(dict(nr=number_base + k, target=target, calls=sorted(calls - tail_calls),
                            frame_accesses=accesses, payload_address_taken_at=taken))
    default_nrs = [number_base + k for k, t in enumerate(targets) if t == default]
    copy_calls = sorted(pc - base for pc, r in handler.rel24.items()
                        if elf["symbols"][r[2]]["name"] == "__copy_tofrom_user")
    return dict(
        decoded_instructions=checks,
        derived=dict(
            cmd_register=5, arg_register=6,
            size_field_shift=checks["copy_in_size_field"]["sh"],
            size_field_width_bits=checks["copy_in_size_field"]["me"] - checks["copy_in_size_field"]["mb"] + 1,
            copy_size_limit_bytes=checks["copy_in_size_clamp"]["imm"],
            copy_out_size_limit_bytes=checks["copy_out_size_clamp"]["imm"],
            write_bit_mask=0x80000000, read_bit_mask=0x40000000, number_mask=0xFF,
            number_base=number_base, number_window_low=number_base, number_window_high=number_base + bound,
            copy_to_from_user_call_offsets_from_symbol=copy_calls,
        ),
        dispatch=dict(
            table_section=".rodata", table_offset=table_off, entries=entries,
            entry_encoding="R_PPC_REL32 addend = target + 4 * index",
            default_target=default, default_is="li 3, -1 (the block every unhandled number goes to)",
            default_nrs=default_nrs, handled=handled,
            distinct_handler_targets=len({h["target"] for h in handled}),
        ),
        common_tail=dict(entry_offset=base + AUDIOCTL_CHECKPOINTS[9][1], calls=sorted(tail_calls)),
        method="control-flow walk over decoded branch instructions; calls are relocation or symbol names; frame_accesses "
               "are direct r1-relative loads and stores into the payload (a lower bound)",
    )


def extract(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise AnchorError(f"artifact digest {digest} is not the anchored {EXPECTED_SHA256}")
    elf = parse_elf32_be(data)
    syms = {s["name"]: s for s in elf["symbols"] if s["name"]}
    text = elf["by_name"][".text"]

    handlers = {}
    for key in ("dsp", "audioctl", "i2c"):
        sym = syms[f"{key}_device_ioctl"]
        if sym["shndx"] != text["index"]:
            raise AnchorError(f"{key}_device_ioctl is not in .text")
        handlers[key] = dict(symbol=f"{key}_device_ioctl", section=".text", offset=sym["value"], size=sym["size"])

    dsp = syms["dsp_device_ioctl"]
    checks = {}
    for name, rel, expected in DSP_CHECKPOINTS:
        got = decode(word_at(data, elf, ".text", dsp["value"] + rel))
        for field, want in expected.items():
            if got.get(field) != want:
                raise AnchorError(f"dsp_device_ioctl+{rel:#x} ({name}): {field} is {got.get(field)!r}, expected {want!r}")
        checks[name] = dict(offset=dsp["value"] + rel, **{k: v for k, v in got.items()})

    lo = [r for r in elf["relocs"][".text"] if r[0] == dsp["value"] + JUMP_TABLE_RELOC_OFFSET]
    if len(lo) != 1 or lo[0][1] != R_PPC_ADDR16_LO:
        raise AnchorError("the jump-table address relocation is not where the layout expects")
    if elf["symbols"][lo[0][2]]["shndx"] != elf["by_name"][".rodata"]["index"]:
        raise AnchorError("the jump-table address relocation does not point into .rodata")
    table_off = lo[0][3]
    entries ={r[0]: r[3] for r in elf["relocs"][".rodata"] if r[1] == R_PPC_REL32}
    targets = []
    for k in range(JUMP_TABLE_ENTRIES):
        addend = entries.get(table_off + 4 * k)
        if addend is None:
            raise AnchorError(f"jump-table entry {k} has no relocation")
        targets.append(addend - 4 * k)
    default = targets[0]
    handled = [dict(nr=k, target=t) for k, t in enumerate(targets) if t != default]
    default_nrs = [k for k, t in enumerate(targets) if t == default]

    copy_calls = sorted(
        r[0] - dsp["value"] for r in elf["relocs"][".text"]
        if dsp["value"] <= r[0] < dsp["value"] + dsp["size"] and r[1] == R_PPC_REL24
        and elf["symbols"][r[2]]["name"] == "__copy_tofrom_user"
    )
    sections = [dict(name=s["name"], size=s["size"]) for s in elf["sections"]
                if s["name"] in (".text", ".rodata", ".rodata.str1.4", ".rodata.cst4", ".modinfo", ".data", ".sdata")]
    return dict(
        schema=SCHEMA,
        audioctl_ioctl=extract_audioctl(data, elf, syms["audioctl_device_ioctl"]),
        i2c_ioctl=extract_i2c(data, elf, syms["i2c_device_ioctl"]),
        artifact=dict(sha256=digest, size_bytes=len(data), format="ELF32 MSB relocatable PowerPC", sections=sections),
        ioctl_handlers=handlers,
        dsp_ioctl=dict(
            decoded_instructions=checks,
            derived=dict(
                cmd_register=5, arg_register=6,
                size_field_shift=checks["copy_in_size_field"]["sh"],
                size_field_width_bits=checks["copy_in_size_field"]["me"] - checks["copy_in_size_field"]["mb"] + 1,
                copy_size_limit_bytes=checks["copy_in_size_clamp"]["imm"],
                write_bit_mask=0x80000000,
                read_bit_mask=checks["read_bit_test"]["imm"] << 16,
                number_mask=0xFF,
                number_bound=checks["number_bound"]["imm"],
                copy_to_from_user_call_offsets_from_symbol=copy_calls,
            ),
            dispatch=dict(
                table_section=".rodata", table_offset=table_off, entries=JUMP_TABLE_ENTRIES,
                entry_encoding="R_PPC_REL32 addend = target + 4 * index",
                default_target=default, default_nrs=default_nrs, handled=handled,
                distinct_handler_targets=len({h["target"] for h in handled}),
            ),
        ),
    )


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("artifact", nargs="?", help="path to audiodev.o (default: the sibling frankensonos capture)")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--write", metavar="FACTS", help="write the facts to FACTS")
    group.add_argument("--check", metavar="FACTS", help="exit 1 unless the facts equal FACTS")
    args = ap.parse_args(argv)
    here = os.path.dirname(os.path.realpath(__file__))
    path = args.artifact or default_artifact_path(os.path.dirname(os.path.dirname(here)))
    if not path or not os.path.isfile(path):
        print("artifact not found; pass its path or set FFW_FRANKENSONOS_DIR", file=sys.stderr)
        return 2
    try:
        facts = extract(path)
    except (AnchorError, KeyError, IndexError, ValueError, struct.error) as e:
        print(f"anchor extraction failed: {e}", file=sys.stderr)
        return 1
    text = json.dumps(facts, indent=1, sort_keys=True) + "\n"
    if args.write:
        with open(args.write, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {args.write}")
    elif args.check:
        with open(args.check, encoding="utf-8") as f:
            committed = json.load(f)
        if committed != facts:
            print("anchor facts differ from the committed file", file=sys.stderr)
            return 1
        print("anchor facts match")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
