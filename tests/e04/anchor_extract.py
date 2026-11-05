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

What the facts do NOT establish: which ioctl implements which HAL operation, any per-command
payload layout, or any behavior on a real board. Those stay unknown in the contract matrix.
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
