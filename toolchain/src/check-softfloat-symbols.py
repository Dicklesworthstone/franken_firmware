#!/usr/bin/env python3
"""Which f64 soft-float helpers does the D02 render path call? Read from compiled objects, not inferred from opcodes.

    check-softfloat-symbols.py [--json] [--root NAME] FILE [FILE ...]

FILE is an `ar` archive (a Rust `.rlib`) or one ELF relocatable object (`.o`), built for big-endian soft-float MIPS32.
Standard library only; it executes nothing it reads and builds nothing.

WHY. mips-unknown-linux-musl is soft-float (`+soft-float`, fp_abi 3): every f64 add, multiply, compare, convert and
divide is a call to a compiler_builtins helper (`__muldf3`, `__fixdfsi`, ...), which is what makes f64 expensive there
(`docs/contracts/d02.md`, the soft-float row). D02's `Section` runs f64 on purpose; D01's sample conversion was made
integer-only so that `Section` is the only f64 left on the render path. That claim has so far been inferred from an
opcode count on a stripped guest ELF. This reads it from the objects: the relocations in each function name the helper
it calls.

WHAT IT JUDGES. The functions reachable from the root (default `ProtectedBoardDsp::render_into`) through relocations
in executable sections (call edges, through global names, local symbols and section symbols alike). Relocations in
non-code sections (`.pdr`, `.eh_frame`, debug info) name every function and are never followed. Policy:

* The f64 helpers `Section::process` needs are exactly widen, multiply, add, subtract, narrow: ALLOWED_RENDER_F64.
* Any other f64 helper, or an f64 libm function (`sqrt`, `exp`, ...), reachable from the root is a violation: a compare,
  a divide, an int<->f64 conversion or a libm call on the render path is f64 use that `Section` does not explain.
* A reachable function whose path is in `franken_dsp::convert` must call NO f64 helper at all, allowed ones included.

REFUSES, BY NAME, never reporting "no f64 calls" for something it could not read: an LLVM bitcode member (MEASURED on trj,
b50, 2026-11-05: under the root profile's `lto = true`, both franken-dsp's rlib members and its `--emit=obj` output are
bitcode, so toolchain/src/softfloat-build.sh builds with `profile.release.lto="off"` and says so in its MANIFEST.txt, which
this reads and prints; the bare magic `BC\\xC0\\xDE` and the wrapper magic `\\xDE\\xC0\\x17\\x0B` are both recognised), a member that is neither ELF nor a known rustc metadata member, an ELF
that is not 32-bit big-endian MIPS, an object that is not soft-float (an abiflags fp_abi naming a hard-float ABI, or any
FPU opcode word in executable code: a hard-float object does its f64 arithmetic in the FPU and calls no helper, so reading
one as "clean" would be a false pass; fp_abi 3 is positive evidence, fp_abi 0 or an absent section is not, and then the
evidence reported is the absence of FPU opcodes), v0 symbol mangling the root cannot be found
in, a root that is not present, a truncated archive or section table, and nothing to judge.

LIMITS, stated in every verdict. (1) It judges the OBJECT it read, not the final LTO'd and linked speaker ELF: the root
workspace release profile sets `lto = true` and `strip = "symbols"`, so the shipped binary may inline differently and has
no symbols to read. (2) Inlining: attribution is per surviving function. A conversion inlined into `render_into` is
judged as part of `render_into`; the helper-set rule still bars any helper outside the five, but cannot see an extra
widen, multiply, add, subtract or narrow that inlined non-`Section` code contributes. (3) Reachability follows relocations;
an indirect call (a function pointer, a vtable) is not an edge. (4) Numerical and instruction-count claims are not made.

Exit: 0 PASS, 1 FAIL (a violation), 2 REFUSED or usage, 3 INTERNAL ERROR (the checker itself failed: no verdict, and a crash
must never read as PASS or FAIL). With `--json` the standard output is always one JSON object: the verdict, or for an input
that cannot be judged `{"verdict": "REFUSED", "refusal": {"code", "message"}, "inputs", "claim", "limits"}`, or for a crash
`{"verdict": "ERROR", "error": {"type", "message"}, ...}`; the exit code and the message on standard error are the same
with or without it.

MEMBERS ARE JUDGED BY THEIR BYTES. An ELF member with machine code is an object. An ELF with none is a NON-CODE member,
listed and not judged: rustc wraps its metadata in ELF objects (`lib.rmeta` with a `.rmeta` section, `lib.rmeta-link` with a
`.rmeta-link` section; measured on the b56 rlib), and they carry no code and no `.MIPS.abiflags`. An ELF with none but an
embedded `.llvmbc` section is a stub for bitcode and is refused. A member named like rustc metadata is skipped by name only
when its bytes are neither ELF nor bitcode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import traceback
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

DEFAULT_ROOT = "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into"
CONVERT_PREFIX = "franken_dsp::convert::"

# What Section::process (widen, 5 multiplies, 2 adds, 2 subtracts, narrow) needs, and nothing else.
ALLOWED_RENDER_F64 = frozenset({"__extendsfdf2", "__truncdfsf2", "__adddf3", "__subdf3", "__muldf3"})
SECTION_PATTERN = {"__extendsfdf2": 1, "__muldf3": 5, "__adddf3": 2, "__subdf3": 2, "__truncdfsf2": 1}

F64_HELPER = re.compile(r"^__[a-z]*df[a-z0-9]*$")  # __muldf3 __gedf2 __fixdfsi __floatsidf __extendsfdf2 __truncdfsf2 ...
F64_LIBM = frozenset({
    "sqrt", "cbrt", "exp", "exp2", "expm1", "log", "log2", "log10", "log1p", "pow", "sin", "cos", "tan", "asin", "acos", "atan",
    "atan2", "sinh", "cosh", "tanh", "hypot", "fmod", "floor", "ceil", "round", "trunc", "rint", "nearbyint", "fabs", "copysign",
    "fmin", "fmax", "ldexp", "frexp", "modf", "scalbn", "remainder", "fma"})

AR_MAGIC = b"!<arch>\n"
BITCODE_MAGIC = b"BC\xc0\xde"
BITCODE_WRAPPER_MAGIC = b"\xde\xc0\x17\x0b"
ELF_MAGIC = b"\x7fELF"
COP1_OPCODES = {0x11: "COP1", 0x13: "COP1X", 0x31: "LWC1", 0x35: "LDC1", 0x39: "SWC1", 0x3D: "SDC1"}  # as toolchain/src/measure-d02-cost.py
SHT_SYMTAB, SHT_REL, SHT_RELA = 2, 9, 4
SHF_EXECINSTR = 0x4
STT_FUNC, STT_SECTION = 2, 3
STB_GLOBAL, STB_WEAK = 1, 2
# MIPS relocations that make a CALL, one per call site: R_MIPS_26 (a `jal`, non-PIC code), R_MIPS_CALL16 (PIC, a GOT load of the
# callee), R_MIPS_CALL_HI16 (PIC with a large GOT, paired with CALL_LO16). R_MIPS_JALR (37) is a linker hint that pairs with every PIC
# call and is NOT a second call site; nor are CALL_LO16 (31), GOT16 (9), LO16 (6) or the data relocations.
MIPS_CALL_RELOCS = frozenset({4, 11, 30})
EM_MIPS = 8
FP_ABI_SOFT = 3
RUST_METADATA_MEMBERS = ("lib.rmeta", "lib.rmeta-link")


class Refusal(Exception):
    """The input cannot be judged. `code` is a stable name; the message says what and where."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


# ---- ar ----------------------------------------------------------------------------------------------------------


@dataclass
class Member:
    name: str
    data: bytes


def parse_ar(data: bytes, origin: str) -> List[Member]:
    """Members of a GNU or BSD `ar` archive, minus the symbol tables and the long-name table."""
    if not data.startswith(AR_MAGIC):
        raise Refusal("not-an-archive", f"{origin}: no `!<arch>` magic")
    pos, out, long_names = len(AR_MAGIC), [], b""
    while pos < len(data):
        header = data[pos:pos + 60]
        if len(header) < 60 or header[58:60] != b"`\n":
            raise Refusal("truncated-archive", f"{origin}: bad or short member header at byte {pos}")
        raw_name = header[0:16].decode("latin-1")
        try:
            size = int(header[48:58].decode("latin-1").strip())
        except ValueError:
            raise Refusal("truncated-archive", f"{origin}: unreadable member size at byte {pos}") from None
        pos += 60
        body = data[pos:pos + size]
        if len(body) < size:
            raise Refusal("truncated-archive", f"{origin}: member at byte {pos - 60} claims {size} bytes, {len(body)} remain")
        pos += size + (size & 1)
        name = raw_name.strip()
        if name.startswith("#1/"):  # BSD long name: the name leads the body (BSD symbol tables are named this way too)
            n = int(name[3:])
            name, body = body[:n].rstrip(b"\0").decode("latin-1"), body[n:]
            if name in ("__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64"):
                continue
            out.append(Member(name, body))
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64"):
            continue
        if name == "//":
            long_names = body
            continue
        if re.fullmatch(r"/\d+", name):  # GNU long name: an offset into the `//` table
            start = int(name[1:])
            end = long_names.find(b"/\n", start)
            if end < 0:
                raise Refusal("truncated-archive", f"{origin}: long-name offset {start} is outside the name table")
            name = long_names[start:end].decode("latin-1")
        else:
            name = name.rstrip("/")
        out.append(Member(name, body))
    return out


# ---- ELF32 big-endian --------------------------------------------------------------------------------------------


@dataclass
class Section:
    index: int
    name: str
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int

    @property
    def type(self) -> int:
        return self.info & 0xF

    @property
    def bind(self) -> int:
        return self.info >> 4


@dataclass
class Node:
    """One executable section (with function-sections, one function)."""
    obj: int
    section: int
    symbols: List[str] = field(default_factory=list)  # FUNC symbols defined in the section
    globals: List[str] = field(default_factory=list)  # the GLOBAL or WEAK ones: the only names another object can call
    helpers: Dict[str, int] = field(default_factory=dict)  # f64 helper / libm name -> call sites
    calls_local: Set[int] = field(default_factory=set)  # code sections of the same object this one refers to (symbol or section symbol)
    calls_named: Set[str] = field(default_factory=set)  # undefined names, resolved against other objects' definitions in link()
    edges: Set[Tuple[int, int]] = field(default_factory=set)  # (object, section), filled by link()

    @property
    def key(self) -> Tuple[int, int]:
        return (self.obj, self.section)


@dataclass
class Obj:
    origin: str  # file[member]
    sha256: str
    machine: int
    fp_abi: Optional[int]
    exec_words: int  # executable words scanned for FPU opcodes (none found, or the object was refused)
    sections: List[Section]
    nodes: Dict[int, Node]
    embedded_bitcode: bool
    coarse: List[str]  # sections that hold more than one function symbol


def _cstr(table: bytes, off: int) -> str:
    end = table.find(b"\0", off)
    return table[off:end if end >= 0 else len(table)].decode("latin-1")


def classify_f64(name: str) -> Optional[str]:
    if F64_HELPER.match(name):
        return name
    if name in F64_LIBM:
        return name
    return None


def read_object(origin: str, data: bytes) -> Obj:
    if data[:4] in (BITCODE_MAGIC, BITCODE_WRAPPER_MAGIC):
        raise Refusal("bitcode-member", f"{origin} is LLVM bitcode, not object code: it has no relocations to read, so no claim about "
                      "its f64 calls can be made. Rebuild with real objects (`--emit=obj`) or without `-C linker-plugin-lto`")
    if data[:4] != ELF_MAGIC:
        raise Refusal("unknown-member-format", f"{origin} is neither an ELF object nor bitcode (starts {data[:8]!r})")
    if len(data) < 52:
        raise Refusal("truncated-elf", f"{origin}: shorter than an ELF32 header")
    if data[4] != 1 or data[5] != 2:
        raise Refusal("not-big-endian-elf32", f"{origin}: class {data[4]}, data encoding {data[5]} (this reads ELF32 big-endian only)")
    e_type, e_machine = struct.unpack(">HH", data[16:20])
    if e_type != 1:
        raise Refusal("not-relocatable", f"{origin}: ELF type {e_type}; a relocatable object is needed (a linked image has no relocations)")
    if e_machine != EM_MIPS:
        raise Refusal("not-mips", f"{origin}: e_machine {e_machine}; this judges big-endian soft-float MIPS32 only")
    shoff, = struct.unpack(">I", data[32:36])
    shentsize, shnum, shstrndx = struct.unpack(">HHH", data[46:52])
    if shoff == 0 or shnum == 0 or shentsize != 40:
        raise Refusal("truncated-elf", f"{origin}: no usable section header table (offset {shoff}, count {shnum}, entry size {shentsize})")
    if shoff + shnum * 40 > len(data):
        raise Refusal("truncated-elf", f"{origin}: the section header table runs past the end of the file")
    raw = [struct.unpack(">IIIIIIIIII", data[shoff + i * 40:shoff + (i + 1) * 40]) for i in range(shnum)]
    if shstrndx >= shnum:
        raise Refusal("truncated-elf", f"{origin}: section name table index {shstrndx} is outside the table")
    names = _slice(data, raw[shstrndx], origin)
    sections = [Section(i, _cstr(names, r[0]), r[1], r[2], r[4], r[5], r[6], r[7], r[9]) for i, r in enumerate(raw)]

    fp_abi = None
    for s in sections:
        if s.name == ".MIPS.abiflags":
            body = _slice(data, raw[s.index], origin)
            if len(body) >= 9:
                fp_abi = body[8]  # version u16, isa_level u8, isa_rev u8, gpr_size u8, cpr1_size u8, cpr2_size u8, fp_abi u8
    # A hard-float object does its f64 arithmetic with FPU instructions and calls no helper, so reading it would report a
    # clean render path for the wrong reason. Refuse on either piece of evidence: an abiflags fp_abi that names a hard-float
    # ABI, or any FPU opcode word in executable code. fp_abi 0 (what zig/clang record for a soft-float object) and an absent
    # section state nothing, so there the evidence is the absence of FPU opcodes, which the verdict reports.
    if fp_abi not in (None, 0, FP_ABI_SOFT):
        raise Refusal("not-soft-float", f"{origin}: .MIPS.abiflags fp_abi is {fp_abi}, a hard-float ABI (soft is {FP_ABI_SOFT})")
    fpu_words, exec_words = 0, 0
    for s in sections:
        if s.flags & SHF_EXECINSTR and s.size > 0:
            code = _slice(data, raw[s.index], origin)
            for off in range(0, len(code) - 3, 4):
                exec_words += 1
                if struct.unpack(">I", code[off:off + 4])[0] >> 26 in COP1_OPCODES:
                    fpu_words += 1
    if fpu_words:
        raise Refusal("not-soft-float", f"{origin}: {fpu_words} FPU opcode word(s) in executable sections; its f64 arithmetic is not done "
                      "by helper calls, so a helper-based reading would be a false pass")

    symtabs = [s for s in sections if s.type == SHT_SYMTAB]
    if len(symtabs) != 1:
        raise Refusal("no-symbol-table", f"{origin}: {len(symtabs)} symbol tables (one is needed; a stripped object has none)")
    symtab = symtabs[0]
    strtab = _slice(data, raw[symtab.link], origin) if symtab.link < shnum else b""
    body = _slice(data, raw[symtab.index], origin)
    symbols: List[Symbol] = []
    for off in range(0, len(body) - 15, 16):
        st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack(">IIIBBH", body[off:off + 16])
        name = _cstr(strtab, st_name)
        if st_info & 0xF == STT_SECTION and 0 < st_shndx < shnum:
            name = sections[st_shndx].name
        symbols.append(Symbol(name, st_value, st_size, st_info, st_shndx))

    nodes: Dict[int, Node] = {}
    for s in sections:
        if s.flags & SHF_EXECINSTR and s.size > 0:
            nodes[s.index] = Node(-1, s.index)
    for sym in symbols:
        if sym.type == STT_FUNC and sym.shndx in nodes and sym.name:
            nodes[sym.shndx].symbols.append(sym.name)
            if sym.bind in (STB_GLOBAL, STB_WEAK):
                nodes[sym.shndx].globals.append(sym.name)
    coarse = [sections[i].name for i, n in nodes.items() if len(n.symbols) > 1]

    for rs in sections:
        if rs.type not in (SHT_REL, SHT_RELA) or rs.info not in nodes:
            continue  # relocations in non-code sections (.pdr, .eh_frame, debug) name every function and are not call edges
        entry = 8 if rs.type == SHT_REL else 12
        rel = _slice(data, raw[rs.index], origin)
        for off in range(0, len(rel) - entry + 1, entry):
            r_info, = struct.unpack(">I", rel[off + 4:off + 8])
            idx, r_type = r_info >> 8, r_info & 0xFF
            if idx >= len(symbols):
                raise Refusal("bad-relocation", f"{origin}: relocation in {rs.name} names symbol {idx} of {len(symbols)}")
            sym = symbols[idx]
            node = nodes[rs.info]
            if sym.shndx == 0:  # undefined: a helper, or a function in another object
                hit = classify_f64(sym.name)
                if hit:
                    # ANY reference marks the helper as used (the violation rule is about presence); only a relocation that MAKES A
                    # CALL is a call site. A PIC call is two relocations against one symbol (CALL16, then the JALR hint), so
                    # counting every relocation doubled every count on the b56 rlib.
                    node.helpers.setdefault(hit, 0)
                    if r_type in MIPS_CALL_RELOCS:
                        node.helpers[hit] += 1
                elif sym.name:
                    node.calls_named.add(sym.name)
            elif sym.shndx in nodes and sym.shndx != rs.info:
                node.calls_local.add(sym.shndx)  # a function of this object, named by its symbol or by its section symbol
    embedded = any(s.name == ".llvmbc" and s.size > 0 for s in sections)
    return Obj(origin, hashlib.sha256(data).hexdigest(), e_machine, fp_abi, exec_words, sections, nodes, embedded, coarse)


def _slice(data: bytes, header: tuple, origin: str) -> bytes:
    offset, size = header[4], header[5]
    if header[1] == 8:  # SHT_NOBITS
        return b""
    if offset + size > len(data):
        raise Refusal("truncated-elf", f"{origin}: a section runs past the end of the file (offset {offset}, size {size})")
    return data[offset:offset + size]


# ---- demangling (legacy Rust mangling) ---------------------------------------------------------------------------

_ESCAPES = {"$LT$": "<", "$GT$": ">", "$u20$": " ", "$RF$": "&", "$C$": ",", "$LP$": "(", "$RP$": ")", "$BP$": "*", "$SP$": "@",
            "$u7b$": "{", "$u7d$": "}", "$u27$": "'", "$u5b$": "[", "$u5d$": "]", "$u3b$": ";", "$u2b$": "+", "$u22$": '"'}


def demangle(name: str) -> str:
    """`_ZN11franken_dsp7convert3foo17h<16 hex>E` -> `franken_dsp::convert::foo`. Anything else is returned as it is."""
    if not (name.startswith("_ZN") and name.endswith("E")):
        return name
    i, parts = 3, []
    while i < len(name) - 1:
        j = i
        while j < len(name) and name[j].isdigit():
            j += 1
        if j == i:
            return name
        n = int(name[i:j])
        part = name[j:j + n]
        if len(part) != n:
            return name
        parts.append(part)
        i = j + n
    if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
        parts.pop()
    out = []
    for part in parts:
        for esc, rep in _ESCAPES.items():
            part = part.replace(esc, rep)
        out.append(part.replace("..", "::"))
    return "::".join(out)


def path_matches(symbol: str, spec: str) -> bool:
    shown = demangle(symbol)
    return symbol == spec or shown == spec or shown.endswith("::" + spec)


# ---- link and judge ----------------------------------------------------------------------------------------------


@dataclass
class Graph:
    objs: List[Obj]
    nodes: Dict[Tuple[int, int], Node]
    by_name: Dict[str, Tuple[int, int]]
    duplicates: List[str]


def link(objs: List[Obj]) -> Graph:
    nodes: Dict[Tuple[int, int], Node] = {}
    by_name: Dict[str, Tuple[int, int]] = {}
    duplicates: List[str] = []
    for oi, obj in enumerate(objs):
        for si, node in obj.nodes.items():
            node.obj = oi
            nodes[node.key] = node
    # Another object can call only a GLOBAL or WEAK name. A local function is reached inside its own object, by symbol or
    # by section symbol (calls_local), and must never be mistaken for a same-named function elsewhere.
    for key, node in nodes.items():
        for name in node.globals:
            if name in by_name and by_name[name] != key:
                duplicates.append(name)
            by_name[name] = key
    for key, node in nodes.items():
        resolved = {(key[0], t) for t in node.calls_local}
        resolved |= {by_name[name] for name in node.calls_named if name in by_name}
        node.edges = {e for e in resolved if e in nodes and e != key}
    return Graph(objs, nodes, by_name, duplicates)


def reachable(graph: Graph, roots: List[Tuple[int, int]]) -> Tuple[List[Tuple[int, int]], Dict[Tuple[int, int], Tuple[int, int]]]:
    """Breadth-first from the roots: the sections reached, in order, and for each one the section it was first reached from (so
    the shortest call path to it can be read back)."""
    seen, queue = set(roots), deque(roots)
    order = list(roots)
    parent: Dict[Tuple[int, int], Tuple[int, int]] = {}
    while queue:
        here = queue.popleft()
        for nxt in sorted(graph.nodes[here].edges):
            if nxt not in seen:
                seen.add(nxt)
                parent[nxt] = here
                order.append(nxt)
                queue.append(nxt)
    return order, parent


NON_CODE_SECTIONS = (".symtab", ".strtab", ".shstrtab")


def judge(files: List[Tuple[str, bytes]], root: str = DEFAULT_ROOT) -> dict:
    """A member is judged by its BYTES, never by its name. An ELF with machine code is an object; an ELF with none (rustc wraps
    its metadata in ELF objects, `lib.rmeta` and `lib.rmeta-link`: measured on b56) is reported as a non-code member and judged
    on nothing; an ELF with none but an embedded bitcode section is a stub for code that lives in bitcode and is refused. A
    name in RUST_METADATA_MEMBERS is skipped only when its bytes are neither ELF nor bitcode (older rustc keeps raw metadata)."""
    objs: List[Obj] = []
    skipped: List[str] = []
    non_code: List[dict] = []
    inputs = []

    def take(label: str, data: bytes) -> None:
        obj = read_object(label, data)
        if obj.nodes:
            objs.append(obj)
        elif obj.embedded_bitcode:
            raise Refusal("bitcode-member", f"{label} is an ELF wrapper with no machine code and an embedded bitcode section: "
                          "the code it stands for is bitcode, which has no relocations to read")
        else:
            non_code.append({"member": label, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                             "sections": [s.name for s in obj.sections if s.size and s.name not in NON_CODE_SECTIONS]})

    for path, data in files:
        inputs.append({"file": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if data.startswith(AR_MAGIC):
            for m in parse_ar(data, path):
                label = f"{path}[{m.name}]"
                if m.name in RUST_METADATA_MEMBERS and m.data[:4] not in (ELF_MAGIC, BITCODE_MAGIC, BITCODE_WRAPPER_MAGIC):
                    skipped.append(label)
                    continue
                if m.name.endswith((".bc", ".bc.z")) and m.data[:4] != ELF_MAGIC:
                    raise Refusal("bitcode-member", f"{label} is a bitcode member by name; no object code to read")
                take(label, m.data)
        else:
            take(path, data)
    if not objs:
        raise Refusal("nothing-to-judge", "no object member with machine code was found in the inputs"
                      + (f" ({len(non_code)} non-code members: {[n['member'] for n in non_code]})" if non_code else ""))
    graph = link(objs)
    if not graph.nodes:
        raise Refusal("nothing-to-judge", "the objects hold no executable section with code")
    roots = [k for k, n in graph.nodes.items() if any(path_matches(s, root) for s in n.symbols)]
    if not roots:
        symbols = [s for n in graph.nodes.values() for s in n.symbols]
        v0 = sum(1 for s in symbols if s.startswith("_R"))
        legacy = sum(1 for s in symbols if s.startswith("_ZN"))
        bitcode_stub = sum(1 for o in objs if o.embedded_bitcode)
        leaf = root.split("::")[-1]
        near = sorted({demangle(s) for s in symbols if leaf in demangle(s)})[:8]
        hint = []
        if v0:
            hint.append(f"{v0} symbols use v0 mangling, which this does not demangle (build with legacy mangling or pass the exact symbol to --root)")
        if bitcode_stub:
            hint.append(f"{bitcode_stub} objects carry embedded bitcode (.llvmbc): the code may live in bitcode, not in the object")
        raise Refusal("root-not-found", f"no function matches {root!r} among {len(graph.nodes)} code sections; function symbols: "
                      f"{legacy} legacy-mangled, {v0} v0-mangled, {len(symbols) - legacy - v0} other; those containing {leaf!r}: "
                      f"{near or 'none'}" + (f" ({'; '.join(hint)})" if hint else ""))
    order, parent = reachable(graph, roots)

    def name_of(key: Tuple[int, int]) -> str:
        node = graph.nodes[key]
        return demangle(node.symbols[0]) if node.symbols else graph.objs[key[0]].sections[key[1]].name

    def call_path(key: Tuple[int, int]) -> List[str]:
        path = [name_of(key)]
        while key in parent:
            key = parent[key]
            path.append(name_of(key))
        return path[::-1]

    violations: List[dict] = []
    users: List[dict] = []
    totals: Dict[str, int] = {}
    convert_seen = []
    coarse_on_path: List[List[str]] = []
    for key in order:
        node = graph.nodes[key]
        shown = [demangle(s) for s in node.symbols] or [graph.objs[key[0]].sections[key[1]].name]
        if len(node.symbols) > 1:  # several functions in one section (merged identical code, or no function-sections)
            coarse_on_path.append(shown)
        if any(p.startswith(CONVERT_PREFIX) for p in shown):
            convert_seen.append(shown[0])
        if node.helpers:
            users.append({"function": shown[0], "also": shown[1:], "object": graph.objs[key[0]].origin, "helpers": dict(sorted(node.helpers.items())),
                          "section_process_copies": pattern_copies(node.helpers), "call_path": call_path(key)})
            for h, n in node.helpers.items():
                totals[h] = totals.get(h, 0) + n
        for h in sorted(node.helpers):
            if h not in ALLOWED_RENDER_F64:
                violations.append({"rule": "helper-outside-section-set", "function": shown[0], "helper": h,
                                   "detail": f"{h} is not one of {sorted(ALLOWED_RENDER_F64)}"})
        if any(p.startswith(CONVERT_PREFIX) for p in shown):
            for h in sorted(node.helpers):
                if h in ALLOWED_RENDER_F64:
                    violations.append({"rule": "f64-in-conversion", "function": shown[0], "helper": h,
                                       "detail": "a franken_dsp::convert function must call no f64 helper"})
    copies = _section_copies(users)
    on_path = set(order)
    elsewhere = sorted({demangle(node.symbols[0]) if node.symbols else graph.objs[key[0]].sections[key[1]].name
                        for key, node in graph.nodes.items() if key not in on_path and node.helpers})
    coarse = sorted({f"{o.origin}:{s}" for o in objs for s in o.coarse})
    return {
        "verdict": "FAIL" if violations else "PASS",
        "root": [demangle(graph.nodes[r].symbols[0]) if graph.nodes[r].symbols else "?" for r in roots],
        "inputs": inputs, "skipped_metadata_members": skipped, "non_code_members": non_code,
        "objects": [{"object": o.origin, "sha256": o.sha256, "fp_abi": o.fp_abi, "code_sections": len(o.nodes), "embedded_bitcode": o.embedded_bitcode,
                     "executable_words_scanned": o.exec_words, "fpu_opcode_words": 0,
                     "soft_float_evidence": ("abiflags fp_abi 3" if o.fp_abi == FP_ABI_SOFT else "no FPU opcode in the executable words; the abiflags state no float ABI")}
                    for o in objs],
        "code_sections": len(graph.nodes), "reachable_sections": len(order),
        "convert_functions_on_the_path": convert_seen,
        "f64_users_on_the_path": users, "f64_helper_call_sites_on_the_path": dict(sorted(totals.items())),
        "section_copies": copies,
        "f64_users_not_reachable_from_the_root": elsewhere,
        "violations": violations,
        "duplicate_global_symbols": sorted(set(graph.duplicates)),
        "coarse_sections": coarse, "coarse_sections_on_the_path": coarse_on_path,
        "allowed": sorted(ALLOWED_RENDER_F64),
        "limits": LIMITS,
    }


def pattern_copies(helpers: Dict[str, int]) -> Optional[int]:
    """How many whole copies of Section::process (1 widen, 5 mul, 2 add, 2 sub, 1 narrow) one function's helper call sites make,
    or None when they are not whole copies of it. Per FUNCTION: summing across functions hides which one holds the copies."""
    if set(helpers) != set(SECTION_PATTERN):
        return None
    ratios = {helpers[h] / n for h, n in SECTION_PATTERN.items()}
    k = next(iter(ratios))
    return int(k) if len(ratios) == 1 and k == int(k) and k > 0 else None


def _section_copies(users: List[dict]) -> str:
    """One line per f64 user: whole copies of the Section::process pattern, or not. An observation, not a gate."""
    if not users:
        return "no f64 helper call sites on the path"
    parts = []
    for u in users:
        k = u["section_process_copies"]
        parts.append(f"{u['function']}: " + (f"{k} whole copy(ies) of the Section::process pattern" if k else
                                              f"not whole copies of the Section::process pattern, {u['helpers']}"))
    return "; ".join(parts)


LIMITS = [
    "judges the object it read, not the final LTO'd and linked speaker ELF: the root release profile sets lto = true and "
    "strip = \"symbols\", and under lto = true rustc writes LLVM bitcode (refused here), so an object that can be read was built "
    "with LTO off; the shipped ELF is fat-LTO'd and may inline differently",
    "attribution is per surviving function: a function inlined into its caller is judged as part of the caller; an extra widen, "
    "multiply, add, subtract or narrow contributed by inlined non-Section code is not visible to the helper-set rule",
    "reachability follows relocations in executable sections, a call and an address taken alike (so it over-approximates); an "
    "indirect call through a pointer is not resolved. Helper counts are CALL SITES in the object (one per R_MIPS_26 or CALL16), not "
    "executions",
    "no numerical or instruction-count claim is made",
]


def render(result: dict) -> str:
    lines = [f"softfloat-symbols: {result['verdict']}"]
    lines.append(f"root: {', '.join(result['root'])}")
    # fp_abi is an int, or None for an object with no .MIPS.abiflags: sort their names, never the mixed values (that crashed on b56)
    abis = sorted({"absent" if o["fp_abi"] is None else str(o["fp_abi"]) for o in result["objects"]})
    lines.append(f"objects with code: {len(result['objects'])} (fp_abi {', '.join(abis)}); code sections {result['code_sections']}, "
                 f"reachable from the root {result['reachable_sections']}")
    for n in result.get("non_code_members", []):
        lines.append(f"  non-code member, not judged: {n['member']}  sha256 {n['sha256'][:16]}  ({n['bytes']} bytes; sections {n['sections'] or 'none'})")
    for s in result.get("skipped_metadata_members", []):
        lines.append(f"  skipped by name (its bytes are not an object): {s}")
    for o in result["objects"]:
        lines.append(f"  {o['object']}  sha256 {o['sha256'][:16]}  code sections {o['code_sections']}  soft-float: {o['soft_float_evidence']} "
                     f"({o['executable_words_scanned']} executable words scanned)"
                     + ("  (embedded bitcode present beside the object code)" if o["embedded_bitcode"] else ""))
    for m in result.get("build_manifests", []):
        if m["manifest"] is None:
            lines.append(f"build manifest: none beside {m['file']}; the build configuration is not recorded, so how this object differs "
                         "from the shipped build cannot be stated from the file")
        else:
            lines.append(f"build manifest beside {m['file']}: {m['manifest']['path']} (sha256 {m['manifest']['sha256'][:16]})")
            lines += [f"  DEVIATION FROM THE SHIPPED BUILD: {d}" for d in m["manifest"]["deviations"]]
    lines.append(f"f64 helper call sites on the path: {result['f64_helper_call_sites_on_the_path'] or 'none'}")
    for u in result["f64_users_on_the_path"]:
        k = u["section_process_copies"]
        lines.append(f"  f64 user: {u['function']}  {u['helpers']}")
        lines.append("    observation, not a gate: " + (f"{k} whole copy(ies) of the Section::process pattern (1 widen, 5 mul, 2 add, 2 sub, 1 narrow)"
                                                       if k else "not whole copies of the Section::process pattern"))
        lines.append("    reached via: " + " -> ".join(u["call_path"]))
    conv = result["convert_functions_on_the_path"]
    lines.append("convert functions on the path: " + (", ".join(conv) if conv else
                 "none survive as symbols (inlined into a caller, or not on the path): their f64 use cannot be separated from the caller's"))
    if result["f64_users_not_reachable_from_the_root"]:
        lines.append(f"f64 users NOT reachable from the root (setup code; not judged): {len(result['f64_users_not_reachable_from_the_root'])}")
    for v in result["violations"]:
        lines.append(f"VIOLATION [{v['rule']}] {v['function']} calls {v['helper']}: {v['detail']}")
    for names in result.get("coarse_sections_on_the_path", []):
        lines.append(f"note: several functions share one section ON THE PATH, so attribution there is per section: {' | '.join(names)}")
    if result["coarse_sections"]:
        lines.append(f"note: {len(result['coarse_sections'])} sections in all hold several functions; the others are not on the path")
    for d in result["duplicate_global_symbols"]:
        lines.append(f"note: global symbol defined more than once: {d}")
    lines.append("limits:")
    lines += [f"  - {x}" for x in result["limits"]]
    return "\n".join(lines)


def read_manifest(directory: str) -> Optional[dict]:
    """The `MANIFEST.txt` the build script (toolchain/src/softfloat-build.sh) leaves beside its artefact, if there is one.
    Its `deviation:` lines say how the object differs from the shipped build; they are copied into the verdict, not guessed."""
    path = os.path.join(directory, "MANIFEST.txt")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    lines = data.decode("utf-8", "replace").splitlines()
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(),
            "deviations": [ln[len("deviation:"):].strip() for ln in lines if ln.startswith("deviation:")],
            "mode": next((ln[len("mode:"):].strip() for ln in lines if ln.startswith("mode:")), None)}


def refusal_result(refusal: Refusal, files: List[Tuple[str, bytes]]) -> dict:
    """What `--json` prints for an input that could not be judged: always an object, never nothing."""
    return {"verdict": "REFUSED", "refusal": {"code": refusal.code, "message": refusal.message},
            "inputs": [{"file": p, "bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files],
            "claim": "none: no claim about f64 calls is made for these inputs", "limits": LIMITS}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read the f64 soft-float helper calls of the D02 render path from compiled objects")
    parser.add_argument("files", nargs="+", metavar="FILE", help="an .rlib/.a archive or an ELF .o (big-endian soft-float MIPS32)")
    parser.add_argument("--root", default=DEFAULT_ROOT, help="the function to start from (a symbol, or a demangled path suffix)")
    parser.add_argument("--json", action="store_true",
                        help="print the result as a JSON object: the verdict, or, for an input that cannot be judged, "
                             '{"verdict": "REFUSED", "refusal": {"code", "message"}, ...}; the exit code (0, 1, 2) is the same either way')
    args = parser.parse_args(argv)
    files: List[Tuple[str, bytes]] = []
    manifests = []
    for path in args.files:
        try:
            with open(path, "rb") as handle:
                files.append((path, handle.read()))
        except OSError as exc:
            refusal = Refusal("unreadable-input", f"{path}: {exc}")
            print(f"softfloat-symbols: REFUSED\n{refusal}", file=sys.stderr)
            if args.json:
                print(json.dumps(refusal_result(refusal, files), indent=1, sort_keys=True))
            return 2
        manifests.append({"file": path, "manifest": read_manifest(os.path.dirname(os.path.abspath(path)))})
    try:
        try:
            result = judge(files, args.root)
        except Refusal as refusal:
            print(f"softfloat-symbols: REFUSED\n{refusal}", file=sys.stderr)
            print("No claim about f64 calls is made for these inputs.", file=sys.stderr)
            if args.json:
                print(json.dumps({**refusal_result(refusal, files), "build_manifests": manifests}, indent=1, sort_keys=True))
            return 2
        result["build_manifests"] = manifests
        out = json.dumps(result, indent=1, sort_keys=True) if args.json else render(result)
    except Exception as exc:  # noqa: BLE001 - any failure of the checker itself must not read as a verdict
        # An uncaught traceback exits 1, which is the FAIL code: a crash would read as "a violation was found". Exit 3 instead.
        print(f"softfloat-symbols: INTERNAL ERROR, no verdict\n{type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        print("No claim about f64 calls is made for these inputs. This is a defect in the checker, not a finding.", file=sys.stderr)
        if args.json:
            print(json.dumps({"verdict": "ERROR", "error": {"type": type(exc).__name__, "message": str(exc)},
                              "inputs": [{"file": p, "bytes": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files],
                              "claim": "none: no claim about f64 calls is made for these inputs", "limits": LIMITS}, indent=1, sort_keys=True))
        return 3
    print(out)
    return 1 if result["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
