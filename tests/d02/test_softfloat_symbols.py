"""Tests for toolchain/src/check-softfloat-symbols.py (ffw-7s0, the soft-float row of docs/contracts/d02.md).

The reader is checked on objects built here from scratch (a small ELF32 big-endian and `ar` writer), so the fixtures do
not share code with the reader, and on ONE real object: tests/d02/fixtures/softfloat/realfix-mips-be-softfloat.o.hex
(the object's bytes as hex, because a plain-text patch cannot carry a binary), compiled from realfix.c next to it with zig
for big-endian soft-float MIPS32r2 and read independently with llvm-readelf (its expected relocations are pinned below
from that output). No franken-dsp object has been read yet: that needs the central device build, and until it exists
these tests prove the reader, not the speaker.

Run: python3 -B -I tests/d02/test_softfloat_symbols.py   (host-only, standard library only; nothing is compiled).
This file lives under tests/d02, not toolchain/tests, on purpose: scripts/test/q00/floor.py makes every test module under
toolchain/tests a required Q00 case, and this one belongs to D02's own gate.

Each planted fault sits beside an unplanted control of the same shape, so a test cannot pass by failing for an unrelated
reason. A refusal test names the refusal code, because "refused for the right reason" is the claim.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCRIPT = REPO / "toolchain" / "src" / "check-softfloat-symbols.py"
FIXTURES = HERE / "fixtures" / "softfloat"
REAL_HEX = FIXTURES / "realfix-mips-be-softfloat.o.hex"
REAL_PIC_HEX = FIXTURES / "realfix-pic-mips-be-softfloat.o.hex"


def load_hex(path):
    """The bytes of a fixture: the hex file's lines that are not `#` comments, joined."""
    text = "".join(line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip() and not line.startswith("#"))
    return bytes.fromhex(text)


def real_object():
    return load_hex(REAL_HEX)


def real_pic_object():
    return load_hex(REAL_PIC_HEX)


def load():
    spec = importlib.util.spec_from_file_location("check_softfloat_symbols_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sf = load()

# The two LLVM bitcode magics, written out here and NOT taken from the script, so that a wrong constant in the script
# cannot move the fixture with it (a mutant that changed the script's constant once survived exactly that way).
BC_MAGIC = b"BC\xc0\xde"
BC_WRAPPER_MAGIC = b"\xde\xc0\x17\x0b"
NOP = b"\0\0\0\0"
COP1 = struct.pack(">I", 0x11 << 26)  # a COP1 word: an FPU instruction
LWC1 = struct.pack(">I", 0x31 << 26)


def mangle(*path):
    """Legacy Rust mangling of a path, with a fixed hash."""
    return "_ZN" + "".join(f"{len(p)}{p}" for p in path) + "17h0123456789abcdefE"


RENDER = mangle("franken_dsp", "protection", "runtime", "ProtectedBoardDsp", "render_into")
SECTION = mangle("franken_dsp", "protection", "runtime", "Section", "process")
CONVERT = mangle("franken_dsp", "convert", "unit_f32_to_i16")
SETUP = mangle("franken_dsp", "protection", "calibration", "validate_channel")
SECTION_OPS = ["__extendsfdf2"] + ["__muldf3"] * 5 + ["__adddf3"] * 2 + ["__subdf3"] * 2 + ["__truncdfsf2"]


# ---- a small ELF32 big-endian relocatable writer ---------------------------------------------------------------------


def func(name, refs=(), *, local=False, section=None, code=NOP * 4, extra_symbols=()):
    """refs: ("sym", name) calls through a symbol (a helper, a global or a local function); ("sec", name) through the
    section symbol of the function `name` of the same object."""
    return {"name": name, "refs": [r if isinstance(r, tuple) else ("sym", r) for r in refs], "local": local,
            "section": section or f".text.{name}", "code": code, "extra": list(extra_symbols)}


def elf(funcs, *, fp_abi=3, abiflags=True, machine=8, data=2, cls=1, etype=1, rela=False, pdr_decoy=True, symtab=True,
        llvmbc=False, shnum_override=None, shentsize_override=None, size_override=None, pic=False, extra_sections=None):
    names = bytearray(b"\0")
    strtab = bytearray(b"\0")

    def name_at(table, text):
        off = len(table)
        table += text.encode() + b"\0"
        return off

    sections = [dict(name="", type=0, flags=0, data=b"", link=0, info=0, entsize=0, align=0)]
    text_index = {}
    shared = {}
    for f in funcs:
        if f["section"] not in shared:
            shared[f["section"]] = len(sections)
            sections.append(dict(name=f["section"], type=1, flags=6, data=b"", link=0, info=0, entsize=0, align=4))
        text_index[f["name"]] = shared[f["section"]]
        sections[shared[f["section"]]]["data"] += f["code"]
    pdr_index = None
    if pdr_decoy:
        pdr_index = len(sections)
        sections.append(dict(name=".pdr", type=1, flags=0, data=NOP * 8, link=0, info=0, entsize=0, align=4))
    if abiflags:
        flags = bytearray(24)
        flags[8] = fp_abi
        sections.append(dict(name=".MIPS.abiflags", type=0x7000002A, flags=2, data=bytes(flags), link=0, info=0, entsize=24, align=8))
    for extra_name, blob in extra_sections or []:  # non-code sections, e.g. the `.rmeta` rustc wraps its metadata in
        sections.append(dict(name=extra_name, type=1, flags=0, data=blob, link=0, info=0, entsize=0, align=1))
    if llvmbc:
        sections.append(dict(name=".llvmbc", type=1, flags=0, data=b"BC\xc0\xde" + b"\0" * 12, link=0, info=0, entsize=0, align=1))

    # symbols: locals first (section symbols, local functions), then globals (functions, undefined names)
    local_syms, global_syms = [], []
    sec_sym = {}
    for sec_name, idx in shared.items():
        sec_sym[idx] = len(local_syms) + 1
        local_syms.append((sec_name, 0, 0, (0 << 4) | sf.STT_SECTION, idx))
    for f in funcs:
        entry = (f["name"], 0, len(f["code"]), ((0 if f["local"] else 1) << 4) | sf.STT_FUNC, text_index[f["name"]])
        (local_syms if f["local"] else global_syms).append(entry)
    undefined = []
    for f in funcs:
        for kind, target in f["refs"]:
            if kind in ("sym", "addr") and target not in text_index and target not in undefined:  # ("sec", ...) and ("raw", ...) add none
                undefined.append(target)
    for target in undefined:
        global_syms.append((target, 0, 0, (1 << 4), 0))
    ordered = local_syms + global_syms
    index_of = {}
    for i, sym in enumerate(ordered, start=1):
        if (sym[3] & 0xF) != sf.STT_SECTION:
            index_of[sym[0]] = i
    sym_bytes = bytearray(16)
    for (nm, value, size, info, shndx) in ordered:
        sym_bytes += struct.pack(">IIIBBH", 0 if (info & 0xF) == sf.STT_SECTION else name_at(strtab, nm), value, size, info, 0, shndx)
    symtab_index = None
    if symtab:
        symtab_index = len(sections)
        sections.append(dict(name=".symtab", type=sf.SHT_SYMTAB, flags=0, data=bytes(sym_bytes), link=0, info=len(local_syms) + 1, entsize=16, align=4))
        strtab_index = len(sections)
        sections.append(dict(name=".strtab", type=3, flags=0, data=b"", link=0, info=0, entsize=0, align=1))
        sections[symtab_index]["link"] = strtab_index

    def reloc(target_index, refs):
        """One relocation entry per (symbol, type). Non-PIC code: a call is one R_MIPS_26 (4). PIC code, as rustc writes it: a call
        is TWO entries against one symbol, R_MIPS_CALL16 (11) then the R_MIPS_JALR (37) hint, and a call to a local function is
        GOT16 (9) + LO16 (6) against its section symbol plus a JALR against the function symbol."""
        out = bytearray()

        def emit(sym, typ):
            out.extend(struct.pack(">II", 0, (sym << 8) | typ))
            if rela:
                out.extend(struct.pack(">i", 0))

        for kind, target in refs:
            if kind == "sec":
                section_symbol = sec_sym[text_index[target]]
                if pic:
                    emit(section_symbol, 9)
                    emit(section_symbol, 6)
                    emit(index_of[target], 37)
                else:
                    emit(section_symbol, 4)
            elif kind == "raw":  # a symbol index written as it is, to plant a relocation that names nothing
                emit(target, 4)
            elif kind == "addr":  # the address of the symbol taken (GOT16), not called
                emit(index_of[target], 9)
            elif pic:
                emit(index_of[target], 11)
                emit(index_of[target], 37)
            else:
                emit(index_of[target], 4)
        return bytes(out)

    for f in funcs:
        if f["refs"] and symtab_index is not None:
            sections.append(dict(name=f".rel{'a' if rela else ''}{f['section']}", type=sf.SHT_RELA if rela else sf.SHT_REL, flags=0x40,
                                 data=reloc(text_index[f["name"]], f["refs"]), link=symtab_index, info=text_index[f["name"]],
                                 entsize=12 if rela else 8, align=4))
    if pdr_decoy and symtab_index is not None:
        decoy = bytearray()
        for f in funcs:  # a non-code relocation section naming every function, as .pdr and .eh_frame do
            decoy += struct.pack(">II", 0, (index_of[f["name"]] << 8) | 2)
        sections.append(dict(name=".rel.pdr", type=sf.SHT_REL, flags=0x40, data=bytes(decoy), link=symtab_index, info=pdr_index, entsize=8, align=4))
    shstr_index = len(sections)
    sections.append(dict(name=".shstrtab", type=3, flags=0, data=b"", link=0, info=0, entsize=0, align=1))

    for s in sections:
        s["name_off"] = name_at(names, s["name"]) if s["name"] else 0
    sections[shstr_index]["data"] = bytes(names)
    if symtab:
        sections[strtab_index]["data"] = bytes(strtab)

    body, offsets = bytearray(52), []
    for s in sections:
        pad = (-len(body)) % 4
        body += b"\0" * pad
        offsets.append(len(body))
        body += s["data"]
    body += b"\0" * ((-len(body)) % 4)
    shoff = len(body)
    for s, off in zip(sections, offsets):
        size = (size_override or {}).get(s["name"], len(s["data"]))  # a header that claims more bytes than the file holds
        body += struct.pack(">IIIIIIIIII", s["name_off"], s["type"], s["flags"], 0, off, size, s["link"], s["info"], s["align"], s["entsize"])
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = cls, data, 1
    struct.pack_into(">HHI", header, 16, etype, machine, 1)
    struct.pack_into(">I", header, 32, shoff)
    struct.pack_into(">HHHHHH", header, 40, 52, 0, 0, shentsize_override or 40,
                     shnum_override if shnum_override is not None else len(sections), shstr_index)
    body[0:52] = header
    return bytes(body)


def ar(members):
    """A GNU ar archive: a symbol-table member first, then a long-name table when any name is longer than 15 characters."""
    def entry(name, body):
        head = name.encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n"
        return head + body + (b"\n" if len(body) & 1 else b"")
    out = bytearray(sf.AR_MAGIC) + entry("/", b"\0\0\0\0")
    table = bytearray()
    refs = {}
    for name, _ in members:
        if len(name) > 15:
            refs[name] = len(table)
            table += name.encode() + b"/\n"
    if table:
        out += entry("//", bytes(table))
    for name, body in members:
        out += entry(f"/{refs[name]}" if name in refs else name + "/", body)
    return bytes(out)


def judge(*files, root=sf.DEFAULT_ROOT):
    return sf.judge([(f"in{i}", f) for i, f in enumerate(files)], root)


def control_object(**kw):
    """render_into -> Section::process (the five allowed helpers) and the conversion (no helper); a setup function that
    uses f64 freely but is not reachable; a decoy relocation section naming every function."""
    return elf([
        func(RENDER, [SECTION, CONVERT]),
        func(SECTION, SECTION_OPS),
        func(CONVERT, ["__mulsf3"]),  # an f32 helper: not f64
        func(SETUP, ["__divdf3", "exp", "__gedf2"]),
    ], **kw)


class Base(unittest.TestCase):
    def assertParseRefuses(self, code, data):
        with self.assertRaises(sf.Refusal) as raised:
            sf.parse_ar(data, "x.rlib")
        self.assertEqual(raised.exception.code, code, str(raised.exception))

    def assertRefuses(self, code, *files, root=sf.DEFAULT_ROOT, contains=None):
        with self.assertRaises(sf.Refusal) as raised:
            judge(*files, root=root)
        self.assertEqual(raised.exception.code, code, str(raised.exception))
        if contains:
            self.assertIn(contains, str(raised.exception))
        return raised.exception

    def violations(self, result):
        return sorted((v["rule"], v["function"], v["helper"]) for v in result["violations"])


class Demangle(unittest.TestCase):
    def test_legacy_names_become_paths(self):
        self.assertEqual(sf.demangle(RENDER), "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into")
        self.assertEqual(sf.demangle(mangle("a", "$LT$impl$u20$b$GT$", "m")), "a::<impl b>::m")
        self.assertEqual(sf.demangle("section_like"), "section_like")
        self.assertEqual(sf.demangle("_ZN3fooE"), "foo")
        self.assertEqual(sf.demangle("_ZN99fooE"), "_ZN99fooE", "a length that runs past the name is left alone")

    def test_matching_a_root(self):
        self.assertTrue(sf.path_matches(RENDER, sf.DEFAULT_ROOT))
        self.assertTrue(sf.path_matches(RENDER, "ProtectedBoardDsp::render_into"))
        self.assertTrue(sf.path_matches("root", "root"))
        self.assertFalse(sf.path_matches(RENDER, "Dsp::render_into"), "a suffix must start at a path boundary")
        self.assertFalse(sf.path_matches(CONVERT, sf.DEFAULT_ROOT))


def ar_bsd(members):
    """A BSD-format archive (what `ar` on macOS writes): every name is `#1/N` with the name at the start of the body, and
    the symbol table is a member called `__.SYMDEF`."""
    def entry(name, body):
        padded = name.encode().ljust((len(name) + 3) // 4 * 4 + 4, b"\0")
        payload = padded + body
        head = f"#1/{len(padded)}".encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"644".ljust(8) + str(len(payload)).encode().ljust(10) + b"`\n"
        return head + payload + (b"\n" if len(payload) & 1 else b"")
    out = bytearray(sf.AR_MAGIC) + entry("__.SYMDEF", b"\0" * 8)
    for name, body in members:
        out += entry(name, body)
    return bytes(out)


class Archive(Base):
    def test_a_bsd_format_archive_is_read_and_its_symbol_table_skipped(self):
        a = ar_bsd([("a_long_member_name_over_fifteen.o", control_object()), ("lib.rmeta", b"rust\0\0\0\0")])
        self.assertEqual([m.name for m in sf.parse_ar(a, "x.a")], ["a_long_member_name_over_fifteen.o", "lib.rmeta"])
        self.assertEqual(judge(a)["verdict"], "PASS")
        self.assertRefuses("bitcode-member", ar_bsd([("x.o", BC_MAGIC + b"\0" * 28)]))

    def test_members_long_names_and_metadata(self):
        a = ar([("lib.rmeta", b"rust\0\0\0\0meta"), ("franken_dsp-0123456789abcdef.franken_dsp.0123456789abcdef-cgu.0.rcgu.o", control_object())])
        members = sf.parse_ar(a, "x.rlib")
        self.assertEqual([m.name for m in members],
                         ["lib.rmeta", "franken_dsp-0123456789abcdef.franken_dsp.0123456789abcdef-cgu.0.rcgu.o"])
        result = judge(a)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["skipped_metadata_members"], ["in0[lib.rmeta]"], "rustc metadata is skipped by name, and said so")
        self.assertEqual(len(result["objects"]), 1)

    def test_a_truncated_archive_is_refused_not_judged(self):
        a = ar([("a.o", control_object())])
        self.assertRefuses("truncated-archive", a[:-40])
        self.assertRefuses("truncated-archive", a[:70])
        broken = bytearray(a)
        broken[8 + 60 + 4 + 58] = ord("X")  # the header terminator of the first real member
        self.assertRefuses("truncated-archive", bytes(broken))

    def test_not_an_archive_nor_an_object(self):
        self.assertRefuses("unknown-member-format", b"just some text that is neither")
        self.assertParseRefuses("not-an-archive", b"just some text that is neither")
        self.assertParseRefuses("truncated-archive", sf.AR_MAGIC + b"short")

    def test_a_long_name_offset_outside_the_table_is_refused(self):
        a = bytearray(ar([("a_long_member_name_over_15.o", control_object())]))
        at = a.index(b"/0 ")  # the member's name field: an offset into the long-name table
        a[at:at + 3] = b"/99"
        self.assertParseRefuses("truncated-archive", bytes(a))


class Reader(Base):
    def test_control_passes_and_names_the_section_as_the_only_f64_user(self):
        result = judge(control_object())
        self.assertEqual(result["verdict"], "PASS", result["violations"])
        self.assertEqual([u["function"] for u in result["f64_users_on_the_path"]], ["franken_dsp::protection::runtime::Section::process"])
        self.assertEqual(result["f64_helper_call_sites_on_the_path"],
                         {"__adddf3": 2, "__extendsfdf2": 1, "__muldf3": 5, "__subdf3": 2, "__truncdfsf2": 1})
        user = result["f64_users_on_the_path"][0]
        self.assertEqual(user["section_process_copies"], 1)
        self.assertEqual(user["call_path"], ["franken_dsp::protection::runtime::ProtectedBoardDsp::render_into",
                                             "franken_dsp::protection::runtime::Section::process"], "how the function is reached, from the root")
        self.assertEqual(result["convert_functions_on_the_path"], ["franken_dsp::convert::unit_f32_to_i16"])
        self.assertEqual(result["f64_users_not_reachable_from_the_root"], ["franken_dsp::protection::calibration::validate_channel"],
                         "setup code that uses f64 is reported, not judged")
        self.assertEqual(result["reachable_sections"], 3)

    def test_planted_a_conversion_that_calls_muldf3_is_a_violation_and_removing_the_plant_clears_it(self):
        def build(plant):
            return elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS),
                        func(CONVERT, ["__muldf3"] if plant else ["__mulsf3"]), func(SETUP, ["__divdf3"])])
        control, planted = judge(build(False)), judge(build(True))
        self.assertEqual(control["verdict"], "PASS")
        self.assertEqual(planted["verdict"], "FAIL")
        self.assertEqual(self.violations(planted), [("f64-in-conversion", "franken_dsp::convert::unit_f32_to_i16", "__muldf3")],
                         "__muldf3 is an ALLOWED helper for Section; it is the conversion that may not call it")

    def test_helpers_outside_the_section_set_are_violations_wherever_they_sit(self):
        for helper in ("__divdf3", "__fixdfsi", "__floatsidf", "__gtdf2", "__ltdf2", "__gedf2", "__negdf2", "__unorddf2", "sqrt", "exp", "floor", "round"):
            with self.subTest(helper=helper):
                converted = judge(elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS), func(CONVERT, [helper])]))
                self.assertEqual(converted["verdict"], "FAIL")
                self.assertEqual(self.violations(converted), [("helper-outside-section-set", "franken_dsp::convert::unit_f32_to_i16", helper)])
                # the same helper inlined into render_into itself (no conversion symbol survives) is still caught
                inlined = judge(elf([func(RENDER, [SECTION] + [helper]), func(SECTION, SECTION_OPS)]))
                self.assertEqual(self.violations(inlined), [("helper-outside-section-set", "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into", helper)])
                self.assertEqual(inlined["convert_functions_on_the_path"], [])

    def test_the_blind_spot_an_inlined_extra_allowed_helper_passes_the_gate_and_shows_in_the_observation(self):
        # An extra f64 multiply inlined into render_into is indistinguishable by helper SET from Section's own. This is
        # the stated limit; the per-function observation at least shows that render_into is no longer whole copies of the pattern.
        result = judge(elf([func(RENDER, [SECTION, "__muldf3"]), func(SECTION, SECTION_OPS)]))
        self.assertEqual(result["verdict"], "PASS")
        by_function = {u["function"].rsplit("::", 2)[-2] + "::" + u["function"].rsplit("::", 1)[-1]: u for u in result["f64_users_on_the_path"]}
        self.assertEqual(by_function["ProtectedBoardDsp::render_into"]["helpers"], {"__muldf3": 1})
        self.assertIsNone(by_function["ProtectedBoardDsp::render_into"]["section_process_copies"], "the extra multiply shows here")
        self.assertEqual(by_function["Section::process"]["section_process_copies"], 1)

    def test_whole_copies_are_counted_per_function_not_summed_across_functions(self):
        # two functions each holding one copy are two users of one copy each; ONE function holding two copies says two. (The b56
        # report summed across functions and called render_into's copies plus from_stored's widenings "not whole copies".)
        two_functions = judge(elf([func(RENDER, [SECTION, "second"]), func(SECTION, SECTION_OPS), func("second", SECTION_OPS)]))
        self.assertEqual([u["section_process_copies"] for u in two_functions["f64_users_on_the_path"]], [1, 1])
        one_function = judge(elf([func(RENDER, SECTION_OPS + SECTION_OPS)]))
        self.assertEqual([u["section_process_copies"] for u in one_function["f64_users_on_the_path"]], [2])
        # all five helpers present but in unequal numbers is not a whole copy either (one multiply too many)
        unequal = judge(elf([func(RENDER, SECTION_OPS + ["__muldf3"])]))
        self.assertEqual([u["section_process_copies"] for u in unequal["f64_users_on_the_path"]], [None])
        mixed = judge(elf([func(RENDER, SECTION_OPS + ["from_stored"]), func("from_stored", ["__extendsfdf2"] * 5)]))
        self.assertEqual([u["section_process_copies"] for u in mixed["f64_users_on_the_path"]], [1, None])
        self.assertEqual(mixed["f64_users_on_the_path"][1]["call_path"][-2:], ["franken_dsp::protection::runtime::ProtectedBoardDsp::render_into", "from_stored"])

    def test_the_call_path_is_the_shortest_from_the_root(self):
        # render -> a -> leaf (2 steps) and render -> b -> c -> leaf (3 steps): the path reported is the short one
        result = judge(elf([func(RENDER, ["a", "b"]), func("a", ["leaf"]), func("b", ["c"]), func("c", ["leaf"]), func("leaf", ["__divdf3"])]))
        self.assertEqual(result["f64_users_on_the_path"][0]["call_path"], ["franken_dsp::protection::runtime::ProtectedBoardDsp::render_into", "a", "leaf"])
        deep = judge(elf([func(RENDER, ["a"]), func("a", ["b"]), func("b", ["leaf"]), func("leaf", ["__divdf3"])]))
        self.assertEqual(deep["f64_users_on_the_path"][0]["call_path"],
                         ["franken_dsp::protection::runtime::ProtectedBoardDsp::render_into", "a", "b", "leaf"], "every step, root first")

    def test_the_limits_say_what_a_helper_count_is(self):
        self.assertTrue(any("CALL SITES" in limit and "not executions" in limit for limit in sf.LIMITS), sf.LIMITS)

    def test_f32_helpers_are_not_f64(self):
        result = judge(elf([func(RENDER, ["__mulsf3", "__addsf3", "__fixsfsi", "__floatsisf", "__gtsf2", "sqrtf", "__extendhfsf2", "__truncsfhf2"])]))
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["f64_users_on_the_path"], [])

    def test_a_relocation_in_a_non_code_section_is_not_a_call_edge(self):
        # `.rel.pdr` names every function; a function reachable ONLY through it must not be reached.
        objects = [func(RENDER, [SECTION]), func(SECTION, SECTION_OPS), func("orphan", ["__divdf3"])]
        self.assertEqual(judge(elf(objects, pdr_decoy=True))["verdict"], "PASS")
        # control for the plant above: the same orphan reached by a real call is a violation
        reached = judge(elf([func(RENDER, [SECTION, "orphan"]), func(SECTION, SECTION_OPS), func("orphan", ["__divdf3"])], pdr_decoy=True))
        self.assertEqual(reached["verdict"], "FAIL")

    def test_every_edge_kind_is_followed(self):
        for how, refs in (("global symbol", [("sym", "leaf")]), ("section symbol", [("sec", "leaf")])):
            for local in (False, True):
                with self.subTest(how=how, local=local):
                    result = judge(elf([func(RENDER, refs), func("leaf", ["__divdf3"], local=local)]))
                    self.assertEqual(self.violations(result), [("helper-outside-section-set", "leaf", "__divdf3")])

    def test_calls_between_objects_resolve_by_name(self):
        caller = elf([func(RENDER, ["callee"])])
        callee = elf([func("callee", ["__fixdfsi"])])
        self.assertEqual(judge(caller, callee)["verdict"], "FAIL")
        self.assertEqual(judge(caller)["verdict"], "PASS", "the control: with the callee's object absent there is nothing to follow")
        # a same-named local function in another object is not the callee
        other = elf([func("callee", ["__fixdfsi"], local=True)])
        self.assertEqual(judge(caller, other)["verdict"], "PASS")

    def test_rela_relocations_are_read_too(self):
        def build(plant, rela):
            return elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS), func(CONVERT, ["__muldf3"] if plant else [])], rela=rela)
        self.assertEqual(judge(build(False, True))["verdict"], "PASS")
        self.assertEqual(judge(build(True, True))["verdict"], "FAIL")

    def test_roots(self):
        obj = control_object()
        self.assertEqual(judge(obj, root="Section::process")["reachable_sections"], 1)
        self.assertEqual(judge(obj, root=SECTION)["verdict"], "PASS")
        self.assertRefuses("root-not-found", obj, root="no_such_function")
        # a v0-mangled build has no demangled path to match: the refusal says why
        v0 = elf([func("_RNvNtCs1_11franken_dsp3foo3bar", ["__muldf3"])])
        self.assertRefuses("root-not-found", v0, contains="v0 mangling")
        # embedded bitcode beside empty code is named too
        stub = elf([func("something_else")], llvmbc=True)
        self.assertRefuses("root-not-found", stub, contains="embedded bitcode")

    def test_one_section_holding_several_functions_is_flagged_as_coarse(self):
        shared = elf([func(RENDER, [SECTION], section=".text", code=NOP * 2), func(SECTION, SECTION_OPS, section=".text", code=NOP * 2)])
        # (both share one section: the call between them is a self reference and is not an edge)
        result = judge(shared)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["coarse_sections"], ["in0:.text"])
        user = result["f64_users_on_the_path"][0]
        self.assertEqual(user["function"], "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into")
        self.assertEqual(user["also"], ["franken_dsp::protection::runtime::Section::process"], "both names are kept; attribution is per section")

    def test_duplicate_globals_are_reported(self):
        a, b = elf([func(RENDER, ["dup"]), func("dup")]), elf([func("dup", ["__divdf3"])])
        self.assertEqual(judge(a, b)["duplicate_global_symbols"], ["dup"])


class Refusals(Base):
    def test_bitcode_members_are_refused_by_name_never_read_as_clean(self):
        for label, magic in (("bare", BC_MAGIC), ("wrapper", BC_WRAPPER_MAGIC)):
            with self.subTest(magic=label):
                bitcode = magic + b"\0" * 28
                a = ar([("franken_dsp.cgu.0.rcgu.o", bitcode)])
                err = self.assertRefuses("bitcode-member", a)
                self.assertIn("franken_dsp.cgu.0.rcgu.o", str(err), "the refusal names the member")
                self.assertRefuses("bitcode-member", bitcode)  # as a bare file, too
        self.assertRefuses("bitcode-member", ar([("franken_dsp.cgu.0.rcgu.bc", b"BC\xc0\xde....")]))
        self.assertRefuses("bitcode-member", ar([("franken_dsp.cgu.0.rcgu.bc.z", b"compressed bitcode....")]))

    def test_a_mixed_archive_is_refused_whole_and_removing_the_bitcode_member_clears_it(self):
        good = ("a.rcgu.o", control_object())
        self.assertEqual(judge(ar([good]))["verdict"], "PASS", "the control: the same archive without the bitcode member")
        self.assertRefuses("bitcode-member", ar([good, ("b.rcgu.o", BC_MAGIC + b"\0" * 28)]), contains="b.rcgu.o")
        self.assertRefuses("bitcode-member", ar([("b.rcgu.o", BC_MAGIC + b"\0" * 28), good]), contains="b.rcgu.o")

    def test_an_elf_with_embedded_bitcode_beside_real_code_is_read_not_refused(self):
        result = judge(elf([func(RENDER, [SECTION]), func(SECTION, SECTION_OPS)], llvmbc=True))
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["objects"][0]["embedded_bitcode"])

    def test_wrong_kind_of_elf(self):
        good = [func(RENDER, [SECTION]), func(SECTION, SECTION_OPS)]
        self.assertRefuses("not-big-endian-elf32", elf(good, data=1))
        self.assertRefuses("not-big-endian-elf32", elf(good, cls=2))
        self.assertRefuses("not-mips", elf(good, machine=20))
        self.assertRefuses("not-relocatable", elf(good, etype=2))
        self.assertRefuses("no-symbol-table", elf(good, symtab=False))
        self.assertRefuses("truncated-elf", elf(good)[:60])
        self.assertRefuses("truncated-elf", elf(good, shnum_override=500))
        self.assertRefuses("truncated-elf", elf(good, shnum_override=0), contains="count 0")
        self.assertRefuses("truncated-elf", elf(good, shentsize_override=64), contains="entry size 64")
        # a section whose header claims more bytes than the file holds (the control is the same object, unaltered)
        self.assertEqual(judge(elf(good))["verdict"], "PASS")
        self.assertRefuses("truncated-elf", elf(good, size_override={".symtab": 0x10000000}), contains="runs past the end of the file")
        self.assertRefuses("truncated-elf", elf(good, size_override={".text." + RENDER: 0x10000000}), contains="runs past the end of the file")

    def test_not_soft_float_is_refused_on_either_kind_of_evidence(self):
        code = [func(RENDER, [SECTION]), func(SECTION, SECTION_OPS)]
        for abi in (1, 2, 4, 5):
            self.assertRefuses("not-soft-float", elf(code, fp_abi=abi), contains=f"fp_abi is {abi}")
        for word in (COP1, LWC1):
            hard = [func(RENDER, [SECTION], code=NOP * 3 + word), func(SECTION, SECTION_OPS)]
            self.assertRefuses("not-soft-float", elf(hard, fp_abi=3), contains="FPU opcode")
            self.assertRefuses("not-soft-float", elf(hard, fp_abi=0), contains="FPU opcode")
            self.assertRefuses("not-soft-float", elf(hard, abiflags=False), contains="FPU opcode")

    def test_soft_float_evidence_is_reported_as_what_it_is(self):
        code = [func(RENDER, [SECTION]), func(SECTION, SECTION_OPS)]
        self.assertEqual(judge(elf(code, fp_abi=3))["objects"][0]["soft_float_evidence"], "abiflags fp_abi 3")
        for kw in ({"fp_abi": 0}, {"abiflags": False}):
            evidence = judge(elf(code, **kw))["objects"][0]["soft_float_evidence"]
            self.assertIn("no FPU opcode", evidence)
            self.assertIn("state no float ABI", evidence)

    def test_nothing_to_judge(self):
        self.assertRefuses("nothing-to-judge", ar([("lib.rmeta", b"rust")]))
        self.assertRefuses("nothing-to-judge", elf([]))
        self.assertRefuses("unknown-member-format", ar([("x.o", b"\x01\x02\x03\x04rest")]))

    def test_every_refusal_code_in_the_script_is_exercised_here(self):
        codes = set(re.findall(r'Refusal\("([a-z0-9-]+)"', SCRIPT.read_text(encoding="utf-8")))
        tested = set(re.findall(r'assert(?:Parse|Cli)?Refuses\("([a-z0-9-]+)"', pathlib.Path(__file__).read_text(encoding="utf-8")))
        self.assertEqual(sorted(codes - tested), [], "a refusal code with no test")
        self.assertEqual(sorted(tested - codes), [], "a test names a refusal code the script does not have")
        self.assertGreaterEqual(len(codes), 12)

    def test_bad_relocation_symbol_is_refused(self):
        control = elf([func(RENDER, [SECTION]), func(SECTION, SECTION_OPS)])
        self.assertEqual(judge(control)["verdict"], "PASS")
        # the same object with one relocation naming a symbol that does not exist
        self.assertRefuses("bad-relocation", elf([func(RENDER, [("raw", 9999)]), func(SECTION, SECTION_OPS)]))


class RealObject(Base):
    """tests/d02/fixtures/softfloat/realfix-mips-be-softfloat.o.hex: zig 0.15.2, zig cc -target mips-linux-musleabi -O2 -g0
    -ffunction-sections -fno-asynchronous-unwind-tables -c realfix.c. Expected relocations are from llvm-readelf -r."""

    SHA256 = "43805620b763ac94"  # prefix; a changed fixture is a deliberate act

    def setUp(self):
        self.data = real_object()

    def test_the_fixture_is_the_one_the_expectations_were_taken_from(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest()[:16], self.SHA256)

    def test_helpers_per_function_match_llvm_readelf(self):
        result = judge(self.data, root="root")
        users = {u["function"]: u["helpers"] for u in result["f64_users_on_the_path"]}
        self.assertEqual(users, {
            "section_like": {"__adddf3": 4, "__extendsfdf2": 1, "__muldf3": 5, "__truncdfsf2": 1},
            "old_conversion": {"__extendsfdf2": 1, "__fixdfsi": 1, "__gedf2": 1, "__muldf3": 1},
        }, "int_conversion has none; __gtsf2 in root is f32 and is not counted")
        self.assertEqual(result["reachable_sections"], 5, "root reaches section_like, int_conversion and, through a SECTION symbol, local_helper and old_conversion")

    def test_the_real_object_reaching_the_old_conversion_fails_and_not_reaching_it_passes(self):
        failing = judge(self.data, root="root")
        self.assertEqual(self.violations(failing), [("helper-outside-section-set", "old_conversion", "__fixdfsi"),
                                                    ("helper-outside-section-set", "old_conversion", "__gedf2")])
        self.assertEqual(judge(self.data, root="section_like")["verdict"], "PASS")
        self.assertEqual(judge(self.data, root="int_conversion")["verdict"], "PASS")
        self.assertEqual(judge(self.data, root="int_conversion")["f64_helper_call_sites_on_the_path"], {})

    def test_the_objects_soft_float_evidence_is_the_absence_of_fpu_opcodes(self):
        obj = judge(self.data, root="root")["objects"][0]
        self.assertIn(obj["fp_abi"], (0, None), "zig records no float ABI in this object")
        self.assertGreater(obj["executable_words_scanned"], 100)
        self.assertIn("no FPU opcode", obj["soft_float_evidence"])

    def test_a_bit_flipped_into_a_cop1_word_makes_the_real_object_refused(self):
        # the planted negative on real bytes: turn the first instruction of int_conversion's section into an FPU word
        marker = sf.read_object("x", self.data)
        section = next(s for s in marker.sections if s.name == ".text.int_conversion")
        flipped = bytearray(self.data)
        struct.pack_into(">I", flipped, section.offset, 0x11 << 26)
        with self.assertRaises(sf.Refusal) as raised:
            sf.read_object("x", bytes(flipped))
        self.assertEqual(raised.exception.code, "not-soft-float")
        sf.read_object("x", self.data)  # the control: the unflipped object reads


class BuildScript(unittest.TestCase):
    """toolchain/src/softfloat-build.sh against STUB `cargo` and `rustc`: this checks the script's own logic (modes, how it
    finds the artefact, which files it keeps, the manifest, its failures), never the real compiler flags working. Nothing is
    compiled. The stub cargo prints cargo-style JSON messages on stdout, with the artefacts in either directory layout (the
    new one has no `release/deps/`, which is what broke the first version on trj) and with decoys."""

    SH = REPO / "toolchain" / "src" / "softfloat-build.sh"
    CARGO = """#!/bin/sh
echo "$@" >> "$STUB_LOG"
echo "CARGO_HOME=${CARGO_HOME:-unset}" >> "$STUB_LOG"
case "$*" in *" -V"*) echo "cargo 0.0.0-stub"; exit 0 ;; esac
echo "   Compiling something   (human noise on stdout is not JSON)"
echo '{"reason":"compiler-artifact","package_id":"registry+x#serde 1.0.0","target":{"kind":["lib"],"crate_types":["lib"],"name":"serde"},"filenames":["/nonexistent/libserde-def456.rlib"],"fresh":false}'
[ -z "${STUB_NO_OUTPUT:-}" ] || exit 0
case "${STUB_LAYOUT:-new}" in
  new) dir="$CARGO_TARGET_DIR/mips-unknown-linux-musl/release/build/franken-dsp/abc123/out" ;;
  *)   dir="$CARGO_TARGET_DIR/mips-unknown-linux-musl/release/deps" ;;
esac
mkdir -p "$dir"
[ -n "${STUB_RLIB_MISSING:-}" ] || printf RLIB > "$dir/libfranken_dsp-abc123.rlib"
printf META > "$dir/libfranken_dsp-abc123.rmeta"
printf DECOY > "$dir/libserde-def456.rlib"
printf EXTRA > "$dir/libfranken_dsp_extra-777.rlib"
case "$*" in
  *--emit=obj*) [ -n "${STUB_NO_OBJ:-}" ] || printf OBJ > "$dir/franken_dsp-abc123.o"; printf DECOY > "$dir/franken_board_profile-def456.o" ;;
esac
echo "{\\"reason\\":\\"compiler-artifact\\",\\"package_id\\":\\"path+file:///x/crates/franken-dsp#0.1.0\\",\\"target\\":{\\"kind\\":[\\"lib\\"],\\"crate_types\\":[\\"lib\\"],\\"name\\":\\"franken_dsp\\"},\\"filenames\\":[\\"$dir/libfranken_dsp-abc123.rlib\\",\\"$dir/libfranken_dsp-abc123.rmeta\\"],\\"fresh\\":false}"
echo "{\\"reason\\":\\"compiler-artifact\\",\\"package_id\\":\\"path+file:///x/franken-dsp-extra#0.1.0\\",\\"target\\":{\\"kind\\":[\\"lib\\"],\\"crate_types\\":[\\"lib\\"],\\"name\\":\\"franken_dsp_extra\\"},\\"filenames\\":[\\"$dir/libfranken_dsp_extra-777.rlib\\"],\\"fresh\\":false}"
echo '{"reason":"build-finished","success":true}'
"""
    RUSTC = "#!/bin/sh\necho 'rustc 0.0.0-stub (nightly)'\n"

    def run_script(self, *args, cache=False, cargo_home=None, env=None, extra_bin=None):
        import subprocess
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, text in (("cargo", self.CARGO), ("rustc", self.RUSTC), *(extra_bin or {}).items()):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        if cache:  # a stand-in for /scratch/tmp/rch-cargo-cache-<worker>
            (root / "rch-cargo-cache-trj").mkdir()
        full_env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "STUB_LOG": str(root / "argv.log"),
                    "FFW_RCH_CARGO_CACHE_GLOB": str(root / "rch-cargo-cache-*")}
        if cargo_home:
            full_env["CARGO_HOME"] = cargo_home
        full_env.update(env or {})
        done = subprocess.run(["sh", str(self.SH), *args], cwd=root, env=full_env, capture_output=True, text=True, check=False)
        log = (root / "argv.log").read_text() if (root / "argv.log").exists() else ""
        return done, root, log

    def cargo_line(self, log, word):
        return [line for line in log.splitlines() if f" {word} " in f" {line} "][0]

    def test_rlib_mode_builds_with_lto_off_and_keeps_only_the_franken_dsp_rlib(self):
        done, root, log = self.run_script("rlib", "build/softfloat/rlib")
        self.assertEqual(done.returncode, 0, done.stderr)
        kept = sorted(p.name for p in (root / "build/softfloat/rlib").iterdir())
        self.assertEqual(kept, ["MANIFEST.txt", "cargo-messages.jsonl", "libfranken_dsp-abc123.rlib", "rustc-vV.txt"],
                         "the decoy and look-alike rlibs and the rmeta are not kept")
        build = self.cargo_line(log, "build")
        for flag in ("+nightly", "--offline", "--release", "--target mips-unknown-linux-musl", "-Z build-std=core,alloc,std,panic_abort",
                     "-p franken-dsp", "--lib", "-j 2", "--message-format=json", 'profile.release.lto="off"', 'profile.release.strip="none"'):
            self.assertIn(flag, build)
        self.assertEqual(build.count("--config"), 3, "the rustflags, lto and strip: nothing else is overridden")
        self.assertNotIn("--emit", build)

    # What rustc is KNOWN to refuse without `-Z unstable-options`: learned from central runs, not derived from rustc.
    NEEDS_UNSTABLE_OPTIONS = ("symbol-mangling-version=legacy",)  # b54, 2026-11-05: rc 101 "requires `-Z unstable-options`"
    EXPECTED_RUSTFLAGS = ["-C", "target-feature=+crt-static", "-C", "link-self-contained=no", "-Z", "unstable-options",
                          "-C", "symbol-mangling-version=legacy"]

    @staticmethod
    def rustflags_of(line):
        found = re.search(r"target\.mips-unknown-linux-musl\.rustflags=(\[[^\]]*\])", line)
        return json.loads(found.group(1)) if found else None

    @classmethod
    def unstable_violations(cls, flags):
        """Flags in a rustflags list that rustc is known to refuse because `-Z unstable-options` is not also in the list."""
        unstable = any(a == "-Z" and b == "unstable-options" for a, b in zip(flags, flags[1:]))
        return [] if unstable else [f for f in flags if f in cls.NEEDS_UNSTABLE_OPTIONS]

    def test_the_exact_rustflags_list_is_pinned_for_both_modes(self):
        for mode, word in (("rlib", "build"), ("obj", "rustc")):
            with self.subTest(mode=mode):
                done, _, log = self.run_script(mode, f"build/softfloat/{mode}")
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(self.rustflags_of(self.cargo_line(log, word)), self.EXPECTED_RUSTFLAGS)

    def test_a_flag_rustc_refuses_without_unstable_options_is_never_passed_without_it(self):
        # planted: the list b54 sent, which rustc rejected in 6 s; control: the list now sent
        b54 = ["-C", "target-feature=+crt-static", "-C", "link-self-contained=no", "-C", "symbol-mangling-version=legacy"]
        self.assertEqual(self.unstable_violations(b54), ["symbol-mangling-version=legacy"])
        self.assertEqual(self.unstable_violations(self.EXPECTED_RUSTFLAGS), [])
        for mode, word in (("rlib", "build"), ("obj", "rustc")):
            with self.subTest(mode=mode):
                _, _, log = self.run_script(mode, f"build/softfloat/{mode}")
                self.assertEqual(self.unstable_violations(self.rustflags_of(self.cargo_line(log, word))), [])

    def test_the_manifest_names_the_deviation_and_carries_the_hashes(self):
        done, root, _ = self.run_script("rlib", "build/softfloat/rlib")
        self.assertEqual(done.returncode, 0, done.stderr)
        manifest = (root / "build/softfloat/rlib/MANIFEST.txt").read_text()
        self.assertEqual(manifest, done.stdout, "what it prints is what it recorded")
        self.assertIn("mode: rlib", manifest)
        self.assertIn("deviation: lto=off.", manifest)
        self.assertIn("shipped ELF is fat-LTO'd and may inline differently", manifest)
        self.assertIn("LLVM bitcode", manifest, "and says why")
        self.assertIn("deviation: strip=none", manifest)
        self.assertIn("deviation: symbol-mangling-version=legacy", manifest)
        self.assertIn("NAMES only", manifest, "and says it changes no code")
        self.assertIn("-Z unstable-options", manifest, "and that the flag is unstable (nightly-only)")
        self.assertEqual(manifest.count("\ndeviation: "), 3, "exactly three: lto, strip, symbol mangling; nothing else differs from the shipped build")
        self.assertIn("found-by: cargo --message-format=json", manifest)
        self.assertIn(f"{hashlib.sha256(b'RLIB').hexdigest()}  libfranken_dsp-abc123.rlib", manifest)
        self.assertIn("  cargo-messages.jsonl", manifest)
        self.assertIn("rustc 0.0.0-stub", (root / "build/softfloat/rlib/rustc-vV.txt").read_text(), "the compiler is recorded")
        self.assertIn('"reason":"compiler-artifact"', (root / "build/softfloat/rlib/cargo-messages.jsonl").read_text())

    def test_the_sha256sum_branch_hashes_the_artefact_and_the_messages(self):
        # Which of `sha256sum` and `shasum` the script uses depends on the machine; a stub forces the first everywhere.
        stub = "#!/bin/sh\nfor f in \"$@\"; do echo \"feedface  $f\"; done\n"
        done, root, _ = self.run_script("rlib", "build/softfloat/rlib", extra_bin={"sha256sum": stub})
        self.assertEqual(done.returncode, 0, done.stderr)
        manifest = (root / "build/softfloat/rlib/MANIFEST.txt").read_text()
        self.assertIn("feedface  libfranken_dsp-abc123.rlib", manifest)
        self.assertIn("feedface  cargo-messages.jsonl", manifest)

    def test_the_artefact_is_found_from_cargos_json_whatever_the_directory_layout(self):
        for layout in ("new", "old"):
            with self.subTest(layout=layout):
                done, root, _ = self.run_script("rlib", "build/softfloat/rlib", env={"STUB_LAYOUT": layout})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue((root / "build/softfloat/rlib/libfranken_dsp-abc123.rlib").exists())
                found_at = [ln for ln in done.stdout.splitlines() if ln.startswith("artifact-found-at:")][0]
                self.assertIn("release/build/franken-dsp/abc123/out" if layout == "new" else "release/deps", found_at)

    def test_obj_mode_asks_rustc_for_a_real_object_found_beside_the_rlib(self):
        for layout in ("new", "old"):
            with self.subTest(layout=layout):
                done, root, log = self.run_script("obj", "build/softfloat/obj", env={"STUB_LAYOUT": layout})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(sorted(p.name for p in (root / "build/softfloat/obj").iterdir()),
                                 ["MANIFEST.txt", "cargo-messages.jsonl", "franken_dsp-abc123.o", "rustc-vV.txt"])
                rustc_line = self.cargo_line(log, "rustc")
                self.assertTrue(rustc_line.endswith("--message-format=json -- --emit=obj"), rustc_line)
                self.assertIn('profile.release.lto="off"', rustc_line)
                self.assertIn("-p franken-dsp --lib", rustc_line)
                self.assertIn("mode: obj", done.stdout)
                self.assertIn(f"{hashlib.sha256(b'OBJ').hexdigest()}  franken_dsp-abc123.o", done.stdout)

    def test_no_artefact_is_a_failure_not_an_empty_success(self):
        for name, env, message in (("no franken_dsp artifact line", {"STUB_NO_OUTPUT": "1"}, "no franken_dsp rlib that exists"),
                                   ("an artifact line whose file does not exist", {"STUB_RLIB_MISSING": "1"}, "no franken_dsp rlib that exists")):
            with self.subTest(name):
                done, root, _ = self.run_script("rlib", "build/softfloat/rlib", env=env)
                self.assertEqual(done.returncode, 3)
                self.assertIn(message, done.stderr)
                self.assertFalse((root / "build/softfloat/rlib/MANIFEST.txt").exists(), "no manifest for a build that produced nothing")
        done, root, _ = self.run_script("obj", "build/softfloat/obj", env={"STUB_NO_OBJ": "1"})
        self.assertEqual(done.returncode, 3)
        self.assertIn("no object", done.stderr)
        self.assertFalse((root / "build/softfloat/obj/MANIFEST.txt").exists())

    def test_job_mode_has_no_cargo_home_so_the_workers_rch_cache_is_used_when_it_exists(self):
        # `rch exec --job` leaves CARGO_HOME unset (the worker's older ~/.cargo); an --offline build there misses crates.
        done, root, log = self.run_script("rlib", "build/softfloat/rlib", cache=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        cache = root / "rch-cargo-cache-trj"
        self.assertIn(f"CARGO_HOME={cache}", log.splitlines(), "cargo ran with the worker's rch cache")
        self.assertNotIn("CARGO_HOME=unset", log.splitlines())
        self.assertIn(f"CARGO_HOME: {cache}", (root / "build/softfloat/rlib/rustc-vV.txt").read_text(), "and the record says which")

    def test_without_that_cache_cargo_home_stays_unset_and_the_record_says_so(self):
        done, root, log = self.run_script("rlib", "build/softfloat/rlib", cache=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(any(ln.startswith("CARGO_HOME=") for ln in log.splitlines()), "cargo was run and its environment recorded")
        self.assertTrue(all(ln == "CARGO_HOME=unset" for ln in log.splitlines() if ln.startswith("CARGO_HOME=")), log)
        self.assertIn("CARGO_HOME: unset", (root / "build/softfloat/rlib/rustc-vV.txt").read_text())

    def test_a_cargo_home_the_caller_set_is_not_overridden(self):
        done, root, log = self.run_script("rlib", "build/softfloat/rlib", cache=True, cargo_home="/somewhere/else")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(all(ln == "CARGO_HOME=/somewhere/else" for ln in log.splitlines() if ln.startswith("CARGO_HOME=")), log)
        self.assertIn("CARGO_HOME: /somewhere/else", (root / "build/softfloat/rlib/rustc-vV.txt").read_text())

    def test_usage_errors(self):
        for args in ((), ("rlib",), ("zip", "x"), ("", "x")):
            with self.subTest(args=args):
                done, _, log = self.run_script(*args)
                self.assertEqual(done.returncode, 2)
                self.assertIn("usage", done.stderr)
                self.assertEqual(log, "", "nothing ran")

    def test_the_script_names_its_consumer_deletion_condition_and_deviation(self):
        text = self.SH.read_text()
        for needle in ("Consumer:", "Deletion condition:", "Defect class:", "--result-dir", "rustc +nightly -vV",
                       "THE DEVIATION FROM THE SHIPPED BUILD", "BITCODE", "b50"):
            self.assertIn(needle, text)


class Cli(Base):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            good, bad, bc = tmp / "good.o", tmp / "bad.o", tmp / "bc.rlib"
            good.write_bytes(control_object())
            bad.write_bytes(elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS), func(CONVERT, ["__muldf3"])]))
            bc.write_bytes(ar([("x.rcgu.o", BC_MAGIC + b"\0" * 28)]))
            code, out, err = self.run_cli(str(good))
            self.assertEqual((code, err), (0, ""))
            self.assertIn("softfloat-symbols: PASS", out)
            self.assertIn("limits:", out)
            self.assertIn("not the final LTO'd and linked speaker ELF", out)
            code, out, _ = self.run_cli(str(bad))
            self.assertEqual(code, 1)
            self.assertIn("VIOLATION [f64-in-conversion]", out)
            code, out, err = self.run_cli(str(bc))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("bitcode-member", err)
            self.assertIn("No claim about f64 calls is made", err)
            code, _, err = self.run_cli(str(tmp / "missing.o"))
            self.assertEqual(code, 2)
            self.assertIn("unreadable-input", err)
            code, out, _ = self.run_cli("--json", str(good))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["verdict"], "PASS")
            code, out, _ = self.run_cli("--root", "Section::process", str(good))
            self.assertEqual(code, 0)
            self.assertEqual(out.splitlines()[1], "root: franken_dsp::protection::runtime::Section::process")


def relocation_types(obj_bytes, section_name):
    """The relocation types of one `.rel.<section_name>` section, read straight from the ELF bytes (independent of the checker)."""
    parsed = sf.read_object("x", obj_bytes)
    for s in parsed.sections:
        if s.name == f".rel{section_name}":
            body = obj_bytes[s.offset:s.offset + s.size]
            return [struct.unpack(">I", body[i + 4:i + 8])[0] & 0xFF for i in range(0, len(body), 8)]
    raise AssertionError(f"no .rel{section_name}")


class PicCounting(Base):
    """PIC code makes every call TWO relocations against one symbol (R_MIPS_CALL16, then the R_MIPS_JALR hint). Counting relocations
    doubled every count on the real b56 rlib (render_into read as 2 whole copies of Section::process, from_stored as 10 widenings,
    where the source has 1 and 5). A call site is one call relocation."""

    EXPECTED = {"__adddf3": 2, "__extendsfdf2": 1, "__muldf3": 5, "__subdf3": 2, "__truncdfsf2": 1}

    def test_a_pic_call_is_one_call_site_not_two(self):
        plain, pic = judge(control_object()), judge(control_object(pic=True))
        self.assertEqual(plain["f64_helper_call_sites_on_the_path"], self.EXPECTED)
        self.assertEqual(pic["f64_helper_call_sites_on_the_path"], self.EXPECTED, "the JALR hint is not a second call")
        self.assertEqual([u["section_process_copies"] for u in pic["f64_users_on_the_path"]], [1])
        self.assertEqual(pic["verdict"], "PASS")

    def test_every_call_style_counts_one_per_call(self):
        for pic in (False, True):
            for rela in (False, True):
                with self.subTest(pic=pic, rela=rela):
                    result = judge(control_object(pic=pic, rela=rela))
                    self.assertEqual(result["f64_helper_call_sites_on_the_path"], self.EXPECTED)

    def test_an_address_taken_helper_is_used_but_is_not_a_call_site(self):
        allowed = judge(elf([func(RENDER, [SECTION, ("addr", "__muldf3")]), func(SECTION, SECTION_OPS)]))
        self.assertEqual(allowed["verdict"], "PASS")
        render = [u for u in allowed["f64_users_on_the_path"] if u["function"].endswith("render_into")][0]
        self.assertEqual(render["helpers"], {"__muldf3": 0}, "referenced, never called here")
        self.assertEqual(allowed["f64_helper_call_sites_on_the_path"]["__muldf3"], 5, "only Section's own five calls")
        forbidden = judge(elf([func(RENDER, [SECTION, ("addr", "__divdf3")]), func(SECTION, SECTION_OPS)]))
        self.assertEqual(self.violations(forbidden), [("helper-outside-section-set", "franken_dsp::protection::runtime::ProtectedBoardDsp::render_into", "__divdf3")],
                         "presence is the violation rule: a divide helper whose address is taken is still on the path")

    def test_local_calls_through_pic_got_pairs_are_edges(self):
        for local in (False, True):
            with self.subTest(local=local):
                reached = judge(elf([func(RENDER, [("sec", "leaf")]), func("leaf", ["__divdf3"], local=local)], pic=True))
                self.assertEqual(reached["verdict"], "FAIL")
                orphan = judge(elf([func(RENDER, []), func("leaf", ["__divdf3"], local=local)], pic=True))
                self.assertEqual(orphan["verdict"], "PASS", "the control: the same leaf with no call to it")

    def test_the_real_pic_object_is_pic_and_its_counts_are_calls_not_relocations(self):
        data = real_pic_object()
        self.assertEqual(hashlib.sha256(data).hexdigest()[:16], "ffb52cd618c6ed0f")
        types = relocation_types(data, ".text.section_like")
        self.assertEqual((types.count(11), types.count(37), len(types)), (11, 11, 24),
                         "llvm-readelf: 11 CALL16 + 11 JALR + the HI16/LO16 pair on _gp_disp")
        users = {u["function"]: u["helpers"] for u in judge(data, root="root")["f64_users_on_the_path"]}
        self.assertEqual(users["section_like"], {"__adddf3": 4, "__extendsfdf2": 1, "__muldf3": 5, "__truncdfsf2": 1},
                         "11 calls, not 22 relocations")

    def test_real_pic_and_real_non_pic_objects_of_one_source_agree(self):
        plain, pic = judge(real_object(), root="root"), judge(real_pic_object(), root="root")
        strip = lambda r: ([(u["function"], u["helpers"], u["call_path"]) for u in r["f64_users_on_the_path"]], r["reachable_sections"], r["verdict"],
                           self.violations(r))  # noqa: E731
        self.assertEqual(strip(plain), strip(pic))
        self.assertEqual(pic["reachable_sections"], 5, "root reaches all four callees, one through a GOT16 + section symbol")
        self.assertEqual(pic["verdict"], "FAIL")


class RealShapes(Base):
    """What a real rlib holds (b56, rustc 1.101.0-nightly 708c94ef0): two ELF wrappers around rustc's metadata, `lib.rmeta` (a
    `.rmeta` section) and `lib.rmeta-link` (a `.rmeta-link` section), neither with code or `.MIPS.abiflags`, and one code member."""

    CODE_NAME = "franken_dsp-4ba94165e5b2af33.franken_dsp.1e8c1debe93f1cd1-cgu.0.rcgu.o"

    def wrapper(self, section=".rmeta", **kw):
        return elf([], abiflags=False, pdr_decoy=False, extra_sections=[(section, b"m" * 40)], **kw)

    def rlib(self, code=None, **kw):
        code = control_object(fp_abi=0, pic=True) if code is None else code
        return ar([("lib.rmeta", self.wrapper(".rmeta")), ("lib.rmeta-link", self.wrapper(".rmeta-link")), (self.CODE_NAME, code)], **kw)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_the_b56_rlib_shape_is_one_object_and_two_non_code_members(self):
        result = judge(self.rlib())
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(len(result["objects"]), 1)
        self.assertEqual(result["objects"][0]["fp_abi"], 0)
        self.assertEqual([n["member"] for n in result["non_code_members"]], ["in0[lib.rmeta]", "in0[lib.rmeta-link]"])
        self.assertEqual([n["sections"] for n in result["non_code_members"]], [[".rmeta"], [".rmeta-link"]])
        self.assertEqual(result["skipped_metadata_members"], [], "they are ELF: judged by their bytes, so not skipped by name")
        self.assertEqual(result["f64_helper_call_sites_on_the_path"], PicCounting.EXPECTED)

    def test_the_text_report_does_not_crash_on_a_real_shaped_rlib_and_json_agrees(self):
        # b56: render() sorted {0, None} and raised TypeError on exactly this shape
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "libfranken_dsp-4ba94165e5b2af33.rlib"
            path.write_bytes(self.rlib())
            rc, out, err = self.run_cli(str(path))
            self.assertEqual((rc, err), (0, ""), err)
            self.assertIn("objects with code: 1 (fp_abi 0)", out)
            self.assertIn("non-code member, not judged:", out)
            self.assertIn("lib.rmeta-link", out)
            rc, out, err = self.run_cli("--json", str(path))
            self.assertEqual(rc, 0)
            self.assertEqual(len(json.loads(out)["non_code_members"]), 2)

    def test_objects_with_and_without_abiflags_render_together(self):
        mixed = ar([("a.rcgu.o", control_object(fp_abi=0)), ("b.rcgu.o", control_object(abiflags=False))])
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.a"
            path.write_bytes(mixed)
            rc, out, err = self.run_cli(str(path))
            self.assertEqual((rc, err), (0, ""), err)
            self.assertIn("fp_abi 0, absent", out)
        self.assertEqual(sorted(str(o["fp_abi"]) for o in judge(mixed)["objects"]), ["0", "None"])

    def test_an_elf_wrapper_with_embedded_bitcode_and_no_code_is_refused(self):
        stub = ar([(self.CODE_NAME, self.wrapper(".rmeta", llvmbc=True))])
        self.assertRefuses("bitcode-member", stub, contains="no machine code and an embedded bitcode section")
        # the control: the same wrapper without the bitcode section is a non-code member, and the archive still judges
        self.assertEqual(judge(self.rlib())["verdict"], "PASS")
        self.assertRefuses("bitcode-member", self.rlib(code=self.wrapper(".rmeta", llvmbc=True)), contains=self.CODE_NAME)

    def test_a_name_never_hides_an_object_and_never_excuses_bitcode(self):
        # an ELF with code named like rustc metadata is an object, not skipped
        named = judge(ar([("lib.rmeta", control_object())]))
        self.assertEqual((len(named["objects"]), named["skipped_metadata_members"]), (1, []))
        # bitcode under a metadata name is refused
        self.assertRefuses("bitcode-member", ar([("lib.rmeta", BC_MAGIC + b"\0" * 28)]))
        self.assertRefuses("bitcode-member", ar([("lib.rmeta-link", BC_WRAPPER_MAGIC + b"\0" * 28)]))
        # raw (non-ELF, non-bitcode) metadata is skipped by name, both names
        raw = judge(ar([("lib.rmeta", b"rust\0\0\0\0meta"), ("lib.rmeta-link", b"rust\0\0\0\0link"), ("a.rcgu.o", control_object())]))
        self.assertEqual(raw["skipped_metadata_members"], ["in0[lib.rmeta]", "in0[lib.rmeta-link]"])

    def test_nothing_to_judge_names_the_non_code_members(self):
        err = self.assertRefuses("nothing-to-judge", ar([("lib.rmeta", self.wrapper()), ("lib.rmeta-link", self.wrapper(".rmeta-link"))]))
        self.assertIn("2 non-code members", str(err))
        self.assertIn("lib.rmeta-link", str(err))

    def test_coarse_sections_are_reported_where_they_matter(self):
        shared = [func(RENDER, [SECTION, "shared_a"]), func(SECTION, SECTION_OPS),
                  func("shared_a", [], section=".text.shared"), func("shared_b", [], section=".text.shared"),
                  func("off_a", [], section=".text.off"), func("off_b", [], section=".text.off")]
        result = judge(elf(shared))
        self.assertEqual(result["coarse_sections_on_the_path"], [["shared_a", "shared_b"]], "the one the path goes through, by function names")
        self.assertEqual(len(result["coarse_sections"]), 2, "both are counted")
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "x.o"
            path.write_bytes(elf(shared))
            _, out, _ = self.run_cli(str(path))
            self.assertIn("ON THE PATH, so attribution there is per section: shared_a | shared_b", out)
            self.assertIn("2 sections in all hold several functions; the others are not on the path", out)
            self.assertEqual(out.count("note:"), 2, "one line for the section on the path and one summary, not one line per section")


class CliJsonAndManifest(Base):
    """`--json` always prints an object (a REFUSED input used to print nothing on stdout); the build manifest beside the
    input is copied into the verdict; a root that is not found says what it did find."""

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def assertCliRefuses(self, code, *argv):
        rc, out, err = self.run_cli(*argv)
        self.assertEqual((rc, out), (2, ""), "text mode: exit 2 and nothing on stdout")
        self.assertIn(code, err)
        rc, out, err = self.run_cli("--json", *argv)
        self.assertEqual(rc, 2, "the exit code does not depend on --json")
        self.assertIn(code, err, "the human message still goes to stderr")
        result = json.loads(out)
        self.assertEqual(result["verdict"], "REFUSED")
        self.assertEqual(result["refusal"]["code"], code)
        self.assertTrue(result["refusal"]["message"])
        self.assertTrue(result["claim"].startswith("none"))
        self.assertEqual(result["limits"], sf.LIMITS)
        return result

    def test_json_mode_prints_an_object_for_every_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            good, bad, bc = tmp / "good.o", tmp / "bad.o", tmp / "bc.rlib"
            good.write_bytes(control_object())
            bad.write_bytes(elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS), func(CONVERT, ["__muldf3"])]))
            bc.write_bytes(ar([("x.rcgu.o", BC_MAGIC + b"\0" * 28)]))
            refused = self.assertCliRefuses("bitcode-member", str(bc))
            self.assertEqual([i["file"] for i in refused["inputs"]], [str(bc)])
            self.assertEqual(refused["inputs"][0]["sha256"], hashlib.sha256(bc.read_bytes()).hexdigest())
            missing = self.assertCliRefuses("unreadable-input", str(tmp / "missing.o"))
            self.assertEqual(missing["inputs"], [], "nothing was read")
            self.assertCliRefuses("root-not-found", "--root", "no_such_function", str(good))
            rc, out, _ = self.run_cli("--json", str(good))
            self.assertEqual((rc, json.loads(out)["verdict"]), (0, "PASS"))
            rc, out, _ = self.run_cli("--json", str(bad))
            self.assertEqual((rc, json.loads(out)["verdict"]), (1, "FAIL"))

    def test_the_build_manifest_beside_the_input_is_copied_into_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            obj = tmp / "franken_dsp-abc123.o"
            obj.write_bytes(control_object())
            rc, out, _ = self.run_cli(str(obj))
            self.assertEqual(rc, 0)
            self.assertIn("build manifest: none beside", out)
            self.assertIn("cannot be stated from the file", out)
            manifest = tmp / "MANIFEST.txt"
            manifest.write_text("mode: obj\ndeviation: lto=off. The shipped ELF is fat-LTO'd and may inline differently.\n"
                                "deviation: strip=none. No code-generation effect.\nfiles: 1\n")
            rc, out, _ = self.run_cli(str(obj))
            self.assertEqual(rc, 0)
            self.assertNotIn("build manifest: none beside", out)
            self.assertIn(f"build manifest beside {obj}", out)
            self.assertIn("DEVIATION FROM THE SHIPPED BUILD: lto=off. The shipped ELF is fat-LTO'd and may inline differently.", out)
            self.assertIn("DEVIATION FROM THE SHIPPED BUILD: strip=none.", out)
            rc, out, _ = self.run_cli("--json", str(obj))
            entry = json.loads(out)["build_manifests"][0]
            self.assertEqual(entry["file"], str(obj))
            self.assertEqual(entry["manifest"]["mode"], "obj")
            self.assertEqual(len(entry["manifest"]["deviations"]), 2)
            self.assertEqual(entry["manifest"]["sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
            # a refused input still reports the manifest it sat beside
            bc = tmp / "bc.rlib"
            bc.write_bytes(ar([("x.rcgu.o", BC_MAGIC + b"\0" * 28)]))
            rc, out, _ = self.run_cli("--json", str(bc))
            self.assertEqual(json.loads(out)["build_manifests"][0]["manifest"]["mode"], "obj")

    def test_every_verdict_states_the_lto_deviation_concretely(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = pathlib.Path(tmp) / "x.o"
            obj.write_bytes(control_object())
            _, out, _ = self.run_cli(str(obj))
            self.assertIn("under lto = true rustc writes LLVM bitcode (refused here)", out)
            self.assertIn("so an object that can be read was built with LTO off; the shipped ELF is fat-LTO'd and may inline differently", out)

    def test_a_crash_of_the_checker_exits_3_and_never_reads_as_pass_or_fail(self):
        # An uncaught traceback exits 1, the FAIL code (b56: render() crashed on a real rlib and the exit code said "violation").
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            good, bad, bc = tmp / "good.o", tmp / "bad.o", tmp / "bc.rlib"
            good.write_bytes(control_object())
            bad.write_bytes(elf([func(RENDER, [SECTION, CONVERT]), func(SECTION, SECTION_OPS), func(CONVERT, ["__muldf3"])]))
            bc.write_bytes(ar([("x.rcgu.o", BC_MAGIC + b"\0" * 28)]))
            # the control: the four outcomes have four different exit codes
            self.assertEqual([self.run_cli(str(p))[0] for p in (good, bad, bc)], [0, 1, 2])
            for where, attr, argv in (("the text renderer", "render", [str(good)]), ("the judge, text", "judge", [str(good)]),
                                      ("the judge, json", "judge", ["--json", str(good)])):
                with self.subTest(where=where), mock.patch.object(sf, attr, side_effect=RuntimeError("planted")):
                    rc, out, err = self.run_cli(*argv)
                    if "--json" not in argv:
                        self.assertEqual(out, "", "no half-printed verdict on stdout")
                    self.assertEqual(rc, 3)
                    self.assertIn("INTERNAL ERROR, no verdict", err)
                    self.assertIn("RuntimeError: planted", err)
                    self.assertIn("Traceback", err)
                    self.assertIn("defect in the checker, not a finding", err)
                    if "--json" in argv:
                        obj = json.loads(out)
                        self.assertEqual((obj["verdict"], obj["error"]["type"], obj["error"]["message"]), ("ERROR", "RuntimeError", "planted"))
                        self.assertEqual(obj["inputs"][0]["file"], str(good))
                        self.assertTrue(obj["claim"].startswith("none"))
            # and the unplanted run is still a PASS
            self.assertEqual(self.run_cli(str(good))[0], 0)

    def test_a_root_that_is_not_found_says_what_was_found(self):
        near = elf([func(mangle("franken_dsp", "protection", "runtime", "ProtectedBoardDsp", "render_into_all"), []),
                    func("_RNvCs1_3foo3bar", []), func("plain_c_symbol", [])])
        err = self.assertRefuses("root-not-found", near)
        text = str(err)
        self.assertIn("1 legacy-mangled, 1 v0-mangled, 1 other", text)
        self.assertIn("franken_dsp::protection::runtime::ProtectedBoardDsp::render_into_all", text, "the near miss is listed")
        self.assertIn("'render_into'", text)


if __name__ == "__main__":
    unittest.main()
