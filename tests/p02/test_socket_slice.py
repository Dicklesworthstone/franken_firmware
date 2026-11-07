#!/usr/bin/env python3
"""P02 (ffw-jub): the socket capability through the seam, the Python half.  Contract: docs/contracts/p02.md, "The socket capability".

The Rust is never compiled here (no cargo), so this file holds what a host can: the facts the Rust is built from, and the shape of the Rust that the
contract's rules depend on.  It does NOT run the Rust tests, and a Rust-logic mistake in `socket.rs` that keeps its shape is not seen by it.

* `listen` and `accept4` (`numbers.rs`, `SERVER_POWERPC32` / `SERVER_MIPS32_O32`) are held to the same three witnesses as the S3 rows, each where it applies:
  the E03 guest probes that issued both calls (direct numbers on both ABIs), the `libc` crate's musl tables (when the registry has the version `Cargo.lock`
  names; otherwise that test is SKIPPED and says so), and the kernel's own files at v2.6.14 and v2.6.35, whose facts below were machine-extracted by the
  author's extractor and not typed (`KERNEL_SOCKET`; None means the kernel has no such entry).  The 32-bit PowerPC kernel files define no direct socket
  syscall at either version, so for PowerPC the direct numbers have the probes and `libc` only, and the kernel witnesses the sub-call, the block size and the
  stock-kernel fact.
* The route plan (`socket_plan_for`) is built from the S3 rows plus these two, so no number is stated twice, and its stock-kernel rule is the kernel's bound.
* The typed flag values in the Rust unit tests (`type` arguments of `socket`, `flags` of `accept4`) are recomputed here from the E03 probes' constants and
  the P06 vectors, so a wrong literal in a test is not just a test agreeing with the code under test.
* The seam source `socket.rs` keeps the shape the rules need: no `unsafe`, no `fcntl`, no `accept`, one issuing site per call, the flags built from `net.rs`'s
  constants, `EINVAL` read as absence in `accept4` and nowhere else, `MSG_TRUNC` always passed.  Each check has a planted fault that it must report.
* The contract's counts equal the files' counts.
Offline, stdlib only.
"""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_syscall_numbers as tsn  # noqa: E402  (helpers only: the S3 parsers and witnesses are reused, not copied)

ROOT = tsn.ROOT
SOCKET_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "socket.rs")
OPS_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "ops.rs")
LIB_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "lib.rs")
VECTORS = os.path.join(ROOT, "crates", "franken-platform", "tests", "vectors", "p06_net_abi.json")
SERVER_TABLES = {"powerpc": "SERVER_POWERPC32", "mips": "SERVER_MIPS32_O32"}
SERVER_CALLS = ("listen", "accept4")
READ = tsn.read

# The kernel facts are DERIVED from `tests/p02/socket_kernel_evidence.json`: verbatim lines of the kernel files, with file, line number and checksum, written by
# `scripts/p02/extract_socket_kernel_facts.py` from the stable tree at git.kernel.org.  Nothing here is a typed literal; re-running the extractor over the
# same files must reproduce the JSON byte for byte (a test runs it over a synthetic tree to show that it records what it says).
EVIDENCE = os.path.join(ROOT, "tests", "p02", "socket_kernel_evidence.json")
EXTRACTOR = os.path.join(ROOT, "scripts", "p02", "extract_socket_kernel_facts.py")
EVIDENCE_FILES = [
    ("v2.6.14", "include/asm-mips/unistd.h"), ("v2.6.14", "include/asm-ppc/unistd.h"), ("v2.6.14", "include/linux/net.h"), ("v2.6.14", "net/socket.c"),
    ("v2.6.26", "include/linux/net.h"), ("v2.6.26", "net/socket.c"),
    ("v2.6.27", "include/linux/net.h"), ("v2.6.27", "net/socket.c"),
    ("v2.6.28", "include/linux/net.h"), ("v2.6.28", "net/socket.c"),
    ("v2.6.35", "arch/mips/include/asm/unistd.h"), ("v2.6.35", "arch/mips/kernel/scall32-o32.S"), ("v2.6.35", "arch/powerpc/include/asm/systbl.h"),
    ("v2.6.35", "arch/powerpc/include/asm/unistd.h"), ("v2.6.35", "include/linux/net.h"), ("v2.6.35", "net/socket.c"),
]
TAGS = ("2.6.14", "2.6.26", "2.6.27", "2.6.28", "2.6.35")


def load_evidence(path=EVIDENCE):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _file(evidence, tag, path):
    found = [f for f in evidence["files"] if f["tag"] == "v" + tag and f["path"] == path]
    if len(found) != 1:
        raise AssertionError("evidence has %d entries for v%s %s" % (len(found), tag, path))
    return found[0]


def _lines(evidence, tag, path, label):
    return [e["text"] for e in _file(evidence, tag, path)["entries"] if e["label"] == label]


def _absent(evidence, tag, path):
    return {a["label"] for a in _file(evidence, tag, path)["absent"]}


def derive_facts(evidence):
    """Every kernel fact the tests use, re-derived from the evidence lines by parsing them (the parsers are this file's, the lines are the kernel's).
    None means the kernel has no such entry (the extractor recorded the pattern as matching nothing)."""
    facts = {}
    for tag in TAGS:
        defines = {}
        for text in _lines(evidence, tag, "include/linux/net.h", "subcalls"):
            m = re.match(r"#define\s+SYS_([A-Z0-9_]+)\s+(\d+)", text)
            defines[m.group(1)] = int(m.group(2))
        names = {"listen": "LISTEN", "accept4": "ACCEPT4", "recv": "RECV", "socket": "SOCKET", "bind": "BIND"}
        facts["subcalls_" + tag.replace(".", "_")] = {call: defines.get(name) for call, name in names.items()}
        facts["subcall18_" + tag.replace(".", "_")] = next((name for name, value in defines.items() if value == 18), None)
        bound = re.search(r"call\s*>\s*(SYS_([A-Z0-9_]+))", " ".join(_lines(evidence, tag, "net/socket.c", "bound")))
        facts["socketcall_bound_" + tag.replace(".", "_")] = (bound.group(1), defines[bound.group(2)])
        nargs_text = " ".join(_lines(evidence, tag, "net/socket.c", "nargs"))
        words = [int(w) for w in re.findall(r"AL\((\d+)\)", nargs_text)]
        declared = re.search(r"nargs\[(\d+)\]", nargs_text)
        if declared and int(declared.group(1)) != len(words):
            raise AssertionError("nargs[%s] declares %s entries but the lines hold %d" % (tag, declared.group(1), len(words)))
        facts["nargs_" + tag.replace(".", "_")] = words
        facts["block_words_" + tag.replace(".", "_")] = {call: words[defines[name]] for call, name in names.items() if defines.get(name) is not None}
        facts["subcall18_words_" + tag.replace(".", "_")] = words[18] if len(words) > 18 else None
        facts["socket_takes_flags_" + tag.replace(".", "_")] = any("flags = type & ~SOCK_TYPE_MASK" in t for t in _lines(evidence, tag, "net/socket.c", "socket_flags"))
        accept_lines = " ".join(_lines(evidence, tag, "net/socket.c", "accept"))
        facts["subcall18_call_" + tag.replace(".", "_")] = ("paccept" if "sys_paccept" in accept_lines else "accept4" if "accept4" in accept_lines else None)
    for tag, path in (("2.6.14", "include/asm-mips/unistd.h"), ("2.6.35", "arch/mips/include/asm/unistd.h")):
        numbers = {}
        for text in _lines(evidence, tag, path, "mips_o32"):
            m = re.match(r"#define\s+__NR_(\w+)\s+\(__NR_Linux\s*\+\s*(\d+)\)", text)
            numbers[m.group(1)] = 4000 + int(m.group(2))
        facts["mips_numbers_" + tag.replace(".", "_")] = {call: numbers.get(call) for call in ("listen", "accept4", "recv")}
    ppc_absent = {
        "2.6.14": _absent(evidence, "2.6.14", "include/asm-ppc/unistd.h"),
        "2.6.35": _absent(evidence, "2.6.35", "arch/powerpc/include/asm/unistd.h") & _absent(evidence, "2.6.35", "arch/powerpc/include/asm/systbl.h"),
    }
    for tag, labels in ppc_absent.items():
        facts["powerpc_direct_" + tag.replace(".", "_")] = {"listen": None if "listen" in labels else "PRESENT", "accept4": None if "accept4" in labels else "PRESENT",
                                                            "recv": None}
    o32 = {}
    for text in _lines(evidence, "2.6.35", "arch/mips/kernel/scall32-o32.S", "o32_table"):
        m = re.match(r"\s*sys\s+sys_(\w+)\s+(\d+)", text)
        o32[m.group(1)] = int(m.group(2))
    facts["o32_slots_2_6_35"] = {call: o32.get(call) for call in ("listen", "accept4", "recv", "socket", "bind")}
    proto = {}
    for label in ("accept", "listen"):
        for text in _lines(evidence, "2.6.35", "net/socket.c", label):
            m = re.search(r"SYSCALL_DEFINE(\d)\((accept4|listen),", text)
            if m:
                proto[m.group(2)] = int(m.group(1))
    facts["prototype_args_2_6_35"] = {call: proto.get(call) for call in SERVER_CALLS}
    return facts


KERNEL_SOCKET = derive_facts(load_evidence())


# ---- the facts of the two rows ------------------------------------------------------------------------------------------------------------

def rust_server(source, constant):
    """{call: {"number", "slots", "sub", "direct_on_stock"}} of `pub const <constant>: ServerCalls = ServerCalls { ... };`."""
    match = re.search(r"pub const %s: ServerCalls = ServerCalls \{(.*?)\n\};" % re.escape(constant), source, re.S)
    if not match:
        raise AssertionError("no ServerCalls table named %s" % constant)
    out = {}
    for field, sub, number, slots, stock in re.findall(tsn.SOCKET_RE, match.group(1)):
        if field in out:
            raise AssertionError("%s lists %s twice" % (constant, field))
        out[field] = {"number": tsn._eval_sum(number), "slots": int(slots), "sub": int(sub), "direct_on_stock": stock == "true"}
    if sorted(out) != sorted(SERVER_CALLS):
        raise AssertionError("%s has calls %s, expected %s" % (constant, sorted(out), sorted(SERVER_CALLS)))
    return out


def e03_server(arch):
    return tsn.e03_numbers(arch, {"listen": (tsn.NET_RS, "LISTEN"), "accept4": (tsn.NET_RS, "ACCEPT4")})


def libc_server(root, arch):
    source, out = READ(os.path.join(root, tsn.LIBC_FILES[arch])), {}
    for call in SERVER_CALLS:
        match = re.search(r"pub const SYS_%s: c_long = ([0-9 +]+);" % call, source)
        if not match:
            raise AssertionError("SYS_%s not in libc's %s table" % (call, arch))
        out[call] = tsn._eval_sum(match.group(1))
    return out


def server_kernel_problems(table, arch):
    """What differs between a ServerCalls table and the kernel facts for `arch`."""
    facts, out = KERNEL_SOCKET, []
    for call in SERVER_CALLS:
        row = table[call]
        if row["sub"] != facts["subcalls_2_6_35"][call]:
            out.append("%s: sub-call numbers.rs=%s net.h(2.6.35)=%s" % (call, row["sub"], facts["subcalls_2_6_35"][call]))
        for label, expected in (("o32 call table", facts["o32_slots_2_6_35"][call]), ("kernel nargs", facts["block_words_2_6_35"][call]), ("prototype", facts["prototype_args_2_6_35"][call])):
            if row["slots"] != expected:
                out.append("%s: slots numbers.rs=%s %s=%s" % (call, row["slots"], label, expected))
        if arch == "mips":
            if row["number"] != facts["mips_numbers_2_6_35"][call]:
                out.append("%s: number numbers.rs=%s unistd.h(2.6.35)=%s" % (call, row["number"], facts["mips_numbers_2_6_35"][call]))
            if row["direct_on_stock"] != (facts["mips_numbers_2_6_14"][call] is not None):
                out.append("%s: direct_on_stock numbers.rs=%s but the 2.6.14 o32 table %s" % (
                    call, row["direct_on_stock"], "has it" if facts["mips_numbers_2_6_14"][call] is not None else "has no entry"))
        else:
            if facts["powerpc_direct_2_6_35"][call] is not None or facts["powerpc_direct_2_6_14"][call] is not None:
                out.append("%s: the 32-bit PowerPC kernel files define a direct number; the table says there is none on the stock kernel" % call)
            if row["direct_on_stock"]:
                out.append("%s: direct_on_stock must be false on PowerPC" % call)
    return out


def server_problems(source, libc=None):
    out = []
    for arch, constant in SERVER_TABLES.items():
        table = rust_server(source, constant)
        out += tsn.diff({c: r["number"] for c, r in table.items()}, e03_server(arch), "numbers.rs %s" % arch, "e03 probes")
        out += ["%s: %s" % (arch, line) for line in server_kernel_problems(table, arch)]
        if libc:
            out += tsn.diff({c: r["number"] for c, r in table.items()}, libc_server(libc, arch), "numbers.rs %s" % arch, "libc")
    return out


class ServerRowShapeTests(unittest.TestCase):
    def setUp(self):
        self.source = READ(tsn.NUMBERS_RS)

    def test_both_tables_have_listen_and_accept4_and_differ_per_abi_in_the_number_only(self):
        ppc, mips = (rust_server(self.source, SERVER_TABLES[a]) for a in ("powerpc", "mips"))
        for call in SERVER_CALLS:
            self.assertNotEqual(ppc[call]["number"], mips[call]["number"], call)
            self.assertLess(ppc[call]["number"], 1000, call)
            self.assertGreaterEqual(mips[call]["number"], 4000, call)
            self.assertEqual((ppc[call]["sub"], ppc[call]["slots"]), (mips[call]["sub"], mips[call]["slots"]), call)

    def test_no_server_number_repeats_an_s3_number(self):
        for arch, name in (("powerpc", "powerpc"), ("mips", "mips")):
            server = rust_server(self.source, SERVER_TABLES[arch])
            s3 = tsn.numbers_of(tsn.rust_p06(self.source, tsn.P06_TABLES[name]))
            for call in SERVER_CALLS:
                self.assertNotIn(server[call]["number"], s3.values(), "%s %s" % (arch, call))

    def test_a_table_that_is_not_plain_numbers_is_refused_rather_than_evaluated(self):
        bad = self.source.replace("number: 329,", "number: 329 * 1,", 1)
        self.assertNotEqual(bad, self.source)
        with self.assertRaises(AssertionError):
            rust_server(bad, SERVER_TABLES["powerpc"])

    def test_a_missing_or_repeated_call_is_refused(self):
        with self.assertRaises(AssertionError):
            rust_server(self.source.replace("    accept4: SocketCall {\n        sub: 18,\n        direct: Call {\n            number: 344,", "    accept5: SocketCall {\n        sub: 18,\n        direct: Call {\n            number: 344,", 1), SERVER_TABLES["powerpc"])


class ServerE03WitnessTests(unittest.TestCase):
    def test_the_numbers_equal_the_ones_the_audited_guest_probes_issued(self):
        source = READ(tsn.NUMBERS_RS)
        for arch, constant in SERVER_TABLES.items():
            table = rust_server(source, constant)
            self.assertEqual({c: r["number"] for c, r in table.items()}, e03_server(arch), arch)

    def test_the_probes_issue_accept4_with_the_flags_in_the_call_and_listen_with_two_arguments(self):
        text = READ(os.path.join(tsn.HELLO, tsn.NET_RS))
        self.assertIn("sc(nr::ACCEPT4, lis, 0, 0, sys::O_NONBLOCK | SOCK_CLOEXEC)", text)
        self.assertIn("sc(nr::LISTEN, lis, 1, 0, 0)", text)

    def test_a_planted_wrong_number_is_reported(self):
        bad = READ(tsn.NUMBERS_RS).replace("number: 344,", "number: 345,", 1)
        self.assertTrue(any("accept4" in line for line in server_problems(bad)), server_problems(bad))


class ServerLibcWitnessTests(unittest.TestCase):
    def setUp(self):
        self.root = tsn.libc_root()
        if not self.root:
            self.skipTest("SKIPPED: the libc crate version Cargo.lock names is not in ~/.cargo/registry; the E03 and kernel witnesses still run")

    def test_the_numbers_equal_the_libc_crates_musl_tables(self):
        source = READ(tsn.NUMBERS_RS)
        for arch, constant in SERVER_TABLES.items():
            table = rust_server(source, constant)
            self.assertEqual({c: r["number"] for c, r in table.items()}, libc_server(self.root, arch), arch)

    def test_a_planted_wrong_number_is_reported_by_libc_too(self):
        bad = READ(tsn.NUMBERS_RS).replace("number: 4000 + 174,", "number: 4000 + 175,", 1)
        self.assertTrue(any("libc" in line and "listen" in line for line in server_problems(bad, self.root)), server_problems(bad, self.root))


class ServerKernelWitnessTests(unittest.TestCase):
    def test_the_rows_equal_the_kernel_facts_in_number_slots_sub_call_and_stock_form(self):
        source = READ(tsn.NUMBERS_RS)
        for arch, constant in SERVER_TABLES.items():
            self.assertEqual(server_kernel_problems(rust_server(source, constant), arch), [], arch)

    def test_the_evidence_file_names_every_kernel_file_with_a_checksum_and_every_fact_derives_from_its_lines(self):
        evidence = load_evidence()
        self.assertEqual(evidence["schema"], "ffw.p02.socket-kernel-evidence.v1")
        self.assertEqual([(f["tag"], f["path"]) for f in evidence["files"]], EVIDENCE_FILES)
        for f in evidence["files"]:
            self.assertRegex(f["sha256_16"], r"^[0-9a-f]{16}$", f["path"])
            for e in f["entries"]:
                self.assertTrue(e["text"].strip() and e["line"] >= 1, (f["tag"], f["path"], e))
        self.assertEqual(derive_facts(evidence), KERNEL_SOCKET)
        for key, value in KERNEL_SOCKET.items():
            self.assertNotEqual(value, {}, key)

    def test_the_extractor_records_what_it_says_over_a_synthetic_tree(self):
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location("extract_socket_kernel_facts", EXTRACTOR)
        extractor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extractor)
        with tempfile.TemporaryDirectory() as root:
            def put(tag, path, text):
                full = os.path.join(root, tag, path)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(text)
            put("v9.9", "net/socket.c", "int x;\nstatic const unsigned char nargs[3]={\n\tAL(0),AL(3),AL(2)\n};\nif (call < 1 || call > SYS_RECVMSG)\n\treturn -EINVAL;\n")
            put("v9.9", "include/asm-mips/unistd.h", "#if _MIPS_SIM == _MIPS_SIM_ABI32\n#define __NR_listen\t(__NR_Linux + 174)\n#endif /* _MIPS_SIM == _MIPS_SIM_ABI32 */\n"
                "#if _MIPS_SIM == _MIPS_SIM_ABI64\n#define __NR_listen\t(__NR_Linux + 49)\n#endif\n")
            spec_ = [("v9.9", "net/socket.c", extractor.SOCKET_C, extractor.SOCKET_C_ABSENT),
                     ("v9.9", "include/asm-mips/unistd.h", [("mips_o32", "o32", r"^#define\s+__NR_(?:listen|accept4)\s")], [("accept4", r"__NR_accept4")])]
            out = extractor.extract(root, spec_)
        socket_c, unistd = out["files"]
        by_label = lambda f, label: [(e["line"], e["text"]) for e in f["entries"] if e["label"] == label]
        self.assertEqual(by_label(socket_c, "bound"), [(5, "if (call < 1 || call > SYS_RECVMSG)")])
        self.assertEqual([t.strip() for _, t in by_label(socket_c, "nargs")], ["static const unsigned char nargs[3]={", "AL(0),AL(3),AL(2)", "};"])
        self.assertEqual([a["label"] for a in socket_c["absent"]], ["accept4", "paccept"])            # no accept4 or paccept anywhere in the synthetic file
        self.assertEqual(by_label(unistd, "mips_o32"), [(2, "#define __NR_listen\t(__NR_Linux + 174)")])  # the n64 number (49) is outside the o32 section
        self.assertEqual([a["label"] for a in unistd["absent"]], ["accept4"])
        self.assertRegex(socket_c["sha256_16"], r"^[0-9a-f]{16}$")

    def test_a_planted_wrong_line_in_the_evidence_changes_the_facts_and_is_reported(self):
        evidence = load_evidence()
        for f in evidence["files"]:
            if (f["tag"], f["path"]) == ("v2.6.35", "include/linux/net.h"):
                for e in f["entries"]:
                    if "SYS_ACCEPT4" in e["text"]:
                        e["text"] = e["text"].replace("18", "17")
        facts = derive_facts(evidence)
        self.assertEqual(facts["subcalls_2_6_35"]["accept4"], 17)
        self.assertNotEqual(facts, KERNEL_SOCKET)

    def test_accept4_is_in_neither_stock_kernel_by_either_route_and_listen_is_in_both(self):
        facts = KERNEL_SOCKET
        self.assertIsNone(facts["mips_numbers_2_6_14"]["accept4"])          # no direct entry in the 2.6.14 o32 table
        self.assertIsNone(facts["subcalls_2_6_14"]["accept4"])              # no SYS_ACCEPT4 in the 2.6.14 net.h
        self.assertEqual(facts["subcalls_2_6_35"]["accept4"], 18)           # present at 2.6.35
        self.assertEqual(facts["subcalls_2_6_14"]["listen"], 4)
        self.assertEqual(facts["mips_numbers_2_6_14"]["listen"], 4174)

    def test_socketcall_sub_call_18_is_three_different_things_across_the_kernels_read(self):
        facts = KERNEL_SOCKET
        # up to 2.6.26 the bound is SYS_RECVMSG (17): sub-call 18 is EINVAL.  At 2.6.27 it is `paccept` (SIX words); from 2.6.28 it is `accept4` (four).
        for tag in ("2_6_14", "2_6_26"):
            self.assertEqual(facts["socketcall_bound_" + tag], ("SYS_RECVMSG", 17), tag)
            self.assertIsNone(facts["subcall18_" + tag], tag)
            self.assertIsNone(facts["subcall18_words_" + tag], tag)
        self.assertEqual(facts["socketcall_bound_2_6_27"], ("SYS_PACCEPT", 18))
        self.assertEqual((facts["subcall18_2_6_27"], facts["subcall18_call_2_6_27"], facts["subcall18_words_2_6_27"]), ("PACCEPT", "paccept", 6))
        self.assertEqual(facts["socketcall_bound_2_6_28"], ("SYS_ACCEPT4", 18))
        for tag in ("2_6_28", "2_6_35"):
            self.assertEqual((facts["subcall18_" + tag], facts["subcall18_call_" + tag], facts["subcall18_words_" + tag]), ("ACCEPT4", "accept4", 4), tag)
        self.assertEqual(facts["socketcall_bound_2_6_35"], ("SYS_RECVMMSG", 19))

    def test_flags_in_socket_type_exist_from_2_6_27_and_never_with_an_einval_for_sub_call_18(self):
        facts = KERNEL_SOCKET
        self.assertEqual({tag: facts["socket_takes_flags_" + tag] for tag in ("2_6_14", "2_6_26", "2_6_27", "2_6_28", "2_6_35")},
                         {"2_6_14": False, "2_6_26": False, "2_6_27": True, "2_6_28": True, "2_6_35": True})
        # The EINVAL-as-absence reading of accept4 can fire only on a socketcall kernel that takes flags in `type` (else `open_socket` fails first, with
        # EINVAL from the flags) and has no sub-call 18 (else the call exists or is a different call).  No kernel read is both.
        for tag in ("2_6_14", "2_6_26", "2_6_27", "2_6_28", "2_6_35"):
            self.assertFalse(facts["socket_takes_flags_" + tag] and facts["subcall18_" + tag] is None, tag)

    def test_the_2_6_powerpc_files_define_no_direct_listen_or_accept4(self):
        for version in ("2_6_14", "2_6_35"):
            self.assertEqual(KERNEL_SOCKET["powerpc_direct_" + version], {"listen": None, "accept4": None, "recv": None})

    def test_a_planted_wrong_slot_count_sub_call_or_stock_form_is_reported(self):
        source = READ(tsn.NUMBERS_RS)
        plants = [
            ("slots", "number: 4000 + 334,\n            slots: 4,", "number: 4000 + 334,\n            slots: 5,", "slots"),
            ("sub", "sub: 18,\n        direct: Call {\n            number: 4000 + 334,", "sub: 17,\n        direct: Call {\n            number: 4000 + 334,", "sub-call"),
            ("stock form", "number: 4000 + 334,\n            slots: 4,\n        },\n        direct_on_stock: false,", "number: 4000 + 334,\n            slots: 4,\n        },\n        direct_on_stock: true,", "direct_on_stock"),
        ]
        for name, old, new, word in plants:
            bad = source.replace(old, new, 1)
            self.assertNotEqual(bad, source, name)
            problems = server_kernel_problems(rust_server(bad, SERVER_TABLES["mips"]), "mips")
            self.assertTrue(any(word in line for line in problems), "%s: %s" % (name, problems))

    def test_the_unplanted_rows_have_no_problem_against_the_probes_and_the_kernel(self):
        self.assertEqual(server_problems(READ(tsn.NUMBERS_RS)), [])


# ---- the plan -----------------------------------------------------------------------------------------------------------------------------

def plan_problems(source):
    """The shape of `socket_plan_for` and the stock rule in numbers.rs."""
    out = []
    match = re.search(r"pub const STOCK_SOCKETCALL_MAX_SUB: usize = (\d+);", source)
    if not match or int(match.group(1)) != KERNEL_SOCKET["socketcall_bound_2_6_14"][1]:
        out.append("STOCK_SOCKETCALL_MAX_SUB is not the v2.6.14 socketcall bound %s" % KERNEL_SOCKET["socketcall_bound_2_6_14"][1])
    plan = re.search(r"pub const fn socket_plan_for\(abi: Abi\) -> SocketPlan \{(.*?)\n\}", source, re.S)
    if not plan:
        return out + ["no socket_plan_for"]
    rows = dict(re.findall(r"(socket|bind|listen|accept4|recv): route\(abi, p06\.socketcall, ((?:p06|server)\.[a-z0-9]+)\)", plan.group(1)))
    expected = {"socket": "p06.socket", "bind": "p06.bind", "listen": "server.listen", "accept4": "server.accept4", "recv": "p06.recv"}
    if rows != expected:
        out.append("socket_plan_for builds %s, expected %s" % (rows, expected))
    route = re.search(r"const fn route\(abi: Abi, socketcall: Call, row: SocketCall\) -> Route \{(.*?)\n\}", source, re.S)
    if not route:
        return out + ["no route()"]
    body = route.group(1)
    ppc = re.search(r"Abi::PowerPc32 => (Route::\w+)", body)
    mips = re.search(r"Abi::Mips32 => (Route::\w+)", body)
    if not ppc or ppc.group(1) != "Route::ViaSocketCall":
        out.append("PowerPC is not socketcall throughout")
    if not mips or mips.group(1) != "Route::Direct":
        out.append("MIPS o32 is not direct throughout")
    if "on_stock: row.sub <= STOCK_SOCKETCALL_MAX_SUB" not in body:
        out.append("the PowerPC stock rule is not the sub-call bound")
    if "block_words: row.direct.slots" not in body:
        out.append("the socketcall block size is not the call's slot count")
    return out


class PlanSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = READ(tsn.NUMBERS_RS)

    def test_the_plan_is_socketcall_on_powerpc_direct_on_mips_and_built_from_the_s3_rows(self):
        self.assertEqual(plan_problems(self.source), [])

    def test_the_powerpc_socketcall_route_has_kernel_file_witnesses_only_and_the_source_says_so(self):
        # No guest has issued a socketcall: the E03 probes issue direct calls on both ABIs.  The Rust test and the contract must not claim a probe witness.
        probes = READ(os.path.join(tsn.HELLO, tsn.NET_RS)) + READ(os.path.join(tsn.HELLO, "main.rs"))
        self.assertNotRegex(probes, r"(?i)socketcall|SYS_SOCKETCALL|NR_SOCKETCALL")
        rust = READ(tsn.NUMBERS_RS)
        self.assertIn("KERNEL FILES ONLY", rust)
        self.assertNotIn("typed_from_the_kernel_and_the_probes", rust)
        doc = READ(tsn.P02_MD)
        section = doc.split("## The socket capability", 1)[1].split("\n## ", 1)[0]
        self.assertIn("no guest has issued a `socketcall`", section)

    def test_the_stock_bound_is_the_kernels_and_the_s3_rows_agree_with_the_kernel_block_sizes(self):
        words = KERNEL_SOCKET["block_words_2_6_14"]
        for arch in ("powerpc", "mips"):
            table = tsn.rust_p06(self.source, tsn.P06_TABLES[arch])
            for call in ("socket", "bind", "recv"):
                self.assertEqual(table[call]["slots"], words[call], "%s %s" % (arch, call))
                self.assertEqual(table[call]["sub"], KERNEL_SOCKET["subcalls_2_6_14"][call], "%s %s" % (arch, call))

    def test_a_planted_plan_fault_is_reported(self):
        plants = [
            ("bound", "STOCK_SOCKETCALL_MAX_SUB: usize = 17", "STOCK_SOCKETCALL_MAX_SUB: usize = 18", "bound"),
            ("source of listen", "listen: route(abi, p06.socketcall, server.listen)", "listen: route(abi, p06.socketcall, p06.bind)", "builds"),
            ("powerpc route", "Abi::PowerPc32 => Route::ViaSocketCall {", "Abi::PowerPc32 => Route::Direct {", "PowerPC"),
            ("stock rule", "on_stock: row.sub <= STOCK_SOCKETCALL_MAX_SUB,", "on_stock: true,", "stock rule"),
            ("block size", "block_words: row.direct.slots,", "block_words: 6,", "block size"),
        ]
        for name, old, new, word in plants:
            bad = self.source.replace(old, new, 1)
            self.assertNotEqual(bad, self.source, name)
            self.assertTrue(any(word in line for line in plan_problems(bad)), "%s: %s" % (name, plan_problems(bad)))


# ---- the typed flag values in the Rust unit tests -------------------------------------------------------------------------------------------

def e03_constant(arch, filename, constant):
    """A `pub const NAME: usize = <literal>;` of the arch's block in an E03 probe source; decimal, hex or octal (`0o200`)."""
    source = READ(os.path.join(tsn.HELLO, filename))
    starts = [m.start() for m in re.finditer(r"#\[cfg\(target_arch = \"(?:mips|powerpc)\"\)\]\nmod ", source)]
    marker = {"mips": 'target_arch = "mips"', "powerpc": 'target_arch = "powerpc"'}[arch]
    for index, start in enumerate(starts):
        block = source[start:(starts[index + 1] if index + 1 < len(starts) else len(source))]
        if marker in block.splitlines()[0]:
            match = re.search(r"pub const %s: usize = (0[oxb][0-9a-fA-F_]+|[0-9_]+);" % re.escape(constant), block)
            if match:
                return int(match.group(1).replace("_", ""), 0)
    raise AssertionError("%s not found in the %s block of %s" % (constant, arch, filename))


def expected_flags(arch):
    """(stream type, dgram type, SOCK_NONBLOCK|SOCK_CLOEXEC for accept4) for `arch`, from the E03 probes' own constants."""
    stream = e03_constant(arch, tsn.NET_RS, "SOCK_STREAM")
    dgram = e03_constant(arch, "main.rs", "SOCK_DGRAM")
    nonblock = e03_constant(arch, "main.rs", "O_NONBLOCK")
    cloexec = int(re.search(r"const SOCK_CLOEXEC: usize = (0x[0-9a-f]+);", READ(os.path.join(tsn.HELLO, tsn.NET_RS))).group(1), 16)
    return stream | nonblock | cloexec, dgram | nonblock | cloexec, nonblock | cloexec


class FlagLiteralTests(unittest.TestCase):
    def setUp(self):
        self.source = READ(SOCKET_RS)

    def rust_cases(self):
        found = {}
        for abi, kind, value in re.findall(r"\(Abi::(PowerPc32|Mips32), SockKind::(Stream|Dgram), (0x[0-9a-f]+)(?:_u32)?\)", self.source):
            found[(abi, kind)] = int(value, 16)
        return found

    def test_the_socket_type_literals_in_the_rust_tests_equal_the_probes_constants(self):
        found = self.rust_cases()
        self.assertEqual(len(found), 4, found)
        for abi, arch in (("PowerPc32", "powerpc"), ("Mips32", "mips")):
            stream, dgram, _ = expected_flags(arch)
            self.assertEqual(found[(abi, "Stream")], stream, abi)
            self.assertEqual(found[(abi, "Dgram")], dgram, abi)
        # The token test types the same four values again, per ABI: they must be the probes' too.
        body = self.source.split("fn a_datagram_token_comes_only_from_a_datagram_open_and_carries_its_descriptor", 1)[1].split("#[test]", 1)[0]
        ppc_stream, ppc_dgram, _ = expected_flags("powerpc")
        mips_stream, mips_dgram, _ = expected_flags("mips")
        self.assertIn("Abi::PowerPc32 => (0x%x_u32, 0x%x_u32)" % (ppc_stream, ppc_dgram), body)
        self.assertIn("Abi::Mips32 => (0x%x, 0x%x)" % (mips_stream, mips_dgram), body)

    def test_the_socket_type_literals_equal_the_p06_vectors_for_nonblock_and_cloexec(self):
        with open(VECTORS, encoding="utf-8") as fh:
            vectors = json.load(fh)["socket_type_arg"]
        both = {(row["abi"], row["kind"]): row["value"] for row in vectors if row["nonblock"] and row["cloexec"]}
        self.assertTrue(both, "the vectors have no row with both flags")
        found = self.rust_cases()
        for (abi, kind), value in both.items():
            key = ({"powerpc32": "PowerPc32", "mips32": "Mips32"}[abi], kind.capitalize())
            self.assertEqual(found[key], value, key)

    def test_the_accept4_flag_literals_equal_the_probes_flags_argument(self):
        match = re.search(r"\(Abi::PowerPc32, (0x[0-9a-f]+)_u32\), \(Abi::Mips32, (0x[0-9a-f]+)\)", self.source)
        self.assertTrue(match, "no accept4 flag literals")
        self.assertEqual(int(match.group(1), 16), expected_flags("powerpc")[2])
        self.assertEqual(int(match.group(2), 16), expected_flags("mips")[2])

    def test_msg_trunc_and_the_nonblock_bits_in_the_rust_test_double_are_the_probes_values(self):
        self.assertIn("const MSG_TRUNC_BIT: u32 = 0x20;", self.source)
        probe = re.search(r"const MSG_TRUNC_FLAG: usize = (0x[0-9a-f]+);", READ(os.path.join(tsn.HELLO, tsn.NET_RS)))
        self.assertTrue(probe, "no MSG_TRUNC_FLAG in the E03 net probe")
        self.assertEqual(int(probe.group(1), 16), 0x20)
        self.assertIn("Abi::PowerPc32 => 0x800,", self.source)
        self.assertIn("Abi::Mips32 => 0x80,", self.source)
        self.assertEqual((e03_constant("powerpc", "main.rs", "O_NONBLOCK"), e03_constant("mips", "main.rs", "O_NONBLOCK")), (0x800, 0x80))
        self.assertIn("const CLOEXEC_BIT: u32 = 0x80000;", self.source)

    def test_a_planted_wrong_literal_is_reported(self):
        bad = self.source.replace("0x80801_u32", "0x80802_u32", 1)
        self.assertNotEqual(bad, self.source)
        saved = self.source
        try:
            self.source = bad
            found = self.rust_cases()
        finally:
            self.source = saved
        self.assertNotEqual(found[("PowerPc32", "Stream")], expected_flags("powerpc")[0])


# ---- the shape of the seam source -----------------------------------------------------------------------------------------------------------

CALL_SITES = ("socket", "bind", "listen", "accept4", "recv")


def non_test(source):
    return source.split("#[cfg(test)]\nmod tests {", 1)[0]


def code_only(text):
    """`text` without `//` comments (doc comments included): the rules are about code, and the documentation names `fcntl` and `accept` to forbid them."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in text.splitlines())


def function_body(code, name):
    match = re.search(r"(?:pub )?fn %s<.*?\n\) -> [^{]*\{\n(.*?)\n\}\n" % re.escape(name), code, re.S) or re.search(r"pub const fn %s\(.*?\{\n(.*?)\n\}\n" % re.escape(name), code, re.S)
    return match.group(1) if match else None


def seam_problems(source, ops_source, lib_source):
    code = code_only(non_test(source))
    out = []
    if re.search(r"\bunsafe\b", code):
        out.append("socket.rs mentions unsafe in code")
    if re.search(r"\bfcntl\b", code):
        out.append("socket.rs mentions fcntl in code")
    if re.search(r"\bfn accept\(|\.accept\(", code):
        out.append("socket.rs has a plain accept")
    for call in CALL_SITES:
        count = len(re.findall(r"\bops\.%s\(" % call, code))
        if count != 1:
            out.append("%s has %d issuing sites, expected 1" % (call, count))
    trait = re.search(r"pub trait SocketOps: KernelOps \{(.*?)\n\}\n", code, re.S)
    if not trait:
        out.append("no `pub trait SocketOps: KernelOps`")
    else:
        methods = re.findall(r"\n\s*fn ([a-z0-9_]+)\(", trait.group(1))
        if methods != list(CALL_SITES):
            out.append("SocketOps methods are %s, expected %s" % (methods, list(CALL_SITES)))
    for name in ("socket", "accept4", "listen", "bind", "recv"):
        if re.search(r"\bfn %s\(" % name, code_only(ops_source)):
            out.append("ops.rs (KernelOps) has a %s method; the socket seam is a separate trait" % name)
    if len(re.findall(r"^pub mod socket;$", lib_source, re.M)) != 1:
        out.append("lib.rs must declare `pub mod socket;` exactly once")
    if "#![forbid(unsafe_code)]" not in lib_source:
        out.append("lib.rs lost forbid(unsafe_code)")
    flags = function_body(code, "accept4_flags")
    if flags is None or flags.strip() != "abi.o_nonblock() | net::SOCK_CLOEXEC":
        out.append("accept4_flags is not `abi.o_nonblock() | net::SOCK_CLOEXEC`")
    if "abi.socket_type_arg(kind, true, true)" not in code:
        out.append("open_socket does not build `type` with socket_type_arg(kind, true, true)")
    if len(re.findall(r"ops\.recv\(fd, buf, net::RECV_FLAGS\)", code)) != 1:
        out.append("the datagram read does not pass net::RECV_FLAGS")
    if re.search(r"\bconst\s+MSG_TRUNC\b|\b0x20\b", code):
        out.append("socket.rs restates MSG_TRUNC instead of using net.rs")
    if len(re.findall(r"SysError::Invalid => SysError::Absent", code)) != 1:
        out.append("the EINVAL-as-absence mapping must appear exactly once")
    accept = function_body(code, "accept4")
    if accept is None or "SysError::Invalid => SysError::Absent" not in accept:
        out.append("the EINVAL-as-absence mapping is not inside accept4")
    if len(re.findall(r"\.call_retrying\(", code)) != 4:
        out.append("expected four call_retrying sites (socket, bind, listen, accept4)")
    if "MAX_INTERRUPTED_ATTEMPTS" not in (function_body(code, "recv_datagram") or ""):
        out.append("the datagram read does not bound its retries with MAX_INTERRUPTED_ATTEMPTS")
    if len(re.findall(r"\bListener \{ fd \}", code)) != 1:
        out.append("a Listener must be built in exactly one place (after a successful listen)")
    if len(re.findall(r"\bDatagramSocket \{ fd \}", code)) != 1:
        out.append("a DatagramSocket must be built in exactly one place (open_datagram_socket)")
    if "DatagramSocket { fd }" not in (function_body(code, "open_datagram_socket") or "") or "SockKind::Dgram" not in (function_body(code, "open_datagram_socket") or ""):
        out.append("open_datagram_socket must open a Dgram socket and build the DatagramSocket")
    if "SockKind::Stream" not in (function_body(code, "open_stream_socket") or "") or "DatagramSocket" in (function_body(code, "open_stream_socket") or ""):
        out.append("open_stream_socket must open a Stream socket and build no DatagramSocket")
    if re.search(r"\bpub fn open_socket\b", code):
        out.append("open_socket must stay private: a public bare-descriptor open would hand recv_datagram a stream")
    if not re.search(r"pub fn recv_datagram<S: SocketOps \+ \?Sized>\(\s*ops: &mut S,\s*abi: Abi,\s*socket: &DatagramSocket,", code):
        out.append("recv_datagram must take a &DatagramSocket, not a bare descriptor")
    return out


class SeamSourceTests(unittest.TestCase):
    def setUp(self):
        self.source, self.ops, self.lib = READ(SOCKET_RS), READ(OPS_RS), READ(LIB_RS)

    def test_the_real_sources_have_the_shape_the_rules_need(self):
        self.assertEqual(seam_problems(self.source, self.ops, self.lib), [])

    def test_each_planted_fault_is_reported(self):
        plants = [
            ("an fcntl", "fn sys_error(", "fn fixup() {\n    let fcntl = 1;\n    let _ = fcntl;\n}\n\nfn sys_error(", "fcntl"),
            ("an unsafe block", "fn sys_error(", "fn raw() { unsafe { } }\n\nfn sys_error(", "unsafe"),
            ("a plain accept", "fn sys_error(", "pub fn accept(fd: i32) -> i32 {\n    fd\n}\n\nfn sys_error(", "plain accept"),
            ("EINVAL read as absence nowhere", "            SysError::Invalid => SysError::Absent,\n", "", "mapping"),
            ("a second accept4 site", ".call_retrying(|| ops.accept4(fd, flags))", ".call_retrying(|| ops.accept4(fd, flags).max(ops.accept4(fd, flags)))", "issuing sites"),
            ("the read drops MSG_TRUNC", "ops.recv(fd, buf, net::RECV_FLAGS)", "ops.recv(fd, buf, 0)", "RECV_FLAGS"),
            ("the accept flags lose cloexec", "abi.o_nonblock() | net::SOCK_CLOEXEC", "abi.o_nonblock()", "accept4_flags"),
            ("the socket flags are not set", "abi.socket_type_arg(kind, true, true)", "abi.socket_type_arg(kind, false, false)", "socket_type_arg"),
            ("MSG_TRUNC restated", "fn sys_error(", "const MSG_TRUNC: u32 = 0x20;\n\nfn sys_error(", "restates"),
            ("a second Listener construction", "fn sys_error(", "fn forge(fd: i32) -> Listener {\n    Listener { fd }\n}\n\nfn sys_error(", "Listener"),
            ("a second DatagramSocket construction", "fn sys_error(", "fn forge_datagram(fd: i32) -> DatagramSocket {\n    DatagramSocket { fd }\n}\n\nfn sys_error(", "DatagramSocket must be built"),
            ("the datagram open opens a stream", "let fd = open_socket(ops, abi, family, SockKind::Dgram)?;", "let fd = open_socket(ops, abi, family, SockKind::Stream)?;", "open_datagram_socket"),
            ("the stream open builds a datagram token", "    open_socket(ops, abi, family, SockKind::Stream)\n}", "    open_socket(ops, abi, family, SockKind::Stream).map(|fd| DatagramSocket { fd })\n}", "open_stream_socket"),
            ("open_socket is public", "\nfn open_socket<S: SocketOps + ?Sized>(", "\npub fn open_socket<S: SocketOps + ?Sized>(", "private"),
            ("recv_datagram takes a bare descriptor", "    socket: &DatagramSocket,\n    buf: &mut [u8],", "    socket: i32,\n    buf: &mut [u8],", "bare descriptor"),
            ("an unbounded read loop", "for _ in 0..MAX_INTERRUPTED_ATTEMPTS {", "loop {", "MAX_INTERRUPTED_ATTEMPTS"),
        ]
        for name, old, new, word in plants:
            bad = self.source.replace(old, new, 1)
            self.assertNotEqual(bad, self.source, name)
            problems = seam_problems(bad, self.ops, self.lib)
            self.assertTrue(problems, "%s: nothing reported" % name)
            if word:
                self.assertTrue(any(word in line for line in problems), "%s: %s" % (name, problems))

    def test_a_socket_method_added_to_kernel_ops_is_reported(self):
        bad = self.ops.replace("    fn close(&mut self, fd: i32) -> isize;", "    fn close(&mut self, fd: i32) -> isize;\n\n    fn accept4(&mut self, fd: i32, flags: u32) -> isize;", 1)
        self.assertNotEqual(bad, self.ops)
        self.assertTrue(any("KernelOps" in line for line in seam_problems(self.source, bad, self.lib)))

    def test_a_missing_or_doubled_module_line_is_reported(self):
        self.assertTrue(any("exactly once" in line for line in seam_problems(self.source, self.ops, self.lib.replace("pub mod socket;\n", "", 1))))
        self.assertTrue(any("exactly once" in line for line in seam_problems(self.source, self.ops, self.lib.replace("pub mod socket;\n", "pub mod socket;\npub mod socket;\n", 1))))


# ---- the contract ---------------------------------------------------------------------------------------------------------------------------

def rust_test_names(source, marker=None):
    text = source if marker is None else source[source.index(marker):]
    return re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn ([a-z0-9_]+)\(", text)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.doc = READ(tsn.P02_MD)

    def test_the_contract_separates_compilation_from_kernel_execution(self):
        self.assertIn("## The socket capability", self.doc)
        section = self.doc.split("## The socket capability", 1)[1].split("\n## ", 1)[0]
        for phrase in ("Compilation is not kernel execution", "SocketOps", "socket.rs", "SocketPlan", "accept4", "MSG_TRUNC", "No real socket descriptor has been observed"):
            self.assertIn(phrase, section, phrase)
        self.assertIn("**socket kernel execution remains unqualified**", section)
        self.assertIn("a safety net, not an observed behaviour", section)
        self.assertIn("None of this is observed on any kernel.", self.doc.split("## Known limits", 1)[1])
        self.assertNotIn("no code exists", self.doc)
        self.assertNotIn("no socket code in this slice", self.doc)

    def test_the_contract_counts_equal_the_files_counts(self):
        socket_tests = len(rust_test_names(READ(SOCKET_RS)))
        plan_tests = len(rust_test_names(READ(tsn.NUMBERS_RS), "// ---- the socket capability's plan"))
        python_tests = len(re.findall(r"^    def test_", READ(__file__), re.M))
        self.assertIn("%d Rust unit tests in `socket.rs`" % socket_tests, self.doc)
        self.assertIn("%d Rust unit tests for the route plan in `numbers.rs`" % plan_tests, self.doc)
        self.assertIn("%d Python tests in `tests/p02/test_socket_slice.py`" % python_tests, self.doc)

    def test_the_file_table_counts_the_leaf_wrappers_the_leaf_has(self):
        words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen"}
        wrappers = len(re.findall(r"^pub\(crate\) fn ", READ(tsn.SYS_RS), re.M))
        row = next(line for line in self.doc.splitlines() if line.startswith("| `crates/franken-platform-linux/` |"))
        self.assertIn("%s typed wrappers" % words[wrappers], row)
        self.assertIn("%s typed wrappers" % words[wrappers], self.doc.split("**The leaf's unsafe surface", 1)[1].split("\n\n", 1)[0])

    def test_every_test_name_the_contract_cites_exists(self):
        section = self.doc.split("## The socket capability", 1)[1].split("\n## ", 1)[0]
        known = set(rust_test_names(READ(SOCKET_RS))) | set(rust_test_names(READ(tsn.NUMBERS_RS), "// ---- the socket capability's plan"))
        known |= set(re.findall(r"^    def (test_[a-z0-9_]+)\(", READ(__file__), re.M))
        known |= set(re.findall(r"#\[test\]\s*fn ([a-z0-9_]+)\(", READ(os.path.join(ROOT, "crates", "franken-platform-linux", "src", "socket_route.rs"))))
        known |= set(re.findall(r"^    def (test_[a-z0-9_]+)\(", READ(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_leaf_socket.py")), re.M))
        cited = set(re.findall(r"`([a-z][a-z0-9_]{24,})`", section))
        self.assertTrue(cited, "the section cites no test")
        self.assertEqual(sorted(cited - known), [], "names that are not tests")

    def test_the_contract_names_the_gaps_it_leaves(self):
        section = self.doc.split("## The socket capability", 1)[1].split("\n## ", 1)[0]
        for header in ("* **The leaf backend has no socket guest-execution proof.**", "* **A kernel-version hazard for the `socketcall` route.**", "* **`recvfrom` and the peer address.**", "* **No admission.**",
                       "* **No qualification.**"):
            self.assertIn(header, section, header)
        for phrase in ("recvfrom", "unsafe", "layer.rs", "peer address"):
            self.assertIn(phrase, section, phrase)


if __name__ == "__main__":
    unittest.main()
