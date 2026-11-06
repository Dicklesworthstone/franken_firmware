#!/usr/bin/env python3
"""P06 (ffw-2nw) slice A1: the durable-file ABI of crates/franken-platform/src/durable.rs has more than one witness.

The Rust is held to the committed vector file by its own unit tests; this file holds the vector file, and the Rust text, to sources that are
not the Rust:

* an independent model of every flag builder, decoder, offset split and the E03 replace-sequence judge, written from the contract and not from
  the Rust (`struct` for the 64-bit words),
* the `libc` crate's musl b32 MIPS and PowerPC files in the local cargo registry (the numbers the Rust musl targets use), for every flag and
  every errno the vector file states,
* the Rust source text itself (so the unit tests cannot be edited around without this noticing).

The Linux header values behind each number, and the kernel sources behind each stated kernel behaviour, are recorded with their sha256 in the
vector file's `witnesses`; they are documentation of where to look, and are not re-fetched here.

Offline, stdlib only, no cargo, no QEMU. A source that is missing is SKIPPED, and the runner (run_cases.py) reports a skip as BLOCKED and
exits 3: a check that did not run never passes. "Sensitivity" tests plant a wrong number in each source and require the comparison to
report it, after first requiring the unplanted comparison to be clean.
"""
import copy
import glob
import importlib.util
import json
import os
import re
import struct
import sys
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VECTORS = os.path.join(ROOT, "crates", "franken-platform", "tests", "vectors", "p06_durable_abi.json")
DURABLE_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "durable.rs")
LIB_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "lib.rs")
ORACLE = os.path.join(ROOT, "tests", "e03", "abi.py")

ABIS = ("powerpc32", "mips32")
ARCH = {"powerpc32": "powerpc", "mips32": "mips"}
FLAGS = ("O_CREAT", "O_EXCL", "O_APPEND", "O_DSYNC", "O_SYNC", "O_DIRECTORY", "O_NOFOLLOW", "O_LARGEFILE")
COMMON_FLAGS = ("O_RDONLY", "O_WRONLY", "O_RDWR", "O_TRUNC", "O_CLOEXEC")
SEQUENCE = ("write", "fsync", "rename", "read_back", "old_name_gone")
SYNC_FAILURES = ("EIO", "ENOSPC", "EDQUOT")

# Typed again, in the headers' own octal, from the kernel files named under `witnesses` (2.6.33 and later numbering). The vector file and this table
# are separate texts; test_the_model_tables_equal_the_vector_numbers holds them together.
MODEL_OPEN = {
    "powerpc32": {"O_CREAT": 0o100, "O_EXCL": 0o200, "O_APPEND": 0o2000, "O_DSYNC": 0o10000, "O_SYNC": 0o4010000, "O_DIRECTORY": 0o40000,
                  "O_NOFOLLOW": 0o100000, "O_LARGEFILE": 0o200000, "O_NONBLOCK": 0o4000},
    "mips32": {"O_CREAT": 0o400, "O_EXCL": 0o2000, "O_APPEND": 0o10, "O_DSYNC": 0o20, "O_SYNC": 0o40020, "O_DIRECTORY": 0o200000,
               "O_NOFOLLOW": 0o400000, "O_LARGEFILE": 0o20000, "O_NONBLOCK": 0o200},
}
MODEL_COMMON = {"O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2, "O_TRUNC": 0o1000, "O_CLOEXEC": 0o2000000}
COMMON_ERRNO = {"EPERM": 1, "ENOENT": 2, "EIO": 5, "EBADF": 9, "ENOMEM": 12, "EACCES": 13, "EBUSY": 16, "EEXIST": 17, "EXDEV": 18, "ENOTDIR": 20,
                "EISDIR": 21, "ENFILE": 23, "EMFILE": 24, "EFBIG": 27, "ENOSPC": 28, "EROFS": 30}
DIFFERING_ERRNO = {
    "powerpc32": {"EDEADLK": 35, "ENAMETOOLONG": 36, "ENOLCK": 37, "ENOTEMPTY": 39, "ELOOP": 40, "EOVERFLOW": 75, "ESTALE": 116, "EDQUOT": 122},
    "mips32": {"EDEADLK": 45, "ENAMETOOLONG": 78, "ENOLCK": 46, "ENOTEMPTY": 93, "ELOOP": 90, "EOVERFLOW": 79, "ESTALE": 151, "EDQUOT": 1133},
}


def model_errno(abi):
    table = dict(COMMON_ERRNO)
    table.update(DIFFERING_ERRNO[abi])
    return table


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def load_oracle():
    spec = importlib.util.spec_from_file_location("ffw_p06_durable_e03_abi", ORACLE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ffw_p06_durable_e03_abi"] = module
    spec.loader.exec_module(module)
    return module


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------- the independent model

def model_decode(abi, raw, oracle):
    """('ok', n) | ('err', name): the in-band -errno convention, then the ABI's own numbering."""
    if raw >= 0:
        return ("ok", raw)
    if raw < -4095:
        return ("err", "malformed")
    errno = -raw
    if errno == oracle.errno_number(ARCH[abi], "ENOSYS"):
        return ("err", "absent")
    if errno in (4, 11, 22):
        return ("err", {4: "interrupted", 11: "would_block", 22: "invalid"}[errno])
    by_number = {number: name for name, number in model_errno(abi).items()}
    return ("err", by_number.get(errno, "unknown:%d" % errno))


def model_open_flags(abi, case):
    """('ok', value) | ('err', name) for one open request."""
    read_only = case["access"] == "read_only"
    sync = case["sync"]
    if read_only and (case["truncate"] or case["append"] or sync != "none"):
        return ("err", "flags:write_flag_on_read_only")
    if case["directory"] and (not read_only or case["truncate"] or case["append"] or case["create"] != "never" or sync != "none"):
        return ("err", "flags:directory_with_file_flag")
    table = MODEL_OPEN[abi]
    value = {"read_only": MODEL_COMMON["O_RDONLY"], "write_only": MODEL_COMMON["O_WRONLY"], "read_write": MODEL_COMMON["O_RDWR"]}[case["access"]]
    if case["create"] in ("if_missing", "must_be_new"):
        value |= table["O_CREAT"]
    if case["create"] == "must_be_new":
        value |= table["O_EXCL"]
    if case["truncate"]:
        value |= MODEL_COMMON["O_TRUNC"]
    if case["append"]:
        value |= table["O_APPEND"]
    if sync == "data":
        value |= table["O_DSYNC"]
    elif sync == "full":
        value |= table["O_SYNC"]
    if case["directory"]:
        value |= table["O_DIRECTORY"]
    if case["no_follow"]:
        value |= table["O_NOFOLLOW"]
    if case["nonblock"]:
        value |= table["O_NONBLOCK"]
    if case["cloexec"]:
        value |= MODEL_COMMON["O_CLOEXEC"]
    if case["large_file"]:
        value |= table["O_LARGEFILE"]
    return ("ok", value)


def model_unit(abi, raw, oracle):
    kind, value = model_decode(abi, raw, oracle)
    if kind == "ok":
        return ("ok", True) if value == 0 else ("err", "unexpected_result")
    return (kind, value)


def model_fsync(abi, raw, oracle):
    kind, value = model_unit(abi, raw, oracle)
    if kind == "err" and value == "invalid":
        return ("err", "not_syncable")
    if kind == "err" and value in SYNC_FAILURES:
        return ("err", "sync_failed:" + value)
    return (kind, value)


def model_open(abi, raw, oracle):
    kind, value = model_decode(abi, raw, oracle)
    if kind == "ok":
        return ("ok", value) if value <= 2**31 - 1 else ("err", "descriptor_range")
    return (kind, value)


def model_write(abi, raw, requested, oracle):
    kind, value = model_decode(abi, raw, oracle)
    if kind == "err":
        return (kind, value)
    if value > requested:
        return ("err", "over_reported")
    if value == requested:
        return ("ok", ("full", None))
    if value == 0:
        return ("err", "no_progress")
    return ("ok", ("partial", value))


def model_offset(offset):
    if offset < 0:
        return ("err", "offset_negative")
    hi, lo = struct.unpack(">II", struct.pack(">Q", offset))
    return ("ok", (hi, lo, offset if offset <= 2**31 - 1 else None))


def model_llseek(hex_bytes):
    hi, lo = struct.unpack(">II", bytes.fromhex(hex_bytes))
    if hi > 0x7FFFFFFF:
        return ("err", "offset_negative")
    return ("ok", (hi << 32) | lo)


def model_sequence(abi, steps, oracle):
    """'ok' or the name of the first causal fault, in the order E03 observes the sequence."""
    for index, expected in enumerate(SEQUENCE):
        if index >= len(steps):
            return "missing:" + expected
        step = steps[index]
        if step["step"] != expected:
            return "out_of_order:%d:%s" % (index, expected)
        if expected == "write":
            if step["written"] > step["requested"]:
                return "failed:0:write:over_reported"
            if step["written"] < step["requested"]:
                return "short_write"
        elif expected == "fsync":
            kind, value = model_fsync(abi, step["raw"], oracle)
            if kind == "err":
                return "failed:%d:fsync:%s" % (index, value)
        elif expected == "rename":
            kind, value = model_unit(abi, step["raw"], oracle)
            if kind == "err":
                return "failed:%d:rename:%s" % (index, value)
        elif expected == "read_back":
            if not step["matches"]:
                return "read_back_differs"
        else:
            kind, value = model_decode(abi, step["raw"], oracle)
            if kind == "ok":
                return "old_name_still_there"
            if value != "ENOENT":
                return "failed:%d:old_name_gone:%s" % (index, value)
    if len(steps) > len(SEQUENCE):
        return "extra:%d" % len(SEQUENCE)
    return "ok"


def expected_pair(expect):
    if "err" in expect:
        return ("err", expect["err"])
    if "fd" in expect:
        return ("ok", expect["fd"])
    if "ok" in expect:
        return ("ok", expect["ok"])
    raise AssertionError("no recognised expectation in %r" % (expect,))


def model_problems(v, oracle):
    """Every answer in the vector file that the independent model does not give; empty when they agree."""
    out = []

    def check(label, got, want):
        if got != want:
            out.append("%s: model %r, vector %r" % (label, got, want))

    for case in v["open_request"]:
        check("open_request %s on %s" % (case["name"], case["abi"]), model_open_flags(case["abi"], case), expected_pair(case["expect"]))
    for case in v["classify"]:
        raw = -case["errno"]
        got = model_decode(case["abi"], raw, oracle)
        check("classify %s %d" % (case["abi"], case["errno"]), got[1], case["expect"])
    for case in v["open_decode"]:
        check("open_decode %s %d" % (case["abi"], case["raw"]), model_open(case["abi"], case["raw"], oracle), expected_pair(case["expect"]))
    for case in v["write_decode"]:
        got = model_write(case["abi"], case["raw"], case["requested"], oracle)
        want = case["expect"]
        if "progress" in want:
            want = ("ok", (want["progress"], want.get("written")))
        else:
            want = ("err", want["err"])
        check("write_decode %s %d/%d" % (case["abi"], case["raw"], case["requested"]), got, want)
    for case in v["fsync_decode"]:
        check("fsync_decode %s %d" % (case["abi"], case["raw"]), model_fsync(case["abi"], case["raw"], oracle), expected_pair(case["expect"]))
    for case in v["unit_decode"]:
        check("unit_decode %s %d" % (case["abi"], case["raw"]), model_unit(case["abi"], case["raw"], oracle), expected_pair(case["expect"]))
    for case in v["offset"]:
        got = model_offset(case["offset"])
        want = case["expect"]
        if "err" in want:
            check("offset %d" % case["offset"], got, ("err", want["err"]))
        else:
            check("offset %d" % case["offset"], got, ("ok", (want["hi"], want["lo"], want.get("i32"))))
    for case in v["llseek_result"]:
        want = case["expect"]
        check("llseek %s" % case["bytes"], model_llseek(case["bytes"]), ("err", want["err"]) if "err" in want else ("ok", want["offset"]))
    for case in v["replace_sequence"]:
        want = "ok" if "ok" in case["expect"] else case["expect"]["err"]
        check("sequence %s on %s" % (case["name"], case["abi"]), model_sequence(case["abi"], case["steps"], oracle), want)
    return out


# ----------------------------------------------------------------------------------------------- the libc crate

CONST = re.compile(r"^\s*pub const (\w+):\s*[\w:]+\s*=\s*(0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d+)\s*;", re.M)


def parse_consts(text):
    found = {}
    for name, literal in CONST.findall(text):
        literal = literal.replace("_", "")
        value = int(literal, 16) if literal.startswith("0x") else int(literal, 8) if literal.startswith("0o") else int(literal, 2) if literal.startswith("0b") else int(literal)
        found.setdefault(name, []).append(value)
    return found


LIBC_FILES = {
    "powerpc32": ["src/unix/linux_like/linux/musl/b32/powerpc.rs", "src/unix/linux_like/linux/musl/mod.rs", "src/unix/linux_like/mod.rs",
                  "src/unix/linux_like/linux_l4re_shared.rs"],
    "mips32": ["src/unix/linux_like/linux/musl/b32/mips/mod.rs", "src/unix/linux_like/linux/musl/mod.rs", "src/unix/linux_like/mod.rs",
               "src/unix/linux_like/linux_l4re_shared.rs"],
}


def libc_candidates():
    paths = []
    override = os.environ.get("FFW_LIBC_SRC")
    if override:
        paths.append(override)
    paths += sorted(glob.glob(os.path.join(os.path.expanduser("~"), ".cargo", "registry", "src", "*", "libc-*")), reverse=True)
    return paths


def find_libc():
    """(root, {abi: [text, ...]}) for the newest cached libc crate that has every file this check reads, or None."""
    for root in libc_candidates():
        rels = {rel for files in LIBC_FILES.values() for rel in files}
        if all(os.path.isfile(os.path.join(root, rel)) for rel in rels):
            return root, {abi: [read(os.path.join(root, rel)) for rel in files] for abi, files in LIBC_FILES.items()}
    return None


def libc_value(texts, name):
    """The first definition of `name` in the ABI's files, most specific file first; None when no file defines it."""
    for text in texts:
        values = parse_consts(text).get(name)
        if values:
            if len(set(values)) != 1:
                raise AssertionError("%s is defined with several values: %r" % (name, values))
            return values[0]
    return None


def problems_against_libc(v, files):
    """Every number in the vector file that the libc crate's files do not state the same way; a number libc does not define is a problem too."""
    out = []

    def check(label, got, want):
        if want is None:
            out.append("%s: libc does not define it" % label)
        elif got != want:
            out.append("%s: vector %r, libc %r" % (label, got, want))

    for name in COMMON_FLAGS:
        check(name, v["common"][name], libc_value(files["powerpc32"], name))
        check(name + " (mips)", v["common"][name], libc_value(files["mips32"], name))
    for abi in ABIS:
        row = v["abi"][abi]
        check("%s O_NONBLOCK" % abi, row["O_NONBLOCK"], libc_value(files[abi], "O_NONBLOCK"))
        for name in FLAGS:
            check("%s %s" % (abi, name), row["open"][name], libc_value(files[abi], name))
        for name, number in row["errno"].items():
            check("%s %s" % (abi, name), number, libc_value(files[abi], name))
    return out


# ------------------------------------------------------------------------------------------------------ the tests

class ModelAgreesWithTheVectors(unittest.TestCase):
    """The vector file is hand-written; an independent restatement of every builder and decoder must reach the same answers."""

    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.oracle = load_oracle()

    def test_the_model_tables_equal_the_vector_numbers(self):
        for abi in ABIS:
            self.assertEqual({k: self.v["abi"][abi]["open"][k] for k in FLAGS}, {k: MODEL_OPEN[abi][k] for k in FLAGS}, abi)
            self.assertEqual(self.v["abi"][abi]["O_NONBLOCK"], MODEL_OPEN[abi]["O_NONBLOCK"], abi)
            self.assertEqual(self.v["abi"][abi]["errno"], model_errno(abi), abi)
        self.assertEqual(self.v["common"], MODEL_COMMON)

    def test_open_request_flags(self):
        rows = [c for c in self.v["open_request"]]
        self.assertGreaterEqual(len(rows), 30)
        self.assertEqual([p for p in model_problems(self.v, self.oracle) if p.startswith("open_request")], [])
        # every request is stated for both ABIs, and the refusals do not depend on the ABI
        names = {}
        for case in rows:
            names.setdefault(case["name"], {})[case["abi"]] = case["expect"]
        for name, per_abi in names.items():
            self.assertEqual(sorted(per_abi), sorted(ABIS), name)
            if "err" in per_abi["powerpc32"]:
                self.assertEqual(per_abi["powerpc32"], per_abi["mips32"], name)
            elif per_abi["powerpc32"]["ok"] != 0:
                self.assertNotEqual(per_abi["powerpc32"], per_abi["mips32"], "%s: a request with flags in it has per-ABI values" % name)

    def test_classification_and_every_decoder(self):
        self.assertEqual(model_problems(self.v, self.oracle), [])

    def test_offsets(self):
        for case in self.v["offset"]:
            kind, value = model_offset(case["offset"])
            if kind == "ok":
                hi, lo, i32 = value
                self.assertEqual((hi << 32) | lo, case["offset"], case)
                self.assertTrue(0 <= hi <= 0x7FFFFFFF and 0 <= lo <= 0xFFFFFFFF, case)
        # the pad word of pread64/pwrite64 is zero and the tail is (pad, hi, lo): three of the six slots
        self.assertEqual(struct.pack(">III", 0, 1, 2).hex(), "000000000000000100000002")

    def test_replace_sequence(self):
        names = [c["name"] for c in self.v["replace_sequence"]]
        self.assertEqual(len(names), len(self.v["replace_sequence"]))
        good = [c for c in self.v["replace_sequence"] if "ok" in c["expect"]]
        self.assertEqual(sorted(c["abi"] for c in good), sorted(ABIS), "the in-order sequence passes on both ABIs")
        self.assertEqual([s["step"] for s in good[0]["steps"]], list(SEQUENCE))
        faults = {c["expect"]["err"].split(":")[0] for c in self.v["replace_sequence"] if "err" in c["expect"]}
        self.assertEqual(faults, {"short_write", "failed", "out_of_order", "read_back_differs", "old_name_still_there", "missing", "extra"})

    def test_release_boundaries(self):
        b = self.v["kernel_boundaries"]
        self.assertEqual(b["cloexec_honored_since"], [2, 6, 23])
        self.assertEqual(b["dsync_native_since"], [2, 6, 33])
        for case in self.v["release_checks"]:
            release = tuple(case["release"])
            self.assertEqual(case["cloexec_honored"], release >= tuple(b["cloexec_honored_since"]), case)
            self.assertEqual(case["dsync_native"], release >= tuple(b["dsync_native_since"]), case)
        # the old O_SYNC value is the new O_DSYNC value on each ABI: a full sync, never a weaker one
        for abi in ABIS:
            self.assertEqual(b["old_sync_value"][abi], self.v["abi"][abi]["open"]["O_DSYNC"], abi)
            self.assertEqual(self.v["abi"][abi]["open"]["O_SYNC"] & b["old_sync_value"][abi], b["old_sync_value"][abi], abi)

    def test_collisions_and_differing_errnos_are_derived_not_asserted(self):
        derived = []
        for a in FLAGS:
            for b in FLAGS:
                if a != b and MODEL_OPEN["powerpc32"][a] == MODEL_OPEN["mips32"][b]:
                    derived.append({"value": MODEL_OPEN["powerpc32"][a], "powerpc32": a, "mips32": b})
        self.assertEqual(derived, self.v["cross_abi_collisions"])
        differing = [n for n in model_errno("powerpc32") if model_errno("powerpc32")[n] != model_errno("mips32")[n]]
        self.assertEqual(differing, self.v["differing_errnos"])
        for abi in ABIS:
            numbers = list(model_errno(abi).values())
            self.assertEqual(len(numbers), len(set(numbers)), "%s: a number names one error" % abi)
            self.assertFalse(set(numbers) & {4, 11, 22, self.oracle.errno_number(ARCH[abi], "ENOSYS")}, abi)

    def test_every_witness_names_a_kernel_file_with_a_checksum(self):
        for witness in self.v["witnesses"]:
            self.assertTrue(witness["fact"] and witness["tag"], witness)
            self.assertTrue(witness["files"], witness)
            for path, digest in witness["files"].items():
                self.assertRegex(digest, r"^[0-9a-f]{16}$", path)


class SensitivityOfTheModelCheck(unittest.TestCase):
    """The model comparison reports a wrong answer planted in each section; the unplanted comparison is clean first."""

    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.oracle = load_oracle()

    def test_each_section_notices_a_planted_wrong_answer(self):
        self.assertEqual(model_problems(self.v, self.oracle), [])
        plants = {
            "an open flag sum": lambda v: v["open_request"][2]["expect"].update({"ok": v["open_request"][2]["expect"]["ok"] + 1}),
            "a refusal turned into a success": lambda v: v["open_request"][16].update({"expect": {"ok": 1}}),
            "an errno name": lambda v: v["classify"][2].update({"expect": "ENOSPC"}),
            "an open result": lambda v: v["open_decode"][0].update({"expect": {"fd": 4}}),
            "a short write called full": lambda v: v["write_decode"][2].update({"expect": {"progress": "full"}}),
            "an fsync failure called retryable": lambda v: v["fsync_decode"][2].update({"expect": {"err": "EIO"}}),
            "a cross-device rename called fine": lambda v: v["unit_decode"][2].update({"expect": {"ok": True}}),
            "an offset word": lambda v: v["offset"][6]["expect"].update({"lo": 3}),
            "a negative llseek result accepted": lambda v: v["llseek_result"][5].update({"expect": {"offset": 0}}),
            "a sequence fault": lambda v: v["replace_sequence"][4].update({"expect": {"ok": True}}),
        }
        for name, plant in plants.items():
            broken = copy.deepcopy(self.v)
            plant(broken)
            self.assertTrue(model_problems(broken, self.oracle), name)


class LibcCrateAgreesWithTheVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load_vectors()
        cls.found = find_libc()

    def test_the_libc_crate_agrees(self):
        if self.found is None:
            self.skipTest("no cached libc crate with the files this check reads (set FFW_LIBC_SRC to one)")
        root, files = self.found
        self.assertEqual(problems_against_libc(self.v, files), [], root)

    def test_the_libc_check_is_sensitive_and_covers_every_number(self):
        if self.found is None:
            self.skipTest("no cached libc crate with the files this check reads (set FFW_LIBC_SRC to one)")
        _, files = self.found
        self.assertEqual(problems_against_libc(self.v, files), [])
        plants = {
            "powerpc O_CREAT is mips's": lambda v: v["abi"]["powerpc32"]["open"].update({"O_CREAT": 256}),
            "mips O_APPEND is powerpc's": lambda v: v["abi"]["mips32"]["open"].update({"O_APPEND": 1024}),
            "mips O_SYNC is the old value": lambda v: v["abi"]["mips32"]["open"].update({"O_SYNC": 16}),
            "powerpc O_SYNC is the old value": lambda v: v["abi"]["powerpc32"]["open"].update({"O_SYNC": 4096}),
            "mips ELOOP is powerpc's": lambda v: v["abi"]["mips32"]["errno"].update({"ELOOP": 40}),
            "powerpc EDQUOT is mips's": lambda v: v["abi"]["powerpc32"]["errno"].update({"EDQUOT": 1133}),
            "O_CLOEXEC": lambda v: v["common"].update({"O_CLOEXEC": 262144}),
            "mips O_NONBLOCK": lambda v: v["abi"]["mips32"].update({"O_NONBLOCK": 2048}),
        }
        for name, plant in plants.items():
            broken = copy.deepcopy(self.v)
            plant(broken)
            self.assertTrue(problems_against_libc(broken, files), name)
        # a number libc does not define is reported, not skipped
        missing = copy.deepcopy(self.v)
        missing["abi"]["mips32"]["errno"]["ENOTAREALERRNO"] = 9999
        self.assertTrue(any("does not define" in p for p in problems_against_libc(missing, files)))


class RustTextAgreesWithTheVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rust = read(DURABLE_RS)
        cls.lib = read(LIB_RS)
        cls.code = "\n".join(line for line in cls.rust.split("#[cfg(test)]")[0].splitlines() if not line.lstrip().startswith("//"))

    def test_the_module_is_declared_between_clock_and_entropy(self):
        ungated = self.lib.split("#[cfg(", 1)[0]          # `sim` is a separate, cfg-gated group after the ordered ones
        mods = re.findall(r"^pub mod (\w+);", ungated, re.M)
        self.assertIn("durable", mods)
        self.assertEqual(mods[mods.index("durable") - 1], "clock")
        self.assertEqual(mods[mods.index("durable") + 1], "entropy")
        self.assertEqual(mods, sorted(mods), "rustfmt orders the mods")

    def test_the_code_has_none_of_what_this_slice_leaves_out(self):
        for forbidden in ("thread_local", "unsafe", "std::fs", "std::net", "std::os", "libc::", "__NR_", "NR_", "extern ", "KernelOps"):
            self.assertNotIn(forbidden, self.code, forbidden)

    def test_the_numbers_in_the_code_are_the_vector_numbers(self):
        """Parse the match arms of FileErrno::number and OpenFlag::value out of the Rust text and hold every one to the vector file."""
        v = load_vectors()
        flag_names = {"Creat": "O_CREAT", "Excl": "O_EXCL", "Append": "O_APPEND", "Dsync": "O_DSYNC", "Sync": "O_SYNC", "Directory": "O_DIRECTORY",
                      "NoFollow": "O_NOFOLLOW", "LargeFile": "O_LARGEFILE"}
        errno_names = {"Perm": "EPERM", "NoEnt": "ENOENT", "Io": "EIO", "BadF": "EBADF", "NoMem": "ENOMEM", "Acces": "EACCES", "Busy": "EBUSY",
                       "Exist": "EEXIST", "XDev": "EXDEV", "NotDir": "ENOTDIR", "IsDir": "EISDIR", "NFile": "ENFILE", "MFile": "EMFILE",
                       "FBig": "EFBIG", "NoSpc": "ENOSPC", "RoFs": "EROFS", "Deadlk": "EDEADLK", "NameTooLong": "ENAMETOOLONG", "NoLck": "ENOLCK",
                       "NotEmpty": "ENOTEMPTY", "Loop": "ELOOP", "Overflow": "EOVERFLOW", "Stale": "ESTALE", "DQuot": "EDQUOT"}
        arm = re.compile(r"\(Self::(\w+), (Abi::PowerPc32|Abi::Mips32|_)\) => (0x[0-9a-f_]+|\d+),")
        seen_flags, seen_errnos = {}, {}
        for variant, which, literal in arm.findall(self.code):
            value = int(literal.replace("_", ""), 16) if literal.startswith("0x") else int(literal)
            abis = ABIS if which == "_" else (("powerpc32",) if which == "Abi::PowerPc32" else ("mips32",))
            for abi in abis:
                if variant in flag_names:
                    seen_flags[(abi, flag_names[variant])] = value
                else:
                    seen_errnos[(abi, errno_names[variant])] = value
        self.assertEqual(seen_flags, {(abi, n): v["abi"][abi]["open"][n] for abi in ABIS for n in FLAGS})
        self.assertEqual(seen_errnos, {(abi, n): number for abi in ABIS for n, number in v["abi"][abi]["errno"].items()})

    def test_the_documented_kernel_boundaries_are_the_constants(self):
        self.assertIn("pub const CLOEXEC_HONORED_SINCE: KernelRelease = (2, 6, 23);", self.rust)
        self.assertIn("pub const DSYNC_SINCE: KernelRelease = (2, 6, 33);", self.rust)


INVARIANTS = [
    {"id": "P06-DUR-001", "statement": "each open flag the ABIs disagree on has its own number per ABI, and a number never names two flags on one ABI",
     "rust": ["the_open_flag_numbers_are_the_vectors", "a_flag_number_names_one_flag_per_abi_and_the_cross_abi_collisions_are_the_vectors"],
     "python": ["test_the_model_tables_equal_the_vector_numbers", "test_collisions_and_differing_errnos_are_derived_not_asserted", "test_the_libc_crate_agrees"]},
    {"id": "P06-DUR-002", "statement": "the kernel-generation facts (O_CLOEXEC from 2.6.23, O_DSYNC and the new O_SYNC from 2.6.33) are constants with tests",
     "rust": ["the_kernel_release_boundaries_are_the_vectors"], "python": ["test_release_boundaries", "test_every_witness_names_a_kernel_file_with_a_checksum"]},
    {"id": "P06-DUR-003", "statement": "an open request becomes the flags or a refusal, and an append open is not a positioned-write target",
     "rust": ["open_requests_build_the_flags_the_vectors_say_or_are_refused", "an_append_open_is_not_a_target_for_positioned_writes"],
     "python": ["test_open_request_flags", "test_each_section_notices_a_planted_wrong_answer"]},
    {"id": "P06-DUR-004", "statement": "the eight file errnos that differ are numbered per ABI, a number names at most one error, and an unknown errno is kept",
     "rust": ["file_errno_numbers_are_the_vectors_and_name_at_most_one_error_per_abi", "errno_classification_follows_the_vectors_and_keeps_what_it_does_not_know"],
     "python": ["test_classification_and_every_decoder", "test_the_libc_check_is_sensitive_and_covers_every_number"]},
    {"id": "P06-DUR-005", "statement": "open, write, fsync and unit-call results decode to typed answers: a short write is neither success nor a fault, an fsync failure is final",
     "rust": ["open_results_decode_as_descriptors_or_typed_errors", "a_short_write_is_neither_success_nor_a_fault",
              "fsync_results_are_durable_or_final_and_a_unit_call_never_returns_a_count"], "python": ["test_classification_and_every_decoder"]},
    {"id": "P06-DUR-006", "statement": "a 64-bit file offset is two big-endian words and is never truncated or wrapped",
     "rust": ["file_offsets_split_into_big_endian_words_and_are_never_truncated", "an_llseek_result_is_eight_big_endian_bytes_and_a_negative_one_is_refused"],
     "python": ["test_offsets"]},
    {"id": "P06-DUR-007", "statement": "the E03 replace sequence passes only in order and names the first causal fault",
     "rust": ["the_replace_sequence_passes_in_order_and_names_the_first_causal_step_otherwise"], "python": ["test_replace_sequence"]},
    {"id": "P06-DUR-008", "statement": "the module has no unsafe, no filesystem, no syscall number, no thread-local errno and no KernelOps",
     "rust": ["the_source_has_no_unsafe_no_filesystem_no_syscall_number_and_no_other_libraries_code"],
     "python": ["test_the_code_has_none_of_what_this_slice_leaves_out", "test_the_module_is_declared_between_clock_and_entropy"]},
]
INAPPLICABLE = {
    "syscall numbers and the leaf's six-slot gap": "no call is issued: the numbers, the KernelOps methods and the wrappers are P02's; docs/contracts/p06.md states that "
                                                  "pread64/pwrite64 need six argument slots and the leaf's trampoline carries five",
    "thread-local errno": "a failure arrives in-band as -errno; there is no TLS to set up, read or race",
    "a directory fsync": "E03 does not observe syncing the directory after the rename, so nothing here judges or claims it",
}


class InvariantsMapToTestsThatExist(unittest.TestCase):
    """Each invariant maps to Rust tests and Python tests that exist; every Rust test in durable.rs is claimed; inapplicable items are explained."""

    def python_test_names(self):
        return set(re.findall(r"^\s+def (test_\w+)\(", read(os.path.abspath(__file__)), re.M))

    def test_every_named_test_exists(self):
        rust = set(re.findall(r"#\[test\]\s*fn (\w+)\(", read(DURABLE_RS)))
        python = self.python_test_names()
        for inv in INVARIANTS:
            self.assertTrue(inv["rust"] and inv["python"], inv["id"])
            for name in inv["rust"]:
                self.assertIn(name, rust, "%s: no Rust test %s" % (inv["id"], name))
            for name in inv["python"]:
                self.assertIn(name, python, "%s: no Python test %s" % (inv["id"], name))

    def test_every_rust_test_is_claimed_by_an_invariant(self):
        rust = set(re.findall(r"#\[test\]\s*fn (\w+)\(", read(DURABLE_RS)))
        claimed = {name for inv in INVARIANTS for name in inv["rust"]}
        self.assertEqual(sorted(rust - claimed), [])

    def test_invariant_ids_are_unique_and_the_inapplicable_ones_have_reasons(self):
        ids = [inv["id"] for inv in INVARIANTS]
        self.assertEqual(len(ids), len(set(ids)))
        for inv in INVARIANTS:
            self.assertTrue(inv["statement"].strip(), inv["id"])
        for what, why in INAPPLICABLE.items():
            self.assertGreater(len(why), 30, what)


if __name__ == "__main__":
    unittest.main()
