#!/usr/bin/env python3
"""P02 (ffw-jub): the errno and open-flag numbers franken-platform decodes with have more than one witness.

The Rust tables (crates/franken-platform/src/abi.rs) are held by a unit test to the committed vector file; this file holds
that vector file to the other independent sources, so a wrong number has to be wrong in all of them at once:

* the E03 oracle (tests/e03/abi.py), from which the vector file is generated,
* the table text in abi.rs itself (so the Rust unit test cannot be deleted without this noticing),
* the `libc` crate in the local cargo registry, when it is there (the numbers the Rust musl targets use).

Offline, stdlib only, no cargo, no QEMU. "Sensitivity" tests plant a wrong number in each source and require the comparison to
report it, so a comparison that cannot fail cannot pass.
"""
import glob
import importlib.util
import json
import os
import re
import sys
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VECTORS = os.path.join(ROOT, "crates", "franken-platform", "tests", "vectors", "p02_errno.json")
ABI_RS = os.path.join(ROOT, "crates", "franken-platform", "src", "abi.rs")
ORACLE = os.path.join(ROOT, "tests", "e03", "abi.py")
CARGO_LOCK = os.path.join(ROOT, "Cargo.lock")

# The vector file's ABI name -> the oracle's arch name, the Rust table's constant, and the libc crate's per-arch file.
ABIS = {
    "powerpc32": {"oracle": "powerpc", "rust": "POWERPC_ERRNO", "libc": "linux_like/linux/musl/b32/powerpc.rs"},
    "mips32": {"oracle": "mips", "rust": "MIPS_ERRNO", "libc": "linux_like/linux/musl/b32/mips/mod.rs"},
}
LIBC_COMMON = "linux_like/linux_l4re_shared.rs"
LIBC_FLAGS = "linux_like/linux/musl/mod.rs"
SETS = ("EPERM ENOENT EINTR EIO EBADF EAGAIN ENOMEM EACCES EFAULT EINVAL EMFILE ENOSYS ENOTSOCK "
        "EPROTONOSUPPORT EOPNOTSUPP EAFNOSUPPORT").split()


def load_oracle():
    spec = importlib.util.spec_from_file_location("ffw_p02_e03_abi", ORACLE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ffw_p02_e03_abi"] = module
    spec.loader.exec_module(module)
    return module


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def diff_tables(left, right, left_name, right_name):
    """Human-readable differences between two {name: number} tables; empty when they are equal."""
    problems = []
    for name in sorted(set(left) | set(right)):
        if name not in left:
            problems.append("%s has %s=%d, %s does not" % (right_name, name, right[name], left_name))
        elif name not in right:
            problems.append("%s has %s=%d, %s does not" % (left_name, name, left[name], right_name))
        elif left[name] != right[name]:
            problems.append("%s: %s=%d but %s=%d" % (name, left_name, left[name], right_name, right[name]))
    return problems


def rust_table(source, constant):
    """The `(&str, i32)` pairs of `pub const <constant>: [(&str, i32); N] = [ ... ];` in abi.rs, as a dict."""
    match = re.search(r"pub const %s: \[\(&str, i32\); (\d+)\] = \[(.*?)\];" % re.escape(constant), source, re.S)
    if not match:
        raise AssertionError("no table named %s in abi.rs" % constant)
    pairs = re.findall(r'\(\s*"([A-Z0-9]+)"\s*,\s*(\d+)\s*\)', match.group(2))
    declared = int(match.group(1))
    if len(pairs) != declared:
        raise AssertionError("%s declares %d entries but has %d" % (constant, declared, len(pairs)))
    table = {}
    for name, number in pairs:
        if name in table:
            raise AssertionError("%s lists %s twice" % (constant, name))
        table[name] = int(number)
    return table


def libc_root():
    """The libc crate source directory the lock names, or None when the registry does not have it."""
    try:
        with open(CARGO_LOCK, encoding="utf-8") as fh:
            lock = fh.read()
    except OSError:
        return None
    version = re.search(r'name = "libc"\nversion = "([^"]+)"', lock)
    if not version:
        return None
    pattern = os.path.join(os.path.expanduser("~"), ".cargo", "registry", "src", "*", "libc-" + version.group(1), "src", "unix")
    found = sorted(glob.glob(pattern))
    return found[0] if found else None


def libc_constants(root, relative):
    out = {}
    with open(os.path.join(root, relative), encoding="utf-8") as fh:
        for line in fh:
            match = re.match(r"pub const ([A-Z0-9_]+): c_int = (0[xob][0-9a-fA-F_]+|\d+);", line.strip())
            if match:
                out[match.group(1)] = int(match.group(2).replace("_", ""), 0)
    return out


class VectorShapeTests(unittest.TestCase):
    def test_the_vector_file_has_both_abis_and_exactly_the_sixteen_names(self):
        vectors = load_vectors()
        self.assertEqual(vectors["schema"], "ffw.p02.errno.v1")
        self.assertEqual(sorted(vectors["abis"]), ["mips32", "powerpc32"])
        for abi, entry in vectors["abis"].items():
            self.assertEqual(sorted(entry["errno"]), sorted(SETS), abi)
            self.assertEqual(entry["enosys"], entry["errno"]["ENOSYS"], abi)

    def test_the_two_abis_differ_exactly_where_linux_numbers_them_differently(self):
        a, b = (load_vectors()["abis"][k]["errno"] for k in ("powerpc32", "mips32"))
        self.assertEqual(sorted(n for n in a if a[n] != b[n]),
                         ["EAFNOSUPPORT", "ENOSYS", "ENOTSOCK", "EOPNOTSUPP", "EPROTONOSUPPORT"])


class OracleTests(unittest.TestCase):
    def test_the_vector_file_equals_the_e03_oracle_per_abi(self):
        oracle = load_oracle()
        vectors = load_vectors()
        for abi, spec in ABIS.items():
            self.assertEqual(diff_tables(vectors["abis"][abi]["errno"], dict(oracle.ERRNO[spec["oracle"]]), "vectors", "oracle"), [], abi)

    def test_a_planted_wrong_number_in_either_side_is_reported(self):
        oracle = load_oracle()
        good = dict(oracle.ERRNO["mips"])
        for mutate in (lambda t: t.update(ENOSYS=38), lambda t: t.pop("EAGAIN"), lambda t: t.update(EXTRA=1)):
            bad = dict(good)
            mutate(bad)
            self.assertNotEqual(diff_tables(good, bad, "a", "b"), [])
            self.assertNotEqual(diff_tables(bad, good, "a", "b"), [])


class RustSourceTests(unittest.TestCase):
    def setUp(self):
        with open(ABI_RS, encoding="utf-8") as fh:
            self.source = fh.read()

    def test_the_tables_in_abi_rs_equal_the_vector_file(self):
        vectors = load_vectors()
        for abi, spec in ABIS.items():
            self.assertEqual(diff_tables(rust_table(self.source, spec["rust"]), vectors["abis"][abi]["errno"], "abi.rs", "vectors"), [], abi)

    def test_a_table_changed_in_the_source_text_is_reported(self):
        vectors = load_vectors()
        mutated = self.source.replace('("ENOSYS", 89)', '("ENOSYS", 38)')
        self.assertNotEqual(mutated, self.source)
        self.assertNotEqual(diff_tables(rust_table(mutated, "MIPS_ERRNO"), vectors["abis"]["mips32"]["errno"], "abi.rs", "vectors"), [])
        dropped = self.source.replace('    ("EMFILE", 24),\n', "", 1)
        with self.assertRaises(AssertionError):
            rust_table(dropped, "POWERPC_ERRNO")           # the declared length no longer matches the entries

    def test_the_rust_unit_test_that_holds_the_tables_to_the_vector_file_is_still_there(self):
        self.assertIn("include_str!(\"../tests/vectors/p02_errno.json\")", self.source)
        self.assertIn("fn the_tables_and_flags_equal_the_committed_vectors_generated_from_the_e03_oracle", self.source)


class LibcCrateTests(unittest.TestCase):
    def setUp(self):
        self.root = libc_root()
        if self.root is None:
            self.skipTest("the libc crate named by Cargo.lock is not in the local cargo registry; the third source is not available")

    def test_the_libc_crate_agrees_with_the_vector_file(self):
        vectors = load_vectors()
        common = libc_constants(self.root, LIBC_COMMON)
        flags = libc_constants(self.root, LIBC_FLAGS)
        for abi, spec in ABIS.items():
            specific = libc_constants(self.root, spec["libc"])
            merged = dict(common)
            merged.update(specific)
            wanted = vectors["abis"][abi]
            theirs = {name: merged[name] for name in SETS if name in merged}
            self.assertEqual(sorted(theirs), sorted(SETS), "%s: libc lacks %s" % (abi, sorted(set(SETS) - set(theirs))))
            self.assertEqual(diff_tables(wanted["errno"], theirs, "vectors", "libc"), [], abi)
            self.assertEqual(specific["O_NONBLOCK"], wanted["o_nonblock"], abi)
            self.assertEqual(flags["O_CLOEXEC"], wanted["o_cloexec"], abi)

    def test_the_numbers_that_differ_between_the_abis_differ_in_libc_too(self):
        ppc = libc_constants(self.root, ABIS["powerpc32"]["libc"])
        mips = libc_constants(self.root, ABIS["mips32"]["libc"])
        for name in ("ENOSYS", "ENOTSOCK", "EPROTONOSUPPORT", "EOPNOTSUPP", "EAFNOSUPPORT", "O_NONBLOCK"):
            self.assertNotEqual(ppc[name], mips[name], name)


if __name__ == "__main__":
    unittest.main()
