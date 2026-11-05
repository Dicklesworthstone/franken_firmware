#!/usr/bin/env python3
"""P02 (ffw-jub): the syscall numbers franken-platform-linux issues, per ABI, have two independent witnesses.

`crates/franken-platform-linux/src/numbers.rs` is held to:
* the E03 guest probes (`toolchain/src/ffw-hello-init`), which issued these exact calls in full-system QEMU guests: `NR_*` in
  `main.rs` (open, pipe2, read, write, close) and `nr::*` in `e03_probes.rs` (getrandom, eventfd2). Always required;
* the `libc` crate's musl tables (`SYS_*`), when the registry has the version Cargo.lock names. If it does not, that test is
  SKIPPED and says so; the E03 witness still runs.

Per ABI: a MIPS o32 number is 4000-based and a PowerPC number is not, so a swapped or copied table fails both witnesses.
Offline, stdlib only. "Sensitivity" tests plant a wrong number in each source and require the comparison to report it.
"""
import glob
import os
import re
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
NUMBERS_RS = os.path.join(ROOT, "crates", "franken-platform-linux", "src", "numbers.rs")
HELLO = os.path.join(ROOT, "toolchain", "src", "ffw-hello-init", "src")
CARGO_LOCK = os.path.join(ROOT, "Cargo.lock")

CALLS = ("getrandom", "eventfd2", "pipe2", "open", "read", "write", "close")      # the clock is std's Instant, not a raw call
TABLES = {"powerpc": "POWERPC32", "mips": "MIPS32_O32"}
# call -> (file, constant name in the E03 probes)
E03 = {
    "pipe2": ("main.rs", "NR_PIPE2"), "open": ("main.rs", "NR_OPEN"), "read": ("main.rs", "NR_READ"),
    "write": ("main.rs", "NR_WRITE"), "close": ("main.rs", "NR_CLOSE"),
    "getrandom": ("e03_probes.rs", "GETRANDOM"), "eventfd2": ("e03_probes.rs", "EVENTFD2"),
}
LIBC_FILES = {"powerpc": "linux_like/linux/musl/b32/powerpc.rs", "mips": "linux_like/linux/musl/b32/mips/mod.rs"}


def _eval_sum(expr):
    """`246` or `4000 + 263`: digits and plus signs only, so nothing else is ever evaluated."""
    if not re.fullmatch(r"[0-9_]+(\s*\+\s*[0-9_]+)*", expr.strip()):
        raise AssertionError("not a plain number expression: %r" % expr)
    return sum(int(part.replace("_", "")) for part in expr.split("+"))


def rust_numbers(source, constant):
    """The `Numbers { field: expr, ... }` of `pub const <constant>: Numbers = ...;` as {call: number}."""
    match = re.search(r"pub const %s: Numbers = Numbers \{(.*?)\};" % re.escape(constant), source, re.S)
    if not match:
        raise AssertionError("no Numbers table named %s" % constant)
    fields = {}
    for name, expr in re.findall(r"([a-z0-9_]+):\s*([^,]+),", match.group(1)):
        if name in fields:
            raise AssertionError("%s lists %s twice" % (constant, name))
        fields[name] = _eval_sum(expr)
    if sorted(fields) != sorted(CALLS):
        raise AssertionError("%s has fields %s, expected %s" % (constant, sorted(fields), sorted(CALLS)))
    return fields


def diff(left, right, left_name, right_name):
    return ["%s: %s=%s but %s=%s" % (name, left_name, left.get(name), right_name, right.get(name))
            for name in sorted(set(left) | set(right)) if left.get(name) != right.get(name)]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def e03_numbers(arch):
    """{call: number} for `arch` from the guest probe sources."""
    out = {}
    marker = {"mips": 'target_arch = "mips"', "powerpc": 'target_arch = "powerpc"'}[arch]
    cache = {}
    for call, (filename, constant) in E03.items():
        source = cache.setdefault(filename, read(os.path.join(HELLO, filename)))
        # the arch's block: from its `#[cfg(...)]` line to the next `#[cfg(target_arch` line or the end
        starts = [m.start() for m in re.finditer(r"#\[cfg\(target_arch = \"(?:mips|powerpc)\"\)\]\nmod ", source)]
        blocks = []
        for index, start in enumerate(starts):
            end = starts[index + 1] if index + 1 < len(starts) else len(source)
            blocks.append(source[start:end])
        block = next((b for b in blocks if marker in b.splitlines()[0]), None)
        if block is None:
            raise AssertionError("no %s block in %s" % (arch, filename))
        match = re.search(r"pub const %s: usize = ([0-9 +]+);" % re.escape(constant), block)
        if not match:
            raise AssertionError("%s not found in the %s block of %s" % (constant, arch, filename))
        out[call] = _eval_sum(match.group(1))
    return out


def libc_root():
    try:
        version = re.search(r'name = "libc"\nversion = "([^"]+)"', read(CARGO_LOCK))
    except OSError:
        return None
    if not version:
        return None
    pattern = os.path.join(os.path.expanduser("~"), ".cargo", "registry", "src", "*", "libc-" + version.group(1), "src", "unix")
    found = sorted(glob.glob(pattern))
    return found[0] if found else None


def libc_numbers(root, arch):
    out = {}
    source = read(os.path.join(root, LIBC_FILES[arch]))
    for call in CALLS:
        match = re.search(r"pub const SYS_%s: c_long = ([0-9 +]+);" % call, source)
        if not match:
            raise AssertionError("SYS_%s not in libc's %s table" % (call, arch))
        out[call] = _eval_sum(match.group(1))
    return out


class TableShapeTests(unittest.TestCase):
    def setUp(self):
        self.source = read(NUMBERS_RS)

    def test_both_tables_have_the_seven_calls_and_differ_in_every_one(self):
        ppc, mips = (rust_numbers(self.source, TABLES[a]) for a in ("powerpc", "mips"))
        self.assertEqual(sorted(ppc), sorted(CALLS))
        for call in CALLS:
            self.assertNotEqual(ppc[call], mips[call], call)
            self.assertGreaterEqual(mips[call], 4000, call)       # o32 is 4000-based
            self.assertLess(ppc[call], 1000, call)

    def test_a_table_that_is_not_plain_numbers_is_refused_rather_than_evaluated(self):
        bad = self.source.replace("getrandom: 359,", "getrandom: 359 * 1,", 1)
        self.assertNotEqual(bad, self.source)
        with self.assertRaises(AssertionError):
            rust_numbers(bad, "POWERPC32")


class E03WitnessTests(unittest.TestCase):
    def test_the_numbers_equal_the_ones_the_audited_guest_probes_issued(self):
        source = read(NUMBERS_RS)
        for arch, constant in TABLES.items():
            self.assertEqual(diff(rust_numbers(source, constant), e03_numbers(arch), "numbers.rs", "e03 probes"), [], arch)

    def test_a_planted_wrong_number_is_reported(self):
        source = read(NUMBERS_RS)
        for old, new in (("getrandom: 359,", "getrandom: 358,"), ("eventfd2: 4000 + 325,", "eventfd2: 4000 + 326,"),
                         ("pipe2: 317,", "pipe2: 4000 + 328,"), ("open: 4000 + 5,", "open: 4000 + 6,"), ("open: 5,", "open: 6,")):
            bad = source.replace(old, new, 1)
            self.assertNotEqual(bad, source, old)
            problems = []
            for arch, constant in TABLES.items():
                problems += diff(rust_numbers(bad, constant), e03_numbers(arch), "numbers.rs", "e03 probes")
            self.assertNotEqual(problems, [], old)

    def test_a_swapped_table_is_reported(self):
        source = read(NUMBERS_RS)
        swapped = source.replace("POWERPC32", "TMP_SWAP").replace("MIPS32_O32", "POWERPC32").replace("TMP_SWAP", "MIPS32_O32")
        problems = []
        for arch, constant in TABLES.items():
            problems += diff(rust_numbers(swapped, constant), e03_numbers(arch), "numbers.rs", "e03 probes")
        self.assertGreaterEqual(len(problems), len(CALLS) * 2)


class LibcWitnessTests(unittest.TestCase):
    def setUp(self):
        self.root = libc_root()
        if self.root is None:
            self.skipTest("the libc crate named by Cargo.lock is not in the local cargo registry; the E03 witness still ran")

    def test_the_numbers_equal_the_libc_crates_musl_tables(self):
        source = read(NUMBERS_RS)
        for arch, constant in TABLES.items():
            self.assertEqual(diff(rust_numbers(source, constant), libc_numbers(self.root, arch), "numbers.rs", "libc"), [], arch)

    def test_libc_agrees_with_the_e03_probes_too(self):
        for arch in TABLES:
            self.assertEqual(diff(e03_numbers(arch), libc_numbers(self.root, arch), "e03 probes", "libc"), [], arch)


if __name__ == "__main__":
    unittest.main()
