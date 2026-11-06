#!/usr/bin/env python3
"""P06 (ffw-2nw): the upstream ledger (tests/p06/ledger.json) is held to the upstream bytes it names.

What is checked, and what happens when the upstream clones are not on this machine:

* Every revision the ledger records resolves to a commit in its sibling clone, and every claimed ancestry is true
  (`git rev-parse --verify`, `git merge-base --is-ancestor`; nothing is checked out or written).
* The one upstream table that could be mistaken for a source of ABI numbers (FrankenLibC's `errno` module at the E06 pin) is read
  from the git object at that pin and shown to be the generic numbering: equal to PowerPC's number, different from MIPS's, for
  every network errno it defines.
* The recorded reason for not consuming `franken_kernel` (its manifest keeps serde's default `std` on) is still true at the pin.
* Nothing in this workspace's lock or manifests names a crate the ledger says is not selected, and the platform crates do not
  depend directly on `libc`.

A clone that is missing makes its checks SKIPPED, which tests/p06/run_cases.py reports as BLOCKED (exit 3): a pin that was not
looked up is not a pin that was verified.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
LEDGER = os.path.join(ROOT, "tests", "p06", "ledger.json")
VECTORS = os.path.join(ROOT, "crates", "franken-platform", "tests", "vectors", "p06_net_abi.json")
CARGO_LOCK = os.path.join(ROOT, "Cargo.lock")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_oracle():
    spec = importlib.util.spec_from_file_location("ffw_p06_ledger_e03_abi", os.path.join(ROOT, "tests", "e03", "abi.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules["ffw_p06_ledger_e03_abi"] = module
    spec.loader.exec_module(module)
    return module


def sibling_root():
    return os.environ.get("FFW_UPSTREAM_ROOT") or os.path.dirname(ROOT)


def git(repo, *args):
    """(returncode, stdout) of a read-only git command in `repo`."""
    done = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout


def clone(entry):
    path = os.path.join(sibling_root(), entry["sibling"])
    return path if os.path.isdir(os.path.join(path, ".git")) else None


def blob(repo, rev, path):
    code, out = git(repo, "show", "%s:%s" % (rev, path))
    return out if code == 0 else None


def upstream_errno(text):
    return {name: int(number) for name, number in re.findall(r"^pub const (E[A-Z0-9]+): i32 = (\d+);", text, re.M)}


class TheLedgerIsWellFormed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = load(LEDGER)

    def test_every_row_names_its_gate_and_when_it_goes_away(self):
        ids = [u["id"] for u in self.ledger["upstreams"]]
        self.assertEqual(len(ids), len(set(ids)))
        for row in self.ledger["upstreams"]:
            for field in ("sibling", "pins", "disposition", "consumed_by", "reason", "gate", "delete_when"):
                self.assertTrue(row.get(field), "%s: %s" % (row["id"], field))
            for pin in row["pins"]:
                self.assertRegex(pin["rev"], r"^[0-9a-f]{40}$", row["id"])
                self.assertTrue(pin["role"].strip())
                if "ancestor_of" in pin:
                    self.assertIn(pin["ancestor_of"], [p["rev"] for p in row["pins"]], row["id"])

    def test_the_recorded_pins_are_the_ones_the_earlier_tasks_used(self):
        pins = {u["id"]: {p["rev"] for p in u["pins"]} for u in self.ledger["upstreams"]}
        # E06's inventory directory names the FrankenLibC pin; P05's scan and E06 name the Asupersync one.
        e06 = os.path.join(ROOT, "toolchain", "results", "e06", "upstream")
        self.assertTrue(os.path.isdir(os.path.join(e06, "frankenlibc-76d7f3469f5f")))
        self.assertTrue(os.path.isdir(os.path.join(e06, "asupersync-8940119023c0")))
        self.assertIn("76d7f3469f5f5251661b3662926d3d6a2b36d494", pins["frankenlibc"])
        self.assertIn("8940119023c0e01b4d6d3e2c1399f41417c2ad24", pins["asupersync"])
        with open(os.path.join(ROOT, "docs", "contracts", "p05.md"), encoding="utf-8") as fh:
            self.assertIn("8940119023c0", fh.read())

    def test_the_oracle_is_the_only_upstream_file_read_for_numbers(self):
        rows = {u["id"]: u for u in self.ledger["upstreams"]}
        self.assertEqual(rows["frankenlibc"]["upstream_bytes"]["table"], "errno")
        for other in ("asupersync", "frankenfs", "franken_remote"):
            self.assertNotIn("table", rows[other].get("upstream_bytes", {}))


class ThePinsResolve(unittest.TestCase):
    """P06-PIN-001 and P06-PIN-002."""

    @classmethod
    def setUpClass(cls):
        cls.ledger = load(LEDGER)

    def test_every_recorded_revision_resolves_and_every_ancestry_claim_is_true(self):
        checked = 0
        for row in self.ledger["upstreams"]:
            repo = clone(row)
            if repo is None:
                continue
            for pin in row["pins"]:
                code, out = git(repo, "rev-parse", "--verify", pin["rev"] + "^{commit}")
                self.assertEqual((code, out.strip()), (0, pin["rev"]), "%s %s does not resolve to itself" % (row["id"], pin["rev"]))
                if "ancestor_of" in pin:
                    code, _ = git(repo, "merge-base", "--is-ancestor", pin["rev"], pin["ancestor_of"])
                    self.assertEqual(code, 0, "%s: %s is not an ancestor of %s" % (row["id"], pin["rev"], pin["ancestor_of"]))
                checked += 1
        if checked == 0:
            self.skipTest("none of the upstream clones is under %s (set FFW_UPSTREAM_ROOT)" % sibling_root())
        missing = [r["id"] for r in self.ledger["upstreams"] if clone(r) is None]
        if missing:
            self.skipTest("clones not found, so their pins were not looked up: %s" % ", ".join(missing))

    def test_a_pin_that_does_not_exist_is_found_out(self):
        row = next(r for r in self.ledger["upstreams"] if r["id"] == "frankenlibc")
        repo = clone(row)
        if repo is None:
            self.skipTest("the frankenlibc clone is not under %s" % sibling_root())
        code, _ = git(repo, "rev-parse", "--verify", "0" * 40 + "^{commit}")
        self.assertNotEqual(code, 0)
        # and two real revisions in the wrong order are not an ancestry
        code, _ = git(repo, "merge-base", "--is-ancestor", row["pins"][0]["rev"], row["pins"][1]["rev"])
        self.assertNotEqual(code, 0)

    def test_the_reason_franken_kernel_is_not_consumed_is_still_true_at_the_pin(self):
        row = next(r for r in self.ledger["upstreams"] if r["id"] == "franken_kernel")
        repo = clone(row)
        if repo is None:
            self.skipTest("the asupersync clone is not under %s" % sibling_root())
        spec = row["upstream_bytes"]
        text = blob(repo, row["pins"][0]["rev"], spec["path"])
        self.assertIsNotNone(text, "%s is not at the pin" % spec["path"])
        self.assertIn(spec["contains"], text)
        self.assertNotIn(spec["absent"], text)
        # control: the check can fail
        self.assertNotIn(spec["contains"], text.replace(spec["contains"], "serde = { version = \"1.0\", default-features = false }"))


class TheGenericErrnoTableIsNotAMipsTable(unittest.TestCase):
    """P06-ORACLE-001: FrankenLibC's errno module at the pin, read from the git object."""

    @classmethod
    def setUpClass(cls):
        cls.ledger = load(LEDGER)
        cls.v = load(VECTORS)

    def upstream(self):
        row = next(r for r in self.ledger["upstreams"] if r["id"] == "frankenlibc")
        repo = clone(row)
        if repo is None:
            self.skipTest("the frankenlibc clone is not under %s" % sibling_root())
        text = blob(repo, row["pins"][0]["rev"], row["upstream_bytes"]["path"])
        self.assertIsNotNone(text, "the errno module is not at the pin")
        return upstream_errno(text)

    def problems(self, table, vectors):
        """Why `table` (an upstream errno table) can or cannot be used for the two ABIs: empty = generic numbering confirmed."""
        out, defined = [], 0
        for name, ppc in vectors["abi"]["powerpc32"]["errno"].items():
            if name not in table:
                continue
            defined += 1
            if table[name] != ppc:
                out.append("%s: upstream %d is not PowerPC's %d" % (name, table[name], ppc))
            if table[name] == vectors["abi"]["mips32"]["errno"][name]:
                out.append("%s: upstream %d equals MIPS's, so it would not show the difference" % (name, table[name]))
        if defined < 9:
            out.append("only %d of the ten network errnos are defined upstream" % defined)
        return out

    def test_every_network_errno_upstream_is_powerpcs_number_and_not_mipss(self):
        table = self.upstream()
        self.assertEqual(self.problems(table, self.v), [])
        # EMSGSIZE is not defined upstream at the pin; the generic table has nine of the ten
        self.assertNotIn("EMSGSIZE", table)

    def test_enosys_upstream_is_the_generic_38_and_mips_is_89(self):
        table = self.upstream()
        self.assertEqual(table["ENOSYS"], 38)
        self.assertEqual(table["EAGAIN"], 11)
        self.assertEqual(table["EINTR"], 4)
        # The one number MIPS moved that decides "the call does not exist" (E03 oracle): reading it with the generic table
        # would call a missing syscall an unknown error, and an unknown error a missing syscall.
        oracle = load_oracle()
        self.assertEqual(oracle.errno_number("powerpc", "ENOSYS"), table["ENOSYS"])
        self.assertEqual(oracle.errno_number("mips", "ENOSYS"), 89)
        self.assertNotEqual(table["ENOSYS"], oracle.errno_number("mips", "ENOSYS"))

    def test_the_oracle_check_is_sensitive(self):
        table = self.upstream()
        self.assertEqual(self.problems(table, self.v), [])
        # Plant: an upstream table that had been given MIPS's numbers no longer shows the difference, and one with a number
        # off by one is not the generic table.
        mips_like = dict(table, **{name: self.v["abi"]["mips32"]["errno"][name] for name in table if name in self.v["abi"]["mips32"]["errno"]})
        self.assertTrue(self.problems(mips_like, self.v))
        off = dict(table, EADDRINUSE=table["EADDRINUSE"] + 1)
        self.assertTrue(self.problems(off, self.v))
        self.assertTrue(self.problems({}, self.v))


class TheWorkspaceDoesNotDependOnWhatWasNotSelected(unittest.TestCase):
    """P06-ISO-001: reject accidental host-only or unselected upstream dependencies."""

    @classmethod
    def setUpClass(cls):
        cls.ledger = load(LEDGER)

    def lock_names(self, text):
        return set(re.findall(r'^name = "([^"]+)"$', text, re.M))

    def manifest_dependencies(self, crate):
        path = os.path.join(ROOT, "crates", crate, "Cargo.toml")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        names = set()
        section = None
        for line in text.splitlines():
            header = re.match(r"^\[([^\]]+)\]", line)
            if header:
                section = header.group(1)
                continue
            if section and section.endswith("dependencies"):
                name = re.match(r"^([A-Za-z0-9_.-]+)\s*[.=]", line)
                if name:
                    names.add(name.group(1).split(".")[0])
        return names

    def test_the_lock_names_none_of_the_crates_the_ledger_says_are_not_selected(self):
        with open(CARGO_LOCK, encoding="utf-8") as fh:
            names = self.lock_names(fh.read())
        self.assertTrue(names)
        for crate in self.ledger["crates_that_must_not_appear_in_the_lock"]:
            self.assertNotIn(crate, names, crate)

    def test_the_platform_crates_do_not_depend_directly_on_libc(self):
        rules = self.ledger["crates_that_must_not_be_direct_dependencies"]
        for crate, banned in rules.items():
            if crate.startswith("_"):
                continue
            deps = self.manifest_dependencies(crate)
            self.assertTrue(deps, crate)
            for name in banned:
                self.assertNotIn(name, deps, "%s depends on %s" % (crate, name))

    def test_the_isolation_check_is_sensitive(self):
        with open(CARGO_LOCK, encoding="utf-8") as fh:
            text = fh.read()
        planted = text + '\n[[package]]\nname = "asupersync"\nversion = "0.0.0"\n'
        self.assertIn("asupersync", self.lock_names(planted))
        self.assertNotIn("asupersync", self.lock_names(text))
        # and the manifest reader sees a dependency when there is one
        self.assertIn("franken-atomic", self.manifest_dependencies("franken-platform"))


if __name__ == "__main__":
    unittest.main()
