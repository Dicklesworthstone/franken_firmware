"""Tests for `toolchain/src/prepare-tailscale-rs.py` (bead ffw-32a): the applier that prepares the pinned tailscale-rs tree, with a named patch applied only on a digest match.

Run: python3 -B -W error -m unittest tests/t01/test_prepare_tailscale_rs.py   (from the repository root; the `patch` tool must be on PATH)

The proof is on a SYNTHETIC mini tree and a synthetic pin in a temporary directory, so it needs no third-party source. Each refusal has a plant (one fault, made in a copy) and
a control (the same call with the fault removed passes). The real tailscale-rs tree is not committed; `RealTree` runs only when FFW_TAILSCALE_RS_SRC names it, and then holds the
repo's own pin and the committed manifest entry against it.
"""
import difflib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import t01lib as L  # noqa: E402

SCRIPT = os.path.join(REPO, "toolchain", "src", "prepare-tailscale-rs.py")
_spec = importlib.util.spec_from_file_location("prepare_tailscale_rs", SCRIPT)
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)

NEED_PATCH = unittest.skipUnless(shutil.which("patch"), "the patch tool is not on PATH")
COMMIT = "d" * 40

BASE_FILES = {
    "LICENSE": "BSD-3-Clause, the upstream text\n",
    "PATENTS": "the upstream patent grant\n",
    "Cargo.toml": "[package]\nname = \"mini\"\n",
    "src/lib.rs": "pub fn a() -> u32 {\n    1\n}\n\npub fn b() -> u32 {\n    2\n}\n",
    "src/deep/mod.rs": "-- a line that starts with two dashes\nfn keep() {}\n",
    "bin/tool.sh": "#!/bin/sh\necho tool\n",
}
EXEC = {"bin/tool.sh"}


def read_file(path, mode="rb"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as handle:
        return handle.read()


def write_file(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def diff(rel, old, new):
    """A plain unified diff of one file (old is None for a new file), labels a/ and b/."""
    old_lines = [] if old is None else old.splitlines(True)
    return "".join(difflib.unified_diff(old_lines, new.splitlines(True), "/dev/null" if old is None else "a/" + rel, "b/" + rel))


def write_tree(root, files, executable=EXEC):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.chmod(path, 0o755 if rel in executable else 0o644)


def identity(files):
    """The tree digest of `files` computed from the expected contents, not by running the tool (the same digest `tree_digest` gives)."""
    return L.tree_digest_of_entries({rel: L.sha256_bytes(text.encode("utf-8")) for rel, text in files.items()})


def snapshot(root):
    """Everything about a tree that a write could change: the root itself, every path, file bytes, permission bits and mtime."""
    info = os.lstat(root)
    out = [(".", None, info.st_mode, info.st_mtime_ns)]
    for directory, dirs, names in os.walk(root):
        dirs.sort()
        for name in sorted(names + dirs):
            path = os.path.join(directory, name)
            info = os.lstat(path)
            content = read_file(path) if os.path.isfile(path) else None
            out.append((os.path.relpath(path, root), content, info.st_mode, info.st_mtime_ns))
    return out


# the two synthetic patches, and what each makes of BASE_FILES
LIB_A = BASE_FILES["src/lib.rs"].replace("    1\n", "    10\n")
LIB_B = BASE_FILES["src/lib.rs"].replace("    2\n", "    20\n")
NEW_FILE = "#[test]\nfn it() {}\n"
EDIT = BASE_FILES["src/deep/mod.rs"].replace("-- a line that starts with two dashes\n", "// a line that used to start with two dashes\n")
PATCH_A_TEXT = diff("src/lib.rs", BASE_FILES["src/lib.rs"], LIB_A) + diff("tests/new.rs", None, NEW_FILE) + diff("src/deep/mod.rs", BASE_FILES["src/deep/mod.rs"], EDIT)
PATCH_B_TEXT = diff("src/lib.rs", BASE_FILES["src/lib.rs"], LIB_B) + diff("Cargo.toml", BASE_FILES["Cargo.toml"], BASE_FILES["Cargo.toml"] + "version = \"1\"\n")
RESULT_A = dict(BASE_FILES, **{"src/lib.rs": LIB_A, "tests/new.rs": NEW_FILE, "src/deep/mod.rs": EDIT})
RESULT_B = dict(BASE_FILES, **{"src/lib.rs": LIB_B, "Cargo.toml": BASE_FILES["Cargo.toml"] + "version = \"1\"\n"})
HEADER = {"consumer": "the candidate builds", "gate": "no patched source without a digest match", "defect": "a synthetic defect", "retirement": "when the pin moves", "note": "a patched tree is not the pin"}


class Base(unittest.TestCase):
    """A synthetic pinned tree, two patches, a manifest for them and a place to prepare into."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        self.pinned = os.path.join(self.root, "pinned")
        write_tree(self.pinned, BASE_FILES)
        self.pin = {"repo": "example/upstream", "tag": "v1", "commit": COMMIT, "license": "BSD-3-Clause", "tree_sha256": identity(BASE_FILES)}
        self.patches = os.path.join(self.root, "patches")
        os.mkdir(self.patches)
        self.work = os.path.join(self.root, "work")
        os.mkdir(self.work)
        self.write_patch("a.patch", PATCH_A_TEXT)
        self.write_patch("b.patch", PATCH_B_TEXT)
        self.manifest = {
            "schema": P.MANIFEST_SCHEMA, "header": dict(HEADER), "upstream": {"repo": "example/upstream", "tag": "v1", "commit": COMMIT, "license": "BSD-3-Clause"},
            "patches": [self.entry("a", "a.patch", PATCH_A_TEXT, RESULT_A, ["src/deep/mod.rs", "src/lib.rs", "tests/new.rs"]),
                        self.entry("b", "b.patch", PATCH_B_TEXT, RESULT_B, ["Cargo.toml", "src/lib.rs"])]}
        self.save_manifest()

    def write_patch(self, name, text):
        with open(os.path.join(self.patches, name), "w", encoding="utf-8", newline="") as handle:
            handle.write(text)

    def entry(self, name, file, text, result, touches):
        return {"name": name, "file": file, "sha256": L.sha256_bytes(text.encode("utf-8")), "base_tree_sha256": self.pin["tree_sha256"], "result_tree_sha256": identity(result),
                "touches": touches}

    def save_manifest(self):
        self.manifest_path = os.path.join(self.patches, "manifest.json")
        with open(self.manifest_path, "w", encoding="utf-8") as handle:
            json.dump(self.manifest, handle, indent=1)

    def prepare(self, patch, out=None, receipt=None, pinned=None):
        out = out or os.path.join(self.work, "out")
        return P.prepare(pinned or self.pinned, patch, out, pin=self.pin, manifest_path=self.manifest_path, patch_dir=self.patches, receipt_path=receipt)

    def refused(self, patch, phrase, out=None, **kwargs):
        """The call is refused with `phrase`, and nothing is left behind: no output directory and no scratch directory beside it."""
        out = out or os.path.join(self.work, "out")
        before = sorted(os.listdir(self.work))
        with self.assertRaises(P.Refused) as caught:
            self.prepare(patch, out=out, **kwargs)
        self.assertIn(phrase, str(caught.exception))
        self.assertFalse(os.path.lexists(out))
        self.assertEqual(sorted(os.listdir(self.work)), before)

    def tree_files(self, root):
        found = {}
        for directory, _, names in os.walk(root):
            for name in names:
                path = os.path.join(directory, name)
                found[os.path.relpath(path, root).replace(os.sep, "/")] = read_file(path, "r")
        return found


@NEED_PATCH
class Applier(Base):
    def test_a_named_patch_is_applied_into_a_fresh_tree_and_the_pinned_tree_is_untouched(self):
        before = snapshot(self.pinned)
        receipt = self.prepare("a")
        out = os.path.join(self.work, "out")
        self.assertEqual(self.tree_files(out), RESULT_A)
        self.assertEqual(L.tree_digest(out), identity(RESULT_A))
        self.assertEqual(receipt["result_tree_sha256"], identity(RESULT_A))
        self.assertEqual(snapshot(self.pinned), before)                                  # byte for byte, mode for mode, mtime for mtime
        self.assertEqual(L.tree_digest(self.pinned), self.pin["tree_sha256"])
        self.assertTrue(os.access(os.path.join(out, "bin", "tool.sh"), os.X_OK))          # permission bits are carried over
        self.assertEqual(sorted(os.listdir(self.work)), ["out"])                          # no scratch directory is left

    def test_the_source_identity_changes_with_the_patch(self):
        none = self.prepare("none", out=os.path.join(self.work, "none"))
        a = self.prepare("a", out=os.path.join(self.work, "a"))
        b = self.prepare("b", out=os.path.join(self.work, "b"))
        self.assertEqual(none["result_tree_sha256"], self.pin["tree_sha256"])
        self.assertEqual(len({none["result_tree_sha256"], a["result_tree_sha256"], b["result_tree_sha256"]}), 3)
        self.assertEqual((a["patch"]["name"], b["patch"]["name"], none["patch"]), ("a", "b", None))
        self.assertNotEqual(a["patch"]["sha256"], b["patch"]["sha256"])
        for receipt in (none, a, b):
            self.assertEqual(receipt["base_tree_sha256"], self.pin["tree_sha256"])
            self.assertIs(receipt["applied_in_place"], False)

    def test_none_copies_the_pinned_tree_unchanged_and_its_identity_is_the_pin(self):
        before = snapshot(self.pinned)
        receipt = self.prepare("none")
        out = os.path.join(self.work, "out")
        self.assertEqual(self.tree_files(out), BASE_FILES)
        self.assertEqual(receipt["result_tree_sha256"], self.pin["tree_sha256"])
        self.assertEqual(L.tree_digest(out), L.tree_digest(self.pinned))
        self.assertIsNone(receipt["patch"])
        self.assertEqual(snapshot(self.pinned), before)

    def test_a_changed_patch_byte_is_refused_by_the_manifests_digest_and_the_restored_byte_passes(self):
        path = os.path.join(self.patches, "a.patch")
        good = read_file(path)
        bad = good.replace(b"    10\n", b"    11\n")
        self.assertNotEqual(bad, good)
        write_file(path, bad)
        self.refused("a", "patch file's sha256")
        write_file(path, good)                                                      # control
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_changed_manifest_digest_is_refused_and_the_restored_one_passes(self):
        good = self.manifest["patches"][0]["sha256"]
        self.manifest["patches"][0]["sha256"] = ("0" if good[0] != "0" else "1") + good[1:]
        self.save_manifest()
        self.refused("a", "patch file's sha256")
        self.manifest["patches"][0]["sha256"] = good                                      # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_tree_that_is_not_the_pin_is_refused_and_the_pinned_one_passes(self):
        other = os.path.join(self.root, "other")
        write_tree(other, dict(BASE_FILES, **{"src/lib.rs": BASE_FILES["src/lib.rs"] + "// one more line\n"}))
        self.refused("a", "not the pinned tree", pinned=other)
        self.refused("none", "not the pinned tree", pinned=other)
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))      # control
        missing = os.path.join(self.root, "absent")
        with self.assertRaises(L.SourceRefused):
            self.prepare("a", out=os.path.join(self.work, "out2"), pinned=missing)

    def test_a_tree_with_a_symlink_is_refused(self):
        linked = os.path.join(self.root, "linked")
        shutil.copytree(self.pinned, linked)
        os.symlink("LICENSE", os.path.join(linked, "LICENSE.link"))
        with self.assertRaises(L.SourceRefused):
            self.prepare("a", pinned=linked)
        self.assertFalse(os.path.lexists(os.path.join(self.work, "out")))
        shutil.rmtree(linked)
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))      # control

    def test_a_result_digest_that_is_not_the_manifests_is_refused(self):
        good = self.manifest["patches"][0]["result_tree_sha256"]
        self.manifest["patches"][0]["result_tree_sha256"] = ("0" if good[0] != "0" else "1") + good[1:]
        self.save_manifest()
        self.refused("a", "prepared tree's digest")
        self.manifest["patches"][0]["result_tree_sha256"] = good                          # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_patch_that_applies_but_makes_another_tree_is_refused_by_the_result_digest(self):
        # the file and the manifest's sha256 agree and the touched paths are the same, so only the identity of the result can tell
        other = PATCH_A_TEXT.replace("    10\n", "    11\n")
        self.assertNotEqual(other, PATCH_A_TEXT)
        self.write_patch("a.patch", other)
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(other.encode("utf-8"))
        self.save_manifest()
        self.refused("a", "prepared tree's digest")
        self.write_patch("a.patch", PATCH_A_TEXT)                                         # control
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(PATCH_A_TEXT.encode("utf-8"))
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_an_entry_made_for_another_base_tree_is_refused(self):
        good = self.manifest["patches"][0]["base_tree_sha256"]
        self.manifest["patches"][0]["base_tree_sha256"] = ("0" if good[0] != "0" else "1") + good[1:]
        self.save_manifest()
        self.refused("a", "another base tree")
        self.manifest["patches"][0]["base_tree_sha256"] = good                            # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_manifest_for_another_upstream_commit_is_refused(self):
        self.manifest["upstream"]["commit"] = "e" * 40
        self.save_manifest()
        self.refused("a", "another upstream commit")
        self.refused("none", "another upstream commit")
        self.manifest["upstream"]["commit"] = COMMIT                                      # control
        self.save_manifest()
        self.assertEqual(self.prepare("none")["result_tree_sha256"], self.pin["tree_sha256"])

    def test_a_patch_that_writes_paths_the_manifest_does_not_list_is_refused(self):
        self.manifest["patches"][0]["touches"] = ["src/deep/mod.rs", "src/lib.rs"]                # plant: the patch writes a path the manifest does not list
        self.save_manifest()
        self.refused("a", "paths other than the manifest lists")
        # plant, the other direction: the manifest lists a path the patch never writes. The list is still sorted, unique and safe, so only the check
        # that the two sets are equal can refuse it (a subset check lets it through)
        self.manifest["patches"][0]["touches"] = ["src/deep/mod.rs", "src/lib.rs", "src/never.rs", "tests/new.rs"]
        self.save_manifest()
        self.refused("a", "paths other than the manifest lists")
        self.manifest["patches"][0]["touches"] = ["src/deep/mod.rs", "src/lib.rs", "tests/new.rs"]   # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_patch_that_touches_an_upstream_licence_file_is_refused_even_when_the_manifest_lists_it(self):
        text = PATCH_A_TEXT + diff("LICENSE", BASE_FILES["LICENSE"], BASE_FILES["LICENSE"] + "an added line\n")
        self.write_patch("a.patch", text)
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(text.encode("utf-8"))
        self.manifest["patches"][0]["touches"] = ["LICENSE", "src/deep/mod.rs", "src/lib.rs", "tests/new.rs"]
        self.save_manifest()
        self.refused("a", "licence file")
        text = PATCH_A_TEXT + diff("PATENTS", BASE_FILES["PATENTS"], "different\n")
        self.write_patch("a.patch", text)
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(text.encode("utf-8"))
        self.manifest["patches"][0]["touches"] = ["PATENTS", "src/deep/mod.rs", "src/lib.rs", "tests/new.rs"]
        self.save_manifest()
        self.refused("a", "licence file")
        self.write_patch("a.patch", PATCH_A_TEXT)                                         # control
        self.manifest["patches"][0] = self.entry("a", "a.patch", PATCH_A_TEXT, RESULT_A, ["src/deep/mod.rs", "src/lib.rs", "tests/new.rs"])
        self.save_manifest()
        self.assertEqual(self.prepare("a")["license_files"], {"LICENSE": L.sha256_bytes(BASE_FILES["LICENSE"].encode()), "PATENTS": L.sha256_bytes(BASE_FILES["PATENTS"].encode())})

    def test_a_patch_that_does_not_apply_cleanly_is_refused_and_leaves_nothing(self):
        # the last context line of the first hunk no longer matches: `patch --fuzz=0` refuses it (with fuzz allowed it would apply, and the tool must not)
        text = PATCH_A_TEXT.replace(" pub fn b() -> u32 {\n", " pub fn y() -> u32 {\n")
        self.assertNotEqual(text, PATCH_A_TEXT)
        self.write_patch("a.patch", text)
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(text.encode("utf-8"))
        self.save_manifest()
        self.refused("a", "does not apply cleanly")
        self.write_patch("a.patch", PATCH_A_TEXT)                                         # control
        self.manifest["patches"][0]["sha256"] = L.sha256_bytes(PATCH_A_TEXT.encode("utf-8"))
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_an_unknown_or_reserved_patch_name_is_refused(self):
        self.refused("nope", "no patch named")
        self.manifest["patches"][0]["name"] = "none"
        self.save_manifest()
        with self.assertRaises(P.Refused):
            self.prepare("none")                                                          # `none` can never name a patch
        self.manifest["patches"][0]["name"] = "a"                                         # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_the_output_path_must_be_fresh_and_outside_the_pinned_tree(self):
        existing = os.path.join(self.work, "taken")
        os.mkdir(existing)
        self.assertRaises(P.Refused, self.prepare, "a", existing)
        self.assertEqual(os.listdir(existing), [])
        for out, phrase in ((os.path.join(self.pinned, "inside"), "lies inside it"), (self.pinned, "already exists"), (self.root, "already exists")):
            before = snapshot(self.pinned)                                                 # including the pinned directory's own mtime: nothing may be created in it
            with self.assertRaises(P.Refused) as caught:
                self.prepare("a", out=out)
            self.assertIn(phrase, str(caught.exception))
            self.assertEqual(snapshot(self.pinned), before)
            self.assertFalse(os.path.lexists(os.path.join(self.pinned, "inside")))
        with self.assertRaises(P.Refused):
            self.prepare("a", out=os.path.join(self.root, "no-such-parent", "out"))
        self.assertEqual(self.prepare("a", out=os.path.join(self.work, "fresh"))["result_tree_sha256"], identity(RESULT_A))   # control

    def test_the_receipt_is_written_once_and_names_no_host_path(self):
        receipt_path = os.path.join(self.work, "receipt.json")
        receipt = self.prepare("a", receipt=receipt_path)
        written = read_file(receipt_path, "r")
        self.assertEqual(json.loads(written), receipt)
        self.assertEqual(receipt["schema"], P.RECEIPT_SCHEMA)
        self.assertEqual(receipt["upstream"], {"repo": "example/upstream", "tag": "v1", "commit": COMMIT, "license": "BSD-3-Clause"})
        self.assertEqual(receipt["manifest_sha256"], L.sha256_file(self.manifest_path))
        self.assertEqual(receipt["tool"]["sha256"], L.sha256_file(SCRIPT))
        self.assertEqual(receipt["result_files"], len(RESULT_A))
        self.assertIn("byte for byte", receipt["license_note"])
        for needle in (self.root, self.tmp.name, os.path.expanduser("~"), "/private/", "/tmp/", "/Users/", "/home/"):
            self.assertNotIn(needle, written)
        before = read_file(receipt_path)
        with self.assertRaises(P.Refused):
            self.prepare("b", out=os.path.join(self.work, "second"), receipt=receipt_path)     # never overwritten
        self.assertEqual(read_file(receipt_path), before)
        self.assertFalse(os.path.lexists(os.path.join(self.work, "second")))
        self.assertEqual(self.prepare("b", out=os.path.join(self.work, "second"), receipt=os.path.join(self.work, "receipt2.json"))["patch"]["name"], "b")   # control

    def after_apply(self, hook):
        """Run `hook(tree)` right after the real patch step, as a fault that happens during preparation (a race, a bad patch tool) would."""
        real = P._apply

        def wrapped(tree, patch_file):
            real(tree, patch_file)
            hook(tree)

        return mock.patch.object(P, "_apply", wrapped)

    def test_an_upstream_licence_file_that_changed_by_any_means_is_refused_even_when_every_other_digest_agrees(self):
        changed = dict(RESULT_A, LICENSE=BASE_FILES["LICENSE"] + "an added line\n")
        good = self.manifest["patches"][0]["result_tree_sha256"]
        self.manifest["patches"][0]["result_tree_sha256"] = identity(changed)             # the manifest even expects the changed tree
        self.save_manifest()

        def alter(tree):
            with open(os.path.join(tree, "LICENSE"), "a", encoding="utf-8") as handle:
                handle.write("an added line\n")

        with self.after_apply(alter):
            self.refused("a", "licence file differs")
        self.manifest["patches"][0]["result_tree_sha256"] = good                          # control
        self.save_manifest()
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_pinned_tree_that_changes_while_it_is_being_prepared_is_refused(self):
        def alter(_tree):
            with open(os.path.join(self.pinned, "Cargo.toml"), "a", encoding="utf-8") as handle:
                handle.write("# changed during the run\n")

        with self.after_apply(alter):
            self.refused("a", "changed while it was being prepared")
        write_tree(self.pinned, {"Cargo.toml": BASE_FILES["Cargo.toml"]})                 # control: put it back, and the same call passes
        self.assertEqual(self.prepare("a")["result_tree_sha256"], identity(RESULT_A))

    def test_a_receipt_that_appears_during_preparation_is_not_overwritten(self):
        receipt_path = os.path.join(self.work, "receipt.json")

        def appear(_tree):
            write_file(receipt_path, b"someone else's receipt\n")

        with self.after_apply(appear):
            with self.assertRaises(P.Refused) as caught:
                self.prepare("a", receipt=receipt_path)
        self.assertIn("receipt could not be written", str(caught.exception))
        self.assertEqual(read_file(receipt_path), b"someone else's receipt\n")


class Reading(unittest.TestCase):
    """`patch_paths`: what the tool reads out of a patch before the patch tool is given it."""

    def test_a_plain_unified_diff_gives_exactly_the_paths_it_writes(self):
        self.assertEqual(P.patch_paths(PATCH_A_TEXT.encode()), {"src/lib.rs", "tests/new.rs", "src/deep/mod.rs"})
        self.assertEqual(P.patch_paths(diff("x/gone.rs", "a\n", "").encode()), {"x/gone.rs"})

    def test_a_removed_line_that_starts_with_two_dashes_is_not_read_as_a_file_header(self):
        data = diff("src/deep/mod.rs", BASE_FILES["src/deep/mod.rs"], EDIT)
        self.assertIn("--- a line that starts with two dashes", data)
        self.assertEqual(P.patch_paths(data.encode()), {"src/deep/mod.rs"})

    def test_a_no_newline_marker_is_part_of_its_hunk(self):
        data = "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
        self.assertEqual(P.patch_paths(data.encode()), {"f"})

    def test_every_other_form_is_refused(self):
        good = diff("f.rs", "a\n", "b\n")
        self.assertEqual(P.patch_paths(good.encode()), {"f.rs"})                          # control
        cases = {
            "git header": "diff --git a/f.rs b/f.rs\n" + good,
            "index line": "index 1..2 100644\n" + good,
            "rename": "--- a/old.rs\n+++ b/new.rs\n@@ -1 +1 @@\n-a\n+b\n",
            "no hunk": "--- a/f.rs\n+++ b/f.rs\n",
            "text after a hunk": good + "trailing words\n",
            "truncated hunk": "--- a/f.rs\n+++ b/f.rs\n@@ -1,3 +1,3 @@\n a\n-b\n",
            "too long a hunk": "--- a/f.rs\n+++ b/f.rs\n@@ -1 +1 @@\n-a\n+b\n+c\n",
            "bad hunk header": "--- a/f.rs\n+++ b/f.rs\n@@ nonsense @@\n-a\n+b\n",
            "no prefix": "--- f.rs\n+++ f.rs\n@@ -1 +1 @@\n-a\n+b\n",
            "dot dot": "--- a/../f.rs\n+++ b/../f.rs\n@@ -1 +1 @@\n-a\n+b\n",
            "dot component": "--- a/./f.rs\n+++ b/./f.rs\n@@ -1 +1 @@\n-a\n+b\n",
            "absolute": "--- a//etc/f.rs\n+++ b//etc/f.rs\n@@ -1 +1 @@\n-a\n+b\n",
            "under .git": "--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n",
            "empty": "",
            "both null": "--- /dev/null\n+++ /dev/null\n@@ -0,0 +0,0 @@\n",
        }
        for label, text in cases.items():
            with self.assertRaises(P.Refused, msg=label):
                P.patch_paths(text.encode())
        with self.assertRaises(P.Refused):
            P.patch_paths(b"\xff\xfe")


class Manifest(unittest.TestCase):
    def good(self):
        return {"schema": P.MANIFEST_SCHEMA, "header": dict(HEADER), "upstream": {"commit": COMMIT},
                "patches": [{"name": "a", "file": "a.patch", "sha256": "1" * 64, "base_tree_sha256": "2" * 64, "result_tree_sha256": "3" * 64, "touches": ["a.rs", "b.rs"]}]}

    def test_each_malformed_field_is_reported_and_the_good_document_is_clean(self):
        self.assertEqual(P.manifest_problems(self.good()), [])
        plants = [
            lambda d: d.update(schema="other"),
            lambda d: d["header"].pop("gate"),
            lambda d: d["header"].update(retirement="  "),
            lambda d: d["upstream"].update(commit="abc"),
            lambda d: d.update(patches={}),
            lambda d: d["patches"][0].update(name="Has Space"),
            lambda d: d["patches"][0].update(name="none"),
            lambda d: d["patches"][0].update(file="../a.patch"),
            lambda d: d["patches"][0].update(file="a.diff"),
            lambda d: d["patches"][0].update(sha256="xyz"),
            lambda d: d["patches"][0].update(result_tree_sha256="3" * 63),
            lambda d: d["patches"][0].update(touches=["b.rs", "a.rs"]),
            lambda d: d["patches"][0].update(touches=["../b.rs"]),
            lambda d: d["patches"][0].update(touches=[]),
            lambda d: d["patches"].append(dict(d["patches"][0])),
        ]
        for number, plant in enumerate(plants):
            doc = self.good()
            plant(doc)
            self.assertTrue(P.manifest_problems(doc), "plant %d was not reported" % number)
        with self.assertRaises(P.Refused):
            P.parse_manifest(b"{not json")


class Committed(unittest.TestCase):
    """The repo's own manifest and the script's stated limits."""

    def test_the_committed_manifest_is_valid_and_each_entry_is_what_its_file_says(self):
        manifest = P.load_manifest()
        pin = P.load_pin()
        self.assertEqual(manifest["upstream"]["commit"], pin["commit"])
        self.assertEqual(manifest["upstream"]["license"], pin["license"])
        for key in P.HEADER_KEYS:
            self.assertTrue(manifest["header"][key].strip(), key)
        for entry in manifest["patches"]:
            data = read_file(os.path.join(P.PATCH_DIR, entry["file"]))
            self.assertEqual(L.sha256_bytes(data), entry["sha256"], entry["name"])
            self.assertEqual(entry["base_tree_sha256"], pin["tree_sha256"], entry["name"])
            self.assertEqual(P.patch_paths(data), set(entry["touches"]), entry["name"])
            self.assertNotEqual(entry["result_tree_sha256"], pin["tree_sha256"], entry["name"])      # a patched tree is not the pin
        files = {name for name in os.listdir(P.PATCH_DIR) if name.endswith(".patch")}
        self.assertEqual(files, {entry["file"] for entry in manifest["patches"]})                   # no patch file without an entry
        text = read_file(P.MANIFEST, "r")
        self.assertEqual(re.findall(r"/Users/|/home/|/private/|/tmp/", text), [])

    def test_the_pin_comes_from_the_profile_and_is_the_pinned_tree_the_probes_check(self):
        pin = P.load_pin()
        profile = L.load_json(L.PROFILE)
        self.assertEqual(pin["tree_sha256"], profile["derived_facts"]["tailscale-rs-0.6.1"]["tree_sha256"])
        self.assertEqual(pin["commit"], "d34658bbb2eb4593ae6df959aa93e9ee1e0457c6")
        for bad in (lambda d: d["derived_facts"].pop("tailscale-rs-0.6.1"), lambda d: d["candidates"]["tailscale-rs-0.6.1"]["pin"].update(commit="x")):
            doc = json.loads(json.dumps(profile))
            bad(doc)
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "profile.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(doc, handle)
                with self.assertRaises(P.Refused):
                    P.load_pin(path)

    def test_the_stated_limits_are_in_the_script_and_the_manifest_and_the_hashing_is_not_copied(self):
        doc = " ".join(P.__doc__.split())
        manifest = " ".join(json.dumps(P.load_manifest()["header"]).split())
        for needle in ("not the pinned tree", "judge_build_record", "separate decision", "never patched in place", "kept byte for byte"):
            self.assertIn(needle, doc)
        for needle in ("not the pinned tree", "judge_build_record", "separate decision"):
            self.assertIn(needle, manifest)
        source = read_file(SCRIPT, "r")
        self.assertNotIn("hashlib", source)                                                # the digest is t01lib's
        self.assertIn("L.tree_digest", source)
        self.assertEqual(re.findall(r"/Users/|/home/", source), [])


@NEED_PATCH
class CommandLine(Base):
    def run_cli(self, *extra, patch="none", out=None):
        profile = os.path.join(self.root, "profile.json")
        with open(profile, "w", encoding="utf-8") as handle:
            json.dump({"candidates": {"tailscale-rs-0.6.1": {"pin": {k: self.pin[k] for k in ("repo", "tag", "commit", "license")}}},
                       "derived_facts": {"tailscale-rs-0.6.1": {"tree_sha256": self.pin["tree_sha256"]}}}, handle)
        args = [sys.executable, "-B", SCRIPT, "--pinned", self.pinned, "--patch", patch, "--out", out or os.path.join(self.work, "out"), "--manifest", self.manifest_path,
                "--profile", profile, *extra]
        return subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)

    def test_exit_codes_and_one_line_outputs(self):
        done = self.run_cli(patch="a", out=os.path.join(self.work, "ok"))
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertRegex(done.stdout, r"^PREPARED tailscale-rs commit=dddddddd patch=a tree=[0-9a-f]{12} files=7\n$")
        self.assertEqual(L.tree_digest(os.path.join(self.work, "ok")), identity(RESULT_A))
        done = self.run_cli(patch="a", out=os.path.join(self.work, "ok"))                  # the output exists now: refused, nothing printed to stdout
        self.assertEqual((done.returncode, done.stdout), (1, ""))
        self.assertTrue(done.stderr.startswith("REFUSED: "))
        self.assertNotIn("Traceback", done.stderr)
        for needle in (self.root, "/private/"):
            self.assertNotIn(needle, done.stderr)
        done = subprocess.run([sys.executable, "-B", SCRIPT], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(done.returncode, 2)                                               # usage

    def test_a_digest_mismatch_through_the_command_line_is_exit_1_and_leaves_no_output(self):
        path = os.path.join(self.patches, "a.patch")
        good = read_file(path)
        write_file(path, good + b"\n")
        done = self.run_cli(patch="a")
        self.assertEqual(done.returncode, 1)
        self.assertIn("sha256", done.stderr)
        self.assertEqual(sorted(os.listdir(self.work)), [])
        write_file(path, good)                                                       # control
        self.assertEqual(self.run_cli(patch="a").returncode, 0)


@NEED_PATCH
@unittest.skipUnless(os.environ.get("FFW_TAILSCALE_RS_SRC"), "set FFW_TAILSCALE_RS_SRC to the pinned tailscale-rs tree to run this")
class RealTree(unittest.TestCase):
    def test_none_equals_the_pin_and_each_committed_entry_reproduces_its_digest(self):
        src = os.environ["FFW_TAILSCALE_RS_SRC"]
        pin = P.load_pin()
        manifest = P.load_manifest()
        before = L.tree_digest(src)
        self.assertEqual(before, pin["tree_sha256"])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(P.prepare(src, "none", os.path.join(tmp, "none"), pin=pin)["result_tree_sha256"], pin["tree_sha256"])
            for entry in manifest["patches"]:
                receipt = P.prepare(src, entry["name"], os.path.join(tmp, entry["name"]), pin=pin)
                self.assertEqual(receipt["result_tree_sha256"], entry["result_tree_sha256"], entry["name"])
                self.assertEqual(L.tree_digest(os.path.join(tmp, entry["name"])), entry["result_tree_sha256"])
        self.assertEqual(L.tree_digest(src), before)


if __name__ == "__main__":
    unittest.main()
