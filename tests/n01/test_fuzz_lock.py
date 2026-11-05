"""Does crates/franken-stream/fuzz/Cargo.lock still agree with the manifests it locks? (docs/contracts/n01.md section 11)

The central fuzz lines pass `--locked`, which refuses to build when the lock would need a change. The fuzz crate has its own
lock, and it contains `franken-stream` and the path crates under it (`franken-dsp`, `franken-board-profile`) as locked
packages, so a dependency added to any of those manifests, or to the fuzz crate's own, makes every `--locked` line fail
until the lock is regenerated. Nothing else in this repository looks at that lock (it is not a workspace member and P01 reads
manifests one level deep), so without this check the first sign is a wasted central lane.

`lock_problems` reads the lock and the manifests (tomllib and files only, no cargo) and lists every disagreement that makes
`--locked` refuse: the format version, a path package whose dependency list differs from its manifest, a dangling or
unreachable package, a registry package without a checksum or from another source, and a direct dependency whose locked
version does not satisfy the requirement in the fuzz manifest. The planted-defect tests change a copy of the real lock (or
one manifest) in exactly one way each; the untouched lock is the control that has none of them.

It does not prove the lock is the one cargo would write (only a cargo run does), and it does not check that the crates exist
on a worker.
"""

import copy
import re
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_frames as rf  # noqa: E402

FUZZ = rf.ROOT / "crates" / "franken-stream" / "fuzz"
LOCK = FUZZ / "Cargo.lock"
ROOT_PACKAGE = "franken-stream-fuzz"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LOCK_FORMAT = 4  # the workspace Cargo.lock's own format version


def load(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def dependency_names(manifest):
    """The names a path package's lock entry lists: normal, build and target-specific dependencies (dev-dependencies of a
    package that is not a member of the locking workspace are not locked), honouring `package = "real-name"`."""
    tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
    names = set()
    for table in tables:
        for key, spec in table.items():
            names.add(spec["package"] if isinstance(spec, dict) and "package" in spec else key)
    return names


def caret_accepts(requirement, version):
    """Cargo's default (caret) requirement for the plain `X`, `X.Y` and `X.Y.Z` forms; anything else fails loudly."""
    if not re.fullmatch(r"\d+(\.\d+){0,2}", requirement):
        raise AssertionError("requirement %r is not a plain caret requirement; extend caret_accepts" % requirement)
    want = [int(part) for part in requirement.split(".")]
    have = [int(part) for part in version.split(".")]
    pad = (want + [0, 0, 0])[:3], (have + [0, 0, 0])[:3]
    if pad[1] < pad[0]:
        return False
    if pad[0][0] > 0:
        return pad[1][0] == pad[0][0]
    if len(want) > 1:
        return pad[1][0] == 0 and pad[1][1] == pad[0][1]
    return pad[1][0] == 0


def lock_problems(lock, manifest_of, workspace_version):
    """Every reason `--locked` would refuse this lock. `lock` is the parsed Cargo.lock; `manifest_of(name)` returns the parsed
    manifest of a path package (None if there is none); `workspace_version` is the repository's `[workspace.package]`
    version that `version.workspace = true` crates inherit."""
    problems = []
    if lock.get("version") != LOCK_FORMAT:
        problems.append("lock format version %r, the workspace lock is %d" % (lock.get("version"), LOCK_FORMAT))
    packages = lock.get("package", [])
    by_name = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    def resolve(reference):
        parts = reference.split(" ")
        found = [p for p in by_name.get(parts[0], []) if len(parts) == 1 or p["version"] == parts[1]]
        return found[0] if len(found) == 1 else None

    roots = by_name.get(ROOT_PACKAGE, [])
    if len(roots) != 1:
        return problems + ["no single %s package in the lock (%d)" % (ROOT_PACKAGE, len(roots))]

    for package in packages:
        name, version = package["name"], package["version"]
        listed = package.get("dependencies", [])
        if "source" not in package:
            manifest = manifest_of(name)
            if manifest is None:
                problems.append("%s: a path package with no manifest here" % name)
                continue
            declared = dependency_names(manifest)
            locked = {reference.split(" ")[0] for reference in listed}
            if locked != declared:
                problems.append("%s: lock lists %s, manifest declares %s" % (name, sorted(locked), sorted(declared)))
            own = manifest.get("package", {}).get("version")
            own = workspace_version if isinstance(own, dict) and own.get("workspace") else own
            if own != version:
                problems.append("%s: lock version %s, manifest version %s" % (name, version, own))
        else:
            if package["source"] != REGISTRY:
                problems.append("%s %s: source %s is not the crates.io registry" % (name, version, package["source"]))
            if not re.fullmatch(r"[0-9a-f]{64}", package.get("checksum", "")):
                problems.append("%s %s: no 64-hex checksum" % (name, version))
        for reference in listed:
            if resolve(reference) is None:
                problems.append("%s %s: dangling dependency %r" % (name, version, reference))

    seen, stack = set(), [roots[0]]
    while stack:
        package = stack.pop()
        if (package["name"], package["version"]) in seen:
            continue
        seen.add((package["name"], package["version"]))
        for reference in package.get("dependencies", []):
            target = resolve(reference)
            if target is not None:
                stack.append(target)
    for package in packages:
        if (package["name"], package["version"]) not in seen:
            problems.append("%s %s: not reachable from %s (a stale entry; `--locked` would prune it)" % (package["name"], package["version"], ROOT_PACKAGE))

    fuzz_manifest = manifest_of(ROOT_PACKAGE) or {}
    for name, spec in fuzz_manifest.get("dependencies", {}).items():
        requirement = spec if isinstance(spec, str) else spec.get("version")
        if requirement is None:
            continue
        for package in by_name.get(name, []):
            if not caret_accepts(requirement, package["version"]):
                problems.append("%s %s does not satisfy the requirement %r of the fuzz manifest" % (name, package["version"], requirement))
    return problems


def real_manifest_of(name):
    path = FUZZ / "Cargo.toml" if name == ROOT_PACKAGE else rf.ROOT / "crates" / name / "Cargo.toml"
    return load(path) if path.is_file() else None


def real_workspace_version():
    return load(rf.ROOT / "Cargo.toml")["workspace"]["package"]["version"]


def real_problems(lock=None, manifest_of=real_manifest_of, workspace_version=None):
    return lock_problems(load(LOCK) if lock is None else lock, manifest_of, workspace_version or real_workspace_version())


def edited(lock, name, change):
    copy_of = copy.deepcopy(lock)
    hit = [p for p in copy_of["package"] if p["name"] == name]
    assert len(hit) == 1, (name, len(hit))
    change(hit[0], copy_of)
    return copy_of


def plants():
    """label -> (the lock or manifest change, a phrase the problem list must contain). Each changes exactly one thing."""
    real = load(LOCK)

    def drop_dependency(owner, dep):
        return lambda: (edited(real, owner, lambda p, _: p["dependencies"].remove(dep)), real_manifest_of, real_workspace_version())

    def with_manifest(owner, extra):
        def manifest_of(name):
            manifest = copy.deepcopy(real_manifest_of(name))
            if name == owner:
                manifest.setdefault("dependencies", {})[extra] = "1"
            return manifest
        return lambda: (real, manifest_of, real_workspace_version())

    def no_manifest(name):
        return lambda: (real, lambda n: None if n == name else real_manifest_of(n), real_workspace_version())

    def package_removed(name):
        def build():
            lock = copy.deepcopy(real)
            lock["package"] = [p for p in lock["package"] if p["name"] != name]
            return lock, real_manifest_of, real_workspace_version()
        return build

    def stale_package():
        lock = copy.deepcopy(real)
        lock["package"].append({"name": "left-over", "version": "1.0.0", "source": REGISTRY, "checksum": "0" * 64})
        return lock, real_manifest_of, real_workspace_version()

    return {
        "the fuzz crate's own dependency is missing from its lock entry": (drop_dependency(ROOT_PACKAGE, "hmac"), "franken-stream-fuzz: lock lists"),
        "franken-stream's dependency is missing from its lock entry": (drop_dependency("franken-stream", "thiserror"), "franken-stream: lock lists"),
        "franken-dsp gained a dependency its lock entry does not have": (with_manifest("franken-dsp", "rand"), "franken-dsp: lock lists"),
        "the fuzz manifest gained a dependency its lock entry does not have": (with_manifest(ROOT_PACKAGE, "rand"), "franken-stream-fuzz: lock lists"),
        "an older lock format": (lambda: (dict(copy.deepcopy(real), version=3), real_manifest_of, real_workspace_version()), "lock format version 3"),
        "a package a dependency needs is gone": (package_removed("shlex"), "dangling dependency"),
        "a package nothing needs is left behind": (stale_package, "not reachable"),
        "a registry package lost its checksum": (lambda: (edited(real, "libfuzzer-sys", lambda p, _: p.pop("checksum")), real_manifest_of, real_workspace_version()), "no 64-hex checksum"),
        "a package from another source": (lambda: (edited(real, "hmac", lambda p, _: p.update(source="git+https://example.invalid/hmac")), real_manifest_of, real_workspace_version()), "is not the crates.io registry"),
        "a locked version the fuzz manifest refuses": (lambda: (edited(real, "libfuzzer-sys", lambda p, _: p.update(version="0.5.0")), real_manifest_of, real_workspace_version()), "does not satisfy the requirement"),
        "the repository version moved": (lambda: (real, real_manifest_of, "0.2.0"), "lock version 0.1.0, manifest version 0.2.0"),
        "there is no fuzz package": (package_removed(ROOT_PACKAGE), "no single franken-stream-fuzz package"),
        "a path package has no manifest here": (no_manifest("franken-dsp"), "a path package with no manifest here"),
    }


class Anchors(unittest.TestCase):
    """The checker reads real files; make sure it is looking at the right ones before trusting a green result."""

    def test_the_lock_and_the_manifests_it_names_exist(self):
        self.assertTrue(LOCK.is_file(), LOCK)
        lock = load(LOCK)
        for name in ("franken-stream", "franken-dsp", "franken-board-profile", ROOT_PACKAGE):
            self.assertIsNotNone(real_manifest_of(name), name)
            self.assertEqual(len([p for p in lock["package"] if p["name"] == name]), 1, name)
        self.assertEqual(real_workspace_version(), "0.1.0")

    def test_the_lock_is_a_plain_text_file_that_git_will_not_ignore(self):
        text = LOCK.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# This file is automatically @generated by Cargo."))
        self.assertNotIn("/Users/", text)
        self.assertNotIn("file://", text)
        ignore = (FUZZ / ".gitignore").read_text(encoding="utf-8").split()
        self.assertNotIn("Cargo.lock", ignore)
        self.assertNotIn("*.lock", ignore)

    def test_the_fuzz_crate_depends_on_what_the_lock_says(self):
        self.assertEqual(sorted(dependency_names(real_manifest_of(ROOT_PACKAGE))), ["franken-stream", "hmac", "libfuzzer-sys", "serde_json", "sha2"])
        self.assertEqual(sorted(dependency_names(real_manifest_of("franken-stream"))), ["franken-dsp", "hmac", "serde", "serde_json", "sha2", "thiserror"])

    def test_dependency_names_cover_every_form_cargo_locks(self):
        manifest = tomllib.loads(
            '[dependencies]\na = "1"\nb.workspace = true\nc = { package = "real-c", version = "1" }\n'
            '[build-dependencies]\nd = "1"\n[dev-dependencies]\ne = "1"\n'
            "[target.'cfg(unix)'.dependencies]\nf = \"1\"\n[target.'cfg(unix)'.dev-dependencies]\ng = \"1\"\n")
        self.assertEqual(dependency_names(manifest), {"a", "b", "real-c", "d", "f"})
        self.assertEqual(dependency_names({}), set())

    def test_caret_requirements(self):
        for requirement, version, want in (("0.4", "0.4.13", True), ("0.4", "0.5.0", False), ("0.4", "0.3.9", False), ("0.13", "0.13.0", True),
                                           ("0.11", "0.11.1", True), ("0.11", "0.12.0", False), ("1.0", "1.0.154", True), ("1.0", "2.0.0", False),
                                           ("1.2", "1.1.9", False), ("1", "1.9.0", True), ("0", "0.9.0", True), ("0", "1.0.0", False), ("0.0.3", "0.0.3", True)):
            self.assertEqual(caret_accepts(requirement, version), want, (requirement, version))
        with self.assertRaises(AssertionError):
            caret_accepts(">=1.0", "1.0.0")


class Positive(unittest.TestCase):
    def test_the_committed_lock_agrees_with_every_manifest_it_locks(self):
        self.assertEqual(real_problems(), [])


class PlantedDefects(unittest.TestCase):
    def test_every_plant_is_found_for_its_own_reason_and_the_untouched_lock_is_clean(self):
        self.assertEqual(real_problems(), [], "the control must be clean before any plant means anything")
        self.assertGreaterEqual(len(plants()), 13)
        for label, (build, phrase) in plants().items():
            with self.subTest(label):
                lock, manifest_of, version = build()
                problems = lock_problems(lock, manifest_of, version)
                self.assertTrue(any(phrase in problem for problem in problems), (phrase, problems))


if __name__ == "__main__":
    unittest.main()
