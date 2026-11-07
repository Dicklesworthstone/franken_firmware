"""E06 against REAL cargo output.

Hand-written metadata proves the analyzer reads the schema the author imagined.  These tests build a real
path-only workspace on disk (no registry, no network), run the real ``cargo generate-lockfile`` and
``cargo metadata --locked --offline`` (resolver reads, no compilation), and check the same contaminations are
reported from what cargo actually emits.  The last class audits this repository's own workspace.
Skipped when cargo is not on PATH.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AU = load("ffw_e06_audit_live", os.path.join(ROOT, "scripts", "e06", "audit.py"))
HAVE_CARGO = shutil.which("cargo") is not None
MIPS = "mips-unknown-linux-musl"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def export_head():
    """A clean copy of the COMMITTED tree (git archive HEAD).  The audit of "this repository" must not depend on what
    another agent is editing in the shared worktree right now: a half-made manifest edit makes `--locked` fail there,
    and that is the worktree audit's finding to report, not a reason for the tool's own tests to flip.  Returns a
    TemporaryDirectory, or None when git or a repository is not available (an environment fact, so the class skips)."""
    if shutil.which("git") is None:
        return None
    if subprocess.run(["git", "-C", ROOT, "rev-parse", "--git-dir"], capture_output=True, timeout=60).returncode != 0:
        return None
    proc = subprocess.run(["git", "-C", ROOT, "archive", "--format=tar", "HEAD"], capture_output=True, timeout=180, check=True)
    tmp = tempfile.TemporaryDirectory()
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in member.name.split("/"):
                raise ValueError("refusing archive member %r" % member.name)
        try:
            tar.extractall(tmp.name, filter="data")
        except TypeError:                                   # Python < 3.12 has no extraction filters
            tar.extractall(tmp.name)
    return tmp


def package(name, version, deps="", extra="", src="pub fn f() {}\n", license='license = "MIT"\n', lints=False):
    return ('[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n%s%s\n%s[dependencies]\n%s'
            % (name, version, license, extra, "[lints]\nworkspace = true\n\n" if lints else "", deps)), src


def build_live_workspace(base):
    """app -> mid -> leaf(unsafe); app -> nat(links); app -> dupe 1.0.0 (member) and dupe 2.0.0 (outside the
    workspace); app -> nolic(no license); app -> ext-path (outside the workspace).  All path dependencies."""
    ws = os.path.join(base, "ws")
    write(os.path.join(ws, "Cargo.toml"),
          '[workspace]\nmembers = ["app"]\nresolver = "2"\n[workspace.lints.rust]\nunsafe_code = "forbid"\n')
    specs = {
        "app": package("app", "0.1.0", deps=('mid = { path = "../mid" }\nnat = { path = "../nat" }\n'
                                             'dupa = { path = "../dupa", package = "dupe" }\n'
                                             'dupb = { path = "../../dupb", package = "dupe" }\n'
                                             'nolic = { path = "../nolic" }\n'
                                             'ext = { path = "../../ext", package = "ext-path" }\n'),
                       src="#![forbid(unsafe_code)]\npub fn run() {}\n", lints=True),
        "mid": package("mid", "0.1.0", deps='leaf = { path = "../leaf" }\n', src="#![forbid(unsafe_code)]\npub fn m() {}\n",
                       lints=True),
        "leaf": package("leaf", "0.1.0", src="pub fn f() { unsafe { core::hint::unreachable_unchecked() } }\n"),
        "nat": package("nat", "0.1.0", extra='links = "natfoo"\nbuild = "build.rs"\n'),
        "dupa": package("dupe", "1.0.0"),
        "nolic": package("nolic", "0.1.0", license=""),
    }
    for name, (manifest, src) in specs.items():
        write(os.path.join(ws, name, "Cargo.toml"), manifest)
        write(os.path.join(ws, name, "src", "lib.rs"), src)
    write(os.path.join(ws, "nat", "build.rs"), 'fn main() { println!("cargo:rustc-link-lib=static=natfoo"); }\n')
    for outside, (name, version) in {"dupb": ("dupe", "2.0.0"), "ext": ("ext-path", "0.1.0")}.items():
        manifest, src = package(name, version)
        write(os.path.join(base, outside, "Cargo.toml"), manifest)
        write(os.path.join(base, outside, "src", "lib.rs"), src)
    write(os.path.join(ws, "LICENSE"), "fixture\n")
    manifest = os.path.join(ws, "Cargo.toml")
    subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", manifest],
                   capture_output=True, text=True, check=True, timeout=120)
    return ws, manifest


def audit_live(manifest, targets=("host", MIPS)):
    platforms = []
    host = AU.host_triple()
    for key, triple in (("host", host), ("mips", MIPS)):
        outcome, meta, detail = AU.run_cargo_metadata(manifest, triple)
        platforms.append(AU.PlatformInput(key, triple, outcome, detail, meta))
    root = next(p.metadata["workspace_root"] for p in platforms if p.metadata)
    with open(os.path.join(root, "Cargo.lock")) as fh:
        return AU.analyze(platforms, fh.read(), root), platforms


def find(report, kind, package=None):
    return [f for f in report["findings"] if f["kind"] == kind and (package is None or f["package"] == package)]


LEAF = "franken-platform-linux"
LEAF_UNSAFE_FILES = ["src/sys.rs"]                       # the leaf's one `#[allow(unsafe_code)]` module


def workspace_unsafe_problems(report):
    """What the audit's unsafe policy objects to among the workspace crates, as sorted strings; [] is a pass.  The policy: only
    the crates in AU.DEFAULT_UNSAFE_ALLOWED may hold an unsafe token (besides the documented test-only franken-alloc-probe, which
    its own test covers); the one allowed crate is the Linux leaf and its unsafe stays in src/sys.rs; and the audit raises
    neither `workspace-unsafe-linked` nor `workspace-unsafe-undeclared` for any crate.  The live test asserts [] on HEAD; each
    planted case asserts exactly the one problem it plants, so a policy that stops objecting fails a named test."""
    problems = set()
    for p in report["packages"]:
        if p["source_kind"] != "workspace" or not p["unsafe"]["tokens"] or p["name"] == "franken-alloc-probe":
            continue
        if p["name"] not in AU.DEFAULT_UNSAFE_ALLOWED:
            problems.add("unsafe in %s" % p["name"])
        elif p["name"] == LEAF and sorted(p["unsafe"]["files"]) != LEAF_UNSAFE_FILES:
            problems.add("unsafe outside src/sys.rs in %s: %s" % (p["name"], ", ".join(sorted(p["unsafe"]["files"]))))
    for kind in ("workspace-unsafe-linked", "workspace-unsafe-undeclared"):
        for f in find(report, kind):
            problems.add("%s %s" % (kind, f["package"].split("@")[0]))
    return sorted(problems)


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class LiveContaminatedWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = cls._tmp.name
        cls.ws, cls.manifest = build_live_workspace(cls.base)
        cls.report, cls.platforms = audit_live(cls.manifest)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_both_platforms_resolve_from_real_cargo(self):
        self.assertEqual({k: v["outcome"] for k, v in self.report["platforms"].items()},
                         {"host": "resolved", "mips": "resolved"})

    def test_the_native_links_key_cargo_reports_is_read(self):
        f = find(self.report, "native-links", "nat@0.1.0")[0]
        self.assertEqual(f["severity"], "review")
        self.assertIn("links = 'natfoo'", f["detail"])
        self.assertIn("rustc-link-lib", f["detail"])

    def test_the_unsafe_transitive_is_found_under_a_parent_that_forbids_unsafe(self):
        # leaf is a path crate inside the workspace, so it is judged as a workspace crate: unsafe, undeclared, and
        # depended on by another workspace crate (mid), which forbids unsafe and thereby clears nothing.
        f = find(self.report, "workspace-unsafe-linked", "leaf@0.1.0")[0]
        self.assertEqual(f["severity"], "blocker")
        self.assertIn("1 unsafe token(s) in src/lib.rs", f["detail"])
        self.assertIn("depended on by mid@0.1.0", f["detail"])
        self.assertEqual(find(self.report, "workspace-unsafe-linked", "mid@0.1.0"), [])
        mid = next(p for p in self.report["packages"] if p["key"] == "mid@0.1.0")
        self.assertEqual(mid["unsafe"]["status"], "none")
        self.assertEqual([(d["mechanism"], d["level"]) for d in mid["unsafe"]["declared"]],
                         [("crate-attribute", "forbid"), ("manifest-lint (workspace)", "forbid")])

    def test_two_versions_of_the_same_package_are_a_duplicate_version(self):
        self.assertIn("1.0.0, 2.0.0", find(self.report, "duplicate-version", "dupe")[0]["detail"])

    def test_a_missing_license_is_reported(self):
        self.assertEqual(find(self.report, "license-missing", "nolic@0.1.0")[0]["severity"], "review")
        self.assertEqual(find(self.report, "license-missing", "app@0.1.0"), [])

    def test_path_dependencies_outside_the_workspace_are_unpinned_blockers(self):
        keys = sorted(f["package"] for f in find(self.report, "external-path-dependency"))
        self.assertEqual(keys, ["dupe@2.0.0", "ext-path@0.1.0"])
        self.assertEqual(find(self.report, "external-path-dependency", "dupe@1.0.0"), [])      # inside: a member

    def test_there_are_no_registry_findings_in_a_path_only_graph(self):
        self.assertEqual([f for f in self.report["findings"] if f["kind"].startswith("lock-")], [])
        # hand count: app, mid, leaf, nat, dupe 1.0.0, dupe 2.0.0, nolic, ext-path
        self.assertEqual(self.report["lock"]["entries"], 8)

    def test_the_big_endian_graph_is_the_same_set_as_the_host_for_path_only_deps(self):
        s = self.report["summary"]["linked"]
        self.assertEqual(s["mips"], s["host"])
        self.assertEqual(s["mips"], ["app@0.1.0", "dupe@1.0.0", "dupe@2.0.0", "ext-path@0.1.0", "leaf@0.1.0", "mid@0.1.0",
                                     "nat@0.1.0", "nolic@0.1.0"])

    def test_the_verdict_is_blocked(self):
        self.assertEqual(AU.exit_code(self.report), 1)


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class LiveCargoErrorClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.ws, cls.manifest = build_live_workspace(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_an_unknown_target_triple_is_target_unsupported(self):
        outcome, meta, detail = AU.run_cargo_metadata(self.manifest, "mipsel-nonexistent-linux-gnu")
        self.assertEqual((outcome, meta), ("target-unsupported", None))
        self.assertIn("could not find specification", detail)

    def test_a_stale_lock_is_a_resolver_failure_not_an_unsupported_target(self):
        extra = os.path.join(self._tmp.name, "late")
        write(os.path.join(extra, "Cargo.toml"), package("late", "0.1.0")[0])
        write(os.path.join(extra, "src", "lib.rs"), "")
        app = os.path.join(self.ws, "app", "Cargo.toml")
        with open(app) as fh:
            original = fh.read()
        try:
            write(app, original + 'late = { path = "../../late" }\n')           # lock no longer matches the manifest
            outcome, meta, detail = AU.run_cargo_metadata(self.manifest, MIPS)
        finally:
            write(app, original)
        self.assertEqual((outcome, meta), ("resolver-failed", None))
        self.assertIn("lock", detail.lower())

    def stale_lock(self):
        """A context in which app's manifest has a dependency the lock does not know: the shared-worktree state that
        made `plan` print nothing and exit 0."""
        outer = self

        class _Stale:
            def __enter__(self):
                outer.late = os.path.join(outer._tmp.name, "late2")
                write(os.path.join(outer.late, "Cargo.toml"), package("late2", "0.1.0")[0])
                write(os.path.join(outer.late, "src", "lib.rs"), "")
                self.app = os.path.join(outer.ws, "app", "Cargo.toml")
                with open(self.app) as fh:
                    self.original = fh.read()
                write(self.app, self.original + 'late2 = { path = "../../late2" }\n')

            def __exit__(self, *exc):
                write(self.app, self.original)
        return _Stale()

    def test_plan_in_a_stale_lock_tree_refuses_with_a_reason_instead_of_printing_nothing(self):
        out, err = io.StringIO(), io.StringIO()
        with self.stale_lock(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = AU.main(["plan", "--manifest-path", self.manifest, "--jobs", "2"])
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), "")                                    # nothing a runner could mistake for a plan
        text = err.getvalue()
        for key in ("host", "mips", "powerpc"):
            self.assertIn("%s (" % key, text)
        self.assertIn("is resolver-failed", text)
        self.assertIn("Cargo.lock does not match the manifests in this tree", text)

    def test_the_real_process_exit_status_is_nonzero_and_stdout_is_empty_for_an_unplannable_tree(self):
        # The failure BeigeMaple saw was an exit status, so assert the exit status of a real process, not a return value.
        with self.stale_lock():
            proc = subprocess.run([sys.executable, "-B", "-I", os.path.join(ROOT, "scripts", "e06", "audit.py"), "plan",
                                   "--manifest-path", self.manifest, "--jobs", "2"],
                                  capture_output=True, text=True, timeout=120)
        self.assertEqual((proc.returncode, proc.stdout), (1, ""))
        self.assertIn("resolver-failed", proc.stderr)
        self.assertNotIn(self._tmp.name, proc.stderr)                         # cargo's absolute path is scrubbed
        self.assertIn("<workspace>", proc.stderr)

    def test_a_resolver_failure_detail_in_the_json_report_carries_no_absolute_path(self):
        out = os.path.join(self._tmp.name, "stale-report.json")
        with self.stale_lock(), contextlib.redirect_stdout(io.StringIO()):
            code = AU.main(["audit", "--manifest-path", self.manifest, "--json", out])
        self.assertEqual(code, 1)
        with open(out) as fh:
            text = fh.read()
        self.assertIn("resolver-failed", text)
        for leaked in (self._tmp.name, os.path.realpath(self._tmp.name), os.path.expanduser("~")):
            self.assertNotIn(leaked, text, leaked)

    def test_the_same_tree_plans_normally_once_the_lock_matches_again(self):
        with self.stale_lock():
            pass
        proc = subprocess.run([sys.executable, "-B", "-I", os.path.join(ROOT, "scripts", "e06", "audit.py"), "plan",
                               "--manifest-path", self.manifest, "--jobs", "2"],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(proc.stdout.splitlines()), 12)
        self.assertTrue(all(l.endswith(" -j 2") for l in proc.stdout.splitlines()))
        self.assertEqual(proc.stderr, "")

    def test_a_missing_manifest_is_a_resolver_failure(self):
        outcome, meta, _ = AU.run_cargo_metadata(os.path.join(self._tmp.name, "nowhere", "Cargo.toml"), MIPS)
        self.assertEqual((outcome, meta), ("resolver-failed", None))

    def test_the_command_line_reports_an_unsupported_target_as_a_blocker_and_exit_one(self):
        out = os.path.join(self._tmp.name, "report.json")
        with contextlib.redirect_stdout(io.StringIO()):
            code = AU.main(["audit", "--manifest-path", self.manifest, "--target", "bogus=mipsel-nonexistent-linux-gnu",
                            "--json", out])
        self.assertEqual(code, 1)
        with open(out) as fh:
            report = json.load(fh)
        self.assertEqual(report["platforms"]["bogus"]["outcome"], "target-unsupported")
        self.assertEqual(find(report, "target-unsupported")[0]["severity"], "blocker")

    def test_the_command_line_refuses_to_overwrite_a_report_and_rejects_bad_usage(self):
        out = os.path.join(self._tmp.name, "exists.json")
        write(out, "{}")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(AU.main(["audit", "--manifest-path", self.manifest, "--json", out]), 2)
            with open(out) as fh:
                self.assertEqual(fh.read(), "{}")                               # untouched
            self.assertEqual(AU.main(["audit", "--manifest-path", self.manifest, "--target", "no-equals-sign"]), 2)
            self.assertEqual(AU.main(["audit", "--manifest-path", self.manifest, "--build-results",
                                      os.path.join(self._tmp.name, "absent.jsonl")]), 2)
        self.assertIn("never overwritten", err.getvalue())
        self.assertIn("KEY=TRIPLE", err.getvalue())

    def test_the_plan_subcommand_prints_exactly_the_planned_commands_and_nothing_else(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = AU.main(["plan", "--manifest-path", self.manifest])
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        # Cargo makes every path dependency INSIDE the workspace directory a member, so the workspace crates are
        # app, dupe 1.0.0, leaf, mid, nat and nolic (dupe 2.0.0 and ext-path live outside it).  Hand count: 6 x 2.
        # None declares #![no_std], so every check needs the std build set.
        crates = ["app", "dupe", "leaf", "mid", "nat", "nolic"]
        expected = ["RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p %s --target %s "
                    "-Z build-std=std,panic_abort" % (crate, triple)
                    for triple in ("mips-unknown-linux-musl", "powerpc-unknown-linux-musl") for crate in crates]
        self.assertEqual(lines, expected)


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class ThisRepositorysWorkspaceTests(unittest.TestCase):
    """The real graph, taken from a clean export of HEAD.  Only structural truths are asserted, so a dependency bump
    does not break the tests.  (The CURRENT worktree is audited by scripts/e2e/e06's second stage.)"""

    @classmethod
    def setUpClass(cls):
        cls._export = export_head()
        if cls._export is None:
            raise unittest.SkipTest("git or a git repository is not available")
        cls.manifest = os.path.join(cls._export.name, "Cargo.toml")
        platforms, lock_text, root = AU.gather(cls.manifest, dict(AU.DEFAULT_TARGETS), None)
        cls.platforms = platforms
        cls.report = AU.analyze(platforms, lock_text, root)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_export", None) is not None:
            cls._export.cleanup()

    def test_all_three_platforms_resolve(self):
        self.assertEqual({k: v["outcome"] for k, v in self.report["platforms"].items()},
                         {"host": "resolved", "mips": "resolved", "powerpc": "resolved"})

    def test_every_non_workspace_package_in_the_graph_is_pinned_with_a_checksum(self):
        bad = [p["key"] for p in self.report["packages"]
               if p["source_kind"] == "registry" and not (p["pin"]["in_lock"] and p["pin"]["checksum"])]
        self.assertEqual(bad, [])
        # Every `lock-`/`unpinned`/`external` finding is still refused except the information note that NAMES the lock entries no
        # platform graph links. That note stays (it is the fact), and the next test holds it to account: each entry it names has
        # to be inventoried with its own checksum, licence and unsafe facts, so the note can no longer stand in for them.
        self.assertEqual([f for f in self.report["findings"]
                          if f["kind"].startswith(("lock-", "unpinned", "external")) and f["kind"] != "lock-unused-entries"], [])
        self.assertEqual({f["severity"] for f in find(self.report, "lock-unused-entries")} - {"info"}, set())

    def test_every_lock_entry_is_pinned_with_its_facts_and_the_unlinked_ones_are_labelled_and_reach_no_platform(self):
        import tomllib
        with open(os.path.join(self._export.name, "Cargo.lock"), "rb") as fh:
            locked = tomllib.load(fh)["package"]
        records = {p["key"]: p for p in self.report["packages"]}
        for entry in locked:
            if "source" not in entry:
                continue                                           # a workspace member: recorded in `packages`, not a pin
            key = "%s@%s" % (entry["name"], entry["version"])
            rec = records.get(key)
            self.assertIsNotNone(rec, "%s is in Cargo.lock but has no package record" % key)
            self.assertEqual((rec["pin"]["source"], rec["pin"]["checksum"]), (entry["source"], entry["checksum"]), key)
            self.assertIn("license", rec, key)
            self.assertIn("unsafe", rec, key)
            # a platform's rows hold what that platform resolves (an x86_64-only crate has none on the big-endian targets), so the
            # entry has to be pinned on at least one; the entries no platform resolves are pinned on all three, checked below
            self.assertTrue(any(key in [r["package"] for r in self.report["pins"][plat]["rows"]] for plat in ("host", "mips", "powerpc")),
                            "%s is in Cargo.lock but pinned on no platform" % key)
        named = [f for f in find(self.report, "unlinked-locked-package")]
        for f in named:
            rec = records[f["package"]]
            self.assertIn("unlinked", rec, f["package"])
            self.assertEqual({v["role"] for v in rec["platforms"].values()}, {"absent"}, "%s is reachable on a platform" % f["package"])
            self.assertEqual({r["role"] for plat in ("host", "mips", "powerpc") for r in self.report["pins"][plat]["rows"]
                              if r["package"] == f["package"]}, {"unlinked"})
            self.assertEqual(f["severity"], "info")
        self.assertEqual(sorted(p["key"] for p in self.report["packages"] if "unlinked" in p), sorted(f["package"] for f in named))
        self.assertEqual([f for f in self.report["findings"] if f["severity"] == "blocker"], [])

    def test_the_two_big_endian_targets_link_the_same_packages(self):
        s = self.report["summary"]["linked"]
        self.assertEqual(s["mips"], s["powerpc"])
        self.assertEqual(self.report["pins"]["mips"]["rows"], self.report["pins"]["powerpc"]["rows"])

    def test_the_documented_unsafe_exception_is_found_and_nothing_depends_on_it(self):
        probe = next(p for p in self.report["packages"] if p["name"] == "franken-alloc-probe")
        self.assertGreater(probe["unsafe"]["tokens"], 0)
        self.assertEqual([d["level"] for d in probe["unsafe"]["declared"]], ["deny"])
        self.assertEqual(probe["platforms"]["mips"]["dependents"], [])
        f = find(self.report, "workspace-unsafe-test-only", "franken-alloc-probe@0.1.0")[0]
        self.assertEqual(f["severity"], "review")

    def test_no_other_workspace_crate_contains_unsafe_unless_policy_allows_it(self):
        self.assertEqual(workspace_unsafe_problems(self.report), [])
        self.assertEqual(find(self.report, "workspace-unsafe-linked"), [])
        self.assertEqual(find(self.report, "workspace-unsafe-undeclared"), [])

    def test_the_linux_leafs_unsafe_is_the_one_permitted_exception_and_is_confined_to_its_sys_module(self):
        # P02 stage 2 (6ab9020): franken-platform forbids unsafe, the syscall unsafe lives in the leaf that franken-speaker links.
        leaf = next(p for p in self.report["packages"] if p["name"] == LEAF)
        self.assertGreater(leaf["unsafe"]["tokens"], 0)
        self.assertEqual(sorted(leaf["unsafe"]["files"]), LEAF_UNSAFE_FILES)
        self.assertEqual({d["level"] for d in leaf["unsafe"]["declared"]}, {"deny"})
        self.assertIn("franken-speaker", {d.split("@")[0] for d in leaf["platforms"]["mips"]["dependents"]})
        permitted = find(self.report, "workspace-unsafe-permitted")
        self.assertEqual({f["package"].split("@")[0] for f in permitted}, {LEAF})
        self.assertEqual({f["severity"] for f in permitted}, {"info"})
        platform = next(p for p in self.report["packages"] if p["name"] == "franken-platform")
        self.assertEqual(platform["unsafe"]["tokens"], 0)
        self.assertEqual({d["level"] for d in platform["unsafe"]["declared"]}, {"forbid"})
        self.assertEqual(AU.DEFAULT_UNSAFE_ALLOWED, (LEAF,))                  # the list does not grow

    def test_proc_macro_crates_are_host_only_and_never_linked_into_a_target(self):
        for key in ("mips", "powerpc"):
            linked = set(self.report["summary"]["linked"][key])
            self.assertTrue(any(k.startswith("serde_derive@") for k in self.report["summary"]["host_only"][key]))
            self.assertFalse(any(k.startswith(("serde_derive@", "syn@", "quote@", "proc-macro2@")) for k in linked))

    def test_a_no_std_crate_that_re_enables_std_by_feature_is_classified_std(self):
        thiserror = next(p for p in self.report["packages"] if p["name"] == "thiserror")
        st = thiserror["platforms"]["mips"]
        if "std" in st["features"]:
            self.assertEqual(st["std"], "std")
            self.assertIn("extern crate std", st["std_why"])

    def test_the_soft_float_target_is_identified_from_the_compilers_own_spec(self):
        mips = self.report["platforms"]["mips"]
        if mips["spec_outcome"] == "captured":
            self.assertEqual(mips["float"], "soft-float")
            self.assertEqual(mips["target_spec"]["target-endian"], "big")

    def test_the_report_is_deterministic_and_leaks_no_absolute_path(self):
        platforms, lock_text, root = AU.gather(self.manifest, dict(AU.DEFAULT_TARGETS), None)
        again = AU.analyze(platforms, lock_text, root)
        self.assertEqual(json.dumps(self.report, sort_keys=True), json.dumps(again, sort_keys=True))
        text = json.dumps(self.report)
        for leaked in (ROOT, self._export.name, os.path.expanduser("~"), "/Users/"):
            self.assertNotIn(leaked, text, leaked)

    def test_candidates_not_in_the_workspace_are_recorded_unevaluated(self):
        by = {c["name"]: c for c in self.report["candidates"]}
        for name in ("asupersync", "franken_kernel", "codecs"):
            self.assertEqual(by[name]["status"], "not in graph; unevaluated", name)


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class PlantedUnsafeInTheWorkspaceTests(unittest.TestCase):
    """Negatives for the unsafe policy test above.  Each case audits a clean export of HEAD with ONE unsafe token planted in a
    source file, through the same predicate (`workspace_unsafe_problems`) the live test uses, and expects exactly that problem:
    the real leaf's own unsafe stays unreported in every case (the permitted positive), and a policy that stopped objecting
    would fail the case by name.  Nothing is compiled: the audit reads tokens and cargo's resolver output."""

    PLANT = "\n#[allow(dead_code)]\nunsafe fn planted_unsafe() {}\n"

    def audit_with_plant(self, relative_path):
        export = export_head()
        if export is None:
            self.skipTest("git or a git repository is not available")
        self.addCleanup(export.cleanup)
        target = os.path.join(export.name, relative_path)
        self.assertTrue(os.path.isfile(target), relative_path)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(self.PLANT)
        platforms, lock_text, root = AU.gather(os.path.join(export.name, "Cargo.toml"), dict(AU.DEFAULT_TARGETS), None)
        return AU.analyze(platforms, lock_text, root)

    def test_another_crate_the_speaker_links_that_gains_an_unsafe_token_is_flagged(self):
        report = self.audit_with_plant("crates/franken-clock/src/lib.rs")
        self.assertEqual(workspace_unsafe_problems(report),
                         ["unsafe in franken-clock", "workspace-unsafe-linked franken-clock"])
        self.assertEqual({f["severity"] for f in find(report, "workspace-unsafe-linked")}, {"blocker"})

    def test_franken_platform_that_now_forbids_unsafe_is_no_longer_allowed_to_hold_it(self):
        report = self.audit_with_plant("crates/franken-platform/src/lib.rs")
        self.assertEqual(workspace_unsafe_problems(report),
                         ["unsafe in franken-platform", "workspace-unsafe-linked franken-platform"])

    def test_the_leaf_gaining_unsafe_outside_its_sys_module_is_flagged(self):
        report = self.audit_with_plant("crates/franken-platform-linux/src/lib.rs")
        self.assertEqual(workspace_unsafe_problems(report),
                         ["unsafe outside src/sys.rs in franken-platform-linux: src/lib.rs, src/sys.rs"])


if __name__ == "__main__":
    unittest.main()
