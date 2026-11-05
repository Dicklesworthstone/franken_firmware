"""E06 upstream-audit tests: feature selection, the upstream subject, offline lock generation, the compact inventory.

Everything here runs real `cargo metadata` / `cargo generate-lockfile --offline` on tiny path-only workspaces built in a
temporary directory, so no network and no third-party source is needed. The expected closures are written from the
manifests below, not read back from the tool.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
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


AU = load("ffw_e06_audit_upstream", os.path.join(ROOT, "scripts", "e06", "audit.py"))
CK = sys.modules["checks"]
LIVE = load("ffw_e06_live_for_upstream", os.path.join(HERE, "test_live.py"))
HAVE_CARGO = shutil.which("cargo") is not None
MIPS, PPC = "mips-unknown-linux-musl", "powerpc-unknown-linux-musl"
REV = "c" * 40


def build_feature_workspace(base, with_lock=True):
    """app (default = [extra], extra = [dep:extra], marker = []) -> base (always) and extra (optional); a third workspace
    member, solo, declares no features. All path dependencies."""
    ws = os.path.join(base, "ws")
    LIVE.write(os.path.join(ws, "Cargo.toml"),
               '[workspace]\nmembers = ["app", "base", "extra", "solo"]\nexclude = ["hostdep"]\nresolver = "2"\n')
    LIVE.write(os.path.join(ws, "app", "Cargo.toml"),
               '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n\n'
               '[features]\ndefault = ["extra"]\nextra = ["dep:extra"]\nmarker = []\n\n'
               '[dependencies]\nbase = { path = "../base" }\nextra = { path = "../extra", optional = true }\n\n'
               '[target.\'cfg(target_vendor = "apple")\'.dependencies]\nhostdep = { path = "../hostdep" }\n')
    LIVE.write(os.path.join(ws, "hostdep", "Cargo.toml"),
               '[package]\nname = "hostdep"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n')
    LIVE.write(os.path.join(ws, "hostdep", "src", "lib.rs"), "pub fn h() {}\n")
    LIVE.write(os.path.join(ws, "app", "src", "lib.rs"), "#![forbid(unsafe_code)]\npub fn a() {}\n")
    for name, src in (("base", "pub fn b() {}\n"), ("extra", "pub fn e() { unsafe { core::hint::unreachable_unchecked() } }\n"),
                      ("solo", "pub fn s() {}\n")):
        LIVE.write(os.path.join(ws, name, "Cargo.toml"),
                   '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n' % name)
        LIVE.write(os.path.join(ws, name, "src", "lib.rs"), src)
    manifest = os.path.join(ws, "Cargo.toml")
    if with_lock:
        import subprocess
        subprocess.run(["cargo", "generate-lockfile", "--offline", "--manifest-path", manifest],
                       capture_output=True, text=True, check=True, timeout=120)
    return ws, manifest


def audit(manifest, cargo_args=(), **kw):
    platforms = []
    for key, triple in (("host", AU.host_triple()), ("mips", MIPS), ("powerpc", PPC)):
        outcome, meta, detail = AU.run_cargo_metadata(manifest, triple, cargo_args=cargo_args)
        platforms.append(AU.PlatformInput(key, triple, outcome, detail, meta))
    root = next(p.metadata["workspace_root"] for p in platforms if p.metadata)
    with open(os.path.join(root, "Cargo.lock")) as fh:
        return AU.analyze(platforms, fh.read(), root, cargo_args=cargo_args, **kw)


def linked(report, platform="mips"):
    return sorted(k.split("@")[0] for k in report["summary"]["linked"][platform])


def dependents(report, name, platform="mips"):
    """Who depends on ``name`` on ``platform``. A workspace member is always in the linked set, so whether a FEATURE
    pulled a crate in is read from its dependents, not from membership."""
    pkg = next(p for p in report["packages"] if p["name"] == name)
    return sorted(d.split("@")[0] for d in pkg["platforms"][platform]["dependents"])


class FeatureArgsTests(unittest.TestCase):
    def test_only_a_validated_feature_selection_is_ever_forwarded(self):
        self.assertEqual(AU.feature_args(False, None), [])
        self.assertEqual(AU.feature_args(True, None), ["--no-default-features"])
        self.assertEqual(AU.feature_args(True, "runtime-core"), ["--no-default-features", "--features", "runtime-core"])
        self.assertEqual(AU.feature_args(False, "a,b/c,dep-x+y"), ["--features", "a,b/c,dep-x+y"])
        for bad in ("a b", "a;rm -rf x", "$(x)", "--release", "a,,", ",", "", "-x", "a\nb", "a,'b"):
            if bad == "":
                self.assertEqual(AU.feature_args(False, bad), [])            # an empty option is no option
                continue
            with self.assertRaises(ValueError, msg=repr(bad)):
                AU.feature_args(False, bad)

    def test_the_same_selection_is_what_a_planned_line_carries(self):
        self.assertEqual(AU.feature_suffix(["--no-default-features", "--features", "x,y"]),
                         " --no-default-features --features x,y")
        self.assertEqual(AU.feature_suffix([]), "")


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class LiveFeatureSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.ws, cls.manifest = build_feature_workspace(cls._tmp.name)
        cls.default = audit(cls.manifest)
        cls.bare = audit(cls.manifest, ["--no-default-features"])
        cls.marker = audit(cls.manifest, ["--no-default-features", "--features", "marker"])
        cls.extra = audit(cls.manifest, ["--no-default-features", "--features", "extra"])

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_default_features_make_app_depend_on_the_optional_crate_on_every_platform(self):
        for platform in ("host", "mips", "powerpc"):
            self.assertEqual(dependents(self.default, "extra", platform), ["app"], platform)

    def test_no_default_features_removes_that_edge_on_every_platform_and_keeps_the_unconditional_one(self):
        for platform in ("host", "mips", "powerpc"):
            self.assertEqual(dependents(self.bare, "extra", platform), [], platform)
            self.assertEqual(dependents(self.bare, "base", platform), ["app"], platform)

    def test_an_empty_marker_feature_changes_nothing_in_the_closure(self):
        # `marker = []` enables no dependency, so selecting it excludes and adds nothing: the name alone proves nothing.
        for platform in ("host", "mips", "powerpc"):
            self.assertEqual(linked(self.marker, platform), linked(self.bare, platform), platform)
        app = next(p for p in self.marker["packages"] if p["name"] == "app")
        self.assertEqual(app["declared_features"]["marker"], [])                 # recorded as the empty list it is
        self.assertEqual(app["declared_features"]["extra"], ["dep:extra"])
        self.assertEqual(app["declared_features"]["default"], ["extra"])

    def test_a_feature_that_does_enable_a_dependency_is_visible_in_the_closure(self):
        self.assertEqual(dependents(self.extra, "extra", "mips"), ["app"])
        self.assertEqual(dependents(self.marker, "extra", "mips"), [])
        app = next(p for p in self.extra["packages"] if p["name"] == "app")
        self.assertEqual(app["platforms"]["mips"]["features"], ["extra"])        # the feature cargo enabled, per platform

    def test_the_selection_is_recorded_in_the_report(self):
        self.assertEqual(self.marker["policy_inputs"]["cargo_args"], ["--no-default-features", "--features", "marker"])
        self.assertEqual(self.default["policy_inputs"]["cargo_args"], [])

    def test_only_workspace_crates_carry_declared_features(self):
        for p in self.default["packages"]:
            self.assertEqual(p["declared_features"] is not None, p["source_kind"] == "workspace", p["name"])

    def test_planned_lines_carry_the_selection_after_the_crate_and_ingest_accepts_the_shape(self):
        args = ["--no-default-features", "--features", "marker"]
        report = audit(self.manifest, args, plan_crates=["app"], jobs=2)
        rows = report["build_checks"]["rows"]
        self.assertEqual(sorted((r["crate"], r["target"]) for r in rows), [("app", MIPS), ("app", PPC)])
        for row in rows:
            self.assertIn(" -p app --no-default-features --features marker --target ", row["command"])
            self.assertTrue(row["command"].endswith(" -Z build-std=std,panic_abort -j 2"), row["command"])
        plan, problems = CK.parse_plan([r["command"] for r in rows])
        self.assertEqual(problems, [])
        self.assertEqual({p["crate"] for p in plan}, {"app"})
        self.assertEqual(CK.plan_argv(rows[0]["command"])[:7], ["cargo", "+nightly", "check", "--locked", "--release", "-p", "app"])

    def test_features_without_a_crate_list_plan_the_crates_that_declare_them_and_say_which_were_left_out(self):
        report = audit(self.manifest, ["--no-default-features", "--features", "marker"], jobs=2)
        self.assertEqual(sorted({r["crate"] for r in report["build_checks"]["rows"]}), ["app"])
        note = [f for f in report["findings"] if f["kind"] == "plan-narrowed-by-features"]
        self.assertEqual(len(note), 1)
        self.assertEqual(note[0]["severity"], "info")
        self.assertIn("do not declare marker: base, extra, solo", note[0]["detail"])
        # no feature selection, or --no-default-features alone, narrows nothing
        for args in ([], ["--no-default-features"]):
            full = audit(self.manifest, args)
            self.assertEqual(len({r["crate"] for r in full["build_checks"]["rows"]}), 4, args)
            self.assertEqual([f for f in full["findings"] if f["kind"] == "plan-narrowed-by-features"], [], args)

    def test_a_plan_for_a_crate_that_does_not_declare_the_feature_or_does_not_exist_is_refused(self):
        args = ["--no-default-features", "--features", "marker"]
        with self.assertRaises(ValueError) as caught:
            audit(self.manifest, args, plan_crates=["app", "base"])
        self.assertIn("base does not declare feature(s) marker", str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            audit(self.manifest, args, plan_crates=["nope"])
        self.assertIn("names no workspace crate: nope", str(caught.exception))

    def test_a_scope_makes_only_the_named_crates_the_roots_of_the_graph(self):
        everything = audit(self.manifest, ["--no-default-features"])
        self.assertEqual(linked(everything, "mips"), ["app", "base", "extra", "solo"])          # every member is a root
        scoped = audit(self.manifest, ["--no-default-features"], scope_crates=["app"])
        self.assertEqual(linked(scoped, "mips"), ["app", "base"])             # solo and extra are not reachable from app
        # packages is the union over platforms: hostdep is Apple-gated, so it is present on the macOS host only
        self.assertEqual(sorted(p["name"] for p in scoped["packages"]), ["app", "base", "hostdep"])
        hostdep = next(p for p in scoped["packages"] if p["name"] == "hostdep")
        self.assertEqual({k: v["role"] for k, v in hostdep["platforms"].items()}, {"host": "linked", "mips": "absent", "powerpc": "absent"})
        self.assertEqual(scoped["policy_inputs"]["scope_crates"], ["app"])
        # with the default feature app does reach extra, so the scoped closure grows to include it, as a dependency
        wide = audit(self.manifest, scope_crates=["app"])
        self.assertEqual(linked(wide, "mips"), ["app", "base", "extra"])
        self.assertEqual(sorted(r["crate"] for r in wide["build_checks"]["rows"]), ["app", "app"])   # planned: scope roots only
        self.assertIsNone(everything["policy_inputs"]["scope_crates"])

    def test_a_scope_naming_no_workspace_crate_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            audit(self.manifest, scope_crates=["app", "ghost"])
        self.assertIn("--scope-crates names no workspace crate: ghost", str(caught.exception))
        # a crate that exists but is not a workspace member is not a valid root either
        with self.assertRaises(ValueError):
            audit(self.manifest, scope_crates=["serde"])

    def test_without_a_feature_selection_every_member_is_planned_and_the_filter_narrows_it(self):
        everything = audit(self.manifest)["build_checks"]["rows"]
        self.assertEqual(sorted({r["crate"] for r in everything}), ["app", "base", "extra", "solo"])
        self.assertEqual(len(everything), 8)
        narrow = audit(self.manifest, plan_crates=["solo", "base"])["build_checks"]["rows"]
        self.assertEqual(sorted({r["crate"] for r in narrow}), ["base", "solo"])
        for row in everything:
            self.assertNotIn("--features", row["command"])
            self.assertNotIn("--no-default-features", row["command"])


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class UpstreamSubjectTests(unittest.TestCase):
    """This project's rule (P01: workspace crates forbid unsafe) is not a rule of somebody else's repository."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.ws, cls.manifest = LIVE.build_live_workspace(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def report(self, subject):
        platforms = []
        for key, triple in (("host", AU.host_triple()), ("mips", MIPS)):
            outcome, meta, detail = AU.run_cargo_metadata(self.manifest, triple)
            platforms.append(AU.PlatformInput(key, triple, outcome, detail, meta))
        root = next(p.metadata["workspace_root"] for p in platforms if p.metadata)
        with open(os.path.join(root, "Cargo.lock")) as fh:
            return AU.analyze(platforms, fh.read(), root, subject=subject)

    def kinds(self, report, severity):
        return sorted({f["kind"] for f in report["findings"] if f["severity"] == severity})

    def test_our_own_workspace_is_held_to_the_rule(self):
        report = self.report("own")
        self.assertIn("workspace-unsafe-linked", self.kinds(report, "blocker"))
        self.assertEqual(report["policy_inputs"]["subject"], "own")

    def test_an_upstream_subjects_unsafe_is_reviewed_and_never_a_blocker(self):
        report = self.report("upstream")
        self.assertEqual(report["policy_inputs"]["subject"], "upstream")
        blockers = [f for f in report["findings"] if f["severity"] == "blocker"]
        self.assertEqual([f["kind"] for f in blockers if f["kind"].startswith("workspace-unsafe")], [])
        leaf = [f for f in report["findings"] if f["kind"] == "upstream-crate-unsafe" and f["package"] == "leaf@0.1.0"]
        # review on the firmware platform; the host reference platform's copy is demoted to info (it is the build machine)
        self.assertEqual(sorted((f["severity"], f["platforms"][0]) for f in leaf), [("info", "host"), ("review", "mips")])
        review = [f for f in leaf if f["severity"] == "review"][0]
        self.assertIn("1 unsafe token(s) in src/lib.rs", review["detail"])
        # the fact is not lost, only the verdict: the same crate is still reported with its unsafe

    def test_a_real_resolver_failure_is_still_a_blocker_for_an_upstream_subject(self):
        platforms = [AU.PlatformInput("mips", MIPS, "resolver-failed", "boom", None)]
        report = AU.analyze(platforms, "", self.ws, subject="upstream")
        self.assertEqual([f["kind"] for f in report["findings"] if f["severity"] == "blocker"], ["resolver-failed"])


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class GenerateLockTests(unittest.TestCase):
    def test_a_missing_lock_is_generated_in_an_export_and_an_existing_one_is_left_alone(self):
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base, with_lock=False)
            self.assertFalse(os.path.exists(os.path.join(ws, "Cargo.lock")))
            self.assertEqual(AU.generate_lock(manifest)[0], "generated")
            self.assertTrue(os.path.exists(os.path.join(ws, "Cargo.lock")))
            with open(os.path.join(ws, "Cargo.lock")) as fh:
                before = fh.read()
            self.assertEqual(AU.generate_lock(manifest)[0], "present")
            with open(os.path.join(ws, "Cargo.lock")) as fh:
                self.assertEqual(fh.read(), before, "an existing lock was rewritten")

    def test_a_git_work_tree_is_never_written_to(self):
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base, with_lock=False)
            os.mkdir(os.path.join(ws, ".git"))                                    # looks like somebody's repository
            outcome, detail = AU.generate_lock(manifest)
            self.assertEqual(outcome, "refused")
            self.assertIn("git work tree", detail)
            self.assertFalse(os.path.exists(os.path.join(ws, "Cargo.lock")))
            with open(os.path.join(ws, ".git", "keep"), "w") as fh:
                fh.write("x")                                                      # .git as a file or dir both count
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base, with_lock=False)
            with open(os.path.join(ws, ".git"), "w") as fh:
                fh.write("gitdir: elsewhere\n")                                    # a worktree's .git is a FILE
            self.assertEqual(AU.generate_lock(manifest)[0], "refused")

    def test_a_manifest_cargo_cannot_resolve_is_a_failure_not_a_lock(self):
        with tempfile.TemporaryDirectory() as base:
            LIVE.write(os.path.join(base, "Cargo.toml"), "this is not toml [\n")
            outcome, detail = AU.generate_lock(os.path.join(base, "Cargo.toml"))
            self.assertEqual(outcome, "failed")
            self.assertFalse(os.path.exists(os.path.join(base, "Cargo.lock")))
            self.assertNotIn(base, detail)                                         # no absolute path in the detail

    def test_a_generated_lock_is_reported_as_not_an_upstream_pin(self):
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base)
            repo = audit(manifest)
            made = audit(manifest, lock_origin="generated-offline")
        self.assertEqual(repo["lock"]["origin"], "repository")
        self.assertEqual(made["lock"]["origin"], "generated-offline")
        self.assertEqual([f for f in repo["findings"] if f["kind"] == "lock-generated-not-an-upstream-pin"], [])
        f = [f for f in made["findings"] if f["kind"] == "lock-generated-not-an-upstream-pin"]
        self.assertEqual([x["severity"] for x in f], ["review"])
        self.assertIn("not pinned by the repository", f[0]["detail"])
        self.assertIn(made["lock"]["sha256"][:16], f[0]["detail"])


@unittest.skipUnless(HAVE_CARGO, "cargo is not installed")
class InventoryTests(unittest.TestCase):
    def test_a_package_absent_from_a_platform_is_written_with_empty_fields_and_not_a_crash(self):
        # hostdep is gated to Apple targets: present on the macOS host, absent from both big-endian graphs. Its platform
        # entries for those two are just {"role": "absent"}; the inventory writer used to assume every field existed.
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base)
            report = audit(manifest)
            if AU.host_triple() and "apple" not in AU.host_triple():
                self.skipTest("the gated dependency is active only on an Apple host")
            inv = AU.inventory(report, "demo", REV)
        row = next(p for p in inv["packages"] if p["name"] == "hostdep")
        self.assertEqual(row["platforms"]["host"]["role"], "linked")
        self.assertEqual(row["platforms"]["mips"], {"role": "absent", "std": None, "effective_std": None, "features": None})
        self.assertEqual(row["platforms"]["powerpc"]["role"], "absent")
        json.dumps(inv)                                                   # and it serialises

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.ws, cls.manifest = build_feature_workspace(cls._tmp.name)
        cls.report = audit(cls.manifest, ["--no-default-features", "--features", "marker"])
        cls.inv = AU.inventory(cls.report, "demo", REV)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_one_row_per_package_with_the_facts_a_reader_needs(self):
        self.assertEqual(self.inv["schema"], AU.INVENTORY_SCHEMA)
        self.assertEqual(self.inv["subject"], {"name": "demo", "rev": REV})
        self.assertEqual(len(self.inv["packages"]), len(self.report["packages"]))
        row = next(p for p in self.inv["packages"] if p["name"] == "app")
        for key in ("version", "source_kind", "checksum", "license", "license_status", "unsafe_tokens", "unsafe_declared",
                    "links", "build_script", "references_alloc", "uses_float", "declared_features", "platforms"):
            self.assertIn(key, row, key)
        self.assertEqual(sorted(row["platforms"]), ["host", "mips", "powerpc"])
        self.assertEqual(row["platforms"]["mips"]["role"], "member")
        self.assertEqual(self.inv["policy_inputs"]["cargo_args"], ["--no-default-features", "--features", "marker"])
        self.assertEqual(self.inv["lock"]["origin"], "repository")

    def test_it_is_deterministic_bounded_and_carries_no_absolute_path(self):
        again = AU.inventory(self.report, "demo", REV)
        self.assertEqual(json.dumps(self.inv, sort_keys=True), json.dumps(again, sort_keys=True))
        self.assertTrue(all(len(f["detail"]) <= AU.FINDING_DETAIL_LIMIT for f in self.inv["findings"]))
        text = json.dumps(self.inv)
        for leaked in (self.ws, os.path.dirname(self.ws), os.path.expanduser("~"), "/private/", "/Users/"):
            self.assertNotIn(leaked, text, leaked)

    def test_a_long_finding_detail_is_cut_and_the_rest_kept(self):
        report = json.loads(json.dumps(self.report))
        report["findings"].append({"kind": "x", "severity": "info", "package": None, "platforms": [], "detail": "y" * 1000})
        inv = AU.inventory(report, "demo", REV)
        long = [f for f in inv["findings"] if f["kind"] == "x"][0]
        self.assertEqual(len(long["detail"]), AU.FINDING_DETAIL_LIMIT)
        self.assertEqual(len(inv["findings"]), len(report["findings"]))

    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = AU.main(["audit", "--manifest-path", self.manifest, *extra])
        return code, out.getvalue(), err.getvalue()

    def test_the_cli_requires_a_subject_a_forty_hex_revision_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "inv.json")
            self.assertEqual(self.run_cli("--inventory", out)[0], 2)                                   # no subject
            self.assertEqual(self.run_cli("--inventory", out, "--subject-name", "demo", "--subject-rev", "abc")[0], 2)
            self.assertFalse(os.path.exists(out))
            code, text, _ = self.run_cli("--inventory", out, "--subject-name", "demo", "--subject-rev", REV,
                                         "--subject", "upstream", "--no-default-features", "--features", "marker")
            self.assertIn(code, (0, 3))
            with open(out) as fh:
                written = json.load(fh)
            self.assertEqual(written["subject"], {"name": "demo", "rev": REV})
            self.assertEqual(written["policy_inputs"]["subject"], "upstream")
            self.assertIn("repository", text)
            with open(out) as fh:
                before = fh.read()
            self.assertEqual(self.run_cli("--inventory", out, "--subject-name", "demo", "--subject-rev", REV)[0], 2)
            with open(out) as fh:
                self.assertEqual(fh.read(), before)

    def test_a_bad_feature_selection_on_the_command_line_is_a_usage_error(self):
        code, _, err = self.run_cli("--features", "a;b")
        self.assertEqual(code, 2)
        self.assertIn("feature names", err)

    def test_generate_lock_is_refused_inside_a_work_tree_and_reported_when_used_on_an_export(self):
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base, with_lock=False)
            os.mkdir(os.path.join(ws, ".git"))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(AU.main(["audit", "--manifest-path", manifest, "--generate-lock"]), 2)
            self.assertIn("git work tree", err.getvalue())
            self.assertFalse(os.path.exists(os.path.join(ws, "Cargo.lock")))
        with tempfile.TemporaryDirectory() as base:
            ws, manifest = build_feature_workspace(base, with_lock=False)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = AU.main(["audit", "--manifest-path", manifest, "--generate-lock", "--subject", "upstream"])
            self.assertEqual(code, 3, "an upstream subject's unsafe and its generated lock are review items, not blockers")
            self.assertIn("generated-offline", out.getvalue())
            self.assertIn("REVIEW   lock-generated-not-an-upstream-pin", out.getvalue())


class IngestPlanShapeTests(unittest.TestCase):
    def line(self, flags=""):
        return ("RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p asupersync%s --target %s "
                "-Z build-std=std,panic_abort -j 2" % (flags, MIPS))

    def test_feature_flags_after_the_crate_are_part_of_a_planned_check(self):
        for flags in ("", " --no-default-features", " --features a,b", " --no-default-features --features runtime-core"):
            plan, problems = CK.parse_plan([self.line(flags)])
            self.assertEqual((problems, [p["crate"] for p in plan]), ([], ["asupersync"]), flags)

    def test_anything_else_in_that_position_is_not_a_planned_check(self):
        for flags in (" --all-features", " --features", " --features a --no-default-features", " --release", " --offline",
                      " --features a;b", " --config x=y"):
            plan, problems = CK.parse_plan([self.line(flags)])
            self.assertEqual(plan, [], flags)
            self.assertTrue(problems, flags)


if __name__ == "__main__":
    unittest.main()
