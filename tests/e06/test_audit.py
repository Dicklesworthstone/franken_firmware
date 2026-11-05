"""E06 audit tests over hand-written graphs.  Expected inventories are written here, independently of the analyzer.

Three fixtures: a SMALL clean graph (every package class once, nothing to review), a CONTAMINATED graph (a native
`links` dependency, an unsafe transitive under a parent that forbids unsafe, duplicate versions, a missing license,
unpinned and missing lock data, ...: each must be reported distinctly) and small purpose-built graphs for platform
outcomes, floating point, the build plan and report hygiene.
"""
import importlib.util
import json
import os
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


AU = load("ffw_e06_audit", os.path.join(ROOT, "scripts", "e06", "audit.py"))
FX = load("ffw_e06_fixtures", os.path.join(HERE, "fixtures.py"))
Crate, Dep, Fixture = FX.Crate, FX.Dep, FX.Fixture

KEYS = ("host", "mips", "powerpc")
TRIPLES = {"host": "aarch64-apple-darwin", "mips": "mips-unknown-linux-musl", "powerpc": "powerpc-unknown-linux-musl"}
GATE = 'cfg(not(target_has_atomic = "64"))'
HEX40 = "0123456789abcdef0123456789abcdef01234567"


def platforms(fx, keys=KEYS, specs=None, replace=None):
    out = []
    for k in keys:
        if replace and k in replace:
            out.append(replace[k])
            continue
        spec = (specs or {}).get(k)
        out.append(AU.PlatformInput(k, TRIPLES[k], "resolved", "", fx.metadata(k), spec,
                                    "captured" if spec else "unavailable"))
    return out


def audit(fx, keys=KEYS, specs=None, replace=None, **kw):
    return AU.analyze(platforms(fx, keys, specs, replace), fx.lock_text(), fx.root, **kw)


def pkg(report, key):
    return next(p for p in report["packages"] if p["key"] == key)


def kinds(report, severity=None):
    return sorted({f["kind"] for f in report["findings"] if severity in (None, f["severity"])})


def find(report, kind, package=None):
    return [f for f in report["findings"] if f["kind"] == kind and (package is None or f["package"] == package)]


class Base(unittest.TestCase):
    def setUp(self):
        self._root = tempfile.TemporaryDirectory()
        self._outside = tempfile.TemporaryDirectory()
        self.root = os.path.join(self._root.name, "ws")
        self.outside = self._outside.name
        self.addCleanup(self._root.cleanup)
        self.addCleanup(self._outside.cleanup)


# ------------------------------------------------------------------------------------------------ small clean graph

def small_fixture(root, outside):
    app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                src="#![forbid(unsafe_code)]\npub fn run() {}\n",
                deps=[Dep("leaf-nostd"), Dep("leaf-std"), Dep("derive"), Dep("feat-crate"),
                      Dep("atomic-fallback", target=GATE, only={"mips", "powerpc"}), Dep("probe", kind="build")])
    fx = Fixture(root, outside, ["app@0.1.0"])
    fx.add(app,
           Crate("leaf-nostd", src="#![no_std]\npub fn id() {}\n"),
           Crate("leaf-std", src="pub fn s() {}\n"),
           Crate("derive", kinds=("proc-macro",), src="pub fn d() {}\n", deps=[Dep("helper")]),
           Crate("helper", src="pub fn h() {}\n"),
           Crate("probe", src="pub fn p() {}\n"),
           Crate("atomic-fallback", src="#![no_std]\npub fn a() {}\n"),
           Crate("feat-crate", src='#![cfg_attr(not(feature = "std"), no_std)]\npub fn f() {}\n',
                 features={"host": ["std"], "mips": ["std"], "powerpc": []}))
    fx.write()
    return fx


class SmallGraphInventoryTests(Base):
    def setUp(self):
        super().setUp()
        self.fx = small_fixture(self.root, self.outside)
        self.report = audit(self.fx)

    def test_which_packages_are_linked_into_each_target_and_which_only_run_on_the_host(self):
        # Hand-written: app plus its normal dependencies are linked; the proc-macro, its helper and the
        # build-dependency run on the host; the gated atomic fallback exists only on the two big-endian targets.
        linked_be = ["app@0.1.0", "atomic-fallback@1.0.0", "feat-crate@1.0.0", "leaf-nostd@1.0.0", "leaf-std@1.0.0"]
        s = self.report["summary"]
        self.assertEqual(s["linked"]["mips"], linked_be)
        self.assertEqual(s["linked"]["powerpc"], linked_be)
        self.assertEqual(s["linked"]["host"], ["app@0.1.0", "feat-crate@1.0.0", "leaf-nostd@1.0.0", "leaf-std@1.0.0"])
        for key in KEYS:
            self.assertEqual(s["host_only"][key], ["derive@1.0.0", "helper@1.0.0", "probe@1.0.0"])

    def test_host_only_packages_say_why(self):
        self.assertEqual(pkg(self.report, "derive@1.0.0")["platforms"]["mips"]["host_only_reason"],
                         "proc-macro used by app")
        self.assertEqual(pkg(self.report, "probe@1.0.0")["platforms"]["mips"]["host_only_reason"],
                         "build-dependency of app")
        self.assertEqual(pkg(self.report, "helper@1.0.0")["platforms"]["mips"]["host_only_reason"],
                         "proc-macro used by app")      # reached only beneath the proc-macro

    def test_roles_and_absence_per_platform(self):
        fb = pkg(self.report, "atomic-fallback@1.0.0")["platforms"]
        self.assertEqual((fb["host"]["role"], fb["mips"]["role"], fb["powerpc"]["role"]), ("absent", "linked", "linked"))
        self.assertEqual(pkg(self.report, "app@0.1.0")["platforms"]["mips"]["role"], "member")

    def test_the_gated_dependency_is_reported_with_where_it_is_active(self):
        gated = pkg(self.report, "app@0.1.0")["gated_dependencies"]
        self.assertEqual(gated, [{"dependency": "atomic-fallback", "kind": "normal", "gate": GATE, "optional": False,
                                  "active_on": {"host": False, "mips": True, "powerpc": True}}])

    def test_unsafe_is_none_for_every_package_and_the_declaration_mechanisms_are_named(self):
        for p in self.report["packages"]:
            self.assertEqual((p["unsafe"]["status"], p["unsafe"]["tokens"]), ("none", 0), p["key"])
        declared = pkg(self.report, "app@0.1.0")["unsafe"]["declared"]
        self.assertEqual([(d["mechanism"], d["level"]) for d in declared],
                         [("crate-attribute", "forbid"), ("manifest-lint (workspace)", "forbid")])
        self.assertEqual(pkg(self.report, "leaf-nostd@1.0.0")["unsafe"]["declared"], [])

    def test_std_no_std_per_target_follows_the_features_cargo_enabled_there(self):
        def std(key, plat):
            return pkg(self.report, key)["platforms"][plat]["std"]
        self.assertEqual((std("leaf-nostd@1.0.0", "mips"), std("leaf-std@1.0.0", "mips")), ("no_std", "std"))
        # feat-crate is no_std exactly when its `std` feature is off: on for mips, off for powerpc
        self.assertEqual((std("feat-crate@1.0.0", "mips"), std("feat-crate@1.0.0", "powerpc")), ("std", "no_std"))
        self.assertEqual(pkg(self.report, "derive@1.0.0")["platforms"]["mips"]["std"], "proc-macro")

    def test_effective_std_means_a_crate_is_std_if_any_linked_dependency_is(self):
        eff = lambda key, plat: pkg(self.report, key)["platforms"][plat]["effective_std"]       # noqa: E731
        self.assertEqual(eff("leaf-nostd@1.0.0", "mips"), "no_std")
        self.assertEqual(eff("app@0.1.0", "mips"), "std")                                       # app itself is std
        self.assertEqual(pkg(self.report, "app@0.1.0")["platforms"]["mips"]["effective_std_because"], "app@0.1.0")

    def test_a_clean_graph_has_nothing_to_review_and_exits_zero(self):
        self.assertEqual(kinds(self.report, "blocker"), [])
        self.assertEqual(kinds(self.report, "review"), [])
        # Information only: the 4 unevaluated candidates, the one gated dependency, the planned build checks that have
        # no result yet, and one "no target spec captured" note per big-endian target (this fixture supplies none).
        self.assertEqual(kinds(self.report, "info"),
                         ["build-check-not-run", "candidate-not-in-graph", "float-spec-unavailable", "gated-dependency"])
        self.assertEqual(AU.exit_code(self.report), 0)
        self.assertEqual(self.report["summary"]["counts"], {"blocker": 0, "review": 0, "info": 8})

    def test_pins_carry_exact_checksums_roles_and_features_and_a_digest_that_follows_them(self):
        rows = {r["package"]: r for r in self.report["pins"]["mips"]["rows"]}
        self.assertEqual(rows["leaf-std@1.0.0"]["checksum"], FX.CHECKSUM)
        self.assertEqual(rows["leaf-std@1.0.0"]["source"], FX.REGISTRY)
        self.assertEqual((rows["feat-crate@1.0.0"]["features"], rows["feat-crate@1.0.0"]["role"]), (["std"], "linked"))
        self.assertEqual(rows["app@0.1.0"]["checksum"], None)                    # a workspace path crate has none
        again = audit(self.fx)
        self.assertEqual(again["pins"]["mips"]["digest"], self.report["pins"]["mips"]["digest"])
        self.fx.crates["leaf-std@1.0.0"].checksum = "cd" * 32
        changed = audit(self.fx)
        self.assertNotEqual(changed["pins"]["mips"]["digest"], self.report["pins"]["mips"]["digest"])
        self.assertEqual(changed["pins"]["powerpc"]["digest"] == self.report["pins"]["powerpc"]["digest"], False)

    def test_pin_rows_differ_between_targets_where_the_graph_differs(self):
        host = {r["package"] for r in self.report["pins"]["host"]["rows"]}
        mips = {r["package"] for r in self.report["pins"]["mips"]["rows"]}
        self.assertEqual(mips - host, {"atomic-fallback@1.0.0"})
        self.assertNotEqual(self.report["pins"]["host"]["digest"], self.report["pins"]["mips"]["digest"])


# ------------------------------------------------------------------------------------------------ contaminated graph

LEAF_UNSAFE = "pub fn f() { unsafe { core::hint::unreachable_unchecked() } }\n"
GIT_PINNED = "git+https://example.invalid/pinned?rev=%s#%s" % (HEX40, HEX40)


def contaminated_fixture(root, outside, mid_forbids=True):
    app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                src="#![forbid(unsafe_code)]\npub fn run() {}\n",
                deps=[Dep("mid"), Dep("native-dep"), Dep("cc-user"), Dep("probe-only"), Dep("dupe", version="1.0.0"),
                      Dep("dupe", version="2.0.0"), Dep("nolicense"), Dep("badlic"), Dep("nosrc"), Dep("std-feat"),
                      Dep("git-unpinned"), Dep("git-pinned"), Dep("ext-path"), Dep("nochecksum"), Dep("notinlock"),
                      Dep("core2"), Dep("nopolicy"), Dep("hdup", version="1.0.0"),
                      Dep("hdup", version="2.0.0", kind="build")])
    fx = Fixture(root, outside, ["app@0.1.0", "core2@0.1.0", "nopolicy@0.1.0"])
    fx.add(app,
           Crate("core2", "0.1.0", where="workspace", license=None, license_file="../../LICENSE",
                 src="pub unsafe fn raw() {}\n"),
           Crate("nopolicy", "0.1.0", where="workspace", license=None, license_file="../../LICENSE",
                 src="pub fn fine() {}\n"),
           Crate("mid", src=("#![forbid(unsafe_code)]\n" if mid_forbids else "") + "pub fn m() {}\n",
                 deps=[Dep("unsafe-leaf")]),
           Crate("unsafe-leaf", src=LEAF_UNSAFE),
           Crate("native-dep", links="nativefoo", src="pub fn n() {}\n",
                 build_rs='fn main() { println!("cargo:rustc-link-lib=static=nativefoo"); }\n'),
           Crate("cc-user", src="pub fn c() {}\n", deps=[Dep("cc", kind="build")],
                 build_rs='fn main() { cc::Build::new().file("x.c").compile("x"); }\n'),
           Crate("cc", src="pub fn cc() {}\n"),
           Crate("probe-only", src="pub fn p() {}\n",
                 build_rs='fn main() { println!("cargo:rustc-cfg=has_x"); println!("cargo:rerun-if-changed=build.rs"); }\n'),
           Crate("dupe", "1.0.0", src="pub fn d() {}\n"), Crate("dupe", "2.0.0", src="pub fn d() {}\n"),
           Crate("hdup", "1.0.0", src="pub fn h() {}\n"), Crate("hdup", "2.0.0", src="pub fn h() {}\n"),
           Crate("nolicense", license=None, src="pub fn x() {}\n"),
           Crate("badlic", license=None, license_file="MISSING-LICENSE", src="pub fn x() {}\n"),
           Crate("nosrc", write_sources=False),
           Crate("std-feat", src='#![no_std]\n#[cfg(feature = "std")]\nextern crate std;\npub fn s() {}\n',
                 features={"host": ["std"], "mips": ["std"], "powerpc": []}),
           Crate("git-unpinned", source="git+https://example.invalid/loose?branch=main", checksum=None, src="pub fn g() {}\n"),
           Crate("git-pinned", source=GIT_PINNED, checksum=None, src="pub fn g() {}\n"),
           Crate("ext-path", where="external", src="pub fn e() {}\n"),
           Crate("nochecksum", checksum=None, src="pub fn x() {}\n"),
           Crate("notinlock", in_lock=False, src="pub fn x() {}\n"))
    fx.write()
    return fx


class ContaminatedGraphTests(Base):
    def setUp(self):
        super().setUp()
        self.fx = contaminated_fixture(self.root, self.outside)
        self.report = audit(self.fx)

    def test_every_planted_defect_is_reported_as_its_own_distinct_finding_with_the_right_severity(self):
        expected = {
            ("blocker", "lock-missing-checksum", "nochecksum@1.0.0"), ("blocker", "lock-missing-entry", "notinlock@1.0.0"),
            ("blocker", "unpinned-git", "git-unpinned@1.0.0"), ("blocker", "external-path-dependency", "ext-path@1.0.0"),
            ("blocker", "workspace-unsafe-linked", "core2@0.1.0"), ("blocker", "workspace-unsafe-undeclared", "nopolicy@0.1.0"),
            ("review", "native-links", "native-dep@1.0.0"), ("review", "native-build-signal", "cc-user@1.0.0"),
            ("review", "unsafe-in-dependency", "unsafe-leaf@1.0.0"), ("review", "duplicate-version", "dupe"),
            ("review", "license-missing", "nolicense@1.0.0"), ("review", "license-file-missing", "badlic@1.0.0"),
            ("review", "unsafe-unscanned", "nosrc@1.0.0"),
            ("info", "build-script", "probe-only@1.0.0"), ("info", "git-pinned", "git-pinned@1.0.0"),
            ("info", "duplicate-version-host", "hdup"),
        }
        got = {(f["severity"], f["kind"], f["package"]) for f in self.report["findings"]}
        self.assertEqual(expected - got, set())

    def test_nothing_unplanned_is_reported_as_a_blocker_or_a_review(self):
        planned = {("lock-missing-checksum", "nochecksum@1.0.0"), ("lock-missing-entry", "notinlock@1.0.0"),
                   ("unpinned-git", "git-unpinned@1.0.0"), ("external-path-dependency", "ext-path@1.0.0"),
                   ("workspace-unsafe-linked", "core2@0.1.0"), ("workspace-unsafe-undeclared", "nopolicy@0.1.0"),
                   ("native-links", "native-dep@1.0.0"), ("native-build-signal", "cc-user@1.0.0"),
                   ("unsafe-in-dependency", "unsafe-leaf@1.0.0"), ("duplicate-version", "dupe"),
                   ("license-missing", "nolicense@1.0.0"), ("license-file-missing", "badlic@1.0.0"),
                   ("unsafe-unscanned", "nosrc@1.0.0"),
                   # a crate whose source cannot be read cannot be classified std or no_std either: a real, separate
                   # consequence of the same defect, because the build plan depends on it
                   ("std-mode-undecided", "nosrc@1.0.0")}
        surprise = [(f["kind"], f["package"]) for f in self.report["findings"]
                    if f["severity"] in ("blocker", "review") and (f["kind"], f["package"]) not in planned]
        self.assertEqual(surprise, [])

    def test_a_build_script_that_only_probes_the_compiler_is_not_a_native_signal(self):
        self.assertEqual(find(self.report, "native-links", "probe-only@1.0.0"), [])
        self.assertEqual(find(self.report, "native-build-signal", "probe-only@1.0.0"), [])
        self.assertEqual(find(self.report, "build-script", "probe-only@1.0.0")[0]["severity"], "info")

    def test_native_links_and_native_build_signal_are_different_findings_with_different_evidence(self):
        links = find(self.report, "native-links", "native-dep@1.0.0")[0]["detail"]
        self.assertIn("links = 'nativefoo'", links)
        self.assertIn("rustc-link-lib", links)
        signal = find(self.report, "native-build-signal", "cc-user@1.0.0")[0]["detail"]
        self.assertIn("build-dependency on cc", signal)
        self.assertIn("build script uses cc", signal)
        self.assertNotIn("links =", signal)

    def test_an_unsafe_transitive_is_flagged_on_its_own_source_and_names_the_forbidding_parent(self):
        f = find(self.report, "unsafe-in-dependency", "unsafe-leaf@1.0.0")[0]
        self.assertEqual(f["platforms"], ["mips", "powerpc"])               # linked on both big-endian targets
        self.assertIn("1 unsafe token(s) in its own source (src/lib.rs)", f["detail"])
        self.assertIn("pulled in by mid@1.0.0", f["detail"])
        self.assertIn("the forbid(unsafe_code) of mid@1.0.0 does not cover this crate", f["detail"])

    def test_no_forbidding_parent_is_ever_flagged_for_its_childs_unsafe(self):
        self.assertEqual(find(self.report, "unsafe-in-dependency", "mid@1.0.0"), [])
        self.assertEqual(find(self.report, "unsafe-in-dependency", "app@0.1.0"), [])
        self.assertEqual((pkg(self.report, "mid@1.0.0")["unsafe"]["status"], pkg(self.report, "app@0.1.0")["unsafe"]["status"]),
                         ("none", "none"))

    def test_a_childs_unsafe_classification_does_not_depend_on_whether_its_parent_forbids_unsafe(self):
        # The same graph with `mid` NOT forbidding unsafe: the child's own record must be identical.
        with tempfile.TemporaryDirectory() as r2, tempfile.TemporaryDirectory() as o2:
            other = audit(contaminated_fixture(os.path.join(r2, "ws"), o2, mid_forbids=False))
        self.assertEqual(pkg(other, "unsafe-leaf@1.0.0")["unsafe"], pkg(self.report, "unsafe-leaf@1.0.0")["unsafe"])
        f = find(other, "unsafe-in-dependency", "unsafe-leaf@1.0.0")[0]
        self.assertEqual(f["severity"], "review")
        self.assertNotIn("does not cover this crate", f["detail"])                # no forbidding parent to name

    def test_a_workspace_crate_with_unsafe_is_a_blocker_when_others_depend_on_it_and_permitted_only_by_policy_input(self):
        self.assertEqual(find(self.report, "workspace-unsafe-linked", "core2@0.1.0")[0]["severity"], "blocker")
        permitted = audit(self.fx, unsafe_allowed={"core2"})
        self.assertEqual(find(permitted, "workspace-unsafe-linked", "core2@0.1.0"), [])
        self.assertEqual(find(permitted, "workspace-unsafe-permitted", "core2@0.1.0")[0]["severity"], "info")
        self.assertEqual(permitted["policy_inputs"], {"unsafe_allowed": ["core2"], "subject": "own", "cargo_args": [],
                                                  "scope_crates": None})

    def test_duplicate_versions_are_a_review_only_when_both_are_linked(self):
        dupe = find(self.report, "duplicate-version", "dupe")[0]
        self.assertIn("1.0.0, 2.0.0", dupe["detail"])
        self.assertEqual(find(self.report, "duplicate-version", "hdup"), [])        # one is only a build-dependency
        self.assertIn("at most one is linked", find(self.report, "duplicate-version-host", "hdup")[0]["detail"])

    def test_the_two_missing_license_cases_are_distinct(self):
        self.assertIn("no license expression or license file", find(self.report, "license-missing", "nolicense@1.0.0")[0]["detail"])
        self.assertIn("MISSING-LICENSE does not exist", find(self.report, "license-file-missing", "badlic@1.0.0")[0]["detail"])
        self.assertEqual(pkg(self.report, "app@0.1.0")["license"]["status"], "file-only")         # an existing file is fine

    def test_std_returned_by_a_feature_gated_extern_crate_is_seen_per_target(self):
        st = pkg(self.report, "std-feat@1.0.0")["platforms"]
        self.assertEqual((st["mips"]["std"], st["powerpc"]["std"]), ("std", "no_std"))
        self.assertIn("extern crate std", st["mips"]["std_why"])

    def test_a_source_that_cannot_be_read_is_unscanned_never_unsafe_free(self):
        u = pkg(self.report, "nosrc@1.0.0")["unsafe"]
        self.assertEqual((u["status"], u["tokens"]), ("unscanned", 0))

    def test_git_pins_are_told_apart_by_the_commit(self):
        self.assertIn("40-hex commit", find(self.report, "unpinned-git")[0]["detail"])
        self.assertIn("pinned to commit " + HEX40, find(self.report, "git-pinned")[0]["detail"])

    def test_the_verdict_is_blocked_and_the_counts_add_up(self):
        self.assertEqual(AU.exit_code(self.report), 1)
        c = self.report["summary"]["counts"]
        self.assertEqual(c["blocker"], len([f for f in self.report["findings"] if f["severity"] == "blocker"]))
        self.assertGreaterEqual(c["blocker"], 6)
        self.assertGreaterEqual(c["review"], 7)

    def test_with_only_review_items_left_the_exit_code_is_three_not_zero(self):
        for c in self.fx.crates.values():
            if c.name in ("nochecksum", "notinlock", "git-unpinned", "ext-path", "core2", "nopolicy"):
                c.in_lock = c.in_lock                                       # noqa: PLW0127 - keep, then drop the edges
        app = self.fx.crates["app@0.1.0"]
        drop = {"nochecksum", "notinlock", "git-unpinned", "ext-path", "core2", "nopolicy"}
        app.deps = [d for d in app.deps if d.name not in drop]
        self.fx.members = ["app@0.1.0"]
        report = audit(self.fx)
        self.assertEqual(kinds(report, "blocker"), [])
        self.assertGreater(len(kinds(report, "review")), 0)
        self.assertEqual(AU.exit_code(report), 3)


class HostIsAReferencePlatformTests(Base):
    def test_a_review_item_that_exists_only_on_the_host_is_demoted_to_info(self):
        app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                    src="#![forbid(unsafe_code)]\n", deps=[Dep("host-unsafe", only={"host"}), Dep("both-unsafe")])
        fx = Fixture(self.root, self.outside, ["app@0.1.0"])
        fx.add(app, Crate("host-unsafe", src=LEAF_UNSAFE), Crate("both-unsafe", src=LEAF_UNSAFE))
        fx.write()
        report = audit(fx)
        self.assertEqual({f["severity"] for f in find(report, "unsafe-in-dependency", "host-unsafe@1.0.0")}, {"info"})
        both = find(report, "unsafe-in-dependency", "both-unsafe@1.0.0")
        self.assertEqual(sorted((f["severity"], tuple(f["platforms"])) for f in both),
                         [("info", ("host",)), ("review", ("mips", "powerpc"))])


# ------------------------------------------------------------------------------------------------ platform outcomes

class PlatformOutcomeTests(Base):
    def setUp(self):
        super().setUp()
        self.fx = small_fixture(self.root, self.outside)

    def broken(self, outcome, detail):
        return {"powerpc": AU.PlatformInput("powerpc", TRIPLES["powerpc"], outcome, detail)}

    def test_missing_target_support_is_its_own_outcome_and_a_blocker_not_a_quiet_pass(self):
        report = audit(self.fx, replace=self.broken("target-unsupported", 'could not find specification for target "x"'))
        self.assertEqual(report["platforms"]["powerpc"]["outcome"], "target-unsupported")
        f = find(report, "target-unsupported")[0]
        self.assertEqual((f["severity"], f["platforms"]), ("blocker", ["powerpc"]))
        self.assertIn("could not find specification", f["detail"])
        self.assertEqual(AU.exit_code(report), 1)

    def test_a_resolver_failure_is_a_different_outcome_from_an_unsupported_target(self):
        report = audit(self.fx, replace=self.broken("resolver-failed", "the lock file needs to be updated"))
        self.assertEqual(report["platforms"]["powerpc"]["outcome"], "resolver-failed")
        self.assertEqual(kinds(report, "blocker"), ["resolver-failed"])
        self.assertEqual(find(report, "target-unsupported"), [])

    def test_the_platforms_that_did_resolve_are_still_fully_analyzed(self):
        report = audit(self.fx, replace=self.broken("target-unsupported", "x"))
        self.assertEqual(report["summary"]["linked"]["mips"], ["app@0.1.0", "atomic-fallback@1.0.0", "feat-crate@1.0.0",
                                                               "leaf-nostd@1.0.0", "leaf-std@1.0.0"])
        self.assertNotIn("powerpc", report["summary"]["linked"])
        self.assertNotIn("powerpc", pkg(report, "leaf-std@1.0.0")["platforms"])      # absent from the record, not "absent"
        self.assertNotIn("powerpc", report["pins"])

    def test_the_cargo_error_texts_are_classified_by_what_they_say(self):
        unknown = ('error: failed to run `rustc` ... error loading target specification: could not find '
                   'specification for target "mipsel-nonexistent-linux-gnu"')
        self.assertTrue(AU._UNKNOWN_TARGET.search(unknown))
        for other in ("error: manifest path `/nonexistent/Cargo.toml` does not exist",
                      "error: the lock file /x/Cargo.lock needs to be updated but --locked was passed",
                      "error: no matching package named `foo` found (offline)"):
            self.assertIsNone(AU._UNKNOWN_TARGET.search(other), other)


# ------------------------------------------------------------------------------------------------ floating point and atomics

MIPS_SPEC = {"llvm-target": TRIPLES["mips"], "arch": "mips", "cpu": "mips32r2", "features": "+mips32r2,+soft-float",
             "max-atomic-width": 32, "target-endian": "big"}
PPC_SPEC = {"llvm-target": TRIPLES["powerpc"], "arch": "powerpc", "max-atomic-width": 32, "target-endian": "big"}
HOST_SPEC = {"llvm-target": TRIPLES["host"], "arch": "aarch64", "max-atomic-width": 128}


class FloatingPointTests(Base):
    def make(self, workspace_float=True):
        body = "pub fn gain(x: f32) -> f32 { x * 0.5 }\n" if workspace_float else "pub fn gain(x: u32) -> u32 { x }\n"
        app = Crate("dsp", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                    src="#![forbid(unsafe_code)]\n" + body, deps=[Dep("fmt-float"), Dep("plain")])
        fx = Fixture(self.root, self.outside, ["dsp@0.1.0"])
        fx.add(app, Crate("fmt-float", src="pub fn f(x: f64) -> f64 { x }\n"), Crate("plain", src="pub fn p() {}\n"))
        fx.write()
        return fx

    SPECS = {"host": HOST_SPEC, "mips": MIPS_SPEC, "powerpc": PPC_SPEC}

    def test_the_compilers_own_spec_decides_soft_float_and_nothing_else_does(self):
        report = audit(self.make(), specs=self.SPECS)
        self.assertEqual(report["platforms"]["mips"]["float"], "soft-float")
        self.assertEqual(report["platforms"]["powerpc"]["float"], "no soft-float feature in the compiler's target spec")
        self.assertEqual(report["platforms"]["mips"]["target_spec"]["cpu"], "mips32r2")

    def test_our_own_crate_using_floats_on_the_soft_float_target_is_a_review_that_names_both_groups(self):
        f = find(audit(self.make(), specs=self.SPECS), "float-on-soft-float")
        self.assertEqual([(x["severity"], x["platforms"]) for x in f], [("review", ["mips"])])
        self.assertIn("workspace: dsp@0.1.0; dependencies: fmt-float@1.0.0", f[0]["detail"])
        self.assertNotIn("plain", f[0]["detail"])

    def test_when_only_a_dependency_uses_floats_the_soft_float_note_is_information_not_a_decision(self):
        f = find(audit(self.make(workspace_float=False), specs=self.SPECS), "float-on-soft-float")
        self.assertEqual([x["severity"] for x in f], ["info"])
        self.assertIn("workspace: none; dependencies: fmt-float@1.0.0", f[0]["detail"])

    def test_powerpc_says_the_hardware_fpu_is_not_established_instead_of_claiming_one(self):
        report = audit(self.make(), specs=self.SPECS)
        self.assertEqual(find(report, "float-on-soft-float")[0]["platforms"], ["mips"])
        usage = find(report, "float-usage")[0]
        self.assertEqual(usage["platforms"], ["powerpc"])
        self.assertIn("no soft-float feature", usage["detail"])
        self.assertIn("not established", find(report, "fp-isa-hardware-unknown")[0]["detail"])
        self.assertEqual(find(report, "fp-isa-hardware-unknown")[0]["platforms"], ["powerpc"])   # never for the host

    def test_no_native_atomic64_is_recorded_for_both_big_endian_targets(self):
        f = find(audit(self.make(), specs=self.SPECS), "no-native-atomic64")
        self.assertEqual(sorted(p for x in f for p in x["platforms"]), ["mips", "powerpc"])
        self.assertIn("max-atomic-width 32", f[0]["detail"])

    def test_a_missing_target_spec_is_stated_not_guessed(self):
        report = audit(self.make(), specs=None)
        self.assertEqual(report["platforms"]["mips"]["float"], None)
        self.assertEqual(sorted(p for x in find(report, "float-spec-unavailable") for p in x["platforms"]), ["mips", "powerpc"])
        self.assertEqual(find(report, "float-on-soft-float"), [])


# ------------------------------------------------------------------------------------------------ build plan

def plan_fixture(root, outside):
    def ws(name, src, deps):
        return Crate(name, "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                     src=src, deps=[Dep(d) for d in deps])
    fx = Fixture(root, outside, ["nostd-ws@0.1.0", "std-ws@0.1.0", "mixed-ws@0.1.0"])
    fx.add(ws("nostd-ws", "#![no_std]\n#![forbid(unsafe_code)]\n", ["leaf-nostd"]),
           ws("std-ws", "#![forbid(unsafe_code)]\n", ["leaf-std"]),
           ws("mixed-ws", "#![no_std]\n#![forbid(unsafe_code)]\n", ["leaf-std"]),
           Crate("leaf-nostd", src="#![no_std]\n"), Crate("leaf-std", src="pub fn s() {}\n"))
    fx.write()
    return fx


class BuildPlanTests(Base):
    def setUp(self):
        super().setUp()
        self.report = audit(plan_fixture(self.root, self.outside))
        self.rows = {(r["crate"], r["target"]): r for r in self.report["build_checks"]["rows"]}

    def cmd(self, crate, triple, std_set):
        return ("RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked --release -p %s --target %s -Z build-std=%s"
                % (crate, triple, std_set))

    def test_one_check_per_workspace_crate_per_big_endian_target_and_none_for_the_host(self):
        self.assertEqual(self.report["build_checks"]["planned"], 6)
        self.assertEqual({t for _, t in self.rows}, {TRIPLES["mips"], TRIPLES["powerpc"]})

    def test_a_crate_whose_whole_linked_closure_is_no_std_gets_core_and_alloc_only(self):
        self.assertEqual(self.rows[("nostd-ws", TRIPLES["mips"])]["command"], self.cmd("nostd-ws", TRIPLES["mips"], "core,alloc"))

    def test_a_std_crate_and_a_no_std_crate_with_a_std_dependency_both_get_std(self):
        for crate in ("std-ws", "mixed-ws"):
            for plat in ("mips", "powerpc"):
                self.assertEqual(self.rows[(crate, TRIPLES[plat])]["command"],
                                 self.cmd(crate, TRIPLES[plat], "std,panic_abort"), (crate, plat))

    def test_jobs_appends_dash_j_to_every_planned_command_and_omitting_it_changes_nothing(self):
        # RCH ignores CARGO_BUILD_JOBS when it admits a build against a worker's slots, so the count must be in the command.
        plain = [r["command"] for r in self.report["build_checks"]["rows"]]
        capped = audit(plan_fixture(self.root + "j", self.outside), jobs=2)
        self.assertEqual([r["command"] for r in capped["build_checks"]["rows"]], [c + " -j 2" for c in plain])
        self.assertTrue(all("-j" not in c for c in plain))

    def test_every_planned_check_starts_not_run_and_that_is_counted_not_hidden(self):
        bc = self.report["build_checks"]
        self.assertEqual(bc["counts"], {"pass": 0, "fail": 0, "not-run": 6, "conflicting": 0})
        self.assertIn("6 of 6 planned minimal-graph checks have no result", find(self.report, "build-check-not-run")[0]["detail"])

    def fold(self, results):
        return audit(plan_fixture(self.root + "x", self.outside), build_results=results)

    def test_supplied_results_turn_into_pass_and_a_failure_is_a_blocker(self):
        mips = TRIPLES["mips"]
        report = self.fold([{"crate": "std-ws", "target": mips, "status": "pass", "evidence": "sha256:aa"},
                            {"crate": "mixed-ws", "target": mips, "status": "fail", "note": "E0463 can't find crate for `std`"}])
        rows = {(r["crate"], r["target"]): r for r in report["build_checks"]["rows"]}
        self.assertEqual(rows[("std-ws", mips)]["status"], "pass")
        self.assertEqual(rows[("std-ws", mips)]["evidence"], "sha256:aa")
        self.assertEqual(report["build_checks"]["counts"], {"pass": 1, "fail": 1, "not-run": 4, "conflicting": 0})
        f = find(report, "does-not-build", "mixed-ws")[0]
        self.assertEqual((f["severity"], f["platforms"]), ("blocker", ["mips"]))
        self.assertIn("E0463", f["detail"])
        self.assertEqual(find(report, "does-not-build", "std-ws"), [])

    def test_two_results_that_disagree_are_conflicting_and_blocking(self):
        mips = TRIPLES["mips"]
        report = self.fold([{"crate": "std-ws", "target": mips, "status": "pass"},
                            {"crate": "std-ws", "target": mips, "status": "fail"}])
        self.assertEqual(report["build_checks"]["counts"]["conflicting"], 1)
        self.assertEqual(find(report, "build-check-conflicting", "std-ws")[0]["severity"], "blocker")

    def test_results_for_something_not_in_the_plan_or_with_a_made_up_status_are_rejected_not_counted(self):
        mips = TRIPLES["mips"]
        report = self.fold([{"crate": "no-such-crate", "target": mips, "status": "pass"},
                            {"crate": "std-ws", "target": "arm-unknown-linux-gnueabi", "status": "pass"},
                            {"crate": "std-ws", "target": mips, "status": "ok"}])
        bc = report["build_checks"]
        self.assertEqual(len(bc["rejected_results"]), 3)
        self.assertEqual(bc["counts"], {"pass": 0, "fail": 0, "not-run": 6, "conflicting": 0})


# ------------------------------------------------------------------------------------------------ candidates and hygiene

class ScrubPathsTests(unittest.TestCase):
    def test_the_workspace_root_and_the_home_directory_never_survive_into_a_report(self):
        root = "/work/people/someone/proj/ws"
        text = "error: cannot update the lock file %s/Cargo.lock; cache /home/someone/.cargo/registry" % root
        saved = os.environ.get("HOME")
        os.environ["HOME"] = "/home/someone"
        try:
            scrubbed = AU.scrub_paths(text, [root])
        finally:
            if saved is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = saved
        self.assertEqual(scrubbed, "error: cannot update the lock file <workspace>/Cargo.lock; cache ~/.cargo/registry")

    def test_the_longest_root_wins_and_unrelated_text_is_untouched(self):
        # Hand-derived: the longer root "/r/ws" goes first and takes "/r/ws/x"; the shorter "/r" then takes the rest.
        self.assertEqual(AU.scrub_paths("a /r/ws/x /r/ws2/y", ["/r", "/r/ws"]), "a <workspace>/x <workspace>/ws2/y")
        # A root only matches at a path boundary: "/r/ws" must not eat the start of the different directory "/r/ws2".
        self.assertEqual(AU.scrub_paths("see /r/ws2/y and /r/ws/z", ["/r/ws"]), "see /r/ws2/y and <workspace>/z")
        self.assertEqual(AU.scrub_paths("nothing to hide here", ["/r/ws"]), "nothing to hide here")
        self.assertEqual(AU.scrub_paths("keep /elsewhere/file", [""]), "keep /elsewhere/file")


class PlanRefusalTests(Base):
    """`plan` must never turn "could not plan" into an empty list and exit 0.  In the real repository cargo could not
    resolve any platform (a worktree manifest changed without a lock update), the plan had no rows, and it printed
    nothing and exited 0: a silent no-op that reads as 'nothing to check'."""

    LOCK_ERROR = ("error: cannot update the lock file /x/Cargo.lock because --locked was passed to prevent this")

    def failed(self, outcome="resolver-failed", keys=KEYS, detail=None):
        return {k: AU.PlatformInput(k, TRIPLES[k], outcome, detail or self.LOCK_ERROR) for k in keys}

    def test_a_healthy_plan_is_returned_whole_with_no_refusals(self):
        lines, refusals = AU.plan_lines(audit(plan_fixture(self.root, self.outside)))
        self.assertEqual(refusals, [])
        self.assertEqual(len(lines), 6)
        self.assertTrue(all(l.startswith("RCH_REQUIRE_REMOTE=1 rch exec -- cargo +nightly check --locked") for l in lines))

    def test_when_no_platform_resolves_the_plan_is_refused_naming_each_platform_and_the_cause(self):
        fx = plan_fixture(self.root, self.outside)
        lines, refusals = AU.plan_lines(audit(fx, replace=self.failed()))
        self.assertEqual(lines, [])
        self.assertEqual(len(refusals), 3)
        for key, why in zip(KEYS, refusals):
            self.assertIn("%s (%s) is resolver-failed" % (key, TRIPLES[key]), why)
            self.assertIn("cannot update the lock file", why)
            self.assertIn("Cargo.lock does not match the manifests in this tree", why)      # the actionable hint

    def test_one_failed_big_endian_platform_refuses_the_whole_plan_not_half_of_it(self):
        fx = plan_fixture(self.root, self.outside)
        report = audit(fx, replace=self.failed("target-unsupported", keys=("powerpc",),
                                                detail='could not find specification for target "x"'))
        self.assertEqual(len(report["build_checks"]["rows"]), 3)                  # mips alone would still produce rows
        lines, refusals = AU.plan_lines(report)
        self.assertEqual(lines, [])                                              # but a half plan is not offered
        self.assertEqual(len(refusals), 1)
        self.assertIn("powerpc", refusals[0])
        self.assertIn("target-unsupported", refusals[0])
        self.assertNotIn("Cargo.lock does not match", refusals[0])                # no lock hint for a non-lock cause

    def test_a_resolved_graph_with_no_workspace_crate_is_an_empty_plan_and_refused(self):
        fx = Fixture(self.root, self.outside, [])
        fx.add(Crate("orphan", src="pub fn o() {}\n"))
        fx.write()
        report = audit(fx)
        self.assertEqual(report["build_checks"]["planned"], 0)
        lines, refusals = AU.plan_lines(report)
        self.assertEqual(lines, [])
        self.assertEqual(len(refusals), 1)
        self.assertIn("the plan is empty", refusals[0])

    def test_the_audit_verdict_for_the_same_stale_state_is_already_blocked_so_the_two_commands_agree(self):
        report = audit(plan_fixture(self.root, self.outside), replace=self.failed())
        self.assertEqual(AU.exit_code(report), 1)
        self.assertEqual(kinds(report, "blocker"), ["resolver-failed"])


class CandidateTests(Base):
    def test_candidates_not_in_the_graph_are_recorded_unevaluated_with_what_would_evaluate_them(self):
        report = audit(small_fixture(self.root, self.outside))
        by = {c["name"]: c for c in report["candidates"]}
        self.assertEqual(sorted(by), ["asupersync", "codecs", "franken_kernel", "libc candidates",
                                      "libc crate (Rust FFI binding table)"])
        for c in by.values():
            self.assertEqual(c["status"], "not in graph; unevaluated")
            self.assertEqual(c["in_graph"], [])
            self.assertTrue(c["evaluate_with"])
        self.assertIn("runtime-core", by["asupersync"]["evaluate_with"])
        self.assertIn("function by function", by["libc candidates"]["evaluate_with"])
        # Four candidates are unevaluated; the Rust libc FFI crate is informational, so its absence is not a finding.
        self.assertEqual(len(find(report, "candidate-not-in-graph")), 4)
        self.assertFalse(any(f["package"] == "libc crate (Rust FFI binding table)" for f in report["findings"]))

    def libc_fixture(self, only=None, kind=None):
        app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                    src="#![forbid(unsafe_code)]\n", deps=[Dep("libc", only=only, kind=kind)])
        fx = Fixture(self.root, self.outside, ["app@0.1.0"])
        fx.add(app, Crate("libc", "0.2.191", src="pub fn l() {}\n"))
        fx.write()
        return fx

    def test_the_rust_libc_crate_is_an_ffi_table_not_a_libc_candidate_and_is_linked_where_it_is_linked(self):
        report = audit(self.libc_fixture())
        by = {c["name"]: c for c in report["candidates"]}
        # FrankenLibC is not in the graph just because a crate called libc is: the two rows must not be confused.
        self.assertEqual(by["libc candidates"]["status"], "not in graph; unevaluated")
        self.assertEqual(by["libc candidates"]["in_graph"], [])
        ffi = by["libc crate (Rust FFI binding table)"]
        self.assertEqual(ffi["in_graph"], ["libc@0.2.191"])
        self.assertEqual(ffi["status"], "linked into the firmware graph of: mips, powerpc (see packages)")
        self.assertEqual(sorted(ffi["on_platforms"]), ["host", "mips", "powerpc"])
        # Linked into a big-endian target is a decision for a human: which functions are called through it.
        flagged = find(report, "ffi-binding-table-linked")
        self.assertEqual(sorted(p for f in flagged for p in f["platforms"]), ["mips", "powerpc"])
        self.assertTrue(all(f["severity"] == "review" for f in flagged))
        self.assertEqual(by["codecs"]["status"], "not in graph; unevaluated")

    def test_libc_present_only_on_the_host_reference_platform_is_not_in_the_firmware_graph(self):
        report = audit(self.libc_fixture(only=["host"]))
        ffi = {c["name"]: c for c in report["candidates"]}["libc crate (Rust FFI binding table)"]
        self.assertEqual(ffi["status"], "present only on the reference platform (host); absent from every big-endian target graph")
        self.assertEqual(sorted(ffi["on_platforms"]), ["host"])
        self.assertEqual(find(report, "ffi-binding-table-linked"), [])             # nothing to decide for the firmware
        self.assertEqual([f["severity"] for f in find(report, "candidate-not-linked-on-firmware")], ["info"])

    def test_a_build_time_only_libc_is_not_called_linked(self):
        report = audit(self.libc_fixture(kind="build"))
        ffi = {c["name"]: c for c in report["candidates"]}["libc crate (Rust FFI binding table)"]
        self.assertIn("only as a build-host dependency, not linked into the firmware", ffi["status"])
        self.assertEqual(find(report, "ffi-binding-table-linked"), [])

    def test_a_real_libc_candidate_in_the_graph_is_reported_in_graph_with_the_matching_package(self):
        app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                    src="#![forbid(unsafe_code)]\n", deps=[Dep("frankenlibc")])
        fx = Fixture(self.root, self.outside, ["app@0.1.0"])
        fx.add(app, Crate("frankenlibc", "0.1.0", src="pub fn l() {}\n"))
        fx.write()
        report = audit(fx)
        by = {c["name"]: c for c in report["candidates"]}
        self.assertEqual((by["libc candidates"]["status"], by["libc candidates"]["in_graph"]),
                         ("linked into the firmware graph of: mips, powerpc (see packages)", ["frankenlibc@0.1.0"]))
        self.assertEqual(by["libc crate (Rust FFI binding table)"]["status"], "not in graph; unevaluated")
        self.assertEqual(sorted(p for f in find(report, "candidate-in-graph") for p in f["platforms"]), ["mips", "powerpc"])
        self.assertEqual(find(report, "ffi-binding-table-linked"), [])
        self.assertEqual(by["codecs"]["status"], "not in graph; unevaluated")


class NoStdWithTestOnlyStdTests(Base):
    """franken_kernel is `#![no_std]` + `extern crate alloc`, and its `mod tests` has `extern crate std;`. That is std in
    tests only: the crate itself is no_std (and not allocation-free, which is a different question)."""

    def report_for(self, src):
        app = Crate("app", "0.1.0", where="workspace", workspace_lints=True, license=None, license_file="../../LICENSE",
                    src="#![forbid(unsafe_code)]\n", deps=[Dep("kern")])
        fx = Fixture(self.root, self.outside, ["app@0.1.0"])
        fx.add(app, Crate("kern", "0.6.0", src=src))
        fx.write()
        return audit(fx)

    def test_a_test_only_extern_crate_std_leaves_the_crate_no_std_and_records_its_alloc(self):
        report = self.report_for("#![no_std]\nextern crate alloc;\nuse alloc::string::String;\n"
                                 "#[cfg(test)]\nmod tests {\n    extern crate std;\n}\n")
        kern = pkg(report, "kern@0.6.0")
        for key in ("mips", "powerpc"):
            self.assertEqual(kern["platforms"][key]["std"], "no_std", key)
        self.assertTrue(kern["references_alloc"])            # no_std is not no allocation

    def test_the_same_extern_crate_std_outside_a_test_gate_still_makes_the_crate_std(self):
        for src in ("#![no_std]\nmod m {\n    extern crate std;\n}\n", "#![no_std]\nextern crate std;\n"):
            report = self.report_for(src)
            self.assertEqual(pkg(report, "kern@0.6.0")["platforms"]["mips"]["std"], "std", src)

    def test_an_enclosing_feature_gate_is_decided_by_the_features_cargo_enabled(self):
        report = self.report_for('#![no_std]\n#[cfg(feature = "std")]\nmod m {\n    extern crate std;\n}\n')
        # the fixture enables no `std` feature on kern, so the gated std does not hold
        self.assertEqual(pkg(report, "kern@0.6.0")["platforms"]["mips"]["std"], "no_std")


class ReportHygieneTests(Base):
    def test_the_report_is_deterministic_and_leaks_no_absolute_path(self):
        fx = contaminated_fixture(self.root, self.outside)
        a, b = audit(fx), audit(fx)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        text = json.dumps(a)
        for leaked in (self.root, self.outside, os.path.expanduser("~"), "/private/var", "/tmp/"):
            self.assertNotIn(leaked, text, leaked)

    def test_the_tool_never_claims_to_admit_anything(self):
        report = audit(small_fixture(self.root, self.outside))
        text = json.dumps(report)
        self.assertNotIn('"admitted"', text)
        self.assertIn("not admitted by this tool", AU.render(report))

    def test_render_lists_blockers_and_reviews_but_not_info_and_states_the_lock_digest(self):
        fx = contaminated_fixture(self.root, self.outside)
        out = AU.render(audit(fx))
        self.assertIn("BLOCKER  lock-missing-checksum", out)
        self.assertIn("REVIEW   unsafe-in-dependency", out)
        self.assertNotIn("INFO", out)
        self.assertIn("Cargo.lock sha256=", out)


if __name__ == "__main__":
    unittest.main()
