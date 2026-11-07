"""E06 audit tests over hand-written graphs.  Expected inventories are written here, independently of the analyzer.

Three fixtures: a SMALL clean graph (every package class once, nothing to review), a CONTAMINATED graph (a native
`links` dependency, an unsafe transitive under a parent that forbids unsafe, duplicate versions, a missing license,
unpinned and missing lock data, ...: each must be reported distinctly) and small purpose-built graphs for platform
outcomes, floating point, the build plan and report hygiene.
"""
import builtins
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
import signal
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

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
                # They leave the lock with their edges. A locked registry entry that no graph links must still be pinned and
                # inventoried (see UnlinkedLockedPackageTests), so one with no checksum or a git source would be a blocker here.
                c.in_lock = False
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


# ------------------------------------------------------------------------------------------------ locked, linked nowhere

class UnlinkedLockedPackageTests(Base):
    """A Cargo.lock entry that no platform graph links (a gated dependency inactive everywhere) is still pinned and inventoried,
    from its cargo source, once the cached archive is proved to be the locked one. Expected facts are written here, from the
    source text each world writes, not read back from the analyzer. Every refusal is paired with the permitted positive."""

    INDEX = "index.crates.io-test"
    KEY = "gated-sys@0.2.0"
    LIB = "pub fn read(x: &u8) -> u8 {\n    unsafe { core::ptr::read(x) }\n}\n"
    MANIFEST = '[package]\nname = "gated-sys"\nversion = "0.2.0"\nlicense = "MIT OR Apache-2.0"\n'

    def world(self, *, lock_checksum=None, archive=True, tamper=None, source=None, listed=True, listing="resolved",
              extra_tar=None, checksum_line=True, write_src=True, not_on_disk=(), replace=None,
              manifest=None, extra_files=None, metadata_edit=None, after_verify=None):
        """(report, lock_text, sha256 of the archive). A cargo-shaped registry cache holding one crate that the lock names and
        no platform links, beside the small clean graph. Every call builds its own cache directory. ``write_src=False`` leaves
        the extracted directory out; ``not_on_disk`` leaves named files out of it (the archive still holds them). ``manifest`` and
        ``extra_files`` change what the archive (and the directory) hold; ``metadata_edit`` edits the listing cargo is imagined to have
        produced; ``after_verify`` is called with the extracted directory right after the verification returns, i.e. it writes into the
        cache in the window the snapshot closes."""
        self.fx = small_fixture(self.root, self.outside)
        reg = os.path.join(tempfile.mkdtemp(prefix="cargo-home-", dir=self.outside), "registry")
        src = os.path.join(reg, "src", self.INDEX, "gated-sys-0.2.0")
        self.src = src
        files = {"Cargo.toml": manifest or self.MANIFEST, "src/lib.rs": self.LIB}
        files.update(extra_files or {})
        if write_src:
            os.makedirs(os.path.join(src, "src"))
            for rel, text in files.items():
                if rel not in not_on_disk:
                    os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
                    with open(os.path.join(src, rel), "w") as fh:
                        fh.write(text)
            with open(os.path.join(src, ".cargo-ok"), "w") as fh:
                fh.write('{"v":1}')
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for rel, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo("gated-sys-0.2.0/" + rel)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            if extra_tar:
                extra_tar(tf)
        blob = buf.getvalue()
        sha = hashlib.sha256(blob).hexdigest()
        if archive:
            os.makedirs(os.path.join(reg, "cache", self.INDEX))
            with open(os.path.join(reg, "cache", self.INDEX, "gated-sys-0.2.0.crate"), "wb") as fh:
                fh.write(blob)
        if tamper:
            tamper(src)
        src_id = source or FX.REGISTRY
        lock = self.fx.lock_text() + '[[package]]\nname = "gated-sys"\nversion = "0.2.0"\nsource = "%s"\n%s\n' % (
            src_id, ('checksum = "%s"\n' % (lock_checksum or sha)) if checksum_line else "")
        pkg_listing = {"id": src_id + "#gated-sys@0.2.0", "name": "gated-sys", "version": "0.2.0", "source": src_id,
                       "license": "MIT OR Apache-2.0", "license_file": None, "links": None, "dependencies": [],
                       "manifest_path": os.path.join(src, "Cargo.toml"),
                       "targets": [{"kind": ["lib"], "name": "gated_sys", "src_path": os.path.join(src, "src", "lib.rs")}]}
        if metadata_edit:
            metadata_edit(pkg_listing)
        self.pkg_listing = pkg_listing
        locked = AU.LockedSources(listing, {"packages": [pkg_listing] if listed else []} if listing == "resolved" else None,
                                  "" if listing == "resolved" else "cargo exited 101")
        if after_verify is None:
            return AU.analyze(platforms(self.fx, replace=replace), lock, self.fx.root, locked=locked), lock, sha
        real_verify = AU.verify_registry_source

        def verify_then_write(listed_pkg, checksum, snapshot=None):
            result = real_verify(listed_pkg, checksum, snapshot)
            after_verify(os.path.dirname(listed_pkg["manifest_path"]))
            return result
        with mock.patch.object(AU, "verify_registry_source", verify_then_write):
            return AU.analyze(platforms(self.fx, replace=replace), lock, self.fx.root, locked=locked), lock, sha

    def pins(self, report, plat):
        return {r["package"]: r for r in report["pins"][plat]["rows"]}

    # -- the permitted positive: the entry is inventoried, labelled, and reaches nothing
    def test_a_locked_package_that_no_platform_links_is_inventoried_from_its_verified_source(self):
        report, lock, sha = self.world()
        rec = pkg(report, self.KEY)
        self.assertEqual((rec["source_kind"], rec["pin"]), ("registry", {"source": FX.REGISTRY, "checksum": sha, "in_lock": True}))
        self.assertEqual((rec["license"]["status"], rec["license"]["expression"]), ("declared", "MIT OR Apache-2.0"))
        self.assertEqual((rec["unsafe"]["status"], rec["unsafe"]["tokens"], sorted(rec["unsafe"]["files"])),
                         ("present", 1, ["src/lib.rs"]))
        self.assertEqual(rec["unlinked"]["source_verified"], {"archive_sha256": sha, "files_in_archive": 2, "files_compared": 2})
        self.assertEqual({k: v["role"] for k, v in rec["platforms"].items()},
                         {"host": "absent", "mips": "absent", "powerpc": "absent"})
        for plat in KEYS:
            row = self.pins(report, plat)[self.KEY]
            self.assertEqual((row["source"], row["checksum"], row["role"]), (FX.REGISTRY, sha, "unlinked"), plat)
            self.assertNotIn(self.KEY, report["summary"]["linked"][plat])
            self.assertNotIn(self.KEY, report["summary"]["host_only"][plat])
        note = find(report, "unlinked-locked-package", self.KEY)
        self.assertEqual([f["severity"] for f in note], ["info"])
        self.assertIn("1 unsafe token(s) in src/lib.rs", note[0]["detail"])
        self.assertIn(self.KEY, find(report, "lock-unused-entries")[0]["detail"])           # the information note stays
        self.assertEqual(kinds(report, "blocker"), [])
        self.assertNotEqual(AU.exit_code(report), 1)
        self.assertNotIn(self.outside, json.dumps(report))

    def test_without_the_lock_wide_listing_an_own_audit_with_an_unused_entry_is_blocked_and_the_rest_of_the_report_is_unchanged(self):
        report, lock, _ = self.world()
        before = AU.analyze(platforms(self.fx), lock, self.fx.root)     # the library default: no lock-wide listing supplied
        self.assertEqual([(f["kind"], f["package"], f["severity"]) for f in before["findings"] if f["severity"] == "blocker"],
                         [("lock-entry-not-located", self.KEY, "blocker")])
        self.assertIn("no lock-wide source listing was supplied", find(before, "lock-entry-not-located")[0]["detail"])
        self.assertEqual(AU.exit_code(before), 1)
        self.assertEqual([p for p in before["packages"] if p["key"] == self.KEY], [], "a record was fabricated")
        self.assertNotIn(self.KEY, self.pins(before, "mips"))
        self.assertEqual([p["key"] for p in report["packages"] if "unlinked" in p], [self.KEY])
        self.assertEqual([p for p in report["packages"] if "unlinked" not in p], before["packages"])
        self.assertEqual([f for f in report["findings"] if f["kind"] != "unlinked-locked-package"],
                         [f for f in before["findings"] if f["kind"] != "lock-entry-not-located"])
        self.assertEqual(report["summary"]["linked"], before["summary"]["linked"])
        self.assertEqual(report["summary"]["host_only"], before["summary"]["host_only"])

    def test_the_missing_listing_blocks_nothing_when_no_entry_is_unused_and_not_an_upstream_or_scoped_audit(self):
        clean = small_fixture(self.root, self.outside)                  # the permitted positive: every locked entry is linked, no listing needed
        report = AU.analyze(platforms(clean), clean.lock_text(), clean.root)
        self.assertEqual(kinds(report, "blocker"), [])
        self.assertEqual(find(report, "lock-unused-entries"), [])
        _, lock, _ = self.world()                                       # an unused registry entry now exists in the lock
        upstream = AU.analyze(platforms(self.fx), lock, self.fx.root, subject="upstream")
        scoped = AU.analyze(platforms(self.fx), lock, self.fx.root, scope_crates=["app"])
        for label, other in (("upstream", upstream), ("scoped", scoped)):
            self.assertEqual(find(other, "lock-entry-not-located"), [], label)
            self.assertEqual(find(other, "unlinked-locked-package"), [], label)
            self.assertEqual([f["severity"] for f in find(other, "lock-unused-entries")], ["info"], label)

    # -- refusals: the source cannot be proved to be the locked one, so nothing is inventoried for it
    def refused(self, kind, **opt):
        report, _, _ = self.world(**opt)
        self.assertEqual([f["package"] for f in find(report, kind)], [self.KEY], kind)
        self.assertEqual(find(report, kind)[0]["severity"], "blocker")
        self.assertEqual(find(report, "unlinked-locked-package"), [], "an unproved entry is not reported as inventoried")
        self.assertEqual([p for p in report["packages"] if p["key"] == self.KEY], [], "a record was fabricated")
        for plat in KEYS:
            self.assertNotIn(self.KEY, self.pins(report, plat), "a pin row was fabricated")
        self.assertEqual(AU.exit_code(report), 1)
        self.assertNotIn(self.outside, json.dumps(report))
        return report

    def test_a_cached_archive_that_does_not_match_the_lock_checksum_is_refused(self):
        report = self.refused("lock-entry-checksum-mismatch", lock_checksum="00" * 32)
        self.assertIn("hashes to", find(report, "lock-entry-checksum-mismatch")[0]["detail"])

    def test_a_missing_cached_archive_or_source_directory_is_refused(self):
        self.refused("lock-entry-source-missing", archive=False)
        self.refused("lock-entry-source-missing", write_src=False)

    def test_an_extracted_source_that_differs_from_its_archive_is_refused(self):
        def edit(src):
            with open(os.path.join(src, "src", "lib.rs"), "a") as fh:
                fh.write("// planted\n")

        def extra(src):
            with open(os.path.join(src, "src", "planted.rs"), "w") as fh:
                fh.write("pub fn p() {}\n")
        for label, opt in (("edited file", {"tamper": edit}), ("extra file", {"tamper": extra}),
                           ("file missing", {"not_on_disk": ("src/lib.rs",)})):
            with self.subTest(label):
                self.refused("lock-entry-source-differs", **opt)

    def test_an_archive_with_a_path_that_escapes_the_crate_or_a_member_that_is_not_a_plain_file_is_refused(self):
        def escape(tf):
            info = tarfile.TarInfo("gated-sys-0.2.0/../escape.rs")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))

        def link(tf):                              # an empty file and a symbolic link to it: every byte comparison below passes on both
            tf.addfile(tarfile.TarInfo("gated-sys-0.2.0/src/empty.rs"))
            info = tarfile.TarInfo("gated-sys-0.2.0/src/link.rs")
            info.type, info.linkname = tarfile.SYMTYPE, "empty.rs"
            tf.addfile(info)
        def escape_on_disk(src):                  # the file sits where the hostile name points, so only the name check can refuse it
            with open(os.path.join(os.path.dirname(src), "escape.rs"), "w") as fh:
                fh.write("x")

        def link_on_disk(src):                    # both are empty files on disk, so only the member-type check can refuse the archive
            for name in ("empty.rs", "link.rs"):
                with open(os.path.join(src, "src", name), "w"):
                    pass
        for label, extra_tar, tamper in (("parent traversal", escape, escape_on_disk), ("symbolic link", link, link_on_disk)):
            with self.subTest(label):
                self.refused("lock-entry-source-differs", extra_tar=extra_tar, tamper=tamper)

    def test_an_entry_the_lock_wide_listing_does_not_name_or_could_not_be_read_is_blocked_not_invented(self):
        self.refused("lock-entry-not-located", listed=False)
        report = self.refused("lock-entry-not-located", listing="resolver-failed")
        self.assertIn("resolver-failed", find(report, "lock-entry-not-located")[0]["detail"])

    def test_a_git_sourced_or_checksumless_entry_cannot_be_tied_to_a_checksum_and_is_blocked(self):
        self.refused("lock-entry-unsupported-source", source="git+https://example.invalid/gated-sys#" + HEX40)
        self.refused("lock-missing-checksum", checksum_line=False)

    def test_a_platform_that_did_not_resolve_leaves_the_audit_blocked_for_that_alone_and_claims_nothing_about_unlinked_entries(self):
        failed = {"mips": AU.PlatformInput("mips", TRIPLES["mips"], "resolver-failed", "cargo could not resolve it")}
        report, _, _ = self.world(replace=failed)
        self.assertEqual(kinds(report, "blocker"), ["resolver-failed"])         # the entry might be linked on the platform that failed
        self.assertEqual(find(report, "unlinked-locked-package"), [])
        self.assertEqual([p for p in report["packages"] if p["key"] == self.KEY], [])
        ok, _, _ = self.world()                                                  # the permitted positive: all three resolve
        self.assertIn("unlinked", pkg(ok, self.KEY))

    # -- activation: the label belongs to this run's graphs alone
    def test_a_package_a_later_graph_links_gets_an_ordinary_linked_record_and_inherits_nothing(self):
        report, lock, sha = self.world()
        self.assertIn("unlinked", pkg(report, self.KEY))                     # unlinked in this graph
        fx = small_fixture(self.root + "-b", self.outside)
        fx.crates["app@0.1.0"].deps.append(Dep("gated-sys", only={"mips"}))
        fx.add(Crate("gated-sys", "0.2.0", src=self.LIB, license="MIT OR Apache-2.0"))
        fx.write()
        stale = AU.LockedSources("resolved", {"packages": [{"id": FX.REGISTRY + "#gated-sys@0.2.0", "name": "gated-sys",
                                                            "version": "0.2.0", "source": FX.REGISTRY}]})
        again = AU.analyze(platforms(fx), fx.lock_text(), fx.root, locked=stale)    # the listing still names the entry
        rec = pkg(again, self.KEY)
        self.assertNotIn("unlinked", rec)                                    # nothing carried over
        self.assertEqual({k: v["role"] for k, v in rec["platforms"].items()},
                         {"host": "absent", "mips": "linked", "powerpc": "absent"})
        self.assertEqual(find(again, "unlinked-locked-package"), [])
        self.assertEqual(find(again, "lock-unused-entries"), [])
        self.assertEqual(self.pins(again, "mips")[self.KEY]["role"], "linked")
        self.assertNotIn(self.KEY, self.pins(again, "host"))
        flagged = find(again, "unsafe-in-dependency", self.KEY)               # linked on a big-endian target: a review item like any other
        self.assertEqual([f["severity"] for f in flagged], ["review"])
        self.assertEqual(flagged[0]["platforms"], ["mips"])

    # -- the consumer contract (P01-BLK-005's judge, loaded as it is, unchanged)
    def test_the_p01_inventory_judge_passes_the_inventoried_audit_and_fails_the_one_without_it(self):
        spec = importlib.util.spec_from_file_location("ffw_p01_inventory", os.path.join(ROOT, "tests", "p01", "inventory.py"))
        inventory = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inventory)
        report, lock, _ = self.world()
        self.assertEqual(inventory.judge(report, lock.encode())[0], "pass")
        without = AU.analyze(platforms(self.fx), lock, self.fx.root)
        verdict, found, _ = inventory.judge(without, lock.encode())
        self.assertEqual(verdict, "fail")
        self.assertIn(("lock_package_not_pinned", self.KEY), found)
        refused, bad_lock, _ = self.world(lock_checksum="00" * 32)           # an entry whose source cannot be proved gives it nothing to accept
        self.assertNotEqual(inventory.judge(refused, bad_lock.encode())[0], "pass")


    # -- the verify -> scan window: the scan reads the attested snapshot, never the directory again
    LICENSE_FILE_MANIFEST = '[package]\nname = "gated-sys"\nversion = "0.2.0"\nlicense-file = "LICENSE.md"\n'

    @staticmethod
    def planted(root):
        """What a writer to the cache could do right after the comparison: more unsafe, an extra source file, a lint, a licence file."""
        with open(os.path.join(root, "src", "lib.rs"), "a") as fh:
            fh.write("pub fn planted() { unsafe { core::hint::unreachable_unchecked() } }\n")
        with open(os.path.join(root, "src", "extra.rs"), "w") as fh:
            fh.write("pub fn more() { unsafe { core::ptr::null::<u8>().read() } }\n")
        with open(os.path.join(root, "Cargo.toml"), "a") as fh:
            fh.write('[lints.rust]\nunsafe_code = "forbid"\n')
        with open(os.path.join(root, "LICENSE.md"), "w") as fh:
            fh.write("planted\n")

    def test_a_stable_source_gives_the_same_facts_from_the_snapshot_as_from_the_directory(self):
        report, _, sha = self.world()
        rec = pkg(report, self.KEY)
        disk = AU.scan_package(self.pkg_listing, self.fx.root)              # the same scan, reading the directory
        for key, want in (("unsafe", disk["unsafe"]), ("build_script", disk["build_script"]), ("uses_float", disk["uses_float"]),
                          ("references_alloc", disk["uses_alloc"]), ("scanned_files", disk["scanned_files"]), ("target_kinds", disk["target_kinds"])):
            self.assertEqual(rec[key], want, key)
        self.assertEqual(rec["license"], AU._license(self.pkg_listing))
        self.assertEqual(rec["unsafe"]["tokens"], 1)

    def test_what_is_written_to_the_cache_after_the_comparison_cannot_change_the_recorded_facts(self):
        report, _, sha = self.world(after_verify=self.planted)
        with open(os.path.join(self.src, "src", "lib.rs")) as fh:
            self.assertIn("planted", fh.read())                              # the plant is live: the directory really changed
        self.assertTrue(os.path.exists(os.path.join(self.src, "src", "extra.rs")))
        rec = pkg(report, self.KEY)
        self.assertEqual((rec["unsafe"]["status"], rec["unsafe"]["tokens"], sorted(rec["unsafe"]["files"])), ("present", 1, ["src/lib.rs"]))
        self.assertEqual(rec["scanned_files"], 1)
        self.assertEqual(rec["unsafe"]["declared"], [])                      # the lint written afterwards is not the attested manifest's
        self.assertEqual(rec["unlinked"]["source_verified"], {"archive_sha256": sha, "files_in_archive": 2, "files_compared": 2})
        self.assertEqual(kinds(report, "blocker"), [])
        first, _, _ = self.world()                                           # and the same record as when nothing was written
        self.assertEqual(rec, pkg(first, self.KEY))

    def test_the_licence_file_is_judged_from_the_snapshot_so_one_written_afterwards_does_not_appear(self):
        def file_license(listing):
            listing["license"], listing["license_file"] = None, "LICENSE.md"
        report, _, _ = self.world(manifest=self.LICENSE_FILE_MANIFEST, metadata_edit=file_license, after_verify=self.planted)
        self.assertTrue(os.path.exists(os.path.join(self.src, "LICENSE.md")))      # written after the comparison, present on disk
        rec = pkg(report, self.KEY)
        self.assertEqual((rec["license"]["status"], rec["license"]["file"]), ("file-missing", "LICENSE.md"))    # the archive holds none
        held, _, _ = self.world(manifest=self.LICENSE_FILE_MANIFEST, extra_files={"LICENSE.md": "terms\n"}, metadata_edit=file_license)
        self.assertEqual(pkg(held, self.KEY)["license"]["status"], "file-only")  # the permitted positive: the archive holds it

    def test_nothing_in_the_cache_is_reopened_walked_or_read_by_path_after_the_comparison(self):
        started = []

        def arm(root):
            def guard(real, what):
                def guarded(target=None, *rest, **named):
                    if str(target).startswith(root):
                        raise AssertionError("the cache was %s: %s" % (what, target))
                    return real(target, *rest, **named)
                return guarded
            for patcher in (mock.patch.object(AU, "_read", side_effect=AssertionError("the scan read a path")),
                            mock.patch.object(AU, "_rs_files", side_effect=AssertionError("the scan walked the directory")),
                            mock.patch.object(os, "walk", side_effect=AssertionError("the cache was walked")),
                            mock.patch.object(builtins, "open", guard(builtins.open, "reopened")),
                            mock.patch.object(os, "open", guard(os.open, "reopened by descriptor")),
                            mock.patch.object(os, "scandir", guard(os.scandir, "listed")),
                            mock.patch.object(os, "listdir", guard(os.listdir, "listed"))):
                patcher.start()
                started.append(patcher)
        try:
            report, _, _ = self.world(after_verify=arm)
        finally:
            for patcher in reversed(started):
                patcher.stop()
        self.assertIn("unlinked", pkg(report, self.KEY))

    def test_cargos_metadata_that_does_not_describe_the_attested_manifest_is_refused_not_mixed_in(self):
        def edit(field, value):
            def apply(listing):
                listing[field] = value
            return apply

        def another_source(listing):
            listing["targets"].append({"kind": ["bin"], "name": "x", "src_path": os.path.join(os.path.dirname(listing["manifest_path"]), "src", "missing.rs")})
        cases = (("a different licence expression", {"metadata_edit": edit("license", "GPL-3.0-only")}),
                 ("a licence file the manifest does not name", {"metadata_edit": edit("license_file", "COPYING")}),
                 ("a links key the manifest does not have", {"metadata_edit": edit("links", "z")}),
                 ("a build dependency the manifest does not have",
                  {"metadata_edit": lambda listing: listing["dependencies"].append({"name": "cc", "kind": "build"})}),
                 ("a proc-macro library the manifest does not declare",
                  {"metadata_edit": lambda listing: listing["targets"][0].update(kind=["proc-macro"])}),
                 ("a target whose source is not in the archive", {"metadata_edit": another_source}),
                 ("another package name in the attested manifest", {"manifest": self.MANIFEST.replace('name = "gated-sys"', 'name = "other-sys"')}),
                 ("another version in the attested manifest", {"manifest": self.MANIFEST.replace('"0.2.0"', '"0.3.0"')}))
        for label, opt in cases:
            with self.subTest(label):
                report = self.refused("lock-entry-source-differs", **opt)
                self.assertIn("does not describe the attested archive", find(report, "lock-entry-source-differs")[0]["detail"])

    def test_a_richer_manifest_that_cargos_metadata_matches_is_bound_and_inventoried(self):
        manifest = (self.MANIFEST + '[build-dependencies]\nfoo = { package = "cc", version = "1" }\n'
                    "[target.'cfg(unix)'.build-dependencies]\npkg-config = \"0.3\"\n")

        def listing_for(listing):
            listing["dependencies"] += [{"name": "cc", "kind": "build"}, {"name": "pkg-config", "kind": "build", "target": "cfg(unix)"},
                                        {"name": "serde", "kind": "dev"}]           # a dev-dependency is not a build dependency
            listing["targets"].append({"kind": ["custom-build"], "name": "build-script-build",
                                       "src_path": os.path.join(os.path.dirname(listing["manifest_path"]), "build.rs")})
        report, _, _ = self.world(manifest=manifest, extra_files={"build.rs": "fn main() {}\n"}, metadata_edit=listing_for)
        rec = pkg(report, self.KEY)
        self.assertTrue(rec["build_script"]["present"])
        self.assertEqual(rec["build_script"]["native_tooling_deps"], ["cc", "pkg-config"])
        self.assertEqual(kinds(report, "blocker"), [])

    # -- the library, the build script and the binaries cargo reports are the attested manifest's, not merely files of the archive
    def at(self, listing, rel):
        return os.path.join(os.path.dirname(listing["manifest_path"]), *rel.split("/"))

    TOOL_BIN = '[[bin]]\nname = "tool"\npath = "tools/tool.rs"\n'
    TOOL_FILES = {"tools/tool.rs": "fn main() {\n    unsafe { core::hint::unreachable_unchecked() }\n}\n"}

    def test_a_code_target_that_the_attested_manifest_does_not_declare_is_refused_not_scanned(self):
        def retarget(rel=None, **fields):
            def apply(listing):
                if rel is not None:
                    listing["targets"][0]["src_path"] = self.at(listing, rel)
                listing["targets"][0].update(fields)
            return apply

        def add(kind, name, rel):
            return lambda listing: listing["targets"].append({"kind": kind, "name": name, "src_path": self.at(listing, rel)})
        build = {"build.rs": "fn main() {}\n", "other.rs": "fn main() {}\n"}
        cases = (
            ("the library moved to another archive file, one that forbids unsafe",
             {"extra_files": {"src/other.rs": "#![forbid(unsafe_code)]\n"}, "metadata_edit": retarget("src/other.rs")},
             "cargo reports the library at src/other.rs, the attested manifest at src/lib.rs"),
            ("the library moved into a subdirectory that holds none of the code",
             {"extra_files": {"src/sub/inner.rs": "pub fn f() {}\n"}, "metadata_edit": retarget("src/sub/inner.rs")},
             "cargo reports the library at src/sub/inner.rs"),
            ("the library reported as a cdylib", {"metadata_edit": retarget(kind=["cdylib"])},
             "cargo reports the library as ['cdylib'], the attested manifest as ['lib']"),
            ("the library reported as a binary", {"metadata_edit": retarget(kind=["bin"])}, "declares one library and cargo reported 0"),
            ("no library although src/lib.rs is in the archive", {"metadata_edit": lambda listing: listing["targets"].clear()},
             "declares one library and cargo reported 0"),
            ("a library although the manifest turns library discovery off", {"manifest": self.MANIFEST + "autolib = false\n"},
             "a library the attested manifest does not declare"),
            ("a build script elsewhere than build.rs", {"extra_files": build, "metadata_edit": add(["custom-build"], "build-script-build", "other.rs")},
             "declares the build script build.rs, cargo reported ['other.rs']"),
            ("no build script although build.rs is in the archive", {"extra_files": build},
             "declares the build script build.rs, cargo reported []"),
            ("a build script although the manifest says build = false",
             {"manifest": self.MANIFEST + "build = false\n", "extra_files": build,
              "metadata_edit": add(["custom-build"], "build-script-build", "build.rs")},
             "a build script the attested manifest does not declare"),
            ("a library the manifest names at a path the archive does not hold",
             {"manifest": self.MANIFEST + '[lib]\npath = "src/gone.rs"\n', "metadata_edit": retarget("src/gone.rs")},
             "is not a file of the attested archive"),
            ("a binary at a path nobody names or discovers",
             {"extra_files": {"src/helper.rs": "fn main() {}\n"}, "metadata_edit": add(["bin"], "helper", "src/helper.rs")},
             "neither named by the attested manifest nor a path cargo discovers"),
            ("a binary the manifest names by path, left out of the metadata",
             {"manifest": self.MANIFEST + self.TOOL_BIN, "extra_files": self.TOOL_FILES},
             "declares the binary tools/tool.rs and cargo did not report it"),
            ("a binary the manifest names by path, reported at a discovered path instead",
             {"manifest": self.MANIFEST + self.TOOL_BIN, "extra_files": dict(self.TOOL_FILES, **{"src/main.rs": "fn main() {}\n"}),
              "metadata_edit": add(["bin"], "tool", "src/main.rs")},
             "declares the binary tools/tool.rs and cargo did not report it"),
            ("a binary the manifest names by path, reported as an example (not a code target) at that file",
             {"manifest": self.MANIFEST + self.TOOL_BIN, "extra_files": self.TOOL_FILES,
              "metadata_edit": add(["example"], "tool", "tools/tool.rs")},
             "declares the binary tools/tool.rs and cargo did not report it"),
            ("a binary the manifest names by a path that is not a plain relative one",
             {"manifest": self.MANIFEST + '[[bin]]\nname = "tool"\npath = "../tool.rs"\n'},
             "the attested [[bin]] path is not a plain relative path"))
        for label, opt, why in cases:
            with self.subTest(label):
                report = self.refused("lock-entry-source-differs", **opt)
                self.assertIn("does not describe the attested archive", find(report, "lock-entry-source-differs")[0]["detail"])
                self.assertIn(why, find(report, "lock-entry-source-differs")[0]["detail"])

    def test_a_library_build_script_and_binaries_that_the_attested_manifest_declares_are_bound_and_inventoried(self):
        manifest = (self.MANIFEST + 'build = "x.rs"\n[lib]\npath = "src/mylib.rs"\ncrate-type = ["cdylib", "rlib"]\n'
                    '[[bin]]\nname = "tool"\npath = "tools/tool.rs"\n')

        def listing_for(listing):
            listing["targets"] = [{"kind": ["cdylib", "rlib"], "name": "gated_sys", "src_path": self.at(listing, "src/mylib.rs")},
                                  {"kind": ["bin"], "name": "tool", "src_path": self.at(listing, "tools/tool.rs")},
                                  {"kind": ["bin"], "name": "aux", "src_path": self.at(listing, "src/bin/aux.rs")},    # discovered, not named
                                  {"kind": ["custom-build"], "name": "build-script-build", "src_path": self.at(listing, "x.rs")}]
        files = {"src/mylib.rs": "pub fn f() {}\n", "tools/tool.rs": "fn main() {}\n", "src/bin/aux.rs": "fn main() {}\n", "x.rs": "fn main() {}\n"}
        report, _, _ = self.world(manifest=manifest, extra_files=files, metadata_edit=listing_for)
        rec = pkg(report, self.KEY)
        self.assertEqual(kinds(report, "blocker"), [])
        self.assertEqual(rec["target_kinds"], ["bin", "cdylib", "custom-build", "rlib"])
        self.assertTrue(rec["build_script"]["present"])
        macro, _, _ = self.world(manifest=self.MANIFEST + "[lib]\nproc-macro = true\n",
                                 metadata_edit=lambda listing: listing["targets"][0].update(kind=["proc-macro"]))
        self.assertEqual(kinds(macro, "blocker"), [])
        self.assertEqual(pkg(macro, self.KEY)["target_kinds"], ["proc-macro"])
        off, _, _ = self.world(manifest=self.MANIFEST + "autolib = false\nbuild = false\n", extra_files={"build.rs": "fn main() {}\n"},
                               metadata_edit=lambda listing: listing["targets"].clear())
        self.assertEqual(kinds(off, "blocker"), [])                           # discovery off and nothing reported: the same thing declared twice

    def test_a_binary_the_manifest_names_by_path_outside_src_is_scanned_when_cargo_reports_it(self):
        report, _, _ = self.world(manifest=self.MANIFEST + self.TOOL_BIN, extra_files=self.TOOL_FILES,
                                  metadata_edit=lambda listing: listing["targets"].append(
                                      {"kind": ["bin"], "name": "tool", "src_path": self.at(listing, "tools/tool.rs")}))
        rec = pkg(report, self.KEY)
        self.assertEqual(kinds(report, "blocker"), [])
        self.assertEqual((rec["unsafe"]["tokens"], rec["unsafe"]["files"]), (2, {"src/lib.rs": 1, "tools/tool.rs": 1}))
        self.assertEqual(rec["target_kinds"], ["bin", "lib"])

    # -- the text the snapshot gives is the text the directory reader gives for the same bytes
    TEXT_VECTORS = (b"fn a() {} // c\r unsafe { }\n", b"a\r\nb\r\nc\r", b"\r\r\n\n", b"\xef\xbb\xbffn a() {}\n", b"fn \xff\xfe() {}\n",
                    b"x\xe2\x82", b"", b"no newline at all")

    def test_the_snapshot_text_is_the_directory_readers_text_for_newlines_a_bom_and_invalid_bytes(self):
        base = tempfile.mkdtemp(dir=self.outside)
        root = os.path.join(base, "pkg-1.0.0")
        os.makedirs(root)
        for index, data in enumerate(self.TEXT_VECTORS):
            with self.subTest(vector=data):
                path = os.path.join(root, "v%d.rs" % index)
                with open(path, "wb") as fh:
                    fh.write(data)
                reader = AU.SnapshotReader(root, {"v%d.rs" % index: data})
                self.assertEqual(reader.read(path), AU._read(path))

    def test_a_lone_carriage_return_ends_a_line_comment_in_the_snapshot_scan_as_it_does_in_the_directory_scan(self):
        lib = "pub fn a() {} // note\r unsafe { core::hint::unreachable_unchecked() }\n"      # the CR ends the comment: the unsafe block is code
        report, _, _ = self.world(extra_files={"src/lib.rs": lib})
        rec = pkg(report, self.KEY)
        disk = AU.scan_package(self.pkg_listing, self.fx.root)
        self.assertEqual((disk["unsafe"]["tokens"], disk["unsafe"]["files"]), (1, {"src/lib.rs": 1}))
        self.assertEqual((rec["unsafe"]["tokens"], rec["unsafe"]["files"]), (1, {"src/lib.rs": 1}))
        self.assertEqual(rec["unsafe"], disk["unsafe"])

    def test_the_snapshot_reader_lists_and_reads_exactly_what_the_directory_reader_does(self):
        base = tempfile.mkdtemp(dir=self.outside)
        root = os.path.join(base, "pkg-1.0.0")
        tree = {"src/a.rs": "a", "src/sub/b.rs": "b", "src/tests/inner.rs": "i", "tests/t.rs": "t", "examples/e.rs": "e", "benches/x.rs": "x",
                "build.rs": "fn main() {}", "src/readme.md": "m", "root.rs": "r"}
        for rel, text in tree.items():
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w") as fh:
                fh.write(text)
        reader = AU.SnapshotReader(root, {rel: text.encode() for rel, text in tree.items()})
        for top in (root, os.path.join(root, "src"), os.path.join(root, "src", "sub")):
            self.assertEqual(sorted(reader.rs_files(top, root)), sorted(AU._rs_files(top, root)), top)
        self.assertEqual(reader.read(os.path.join(root, "src", "a.rs")), AU._read(os.path.join(root, "src", "a.rs")))
        self.assertIsNone(reader.read(os.path.join(root, "src", "none.rs")))
        self.assertIsNone(reader.read(os.path.join(base, "elsewhere.rs")))      # outside the package: nothing
        self.assertTrue(reader.exists(os.path.join(root, "build.rs")))
        self.assertFalse(reader.exists(os.path.join(root, "src", "none.rs")))


class RegistrySourceVerifierTests(Base):
    """``verify_registry_source`` on its own: the cached archive is proved to be the locked one and the extracted directory to equal it, with
    every step bounded before it reads on. Each refusal is paired with the permitted positive (the plain cache); the caps are patched down
    for the over-limit cases so no fixture is large. The exact-bound cases pass at the cap and fail one over."""

    INDEX = "index.crates.io-test"
    LIB = "pub fn read(x: &u8) -> u8 {\n    unsafe { core::ptr::read(x) }\n}\n"
    MANIFEST = '[package]\nname = "gated-sys"\nversion = "0.2.0"\nlicense = "MIT OR Apache-2.0"\n'
    DIFFERS = "lock-entry-source-differs"

    def cache(self, *, extra_tar=None, tamper=None, not_on_disk=(), marker="file", root_link=False, blob_override=None, raw_tar=None,
              archive="file"):
        """(pkg, sha256 of the archive, archive bytes): a cargo-shaped registry cache in a fresh directory, holding two files. ``archive`` is
        what stands where the cached .crate belongs: the file, a link to a file with the same bytes, a pipe, a directory, or nothing."""
        files = {"Cargo.toml": self.MANIFEST, "src/lib.rs": self.LIB}
        reg = os.path.join(tempfile.mkdtemp(prefix="cargo-home-", dir=self.outside), "registry")
        src = os.path.join(reg, "src", self.INDEX, "gated-sys-0.2.0")
        real = src if not root_link else os.path.join(reg, "elsewhere", "gated-sys-0.2.0")
        os.makedirs(os.path.join(real, "src"))
        for rel, text in files.items():
            if rel not in not_on_disk:
                with open(os.path.join(real, rel), "w") as fh:
                    fh.write(text)
        if marker == "file":
            with open(os.path.join(real, ".cargo-ok"), "w") as fh:
                fh.write('{"v":1}')
        elif marker == "link":                                        # a link to a file with exactly the marker's bytes
            target = os.path.join(tempfile.mkdtemp(dir=self.outside), "marker")
            with open(target, "w") as fh:
                fh.write('{"v":1}')
            os.symlink(target, os.path.join(real, ".cargo-ok"))
        if root_link:
            os.makedirs(os.path.dirname(src))
            os.symlink(real, src)
        if blob_override is not None:
            blob = blob_override
        elif raw_tar is not None:
            blob = gzip.compress(raw_tar)
        else:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                for rel, text in files.items():
                    data = text.encode()
                    info = tarfile.TarInfo("gated-sys-0.2.0/" + rel)
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                if extra_tar:
                    extra_tar(tf)
            blob = buf.getvalue()
        os.makedirs(os.path.join(reg, "cache", self.INDEX))
        crate = os.path.join(reg, "cache", self.INDEX, "gated-sys-0.2.0.crate")
        if archive == "file":
            with open(crate, "wb") as fh:
                fh.write(blob)
        elif archive == "link":                                      # the checksum would match if the link were followed
            target = os.path.join(tempfile.mkdtemp(dir=self.outside), "archive.crate")
            with open(target, "wb") as fh:
                fh.write(blob)
            os.symlink(target, crate)
        elif archive == "pipe":
            os.mkfifo(crate)
        elif archive == "directory":
            os.mkdir(crate)
        if tamper:
            tamper(src)
        pkg_listing = {"name": "gated-sys", "version": "0.2.0", "manifest_path": os.path.join(src, "Cargo.toml")}
        return pkg_listing, hashlib.sha256(blob).hexdigest(), blob

    def refused(self, why, *, expect=None, **opt):
        pkg_listing, sha, _ = self.cache(**opt)
        facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertIsNone(facts, why)
        self.assertEqual(problem[0], expect or self.DIFFERS, (why, problem))
        return problem[1]

    @staticmethod
    def dir_members(count):
        def add(tf):
            for i in range(count):
                info = tarfile.TarInfo("gated-sys-0.2.0/d%d" % i)
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
        return add

    # -- the permitted positive, and what it must not use or leave open
    def test_the_plain_cache_verifies_with_a_bounded_inflate_no_whole_listing_and_every_stream_closed(self):
        pkg_listing, sha, _ = self.cache()
        streams, handles, sizes, opened = [], [], [], []
        real_extract, real_plain, real_read, real_open = tarfile.TarFile.extractfile, AU._plain_file, gzip.GzipFile.read, os.open

        def spy_extract(tf, member):
            streams.append(real_extract(tf, member))
            return streams[-1]

        def spy_plain(path):
            handles.append(real_plain(path))
            return handles[-1]

        def spy_read(gz, size=-1):
            sizes.append(size)
            return real_read(gz, size)

        def spy_open(path, flags, *rest, **named):
            opened.append((path, flags))
            return real_open(path, flags, *rest, **named)
        with mock.patch.object(builtins, "open", side_effect=AssertionError("a blocking builtin open")), \
                mock.patch.object(os, "open", spy_open), \
                mock.patch.object(tarfile.TarFile, "getmembers", side_effect=AssertionError("the whole archive was listed")), \
                mock.patch.object(gzip, "decompress", side_effect=AssertionError("an unbounded inflate")), \
                mock.patch.object(tarfile.TarFile, "extractfile", spy_extract), mock.patch.object(AU, "_plain_file", spy_plain), \
                mock.patch.object(gzip.GzipFile, "read", spy_read):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertIsNone(problem)
        self.assertEqual(facts, {"archive_sha256": sha, "files_in_archive": 2, "files_compared": 2})
        self.assertEqual(sizes, [AU.INFLATE_LIMIT + 1])                  # one read, with a size, one over the cap
        self.assertEqual((len(streams), len(handles)), (2, 3))          # two members read; the archive and the two files opened
        self.assertTrue(all(s.closed for s in streams), "an archive member stream was left open")
        self.assertTrue(all(h.closed for h in handles), "the archive or an extracted file was left open")
        self.assertEqual(len(opened), 3)
        self.assertTrue(opened[0][0].endswith("gated-sys-0.2.0.crate"), "the archive is the first thing opened")
        want = os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        self.assertTrue(all(flags & want == want for _, flags in opened), "something was opened that could block or follow a link")

    def test_the_marker_is_optional_and_a_cache_without_it_verifies(self):
        pkg_listing, sha, _ = self.cache(marker="none")
        self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])

    # -- bounds, each at the cap (permitted) and one over (refused)
    def test_the_archive_size_cap_admits_exactly_its_size_and_refuses_one_byte_over(self):
        pkg_listing, sha, blob = self.cache()
        with mock.patch.object(AU, "CRATE_READ_LIMIT", len(blob)):
            self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])
        with mock.patch.object(AU, "CRATE_READ_LIMIT", len(blob) - 1):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("larger than", problem[1])

    def test_the_inflation_cap_admits_exactly_the_inflated_size_and_refuses_one_byte_over(self):
        pkg_listing, sha, blob = self.cache()
        inflated = len(gzip.decompress(blob))                          # the test knows the size; the verifier must not inflate unbounded
        with mock.patch.object(AU, "INFLATE_LIMIT", inflated):
            self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])
        with mock.patch.object(AU, "INFLATE_LIMIT", inflated - 1):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("inflates to more than", problem[1])

    def test_a_decompression_bomb_is_stopped_by_the_bounded_read_before_any_tar_is_parsed(self):
        bomb = gzip.compress(b"\0" * 400_000)                          # tiny to store, 400 kB inflated, against a 100 kB cap
        pkg_listing, sha, _ = self.cache(blob_override=bomb)
        sizes, real_read = [], gzip.GzipFile.read

        def spy_read(gz, size=-1):
            sizes.append(size)
            return real_read(gz, size)
        with mock.patch.object(AU, "INFLATE_LIMIT", 100_000), mock.patch.object(gzip.GzipFile, "read", spy_read), \
                mock.patch.object(tarfile, "open", side_effect=AssertionError("a bomb reached the tar parser")):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("inflates to more than", problem[1])
        self.assertEqual(sizes, [100_001])                              # never asked for more than one byte over the cap

    def test_the_entry_cap_admits_exactly_its_count_and_refuses_one_over_before_any_data_is_read(self):
        pkg_listing, sha, _ = self.cache(extra_tar=self.dir_members(6))          # 2 files + 6 directories = 8 entries
        with mock.patch.object(AU, "MAX_ARCHIVE_MEMBERS", 8):
            self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])
        with mock.patch.object(AU, "MAX_ARCHIVE_MEMBERS", 7), \
                mock.patch.object(tarfile.TarFile, "extractfile", side_effect=AssertionError("data was read before the count was checked")):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("more than 7 entries", problem[1])

    def test_a_compressed_header_storm_is_stopped_by_the_inflation_cap_and_the_entry_cap_in_turn(self):
        pkg_listing, sha, blob = self.cache(extra_tar=self.dir_members(300))     # 300 headers of 512 bytes: ~150 kB inflated, ~a few hundred bytes stored
        self.assertLess(len(blob), 5_000)
        with mock.patch.object(AU, "INFLATE_LIMIT", 50_000), mock.patch.object(tarfile, "open", side_effect=AssertionError("the storm was parsed")):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertIn("inflates to more than", problem[1])
        with mock.patch.object(AU, "MAX_ARCHIVE_MEMBERS", 50):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("more than 50 entries", problem[1])

    def test_a_member_that_declares_more_than_the_archive_holds_is_refused(self):
        def block(name, body=None, declared=None):
            info = tarfile.TarInfo(name)
            info.size = len(body) if body is not None else declared
            header = info.tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape")
            return header + (body + b"\0" * (-len(body) % 512) if body is not None else b"")
        tail = b"\0" * 1024
        good = block("gated-sys-0.2.0/Cargo.toml", self.MANIFEST.encode()) + block("gated-sys-0.2.0/src/lib.rs", self.LIB.encode())
        pkg_listing, sha, _ = self.cache(raw_tar=good + tail)                    # the permitted positive of this raw form
        self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])
        for label, declared in (("beyond the cap", 10 ** 9), ("beyond the data", 4096)):
            with self.subTest(label):
                why = self.refused(label, raw_tar=good + block("gated-sys-0.2.0/src/big.rs", declared=declared) + tail)
                self.assertIn("declares a member larger", why)

    # -- the cached archive itself is as mutable as the tree: what stands in its place is refused by type, and never opened blocking
    def test_a_cached_archive_that_is_a_pipe_a_link_or_a_directory_is_refused_by_type_before_any_blocking_open_or_read(self):
        for kind in ("pipe", "link", "directory"):
            with self.subTest(kind):
                if kind == "pipe" and not hasattr(os, "mkfifo"):
                    self.skipTest("no named pipes on this platform")
                pkg_listing, sha, _ = self.cache(archive=kind)
                with self.watchdog(), mock.patch.object(builtins, "open", side_effect=AssertionError("a blocking builtin open")), \
                        mock.patch.object(gzip, "GzipFile", side_effect=AssertionError("a non-file archive was inflated")):
                    facts, problem = AU.verify_registry_source(pkg_listing, sha)
                self.assertEqual((facts, problem[0]), (None, self.DIFFERS), kind)
                self.assertIn("the cached .crate archive is not a plain file", problem[1])
        pkg_listing, sha, _ = self.cache(archive="none")                  # absent stays the other kind of refusal
        facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, "lock-entry-source-missing"))
        regular, sha, _ = self.cache()                                  # and the plain archive is the permitted positive
        self.assertIsNone(AU.verify_registry_source(regular, sha)[1])

    # -- the extracted tree is enumerated lazily and counted, every entry kind, against a finite cap (the disk side of the same bounds)
    @staticmethod
    def counting_scandir(seen):
        """A stand-in for os.scandir that records each entry the caller actually pulls, so 'stopped early' is observable."""
        real = os.scandir

        class Counting:
            def __init__(self, target):
                self._it = real(target)

            def __iter__(self):
                return self

            def __next__(self):
                entry = next(self._it)
                seen.append(entry.name)
                return entry

            def __enter__(self):
                self._it.__enter__()
                return self

            def __exit__(self, *exc):
                return self._it.__exit__(*exc)
        return Counting

    @staticmethod
    def nested_empty_dirs(depth):
        def make(src):
            os.makedirs(os.path.join(src, *["d%d" % i for i in range(depth)]))
        return make

    @staticmethod
    def extra_files(count):
        def make(src):
            for i in range(count):
                with open(os.path.join(src, "src", "extra%03d.rs" % i), "w"):
                    pass
        return make

    def test_the_tree_entry_cap_counts_files_directories_and_the_marker_and_admits_exactly_its_count(self):
        # Cargo.toml, src, src/lib.rs and .cargo-ok = 4 entries; three nested empty directories (not extra files: the archive need not list them) make 7
        pkg_listing, sha, _ = self.cache(tamper=self.nested_empty_dirs(3))
        with mock.patch.object(AU, "MAX_TREE_ENTRIES", 7):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertIsNone(problem)
        self.assertEqual(facts["files_compared"], 2)
        with mock.patch.object(AU, "MAX_TREE_ENTRIES", 6):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("the extracted source holds more than 6 entries", problem[1])
        # the marker is an entry: with it the plain cache is 4 and a cap of 3 refuses; without it the same cache is 3 and a cap of 3 admits
        with_marker, sha_a, _ = self.cache()
        without_marker, sha_b, _ = self.cache(marker="none")
        with mock.patch.object(AU, "MAX_TREE_ENTRIES", 3):
            self.assertEqual(AU.verify_registry_source(with_marker, sha_a)[1][0], self.DIFFERS)
            self.assertIsNone(AU.verify_registry_source(without_marker, sha_b)[1])

    def test_an_extra_file_storm_and_a_nested_directory_storm_are_refused_at_the_cap_having_pulled_only_one_entry_past_it(self):
        for label, opt in (("flat storm of extra files", {"tamper": self.extra_files(50)}),
                           ("nested storm of empty directories", {"tamper": self.nested_empty_dirs(40)})):
            with self.subTest(label):
                pkg_listing, sha, _ = self.cache(**opt)
                seen, opened = [], []
                real_open = os.open

                def spy_open(target, flags, *rest, **named):
                    opened.append(target)
                    return real_open(target, flags, *rest, **named)
                with mock.patch.object(AU, "MAX_TREE_ENTRIES", 10), mock.patch.object(os, "scandir", self.counting_scandir(seen)), \
                        mock.patch.object(os, "open", spy_open), mock.patch.object(tarfile, "open", side_effect=AssertionError("the archive was parsed")):
                    facts, problem = AU.verify_registry_source(pkg_listing, sha)
                self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
                self.assertIn("the extracted source holds more than 10 entries", problem[1])
                self.assertEqual(len(seen), 11, "the traversal pulled more than one entry past the cap")      # cap + 1, then it stopped
                self.assertEqual(len(opened), 1, "a file of the tree was opened before the tree was proved finite")     # only the archive
        regular, sha, _ = self.cache()                                  # the permitted positive under the production cap
        self.assertIsNone(AU.verify_registry_source(regular, sha)[1])

    def test_the_tree_is_listed_by_a_lazy_iterative_scan_never_by_os_walk(self):
        pkg_listing, sha, _ = self.cache(tamper=self.nested_empty_dirs(5))
        with mock.patch.object(os, "walk", side_effect=AssertionError("os.walk lists a whole directory at once")):
            self.assertIsNone(AU.verify_registry_source(pkg_listing, sha)[1])
        self.assertEqual(AU.MAX_TREE_ENTRIES, 2 * AU.MAX_ARCHIVE_MEMBERS + 1)          # the documented relation, pinned

    # -- duplicates and entries that are not plain files
    def test_an_archive_that_names_a_file_twice_is_refused_before_anything_is_compared(self):
        def twice(tf):
            data = self.LIB.encode()
            info = tarfile.TarInfo("gated-sys-0.2.0/src/lib.rs")           # same name, same bytes: the files on disk match it
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        pkg_listing, sha, _ = self.cache(extra_tar=twice)
        with mock.patch.object(tarfile.TarFile, "extractfile", side_effect=AssertionError("data was read before the duplicate was seen")):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("more than once", problem[1])

    def test_an_archive_member_that_is_a_hard_link_or_a_contiguous_file_is_refused_though_its_bytes_match(self):
        def hard(tf):
            info = tarfile.TarInfo("gated-sys-0.2.0/src/hard.rs")
            info.type, info.linkname = tarfile.LNKTYPE, "gated-sys-0.2.0/src/lib.rs"
            tf.addfile(info)

        def contiguous(tf):
            data = self.LIB.encode()
            info = tarfile.TarInfo("gated-sys-0.2.0/src/cont.rs")
            info.type, info.size = tarfile.CONTTYPE, len(data)
            tf.addfile(info, io.BytesIO(data))

        def copy(name):
            def write(src):
                with open(os.path.join(src, "src", name), "w") as fh:
                    fh.write(self.LIB)
            return write
        for label, extra_tar, tamper in (("hard link", hard, copy("hard.rs")), ("contiguous file", contiguous, copy("cont.rs"))):
            with self.subTest(label):
                self.assertIn("not a plain file", self.refused(label, extra_tar=extra_tar, tamper=tamper))

    # -- links and special files in the extracted tree: refused by name and type, before any content is read
    def test_a_file_symbolic_link_to_byte_identical_content_is_refused_so_the_byte_comparison_cannot_mask_it(self):
        def link_lib(src):
            target = os.path.join(tempfile.mkdtemp(dir=self.outside), "lib.rs")
            with open(target, "w") as fh:
                fh.write(self.LIB)                                        # exactly the archive's bytes, outside the crate
            os.symlink(target, os.path.join(src, "src", "lib.rs"))
        why = self.refused("file link", not_on_disk=("src/lib.rs",), tamper=link_lib)
        self.assertIn("src/lib.rs in the extracted source is a symbolic link", why)

    def test_a_symbolic_link_marker_a_linked_directory_and_a_linked_root_are_refused_too(self):
        def link_dir(src):
            os.symlink(tempfile.mkdtemp(dir=self.outside), os.path.join(src, "src", "sub"))
        self.assertIn(".cargo-ok in the extracted source is a symbolic link", self.refused("marker link", marker="link"))
        self.assertIn("symbolic link to a directory", self.refused("directory link", tamper=link_dir))
        self.assertIn("directory is a symbolic link", self.refused("root link", root_link=True))

    @contextlib.contextmanager
    def watchdog(self, seconds=10):
        """Fail, instead of hanging, if a named pipe is ever opened for reading without the no-block flag. A no-op where SIGALRM does not exist."""
        if not hasattr(signal, "SIGALRM"):
            yield
            return

        def boom(signum, frame):
            raise AssertionError("blocked on a special file")
        previous = signal.signal(signal.SIGALRM, boom)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes on this platform")
    def test_a_named_pipe_in_the_extracted_tree_is_refused_without_opening_it(self):
        def pipe(src):
            os.mkfifo(os.path.join(src, "src", "pipe"))
        with self.watchdog():
            self.assertIn("not a plain file", self.refused("pipe", tamper=pipe))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes on this platform")
    def test_a_named_pipe_standing_for_an_archive_file_is_refused_by_type_before_any_path_is_opened(self):
        def pipe_for_lib(src):                                          # the archive names src/lib.rs; on disk that name is a pipe
            os.mkfifo(os.path.join(src, "src", "lib.rs"))
        pkg_listing, sha, _ = self.cache(not_on_disk=("src/lib.rs",), tamper=pipe_for_lib)
        real_open = os.open

        def guarded(target, flags, *rest, **named):                     # the archive is opened first, plainly; the extracted tree not before its types are known
            if os.sep.join(("", "src", self.INDEX, "")) in target:
                raise AssertionError("a path of the extracted tree was opened before its type was known")
            return real_open(target, flags, *rest, **named)
        with self.watchdog(), mock.patch.object(os, "open", guarded):
            facts, problem = AU.verify_registry_source(pkg_listing, sha)
        self.assertEqual((facts, problem[0]), (None, self.DIFFERS))
        self.assertIn("src/lib.rs in the extracted source is not a plain file", problem[1])
        regular, sha, _ = self.cache()                                  # the permitted positive: the same name as a real file opens and verifies
        self.assertIsNone(AU.verify_registry_source(regular, sha)[1])

    def test_the_plain_file_opener_follows_no_link_and_opens_no_directory_or_pipe(self):
        base = tempfile.mkdtemp(dir=self.outside)
        real, link, sub = (os.path.join(base, n) for n in ("real", "link", "sub"))
        with open(real, "w") as fh:
            fh.write("same bytes")
        os.symlink(real, link)
        os.mkdir(sub)
        handle = AU._plain_file(real)                                      # the permitted positive
        with handle:
            self.assertEqual(handle.read(), b"same bytes")
        self.assertTrue(handle.closed)
        for label, path in (("link to identical content", link), ("directory", sub), ("missing", os.path.join(base, "none"))):
            with self.subTest(label):
                self.assertIsNone(AU._plain_file(path))
        if os.path.exists("/dev/null"):                                    # a character device: it reads as empty and is not a file
            self.assertIsNone(AU._plain_file("/dev/null"))
        if hasattr(os, "mkfifo"):
            os.mkfifo(os.path.join(base, "pipe"))
            with self.watchdog():                                          # opened without blocking and refused on the descriptor's type
                self.assertIsNone(AU._plain_file(os.path.join(base, "pipe")))


if __name__ == "__main__":
    unittest.main()
