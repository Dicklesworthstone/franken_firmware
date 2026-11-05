"""E06 audit at the closing revision, committed evidence consistency (toolchain/results/e06/audit-08d5a00266d4).

The directory holds the `audit.py audit` report (`ffw.e06.audit.v1`) of a clean export of revision 08d5a00266d4, run with the committed run7 ingest record folded
in. These tests make that report agree with itself, with the committed run7 ingest record it folded in, with the pinned hash, and with docs/contracts/e06.md, and
they keep personal data out. The `5b8d5696` report in rev-5b8d56966da5 is a different revision and keeps its own tests (test_evidence.py).

Expected values are written from the workspace's structure and from the earlier audit's findings (15 crates, the review items of the 5b8d5696 audit less the one
dependency that left the graph), not read back from the file under test. The checker is `problems()`: the real report must give [], and each planted corruption
of a COPY must give the problem it plants.
"""
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.dont_write_bytecode = True
EVIDENCE = os.path.join(ROOT, "toolchain", "results", "e06", "audit-08d5a00266d4")
AUDIT = os.path.join(EVIDENCE, "audit.json")
INGEST = os.path.join(ROOT, "toolchain", "results", "e06", "rev-08d5a00266d4", "ingest-run7.json")
DOC = os.path.join(ROOT, "docs", "contracts", "e06.md")
PIN = "ab18f97973e9c92353d850e1eeb24c4a696f30e83f5ba8c424554efb441a0104"
CRATES = ["franken-alloc-probe", "franken-atomic", "franken-baseline", "franken-board-profile", "franken-clock", "franken-control", "franken-dsp", "franken-hal",
          "franken-journal", "franken-platform", "franken-platform-linux", "franken-session", "franken-speaker", "franken-stream", "franken-test-support"]
TRIPLES = ["mips-unknown-linux-musl", "powerpc-unknown-linux-musl"]
# The 5b8d5696 audit's 12 linked dependencies with unsafe, less portable-atomic (no longer in the graph).
UNSAFE_DEPS = ["block-buffer", "cmov", "const-oid", "hybrid-array", "itoa", "memchr", "serde", "serde_core", "serde_json", "sha2", "zmij"]
REVIEW = {("float-on-soft-float", None), ("workspace-unsafe-test-only", "franken-alloc-probe")} | {("unsafe-in-dependency", n) for n in UNSAFE_DEPS}
LEAF = "franken-platform-linux"
# Independent of scripts/e06/checks.py::redact, on purpose: what must not be in a committed file.
LEAKS = re.compile(r"/Users/|/home/|/private/|/tmp/|jemanuel|claude-501|ubuntu|scratchpad|\b\d{1,3}(?:\.\d{1,3}){3}\b")


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_text(path):
    return read_bytes(path).decode("utf-8")


def name(key):
    return None if key is None else key.split("@")[0]


def problems(path, check_pin=True):
    """Everything wrong with the audit report at `path`, as short strings; [] means consistent."""
    out = []
    raw = read_bytes(path)
    if check_pin and hashlib.sha256(raw).hexdigest() != PIN:
        out.append("pinned hash differs")
    m = LEAKS.search(raw.decode("utf-8"))
    if m:
        out.append("leak: %s" % m.group(0))
    a = json.loads(raw)
    if a.get("schema") != "ffw.e06.audit.v1":
        out.append("schema is %r" % a.get("schema"))
    if not a["lock"]["sha256"].startswith("8e3ea0d826c2ecea") or a["lock"]["entries"] != 42:
        out.append("lock is not the closing revision's (8e3ea0d8…, 42 entries)")
    if {k: v.get("outcome") for k, v in a["platforms"].items()} != {"host": "resolved", "mips": "resolved", "powerpc": "resolved"} or a["platforms"]["mips"].get("float") != "soft-float":
        out.append("platforms: not three resolved platforms with a soft-float mips")
    if a["summary"]["counts"] != {"blocker": 0, "review": 13, "info": 37}:
        out.append("counts are %r, not 0 blockers, 13 review, 37 info" % a["summary"]["counts"])
    review = [(f["kind"], name(f["package"])) for f in a["findings"] if f["severity"] == "review"]
    if len(review) != 13 or set(review) != REVIEW:
        out.append("review items are not the expected 13")
    if [f for f in a["findings"] if f["kind"] in ("workspace-unsafe-linked", "workspace-unsafe-undeclared")]:
        out.append("an unsafe policy finding (linked or undeclared) is present")
    if sorted((name(f["package"]), f["severity"]) for f in a["findings"] if f["kind"] == "workspace-unsafe-permitted") != [(LEAF, "info")]:
        out.append("workspace-unsafe-permitted is not exactly the leaf, as info")
    if a["policy_inputs"].get("unsafe_allowed") != [LEAF]:
        out.append("policy unsafe_allowed is %r" % a["policy_inputs"].get("unsafe_allowed"))
    ws = {p["name"]: p for p in a["packages"] if p["source_kind"] == "workspace"}
    if sorted(ws) != CRATES:
        out.append("workspace crates are not the expected 15")
    else:
        holders = {n: (p["unsafe"]["tokens"], sorted(p["unsafe"]["files"])) for n, p in ws.items() if p["unsafe"]["tokens"]}
        if sorted(holders) != ["franken-alloc-probe", LEAF] or holders[LEAF][1] != ["src/sys.rs"]:
            out.append("unsafe: not only franken-alloc-probe and the leaf, or the leaf's is not confined to src/sys.rs")
    if [p["key"] for p in a["packages"] if p["name"] == "portable-atomic"]:
        out.append("portable-atomic is in the graph")
    if [p["key"] for p in a["packages"] if p["source_kind"] == "registry" and not (p["pin"]["in_lock"] and p["pin"]["checksum"])]:
        out.append("a registry package is not pinned with a checksum")
    bc = a["build_checks"]
    rows = {(r["crate"], r["target"]): r for r in bc["rows"]}
    if (bc["planned"], bc["counts"]) != (30, {"conflicting": 0, "fail": 0, "not-run": 0, "pass": 30}) or set(rows) != {(c, t) for c in CRATES for t in TRIPLES} or len(bc["rows"]) != 30:
        out.append("build checks are not 30 passing rows for 15 crates x 2 targets")
    ing = {(r["crate"], r["target"]): r for r in (json.loads(ln) for ln in read_text(INGEST).splitlines() if ln.strip())}
    if any((r.get("evidence"), r.get("note"), r.get("status")) != (ing.get(k, {}).get("evidence"), ing.get(k, {}).get("note"), ing.get(k, {}).get("status")) for k, r in rows.items()):
        out.append("a build-check row differs from the run7 ingest record it folded in")
    return out


@unittest.skipUnless(os.path.isfile(AUDIT) and os.path.isfile(INGEST), "the committed closing-revision audit or the run7 ingest record is not present")
class ClosingRevisionAuditTests(unittest.TestCase):
    def test_the_committed_audit_is_consistent(self):
        self.assertEqual(problems(AUDIT), [])

    def test_the_directory_holds_exactly_the_report(self):
        self.assertEqual(sorted(os.listdir(EVIDENCE)), ["audit.json"])

    def test_the_contract_states_what_the_report_says(self):
        doc = read_text(DOC)
        self.assertIn("### The audit at the closing revision, and how it differs from the `5b8d5696` audit", doc)
        self.assertIn("toolchain/results/e06/audit-08d5a00266d4/audit.json", doc)
        self.assertIn(PIN[:16], doc)
        for fact in ("**0 blockers, 13 review items, 37 info**", "`8e3ea0d826c2ecea…`, 42 entries", "`workspace-unsafe-permitted`", "**No review item is new.**", "all in `src/sys.rs`",
                     "`portable-atomic@1.15.0` is no longer in either big-endian graph"):
            self.assertIn(fact, doc, fact)


@unittest.skipUnless(os.path.isfile(AUDIT) and os.path.isfile(INGEST), "the committed closing-revision audit or the run7 ingest record is not present")
class PlantedAuditCorruptionTests(unittest.TestCase):
    """Each case corrupts a COPY of the report in one way and expects the checker to name it; the real report passes above."""

    def corrupted(self, edit):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a = json.loads(read_text(AUDIT))
        edit(a)
        path = os.path.join(tmp.name, "audit.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(a, fh, sort_keys=True)
        return path

    def named(self, path, prefix):
        got = problems(path, check_pin=False)
        self.assertTrue(any(m.startswith(prefix) for m in got), got)

    def test_another_schema_is_named(self):
        self.named(self.corrupted(lambda a: a.update(schema="ffw.e06.audit.v2")), "schema is")

    def test_an_unresolved_platform_is_named(self):
        self.named(self.corrupted(lambda a: a["platforms"]["powerpc"].update(outcome="resolver-failed")), "platforms: not three")

    def test_a_mips_that_is_not_soft_float_is_named(self):
        self.named(self.corrupted(lambda a: a["platforms"]["mips"].update(float="hard-float")), "platforms: not three")

    def test_a_blocker_in_the_counts_is_named(self):
        self.named(self.corrupted(lambda a: a["summary"]["counts"].update(blocker=1)), "counts are")

    def test_a_linked_unsafe_finding_is_named(self):
        self.named(self.corrupted(lambda a: a["findings"].append({"kind": "workspace-unsafe-linked", "severity": "blocker", "package": "franken-clock@0.1.0", "platforms": ["mips"], "detail": "planted"})),
                   "an unsafe policy finding")

    def test_a_different_lock_is_named(self):
        self.named(self.corrupted(lambda a: a["lock"].update(sha256="55ee4dab437f6210" + "0" * 48)), "lock is not")

    def test_portable_atomic_back_in_the_graph_is_named(self):
        def edit(a):
            clone = json.loads(json.dumps(next(p for p in a["packages"] if p["source_kind"] == "registry")))
            clone.update(name="portable-atomic", version="1.15.0", key="portable-atomic@1.15.0")
            a["packages"].append(clone)
        self.named(self.corrupted(edit), "portable-atomic is in the graph")

    def test_a_dropped_build_check_row_is_named(self):
        self.named(self.corrupted(lambda a: a["build_checks"]["rows"].pop(0)), "build checks are not")

    def test_the_old_policy_input_is_named(self):
        self.named(self.corrupted(lambda a: a["policy_inputs"].update(unsafe_allowed=["franken-platform"])), "policy unsafe_allowed")

    def test_unsafe_outside_the_leafs_sys_module_is_named(self):
        def edit(a):
            leaf = next(p for p in a["packages"] if p["name"] == LEAF)
            leaf["unsafe"]["files"] = dict(leaf["unsafe"]["files"], **{"src/lib.rs": 1}) if isinstance(leaf["unsafe"]["files"], dict) else sorted(leaf["unsafe"]["files"]) + ["src/lib.rs"]
        self.named(self.corrupted(edit), "unsafe: not only")

    def test_a_missing_review_finding_is_named(self):
        def edit(a):
            i = next(i for i, f in enumerate(a["findings"]) if f["severity"] == "review" and f["kind"] == "unsafe-in-dependency")
            a["findings"].pop(i)
        self.named(self.corrupted(edit), "review items are not")

    def test_a_local_path_in_a_finding_is_named(self):
        self.named(self.corrupted(lambda a: a["findings"][0].update(detail="see /Users/someone/scratch")), "leak:")

    def test_a_build_check_row_that_differs_from_the_ingest_record_is_named(self):
        self.named(self.corrupted(lambda a: a["build_checks"]["rows"][0].update(evidence="a different log, sha256 " + "0" * 64)), "a build-check row differs")

    def test_a_missing_permitted_finding_for_the_leaf_is_named(self):
        self.named(self.corrupted(lambda a: a["findings"].__setitem__(slice(None), [f for f in a["findings"] if f["kind"] != "workspace-unsafe-permitted"])), "workspace-unsafe-permitted is not exactly")

    def test_a_missing_workspace_crate_is_named(self):
        self.named(self.corrupted(lambda a: a["packages"].__setitem__(slice(None), [p for p in a["packages"] if p["name"] != "franken-journal"])), "workspace crates are not")

    def test_another_crate_holding_unsafe_tokens_is_named(self):
        def edit(a):
            clock = next(p for p in a["packages"] if p["name"] == "franken-clock")
            clock["unsafe"]["tokens"] = 1
        self.named(self.corrupted(edit), "unsafe: not only")

    def test_an_unpinned_registry_package_is_named(self):
        def edit(a):
            next(p for p in a["packages"] if p["source_kind"] == "registry")["pin"]["checksum"] = None
        self.named(self.corrupted(edit), "a registry package is not pinned")

    def test_a_changed_byte_breaks_the_pin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "audit.json")
        with open(path, "wb") as fh:
            fh.write(read_bytes(AUDIT) + b"\n")
        self.assertIn("pinned hash differs", problems(path))


if __name__ == "__main__":
    unittest.main()
