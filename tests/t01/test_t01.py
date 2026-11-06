"""Tests of the T01 rules, ledger, profile, synthetic fixtures, source probes, runner and receipt (tests/t01/, bead ffw-32a). Standard library only, offline, no cargo.

Run: python3 -B -W error -m unittest tests/t01/test_t01.py   (from the repository root)

Each check passes on the committed files and reports a fault planted in a copy of them. The pinned third-party source trees are not committed, so the probes are tested here on small
SYNTHETIC trees written into temporary directories (which show that a probe sees what it should and refuses what it should), and on the real pinned trees only when
T01_SOURCES names a directory holding them (the test is skipped otherwise, and the runner's own full tier is the way to run them: scripts/e2e/t01 --tier full --sources DIR).
"""
import contextlib
import copy
import hashlib
import io
import itertools
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import case_log  # noqa: E402
import run_cases as rc  # noqa: E402
import t01lib as L  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
ENTRY = os.path.join(REPO, "scripts", "e2e", "t01")
PROFILE = L.load_json(L.PROFILE)
LEDGER = L.load_json(L.LEDGER)
CASES = L.load_json(L.CASES)
FIX = [L.load_json(os.path.join(L.FIXTURES, n)) for n in ("identity.json", "netmap.json", "derp_map.json", "key_expiry.json")]
SECRET = "Authorization: Bearer abcdef0123456789abcdef0123456789abcdef"


def planted(problems, needle):
    return any(needle in p for p in problems)


class Rules(unittest.TestCase):
    def test_the_hand_written_tables_equal_the_rules(self):
        for row in CASES["classification"]:
            try:
                got = L.classify(row["facts"])
            except ValueError:
                got = "unclassifiable"
            self.assertEqual(got, row["expect"], row["id"])
        table = CASES["cell_rules"]
        for row in table["rows"]:
            self.assertEqual([L.derive_cell(row["behavior"], p, row["extensible"]) for p in table["platforms"]], row["expect"], row)
        for row in CASES["budget_rules"]["rows"]:
            self.assertEqual(L.budget_verdict(row["measured"], row["cap"], CASES["budget_rules"]["reserve_floor_bytes"], row["reserve"]), row["expect"], row["id"])

    def test_nothing_is_supported_without_a_run_on_the_target_over_every_combination(self):
        for behavior, platform, extensible in itertools.product(L.BEHAVIOR_STATES, L.PLATFORM_STATES, (True, False)):
            cell = L.derive_cell(behavior, platform, extensible)
            self.assertIn(cell, L.CELL_STATES)
            self.assertEqual(cell == "supported", behavior == "implemented" and platform == "ran_on_target", (behavior, platform, extensible))
            if platform == "incompatible":
                self.assertEqual(cell, "incompatible")

    def test_only_a_rust_native_process_with_its_own_identity_is_native_over_every_fact_combination(self):
        keys = {"language": ("rust", "go", "c"), "role": ("client", "server", "data_plane"), "mode": ("native_process", "proxy_of_other_daemon", "embeds_foreign_runtime", "wireguard_data_plane_only"),
                "membership": ("own_identity", "host_identity", "none"), "daemon_location": ("same_device", "other_host", None)}
        for values in itertools.product(*keys.values()):
            facts = dict(zip(keys, values))
            try:
                cls = L.classify(facts)
            except ValueError:
                continue
            self.assertIn(cls, L.CLASSES)
            native = cls == "native_strict_rust"
            self.assertEqual(native, facts["language"] == "rust" and facts["role"] != "server" and facts["mode"] == "native_process" and facts["membership"] == "own_identity", facts)

    def test_missing_data_is_never_a_pass_over_a_grid(self):
        measured = [None, {"value": 1, "unit": "bytes", "receipt": "r"}, {"value": 1, "unit": "bytes"}, {"value": 1, "unit": "kib", "receipt": "r"}]
        caps = [None, {"value": 100, "unit": "bytes"}]
        for m, c, reserve in itertools.product(measured, caps, (None, 0, 4194303, 4194304, 9999999)):
            got = L.budget_verdict(m, c, 4194304, reserve)
            if m is None or c is None or reserve is None or reserve < 4194304 or not m.get("receipt") or m.get("unit") != (c or {}).get("unit"):
                self.assertNotEqual(got, "pass", (m, c, reserve))

    def test_a_changed_rule_would_be_caught_by_the_tables(self):
        wrong = lambda b, p, e: "supported" if p == "build_ok_unrun" and b == "implemented" else L.derive_cell(b, p, e)  # noqa: E731
        table = CASES["cell_rules"]
        bad = [row for row in table["rows"] if [wrong(row["behavior"], p, row["extensible"]) for p in table["platforms"]] != row["expect"]]
        self.assertTrue(bad)


class Ledger(unittest.TestCase):
    def test_the_committed_ledger_holds(self):
        self.assertEqual(L.check_ledger(LEDGER), [])
        ids = [e["id"] for e in LEDGER["entries"]]
        self.assertEqual((len(ids), ids[0], ids[-1]), (47, "T01-E01", "T01-E47"))

    def test_each_planted_fault_is_reported(self):
        def entry(i):
            doc = copy.deepcopy(LEDGER)
            return doc, doc["entries"][i]

        doc, e = entry(0); e["excerpt"] += "x"
        self.assertTrue(planted(L.check_ledger(doc), "does not match its sha256"))
        doc, e = entry(0); doc["entries"].append(copy.deepcopy(e))
        self.assertTrue(planted(L.check_ledger(doc), "duplicate id"))
        doc, e = entry(0); e["rev"] = "main"
        self.assertTrue(planted(L.check_ledger(doc), "full commit"))
        doc, e = entry(27); e["rev"] = "0.45"
        self.assertEqual(e["kind"], "crate_file")
        self.assertTrue(planted(L.check_ledger(doc), "exact version"))
        doc, e = entry(1); e["immutable"] = True
        self.assertEqual(e["kind"], "web_text")
        self.assertTrue(planted(L.check_ledger(doc), "not an immutable pin"))
        doc, e = entry(1); del e["retrieved_utc"]
        self.assertTrue(planted(L.check_ledger(doc), "retrieval time"))
        doc, e = entry(0); e["lines"] = [5, 5]
        self.assertTrue(planted(L.check_ledger(doc), "line range"))
        doc, e = entry(0); e["id"] = "E1"
        self.assertTrue(planted(L.check_ledger(doc), "stable ledger id"))
        doc, e = entry(0); e["claim"] = "see 192.0.2." + "7"
        self.assertTrue(planted(L.check_ledger(doc), "site data"))
        doc, e = entry(0); e["kind"] = "blog"
        self.assertTrue(planted(L.check_ledger(doc), "kind"))

    def test_a_local_excerpt_that_moved_is_reported(self):
        index = next(i for i, e in enumerate(LEDGER["entries"]) if e["kind"] == "local_file")
        with tempfile.TemporaryDirectory() as tmp:
            for e in LEDGER["entries"]:
                if e["kind"] == "local_file":
                    path = os.path.join(tmp, e["path"])
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write("some text\n" + e["excerpt"] + "\nmore text\n")
            self.assertEqual(L.check_ledger(LEDGER, tmp), [])                               # control: the excerpt is in the file
            with open(os.path.join(tmp, LEDGER["entries"][index]["path"]), "w", encoding="utf-8") as handle:
                handle.write("the text was rewritten\n")
            self.assertTrue(planted(L.check_ledger(LEDGER, tmp), "the evidence moved"))
            self.assertTrue(planted(L.check_ledger(LEDGER, os.path.join(tmp, "elsewhere")), "is not in this checkout"))


class Profile(unittest.TestCase):
    def check(self, mutate):
        doc = copy.deepcopy(PROFILE)
        mutate(doc)
        return L.check_profile(doc, LEDGER)

    def test_the_committed_profile_holds(self):
        self.assertEqual(L.check_profile(PROFILE, LEDGER), [])
        self.assertEqual(PROFILE["profile_version"], "t01-profile-2026-11-06.1")

    def test_each_planted_fault_is_reported(self):
        tsrs, go = "tailscale-rs-0.6.1", "tailscale-go-1.104.5"
        self.assertTrue(planted(self.check(lambda d: d["candidates"][go].update({"class": "native_strict_rust"})), "its facts make it official_reference"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][go].update({"counts_as_native": True})), "counts_as_native"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"]["host-gateway"].update({"counts_as_native": True})), "counts_as_native"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["behaviors"]["nat_traversal"]["evidence"].append("T01-E99")), "T01-E99"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["behaviors"]["nat_traversal"].update({"evidence": []})), "without citing evidence"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["platform"]["ppc32be_stock"].pop("conditional_on")), "conditional on"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["platform"].pop("mips32be_harness")), "no valid platform state"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["behaviors"].pop("dns_naming")), "no valid state"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["platform"]["mips32be_harness"].update({"state": "ran_on_target"})), "needs a receipt"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["platform"]["mips32be_harness"].update({"state": "ran_on_target", "receipt": "x"})), "is supported"))
        self.assertTrue(planted(self.check(lambda d: d["targets"]["ppc32be_stock"].update({"kernel_state": "qualified"})), "unqualified"))
        self.assertTrue(planted(self.check(lambda d: d["budgets"].update({"reserve_floor_bytes": 1})), "4 MiB"))
        self.assertTrue(planted(self.check(lambda d: d["budgets"]["tailnet_ram_cap_bytes"].update({"ppc32be_stock": 8388608})), "absent budget is pending"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][tsrs + "/ppc32be_stock"]["rss_peak_bytes"].update({"state": "measured"})), "without a receipt"))
        self.assertTrue(planted(self.check(lambda d: d["measurements"][tsrs + "/mips32r2be_stock"]["cpu"].pop("blocker")), "without its reason"))
        self.assertTrue(planted(self.check(lambda d: d["native_requirement"].update({"waived": True})), "native requirement"))
        self.assertTrue(planted(self.check(lambda d: d["native_requirement"].update({"satisfied_by": [tsrs]})), "native requirement"))
        self.assertTrue(planted(self.check(lambda d: d["native_requirement"]["does_not_close"].remove("T04")), "T04"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs].update({"strict_rust": False})), "strict_rust"))
        self.assertTrue(planted(self.check(lambda d: d["candidates"][tsrs]["facts"].update({"membership": "host_identity"})), "unclassifiable"))
        self.assertTrue(planted(self.check(lambda d: d.update({"profile_version": "latest"})), "frozen version"))

    def test_the_matrix_is_complete_derived_and_has_no_supported_cell(self):
        cells = L.matrix(PROFILE)
        self.assertEqual(len(cells), 5 * 4 * 12)
        self.assertNotIn("supported", cells.values())
        self.assertEqual({c for (cid, t, b), c in cells.items() if cid == "tailscale-go-1.104.5" and t in ("ppc32be_stock", "ppc32be_harness", "mips32r2be_stock")}, {"incompatible"})
        self.assertEqual({c for (cid, t, b), c in cells.items() if cid == "host-gateway"}, {"not_applicable"})
        self.assertEqual(cells[("tailscale-rs-0.6.1", "mips32r2be_stock", "nat_traversal")], "implementable_upstream_work")
        self.assertEqual(cells[("tailscale-rs-0.6.1", "mips32r2be_stock", "enrollment")], "no_evidence")
        self.assertEqual(cells[("tailscale-rs-0.6.1", "ppc32be_stock", "enrollment")], "incompatible")
        self.assertEqual(cells[("tailscale-go-1.104.5", "mips32be_harness", "enrollment")], "no_evidence")

    def test_a_cell_is_never_read_from_the_file(self):
        self.assertNotIn("cells", PROFILE)
        doc = copy.deepcopy(PROFILE)
        doc["candidates"]["tailscale-rs-0.6.1"]["behaviors"]["nat_traversal"]["state"] = "implemented"
        self.assertEqual(L.matrix(doc)[("tailscale-rs-0.6.1", "mips32r2be_stock", "nat_traversal")], "no_evidence")


class Fixtures(unittest.TestCase):
    def test_the_committed_fixtures_equal_the_models_on_hand_written_expectations(self):
        self.assertEqual(L.check_fixtures(*FIX), [])
        self.assertEqual((len(FIX[1]["filter_cases"]), len(FIX[2]["route_cases"]) + len(FIX[2]["no_region_cases"]), len(FIX[3]["steps"])), (12, 9, 12))

    def test_each_planted_fault_is_reported(self):
        ident, netmap, derp, expiry = (copy.deepcopy(x) for x in FIX)
        ident["nodes"][1]["node_key"] = ident["nodes"][0]["node_key"]
        self.assertTrue(planted(L.check_identity(ident), "repeats the key digits"))
        ident = copy.deepcopy(FIX[0]); ident["nodes"][0]["hostname"] = "speaker-a.example.com"
        self.assertTrue(planted(L.check_identity(ident), ".invalid"))
        ident = copy.deepcopy(FIX[0]); ident["nodes"][0]["addresses"] = ["10.1.2." + "3"]
        self.assertTrue(planted(L.check_identity(ident), "outside the tailnet range"))
        ident = copy.deepcopy(FIX[0]); ident["nodes"][0]["machine_key"] = "mkey:abc"
        self.assertTrue(planted(L.check_identity(ident), "placeholder key"))
        ident = copy.deepcopy(FIX[0]); ident["nodes"][3]["disco_key"] = "discokey:" + ident["nodes"][3]["machine_key"].split(":")[1]
        self.assertTrue(planted(L.check_identity(ident), "repeats the key digits"))
        netmap["peer_cap"] = 2
        self.assertTrue(planted(L.check_netmap(netmap, FIX[0]), "exceed the declared cap"))
        netmap = copy.deepcopy(FIX[1]); netmap["filter_cases"][0]["expect"] = "deny"
        self.assertTrue(planted(L.check_netmap(netmap, FIX[0]), "F01"))
        netmap = copy.deepcopy(FIX[1]); netmap["packet_filter"][0]["ports"] = ["*"]
        self.assertTrue(planted(L.check_netmap(netmap, FIX[0]), "F02"))
        netmap = copy.deepcopy(FIX[1]); netmap["peers"][0]["id"] = "node-zz"
        self.assertTrue(planted(L.check_netmap(netmap, FIX[0]), "not an identity"))
        derp["route_cases"][1]["expect"] = "direct"
        self.assertTrue(planted(L.check_derp(derp), "R02"))
        derp = copy.deepcopy(FIX[2]); derp["regions"][1]["latency_ms"] = 99
        self.assertTrue(planted(L.check_derp(derp), "R04"))
        expiry["steps"][4]["expect"] = ["valid", "up", "none"]
        self.assertTrue(planted(L.check_key_expiry(expiry), "K05"))
        expiry = copy.deepcopy(FIX[3]); expiry["policy"]["warn_window_s"] = 0
        self.assertTrue(planted(L.check_key_expiry(expiry), "K03"))

    def test_edges_of_the_models_by_hand(self):
        policy = {"warn_window_s": 100, "max_offline_netmap_age_s": 10}
        self.assertEqual(L.key_step(policy, 1000, 999, True, True, 0), ("expiring", "up", "renew"))
        self.assertEqual(L.key_step(policy, 1000, 1000, True, True, 0), ("expired", "down", "reauthenticate"))
        self.assertEqual(L.key_step(policy, 1000, 899, True, True, 0), ("valid", "up", "none"))
        self.assertEqual(L.key_step(policy, 1000, 900, True, True, 0), ("expiring", "up", "renew"))
        self.assertEqual(L.key_step(policy, 1000, 5000, False, True, 0), ("unknown", "hold", "get_trusted_time"))
        self.assertEqual(L.key_step(policy, 1000, 0, True, False, 10), ("valid", "up_stale", "retry_control"))
        self.assertEqual(L.key_step(policy, 1000, 0, True, False, 11), ("valid", "down", "wait_for_control"))
        netmap = {"packet_filter": [{"srcs": ["a"], "dsts": ["b"], "ports": ["*"], "proto": "*"}]}
        self.assertEqual(L.filter_decision(netmap, "a", "b", 65535, "tcp"), "allow")
        self.assertEqual(L.filter_decision(netmap, "a", "b", 65536, "tcp"), "deny")
        self.assertEqual(L.filter_decision(netmap, "a", "b", -1, "tcp"), "deny")
        self.assertEqual(L.filter_decision(netmap, "a", "b", "80", "tcp"), "deny")
        self.assertEqual(L.filter_decision({"packet_filter": []}, "a", "b", 1, "tcp"), "deny")
        regions = [{"id": 1, "reachable": True, "latency_ms": 5}, {"id": 2, "reachable": True, "latency_ms": 5}]
        self.assertEqual(L.route_for(regions, None, False), "derp:1")                       # equal latency: the lower id
        self.assertEqual(L.route_for([], 1, False), "unreachable")


def write(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(text))


def write_raw(root, rel, text):
    """As `write`, without dedenting: for a file whose exact indentation a probe matches."""
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def synthetic_tsrs(root, extra_dep=None, dev_dep=None, target_dep=None, unsafe_in=None):
    write(root, "Cargo.toml", """
        [workspace]
        members = ["ts_core", "ts_io", "ts_mid"]
        [workspace.package]
        version = "9.9.9"
        rust-version = "1.92.0"
        [package]
        name = "tailscale"
        [dependencies]
        ts_io = { workspace = true }
        """)
    write(root, "Cargo.lock", """
        version = 4
        [[package]]
        name = "tailscale"
        dependencies = ["ts_io", "tokio"]
        [[package]]
        name = "ts_io"
        dependencies = ["ts_core", "tokio"]
        [[package]]
        name = "ts_core"
        [[package]]
        name = "ts_mid"
        dependencies = ["ts_core"]
        [[package]]
        name = "tokio"
        """)
    write(root, "ts_core/Cargo.toml", "[package]\nname = 'ts_core'\n[dependencies]\nserde = '1'\n" + ("[dev-dependencies]\ntokio = '1'\n" if dev_dep else ""))
    write(root, "ts_core/src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n")
    write(root, "ts_mid/Cargo.toml", "[package]\nname = 'ts_mid'\n[dependencies]\nts_core = { workspace = true }\n" + (extra_dep or "") + ("[target.'cfg(unix)'.dependencies]\nlibc = '0.2'\n" if target_dep else ""))
    write(root, "ts_mid/src/lib.rs", "pub fn g() {}\n" + ("unsafe fn h() {}\n" if unsafe_in == "ts_mid" else ""))
    write(root, "ts_io/Cargo.toml", "[package]\nname = 'ts_io'\n[dependencies]\nts_core = { workspace = true }\ntokio = '1'\n")
    write(root, "ts_io/src/lib.rs", "// an unsafe word in a comment still counts: the census is of tokens\npub fn io() {}\n")
    write(root, "README.md", "x\nThe current MSRV is 1.97. The current edition is Rust 2024.\n- Linux (`x86_64`/`ARM64`)\n<details>\n<summary>\nUnsupported features\n</summary>\n\n- Networking\n    - MagicDNS\n    - Peer relays\n</details>\n")
    write(root, "ts_tls_util/Cargo.toml", "[dependencies]\ntokio-rustls = { version = '0.26', features = ['aws-lc-rs'] }\n")
    write(root, "src/lib.rs", "pub fn root() {}\n")


class Probes(unittest.TestCase):
    def test_the_workspace_edge_probe_sees_runtime_crates_through_workspace_edges_and_ignores_dev_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(tmp, dev_dep=True)
            got = L.probe_workspace_edges(tmp)
            self.assertEqual(got["no_runtime_edge_in_workspace"], ["ts_core", "ts_mid"])                      # control: a dev-dependency on tokio does not bind ts_core
            self.assertEqual(got["runtime_edge_in_workspace"], ["tailscale", "ts_io", "ts_tls_util"])
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(tmp, extra_dep="tokio = '1'\n")
            self.assertEqual(L.probe_workspace_edges(tmp)["runtime_edge_in_workspace"], ["tailscale", "ts_io", "ts_mid", "ts_tls_util"])
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(tmp, target_dep=True)
            self.assertIn("ts_mid", L.probe_workspace_edges(tmp)["runtime_edge_in_workspace"])               # a target-specific dependency is a dependency

    def test_the_census_probe_counts_and_a_wrong_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(tmp, unsafe_in="ts_mid")
            facts = L.probe_tsrs(tmp)
            self.assertEqual((facts["lock_packages"], facts["lock_distinct_names"], facts["lock_closure_of_tailscale"], facts["lock_closure_ts_crates"]), (5, 5, 4, 2))
            self.assertEqual((facts["workspace_members_declared"], facts["member_dirs"], facts["forbid_unsafe_crates"]), (3, 4, 1))
            self.assertEqual(facts["unsafe_tokens"], {"ts_io": 1, "ts_mid": 1})
            self.assertEqual((facts["readme_msrv"], facts["rust_version_manifest"]), ("1.97", "1.92.0"))
            self.assertEqual(facts["readme_unsupported_items"], ["MagicDNS", "Peer relays"])
            self.assertEqual(facts["readme_platforms"], ["Linux (`x86_64`/`ARM64`)"])
            self.assertIn("aws-lc-rs", facts["tls_backend_line"])
            same = L.probe_tsrs(tmp)
            self.assertEqual(L.check_probe(facts, same, "t"), [])                               # control
            expected = dict(facts, lock_packages=6)
            self.assertTrue(planted(L.check_probe(facts, expected, "t"), "lock_packages is 5"))
            self.assertTrue(planted(L.check_probe(facts, dict(facts, extra=1), "t"), "did not report"))
            self.assertTrue(planted(L.check_probe(dict(facts, extra=1), facts, "t"), "does not record"))
        with tempfile.TemporaryDirectory() as other:
            synthetic_tsrs(other)
            write(other, "ts_core/src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n// changed\n")
            self.assertNotEqual(L.tree_digest(other), L.probe_tsrs(other)["tree_sha256"] + "x")
            before = L.tree_digest(other)
            write(other, "ts_core/src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n// changed again\n")
            self.assertNotEqual(L.tree_digest(other), before)                                      # the digest binds the content

    def test_the_awslc_and_mio_probes(self):
        builder = "\n".join([
            '    } else if target_vendor() == "apple" {', "        x", '    } else if target_arch() == "x86_64" {', "        a", '    } else if target_arch() == "powerpc64" {', "        b",
            "    } else {", "        target_specific_source_found = false;", "    }", '    assert!(!is_no_asm(), "AWS_LC_SYS_NO_ASM only allowed for debug builds!");', ""])
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "Cargo.toml", "[package]\nname = 'aws-lc-sys'\nversion = '0.45.0'\n")
            write_raw(tmp, "builder/cc_builder.rs", builder)
            write(tmp, "aws-lc/include/openssl/target.h", "#  define OPENSSL_PPC32BE\n#    define OPENSSL_MIPS\n")
            facts = L.probe_awslc(tmp)
            self.assertEqual(facts["asm_source_sets"], ["x86_64", "powerpc64"])
            self.assertTrue(facts["no_asm_refused_in_release"])
            self.assertEqual(facts["header_defines"], {"OPENSSL_PPC32BE": True, "OPENSSL_MIPS": True, "OPENSSL_PPC64BE": False, "OPENSSL_PPC64LE": False})
            write_raw(tmp, "builder/cc_builder.rs", builder.replace("AWS_LC_SYS_NO_ASM only allowed for debug builds!", "fine"))
            self.assertFalse(L.probe_awslc(tmp)["no_asm_refused_in_release"])                  # a relaxed refusal would be seen
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "Cargo.toml", "[package]\nname = 'mio'\nversion = '1.2.1'\n")
            write(tmp, "src/sys/unix/selector/epoll.rs", "let ep = syscall!(epoll_create1(libc::EPOLL_CLOEXEC))?;\n")
            self.assertEqual(L.probe_mio(tmp)["epoll_create1_calls"], 1)
            self.assertEqual(L.probe_mio(tmp)["plain_epoll_create_calls"], 0)
            write(tmp, "src/sys/unix/selector/epoll.rs", "let ep = syscall!(epoll_create1(libc::EPOLL_CLOEXEC))?;\nlet old = syscall!(epoll_create(1024))?;\n")
            self.assertEqual(L.probe_mio(tmp)["plain_epoll_create_calls"], 1)                   # a fallback would be seen

    def test_the_ledger_is_checked_against_a_supplied_file_and_a_changed_file_or_line_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = "line one\nTARGET LINE A\nTARGET LINE B\nlast\n"
            write(tmp, "tailscale-rs/README.md", body)
            excerpt = "TARGET LINE A\nTARGET LINE B"
            entry = {"id": "T01-E01", "topic": "t", "kind": "git_file", "repo": "tailscale/tailscale-rs", "rev": "a" * 40, "path": "README.md", "lines": [2, 3], "immutable": True,
                     "source_sha256": hashlib.sha256(body.encode()).hexdigest(), "excerpt": excerpt, "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(), "claim": "c"}
            ledger = {"schema": "ffw.t01.ledger.v1", "entries": [entry]}
            self.assertEqual(L.check_ledger(ledger), [])
            self.assertEqual(rc.ledger_against_sources(ledger, tmp), [])
            write(tmp, "tailscale-rs/README.md", body.replace("LINE A", "LINE Z"))
            self.assertTrue(planted(rc.ledger_against_sources(ledger, tmp), "not the file the excerpt was cut from"))
            write(tmp, "tailscale-rs/README.md", "extra\n" + body)
            self.assertTrue(planted(rc.ledger_against_sources(ledger, tmp), "not the file the excerpt was cut from"))
            self.assertTrue(planted(rc.ledger_against_sources(ledger, os.path.join(tmp, "nowhere")), "could be re-checked"))

    @unittest.skipUnless(os.environ.get("T01_SOURCES"), "set T01_SOURCES to a directory holding the pinned trees to run the probes on them")
    def test_the_probes_on_the_real_pinned_trees(self):
        sources = os.environ["T01_SOURCES"]
        results = {r.case_id: r.status for r in rc.run("full", sources)}
        for case_id in ("T01-P01-tsrs-source", "T01-P02-workspace-edges", "T01-P03-awslc-targets", "T01-P04-mio-reactor", "T01-P05-ledger-vs-sources"):
            self.assertEqual(results[case_id], "passed", case_id)


def synthetic_reach(root, with_libc=True):
    """ts_core -> rand -> getrandom [-> libc]: the pinned counterexample shape in miniature, with a control that removes the last edge."""
    registry = "source = 'registry+https://github.com/rust-lang/crates.io-index'\n"
    write(root, "Cargo.toml", "[workspace]\nmembers = ['ts_core']\n")
    write(root, "Cargo.lock", "version = 4\n[[package]]\nname = 'ts_core'\nversion = '0.1.0'\ndependencies = ['rand']\n"
          "[[package]]\nname = 'rand'\nversion = '0.10.2'\n" + registry + "checksum = '" + "a" * 64 + "'\ndependencies = ['getrandom']\n"
          "[[package]]\nname = 'getrandom'\nversion = '0.4.3'\n" + registry + "checksum = '" + "b" * 64 + "'\n" + ("dependencies = ['libc']\n" if with_libc else "") +
          "[[package]]\nname = 'libc'\nversion = '0.2.1'\n" + registry + "checksum = '" + "c" * 64 + "'\n")
    write(root, "ts_core/Cargo.toml", "[package]\nname = 'ts_core'\n[dependencies]\nrand = '0.10'\n")
    write(root, "ts_core/src/lib.rs", "pub fn f() {}\n")


class Bounds(unittest.TestCase):
    """Review defects 1-3: an error inside a case is a failed case (no traceback, no path), a supplied tree is bounded and plain, and the workspace-edge fact does not claim portability."""

    def receipt_text(self, directory):
        names = [n for n in os.listdir(directory) if n.startswith("t01-") and n.endswith(".json")]
        self.assertEqual(len(names), 1, names)
        with open(os.path.join(directory, names[0]), encoding="utf-8") as handle:
            return handle.read()

    def test_a_malformed_present_tree_is_a_failed_case_with_the_cause_and_without_the_path(self):
        data = rc.inputs()
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "tailscale-rs"))                                       # present and empty: no Cargo.lock
            result = rc.case_tsrs(data, tmp)
            self.assertEqual(result.status, "failed")
            self.assertIn("FileNotFoundError", result.detail)
            self.assertIn("Cargo.lock", result.detail)
            self.assertNotIn(tmp, result.detail)
            write(tmp, "tailscale-rs/Cargo.lock", "this is not toml [[\n")
            bad = rc.case_tsrs(data, tmp)
            self.assertEqual(bad.status, "failed")
            self.assertIn("TOMLDecodeError", bad.detail)
            self.assertNotIn(tmp, bad.detail)

    def test_the_command_line_run_of_a_malformed_tree_logs_and_receipts_instead_of_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "src", "tailscale-rs"))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = rc.main(["--tier", "full", "--sources", os.path.join(tmp, "src"), "--receipts", os.path.join(tmp, "r")])
            self.assertEqual(code, 1)                                                          # a failed case, not a crash and not a pass
            self.assertNotIn("Traceback", out.getvalue() + err.getvalue())
            text = self.receipt_text(os.path.join(tmp, "r"))
            self.assertIn("FileNotFoundError", text)
            self.assertNotIn(tmp, text)
            self.assertIn("RETAINED FOR REPLAY", out.getvalue())
            # the positive beside it: a plain tree of the same shape passes the bounds
            synthetic_tsrs(os.path.join(tmp, "good", "tailscale-rs"))
            self.assertGreater(len(L.bounded_tree(os.path.join(tmp, "good", "tailscale-rs"))), 5)

    def test_the_runner_logs_even_when_the_run_itself_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with mock.patch.object(rc, "run", side_effect=RuntimeError("boom")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = rc.main(["--tier", "smoke", "--receipts", tmp])
            self.assertEqual(code, 1)
            text = self.receipt_text(tmp)
            self.assertIn("T01-RUNNER", text)
            self.assertIn("RuntimeError", text)

    def test_every_smoke_case_that_raises_is_a_failed_case(self):
        def boom(_data, _repo):
            raise ValueError("planted")
        with mock.patch.object(rc, "SMOKE_CASES", (boom,) + rc.SMOKE_CASES[1:]):
            results = {r.case_id: r for r in rc.run("smoke")}
        self.assertEqual(results["T01-META-LEDGER"].status, "failed")
        self.assertIn("ValueError", results["T01-META-LEDGER"].detail)
        self.assertEqual(results["T01-META-PROFILE"].status, "passed")                        # the others still ran

    def test_a_supplied_tree_must_be_plain_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "good")
            write(good, "a/b.txt", "x\n")
            self.assertEqual(L.bounded_tree(good), [("a/b.txt", 2)])                           # control: the plain tree passes
            outside = os.path.join(tmp, "outside.txt")
            write(tmp, "outside.txt", "secret\n")
            link = os.path.join(tmp, "link")
            write(link, "ok.txt", "x\n")
            os.symlink(outside, os.path.join(link, "escape.txt"))
            with self.assertRaises(L.SourceRefused) as caught:
                L.bounded_tree(link)
            self.assertIn("escape.txt is a symlink", str(caught.exception))
            self.assertNotIn(tmp, str(caught.exception))
            inner = os.path.join(tmp, "inner")
            write(inner, "real/f.txt", "x\n")
            os.symlink("real", os.path.join(inner, "dirlink"))                                 # an in-tree directory link is refused too
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(inner)
            fifo = os.path.join(tmp, "fifo")
            os.mkdir(fifo)
            os.mkfifo(os.path.join(fifo, "pipe"))                                              # would block an open(); lstat never opens it
            started = time.monotonic()
            with self.assertRaises(L.SourceRefused) as caught:
                L.bounded_tree(fifo)
            self.assertIn("not a regular file", str(caught.exception))
            self.assertLess(time.monotonic() - started, 2.0)
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(os.path.join(tmp, "missing"))
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(outside)                                                       # not a directory

    def test_the_caps_are_enforced_and_the_real_numbers_clear_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n in range(5):
                write(tmp, "f%d.txt" % n, "0123456789")
            self.assertEqual(len(L.bounded_tree(tmp)), 5)
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(tmp, max_files=4)
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(tmp, max_bytes=49)
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(tmp, max_file_bytes=9)
            write(tmp, "d1/d2/d3/x.txt", "x")
            with self.assertRaises(L.SourceRefused):
                L.bounded_tree(tmp, max_depth=2)
            with self.assertRaises(L.SourceRefused) as caught:
                L.bounded_tree(tmp, seconds=-1.0)                                              # an already-passed deadline
            self.assertIn("deadline", str(caught.exception))
        self.assertGreaterEqual(L.MAX_FILES, 2029 * 2)                                         # the measured pinned maxima (see the contract) clear the caps with room
        self.assertGreaterEqual(L.MAX_TOTAL_BYTES, 67030645 * 2)
        self.assertGreaterEqual(L.MAX_FILE_BYTES, 3299348 * 2)
        self.assertGreaterEqual(L.MAX_DEPTH, 8 * 2)

    def test_the_probes_refuse_a_hostile_tree_as_a_failed_case_and_never_open_it(self):
        data = rc.inputs()
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(os.path.join(tmp, "tailscale-rs"))
            os.mkfifo(os.path.join(tmp, "tailscale-rs", "pipe"))
            started = time.monotonic()
            for case in (rc.case_tsrs, rc.case_workspace_edges):
                result = case(data, tmp)
                self.assertEqual(result.status, "failed", case.__name__)
                self.assertIn("not a regular file", result.detail)
                self.assertNotIn(tmp, result.detail)
            self.assertLess(time.monotonic() - started, 5.0)
            os.remove(os.path.join(tmp, "tailscale-rs", "pipe"))
            os.symlink(os.path.join(tmp, "tailscale-rs", "README.md"), os.path.join(tmp, "tailscale-rs", "readme-link"))
            self.assertIn("is a symlink", rc.case_tsrs(data, tmp).detail)
            self.assertIn("is a symlink", rc.case_ledger_sources(data, tmp).detail)           # the ledger re-cut refuses it as well

    def test_a_hung_probe_is_cut_by_the_one_absolute_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "mio"))
            started = time.monotonic()
            with mock.patch.object(L, "PROBE_SECONDS", 0.3):
                result = rc.probe_case("T01-P04-mio-reactor", "mio", tmp, lambda _path: time.sleep(30) or [])
            self.assertEqual(result.status, "failed")
            self.assertIn("TimeoutError", result.detail)
            self.assertIn("deadline", result.detail)
            self.assertLess(time.monotonic() - started, 5.0)
        with self.assertRaises(TimeoutError):
            L.with_deadline(0.2, lambda: time.sleep(30))
        self.assertEqual(L.with_deadline(5.0, lambda: 7), 7)                                   # control: a quick call returns its value

    def test_a_failure_detail_names_the_type_and_never_the_supplied_path(self):
        self.assertEqual(rc.failure_detail(FileNotFoundError(2, "No such file", "/private/some/where/Cargo.lock")), "FileNotFoundError while reading a supplied input (Cargo.lock)")
        self.assertEqual(rc.failure_detail(KeyError("workspace"), "/x/src"), "KeyError: 'workspace'")
        self.assertNotIn("/x/src", rc.failure_detail(ValueError("bad /x/src/a"), "/x/src"))

    def test_the_third_party_reach_is_reported_and_the_control_without_the_edge_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_reach(tmp)
            self.assertEqual(L.probe_third_party_reach(tmp, ["ts_core"]), {"ts_core": ["libc"]})
            self.assertIn("ts_core", L.probe_workspace_edges(tmp)["no_runtime_edge_in_workspace"])  # the workspace-edge fact alone would call it free: that is the overreach
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_reach(tmp, with_libc=False)
            self.assertEqual(L.probe_third_party_reach(tmp, ["ts_core"]), {"ts_core": []})

    def test_the_committed_wording_does_not_claim_portability_or_closure(self):
        profile = L.load_json(L.PROFILE)
        facts = profile["derived_facts"]["tailscale-rs-0.6.1/workspace_edges"]
        self.assertEqual(facts["third_party_reaches_runtime_or_os"]["ts_tunnel"], ["libc"])
        self.assertEqual(profile["native_requirement"]["closes"], [])
        self.assertIn("INCOMPLETE", profile["status"])
        for rel in ("docs/tailscale/feasibility.md", "docs/contracts/t01.md", "docs/tailscale/profiles.json"):
            with open(os.path.join(REPO, rel), encoding="utf-8") as handle:
                text = handle.read()
            for banned in ("portable_core", "runtime-free", "runtime_free", "This closes the T01 investigation", "closes the T01 investigation at most"):
                self.assertNotIn(banned, text, rel)
        with open(os.path.join(REPO, "docs/contracts/t01.md"), encoding="utf-8") as handle:
            contract = handle.read()
        self.assertIn("INCOMPLETE and pending", contract)
        self.assertIn("NOT a portability finding", contract)


class ReadBoundary(unittest.TestCase):
    """TanGate 8056: the bound must hold at the READ, not only at the preflight. A tree that changes after admission is refused; a deadline that cannot be enforced is not run."""

    def admitted(self, tmp, files):
        root = os.path.join(tmp, "tree")
        for rel, text in files.items():
            write(root, rel, text)
        return root, L.Source(root)

    def test_a_file_that_grows_after_admission_is_refused_not_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "tree")
            write(root, "a.txt", "x")
            real = L.bounded_tree

            def preflight_then_grow(path, **limits):
                got = real(path, **limits)
                with open(os.path.join(root, "a.txt"), "wb") as handle:
                    handle.write(b"y" * (L.MAX_FILE_BYTES + 1))                                # TanGate's witness: grown past the per-file cap after the preflight
                return got
            with mock.patch.object(L, "bounded_tree", preflight_then_grow):
                with self.assertRaises(L.SourceRefused) as caught:
                    L.tree_digest(root)
            self.assertIn("at read time, admitted as 1", str(caught.exception))
            self.assertNotIn(tmp, str(caught.exception))
        with tempfile.TemporaryDirectory() as tmp:                                              # control: unchanged, the digest is the one computed independently
            root, src = self.admitted(tmp, {"a.txt": "x", "d/b.txt": "yz"})
            expect = L.sha256_text("a.txt\0%s\nd/b.txt\0%s\n" % (hashlib.sha256(b"x").hexdigest(), hashlib.sha256(b"yz").hexdigest()))
            self.assertEqual(L.tree_digest(src), expect)
            self.assertEqual(src.read_total, 3)

    def test_a_file_swapped_for_a_fifo_or_a_symlink_after_admission_is_refused_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, src = self.admitted(tmp, {"f.txt": "abc", "g.txt": "abc"})
            outside = os.path.join(tmp, "outside.txt")
            write(tmp, "outside.txt", "abc")
            os.remove(os.path.join(root, "f.txt"))
            os.mkfifo(os.path.join(root, "f.txt"))
            os.remove(os.path.join(root, "g.txt"))
            os.symlink(outside, os.path.join(root, "g.txt"))
            started = time.monotonic()
            with self.assertRaises(L.SourceRefused) as fifo:
                src.read("f.txt")
            self.assertIn("not a regular file at read time", str(fifo.exception))
            with self.assertRaises(L.SourceRefused) as link:
                src.read("g.txt")                                                              # same size and content as the original: only O_NOFOLLOW stops it
            self.assertIn("cannot be read safely", str(link.exception))
            self.assertLess(time.monotonic() - started, 2.0)

    def test_a_parent_directory_or_the_root_swapped_for_another_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, src = self.admitted(tmp, {"d/f.txt": "abc"})
            other = os.path.join(tmp, "other")
            write(other, "f.txt", "abc")
            os.rename(os.path.join(root, "d"), os.path.join(tmp, "d.moved"))
            os.symlink(other, os.path.join(root, "d"))                                         # a parent component is now a link to a tree with an identical file
            with self.assertRaises(L.SourceRefused):
                src.read("d/f.txt")
        with tempfile.TemporaryDirectory() as tmp:
            root, src = self.admitted(tmp, {"f.txt": "abc"})
            os.rename(root, os.path.join(tmp, "tree.moved"))
            write(root, "f.txt", "abc")                                                        # a different directory now stands at the admitted path
            with self.assertRaises(L.SourceRefused) as caught:
                src.read("f.txt")
            self.assertIn("not the directory that was admitted", str(caught.exception))

    def test_only_admitted_files_are_read_and_the_total_is_finite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "tree")
            write(root, "a.txt", "0123456789")
            write(root, "b.txt", "0123456789")
            src = L.Source(root, max_read=15)
            self.assertEqual(src.read("a.txt"), b"0123456789")
            with self.assertRaises(L.SourceRefused) as caught:
                src.read("b.txt")                                                              # 10 + 10 > 15
            self.assertIn("read total", str(caught.exception))
            write(root, "late.txt", "x")                                                       # created after admission: never opened
            with self.assertRaises(FileNotFoundError):
                src.read("late.txt")
            self.assertEqual(L.Source(root).text("a.txt"), "0123456789")                       # control: a fresh admission reads it

    def test_a_directory_with_too_many_entries_is_refused_before_any_sorting(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n in range(10):
                os.mkdir(os.path.join(tmp, "d%d" % n))                                         # no files at all: only the entry count can stop it
            with self.assertRaises(L.SourceRefused) as caught:
                L.bounded_tree(tmp, max_files=3)
            self.assertIn("more than 3 entries", str(caught.exception))

    def test_a_deadline_that_cannot_be_enforced_fails_closed_and_never_runs_the_probe(self):
        called = []
        with self.assertRaises(TimeoutError):
            L.with_deadline(-1, lambda: called.append("expired"))
        with mock.patch.object(L, "_deadline_supported", return_value=False):
            with self.assertRaises(L.SourceRefused) as caught:
                L.with_deadline(5.0, lambda: called.append("unsupported"))
        self.assertIn("cannot be enforced", str(caught.exception))
        outcome = []

        def in_thread():
            try:
                L.with_deadline(5.0, lambda: called.append("thread"))
            except Exception as err:  # noqa: BLE001 - the witness is the type
                outcome.append(type(err).__name__)
        worker = threading.Thread(target=in_thread)
        worker.start()
        worker.join(10)
        self.assertEqual(outcome, ["SourceRefused"])
        self.assertEqual(called, [])                                                           # not one of the three ran
        self.assertEqual(L.with_deadline(5.0, lambda: 7), 7)                                   # control: the main thread with a live deadline still runs
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(os.path.join(tmp, "tailscale-rs"))
            with mock.patch.object(L, "_deadline_supported", return_value=False):
                result = rc.case_tsrs(rc.inputs(), tmp)
            self.assertEqual(result.status, "failed")                                          # the case is a failure, not an unbounded pass
            self.assertIn("cannot be enforced", result.detail)

    def test_the_ledger_recut_reads_through_the_same_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "tailscale-rs")
            write(root, "README.md", "line one\nline two\n")
            digest = hashlib.sha256(b"line one\nline two\n").hexdigest()
            ledger = {"entries": [{"id": "T01-E99", "repo": "tailscale/tailscale-rs", "path": "README.md", "source_sha256": digest, "lines": [1, 1], "excerpt": "line one"}]}
            self.assertEqual(rc.ledger_against_sources(ledger, tmp), [])                       # control: the plain tree re-cuts
            real = L.bounded_tree

            def preflight_then_grow(path, **limits):
                got = real(path, **limits)
                with open(os.path.join(root, "README.md"), "ab") as handle:
                    handle.write(b"x" * 100)
                return got
            with mock.patch.object(L, "bounded_tree", preflight_then_grow):
                with self.assertRaises(L.SourceRefused):
                    rc.ledger_against_sources(ledger, tmp)
                self.assertEqual(rc.case_ledger_sources({"ledger": ledger}, tmp).status, "failed")


class Runner(unittest.TestCase):
    def test_the_tiers_plan_what_they_say(self):
        self.assertEqual(len(rc.planned_ids("smoke")), 8)
        self.assertEqual(len(rc.planned_ids("full")), 15)
        self.assertEqual(sorted(rc.DESCRIPTIONS), sorted(rc.planned_ids("full")))
        with self.assertRaises(ValueError):
            rc.run("soak")
        self.assertEqual(rc.SOAK_EXIT, 4)

    def test_smoke_passes_and_full_without_sources_blocks_exactly_the_source_and_central_cases(self):
        smoke = {r.case_id: r.status for r in rc.run("smoke")}
        self.assertEqual(set(smoke.values()), {"passed"})
        full = {r.case_id: r.status for r in rc.run("full")}
        self.assertEqual({k for k, v in full.items() if v == "blocked"}, set(rc.FULL_IDS))
        self.assertEqual({k for k, v in full.items() if v == "passed"}, set(rc.SMOKE_IDS))

    def test_a_wrong_source_tree_fails_its_probe_instead_of_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(os.path.join(tmp, "tailscale-rs"))
            full = {r.case_id: (r.status, r.detail) for r in rc.run("full", tmp)}
            self.assertEqual(full["T01-P01-tsrs-source"][0], "failed")
            self.assertIn("on the supplied source", full["T01-P01-tsrs-source"][1])
            self.assertEqual(full["T01-P02-workspace-edges"][0], "failed")
            self.assertEqual(full["T01-P03-awslc-targets"][0], "blocked")                      # that tree was not supplied

    def test_a_receipt_nobody_can_judge_yet_is_still_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "toolchain/results/tailscale/builds/x.json", "{}\n")
            write(tmp, "toolchain/results/tailscale/measurements/x.json", "{}\n")
            self.assertEqual(rc.case_build(tmp).status, "blocked")
            self.assertIn("no judge for it yet", rc.case_build(tmp).detail)
            self.assertEqual(rc.case_resources(tmp).status, "blocked")
            self.assertIn("no judge for it yet", rc.case_resources(tmp).detail)
            self.assertEqual(rc.case_build(os.path.join(tmp, "empty")).status, "blocked")

    def test_the_native_requirement_case_reports_each_planted_weakening(self):
        data = rc.inputs()
        self.assertEqual(rc.case_native_requirement(data, REPO).status, "passed")
        weak = copy.deepcopy(data)
        weak["profile"]["native_requirement"]["waived"] = True
        self.assertEqual(rc.case_native_requirement(weak, REPO).status, "failed")
        weak = copy.deepcopy(data)
        weak["profile"]["candidates"]["host-gateway"]["counts_as_native"] = True
        self.assertIn("counts as native", rc.case_native_requirement(weak, REPO).detail)
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "docs/contracts/t01.md", "A negative result closes the investigation only.\n")
            self.assertIn("lacks the statement", rc.case_native_requirement(data, tmp).detail)

    def test_a_failure_detail_is_redacted_before_it_is_printed_or_recorded(self):
        self.assertNotIn("abcdef0123456789", rc.Result("T01-X", "failed", "boom " + SECRET).detail)
        self.assertEqual(rc.Result("T01-X", "failed", "plain words").detail, "plain words")


class TheLogAndReceipt(unittest.TestCase):
    def test_a_run_writes_a_complete_log_and_a_receipt_without_a_local_path_and_never_overwrites_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = rc.run("full")
            log = case_log.CaseLog.open(REPO, "r1", "full", tmp)
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            evidence = log.finish(rc.summarize(results))
            self.assertTrue(evidence.complete, evidence.reasons)
            path = rc.write_receipt(tmp, "full", results, rc.artifact_digests(), None, "r1", evidence)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            doc = json.loads(text)
            self.assertEqual((doc["schema"], doc["tier"], doc["exit_code"], doc["counts"]), (rc.RECEIPT_SCHEMA, "full", 3, {"passed": 8, "failed": 0, "blocked": 7}))
            self.assertEqual(set(doc["artifacts"].values()) & {"missing"}, set())
            self.assertEqual(sorted(os.path.splitext(n)[1] for n in os.listdir(tmp)), [".json", ".jsonl"])
            self.assertNotIn(tmp, text)
            self.assertNotIn(os.path.expanduser("~"), text)
            with self.assertRaises(FileExistsError):
                rc.write_receipt(tmp, "full", results, rc.artifact_digests(), None, "r1", evidence)

    def test_lost_critical_evidence_makes_a_run_that_would_pass_not_qualified(self):
        results = rc.run("smoke")
        self.assertEqual(rc.exit_code(results), 0)
        diag = case_log.load(REPO)

        def evidence(target):
            log = case_log.CaseLog.open(REPO, "t1", "smoke", target=target)
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            return log.finish(rc.summarize(results))

        whole = evidence(diag.FaultableSink())
        self.assertTrue(whole.complete, whole.reasons)                                           # control
        self.assertEqual(rc.final_exit(results, whole), 0)
        full = evidence(diag.FaultableSink(capacity_bytes=1_500))
        self.assertFalse(full.complete)
        self.assertEqual(rc.final_exit(results, full), 1)
        blocked = results + [rc.Result("T01-X", "blocked", "x")]
        self.assertEqual((rc.final_exit(blocked, full), rc.final_exit(blocked, whole)), (3, 3))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc.report(results, "smoke", None, rc.artifact_digests(), full)
        self.assertIn("NOT QUALIFIED", out.getvalue())

    def test_a_non_pass_prints_how_to_replay_it_and_the_digest_of_everything_judged(self):
        lines = rc.retained_lines(rc.run("full"), "full", None, rc.artifact_digests())
        self.assertTrue(lines[0].startswith("RETAINED FOR REPLAY. First blocked case: T01-P01-tsrs-source"))
        self.assertEqual(lines[1], "  replay: scripts/e2e/t01 --tier full")
        self.assertTrue(any(l.startswith("  artifact docs/tailscale/profiles.json sha256 ") for l in lines))
        self.assertEqual(rc.retained_lines(rc.run("smoke"), "smoke", None, rc.artifact_digests()), [])
        with_sources = rc.retained_lines(rc.run("full"), "full", "/some/where/private", rc.artifact_digests())
        self.assertEqual(with_sources[1], "  replay: scripts/e2e/t01 --tier full --sources SOURCES_DIR")
        self.assertFalse(any("/some/where/private" in l for l in with_sources))


class TheEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def call(self, *argv):
        done = subprocess.run([ENTRY, *argv], capture_output=True, text=True, stdin=subprocess.DEVNULL, env=dict(os.environ, TMPDIR=self.scratch.name), timeout=300)
        return done.returncode, done.stdout, done.stderr

    def test_the_tiers_exit_codes_and_usage_through_the_real_entry_point(self):
        code, out, err = self.call("--tier", "smoke")
        self.assertEqual(code, 0, out + err)
        self.assertIn("T01 e2e tier=smoke: QUALIFIED  planned=8 passed=8 failed=0 blocked=0", out)
        self.assertIn("evidence COMPLETE", out)
        code, out, _ = self.call()
        self.assertEqual(code, 3, out)
        self.assertIn("planned=15 passed=8 failed=0 blocked=7", out)
        self.assertIn("BLOCKED  T01-X01-legacy-isa-build", out)
        code, out, _ = self.call("--tier", "soak")
        self.assertEqual((code, "T01 soak: NOT RUN" in out, "This is not a pass." in out), (4, True, True))
        code, out, _ = self.call("--tier", "full", "--list")
        self.assertEqual((code, len(out.strip().splitlines())), (0, 15))
        self.assertEqual(self.call("--no-such-flag")[0], 2)
        code, _, err = self.call("--sources", "/nonexistent/place")
        self.assertEqual((code, "sources directory was not found" in err, "/nonexistent" in err), (2, True, False))


if __name__ == "__main__":
    unittest.main()
