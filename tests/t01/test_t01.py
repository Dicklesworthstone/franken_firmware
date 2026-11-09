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
        self.assertEqual(PROFILE["profile_version"], "t01-profile-2026-11-07.1")      # the version bump the profile's own rule asks for; the old version is named in frozen_note

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
        done = {"T01-X01-legacy-isa-build", "T01-X02-target-resources"}      # all four X01 attempts have a built record; X02 has a passed guest run on each target (measurements/)
        self.assertEqual({k for k, v in full.items() if v == "blocked"}, set(rc.FULL_IDS) - done)
        self.assertEqual({k for k, v in full.items() if v == "passed"}, set(rc.SMOKE_IDS) | done)

    def test_a_wrong_source_tree_fails_its_probe_instead_of_passing(self):
        with tempfile.TemporaryDirectory() as tmp:
            synthetic_tsrs(os.path.join(tmp, "tailscale-rs"))
            full = {r.case_id: (r.status, r.detail) for r in rc.run("full", tmp)}
            self.assertEqual(full["T01-P01-tsrs-source"][0], "failed")
            self.assertIn("on the supplied source", full["T01-P01-tsrs-source"][1])
            self.assertEqual(full["T01-P02-workspace-edges"][0], "failed")
            self.assertEqual(full["T01-P03-awslc-targets"][0], "blocked")                      # that tree was not supplied

    def test_a_build_receipt_nobody_can_judge_yet_is_still_blocked_and_a_foreign_measurement_file_now_fails_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "toolchain/results/tailscale/builds/x.json", "{}\n")
            write(tmp, "toolchain/results/tailscale/measurements/x.json", "{}\n")
            self.assertEqual(rc.case_build(tmp).status, "blocked")
            self.assertIn("no judge for it yet", rc.case_build(tmp).detail)
            self.assertEqual(rc.case_resources(tmp).status, "failed")                          # X02 has a judge now: a file that is not its receipt is a failure, named
            self.assertIn("x.json", rc.case_resources(tmp).detail)
            self.assertIn("schema", rc.case_resources(tmp).detail)
            self.assertEqual(rc.case_build(os.path.join(tmp, "empty")).status, "blocked")
            self.assertEqual(rc.case_resources(os.path.join(tmp, "empty")).status, "blocked")  # and no receipt at all is still blocked

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
            self.assertEqual((doc["schema"], doc["tier"], doc["exit_code"], doc["counts"]), (rc.RECEIPT_SCHEMA, "full", 3, {"passed": 10, "failed": 0, "blocked": 5}))
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


class BuildRecord(unittest.TestCase):
    """T01-X01: the judge of the captured, compile-only build record. The positive control is the first REAL record (the redacted PowerPC log committed under
    toolchain/results/tailscale/builds/); every plant is made in a copy of its text, must be reported for the named reason, and the unplanted text must pass again."""
    BUILDS = os.path.join(REPO, "toolchain", "results", "tailscale", "builds")
    PPC = os.path.join(BUILDS, "x01-core-powerpc-unknown-linux-musl-20261107.log")
    PREFIX = "[RCH] source content receipt:"
    SEED_LOCK = "4745e012086b9abeb901c26541e95cea35cb65a868a3a76fc95b018e6fe8b6fd"

    @classmethod
    def setUpClass(cls):
        cls.anchors = CASES["x01_build"]
        cls.pin = PROFILE["derived_facts"]["tailscale-rs-0.6.1"]["tree_sha256"]
        cls.lock = L.read_bounded_file(os.path.join(REPO, *cls.anchors["lock_fixture"].split("/"))).decode("utf-8")
        cls.text = L.read_bounded_file(cls.PPC).decode("utf-8")
        real = lambda kind, target: L.read_bounded_file(os.path.join(cls.BUILDS, "x01-%s-%s-unknown-linux-musl-20261107.log" % (kind, target))).decode("utf-8")
        cls.core_ppc, cls.core_mips, cls.whole_ppc, cls.whole_mips = cls.text, real("core", "mips"), real("whole", "powerpc"), real("whole", "mips")
        tagged = lambda tag: L.read_bounded_file(os.path.join(cls.BUILDS, "x01-whole-mips-unknown-linux-musl-%s-20261107.log" % tag)).decode("utf-8")
        cls.zig_inline, cls.zig_keys, cls.zig_ccrs, cls.zig_ccrs_v2 = tagged("zig-inline"), tagged("zig-keys"), tagged("zig-ccrs"), tagged("zig-ccrs-v2")
        cls.six = {"1.log": cls.core_ppc, "2.log": cls.core_mips, "3.log": cls.whole_ppc, "4.log": cls.whole_mips, "5.log": cls.zig_inline, "6.log": cls.zig_keys}

    def judge(self, text, redacted=True):
        return L.judge_build_record(text, self.anchors, self.pin, self.lock, redacted)

    def plant(self, name, mutate, needle, base=None):
        """Control, plant, reported for the named reason, and the unplanted record passing again."""
        base = self.text if base is None else base
        self.assertEqual(self.judge(base)[0], [], name + ": control")
        text = mutate(base)
        self.assertNotEqual(text, base, name + ": the plant changed nothing")
        problems, _ = self.judge(text)
        self.assertTrue(planted(problems, needle), "%s: %r not in %r" % (name, needle, problems[:4]))
        self.assertEqual(self.judge(base)[0], [], name + ": removing the plant restores the pass")

    def edit_receipt(self, text, fn):
        out = []
        for line in text.split("\n"):
            if line.startswith(self.PREFIX):
                doc = json.loads(line.split(":", 1)[1].strip())
                fn(doc)
                line = self.PREFIX + " " + json.dumps(doc, separators=(",", ":"))
            out.append(line)
        return "\n".join(out)

    def files(self, doc):
        return doc["roots"][0]["files"]

    @staticmethod
    def drop(text, needle, start='{"reason":"compiler-artifact"'):
        return "\n".join(line for line in text.split("\n") if not (line.startswith(start) and needle in line))

    @staticmethod
    def raw_form(text):
        return text.replace("<home>", "/home/ubuntu").replace("<local>", "/Users/someone").replace("<user>@", "ubuntu@").replace("<ip>", "203.0.113.7").replace("   Compiling libc", "\x1b[1;32m   Compiling\x1b[0m libc")

    # ---- the real record and its boundaries ----------------------------------------------------------------------------------------------------

    def test_the_first_real_powerpc_record_passes_and_says_only_that_it_compiled(self):
        problems, facts = self.judge(self.text)
        self.assertEqual(problems, [])
        self.assertEqual((facts["target"], facts["scope"], facts["toolchain"], facts["worker"]), ("powerpc-unknown-linux-musl", "compile-only", "nightly-2026-08-31", "ovh-b"))
        self.assertEqual((facts["attempt"], facts["outcome"], facts["stop"] if "stop" in facts else None), ("core", "built", None))
        self.assertEqual((facts["artifacts"], facts["registry_packages"], facts["tailscale_rs_packages"], facts["std_packages"], facts["core_crates_compiled"]), (176, 119, 19, 11, 7))
        self.assertEqual((facts["tree_sha256"], facts["lock_sha256"], facts["source_files"]), (self.pin, self.anchors["consumer_files"]["Cargo.lock"], 550))
        for word in ("rss", "cpu", "run", "enroll", "endpoint", "latency", "memory"):
            self.assertFalse([k for k in facts if word in k], word)          # the log cannot hold a runtime figure, so the judge reports none
        self.assertEqual(L.site_hits(self.text), [])
        self.assertEqual(L.check_x01_lock(self.lock, self.anchors), [])

    def test_the_raw_and_the_redacted_log_give_one_verdict_and_a_committed_raw_log_is_refused(self):
        raw = self.raw_form(self.text)
        self.assertEqual({"ipv4", "personal-path"}, set(L.site_hits(raw)))
        self.assertTrue(all(token in self.text for token in ("<home>", "<local>", "<ip>", "<user>@<ip>")))
        self.assertIn("ubuntu@203.0.113.7", raw)
        self.assertEqual(L.redact_build_log(raw), self.text)
        a, b = self.judge(self.text, True), self.judge(raw, False)
        self.assertEqual((a[0], a[1]), (b[0], b[1]))
        self.assertTrue(planted(self.judge(raw, True)[0], "still holds site data"))             # raw, as if committed

    def test_a_wrong_target_is_reported_wherever_it_is_planted(self):
        ppc, mips = "powerpc-unknown-linux-musl", "mips-unknown-linux-musl"
        first = lambda t: t.replace(ppc, mips, 1)                                              # the COMMAND line only
        self.plant("command only", first, "disagree on target")
        self.plant("command only: artifacts", first, "other legacy target")
        self.plant("unpinned triple everywhere", lambda t: t.replace(ppc, "riscv64gc-unknown-linux-musl"), "not one of the pinned legacy targets")

        def remote_only(t):
            return "\n".join(l.replace("--target " + ppc, "--target " + mips) if "Executing command remotely" in l else l for l in t.split("\n"))
        self.plant("remote command only", remote_only, "disagree on target")

        def one_artifact(t):
            lines = t.split("\n")
            i = next(i for i, l in enumerate(lines) if l.startswith('{"reason":"compiler-artifact"') and "/tailscale-rs/ts_keys#" in l)
            lines[i] = lines[i].replace(ppc, mips)
            return "\n".join(lines)
        self.plant("one artifact in the other target's directory", one_artifact, "other legacy target")

        def one_artifact_unlisted(t):
            lines = t.split("\n")
            i = next(i for i, l in enumerate(lines) if l.startswith('{"reason":"compiler-artifact"') and "/tailscale-rs/ts_keys#" in l)
            lines[i] = lines[i].replace("/" + ppc + "/debug/", "/debug/")
            return "\n".join(lines)
        self.plant("a core crate built outside the target directory", one_artifact_unlisted, "outside the powerpc-unknown-linux-musl directory")

    def test_each_missing_core_crate_and_std_crate_is_reported(self):
        for crate in self.anchors["core_crates"]:
            self.plant(crate, lambda t, c=crate: self.drop(t, "/tailscale-rs/%s#" % c), "%s has no compiled library artifact" % crate)
        self.plant("x01_core", lambda t: self.drop(t, "/x01_core#"), "x01_core itself was not compiled")
        for std in self.anchors["std_crates"]:
            self.plant(std, lambda t, s=std: self.drop(t, "/library/%s#" % s), "build-std did not compile %s" % std)
        self.plant("std fingerprint", lambda t: t.replace("compiler_builtins@0.1.160", "compiler_builtins@0.1.159"), "compiler_builtins")

    def test_a_stale_lock_a_stale_source_and_a_changed_consumer_are_reported(self):
        def set_hash(rel, value):
            def mutate(doc):
                for entry in self.files(doc):
                    if entry["path"] == rel:
                        entry["sha256"] = value
            return lambda t: self.edit_receipt(t, mutate)
        self.plant("the seed lock instead of the resolved lock", set_hash("Cargo.lock", self.SEED_LOCK), "synced Cargo.lock is not the pinned")
        self.plant("a changed consumer manifest", set_hash("x01_core/Cargo.toml", "0" * 64), "x01_core/Cargo.toml is not the pinned")
        self.plant("a changed consumer root manifest", set_hash("Cargo.toml", "1" * 64), "synced Cargo.toml is not the pinned")
        self.plant("a changed consumer lib.rs", set_hash("x01_core/src/lib.rs", "2" * 64), "x01_core/src/lib.rs is not the pinned")
        self.plant("one changed source file", set_hash("tailscale-rs/ts_keys/src/lib.rs", "3" * 64), "tree digest")

        def remove_one(doc):
            files = self.files(doc)
            files.pop(next(i for i, e in enumerate(files) if e["path"] == "tailscale-rs/ts_noise/src/lib.rs"))
        self.plant("one source file missing from the list", lambda t: self.edit_receipt(t, remove_one), "tree digest")

        def add_one(doc):
            self.files(doc).append({"path": "tailscale-rs/ts_keys/src/extra.rs", "sha256": "4" * 64, "byte_count": 1, "executable": False})
        self.plant("one source file added", lambda t: self.edit_receipt(t, add_one), "tree digest")

        def duplicate(doc):
            self.files(doc).append({"path": "Cargo.lock", "sha256": self.SEED_LOCK, "byte_count": 1, "executable": False})
        self.plant("the lock listed twice", lambda t: self.edit_receipt(t, duplicate), "twice")

        def extra_file(rel):
            return lambda t: self.edit_receipt(t, lambda doc: self.files(doc).append({"path": rel, "sha256": "5" * 64, "byte_count": 1, "executable": False}))
        self.plant("a cargo config in the root", extra_file(".cargo/config.toml"), "cargo config, toolchain override or build script")
        self.plant("a toolchain override in the root", extra_file("rust-toolchain.toml"), "cargo config, toolchain override or build script")
        self.plant("a build script in the consumer package", extra_file("x01_core/build.rs"), "beyond its manifest")
        self.plant("a count that is not its own list", lambda t: self.edit_receipt(t, lambda doc: doc["roots"][0].update(file_count=549)), "does not match its own file list")
        self.plant("another worker", lambda t: self.edit_receipt(t, lambda doc: doc.update(worker_id="other")), "worker")
        self.plant("another schema", lambda t: self.edit_receipt(t, lambda doc: doc.update(schema="rch.source_content_receipt.v0")), "schema rch.source_content_receipt.v1")
        self.plant("a partial root", lambda t: self.edit_receipt(t, lambda doc: doc["roots"][0].update(mode="partial")), "not the full primary root")

    def test_truncated_failed_and_zero_run_logs_are_reported(self):
        self.assertTrue(planted(self.judge("")[0], "COMMAND"))
        self.assertTrue(planted(self.judge(self.text.split("\n")[0] + "\n")[0], "expected one"))
        cut = self.text.index('{"reason":"build-finished"')
        self.plant("cut before build-finished", lambda t: t[:cut], "build-finished")
        self.plant("cut in the middle", lambda t: t[:len(t) // 2], "build-finished")
        last = self.text.rindex(self.PREFIX)
        self.plant("the receipt line cut short", lambda t: t[:last + len(self.PREFIX) + 4000], "not valid JSON")
        self.plant("build-finished failed", lambda t: t.replace('"reason":"build-finished","success":true', '"reason":"build-finished","success":false'), "terminal results disagree")
        self.plant("rch exit 101", lambda t: t.replace("Remote command finished: exit=0", "Remote command finished: exit=101"), "terminal results disagree")
        self.plant("receipt exit 101", lambda t: self.edit_receipt(t, lambda doc: doc.update(command_exit_code=101)), "terminal results disagree")
        self.plant("no Finished line", lambda t: "\n".join(l for l in t.split("\n") if "Finished `" not in l), "terminal results disagree")
        self.plant("zero artifacts", lambda t: self.drop(t, ""), "nothing was compiled")
        self.plant("a compiler error message", lambda t: t.replace('{"reason":"build-finished"', '{"reason":"compiler-message","message":{"level":"error","message":"x"}}\n{"reason":"build-finished"'), "terminal results disagree")
        self.plant("an error line", lambda t: t.replace("    Finished `", "error[E0432]: unresolved import\n    Finished `"), "terminal results disagree")
        self.plant("artifacts after build-finished", lambda t: t + '\n{"reason":"compiler-artifact","package_id":"x"}\n', "build-finished")
        self.plant("no exit line", lambda t: "\n".join(l for l in t.split("\n") if "Remote command finished" not in l), "remote command exit")

    def test_only_the_pinned_check_command_is_accepted(self):
        def both(old, new):
            def mutate(text):
                lines = text.split("\n")
                lines = [l.replace(old, new) if (l.startswith("COMMAND: ") or "Executing command remotely" in l) else l for l in lines]
                return "\n".join(lines)
            return mutate
        self.plant("build instead of check", lambda t: both(" check ", " build ")(both('"check"', '"build"')(t)), "subcommand")
        self.plant("a run", lambda t: both(" check ", " run ")(both('"check"', '"run"')(t)), "subcommand")
        self.plant("not locked", lambda t: both(" --locked", "")(both('"--locked", ', "")(t)), "not run with --locked")
        self.plant("another toolchain", both("nightly-2026-08-31", "nightly-2026-09-07"), "toolchain")
        self.plant("another build-std set", lambda t: both("core,alloc,std,panic_abort", "core,alloc,std")(t), "build-std")
        self.plant("the whole library's package with the core manifest", lambda t: both(" x01_core", " tailscale")(both('"x01_core"', '"tailscale"')(t)), "manifest")
        self.plant("a package that is neither attempt", lambda t: both(" x01_core", " ts_keys")(both('"x01_core"', '"ts_keys"')(t)), "the pinned selections are only")
        self.plant("no json messages", lambda t: both(" '--message-format=json'", "")(both(', "--message-format=json"', "")(t)), "message-format")
        self.plant("a release build", lambda t: both(" -p x01_core", " -p x01_core --release")(t), "unexpected arguments")
        self.plant("a patched dependency", lambda t: both("--config 'env.RCH_BUILD_SOURCE.value", "--config 'patch.crates-io.serde.path=\"/x\"' --config 'env.RCH_BUILD_SOURCE.value")(t), "unexpected --config arguments")
        self.plant("rustflags in the remote environment", both("env 'CARGO_INCREMENTAL=0'", "env 'RUSTFLAGS=-Cdebuginfo=2' 'CARGO_INCREMENTAL=0'"), "sets RUSTFLAGS")
        self.plant("an unexpected rch option", lambda t: t.replace('"--source-content-receipt",', '"--source-content-receipt", "--force",', 1), "unexpected rch option")
        self.plant("not an rch command", lambda t: t.replace('["rch", "exec",', '["sh", "exec",', 1), "not `rch exec")

    def test_a_package_from_anywhere_but_the_lock_the_synced_tree_and_the_toolchain_is_reported(self):
        index = "registry+https://github.com/rust-lang/crates.io-index#"
        self.plant("a registry crate that is not locked", lambda t: t.replace(index + "serde@1.0.228", index + "serde@9.9.9", 1), "neither in the locked closure")
        self.plant("another registry", lambda t: t.replace(index + "serde@1.0.228", "registry+https://example.invalid/index#serde@1.0.228", 1), "other than crates.io")
        self.plant("a git source", lambda t: t.replace(index + "serde@1.0.228", "git+https://example.invalid/x?rev=abc#serde@1.0.228", 1), "git source")
        self.plant("a std crate at another version", lambda t: t.replace("gimli@0.34.0", "gimli@0.33.0", 1), "neither in the locked closure")
        self.plant("a tailscale-rs crate at another version", lambda t: t.replace("/tailscale-rs/ts_keys#0.6.1", "/tailscale-rs/ts_keys#0.6.2", 1), "not the locked tailscale-rs crate")
        self.plant("a path outside the synced tree", lambda t: t.replace("path+file:///data/tmp/rch/", "path+file:///elsewhere/tmp/rch/", 1), "outside the synced tree and the pinned toolchain")

    # ---- the two false accepts GrayMeadow found in v3+v4+v5 (mail 10671): an empty remote command, and file names that were emptied ---------------------

    REMOTE = "Executing command remotely: "
    PPC_T, MIPS_T = "powerpc-unknown-linux-musl", "mips-unknown-linux-musl"

    def real_records(self):
        """The eight REAL committed records: (text, built). Five built, three stopped (no C compiler; cargo refused the inline table; Zig could not parse the Rust target spelling)."""
        return {"core powerpc": (self.core_ppc, True), "core mips": (self.core_mips, True), "whole powerpc": (self.whole_ppc, True), "whole mips, cc-rs adapter": (self.zig_ccrs, True),
                "whole mips, hardened adapter": (self.zig_ccrs_v2, True), "whole mips, original stop": (self.whole_mips, False), "whole mips, inline refusal": (self.zig_inline, False),
                "whole mips, target spelling stop": (self.zig_keys, False)}

    def with_remote(self, text, replacement):
        return "\n".join(l.split(self.REMOTE, 1)[0] + self.REMOTE + replacement if self.REMOTE in l else l for l in text.split("\n"))

    @staticmethod
    def edit_artifacts(text, fn, needle=None):
        out = []
        for line in text.split("\n"):
            if line.startswith('{"reason":"compiler-artifact"') and (needle is None or needle in line):
                doc = json.loads(line)
                fn(doc)
                line = json.dumps(doc, separators=(",", ":"))
            out.append(line)
        return "\n".join(out)

    def retarget(self, text, old, new):
        """Only the two places the command is recorded: the COMMAND line and the remote command. The receipt, the sources and the cargo messages stay as they were."""
        return "\n".join(l.replace(old, new) if (l.startswith("COMMAND: ") or self.REMOTE in l) else l for l in text.split("\n"))

    def test_an_empty_or_blank_remote_command_is_a_defect_of_every_real_record(self):
        for name, (text, _built) in self.real_records().items():
            self.assertEqual(self.judge(text)[0], [], name + ": the real record is the control")
            for label, blank in (("empty", ""), ("blank", "   \t ")):
                self.plant("%s: %s remote command" % (name, label), lambda t, b=blank: self.with_remote(t, b), "the remote command line is empty", base=text)
        problems, _ = self.judge(self.with_remote(self.core_ppc, ""))
        self.assertEqual(len(problems), 1, problems)                                             # nothing else is claimed to have been checked, and nothing else is reported
        self.plant("only environment words", lambda t: self.with_remote(t, "env 'CARGO_INCREMENTAL=0'"), "not a cargo invocation")
        self.plant("unsplittable", lambda t: self.with_remote(t, "cargo 'unterminated"), "does not split into words")
        self.assertFalse(planted(self.judge(self.with_remote(self.core_ppc, "cargo 'unterminated"))[0], "line is empty"))

    def test_target_artifacts_without_an_output_file_under_the_selected_target_do_not_count(self):
        emptied = lambda t: self.edit_artifacts(t, lambda d: d.update(filenames=[]))
        for name, (text, built) in self.real_records().items():
            if built:
                self.plant("%s: every artifact's file names emptied" % name, emptied, "ts_keys has no compiled library artifact with an output file under the", base=text)
                problems, _ = self.judge(emptied(text))
                self.assertTrue(planted(problems, "ts_noise has no compiled library artifact"), name)
                self.assertTrue(planted(problems, "build-std did not compile core"), name)
                self.assertEqual(planted(problems, "x01_core itself was not compiled"), name.startswith("core"), name)
                self.assertEqual(planted(problems, "tailscale has no compiled library artifact"), name.startswith("whole"), name)
            else:
                self.assertEqual(self.judge(emptied(text))[0], [], name + ": a stop makes no claim to have built, so it has no required artifacts to witness")

        def only(needle):
            return lambda t: self.edit_artifacts(t, lambda d: d.update(filenames=[]), needle)
        # each counting site on its own: the one required crate whose file names are emptied is the one reported
        only_problem = lambda text, needle: self.judge(only(needle)(text))[0]
        self.assertEqual(only_problem(self.core_ppc, "/tailscale-rs/ts_keys#"), ["ts_keys has no compiled library artifact with an output file under the %s directory" % self.PPC_T])
        self.assertEqual(only_problem(self.core_ppc, "/x01_core#"), ["x01_core itself was not compiled (no artifact with an output file under the %s directory)" % self.PPC_T])
        self.assertEqual(only_problem(self.whole_ppc, "#tailscale@0.6.1"), ["tailscale has no compiled library artifact with an output file under the %s directory" % self.PPC_T])
        for std in self.anchors["std_crates"]:
            self.assertTrue(planted(only_problem(self.core_ppc, "/library/%s#" % std), "build-std did not compile %s (no artifact" % std), std)
        self.assertEqual(only_problem(self.core_ppc, "/library/core#"), ["build-std did not compile core (no artifact with an output file under the %s directory)" % self.PPC_T])
        self.plant("one core crate's file names emptied", only("/tailscale-rs/ts_keys#"), "ts_keys has no compiled library artifact")

        def outside(doc):
            doc["filenames"] = ["/elsewhere/libts_keys.rlib"]

        def one_inside_one_outside(doc):
            doc["filenames"] = doc["filenames"][:1] + ["/elsewhere/libts_keys.rlib"]
        for label, fn in (("every file name outside the target directory", outside), ("one inside and one outside", one_inside_one_outside)):
            problems = self.judge(self.edit_artifacts(self.core_ppc, fn, "/tailscale-rs/ts_keys#"))[0]
            self.assertTrue(planted(problems, "outside the %s directory" % self.PPC_T), label)         # the older directory check
            self.assertTrue(planted(problems, "ts_keys has no compiled library artifact"), label)       # and the witness: every file name must be under the target

    def test_a_record_cannot_be_promoted_to_another_target_by_emptying_its_output_files(self):
        emptied = lambda t: self.edit_artifacts(t, lambda d: d.update(filenames=[]))
        for name, text, own, other in (("core powerpc", self.core_ppc, self.PPC_T, self.MIPS_T), ("core mips", self.core_mips, self.MIPS_T, self.PPC_T), ("whole powerpc", self.whole_ppc, self.PPC_T, self.MIPS_T)):
            flipped = self.retarget(text, own, other)
            problems, facts = self.judge(flipped)
            self.assertEqual(facts["target"], other, name)
            self.assertTrue(planted(problems, "other legacy target"), name + ": with its file names intact the other target's directory gives the promotion away")
            problems, facts = self.judge(emptied(flipped))
            self.assertTrue(planted(problems, "has no compiled library artifact with an output file under the %s directory" % other), name)
            self.assertFalse(planted(problems, "other legacy target"), name + ": emptying the names removes the older detector's input, so the witness is what rejects it")
            self.plant(name + ": retargeted, then emptied", lambda t, o=own, n=other: emptied(self.retarget(t, o, n)), "has no compiled library artifact", base=text)
        for name in ("whole mips, cc-rs adapter", "whole mips, hardened adapter"):          # the pinned C compiler configuration rejects the retarget on its own; the plain emptying still needs the witness
            text = self.real_records()[name][0]
            self.plant(name + ": emptied", emptied, "has no compiled library artifact", base=text)

    def test_a_filenames_value_that_is_not_a_list_of_strings_is_reported_by_itself_and_never_counts(self):
        serde = "crates.io-index#serde@1.0.228"
        bad = (("missing", lambda d: d.pop("filenames")), ("null", lambda d: d.update(filenames=None)), ("a string", lambda d: d.update(filenames="libserde.rlib")),
               ("an object", lambda d: d.update(filenames={"a": "b"})), ("a list with a non-string", lambda d: d.update(filenames=["x", 3])))
        for label, fn in bad:
            problems, _ = self.judge(self.edit_artifacts(self.text, fn, serde))
            self.assertTrue(problems and all("serde 1.0.228 has no readable filenames list" in p for p in problems), (label, problems[:2]))
            self.assertEqual(self.judge(self.text)[0], [], label + ": removing the plant restores the pass")
            problems, _ = self.judge(self.edit_artifacts(self.text, fn, "/tailscale-rs/ts_keys#"))
            self.assertTrue(planted(problems, "ts_keys 0.6.1 has no readable filenames list"), label)
            self.assertTrue(planted(problems, "ts_keys has no compiled library artifact"), label + ": a crate with no readable file names is not counted either")

    def test_the_forged_cross_target_record_cannot_complete_the_four_attempts(self):
        data = rc.inputs()
        forged = self.edit_artifacts(self.retarget(self.core_ppc, self.PPC_T, self.MIPS_T), lambda d: d.update(filenames=[]))
        four = {"1.log": self.core_ppc, "2.log": self.core_mips, "3.log": self.whole_ppc, "4.log": self.relabel(self.whole_ppc)}
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, four)
            self.assertEqual(rc.case_build(tmp, data).status, "passed")                          # the control: the four records the existing test accepts
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, dict(four, **{"2.log": forged}))                                 # the powerpc record, presented as the mips core attempt
            result = rc.case_build(tmp, data)
            self.assertEqual(result.status, "failed", result.detail)
            self.assertIn("2.log: ", result.detail)
            self.assertIn("has no compiled library artifact", result.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, dict(four, **{"2.log": self.with_remote(self.core_mips, "")}))   # an unchecked remote command
            result = rc.case_build(tmp, data)
            self.assertEqual(result.status, "failed", result.detail)
            self.assertIn("the remote command line is empty", result.detail)

    # ---- the case, the runner and the boundaries --------------------------------------------------------------------------------------------

    def repo_with(self, tmp, records):
        lock = os.path.join(tmp, *self.anchors["lock_fixture"].split("/"))
        os.makedirs(os.path.dirname(lock))
        with open(lock, "w", encoding="utf-8") as handle:
            handle.write(self.lock)
        for name, text in records.items():
            write_raw(tmp, "toolchain/results/tailscale/builds/" + name, text)

    def relabel(self, text):
        return text.replace("powerpc-unknown-linux-musl", "mips-unknown-linux-musl")

    def test_the_case_reports_each_state_and_passes_only_when_all_four_attempts_built(self):
        data = rc.inputs()
        ppc, mips = "powerpc-unknown-linux-musl", "mips-unknown-linux-musl"
        four = {"1.log": self.core_ppc, "2.log": self.core_mips, "3.log": self.whole_ppc, "4.log": self.relabel(self.whole_ppc)}      # 4: a relabelled stand-in for the MIPS retry that has not been made
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {})
            self.assertIn("no build record", rc.case_build(tmp, data).detail)
        with tempfile.TemporaryDirectory() as tmp:                                              # the core attempts alone, on both targets: partial evidence, never the whole probe
            self.repo_with(tmp, {"1.log": self.core_ppc, "2.log": self.core_mips})
            core = rc.case_build(tmp, data)
            self.assertEqual(core.status, "blocked", core.detail)
            for said in ("INCOMPLETE", "a core pass is partial evidence only", "core powerpc: BUILT", "core mips: BUILT", "whole powerpc: NOT RECORDED", "whole mips: NOT RECORDED"):
                self.assertIn(said, core.detail)
        with tempfile.TemporaryDirectory() as tmp:                                              # the four real records: three built, the MIPS whole library stopped for want of a C compiler
            self.repo_with(tmp, {"1.log": self.core_ppc, "2.log": self.core_mips, "3.log": self.whole_ppc, "4.log": self.whole_mips})
            real = rc.case_build(tmp, data)
            self.assertEqual(real.status, "blocked", real.detail)
            for said in ("whole powerpc: BUILT", "whole mips: STOPPED at aws-lc-sys v0.45.0", "'mips-linux-musl-gcc'", "a toolchain blocker and not an ISA or source finding"):
                self.assertIn(said, real.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, four)
            allbuilt = rc.case_build(tmp, data)
            self.assertEqual(allbuilt.status, "passed", allbuilt.detail)
            for said in ("all four required attempts built", "type-check only", "no runtime, memory, CPU, enrollment or native-endpoint result", "T01-X02 and the native requirement are untouched"):
                self.assertIn(said, allbuilt.detail)
            self.assertEqual(rc.case_resources(tmp).status, "blocked")                          # a compile record never answers the resource case
            self.assertEqual(rc.exit_code([allbuilt, rc.case_resources(tmp)]), 3)               # so a run that has it is still not a pass
            self.assertEqual(rc.case_native_requirement(data, REPO).status, "passed")
            self.assertNotIn("supported", set(L.matrix(PROFILE).values()))
            write(tmp, "toolchain/results/tailscale/builds/other.json", "{}\n")
            self.assertIn("no judge for it yet", rc.case_build(tmp, data).detail)                # a receipt nobody can judge still blocks
        with tempfile.TemporaryDirectory() as tmp:                                              # a later run built what stopped: the stop stays in the account
            self.repo_with(tmp, dict(four, **{"5-earlier-stop.log": self.whole_mips}))
            kept = rc.case_build(tmp, data)
            self.assertEqual(kept.status, "passed", kept.detail)
            self.assertIn("earlier stops kept: STOPPED at aws-lc-sys v0.45.0", kept.detail)
        with tempfile.TemporaryDirectory() as tmp:                                              # a record that does not hold fails the case, whatever else is recorded
            self.repo_with(tmp, dict(four, **{"bad.log": self.whole_mips.replace("Remote command finished: exit=101", "Remote command finished: exit=0")}))
            bad = rc.case_build(tmp, data)
            self.assertEqual(bad.status, "failed")
            self.assertIn("bad.log: ", bad.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {"ppc.log": self.raw_form(self.text)})
            self.assertIn("still holds site data", rc.case_build(tmp, data).detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {"ppc.log": self.text})
            os.symlink(self.PPC, os.path.join(tmp, "toolchain/results/tailscale/builds/link.log"))
            linked = rc.case_build(tmp, data)
            self.assertEqual(linked.status, "failed")
            self.assertIn("not a plain regular file", linked.detail)
            self.assertNotIn(REPO, linked.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {})
            raw = os.path.join(tmp, "raw.txt")
            with open(raw, "w", encoding="utf-8") as handle:
                handle.write(self.raw_form(self.text))
            supplied = rc.case_build(tmp, data, (raw,))
            self.assertIn("core powerpc: BUILT", supplied.detail)
            self.assertNotIn(tmp, supplied.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {"ppc.log": self.text})
            lock = os.path.join(tmp, *self.anchors["lock_fixture"].split("/"))
            with open(lock, "a", encoding="utf-8") as handle:
                handle.write("# changed\n")
            self.assertIn("lock fixture", rc.case_build(tmp, data).detail)

    def test_the_whole_library_records_hold_the_powerpc_build_and_the_named_mips_stop(self):
        problems, facts = self.judge(self.whole_ppc)
        self.assertEqual(problems, [])
        self.assertEqual((facts["attempt"], facts["target"], facts["outcome"], facts["artifacts"]), ("whole", "powerpc-unknown-linux-musl", "built", 340))
        self.assertEqual((facts["core_crates_compiled"], facts["std_packages"]), (7, 11))
        self.assertGreater(facts["tailscale_rs_packages"], 19)
        problems, facts = self.judge(self.whole_mips)
        self.assertEqual(problems, [])
        self.assertEqual((facts["attempt"], facts["target"], facts["outcome"]), ("whole", "mips-unknown-linux-musl", "stopped"))
        self.assertEqual(facts["stop"], {"package": "aws-lc-sys v0.45.0", "exit": 101, "class": "missing-c-toolchain", "tool": "mips-linux-musl-gcc", "detail": None})
        problems, facts = self.judge(self.core_mips)
        self.assertEqual((problems, facts["attempt"], facts["outcome"]), ([], "core", "built"))

    def test_a_stop_is_a_held_record_that_is_never_a_built_attempt(self):
        def stop(text):                                                                         # a consistent stop of the core record: failure in all three witnesses, no Finished line
            text = text.replace('"reason":"build-finished","success":true', '"reason":"build-finished","success":false').replace("Remote command finished: exit=0", "Remote command finished: exit=101")
            text = "\n".join(l for l in text.split("\n") if "Finished `" not in l)
            return self.edit_receipt(text, lambda doc: doc.update(command_exit_code=101))
        stopped = stop(self.text)
        problems, facts = self.judge(stopped)
        self.assertEqual((problems, facts["outcome"], facts["stop"]), ([], "stopped", {"package": None, "exit": 101, "class": "unclassified", "tool": None, "detail": None}))
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {"1.log": stopped, "2.log": self.core_mips, "3.log": self.whole_ppc, "4.log": self.relabel(self.whole_ppc)})
            result = rc.case_build(tmp, rc.inputs())
            self.assertEqual(result.status, "blocked", result.detail)
            self.assertIn("core powerpc: STOPPED at an unnamed crate: the cause is not classified here", result.detail)
            self.assertIn("neither as a toolchain blocker nor as an ISA or source finding", result.detail)

    def test_the_stop_is_classified_from_its_own_text_and_cannot_be_doctored_into_a_build(self):
        base = self.whole_mips
        cc = 'error occurred in cc-rs: failed to find tool "mips-linux-musl-gcc"'
        self.assertIn(cc, base)

        def forged(text):                                                                       # every witness says built, and the error text is gone
            out = []
            for line in text.split("\n"):
                if line.startswith("error"):
                    continue
                if "Remote command finished: exit=101" in line:
                    out.append("    Finished `dev` profile [unoptimized] target(s) in 1m 41s")
                    line = line.replace("exit=101", "exit=0")
                out.append(line)
            text = "\n".join(out).replace('"reason":"build-finished","success":false', '"reason":"build-finished","success":true')
            return self.edit_receipt(text, lambda doc: doc.update(command_exit_code=0))
        self.plant("the success flag only", lambda t: t.replace('"success":false', '"success":true'), "terminal results disagree", base)
        self.plant("the exit code only", lambda t: t.replace("exit=101", "exit=0"), "terminal results disagree", base)
        self.plant("the receipt's exit only", lambda t: self.edit_receipt(t, lambda doc: doc.update(command_exit_code=0)), "terminal results disagree", base)
        self.plant("another exit in the receipt", lambda t: self.edit_receipt(t, lambda doc: doc.update(command_exit_code=1)), "terminal results disagree", base)
        def finished_line(text):
            out = []
            for line in text.split("\n"):
                if "Remote command finished: exit=101" in line:
                    out.append("    Finished `dev` profile [unoptimized] target(s) in 1s")
                out.append(line)
            return "\n".join(out)
        self.plant("a Finished line in a stop", finished_line, "terminal results disagree", base)
        self.plant("a stop doctored into a clean build", forged, "has no compiled library artifact", base)
        known = lambda text: (lambda p, f: (p, f["stop"]))(*self.judge(text))
        self.assertEqual(known(base)[1]["class"], "missing-c-toolchain")
        no_cc = "\n".join(l for l in base.split("\n") if "error occurred in cc-rs" not in l)
        self.assertEqual(known(no_cc), ([], {"package": "aws-lc-sys v0.45.0", "exit": 101, "class": "unclassified", "tool": None, "detail": None}))     # without the cc-rs text it is not called a toolchain blocker
        self.assertEqual(known(base.replace("mips-linux-musl-gcc", "other-gcc"))[1]["tool"], "other-gcc")                              # the tool comes from the text, not from this test
        self.assertEqual(known(base + "\n" + cc.replace("mips-linux-musl-gcc", "second-gcc") + "\n")[1]["class"], "unclassified")      # two different tools: not classified
        no_package = "\n".join(l for l in base.split("\n") if not l.startswith("error: failed to run custom build command"))
        self.assertEqual(known(no_package), ([], {"package": None, "exit": 101, "class": "unclassified", "tool": None, "detail": None}))

    def test_the_whole_library_attempt_is_held_to_its_own_manifest_package_and_artifacts(self):
        base = self.whole_ppc

        def both(old, new):
            return lambda text: "\n".join(l.replace(old, new) if (l.startswith("COMMAND: ") or "Executing command remotely" in l) else l for l in text.split("\n"))
        self.plant("the core manifest for the whole library", both("tailscale-rs/Cargo.toml", "Cargo.toml"), "manifest", base)
        self.plant("the core package with the whole library's manifest", lambda t: both(" tailscale ", " x01_core ")(both('"tailscale",', '"x01_core",')(t)), "manifest", base)
        self.plant("no tailscale library artifact", lambda t: self.drop(t, "/tailscale-rs#tailscale@"), "tailscale has no compiled library artifact", base)
        for crate in ("ts_keys", "ts_tunnel"):
            self.plant(crate, lambda t, c=crate: self.drop(t, "/tailscale-rs/%s#" % c), "%s has no compiled library artifact" % crate, base)
        self.plant("a tailscale-rs crate at another version", lambda t: t.replace("/tailscale-rs/ts_keys#0.6.1", "/tailscale-rs/ts_keys#0.6.2", 1), "not at the pinned tailscale-rs version", base)
        self.plant("a git source", lambda t: t.replace("registry+https://github.com/rust-lang/crates.io-index#serde@", "git+https://example.invalid/x?rev=abc#serde@", 1), "git source", base)
        self.plant("a path outside the synced tree", lambda t: t.replace("path+file:///data/tmp/rch/", "path+file:///elsewhere/tmp/rch/", 1), "outside the synced tree and the pinned toolchain", base)
        self.plant("the upstream lock changed", lambda t: self.edit_receipt(t, lambda doc: [e.update(sha256="6" * 64) for e in self.files(doc) if e["path"] == "tailscale-rs/Cargo.lock"]), "tree digest", base)
        ppc, mips = "powerpc-unknown-linux-musl", "mips-unknown-linux-musl"

        def one_artifact(text):
            lines = text.split("\n")
            i = next(i for i, l in enumerate(lines) if l.startswith('{"reason":"compiler-artifact"') and "/tailscale-rs/ts_keys#" in l)
            lines[i] = lines[i].replace(ppc, mips)
            return "\n".join(lines)
        self.plant("one artifact under the other target", one_artifact, "other legacy target", base)

    def test_a_compile_record_is_independent_of_the_measurement_receipt(self):
        data = rc.inputs()
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, {"1.log": self.core_ppc, "2.log": self.core_mips, "3.log": self.whole_ppc, "4.log": self.relabel(self.whole_ppc)})
            write(tmp, "toolchain/results/tailscale/measurements/x.json", "{}\n")
            self.assertEqual(rc.case_resources(tmp).status, "failed")                           # a foreign measurement file fails the X02 case, by name
            self.assertIn("x.json", rc.case_resources(tmp).detail)
            self.assertEqual(rc.case_build(tmp, data).status, "passed")                         # and a measurement file does not touch the compile verdict

    def test_the_historical_receipts_are_kept_byte_for_byte_and_still_say_blocked(self):
        pinned = {"t01-8cdc69be60fccfa2.json": "29211952173eb4e8ad087d63bf7bee2a1c52740685b0cd70e58faf2ba717b235",
                  "t01-01665612603d232e.json": "d2f7340eb21cd96efdf095e9eb4a92da81b6172e4298756c6ce9469a1d12f5fa",
                  "t01-9f4270b321a6868a.json": "3559d98853a11079eb2d0e7cdf80e4f11b1d725b836171742afb5c48f5466199"}
        directory = os.path.join(REPO, "toolchain", "results", "tailscale", "receipts")
        for name, digest in pinned.items():
            data = L.read_bounded_file(os.path.join(directory, name))
            self.assertEqual(L.sha256_bytes(data), digest, name)
            doc = json.loads(data)
            x01 = [r for r in doc["results"] if r["case"] == "T01-X01-legacy-isa-build"]
            if doc["tier"] == "full":
                self.assertEqual([r["status"] for r in x01], ["blocked"], name)
                self.assertTrue(x01[0]["detail"].startswith("no build receipt under toolchain/results/tailscale/builds/"), name)

    def test_the_committed_records_are_redacted_regular_files_that_hold_and_keep_every_earlier_failure(self):
        names = sorted(os.listdir(self.BUILDS))
        self.assertEqual([n for n in names if n.endswith(".log")], [
            "x01-core-mips-unknown-linux-musl-20261107.log", "x01-core-powerpc-unknown-linux-musl-20261107.log", "x01-whole-mips-unknown-linux-musl-20261107.log",
            "x01-whole-mips-unknown-linux-musl-zig-ccrs-20261107.log", "x01-whole-mips-unknown-linux-musl-zig-ccrs-v2-20261107.log",
            "x01-whole-mips-unknown-linux-musl-zig-inline-20261107.log", "x01-whole-mips-unknown-linux-musl-zig-keys-20261107.log", "x01-whole-powerpc-unknown-linux-musl-20261107.log"])
        outcomes = {}
        for name in names:
            path = os.path.join(self.BUILDS, name)
            self.assertTrue(os.path.isfile(path) and not os.path.islink(path), name)
            text = L.read_bounded_file(path).decode("utf-8")
            self.assertEqual(L.site_hits(text), [], name)
            if name.endswith(".log"):
                problems, facts = self.judge(text)
                self.assertEqual(problems, [], name)
                outcomes[name[4:-13]] = (facts["target"], facts["attempt"], facts["outcome"], (facts.get("stop") or {}).get("class"), (facts.get("cc") or {}).get("wrapper"))
        ppc, mips = "powerpc-unknown-linux-musl", "mips-unknown-linux-musl"
        self.assertEqual(outcomes, {
            "core-powerpc-unknown-linux-musl": (ppc, "core", "built", None, None), "core-mips-unknown-linux-musl": (mips, "core", "built", None, None),
            "whole-powerpc-unknown-linux-musl": (ppc, "whole", "built", None, None),
            "whole-mips-unknown-linux-musl": (mips, "whole", "stopped", "missing-c-toolchain", None),
            "whole-mips-unknown-linux-musl-zig-inline": (mips, "whole", "stopped", "cargo-config-rejected", "x01-cc/zig-cc-mips-be"),
            "whole-mips-unknown-linux-musl-zig-keys": (mips, "whole", "stopped", "c-compiler-rejected-target", "x01-cc/zig-cc-mips-be"),
            "whole-mips-unknown-linux-musl-zig-ccrs": (mips, "whole", "built", None, "x01-cc/zig-cc-mips-be-ccrs"),
            "whole-mips-unknown-linux-musl-zig-ccrs-v2": (mips, "whole", "built", None, "x01-cc/zig-cc-mips-be-ccrs-v2")})
        live = rc.case_build(REPO)
        self.assertEqual(live.status, "passed", live.detail)                                    # every earlier failure is still recorded, and the account says so
        self.assertEqual(live.detail.count("STOPPED at aws-lc-sys v0.45.0"), 2)
        for said in ("earlier stops kept", "REJECTED by cargo before building", "x01-cc/zig-cc-mips-be-ccrs (sha256 17848d169db2)", "x01-cc/zig-cc-mips-be-ccrs-v2 (sha256 3dc93ff4f618)",
                     "a toolchain blocker and not an ISA or source finding"):
            self.assertIn(said, live.detail)

    def cfg_both(self, old, new):
        """Replace text in the COMMAND line and in the executed remote command only."""
        return lambda text: "\n".join(l.replace(old, new) if (l.startswith("COMMAND: ") or "Executing command remotely" in l) else l for l in text.split("\n"))

    def test_the_three_zig_attempts_hold_as_a_cargo_refusal_the_original_wrapper_stop_and_the_build(self):
        problems, facts = self.judge(self.zig_inline)
        self.assertEqual(problems, [])
        self.assertEqual((facts["outcome"], facts["artifacts"], facts["cc"]["form"], facts["stop"]["class"], facts["stop"]["package"]), ("stopped", 0, "inline", "cargo-config-rejected", None))
        self.assertEqual(facts["stop"]["detail"], 'env.CC_mips_unknown_linux_musl={value="x01-cc/zig-cc-mips-be",relative=true,force=true}')
        problems, facts = self.judge(self.zig_keys)
        self.assertEqual(problems, [])
        self.assertEqual((facts["outcome"], facts["cc"]["wrapper"], facts["cc"]["form"], facts["stop"]["class"], facts["stop"]["detail"], facts["stop"]["package"]),
                         ("stopped", "x01-cc/zig-cc-mips-be", "keys", "c-compiler-rejected-target", "mips-unknown-linux-musl", "aws-lc-sys v0.45.0"))
        problems, facts = self.judge(self.zig_ccrs)
        self.assertEqual(problems, [])
        self.assertEqual((facts["outcome"], facts["attempt"], facts["target"], facts["artifacts"], facts["core_crates_compiled"]), ("built", "whole", "mips-unknown-linux-musl", 340, 7))
        self.assertEqual(facts["cc"], {"wrapper": "x01-cc/zig-cc-mips-be-ccrs", "sha256": self.anchors["cc_wrappers"]["files"]["x01-cc/zig-cc-mips-be-ccrs"]["sha256"], "form": "keys"})

    def swap_cfg(self, old, new):
        """Replace one --config string in the COMMAND line (JSON) and in the executed remote command (rch single-quotes every one)."""
        pairs = [(json.dumps(old), json.dumps(new)), ("'%s'" % old, "'%s'" % new)]
        return lambda text: "\n".join(self.apply_pairs(line, pairs) for line in text.split("\n"))

    def apply_pairs(self, line, pairs):
        if line.startswith("COMMAND: ") or "Executing command remotely" in line:
            for old, new in pairs:
                line = line.replace(old, new)
        return line

    def drop_cfg(self, cfg):
        pairs = [(', "--config", %s' % json.dumps(cfg), ""), (" --config '%s'" % cfg, "")]
        return lambda text: "\n".join(self.apply_pairs(line, pairs) for line in text.split("\n"))

    def add_cfg(self, cfg):
        pairs = [('"--message-format=json"', '"--message-format=json", "--config", %s' % json.dumps(cfg)), ("'--message-format=json'", "'--message-format=json' --config '%s'" % cfg)]
        return lambda text: "\n".join(self.apply_pairs(line, pairs) for line in text.split("\n"))

    def test_the_c_compiler_configuration_is_exactly_the_pinned_one(self):
        base = self.zig_ccrs
        key = "env.CC_mips_unknown_linux_musl"
        wrapper = "x01-cc/zig-cc-mips-be-ccrs"
        value, relative, force = '%s.value="%s"' % (key, wrapper), "%s.relative=true" % key, "%s.force=true" % key
        self.plant("an unpinned wrapper path", self.swap_cfg(value, '%s.value="x01-cc/zig-cc-other"' % key), "unexpected --config arguments", base)
        self.plant("a missing key", self.drop_cfg(force), "unexpected --config arguments", base)
        self.plant("a missing value key", self.drop_cfg(value), "unexpected --config arguments", base)
        self.plant("an extra key", self.add_cfg('%s.flags="-O3"' % key), "unexpected --config arguments", base)
        self.plant("a different environment variable", self.swap_cfg(relative, 'env.CFLAGS.value="x"'), "unexpected --config arguments", base)
        self.plant("a patched dependency", self.swap_cfg(relative, 'patch.crates-io.serde.path="/x"'), "unexpected --config arguments", base)
        self.plant("a path outside the pinned table that exists in the root", self.swap_cfg(value, '%s.value="tailscale-rs/Cargo.toml"' % key), "unexpected --config arguments", base)

        def remote_only(text):                                                                   # the remote command names the other pinned wrapper, the command does not
            return "\n".join(line.replace("'%s'" % value, "'%s.value=\"x01-cc/zig-cc-mips-be\"'" % key) if "Executing command remotely" in line else line for line in text.split("\n"))
        self.plant("the command and the remote command disagree", remote_only, "disagree on configs", base)
        mips, ppc = "mips-unknown-linux-musl", "powerpc-unknown-linux-musl"
        self.plant("the configuration on another target", lambda t: self.cfg_both("--target " + mips, "--target " + ppc)(self.cfg_both('"%s"' % mips, '"%s"' % ppc)(t)),
                   "pinned for the whole attempt on %s only" % mips, base)
        inline_value = '%s={value="%s",relative=true,force=true}' % (key, wrapper)
        self.plant("the refused inline spelling claimed to have built", lambda t: self.drop_cfg(force)(self.drop_cfg(relative)(self.swap_cfg(value, inline_value)(t))),
                   "inline-table C compiler configuration is refused by cargo", base)

        def set_hash(path, digest):
            return lambda t: self.edit_receipt(t, lambda doc: [e.update(sha256=digest) for e in self.files(doc) if e["path"] == path])
        self.plant("a changed wrapper", set_hash("x01-cc/zig-cc-mips-be-ccrs", "7" * 64), "is not the pinned wrapper", base)
        self.plant("the original wrapper changed", set_hash("x01-cc/zig-cc-mips-be", "8" * 64), "is not the pinned wrapper", base)
        self.plant("the configured wrapper not synced", lambda t: self.edit_receipt(t, lambda doc: self.files(doc).pop(next(i for i, e in enumerate(self.files(doc)) if e["path"] == wrapper))),
                   "is not among the synced files", base)
        self.plant("an unpinned file beside the wrappers", lambda t: self.edit_receipt(t, lambda doc: self.files(doc).append({"path": "x01-cc/extra", "sha256": "9" * 64, "byte_count": 1, "executable": True})),
                   "not pinned C compiler wrappers", base)
        self.assertIsNone(self.judge(self.whole_ppc)[1]["cc"])                                  # no configuration at all is the ordinary case

    def test_the_new_stop_classes_come_only_from_the_logs_own_text(self):
        known = lambda text: self.judge(text)[1]["stop"]
        inline = self.zig_inline
        self.assertEqual(known(inline)["class"], "cargo-config-rejected")
        self.assertEqual(known(inline.replace("sets a value to an inline table", "is wrong in another way"))["class"], "unclassified")            # a different cargo error is not that class
        refused = [l for l in inline.split("\n") if "sets a value to an inline table" in l][0]
        other = refused.replace("x01-cc/zig-cc-mips-be", "x01-cc/zig-cc-mips-x")
        self.assertEqual(known(inline.replace(refused, other))["class"], "unclassified")                                                          # it must name an argument this command carried
        keys = self.zig_keys
        self.assertEqual(known(keys), {"package": "aws-lc-sys v0.45.0", "exit": 101, "class": "c-compiler-rejected-target", "tool": None, "detail": "mips-unknown-linux-musl"})
        no_query = "\n".join(l for l in keys.split("\n") if "unable to parse target query" not in l)
        self.assertEqual(known(no_query)["class"], "unclassified")
        self.assertEqual(known(keys.replace("unable to parse target query 'mips-unknown-linux-musl'", "unable to parse target query 'riscv64-unknown-linux-musl'"))["class"], "unclassified")
        self.assertEqual(known(keys.replace("error occurred in cc-rs: command did not execute successfully", "error occurred in cc-rs: something else"))["class"], "unclassified")
        # a refusal that is not consistent is not a record
        self.plant("a refusal without its error text", lambda t: "\n".join(l for l in t.split("\n") if "sets a value to an inline table" not in l), "not a consistent refusal", inline)
        self.plant("a refusal with exit 0", lambda t: t.replace("exit=101", "exit=0"), "not a consistent refusal", inline)
        self.plant("a refusal with another exit in the receipt", lambda t: self.edit_receipt(t, lambda doc: doc.update(command_exit_code=1)), "not a consistent refusal", inline)
        self.plant("a refusal without its exit line", lambda t: "\n".join(l for l in t.split("\n") if "Remote command finished" not in l), "remote command exit", inline)
        self.plant("a refusal cut before its receipt", lambda t: t[:t.rindex("[RCH] source content receipt:")], "expected one rch source content receipt", inline)

    def test_the_wrapper_pins_are_the_files_they_name(self):
        files = self.anchors["cc_wrappers"]["files"]
        original = L.read_bounded_file(os.path.join(REPO, "toolchain", "linker", "zig-cc-mips-be"))
        self.assertEqual(L.sha256_bytes(original), files["x01-cc/zig-cc-mips-be"]["sha256"])                                                         # the repository's own linker driver
        adapter = L.read_bounded_file(os.path.join(REPO, "tests", "tailscale-fixtures", "x01", "x01-cc", "zig-cc-mips-be-ccrs"))
        self.assertEqual(L.sha256_bytes(adapter), files["x01-cc/zig-cc-mips-be-ccrs"]["sha256"])
        self.assertEqual(sorted(files), ["x01-cc/zig-cc-mips-be", "x01-cc/zig-cc-mips-be-ccrs", "x01-cc/zig-cc-mips-be-ccrs-v2"])
        hardened = L.read_bounded_file(os.path.join(REPO, "tests", "tailscale-fixtures", "x01", "x01-cc", "zig-cc-mips-be-ccrs-v2"))
        self.assertEqual(L.sha256_bytes(hardened), files["x01-cc/zig-cc-mips-be-ccrs-v2"]["sha256"])
        for body in (original, adapter, hardened):
            self.assertIn(b"want=0.14.1", body)                                                                                                       # the Zig version is enforced by the file
            self.assertIn(b"-target mips-linux-musleabi", body)                                                                                       # Zig's big-endian o32 soft-float target
        self.assertEqual(set(self.anchors["cc_wrappers"]) - {"note", "files"}, {"target", "attempt", "env_key"})

    def test_the_adapter_normalizes_only_the_two_known_target_spellings(self):
        adapter = os.path.join(REPO, "tests", "tailscale-fixtures", "x01", "x01-cc", "zig-cc-mips-be-ccrs")
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "zig")
            with open(fake, "w", encoding="utf-8") as handle:
                handle.write('#!/bin/sh\nif [ "$1" = version ]; then printf "%s\\n" "$FAKE_ZIG_VERSION"; exit 0; fi\nprintf "ARG:%s\\n" "$@"\n')
            os.chmod(fake, 0o755)

            def run(version, *args):
                done = subprocess.run(["bash", adapter, *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60,
                                      env={"PATH": tmp + os.pathsep + "/usr/bin:/bin", "FAKE_ZIG_VERSION": version, "HOME": tmp})
                return done.returncode, [l[4:] for l in done.stdout.splitlines() if l.startswith("ARG:")], done.stderr
            code, args, _ = run("0.14.1", "-O0", "--target=mips-unknown-linux-musl", "-c", "x.c")
            self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-O0", "-c", "x.c"]))                                              # the Rust spelling is dropped, the rest kept in order
            code, args, _ = run("0.14.1", "--target=mips-linux-musleabi", "-c", "x.c")
            self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-c", "x.c"]))
            code, args, err = run("0.14.1", "--target=mips-unknown-linux-gnu", "-c", "x.c")
            self.assertEqual((code, args, "unsupported target override" in err), (98, [], True))                                                       # any other target override is refused
            code, args, err = run("0.14.1", "-target", "x", "-c", "x.c")
            self.assertEqual((code, args), (98, []))
            code, args, err = run("0.15.0", "-c", "x.c")
            self.assertEqual((code, args, "zig 0.14.1 required, found 0.15.0" in err), (97, [], True))                                                # a different Zig is refused

    def test_the_full_real_account_fits_the_shared_bound_and_states_the_boundary_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, self.six)
            blocked = rc.case_build(tmp, rc.inputs())
            self.assertEqual(blocked.status, "blocked", blocked.detail)                                                                                # without the adapter build the MIPS whole library has only stops
            self.assertIn("whole mips: STOPPED at aws-lc-sys v0.45.0", blocked.detail)
            self.assertIn("REJECTED by cargo before building", blocked.detail)
            self.assertIn("rejected the target spelling", blocked.detail)
            self.repo_with(os.path.join(tmp, "x"), dict(self.six, **{"7.log": self.zig_ccrs}))
            passed = rc.case_build(os.path.join(tmp, "x"), rc.inputs())
            self.assertEqual(passed.status, "passed", passed.detail)
            self.assertNotIn("zig-cc-mips-be-ccrs-v2", passed.detail)                                                                                  # only the wrappers that built are named
            self.repo_with(os.path.join(tmp, "y"), dict(self.six, **{"7.log": self.zig_ccrs, "8.log": self.zig_ccrs_v2}))
            both = rc.case_build(os.path.join(tmp, "y"), rc.inputs())
            self.assertEqual(both.status, "passed", both.detail)
            self.assertIn("wrappers x01-cc/zig-cc-mips-be-ccrs (sha256 17848d169db2) and x01-cc/zig-cc-mips-be-ccrs-v2 (sha256 3dc93ff4f618)", both.detail)
        for result in (blocked, passed, both, rc.case_build(REPO)):
            self.assertLess(len(result.detail), 1000, result.detail)
            self.assertNotIn("[+", result.detail)                                                                                                      # nothing the shared case log bound would cut
            boundary = result.detail.index("T01-X02 and the native requirement are untouched")
            self.assertLess(boundary, result.detail.index("core powerpc"))                                                                           # the boundary comes before the account, so it cannot be truncated away
            self.assertIn("nothing linked or run", result.detail)

    def test_a_built_attempt_with_a_stale_wrapper_fails_the_case_and_the_earlier_stops_cannot_pass_it(self):
        data = rc.inputs()
        with tempfile.TemporaryDirectory() as tmp:
            stale = self.edit_receipt(self.zig_ccrs, lambda doc: [e.update(sha256="a" * 64) for e in self.files(doc) if e["path"] == "x01-cc/zig-cc-mips-be-ccrs"])
            self.repo_with(tmp, dict(self.six, **{"7.log": stale}))
            result = rc.case_build(tmp, data)
            self.assertEqual(result.status, "failed")
            self.assertIn("7.log: ", result.detail)
        with tempfile.TemporaryDirectory() as tmp:
            self.repo_with(tmp, dict(self.six, **{"7.log": self.zig_inline.replace("zig-cc-mips-be", "zig-cc-mips-be-ccrs")}))
            self.assertEqual(rc.case_build(tmp, data).status, "failed")                                                                              # an altered record does not hold

    ADAPTERS = os.path.join(REPO, "tests", "tailscale-fixtures", "x01", "x01-cc")

    def run_adapter(self, name, version, *args):
        """Run one committed wrapper under bash with a stand-in `zig` that prints its arguments (no real Zig, no compile)."""
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "zig")
            with open(fake, "w", encoding="utf-8") as handle:
                handle.write('#!/bin/sh\nif [ "$1" = version ]; then printf "%s\\n" "$FAKE_ZIG_VERSION"; exit 0; fi\nprintf "ARG:%s\\n" "$@"\n')
            os.chmod(fake, 0o755)
            done = subprocess.run(["bash", os.path.join(self.ADAPTERS, name), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60,
                                  env={"PATH": tmp + os.pathsep + "/usr/bin:/bin", "FAKE_ZIG_VERSION": version, "HOME": tmp})
        return done.returncode, [l[4:] for l in done.stdout.splitlines() if l.startswith("ARG:")], done.stderr

    def test_the_hardened_adapter_refuses_every_spelling_of_a_target_override_and_forwards_the_rest(self):
        v2 = "zig-cc-mips-be-ccrs-v2"
        code, args, _ = self.run_adapter(v2, "0.14.1", "-O0", "--target=mips-unknown-linux-musl", "-c", "x.c")
        self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-O0", "-c", "x.c"]))                                          # the Rust spelling is dropped, the rest kept in order
        code, args, _ = self.run_adapter(v2, "0.14.1", "--target=mips-linux-musleabi", "-c", "x.c")
        self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-c", "x.c"]))
        code, args, _ = self.run_adapter(v2, "0.14.1", "-DTARGET=1", "-Itarget/include", "-Wno-error=target", "-c", "x.c")                          # flags that only mention "target" are not overrides
        self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-DTARGET=1", "-Itarget/include", "-Wno-error=target", "-c", "x.c"]))
        for override in (["--target=mips-unknown-linux-gnu"], ["--target", "mips-unknown-linux-gnu"], ["-target", "mips-unknown-linux-gnu"], ["-target=mips-unknown-linux-gnu"],
                         ["--target"], ["-target"], ["--target", "mips-unknown-linux-musl"]):                                                          # all four spellings, with a value or without, even the known one in two arguments
            code, args, err = self.run_adapter(v2, "0.14.1", "-O0", *override, "-c", "x.c")
            self.assertEqual((code, args, "unsupported target override" in err), (98, [], True), override)
        code, args, err = self.run_adapter(v2, "0.15.0", "-c", "x.c")
        self.assertEqual((code, args, "zig 0.14.1 required, found 0.15.0" in err), (97, [], True))

    def test_the_first_adapter_forwarded_the_two_spellings_the_hardened_one_refuses(self):
        # the retained baseline: x01-cc/zig-cc-mips-be-ccrs is unchanged and its recorded build stands; it let these two through, which the broader "any other override" wording should have refused
        for override in (["--target", "mips-unknown-linux-gnu"], ["-target=mips-unknown-linux-gnu"]):
            code, args, _ = self.run_adapter("zig-cc-mips-be-ccrs", "0.14.1", "-O0", *override, "-c", "x.c")
            self.assertEqual((code, args), (0, ["cc", "-target", "mips-linux-musleabi", "-O0", *override, "-c", "x.c"]), override)
            code, args, err = self.run_adapter("zig-cc-mips-be-ccrs-v2", "0.14.1", "-O0", *override, "-c", "x.c")
            self.assertEqual((code, args, "unsupported target override" in err), (98, [], True), override)
        for override in (["--target=mips-unknown-linux-gnu"], ["-target", "mips-unknown-linux-gnu"]):                                                 # what both always refused, still refused by both
            for name in ("zig-cc-mips-be-ccrs", "zig-cc-mips-be-ccrs-v2"):
                self.assertEqual(self.run_adapter(name, "0.14.1", *override, "-c", "x.c")[:2], (98, []), (name, override))

    def test_the_hardened_wrapper_record_holds_and_its_pin_is_exact(self):
        problems, facts = self.judge(self.zig_ccrs_v2)
        self.assertEqual(problems, [])
        self.assertEqual((facts["outcome"], facts["attempt"], facts["target"], facts["artifacts"], facts["core_crates_compiled"]), ("built", "whole", "mips-unknown-linux-musl", 340, 7))
        self.assertEqual(facts["cc"], {"wrapper": "x01-cc/zig-cc-mips-be-ccrs-v2", "sha256": "3dc93ff4f618cd96f1a8f4dbe68b0f37a9712778d3bf0f3f6e3d634eb61e64ab", "form": "keys"})
        base, wrapper, key = self.zig_ccrs_v2, "x01-cc/zig-cc-mips-be-ccrs-v2", "env.CC_mips_unknown_linux_musl"

        def set_hash(path, digest):
            return lambda t: self.edit_receipt(t, lambda doc: [e.update(sha256=digest) for e in self.files(doc) if e["path"] == path])
        self.plant("a changed hardened wrapper", set_hash(wrapper, "b" * 64), "is not the pinned wrapper", base)
        self.plant("the hardened wrapper not synced", lambda t: self.edit_receipt(t, lambda doc: self.files(doc).pop(next(i for i, e in enumerate(self.files(doc)) if e["path"] == wrapper))),
                   "is not among the synced files", base)
        self.plant("an unpinned successor", self.swap_cfg('%s.value="%s"' % (key, wrapper), '%s.value="x01-cc/zig-cc-mips-be-ccrs-v3"' % key), "unexpected --config arguments", base)
        self.plant("an unpinned file beside the three", lambda t: self.edit_receipt(t, lambda doc: self.files(doc).append({"path": "x01-cc/zig-cc-mips-be-ccrs-v3", "sha256": "c" * 64, "byte_count": 1, "executable": True})),
                   "not pinned C compiler wrappers", base)
        self.plant("a changed first adapter, which stays pinned", set_hash("x01-cc/zig-cc-mips-be-ccrs", "d" * 64), "is not the pinned wrapper", base)
        # the earlier adapter's build and its three stops are still judged exactly as before
        self.assertEqual(self.judge(self.zig_ccrs)[1]["cc"]["wrapper"], "x01-cc/zig-cc-mips-be-ccrs")
        self.assertEqual(sorted(self.anchors["cc_wrappers"]["files"]), ["x01-cc/zig-cc-mips-be", "x01-cc/zig-cc-mips-be-ccrs", "x01-cc/zig-cc-mips-be-ccrs-v2"])
        v2 = L.read_bounded_file(os.path.join(self.ADAPTERS, "zig-cc-mips-be-ccrs-v2"))
        self.assertEqual(L.sha256_bytes(v2), "3dc93ff4f618cd96f1a8f4dbe68b0f37a9712778d3bf0f3f6e3d634eb61e64ab")
        for line in (b"want=0.14.1", b"-target mips-linux-musleabi", b"--target=*|--target|-target|-target=*)"):
            self.assertIn(line, v2)

    def test_the_x01_statements_in_the_profile_and_the_study_match_the_recorded_scope_and_strengthen_nothing(self):
        profile = L.load_json(L.PROFILE)
        self.assertEqual(profile["profile_version"], "t01-profile-2026-11-07.1")
        for said in ("t01-profile-2026-11-06.1", "no state, evidence citation, cell or figure changed"):
            self.assertIn(said, profile["frozen_note"])
        self.assertIn("type-checks only", profile["status"])
        self.assertIn("nothing linked or run", profile["status"])
        raw = json.dumps(profile)
        for stale in ("no receipt exists yet", "nothing was built", "mandatory legacy-ISA build (X01)", "X01/X02 are blocked", "while X01/X02"):
            self.assertNotIn(stale, raw)
        for tid in ("ppc32be_stock", "mips32r2be_stock", "ppc32be_harness", "mips32be_harness"):
            m = profile["measurements"]["tailscale-rs-0.6.1/" + tid]
            triple = profile["targets"][tid]["rust_triple"]
            self.assertEqual((m["build"]["state"], m["binary_bytes"]["state"], m["rss_peak_bytes"]["state"], m["cpu"]["state"]), ("pending",) * 4)       # nothing became a measurement
            self.assertIn("type-check for " + triple, m["build"]["blocker"])
            self.assertIn("no linked build has been made", m["build"]["blocker"])
            self.assertIn("cargo check does not link", m["binary_bytes"]["blocker"])
        for tid in ("mips32r2be_stock", "mips32be_harness"):
            self.assertIn("covers tailscale-rs only", profile["measurements"]["tailscale-go-1.104.5/" + tid]["build"]["blocker"])
        platform = profile["candidates"]["tailscale-rs-0.6.1"]["platform"]
        self.assertEqual({k: v["state"] for k, v in platform.items()}, {"ppc32be_stock": "incompatible", "mips32r2be_stock": "no_evidence", "ppc32be_harness": "no_evidence", "mips32be_harness": "no_evidence"})
        for tid in ("mips32r2be_stock", "ppc32be_harness", "mips32be_harness"):
            self.assertIn("type-check", platform[tid]["note"])
            self.assertIn("nothing was linked or run", platform[tid]["note"])
            self.assertNotIn("receipt", platform[tid])                                                                                              # no build_ok_unrun, so no receipt is claimed
        self.assertTrue(platform["ppc32be_stock"]["note"].startswith("tokio's net feature rides on mio"))                                           # the kernel incompatibility is untouched
        for cand in profile["candidates"].values():
            for p in cand["platform"].values():
                self.assertNotIn(p["state"], ("build_ok_unrun", "ran_on_target"))
        nr = profile["native_requirement"]
        self.assertEqual((nr["status"], nr["waived"], nr["satisfied_by"], nr["closes"]), ("required", False, [], []))
        self.assertIn("X02", nr["t01_status"])
        self.assertIn("nothing was linked or run", nr["t01_status"])
        self.assertNotIn("supported", set(L.matrix(profile).values()))
        with open(os.path.join(REPO, "docs", "tailscale", "feasibility.md"), encoding="utf-8") as handle:
            study = handle.read()
        with open(os.path.join(REPO, "docs", "contracts", "t01.md"), encoding="utf-8") as handle:
            contract = handle.read()
        for stale in ("This is the first thing a central build would answer", "until an actual selected Cargo graph and build (T01-X01)", "the mandatory legacy-ISA build (T01-X01)",
                      "while the mandatory T01-X01 build", "BLOCKED until all four built", "T01-X02 is BLOCKED until a measurement receipt exists"):
            self.assertNotIn(stale, study + contract)
        for said in ("so whether the crypto passes on big-endian 32-bit stays unknown", "stays **unqualified**", "built as type-checks only"):
            self.assertIn(said, study)
        self.assertIn("INCOMPLETE and pending", contract)

    def test_the_lock_fixture_is_the_pinned_lock_and_a_changed_one_is_reported(self):
        def fault(mutate, needle):
            self.assertEqual(L.check_x01_lock(self.lock, self.anchors), [])
            self.assertTrue(planted(L.check_x01_lock(mutate(self.lock), self.anchors), needle), needle)
        fault(lambda t: t.replace("checksum = ", "checksum = \"0\" #", 1), "sha256 differs")
        pinned = copy.deepcopy(self.anchors)
        for cut in (lambda t: t.rsplit("[[package]]", 1)[0], lambda t: t.replace("registry+https://github.com/rust-lang/crates.io-index", "git+https://example.invalid/x", 1)):
            changed = cut(self.lock)
            pinned["consumer_files"]["Cargo.lock"] = L.sha256_text(changed)                      # the digest is made to agree, so only the structure can object
            problems = L.check_x01_lock(changed, pinned)
            self.assertTrue(problems, "a structurally changed lock must be reported")
        pinned = copy.deepcopy(self.anchors)
        pinned["core_crates"] = pinned["core_crates"][:-1]
        self.assertTrue(planted(L.check_x01_lock(self.lock, pinned), "does not depend on exactly the seven core crates"))

    def test_the_tree_digest_of_a_file_list_equals_the_digest_of_the_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = {}
            for rel, body in {"Cargo.toml": b"a", "src/lib.rs": b"b", "src/z/mod.rs": b"c", "src/a.rs": b"d", "zz": b"e", "src-x/y.rs": b"f"}.items():
                write_raw(tmp, rel, body.decode())
                entries[rel] = hashlib.sha256(body).hexdigest()
            self.assertEqual(L.tree_digest_of_entries(entries), L.tree_digest(tmp))

    def test_one_log_file_is_read_without_following_a_link_or_blocking_and_within_its_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = os.path.join(tmp, "good.log")
            with open(good, "wb") as handle:
                handle.write(b"x" * 100)
            self.assertEqual(len(L.read_bounded_file(good, 100)), 100)
            for refused in (lambda: L.read_bounded_file(good, 99),):
                with self.assertRaises(L.SourceRefused) as caught:
                    refused()
                self.assertNotIn(tmp, str(caught.exception))
            link = os.path.join(tmp, "link.log")
            os.symlink(good, link)
            fifo = os.path.join(tmp, "fifo.log")
            os.mkfifo(fifo)
            for odd in (link, fifo, tmp):
                with self.assertRaises(L.SourceRefused) as caught:
                    L.read_bounded_file(odd)
                self.assertNotIn(tmp, str(caught.exception))
            with self.assertRaises(FileNotFoundError):
                L.read_bounded_file(os.path.join(tmp, "absent.log"))

    def test_the_redact_command_writes_once_refuses_to_overwrite_and_never_leaves_site_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, dest = os.path.join(tmp, "raw.txt"), os.path.join(tmp, "out.log")
            with open(raw, "w", encoding="utf-8") as handle:
                handle.write(self.raw_form(self.text))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(rc.redact_command(raw, dest), 0)
            self.assertEqual(L.read_bounded_file(dest).decode("utf-8"), self.text)
            self.assertNotIn(tmp, out.getvalue())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(rc.redact_command(raw, dest), 1)                                   # never overwrites
                self.assertEqual(rc.redact_command(os.path.join(tmp, "absent"), os.path.join(tmp, "o2")), 2)
            self.assertEqual(L.read_bounded_file(dest).decode("utf-8"), self.text)
            self.assertNotIn(tmp, err.getvalue())

    def test_the_entry_point_judges_a_supplied_log_and_never_prints_its_path(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as scratch:
            good, bad = os.path.join(tmp, "good.txt"), os.path.join(tmp, "bad.txt")
            with open(good, "w", encoding="utf-8") as handle:
                handle.write(self.raw_form(self.text))
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write(self.raw_form(self.text).replace("Remote command finished: exit=0", "Remote command finished: exit=101"))
            run = lambda *argv: subprocess.run([ENTRY, *argv], capture_output=True, text=True, stdin=subprocess.DEVNULL, env=dict(os.environ, TMPDIR=scratch), timeout=300)
            ok = run("--tier", "full", "--build-log", good)
            self.assertEqual(ok.returncode, 3, ok.stdout + ok.stderr)                                # T01-X02 stays blocked whatever the compile records say
            self.assertNotIn("FAIL     T01-X01-legacy-isa-build", ok.stdout)                           # independent of which records are committed
            self.assertNotIn(tmp, ok.stdout + ok.stderr)
            failing = run("--tier", "full", "--build-log", bad)
            self.assertEqual(failing.returncode, 1, failing.stdout + failing.stderr)
            self.assertIn("FAIL     T01-X01-legacy-isa-build", failing.stdout)
            self.assertIn("supplied build log 1:", failing.stdout)
            self.assertNotIn(tmp, failing.stdout + failing.stderr)


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
        self.assertIn("planned=15 passed=10 failed=0 blocked=5", out)
        self.assertNotIn("T01-X01-legacy-isa-build", out)                                  # passed: only blocked and failed cases are printed
        self.assertNotIn("T01-X02-target-resources", out)                                  # passed too, on the two committed guest receipts under measurements/
        self.assertIn("BLOCKED  T01-P01-tsrs-source", out)
        code, out, _ = self.call("--tier", "soak")
        self.assertEqual((code, "T01 soak: NOT RUN" in out, "This is not a pass." in out), (4, True, True))
        code, out, _ = self.call("--tier", "full", "--list")
        self.assertEqual((code, len(out.strip().splitlines())), (0, 15))
        self.assertEqual(self.call("--no-such-flag")[0], 2)
        code, _, err = self.call("--sources", "/nonexistent/place")
        self.assertEqual((code, "sources directory was not found" in err, "/nonexistent" in err), (2, True, False))


if __name__ == "__main__":
    unittest.main()
