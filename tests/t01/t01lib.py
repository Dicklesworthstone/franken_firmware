"""T01 (`ffw-32a`): analysis rules, synthetic-fixture models and read-only source probes for the native Tailscale feasibility study (offline, standard library only).

* The RULES (`classify`, `derive_cell`, `budget_verdict`) are small and total, so a table written by hand from the contract (tests/t01/cases.json) can be held against them.
* The LEDGER (`check_ledger`) holds verbatim excerpts of primary sources with their digests; the PROFILE (`check_profile`, docs/tailscale/profiles.json) may state only what the
  ledger can back, and a cell is `supported` only on a measured receipt, which no local run can produce.
* The FIXTURES are synthetic (identity, network map, relay map, key-expiry timeline); the models here are checked against expectations written by hand in the fixture files.
* The PROBES read the pinned source trees as DATA (they never run, build or import anything from them) and recompute the census the profile records.

Nothing here contacts a network, a provider or a device, and nothing measures a target. Every check takes the data it judges as an argument so test_t01.py can plant a fault in a
copy and require the check to report it. A check returns a list of problems; an empty list is a pass.
"""
import hashlib
import ipaddress
import json
import os
import re
import shlex
import signal
import stat
import threading
import time
import tomllib

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PROFILE = os.path.join(ROOT, "docs", "tailscale", "profiles.json")
LEDGER = os.path.join(ROOT, "tests", "tailscale-fixtures", "evidence", "ledger.json")
FIXTURES = os.path.join(ROOT, "tests", "tailscale-fixtures", "synthetic")
CASES = os.path.join(HERE, "cases.json")
RESULTS = os.path.join(ROOT, "toolchain", "results", "tailscale")

BEHAVIOR_STATES = ("implemented", "partial", "not_implemented", "unknown")
PLATFORM_STATES = ("incompatible", "no_evidence", "build_unproven", "build_ok_unrun", "ran_on_target", "not_applicable")
CELL_STATES = ("supported", "implementable_upstream_work", "incompatible", "no_evidence", "not_applicable")
CLASSES = ("native_strict_rust", "official_reference", "wireguard_only", "wrapper", "gateway", "control_server_only")
LEDGER_KINDS = ("git_file", "crate_file", "web_text", "web_json", "web_header", "local_file", "tracker")
IMMUTABLE_KINDS = ("git_file", "crate_file")
# The bead's tailnet resource table: "identity enrollment, maps at the declared peer cap, reconnect, relay traffic and key rotation while audio runs". Every measurements row carries all five.
SCENARIO_ITEMS = ("scenario_enrollment", "scenario_maps_at_peer_cap", "scenario_reconnect", "scenario_relay_traffic", "scenario_key_rotation")
# A measurement item may be `not_applicable` only where the candidate has no build for the target at all. The ledger entry that says so: Go 1.27.3 has no 32-bit linux/ppc port (T01-E01).
NO_GO_PORT_EVIDENCE = "T01-E01"


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path):
    with open(path, "rb") as handle:
        return sha256_bytes(handle.read())


# ---- the rules ---------------------------------------------------------------------------------------------------------------------------

def classify(facts):
    """The class of an approach from facts about it, in a fixed order. Only a strict-Rust process with its own tailnet identity is `native_strict_rust`; the same
    thing in another language is the official reference; anything that rides on another daemon, another runtime or another host is a wrapper or a gateway; a
    WireGuard data plane without a control plane is not Tailscale membership at all."""
    role, mode, membership = facts.get("role"), facts.get("mode"), facts.get("membership")
    if role == "server":
        return "control_server_only"
    if mode == "wireguard_data_plane_only":
        return "wireguard_only"
    if mode == "proxy_of_other_daemon":
        return "gateway" if facts.get("daemon_location") == "other_host" else "wrapper"
    if mode == "embeds_foreign_runtime":
        return "wrapper"
    if mode == "native_process" and membership == "own_identity":
        return "native_strict_rust" if facts.get("language") == "rust" else "official_reference"
    raise ValueError("unclassifiable facts: %r" % (facts,))


def derive_cell(behavior, platform, extensible):
    """One cell of the matrix from the candidate's implementation state of a behavior and the platform state of a target. The weakest honest statement wins: a platform
    that cannot run the candidate is `incompatible` whatever it implements; a gap is `implementable_upstream_work` only when the gap can be closed in a code base we
    can extend; an implemented behavior is `supported` only when the candidate has run on the target, which no fixture, review or source probe can show."""
    if platform == "not_applicable":
        return "not_applicable"
    if platform == "incompatible":
        return "incompatible"
    if behavior in ("not_implemented", "partial"):
        return "implementable_upstream_work" if extensible else "incompatible"
    if behavior == "unknown":
        return "no_evidence"
    return "supported" if platform == "ran_on_target" else "no_evidence"


def budget_verdict(measured, cap, reserve_floor, reserve):
    """A resource figure against a budget. Missing data is `pending`, never a pass. `measured`/`cap` are None or {"value": int, "unit": str[, "receipt": str]}."""
    if reserve is None or reserve < reserve_floor:
        return "invalid:reserve_below_floor"
    if measured is None:
        return "pending:no_measurement"
    if cap is None:
        return "pending:no_budget"
    if measured.get("unit") != cap.get("unit"):
        return "invalid:unit_mismatch"
    if not measured.get("receipt"):
        return "invalid:measurement_without_receipt"
    return "pass" if measured["value"] + reserve <= cap["value"] else "fail"


# ---- the ledger --------------------------------------------------------------------------------------------------------------------------

SITE_PATTERNS = (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), re.compile(r"/(?:Users|home)/[A-Za-z]"), re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.I))


def normalized(text):
    return re.sub(r"\s+", " ", text).strip()


def check_ledger(ledger, root=ROOT):
    problems = []
    if ledger.get("schema") != "ffw.t01.ledger.v1":
        problems.append("the ledger schema is %r" % ledger.get("schema"))
    ids = [e.get("id") for e in ledger.get("entries", [])]
    if not ids:
        problems.append("the ledger has no entries")
    if len(ids) != len(set(ids)):
        problems.append("the ledger has a duplicate id")
    for e in ledger.get("entries", []):
        eid = e.get("id", "?")
        if not re.fullmatch(r"T01-E\d\d", str(eid)):
            problems.append("%s: not a stable ledger id" % eid)
        if e.get("kind") not in LEDGER_KINDS:
            problems.append("%s: kind %r" % (eid, e.get("kind")))
        for key in ("topic", "claim", "excerpt", "excerpt_sha256"):
            if not e.get(key):
                problems.append("%s: no %s" % (eid, key))
        if e.get("excerpt") and sha256_text(e["excerpt"]) != e.get("excerpt_sha256"):
            problems.append("%s: the excerpt does not match its sha256" % eid)
        if e.get("kind") in IMMUTABLE_KINDS:
            rev = str(e.get("rev", ""))
            if e["kind"] == "git_file" and not re.fullmatch(r"[0-9a-f]{40}", rev):
                problems.append("%s: a git pin must be a full commit, not %r" % (eid, rev))
            if e["kind"] == "crate_file" and not re.fullmatch(r"\d+\.\d+\.\d+", rev):
                problems.append("%s: a crate pin must be an exact version, not %r" % (eid, rev))
            if not e.get("immutable"):
                problems.append("%s: a commit or version pin is immutable" % eid)
            if not re.fullmatch(r"[0-9a-f]{64}", str(e.get("source_sha256", ""))):
                problems.append("%s: no sha256 of the whole source file" % eid)
            lines = e.get("lines")
            if not (isinstance(lines, list) and len(lines) == 2 and 1 <= lines[0] <= lines[1]) or (lines and lines[1] - lines[0] + 1 != e.get("excerpt", "").count("\n") + 1):
                problems.append("%s: the line range does not match the excerpt" % eid)
        elif e.get("kind") in ("web_text", "web_json", "web_header"):
            if e.get("immutable"):
                problems.append("%s: a web page is not an immutable pin" % eid)
            if not e.get("retrieved_utc") or not re.fullmatch(r"[0-9a-f]{64}", str(e.get("source_sha256", ""))):
                problems.append("%s: a web excerpt needs its retrieval time and the sha256 of what was retrieved" % eid)
        elif e.get("kind") == "local_file":
            path = os.path.join(root, e.get("path", ""))
            if not os.path.isfile(path):
                problems.append("%s: %s is not in this checkout" % (eid, e.get("path")))
            else:
                with open(path, encoding="utf-8") as handle:
                    if normalized(e.get("excerpt", "")) not in normalized(handle.read()):
                        problems.append("%s: the excerpt is no longer in %s (the evidence moved)" % (eid, e.get("path")))
        for field in ("excerpt", "claim"):
            for pattern in SITE_PATTERNS:
                if pattern.search(e.get(field, "")):
                    problems.append("%s: %s carries something that looks like site data (%s)" % (eid, field, pattern.pattern[:24]))
    return problems


# ---- the profile and its matrix ----------------------------------------------------------------------------------------------------------

def matrix(profile):
    """(candidate, target, behavior) -> cell, derived; never read from the file."""
    out = {}
    for cid, cand in profile["candidates"].items():
        for tid in profile["targets"]:
            platform = cand["platform"][tid]["state"]
            for bid in (b["id"] for b in profile["behaviors"]):
                out[(cid, tid, bid)] = derive_cell(cand["behaviors"][bid]["state"], platform, cand["extensible"])
    return out


def has_no_build_for_target(profile, candidate_id, target_id):
    """True only where the candidate cannot be built for the target at all, so a measurement of it is inapplicable. The profile has exactly one such case, the Go client on a 32-bit PowerPC target,
    and it is derived from the profile's own facts, not from a list of rows: the candidate's language is Go, the target's Rust triple is powerpc, and the candidate's platform on that target is
    `incompatible` with the Go port table (T01-E01: no 32-bit linux/ppc port) among its evidence. A tailscale-rs row has a build path on every target (a type-check passes), so what it lacks is a
    figure, which is `pending` with a blocker, never `not_applicable`."""
    candidate = profile.get("candidates", {}).get(candidate_id, {})
    platform = candidate.get("platform", {}).get(target_id, {})
    triple = str(profile.get("targets", {}).get(target_id, {}).get("rust_triple", ""))
    return bool(candidate.get("facts", {}).get("language") == "go" and triple.startswith("powerpc-") and platform.get("state") == "incompatible"
                and NO_GO_PORT_EVIDENCE in platform.get("evidence", []))


# A measurement is `measured` only on a receipt: a JSON file directly under this directory (the X02 writer's, scripts/e2e/t01 --x02).
MEASUREMENT_RECEIPT_DIR = "toolchain/results/tailscale/measurements/"


def receipt_problem(receipt, repo=None):
    """Why a `measured` item's `receipt` does not name a real receipt, or None. It must be a repo-relative path directly under toolchain/results/tailscale/measurements/ ending in .json. Given the
    repository, the file must also exist as a plain regular file (a symlink, FIFO or oversize file is refused unread) and parse as a JSON object; without it only the form is checked, so a caller that
    can see the repository (the runner's T01-META-PROFILE does) is what makes a bare string like "x" or a missing file fail. A parseable file is not proof that it holds the figure: judging that
    is the X02 judge's job (x02_judge.judge_receipt), and nothing here binds the item's value to the receipt."""
    if not isinstance(receipt, str) or not receipt.startswith(MEASUREMENT_RECEIPT_DIR):
        return "names %s, not a file under %s" % (repr(receipt)[:60], MEASUREMENT_RECEIPT_DIR)
    leaf = receipt[len(MEASUREMENT_RECEIPT_DIR):]
    if not leaf.endswith(".json") or "/" in leaf or "\\" in leaf or leaf.startswith("."):
        return "names %s, which is not a .json file directly under %s" % (repr(receipt)[:80], MEASUREMENT_RECEIPT_DIR)
    if repo is None:
        return None
    try:
        data = read_bounded_file(os.path.join(repo, *receipt.split("/")))
    except (SourceRefused, OSError):
        return "names %s, a file that does not exist or cannot be read" % receipt
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "names %s, a file that does not parse as JSON" % receipt
    if not isinstance(doc, dict):
        return "names %s, a file that is not a JSON object" % receipt
    return None


def check_profile(profile, ledger, repo=None):
    problems = []
    ids = {e["id"] for e in ledger.get("entries", [])}
    if profile.get("schema") != "ffw.t01.profile.v1":
        problems.append("the profile schema is %r" % profile.get("schema"))
    if not re.fullmatch(r"t01-profile-\d{4}-\d{2}-\d{2}\.\d+", str(profile.get("profile_version", ""))):
        problems.append("the profile has no frozen version")
    behaviors = [b.get("id") for b in profile.get("behaviors", [])]
    if len(behaviors) != len(set(behaviors)) or not behaviors:
        problems.append("the behaviors are missing or repeated")
    targets = profile.get("targets", {})
    for tid, t in targets.items():
        for key in ("isa", "rust_triple", "kernel", "kernel_state", "stock"):
            if key not in t:
                problems.append("target %s lacks %s" % (tid, key))
        if t.get("stock") and t.get("kernel_state") != "unqualified":
            problems.append("target %s: a stock kernel with no matching guest is unqualified (E03)" % tid)

    def cites(where, node, need):
        refs = node.get("evidence", [])
        missing = [r for r in refs if r not in ids]
        if missing:
            problems.append("%s cites %s, which the ledger does not hold" % (where, ", ".join(missing)))
        if need and not refs:
            problems.append("%s states something without citing evidence" % where)

    for cid, cand in profile.get("candidates", {}).items():
        try:
            derived = classify(cand.get("facts", {}))
        except ValueError as err:
            problems.append("candidate %s: %s" % (cid, err))
            continue
        if cand.get("class") != derived:
            problems.append("candidate %s is declared %s but its facts make it %s" % (cid, cand.get("class"), derived))
        if cand.get("class") not in CLASSES:
            problems.append("candidate %s: class %r" % (cid, cand.get("class")))
        if bool(cand.get("strict_rust")) != (cand.get("facts", {}).get("language") == "rust"):
            problems.append("candidate %s: strict_rust disagrees with its language" % cid)
        if cand.get("class") != "native_strict_rust" and cand.get("counts_as_native") is not False:
            problems.append("candidate %s is a %s and must say counts_as_native: false" % (cid, cand.get("class")))
        if cand.get("counts_as_native") is not False:
            problems.append("candidate %s: no candidate counts as the native implementation on this evidence" % cid)
        for bid in behaviors:
            b = cand.get("behaviors", {}).get(bid)
            if b is None or b.get("state") not in BEHAVIOR_STATES:
                problems.append("candidate %s: behavior %s has no valid state" % (cid, bid))
                continue
            cites("candidate %s behavior %s" % (cid, bid), b, need=b["state"] != "unknown")
        for tid in targets:
            p = cand.get("platform", {}).get(tid)
            if p is None or p.get("state") not in PLATFORM_STATES:
                problems.append("candidate %s: target %s has no valid platform state" % (cid, tid))
                continue
            cites("candidate %s on %s" % (cid, tid), p, need=p["state"] in ("incompatible", "not_applicable"))
            if p["state"] == "incompatible" and targets[tid].get("stock") and not p.get("conditional_on") and p.get("unconditional") is not True:
                problems.append("candidate %s on %s: an incompatibility on a stock target must say what it is conditional on (the reported kernel release) or that it is unconditional" % (cid, tid))
            if p["state"] in ("build_ok_unrun", "ran_on_target") and not p.get("receipt"):
                problems.append("candidate %s on %s: %s needs a receipt" % (cid, tid, p["state"]))
    cells = matrix(profile) if not problems else {}
    for key, cell in cells.items():
        if cell == "supported":
            problems.append("%s/%s/%s is supported, which needs a receipt from a run on the target" % key)

    budgets = profile.get("budgets", {})
    if budgets.get("reserve_floor_bytes") != 4 * 1024 * 1024:
        problems.append("the provisional reserve floor is not 4 MiB (the bead's rule)")
    if any(v is not None for v in budgets.get("tailnet_ram_cap_bytes", {}).values()):
        problems.append("a tailnet RAM cap is set, but no shared budget is allocated (absent budget is pending, not pass)")
    for mid, m in profile.get("measurements", {}).items():
        for name, item in m.items():
            if item.get("state") == "measured" and not item.get("receipt"):
                problems.append("measurement %s/%s is 'measured' without a receipt" % (mid, name))
            elif item.get("state") == "measured":
                why = receipt_problem(item["receipt"], repo)
                if why:
                    problems.append("measurement %s/%s is 'measured', but its receipt %s" % (mid, name, why))
            if item.get("state") not in ("measured", "pending", "observed_not_a_footprint", "not_applicable"):
                problems.append("measurement %s/%s: state %r" % (mid, name, item.get("state")))
            if item.get("state") in ("pending", "not_applicable") and not item.get("blocker"):
                problems.append("measurement %s/%s is %s without its reason" % (mid, name, item["state"]))
            if item.get("state") == "not_applicable" and not has_no_build_for_target(profile, *mid.partition("/")[::2]):
                problems.append("measurement %s/%s is not_applicable, but this candidate has a build path on that target, so what it lacks is a figure and stays pending with its blocker "
                                "(only a candidate with no build for the target, the Go client on 32-bit PowerPC, T01-E01, may be inapplicable)" % (mid, name))
        for name in SCENARIO_ITEMS:
            if name not in m:
                problems.append("measurement %s lacks the tailnet scenario item %s (the bead's resource table: absent is pending with a blocker, not missing)" % (mid, name))
            elif m[name].get("state") not in ("measured", "pending", "not_applicable"):
                problems.append("measurement %s/%s: a scenario figure is measured, pending or not_applicable, not %r" % (mid, name, m[name].get("state")))
    nr = profile.get("native_requirement", {})
    if nr.get("status") != "required" or nr.get("waived") is not False or nr.get("satisfied_by"):
        problems.append("the native requirement must stay required, unwaived and unsatisfied")
    for later in ("T02", "T04", "Q06"):
        if later not in nr.get("does_not_close", []):
            problems.append("the study must say it does not close %s" % later)
    return problems


# ---- the synthetic fixtures and their models ----------------------------------------------------------------------------------------------

def filter_decision(netmap, src, dst, port, proto):
    """Default deny; allow only when some rule matches source, destination, port and protocol (`*` matches anything)."""
    if not isinstance(port, int) or not 0 <= port <= 65535:
        return "deny"
    for rule in netmap["packet_filter"]:
        if src in rule["srcs"] and dst in rule["dsts"] and rule["proto"] in (proto, "*") and ("*" in rule["ports"] or port in rule["ports"]):
            return "allow"
    return "deny"


def route_for(regions, home_derp, direct_ok, reachable_only=None):
    """direct if the direct path works; else the peer's home relay region if it exists and is reachable; else the reachable region with the lowest latency; else unreachable."""
    if direct_ok:
        return "direct"
    usable = {r["id"]: r for r in regions if r["reachable"] and (reachable_only is None or r["id"] in reachable_only)}
    if home_derp in usable:
        return "derp:%d" % home_derp
    if usable:
        best = min(usable.values(), key=lambda r: (r["latency_ms"], r["id"]))
        return "derp:%d" % best["id"]
    return "unreachable"


def key_step(policy, key_expiry, now, clock_trusted, control_up, netmap_age_s):
    """(key state, data plane, action). An untrusted clock decides nothing; the expiry instant itself is expired; an expired key wins over every other condition; with the control
    plane down the last netmap is used only while it is younger than the offline bound (inclusive)."""
    if not clock_trusted:
        return ("unknown", "hold", "get_trusted_time")
    if now >= key_expiry:
        return ("expired", "down", "reauthenticate")
    state = "expiring" if now >= key_expiry - policy["warn_window_s"] else "valid"
    if control_up:
        return (state, "up", "renew" if state == "expiring" else "none")
    if netmap_age_s > policy["max_offline_netmap_age_s"]:
        return (state, "down", "wait_for_control")
    return (state, "up_stale", "retry_control")


KEY_RE = {"machine_key": re.compile(r"mkey:[0-9a-f]{64}"), "node_key": re.compile(r"nodekey:[0-9a-f]{64}"), "disco_key": re.compile(r"discokey:[0-9a-f]{64}")}
TAILNET_RANGE = ipaddress.ip_network("100.64.0.0/10")


def check_identity(doc):
    problems = []
    seen = {}
    for node in doc.get("nodes", []):
        nid = node.get("id", "?")
        for kind, pattern in KEY_RE.items():
            value = node.get(kind, "")
            if not pattern.fullmatch(value):
                problems.append("%s: %s is not a placeholder key of the documented shape" % (nid, kind))
            else:
                digits = value.split(":", 1)[1]
                if digits in seen:
                    problems.append("%s: %s repeats the key digits of %s (a key is never cloned across identities or across kinds)" % (nid, kind, seen[digits]))
                seen[digits] = nid
        if not str(node.get("hostname", "")).endswith(".invalid"):
            problems.append("%s: a synthetic hostname must be under .invalid" % nid)
        for address in node.get("addresses", []):
            try:
                if ipaddress.ip_address(address) not in TAILNET_RANGE:
                    problems.append("%s: %s is outside the tailnet range" % (nid, address))
            except ValueError:
                problems.append("%s: %r is not an address" % (nid, address))
        if not re.fullmatch(r"m-[0-9a-f]{12}", str(node.get("pseudonym", ""))):
            problems.append("%s: no pseudonym of the log-safe shape" % nid)
    ids = [n.get("id") for n in doc.get("nodes", [])]
    if len(ids) != len(set(ids)):
        problems.append("a node id repeats")
    return problems


def check_netmap(netmap, identity):
    problems = []
    known = {n["id"] for n in identity["nodes"]}
    if netmap.get("self") not in known:
        problems.append("the netmap's self is not an identity")
    if len(netmap.get("peers", [])) > netmap.get("peer_cap", 0):
        problems.append("%d peers exceed the declared cap of %s" % (len(netmap["peers"]), netmap.get("peer_cap")))
    for peer in netmap.get("peers", []):
        if peer["id"] not in known:
            problems.append("peer %s is not an identity" % peer["id"])
    for case in netmap.get("filter_cases", []):
        got = filter_decision(netmap, case["src"], case["dst"], case["port"], case["proto"])
        if got != case["expect"]:
            problems.append("%s: the model decides %s, the hand-written expectation is %s" % (case["id"], got, case["expect"]))
    return problems


def check_derp(doc):
    problems = []
    for case in doc.get("route_cases", []):
        got = route_for(doc["regions"], case["home_derp"], case["direct_ok"])
        if got != case["expect"]:
            problems.append("%s: the model routes %s, the hand-written expectation is %s" % (case["id"], got, case["expect"]))
    for case in doc.get("no_region_cases", []):
        got = route_for(doc["regions"], case["home_derp"], case["direct_ok"], set(case["regions_reachable"]))
        if got != case["expect"]:
            problems.append("%s: the model routes %s, the hand-written expectation is %s" % (case["id"], got, case["expect"]))
    return problems


def check_key_expiry(doc):
    problems = []
    for step in doc.get("steps", []):
        got = key_step(doc["policy"], doc["key_expiry"], step["now"], step["clock_trusted"], step["control_up"], step["netmap_age_s"])
        if list(got) != step["expect"]:
            problems.append("%s: the model gives %r, the hand-written expectation is %r" % (step["id"], list(got), step["expect"]))
    return problems


def check_fixtures(identity, netmap, derp, expiry):
    return check_identity(identity) + check_netmap(netmap, identity) + check_derp(derp) + check_key_expiry(expiry)


# ---- probes over the pinned source trees (read as data) -----------------------------------------------------------------------------------

# Limits for a supplied source tree, documented in docs/contracts/t01.md section 7. The pinned trees measure: tailscale-rs 533 files / 5.8 MB (largest file 2.9 MB), aws-lc-sys 2029 files /
# 67 MB (largest 3.3 MB, deepest 8), mio 69 files / 0.5 MB. The caps are about 2.5x the largest, so a normal pinned tree passes and a runaway one is refused before any file is opened.
MAX_FILES = 5000
MAX_TOTAL_BYTES = 160 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 16
SCAN_SECONDS = 30.0
PROBE_SECONDS = 120.0


class SourceRefused(Exception):
    """A supplied source tree is outside the bounds or is not a plain tree of directories and regular files. The message never carries the supplied absolute path."""


def _shown(rel):
    return rel if len(rel) <= 100 else rel[:97] + "..."


def bounded_tree(root, max_files=MAX_FILES, max_bytes=MAX_TOTAL_BYTES, max_file_bytes=MAX_FILE_BYTES, max_depth=MAX_DEPTH, seconds=SCAN_SECONDS):
    """Walk a supplied tree with lstat only (no file is opened, so a FIFO or device cannot block it) and refuse: a symlink anywhere below the root, a file that is not regular, a file over the
    per-file cap, more than the file count or total byte cap, a tree deeper than the cap, and a walk that outlasts one absolute deadline. The root itself may be a symlink the operator
    supplied (it is resolved once). `.git` is skipped, as `tree_digest` skips it. Returns the sorted (relative path, size) list."""
    deadline = time.monotonic() + seconds
    try:
        real = os.path.realpath(root)
        if not stat.S_ISDIR(os.lstat(real).st_mode):
            raise SourceRefused("the supplied source is not a directory")
    except OSError as err:
        raise SourceRefused("the supplied source cannot be read (%s)" % type(err).__name__) from None
    found, total, stack = [], 0, [(real, "", 0)]
    while stack:
        directory, prefix, depth = stack.pop()
        if depth > max_depth:
            raise SourceRefused("the tree is deeper than %d levels at %s" % (max_depth, _shown(prefix)))
        entries = []
        try:
            with os.scandir(directory) as it:  # lazily: the count and the deadline are checked per entry, before anything is sorted
                for entry in it:
                    if time.monotonic() > deadline:
                        raise SourceRefused("the tree walk passed its %.0f s deadline" % seconds)
                    entries.append(entry)
                    if len(entries) > max_files:
                        raise SourceRefused("more than %d entries in %s" % (max_files, _shown(prefix or ".")))
            entries.sort(key=lambda e: e.name)
        except OSError as err:
            raise SourceRefused("a directory cannot be listed (%s) at %s" % (type(err).__name__, _shown(prefix or "."))) from None
        for entry in entries:
            if time.monotonic() > deadline:
                raise SourceRefused("the tree walk passed its %.0f s deadline" % seconds)
            if entry.name == ".git":
                continue
            rel = prefix + entry.name
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
                size = entry.stat(follow_symlinks=False).st_size
            except OSError as err:
                raise SourceRefused("%s cannot be examined (%s)" % (_shown(rel), type(err).__name__)) from None
            if stat.S_ISLNK(mode):
                raise SourceRefused("%s is a symlink" % _shown(rel))
            if stat.S_ISDIR(mode):
                stack.append((entry.path, rel + "/", depth + 1))
            elif stat.S_ISREG(mode):
                if size > max_file_bytes:
                    raise SourceRefused("%s is %d bytes, over the %d byte file cap" % (_shown(rel), size, max_file_bytes))
                found.append((rel, size))
                total += size
                if len(found) > max_files:
                    raise SourceRefused("more than %d files" % max_files)
                if total > max_bytes:
                    raise SourceRefused("more than %d bytes in total" % max_bytes)
            else:
                raise SourceRefused("%s is not a regular file" % _shown(rel))
    return sorted(found)


def _deadline_supported():
    return hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()


def with_deadline(seconds, fn):
    """Run fn() under one absolute deadline (SIGALRM, main thread only; raises TimeoutError). FAILS CLOSED: a deadline that has already passed raises TimeoutError, and where it cannot be
    enforced (no setitimer, or not the main thread) fn is not called at all and SourceRefused is raised, never an unbounded run."""
    if seconds <= 0:
        raise TimeoutError("the probe deadline had already passed")
    if not _deadline_supported():
        raise SourceRefused("a probe deadline cannot be enforced here (it needs SIGALRM in the main thread), so the probe is not run")

    def on_alarm(_signum, _frame):
        raise TimeoutError("the probe passed its %.0f s deadline" % seconds)

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


MAX_READ_BYTES = 2 * MAX_TOTAL_BYTES  # all reads through one Source together (a digest of the whole tree plus a few re-reads)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_ADMISSION_POSSIBLE = all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")) and os.open in os.supports_dir_fd


class Source:
    """A supplied source tree, admitted once and then read ONLY through this object. Admission is `bounded_tree` (lstat only, finite). Every read re-checks at the read boundary: the root is
    the same directory (device and inode), each path component is opened relative to its parent with O_NOFOLLOW (so a swapped symlink anywhere on the path fails), the final file is opened
    nonblocking and must be a regular file whose size is exactly the admitted size, the read stops at that size plus one byte (anything more is refused), and the total bytes read are
    finite. A file that was not admitted is `FileNotFoundError`. Nothing outside the manifest is ever opened, so a tree that changes after admission fails closed instead of being read."""

    def __init__(self, root, max_read=MAX_READ_BYTES, **limits):
        if not _ADMISSION_POSSIBLE:
            raise SourceRefused("this platform cannot open a supplied tree without following links, so it is refused")
        self.root = os.path.realpath(root)
        self.max_file_bytes = limits.get("max_file_bytes", MAX_FILE_BYTES)
        self.max_read = max_read
        self._files = dict(bounded_tree(self.root, **limits))
        info = os.stat(self.root)
        self._identity = (info.st_dev, info.st_ino)
        self.read_total = 0

    def files(self):
        return self._files

    def has(self, rel):
        return rel in self._files

    def members(self):
        """Directories directly under the root that hold a Cargo.toml (from the admitted manifest, not a fresh listing)."""
        return sorted({r.split("/")[0] for r in self._files if r.count("/") == 1 and r.endswith("/Cargo.toml")})

    def read(self, rel):
        size = self._files.get(rel)
        if size is None:
            raise FileNotFoundError(2, "not in the admitted tree", rel)
        if size > self.max_file_bytes or self.read_total + size > self.max_read:
            raise SourceRefused("reading %s would pass the %d byte read total" % (_shown(rel), self.max_read))
        fds = []
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | _O_CLOEXEC)
            fds.append(fd)
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._identity:
                raise SourceRefused("the supplied root is not the directory that was admitted")
            parts = rel.split("/")
            for part in parts[:-1]:
                fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | _O_CLOEXEC, dir_fd=fd)
                fds.append(fd)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _O_CLOEXEC, dir_fd=fd)
            fds.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SourceRefused("%s is not a regular file at read time" % _shown(rel))
            if info.st_size != size:
                raise SourceRefused("%s is %d bytes at read time, admitted as %d" % (_shown(rel), info.st_size, size))
            chunks, got = [], 0
            while True:
                chunk = os.read(fd, min(1 << 20, size + 1 - got))
                if not chunk:
                    break
                got += len(chunk)
                if got > size:
                    raise SourceRefused("%s grew past its admitted %d bytes while being read" % (_shown(rel), size))
                chunks.append(chunk)
            if got != size:
                raise SourceRefused("%s shrank while being read" % _shown(rel))
        except OSError as err:
            raise SourceRefused("%s cannot be read safely (%s)" % (_shown(rel), type(err).__name__)) from None
        finally:
            for open_fd in fds:
                try:
                    os.close(open_fd)
                except OSError:
                    pass
        self.read_total += got
        return b"".join(chunks)

    def text(self, rel, errors="strict"):
        """The file as text with universal newlines, as `open(path, encoding='utf-8')` returned it."""
        return self.read(rel).decode("utf-8", errors).replace("\r\n", "\n").replace("\r", "\n")

    def toml(self, rel):
        return tomllib.loads(self.read(rel).decode("utf-8"))


def _source(root):
    return root if isinstance(root, Source) else Source(root)


def _digest_key(rel):
    parts = rel.split("/")
    return tuple((1, p) for p in parts[:-1]) + ((0, parts[-1]),)


def tree_digest(root):
    """sha256 over every admitted file's relative path and content digest, in the order a top-down sorted walk gives (a directory's files, then its subdirectories): the same tree gives
    the same digest wherever it is extracted. Symlinks and non-regular files cannot be in a tree that was admitted. The bytes hashed are the bounded bytes `Source.read` returned."""
    src = _source(root)
    entries = ["%s\0%s\n" % (rel, sha256_bytes(src.read(rel))) for rel in sorted(src.files(), key=_digest_key)]
    return sha256_text("".join(entries))


def _normal_deps(root):
    """crate -> its declared NORMAL dependencies (dev- and build-dependencies excluded), including target-specific ones."""
    src = _source(root)
    out = {}
    manifests = {m: m + "/Cargo.toml" for m in src.members()}
    manifests["tailscale"] = "Cargo.toml"
    for name, rel in manifests.items():
        doc = src.toml(rel)
        deps = set(doc.get("dependencies", {}))
        for target in doc.get("target", {}).values():
            deps |= set(target.get("dependencies", {}))
        out[name] = deps
    return out


RUNTIME_OS_CRATES = frozenset({"tokio", "tokio-util", "tokio-stream", "tokio-rustls", "reqwest", "hyper", "hyper-util", "http-body-util", "rustls", "aws-lc-rs", "ring", "libc", "nix",
                               "netlink-sys", "tun-rs", "socket2", "windows-sys", "windows", "core-foundation", "system-configuration", "russh", "axum", "flume", "pyo3", "rustler", "futures"})
TOOLING_CRATES = frozenset({"checks", "ts_test_util"})


def probe_workspace_edges(root):
    """Which workspace crates reach a name on RUNTIME_OS_CRATES through the INTRA-WORKSPACE closure of their declared normal dependencies, and which do not. This looks at workspace crates
    and their direct third-party names only: it stops at every third-party package, so a crate listed here as having no such edge may still reach a platform crate through a third-party
    one (see `probe_third_party_reach`). It is not a portability or OS-free claim, and nothing was built for any target."""
    normal = _normal_deps(_source(root))
    none, edge = [], []
    for name in sorted(normal):
        if name in TOOLING_CRATES:
            continue
        seen, todo = set(), [name]
        while todo:
            x = todo.pop()
            if x not in seen:
                seen.add(x)
                todo.extend(d for d in normal.get(x, ()) if d in normal)
        hit = {d for x in seen for d in normal[x] if d in RUNTIME_OS_CRATES}
        (edge if hit else none).append(name)
    return {"no_runtime_edge_in_workspace": none, "runtime_edge_in_workspace": edge}


def probe_third_party_reach(root, crates):
    """For each named workspace crate, which names on RUNTIME_OS_CRATES its THIRD-PARTY closure reaches in the pinned Cargo.lock (declared normal and build edges, every target and feature:
    an over-approximation of any one configuration). The pinned counterexample to an OS-free reading: ts_tunnel -> rand -> getrandom -> libc."""
    src = _source(root)
    out = {}
    for name in crates:
        names = {e["name"] for e in core_import_manifest(src, crates=(name,))["registry"]}
        out[name] = sorted(names & RUNTIME_OS_CRATES)
    return out


def probe_tsrs(root):
    src = _source(root)
    lock = src.toml("Cargo.lock")
    deps, names = {}, set()
    for package in lock["package"]:
        names.add(package["name"])
        deps.setdefault(package["name"], set()).update(d.split(" ")[0] for d in package.get("dependencies", []))
    seen, todo = set(), ["tailscale"]
    while todo:
        x = todo.pop()
        if x not in seen:
            seen.add(x)
            todo.extend(deps.get(x, ()))
    manifest = src.toml("Cargo.toml")
    members = src.members()
    unsafe, forbid, lines = {}, 0, 0
    for crate in ["."] + members:
        prefix = "src/" if crate == "." else crate + "/src/"
        count, forbidden = 0, False
        for rel in sorted(r for r in src.files() if r.startswith(prefix) and r.endswith(".rs")):
            text = src.text(rel, errors="replace")
            lines += text.count("\n")
            count += len(re.findall(r"\bunsafe\b", text))
            forbidden = forbidden or "forbid(unsafe_code)" in text
        if count:
            unsafe["root" if crate == "." else crate] = count
        forbid += 1 if forbidden else 0
    readme = src.text("README.md")
    unsupported = readme.split("<summary>\nUnsupported features\n</summary>")[1].split("</details>")[0] if "<summary>\nUnsupported features\n</summary>" in readme else ""
    tls = next((l.strip() for l in src.text("ts_tls_util/Cargo.toml").split("\n") if l.startswith("tokio-rustls")), "")
    return {
        "tree_sha256": tree_digest(src), "lock_sha256": sha256_bytes(src.read("Cargo.lock")), "lock_packages": len(lock["package"]), "lock_distinct_names": len(names),
        "lock_closure_of_tailscale": len(seen), "lock_closure_ts_crates": len([n for n in seen if n.startswith("ts_")]),
        "workspace_members_declared": len(manifest["workspace"]["members"]), "member_dirs": len(members), "workspace_version": manifest["workspace"]["package"]["version"],
        "rust_version_manifest": manifest["workspace"]["package"]["rust-version"], "rust_lines_in_src": lines, "unsafe_tokens": unsafe, "forbid_unsafe_crates": forbid,
        "readme_msrv": (re.search(r"The current MSRV is ([0-9]+(?:\.[0-9]+)+)", readme) or [None, None])[1],
        "readme_platforms": sorted(m.group(0)[2:] for m in re.finditer(r"^- (?:Linux|macOS|Windows) \([^)]*\)", readme, re.M)),
        "readme_unsupported_items": sorted(re.findall(r"^ {4}- ([^\n]+)$", unsupported, re.M)),
        "tls_backend_line": tls,
    }


def probe_awslc(root):
    src = _source(root)
    lines = src.text("builder/cc_builder.rs").split("\n")
    start = next(i for i, l in enumerate(lines) if l == '    } else if target_arch() == "x86_64" {')
    arches = []
    for line in lines[start:]:
        if "target_specific_source_found = false;" in line:
            break
        found = re.search(r'target_arch\(\) == "([a-z0-9_]+)"', line)
        if found:
            arches.append(found.group(1))
    header = src.text("aws-lc/include/openssl/target.h")
    version = src.toml("Cargo.toml")["package"]["version"]
    cc = "\n".join(lines)
    return {"tree_sha256": tree_digest(src), "crate_version": version, "asm_source_sets": arches,
            "no_asm_refused_in_release": "AWS_LC_SYS_NO_ASM only allowed for debug builds!" in cc,
            "header_defines": {m: bool(re.search(r"^#\s*define\s+%s\b" % m, header, re.M)) for m in ("OPENSSL_PPC32BE", "OPENSSL_MIPS", "OPENSSL_PPC64BE", "OPENSSL_PPC64LE")}}


def probe_mio(root):
    src = _source(root)
    text = src.text("src/sys/unix/selector/epoll.rs")
    version = src.toml("Cargo.toml")["package"]["version"]
    return {"tree_sha256": tree_digest(src), "crate_version": version, "epoll_create1_calls": len(re.findall(r"epoll_create1\(", text)), "plain_epoll_create_calls": len(re.findall(r"(?<![A-Za-z_0-9])epoll_create\(", text))}


CORE_CRATES = ("ts_keys", "ts_noise", "ts_tunnel", "ts_control_serde", "ts_packetfilter_state", "ts_disco_protocol", "ts_overlay_router")
IMPORT_SCHEMA = "ffw.t01.import-manifest.v1"


def _declared(src, name):
    """The names a workspace crate declares as normal or build dependencies (dev-dependencies excluded: a path dependency's dev-dependencies are never resolved)."""
    doc = src.toml("Cargo.toml" if name == "tailscale" else name + "/Cargo.toml")
    names = set(doc.get("dependencies", {})) | set(doc.get("build-dependencies", {}))
    for target in doc.get("target", {}).values():
        names |= set(target.get("dependencies", {})) | set(target.get("build-dependencies", {}))
    return names


def core_import_manifest(root, crates=CORE_CRATES):
    """The registry packages (exact name, version, checksum from the pinned Cargo.lock) that a scratch consumer workspace depending on `crates` by path would resolve, for every target and
    feature (an over-approximation of any one configuration, never an under-approximation). Workspace edges come from the manifests' declared normal and build dependencies
    narrowed to the lock's own version-qualified edges; external edges are the lock's. Nothing is built, fetched or resolved by cargo."""
    src = _source(root)
    lock = src.toml("Cargo.lock")
    by_key = {(p["name"], p["version"]): p for p in lock["package"]}
    by_name = {}
    for p in lock["package"]:
        by_name.setdefault(p["name"], []).append(p)
    members = set(src.members())

    def edge(entry):
        name, _, version = entry.partition(" ")
        if not version:
            (only,) = by_name[name]
            version = only["version"]
        return name, version

    workspace, registry, todo = set(), set(), [(c, None) for c in crates]
    while todo:
        name, version = todo.pop()
        if name in members:
            if name in workspace:
                continue
            workspace.add(name)
            declared = _declared(src, name)
            todo.extend(edge(d) for d in by_name[name][0].get("dependencies", []) if d.split(" ")[0] in declared)
        else:
            if (name, version) in registry:
                continue
            package = by_key[(name, version)]
            if not str(package.get("source", "")).startswith("registry+"):
                raise ValueError("%s %s is not a registry package" % (name, version))
            registry.add((name, version))
            todo.extend(edge(d) for d in package.get("dependencies", []))
    entries = [{"name": n, "version": v, "checksum": by_key[(n, v)]["checksum"]} for n, v in sorted(registry)]
    return {"schema": IMPORT_SCHEMA, "crates": list(crates), "workspace_crates": sorted(workspace), "registry": entries,
            "counts": {"workspace_crates": len(workspace), "registry_packages": len(entries), "registry_names": len({e["name"] for e in entries})},
            "lock_sha256": sha256_bytes(src.read("Cargo.lock"))}


def check_probe(facts, expected, label):
    problems = []
    for key in sorted(set(facts) | set(expected)):
        if key not in expected:
            problems.append("%s: the probe reports %s, which the profile does not record" % (label, key))
        elif key not in facts:
            problems.append("%s: the profile records %s, which the probe did not report" % (label, key))
        elif facts[key] != expected[key]:
            problems.append("%s: %s is %r on the supplied source, the profile records %r" % (label, key, facts[key], expected[key]))
    return problems


# ---- X01: the captured, compile-only build records -----------------------------------------------------------------------------------------
#
# T01-X01 asks for TWO attempts on EACH legacy target (the contract, section 6): the check of the seven core crates ("core", `-p x01_core` in the consumer workspace) AND the same check of the
# whole library ("whole", `-p tailscale` in the pinned tailscale-rs workspace), the second "expected to stop at the first crate that does not build; the receipt names it". Each attempt is judged
# from the CAPTURED LOG of one real run, never from anyone's account of it; the case (run_cases.case_build) passes only when all four attempts BUILT, and a stop is kept and named, never hidden. The log has the shape the first real run produced (a PowerPC `cargo check` of the resolved
# consumer workspace through `rch exec --source-content-receipt`): a first line `COMMAND: <json argv>`, rch's own text, cargo's `--message-format=json` messages, cargo's `Finished` line,
# rch's `Remote command finished: exit=N` and its `[RCH] source content receipt: <json>` (the sha256 of every file it synced). The judge below reads those and nothing else. What a pass
# says is bounded by what the log can say: this exact cargo check command, on these exact inputs, compiled the seven core crates and their locked closure for this triple and finished
# with exit 0. It says nothing about linking, running, memory, CPU, enrollment or a native endpoint; those are other cases and other receipts.

MAX_LOG_BYTES = 8 * 1024 * 1024
X01_SCOPE = "compile-only"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ENV_ALLOWED = ("CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_HOME", "CARGO_BUILD_JOBS")
_RCH_CONFIG_KEYS = ("build.build-dir", "env.RCH_BUILD_SOURCE.value", "env.RCH_BUILD_SOURCE.force")
_REGISTRY_INDEX = "https://github.com/rust-lang/crates.io-index"
_PKG_ID = re.compile(r"^(?:path\+file://(?P<path>[^#]+)|registry\+(?P<index>[^#]*)|(?P<other>[a-z]+\+[^#]*))#(?:(?P<name>[A-Za-z0-9_.-]+)@)?(?P<version>[^@#]+)$")


def read_bounded_file(path, max_bytes=MAX_LOG_BYTES):
    """The bytes of ONE plain regular file. `lstat` first (a symlink, FIFO, device or directory, or a file over the cap, is refused without being opened), then the file is opened without
    following a link and without blocking, checked again (same device and inode, still regular), and read to the cap plus one byte. The message never carries the path."""
    name = _shown(os.path.basename(str(path)))
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise SourceRefused("%s is not a plain regular file (a link, FIFO, device or directory is refused)" % name)
    if before.st_size > max_bytes:
        raise SourceRefused("%s is %d bytes, over the %d byte cap" % (name, before.st_size, max_bytes))
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | _O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SourceRefused("%s changed between the check and the read" % name)
        chunks, total = [], 0
        while total <= max_bytes:
            chunk = os.read(fd, min(1 << 20, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > max_bytes:
        raise SourceRefused("%s grew past the %d byte cap while it was read" % (name, max_bytes))
    return b"".join(chunks)


def redact_build_log(text):
    """The committed form of a raw build log: terminal colors removed; worker addresses, the login name used to reach a worker, the local and the remote home directory replaced. Nothing the judge reads is touched (it reads
    the same facts from the raw and the redacted text)."""
    text = _ANSI.sub("", text)
    text = re.sub(r"/Users/[^/\s\"'<>]+", "<local>", text)
    text = re.sub(r"/home/[^/\s\"'<>]+", "<home>", text)
    text = SITE_PATTERNS[0].sub("<ip>", text)
    return re.sub(r"[\w.-]+@(?=<ip>)", "<user>@", text)


def site_hits(text):
    """Which kinds of site data (an IPv4 address, a personal home path, an e-mail-like token) a text still holds. Kinds only, never the matched text."""
    return [kind for kind, pattern in zip(("ipv4", "personal-path", "email-like"), SITE_PATTERNS) if pattern.search(text)]


def tree_digest_of_entries(entries):
    """`tree_digest` computed from a {relative path: sha256} map: the same digest, so a recorded file list can be held against the pin without the tree itself."""
    return sha256_text("".join("%s\0%s\n" % (rel, entries[rel]) for rel in sorted(entries, key=_digest_key)))


def _cargo_semantics(tokens, rch_rewrites):
    """What a cargo command line asks for, as data. Anything not recognised lands in `extra`, which a pinned command must leave empty."""
    sem = {"toolchain": None, "subcommand": None, "locked": False, "offline": False, "build_std": None, "jobs": None, "manifest": None, "target": None, "package": [],
           "message_format": None, "configs": [], "extra": []}
    i = 1
    while i < len(tokens):
        tok, nxt = tokens[i], (tokens[i + 1] if i + 1 < len(tokens) else None)
        if tok.startswith("+") and sem["toolchain"] is None and sem["subcommand"] is None:
            sem["toolchain"] = tok[1:]
        elif sem["subcommand"] is None and not tok.startswith("-"):
            sem["subcommand"] = tok
        elif tok == "--locked":
            sem["locked"] = True
        elif tok == "--offline":
            sem["offline"] = True
        elif tok == "-Z" and nxt is not None and nxt.startswith("build-std="):
            sem["build_std"] = nxt[len("build-std="):]
            i += 1
        elif re.fullmatch(r"-j\d+", tok):
            sem["jobs"] = tok[2:]
        elif tok == "--manifest-path" and nxt is not None:
            sem["manifest"] = nxt
            i += 1
        elif tok == "--target" and nxt is not None:
            sem["target"] = nxt
            i += 1
        elif tok == "-p" and nxt is not None:
            sem["package"].append(nxt)
            i += 1
        elif tok == "--message-format=json":
            sem["message_format"] = "json"
        elif rch_rewrites and tok == "--config" and nxt is not None and nxt.split("=", 1)[0] in _RCH_CONFIG_KEYS:
            i += 1
        elif tok == "--config" and nxt is not None:
            sem["configs"].append(nxt)
            i += 1
        elif rch_rewrites and tok == "--target-dir" and nxt is not None:
            i += 1
        else:
            sem["extra"].append(_shown(tok))
        i += 1
    return sem


def _check_semantics(sem, anchors, label):
    problems = []
    if sem["toolchain"] != anchors["toolchain"]:
        problems.append("%s: toolchain %r, the pinned toolchain is %r" % (label, sem["toolchain"], anchors["toolchain"]))
    if sem["subcommand"] != "check":
        problems.append("%s: subcommand %r, this gate is `cargo check` (compile only)" % (label, sem["subcommand"]))
    if not sem["locked"]:
        problems.append("%s: not run with --locked" % label)
    if sem["build_std"] != anchors["build_std"]:
        problems.append("%s: build-std %r, the pinned set is %r" % (label, sem["build_std"], anchors["build_std"]))
    if _attempt_kind(sem, anchors) is None:
        problems.append("%s: packages %r, the pinned selections are only %r" % (label, sem["package"], [a["package"] for a in anchors["attempts"].values()]))
    if sem["target"] not in anchors["targets"]:
        problems.append("%s: target %r is not one of the pinned legacy targets %r" % (label, sem["target"], anchors["targets"]))
    if sem["message_format"] != "json":
        problems.append("%s: not --message-format=json, so cargo's artifacts are not in the log" % label)
    if sem["extra"]:
        problems.append("%s: unexpected arguments %r" % (label, sem["extra"][:4]))
    problems += ["%s: %s" % (label, p) for p in _cc_config(sem, anchors, _attempt_kind(sem, anchors))[2]]
    return problems


def cc_forms(anchors):
    """Every C compiler configuration a command line may carry, as {wrapper: {form: sorted --config strings}}. Exactly three explicit cargo env keys (value, relative, force) for a pinned wrapper
    path, or the single inline-table spelling, which cargo REFUSES and which is therefore accepted only as a record of that refusal. Nothing else is a pinned C compiler configuration."""
    cc = anchors["cc_wrappers"]
    key = "env." + cc["env_key"]
    forms = {}
    for wrapper in cc["files"]:
        forms[wrapper] = {"keys": sorted(['%s.value="%s"' % (key, wrapper), "%s.relative=true" % key, "%s.force=true" % key]),
                          "inline": ['%s={value="%s",relative=true,force=true}' % (key, wrapper)]}
    return forms


def _cc_config(sem, anchors, kind):
    """(wrapper, form, problems) for the --config arguments of one command line: (None, None, []) when it carries none."""
    if not sem["configs"]:
        return None, None, []
    cc = anchors["cc_wrappers"]
    for wrapper, forms in cc_forms(anchors).items():
        for form, want in forms.items():
            if sorted(sem["configs"]) == want:
                problems = []
                if sem["target"] != cc["target"] or kind != cc["attempt"]:
                    problems.append("the C compiler configuration is pinned for the %s attempt on %s only" % (cc["attempt"], cc["target"]))
                return wrapper, form, problems
    return None, None, ["unexpected --config arguments %r: only the pinned C compiler wrapper table is accepted" % [_shown(c) for c in sem["configs"][:4]]]


def _attempt_kind(sem, anchors):
    """"core" or "whole": the pinned attempt whose package selection (and only that) this command line asks for."""
    kinds = [name for name, attempt in anchors["attempts"].items() if sem["package"] == [attempt["package"]]]
    return kinds[0] if len(kinds) == 1 else None


def _package_id(pid):
    match = _PKG_ID.match(pid) if isinstance(pid, str) else None
    if not match:
        return None
    path = match.group("path")
    name = match.group("name") or (os.path.basename(path.rstrip("/")) if path else None)
    return {"path": path, "index": match.group("index"), "other": match.group("other"), "name": name, "version": match.group("version")}


def check_x01_lock(lock_text, anchors):
    """The committed copy of the resolved consumer lock: the pinned digest, the counts a shell grep gave, only crates.io sources, and `x01_core` depends on exactly the seven core crates."""
    problems = []
    if sha256_text(lock_text) != anchors["consumer_files"]["Cargo.lock"]:
        problems.append("the consumer lock fixture is not the pinned resolved lock (sha256 differs)")
    try:
        lock = tomllib.loads(lock_text)
    except ValueError:
        return problems + ["the consumer lock fixture is not valid TOML"]
    packages = lock.get("package", [])
    registry = [p for p in packages if str(p.get("source", "")).startswith("registry+")]
    local = [p for p in packages if "source" not in p]
    if (len(packages), len(registry), len(local)) != (anchors["lock_packages"], anchors["lock_registry"], anchors["lock_path"]):
        problems.append("the lock has %d packages (%d registry, %d path), the independent grep gave %d / %d / %d" % (
            len(packages), len(registry), len(local), anchors["lock_packages"], anchors["lock_registry"], anchors["lock_path"]))
    if len(registry) + len(local) != len(packages):
        problems.append("the lock has a package whose source is neither crates.io nor a path")
    if any(p["source"] != "registry+" + _REGISTRY_INDEX for p in registry) or any("checksum" not in p for p in registry):
        problems.append("a locked registry package is not from the crates.io index or has no checksum")
    top = [p for p in packages if p["name"] == anchors["package"]]
    if len(top) != 1 or sorted(top[0].get("dependencies", [])) != sorted(anchors["core_crates"]):
        problems.append("%s does not depend on exactly the seven core crates in the lock" % anchors["package"])
    return problems


def judge_build_record(text, anchors, tree_pin, lock_text, redacted=False):
    """Judge one captured build log of ONE attempt: the seven-core-crate check ("core": `-p x01_core` in the consumer workspace) or the whole-library check ("whole": `-p tailscale` in the
    pinned tailscale-rs workspace), for one legacy target. Returns (problems, facts).

    `problems` are defects of the RECORD: it does not hold (a pin, the structure, a contradiction between the log's own witnesses). A build that STOPPED is not a defect of its record: it is the
    outcome, `facts["outcome"]` is "built" or "stopped", and a stop names where and why (`facts["stop"]`), classified only from text the log itself holds. A stop is never read as a built attempt, nor
    as an ISA or source finding unless its cause says so. `facts` carries what was established and never a runtime, memory, CPU or enrollment figure, because the log cannot hold one."""
    problems = []
    facts = {"scope": X01_SCOPE}
    lines = _ANSI.sub("", text).splitlines()
    try:
        lock = tomllib.loads(lock_text)
    except ValueError:
        return ["the consumer lock fixture cannot be read"], facts
    lock_registry = {(p["name"], p["version"]) for p in lock.get("package", []) if str(p.get("source", "")).startswith("registry+")}
    lock_local = {(p["name"], p["version"]) for p in lock.get("package", []) if "source" not in p}
    std_registry = {tuple(item.split(" ", 1)) for item in anchors["std_registry"]}
    attempts = anchors["attempts"]

    # 1. the command, as the capture wrapper wrote it, and as rch executed it
    argv = None
    if lines and lines[0].startswith("COMMAND: "):
        try:
            argv = json.loads(lines[0][len("COMMAND: "):])
        except ValueError:
            argv = None
        if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
            argv = None
    argv_sem, worker = None, None
    if argv is None:
        problems.append("the first line is not a `COMMAND: <json argv>` line")
    elif argv[:2] != ["rch", "exec"] or "--" not in argv or argv[argv.index("--") + 1:argv.index("--") + 2] != ["cargo"]:
        problems.append("the command is not `rch exec ... -- cargo ...`")
    else:
        cut = argv.index("--")
        opts, i = argv[2:cut], 0
        while i < len(opts):
            if opts[i] == "--source-content-receipt":
                i += 1
            elif opts[i] == "--worker" and i + 1 < len(opts):
                worker, i = opts[i + 1], i + 2
            else:
                problems.append("unexpected rch option %r" % _shown(opts[i]))
                i += 1
        argv_sem = _cargo_semantics(argv[cut + 1:], False)
        problems += _check_semantics(argv_sem, anchors, "command")
    kind = _attempt_kind(argv_sem, anchors) if argv_sem else None
    target = argv_sem["target"] if argv_sem else None
    cc_wrapper, cc_form, _ = _cc_config(argv_sem, anchors, kind) if argv_sem else (None, None, [])
    facts.update({"target": target, "attempt": kind, "cc": ({"wrapper": cc_wrapper, "sha256": anchors["cc_wrappers"]["files"][cc_wrapper]["sha256"], "form": cc_form} if cc_wrapper else None)})
    if kind and argv_sem["manifest"] != attempts[kind]["manifest"]:
        problems.append("command: manifest %r, the %s attempt runs %r" % (argv_sem["manifest"], kind, attempts[kind]["manifest"]))
    remotes = [line.split("Executing command remotely: ", 1)[1] for line in lines if "Executing command remotely: " in line]
    remote_sem = None
    if len(remotes) != 1:
        problems.append("expected one 'Executing command remotely' line, found %d" % len(remotes))
    else:
        try:
            words = shlex.split(remotes[0])
        except ValueError:
            words = []
            problems.append("the remote command line does not split into words (truncated?)")
        else:
            if not words:                  # an empty or blank command splits into no words at all: nothing would be checked, so it is a defect and never a pass
                problems.append("the remote command line is empty: no cargo invocation was recorded")
        j = 1 if words[:1] == ["env"] else 0
        while j < len(words) and re.fullmatch(r"[A-Z_][A-Z0-9_]*=.*", words[j]):
            if words[j].split("=", 1)[0] not in _ENV_ALLOWED:
                problems.append("the remote command sets %s, which changes the build" % words[j].split("=", 1)[0])
            j += 1
        if words and words[j:j + 1] != ["cargo"]:
            problems.append("the remote command is not a cargo invocation")
        elif words:
            remote_sem = _cargo_semantics(words[j:], True)
            problems += _check_semantics(remote_sem, anchors, "remote command")
    if argv_sem and remote_sem:
        for key in ("toolchain", "subcommand", "locked", "offline", "build_std", "jobs", "target", "package", "message_format", "configs"):
            if argv_sem[key] != remote_sem[key]:
                problems.append("the command and the remote command disagree on %s (%r vs %r)" % (key, argv_sem[key], remote_sem[key]))

    # 2. what rch says it synced, and the pins it is held against
    receipts = [line for line in lines if line.startswith("[RCH] source content receipt:")]
    root, remote_root, receipt = None, None, None
    if len(receipts) != 1:
        problems.append("expected one rch source content receipt, found %d" % len(receipts))
    else:
        try:
            receipt = json.loads(receipts[0].split(":", 1)[1].strip())
        except ValueError:
            problems.append("the rch source content receipt is not valid JSON (truncated?)")
    if isinstance(receipt, dict):
        roots = receipt.get("roots")
        if receipt.get("schema") != "rch.source_content_receipt.v1" or receipt.get("root_count") != 1 or not isinstance(roots, list) or len(roots) != 1:
            problems.append("the rch source content receipt is not one root of schema rch.source_content_receipt.v1")
        else:
            root = roots[0]
        if worker is not None and receipt.get("worker_id") != worker:
            problems.append("the receipt's worker differs from the worker the command asked for")
        facts["worker"] = receipt.get("worker_id")
    entries = {}
    if isinstance(root, dict):
        files = root.get("files")
        remote_root = root.get("remote_root")
        if not isinstance(files, list) or not isinstance(remote_root, str) or not remote_root.startswith("/"):
            problems.append("the receipt's root has no file list or no remote root")
        else:
            for entry in files:
                path, digest = (entry.get("path"), entry.get("sha256")) if isinstance(entry, dict) else (None, None)
                if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or path.startswith("/") or ".." in path.split("/"):
                    problems.append("the receipt lists a malformed file entry")
                elif path in entries:
                    problems.append("the receipt lists %s twice" % _shown(path))
                else:
                    entries[path] = digest
            if root.get("file_count") != len(files) or root.get("byte_count") != sum(e.get("byte_count", 0) for e in files if isinstance(e, dict)):
                problems.append("the receipt's file_count or byte_count does not match its own file list")
        if root.get("mode") != "full" or root.get("is_primary") is not True:
            problems.append("the synced root is not the full primary root")
    if remote_sem and kind and remote_root and remote_sem["manifest"] != "%s/%s" % (remote_root, attempts[kind]["manifest"]):
        problems.append("remote command: the manifest is not the synced root's %s" % attempts[kind]["manifest"])
    for rel, want in anchors["consumer_files"].items():
        if entries and entries.get(rel) != want:
            problems.append("synced %s is not the pinned consumer file (stale or changed)" % rel)
    pinned_cc = anchors["cc_wrappers"]["files"]
    if entries:
        stray = sorted(p for p in entries if p.startswith("x01-cc/") and p not in pinned_cc)
        if stray:
            problems.append("the synced root holds files under x01-cc/ that are not pinned C compiler wrappers: %s" % ", ".join(_shown(p) for p in stray[:3]))
        for path, info in pinned_cc.items():
            if path in entries and entries[path] != info["sha256"]:
                problems.append("synced %s is not the pinned wrapper (sha256 %s, pinned %s)" % (path, entries[path][:12], info["sha256"][:12]))
        if cc_wrapper and cc_wrapper not in entries:
            problems.append("the wrapper %s the command configures is not among the synced files" % cc_wrapper)
    if entries:
        under = sorted(p for p in entries if p.startswith("x01_core/"))
        if under != ["x01_core/Cargo.toml", "x01_core/src/lib.rs"]:
            problems.append("the consumer package holds files beyond its manifest and src/lib.rs")
        if any(p == "rust-toolchain" or p == "rust-toolchain.toml" or p.startswith(".cargo/") or p in ("build.rs", "config.toml") for p in entries):
            problems.append("the synced root holds a cargo config, toolchain override or build script that can change the build")
        pinned = {p[len("tailscale-rs/"):]: d for p, d in entries.items() if p.startswith("tailscale-rs/")}
        tree = tree_digest_of_entries(pinned)
        facts.update({"source_files": len(entries), "tree_sha256": tree, "lock_sha256": entries.get("Cargo.lock")})
        if tree != tree_pin:
            problems.append("the synced tailscale-rs tree digest %s is not the pinned %s" % (tree[:12], tree_pin[:12]))

    # 3. cargo's own messages and the terminal result: three witnesses (cargo, rch, the receipt) that must agree
    messages = []
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except ValueError:
                problems.append("line %d looks like a cargo message but is not valid JSON (truncated?)" % number)
                continue
            if isinstance(doc, dict) and isinstance(doc.get("reason"), str):
                messages.append(doc)
    finished = [i for i, m in enumerate(messages) if m["reason"] == "build-finished"]
    refused = not messages                 # cargo refused to start (a rejected --config, say): there is no cargo message at all, and then only a consistent refusal is a record
    last_ok = len(finished) == 1 and finished[0] == len(messages) - 1
    if not last_ok and not refused:
        problems.append("cargo's build-finished message is missing, repeated or not last")
    success = messages[finished[0]].get("success") if last_ok else None
    exits = [m.group(1) for m in (re.search(r"Remote command finished: exit=(-?\d+)", line) for line in lines) if m]
    if len(exits) != 1:
        problems.append("rch's remote command exit is %s, expected exactly one exit line" % (exits or "absent"))
    rch_exit = int(exits[0]) if len(exits) == 1 else None
    receipt_exit = receipt.get("command_exit_code") if isinstance(receipt, dict) else None
    finished_lines = len([line for line in lines if re.match(r"\s*Finished `", line)])
    compiler_error = any(m["reason"] == "compiler-message" and str(m.get("message", {}).get("level", "")).startswith("error") for m in messages)
    error_line = any(re.match(r"\s*error(\[E\d+\])?:", line) for line in lines)
    outcome = None
    if refused:
        if rch_exit not in (None, 0) and receipt_exit == rch_exit and finished_lines == 0 and error_line:
            outcome = "stopped"
        elif rch_exit is not None and not any("terminal results" in p for p in problems):
            problems.append("the log holds no cargo message and is not a consistent refusal: rch exit %r, receipt exit %r, %d Finished line(s), error line %s" % (rch_exit, receipt_exit, finished_lines, error_line))
    elif last_ok and rch_exit is not None and isinstance(receipt_exit, int):
        if success is True and rch_exit == 0 and receipt_exit == 0 and finished_lines == 1 and not compiler_error and not error_line:
            outcome = "built"
        elif success is False and rch_exit != 0 and receipt_exit == rch_exit and finished_lines == 0:
            outcome = "stopped"
        else:
            problems.append("the terminal results disagree: build-finished success=%r, rch exit %r, receipt exit %r, %d Finished line(s), compiler error %s, error line %s"
                            % (success, rch_exit, receipt_exit, finished_lines, compiler_error, error_line))
    elif last_ok and rch_exit is not None:
        problems.append("the receipt records no command_exit_code")
    if outcome == "built" and cc_form == "inline":
        problems.append("the inline-table C compiler configuration is refused by cargo, so a log that claims to have built with it does not hold")
    facts["outcome"] = outcome
    if outcome == "stopped":
        body = "\n".join(lines)
        script = re.findall(r"^error: failed to run custom build command for `([^`]+)`", body, re.M)
        unit = re.findall(r"^error: could not compile `([^`]+)`", body, re.M)
        tools = sorted(set(re.findall(r'error occurred in cc-rs: failed to find tool "([^"]+)"', body)))
        refused_arg = re.findall(r"^\s*error: --config argument `([^`]+)` sets a value to an inline table, which is not accepted", body, re.M)
        spelled = sorted(set(re.findall(r"unable to parse target query '([^']+)'", body)))
        stop = {"package": (script or unit or [None])[0], "exit": rch_exit, "class": "unclassified", "tool": None, "detail": None}
        if refused and refused_arg and argv_sem and refused_arg[0] in argv_sem["configs"]:     # cargo refused a --config argument this very command carried
            stop.update({"class": "cargo-config-rejected", "detail": refused_arg[0]})
        elif script and "error occurred in cc-rs: command did not execute successfully" in body and target and spelled == [target]:      # the configured C compiler ran and refused the target spelling
            stop.update({"class": "c-compiler-rejected-target", "detail": target})
        elif script and len(tools) == 1:               # a build script failed because cc-rs could not find the target's C compiler, and the log names that one tool
            stop.update({"class": "missing-c-toolchain", "tool": tools[0]})
        facts["stop"] = stop

    # 4. what was compiled
    artifacts = [m for m in messages if m["reason"] == "compiler-artifact"]
    if outcome == "built" and not artifacts:
        problems.append("no compiler-artifact message: nothing was compiled")
    tc = anchors["toolchain"]
    found = {"registry": set(), "tailscale_rs": set(), "x01": False, "std": {}}
    libs = set()
    for art in artifacts:
        pid = _package_id(art.get("package_id"))
        kinds = (art.get("target") or {}).get("kind") or []
        raw_names = art.get("filenames")
        names_ok = isinstance(raw_names, list) and all(isinstance(f, str) for f in raw_names)
        names = raw_names if names_ok else []
        if pid is None:
            problems.append("an artifact has an unreadable package id")
            continue
        label = "%s %s" % (pid["name"], pid["version"])
        if not names_ok:
            problems.append("%s has no readable filenames list (missing, not a list, or not all strings)" % label)
        for_target = False
        host = any(k in kinds for k in ("custom-build", "proc-macro"))
        if pid["index"] is not None:
            if pid["index"] != _REGISTRY_INDEX:
                problems.append("%s comes from a registry other than crates.io" % label)
            elif kind != "whole" and (pid["name"], pid["version"]) not in lock_registry and (pid["name"], pid["version"]) not in std_registry:
                problems.append("%s is neither in the locked closure nor one of the toolchain's own build-std crates" % label)
            found["registry"].add((pid["name"], pid["version"]))
        elif pid["other"] is not None:
            problems.append("%s comes from a %s source" % (label, pid["other"].split("+")[0]))
        else:
            path = pid["path"]
            # An artifact counts toward a REQUIRED crate only with a witness: at least one output file name, and every one of them under the selected target's directory. Without it (an empty or
            # unreadable filenames list) nothing ties the artifact to the target, so a record could be promoted to another target by emptying its file names.
            witness = bool(target) and bool(names) and all("/%s/debug/" % target in name for name in names)
            if kind != "whole" and remote_root and path == remote_root + "/x01_core":
                found["x01"] = found["x01"] or witness
                for_target = True
            elif remote_root and kind == "whole" and (path == remote_root + "/tailscale-rs" or path.startswith(remote_root + "/tailscale-rs/")):
                if pid["version"] != anchors["tailscale_rs_version"]:
                    problems.append("%s is not at the pinned tailscale-rs version" % label)
                found["tailscale_rs"].add(pid["name"])
                for_target = True
                if "lib" in kinds and witness:
                    libs.add(pid["name"])
            elif remote_root and kind != "whole" and path == "%s/tailscale-rs/%s" % (remote_root, pid["name"]):
                if (pid["name"], pid["version"]) not in lock_local or pid["version"] != anchors["tailscale_rs_version"]:
                    problems.append("%s is not the locked tailscale-rs crate" % label)
                found["tailscale_rs"].add(pid["name"])
                for_target = True
                if "lib" in kinds and witness:
                    libs.add(pid["name"])
            elif re.search(r"/toolchains/%s-[A-Za-z0-9_.-]+/lib/rustlib/src/rust/library/" % re.escape(tc), path):
                if witness:
                    found["std"][pid["name"]] = pid["version"]
                for_target = True
            else:
                problems.append("%s is built from a path outside the synced tree and the pinned toolchain" % label)
        for name in names:
            others = [t for t in anchors["targets"] if t != target and "/%s/" % t in name]
            if others:
                problems.append("%s has an artifact under the other legacy target %s" % (label, others[0]))
            elif target and for_target and not host and "/%s/debug/" % target not in name:
                problems.append("%s has an artifact outside the %s directory" % (label, target))
    if outcome == "built" and kind:
        need = list(anchors["core_crates"]) + (["tailscale"] if kind == "whole" else [])
        witnessed = "with an output file under the %s directory" % target
        for crate in need:
            if crate not in libs:
                problems.append("%s has no compiled library artifact %s" % (crate, witnessed))
        if kind == "core" and not found["x01"]:
            problems.append("%s itself was not compiled (no artifact %s)" % (attempts["core"]["package"], witnessed))
        for std in anchors["std_crates"]:
            if std not in found["std"]:
                problems.append("build-std did not compile %s (no artifact %s)" % (std, witnessed))
        for name, version in anchors["std_fingerprint"].items():
            if found["std"].get(name) != version:
                problems.append("the toolchain's standard library source has %s %s, the pinned toolchain has %s" % (name, found["std"].get(name), version))
    if redacted and site_hits(text):
        problems.append("a committed record still holds site data (%s): redact the raw log" % ", ".join(site_hits(text)))
    facts.update({"toolchain": tc, "artifacts": len(artifacts), "registry_packages": len(found["registry"]), "tailscale_rs_packages": len(found["tailscale_rs"]),
                  "std_packages": len(found["std"]), "core_crates_compiled": len(libs & set(anchors["core_crates"]))})
    return problems, facts
