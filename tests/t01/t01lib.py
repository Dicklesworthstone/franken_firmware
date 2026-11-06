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


def check_profile(profile, ledger):
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
            if item.get("state") not in ("measured", "pending", "observed_not_a_footprint", "not_applicable"):
                problems.append("measurement %s/%s: state %r" % (mid, name, item.get("state")))
            if item.get("state") in ("pending", "not_applicable") and not item.get("blocker"):
                problems.append("measurement %s/%s is %s without its reason" % (mid, name, item["state"]))
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
