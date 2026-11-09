#!/usr/bin/env python3
"""T01 tiered runner and bounded diagnostic receipt (bead ffw-32a): native Tailscale protocol and resource feasibility, offline.

    run_cases.py [--tier smoke|full|soak] [--sources DIR] [--receipts DIR] [--build-log LOG ...] [--list]
    run_cases.py --redact-build-log RAW DEST

Offline, standard library only; it builds nothing, boots nothing, contacts nothing and never invokes cargo (it READS the captured log of a build somebody else ran). It judges the study's own artifacts: the evidence ledger, the frozen profile
(docs/tailscale/profiles.json), the synthetic fixtures, and the rules that turn them into a matrix. It measures no target: a resource figure is `pending` until a receipt from a run on
the target exists, and no such run is possible locally.

Tiers (explicit):

  smoke  the ledger and the profile hold; the classification, cell and budget rules equal the tables written by hand in cases.json; the matrix is complete and has no `supported`
         cell; the synthetic identity, network-map, relay and key-expiry fixtures equal the model; the native requirement is still required; with X02 blocked and nothing linked or run the study is incomplete and closes nothing.
  full   smoke, and the source probes: with ``--sources DIR`` (subdirectories `tailscale-rs`, `aws-lc-sys`, `mio`: the pinned trees, extracted) they recompute the census recorded in
         the profile and re-check every ledger excerpt against the file it was cut from. Without ``--sources`` those cases are BLOCKED. T01-X01 judges the captured build logs
         under toolchain/results/tailscale/builds/ (and any ``--build-log LOG``): the contract's TWO COMPILE-ONLY ``cargo check`` attempts on EACH legacy target, the seven core crates and
         the whole library, held against pinned inputs. It PASSES only when all four attempts built; otherwise it is BLOCKED with every attempt accounted for (built, stopped at a named
         crate with its classified cause, or not recorded), and FAILED by any record that does not hold. A stop is kept and named, never read as a pass nor as an ISA finding it does not
         show. T01-X02 (on-target memory and CPU) is BLOCKED until a measurement receipt exists, and judges the receipts under toolchain/results/tailscale/measurements/ that ``scripts/e2e/t01 --x02`` writes: it
         PASSES only when EACH legacy target has a captured guest run (never a supplied transcript analysis) with every phase ok, no UNKNOWN reading and the ELF, kernel and initramfs hashes; a malformed or
         other-schema receipt, or a captured run that did not pass, FAILS by name. A compile record never satisfies it, nor a runtime, enrollment or native-endpoint claim; a pass is harness-guest figures only.
  soak   selectable, says why nothing runs, exits 4. It is never a pass.

Every decided case writes a CRITICAL begin and end event through the shared Q00 sink (``case_log.py``); a run whose log lost critical evidence is NOT QUALIFIED. A run that is not a pass
prints RETAINED FOR REPLAY: the first failure or block, the replay command and the sha256 of every artifact judged. ``--receipts DIR`` also writes a JSON receipt next to the JSONL log.

Exit codes: 0 every case passed and the diagnostic log is complete; 1 a case failed or the log lost critical evidence; 3 the only non-passes are blocked cases; 4 ``--tier soak``; 2 usage.

What a pass is not. A pass of this runner says the study is internally consistent and its pinned excerpts are what they were; it does not say any candidate runs on any target, that
the native requirement is met, or that T02, T04 or Q06 may proceed. The two cases that could say something about a target are the two that stay blocked.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import secrets
import sys
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import t01lib as L  # noqa: E402
import x02_judge as X  # noqa: E402  (judges the X02 guest-run receipts; stdlib only, the P05 guest layer is loaded lazily by its own commands)

TIERS = ("smoke", "full", "soak")
RUN_TIERS = ("smoke", "full")
SOAK_EXIT = 4
SOAK_NOT_RUN = (
    "T01 soak: NOT RUN. T01 is a feasibility study over pinned sources and synthetic fixtures: it owns no long-running test, and the long-running questions (a 24-hour campaign, key rotation "
    "while audio runs, relay traffic) need a candidate that builds and runs on the target, which does not exist yet. Nothing here soaks. This is not a pass.")
RECEIPT_SCHEMA = "ffw.t01.receipt.v1"
MAX_PRINTED = 12
CONTRACT = "docs/contracts/t01.md"
CONTRACT_PHRASES = (
    "A negative result closes the investigation only",
    "No Go reference client or gateway counts as a strict-Rust native implementation",
    "The native requirement stays required",
    "absent budget is pending, not pass",
    "T04 is provisional development admission",
)
JUDGED_ARTIFACTS = ("tests/t01/run_cases.py", "tests/t01/x02_judge.py", "tests/t01/t01lib.py","tests/t01/case_log.py", "tests/t01/cases.json", "docs/tailscale/profiles.json", "docs/tailscale/feasibility.md", CONTRACT,
                    "tests/tailscale-fixtures/evidence/ledger.json", "tests/tailscale-fixtures/synthetic/identity.json", "tests/tailscale-fixtures/synthetic/netmap.json",
                    "tests/tailscale-fixtures/synthetic/derp_map.json", "tests/tailscale-fixtures/synthetic/key_expiry.json", "tests/tailscale-fixtures/x01/consumer.lock", "tests/tailscale-fixtures/x01/x01-cc/zig-cc-mips-be-ccrs",
                    "tests/tailscale-fixtures/x01/x01-cc/zig-cc-mips-be-ccrs-v2", "scripts/test/test_support/diagnostics.py")
BUILD_DIR = ("toolchain", "results", "tailscale", "builds")
SOURCE_DIRS = {"tailscale-rs": "tailscale/tailscale-rs", "aws-lc-sys": "crates.io/aws-lc-sys", "mio": "crates.io/mio"}

# The central lines that give the legacy-ISA COMPILE evidence (case T01-X01), in the form the first real runs used. They are root's, on its strict-remote lane, from the resolved consumer
# workspace (the pinned tailscale-rs tree, x01_core, and the resolved lock tests/tailscale-fixtures/x01/consumer.lock); the capture wrapper writes `COMMAND: <json argv>` as the first line and
# then rch's stdout and stderr. The log is the record; nothing here runs them.
CENTRAL_LINES = (
    "# from the consumer workspace (cwd), one run per target:",
    "rch exec --source-content-receipt --worker <W> -- cargo +nightly-2026-08-31 check --locked -Z build-std=core,alloc,std,panic_abort -j1 --manifest-path Cargo.toml "
    "--target {triple} -p x01_core --message-format=json",
    "# the same check of the whole library, in the pinned tailscale-rs workspace (its own lock), from the same synced root:",
    "rch exec --source-content-receipt --worker <W> -- cargo +nightly-2026-08-31 check --locked -Z build-std=core,alloc,std,panic_abort -j1 --manifest-path tailscale-rs/Cargo.toml "
    "--target {triple} -p tailscale --message-format=json",
    "# MIPS whole library only: aws-lc-sys needs a C compiler for the target, which the workers lack, so root syncs the pinned wrapper files under x01-cc/ and sets CC through exactly three explicit "
    "cargo env keys (one --config argument each): env.CC_mips_unknown_linux_musl.value=\"x01-cc/zig-cc-mips-be-ccrs-v2\", env.CC_mips_unknown_linux_musl.relative=true, "
    "env.CC_mips_unknown_linux_musl.force=true. The one-argument inline-table spelling is refused by cargo.",
    "# {triple} in powerpc-unknown-linux-musl, mips-unknown-linux-musl: four attempts, each captured. x01_core depends on the seven core crates only. The whole-library attempt may stop at the "
    "first crate that does not build (the log names it); a stop is recorded, classified from its own text, and does not complete T01-X01. Neither is a link or a run.",
)
MEASUREMENT_BLOCKER = ("no on-target figure is possible: there is no 2.6.14 PowerPC or 2.6.35 MIPS full-system guest (E03), and a harness-guest run (Debian 4.9 / 4.19) is indicative only and has not been run")


def safe_detail(text: str) -> str:
    """Use the existing Q00 policy before any human or receipt output, not only the JSONL log."""
    try:
        return load_case_log().load(REPO).redact_text(text)
    except Exception:  # noqa: BLE001
        return "Diagnostic detail withheld: redaction is unavailable."


class Result:
    def __init__(self, case_id: str, status: str, detail: str = "", group: str = ""):
        self.case_id, self.status, self.detail, self.group = case_id, status, safe_detail(detail) if detail else "", group

    def as_dict(self) -> dict:
        return {"case": self.case_id, "status": self.status, "detail": self.detail, "group": self.group}


def judged(case_id: str, group: str, problems: List[str]) -> Result:
    return Result(case_id, "failed" if problems else "passed", "; ".join(problems[:3]) + (" (+%d more)" % (len(problems) - 3) if len(problems) > 3 else ""), group)


def blocked(case_id: str, group: str, reason: str) -> Result:
    return Result(case_id, "blocked", reason, group)


# ---- the files the study is made of -------------------------------------------------------------------------------------------------------

def inputs(repo: str = REPO) -> Dict[str, Any]:
    fx = os.path.join(repo, "tests", "tailscale-fixtures", "synthetic")
    return {"profile": L.load_json(os.path.join(repo, "docs", "tailscale", "profiles.json")), "ledger": L.load_json(os.path.join(repo, "tests", "tailscale-fixtures", "evidence", "ledger.json")),
            "cases": L.load_json(os.path.join(repo, "tests", "t01", "cases.json")),
            "fixtures": [L.load_json(os.path.join(fx, name)) for name in ("identity.json", "netmap.json", "derp_map.json", "key_expiry.json")]}


# ---- smoke cases ----------------------------------------------------------------------------------------------------------------------------------

def case_ledger(data: Dict[str, Any], repo: str) -> Result:
    return judged("T01-META-LEDGER", "meta", L.check_ledger(data["ledger"], repo))


def case_profile(data: Dict[str, Any], repo: str) -> Result:
    return judged("T01-META-PROFILE", "meta", L.check_profile(data["profile"], data["ledger"], repo))


def case_classification(data: Dict[str, Any], repo: str) -> Result:
    problems = []
    for row in data["cases"]["classification"]:
        try:
            got = L.classify(row["facts"])
        except ValueError:
            got = "unclassifiable"
        if got != row["expect"]:
            problems.append("%s: classified %s, the hand-written expectation is %s" % (row["id"], got, row["expect"]))
    for cid, cand in data["profile"]["candidates"].items():
        if cand["class"] != L.classify(cand["facts"]):
            problems.append("%s: declared %s, derived %s" % (cid, cand["class"], L.classify(cand["facts"])))
    return judged("T01-C01-classification", "rules", problems)


def case_cell_rules(data: Dict[str, Any], repo: str) -> Result:
    table = data["cases"]["cell_rules"]
    problems = []
    for row in table["rows"]:
        got = [L.derive_cell(row["behavior"], platform_state, row["extensible"]) for platform_state in table["platforms"]]
        if got != row["expect"]:
            problems.append("behavior %s, extensible %s: %r, the hand-written expectation is %r" % (row["behavior"], row["extensible"], got, row["expect"]))
    return judged("T01-C02-cell-rules", "rules", problems)


def case_matrix(data: Dict[str, Any], repo: str) -> Result:
    profile = data["profile"]
    cells = L.matrix(profile)
    want = len(profile["candidates"]) * len(profile["targets"]) * len(profile["behaviors"])
    problems = []
    if len(cells) != want:
        problems.append("the matrix has %d cells, %d expected" % (len(cells), want))
    if any(v not in L.CELL_STATES for v in cells.values()):
        problems.append("a cell has a state outside %r" % (L.CELL_STATES,))
    if any(v == "supported" for v in cells.values()):
        problems.append("a cell is supported, which needs a run on the target")
    native = [cid for cid, c in profile["candidates"].items() if c["class"] == "native_strict_rust"]
    if native != ["tailscale-rs-0.6.1"]:
        problems.append("the strict-Rust native class holds %r" % native)
    return judged("T01-C03-matrix", "rules", problems)


def case_budget(data: Dict[str, Any], repo: str) -> Result:
    table = data["cases"]["budget_rules"]
    problems = []
    for row in table["rows"]:
        got = L.budget_verdict(row["measured"], row["cap"], table["reserve_floor_bytes"], row["reserve"])
        if got != row["expect"]:
            problems.append("%s: %s, the hand-written expectation is %s" % (row["id"], got, row["expect"]))
    profile = data["profile"]
    floor = profile["budgets"]["reserve_floor_bytes"]
    for key, m in profile["measurements"].items():
        verdict = L.budget_verdict(None, profile["budgets"]["tailnet_ram_cap_bytes"][key.split("/")[1]], floor, floor)
        if not verdict.startswith("pending"):
            problems.append("%s: the recorded state gives %s, but nothing is measured and no budget is allocated, so it must be pending" % (key, verdict))
    return judged("T01-C04-budget-rules", "rules", problems)


def case_fixtures(data: Dict[str, Any], repo: str) -> Result:
    return judged("T01-C05-fixtures", "fixtures", L.check_fixtures(*data["fixtures"]))


def case_native_requirement(data: Dict[str, Any], repo: str) -> Result:
    problems = []
    nr = data["profile"]["native_requirement"]
    if nr["status"] != "required" or nr["waived"] is not False or nr["satisfied_by"]:
        problems.append("the native requirement is not 'required, unwaived, unsatisfied'")
    for later in ("T02", "T04", "Q06"):
        if later not in nr["does_not_close"]:
            problems.append("the study does not say it leaves %s open" % later)
    try:
        with open(os.path.join(repo, CONTRACT), encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        text = ""
        problems.append("%s cannot be read" % CONTRACT)
    for phrase in CONTRACT_PHRASES:
        if text and phrase not in text:
            problems.append("%s lacks the statement %r" % (CONTRACT, phrase))
    derived = data["profile"]["derived_facts"]
    figures = [str(derived["tailscale-rs-0.6.1"][k]) for k in ("lock_packages", "lock_distinct_names", "lock_closure_of_tailscale")] + ["36,700,859"] + derived["aws-lc-sys-0.45.0"]["asm_source_sets"]
    for figure in figures:
        if text and figure not in text:
            problems.append("%s does not state the figure %s that the profile records" % (CONTRACT, figure))
    for cid, cand in data["profile"]["candidates"].items():
        if cand["class"] in ("gateway", "wrapper", "official_reference", "wireguard_only") and cand["counts_as_native"]:
            problems.append("%s (%s) counts as native" % (cid, cand["class"]))
    return judged("T01-C06-native-requirement", "contract", problems)


# ---- full-tier cases: source probes and the cases that need a central build -----------------------------------------------------------------------

def failure_detail(err: BaseException, sources: Optional[str] = None) -> str:
    """A bounded, path-free account of an unexpected error: its type, and the base name of the file for an I/O error (never the supplied absolute path)."""
    kind = type(err).__name__
    if isinstance(err, OSError) and not isinstance(err, TimeoutError):
        name = os.path.basename(str(err.filename)) if getattr(err, "filename", None) else ""
        return "%s while reading a supplied input%s" % (kind, " (%s)" % name if name else "")
    text = str(err)
    for prefix in {p for p in (sources, os.path.realpath(sources) if sources else None) if p}:
        text = text.replace(prefix, "<sources>")
    return "%s: %s" % (kind, text[:200])


def guarded(case_id: str, group: str, fn: Callable[[], Result], sources: Optional[str] = None) -> Result:
    """A case that raises is a FAILED case with the cause named, never a traceback: the run goes on, is logged and gets its receipt."""
    try:
        return fn()
    except Exception as err:  # noqa: BLE001 - every error a case can hit is a verdict on that case
        return Result(case_id, "failed", "the case raised %s" % failure_detail(err, sources), group)


def source_dir(sources: Optional[str], name: str) -> Optional[str]:
    path = os.path.join(sources, name) if sources else None
    return path if path and os.path.isdir(path) else None


def probe_case(case_id: str, name: str, sources: Optional[str], run: Callable[[str], List[str]]) -> Result:
    if not sources:
        return blocked(case_id, "probe", "no pinned sources supplied (--sources DIR with %s/)" % name)
    path = source_dir(sources, name)
    if path is None:
        return blocked(case_id, "probe", "%s/ is not in the supplied sources" % name)

    def bounded() -> List[str]:
        return run(L.Source(path))  # admitted once (lstat only), then read only through the Source's checked reads
    return guarded(case_id, "probe", lambda: judged(case_id, "probe", L.with_deadline(L.PROBE_SECONDS, bounded)), sources)


def case_tsrs(data: Dict[str, Any], sources: Optional[str]) -> Result:
    def run(path: str) -> List[str]:
        facts = L.probe_tsrs(path)
        problems = L.check_probe(facts, data["profile"]["derived_facts"]["tailscale-rs-0.6.1"], "tailscale-rs")
        packages = sum(1 for line in path.text("Cargo.lock").split("\n") if line.strip() == "[[package]]")
        anchor = data["cases"]["independent_anchors"]["tailscale_rs_lock_packages"]["value"]
        if packages != anchor or facts["lock_packages"] != anchor:
            problems.append("lock packages: probe %d, text count %d, independent anchor %d" % (facts["lock_packages"], packages, anchor))
        return problems
    return probe_case("T01-P01-tsrs-source", "tailscale-rs", sources, run)


def case_workspace_edges(data: Dict[str, Any], sources: Optional[str]) -> Result:
    def run(path: str) -> List[str]:
        facts = L.probe_workspace_edges(path)
        reach = L.probe_third_party_reach(path, facts["no_runtime_edge_in_workspace"])
        facts["third_party_reaches_runtime_or_os"] = {name: found for name, found in reach.items() if found}
        recorded = {k: v for k, v in data["profile"]["derived_facts"]["tailscale-rs-0.6.1/workspace_edges"].items() if k != "note"}  # the note is prose, not a fact
        return L.check_probe(facts, recorded, "workspace edges")
    return probe_case("T01-P02-workspace-edges", "tailscale-rs", sources, run)


def case_awslc(data: Dict[str, Any], sources: Optional[str]) -> Result:
    return probe_case("T01-P03-awslc-targets", "aws-lc-sys", sources, lambda path: L.check_probe(L.probe_awslc(path), data["profile"]["derived_facts"]["aws-lc-sys-0.45.0"], "aws-lc-sys"))


def case_mio(data: Dict[str, Any], sources: Optional[str]) -> Result:
    return probe_case("T01-P04-mio-reactor", "mio", sources, lambda path: L.check_probe(L.probe_mio(path), data["profile"]["derived_facts"]["mio-1.2.1"], "mio"))


def ledger_against_sources(ledger: Dict[str, Any], sources: Optional[str]) -> List[str]:
    """Every excerpt cut from a file that is supplied is re-cut from that file: the whole-file digest and the lines must still be what the ledger recorded."""
    problems = []
    checked = 0
    admitted: Dict[str, Any] = {}
    for e in ledger["entries"]:
        name = {"tailscale/tailscale-rs": "tailscale-rs", "crates.io/aws-lc-sys": "aws-lc-sys", "crates.io/mio": "mio"}.get(e.get("repo"))
        base = source_dir(sources, name) if name else None
        if base is None:
            continue
        if name not in admitted:
            admitted[name] = L.Source(base)  # bounded admission; every read below is a checked read of an admitted file
        src = admitted[name]
        if not src.has(e["path"]):
            problems.append("%s: %s is not in the supplied source" % (e["id"], e["path"]))
            continue
        data = src.read(e["path"])
        if L.sha256_bytes(data) != e["source_sha256"]:
            problems.append("%s: %s is not the file the excerpt was cut from" % (e["id"], e["path"]))
            continue
        lines = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if "\n".join(lines[e["lines"][0] - 1:e["lines"][1]]) != e["excerpt"]:
            problems.append("%s: lines %d-%d of %s are not the recorded excerpt" % (e["id"], e["lines"][0], e["lines"][1], e["path"]))
        checked += 1
    if not checked:
        problems.append("no ledger excerpt could be re-checked against the supplied sources")
    return problems


def case_ledger_sources(data: Dict[str, Any], sources: Optional[str]) -> Result:
    if not sources:
        return blocked("T01-P05-ledger-vs-sources", "probe", "no pinned sources supplied (--sources DIR)")
    def bounded() -> List[str]:
        return ledger_against_sources(data["ledger"], sources)
    return guarded("T01-P05-ledger-vs-sources", "probe", lambda: judged("T01-P05-ledger-vs-sources", "probe", L.with_deadline(L.PROBE_SECONDS, bounded)), sources)


def receipt_files(kind: str, repo: str = REPO) -> List[str]:
    directory = os.path.join(repo, "toolchain", "results", "tailscale", kind)
    return sorted(os.path.join(directory, n) for n in os.listdir(directory) if n.endswith(".json")) if os.path.isdir(directory) else []


X01_ID = "T01-X01-legacy-isa-build"
X01_KINDS = (("core", "the seven core crates"), ("whole", "the whole library"))


def stop_text(stop: Dict[str, Any]) -> str:
    """A stop in one short sentence (the shared case log bounds a detail at 1024 characters, so the account has to fit): where it stopped and why, as the log's own text classified it."""
    where = "at %s" % stop["package"] if stop.get("package") else "at an unnamed crate"
    if stop.get("class") == "missing-c-toolchain":
        return "STOPPED %s: the worker has no C compiler '%s', a toolchain blocker and not an ISA or source finding" % (where, stop["tool"])
    if stop.get("class") == "cargo-config-rejected":
        return "REJECTED by cargo before building: an inline-table --config, a syntax failure and not an ISA or source finding"
    if stop.get("class") == "c-compiler-rejected-target":
        return "STOPPED %s: the C compiler wrapper rejected the target spelling '%s', an adapter failure and not an ISA or source finding" % (where, stop["detail"])
    return "STOPPED %s: the cause is not classified here, so it is read neither as a toolchain blocker nor as an ISA or source finding" % where


def account_x01(got: Dict[Any, List[Dict[str, Any]]], targets: Any) -> Any:
    """One short line per required attempt, and whether every one built. A stop stays in the account even when a later run built the same attempt."""
    lines, complete = [], True
    for target in targets:
        for kind, _what in X01_KINDS:
            records = got.get((target, kind), [])
            built = [f for f in records if f["outcome"] == "built"]
            stops = [f["stop"] for f in records if f["outcome"] == "stopped"]
            if built:
                text = "BUILT (%d artifacts)" % built[0]["artifacts"]
                wrappers = sorted({(f["cc"]["wrapper"], f["cc"]["sha256"][:12]) for f in built if f.get("cc")})
                if wrappers:
                    text += " with the pinned C compiler wrapper%s %s (Zig 0.14.1, three cargo env keys)" % ("s" if len(wrappers) > 1 else "", " and ".join("%s (sha256 %s)" % w for w in wrappers))
                if stops:
                    text += "; earlier stops kept: " + "; ".join(stop_text(s) for s in stops)
            elif stops:
                text, complete = "; ".join(stop_text(s) for s in stops), False
            else:
                text, complete = "NOT RECORDED", False
            lines.append("%s %s: %s" % (kind, target.split("-")[0], text))
    return lines, complete


def case_build(repo: str, data: Optional[Dict[str, Any]] = None, build_logs: Any = ()) -> Result:
    """Judge the captured compile-only build logs: those committed under toolchain/results/tailscale/builds/ (which must be redacted) and any supplied with --build-log (which may be raw).
    The contract asks for four attempts, the seven core crates and the whole library on each legacy target. A record that does not hold FAILS the case; it PASSES only when all four
    attempts built; otherwise it is BLOCKED with every attempt accounted for, so a core-only pass, a stop, or a missing attempt can never read as the whole probe."""
    directory = os.path.join(repo, *BUILD_DIR)
    names = sorted(os.listdir(directory)) if os.path.isdir(directory) else []
    logs, unjudged = [n for n in names if n.endswith(".log")], [n for n in names if n.endswith(".json")]
    if not logs and not build_logs:
        if unjudged:
            return blocked(X01_ID, "central", "a build receipt exists but this runner has no judge for it yet: the judged record is the captured build log (builds/*.log, contract section 6); "
                           "do not read a JSON receipt as a pass")
        return blocked(X01_ID, "central",
                       "no build record under toolchain/results/tailscale/builds/: the legacy-ISA build probes (the seven core crates AND the whole library, on powerpc and on mips) need central runs "
                       "(root's strict-remote lane) whose captured logs are committed there. The lines are in CENTRAL_LINES and docs/contracts/t01.md section 6")
    data = data or inputs(repo)
    anchors = data["cases"]["x01_build"]
    tree_pin = data["profile"]["derived_facts"]["tailscale-rs-0.6.1"]["tree_sha256"]
    lock_text = L.read_bounded_file(os.path.join(repo, *anchors["lock_fixture"].split("/"))).decode("utf-8")
    problems = ["lock fixture: " + p for p in L.check_x01_lock(lock_text, anchors)]
    got: Dict[Any, List[Dict[str, Any]]] = {}
    records = [(name, os.path.join(directory, name), True) for name in logs] + [("supplied build log %d" % (i + 1), path, False) for i, path in enumerate(build_logs)]
    for label, path, redacted in records:
        try:
            text = L.read_bounded_file(path).decode("utf-8")
        except (L.SourceRefused, OSError, UnicodeDecodeError) as err:
            problems.append("%s: %s" % (label, failure_detail(err) if isinstance(err, (OSError, UnicodeDecodeError)) else str(err)))
            continue
        found, facts = L.judge_build_record(text, anchors, tree_pin, lock_text, redacted)
        problems += ["%s: %s" % (label, p) for p in found]
        if not found:
            got.setdefault((facts["target"], facts["attempt"]), []).append(facts)
    if problems:
        return judged(X01_ID, "central", problems)
    lines, complete = account_x01(got, anchors["targets"])
    bound = "type-check only: nothing linked or run, no runtime, memory, CPU, enrollment or native-endpoint result; T01-X02 and the native requirement are untouched"
    if unjudged:
        return blocked(X01_ID, "central", "INCOMPLETE and a JSON build receipt exists that this runner has no judge for it yet; %s: %s" % (bound, "; ".join(lines)))
    if not complete:
        return blocked(X01_ID, "central", "INCOMPLETE; a core pass is partial evidence only; %s: %s" % (bound, "; ".join(lines)))
    return Result(X01_ID, "passed", "all four required attempts built; %s: %s" % (bound, "; ".join(lines)), "central")


X02_ID = "T01-X02-target-resources"
X02_BOUND = ("harness guests only (Debian 4.19 MIPS Malta, Debian 4.9 PowerPC g3beige), not the Sonos 2.6.35 / 2.6.14 kernels or a board, so the figures are indicative; ticks are raw /proc clock "
             "ticks; no tunnel, enrollment, interop or native-endpoint result; the native requirement and the closure of T01 are untouched")


def case_resources(repo: str) -> Result:
    """Judge the X02 receipts under toolchain/results/tailscale/measurements/ (written by `scripts/e2e/t01 --x02 run|analyze`, judged by x02_judge.judge_receipt, which re-judges the facts
    a receipt records and never trusts its own `result`). No receipt: BLOCKED. FAILED by any receipt that is malformed, has another schema, or records a captured run that did not pass.
    A supplied_transcript_analysis is never execution evidence. PASSES only when EACH legacy target (mips and powerpc) has a captured guest run with every phase ok, no UNKNOWN
    reading and its ELF, kernel and initramfs hashes; otherwise BLOCKED with each target accounted for, so one target can never read as both."""
    files = receipt_files("measurements", repo)
    if not files:
        return blocked(X02_ID, "central", "no measurement receipt under toolchain/results/tailscale/measurements/: " + MEASUREMENT_BLOCKER)
    problems: List[str] = []
    notes: List[str] = []
    passed: Dict[str, List[Any]] = {}
    for path in files:
        name = os.path.basename(path)
        try:
            text = L.read_bounded_file(path, X.MAX_RECEIPT_BYTES).decode("utf-8")
        except (L.SourceRefused, OSError, UnicodeDecodeError) as err:
            problems.append("%s: %s" % (name, failure_detail(err) if isinstance(err, (OSError, UnicodeDecodeError)) else str(err)))
            continue
        verdict = X.judge_receipt(text)
        if verdict.state == "failed":
            problems += ["%s: %s" % (name, p) for p in verdict.problems]
        elif verdict.state == "passed":
            passed.setdefault(verdict.arch, []).append((name, verdict.resources))
        elif verdict.state == "blocked":
            notes.append("%s (%s) is blocked: %s" % (name, verdict.arch, "; ".join(verdict.problems)))
        else:
            notes.append("%s is a supplied transcript analysis, not a guest run" % name)
    if problems:
        return judged(X02_ID, "central", problems)
    lines = []
    for arch in X.ARCHES:
        if arch not in passed:
            lines.append("%s: NOT RECORDED as a passed captured guest run" % arch)
            continue
        name, figures = passed[arch][-1]
        earlier = " (+%d earlier passed)" % (len(passed[arch]) - 1) if len(passed[arch]) > 1 else ""
        lines.append("%s: PASSED, VmHWM %d kB, VmRSS %d kB, utime %d, stime %d ticks, from %s%s" % (arch, figures["VmHWM"], figures["VmRSS"], figures["utime"], figures["stime"], name, earlier))
    if all(arch in passed for arch in X.ARCHES):
        return Result(X02_ID, "passed", "a captured guest run with every phase ok and every reading known on each legacy target; %s: %s" % (X02_BOUND, "; ".join(lines)), "central")
    return blocked(X02_ID, "central", "INCOMPLETE; one target is partial evidence only; %s: %s" % (X02_BOUND, "; ".join(lines + notes)))


SMOKE_CASES = (case_ledger, case_profile, case_classification, case_cell_rules, case_matrix, case_budget, case_fixtures, case_native_requirement)
SMOKE_IDS = ["T01-META-LEDGER", "T01-META-PROFILE", "T01-C01-classification", "T01-C02-cell-rules", "T01-C03-matrix", "T01-C04-budget-rules", "T01-C05-fixtures", "T01-C06-native-requirement"]
FULL_IDS = ["T01-P01-tsrs-source", "T01-P02-workspace-edges", "T01-P03-awslc-targets", "T01-P04-mio-reactor", "T01-P05-ledger-vs-sources", "T01-X01-legacy-isa-build", "T01-X02-target-resources"]
DESCRIPTIONS = {
    "T01-META-LEDGER": "every ledger excerpt matches its digest, pins are full commits or exact versions, web pages are not passed off as immutable, local excerpts are still in the checkout",
    "T01-META-PROFILE": "the frozen profile states only what the ledger backs; classes follow from facts; the native requirement is intact",
    "T01-C01-classification": "native / official-reference / wireguard-only / wrapper / gateway / control-server classification equals the hand-written table",
    "T01-C02-cell-rules": "the cell rule (behavior x platform x extensible) equals the hand-written table; `supported` only on a run on the target",
    "T01-C03-matrix": "the derived matrix is complete, has no supported cell, and only tailscale-rs is in the strict-Rust native class",
    "T01-C04-budget-rules": "missing data is pending, never a pass; units, receipts and the 4 MiB reserve floor are enforced; no cap is allocated",
    "T01-C05-fixtures": "synthetic identity, network-map, relay and key-expiry fixtures equal the model on hand-written expectations",
    "T01-C06-native-requirement": "the native requirement stays required and unwaived; the study stays incomplete while no client is linked, run and measured (the X02 probe is not a client), and closes no other task; gateways and the Go client never count as native",
    "T01-P01-tsrs-source": "the pinned tailscale-rs tree: digest, lock census, unsafe census, README claims (needs --sources)",
    "T01-P02-workspace-edges": "which tailscale-rs crates have an intra-workspace edge to a runtime, OS or TLS crate, and which third-party closures still reach one: NOT a portability claim (needs --sources)",
    "T01-P03-awslc-targets": "aws-lc-sys 0.45.0: its assembly target sets, the no-asm refusal in optimized builds, the BE 32-bit arch macros (needs --sources)",
    "T01-P04-mio-reactor": "mio 1.2.1 creates its epoll instance with epoll_create1 and has no epoll_create fallback (needs --sources)",
    "T01-P05-ledger-vs-sources": "every ledger excerpt cut from a supplied source file is re-cut from that file (needs --sources)",
    "T01-X01-legacy-isa-build": "the legacy-ISA COMPILE-ONLY checks, the seven core crates AND the whole library on each target (captured cargo check logs; PASSES only when all four built, else BLOCKED with every attempt accounted for)",
    "T01-X02-target-resources": "memory and CPU measurements on the target (judged X02 guest-run receipts; PASSES only with a captured run on EACH legacy target, else BLOCKED; indicative, harness guests only)",
}


def run(tier: str, sources: Optional[str] = None, repo: str = REPO, build_logs: Any = ()) -> List[Result]:
    if tier not in RUN_TIERS:
        raise ValueError("tier %r judges nothing (the soak tier is not run)" % tier)
    try:
        data = inputs(repo)
    except Exception as err:  # noqa: BLE001 - the judged inputs themselves are unreadable: every case fails with that cause
        cause = "the judged inputs could not be loaded: %s" % failure_detail(err)
        return [Result(case_id, "failed", cause, "contract") for case_id in planned_ids(tier)]
    results = [guarded(case_id, "contract", lambda case=case: case(data, repo)) for case_id, case in zip(SMOKE_IDS, SMOKE_CASES)]
    if tier == "full":
        results += [case_tsrs(data, sources), case_workspace_edges(data, sources), case_awslc(data, sources), case_mio(data, sources), case_ledger_sources(data, sources),
                    guarded("T01-X01-legacy-isa-build", "central", lambda: case_build(repo, data, build_logs)), guarded("T01-X02-target-resources", "central", lambda: case_resources(repo))]
    return results


def planned_ids(tier: str) -> List[str]:
    return SMOKE_IDS + (FULL_IDS if tier == "full" else [])


# ---- reporting --------------------------------------------------------------------------------------------------------------------------------------------

def summarize(results: List[Result]) -> Dict[str, int]:
    return {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "blocked")}


def exit_code(results: List[Result]) -> int:
    counts = summarize(results)
    return 1 if counts["failed"] else 3 if counts["blocked"] else 0


def final_exit(results: List[Result], evidence: Optional[Any]) -> int:
    """The cases' exit code, except that a pass cannot rest on a diagnostic log that lost critical evidence."""
    code = exit_code(results)
    return 1 if code == 0 and evidence is not None and not evidence.complete else code


def artifact_digests(repo: str = REPO) -> Dict[str, str]:
    digests = {rel: (L.sha256_file(os.path.join(repo, rel)) if os.path.isfile(os.path.join(repo, rel)) else "missing") for rel in JUDGED_ARTIFACTS}
    builds = os.path.join(repo, *BUILD_DIR)
    for name in sorted(os.listdir(builds)) if os.path.isdir(builds) else []:
        if name.endswith(".log") and os.path.isfile(os.path.join(builds, name)):
            digests["/".join(BUILD_DIR + (name,))] = L.sha256_file(os.path.join(builds, name))
    return digests


def artifact_set_digest(digests: Dict[str, str]) -> str:
    return L.sha256_text("".join("%s %s\n" % (rel, d) for rel, d in sorted(digests.items())))


def replay_command(tier: str, sources: Optional[str]) -> str:
    return "scripts/e2e/t01 --tier %s" % tier + (" --sources SOURCES_DIR" if sources else "")


def retained_lines(results: List[Result], tier: str, sources: Optional[str], artifacts: Dict[str, str]) -> List[str]:
    bad = [r for r in results if r.status == "failed"] or [r for r in results if r.status == "blocked"]
    if not bad:
        return []
    first = bad[0]
    lines = ["RETAINED FOR REPLAY. First %s case: %s: %s" % (first.status, first.case_id, first.detail), "  replay: " + replay_command(tier, sources)]
    if sources:
        lines.append("  sources: " + ", ".join("%s (%s)" % (n, "present" if source_dir(sources, n) else "absent") for n in SOURCE_DIRS) + " (the supplied directory is not named here)")
    lines.append("  python %s; receipt %s" % (platform.python_version(), RECEIPT_SCHEMA))
    lines += ["  artifact %s sha256 %s" % kv for kv in artifacts.items()]
    return lines


def report(results: List[Result], tier: str, sources: Optional[str] = None, artifacts: Optional[Dict[str, str]] = None, evidence: Optional[Any] = None) -> None:
    counts = summarize(results)
    for status, label in (("failed", "FAIL"), ("blocked", "BLOCKED")):
        rows = [r for r in results if r.status == status]
        for r in rows[:MAX_PRINTED]:
            print("%-8s %s  %s" % (label, r.case_id, r.detail))
        if len(rows) > MAX_PRINTED:
            print("%-8s ... and %d more %s case(s)" % (label, len(rows) - MAX_PRINTED, status))
    if artifacts is not None:
        for line in retained_lines(results, tier, sources, artifacts):
            print(line)
    verdict = "QUALIFIED" if final_exit(results, evidence) == 0 else "NOT QUALIFIED"
    note = ""
    if evidence is not None:
        print(evidence.summary)
        if not evidence.complete:
            note = "  [diagnostic evidence INCOMPLETE: " + ", ".join(evidence.reasons) + "]"
    print("T01 e2e tier=%s: %s  planned=%d passed=%d failed=%d blocked=%d%s" % (tier, verdict, len(results), counts["passed"], counts["failed"], counts["blocked"], note))


def write_receipt(directory: str, tier: str, results: List[Result], artifacts: Dict[str, str], sources: Optional[str], run_id: str, evidence: Optional[Any]) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "t01-%s.json" % run_id)
    doc = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "tier": tier, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "counts": summarize(results), "exit_code": final_exit(results, evidence), "replay": replay_command(tier, sources), "python": platform.python_version(),
           "sources_supplied": sorted(n for n in SOURCE_DIRS if source_dir(sources, n)) if sources else [], "artifacts": artifacts, "results": [r.as_dict() for r in results]}
    if evidence is not None:
        doc["diagnostics"] = {"complete": evidence.complete, "reasons": list(evidence.reasons), "log": evidence.log, "file": os.path.basename(evidence.path) if evidence.path else None}
    with open(path, "x", encoding="utf-8") as handle:  # never overwrites an earlier run's receipt
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return path


def load_case_log() -> Any:
    import case_log  # noqa: PLC0415 - loaded by name from this directory
    return case_log


def redact_command(raw: str, dest: str) -> int:
    """Write the committed form of a raw build log. Refuses an unreadable or oversize input, refuses to overwrite, and writes nothing if site data would remain."""
    try:
        text = L.read_bounded_file(raw).decode("utf-8")
    except (L.SourceRefused, OSError, UnicodeDecodeError) as err:
        print("error: the raw log was not read: %s" % (failure_detail(err) if isinstance(err, (OSError, UnicodeDecodeError)) else err), file=sys.stderr)
        return 2
    redacted = L.redact_build_log(text)
    hits = L.site_hits(redacted)
    if hits:
        print("error: site data would remain (%s); nothing was written" % ", ".join(hits), file=sys.stderr)
        return 1
    try:
        with open(dest, "x", encoding="utf-8", newline="") as handle:
            handle.write(redacted)
    except FileExistsError:
        print("error: the destination exists; it is never overwritten", file=sys.stderr)
        return 1
    except OSError as err:
        print("error: the destination was not written: %s" % type(err).__name__, file=sys.stderr)
        return 2
    print("redacted record written: %d bytes, sha256 %s (raw sha256 %s)" % (len(redacted.encode("utf-8")), L.sha256_text(redacted), L.sha256_text(text)))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="T01 tiered runner and judge (ffw-32a)")
    parser.add_argument("--tier", choices=TIERS, default="full")
    parser.add_argument("--sources", metavar="DIR", help="the pinned source trees, extracted: tailscale-rs/, aws-lc-sys/, mio/")
    parser.add_argument("--receipts", metavar="DIR", help="write a JSON receipt and the JSONL diagnostic log here")
    parser.add_argument("--list", action="store_true", help="list the planned case ids of the tier and exit")
    parser.add_argument("--build-log", metavar="LOG", action="append", default=[], help="also judge this captured build log (raw or redacted); repeatable")
    parser.add_argument("--redact-build-log", metavar=("RAW", "DEST"), nargs=2, help="write the committed (redacted) form of a raw build log and exit")
    args = parser.parse_args(argv)
    if args.redact_build_log:
        return redact_command(*args.redact_build_log)
    if args.tier not in RUN_TIERS:
        print(SOAK_NOT_RUN)
        return SOAK_EXIT
    if args.sources and not os.path.isdir(args.sources):
        print("error: the sources directory was not found", file=sys.stderr)
        return 2
    if args.list:
        for case_id in planned_ids(args.tier):
            print("%-28s %s" % (case_id, DESCRIPTIONS[case_id]))
        return 0
    case_log = load_case_log()
    run_id = secrets.token_hex(8)
    try:
        artifacts = artifact_digests()
    except OSError as err:  # an unreadable judged artifact is reported by the cases that read it; the log opens anyway
        artifacts = {}
        print(safe_detail("error: judged artifacts could not be digested: %s" % type(err).__name__), file=sys.stderr)
    log = case_log.CaseLog.open(REPO, run_id, args.tier, args.receipts, header_extra={
        "python": platform.python_version(), "tier": args.tier, "artifact_count": len(artifacts), "artifact_set_sha256": artifact_set_digest(artifacts)})
    try:
        results = run(args.tier, args.sources, REPO, tuple(args.build_log))
    except Exception as err:  # noqa: BLE001 - last resort: still a failed, logged, receipted run, never a traceback
        results = [Result("T01-RUNNER", "failed", "the runner raised %s" % failure_detail(err, args.sources), "runner")]
    for r in results:
        log.record(r.case_id, r.group, r.status, r.detail)
    evidence = log.finish(summarize(results))
    report(results, args.tier, args.sources, artifacts, evidence)
    if evidence.path and not args.receipts:
        print("diagnostic log kept:", evidence.path)
    code = final_exit(results, evidence)
    if args.receipts:
        try:
            print("receipt:", write_receipt(args.receipts, args.tier, results, artifacts, args.sources, run_id, evidence))
        except OSError as err:
            print(safe_detail("error: the receipt could not be written under the receipts directory: %s" % type(err).__name__), file=sys.stderr)
            return code or 1
    return code


if __name__ == "__main__":
    sys.exit(main())
