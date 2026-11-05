#!/usr/bin/env python3
"""E04 (ffw-25l) host-side case runner.

    run_cases.py --tier smoke|full [--case ID] [--list] [--receipts DIR]

Runs the named cases in ``cases.json`` plus one ``sim_trace`` case per trace in ``sim_cases.json``,
and prints one line per case and an exact denominator. Exit codes: 0 qualified, 1 a case failed,
3 only blocked cases stand in the way, 2 usage or a malformed case file.

What a pass means, so it is not over-read:
* This is a HOST SIMULATION and a document check. It boots nothing, touches no device, builds
  nothing and reads no network. Nothing here shows what the retained driver does on a real board.
* The Python reference models (sim_ref.py, contract_ref.py) re-implement the rules in
  docs/contracts/e04.md. The Rust crate replays the same sim_cases.json and matrix under central
  verification. The expected values in the case files are hand-written, not produced by either model.
  All of it has one author, so agreement is a cross-check and not a second author.
* ``anchor_facts`` re-derives the committed anchor facts from the git-ignored artifact when it is
  present. If it is absent the case is BLOCKED, never passed.
* A case of kind ``blocked`` is a required invariant nothing here can verify. It is counted, named
  with its owner and external blocker, and makes the run NOT QUALIFIED.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import anchor_extract  # noqa: E402
import contract_ref  # noqa: E402
import sim_ref  # noqa: E402

CASES_FILE = os.path.join(HERE, "cases.json")
SIM_FILE = os.path.join(HERE, "sim_cases.json")
MATRIX_FILE = os.path.join(HERE, "matrix_audiodev_m16.json")
ANCHORS_FILE = os.path.join(HERE, "anchors", "audiodev_m16.json")
DOC_FILE = os.path.join(REPO, "docs", "contracts", "e04.md")
RUST_DIR = os.path.join(REPO, "crates", "franken-hal", "src")
SCHEMA = "ffw.e04.cases.v1"
SIM_SCHEMA = "ffw.e04.sim_cases.v1"
TIERS = ("smoke", "full")
KINDS = ("ioctl_decode", "ioctl_encode", "read_uint", "field_map", "matrix_real", "matrix_scenario",
         "matrix_size_independence", "sim_trace", "planted_defect", "anchor_facts", "meta_files",
         "meta_shared_vectors", "meta_invariants", "meta_matrix_vs_anchors", "meta_hygiene", "meta_log",
         "runner_selftest", "blocked")

PASS, FAIL, BLOCKED = "pass", "fail", "blocked"
Result = Tuple[str, str]


class CaseError(Exception):
    pass


def load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise CaseError(f"cannot read {os.path.relpath(path, REPO)}: {e}") from e


def sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---------------------------------------------------------------------------------------- case kinds

def to_int(x: Any) -> int:
    return int(x, 16) if isinstance(x, str) else x


def run_ioctl_decode(c) -> Result:
    got = contract_ref.decode_ppc_ioctl(to_int(c["cmd"]))
    return (PASS, "") if got == c["expect"] else (FAIL, f"decoded {got}, expected {c['expect']}")


def run_ioctl_encode(c) -> Result:
    got = contract_ref.encode_ppc_ioctl(*c["args"])
    want = None if c["expect"] is None else to_int(c["expect"])
    return (PASS, "") if got == want else (FAIL, f"encoded {got!r}, expected {want!r}")


def run_read_uint(c) -> Result:
    got = contract_ref.read_uint(c["bytes"], c["offset"], c["width"], c["endian"])
    want = {k: to_int(v) if k == "ok" else v for k, v in c["expect"].items()}
    return (PASS, "") if got == want else (FAIL, f"read {got}, expected {want}")


def run_field_map(c) -> Result:
    got = contract_ref.validate_field_map(c["fields"], c["payload_size"], c["alignment"])
    return (PASS, "") if got == c["expect"] else (FAIL, f"problem {got!r}, expected {c['expect']!r}")


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    compact = []
    by_kind: Dict[str, int] = {}
    by_blocker: Dict[str, int] = {}
    for m in report["missing"]:
        r = m["reason"]
        entry = {"scope": m["scope"], "record": m["record"], "field": m["field"], "kind": r["kind"]}
        if r["kind"] == "unknown":
            entry["blocker_id"] = r["blocker"]["id"]
            by_blocker[r["blocker"]["id"]] = by_blocker.get(r["blocker"]["id"], 0) + 1
        if "detail" in r:
            entry["detail"] = r["detail"]
        if r["kind"] == "unregistered_artifact":
            entry["sha256"] = r["sha256"]
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        compact.append(entry)
    return {"hardware_eligible": report["hardware_eligible"], "offline_model_ok": report["offline_model_ok"],
            "missing_count": len(compact), "missing": compact, "by_kind": by_kind, "by_blocker": by_blocker,
            "first": compact[0] if compact else None}


def entry_matches(got: Dict[str, Any], want: Dict[str, Any]) -> bool:
    """An expected entry pins the keys it names. Free-text detail the case did not pin is not compared."""
    return all(got.get(k) == v for k, v in want.items())


def check_summary(summary: Dict[str, Any], expect: Dict[str, Any]) -> Result:
    for key, want in expect.items():
        got = summary.get(key)
        if key == "missing":
            same = len(got) == len(want) and all(entry_matches(g, w) for g, w in zip(got, want))
        elif key == "first" and want is not None:
            same = got is not None and entry_matches(got, want)
        else:
            same = got == want
        if not same:
            return FAIL, f"{key}: got {got!r}, expected {want!r}"
    return PASS, ""


def scenario(name: str) -> Dict[str, Any]:
    art, syn = contract_ref.artifact_anchor, contract_ref.synthetic_anchor
    if name == "complete_artifact":
        return contract_ref.complete_matrix(art())
    if name == "complete_synthetic":
        return contract_ref.complete_matrix(syn())
    m = contract_ref.complete_matrix(art())
    rec = contract_ref.record(m, "start")
    if name == "one_unknown_payload_size":
        rec["payload_size"] = contract_ref.unknown("EXT-TEST-SIZE", "decode the start handler")
    elif name == "missing_drain_and_roam":
        m["interfaces"] = [r for r in m["interfaces"] if r["operation"] != "drain"]
        m["radio"] = [r for r in m["radio"] if r["duty"] != "roam"]
    elif name == "contradictory_start":
        # fixture start is selector 6 with command 0x80087e06 (write, 8 bytes, type 0x7e)
        rec["selector"] = contract_ref._known(7, art())
        rec["direction"] = contract_ref._known("read", art())
        rec["payload_size"] = contract_ref._known(16, art())
    elif name == "bad_anchor_offset":
        rec["endianness"] = contract_ref._known("big", art(offset=0x1000))
    elif name == "unregistered_artifact":
        bad = art()
        bad["sha256"] = "f" * 64
        rec["endianness"] = contract_ref._known("big", bad)
    elif name == "non_ioctl_with_selector":
        sub = contract_ref.record(m, "submit_block")
        sub["interface"] = contract_ref._known("write", art())
    elif name == "topology_route_count_mismatch":
        m["topology"][0]["routing"] = contract_ref._known(
            [{"index": 0, "role": "woofer_mono"}, {"index": 1, "role": "tweeter_mono"},
             {"index": 2, "role": "subwoofer_lfe"}], art())
    elif name == "topology_rates_not_increasing":
        m["topology"][0]["sample_rates_hz"] = contract_ref._known([48000, 44100], art())
    elif name == "startup_unmutes_early":
        contract_ref.sequence(m, "startup")["steps"] = contract_ref._known(
            [{"action": a, "min_delay_us": 0} for a in ("assert_mute", "deassert_mute", "configure_codec")], art())
    elif name == "shutdown_unmutes":
        contract_ref.sequence(m, "shutdown")["steps"] = contract_ref._known(
            [{"action": a, "min_delay_us": 0} for a in ("assert_mute", "deassert_mute")], art())
    elif name == "mute_ack_not_required":
        contract_ref.sequence(m, "fault")["mute_acknowledgment_required"] = contract_ref._known(False, art())
    elif name == "no_fault_sequence":
        m["amp_sequences"] = [r for r in m["amp_sequences"] if r["kind"] != "fault"]
    elif name == "no_topology":
        m["topology"] = []
    else:
        raise CaseError(f"unknown scenario {name!r}")
    return m


def run_matrix_scenario(c) -> Result:
    return check_summary(summarize(contract_ref.evaluate(scenario(c["scenario"]))), c["expect"])


def run_matrix_real(c) -> Result:
    return check_summary(summarize(contract_ref.evaluate(load_json(MATRIX_FILE))), c["expect"])


def run_size_independence(c) -> Result:
    base = load_json(MATRIX_FILE)
    reports = []
    for size in c["sizes"]:
        m = copy.deepcopy(base)
        for a in m["artifacts"]:
            a["size_bytes"] = size
        reports.append(contract_ref.evaluate(m))
    identical = all(r == reports[0] for r in reports)
    got = {"identical": identical, "hardware_eligible": reports[0]["hardware_eligible"]}
    return (PASS, "") if got == c["expect"] else (FAIL, f"{got}, expected {c['expect']}")


def sim_cases() -> List[Dict[str, Any]]:
    doc = load_json(SIM_FILE)
    if doc.get("schema") != SIM_SCHEMA:
        raise CaseError(f"sim_cases.json schema is {doc.get('schema')!r}, expected {SIM_SCHEMA!r}")
    return doc["cases"]


def run_sim_trace(c) -> Result:
    mismatch = sim_ref.replay(c["trace"])
    return (PASS, "") if mismatch is None else (FAIL, json.dumps(mismatch, sort_keys=True))


def run_planted_defect(c) -> Result:
    cases = sim_cases()
    green = [x["id"] for x in cases if sim_ref.replay(x) is not None]
    if green:
        return FAIL, f"baseline is not green, so no catch can be credited: {green}"
    caught = sorted(x["id"] for x in cases if sim_ref.replay(x, [c["defect"]]) is not None)
    missing = [i for i in c["caught_by"] if i not in caught]
    if missing:
        return FAIL, f"defect {c['defect']!r} was not caught by {missing}; caught by {caught}"
    return PASS, f"caught by {len(caught)} case(s): {', '.join(caught)}"


def run_anchor_facts(c) -> Result:
    path = anchor_extract.default_artifact_path(REPO)
    if not path:
        return BLOCKED, ("artifact not present (git-ignored capture in the frankensonos checkout); set "
                         "FFW_FRANKENSONOS_DIR. Owner: the person holding the capture. Never counted as a pass.")
    try:
        facts = anchor_extract.extract(path)
    except (anchor_extract.AnchorError, KeyError, IndexError, ValueError) as e:
        return FAIL, f"extraction failed: {e}"
    committed = load_json(ANCHORS_FILE)
    if facts != committed:
        diff = [k for k in sorted(set(facts) | set(committed)) if facts.get(k) != committed.get(k)]
        return FAIL, f"re-derived facts differ from the committed file in {diff}"
    return PASS, f"re-derived from the artifact, digest {facts['artifact']['sha256'][:16]}"


def struct_fields(source: str, name: str) -> List[str]:
    """Field names of a Rust struct, in order, read from its source text."""
    m = re.search(r"(?:pub )?struct %s \{(.*?)\n\}" % re.escape(name), source, re.S)
    if not m:
        return []
    return [f.group(1) for f in re.finditer(r"^\s*(?:pub )?(\w+):\s", m.group(1), re.M)]


def run_meta_log(c) -> Result:
    """The JSONL line the contract log writes has exactly the fields of the ffw.log.v1 schema type, in
    its order. The Rust tests go further (they round-trip every line through that type); this catches a
    drift in the field list without compiling anything."""
    support = open(os.path.join(REPO, "crates", "franken-test-support", "src", "lib.rs"), encoding="utf-8").read()
    ours = open(os.path.join(RUST_DIR, "contract_log.rs"), encoding="utf-8").read()
    want = struct_fields(support, "DiagnosticEvent")
    got = struct_fields(ours, "LogLine")
    problems = []
    if not want:
        problems.append("could not read DiagnosticEvent from franken-test-support")
    elif got != want:
        problems.append(f"LogLine fields {got} differ from DiagnosticEvent fields {want}")
    if 'pub const LOG_SCHEMA_VERSION: &str = "ffw.log.v1";' not in ours:
        problems.append("contract_log.rs does not state the ffw.log.v1 schema string")
    production = ours.split("#[cfg(test)]")[0]
    if "franken_test_support" in production:
        problems.append("the production half of contract_log.rs names franken_test_support")
    cargo = open(os.path.join(REPO, "crates", "franken-hal", "Cargo.toml"), encoding="utf-8").read()
    if "franken-test-support" in cargo.split("[dev-dependencies]")[0]:
        problems.append("franken-test-support is a normal dependency of franken-hal, not a dev-dependency")
    return (PASS, f"{len(want)} fields in order") if not problems else (FAIL, "; ".join(problems))


def run_meta_files(c) -> Result:
    needed = [CASES_FILE, SIM_FILE, MATRIX_FILE, ANCHORS_FILE, DOC_FILE,
              os.path.join(RUST_DIR, "contract.rs"), os.path.join(RUST_DIR, "dma_sim.rs"),
              os.path.join(RUST_DIR, "contract_log.rs"),
              os.path.join(REPO, "scripts", "e2e", "e04")]
    gone = [os.path.relpath(p, REPO) for p in needed if not os.path.isfile(p)]
    if gone:
        return FAIL, f"missing: {gone}"
    schemas = {"cases": load_json(CASES_FILE).get("schema"), "sim": load_json(SIM_FILE).get("schema"),
               "matrix": load_json(MATRIX_FILE).get("schema"), "anchors": load_json(ANCHORS_FILE).get("schema")}
    want = {"cases": SCHEMA, "sim": SIM_SCHEMA, "matrix": contract_ref.SCHEMA, "anchors": anchor_extract.SCHEMA}
    return (PASS, "") if schemas == want else (FAIL, f"schemas {schemas}, expected {want}")


def run_meta_shared_vectors(c) -> Result:
    """The Rust crate must replay this same sim_cases.json and matrix, and know how many cases to expect."""
    sim = open(os.path.join(RUST_DIR, "dma_sim.rs"), encoding="utf-8").read()
    contract = open(os.path.join(RUST_DIR, "contract.rs"), encoding="utf-8").read()
    problems = []
    if 'include_str!("../../../tests/e04/sim_cases.json")' not in sim:
        problems.append("dma_sim.rs does not include tests/e04/sim_cases.json")
    if 'include_str!("../../../tests/e04/matrix_audiodev_m16.json")' not in contract:
        problems.append("contract.rs does not include tests/e04/matrix_audiodev_m16.json")
    m = re.search(r"file\.cases\.len\(\),\s*(\d+)", sim)
    if not m or int(m.group(1)) != len(sim_cases()):
        problems.append(f"the Rust test expects {m.group(1) if m else 'no'} trace cases, the file has {len(sim_cases())}")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def expand(patterns: List[str], ids: List[str]) -> List[str]:
    out = []
    for p in patterns:
        if p.endswith("*"):
            out.extend(i for i in ids if i.startswith(p[:-1]))
        else:
            out.append(p)
    return out


def run_meta_invariants(c) -> Result:
    doc = load_json(CASES_FILE)
    ids = [x["id"] for x in doc["cases"]] + [x["id"] for x in sim_cases()]
    mapped, problems = set(), []
    for inv in doc["invariants"]:
        refs = expand(inv["cases"], ids)
        if not refs:
            problems.append(f"{inv['id']} maps to no case")
        for r in refs:
            if r not in ids:
                problems.append(f"{inv['id']} names unknown case {r}")
        mapped.update(refs)
    orphans = [i for i in ids if i not in mapped]
    if orphans:
        problems.append(f"cases covering no invariant: {orphans}")
    return (PASS, f"{len(doc['invariants'])} invariants, {len(ids)} cases") if not problems else (FAIL, "; ".join(problems))


def run_meta_matrix_vs_anchors(c) -> Result:
    """The matrix registers the artifact the anchor facts describe, with the same digest, size and sections."""
    matrix, anchors = load_json(MATRIX_FILE), load_json(ANCHORS_FILE)
    art = anchors["artifact"]
    reg = matrix["artifacts"]
    if len(reg) != 1:
        return FAIL, f"matrix registers {len(reg)} artifacts, expected 1"
    r = reg[0]
    problems = []
    if r["sha256"] != art["sha256"]:
        problems.append("digest differs")
    if r["size_bytes"] != art["size_bytes"]:
        problems.append("size differs")
    sizes = {s["name"]: s["size"] for s in r["sections"]}
    for s in art["sections"]:
        if sizes.get(s["name"]) != s["size"]:
            problems.append(f"section {s['name']} differs")
    handled = {h["nr"] for h in anchors["dsp_ioctl"]["dispatch"]["handled"]}
    default_nrs = set(anchors["dsp_ioctl"]["dispatch"]["default_nrs"])
    if handled & default_nrs or handled | default_nrs != set(range(anchors["dsp_ioctl"]["dispatch"]["entries"])):
        problems.append("handled and default command numbers do not partition the table")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


HYGIENE_FILES = ("cases.json", "sim_cases.json", "matrix_audiodev_m16.json", "anchors/audiodev_m16.json",
                 "anchor_extract.py", "sim_ref.py", "contract_ref.py", "run_cases.py")
ALLOWED_DIGESTS = {anchor_extract.EXPECTED_SHA256, contract_ref.FIXTURE_SHA}


def run_meta_hygiene(c) -> Result:
    """Public-repo hygiene: no network or hardware identifiers, and no hex blob beyond the known digests."""
    problems = []
    ipv4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    mac = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
    longhex = re.compile(r"\b[0-9a-fA-F]{40,}\b")
    for rel in HYGIENE_FILES:
        text = open(os.path.join(HERE, rel), encoding="utf-8").read()
        for rx, what in ((ipv4, "an IPv4 address"), (mac, "a MAC address")):
            hit = rx.search(text)
            if hit:
                problems.append(f"{rel}: {what} {hit.group(0)!r}")
        for blob in longhex.findall(text):
            if blob.lower() not in ALLOWED_DIGESTS and set(blob.lower()) - {"f"}:
                problems.append(f"{rel}: unexpected {len(blob)}-hex blob")
    return (PASS, "") if not problems else (FAIL, "; ".join(problems))


def run_runner_selftest(c) -> Result:
    """The comparison is not vacuous: a corrupted expectation and a corrupted model must both be seen."""
    case = copy.deepcopy(next(x for x in sim_cases() if x["id"] == "E04-SIM-002"))
    if sim_ref.replay(case) is not None:
        return FAIL, "baseline E04-SIM-002 does not pass"
    case["steps"][4]["expect"] = {"result": "ok"}
    seen = sim_ref.replay(case)
    if not seen or seen["step"] != 4:
        return FAIL, f"a corrupted expectation was not detected at step 4: {seen}"
    case = copy.deepcopy(next(x for x in sim_cases() if x["id"] == "E04-SIM-002"))
    case["final"]["submitted"] += 1
    seen = sim_ref.replay(case)
    if not seen or seen["step"] is not None:
        return FAIL, f"a corrupted final state was not detected: {seen}"
    bad = scenario("complete_artifact")
    contract_ref.record(bad, "start")["payload_size"] = contract_ref.unknown("EXT-X", "y")
    if contract_ref.evaluate(bad)["hardware_eligible"]:
        return FAIL, "an unknown field did not block hardware eligibility"
    return PASS, ""


def run_blocked(c) -> Result:
    return BLOCKED, f"{c['blocker']} (owner: {c['owner']}): {c['needs']}"


RUNNERS: Dict[str, Callable[[Dict[str, Any]], Result]] = {
    "ioctl_decode": run_ioctl_decode, "ioctl_encode": run_ioctl_encode, "read_uint": run_read_uint,
    "field_map": run_field_map, "matrix_real": run_matrix_real, "matrix_scenario": run_matrix_scenario,
    "matrix_size_independence": run_size_independence, "sim_trace": run_sim_trace,
    "planted_defect": run_planted_defect, "anchor_facts": run_anchor_facts, "meta_files": run_meta_files,
    "meta_shared_vectors": run_meta_shared_vectors, "meta_log": run_meta_log, "meta_invariants": run_meta_invariants,
    "meta_matrix_vs_anchors": run_meta_matrix_vs_anchors, "meta_hygiene": run_meta_hygiene,
    "runner_selftest": run_runner_selftest, "blocked": run_blocked,
}


# ---------------------------------------------------------------------------------------------- main

def all_cases() -> List[Dict[str, Any]]:
    doc = load_json(CASES_FILE)
    if doc.get("schema") != SCHEMA:
        raise CaseError(f"cases.json schema is {doc.get('schema')!r}, expected {SCHEMA!r}")
    cases = list(doc["cases"])
    for t in sim_cases():
        cases.append({"id": t["id"], "kind": "sim_trace", "tier": "smoke", "trace": t, "title": t["title"]})
    seen = set()
    for c in cases:
        if c["kind"] not in KINDS:
            raise CaseError(f"{c['id']}: unknown kind {c['kind']!r}")
        if c["tier"] not in TIERS:
            raise CaseError(f"{c['id']}: unknown tier {c['tier']!r}")
        if c["id"] in seen:
            raise CaseError(f"duplicate case id {c['id']}")
        seen.add(c["id"])
    return cases


def select(cases, tier: str, only: Optional[str]):
    if only:
        picked = [c for c in cases if c["id"] == only]
        if not picked:
            raise CaseError(f"no case {only!r}")
        return picked
    return [c for c in cases if tier == "full" or c["tier"] == "smoke"]


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="E04 host-side case runner", formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tier", choices=TIERS, default="full")
    ap.add_argument("--case", metavar="ID", help="replay one case")
    ap.add_argument("--list", action="store_true", help="list the selected cases and exit")
    ap.add_argument("--receipts", metavar="DIR", help="write a JSON receipt into DIR")
    args = ap.parse_args(argv)
    try:
        chosen = select(all_cases(), args.tier, args.case)
        if args.list:
            for c in chosen:
                print(f"{c['id']:<18} {c['tier']:<6} {c['kind']}")
            return 0
        results = []
        for c in chosen:
            try:
                status, detail = RUNNERS[c["kind"]](c)
            except CaseError:
                raise
            except Exception as e:  # a crashing case is a failed case, never a skipped one
                status, detail = FAIL, f"crashed: {type(e).__name__}: {e}"
            results.append((c, status, detail))
            tail = f"  {detail}" if detail else ""
            print(f"{status.upper():<7} {c['id']:<18} {c['kind']}{tail}")
    except CaseError as e:
        print(f"E04 runner: {e}", file=sys.stderr)
        return 2
    counts = {s: sum(1 for _, st, _ in results if st == s) for s in (PASS, FAIL, BLOCKED)}
    total = len(results)
    qualified = counts[FAIL] == 0 and counts[BLOCKED] == 0
    print(f"\nE04 {args.tier}: {total} case(s): {counts[PASS]} passed, {counts[FAIL]} failed, {counts[BLOCKED]} blocked"
          f" -- {'QUALIFIED (host simulation only)' if qualified else 'NOT QUALIFIED'}")
    if counts[BLOCKED]:
        print("blocked cases are required invariants nothing here can verify; they are counted, not passed")
    if args.receipts:
        os.makedirs(args.receipts, exist_ok=True)
        art = anchor_extract.default_artifact_path(REPO)
        receipt = {
            "schema": "ffw.e04.receipt.v1", "kind": "host_simulation",
            "command": "tests/e04/run_cases.py " + " ".join(argv),
            "utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": sys.version.split()[0], "tier": args.tier, "denominator": total, "counts": counts,
            "qualified": qualified,
            "inputs": {os.path.relpath(p, REPO): sha256_file(p) for p in (CASES_FILE, SIM_FILE, MATRIX_FILE, ANCHORS_FILE)},
            "artifact_present": bool(art),
            "cases": [{"id": c["id"], "status": st} for c, st, _ in results],
        }
        path = os.path.join(args.receipts, f"e04-{args.tier}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1)
            f.write("\n")
        print(f"receipt: {path}")
    if counts[FAIL]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
