#!/usr/bin/env python3
"""Q01 (ffw-gmq) end-to-end runner and judge.

    run_cases.py [--list] [--judge LOG [LOG ...]] [--receipts DIR] [--verify-receipt FILE [FILE ...]]

Offline, standard library only; it builds and boots nothing and never invokes cargo.

* META  - always. cases.json is well formed and every unit test of franken-speaker's harness, control adapter and playout adapter is in exactly one
          case (so a test added or removed without the table noticing fails here); the contract's limit-1 table parses; the
          independent digest of silence reproduces the value measured centrally (b40: 400 blocks, 2 channels).
* JUDGE - with ``--judge LOG``: the output of the centrally run ``cargo test -p franken-speaker --features harness --lib --locked --
          --nocapture``. Every test of a case must report ``ok`` in the log. The two measurement tests print one JSON record per
          line (``Q01-MEMBER``, ``Q01-PLANT``); each record is re-derived here (the digest of silence is recomputed, and must agree
          with the counter that says the member rendered only zeros), and the contract's limit-1 table (docs/contracts/q01.md) is
          held to what the records show: a cell that claims *measured* must equal the measurement, a cell that claims *by routing*
          must not be contradicted by it (and is reported as ready to upgrade when it is confirmed).

A case with no observation in the log is ``blocked``: counted, named, never passed. A log is evidence about the build it came from,
not about any device; the campaign is a simulation (docs/contracts/q01.md section 1).

The suite runs only through the centralized RCH path (never on the orchestrator):

    RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p franken-speaker --features harness --lib --locked -- --nocapture
    RCH_REQUIRE_REMOTE=1 rch exec -- cargo clippy -p franken-speaker --features harness --all-targets --locked -- -D warnings

A qualified run's redacted record (``--receipts DIR``) is committed under tests/q01/receipts/. ``--verify-receipt FILE`` re-verifies one
without the raw log (which is not committable): its content hash, its fields, and every record re-derived as for a log, with the contract's
limit-1 table held to it. META always re-verifies every committed receipt and requires that every cell the contract calls ``measured`` is
backed by one, so a measurement claim cannot outlive the evidence behind it.

Exit codes: 0 qualified (every case passed, none blocked), 1 a case or check failed, 3 only blocked cases stand in the way,
2 usage or malformed input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CASES = os.path.join(HERE, "cases.json")
CONTRACT = os.path.join(REPO, "docs", "contracts", "q01.md")
RUST_SOURCES = [
    ("crates/franken-speaker/src/harness.rs", "harness::tests::"),
    ("crates/franken-speaker/src/control_adapter.rs", "control_adapter::tests::"),
    ("crates/franken-speaker/src/playout_adapter.rs", "playout_adapter::tests::"),
]
RECEIPT_SCHEMA = "ffw.q01.measurement.v1"
RECEIPT_DIR = os.path.join(HERE, "receipts")
RECEIPT_NAME = re.compile(r"^q01-measurement-([0-9a-f]{12})\.json$")
RECEIPT_KEYS = {"schema", "bead", "evidence", "logs", "contract_sha256", "cases_sha256", "campaign", "verdicts", "members", "plants",
                "not_measured"}
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
CLASSES = ("positive", "negative", "control", "limit", "measurement")

# The campaign `franken-speaker --virtual-house` runs, and what the two measurement tests run.
SEED = 0x2026_1104
BLOCKS = 250
FRAMES_PER_BLOCK = 256
BYTES_PER_SAMPLE = 2
FNV_BASIS = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
# The fleet, from the board profile rows (docs/contracts/q01.md section 2), restated here and not read from the Rust: member -> channels.
FLEET = {
    "spk-office-s5": 5,
    "spk-bedroom-s1": 2,
    "spk-kitchen-s12": 2,
    "spk-den-s3": 3,
    "spk-living-sub": 1,
}
SIGNALS = ("opposed", "asymmetric")
MEMBER_KEYS = {"signal", "member", "seed", "blocks", "channels", "rendered_blocks",
               "audible_authentic_blocks", "rendered_nonzero_blocks", "digest"}
PLANT_KEYS = {"member", "planted", "outcome", "message"}
PLANT_MESSAGE = re.compile(r"^member_rendered_silence: (\S+): (\d+) authentic blocks sounded and every sample it rendered is zero$")
TEST_LINE = re.compile(r"\btest (\S+) \.\.\. (ok|FAILED|ignored)\b")
# libtest writes `test X ... ` and then its result in two writes; a test thread's --nocapture output can land between them, leaving the
# name with other text after it and the result alone on the next line.
TEST_START = re.compile(r"\btest (\S+) \.\.\.")
RESULT_ALONE = re.compile(r"^(ok|FAILED|ignored)$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RECORD_MARKER = re.compile(r"\bQ01-(MEMBER|PLANT)\b ?(.*?)\s*$")
LIMIT_BEGIN, LIMIT_END = "<!-- q01-limit-1:begin -->", "<!-- q01-limit-1:end -->"
CELL = re.compile(r"^(renders|silent) \((measured|by routing)\)$")
NOT_MEASURED = [
    "any real board, device, provider account, network or kernel (every campaign is a simulation)",
    "the absolute level of any block (the DSP applies gain before the crossover filters)",
    "concealment quality",
]


def silent_digest(blocks: int, channels: int) -> int:
    """FNV-1a over N zero bytes is `basis * prime^N mod 2^64` (every step xors 0, then multiplies by the prime)."""
    n = blocks * channels * FRAMES_PER_BLOCK * BYTES_PER_SAMPLE
    return (FNV_BASIS * pow(FNV_PRIME, n, 1 << 64)) & ((1 << 64) - 1)


# ---- the sources, the case table and the contract ------------------------------------------------------------------------

def rust_test_names(repo: str = REPO) -> List[str]:
    names: List[str] = []
    for rel, prefix in RUST_SOURCES:
        with open(os.path.join(repo, rel), encoding="utf-8") as handle:
            text = handle.read()
        names += [prefix + n for n in re.findall(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+(\w+)", text)]
    return names


def load_cases(path: str = CASES) -> List[dict]:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    if doc.get("schema") != "ffw.q01.cases.v1":
        raise ValueError("cases.json: unknown schema %r" % doc.get("schema"))
    return doc["cases"]


def parse_limit_table(text: str) -> Dict[Tuple[str, str], Tuple[str, str]]:
    """The contract's limit-1 table: (member, signal) -> (behaviour, basis), `renders|silent` and `measured|by routing`."""
    if text.count(LIMIT_BEGIN) != 1 or text.count(LIMIT_END) != 1:
        raise ValueError("the contract must hold exactly one limit-1 table between %s and %s" % (LIMIT_BEGIN, LIMIT_END))
    body = text.split(LIMIT_BEGIN, 1)[1].split(LIMIT_END, 1)[0]
    table: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for line in body.strip().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 3 or cells[0] == "member" or set(cells[0]) <= set("-: "):
            continue
        member = cells[0].strip("`")
        if member not in FLEET:
            raise ValueError("limit-1 table: %r is not a member of the fleet" % member)
        for signal, cell in zip(SIGNALS, cells[1:]):
            match = CELL.match(cell)
            if not match:
                raise ValueError("limit-1 table: cell %r of %s is not `renders|silent (measured|by routing)`" % (cell, member))
            if (member, signal) in table:
                raise ValueError("limit-1 table: %s listed twice" % member)
            table[(member, signal)] = (match.group(1), match.group(2))
    wanted = {(m, s) for m in FLEET for s in SIGNALS}
    if set(table) != wanted:
        raise ValueError("limit-1 table: missing %r" % sorted(wanted - set(table)))
    return table


# ---- the log ------------------------------------------------------------------------------------------------------------

class Log:
    def __init__(self) -> None:
        self.tests: Dict[str, List[str]] = {}
        self.members: List[dict] = []
        self.plants: List[dict] = []
        self.problems: List[str] = []
        # Tests whose name was printed but whose result never was (the log ended, or another test started first): never passed.
        self.unterminated: List[str] = []

    def add(self, text: str, source: str) -> None:
        pending: Optional[str] = None  # a test whose name was printed but whose result was not on the same line
        for number, raw in enumerate(text.splitlines(), 1):
            line = ANSI.sub("", raw)
            found = TEST_LINE.findall(line)
            for name, status in found:
                self.tests.setdefault(name, []).append(status)
            if found:
                if pending is not None:
                    self.unterminated.append(pending)
                pending = None  # a complete line ends any wait
            else:
                started = TEST_START.search(line)
                alone = RESULT_ALONE.match(line.strip())
                if started:
                    if pending is not None:
                        self.unterminated.append(pending)
                    pending = started.group(1)
                elif alone and pending is not None:
                    self.tests.setdefault(pending, []).append(alone.group(1))
                    pending = None
            # Any marker must carry a record that parses: a truncated or interleaved line is a problem, never silently dropped.
            marker = RECORD_MARKER.search(line)
            if marker:
                kind = "Q01-" + marker.group(1)
                try:
                    (self.members if marker.group(1) == "MEMBER" else self.plants).append(json.loads(marker.group(2)))
                except ValueError:
                    self.problems.append("%s:%d: a %s record is not valid JSON" % (source, number, kind))
        if pending is not None:
            self.unterminated.append(pending)

    def status(self, test: str) -> Optional[str]:
        seen = self.tests.get(test)
        if not seen:
            return None
        return seen[0] if len(set(seen)) == 1 else "conflict"


# ---- the records ---------------------------------------------------------------------------------------------------------

def check_members(records: List[dict], table: Dict[Tuple[str, str], Tuple[str, str]], what: str = "the log") -> Tuple[List[str], List[str], Dict[Tuple[str, str], dict]]:
    """Returns (problems, notes, measured): measured maps (member, signal) -> the accepted record."""
    problems: List[str] = []
    notes: List[str] = []
    measured: Dict[Tuple[str, str], dict] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != MEMBER_KEYS:
            problems.append("a Q01-MEMBER record has the keys %r" % (sorted(record) if isinstance(record, dict) else record))
            continue
        member, signal = record["member"], record["signal"]
        where = "%s under %s" % (member, signal)
        ints = [record[k] for k in ("seed", "blocks", "channels", "rendered_blocks", "audible_authentic_blocks", "rendered_nonzero_blocks", "digest")]
        if not (isinstance(member, str) and isinstance(signal, str)) or member not in FLEET or signal not in SIGNALS:
            problems.append("a record names an unknown member or source: %s" % where)
            continue
        if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in ints):
            problems.append("%s: a field is not a non-negative integer" % where)
            continue
        if (member, signal) in measured:
            problems.append("%s: reported twice" % where)
            continue
        issues = []
        if record["seed"] != SEED or record["blocks"] != BLOCKS:
            issues.append("it is not the --virtual-house campaign (seed %#x, %d blocks)" % (SEED, BLOCKS))
        if record["channels"] != FLEET[member]:
            issues.append("%d hardware channels, the profile has %d" % (record["channels"], FLEET[member]))
        if record["rendered_blocks"] != record["blocks"]:
            issues.append("rendered %d of %d blocks" % (record["rendered_blocks"], record["blocks"]))
        if record["rendered_nonzero_blocks"] > record["rendered_blocks"]:
            issues.append("more non-zero blocks than rendered blocks")
        if record["audible_authentic_blocks"] > record["rendered_blocks"]:
            issues.append("more audible authentic blocks than rendered blocks")
        if not issues:
            counter_says_silent = record["rendered_nonzero_blocks"] == 0
            digest_says_silent = record["digest"] == silent_digest(record["blocks"], record["channels"])
            if counter_says_silent != digest_says_silent:
                issues.append("the counter says %s and the digest says %s" % (
                    "silent" if counter_says_silent else "sound", "silent" if digest_says_silent else "sound"))
            if signal == "asymmetric" and (record["audible_authentic_blocks"] == 0 or counter_says_silent):
                issues.append("under the asymmetric source a member must sound and render something (the campaign's own oracle)")
        if issues:
            problems.append("%s: %s" % (where, "; ".join(issues)))
            continue
        measured[(member, signal)] = record
    for member in FLEET:
        for signal in SIGNALS:
            if (member, signal) not in measured and not any(p.startswith("%s under %s" % (member, signal)) for p in problems):
                problems.append("%s under %s: no record" % (member, signal))
    # the contract's limit-1 table is held to the measurement
    for (member, signal), record in sorted(measured.items()):
        got = "silent" if record["rendered_nonzero_blocks"] == 0 else "renders"
        claim, basis = table[(member, signal)]
        if basis == "measured" and got != claim:
            problems.append("docs/contracts/q01.md says %s under %s is %s (measured), %s shows it %s" % (member, signal, claim, what, got))
        elif basis == "by routing" and got != claim:
            problems.append("docs/contracts/q01.md says %s under %s %s (by routing), %s contradicts it: %s" % (member, signal, claim, what, got))
        elif basis == "by routing":
            notes.append("%s under %s: %s, confirmed by measurement; the contract may now say `(measured)`" % (member, signal, got))
    return problems, notes, measured


def check_plants(records: List[dict]) -> List[str]:
    problems: List[str] = []
    controls, planted = [], {}
    for record in records:
        if not isinstance(record, dict) or set(record) != PLANT_KEYS:
            problems.append("a Q01-PLANT record has the keys %r" % (sorted(record) if isinstance(record, dict) else record))
            continue
        if record["planted"] is False:
            controls.append(record)
        elif record["planted"] is True:
            if record["member"] in planted:
                problems.append("the plant on %s is reported twice" % record["member"])
            planted[record["member"]] = record
        else:
            problems.append("a Q01-PLANT record has planted=%r" % (record["planted"],))
    if len(controls) != 1:
        problems.append("expected exactly one remove-the-plant control record, found %d" % len(controls))
    elif controls[0] != {"member": None, "planted": False, "outcome": "ok", "message": None}:
        problems.append("the control (no plant) did not pass: %r" % (controls[0],))
    for member in FLEET:
        record = planted.get(member)
        if record is None:
            problems.append("no record of the plant on %s" % member)
            continue
        match = PLANT_MESSAGE.match(record["message"]) if isinstance(record["message"], str) else None
        if record["outcome"] != "error" or not match:
            problems.append("the plant on %s was not named by the oracle: %r" % (member, record["message"]))
        elif match.group(1) != member:
            problems.append("the plant on %s was reported against %s" % (member, match.group(1)))
        elif not 0 < int(match.group(2)) <= BLOCKS:
            problems.append("the plant on %s names %s authentic blocks" % (member, match.group(2)))
    extra = sorted(set(planted) - set(FLEET))
    if extra:
        problems.append("plants on members that are not in the fleet: %r" % extra)
    return problems


# ---- the cases -----------------------------------------------------------------------------------------------------------

def seal(record: dict) -> str:
    """The 12 hex digits a receipt's file name carries: the start of the sha256 of its canonical JSON."""
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()[:12]


def verify_receipt(path: str, table: Dict[Tuple[str, str], Tuple[str, str]]) -> Tuple[List[str], List[str], Dict[Tuple[str, str], dict]]:
    """Re-verify a committed receipt without the raw log: its seal, its fields, and every record re-derived exactly as for a log, with the
    contract's limit-1 table held to it. Returns (problems, notes, measured)."""
    name = os.path.basename(path)
    problems: List[str] = []
    notes: List[str] = []
    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError) as error:
        return ["%s cannot be read as JSON: %s" % (name, error)], notes, {}
    if not isinstance(record, dict) or set(record) != RECEIPT_KEYS:
        keys = sorted(record) if isinstance(record, dict) else type(record).__name__
        return ["%s has the keys %r, not the receipt's" % (name, keys)], notes, {}
    named = RECEIPT_NAME.match(name)
    if not named:
        problems.append("the file name is not q01-measurement-<12 hex digits>.json")
    elif named.group(1) != seal(record):
        problems.append("the name says %s but the content hashes to %s: the receipt was edited after it was sealed" % (named.group(1), seal(record)))
    if record["schema"] != RECEIPT_SCHEMA:
        problems.append("unknown schema %r" % (record["schema"],))
    if record["bead"] != "ffw-gmq":
        problems.append("it is a receipt for %r, not ffw-gmq" % (record["bead"],))
    if record["evidence"] != "simulation_only":
        problems.append("its evidence class is %r, not simulation_only" % (record["evidence"],))
    if record["campaign"] != {"seed": SEED, "blocks": BLOCKS}:
        problems.append("it is not the --virtual-house campaign: %r" % (record["campaign"],))
    logs = record["logs"]
    if not isinstance(logs, list) or not logs or not all(
            isinstance(l, dict) and set(l) == {"sha256", "bytes"} and isinstance(l["sha256"], str) and SHA256_HEX.match(l["sha256"])
            and isinstance(l["bytes"], int) and not isinstance(l["bytes"], bool) and l["bytes"] > 0 for l in logs):
        problems.append("it does not name its log(s) by sha256 and size")
    verdicts = record["verdicts"]
    if not isinstance(verdicts, dict) or not verdicts or any(v != "pass" for v in verdicts.values()):
        bad = sorted(k for k, v in verdicts.items() if v != "pass") if isinstance(verdicts, dict) else []
        problems.append("a receipt records only qualified runs; verdicts that are not pass: %r" % (bad or "none recorded"))
    elif isinstance(verdicts, dict):
        current = {c["id"] for c in load_cases()}
        if set(verdicts) != current:
            notes.append("it was judged against an earlier case table (verdicts for %d cases, the table has %d)" % (len(verdicts), len(current)))
    if not isinstance(record["not_measured"], list) or not record["not_measured"]:
        problems.append("it does not say what is not measured")
    measured: Dict[Tuple[str, str], dict] = {}
    if isinstance(record["members"], list):
        member_problems, member_notes, measured = check_members(record["members"], table, what="the receipt")
        problems += member_problems
        notes += member_notes
    else:
        problems.append("members is not a list")
    if isinstance(record["plants"], list):
        problems += check_plants(record["plants"])
    else:
        problems.append("plants is not a list")
    if record["contract_sha256"] != sha256_file(CONTRACT):
        notes.append("it was judged against an earlier text of the contract (expected once a cell has been flipped to measured)")
    if record["cases_sha256"] != sha256_file(CASES):
        notes.append("it was judged against an earlier case table")
    return problems, notes, measured


def receipt_files(directory: str = RECEIPT_DIR) -> List[str]:
    if not os.path.isdir(directory):
        return []
    return sorted(os.path.join(directory, n) for n in os.listdir(directory) if n.endswith(".json"))


def check_receipts(directory: str, table: Dict[Tuple[str, str], Tuple[str, str]]) -> Tuple[List[str], str]:
    """Every committed receipt verifies, and every cell the contract calls `measured` is backed by one that does."""
    files = receipt_files(directory)
    covered = set()
    problems: List[str] = []
    for path in files:
        found, _notes, measured = verify_receipt(path, table)
        problems += ["%s: %s" % (os.path.basename(path), p) for p in found]
        if not found:
            covered |= set(measured)
    claimed = {cell for cell, (_behaviour, basis) in table.items() if basis == "measured"}
    unbacked = sorted(claimed - covered)
    if unbacked:
        problems.append("%d cell(s) the contract calls measured have no verified receipt behind them: %s" % (len(unbacked), unbacked[:4]))
    return problems, "%d receipt(s) verify and back all %d measured cells" % (len(files), len(claimed))


class Result:
    def __init__(self, case: str, status: str, detail: str) -> None:
        self.case, self.status, self.detail = case, status, detail


def meta_results() -> List[Result]:
    out: List[Result] = []

    def note(case: str, problem: Optional[str], ok: str) -> None:
        out.append(Result(case, "fail" if problem else "pass", problem or ok))

    try:
        cases = load_cases()
        names = rust_test_names()
        mapped = [t for c in cases for t in c["tests"]]
        problem = None
        ids = [c["id"] for c in cases]
        if len(set(ids)) != len(ids):
            problem = "case ids are not unique"
        elif any(c["class"] not in CLASSES for c in cases):
            problem = "a case has an unknown class"
        elif sorted(set(mapped) - set(names)):
            problem = "mapped tests that are not in the sources: %r" % sorted(set(mapped) - set(names))[:5]
        elif sorted(set(names) - set(mapped)):
            problem = "unit tests that no case covers: %r" % sorted(set(names) - set(mapped))[:5]
        elif len(mapped) != len(set(mapped)):
            problem = "a test is in two cases"
        note("META-CASES", problem, "%d cases cover all %d unit tests of the harness, the control adapter and the playout adapter, each once" % (len(cases), len(names)))
    except (OSError, ValueError, KeyError) as error:
        note("META-CASES", "cannot load the case table or the sources: %s" % error, "")
    try:
        with open(CONTRACT, encoding="utf-8") as handle:
            text = handle.read()
        table = parse_limit_table(text)
        missing = [m for m in FLEET if "`%s`" % m not in text]
        note("META-CONTRACT", ("the contract does not name %r" % missing) if missing else None,
             "the limit-1 table parses: %d cells for %d members; every fleet member is named" % (len(table), len(FLEET)))
    except (OSError, ValueError) as error:
        note("META-CONTRACT", str(error), "")
    try:
        with open(CONTRACT, encoding="utf-8") as handle:
            contract_table = parse_limit_table(handle.read())
        receipt_problems, receipt_summary = check_receipts(RECEIPT_DIR, contract_table)
        note("META-RECEIPTS", "; ".join(receipt_problems[:3]) if receipt_problems else None, receipt_summary)
    except (OSError, ValueError) as error:
        note("META-RECEIPTS", str(error), "")
    anchor = silent_digest(400, 2)
    note("META-DIGEST", None if anchor == 5755000421370241829 else "the digest of silence is %d, b40 measured 5755000421370241829" % anchor,
         "the independent digest of 400 blocks of 2-channel silence is 5755000421370241829, the value measured centrally in b40")
    return out


def judge_cases(log: Optional[Log]) -> Tuple[List[Result], List[str], Dict[Tuple[str, str], dict]]:
    cases = load_cases()
    with open(CONTRACT, encoding="utf-8") as handle:
        table = parse_limit_table(handle.read())
    results: List[Result] = []
    notes: List[str] = []
    measured: Dict[Tuple[str, str], dict] = {}
    record_problems: Dict[str, List[str]] = {}
    if log is not None:
        member_problems, notes, measured = check_members(log.members, table)
        if log.unterminated:
            notes = notes + ["%d test(s) printed their name and no result (they are blocked, never passed): %s"
                             % (len(log.unterminated), ", ".join(sorted(set(log.unterminated))[:3]))]
        record_problems["Q01-M01"] = member_problems + [p for p in log.problems if "Q01-MEMBER" in p]
        record_problems["Q01-M02"] = check_plants(log.plants) + [p for p in log.problems if "Q01-PLANT" in p]
    for case in cases:
        if log is None:
            results.append(Result(case["id"], "blocked", "no log was given"))
            continue
        statuses = {t: log.status(t) for t in case["tests"]}
        failed = [t for t, s in statuses.items() if s in ("FAILED", "conflict")]
        absent = [t for t, s in statuses.items() if s in (None, "ignored")]
        if failed:
            results.append(Result(case["id"], "fail", "%d of %d tests did not pass: %s" % (len(failed), len(statuses), ", ".join(failed[:3]))))
        elif absent:
            results.append(Result(case["id"], "blocked", "%d of %d tests are not in the log: %s" % (len(absent), len(statuses), ", ".join(absent[:3]))))
        elif record_problems.get(case["id"]):
            results.append(Result(case["id"], "fail", "the records do not re-derive: " + " | ".join(record_problems[case["id"]][:4])))
        else:
            results.append(Result(case["id"], "pass", "%d tests ok" % len(statuses)))
    return results, notes, measured


def exit_code(results: List[Result]) -> int:
    if any(r.status == "fail" for r in results):
        return 1
    if any(r.status == "blocked" for r in results):
        return 3
    return 0


def report(results: List[Result], notes: List[str], measured: Dict[Tuple[str, str], dict]) -> None:
    for r in results:
        print("%-8s %-8s %s" % (r.case, r.status.upper(), r.detail))
    counts = {s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "blocked")}
    print("cases: %(pass)d passed, %(fail)d failed, %(blocked)d blocked" % counts)
    if measured:
        print("\nmeasured (campaign seed %#x, %d blocks):" % (SEED, BLOCKS))
        print("  %-18s %-11s %9s %9s  %s" % ("member", "source", "audible", "non-zero", "digest"))
        for (member, signal), rec in sorted(measured.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            print("  %-18s %-11s %9d %9d  %d%s" % (member, signal, rec["audible_authentic_blocks"], rec["rendered_nonzero_blocks"], rec["digest"],
                                                  "  (silence)" if rec["rendered_nonzero_blocks"] == 0 else ""))
    for n in notes:
        print("note:", n)
    print("not measured here:", "; ".join(NOT_MEASURED))


def sha256_file(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def write_receipt(directory: str, logs: List[Tuple[str, str, int]], results: List[Result], measured: Dict[Tuple[str, str], dict],
                  plants: List[dict]) -> str:
    """A redacted verified record: no raw log text, no paths; the logs are named by sha256 only."""
    record = {
        "schema": RECEIPT_SCHEMA,
        "bead": "ffw-gmq",
        "evidence": "simulation_only",
        "logs": [{"sha256": digest, "bytes": size} for _name, digest, size in logs],
        "contract_sha256": sha256_file(CONTRACT),
        "cases_sha256": sha256_file(CASES),
        "campaign": {"seed": SEED, "blocks": BLOCKS},
        "verdicts": {r.case: r.status for r in results},
        "members": [measured[k] for k in sorted(measured, key=lambda k: (k[1], k[0]))],
        "plants": plants,
        "not_measured": NOT_MEASURED,
    }
    name = "q01-measurement-%s.json" % seal(record)
    path = os.path.join(directory, name)
    if os.path.exists(path):
        raise FileExistsError(path)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--list", action="store_true", help="print the case ids and what each shows")
    parser.add_argument("--judge", nargs="+", metavar="LOG", help="judge the centrally run cargo test output")
    parser.add_argument("--receipts", metavar="DIR", help="with --judge: write the redacted verified record into this existing directory")
    parser.add_argument("--verify-receipt", nargs="+", metavar="FILE", help="re-verify committed receipts against the contract (no raw log needed)")
    args = parser.parse_args(argv)
    if args.receipts and not args.judge:
        parser.error("--receipts needs --judge")
    if args.verify_receipt and (args.judge or args.receipts or args.list):
        parser.error("--verify-receipt stands alone")
    if args.verify_receipt:
        try:
            with open(CONTRACT, encoding="utf-8") as handle:
                table = parse_limit_table(handle.read())
        except (OSError, ValueError) as error:
            print("cannot read the contract's limit-1 table: %s" % error, file=sys.stderr)
            return 2
        code = 0
        for receipt in args.verify_receipt:
            found, notes, measured = verify_receipt(receipt, table)
            print("%s: %s (%d of %d cells)" % (os.path.basename(receipt), "FAIL" if found else "PASS", len(measured), len(table)))
            for p in found:
                print("  problem:", p)
            for n in notes:
                print("  note:", n)
            code = 1 if found else code
        return code
    if args.list:
        for case in load_cases():
            print("%-8s %-12s %-11s %s" % (case["id"], case["group"], case["class"], case["what"]))
        return 0
    log: Optional[Log] = None
    logs: List[Tuple[str, str, int]] = []
    if args.judge:
        log = Log()
        for path in args.judge:
            try:
                with open(path, "rb") as handle:
                    raw = handle.read()
                log.add(raw.decode("utf-8", errors="replace"), os.path.basename(path))
                logs.append((os.path.basename(path), hashlib.sha256(raw).hexdigest(), len(raw)))
            except OSError as error:
                print("cannot read %s: %s" % (path, error), file=sys.stderr)
                return 2
    results = meta_results()
    meta_failed = any(r.status == "fail" for r in results)
    for r in results:
        print("%-14s %-6s %s" % (r.case, r.status.upper(), r.detail))
    if meta_failed:
        return 1
    judged, notes, measured = judge_cases(log)
    print()
    report(judged, notes, measured)
    code = exit_code(judged)
    if args.receipts and log is not None:
        if not os.path.isdir(args.receipts):
            print("--receipts: %s is not an existing directory" % args.receipts, file=sys.stderr)
            return 2
        print("receipt:", write_receipt(args.receipts, logs, judged, measured, log.plants))
    return code


if __name__ == "__main__":
    sys.exit(main())
