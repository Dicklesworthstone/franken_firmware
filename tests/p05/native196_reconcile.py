#!/usr/bin/env python3
"""P05 AC-3: reconcile the native196 runs against the frozen 196-name registry. Pure Python; no cargo, no network.

    native196_reconcile.py --run STDOUT_LOG EXIT_STATUS [--run STDOUT_LOG EXIT_STATUS ...] [--repo DIR]

It reports `complete` only if every one of the 196 frozen names was reported `ok` exactly once, across all runs given, and every run's
libtest accounting is whole: one `running N tests` section, one `test result: ok.` line with `failed`, `ignored` and `measured` all 0,
`N == passed`, and the run's own exit status 0 (taken from outside the log). `filtered out` is parsed and printed per run, never ignored.
Anything else prints each problem and exits 1. A missing name, a duplicate (in one log or across logs), a name outside the registry,
a `FAILED` or `ignored` test, a truncated log with no summary line, and a conflicting or unattributable result are each a problem.
Exit 0 only for `complete`; 2 for a usage error.

The registry is chosen by its digest, never by a flag. `--registry FILE` takes a file whose sha256 is one of the three pinned ones: the 196
names (the default), the 38 native tests of the P05 runtime probe at its single-owner revision, `native_runtime38_names.txt`
(`94be74e6...`), or the 45 of the probe with its caller-driven profile, `native_runtime45_names.txt` (`52f277cd...`: those 38, unchanged and
in order, then 7); any other file, any of them with one byte changed or reordered included, is a usage error (exit 2) and nothing is
reconciled. For the 38 and the 45 the binary a run may come from is the probe's (`ffw_p05_runtime`), not Asupersync's, and results are
credited by libtest's own totals when `--nocapture` makes them unattributable (see `credit_by_closure`). The 196 path is unchanged: it
never credits an interrupted result.

Reuse, not a fork. The result parser is D01's `Logs` (tests/d01/run_cases.py): it already reads libtest output under `--nocapture`, where
another line can land between `test <name> ... ` and its `ok`. The failure and terminal-line patterns are `audit_check.py`'s
`TERMINAL_FAILURES` and `ANSI` (toolchain/asupersync-cancel-audit/scripts/audit_check.py), the same code that judges the 50-name audit record.
This file adds only what those do not do: the 196-name registry (pinned by digest), exactly-once counting across logs, and the
per-section libtest counts.

The invocations that produce the logs (one test target, `lib`, one feature graph, `default`: see native196_targets.tsv) are, from the
Asupersync repository root, with W an eligible worker. The base is the frozen revision (460306de2aa4 has the same `src/`; it only adds a lockfile):

    B=e1a27c7ba89fb785e84c20f4216c6554a527b9a3
    COMMON='RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_TEST_SLOTS=1 rch exec --worker "$W" --base $B --clean-overlay --no-overlay --'
    ENV='env CARGO_TARGET_DIR=/tmp/rch_target_asup_native196 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0'
    # 1. compile only; safe to re-issue unchanged to continue after a kill, on the same worker and target dir
    $COMMON $ENV cargo +nightly-2026-08-31 test --locked --lib --no-run -j 1
    # 2. execute: no compiler work is left; the nine filters select exactly the 196 (native196_targets.tsv, source enumeration).
    #    No --nocapture: every result stays on one `test <name> ... ok` line, which is what this reconciler credits.
    $COMMON $ENV cargo +nightly-2026-08-31 test --locked --lib --no-fail-fast -j 1 -- \\
        runtime::blocking_pool::admission::tests:: io::stdio::tests:: cx::scoped_race::tests:: cx::scoped_timeout::tests:: \\
        cx::scoped_first_ok::tests:: cx::scoped_quorum::tests:: runtime::legacy_profile::tests:: runtime::spawn_blocking::tests:: \\
        net::resolve::tests:: --test-threads=1

The 38 native tests of the P05 runtime probe (one test binary, `ffw_p05_runtime`) are reconciled the same way, from the repository root, on
the log of the central `cargo test` run for that package and the exit status of that command, taken from outside the log. `--nocapture` may
be used: the probe's transcript tests print between `test <name> ... ` and their `ok`, which the 196 path would refuse; for this registry
only, libtest's own totals credit them (`credit_by_closure`):

    python3 tests/p05/native196_reconcile.py --registry tests/p05/native_runtime38_names.txt --run LOG EXIT_STATUS

A probe that has the caller-driven profile (45 tests, `native_runtime45_names.txt`) is reconciled the same way against its own registry:

    python3 tests/p05/native196_reconcile.py --registry tests/p05/native_runtime45_names.txt --run LOG EXIT_STATUS

A log of one probe is never complete against the other's registry: 38 names are missing from it or 7 are outside it.

A reconcile says which names ran once and `ok`. It decides nothing else about the run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY_FILE = HERE / "native196_names.txt"
REGISTRY_SHA256 = "47c760584d089e3143d6e6a9d79baaf35125a3c52296cf87798b70d73726126f"
LIB_STEMS = (None, "asupersync")    # stdout alone carries no `Running` header (cargo prints it on stderr), so the stem may be None
RUNTIME38_FILE = HERE / "native_runtime38_names.txt"
RUNTIME38_SHA256 = "94be74e65f47711951368d6776a4516699d761333338db5057f881867c679ba1"
RUNTIME38_STEMS = (None, "ffw_p05_runtime")     # the probe's own test binary (package `ffw-p05-runtime`), never Asupersync's
RUNTIME45_FILE = HERE / "native_runtime45_names.txt"
RUNTIME45_SHA256 = "52f277cd4bdc68e2682795c65ebe060ca25de1aa87216cbc1c4184cc86219703"     # the 38 names above, then the 7 caller-driven ones


@dataclass(frozen=True)
class Pinned:
    """A registry the command line accepts: found by the digest of its bytes, with what is true of that registry alone."""
    label: str              # printed before COMPLETE / INCOMPLETE
    sha256: str
    size: int
    stems: tuple            # the test binaries a run may be attributed to
    serial_closure: bool    # credit results `--nocapture` made unattributable, by libtest's own totals (credit_by_closure)


PINNED = (
    Pinned("native196", REGISTRY_SHA256, 196, LIB_STEMS, False),
    Pinned("native_runtime38", RUNTIME38_SHA256, 38, RUNTIME38_STEMS, True),
    Pinned("native_runtime45", RUNTIME45_SHA256, 45, RUNTIME38_STEMS, True),
)

# D01's note for a sorted (one-test-thread) section whose interrupted results it declined to attribute.
SERIAL_NOTE = re.compile(r": a section of (\d+) tests reports in sorted order, which is how libtest runs with one test thread; "
                         r"(\d+) result\(s\) found only by the open-prefix rule were not attributed$")

RESULT = re.compile(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out")
PREFIX = re.compile(r"(?<![A-Za-z0-9_:])test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ")


def _load(path: Path, tag: str):
    if not path.is_file():
        raise SystemExit(f"native196_reconcile: {path} is required (reused, not forked); pass --repo")
    spec = importlib.util.spec_from_file_location(tag, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def find_repo(explicit=None) -> Path:
    for candidate in ([Path(explicit)] if explicit else []) + [HERE.parents[1]]:
        if (candidate / "tests" / "d01" / "run_cases.py").is_file():
            return candidate
    raise SystemExit("native196_reconcile: cannot find the franken_firmware checkout (tests/d01/run_cases.py); pass --repo")


def load_reused(repo: Path):
    d01 = _load(repo / "tests" / "d01" / "run_cases.py", "d01_run_cases_for_native196")
    audit = _load(repo / "toolchain" / "asupersync-cancel-audit" / "scripts" / "audit_check.py", "audit_check_for_native196")
    return d01, audit


def _names(path: Path, data: bytes) -> list:
    names = [line for line in data.decode("utf-8").splitlines() if line.strip()]
    if len(set(names)) != len(names):
        raise ValueError(f"{path.name}: duplicate names in the registry")
    return names


def load_registry(path: Path = REGISTRY_FILE, expected_sha256: str | None = REGISTRY_SHA256) -> list:
    data = path.read_bytes()
    if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"{path.name}: sha256 {hashlib.sha256(data).hexdigest()} is not the frozen {expected_sha256}")
    return _names(path, data)


def load_pinned(path: Path = REGISTRY_FILE) -> tuple:
    """(names, Pinned) for a registry file whose bytes hash to one of the pinned digests; ValueError for any other file."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    for pinned in PINNED:
        if digest == pinned.sha256:
            names = _names(path, data)
            if len(names) != pinned.size:
                raise ValueError(f"{path.name}: {len(names)} names, but the pinned {pinned.label} registry has {pinned.size}")
            return names, pinned
    known = ", ".join(f"{pinned.label} {pinned.sha256}" for pinned in PINNED)
    raise ValueError(f"{path.name}: sha256 {digest} is not a pinned registry ({known})")


@dataclass
class Run:
    path: Path
    exit_status: int

    @property
    def label(self) -> str:
        return self.path.name


@dataclass
class Report:
    problems: list = field(default_factory=list)
    runs: list = field(default_factory=list)
    ok_names: int = 0
    registry: int = 0

    @property
    def complete(self) -> bool:
        return not self.problems


def credit_by_closure(problems: list, statuses: dict, counts: Counter, summary: dict) -> int:
    """Credit the results `--nocapture` made unattributable, from libtest's own totals, or credit none. Returns how many were credited.

    With `--nocapture --test-threads=1` a test that prints puts its output between `test <name> ... ` and its `ok`, and D01 will not guess
    which later line is the token in a sorted, one-thread log: it drops those results and says so. This does not guess either. It credits a
    name only when libtest's own figures close around it, all of these at once, and otherwise changes nothing:
      * the run's only problem is D01's note that it did not attribute K results (any other problem means the run is not trusted);
      * the log has one `running N tests` section and one `test result: ok.` line with failed, ignored and measured all 0;
      * the K names are exactly the names that have a `test <name> ... ` prefix but no attributed result, each prefix once;
      * N == passed == (results D01 attributed) + K, i.e. every test libtest started is accounted for as passed.
    A test that started and failed or was ignored would make `failed`/`ignored` nonzero or show its own token, so it cannot be among the K.
    The credit is the name's prefix plus libtest's totals; it is not a reading of the interrupted line, and the run line says how many."""
    serial = [p for p in problems if SERIAL_NOTE.search(p)]
    if len(serial) != 1 or len(problems) != 1:
        return 0
    interrupted = sorted(name for name in counts if name not in statuses)
    k = int(SERIAL_NOTE.search(serial[0]).group(2))
    passed = summary.get("passed")
    closed = (
        k > 0
        and k == len(interrupted)
        and all(counts[name] == 1 for name in interrupted)
        and summary["results"] == 1
        and len(summary["declared"]) == 1
        and (summary.get("failed"), summary.get("ignored"), summary.get("measured")) == (0, 0, 0)
        and summary["declared"][0] == passed == len(statuses) + k
    )
    if not closed:
        return 0
    problems.clear()
    for name in interrupted:
        statuses[name] = "ok"
    return k


def analyse_run(run: Run, d01, audit, report: Report, size: int = 196, stems: tuple = LIB_STEMS, serial_closure: bool = False):
    """Problems for one run, plus (name -> status) for every name the run reports and the run's raw `test <name> ...` counts."""
    label = run.label
    raw = run.path.read_text(encoding="utf-8", errors="replace")
    text = audit.ANSI.sub("", raw)
    problems = []
    if run.exit_status != 0:
        problems.append(f"{label}: the command exited {run.exit_status}")
    finished = re.findall(r"Remote command finished: exit=(\d+)", text)
    if re.search(r"\brch::", text) and not finished:
        problems.append(f"{label}: an RCH log with no `Remote command finished` line (custody incomplete)")
    problems += [f"{label}: the remote command finished with exit={code}" for code in finished if code != "0"]
    for pattern, why in audit.TERMINAL_FAILURES:
        hit = pattern.search(text)
        if hit:
            problems.append(f"{label}: {why}: {text[hit.start():].split(chr(10), 1)[0][:100]}")

    lines = text.replace("\r\n", "\n").split("\n")
    declared = [int(m.group(1)) for line in lines if (m := d01.SECTION_START.match(line))]
    results = [m for line in lines if (m := RESULT.search(line))]
    summary = {"declared": declared, "results": len(results), "filtered_out": None}
    if len(declared) != 1:
        problems.append(f"{label}: {len(declared)} `running N tests` sections; a `--lib` run has exactly one")
    if not results:
        problems.append(f"{label}: no `test result:` line: the output is truncated or the binary never finished")
    elif len(results) > 1:
        problems.append(f"{label}: {len(results)} `test result:` lines; a `--lib` run has exactly one")
    passed = 0
    if results:
        verdict, passed, failed, ignored, measured, filtered = (results[0].group(1), *(int(results[0].group(i)) for i in range(2, 7)))
        summary.update(passed=passed, failed=failed, ignored=ignored, measured=measured, filtered_out=filtered)
        if verdict != "ok":
            problems.append(f"{label}: `test result: {verdict}.`")
        for what, value in (("failed", failed), ("ignored", ignored), ("measured", measured)):
            if value:
                problems.append(f"{label}: {value} {what}; every one of the {size} must be `ok`, none ignored")
        if len(declared) == 1 and declared[0] != passed + failed + ignored + measured:
            problems.append(f"{label}: announced {declared[0]} tests, accounted for {passed + failed + ignored + measured}")

    # D01 reads the file itself; give it ANSI-free text when the original has escapes.
    if text == raw:
        logs = d01.Logs()
        logs.add(str(run.path))
    else:
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / run.path.name
            clean.write_text(text, encoding="utf-8")
            logs = d01.Logs()
            logs.add(str(clean))
    problems += [f"{label}: {note}" for note in logs.attribution_notes]
    for key in sorted(logs.conflicting_tests, key=str):
        problems.append(f"{label}: conflicting results for {key[1]}")
    statuses = {}
    for (stem, name), status in logs.tests.items():
        if stem not in stems:
            which = "library" if stems == LIB_STEMS else "probe"
            problems.append(f"{label}: {name} was reported by binary `{stem}`, not the {which} test binary")
        statuses[name] = status
    for name in sorted(logs.ambiguous_names):
        problems.append(f"{label}: {name} was reported more than once in this log")
    counts = Counter(PREFIX.findall(text))
    if serial_closure:
        credited = credit_by_closure(problems, statuses, counts, summary)
        if credited:
            summary["credited_by_closure"] = credited
    return problems, statuses, counts, summary, passed


def reconcile(registry: list, runs: list, repo: Path | None = None, pinned: Pinned | None = None) -> Report:
    """`pinned` says what is true of this registry (binary stems, closure); None is the 196 behaviour, exactly as before."""
    d01, audit = load_reused(find_repo(repo))
    report = Report(registry=len(registry))
    wanted = set(registry)
    seen_in = {}                      # name -> [(run label, status)]
    occurrences = Counter()
    total_passed = 0
    for run in runs:
        problems, statuses, counts, summary, passed = analyse_run(
            run, d01, audit, report, len(registry), pinned.stems if pinned else LIB_STEMS, bool(pinned and pinned.serial_closure))
        report.problems += problems
        report.runs.append((run.label, summary))
        total_passed += passed
        occurrences.update(counts)
        for name, status in statuses.items():
            seen_in.setdefault(name, []).append((run.label, status))
    ok = {n for n, rows in seen_in.items() if any(s == "ok" for _, s in rows)}
    missing = sorted(wanted - set(seen_in))
    if missing:
        report.problems.append(f"{len(missing)} registry name(s) never reported, e.g. {missing[:3]}")
    extra = sorted(set(seen_in) - wanted)
    if extra:
        report.problems.append(f"{len(extra)} reported name(s) outside the registry, e.g. {extra[:3]}")
    for name in sorted(wanted & set(seen_in)):
        rows = seen_in[name]
        if len(rows) > 1:
            report.problems.append(f"{name}: reported by {len(rows)} runs {[label for label, _ in rows]}; exactly one is required")
        bad = [s for _, s in rows if s != "ok"]
        if bad:
            report.problems.append(f"{name}: {', '.join(sorted(set(bad)))}, not `ok`")
        if occurrences[name] > 1 and len(rows) == 1:
            report.problems.append(f"{name}: `test {name} ... ` appears {occurrences[name]} times")
    if not missing and not extra and total_passed != len(registry):
        report.problems.append(f"the runs account for {total_passed} passed tests, the registry has {len(registry)}")
    report.ok_names = len(wanted & ok)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", nargs=2, action="append", metavar=("STDOUT_LOG", "EXIT_STATUS"), required=True)
    ap.add_argument("--registry", type=Path, default=REGISTRY_FILE)
    ap.add_argument("--repo", type=Path)
    args = ap.parse_args(argv)
    try:
        registry, pinned = load_pinned(args.registry)
        runs = [Run(Path(path), int(code)) for path, code in args.run]
    except (ValueError, OSError) as error:
        print(f"native196: usage/input error: {error}")
        return 2
    report = reconcile(registry, runs, args.repo, pinned)
    for label, summary in report.runs:
        credited = f" credited_by_closure={summary['credited_by_closure']}" if "credited_by_closure" in summary else ""
        print(f"  {label}: declared={summary['declared']} result_lines={summary['results']} "
              f"passed={summary.get('passed')} failed={summary.get('failed')} ignored={summary.get('ignored')} "
              f"measured={summary.get('measured')} filtered_out={summary['filtered_out']}{credited}")
    if report.complete:
        print(f"{pinned.label}: COMPLETE: {report.ok_names}/{report.registry} names `ok` exactly once across {len(report.runs)} run(s); "
              f"filtered out and ignored are accounted for in the lines above")
        return 0
    print(f"{pinned.label}: INCOMPLETE: {report.ok_names}/{report.registry} names `ok`; {len(report.problems)} problem(s)")
    for problem in report.problems:
        print(f"  - {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
