"""P02's connection to the shared Q00 diagnostic sink (bead ffw-jub, the bead's "Logging" and "bounded redacted failure diagnostics" clauses).

This is an ADAPTER and nothing else, the same shape as `tests/n01/case_log.py`, `tests/d01/case_log.py` and `tests/p01/case_log.py`. It loads the existing
`scripts/test/test_support/diagnostics.py` by explicit path (one module object per file, fail closed) and uses its `DiagnosticSink`
(`ff.diag.v1` JSONL: monotonic timebase, run and case ids, bounded event rate, memory and disk, counted drops, redaction), its loss
accounting and its independent `audit_log` as they are. It adds no logger, no schema and no counter of its own.

What it connects: every case the P02 runner decides (the clause map check, the Python cross-checks, an acceptance clause backed by named Rust tests,
passed, failed or blocked alike) writes a CRITICAL `case.begin` and a CRITICAL `case.end` event (status, bounded detail), and the run ends with one
CRITICAL `run.summary`. Critical events bypass the sink's rate limit and have a reserved slice of its disk budget. If one is lost anyway,
or the log is torn, unreadable, never closed or hung, `Evidence.complete` is False and the judge will not call the run qualified.
Nothing here can change a case's verdict: `emit()` never blocks, never raises and never performs I/O, so a slow, full or unavailable log
costs evidence, not a verdict.

Where the log goes: next to the receipt (`--receipts DIR` -> `DIR/p02-diag-<tier>-<run id>.jsonl`, created exclusively, so a rerun never
overwrites the first run's evidence). With no receipts directory the same sink writes into a fresh `mkdtemp` directory that is audited and KEPT (the runner never deletes it,
the standing no-deletion rule), so the loss handling runs on every execution and the evidence of every run survives.

The header of the log carries the run's versions and artifact digests (`header_extra`), so the file alone says what was judged.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
import tempfile
from typing import Any, Dict, List, Mapping, Optional

DIAG_REL = os.path.join("scripts", "test", "test_support", "diagnostics.py")
MODULE_NAME = "ffw_diagnostics"  # the name scripts/test/run-suite and tests/p01/case_log.py load the same file under
NEEDED = ("DiagnosticSink", "SinkLimits", "audit_log", "audit_bytes", "format_summary")
DETAIL_CAP = 600  # characters of a case's detail kept in its `case.end` event (the printed line and the receipt keep all of it)
# Critical events a run must show in the log when nothing was lost: one begin and one end per recorded case, and the run summary.
# The sink accounts for its own losses; this is the count the judge expects independently of that accounting.
PER_CASE_CRITICAL = 2
RUN_CRITICAL = 1
LEVELS = {"passed": "info", "blocked": "warn", "failed": "error"}


class LogUnavailable(Exception):
    """The shared diagnostics module cannot be loaded; the run goes on, without evidence, and is not qualified."""


def load(repo: str) -> Any:
    path = os.path.join(repo, DIAG_REL)
    if not os.path.isfile(path):
        raise LogUnavailable(f"{DIAG_REL} is missing")
    have = sys.modules.get(MODULE_NAME)
    if have is not None and os.path.realpath(getattr(have, "__file__", "") or "") == os.path.realpath(path):
        return have
    spec = importlib.util.spec_from_file_location(MODULE_NAME, path)
    if spec is None or spec.loader is None:
        raise LogUnavailable(f"cannot load {DIAG_REL}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as err:  # noqa: BLE001 - a module that does not import is an unavailable log, never a crash of the judge
        sys.modules.pop(MODULE_NAME, None)
        raise LogUnavailable(f"{DIAG_REL} failed to import: {type(err).__name__}") from err
    missing = [name for name in NEEDED if not hasattr(mod, name)]
    if missing:
        raise LogUnavailable(f"{DIAG_REL} lacks {', '.join(missing)}")
    return mod


@dataclasses.dataclass
class Evidence:
    """What the run's log shows, read back from the log itself. `complete` False means qualification is invalid."""
    complete: bool
    reasons: List[str]
    summary: str                      # one human line (`format_summary` of the audit)
    log: Optional[Dict[str, Any]]     # the `log` block of a receipt (sha256, events, dropped, bytes, truncated, critical_lost)
    sink: Optional[Dict[str, Any]]    # `ff.diag.summary.v1`
    path: Optional[str]               # where the log was kept, or None when it was a temporary file or an injected target


class CaseLog:
    def __init__(self, diag: Any, sink: Any, run_id: str, tier: str, path: Optional[str], target: Any,
                 temp: Optional[tempfile.TemporaryDirectory], problem: str = "") -> None:
        self.diag, self.sink, self.run_id, self.tier = diag, sink, run_id, tier
        self.path, self.target, self._temp, self.problem = path, target, temp, problem
        self.kept = target is None  # a file log (under the receipts directory or a kept mkdtemp directory) outlives the run; an injected target has no file
        self.cases = 0

    @classmethod
    def open(cls, repo: str, run_id: str, tier: str, receipts: Optional[str] = None, target: Any = None, limits: Any = None,
             clock_ns: Any = None, header_extra: Optional[Mapping[str, Any]] = None) -> "CaseLog":
        """A log for one run. `target` (a `FaultableSink`, a test double with recorded faults) replaces the file; `limits` and `clock_ns`
        are the sink's own parameters, passed through."""
        try:
            diag = load(repo)
        except LogUnavailable as err:
            return cls(None, None, run_id, tier, None, None, None, problem=f"diagnostics_unavailable:{err}")
        temp = None
        path = None
        if target is None:
            if receipts:
                try:
                    os.makedirs(receipts, exist_ok=True)
                except OSError as err:  # a receipts directory that cannot be made is a log that cannot be kept, not a crash
                    return cls(diag, None, run_id, tier, None, None, None, problem=f"receipts_unavailable:{type(err).__name__}")
                path = os.path.join(receipts, f"p02-diag-{tier}-{run_id}.jsonl")
            else:
                try:
                    path = os.path.join(tempfile.mkdtemp(prefix="p02-diag-"), "diag.jsonl")
                except OSError as err:  # no place to keep a log is a log that cannot be kept, not a crash
                    return cls(diag, None, run_id, tier, None, None, None, problem=f"tempdir_unavailable:{type(err).__name__}")
        kw: Dict[str, Any] = {"run_id": f"p02-{tier}-{run_id}"[:64]}
        if limits is not None:
            kw["limits"] = limits
        if clock_ns is not None:
            kw["clock_ns"] = clock_ns
        if header_extra:
            kw["header_extra"] = dict(header_extra)
        try:
            sink = diag.DiagnosticSink(target, **kw) if target is not None else diag.DiagnosticSink.to_file(path, **kw)
        except Exception as err:  # noqa: BLE001 - a sink that cannot be built is a log that cannot be kept
            return cls(diag, None, run_id, tier, path, None, temp, problem=f"sink_unavailable:{type(err).__name__}")
        return cls(diag, sink, run_id, tier, path, target, temp)

    # ---- events: each a fire-and-forget, bounded, redacting call into the shared sink

    def record(self, case_id: str, group: str, status: str, detail: str) -> None:
        """One decided case: a begin and an end, both critical, tied by a correlation id."""
        if self.sink is None:
            return
        self.cases += 1
        corr = f"{self.run_id}.{case_id}"
        self.sink.emit("case.begin", critical=True, case_id=case_id, correlation_id=corr, fields={"group": group, "tier": self.tier})
        text = detail if len(detail) <= DETAIL_CAP else detail[:DETAIL_CAP] + f"...[{len(detail) - DETAIL_CAP} more chars]"
        self.sink.emit("case.end", level=LEVELS.get(status, "error"), critical=True, case_id=case_id, correlation_id=corr,
                       fields={"group": group, "status": status, "detail": text})

    def finish(self, totals: Dict[str, int]) -> Evidence:
        """Write the run summary, close the sink, and read the log back. The verdict is the sink's own (`close()`), checked against the
        independent re-read of the file (`audit_log`) and against the number of critical events this run must have produced."""
        if self.sink is None:
            return Evidence(False, [self.problem or "no_log"], "diag: NO LOG (evidence INCOMPLETE)", None, None, None)
        self.sink.emit("run.summary", critical=True, level="info", fields=dict(totals, tier=self.tier, cases=self.cases))
        verdict = self.sink.close()
        if self.path is not None:
            audit = self.diag.audit_log(self.path)
        else:
            audit = self.diag.audit_bytes(bytes(getattr(self.target, "data", b"")))
        reasons = list(dict.fromkeys(list(verdict.reasons) + list(audit.reasons)))
        expected = PER_CASE_CRITICAL * self.cases + RUN_CRITICAL
        if audit.complete and verdict.complete and audit.critical_events != expected:
            reasons.append(f"critical_event_count:{audit.critical_events}_of_{expected}")
        complete = verdict.complete and audit.complete and not reasons
        out = Evidence(complete, reasons, self.diag.format_summary(audit), audit.receipt_log_block(),
                       self.sink.summary_record(), self.path if self.kept else None)
        return out
