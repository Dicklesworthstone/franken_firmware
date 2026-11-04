#!/usr/bin/env python3
"""Independent sample/state oracles, replay schedules and planted-defect canaries.

Q00 / ffw-2qz foundation module.  Standard library only: it imports no future
production crate and no sibling test-support module, so it bootstraps before
P01 integrates the workspace.  P01 and later consumers extend the registry.

What this module is
-------------------
* Oracles judge a structured *event trace*.  They never parse log text, so no
  functional verdict can depend on a log line surviving.
* An oracle is independent of the device under test (DUT) in two ways:
  - sample values are checked against a stateless seeded reference signal,
    not against the DUT's own frame counters;
  - authority epochs, command issue/delivery and prerequisite state come from
    *truth* events emitted by the harness or an independent probe, never from
    the DUT's own claims about them.
* An oracle that saw nothing, was never finalised, or lost tracking state
  reports ``incomplete``.  It never reports ``passed`` on absence of evidence.
* Every oracle is bounded: retained violations are capped (the true count is
  kept), and command tracking is capped (overflow makes the verdict
  ``incomplete``).

Trace vocabulary
----------------
Every event is a mapping with ``kind`` (str), ``t_ns`` (int, monotonic across
the whole trace) and an optional ``cause`` (str id of the scheduled event that
provoked it).  Identifiers (``scope``, ``command_id``, prerequisite names) are
opaque and must already be pseudonymous; audio payloads must never be real
programme material.

Truth events (harness / independent probe):
  authority_epoch {scope, epoch}      command_issued {command_id, scope, epoch}
  command_delivered {command_id}      prereq_state {name, satisfied}
  stop_requested {}

DUT observations:
  audio_block {stream?, start_frame, channels, samples}   (interleaved int16)
  audio_gap {stream?, start_frame, frame_count, reason}   (announced concealment)
  command_applied {command_id}   command_rejected {command_id, reason}
  ready_announced {}             ready_withdrawn {}

Ordering rule: events at the same ``t_ns`` are ordered truth first, DUT second.
``command_applied`` must be timestamped at the atomic fence-check/apply point.

Verdicts use schema ``ffw.oracle_verdict.v1`` with status ``passed``, ``failed``
or ``incomplete``.  ``receipt_outcome`` maps onto the receipt vocabulary
(``pass`` / ``fail`` / ``blocked``): an incomplete oracle is *blocked*, a distinct
typed outcome, never a failure that could satisfy an expected-failure canary.

Runner contract (``ffw.case-result.v1``)
----------------------------------------
``replay --defect D`` and ``positive --oracle O`` write ``$FFW_RESULT_PATH``
(atomic tmp + rename, <= 256 KiB) when that variable is set; the seed comes
from ``--seed`` or ``$FFW_SEED``.  A planted-defect replay reports ``fail`` under
the exact corresponding oracle name (exit 1) only if that oracle caught the
defect with the expected first violation kind.  An incomplete oracle reports
``fail`` under ``<oracle>.incomplete`` with ``checks`` and ``mismatches`` both 0
and exit 2: it carries a different identity and exit code from any expected
defect, and no mismatch is manufactured from missing evidence.

Limits (tests do not prove perfection): the canary endpoints are deliberately
minimal models.  They show that each oracle rejects its planted defect and
accepts the paired good behaviour; they say nothing about a real device.

Replay: ``python3 oracles.py replay --seed N [--defect NAME]`` re-derives the
schedule, trace and verdicts from the seed alone.  Exit codes: 0 passed,
1 failed, 2 incomplete or usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SCHEMA_VERDICT = "ffw.oracle_verdict.v1"
SCHEMA_REPORT = "ffw.oracle_report.v1"
SCHEMA_SCHEDULE = "ffw.oracle_schedule.v1"
SCHEMA_CANARY = "ffw.oracle_canary.v1"

PASSED = "passed"
FAILED = "failed"
INCOMPLETE = "incomplete"

# Mapping onto the receipt vocabulary (receipts.py OUTCOMES).  Incomplete
# evidence is "blocked" with a reason, not a failure: it must never be able to
# satisfy a canary that expects one specific defect.
RECEIPT_OUTCOME = {PASSED: "pass", FAILED: "fail", INCOMPLETE: "blocked"}

RESULT_SCHEMA = "ffw.case-result.v1"
MAX_RESULT_BYTES = 256 * 1024
# receipts.py ORACLE_KINDS: the judgement each oracle makes.
ORACLE_KIND = {"sample": "sample", "epoch": "state", "command": "state", "readiness": "state", "priority_stop": "sample"}

DEFAULT_REQUIRED = ("board_profile_verified", "amplifier_muted_until_primed", "clock_locked")

INT16_MIN = -32768
INT16_MAX = 32767

_MISSING = object()


class OracleUsageError(ValueError):
    """The harness fed an oracle something no correct harness can produce."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ref(event: Mapping[str, Any]) -> Optional[str]:
    """Causal reference of an event: its ``cause`` (DUT events point at the
    scheduled event that provoked them) or, for truth events, their own ``id``."""
    for key in ("cause", "id"):
        value = event.get(key)
        if isinstance(value, str):
            return value
    return None


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Deterministic randomness: SplitMix64 and a random-access reference signal.
# ---------------------------------------------------------------------------

MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15


def mix64(z: int) -> int:
    z &= MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


class SplitMix64:
    """Sequential SplitMix64; same constants as the Rust-side generator."""

    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next_u64(self) -> int:
        self.state = (self.state + GOLDEN) & MASK64
        return mix64(self.state)

    def below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("below() needs a positive bound")
        return self.next_u64() % n

    def chance_bps(self, bps: int) -> bool:
        """True with probability bps / 10_000 (always consumes one draw)."""
        return self.below(10_000) < bps


def _check_seed(seed: Any) -> int:
    if not _is_int(seed) or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    return seed


def derive_seed(seed: int, label: str) -> int:
    """Domain-separated sub-seed so adding a new domain never reshuffles another."""
    _check_seed(seed)
    digest = hashlib.sha256(f"ffw.oracles.v1:{seed}:{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


class ReferenceSignal:
    """Stateless random-access programme signal (synthetic, never real audio).

    ``sample(frame, channel)`` is the n-th SplitMix64 output of the stream key
    with ``n = frame * channels + channel``, top 16 bits as signed int16.  Any
    block can be verified in any order without trusting the DUT's counters.
    """

    def __init__(self, seed: int, stream: str = "main", channels: int = 2) -> None:
        if not _is_int(channels) or not 1 <= channels <= 8:
            raise ValueError("channels must be 1..8")
        self.channels = channels
        self.stream = stream
        self._key = derive_seed(seed, "signal:" + stream)

    def sample(self, frame: int, channel: int) -> int:
        n = frame * self.channels + channel
        value = mix64((self._key + (n + 1) * GOLDEN) & MASK64) >> 48
        return value - 65536 if value >= 32768 else value

    def block(self, start_frame: int, frames: int) -> List[int]:
        ch = self.channels
        return [self.sample(f, c) for f in range(start_frame, start_frame + frames) for c in range(ch)]


# ---------------------------------------------------------------------------
# Violations and the oracle base class.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Violation:
    oracle: str
    kind: str
    event_index: int
    t_ns: Optional[int]
    cause: Optional[str]
    expected: Dict[str, Any]
    observed: Dict[str, Any]
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle": self.oracle,
            "kind": self.kind,
            "event_index": self.event_index,
            "t_ns": self.t_ns,
            "cause": self.cause,
            "expected": self.expected,
            "observed": self.observed,
            "detail": self.detail,
        }


class Oracle:
    """Base: ordinal/time bookkeeping, bounded violations, fail-closed verdicts."""

    name = "oracle"
    HANDLES: Dict[str, str] = {}

    def __init__(self, *, max_violations: int = 32, allow_empty: bool = False) -> None:
        if not _is_int(max_violations) or max_violations < 1:
            raise ValueError("max_violations must be >= 1")
        self._max_violations = max_violations
        self._allow_empty = allow_empty
        self._ordinal = -1
        self._last_t: Optional[int] = None
        self._relevant = 0
        self._ignored = 0
        self._violations: List[Violation] = []
        self._violation_count = 0
        self._kinds: Dict[str, int] = {}
        self._incomplete: List[str] = []
        self._finalized = False
        self._cur: Optional[Mapping[str, Any]] = None

    # -- hooks -------------------------------------------------------------
    def _accepts(self, event: Mapping[str, Any]) -> bool:
        return True

    def _on_time(self, t_ns: int) -> None:
        return None

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        return None

    def _stats(self) -> Dict[str, Any]:
        return {}

    # -- feeding -----------------------------------------------------------
    def observe(self, event: Mapping[str, Any]) -> None:
        if self._finalized:
            raise OracleUsageError(f"{self.name}: observe() after finalize()")
        if not isinstance(event, Mapping):
            raise OracleUsageError(f"{self.name}: event must be a mapping")
        kind = event.get("kind")
        t_ns = event.get("t_ns")
        if not isinstance(kind, str) or not kind:
            raise OracleUsageError(f"{self.name}: event needs a non-empty string 'kind'")
        if not _is_int(t_ns) or t_ns < 0:
            raise OracleUsageError(f"{self.name}: event needs a non-negative integer 't_ns'")
        if self._last_t is not None and t_ns < self._last_t:
            raise OracleUsageError(
                f"{self.name}: time went backwards ({t_ns} < {self._last_t}) at event {self._ordinal + 1}"
            )
        self._ordinal += 1
        self._last_t = t_ns
        self._cur = event
        self._on_time(t_ns)
        handler = self.HANDLES.get(kind)
        if handler is None or not self._accepts(event):
            self._ignored += 1
            return
        self._relevant += 1
        getattr(self, handler)(event)

    def finalize(self, *, end_t_ns: Optional[int] = None) -> Dict[str, Any]:
        if self._finalized:
            return self.verdict()
        if end_t_ns is not None:
            if not _is_int(end_t_ns) or end_t_ns < 0:
                raise OracleUsageError(f"{self.name}: end_t_ns must be a non-negative integer")
            if self._last_t is not None and end_t_ns < self._last_t:
                raise OracleUsageError(f"{self.name}: end_t_ns precedes the last event")
        self._cur = None
        self._on_finalize(end_t_ns)
        if self._relevant == 0 and not self._allow_empty:
            self._add_incomplete("no_evidence")
        self._finalized = True
        return self.verdict()

    # -- reporting ---------------------------------------------------------
    def _add_incomplete(self, reason: str) -> None:
        if reason not in self._incomplete:
            self._incomplete.append(reason)

    def _violate(
        self,
        kind: str,
        *,
        expected: Mapping[str, Any],
        observed: Mapping[str, Any],
        detail: str,
        event_index: Optional[int] = None,
        t_ns: Optional[int] = None,
        cause: Any = _MISSING,
    ) -> None:
        self._violation_count += 1
        self._kinds[kind] = self._kinds.get(kind, 0) + 1
        if len(self._violations) >= self._max_violations:
            return
        cur = self._cur or {}
        if cause is _MISSING:
            cause = _ref(cur)
        self._violations.append(
            Violation(
                oracle=self.name,
                kind=kind,
                event_index=self._ordinal if event_index is None else event_index,
                t_ns=cur.get("t_ns") if t_ns is None else t_ns,
                cause=cause if isinstance(cause, str) else None,
                expected=dict(expected),
                observed=dict(observed),
                detail=detail,
            )
        )

    def verdict(self) -> Dict[str, Any]:
        reasons = list(self._incomplete)
        if not self._finalized:
            reasons.insert(0, "not_finalized")
        if self._violation_count:
            status = FAILED
        elif reasons:
            status = INCOMPLETE
        else:
            status = PASSED
        return {
            "schema": SCHEMA_VERDICT,
            "oracle": self.name,
            "status": status,
            "receipt_outcome": RECEIPT_OUTCOME[status],
            "finalized": self._finalized,
            "events_seen": self._ordinal + 1,
            "events_relevant": self._relevant,
            "events_ignored": self._ignored,
            "violation_count": self._violation_count,
            "violation_kinds": dict(sorted(self._kinds.items())),
            "violations_retained": len(self._violations),
            "violations_dropped": self._violation_count - len(self._violations),
            "incomplete_reasons": reasons,
            "stats": self._stats(),
            "violations": [v.to_dict() for v in self._violations],
        }

    # -- field access ------------------------------------------------------
    def _truth(self, event: Mapping[str, Any], key: str, types: Tuple[type, ...]) -> Any:
        """Truth events come from the harness: a bad one is a harness bug."""
        value = event.get(key, _MISSING)
        ok = value is not _MISSING and isinstance(value, types)
        if ok and isinstance(value, bool) and bool not in types:
            ok = False
        if not ok:
            raise OracleUsageError(
                f"{self.name}: truth event '{event.get('kind')}' needs {key} of type "
                f"{'/'.join(t.__name__ for t in types)}"
            )
        return value

    def _dut(self, event: Mapping[str, Any], key: str, types: Tuple[type, ...], minimum: Optional[int] = None) -> Any:
        """DUT events are under test: a bad one is a violation, not a crash."""
        value = event.get(key, _MISSING)
        ok = value is not _MISSING and isinstance(value, types)
        if ok and isinstance(value, bool) and bool not in types:
            ok = False
        if ok and minimum is not None and value < minimum:
            ok = False
        if ok:
            return value
        self._violate(
            "malformed_event",
            expected={"event": event.get("kind"), "field": key, "types": [t.__name__ for t in types], "minimum": minimum},
            observed={"present": value is not _MISSING, "type": None if value is _MISSING else type(value).__name__},
            detail=f"DUT event '{event.get('kind')}' has missing or invalid '{key}'",
        )
        return _MISSING

    def _finalize_t(self, end_t_ns: Optional[int]) -> Optional[int]:
        return end_t_ns if end_t_ns is not None else self._last_t


# ---------------------------------------------------------------------------
# Sample oracle: lost, repeated, wrong and missing-tail samples.
# ---------------------------------------------------------------------------


def _merge_ranges(ranges: Iterable[Sequence[int]]) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for item in ranges:
        start, count = item
        if not _is_int(start) or not _is_int(count) or start < 0 or count < 1:
            raise ValueError("permitted gap ranges are (start_frame >= 0, frame_count >= 1)")
        spans.append((start, start + count))
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


class SampleOracle(Oracle):
    """Every frame of [0, expected_total_frames) must be a verified block or a
    permitted, announced gap, in order, exactly once.

    ``permitted_gaps`` is scenario truth (for example blocks the injected
    network schedule dropped).  Concealment *content* inside an announced gap
    is not verified; the limit is documented, not hidden.
    """

    name = "sample"
    HANDLES = {"audio_block": "_on_block", "audio_gap": "_on_gap"}

    def __init__(
        self,
        reference: ReferenceSignal,
        *,
        expected_total_frames: Optional[int],
        stream: str = "main",
        permitted_gaps: Iterable[Sequence[int]] = (),
        include_sample_values: bool = True,
        max_violations: int = 32,
        allow_empty: bool = False,
    ) -> None:
        super().__init__(max_violations=max_violations, allow_empty=allow_empty)
        if expected_total_frames is not None and (not _is_int(expected_total_frames) or expected_total_frames < 0):
            raise ValueError("expected_total_frames must be a non-negative integer or None")
        self.reference = reference
        self.stream = stream
        self.expected_total_frames = expected_total_frames
        self.include_sample_values = include_sample_values
        self._permitted = _merge_ranges(permitted_gaps)
        self._next = 0
        self._blocks = 0
        self._gaps = 0
        self._gap_frames = 0
        self._mismatched_blocks = 0

    def _accepts(self, event: Mapping[str, Any]) -> bool:
        return event.get("stream", "main") == self.stream

    def _stats(self) -> Dict[str, Any]:
        return {
            "blocks": self._blocks,
            "gaps": self._gaps,
            "gap_frames": self._gap_frames,
            "frames_accounted": self._next,
            "expected_total_frames": self.expected_total_frames,
            "mismatched_blocks": self._mismatched_blocks,
        }

    def _block_problem(self, samples: Any, channels: Any) -> Optional[str]:
        if channels != self.reference.channels or not _is_int(channels):
            return "channel_count_mismatch"
        if not isinstance(samples, (list, tuple)):
            return "samples_not_a_sequence"
        if len(samples) == 0:
            return "empty_block"
        if len(samples) % channels:
            return "partial_frame"
        for s in samples:
            if type(s) is not int or s < INT16_MIN or s > INT16_MAX:
                return "sample_out_of_int16_range"
        return None

    def _account(self, start: int, end: int) -> None:
        exp = self._next
        if start > exp:
            self._violate(
                "lost_samples",
                expected={"next_frame": exp},
                observed={"start_frame": start, "missing_frames": start - exp},
                detail=f"{start - exp} frame(s) vanished before frame {start} without an announced gap",
            )
        elif start < exp:
            self._violate(
                "repeated_samples",
                expected={"next_frame": exp},
                observed={"start_frame": start, "overlap_frames": min(exp, end) - start},
                detail=f"output went back to frame {start} after reaching {exp}",
            )
        total = self.expected_total_frames
        if total is not None and end > total:
            self._violate(
                "overrun_stream",
                expected={"total_frames": total},
                observed={"end_frame": end},
                detail=f"output ran to frame {end}, past the declared {total}",
            )
        if end > exp:
            self._next = end

    def _on_block(self, event: Mapping[str, Any]) -> None:
        start = self._dut(event, "start_frame", (int,), minimum=0)
        if start is _MISSING:
            return
        samples = event.get("samples", _MISSING)
        channels = event.get("channels", self.reference.channels)
        problem = self._block_problem(samples, channels)
        if problem is not None:
            self._violate(
                "malformed_block",
                expected={"channels": self.reference.channels, "sample_range": [INT16_MIN, INT16_MAX], "non_empty": True},
                observed={"problem": problem},
                detail=f"block at frame {start} is malformed: {problem}",
            )
            return
        ch = self.reference.channels
        frames = len(samples) // ch
        self._blocks += 1
        self._account(start, start + frames)
        observed = list(samples)
        expected = self.reference.block(start, frames)
        if observed != expected:
            self._mismatched_blocks += 1
            bad = [i for i, (a, b) in enumerate(zip(observed, expected)) if a != b]
            first = bad[0]
            frame, channel = start + first // ch, first % ch
            exp_info: Dict[str, Any] = {"frame": frame, "channel": channel}
            obs_info: Dict[str, Any] = {"frame": frame, "channel": channel, "mismatched_samples": len(bad), "block_start_frame": start}
            if self.include_sample_values:
                exp_info["value"] = expected[first]
                obs_info["value"] = observed[first]
            self._violate(
                "wrong_samples",
                expected=exp_info,
                observed=obs_info,
                detail=f"{len(bad)} sample(s) differ from the reference; first at frame {frame} channel {channel}",
            )

    def _on_gap(self, event: Mapping[str, Any]) -> None:
        start = self._dut(event, "start_frame", (int,), minimum=0)
        count = self._dut(event, "frame_count", (int,), minimum=1)
        if start is _MISSING or count is _MISSING:
            return
        end = start + count
        self._gaps += 1
        self._account(start, end)
        self._gap_frames += count
        if not any(lo <= start and end <= hi for lo, hi in self._permitted):
            self._violate(
                "unpermitted_gap",
                expected={"within_permitted_gap": True},
                observed={"start_frame": start, "frame_count": count},
                detail=f"gap [{start}, {end}) was announced but the scenario never lost those frames",
            )

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        total = self.expected_total_frames
        if total is None:
            self._add_incomplete("completeness_unchecked_total_frames_unknown")
        elif self._relevant > 0 and self._next < total:
            self._violate(
                "truncated_stream",
                expected={"total_frames": total},
                observed={"accounted_frames": self._next, "missing_frames": total - self._next},
                detail=f"stream ended at frame {self._next}; {total} were required",
                event_index=self._ordinal + 1,
                t_ns=self._finalize_t(end_t_ns),
                cause=None,
            )


# ---------------------------------------------------------------------------
# Command truth ledger shared (by composition) by the epoch and command oracles.
# ---------------------------------------------------------------------------


class _Ledger:
    def __init__(self, max_tracked: int) -> None:
        self.authority: Dict[str, int] = {}
        self.issued: Dict[str, Tuple[str, int]] = {}
        self.max_tracked = max_tracked
        self.overflowed = False

    def set_authority(self, scope: str, epoch: int) -> None:
        prev = self.authority.get(scope)
        if prev is not None and epoch < prev:
            raise OracleUsageError(f"authority epoch for scope regressed ({epoch} < {prev})")
        self.authority[scope] = epoch

    def issue(self, command_id: str, scope: str, epoch: int) -> None:
        if command_id in self.issued:
            raise OracleUsageError(f"command_issued repeated for {command_id!r}")
        if len(self.issued) >= self.max_tracked:
            self.overflowed = True
            return
        self.issued[command_id] = (scope, epoch)

    def is_stale(self, command_id: str) -> Optional[bool]:
        entry = self.issued.get(command_id)
        if entry is None:
            return None
        scope, epoch = entry
        auth = self.authority.get(scope)
        return None if auth is None else epoch < auth


class EpochOracle(Oracle):
    """A command stamped with an epoch older than the harness-declared authority
    epoch for its scope must never be applied.

    Rejecting a stale command, or silently ignoring it, is permitted behaviour.
    With ``require_stale_exercised`` a trace that never delivered a stale
    command is ``incomplete``: the fence was never tested.
    """

    name = "epoch"
    HANDLES = {
        "authority_epoch": "_on_authority",
        "command_issued": "_on_issued",
        "command_delivered": "_on_delivered",
        "command_applied": "_on_applied",
        "command_rejected": "_on_rejected",
    }

    def __init__(
        self,
        *,
        require_stale_exercised: bool = False,
        max_tracked_commands: int = 100_000,
        max_violations: int = 32,
        allow_empty: bool = False,
    ) -> None:
        super().__init__(max_violations=max_violations, allow_empty=allow_empty)
        self.require_stale_exercised = require_stale_exercised
        self._ledger = _Ledger(max_tracked_commands)
        self._stale_deliveries = 0
        self._stale_rejected = 0
        self._stale_ids: set = set()
        self._applied = 0
        self._unknown_applied = 0

    def _stats(self) -> Dict[str, Any]:
        return {
            "stale_deliveries": self._stale_deliveries,
            "stale_rejected": self._stale_rejected,
            "applied": self._applied,
            "applied_unknown_command": self._unknown_applied,
        }

    def _on_authority(self, event: Mapping[str, Any]) -> None:
        self._ledger.set_authority(self._truth(event, "scope", (str,)), self._truth(event, "epoch", (int,)))

    def _on_issued(self, event: Mapping[str, Any]) -> None:
        self._ledger.issue(
            self._truth(event, "command_id", (str,)),
            self._truth(event, "scope", (str,)),
            self._truth(event, "epoch", (int,)),
        )

    def _on_delivered(self, event: Mapping[str, Any]) -> None:
        cid = self._truth(event, "command_id", (str,))
        stale = self._ledger.is_stale(cid)
        if stale:
            self._stale_deliveries += 1
            if len(self._stale_ids) < self._ledger.max_tracked:
                self._stale_ids.add(cid)

    def _on_applied(self, event: Mapping[str, Any]) -> None:
        cid = self._dut(event, "command_id", (str,))
        if cid is _MISSING:
            return
        self._applied += 1
        entry = self._ledger.issued.get(cid)
        if entry is None:
            self._unknown_applied += 1
            return
        scope, epoch = entry
        auth = self._ledger.authority.get(scope)
        if auth is None:
            self._violate(
                "unknown_scope",
                expected={"scope_has_declared_authority": True},
                observed={"scope": scope, "command_id": cid},
                detail=f"command {cid} applied in scope {scope} with no declared authority epoch",
            )
        elif epoch < auth:
            self._violate(
                "stale_epoch_applied",
                expected={"scope": scope, "min_epoch": auth},
                observed={"command_id": cid, "command_epoch": epoch},
                detail=f"command {cid} from epoch {epoch} was applied under authority epoch {auth}",
            )
        elif epoch > auth:
            self._violate(
                "future_epoch_applied",
                expected={"scope": scope, "max_epoch": auth},
                observed={"command_id": cid, "command_epoch": epoch},
                detail=f"command {cid} from epoch {epoch} was applied before that epoch was granted ({auth})",
            )

    def _on_rejected(self, event: Mapping[str, Any]) -> None:
        cid = self._dut(event, "command_id", (str,))
        if cid is not _MISSING and cid in self._stale_ids:
            self._stale_rejected += 1

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        if self._ledger.overflowed:
            self._add_incomplete("tracking_overflow")
        if self.require_stale_exercised and self._stale_deliveries == 0:
            self._add_incomplete("fence_not_exercised")


class CommandOracle(Oracle):
    """Each issued command is applied at most once, never without being
    delivered, never if it was never issued, and at least once if any delivery
    of it arrived while its epoch was current.

    A duplicate *delivery* that the DUT suppresses is the permitted positive
    case.  With ``require_duplicate_exercised`` a trace without any duplicate
    delivery is ``incomplete``.
    """

    name = "command"
    HANDLES = {
        "authority_epoch": "_on_authority",
        "command_issued": "_on_issued",
        "command_delivered": "_on_delivered",
        "command_applied": "_on_applied",
    }

    def __init__(
        self,
        *,
        require_duplicate_exercised: bool = False,
        max_tracked_commands: int = 100_000,
        max_violations: int = 32,
        allow_empty: bool = False,
    ) -> None:
        super().__init__(max_violations=max_violations, allow_empty=allow_empty)
        self.require_duplicate_exercised = require_duplicate_exercised
        self._ledger = _Ledger(max_tracked_commands)
        self._deliveries: Dict[str, int] = {}
        self._applies: Dict[str, int] = {}
        self._fresh: set = set()
        self._duplicate_deliveries = 0
        self._phantom = 0

    def _stats(self) -> Dict[str, Any]:
        return {
            "issued": len(self._ledger.issued),
            "deliveries": sum(self._deliveries.values()),
            "duplicate_deliveries": self._duplicate_deliveries,
            "applications": sum(self._applies.values()),
            "phantom_applications": self._phantom,
        }

    def _on_authority(self, event: Mapping[str, Any]) -> None:
        self._ledger.set_authority(self._truth(event, "scope", (str,)), self._truth(event, "epoch", (int,)))

    def _on_issued(self, event: Mapping[str, Any]) -> None:
        self._ledger.issue(
            self._truth(event, "command_id", (str,)),
            self._truth(event, "scope", (str,)),
            self._truth(event, "epoch", (int,)),
        )

    def _on_delivered(self, event: Mapping[str, Any]) -> None:
        cid = self._truth(event, "command_id", (str,))
        if cid not in self._ledger.issued:
            if self._ledger.overflowed:
                return
            raise OracleUsageError(f"command_delivered for never-issued command {cid!r}")
        count = self._deliveries.get(cid, 0) + 1
        self._deliveries[cid] = count
        if count > 1:
            self._duplicate_deliveries += 1
        if self._ledger.is_stale(cid) is False:
            self._fresh.add(cid)

    def _on_applied(self, event: Mapping[str, Any]) -> None:
        cid = self._dut(event, "command_id", (str,))
        if cid is _MISSING:
            return
        if cid not in self._ledger.issued:
            self._phantom += 1
            self._violate(
                "phantom_command",
                expected={"command_was_issued": True},
                observed={"command_id": cid},
                detail=f"command {cid} was applied but never issued",
            )
            return
        if self._deliveries.get(cid, 0) == 0:
            self._violate(
                "applied_without_delivery",
                expected={"deliveries_before_apply": ">=1"},
                observed={"command_id": cid, "deliveries": 0},
                detail=f"command {cid} was applied before any delivery of it",
            )
        count = self._applies.get(cid, 0) + 1
        self._applies[cid] = count
        if count > 1:
            self._violate(
                "double_applied",
                expected={"max_applications": 1},
                observed={"command_id": cid, "applications": count, "deliveries": self._deliveries.get(cid, 0)},
                detail=f"command {cid} was applied {count} times",
            )

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        if self._ledger.overflowed:
            self._add_incomplete("tracking_overflow")
        for cid in self._ledger.issued:
            if cid in self._fresh and self._applies.get(cid, 0) == 0:
                self._violate(
                    "lost_command",
                    expected={"min_applications": 1},
                    observed={"command_id": cid, "applications": 0, "deliveries": self._deliveries.get(cid, 0)},
                    detail=f"command {cid} arrived while current but was never applied",
                    event_index=self._ordinal + 1,
                    t_ns=self._finalize_t(end_t_ns),
                    cause=None,
                )
        if self.require_duplicate_exercised and self._duplicate_deliveries == 0:
            self._add_incomplete("duplicates_not_exercised")


# ---------------------------------------------------------------------------
# Readiness oracle: prerequisites come from independent probe events.
# ---------------------------------------------------------------------------


class ReadinessOracle(Oracle):
    """``ready_announced`` is legal only while every required prerequisite is
    satisfied according to independent ``prereq_state`` probe events, and a
    ready DUT must withdraw within ``withdraw_deadline_ns`` of losing one.

    With ``announce_deadline_ns`` a DUT that never announces ready (a
    refusal-only path) fails once all prerequisites held for that long.
    Deadlines are evaluated lazily at the next event or at ``end_t_ns``.
    """

    name = "readiness"
    HANDLES = {
        "prereq_state": "_on_prereq",
        "ready_announced": "_on_announce",
        "ready_withdrawn": "_on_withdraw",
    }

    def __init__(
        self,
        required: Sequence[str] = DEFAULT_REQUIRED,
        *,
        withdraw_deadline_ns: int = 5_000_000,
        announce_deadline_ns: Optional[int] = None,
        max_violations: int = 32,
        allow_empty: bool = False,
    ) -> None:
        super().__init__(max_violations=max_violations, allow_empty=allow_empty)
        required = tuple(required)
        if not required or len(set(required)) != len(required) or not all(isinstance(n, str) and n for n in required):
            raise ValueError("required must be distinct non-empty strings")
        if not _is_int(withdraw_deadline_ns) or withdraw_deadline_ns < 0:
            raise ValueError("withdraw_deadline_ns must be a non-negative integer")
        if announce_deadline_ns is not None and (not _is_int(announce_deadline_ns) or announce_deadline_ns < 0):
            raise ValueError("announce_deadline_ns must be a non-negative integer or None")
        self.required = required
        self.withdraw_deadline_ns = withdraw_deadline_ns
        self.announce_deadline_ns = announce_deadline_ns
        self._sat = {n: False for n in required}
        self._unsat_since = {n: 0 for n in required}
        self._unsat_index = {n: -1 for n in required}
        self._unsat_cause: Dict[str, Optional[str]] = {n: None for n in required}
        self._ready = False
        self._ready_since = 0
        self._withdraw_flagged = False
        self._all_sat_since: Optional[int] = None
        self._all_sat_index = -1
        self._all_sat_cause: Optional[str] = None
        self._announce_flagged = False
        self._announcements = 0
        self._withdrawals = 0
        self._redundant = 0
        self._unknown_prereqs = 0

    def _stats(self) -> Dict[str, Any]:
        return {
            "announcements": self._announcements,
            "withdrawals": self._withdrawals,
            "redundant_ready_events": self._redundant,
            "ignored_unknown_prerequisites": self._unknown_prereqs,
            "ready_at_end": self._ready,
        }

    def _on_time(self, t_ns: int) -> None:
        if self._ready and not self._withdraw_flagged:
            lost = [n for n in self.required if not self._sat[n]]
            if lost:
                first = min(lost, key=lambda n: (self._unsat_since[n], self.required.index(n)))
                since = max(self._unsat_since[first], self._ready_since)
                if t_ns - since > self.withdraw_deadline_ns:
                    self._withdraw_flagged = True
                    self._violate(
                        "ready_not_withdrawn",
                        expected={"prerequisite": first, "withdrawn_by_ns": since + self.withdraw_deadline_ns},
                        observed={"still_ready_at_ns": t_ns, "prerequisite_unsatisfied_since_ns": self._unsat_since[first]},
                        detail=f"still ready {t_ns - since} ns after '{first}' was lost (limit {self.withdraw_deadline_ns})",
                        event_index=self._unsat_index[first],
                        t_ns=since + self.withdraw_deadline_ns,
                        cause=self._unsat_cause[first],
                    )
        if (
            not self._ready
            and self.announce_deadline_ns is not None
            and self._all_sat_since is not None
            and not self._announce_flagged
            and t_ns - self._all_sat_since > self.announce_deadline_ns
        ):
            self._announce_flagged = True
            self._violate(
                "ready_not_announced",
                expected={"announced_by_ns": self._all_sat_since + self.announce_deadline_ns},
                observed={"not_ready_at_ns": t_ns, "all_prerequisites_satisfied_since_ns": self._all_sat_since},
                detail=f"not ready {t_ns - self._all_sat_since} ns after every prerequisite held (limit {self.announce_deadline_ns})",
                event_index=self._all_sat_index,
                t_ns=self._all_sat_since + self.announce_deadline_ns,
                cause=self._all_sat_cause,
            )

    def _on_prereq(self, event: Mapping[str, Any]) -> None:
        name = self._truth(event, "name", (str,))
        satisfied = self._truth(event, "satisfied", (bool,))
        if name not in self._sat:
            self._unknown_prereqs += 1
            return
        if self._sat[name] == satisfied:
            return
        self._sat[name] = satisfied
        cause = _ref(event)
        if satisfied:
            if all(self._sat.values()):
                self._all_sat_since = event["t_ns"]
                self._all_sat_index = self._ordinal
                self._all_sat_cause = cause
                self._announce_flagged = False
                self._withdraw_flagged = False
        else:
            self._unsat_since[name] = event["t_ns"]
            self._unsat_index[name] = self._ordinal
            self._unsat_cause[name] = cause
            self._all_sat_since = None

    def _on_announce(self, event: Mapping[str, Any]) -> None:
        if self._ready:
            self._redundant += 1
            return
        self._ready = True
        self._ready_since = event["t_ns"]
        self._announcements += 1
        missing = [n for n in self.required if not self._sat[n]]
        if missing:
            self._withdraw_flagged = True
            self._violate(
                "false_ready",
                expected={"all_prerequisites_satisfied": list(self.required)},
                observed={"missing_prerequisites": missing},
                detail=f"announced ready while {', '.join(missing)} unsatisfied",
            )
        else:
            self._withdraw_flagged = False

    def _on_withdraw(self, event: Mapping[str, Any]) -> None:
        if not self._ready:
            self._redundant += 1
            return
        self._ready = False
        self._withdrawals += 1
        self._withdraw_flagged = False

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        if end_t_ns is not None:
            self._on_time(end_t_ns)
            return
        pending_withdraw = self._ready and not self._withdraw_flagged and not all(self._sat.values())
        pending_announce = (
            not self._ready
            and self.announce_deadline_ns is not None
            and self._all_sat_since is not None
            and not self._announce_flagged
        )
        if pending_withdraw or pending_announce:
            self._add_incomplete("end_time_required_for_pending_deadline")


# ---------------------------------------------------------------------------
# Priority-stop oracle: judged from output samples and the clock only.
# ---------------------------------------------------------------------------


class PriorityStopOracle(Oracle):
    """After ``stop_requested``, output must be silent from ``stop + deadline``
    on.  Inputs are the output samples and timestamps only, so queue depth or a
    saturated log sink cannot influence the verdict.  Evidence of silence is
    required: a DUT that simply stops producing blocks is ``incomplete``.
    """

    name = "priority_stop"
    HANDLES = {"stop_requested": "_on_stop", "audio_block": "_on_block"}

    def __init__(
        self,
        *,
        sample_rate_hz: int,
        deadline_ns: int,
        stream: str = "main",
        max_violations: int = 32,
        allow_empty: bool = False,
    ) -> None:
        super().__init__(max_violations=max_violations, allow_empty=allow_empty)
        if not _is_int(sample_rate_hz) or sample_rate_hz <= 0:
            raise ValueError("sample_rate_hz must be positive")
        if not _is_int(deadline_ns) or deadline_ns < 0:
            raise ValueError("deadline_ns must be non-negative")
        self.sample_rate_hz = sample_rate_hz
        self.deadline_ns = deadline_ns
        self.stream = stream
        self._stop_t: Optional[int] = None
        self._last_block: Optional[Tuple[int, int, Sequence[int], Optional[str], int]] = None
        self._silent_frames = 0
        self._audible_blocks = 0
        self._pre_stop_blocks = 0

    def _accepts(self, event: Mapping[str, Any]) -> bool:
        return event.get("kind") != "audio_block" or event.get("stream", "main") == self.stream

    def _stats(self) -> Dict[str, Any]:
        return {
            "stop_requested_ns": self._stop_t,
            "deadline_ns": self.deadline_ns,
            "silent_frames_after_deadline": self._silent_frames,
            "audible_blocks_after_deadline": self._audible_blocks,
            "blocks_before_stop": self._pre_stop_blocks,
        }

    def _frame_time(self, block_t: int, k: int) -> int:
        return block_t + (k * 1_000_000_000) // self.sample_rate_hz

    def _check_block(self, block_t: int, ch: int, samples: Sequence[int], cause: Optional[str], index: int) -> None:
        assert self._stop_t is not None
        limit = self._stop_t + self.deadline_ns
        frames = len(samples) // ch
        k0 = 0
        while k0 < frames and self._frame_time(block_t, k0) < limit:
            k0 += 1
        if k0 >= frames:
            return
        tail = samples[k0 * ch:]
        audible = [i for i, s in enumerate(tail) if s != 0]
        if audible:
            self._audible_blocks += 1
            first_frame = k0 + audible[0] // ch
            self._violate(
                "audible_after_deadline",
                expected={"silent_from_ns": limit},
                observed={
                    "first_audible_frame_t_ns": self._frame_time(block_t, first_frame),
                    "audible_samples": len(audible),
                    "stop_requested_ns": self._stop_t,
                },
                detail=f"output still audible {self._frame_time(block_t, first_frame) - self._stop_t} ns after stop (limit {self.deadline_ns})",
                event_index=index,
                t_ns=block_t,
                cause=cause,
            )
        else:
            self._silent_frames += frames - k0

    def _on_stop(self, event: Mapping[str, Any]) -> None:
        if self._stop_t is not None:
            return
        self._stop_t = event["t_ns"]
        if self._last_block is not None:
            block_t, ch, samples, cause, index = self._last_block
            self._check_block(block_t, ch, samples, cause, index)
            self._last_block = None

    def _on_block(self, event: Mapping[str, Any]) -> None:
        samples = event.get("samples", _MISSING)
        ch = event.get("channels", _MISSING)
        if (
            not _is_int(ch)
            or ch < 1
            or not isinstance(samples, (list, tuple))
            or not samples
            or len(samples) % ch
            or any(type(s) is not int for s in samples)
        ):
            self._violate(
                "malformed_block",
                expected={"channels": ">=1", "non_empty": True, "int_samples": True},
                observed={"channels_type": type(ch).__name__ if ch is not _MISSING else None},
                detail="output block is malformed, so silence cannot be established",
            )
            return
        cause = _ref(event)
        if self._stop_t is None:
            self._pre_stop_blocks += 1
            self._last_block = (event["t_ns"], ch, samples, cause, self._ordinal)
            return
        self._check_block(event["t_ns"], ch, samples, cause, self._ordinal)

    def _on_finalize(self, end_t_ns: Optional[int]) -> None:
        if self._stop_t is None:
            self._add_incomplete("stop_not_exercised")
        elif self._silent_frames == 0 and self._violation_count == 0:
            self._add_incomplete("no_evidence_of_silence")


# ---------------------------------------------------------------------------
# Evaluation and trace persistence.
# ---------------------------------------------------------------------------


def trace_digest(trace: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex("\n".join(canonical_json(e) for e in trace))


def trace_to_jsonl(trace: Sequence[Mapping[str, Any]]) -> str:
    return "".join(canonical_json(e) + "\n" for e in trace)


def trace_from_jsonl(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OracleUsageError(f"trace line {number} is not valid JSON: {exc.msg}") from exc
        if not isinstance(obj, dict):
            raise OracleUsageError(f"trace line {number} is not a JSON object")
        events.append(obj)
    return events


def overall_status(statuses: Iterable[str]) -> str:
    statuses = list(statuses)
    if not statuses:
        return INCOMPLETE
    if FAILED in statuses:
        return FAILED
    if INCOMPLETE in statuses:
        return INCOMPLETE
    return PASSED


def evaluate(
    trace: Sequence[Mapping[str, Any]],
    oracles: Sequence[Oracle],
    *,
    end_t_ns: Optional[int] = None,
) -> Dict[str, Any]:
    names = [o.name for o in oracles]
    if len(set(names)) != len(names):
        raise OracleUsageError("oracle names must be unique")
    for event in trace:
        for oracle in oracles:
            oracle.observe(event)
    verdicts = {o.name: o.finalize(end_t_ns=end_t_ns) for o in oracles}
    return {
        "schema": SCHEMA_REPORT,
        "status": overall_status(v["status"] for v in verdicts.values()),
        "trace_events": len(trace),
        "trace_digest": trace_digest(trace),
        "oracles": verdicts,
    }


# ---------------------------------------------------------------------------
# Deterministic replay schedules.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleProfile:
    sample_rate_hz: int = 48_000
    channels: int = 2
    block_frames: int = 48
    blocks: int = 80
    loss_bps: int = 400
    dup_bps: int = 500
    max_jitter_ns: int = 400_000
    playout_delay_ns: int = 1_000_000
    burst_every_blocks: int = 25
    burst_len_blocks: int = 2
    random_commands: int = 10
    command_latency_max_ns: int = 800_000
    duplicate_command_bps: int = 3_000
    scopes: Tuple[str, ...] = ("grp-a", "grp-b")
    reaction_ns: int = 100_000
    withdraw_deadline_ns: int = 4_000_000
    announce_deadline_ns: int = 4_000_000

    def __post_init__(self) -> None:
        positive = (
            "sample_rate_hz", "block_frames", "blocks", "playout_delay_ns", "command_latency_max_ns",
            "reaction_ns", "withdraw_deadline_ns", "announce_deadline_ns",
        )
        for name in positive:
            if not _is_int(getattr(self, name)) or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("loss_bps", "dup_bps", "duplicate_command_bps"):
            if not _is_int(getattr(self, name)) or not 0 <= getattr(self, name) <= 10_000:
                raise ValueError(f"{name} must be 0..10000")
        for name in ("max_jitter_ns", "burst_every_blocks", "burst_len_blocks", "random_commands"):
            if not _is_int(getattr(self, name)) or getattr(self, name) < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not _is_int(self.channels) or not 1 <= self.channels <= 8:
            raise ValueError("channels must be 1..8")
        if self.blocks < 20:
            raise ValueError("blocks must be >= 20 to leave room for forced scenario events")
        if self.block_ns < 1:
            raise ValueError("block duration rounds to zero nanoseconds")
        if self.playout_delay_ns < self.max_jitter_ns:
            raise ValueError("playout_delay_ns must cover max_jitter_ns, or on-time arrival is not guaranteed")
        if self.burst_every_blocks and not 0 < self.burst_len_blocks <= self.burst_every_blocks // 2:
            raise ValueError("burst_len_blocks must be 1..burst_every_blocks/2")
        if not self.scopes or not all(isinstance(s, str) and s for s in self.scopes) or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("scopes must be distinct non-empty strings")
        if self.withdraw_deadline_ns <= self.reaction_ns or self.announce_deadline_ns <= self.reaction_ns:
            raise ValueError("deadlines must exceed the DUT reaction time")

    @property
    def block_ns(self) -> int:
        return self.block_frames * 1_000_000_000 // self.sample_rate_hz

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scopes"] = list(self.scopes)
        return d

    @classmethod
    def from_overrides(cls, overrides: Optional[Mapping[str, Any]] = None) -> "ScheduleProfile":
        merged = cls().to_dict()
        merged.update(overrides or {})
        merged["scopes"] = tuple(merged["scopes"])
        return cls(**merged)


@dataclass
class Schedule:
    seed: int
    profile: ScheduleProfile
    audio: List[Dict[str, Any]]
    truth: List[Dict[str, Any]]
    end_t_ns: int
    digest: str

    def dropped_ranges(self) -> List[Tuple[int, int]]:
        bf = self.profile.block_frames
        return [(a["seq"] * bf, bf) for a in self.audio if a["dropped"]]

    def target_block(self) -> int:
        for i in range(3, self.profile.blocks - 3):
            if not self.audio[i]["dropped"]:
                return i
        raise ValueError("no delivered mid-stream block to plant a defect in")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_SCHEDULE,
            "seed": self.seed,
            "profile": self.profile.to_dict(),
            "audio": self.audio,
            "truth": self.truth,
            "end_t_ns": self.end_t_ns,
            "digest": self.digest,
        }


_TRUTH_RANK = {"authority_epoch": 0, "prereq_state": 0, "stop_requested": 0, "command_issued": 1, "command_delivered": 2}


def build_schedule(seed: int, profile: Optional[ScheduleProfile] = None) -> Schedule:
    """Pure function of (seed, profile).  Random extras plus forced events
    (stale delivery, duplicate delivery, prerequisite dip, at least one loss) so
    every schedule can trigger every planted defect."""
    _check_seed(seed)
    p = profile or ScheduleProfile()
    block_ns = p.block_ns
    total_ns = p.blocks * block_ns

    arng = SplitMix64(derive_seed(seed, "audio"))
    phase = arng.below(p.burst_every_blocks) if p.burst_every_blocks else 0
    audio: List[Dict[str, Any]] = []
    for i in range(p.blocks):
        send = i * block_ns
        in_burst = bool(p.burst_every_blocks) and ((i + phase) % p.burst_every_blocks) < p.burst_len_blocks
        loss = arng.chance_bps(p.loss_bps)
        jitter = arng.below(p.max_jitter_ns + 1)
        dup = arng.chance_bps(p.dup_bps)
        dup_extra = 1 + arng.below(block_ns)
        dropped = in_burst or loss
        audio.append(
            {
                "seq": i,
                "send_t_ns": send,
                "dropped": dropped,
                "burst": in_burst,
                "arrive_t_ns": None if dropped else send + jitter,
                "dup_arrive_t_ns": None if dropped or not dup else send + jitter + dup_extra,
            }
        )
    if not any(a["dropped"] for a in audio):
        mid = p.blocks // 2
        audio[mid].update(dropped=True, arrive_t_ns=None, dup_arrive_t_ns=None)
    if sum(1 for a in audio[3:-3] if not a["dropped"]) < 4:
        raise ValueError("profile is too lossy to leave delivered mid-stream blocks")

    items: List[Tuple[int, int, int, Dict[str, Any]]] = []

    def add(event: Dict[str, Any]) -> None:
        items.append((event["t_ns"], _TRUTH_RANK[event["kind"]], len(items), event))

    crng = SplitMix64(derive_seed(seed, "commands"))
    bumps: Dict[str, int] = {}
    for scope in p.scopes:
        add({"kind": "authority_epoch", "t_ns": 0, "scope": scope, "epoch": 1})
    for idx, scope in enumerate(p.scopes):
        bump = total_ns // 2 if idx == 0 else total_ns // 4 + crng.below(total_ns // 2)
        bumps[scope] = bump
        add({"kind": "authority_epoch", "t_ns": bump, "scope": scope, "epoch": 2})

    def epoch_at(scope: str, t: int) -> int:
        return 2 if t >= bumps[scope] else 1

    def add_command(cid: str, scope: str, issue_t: int, deliveries: Sequence[int]) -> None:
        add({"kind": "command_issued", "t_ns": issue_t, "command_id": cid, "scope": scope, "epoch": epoch_at(scope, issue_t)})
        for dt in deliveries:
            add({"kind": "command_delivered", "t_ns": dt, "command_id": cid})

    first = p.scopes[0]
    add_command("cmd-stale-0", first, bumps[first] - 1000, [bumps[first] + 1000])
    add_command("cmd-dup-0", first, 2000, [5000, 9000])
    for i in range(p.random_commands):
        scope = p.scopes[crng.below(len(p.scopes))]
        issue_t = 1 + crng.below(total_ns * 9 // 10)
        lat1 = 1 + crng.below(p.command_latency_max_ns)
        dup = crng.chance_bps(p.duplicate_command_bps)
        lat2 = 1 + crng.below(p.command_latency_max_ns)
        deliveries = [issue_t + lat1] + ([issue_t + lat1 + lat2] if dup else [])
        add_command(f"cmd-{i:03d}", scope, issue_t, deliveries)

    rrng = SplitMix64(derive_seed(seed, "readiness"))
    names = list(DEFAULT_REQUIRED)
    for i in range(len(names) - 1, 0, -1):
        j = rrng.below(i + 1)
        names[i], names[j] = names[j], names[i]
    t = total_ns // 20 + rrng.below(block_ns)
    for name in names:
        add({"kind": "prereq_state", "t_ns": t, "name": name, "satisfied": True})
        t += 200_000 * (1 + rrng.below(5))
    dip = total_ns * 11 // 20 + rrng.below(total_ns // 20)
    dip_end = dip + 2 * p.withdraw_deadline_ns
    if dip_end + 2 * p.announce_deadline_ns + p.reaction_ns > total_ns:
        raise ValueError("profile timeline is too short for the readiness dip and re-announcement")
    add({"kind": "prereq_state", "t_ns": dip, "name": "clock_locked", "satisfied": False})
    add({"kind": "prereq_state", "t_ns": dip_end, "name": "clock_locked", "satisfied": True})

    items.sort(key=lambda x: (x[0], x[1], x[2]))
    truth: List[Dict[str, Any]] = []
    for n, (_, _, _, event) in enumerate(items):
        event = dict(event)
        event["id"] = f"ev-{n:04d}"
        truth.append(event)

    end_t_ns = total_ns + p.playout_delay_ns
    body = {"schema": SCHEMA_SCHEDULE, "seed": seed, "profile": p.to_dict(), "audio": audio, "truth": truth, "end_t_ns": end_t_ns}
    return Schedule(seed, p, audio, truth, end_t_ns, sha256_hex(canonical_json(body)))


@dataclass
class StopScenario:
    seed: int
    sample_rate_hz: int
    channels: int
    block_frames: int
    queue_blocks: int
    deadline_ns: int
    reaction_ns: int
    stop_t_ns: int
    end_t_ns: int
    digest: str

    @property
    def block_ns(self) -> int:
        return self.block_frames * 1_000_000_000 // self.sample_rate_hz


def build_stop_scenario(seed: int, queue_blocks: int = 8) -> StopScenario:
    """A saturated output queue plus a priority stop.  The stop must beat the
    backlog: queue_blocks * block_ns must clearly exceed the deadline."""
    _check_seed(seed)
    sample_rate_hz, channels, block_frames = 48_000, 2, 48
    block_ns = block_frames * 1_000_000_000 // sample_rate_hz
    deadline_ns, reaction_ns = 3_000_000, 100_000
    if not _is_int(queue_blocks) or queue_blocks * block_ns < deadline_ns + 2 * block_ns:
        raise ValueError("queue backlog must exceed the stop deadline by at least two blocks")
    stop_t = 10_000_000 + SplitMix64(derive_seed(seed, "stop")).below(1_000_000)
    end_t = stop_t + 20_000_000
    body = {"seed": seed, "sr": sample_rate_hz, "ch": channels, "bf": block_frames, "q": queue_blocks,
            "deadline": deadline_ns, "reaction": reaction_ns, "stop": stop_t, "end": end_t}
    return StopScenario(seed, sample_rate_hz, channels, block_frames, queue_blocks, deadline_ns, reaction_ns,
                        stop_t, end_t, sha256_hex(canonical_json(body)))


# ---------------------------------------------------------------------------
# Canary endpoint models with planted defects.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DefectSpec:
    name: str
    scenario: str
    oracle: str
    kind: str
    description: str


DEFECTS: Dict[str, DefectSpec] = {
    d.name: d
    for d in (
        DefectSpec("sample_loss", "house", "sample", "lost_samples", "a delivered block is silently discarded with no gap announced"),
        DefectSpec("wrong_samples", "house", "sample", "wrong_samples", "one delivered sample is off by one"),
        DefectSpec("repeated_samples", "house", "sample", "repeated_samples", "a delivered block is played twice"),
        DefectSpec("truncate_tail", "house", "sample", "truncated_stream", "the final two blocks are never emitted"),
        DefectSpec("stale_epoch", "house", "epoch", "stale_epoch_applied", "the epoch fence is disabled"),
        DefectSpec("double_apply", "house", "command", "double_applied", "duplicate deliveries are not suppressed"),
        DefectSpec("false_ready_early", "house", "readiness", "false_ready", "ready is announced with one prerequisite still missing"),
        DefectSpec("false_ready_stuck", "house", "readiness", "ready_not_withdrawn", "ready is never withdrawn when clock lock is lost"),
        DefectSpec("never_ready", "house", "readiness", "ready_not_announced", "ready is never announced (refusal-only path)"),
        DefectSpec("stop_behind_queue", "stop", "priority_stop", "audible_after_deadline", "stop waits behind the saturated output queue"),
    )
}


def _check_defects(defects: Iterable[str], scenario: str) -> frozenset:
    chosen = frozenset(defects)
    for name in chosen:
        spec = DEFECTS.get(name)
        if spec is None:
            raise ValueError(f"unknown defect {name!r}")
        if spec.scenario != scenario:
            raise ValueError(f"defect {name!r} belongs to the {spec.scenario!r} scenario, not {scenario!r}")
    return chosen


def _merge_trace(items: List[Tuple[int, int, int, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    items.sort(key=lambda x: (x[0], x[1], x[2]))
    return [e for _, _, _, e in items]


def simulate_house(sched: Schedule, defects: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """Minimal canary endpoint: plays what the schedule delivered, fences
    stale commands, suppresses duplicates, and follows prerequisite state."""
    defects = _check_defects(defects, "house")
    p = sched.profile
    ref = ReferenceSignal(sched.seed, "main", p.channels)
    bf, block_ns = p.block_frames, p.block_ns
    items: List[Tuple[int, int, int, Dict[str, Any]]] = []

    def dut(event: Dict[str, Any]) -> None:
        items.append((event["t_ns"], 10, len(items), event))

    for event in sched.truth:
        items.append((event["t_ns"], _TRUTH_RANK[event["kind"]], len(items), dict(event)))

    target = sched.target_block()
    for i, decision in enumerate(sched.audio):
        play_t = i * block_ns + p.playout_delay_ns
        cause = f"blk-{i:04d}"
        if "truncate_tail" in defects and i >= p.blocks - 2:
            continue
        if decision["dropped"]:
            dut({"kind": "audio_gap", "t_ns": play_t, "stream": "main", "start_frame": i * bf, "frame_count": bf,
                 "reason": "network_loss", "cause": cause})
            continue
        if "sample_loss" in defects and i == target:
            continue
        samples = ref.block(i * bf, bf)
        if "wrong_samples" in defects and i == target:
            mid = len(samples) // 2
            samples[mid] = ((samples[mid] + 1 + 32768) & 0xFFFF) - 32768
        block = {"kind": "audio_block", "t_ns": play_t, "stream": "main", "start_frame": i * bf,
                 "channels": p.channels, "samples": samples, "cause": cause}
        dut(block)
        if "repeated_samples" in defects and i == target:
            dut(dict(block, samples=list(samples)))

    authority: Dict[str, int] = {}
    issued: Dict[str, Tuple[str, int]] = {}
    applied: set = set()
    sat = {n: False for n in DEFAULT_REQUIRED}
    ready = False
    early_done = False
    for event in sched.truth:
        kind, t, eid = event["kind"], event["t_ns"], event["id"]
        if kind == "authority_epoch":
            authority[event["scope"]] = event["epoch"]
        elif kind == "command_issued":
            issued[event["command_id"]] = (event["scope"], event["epoch"])
        elif kind == "command_delivered":
            cid = event["command_id"]
            scope, epoch = issued[cid]
            if "stale_epoch" not in defects and epoch < authority[scope]:
                dut({"kind": "command_rejected", "t_ns": t, "command_id": cid, "reason": "stale_epoch", "cause": eid})
                continue
            if cid in applied and "double_apply" not in defects:
                continue
            applied.add(cid)
            dut({"kind": "command_applied", "t_ns": t, "command_id": cid, "cause": eid})
        elif kind == "prereq_state":
            sat[event["name"]] = event["satisfied"]
            want = all(sat.values()) and "never_ready" not in defects
            if "false_ready_early" in defects and not early_done and not ready and sum(sat.values()) == len(sat) - 1:
                want, early_done = True, True
            if "false_ready_stuck" in defects and ready and not want:
                continue
            if want and not ready:
                ready = True
                dut({"kind": "ready_announced", "t_ns": t + p.reaction_ns, "cause": eid})
            elif not want and ready:
                ready = False
                dut({"kind": "ready_withdrawn", "t_ns": t + p.reaction_ns, "cause": eid})
    return _merge_trace(items)


def simulate_stop(scn: StopScenario, defects: Iterable[str] = ()) -> List[Dict[str, Any]]:
    defects = _check_defects(defects, "stop")
    ref = ReferenceSignal(scn.seed, "main", scn.channels)
    block_ns, bf = scn.block_ns, scn.block_frames
    items: List[Tuple[int, int, int, Dict[str, Any]]] = [
        (scn.stop_t_ns, 0, 0, {"kind": "stop_requested", "t_ns": scn.stop_t_ns, "id": "stop-0"})
    ]
    silent_from = scn.stop_t_ns + scn.reaction_ns
    if "stop_behind_queue" in defects:
        silent_from += scn.queue_blocks * block_ns
    k, t = 0, 0
    while t <= scn.end_t_ns:
        samples = ref.block(k * bf, bf) if t < silent_from else [0] * (bf * scn.channels)
        items.append((t, 10, len(items), {"kind": "audio_block", "t_ns": t, "stream": "main", "start_frame": k * bf,
                                          "channels": scn.channels, "samples": samples, "cause": f"out-{k:05d}"}))
        k, t = k + 1, t + block_ns
    return _merge_trace(items)


def build_house_oracles(sched: Schedule) -> List[Oracle]:
    p = sched.profile
    return [
        SampleOracle(
            ReferenceSignal(sched.seed, "main", p.channels),
            expected_total_frames=p.blocks * p.block_frames,
            permitted_gaps=sched.dropped_ranges(),
        ),
        EpochOracle(require_stale_exercised=True),
        CommandOracle(require_duplicate_exercised=True),
        ReadinessOracle(withdraw_deadline_ns=p.withdraw_deadline_ns, announce_deadline_ns=p.announce_deadline_ns),
    ]


def build_stop_oracles(scn: StopScenario) -> List[Oracle]:
    return [PriorityStopOracle(sample_rate_hz=scn.sample_rate_hz, deadline_ns=scn.deadline_ns)]


def replay_argv(seed: int, defect: Optional[str] = None, profile_overrides: Optional[Mapping[str, Any]] = None) -> List[str]:
    """Replay command, relative to the repository root (no absolute paths)."""
    argv = ["scripts/test/test_support/oracles.py", "replay", "--seed", str(seed)]
    if defect:
        argv += ["--defect", defect]
    if profile_overrides:
        argv += ["--profile-json", canonical_json(dict(profile_overrides))]
    return argv


OracleFactory = Callable[[Any], List[Oracle]]


def run_house(
    seed: int,
    defects: Iterable[str] = (),
    profile: Optional[ScheduleProfile] = None,
    oracle_factory: Optional[OracleFactory] = None,
) -> Dict[str, Any]:
    sched = build_schedule(seed, profile)
    defects = sorted(_check_defects(defects, "house"))
    trace = simulate_house(sched, defects)
    report = evaluate(trace, (oracle_factory or build_house_oracles)(sched), end_t_ns=sched.end_t_ns)
    report.update(scenario="house", seed=seed, defects=defects, schedule_digest=sched.digest,
                  replay_argv=replay_argv(seed, defects[0] if defects else None))
    return report


def run_stop(seed: int, defects: Iterable[str] = (), oracle_factory: Optional[OracleFactory] = None) -> Dict[str, Any]:
    scn = build_stop_scenario(seed)
    defects = sorted(_check_defects(defects, "stop"))
    trace = simulate_stop(scn, defects)
    report = evaluate(trace, (oracle_factory or build_stop_oracles)(scn), end_t_ns=scn.end_t_ns)
    report.update(scenario="stop", seed=seed, defects=defects, schedule_digest=scn.digest,
                  replay_argv=replay_argv(seed, defects[0] if defects else None))
    return report


def run_case(seed: int, defect: Optional[str] = None, profile: Optional[ScheduleProfile] = None) -> Dict[str, Any]:
    """Replay entry point.  No defect runs both good scenarios."""
    if defect is not None:
        spec = DEFECTS.get(defect)
        if spec is None:
            raise ValueError(f"unknown defect {defect!r}")
        report = run_stop(seed, [defect]) if spec.scenario == "stop" else run_house(seed, [defect], profile)
        return {"schema": SCHEMA_REPORT, "status": report["status"], "seed": seed, "defect": defect, "reports": [report]}
    reports = [run_house(seed, (), profile), run_stop(seed)]
    return {"schema": SCHEMA_REPORT, "status": overall_status(r["status"] for r in reports),
            "seed": seed, "defect": None, "reports": reports}


# ---------------------------------------------------------------------------
# Paired canaries.
# ---------------------------------------------------------------------------

CANARY_SEEDS = (11, 4242, 0xFF0020260001)


def run_canary(
    defect: str,
    seed: int,
    *,
    profile: Optional[ScheduleProfile] = None,
    oracle_factory: Optional[OracleFactory] = None,
) -> Dict[str, Any]:
    """Run one paired canary: the good run must pass every oracle with real
    evidence; the defect run must fail exactly the corresponding oracle with
    the corresponding kind, while every other oracle stays ``passed``."""
    spec = DEFECTS.get(defect)
    if spec is None:
        raise ValueError(f"unknown defect {defect!r}")
    if spec.scenario == "stop":
        positive = run_stop(seed, (), oracle_factory)
        planted = run_stop(seed, [defect], oracle_factory)
    else:
        positive = run_house(seed, (), profile, oracle_factory)
        planted = run_house(seed, [defect], profile, oracle_factory)
    target = planted["oracles"].get(spec.oracle)
    others = {n: v["status"] for n, v in planted["oracles"].items() if n != spec.oracle}
    checks = {
        "positive_passed": positive["status"] == PASSED,
        "oracle_present": target is not None,
        "defect_failed_corresponding_oracle": bool(target) and target["status"] == FAILED,
        "defect_kind_observed": bool(target) and spec.kind in target["violation_kinds"],
        "first_violation_is_expected_kind": bool(target) and bool(target["violations"]) and target["violations"][0]["kind"] == spec.kind,
        "other_oracles_stayed_passed": all(s == PASSED for s in others.values()),
    }
    return {
        "schema": SCHEMA_CANARY,
        "case_id": f"q00.oracle.canary.{defect}",
        "defect": defect,
        "seed": seed,
        "expected": {"oracle": spec.oracle, "kind": spec.kind},
        "observed": {
            "oracle_status": None if target is None else target["status"],
            "kinds": {} if target is None else target["violation_kinds"],
            "other_oracles": others,
        },
        "checks": checks,
        "status": PASSED if all(checks.values()) else FAILED,
        "first_causal_event": None if not target or not target["violations"] else {
            k: target["violations"][0][k] for k in ("oracle", "kind", "event_index", "t_ns", "cause")
        },
        "positive_trace_digest": positive["trace_digest"],
        "defect_trace_digest": planted["trace_digest"],
        "schedule_digest": planted["schedule_digest"],
        "replay_argv": replay_argv(seed, defect),
    }


def run_canary_all_seeds(defect: str, seeds: Sequence[int] = CANARY_SEEDS, **kwargs: Any) -> Dict[str, Any]:
    results = [run_canary(defect, s, **kwargs) for s in seeds]
    return {
        "schema": SCHEMA_CANARY,
        "case_id": f"q00.oracle.canary.{defect}",
        "defect": defect,
        # A case that ran no seed has proven nothing: it must not pass.
        "status": PASSED if results and all(r["status"] == PASSED for r in results) else FAILED,
        "seeds": list(seeds),
        "runs": results,
    }


def _exercised(oracle: str, stats: Mapping[str, Any]) -> bool:
    """Did the scenario really test the guard, or did the oracle just stay green?"""
    return {
        "sample": stats.get("gaps", 0) > 0 and stats.get("blocks", 0) > 0,
        "epoch": stats.get("stale_deliveries", 0) > 0 and stats.get("stale_rejected", 0) > 0,
        "command": stats.get("duplicate_deliveries", 0) > 0 and stats.get("applications", 0) > 0,
        "readiness": stats.get("announcements", 0) >= 2 and stats.get("withdrawals", 0) >= 1,
        "priority_stop": stats.get("silent_frames_after_deadline", 0) > 0,
    }.get(oracle, False)


def positive_verdict(
    oracle: str, seed: int, oracle_factory: Optional[OracleFactory] = None
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Good-run verdict for one oracle.  A pass whose scenario never exercised
    the guard is demoted to ``incomplete`` (reason ``guard_not_exercised``)."""
    if oracle not in ORACLE_NAMES:
        raise ValueError(f"unknown oracle {oracle!r}")
    report = (run_stop(seed, (), oracle_factory) if oracle == "priority_stop"
              else run_house(seed, (), None, oracle_factory))
    verdict = report["oracles"].get(oracle)
    if verdict is not None and verdict["status"] == PASSED and not _exercised(oracle, verdict["stats"]):
        verdict = dict(verdict)
        verdict["status"] = INCOMPLETE
        verdict["receipt_outcome"] = RECEIPT_OUTCOME[INCOMPLETE]
        verdict["incomplete_reasons"] = list(verdict["incomplete_reasons"]) + ["guard_not_exercised"]
    return verdict, report


def run_positive(
    oracle: str,
    seeds: Sequence[int] = CANARY_SEEDS,
    *,
    oracle_factory: Optional[OracleFactory] = None,
) -> Dict[str, Any]:
    """Permitted behaviour must be accepted *with evidence*: the oracle passed,
    saw events, and the scenario really exercised what it guards against."""
    problems: List[str] = []
    if oracle not in ORACLE_NAMES:
        raise ValueError(f"unknown oracle {oracle!r}")
    if not seeds:
        problems.append("no seeds: nothing ran, so nothing was proven")
    for seed in seeds:
        verdict, _ = positive_verdict(oracle, seed, oracle_factory)
        if verdict is None:
            problems.append(f"seed {seed}: oracle {oracle!r} missing")
            continue
        if "guard_not_exercised" in verdict["incomplete_reasons"]:
            problems.append(f"seed {seed}: scenario did not exercise {oracle}")
        elif verdict["status"] != PASSED:
            problems.append(f"seed {seed}: status {verdict['status']} {verdict['violation_kinds']} {verdict['incomplete_reasons']}")
        if verdict["events_relevant"] == 0:
            problems.append(f"seed {seed}: no relevant events")
    return {"schema": SCHEMA_CANARY, "case_id": f"q00.oracle.positive.{oracle}",
            "status": FAILED if problems else PASSED, "problems": problems, "seeds": list(seeds)}


ORACLE_NAMES = ("sample", "epoch", "command", "readiness", "priority_stop")


def _case(fn: Callable[..., Dict[str, Any]], *args: Any) -> Callable[[], Dict[str, Any]]:
    return lambda: fn(*args)


# Stable (case_id, callable) pairs a runner can register.  Callables return a
# dict with ``status`` ("passed"/"failed"); they do not raise for oracle misbehaviour.
CANARY_CASES: List[Tuple[str, Callable[[], Dict[str, Any]]]] = (
    [(f"q00.oracle.canary.{name}", _case(run_canary_all_seeds, name)) for name in DEFECTS]
    + [(f"q00.oracle.positive.{name}", _case(run_positive, name)) for name in ORACLE_NAMES]
)


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def defect_verdict(
    seed: int,
    defect: str,
    profile: Optional[ScheduleProfile] = None,
    oracle_factory: Optional[OracleFactory] = None,
) -> Tuple[DefectSpec, Dict[str, Any], Dict[str, Any], int]:
    """Run one planted defect; return (spec, report, verdict of the corresponding
    oracle, number of *other* oracles that did not pass)."""
    spec = DEFECTS.get(defect)
    if spec is None:
        raise ValueError(f"unknown defect {defect!r}")
    report = (run_stop(seed, [defect], oracle_factory) if spec.scenario == "stop"
              else run_house(seed, [defect], profile, oracle_factory))
    verdict = report["oracles"].get(spec.oracle)
    if verdict is None:
        raise ValueError(f"oracle {spec.oracle!r} missing from the run")
    collateral = sum(1 for n, v in report["oracles"].items() if n != spec.oracle and v["status"] != PASSED)
    return spec, report, verdict, collateral


def _counters(verdict: Mapping[str, Any], collateral: int) -> Dict[str, int]:
    counters = {k: verdict[k] for k in ("events_seen", "events_relevant", "events_ignored", "violation_count", "violations_dropped")}
    counters.update({k: v for k, v in verdict["stats"].items() if _is_int(v)})
    counters["other_oracles_not_passed"] = collateral
    return counters


def build_case_result(
    oracle: str,
    verdict: Mapping[str, Any],
    *,
    run_id: str,
    case_id: str,
    nonce: str,
    context: Mapping[str, Any],
    expect: Optional[Mapping[str, str]] = None,
    collateral: int = 0,
) -> Dict[str, Any]:
    """Map one oracle verdict onto the runner's ``ffw.case-result.v1`` object.

    ``expect`` (``{"oracle", "kind"}``) is the planted defect's exact identity.
    A failure of the right oracle with the wrong first violation kind is
    reported under ``<oracle>.identity_mismatch``; incomplete evidence under
    ``<oracle>.incomplete`` with no checks and no mismatches.  Neither can equal
    the expected oracle name, so neither can satisfy an expected-failure canary.
    """
    status = verdict["status"]
    first = verdict["violations"][0] if verdict["violations"] else None
    base = {
        "schema": RESULT_SCHEMA, "run_id": run_id, "case_id": case_id, "nonce": nonce,
        "oracle_kind": ORACLE_KIND[oracle], "independent": True,
        "counters": _counters(verdict, collateral),
    }
    if status == PASSED and verdict["events_relevant"] >= 1:
        return dict(base, verdict="pass", oracle=oracle, checks=verdict["events_relevant"], mismatches=0,
                    expected={"status": PASSED}, observed=dict(context, status=PASSED),
                    first_causal_event="none: no violation")
    if status == FAILED and first is not None:
        identity_ok = expect is None or (expect["oracle"] == oracle and expect["kind"] == first["kind"])
        expected: Dict[str, Any] = {"oracle_rule": first["expected"]}
        if expect is not None:
            expected["defect_identity"] = dict(expect)
        observed = dict(context, kind=first["kind"], event_index=first["event_index"], t_ns=first["t_ns"], violation=first["observed"])
        return dict(base, verdict="fail", oracle=oracle if identity_ok else f"{oracle}.identity_mismatch",
                    checks=verdict["events_relevant"], mismatches=verdict["violation_count"],
                    expected=expected, observed=observed,
                    first_causal_event=f"{oracle}:{first['kind']} event_index={first['event_index']} t_ns={first['t_ns']} cause={first['cause']}")
    text = "oracle incomplete: " + (",".join(verdict["incomplete_reasons"]) or "no_evidence")
    return dict(base, verdict="fail", oracle=f"{oracle}.incomplete", checks=0, mismatches=0,
                expected={"status": PASSED}, observed=text, first_causal_event=text)


def write_case_result(path: str, result: Mapping[str, Any]) -> None:
    """Atomic tmp + rename.  Raises OSError / ValueError; the caller must treat
    any failure as 'no result', which can never pass."""
    data = canonical_json(result) + "\n"
    if len(data.encode("utf-8")) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds the 256 KiB limit")
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "x", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)  # our own scratch file only
        except OSError:
            pass
        raise


def _int_arg(text: str) -> int:
    return int(text, 0)


def _exit_code(status: str) -> int:
    return {PASSED: 0, FAILED: 1}.get(status, 2)


def _seed_from(seed: Optional[int]) -> int:
    if seed is not None:
        return seed
    raw = os.environ.get("FFW_SEED")
    if raw is None:
        raise ValueError("no seed: pass --seed or set FFW_SEED")
    if not (raw.isascii() and raw.isdigit()):
        raise ValueError("FFW_SEED must be a decimal integer")
    return int(raw)


def _result_target() -> Optional[Tuple[str, Dict[str, str]]]:
    """(path, ids) when the runner asked for a result file; ValueError if it did
    but the identifiers needed to make the result valid are missing."""
    path = os.environ.get("FFW_RESULT_PATH")
    if not path:
        return None
    ids = {}
    for key in ("FFW_RUN_ID", "FFW_CASE_ID", "FFW_RESULT_NONCE"):
        value = os.environ.get(key)
        if not value:
            raise ValueError(f"{key} is required when FFW_RESULT_PATH is set")
        ids[key] = value
    return path, ids


def _emit(payload: Mapping[str, Any], target: Optional[Tuple[str, Dict[str, str]]], oracle: str, verdict: Mapping[str, Any],
          context: Mapping[str, Any], expect: Optional[Mapping[str, str]], collateral: int) -> None:
    if target is not None:
        path, ids = target
        result = build_case_result(oracle, verdict, run_id=ids["FFW_RUN_ID"], case_id=ids["FFW_CASE_ID"],
                                   nonce=ids["FFW_RESULT_NONCE"], context=context, expect=expect, collateral=collateral)
        write_case_result(path, result)
    print(canonical_json(payload))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="oracles.py", description="Oracle replay and canary runner (offline, stdlib only).")
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay", help="re-derive one scenario from its seed")
    replay.add_argument("--seed", type=_int_arg, help="default: $FFW_SEED")
    replay.add_argument("--defect", choices=sorted(DEFECTS))
    replay.add_argument("--profile-json", help="JSON object of ScheduleProfile overrides")
    positive = sub.add_parser("positive", help="judge one oracle on the good run, requiring proof the guard was exercised")
    positive.add_argument("--oracle", choices=ORACLE_NAMES, required=True)
    positive.add_argument("--seed", type=_int_arg, help="default: $FFW_SEED")
    canaries = sub.add_parser("canaries", help="run every paired canary")
    canaries.add_argument("--seeds", type=_int_arg, nargs="+", default=list(CANARY_SEEDS))
    args = parser.parse_args(argv)
    try:
        if args.command == "replay":
            seed = _seed_from(args.seed)
            target = _result_target()
            overrides = json.loads(args.profile_json) if args.profile_json else None
            if overrides is not None and not isinstance(overrides, dict):
                raise ValueError("--profile-json must be a JSON object")
            profile = ScheduleProfile.from_overrides(overrides)
            if args.defect is None:
                if target is not None:
                    raise ValueError("a result file judges one oracle: use `replay --defect D` or `positive --oracle O`")
                result = run_case(seed, None, profile)
                print(canonical_json(result))
                return _exit_code(result["status"])
            spec, report, verdict, collateral = defect_verdict(seed, args.defect, profile)
            payload = {"schema": SCHEMA_REPORT, "status": report["status"], "seed": seed, "defect": args.defect, "reports": [report]}
            context = {"seed": seed, "defect": args.defect, "trace_digest": report["trace_digest"], "schedule_digest": report["schedule_digest"]}
            _emit(payload, target, spec.oracle, verdict, context, {"oracle": spec.oracle, "kind": spec.kind}, collateral)
            return _exit_code(verdict["status"])  # the question asked: did the corresponding oracle catch it?
        if args.command == "positive":
            seed = _seed_from(args.seed)
            target = _result_target()
            verdict, report = positive_verdict(args.oracle, seed)
            if verdict is None:
                raise ValueError(f"oracle {args.oracle!r} missing from the run")
            payload = {"schema": SCHEMA_REPORT, "status": verdict["status"], "seed": seed, "oracle": args.oracle, "reports": [report]}
            context = {"seed": seed, "trace_digest": report["trace_digest"], "schedule_digest": report["schedule_digest"]}
            _emit(payload, target, args.oracle, verdict, context, None, 0)
            return _exit_code(verdict["status"])
        results = [run_canary_all_seeds(name, args.seeds) for name in DEFECTS]
        positives = [run_positive(name, args.seeds) for name in ORACLE_NAMES]
        everything = results + positives
        summary = {
            "schema": SCHEMA_CANARY,
            "status": PASSED if all(r["status"] == PASSED for r in everything) else FAILED,
            "denominator": len(everything),
            "passed": sum(1 for r in everything if r["status"] == PASSED),
            "failed": sum(1 for r in everything if r["status"] != PASSED),
            "seeds": list(args.seeds),
            "cases": [{"case_id": r["case_id"], "status": r["status"]} for r in everything],
        }
        print(canonical_json(summary))
        return 0 if summary["status"] == PASSED else 1
    except (ValueError, TypeError, OSError, OracleUsageError) as exc:  # JSONDecodeError is a ValueError
        print(canonical_json({"schema": SCHEMA_REPORT, "status": INCOMPLETE, "error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
