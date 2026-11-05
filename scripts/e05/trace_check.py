#!/usr/bin/env python3
"""E05 trace checker (bead ffw-xcz): judges a boot-model trace against the invariants.

This module deliberately does NOT import boot_model.  It reads only the trace schema (events with
boot, step, event, owners, audible, reason, claims, delay; and a verdict) and the profile's fact
statuses, so a defect in the simulator cannot also hide itself here.

    check_trace(trace, profile) -> list of {"kind": ..., "n": event index or None, "detail": ...}

Violation kinds, grouped by the invariant they enforce (docs/contracts/e05.md section 4):

  INV-1 one owner       two_owners, audible_unowned, audible_before_ready, bad_terminal_owner
  INV-2 recovery        no_recovery_path
  INV-3 bounded loops   unbounded_restarts, no_backoff, repeated_audible_activation
  INV-4 torn write      partial_hook_executed
  INV-5 reasons         missing_reason
  INV-6 unknown != ok   unknown_resolved_ok
  PRED  predicates      unsupported_claim
  ORDER                 step_order
"""
from __future__ import annotations

from typing import Any, Dict, List

STEP_ORDER = ("jffs_mount", "hook_gate", "hook_read", "hook_run", "preflight",
              "stock_stop", "custom_start", "custom_ready", "owner_commit")

# Events that change the path a boot takes.  Each must say why.
REASON_REQUIRED = frozenset({
    "power_loss", "provision_power_loss", "update_applied", "hook_failed", "hook_partial_executed",
    "hook_hang_background", "boot_stalled", "watchdog_reboot", "attempt_cap_reached", "rollback",
    "stop_ack_missing", "stop_ack_ignored", "stock_respawned", "custom_crashed", "restart_scheduled",
    "unqualified", "verdict",
})

# Which earlier event in the same boot establishes each reported predicate.
CLAIM_EVIDENCE = {
    "present": "hook_present",
    "readable": "hook_readable",
    "executed": "hook_started",
    "exited_ok": "hook_exited_ok",
    "service_started": "custom_ready",
}

MAX_BOOTS = 6
MAX_RESTARTS_PER_BOOT = 5


def _v(kind: str, n: Any, detail: str) -> Dict[str, Any]:
    return {"kind": kind, "n": n, "detail": detail}


def check_trace(trace: Dict[str, Any], profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    events = trace["events"]
    verdict = trace["verdict"]

    last_step_idx: Dict[int, int] = {}
    seen: Dict[int, set] = {}
    restarts: Dict[int, int] = {}
    delays: Dict[int, List[int]] = {}
    custom_unmutes: Dict[int, int] = {}

    for e in events:
        n, boot, step, name = e["n"], e["boot"], e["step"], e["event"]
        seen.setdefault(boot, set())

        if step in STEP_ORDER:
            idx = STEP_ORDER.index(step)
            if idx < last_step_idx.get(boot, -1):
                out.append(_v("step_order", n, "%s after a later step in boot %d" % (step, boot)))
            last_step_idx[boot] = max(idx, last_step_idx.get(boot, -1))

        if name == "custom_ready":
            seen[boot].add("custom_ready")

        owners = e["owners"]
        if len(owners) > 1:
            out.append(_v("two_owners", n, "owners %s at %s" % (owners, name)))
        if e["audible"] and not owners:
            out.append(_v("audible_unowned", n, "audible with no owner at %s" % name))
        if e["audible"] and "CUSTOM" in owners and "custom_ready" not in seen[boot]:
            out.append(_v("audible_before_ready", n, "custom audible before ready at %s" % name))

        if name == "restart_scheduled":
            restarts[boot] = restarts.get(boot, 0) + 1
            delays.setdefault(boot, []).append(e.get("delay", 0))
        if name == "unmuted" and "CUSTOM" in owners:
            custom_unmutes[boot] = custom_unmutes.get(boot, 0) + 1
        if name == "hook_partial_executed":
            out.append(_v("partial_hook_executed", n, "a half-written hook was executed"))

        if name in REASON_REQUIRED and not e.get("reason"):
            out.append(_v("missing_reason", n, "%s carries no reason" % name))
        if name == "rollback" and not e.get("rollback_reason"):
            out.append(_v("missing_reason", n, "rollback carries no rollback_reason"))

        if name == "status_report":
            for claim, value in e.get("claims", {}).items():
                if not value:
                    continue
                needed = CLAIM_EVIDENCE.get(claim)
                if needed is None or not any(x["boot"] == boot and x["event"] == needed and x["n"] < n
                                             for x in events):
                    out.append(_v("unsupported_claim", n, "claims %s without a %s event" % (claim, needed)))

    for boot, count in restarts.items():
        if count > MAX_RESTARTS_PER_BOOT:
            out.append(_v("unbounded_restarts", None, "boot %d restarted %d times" % (boot, count)))
    for boot, seq in delays.items():
        if any(d < 1 for d in seq) or any(b < a for a, b in zip(seq, seq[1:])):
            out.append(_v("no_backoff", None, "boot %d restart delays %s" % (boot, seq)))
    for boot, count in custom_unmutes.items():
        if count > 1:
            out.append(_v("repeated_audible_activation", None, "boot %d unmuted custom %d times" % (boot, count)))
    if trace.get("boots", 0) > MAX_BOOTS:
        out.append(_v("unbounded_restarts", None, "%d boots" % trace["boots"]))

    kind, reason = verdict["kind"], verdict.get("reason")
    if kind == "FAILED" and reason == "no_recovery_path":
        out.append(_v("no_recovery_path", None, "cause: %s" % verdict.get("cause")))
    if kind == "FAILED" and reason == "restart_loop_unbounded":
        out.append(_v("unbounded_restarts", None, "restart loop never settled"))

    last = events[-1] if events else None
    if kind == "STOCK_OK" and last is not None and (last["owners"] != ["STOCK"] or not last["audible"]):
        out.append(_v("bad_terminal_owner", last["n"], "STOCK_OK must end with stock as the audible owner"))
    if kind == "CUSTOM_OK" and last is not None and ("CUSTOM" not in last["owners"] or not last["audible"]):
        out.append(_v("bad_terminal_owner", last["n"], "CUSTOM_OK must end with custom as the audible owner"))

    if kind in ("STOCK_OK", "CUSTOM_OK"):
        for fid in verdict.get("depends", []):
            if profile["facts"][fid]["status"] != "observed":
                out.append(_v("unknown_resolved_ok", None, "%s resolved ok but depends on unknown fact %s" % (kind, fid)))
    return out
