#!/usr/bin/env python3
"""E05 boot-hook model (bead ffw-xcz): a deterministic boot-state simulator with fault injection.

It answers one question offline: given what is *known* about an image's boot chain, what happens to
audio ownership when the hook is missing, unreadable, hangs, fails, the launcher binary is missing or
dies, the machine loses power mid-write, or the unit restarts repeatedly?

Evidence discipline (the point of the module):

* An image profile is a set of eleven named facts.  Each is ``observed`` (with a value and a source) or
  ``unknown`` (with a named external blocker).  Nothing else.
* Every branch that depends on a fact calls ``need()``.  If any needed fact is unknown the whole run
  resolves to ``UNQUALIFIED`` and names the blockers; the simulation never guesses a value.
* "Hook present", "readable", "executed", "exited ok" and "service started" are separate predicates
  and separate events.  Nothing derives a later one from an earlier one.

This is a model of the contract in docs/contracts/e05.md.  It touches no device, network or file other
than the profile you name, and it contains no write primitive: it models how the boot chain *consumes*
a hook and what the launcher does when something goes wrong.  Judging a trace is a separate module
(trace_check.py) that does not import this one.

    boot_model.py trace  --profile P [--fault KIND[@STEP] ...] [--policy k=v ...] [--provision SUB]
                         [--update none|power_loss] [--prior absent|valid]
    boot_model.py matrix --profile P [--cases tests/e05/cases.json]

Exit: 0 verdict STOCK_OK/CUSTOM_OK and no violation; 3 UNQUALIFIED (blockers listed, never a pass);
1 FAILED or a violation; 2 usage or malformed input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PROFILE_SCHEMA = "ffw.e05.profile.v1"
BLOCKER_RE = re.compile(r"^EXT-E05-[A-Z0-9]+(-[A-Z0-9]+)*$")

# The eleven facts.  Order is documentation only.
FACT_IDS: Tuple[str, ...] = (
    "hook_gate_existence_only",     # the boot script skips the hook iff the file is absent
    "hook_interpreted",             # the hook is run by an interpreter, so no exec bit is needed
    "hook_runs_synchronously",      # boot waits for the hook to return
    "hook_failure_nonfatal",        # a failing hook does not abort boot
    "jffs_noexec",                  # binaries on the writable partition are not runnable in place
    "stock_stop_effective",         # a stopped stock daemon stays stopped (no respawn)
    "watchdog_covers_boot_stall",   # a stalled boot is reset by a watchdog
    "watchdog_restarts_daemon",     # a stopped/killed stock daemon is restarted by a watchdog
    "fs_rename_atomic",             # rename over an existing file is atomic across power loss
    "hook_survives_update",         # an update keeps the hook
    "update_interrupted_preserves_hook",  # an interrupted update keeps the hook
)

STEPS: Tuple[str, ...] = (
    "jffs_mount", "hook_gate", "hook_read", "hook_run", "preflight",
    "stock_stop", "custom_start", "custom_ready", "owner_commit",
)

# Declared fault table: the denominator the cases must cover.  power_loss is transient (fires once);
# every other kind is a persistent condition that is true on every boot.
FAULT_TABLE: Dict[str, Tuple[str, ...]] = {
    "jffs_mount": ("power_loss",),
    "hook_gate": ("hook_missing", "power_loss"),
    "hook_read": ("hook_unreadable", "hook_mode_no_exec", "power_loss"),
    "hook_run": ("hook_hangs", "hook_exits_nonzero", "power_loss"),
    "preflight": ("binary_missing", "binary_not_runnable", "power_loss"),
    "stock_stop": ("stock_stop_fails", "power_loss"),
    "custom_start": ("binary_start_fails", "power_loss"),
    "custom_ready": ("binary_exits_nonzero", "binary_hangs", "power_loss"),
    "owner_commit": ("binary_crashes_after_ready", "power_loss"),
}
PROVISION_SUBS: Dict[str, Tuple[str, ...]] = {
    "atomic": ("write_temp", "fsync_temp", "rename", "fsync_dir"),
    "in_place": ("truncate", "write", "fsync"),
}
UPDATE_FAULTS: Tuple[str, ...] = ("none", "power_loss")
HOOK_STATES = ("absent", "valid", "partial")
SAFETY_RESTARTS = 12   # the model gives up here and reports an unbounded loop


class ModelError(ValueError):
    """Bad input (profile, fault, policy).  Exit 2, never a verdict."""


class _Unqualified(Exception):
    def __init__(self, facts: List[str], blockers: List[str]):
        super().__init__(",".join(facts))
        self.facts, self.blockers = facts, blockers


class _Done(Exception):
    def __init__(self, kind: str, reason: str, extra: Dict[str, Any]):
        super().__init__(kind)
        self.kind, self.reason, self.extra = kind, reason, extra


class _Reboot(Exception):
    pass


@dataclass(frozen=True)
class Policy:
    """The launcher discipline under test.  The defaults are the safe baseline; every other value is a
    deliberate defect used as a planted negative."""
    atomic_write: bool = True          # False: in-place rewrite of the hook
    preflight: bool = True             # check the binary before stopping stock
    stop_ack_required: bool = True     # wait for the stock-stop acknowledgement
    unmute: str = "after_stable"       # after_stable | at_ready | at_start
    attempt_cap: Optional[int] = 3     # None: no bound
    backoff: bool = True               # False: restart at once
    restore_stock: bool = True         # False: no rollback path
    log_reasons: bool = True           # False: transitions carry no reason
    claim_from_presence: bool = False  # True: report success because the hook exists
    strict_unknown: bool = True        # False: an unknown fact is read as "fine"
    binary_location: str = "exec_fs"   # exec_fs | jffs


def policy_from_pairs(pairs: Sequence[str]) -> Policy:
    pol = Policy()
    for pair in pairs:
        if "=" not in pair:
            raise ModelError("policy must be key=value: %r" % pair)
        key, raw = pair.split("=", 1)
        if not hasattr(pol, key):
            raise ModelError("unknown policy key %r" % key)
        cur = getattr(pol, key)
        if raw in ("none", "None") and key == "attempt_cap":
            val: Any = None
        elif isinstance(cur, bool):
            if raw not in ("true", "false"):
                raise ModelError("policy %s must be true|false" % key)
            val = raw == "true"
        elif key == "attempt_cap":
            try:
                val = int(raw)
            except ValueError:
                raise ModelError("policy attempt_cap must be an integer or none")
            if val < 1:
                raise ModelError("policy attempt_cap must be >= 1")
        else:
            val = raw
        pol = replace(pol, **{key: val})
    if pol.unmute not in ("after_stable", "at_ready", "at_start"):
        raise ModelError("policy unmute must be after_stable|at_ready|at_start")
    if pol.binary_location not in ("exec_fs", "jffs"):
        raise ModelError("policy binary_location must be exec_fs|jffs")
    return pol


# --------------------------------------------------------------------------------------- profiles

def load_profile(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ModelError("cannot read profile %s: %s" % (os.path.basename(path), exc))
    return validate_profile(doc)


def validate_profile(doc: Any) -> Dict[str, Any]:
    if not isinstance(doc, dict) or set(doc) != {"schema", "image", "kind", "facts"}:
        raise ModelError("profile must have exactly schema, image, kind, facts")
    if doc["schema"] != PROFILE_SCHEMA:
        raise ModelError("unsupported profile schema %r" % (doc["schema"],))
    if not isinstance(doc["image"], str) or not doc["image"]:
        raise ModelError("profile image must be a non-empty string")
    if doc["kind"] not in ("synthetic", "extracted"):
        raise ModelError("profile kind must be synthetic|extracted")
    facts = doc["facts"]
    if not isinstance(facts, dict) or set(facts) != set(FACT_IDS):
        missing = sorted(set(FACT_IDS) - set(facts or {}))
        extra = sorted(set(facts or {}) - set(FACT_IDS))
        raise ModelError("profile facts must be exactly the eleven named facts (missing %s, extra %s)" % (missing, extra))
    for fid, fact in facts.items():
        if not isinstance(fact, dict):
            raise ModelError("fact %s must be an object" % fid)
        status = fact.get("status")
        if status == "observed":
            if set(fact) != {"status", "value", "source"}:
                raise ModelError("observed fact %s must have exactly status, value, source" % fid)
            if not isinstance(fact["value"], bool):
                raise ModelError("observed fact %s value must be a boolean" % fid)
            if not isinstance(fact["source"], str) or not fact["source"].strip():
                raise ModelError("observed fact %s needs a source" % fid)
        elif status == "unknown":
            if set(fact) != {"status", "blocker"}:
                raise ModelError("unknown fact %s must have exactly status, blocker" % fid)
            if not isinstance(fact["blocker"], str) or not BLOCKER_RE.match(fact["blocker"]):
                raise ModelError("unknown fact %s needs a blocker like EXT-E05-NAME" % fid)
        else:
            raise ModelError("fact %s status must be observed|unknown" % fid)
    return doc


def with_facts(profile: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``profile`` with some facts replaced.  A bool means observed-with-that-value
    (source 'override'); the string 'unknown' means unknown (blocker EXT-E05-OVERRIDE)."""
    facts = {k: dict(v) for k, v in profile["facts"].items()}
    for fid, val in overrides.items():
        if fid not in FACT_IDS:
            raise ModelError("unknown fact %r" % fid)
        if val == "unknown":
            facts[fid] = {"status": "unknown", "blocker": "EXT-E05-OVERRIDE"}
        elif isinstance(val, bool):
            facts[fid] = {"status": "observed", "value": val, "source": "override in a test scenario"}
        else:
            raise ModelError("override for %s must be true, false or 'unknown'" % fid)
    return validate_profile({"schema": profile["schema"], "image": profile["image"],
                             "kind": profile["kind"], "facts": facts})


# ------------------------------------------------------------------------------------- simulation

class _Sim:
    def __init__(self, profile: Dict[str, Any], policy: Policy, faults: Sequence[Dict[str, str]],
                 hook: str, max_boots: int):
        self.profile, self.pol = profile, policy
        self.persistent = {f["kind"] for f in faults if f["kind"] != "power_loss"}
        self.pending_loss = [f["step"] for f in faults if f["kind"] == "power_loss"]
        self.hook, self.max_boots = hook, max_boots
        self.events: List[Dict[str, Any]] = []
        self.depends: set = set()
        self.counter = 0
        self.b = 0
        self.owners: List[str] = ["STOCK"]
        self.audible = False
        self.pred = {"present": False, "readable": False, "executed": False,
                     "exited_ok": False, "service_started": False}

    # -- plumbing -------------------------------------------------------------------------------
    def ev(self, event: str, step: str, reason: Optional[str] = None, **extra: Any) -> None:
        rec: Dict[str, Any] = {"n": len(self.events), "boot": self.b, "step": step, "event": event,
                               "owners": list(self.owners), "audible": self.audible}
        if self.pol.log_reasons:
            if reason is not None:
                rec["reason"] = reason
        else:
            extra = {k: v for k, v in extra.items() if k != "rollback_reason"}
        rec.update(extra)
        self.events.append(rec)

    def need(self, *fact_ids: str) -> List[bool]:
        vals: List[bool] = []
        unknown: List[str] = []
        for fid in fact_ids:
            fact = self.profile["facts"][fid]
            self.depends.add(fid)
            if fact["status"] == "observed":
                vals.append(fact["value"])
            else:
                unknown.append(fid)
                vals.append(True)
        if unknown and self.pol.strict_unknown:
            raise _Unqualified(unknown, sorted({self.profile["facts"][f]["blocker"] for f in unknown}))
        return vals

    def loss(self, step: str) -> None:
        if step in self.pending_loss:
            self.pending_loss.remove(step)
            self.ev("power_loss", step, reason="power_loss")
            raise _Reboot()

    def finish(self, kind: str, reason: str, step: str, **extra: Any) -> None:
        if kind == "STOCK_OK":
            self.owners, self.audible = ["STOCK"], True
        elif kind == "CUSTOM_OK":
            self.audible = True
        claims = {k: (True if self.pol.claim_from_presence and self.pred["present"] else v)
                  for k, v in self.pred.items()}
        self.ev("status_report", step, claims=claims)
        self.ev("verdict", step, reason=reason, kind=kind)
        raise _Done(kind, reason, extra)

    def stall(self, reason: str, step: str) -> None:
        self.owners, self.audible = [], False
        self.ev("boot_stalled", step, reason=reason)
        (covers,) = self.need("watchdog_covers_boot_stall")
        if covers:
            self.ev("watchdog_reboot", step, reason="watchdog_reboot")
            raise _Reboot()
        self.finish("FAILED", "no_recovery_path", step, cause=reason)

    def hook_failed(self, reason: str, step: str) -> None:
        (nonfatal,) = self.need("hook_failure_nonfatal")
        if nonfatal:
            self.ev("hook_failed", step, reason=reason)
            self.finish("STOCK_OK", reason, step)
        self.stall(reason, step)

    def rollback(self, reason: str, step: str, stopped: bool) -> None:
        self.ev("rollback", step, reason=reason, rollback_reason=reason)
        if stopped:
            ok = self.pol.restore_stock
            if ok:
                (ok,) = self.need("watchdog_restarts_daemon")
            if not ok:
                self.owners, self.audible = [], False
                self.finish("FAILED", "no_recovery_path", step, cause=reason)
        self.finish("STOCK_OK", reason, step)

    def binary_problem(self) -> Optional[str]:
        if "binary_missing" in self.persistent:
            return "binary_missing"
        if "binary_not_runnable" in self.persistent:
            return "binary_not_runnable"
        if self.pol.binary_location == "jffs":
            (noexec,) = self.need("jffs_noexec")
            if noexec:
                return "binary_not_runnable"
        return None

    # -- one boot -------------------------------------------------------------------------------
    def boot(self) -> None:
        self.b += 1
        self.owners, self.audible = ["STOCK"], False
        self.pred = dict.fromkeys(self.pred, False)   # predicates are per boot: nothing carries over a reboot
        self.ev("boot_start", "jffs_mount")
        self.loss("jffs_mount")

        step = "hook_gate"
        hook = "absent" if "hook_missing" in self.persistent else self.hook
        (existence_only,) = self.need("hook_gate_existence_only")
        if hook == "absent":
            if existence_only:
                self.finish("STOCK_OK", "hook_absent", step)
            self.hook_failed("hook_absent_unskipped", step)
        self.ev("hook_present", step)
        self.pred["present"] = True
        self.loss(step)

        step = "hook_read"
        if "hook_unreadable" in self.persistent:
            self.hook_failed("hook_unreadable", step)
        if "hook_mode_no_exec" in self.persistent:
            (interpreted,) = self.need("hook_interpreted")
            if not interpreted:
                self.hook_failed("hook_not_executable", step)
        self.ev("hook_readable", step)
        self.pred["readable"] = True
        self.loss(step)

        step = "hook_run"
        if hook == "partial":
            self.owners, self.audible = [], False
            self.ev("hook_partial_executed", step, reason="partial_hook_executed")
            self.finish("FAILED", "partial_hook_executed", step)
        cap = self.pol.attempt_cap
        if cap is not None and self.counter >= cap:
            self.ev("attempt_cap_reached", step, reason="attempt_cap")
            self.finish("STOCK_OK", "attempt_cap", step)
        self.counter += 1
        self.ev("hook_started", step, counter=self.counter)
        self.pred["executed"] = True
        self.loss(step)
        if "hook_hangs" in self.persistent:
            (sync,) = self.need("hook_runs_synchronously")
            if sync:
                self.stall("hook_hang", step)
            self.ev("hook_hang_background", step, reason="hook_hang_async")
            self.finish("STOCK_OK", "hook_hang_async", step)
        if "hook_exits_nonzero" in self.persistent:
            self.hook_failed("hook_failed", step)

        step = "preflight"
        if self.pol.preflight:
            bad = self.binary_problem()
            if bad:
                self.rollback(bad, step, stopped=False)
            self.ev("preflight_ok", step)
        self.loss(step)

        step = "stock_stop"
        if "stock_stop_fails" in self.persistent:
            if self.pol.stop_ack_required:
                self.ev("stop_ack_missing", step, reason="stop_ack_missing")
                self.rollback("stop_ack_missing", step, stopped=True)
            self.ev("stop_ack_ignored", step, reason="stop_ack_not_required")
        else:
            (effective,) = self.need("stock_stop_effective")
            if not effective:
                self.ev("stock_respawned", step, reason="stock_respawn_detected")
                self.finish("STOCK_OK", "stock_respawn_detected", step)
            self.owners = []
            self.ev("stock_stopped", step)
        self.loss(step)

        step = "custom_start"
        if not self.pol.preflight:
            bad = self.binary_problem()
            if bad:
                self.rollback(bad, step, stopped=True)
        if "binary_start_fails" in self.persistent:
            self.rollback("binary_start_failed", step, stopped=True)
        self.owners = self.owners + ["CUSTOM"]
        self.ev("custom_started", step)
        if self.pol.unmute == "at_start":
            self.audible = True
            self.ev("unmuted", step)
        self.loss(step)

        step = "custom_ready"
        if "binary_exits_nonzero" in self.persistent:
            self.rollback("binary_exit", step, stopped=True)
        if "binary_hangs" in self.persistent:
            self.rollback("ready_timeout", step, stopped=True)
        self.ev("custom_ready", step)
        self.pred["service_started"] = True
        if self.pol.unmute == "at_ready":
            self.audible = True
            self.ev("unmuted", step)
        self.loss(step)

        step = "owner_commit"
        if "binary_crashes_after_ready" in self.persistent:
            restarts, delay = 0, 1
            while True:
                self.audible = False
                self.ev("custom_crashed", step, reason="crash_after_ready")
                restarts += 1
                cap = self.pol.attempt_cap
                if cap is not None and restarts >= cap:
                    self.rollback("restart_cap", step, stopped=True)
                if restarts >= SAFETY_RESTARTS:
                    self.finish("FAILED", "restart_loop_unbounded", step)
                wait = delay if self.pol.backoff else 0
                self.ev("restart_scheduled", step, reason="restart_after_crash", delay=wait)
                delay = min(delay * 2, 64)
                self.ev("custom_ready", step)
                if self.pol.unmute == "at_ready":
                    self.audible = True
                    self.ev("unmuted", step)
        self.ev("stable", step)
        if not self.audible:
            self.audible = True
            self.ev("unmuted", step)
        self.counter = 0
        self.ev("counter_reset", step)
        self.ev("hook_exited_ok", step)
        self.pred["exited_ok"] = True
        self.loss(step)
        self.finish("CUSTOM_OK", "custom_owner", step)

    def run(self) -> Dict[str, Any]:
        result: Dict[str, Any]
        try:
            while True:
                if self.b >= self.max_boots:
                    self.ev("verdict", self.events[-1]["step"], reason="restart_loop_unbounded", kind="FAILED")
                    result = {"kind": "FAILED", "reason": "restart_loop_unbounded"}
                    break
                try:
                    self.boot()
                except _Reboot:
                    continue
        except _Done as done:
            result = {"kind": done.kind, "reason": done.reason}
            result.update(done.extra)
        except _Unqualified as unq:
            self.ev("unqualified", self.events[-1]["step"] if self.events else "jffs_mount",
                    reason="unknown_fact", facts=unq.facts, blockers=unq.blockers)
            result = {"kind": "UNQUALIFIED", "reason": "unknown_fact", "facts": unq.facts,
                      "blockers": unq.blockers}
        result["depends"] = sorted(self.depends)
        return {"image": self.profile["image"], "boots": self.b, "events": self.events, "verdict": result}


def _norm_faults(faults: Sequence[Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for f in faults:
        if isinstance(f, str):
            kind, _, step = f.partition("@")
            f = {"kind": kind, "step": step} if step else {"kind": kind}
        kind, step = f.get("kind"), f.get("step")
        if kind == "power_loss":
            if step not in FAULT_TABLE:
                raise ModelError("power_loss needs @STEP, one of %s" % ", ".join(STEPS))
            out.append({"kind": kind, "step": step})
            continue
        owners = [s for s, kinds in FAULT_TABLE.items() if kind in kinds]
        if not owners:
            raise ModelError("unknown fault %r" % (kind,))
        if step is not None and step not in owners:
            raise ModelError("fault %s does not apply at step %s" % (kind, step))
        out.append({"kind": kind, "step": step or owners[0]})
    return out


def simulate(profile: Dict[str, Any], policy: Optional[Policy] = None, faults: Sequence[Any] = (), *,
             provision: Optional[str] = None, update: Optional[str] = None, prior: str = "valid",
             max_boots: int = 8) -> Dict[str, Any]:
    """Run one scenario and return {image, boots, events, verdict}.  Pure: same input, same output."""
    validate_profile(profile)
    pol = policy or Policy()
    if prior not in ("absent", "valid"):
        raise ModelError("prior must be absent|valid")
    if not isinstance(max_boots, int) or max_boots < 1:
        raise ModelError("max_boots must be a positive integer")
    if provision is not None and update is not None:
        raise ModelError("provision and update are separate scenarios")
    sim = _Sim(profile, pol, _norm_faults(faults), prior, max_boots)
    pre: Optional[Dict[str, Any]] = None
    try:
        if provision is not None:
            sim.hook = _provision(sim, provision, prior)
        elif update is not None:
            sim.hook = _update(sim, update, prior)
    except _Unqualified as unq:
        sim.ev("unqualified", "provision" if provision else "update", reason="unknown_fact",
               facts=unq.facts, blockers=unq.blockers)
        pre = {"kind": "UNQUALIFIED", "reason": "unknown_fact", "facts": unq.facts,
               "blockers": unq.blockers, "depends": sorted(sim.depends)}
    if pre is not None:
        return {"image": profile["image"], "boots": 0, "events": sim.events, "verdict": pre}
    return sim.run()


def _provision(sim: _Sim, sub: str, prior: str) -> str:
    family = "atomic" if sim.pol.atomic_write else "in_place"
    if sub not in PROVISION_SUBS[family]:
        raise ModelError("provision step %r does not exist for the %s discipline" % (sub, family))
    if family == "atomic":
        if sub in ("write_temp", "fsync_temp"):
            state = prior
        else:
            (atomic,) = sim.need("fs_rename_atomic")
            if not atomic:
                state = "partial"
            else:
                state = prior if sub == "rename" else "valid"
    else:
        state = "partial" if sub in ("truncate", "write") else "valid"
    sim.ev("provision_power_loss", "provision", reason="power_loss", sub=sub, hook_after=state)
    return state


def _update(sim: _Sim, fault: str, prior: str) -> str:
    if fault not in UPDATE_FAULTS:
        raise ModelError("update fault must be none|power_loss")
    fid = "hook_survives_update" if fault == "none" else "update_interrupted_preserves_hook"
    (keeps,) = sim.need(fid)
    state = prior if keeps else "absent"
    sim.ev("update_applied", "update", reason="update_%s" % fault, hook_after=state)
    return state


# --------------------------------------------------------------------------------------- CLI

def _load_cases(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise ModelError("cannot read cases %s: %s" % (os.path.basename(path), exc))


def run_cell(profile: Dict[str, Any], cell: Dict[str, Any]) -> Dict[str, Any]:
    """Run one hand-written cell (see tests/e05/cases.json) against ``profile``."""
    pol = policy_from_pairs(["%s=%s" % (k, ("none" if v is None else str(v).lower() if isinstance(v, bool) else v))
                             for k, v in (cell.get("policy") or {}).items()])
    prof = with_facts(profile, cell["facts"]) if cell.get("facts") else profile
    kind, step = cell["kind"], cell["step"]
    if step == "provision":
        return simulate(prof, pol, provision=kind, prior=cell.get("prior", "valid"))
    if step == "update":
        return simulate(prof, pol, update=kind, prior=cell.get("prior", "valid"))
    faults = [] if kind == "none" else [{"kind": kind, "step": step}]
    return simulate(prof, pol, faults, prior=cell.get("prior", "valid"))


def _cmd_trace(args: argparse.Namespace) -> int:
    from trace_check import check_trace
    profile = load_profile(args.profile)
    result = simulate(profile, policy_from_pairs(args.policy or []), args.fault or [],
                      provision=args.provision, update=args.update, prior=args.prior)
    violations = check_trace(result, profile)
    for rec in result["events"]:
        sys.stdout.write(json.dumps(rec, sort_keys=True) + "\n")
    sys.stdout.write(json.dumps({"verdict": result["verdict"], "boots": result["boots"],
                                 "violations": violations}, sort_keys=True) + "\n")
    kind = result["verdict"]["kind"]
    if violations or kind == "FAILED":
        return 1
    return 3 if kind == "UNQUALIFIED" else 0


def _cmd_matrix(args: argparse.Namespace) -> int:
    from trace_check import check_trace
    profile = load_profile(args.profile)
    cases = _load_cases(args.cases)
    rows, blockers, counts, mismatches = [], {}, {}, 0
    for cell in cases["cells"]:
        res = run_cell(profile, cell)
        v = res["verdict"]
        viol = [x["kind"] for x in check_trace(res, profile)]
        exp = (cell.get("expect") or {}).get(profile["image"])
        ok: Optional[bool] = None
        if exp is not None:
            ok = (v["kind"] == exp["verdict"] and res["boots"] == exp["boots"]
                  and v.get("reason") == exp.get("reason", v.get("reason"))
                  and v.get("blockers") == exp.get("blockers", v.get("blockers"))
                  and (not viol or exp["verdict"] == "FAILED"))
            mismatches += 0 if ok else 1
        elif viol:
            mismatches += 1
        rows.append({"cell": cell["id"], "verdict": v["kind"], "reason": v["reason"],
                     "blockers": v.get("blockers", []), "violations": viol, "as_expected": ok})
        counts[v["kind"]] = counts.get(v["kind"], 0) + 1
        for b in v.get("blockers", []):
            blockers[b] = blockers.get(b, 0) + 1
    out = {"image": profile["image"], "cells": len(rows), "counts": counts,
           "blocked_by": dict(sorted(blockers.items())), "mismatches": mismatches, "rows": rows}
    sys.stdout.write(json.dumps(out, sort_keys=True, indent=1) + "\n")
    return 1 if mismatches else (3 if counts.get("UNQUALIFIED") else 0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="E05 boot-hook model (offline; touches only the files named)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("trace", help="run one scenario and print its JSONL trace and verdict")
    t.add_argument("--profile", required=True)
    t.add_argument("--fault", action="append", help="KIND or KIND@STEP (power_loss needs @STEP)")
    t.add_argument("--policy", action="append", help="key=value launcher policy override")
    t.add_argument("--provision", help="power loss during the hook write at this sub-step")
    t.add_argument("--update", help="none|power_loss: boot after an update")
    t.add_argument("--prior", default="valid", help="hook state before provisioning/update: absent|valid")
    m = sub.add_parser("matrix", help="run every hand-written cell against a profile")
    m.add_argument("--profile", required=True)
    m.add_argument("--cases", default=os.path.join(HERE, "..", "..", "tests", "e05", "cases.json"))
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        return _cmd_trace(args) if args.cmd == "trace" else _cmd_matrix(args)
    except ModelError as exc:
        sys.stderr.write("boot_model: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
