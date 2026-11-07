"""Judge the U02 vectors through the reference model, with or without planted defects, and check properties directly on what the model did.

Two independent verdicts, as in G02:

* `failing(doc, bugs)` replays every vector through the reference (with `bugs` switched on) and names the vectors whose observed outcome differs
  from the hand-written expectation stored in the file. With no bug it must name none (the control).
* `unsound(doc, bugs)` ignores the stored expectations altogether and checks first-principles properties on what the model did: an admission that
  went through really satisfies every rule (the signature is checked by the OpenSSL-validated oracle, not by the model's code), an artifact that
  verified really has the right length and digest, a group answer really names no action on another member, the floor moves only where it may.
  A defect that makes the model accept something it should not is therefore caught here without any stored expected value; a defect that only
  over-refuses is caught by the stored positives alone, and `OVER_REFUSAL` names those.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, FrozenSet, List, Optional

import ed25519_ref as ed
import make_vectors as mv
import reference as ref

OVER_REFUSAL = frozenset({"backup_ignored"})
NEEDS_A_CRASH = frozenset({"commit_not_atomic"})


def _summary(admitted: Dict[str, Any]) -> Dict[str, Any]:
    return mv.summarize(admitted)


def _outcome(fn) -> Dict[str, Any]:
    return mv.outcome(fn)


def failing(doc: Dict[str, Any], bugs: FrozenSet[str] = frozenset()) -> List[str]:
    bad: List[str] = []
    for v in doc["ed25519"]:
        if ed.verify(bytes.fromhex(v["public"]), bytes.fromhex(v["message"]), bytes.fromhex(v["signature"])) != v["expect"]:
            bad.append(v["id"])
    for v in doc["keys_check"]:
        if ed.key_ok(bytes.fromhex(v["public"])) != v["expect"]:
            bad.append(v["id"])
    for v in doc["trust"]:
        got = _outcome(lambda v=v: (ref.TrustStore([(bytes.fromhex(k["public"]), k["revoked"]) for k in v["keys"]], bugs), "built")[1])
        if got != v["expect"]:
            bad.append(v["id"])
    for v in doc["parse"]:
        if _outcome(lambda v=v: {"version": ref.parse(bytes.fromhex(v["manifest"]))["version"]}) != v["expect"]:
            bad.append(v["id"])
    for v in doc["admit"]:
        got = _outcome(lambda v=v: _summary(ref.admit(mv.build_ctx(v["ctx"], bugs), bytes.fromhex(v["manifest"]), bugs)))
        if got != v["expect"]:
            bad.append(v["id"])
    for v in doc["artifact"]:
        m = ref.parse(bytes.fromhex(v["manifest"]))
        if _outcome(lambda v=v, m=m: (ref.check_artifact(m, bytes.fromhex(v["artifact"]), bugs), "verified")[1]) != v["expect"]:
            bad.append(v["id"])
    arts = {k: bytes.fromhex(x) for k, x in doc["engine_assets"]["artifacts"].items()}
    mans = {k: bytes.fromhex(x) for k, x in doc["engine_assets"]["manifests"].items()}
    for script in doc["engine"]:
        got = play(script, arts, mans, bugs)
        if any(g["result"] != op["expect"]["result"] or g["state"] != op["expect"]["state"] for g, op in zip(got, script["ops"])):
            bad.append(script["id"])
    for v in doc["group"]:
        members = [ref.Member(m["id"], _image(m["image"]), m["connected"]) for m in v["members"]]
        if ref.group_decision(members, v["index"], _image(v["candidate"]), bugs) != v["expect"]:
            bad.append(v["id"])
    for v in doc["rollback"]:
        if ref.rollback_decision(v["stored_settings_schema"], v["settings_backup"], _image(v["target"]), bugs) != v["expect"]:
            bad.append(v["id"])
    return bad


def _image(d: Optional[Dict[str, Any]]) -> Optional[ref.Installed]:
    return None if d is None else ref.Installed(d["version"], d["security_version"], d["settings_schema"], d["settings_read_min"], d["calibration_schema"],
                                                d["wire_schema"], d["wire_read_min"], d["wire_read_max"], d["features"], bytes.fromhex(d["sha"]))


def play(script: Dict[str, Any], arts: Dict[str, bytes], mans: Dict[str, bytes], bugs: FrozenSet[str] = frozenset()) -> List[Dict[str, Any]]:
    return mv.play(script["ctx"], script["ops"], arts, mans, bugs)


# --------------------------------------------------------------------------------------------------------- first principles


def admission_problem(spec: Dict[str, Any], raw: bytes, summary: Dict[str, Any]) -> Optional[str]:
    """Why an ADMITTED manifest should not have been, written from the contract and checked with the oracle; None if it is sound."""
    m = ref.parse(raw)
    keys = {ref.key_id_of(bytes.fromhex(mv.PUBS[k["key"]].hex())): (mv.PUBS[k["key"]], k["revoked"]) for k in spec["trust"]}
    if m["key_id"] not in keys:
        return "signed by a key that is not in the trust store"
    public, revoked = keys[m["key_id"]]
    if revoked:
        return "signed by a revoked key"
    if not ed.verify(public, ref.DOMAIN + m["body"], m["sig"]):
        return "the signature does not verify over the domain-separated body"
    if m["stage"] != ref.STAGE_USERSPACE or m["flags"] != 0:
        return "a stage other than our userspace payload, or a vendor, bypass or A/B claim"
    b = mv.BOARDS[spec["board"]]
    if (m["profile_id"], m["hw_rev"], m["isa"], m["kernel_profile"]) != (b["profile_id"], b["hw_rev"], b["isa"], b["kernel_profile"]):
        return "not this board"
    if spec["production"] and (b["synthetic"] or not b["attested"] or spec["evidence"] is None or not any(m["evidence_digest"])
                               or m["evidence_digest"].hex() != spec["evidence"]):
        return "production admission without an attested board and a non-zero E01 evidence digest that the manifest carries and the device was handed"
    if m["features"] & spec["required"] != spec["required"]:
        return "a required feature is missing"
    if m["security_version"] < spec["floor"]:
        return "below the anti-rollback floor"
    if spec["failed"] is not None and ref.sha256(raw).hex() == spec["failed"]:
        return "a candidate that already failed its trial"
    inst = spec["installed"]
    if inst is not None:
        if ref.sha256(raw).hex() == inst["sha"] or m["version"] == inst["version"]:
            return "the installed image or its version number again"
        if m["version"] < inst["version"] and not spec["allow_downgrade"]:
            return "a downgrade without consent"
        if m["calibration_schema"] != inst["calibration_schema"]:
            return "a different calibration schema"
        stored, backup = inst["settings_schema"], spec["settings_backup"]
        window = range(m["settings_read_min"], m["settings_schema"] + 1)
        if stored not in window and (backup is None or backup not in window):
            return "settings the image cannot read and no preserved copy it can"
    ssh = m["ssh"]
    if ssh is not None:
        fixed = (ssh["fix"] == ref.FIX_UPSTREAM and (ssh["major"], ssh["minor"], ssh["portable"]) >= ref.OPENSSH_FIXED) or ssh["fix"] == ref.FIX_REVIEWED
        if not fixed or ref.ZERO32 in (ssh["source_digest"], ssh["build_digest"]):
            return "SSH without the fix or without a bound daemon"
        if ssh["auth"] & ref.AUTH_PASSWORD:
            if spec["production"]:
                return "password authentication in production"
        elif ssh["auth"] & 6 != 6:
            return "SSH authentication neither password nor resolved public-key-only"
        if spec["production"] and ssh["qualification"] == ref.ZERO32:
            return "production SSH with no guest qualification receipt"
    if m["artifact_size"] + spec["reserve"] > spec["staging_bytes"]:
        return "does not fit the staging area"
    if summary["vendor_acceptance"] != "not_claimed":
        return "a plan that claims vendor acceptance"
    if summary["mode"] == "ab_slots":
        rc = spec["ab_receipt"]
        if rc is None or rc["slot_bytes"] < m["artifact_size"] + spec["reserve"] or (rc["synthetic"] and not b["synthetic"]):
            return "A/B planned without a receipt that covers it"
        if rc["digest"] == ref.ZERO32.hex():
            return "A/B planned on a receipt with no digest"
    return None


def trust_problem(keys: List[Dict[str, Any]]) -> Optional[str]:
    if len(keys) > ref.MAX_KEYS:
        return "more keys than a store may hold"
    seen = set()
    for k in keys:
        pub = bytes.fromhex(k["public"])
        if not ed.key_ok(pub):
            return "a key that is not canonical, on the curve, of prime order and not the identity"
        if pub in seen:
            return "a key twice"
        seen.add(pub)
    return None


def engine_problems(script: Dict[str, Any], got: List[Dict[str, Any]], mans: Dict[str, bytes]) -> List[str]:
    """What an engine run must satisfy whatever the vectors say: the floor, the installed image and the phases move only where they may."""
    problems: List[str] = []
    spec = script["ctx"]
    floor, installed = spec["floor"], spec["installed"]["version"] if spec["installed"] else None
    candidate_security: Optional[int] = None
    candidate_sha: Optional[bytes] = None
    candidate_size = 0
    before_next = 0
    failed = {bytes.fromhex(spec["failed"])} if spec["failed"] else set()
    unhealthy = 0
    phase = "idle"
    copy_damaged = False
    candidate_raw: Optional[bytes] = None
    for n, (op, g) in enumerate(zip(script["ops"], got)):
        kind, res, state = op["op"], g["result"], g["state"]
        where = f"{script['id']} op {n} {kind}"
        if kind == "restart_with" and "floor" in op["ctx"]:
            floor = max(floor, op["ctx"]["floor"])        # the owner raised the floor between the two runs: the one way it moves outside a confirm
        if state["floor"] < floor:
            problems.append(f"{where}: the floor went down {floor} -> {state['floor']}")
        committed = res == {"ok": "committed"}
        if state["floor"] != floor and not committed:
            problems.append(f"{where}: the floor moved {floor} -> {state['floor']} outside a confirm")
        if state["installed"] != installed and not committed:
            problems.append(f"{where}: the installed image changed {installed} -> {state['installed']} outside a confirm")
        if kind == "begin":
            m = ref.parse(mans[op["manifest"]])
            if "ok" in res:
                candidate_security, candidate_sha, candidate_size, unhealthy = m["security_version"], m["sha256"], m["artifact_size"], 0
                candidate_raw = mans[op["manifest"]]
            elif m["sha256"] in failed and res != {"refuse": "candidate_previously_failed"} and "ok" in res:
                problems.append(f"{where}: a candidate that already failed was admitted again")
            if "ok" in res and m["sha256"] in failed:
                problems.append(f"{where}: a candidate that already failed was admitted again")
        if committed:
            if state["floor"] != max(floor, candidate_security or 0):
                problems.append(f"{where}: after a confirm the floor is {state['floor']}, not the candidate's security version {candidate_security}")
        if kind == "boot":
            if not op["healthy"] and "ok" in res:
                unhealthy += 1
                if unhealthy >= 3 and res != {"ok": "rolled_back"}:
                    problems.append(f"{where}: {unhealthy} unhealthy boots and the trial goes on")
            if res == {"ok": "rolled_back"} and candidate_sha is not None:
                failed.add(candidate_sha)
        if kind == "finish" and res == {"refuse": "artifact_digest_mismatch"} and candidate_sha is not None:
            failed.add(candidate_sha)
        if kind == "finish" and phase == "staging" and before_next < candidate_size and res != {"refuse": "artifact_truncated"}:
            problems.append(f"{where}: {before_next} of {candidate_size} bytes staged and the finish was not refused as truncated")
        if kind == "finish" and res == {"refuse": "artifact_truncated"} and state["phase"] != "staging":
            problems.append(f"{where}: a truncated artifact closed the stage instead of leaving it open")
        if kind == "activate" and res == {"refuse": "artifact_digest_mismatch"} and candidate_sha is not None:
            failed.add(candidate_sha)
        if kind in ("tamper_manifest", "swap_manifest"):
            copy_damaged = True
        if kind == "restart" and copy_damaged and state["phase"] != "idle":
            problems.append(f"{where}: a damaged manifest copy was resumed")
        if kind == "restart" and not copy_damaged and state["phase"] != phase:
            problems.append(f"{where}: a plain restart changed the phase {phase} -> {state['phase']}")
        if kind == "restart_with" and state["phase"] != "idle" and candidate_raw is not None:
            # a restart is an admission under the policy of the day: whatever it resumed must pass every rule again, against the floor and the
            # installed image as they now are (the oracle below is written from the contract, not taken from the model)
            now = dict(spec, **op["ctx"])
            now["floor"] = state["floor"]
            now["failed"] = None
            why = admission_problem(now, candidate_raw, {"vendor_acceptance": "not_claimed", "mode": "single_slot_recovery"})
            if why is None and candidate_sha in failed:
                why = "a candidate that already failed its trial"
            if why is not None:
                problems.append(f"{where}: resumed a stage that the current policy does not admit: {why}")
        if kind == "restart_with" and state["phase"] != phase and state["phase"] != "idle":
            problems.append(f"{where}: a restart changed the phase {phase} -> {state['phase']}")
        phase, floor, installed, before_next = state["phase"], state["floor"], state["installed"], state["next"]
    return problems


def artifact_problem(m: Dict[str, Any], data: bytes, ok: bool) -> Optional[str]:
    if ok and (len(data) != m["artifact_size"] or hashlib.sha256(data).digest() != m["artifact_sha256"]):
        return "an artifact that verified but is not the declared size and digest"
    return None


def group_problem(v: Dict[str, Any], got: Dict[str, Any]) -> Optional[str]:
    if "upgrade_others" in got:
        return "an action on another member"
    if got["decision"] == "admit" and not 0 <= v["index"] < len(v["members"]):
        return "admitted although no member is at the index: nobody would take the candidate"
    if got["decision"] == "admit":
        cand = _image(v["candidate"])
        for j, m in enumerate(v["members"]):
            if j == v["index"]:
                continue
            if m["image"] is None:
                return "admitted past a member nobody has ever heard from"
            img = _image(m["image"])
            # written out here, not taken from the model: each side must read exactly what the other emits, upper bound included
            if not (img.wire_read_min <= cand.wire_schema <= img.wire_read_max and cand.wire_read_min <= img.wire_schema <= cand.wire_read_max):
                return f"admitted although member {m['id']} cannot read the candidate's wire or vice versa"
            if not m["connected"] and m["id"] not in got["assumed"]:
                return "a disconnected member counted without saying so"
    return None


def unsound(doc: Dict[str, Any], bugs: FrozenSet[str] = frozenset()) -> List[str]:
    """Vectors whose observed behaviour breaks a first-principles property, with no stored expectation consulted."""
    bad: List[str] = []
    for v in doc["trust"]:
        try:
            ref.TrustStore([(bytes.fromhex(k["public"]), k["revoked"]) for k in v["keys"]], bugs)
        except ref.Refusal:
            continue
        if trust_problem(v["keys"]):
            bad.append(v["id"])
    for v in doc["admit"]:
        try:
            summary = _summary(ref.admit(mv.build_ctx(v["ctx"], bugs), bytes.fromhex(v["manifest"]), bugs))
        except ref.Refusal:
            continue
        if admission_problem(v["ctx"], bytes.fromhex(v["manifest"]), summary):
            bad.append(v["id"])
    for v in doc["artifact"]:
        m = ref.parse(bytes.fromhex(v["manifest"]))
        data = bytes.fromhex(v["artifact"])
        try:
            ref.check_artifact(m, data, bugs)
        except ref.Refusal:
            continue
        if artifact_problem(m, data, True):
            bad.append(v["id"])
    arts = {k: bytes.fromhex(x) for k, x in doc["engine_assets"]["artifacts"].items()}
    mans = {k: bytes.fromhex(x) for k, x in doc["engine_assets"]["manifests"].items()}
    for script in doc["engine"]:
        if engine_problems(script, play(script, arts, mans, bugs), mans):
            bad.append(script["id"])
    for v in doc["group"]:
        members = [ref.Member(m["id"], _image(m["image"]), m["connected"]) for m in v["members"]]
        if group_problem(v, ref.group_decision(members, v["index"], _image(v["candidate"]), bugs)):
            bad.append(v["id"])
    return bad
