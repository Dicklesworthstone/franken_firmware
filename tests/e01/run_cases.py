#!/usr/bin/env python3
"""E01 end-to-end case runner (bead ffw-xdi).  Offline; stdlib only; no builds.

Runs the real CLI (`inventory/reconcile.py`) as a subprocess over fixtures declared in
`cases.json`, compares stdout with hand-written expected patterns, checks that inputs are
unchanged and that no private marker appears in any output, replays permutations, and writes a
JSONL receipt per case.  Entry point: `scripts/e2e/e01 [--tier smoke|full|soak|real]`.

Evidence classes (stated in every receipt):
  synthetic    fixtures built by this runner from documentation-range identifiers.
  owner-local  the owner's private `.local-real/devices.json`; only counts are reported.
Neither is physical-device or provider evidence.

A required case that cannot run is `blocked`, and any `blocked`, `failed` or missing required
case makes the run exit non-zero.  There are no retries.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CASES_FILE = HERE / "cases.json"
RECONCILE = ROOT / "inventory" / "reconcile.py"
EVIDENCE_SEED = ROOT / "inventory" / "image-evidence.json"
HYPOTHESES = ROOT / "inventory" / "hardware-profiles.json"
REAL_INPUT = ROOT / ".local-real" / "devices.json"
CALL_TIMEOUT_S = 30
SYNTHETIC_MARKERS = ("00-00-5e-00-53", "00:00:5e:00:53", "00005e0053", "192.0.2.", "rincon_", "test room",
                     "synthetichousehold", "e2e-cpu-note")
MISSING = object()

DEV_DEFAULTS = {"model": "S5", "name": "Sonos Play:5", "series": "P100", "variant": "0", "rev": "1.2.3.4-5.6",
                "sw": "57.23-74170", "gen": "1", "mem": "32", "flash": "32"}


# --------------------------------------------------------------------------- fixtures
def build_dev(spec: dict) -> dict:
    n = spec.get("n", 1)
    d = dict(DEV_DEFAULTS)
    d.update({k: v for k, v in spec.items() if k in DEV_DEFAULTS})
    ip = spec.get("ip", f"192.0.2.{n}")
    room = spec.get("room", f"Test Room {n}")
    serial, mac = f"00-00-5E-00-53-{n:02X}:1", f"00:00:5e:00:53:{n:02x}"
    udn = f"uuid:RINCON_00005E0053{n:02X}01400_MR"
    fields = {"serialNum": serial, "MACAddress": mac, "UDN": udn, "modelNumber": d["model"], "modelName": d["name"],
              "seriesid": d["series"], "variant": d["variant"], "hardwareVersion": d["rev"],
              "softwareVersion": d["sw"], "swGen": d["gen"], "memory": d["mem"], "flash": d["flash"],
              "roomName": room, "friendlyName": f"{ip} - {d['name']}"}
    status = {"SerialNumber": serial, "MACAddress": mac, "IPAddress": ip, "HardwareVersion": d["rev"],
              "SoftwareVersion": d["sw"], "SWGen": d["gen"], "Variant": d["variant"], "SeriesID": d["series"],
              "ZoneName": room, "HouseholdControlID": f"Sonos_SyntheticHousehold{n}"}
    for k in spec.get("drop", []):
        fields.pop(k, None)
        status.pop(k, None)
    fields.update(spec.get("over", {}))
    status.update(spec.get("status_over", {}))
    rec = {"url": f"http://{ip}:1400/xml/device_description.xml", "fields": fields, "status": status}
    if "ts" in spec:
        rec["observed_at"] = spec["ts"]
    return rec


def expand(obj):
    if isinstance(obj, dict):
        if set(obj) == {"$dev"}:
            return build_dev(obj["$dev"])
        return {k: expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand(v) for v in obj]
    return obj


# ------------------------------------------------------------------------- matcher
def match(pattern, actual, path="$"):
    """Return a list of mismatch descriptions (empty means the pattern matches)."""
    if isinstance(pattern, dict):
        if set(pattern) == {"$absent"}:
            return [] if actual is MISSING else [f"{path}: expected absent"]
        if set(pattern) == {"$regex"}:
            ok = isinstance(actual, str) and re.fullmatch(pattern["$regex"], actual)
            return [] if ok else [f"{path}: does not match regex {pattern['$regex']!r}"]
        if set(pattern) == {"$contains"}:
            if not isinstance(actual, list):
                return [f"{path}: expected a list"]
            out = []
            for i, sub in enumerate(pattern["$contains"]):
                if not any(not match(sub, a, path) for a in actual):
                    out.append(f"{path}: no element matches $contains[{i}]")
            return out
        if not isinstance(actual, dict):
            return [f"{path}: expected an object"]
        out = []
        for k, sub in pattern.items():
            out += match(sub, actual.get(k, MISSING), f"{path}.{k}")
        return out
    if isinstance(pattern, list):
        if not isinstance(actual, list) or len(actual) != len(pattern):
            return [f"{path}: expected a list of length {len(pattern)}"]
        out = []
        for i, (p, a) in enumerate(zip(pattern, actual)):
            out += match(p, a, f"{path}[{i}]")
        return out
    if actual is MISSING:
        return [f"{path}: missing"]
    return [] if (pattern == actual and type(pattern) is type(actual)) else [f"{path}: expected {pattern!r}, got {actual!r}"]


def matcher_self_test():
    """The matcher must reject what it should: a runner that cannot fail proves nothing."""
    good = [({"a": 1}, {"a": 1, "b": 2}), ({"a": [1, 2]}, {"a": [1, 2]}), ({"a": {"$contains": [{"c": 1}]}}, {"a": [{"c": 1, "d": 2}]}),
            ({"a": {"$regex": "x+"}}, {"a": "xxx"}), ({"a": {"$absent": True}}, {}), ({"a": None}, {"a": None})]
    bad = [({"a": 1}, {"a": 2}), ({"a": 1}, {}), ({"a": [1, 2]}, {"a": [1]}), ({"a": 1}, {"a": True}), ({"a": 1}, {"a": 1.0}),
           ({"a": {"$contains": [{"c": 2}]}}, {"a": [{"c": 1}]}), ({"a": {"$regex": "x+"}}, {"a": "y"}),
           ({"a": {"$absent": True}}, {"a": 1}), ({"a": None}, {"a": 0}), ({"a": {"b": 1}}, {"a": 5})]
    for p, a in good:
        assert not match(p, a), ("matcher rejected a match", p, a)
    for p, a in bad:
        assert match(p, a), ("matcher accepted a mismatch", p, a)


# -------------------------------------------------------------------------- running
def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_cli(args, cwd, timeout=CALL_TIMEOUT_S):
    env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
    t0 = time.monotonic_ns()
    try:
        r = subprocess.run([sys.executable, "-B", "-I", str(RECONCILE), *args], cwd=cwd, env=env,
                           capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr, time.monotonic_ns() - t0
    except subprocess.TimeoutExpired:
        return None, b"", b"timeout", time.monotonic_ns() - t0


def write_json(path: Path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def prepare(case, tmp: Path, perm_rng=None):
    """Write fixtures; return (input_args, input_paths)."""
    args, paths = [], []
    batches = expand(case.get("batches", []))
    order = list(range(len(batches)))
    if perm_rng:
        batches = [perm_rng.sample(b, len(b)) for b in batches]
        perm_rng.shuffle(order)
    for pos, i in enumerate(order):
        p = write_json(tmp / f"batch{i}.json", {"method": "e2e fixture", "devices": batches[i]})
        paths.append(p)
    args += [x for p in paths for x in ("--input", p)]
    for i, raw in enumerate(case.get("raw_inputs", [])):
        p = tmp / raw["name"]
        p.write_text(raw["text"], encoding="utf-8")
        paths.append(str(p))
        args += ["--input", str(p)]
    for i, reg in enumerate(case.get("evidence", [])):
        p = write_json(tmp / f"evidence{i}.json", reg)
        paths.append(p)
        args += ["--evidence", p]
    if "hypotheses" in case:
        p = write_json(tmp / "hypotheses.json", case["hypotheses"])
        paths.append(p)
        args += ["--hypotheses", p]
    return args, paths


def subst(argv, tmp: Path):
    (tmp / ".local-real").mkdir(exist_ok=True)
    table = {"{tmp}": str(tmp), "{out}": str(tmp / "public.json"), "{priv}": str(tmp / ".local-real" / "report.json")}
    out = []
    for a in argv:
        for k, v in table.items():
            a = a.replace(k, v)
        out.append(a)
    return out


def check_markers(blobs, markers):
    low = b"\n".join(blobs).lower()
    return [m for m in markers if m.encode() in low]


def run_step(case, step, tmp, perm_rng=None):
    """-> (result dict, stdout bytes)."""
    in_args, in_paths = prepare(case, tmp, perm_rng)
    before = {p: sha(Path(p).read_bytes()) for p in in_paths}
    argv = subst(step.get("argv", []), tmp)
    code, out, err, ns = run_cli([*in_args, *argv], tmp)
    mism = []
    exp = step.get("expect", {})
    if code is None:
        mism.append("timeout")
    elif code != exp.get("exit", 0):
        mism.append(f"exit: expected {exp.get('exit', 0)}, got {code}")
    if "stderr_regex" in exp and not re.search(exp["stderr_regex"], err.decode("utf-8", "replace")):
        mism.append(f"stderr does not match {exp['stderr_regex']!r}")
    pub = None
    if out.strip():
        try:
            pub = json.loads(out)
        except ValueError:
            if "public" in exp:
                mism.append("stdout is not JSON")
    if "public" in exp and pub is not None:
        mism += match(exp["public"], pub)
    elif "public" in exp and not out.strip():
        mism.append("stdout is empty but a public document was expected")
    if exp.get("stdout_empty") and out.strip():
        mism.append("stdout should be empty")
    for ctl in step.get("negative_controls", []):
        if pub is not None and not match(ctl["public"], pub):
            mism.append(f"negative control matched (output wrongly satisfies: {ctl['why']})")
    if "out_file" in exp:
        exists = (tmp / "public.json").exists()
        if exists != exp["out_file"]:
            mism.append(f"public.json exists={exists}, expected {exp['out_file']}")
    for name in exp.get("absent", []):
        if (tmp / name).exists():
            mism.append(f"{name} should not exist")
    if "priv_file" in exp:
        exists = (tmp / ".local-real" / "report.json").exists()
        if exists != exp["priv_file"]:
            mism.append(f"report.json exists={exists}, expected {exp['priv_file']}")
    after = {p: sha(Path(p).read_bytes()) for p in in_paths}
    if before != after:
        mism.append("an input file was modified")
    blobs = [out, err] + ([(tmp / "public.json").read_bytes()] if (tmp / "public.json").exists() else [])
    leaked = check_markers(blobs, SYNTHETIC_MARKERS)
    if leaked:
        mism.append(f"private marker(s) in output: {len(leaked)}")
    leftovers = [p.name for p in tmp.iterdir() if p.name.startswith(".e01-")]
    if leftovers:
        mism.append("temp file left behind")
    return {"exit_code": code, "stdout_sha256": sha(out), "duration_ns": ns, "mismatches": mism}, out


def run_case(case, soak_factor, receipts):
    start = time.monotonic_ns()
    steps = case.get("steps") or [{"argv": case.get("argv", []), "expect": case.get("expect", {}),
                                   "negative_controls": case.get("negative_controls", [])}]
    mism, step_hashes, out_hashes = [], [], []
    with tempfile.TemporaryDirectory(prefix="ffw-e01-") as t:
        tmp = Path(t)
        for i, step in enumerate(steps):
            res, _ = run_step(case, step, tmp)
            step_hashes.append(res["stdout_sha256"])
            mism += [f"step {i}: {m}" for m in res["mismatches"]]
            pub = tmp / "public.json"
            out_hashes.append(sha(pub.read_bytes()) if pub.exists() else None)
            ref = step.get("expect", {}).get("out_equals_step")
            if ref is not None and (out_hashes[i] is None or out_hashes[i] != out_hashes[ref]):
                mism.append(f"step {i}: output file differs from step {ref}")
    perms = int(case.get("permute", 0)) * soak_factor
    for k in range(perms):
        rng = random.Random(int(hashlib.sha256(f"{case['id']}:{k}".encode()).hexdigest()[:8], 16))
        with tempfile.TemporaryDirectory(prefix="ffw-e01-") as t:
            res, _ = run_step(case, steps[0], Path(t), rng)
        if res["stdout_sha256"] != step_hashes[0]:
            mism.append(f"permutation {k}: stdout differs from the baseline run")
            break
        mism += [f"permutation {k}: {m}" for m in res["mismatches"]]
    return {"status": "failed" if mism else "passed", "mismatches": mism[:8], "steps": len(steps),
            "permutations": perms, "stdout_sha256": step_hashes[-1] if step_hashes else None,
            "duration_ms": (time.monotonic_ns() - start) // 1_000_000,
            "monotonic_start_ns": start, "monotonic_end_ns": time.monotonic_ns(), "input_class": "synthetic"}


# ----------------------------------------------------------------- special case kinds
def _result(status, mism, start, input_class="synthetic", **extra):
    return {"status": status, "mismatches": mism[:8], "steps": extra.pop("steps", 1), "permutations": extra.pop("permutations", 0),
            "stdout_sha256": extra.pop("stdout_sha256", None), "duration_ms": (time.monotonic_ns() - start) // 1_000_000,
            "monotonic_start_ns": start, "monotonic_end_ns": time.monotonic_ns(), "input_class": input_class, **extra}


def run_interrupt(case):
    """Cancellation: SIGINT while the CLI is blocked reading a FIFO input.  Exit 130, no output, no temp file."""
    start, mism = time.monotonic_ns(), []
    with tempfile.TemporaryDirectory(prefix="ffw-e01-") as t:
        tmp = Path(t)
        fifo, out = tmp / "blocked-input.json", tmp / "public.json"
        os.mkfifo(fifo)  # no writer ever opens it, so open() in the child blocks until interrupted
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
        proc = subprocess.Popen([sys.executable, "-B", "-I", str(RECONCILE), "--input", str(fifo), "--out", str(out)],
                                cwd=tmp, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(float(case.get("settle_s", 2.0)))
        if proc.poll() is not None:
            mism.append("the process exited before it could be interrupted")
            proc.communicate()
        else:
            proc.send_signal(signal.SIGINT)
            try:
                so, se = proc.communicate(timeout=10)
                if proc.returncode != 130:
                    mism.append(f"exit: expected 130, got {proc.returncode}")
                if b"error[interrupted]" not in se:
                    mism.append("stderr lacks error[interrupted]")
                if so.strip():
                    mism.append("stdout should be empty")
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                mism.append("did not exit within 10 s of SIGINT")
        left = sorted(p.name for p in tmp.iterdir() if p.name not in ("blocked-input.json",))
        if left:
            mism.append(f"files left behind after cancellation: {len(left)}")
    return _result("failed" if mism else "passed", mism, start)


def run_cross_caller(case):
    """enrich.py and reconcile.py must issue the same profile ids, in any record order; ineligibility must agree."""
    start, mism = time.monotonic_ns(), []
    recs = expand(case["batches"])[0]
    expect = case["expect_ids"]

    def reconcile_ids(rs, unit, tmp):
        cap = write_json(tmp / "cap.json", {"method": "e2e fixture", "devices": rs})
        code, out, err, _ = run_cli(["--input", cap] + (["--nominal-unit", unit] if unit else []), tmp)
        if code not in (0, 3):  # 3 = incomplete, which is the point of some of these captures
            mism.append(f"reconcile exit {code}")
            return {}, {}
        doc = json.loads(out)
        return {e["profile_id"]: e["device_count"] for e in doc["profiles"] if e["profile_id"]}, doc

    def enrich_records(rs, unit, tmp):
        cap = write_json(tmp / "cap.json", {"method": "e2e fixture", "devices": rs})
        outp = tmp / "enriched.json"
        outp.unlink(missing_ok=True)
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
        r = subprocess.run([sys.executable, "-B", "-I", str(ROOT / "inventory" / "enrich.py"), "--devices", cap, "--out", str(outp)]
                           + (["--nominal-unit", unit] if unit else []), cwd=tmp, env=env, capture_output=True, timeout=CALL_TIMEOUT_S)
        if r.returncode not in (0, 3):
            mism.append(f"enrich exit {r.returncode}")
            return []
        return json.loads(outp.read_text())["devices"]

    with tempfile.TemporaryDirectory(prefix="ffw-e01-") as t:
        tmp = Path(t)
        for k in range(int(case.get("shuffles", 3)) + 1):
            rs = recs if k == 0 else random.Random(900 + k).sample(recs, len(recs))
            rec_ids, doc = reconcile_ids(rs, "MB", tmp)
            enr = enrich_records(rs, "MB", tmp)
            enr_ids = {}
            for r in enr:
                if r["board_profile_id"]:
                    enr_ids[r["board_profile_id"]] = enr_ids.get(r["board_profile_id"], 0) + 1
            if rec_ids != expect:
                mism.append(f"order {k}: reconcile ids {rec_ids} != expected {expect}")
            if enr_ids != expect:
                mism.append(f"order {k}: enrich ids {enr_ids} != expected {expect}")
        # Missing revision: no id and ineligible in both.
        if not any(e["profile_id"] is None and e["resolution"] == "unresolved" and not e["activation_eligible"] for e in doc.get("profiles", [])):
            mism.append("reconcile: the revision-less device is not an id-less, ineligible entry")
        if not any(r["board_profile_id"] is None and "hardware_revision_missing" in r["reason_codes"] for r in enr):
            mism.append("enrich: the revision-less device still received an id")
        # Unknown unit: incomplete in both tools.
        _, doc2 = reconcile_ids(recs, None, tmp)
        if any(e["activation_eligible"] for e in doc2.get("profiles", [])):
            mism.append("reconcile: eligible although the unit is unknown")
        if not all(r["status"] != "enriched" and "memory_unit_unknown" in r["reason_codes"] for r in enrich_records(recs, None, tmp)):
            mism.append("enrich: a record is complete although the unit is unknown")
    return _result("failed" if mism else "passed", mism, start, permutations=int(case.get("shuffles", 3)))


# ------------------------------------------------------------------ owner-local case
def norm_serial(v):
    return v.strip().upper()


def run_real(case):
    """Run on the owner's private capture.  Expected counts come from an independent read of the file."""
    start = time.monotonic_ns()
    base = {"input_class": "owner-local", "monotonic_start_ns": start}
    if not REAL_INPUT.exists():
        return {**base, "status": "blocked", "mismatches": ["owner-local input .local-real/devices.json is absent"],
                "steps": 0, "permutations": 0, "stdout_sha256": None, "duration_ms": 0, "monotonic_end_ns": time.monotonic_ns()}
    raw = json.loads(REAL_INPUT.read_text())
    recs = [r for r in raw["devices"] if isinstance(r, dict) and isinstance(r.get("fields"), dict)]
    serials = {norm_serial(r["fields"]["serialNum"]) for r in recs if r["fields"].get("serialNum")}
    macs = {re.sub(r"[^0-9a-f]", "", r["fields"]["MACAddress"].lower()) for r in recs if r["fields"].get("MACAddress")}
    clean_identity = len(serials) == len(macs) == len(recs)
    ident_keys = {"serialnum", "serialnumber", "macaddress", "udn", "deviceid", "ipaddress", "householdcontrolid", "localuid"}
    name_keys = {"roomname", "friendlyname", "zonename"}
    idv, namev = set(), set()
    for r in recs:
        for part in ("fields", "status"):
            for k, v in (r.get(part) or {}).items():
                if isinstance(v, str) and v.strip():
                    if k.lower() in ident_keys and len(v.strip()) >= 6:
                        idv.add(v.strip().lower())
                    if k.lower() in name_keys and len(v.strip()) >= 3:
                        namev.add(v.strip().lower())
        if isinstance(r.get("url"), str):
            idv.add(r["url"].strip().lower())
    mism = []
    with tempfile.TemporaryDirectory(prefix="ffw-e01-real-") as t:
        tmp = Path(t)
        (tmp / ".local-real").mkdir()
        before = sha(REAL_INPUT.read_bytes())
        args = ["--input", str(REAL_INPUT), "--evidence", str(EVIDENCE_SEED), "--hypotheses", str(HYPOTHESES),
                "--private-out", str(tmp / ".local-real" / "report.json")]
        code, out, err, _ = run_cli(args, tmp)
        if code not in (0, 3):  # 3 = incomplete (expected while no digest/attested join exists)
            mism.append(f"exit {code}")
        if sha(REAL_INPUT.read_bytes()) != before:
            mism.append("private input was modified")
        try:
            doc = json.loads(out)
        except ValueError:
            doc = None
            mism.append("stdout is not JSON")
        if doc:
            s = doc["summary"]
            if s["observations"] != len(recs):
                mism.append("observation count differs from the independent count")
            if clean_identity:
                if s["identity_components"] != len(serials) or s["devices_in_profiles"] != len(serials) or doc["conflicts"]:
                    mism.append("device count / conflicts differ from the independent distinct-serial count")
            low = out.decode().lower()
            hits_id = sum(1 for v in idv if v in low)
            pub_strings = set(re.findall(r'"([^"]*)"', low))
            model_strings = {str(x).lower() for e in doc["profiles"] for x in (*e["model"].values(), e["hardware_revision"]) if x}
            hits_name = sum(1 for v in namev if v in pub_strings and v not in model_strings)
            if hits_id:
                mism.append(f"{hits_id} private identifier value(s) appear in the public output")
            if hits_name:
                mism.append(f"{hits_name} private name(s) appear in the public output")
            if any(e["resolution"] == "resolved" for e in doc["profiles"]) and not doc["summary"]["profiles_resolved"]:
                mism.append("inconsistent resolution counts")
            report = {"observations": s["observations"], "identity_components": s["identity_components"],
                      "profiles": s["profiles"], "resolved": s["profiles_resolved"],
                      "unresolved": s["profiles_unresolved"], "conflicted": s["profiles_conflicted"],
                      "independent_distinct_serials": len(serials)}
        else:
            report = {}
        # Reordering the same private records must not change the output.
        shuffled = dict(raw)
        shuffled["devices"] = random.Random(7).sample(raw["devices"], len(raw["devices"]))
        sp = tmp / "shuffled.local.json"
        sp.write_text(json.dumps(shuffled))
        code2, out2, _, _ = run_cli([a if a != str(REAL_INPUT) else str(sp) for a in args[:-2]], tmp)
        if code2 not in (0, 3) or out2 != out:
            mism.append("shuffled record order changed the public output")
    return {**base, "status": "failed" if mism else "passed", "mismatches": mism[:8], "steps": 2, "permutations": 1,
            "stdout_sha256": sha(out), "duration_ms": (time.monotonic_ns() - start) // 1_000_000,
            "monotonic_end_ns": time.monotonic_ns(), "counts_only": report}


def _local_name(tag):
    return tag.split("}")[-1]


def run_real_xml(case):
    """Real `device-*.xml` captures: one XML rule, and XML + the scan.py capture merge without an identity conflict.

    The oracle is this runner's own read of the files (first <device>, direct leaf children), not
    reconcile's output.  Only counts are reported; no value is printed.
    """
    import xml.etree.ElementTree as ET
    start = time.monotonic_ns()
    xmls = sorted((ROOT / ".local-real").glob("device-*.xml"))
    base = {"input_class": "owner-local", "monotonic_start_ns": start}
    if not xmls or not REAL_INPUT.exists():
        return {**base, "status": "blocked", "mismatches": ["owner-local .local-real/device-*.xml and devices.json are required"],
                "steps": 0, "permutations": 0, "stdout_sha256": None, "duration_ms": 0, "monotonic_end_ns": time.monotonic_ns()}
    xml_serials, xml_private, nested_udn_files, rule_mismatch, premise_failures, foreign_leaf = set(), set(), 0, 0, 0, 0
    spec = importlib.util.spec_from_file_location("ffw_reconcile_under_e2e", RECONCILE)
    rc_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc_mod)  # no import-time work; used only for its public XML rule
    for f in xmls:
        root = ET.parse(f).getroot()
        devs = [e for e in root.iter() if _local_name(e.tag) == "device"]
        upnp = "{urn:schemas-upnp-org:device-1-0}"
        upnp_devs = [e for e in root.iter() if e.tag == upnp + "device"]
        if not upnp_devs:  # the premise of the namespace-strict rule: real speakers emit the UPnP namespace
            premise_failures += 1
            continue
        devs = upnp_devs + [e for e in devs if e not in upnp_devs]
        direct = {c.tag[len(upnp):]: (c.text or "").strip() for c in upnp_devs[0] if len(c) == 0 and c.tag.startswith(upnp)}
        foreign_leaf += sum(1 for c in upnp_devs[0] if len(c) == 0 and not c.tag.startswith(upnp))
        try:  # the public rule must equal this runner's independent read of the real bytes, field for field
            if rc_mod.parse_description_xml(f.read_bytes(), "real") != direct:
                rule_mismatch += 1
        except rc_mod.E01Error:
            rule_mismatch += 1
        xml_serials.add(direct["serialNum"].strip().upper())
        for e in root.iter():  # every leaf value of identifier class, nested devices included
            if len(e) == 0 and _local_name(e.tag) in ("serialNum", "MACAddress", "UDN", "friendlyName") and (e.text or "").strip():
                xml_private.add(e.text.strip().lower())
        nested_udn_files += len(devs) > 1
    raw = json.loads(REAL_INPUT.read_text())
    json_recs = [r for r in raw["devices"] if isinstance(r, dict) and isinstance(r.get("fields"), dict)]
    json_serials = {r["fields"]["serialNum"].strip().upper() for r in json_recs if r["fields"].get("serialNum")}
    json_private = set()
    for r in json_recs:
        for part in ("fields", "status"):
            for k, v in (r.get(part) or {}).items():
                if isinstance(v, str) and len(v.strip()) >= 6 and k.lower() in {"serialnum", "serialnumber", "macaddress", "udn", "deviceid", "ipaddress", "householdcontrolid", "localuid"}:
                    json_private.add(v.strip().lower())
    mism = []
    if premise_failures:
        mism.append(f"{premise_failures} of {len(xmls)} real file(s) have no UPnP-namespace <device>; the namespace-strict rule would refuse them")
    if rule_mismatch:
        mism.append(f"parse_description_xml differs from the independent read in {rule_mismatch} of {len(xmls)} real file(s)")
    common = ["--evidence", str(EVIDENCE_SEED), "--hypotheses", str(HYPOTHESES)]
    before = {str(f): sha(f.read_bytes()) for f in xmls}
    with tempfile.TemporaryDirectory(prefix="ffw-e01-realxml-") as t:
        tmp = Path(t)

        def run(inputs):
            args = [x for p in inputs for x in ("--input", str(p))] + common
            code, out, err, _ = run_cli(args, tmp)
            if code not in (0, 3):
                mism.append(f"exit {code}")
                return None, out
            doc = json.loads(out)
            low = out.decode().lower()
            leaked = sum(1 for v in (xml_private | json_private) if len(v) >= 6 and v in low)
            if leaked:
                mism.append(f"{leaked} private value(s) appear in the public output")
            return doc, out

        doc_x, out_x = run(xmls)
        if doc_x:
            s_x = doc_x["summary"]
            if s_x["observations"] != len(xmls) or s_x["identity_components"] != len(xml_serials):
                mism.append("XML-only counts differ from the independent read")
            if doc_x["conflicts"]:
                mism.append("XML-only run reports identity conflicts")
        both = [*xmls, REAL_INPUT]
        doc_b, out_b = run(both)
        if doc_b:
            s_b = doc_b["summary"]
            if s_b["observations"] != len(xmls) + len(json_recs) or s_b["identity_components"] != len(xml_serials | json_serials):
                mism.append("XML + capture counts differ from the independent union")
            if doc_b["conflicts"]:
                mism.append("XML + capture produce identity conflicts (root vs nested UDN must merge cleanly)")
        _, out_rev = run(both[::-1])
        if out_rev != out_b:
            mism.append("input order changed the public output")
        if {str(f): sha(f.read_bytes()) for f in xmls} != before:
            mism.append("a private XML file was modified")
    counts = {"xml_files": len(xmls), "xml_files_with_nested_devices": nested_udn_files, "rule_equals_independent_read": len(xmls) - rule_mismatch - premise_failures, "foreign_namespace_leaf_fields": foreign_leaf, "independent_distinct_serials": len(xml_serials),
              "union_with_capture": len(xml_serials | json_serials)}
    return {**base, "status": "failed" if mism else "passed", "mismatches": mism[:8], "steps": 3, "permutations": 1,
            "stdout_sha256": sha(out_b), "duration_ms": (time.monotonic_ns() - start) // 1_000_000,
            "monotonic_end_ns": time.monotonic_ns(), "counts_only": counts}


# ------------------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--tier", choices=("smoke", "full", "soak", "real"), required=True)
    ap.add_argument("--case", help="run one case id (replay)")
    ap.add_argument("--receipts", help="directory for receipts.jsonl (default: a new temp directory, kept)")
    args = ap.parse_args(argv)

    matcher_self_test()
    spec = json.loads(CASES_FILE.read_text())
    cases = spec["cases"]
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    tiers = {"smoke": ("smoke",), "full": ("smoke", "full"), "soak": ("smoke", "full"), "real": ("real",)}[args.tier]
    planned = [c for c in cases if c["tier"] in tiers and (not args.case or c["id"] == args.case)]
    required = [i for t in tiers for i in spec["required"].get(t, [])]
    missing = [i for i in required if i not in ids]
    run_dir = Path(args.receipts) if args.receipts else Path(tempfile.mkdtemp(prefix="ffw-e01-receipts-"))
    run_dir.mkdir(parents=True, exist_ok=True)
    rpath = run_dir / "receipts.jsonl"
    if rpath.exists() and rpath.stat().st_size:
        print(f"refusing to overwrite existing receipts: {rpath}", file=sys.stderr)
        return 2
    run_id = hashlib.sha256(f"{time.time_ns()}:{os.getpid()}".encode()).hexdigest()[:12]
    versions = {"python": sys.version.split()[0], "reconcile_sha256": sha(RECONCILE.read_bytes()),
                "cases_sha256": sha(CASES_FILE.read_bytes()), "seed_registry_sha256": sha(EVIDENCE_SEED.read_bytes())}
    counts = {"passed": 0, "failed": 0, "blocked": 0}
    lines = []
    soak_factor = 10 if args.tier == "soak" else 1
    for c in planned:
        kind = c.get("kind")
        if kind == "owner_local":
            res = run_real(c)
        elif kind == "owner_local_xml":
            res = run_real_xml(c)
        elif kind == "interrupt_fifo":
            res = run_interrupt(c)
        elif kind == "cross_caller":
            res = run_cross_caller(c)
        else:
            res = run_case(c, soak_factor, run_dir)
        counts[res["status"]] += 1
        rec = {"schema": "ffw.e01.receipt.v1", "run_id": run_id, "case_id": c["id"], "tier": c["tier"],
               "invariants": c["invariants"], "replay": f"scripts/e2e/e01 --tier {args.tier} --case {c['id']}",
               "versions": versions, "dropped_events": 0, **res}
        lines.append(json.dumps(rec, sort_keys=True))
        mark = {"passed": "PASS", "failed": "FAIL", "blocked": "BLOCKED"}[res["status"]]
        print(f"{mark:8} {c['id']}  {c.get('title', '')}  ({res['duration_ms']} ms, {res['input_class']})")
        for m in res["mismatches"][:3]:
            print(f"           first causal mismatch: {m}")
    not_run = len(missing)
    summary = {"schema": "ffw.e01.receipt.v1", "record": "summary", "run_id": run_id, "tier": args.tier,
               "planned": len(planned), **counts, "executed": counts["passed"] + counts["failed"],
               "missing_required": missing, "not_run": not_run, "versions": versions}
    lines.append(json.dumps(summary, sort_keys=True))
    rpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok = counts["failed"] == 0 and counts["blocked"] == 0 and not missing and summary["not_run"] == 0 and bool(planned)
    print(f"\ntier={args.tier} planned={len(planned)} passed={counts['passed']} failed={counts['failed']} "
          f"blocked={counts['blocked']} not_run={summary['not_run']}  receipts: {rpath}")
    print("RESULT:", "QUALIFIED (synthetic/owner-local evidence only; no device or provider claim)" if ok else "NOT QUALIFIED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
