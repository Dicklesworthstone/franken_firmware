#!/usr/bin/env python3
"""Mutation check for the E01 tests (bead ffw-xdi).  Offline; stdlib only; no builds.

Plants ONE deliberate defect at a time in a temporary copy of `inventory/reconcile.py` and runs the
tests against that copy.  A mutant that the tests do not detect is reported as SURVIVED and makes
this script exit non-zero.  Nothing in the repository is modified; copies live in temp directories.

    python3 -B -I tests/e01/mutation_check.py [--layer unit|e2e|real|all]

`real` mutants need the owner's private `.local-real/` (symlinked read-only into the temp tree); they
are reported SKIPPED, not passed, when it is absent.  A mutant whose edit no longer applies (the
source moved) is reported NOT-APPLIED and also fails the run, so this list cannot rot silently.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "inventory" / "reconcile.py").read_text()
COPY = ("inventory/test_reconcile.py", "inventory/image-evidence.json", "inventory/hardware-profiles.json",
        "inventory/identity.py", "inventory/enrich.py",  # reconcile.py loads these siblings; without them every mutant would "die" for the wrong reason
        "docs/contracts/e01.md", "tests/e01/run_cases.py", "tests/e01/cases.json")

ORDER_DEP = [('devices.sort(key=lambda d: d["tokens"])', 'pass'),
             ('entries = [_build_entry(k, groups[k], registry, hypotheses) for k in sorted(groups)]',
              'entries = [_build_entry(k, groups[k], registry, hypotheses) for k in groups]')]
LEAK_OFF = ('assert_public_clean(public, ids, names)', 'pass')

# (layer, name, [(old, new)...], what should catch it)
MUTANTS = [
    ("unit", "firmware tie not a conflict", [('if len(top) > 1:\n        return ("conflict",)', 'if False:\n        return ("conflict",)')], "FW-TIE"),
    ("unit", "undated firmware not a conflict", [('if any(ts is None for ts, _ in pairs):\n        return ("conflict",)', 'if False:\n        return ("conflict",)')], "FW-UNORDERED"),
    ("unit", "firmware: oldest wins", [('latest = max(ts for ts, _ in pairs)', 'latest = min(ts for ts, _ in pairs)')], "FW-ORDERED"),
    ("unit", "UDN suffix not stripped", [('(?:_[A-Z]{1,3})?$", re.I)', '$", re.I)')], "UDN-SUFFIX"),
    ("unit", "MAC case kept", [('h = re.sub(r"[^0-9A-Fa-f]", "", v).lower()', 'h = re.sub(r"[^0-9A-Fa-f]", "", v)')], "MAC-FORMATS"),
    ("unit", "no transitive identity", [('        ra, rb = self.find(a), self.find(b)\n        if ra != rb:', '        ra, rb = self.find(a), self.find(b)\n        if False:')], "ID-TRANSITIVE"),
    ("unit", "conflicted device kept in a profile", [('if d["conflicts"]:\n            sig =', 'if False:\n            sig =')], "ID-SERIAL-MAC-CONFLICT"),
    ("unit", "duplicates miscounted", [('            dups += 1', '            dups += 2')], "DEDUP-EXACT"),
    ("unit", "duplicate batch not ignored", [('        if bid in seen:', '        if False:')], "DEDUP-BATCH"),
    ("unit", "status/zp source ignored", [('    if skey:\n        v = o["status"].get(skey)', '    if False:\n        v = o["status"].get(skey)')], "XSOURCE-CONFLICT"),
    ("unit", "bare size assumed MB", [('        return ("bare", str(int(digits)) if digits else "0"), "unknown"', '        return ("ok", f"{int(digits)} MB"), "assumed"')], "MEM-BARE"),
    ("unit", "declared unit overrides stated unit", [('        unit = _stated_unit(raw, factors)', '        unit = declared_unit or _stated_unit(raw, factors)')], "MEM-SUFFIX"),
    ("unit", "private profile-id formula", [('        return idm.profile_id_for(model_number, hardware_revision)', '        return "bp-" + __import__("hashlib").sha256((model_number + hardware_revision).encode()).hexdigest()[:16]')], "ID-CROSSCHECK"),
    ("unit", "model not canonicalised", [('        return "ok", idm.make_claim(subject, field, raw, source, unit=unit).value', '        _v = idm.make_claim(subject, field, raw, source, unit=unit).value\n        return "ok", (raw if field == "product_model" else _v)')], "CANON-SPELLINGS"),
    ("unit", "shared scanner gate off", [('    if shared:', '    if False:')], "LEAK-SHARED"),
    ("unit", "shared module fallback instead of failing", [('            raise InputError("shared_module_missing", f"required sibling module {name}.py is missing")', '            return None')], "IDENTITY-REQUIRED"),
    ("unit", "rejected sw_gen emitted", [('        state[logical] = ("malformed",) if pick[1] == _BAD else ("ok", pick[1])', '        state[logical] = ("ok", pick[1])')], "SWGEN-MALFORMED"),
    ("unit", "name-inferred join accepted", [('ACCEPTED_JOIN_BASES = ("image-verified", "owner-attested")', 'ACCEPTED_JOIN_BASES = ("image-verified", "owner-attested", "name-inferred")')], "ISA-UNATTESTED"),
    ("unit", "firmware line ignored in matching", [('fw_ok = fw_line in r["firmware_lines"]', 'fw_ok = True')], "ISA-FWLINE-MISMATCH"),
    ("unit", "ISA conflict ignored", [('if len(isas) > 1 or len(abis) > 1 or len(fabis) > 1 or len(atoms) > 1 \\\n            or any(r["id"] in registry["contradicted"] for r in matched):', 'if False:')], "ISA-CONFLICT"),
    ("unit", "digest contradiction pre-pass off", [('if len({g["isa"] for g in group}) > 1:', 'if False:')], "ISA-DIGEST-CONTRADICTION"),
    ("unit", "missing digest silent", [('        reasons.add(("image_digest_absent", None))', '        pass')], "DIGEST-ABSENT"),
    ("unit", "forced S5 hypothesis", [('hyp = hypotheses.get(model) if model else None', 'hyp = (hypotheses.get(model) or hypotheses.get("S5")) if model else None')], "NO-FORCED-S5"),
    ("unit", "leak guard off", [LEAK_OFF], "LEAK-GUARD"),
    ("unit", "ipv4 not exempt for revision", [('if kind == "ipv4" and path.endswith("hardware_revision"):', 'if False:')], "LEAK-PATTERNS"),
    ("unit", "error text echoes content", [('not valid JSON (offset {e.pos})"', 'not valid JSON (offset {e.pos}) near {e.doc[:60]}"')], "ERRORS-NO-ECHO"),
    ("unit", "DOCTYPE allowed", [('if re.search(rb"<!\\s*(DOCTYPE|ENTITY)", data, re.I):', 'if False:')], "XML-HAZARDS"),
    ("unit", "output may be an input", [('if p in protected:', 'if False:')], "OUT-NOT-INPUT"),
    ("unit", "clobber check removed", [('if p.exists() and not args.overwrite:', 'if False:')], "OUT-NOCLOBBER"),
    ("unit", "private-out location unchecked", [('if priv is not None and not _is_private_location(priv):', 'if False:')], "PRIVATE-LOCATION"),
    ("unit", "temp file leaked on failure", [('        try:\n            os.unlink(tmp)\n        except FileNotFoundError:\n            pass\n        raise', '        raise')], "WRITE-FAILURE"),
    ("unit", "incomplete exits 0", [('    return EXIT_INCOMPLETE if (not clean and not args.allow_incomplete) else EXIT_OK', '    return EXIT_OK')], "INCOMPLETE-EXIT"),
    ("unit", "ordinals follow arrival order", [('devices.sort(key=lambda d: d["tokens"])', 'pass')], "ORDINALS"),
    ("e2e", "ISA guessed from model", [('    model, revision, fw_line = _val(s["model_number"]), _val(s["hardware_revision"]), _val(s["firmware_line"])\n    reasons = set(_key_reasons(key))',
        '    model, revision, fw_line = _val(s["model_number"]), _val(s["hardware_revision"]), _val(s["firmware_line"])\n    reasons = set(_key_reasons(key))\n    _guess = model == "S5"'),
        ('    severities = {REASONS[c][0] for c, _ in reasons}', '    if _guess and evidence["isa"] is None:\n        evidence["isa"] = {"machine": "powerpc", "elf_class": 32, "endianness": "big"}\n    severities = {REASONS[c][0] for c, _ in reasons}')], "E01-E2E-002"),
    ("e2e", "contradictory evidence resolved", [('if len(isas) > 1 or len(abis) > 1 or len(fabis) > 1 or len(atoms) > 1 \\\n            or any(r["id"] in registry["contradicted"] for r in matched):', 'if False:')], "E01-E2E-003"),
    ("e2e", "identifier collision merged", [('ambiguous = sorted(k for k, v in ids.items() if len(v) > 1)', 'ambiguous = []')], "E01-E2E-004"),
    ("e2e", "duplicates uncounted", [('            dups += 1', '            dups += 0')], "E01-E2E-005"),
    ("e2e", "output depends on input order", ORDER_DEP, "E01-E2E-006"),
    ("e2e", "profile_id depends on device count", [('"profile_id": profile_id_for(model, revision),', '"profile_id": profile_id_for(model, revision + str(len(devices))) if revision else None,')], "E01-E2E-006"),
    ("e2e", "leak guard off", [LEAK_OFF], "E01-E2E-007"),
    ("e2e", "identifier-by-value guard off", [('    ids = sorted(x.lower() for x in private_ids if len(x) >= 6)', '    ids = []')], "E01-E2E-012"),
    ("e2e", "DOCTYPE allowed", [('if re.search(rb"<!\\s*(DOCTYPE|ENTITY)", data, re.I):', 'if False:')], "E01-E2E-008"),
    ("e2e", "private-out location unchecked", [('if priv is not None and not _is_private_location(priv):', 'if False:')], "E01-E2E-009"),
    ("e2e", "rerun clobbers", [('if p.exists() and not args.overwrite:', 'if False:'), ('        if overwrite:\n            os.replace(tmp, path)', '        if True:\n            os.replace(tmp, path)')], "E01-E2E-010"),
    ("e2e", "profile_id from a different revision", [('        return idm.profile_id_for(model_number, hardware_revision)', '        return idm.profile_id_for(model_number, hardware_revision.replace("-5.", "-6."))')], "E01-E2E-014"),
    ("e2e", "interrupt exits 0", [('        return EXIT_INTERRUPT', '        return EXIT_OK')], "E01-E2E-013"),
    ("real", "serial leaks into public output", [LEAK_OFF, ('"sanitization": {"policy": "allowlist-v1",', '"sanitization": {"leak": observations[0]["fields"].get("serialNum"), "policy": "allowlist-v1",')], "E01-E2E-011"),
    ("real", "a device is dropped", [('        if not tokens[i]:\n            unidentifiable.append(o)', '        if not tokens[i] or i == 0:\n            unidentifiable.append(o)')], "E01-E2E-011"),
    ("real", "output depends on input order", ORDER_DEP, "E01-E2E-011"),
]


def run_unit(t: Path):
    r = subprocess.run([sys.executable, "-B", "-I", "-m", "unittest", "discover", "-s", "inventory", "-p", "test_reconcile.py"],
                       cwd=t, capture_output=True, text=True, timeout=600)
    # Report each failing test by the stable case ID that starts its docstring (E01-...).
    failed, pending = [], False
    for line in r.stderr.splitlines():
        if line.startswith(("FAIL:", "ERROR:")):
            pending, name = True, line.split()[1]
        elif pending and line.strip():
            failed.append(line.strip().split(":")[0] if line.strip().startswith("E01-") else name)
            pending = False
    return r.returncode != 0, failed


def run_e2e(t: Path, tier: str):
    r = subprocess.run([sys.executable, "-B", "-I", str(t / "tests/e01/run_cases.py"), "--tier", tier, "--receipts", str(t / "receipts")],
                       cwd=t, capture_output=True, text=True, timeout=600)
    failed = [l.split()[1] for l in r.stdout.splitlines() if l.startswith(("FAIL", "BLOCKED"))]
    return r.returncode != 0, failed


def stage(td: Path, source: str, lay: str):
    for rel in COPY:
        (td / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, td / rel)
    (td / "inventory" / "reconcile.py").write_text(source)
    if lay == "real":
        (td / ".local-real").symlink_to(ROOT / ".local-real")


def controls(layer: str):
    """The UNMUTATED source must pass every layer, or a "kill" below would prove nothing."""
    ok = True
    for lay in ("unit", "e2e", "real"):
        if layer not in ("all", lay):
            continue
        if lay == "real" and not (ROOT / ".local-real" / "devices.json").exists():
            continue
        with tempfile.TemporaryDirectory(prefix="ffw-e01-mut-") as td:
            t = Path(td)
            stage(t, SRC, lay)
            detected, failed = run_unit(t) if lay == "unit" else run_e2e(t, "real" if lay == "real" else "full")
        print(f"control     [{lay}] unmutated source {'FAILED: ' + ', '.join(failed[:3]) if detected else 'passes'}")
        ok = ok and not detected
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--layer", choices=("unit", "e2e", "real", "all"), default="all")
    layer = ap.parse_args(argv).layer
    killed = survived = skipped = unapplied = 0
    if not controls(layer):
        print("\nINVALID RUN: the unmutated control fails, so no kill below would mean anything.")
        return 2
    for lay, name, edits, want in MUTANTS:
        if layer not in ("all", lay):
            continue
        if lay == "real" and not (ROOT / ".local-real" / "devices.json").exists():
            print(f"SKIPPED     [{lay}] {name}  (owner-local .local-real/devices.json absent)")
            skipped += 1
            continue
        s, ok = SRC, True
        for old, new in edits:
            if s.count(old) != 1:
                ok = False
                break
            s = s.replace(old, new)
        if not ok:
            print(f"NOT-APPLIED [{lay}] {name}  (source changed; update this list)")
            unapplied += 1
            continue
        with tempfile.TemporaryDirectory(prefix="ffw-e01-mut-") as td:
            t = Path(td)
            stage(t, s, lay)
            detected, failed = run_unit(t) if lay == "unit" else run_e2e(t, "real" if lay == "real" else "full")
        hit = any(f.startswith(want if want.startswith("E01-") else "E01-" + want) for f in failed)
        if detected:
            killed += 1
            print(f"killed      [{lay}] {name:44} by {', '.join(failed[:2])}{'' if hit else '   (not by the expected case ' + want + ')'}")
        else:
            survived += 1
            print(f"SURVIVED    [{lay}] {name}")
    print(f"\nkilled={killed} survived={survived} not_applied={unapplied} skipped={skipped}")
    return 0 if (survived == 0 and unapplied == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
