"""Shared helpers for the E05 test modules (stdlib only, offline)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPTS = os.path.join(ROOT, "scripts", "e05")
MODEL = os.path.join(SCRIPTS, "boot_model.py")
PROFILES = os.path.join(HERE, "profiles")
CASES = os.path.join(HERE, "cases.json")

if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import boot_model as bm          # noqa: E402
import trace_check as tc         # noqa: E402

PROFILE_NAMES = ("synthetic-benign", "57.23", "86.10")


def profile(name: str) -> Dict[str, Any]:
    return bm.load_profile(os.path.join(PROFILES, name + ".json"))


def cases() -> Dict[str, Any]:
    with open(CASES, "r", encoding="utf-8") as fh:
        return json.load(fh)


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def violations(result: Dict[str, Any], prof: Dict[str, Any]) -> List[str]:
    return sorted({v["kind"] for v in tc.check_trace(result, prof)})


def run_cli(args: List[str], cwd: str = None) -> Tuple[int, str, str]:
    """Run the model CLI in a clean interpreter from a non-repo working directory."""
    work = cwd or tempfile.mkdtemp(prefix="e05-cli-")
    proc = subprocess.run([sys.executable, "-B", "-I", MODEL] + args, cwd=work, capture_output=True,
                          text=True, timeout=60)
    return proc.returncode, proc.stdout, proc.stderr
