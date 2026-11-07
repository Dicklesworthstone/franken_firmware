#!/usr/bin/env python3
"""Checks for the focused cancellation-audit harness. Standard library only; never builds, never writes outside `--out`.

  derive --repo GIT_REPO --out provenance/expected.json
      Recompute every expected fact from the pinned revision's own bytes (read-only `git show` / `git archive`).
  static
      Before any compile: the harness holds the original audit bytes, requests exactly the asupersync feature set the original
      lane ends up with, uses the pinned git revision, and registers only the targets that make the audit run unchanged.
  lock --lock Cargo.lock --asup-lock ASUP_Cargo.lock [--report-only]
      Versions the harness resolved against the versions the original lane's committed lock pins.
  run LOG --exit-status N [--repo FRANKEN_FIRMWARE]
      Judge a captured `cargo test` log: every original test and every guard test reported ok by its own binary (D01's parser pairs
      the stderr headers with the stdout sections whatever order RCH delivers them), no terminal Cargo/RCH failure, and the command's
      exit status, which the caller supplies, is 0.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
EXPECTED = HERE / "provenance" / "expected.json"
AUDIT = "tests/runtime_abort_vs_cancel_semantics_audit.rs"
HELPER = "tests/runtime_abort_vs_cancel_semantics_audit/stream_cancellation.rs"
PRIOR_AUDITS = [
    "tests/runtime_cancel_signal_coalescing_audit.rs",
    "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
    "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
]
GIT_URL = "https://github.com/Dicklesworthstone/asupersync"
# The original lane, copied from the RCH log of the audit that hit the external deadline (no --features, no --all-features).
ORIGINAL_COMMAND = (
    "cargo +nightly-2026-08-31 test -p asupersync --locked --test runtime_abort_vs_cancel_semantics_audit -j1 -- --nocapture"
)
ORIGINAL_ENV = {"CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "RUSTFLAGS": "-D warnings -C debuginfo=0"}
TEST_ATTR = re.compile(r"^\s*#\[test\]\s*\n\s*(?:async\s+)?fn\s+([A-Za-z0-9_]+)", re.MULTILINE)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: str, *args: str) -> bytes:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True).stdout


def test_names(text: str):
    return TEST_ATTR.findall(text)


def asupersync_dep_features(manifest: dict):
    """(features, default_features) of every `asupersync` dependency a manifest declares in its normal or build tables."""
    out = []
    for table in ("dependencies", "build-dependencies"):
        for name, spec in manifest.get(table, {}).items():
            if isinstance(spec, dict) and (name == "asupersync" or spec.get("package") == "asupersync"):
                out.append((list(spec.get("features", [])), spec.get("default-features", True)))
    return out


def feature_union(root: dict, dev_path_manifests: list):
    """The features of asupersync that the original `cargo test -p asupersync` links: the package's own defaults, plus what each
    dev-dependency that depends on asupersync asks for (Cargo unifies them), closed over the package's `[features]` table."""
    table = root["features"]
    requested = set(table.get("default", []))
    sources = {"default": sorted(requested)}
    for name, manifest in dev_path_manifests:
        for features, default_features in asupersync_dep_features(manifest):
            requested |= set(features)
            if default_features:
                requested |= set(table.get("default", []))
            sources[name] = sorted(features)
    seen, stack = set(), list(requested)
    while stack:
        feature = stack.pop()
        if feature in seen:
            continue
        if feature not in table:
            raise SystemExit(f"feature {feature!r} is requested but is not in the pinned [features] table")
        seen.add(feature)
        stack.extend(item for item in table[feature] if not item.startswith("dep:") and "/" not in item)
    return sorted(seen), sources


def dev_path_dependencies(root: dict):
    specs = list(root.get("dev-dependencies", {}).values())
    for target in root.get("target", {}).values():
        specs.extend(target.get("dev-dependencies", {}).values())
    return sorted({spec["path"] for spec in specs if isinstance(spec, dict) and "path" in spec})


def derive(repo: str, rev: str, out: Path):
    git(repo, "cat-file", "-e", f"{rev}^{{commit}}")
    show = lambda path: git(repo, "show", f"{rev}:{path}")
    root = tomllib.loads(show("Cargo.toml").decode())
    dev_manifests = [(p, tomllib.loads(show(f"{p}/Cargo.toml").decode())) for p in dev_path_dependencies(root)]
    features, sources = feature_union(root, [(p, m) for p, m in dev_manifests if asupersync_dep_features(m)])
    audit, helper = show(AUDIT), show(HELPER)
    audit_text, helper_text = audit.decode(), helper.decode()
    for prior in PRIOR_AUDITS:
        git(repo, "cat-file", "-e", f"{rev}:{prior}")
        assert prior in audit_text, f"{prior} is not named by the audit"
    toolchain = tomllib.loads(show("rust-toolchain.toml").decode())["toolchain"]["channel"]
    expected = {
        "schema": 1,
        "asupersync": {"git": GIT_URL, "rev": rev, "version": root["package"]["version"]},
        "toolchain_channel": toolchain,
        "toolchain_file_sha256": sha(show("rust-toolchain.toml")),
        "original_command": ORIGINAL_COMMAND,
        "original_env": ORIGINAL_ENV,
        "features": features,
        "feature_sources": sources,
        "pinned_files": {path: sha(show(path)) for path in ("Cargo.toml", "conformance/Cargo.toml", "Cargo.lock")},
        "harness_files": {AUDIT: sha(audit), HELPER: sha(helper)},
        "tests": {"audit": len(test_names(audit_text)), "stream_cancellation": len(test_names(helper_text))},
    }
    expected["tests"]["total"] = expected["tests"]["audit"] + expected["tests"]["stream_cancellation"]
    out.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out}: {len(features)} features {features}; tests {expected['tests']}")


def static():
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    problems = []
    for rel, want in expected["harness_files"].items():
        path = HERE / rel
        if not path.is_file():
            problems.append(f"missing original source {rel}")
        elif sha(path.read_bytes()) != want:
            problems.append(f"{rel} is not the original audit source (sha256 {sha(path.read_bytes())[:16]}, want {want[:16]})")
    manifest = tomllib.loads((HERE / "Cargo.toml").read_text(encoding="utf-8"))
    dep = manifest.get("dependencies", {}).get("asupersync", {})
    pin = expected["asupersync"]
    if dep.get("git") != pin["git"] or dep.get("rev") != pin["rev"]:
        problems.append(f"asupersync is not the git dependency at the pinned rev: {dep}")
    if any(key in dep for key in ("path", "branch", "tag", "version", "registry")):
        problems.append("asupersync must be the git+rev dependency only")
    if dep.get("default-features") is not False:
        problems.append("default-features must be false so the feature list below is the whole feature set")
    if sorted(dep.get("features", [])) != expected["features"]:
        got, want = set(dep.get("features", [])), set(expected["features"])
        problems.append(f"feature mismatch: missing {sorted(want - got)} extra {sorted(got - want)}")
    if manifest.get("package", {}).get("autotests") is not False:
        problems.append("autotests must be false: the original audit file must not be compiled as its own target")
    targets = {t["name"]: t["path"] for t in manifest.get("test", [])}
    if targets != {"cancel_audit": "tests/cancel_audit.rs", "provenance_guard": "tests/provenance_guard.rs"}:
        problems.append(f"unexpected test targets {targets}")
    for forbidden in ("patch", "replace"):
        if forbidden in manifest:
            problems.append(f"[{forbidden}] would change what is compiled")
    if "workspace" not in manifest:
        problems.append("a standalone [workspace] table is required so no parent workspace adopts the harness")
    if (HERE / "rust-toolchain.toml").is_file():
        if sha((HERE / "rust-toolchain.toml").read_bytes()) != expected["toolchain_file_sha256"]:
            problems.append("rust-toolchain.toml differs from the pinned asupersync toolchain file")
    else:
        problems.append("rust-toolchain.toml is missing")
    wrapper = (HERE / "tests" / "cancel_audit.rs").read_text(encoding="utf-8")
    if len(re.findall(r"^macro_rules!\s+env\s*\{", wrapper, flags=re.MULTILINE)) != 1 or "ASUP_ROOT" not in wrapper:
        problems.append("tests/cancel_audit.rs must define exactly the one `env!` interposition")
    return report("static", problems)


def lock_packages(text: str):
    out = {}
    for package in tomllib.loads(text).get("package", []):
        out.setdefault(package["name"], set()).add(package["version"])
    return out


def lock(harness_lock: Path, asup_lock: Path, report_only: bool):
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    asup_bytes = asup_lock.read_bytes()
    if sha(asup_bytes) != expected["pinned_files"]["Cargo.lock"]:
        return report("lock", ["--asup-lock is not the pinned Cargo.lock"])
    ours, theirs = lock_packages(harness_lock.read_text(encoding="utf-8")), lock_packages(asup_bytes.decode())
    problems, fixes = [], []
    for name in sorted(ours):
        if name in ("asupersync", "asupersync-cancel-audit") or name not in theirs:
            continue
        extra = ours[name] - theirs[name]
        if extra:
            problems.append(f"{name}: harness {sorted(ours[name])} vs pinned lock {sorted(theirs[name])}")
            if len(ours[name]) == 1 and len(theirs[name]) == 1:
                fixes.append(f"cargo update -p {name}@{next(iter(ours[name]))} --precise {next(iter(theirs[name]))}")
    for fix in fixes:
        print("  fix:", fix)
    return report("lock", problems, soft=report_only)


ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Cargo's own terminal failures, each anchored at the start of a line. Not a search for the word "error": the audit prints
# diagnostics and panic messages whose text says "error" in the middle of a line, and that is not a failed run.
TERMINAL_FAILURES = [
    (re.compile(r"^error: test failed, to rerun pass", re.MULTILINE), "cargo: a test binary failed"),
    (re.compile(r"^error: doctest failed, to rerun pass", re.MULTILINE), "cargo: the doctests failed"),
    (re.compile(r"^error: could not compile ", re.MULTILINE), "cargo: a target did not compile"),
    (re.compile(r"^error\[E\d{4}\]: ", re.MULTILINE), "rustc: a compile error"),
    (re.compile(r"^error: aborting due to ", re.MULTILINE), "rustc: aborting due to errors"),
    (re.compile(r"^error: process didn't exit successfully", re.MULTILINE), "cargo: a process did not exit successfully"),
    (re.compile(r"^test result: FAILED", re.MULTILINE), "libtest: a binary reported FAILED"),
    (re.compile(r"^test \S+ \.\.\. FAILED", re.MULTILINE), "libtest: a test FAILED"),
    (re.compile(r"^RCH_EXTERNAL_DEADLINE", re.MULTILINE), "rch: the external deadline fired"),
    (re.compile(r"completion is unconfirmed"), "rch: completion unconfirmed"),
]
HARNESS_STEMS = ("cancel_audit", "provenance_guard")


def load_d01_parser(repo: Path):
    """D01's runner, for its cargo-log parser (header/section ordinal pairing for RCH logs), as N04 and N03 reuse it."""
    import importlib.util

    path = repo / "tests" / "d01" / "run_cases.py"
    if not path.is_file():
        raise SystemExit(f"run: D01's runner ({path}) is required for its cargo-log parser; pass --repo")
    spec = importlib.util.spec_from_file_location("d01_run_cases_for_cancel_audit", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run(log: Path, exit_status: int, repo: Path):
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    text = ANSI.sub("", log.read_text(encoding="utf-8", errors="replace"))
    problems = []
    # 1. The command itself: its status comes from outside the log, and the log must not contradict it or end in a failure.
    if exit_status != 0:
        problems.append(f"the command exited {exit_status}")
    finished = re.findall(r"Remote command finished: exit=(\d+)", text)
    if re.search(r"\brch::", text) and not finished:
        problems.append("an RCH log with no `Remote command finished` line: the remote run's custody is incomplete")
    problems += [f"rch: the remote command finished with exit={code}" for code in finished if code != "0"]
    for pattern, why in TERMINAL_FAILURES:
        hit = pattern.search(text)
        if hit:
            line = text[hit.start():].split("\n", 1)[0]
            problems.append(f"{why}: {line[:120]}")
    # 2. Every original test, and the guard's own, reported ok by the binary that owns it. D01's parser pairs the n-th Running
    #    header (stderr) with the n-th `running N tests` section (stdout) however RCH interleaves the two streams.
    audit_names = [f"audit::{n}" for n in test_names((HERE / AUDIT).read_text(encoding="utf-8"))]
    audit_names += [f"audit::stream_cancellation::{n}" for n in test_names((HERE / HELPER).read_text(encoding="utf-8"))]
    guard_names = test_names((HERE / "tests" / "provenance_guard.rs").read_text(encoding="utf-8"))
    if len(audit_names) != expected["tests"]["total"]:
        problems.append(f"the harness sources define {len(audit_names)} tests, expected {expected['tests']['total']}")
    logs = load_d01_parser(repo).Logs()
    logs.add(str(log))
    if logs.unattributed_logs:
        problems.append(f"tests cannot be attributed to their binaries: {logs.unattributed_logs}")
    problems += list(logs.attribution_notes)
    wanted = [("cancel_audit", n) for n in audit_names] + [("provenance_guard", n) for n in guard_names]
    not_ok = [(stem, name, logs.test_status(stem, name)) for stem, name in wanted if logs.test_status(stem, name) != "ok"]
    if not_ok:
        problems.append(f"{len(not_ok)} of {len(wanted)} expected tests are not `ok`, e.g. {not_ok[:3]}")
    unexpected = sorted(key for key in logs.tests if key[0] in HARNESS_STEMS and key not in set(wanted))
    if unexpected:
        problems.append(f"tests that are not in the harness sources ran: {unexpected[:3]}")
    return report("run", problems)


def report(label: str, problems: list, soft: bool = False):
    if problems:
        print(f"{label}: {len(problems)} problem(s)")
        for problem in problems:
            print("  -", problem)
        return 0 if soft else 1
    print(f"{label}: ok")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--repo", required=True)
    d.add_argument("--rev", default="14032b8f2c832ee7ef1946404f5efb18162af045")
    d.add_argument("--out", type=Path, default=EXPECTED)
    sub.add_parser("static")
    l = sub.add_parser("lock")
    l.add_argument("--lock", type=Path, default=HERE / "Cargo.lock")
    l.add_argument("--asup-lock", type=Path, required=True)
    l.add_argument("--report-only", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("log", type=Path)
    r.add_argument("--exit-status", type=int, required=True, help="the exit status of the cargo command, from outside the log")
    r.add_argument("--repo", type=Path, default=HERE.parent.parent, help="the franken_firmware checkout that holds tests/d01/run_cases.py")
    args = parser.parse_args()
    if args.cmd == "derive":
        derive(args.repo, args.rev, args.out)
        return 0
    if args.cmd == "static":
        return static()
    if args.cmd == "lock":
        return lock(args.lock, args.asup_lock, args.report_only)
    return run(args.log, args.exit_status, args.repo)


if __name__ == "__main__":
    sys.exit(main())
