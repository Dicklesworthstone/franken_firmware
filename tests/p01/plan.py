"""The P01 build-identity pipeline: a command plan, artifact identity extraction, and receipts.

Nothing in this module runs cargo by itself. `plan_steps` builds the exact command lines a central run
executes (`RCH_REQUIRE_REMOTE=1 rch exec -- cargo ...`, `--locked --offline`, an absolute `--manifest-path`,
a working directory that is not the repository root, except a device step that names a linker wrapper, which runs from the
root so the wrapper is synced). `check_plan` holds a plan to those rules. `execute` runs a
plan through an injected executor and writes a versioned receipt that carries the contract digest and, per
artifact, the exact target, triple, profile, SHA-256 and ELF identity read from the built bytes. `check_receipt`
re-verifies a receipt against the contract with the independent reference.

What a receipt proves, so it is not over-read: it records what was built and what the files contain. It is not
an attestation of the remote compiler; the toolchain block is whatever plain `rustc -vV` printed on the build host.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import reference as ref

RCH = "rch"
BYPASS_ENV = ("RCH_CARGO_WRAPPER_BYPASS", "RCH_ENABLED")
RECEIPT_SCHEMA = "ffw.p01.receipt.v1"
HELLO_REL = "toolchain/src/ffw-hello-init"
WORKSPACE_BUILD_STD = "build-std=core,alloc,std,panic_abort"
HELLO_BUILD_STD = "build-std=core,panic_abort"
# RCH admits a build against a worker's slot count and ignores CARGO_BUILD_JOBS, so the plan itself names the job count. The default is ONE:
# a worker with a single slot cannot admit `-j 2`, and one job changes how long a build takes, not what it builds (every step, target, feature
# and flag is the same). `plan_steps(jobs=N)` still takes any positive N, and a cargo step without a positive `-j N` is still refused.
DEFAULT_JOBS = 1
# A host-target build runs on a Linux worker; rch refuses to fetch that executable to a different-OS operator unless
# told to. It is fetched to be identified (hashed, header read), never run, so only host-target builds may carry it.
FOREIGN_ARTIFACTS_ENV = "RCH_ALLOW_FOREIGN_ARTIFACTS"
# The compilers the plan asks for, each named in ONE place. A bare `cargo` (the workspace test, the host build) resolves the
# repository's own pin, `PIN_FILE`; the device builds ask for one DATED nightly, because a floating `+nightly` is whatever each worker
# happened to have that day. `rustc +X -vV` through rch drops `+X` and prints the default compiler, so no plan step asks it.
PIN_FILE = "rust-toolchain.toml"
DEVICE_TOOLCHAIN = "nightly-2026-08-31"
# What a device artifact built by DEVICE_TOOLCHAIN carries in its bytes (`rustc version ` is stripped). A dated nightly is immutable, so this
# is a fact of the date, MEASURED with `rustc +nightly-2026-08-31 -V` on a host that has it (2026-11-05), and its commit prefix agrees with
# the commit `90850177249e` the supervisor saw on a worker (mail 5443). It has NOT yet been seen in a central receipt: the first receipt
# either shows exactly this or BLK-004 fails with both strings. Change it only together with DEVICE_TOOLCHAIN (toolchain.judge_plan
# refuses a string whose commit date is not within three days before the toolchain date).
DEVICE_RUSTC_VERSION = "1.100.0-nightly (908501772 2026-08-30)"
# P01-BLK-006 judges the speaker's service tests BY NAME in two configurations: no service flag (the `workspace-test` log) and all of the
# services' flags on (this step, which also runs the real-binary tests of `tests/cli_services.rs`). It is a test step of its own kind so
# the workspace totals stay the workspace-test's, and it is listed after the builds so the order the builds ran in does not move.
SERVICE_TEST_STEP = "test-franken-speaker-services"
SERVICE_TEST_BIN = "cli_services"
# rustc's default for these musl targets is a dynamic PIE that needs ld-musl-*.so.1, which the initramfs does not have, and
# `-lgcc_s`, which zig does not ship. A device std artifact is linked static, by the contract's zig wrapper. The tokens are
# inline `--config` arguments (absolute paths, nothing discovered from a working directory, all of it in the recorded argv).
STATIC_RUSTFLAGS = ["-C", "target-feature=+crt-static", "-C", "link-self-contained=no"]
CRT_STATIC = "target-feature=+crt-static"

Step = Dict[str, Any]
Pair = Tuple[str, str]
Executor = Callable[[List[str], str, Dict[str, str], float], Tuple[int, str]]


def _manifest_for(root: str, crate: str, contract: Dict[str, Any]) -> Tuple[str, str]:
    """(manifest path, directory) of a crate: a member under crates/, or an excluded crate by its path."""
    for rec in list(contract["crates"]) + list(contract["excluded"]):
        if rec["name"] == crate:
            directory = os.path.join(root, rec["path"])
            return os.path.join(directory, "Cargo.toml"), directory
    raise KeyError(crate)


def artifact_path(target_dir: str, artifact: Dict[str, Any], contract: Dict[str, Any]) -> str:
    """Where a build leaves an artifact: in the build's own target directory (see `build_dir`)."""
    triple = ref.TARGETS[artifact["target"]][0]
    leaf = artifact["bin"] or artifact["crate"]
    base = build_dir(target_dir, contract, artifact)
    if triple == "host":
        return os.path.join(base, "release", leaf)
    return os.path.join(base, triple, "release", leaf)


def _cargo_features(contract: Dict[str, Any], artifact: Dict[str, Any]) -> List[str]:
    """Cargo flags for the features this artifact's profile enables. A feature with no flag contributes none."""
    profile = next(p for p in contract["profiles"] if p["name"] == artifact["profile"])
    flags = []
    for sel in profile["features"]:
        spec = next((f for f in contract["features"] if f["name"] == sel["feature"]), None)
        if spec and sel["state"] == "enabled" and spec["cargo_feature"]:
            flags.append(f"{spec['owner_crate']}/{spec['cargo_feature']}")
    return sorted(set(flags))


def service_test_features(contract: Dict[str, Any]) -> List[str]:
    """The `franken-speaker` flags the device speakers' full profile builds with (bare names), sorted: the services' flags that the
    all-on test configuration turns on. Derived from the same contract rows as the builds, so the two cannot name different flags."""
    flags = set()
    for art in contract["artifacts"]:
        if art["bin"] and art["crate"] == "franken-speaker" and art["target"] != "host":
            flags.update(f.split("/", 1)[1] for f in _cargo_features(contract, art) if f.startswith("franken-speaker/"))
    return sorted(flags)


def build_variant(contract: Dict[str, Any], artifact: Dict[str, Any]) -> str:
    """"" for the first build (in contract order) of a crate for a target, and the profile's name for any later build of the
    same crate and target with different Cargo features. Artifacts with the same features share one build; artifacts with
    different features are different cargo invocations, and cargo writes the same file name for both."""
    firsts: Dict[Tuple[str, str], Tuple[str, ...]] = {}
    names: Dict[Tuple[str, str, Tuple[str, ...]], str] = {}
    for art in contract["artifacts"]:
        if not art["bin"]:
            continue
        features = tuple(_cargo_features(contract, art))
        group = (art["crate"], art["target"])
        firsts.setdefault(group, features)
        names.setdefault(group + (features,), "" if features == firsts[group] else art["profile"])
    return names[(artifact["crate"], artifact["target"], tuple(_cargo_features(contract, artifact)))]


def build_dir(target_dir: str, contract: Dict[str, Any], artifact: Dict[str, Any]) -> str:
    """The CARGO_TARGET_DIR of the build that makes `artifact`: the plan's own directory, or `variants/<profile>` under it for a
    build whose Cargo features differ from the first build of the same crate and target, so that two profiles of one
    binary never overwrite each other's file."""
    variant = build_variant(contract, artifact)
    return os.path.join(target_dir, "variants", variant) if variant else target_dir


def differing_builds(contract: Dict[str, Any]) -> List[Pair]:
    """Pairs of artifacts that are the same binary for the same target but are built with different Cargo features. Built
    files that differ only by a flag the binary never reads would be the same bytes; these pairs must not be."""
    arts = [a for a in contract["artifacts"] if a["bin"]]
    return [(a["id"], b["id"]) for i, a in enumerate(arts) for b in arts[i + 1:]
            if (a["crate"], a["target"]) == (b["crate"], b["target"]) and _cargo_features(contract, a) != _cargo_features(contract, b)]


def linker_for(contract: Dict[str, Any], artifact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The declared linker for a device artifact, or None (the bootstrap probe links with rust-lld)."""
    return ref.linker_for(contract, artifact)


def linker_config(root: str, triple: str, linker: Dict[str, Any]) -> List[str]:
    """The two `--config` pairs that make rustc link a device artifact static through the contract's wrapper."""
    wrapper = os.path.join(root, linker["wrapper"])
    return ["--config", f'target.{triple}.linker="{wrapper}"',
            "--config", f"target.{triple}.rustflags={json.dumps(STATIC_RUSTFLAGS, separators=(',', ':'))}"]


def unbacked_disabled_features(contract: Dict[str, Any], artifact: Dict[str, Any]) -> List[str]:
    """Features the artifact's profile disables that the artifact's own build cannot omit: no Cargo flag, or a flag that belongs
    to another crate than the one this artifact is built from (a flag on `franken-speaker` does nothing to a probe built from
    `ffw-hello-init`)."""
    profile = next(p for p in contract["profiles"] if p["name"] == artifact["profile"])
    out = []
    for sel in profile["features"]:
        spec = next((f for f in contract["features"] if f["name"] == sel["feature"]), None)
        if spec and sel["state"] == "disabled" and not (spec["cargo_feature"] and spec["owner_crate"] == artifact["crate"]):
            out.append(sel["feature"])
    return sorted(out)


def plan_steps(root: str, cwd: str, target_dir: str, contract: Dict[str, Any],
               jobs: int = DEFAULT_JOBS) -> List[Step]:
    """The central command plan. Builds are shared by artifacts that need the identical cargo invocation.

    One toolchain step records what the build host runs: plain `rustc -vV`, the compiler a bare `cargo` resolves to there (the
    repository's pin, `PIN_FILE`), which is what the workspace test and the host build use. There is no `rustc +nightly -vV` step:
    rch drops the `+nightly` and prints the default compiler, so it would label one compiler as another. The compiler a device
    artifact was built by is read from the artifact itself (`rustc_versions`). Every cargo step ends with `-j <jobs>`.

    Artifacts share a build only when they need the identical cargo invocation, Cargo features included. The first build of
    a crate for a target is `build-<crate>-<target>` in the plan's target directory; a later build of the same crate and
    target with other features (the minimal profile, which selects no native service) is
    `build-<crate>-<target>-<profile>`, in its own `variants/<profile>` target directory (`build_dir`)."""
    root = os.path.realpath(root)
    env = {"RCH_REQUIRE_REMOTE": "1", "CARGO_TARGET_DIR": target_dir}
    jobs_args = ["-j", str(jobs)]
    steps: List[Step] = [{
        "id": "toolchain-default", "kind": "toolchain_default", "artifacts": [], "cwd": cwd, "env": dict(env),
        "argv": [RCH, "exec", "--", "rustc", "-vV"],
    }]
    workspace_manifest = os.path.join(root, "Cargo.toml")
    steps.append({
        "id": "workspace-test", "kind": "test", "artifacts": [], "cwd": cwd, "env": dict(env),
        "argv": [RCH, "exec", "--", "cargo", "test", "--locked", "--offline", "--manifest-path",
                 workspace_manifest, "--workspace", "--config", "build.incremental=false", *jobs_args],
    })
    builds: Dict[Tuple[Any, ...], Step] = {}
    for art in contract["artifacts"]:
        if not art["bin"]:
            continue
        manifest, directory = _manifest_for(root, art["crate"], contract)
        triple, _isa, _machine, is_device = ref.TARGETS[art["target"]]
        is_hello = os.path.relpath(directory, root) == HELLO_REL
        features = _cargo_features(contract, art)
        key = (art["crate"], art["target"], tuple(features))
        if key in builds:
            builds[key]["artifacts"].append(art["id"])
            continue
        argv = [RCH, "exec", "--", "cargo"]
        if is_device:
            argv.append("+" + DEVICE_TOOLCHAIN)
        argv += ["build", "--locked", "--offline", "--manifest-path", manifest, "--release"]
        if not is_hello:
            argv += ["-p", art["crate"]]
        else:
            # Cargo finds .cargo/config.toml from the working directory, not from the manifest. From another
            # directory the bootstrap probe's linker and flags would be silently dropped, so name the file.
            argv += ["--config", os.path.join(directory, ".cargo", "config.toml")]
        if is_device:
            argv += ["--target", triple, "-Z", HELLO_BUILD_STD if is_hello else WORKSPACE_BUILD_STD]
            linker = linker_for(contract, art)
            if linker is not None:
                argv += linker_config(root, triple, linker)
        if features:
            argv += ["--features", ",".join(features)]
        argv += jobs_args
        step_env = dict(env)
        variant = build_variant(contract, art)
        if variant:
            step_env["CARGO_TARGET_DIR"] = build_dir(target_dir, contract, art)
        if not is_device:
            step_env[FOREIGN_ARTIFACTS_ENV] = "1"
        # RCH syncs to the worker only the Cargo closure of the project the step runs from. A linker wrapper under
        # toolchain/linker/ is in no crate's closure, so a step that names one runs from the workspace root, whose sync
        # carries it (observed: from crates/franken-board-profile the sync was 91 files and had no toolchain/).
        uses_linker = is_device and linker_for(contract, art) is not None
        step = {"id": f"build-{art['crate']}-{art['target']}" + (f"-{variant}" if variant else ""), "kind": "build",
                "artifacts": [art["id"]],
                "cwd": root if uses_linker else cwd, "env": step_env, "argv": argv}
        builds[key] = step
        steps.append(step)
    services = service_test_features(contract)
    if services:
        steps.append({
            "id": SERVICE_TEST_STEP, "kind": "service_test", "artifacts": [], "cwd": cwd, "env": dict(env),
            "argv": [RCH, "exec", "--", "cargo", "test", "--locked", "--offline", "--manifest-path", workspace_manifest,
                     "-p", "franken-speaker", "--lib", "--test", SERVICE_TEST_BIN, "--features", ",".join(services),
                     "--config", "build.incremental=false", *jobs_args],
        })
    return steps


def inner_command(argv: Sequence[str]) -> List[str]:
    """The command rch runs remotely: what follows `rch exec --`."""
    return list(argv[list(argv).index("--") + 1:]) if "--" in argv else list(argv)


def _has_jobs(inner: Sequence[str]) -> bool:
    """`-j N` or `--jobs N` with a positive integer N."""
    for flag in ("-j", "--jobs"):
        if flag in inner:
            i = list(inner).index(flag)
            return i + 1 < len(inner) and inner[i + 1].isdigit() and int(inner[i + 1]) >= 1
    return False


def check_plan(steps: Sequence[Step], root: str, contract: Dict[str, Any]) -> List[Pair]:
    """Rule violations of a plan as sorted (code, step id) pairs. An empty list means the plan is acceptable."""
    root = os.path.realpath(root)
    errs = set()
    by_id = {a["id"]: a for a in contract["artifacts"]}
    for step in steps:
        sid = step["id"]
        argv = step["argv"]
        if argv[:2] != [RCH, "exec"] or "--" not in argv:
            errs.add(("plan_not_remote", sid))
            continue
        inner = argv[argv.index("--") + 1:]
        env = step["env"]
        if env.get("RCH_REQUIRE_REMOTE") != "1":
            errs.add(("plan_require_remote_missing", sid))
        if any(k in env for k in BYPASS_ENV):
            errs.add(("plan_bypass_env", sid))
        if FOREIGN_ARTIFACTS_ENV in env:
            hosted = [by_id[a]["target"] == "host" for a in step["artifacts"] if a in by_id]
            if step["kind"] != "build" or not hosted or not all(hosted):
                errs.add(("plan_foreign_artifacts_misplaced", sid))
        cwd = step["cwd"]
        linked = step["kind"] == "build" and any(
            a in by_id and ref.TARGETS[by_id[a]["target"]][3] and linker_for(contract, by_id[a]) is not None
            for a in step["artifacts"])
        if not os.path.isdir(cwd):
            errs.add(("plan_cwd_missing", sid))
        elif linked:
            # the wrapper is synced only with the workspace root (see plan_steps)
            if os.path.realpath(cwd) != root:
                errs.add(("plan_linker_step_not_from_root", sid))
        elif os.path.realpath(cwd) == root:
            errs.add(("plan_cwd_is_root", sid))
        if not inner or inner[0] != "cargo":
            continue
        if "--locked" not in inner:
            errs.add(("plan_missing_locked", sid))
        if "--offline" not in inner:
            errs.add(("plan_missing_offline", sid))
        if not _has_jobs(inner):
            errs.add(("plan_missing_jobs", sid))
        manifest = inner[inner.index("--manifest-path") + 1] if "--manifest-path" in inner else ""
        if not manifest or not os.path.isabs(manifest) or not os.path.realpath(manifest).startswith(root + os.sep):
            errs.add(("plan_manifest_not_absolute", sid))
        if step["kind"] != "build":
            continue
        for aid in step["artifacts"]:
            art = by_id.get(aid)
            if art is None:
                continue
            if ref.TARGETS[art["target"]][3]:
                triple = ref.TARGETS[art["target"]][0]
                if "--target" not in inner or inner[inner.index("--target") + 1] != triple:
                    errs.add(("plan_device_without_target", sid))
                if "-Z" not in inner or not inner[inner.index("-Z") + 1].startswith("build-std="):
                    errs.add(("plan_device_without_build_std", sid))
        configs = [inner[i + 1] for i, tok in enumerate(inner[:-1]) if tok == "--config"]
        for aid in step["artifacts"]:
            art = by_id.get(aid)
            linker = linker_for(contract, art) if art is not None else None
            if linker is None or not ref.TARGETS[art["target"]][3]:
                continue
            triple = ref.TARGETS[art["target"]][0]
            if f'target.{triple}.linker="{os.path.join(root, linker["wrapper"])}"' not in configs:
                errs.add(("plan_device_without_linker", sid))
            if not any(c.startswith(f"target.{triple}.rustflags=") and CRT_STATIC in c for c in configs):
                errs.add(("plan_device_not_static", sid))
        manifest_dir = os.path.dirname(manifest)
        if os.path.isabs(manifest) and os.path.isfile(os.path.join(manifest_dir, ".cargo", "config.toml")):
            wanted = os.path.join(manifest_dir, ".cargo", "config.toml")
            if "--config" not in inner or wanted not in inner:
                errs.add(("plan_config_not_explicit", sid))
    return sorted(errs)


# ------------------------------------------------------------------------------ identity from bytes

PT_DYNAMIC, PT_INTERP, PT_MIPS_ABIFLAGS = 2, 3, 0x70000003
# Val_GNU_MIPS_ABI_FP_* in .MIPS.abiflags. Only DOUBLE ("hard") and SOFT are the two the contract can declare.
_MIPS_FP_ABI = {0: "", 1: "hard", 2: "single", 3: "soft", 4: "old64", 5: "xx", 6: "fp64", 7: "fp64a"}


def elf_program_facts(data: bytes) -> Tuple[bool, str, str]:
    """(dynamic, isa_revision, fp_abi) from an ELF's program headers.

    `dynamic` is True if there is a PT_INTERP or PT_DYNAMIC segment, and also when the header table cannot be read: a file
    that cannot be shown to be static is not reported as static. `isa_revision` ("mips32r2") and `fp_abi` ("soft"/"hard")
    come from the PT_MIPS_ABIFLAGS segment (.MIPS.abiflags) and are "" when it is absent, as it is on PowerPC; they are read
    from the segment, not the section headers, so a stripped file keeps them."""
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return False, "", ""
    order = "big" if data[5] == 2 else "little"
    wide = data[4] == 2
    try:
        if wide:
            phoff = int.from_bytes(data[32:40], order)
            phentsize, phnum = int.from_bytes(data[54:56], order), int.from_bytes(data[56:58], order)
        else:
            phoff = int.from_bytes(data[28:32], order)
            phentsize, phnum = int.from_bytes(data[42:44], order), int.from_bytes(data[44:46], order)
        min_entry = 56 if wide else 32
        if phnum and (phentsize < min_entry or phoff + phentsize * phnum > len(data)):
            return True, "", ""
        dynamic, isa, fp = False, "", ""
        for index in range(phnum):
            base = phoff + index * phentsize
            p_type = int.from_bytes(data[base:base + 4], order)
            if p_type in (PT_INTERP, PT_DYNAMIC):
                dynamic = True
            if p_type == PT_MIPS_ABIFLAGS:
                if wide:
                    offset, size = int.from_bytes(data[base + 8:base + 16], order), int.from_bytes(data[base + 32:base + 40], order)
                else:
                    offset, size = int.from_bytes(data[base + 4:base + 8], order), int.from_bytes(data[base + 16:base + 20], order)
                if size < 8 or offset + 8 > len(data):
                    return True, "", ""
                level, rev, fp_abi = data[offset + 2], data[offset + 3], data[offset + 7]
                isa = f"mips{level}" + (f"r{rev}" if rev else "")
                fp = _MIPS_FP_ABI.get(fp_abi, f"fp{fp_abi}")
        return dynamic, isa, fp
    except (IndexError, ValueError):
        return True, "", ""


# rustc leaves `rustc version <release> (<short hash> <commit date>)` in the `.comment` section of what it links, and it survives
# `strip = "symbols"`. It is the one place a built file names the compiler that built it.
_RUSTC_VERSION = re.compile(rb"rustc version ([0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{0,80})")


def rustc_versions(data: bytes) -> List[str]:
    """The distinct `rustc version` strings in a file's bytes (the part after `rustc version `), sorted; at most eight."""
    return sorted({m.group(1).decode("ascii", "replace").strip() for m in _RUSTC_VERSION.finditer(data)})[:8]


def elf_identity(path: str) -> Dict[str, Any]:
    """SHA-256 of the file and, if it is an ELF, its class, byte order, e_machine, whether it is dynamic, and the ISA
    revision and float ABI its MIPS ABI flags state, read from the bytes, plus the compiler strings the file carries."""
    with open(path, "rb") as f:
        data = f.read()
    out: Dict[str, Any] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                           "elf_machine": 0, "elf_class": 0, "elf_big_endian": False,
                           "elf_dynamic": False, "isa_revision": "", "fp_abi": "", "rustc_versions": rustc_versions(data)}
    if len(data) >= 20 and data[:4] == b"\x7fELF":
        big = data[5] == 2
        out["elf_class"] = data[4]
        out["elf_big_endian"] = big
        out["elf_machine"] = int.from_bytes(data[18:20], "big" if big else "little")
        out["elf_dynamic"], out["isa_revision"], out["fp_abi"] = elf_program_facts(data)
    return out


def observed_row(contract: Dict[str, Any], artifact: Dict[str, Any], ident: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": artifact["id"], "target": artifact["target"], "triple": ref.TARGETS[artifact["target"]][0],
            "profile": artifact["profile"], "sha256": ident["sha256"], "elf_machine": ident["elf_machine"],
            "elf_class": ident["elf_class"], "elf_big_endian": ident["elf_big_endian"],
            "contract_digest": ref.digest(contract), "elf_dynamic": ident["elf_dynamic"],
            "isa_revision": ident["isa_revision"], "fp_abi": ident["fp_abi"]}


def parse_rustc_vv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            if key in ("release", "commit-hash", "host", "LLVM version"):
                out[key] = val.strip()
    return out


# ------------------------------------------------------------------------------ receipts

def _utc(now: Optional[float] = None) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))


def _write_new(receipts_dir: str, run_id: str) -> str:
    os.makedirs(receipts_dir, exist_ok=True)
    path = os.path.join(receipts_dir, f"p01-{run_id}.json")
    with open(path, "xb"):  # exclusive create: an earlier receipt is never overwritten
        pass
    return path


def _save(path: str, receipt: Dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def execute(steps: Sequence[Step], contract: Dict[str, Any], root: str, target_dir: str, receipts_dir: str,
            executor: Executor, lock_sha256: str = "", timeout: float = 7200.0,
            now: Callable[[], float] = time.time) -> Tuple[int, str, Dict[str, Any]]:
    """Run a plan, write the receipt after every step, and verify the artifacts it produced.

    Returns (exit code, receipt path, receipt). Exit 0 only when every step succeeded and the artifact identities
    verify against the contract. A cancelled run leaves a receipt marked `incomplete` and exits 130."""
    run_id = f"{_utc(now())}-{secrets.token_hex(4)}"
    path = _write_new(receipts_dir, run_id)
    by_id = {a["id"]: a for a in contract["artifacts"]}
    receipt: Dict[str, Any] = {
        "schema": RECEIPT_SCHEMA, "kind": "build_identity", "run_id": run_id, "status": "incomplete",
        "contract_digest": ref.digest(contract), "lock_sha256": lock_sha256,
        "plan": [{"id": s["id"], "kind": s["kind"], "argv": list(s["argv"]), "artifacts": list(s["artifacts"])}
                 for s in steps],
        "steps": [], "toolchain_default": {}, "artifacts": [], "unbacked_disabled_features": {},
        "verification": {"codes": [], "pairs": []},
        "boundary": ("Records what a build host built and what the files contain. Not an attestation of the "
                     "remote compiler; evidence kind is a build, not a guest execution or a physical result."),
    }
    _save(path, receipt)
    code = 0
    try:
        for step in steps:
            started = now()
            rc, output = executor(list(step["argv"]), step["cwd"], dict(step["env"]), timeout)
            record = {"id": step["id"], "rc": rc, "seconds": round(now() - started, 3),
                      "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
                      "status": "ok" if rc == 0 else "failed"}
            receipt["steps"].append(record)
            if step["kind"] == "toolchain_default" and rc == 0:
                receipt["toolchain_default"] = parse_rustc_vv(output)
            if step["kind"] == "build" and rc == 0:
                for aid in step["artifacts"]:
                    art = by_id[aid]
                    built = artifact_path(target_dir, art, contract)
                    if not os.path.isfile(built):
                        record["status"] = "failed"
                        record["note"] = "build reported success but the artifact file is absent"
                        continue
                    receipt["artifacts"].append(observed_row(contract, art, elf_identity(built)))
                    receipt["unbacked_disabled_features"][aid] = unbacked_disabled_features(contract, art)
            _save(path, receipt)
            if record["status"] != "ok":
                code = 1
        pairs = ref.verify_observed(contract, receipt["artifacts"], require_all=False)
        receipt["verification"] = {"codes": ref.codes(pairs), "pairs": [list(p) for p in pairs]}
        complete = (code == 0 and not pairs and {a["id"] for a in contract["artifacts"] if a["bin"]}
                    == {r["id"] for r in receipt["artifacts"]})
        receipt["status"] = "complete" if complete else "failed"
        if not complete:
            code = code or 1
        _save(path, receipt)
        return code, path, receipt
    except KeyboardInterrupt:
        receipt["status"] = "incomplete"
        receipt["interrupted_after"] = [s["id"] for s in receipt["steps"]]
        _save(path, receipt)
        return 130, path, receipt


def check_receipt(contract: Dict[str, Any], receipt: Dict[str, Any]) -> List[Pair]:
    """Re-verify a receipt against the contract. Sorted (code, subject) pairs; empty means it holds up."""
    errs = set()
    if receipt.get("schema") != RECEIPT_SCHEMA:
        errs.add(("receipt_schema", "receipt"))
        return sorted(errs)
    if receipt.get("contract_digest") != ref.digest(contract):
        errs.add(("receipt_digest_mismatch", "receipt"))
    try:
        rows = ref.parse_observed(receipt.get("artifacts", []))
    except ref.ParseError:
        errs.add(("receipt_row_incomplete", "artifacts"))
        return sorted(errs)
    pairs = ref.verify_observed(contract, rows, require_all=False)
    errs.update(pairs)
    if receipt.get("verification", {}).get("codes") != ref.codes(pairs):
        errs.add(("receipt_verification_stale", "verification"))
    if receipt.get("status") == "complete":
        failed = [s["id"] for s in receipt.get("steps", []) if s.get("rc") != 0 or s.get("status") != "ok"]
        if failed or pairs:
            errs.add(("receipt_status_inconsistent", "status"))
        wanted = {a["id"] for a in contract["artifacts"] if a["bin"]}
        if wanted != {r["id"] for r in rows}:
            errs.add(("receipt_status_inconsistent", "artifacts"))
    return sorted(errs)
