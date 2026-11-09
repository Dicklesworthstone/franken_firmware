"""Prepare the pinned tailscale-rs source tree for T01 candidate builds: copy it into a fresh directory and, if a named patch is asked for, apply that patch
there, only when every digest matches (bead ffw-32a).

    python3 -B toolchain/src/prepare-tailscale-rs.py --pinned DIR --patch NAME|none --out NEWDIR [--receipt FILE]

consumer    the T01 candidate builds that need a patched tailscale-rs tree (the manifest's `header` says which defect and when the patch retires).
gate        no patched tailscale-rs source reaches a build without a digest match: the patch file's sha256 must be the manifest's, the supplied tree must be the pin
            (`profiles.json`, hashed by `t01lib.tree_digest` through `t01lib.Source`, which refuses symlinks and non-regular files), the patch may write only the paths the
            manifest lists and never `LICENSE` or `PATENTS`, and the patched tree's digest must be the manifest's `result_tree_sha256`. Any mismatch is a refusal (exit 1)
            and leaves no output directory.
never       the pinned tree is only read (through `Source`), never patched in place and never written; its digest is taken again before the output is put in place, and
            `--out` must not exist or lie inside it. `--patch none` copies the pinned tree unchanged, so its identity is the pin (the unpatched control). Only regular
            files are copied (as the digest sees them); empty directories are not.
record      `--receipt FILE` (written once, never overwritten) holds the upstream pin, the base tree digest, the patch name and sha256, the manifest's sha256, the result tree
            digest, the upstream `LICENSE` and `PATENTS` digests (kept byte for byte) and this script's own sha256. It names no host path.

A patched tree's identity is NOT the pin. `t01lib.judge_build_record` compares a synced `tailscale-rs/` tree to the pin, so a patched candidate's build record is refused as
"not the pinned tree", and that refusal is correct. Accepting a patched identity is a separate decision, to be taken once the reviewed patch exists and a patched build is about
to be judged; this script does not change it. Standard library only; the hashing and the tree walk are `t01lib`'s, not a copy. The `patch` tool must be on PATH.
"""
import argparse
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests", "t01"))
import t01lib as L  # noqa: E402

PATCH_DIR = os.path.join(ROOT, "toolchain", "patches", "tailscale-rs")
MANIFEST = os.path.join(PATCH_DIR, "manifest.json")
MANIFEST_SCHEMA = "ffw.t01.tailscale_rs_patches.v1"
RECEIPT_SCHEMA = "ffw.t01.tailscale_rs_prepare_receipt.v1"
PIN_KEY = "tailscale-rs-0.6.1"
LICENSE_FILES = ("LICENSE", "PATENTS")
HEADER_KEYS = ("consumer", "gate", "defect", "retirement", "note")
MAX_PATCH_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
PATCH_SECONDS = 60
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PATCH_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.patch")
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class Refused(Exception):
    """A digest, bound or form check failed. The message never carries a supplied or host path."""


def safe_rel(rel):
    """A tree-relative path with no `..`, no empty part, no backslash and nothing under `.git`."""
    parts = rel.split("/")
    return bool(rel) and posixpath.normpath(rel) == rel and not rel.startswith("/") and "\\" not in rel and "" not in parts and ".." not in parts and ".git" not in parts


def read_capped(path, cap, what):
    try:
        with open(path, "rb") as handle:
            data = handle.read(cap + 1)
    except OSError as err:
        raise Refused("the %s cannot be read (%s)" % (what, type(err).__name__)) from None
    if len(data) > cap:
        raise Refused("the %s is over the %d byte cap" % (what, cap))
    return data


def load_pin(profile_path=None):
    """The pin from the profile: upstream commit, licence and the pinned tree digest."""
    try:
        profile = L.load_json(profile_path or L.PROFILE)
        pin = dict(profile["candidates"][PIN_KEY]["pin"])
        tree = profile["derived_facts"][PIN_KEY]["tree_sha256"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise Refused("the profile does not carry the tailscale-rs pin (%s)" % type(err).__name__) from None
    if not (HEX40.fullmatch(str(pin.get("commit"))) and HEX64.fullmatch(str(tree))):
        raise Refused("the profile's pin is malformed")
    return {"repo": pin.get("repo"), "tag": pin.get("tag"), "commit": pin["commit"], "license": pin.get("license"), "tree_sha256": tree}


def manifest_problems(doc):
    """Why a manifest is not usable, as a list (empty when it is)."""
    problems = []
    if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA:
        return ["the schema is not %s" % MANIFEST_SCHEMA]
    header = doc.get("header")
    if not isinstance(header, dict) or any(not isinstance(header.get(k), str) or not header[k].strip() for k in HEADER_KEYS):
        problems.append("the header lacks one of %s" % ", ".join(HEADER_KEYS))
    upstream = doc.get("upstream")
    if not isinstance(upstream, dict) or not HEX40.fullmatch(str(upstream.get("commit"))):
        problems.append("upstream.commit is not a 40-digit commit")
    entries = doc.get("patches")
    if not isinstance(entries, list):
        return problems + ["patches is not a list"]
    names = set()
    for number, entry in enumerate(entries):
        where = "patches[%d]" % number
        if not isinstance(entry, dict):
            problems.append("%s is not an object" % where)
            continue
        name = entry.get("name")
        if not (isinstance(name, str) and NAME.fullmatch(name)) or name == "none" or name in names:
            problems.append("%s has a missing, reserved or repeated name" % where)
        names.add(name)
        if not (isinstance(entry.get("file"), str) and PATCH_FILE.fullmatch(entry["file"])):
            problems.append("%s.file is not a plain *.patch file name" % where)
        for key in ("sha256", "base_tree_sha256", "result_tree_sha256"):
            if not HEX64.fullmatch(str(entry.get(key))):
                problems.append("%s.%s is not a sha256" % (where, key))
        touches = entry.get("touches")
        if not (isinstance(touches, list) and touches and all(isinstance(t, str) and safe_rel(t) for t in touches) and touches == sorted(set(touches))):
            problems.append("%s.touches is not a sorted list of unique safe paths" % where)
    return problems


def parse_manifest(data):
    """The manifest document from its bytes, or Refused."""
    try:
        doc = json.loads(data)
    except ValueError:
        raise Refused("the manifest is not valid JSON") from None
    problems = manifest_problems(doc)
    if problems:
        raise Refused("the manifest is not valid: %s" % "; ".join(problems[:3]))
    return doc


def load_manifest(path=MANIFEST):
    return parse_manifest(read_capped(path, MAX_MANIFEST_BYTES, "manifest"))


def _label_path(label, prefix):
    label = label.split("\t")[0].strip()
    if label == "/dev/null":
        return None
    if not label.startswith(prefix) or not safe_rel(label[len(prefix):]):
        raise Refused("the patch names a path that is not a safe %s... path" % prefix)
    return label[len(prefix):]


def patch_paths(data):
    """The tree paths a plain unified diff (`diff -u`, labels `a/PATH` and `b/PATH`, `/dev/null` for a new or removed file) writes. Anything else (git headers, renames, copies, binary
    or mode changes, text outside a hunk, a truncated hunk) is refused, so what `patch` is given is exactly what this reading covers."""
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        raise Refused("the patch is not UTF-8 text") from None
    if lines and lines[-1] == "":
        lines.pop()
    paths, i = set(), 0
    while i < len(lines):
        if not (lines[i].startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
            raise Refused("the patch is not a plain unified diff (unexpected text outside a hunk)")
        old, new = _label_path(lines[i][4:], "a/"), _label_path(lines[i + 1][4:], "b/")
        if old is None and new is None or (old is not None and new is not None and old != new):
            raise Refused("the patch renames, copies or names no file")
        paths.add(old or new)
        i += 2
        hunks = 0
        while i < len(lines) and lines[i].startswith("@@"):
            found = HUNK.fullmatch(lines[i])
            if not found:
                raise Refused("the patch has a malformed hunk header")
            old_n = 1 if found[2] is None else int(found[2])
            new_n = 1 if found[4] is None else int(found[4])
            i += 1
            while old_n > 0 or new_n > 0:
                if i >= len(lines):
                    raise Refused("the patch ends inside a hunk")
                tag = lines[i][:1]
                if tag == "\\":
                    i += 1
                    continue
                if tag in (" ", ""):
                    old_n, new_n = old_n - 1, new_n - 1
                elif tag == "-":
                    old_n -= 1
                elif tag == "+":
                    new_n -= 1
                else:
                    raise Refused("the patch has a line that is not part of its hunk")
                if old_n < 0 or new_n < 0:
                    raise Refused("the patch has a hunk longer than its header says")
                i += 1
            while i < len(lines) and lines[i].startswith("\\"):
                i += 1
            hunks += 1
        if hunks == 0:
            raise Refused("the patch names a file and has no hunk")
    if not paths:
        raise Refused("the patch writes nothing")
    return paths


def _copy_tree(source, dest_root):
    """Write every admitted file of `source` (read through `Source`, so each read is checked) under `dest_root`, with the source file's permission bits."""
    for rel in sorted(source.files()):
        dest = os.path.join(dest_root, *rel.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        data = source.read(rel)
        try:
            mode = os.lstat(os.path.join(source.root, *rel.split("/"))).st_mode & 0o777
        except OSError:
            mode = 0o644
        with open(dest, "xb") as handle:
            handle.write(data)
        os.chmod(dest, mode)


def _apply(tree, patch_file):
    try:
        done = subprocess.run(["patch", "-p1", "--fuzz=0", "--silent", "--no-backup-if-mismatch", "-i", patch_file], cwd=tree, capture_output=True, text=True,
                              timeout=PATCH_SECONDS, env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}, check=False)
    except FileNotFoundError:
        raise Refused("the patch tool is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise Refused("the patch tool passed its %d s deadline" % PATCH_SECONDS) from None
    if done.returncode != 0:
        said = " ".join((done.stdout + " " + done.stderr).replace(tree, "<tree>").replace(patch_file, "<patch>").split())[:200]
        raise Refused("the patch does not apply cleanly (rc %d: %s)" % (done.returncode, said))


def prepare(pinned, patch_name, out, *, pin, manifest_path=MANIFEST, patch_dir=PATCH_DIR, receipt_path=None):
    """Prepare `out` (a directory that must not exist) from the pinned tree `pinned`, with the manifest's patch `patch_name` applied or, for "none", unpatched. Returns the receipt
    (a dict) and raises Refused, or `t01lib.SourceRefused` for a tree that is not a plain tree, on any mismatch, leaving nothing at `out`."""
    manifest_bytes = read_capped(manifest_path, MAX_MANIFEST_BYTES, "manifest")
    manifest = parse_manifest(manifest_bytes)
    if manifest["upstream"]["commit"] != pin["commit"]:
        raise Refused("the manifest is for another upstream commit than the profile's pin")
    entry = patch_data = None
    expected = pin["tree_sha256"]
    if patch_name != "none":
        matching = [e for e in manifest["patches"] if e["name"] == patch_name]
        if len(matching) != 1:
            raise Refused("the manifest has no patch named %s" % patch_name[:40])
        entry = matching[0]
        patch_data = read_capped(os.path.join(patch_dir, entry["file"]), MAX_PATCH_BYTES, "patch file")
        if L.sha256_bytes(patch_data) != entry["sha256"]:
            raise Refused("the patch file's sha256 is not the manifest's")
        if entry["base_tree_sha256"] != pin["tree_sha256"]:
            raise Refused("the manifest entry was made for another base tree than the pin")
        paths = patch_paths(patch_data)
        if paths != set(entry["touches"]):
            raise Refused("the patch writes paths other than the manifest lists")
        if any(posixpath.basename(p).upper() in LICENSE_FILES for p in paths):
            raise Refused("the patch touches an upstream licence file")
        expected = entry["result_tree_sha256"]

    real_pinned, real_out = os.path.realpath(pinned), os.path.realpath(out)
    if os.path.lexists(out):
        raise Refused("the output path already exists")
    if os.path.commonpath([real_pinned, real_out]) in (real_pinned, real_out):
        raise Refused("the output path is the pinned tree or lies inside it, or contains it")
    parent = os.path.dirname(real_out)
    if not os.path.isdir(parent):
        raise Refused("the output path has no parent directory")
    if receipt_path is not None and os.path.lexists(receipt_path):
        raise Refused("the receipt path already exists")

    source = L.Source(real_pinned)
    if L.tree_digest(source) != pin["tree_sha256"]:
        raise Refused("the supplied tree is not the pinned tree (digest %s, pin %s)" % (L.tree_digest(source)[:12], pin["tree_sha256"][:12]))
    base_licences = {name: (L.sha256_bytes(source.read(name)) if source.has(name) else None) for name in LICENSE_FILES}

    scratch = None
    try:
        scratch = tempfile.mkdtemp(prefix=".prepare-tailscale-rs-", dir=parent)
        tree = os.path.join(scratch, "tree")
        os.mkdir(tree)
        _copy_tree(source, tree)
        if patch_data is not None:
            # The bytes that were hashed, from a file of our own: the patch tool never reads the manifest's file again.
            applied = os.path.join(scratch, "applied.patch")
            with open(applied, "xb") as handle:
                handle.write(patch_data)
            _apply(tree, applied)
        result = L.Source(tree)
        got = L.tree_digest(result)
        if got != expected:
            raise Refused("the prepared tree's digest %s is not the expected %s" % (got[:12], expected[:12]))
        licences = {name: (L.sha256_bytes(result.read(name)) if result.has(name) else None) for name in LICENSE_FILES}
        if licences != base_licences:
            raise Refused("an upstream licence file differs from the pinned tree's")
        if L.tree_digest(L.Source(real_pinned)) != pin["tree_sha256"]:
            raise Refused("the pinned tree changed while it was being prepared")
        os.rename(tree, real_out)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "upstream": {"repo": pin["repo"], "tag": pin["tag"], "commit": pin["commit"], "license": pin["license"]},
            "base_tree_sha256": pin["tree_sha256"],
            "manifest_sha256": L.sha256_bytes(manifest_bytes),
            "patch": None if entry is None else {"name": entry["name"], "file": entry["file"], "sha256": entry["sha256"], "touches": entry["touches"]},
            "result_tree_sha256": got,
            "result_files": len(result.files()),
            "applied_in_place": False,
            "license_files": licences,
            "license_note": "upstream LICENSE and PATENTS are kept byte for byte (checked against the pinned tree)",
            "tool": {"script": "toolchain/src/prepare-tailscale-rs.py", "sha256": L.sha256_file(os.path.realpath(__file__))},
        }
    except OSError as err:
        raise Refused("the output could not be prepared (%s)" % type(err).__name__) from None
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)
    if receipt_path is not None:
        try:
            with open(receipt_path, "x", encoding="utf-8") as handle:
                json.dump(receipt, handle, indent=1, sort_keys=True)
                handle.write("\n")
        except OSError as err:
            raise Refused("the receipt could not be written (%s); the prepared tree is in place" % type(err).__name__) from None
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare the pinned tailscale-rs tree, with a named patch applied only on a digest match (see the module docstring).")
    parser.add_argument("--pinned", required=True, help="the pinned tailscale-rs tree (read only)")
    parser.add_argument("--patch", required=True, help="a patch name from the manifest, or none for an unpatched copy")
    parser.add_argument("--out", required=True, help="the directory to create (must not exist)")
    parser.add_argument("--receipt", help="write a JSON receipt here (must not exist)")
    parser.add_argument("--manifest", default=MANIFEST, help="the patch manifest (default: the repo's)")
    parser.add_argument("--profile", default=L.PROFILE, help="the profile that carries the pin (default: the repo's)")
    args = parser.parse_args(argv)
    try:
        receipt = prepare(args.pinned, args.patch, args.out, pin=load_pin(args.profile), manifest_path=args.manifest, patch_dir=os.path.dirname(os.path.realpath(args.manifest)),
                          receipt_path=args.receipt)
    except (Refused, L.SourceRefused) as err:
        print("REFUSED: %s" % err, file=sys.stderr)
        return 1
    patch = receipt["patch"]
    print("PREPARED tailscale-rs commit=%s patch=%s tree=%s files=%d" % (receipt["upstream"]["commit"][:8], "none" if patch is None else patch["name"],
                                                                         receipt["result_tree_sha256"][:12], receipt["result_files"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
