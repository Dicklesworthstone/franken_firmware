#!/usr/bin/env python3
"""Build the four directories the E06 codec check lines run in, from the two pinned archives. Offline, stdlib only, no shell.

    prepare_candidates.py --archives-dir <repo>/build/e06-candidates --locks-dir <this handoff>/locks --out <NEW dir>

* verifies each archive's sha256 against the digest root mailed (4251) and each lock file against the digest recorded when the audit ran;
* extracts the archives with tarfile's `data` filter into new directories (nothing existing is touched or overwritten);
* writes, under --out:
    symphonia-ws/        workspace root + probe (Symphonia 0.6.1, default-features = false, features aac alac vorbis pcm ogg isomp4) + upstream/ + Cargo.lock
    opus-ws/             workspace root + probe (opus-pure 0.2.2, default features, `probe` feature OFF) + upstream/ + Cargo.lock
    opus-lint/           the opus-pure export alone + Cargo.lock           (the root-lint check lines run here)
    opus-lint-planted/   the same plus ONE planted `unsafe` block in src/lib.rs (the control: the root lint must FAIL here)
  and prints a tree digest per directory (sha256 over sorted path/file-sha256 pairs) to compare with RUN.md.
The locks are the ones the audit used. They are generated offline from the auditing machine's registry cache, so they are NOT upstream
pins (neither project commits a lock for these configurations); they fix the versions the audit and the checks share."""
import argparse
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile

ARCHIVES = {
    "symphonia": ("Symphonia-ee35874b571a35a9a6e15d3bc9a3aaf8f11fbeee", "3c1d84c8789b86e950ee045edbac2ce74c7ac0525fe31c1b4b08233f2ec3cd33"),
    "opus-pure": ("opus-pure-cf954a76381ae8968b2bc35bb5d578b3a2311d53", "65ef43dab77204db7e1809fab5ed2eba23f92ab00e4c10094931d3bd52367d32"),
}
LOCKS = {
    "symphonia-ws.Cargo.lock": "99e4fff573a1b36e678959d3101ab0909033028fb9c24ccdb1b8203906fbd69e",
    "opus-ws.Cargo.lock": "ddd8830fa13b605bd1bf4612c72bbb857aaf297e4e0f043b56e47ef2a5b06547",
    "opus-pure.Cargo.lock": "3220752619f2645c19be5eb64e49e5ce116a771fd22df37c0b4b2aa7aaaa06ff",
}
ROOT_MANIFEST = '[workspace]\nresolver = "2"\nmembers = ["probe"]\nexclude = ["upstream"]\n'
PROBE_HEAD = '[package]\nname = "probe"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[dependencies]\n'
PROBE_SYMPHONIA = 'symphonia = { path = "../upstream/symphonia", default-features = false, features = ["aac", "alac", "vorbis", "pcm", "ogg", "isomp4"] }\n'
PROBE_OPUS = 'opus-pure = { path = "../upstream" }\n'
PLANT = (
    "\n// PLANTED by prepare_candidates.py: the control for the root `-F unsafe_code` lint. Not part of opus-pure.\n"
    "#[allow(dead_code)]\npub fn planted_unsafe_for_the_lint_control() -> u8 {\n    let x = 7u8;\n    unsafe { std::ptr::read(&x) }\n}\n"
)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def tree_digest(root):
    rows = []
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            rows.append("%s\0%s\n" % (os.path.relpath(p, root), "symlink:" + os.readlink(p) if os.path.islink(p) else sha(p)))
    h = hashlib.sha256()
    for row in sorted(rows):
        h.update(row.encode())
    return h.hexdigest(), len(rows)


def extract(archive, expect_sha, top, into):
    got = sha(archive)
    if got != expect_sha:
        sys.exit("archive %s has sha256 %s, expected %s" % (archive, got, expect_sha))
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(archive) as tar:
            tops = {m.name.split("/")[0] for m in tar.getmembers()}
            if tops != {top}:
                sys.exit("archive %s has top-level entries %s, expected only %s" % (archive, sorted(tops), top))
            tar.extractall(tmp, filter="data")
        shutil.copytree(os.path.join(tmp, top), into, symlinks=True)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "x", encoding="utf-8") as fh:
        fh.write(text)


def take_lock(locks_dir, name, expect, dest):
    src = os.path.join(locks_dir, name)
    got = sha(src)
    if got != expect:
        sys.exit("lock %s has sha256 %s, expected %s" % (src, got, expect))
    shutil.copyfile(src, dest)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archives-dir", required=True)
    ap.add_argument("--locks-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if os.path.exists(args.out):
        sys.exit("%s already exists; nothing is overwritten" % args.out)
    sym_top, sym_sha = ARCHIVES["symphonia"]
    opus_top, opus_sha = ARCHIVES["opus-pure"]
    sym_archive = os.path.join(args.archives_dir, sym_top + ".tar.gz")
    opus_archive = os.path.join(args.archives_dir, opus_top + ".tar.gz")
    os.makedirs(args.out)
    out = os.path.abspath(args.out)

    extract(sym_archive, sym_sha, sym_top, os.path.join(out, "symphonia-ws", "upstream"))
    write(os.path.join(out, "symphonia-ws", "Cargo.toml"), ROOT_MANIFEST)
    write(os.path.join(out, "symphonia-ws", "probe", "Cargo.toml"), PROBE_HEAD + PROBE_SYMPHONIA)
    write(os.path.join(out, "symphonia-ws", "probe", "src", "lib.rs"), "")
    take_lock(args.locks_dir, "symphonia-ws.Cargo.lock", LOCKS["symphonia-ws.Cargo.lock"], os.path.join(out, "symphonia-ws", "Cargo.lock"))

    extract(opus_archive, opus_sha, opus_top, os.path.join(out, "opus-ws", "upstream"))
    write(os.path.join(out, "opus-ws", "Cargo.toml"), ROOT_MANIFEST)
    write(os.path.join(out, "opus-ws", "probe", "Cargo.toml"), PROBE_HEAD + PROBE_OPUS)
    write(os.path.join(out, "opus-ws", "probe", "src", "lib.rs"), "")
    take_lock(args.locks_dir, "opus-ws.Cargo.lock", LOCKS["opus-ws.Cargo.lock"], os.path.join(out, "opus-ws", "Cargo.lock"))

    for name in ("opus-lint", "opus-lint-planted"):
        extract(opus_archive, opus_sha, opus_top, os.path.join(out, name))
        take_lock(args.locks_dir, "opus-pure.Cargo.lock", LOCKS["opus-pure.Cargo.lock"], os.path.join(out, name, "Cargo.lock"))
    with open(os.path.join(out, "opus-lint-planted", "src", "lib.rs"), "a", encoding="utf-8") as fh:
        fh.write(PLANT)

    for name in ("symphonia-ws", "opus-ws", "opus-lint", "opus-lint-planted"):
        digest, count = tree_digest(os.path.join(out, name))
        print("%-18s %5d files  tree sha256 %s  %s" % (name, count, digest, os.path.join(out, name)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
