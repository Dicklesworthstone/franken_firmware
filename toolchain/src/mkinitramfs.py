#!/usr/bin/env python3
"""Deterministic newc-format CPIO initramfs builder and independent verifier.

Spec: https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html

Repairs and invariants (E07 / ffw-ll1):
- Explicit (major, minor) tuple handling: never pass already-unpacked major numbers
  through os.major()/os.minor().
- Independent parser advances via aligned `dataoff = (off + 110 + namesize + 3) & ~3`
  followed by `off = dataoff + ((filesize + 3) & ~3)`, never by aligning the unpadded
  sum `110 + namesize + filesize`.
- Deterministic gzip output (`mtime=0`, empty filename header).
- No hardcoded personal paths; paths are passed explicitly or derived from
  `FFW_BUILD_DIR` / repository-relative `build/`.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
from typing import Any, Iterable

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFCHR = 0o020000
S_IFREG = 0o100000

NEWC_MAGIC = b"070701"
TRAILER_NAME = "TRAILER!!!"

DEFAULT_DEVICE_NODES: tuple[tuple[str, int, tuple[int, int]], ...] = (
    ("dev/console", S_IFCHR | 0o600, (5, 1)),
    ("dev/ttyS0", S_IFCHR | 0o600, (4, 64)),
    ("dev/ttyPZ0", S_IFCHR | 0o600, (204, 192)),
    ("dev/null", S_IFCHR | 0o666, (1, 3)),
    ("dev/zero", S_IFCHR | 0o666, (1, 5)),
    # P02's explicit legacy entropy provider opens this device, never urandom.
    # Making the node available neither seeds the pool nor changes that policy.
    ("dev/random", S_IFCHR | 0o600, (1, 8)),
    ("dev/urandom", S_IFCHR | 0o666, (1, 9)),
)

DEFAULT_DIRS: tuple[str, ...] = (".", "dev", "proc", "sys", "tmp")


def normalize_dev_tuple(dev: tuple[int, int] | None) -> tuple[int, int]:
    """Return explicit (rdevmajor, rdevminor) integers without os.major/os.minor corruption."""
    if dev is None:
        return (0, 0)
    if not isinstance(dev, tuple) or len(dev) != 2:
        raise ValueError(f"device specification must be a 2-tuple (major, minor), got {dev!r}")
    if any(type(value) is not int for value in dev):
        raise ValueError("device major/minor must be integers, not coerced values")
    maj, minr = dev
    if maj < 0 or minr < 0 or maj > 0xFFFFFFFF or minr > 0xFFFFFFFF:
        raise ValueError(f"device major/minor out of 32-bit range: {(maj, minr)!r}")
    return (maj, minr)


def encode_newc_entry(
    name: str,
    mode: int,
    data: bytes = b"",
    dev: tuple[int, int] | None = None,
    ino: int = 1,
    nlink: int | None = None,
) -> bytes:
    """Encode a single SVR4 newc (070701) CPIO entry with 4-byte header and data padding."""
    name_bytes = name.encode("utf-8") + b"\0"
    namesize = len(name_bytes)
    filesize = len(data)
    if nlink is None:
        nlink = 2 if (mode & S_IFMT) == S_IFDIR else 1
    rdevmaj, rdevmin = normalize_dev_tuple(dev)

    fields = [
        NEWC_MAGIC,
        f"{ino & 0xFFFFFFFF:08X}".encode("ascii"),
        f"{mode & 0xFFFFFFFF:08X}".encode("ascii"),
        b"00000000",  # uid
        b"00000000",  # gid
        f"{nlink & 0xFFFFFFFF:08X}".encode("ascii"),
        b"00000000",  # mtime (0 for deterministic output)
        f"{filesize & 0xFFFFFFFF:08X}".encode("ascii"),
        b"00000000",  # devmajor
        b"00000000",  # devminor
        f"{rdevmaj:08X}".encode("ascii"),
        f"{rdevmin:08X}".encode("ascii"),
        f"{namesize:08X}".encode("ascii"),
        b"00000000",  # check
    ]
    buf = io.BytesIO()
    buf.write(b"".join(fields))
    assert buf.tell() == 110
    buf.write(name_bytes)
    hdr_pad = (4 - (buf.tell() % 4)) % 4
    if hdr_pad:
        buf.write(b"\0" * hdr_pad)
    if data:
        buf.write(data)
        data_pad = (4 - (len(data) % 4)) % 4
        if data_pad:
            buf.write(b"\0" * data_pad)
    return buf.getvalue()


def build_cpio_bytes(
    init_bytes: bytes,
    extra_entries: Iterable[tuple[str, int, bytes, tuple[int, int] | None]] = (),
) -> bytes:
    """Build a complete uncompressed newc CPIO archive padded to a 512-byte boundary."""
    buf = io.BytesIO()
    ino = 300

    for dname in DEFAULT_DIRS:
        ino += 1
        buf.write(encode_newc_entry(dname, S_IFDIR | 0o755, ino=ino))

    for dev_name, dev_mode, dev_tuple in DEFAULT_DEVICE_NODES:
        ino += 1
        buf.write(encode_newc_entry(dev_name, dev_mode, dev=dev_tuple, ino=ino))

    ino += 1
    buf.write(encode_newc_entry("init", S_IFREG | 0o755, data=init_bytes, ino=ino))

    for name, mode, data, dev in extra_entries:
        ino += 1
        buf.write(encode_newc_entry(name, mode, data=data, dev=dev, ino=ino))

    buf.write(encode_newc_entry(TRAILER_NAME, 0, data=b"", dev=None, ino=0, nlink=1))
    tail_pad = (512 - (buf.tell() % 512)) % 512
    if tail_pad:
        buf.write(b"\0" * tail_pad)
    return buf.getvalue()


def compress_deterministic_gzip(raw_cpio: bytes) -> bytes:
    """Compress `raw_cpio` into deterministic gzip bytes (mtime=0, empty filename)."""
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, compresslevel=9, mtime=0) as gz:
        gz.write(raw_cpio)
    return out.getvalue()


def parse_cpio_bytes(raw: bytes) -> list[dict[str, Any]]:
    """Independently parse a raw newc CPIO archive and verify alignment/padding invariants."""
    entries: list[dict[str, Any]] = []
    off = 0
    saw_trailer = False
    seen_names: set[str] = set()

    while off < len(raw):
        if raw[off:] == b"\0" * len(raw[off:]):
            break
        if off + 110 > len(raw):
            raise ValueError(f"truncated CPIO header at offset {off}")
        magic = raw[off : off + 6]
        if magic != NEWC_MAGIC:
            raise ValueError(f"invalid CPIO magic at offset {off}: {magic!r}")
        try:
            fields = [
                int(raw[off + 6 + i * 8 : off + 14 + i * 8].decode("ascii"), 16)
                for i in range(13)
            ]
        except Exception as exc:
            raise ValueError(f"malformed hex header field at offset {off}") from exc

        (
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            filesize,
            devmajor,
            devminor,
            rdevmajor,
            rdevminor,
            namesize,
            check,
        ) = fields

        if namesize < 1:
            raise ValueError(f"invalid namesize {namesize} at offset {off}")
        name_end = off + 110 + namesize
        if name_end > len(raw):
            raise ValueError(f"truncated entry name at offset {off}")
        name_with_nul = raw[off + 110 : name_end]
        if name_with_nul[-1:] != b"\0":
            raise ValueError(f"entry name missing trailing NUL at offset {off}")
        if b"\0" in name_with_nul[:-1]:
            raise ValueError(f"embedded NUL in entry name at offset {off}")
        name = name_with_nul[:-1].decode("utf-8")
        if name in seen_names:
            raise ValueError(f"duplicate CPIO entry {name!r}")
        seen_names.add(name)
        if name != "." and (not name or name.startswith("/") or any(
            part in ("", ".", "..") for part in name.split("/")
        )):
            raise ValueError("noncanonical or escaping archive path")

        # Crucial invariant: align header+namesize first, then align filesize separately.
        dataoff = (name_end + 3) & ~3
        if raw[name_end:dataoff] != b"\0" * (dataoff - name_end):
            raise ValueError(f"non-zero header padding at offset {name_end}..{dataoff}")

        data_end = dataoff + filesize
        if data_end > len(raw):
            raise ValueError(f"truncated entry data for {name!r} at offset {dataoff}")
        data = raw[dataoff:data_end]

        next_off = dataoff + ((filesize + 3) & ~3)
        if next_off > len(raw):
            raise ValueError(f"truncated data padding for {name!r} at offset {data_end}")
        if raw[data_end:next_off] != b"\0" * (next_off - data_end):
            raise ValueError(f"non-zero data padding for {name!r} at offset {data_end}..{next_off}")

        entry = {
            "name": name,
            "ino": ino,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "nlink": nlink,
            "mtime": mtime,
            "filesize": filesize,
            "dev": (devmajor, devminor),
            "rdev": (rdevmajor, rdevminor),
            "namesize": namesize,
            "check": check,
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": data,
        }
        entries.append(entry)
        off = next_off

        if name == TRAILER_NAME:
            if filesize != 0:
                raise ValueError("TRAILER!!! must not contain data")
            saw_trailer = True
            if raw[off:] != b"\0" * len(raw[off:]):
                raise ValueError(f"non-zero bytes after TRAILER!!! at offset {off}")
            break

    if not saw_trailer:
        raise ValueError("missing TRAILER!!! entry in CPIO archive")
    return entries


def verify_initramfs_bytes(
    archive_bytes: bytes,
    expected_init_sha256: str | None = None,
    *,
    require_legacy_random: bool = False,
) -> dict[str, Any]:
    """Verify the archive, optionally requiring the selected legacy entropy device.

    Historical archives without that provider remain verifiable. When present,
    its node is always checked; new builds require it explicitly.
    """
    if archive_bytes[:2] == b"\x1f\x8b":
        raw = gzip.decompress(archive_bytes)
    else:
        raw = archive_bytes

    entries = parse_cpio_bytes(raw)
    by_name = {e["name"]: e for e in entries}

    if require_legacy_random and "dev/random" not in by_name:
        raise ValueError("missing required device node 'dev/random'")

    for required_dir in DEFAULT_DIRS:
        if required_dir not in by_name:
            raise ValueError(f"missing required directory {required_dir!r}")
        if (by_name[required_dir]["mode"] & S_IFMT) != S_IFDIR:
            raise ValueError(f"entry {required_dir!r} is not a directory")

    for dev_name, dev_mode, expected_rdev in DEFAULT_DEVICE_NODES:
        if dev_name not in by_name:
            if dev_name == "dev/random" and not require_legacy_random:
                continue
            raise ValueError(f"missing required device node {dev_name!r}")
        ent = by_name[dev_name]
        if ent["mode"] != dev_mode:
            raise ValueError(
                f"device {dev_name!r} mode mismatch: got {oct(ent['mode'])}, expected {oct(dev_mode)}"
            )
        if ent["rdev"] != expected_rdev:
            raise ValueError(
                f"device {dev_name!r} rdev mismatch: got {ent['rdev']}, expected {expected_rdev}"
            )

    if "init" not in by_name:
        raise ValueError("missing required 'init' executable")
    init_ent = by_name["init"]
    if init_ent["mode"] != (S_IFREG | 0o755):
        raise ValueError(f"unexpected init mode {oct(init_ent['mode'])}")
    if expected_init_sha256 is not None and init_ent["sha256"] != expected_init_sha256:
        raise ValueError(
            f"init sha256 mismatch: archive has {init_ent['sha256']}, expected {expected_init_sha256}"
        )

    return {
        "uncompressed_bytes": len(raw),
        "compressed_bytes": len(archive_bytes) if archive_bytes[:2] == b"\x1f\x8b" else None,
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "raw_cpio_sha256": hashlib.sha256(raw).hexdigest(),
        "init_sha256": init_ent["sha256"],
        "init_size": init_ent["filesize"],
        "entry_count": len(entries),
        "devices": {
            dev_name: {"mode": oct(by_name[dev_name]["mode"]), "rdev": list(by_name[dev_name]["rdev"])}
            for dev_name, _, _ in DEFAULT_DEVICE_NODES
            if dev_name in by_name
        },
    }


RESERVED_NAMES = frozenset({"init", TRAILER_NAME, *DEFAULT_DIRS, *(name for name, _, _ in DEFAULT_DEVICE_NODES)})


def check_extra_files(extra_files: Iterable[tuple[str, int, bytes]]) -> list[tuple[str, int, bytes]]:
    """Validate extra regular files for the archive: a plain relative name that does not collide with `init`, the
    standard directories or device nodes (or with another extra), and a regular-file mode."""
    checked: list[tuple[str, int, bytes]] = []
    seen: set[str] = set()
    for name, mode, data in extra_files:
        parts = name.split("/")
        if not name or name.startswith("/") or any(part in ("", ".", "..") for part in parts):
            raise ValueError(f"extra file name must be a plain relative path: {name!r}")
        if name in RESERVED_NAMES or name in seen:
            raise ValueError(f"extra file name collides with an existing archive entry: {name!r}")
        if (mode & S_IFMT) != S_IFREG:
            raise ValueError(f"extra file {name!r} must be a regular file mode, got {oct(mode)}")
        if not isinstance(data, bytes):
            raise ValueError(f"extra file {name!r} data must be bytes")
        seen.add(name)
        checked.append((name, mode, data))
    return checked


def verify_extra_files(archive_bytes: bytes, extra_files: Iterable[tuple[str, int, bytes]]) -> dict[str, Any]:
    """Parse the finished archive independently and confirm each extra file is present with the mode and bytes that
    were handed in. Returns name -> {mode, size, sha256} as read back from the archive."""
    raw = gzip.decompress(archive_bytes) if archive_bytes[:2] == b"\x1f\x8b" else archive_bytes
    by_name = {entry["name"]: entry for entry in parse_cpio_bytes(raw)}
    read_back: dict[str, Any] = {}
    for name, mode, data in extra_files:
        entry = by_name.get(name)
        if entry is None:
            raise ValueError(f"extra file {name!r} is missing from the archive")
        if entry["mode"] != mode:
            raise ValueError(f"extra file {name!r} mode mismatch: got {oct(entry['mode'])}, expected {oct(mode)}")
        if entry["data"] != data:
            raise ValueError(f"extra file {name!r} contents differ from what was packed")
        read_back[name] = {"mode": oct(entry["mode"]), "size": entry["filesize"], "sha256": entry["sha256"]}
    return read_back


def build(
    init_path: str | os.PathLike[str],
    out_path: str | os.PathLike[str],
    extra_files: Iterable[tuple[str, int, bytes]] = (),
) -> dict[str, Any]:
    """Build a deterministic `.cpio.gz` initramfs from `init_path` and verify it independently.

    `extra_files` are `(name, mode, bytes)` regular files packed after `init`.
    New archives always provide the legacy entropy device, including with no extra files."""
    init_p = pathlib.Path(init_path)
    out_p = pathlib.Path(out_path)
    if not init_p.is_file():
        raise FileNotFoundError(f"init binary does not exist: {init_p}")
    extras = check_extra_files(extra_files)
    init_bytes = init_p.read_bytes()
    init_sha256 = hashlib.sha256(init_bytes).hexdigest()

    raw_cpio = build_cpio_bytes(init_bytes, extra_entries=[(name, mode, data, None) for name, mode, data in extras])
    gz_bytes = compress_deterministic_gzip(raw_cpio)
    receipt = verify_initramfs_bytes(gz_bytes, expected_init_sha256=init_sha256,
                                     require_legacy_random=True)
    if extras:
        receipt["extra_files"] = verify_extra_files(gz_bytes, extras)

    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_bytes(gz_bytes)
    receipt["init_path"] = str(init_p)
    receipt["out_path"] = str(out_p)
    return receipt


def self_test() -> dict[str, Any]:
    """Run unit/property checks across all 16 (namesize % 4, filesize % 4) combinations and error paths."""
    modulo_cases = 0
    extra = []
    for name_mod in range(4):
        for data_mod in range(4):
            # Construct name of exact length modulo 4
            base = f"mod_{name_mod}_{data_mod}_"
            pad_len = (name_mod - (len(base) % 4)) % 4
            name = base + ("x" * pad_len)
            assert len(name) % 4 == name_mod
            data = bytes(((i * 37 + name_mod * 7 + data_mod) & 0xFF) for i in range(16 + data_mod))
            assert len(data) % 4 == data_mod
            extra.append((name, S_IFREG | 0o644, data, None))
            modulo_cases += 1

    fake_init = b"\x7fELF\x01\x02\x01\x00" + b"FFW_SYNTHETIC_INIT_PAYLOAD"
    expected_sha = hashlib.sha256(fake_init).hexdigest()
    raw = build_cpio_bytes(fake_init, extra_entries=extra)
    gz1 = compress_deterministic_gzip(raw)
    gz2 = compress_deterministic_gzip(raw)
    if gz1 != gz2:
        raise AssertionError("deterministic gzip produced non-identical outputs")

    receipt = verify_initramfs_bytes(gz1, expected_init_sha256=expected_sha)
    parsed = {e["name"]: e for e in parse_cpio_bytes(raw)}
    for name, _, data, _ in extra:
        if parsed[name]["data"] != data:
            raise AssertionError(f"payload corruption for modulo case {name}")

    # Negative oracle 1: corrupted device major/minor (simulating old os.major(5) -> (0, 5) bug)
    bad_dev_raw = raw.replace(
        encode_newc_entry("dev/console", S_IFCHR | 0o600, dev=(5, 1), ino=306),
        encode_newc_entry("dev/console", S_IFCHR | 0o600, dev=(0, 5), ino=306),
    )
    try:
        verify_initramfs_bytes(bad_dev_raw, expected_init_sha256=expected_sha)
        raise AssertionError("corrupted (0, 5) device node was not rejected")
    except ValueError:
        pass

    # Negative oracle 2: missing TRAILER!!!
    no_trailer = encode_newc_entry(".", S_IFDIR | 0o755, ino=1)
    try:
        parse_cpio_bytes(no_trailer)
        raise AssertionError("archive without TRAILER!!! was not rejected")
    except ValueError:
        pass

    # Negative oracle 3: wrong init sha256
    try:
        verify_initramfs_bytes(gz1, expected_init_sha256="0" * 64)
        raise AssertionError("mismatched init sha256 was not rejected")
    except ValueError:
        pass

    return {
        "status": "PASS",
        "modulo_4x4_cases": modulo_cases,
        "deterministic_gzip": True,
        "negative_oracles": ["bad_device_tuple_0_5", "missing_trailer", "init_sha256_mismatch"],
        "receipt": receipt,
    }


def resolve_default_build_dir(repo_root: pathlib.Path) -> pathlib.Path:
    env_dir = os.environ.get("FFW_BUILD_DIR")
    if env_dir:
        return pathlib.Path(env_dir)
    return repo_root / "build"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run internal 4x4 alignment and negative oracle suite")
    parser.add_argument("--init", type=str, help="Path to init ELF binary to package")
    parser.add_argument("--out", type=str, help="Output .cpio.gz path")
    parser.add_argument("--verify", type=str, help="Verify an existing .cpio or .cpio.gz archive")
    parser.add_argument("--require-legacy-random", action="store_true",
                        help="Require /dev/random when verifying a legacy-entropy archive")
    parser.add_argument("--expected-init-sha256", type=str, default=None, help="Expected SHA-256 of /init")
    parser.add_argument("--build-dir", type=str, default=None, help="Build root containing hello-init-target and initramfs/")
    args = parser.parse_args(argv)

    if args.self_test:
        res = self_test()
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.verify:
        data = pathlib.Path(args.verify).read_bytes()
        res = verify_initramfs_bytes(data, expected_init_sha256=args.expected_init_sha256,
                                    require_legacy_random=args.require_legacy_random)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.init and args.out:
        res = build(args.init, args.out)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    build_dir = pathlib.Path(args.build_dir) if args.build_dir else resolve_default_build_dir(repo_root)
    target_root = build_dir / "hello-init-target"
    out_root = build_dir / "initramfs"

    receipts = {}
    for arch, triple in (
        ("mips", "mips-unknown-linux-musl"),
        ("ppc", "powerpc-unknown-linux-musl"),
    ):
        binary = target_root / triple / "release" / "ffw-hello-init"
        out_path = out_root / f"initramfs-{arch}.cpio.gz"
        receipts[arch] = build(binary, out_path)

    print(json.dumps({"status": "PASS", "archives": receipts}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
