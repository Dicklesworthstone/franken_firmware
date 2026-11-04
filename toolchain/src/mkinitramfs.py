#!/usr/bin/env python3
"""Build newc-format cpio initramfs archives (gzip) with a /dev/console node,
no root required. Spec: https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html
Verified against macOS cpio -it and Linux kernel unpacker.
"""
import io, gzip, os, sys

S_IFDIR, S_IFCHR, S_IFREG = 0o040000, 0o020000, 0o100000

def build(init_path: str, out_path: str):
    buf = io.BytesIO()
    ino = 300

    def ent(name, mode, typ, data=b'', dev=None):
        nonlocal ino
        ino += 1
        nlink = 2 if typ == b'd' else 1
        filesize = len(data)
        devmaj, devmin = (os.major(dev[0]), os.minor(dev[0])) if dev else (0, 0)
        # newc magic + 13 hex fields: ino mode uid gid nlink mtime filesize
        # devmajor(dev encoded hi/lo pair uses two fields) rdevmajor rdevminor
        # namesize check
        # Linux expects: ino mode uid gid nlink mtime filesize devmajor
        #                devminor rdevmajor rdevminor namesize check
        # where for device nodes rdevmajor/rdevminor carry the numbers.
        fields = [
            b'070701',
            f'{ino:08X}'.encode(), f'{mode:08X}'.encode(), f'{0:08X}'.encode(), f'{0:08X}'.encode(),
            f'{nlink:08X}'.encode(), f'{0:08X}'.encode(), f'{filesize:08X}'.encode(),
            f'{0:08X}'.encode(), f'{0:08X}'.encode(),          # devmajor, devminor (of the fs)
            f'{devmaj:08X}'.encode(), f'{devmin:08X}'.encode(),  # rdevmajor, rdevminor
            f'{len(name) + 1:08X}'.encode(), f'{0:08X}'.encode(),
        ]
        buf.write(b''.join(fields))
        name_b = name.encode() + b'\0'
        buf.write(name_b)
        pad = (4 - buf.tell() % 4) % 4
        if pad:
            buf.write(b'\0' * pad)
        if data:
            buf.write(data)
            pad = (4 - len(data) % 4) % 4
            if pad:
                buf.write(b'\0' * pad)

    ent('.', S_IFDIR | 0o755, b'd')
    ent('dev', S_IFDIR | 0o755, b'd')
    ent('dev/console', S_IFCHR | 0o600, b'c', dev=(5, 1))
    ent('dev/ttyS0', S_IFCHR | 0o600, b'c', dev=(4, 64))
    ent('init', S_IFREG | 0o755, b'f', data=open(init_path, 'rb').read())
    # trailer: magic + 13 zero fields, then name
    buf.write(b'070701' + b'0' * 88 + b'0000000B' + b'00000000' + b'TRAILER!!!\0')
    pad = (512 - buf.tell() % 512) % 512
    if pad:
        buf.write(b'\0' * pad)
    with gzip.open(out_path, 'wb') as f:
        f.write(buf.getvalue())
    print(f"wrote {out_path} ({buf.tell()} bytes uncompressed)")

if __name__ == '__main__':
    import subprocess, tempfile

    def append_entry(archive_path, name, mode, typ, dev=None, data=b''):
        """Append one newc entry + trailer to an existing raw cpio archive."""
        buf = io.BytesIO()
        # single entry with fresh inode
        devmaj, devmin = (os.major(dev[0]), os.minor(dev[0])) if dev else (0, 0)
        fields = [
            b'070701',
            f'{999:08X}'.encode(), f'{mode:08X}'.encode(), b'00000000', b'00000000',
            b'00000001', b'00000000', f'{len(data):08X}'.encode(),
            b'00000000', b'00000000',
            f'{devmaj:08X}'.encode(), f'{devmin:08X}'.encode(),
            f'{len(name) + 1:08X}'.encode(), b'00000000',
        ]
        buf.write(b''.join(fields))
        name_b = name.encode() + b'\0'
        buf.write(name_b)
        pad = (4 - buf.tell() % 4) % 4
        if pad:
            buf.write(b'\0' * pad)
        if data:
            buf.write(data)
            pad = (4 - len(data) % 4) % 4
            if pad:
                buf.write(b'\0' * pad)
        buf.write(b'070701' + b'0' * 88 + b'0000000B' + b'00000000' + b'TRAILER!!!\0')
        pad = (512 - buf.tell() % 512) % 512
        if pad:
            buf.write(b'\0' * pad)
        with open(archive_path, 'ab') as f:
            f.write(buf.getvalue())

    def build_findcpio(init_path, out_path):
        """macOS find|cpio (kernel-clean) + appended dev/console entry."""
        import shutil, tempfile
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(init_path, os.path.join(td, 'init'))
            os.chmod(os.path.join(td, 'init'), 0o755)
            # cpio from the tree (includes trailer)
            raw = subprocess.run(
                f'cd "{td}" && find . | cpio -o -H newc 2>/dev/null',
                shell=True, capture_output=True).stdout
            # strip the trailer block (last entry) — find|cpio's trailer +
            # padding, then append our dev/console + fresh trailer
            # Simpler: keep both trailers; kernel stops at first trailer,
            # so dev/console must come BEFORE the first trailer. Rebuild:
            # extract entries except trailer is hard; instead write our own
            # whole archive using the reference header style (mimic ref
            # exactly: namesize includes NUL, dev numbers in rdev fields).
            open(out_path + '.raw', 'wb').write(raw)
        return open(out_path + '.raw', 'rb').read()

    for arch, binary in [
        ('mips', '/Volumes/trj-data/franken_firmware_build/hello-init-target/mips-unknown-linux-musl/release/ffw-hello-init'),
        ('ppc', '/Volumes/trj-data/franken_firmware_build/hello-init-target/powerpc-unknown-linux-musl/release/ffw-hello-init'),
    ]:
        # Build tree archive with find|cpio, then INSERT dev/console before
        # the trailer by rebuilding: parse find|cpio output, drop trailer,
        # re-emit + our dev/console entry + trailer.
        raw = build_findcpio(binary, f'/tmp/ir-{arch}')
        entries = []
        d = raw
        off = 0
        while d[off:off+6] == b'070701':
            f = [int(d[off+6+i*8: off+14+i*8], 16) for i in range(13)]
            namesz = f[11]
            name = d[off+110: off+110+namesz-1].decode()
            if name == 'TRAILER!!!':
                break
            filesize = f[6]
            dataoff = (off + 110 + namesz + 3) & ~3
            data = d[dataoff: dataoff + filesize]
            rdevmaj, rdevmin = f[9], f[10]
            entries.append((name, f[1], data, (rdevmaj, rdevmin) if (f[1] & 0o170000) == 0o020000 else None))
            advance = (110 + namesz + filesize + 3) & ~3
            off += advance
        if not any(e[0] == 'dev/console' for e in entries):
            entries.append(('dev', S_IFDIR | 0o755, b'', None))
            entries.append(('dev/console', S_IFCHR | 0o600, b'', (5, 1)))
        # re-emit all entries with a fresh writer
        out = io.BytesIO()
        ino = 300
        for (name, mode, data, dev) in entries:
            ino += 1
            nlink = 2 if (mode & 0o170000) == S_IFDIR else 1
            devmaj, devmin = (os.major(dev[0]), os.minor(dev[0])) if dev else (0, 0)
            fields = [
                b'070701',
                f'{ino:08X}'.encode(), f'{mode:08X}'.encode(), b'00000000', b'00000000',
                f'{nlink:08X}'.encode(), b'00000000', f'{len(data):08X}'.encode(),
                b'00000000', b'00000000',
                f'{devmaj:08X}'.encode(), f'{devmin:08X}'.encode(),
                f'{len(name) + 1:08X}'.encode(), b'00000000',
            ]
            out.write(b''.join(fields))
            name_b = name.encode() + b'\0'
            out.write(name_b)
            pad = (4 - out.tell() % 4) % 4
            if pad:
                out.write(b'\0' * pad)
            if data:
                out.write(data)
                pad = (4 - len(data) % 4) % 4
                if pad:
                    out.write(b'\0' * pad)
        out.write(b'070701' + b'0' * 88 + b'0000000B' + b'00000000' + b'TRAILER!!!\0')
        pad = (512 - out.tell() % 512) % 512
        if pad:
            out.write(b'\0' * pad)
        out_path = f'/Volumes/trj-data/franken_firmware_build/initramfs/initramfs-{arch}-v2.cpio.gz'
        with gzip.open(out_path, 'wb') as gf:
            gf.write(out.getvalue())
        print(f"wrote {out_path} ({out.tell()} bytes, {len(entries)} entries)")
