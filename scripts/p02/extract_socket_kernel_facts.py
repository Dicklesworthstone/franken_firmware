#!/usr/bin/env python3
"""Extract the kernel facts the P02 socket capability rests on, as VERBATIM SOURCE LINES with file, line number and checksum (docs/contracts/p02.md,
"The socket capability").  Stdlib only, offline.

    scripts/p02/extract_socket_kernel_facts.py --root DIR            print the evidence as JSON
    scripts/p02/extract_socket_kernel_facts.py --root DIR --out F    write it to F (refuses to overwrite)

DIR holds the kernel files as `DIR/<tag>/<path>` (for example `DIR/v2.6.27/net/socket.c`, from the stable tree at git.kernel.org, one file per
tag and path named in SPEC).  A file that is missing is an error, not a guess; a rule that matches nothing records nothing (the tests say what must be there).  The committed result is `tests/p02/socket_kernel_evidence.json`;
`tests/p02/test_socket_slice.py` derives every kernel fact it checks from those lines (it does not hold them as typed literals), and runs this
extractor over a small synthetic tree to show that it records what it says.

Each file yields `entries` (a matching line: its 1-based number and text, minus the newline) and `absent` (a candidate pattern that matched
NOTHING in the file, which is how "this kernel has no accept4" is recorded).  Kinds of rule:
  lines     every line matching the pattern
  o32       the same, but only inside the o32 section of a MIPS `unistd.h` (the file also holds the n32 and n64 numbers)
  block     from the first line matching the pattern to the first later line containing `};` (an initializer table)
"""
import argparse
import hashlib
import json
import os
import re
import sys

SCHEMA = "ffw.p02.socket-kernel-evidence.v1"
O32_START = "#if _MIPS_SIM == _MIPS_SIM_ABI32"
O32_END = "#endif /* _MIPS_SIM == _MIPS_SIM_ABI32 */"

NET_H = [("subcalls", "lines", r"^#define\s+SYS_[A-Z0-9_]+\s+\d+")]
NET_H_ABSENT = [("accept4", r"\bSYS_ACCEPT4\b"), ("paccept", r"\bSYS_PACCEPT\b")]
SOCKET_C = [
    ("bound", "lines", r"\bcall\s*<\s*1\s*\|\|\s*call\s*>\s*SYS_[A-Z0-9_]+"),
    ("nargs", "block", r"\bnargs\[\d*\]\s*="),
    ("accept", "lines", r"(case SYS_(?:PACCEPT|ACCEPT4):|sys_accept4\(a0|sys_paccept\(a0|SYSCALL_DEFINE4\(accept4|asmlinkage long sys_(?:accept4|paccept)\()"),
    ("socket_flags", "lines", r"(type\s*>=\s*SOCK_MAX|flags\s*=\s*type\s*&\s*~SOCK_TYPE_MASK)"),
    ("listen", "lines", r"(SYSCALL_DEFINE2\(listen,|asmlinkage long sys_listen\()"),
]
SOCKET_C_ABSENT = [("accept4", r"sys_accept4|SYSCALL_DEFINE4\(accept4"), ("paccept", r"sys_paccept")]

SPEC = [
    ("v2.6.14", "include/asm-mips/unistd.h", [("mips_o32", "o32", r"^#define\s+__NR_(?:listen|accept4|recv|accept)\s")], [("accept4", r"__NR_accept4")]),
    ("v2.6.14", "include/asm-ppc/unistd.h", [("socketcall", "lines", r"^#define\s+__NR_socketcall\s")], [("listen", r"__NR_listen"), ("accept4", r"__NR_accept4")]),
    ("v2.6.14", "include/linux/net.h", NET_H, NET_H_ABSENT),
    ("v2.6.14", "net/socket.c", SOCKET_C, SOCKET_C_ABSENT),
    ("v2.6.26", "include/linux/net.h", NET_H, NET_H_ABSENT),
    ("v2.6.26", "net/socket.c", SOCKET_C, SOCKET_C_ABSENT),
    ("v2.6.27", "include/linux/net.h", NET_H, NET_H_ABSENT),
    ("v2.6.27", "net/socket.c", SOCKET_C, SOCKET_C_ABSENT),
    ("v2.6.28", "include/linux/net.h", NET_H, NET_H_ABSENT),
    ("v2.6.28", "net/socket.c", SOCKET_C, SOCKET_C_ABSENT),
    ("v2.6.35", "arch/mips/include/asm/unistd.h", [("mips_o32", "o32", r"^#define\s+__NR_(?:listen|accept4|recv|accept)\s")], [("accept4", r"__NR_accept4")]),
    ("v2.6.35", "arch/mips/kernel/scall32-o32.S", [("o32_table", "lines", r"^\s*sys\s+sys_(?:listen|accept4|recv|socketcall|socket|bind)\s+\d+")], []),
    ("v2.6.35", "arch/powerpc/include/asm/systbl.h", [("socketcall", "lines", r"\bsocketcall\b")], [("listen", r"\blisten\b"), ("accept4", r"\baccept4\b")]),
    ("v2.6.35", "arch/powerpc/include/asm/unistd.h", [("socketcall", "lines", r"^#define\s+__NR_socketcall\s")], [("listen", r"__NR_listen"), ("accept4", r"__NR_accept4")]),
    ("v2.6.35", "include/linux/net.h", NET_H, NET_H_ABSENT),
    ("v2.6.35", "net/socket.c", SOCKET_C, SOCKET_C_ABSENT),
]


def sha16(data):
    return hashlib.sha256(data).hexdigest()[:16]


def rule_entries(kind, pattern, lines):
    regex = re.compile(pattern)
    if kind == "o32":
        try:
            start = next(i for i, ln in enumerate(lines) if ln.startswith(O32_START))
            end = next(i for i in range(start, len(lines)) if lines[i].startswith(O32_END))
        except StopIteration:
            raise SystemExit("no o32 section in a MIPS unistd.h")
        return [(i + 1, lines[i]) for i in range(start, end) if regex.search(lines[i])]
    if kind == "block":
        start = next((i for i, ln in enumerate(lines) if regex.search(ln)), None)
        if start is None:
            return []
        end = next(i for i in range(start, len(lines)) if "};" in lines[i])
        return [(i + 1, lines[i]) for i in range(start, end + 1)]
    return [(i + 1, ln) for i, ln in enumerate(lines) if regex.search(ln)]


def extract(root, spec=None):
    files = []
    for tag, path, rules, absent_candidates in (SPEC if spec is None else spec):
        full = os.path.join(root, tag, path)
        if not os.path.isfile(full):
            raise SystemExit("missing kernel file: %s" % full)
        with open(full, "rb") as fh:
            data = fh.read()
        lines = data.decode("utf-8", errors="replace").splitlines()
        entries = []
        for label, kind, pattern in rules:
            found = rule_entries(kind, pattern, lines)        # a rule may find nothing (an old kernel has no accept4); the tests say what must be there
            entries += [{"label": label, "line": number, "text": text} for number, text in found]
        absent = [{"label": label, "pattern": pattern} for label, pattern in absent_candidates if not any(re.search(pattern, ln) for ln in lines)]
        files.append({"tag": tag, "path": path, "sha256_16": sha16(data), "entries": entries, "absent": absent})
    return {"schema": SCHEMA, "files": files}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    text = json.dumps(extract(args.root), indent=1) + "\n"
    if args.out:
        if os.path.exists(args.out):
            raise SystemExit(args.out + " exists; nothing is overwritten")
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote", args.out)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
