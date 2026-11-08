#!/usr/bin/env python3
"""P05 AC-3: map the frozen native196 test names to the Asupersync source that defines them (git objects only; read-only).

    native196_map.py CLONE REV [--names native196_names.txt] [--out native196_targets.tsv]

For each name `a::b::tests::c::leaf` this walks the module path from `src/lib.rs` (honouring `#[path]`, inline `mod x { }` blocks and
the `mod x;` file rules), finds the `#[test]` fn, and writes one row: name, package, test target, feature graph, defined_at
(`file:line`), the chain of `mod` declarations that links the file, and every `cfg(...)` attribute met on the way. A feature-gated
test therefore cannot hide in a "default" row. It also lists, for every filter prefix (`...::tests::`), the `#[test]` fns the
source defines under it, so a substring filter that would select more (or fewer) than the registry is visible.

Nothing here runs a compiler. The table is source evidence for which cargo target owns a name; it is not execution evidence.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
ATTR = r"(?:#\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)"
ATTRS = rf"((?:{ATTR})*)"


def git_show(clone: str, rev: str, path: str):
    out = subprocess.run(["git", "-C", clone, "show", f"{rev}:{path}"], capture_output=True)
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def blank(text: str, strings: bool) -> str:
    """Blank comments (and string/char literal contents when `strings`), keeping length and newlines."""
    out, i, n = [], 0, len(text)
    while i < n:
        c, two = text[i], text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text[j:j + 2] == "/*":
                    depth, j = depth + 1, j + 2
                elif text[j:j + 2] == "*/":
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            seg = text[i:j]
            out.append("".join(ch if ch == "\n" else " " for ch in seg) if strings else seg)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


class Src:
    def __init__(self, path: str, text: str):
        self.path = path
        self.raw = text
        self.c = blank(text, strings=False)   # comments blanked, strings kept (attribute values)
        self.b = blank(text, strings=True)    # both blanked (structure)
        self.spans = self._mod_spans()

    def line(self, pos: int) -> int:
        return self.raw.count("\n", 0, pos) + 1

    def _mod_spans(self):
        spans, stack, depth = [], [], 0
        for m in re.finditer(r"\bmod\s+(\w+)\s*\{|\{|\}", self.b):
            tok = m.group(0)
            if tok == "}":
                depth -= 1
                if stack and stack[-1][1] == depth:
                    name, _d, start = stack.pop()
                    spans.append((name, start, m.end()))
            elif tok == "{":
                depth += 1
            else:
                stack.append((m.group(1), depth, m.start()))
                depth += 1
        return spans

    def enclosing(self, pos: int):
        return [s for s in sorted(self.spans, key=lambda s: s[1]) if s[1] <= pos < s[2]]


def is_modrs(path: str) -> bool:
    return PurePosixPath(path).name in ("mod.rs", "lib.rs", "main.rs")


def child_candidates(path: str, inline: list, name: str, path_attr):
    p = PurePosixPath(path)
    base = p.parent if is_modrs(path) else p.parent / p.stem
    if path_attr is not None:
        target = base.joinpath(*inline, path_attr) if inline else p.parent / path_attr
        return [str(PurePosixPath(*[x for x in target.parts if x != "."]))]
    sub = base.joinpath(*inline) if inline else base
    return [str(sub / f"{name}.rs"), str(sub / name / "mod.rs")]


def cfgs(attrs: str):
    return re.findall(r"#\[(cfg(?:_attr)?\((?:[^\[\]]|\[[^\]]*\])*\))\]", attrs)


def resolve(clone, rev, cache, comps):
    """Walk `comps` (a module path, no leaf) from src/lib.rs. Returns (src, inline, range, chain, gates) or an error string."""
    def load(path):
        if path not in cache:
            text = git_show(clone, rev, path)
            cache[path] = Src(path, text) if text is not None else None
        return cache[path]

    cur = load("src/lib.rs")
    if cur is None:
        return "src/lib.rs is not in the revision"
    inline, rng, chain, gates = [], (0, len(cur.raw)), [], []
    for comp in comps:
        pat = re.compile(rf"{ATTRS}(?:pub(?:\([^)]*\))?\s+)?mod\s+{re.escape(comp)}\s*(;|\{{)")
        m = pat.search(cur.c, rng[0], rng[1])
        if m is None:
            return f"no `mod {comp}` in {cur.path}"
        attrs = m.group(1)
        gates += cfgs(attrs)
        chain.append(f"{cur.path}:{cur.line(m.start())} mod {comp}")
        if m.group(2) == "{":
            spans = [s for s in cur.spans if s[0] == comp and s[1] <= m.end() - 1 < s[2]]
            if not spans:
                return f"unbalanced inline mod {comp} in {cur.path}"
            rng = (m.end(), min(spans, key=lambda s: s[2] - s[1])[2])
            inline = inline + [comp]
        else:
            pa = re.search(r'#\[path\s*=\s*"([^"]+)"\]', attrs)
            nxt = None
            for cand in child_candidates(cur.path, inline, comp, pa.group(1) if pa else None):
                nxt = load(cand)
                if nxt is not None:
                    break
            if nxt is None:
                return f"`mod {comp};` in {cur.path}:{cur.line(m.start())} resolves to no file"
            cur, inline, rng = nxt, [], (0, len(nxt.raw))
    return cur, inline, rng, chain, gates


def tests_in(src: Src, rng):
    """(fn name, line, inline mods below `rng`, attrs) for every test-attributed fn inside the range."""
    out = []
    for m in re.finditer(rf"{ATTRS}(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]", src.c[rng[0]:rng[1]]):
        attrs = m.group(1)
        if not re.search(r"#\[(?:[\w:]*::)?test(?:\b|\()", attrs):
            continue
        pos = rng[0] + m.start(2)
        mods = [s[0] for s in src.enclosing(pos) if s[1] >= rng[0] and s[2] <= rng[1] and (s[1], s[2]) != rng]
        out.append((m.group(2), src.line(pos), mods, attrs))
    return out


def build(clone: str, rev: str, names: list):
    cache: dict = {}
    rows, problems = [], []
    groups = defaultdict(lambda: {"registry": set(), "source": None})
    for name in names:
        comps = name.split("::")
        mod = comps[:-1]
        res = resolve(clone, rev, cache, mod)
        if isinstance(res, str):
            problems.append(f"{name}: {res}")
            continue
        src, _inline, rng, chain, gates = res
        hits = [t for t in tests_in(src, rng) if t[0] == comps[-1]]
        if len(hits) != 1:
            problems.append(f"{name}: {len(hits)} test fn(s) named {comps[-1]} in {src.path}")
            continue
        _fn, line, _mods, attrs = hits[0]
        every_cfg = gates + cfgs(attrs)
        feats = sorted(set(re.findall(r'feature\s*=\s*"([^"]+)"', " ".join(every_cfg))))
        rows.append((name, "asupersync", "lib", ",".join(feats) or "default", f"{src.path}:{line}", " > ".join(chain),
                     " ".join(every_cfg)))
        base_mod = mod[:mod.index("tests") + 1] if "tests" in mod else mod
        pref = "::".join(base_mod) + "::"
        groups[pref]["registry"].add(name)
        if groups[pref]["source"] is None:
            groups[pref]["source"] = set()
            r2 = resolve(clone, rev, cache, base_mod)
            if not isinstance(r2, str):
                s2, _i, rng2, _c, _g = r2
                for fname, _l, mods, _a in tests_in(s2, rng2):
                    groups[pref]["source"].add("::".join(base_mod + mods + [fname]))
    return rows, problems, groups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("clone")
    ap.add_argument("rev")
    ap.add_argument("--names", type=Path, default=HERE / "native196_names.txt")
    ap.add_argument("--out", type=Path, default=HERE / "native196_targets.tsv")
    args = ap.parse_args()
    names = [line.strip() for line in args.names.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows, problems, groups = build(args.clone, args.rev, names)
    with args.out.open("x", encoding="utf-8") as handle:     # never overwrites an existing table
        handle.write("# name\tpackage\ttarget\tfeatures\tdefined_at\tlinked_by\tcfg_attrs\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")
    print(f"mapped {len(rows)} of {len(names)} names at {args.rev}; {len(problems)} problem(s)")
    for p in problems:
        print("  PROBLEM", p)
    print("filter prefix: registry / defined in source under it / source-only (a substring filter would also run these) / registry-only")
    bad = len(problems)
    for pref in sorted(groups):
        reg, src = groups[pref]["registry"], groups[pref]["source"] or set()
        extra, missing = sorted(src - reg), sorted(reg - src)
        bad += len(extra) + len(missing)
        print(f"  {pref} {len(reg)} / {len(src)} / {len(extra)} / {len(missing)}")
        for e in extra[:5]:
            print("     source-only:", e)
        for e in missing[:5]:
            print("     registry-only:", e)
    print("targets:", sorted({r[2] for r in rows}), "feature graphs:", sorted({r[3] for r in rows}))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
