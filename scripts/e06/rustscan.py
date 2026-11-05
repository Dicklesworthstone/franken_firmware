#!/usr/bin/env python3
"""Lexical facts about Rust source for the E06 dependency audit (bead ffw-unk).  Stdlib only, offline.

Why a lexer and not a regex: counting the word ``unsafe`` in raw text finds it inside comments, doc
examples and string literals (false positives) and, with a cleverer strip, still misjudges raw strings,
nested block comments, lifetimes versus character literals and tuple indexes like ``x.0.1`` (which a
naive number rule reads as a float).  This tokenizer handles those, so the facts below come from code
tokens only.  It is NOT a parser: it does not expand macros or ``cfg`` gates, so

* unsafe code produced by a procedural macro or ``macro_rules!`` expansion is invisible here (the
  macro's own body is scanned if it is in the scanned sources);
* ``unsafe`` under a ``cfg`` that is off for the target is still counted (conservative);
* module files outside the scanned directory (``#[path]``) are not followed.

Everything returned is a fact about tokens, never an admission decision.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

__all__ = ["Tok", "tokenize", "SourceFacts", "scan_source", "BuildScriptSignals", "scan_build_script",
           "parse_cfg", "eval_cfg", "cfg_text", "CfgExpr"]

_IDENT = re.compile(r"[^\W\d]\w*")
_RAW_OR_PREFIXED_STR = re.compile(r'(?:(?P<raw>[bc]?r)(?P<hashes>#*)"|(?P<pre>[bc])")')
_HEX_OCT_BIN = re.compile(r"0[xX][0-9a-fA-F_]+(?:[iu](?:8|16|32|64|128|size))?"
                          r"|0[oO][0-7_]+(?:[iu](?:8|16|32|64|128|size))?"
                          r"|0[bB][01_]+(?:[iu](?:8|16|32|64|128|size))?")
_DECIMAL = re.compile(r"[0-9][0-9_]*(?:\.(?![.A-Za-z_])[0-9_]*)?(?:[eE][+-]?[0-9_]+)?"
                      r"(?:[iu](?:8|16|32|64|128|size)|f32|f64)?")
_INT_ONLY = re.compile(r"[0-9][0-9_]*(?:[iu](?:8|16|32|64|128|size))?")


@dataclass(frozen=True)
class Tok:
    kind: str          # ident | str | char | lifetime | num | punct
    text: str          # for str: the literal body without quotes (escapes untouched)
    line: int
    is_float: bool = False


def tokenize(src: str) -> List[Tok]:
    """Code tokens of ``src``; comments and whitespace are dropped, literals are single tokens."""
    toks: List[Tok] = []
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    line += src[j] == "\n"
                    j += 1
            i = j
            continue
        m = _RAW_OR_PREFIXED_STR.match(src, i)
        if m is not None and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            start = m.end()
            if m.group("raw"):
                closer = '"' + m.group("hashes")
                end = src.find(closer, start)
                end = n if end < 0 else end
                body, i2 = src[start:end], min(n, end + len(closer))
            else:
                j = start
                while j < n and src[j] != '"':
                    j += 2 if src[j] == "\\" else 1
                body, i2 = src[start:j], min(n, j + 1)
            toks.append(Tok("str", body, line))
            line += body.count("\n")
            i = i2
            continue
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            body = src[i + 1:j]
            toks.append(Tok("str", body, line))
            line += body.count("\n")
            i = min(n, j + 1)
            continue
        if c == "b" and src.startswith("b'", i):
            c, i = "'", i + 1          # byte character literal: fall into the char rule below
        if c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = i + 3
                while j < n and src[j] != "'":
                    j += 1
                toks.append(Tok("char", src[i + 1:j], line))
                i = min(n, j + 1)
            elif i + 2 < n and src[i + 2] == "'":
                toks.append(Tok("char", src[i + 1], line))
                i += 3
            else:
                m = _IDENT.match(src, i + 1)
                if m is not None:
                    toks.append(Tok("lifetime", m.group(0), line))
                    i = m.end()
                else:
                    toks.append(Tok("punct", "'", line))
                    i += 1
            continue
        if c.isdigit():
            prev_dot = bool(toks) and toks[-1].kind == "punct" and toks[-1].text == "."
            m = _INT_ONLY.match(src, i) if prev_dot else (_HEX_OCT_BIN.match(src, i) or _DECIMAL.match(src, i))
            text = m.group(0)
            hexlike = text[:2].lower() in ("0x", "0o", "0b")
            is_float = (not hexlike) and (("." in text) or bool(re.search(r"[eE][+-]?[0-9]", text))
                                          or text.endswith(("f32", "f64")))
            toks.append(Tok("num", text, line, is_float))
            i = m.end()
            continue
        if c == "r" and src.startswith("r#", i) and i + 2 < n and (src[i + 2].isalpha() or src[i + 2] == "_"):
            m = _IDENT.match(src, i + 2)
            toks.append(Tok("ident", "r#" + m.group(0), line))      # a raw identifier is a NAME, never a keyword
            i = m.end()
            continue
        m = _IDENT.match(src, i)
        if m is not None:
            toks.append(Tok("ident", m.group(0), line))
            i = m.end()
            continue
        toks.append(Tok("punct", c, line))
        i += 1
    return toks


# ------------------------------------------------------------------------------------------------ cfg

CfgExpr = Tuple  # ("flag", name) | ("kv", key, value) | ("not", e) | ("all", [e]) | ("any", [e])


def parse_cfg(toks: Sequence[Tok], pos: int = 0) -> Tuple[Optional[CfgExpr], int]:
    """Parse one cfg predicate from ``toks[pos:]``; returns (expr or None, next position)."""
    if pos >= len(toks) or toks[pos].kind != "ident":
        return None, pos
    name = toks[pos].text
    pos += 1
    if pos < len(toks) and toks[pos].text == "=" and pos + 1 < len(toks) and toks[pos + 1].kind == "str":
        return ("kv", name, toks[pos + 1].text), pos + 2
    if pos < len(toks) and toks[pos].text == "(" and name in ("all", "any", "not"):
        pos += 1
        items: List[CfgExpr] = []
        while pos < len(toks) and toks[pos].text != ")":
            expr, pos = parse_cfg(toks, pos)
            if expr is None:
                return None, pos
            items.append(expr)
            if pos < len(toks) and toks[pos].text == ",":
                pos += 1
        pos += 1
        if name == "not":
            return (("not", items[0]), pos) if len(items) == 1 else (None, pos)
        return (name, items), pos
    return ("flag", name), pos


# Predicates a plain library build decides.  Everything else (target_os, panic, ...) is unknown here, on
# purpose: this audit does not evaluate target cfgs itself, cargo does (see audit.py).
_KNOWN_FLAGS = {"test": False, "docsrs": False, "miri": False, "doc": False}


def eval_cfg(expr: Optional[CfgExpr], features: Set[str]) -> Optional[bool]:
    """Three-valued: True, False, or None when the answer depends on something not modelled."""
    if expr is None:
        return None
    kind = expr[0]
    if kind == "flag":
        return _KNOWN_FLAGS.get(expr[1])
    if kind == "kv":
        return (expr[2] in features) if expr[1] == "feature" else None
    if kind == "not":
        inner = eval_cfg(expr[1], features)
        return None if inner is None else (not inner)
    values = [eval_cfg(e, features) for e in expr[1]]
    if kind == "all":
        return False if False in values else (None if None in values else True)
    return True if True in values else (None if None in values else False)       # any


def cfg_text(expr: Optional[CfgExpr]) -> str:
    if expr is None:
        return "?"
    kind = expr[0]
    if kind == "flag":
        return expr[1]
    if kind == "kv":
        return '%s = "%s"' % (expr[1], expr[2])
    if kind == "not":
        return "not(%s)" % cfg_text(expr[1])
    return "%s(%s)" % (kind, ", ".join(cfg_text(e) for e in expr[1]))


# ------------------------------------------------------------------------------------------------ facts

@dataclass
class SourceFacts:
    unsafe_lines: List[int] = field(default_factory=list)       # one entry per `unsafe` keyword token
    uses_float: bool = False                                    # f32/f64 token or a float literal
    uses_alloc: bool = False                                    # `extern crate alloc` or an `alloc::` path
    # crate-level inner attributes (brace depth 0 only), as facts:
    no_std: bool = False                                        # unconditional #![no_std]
    cfg_no_std: List[CfgExpr] = field(default_factory=list)     # predicates of #![cfg_attr(PRED, ..no_std..)]
    lints: List[Tuple[str, str, Optional[CfgExpr]]] = field(default_factory=list)   # (level, lint, cfg or None)
    # every `extern crate std`, with the #[cfg(..)] gate stacked directly above it (None = unconditional).  A
    # #![no_std] crate that re-enables std under a feature (thiserror, serde_json, memchr) links std when that
    # gate holds, so #![no_std] alone does not make a crate no_std for the features cargo enabled.
    extern_std: List[Optional[CfgExpr]] = field(default_factory=list)
    tokens: int = 0


def _split_commas(toks: Sequence[Tok]) -> List[List[Tok]]:
    parts: List[List[Tok]] = [[]]
    depth = 0
    for t in toks:
        if t.kind == "punct" and t.text in "([{":
            depth += 1
        elif t.kind == "punct" and t.text in ")]}":
            depth -= 1
        if depth == 0 and t.kind == "punct" and t.text == ",":
            parts.append([])
        else:
            parts[-1].append(t)
    return [p for p in parts if p]


def _lints_of(attr: Sequence[Tok], cond: Optional[CfgExpr]) -> List[Tuple[str, str, Optional[CfgExpr]]]:
    """`forbid(unsafe_code, other)` -> [("forbid", "unsafe_code", cond), ("forbid", "other", cond)]."""
    if not attr or attr[0].kind != "ident" or attr[0].text not in ("forbid", "deny", "warn", "allow", "expect"):
        return []
    inner = list(attr[2:-1]) if len(attr) > 3 and attr[1].text == "(" and attr[-1].text == ")" else []
    names: List[str] = []
    for part in _split_commas(inner):
        names.append("::".join(t.text for t in part if t.kind == "ident"))
    return [(attr[0].text, nm, cond) for nm in names if nm]


def _inner_attributes(toks: Sequence[Tok], facts: SourceFacts) -> None:
    depth, i, n = 0, 0, len(toks)
    while i < n:
        t = toks[i]
        if t.kind == "punct" and t.text == "{":
            depth += 1
        elif t.kind == "punct" and t.text == "}":
            depth -= 1
        elif (depth == 0 and t.text == "#" and i + 2 < n and toks[i + 1].text == "!" and toks[i + 2].text == "["):
            j, bracket = i + 3, 1
            while j < n and bracket:
                bracket += (toks[j].text == "[") - (toks[j].text == "]") if toks[j].kind == "punct" else 0
                j += 1
            attr = toks[i + 3:j - 1]
            i = j
            if len(attr) == 1 and attr[0].text == "no_std":
                facts.no_std = True
            elif attr and attr[0].text == "cfg_attr" and len(attr) > 3:
                parts = _split_commas(attr[2:-1])
                cond, _ = parse_cfg(parts[0]) if parts else (None, 0)
                for sub in parts[1:]:
                    if len(sub) == 1 and sub[0].text == "no_std":
                        facts.cfg_no_std.append(cond if cond is not None else ("flag", "?"))
                    facts.lints.extend(_lints_of(sub, cond if cond is not None else ("flag", "?")))
            else:
                facts.lints.extend(_lints_of(attr, None))
            continue
        i += 1


def _cfg_above(toks: Sequence[Tok], idx: int) -> Optional[CfgExpr]:
    """The conjunction of the ``#[cfg(..)]`` outer attributes stacked directly above the item at ``idx``
    (other attributes such as ``#[macro_use]`` are skipped); None when there is no cfg gate."""
    gates: List[CfgExpr] = []
    j = idx - 1
    while j >= 0 and toks[j].kind == "punct" and toks[j].text == "]":
        depth, k = 1, j - 1
        while k >= 0 and depth:
            if toks[k].kind == "punct":
                depth += (toks[k].text == "]") - (toks[k].text == "[")
            k -= 1
        start = k + 1                                       # the "[" of this attribute
        if start < 1 or toks[start - 1].text != "#":
            break
        attr = toks[start + 1:j]
        if len(attr) > 3 and attr[0].text == "cfg" and attr[1].text == "(":
            expr, _ = parse_cfg(attr[2:-1])
            gates.append(expr if expr is not None else ("flag", "?"))
        j = start - 2
    if not gates:
        return None
    gates.reverse()                                         # collected bottom-up; report in source order
    return gates[0] if len(gates) == 1 else ("all", gates)


def scan_source(src: str) -> SourceFacts:
    """Facts from one Rust source text.  ``unsafe`` is the keyword token only: ``unsafe_code`` (the lint
    name), strings and comments never count."""
    toks = tokenize(src)
    facts = SourceFacts(tokens=len(toks))
    for k, t in enumerate(toks):
        if t.kind == "ident":
            if t.text == "unsafe":
                facts.unsafe_lines.append(t.line)
            elif t.text in ("f32", "f64"):
                facts.uses_float = True
            elif t.text == "alloc" and k + 1 < len(toks) and toks[k + 1].text == ":":
                facts.uses_alloc = True
            elif (t.text == "crate" and k >= 1 and toks[k - 1].text == "extern" and k + 1 < len(toks)
                  and toks[k + 1].text == "alloc"):
                facts.uses_alloc = True
            elif (t.text == "crate" and k >= 1 and toks[k - 1].text == "extern" and k + 1 < len(toks)
                  and toks[k + 1].text == "std"):
                facts.extern_std.append(_cfg_above(toks, k - 1))
        elif t.kind == "num" and t.is_float:
            facts.uses_float = True
    _inner_attributes(toks, facts)
    return facts


# ------------------------------------------------------------------------------------------------ build.rs

@dataclass
class BuildScriptSignals:
    link_directives: List[str] = field(default_factory=list)    # rustc-link-lib / -search / -arg markers
    spawns_process: bool = False                                # Command / process::Command identifier
    native_tooling: List[str] = field(default_factory=list)     # cc, cmake, pkg_config, bindgen, vcpkg paths


_LINK_MARKERS = ("rustc-link-lib", "rustc-link-search", "rustc-link-arg", "rustc-cdylib-link-arg")
_TOOLING = ("cc", "cmake", "pkg_config", "bindgen", "vcpkg", "autocfg")


def scan_build_script(src: str) -> BuildScriptSignals:
    """Signals that a build script reaches native code.  Presence of a build script alone is NOT such a
    signal (most only probe the compiler).  ``autocfg`` is listed so the report can say a script probes the
    compiler by compiling snippets; it is not native code."""
    toks = tokenize(src)
    sig = BuildScriptSignals()
    for k, t in enumerate(toks):
        if t.kind == "str":
            for marker in _LINK_MARKERS:
                if marker in t.text and marker not in sig.link_directives:
                    sig.link_directives.append(marker)
        elif t.kind == "ident":
            if t.text == "Command":
                sig.spawns_process = True
            is_path = k + 2 < len(toks) and toks[k + 1].text == ":" and toks[k + 2].text == ":"
            if t.text in _TOOLING and is_path and t.text not in sig.native_tooling:
                sig.native_tooling.append(t.text)
    return sig
