#!/usr/bin/env python3
"""Generates the `auth_vectors` and `tamper_vectors` sections of the N02 golden file (bead ffw-ugf).

    python3 -B -I tests/n02/gen_auth_vectors.py --check    fail if the file's two sections differ from this script's output
    python3 -B -I tests/n02/gen_auth_vectors.py --write    rewrite those two sections in place

What is generated, and what is not. The HMAC tags are computed with the standard library's `hmac`
over the context label and the signed bytes of the hand-derived `signing_vectors`; the tamper list is
defined once, below. The signing vectors themselves and every scenario expectation are hand-written
and are never touched here: a generator that wrote its own expectations could only agree with itself.

Before anything is written, each tamper is checked for the properties the Rust replay relies on:
* the Rust `RequestBody::new` would build it (`reference.malformed`), so the replay reaches the tag
  check and not a constructor error;
* it changes exactly one signed field of its base request, and the signed bytes differ;
* the base request's tag does not verify under it.
"""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as ref  # noqa: E402

START_MARK = '  "auth_vectors": ['
END_MARK = '  "scenarios": ['

# (field, base auth vector, peer, seq, epoch, rev, cmd). Each differs from its base in one signed field.
ADJ = {"kind": "adjust_member_volume", "member": "kitchen", "delta": -5}
TAMPERS = [
    ("peer", "N02-A001", "ctl-b", 7, 3, 12, ADJ),
    ("seq", "N02-A001", "ctl-a", 8, 3, 12, ADJ),
    ("epoch", "N02-A001", "ctl-a", 7, 4, 12, ADJ),
    ("expected revision value", "N02-A001", "ctl-a", 7, 3, 13, ADJ),
    # Presence is tampered on an absolute command: a relative one cannot be built without a revision.
    ("expected revision presence", "N02-A005", "ctl-a", 1, 10, None, {"kind": "set_group_volume", "volume": 100}),
    ("member", "N02-A001", "ctl-a", 7, 3, 12, {**ADJ, "member": "den"}),
    ("delta", "N02-A001", "ctl-a", 7, 3, 12, {**ADJ, "delta": 5}),
    # Same payload byte (0x64), different tag byte: only the command kind changes.
    ("command kind", "N02-A005", "ctl-a", 1, 10, 2, {"kind": "adjust_group_volume", "delta": 100}),
    ("stop now_ns", "N02-A002", "panel", 1, 10, None, {"kind": "stop", "now_ns": 257, "tail_ns": 65535}),
    ("stop tail_ns", "N02-A002", "panel", 1, 10, None, {"kind": "stop", "now_ns": 256, "tail_ns": 65534}),
    ("cancel target_seq", "N02-A003", "ctl-b", 300, 11, None, {"kind": "cancel", "target_seq": 298}),
    ("mute flag", "N02-A004", "panel", 2, 0, None, {"kind": "set_member_mute", "member": "den", "muted": False}),
    # A revision of zero is present; the signed bytes must tell it from none.
    ("expected revision zero versus absent", "N02-A002", "panel", 1, 10, 0, {"kind": "stop", "now_ns": 256, "tail_ns": 65535}),
]


def key_for(peer):
    return f"key-{peer}-0123456789abcdef"


def logical_fields(peer, seq, epoch, rev, cmd):
    """The signed fields of a request as a dict. A change of command kind counts as one field: the
    payload of a different kind has no meaningful field-by-field comparison."""
    fields = {"peer": peer, "seq": seq, "epoch": epoch, "rev": rev, "kind": cmd["kind"]}
    return fields, {k: v for k, v in cmd.items() if k != "kind"}


def changed_fields(base, other):
    a, a_params = logical_fields(*base)
    b, b_params = logical_fields(*other)
    changed = {k for k in a if a[k] != b[k]}
    if "kind" not in changed:
        changed |= {k for k in set(a_params) | set(b_params) if a_params.get(k) != b_params.get(k)}
    return changed


def build(doc):
    """The two sections as (text, problems)."""
    problems = []
    signing = {v["id"]: v for v in doc["signing_vectors"]}
    auth_lines, auth = [], {}
    for n, vector in enumerate(doc["signing_vectors"], 1):
        aid = f"N02-A{n:03d}"
        key = key_for(vector["peer"])
        tag = hmac.new(key.encode("ascii"), ref.AUTH_CONTEXT + bytes.fromhex(vector["hex"]), hashlib.sha256).hexdigest()
        auth[aid] = {"signing": vector, "tag": tag, "key": key}
        auth_lines.append(
            f'    {{"id": "{aid}", "signing_vector": "{vector["id"]}", "key": "{key}", "tag_hex": "{tag}"}}'
        )
    tamper_lines = []
    for n, (field, base_id, peer, seq, epoch, rev, cmd) in enumerate(TAMPERS, 1):
        tid = f"N02-T{n:03d}"
        base = auth[base_id]["signing"]
        why = ref.malformed(seq, rev, cmd)
        if why:
            problems.append(f"{tid} ({field}): the Rust body constructor would refuse it: {why}")
        base_req = (base["peer"], base["seq"], base["epoch"], base["rev"], base["cmd"])
        changed = changed_fields(base_req, (peer, seq, epoch, rev, cmd))
        if len(changed) != 1:
            problems.append(f"{tid} ({field}): changes {sorted(changed) or 'nothing'}, not exactly one signed field")
        request = {"peer": peer, "seq": seq, "epoch": epoch, "rev": rev, "cmd": cmd}
        if ref.request_bytes(request) == bytes.fromhex(base["hex"]):
            problems.append(f"{tid} ({field}): the signed bytes do not change")
        claimed_key = key_for(peer).encode("ascii")
        if hmac.compare_digest(ref.proof(claimed_key, ref.request_bytes(request)), bytes.fromhex(auth[base_id]["tag"])):
            problems.append(f"{tid} ({field}): the base tag still verifies")
        revs = "null" if rev is None else str(rev)
        tamper_lines.append(
            f'    {{"id": "{tid}", "auth_vector": "{base_id}", "field": "{field}", "peer": "{peer}", '
            f'"seq": {seq}, "epoch": {epoch}, "rev": {revs}, "cmd": {json.dumps(cmd)}}}'
        )
    text = (
        '  "auth_vectors": [\n' + ",\n".join(auth_lines) + "\n  ],\n"
        '  "tamper_vectors": [\n' + ",\n".join(tamper_lines) + "\n  ],\n"
    )
    return text, problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--vectors", default=str(ref.DEFAULT_VECTORS))
    args = parser.parse_args(argv)
    path = Path(args.vectors)
    current = path.read_text(encoding="utf-8")
    doc = json.loads(current)
    text, problems = build(doc)
    for line in problems:
        print("PROBLEM", line, file=sys.stderr)
    if problems:
        return 1
    start, end = current.index(START_MARK), current.index(END_MARK)
    if args.write:
        path.write_text(current[:start] + text + current[end:], encoding="utf-8")
        print(f"wrote {len(doc['signing_vectors'])} auth vectors and {len(TAMPERS)} tampers to {path}")
        return 0
    if current[start:end] != text:
        print("the auth_vectors/tamper_vectors sections differ from the generator's output; run --write", file=sys.stderr)
        return 1
    print(f"N02 generated vectors: PASS ({len(doc['signing_vectors'])} auth vectors, {len(TAMPERS)} tampers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
