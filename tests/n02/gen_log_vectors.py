#!/usr/bin/env python3
"""Generates crates/franken-control/tests/vectors/n02_log_vectors.json (bead ffw-ugf, JSONL diagnostics).

    python3 -B -I tests/n02/gen_log_vectors.py --check    fail if the file differs from this script's output
    python3 -B -I tests/n02/gen_log_vectors.py --write    rewrite it

The file pins two things the Rust diagnostics must reproduce, computed here with the standard library
and not with the code under test:

* the keyed pseudonyms: SHA-256 over "ffw.pseudonym.v1", the 32-byte key, the identifier's length as
  eight big-endian bytes, and the identifier; "p-" and the first sixteen hex characters. This is the
  construction the shared diagnostics sink uses, so a pseudonym agrees across both;
* four complete JSONL lines, assembled field by field below with `json.dumps` in the `ffw.log.v1`
  field order. The Rust test builds the same settled commands and must produce the same bytes;
* six complete JSONL lines for acknowledgements, the same way. The Rust builds each from the outcome
  named in the fact (so its vocabulary and arithmetic are checked), and must produce the same bytes.

The facts (what settled, when, and what the record should say) are written by hand here. Only the
pseudonyms are computed.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "crates" / "franken-control" / "tests" / "vectors" / "n02_log_vectors.json"

KEY = bytes([7]) * 32
IDS = ["ctl-a", "ctl-b", "kitchen", "nowhere", "grp", "tok-9f3a1c77e0b2", "sk-live-4e7d9a1c5b22"]
RUN, CASE = "run-1", "case-1"


def pseudonym(identifier):
    digest = hashlib.sha256(
        b"ffw.pseudonym.v1" + KEY + len(identifier.encode()).to_bytes(8, "big") + identifier.encode()
    ).hexdigest()
    return "p-" + digest[:16]


# (id, what, fact) where the fact is what the channel knew when the command settled.
FACTS = [
    ("N02-L001", "a committed command that names no member",
     {"peer": "ctl-a", "seq": 1, "member": None, "outcome": "committed", "revision": 3,
      "queue_depth": 3, "waited_ns": 2_000_000, "now_ns": 2_000_000, "epoch": 10, "group": "grp", "cause": None},
     "committed", "committed at revision 3"),
    ("N02-L002", "a refusal by the session for an unknown member: the member is pseudonymized, the cause is a word",
     {"peer": "ctl-b", "seq": 7, "member": "nowhere", "outcome": "refused_session", "revision": 4,
      "queue_depth": 0, "waited_ns": 2_000_000, "now_ns": 2_000_000, "epoch": 10, "group": "grp", "cause": "unknown_member"},
     "refused.session", "the session refused the command"),
    ("N02-L003", "a refusal for want of a live group lease: the cause is the session's own error code, lower-cased",
     {"peer": "ctl-a", "seq": 2, "member": None, "outcome": "refused_lease", "revision": 3,
      "queue_depth": 1, "waited_ns": 1_500_000, "now_ns": 9_000_000, "epoch": 11, "group": "grp", "cause": "stale_authority"},
     "refused.lease", "the group lease is not live"),
    ("N02-L004", "a command that expired in the queue: five seconds is five million microseconds",
     {"peer": "ctl-a", "seq": 9, "member": "kitchen", "outcome": "expired", "revision": 5,
      "queue_depth": 2, "waited_ns": 5_000_000_000, "now_ns": 5_000_000_000, "epoch": 10, "group": "grp", "cause": None},
     "refused.expired", "expired in the queue"),
]


# (id, what, fact, kind suffix, message). The fact names the acknowledgement outcome the channel reached
# and what it knew at that moment; the kind, the message, the cause and `age_ns` (the basis of latency_us)
# are what the record must say, written by hand.
ACK_FACTS = [
    ("N02-A001", "an on-time acknowledgement: one second after the outcome, correlated with the command",
     {"peer": "ctl-a", "seq": 1, "outcome": {"kind": "on_time", "age_ns": 1_000_000_000}, "revision": 3,
      "queue_depth": 0, "now_ns": 1_000_000_000, "epoch": 10, "group": "grp", "cause": None, "age_ns": 1_000_000_000},
     "on_time", "acknowledged 1000000 us after the outcome"),
    ("N02-A002", "a late acknowledgement: twelve seconds after, ten over a two second budget",
     {"peer": "ctl-a", "seq": 2, "outcome": {"kind": "late", "age_ns": 12_000_000_000, "over_by_ns": 10_000_000_000},
      "revision": 4, "queue_depth": 1, "now_ns": 12_000_000_000, "epoch": 10, "group": "grp", "cause": None,
      "age_ns": 12_000_000_000},
     "late", "acknowledged 10000000 us over the budget"),
    ("N02-A003", "an acknowledgement for a command issued under an epoch the group has left",
     {"peer": "ctl-b", "seq": 7, "outcome": {"kind": "superseded", "epoch": 10, "current": 11}, "revision": 6,
      "queue_depth": 0, "now_ns": 5_000_000_000, "epoch": 11, "group": "grp", "cause": None, "age_ns": 0},
     "superseded", "command issued under epoch 10, the group is at 11"),
    ("N02-A004", "an acknowledgement that did not authenticate: the claimed identifier is only a pseudonym, the cause is a word",
     {"peer": "tok-9f3a1c77e0b2", "seq": 4, "outcome": {"kind": "unauthenticated", "failure": "unknown_peer"},
      "revision": 5, "queue_depth": 2, "now_ns": 2_000_000_000, "epoch": 10, "group": "grp",
      "cause": "unknown_peer", "age_ns": 0},
     "rejected.unauthenticated", "did not authenticate"),
    ("N02-A005", "an acknowledgement for a command the ledger has forgotten",
     {"peer": "ctl-a", "seq": 2, "outcome": {"kind": "out_of_window", "floor": 2}, "revision": 5,
      "queue_depth": 0, "now_ns": 30_000_000_000, "epoch": 10, "group": "grp", "cause": None, "age_ns": 0},
     "rejected.out_of_window", "forgotten: at or below the remembered floor 2"),
    ("N02-A006", "an acknowledgement naming another epoch than the command was issued under",
     {"peer": "ctl-a", "seq": 3, "outcome": {"kind": "mismatch", "recorded_epoch": 10}, "revision": 5,
      "queue_depth": 0, "now_ns": 1_000_000_000, "epoch": 10, "group": "grp", "cause": None, "age_ns": 0},
     "rejected.mismatch", "the command was issued under epoch 10"),
]


def ack_line_for(fact, kind, message):
    record = {
        "schema_version": "ffw.log.v1",
        "timestamp_mono_ns": fact["now_ns"],
        "run_id": RUN,
        "case_id": CASE,
        "correlation_id": f"{pseudonym(fact['peer'])}#{fact['seq']}",
        "member_id": "",
        "group_id": pseudonym(fact["group"]),
        "source_epoch": fact["epoch"],
        "state_revision": fact["revision"],
        "event_kind": f"n02.ack.{kind}",
        "message": message,
        "queue_depth": fact["queue_depth"],
        "latency_us": fact["age_ns"] // 1000,
    }
    if fact["cause"]:
        record["cause"] = fact["cause"]
    return json.dumps(record, separators=(",", ":"))


def line_for(fact, kind, message):
    record = {
        "schema_version": "ffw.log.v1",
        "timestamp_mono_ns": fact["now_ns"],
        "run_id": RUN,
        "case_id": CASE,
        "correlation_id": f"{pseudonym(fact['peer'])}#{fact['seq']}",
        "member_id": pseudonym(fact["member"]) if fact["member"] else "",
        "group_id": pseudonym(fact["group"]),
        "source_epoch": fact["epoch"],
        "state_revision": fact["revision"],
        "event_kind": f"n02.step.{kind}",
        "message": message,
        "queue_depth": fact["queue_depth"],
        "latency_us": fact["waited_ns"] // 1000,
    }
    if fact["cause"]:
        record["cause"] = fact["cause"]
    return json.dumps(record, separators=(",", ":"))


def build():
    return {
        "schema": "ffw.n02.log-vectors.v1",
        "notes": [
            "Generated by tests/n02/gen_log_vectors.py: pseudonyms, the four golden lines and the six acknowledgement lines are computed with hashlib/json, not with the Rust under test.",
            "Replayed by crates/franken-control/src/channel/diag.rs (tests `pseudonyms_and_golden_lines_match_the_independent_vectors` and `acknowledgement_lines_match_the_independent_vectors`).",
            "The key is a test fixture, not a secret.",
        ],
        "run_id": RUN,
        "case_id": CASE,
        "pseudonym_key_hex": KEY.hex(),
        "pseudonyms": [{"id": i, "pseudonym": pseudonym(i)} for i in IDS],
        "golden_lines": [
            {"id": fid, "what": what, "fact": fact, "line": line_for(fact, kind, message)}
            for fid, what, fact, kind, message in FACTS
        ],
        "ack_golden_lines": [
            {"id": fid, "what": what, "fact": fact, "line": ack_line_for(fact, kind, message)}
            for fid, what, fact, kind, message in ACK_FACTS
        ],
    }


def render():
    return json.dumps(build(), indent=2) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    path = Path(args.out)
    text = render()
    if args.write:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
        return 0
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        print(f"{path} differs from the generator's output; run --write", file=sys.stderr)
        return 1
    print(f"N02 log vectors: PASS ({len(IDS)} pseudonyms, {len(FACTS)} golden lines, {len(ACK_FACTS)} acknowledgement lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
