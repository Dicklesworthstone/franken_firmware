"""Mutation canary for U01. With a green baseline, break one rule of reference.py at a time (in a temporary copy) and
require the battery to fail. A mutant the battery survives means a rule nothing checks. Exit 0 only if all are caught."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from typing import List, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
FILES = ("reference.py", "scenarios.py", "images.py", "battery.py")

MUTANTS: List[Tuple[str, str, str]] = [
    ("frame checksum unchecked", 'if zlib.crc32(fh[:8] + payload) != crc:', "if False:"),
    ("header checksum unchecked", ' or struct.unpack(">I", head[12:16])[0] != zlib.crc32(head[:12])', ""),
    ("frame sequence unchecked", " or fseq != seq", ""),
    ("hostile length reaches the medium", " or length > cap or off + FRAME_HEADER + length > seg", ""),
    ("first frame need not be a snapshot", "if (frames == 0) != (kind == KIND_SNAPSHOT):", "if False:"),
    ("append is not synced", "frame)\n            self._io(self.media.sync)\n            self.bytes_programmed += len(frame)",
     "frame)\n            self.bytes_programmed += len(frame)"),
    ("compaction does not sync", "        self._io(self.media.program, base + SEG_HEADER, frame)\n        self._io(self.media.sync)\n",
     "        self._io(self.media.program, base + SEG_HEADER, frame)\n"),
    ("target segment is not erased", "if not _blank(self._io(self.media.read, target * seg, seg)):", "if False:"),
    ("state published before the write", "        frame = encode_frame(KIND_TXN, self.next_seq, payload)\n",
     "        frame = encode_frame(KIND_TXN, self.next_seq, payload)\n        self.state = trial\n"),
    ("a failed storage operation does not poison", "            self.poisoned = True\n            raise JournalError(\"storage\"",
     "            raise JournalError(\"storage\""),
    ("snapshot drops tombstones", 'ops.append(("install", key, value[1], value[2]) if value[0] == "live" else ("tomb", key, value[1]))',
     'ops.append(("install", key, value[1], value[2])) if value[0] == "live" else None'),
    ("a revoked identity returns at its old version",
     "if current is not None and version <= current[1]:\n            raise JournalError(\"revoked\" if current[0] == \"revoked\" else \"not_newer\", current=current[1])",
     "if current is not None and current[0] == \"live\" and version <= current[1]:\n            raise JournalError(\"not_newer\", current=current[1])"),
    ("a replacement need not be newer", "raise JournalError(\"revoked\" if current[0] == \"revoked\" else \"not_newer\", current=current[1])",
     "raise JournalError(\"revoked\", current=current[1]) if current[0] == \"revoked\" else None"),
    ("a reset clears every blob namespace", "        state[ns].clear()", "        [state[n].clear() for n in BLOB_NAMESPACES]"),
    ("a pairing reset forgets the tombstones", 'state[NS_CREDENTIALS][ident] = ("revoked", current[1])\n    elif tag == "raise":',
     'del state[NS_CREDENTIALS][ident]\n    elif tag == "raise":'),
    ("a mark may go down", "if current is not None and value < current:", "if False:"),
    ("an unchanged commit is written", '        if canonical(trial) == canonical(self.state):\n            return "noop"\n', ""),
    ("the flush interval is ignored", "if self.last_flush is not None and now < self.last_flush + self.lim.min_flush_interval_ticks:", "if False:"),
    ("the wear budget is ignored", "if self.gen + 1 > self.lim.max_segment_gen or self.next_seq >= MAX_SEQ:", "if False:"),
    ("the stale segment is never retired", "        self.pending_retire = old_active\n", ""),
    ("a dirty tail is appended after", 'if best["tail_dirty"] or best["version"] != FORMAT_VERSION:', 'if best["version"] != FORMAT_VERSION:'),
    ("an unsupported schema is read anyway", "raise JournalError(\"unsupported_version\", version=s[\"version\"])", "pass"),
    ("a legacy install gets version 0", "version = r.u64() if schema >= 1 else 1", "version = r.u64() if schema >= 1 else 0"),
    ("a legacy image is not migrated", 'if best["version"] != FORMAT_VERSION:\n                rec.migrated_from = best["version"]\n            j._compact(j.state)',
     'if best["version"] != FORMAT_VERSION:\n                rec.migrated_from = best["version"]\n            if best["tail_dirty"]:\n                j._compact(j.state)'),
    ("an error carries the key", 'raise JournalError("invalid_key", ns=ns)', 'raise JournalError("invalid_key", ns=ns, key=key)'),
    ("an oversized transaction is written", 'if len(payload) > self.lim.max_txn_payload:\n            raise JournalError("txn_too_large")', "pass"),
    ("a full namespace accepts a new key", "if key not in state[ns] and len(state[ns]) >= lim.entries(ns):", "if False:"),
    ("an unrecoverable medium is not reported", '"blank" if blank else "unrecoverable"', '"blank"'),
]


def run_battery(directory: str) -> Tuple[int, str]:
    proc = subprocess.run([sys.executable, "-B", os.path.join(directory, "battery.py")], cwd=directory, capture_output=True,
                          text=True, timeout=300)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="u01-mutants-") as tmp:
        for name in FILES:
            shutil.copy(os.path.join(HERE, name), os.path.join(tmp, name))
        code, out = run_battery(tmp)
        print("baseline:", "green" if code == 0 else "NOT GREEN")
        if code != 0:
            print(out)
            return 2
        source = open(os.path.join(HERE, "reference.py"), encoding="utf-8").read()
        missed = []
        for name, old, new in MUTANTS:
            if source.count(old) != 1:
                print(f"BAD   {name}: the target text occurs {source.count(old)} times")
                missed.append(name)
                continue
            with open(os.path.join(tmp, "reference.py"), "w", encoding="utf-8") as f:
                f.write(source.replace(old, new))
            code, out = run_battery(tmp)
            fails = [line.split(":")[0].replace("FAIL ", "") for line in out.splitlines() if line.startswith("FAIL")]
            if code == 0:
                print(f"MISSED {name}")
                missed.append(name)
            else:
                print(f"caught {name}  [{', '.join(fails) or 'crashed'}]")
        print(f"mutants: {len(MUTANTS) - len(missed)} caught, {len(missed)} missed")
        return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
