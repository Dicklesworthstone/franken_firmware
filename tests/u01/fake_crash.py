#!/usr/bin/env python3
"""A Python stand-in for the `journal_crash` example, used ONLY to test the e2e driver's logic before the Rust example has
been built centrally. It runs the Python reference journal over a real file and dies (os.abort, no cleanup) in the middle
of the write or erase that crosses the byte budget, like the example does. It is not evidence about the Rust code."""
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import reference as ref  # noqa: E402
import scenarios as sc  # noqa: E402


class FileMedia(ref.Media):
    def __init__(self, path, die_after=None):
        super().__init__(ref.TINY.segment_bytes)
        self.path, self.die_after, self.written = path, die_after, 0

    def _file(self):
        return open(self.path, "r+b", buffering=0)

    def read(self, offset, length):
        with self._file() as f:
            f.seek(offset)
            return f.read(length)

    def _put(self, offset, data):
        keep = len(data)
        dying = self.die_after is not None and self.written + len(data) > self.die_after
        if dying:
            keep = max(0, self.die_after - self.written)
        with self._file() as f:
            f.seek(offset)
            f.write(data[:keep])
        self.written += keep
        if dying:
            os.abort()

    def program(self, offset, data):
        current = self.read(offset, len(data))
        if any(b & ~c & 0xFF for b, c in zip(data, current)):
            raise ref.StorageFault("bits_cannot_rise")
        self._put(offset, bytes(data))

    def erase(self, index):
        self._put(index * self.seg, bytes([0xFF]) * self.seg)

    def sync(self):
        with self._file() as f:
            os.fsync(f.fileno())


def main(argv):
    cmd = argv[0]
    if cmd == "init":
        with open(argv[1], "xb") as f:
            f.write(bytes([0xFF]) * (2 * ref.TINY.segment_bytes))
        return 0
    if cmd == "dump":
        journal, rec = ref.Journal.open(FileMedia(argv[1]), ref.TINY)
        print("state", ref.state_hex(journal.state))
        print("source", rec.source)
        return 0
    if cmd == "run":
        import json
        die = int(argv[argv.index("--die-after-bytes") + 1]) if "--die-after-bytes" in argv else None
        with open(argv[2], encoding="utf-8") as f:
            script = next(s for s in json.load(f)["scripts"] if s["id"] == argv[3])
        journal, _rec = ref.Journal.open(FileMedia(argv[1], die), ref.TINY)
        print("opened", flush=True)
        for i, doc in enumerate(script["steps"], start=1):
            step = sc.step_from_json(doc)
            try:
                getattr(journal, step[0])(*step[1:])
            except ref.JournalError as err:
                if err.code in ("storage", "poisoned"):
                    return 3
            print("ack", i, flush=True)
        print("done", flush=True)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
