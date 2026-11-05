"""U01 (ffw-mgb) reference: the crash-consistent state journal, written from docs/contracts/u01.md.

This is an independent implementation of the on-media format, the publication state machine, the bounded scanner, the
recovery rules and the namespace semantics, plus the fault-injecting media model and the cut-point oracle. The Rust crate
`franken-journal` implements the same specification; `tests/u01/make_vectors.py` writes the shared vectors both replay.
Stdlib only. Nothing here touches a filesystem or a device.

Byte order is big-endian everywhere. A checksum is CRC-32/IEEE (zlib.crc32). A byte is `0xFF` when erased; programming can
only clear bits (1 -> 0); erasing is per segment.
"""
from __future__ import annotations

import copy
import hashlib
import struct
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

ERASED = 0xFF
FRAME_MAGIC = 0xA5
KIND_TXN, KIND_SNAPSHOT = 1, 2
SEG_HEADER, FRAME_HEADER = 16, 12
FORMAT_VERSION = 1
LEGACY_VERSION = 0
NS_SETTINGS, NS_CREDENTIALS, NS_CALIBRATION, NS_RECORDS, NS_MARKS = 1, 2, 3, 4, 5
BLOB_NAMESPACES = (NS_SETTINGS, NS_CALIBRATION, NS_RECORDS)
NS_ORDER = (NS_SETTINGS, NS_CREDENTIALS, NS_CALIBRATION, NS_RECORDS, NS_MARKS)
T_PUT, T_DELETE, T_RESET, T_INSTALL, T_REVOKE, T_RESET_PAIRING, T_RAISE, T_TOMB = 1, 2, 3, 4, 5, 6, 7, 8
MAX_SEQ = 0xFFFF_FFFF


class JournalError(Exception):
    """A rejected operation or a refused recovery. `code` is the stable name; the message never carries a key or a value."""

    def __init__(self, code: str, **detail: Any) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class StorageFault(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Limits:
    """Per-namespace bounds and the journal's bounds. `key_max`, `value_max`, `entries` are keyed by namespace id."""

    def __init__(self, segment_bytes: int, max_txn_payload: int, settings: Tuple[int, int, int],
                 calibration: Tuple[int, int, int], records: Tuple[int, int, int], credentials: Tuple[int, int, int],
                 marks: Tuple[int, int, int], min_flush_interval_ticks: int, max_segment_gen: int) -> None:
        self.segment_bytes = segment_bytes
        self.max_txn_payload = max_txn_payload
        self.ns = {NS_SETTINGS: settings, NS_CALIBRATION: calibration, NS_RECORDS: records,
                   NS_CREDENTIALS: credentials, NS_MARKS: marks}  # (key_max, value_max, entries)
        self.min_flush_interval_ticks = min_flush_interval_ticks
        self.max_segment_gen = max_segment_gen

    def key_max(self, ns: int) -> int:
        return self.ns[ns][0]

    def value_max(self, ns: int) -> int:
        return self.ns[ns][1]

    def entries(self, ns: int) -> int:
        return self.ns[ns][2]

    def worst_snapshot_payload(self) -> int:
        total = 2
        for ns in BLOB_NAMESPACES:
            key_max, value_max, entries = self.ns[ns]
            total += entries * (1 + 1 + 1 + key_max + 2 + value_max)
        key_max, value_max, entries = self.ns[NS_CREDENTIALS]
        total += entries * (1 + 1 + key_max + 8 + 2 + value_max)  # a live identity is the larger of live and revoked
        key_max, _value_max, entries = self.ns[NS_MARKS]
        total += entries * (1 + 1 + key_max + 8)
        return total

    def validate(self) -> None:
        need = SEG_HEADER + FRAME_HEADER + self.worst_snapshot_payload() + FRAME_HEADER + self.max_txn_payload
        if need > self.segment_bytes:
            raise JournalError("bad_config", need=need, segment_bytes=self.segment_bytes)
        for ns in BLOB_NAMESPACES:
            key_max, value_max, entries = self.ns[ns]
            if self.max_txn_payload < 2 + 3 + key_max + 2 + value_max:
                raise JournalError("bad_config", what="txn cap below one operation")
        if self.max_segment_gen < 2:
            raise JournalError("bad_config", what="wear budget")


STANDARD = Limits(8192, 1024, settings=(16, 32, 16), calibration=(32, 256, 4), records=(32, 256, 4),
                  credentials=(32, 128, 16), marks=(16, 8, 8), min_flush_interval_ticks=1000,
                  max_segment_gen=200_000)
TINY = Limits(512, 128, settings=(8, 16, 2), calibration=(8, 32, 1), records=(8, 32, 1), credentials=(8, 16, 3),
              marks=(8, 8, 1), min_flush_interval_ticks=10, max_segment_gen=1_000)


# --------------------------------------------------------------------------- state and operations

def empty_state() -> Dict[str, Any]:
    return {NS_SETTINGS: {}, NS_CREDENTIALS: {}, NS_CALIBRATION: {}, NS_RECORDS: {}, NS_MARKS: {}}


def check_key(lim: Limits, ns: int, key: bytes) -> None:
    if not 1 <= len(key) <= lim.key_max(ns):
        raise JournalError("invalid_key", ns=ns)


def check_value(lim: Limits, ns: int, value: bytes) -> None:
    if len(value) > lim.value_max(ns):
        raise JournalError("value_too_long", ns=ns)


def apply_op(lim: Limits, state: Dict[str, Any], op: Tuple, snapshot: bool = False) -> None:
    """Apply one operation to `state` in place, or raise JournalError. The caller applies to a copy: a transaction is
    all-or-nothing."""
    tag = op[0]
    if tag == "put":
        _tag, ns, key, value = op
        if ns not in BLOB_NAMESPACES:
            raise JournalError("bad_op")
        check_key(lim, ns, key)
        check_value(lim, ns, value)
        if key not in state[ns] and len(state[ns]) >= lim.entries(ns):
            raise JournalError("namespace_full", ns=ns)
        state[ns][key] = value
    elif tag == "delete":
        _tag, ns, key = op
        if ns not in BLOB_NAMESPACES:
            raise JournalError("bad_op")
        check_key(lim, ns, key)
        if key not in state[ns]:
            raise JournalError("not_found", ns=ns)
        del state[ns][key]
    elif tag == "reset":
        _tag, ns = op
        if ns not in BLOB_NAMESPACES:
            raise JournalError("bad_op")
        state[ns].clear()
    elif tag == "install":
        _tag, ident, version, secret = op
        check_key(lim, NS_CREDENTIALS, ident)
        check_value(lim, NS_CREDENTIALS, secret)
        if not 1 <= version < 2 ** 64:
            raise JournalError("bad_version")
        current = state[NS_CREDENTIALS].get(ident)
        if current is not None and version <= current[1]:
            raise JournalError("revoked" if current[0] == "revoked" else "not_newer", current=current[1])
        if current is None and len(state[NS_CREDENTIALS]) >= lim.entries(NS_CREDENTIALS):
            raise JournalError("namespace_full", ns=NS_CREDENTIALS)
        state[NS_CREDENTIALS][ident] = ("live", version, secret)
    elif tag == "revoke":
        _tag, ident = op
        check_key(lim, NS_CREDENTIALS, ident)
        current = state[NS_CREDENTIALS].get(ident)
        if current is None:
            raise JournalError("not_found", ns=NS_CREDENTIALS)
        if current[0] == "revoked":
            raise JournalError("already_revoked")
        state[NS_CREDENTIALS][ident] = ("revoked", current[1])
    elif tag == "reset_pairing":
        for ident, current in list(state[NS_CREDENTIALS].items()):
            if current[0] == "live":
                state[NS_CREDENTIALS][ident] = ("revoked", current[1])
    elif tag == "raise":
        _tag, key, value = op
        check_key(lim, NS_MARKS, key)
        if not 0 <= value < 2 ** 64:
            raise JournalError("bad_version")
        current = state[NS_MARKS].get(key)
        if current is not None and value < current:
            raise JournalError("mark_regressed", current=current)
        if current is None and len(state[NS_MARKS]) >= lim.entries(NS_MARKS):
            raise JournalError("namespace_full", ns=NS_MARKS)
        state[NS_MARKS][key] = value
    elif tag == "tomb":
        if not snapshot:
            raise JournalError("bad_op")
        _tag, ident, version = op
        check_key(lim, NS_CREDENTIALS, ident)
        if ident in state[NS_CREDENTIALS] or len(state[NS_CREDENTIALS]) >= lim.entries(NS_CREDENTIALS):
            raise JournalError("bad_op")
        state[NS_CREDENTIALS][ident] = ("revoked", version)
    else:
        raise JournalError("bad_op")


def snapshot_ops(state: Dict[str, Any]) -> List[Tuple]:
    """The canonical operation list for a state: namespaces in NS_ORDER, keys ascending as bytes."""
    ops: List[Tuple] = []
    for ns in NS_ORDER:
        for key in sorted(state[ns]):
            value = state[ns][key]
            if ns == NS_CREDENTIALS:
                ops.append(("install", key, value[1], value[2]) if value[0] == "live" else ("tomb", key, value[1]))
            elif ns == NS_MARKS:
                ops.append(("raise", key, value))
            else:
                ops.append(("put", ns, key, value))
    return ops


def canonical(state: Dict[str, Any]) -> bytes:
    return encode_ops(snapshot_ops(state))


# --------------------------------------------------------------------------- encoding

def encode_op(op: Tuple) -> bytes:
    tag = op[0]
    if tag == "put":
        return struct.pack(">BBB", T_PUT, op[1], len(op[2])) + op[2] + struct.pack(">H", len(op[3])) + op[3]
    if tag == "delete":
        return struct.pack(">BBB", T_DELETE, op[1], len(op[2])) + op[2]
    if tag == "reset":
        return struct.pack(">BB", T_RESET, op[1])
    if tag == "install":
        return (struct.pack(">BB", T_INSTALL, len(op[1])) + op[1] + struct.pack(">QH", op[2], len(op[3])) + op[3])
    if tag == "revoke":
        return struct.pack(">BB", T_REVOKE, len(op[1])) + op[1]
    if tag == "reset_pairing":
        return struct.pack(">B", T_RESET_PAIRING)
    if tag == "raise":
        return struct.pack(">BB", T_RAISE, len(op[1])) + op[1] + struct.pack(">Q", op[2])
    if tag == "tomb":
        return struct.pack(">BB", T_TOMB, len(op[1])) + op[1] + struct.pack(">Q", op[2])
    raise ValueError(tag)


def encode_ops(ops: Sequence[Tuple]) -> bytes:
    return struct.pack(">H", len(ops)) + b"".join(encode_op(op) for op in ops)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise JournalError("malformed")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]


def decode_ops(lim: Limits, payload: bytes, schema: int, snapshot: bool) -> List[Tuple]:
    """Decode a payload. Every length is checked against the namespace bounds BEFORE the bytes are taken, so a hostile
    length never causes an allocation or a read beyond the payload."""
    r = _Reader(payload)
    count = r.u16()
    ops: List[Tuple] = []
    for _ in range(count):
        tag = r.u8()
        if tag == T_PUT:
            ns = r.u8()
            if ns not in BLOB_NAMESPACES:
                raise JournalError("malformed")
            klen = r.u8()
            if klen > lim.key_max(ns):
                raise JournalError("malformed")
            key = r.take(klen)
            vlen = r.u16()
            if vlen > lim.value_max(ns):
                raise JournalError("malformed")
            ops.append(("put", ns, key, r.take(vlen)))
        elif tag == T_DELETE:
            ns = r.u8()
            if ns not in BLOB_NAMESPACES:
                raise JournalError("malformed")
            klen = r.u8()
            if klen > lim.key_max(ns):
                raise JournalError("malformed")
            ops.append(("delete", ns, r.take(klen)))
        elif tag == T_RESET:
            ops.append(("reset", r.u8()))
        elif tag == T_INSTALL:
            klen = r.u8()
            if klen > lim.key_max(NS_CREDENTIALS):
                raise JournalError("malformed")
            key = r.take(klen)
            version = r.u64() if schema >= 1 else 1
            slen = r.u16()
            if slen > lim.value_max(NS_CREDENTIALS):
                raise JournalError("malformed")
            ops.append(("install", key, version, r.take(slen)))
        elif schema >= 1 and tag in (T_REVOKE, T_TOMB, T_RAISE):
            klen = r.u8()
            if klen > lim.key_max(NS_MARKS if tag == T_RAISE else NS_CREDENTIALS):
                raise JournalError("malformed")
            key = r.take(klen)
            if tag == T_REVOKE:
                ops.append(("revoke", key))
            elif tag == T_TOMB:
                ops.append(("tomb", key, r.u64()))
            else:
                ops.append(("raise", key, r.u64()))
        elif schema >= 1 and tag == T_RESET_PAIRING:
            ops.append(("reset_pairing",))
        else:
            raise JournalError("malformed")
    if r.pos != len(payload):
        raise JournalError("malformed")
    if not snapshot and any(op[0] == "tomb" for op in ops):
        raise JournalError("malformed")
    return ops


def encode_segment_header(version: int, gen: int, first_seq: int) -> bytes:
    body = b"FJ" + struct.pack(">BBII", version, 0, gen, first_seq)
    return body + struct.pack(">I", zlib.crc32(body))


def encode_frame(kind: int, seq: int, payload: bytes) -> bytes:
    head = struct.pack(">BBHI", FRAME_MAGIC, kind, len(payload), seq)
    return head + struct.pack(">I", zlib.crc32(head + payload)) + payload


# --------------------------------------------------------------------------- media model

class Media:
    """Two erase segments with a volatile write cache. `program` can only clear bits; `erase` is per segment; `read` sees
    the cache. A power cut keeps the durable bytes plus a byte-budgeted prefix of the unsynced operations."""

    def __init__(self, segment_bytes: int) -> None:
        self.seg = segment_bytes
        self.media = bytearray([ERASED]) * (2 * segment_bytes)
        self.view = bytearray(self.media)
        self.pending: List[Tuple] = []
        self.ops_done = 0
        self.pending_before: List[int] = []
        self.cut_after_ops: Optional[int] = None
        self.cut_budget = 0
        self.cut_reverse = False
        self.fail_op_at: Optional[int] = None
        self.sync_fail_at: Optional[int] = None
        self.sync_fail_persists = False
        self.dead = False

    # -- helpers
    def pending_bytes(self) -> int:
        return sum(len(p[2]) if p[0] == "p" else self.seg for p in self.pending)

    def _begin(self, kind: str) -> None:
        if self.dead:
            raise StorageFault("power_cut")
        self.pending_before.append(self.pending_bytes())
        if self.cut_after_ops is not None and self.ops_done == self.cut_after_ops:
            self.power_cut(self.cut_budget, self.cut_reverse)
            raise StorageFault("power_cut")
        if self.fail_op_at is not None and self.ops_done == self.fail_op_at and kind != "s":
            self.ops_done += 1
            raise StorageFault("io")

    def power_cut(self, budget: int, reverse: bool = False) -> None:
        ops = list(reversed(self.pending)) if reverse else list(self.pending)
        for kind, off, data in ops:
            if kind == "p":
                take = min(len(data), budget)
                for i in range(take):
                    self.media[off + i] &= data[i]
                budget -= take
            else:
                take = min(self.seg, budget)
                for i in range(take):
                    self.media[off + i] = ERASED
                budget -= take
        self.pending = []
        self.view = bytearray(self.media)
        self.dead = True

    def restart(self) -> None:
        """Power returns: only the durable bytes remain; the fault plan is cleared."""
        self.view = bytearray(self.media)
        self.pending = []
        self.dead = False
        self.cut_after_ops = None
        self.fail_op_at = None
        self.sync_fail_at = None

    # -- the storage interface
    def read(self, offset: int, length: int) -> bytes:
        if self.dead:
            raise StorageFault("power_cut")
        if offset < 0 or offset + length > len(self.view):
            raise StorageFault("out_of_range")
        return bytes(self.view[offset:offset + length])

    def program(self, offset: int, data: bytes) -> None:
        self._begin("p")
        if offset < 0 or offset + len(data) > len(self.view):
            raise StorageFault("out_of_range")
        for i, byte in enumerate(data):
            if byte & ~self.view[offset + i] & 0xFF:
                raise StorageFault("bits_cannot_rise")
        for i, byte in enumerate(data):
            self.view[offset + i] &= byte
        self.pending.append(("p", offset, bytes(data)))
        self.ops_done += 1

    def erase(self, index: int) -> None:
        self._begin("e")
        if index not in (0, 1):
            raise StorageFault("out_of_range")
        base = index * self.seg
        for i in range(self.seg):
            self.view[base + i] = ERASED
        self.pending.append(("e", base, b""))
        self.ops_done += 1

    def sync(self) -> None:
        self._begin("s")
        if self.sync_fail_at is not None and self.ops_done == self.sync_fail_at:
            self.ops_done += 1
            if self.sync_fail_persists:
                self.media = bytearray(self.view)
            self.pending = []
            self.view = bytearray(self.media)
            self.dead = True
            raise StorageFault("sync_failed")
        self.media = bytearray(self.view)
        self.pending = []
        self.ops_done += 1


# --------------------------------------------------------------------------- the journal

class Recovery:
    def __init__(self, source: str, gen: int = 0, frames: int = 0, tail_dirty: bool = False, migrated_from: Optional[int] = None,
                 retired_stale: bool = False, compacted: bool = False) -> None:
        self.source, self.gen, self.frames, self.tail_dirty = source, gen, frames, tail_dirty
        self.migrated_from, self.retired_stale, self.compacted = migrated_from, retired_stale, compacted

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _blank(data: bytes) -> bool:
    return all(b == ERASED for b in data)


class Journal:
    def __init__(self, media: Media, lim: Limits) -> None:
        self.media, self.lim = media, lim
        self.state = empty_state()
        self.active = 0
        self.gen = 0
        self.next_seq = 1
        self.write_off = SEG_HEADER
        self.poisoned = False
        self.pending_retire: Optional[int] = None
        self.staged: Dict[bytes, bytes] = {}
        self.last_flush: Optional[int] = None
        self.frames_written = 0
        self.compactions = 0
        self.bytes_programmed = 0

    # -- scanning
    def scan(self, index: int) -> Dict[str, Any]:
        """Bounded scan of one segment. Reads only what the segment's own structure says is there."""
        seg = self.lim.segment_bytes
        base = index * seg
        head = self.media.read(base, SEG_HEADER)
        if _blank(head):
            return {"status": "blank"}
        if head[0:2] != b"FJ" or struct.unpack(">I", head[12:16])[0] != zlib.crc32(head[:12]):
            return {"status": "invalid"}
        version, _reserved, gen, first_seq = struct.unpack(">BBII", head[2:12])
        if version not in (LEGACY_VERSION, FORMAT_VERSION):
            return {"status": "unsupported", "gen": gen, "version": version}
        state = empty_state()
        off, seq, frames = SEG_HEADER, first_seq, 0
        for _ in range(seg // FRAME_HEADER):
            if off + FRAME_HEADER > seg:
                break
            fh = self.media.read(base + off, FRAME_HEADER)
            if fh[0] == ERASED:
                break
            if fh[0] != FRAME_MAGIC:
                break
            _m, kind, length, fseq, crc = struct.unpack(">BBHII", fh)
            cap = self.lim.worst_snapshot_payload() if kind == KIND_SNAPSHOT else self.lim.max_txn_payload
            if kind not in (KIND_TXN, KIND_SNAPSHOT) or length > cap or off + FRAME_HEADER + length > seg or fseq != seq:
                break
            if (frames == 0) != (kind == KIND_SNAPSHOT):
                break
            payload = self.media.read(base + off + FRAME_HEADER, length)
            if zlib.crc32(fh[:8] + payload) != crc:
                break
            try:
                ops = decode_ops(self.lim, payload, version, kind == KIND_SNAPSHOT)
                trial = copy.deepcopy(state)
                for op in ops:
                    apply_op(self.lim, trial, op, snapshot=kind == KIND_SNAPSHOT)
            except JournalError:
                break
            state = trial
            off += FRAME_HEADER + length
            seq += 1
            frames += 1
        if frames == 0:
            return {"status": "invalid"}
        tail = self.media.read(base + off, seg - off) if off < seg else b""
        return {"status": "ok", "gen": gen, "version": version, "state": state, "end": off, "next_seq": seq,
                "frames": frames, "tail_dirty": not _blank(tail), "first_seq": first_seq}

    # -- opening
    @classmethod
    def open(cls, media: Media, lim: Limits) -> Tuple["Journal", Recovery]:
        lim.validate()
        j = cls(media, lim)
        scans = [j.scan(0), j.scan(1)]
        good = [(i, s) for i, s in enumerate(scans) if s["status"] == "ok"]
        for i, s in enumerate(scans):
            if s["status"] == "unsupported" and (not good or s["gen"] > max(g["gen"] for _, g in good)):
                raise JournalError("unsupported_version", version=s["version"])
        if not good:
            blank = all(s["status"] == "blank" for s in scans)
            j._format()
            return j, Recovery("blank" if blank else "unrecoverable", gen=j.gen, compacted=True)
        index, best = max(good, key=lambda item: item[1]["gen"])
        j.active, j.gen, j.state = index, best["gen"], best["state"]
        j.next_seq, j.write_off = best["next_seq"], best["end"]
        rec = Recovery("segment", gen=best["gen"], frames=best["frames"], tail_dirty=best["tail_dirty"])
        stale = 1 - index
        if scans[stale]["status"] in ("ok", "unsupported"):
            j.pending_retire = stale
        if best["tail_dirty"] or best["version"] != FORMAT_VERSION:
            if best["version"] != FORMAT_VERSION:
                rec.migrated_from = best["version"]
            j._compact(j.state)
            rec.compacted = True
        if j.pending_retire is not None:
            j._retire()
            rec.retired_stale = True
        return j, rec

    # -- low-level steps; any storage fault poisons the journal until it is reopened
    def _io(self, fn, *args):
        try:
            return fn(*args)
        except StorageFault as fault:
            self.poisoned = True
            raise JournalError("storage", fault=fault.code)

    def _format(self) -> None:
        seg = self.lim.segment_bytes
        for index in (0, 1):
            if not _blank(self._io(self.media.read, index * seg, seg)):
                self._io(self.media.erase, index)
        self.active, self.gen, self.next_seq = 0, 0, 1
        self._write_segment(0, 1, empty_state())
        self.gen, self.active, self.state = 1, 0, empty_state()

    def _write_segment(self, index: int, gen: int, state: Dict[str, Any]) -> None:
        seg = self.lim.segment_bytes
        base = index * seg
        frame = encode_frame(KIND_SNAPSHOT, self.next_seq, canonical(state))
        self._io(self.media.program, base, encode_segment_header(FORMAT_VERSION, gen, self.next_seq))
        self._io(self.media.program, base + SEG_HEADER, frame)
        self._io(self.media.sync)
        self.bytes_programmed += SEG_HEADER + len(frame)
        self.write_off = SEG_HEADER + len(frame)
        self.next_seq += 1

    def _compact(self, new_state: Dict[str, Any]) -> None:
        """Write `new_state` as the first frame of the other segment, sync, then publish it. The old segment stays valid
        until the deferred retire, so a cut anywhere before the sync recovers the old state."""
        if self.gen + 1 > self.lim.max_segment_gen or self.next_seq >= MAX_SEQ:
            raise JournalError("wear_exhausted")
        seg = self.lim.segment_bytes
        target = 1 - self.active
        if not _blank(self._io(self.media.read, target * seg, seg)):
            self._io(self.media.erase, target)
        old_active, old_off, old_seq = self.active, self.write_off, self.next_seq
        try:
            self._write_segment(target, self.gen + 1, new_state)
        except JournalError:
            self.write_off, self.next_seq = old_off, old_seq
            raise
        self.active, self.gen, self.state = target, self.gen + 1, copy.deepcopy(new_state)
        self.pending_retire = old_active
        self.compactions += 1

    def _retire(self) -> None:
        """Clear the stale segment's magic (programming only clears bits), so a damaged current segment cannot fall back
        to a state that predates a revocation."""
        index = self.pending_retire
        if index is None:
            return
        self._io(self.media.program, index * self.lim.segment_bytes, b"\x00\x00")
        self._io(self.media.sync)
        self.pending_retire = None

    # -- the publication state machine
    def commit(self, ops: Sequence[Tuple]) -> str:
        """Validate, write, sync, publish. Returns 'noop', 'appended' or 'compacted'. A storage fault leaves the journal
        poisoned and the published state unchanged; reopen to learn which of old and new is on the medium."""
        if self.poisoned:
            raise JournalError("poisoned")
        if self.pending_retire is not None:
            self._retire()
        trial = copy.deepcopy(self.state)
        for op in ops:
            apply_op(self.lim, trial, op)
        if canonical(trial) == canonical(self.state):
            return "noop"
        payload = encode_ops(ops)
        if len(payload) > self.lim.max_txn_payload:
            raise JournalError("txn_too_large")
        frame = encode_frame(KIND_TXN, self.next_seq, payload)
        if self.next_seq < MAX_SEQ and self.write_off + len(frame) <= self.lim.segment_bytes:
            self._io(self.media.program, self.active * self.lim.segment_bytes + self.write_off, frame)
            self._io(self.media.sync)
            self.bytes_programmed += len(frame)
            self.write_off += len(frame)
            self.next_seq += 1
            self.state = trial
            self.frames_written += 1
            return "appended"
        self._compact(trial)
        return "compacted"

    # -- the named operations
    def put(self, ns: int, key: bytes, value: bytes) -> str:
        return self.commit([("put", ns, key, value)])

    def delete(self, ns: int, key: bytes) -> str:
        return self.commit([("delete", ns, key)])

    def reset_settings(self) -> str:
        self.staged.clear()
        return self.commit([("reset", NS_SETTINGS)])

    def clear_calibration(self) -> str:
        return self.commit([("reset", NS_CALIBRATION)])

    def install(self, ident: bytes, version: int, secret: bytes) -> str:
        return self.commit([("install", ident, version, secret)])

    def revoke(self, ident: bytes) -> str:
        return self.commit([("revoke", ident)])

    def reset_pairing(self) -> str:
        return self.commit([("reset_pairing",)])

    def raise_mark(self, key: bytes, value: int) -> str:
        return self.commit([("raise", key, value)])

    def stage_setting(self, key: bytes, value: bytes) -> None:
        check_key(self.lim, NS_SETTINGS, key)
        check_value(self.lim, NS_SETTINGS, value)
        keys = set(self.state[NS_SETTINGS]) | set(self.staged) | {key}
        if len(keys) > self.lim.entries(NS_SETTINGS):
            raise JournalError("namespace_full", ns=NS_SETTINGS)
        self.staged[key] = value

    def flush_settings(self, now: int) -> str:
        if not self.staged:
            return "noop"
        if self.last_flush is not None and now < self.last_flush + self.lim.min_flush_interval_ticks:
            raise JournalError("rate_limited", retry_after=self.last_flush + self.lim.min_flush_interval_ticks - now)
        ops = [("put", NS_SETTINGS, k, v) for k, v in sorted(self.staged.items())]
        outcome = self.commit(ops)
        self.staged.clear()
        self.last_flush = now
        return outcome


# --------------------------------------------------------------------------- the cut-point oracle

def state_hex(state: Dict[str, Any]) -> str:
    return canonical(state).hex()


def run_script(lim: Limits, script: Sequence[Tuple], media: Media) -> Tuple[List[str], List[Tuple[int, int]], Optional[Journal]]:
    """Run `script` (a list of (method, args...) steps) against `media`, formatting first. Returns the canonical state
    hex after the format and after every step, the half-open storage-operation range each step used, and the journal.
    A step that raises JournalError records its error code and leaves the state unchanged (a rejected step writes nothing)."""
    j, _rec = Journal.open(media, lim)
    states = [state_hex(j.state)]
    ranges: List[Tuple[int, int]] = [(0, media.ops_done)]
    for step in script:
        start = media.ops_done
        try:
            getattr(j, step[0])(*step[1:])
        except JournalError as err:
            if err.code in ("storage", "poisoned"):
                raise
        states.append(state_hex(j.state))
        ranges.append((start, media.ops_done))
    return states, ranges, j


def enumerate_cuts(lim: Limits, script: Sequence[Tuple], reverse: bool = False, stride: int = 1) -> Dict[str, Any]:
    """Cut the power at every storage-operation boundary and every byte budget of the unsynced writes, restart, reopen,
    and check the recovered state is exactly the state before or after the step that was running; if the step had
    finished (the cut is after its last operation), exactly the state after it. Returns the digest of every cut's media."""
    baseline = Media(lim.segment_bytes)
    states, ranges, _j = run_script(lim, script, baseline)
    total_ops = baseline.ops_done
    pending_before = list(baseline.pending_before) + [0]
    digests = hashlib.sha256()
    cuts = old = new = 0
    # ranges[i] is the storage-operation range that produced states[i]; i = 0 is the format of a blank medium.
    for n in range(total_ops + 1):
        idx = next((i for i, (a, b) in enumerate(ranges) if a <= n < b), None)
        budgets = range(0, pending_before[n] + 1, stride) if n < total_ops else range(1)
        for k in budgets:
            media = Media(lim.segment_bytes)
            media.cut_after_ops, media.cut_budget, media.cut_reverse = n, k, reverse
            try:
                run_script(lim, script, media)
            except JournalError:
                pass
            if not media.dead:
                media.power_cut(0, reverse)
            digests.update(hashlib.sha256(bytes(media.media)).digest())
            media.restart()
            reopened, rec = Journal.open(media, lim)
            got = state_hex(reopened.state)
            if idx is None:
                want = {states[-1]}  # every step had finished: acknowledged means durable
            elif idx == 0:
                want = {states[0]}  # a torn format recovers as a fresh, empty journal
            else:
                want = {states[idx - 1], states[idx]}
                if n == ranges[idx][0] and k == 0:
                    want = {states[idx - 1]}  # nothing of this step had started
            if got not in want:
                raise AssertionError(f"cut n={n} k={k}: recovered state is neither old nor new (step {idx})")
            cuts += 1
            if idx is not None and idx > 0 and got == states[idx] and states[idx - 1] != states[idx]:
                new += 1
            else:
                old += 1
    return {"cuts": cuts, "old": old, "new": new, "total_ops": total_ops, "digest": digests.hexdigest(),
            "states": states}
