"""Independent oracles for the S02 vectors (stdlib only). Nothing here decodes lossy audio; it builds the deterministic source signal,
and reads container structure (Ogg pages, MP4 boxes, ADTS headers, MP3 frame headers) so that the frame counts, packet boundaries and
codec configuration the Rust adapter is held to come from the files' own bytes and not from the adapter, from Symphonia or from the encoder's
documentation.

The source signal (`signal`) is integer-only on purpose, so the Rust test can regenerate it bit for bit from the same written rule:

    tri(n, period, amp) = ((abs((4*n) mod (4*period) - 2*period) * 2*amp) div (2*period)) - amp        (n >= 0, all terms >= 0 before the last subtraction)
    xorshift32(s): s ^= s << 13 (mod 2^32); s ^= s >> 17; s ^= s << 5 (mod 2^32)
    left[n]  = tri(n, 100, 6000) + tri(n, 37, 2000) + (xorshift32 stream A draw mod 601) - 300
    right[n] = tri(n, 91, 6000)  + tri(n, 53, 2000) + (xorshift32 stream B draw mod 601) - 300
    streams A and B start from `seed_a` and `seed_b` and are advanced once per frame, A before B, before the sample is read.
    24-bit tracks: s24 = s16 * 256 + (xorshift32 stream C draw mod 256), C advanced once per sample (left then right) after A and B.
"""
from __future__ import annotations

import hashlib
import struct
import wave
from typing import Dict, List, Tuple

MASK32 = 0xFFFFFFFF


def xorshift32(s: int) -> int:
    s ^= (s << 13) & MASK32
    s ^= s >> 17
    s ^= (s << 5) & MASK32
    return s & MASK32


def tri(n: int, period: int, amp: int) -> int:
    t = abs(((4 * n) % (4 * period)) - 2 * period)
    return (t * 2 * amp) // (2 * period) - amp


def signal(frames: int, seed_a: int, seed_b: int, seed_c: int = 0, bits: int = 16) -> List[Tuple[int, int]]:
    """Interleaved-pair list of (left, right) integers at `bits` (16 or 24)."""
    a, b, c = seed_a, seed_b, seed_c
    out = []
    for n in range(frames):
        a = xorshift32(a)
        b = xorshift32(b)
        left = tri(n, 100, 6000) + tri(n, 37, 2000) + (a % 601) - 300
        right = tri(n, 91, 6000) + tri(n, 53, 2000) + (b % 601) - 300
        if bits == 24:
            c = xorshift32(c)
            left = left * 256 + (c % 256)
            c = xorshift32(c)
            right = right * 256 + (c % 256)
        out.append((left, right))
    return out


def pcm_le(pairs: List[Tuple[int, int]], bits: int) -> bytes:
    if bits == 16:
        return b"".join(struct.pack("<hh", l, r) for l, r in pairs)
    return b"".join(struct.pack("<i", l)[:3] + struct.pack("<i", r)[:3] for l, r in pairs)


def pcm_be16(pairs: List[Tuple[int, int]]) -> bytes:
    return b"".join(struct.pack(">hh", l, r) for l, r in pairs)


def write_wav(path: str, pairs: List[Tuple[int, int]], rate: int, bits: int) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(bits // 8)
        w.setframerate(rate)
        w.writeframes(pcm_le(pairs, bits))


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------ Ogg

def ogg_pages(data: bytes) -> List[Dict[str, int]]:
    """Every page: flags, granule position, serial, sequence, body size. Refuses a capture-pattern miss (a torn file)."""
    pages, pos = [], 0
    while pos < len(data):
        if data[pos:pos + 4] != b"OggS":
            raise ValueError(f"no Ogg capture pattern at {pos}")
        _ver, flags, gran, serial, seq, _crc, nseg = struct.unpack_from("<BBqIIIB", data, pos + 4)
        size = sum(data[pos + 27:pos + 27 + nseg])
        pages.append({"flags": flags, "granule": gran, "serial": serial, "seq": seq, "body": size, "offset": pos})
        pos += 27 + nseg + size
    return pages


def ogg_streams(data: bytes) -> List[Dict[str, int]]:
    """Per logical stream (chained streams have different serials): the final granule position, i.e. the stream's frame count."""
    streams: Dict[int, Dict[str, int]] = {}
    order: List[int] = []
    for page in ogg_pages(data):
        s = streams.setdefault(page["serial"], {"serial": page["serial"], "last_granule": 0, "pages": 0})
        if page["serial"] not in order:
            order.append(page["serial"])
        s["pages"] += 1
        if page["granule"] >= 0:
            s["last_granule"] = page["granule"]
    return [streams[k] for k in order]


def vorbis_ident(data: bytes) -> Dict[str, int]:
    """Channels and sample rate from the first Vorbis identification header packet in the file (the first page's body)."""
    pos = data.index(b"\x01vorbis")
    _ver, channels, rate = struct.unpack_from("<IBI", data, pos + 7)
    return {"channels": channels, "rate": rate}


# ------------------------------------------------------------------------------------------------ MP3

_MP3_RATES = {0: (11025, 12000, 8000), 2: (22050, 24000, 16000), 3: (44100, 48000, 32000)}  # keyed by MPEG version bits (0=2.5, 2=2, 3=1)
_MP3_BITRATES_L3_V1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]


def mp3_frames(data: bytes) -> Dict[str, object]:
    """Walk MPEG-1 Layer III frames from the first sync word: count, sample rate, channel mode, and the LAME/Xing gapless fields of the first
    frame if it carries them. Refuses anything that is not MPEG-1 Layer III (the only layer S02 admits)."""
    pos = 0
    if data[:3] == b"ID3":
        size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
        pos = 10 + size
    frames, rate, mode, first = 0, 0, 0, None
    while pos + 4 <= len(data):
        h = struct.unpack_from(">I", data, pos)[0]
        if (h >> 21) != 0x7FF:
            break
        ver, layer = (h >> 19) & 3, (h >> 17) & 3
        if ver != 3 or layer != 1:
            raise ValueError(f"not MPEG-1 Layer III at {pos}")
        br_idx, sr_idx, pad = (h >> 12) & 15, (h >> 10) & 3, (h >> 9) & 1
        if br_idx in (0, 15) or sr_idx == 3:
            raise ValueError(f"free-format or reserved bitrate/rate at {pos}")
        rate = _MP3_RATES[ver][sr_idx]
        mode = (h >> 6) & 3
        length = 144 * _MP3_BITRATES_L3_V1[br_idx] * 1000 // rate + pad
        if first is None:
            first = data[pos:pos + length]
        frames += 1
        pos += length
    info: Dict[str, object] = {"frames": frames, "rate": rate, "channel_mode": mode, "tail_bytes": len(data) - pos}
    if first is not None:
        for tag in (b"Xing", b"Info"):
            at = first.find(tag)
            if at >= 0:
                flags = struct.unpack_from(">I", first, at + 4)[0]
                off = at + 8
                if flags & 1:
                    info["xing_frames"] = struct.unpack_from(">I", first, off)[0]
                    off += 4
                if flags & 2:
                    off += 4
                if flags & 4:
                    off += 100
                if flags & 8:
                    off += 4
                # the encoder string (9 bytes: "LAME3.100", or "Lavc62.28" from ffmpeg's libmp3lame) starts right after the optional Xing fields;
                # the 12-bit encoder delay and 12-bit padding sit at byte 21 of that string
                if first[off:off + 4] in (b"LAME", b"Lavc"):
                    d = first[off + 21:off + 24]
                    info["enc_delay"] = (d[0] << 4) | (d[1] >> 4)
                    info["enc_padding"] = ((d[1] & 15) << 8) | d[2]
                    info["encoder_string"] = first[off:off + 9].decode("ascii", "replace")
                info["xing_tag"] = tag.decode()
                break
    return info


# ------------------------------------------------------------------------------------------------ ADTS / AAC

ADTS_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350]


def adts_frames(data: bytes) -> Dict[str, object]:
    """Split an ADTS stream into raw AAC frames (header removed) and report the stream parameters of the first frame; refuses a parameter
    change inside the stream (the sender's session fixes them) and anything that is not AAC-LC (object type 2)."""
    frames: List[bytes] = []
    pos, params = 0, None
    while pos + 7 <= len(data):
        if data[pos] != 0xFF or (data[pos + 1] & 0xF0) != 0xF0:
            raise ValueError(f"no ADTS sync at {pos}")
        protection_absent = data[pos + 1] & 1
        profile = (data[pos + 2] >> 6) & 3          # object type - 1
        sr_idx = (data[pos + 2] >> 2) & 15
        channel_cfg = ((data[pos + 2] & 1) << 2) | (data[pos + 3] >> 6)
        length = ((data[pos + 3] & 3) << 11) | (data[pos + 4] << 3) | (data[pos + 5] >> 5)
        header = 7 if protection_absent else 9
        if profile + 1 != 2:
            raise ValueError(f"object type {profile + 1} is not AAC-LC")
        here = (profile + 1, sr_idx, channel_cfg)
        if params is None:
            params = here
        elif here != params:
            raise ValueError("ADTS parameters change inside the stream")
        if length < header or pos + length > len(data):
            raise ValueError(f"ADTS frame length {length} at {pos} runs past the data")
        frames.append(data[pos + header:pos + length])
        pos += length
    if params is None or pos != len(data):
        raise ValueError("ADTS stream is empty or has trailing bytes")
    object_type, sr_idx, channel_cfg = params
    asc = ((object_type << 11) | (sr_idx << 7) | (channel_cfg << 3)).to_bytes(2, "big")
    return {"frames": frames, "rate": ADTS_RATES[sr_idx], "channel_config": channel_cfg, "object_type": object_type, "asc": asc}


# ------------------------------------------------------------------------------------------------ MP4 / ALAC

def _boxes(data: bytes, start: int, end: int):
    pos = start
    while pos + 8 <= end:
        size, kind = struct.unpack_from(">I4s", data, pos)
        header = 8
        if size == 1:
            size = struct.unpack_from(">Q", data, pos + 8)[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header or pos + size > end:
            raise ValueError(f"box {kind!r} at {pos} has size {size}")
        yield kind, pos + header, pos + size
        pos += size


def _find(data: bytes, start: int, end: int, path: List[bytes]):
    for kind, body, stop in _boxes(data, start, end):
        if kind == path[0]:
            if len(path) == 1:
                return body, stop
            found = _find(data, body, stop, path[1:])
            if found:
                return found
    return None


def alac_packets(data: bytes) -> Dict[str, object]:
    """Raw ALAC packets and the magic cookie (the 24-byte ALACSpecificConfig) of the first audio track of an MP4/M4A file, found through
    stsd/alac/alac, stsz, stsc and stco/co64. The packet list is in decode order."""
    stbl = _find(data, 0, len(data), [b"moov", b"trak", b"mdia", b"minf", b"stbl"])
    if stbl is None:
        raise ValueError("no stbl")
    sb, se = stbl
    stsd = _find(data, sb, se, [b"stsd"])
    stsz = _find(data, sb, se, [b"stsz"])
    stsc = _find(data, sb, se, [b"stsc"])
    stco = _find(data, sb, se, [b"stco"]) or _find(data, sb, se, [b"co64"])
    if not (stsd and stsz and stsc and stco):
        raise ValueError("missing sample table")
    # stsd: version/flags(4) + entry count(4), then an 'alac' sample entry (28 bytes of audio sample entry, then a child 'alac' box)
    entry_at = stsd[0] + 8
    esize, ekind = struct.unpack_from(">I4s", data, entry_at)
    if ekind != b"alac":
        raise ValueError(f"sample entry is {ekind!r}, not alac")
    cookie_box = _find(data, entry_at + 36, entry_at + esize, [b"alac"])
    if cookie_box is None:
        raise ValueError("no alac cookie box")
    cookie = data[cookie_box[0] + 4:cookie_box[1]]            # skip the box's version/flags
    sz_ver, sample_size, count = struct.unpack_from(">III", data, stsz[0])
    sizes = [sample_size] * count if sample_size else list(struct.unpack_from(f">{count}I", data, stsz[0] + 12))
    n_chunks = struct.unpack_from(">I", data, stsc[0] + 4)[0]
    runs = [struct.unpack_from(">III", data, stsc[0] + 8 + 12 * i) for i in range(n_chunks)]
    wide = _find(data, sb, se, [b"co64"]) is not None and _find(data, sb, se, [b"stco"]) is None
    n_off = struct.unpack_from(">I", data, stco[0] + 4)[0]
    offsets = list(struct.unpack_from(f">{n_off}{'Q' if wide else 'I'}", data, stco[0] + 8))
    packets, index = [], 0
    for chunk in range(n_off):
        per = next(r[1] for r in reversed(runs) if r[0] <= chunk + 1)
        at = offsets[chunk]
        for _ in range(per):
            if index >= len(sizes):
                break
            packets.append(data[at:at + sizes[index]])
            at += sizes[index]
            index += 1
    if index != len(sizes):
        raise ValueError("sample table does not cover every packet")
    return {"packets": packets, "cookie": cookie}


def alac_cookie_fields(cookie: bytes) -> Dict[str, int]:
    frame_length, _compat, bit_depth, pb, mb, kb, channels, max_run, max_frame, avg_rate, sample_rate = struct.unpack(">IBBBBBBHIII", cookie[:24])
    return {"frame_length": frame_length, "bit_depth": bit_depth, "pb": pb, "mb": mb, "kb": kb, "channels": channels, "max_run": max_run,
            "max_frame_bytes": max_frame, "avg_bitrate": avg_rate, "sample_rate": sample_rate}
