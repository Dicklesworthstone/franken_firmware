#!/usr/bin/env python3
"""Build the S02 complete-track vectors (bead ffw-6dh) with INDEPENDENT tools and pin them by hash.

    make_vectors.py [--out DIR]       write the vector files and s02_vectors.json (default: crates/franken-codec/tests/vectors)
    make_vectors.py --check           verify the committed files against the manifest, and re-derive every fact from the files' own bytes

Independence: the source signal is the integer rule in oracle.py (no encoder involved). Encoders are Apple's `afconvert` (ALAC, AAC-LC),
ffmpeg's libmp3lame (MP3) and ffmpeg's native Vorbis encoder. Reference decodes come from ffmpeg and a SECOND independent decoder for every lossy codec:
Apple's (`afconvert`) for MP3 and AAC-LC, libvorbis (through libsndfile, `vorbis_tool.py`, run under the Python given by `--vorbis-python`) for Vorbis;
never from Symphonia or from the adapter under test.

The Vorbis reference is ffmpeg's SCALAR decode (`-cpuflags 0`). The observed default (optimised, aarch64) decode disagrees with scalar ffmpeg and libvorbis.
Their corroboration disqualifies the old reference; matching error summaries do not establish what PCM the Rust adapter produced. That comparison awaits
a new central run. The old decode is kept as `<id>.ref.ffmpeg-optimised.s16`, listed in the manifest as a retained BAD reference, so the failure and
its discrimination control stay reproducible. Reusing the exact committed streams copies that archived control after hash checks; fresh encodes do not inherit it.
MP3 and AAC-LC references are still the default-cpuflags decode (the optimised path differs from the scalar one
by at most 1 LSB there, recorded per track as `optimised_vs_scalar`); `SCALAR_REFERENCE_CODECS` moves a codec to the scalar decode. Lossless tracks (ALAC, PCM) are held to the SOURCE signal, bit for
bit; lossy tracks are held to the reference decode inside a tolerance fixed here, before any Rust run, from the observed disagreement of two
independent reference decoders. Generation needs ffmpeg, afconvert and a Python with soundfile; `--check` needs none of them.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True
import oracle  # noqa: E402

VEC_DIR = os.path.join(REPO, "crates", "franken-codec", "tests", "vectors")
MANIFEST = "s02_vectors.json"
SCHEMA = "ffw.s02.vectors.v1"
SECONDS_HALF = 2          # tracks are half a second: frames = rate // SECONDS_HALF
# Tolerance for LOSSY tracks, in 16-bit LSB, against the reference decode. Fixed from the two-decoder disagreement measured when the
# vectors were made (max 1, rms 0.71 for MP3 and AAC); a codec output that is within 4 / 1.5 of an independent reference decoder is accepted.
LOSSY_TOLERANCE = {"max_abs_lsb": 4, "rms_lsb": 1.5, "rule": "4x the largest observed two-decoder max error (1), and about 2x the largest rms (0.71)"}
# Seek preroll (packets decoded and discarded after a seek or reset before output is compared). Fixed here from each codec's overlap/reservoir
# structure, not from the adapter: Vorbis windows overlap by one block, MP3 Layer III needs the bit reservoir of previous frames, AAC-LC one
# overlapped 1024-sample frame, ALAC frames are independent.
PREROLL = {"vorbis": {"packets": 2}, "mp3": {"packets": 3}, "aac": {"packets": 1}, "alac": {"packets": 0}, "pcm": {"packets": 0}}

TRACKS: List[Dict[str, Any]] = [
    {"id": "vorbis_44100", "codec": "vorbis", "rate": 44100, "bits": 16, "channels": 2, "seeds": [1, 2, 0], "file": "vorbis_44100.ogg", "mandatory": "spotify"},
    {"id": "vorbis_48000", "codec": "vorbis", "rate": 48000, "bits": 16, "channels": 2, "seeds": [3, 4, 0], "file": "vorbis_48000.ogg", "mandatory": "spotify"},
    {"id": "mp3_44100", "codec": "mp3", "rate": 44100, "bits": 16, "channels": 2, "seeds": [5, 6, 0], "file": "mp3_44100.mp3", "mandatory": "spotify"},
    {"id": "mp3_48000", "codec": "mp3", "rate": 48000, "bits": 16, "channels": 2, "seeds": [7, 8, 0], "file": "mp3_48000.mp3", "mandatory": "spotify"},
    {"id": "alac_44100_16", "codec": "alac", "rate": 44100, "bits": 16, "channels": 2, "seeds": [9, 10, 0], "file": "alac_44100_16.packets", "mandatory": "airplay"},
    {"id": "alac_48000_24", "codec": "alac", "rate": 48000, "bits": 24, "channels": 2, "seeds": [11, 12, 13], "file": "alac_48000_24.packets", "mandatory": "airplay"},
    {"id": "aac_lc_44100", "codec": "aac", "rate": 44100, "bits": 16, "channels": 2, "seeds": [14, 15, 0], "file": "aac_lc_44100.packets", "mandatory": "airplay"},
    {"id": "aac_lc_48000", "codec": "aac", "rate": 48000, "bits": 16, "channels": 2, "seeds": [16, 17, 0], "file": "aac_lc_48000.packets", "mandatory": "airplay"},
]
NEGATIVE = {"id": "aac_lc_48000_6ch", "codec": "aac", "rate": 48000, "channels": 6, "file": "aac_lc_48000_6ch.packets",
            "why": "AirPlay 2 can send AAC 5.1 (and 7.1); this speaker renders stereo, so the adapter must refuse it explicitly"}
PCM = {"id": "pcm_s16be_44100", "codec": "pcm", "rate": 44100, "bits": 16, "channels": 2, "seeds": [18, 19, 0], "file": "pcm_s16be_44100.raw", "mandatory": "airplay"}


VORBIS_PYTHON: Optional[str] = None
# ffmpeg's native Vorbis encoder writes a RANDOM Ogg serial number, so two encodes of the same signal differ; the committed Vorbis streams are therefore the
# source of truth and `--reuse-vorbis-streams DIR` takes them from DIR instead of encoding again (the references are then derived from those exact bytes).
REUSE_VORBIS_DIR: Optional[str] = None
# Lossy codecs whose reference is ffmpeg's SCALAR decode (`-cpuflags 0`) instead of its default optimised one. Only the codec whose optimised decode was
# demonstrated wrong is listed; widening it changes that codec's reference files (by at most 1 LSB for MP3).
SCALAR_REFERENCE_CODECS = ("vorbis",)


def vorbis_helper(*args: str) -> bytes:
    if not VORBIS_PYTHON:
        raise RuntimeError("generating the Vorbis vectors needs --vorbis-python (a Python with numpy and soundfile) or S02_VORBIS_PYTHON")
    return run([VORBIS_PYTHON, os.path.join(HERE, "vorbis_tool.py"), *args]).stdout


def run(cmd: List[str], **kw: Any) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, **kw)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}... failed rc={p.returncode}: {p.stderr.decode('utf-8', 'replace')[-300:]}")
    return p


def tool_versions() -> Dict[str, str]:
    ff = run(["ffmpeg", "-hide_banner", "-version"]).stdout.decode().splitlines()[0]
    helped = subprocess.run(["afconvert", "-h"], capture_output=True)   # prints its help and exits 2: that is how it reports its version
    af = [l.strip() for l in (helped.stdout + helped.stderr).decode("utf-8", "replace").splitlines() if "Version" in l]
    sw = run(["sw_vers", "-productVersion"]).stdout.decode().strip() if platform.system() == "Darwin" else platform.platform()
    out = {"ffmpeg": ff, "afconvert": af[0] if af else "afconvert (version line not printed)", "os": f"macOS {sw}" if platform.system() == "Darwin" else sw}
    if VORBIS_PYTHON:
        out["libvorbis_via_libsndfile"] = json.loads(vorbis_helper("versions").decode())
    return out


def s16_pairs(data: bytes) -> List[tuple]:
    import struct
    return [struct.unpack_from("<hh", data, i) for i in range(0, len(data) - 3, 4)]


def deviation(a: bytes, b: bytes) -> Dict[str, Any]:
    pa, pb = s16_pairs(a), s16_pairs(b)
    n = min(len(pa), len(pb))
    worst, acc = 0, 0
    for i in range(n):
        for c in (0, 1):
            d = abs(pa[i][c] - pb[i][c])
            worst = max(worst, d)
            acc += d * d
    return {"frames_a": len(pa), "frames_b": len(pb), "compared": n, "max_abs": worst, "rms": round((acc / max(1, 2 * n)) ** 0.5, 4)}


def reused_bad_vorbis_reference(track: Dict[str, Any], stream: bytes):
    """Copy an observed bad control only from the manifest for the exact reused Ogg bytes; never regenerate it with default CPU flags."""
    if not REUSE_VORBIS_DIR:
        return None
    source = os.path.join(REUSE_VORBIS_DIR, MANIFEST)
    if not os.path.isfile(source):
        return None
    with open(source, encoding="utf-8") as handle:
        matches = [row for row in json.load(handle)["tracks"] if row["id"] == track["id"]]
    if len(matches) != 1 or matches[0]["sha256"] != oracle.sha256(stream):
        raise RuntimeError(f"{track['id']}: retained control is not bound to these exact Ogg bytes")
    retained = matches[0].get("retained_bad_reference")
    if retained is None:
        return None
    name = track["id"] + ".ref.ffmpeg-optimised.s16"
    if retained["file"] != name:
        raise RuntimeError(f"{track['id']}: unexpected retained-control filename")
    with open(os.path.join(REUSE_VORBIS_DIR, name), "rb") as handle:
        bad = handle.read()
    if len(bad) != retained["bytes"] or oracle.sha256(bad) != retained["sha256"]:
        raise RuntimeError(f"{track['id']}: retained control does not match its pinned bytes")
    return dict(retained), bad


def build_track(tmp: str, t: Dict[str, Any], out: str) -> Dict[str, Any]:
    rate, bits = t["rate"], t["bits"]
    frames = rate // SECONDS_HALF
    pairs = oracle.signal(frames, t["seeds"][0], t["seeds"][1], t["seeds"][2], bits)
    wav = os.path.join(tmp, t["id"] + ".wav")
    oracle.write_wav(wav, pairs, rate, bits)
    row: Dict[str, Any] = {"id": t["id"], "codec": t["codec"], "rate_hz": rate, "bits": bits, "channels": 2, "mandatory_for": t["mandatory"],
                           "source": {"frames": frames, "seeds": t["seeds"], "fnv1a64": f"{oracle.fnv1a64(oracle.pcm_le(pairs, bits)):016x}"},
                           "file": t["file"], "preroll": PREROLL[t["codec"]]}
    codec = t["codec"]
    if codec == "vorbis":
        data_path = os.path.join(tmp, t["file"])
        if REUSE_VORBIS_DIR:
            shutil.copyfile(os.path.join(REUSE_VORBIS_DIR, t["file"]), data_path)
        else:
            run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", wav, "-c:a", "vorbis", "-strict", "-2", "-b:a", "96k", "-page_duration", "40000", data_path])
        blob = open(data_path, "rb").read()
        streams = oracle.ogg_streams(blob)
        ident = oracle.vorbis_ident(blob)
        row.update(container="ogg", encoder={"name": "ffmpeg native vorbis", "args": "-c:a vorbis -strict -2 -b:a 96k -page_duration 40000",
                            "stream_bytes": "kept from the first generation: this encoder writes a random Ogg serial, so a fresh encode differs; `make_vectors.py --reuse-vorbis-streams`"},
                   stream={"serial": streams[0]["serial"], "last_granule": streams[0]["last_granule"], "pages": streams[0]["pages"], **ident},
                   expected_frames=streams[0]["last_granule"])
        lib_ref = os.path.join(tmp, t["id"] + ".libvorbis.s16")
        vorbis_helper("decode", data_path, lib_ref)
        refs = {"ffmpeg": ffmpeg_decode(data_path, scalar=True), "libvorbis": open(lib_ref, "rb").read()}
        src_path = data_path
    elif codec == "mp3":
        data_path = os.path.join(tmp, t["file"])
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", wav, "-c:a", "libmp3lame", "-b:a", "128k", data_path])
        blob = open(data_path, "rb").read()
        info = oracle.mp3_frames(blob)
        row.update(container="mp3", encoder={"name": "ffmpeg libmp3lame", "args": "-c:a libmp3lame -b:a 128k"},
                   stream={k: v for k, v in info.items()}, expected_frames=frames)
        refs = {"ffmpeg": ffmpeg_decode(data_path), "apple": apple_decode(data_path, tmp)}
        src_path = data_path
    elif codec == "alac":
        m4a = os.path.join(tmp, t["id"] + ".m4a")
        dfmt = "alac" if bits == 16 else "alac"
        cmd = ["afconvert", "-f", "m4af", "-d", dfmt]
        run(cmd + [wav, m4a])
        parsed = oracle.alac_packets(open(m4a, "rb").read())
        blob = b"".join(parsed["packets"])
        fields = oracle.alac_cookie_fields(parsed["cookie"])
        row.update(container="raw-packets", encoder={"name": "Apple afconvert", "args": f"-f m4af -d {dfmt}"},
                   packets={"sizes": [len(p) for p in parsed["packets"]]}, cookie_hex=parsed["cookie"].hex(), cookie_fields=fields,
                   expected_frames=frames)
        refs = {"ffmpeg": ffmpeg_decode(m4a, bits=bits), "apple": apple_decode(m4a, tmp, bits=bits)}
        src_path = m4a
    elif codec == "aac":
        adts = os.path.join(tmp, t["id"] + ".aac")
        run(["afconvert", "-f", "adts", "-d", "aac", "-b", "96000", wav, adts])
        parsed = oracle.adts_frames(open(adts, "rb").read())
        blob = b"".join(parsed["frames"])
        row.update(container="raw-packets", encoder={"name": "Apple afconvert", "args": "-f adts -d aac -b 96000"},
                   packets={"sizes": [len(p) for p in parsed["frames"]]}, asc_hex=parsed["asc"].hex(), adts={"rate": parsed["rate"],
                   "channel_config": parsed["channel_config"], "object_type": parsed["object_type"]},
                   expected_frames=1024 * len(parsed["frames"]),
                   expected_frames_note="raw frames: the decoder emits packets x 1024 frames; priming and padding are the sender's RTP timestamps, not the decoder's")
        refs = {"ffmpeg": ffmpeg_decode(adts), "apple": apple_decode(adts, tmp)}
        src_path = adts
    else:
        raise ValueError(codec)
    with open(os.path.join(out, t["file"]), "wb") as f:
        f.write(blob)
    row["bytes"], row["sha256"] = len(blob), oracle.sha256(blob)
    if codec in ("alac",):
        # lossless: BOTH independent decoders must reproduce the SOURCE exactly
        want = oracle.pcm_le(pairs, bits)
        for name, got in refs.items():
            if got != want:
                raise RuntimeError(f"{t['id']}: {name} did not reproduce the source bit for bit")
        row["lossless"] = {"equals_source_in": sorted(refs), "reference_fnv1a64": row["source"]["fnv1a64"]}
    else:
        use_scalar = codec in SCALAR_REFERENCE_CODECS
        # Vorbis has one FFmpeg reference path and it is always scalar. MP3/AAC
        # keep their already cross-checked default references; no rebaseline.
        scalar = refs["ffmpeg"] if use_scalar else ffmpeg_decode(src_path, bits, scalar=True)
        primary = scalar if use_scalar else refs["ffmpeg"]
        raw_frames = len(primary) // 4
        trimmed = None
        if codec == "vorbis" and raw_frames > row["expected_frames"]:
            # The Vorbis rule: the final page's granule position is the stream's length and a decoder discards what follows it. ffmpeg's
            # native decoder keeps the tail of the last block, so the reference is cut to the length the FILE states (read by oracle.py).
            trimmed = raw_frames - row["expected_frames"]
            primary = primary[:row["expected_frames"] * 4]
        ref_name = t["id"] + ".ref.s16"
        with open(os.path.join(out, ref_name), "wb") as f:
            f.write(primary)
        row["reference"] = {"file": ref_name, "decoder": "ffmpeg -cpuflags 0 (scalar)" if use_scalar else "ffmpeg (default cpuflags)", "bytes": len(primary),
                            "sha256": oracle.sha256(primary), "frames": len(primary) // 4, "fnv1a64": f"{oracle.fnv1a64(primary):016x}"}
        if use_scalar:
            retained = reused_bad_vorbis_reference(t, blob)
            if retained is not None:
                record, bad = retained
                if len(bad) != len(primary):
                    raise RuntimeError(f"{t['id']}: retained control and scalar reference have different lengths")
                difference = deviation(bad, primary)
                record["versus_reference"] = difference
                row["reference"]["optimised_vs_scalar"] = difference
                row["retained_bad_reference"] = record
                with open(os.path.join(out, record["file"]), "wb") as handle:
                    handle.write(bad)
        else:
            row["reference"]["optimised_vs_scalar"] = deviation(refs["ffmpeg"], scalar)
        if trimmed is not None:
            row["reference"]["cut_to_end_granule"] = {"decoder_frames": raw_frames, "frames_removed": trimmed,
                                                      "why": "Vorbis: the last page's granule position is the stream length; ffmpeg's decoder keeps the tail of the final block"}
        if len(primary) // 4 != row["expected_frames"]:
            raise RuntimeError(f"{t['id']}: reference has {len(primary) // 4} frames, the file's own bytes say {row['expected_frames']}")
        row["tolerance"] = dict(LOSSY_TOLERANCE)
        second = next((k for k in refs if k != "ffmpeg"), None)
        if second is None:
            raise RuntimeError(f"{t['id']}: a lossy track needs a second independent reference decoder")
        row["inter_reference"] = {"decoders": [row["reference"]["decoder"], second], **deviation(primary, refs[second])}
        if row["inter_reference"]["max_abs"] > 1 or row["inter_reference"]["frames_a"] != row["inter_reference"]["frames_b"]:
            raise RuntimeError(f"{t['id']}: the two reference decoders disagree more than the pre-registered basis allows")
    n = row["expected_frames"]
    row["seek_targets"] = sorted({0, 1, 1000, n // 3, n // 2, max(0, n - 1500)} & set(range(0, n)))
    return row


def ffmpeg_decode(path: str, bits: int = 16, scalar: bool = False) -> bytes:
    if path.lower().endswith(".ogg") and not scalar:
        raise ValueError("Vorbis reference decoding requires scalar=True (-cpuflags 0)")
    fmt = ("s16le", "pcm_s16le") if bits == 16 else ("s32le", "pcm_s32le")
    flags = ["-cpuflags", "0"] if scalar else []   # `-cpuflags 0`: no SIMD, the portable C code path
    raw = run(["ffmpeg", "-hide_banner", "-loglevel", "error", *flags, "-i", path, "-f", fmt[0], "-acodec", fmt[1], "-"]).stdout
    if bits == 24:  # ffmpeg widens ALAC 24-bit to the top of 32; keep the low-order 24-bit value, little-endian 3 bytes
        out = bytearray()
        import struct
        for i in range(0, len(raw), 4):
            v = struct.unpack_from("<i", raw, i)[0] >> 8
            out += struct.pack("<i", v)[:3]
        return bytes(out)
    return raw


def apple_decode(path: str, tmp: str, bits: int = 16) -> bytes:
    out = os.path.join(tmp, "apple_" + os.path.basename(path) + ".wav")
    run(["afconvert", "-f", "WAVE", "-d", "LEI16" if bits == 16 else "LEI24", path, out])
    import wave
    with wave.open(out) as w:
        return w.readframes(w.getnframes())


def build_all(out: str) -> Dict[str, Any]:
    os.makedirs(out, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="s02-vectors-") as tmp:
        for t in TRACKS:
            rows.append(build_track(tmp, t, out))
        # PCM S16BE: no codec, the bytes are the big-endian source
        pairs = oracle.signal(PCM["rate"] // SECONDS_HALF, PCM["seeds"][0], PCM["seeds"][1], 0, 16)
        blob = oracle.pcm_be16(pairs)
        with open(os.path.join(out, PCM["file"]), "wb") as f:
            f.write(blob)
        rows.append({"id": PCM["id"], "codec": "pcm", "container": "raw-bytes", "rate_hz": PCM["rate"], "bits": 16, "channels": 2,
                     "mandatory_for": "airplay", "source": {"frames": len(pairs), "seeds": PCM["seeds"], "fnv1a64": f"{oracle.fnv1a64(oracle.pcm_le(pairs, 16)):016x}"},
                     "file": PCM["file"], "bytes": len(blob), "sha256": oracle.sha256(blob), "expected_frames": len(pairs),
                     "endian": "big", "lossless": {"equals_source_in": ["definition"]}, "preroll": PREROLL["pcm"]})
        # negative: AAC-LC 5.1 (6 channels) made by ffmpeg's aac encoder; the adapter must refuse it BEFORE decoding
        wav6 = os.path.join(tmp, "six.wav")
        oracle.write_wav(wav6, oracle.signal(24000, 20, 21, 0, 16), 48000, 16)
        adts6 = os.path.join(tmp, "six.aac")
        run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", wav6, "-ac", "6", "-c:a", "aac", "-b:a", "192k", "-f", "adts", adts6])
        p6 = oracle.adts_frames(open(adts6, "rb").read())
        blob6 = b"".join(p6["frames"])
        with open(os.path.join(out, NEGATIVE["file"]), "wb") as f:
            f.write(blob6)
        rows.append({"id": NEGATIVE["id"], "codec": "aac", "container": "raw-packets", "rate_hz": 48000, "channels": p6["channel_config"], "negative": True,
                     "why": NEGATIVE["why"], "file": NEGATIVE["file"], "bytes": len(blob6), "sha256": oracle.sha256(blob6),
                     "packets": {"sizes": [len(p) for p in p6["frames"]]}, "asc_hex": p6["asc"].hex(),
                     "encoder": {"name": "ffmpeg native aac", "args": "-ac 6 -c:a aac -b:a 192k -f adts"}, "expect": "refused_before_decode"})
        # chained streams: a rate change in the middle of one file
        by = {r["id"]: r for r in rows}
        for chain_id, first, second, ext in (("chain_vorbis_44100_48000", "vorbis_44100", "vorbis_48000", "ogg"),
                                              ("chain_mp3_44100_48000", "mp3_44100", "mp3_48000", "mp3")):
            a = open(os.path.join(out, by[first]["file"]), "rb").read()
            b = open(os.path.join(out, by[second]["file"]), "rb").read()
            name = f"{chain_id}.{ext}"
            with open(os.path.join(out, name), "wb") as f:
                f.write(a + b)
            rows.append({"id": chain_id, "codec": by[first]["codec"], "container": by[first]["container"], "negative": True, "file": name,
                         "bytes": len(a) + len(b), "sha256": oracle.sha256(a + b), "parts": [first, second],
                         "first_part_bytes": len(a), "first_part_frames": by[first]["expected_frames"],
                         "expect": "format_changed_explicit_after_the_first_part"})
        doc = {"schema": SCHEMA, "tracks": rows, "tolerance_lossy": LOSSY_TOLERANCE, "tools": tool_versions(),
               "note": ("Half-second COMPLETE files (header to end), not music: they exercise whole-file decode, gapless length, seek and "
                        "rate change; they are not a claim about real-length tracks or about any board. Generated by tests/s02/make_vectors.py.")}
    with open(os.path.join(out, MANIFEST), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    return doc


# ------------------------------------------------------------------------------------------------ --check (needs no encoder)

def check(vec_dir: str) -> List[str]:
    """Re-derive every fact in the manifest from the committed files' own bytes. Returns the problems (empty = consistent)."""
    problems: List[str] = []
    path = os.path.join(vec_dir, MANIFEST)
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as err:
        return [f"manifest unreadable: {err}"]
    if doc.get("schema") != SCHEMA:
        problems.append(f"schema {doc.get('schema')!r}")
    files = set()
    for t in doc.get("tracks", []):
        tid = t.get("id", "?")
        fp = os.path.join(vec_dir, t["file"])
        files.add(t["file"])
        try:
            blob = open(fp, "rb").read()
        except OSError as err:
            problems.append(f"{tid}: {err}")
            continue
        if len(blob) != t["bytes"] or oracle.sha256(blob) != t["sha256"]:
            problems.append(f"{tid}: file does not match the manifest bytes/sha256")
            continue
        codec = t["codec"]
        try:
            if codec == "vorbis" and not t.get("negative"):
                s = oracle.ogg_streams(blob)
                if len(s) != 1 or s[0]["last_granule"] != t["expected_frames"]:
                    problems.append(f"{tid}: Ogg end granule {s[0]['last_granule']} != expected_frames {t['expected_frames']}")
                ident = oracle.vorbis_ident(blob)
                if (ident["rate"], ident["channels"]) != (t["rate_hz"], 2):
                    problems.append(f"{tid}: Vorbis identification header says {ident}")
            elif codec == "mp3" and not t.get("negative"):
                info = oracle.mp3_frames(blob)
                if info["rate"] != t["rate_hz"] or info["tail_bytes"] != 0:
                    problems.append(f"{tid}: MP3 frame walk says rate {info['rate']}, tail {info['tail_bytes']}")
                if "enc_delay" in info:
                    audio_frames = info["frames"] - (1 if "xing_tag" in info else 0)   # the Xing/Info frame carries no audio
                    total = audio_frames * 1152 - info["enc_delay"] - info["enc_padding"]
                    if t["expected_frames"] != total:
                        problems.append(f"{tid}: LAME gapless fields give {total} frames, expected_frames {t['expected_frames']}")
                else:
                    problems.append(f"{tid}: no LAME gapless fields in the first frame")
            elif codec in ("alac", "aac") and not t.get("negative"):
                sizes = t["packets"]["sizes"]
                if sum(sizes) != len(blob):
                    problems.append(f"{tid}: packet sizes sum {sum(sizes)} != file {len(blob)}")
                if codec == "alac":
                    f = oracle.alac_cookie_fields(bytes.fromhex(t["cookie_hex"]))
                    if (f["sample_rate"], f["bit_depth"], f["channels"]) != (t["rate_hz"], t["bits"], 2):
                        problems.append(f"{tid}: cookie says {f}")
                else:
                    asc = int.from_bytes(bytes.fromhex(t["asc_hex"]), "big")
                    if (asc >> 11, oracle.ADTS_RATES[(asc >> 7) & 15], (asc >> 3) & 15) != (2, t["rate_hz"], 2):
                        problems.append(f"{tid}: ASC {asc:04x} does not say AAC-LC/{t['rate_hz']}/2ch")
                    if t["expected_frames"] != 1024 * len(sizes):
                        problems.append(f"{tid}: expected_frames != 1024 x packets")
            elif codec == "aac" and t.get("negative"):
                asc = int.from_bytes(bytes.fromhex(t["asc_hex"]), "big")
                if (asc >> 3) & 15 != 6:
                    problems.append(f"{tid}: not a 6-channel stream")
            elif t.get("parts"):
                parts = [x for x in doc["tracks"] if x["id"] in t["parts"]]
                joined = b"".join(open(os.path.join(vec_dir, p["file"]), "rb").read() for p in parts)
                if joined != blob:
                    problems.append(f"{tid}: not the concatenation of its parts")
        except (ValueError, KeyError, IndexError) as err:
            problems.append(f"{tid}: {type(err).__name__}: {err}")
        # the source rule: lossless tracks and PCM equal the regenerated signal; lossy references have the stated frame count
        if "source" in t and "lossless" in t:
            bits = t["bits"]
            pairs = oracle.signal(t["source"]["frames"], t["source"]["seeds"][0], t["source"]["seeds"][1], t["source"]["seeds"][2], bits)
            if f"{oracle.fnv1a64(oracle.pcm_le(pairs, bits)):016x}" != t["source"]["fnv1a64"]:
                problems.append(f"{tid}: the source signal rule no longer reproduces the recorded fnv1a64")
            if codec == "pcm" and oracle.pcm_be16(pairs) != blob:
                problems.append(f"{tid}: PCM bytes are not the big-endian source")
        if "reference" in t:
            ref_path = os.path.join(vec_dir, t["reference"]["file"])
            files.add(t["reference"]["file"])
            try:
                ref = open(ref_path, "rb").read()
            except OSError as err:
                problems.append(f"{tid}: {err}")
                continue
            if oracle.sha256(ref) != t["reference"]["sha256"] or len(ref) // 4 != t["expected_frames"]:
                problems.append(f"{tid}: reference file does not match the manifest")
    for t in doc.get("tracks", []):
        if "retained_bad_reference" in t:
            rb = t["retained_bad_reference"]
            files.add(rb["file"])
            try:
                blob = open(os.path.join(vec_dir, rb["file"]), "rb").read()
            except OSError as err:
                problems.append(f"{t['id']}: {err}")
                continue
            if oracle.sha256(blob) != rb["sha256"] or len(blob) != rb["bytes"]:
                problems.append(f"{t['id']}: the retained bad reference does not match the manifest")
    # s02_bridge_vectors.json belongs to the rate bridge, not to a decode track: it is derived and checked by bridge_reference.py.
    extra = sorted(set(os.listdir(vec_dir)) - files - {MANIFEST, "s02_bridge_vectors.json"})
    if extra:
        problems.append(f"files in the vectors directory that the manifest does not name: {extra}")
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=VEC_DIR)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--reuse-vorbis-streams", metavar="DIR", default=None,
                    help="use the already-encoded Vorbis streams in DIR (the committed ones) instead of encoding new ones: ffmpeg's Vorbis encoder is not reproducible")
    ap.add_argument("--vorbis-python", default=os.environ.get("S02_VORBIS_PYTHON"),
                    help="a Python with numpy and soundfile, for the libvorbis decode (generation only; default $S02_VORBIS_PYTHON)")
    args = ap.parse_args(argv)
    global VORBIS_PYTHON, REUSE_VORBIS_DIR
    VORBIS_PYTHON = args.vorbis_python
    REUSE_VORBIS_DIR = args.reuse_vorbis_streams
    if args.check:
        problems = check(args.out)
        for p in problems:
            print("PROBLEM", p)
        print("s02 vectors: " + ("consistent with the manifest and with their own bytes" if not problems else f"{len(problems)} problem(s)"))
        return 1 if problems else 0
    if os.path.exists(os.path.join(args.out, MANIFEST)):
        print(f"refusing to overwrite {args.out}/{MANIFEST}: choose a new --out", file=sys.stderr)
        return 2
    doc = build_all(args.out)
    print(f"wrote {len(doc['tracks'])} tracks to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
