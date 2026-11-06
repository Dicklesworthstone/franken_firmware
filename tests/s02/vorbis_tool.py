#!/usr/bin/env python3
"""Helper for make_vectors.py and the reference controls: decode Ogg Vorbis with libvorbis, through libsndfile (python-soundfile).

Run it under a Python that has numpy and soundfile (a private venv is fine); make_vectors.py takes that interpreter with `--vorbis-python` or the
environment variable S02_VORBIS_PYTHON. Only vector GENERATION and the optional reference controls need this; `make_vectors.py --check` and every judge
need neither soundfile nor ffmpeg.

    vorbis_tool.py versions                 one JSON line: soundfile, libsndfile, and the vendor string of the libvorbis build (read from a stream it writes)
    vorbis_tool.py decode IN.ogg OUT.s16    libvorbis decode to interleaved little-endian 16-bit (round to nearest, clamp); OUT must not exist

libvorbis is the Xiph reference implementation. It is a SECOND, independent decoder next to ffmpeg for the Vorbis references: ffmpeg's scalar decode and this
one agree within 1 LSB on the S02 streams, while ffmpeg's default optimised decode of the same streams does not (it is about 950 LSB rms away).
"""
import json
import os
import struct
import sys
import tempfile


def vendor(blob: bytes) -> str:
    pos = blob.index(b"\x03vorbis") + 7
    (length,) = struct.unpack_from("<I", blob, pos)
    return blob[pos + 4:pos + 4 + length].decode("utf-8", "replace")


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    import numpy as np
    import soundfile as sf
    if argv[0] == "versions":
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "probe.ogg")
            with sf.SoundFile(path, "x", samplerate=44100, channels=2, format="OGG", subtype="VORBIS") as f:
                f.write(np.zeros((2048, 2), dtype=np.int16))
            with open(path, "rb") as f:
                libvorbis = vendor(f.read())
        print(json.dumps({"soundfile": sf.__version__, "libsndfile": sf.__libsndfile_version__, "libvorbis": libvorbis}))
        return 0
    if argv[0] == "decode" and len(argv) == 3:
        data, _rate = sf.read(argv[1], dtype="float64", always_2d=True)
        s16 = np.clip(np.round(data * 32768.0), -32768, 32767).astype("<i2")
        with open(argv[2], "xb") as f:
            f.write(s16.tobytes())
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
