#!/usr/bin/env python3
"""Generate a new >N04-horizon MP3 fixture without modifying S02 vectors.

Requires installed FFmpeg with libmp3lame. Writes only a new output directory;
retains its intermediate input and complete commands. Never emits physical audio.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crates/franken-codec/tests/vectors/mp3_48000.ref.s16"
SOURCE_SHA = "4e20de020e5cbc629e58d92097a6f46934160f1f68f9eb4619b073947d35a90b"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    source = SOURCE.read_bytes()
    if len(source) != 96000 or hashlib.sha256(source).hexdigest() != SOURCE_SHA:
        raise ValueError("original public scalar reference changed")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    raw = args.output_dir / "loop-input.s16"
    raw.write_bytes(source * 3)
    encoded = args.output_dir / "mp3_48000_long.mp3"
    reference = args.output_dir / "mp3_48000_long.ref.s16"
    commands = [
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-n", "-f", "s16le", "-ar", "48000",
         "-ac", "2", "-i", str(raw), "-map_metadata", "-1", "-c:a", "libmp3lame", "-b:a", "192k",
         "-threads", "1", str(encoded)],
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-n", "-cpuflags", "0", "-i", str(encoded),
         "-map_metadata", "-1", "-f", "s16le", "-c:a", "pcm_s16le", str(reference)],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=30)
    if reference.stat().st_size != 72000 * 4:
        raise ValueError("independent decode frame count differs from 72000")
    version = subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True,
                             check=True, timeout=5).stdout.splitlines()[0]
    def digest(path):
        data = path.read_bytes()
        return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    row = {"id": "mp3_48000_long", "codec": "mp3", "rate_hz": 48000, "channels": 2,
           "expected_frames": 72000, **digest(encoded),
           "reference": {**digest(reference), "frames": 72000, "decoder": "scalar FFmpeg"},
           "tolerance": {"max_abs_lsb": 4, "rms_lsb": 1.5},
           "source_reference_sha256": SOURCE_SHA, "source_repetitions": 3,
           "generator_version": version,
           "commands": [[Path(token).name if token.startswith(str(args.output_dir)) else token
                          for token in command] for command in commands]}
    (args.output_dir / "long_vectors.json").write_text(json.dumps({"tracks": [row]}, indent=2, sort_keys=True) + "\n")
    print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
