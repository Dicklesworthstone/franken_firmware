"""One offline execution of already-built P05 Linux ELFs; no compiler or provider access."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

root = Path(__file__).resolve().parent
capture = runpy.run_path(str(root / "toolchain/src/run-qemu-verification.py"))["capture_guest"]
results = root / "results"
results.mkdir()
failed = False
expected = {"tests": "c6eb220ad8c55d5db6b5d856c8bcbfa320916a3f69baf7d43d4eae192d5269ca",
            "standalone": "fe3b20f7cea5385472b34d132cab2a81cf275c340c7c10a9d0e659513964eacd"}
for name, argv in (
    ("tests", [str(root / "p05-native-tests"), "--test-threads=1", "--nocapture"]),
    ("standalone", [str(root / "p05-native")]),
):
    before = hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest()
    if before != expected[name]:
        raise ValueError(name + " ELF differs from the linked artifact; not executed")
    result = capture(argv, dict(os.environ), 180, max_bytes=1024 * 1024,
                     capture_paths={stream: results / (name + "." + stream)
                                    for stream in ("stdout", "stderr")})
    after = hashlib.sha256(Path(argv[0]).read_bytes()).hexdigest()
    observed = {"returncode": result["returncode"], "stop_reason": result["stop_reason"],
                "elf_sha256_before": before, "elf_sha256_after": after,
                **{stream + "_sha256": hashlib.sha256(result[stream]).hexdigest()
                   for stream in ("stdout", "stderr")}}
    with (results / (name + ".capture.json")).open("x") as output:
        json.dump(observed, output, sort_keys=True)
        output.write("\n")
    print(name, json.dumps(observed, sort_keys=True), flush=True)
    failed |= result["returncode"] != 0 or result["stop_reason"] is not None or after != before
sys.exit(1 if failed else 0)
