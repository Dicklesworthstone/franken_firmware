#!/usr/bin/env python3
"""Judge the logs of the N01 fuzz runs (docs/contracts/n01.md section 11).

A fuzz run proves nothing by exiting quietly: a run that executed nothing, stopped early, or never read its seeds also
exits quietly. This judge holds the libFuzzer log of each central run to what a real run leaves behind, and holds the
CONTROL run (the build with the planted bug) to finding that bug within the same budget, on an input that really triggers
it. It reads logs and one crash input; it runs no fuzzer and no Rust.

    fuzz_judge.py seeds SEEDS_LOG
    fuzz_judge.py run LOG --target T --kind clean|control --budget SECONDS
                      [--min-execs N] [--seeds-log SEEDS_LOG] [--crash FILE]

Exit 0 only if every check holds; the record of what was judged (executions, coverage, crashes) is printed as JSON.
The `control` kind is supported for `stream_decode` only, the target the planted bug lives behind. The crash input is the
file given with --crash or, without one, the `Base64:` line libFuzzer prints under 'Test unit written to' (only for inputs of
at most 256 bytes); either way it is held to the same checks.

Why a crash input is re-checked here: a panic in the control run could be an oracle failing for some other reason.
The planted bug fires only for an ACCEPTED packet with a payload of exactly CONTROL_PAYLOAD_LEN bytes, so the judge
rebuilds the datagram the target was handed (the target's own "re-sign" rule, re-derived here) and decodes it with the
independent Python decoder; the crash input has to be exactly such a packet.
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_frames as rf  # noqa: E402

TARGETS = ("stream_decode", "stream_receiver", "negotiation_respond", "negotiation_finish")
CONTROL_TARGET = "stream_decode"
CONTROL_PAYLOAD_LEN = 516
PLANT_MESSAGE = "planted decoder bug: payload length"
MODE_RESIGN = 1
RESIGN_PAYLOAD_CAP = 2 * rf.MAX_PAYLOAD
DEFAULT_MIN_EXECS = 50_000

SEEDS_RE = re.compile(r"^N01-FUZZ-SEEDS (\w+) files=(\d+) max_bytes=(\d+)$", re.M)
DONE_RE = re.compile(r"^Done (\d+) runs in (\d+) second\(s\)", re.M)
CORPUS_RE = re.compile(r"^INFO: seed corpus: files: (\d+)", re.M)
STATUS_RE = re.compile(r"^#(\d+)\s+(INITED|NEW|REDUCE|pulse|DONE|RELOAD)\s+cov: (\d+) ft: (\d+) corp: (\d+)/", re.M)
PLANT_RE = re.compile(re.escape(PLANT_MESSAGE) + r" (\d+)")
ARTIFACT_RE = re.compile(r"Test unit written to (\S+crash-[0-9a-f]{40})")
BASE64_RE = re.compile(r"Test unit written to \S+crash-[0-9a-f]{40}\s+Base64: ([A-Za-z0-9+/]+={0,2})")
CRASH_MARKERS = ("ERROR: libFuzzer", "deathly signal", "panicked at", "SUMMARY: libFuzzer", "Test unit written")


def load_key():
    doc = json.loads(rf.DEFAULT_VECTORS.read_text(encoding="utf-8"))
    return bytes.fromhex(doc["key_hex"])


def resign(key, data):
    """The target's own re-sign rule: header = first 64 bytes (zero-padded), payload = the rest cut or zero-padded to
    the declared length (capped), tag recomputed."""
    header = bytes(data[: rf.HEADER_LEN]).ljust(rf.HEADER_LEN, b"\0")
    declared = min(int.from_bytes(header[62:64], "big"), RESIGN_PAYLOAD_CAP)
    payload = bytes(data[rf.HEADER_LEN:])[:declared].ljust(declared, b"\0")
    return header + payload + rf.tag(key, header, payload)


def datagram_for(key, data):
    mode, rest = (data[0], data[1:]) if data else (0, b"")
    return resign(key, rest) if mode == MODE_RESIGN else bytes(rest)


def triggers_the_plant(data, key=None):
    """Whether this stream_decode input is an accepted packet with a payload of exactly CONTROL_PAYLOAD_LEN bytes."""
    key = key or load_key()
    datagram = datagram_for(key, data)
    verdict = rf.decode(datagram, key)[0]
    return verdict == "ACCEPT" and len(datagram) - rf.HEADER_LEN - rf.TAG_LEN == CONTROL_PAYLOAD_LEN


def judge_seeds(text):
    """The seed-corpus manifest: each target exactly once, with at least one file. Returns (problems, {target: files})."""
    problems, files = [], {}
    for target, count, _ in SEEDS_RE.findall(text):
        if target in files:
            problems.append("seed manifest names %s twice" % target)
        files[target] = int(count)
    for target in TARGETS:
        if target not in files:
            problems.append("seed manifest has no line for %s" % target)
        elif files[target] < 1:
            problems.append("target %s was given no seeds" % target)
    for target in files:
        if target not in TARGETS:
            problems.append("seed manifest names an unknown target %s" % target)
    return problems, files


def crash_in_log(text):
    """The crashing input as libFuzzer printed it after 'Test unit written to ...' (it prints one only when the input is at most
    256 bytes), or None when the log has none or it is not base64. It is judged exactly like a supplied crash file."""
    found = BASE64_RE.search(text)
    if not found:
        return None
    try:
        return base64.b64decode(found.group(1), validate=True)
    except ValueError:
        return None


def status_numbers(text):
    return [(int(a), s, int(c), int(f), int(k)) for a, s, c, f, k in STATUS_RE.findall(text)]


def judge_run(text, target, kind, budget, min_execs=DEFAULT_MIN_EXECS, seed_files=None, crash=None):
    """Judge one libFuzzer log. Returns (problems, record)."""
    problems = []
    record = {"target": target, "kind": kind, "budget_seconds": budget}
    if target not in TARGETS:
        problems.append("unknown target %s" % target)
    if kind not in ("clean", "control"):
        problems.append("kind must be clean or control, not %s" % kind)
    if kind == "control" and target != CONTROL_TARGET:
        problems.append("the planted bug is behind %s only; %s has no control" % (CONTROL_TARGET, target))
    status = status_numbers(text)
    done = DONE_RE.search(text)
    corpus = CORPUS_RE.search(text)
    crashed = [marker for marker in CRASH_MARKERS if marker in text]
    if status:
        record["coverage"] = status[-1][2]
        record["features"] = status[-1][3]
        record["corpus_units"] = status[-1][4]
        record["last_status_execs"] = status[-1][0]
    if corpus:
        record["seed_files_read"] = int(corpus.group(1))

    if kind == "clean":
        if crashed:
            problems.append("a clean run shows a crash: %s" % ", ".join(crashed))
        if not done:
            problems.append("no 'Done N runs' line: the run did not finish")
        else:
            record["executions"] = int(done.group(1))
            record["seconds"] = int(done.group(2))
            if int(done.group(1)) < min_execs:
                problems.append("only %s executions, fewer than the floor %d" % (done.group(1), min_execs))
            if int(done.group(2)) < budget:
                problems.append("the run stopped after %s s, before its %d s budget" % (done.group(2), budget))
        if not status:
            problems.append("no coverage status lines")
        elif status[-1][2] < 1:
            problems.append("coverage is zero: the target was not instrumented or not reached")
        initial = [s for s in status if s[1] == "INITED"]
        if status and not initial:
            problems.append("no INITED line: the seed corpus was never loaded")
        elif initial and status[-1][2] < initial[0][2]:
            problems.append("coverage fell from %d to %d" % (initial[0][2], status[-1][2]))
        if not corpus:
            problems.append("no 'seed corpus: files' line: the run started without seeds")
        elif seed_files is not None and int(corpus.group(1)) < seed_files:
            problems.append("read %s seed files, the manifest has %d" % (corpus.group(1), seed_files))
        record["crashes"] = 0 if not crashed else len(crashed)
    else:
        planted = PLANT_RE.search(text)
        if done:
            problems.append("the control run finished without a crash: the planted bug was not found in the budget")
        if "panicked at" in text and not planted:
            problems.append("the control run crashed, but not on the planted bug")
        if not planted:
            problems.append("no planted-bug panic message in the control log")
        elif int(planted.group(1)) != CONTROL_PAYLOAD_LEN:
            problems.append("the panic names payload length %s, not %d" % (planted.group(1), CONTROL_PAYLOAD_LEN))
        if "ERROR: libFuzzer" not in text and "deathly signal" not in text:
            problems.append("libFuzzer did not report the crash")
        artifact = ARTIFACT_RE.search(text)
        if not artifact:
            problems.append("no 'Test unit written to ...crash-<sha1>' line: the crashing input was not kept")
        else:
            record["artifact"] = Path(artifact.group(1)).name
        crash_source = "file"
        if crash is None:
            crash, crash_source = crash_in_log(text), "log"
        if crash is None:
            problems.append("no crash input: it was not supplied as a file and libFuzzer did not print it in the log")
        else:
            record["crash_source"] = crash_source
            record["crash_bytes"] = len(crash)
            record["crash_sha256"] = hashlib.sha256(crash).hexdigest()
            if artifact and hashlib.sha1(crash).hexdigest() != Path(artifact.group(1)).name[len("crash-"):]:
                problems.append("the crash file is not the artifact the log names (SHA-1 differs)")
            if not triggers_the_plant(crash):
                problems.append("the crash input is not an accepted packet of %d payload bytes" % CONTROL_PAYLOAD_LEN)
        record["crashes"] = 1 if planted else 0
    return problems, record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    seeds = sub.add_parser("seeds")
    seeds.add_argument("log")
    run = sub.add_parser("run")
    run.add_argument("log")
    run.add_argument("--target", required=True)
    run.add_argument("--kind", required=True, choices=("clean", "control"))
    run.add_argument("--budget", type=int, required=True)
    run.add_argument("--min-execs", type=int, default=DEFAULT_MIN_EXECS)
    run.add_argument("--seeds-log")
    run.add_argument("--crash")
    args = ap.parse_args(argv)
    if args.cmd == "seeds":
        problems, files = judge_seeds(Path(args.log).read_text(encoding="utf-8", errors="replace"))
        print(json.dumps({"seed_files": files, "problems": problems}, sort_keys=True))
        return 1 if problems else 0
    seed_files = None
    if args.seeds_log:
        problems, files = judge_seeds(Path(args.seeds_log).read_text(encoding="utf-8", errors="replace"))
        if problems:
            print(json.dumps({"problems": problems}, sort_keys=True))
            return 1
        seed_files = files.get(args.target)
    crash = Path(args.crash).read_bytes() if args.crash else None
    problems, record = judge_run(Path(args.log).read_text(encoding="utf-8", errors="replace"), args.target, args.kind,
                                 args.budget, args.min_execs, seed_files, crash)
    record["problems"] = problems
    print(json.dumps(record, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
