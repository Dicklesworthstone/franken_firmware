#!/usr/bin/env python3
"""Self-tests for toolchain/src/measure-p05-target.py (the judge of P05's big-endian MIPS guest).

No guest, no QEMU and no Rust is involved. A BASELINE transcript is formatted here, by an encoder written separately from the
judge's, from the independent reference and from hand-written values; the judge must accept it. Then, for every gate, one PLANT
corrupts exactly what that gate checks while leaving every other gate satisfied, and the judge must fail exactly that gate; and
removing the plant (the control) must pass again. A plant that trips two detectors would stay red after one were deleted, so each
is asserted to fail ONLY its own gate.

    python3 -B -m unittest discover -s toolchain/tests -p 'test_measure_p05_target.py'
"""
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE.parent / "src" / "measure-p05-target.py"
spec = importlib.util.spec_from_file_location("measure_p05_target_under_test", SCRIPT)
judge_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = judge_mod
spec.loader.exec_module(judge_mod)

REPO = judge_mod.REPO
REF = judge_mod.reference(REPO)
SEED = 987654321
ELF = {"sha256": "0" * 64, "bytes": 1, "e_type": 2, "machine": 8, "e_flags": 0}


# ---- a SECOND encoder, written separately from the judge's: dispatch tables instead of if-chains ------------------------

def _hex(n):
    return format(n, "x")


OP_FORMAT = {"load": lambda o: "L", "store": lambda o: "S" + _hex(o[1]), "cas": lambda o: "C" + _hex(o[1]) + "." + _hex(o[2]),
             "add": lambda o: "A" + _hex(o[1])}
RESP_FORMAT = {"value": lambda r: "V" + _hex(r[1]), "stored": lambda r: "T", "cas_ok": lambda r: "Co" + _hex(r[1]),
               "cas_err": lambda r: "Ce" + _hex(r[1]), "add_ok": lambda r: "Ao" + _hex(r[1]),
               "add_overflow": lambda r: "Af" + _hex(r[1]) + "." + _hex(r[2])}


def enc_history(events):
    parts = []
    for e in events:
        parts.append("t" + str(e.thread) + ":" + str(e.inv) + ":" + str(e.res) + ":" + OP_FORMAT[e.op[0]](e.op) + ":" +
                     RESP_FORMAT[e.resp[0]](e.resp))
    return ";".join(parts)


def fnv(data, state=14695981039346656037):
    for b in bytearray(data):
        state = ((state ^ b) * 1099511628211) % (1 << 64)
    return state


def sweep_line(group, kind, first, seeds=256, threads=3, ops=4):
    digest, viol, inc = 14695981039346656037, [], 0
    for seed in range(first, first + seeds):
        events = REF.seeded_run(kind, seed, threads, ops)
        verdict = REF.check(REF.INITIAL, events, 200000)
        mark = {"linearizable": "L", "not_linearizable": "N", "inconclusive": "I"}[verdict]
        if mark == "N":
            viol.append(seed)
        if mark == "I":
            inc += 1
        digest = fnv((_hex(seed) + "|" + mark + "|" + enc_history(events) + "\n").encode(), digest)
    head = ",".join(str(s) for s in viol[:8]) or "-"
    return (f"FFW_P05T_SWEEP set={group} kind={kind} first_seed={first} seeds={seeds} violations={len(viol)} "
            f"inconclusive={inc} head={head} digest={digest:016x}")


def directed_line(name, kind):
    initial, plans, picks = REF.scenario(name)
    events = REF.scripted_run(kind, initial, plans, picks)
    mark = {"linearizable": "L", "not_linearizable": "N", "inconclusive": "I"}[REF.check(initial, events, 200000)]
    return (f"FFW_P05T_DIRECTED name={name} kind={kind} verdict={mark} loaded={_hex(REF.load_value(events))} "
            f"history={enc_history(events)}")


def vec_lines():
    return [f"FFW_P05T_VEC id={name} r={','.join(tokens)}" for name, tokens in judge_mod.VECTOR_EXPECTED.items()]


def baseline_text(seed=SEED, repo=REPO):
    lines = ["[    0.000000] Linux version 4.19.0-21-4kc-malta", "FFW_P05T_ALIVE",
             "FFW_P05T_BEGIN version=1 threads=3 ops=4 seeds=256 budget=200000 threaded_budget=2000000",
             "FFW_P05T_ENV target_arch=mips target_endian=big pointer_width=32 target_os=linux size_usize=4 size_u64=8 "
             "ne_u32=01020304 ne_u64=0102030405060708",
             "FFW_P05T_SYS sysname=Linux release=4.19.0-21-4kc-malta machine=mips"]
    for name, rel in judge_mod.SOURCE_FILES:
        data = (repo / rel).read_bytes()
        lines.append(f"FFW_P05T_SRC file={name} bytes={len(data)} fnv={fnv(data):016x}")
    lines.append(f"FFW_P05T_SEED value={seed}")
    lines += vec_lines()
    for kind in ("good", "split", "trunc"):
        lines.append(sweep_line("pinned", kind, 0))
    for kind in ("good", "split", "trunc"):
        lines.append(sweep_line("seeded", kind, seed))
    for name in ("torn_store", "torn_carry", "truncated_store"):
        for kind in ("good", "split", "trunc"):
            lines.append(directed_line(name, kind))
    lines += [
        f"FFW_P05T_THREADED first_seed={seed} seeds=24 threads=3 ops=5 linearizable=24 not=0 inconclusive=0",
        "FFW_P05T_TICKETS threads=4 per=2000 total=8000 duplicates=0 out_of_range=0 complete=1 increasing=1 final=1f40",
        "FFW_P05T_CASLOOP start=fffff000 threads=4 per=2000 final=100000f40 crossed=1",
        "FFW_P05T_OVERFLOWRACE threads=8 attempts=10 oks=fffffffffffffffc,fffffffffffffffd,fffffffffffffffe errors=77 "
        "all_typed=1 final=ffffffffffffffff",
        "FFW_P05T_SEQRACE span=100 threads=4 issued=100 exact=1 next_err=1 peek=ffffffffffffffff",
        "FFW_P05T_MONOTONE start=ffffff00 adds=512 reads=3141 backwards=0 final=100000100 crossed=1",
        "FFW_P05T_INFO what=naive_two_word_store_tear reads=88888 torn=0", "FFW_P05T_END"]
    return "\n".join(lines) + "\n"


_CACHE = {}


def baseline(seed=SEED):
    if seed not in _CACHE:
        _CACHE[seed] = baseline_text(seed)
    return _CACHE[seed]


def failed_gates(text, seed=SEED, elf=ELF):
    report = judge_mod.judge(text, elf, seed)
    return {g.gate_id for g in report["gates"] if g.status == "failed"}


def sub1(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new)


# ---- plain-integer evaluator of the same vector programs, to check the hand-written table independently ------------------

M = (1 << 64) - 1


class Cell:
    def __init__(self, value, signed=False):
        self.v, self.signed = value & M, signed

    def _signed(self, x):
        return x - (1 << 64) if x >= (1 << 63) else x

    def load(self):
        return self.v

    def store(self, x):
        self.v = x & M

    def swap(self, x):
        old, self.v = self.v, x & M
        return old

    def _checked(self, delta, sign):
        cur = self._signed(self.v) if self.signed else self.v
        d = self._signed(delta & M) if self.signed else delta
        total = cur + sign * d
        lo, hi = (-(1 << 63), (1 << 63) - 1) if self.signed else (0, M)
        if lo <= total <= hi:
            old = self.v
            self.v = total & M
            return ("ok", old)
        return ("of" if total > hi else "uf", self.v, delta & M)

    def add(self, d):
        return self._checked(d, 1)

    def sub(self, d):
        return self._checked(d, -1)

    def add_wrapping(self, d):
        old = self.v
        self.v = (self.v + d) & M
        return old

    def sub_wrapping(self, d):
        old = self.v
        self.v = (self.v - d) & M
        return old

    def cas(self, current, new):
        if self.v == current & M:
            old, self.v = self.v, new & M
            return ("cx_ok", old)
        return ("cx_err", self.v)

    def fmax(self, x):
        old = self.v
        a, b = (self._signed(old), self._signed(x & M)) if self.signed else (old, x & M)
        if b > a:
            self.v = x & M
        return old

    def fmin(self, x):
        old = self.v
        a, b = (self._signed(old), self._signed(x & M)) if self.signed else (old, x & M)
        if b < a:
            self.v = x & M
        return old

    def fand(self, x):
        old, self.v = self.v, self.v & x
        return old

    def forr(self, x):
        old, self.v = self.v, self.v | x
        return old


def tv(x):
    return "v:" + _hex(x)


def tchecked(result):
    if result[0] == "ok":
        return "ok:" + _hex(result[1])
    return f"{result[0]}:{_hex(result[1])}/{_hex(result[2])}"


def tcx(result):
    return result[0] + ":" + _hex(result[1])


def evaluate_vectors():
    out = {}
    t, c, prev = [], Cell(0), 0
    for x in (0, 1, 0xFFFFFFFF, 0x100000000, 0x100000001, 0xFFFFFFFF00000000, 1 << 63, 0x0123456789ABCDEF, M):
        c.store(x)
        t += [tv(c.load()), tv(c.swap(prev)), tv(c.load())]
        prev = x
    t += [tv(0), tv(0xABCDEF0123456789), tv(0x100000007)]
    out["load_store_roundtrip"] = t
    t = []
    for start, delta in ((0xFFFFFFFF, 1), (5, 0x100000000), (0x1FFFFFFF0, 0x20)):
        c = Cell(start)
        t += [tchecked(c.add(delta)), tv(c.load())]
    out["add_carry"] = t
    c = Cell(M - 1)
    t = [tchecked(c.add(1)), tv(c.load()), tchecked(c.add(1)), tv(c.load()), tchecked(c.add(0))]
    c = Cell(1)
    t += [tchecked(c.add(M)), tv(c.load())]
    out["add_overflow"] = t
    c = Cell(1)
    t = [tchecked(c.sub(1)), tv(c.load()), tchecked(c.sub(1)), tv(c.load()), tchecked(c.sub(0))]
    c = Cell(0x100000000)
    t += [tchecked(c.sub(1)), tv(c.load())]
    out["sub_underflow"] = t
    c = Cell(M)
    t = [tv(c.add_wrapping(2)), tv(c.load())]
    c = Cell(0)
    t += [tv(c.sub_wrapping(1)), tv(c.load())]
    c = Cell(M)
    t += [tchecked(c.add(2)), tv(c.load())]
    out["wrapping"] = t
    c = Cell(0x100000001)
    out["cas_full_width"] = [tcx(c.cas(1, 9)), tv(c.load()), tcx(c.cas(0x100000001, 9)), tv(c.load()), tcx(c.cas(9, 9)),
                             tcx(c.cas(0, 1))]
    c = Cell(5)
    t = [tv(c.fmax(0x100000000)), tv(c.load()), tv(c.fmax(3)), tv(c.load()), tv(c.fmin(7)), tv(c.load()), tv(c.fmin(9)),
         tv(c.load())]
    c = Cell(0xF0F0F0F0F0F0F0F0)
    t += [tv(c.fand(0xFFFFFFFF00000000)), tv(c.load()), tv(c.forr(0x0F0F0F0F)), tv(c.load())]
    out["max_min_bits"] = t
    s = Cell((1 << 63) - 1, signed=True)
    t = [tchecked(s.add(1)), tchecked(s.add(M)), tv(s.load()), tchecked(s.sub(M)), tchecked(s.sub(M))]
    s = Cell(1 << 63, signed=True)
    t += [tchecked(s.add(M)), tchecked(s.sub(1)), tv(s.load()), tchecked(s.sub(M)), tv(s.load())]
    s = Cell(0xFFFFFFFF, signed=True)
    t += [tcx(s.cas(M, 3))]
    s.store((-0x100000000) & M)
    t += [tv(s.load()), tv(s.add_wrapping((1 << 63) - 1))]
    out["i64_range"] = t

    def sequence(first, count):
        issued, nxt, toks = [], first, []
        for _ in range(count):
            if nxt >= M:
                toks.append("ex")
            else:
                toks.append("ok:" + _hex(nxt))
                nxt += 1
        return toks, nxt

    a, _ = sequence(0, 3)
    b1, n = sequence(M - 2, 2)
    b2, n = sequence(n, 2)
    out["sequence"] = a + b1 + [tv(M)] + ["ex", "ex"] + [tv(M)] + ["ex"]
    local = Cell(M - 1)
    t = [tchecked(local.add(1)), tchecked(local.add(1)), tv(local.load()), tv(local.add_wrapping(2)), tv(local.load())]
    local.store(0x100000000)
    t += [tv(local.load()), tv(0), tv(0x100000001)]
    out["local_u64"] = t
    return out


# ---- tests --------------------------------------------------------------------------------------------------------------


class Encoding(unittest.TestCase):
    def test_fnv1a64_matches_the_published_test_vectors(self):
        # Published FNV-1a 64-bit vectors (the two implementations here and the Rust one must all agree with them).
        for data, want in ((b"", 0xCBF29CE484222325), (b"a", 0xAF63DC4C8601EC8C), (b"foobar", 0x85944171F73967E8)):
            self.assertEqual(judge_mod.fnv1a64(data), want)
            self.assertEqual(fnv(data), want)

    def test_the_judges_history_text_equals_the_independent_encoder_and_the_hand_written_anchors(self):
        # Hand-derived BEFORE running anything, from the scheduler rules: the real cell finishes each operation in one step; in the
        # split-word cell the load lands between the two word writes of the store and returns 0x1_FFFF_FFF0.
        anchors = {("torn_store", "good"): "t0:0:1:S100000000:T;t1:1:2:L:V100000000",
                   ("torn_store", "split"): "t1:1:3:L:V1fffffff0;t0:0:4:S100000000:T"}
        for (name, kind), want in anchors.items():
            initial, plans, picks = REF.scenario(name)
            events = REF.scripted_run(kind, initial, plans, picks)
            self.assertEqual(judge_mod.history_text(events), want)
            self.assertEqual(enc_history(events), want)

    def test_both_encoders_agree_on_every_seeded_history(self):
        for kind in ("good", "split", "trunc"):
            for seed in range(0, 40):
                events = REF.seeded_run(kind, seed, 3, 4)
                self.assertEqual(judge_mod.history_text(events), enc_history(events))

    def test_the_hand_written_vector_table_equals_a_plain_integer_evaluation(self):
        self.assertEqual(evaluate_vectors(), judge_mod.VECTOR_EXPECTED)

    def test_the_directed_table_equals_the_reference_for_all_nine_scripts(self):
        for (name, kind), (mark, loaded) in judge_mod.DIRECTED_EXPECTED.items():
            initial, plans, picks = REF.scenario(name)
            events = REF.scripted_run(kind, initial, plans, picks)
            verdict = REF.check(initial, events, 200000)
            self.assertEqual((judge_mod.VERDICT_MARK[verdict], REF.load_value(events)), (mark, loaded), (name, kind))

    def test_the_pinned_sweep_the_judge_expects_is_the_one_hand_pinned_in_vectors_txt(self):
        profile = judge_mod.read_profile(REPO)
        for kind, prefix in (("good", "good"), ("split", "split"), ("trunc", "trunc")):
            facts = judge_mod.expected_sweep(str(REPO), kind, profile["profile_first_seed"][0], profile["profile_seeds"][0],
                                             profile["profile_threads"][0], profile["profile_ops_per_thread"][0])
            self.assertEqual((facts.violations, facts.inconclusive), (profile[prefix + "_violations"][0],
                                                                      profile[prefix + "_inconclusive"][0]))

    def test_the_seeded_counts_depend_on_the_seed_so_a_replay_cannot_match(self):
        a = judge_mod.expected_sweep(str(REPO), "split", 987654321, 256, 3, 4)
        b = judge_mod.expected_sweep(str(REPO), "split", 123456789, 256, 3, 4)
        self.assertNotEqual((a.digest, a.head), (b.digest, b.head))


class Baseline(unittest.TestCase):
    def test_the_baseline_passes_every_gate(self):
        report = judge_mod.judge(baseline(), ELF, SEED)
        self.assertEqual([(g.gate_id, g.status, g.detail) for g in report["gates"] if g.status != "passed"], [])
        self.assertTrue(report["ok"])
        self.assertEqual(judge_mod.exit_code(report), 0)

    def test_kernel_messages_between_marker_lines_are_ignored(self):
        text = baseline().replace("FFW_P05T_SEED", "[   1.5] random: crng init done\nFFW_P05T_SEED")
        self.assertEqual(failed_gates(text), set())

    def test_the_information_line_is_reported_and_never_judged(self):
        text = sub1(baseline(), "reads=88888 torn=0", "reads=88888 torn=57")
        self.assertEqual(failed_gates(text), set())
        self.assertIn("57 torn", judge_mod.render(judge_mod.judge(text, ELF, SEED), None))


class Plants(unittest.TestCase):
    """One plant per gate, each leaving every other gate satisfied; the control is the unplanted baseline."""

    def assertOnly(self, text, gate_id, seed=SEED, elf=ELF):
        self.assertEqual(failed_gates(text, seed, elf), {gate_id})

    def test_a_little_endian_host_transcript_presented_as_the_guests_fails_only_the_env_gate(self):
        planted = judge_mod.plant_host(baseline())
        self.assertNotEqual(planted, baseline())
        self.assertOnly(planted, "P05T-ENV")
        self.assertEqual(failed_gates(baseline()), set())          # remove the plant

    def test_each_env_fact_is_checked_on_its_own(self):
        for old, new in (("target_endian=big", "target_endian=little"), ("pointer_width=32", "pointer_width=64"),
                         ("ne_u32=01020304", "ne_u32=04030201"), ("machine=mips", "machine=mipsel"),
                         ("release=4.19.0-21-4kc-malta", "release=6.8.0-generic"), ("target_arch=mips", "target_arch=mips64")):
            self.assertOnly(sub1(baseline(), old, new), "P05T-ENV")

    def test_a_replayed_transcript_fails_the_seeded_gate_only(self):
        earlier = baseline(111222333)
        planted = judge_mod.plant_replay(baseline(), earlier)
        self.assertNotEqual(planted, baseline())
        self.assertOnly(planted, "P05T-SEEDED")
        self.assertEqual(failed_gates(baseline()), set())

    def test_a_transcript_from_another_run_fails_the_seed_echo_and_the_seeded_sweeps(self):
        self.assertEqual(failed_gates(baseline(111222333), seed=SEED),
                         {"P05T-SEED", "P05T-SEEDED", "P05T-THREADS"})
        self.assertEqual(failed_gates(baseline(111222333), seed=111222333), set())

    def test_a_truncated_transcript_fails_the_transcript_gate_only(self):
        planted = judge_mod.plant_truncate(baseline())
        self.assertOnly(planted, "P05T-TRANSCRIPT")
        self.assertEqual(failed_gates(baseline()), set())

    def test_a_transcript_cut_mid_way_fails_the_gates_of_the_lines_it_lost(self):
        text = baseline()
        cut = text[: text.index("FFW_P05T_THREADED")]
        self.assertEqual(failed_gates(cut), {"P05T-TRANSCRIPT", "P05T-THREADS"})

    def test_one_adjacent_pair_swapped_in_one_scripted_history_fails_the_directed_gate_only(self):
        planted = judge_mod.plant_order(baseline())
        self.assertNotEqual(planted, baseline())
        self.assertOnly(planted, "P05T-DIRECTED")
        self.assertEqual(failed_gates(baseline()), set())

    def test_the_same_values_in_a_different_order_in_a_seeded_history_changes_the_sweep_digest(self):
        line = next(ln for ln in baseline().split("\n") if "set=seeded" in ln and "kind=split" in ln)
        digest = line.rsplit("digest=", 1)[1]
        planted = baseline().replace(line, line.replace(digest, f"{(int(digest, 16) ^ 1):016x}"))
        self.assertOnly(planted, "P05T-SEEDED")

    def test_a_changed_pinned_count_or_digest_fails_the_pinned_gate_only(self):
        text = baseline()
        pinned = next(ln for ln in text.split("\n") if "set=pinned" in ln and "kind=split" in ln)
        self.assertOnly(text.replace(pinned, pinned.replace("violations=198", "violations=197")), "P05T-PINNED")
        digest = pinned.rsplit("digest=", 1)[1]
        self.assertOnly(text.replace(pinned, pinned.replace(digest, f"{(int(digest, 16) ^ 1):016x}")), "P05T-PINNED")

    def test_a_vector_result_that_is_wrong_in_one_token_fails_the_vectors_gate_only(self):
        self.assertOnly(sub1(baseline(), "r=cx_err:100000001,v:100000001,cx_ok:100000001",
                             "r=cx_ok:100000001,v:100000001,cx_ok:100000001"), "P05T-VECTORS")

    def test_a_truncating_compare_exchange_result_is_refused_by_name(self):
        # What a cell that compared only the low word would print for the full-width compare-exchange vector.
        self.assertOnly(sub1(baseline(), "cx_err:100000001,v:100000001,cx_ok:100000001,v:9,cx_ok:9,cx_err:9",
                             "cx_ok:100000001,v:9,cx_err:9,v:9,cx_ok:9,cx_err:9"), "P05T-VECTORS")

    def test_a_wrong_token_anywhere_in_a_vector_result_is_refused_not_only_the_first(self):
        # The earlier plants changed a vector's FIRST token; a comparison of only the first token would have let these through.
        self.assertOnly(sub1(baseline(), "cx_ok:9,cx_err:9", "cx_ok:9,cx_ok:9"), "P05T-VECTORS")          # the last token
        self.assertOnly(sub1(baseline(), "of:1/ffffffffffffffff,v:1", "of:1/ffffffffffffffff,v:2"), "P05T-VECTORS")
        self.assertOnly(sub1(baseline(), "v:f0f0f0f000000000,v:f0f0f0f00f0f0f0f", "v:f0f0f0f000000000,v:f0f0f0f00f0f0f0e"),
                        "P05T-VECTORS")
        # a missing trailing token, and a vector the judge has never heard of
        self.assertOnly(sub1(baseline(), "cx_ok:9,cx_err:9\n", "cx_ok:9\n"), "P05T-VECTORS")
        # (renamed, not added: an extra VEC line would also break the transcript's line count, a second detector)
        self.assertOnly(sub1(baseline(), "FFW_P05T_VEC id=add_carry ", "FFW_P05T_VEC id=made_up "), "P05T-VECTORS")

    def test_the_hand_pinned_counts_are_checked_even_when_the_reference_agrees_with_the_guest(self):
        # A repository whose vectors.txt pins 197 where the reference (and the guest) say 198: only the hand-pinned check can fail.
        with tempfile.TemporaryDirectory() as scratch:
            repo = pathlib.Path(scratch)
            (repo / "tests" / "p05").mkdir(parents=True)
            (repo / "tests" / "p05" / "reference.py").write_text((REPO / "tests" / "p05" / "reference.py").read_text())
            pinned = (REPO / "tests" / "p05" / "vectors.txt").read_text()
            self.assertEqual(pinned.count("split_violations 198"), 1)
            (repo / "tests" / "p05" / "vectors.txt").write_text(pinned.replace("split_violations 198", "split_violations 197"))
            transcript = judge_mod.parse_transcript(baseline())
            gate = judge_mod.gate_pinned(transcript, repo)
            self.assertEqual(gate.status, "failed")
            self.assertIn("pins 197", gate.detail)
            self.assertEqual(judge_mod.gate_pinned(transcript, REPO).status, "passed")          # remove the plant

    def test_a_verdict_or_loaded_value_that_differs_from_the_hand_table_fails_even_with_the_reference_history(self):
        text = baseline()
        line = next(ln for ln in text.split("\n") if "name=torn_store kind=split" in ln)
        self.assertOnly(text.replace(line, line.replace("verdict=N", "verdict=L")), "P05T-DIRECTED")
        self.assertOnly(text.replace(line, line.replace("loaded=1fffffff0", "loaded=0")), "P05T-DIRECTED")

    def test_an_end_line_in_the_middle_of_the_transcript_fails_the_transcript_gate_only(self):
        text = baseline()
        moved = text.replace("FFW_P05T_END\n", "").replace("FFW_P05T_MONOTONE", "FFW_P05T_END\nFFW_P05T_MONOTONE", 1)
        self.assertEqual(moved.count("FFW_P05T_END"), 1)
        self.assertOnly(moved, "P05T-TRANSCRIPT")

    def test_a_duplicated_line_or_an_unknown_tag_fails_the_transcript_gate_only(self):
        text = baseline()
        vec = next(ln for ln in text.split("\n") if "FFW_P05T_VEC id=add_carry" in ln)
        self.assertOnly(text.replace(vec, vec + "\n" + vec), "P05T-TRANSCRIPT")
        self.assertOnly(text.replace("FFW_P05T_END", "FFW_P05T_BOGUS x=1\nFFW_P05T_END"), "P05T-TRANSCRIPT")

    def test_a_source_file_the_guest_did_not_compile_fails_the_sources_gate_only(self):
        line = next(ln for ln in baseline().split("\n") if "FFW_P05T_SRC file=shared.rs" in ln)
        fnv_value = line.rsplit("fnv=", 1)[1]
        self.assertOnly(baseline().replace(line, line.replace(fnv_value, f"{(int(fnv_value, 16) ^ 1):016x}")), "P05T-SOURCES")

    def test_a_wrong_seed_echo_fails_the_seed_gate_only(self):
        self.assertOnly(sub1(baseline(), f"FFW_P05T_SEED value={SEED}", f"FFW_P05T_SEED value={SEED + 1}"), "P05T-SEED")

    def test_each_real_thread_outcome_is_checked_on_its_own(self):
        for old, new in (("duplicates=0", "duplicates=1"), ("complete=1", "complete=0"), ("final=1f40", "final=1f3f"),
                         ("final=100000f40", "final=1000000f40"), ("errors=77", "errors=76"), ("all_typed=1", "all_typed=0"),
                         ("exact=1", "exact=0"), ("backwards=0", "backwards=1"), ("linearizable=24 not=0", "linearizable=23 not=1")):
            self.assertOnly(sub1(baseline(), old, new), "P05T-THREADS")

    def test_a_missing_or_non_mips_elf_fails_the_elf_gate_only(self):
        self.assertOnly(baseline(), "P05T-ELF", elf=None)
        self.assertOnly(baseline(), "P05T-ELF", elf=dict(ELF, machine=40))

    def test_a_guest_that_ran_on_the_host_is_refused(self):
        text = "FFW_P05T_HOST_BUILD this program is a guest probe\n"
        self.assertIn("P05T-TRANSCRIPT", failed_gates(text))

    def test_every_planted_negative_is_caught_by_exactly_its_gates(self):
        for name in judge_mod.PLANTS:
            planted = {"host": judge_mod.plant_host, "truncate": judge_mod.plant_truncate, "order": judge_mod.plant_order,
                       "replay": lambda t: judge_mod.plant_replay(t, baseline(111222333))}[name](baseline())
            caught, why = judge_mod.plant_verdict(name, judge_mod.judge(planted, ELF, SEED))
            self.assertTrue(caught, (name, why))
        # ...and a green baseline is not "caught" for any of them
        for name in judge_mod.PLANTS:
            self.assertFalse(judge_mod.plant_verdict(name, judge_mod.judge(baseline(), ELF, SEED))[0], name)


class PlantCredit(unittest.TestCase):
    """A catch is credited only when exactly the intended gates fail."""

    def report(self, failed):
        gates = [judge_mod.Gate(g, "x", "failed" if g in failed else "passed") for g in
                 ("P05T-ENV", "P05T-TRANSCRIPT", "P05T-DIRECTED", "P05T-SEEDED", "P05T-SEED")]
        return {"gates": gates}

    def test_a_plant_that_trips_an_extra_gate_is_not_credited(self):
        # The host plant must fail ENV and nothing else; ENV plus SEED would stay red after either detector were deleted.
        self.assertTrue(judge_mod.plant_verdict("host", self.report({"P05T-ENV"}))[0])
        self.assertFalse(judge_mod.plant_verdict("host", self.report({"P05T-ENV", "P05T-SEED"}))[0])

    def test_a_plant_that_trips_nothing_is_not_credited(self):
        self.assertFalse(judge_mod.plant_verdict("host", self.report(set()))[0])

    def test_a_plant_that_trips_only_another_gate_is_not_credited(self):
        self.assertFalse(judge_mod.plant_verdict("order", self.report({"P05T-SEEDED"}))[0])


class NoReceipt(unittest.TestCase):
    def test_with_no_transcript_the_case_is_blocked_not_passed(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = judge_mod.main(["analyze"])
        self.assertEqual(code, 3)
        self.assertIn("BLOCKED", out.getvalue())
        self.assertNotIn("PASSED", out.getvalue().replace("NOT PASSED", ""))

    def test_a_blocked_report_is_never_ok(self):
        report = judge_mod.blocked_report()
        self.assertFalse(report["ok"])
        self.assertEqual(judge_mod.exit_code(report), 3)

    def test_analyzing_a_good_log_exits_zero_and_a_bad_one_exits_one(self):
        with tempfile.TemporaryDirectory() as scratch:
            good, bad = pathlib.Path(scratch) / "good.log", pathlib.Path(scratch) / "bad.log"
            good.write_text(baseline())
            bad.write_text(judge_mod.plant_truncate(baseline()))
            fake = pathlib.Path(scratch) / "fake.elf"
            fake.write_bytes(b"\x7fELF" + bytes([1, 2, 1]) + bytes(9) + (2).to_bytes(2, "big") + (8).to_bytes(2, "big") + bytes(36))
            for path, want in ((good, 0), (bad, 1)):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(judge_mod.main(["analyze", "--log", str(path), "--elf", str(fake), "--seed", str(SEED)]),
                                     want)


class Elf(unittest.TestCase):
    def header(self, data, machine):
        return (b"\x7fELF" + bytes([1, data, 1]) + bytes(9) + (2).to_bytes(2, "big" if data == 2 else "little") +
                machine.to_bytes(2, "big" if data == 2 else "little") + bytes(36))

    def test_a_big_endian_mips_header_is_accepted(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = pathlib.Path(scratch) / "a.elf"
            path.write_bytes(self.header(2, 8))
            self.assertEqual(judge_mod.read_elf(path)["machine"], 8)

    def test_little_endian_non_mips_and_non_elf_files_are_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            for name, data in (("le.elf", self.header(1, 8)), ("ppc.elf", self.header(2, 20)), ("junk", b"not an elf at all" * 4)):
                path = pathlib.Path(scratch) / name
                path.write_bytes(data)
                with self.assertRaises(judge_mod.MeasurementError):
                    judge_mod.read_elf(path)


class Hygiene(unittest.TestCase):
    def test_no_site_data_or_host_paths_in_the_new_files(self):
        import re
        ipv4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
        mac = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
        user_path = re.compile("/" + "Users/|/" + "home/|/" + "private/")
        files = [SCRIPT, pathlib.Path(__file__), SCRIPT.parent / "p05-target" / "src" / "main.rs",
                 SCRIPT.parent / "p05-target" / "Cargo.toml"]
        for path in files:
            text = path.read_text(encoding="utf-8")
            for rx in (ipv4, mac, user_path):
                self.assertIsNone(rx.search(text), (path.name, rx.pattern))

    def test_the_guest_prints_exactly_the_tags_the_judge_expects(self):
        main_rs = (SCRIPT.parent / "p05-target" / "src" / "main.rs").read_text(encoding="utf-8")
        import re
        printed = set(re.findall(r"FFW_P05T_([A-Z_0-9]+)", main_rs))
        expected = set(judge_mod.TAG_COUNTS) | set(judge_mod.FATAL_TAGS)
        self.assertEqual(printed - {"HOST_BUILD", "REBOOT_FAILED", "REPLAY_MISSING"}, set(judge_mod.TAG_COUNTS))
        self.assertTrue(set(judge_mod.FATAL_TAGS) <= printed, "the judge refuses tags the guest never prints")
        self.assertEqual(printed - expected, set())

    def test_the_guest_prints_the_vector_ids_and_directed_scripts_the_judge_expects(self):
        main_rs = (SCRIPT.parent / "p05-target" / "src" / "main.rs").read_text(encoding="utf-8")
        import re
        ids = set(re.findall(r'vec_line\("([a-z0-9_]+)"', main_rs))
        self.assertEqual(ids, set(judge_mod.VECTOR_EXPECTED))
        for name in {n for n, _ in judge_mod.DIRECTED_EXPECTED}:
            self.assertIn(f'"{name}"', main_rs)

    def test_the_guest_includes_exactly_the_files_the_judge_hashes(self):
        main_rs = (SCRIPT.parent / "p05-target" / "src" / "main.rs").read_text(encoding="utf-8")
        import re
        included = re.findall(r'include_bytes!\("\.\./\.\./\.\./\.\./([^"]+)"\)', main_rs)
        self.assertEqual(included, [rel for _, rel in judge_mod.SOURCE_FILES])
        for rel in included:
            self.assertTrue((REPO / rel).is_file(), rel)


if __name__ == "__main__":
    unittest.main()
