"""Tests for the D01 reference, vectors and judge (ffw-f3b). Host-only, standard library only.

    python3 -B -I tests/d01/test_d01.py

IMPORTANT scope note. The "perfect log" below is synthesized from the reference's own expected
values. It exercises the JUDGE (does it accept a correct log, reject a corrupted one, and refuse to
pass what was not observed?). It says nothing about the Rust implementation; that evidence is the
centrally run ``cargo test`` log fed to ``run_cases.py --judge``.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from typing import Any, List, Optional

HERE = os.path.dirname(os.path.realpath(__file__))


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location("d01_t_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load("reference")
gen = _load("generate")
anchors = _load("anchors")
runner = _load("run_cases")


def observed_for(case: dict) -> dict:
    """What a correct Rust implementation would print for ``case`` (derived from the expectation)."""
    kind, base = case["kind"], {"id": case["id"], "kind": case["kind"]}
    if kind == "convert":
        return {**base, "status": "ok", "dst_hex": case["dst_expected_hex"], **case["expected"]}
    if kind == "pipeline":
        return {**base, "status": "ok", "out_hex": case["out_expected_hex"], **case["expected"]}
    if kind == "ring":
        return {**base, "results": case["expect"]}
    expect = case["expect"]
    if "error" in expect:
        return {**base, "status": "err", "error": expect["error"]}
    return {**base, "status": "ok", **{k: v for k, v in expect.items() if k != "ok"}}


# Synthetic stand-ins of the same FORM as a real RCH run (worker id and pool hash are invented).
WORKER, POOL = "vmi0000000", "0123456789abcdef0123456789abcdef"
# Test binaries in cargo's execution order. An unrelated crate is included so the judge has to
# tell D01's binaries apart from others.
BINARIES = [
    ("lib", "franken_alloc_probe", "franken-alloc-probe"),
    ("test", "render_path_no_alloc", "franken-alloc-probe"),
    ("lib", "franken_clock", "franken-clock"),
    ("lib", "franken_dsp", "franken-dsp"),
    ("test", "d01_vectors", "franken-dsp"),
]
DOC_BINARIES = ["franken_alloc_probe", "franken_clock", "franken_dsp"]
OTHER_TESTS = {"franken_clock": ["tests::unrelated_one", "tests::unrelated_two"]}


def _header(kind: str, stem: str, crate: str) -> str:
    h = hashlib.sha256(stem.encode()).hexdigest()[:16]
    what = "unittests src/lib.rs" if kind == "lib" else f"tests/{stem}.rs"
    return f"     Running {what} (.rch-target-{WORKER}-pool-{POOL}/debug/build/{crate}/{h}/out/{stem}-{h})"


def _section(names: List[str], failed: tuple, extra: List[str]) -> List[str]:
    """`running N tests` ... `test result:` for one binary; `extra` lands after the first test."""
    count, bad = len(names), sum(1 for n in names if n in failed)
    body = [f"test {n} ... {'FAILED' if n in failed else 'ok'}" for n in names]
    lines = [f"running {count} test{'' if count == 1 else 's'}"] + body[:1] + extra + body[1:]
    verdict = "FAILED" if bad else "ok"
    return lines + ["", f"test result: {verdict}. {count - bad} passed; {bad} failed; 0 ignored; 0 measured; "
                    "0 filtered out; finished in 0.01s", ""]


def cargo_log(doc: dict, layout: str = "classic", drop_tests: tuple = (), drop_cases: tuple = (),
              mutate: Optional[dict] = None, failed_tests: tuple = (), duplicate: Optional[str] = None,
              conflict: Optional[str] = None, moved: Optional[dict] = None, also_in: Optional[dict] = None,
              drop_header_for: tuple = ()) -> str:
    """A synthetic cargo-test log in which every required test passed and every case matches.

    layout "classic": each header is immediately followed by its own section (plain cargo).
    layout "rch": the shape seen through RCH: every ``Running`` header arrives up front, the stdout
    sections follow in the same order, one header lands in the middle of a section, and the
    ``Doc-tests`` headers arrive later still.
    ``moved``  {test name: stem}: print that test under another binary.
    ``also_in`` {test name: stem}: additionally print the same name under another binary.
    """
    by_stem: dict = {}
    for stem, name in runner.derive_rust_tests():
        by_stem.setdefault(stem, []).append(name)
    for stem, names in OTHER_TESTS.items():
        by_stem[stem] = list(names)
    moved, also_in = moved or {}, also_in or {}

    observed_lines: List[str] = []
    for case in doc["cases"]:
        if case["id"] in drop_cases:
            continue
        obs = observed_for(case)
        if mutate and case["id"] in mutate:
            obs = mutate[case["id"]](obs)
        observed_lines.append("D01-OBSERVED " + json.dumps(obs))
        if duplicate == case["id"]:
            observed_lines.append("D01-OBSERVED " + json.dumps(obs))
        if conflict == case["id"]:
            observed_lines.append("D01-OBSERVED " + json.dumps({**obs, "saturated": 999, "error": "conflicting"}))

    sections = []  # (header, stdout lines)
    for kind, stem, crate in BINARIES:
        names = [n for n in by_stem.get(stem, []) if n not in drop_tests and moved.get(n, stem) == stem]
        names += [n for n, target in {**moved, **also_in}.items() if target == stem and n not in drop_tests]
        extra = observed_lines if stem == "d01_vectors" else []
        sections.append((_header(kind, stem, crate), _section(names, failed_tests, extra)))
    for stem in DOC_BINARIES:
        sections.append((f"   Doc-tests {stem}", _section([], (), [])))

    def header_dropped(header: str) -> bool:
        return any(f"/out/{stem}-" in header for stem in drop_header_for)

    head = ["   Compiling franken-dsp v0.1.0 (/synthetic/workspace/crates/franken-dsp)",
            "    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.00s"]
    if layout == "classic":
        out = list(head)
        for header, lines in sections:
            if not header_dropped(header):
                out.append(header)
            out += lines
        return "\n".join(out) + "\n"

    run_headers = [h for h, _ in sections if "Running" in h and not header_dropped(h)]
    doc_headers = [h for h, _ in sections if "Doc-tests" in h]
    stray = next((h for h in run_headers if "d01_vectors" in h), None)  # lands inside franken_dsp's section
    out = list(head) + [h for h in run_headers if h != stray]
    doc_emitted = False
    for header, lines in sections:
        if "Doc-tests" in header and not doc_emitted:
            out += doc_headers
            doc_emitted = True
        if stray is not None and "/out/franken_dsp-" in header:
            lines = lines[:2] + [stray] + lines[2:]
        out += lines
    return "\n".join(out) + "\n"


perfect_log = cargo_log


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.doc = json.load(handle)

    def parse(self, *texts: str) -> Any:
        """Write each text to its own file (distinct names) and load them all into one Logs."""
        logs = runner.Logs()
        for i, text in enumerate(texts):
            path = os.path.join(self.tmp.name, f"cargo{i}.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            logs.add(path)
        return logs

    def judge(self, text: str, tier: str = "full") -> List[Any]:
        results, _ = runner.run(tier, self.parse(text))
        return results

    def by_status(self, results: List[Any], status: str) -> List[Any]:
        return [r for r in results if r.status == status]


class ReferenceAndVectors(Harness):
    def test_hand_computed_anchors_hold(self) -> None:
        self.assertEqual(anchors.check(), [])

    def test_committed_vectors_equal_a_fresh_generation(self) -> None:
        with open(runner.VECTORS, encoding="utf-8") as handle:
            self.assertTrue(handle.read() == gen.dumps(gen.build()), "vectors.json is stale: --write-vectors")

    def test_every_invariant_is_covered_and_every_case_id_is_unique(self) -> None:
        ids = [c["id"] for c in self.doc["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        covered = {i for c in self.doc["cases"] for i in c["invariants"]}
        external = {k for k, v in self.doc["external"].items() if v}
        self.assertEqual(set(self.doc["invariants"]) - covered - external, set())
        self.assertEqual(covered - set(self.doc["invariants"]), set())

    def test_matrix_covers_every_format_endian_pair(self) -> None:
        ids = {c["id"] for c in self.doc["cases"] if c["id"].startswith("D01-CONV-")}
        self.assertEqual(len(ids), 64)
        for sf in ref.FORMATS:
            for se in ref.ENDIANS:
                for df in ref.FORMATS:
                    for de in ref.ENDIANS:
                        self.assertIn(f"D01-CONV-{sf}-{se}__{df}-{de}", ids)

    def test_boundary_inputs_really_contain_the_edges_they_claim(self) -> None:
        self.assertTrue({-(2 ** 31), 2 ** 31 - 1, 0}.issubset(set(gen.int_boundaries(32))))
        self.assertTrue({0x7FFFFF80, 0x7FFFFF7F, 0x7FFF8000, 0x7FFF7FFF}.issubset(set(gen.int_boundaries(32))))
        bits = set(gen.f32_boundaries())
        for pattern in gen.F32_NON_FINITE_BITS + [0x80000000, 0x3F800000, 0xBF800000, 0x00000001]:
            self.assertIn(pattern, bits)

    def test_ring_model_matches_a_plain_fifo_on_a_long_random_script(self) -> None:
        spec = ref.Spec("s16", "big", 1, 48_000)
        model = ref.RingModel(spec, 5)
        shadow: List[int] = []
        rng = gen.prng(7)
        for _ in range(2000):
            frames = next(rng) % 7 + 1
            if next(rng) % 2:
                block = bytes(next(rng) % 256 for _ in range(frames * 2))
                try:
                    model.push(block)
                    shadow.extend(block)
                    self.assertLessEqual(len(shadow), 10)
                except ref.RefError as e:
                    self.assertIn(e.code, ("ring_full", "block_too_large"))
            else:
                try:
                    data = model.pop(frames * 2)
                    self.assertEqual(list(data), shadow[:frames * 2])
                    del shadow[:frames * 2]
                except ref.RefError as e:
                    self.assertIn(e.code, ("ring_underrun", "block_too_large"))

    def test_vectors_distinguish_the_classic_wrong_rules(self) -> None:
        """Baseline first (the unmutated generator equals the committed file), then three planted
        wrong rules must each change at least one expected byte."""
        with open(runner.VECTORS, encoding="utf-8") as handle:
            committed = handle.read()
        # generate.py loads its own copy of reference.py; the mutation must hit THAT copy.
        gref = gen.ref
        self.assertTrue(gen.dumps(gen.build()) == committed, "baseline must be green before mutating")
        real = gref.convert_value

        def truncating(value, src_fmt, dst_fmt, stats):  # wrong: narrowing floors instead of rounding
            sb, db = ref.FORMATS[src_fmt][1], ref.FORMATS[dst_fmt][1]
            if value[0] == "i" and db is not None and sb is not None and db < sb:
                r = value[1] // 2 ** (sb - db)
                return ("i", max(-(2 ** (db - 1)), min(2 ** (db - 1) - 1, r)))
            return real(value, src_fmt, dst_fmt, stats)

        def half_away(value, src_fmt, dst_fmt, stats):  # wrong: float->int rounds halves away from zero
            db = ref.FORMATS[dst_fmt][1]
            if value[0] == "f" and db is not None and value[1] == value[1] and abs(value[1]) != float("inf"):
                x = value[1] * 2 ** (db - 1)
                r = int(x + 0.5) if x >= 0 else -int(-x + 0.5)
                return ("i", max(-(2 ** (db - 1)), min(2 ** (db - 1) - 1, r)))
            return real(value, src_fmt, dst_fmt, stats)

        def nan_to_full_scale(value, src_fmt, dst_fmt, stats):  # wrong: non-finite becomes a rail
            db = ref.FORMATS[dst_fmt][1]
            if value[0] == "f" and (value[1] != value[1] or abs(value[1]) == float("inf")) and db is not None:
                return ("i", 2 ** (db - 1) - 1)
            return real(value, src_fmt, dst_fmt, stats)

        try:
            for name, wrong in (("truncating narrowing", truncating), ("half-away rounding", half_away),
                                ("non-finite to full scale", nan_to_full_scale)):
                gref.convert_value = wrong
                self.assertIs(gref.convert_value, wrong, "the mutation must actually be installed")
                with self.subTest(wrong_rule=name):
                    self.assertTrue(gen.dumps(gen.build()) != committed, f"vectors do not detect: {name}")
        finally:
            gref.convert_value = real
        self.assertTrue(gen.dumps(gen.build()) == committed, "reference restored")


class JudgeBehavior(Harness):
    def test_a_perfect_log_is_qualified(self) -> None:
        results = self.judge(perfect_log(self.doc))
        self.assertEqual(self.by_status(results, "failed"), [])
        self.assertEqual(self.by_status(results, "blocked"), [])
        self.assertEqual(runner.exit_code(results), 0)
        self.assertGreater(len(self.by_status(results, "passed")), 200)

    def test_no_log_blocks_everything_rust_backed_and_never_passes_it(self) -> None:
        results, _ = runner.run("full", None)
        self.assertEqual(self.by_status(results, "failed"), [])
        self.assertEqual(runner.exit_code(results), 3)
        passed = {r.case_id for r in self.by_status(results, "passed")}
        self.assertTrue(all(i.startswith("D01-META-") for i in passed), passed)
        self.assertEqual(len(self.by_status(results, "blocked")), len(results) - len(passed))

    def test_a_corrupted_byte_is_reported_with_frame_channel_and_format(self) -> None:
        target = "D01-CONV-s16-big__s32-little"
        case = next(c for c in self.doc["cases"] if c["id"] == target)

        def corrupt(obs: dict) -> dict:
            data = bytearray(bytes.fromhex(obs["dst_hex"]))
            data[5] ^= 0x01  # s32 little-endian stereo: frame 0, channel 1
            return {**obs, "dst_hex": data.hex()}

        results = self.judge(perfect_log(self.doc, mutate={target: corrupt}))
        failed = self.by_status(results, "failed")
        self.assertEqual([r.case_id for r in failed], [target])
        self.assertIn("frame 0 channel 1", failed[0].detail)
        self.assertIn("s32 little", failed[0].detail)
        self.assertIn("s16 big -> s32 little", failed[0].detail)
        self.assertEqual(runner.exit_code(results), 1)
        self.assertEqual(case["dst"]["format"], "s32")

    def test_padding_and_guard_divergence_is_named_as_such(self) -> None:
        target = "D01-LAYOUT-001"

        def corrupt(obs: dict) -> dict:
            data = bytearray(bytes.fromhex(obs["dst_hex"]))
            data[13] ^= 0xFF  # inside the plane gap, not a sample
            return {**obs, "dst_hex": data.hex()}

        failed = self.by_status(self.judge(perfect_log(self.doc, mutate={target: corrupt})), "failed")
        self.assertEqual([r.case_id for r in failed], [target])
        self.assertIn("padding or guard", failed[0].detail)

    def test_wrong_saturation_count_wrong_error_code_and_wrong_ring_step_all_fail(self) -> None:
        pipeline = next(c for c in self.doc["cases"] if c["kind"] == "pipeline")
        cerr = next(c for c in self.doc["cases"] if c["kind"] == "convert_error" and "error" in c["expect"])
        ring = next(c for c in self.doc["cases"] if c["kind"] == "ring")
        mutate = {
            pipeline["id"]: lambda o: {**o, "saturated": o["saturated"] + 1},
            cerr["id"]: lambda o: {**o, "error": "empty_block" if o["error"] != "empty_block" else "ring_full"},
            ring["id"]: lambda o: {**o, "results": [dict(o["results"][0], avail=99)] + o["results"][1:]},
        }
        failed = {r.case_id: r.detail for r in self.by_status(self.judge(perfect_log(self.doc, mutate=mutate)), "failed")}
        self.assertEqual(set(failed), set(mutate))
        self.assertIn("stats differ", failed[pipeline["id"]])
        self.assertIn("expected error", failed[cerr["id"]])
        self.assertIn("ring step 0", failed[ring["id"]])

    def test_a_case_that_did_not_run_is_blocked_not_passed(self) -> None:
        results = self.judge(perfect_log(self.doc, drop_cases=("D01-RING-003",)))
        blocked = self.by_status(results, "blocked")
        self.assertEqual([r.case_id for r in blocked], ["D01-RING-003"])
        self.assertEqual(runner.exit_code(results), 3)

    def test_missing_ignored_and_failed_rust_tests(self) -> None:
        results = self.judge(perfect_log(self.doc, drop_tests=("tests::wire_path_round_trips_every_i16_value_exactly",),
                                         failed_tests=("convert::tests::s16_endian_vectors",)))
        self.assertEqual([r.case_id for r in self.by_status(results, "failed")],
                         ["RUST:franken_dsp::convert::tests::s16_endian_vectors"])
        self.assertEqual([r.case_id for r in self.by_status(results, "blocked")],
                         ["RUST:franken_dsp::tests::wire_path_round_trips_every_i16_value_exactly"])
        self.assertEqual(runner.exit_code(results), 1)  # a failure outranks a block

    def test_an_identical_repeated_observation_changes_nothing(self) -> None:
        baseline = self.judge(perfect_log(self.doc))
        repeated = self.judge(perfect_log(self.doc, duplicate="D01-LEN-001"))
        self.assertEqual(len(repeated), len(baseline))
        self.assertEqual(runner.summarize(repeated), runner.summarize(baseline))
        self.assertEqual(runner.exit_code(repeated), 0)

    def test_a_conflicting_observation_fails_only_its_own_case_and_adds_no_case(self) -> None:
        baseline = self.judge(perfect_log(self.doc))
        results = self.judge(perfect_log(self.doc, conflict="D01-LEN-001"))
        self.assertEqual(len(results), len(baseline), "the denominator must not move")
        failed = self.by_status(results, "failed")
        self.assertEqual([r.case_id for r in failed], ["D01-LEN-001"])
        self.assertIn("conflicting", failed[0].detail)

    def test_smoke_tier_selects_a_subset_but_still_blocks_what_is_missing(self) -> None:
        full, _ = runner.run("full", None)
        smoke, _ = runner.run("smoke", None)
        self.assertLess(len(smoke), len(full))
        self.assertEqual(runner.exit_code(smoke), 3)
        self.assertTrue(self.by_status(self.judge(perfect_log(self.doc), tier="smoke"), "failed") == [])

    def test_required_rust_tests_are_derived_from_the_sources(self) -> None:
        required = runner.derive_rust_tests()
        names = {name for _, name in required}
        self.assertIn(runner.HARNESS_TEST, required)
        self.assertIn("convert::tests::s16_endian_vectors", names)
        self.assertIn("ring::tests::two_threads_preserve_order_and_content_with_different_block_sizes", names)
        self.assertIn("convert_ring_convert_sink_pipeline_does_not_allocate", names)
        self.assertGreaterEqual(len(required), 40)


OLD_RUNNING = re.compile(r"Running .*\(.*?([A-Za-z0-9_]+)-[0-9a-f]{6,}\)")  # the first parser's header rule


def nearest_header_misses(text: str) -> List[Any]:
    """Required tests the ORIGINAL attribution (a test belongs to the nearest preceding header)
    fails to credit. Used to prove the fixtures reproduce the defect."""
    stem, seen = None, set()
    for line in text.splitlines():
        header = OLD_RUNNING.search(line)
        if header:
            stem = header.group(1)
            continue
        test = runner.TEST_LINE.search(line)
        if test:
            seen.add((stem, test.group(1)))
    return [t for t in runner.derive_rust_tests() if t not in seen]


class RchShape(Harness):
    """Real RCH cargo output: ``Running`` headers (stderr) and test sections (stdout) arrive as
    separate streams, so a test is not under its own header. Fixtures use the real form with
    invented worker and pool values."""

    def test_header_forms_parse_to_the_binary_stem(self) -> None:
        pool = f".rch-target-{WORKER}-pool-{POOL}/debug/build"
        for line, stem in (
            (f"     Running unittests src/lib.rs ({pool}/franken-dsp/6804a12cce576680/out/franken_dsp-6804a12cce576680)", "franken_dsp"),
            (f"     Running tests/d01_vectors.rs ({pool}/franken-dsp/eed191ef6cf9feaa/out/d01_vectors-eed191ef6cf9feaa)", "d01_vectors"),
            (f"     Running tests/render_path_no_alloc.rs ({pool}/franken-alloc-probe/351dfa62b2517df6/out/render_path_no_alloc-351dfa62b2517df6)", "render_path_no_alloc"),
            (f"     Running unittests src/main.rs ({pool}/franken-speaker/77291aa7672dc7d2/out/franken_speaker-77291aa7672dc7d2)", "franken_speaker"),
            ("     Running unittests src/lib.rs (target/debug/deps/franken_dsp-0123abcd)", "franken_dsp"),
        ):
            match = runner.RUNNING.match(line)
            self.assertIsNotNone(match, line)
            self.assertEqual(match.group(1), stem)
        self.assertEqual(runner.DOC_TESTS.match("   Doc-tests franken_dsp").group(1), "franken_dsp")
        self.assertIsNone(runner.RUNNING.match("   Compiling franken-dsp v0.1.0 (/x/crates/franken-dsp)"))

    def test_the_fixture_really_separates_headers_from_their_tests(self) -> None:
        lines = cargo_log(self.doc, layout="rch").splitlines()
        headers = [i for i, line in enumerate(lines) if runner.RUNNING.match(line)]
        first_test = next(i for i, line in enumerate(lines) if line.startswith("test "))
        self.assertGreaterEqual(sum(1 for i in headers if i < first_test), 4, "headers arrive up front")
        stray = [i for i in headers if i > first_test]
        self.assertEqual(len(stray), 1, "one header lands inside a test section")
        self.assertTrue(lines[stray[0] - 1].startswith("test "))

    def test_the_original_nearest_header_rule_fails_on_this_shape_but_not_on_plain_cargo(self) -> None:
        self.assertEqual(nearest_header_misses(cargo_log(self.doc, layout="classic")), [])
        misses = nearest_header_misses(cargo_log(self.doc, layout="rch"))
        self.assertGreater(len(misses), 30, "the fixture must reproduce the defect that blocked 44 tests")

    def test_an_rch_shaped_log_is_attributed_by_order_and_qualifies(self) -> None:
        logs = self.parse(cargo_log(self.doc, layout="rch"))
        self.assertEqual(logs.unattributed_logs, [], "ordinal pairing must be available")
        results, _ = runner.run("full", logs)
        self.assertEqual(self.by_status(results, "failed"), [])
        self.assertEqual(self.by_status(results, "blocked"), [])
        self.assertEqual(runner.exit_code(results), 0)
        self.assertEqual(len(results), len(runner.run("full", None)[0]))

    def test_plain_cargo_and_rch_shapes_agree(self) -> None:
        classic = runner.run("full", self.parse(cargo_log(self.doc, layout="classic")))[0]
        rch = runner.run("full", self.parse(cargo_log(self.doc, layout="rch")))[0]
        self.assertEqual([(r.case_id, r.status) for r in classic], [(r.case_id, r.status) for r in rch])

    def test_a_planted_absent_test_stays_blocked_in_the_rch_shape(self) -> None:
        absent = "convert::tests::s16_endian_vectors"
        results = self.judge(cargo_log(self.doc, layout="rch", drop_tests=(absent,)))
        self.assertEqual([r.case_id for r in self.by_status(results, "blocked")], [f"RUST:franken_dsp::{absent}"])
        self.assertEqual(self.by_status(results, "failed"), [])
        self.assertEqual(runner.exit_code(results), 3)

    def test_a_failed_test_is_a_failure_in_the_rch_shape(self) -> None:
        name = "ring::tests::capacity_is_validated"
        results = self.judge(cargo_log(self.doc, layout="rch", failed_tests=(name,)))
        self.assertEqual([r.case_id for r in self.by_status(results, "failed")], [f"RUST:franken_dsp::{name}"])
        self.assertEqual(runner.exit_code(results), 1)

    def test_a_test_printed_under_the_wrong_binary_is_not_credited(self) -> None:
        name = "convert::tests::s16_endian_vectors"
        results = self.judge(cargo_log(self.doc, layout="rch", moved={name: "render_path_no_alloc"}))
        self.assertEqual([r.case_id for r in self.by_status(results, "blocked")], [f"RUST:franken_dsp::{name}"])

    def test_header_count_mismatch_falls_back_to_exact_names_and_keeps_absent_tests_blocked(self) -> None:
        text = cargo_log(self.doc, layout="rch", drop_header_for=("franken_clock",))
        logs = self.parse(text)
        self.assertEqual(len(logs.unattributed_logs), 1)
        results, _ = runner.run("full", logs)
        self.assertEqual(runner.exit_code(results), 0, "exact unique names still count when attribution is impossible")
        absent = "ring::tests::two_threads_preserve_order_and_content_with_different_block_sizes"
        results = self.judge(cargo_log(self.doc, layout="rch", drop_header_for=("franken_clock",), drop_tests=(absent,)))
        self.assertEqual([r.case_id for r in self.by_status(results, "blocked")], [f"RUST:franken_dsp::{absent}"])

    def test_a_name_seen_in_two_sections_is_ambiguous_only_when_attribution_is_lost(self) -> None:
        name = "tests::wire_path_round_trips_every_i16_value_exactly"
        both = {name: "franken_clock"}
        attributed = self.judge(cargo_log(self.doc, layout="rch", also_in=both))
        self.assertEqual(runner.exit_code(attributed), 0, "with ordered pairing each copy has its own binary")
        lost = self.judge(cargo_log(self.doc, layout="rch", also_in=both, drop_header_for=("franken_clock",)))
        self.assertEqual([r.case_id for r in self.by_status(lost, "blocked")], [f"RUST:franken_dsp::{name}"])
        self.assertIn("more than one", self.by_status(lost, "blocked")[0].detail)

    def test_repeating_a_log_never_changes_the_denominator(self) -> None:
        text = cargo_log(self.doc, layout="rch")
        once = runner.run("full", self.parse(text))[0]
        logs = self.parse(text, text)  # two files, identical content
        twice = runner.run("full", logs)[0]
        self.assertEqual(len(logs.repeated_inputs), 1)
        self.assertEqual(len(twice), len(once))
        self.assertEqual(runner.summarize(twice), runner.summarize(once))
        same_path = os.path.join(self.tmp.name, "cargo0.log")
        logs.add(same_path)  # the very same path again
        self.assertEqual(len(logs.repeated_inputs), 2)
        self.assertEqual(runner.summarize(runner.run("full", logs)[0]), runner.summarize(once))


class CommandLine(Harness):
    def run_main(self, argv: List[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main(argv)

    def test_exit_codes_list_receipt_and_missing_log(self) -> None:
        self.assertEqual(self.run_main(["--list"]), 0)
        self.assertEqual(self.run_main(["--judge", os.path.join(self.tmp.name, "absent.log")]), 2)
        log = os.path.join(self.tmp.name, "ok.log")
        with open(log, "w", encoding="utf-8") as handle:
            handle.write(perfect_log(self.doc))
        receipts = os.path.join(self.tmp.name, "receipts")
        self.assertEqual(self.run_main(["--judge", log, "--receipts", receipts]), 0)
        (name,) = os.listdir(receipts)
        with open(os.path.join(receipts, name), encoding="utf-8") as handle:
            receipt = json.load(handle)
        self.assertEqual(receipt["schema"], "ffw.d01.receipt.v1")
        self.assertEqual(receipt["counts"]["failed"], 0)
        self.assertEqual(receipt["counts"]["blocked"], 0)
        self.assertEqual(len(receipt["judged_logs"][0]["sha256"]), 64)
        self.assertEqual(self.run_main(["--tier", "full"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=1)
