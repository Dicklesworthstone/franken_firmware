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
import random
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
    ("test", "render_events_no_alloc", "franken-alloc-probe"),
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
        # The integer-only conversions are gated against the retained f64 oracle; the 2^32 sweep is opt-in.
        self.assertIn("convert::soft_float_tests::hand_derived_anchors_hold_for_the_new_and_the_original_implementation", names)
        self.assertIn("convert::soft_float_tests::the_conversion_code_contains_no_double_precision_and_no_float_compare", names)
        self.assertNotIn(
            "convert::soft_float_tests::f32_to_s16_and_the_clamp_match_the_original_over_all_four_billion_bit_patterns", names
        )
        # The render-path event ring (the shared logging clause) and its allocation proof are gated too.
        self.assertIn("render_events::tests::slow_full_and_unavailable_sinks_leave_the_real_render_path_bit_identical", names)
        self.assertIn("render_events::tests::a_consumer_that_has_read_nothing_does_not_stop_the_producer", names)
        self.assertIn(("render_events_no_alloc", "emit_the_adapters_and_pop_do_not_allocate_even_when_the_ring_is_full_or_the_consumer_is_gone"), required)


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


class OpenPrefix(Harness):
    """Under ``--nocapture`` another test's line can land between the pieces libtest's main thread writes for a test (``test <name> ... ``,
    the token, the newline). ``Logs`` attributes by the one open prefix, and refuses what that model cannot explain. The shapes are the
    ones of a real central log (a record between a prefix and its ``ok``; a token with a record glued to it); the names are invented."""

    HEADER = "     Running unittests src/lib.rs (target/debug/deps/franken_clock-0123abcd)"
    RECORD = 'D01-OBSERVED {"id":"x-1","kind":"convert","status":"ok"}'
    STEM = "franken_clock"

    def section(self, body: List[str], declared: int) -> str:
        lines = [self.HEADER, f"running {declared} tests"] + body + [
            "", f"test result: ok. {declared} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s", ""]
        return "\n".join(lines) + "\n"

    def statuses(self, logs: Any, names: List[str]) -> List[Optional[str]]:
        return [logs.test_status(self.STEM, n) for n in names]

    def test_a_prefix_interrupted_by_a_line_gets_the_token_that_follows(self) -> None:
        body = ["test t::a ... ok", "test t::b ... " + self.RECORD, "ok", "test t::c ... ok"]
        logs = self.parse(self.section(body, 3))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b", "t::c"]), ["ok", "ok", "ok"])
        self.assertEqual((logs.unattributed_logs, logs.attribution_notes, logs.interrupted_results), ([], [], 1))

    def test_a_prefix_interrupted_by_several_lines_of_any_kind_is_still_read(self) -> None:
        body = ["test t::a ... " + self.RECORD, 'FFW_X_EVENT {"a":1}', "plain text from a test", self.RECORD, "ok", "test t::b ... ok"]
        logs = self.parse(self.section(body, 2))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), ["ok", "ok"])
        self.assertEqual(logs.attribution_notes, [])

    def test_the_token_comes_from_the_log_not_from_the_shape(self) -> None:
        for token, expected in (("FAILED", "FAILED"), ("ignored", "ignored"), ("ignored, slow", "ignored")):
            body = ["test t::a ... ok", "test t::b ... " + self.RECORD, token]
            logs = self.parse(self.section(body, 2))
            self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), ["ok", expected], token)

    def test_a_token_with_a_record_glued_to_it_is_read(self) -> None:
        body = ["test t::a ... ok", "test t::b ... ok" + self.RECORD, "", "test t::c ... FAILED" + self.RECORD, ""]
        logs = self.parse(self.section(body, 3))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b", "t::c"]), ["ok", "ok", "FAILED"])
        self.assertEqual(logs.attribution_notes, [])

    def test_a_prefix_that_never_gets_a_result_is_not_reported(self) -> None:
        # the section ends while it is open
        logs = self.parse(self.section(["test t::a ... ok", "test t::b ... " + self.RECORD], 2))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), ["ok", None])
        self.assertTrue(any("has no result" in n for n in logs.attribution_notes), logs.attribution_notes)
        # the log ends while it is open
        path = os.path.join(self.tmp.name, "cut.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join([self.HEADER, "running 2 tests", "test t::a ... ok", "test t::b ... " + self.RECORD]) + "\n")
        cut = runner.Logs()
        cut.add(path)
        self.assertEqual(cut.test_status(None, "t::b"), None)
        self.assertTrue(any("the log ends" in n for n in cut.attribution_notes), cut.attribution_notes)
        # a prefix left open at the end of one section does not reach into the next binary's section
        second = "\n".join(["     Running unittests src/lib.rs (target/debug/deps/franken_dsp-0123abcd)", "running 1 test", "test t::z ... ok", "",
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s", ""]) + "\n"
        both = self.parse(self.section(["test t::a ... ok", "test t::b ... " + self.RECORD], 2) + second)
        self.assertEqual(both.test_status("franken_dsp", "t::z"), "ok")
        self.assertEqual(both.test_status(None, "t::b"), None)

    def test_two_open_prefixes_are_refused_and_neither_test_is_credited(self) -> None:
        body = ["test t::a ... " + self.RECORD, "test t::b ... " + self.RECORD, "ok", "ok", "test t::c ... ok"]
        logs = self.parse(self.section(body, 3))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), [None, None])
        self.assertEqual(logs.test_status(None, "t::c"), "ok", "a test with its own complete line is still read")
        self.assertTrue(any("is open; neither is attributed" in n for n in logs.attribution_notes), logs.attribution_notes)
        # a complete line opening while a prefix is open is the same defect
        body = ["test t::a ... " + self.RECORD, "test t::b ... ok", "ok"]
        logs = self.parse(self.section(body, 2))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), [None, None])

    def test_a_token_with_no_prefix_open_is_noted_and_credits_nothing(self) -> None:
        body = ["test t::a ... ok", "ok", "test t::b ... ok"]
        logs = self.parse(self.section(body, 2))
        self.assertEqual(self.statuses(logs, ["t::a", "t::b"]), ["ok", "ok"])
        self.assertTrue(any("no test prefix open" in n for n in logs.attribution_notes), logs.attribution_notes)

    def test_a_test_that_printed_a_line_starting_with_a_token_cannot_be_misread_silently(self) -> None:
        # a line that looks like a token takes the result, and then the real token is a token with no prefix open: it is refused
        body = ["test t::a ... " + self.RECORD, "ok, said the test", "FAILED", "test t::b ... ok"]
        logs = self.parse(self.section(body, 2))
        self.assertTrue(any("no test prefix open" in n for n in logs.attribution_notes), logs.attribution_notes)

    def names(self, n: int) -> List[str]:
        return [f"t::case_{i:02d}" for i in range(n)]

    def test_a_section_reporting_in_sorted_order_is_a_serial_run_and_its_interrupted_prefixes_are_not_attributed(self) -> None:
        names = self.names(20)
        body = []
        for i, n in enumerate(names):
            body += [f"test {n} ... " + self.RECORD, "ok"] if i % 2 == 0 else [f"test {n} ... ok"]
        logs = self.parse(self.section(body, 20))
        got = self.statuses(logs, names)
        self.assertEqual([g for i, g in enumerate(got) if i % 2 == 1], ["ok"] * 10, "complete lines are read as they always were")
        self.assertEqual([g for i, g in enumerate(got) if i % 2 == 0], [None] * 10, "interrupted prefixes of a serial run are not")
        self.assertTrue(any("sorted order" in n for n in logs.attribution_notes), logs.attribution_notes)
        self.assertEqual(logs.interrupted_results, 0)
        # the control: the same lines in a parallel-looking (unsorted) order are all read
        shuffled = list(reversed(names))
        body = []
        for i, n in enumerate(shuffled):
            body += [f"test {n} ... " + self.RECORD, "ok"] if i % 2 == 0 else [f"test {n} ... ok"]
        logs = self.parse(self.section(body, 20))
        self.assertEqual(self.statuses(logs, names), ["ok"] * 20)
        self.assertEqual((logs.attribution_notes, logs.interrupted_results), ([], 10))
        # and a short section is not taken for a serial run
        body = [f"test {n} ... " + self.RECORD + "\nok" for n in self.names(5)]
        logs = self.parse(self.section(body, 5))
        self.assertEqual(self.statuses(logs, self.names(5)), ["ok"] * 5)

    def test_a_clean_log_reads_as_it_always_did(self) -> None:
        names = self.names(30)
        logs = self.parse(self.section([f"test {n} ... ok" for n in names], 30))
        self.assertEqual(self.statuses(logs, names), ["ok"] * 30)
        self.assertEqual((logs.unattributed_logs, logs.attribution_notes, logs.interrupted_results), ([], [], 0))

    def test_any_interleaving_of_whole_lines_between_the_three_pieces_is_read_exactly(self) -> None:
        """libtest's main thread writes ``test <n> ... ``, the token, then a newline, one test after another; a test thread writes whole
        lines. Every placement of whole lines between the pieces (none, one or two in each gap) must read back each test's own token."""
        noise = [self.RECORD, 'FFW_V01_EVENT {"schema_version":"ffw.log.v1"}', "a plain line a test printed", "N03-OBSERVED {\"id\":\"n\"}"]
        for seed in range(60):
            rng = random.Random(seed)
            names = self.names(30)
            order = list(names)
            while order == sorted(order):
                rng.shuffle(order)
            want = {n: rng.choice(["ok", "ok", "ok", "FAILED", "ignored"]) for n in names}
            stream = ""
            for n in order:
                for piece in (f"test {n} ... ", want[n], "\n"):
                    stream += piece + "".join(rng.choice(noise) + "\n" for _ in range(rng.choice([0, 0, 1, 2])))
            text = (self.HEADER + "\nrunning 30 tests\n" + stream
                    + "\ntest result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
            logs = self.parse(text)
            got = {n: logs.test_status(self.STEM, n) for n in names}
            self.assertEqual(got, want, f"seed {seed}")
            self.assertEqual((logs.unattributed_logs, logs.attribution_notes), ([], []), f"seed {seed}")


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
        # the receipts directory holds the receipt and the JSONL diagnostic log of the same run, nothing else
        (name,) = [n for n in os.listdir(receipts) if n.endswith(".json")]
        (diag_name,) = [n for n in os.listdir(receipts) if n.endswith(".jsonl")]
        self.assertEqual(sorted(os.listdir(receipts)), sorted([name, diag_name]))
        with open(os.path.join(receipts, name), encoding="utf-8") as handle:
            receipt = json.load(handle)
        self.assertEqual(receipt["schema"], "ffw.d01.receipt.v1")
        self.assertEqual(receipt["counts"]["failed"], 0)
        self.assertEqual(receipt["counts"]["blocked"], 0)
        self.assertEqual(len(receipt["judged_logs"][0]["sha256"]), 64)
        self.assertEqual(self.run_main(["--tier", "full"]), 3)


class Retention(Harness):
    """The original acceptance clauses about tiers, structured diagnostics and what a failure keeps. Each plant is paired with its
    control (the same run without the plant), and every digest is recomputed here with hashlib from the files themselves."""

    # Written out by hand, so that a file silently dropped from the runner's own list is noticed: the verdict rests on these bytes.
    MUST_BIND = (
        "tests/d01/vectors.json", "tests/d01/reference.py", "tests/d01/generate.py", "tests/d01/anchors.py", "tests/d01/run_cases.py",
        "tests/d01/case_log.py", "scripts/test/test_support/diagnostics.py", "docs/contracts/d01.md", "Cargo.lock", "rust-toolchain.toml",
        "crates/franken-dsp/Cargo.toml", "crates/franken-dsp/src/format.rs", "crates/franken-dsp/src/convert.rs",
        "crates/franken-dsp/src/ring.rs", "crates/franken-dsp/src/render_events.rs", "crates/franken-dsp/src/lib.rs",
        "crates/franken-dsp/tests/d01_vectors.rs", "crates/franken-alloc-probe/Cargo.toml", "crates/franken-alloc-probe/src/lib.rs",
        "crates/franken-alloc-probe/tests/render_path_no_alloc.rs", "crates/franken-alloc-probe/tests/render_events_no_alloc.rs",
    )

    def write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def run_main(self, argv: List[str]) -> tuple:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = runner.main(argv)
        return code, out.getvalue()

    @staticmethod
    def sha(path: str) -> str:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def diag(self) -> Any:
        return runner.case_log.load(runner.REPO)

    # ---- tiers

    def test_the_soak_tier_is_selectable_and_is_never_a_pass(self) -> None:
        good = self.write("good.log", perfect_log(self.doc))
        code, _ = self.run_main(["--tier", "full", "--judge", good])
        self.assertEqual(code, 0, "control: the same log qualifies at the full tier")
        code, text = self.run_main(["--tier", "soak", "--judge", good])
        self.assertEqual(code, runner.SOAK_EXIT)
        self.assertEqual(runner.SOAK_EXIT, 4)
        self.assertIn("NOT RUN", text)
        self.assertIn("not a pass", text)
        self.assertNotIn("QUALIFIED", text.replace("NOT QUALIFIED", ""))
        self.assertEqual(self.run_main(["--tier", "soak"])[0], 4, "soak does not depend on a log")
        with self.assertRaises(ValueError):
            runner.run("soak", None)  # nothing can be judged under the soak tier, even by calling the judge directly

    # ---- a failure keeps what a replay needs

    def test_a_failing_run_prints_the_replay_command_the_versions_and_digests_that_equal_the_files(self) -> None:
        case = next(c for c in self.doc["cases"] if c["kind"] == "convert")
        bad = self.write("corrupt.log", perfect_log(self.doc, mutate={case["id"]: lambda o: {**o, "dst_hex": "00" + o["dst_hex"][2:]}}))
        code, text = self.run_main(["--tier", "full", "--judge", bad])
        self.assertEqual(code, 1)
        lines = text.splitlines()
        (first,) = [l for l in lines if l.startswith("RETAINED FOR REPLAY.")]
        self.assertTrue(first.startswith(f"RETAINED FOR REPLAY. First failed case: {case['id']}: "), first)
        self.assertIn("first divergence at frame", first)  # the expected-versus-observed text of the first causal event
        self.assertIn("  replay: scripts/e2e/d01 --tier full --judge corrupt.log", lines)
        self.assertIn(f"  judged log corrupt.log sha256 {self.sha(bad)}", lines)
        self.assertIn(f"  versions: python {sys.version.split()[0]}; receipt ffw.d01.receipt.v1; vectors ffw.d01.vectors.v1", lines)
        shown = {l.split()[1]: l.split()[3] for l in lines if l.startswith("  artifact ")}
        self.assertEqual(set(shown), set(runner.artifact_digests()))
        self.assertTrue(set(self.MUST_BIND) <= set(shown), sorted(set(self.MUST_BIND) - set(shown)))
        for rel, digest in shown.items():
            self.assertEqual(digest, self.sha(os.path.join(runner.REPO, rel)), rel)  # recomputed here, not taken from the runner
        self.assertNotIn(runner.REPO, text, "a retained path is relative to the repository root")
        # control: the same run without the plant keeps nothing and says nothing of the kind
        good = self.write("good.log", perfect_log(self.doc))
        code, text = self.run_main(["--tier", "full", "--judge", good])
        self.assertEqual(code, 0)
        self.assertNotIn("RETAINED", text)

    def test_a_blocked_run_keeps_the_same_replay_context(self) -> None:
        code, text = self.run_main(["--tier", "full"])
        self.assertEqual(code, 3)
        self.assertIn("RETAINED FOR REPLAY. First blocked case: ", text)
        self.assertIn("  replay: scripts/e2e/d01 --tier full\n", text)

    def test_a_failed_rust_test_names_its_first_causal_event(self) -> None:
        name = next(n for stem, n in runner.derive_rust_tests() if n.startswith("ring::tests::"))
        section = ["", "failures:", "", f"---- {name} stdout ----", f"thread '{name}' panicked at crates/franken-dsp/src/ring.rs:9:9:",
                   "assertion `left == right` failed", "  left: 1", " right: 2", "", "failures:", f"    {name}", ""]
        with_event = self.parse(cargo_log(self.doc, failed_tests=(name,)) + "\n".join(section) + "\n")
        results, _ = runner.run("full", with_event)
        (hit,) = [r for r in results if r.status == "failed"]
        self.assertTrue(hit.case_id.endswith("::" + name), hit.case_id)
        self.assertIn("first causal event cargo0.log:", hit.detail)
        self.assertIn("panicked at crates/franken-dsp/src/ring.rs:9:9:", hit.detail)
        self.assertIn("assertion `left == right` failed", hit.detail)
        # control: a FAILED test whose report is not in the log still fails, and claims no cause it cannot show
        without = self.parse(cargo_log(self.doc, failed_tests=(name,)))
        results, _ = runner.run("full", without)
        (hit,) = [r for r in results if r.status == "failed"]
        self.assertEqual(hit.detail, "cargo reported FAILED")

    def test_a_failed_rust_test_under_nocapture_names_its_first_causal_event_from_the_live_stderr_line(self) -> None:
        # The documented central line is `cargo test ... -- --nocapture`: nothing is captured, so there is no `---- stdout ----` block. The
        # panic goes to stderr as it happens, with the message on the next line, and RCH delivers stderr and stdout as separate streams.
        names = [n for stem, n in runner.derive_rust_tests() if n.startswith("ring::tests::")]
        name, other = names[0], names[1]
        live = [f"thread '{name}' (4242) panicked at crates/franken-dsp/src/ring.rs:9:9:", "assertion `left == right` failed",
                "  left: 1", " right: 2", "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"]
        base = cargo_log(self.doc, failed_tests=(name,))
        want_at = "thread '%s' panicked at crates/franken-dsp/src/ring.rs:9:9:" % name

        def failed_detail(text: str) -> str:
            results, _ = runner.run("full", self.parse(text))
            (hit,) = [r for r in results if r.status == "failed"]
            return hit.detail

        lines = base.split("\n")
        middle = "\n".join(lines[:3] + live + lines[3:])  # live, between the lines of a section
        appended = base + "\n".join(live) + "\n"  # a separate stream, after the stdout
        older = "\n".join(lines[:3] + [live[0].replace(" (4242)", "")] + live[1:] + lines[3:])  # rustc before the thread id
        for label, text in (("between lines", middle), ("separate stream", appended), ("older rustc", older)):
            detail = failed_detail(text)
            self.assertIn("first causal event cargo0.log:", detail, label)
            self.assertIn(want_at, detail, label)
            self.assertIn("assertion `left == right` failed", detail, label)
            self.assertNotIn("RUST_BACKTRACE", detail, label)  # the message is the line under the panic, not the note after it
        # keyed by the thread's test name: another test's panic is not this test's cause
        wrong = "\n".join(lines[:3] + [l.replace(name, other) for l in live] + lines[3:])
        self.assertEqual(failed_detail(wrong), "cargo reported FAILED")
        # a panic line that is followed at once by another test's result keeps the panic line and invents no message
        cut = "\n".join(lines[:3] + [live[0], f"test {other} ... ok"] + lines[3:])
        detail = failed_detail(cut)
        self.assertTrue(detail.endswith(want_at), detail)
        # the control: the same FAILED test with no panic in the log claims no cause
        self.assertEqual(failed_detail(base), "cargo reported FAILED")

    def test_an_unwritable_receipts_directory_is_a_verdict_not_a_traceback(self) -> None:
        good = self.write("good.log", perfect_log(self.doc))
        blocker = self.write("blocker", "a regular file, so nothing can be created under it")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.main(["--tier", "full", "--judge", good, "--receipts", os.path.join(blocker, "sub")])
        self.assertEqual(code, 1)
        self.assertIn("NOT QUALIFIED", out.getvalue())
        self.assertIn("diagnostic evidence INCOMPLETE: receipts_unavailable:", out.getvalue())
        self.assertIn("the receipt could not be written", err.getvalue())
        # the control: a directory that can be made gives a qualified run and a receipt
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.main(["--tier", "full", "--judge", good, "--receipts", os.path.join(self.tmp.name, "fine")])
        self.assertEqual((code, err.getvalue()), (0, ""))
        self.assertIn("QUALIFIED", out.getvalue())

    # ---- the receipt

    def test_the_receipt_carries_digests_versions_and_the_exact_replay_command(self) -> None:
        good = self.write("good.log", perfect_log(self.doc))
        receipts = os.path.join(self.tmp.name, "receipts")
        self.assertEqual(self.run_main(["--tier", "full", "--judge", good, "--receipts", receipts])[0], 0)
        (name,) = [n for n in os.listdir(receipts) if n.endswith(".json")]
        with open(os.path.join(receipts, name), encoding="utf-8") as handle:
            receipt = json.load(handle)
        self.assertEqual(receipt["replay"], "scripts/e2e/d01 --tier full --judge good.log")
        self.assertEqual(receipt["versions"], {"python": sys.version.split()[0], "receipt_schema": "ffw.d01.receipt.v1",
                                               "vectors_schema": "ffw.d01.vectors.v1"})
        self.assertEqual(set(receipt["artifacts"]), set(runner.artifact_digests()))
        self.assertTrue(set(self.MUST_BIND) <= set(receipt["artifacts"]), sorted(set(self.MUST_BIND) - set(receipt["artifacts"])))
        for rel, digest in receipt["artifacts"].items():
            self.assertEqual(digest, self.sha(os.path.join(runner.REPO, rel)), rel)
        self.assertEqual(receipt["judged_logs"], [{"path": "good.log", "sha256": self.sha(good)}])

    # ---- the structured diagnostic log

    def test_every_run_writes_a_complete_jsonl_log_next_to_its_receipt_and_the_header_binds_the_artifacts(self) -> None:
        good = self.write("good.log", perfect_log(self.doc))
        receipts = os.path.join(self.tmp.name, "receipts")
        self.assertEqual(self.run_main(["--tier", "full", "--judge", good, "--receipts", receipts])[0], 0)
        (name,) = [n for n in os.listdir(receipts) if n.endswith(".json")]
        (diag_name,) = [n for n in os.listdir(receipts) if n.endswith(".jsonl")]
        with open(os.path.join(receipts, name), encoding="utf-8") as handle:
            receipt = json.load(handle)
        run_id = receipt["run_id"]
        self.assertEqual(diag_name, f"d01-diag-full-{run_id}.jsonl")
        path = os.path.join(receipts, diag_name)
        audit = self.diag().audit_log(path)  # the shared module's own re-read of the file
        cases = len(receipt["results"])
        self.assertEqual(cases, 4 + receipt["planned_vectors"] + receipt["planned_rust_tests"])
        self.assertTrue(audit.complete, audit.reasons)
        self.assertEqual(audit.critical_events, 2 * cases + 1)
        self.assertEqual(receipt["diagnostics"]["complete"], True)
        self.assertEqual(receipt["diagnostics"]["file"], diag_name)
        self.assertEqual(receipt["diagnostics"]["log"]["critical_lost"], 0)
        self.assertEqual(receipt["diagnostics"]["log"]["sha256"], self.sha(path))
        records = []
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                records.append(json.loads(line))
        header = records[0]
        self.assertEqual(header["schema"], "ff.diag.v1")
        self.assertEqual(header["timebase"]["clock"], "monotonic_ns")
        want_set = hashlib.sha256("".join(f"{rel} {self.sha(os.path.join(runner.REPO, rel))}\n" for rel in sorted(receipt["artifacts"])).encode()).hexdigest()
        self.assertEqual(header["extra"]["artifact_set_sha256"], want_set)
        self.assertEqual(header["extra"]["vectors_sha256"], self.sha(runner.VECTORS))
        begins = {r["case"]: r for r in records if r.get("kind") == "case.begin"}
        ends = {r["case"]: r for r in records if r.get("kind") == "case.end"}
        self.assertEqual(len(begins), cases)
        self.assertEqual(set(begins), set(ends))
        by_id = {r["id"]: r for r in receipt["results"]}
        for case_id, end in ends.items():
            self.assertEqual(end["corr"], begins[case_id]["corr"])
            # the sink cuts a very long id (some Rust test paths); the cut id must still name exactly one decided case
            (match,) = [r for rid, r in by_id.items() if rid.startswith(case_id)]
            self.assertEqual(end["fields"]["status"], match["status"], case_id)
        self.assertEqual(sum(1 for r in records if r.get("kind") == "run.summary"), 1)
        # a rerun never overwrites the first run's evidence
        self.assertEqual(self.run_main(["--tier", "full", "--judge", good, "--receipts", receipts])[0], 0)
        self.assertEqual(len([n for n in os.listdir(receipts) if n.endswith(".jsonl")]), 2)

    def test_lost_critical_evidence_makes_a_run_that_would_pass_not_qualified(self) -> None:
        results, meta = runner.run("full", self.parse(perfect_log(self.doc)))
        self.assertEqual(runner.exit_code(results), 0)
        diag = self.diag()

        def evidence(target: Any) -> Any:
            log = runner.case_log.CaseLog.open(runner.REPO, "t1", "full", target=target)
            for r in results:
                log.record(r.case_id, r.group, r.status, r.detail)
            return log.finish(runner.summarize(results))

        whole = evidence(diag.FaultableSink())
        self.assertTrue(whole.complete, whole.reasons)  # control: a sink that takes every write
        self.assertEqual(runner.final_exit(results, whole), 0)
        full = evidence(diag.FaultableSink(capacity_bytes=60_000))  # the plant: a disk that fills long before the run ends
        self.assertFalse(full.complete)
        self.assertTrue(any("critical" in reason for reason in full.reasons), full.reasons)
        self.assertEqual(runner.final_exit(results, full), 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            runner.report(results, "full", None, {**meta, "versions": runner.versions(), "artifacts": runner.artifact_digests()}, full)
        self.assertIn("NOT QUALIFIED", out.getvalue())
        self.assertIn("diagnostic evidence INCOMPLETE", out.getvalue())
        # a failure is still a failure when the log is whole, and an incomplete log does not hide a failure
        failing = [runner.Result("D01-X", "failed", "x", "vector")] + results
        self.assertEqual(runner.final_exit(failing, full), 1)
        self.assertEqual(runner.final_exit(failing, whole), 1)

    def test_a_case_that_wrote_no_events_is_caught_by_the_independent_count_not_only_by_the_sinks_own_loss_accounting(self) -> None:
        diag = self.diag()

        def evidence(extra_case: bool) -> Any:
            log = runner.case_log.CaseLog.open(runner.REPO, "t3", "full", target=diag.FaultableSink())
            for n in range(3):
                log.record(f"D01-X-{n}", "vector", "passed", "")
            if extra_case:
                log.cases += 1  # a case the judge decided and that never reached the log
            return log.finish({"passed": 4, "failed": 0, "blocked": 0})

        self.assertTrue(evidence(False).complete)  # control
        missing = evidence(True)
        self.assertFalse(missing.complete)
        self.assertEqual(missing.reasons, ["critical_event_count:7_of_9"])

    def test_an_unavailable_diagnostics_module_is_an_incomplete_log_not_a_crash(self) -> None:
        empty_repo = tempfile.mkdtemp(dir=self.tmp.name)  # a tree with no scripts/test/test_support/diagnostics.py
        log = runner.case_log.CaseLog.open(empty_repo, "t2", "full")
        log.record("D01-X", "vector", "passed", "")
        evidence = log.finish({"passed": 1, "failed": 0, "blocked": 0})
        self.assertFalse(evidence.complete)
        self.assertTrue(evidence.reasons[0].startswith("diagnostics_unavailable"), evidence.reasons)
        results, _ = runner.run("full", self.parse(perfect_log(self.doc)))
        self.assertEqual(runner.final_exit(results, evidence), 1)


class AcceptanceMap(unittest.TestCase):
    """The acceptance map in docs/contracts/d01.md cites only tests, identifiers and case ids that exist in the tree."""

    DOC = "docs/contracts/d01.md"
    VECTORS = ("tests/d01/vectors.json",)
    PREFIXES = ("D01",)

    def setUp(self) -> None:
        import pathlib

        self.repo = pathlib.Path(__file__).resolve().parents[2]
        text = (self.repo / self.DOC).read_text(encoding="utf-8")
        self.assertIn("## Acceptance map", text)
        self.section = text.split("## Acceptance map", 1)[1]

    def corpus(self) -> str:
        import os
        import pathlib

        parts = []
        for top in ("crates", "tests", "scripts"):
            for root, dirs, files in os.walk(self.repo / top):
                dirs[:] = [d for d in dirs if d not in ("target", "__pycache__", ".git", "build")]
                for name in files:
                    if name.endswith((".rs", ".py")) or "." not in name:
                        parts.append((pathlib.Path(root) / name).read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)

    def test_every_cited_identifier_exists_in_the_tree(self) -> None:
        tokens = set(re.findall(r"`([A-Za-z0-9_:]+)`", self.section))
        corpus = self.corpus()
        missing = []
        for token in sorted(tokens):
            name = token.split("::")[-1]
            if name.count("_") >= 2 and name.islower() and name not in corpus:
                missing.append(token)
        self.assertEqual(missing, [], "the map cites identifiers that are not in the tree")

    def expand(self, prefix: str, family: str, numbers: str) -> List[str]:
        ids = []
        width = len(re.match(r"\d+", numbers).group(0))
        for piece in numbers.split("/"):
            if ".." in piece:
                low, high = (int(p) for p in piece.split(".."))
                ids += [f"{prefix}{family}-{n:0{width}d}" for n in range(low, high + 1)]
            else:
                ids.append(f"{prefix}{family}-{int(piece):0{width}d}")
        return ids

    def test_every_cited_case_and_invariant_exists(self) -> None:
        ids, invariants = set(), set()
        for path in self.VECTORS:
            doc = json.loads((self.repo / path).read_text(encoding="utf-8"))
            ids |= {case["id"] for case in doc["cases"]}
            invariants |= set(doc["invariants"])
        problems = []
        for prefix in self.PREFIXES:
            for family, numbers in re.findall(prefix + r"-([A-Z]+)-(\*|\d+(?:(?:\.\.|/)\d+)*)", self.section):
                if numbers == "*":
                    if not any(i.startswith(f"{prefix}-{family}-") for i in ids):
                        problems.append(f"{prefix}-{family}-*")
                else:
                    problems += [i for i in self.expand(prefix + "-", family, numbers) if i not in ids]
            for name in re.findall(prefix + r"-INV-[A-Z-]*[A-Z]", self.section):
                if name not in invariants:
                    problems.append(name)
        self.assertEqual(problems, [], "the map cites case ids or invariants that do not exist")

    def test_every_row_has_a_status_and_the_open_rows_say_what_they_need(self) -> None:
        rows = [l for l in self.section.splitlines() if l.startswith("| ") and not l.startswith("| Clause") and not l.startswith("|---")]
        self.assertGreater(len(rows), 10)
        for row in rows:
            cells = [c.strip() for c in row.strip("|").split("|")]
            self.assertEqual(len(cells), 3, row)
            status = cells[1].lower()
            self.assertTrue(any(w in status for w in ("covered", "partly", "open", "not ")), row)
            if "open" in status or "partly" in status:
                self.assertTrue("code" in row.lower() or "waits" in row.lower() or "not a code" in row.lower(), "an open or partial row must say code or waits: " + row)


if __name__ == "__main__":
    unittest.main(verbosity=1)
