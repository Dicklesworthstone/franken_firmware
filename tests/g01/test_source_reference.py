"""Checks on the G01 source-arbitration reference (contract section 10), run by scripts/e2e/g01.

They establish that the reference is a trustworthy oracle for the Rust: its scenarios hold under the
contract's rules, every rule can be switched off and something notices, the three planted defects are
noticed by the scenarios and by the seeded schedule, the table is the one the contract states, and the
Rust source agrees with it (error names, table cells, enum order, the schedule's draw order and
re-exports). They do not exercise the Rust.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_reference as sr  # noqa: E402

SESSION_SRC = sr.ROOT / "crates" / "franken-session" / "src"
SOURCE = SESSION_SRC / "source.rs"
TESTS = SESSION_SRC / "source" / "tests.rs"
LIB = SESSION_SRC / "lib.rs"
CONTRACT = sr.ROOT / "docs" / "contracts" / "g01.md"

# Rules only a scenario can notice: the schedule's sources never present an epoch above the current
# one, the counter never nears 2^64 and the labels are fixed.
SCENARIO_ONLY = {"future_refused", "exhaustion_checked", "label_checked"}


def rust(path):
    return path.read_text(encoding="utf-8")


class Scenarios(unittest.TestCase):
    def test_every_scenario_holds_under_the_rules_of_the_contract(self):
        results = sr.run_scenarios()
        self.assertEqual(sr.failing(results), [])
        self.assertGreaterEqual(len(results), 50)

    def test_the_table_is_the_one_written_out_by_hand(self):
        self.assertEqual(len(sr.EXPECTED_CELLS), len(sr.KINDS) * len(sr.CLASSES))
        for (kind, cls), want in sr.EXPECTED_CELLS.items():
            self.assertEqual(sr.STANDARD[kind][cls], want, (kind, cls))
        self.assertEqual({(k, c) for k in sr.KINDS for c in sr.CLASSES}, set(sr.EXPECTED_CELLS))

    def test_every_cell_of_the_table_is_exercised_against_both_kinds_of_incumbent(self):
        ids = [sid for sid, _ in sr.cell_scenarios()]
        self.assertEqual(len(ids), 2 * 3 * 4)
        self.assertEqual(len(set(ids)), len(ids))

    def test_the_authority_margin_makes_a_holder_stop_early(self):
        session = sr.base.Session("coord")
        token = sr.token_of(session.group, session.coord, session.epoch, 5_050)
        with_margin = sr.Arbiter(margin=100)
        with self.assertRaises(sr.Refuse) as caught:
            with_margin.submit(session, token, 5_000, sr.SOURCES["s"], "start", 0)
        self.assertEqual(caught.exception.code, "AUTHORITY_EXPIRED")
        without = sr.Arbiter()
        receipt = without.submit(session, token, 5_000, sr.SOURCES["s"], "start", 0)
        self.assertEqual(receipt["epoch"], 1)


class Planted(unittest.TestCase):
    """The three planted negatives, each broken in a copy of the engine and caught."""

    PLANTS = {
        "publish_validated": ("G01S-003-replaced-source-cannot-publish", "reached output"),
        "start_cas": ("G01S-004-two-starts-that-saw-the-same-epoch-admit-one", "saw the same epoch"),
        "seek_validated": ("G01S-005-a-seek-from-the-losing-epoch-is-not-applied", "seek admitted at epoch"),
    }

    def test_each_plant_breaks_its_scenario_and_the_schedule(self):
        for rule, (scenario, needle) in self.PLANTS.items():
            with self.subTest(rule=rule):
                failed = sr.failing(sr.run_scenarios(sr.broken(rule)))
                self.assertIn(scenario, failed)
                _, violations = sr.run_all_seeds(sr.broken(rule))
                self.assertTrue(any(needle in v for v in violations), (rule, violations[:3]))

    def test_removing_the_contest_from_each_scenario_makes_its_expectation_fail(self):
        # The planted negatives are only meaningful if the scenario depends on the contest it creates.
        by_id = dict(sr.scenarios())
        contest_step = {
            "G01S-003-replaced-source-cannot-publish": 1,  # the replacing start
            "G01S-004-two-starts-that-saw-the-same-epoch-admit-one": 0,  # the first, winning start
            "G01S-005-a-seek-from-the-losing-epoch-is-not-applied": 1,  # the replacing start
        }
        for scenario, index in contest_step.items():
            steps = [s for i, s in enumerate(by_id[scenario]) if i != index]
            self.assertTrue(sr.run_steps(steps), scenario)

    def test_the_unbroken_rules_pass_the_same_checks(self):
        self.assertEqual(sr.failing(sr.run_scenarios()), [])
        _, violations = sr.run_all_seeds()
        self.assertEqual(violations, [])


class Mutations(unittest.TestCase):
    def test_every_rule_can_be_broken_and_something_notices(self):
        matrix = sr.mutation_matrix()
        self.assertEqual(set(matrix), set(sr.RULE_NAMES))
        for name, (failed, found) in matrix.items():
            with self.subTest(rule=name):
                self.assertTrue(failed or found, "nothing notices a broken `%s`" % name)

    def test_the_schedule_notices_every_rule_except_the_declared_scenario_only_ones(self):
        matrix = sr.mutation_matrix()
        for name, (failed, found) in matrix.items():
            if name in SCENARIO_ONLY:
                self.assertEqual(found, [], name)
                self.assertTrue(failed, name)
            else:
                self.assertTrue(found, "the schedule does not notice a broken `%s`" % name)

    def test_a_broken_rule_is_caught_by_a_scenario_that_names_it(self):
        expected = {
            "authority_first": "G01S-009-authority-is-judged-before-the-source",
            "owner_restart_mints": "G01S-006-the-owner-starting-again-is-a-new-stream",
            "stop_mints": "G01S-007-stop-ends-the-stream-and-fences-its-late-blocks",
            "future_refused": "G01S-008-an-epoch-from-the-future-is-refused",
            "group_epoch_effective": "G01S-010-a-group-epoch-advance-voids-the-program",
            "group_epoch_fenced_publish": "G01S-010-a-group-epoch-advance-voids-the-program",
            "refusal_pure": "G01S-011-a-refusal-changes-nothing",
            "exhaustion_checked": "G01S-C04-an-exhausted-counter-refuses-to-mint",
            "label_checked": "G01S-018-labels",
        }
        for rule, scenario in expected.items():
            with self.subTest(rule=rule):
                self.assertIn(scenario, sr.failing(sr.run_scenarios(sr.broken(rule))))


class Schedule(unittest.TestCase):
    def test_the_schedule_is_deterministic_and_clean(self):
        first, violations = sr.run_all_seeds()
        second, _ = sr.run_all_seeds()
        self.assertEqual(first, second)
        self.assertEqual(violations, [])

    def test_the_schedule_reaches_every_path_it_is_meant_to(self):
        totals, _ = sr.run_all_seeds()
        for field in sr.COUNT_FIELDS:
            if field == "future_refused":
                self.assertEqual(totals.get(field, 0), 0)
            else:
                self.assertGreater(totals.get(field, 0), 0, field)

    def test_a_race_round_never_admits_two_new_epochs(self):
        totals, _ = sr.run_all_seeds()
        self.assertGreaterEqual(totals["race_rounds"], 100)
        self.assertGreaterEqual(totals["race_winners"], 50)
        _, violations = sr.run_all_seeds(sr.broken("start_cas"))
        self.assertTrue(any("saw the same epoch" in v for v in violations))


class RustAgreement(unittest.TestCase):
    def test_rust_error_names_are_the_contract_names(self):
        text = rust(SOURCE)
        start = text.index("pub const fn code(&self)")
        end = text.index("\n    }\n}", start)
        names = set(re.findall(r'=> "([A-Z_]+)"', text[start:end]))
        self.assertEqual(sorted(names ^ set(sr.SOURCE_CODES)), [])

    def test_the_label_limit_matches(self):
        self.assertIn("pub const MAX_SOURCE_LABEL_BYTES: usize = %d;" % sr.MAX_LABEL, rust(SOURCE))
        self.assertIn("1 to %d bytes" % sr.MAX_LABEL, rust(SOURCE))

    def test_enum_order_matches(self):
        text = rust(SOURCE)
        for enum, names in (("SourceKind", ("Spotify", "AirPlay2", "LineIn")),
                            ("CommandClass", ("Start", "Seek", "GroupChange", "Stop"))):
            body = re.search(r"pub enum %s \{(.*?)\n\}" % enum, text, re.S).group(1)
            declared = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*),?$", re.sub(r"///.*", "", body), re.M)
            self.assertEqual(declared, list(names), enum)
        self.assertEqual(list(sr.KINDS), ["spotify", "airplay2", "line_in"])
        self.assertEqual(list(sr.CLASSES), ["start", "seek", "group_change", "stop"])

    def test_the_rust_table_is_the_reference_table(self):
        text = rust(SOURCE)
        block = text[text.index("pub const STANDARD"):text.index("#[must_use]", text.index("pub const STANDARD"))]
        cells = [c.lower() for c in re.findall(r"SourcePolicy::(Replace|Reject)", block)]
        want = [sr.STANDARD[kind][cls] for kind in sr.KINDS for cls in sr.CLASSES]
        self.assertEqual(cells, want)

    def test_the_rust_order_of_checks_is_the_contracts(self):
        text = rust(SOURCE)
        body = text[text.index("pub fn submit"):text.index("pub fn check_publish")]
        positions = [body.index(fragment) for fragment in (
            "check_with_margin", "SourceEpochStale", "SourceEpochFuture", "self.decide(", "SourceEpochExhausted")]
        self.assertEqual(positions, sorted(positions))
        gate = text[text.index("pub fn check_publish"):]
        positions = [gate.index(fragment) for fragment in (
            "NoActiveSource", "GroupEpochAdvanced", "self.owner.as_ref()", "SourceReplaced", "SourceEpochFuture", "NotSourceOwner")]
        self.assertEqual(positions, sorted(positions))

    def test_lib_reexports_every_public_item(self):
        text = rust(SOURCE)
        public = set(re.findall(r"^pub (?:struct|enum|const) ([A-Za-z_][A-Za-z0-9_]*)", text, re.M))
        exported = re.search(r"pub use source::\{(.*?)\};", rust(LIB), re.S).group(1)
        exported = {name.strip() for name in exported.split(",") if name.strip()}
        self.assertEqual(public, exported)
        self.assertIn("mod source;", rust(LIB))

    def test_the_rust_schedule_draws_like_the_reference(self):
        text = rust(TESTS)
        for fragment in (
            "SplitMix64(seed ^ 0x4730_3153)", "0x9E37_79B9_7F4A_7C15", "0xBF58_476D_1CE4_E5B9", "0x94D0_49BB_1331_11EB",
            "self.now += 1 + self.rng.below(5)", "let roll = self.rng.below(100)", "roll < 28", "roll < 42", "roll < 50",
            "roll < 56", "roll < 78", "roll < 90", "roll < 95", "roll < 98", "2 + self.rng.below(3)",
            "self.rng.below(6) == 0", "CommandClass::ALL[self.rng.pick(4)]", "const SCHEDULE_SEEDS: u64 = %d;" % len(sr.SCHEDULE_SEEDS),
            "const SCHEDULE_STEPS: usize = %d;" % sr.SCHEDULE_STEPS,
        ):
            self.assertIn(fragment, text)
        self.assertIn('const SCHEDULE_SOURCES: [&str; 4] = ["s", "a", "b", "l"];', text)
        self.assertEqual(sr.SCHEDULE_SOURCES, ("s", "a", "b", "l"))

    def test_the_rust_floors_are_about_a_third_of_the_references_totals(self):
        totals, _ = sr.run_all_seeds()
        text = rust(TESTS)
        start = text.index("let floors")
        block = text[start:text.index("];", start)]
        floors = dict((name, int(n)) for name, n in re.findall(r'\("([a-z_]+)", (\d+)\)', block))
        self.assertEqual(set(floors), set(sr.COUNT_FIELDS) - {"future_refused"})
        for name, floor in floors.items():
            total = totals[name]
            self.assertLessEqual(floor, total // 2, name)
            self.assertGreaterEqual(floor * 4, total, name)

    def test_the_rust_scenarios_and_the_reference_agree_on_the_hand_written_cells(self):
        text = rust(TESTS)
        cells = re.findall(r"\(\s*SourceKind::(\w+),\s*CommandClass::(\w+),\s*SourcePolicy::(Replace|Reject),?\s*\)", text)
        kinds = {"Spotify": "spotify", "AirPlay2": "airplay2", "LineIn": "line_in"}
        classes = {"Start": "start", "Seek": "seek", "GroupChange": "group_change", "Stop": "stop"}
        got = {(kinds[k], classes[c]): p.lower() for k, c, p in cells[:12]}
        self.assertEqual(got, sr.EXPECTED_CELLS)


class Contract(unittest.TestCase):
    def section(self):
        text = rust(CONTRACT)
        return text[text.index("## 10. Source ownership arbitration"):]

    def test_the_contract_states_the_table_the_code_has(self):
        section = self.section()
        for kind, label in (("spotify", "Spotify"), ("airplay2", "AirPlay 2"), ("line_in", "Line-in")):
            row = next(line for line in section.splitlines() if line.startswith("| %s |" % label))
            cells = [c.strip().lower() for c in row.strip("|").split("|")[1:]]
            self.assertEqual(cells, [sr.STANDARD[kind][cls] for cls in sr.CLASSES], label)

    def test_every_error_code_is_documented(self):
        section = self.section()
        for code in sr.SOURCE_CODES:
            self.assertIn("`%s`" % code, section, code)

    def test_every_rust_test_is_named_in_the_contract_and_every_named_test_exists(self):
        section = self.section()
        names = set(re.findall(r"#\[test\]\s+fn (\w+)\(", rust(TESTS)))
        self.assertGreaterEqual(len(names), 25)
        for name in sorted(names):
            self.assertIn("`%s`" % name, section, "the contract does not name `%s`" % name)
        for named in re.findall(r"`([a-z][a-z0-9_]{30,})`", section):
            self.assertIn(named, names, "the contract names a test that does not exist: %s" % named)

    def test_the_contract_states_the_reference_numbers(self):
        section = self.section()
        totals, _ = sr.run_all_seeds()
        self.assertIn("%d scenarios" % (len(sr.scenarios()) + len(sr.custom_scenarios())), section)
        self.assertIn("%d seeds of %d steps" % (len(sr.SCHEDULE_SEEDS), sr.SCHEDULE_STEPS), section)
        self.assertIn("%d racing rounds" % totals["race_rounds"], section)
        names = set(re.findall(r"#\[test\]\s+fn (\w+)\(", rust(TESTS)))
        self.assertIn("%d unit tests" % len(names), section)
        self.assertIn("adds %d\ntests" % len(names), section)


if __name__ == "__main__":
    unittest.main()
