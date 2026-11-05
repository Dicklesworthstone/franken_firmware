"""Checks on the G01 reference model and its vectors (bead ffw-kh0), run by scripts/e2e/g01.

They establish that the golden scenarios are consistent with an independently built model, that the
model can fail (every rule of the contract can be switched off, the unbroken model is shown green
first, and the scenarios and the schedule notice the removals), that the model's ledger voter and the
Rust's view-plus-grant voter reach identical counts on every recorded schedule run, that the numbers
in the vector file are the ones the Rust test source asserts, and that every invariant maps to
scenarios and to Rust tests that exist. They read the Rust source as text. They do not build or run
the Rust.
"""

import copy
import dataclasses
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as ref  # noqa: E402

SESSION_SRC = ref.ROOT / "crates" / "franken-session" / "src"
MEMBERSHIP = SESSION_SRC / "membership.rs"
REPLAY = ref.ROOT / "crates" / "franken-session" / "tests" / "g01_replay.rs"
LIB = SESSION_SRC / "lib.rs"
CONTRACT = ref.ROOT / "docs" / "contracts" / "g01.md"
CASES = Path(__file__).resolve().parent / "cases.json"

KNOWN_OPS = {
    "quorum", "found", "observe", "request", "raw_request", "respond", "gather", "round_start", "round_ack",
    "round_outcome", "record", "restart", "restore", "forget", "node", "issue", "live", "renew", "assume",
    "adopt", "session", "probe", "advance", "discover", "gate", "grant_output", "permitted", "propose", "ack",
    "commit", "abort", "tick", "status", "resolve", "start_gate", "unresolved", "restart_node", "repeat",
}


def doc():
    return ref.load()


def cases():
    return json.loads(CASES.read_text(encoding="utf-8"))


def rust_text():
    return MEMBERSHIP.read_text(encoding="utf-8")


def rust_tests(text):
    return re.findall(r"#\[test\]\s*\n\s*fn (\w+)\(", text)


def rust_floors(text):
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"assert!\(\s*total\.(\w+) >= (\d+)", text)}


def rust_codes(text):
    body = text[text.index("pub const fn code") : text.index("/// Lease naming who may")]
    return set(re.findall(r'=> "([A-Z][A-Z_]+)",', body))


def scenario(doc_, sid):
    return next(s for s in doc_["scenarios"] if s["id"] == sid)


def steps_of(scenario_):
    return ref.expand(scenario_["steps"])


class TwoSlotVoter:
    """The Rust's formulation of a lease voter: one confirmed view and at most one grant. Written here
    only to be run beside the model's ledger on the seeded schedules."""

    def __init__(self, vid, electorate, group, terms, rules):
        self.id, self.electorate, self.group, self.terms = vid, electorate, group, terms
        self.view = None  # (epoch, holder, expires)
        self.grant = None  # dict(epoch, cand, exp, prior)

    def high(self):
        epochs = [x for x in (self.view[0] if self.view else None, self.grant["epoch"] if self.grant else None) if x is not None]
        return max(epochs) if epochs else None

    def confirm(self, view):
        if self.grant is not None and self.grant["epoch"] <= view[0]:
            self.grant = None
        self.view = view

    def observe(self, view):
        epoch, holder, expires = view["epoch"], view["holder"], view["expires"]
        if view.get("group", self.group) != self.group:
            raise ref.Refuse("WRONG_GROUP")
        if holder not in self.electorate:
            raise ref.Refuse("NOT_A_VOTER", member_id=holder)
        high = self.high()
        if high is not None and epoch < high:
            raise ref.Refuse("STALE_AUTHORITY", token_epoch=epoch, current_epoch=high)
        if self.view is not None and self.view[0] == epoch:
            if self.view[1] != holder:
                raise ref.Refuse("CONFLICTING_LEADERS", epoch=epoch, held_by=self.view[1], announced_by=holder)
            expires = max(expires, self.view[2])
        self.confirm((epoch, holder, expires))

    def _request(self, kind, epoch, now, length):
        if length > self.terms["max_lease"]:
            raise ref.Refuse("LEASE_TOO_LONG")
        return {"kind": kind, "group": self.group, "requester": self.id, "epoch": epoch, "expires": now + length}

    def renew_request(self, now, length):
        if self.view is None:
            raise ref.Refuse("NO_LEASE_VIEW")
        if self.view[1] != self.id:
            raise ref.Refuse("NOT_LEASE_HOLDER")
        return self._request("renew", self.view[0], now, length)

    def takeover_request(self, now, length):
        high = self.high()
        if high is None:
            raise ref.Refuse("NO_LEASE_VIEW")
        epoch = self.grant["epoch"] if self.grant is not None and self.grant["cand"] == self.id else high + 1
        return self._request("takeover", epoch, now, length)

    def respond(self, req, now):
        if req["group"] != self.group:
            raise ref.Refuse("WRONG_GROUP")
        if req["requester"] not in self.electorate:
            raise ref.Refuse("NOT_A_VOTER")
        prior = self._renewal(req) if req["kind"] == "renew" else self._takeover(req, now)
        return {"kind": req["kind"], "group": req["group"], "voter": self.id, "requester": req["requester"],
                "epoch": req["epoch"], "expires": req["expires"], "prior": prior}

    def _renewal(self, req):
        high = self.high()
        if high is None:
            raise ref.Refuse("NO_LEASE_VIEW")
        if req["epoch"] < high:
            raise ref.Refuse("STALE_AUTHORITY")
        if self.view is not None and self.view[0] == req["epoch"]:
            if self.view[1] != req["requester"]:
                raise ref.Refuse("NOT_LEASE_HOLDER")
            expires = max(req["expires"], self.view[2])
        elif self.grant is not None and self.grant["epoch"] == req["epoch"]:
            if self.grant["cand"] != req["requester"]:
                raise ref.Refuse("NOT_LEASE_HOLDER")
            expires = max(req["expires"], self.grant["exp"])
        else:
            raise ref.Refuse("FUTURE_AUTHORITY")
        self.confirm((req["epoch"], req["requester"], expires))
        return 0

    def _takeover(self, req, now):
        high = self.high()
        if high is None:
            raise ref.Refuse("NO_LEASE_VIEW")
        g = self.grant
        if g is not None and g["epoch"] == req["epoch"] and g["cand"] == req["requester"]:
            g["exp"] = max(g["exp"], req["expires"])
            return g["prior"]
        if g is not None and g["epoch"] == req["epoch"]:
            raise ref.Refuse("CONFLICTING_LEADERS")
        if req["epoch"] != high + 1:
            raise ref.Refuse("NOT_NEXT_EPOCH")
        known = [x for x in (self.view[2] if self.view else None, g["exp"] if g else None) if x is not None]
        latest = max(known) if known else 0
        if now < latest + self.terms["u"]:
            raise ref.Refuse("LEASE_NOT_EXPIRED")
        self.grant = {"epoch": req["epoch"], "cand": req["requester"], "exp": req["expires"], "prior": latest}
        return latest


def schedule_verdict(rules, floors, voter_class=ref.Voter):
    """What switching a rule off does to the proper-configuration schedules: a list of reasons the
    schedule notices (empty = it does not)."""
    totals = dict.fromkeys(ref.COUNT_FIELDS, 0)
    why = set()
    for skew in (False, True):
        for seed in range(8):
            try:
                counts = ref.run_schedule(seed, 100, 50, skew, 400, rules, voter_class)
            except AssertionError as error:
                why.add("assertion: " + str(error).split(":")[0])
                continue
            if counts["overlaps"] or counts["conflicts"]:
                why.add("violation")
            for key in totals:
                totals[key] += counts[key]
    below = sorted(k for k, v in floors.items() if totals[k] < v)
    if below:
        why.add("below floor: " + ",".join(below))
    return sorted(why)


class Scenarios(unittest.TestCase):
    def test_every_golden_scenario_matches_the_independent_model(self):
        d = doc()
        self.assertGreaterEqual(len(d["scenarios"]), 40)
        for sc in d["scenarios"]:
            with self.subTest(scenario=sc["id"]):
                self.assertEqual(ref.replay(d, sc), [])

    def test_scenarios_are_well_formed(self):
        d = doc()
        ids = [s["id"] for s in d["scenarios"]]
        self.assertEqual(len(ids), len(set(ids)), "scenario ids repeat")
        for sc in d["scenarios"]:
            with self.subTest(scenario=sc["id"]):
                self.assertRegex(sc["id"], r"^G01-S\d{3}$")
                self.assertTrue(sc["invariants"], "a scenario must name the invariants it exercises")
                for st in sc["steps"]:
                    self.assertIn(st["op"], KNOWN_OPS)
                    if st["op"] != "repeat":
                        self.assertIn("expect", st, "%s has no expectation" % st["op"])
                    expect = st.get("expect", {})
                    self.assertTrue(set(expect) <= {"ok", "error", "details"}, expect)

    def test_the_schedule_counts_in_the_file_are_what_the_model_predicts(self):
        self.assertEqual(ref.check_schedule(doc()), [])

    def test_the_replayer_can_fail(self):
        """A replayer that accepted anything would also pass the test above. Change one expected
        number, one expected code and one expected success, and each must be reported."""
        d = doc()
        sc = copy.deepcopy(scenario(d, "G01-S001"))
        self.assertEqual(ref.replay(d, sc), [])
        status = next(s for s in sc["steps"] if s["op"] == "status")
        status["expect"]["ok"]["status"]["missing"] = ["a", "b"]
        self.assertTrue(ref.replay(d, sc), "a wrong list was accepted")

        sc = copy.deepcopy(scenario(d, "G01-S005"))
        commit = next(s for s in sc["steps"] if s["op"] == "commit")
        commit["expect"] = {"error": "MEMBER_NOT_READY"}
        self.assertTrue(ref.replay(d, sc), "a wrong error code was accepted")

        sc = copy.deepcopy(scenario(d, "G01-S105"))
        sc["steps"][-1]["expect"] = {"ok": {}}
        self.assertTrue(ref.replay(d, sc), "a refusal was accepted as success")

        sc = copy.deepcopy(scenario(d, "G01-S106"))
        refusal = next(s for s in sc["steps"] if s["expect"].get("error") == "LEASE_NOT_EXPIRED")
        refusal["expect"]["details"]["conservative_expiry_ns"] = 1051
        self.assertTrue(ref.replay(d, sc), "a wrong number inside a refusal was accepted")


class Rules(unittest.TestCase):
    """Every rule of the contract is a switch of the model. The unbroken model is shown green first
    (above); then each rule off must be noticed by the scenarios, and the schedule's response is pinned."""

    def test_every_rule_removed_is_noticed_by_a_scenario_except_the_cluster_only_one(self):
        d = doc()
        self.assertTrue(all(not ref.replay(d, s) for s in d["scenarios"]), "the unbroken model must be green first")
        uncaught = []
        for field in dataclasses.fields(ref.Rules):
            rules = ref.Rules(**{field.name: False})
            noticed = []
            for sc in d["scenarios"]:
                try:
                    problems = ref.replay(d, sc, rules)
                except Exception:  # noqa: BLE001 - a broken rule may crash the model; that is noticed too
                    problems = ["crash"]
                if problems:
                    noticed.append(sc["id"])
            if not noticed:
                uncaught.append(field.name)
        # winner_observes lives in the cluster (the winner's own voter learning its lease); only the
        # schedule can see it, and the next test shows the schedule does.
        self.assertEqual(uncaught, ["winner_observes"])

    def test_the_schedule_response_to_each_rule_is_the_one_recorded_in_cases_json(self):
        floors = rust_floors(rust_text())
        self.assertTrue(floors, "could not read the Rust floors")
        self.assertEqual(schedule_verdict(ref.Rules(), floors), [], "the unbroken schedule must be clean first")
        recorded = cases()["rule_matrix"]
        self.assertEqual(sorted(recorded), sorted(f.name for f in dataclasses.fields(ref.Rules)))
        for field in dataclasses.fields(ref.Rules):
            with self.subTest(rule=field.name):
                noticed = schedule_verdict(ref.Rules(**{field.name: False}), floors)
                kind = recorded[field.name]["schedule"]
                self.assertIn(kind, {"defends", "equivalent", "out_of_scope"})
                if kind == "defends":
                    self.assertTrue(noticed, "the schedule no longer notices %s being removed" % field.name)
                else:
                    self.assertEqual(noticed, [], "the schedule now notices %s: update cases.json" % field.name)

    def test_the_rules_the_contract_calls_redundant_are_the_ones_marked_equivalent(self):
        text = CONTRACT.read_text(encoding="utf-8")
        section = text[text.index("### 6.5") : text.index("### 6.6")]
        equivalent = {k for k, v in cases()["rule_matrix"].items() if v["schedule"] == "equivalent"}
        self.assertEqual(equivalent, {"holder_margin", "refuse_older_renewal", "next_epoch_only"})
        self.assertIn("holder margin", section.lower())
        self.assertIn("older-epoch", section.lower())
        self.assertIn("next-epoch-only", section.lower())


class Formulations(unittest.TestCase):
    def test_the_rusts_view_plus_grant_voter_reaches_the_same_counts_as_the_ledger_on_every_run(self):
        d = doc()
        self.assertEqual(
            ref.check_schedule(d, voter_class=TwoSlotVoter), [],
            "the two state representations disagree on a recorded schedule run",
        )

    def test_the_planted_runs_overlap_in_every_seed_and_the_proper_runs_never_do(self):
        runs = doc()["schedule"]["runs"]
        planted = [r for r in runs if r["label"].startswith("PLANTED")]
        proper = [r for r in runs if r["u"] == 100]
        agreeing = [r for r in runs if r["u"] == 0 and r["max_offset"] == 0]
        self.assertEqual((len(planted), len(proper), len(agreeing)), (8, 16, 8))
        self.assertTrue(all(r["counts"]["overlaps"] >= 1 for r in planted))
        self.assertTrue(all(r["counts"]["overlaps"] == 0 and r["counts"]["conflicts"] == 0 for r in proper + agreeing))


class Mapping(unittest.TestCase):
    def test_every_invariant_maps_to_scenarios_and_rust_tests_that_exist(self):
        d, c, text = doc(), cases(), rust_text()
        tests = set(rust_tests(text))
        declared = {i["id"]: i for i in c["invariants"]}
        self.assertEqual(len(declared), len(c["invariants"]), "invariant ids repeat")
        named = {}
        for sc in d["scenarios"]:
            for inv in sc["invariants"]:
                self.assertIn(inv, declared, "%s names an undeclared invariant %s" % (sc["id"], inv))
                named.setdefault(inv, []).append(sc["id"])
        for inv_id, inv in declared.items():
            with self.subTest(invariant=inv_id):
                self.assertEqual(sorted(inv["scenarios"]), sorted(named.get(inv_id, [])))
                self.assertTrue(inv["rust_tests"], "no Rust test named")
                for name in inv["rust_tests"]:
                    self.assertIn(name, tests, "Rust test %s does not exist" % name)
        runs = {r["label"] for r in d["schedule"]["runs"]}
        for inv in c["schedule_invariants"]:
            self.assertTrue(set(inv["labels"]) <= runs, inv["id"])
            for name in inv["rust_tests"]:
                self.assertIn(name, tests)

    def test_every_rust_test_is_mapped_or_listed_as_rust_only(self):
        c = cases()
        mapped = set(c["rust_only"])
        for inv in c["invariants"] + c["schedule_invariants"]:
            mapped.update(inv["rust_tests"])
        unmapped = sorted(set(rust_tests(rust_text())) - mapped)
        self.assertEqual(unmapped, [], "Rust tests that no invariant names")
        for name in c["rust_only"]:
            self.assertIn(name, rust_tests(rust_text()))


class AgainstTheRustSource(unittest.TestCase):
    """Text checks of the model and the vectors against the Rust source and the contract."""

    def test_the_model_and_the_scenarios_use_only_codes_the_rust_defines_and_cover_all_of_them(self):
        codes = rust_codes(rust_text())
        self.assertEqual(len(codes), 42)
        modelled = set(re.findall(r'Refuse\("([A-Z][A-Z_]+)"', (Path(ref.__file__)).read_text(encoding="utf-8")))
        self.assertEqual(sorted(modelled - codes), [], "the model raises a code the Rust does not define")
        used = set()
        for sc in doc()["scenarios"]:
            for st in steps_of(sc):
                if "error" in st["expect"]:
                    used.add(st["expect"]["error"])
        self.assertEqual(sorted(used - codes), [])
        self.assertEqual(sorted(codes - used), [], "stable codes no scenario exercises")

    def test_the_codes_the_contract_does_not_name_are_exactly_the_recorded_gap(self):
        codes = rust_codes(rust_text())
        text = CONTRACT.read_text(encoding="utf-8")
        missing = sorted(c for c in codes if c not in text)
        self.assertEqual(missing, sorted(cases()["known_gaps"]["codes_missing_from_the_contract"]))

    def test_the_constants_the_model_assumes_are_the_ones_in_the_rust(self):
        text = rust_text()

        def number(pattern):
            return int(re.search(pattern, text).group(1).replace("_", ""))

        self.assertEqual(number(r"pub const MAX_TERMINAL_HISTORY: usize = ([\d_]+);"), ref.MAX_TERMINAL_HISTORY)
        self.assertEqual(number(r"pub const MAX_GROUP_MEMBERS: usize = ([\d_]+);"), ref.Config().max_members)
        self.assertEqual(number(r"min_cutover_lead_frames: ([\d_]+),\s*\n\s*max_members"), ref.Config().lead)
        defaults = ref.Config()
        self.assertEqual(number(r"max_lease_ns: ([\d_]+),\s*\n\s*clock_uncertainty_ns: 0"), defaults.max_lease)
        self.assertEqual(number(r"max_output_horizon_ns: ([\d_]+),\s*\n\s*\}"), defaults.horizon_ns)
        self.assertEqual(number(r"max_output_horizon_frames: ([\d_]+),\s*\n\s*epoch_mint"), defaults.horizon_frames)
        self.assertEqual(defaults.u, 0)
        # the two horizons describe one duration: 10 s as 48 kHz frames and as nanoseconds
        self.assertEqual(defaults.horizon_frames * 1_000_000_000 // 48_000, defaults.horizon_ns)

    def test_the_schedule_in_the_vector_file_is_the_one_the_rust_test_runs(self):
        text = rust_text()
        self.assertIn("run_partition_schedule(seed, 100, 50, skew_holder, 400)", text)
        self.assertIn("run_partition_schedule(seed, 0, 50, true, 400)", text)
        self.assertIn("run_partition_schedule(seed, 0, 0, false, 400)", text)
        self.assertEqual(len(re.findall(r"for seed in 0\.\.8_u64", text)), 4, "seed ranges changed")
        self.assertEqual(doc()["schedule"]["steps"], 400)
        # the draw structure the model reproduces
        for fragment in ("self.true_ns += 1 + self.rng.below(300)", "500 + self.rng.below(1_500)", "match self.rng.below(100)",
                         "0..30 =>", "30..65 =>", "65..85 =>", "self.rng.below(3) == 0", "self.rng.below(4) == 0"):
            self.assertIn(fragment, text)

    def test_the_totals_of_the_recorded_proper_runs_meet_every_floor_the_rust_asserts(self):
        floors = rust_floors(rust_text())
        self.assertEqual(
            sorted(floors),
            sorted(["renewals", "takeovers", "takeovers_refused", "minority_refused", "fenced", "mutations_accepted",
                    "led_steps", "leaderless_steps"]),
        )
        runs = [r for r in doc()["schedule"]["runs"] if r["u"] == 100]
        for key, floor in floors.items():
            total = sum(r["counts"][key] for r in runs)
            self.assertGreaterEqual(total, floor, "%s: the model predicts %d, the Rust asserts at least %d" % (key, total, floor))
            self.assertLess(floor * 1.0, total, "%s: the floor equals the prediction, so it is not a floor" % key)

    def test_the_test_count_the_contract_states_is_the_count_in_the_source(self):
        text = CONTRACT.read_text(encoding="utf-8")
        stated = re.search(r"expect (\d+) \+ (\d+) = (\d+) passed", text)
        self.assertIsNotNone(stated, "the contract no longer states the expected test count")
        lib_tests, membership_tests, total = (int(g) for g in stated.groups())
        self.assertEqual(len(rust_tests(LIB.read_text(encoding="utf-8"))), lib_tests)
        self.assertEqual(len(rust_tests(rust_text())), membership_tests)
        self.assertEqual(lib_tests + membership_tests, total)

    def test_the_counts_the_contract_states_about_the_vectors_are_true(self):
        text = CONTRACT.read_text(encoding="utf-8")
        scenarios = re.search(r"replays (\d+)\s+hand-written\s+scenarios", text)
        runs = re.search(r"exact\s+counts\s+of\s+(\d+)\s+recorded\s+schedule\s+runs", text)
        self.assertIsNotNone(scenarios, "the contract no longer states the scenario count")
        self.assertIsNotNone(runs, "the contract no longer states the schedule run count")
        self.assertEqual(int(scenarios.group(1)), len(doc()["scenarios"]))
        self.assertEqual(int(runs.group(1)), len(doc()["schedule"]["runs"]))
        self.assertIn("scripts/e2e/g01", text)

    def test_the_authority_order_in_the_contract_is_the_order_the_model_and_the_scenarios_use(self):
        text = CONTRACT.read_text(encoding="utf-8")
        section = text[text.index("## 1. Authority") : text.index("## 2. The cutover protocol")]
        table = re.findall(r"\| `[^`]*` [^|]*\| `([A-Z_]+)`", section)
        self.assertEqual(
            table[:5],
            ["WRONG_GROUP", "STALE_AUTHORITY", "FUTURE_AUTHORITY", "NOT_CONFIGURED_ISSUER", "AUTHORITY_EXPIRED"],
        )
        # the model, given tokens flawed two ways, answers by that order
        session = ref.Session("coord")
        rules = ref.Rules()

        def answer(**flaws):
            token = ref.token_of("grp", "coord", 1, 10**9)
            token.update(flaws)
            try:
                ref.authorize(rules, session, token, 1000, 0)
            except ref.Refuse as refusal:
                return refusal.code
            return "ok"

        self.assertEqual(answer(group="other", epoch=0), "WRONG_GROUP")
        self.assertEqual(answer(issuer="x", epoch=0), "STALE_AUTHORITY")
        self.assertEqual(answer(issuer="x", epoch=9), "FUTURE_AUTHORITY")
        self.assertEqual(answer(issuer="x", expires=1000), "NOT_CONFIGURED_ISSUER")
        self.assertEqual(answer(epoch=0, expires=1000), "STALE_AUTHORITY")
        self.assertEqual(answer(expires=1000), "AUTHORITY_EXPIRED")


class ReplaySource(unittest.TestCase):
    """Text checks of the Rust replay (crates/franken-session/tests/g01_replay.rs) against this side.
    They read the file as text; they do not build it."""

    @staticmethod
    def source():
        return REPLAY.read_text(encoding="utf-8")

    def test_the_replay_has_exactly_the_tests_cases_json_names(self):
        names = re.findall(r"#\[test\]\s*\nfn (\w+)\(", self.source())
        self.assertEqual(sorted(names), sorted(cases()["replay"]["tests"]))
        self.assertEqual(len(names), len(set(names)))

    def test_the_replay_reads_the_vector_file_and_knows_the_models_ops_plants_and_constants(self):
        text = self.source()
        self.assertIn('include_str!("vectors/g01_scenarios.json")', text)
        ops_block = text[text.index("const KNOWN_OPS"): text.index("];", text.index("const KNOWN_OPS"))]
        self.assertEqual(set(re.findall(r'"([a-z_]+)"', ops_block)), KNOWN_OPS)
        plants_block = text[text.index("const PLANTS"): text.index("];", text.index("const PLANTS"))]
        self.assertEqual(re.findall(r'"([a-z_]+)"', plants_block), list(ref.PLANTS))
        far = re.search(r"const FAR_FUTURE: u64 = ([\d_]+);", text)
        self.assertEqual(int(far.group(1).replace("_", "")), ref.FAR_FUTURE)

    def test_the_replay_implements_every_op_it_claims_to_know(self):
        text = self.source()
        for op in sorted(KNOWN_OPS - {"repeat"}):
            self.assertRegex(text, r'"%s"\s*=>' % op, "the replay has no arm for op %s" % op)
        self.assertIn('Some("repeat")', text)

    def test_the_replay_plants_the_faults_the_model_plants(self):
        text = self.source()
        for plant in ref.PLANTS:
            self.assertIn('"%s"' % plant, text)
        # the plants are in the driver, not in the engine: nothing in the crate's source mentions them
        for source_file in SESSION_SRC.glob("*.rs"):
            body = source_file.read_text(encoding="utf-8")
            for plant in ref.PLANTS:
                self.assertNotIn(plant, body, "%s carries a fault switch" % source_file.name)

    def test_the_replays_schedule_driver_draws_like_the_model_and_the_in_crate_test(self):
        text = self.source()
        for fragment in ("self.true_ns += 1 + self.rng.below(300)", "500 + self.rng.below(1_500)", "match self.rng.below(100)",
                         "0..30 =>", "30..65 =>", "65..85 =>", "self.rng.below(3) == 0", "self.rng.below(4) == 0",
                         "self.true_ns += 200", "self.true_ns += 4_000", "self.true_ns += 3_000",
                         "0x9E37_79B9_7F4A_7C15", "0xBF58_476D_1CE4_E5B9", "0x94D0_49BB_1331_11EB"):
            self.assertIn(fragment, text)
            self.assertIn(fragment, rust_text() if fragment not in ("self.true_ns += 200",) else text)
        self.assertEqual(rust_text().count("founding = 11_500"), text.count("founding = 11_500"))

    def test_the_contract_states_how_many_tests_the_replay_adds(self):
        text = CONTRACT.read_text(encoding="utf-8")
        stated = re.search(r"integration target `g01_replay` adds (\d+)", text)
        self.assertIsNotNone(stated, "the contract no longer states the replay's test count")
        self.assertEqual(int(stated.group(1)), len(cases()["replay"]["tests"]))
        self.assertIn("--test g01_replay", text)
        self.assertIn("scripts/e2e/g01 --judge", text)


class Cluster(unittest.TestCase):
    def test_the_prologue_takes_every_rare_path_in_every_seed(self):
        for seed in range(8):
            with self.subTest(seed=seed):
                n = 3 + 2 * (seed % 2)
                cluster = ref.Cluster(seed, n, 100, 50)
                cluster.prologue()  # raises AssertionError if a scripted path does not behave
                self.assertEqual(cluster.c["overlaps"], 0)
                self.assertGreaterEqual(cluster.c["takeovers"], 2)
                self.assertGreaterEqual(cluster.c["fenced"], 1)
                self.assertGreaterEqual(cluster.c["minority_refused"], 1)

    def test_a_cluster_without_the_one_candidate_rule_lets_the_duel_produce_two_winners(self):
        broken = ref.Rules(one_candidate=False)
        with self.assertRaises(AssertionError):
            ref.Cluster(0, 3, 100, 50, False, broken).prologue()


if __name__ == "__main__":
    unittest.main()
