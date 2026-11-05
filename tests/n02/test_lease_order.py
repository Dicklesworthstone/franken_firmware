"""The order in which G01 judges a lease token, as the N02 reference models it (bead ffw-ugf).

G01 slice 2 changed `AuthorityToken::check` to judge, in this order: group, stale epoch, future epoch,
issuer, expiry. A coordinator that has been replaced names the old issuer *and* the old epoch, and it
must be refused as stale, not as a foreign issuer. A single-flaw vector cannot tell the two orders
apart; only a token flawed in two ways can, so the golden scenario N02-S032 carries several.

These checks are about the Python model and the golden file. They do not exercise the Rust, which
replays the same scenario centrally.
"""

import itertools
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference as ref  # noqa: E402

ORDER = ["WRONG_GROUP", "STALE_AUTHORITY", "FUTURE_AUTHORITY", "NOT_CONFIGURED_ISSUER", "AUTHORITY_EXPIRED"]
RUST_REPLAY = ref.ROOT / "crates" / "franken-control" / "src" / "channel" / "replay.rs"


def doc():
    return ref.load()


def s032(d):
    return next(s for s in d["scenarios"] if s["id"] == "N02-S032")


def first_in_order(group_bad, epoch_offset, issuer_bad, expired):
    """The code G01 answers, written from the order above and not from the model under test."""
    applicable = {
        "WRONG_GROUP": group_bad,
        "STALE_AUTHORITY": epoch_offset < 0,
        "FUTURE_AUTHORITY": epoch_offset > 0,
        "NOT_CONFIGURED_ISSUER": issuer_bad,
        "AUTHORITY_EXPIRED": expired,
    }
    return next((code for code in ORDER if applicable[code]), "installed")


class OldOrder(ref.Model):
    """G01 before slice 2: group, issuer, stale, future, expiry."""

    def install_lease(self, token, at_ms):
        if not token["group_ok"]:
            return "WRONG_GROUP"
        if not token["issuer_ok"]:
            return "NOT_CONFIGURED_ISSUER"
        return super().install_lease(dict(token, issuer_ok=True), at_ms)


class LeaseOrder(unittest.TestCase):
    def model(self):
        return ref.Model(ref.config_for(doc(), {}))

    def test_every_combination_of_flaws_is_judged_in_g01s_order(self):
        for group_bad, offset, issuer_bad, expired in itertools.product([False, True], [-1, 0, 1], [False, True], [False, True]):
            m = self.model()
            before = dict(m.lease)
            token = {
                "group_ok": not group_bad,
                "issuer_ok": not issuer_bad,
                "epoch": m.epoch + offset,
                "expires_ms": 5 if expired else 1_000_000,
            }
            got = m.install_lease(token, 5)
            want = first_in_order(group_bad, offset, issuer_bad, expired)
            self.assertEqual(got, want, (group_bad, offset, issuer_bad, expired))
            if want != "installed":
                self.assertEqual(m.lease, before, "a refused token must leave the held lease alone")

    def test_a_replaced_coordinators_token_is_stale_not_a_foreign_issuer(self):
        m = self.model()
        token = ref.foreign_token(m, "issuer+stale", 5)
        self.assertEqual(m.install_lease(token, 5), "STALE_AUTHORITY")
        token = ref.foreign_token(m, "issuer+future", 5)
        self.assertEqual(m.install_lease(token, 5), "FUTURE_AUTHORITY")

    def test_compound_flaws_are_built_from_their_parts(self):
        m = self.model()
        token = ref.foreign_token(m, "group+issuer+stale+expired", 7)
        self.assertEqual(token, {"group_ok": False, "issuer_ok": False, "epoch": m.epoch - 1, "expires_ms": 7})
        with self.assertRaises(ValueError):
            ref.foreign_token(m, "issuer+nonsense", 5)


class GoldenScenario(unittest.TestCase):
    PAIRS_THAT_PIN_THE_ORDER = {
        frozenset({"group", "stale"}): "WRONG_GROUP",
        frozenset({"group", "issuer"}): "WRONG_GROUP",
        frozenset({"issuer", "stale"}): "STALE_AUTHORITY",
        frozenset({"issuer", "future"}): "FUTURE_AUTHORITY",
        frozenset({"issuer", "expired"}): "NOT_CONFIGURED_ISSUER",
        frozenset({"stale", "expired"}): "STALE_AUTHORITY",
        frozenset({"future", "expired"}): "FUTURE_AUTHORITY",
    }

    def test_the_scenario_carries_every_pair_that_distinguishes_the_orders(self):
        steps = [s for s in s032(doc())["steps"] if s["op"] == "foreign_lease"]
        pairs = {frozenset(s["flaw"].split("+")): s["expect"] for s in steps if "+" in s["flaw"]}
        self.assertEqual(pairs, self.PAIRS_THAT_PIN_THE_ORDER)

    def test_the_scenario_still_holds_the_five_single_flaw_vectors(self):
        singles = {s["flaw"]: s["expect"] for s in s032(doc())["steps"] if s["op"] == "foreign_lease" and "+" not in s["flaw"]}
        self.assertEqual(
            singles,
            {
                "issuer": "NOT_CONFIGURED_ISSUER",
                "group": "WRONG_GROUP",
                "stale": "STALE_AUTHORITY",
                "future": "FUTURE_AUTHORITY",
                "expired": "AUTHORITY_EXPIRED",
            },
        )

    def test_the_model_passes_it_and_the_old_order_does_not(self):
        d = doc()
        self.assertEqual(ref.replay(d, s032(d)), [])
        problems = ref.replay(d, s032(d), OldOrder)
        self.assertTrue(problems, "the old order must be caught")
        # Exactly the two pairs that put the issuer against an epoch tell the orders apart.
        flawed = sorted(p.split(" step ")[1].split(" ")[0] for p in problems)
        self.assertEqual(len(flawed), 2, problems)
        self.assertTrue(all("expected" in p for p in problems))
        self.assertTrue(any("'STALE_AUTHORITY'" in p for p in problems))
        self.assertTrue(any("'FUTURE_AUTHORITY'" in p for p in problems))

    def test_the_rust_replay_understands_compound_flaws(self):
        source = RUST_REPLAY.read_text(encoding="utf-8")
        self.assertIn("split('+')", source)
        for flaw in ("issuer", "group", "stale", "future", "expired"):
            self.assertIn(f'"{flaw}" =>', source)


if __name__ == "__main__":
    unittest.main()
