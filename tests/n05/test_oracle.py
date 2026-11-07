"""Judge controls use independent hand-derived anchors, never fabricated worker success."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import oracle
import run_cases


class OracleControls(unittest.TestCase):
    def test_pcm_and_rational_timing_hand_anchors(self):
        self.assertEqual(oracle.payload(0)[:4], b"\xd1\x20\xd1\x3f")  # -12000, -11969
        self.assertEqual(oracle.source_time(3), 16_000_000)
        self.assertEqual(oracle.source_time(64), 341_333_333)
        self.assertEqual(oracle.mix(0), 0xE220A8397B1DCDAF)

    def test_window_outage_removes_sources_and_repairs(self):
        _, _, real = oracle.source_oracle("coding_window_outage", oracle.SEED)
        self.assertEqual([i for i, value in enumerate(real) if not value], [4, 5, 6, 7])
        for strategy in ("concealment", "retransmit"):
            self.assertEqual(oracle.expected_plain_or_retransmit("coding_window_outage", strategy, oracle.SEED), real)
        for slot in range(4):
            self.assertIsNone(oracle.arrival("coding_window_outage", oracle.SEED, 1, slot, True, 100_000_000))

    def test_permitted_retransmission_and_late_refusal_are_distinct(self):
        real = oracle.expected_plain_or_retransmit("positive_recovery", "retransmit", oracle.SEED)
        self.assertTrue(all(real))
        late = oracle.expected_plain_or_retransmit("late_repair", "retransmit", oracle.SEED)
        self.assertFalse(late[4])
        self.assertFalse(late[5])
        self.assertTrue(late[6])

    def test_loss_seed_and_channel_draws_do_not_depend_on_strategy(self):
        for seed in (0, 1, 123, oracle.SEED, (1 << 64) - 1):
            first = oracle.source_oracle("independent", seed)
            self.assertEqual(first, oracle.source_oracle("independent", seed))
        self.assertNotEqual(oracle.source_oracle("independent", 0)[0], oracle.source_oracle("independent", 1)[0])

    def test_missing_worker_does_not_shrink_denominator(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = run_cases.main([])
        result = json.loads(out.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(result["blocked"], 12)
        self.assertEqual(result["passed"], 0)

    def test_soak_is_not_run_never_green(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run_cases.main(["--tier", "soak"]), 4)

    def test_process_limits_are_set_before_execution(self):
        with patch.object(run_cases.resource, "setrlimit") as limit:
            run_cases.limits()
        self.assertEqual(limit.call_count, 3)
        limit.assert_any_call(run_cases.resource.RLIMIT_CPU, (5, 5))
        limit.assert_any_call(run_cases.resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
        limit.assert_any_call(run_cases.resource.RLIMIT_CORE, (0, 0))

    def test_every_headline_fec_outcome_has_an_independent_expected_set(self):
        independent = oracle.expected_transport("independent", "raptorq", oracle.SEED)
        self.assertTrue(all(independent["real"]))
        self.assertEqual(independent["decode_windows"], [9])
        burst = oracle.expected_transport("burst", "raptorq", oracle.SEED)
        self.assertEqual([i for i, real in enumerate(burst["real"]) if not real], list(range(19, 36)))
        self.assertEqual(burst["no_information"], [5, 6, 7, 8])
        self.assertEqual(burst["insufficient"], [4])
        self.assertEqual(burst["decode_windows"], [9])

    def test_partial_salvage_and_same_run_post_cancel_recovery_are_required(self):
        for strategy in ("retransmit", "raptorq", "hybrid"):
            partial = oracle.expected_transport("partial_salvage", strategy, oracle.SEED)
            self.assertFalse(partial["real"][4])
            self.assertTrue(partial["real"][5])
            self.assertEqual((partial["late"], partial["admitted"]), (int(strategy != "retransmit"), 1))
            for scenario in ("work_exhausted", "cancelled"):
                expected = oracle.expected_transport(scenario, strategy, oracle.SEED)
                self.assertTrue(expected["real"][12] and expected["real"][13])
                self.assertEqual(expected["admitted"], 2)

    def test_causal_collection_and_hybrid_tail_have_explicit_separate_costs(self):
        retransmit = oracle.expected_transport("burst", "retransmit", oracle.SEED)
        fec = oracle.expected_transport("burst", "raptorq", oracle.SEED)
        hybrid = oracle.expected_transport("burst", "hybrid", oracle.SEED)
        self.assertEqual([i for i,r in enumerate(retransmit["real"]) if not r], list(range(19,24)))
        self.assertEqual([i for i,r in enumerate(fec["real"]) if not r], list(range(19,36)))
        self.assertEqual([i for i,r in enumerate(hybrid["real"]) if not r], [19])
        self.assertEqual(hybrid["tail"]["recovered_blocks"], list(range(20,36)))
        self.assertEqual(hybrid["tail"]["admitted"],17)
        self.assertEqual(hybrid["tail"]["feedback_messages"],5)
        self.assertEqual(hybrid["tail"]["max_outstanding"],4)
        self.assertEqual((hybrid["repair_air"],hybrid["feedback_air"],hybrid["work_charged"]),(89680,160,17850000))
        self.assertEqual(retransmit["original_barriers"][5][1], oracle.source_time(23)+52000000)
        self.assertEqual(hybrid["fec_barriers"][5][1], oracle.source_time(24)+53300000)

    def test_refused_hybrid_tails_preserve_cpu_and_wire_while_later_recovery_is_real(self):
        for scenario in ("late_repair", "partial_salvage", "work_exhausted", "cancelled"):
            tail = oracle.expected_transport(scenario,"hybrid",oracle.SEED)["tail"]
            self.assertEqual((tail["admitted"],tail["air_bytes"],tail["feedback_air_bytes"],tail["work_charged_ns"]),(0,0,0,0))
            self.assertGreater(tail["requested"],0)
        partial = oracle.expected_transport("partial_salvage","hybrid",oracle.SEED)
        self.assertEqual(partial["max_repair_latency"],500500000)

    def test_baseline_retransmit_refuses_the_same_unusable_tail_before_charging(self):
        late = oracle.expected_transport("late_repair", "retransmit", oracle.SEED)
        self.assertEqual((late["deadline_refusals"], late["late"], late["admitted"]), (2, 0, 0))
        self.assertEqual((late["repair_air"], late["feedback_air"], late["work_charged"]), (0, 0, 0))
        partial = oracle.expected_transport("partial_salvage", "retransmit", oracle.SEED)
        self.assertEqual((partial["deadline_refusals"], partial["late"], partial["admitted"]), (1, 0, 1))
        self.assertEqual((partial["repair_air"], partial["feedback_air"], partial["work_charged"]), (1104, 32, 50000))
        for scenario in ("work_exhausted", "cancelled"):
            out = oracle.expected_transport(scenario, "retransmit", oracle.SEED)
            # Only the later permitted window3 spends feedback and wire.
            self.assertEqual((out["feedback_air"], out["repair_air"]), (32, 2208))
            self.assertTrue(out["real"][12] and out["real"][13])


if __name__ == "__main__":
    unittest.main()
