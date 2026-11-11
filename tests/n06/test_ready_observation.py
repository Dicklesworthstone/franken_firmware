"""Synthetic controls for the independent actual-output checker; never native proof."""
import copy
import unittest
from reference import PROFILE, check_ready


def row():
    return {
        "schema": "n06.ready-resource.v1", "profile": PROFILE,
        "current_epoch": 1, "future_epoch": 2, "ready_assertions": 2,
        "target_streams": [9001, 9002], "ready_lengths": [256, 264],
        "before_bytes": [100000, 100000], "pending_bytes": [300000, 300000],
        "after_drop_bytes": [100000, 100000],
        "old_pcm_probe_sha256": ['02295ff7f092558b92f166acca64a4d201abfab6bbf64ea5a708f03f0042cb9a', '4ee6141a6af0f9f19910a78d60a0f62dbc829c572529c13b294f792a24820230'],
        "active_fec_selected": [False, False],
    }


class ReadyObservationControls(unittest.TestCase):
    def test_hand_anchored_positive(self):
        check_ready(row())

    def test_semantic_corruption_fails(self):
        bad = {
            "schema": "other", "profile": "other", "current_epoch": 2,
            "future_epoch": 1, "ready_assertions": 1, "target_streams": [9001, 9001],
            "ready_lengths": [32, 264], "before_bytes": [0, 100000],
            "pending_bytes": [100001, 300000], "after_drop_bytes": [100001, 100000],
            "old_pcm_probe_sha256": ["00" * 32, "00" * 32],
            "active_fec_selected": [False, True],
        }
        for name, value in bad.items():
            broken = row(); broken[name] = value
            with self.subTest(field=name), self.assertRaises(AssertionError):
                check_ready(broken)
        over = row(); over["pending_bytes"] = [2 * 1024 * 1024 + 1, 300000]
        with self.assertRaises(AssertionError):
            check_ready(over)
        swapped = row(); swapped["old_pcm_probe_sha256"] = list(reversed(swapped["old_pcm_probe_sha256"]))
        with self.assertRaises(AssertionError):
            check_ready(swapped)

    def test_missing_unknown_and_nonobject_fail(self):
        for name in row():
            broken = row(); del broken[name]
            with self.subTest(missing=name), self.assertRaises(AssertionError):
                check_ready(broken)
        broken = row(); broken["unadmitted"] = 0
        with self.assertRaises(AssertionError):
            check_ready(broken)
        for value in (None, [], "row"):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                check_ready(value)

    def test_numeric_pair_shape_and_values_are_strict(self):
        names = ("target_streams", "ready_lengths", "before_bytes", "pending_bytes", "after_drop_bytes")
        for name in names:
            for value in (None, "1,2", [1], [1, 2, 3], (1, 2), [True, 2], [1, False], [-1, 2], [1, 2**64], [1, "2"]):
                broken = row(); broken[name] = value
                with self.subTest(field=name, value=value), self.assertRaises(AssertionError):
                    check_ready(broken)
        for lengths in ([513, 264], [256, 0]):
            broken = row(); broken["ready_lengths"] = lengths
            with self.assertRaises(AssertionError):
                check_ready(broken)

    def test_scalar_and_boolean_types_are_strict(self):
        for name in ("current_epoch", "future_epoch", "ready_assertions"):
            for value in (True, False, "1", -1, 2**64, 1.0):
                broken = row(); broken[name] = value
                with self.subTest(field=name, value=value), self.assertRaises(AssertionError):
                    check_ready(broken)
        for value in ([0, False], [False, 0], [], [False], "false", None):
            broken = copy.deepcopy(row()); broken["active_fec_selected"] = value
            with self.subTest(value=value), self.assertRaises(AssertionError):
                check_ready(broken)


if __name__ == "__main__":
    unittest.main()
