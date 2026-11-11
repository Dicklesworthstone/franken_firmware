"""Synthetic oracle controls only. These rows are never native execution evidence."""
import copy
import hashlib
import unittest

from reference import PROFILE, check_future


def row():
    prefix = b"FFWR-N06-v1-source" + bytes(64)
    old = bytes(17 + ((byte % 251 + 19) % 200) for byte in range(1024))
    return {
        "schema": "n06.future-resource.v1", "profile": PROFILE,
        "current_epoch": 1, "future_epoch": 2, "anchor_frame": 0,
        "before_bytes": 100_000, "pending_bytes": 300_000, "after_drop_bytes": 100_000,
        "recovered": 2, "old_real": True, "future_real": True,
        "old_pcm_probe_sha256": hashlib.sha256(prefix + old * 4).hexdigest(),
        "future_pcm_probe_sha256": hashlib.sha256(prefix + bytes([9]) * 4096).hexdigest(),
        "active_fec_selected": False,
    }


class FutureObservationControls(unittest.TestCase):
    def test_hand_anchored_positive_is_accepted(self):
        check_future(row())

    def test_corrupt_pcm_concealment_epoch_activation_and_resource_charges_are_refused(self):
        replacements = {
            "schema": "n06.other.v1", "profile": "other-profile",
            "current_epoch": 2, "future_epoch": 1, "anchor_frame": 1024,
            "before_bytes": 0, "pending_bytes": 100_001, "after_drop_bytes": 100_001,
            "recovered": 0, "old_real": False, "future_real": False,
            "old_pcm_probe_sha256": "00" * 32, "future_pcm_probe_sha256": "00" * 32,
            "active_fec_selected": True,
        }
        for name, wrong in replacements.items():
            broken = row()
            broken[name] = wrong
            with self.subTest(field=name), self.assertRaises(AssertionError):
                check_future(broken)

    def test_missing_and_unknown_fields_fail(self):
        for name in row():
            broken = row()
            del broken[name]
            with self.subTest(missing=name), self.assertRaises(AssertionError):
                check_future(broken)
        extra = row()
        extra["undeclared"] = 0
        with self.assertRaises(AssertionError):
            check_future(extra)

    def test_boolean_string_negative_and_overflow_integers_fail(self):
        names = ("current_epoch", "future_epoch", "anchor_frame", "before_bytes",
                 "pending_bytes", "after_drop_bytes", "recovered")
        for name in names:
            for wrong in (True, False, "1", -1, 2**64, None):
                broken = row()
                broken[name] = wrong
                with self.subTest(field=name, value=wrong), self.assertRaises(AssertionError):
                    check_future(broken)
        for name in ("old_real", "future_real", "active_fec_selected"):
            broken = copy.deepcopy(row())
            broken[name] = int(broken[name])
            with self.subTest(boolean=name), self.assertRaises(AssertionError):
                check_future(broken)


if __name__ == "__main__":
    unittest.main()
