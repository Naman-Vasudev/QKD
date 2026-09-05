"""
Unit Test Suite for App Helper Functions and UI Presentation Formatting (Phase 3).
"""

import unittest
import numpy as np
from qds.encoding import sha256_bits
from evaluation.runner import run_experiment


class TestAppHelpers(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "AppHelperTest"
        self.key_balanced = [i % 2 for i in range(256)]

    def test_digest_bits_conversion(self) -> None:
        bits = sha256_bits(self.message)
        self.assertEqual(len(bits), 256)
        self.assertTrue(all(b in (0, 1) for b in bits))

        # Check hex digest conversion consistency
        digest_hex = "".join(f"{b:02x}" for b in np.packbits(bits))
        self.assertEqual(len(digest_hex), 64)

    def test_experiment_result_fields(self) -> None:
        res = run_experiment(
            attack_name="No Attack / Baseline",
            message=self.message,
            shared_key=self.key_balanced,
            seed=123,
        )
        self.assertTrue(hasattr(res, "attack_name"))
        self.assertTrue(hasattr(res, "observed_error_rate"))
        self.assertTrue(hasattr(res, "threat_result"))
        self.assertTrue(hasattr(res, "protocol_note"))
        self.assertEqual(res.message, self.message)

    def test_random_key_generation_helper(self) -> None:
        random_key = list(np.random.randint(0, 2, size=256))
        self.assertEqual(len(random_key), 256)
        self.assertTrue(all(k in (0, 1) for k in random_key))


if __name__ == "__main__":
    unittest.main()
