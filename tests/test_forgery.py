"""
Unit Test Suite for Digital Signature Forgery Attack Simulator.
"""

import unittest
from attacks.forgery import create_forged_encoded_qubits, run_forgery_attack
from qds.verification import verify_signature


class TestForgeryAttack(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "QuantumSignatureForgeryTest"
        self.key_balanced = [i % 2 for i in range(256)]           # Exactly 50% ones (128 ones)
        self.key_quarter = [1] * 64 + [0] * 192                    # Exactly 25% ones (64 ones)
        self.key_zeros = [0] * 256                                 # 0% ones
        self.key_ones = [1] * 256                                  # 100% ones

    def test_1_forgery_produces_quantum_verification_errors(self) -> None:
        # Test 1: Forgery produces actual quantum verification errors
        res = run_forgery_attack(
            message=self.message,
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=100,
        )
        self.assertGreater(res["total_errors"], 0)
        self.assertAlmostEqual(res["theoretical_mismatch_rate"], 0.50)
        self.assertAlmostEqual(res["observed_error_rate"], 0.50)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_2_secret_key_dependence(self) -> None:
        # Test 2: Mismatch rate depends strictly on secret key K
        # Key zeros (0% ones) -> Eve's digest-only state coincides with Alice's state -> 0 errors
        res_zeros = run_forgery_attack(
            message=self.message,
            shared_key=self.key_zeros,
            shots_per_qubit=1,
            seed=200,
        )
        self.assertEqual(res_zeros["total_errors"], 0)
        self.assertEqual(res_zeros["observed_error_rate"], 0.0)
        self.assertFalse(res_zeros["threat_result"].threat_detected)

        # Key ones (100% ones) -> Every forged qubit bit is inverted -> 100% errors
        res_ones = run_forgery_attack(
            message=self.message,
            shared_key=self.key_ones,
            shots_per_qubit=1,
            seed=300,
        )
        self.assertEqual(res_ones["total_errors"], 256)
        self.assertEqual(res_ones["observed_error_rate"], 1.0)
        self.assertTrue(res_ones["threat_result"].threat_detected)

    def test_3_strong_forgery_detection(self) -> None:
        # Test 3: Binomial statistical detector triggers threat detection for balanced key
        res = run_forgery_attack(
            message=self.message,
            shared_key=self.key_balanced,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=400,
        )
        self.assertGreater(res["observed_error_rate"], res["baseline_error_rate"])
        self.assertTrue(res["threat_result"].threat_detected)
        self.assertLess(res["threat_result"].p_value, 0.05)

    def test_4_no_hardcoded_50_percent_error(self) -> None:
        # Test 4: Verify key with 25% ones yields 25% error rate, proving no hardcoded 50% assumption
        res = run_forgery_attack(
            message=self.message,
            shared_key=self.key_quarter,
            shots_per_qubit=1,
            seed=500,
        )
        self.assertAlmostEqual(res["theoretical_mismatch_rate"], 0.25)
        self.assertAlmostEqual(res["observed_error_rate"], 0.25)
        self.assertEqual(res["total_errors"], 64)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_5_legitimate_signature_remains_unaffected(self) -> None:
        # Test 5: Legitimate verification pipeline remains unaffected (regression test)
        legit_summary = verify_signature(
            message=self.message,
            key_bits=self.key_balanced,
            seed_simulator=600,
        )
        self.assertEqual(legit_summary.num_errors, 0)
        self.assertEqual(legit_summary.error_rate, 0.0)
        self.assertTrue(legit_summary.accepted)


if __name__ == "__main__":
    unittest.main()
