"""
Unit Test Suite for Digital Signature Impersonation Attack Simulator.
"""

import unittest
from attacks.impersonation import create_impersonation_encoded_qubits, run_impersonation_attack
from qds.verification import verify_signature


class TestImpersonationAttack(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "ImpersonationAttackUnitTest"
        self.key_balanced = [i % 2 for i in range(256)]

    def test_1_impersonation_produces_quantum_verification_errors(self) -> None:
        # Test 1: Impersonation produces actual quantum verification errors
        res = run_impersonation_attack(
            message=self.message,
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=42,
        )
        self.assertGreater(res["total_errors"], 0)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_2_random_attacker_approaches_50_percent(self) -> None:
        # Test 2: Random guessing approaches ~50% error rate within statistical tolerance
        res = run_impersonation_attack(
            message=self.message,
            shared_key=self.key_balanced,
            shots_per_qubit=2,
            seed=100,
        )
        # Total trials = 512, expected error rate ~0.50
        self.assertGreaterEqual(res["observed_error_rate"], 0.40)
        self.assertLessEqual(res["observed_error_rate"], 0.60)

    def test_3_no_hardcoded_50_percent(self) -> None:
        # Test 3: Verify different seeds yield varying execution counts (proving no hardcoded 0.5)
        res1 = run_impersonation_attack(message=self.message, shared_key=self.key_balanced, seed=1)
        res2 = run_impersonation_attack(message=self.message, shared_key=self.key_balanced, seed=2)
        res3 = run_impersonation_attack(message=self.message, shared_key=self.key_balanced, seed=3)

        # Error counts should vary slightly due to random guessing, not be statically hardcoded
        error_counts = {res1["total_errors"], res2["total_errors"], res3["total_errors"]}
        self.assertGreater(len(error_counts), 1, f"Error counts should vary across seeds, got {error_counts}")

    def test_4_threat_detector_integration(self) -> None:
        # Test 4: Binomial statistical detector triggers threat detection
        res = run_impersonation_attack(
            message=self.message,
            shared_key=self.key_balanced,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=999,
        )
        self.assertGreater(res["observed_error_rate"], res["baseline_error_rate"])
        self.assertTrue(res["threat_result"].threat_detected)
        self.assertLess(res["threat_result"].p_value, 0.05)

    def test_5_legitimate_signature_regression(self) -> None:
        # Test 5: Legitimate verification pipeline remains unaffected (regression test)
        legit_summary = verify_signature(
            message=self.message,
            key_bits=self.key_balanced,
            seed_simulator=555,
        )
        self.assertEqual(legit_summary.num_errors, 0)
        self.assertEqual(legit_summary.error_rate, 0.0)
        self.assertTrue(legit_summary.accepted)


if __name__ == "__main__":
    unittest.main()
