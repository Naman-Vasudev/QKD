"""
Unit Test Suite for Quantum Channel Tampering Attack Simulator.
"""

import unittest
from attacks.channel import (
    apply_bit_flip_channel,
    run_single_qubit_channel_attack,
    run_channel_attack,
)
from qiskit import QuantumCircuit


class TestChannelAttack(unittest.TestCase):

    def setUp(self) -> None:
        self.test_key = [i % 2 for i in range(256)]

    def test_input_validation(self) -> None:
        # Invalid attack probabilities
        with self.assertRaises(ValueError):
            run_single_qubit_channel_attack("|0>", "Z", +1, attack_probability=-0.1)

        with self.assertRaises(ValueError):
            run_single_qubit_channel_attack("|0>", "Z", +1, attack_probability=1.5)

        with self.assertRaises(ValueError):
            run_channel_attack("ABC", self.test_key, attack_probability=-0.05)

        # Invalid shots
        with self.assertRaises(ValueError):
            run_single_qubit_channel_attack("|0>", "Z", +1, attack_probability=0.2, shots=0)

        # Circuit qubit out of bounds
        qc = QuantumCircuit(2)
        with self.assertRaises(ValueError):
            apply_bit_flip_channel(qc, qubit=3, probability=0.5)

    def test_a_no_attack(self) -> None:
        # Test A: p_attack = 0.0 -> measured error rate ≈ 0.0 under ideal Aer simulation
        res = run_single_qubit_channel_attack(
            state_label="|0>",
            basis="Z",
            expected_eigenvalue=+1,
            attack_probability=0.0,
            shots=500,
            seed=42,
        )
        self.assertAlmostEqual(res["observed_error_rate"], 0.0, places=3)
        self.assertEqual(res["error_count"], 0)

        # Full signature test under p_attack = 0.0
        sig_res = run_channel_attack(
            message="ABC",
            key_bits=self.test_key,
            attack_probability=0.0,
            shots_per_qubit=1,
            seed=100,
        )
        self.assertEqual(sig_res["total_errors"], 0)
        self.assertEqual(sig_res["observed_error_rate"], 0.0)

    def test_b_full_bit_flip_channel(self) -> None:
        # Test B: p_attack = 1.0 -> deterministic bit flip on Z-basis state
        res = run_single_qubit_channel_attack(
            state_label="|0>",
            basis="Z",
            expected_eigenvalue=+1,
            attack_probability=1.0,
            shots=500,
            seed=42,
        )
        # In Z basis, X operation flips |0> to |1> (measured bit 1 -> -1 eigenvalue vs expected +1)
        self.assertAlmostEqual(res["observed_error_rate"], 1.0, places=3)
        self.assertEqual(res["error_count"], 500)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_c_intermediate_attack(self) -> None:
        # Test C: p_attack = 0.20 -> measured error rate near injected probability (tolerance check)
        shots = 1000
        p_attack = 0.20
        res = run_single_qubit_channel_attack(
            state_label="|0>",
            basis="Z",
            expected_eigenvalue=+1,
            attack_probability=p_attack,
            shots=shots,
            seed=1234,
        )
        # Measured error rate should be within binomial sampling noise of 0.20 (e.g. 0.15 to 0.25)
        self.assertGreaterEqual(res["observed_error_rate"], 0.15)
        self.assertLessEqual(res["observed_error_rate"], 0.25)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_d_monotonicity_experiment(self) -> None:
        # Test D: Monotonicity trend check over attack probabilities: 0.00, 0.05, 0.10, 0.20, 0.30, 0.50
        probabilities = [0.00, 0.05, 0.10, 0.20, 0.30, 0.50]
        measured_error_rates = []

        for p in probabilities:
            res = run_single_qubit_channel_attack(
                state_label="|0>",
                basis="Z",
                expected_eigenvalue=+1,
                attack_probability=p,
                shots=1000,
                seed=500,
            )
            measured_error_rates.append(res["observed_error_rate"])

        # Check overall upward trend (e.g., p=0.0 < p=0.10 < p=0.50)
        self.assertLessEqual(measured_error_rates[0], measured_error_rates[1])
        self.assertLess(measured_error_rates[0], measured_error_rates[3])
        self.assertLess(measured_error_rates[3], measured_error_rates[5])

    def test_detector_integration(self) -> None:
        # Test integration with Binomial threat detector
        res = run_channel_attack(
            message="ABC",
            key_bits=self.test_key,
            attack_probability=0.20,
            shots_per_qubit=2,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=777,
        )
        # Threat should be detected due to high error rate
        self.assertTrue(res["threat_result"].threat_detected)
        self.assertLess(res["threat_result"].p_value, 0.05)


if __name__ == "__main__":
    unittest.main()
