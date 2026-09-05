"""
Unit Test Suite for Quantum Interception (Intercept-Resend) Attack Simulator.
"""

import unittest
from attacks.interception import (
    select_eve_basis,
    build_intercepted_teleportation_circuit,
    run_single_qubit_interception_attack,
    run_interception_attack,
)
from qiskit import QuantumCircuit


class TestInterceptionAttack(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "InterceptionAttackUnitTest"
        self.key_balanced = [i % 2 for i in range(256)]

    def test_select_eve_basis_validation(self) -> None:
        # Valid basis choices
        self.assertEqual(select_eve_basis("Z"), "Z")
        self.assertEqual(select_eve_basis("X"), "X")
        self.assertEqual(select_eve_basis("Y"), "Y")

        # Invalid basis choice
        with self.assertRaises(ValueError):
            select_eve_basis("W")

        # Random choice returns valid basis
        b = select_eve_basis()
        self.assertIn(b, ("Z", "X", "Y"))

    def test_same_basis_measurement_no_disturbance(self) -> None:
        # When Eve chooses the exact same basis as Alice, error rate is 0.0
        res = run_single_qubit_interception_attack(
            state_label="|0>",
            alice_basis="Z",
            expected_eigenvalue=+1,
            eve_basis="Z",
            shots=500,
            seed=42,
        )
        self.assertEqual(res["error_count"], 0)
        self.assertEqual(res["observed_error_rate"], 0.0)
        self.assertFalse(res["threat_result"].threat_detected)

    def test_different_basis_measurement_disturbance(self) -> None:
        # When Eve chooses an incompatible basis (X basis for Z state), error rate is ~50%
        res = run_single_qubit_interception_attack(
            state_label="|0>",
            alice_basis="Z",
            expected_eigenvalue=+1,
            eve_basis="X",
            shots=1000,
            seed=100,
        )
        self.assertGreaterEqual(res["observed_error_rate"], 0.40)
        self.assertLessEqual(res["observed_error_rate"], 0.60)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_uniform_random_basis_interception(self) -> None:
        # Uniform basis selection yields theoretical error rate ~1/3 (33.33%)
        res = run_single_qubit_interception_attack(
            state_label="|0>",
            alice_basis="Z",
            expected_eigenvalue=+1,
            eve_basis=None,  # Random uniform selection
            shots=1500,
            seed=200,
        )
        # Expected error rate ~0.3333 (tolerance 0.25 to 0.42)
        self.assertGreaterEqual(res["observed_error_rate"], 0.25)
        self.assertLessEqual(res["observed_error_rate"], 0.42)
        self.assertTrue(res["threat_result"].threat_detected)

    def test_full_signature_interception_attack(self) -> None:
        # Full 256-qubit signature interception experiment
        res = run_interception_attack(
            message=self.message,
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=300,
        )
        self.assertEqual(res["total_trials"], 256)
        self.assertGreaterEqual(res["observed_error_rate"], 0.25)
        self.assertLessEqual(res["observed_error_rate"], 0.45)
        self.assertTrue(res["threat_result"].threat_detected)
        self.assertLess(res["threat_result"].p_value, 0.05)

    def test_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            run_single_qubit_interception_attack("|0>", "Z", +1, shots=0)

        with self.assertRaises(ValueError):
            run_interception_attack("ABC", shared_key=[0] * 100)


if __name__ == "__main__":
    unittest.main()
