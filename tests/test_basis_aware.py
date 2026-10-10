"""
tests/test_basis_aware.py
=========================
Unit tests for the basis-aware individual-qubit interceptor attack module.
"""

import unittest
from attacks.basis_aware import (
    build_basis_aware_intercepted_circuit,
    run_basis_aware_attack,
)
from core.backend import QuantumBackendAdapter


class TestBasisAwareAttack(unittest.TestCase):
    def setUp(self):
        self.message = "BASIS_AWARE_TEST"
        self.key = [i % 2 for i in range(256)]  # Balanced 256-bit key
        self.backend = QuantumBackendAdapter("aer_simulator")

    def test_circuit_construction(self):
        """Verify circuit construction across all bases."""
        for state, basis in [("|0>", "Z"), ("|1>", "Z"), ("|+>", "X"), ("|->", "X"), ("|+i>", "Y"), ("|-i>", "Y")]:
            qc = build_basis_aware_intercepted_circuit(state, basis)
            self.assertEqual(qc.num_qubits, 3)
            self.assertEqual(qc.num_clbits, 4)  # c_eve, c0, c1, c2

    def test_basis_aware_attack_extracts_key_completely(self):
        """
        Verify that on a noiseless simulator, an adversary aware of the deterministic basis
        schedule:
          1. Recovers 100% of the secret key bits (key_leakage_rate == 1.0).
          2. Causes 0 verification errors at Bob (observed_error_rate == 0.0).
          3. Evades detection completely (threat_detected is False).
        """
        # Run on a 32-qubit prefix for fast test execution
        sample_indices = list(range(32))
        res = run_basis_aware_attack(
            message=self.message,
            shared_key=self.key,
            shots_per_qubit=1,
            sample_indices=sample_indices,
            backend=self.backend,
            seed=42,
        )

        # 1. Eve achieves 100% key reconstruction
        self.assertEqual(res["key_leakage_rate"], 1.0)
        self.assertEqual(res["eve_correct_bits"], 32)
        expected_key_prefix = [self.key[i] for i in sample_indices]
        self.assertEqual(res["extracted_key"], expected_key_prefix)

        # 2. Bob sees 0 verification errors
        self.assertEqual(res["total_errors"], 0)
        self.assertEqual(res["observed_error_rate"], 0.0)

        # 3. Detector never alarms (stealthy break)
        self.assertFalse(res["threat_result"].threat_detected)

    def test_input_validation(self):
        """Verify key length and index validation."""
        with self.assertRaises(ValueError):
            run_basis_aware_attack(self.message, [0] * 128)
        with self.assertRaises(ValueError):
            run_basis_aware_attack(self.message, self.key, sample_indices=[])


if __name__ == "__main__":
    unittest.main()
