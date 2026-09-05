"""
Unit tests for 3-Qubit Quantum Teleportation and End-to-End Signature Verification.
"""

import unittest
from core.backend import QuantumBackendAdapter
from qds.teleportation import build_teleportation_circuit, teleport_and_measure
from qds.verification import verify_signature, verify_encoded_qubit
from qds.encoding import encode_message


class TestQDSTeleportation(unittest.TestCase):

    def setUp(self) -> None:
        self.backend = QuantumBackendAdapter("aer_simulator")
        self.test_key = [i % 2 for i in range(256)]

    def test_teleportation_all_six_states(self) -> None:
        test_cases = [
            ("|0>", "Z", +1),
            ("|1>", "Z", -1),
            ("|+>", "X", +1),
            ("|->", "X", -1),
            ("|+i>", "Y", +1),
            ("|-i>", "Y", -1),
        ]

        for state_label, basis, expected_eigenvalue in test_cases:
            with self.subTest(state=state_label, basis=basis):
                res = teleport_and_measure(
                    state_label=state_label,
                    basis=basis,
                    expected_eigenvalue=expected_eigenvalue,
                    backend=self.backend,
                    seed_simulator=42,
                )
                self.assertTrue(res.matched, f"Teleportation failed for {state_label} in basis {basis}.")
                self.assertEqual(res.observed_eigenvalue, expected_eigenvalue)
                self.assertIn(res.correction, ("I", "X", "Z", "XZ"))

    def test_teleportation_circuit_structure(self) -> None:
        qc = build_teleportation_circuit("|+>", "X")
        self.assertEqual(qc.num_qubits, 3)
        self.assertEqual(len(qc.cregs), 3)

    def test_signature_verification_full_256_qubits(self) -> None:
        # Test full 256 qubit verification under ideal simulation
        summary = verify_signature(
            message="ABC",
            key_bits=self.test_key,
            backend=self.backend,
            seed_simulator=100,
        )
        self.assertEqual(summary.message, "ABC")
        self.assertEqual(summary.num_qubits, 256)
        self.assertEqual(summary.num_errors, 0)
        self.assertEqual(summary.num_matches, 256)
        self.assertEqual(summary.error_rate, 0.0)
        self.assertTrue(summary.accepted)

    def test_signature_verification_sample_subset(self) -> None:
        # Test sampling a subset of qubit indices (e.g. 10 qubits)
        sample_indices = list(range(10))
        summary = verify_signature(
            message="TestMessage",
            key_bits=self.test_key,
            backend=self.backend,
            sample_indices=sample_indices,
            seed_simulator=200,
        )
        self.assertEqual(summary.num_qubits, 10)
        self.assertEqual(summary.num_errors, 0)
        self.assertTrue(summary.accepted)


if __name__ == "__main__":
    unittest.main()
