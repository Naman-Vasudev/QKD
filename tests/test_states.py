"""
Unit tests for Pauli Eigenstate Preparation and Basis Rotation Functions.
"""

import unittest
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
from qds.states import apply_state_preparation, apply_basis_rotation, SUPPORTED_STATES, SUPPORTED_BASES


class TestQDSStates(unittest.TestCase):

    def test_supported_states_and_bases(self) -> None:
        self.assertEqual(len(SUPPORTED_STATES), 6)
        self.assertIn("|0>", SUPPORTED_STATES)
        self.assertIn("|1>", SUPPORTED_STATES)
        self.assertIn("|+>", SUPPORTED_STATES)
        self.assertIn("|->", SUPPORTED_STATES)
        self.assertIn("|+i>", SUPPORTED_STATES)
        self.assertIn("|-i>", SUPPORTED_STATES)

    def test_state_preparation_circuits(self) -> None:
        for state_label in SUPPORTED_STATES:
            qc = QuantumCircuit(1)
            apply_state_preparation(qc, 0, state_label)
            # Verify quantum circuit statevector calculation
            sv = Statevector.from_instruction(qc)
            probs = sv.probabilities_dict()
            self.assertAlmostEqual(sum(probs.values()), 1.0)

    def test_basis_rotation_circuits(self) -> None:
        for basis in SUPPORTED_BASES:
            qc = QuantumCircuit(1)
            apply_basis_rotation(qc, 0, basis)
            self.assertIsInstance(qc, QuantumCircuit)

    def test_invalid_inputs(self) -> None:
        qc = QuantumCircuit(1)
        with self.assertRaises(ValueError):
            apply_state_preparation(qc, 0, "|invalid>")

        with self.assertRaises(ValueError):
            apply_basis_rotation(qc, 0, "W")


if __name__ == "__main__":
    unittest.main()
