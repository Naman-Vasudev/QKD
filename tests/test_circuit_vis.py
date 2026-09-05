"""
Unit Test Suite for Circuit Visualization and State Vector Analysis Helpers (Phase 4).
"""

import unittest
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit
from qds.circuit_visualization import (
    get_state_math_info,
    build_demonstration_teleportation_circuit,
    draw_circuit_mpl,
    draw_circuit_ascii,
)


class TestCircuitVisualization(unittest.TestCase):

    def test_1_get_state_math_info_all_states(self) -> None:
        states = ["|0>", "|1>", "|+>", "|->", "|+i>", "|-i>"]
        for s in states:
            info = get_state_math_info(s)
            self.assertEqual(info["state_label"], s)
            self.assertIn("bloch_before", info)
            self.assertIn("bloch_after", info)
            self.assertIn("transformed_label", info)

        # Invariant checks
        plus_info = get_state_math_info("|+>")
        self.assertEqual(plus_info["transformed_label"], "|+>")
        self.assertEqual(plus_info["bloch_before"], plus_info["bloch_after"])

    def test_2_build_demonstration_teleportation_circuit(self) -> None:
        qc_none = build_demonstration_teleportation_circuit("|0>", "Z", attack_type="none")
        self.assertIsInstance(qc_none, QuantumCircuit)
        self.assertEqual(qc_none.num_qubits, 3)

        qc_channel = build_demonstration_teleportation_circuit("|+>", "X", attack_type="channel_x")
        self.assertIsInstance(qc_channel, QuantumCircuit)

        qc_intercept = build_demonstration_teleportation_circuit("|+i>", "Y", attack_type="interception", eve_basis="Z")
        self.assertIsInstance(qc_intercept, QuantumCircuit)

    def test_3_draw_circuit_mpl_and_ascii(self) -> None:
        qc = build_demonstration_teleportation_circuit("|0>", "Z")
        fig = draw_circuit_mpl(qc)
        self.assertIsInstance(fig, plt.Figure)
        plt.close(fig)

        ascii_str = draw_circuit_ascii(qc)
        self.assertIsInstance(ascii_str, str)
        self.assertIn("q_", ascii_str)


if __name__ == "__main__":
    unittest.main()
