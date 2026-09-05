"""
Quantum Circuit Visualization and State Vector Analysis Helpers.

Provides facilities for:
- Exact 3-qubit Qiskit teleportation circuit construction with visual attack annotations.
- Matplotlib and ASCII Qiskit circuit drawing.
- State vector and Bloch vector expectation calculations for Pauli eigenstates.
"""

import math
from typing import Dict, Any, Tuple, Optional
import numpy as np
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from .states import apply_state_preparation, apply_basis_rotation


def get_state_math_info(state_label: str) -> Dict[str, Any]:
    """
    Get mathematical representation and Bloch vector expectations for a Pauli eigenstate.

    Args:
        state_label: One of '|0>', '|1>', '|+>', '|->', '|+i>', '|-i>'.

    Returns:
        Dictionary containing statevector, Bloch expectations (X, Y, Z),
        and state transformation under Pauli-X operator.
    """
    if state_label == "|0>":
        vec_str = "[1, 0]^T"
        bloch_before = (0.0, 0.0, +1.0)
        transformed_label = "|1>"
        bloch_after = (0.0, 0.0, -1.0)
        sensitivity_note = "Sensitive to X error (Z-basis state flips: |0> -> |1>)"
    elif state_label == "|1>":
        vec_str = "[0, 1]^T"
        bloch_before = (0.0, 0.0, -1.0)
        transformed_label = "|0>"
        bloch_after = (0.0, 0.0, +1.0)
        sensitivity_note = "Sensitive to X error (Z-basis state flips: |1> -> |0>)"
    elif state_label == "|+>":
        vec_str = "1/sqrt(2) [1, 1]^T"
        bloch_before = (+1.0, 0.0, 0.0)
        transformed_label = "|+>"
        bloch_after = (+1.0, 0.0, 0.0)
        sensitivity_note = "Invariant under X error (X|+> = |+>, 0% measurement error)"
    elif state_label == "|->":
        vec_str = "1/sqrt(2) [1, -1]^T"
        bloch_before = (-1.0, 0.0, 0.0)
        transformed_label = "-|->"
        bloch_after = (-1.0, 0.0, 0.0)
        sensitivity_note = "Invariant up to global phase under X error (X|-> = -|->, 0% measurement error)"
    elif state_label == "|+i>":
        vec_str = "1/sqrt(2) [1, i]^T"
        bloch_before = (0.0, +1.0, 0.0)
        transformed_label = "|-i>"
        bloch_after = (0.0, -1.0, 0.0)
        sensitivity_note = "Sensitive to X error (Y-basis state flips: |+i> -> |-i>)"
    elif state_label == "|-i>":
        vec_str = "1/sqrt(2) [1, -i]^T"
        bloch_before = (0.0, -1.0, 0.0)
        transformed_label = "|+i>"
        bloch_after = (0.0, +1.0, 0.0)
        sensitivity_note = "Sensitive to X error (Y-basis state flips: |-i> -> |+i>)"
    else:
        raise ValueError(f"Unknown state label: {state_label}")

    return {
        "state_label": state_label,
        "statevector_str": vec_str,
        "bloch_before": bloch_before,
        "transformed_label": transformed_label,
        "bloch_after": bloch_after,
        "sensitivity_note": sensitivity_note,
    }


def build_demonstration_teleportation_circuit(
    state_label: str,
    basis: str,
    attack_type: str = "none",
    p_attack: float = 0.0,
    eve_basis: Optional[str] = None,
) -> QuantumCircuit:
    """
    Build a complete Qiskit QuantumCircuit representing 3-qubit teleportation,
    with explicit gates for the selected attack model.

    Qubit Layout:
        q0: Alice's signature qubit
        q1: Alice's EPR qubit
        q2: Bob's EPR qubit

    Args:
        state_label: Signature state label ('|0>', '|1>', '|+>', '|->', '|+i>', '|-i>').
        basis: Bob's expected measurement basis ('Z', 'X', 'Y').
        attack_type: Attack model ('none', 'channel_x', 'interception').
        p_attack: Channel attack probability (for annotation).
        eve_basis: Eve's measurement basis for interception attack.

    Returns:
        Configured Qiskit QuantumCircuit.
    """
    if attack_type == "interception":
        qr = QuantumRegister(3, "q")
        c_eve = ClassicalRegister(1, "c_eve")
        c0 = ClassicalRegister(1, "c0")
        c1 = ClassicalRegister(1, "c1")
        c2 = ClassicalRegister(1, "c2")
        qc = QuantumCircuit(qr, c_eve, c0, c1, c2, name="Teleport_Intercept_Circuit")

        # 1. Alice State Prep on q0
        apply_state_preparation(qc, 0, state_label)

        # 2. Eve Interception on q0
        chosen_eve_basis = eve_basis if eve_basis in ("Z", "X", "Y") else "Z"
        apply_basis_rotation(qc, 0, chosen_eve_basis)
        qc.measure(0, c_eve[0])
        qc.reset(0)
        # Re-prepare eigenstate based on Eve measurement
        with qc.if_test((c_eve[0], 0)):
            if chosen_eve_basis == "Z":
                qc.id(0)
            elif chosen_eve_basis == "X":
                qc.h(0)
            elif chosen_eve_basis == "Y":
                qc.sdg(0)
                qc.h(0)
        with qc.if_test((c_eve[0], 1)):
            if chosen_eve_basis == "Z":
                qc.x(0)
            elif chosen_eve_basis == "X":
                qc.x(0)
                qc.h(0)
            elif chosen_eve_basis == "Y":
                qc.x(0)
                qc.sdg(0)
                qc.h(0)

        # 3. Bell-pair creation on q1, q2
        qc.h(1)
        qc.cx(1, 2)

        # 4. Bell measurement on q0, q1
        qc.cx(0, 1)
        qc.h(0)
        qc.measure(0, c0[0])
        qc.measure(1, c1[0])

        # 5. Bob corrections on q2
        with qc.if_test((c1[0], 1)):
            qc.x(2)
        with qc.if_test((c0[0], 1)):
            qc.z(2)

        # 6. Bob verification readout
        apply_basis_rotation(qc, 2, basis)
        qc.measure(2, c2[0])
        return qc

    else:
        qr = QuantumRegister(3, "q")
        c0 = ClassicalRegister(1, "c0")
        c1 = ClassicalRegister(1, "c1")
        c2 = ClassicalRegister(1, "c2")
        qc = QuantumCircuit(qr, c0, c1, c2, name=f"Teleport_{attack_type}")

        # 1. State Prep on q0
        apply_state_preparation(qc, 0, state_label)

        # 2. Bell pair creation
        qc.h(1)
        qc.cx(1, 2)

        # 3. Channel attack injection on q2 if enabled
        if attack_type == "channel_x":
            qc.x(2)

        # 4. Bell measurement
        qc.cx(0, 1)
        qc.h(0)
        qc.measure(0, c0[0])
        qc.measure(1, c1[0])

        # 5. Bob corrections
        with qc.if_test((c1[0], 1)):
            qc.x(2)
        with qc.if_test((c0[0], 1)):
            qc.z(2)

        # 6. Bob verification
        apply_basis_rotation(qc, 2, basis)
        qc.measure(2, c2[0])
        return qc


def draw_circuit_mpl(qc: QuantumCircuit) -> plt.Figure:
    """
    Render a Qiskit QuantumCircuit to a Matplotlib Figure.

    Args:
        qc: Qiskit QuantumCircuit.

    Returns:
        Matplotlib Figure instance.
    """
    fig = qc.draw(output="mpl")
    return fig


def draw_circuit_ascii(qc: QuantumCircuit) -> str:
    """
    Render a Qiskit QuantumCircuit to ASCII text string.

    Args:
        qc: Qiskit QuantumCircuit.

    Returns:
        String representation.
    """
    return str(qc.draw(output="text"))
