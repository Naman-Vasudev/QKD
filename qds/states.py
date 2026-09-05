"""
Pauli Eigenstate Preparation and Measurement Basis Rotation Module.

Implements Qiskit circuit routines for:
- 6 Pauli Eigenstates: |0>, |1>, |+>, |->, |+i>, |-i>
- Measurement basis transformations for Z, X, and Y observables.

Measurement Convention:
- Qiskit measurement result '0' maps to eigenvalue +1.
- Qiskit measurement result '1' maps to eigenvalue -1.
"""

from qiskit import QuantumCircuit


SUPPORTED_STATES = ("|0>", "|1>", "|+>", "|->", "|+i>", "|-i>")
SUPPORTED_BASES = ("Z", "X", "Y")


def apply_state_preparation(qc: QuantumCircuit, qubit: int, state_label: str) -> QuantumCircuit:
    """
    Apply quantum gates to prepare a specific Pauli eigenstate on a qubit.

    Gate Sequence Definitions:
    - '|0>': No operation (computational state |0>).
    - '|1>': X gate.
    - '|+>': H gate.
    - '|->': X gate followed by H gate.
    - '|+i>': H gate followed by S gate.
    - '|-i>': X gate followed by H gate followed by S gate.

    Args:
        qc: QuantumCircuit object to modify.
        qubit: Index of the qubit to prepare.
        state_label: One of '|0>', '|1>', '|+>', '|->', '|+i>', '|-i>'.

    Returns:
        Modified QuantumCircuit.
    """
    if state_label not in SUPPORTED_STATES:
        raise ValueError(f"Unsupported state: '{state_label}'. Must be one of {SUPPORTED_STATES}")

    if state_label == "|0>":
        pass  # Default state |0>
    elif state_label == "|1>":
        qc.x(qubit)
    elif state_label == "|+>":
        qc.h(qubit)
    elif state_label == "|->":
        qc.x(qubit)
        qc.h(qubit)
    elif state_label == "|+i>":
        qc.h(qubit)
        qc.s(qubit)
    elif state_label == "|-i>":
        qc.x(qubit)
        qc.h(qubit)
        qc.s(qubit)

    return qc


def apply_basis_rotation(qc: QuantumCircuit, qubit: int, basis: str) -> QuantumCircuit:
    """
    Apply basis transformation gates before measuring in the computational basis.

    Basis Transformation Rules:
    - 'Z': No rotation (measures directly in Z basis).
    - 'X': H gate (transforms X basis eigenvectors to Z basis).
    - 'Y': Sdg gate followed by H gate (transforms Y basis eigenvectors to Z basis).

    Args:
        qc: QuantumCircuit object to modify.
        qubit: Index of the qubit to rotate.
        basis: Measurement basis ('Z', 'X', or 'Y').

    Returns:
        Modified QuantumCircuit.
    """
    if basis not in SUPPORTED_BASES:
        raise ValueError(f"Unsupported basis: '{basis}'. Must be one of {SUPPORTED_BASES}")

    if basis == "Z":
        pass
    elif basis == "X":
        qc.h(qubit)
    elif basis == "Y":
        qc.sdg(qubit)
        qc.h(qubit)

    return qc
