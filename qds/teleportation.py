"""
3-Qubit Quantum Teleportation Protocol Engine.

SCIENTIFIC DISCLOSURES:
- Quantum teleportation transfers an unknown state |ψ> from Alice to Bob using an EPR pair |Φ+>
  and classical communication (bits c0, c1).
- Teleportation transfers state information but does NOT authenticate the sender identity.
- Pauli corrections (I, X, Z, XZ) restore the original state vector at Bob's qubit q2.
"""

from typing import Optional, Tuple
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from core.models import TeleportationResult
from core.backend import QuantumBackendAdapter
from .states import apply_state_preparation, apply_basis_rotation


def build_teleportation_circuit(state_label: str, basis: str) -> QuantumCircuit:
    """
    Construct a complete 3-qubit Qiskit teleportation and verification circuit.

    Qubit Layout:
        q0: Alice's signature qubit (initialized to state_label)
        q1: Alice's half of the EPR Bell pair
        q2: Bob's half of the EPR Bell pair (receives teleported state)

    Classical Registers:
        c0: Holds Alice's measurement of q0 (triggers Z correction on q2 if 1)
        c1: Holds Alice's measurement of q1 (triggers X correction on q2 if 1)
        c2: Holds Bob's verification measurement of q2

    Args:
        state_label: One of '|0>', '|1>', '|+>', '|->', '|+i>', '|-i>'.
        basis: Target measurement basis ('Z', 'X', or 'Y').

    Returns:
        Configured Qiskit QuantumCircuit.
    """
    qr = QuantumRegister(3, "q")
    c0 = ClassicalRegister(1, "c0")
    c1 = ClassicalRegister(1, "c1")
    c2 = ClassicalRegister(1, "c2")
    qc = QuantumCircuit(qr, c0, c1, c2, name=f"Teleport_{state_label}_{basis}")

    # 1. State Preparation on Alice's signature qubit q0
    apply_state_preparation(qc, 0, state_label)

    # 2. Bell-pair Creation (|Φ+> = (|00> + |11>) / sqrt(2)) on q1 and q2
    qc.h(1)
    qc.cx(1, 2)

    # 3. Alice's Bell-state Measurement on q0 and q1
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, c0[0])
    qc.measure(1, c1[0])

    # 4. Bob's Conditional Pauli Corrections on q2 using modern Qiskit 2.x if_test syntax
    with qc.if_test((c1[0], 1)):
        qc.x(2)
    with qc.if_test((c0[0], 1)):
        qc.z(2)

    # 5. Bob's Measurement Basis Transformation & Readout on q2
    apply_basis_rotation(qc, 2, basis)
    qc.measure(2, c2[0])

    return qc


def teleport_and_measure(
    state_label: str,
    basis: str,
    expected_eigenvalue: int,
    backend: Optional[QuantumBackendAdapter] = None,
    seed_simulator: Optional[int] = None,
) -> TeleportationResult:
    """
    Execute a single-qubit quantum teleportation experiment and evaluate Bob's outcome.

    Args:
        state_label: Pauli eigenstate prepared by Alice.
        basis: Verification basis expected at Bob.
        expected_eigenvalue: Expected measurement eigenvalue (+1 or -1).
        backend: Optional QuantumBackendAdapter (uses AerSimulator default if None).
        seed_simulator: Optional seed for execution reproducibility.

    Returns:
        TeleportationResult instance.
    """
    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    circuit = build_teleportation_circuit(state_label, basis)
    exec_res = backend.run_circuit(circuit, shots=1, seed_simulator=seed_simulator)

    memory_list = exec_res.get("memory", [])
    if memory_list:
        raw_bits = memory_list[0]
        # In Qiskit memory output with multiple registers, format may be 'c2 c1 c0' or 'c2c1c0'
        clean_bits = raw_bits.replace(" ", "")
        # Memory string format: c2 is bit 0, c1 is bit 1, c0 is bit 2 from left
        c2_val = int(clean_bits[0])
        c1_val = int(clean_bits[1])
        c0_val = int(clean_bits[2])
    else:
        # Fallback using counts keys
        counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
        c2_val = int(counts_key[0])
        c1_val = int(counts_key[1])
        c0_val = int(counts_key[2])

    # Determine Pauli correction label applied by Bob
    if c0_val == 0 and c1_val == 0:
        correction_label = "I"
    elif c0_val == 0 and c1_val == 1:
        correction_label = "X"
    elif c0_val == 1 and c1_val == 0:
        correction_label = "Z"
    else:  # c0_val == 1 and c1_val == 1
        correction_label = "XZ"

    # Map measurement result bit: '0' -> +1 eigenvalue, '1' -> -1 eigenvalue
    observed_eigenvalue = +1 if c2_val == 0 else -1
    matched = observed_eigenvalue == expected_eigenvalue

    return TeleportationResult(
        state_label=state_label,
        c0=c0_val,
        c1=c1_val,
        correction=correction_label,
        observed_eigenvalue=observed_eigenvalue,
        expected_eigenvalue=expected_eigenvalue,
        matched=matched,
    )
