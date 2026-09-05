"""
Signature Verification Engine for Quantum Digital Signatures.

Evaluates teleported Pauli eigenstates against expected measurement bases and eigenvalues
derived from classical digest bits and secret shared key K.
"""

from typing import List, Optional
from core.models import EncodedQubit, TeleportationResult, SignatureVerificationResult
from core.backend import QuantumBackendAdapter
from .encoding import encode_message
from .teleportation import teleport_and_measure


def verify_encoded_qubit(
    encoded_qubit: EncodedQubit,
    backend: Optional[QuantumBackendAdapter] = None,
    seed_simulator: Optional[int] = None,
) -> TeleportationResult:
    """
    Verify a single encoded signature qubit by performing 3-qubit quantum teleportation
    and checking the observed eigenvalue against the expected protocol eigenvalue.

    Args:
        encoded_qubit: EncodedQubit record containing state_label, basis, and expected_eigenvalue.
        backend: Optional QuantumBackendAdapter (uses AerSimulator default if None).
        seed_simulator: Optional seed for execution reproducibility.

    Returns:
        TeleportationResult instance.
    """
    return teleport_and_measure(
        state_label=encoded_qubit.state_label,
        basis=encoded_qubit.basis,
        expected_eigenvalue=encoded_qubit.expected_eigenvalue,
        backend=backend,
        seed_simulator=seed_simulator,
    )


def verify_signature(
    message: str,
    key_bits: List[int],
    backend: Optional[QuantumBackendAdapter] = None,
    sample_indices: Optional[List[int]] = None,
    seed_simulator: Optional[int] = None,
) -> SignatureVerificationResult:
    """
    Perform end-to-end verification of a Quantum Digital Signature sequence.

    Args:
        message: Classical message string to verify (e.g., "ABC").
        key_bits: List of 256 integers (0 or 1) representing the pre-shared secret key K.
        backend: Optional QuantumBackendAdapter backend instance.
        sample_indices: Optional list of qubit indices (0 to 255) to verify.
                        If None, verifies all 256 signature qubits.
        seed_simulator: Optional random seed for reproducible testing.

    Returns:
        SignatureVerificationResult instance.
    """
    encoded_qubits = encode_message(message, key_bits)

    if sample_indices is not None:
        target_qubits = [encoded_qubits[idx] for idx in sample_indices if 0 <= idx < 256]
    else:
        target_qubits = encoded_qubits

    if not target_qubits:
        raise ValueError("No valid signature qubits selected for verification.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    results: List[TeleportationResult] = []
    num_matches = 0
    num_errors = 0

    for idx, q_record in enumerate(target_qubits):
        seed_idx = (seed_simulator + idx) if seed_simulator is not None else None
        res = verify_encoded_qubit(q_record, backend=backend, seed_simulator=seed_idx)
        results.append(res)

        if res.matched:
            num_matches += 1
        else:
            num_errors += 1

    total_eval = len(target_qubits)
    error_rate = num_errors / total_eval
    accepted = error_rate == 0.0

    return SignatureVerificationResult(
        message=message,
        num_qubits=total_eval,
        num_matches=num_matches,
        num_errors=num_errors,
        error_rate=error_rate,
        accepted=accepted,
        results=results,
    )
