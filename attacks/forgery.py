"""
Digital Signature Forgery Attack Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates a digest-only forgery attack where Eve knows message M, public digest D = SHA-256(M),
  the basis schedule, and state encoding rules, but does NOT possess the secret key K.
- Eve constructs candidate signature quantum states using b'_i = d_i (digest bits directly, assuming key is 0).
- Legitimate Alice prepares states using b_i = d_i XOR K_i.
- Therefore, Eve's forged state differs from Alice's expected state at positions where K_i = 1.
- Theoretical forgery mismatch rate = (number of 1s in K) / (total key bits) = key_one_density.
  - For a balanced key (50% 1s), theoretical mismatch rate is 50%.
  - For a key with 25% 1s, theoretical mismatch rate is 25%.
  - For a key with 0% 1s, theoretical mismatch rate is 0%.
- Observed error rates emerge from actual Qiskit quantum teleportation and measurement execution.
- Threat decision is evaluated using the existing exact Binomial upper-tail detector.
"""

from typing import List, Optional, Dict, Any
from core.models import EncodedQubit
from core.backend import QuantumBackendAdapter
from qds.encoding import encode_message
from qds.teleportation import teleport_and_measure
from statistics.detector import detect_threat


def create_forged_encoded_qubits(message: str) -> List[EncodedQubit]:
    """
    Construct Eve's forged EncodedQubit records using only the public digest D = SHA-256(M).
    Eve assumes key bits are 0 (b'_i = d_i).

    Args:
        message: Classical payload string M.

    Returns:
        List of 256 EncodedQubit records prepared without secret key K.
    """
    key_zeros = [0] * 256
    return encode_message(message, key_bits=key_zeros)


def run_forgery_attack(
    message: str,
    shared_key: List[int],
    shots_per_qubit: int = 1,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    sample_indices: Optional[List[int]] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute a Quantum Digital Signature Forgery Attack experiment.

    Eve prepares quantum signature states using only message M and digest D = SHA-256(M),
    without secret key K. Bob verifies the received teleported states against the expected
    legitimate signature states derived from (D XOR K).

    Args:
        message: Classical message string to verify (e.g., "ABC").
        shared_key: Legitimate secret key vector K (256 bits).
        shots_per_qubit: Number of execution shots per signature qubit (default 1).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        sample_indices: Optional list of qubit indices to verify.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible sampling.

    Returns:
        Dictionary containing experimental outcomes, theoretical mismatch rate,
        detailed per-qubit results, and ThreatResult from existing statistical detector.
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")

    # 1. Legitimate expected qubits (prepared with secret key K)
    legitimate_qubits = encode_message(message, shared_key)

    # 2. Forged qubits prepared by Eve (prepared without secret key K, b'_i = d_i)
    forged_qubits = create_forged_encoded_qubits(message)

    if sample_indices is not None:
        target_indices = [idx for idx in sample_indices if 0 <= idx < 256]
    else:
        target_indices = list(range(256))

    if not target_indices:
        raise ValueError("No valid signature qubits selected for forgery experiment.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    # Theoretical expectation: mismatch occurs at index i where shared_key[i] == 1
    key_subset = [shared_key[idx] for idx in target_indices]
    theoretical_mismatch_rate = sum(key_subset) / len(key_subset)

    total_trials = 0
    total_errors = 0
    total_matches = 0
    detailed_results: List[Dict[str, Any]] = []

    for q_idx, idx in enumerate(target_indices):
        legit_record = legitimate_qubits[idx]
        forged_record = forged_qubits[idx]

        for shot_idx in range(shots_per_qubit):
            sim_seed = (seed + q_idx * shots_per_qubit + shot_idx) if seed is not None else None
            # Teleport Eve's forged state and measure in Bob's legitimate expected basis
            res = teleport_and_measure(
                state_label=forged_record.state_label,
                basis=legit_record.basis,
                expected_eigenvalue=legit_record.expected_eigenvalue,
                backend=backend,
                seed_simulator=sim_seed,
            )

            total_trials += 1
            if res.matched:
                total_matches += 1
            else:
                total_errors += 1

            detailed_results.append({
                "qubit_index": idx,
                "digest_bit": legit_record.digest_bit,
                "key_bit": legit_record.key_bit,
                "legitimate_encoded_bit": legit_record.encoded_bit,
                "forged_encoded_bit": forged_record.encoded_bit,
                "legitimate_state": legit_record.state_label,
                "forged_state": forged_record.state_label,
                "basis": legit_record.basis,
                "expected_eigenvalue": legit_record.expected_eigenvalue,
                "observed_eigenvalue": res.observed_eigenvalue,
                "matched": res.matched,
            })

    observed_error_rate = total_errors / total_trials
    threat_res = detect_threat(
        error_count=total_errors,
        total_trials=total_trials,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    return {
        "attack_type": "signature_forgery",
        "message": message,
        "num_qubits": len(target_indices),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "observed_error_rate": observed_error_rate,
        "theoretical_mismatch_rate": theoretical_mismatch_rate,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "detailed_results": detailed_results,
    }
