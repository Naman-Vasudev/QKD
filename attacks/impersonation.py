"""
Digital Signature Impersonation Attack Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates an impersonation attack where Eve attempts to impersonate Alice and produce a valid signature
  without access to the shared secret key K or Alice's legitimate quantum states.
- Because K is unknown to Eve, the key-dependent encoded bit b_i = d_i XOR K_i is unpredictable.
- Eve generates candidate signature states by selecting a random encoded bit b'_i ~ Bernoulli(0.5)
  independently for each signature position, and preparing the corresponding Pauli eigenstate
  according to the public basis schedule.
- Theoretical expected error rate for an unknown balanced key is approximately 50%.
- Observed error rates emerge directly from actual Qiskit quantum teleportation and measurement execution;
  they are NOT hardcoded or manually forced.
- Anomaly detection is evaluated using the existing exact Binomial upper-tail hypothesis detector.
"""

import random
from typing import List, Optional, Dict, Any, Tuple
from core.models import EncodedQubit
from core.backend import QuantumBackendAdapter
from qds.encoding import encode_message
from qds.teleportation import teleport_and_measure
from statistics.detector import detect_threat


def create_impersonation_encoded_qubits(
    message: str,
    rng: Optional[random.Random] = None,
) -> Tuple[List[EncodedQubit], List[int]]:
    """
    Construct Eve's impersonation EncodedQubit records by randomly guessing encoded bits b'_i ~ Bernoulli(0.5).

    Args:
        message: Classical payload string M.
        rng: Optional random.Random instance for reproducible random guessing.

    Returns:
        Tuple of (List of 256 EncodedQubit records prepared by Eve, List of 256 guessed key bits).
    """
    if rng is None:
        rng = random.Random()

    impersonation_key_guess = [rng.randint(0, 1) for _ in range(256)]
    qubits = encode_message(message, key_bits=impersonation_key_guess)
    return qubits, impersonation_key_guess


def run_impersonation_attack(
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
    Execute a Quantum Digital Signature Impersonation Attack experiment.

    Eve pretends to be Alice and generates quantum signature states using random bit guesses b'_i ~ Bernoulli(0.5),
    without access to shared key K. Bob verifies the received teleported states against expected legitimate
    signature states derived from (D XOR K).

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
        Dictionary containing experimental outcomes, detailed per-qubit results,
        and ThreatResult from existing statistical detector.
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")

    rng = random.Random(seed) if seed is not None else None

    # 1. Legitimate expected qubits (prepared with secret key K)
    legitimate_qubits = encode_message(message, shared_key)

    # 2. Impersonation qubits prepared by Eve (random encoded bit b'_i ~ Bernoulli(0.5))
    impersonation_qubits, eve_guessed_bits = create_impersonation_encoded_qubits(message, rng=rng)

    if sample_indices is not None:
        target_indices = [idx for idx in sample_indices if 0 <= idx < 256]
    else:
        target_indices = list(range(256))

    if not target_indices:
        raise ValueError("No valid signature qubits selected for impersonation experiment.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    total_trials = 0
    total_errors = 0
    total_matches = 0
    detailed_results: List[Dict[str, Any]] = []

    for q_idx, idx in enumerate(target_indices):
        legit_record = legitimate_qubits[idx]
        impersonated_record = impersonation_qubits[idx]

        for shot_idx in range(shots_per_qubit):
            sim_seed = (seed + q_idx * shots_per_qubit + shot_idx) if seed is not None else None
            # Teleport Eve's impersonated state and measure in Bob's legitimate expected basis
            res = teleport_and_measure(
                state_label=impersonated_record.state_label,
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
                "impersonated_encoded_bit": impersonated_record.encoded_bit,
                "legitimate_state": legit_record.state_label,
                "impersonated_state": impersonated_record.state_label,
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
        "attack_type": "signature_impersonation",
        "message": message,
        "num_qubits": len(target_indices),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "eve_guessed_bits": [eq.encoded_bit for eq in impersonation_qubits],
        "observed_error_rate": observed_error_rate,
        "theoretical_expected_error_rate": 0.50,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "detailed_results": detailed_results,
    }
