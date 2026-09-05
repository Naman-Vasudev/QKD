"""
Quantum Digital Signature Replay Attack Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates a replay attack where Eve captures a previously valid quantum signature transmission
  and attempts to reuse/replay it for verification of a (possibly different) message.
- Eve does NOT need to know the shared secret key Kshared.
- Eve captures the quantum states produced by legitimate Alice for M_original and replays them
  when Bob expects verification for M_target.

PROTOCOL PROPERTY — NO FRESHNESS MECHANISM:
- The existing QDS encoding is deterministic: D = SHA-256(M), b_i = d_i XOR K_i.
- There is no session nonce, timestamp, or freshness token in the current protocol.
- Therefore, replaying a captured signature for the SAME message (M_target == M_original)
  produces states identical to a fresh signature and is INDISTINGUISHABLE from legitimate.
- This is a known protocol limitation, not a bug.

DIFFERENT-MESSAGE REPLAY:
- When M_target != M_original, Bob expects states derived from D' = SHA-256(M_target),
  but Eve supplies states derived from D = SHA-256(M_original).
- Errors occur at bit positions where d_i != d'_i (digest Hamming distance).
- Since b_original_i = d_i XOR K_i and b_target_i = d'_i XOR K_i, the mismatch positions
  are exactly where d_i != d'_i (the key K_i cancels in the XOR comparison).
- Theoretical error rate = hamming_distance(D, D') / 256.
- Due to SHA-256 avalanche property, typical error rate for distinct messages ≈ 50%.
"""

from typing import List, Optional, Dict, Any, Tuple
from core.models import EncodedQubit
from core.backend import QuantumBackendAdapter
from qds.encoding import encode_message, sha256_bits
from qds.teleportation import teleport_and_measure
from statistics.detector import detect_threat


def capture_legitimate_signature(
    message: str,
    shared_key: List[int],
) -> List[EncodedQubit]:
    """
    Generate and capture a legitimate QDS signature for message M.

    In a real scenario, Alice produces this signature and transmits it.
    Eve intercepts and stores the full set of encoded qubit records.

    Args:
        message: Classical message string M_original.
        shared_key: Alice and Bob's pre-shared secret key K (256 bits).

    Returns:
        List of 256 EncodedQubit records representing the captured signature.
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")
    return encode_message(message, shared_key)


def compute_digest_hamming_distance(message_a: str, message_b: str) -> Tuple[int, float]:
    """
    Compute the Hamming distance between SHA-256 digests of two messages.

    Args:
        message_a: First message string.
        message_b: Second message string.

    Returns:
        Tuple of (hamming_distance, hamming_fraction) where:
            hamming_distance: Number of bit positions where digests differ.
            hamming_fraction: hamming_distance / 256.
    """
    digest_a = sha256_bits(message_a)
    digest_b = sha256_bits(message_b)
    distance = sum(a != b for a, b in zip(digest_a, digest_b))
    return distance, distance / 256.0


def run_replay_attack(
    original_message: str,
    target_message: str,
    shared_key: List[int],
    shots_per_qubit: int = 1,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    sample_indices: Optional[List[int]] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute a Quantum Digital Signature Replay Attack experiment.

    Eve captures a legitimate signature for original_message produced by Alice,
    then replays those quantum states when Bob is verifying target_message.

    Bob's verification computes his own expected encoding from target_message:
        D_target = SHA-256(target_message)
        b_target_i = d_target_i XOR K_i

    Eve supplies states from original_message:
        D_original = SHA-256(original_message)
        b_original_i = d_original_i XOR K_i

    Mismatch occurs at positions where d_original_i != d_target_i.

    Args:
        original_message: Message for which Alice produced the legitimate signature.
        target_message: Message for which Bob is expecting verification.
        shared_key: Pre-shared secret key K (256 bits).
        shots_per_qubit: Number of Qiskit execution shots per qubit (default 1).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        sample_indices: Optional list of qubit indices to verify.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.

    Returns:
        Dictionary containing:
            - attack_type: "signature_replay"
            - original_message, target_message
            - same_message: Boolean indicating if replay is for the same message
            - digest_hamming_distance, digest_hamming_fraction
            - theoretical_error_rate: Expected mismatch rate from digest comparison
            - total_trials, total_errors, total_matches
            - observed_error_rate
            - baseline_error_rate
            - threat_result: ThreatResult from exact Binomial detector
            - protocol_note: Scientific observation about freshness
            - detailed_results: Per-qubit breakdown
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")

    same_message = (original_message == target_message)

    # 1. Capture legitimate signature for original message (Eve's captured states)
    captured_qubits = capture_legitimate_signature(original_message, shared_key)

    # 2. Compute Bob's expected encoding for the target message
    target_qubits = encode_message(target_message, shared_key)

    # 3. Compute digest Hamming distance (theoretical error prediction)
    hamming_dist, hamming_frac = compute_digest_hamming_distance(original_message, target_message)

    # 4. Select qubit indices
    if sample_indices is not None:
        target_indices = [idx for idx in sample_indices if 0 <= idx < 256]
    else:
        target_indices = list(range(256))

    if not target_indices:
        raise ValueError("No valid signature qubits selected for replay experiment.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    # 5. Compute theoretical error rate for the selected subset
    subset_mismatches = sum(
        1 for idx in target_indices
        if captured_qubits[idx].encoded_bit != target_qubits[idx].encoded_bit
    )
    theoretical_error_rate = subset_mismatches / len(target_indices)

    # 6. Execute quantum teleportation and verification
    total_trials = 0
    total_errors = 0
    total_matches = 0
    detailed_results: List[Dict[str, Any]] = []

    for q_idx, idx in enumerate(target_indices):
        captured = captured_qubits[idx]
        expected = target_qubits[idx]

        for shot_idx in range(shots_per_qubit):
            sim_seed = (seed + q_idx * shots_per_qubit + shot_idx) if seed is not None else None

            # Eve replays captured state; Bob measures in target-expected basis
            res = teleport_and_measure(
                state_label=captured.state_label,
                basis=expected.basis,
                expected_eigenvalue=expected.expected_eigenvalue,
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
                "captured_state": captured.state_label,
                "expected_state": expected.state_label,
                "basis": expected.basis,
                "captured_encoded_bit": captured.encoded_bit,
                "expected_encoded_bit": expected.encoded_bit,
                "bits_differ": captured.encoded_bit != expected.encoded_bit,
                "expected_eigenvalue": expected.expected_eigenvalue,
                "observed_eigenvalue": res.observed_eigenvalue,
                "matched": res.matched,
            })

    observed_error_rate = total_errors / total_trials

    # 7. Statistical threat detection
    threat_res = detect_threat(
        error_count=total_errors,
        total_trials=total_trials,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    # 8. Scientific observation about protocol freshness
    if same_message:
        protocol_note = (
            "PROTOCOL PROPERTY: The replayed signature was for the SAME message. "
            "The current protocol has no freshness mechanism (no nonce, timestamp, or session token). "
            "Therefore, a byte-for-byte replay of a valid signature for the same message is "
            "indistinguishable from a fresh legitimate signature. "
            "This is a known limitation of the current prototype architecture."
        )
    else:
        protocol_note = (
            "DIFFERENT MESSAGE REPLAY: The replayed signature was originally produced for a "
            f"different message. Bob's expected encoding is derived from SHA-256(\"{target_message}\"), "
            f"but Eve supplied states derived from SHA-256(\"{original_message}\"). "
            f"Digest Hamming distance = {hamming_dist}/256 ({hamming_frac:.4f}). "
            "Errors emerge at positions where the digest bits differ."
        )

    return {
        "attack_type": "signature_replay",
        "original_message": original_message,
        "target_message": target_message,
        "same_message": same_message,
        "digest_hamming_distance": hamming_dist,
        "digest_hamming_fraction": hamming_frac,
        "theoretical_error_rate": theoretical_error_rate,
        "num_qubits": len(target_indices),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "observed_error_rate": observed_error_rate,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "protocol_note": protocol_note,
        "detailed_results": detailed_results,
    }
