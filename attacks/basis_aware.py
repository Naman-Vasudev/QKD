"""
attacks/basis_aware.py
======================
Basis-Aware Individual-Qubit Intercept-Resend Attack Simulation Module.

THREAT MODEL & SCIENTIFIC PRINCIPLES:
- In the baseline scheme, the basis schedule is public and deterministic:
      position i uses basis B_i = i mod 3 in {Z, X, Y}.
- The message M is public, so the adversary computes digest bits d_i = SHA-256(P)_i.
- An individual-qubit interceptor sitting on the quantum channel who is aware of the
  public basis schedule does NOT guess bases uniformly at random.
- Instead, for each qubit index i:
    1. Eve measures Alice's signature qubit in the KNOWN preparation basis B_i = i mod 3.
    2. Because Alice prepared an eigenstate of basis B_i, Eve's measurement operator
       commutes with the state: the measurement causes ZERO basis-mismatch collapse.
    3. Eve's classical measurement outcome c_eve directly reveals the encoded bit:
           b'_i = 0 if outcome corresponds to +1 eigenvalue, 1 if -1 eigenvalue.
    4. Since b_i = d_i XOR K_i, Eve solves for the secret key bit directly:
           K'_i = b'_i XOR d_i.
    5. Eve prepares a replacement state in basis B_i matching her measurement outcome
       and forwards it into the teleportation channel toward Bob.
    6. Bob applies feedforward Pauli corrections and measures in basis B_i.
       Because the resent state exactly matches Alice's prepared state, Bob observes
       an error rate of 0.0 on an ideal channel!
    7. Bob's statistical threat detector observes 0 errors and NEVER flags an alert
       (detection rate = 0.0).
    8. Eve extracts the secret key bits K_i with 100% accuracy on an ideal channel.

This module models this specific adversary to evaluate whether the public deterministic
basis schedule leaks key material under individual-qubit interception.
"""

from typing import List, Optional, Dict, Any, Tuple
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from core.models import EncodedQubit
from core.backend import QuantumBackendAdapter
from core.seeding import ShotSeeder
from qds.states import apply_state_preparation, apply_basis_rotation
from qds.encoding import encode_message
from qds_statistics.detector import detect_threat


def build_basis_aware_intercepted_circuit(
    state_label: str,
    basis: str,
) -> QuantumCircuit:
    """
    Construct a 3-qubit teleportation circuit where Eve intercepts q0 and measures
    in the KNOWN basis before teleportation.

    Circuit Pipeline:
        1. Alice prepares signature state |psi_i> on q0 in basis.
        2. Eve intercepts q0, rotates into basis, and measures into c_eve.
        3. Eve resets q0 and re-prepares the state matching c_eve in the same basis.
        4. Standard 3-qubit teleportation carries q0 to Bob's qubit q2 via Bell pair (q1, q2).
        5. Bob applies feedforward Pauli corrections (Z^c0 X^c1) on q2.
        6. Bob applies basis rotation for basis on q2 and measures into c2.

    Args:
        state_label: Alice's prepared Pauli eigenstate.
        basis: The public preparation and verification basis ('Z', 'X', or 'Y').

    Returns:
        Configured Qiskit QuantumCircuit.
    """
    qr = QuantumRegister(3, "q")
    c_eve = ClassicalRegister(1, "c_eve")
    c0 = ClassicalRegister(1, "c0")
    c1 = ClassicalRegister(1, "c1")
    c2 = ClassicalRegister(1, "c2")
    qc = QuantumCircuit(qr, c_eve, c0, c1, c2, name=f"BasisAware_{state_label}_{basis}")

    # 1. Alice prepares signature state on q0
    apply_state_preparation(qc, 0, state_label)

    # 2. Eve intercepts q0 and measures in the KNOWN basis
    apply_basis_rotation(qc, 0, basis)
    qc.measure(0, c_eve[0])

    # 3. Eve resets q0 and re-prepares state matching her outcome in the same basis
    qc.reset(0)
    with qc.if_test((c_eve[0], 0)):
        if basis == "Z":
            apply_state_preparation(qc, 0, "|0>")
        elif basis == "X":
            apply_state_preparation(qc, 0, "|+>")
        else:  # Y
            apply_state_preparation(qc, 0, "|+i>")

    with qc.if_test((c_eve[0], 1)):
        if basis == "Z":
            apply_state_preparation(qc, 0, "|1>")
        elif basis == "X":
            apply_state_preparation(qc, 0, "|->")
        else:  # Y
            apply_state_preparation(qc, 0, "|-i>")

    # 4. Standard Bell pair on q1, q2
    qc.h(1)
    qc.cx(1, 2)

    # 5. Alice's Bell-basis measurement on q0, q1
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, c0[0])
    qc.measure(1, c1[0])

    # 6. Bob's conditional Pauli corrections on q2
    with qc.if_test((c1[0], 1)):
        qc.x(2)
    with qc.if_test((c0[0], 1)):
        qc.z(2)

    # 7. Bob measures in basis on q2
    apply_basis_rotation(qc, 2, basis)
    qc.measure(2, c2[0])

    return qc


def run_basis_aware_attack(
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
    Execute a Basis-Aware Interception attack across a sequence of signature qubits.

    Args:
        message: Classical message payload string.
        shared_key: 256-bit secret key vector K.
        shots_per_qubit: Number of execution shots per qubit (default 1).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        sample_indices: Optional subset of qubit indices to evaluate.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible simulation.

    Returns:
        Dictionary containing:
            - attack_type: "basis_aware_interception"
            - total_trials: Total verification shots executed
            - total_errors: Total errors observed by Bob
            - observed_error_rate: Error fraction observed by Bob
            - threat_result: ThreatResult from exact Binomial detector
            - key_leakage_rate: Fraction of secret key bits correctly recovered by Eve
            - extracted_key: Eve's reconstructed key bits
            - detailed_results: Per-qubit breakdown
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")

    encoded_qubits = encode_message(message, shared_key)

    if sample_indices is not None:
        target_qubits = [encoded_qubits[idx] for idx in sample_indices if 0 <= idx < 256]
    else:
        target_qubits = encoded_qubits

    if not target_qubits:
        raise ValueError("No valid signature qubits selected.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    seeder = ShotSeeder(seed)

    total_trials = 0
    total_errors = 0
    total_matches = 0
    eve_correct_bits = 0
    extracted_key: List[int] = []
    detailed_results: List[Dict[str, Any]] = []

    for q_record in target_qubits:
        idx = q_record.index
        d_i = q_record.digest_bit
        k_true = shared_key[idx]
        known_basis = q_record.basis

        qc = build_basis_aware_intercepted_circuit(
            state_label=q_record.state_label,
            basis=known_basis,
        )

        exec_res = backend.run_circuit(qc, shots=shots_per_qubit, seed_simulator=seeder.next())

        memory_list = exec_res.get("memory", [])
        if memory_list:
            raw_bits = memory_list[0].replace(" ", "")
            # Qiskit registers: c2 is bit 0, c1 is bit 1, c0 is bit 2, c_eve is bit 3 from left
            # Format: 'c2 c1 c0 c_eve' -> indices: c2=0, c1=1, c0=2, c_eve=3
            c2_val = int(raw_bits[0])
            c_eve_val = int(raw_bits[3]) if len(raw_bits) >= 4 else int(raw_bits[-1])
        else:
            counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
            c2_val = int(counts_key[0])
            c_eve_val = int(counts_key[3]) if len(counts_key) >= 4 else int(counts_key[-1])

        # Bob's eigenvalue evaluation: '0' -> +1, '1' -> -1
        observed_eigenvalue = +1 if c2_val == 0 else -1
        bob_matched = observed_eigenvalue == q_record.expected_eigenvalue

        total_trials += 1
        if bob_matched:
            total_matches += 1
        else:
            total_errors += 1

        # Eve deduces encoded bit b'_i from her measurement outcome c_eve:
        # outcome 0 -> +1 eigenvalue -> b'_i = 0
        # outcome 1 -> -1 eigenvalue -> b'_i = 1
        eve_b_guess = c_eve_val

        # Eve solves for key bit: K'_i = b'_i XOR d_i
        eve_k_guess = eve_b_guess ^ d_i
        extracted_key.append(eve_k_guess)

        if eve_k_guess == k_true:
            eve_correct_bits += 1

        detailed_results.append({
            "index": idx,
            "basis": known_basis,
            "d_i": d_i,
            "k_true": k_true,
            "b_true": q_record.encoded_bit,
            "c_eve": c_eve_val,
            "eve_k_guess": eve_k_guess,
            "key_bit_leaked": (eve_k_guess == k_true),
            "bob_matched": bob_matched,
        })

    observed_error_rate = total_errors / total_trials
    key_leakage_rate = eve_correct_bits / len(target_qubits)

    threat_res = detect_threat(
        error_count=total_errors,
        total_trials=total_trials,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    return {
        "attack_type": "basis_aware_interception",
        "message": message,
        "num_qubits": len(target_qubits),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "observed_error_rate": observed_error_rate,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "key_leakage_rate": key_leakage_rate,
        "eve_correct_bits": eve_correct_bits,
        "extracted_key": extracted_key,
        "detailed_results": detailed_results,
    }
