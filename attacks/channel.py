"""
Quantum Channel Tampering Attack Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates physical quantum channel disturbance (probabilistic Pauli-X bit-flip errors).
- For every signature qubit being teleported, a bit-flip X error is introduced on qubit 2 (Bob's qubit)
  after teleportation state delivery and Pauli correction, with probability p_attack in [0, 1].
- The verification error rate emerges naturally from actual Qiskit quantum measurements;
  it is NOT hardcoded or manually assigned.
- In accordance with quantum mechanics:
  - Bit-flip X errors cause eigenstate projection mismatches in Z-basis and Y-basis observables.
  - In X-basis, X-eigenstates (|+) and |->) are invariant under X operations up to global phase.
- Anomaly detection identifies statistical inconsistency with the calibrated legitimate baseline (p0);
  it does NOT prove intentional adversary action versus environmental channel noise.
"""

import random
from typing import List, Optional, Dict, Any
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from core.models import EncodedQubit, TeleportationResult, ThreatResult
from core.backend import QuantumBackendAdapter
from qds.states import apply_state_preparation, apply_basis_rotation
from qds.encoding import encode_message
from statistics.detector import detect_threat


def apply_bit_flip_channel(
    qc: QuantumCircuit,
    qubit: int,
    probability: float,
    rng: Optional[random.Random] = None,
) -> QuantumCircuit:
    """
    Apply a probabilistic Pauli-X bit-flip channel error to a target qubit in a QuantumCircuit.

    Mathematical Transformation:
        rho -> (1 - p) * rho + p * X * rho * X

    Args:
        qc: Qiskit QuantumCircuit instance.
        qubit: Target qubit index (0 <= qubit < qc.num_qubits).
        probability: Channel disturbance probability p_attack in [0.0, 1.0].
        rng: Optional random.Random generator for reproducible sampling.

    Returns:
        Modified QuantumCircuit.
    """
    if not (0.0 <= probability <= 1.0):
        raise ValueError(f"Attack probability must be in range [0.0, 1.0], got {probability}.")
    if qubit < 0 or qubit >= qc.num_qubits:
        raise ValueError(f"Target qubit index {qubit} out of range for circuit with {qc.num_qubits} qubits.")

    if probability > 0.0:
        rand_val = rng.random() if rng is not None else random.random()
        if rand_val < probability:
            qc.x(qubit)

    return qc


def build_tampered_teleportation_circuit(
    state_label: str,
    basis: str,
    attack_probability: float,
    rng: Optional[random.Random] = None,
    force_x: Optional[bool] = None,
) -> QuantumCircuit:
    """
    Construct a 3-qubit teleportation circuit with injected bit-flip channel tampering.

    Circuit Pipeline:
        1. Alice prepares signature state |psi_i> on q0.
        2. Bell pair creation (|Phi+>) on q1, q2.
        3. Alice's Bell-state measurement on q0, q1.
        4. Bob's conditional Pauli corrections (Z^(c0) X^(c1)) on q2.
        5. Probabilistic channel tampering (X error with probability p_attack) on q2.
        6. Bob's measurement basis transformation & readout on q2.

    Args:
        state_label: Prepared Pauli eigenstate ('|0>', '|1>', '|+>', '|->', '|+i>', '|-i>').
        basis: Target verification basis ('Z', 'X', or 'Y').
        attack_probability: Channel disturbance probability p_attack in [0.0, 1.0].
        rng: Optional random.Random instance for sampling.
        force_x: If explicit bool provided, force Pauli-X gate on q2 (True) or skip (False).

    Returns:
        Configured Qiskit QuantumCircuit.
    """
    qr = QuantumRegister(3, "q")
    c0 = ClassicalRegister(1, "c0")
    c1 = ClassicalRegister(1, "c1")
    c2 = ClassicalRegister(1, "c2")
    qc = QuantumCircuit(qr, c0, c1, c2, name=f"TamperedTeleport_{state_label}_{basis}")

    # 1. State Preparation on q0
    apply_state_preparation(qc, 0, state_label)

    # 2. Bell-pair Creation on q1 and q2
    qc.h(1)
    qc.cx(1, 2)

    # 3. Alice's Bell-state Measurement on q0 and q1
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, c0[0])
    qc.measure(1, c1[0])

    # 4. Bob's Conditional Pauli Corrections on q2
    with qc.if_test((c1[0], 1)):
        qc.x(2)
    with qc.if_test((c0[0], 1)):
        qc.z(2)

    # 5. Inject Bit-Flip Channel Tampering on q2
    if force_x is not None:
        if force_x:
            qc.x(2)
    else:
        apply_bit_flip_channel(qc, qubit=2, probability=attack_probability, rng=rng)

    # 6. Bob's Basis Transformation & Readout on q2
    apply_basis_rotation(qc, 2, basis)
    qc.measure(2, c2[0])

    return qc


def run_single_qubit_channel_attack(
    state_label: str,
    basis: str,
    expected_eigenvalue: int,
    attack_probability: float,
    shots: int = 1000,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run a multi-shot channel tampering experiment on a single Pauli eigenstate.

    Args:
        state_label: Prepared Pauli eigenstate.
        basis: Target verification basis.
        expected_eigenvalue: Target eigenvalue (+1 or -1).
        attack_probability: Channel disturbance probability p_attack in [0.0, 1.0].
        shots: Number of experiment shots (> 0).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible sampling.

    Returns:
        Dictionary containing experimental outcomes and ThreatResult.
    """
    if not (0.0 <= attack_probability <= 1.0):
        raise ValueError(f"Attack probability must be in range [0.0, 1.0], got {attack_probability}.")
    if shots <= 0:
        raise ValueError(f"Shots must be positive integer, got {shots}.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    rng = random.Random(seed) if seed is not None else None

    error_count = 0
    match_count = 0

    for idx in range(shots):
        qc = build_tampered_teleportation_circuit(
            state_label=state_label,
            basis=basis,
            attack_probability=attack_probability,
            rng=rng,
        )
        sim_seed = (seed + idx) if seed is not None else None
        exec_res = backend.run_circuit(qc, shots=1, seed_simulator=sim_seed)

        memory_list = exec_res.get("memory", [])
        if memory_list:
            clean_bits = memory_list[0].replace(" ", "")
            c2_val = int(clean_bits[0])
        else:
            counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
            c2_val = int(counts_key[0])

        observed_eigenvalue = +1 if c2_val == 0 else -1

        if observed_eigenvalue == expected_eigenvalue:
            match_count += 1
        else:
            error_count += 1

    observed_error_rate = error_count / shots
    threat_res = detect_threat(
        error_count=error_count,
        total_trials=shots,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    return {
        "attack_type": "bit_flip_channel",
        "attack_probability": attack_probability,
        "state_label": state_label,
        "basis": basis,
        "total_trials": shots,
        "match_count": match_count,
        "error_count": error_count,
        "observed_error_rate": observed_error_rate,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
    }


def run_channel_attack(
    message: str,
    key_bits: List[int],
    attack_probability: float,
    shots_per_qubit: int = 1,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    sample_indices: Optional[List[int]] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run a channel tampering attack experiment across a full Quantum Digital Signature sequence.

    Args:
        message: Classical message string to verify (e.g., "ABC").
        key_bits: List of 256 secret key bits.
        attack_probability: Probabilistic bit-flip channel parameter p_attack in [0.0, 1.0].
        shots_per_qubit: Number of execution shots per signature qubit (default 1).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        sample_indices: Optional list of qubit indices to verify.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible sampling.

    Returns:
        Dictionary containing overall verification statistics, per-qubit results, and ThreatResult.
    """
    if not (0.0 <= attack_probability <= 1.0):
        raise ValueError(f"Attack probability must be in range [0.0, 1.0], got {attack_probability}.")
    if shots_per_qubit <= 0:
        raise ValueError(f"Shots per qubit must be positive, got {shots_per_qubit}.")

    encoded_qubits = encode_message(message, key_bits)

    if sample_indices is not None:
        target_qubits = [encoded_qubits[idx] for idx in sample_indices if 0 <= idx < 256]
    else:
        target_qubits = encoded_qubits

    if not target_qubits:
        raise ValueError("No valid signature qubits selected for attack experiment.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    rng = random.Random(seed) if seed is not None else None

    total_trials = 0
    total_errors = 0
    total_matches = 0
    total_x_injected = 0
    detailed_results: List[Dict[str, Any]] = []

    for q_idx, q_record in enumerate(target_qubits):
        for shot_idx in range(shots_per_qubit):
            x_injected = False
            if attack_probability > 0.0:
                rand_val = rng.random() if rng is not None else random.random()
                x_injected = rand_val < attack_probability

            if x_injected:
                total_x_injected += 1

            qc = build_tampered_teleportation_circuit(
                state_label=q_record.state_label,
                basis=q_record.basis,
                attack_probability=attack_probability,
                force_x=x_injected,
            )
            sim_seed = (seed + q_idx * shots_per_qubit + shot_idx) if seed is not None else None
            exec_res = backend.run_circuit(qc, shots=1, seed_simulator=sim_seed)

            memory_list = exec_res.get("memory", [])
            if memory_list:
                clean_bits = memory_list[0].replace(" ", "")
                c2_val = int(clean_bits[0])
                c1_val = int(clean_bits[1])
                c0_val = int(clean_bits[2])
            else:
                counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
                c2_val = int(counts_key[0])
                c1_val = int(counts_key[1])
                c0_val = int(counts_key[2])

            observed_eigenvalue = +1 if c2_val == 0 else -1
            matched = observed_eigenvalue == q_record.expected_eigenvalue

            total_trials += 1
            if matched:
                total_matches += 1
            else:
                total_errors += 1

            detailed_results.append({
                "qubit_index": q_record.index,
                "digest_bit": q_record.digest_bit,
                "key_bit": q_record.key_bit,
                "encoded_bit": q_record.encoded_bit,
                "state_label": q_record.state_label,
                "basis": q_record.basis,
                "x_injected": x_injected,
                "expected_eigenvalue": q_record.expected_eigenvalue,
                "observed_eigenvalue": observed_eigenvalue,
                "matched": matched,
                "c0": c0_val,
                "c1": c1_val,
            })

    observed_error_rate = total_errors / total_trials
    threat_res = detect_threat(
        error_count=total_errors,
        total_trials=total_trials,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    return {
        "attack_type": "bit_flip_channel",
        "attack_probability": attack_probability,
        "message": message,
        "num_qubits": len(target_qubits),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "total_x_injected": total_x_injected,
        "observed_error_rate": observed_error_rate,
        "theoretical_error_rate": (2.0 / 3.0) * attack_probability,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "detailed_results": detailed_results,
    }
