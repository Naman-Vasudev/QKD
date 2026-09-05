"""
Quantum Channel Interception (Intercept-Resend) Attack Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates an Intercept-Resend attack where Eve intercepts Alice's transmitted quantum state
  before Bob receives it over the quantum teleportation channel.
- Eve does NOT possess the secret key K_shared or Alice's legitimate preparation basis B_Alice.
- For each signature qubit:
  1. Alice prepares state |psi_i> using b_i = d_i XOR K_i.
  2. Eve intercepts the qubit and measures it in a chosen basis B_Eve in {Z, X, Y}.
  3. Quantum state collapse forces the qubit into an eigenstate of B_Eve.
  4. Eve prepares and resends a replacement state corresponding to her measurement outcome in B_Eve.
  5. Bob receives the resent state, applies Pauli corrections, and measures in basis B_Alice.
- Quantum Measurement-Disturbance Principles:
  - If B_Eve == B_Alice (probability ~ 1/3), Eve's measurement causes NO basis disturbance (0% error).
  - If B_Eve != B_Alice (probability ~ 2/3), Eve's measurement collapses the state into an orthogonal basis.
    When Bob measures in B_Alice, an error occurs with probability 1/2.
  - Overall theoretical error rate for uniform basis guessing = (1/3 * 0) + (2/3 * 1/2) = 1/3 (~33.33%).
- Verification errors emerge directly from actual Qiskit quantum circuit executions; they are NOT hardcoded.
"""

import random
from typing import List, Optional, Dict, Any, Tuple
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from core.models import EncodedQubit
from core.backend import QuantumBackendAdapter
from qds.states import apply_state_preparation, apply_basis_rotation, SUPPORTED_BASES
from qds.encoding import encode_message
from statistics.detector import detect_threat


def select_eve_basis(
    basis_choice: Optional[str] = None,
    rng: Optional[random.Random] = None,
) -> str:
    """
    Select Eve's measurement basis.

    Args:
        basis_choice: Optional fixed basis ('Z', 'X', or 'Y'). If None, selects uniformly at random.
        rng: Optional random.Random instance for reproducible sampling.

    Returns:
        Basis string ('Z', 'X', or 'Y').
    """
    if basis_choice is not None:
        if basis_choice not in SUPPORTED_BASES:
            raise ValueError(f"Invalid basis choice: '{basis_choice}'. Must be one of {SUPPORTED_BASES}")
        return basis_choice

    if rng is not None:
        return rng.choice(SUPPORTED_BASES)
    return random.choice(SUPPORTED_BASES)


def build_intercepted_teleportation_circuit(
    state_label: str,
    alice_basis: str,
    eve_basis: str,
) -> QuantumCircuit:
    """
    Construct a 3-qubit teleportation circuit with an active Intercept-Resend attack by Eve.

    Circuit Pipeline:
        1. Alice prepares signature state |psi_i> on q0.
        2. Eve intercepts q0 and measures in eve_basis (recorded in c_eve).
        3. Eve resets q0 and re-prepares the state matching her measurement outcome in eve_basis.
        4. Quantum teleportation carries q0 to Bob's qubit q2 (Bell pair on q1, q2).
        5. Bob applies conditional Pauli corrections (Z^(c0) X^(c1)) on q2.
        6. Bob applies basis rotation for alice_basis on q2 and measures into c2.

    Args:
        state_label: Alice's prepared Pauli eigenstate.
        alice_basis: Legitimate target verification basis ('Z', 'X', or 'Y').
        eve_basis: Eve's chosen measurement basis ('Z', 'X', or 'Y').

    Returns:
        Configured Qiskit QuantumCircuit.
    """
    qr = QuantumRegister(3, "q")
    c_eve = ClassicalRegister(1, "c_eve")
    c0 = ClassicalRegister(1, "c0")
    c1 = ClassicalRegister(1, "c1")
    c2 = ClassicalRegister(1, "c2")
    qc = QuantumCircuit(qr, c_eve, c0, c1, c2, name=f"Intercept_{state_label}_A{alice_basis}_E{eve_basis}")

    # 1. Alice Prepares Signature State on q0
    apply_state_preparation(qc, 0, state_label)

    # 2. Eve Intercepts q0 and Measures in eve_basis
    apply_basis_rotation(qc, 0, eve_basis)
    qc.measure(0, c_eve[0])

    # 3. Eve Resets q0 and Re-prepares Replacement State matching her outcome
    qc.reset(0)
    with qc.if_test((c_eve[0], 0)):
        if eve_basis == "Z":
            apply_state_preparation(qc, 0, "|0>")
        elif eve_basis == "X":
            apply_state_preparation(qc, 0, "|+>")
        elif eve_basis == "Y":
            apply_state_preparation(qc, 0, "|+i>")

    with qc.if_test((c_eve[0], 1)):
        if eve_basis == "Z":
            apply_state_preparation(qc, 0, "|1>")
        elif eve_basis == "X":
            apply_state_preparation(qc, 0, "|->")
        elif eve_basis == "Y":
            apply_state_preparation(qc, 0, "|-i>")

    # 4. Teleportation of q0 to q2
    qc.h(1)
    qc.cx(1, 2)
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, c0[0])
    qc.measure(1, c1[0])

    # 5. Bob's Conditional Pauli Corrections on q2
    with qc.if_test((c1[0], 1)):
        qc.x(2)
    with qc.if_test((c0[0], 1)):
        qc.z(2)

    # 6. Bob's Basis Transformation & Readout on q2
    apply_basis_rotation(qc, 2, alice_basis)
    qc.measure(2, c2[0])

    return qc


def run_single_qubit_interception_attack(
    state_label: str,
    alice_basis: str,
    expected_eigenvalue: int,
    eve_basis: Optional[str] = None,
    shots: int = 1000,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run an Intercept-Resend attack experiment on a single signature qubit.

    Args:
        state_label: Prepared Pauli eigenstate.
        alice_basis: Legitimate verification basis at Bob.
        expected_eigenvalue: Target expected eigenvalue (+1 or -1).
        eve_basis: Optional fixed basis for Eve ('Z', 'X', 'Y'). If None, sampled uniformly per shot.
        shots: Number of experiment shots (> 0).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible sampling.

    Returns:
        Dictionary containing experimental statistics and ThreatResult.
    """
    if shots <= 0:
        raise ValueError(f"Shots must be positive integer, got {shots}.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    rng = random.Random(seed) if seed is not None else None

    error_count = 0
    match_count = 0
    same_basis_count = 0
    diff_basis_count = 0

    for idx in range(shots):
        chosen_eve_basis = select_eve_basis(basis_choice=eve_basis, rng=rng)
        if chosen_eve_basis == alice_basis:
            same_basis_count += 1
        else:
            diff_basis_count += 1

        qc = build_intercepted_teleportation_circuit(
            state_label=state_label,
            alice_basis=alice_basis,
            eve_basis=chosen_eve_basis,
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
        "attack_type": "quantum_interception",
        "state_label": state_label,
        "alice_basis": alice_basis,
        "eve_basis": eve_basis if eve_basis is not None else "random_uniform",
        "total_trials": shots,
        "match_count": match_count,
        "error_count": error_count,
        "observed_error_rate": observed_error_rate,
        "same_basis_count": same_basis_count,
        "diff_basis_count": diff_basis_count,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
    }


def run_interception_attack(
    message: str,
    shared_key: List[int],
    eve_basis_strategy: Optional[str] = None,
    shots_per_qubit: int = 1,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    sample_indices: Optional[List[int]] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run an Intercept-Resend attack experiment across a full Quantum Digital Signature sequence.

    Args:
        message: Classical message string to verify (e.g., "ABC").
        shared_key: List of 256 secret key bits.
        eve_basis_strategy: Optional fixed basis strategy ('Z', 'X', 'Y') for Eve.
                            If None, Eve chooses basis uniformly at random per qubit.
        shots_per_qubit: Number of execution shots per signature qubit (default 1).
        baseline_error_rate: Calibrated legitimate baseline error rate p0.
        alpha: Statistical significance threshold.
        sample_indices: Optional list of qubit indices to verify.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducible sampling.

    Returns:
        Dictionary containing overall verification statistics, per-qubit results, and ThreatResult.
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")
    if shots_per_qubit <= 0:
        raise ValueError(f"Shots per qubit must be positive, got {shots_per_qubit}.")

    encoded_qubits = encode_message(message, shared_key)

    if sample_indices is not None:
        target_qubits = [encoded_qubits[idx] for idx in sample_indices if 0 <= idx < 256]
    else:
        target_qubits = encoded_qubits

    if not target_qubits:
        raise ValueError("No valid signature qubits selected for interception experiment.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    rng = random.Random(seed) if seed is not None else None

    total_trials = 0
    total_errors = 0
    total_matches = 0
    same_basis_trials = 0
    diff_basis_trials = 0
    detailed_results: List[Dict[str, Any]] = []

    for q_idx, q_record in enumerate(target_qubits):
        for shot_idx in range(shots_per_qubit):
            chosen_eve_basis = select_eve_basis(basis_choice=eve_basis_strategy, rng=rng)
            is_same_basis = chosen_eve_basis == q_record.basis

            if is_same_basis:
                same_basis_trials += 1
            else:
                diff_basis_trials += 1

            qc = build_intercepted_teleportation_circuit(
                state_label=q_record.state_label,
                alice_basis=q_record.basis,
                eve_basis=chosen_eve_basis,
            )
            sim_seed = (seed + q_idx * shots_per_qubit + shot_idx) if seed is not None else None
            exec_res = backend.run_circuit(qc, shots=1, seed_simulator=sim_seed)

            memory_list = exec_res.get("memory", [])
            if memory_list:
                clean_bits = memory_list[0].replace(" ", "")
                c2_val = int(clean_bits[0])
                c_eve_val = int(clean_bits[3]) if len(clean_bits) >= 4 else 0
            else:
                counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
                c2_val = int(counts_key[0])
                c_eve_val = 0

            observed_eigenvalue = +1 if c2_val == 0 else -1
            matched = observed_eigenvalue == q_record.expected_eigenvalue

            total_trials += 1
            if matched:
                total_matches += 1
            else:
                total_errors += 1

            detailed_results.append({
                "qubit_index": q_record.index,
                "state_label": q_record.state_label,
                "alice_basis": q_record.basis,
                "eve_basis": chosen_eve_basis,
                "same_basis": is_same_basis,
                "expected_eigenvalue": q_record.expected_eigenvalue,
                "observed_eigenvalue": observed_eigenvalue,
                "matched": matched,
            })

    observed_error_rate = total_errors / total_trials
    # Theoretical error rate: if uniform random basis selection, 1/3 of the time same basis (0% error),
    # 2/3 of the time diff basis (50% error) => expected total error rate = 1/3 (~33.33%)
    theoretical_error_rate = 1/3 if eve_basis_strategy is None else (0.0 if eve_basis_strategy == "MATCH_ALL" else 1/3)

    threat_res = detect_threat(
        error_count=total_errors,
        total_trials=total_trials,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
    )

    return {
        "attack_type": "quantum_interception",
        "eve_basis_strategy": eve_basis_strategy if eve_basis_strategy is not None else "random_uniform",
        "message": message,
        "num_qubits": len(target_qubits),
        "total_trials": total_trials,
        "total_matches": total_matches,
        "total_errors": total_errors,
        "observed_error_rate": observed_error_rate,
        "theoretical_expected_error_rate": theoretical_error_rate,
        "same_basis_trials": same_basis_trials,
        "diff_basis_trials": diff_basis_trials,
        "baseline_error_rate": baseline_error_rate,
        "threat_result": threat_res,
        "detailed_results": detailed_results,
    }
