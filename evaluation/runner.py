"""
Integrated Experiment Orchestration Engine for Quantum Digital Signatures.

SCIENTIFIC DISCLOSURES:
- Unifies execution of Phase 1 through Phase 2F modules without modifying underlying logic.
- Baseline noise probability p0 is an experimental parameter (calibrated/demo), NOT an industry constant.
- Threat detection uses exact Binomial upper-tail testing; threat_detected = True indicates statistical anomaly.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from core.models import ThreatResult
from core.backend import QuantumBackendAdapter
from qds.verification import verify_signature
from statistics.detector import detect_threat
from attacks.channel import run_channel_attack
from attacks.forgery import run_forgery_attack
from attacks.impersonation import run_impersonation_attack
from attacks.interception import run_interception_attack
from attacks.replay import run_replay_attack, compute_digest_hamming_distance


@dataclass
class ExperimentResult:
    """
    Unified experiment outcome representation across all attack classes.

    Attributes:
        attack_name: Readable name of the attack scenario.
        message: Target classical message payload string.
        num_qubits: Total number of signature qubits evaluated (n).
        total_trials: Total verification trials (shots).
        num_errors: Total verification errors observed (k).
        observed_error_rate: Observed error fraction k / n.
        baseline_error_rate: Calibrated baseline error rate p0.
        alpha: Statistical significance threshold.
        threat_result: ThreatResult instance from exact Binomial detector.
        theoretical_expectation: Theoretical prediction description or value.
        relevant_params: Parameter dictionary specific to the attack class.
        protocol_note: Scientific or protocol property disclosure note.
        detailed_results: Detailed per-qubit results list.
    """

    attack_name: str
    message: str
    num_qubits: int
    total_trials: int
    num_errors: int
    observed_error_rate: float
    baseline_error_rate: float
    alpha: float
    threat_result: ThreatResult
    theoretical_expectation: Union[float, str]
    relevant_params: Dict[str, Any] = field(default_factory=dict)
    protocol_note: str = ""
    detailed_results: List[Dict[str, Any]] = field(default_factory=list)


def run_experiment(
    attack_name: str,
    message: str,
    shared_key: List[int],
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    shots_per_qubit: int = 1,
    seed: Optional[int] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    attack_params: Optional[Dict[str, Any]] = None,
) -> ExperimentResult:
    """
    Dispatch and execute a single QDS security experiment, normalizing the result.

    Supported attack_name values:
        - "No Attack / Baseline"
        - "Channel Tampering"
        - "Signature Forgery"
        - "Impersonation"
        - "Quantum Interception"
        - "Replay Attack"

    Args:
        attack_name: Name of attack scenario to execute.
        message: Classical payload message string (non-empty).
        shared_key: 256-bit secret key vector.
        baseline_error_rate: Calibrated baseline noise rate p0 (0 <= p0 <= 1).
        alpha: Significance level (0 < alpha < 1).
        shots_per_qubit: Qiskit execution shots per qubit.
        seed: Optional random seed for reproducible testing.
        backend: Optional QuantumBackendAdapter.
        attack_params: Optional dict containing specific attack controls:
            - channel: {"p_attack": float}
            - interception: {"strategy": str, "fixed_basis": str}
            - replay: {"target_message": str}

    Returns:
        Unified ExperimentResult dataclass instance.
    """
    if not message:
        raise ValueError("Message string cannot be empty.")
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")
    if not (0.0 <= baseline_error_rate <= 1.0):
        raise ValueError(f"Baseline error rate must be in range [0.0, 1.0], got {baseline_error_rate}.")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"Alpha must be in range (0.0, 1.0), got {alpha}.")
    if shots_per_qubit <= 0:
        raise ValueError(f"Shots per qubit must be positive, got {shots_per_qubit}.")

    params = attack_params or {}

    if attack_name == "No Attack / Baseline":
        ver_res = verify_signature(
            message=message,
            key_bits=shared_key,
            backend=backend,
            seed_simulator=seed,
        )
        total_trials = ver_res.num_qubits * shots_per_qubit
        num_errors = ver_res.num_errors * shots_per_qubit
        obs_rate = num_errors / total_trials

        threat_res = detect_threat(
            error_count=num_errors,
            total_trials=total_trials,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
        )

        return ExperimentResult(
            attack_name="No Attack / Baseline",
            message=message,
            num_qubits=ver_res.num_qubits,
            total_trials=total_trials,
            num_errors=num_errors,
            observed_error_rate=obs_rate,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=threat_res,
            theoretical_expectation=0.0,
            relevant_params={"status": "Legitimate channel without attack"},
            protocol_note="Legitimate signature transmission verified over calibrated channel.",
            detailed_results=[],
        )

    elif attack_name == "Channel Tampering":
        p_attack = float(params.get("p_attack", 0.05))
        res = run_channel_attack(
            message=message,
            key_bits=shared_key,
            attack_probability=p_attack,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
        )
        theoretical_exp = res.get("theoretical_error_rate", (2.0 / 3.0) * p_attack)
        return ExperimentResult(
            attack_name="Channel Tampering",
            message=message,
            num_qubits=res["num_qubits"],
            total_trials=res["total_trials"],
            num_errors=res["total_errors"],
            observed_error_rate=res["observed_error_rate"],
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=res["threat_result"],
            theoretical_expectation=theoretical_exp,
            relevant_params={"p_attack": p_attack},
            protocol_note="Probabilistic bit-flip noise injected into Bob's qubit q2. Z and Y basis qubits are sensitive; X basis is invariant.",
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Signature Forgery":
        res = run_forgery_attack(
            message=message,
            shared_key=shared_key,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
        )
        return ExperimentResult(
            attack_name="Signature Forgery",
            message=message,
            num_qubits=res["num_qubits"],
            total_trials=res["total_trials"],
            num_errors=res["total_errors"],
            observed_error_rate=res["observed_error_rate"],
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=res["threat_result"],
            theoretical_expectation=res["theoretical_mismatch_rate"],
            relevant_params={"attacker_knowledge": "Message M and SHA-256 digest D; Key K unknown"},
            protocol_note="Eve creates states assuming K=0 (b'_i = d_i). Verification errors equal the 1-bit density of shared key K.",
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Impersonation":
        res = run_impersonation_attack(
            message=message,
            shared_key=shared_key,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
        )
        return ExperimentResult(
            attack_name="Impersonation",
            message=message,
            num_qubits=res["num_qubits"],
            total_trials=res["total_trials"],
            num_errors=res["total_errors"],
            observed_error_rate=res["observed_error_rate"],
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=res["threat_result"],
            theoretical_expectation=res.get("theoretical_error_rate", 0.50),
            relevant_params={"attacker_knowledge": "None; Random Bernoulli(0.5) state guessing"},
            protocol_note="Eve guesses encoded signature bits randomly. Verification error rate approaches 50%.",
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Quantum Interception":
        strategy = str(params.get("strategy", "uniform_random"))
        fixed_basis = params.get("fixed_basis", None)
        eve_strategy = fixed_basis if strategy == "fixed_basis" else None
        res = run_interception_attack(
            message=message,
            shared_key=shared_key,
            eve_basis_strategy=eve_strategy,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
        )

        return ExperimentResult(
            attack_name="Quantum Interception",
            message=message,
            num_qubits=res["num_qubits"],
            total_trials=res["total_trials"],
            num_errors=res["total_errors"],
            observed_error_rate=res["observed_error_rate"],
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=res["threat_result"],
            theoretical_expectation=res.get("theoretical_error_rate", "1/3 (~33.3%) for random basis"),
            relevant_params={"eve_strategy": strategy, "fixed_basis": fixed_basis},
            protocol_note="Eve measures intercepted state in chosen basis and resends eigenstate. Basis mismatch introduces ~50% error on mismatched bases.",
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Replay Attack":
        target_message = str(params.get("target_message", message))
        res = run_replay_attack(
            original_message=message,
            target_message=target_message,
            shared_key=shared_key,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
        )
        return ExperimentResult(
            attack_name="Replay Attack",
            message=message,
            num_qubits=res["num_qubits"],
            total_trials=res["total_trials"],
            num_errors=res["total_errors"],
            observed_error_rate=res["observed_error_rate"],
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=res["threat_result"],
            theoretical_expectation=res["theoretical_error_rate"],
            relevant_params={
                "original_message": message,
                "target_message": target_message,
                "same_message": res["same_message"],
                "digest_hamming_distance": res["digest_hamming_distance"],
            },
            protocol_note=res["protocol_note"],
            detailed_results=res.get("detailed_results", []),
        )

    else:
        raise ValueError(
            f"Unknown attack_name '{attack_name}'. Valid options: "
            "'No Attack / Baseline', 'Channel Tampering', 'Signature Forgery', "
            "'Impersonation', 'Quantum Interception', 'Replay Attack'."
        )


def run_security_comparison(
    message: str,
    shared_key: List[int],
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    shots_per_qubit: int = 1,
    seed: Optional[int] = None,
    backend: Optional[QuantumBackendAdapter] = None,
) -> List[ExperimentResult]:
    """
    Execute all 6 attack scenarios in sequence and aggregate standardized results into a list.

    Args:
        message: Classical payload string.
        shared_key: Secret key vector K (256 bits).
        baseline_error_rate: Calibrated baseline error rate p0.
        alpha: Statistical significance threshold.
        shots_per_qubit: Execution shots per qubit.
        seed: Base random seed for execution.
        backend: Optional QuantumBackendAdapter.

    Returns:
        List of 6 ExperimentResult instances, one for each attack scenario.
    """
    scenarios = [
        ("No Attack / Baseline", {}),
        ("Channel Tampering", {"p_attack": 0.05}),
        ("Signature Forgery", {}),
        ("Impersonation", {}),
        ("Quantum Interception", {"strategy": "uniform_random"}),
        ("Replay Attack", {"target_message": f"{message}_diff"}),
    ]

    results: List[ExperimentResult] = []
    for idx, (name, params) in enumerate(scenarios):
        sim_seed = (seed + idx * 100) if seed is not None else None
        res = run_experiment(
            attack_name=name,
            message=message,
            shared_key=shared_key,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            shots_per_qubit=shots_per_qubit,
            seed=sim_seed,
            backend=backend,
            attack_params=params,
        )
        results.append(res)

    return results


def run_channel_tampering_sweep(
    message: str,
    shared_key: List[int],
    probabilities: Optional[List[float]] = None,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    shots_per_qubit: int = 1,
    seed: Optional[int] = None,
    backend: Optional[QuantumBackendAdapter] = None,
) -> List[ExperimentResult]:
    """
    Execute a channel tampering attack sweep across specified noise probabilities.

    Args:
        message: Classical payload string.
        shared_key: Secret key vector K.
        probabilities: List of attack probabilities to sweep (default: [0.00, 0.01, 0.02, 0.03, 0.05, 0.10, 0.20, 0.50, 1.00]).
        baseline_error_rate: Calibrated baseline error rate p0.
        alpha: Significance level.
        shots_per_qubit: Execution shots per qubit.
        seed: Base random seed.
        backend: Optional QuantumBackendAdapter.

    Returns:
        List of ExperimentResult objects corresponding to each probability.
    """
    if probabilities is None:
        probabilities = [0.00, 0.01, 0.02, 0.03, 0.05, 0.10, 0.20, 0.50, 1.00]

    sweep_results: List[ExperimentResult] = []
    for idx, p in enumerate(probabilities):
        sim_seed = (seed + idx * 50) if seed is not None else None
        res = run_experiment(
            attack_name="Channel Tampering",
            message=message,
            shared_key=shared_key,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            shots_per_qubit=shots_per_qubit,
            seed=sim_seed,
            backend=backend,
            attack_params={"p_attack": p},
        )
        sweep_results.append(res)

    return sweep_results


def run_basis_wise_channel_sweep(
    message: str,
    shared_key: List[int],
    probabilities: Optional[List[float]] = None,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    shots_per_qubit: int = 1,
    seed: Optional[int] = None,
    backend: Optional[QuantumBackendAdapter] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Execute channel tampering attack sweeps separately for Z, X, and Y measurement bases.

    Args:
        message: Classical payload string.
        shared_key: Secret key vector K.
        probabilities: List of attack probabilities (default: [0.00, 0.05, 0.10, 0.20, 0.50, 1.00]).
        baseline_error_rate: Calibrated baseline p0.
        alpha: Significance level.
        shots_per_qubit: Shots per signature qubit.
        seed: Base random seed.
        backend: Optional QuantumBackendAdapter.

    Returns:
        Dictionary mapping basis label ('Z', 'X', 'Y') to a list of per-probability result dicts:
        {"probability": p, "total_trials": n, "total_errors": k, "observed_error_rate": rate, "theoretical_rate": theo}
    """
    if probabilities is None:
        probabilities = [0.00, 0.05, 0.10, 0.20, 0.50, 1.00]

    basis_indices = {
        "Z": [i for i in range(256) if i % 3 == 0],
        "X": [i for i in range(256) if i % 3 == 1],
        "Y": [i for i in range(256) if i % 3 == 2],
    }

    basis_results: Dict[str, List[Dict[str, Any]]] = {"Z": [], "X": [], "Y": []}

    for b_label, indices in basis_indices.items():
        for idx, p in enumerate(probabilities):
            sim_seed = (seed + idx * 30 + (0 if b_label=="Z" else 10 if b_label=="X" else 20)) if seed is not None else None
            raw_res = run_channel_attack(
                message=message,
                key_bits=shared_key,
                attack_probability=p,
                shots_per_qubit=shots_per_qubit,
                baseline_error_rate=baseline_error_rate,
                alpha=alpha,
                sample_indices=indices,
                backend=backend,
                seed=sim_seed,
            )

            # Theoretical expectations under Pauli-X channel:
            # Z basis: sensitive -> error rate ~ p
            # X basis: invariant -> error rate ~ 0
            # Y basis: sensitive -> error rate ~ p
            if b_label in ("Z", "Y"):
                theo = p
            else:  # X
                theo = 0.0

            basis_results[b_label].append({
                "probability": p,
                "num_qubits": raw_res["num_qubits"],
                "total_trials": raw_res["total_trials"],
                "total_errors": raw_res["total_errors"],
                "observed_error_rate": raw_res["observed_error_rate"],
                "theoretical_rate": theo,
            })

    return basis_results

