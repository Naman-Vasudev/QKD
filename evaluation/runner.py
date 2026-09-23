"""
Integrated Experiment Orchestration Engine for Quantum Digital Signatures.

SCIENTIFIC DISCLOSURES:
- Unifies execution of Phase 1 through Phase 2F modules without modifying underlying logic.
- Baseline noise probability p0 is an experimental parameter (calibrated/demo), NOT an industry constant.
- Threat detection uses exact Binomial upper-tail testing; threat_detected = True indicates statistical anomaly.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from core.models import (
    ThreatResult,
    ThreatClassification,
    SignatureDecision,
    SessionContext,
)
from core.backend import QuantumBackendAdapter
from core.audit import AuditLogger
from core.seeding import derive_seed
from qds.encoding import sha256_hex
from qds.session import NonceRegistry, create_session
from qds.verification import verify_signature
from qds_statistics.detector import detect_threat, decide_signature
from qds_statistics.classifier import classify_threat
from attacks.channel import run_channel_attack
from attacks.forgery import run_forgery_attack
from attacks.impersonation import run_impersonation_attack
from attacks.interception import run_interception_attack
from attacks.replay import run_replay_attack, compute_digest_hamming_distance
from attacks.unauthorized import run_unauthorized_verification_attack


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
        classification: ThreatClassification identifying WHICH threat the basis-resolved
            measurement statistics point to, not merely that an anomaly occurred.
        decision: Three-way ACCEPT / ABORT / REJECT verification verdict.
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
    classification: Optional[ThreatClassification] = None
    decision: Optional[SignatureDecision] = None


def _dispatch_experiment(
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

    Internal: use run_experiment(), which additionally attaches threat classification,
    the three-way verification decision, and audit logging.

    Supported attack_name values:
        - "No Attack / Baseline"
        - "Channel Tampering"
        - "Signature Forgery"
        - "Impersonation"
        - "Quantum Interception"
        - "Replay Attack"
        - "Unauthorized Verification"

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
            - replay: {"target_message": str, "session": SessionContext,
                       "nonce_registry": NonceRegistry}
            - unauthorized: {"profile": str}

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
            theoretical_expectation=res["theoretical_expected_error_rate"],
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
            theoretical_expectation=res["theoretical_expected_error_rate"],
            relevant_params={"eve_strategy": strategy, "fixed_basis": fixed_basis},
            protocol_note="Eve measures intercepted state in chosen basis and resends eigenstate. Basis mismatch introduces ~50% error on mismatched bases.",
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Replay Attack":
        target_message = str(params.get("target_message", message))
        session: Optional[SessionContext] = params.get("session")
        registry: Optional[NonceRegistry] = params.get("nonce_registry")
        res = run_replay_attack(
            original_message=message,
            target_message=target_message,
            shared_key=shared_key,
            shots_per_qubit=shots_per_qubit,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            backend=backend,
            seed=seed,
            original_session=session,
            nonce_registry=registry,
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
                "freshness_enabled": res["freshness_enabled"],
                "replay_detected_classically": res["replay_detected_classically"],
                "presented_nonce": res["presented_nonce"],
            },
            protocol_note=res["protocol_note"],
            detailed_results=res.get("detailed_results", []),
        )

    elif attack_name == "Unauthorized Verification":
        profile = str(params.get("profile", "NO_TOKEN"))
        res = run_unauthorized_verification_attack(
            message=message,
            shared_key=shared_key,
            attacker_profile=profile,
            baseline_error_rate=baseline_error_rate,
            backend=backend,
            seed=seed,
        )
        # Access control is deterministic, so the binomial detector is not the mechanism
        # here. A synthetic single-trial ThreatResult keeps the result shape uniform while
        # recording honestly that detection came from the classical check.
        threat_res = detect_threat(
            error_count=1 if res["denied"] else 0,
            total_trials=1,
            baseline_error_rate=min(baseline_error_rate, 0.999),
            alpha=alpha,
        )
        return ExperimentResult(
            attack_name="Unauthorized Verification",
            message=message,
            num_qubits=0,
            total_trials=1,
            num_errors=1 if res["denied"] else 0,
            observed_error_rate=1.0 if res["denied"] else 0.0,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            threat_result=threat_res,
            theoretical_expectation="Deterministic denial (no statistical test required)",
            relevant_params={
                "attacker_profile": profile,
                "attacker_id": res["attacker_id"],
                "token_presented": res["token_presented"],
                "quantum_states_consumed_by_attacker": res["quantum_states_consumed_by_attacker"],
                "control_verification_accepted": res["control_verification_accepted"],
            },
            protocol_note=res["interpretation"],
            detailed_results=[],
        )

    else:
        raise ValueError(
            f"Unknown attack_name '{attack_name}'. Valid options: "
            "'No Attack / Baseline', 'Channel Tampering', 'Signature Forgery', "
            "'Impersonation', 'Quantum Interception', 'Replay Attack', "
            "'Unauthorized Verification'."
        )


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
    classify: bool = True,
    audit_logger: Optional[AuditLogger] = None,
) -> ExperimentResult:
    """
    Execute a QDS security experiment, then classify the threat and record the event.

    Extends the raw dispatch with the three deliverables that operate on its output:
      - a three-way ACCEPT / ABORT / REJECT verification decision,
      - basis-resolved threat classification identifying WHICH attack occurred,
      - an append-only security event record.

    Args:
        attack_name: Name of attack scenario to execute.
        message: Classical payload message string (non-empty).
        shared_key: 256-bit secret key vector.
        baseline_error_rate: Calibrated baseline noise rate p0.
        alpha: Significance level.
        shots_per_qubit: Qiskit execution shots per qubit.
        seed: Optional random seed for reproducible testing.
        backend: Optional QuantumBackendAdapter.
        attack_params: Optional attack-specific controls (see _dispatch_experiment).
        classify: When True, attach a ThreatClassification derived from the per-position
            results. Skipped automatically when no per-position results are available.
        audit_logger: Optional AuditLogger. No event is recorded when omitted.

    Returns:
        Enriched ExperimentResult dataclass instance.
    """
    result = _dispatch_experiment(
        attack_name=attack_name,
        message=message,
        shared_key=shared_key,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
        shots_per_qubit=shots_per_qubit,
        seed=seed,
        backend=backend,
        attack_params=attack_params,
    )

    params = attack_params or {}

    # --- Three-way verification decision ---------------------------------------------
    if result.total_trials > 0:
        result.decision = decide_signature(
            error_count=result.num_errors,
            total_trials=result.total_trials,
            baseline_error_rate=baseline_error_rate,
        )

    # --- Threat classification --------------------------------------------------------
    if classify and result.detailed_results:
        key_density = sum(shared_key) / len(shared_key)
        result.classification = classify_threat(
            detailed_results=result.detailed_results,
            baseline_error_rate=baseline_error_rate,
            key_one_density=key_density,
            channel_probability=result.relevant_params.get("p_attack"),
            digest_hamming_fraction=(
                result.relevant_params.get("digest_hamming_distance", 0) / 256.0
                if "digest_hamming_distance" in result.relevant_params
                else None
            ),
            nonce_replay_detected=bool(
                result.relevant_params.get("replay_detected_classically", False)
            ),
            digest_mismatch_detected=(
                result.relevant_params.get("same_message") is False
            ),
        )
    elif classify and attack_name == "Unauthorized Verification":
        # No quantum measurements exist to profile; the denial is the whole finding.
        result.classification = None

    # --- Security event logging -------------------------------------------------------
    if audit_logger is not None:
        threat = result.threat_result.threat_detected
        if attack_name == "Unauthorized Verification":
            event_type = "AUTH_DENIED" if threat else "AUTH_GRANTED"
            severity = "CRITICAL" if threat else "INFO"
        elif result.relevant_params.get("replay_detected_classically"):
            event_type = "REPLAY_BLOCKED"
            severity = "CRITICAL"
        elif threat:
            event_type = "THREAT_DETECTED"
            severity = "CRITICAL"
        else:
            event_type = "VERIFICATION"
            severity = "INFO"

        audit_logger.log_event(
            event_type=event_type,
            severity=severity,
            verdict=result.decision.verdict if result.decision else "",
            message_digest_prefix=sha256_hex(message)[:16],
            detail={
                "attack_name": result.attack_name,
                "num_qubits": result.num_qubits,
                "total_trials": result.total_trials,
                "num_errors": result.num_errors,
                "observed_error_rate": round(result.observed_error_rate, 6),
                "baseline_error_rate": baseline_error_rate,
                "alpha": alpha,
                "p_value": result.threat_result.p_value,
                "threat_detected": threat,
                "classified_as": (
                    result.classification.top_label if result.classification else None
                ),
                "classification_confidence": (
                    round(result.classification.confidence, 4)
                    if result.classification
                    else None
                ),
                "key_one_density": round(sum(shared_key) / len(shared_key), 6),
                "backend": backend.backend_name if backend else "aer_simulator",
                "seed": seed,
            },
        )

    return result


def run_security_comparison(
    message: str,
    shared_key: List[int],
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    shots_per_qubit: int = 1,
    seed: Optional[int] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    audit_logger: Optional[AuditLogger] = None,
) -> List[ExperimentResult]:
    """
    Execute every attack scenario in sequence and aggregate standardized results.

    Covers all threat classes in the framework's scope: the baseline, channel tampering,
    forgery, impersonation, quantum interception, different-message replay, same-message
    replay via nonce reuse, and unauthorized verification.

    Args:
        message: Classical payload string.
        shared_key: Secret key vector K (256 bits).
        baseline_error_rate: Calibrated baseline error rate p0.
        alpha: Statistical significance threshold.
        shots_per_qubit: Execution shots per qubit.
        seed: Base random seed for execution.
        backend: Optional QuantumBackendAdapter.
        audit_logger: Optional AuditLogger for security event recording.

    Returns:
        List of ExperimentResult instances, one for each attack scenario.
    """
    # A pre-consumed session so the same-message replay scenario exercises the freshness
    # registry rather than the legacy undetectable path.
    replay_session = create_session(signer_id="alice", counter=1)
    replay_registry = NonceRegistry()

    scenarios = [
        ("No Attack / Baseline", {}),
        ("Channel Tampering", {"p_attack": 0.05}),
        ("Signature Forgery", {}),
        ("Impersonation", {}),
        ("Quantum Interception", {"strategy": "uniform_random"}),
        ("Replay Attack", {"target_message": f"{message}_diff"}),
        (
            "Replay Attack (Same Message, Nonce Reuse)",
            {
                "target_message": message,
                "session": replay_session,
                "nonce_registry": replay_registry,
            },
        ),
        ("Unauthorized Verification", {"profile": "FORGED_TOKEN"}),
    ]

    results: List[ExperimentResult] = []
    for idx, (name, params) in enumerate(scenarios):
        # Independent sub-stream per scenario; avoids the correlated-seed bias that
        # consecutive integer seeds introduce.
        sim_seed = derive_seed(seed, idx)
        dispatch_name = "Replay Attack" if name.startswith("Replay Attack") else name
        res = run_experiment(
            attack_name=dispatch_name,
            message=message,
            shared_key=shared_key,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
            shots_per_qubit=shots_per_qubit,
            seed=sim_seed,
            backend=backend,
            attack_params=params,
            audit_logger=audit_logger,
        )
        res.attack_name = name
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
        sim_seed = derive_seed(seed, 50, idx)
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

    for b_idx, (b_label, indices) in enumerate(basis_indices.items()):
        for idx, p in enumerate(probabilities):
            sim_seed = derive_seed(seed, 30, b_idx, idx)
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

