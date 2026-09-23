"""
Core Data Models for Quantum Digital Signature (QDS) Simulation.

SCIENTIFIC DISTINCTIONS & DISCLOSURES:
- SHA-256 is classical preprocessing used to digest arbitrary messages; it is NOT the quantum signature.
- Quantum signature elements consist of Pauli eigenstates (|0>, |1>, |+>, |->, |+i>, |-i>).
- Quantum teleportation transfers quantum states across channels; it does NOT by itself authenticate Alice.
- Sender authentication and unforgeability depend on the pre-shared secret key K used during state encoding.
- Message freshness (replay resistance) depends on the per-session nonce bound into the digest.
- This is a research and educational prototype, not a production QDS deployment.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class EncodedQubit:
    """
    Represents a single classical-to-quantum encoded element of the QDS signature.

    Attributes:
        index: Position index in the signature sequence (0 to 255).
        digest_bit: Bit value from SHA-256 message digest (0 or 1).
        key_bit: Bit value from pre-shared secret key (0 or 1).
        encoded_bit: Result of digest_bit XOR key_bit (0 or 1).
        basis: Measurement basis string ("Z", "X", or "Y").
        state_label: Pauli eigenstate string ("|0>", "|1>", "|+>", "|->", "|+i>", "|-i>").
        expected_eigenvalue: Target observable measurement (+1 or -1).
    """

    index: int
    digest_bit: int
    key_bit: int
    encoded_bit: int
    basis: str
    state_label: str
    expected_eigenvalue: int

    def __post_init__(self) -> None:
        if self.basis not in ("Z", "X", "Y"):
            raise ValueError(f"Invalid basis: {self.basis}. Must be 'Z', 'X', or 'Y'.")
        if self.expected_eigenvalue not in (+1, -1):
            raise ValueError(f"Invalid eigenvalue: {self.expected_eigenvalue}. Must be +1 or -1.")
        if self.encoded_bit not in (0, 1):
            raise ValueError(f"Invalid encoded_bit: {self.encoded_bit}. Must be 0 or 1.")


@dataclass
class TeleportationResult:
    """
    Result of quantum state teleportation, Pauli correction, and projective measurement.

    Attributes:
        state_label: Label of the prepared Pauli eigenstate.
        c0: Alice's first Bell measurement classical bit (Z-correction trigger).
        c1: Alice's second Bell measurement classical bit (X-correction trigger).
        correction: Pauli correction applied by Bob ("I", "X", "Z", or "XZ").
        observed_eigenvalue: Measured eigenvalue at Bob (+1 or -1).
        expected_eigenvalue: Target eigenvalue expected by protocol (+1 or -1).
        matched: Boolean indicating whether observed_eigenvalue == expected_eigenvalue.
    """

    state_label: str
    c0: int
    c1: int
    correction: str
    observed_eigenvalue: int
    expected_eigenvalue: int
    matched: bool


@dataclass
class SignatureVerificationResult:
    """
    Overall verification result for a Quantum Digital Signature sequence.

    Attributes:
        message: Original classical payload string.
        num_qubits: Total number of signature qubits evaluated.
        num_matches: Number of qubits matching expected eigenvalues.
        num_errors: Number of qubits failing eigenvalue match.
        error_rate: Ratio of errors (num_errors / num_qubits).
        accepted: Boolean decision (True if error_rate == 0.0 under ideal simulation).
        results: Detailed per-qubit teleportation results.
        decision: Three-way SignatureDecision (ACCEPT / ABORT / REJECT) under the
            two-threshold rule. None if no baseline was supplied.
        freshness: FreshnessResult from the verifier's nonce registry, when a session
            context was supplied. None if the protocol ran without freshness binding.
        authorization: AuthorizationResult from the verifier-authorization check.
            None if verification was not access-controlled.
    """

    message: str
    num_qubits: int
    num_matches: int
    num_errors: int
    error_rate: float
    accepted: bool
    results: List[TeleportationResult] = field(default_factory=list)
    decision: Optional["SignatureDecision"] = None
    freshness: Optional["FreshnessResult"] = None
    authorization: Optional["AuthorizationResult"] = None


@dataclass
class ThreatResult:
    """
    Result of non-ML exact Binomial upper-tail statistical anomaly detection.

    Attributes:
        error_count: Number of verification errors observed (k).
        total_trials: Total verification trials evaluated (n).
        observed_error_rate: Ratio k / n.
        baseline_error_rate: Calibrated legitimate channel baseline error rate (p0).
        alpha: Statistical significance threshold (default: 0.05).
        p_value: Exact upper-tail probability P(K >= k | n, p0).
        threat_detected: True if p_value < alpha, indicating statistical anomaly.
        interpretation: Scientific interpretation statement.
    """

    error_count: int
    total_trials: int
    observed_error_rate: float
    baseline_error_rate: float
    alpha: float
    p_value: float
    threat_detected: bool
    interpretation: str = ""


@dataclass
class DecisionThresholds:
    """
    Two-threshold (accept / abort / reject) decision boundaries for signature verification.

    The single-threshold rule `accept iff error_rate == 0` is only correct for a noiseless
    channel. On a calibrated noisy channel a three-way rule is required so that legitimate
    signatures are still accepted deterministically while genuine attacks are rejected.

    Attributes:
        s_accept: Upper error-rate bound for ACCEPT (authentication threshold s_a).
        s_reject: Lower error-rate bound for REJECT (verification threshold s_v).
        baseline_error_rate: Calibrated baseline p0 the thresholds were derived from.
        total_trials: Number of trials n the thresholds were derived for.
        sigma: Binomial standard error sqrt(p0 (1 - p0) / n).
        sigma_multiplier: Number of standard errors allowed above p0 for ACCEPT.
        min_attack_error_rate: Smallest error rate any modelled attack produces (default 1/3).
        rationale: Human-readable derivation statement.
    """

    s_accept: float
    s_reject: float
    baseline_error_rate: float
    total_trials: int
    sigma: float
    sigma_multiplier: float
    min_attack_error_rate: float
    rationale: str = ""


@dataclass
class SignatureDecision:
    """
    Three-way verification verdict for a Quantum Digital Signature.

    Attributes:
        verdict: One of "ACCEPT", "ABORT", or "REJECT".
        error_count: Observed verification errors k.
        total_trials: Total verification trials n.
        observed_error_rate: k / n.
        thresholds: DecisionThresholds used to reach the verdict.
        deterministic_accept: True if error_rate was exactly 0.0 (ideal-channel acceptance).
        statistically_anomalous: Whether the exact binomial test rejected H0 (p = p0) at
            the supplied alpha. This is strictly more sensitive than the threshold rule:
            a weak channel attack can be statistically anomalous while still falling in
            the ABORT band. None when no alpha was supplied.
        p_value: Exact binomial upper-tail p-value, when computed.
        justification: Human-readable explanation of the verdict.
    """

    verdict: str
    error_count: int
    total_trials: int
    observed_error_rate: float
    thresholds: DecisionThresholds
    deterministic_accept: bool
    statistically_anomalous: Optional[bool] = None
    p_value: Optional[float] = None
    justification: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in ("ACCEPT", "ABORT", "REJECT"):
            raise ValueError(f"Invalid verdict: {self.verdict}. Must be 'ACCEPT', 'ABORT', or 'REJECT'.")


@dataclass
class BasisErrorProfile:
    """
    Basis-resolved error statistics — the observable fingerprint used for threat classification.

    Different attacks disturb the three Pauli bases in measurably different ways, so the
    triple (e_Z, e_X, e_Y) carries strictly more information than the pooled error rate.

    Attributes:
        counts: Trials evaluated per basis, keyed "Z", "X", "Y".
        errors: Errors observed per basis, keyed "Z", "X", "Y".
        rates: Error rate per basis, keyed "Z", "X", "Y".
        overall_rate: Pooled error rate across all bases.
        total_trials: Total trials across all bases.
        total_errors: Total errors across all bases.
        key_error_correlation: Matthews correlation between the per-position error indicator
            and the secret key bit K_i. Approaches +1.0 for a digest-only forgery (errors
            land exactly where K_i = 1) and ~0.0 for random-guess impersonation.
            None when key bits were not recorded for the experiment.
        uniformity: Max absolute deviation of any single basis rate from the overall rate.
            Near 0.0 means the attack hit all three bases equally.
    """

    counts: Dict[str, int]
    errors: Dict[str, int]
    rates: Dict[str, float]
    overall_rate: float
    total_trials: int
    total_errors: int
    key_error_correlation: Optional[float] = None
    uniformity: float = 0.0


@dataclass
class ClassificationHypothesis:
    """
    A single scored threat hypothesis produced by the classifier.

    Attributes:
        label: Threat class identifier (e.g. "CHANNEL_TAMPERING").
        display_name: Human-readable threat name.
        score: Match score in [0, 1]; higher means the observed fingerprint fits better.
        distance: Raw distance between observed and expected signature (lower is better),
            inclusive of any discriminator penalty.
        expected_signature: Expected (e_Z, e_X, e_Y) under this hypothesis.
        penalty: Distance added because a deterministic discriminator argued against this
            hypothesis (absent X-basis immunity, wrong key correlation, missing classical
            evidence). A non-zero penalty means the hypothesis was ruled down by structure
            rather than by error-rate proximity.
        evidence: Human-readable statements supporting or opposing this hypothesis.
    """

    label: str
    display_name: str
    score: float
    distance: float
    expected_signature: Dict[str, float]
    penalty: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class ThreatClassification:
    """
    Result of quantum-inspired threat classification from measurement statistics.

    DISCLOSURE: Classification is performed by deterministic distance scoring against
    analytically derived per-basis error signatures plus classical protocol evidence.
    No artificial intelligence or machine learning is used.

    Attributes:
        profile: BasisErrorProfile the classification was computed from.
        top_label: Highest-scoring threat class label.
        top_display_name: Highest-scoring threat class display name.
        confidence: Separation between the best and second-best hypothesis, in [0, 1].
        hypotheses: All hypotheses ranked best-first.
        classical_evidence: Classical protocol checks folded into the decision
            (nonce replay, digest mismatch, verifier authorization).
        interpretation: Human-readable summary statement.
    """

    profile: BasisErrorProfile
    top_label: str
    top_display_name: str
    confidence: float
    hypotheses: List[ClassificationHypothesis] = field(default_factory=list)
    classical_evidence: Dict[str, Any] = field(default_factory=dict)
    interpretation: str = ""


@dataclass
class SessionContext:
    """
    Per-signature freshness context providing replay resistance.

    The nonce, counter, and signer identity are bound into the hashed payload before
    encoding, so a captured signature cannot be replayed in a later session: the verifier
    derives a different digest and the attacker cannot re-derive the matching quantum
    states without the secret key K.

    Attributes:
        nonce: Cryptographically random hex nonce (unique per signing session).
        counter: Monotonically increasing sequence number for the signer.
        timestamp: UTC ISO-8601 timestamp of session creation.
        signer_id: Identity label of the signing party.
    """

    nonce: str
    counter: int
    timestamp: str
    signer_id: str = "alice"

    def canonical_binding(self) -> str:
        """Return the canonical string bound into the digest for this session."""
        return f"{self.signer_id}|{self.nonce}|{self.counter}|{self.timestamp}"


@dataclass
class FreshnessResult:
    """
    Outcome of a replay / freshness check performed by the verifier's nonce registry.

    Attributes:
        is_fresh: True if the session context has not been seen before.
        reason: Explanation of the accept/reject decision.
        replay_detected: True if this exact nonce was already consumed.
        stale_counter: True if the counter did not advance for this signer.
        nonce: The nonce that was checked.
        signer_id: The signer the check was performed for.
    """

    is_fresh: bool
    reason: str
    replay_detected: bool = False
    stale_counter: bool = False
    nonce: str = ""
    signer_id: str = ""


@dataclass
class AuthorizationResult:
    """
    Outcome of a verifier-authorization check (unauthorized verification detection).

    Attributes:
        authorized: True if the presented verifier token is valid.
        verifier_id: Identity of the party attempting verification.
        reason: Explanation of the accept/deny decision.
        token_present: True if any token was presented at all.
    """

    authorized: bool
    verifier_id: str
    reason: str
    token_present: bool = True


@dataclass
class ForgeryBound:
    """
    Information-theoretic forgery success probability analysis.

    Attributes:
        signature_length: Number of signature positions n.
        acceptance_threshold: Error-rate threshold s_a below which a signature is accepted.
        max_tolerated_errors: floor(s_a * n) — most errors an accepted signature may carry.
        per_position_success: Attacker's per-position probability of matching (0.5 unaided).
        forgery_probability: P(attacker lands within the acceptance region).
        security_bits: -log2(forgery_probability), i.e. equivalent security level.
        interpretation: Human-readable summary.
    """

    signature_length: int
    acceptance_threshold: float
    max_tolerated_errors: int
    per_position_success: float
    forgery_probability: float
    security_bits: float
    interpretation: str = ""


@dataclass
class DetectionPower:
    """
    Statistical power of the binomial detector against a specified attack strength.

    Attributes:
        signature_length: Number of trials n.
        baseline_error_rate: Calibrated baseline p0 under H0.
        attack_error_rate: True error rate under H1.
        alpha: Significance threshold.
        critical_errors: Smallest error count that triggers detection.
        detection_probability: Power = P(detect | attack present).
        false_positive_rate: Actual size of the test = P(detect | no attack).
    """

    signature_length: int
    baseline_error_rate: float
    attack_error_rate: float
    alpha: float
    critical_errors: int
    detection_probability: float
    false_positive_rate: float


@dataclass
class SecurityEvent:
    """
    Append-only audit record of a single security-relevant occurrence.

    DISCLOSURE: Secret key material is never written to the audit log. Only the key's
    1-bit density and a truncated digest prefix are recorded, so logs are safe to export.

    Attributes:
        event_id: Unique identifier for this event.
        timestamp: UTC ISO-8601 timestamp.
        event_type: Category (e.g. "VERIFICATION", "THREAT_DETECTED", "AUTH_DENIED").
        severity: One of "INFO", "WARNING", "CRITICAL".
        verdict: Verification verdict, if applicable.
        message_digest_prefix: First 16 hex characters of the message digest.
        detail: Structured event payload.
    """

    event_id: str
    timestamp: str
    event_type: str
    severity: str
    verdict: str = ""
    message_digest_prefix: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in ("INFO", "WARNING", "CRITICAL"):
            raise ValueError(f"Invalid severity: {self.severity}. Must be 'INFO', 'WARNING', or 'CRITICAL'.")


@dataclass
class SiftedKeyResult:
    """
    Result of entanglement-based quantum key distribution (BBM92) used to establish K.

    Attributes:
        raw_bits: Number of Bell pairs distributed and measured.
        sifted_length: Number of bits surviving basis reconciliation.
        key_bits: The sifted, reconciled key bits held by both parties.
        sample_size: Number of sifted bits sacrificed to estimate QBER.
        qber_errors: Disagreements observed within the disclosed sample.
        qber: Quantum bit error rate estimated from the disclosed sample.
        eavesdropper_present: Whether an intercept-resend adversary was simulated.
        threat_result: ThreatResult from the binomial detector applied to the QBER sample.
        bases_used: Measurement bases available during distribution.
        interpretation: Human-readable summary.
    """

    raw_bits: int
    sifted_length: int
    key_bits: List[int]
    sample_size: int
    qber_errors: int
    qber: float
    eavesdropper_present: bool
    threat_result: Optional[ThreatResult] = None
    bases_used: List[str] = field(default_factory=list)
    interpretation: str = ""


@dataclass
class RecipientShare:
    """
    One recipient's partial knowledge of the signature, forming their quantum public key.

    A recipient receives the full set of signature states but can only measure a subset of
    them, because measurement destroys each state and no-cloning forbids keeping a spare
    copy. Which positions they chose is private to that recipient and, critically, unknown
    to the signer -- that asymmetry is what prevents repudiation.

    Attributes:
        recipient_id: Identity label of the recipient.
        measured_positions: Signature positions this recipient measured and can verify.
        subset_fraction: measured_positions count divided by signature length.
        signature_length: Total signature length n.
    """

    recipient_id: str
    measured_positions: List[int]
    subset_fraction: float
    signature_length: int

    def __post_init__(self) -> None:
        if not self.recipient_id:
            raise ValueError("Recipient identity must be a non-empty string.")


@dataclass
class TransferThresholds:
    """
    The two acceptance thresholds that make a signature transferable.

    A single threshold cannot support forwarding: statistical fluctuation between two
    recipients' independently chosen subsets means a signature sitting near the boundary
    could pass for one and fail for the other. Two thresholds separated by a margin absorb
    that fluctuation.

        s_direct    Threshold a direct recipient applies.
        s_forwarded Threshold a third party applies to a forwarded signature.

    with s_direct < s_forwarded. Anything the direct recipient accepts, the third party
    also accepts (TRANSFERABILITY), while the signer cannot place a signature reliably
    between the two thresholds (NON-REPUDIATION).

    Attributes:
        s_direct: Error-rate threshold for direct acceptance.
        s_forwarded: Error-rate threshold for accepting a forwarded signature.
        margin: s_forwarded - s_direct, the fluctuation budget.
        subset_size: Positions each recipient verifies.
        baseline_error_rate: Calibrated baseline p0 the thresholds were derived from.
        rationale: Human-readable derivation statement.
    """

    s_direct: float
    s_forwarded: float
    margin: float
    subset_size: int
    baseline_error_rate: float
    rationale: str = ""


@dataclass
class TransferVerdict:
    """
    One recipient's verdict on a signature.

    Attributes:
        recipient_id: Identity of the verifying party.
        role: "DIRECT" for the original recipient, "FORWARDED" for a third party.
        positions_checked: Number of signature positions verified.
        errors: Verification errors observed on those positions.
        error_rate: errors / positions_checked.
        threshold: Threshold applied for this role.
        accepted: Whether the signature was accepted.
        justification: Human-readable explanation.
    """

    recipient_id: str
    role: str
    positions_checked: int
    errors: int
    error_rate: float
    threshold: float
    accepted: bool
    justification: str = ""

    def __post_init__(self) -> None:
        if self.role not in ("DIRECT", "FORWARDED"):
            raise ValueError(f"Invalid role: {self.role}. Must be 'DIRECT' or 'FORWARDED'.")


@dataclass
class TransferabilityResult:
    """
    Outcome of forwarding a signature from a direct recipient to a third party.

    Attributes:
        message: The signed message.
        direct_verdict: The direct recipient's verdict.
        forwarded_verdict: The third party's verdict on the forwarded signature.
        transferable: True if the direct acceptance was honoured downstream, i.e. NOT
            (direct accepted AND forwarded rejected).
        consistent: True if both parties reached the same verdict.
        thresholds: TransferThresholds in force.
        interpretation: Human-readable summary.
    """

    message: str
    direct_verdict: TransferVerdict
    forwarded_verdict: TransferVerdict
    transferable: bool
    consistent: bool
    thresholds: TransferThresholds
    interpretation: str = ""


@dataclass
class RepudiationResult:
    """
    Analysis of a signer's attempt to repudiate a signature.

    A repudiating signer deliberately corrupts a fraction of signature positions, hoping
    the damage falls below the direct recipient's threshold but above the third party's,
    so the signature is accepted now and disownable later. Because the signer does not
    know which positions either party measured, the corruption lands on both subsets in
    the same proportion on average, and splitting the verdicts requires a large
    fluctuation in opposite directions simultaneously.

    Attributes:
        corruption_fraction: Fraction of positions the signer deliberately corrupted.
        signature_length: Signature length n.
        subset_size: Positions each recipient verifies.
        analytic_success_probability: Exact probability of a successful split, computed
            from the hypergeometric distribution.
        trials: Number of simulated trials run, if any.
        observed_successes: Successful splits observed in simulation.
        observed_success_rate: observed_successes / trials.
        security_bits: -log2(analytic_success_probability).
        interpretation: Human-readable summary.
    """

    corruption_fraction: float
    signature_length: int
    subset_size: int
    analytic_success_probability: float
    trials: int = 0
    observed_successes: int = 0
    observed_success_rate: float = 0.0
    security_bits: float = 0.0
    interpretation: str = ""


@dataclass
class PerformanceMetrics:
    """
    Measured runtime performance of signature generation and verification.

    Attributes:
        operation: Name of the measured operation.
        signature_length: Number of signature positions processed.
        shots_per_qubit: Execution shots per position.
        total_seconds: Wall-clock duration of the whole operation.
        seconds_per_qubit: total_seconds / signature_length.
        qubits_per_second: Throughput.
        circuit_executions: Total circuit executions performed.
        backend_name: Backend the measurement was taken on.
    """

    operation: str
    signature_length: int
    shots_per_qubit: int
    total_seconds: float
    seconds_per_qubit: float
    qubits_per_second: float
    circuit_executions: int
    backend_name: str = ""


@dataclass
class ComplexityAnalysis:
    """
    Empirical computational-complexity scaling measurement.

    Attributes:
        sizes: Signature lengths measured.
        durations: Wall-clock seconds recorded at each size.
        log_log_slope: Slope of log(duration) vs log(size); ~1.0 indicates linear O(n).
        r_squared: Goodness of fit of the log-log regression.
        classification: Human-readable complexity class (e.g. "O(n) linear").
        per_qubit_seconds: Mean seconds per signature position across all sizes.
    """

    sizes: List[int]
    durations: List[float]
    log_log_slope: float
    r_squared: float
    classification: str
    per_qubit_seconds: float
