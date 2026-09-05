"""
Core Data Models for Quantum Digital Signature (QDS) Simulation.

SCIENTIFIC DISTINCTIONS & DISCLOSURES:
- SHA-256 is classical preprocessing used to digest arbitrary messages; it is NOT the quantum signature.
- Quantum signature elements consist of Pauli eigenstates (|0>, |1>, |+>, |->, |+i>, |-i>).
- Quantum teleportation transfers quantum states across channels; it does NOT by itself authenticate Alice.
- Sender authentication and unforgeability depend on the pre-shared secret key K used during state encoding.
- This is a research and educational prototype, not a production QDS deployment.
"""

from dataclasses import dataclass, field
from typing import List, Optional


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
    """

    message: str
    num_qubits: int
    num_matches: int
    num_errors: int
    error_rate: float
    accepted: bool
    results: List[TeleportationResult] = field(default_factory=list)


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
