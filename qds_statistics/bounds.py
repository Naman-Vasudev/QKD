"""
Forgery Probability Analysis and Security Bounds.

PURPOSE:
Quantifies the security the protocol actually delivers, rather than asserting it. Every
quantity here is a closed-form binomial expression evaluated exactly, so the numbers are
reproducible and independently checkable.

FORGERY PROBABILITY
-------------------
An attacker without the secret key K has no information about b_i = d_i XOR K_i. For a
uniformly random K, each b_i is uniform on {0, 1} and independent of the digest, so the
attacker's best strategy at every position is a coin flip:

    P(match at position i) = 1/2

A signature of length n is accepted when at most t = floor(s_a * n) positions disagree.
The attacker succeeds exactly when their error count lands in the acceptance region:

    P_forge(n, s_a) = sum_{j=0}^{t} C(n, j) * (1/2)^n

Security level in bits is -log2(P_forge). This decays exponentially in n, which is the
information-theoretic guarantee the protocol rests on: it holds against an adversary with
unbounded computational power, including a quantum computer, because the attacker is
missing information rather than facing a hard computation.

Worked value for this implementation (n = 256, s_a = 0.046, so t = 11):
    P_forge = 2^-256 * sum_{j=0}^{11} C(256, j)  ~  1.7e-58   ~  191 bits of security

INTERCEPT-RESEND BOUND
----------------------
An eavesdropper measuring in a uniformly random Pauli basis matches Alice's basis with
probability 1/3 and otherwise collapses the state, erring at 1/2:

    QBER_intercept = (1/3)(0) + (2/3)(1/2) = 1/3

Surviving verification then requires the resulting 1/3 error rate to fall inside the
acceptance region, which is itself a binomial tail.

DETECTION POWER
---------------
The statistical power of the binomial detector against an attack of true error rate q:

    k*    = min { k : P(K >= k | n, p0) < alpha }      (critical error count)
    Power = P(K >= k* | n, q)
    Size  = P(K >= k* | n, p0)                          (actual false-positive rate)

SCIENTIFIC DISCLOSURES:
- These are exact binomial evaluations, not approximations or simulations.
- The 1/2 per-position success rate assumes a uniformly random secret key. A biased or
  publicly guessable key (for example the alternating 0101... pattern) invalidates it;
  key_success_probability() makes that dependence explicit.
- Bounds describe the modelled adversaries. They are not a proof of security against
  adversaries outside this threat model (for example coherent multi-copy attacks).
- No artificial intelligence or machine learning is used.
"""

import math
from typing import Dict, List, Optional

from scipy.stats import binom

from core.models import ForgeryBound, DetectionPower


def key_success_probability(key_one_density: float) -> float:
    """
    Per-position success probability for a digest-only forger against a key of given density.

    A forger who assumes K = 0 matches at every position where K_i = 0, so their
    per-position success probability is 1 - rho. This is 1/2 only for a balanced key, and
    approaches 1.0 for a degenerate all-zero key.

    Args:
        key_one_density: Fraction of key bits equal to 1, in [0, 1].

    Returns:
        Per-position probability that the forger's state matches Bob's expectation.
    """
    if not (0.0 <= key_one_density <= 1.0):
        raise ValueError(f"Key 1-bit density must be in range [0.0, 1.0], got {key_one_density}.")
    return 1.0 - key_one_density


def forgery_success_probability(
    signature_length: int,
    acceptance_threshold: float,
    per_position_success: float = 0.5,
) -> ForgeryBound:
    """
    Compute the exact probability that an unaided forger is accepted.

    P_forge = P(Binomial(n, 1 - per_position_success) <= floor(s_a * n))

    Args:
        signature_length: Number of signature positions n (> 0).
        acceptance_threshold: Error-rate threshold s_a for acceptance, in [0, 1].
        per_position_success: Attacker's per-position match probability (0.5 unaided).

    Returns:
        ForgeryBound instance.
    """
    if signature_length <= 0:
        raise ValueError(f"Signature length must be positive, got {signature_length}.")
    if not (0.0 <= acceptance_threshold <= 1.0):
        raise ValueError(
            f"Acceptance threshold must be in range [0.0, 1.0], got {acceptance_threshold}."
        )
    if not (0.0 <= per_position_success <= 1.0):
        raise ValueError(
            f"Per-position success must be in range [0.0, 1.0], got {per_position_success}."
        )

    max_tolerated_errors = int(math.floor(acceptance_threshold * signature_length))
    per_position_error = 1.0 - per_position_success

    # P(errors <= t) under the attacker's own error distribution.
    p_forge = float(binom.cdf(max_tolerated_errors, signature_length, per_position_error))
    p_forge = min(1.0, max(0.0, p_forge))

    if p_forge <= 0.0:
        security_bits = math.inf
    elif p_forge >= 1.0:
        security_bits = 0.0
    else:
        security_bits = -math.log2(p_forge)

    interpretation = (
        f"An attacker without the secret key matches each of the n = {signature_length} positions "
        f"with probability {per_position_success:.4f}. Acceptance tolerates at most "
        f"{max_tolerated_errors} errors (s_a = {acceptance_threshold:.4f}), so the forgery success "
        f"probability is P_forge = {p_forge:.6e}, i.e. {security_bits:.1f} bits of security. "
        f"This bound is information-theoretic: it holds against unbounded computational power "
        f"because the attacker lacks information about K rather than facing a hard computation."
    )

    return ForgeryBound(
        signature_length=signature_length,
        acceptance_threshold=acceptance_threshold,
        max_tolerated_errors=max_tolerated_errors,
        per_position_success=per_position_success,
        forgery_probability=p_forge,
        security_bits=security_bits,
        interpretation=interpretation,
    )


def forgery_bound_curve(
    signature_lengths: Optional[List[int]] = None,
    acceptance_threshold: float = 0.05,
    per_position_success: float = 0.5,
) -> List[ForgeryBound]:
    """
    Evaluate the forgery bound across a range of signature lengths.

    Demonstrates the exponential decay of forgery probability in n, which is the core
    security scaling claim of the protocol.

    Args:
        signature_lengths: Signature lengths to evaluate
            (default [8, 16, 32, 64, 128, 256, 512]).
        acceptance_threshold: Error-rate acceptance threshold s_a.
        per_position_success: Attacker's per-position match probability.

    Returns:
        List of ForgeryBound instances, one per length.
    """
    if signature_lengths is None:
        signature_lengths = [8, 16, 32, 64, 128, 256, 512]

    return [
        forgery_success_probability(
            signature_length=n,
            acceptance_threshold=acceptance_threshold,
            per_position_success=per_position_success,
        )
        for n in signature_lengths
    ]


def critical_error_count(
    signature_length: int,
    baseline_error_rate: float,
    alpha: float = 0.05,
) -> int:
    """
    Find the smallest error count whose upper-tail p-value falls below alpha.

    This is the detector's rejection boundary k*: observing k >= k* errors triggers a
    threat alert.

    Args:
        signature_length: Number of trials n (> 0).
        baseline_error_rate: Baseline error rate p0 under H0.
        alpha: Significance threshold.

    Returns:
        Critical error count k* in [0, n + 1]. A return of n + 1 means no achievable
        error count reaches significance (the test has no power at this n and alpha).
    """
    if signature_length <= 0:
        raise ValueError(f"Signature length must be positive, got {signature_length}.")
    if not (0.0 <= baseline_error_rate <= 1.0):
        raise ValueError(f"Baseline error rate must be in range [0.0, 1.0], got {baseline_error_rate}.")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"Alpha must be in range (0.0, 1.0), got {alpha}.")

    if baseline_error_rate == 0.0:
        # Any single error is impossible under H0, so one error is already significant.
        return 1

    for k in range(0, signature_length + 1):
        # Upper tail P(K >= k) = sf(k - 1)
        tail = float(binom.sf(k - 1, signature_length, baseline_error_rate)) if k > 0 else 1.0
        if tail < alpha:
            return k

    return signature_length + 1


def detection_power(
    signature_length: int,
    baseline_error_rate: float,
    attack_error_rate: float,
    alpha: float = 0.05,
) -> DetectionPower:
    """
    Compute the exact statistical power of the binomial detector against an attack.

    Args:
        signature_length: Number of trials n (> 0).
        baseline_error_rate: Baseline error rate p0 under H0.
        attack_error_rate: True error rate q under H1 (e.g. 1/3 for intercept-resend).
        alpha: Significance threshold.

    Returns:
        DetectionPower instance.
    """
    if not (0.0 <= attack_error_rate <= 1.0):
        raise ValueError(f"Attack error rate must be in range [0.0, 1.0], got {attack_error_rate}.")

    k_star = critical_error_count(signature_length, baseline_error_rate, alpha)

    if k_star > signature_length:
        power = 0.0
        size = 0.0
    else:
        power = float(binom.sf(k_star - 1, signature_length, attack_error_rate))
        size = float(binom.sf(k_star - 1, signature_length, baseline_error_rate))

    return DetectionPower(
        signature_length=signature_length,
        baseline_error_rate=baseline_error_rate,
        attack_error_rate=attack_error_rate,
        alpha=alpha,
        critical_errors=k_star,
        detection_probability=min(1.0, max(0.0, power)),
        false_positive_rate=min(1.0, max(0.0, size)),
    )


def detection_power_curve(
    signature_lengths: Optional[List[int]] = None,
    baseline_error_rate: float = 0.02,
    attack_error_rate: float = 1.0 / 3.0,
    alpha: float = 0.05,
) -> List[DetectionPower]:
    """
    Evaluate detector power across a range of signature lengths.

    Args:
        signature_lengths: Lengths to evaluate (default [8, 16, 32, 64, 128, 256, 512]).
        baseline_error_rate: Baseline error rate p0.
        attack_error_rate: Attack error rate q under H1.
        alpha: Significance threshold.

    Returns:
        List of DetectionPower instances.
    """
    if signature_lengths is None:
        signature_lengths = [8, 16, 32, 64, 128, 256, 512]

    return [
        detection_power(
            signature_length=n,
            baseline_error_rate=baseline_error_rate,
            attack_error_rate=attack_error_rate,
            alpha=alpha,
        )
        for n in signature_lengths
    ]


# Analytic error rates produced by each modelled attack, used for power comparisons.
ATTACK_ERROR_RATES: Dict[str, float] = {
    "Channel Tampering (p=0.10)": (2.0 / 3.0) * 0.10,
    "Channel Tampering (p=0.50)": (2.0 / 3.0) * 0.50,
    "Quantum Interception": 1.0 / 3.0,
    "Signature Forgery": 0.5,
    "Impersonation": 0.5,
    "Replay (Different Message)": 0.5,
}


def attack_detection_summary(
    signature_length: int = 256,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
) -> List[Dict[str, object]]:
    """
    Build a detection-power summary table across all modelled attacks.

    Args:
        signature_length: Number of trials n.
        baseline_error_rate: Baseline error rate p0.
        alpha: Significance threshold.

    Returns:
        List of dicts with attack name, analytic error rate, power, and critical count.
    """
    summary: List[Dict[str, object]] = []
    for name, q in ATTACK_ERROR_RATES.items():
        power = detection_power(
            signature_length=signature_length,
            baseline_error_rate=baseline_error_rate,
            attack_error_rate=q,
            alpha=alpha,
        )
        summary.append({
            "attack": name,
            "analytic_error_rate": q,
            "critical_errors": power.critical_errors,
            "detection_probability": power.detection_probability,
            "false_positive_rate": power.false_positive_rate,
        })
    return summary
