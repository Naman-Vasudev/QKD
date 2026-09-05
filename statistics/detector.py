"""
Statistical Threat Detector Engine for Quantum Digital Signatures.

SCIENTIFIC DISCLOSURES & REQUIREMENTS:
- There is NO single universal quantum error rate that constitutes an "industry standard."
- Error rates depend on physical hardware, gates, measurement noise, and channel environment.
- The baseline error probability (p0) MUST be obtained through experimental calibration or explicitly
  supplied as a synthetic experimental parameter.
- This detector uses exact Binomial upper-tail hypothesis testing (H0: p = p0 vs H1: p > p0).
- "Threat detected" (p-value < alpha) indicates that observed error counts are statistically
  inconsistent with the calibrated legitimate baseline at significance level alpha.
- Statistical anomaly detection indicates physical channel disturbance or state mismatch;
  it does NOT prove the presence or identity of an intentional attacker.
- Artificial intelligence (AI) and machine learning (ML) are explicitly NOT used.
"""

import math
from scipy.stats import binomtest
from core.models import ThreatResult


def calibrate_baseline(error_count: int, total_trials: int) -> float:
    """
    Estimate the legitimate system baseline error probability (p0) from calibration trials.

    Args:
        error_count: Number of verification errors observed during legitimate calibration (>= 0).
        total_trials: Total calibration trials executed (> 0).

    Returns:
        Estimated baseline error probability p0 = error_count / total_trials.
    """
    if total_trials <= 0:
        raise ValueError(f"Total trials must be positive, got {total_trials}.")
    if error_count < 0 or error_count > total_trials:
        raise ValueError(f"Error count must be in range [0, {total_trials}], got {error_count}.")

    return error_count / total_trials


def detect_threat(
    error_count: int,
    total_trials: int,
    baseline_error_rate: float,
    alpha: float = 0.05,
) -> ThreatResult:
    """
    Perform an exact Binomial upper-tail hypothesis test to detect statistical anomalies.

    Hypothesis Formulation:
        Null Hypothesis (H0): p = p0 (Observed errors are consistent with baseline noise p0).
        Alternative (H1): p > p0 (Observed errors significantly exceed baseline noise p0).

    Upper-Tail Probability Calculation:
        P(K >= k | n, p0) = sum_{j=k}^{n} C(n, j) * p0^j * (1 - p0)^(n - j)

    Args:
        error_count: Observed number of verification errors k (0 <= k <= n).
        total_trials: Total verification trials n (> 0).
        baseline_error_rate: Calibrated baseline error rate p0 (0 <= p0 <= 1).
        alpha: Statistical significance threshold (0 < alpha < 1, default 0.05).

    Returns:
        ThreatResult dataclass containing statistical parameters and threat decision.
    """
    # 1. Input Validation
    if total_trials <= 0:
        raise ValueError(f"Total trials must be positive, got {total_trials}.")
    if error_count < 0 or error_count > total_trials:
        raise ValueError(f"Error count must be in range [0, {total_trials}], got {error_count}.")
    if not (0.0 <= baseline_error_rate <= 1.0):
        raise ValueError(f"Baseline error rate must be in range [0.0, 1.0], got {baseline_error_rate}.")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"Alpha significance level must be in range (0.0, 1.0), got {alpha}.")

    observed_error_rate = error_count / total_trials

    # 2. Exact Binomial Upper-Tail p-value Calculation with Edge-Case Handling
    if error_count == 0:
        # Observing >= 0 errors under any probability model is certain
        p_value = 1.0
    elif baseline_error_rate == 0.0:
        # If expected baseline error is strictly 0.0, observing any error (k > 0) is impossible under H0
        p_value = 0.0
    elif baseline_error_rate == 1.0:
        # If baseline error is 1.0, observing k <= n errors has p-value 1.0
        p_value = 1.0
    else:
        # Compute exact upper-tail p-value P(K >= k) using scipy.stats.binomtest
        test_res = binomtest(
            k=error_count,
            n=total_trials,
            p=baseline_error_rate,
            alternative="greater",
        )
        p_value = float(test_res.pvalue)

    # 3. Decision Rule
    threat_detected = p_value < alpha

    # 4. Scientific Interpretation Statement
    if threat_detected:
        interpretation = (
            f"THREAT DETECTED: Observed error count ({error_count}/{total_trials}, "
            f"rate {observed_error_rate:.4f}) is statistically inconsistent with the calibrated "
            f"baseline error rate ({baseline_error_rate:.4f}) at significance level alpha={alpha} "
            f"(p-value = {p_value:.6e} < {alpha})."
        )
    else:
        interpretation = (
            f"NORMAL CHANNEL: Observed error count ({error_count}/{total_trials}, "
            f"rate {observed_error_rate:.4f}) is statistically consistent with the calibrated "
            f"baseline error rate ({baseline_error_rate:.4f}) at significance level alpha={alpha} "
            f"(p-value = {p_value:.6f} >= {alpha})."
        )

    return ThreatResult(
        error_count=error_count,
        total_trials=total_trials,
        observed_error_rate=observed_error_rate,
        baseline_error_rate=baseline_error_rate,
        alpha=alpha,
        p_value=p_value,
        threat_detected=threat_detected,
        interpretation=interpretation,
    )
