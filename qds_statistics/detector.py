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

DECISION RULES PROVIDED HERE:
1. detect_threat()      - binary anomaly test (is the channel inconsistent with p0?).
2. decide_signature()   - three-way ACCEPT / ABORT / REJECT rule for the verifier.

The three-way rule exists because a single "accept iff zero errors" test is only correct on a
noiseless channel: on any calibrated noisy channel it rejects every legitimate signature. The
two-threshold construction preserves deterministic acceptance under ideal conditions while
tolerating calibrated noise and still rejecting every modelled attack.
"""

import math
from typing import Optional

from scipy.stats import binomtest
from core.models import ThreatResult, DecisionThresholds, SignatureDecision


# Smallest verification error rate produced by any attack modelled in this framework.
# Intercept-resend with uniform basis guessing is the quietest attack at 1/3; forgery,
# impersonation, and different-message replay all sit near 1/2.
MIN_MODELLED_ATTACK_ERROR_RATE = 1.0 / 3.0


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


def compute_decision_thresholds(
    total_trials: int,
    baseline_error_rate: float,
    sigma_multiplier: float = 3.0,
    min_attack_error_rate: float = MIN_MODELLED_ATTACK_ERROR_RATE,
) -> DecisionThresholds:
    """
    Derive the two-threshold (ACCEPT / ABORT / REJECT) decision boundaries.

    Derivation:
        sigma    = sqrt(p0 * (1 - p0) / n)          Binomial standard error under H0
        s_accept = p0 + sigma_multiplier * sigma    Upper edge of calibrated-noise behaviour
        s_reject = (s_accept + q_min) / 2           Midpoint between noise and the quietest attack

    where q_min is the smallest error rate any modelled attack produces (1/3 for
    intercept-resend under uniform basis guessing).

    Properties, stated precisely:
    - An ideal channel produces exactly 0 errors, so 0.0 <= s_accept always holds and
      legitimate signatures are accepted deterministically.
    - Calibrated noise stays below s_accept with probability ~99.7% at 3 sigma.
    - Every attack that attempts to produce a signature without the key -- forgery,
      impersonation, intercept-resend, different-message replay -- yields an error rate
      of at least q_min = 1/3, hence above s_reject, and is always REJECTED.
    - CHANNEL TAMPERING IS A CONTINUUM AND IS NOT ALWAYS REJECTED. A bit-flip channel of
      strength p produces (2/3)p errors, which can land anywhere:
          p = 0.50 -> 0.333  REJECT
          p = 0.10 -> 0.067  ABORT   (statistically anomalous, but unattributable)
          p = 0.01 -> 0.007  ACCEPT  (below the calibrated noise floor)
      This is a property of the physics, not a deficiency of the rule: a disturbance
      weaker than the calibrated noise floor is information-theoretically
      indistinguishable from that noise. Note that such a weak channel attack corrupts a
      few positions without forging anything, so acceptance is the correct action.
    - The ABORT band is the honest "inconclusive" region: evidence is too strong for
      noise and too weak to attribute to a specific attack. Use statistically_anomalous
      on the returned decision, which reflects the more sensitive binomial test, to tell
      an anomalous ABORT from a quiet one.

    Args:
        total_trials: Number of verification trials n (> 0).
        baseline_error_rate: Calibrated baseline error rate p0 in [0, 1].
        sigma_multiplier: Standard errors of slack allowed above p0 (default 3.0).
        min_attack_error_rate: Quietest modelled attack error rate (default 1/3).

    Returns:
        DecisionThresholds instance.
    """
    if total_trials <= 0:
        raise ValueError(f"Total trials must be positive, got {total_trials}.")
    if not (0.0 <= baseline_error_rate <= 1.0):
        raise ValueError(f"Baseline error rate must be in range [0.0, 1.0], got {baseline_error_rate}.")
    if sigma_multiplier < 0.0:
        raise ValueError(f"Sigma multiplier must be non-negative, got {sigma_multiplier}.")
    if not (0.0 < min_attack_error_rate <= 1.0):
        raise ValueError(
            f"Minimum attack error rate must be in range (0.0, 1.0], got {min_attack_error_rate}."
        )

    sigma = math.sqrt(baseline_error_rate * (1.0 - baseline_error_rate) / total_trials)
    s_accept = baseline_error_rate + sigma_multiplier * sigma

    # The accept threshold must stay strictly below the quietest attack, otherwise an
    # attack could be accepted. Clamp it well below q_min if calibration is very noisy.
    ceiling = min_attack_error_rate * 0.5
    if s_accept >= ceiling:
        s_accept = ceiling

    s_reject = (s_accept + min_attack_error_rate) / 2.0

    rationale = (
        f"sigma = sqrt(p0(1-p0)/n) = sqrt({baseline_error_rate:.4f} * "
        f"{1.0 - baseline_error_rate:.4f} / {total_trials}) = {sigma:.6f}; "
        f"s_accept = p0 + {sigma_multiplier:g} * sigma = {s_accept:.4f}; "
        f"s_reject = (s_accept + q_min) / 2 = (({s_accept:.4f}) + {min_attack_error_rate:.4f}) / 2 "
        f"= {s_reject:.4f}, where q_min = {min_attack_error_rate:.4f} is the quietest modelled attack."
    )

    return DecisionThresholds(
        s_accept=s_accept,
        s_reject=s_reject,
        baseline_error_rate=baseline_error_rate,
        total_trials=total_trials,
        sigma=sigma,
        sigma_multiplier=sigma_multiplier,
        min_attack_error_rate=min_attack_error_rate,
        rationale=rationale,
    )


def decide_signature(
    error_count: int,
    total_trials: int,
    baseline_error_rate: float,
    sigma_multiplier: float = 3.0,
    min_attack_error_rate: float = MIN_MODELLED_ATTACK_ERROR_RATE,
    thresholds: Optional[DecisionThresholds] = None,
    alpha: Optional[float] = 0.05,
) -> SignatureDecision:
    """
    Apply the three-way ACCEPT / ABORT / REJECT verification rule.

    Decision Rule:
        error_rate <= s_accept          -> ACCEPT
        s_accept < error_rate < s_reject -> ABORT   (inconclusive; re-run or re-calibrate)
        error_rate >= s_reject          -> REJECT

    The exact binomial test is also evaluated and reported on the result, because it is
    more sensitive than the threshold rule: a weak channel attack can be statistically
    anomalous while still landing in the ABORT band.

    Args:
        error_count: Observed verification errors k.
        total_trials: Total verification trials n (> 0).
        baseline_error_rate: Calibrated baseline error rate p0.
        sigma_multiplier: Standard errors of slack above p0 for ACCEPT.
        min_attack_error_rate: Quietest key-independent attack error rate.
        thresholds: Optional pre-computed DecisionThresholds. Derived when omitted.
        alpha: Significance level for the accompanying binomial test. Pass None to skip it.

    Returns:
        SignatureDecision instance.
    """
    if total_trials <= 0:
        raise ValueError(f"Total trials must be positive, got {total_trials}.")
    if error_count < 0 or error_count > total_trials:
        raise ValueError(f"Error count must be in range [0, {total_trials}], got {error_count}.")

    if thresholds is None:
        thresholds = compute_decision_thresholds(
            total_trials=total_trials,
            baseline_error_rate=baseline_error_rate,
            sigma_multiplier=sigma_multiplier,
            min_attack_error_rate=min_attack_error_rate,
        )

    observed_error_rate = error_count / total_trials
    deterministic_accept = error_count == 0

    statistically_anomalous: Optional[bool] = None
    p_value: Optional[float] = None
    if alpha is not None:
        threat = detect_threat(
            error_count=error_count,
            total_trials=total_trials,
            baseline_error_rate=thresholds.baseline_error_rate,
            alpha=alpha,
        )
        statistically_anomalous = threat.threat_detected
        p_value = threat.p_value

    if observed_error_rate <= thresholds.s_accept:
        verdict = "ACCEPT"
        if deterministic_accept:
            justification = (
                f"ACCEPT (deterministic): {error_count}/{total_trials} errors. An ideal channel "
                f"yields exact eigenvalue agreement at every position, so the signature is accepted "
                f"with certainty."
            )
        else:
            justification = (
                f"ACCEPT: observed error rate {observed_error_rate:.4f} is within the calibrated "
                f"noise envelope s_accept = {thresholds.s_accept:.4f} "
                f"(p0 = {thresholds.baseline_error_rate:.4f}, {thresholds.sigma_multiplier:g} sigma)."
            )
    elif observed_error_rate >= thresholds.s_reject:
        verdict = "REJECT"
        justification = (
            f"REJECT: observed error rate {observed_error_rate:.4f} meets or exceeds "
            f"s_reject = {thresholds.s_reject:.4f}. This is incompatible with calibrated channel "
            f"noise (p0 = {thresholds.baseline_error_rate:.4f}) and consistent with an active attack."
        )
    else:
        verdict = "ABORT"
        justification = (
            f"ABORT (inconclusive): observed error rate {observed_error_rate:.4f} falls in the "
            f"indeterminate band ({thresholds.s_accept:.4f}, {thresholds.s_reject:.4f}). Errors "
            f"exceed the calibrated noise envelope but are too few to attribute to a modelled "
            f"attack. The signature is NOT accepted."
        )
        if statistically_anomalous:
            justification += (
                f" The exact binomial test does reject H0 (p-value = {p_value:.3e} < {alpha}), "
                f"so a real disturbance is present -- consistent with weak channel tampering, "
                f"which produces (2/3)p errors and can sit in this band. Re-run with more shots "
                f"to tighten the estimate."
            )
        elif statistically_anomalous is False:
            justification += (
                f" The binomial test does not reject H0 (p-value = {p_value:.4f} >= {alpha}), so "
                f"this is most likely an unlucky noise draw rather than an attack."
            )

    return SignatureDecision(
        verdict=verdict,
        error_count=error_count,
        total_trials=total_trials,
        observed_error_rate=observed_error_rate,
        thresholds=thresholds,
        deterministic_accept=deterministic_accept,
        statistically_anomalous=statistically_anomalous,
        p_value=p_value,
        justification=justification,
    )
