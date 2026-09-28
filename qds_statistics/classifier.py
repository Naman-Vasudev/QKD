"""
Quantum-Inspired Threat Classification Engine.

PURPOSE:
A single pooled error rate answers only "was there an anomaly?". It cannot answer
"which threat?", because forgery, impersonation, and different-message replay all
produce approximately 50% verification errors.

This module discriminates between threat classes using the BASIS-RESOLVED error
signature (e_Z, e_X, e_Y) together with the error-to-key positional correlation and
classical protocol evidence. Every discriminator below is an analytic consequence of
quantum mechanics applied to this protocol.

ANALYTIC SIGNATURES
-------------------
Let p be the channel tampering probability, rho the 1-bit density of the secret key K,
and h the normalised digest Hamming distance between two messages.

  Threat                     e_Z      e_X      e_Y     K-correlation   Discriminator
  -------------------------  -------  -------  ------  --------------  ----------------------
  No attack                  p0       p0       p0      ~0              all rates at baseline
  Channel tampering (X)      p        ~0       p       ~0              X-BASIS IMMUNITY
  Intercept-resend           1/3      1/3      1/3     ~0              uniform at 1/3
  Digest-only forgery        rho      rho      rho     ~+1             errors track K_i = 1
  Impersonation              1/2      1/2      1/2     ~0              uniform at 1/2
  Replay (different message) h        h        h       ~0              classical digest evidence

WHY X-BASIS IMMUNITY IDENTIFIES CHANNEL TAMPERING:
A Pauli-X error maps |+> -> |+> and |-> -> -|->. Both are X eigenstates, so an X-basis
measurement is invariant up to global phase and records no error. Z and Y eigenstates are
flipped. A bit-flip channel therefore produces the distinctive profile e_X ~ 0 while
e_Z, e_Y ~ p. No other modelled attack spares a single basis.

WHY K-CORRELATION SEPARATES FORGERY FROM IMPERSONATION:
In a digest-only forgery Eve prepares states from d_i while Bob expects d_i XOR K_i. The
two states are orthogonal in the same basis exactly when K_i = 1, producing a
deterministic error at those positions and no error elsewhere. The error indicator is
therefore a perfect copy of K, giving a Matthews correlation near +1. An impersonator
guessing b'_i ~ Bernoulli(0.5) errs independently of K, giving a correlation near 0.

SCIENTIFIC DISCLOSURES:
- Classification is deterministic distance scoring against analytically derived signatures.
  There are no learned parameters, no training data, and no AI/ML of any kind.
- Classification identifies the threat class whose physical signature best matches the
  observed measurement statistics. It does not prove adversarial intent, and environmental
  noise with an unusual basis profile can mimic an attack signature.
- Confidence is the normalised separation between the best and second-best hypothesis. It
  is a discriminability measure, NOT a probability that the classification is correct.
"""

import math
from typing import Any, Dict, List, Optional, Sequence

from core.models import (
    BasisErrorProfile,
    ClassificationHypothesis,
    ThreatClassification,
)


BASES = ("Z", "X", "Y")

THREAT_DISPLAY_NAMES = {
    "NO_ATTACK": "No Attack / Legitimate Channel",
    "CHANNEL_TAMPERING": "Channel Tampering (Pauli-X Bit-Flip)",
    "INTERCEPT_RESEND": "Quantum Interception (Intercept-Resend)",
    "FORGERY": "Signature Forgery (Digest-Only)",
    "IMPERSONATION": "Impersonation (Random State Guessing)",
    "REPLAY_DIFFERENT_MESSAGE": "Replay Attack (Different Message)",
    "REPLAY_SAME_MESSAGE": "Replay Attack (Same Message, Nonce Reuse)",
    "UNAUTHORIZED_VERIFICATION": "Unauthorized Verification Attempt",
}


def matthews_correlation(
    error_flags: Sequence[int],
    key_bits: Sequence[int],
) -> Optional[float]:
    """
    Compute the Matthews correlation coefficient between error occurrence and key bits.

    MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))

    Interpretation in this protocol:
        +1.0  errors occur exactly where K_i = 1  -> digest-only forgery
         0.0  errors are independent of K         -> impersonation, interception, channel noise

    Args:
        error_flags: Per-position error indicators (1 = error, 0 = match).
        key_bits: Per-position secret key bits K_i.

    Returns:
        MCC in [-1, 1], or None if undefined (degenerate marginal, e.g. a constant key
        or zero observed errors).
    """
    if len(error_flags) != len(key_bits) or not error_flags:
        return None

    tp = sum(1 for e, k in zip(error_flags, key_bits) if e == 1 and k == 1)
    tn = sum(1 for e, k in zip(error_flags, key_bits) if e == 0 and k == 0)
    fp = sum(1 for e, k in zip(error_flags, key_bits) if e == 1 and k == 0)
    fn = sum(1 for e, k in zip(error_flags, key_bits) if e == 0 and k == 1)

    denominator_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    if denominator_sq == 0:
        return None

    return (tp * tn - fp * fn) / math.sqrt(denominator_sq)


def build_basis_error_profile(detailed_results: List[Dict[str, Any]]) -> BasisErrorProfile:
    """
    Aggregate per-position experiment results into a basis-resolved error profile.

    Args:
        detailed_results: Per-trial records. Each record must carry a "basis" key and a
            "matched" key. A "key_bit" key enables the error-to-key correlation statistic.

    Returns:
        BasisErrorProfile instance.
    """
    if not detailed_results:
        raise ValueError("Cannot build a basis error profile from an empty result set.")

    counts = {b: 0 for b in BASES}
    errors = {b: 0 for b in BASES}

    error_flags: List[int] = []
    key_bits: List[int] = []

    for record in detailed_results:
        # Bob's verification basis. Some attack modules label it "alice_basis" because it
        # is Alice's legitimate preparation basis; both names refer to the same quantity.
        basis = record.get("basis", record.get("alice_basis"))
        if basis not in counts:
            # Records without a recognised basis label cannot contribute to the profile.
            continue

        is_error = 0 if record.get("matched", False) else 1
        counts[basis] += 1
        errors[basis] += is_error

        if "key_bit" in record:
            error_flags.append(is_error)
            key_bits.append(int(record["key_bit"]))

    total_trials = sum(counts.values())
    if total_trials == 0:
        raise ValueError("No results carried a recognised measurement basis ('Z', 'X', or 'Y').")

    total_errors = sum(errors.values())
    rates = {
        b: (errors[b] / counts[b]) if counts[b] > 0 else 0.0
        for b in BASES
    }
    overall_rate = total_errors / total_trials

    # Uniformity: how evenly the disturbance is spread across the three bases.
    observed_rates = [rates[b] for b in BASES if counts[b] > 0]
    uniformity = max(abs(r - overall_rate) for r in observed_rates) if observed_rates else 0.0

    correlation = matthews_correlation(error_flags, key_bits) if error_flags else None

    return BasisErrorProfile(
        counts=counts,
        errors=errors,
        rates=rates,
        overall_rate=overall_rate,
        total_trials=total_trials,
        total_errors=total_errors,
        key_error_correlation=correlation,
        uniformity=uniformity,
    )


def minimum_trials_for_resolution(
    rate_a: float,
    rate_b: float,
    separation_sigma: float = 3.0,
) -> int:
    """
    Smallest trial count at which two error rates are statistically distinguishable.

    Two hypotheses predicting error rates q_a and q_b cannot be told apart unless their
    difference exceeds the combined sampling noise. Requiring a separation of
    `separation_sigma` pooled standard errors:

        n >= separation_sigma^2 * (q_a(1-q_a) + q_b(1-q_b)) / (q_a - q_b)^2

    The tightest pair in this framework is intercept-resend (1/3) against
    impersonation/forgery (1/2), which needs n ~ 195 at 3 sigma. This is why
    classification is unreliable on small signature subsets and dependable at n = 256.

    Args:
        rate_a: First predicted error rate.
        rate_b: Second predicted error rate.
        separation_sigma: Required separation in pooled standard errors.

    Returns:
        Minimum number of trials, or 0 if the rates are identical (never separable).
    """
    gap = abs(rate_a - rate_b)
    if gap == 0.0:
        return 0
    variance = rate_a * (1.0 - rate_a) + rate_b * (1.0 - rate_b)
    return int(math.ceil((separation_sigma ** 2) * variance / (gap ** 2)))


def _signature_distance(
    observed: Dict[str, float],
    expected: Dict[str, float],
    counts: Dict[str, int],
) -> float:
    """
    Weighted mean absolute distance between observed and expected basis signatures.

    Bases with more trials carry proportionally more weight, so a basis measured only a
    handful of times cannot dominate the verdict.

    Args:
        observed: Observed per-basis error rates.
        expected: Expected per-basis error rates under a hypothesis.
        counts: Trials per basis.

    Returns:
        Weighted mean absolute deviation.
    """
    total = sum(counts[b] for b in BASES if counts.get(b, 0) > 0)
    if total == 0:
        return 1.0

    weighted = sum(
        counts[b] * abs(observed[b] - expected[b])
        for b in BASES
        if counts.get(b, 0) > 0
    )
    return weighted / total


def classify_threat(
    detailed_results: List[Dict[str, Any]],
    baseline_error_rate: float = 0.02,
    key_one_density: Optional[float] = None,
    channel_probability: Optional[float] = None,
    digest_hamming_fraction: Optional[float] = None,
    nonce_replay_detected: bool = False,
    digest_mismatch_detected: bool = False,
    authorization_denied: bool = False,
    accept_threshold: Optional[float] = None,
) -> ThreatClassification:
    """
    Classify the active threat from basis-resolved measurement statistics.

    Classical protocol evidence (nonce replay, verifier authorization) takes precedence
    over statistical inference, because it is deterministic rather than probabilistic:
    a consumed nonce is proof of replay, whereas an elevated error rate is only evidence.

    Args:
        detailed_results: Per-position experiment records (see build_basis_error_profile).
        baseline_error_rate: Calibrated baseline p0 for the no-attack hypothesis.
        key_one_density: 1-bit density of the secret key K, used for the forgery hypothesis.
            Defaults to 0.5 when unknown.
        channel_probability: Known or estimated bit-flip probability p. When omitted, it is
            estimated from the Z and Y basis rates.
        digest_hamming_fraction: Normalised digest Hamming distance, used for the
            different-message replay hypothesis. Defaults to 0.5 when unknown.
        nonce_replay_detected: Classical evidence that a nonce was reused.
        digest_mismatch_detected: Classical evidence that the presented digest did not
            match the message being verified.
        authorization_denied: Classical evidence that verifier authorization failed.
        accept_threshold: Error rate below which the channel counts as clean. Defaults to
            baseline_error_rate + 0.02.

    Returns:
        ThreatClassification instance with hypotheses ranked best-first.
    """
    profile = build_basis_error_profile(detailed_results)

    rho = key_one_density if key_one_density is not None else 0.5
    hamming = digest_hamming_fraction if digest_hamming_fraction is not None else 0.5
    clean_threshold = (
        accept_threshold if accept_threshold is not None else baseline_error_rate + 0.02
    )

    # Estimate the bit-flip probability from the two X-sensitive bases when not supplied.
    if channel_probability is not None:
        p_est = channel_probability
    else:
        sensitive = [profile.rates[b] for b in ("Z", "Y") if profile.counts[b] > 0]
        p_est = (sum(sensitive) / len(sensitive)) if sensitive else profile.overall_rate

    corr = profile.key_error_correlation

    candidates: List[ClassificationHypothesis] = []

    def add(label: str, expected: Dict[str, float], evidence: List[str], penalty: float = 0.0) -> None:
        distance = _signature_distance(profile.rates, expected, profile.counts) + penalty
        candidates.append(
            ClassificationHypothesis(
                label=label,
                display_name=THREAT_DISPLAY_NAMES.get(label, label),
                score=0.0,  # assigned after all distances are known
                distance=distance,
                expected_signature=expected,
                penalty=penalty,
                evidence=evidence,
            )
        )

    # --- Hypothesis: no attack -------------------------------------------------------
    add(
        "NO_ATTACK",
        {b: baseline_error_rate for b in BASES},
        [
            f"All three bases are expected at the calibrated baseline p0 = {baseline_error_rate:.4f}.",
            f"Observed pooled error rate is {profile.overall_rate:.4f}.",
        ],
    )

    # --- Hypothesis: channel tampering (X-basis immunity) ----------------------------
    x_immunity_evidence: List[str] = []
    x_penalty = 0.0
    if profile.counts["X"] > 0:
        sensitive_mean = (
            sum(profile.rates[b] for b in ("Z", "Y") if profile.counts[b] > 0)
            / max(1, sum(1 for b in ("Z", "Y") if profile.counts[b] > 0))
        )
        if profile.rates["X"] <= clean_threshold and sensitive_mean > clean_threshold:
            x_immunity_evidence.append(
                f"X-BASIS IMMUNITY CONFIRMED: e_X = {profile.rates['X']:.4f} is at baseline while "
                f"e_Z, e_Y average {sensitive_mean:.4f}. A Pauli-X error leaves X eigenstates "
                f"invariant, so this profile is unique to a bit-flip channel."
            )
        else:
            x_immunity_evidence.append(
                f"No X-basis immunity: e_X = {profile.rates['X']:.4f} is not at baseline while the "
                f"Z/Y bases average {sensitive_mean:.4f}. A bit-flip channel cannot disturb the "
                f"X basis, so this evidence argues against channel tampering."
            )
            # Absence of the defining signature must count against this hypothesis even
            # when the pooled rates happen to fit.
            x_penalty = 0.15
    add(
        "CHANNEL_TAMPERING",
        {"Z": p_est, "X": baseline_error_rate, "Y": p_est},
        x_immunity_evidence,
        penalty=x_penalty,
    )

    # --- Hypothesis: intercept-resend (uniform at 1/3) -------------------------------
    add(
        "INTERCEPT_RESEND",
        {b: 1.0 / 3.0 for b in BASES},
        [
            "Eve's basis matches Alice's for 1/3 of positions (no disturbance) and mismatches "
            "for 2/3 (50% error), giving a uniform 1/3 error rate across all three bases.",
            f"Observed basis spread (max deviation from pooled rate) is {profile.uniformity:.4f}.",
        ],
    )

    # --- Hypothesis: digest-only forgery (errors track K) ----------------------------
    forgery_evidence: List[str] = []
    forgery_penalty = 0.0
    if corr is not None:
        if corr >= 0.75:
            forgery_evidence.append(
                f"KEY CORRELATION CONFIRMED: Matthews correlation between the error indicator and "
                f"K_i is {corr:+.4f}. Errors land exactly where K_i = 1, which is the deterministic "
                f"signature of a forger who assumed K = 0."
            )
        else:
            forgery_evidence.append(
                f"Key correlation is only {corr:+.4f}; a digest-only forgery would drive this toward "
                f"+1.0. Errors are not tracking the secret key."
            )
            forgery_penalty = 0.15
    else:
        forgery_evidence.append(
            "Key bits were not recorded for this experiment, so the error-to-key correlation "
            "discriminator is unavailable."
        )
        forgery_penalty = 0.05
    forgery_evidence.append(
        f"Expected error rate equals the key 1-bit density rho = {rho:.4f}."
    )
    # A digest mismatch proves the signature was produced for a DIFFERENT message. A forger
    # signs the message under verification, so this evidence rules forgery down.
    if digest_mismatch_detected:
        forgery_penalty += 0.15
        forgery_evidence.append(
            "CLASSICAL EVIDENCE AGAINST: the presented digest belongs to a different "
            "message, but a forger targets the message actually being verified."
        )
    add("FORGERY", {b: rho for b in BASES}, forgery_evidence, penalty=forgery_penalty)

    # --- Hypothesis: impersonation (uniform at 1/2, no K correlation) ----------------
    imp_evidence = [
        "Random Bernoulli(0.5) state guessing errs at 50% independently of the secret key, "
        "uniformly across all three bases.",
    ]
    imp_penalty = 0.0
    if corr is not None:
        if abs(corr) < 0.25:
            imp_evidence.append(
                f"Key correlation {corr:+.4f} is near zero, consistent with guessing that is "
                f"independent of K."
            )
        else:
            imp_evidence.append(
                f"Key correlation {corr:+.4f} is too strong for independent guessing; this argues "
                f"for forgery instead."
            )
            imp_penalty = 0.15
    # Same reasoning as for forgery: an impersonator signs the message under verification,
    # so a digest belonging to another message argues against this hypothesis.
    if digest_mismatch_detected:
        imp_penalty += 0.15
        imp_evidence.append(
            "CLASSICAL EVIDENCE AGAINST: the presented digest belongs to a different "
            "message, which points to a replayed capture rather than fresh guessing."
        )
    add("IMPERSONATION", {b: 0.5 for b in BASES}, imp_evidence, penalty=imp_penalty)

    # --- Hypothesis: different-message replay ----------------------------------------
    replay_evidence = [
        f"A signature captured for another message errs wherever the digests differ; the "
        f"SHA-256 avalanche effect puts this near 50% (observed/assumed h = {hamming:.4f}).",
    ]
    replay_penalty = 0.0
    if digest_mismatch_detected:
        replay_evidence.append(
            "CLASSICAL EVIDENCE: the presented digest does not match the message under "
            "verification, which directly indicates a replayed signature."
        )
    else:
        # Without classical corroboration this hypothesis is statistically
        # indistinguishable from impersonation, so it must not win on statistics alone.
        replay_penalty = 0.08
        replay_evidence.append(
            "No classical digest-mismatch evidence was supplied, so this hypothesis is "
            "statistically indistinguishable from impersonation."
        )
    add("REPLAY_DIFFERENT_MESSAGE", {b: hamming for b in BASES}, replay_evidence, penalty=replay_penalty)

    # --- Score and rank ---------------------------------------------------------------
    # Convert distances to scores in (0, 1]: score = 1 / (1 + distance), then normalise.
    for hypothesis in candidates:
        hypothesis.score = 1.0 / (1.0 + max(0.0, hypothesis.distance))

    score_sum = sum(h.score for h in candidates)
    if score_sum > 0:
        for hypothesis in candidates:
            hypothesis.score = hypothesis.score / score_sum

    candidates.sort(key=lambda h: h.distance)

    classical_evidence: Dict[str, Any] = {
        "nonce_replay_detected": nonce_replay_detected,
        "digest_mismatch_detected": digest_mismatch_detected,
        "authorization_denied": authorization_denied,
        "key_error_correlation": corr,
        "estimated_channel_probability": p_est,
    }

    # --- Classical overrides ----------------------------------------------------------
    # Deterministic protocol evidence outranks statistical inference.
    if authorization_denied:
        top_label = "UNAUTHORIZED_VERIFICATION"
        confidence = 1.0
        interpretation = (
            "UNAUTHORIZED VERIFICATION ATTEMPT: verifier authorization failed. Access control "
            "is a deterministic classical check, so this conclusion does not depend on "
            "measurement statistics."
        )
    elif nonce_replay_detected:
        top_label = "REPLAY_SAME_MESSAGE"
        confidence = 1.0
        interpretation = (
            "REPLAY ATTACK CONFIRMED: the session nonce presented with this signature was already "
            "consumed by this verifier. Nonce reuse is deterministic proof of replay and is "
            "detected regardless of the observed error rate."
        )
    else:
        best = candidates[0]
        runner_up = candidates[1] if len(candidates) > 1 else None
        top_label = best.label

        if runner_up is not None:
            spread = runner_up.distance - best.distance
            # Normalise the separation onto [0, 1]; 0.2 absolute distance is decisive.
            confidence = max(0.0, min(1.0, spread / 0.2))
        else:
            confidence = 1.0

        # Penalise confidence when the sample is too small to separate the top two
        # hypotheses' predicted rates. Without this, an unlucky draw at small n reports a
        # confident answer that the data cannot actually support.
        #
        # This applies ONLY when the two hypotheses are separated by their error rates. If
        # a deterministic discriminator did the separating (X-basis immunity, key
        # correlation, or classical digest/nonce evidence -- all of which register as a
        # penalty difference), then rate resolution is irrelevant and scaling confidence
        # down would understate a structurally certain result.
        resolution_warning = ""
        if runner_up is not None and abs(best.penalty - runner_up.penalty) < 1e-9:
            best_rate = sum(best.expected_signature.values()) / 3.0
            next_rate = sum(runner_up.expected_signature.values()) / 3.0
            required_n = minimum_trials_for_resolution(best_rate, next_rate)
            if required_n > 0 and profile.total_trials < required_n:
                resolution_factor = profile.total_trials / required_n
                confidence *= resolution_factor
                resolution_warning = (
                    f" RESOLUTION WARNING: separating {best.display_name} from "
                    f"{runner_up.display_name} by error rate alone requires about "
                    f"{required_n} trials at 3 sigma, but only {profile.total_trials} were "
                    f"evaluated. Confidence has been scaled by {resolution_factor:.2f}; "
                    f"verify the full 256-position signature before acting on this result."
                )
        elif runner_up is not None:
            discriminators = [
                h.evidence[0]
                for h in (best, runner_up)
                if h.penalty > 0.0 and h.evidence
            ]
            if discriminators:
                resolution_warning = (
                    " Separation rests on a deterministic discriminator rather than on "
                    "error-rate proximity, so it does not depend on sample size."
                )

        if top_label == "NO_ATTACK":
            interpretation = (
                f"NO ATTACK SIGNATURE: the basis-resolved profile "
                f"(e_Z={profile.rates['Z']:.4f}, e_X={profile.rates['X']:.4f}, "
                f"e_Y={profile.rates['Y']:.4f}) is consistent with calibrated baseline noise "
                f"p0 = {baseline_error_rate:.4f}."
                + resolution_warning
            )
        else:
            interpretation = (
                f"THREAT CLASSIFIED AS {THREAT_DISPLAY_NAMES.get(top_label, top_label)}: observed "
                f"profile (e_Z={profile.rates['Z']:.4f}, e_X={profile.rates['X']:.4f}, "
                f"e_Y={profile.rates['Y']:.4f}) best matches this class's analytic signature "
                f"(distance {best.distance:.4f}"
                + (f" vs {runner_up.distance:.4f} for the next hypothesis" if runner_up else "")
                + f"). Discriminability confidence {confidence:.2f}."
                + resolution_warning
            )

    return ThreatClassification(
        profile=profile,
        top_label=top_label,
        top_display_name=THREAT_DISPLAY_NAMES.get(top_label, top_label),
        confidence=confidence,
        hypotheses=candidates,
        classical_evidence=classical_evidence,
        interpretation=interpretation,
    )
