"""
Transferable Quantum Digital Signatures: Non-Repudiation and Forwarding.

WHAT THIS ADDS:
The base protocol is a two-party authentication scheme. Alice and Bob share the key K, so
Bob could have produced any signature Alice could. That gives authenticity and integrity
but NOT non-repudiation: Bob cannot prove to Charlie that Alice signed, and Alice can
deny having signed. A scheme without transferability is a quantum MAC, not a signature.

This module implements the Gottesman-Chuang construction that closes the gap.

THE CONSTRUCTION
----------------
1. QUANTUM PUBLIC KEY DISTRIBUTION.
   Alice sends every recipient the full set of signature states. Each recipient can only
   measure a SUBSET of them, because measurement destroys a state and the no-cloning
   theorem forbids keeping a spare copy to check later. Each recipient therefore ends up
   knowing the key bits at a random subset of positions.

2. THE ASYMMETRY THAT MAKES IT WORK.
   Which positions a recipient measured is private to that recipient, and in particular
   is UNKNOWN TO ALICE. Alice cannot aim a corruption at Bob's positions while sparing
   Charlie's, because she cannot see either subset.

3. TWO THRESHOLDS.
   A single threshold cannot support forwarding: two recipients checking different random
   subsets see slightly different error rates, so a signature near the boundary could pass
   for one and fail for the other. Two thresholds separated by a margin absorb this:

       s_direct  <  s_forwarded

   - Bob accepts directly if his error rate <= s_direct.
   - Charlie accepts a forwarded signature if his error rate <= s_forwarded.

   TRANSFERABILITY: anything Bob accepts sits at <= s_direct, and Charlie's independent
   estimate of the same underlying corruption rate is very unlikely to exceed
   s_forwarded, so Charlie accepts too.

   NON-REPUDIATION: to repudiate, Alice must land Bob below s_direct AND Charlie above
   s_forwarded simultaneously. Since both subsets sample the same corrupted positions,
   their error counts are hypergeometric with the SAME mean. Splitting them requires a
   large fluctuation in opposite directions at once, whose probability decays
   exponentially in the subset size.

SCIENTIFIC DISCLOSURES:
- The subset each recipient measures is modelled as a uniformly random choice made by
  that recipient and hidden from the signer. This is the classical shadow of the physical
  process (measure-and-destroy under no-cloning); the verification of each retained
  position remains a genuine quantum teleportation and projective measurement.
- Repudiation probabilities are exact hypergeometric evaluations, and are corroborated by
  optional Monte-Carlo simulation.
- The security statement covers an individually-corrupting signer within this threat
  model. It is not a general proof against arbitrary quantum cheating strategies.
- No artificial intelligence or machine learning is used.
"""

import math
import random
from typing import Dict, List, Optional, Sequence, Tuple

from scipy.stats import hypergeom

from core.backend import QuantumBackendAdapter
from core.models import (
    RecipientShare,
    RepudiationResult,
    SessionContext,
    TransferThresholds,
    TransferVerdict,
    TransferabilityResult,
)
from core.seeding import ShotSeeder
from .encoding import encode_message
from .teleportation import teleport_and_measure


DEFAULT_SUBSET_FRACTION = 0.5
SIGNATURE_LENGTH = 256


def allocate_recipient_subsets(
    recipient_ids: Sequence[str],
    signature_length: int = SIGNATURE_LENGTH,
    subset_fraction: float = DEFAULT_SUBSET_FRACTION,
    rng: Optional[random.Random] = None,
) -> Dict[str, RecipientShare]:
    """
    Assign each recipient the random subset of positions they measured.

    The subsets are chosen independently per recipient and are private to them. The signer
    never sees them, which is the property non-repudiation rests on.

    Args:
        recipient_ids: Identities of the recipients.
        signature_length: Signature length n (> 0).
        subset_fraction: Fraction of positions each recipient measures, in (0, 1].
        rng: Optional random.Random for reproducibility.

    Returns:
        Dict mapping recipient id to their RecipientShare.
    """
    if signature_length <= 0:
        raise ValueError(f"Signature length must be positive, got {signature_length}.")
    if not (0.0 < subset_fraction <= 1.0):
        raise ValueError(f"Subset fraction must be in range (0.0, 1.0], got {subset_fraction}.")
    if not recipient_ids:
        raise ValueError("At least one recipient identity is required.")

    generator = rng if rng is not None else random.Random()
    subset_size = max(1, int(round(subset_fraction * signature_length)))

    shares: Dict[str, RecipientShare] = {}
    for recipient_id in recipient_ids:
        positions = sorted(generator.sample(range(signature_length), subset_size))
        shares[recipient_id] = RecipientShare(
            recipient_id=recipient_id,
            measured_positions=positions,
            subset_fraction=subset_size / signature_length,
            signature_length=signature_length,
        )
    return shares


def compute_transfer_thresholds(
    subset_size: int,
    baseline_error_rate: float = 0.02,
    direct_sigma: float = 3.0,
    margin_sigma: float = 6.0,
) -> TransferThresholds:
    """
    Derive the direct and forwarded acceptance thresholds.

    Derivation:
        sigma       = sqrt(p0 (1 - p0) / m)          m = subset size
        s_direct    = p0 + direct_sigma * sigma
        s_forwarded = s_direct + margin_sigma * sigma

    The margin is what a forwarded verdict can absorb. It must exceed the typical
    disagreement between two independent subsets sampling the same corruption, which is
    of order sigma, while remaining below the error rate of any real attack so that a
    forged signature is still rejected downstream.

    Args:
        subset_size: Positions each recipient verifies (> 0).
        baseline_error_rate: Calibrated baseline p0.
        direct_sigma: Standard errors of slack above p0 for direct acceptance.
        margin_sigma: Standard errors of separation between the two thresholds.

    Returns:
        TransferThresholds instance.
    """
    if subset_size <= 0:
        raise ValueError(f"Subset size must be positive, got {subset_size}.")
    if not (0.0 <= baseline_error_rate <= 1.0):
        raise ValueError(f"Baseline error rate must be in range [0.0, 1.0], got {baseline_error_rate}.")
    if direct_sigma < 0.0 or margin_sigma <= 0.0:
        raise ValueError("direct_sigma must be non-negative and margin_sigma positive.")

    sigma = math.sqrt(baseline_error_rate * (1.0 - baseline_error_rate) / subset_size)
    # A zero baseline gives sigma = 0, which would collapse both thresholds onto p0 and
    # leave no fluctuation budget. Fall back to a one-position margin.
    if sigma == 0.0:
        sigma = 1.0 / (2.0 * subset_size)

    s_direct = baseline_error_rate + direct_sigma * sigma
    s_forwarded = s_direct + margin_sigma * sigma

    # Both thresholds must stay below the quietest key-independent attack (1/3), otherwise
    # a forged signature could be accepted downstream.
    ceiling = 1.0 / 3.0
    if s_forwarded >= ceiling:
        s_forwarded = ceiling * 0.9
        s_direct = min(s_direct, s_forwarded * 0.5)

    return TransferThresholds(
        s_direct=s_direct,
        s_forwarded=s_forwarded,
        margin=s_forwarded - s_direct,
        subset_size=subset_size,
        baseline_error_rate=baseline_error_rate,
        rationale=(
            f"sigma = sqrt(p0(1-p0)/m) = sqrt({baseline_error_rate:.4f} * "
            f"{1.0 - baseline_error_rate:.4f} / {subset_size}) = {sigma:.6f}; "
            f"s_direct = p0 + {direct_sigma:g} sigma = {s_direct:.4f}; "
            f"s_forwarded = s_direct + {margin_sigma:g} sigma = {s_forwarded:.4f}; "
            f"margin = {s_forwarded - s_direct:.4f}."
        ),
    )


def verify_as_recipient(
    message: str,
    shared_key: List[int],
    share: RecipientShare,
    thresholds: TransferThresholds,
    role: str = "DIRECT",
    corrupted_positions: Optional[Sequence[int]] = None,
    session: Optional[SessionContext] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> TransferVerdict:
    """
    Verify a signature using only the positions this recipient actually measured.

    Args:
        message: Classical message being verified.
        shared_key: Secret key K (256 bits).
        share: This recipient's RecipientShare.
        thresholds: TransferThresholds in force.
        role: "DIRECT" for the original recipient, "FORWARDED" for a third party.
        corrupted_positions: Positions the signer deliberately corrupted, used to model a
            repudiation attempt. Corrupted positions carry the opposite encoded bit.
        session: Optional SessionContext bound into the digest.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.

    Returns:
        TransferVerdict instance.
    """
    if role not in ("DIRECT", "FORWARDED"):
        raise ValueError(f"Invalid role: {role}. Must be 'DIRECT' or 'FORWARDED'.")
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    expected_qubits = encode_message(message, shared_key, session=session)
    corrupted = set(corrupted_positions or ())
    seeder = ShotSeeder(seed)

    errors = 0
    for position in share.measured_positions:
        expected = expected_qubits[position]

        if position in corrupted:
            # A corrupted position carries the opposite encoded bit, so the signer
            # transmits the orthogonal state in the same basis.
            flipped_key = list(shared_key)
            flipped_key[position] ^= 1
            transmitted = encode_message(message, flipped_key, session=session)[position]
        else:
            transmitted = expected

        result = teleport_and_measure(
            state_label=transmitted.state_label,
            basis=expected.basis,
            expected_eigenvalue=expected.expected_eigenvalue,
            backend=backend,
            seed_simulator=seeder.next(),
        )
        if not result.matched:
            errors += 1

    checked = len(share.measured_positions)
    error_rate = errors / checked if checked else 0.0
    threshold = thresholds.s_direct if role == "DIRECT" else thresholds.s_forwarded
    accepted = error_rate <= threshold

    justification = (
        f"{'ACCEPTED' if accepted else 'REJECTED'} by '{share.recipient_id}' acting as "
        f"{role.lower()} recipient: {errors}/{checked} errors (rate {error_rate:.4f}) "
        f"against threshold {threshold:.4f}."
    )

    return TransferVerdict(
        recipient_id=share.recipient_id,
        role=role,
        positions_checked=checked,
        errors=errors,
        error_rate=error_rate,
        threshold=threshold,
        accepted=accepted,
        justification=justification,
    )


def run_transferability_test(
    message: str,
    shared_key: List[int],
    direct_recipient: str = "bob",
    third_party: str = "charlie",
    subset_fraction: float = DEFAULT_SUBSET_FRACTION,
    corruption_fraction: float = 0.0,
    baseline_error_rate: float = 0.02,
    session: Optional[SessionContext] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> TransferabilityResult:
    """
    Sign, verify at the direct recipient, forward, and verify at a third party.

    Args:
        message: Classical message to sign.
        shared_key: Secret key K (256 bits).
        direct_recipient: Identity of the recipient who verifies first.
        third_party: Identity of the party the signature is forwarded to.
        subset_fraction: Fraction of positions each recipient measured.
        corruption_fraction: Fraction of positions the signer deliberately corrupted.
            Zero models an honest signer.
        baseline_error_rate: Calibrated baseline p0.
        session: Optional SessionContext bound into the digest.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.

    Returns:
        TransferabilityResult instance.
    """
    if not (0.0 <= corruption_fraction <= 1.0):
        raise ValueError(
            f"Corruption fraction must be in range [0.0, 1.0], got {corruption_fraction}."
        )

    rng = random.Random(seed)
    shares = allocate_recipient_subsets(
        recipient_ids=[direct_recipient, third_party],
        signature_length=256,
        subset_fraction=subset_fraction,
        rng=rng,
    )
    thresholds = compute_transfer_thresholds(
        subset_size=shares[direct_recipient].measured_positions.__len__(),
        baseline_error_rate=baseline_error_rate,
    )

    num_corrupted = int(round(corruption_fraction * 256))
    corrupted_positions = rng.sample(range(256), num_corrupted) if num_corrupted else []

    direct_verdict = verify_as_recipient(
        message=message,
        shared_key=shared_key,
        share=shares[direct_recipient],
        thresholds=thresholds,
        role="DIRECT",
        corrupted_positions=corrupted_positions,
        session=session,
        backend=backend,
        seed=seed,
    )
    forwarded_verdict = verify_as_recipient(
        message=message,
        shared_key=shared_key,
        share=shares[third_party],
        thresholds=thresholds,
        role="FORWARDED",
        corrupted_positions=corrupted_positions,
        session=session,
        backend=backend,
        seed=(seed + 9871) if seed is not None else None,
    )

    # Transferability fails only when the direct recipient accepts and the third party
    # then refuses to honour that acceptance.
    transferable = not (direct_verdict.accepted and not forwarded_verdict.accepted)
    consistent = direct_verdict.accepted == forwarded_verdict.accepted

    if transferable and direct_verdict.accepted:
        interpretation = (
            f"TRANSFERABLE: '{direct_recipient}' accepted at {direct_verdict.error_rate:.4f} "
            f"(<= {thresholds.s_direct:.4f}) and '{third_party}' independently honoured it at "
            f"{forwarded_verdict.error_rate:.4f} (<= {thresholds.s_forwarded:.4f}), checking a "
            f"different random subset of positions. The signature carries downstream."
        )
    elif transferable:
        interpretation = (
            f"CONSISTENTLY REJECTED: neither '{direct_recipient}' "
            f"({direct_verdict.error_rate:.4f}) nor '{third_party}' "
            f"({forwarded_verdict.error_rate:.4f}) accepted. Transferability is not "
            f"violated, since nothing was accepted to transfer."
        )
    else:
        interpretation = (
            f"TRANSFERABILITY VIOLATED: '{direct_recipient}' accepted at "
            f"{direct_verdict.error_rate:.4f} but '{third_party}' rejected at "
            f"{forwarded_verdict.error_rate:.4f}. The signer could disown this signature. "
            f"The threshold margin ({thresholds.margin:.4f}) was insufficient for the "
            f"corruption level applied."
        )

    return TransferabilityResult(
        message=message,
        direct_verdict=direct_verdict,
        forwarded_verdict=forwarded_verdict,
        transferable=transferable,
        consistent=consistent,
        thresholds=thresholds,
        interpretation=interpretation,
    )


def repudiation_success_probability(
    signature_length: int,
    subset_size: int,
    corruption_fraction: float,
    thresholds: TransferThresholds,
) -> float:
    """
    Exact probability that a repudiating signer splits the two recipients' verdicts.

    The signer corrupts c*n positions. Each recipient measures m positions drawn uniformly
    without replacement, so the number of corrupted positions each one sees follows a
    hypergeometric distribution with population n, successes c*n, and draws m. The subsets
    are drawn independently, so:

        P(split) = P(Bob's errors <= s_direct * m) * P(Charlie's errors > s_forwarded * m)

    Both factors come from the SAME distribution, so making one small forces the other to
    be small too. That tension is what makes repudiation hard.

    Args:
        signature_length: Signature length n.
        subset_size: Positions each recipient verifies m.
        corruption_fraction: Fraction of positions corrupted by the signer.
        thresholds: TransferThresholds in force.

    Returns:
        Probability of a successful repudiation split.
    """
    if signature_length <= 0 or subset_size <= 0:
        raise ValueError("Signature length and subset size must be positive.")
    if subset_size > signature_length:
        raise ValueError("Subset size cannot exceed signature length.")
    if not (0.0 <= corruption_fraction <= 1.0):
        raise ValueError(
            f"Corruption fraction must be in range [0.0, 1.0], got {corruption_fraction}."
        )

    num_corrupted = int(round(corruption_fraction * signature_length))
    if num_corrupted == 0:
        return 0.0

    direct_allowance = int(math.floor(thresholds.s_direct * subset_size))
    forwarded_allowance = int(math.floor(thresholds.s_forwarded * subset_size))

    # P(Bob sees at most his allowance of corrupted positions)
    p_direct_accepts = float(
        hypergeom.cdf(direct_allowance, signature_length, num_corrupted, subset_size)
    )
    # P(Charlie sees more than his allowance)
    p_forwarded_rejects = float(
        hypergeom.sf(forwarded_allowance, signature_length, num_corrupted, subset_size)
    )

    return max(0.0, min(1.0, p_direct_accepts * p_forwarded_rejects))


def analyze_repudiation(
    signature_length: int = 256,
    subset_fraction: float = DEFAULT_SUBSET_FRACTION,
    baseline_error_rate: float = 0.02,
    corruption_fraction: Optional[float] = None,
    trials: int = 0,
    seed: Optional[int] = None,
) -> RepudiationResult:
    """
    Evaluate a repudiation attempt, optionally corroborating the analytic bound by simulation.

    When no corruption level is supplied, the worst case over a fine grid is reported --
    the signer's best possible strategy rather than an arbitrary one.

    Args:
        signature_length: Signature length n.
        subset_fraction: Fraction of positions each recipient measures.
        baseline_error_rate: Calibrated baseline p0.
        corruption_fraction: Fraction of positions to corrupt. None selects the worst case.
        trials: Monte-Carlo trials for corroboration. Zero skips simulation.
        seed: Optional random seed for the simulation.

    Returns:
        RepudiationResult instance.
    """
    subset_size = max(1, int(round(subset_fraction * signature_length)))
    thresholds = compute_transfer_thresholds(
        subset_size=subset_size, baseline_error_rate=baseline_error_rate
    )

    if corruption_fraction is None:
        # Search the signer's best corruption level rather than assuming one.
        candidates = [i / 200.0 for i in range(1, 201)]
        best_fraction, best_probability = 0.0, 0.0
        for candidate in candidates:
            probability = repudiation_success_probability(
                signature_length, subset_size, candidate, thresholds
            )
            if probability > best_probability:
                best_fraction, best_probability = candidate, probability
        corruption_fraction, analytic = best_fraction, best_probability
    else:
        analytic = repudiation_success_probability(
            signature_length, subset_size, corruption_fraction, thresholds
        )

    observed_successes = 0
    if trials > 0:
        rng = random.Random(seed)
        num_corrupted = int(round(corruption_fraction * signature_length))
        direct_allowance = thresholds.s_direct * subset_size
        forwarded_allowance = thresholds.s_forwarded * subset_size

        for _ in range(trials):
            corrupted = set(rng.sample(range(signature_length), num_corrupted))
            bob = rng.sample(range(signature_length), subset_size)
            charlie = rng.sample(range(signature_length), subset_size)
            bob_errors = sum(1 for p in bob if p in corrupted)
            charlie_errors = sum(1 for p in charlie if p in corrupted)
            if bob_errors <= direct_allowance and charlie_errors > forwarded_allowance:
                observed_successes += 1

    if analytic <= 0.0:
        security_bits = math.inf
    elif analytic >= 1.0:
        security_bits = 0.0
    else:
        security_bits = -math.log2(analytic)

    interpretation = (
        f"Best-case repudiation for a signer corrupting {corruption_fraction:.1%} of "
        f"positions succeeds with probability {analytic:.4e} "
        f"({'infinite' if math.isinf(security_bits) else f'{security_bits:.1f}'} bits). "
        f"The signer must simultaneously land below {thresholds.s_direct:.4f} for the "
        f"direct recipient and above {thresholds.s_forwarded:.4f} for the third party, "
        f"while both subsets sample the same corrupted positions and therefore share the "
        f"same mean. Splitting them requires a large fluctuation in opposite directions "
        f"at once."
    )

    return RepudiationResult(
        corruption_fraction=corruption_fraction,
        signature_length=signature_length,
        subset_size=subset_size,
        analytic_success_probability=analytic,
        trials=trials,
        observed_successes=observed_successes,
        observed_success_rate=(observed_successes / trials) if trials > 0 else 0.0,
        security_bits=security_bits,
        interpretation=interpretation,
    )


def repudiation_curve(
    signature_length: int = 256,
    subset_fraction: float = DEFAULT_SUBSET_FRACTION,
    baseline_error_rate: float = 0.02,
    corruption_levels: Optional[List[float]] = None,
) -> List[Tuple[float, float]]:
    """
    Evaluate repudiation success probability across corruption levels.

    Args:
        signature_length: Signature length n.
        subset_fraction: Fraction of positions each recipient measures.
        baseline_error_rate: Calibrated baseline p0.
        corruption_levels: Corruption fractions to evaluate.

    Returns:
        List of (corruption_fraction, success_probability) pairs.
    """
    if corruption_levels is None:
        corruption_levels = [i / 50.0 for i in range(1, 26)]

    subset_size = max(1, int(round(subset_fraction * signature_length)))
    thresholds = compute_transfer_thresholds(
        subset_size=subset_size, baseline_error_rate=baseline_error_rate
    )
    return [
        (
            level,
            repudiation_success_probability(
                signature_length, subset_size, level, thresholds
            ),
        )
        for level in corruption_levels
    ]
