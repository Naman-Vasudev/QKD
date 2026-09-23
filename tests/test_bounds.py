"""
Unit Test Suite for Forgery Probability Bounds, Detection Power, and Decision Thresholds.

All expected values here are independently derived closed-form binomial quantities, so the
tests check the mathematics rather than merely re-running the implementation.
"""

import math
import unittest
from fractions import Fraction

from qds_statistics.bounds import (
    ATTACK_ERROR_RATES,
    attack_detection_summary,
    critical_error_count,
    detection_power,
    detection_power_curve,
    forgery_bound_curve,
    forgery_success_probability,
    key_success_probability,
)
from qds_statistics.detector import (
    MIN_MODELLED_ATTACK_ERROR_RATE,
    compute_decision_thresholds,
    decide_signature,
)


def exact_binomial_tail_le(n, t):
    """Exact P(Binomial(n, 1/2) <= t) as a Fraction, computed independently."""
    total = sum(math.comb(n, j) for j in range(0, t + 1))
    return Fraction(total, 2 ** n)


class TestForgeryBounds(unittest.TestCase):

    def test_1_matches_independent_exact_computation(self) -> None:
        # n = 32, s_a = 0.10 -> t = floor(3.2) = 3
        bound = forgery_success_probability(32, 0.10)
        self.assertEqual(bound.max_tolerated_errors, 3)
        expected = float(exact_binomial_tail_le(32, 3))
        self.assertAlmostEqual(bound.forgery_probability, expected, places=15)
        self.assertAlmostEqual(bound.security_bits, -math.log2(expected), places=9)

    def test_2_zero_tolerance_is_two_to_the_minus_n(self) -> None:
        # With s_a = 0 the forger must match every position: P = 2^-n.
        bound = forgery_success_probability(20, 0.0)
        self.assertEqual(bound.max_tolerated_errors, 0)
        self.assertAlmostEqual(bound.forgery_probability, 2.0 ** -20, places=15)
        self.assertAlmostEqual(bound.security_bits, 20.0, places=9)

    def test_3_decays_exponentially_in_n(self) -> None:
        curve = forgery_bound_curve([16, 32, 64, 128, 256], acceptance_threshold=0.05)
        probs = [c.forgery_probability for c in curve]
        # Strictly decreasing.
        for earlier, later in zip(probs, probs[1:]):
            self.assertLess(later, earlier)
        # Security in bits must grow at least linearly.
        bits = [c.security_bits for c in curve]
        for earlier, later in zip(bits, bits[1:]):
            self.assertGreater(later, earlier)

    def test_4_full_signature_is_strongly_secure(self) -> None:
        bound = forgery_success_probability(256, 0.046)
        self.assertLess(bound.forgery_probability, 1e-40)
        self.assertGreater(bound.security_bits, 150.0)

    def test_5_acceptance_of_everything_gives_no_security(self) -> None:
        bound = forgery_success_probability(64, 1.0)
        self.assertAlmostEqual(bound.forgery_probability, 1.0, places=12)
        self.assertAlmostEqual(bound.security_bits, 0.0, places=12)

    def test_6_key_density_controls_forger_advantage(self) -> None:
        # A digest-only forger succeeds where K_i == 0, so a degenerate key is fatal.
        self.assertAlmostEqual(key_success_probability(0.0), 1.0, places=12)
        self.assertAlmostEqual(key_success_probability(0.5), 0.5, places=12)
        self.assertAlmostEqual(key_success_probability(1.0), 0.0, places=12)

        weak = forgery_success_probability(256, 0.05, per_position_success=0.95)
        strong = forgery_success_probability(256, 0.05, per_position_success=0.5)
        self.assertGreater(weak.forgery_probability, strong.forgery_probability)

    def test_7_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            forgery_success_probability(0, 0.05)
        with self.assertRaises(ValueError):
            forgery_success_probability(256, 1.5)
        with self.assertRaises(ValueError):
            forgery_success_probability(256, 0.05, per_position_success=-0.1)
        with self.assertRaises(ValueError):
            key_success_probability(1.5)


class TestDetectionPower(unittest.TestCase):

    def test_1_critical_count_is_the_smallest_significant_value(self) -> None:
        from scipy.stats import binom
        n, p0, alpha = 256, 0.02, 0.05
        k_star = critical_error_count(n, p0, alpha)
        # k* itself must be significant, and k*-1 must not be.
        self.assertLess(float(binom.sf(k_star - 1, n, p0)), alpha)
        self.assertGreaterEqual(float(binom.sf(k_star - 2, n, p0)), alpha)

    def test_2_zero_baseline_flags_any_error(self) -> None:
        self.assertEqual(critical_error_count(256, 0.0, 0.05), 1)

    def test_3_power_is_near_certain_against_modelled_attacks(self) -> None:
        for name, rate in ATTACK_ERROR_RATES.items():
            power = detection_power(256, 0.02, rate, 0.05)
            self.assertGreater(
                power.detection_probability, 0.95,
                msg=f"Detection power too low for {name}",
            )

    def test_4_false_positive_rate_respects_alpha(self) -> None:
        power = detection_power(256, 0.02, 1.0 / 3.0, 0.05)
        self.assertLess(power.false_positive_rate, 0.05)

    def test_5_power_grows_with_signature_length(self) -> None:
        curve = detection_power_curve([8, 16, 32, 64, 128, 256], 0.02, 1.0 / 3.0, 0.05)
        powers = [c.detection_probability for c in curve]
        self.assertLess(powers[0], powers[-1])
        self.assertGreater(powers[-1], 0.99)

    def test_6_no_power_against_baseline_itself(self) -> None:
        # An "attack" that produces exactly baseline noise is by construction undetectable.
        power = detection_power(256, 0.02, 0.02, 0.05)
        self.assertLess(power.detection_probability, 0.05)

    def test_7_summary_table_shape(self) -> None:
        summary = attack_detection_summary(256, 0.02, 0.05)
        self.assertEqual(len(summary), len(ATTACK_ERROR_RATES))
        for row in summary:
            self.assertIn("attack", row)
            self.assertIn("detection_probability", row)
            self.assertGreaterEqual(row["detection_probability"], 0.0)
            self.assertLessEqual(row["detection_probability"], 1.0)

    def test_8_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            critical_error_count(0, 0.02, 0.05)
        with self.assertRaises(ValueError):
            critical_error_count(256, 0.02, 1.5)
        with self.assertRaises(ValueError):
            detection_power(256, 0.02, 1.5, 0.05)


class TestDecisionThresholds(unittest.TestCase):

    def test_1_thresholds_are_ordered(self) -> None:
        th = compute_decision_thresholds(256, 0.02)
        self.assertLess(th.s_accept, th.s_reject)
        self.assertLess(th.s_reject, MIN_MODELLED_ATTACK_ERROR_RATE)

    def test_2_sigma_derivation_is_correct(self) -> None:
        th = compute_decision_thresholds(256, 0.02, sigma_multiplier=3.0)
        expected_sigma = math.sqrt(0.02 * 0.98 / 256)
        self.assertAlmostEqual(th.sigma, expected_sigma, places=12)
        self.assertAlmostEqual(th.s_accept, 0.02 + 3.0 * expected_sigma, places=12)

    def test_3_ideal_channel_accepts_deterministically(self) -> None:
        decision = decide_signature(0, 256, 0.0)
        self.assertEqual(decision.verdict, "ACCEPT")
        self.assertTrue(decision.deterministic_accept)
        self.assertIn("deterministic", decision.justification)

    def test_4_noisy_legitimate_signature_still_accepts(self) -> None:
        # This is the case the original `accepted = error_rate == 0.0` rule got wrong.
        decision = decide_signature(5, 256, 0.02)
        self.assertEqual(decision.verdict, "ACCEPT")
        self.assertFalse(decision.deterministic_accept)

    def test_5_no_modelled_attack_is_ever_accepted(self) -> None:
        # The security-critical invariant: no attack may be ACCEPTED. Channel tampering is
        # a continuum, so a weak instance legitimately lands in ABORT rather than REJECT.
        for name, rate in ATTACK_ERROR_RATES.items():
            errors = int(round(rate * 256))
            decision = decide_signature(errors, 256, 0.02)
            self.assertNotEqual(
                decision.verdict, "ACCEPT",
                msg=f"{name} at rate {rate} must never be accepted",
            )

    def test_5b_key_independent_attacks_are_rejected(self) -> None:
        # Every attack that forges a signature without the key sits at or above 1/3.
        for name, rate in ATTACK_ERROR_RATES.items():
            if rate < MIN_MODELLED_ATTACK_ERROR_RATE - 1e-9:
                continue
            errors = int(round(rate * 256))
            decision = decide_signature(errors, 256, 0.02)
            self.assertEqual(
                decision.verdict, "REJECT",
                msg=f"{name} at rate {rate} should be rejected, got {decision.verdict}",
            )

    def test_5c_weak_channel_tampering_aborts_but_is_flagged(self) -> None:
        # p = 0.10 -> (2/3)(0.10) = 6.67% errors: inside the ABORT band, yet the binomial
        # test is sensitive enough to register the disturbance.
        errors = int(round((2.0 / 3.0) * 0.10 * 256))
        decision = decide_signature(errors, 256, 0.02, alpha=0.05)
        self.assertEqual(decision.verdict, "ABORT")
        self.assertTrue(decision.statistically_anomalous)
        self.assertLess(decision.p_value, 0.05)

    def test_5d_very_weak_channel_tampering_is_below_the_noise_floor(self) -> None:
        # p = 0.01 -> 0.67% errors, beneath a 2% calibrated noise floor. No detector can
        # separate this from noise; acceptance is the information-theoretically correct
        # outcome, and such an attack forges nothing.
        errors = int(round((2.0 / 3.0) * 0.01 * 256))
        decision = decide_signature(errors, 256, 0.02, alpha=0.05)
        self.assertEqual(decision.verdict, "ACCEPT")
        self.assertFalse(decision.statistically_anomalous)

    def test_5e_binomial_verdict_is_reported(self) -> None:
        clean = decide_signature(0, 256, 0.02, alpha=0.05)
        self.assertFalse(clean.statistically_anomalous)
        self.assertIsNotNone(clean.p_value)

        attacked = decide_signature(128, 256, 0.02, alpha=0.05)
        self.assertTrue(attacked.statistically_anomalous)

        skipped = decide_signature(0, 256, 0.02, alpha=None)
        self.assertIsNone(skipped.statistically_anomalous)
        self.assertIsNone(skipped.p_value)

    def test_6_intermediate_band_aborts(self) -> None:
        th = compute_decision_thresholds(256, 0.02)
        midpoint_rate = (th.s_accept + th.s_reject) / 2.0
        decision = decide_signature(int(midpoint_rate * 256), 256, 0.02)
        self.assertEqual(decision.verdict, "ABORT")
        self.assertIn("inconclusive", decision.justification.lower())

    def test_7_high_baseline_is_clamped_below_attacks(self) -> None:
        # Even with an implausibly noisy channel, s_accept must stay under the quietest
        # attack so that an attack can never be accepted.
        th = compute_decision_thresholds(16, 0.30)
        self.assertLess(th.s_accept, MIN_MODELLED_ATTACK_ERROR_RATE)
        self.assertLess(th.s_accept, th.s_reject)

    def test_8_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            compute_decision_thresholds(0, 0.02)
        with self.assertRaises(ValueError):
            compute_decision_thresholds(256, 1.5)
        with self.assertRaises(ValueError):
            decide_signature(300, 256, 0.02)
        with self.assertRaises(ValueError):
            decide_signature(-1, 256, 0.02)


if __name__ == "__main__":
    unittest.main()
