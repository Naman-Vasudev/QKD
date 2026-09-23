"""
Unit Test Suite for the Quantum-Inspired Threat Classification Engine.

Verifies that the classifier names the correct threat class from basis-resolved
measurement statistics, using synthetic profiles for the analytic edge cases and real
circuit executions for end-to-end confirmation.
"""

import unittest

from qds_statistics.classifier import (
    build_basis_error_profile,
    classify_threat,
    matthews_correlation,
    minimum_trials_for_resolution,
)
from attacks.channel import run_channel_attack
from attacks.forgery import run_forgery_attack
from attacks.impersonation import run_impersonation_attack
from attacks.interception import run_interception_attack


BASES_CYCLE = ("Z", "X", "Y")


def synthetic_results(rates, n_per_basis=120, key_bits=None, key_correlated=False):
    """
    Build a synthetic detailed_results list with prescribed per-basis error rates.

    Args:
        rates: Dict of basis -> error rate.
        n_per_basis: Positions per basis.
        key_bits: Optional per-position key bits to attach.
        key_correlated: When True, errors are placed exactly where key_bit == 1.

    Returns:
        List of per-position record dicts.
    """
    records = []
    index = 0
    for basis in BASES_CYCLE:
        n_errors = int(round(rates[basis] * n_per_basis))
        for i in range(n_per_basis):
            if key_correlated and key_bits is not None:
                key_bit = key_bits[index % len(key_bits)]
                matched = key_bit == 0
            else:
                key_bit = (i % 2) if key_bits is None else key_bits[index % len(key_bits)]
                matched = i >= n_errors
            records.append({
                "qubit_index": index,
                "basis": basis,
                "matched": matched,
                "key_bit": key_bit,
            })
            index += 1
    return records


class TestBasisErrorProfile(unittest.TestCase):

    def test_1_profile_computes_per_basis_rates(self) -> None:
        records = synthetic_results({"Z": 0.5, "X": 0.0, "Y": 0.5}, n_per_basis=100)
        profile = build_basis_error_profile(records)
        self.assertAlmostEqual(profile.rates["Z"], 0.5, places=6)
        self.assertAlmostEqual(profile.rates["X"], 0.0, places=6)
        self.assertAlmostEqual(profile.rates["Y"], 0.5, places=6)
        self.assertEqual(profile.total_trials, 300)

    def test_2_empty_results_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_basis_error_profile([])

    def test_3_unrecognised_basis_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_basis_error_profile([{"basis": "W", "matched": True}])

    def test_4_alice_basis_key_is_accepted(self) -> None:
        # The interception module labels the field "alice_basis"; both must work.
        records = [{"alice_basis": "Z", "matched": False} for _ in range(10)]
        profile = build_basis_error_profile(records)
        self.assertEqual(profile.counts["Z"], 10)
        self.assertAlmostEqual(profile.rates["Z"], 1.0, places=6)


class TestMatthewsCorrelation(unittest.TestCase):

    def test_1_perfect_correlation(self) -> None:
        errors = [1, 0, 1, 0, 1, 0]
        keys = [1, 0, 1, 0, 1, 0]
        self.assertAlmostEqual(matthews_correlation(errors, keys), 1.0, places=6)

    def test_2_perfect_anticorrelation(self) -> None:
        errors = [1, 0, 1, 0]
        keys = [0, 1, 0, 1]
        self.assertAlmostEqual(matthews_correlation(errors, keys), -1.0, places=6)

    def test_3_degenerate_returns_none(self) -> None:
        # No errors at all: the marginal is constant, so MCC is undefined.
        self.assertIsNone(matthews_correlation([0, 0, 0], [1, 0, 1]))
        self.assertIsNone(matthews_correlation([], []))
        self.assertIsNone(matthews_correlation([1, 0], [1]))


class TestResolutionLimit(unittest.TestCase):

    def test_1_tightest_pair_needs_many_trials(self) -> None:
        # Intercept-resend (1/3) vs impersonation (1/2) is the hardest pair to separate.
        required = minimum_trials_for_resolution(1.0 / 3.0, 0.5)
        self.assertGreater(required, 100)
        self.assertLess(required, 256)

    def test_2_identical_rates_never_separable(self) -> None:
        self.assertEqual(minimum_trials_for_resolution(0.5, 0.5), 0)

    def test_3_far_apart_rates_need_few_trials(self) -> None:
        self.assertLess(minimum_trials_for_resolution(0.02, 0.5), 40)


class TestSyntheticClassification(unittest.TestCase):

    def test_1_x_basis_immunity_identifies_channel_tampering(self) -> None:
        # The defining signature of a Pauli-X channel: X basis untouched, Z and Y hit.
        records = synthetic_results({"Z": 0.5, "X": 0.0, "Y": 0.5}, n_per_basis=120)
        result = classify_threat(records, baseline_error_rate=0.02, channel_probability=0.5)
        self.assertEqual(result.top_label, "CHANNEL_TAMPERING")
        self.assertIn("X-BASIS IMMUNITY CONFIRMED", " ".join(result.hypotheses[0].evidence))

    def test_2_uniform_third_identifies_interception(self) -> None:
        third = 1.0 / 3.0
        records = synthetic_results({"Z": third, "X": third, "Y": third}, n_per_basis=150)
        result = classify_threat(records, baseline_error_rate=0.02)
        self.assertEqual(result.top_label, "INTERCEPT_RESEND")

    def test_3_baseline_identifies_no_attack(self) -> None:
        records = synthetic_results({"Z": 0.0, "X": 0.0, "Y": 0.0}, n_per_basis=120)
        result = classify_threat(records, baseline_error_rate=0.0)
        self.assertEqual(result.top_label, "NO_ATTACK")

    def test_4_key_correlation_separates_forgery_from_impersonation(self) -> None:
        key_bits = [i % 2 for i in range(360)]
        # Errors land exactly where K_i == 1 -> forgery.
        forged = synthetic_results(
            {"Z": 0.5, "X": 0.5, "Y": 0.5}, n_per_basis=120,
            key_bits=key_bits, key_correlated=True,
        )
        result = classify_threat(forged, baseline_error_rate=0.02, key_one_density=0.5)
        self.assertEqual(result.top_label, "FORGERY")
        self.assertIsNotNone(result.profile.key_error_correlation)
        self.assertGreater(result.profile.key_error_correlation, 0.9)

    def test_5_classical_overrides_take_precedence(self) -> None:
        # A clean channel with a consumed nonce is still a confirmed replay.
        records = synthetic_results({"Z": 0.0, "X": 0.0, "Y": 0.0}, n_per_basis=60)
        result = classify_threat(
            records, baseline_error_rate=0.02, nonce_replay_detected=True
        )
        self.assertEqual(result.top_label, "REPLAY_SAME_MESSAGE")
        self.assertEqual(result.confidence, 1.0)

        result = classify_threat(
            records, baseline_error_rate=0.02, authorization_denied=True
        )
        self.assertEqual(result.top_label, "UNAUTHORIZED_VERIFICATION")
        self.assertEqual(result.confidence, 1.0)

    def test_6_hypotheses_are_ranked_and_scored(self) -> None:
        records = synthetic_results({"Z": 0.5, "X": 0.0, "Y": 0.5}, n_per_basis=90)
        result = classify_threat(records, baseline_error_rate=0.02)
        distances = [h.distance for h in result.hypotheses]
        self.assertEqual(distances, sorted(distances))
        self.assertAlmostEqual(sum(h.score for h in result.hypotheses), 1.0, places=6)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_7_small_sample_lowers_confidence(self) -> None:
        third = 1.0 / 3.0
        small = synthetic_results({"Z": third, "X": third, "Y": third}, n_per_basis=6)
        large = synthetic_results({"Z": third, "X": third, "Y": third}, n_per_basis=150)
        conf_small = classify_threat(small, baseline_error_rate=0.02).confidence
        conf_large = classify_threat(large, baseline_error_rate=0.02).confidence
        self.assertLess(conf_small, conf_large)


class TestEndToEndClassification(unittest.TestCase):
    """Classification driven by real Qiskit circuit executions at full signature length."""

    def setUp(self) -> None:
        self.message = "ABC"
        self.key = [i % 2 for i in range(256)]
        self.density = sum(self.key) / 256

    def test_1_channel_tampering_classified(self) -> None:
        res = run_channel_attack(self.message, self.key, 0.5, seed=4242)
        result = classify_threat(
            res["detailed_results"], baseline_error_rate=0.02,
            key_one_density=self.density, channel_probability=0.5,
        )
        self.assertEqual(result.top_label, "CHANNEL_TAMPERING")

    def test_2_forgery_classified(self) -> None:
        res = run_forgery_attack(self.message, self.key, seed=4243)
        result = classify_threat(
            res["detailed_results"], baseline_error_rate=0.02,
            key_one_density=self.density,
        )
        self.assertEqual(result.top_label, "FORGERY")

    def test_3_impersonation_classified(self) -> None:
        res = run_impersonation_attack(self.message, self.key, seed=4244)
        result = classify_threat(
            res["detailed_results"], baseline_error_rate=0.02,
            key_one_density=self.density,
        )
        self.assertEqual(result.top_label, "IMPERSONATION")

    def test_4_interception_classified(self) -> None:
        res = run_interception_attack(self.message, self.key, seed=4245)
        result = classify_threat(
            res["detailed_results"], baseline_error_rate=0.02,
            key_one_density=self.density,
        )
        self.assertEqual(result.top_label, "INTERCEPT_RESEND")

    def test_5_clean_channel_classified(self) -> None:
        res = run_channel_attack(self.message, self.key, 0.0, seed=4246)
        result = classify_threat(
            res["detailed_results"], baseline_error_rate=0.02,
            key_one_density=self.density, channel_probability=0.0,
        )
        self.assertEqual(result.top_label, "NO_ATTACK")


if __name__ == "__main__":
    unittest.main()
