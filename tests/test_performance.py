"""
Unit Test Suite for Performance and Complexity Measurement.

Timing assertions are deliberately loose: wall-clock measurements vary between machines
and runs. The tests check structural correctness and the scaling exponent, not absolute
speed, so they remain valid on slow CI hardware.
"""

import unittest

from core.seeding import MAX_SEED, ShotSeeder, derive_seed
from evaluation.performance import (
    analyze_verification_complexity,
    build_complexity_table,
    classify_slope,
    measure_encoding_performance,
    measure_verification_performance,
)


class TestShotSeeder(unittest.TestCase):

    def test_1_reproducible_under_same_master_seed(self) -> None:
        first = ShotSeeder(42).take(20)
        second = ShotSeeder(42).take(20)
        self.assertEqual(first, second)

    def test_2_different_master_seeds_diverge(self) -> None:
        self.assertNotEqual(ShotSeeder(1).take(20), ShotSeeder(2).take(20))

    def test_3_unseeded_yields_none(self) -> None:
        seeder = ShotSeeder(None)
        self.assertEqual(seeder.take(5), [None] * 5)

    def test_4_seeds_are_in_valid_range(self) -> None:
        for seed in ShotSeeder(7).take(100):
            self.assertGreaterEqual(seed, 1)
            self.assertLess(seed, MAX_SEED)

    def test_5_seeds_are_well_spread(self) -> None:
        # The bug this replaces was consecutive integers; assert we are not doing that.
        seeds = ShotSeeder(11).take(50)
        consecutive = sum(1 for a, b in zip(seeds, seeds[1:]) if b == a + 1)
        self.assertEqual(consecutive, 0)
        self.assertEqual(len(set(seeds)), 50)

    def test_6_emitted_counter(self) -> None:
        seeder = ShotSeeder(3)
        seeder.take(7)
        self.assertEqual(seeder.emitted, 7)

    def test_7_take_validation(self) -> None:
        with self.assertRaises(ValueError):
            ShotSeeder(1).take(-1)

    def test_8_derive_seed_is_deterministic_and_independent(self) -> None:
        self.assertEqual(derive_seed(5, 1, 2), derive_seed(5, 1, 2))
        self.assertNotEqual(derive_seed(5, 1, 2), derive_seed(5, 1, 3))
        self.assertNotEqual(derive_seed(5, 1, 2), derive_seed(6, 1, 2))
        self.assertIsNone(derive_seed(None, 1, 2))


class TestPerformanceMeasurement(unittest.TestCase):

    def setUp(self) -> None:
        self.key = [i % 2 for i in range(256)]

    def test_1_verification_metrics_are_consistent(self) -> None:
        metrics = measure_verification_performance(
            message="ABC", shared_key=self.key, signature_length=16, seed=1,
        )
        self.assertEqual(metrics.signature_length, 16)
        self.assertEqual(metrics.circuit_executions, 16)
        self.assertGreater(metrics.total_seconds, 0.0)
        self.assertAlmostEqual(
            metrics.seconds_per_qubit, metrics.total_seconds / 16, places=9
        )
        self.assertGreater(metrics.qubits_per_second, 0.0)

    def test_2_shots_multiply_executions(self) -> None:
        metrics = measure_verification_performance(
            message="ABC", shared_key=self.key, signature_length=8,
            shots_per_qubit=3, seed=2,
        )
        self.assertEqual(metrics.circuit_executions, 24)

    def test_3_encoding_is_purely_classical(self) -> None:
        metrics = measure_encoding_performance(
            message="ABC", shared_key=self.key, repetitions=50,
        )
        self.assertEqual(metrics.circuit_executions, 0)
        self.assertEqual(metrics.backend_name, "classical")
        self.assertGreater(metrics.total_seconds, 0.0)

    def test_4_encoding_is_much_faster_than_circuits(self) -> None:
        # The classical stage should be orders of magnitude cheaper per position,
        # confirming that circuit execution dominates the constant factor.
        encoding = measure_encoding_performance(
            message="ABC", shared_key=self.key, repetitions=50,
        )
        quantum = measure_verification_performance(
            message="ABC", shared_key=self.key, signature_length=16, seed=3,
        )
        self.assertLess(encoding.seconds_per_qubit, quantum.seconds_per_qubit)

    def test_5_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            measure_verification_performance("ABC", self.key, signature_length=0)
        with self.assertRaises(ValueError):
            measure_verification_performance("ABC", self.key, signature_length=300)
        with self.assertRaises(ValueError):
            measure_verification_performance("ABC", self.key, shots_per_qubit=0)
        with self.assertRaises(ValueError):
            measure_encoding_performance("ABC", self.key, repetitions=0)


class TestComplexityAnalysis(unittest.TestCase):

    def setUp(self) -> None:
        self.key = [i % 2 for i in range(256)]

    def test_1_verification_scales_linearly(self) -> None:
        analysis = analyze_verification_complexity(
            message="ABC", shared_key=self.key,
            sizes=[16, 32, 64, 128], seed=1, repeats=3,
        )
        self.assertEqual(analysis.sizes, [16, 32, 64, 128])
        self.assertEqual(len(analysis.durations), 4)
        # The protocol performs one circuit per position, so the exponent must be ~1.
        # The window is wide enough to tolerate timing noise on loaded machines.
        self.assertGreater(analysis.log_log_slope, 0.7)
        self.assertLess(analysis.log_log_slope, 1.4)
        self.assertGreater(analysis.r_squared, 0.9)
        self.assertIn("O(n)", analysis.classification)

    def test_2_durations_increase_with_size(self) -> None:
        analysis = analyze_verification_complexity(
            message="ABC", shared_key=self.key, sizes=[16, 64], seed=2, repeats=3,
        )
        self.assertLess(analysis.durations[0], analysis.durations[1])

    def test_3_slope_classification_boundaries(self) -> None:
        self.assertIn("O(1)", classify_slope(0.1))
        self.assertIn("O(n) linear", classify_slope(1.0))
        self.assertIn("O(n log n)", classify_slope(1.5))
        self.assertIn("O(n^2)", classify_slope(2.0))
        self.assertIn("super-quadratic", classify_slope(3.0))

    def test_4_complexity_table_declares_linear_total(self) -> None:
        table = build_complexity_table()
        self.assertGreater(len(table), 5)
        total = [row for row in table if row["stage"] == "TOTAL"]
        self.assertEqual(len(total), 1)
        self.assertEqual(total[0]["complexity"], "O(n)")
        # No declared stage may exceed O(n).
        self.assertNotIn("O(n^2)", {row["complexity"] for row in table})

    def test_5_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            analyze_verification_complexity("ABC", self.key, sizes=[32])
        with self.assertRaises(ValueError):
            analyze_verification_complexity("ABC", self.key, sizes=[16, 999])
        with self.assertRaises(ValueError):
            analyze_verification_complexity("ABC", self.key, sizes=[16, 32], repeats=0)


if __name__ == "__main__":
    unittest.main()
