"""
Unit Test Suite for Statistical Threat Detection Module.
"""

import unittest
from statistics.detector import calibrate_baseline, detect_threat


class TestStatisticalDetector(unittest.TestCase):

    def test_calibration(self) -> None:
        # A. Calibration: 20 errors / 1000 trials -> 0.02
        p0 = calibrate_baseline(20, 1000)
        self.assertAlmostEqual(p0, 0.02)

        # B. Zero errors: 0 / 1000 -> 0.0
        p0_zero = calibrate_baseline(0, 1000)
        self.assertEqual(p0_zero, 0.0)

        # C. Full errors: 1000 / 1000 -> 1.0
        p0_full = calibrate_baseline(1000, 1000)
        self.assertEqual(p0_full, 1.0)

    def test_legitimate_like_observation(self) -> None:
        # D. Legitimate-like observation
        # Baseline = 0.02, observed = 20 errors in 1000 trials (exactly baseline)
        res = detect_threat(error_count=20, total_trials=1000, baseline_error_rate=0.02, alpha=0.05)
        self.assertFalse(res.threat_detected)
        self.assertGreaterEqual(res.p_value, 0.05)

        # Slight variation: 22 errors in 1000 trials with 0.02 baseline
        res_slight = detect_threat(error_count=22, total_trials=1000, baseline_error_rate=0.02, alpha=0.05)
        self.assertFalse(res_slight.threat_detected)
        self.assertGreaterEqual(res_slight.p_value, 0.05)

    def test_strong_anomaly(self) -> None:
        # E. Strong anomaly: n = 1000, baseline = 0.02, observed = 100
        res = detect_threat(error_count=100, total_trials=1000, baseline_error_rate=0.02, alpha=0.05)
        self.assertTrue(res.threat_detected)
        self.assertLess(res.p_value, 1e-30)
        self.assertIn("THREAT DETECTED", res.interpretation)

    def test_input_validation(self) -> None:
        # F. Input validation errors
        # Negative error count
        with self.assertRaises(ValueError):
            detect_threat(error_count=-1, total_trials=1000, baseline_error_rate=0.02)

        # Error count > total trials
        with self.assertRaises(ValueError):
            detect_threat(error_count=1001, total_trials=1000, baseline_error_rate=0.02)

        # Non-positive total trials
        with self.assertRaises(ValueError):
            detect_threat(error_count=0, total_trials=0, baseline_error_rate=0.02)

        with self.assertRaises(ValueError):
            calibrate_baseline(error_count=5, total_trials=-10)

        # Baseline outside [0, 1]
        with self.assertRaises(ValueError):
            detect_threat(error_count=10, total_trials=100, baseline_error_rate=1.5)

        with self.assertRaises(ValueError):
            detect_threat(error_count=10, total_trials=100, baseline_error_rate=-0.1)

        # Alpha outside (0, 1)
        with self.assertRaises(ValueError):
            detect_threat(error_count=10, total_trials=100, baseline_error_rate=0.02, alpha=0.0)

        with self.assertRaises(ValueError):
            detect_threat(error_count=10, total_trials=100, baseline_error_rate=0.02, alpha=1.0)

    def test_mathematical_consistency(self) -> None:
        # G. For fixed n and p0, increasing k must monotonically non-increase upper-tail p-value
        n = 1000
        p0 = 0.02
        p_vals = []
        for k in [10, 20, 30, 40, 50, 100]:
            res = detect_threat(error_count=k, total_trials=n, baseline_error_rate=p0)
            p_vals.append(res.p_value)

        for i in range(len(p_vals) - 1):
            self.assertGreaterEqual(p_vals[i], p_vals[i + 1])

    def test_edge_cases(self) -> None:
        # k = 0 -> p_value = 1.0
        res_zero_k = detect_threat(error_count=0, total_trials=100, baseline_error_rate=0.05)
        self.assertEqual(res_zero_k.p_value, 1.0)
        self.assertFalse(res_zero_k.threat_detected)

        # p0 = 0.0 with k > 0 -> p_value = 0.0
        res_p0_zero_error = detect_threat(error_count=1, total_trials=100, baseline_error_rate=0.0)
        self.assertEqual(res_p0_zero_error.p_value, 0.0)
        self.assertTrue(res_p0_zero_error.threat_detected)

        # p0 = 0.0 with k = 0 -> p_value = 1.0
        res_p0_zero_no_error = detect_threat(error_count=0, total_trials=100, baseline_error_rate=0.0)
        self.assertEqual(res_p0_zero_no_error.p_value, 1.0)
        self.assertFalse(res_p0_zero_no_error.threat_detected)

        # p0 = 1.0 -> p_value = 1.0
        res_p0_one = detect_threat(error_count=100, total_trials=100, baseline_error_rate=1.0)
        self.assertEqual(res_p0_one.p_value, 1.0)
        self.assertFalse(res_p0_one.threat_detected)


if __name__ == "__main__":
    unittest.main()
