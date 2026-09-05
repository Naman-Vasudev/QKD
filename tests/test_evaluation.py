"""
Unit Test Suite for Integrated Evaluation Orchestration Engine (Phase 3).
"""

import unittest
from evaluation.runner import (
    ExperimentResult,
    run_experiment,
    run_security_comparison,
    run_channel_tampering_sweep,
    run_basis_wise_channel_sweep,
)



class TestEvaluationEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "EvaluationTestMsg"
        self.key_balanced = [i % 2 for i in range(256)]

    def test_1_baseline_experiment(self) -> None:
        res = run_experiment(
            attack_name="No Attack / Baseline",
            message=self.message,
            shared_key=self.key_balanced,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=100,
        )
        self.assertEqual(res.attack_name, "No Attack / Baseline")
        self.assertEqual(res.num_errors, 0)
        self.assertEqual(res.observed_error_rate, 0.0)
        self.assertFalse(res.threat_result.threat_detected)

    def test_2_attack_dispatch_channel(self) -> None:
        res = run_experiment(
            attack_name="Channel Tampering",
            message=self.message,
            shared_key=self.key_balanced,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=200,
            attack_params={"p_attack": 0.50},
        )
        self.assertEqual(res.attack_name, "Channel Tampering")
        self.assertGreater(res.num_errors, 0)
        self.assertTrue(res.threat_result.threat_detected)

    def test_3_attack_dispatch_forgery(self) -> None:
        res = run_experiment(
            attack_name="Signature Forgery",
            message=self.message,
            shared_key=self.key_balanced,
            seed=300,
        )
        self.assertEqual(res.attack_name, "Signature Forgery")
        self.assertGreater(res.num_errors, 0)
        self.assertTrue(res.threat_result.threat_detected)

    def test_4_attack_dispatch_impersonation(self) -> None:
        res = run_experiment(
            attack_name="Impersonation",
            message=self.message,
            shared_key=self.key_balanced,
            seed=400,
        )
        self.assertEqual(res.attack_name, "Impersonation")
        self.assertGreater(res.num_errors, 0)
        self.assertTrue(res.threat_result.threat_detected)

    def test_5_attack_dispatch_interception(self) -> None:
        res = run_experiment(
            attack_name="Quantum Interception",
            message=self.message,
            shared_key=self.key_balanced,
            seed=500,
            attack_params={"strategy": "uniform_random"},
        )
        self.assertEqual(res.attack_name, "Quantum Interception")
        self.assertGreater(res.num_errors, 0)
        self.assertTrue(res.threat_result.threat_detected)

    def test_6_replay_experiment_same_vs_diff(self) -> None:
        # Same message replay -> 0 errors, no threat
        res_same = run_experiment(
            attack_name="Replay Attack",
            message="MsgA",
            shared_key=self.key_balanced,
            seed=600,
            attack_params={"target_message": "MsgA"},
        )
        self.assertEqual(res_same.num_errors, 0)
        self.assertFalse(res_same.threat_result.threat_detected)

        # Different message replay -> errors, threat detected
        res_diff = run_experiment(
            attack_name="Replay Attack",
            message="MsgA",
            shared_key=self.key_balanced,
            seed=700,
            attack_params={"target_message": "MsgB"},
        )
        self.assertGreater(res_diff.num_errors, 0)
        self.assertTrue(res_diff.threat_result.threat_detected)

    def test_7_comparison_aggregation(self) -> None:
        results = run_security_comparison(
            message=self.message,
            shared_key=self.key_balanced,
            seed=800,
        )
        self.assertEqual(len(results), 6)
        attack_names = [r.attack_name for r in results]
        self.assertIn("No Attack / Baseline", attack_names)
        self.assertIn("Channel Tampering", attack_names)
        self.assertIn("Signature Forgery", attack_names)
        self.assertIn("Impersonation", attack_names)
        self.assertIn("Quantum Interception", attack_names)
        self.assertIn("Replay Attack", attack_names)

    def test_8_channel_tampering_sweep(self) -> None:
        sweep = run_channel_tampering_sweep(
            message=self.message,
            shared_key=self.key_balanced,
            probabilities=[0.00, 0.10, 0.50],
            seed=900,
        )
        self.assertEqual(len(sweep), 3)
        self.assertEqual(sweep[0].relevant_params["p_attack"], 0.00)
        self.assertEqual(sweep[0].num_errors, 0)
        self.assertGreater(sweep[2].num_errors, 0)

    def test_9_invalid_configuration_handling(self) -> None:
        # Invalid message
        with self.assertRaises(ValueError):
            run_experiment("No Attack / Baseline", "", self.key_balanced)

        # Invalid key
        with self.assertRaises(ValueError):
            run_experiment("No Attack / Baseline", "ABC", [0] * 128)

        # Invalid baseline
        with self.assertRaises(ValueError):
            run_experiment("No Attack / Baseline", "ABC", self.key_balanced, baseline_error_rate=1.5)

        # Unknown attack name
        with self.assertRaises(ValueError):
            run_experiment("Invalid Attack Name", "ABC", self.key_balanced)

    def test_10_basis_wise_channel_sweep(self) -> None:
        sweep_data = run_basis_wise_channel_sweep(
            message=self.message,
            shared_key=self.key_balanced,
            probabilities=[0.00, 0.50],
            seed=999,
        )
        self.assertIn("Z", sweep_data)
        self.assertIn("X", sweep_data)
        self.assertIn("Y", sweep_data)
        self.assertEqual(len(sweep_data["Z"]), 2)
        # X basis should remain ~0 under Pauli-X channel
        self.assertEqual(sweep_data["X"][1]["observed_error_rate"], 0.0)
        # Z basis should exhibit errors under p_attack = 0.50
        self.assertGreater(sweep_data["Z"][1]["observed_error_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()

