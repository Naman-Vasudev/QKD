"""
Unit Test Suite for Position-by-Position Experimental Trace Data Structures.
"""

import unittest
from attacks.channel import run_channel_attack
from attacks.forgery import run_forgery_attack
from attacks.impersonation import run_impersonation_attack
from attacks.interception import run_interception_attack
from attacks.replay import run_replay_attack


class TestTraceIntegrity(unittest.TestCase):

    def setUp(self) -> None:
        self.key = [i % 2 for i in range(256)]
        self.message = "ABC"

    def test_channel_trace_fields(self) -> None:
        res = run_channel_attack(self.message, self.key, attack_probability=0.20, seed=42)
        self.assertIn("detailed_results", res)
        self.assertEqual(len(res["detailed_results"]), 256)
        first = res["detailed_results"][0]
        self.assertIn("digest_bit", first)
        self.assertIn("key_bit", first)
        self.assertIn("encoded_bit", first)
        self.assertIn("x_injected", first)
        self.assertIn("matched", first)

    def test_forgery_trace_fields(self) -> None:
        res = run_forgery_attack(self.message, self.key, seed=42)
        self.assertIn("detailed_results", res)
        self.assertEqual(len(res["detailed_results"]), 256)
        first = res["detailed_results"][0]
        self.assertIn("digest_bit", first)
        self.assertIn("key_bit", first)
        self.assertIn("legitimate_encoded_bit", first)
        self.assertIn("forged_encoded_bit", first)
        self.assertIn("matched", first)

    def test_impersonation_trace_fields(self) -> None:
        res = run_impersonation_attack(self.message, self.key, seed=42)
        self.assertIn("detailed_results", res)
        self.assertEqual(len(res["detailed_results"]), 256)
        self.assertIn("eve_guessed_bits", res)
        self.assertEqual(len(res["eve_guessed_bits"]), 256)
        first = res["detailed_results"][0]
        self.assertIn("impersonated_encoded_bit", first)
        self.assertIn("matched", first)

    def test_interception_trace_fields(self) -> None:
        res = run_interception_attack(self.message, self.key, seed=42)
        self.assertIn("detailed_results", res)
        self.assertEqual(len(res["detailed_results"]), 256)
        first = res["detailed_results"][0]
        self.assertIn("alice_basis", first)
        self.assertIn("eve_basis", first)
        self.assertIn("same_basis", first)
        self.assertIn("matched", first)

    def test_replay_trace_fields(self) -> None:
        res = run_replay_attack(self.message, "XYZ", self.key, seed=42)
        self.assertIn("detailed_results", res)
        self.assertEqual(len(res["detailed_results"]), 256)
        first = res["detailed_results"][0]
        self.assertIn("captured_state", first)
        self.assertIn("expected_state", first)
        self.assertIn("bits_differ", first)
        self.assertIn("matched", first)


if __name__ == "__main__":
    unittest.main()
