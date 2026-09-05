"""
Unit Test Suite for Digital Signature Replay Attack Simulator (Phase 2F).
"""

import unittest
from attacks.replay import (
    capture_legitimate_signature,
    compute_digest_hamming_distance,
    run_replay_attack,
)
from qds.verification import verify_signature


class TestReplayAttack(unittest.TestCase):

    def setUp(self) -> None:
        self.message_orig = "ABC"
        self.message_target = "XYZ"
        self.key_balanced = [i % 2 for i in range(256)]

    def test_1_legitimate_signature_capture(self) -> None:
        # Test capturing legitimate signature yields 256 valid EncodedQubit records
        captured = capture_legitimate_signature(self.message_orig, self.key_balanced)
        self.assertEqual(len(captured), 256)
        self.assertEqual(captured[0].digest_bit ^ captured[0].key_bit, captured[0].encoded_bit)

    def test_2_same_message_replay_accepted(self) -> None:
        # Experiment A: Replaying signature for same message produces 0 verification errors
        # Demonstrates that the protocol lacks a freshness mechanism (session nonce/timestamp)
        res = run_replay_attack(
            original_message="ABC",
            target_message="ABC",
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=100,
        )
        self.assertTrue(res["same_message"])
        self.assertEqual(res["total_errors"], 0)
        self.assertEqual(res["observed_error_rate"], 0.0)
        self.assertFalse(res["threat_result"].threat_detected)
        self.assertIn("PROTOCOL PROPERTY", res["protocol_note"])

    def test_3_different_message_replay_rejected(self) -> None:
        # Experiment B: Replaying signature for different message causes digest mismatch errors
        res = run_replay_attack(
            original_message="ABC",
            target_message="XYZ",
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            baseline_error_rate=0.02,
            alpha=0.05,
            seed=200,
        )
        self.assertFalse(res["same_message"])
        self.assertGreater(res["total_errors"], 0)
        self.assertAlmostEqual(res["observed_error_rate"], res["theoretical_error_rate"], delta=0.01)
        self.assertTrue(res["threat_result"].threat_detected)
        self.assertIn("DIFFERENT MESSAGE REPLAY", res["protocol_note"])

    def test_4_multiple_message_pairs(self) -> None:
        # Experiment C: Test multiple original/target message pairs
        message_pairs = [
            ("Hello World", "Hello World!"),
            ("Sender: Alice", "Sender: Eve"),
            ("Transfer 100", "Transfer 1000"),
        ]

        for msg_orig, msg_target in message_pairs:
            dist, frac = compute_digest_hamming_distance(msg_orig, msg_target)
            res = run_replay_attack(
                original_message=msg_orig,
                target_message=msg_target,
                shared_key=self.key_balanced,
                seed=300,
            )
            self.assertEqual(res["digest_hamming_distance"], dist)
            self.assertAlmostEqual(res["observed_error_rate"], frac, delta=0.01)
            self.assertTrue(res["threat_result"].threat_detected)

    def test_5_digest_hamming_distance(self) -> None:
        # Test helper function for digest Hamming distance
        # Same message -> Hamming distance 0
        dist, frac = compute_digest_hamming_distance("TestMsg", "TestMsg")
        self.assertEqual(dist, 0)
        self.assertEqual(frac, 0.0)

        # Different message -> Non-zero distance
        dist_diff, frac_diff = compute_digest_hamming_distance("TestMsg1", "TestMsg2")
        self.assertGreater(dist_diff, 0)
        self.assertGreater(frac_diff, 0.0)

    def test_6_input_validation(self) -> None:
        # Invalid secret key length
        with self.assertRaises(ValueError):
            run_replay_attack("ABC", "XYZ", shared_key=[0] * 128)

        # Invalid sample indices
        with self.assertRaises(ValueError):
            run_replay_attack("ABC", "XYZ", shared_key=self.key_balanced, sample_indices=[-1, 300])

    def test_7_legitimate_signature_regression(self) -> None:
        # Ensure legitimate signature pipeline is unaffected
        ver_res = verify_signature(self.message_orig, self.key_balanced, seed_simulator=500)
        self.assertEqual(ver_res.num_errors, 0)
        self.assertEqual(ver_res.error_rate, 0.0)
        self.assertTrue(ver_res.accepted)


if __name__ == "__main__":
    unittest.main()
