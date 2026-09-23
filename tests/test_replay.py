"""
Unit Test Suite for Digital Signature Replay Attack Simulator (Phase 2F).
"""

import unittest
from attacks.replay import (
    capture_legitimate_signature,
    compute_digest_hamming_distance,
    run_replay_attack,
)
from qds.session import NonceRegistry, create_session
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

    def test_2_same_message_replay_undetectable_without_freshness(self) -> None:
        # LEGACY MODE: with no SessionContext the encoding is deterministic, so a
        # same-message replay produces zero errors and cannot be detected by measurement.
        # Retained to document exactly what the freshness binding fixes.
        res = run_replay_attack(
            original_message="ABC",
            target_message="ABC",
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=100,
        )
        self.assertTrue(res["same_message"])
        self.assertFalse(res["freshness_enabled"])
        self.assertEqual(res["total_errors"], 0)
        self.assertEqual(res["observed_error_rate"], 0.0)
        self.assertFalse(res["threat_result"].threat_detected)
        self.assertFalse(res["replay_detected_classically"])
        self.assertIn("LEGACY MODE", res["protocol_note"])

    def test_2b_same_message_replay_detected_with_nonce(self) -> None:
        # PROTECTED MODE: the nonce registry catches the reuse deterministically, and does
        # so before any quantum state is consumed.
        session = create_session(signer_id="alice", counter=1)
        registry = NonceRegistry()
        res = run_replay_attack(
            original_message="ABC",
            target_message="ABC",
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=101,
            original_session=session,
            nonce_registry=registry,
        )
        self.assertTrue(res["same_message"])
        self.assertTrue(res["freshness_enabled"])
        self.assertTrue(res["replay_detected_classically"])
        self.assertTrue(res["quantum_verification_bypassed"])
        self.assertIsNotNone(res["freshness_result"])
        self.assertTrue(res["freshness_result"].replay_detected)
        self.assertIn("REPLAY BLOCKED", res["protocol_note"])

    def test_2c_first_use_of_nonce_is_accepted(self) -> None:
        # Freshness must not reject a legitimate first presentation.
        session = create_session(signer_id="alice", counter=1)
        registry = NonceRegistry()
        res = run_replay_attack(
            original_message="ABC",
            target_message="ABC",
            shared_key=self.key_balanced,
            shots_per_qubit=1,
            seed=102,
            original_session=session,
            nonce_registry=registry,
            original_already_verified=False,
        )
        self.assertFalse(res["replay_detected_classically"])
        self.assertEqual(res["total_errors"], 0)
        self.assertIn("FIRST USE", res["protocol_note"])

    def test_2d_session_binding_changes_the_digest(self) -> None:
        # The whole mechanism rests on the session altering the digest; verify it does.
        session_a = create_session(signer_id="alice", counter=1, nonce="aa" * 16)
        session_b = create_session(signer_id="alice", counter=2, nonce="bb" * 16)
        dist_bound, frac_bound = compute_digest_hamming_distance(
            "ABC", "ABC", session_a, session_b
        )
        self.assertGreater(dist_bound, 0)
        # SHA-256 avalanche: two different sessions over the same message differ in ~50%
        # of digest bits, which is what forces an attacker back to the forgery problem.
        self.assertGreater(frac_bound, 0.3)
        self.assertLess(frac_bound, 0.7)

        dist_unbound, _ = compute_digest_hamming_distance("ABC", "ABC", None, None)
        self.assertEqual(dist_unbound, 0)

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
