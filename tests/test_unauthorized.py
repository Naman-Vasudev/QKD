"""
Unit Test Suite for Unauthorized Verification Attempt Detection.
"""

import unittest

from attacks.unauthorized import (
    ATTACKER_PROFILES,
    build_attacker_token,
    run_authorization_profile_sweep,
    run_unauthorized_verification_attack,
)
from qds.session import (
    NonceRegistry,
    create_session,
    generate_master_secret,
    issue_verifier_token,
)
from qds.verification import verify_signature


class TestAttackerTokens(unittest.TestCase):

    def setUp(self) -> None:
        self.secret = generate_master_secret()

    def test_1_no_token_profile(self) -> None:
        self.assertIsNone(build_attacker_token("NO_TOKEN", self.secret))

    def test_2_forged_token_is_wrong_but_well_formed(self) -> None:
        token = build_attacker_token("FORGED_TOKEN", self.secret)
        self.assertEqual(len(token), 64)
        self.assertNotEqual(token, issue_verifier_token("eve", self.secret))

    def test_3_wrong_identity_token_is_genuine_but_misaddressed(self) -> None:
        token = build_attacker_token("WRONG_IDENTITY", self.secret, "bob")
        self.assertEqual(token, issue_verifier_token("bob", self.secret))

    def test_4_unknown_profile_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_attacker_token("SOMETHING_ELSE", self.secret)


class TestUnauthorizedVerification(unittest.TestCase):

    def setUp(self) -> None:
        self.message = "ABC"
        self.key = [i % 2 for i in range(256)]
        # A small subset keeps the quantum control run fast; the denial path never
        # executes circuits at all.
        self.subset = list(range(24))

    def test_1_all_profiles_are_denied(self) -> None:
        for profile in ATTACKER_PROFILES:
            res = run_unauthorized_verification_attack(
                message=self.message, shared_key=self.key,
                attacker_profile=profile, sample_indices=self.subset, seed=11,
            )
            self.assertTrue(res["denied"], msg=f"{profile} should be denied")
            self.assertTrue(res["threat_detected"])
            self.assertTrue(res["detection_is_deterministic"])

    def test_2_no_quantum_state_is_consumed_by_attacker(self) -> None:
        # Denial must precede the quantum stage: an unauthorized party measuring the
        # signature would destroy it, which is itself a denial-of-service vector.
        for profile in ATTACKER_PROFILES:
            res = run_unauthorized_verification_attack(
                message=self.message, shared_key=self.key,
                attacker_profile=profile, sample_indices=self.subset, seed=12,
            )
            self.assertEqual(res["quantum_states_consumed_by_attacker"], 0)

    def test_3_legitimate_verifier_still_accepted(self) -> None:
        for profile in ATTACKER_PROFILES:
            res = run_unauthorized_verification_attack(
                message=self.message, shared_key=self.key,
                attacker_profile=profile, sample_indices=self.subset, seed=13,
            )
            self.assertTrue(res["control_verification_accepted"])
            self.assertEqual(res["control_error_rate"], 0.0)

    def test_4_authorization_result_is_populated(self) -> None:
        res = run_unauthorized_verification_attack(
            message=self.message, shared_key=self.key,
            attacker_profile="FORGED_TOKEN", sample_indices=self.subset, seed=14,
        )
        auth = res["authorization_result"]
        self.assertIsNotNone(auth)
        self.assertFalse(auth.authorized)
        self.assertIn("UNAUTHORIZED VERIFICATION ATTEMPT", auth.reason)

    def test_5_profile_sweep_covers_all(self) -> None:
        results = run_authorization_profile_sweep(
            message=self.message, shared_key=self.key,
            sample_indices=self.subset, seed=15,
        )
        self.assertEqual(len(results), len(ATTACKER_PROFILES))
        self.assertTrue(all(r["denied"] for r in results))

    def test_6_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            run_unauthorized_verification_attack(
                message=self.message, shared_key=[0] * 10,
            )
        with self.assertRaises(ValueError):
            run_unauthorized_verification_attack(
                message=self.message, shared_key=self.key,
                attacker_profile="NOPE",
            )


class TestVerificationAccessControl(unittest.TestCase):
    """Authorization enforcement at the verify_signature entry point."""

    def setUp(self) -> None:
        self.key = [i % 2 for i in range(256)]
        self.secret = generate_master_secret()
        self.subset = list(range(16))

    def test_1_authorized_verifier_proceeds_to_quantum_stage(self) -> None:
        token = issue_verifier_token("bob", self.secret)
        res = verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=21, verifier_id="bob", verifier_token=token,
            master_secret=self.secret,
        )
        self.assertTrue(res.authorization.authorized)
        self.assertEqual(res.num_qubits, len(self.subset))
        self.assertTrue(res.accepted)

    def test_2_unauthorized_verifier_skips_quantum_stage(self) -> None:
        res = verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=22, verifier_id="eve", verifier_token=None,
            master_secret=self.secret,
        )
        self.assertFalse(res.authorization.authorized)
        self.assertEqual(res.num_qubits, 0)
        self.assertFalse(res.accepted)
        self.assertEqual(res.results, [])

    def test_3_freshness_check_skips_quantum_stage_on_replay(self) -> None:
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        first = verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=23, session=session, nonce_registry=registry,
        )
        self.assertTrue(first.freshness.is_fresh)
        self.assertEqual(first.num_qubits, len(self.subset))

        replay = verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=23, session=session, nonce_registry=registry,
        )
        self.assertFalse(replay.freshness.is_fresh)
        self.assertTrue(replay.freshness.replay_detected)
        self.assertEqual(replay.num_qubits, 0)

    def test_4_authorization_precedes_freshness(self) -> None:
        # An unauthorized party must not be able to burn a legitimate nonce.
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=24, session=session, nonce_registry=registry,
            verifier_id="eve", verifier_token="bad", master_secret=self.secret,
        )
        self.assertEqual(registry.consumed_count, 0)
        # The nonce is still usable by the legitimate verifier.
        token = issue_verifier_token("bob", self.secret)
        res = verify_signature(
            message="ABC", key_bits=self.key, sample_indices=self.subset,
            seed_simulator=25, session=session, nonce_registry=registry,
            verifier_id="bob", verifier_token=token, master_secret=self.secret,
        )
        self.assertTrue(res.freshness.is_fresh)


if __name__ == "__main__":
    unittest.main()
