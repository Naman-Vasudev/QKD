"""
Unit Test Suite for Session Freshness and Verifier Authorization.
"""

import unittest

from qds.session import (
    NonceRegistry,
    authorize_verifier,
    bind_session,
    create_session,
    generate_master_secret,
    generate_nonce,
    issue_verifier_token,
)
from qds.encoding import encode_message, session_digest_bits, sha256_bits


class TestNonceGeneration(unittest.TestCase):

    def test_1_nonce_is_random_and_hex(self) -> None:
        nonces = {generate_nonce() for _ in range(200)}
        # 128-bit nonces must not collide across 200 draws.
        self.assertEqual(len(nonces), 200)
        for nonce in list(nonces)[:5]:
            self.assertEqual(len(nonce), 32)
            int(nonce, 16)  # must parse as hex

    def test_2_nonce_length_validation(self) -> None:
        with self.assertRaises(ValueError):
            generate_nonce(0)
        with self.assertRaises(ValueError):
            generate_nonce(-4)

    def test_3_session_validation(self) -> None:
        with self.assertRaises(ValueError):
            create_session(signer_id="")
        with self.assertRaises(ValueError):
            create_session(counter=-1)

    def test_4_sessions_are_unique(self) -> None:
        a = create_session("alice", counter=1)
        b = create_session("alice", counter=2)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.canonical_binding(), b.canonical_binding())


class TestSessionBinding(unittest.TestCase):

    def test_1_no_session_preserves_legacy_encoding(self) -> None:
        # Backward compatibility: without a session the digest must be the bare SHA-256.
        self.assertEqual(bind_session("ABC", None), "ABC")
        self.assertEqual(session_digest_bits("ABC", None), sha256_bits("ABC"))

    def test_2_session_changes_the_digest(self) -> None:
        session = create_session("alice", counter=1, nonce="ab" * 16)
        bound = session_digest_bits("ABC", session)
        self.assertNotEqual(bound, sha256_bits("ABC"))
        self.assertEqual(len(bound), 256)

    def test_3_binding_is_deterministic(self) -> None:
        session = create_session("alice", counter=7, nonce="cd" * 16, timestamp="2026-01-01T00:00:00+00:00")
        first = session_digest_bits("ABC", session)
        second = session_digest_bits("ABC", session)
        self.assertEqual(first, second)

    def test_4_encoding_accepts_session(self) -> None:
        key = [i % 2 for i in range(256)]
        session = create_session("alice", counter=1, nonce="ef" * 16)
        plain = encode_message("ABC", key)
        bound = encode_message("ABC", key, session=session)
        self.assertEqual(len(bound), 256)
        # The basis schedule is position-derived and must be unaffected by binding.
        self.assertEqual([q.basis for q in plain], [q.basis for q in bound])
        # The encoded bits must differ, since the digest changed.
        self.assertNotEqual(
            [q.encoded_bit for q in plain], [q.encoded_bit for q in bound]
        )


class TestNonceRegistry(unittest.TestCase):

    def test_1_first_use_is_fresh(self) -> None:
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        result = registry.consume(session)
        self.assertTrue(result.is_fresh)
        self.assertFalse(result.replay_detected)
        self.assertEqual(registry.consumed_count, 1)

    def test_2_reuse_is_rejected(self) -> None:
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        registry.consume(session)
        result = registry.consume(session)
        self.assertFalse(result.is_fresh)
        self.assertTrue(result.replay_detected)
        self.assertIn("REPLAY DETECTED", result.reason)

    def test_3_stale_counter_is_rejected(self) -> None:
        registry = NonceRegistry()
        registry.consume(create_session("alice", counter=5))
        # Fresh nonce, but the counter does not advance.
        result = registry.consume(create_session("alice", counter=3))
        self.assertFalse(result.is_fresh)
        self.assertTrue(result.stale_counter)
        self.assertIn("STALE SESSION", result.reason)

    def test_4_check_does_not_consume(self) -> None:
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        self.assertTrue(registry.check(session).is_fresh)
        self.assertEqual(registry.consumed_count, 0)
        self.assertTrue(registry.check(session).is_fresh)

    def test_5_signers_are_tracked_independently(self) -> None:
        registry = NonceRegistry()
        self.assertTrue(registry.consume(create_session("alice", counter=5)).is_fresh)
        # Bob's counter is independent of Alice's.
        self.assertTrue(registry.consume(create_session("bob", counter=1)).is_fresh)

    def test_6_reset_clears_state(self) -> None:
        registry = NonceRegistry()
        session = create_session("alice", counter=1)
        registry.consume(session)
        registry.reset()
        self.assertEqual(registry.consumed_count, 0)
        self.assertTrue(registry.consume(session).is_fresh)


class TestVerifierAuthorization(unittest.TestCase):

    def setUp(self) -> None:
        self.secret = generate_master_secret()

    def test_1_valid_token_is_authorized(self) -> None:
        token = issue_verifier_token("bob", self.secret)
        result = authorize_verifier("bob", token, self.secret)
        self.assertTrue(result.authorized)
        self.assertTrue(result.token_present)

    def test_2_missing_token_is_denied(self) -> None:
        result = authorize_verifier("eve", None, self.secret)
        self.assertFalse(result.authorized)
        self.assertFalse(result.token_present)
        self.assertIn("UNAUTHORIZED", result.reason)

    def test_3_forged_token_is_denied(self) -> None:
        result = authorize_verifier("eve", "00" * 32, self.secret)
        self.assertFalse(result.authorized)
        self.assertIn("UNAUTHORIZED", result.reason)

    def test_4_token_is_identity_bound(self) -> None:
        # A token validly issued to bob must not authorize eve.
        bobs_token = issue_verifier_token("bob", self.secret)
        result = authorize_verifier("eve", bobs_token, self.secret)
        self.assertFalse(result.authorized)

    def test_5_token_is_secret_bound(self) -> None:
        token = issue_verifier_token("bob", self.secret)
        other_secret = generate_master_secret()
        self.assertFalse(authorize_verifier("bob", token, other_secret).authorized)

    def test_6_token_is_deterministic_per_identity(self) -> None:
        self.assertEqual(
            issue_verifier_token("bob", self.secret),
            issue_verifier_token("bob", self.secret),
        )
        self.assertNotEqual(
            issue_verifier_token("bob", self.secret),
            issue_verifier_token("carol", self.secret),
        )

    def test_7_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            issue_verifier_token("", self.secret)
        with self.assertRaises(ValueError):
            issue_verifier_token("bob", b"")
        result = authorize_verifier("", "token", self.secret)
        self.assertFalse(result.authorized)

    def test_8_master_secret_is_random(self) -> None:
        secrets_set = {generate_master_secret() for _ in range(50)}
        self.assertEqual(len(secrets_set), 50)
        with self.assertRaises(ValueError):
            generate_master_secret(0)


if __name__ == "__main__":
    unittest.main()
