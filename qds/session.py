"""
Session Freshness and Verifier Authorization Module.

PURPOSE:
Closes the two protocol gaps that pure measurement statistics cannot close on their own:

1. REPLAY RESISTANCE (freshness)
   The bare encoding D = SHA-256(M), b_i = d_i XOR K_i is deterministic, so a captured
   signature for message M is bit-identical to a fresh signature for M. No quantum
   measurement can distinguish them, because there is nothing to distinguish.

   This module binds a per-session nonce, a monotonic counter, and the signer identity
   into the hashed payload BEFORE encoding:

       P     = signer_id | nonce | counter | timestamp
       D     = SHA-256(M | P)
       b_i   = d_i XOR K_i

   Consequences:
   - Replaying a captured signature in a later session fails the verifier's nonce
     registry check immediately (classical, O(1), deterministic).
   - Replaying it with a *forged* fresh nonce changes D, so the attacker would have to
     re-derive 256 quantum states for the new digest. Without K that is exactly the
     forgery problem, and the measurement statistics detect it at ~50% error.

   Replay therefore moves from "undetectable" to "detected by two independent mechanisms".

2. UNAUTHORIZED VERIFICATION ATTEMPTS
   Verification is an access-controlled operation. A verifier proves it is entitled to
   verify by presenting an HMAC-SHA256 token issued under a master secret held by the
   signing authority. Tokens are compared in constant time.

SCIENTIFIC DISCLOSURES:
- Freshness and verifier authorization are CLASSICAL mechanisms. They are not, and are
  not claimed to be, information-theoretically secure; they rest on the collision and
  PRF security of SHA-256/HMAC-SHA256.
- The information-theoretic component of the framework remains the key-dependent quantum
  state encoding. These mechanisms are complementary, not a substitute.
- No artificial intelligence or machine learning is used.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple

from core.models import SessionContext, FreshnessResult, AuthorizationResult


NONCE_BYTES = 16
VERIFIER_TOKEN_BYTES = 32


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with second resolution."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def generate_nonce(num_bytes: int = NONCE_BYTES) -> str:
    """
    Generate a cryptographically secure random nonce.

    Args:
        num_bytes: Nonce length in bytes (default 16 = 128 bits).

    Returns:
        Hex-encoded nonce string.
    """
    if num_bytes <= 0:
        raise ValueError(f"Nonce length must be positive, got {num_bytes}.")
    return secrets.token_hex(num_bytes)


def create_session(
    signer_id: str = "alice",
    counter: int = 1,
    nonce: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> SessionContext:
    """
    Create a fresh signing session context.

    Args:
        signer_id: Identity label of the signing party.
        counter: Monotonic sequence number for this signer (must be positive).
        nonce: Optional explicit nonce (used for reproducible tests and replay simulation).
               A cryptographically random nonce is generated when omitted.
        timestamp: Optional explicit UTC ISO-8601 timestamp.

    Returns:
        SessionContext instance.
    """
    if counter < 0:
        raise ValueError(f"Session counter must be non-negative, got {counter}.")
    if not signer_id:
        raise ValueError("Signer identity must be a non-empty string.")

    return SessionContext(
        nonce=nonce if nonce is not None else generate_nonce(),
        counter=counter,
        timestamp=timestamp if timestamp is not None else utc_now_iso(),
        signer_id=signer_id,
    )


def bind_session(message: str, session: Optional[SessionContext]) -> str:
    """
    Produce the canonical payload that is hashed during encoding.

    Args:
        message: Classical message string M.
        session: Optional SessionContext. When None, the payload is M unchanged, which
                 preserves the original (freshness-free) protocol behaviour exactly.

    Returns:
        The canonical string to be hashed.
    """
    if session is None:
        return message
    return f"{message}|{session.canonical_binding()}"


class NonceRegistry:
    """
    Verifier-side registry of consumed session nonces.

    Enforces two independent freshness rules:
      - A nonce may be consumed at most once (strict replay rejection).
      - A signer's counter must strictly increase (ordering / stale-session rejection).

    Lookup and insertion are O(1), so freshness checking adds negligible cost to
    verification and does not affect the protocol's overall O(n) complexity.
    """

    def __init__(self) -> None:
        self._seen_nonces: Set[str] = set()
        self._highest_counter: Dict[str, int] = {}

    @property
    def consumed_count(self) -> int:
        """Number of nonces consumed so far."""
        return len(self._seen_nonces)

    def is_consumed(self, nonce: str) -> bool:
        """Return True if this nonce has already been consumed."""
        return nonce in self._seen_nonces

    def check(self, session: SessionContext) -> FreshnessResult:
        """
        Evaluate freshness WITHOUT consuming the nonce.

        Args:
            session: SessionContext presented with the signature.

        Returns:
            FreshnessResult describing the outcome.
        """
        if session.nonce in self._seen_nonces:
            return FreshnessResult(
                is_fresh=False,
                replay_detected=True,
                reason=(
                    f"REPLAY DETECTED: nonce {session.nonce[:16]}... was already consumed by this "
                    f"verifier. A signature may be verified at most once per session nonce."
                ),
                nonce=session.nonce,
                signer_id=session.signer_id,
            )

        last_counter = self._highest_counter.get(session.signer_id)
        if last_counter is not None and session.counter <= last_counter:
            return FreshnessResult(
                is_fresh=False,
                stale_counter=True,
                reason=(
                    f"STALE SESSION: counter {session.counter} for signer '{session.signer_id}' does "
                    f"not advance beyond the highest counter already seen ({last_counter}). "
                    f"This indicates an out-of-order or replayed session."
                ),
                nonce=session.nonce,
                signer_id=session.signer_id,
            )

        return FreshnessResult(
            is_fresh=True,
            reason=(
                f"FRESH SESSION: nonce {session.nonce[:16]}... is unused and counter "
                f"{session.counter} advances for signer '{session.signer_id}'."
            ),
            nonce=session.nonce,
            signer_id=session.signer_id,
        )

    def consume(self, session: SessionContext) -> FreshnessResult:
        """
        Evaluate freshness and, if fresh, permanently consume the nonce.

        Args:
            session: SessionContext presented with the signature.

        Returns:
            FreshnessResult describing the outcome.
        """
        result = self.check(session)
        if result.is_fresh:
            self._seen_nonces.add(session.nonce)
            previous = self._highest_counter.get(session.signer_id, -1)
            self._highest_counter[session.signer_id] = max(previous, session.counter)
        return result

    def reset(self) -> None:
        """Clear all consumed nonces and counters."""
        self._seen_nonces.clear()
        self._highest_counter.clear()


def generate_master_secret(num_bytes: int = VERIFIER_TOKEN_BYTES) -> bytes:
    """
    Generate a cryptographically secure master secret for issuing verifier tokens.

    Args:
        num_bytes: Secret length in bytes (default 32 = 256 bits).

    Returns:
        Random secret bytes.
    """
    if num_bytes <= 0:
        raise ValueError(f"Master secret length must be positive, got {num_bytes}.")
    return secrets.token_bytes(num_bytes)


def issue_verifier_token(verifier_id: str, master_secret: bytes) -> str:
    """
    Issue an HMAC-SHA256 authorization token entitling a verifier to verify signatures.

    Args:
        verifier_id: Identity label of the authorized verifier (e.g. "bob").
        master_secret: Master secret held by the signing authority.

    Returns:
        Hex-encoded HMAC token.
    """
    if not verifier_id:
        raise ValueError("Verifier identity must be a non-empty string.")
    if not master_secret:
        raise ValueError("Master secret must be non-empty.")

    return hmac.new(
        key=master_secret,
        msg=verifier_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def authorize_verifier(
    verifier_id: str,
    presented_token: Optional[str],
    master_secret: bytes,
) -> AuthorizationResult:
    """
    Validate a verifier's authorization token in constant time.

    Detects unauthorized verification attempts: a party with no token, a guessed token,
    or a token issued for a different identity is denied.

    Args:
        verifier_id: Identity claimed by the party attempting verification.
        presented_token: Hex-encoded token presented by that party, or None.
        master_secret: Master secret held by the signing authority.

    Returns:
        AuthorizationResult describing the outcome.
    """
    if not verifier_id:
        return AuthorizationResult(
            authorized=False,
            verifier_id="",
            reason="UNAUTHORIZED: no verifier identity was presented.",
            token_present=presented_token is not None,
        )

    if not presented_token:
        return AuthorizationResult(
            authorized=False,
            verifier_id=verifier_id,
            reason=(
                f"UNAUTHORIZED VERIFICATION ATTEMPT: verifier '{verifier_id}' presented no "
                f"authorization token. Verification denied before any quantum state was consumed."
            ),
            token_present=False,
        )

    expected = issue_verifier_token(verifier_id, master_secret)
    # Constant-time comparison prevents timing side-channels on token validation.
    if hmac.compare_digest(expected, presented_token):
        return AuthorizationResult(
            authorized=True,
            verifier_id=verifier_id,
            reason=f"AUTHORIZED: verifier '{verifier_id}' presented a valid HMAC-SHA256 token.",
            token_present=True,
        )

    return AuthorizationResult(
        authorized=False,
        verifier_id=verifier_id,
        reason=(
            f"UNAUTHORIZED VERIFICATION ATTEMPT: token presented by '{verifier_id}' failed "
            f"HMAC-SHA256 validation. Verification denied before any quantum state was consumed."
        ),
        token_present=True,
    )
