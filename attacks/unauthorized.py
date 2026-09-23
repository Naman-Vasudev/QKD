"""
Unauthorized Verification Attempt Simulation Module.

SCIENTIFIC DISCLOSURES & THREAT MODEL:
- Simulates a party attempting to verify a Quantum Digital Signature without being
  entitled to do so. Three attacker profiles are modelled:

    1. NO_TOKEN        The party presents no authorization token at all.
    2. FORGED_TOKEN    The party guesses or fabricates a token.
    3. WRONG_IDENTITY  The party presents a token that was validly issued, but to a
                       different verifier identity (token substitution / relay).

- Authorization is an HMAC-SHA256 check against a master secret held by the signing
  authority, compared in constant time via hmac.compare_digest.

- This is a CLASSICAL access-control mechanism, not an information-theoretic one. Its
  security rests on the PRF security of HMAC-SHA256 and on the master secret remaining
  secret. It is included because unauthorized verification is a named threat in the
  framework's scope, and because the quantum layer cannot address it: the quantum states
  do not encode *who* is permitted to measure them.

- SECURITY VALUE OF REJECTING EARLY: an unauthorized verifier is denied before any
  signature state is measured. Because quantum states cannot be copied (no-cloning) and
  are destroyed by measurement, this matters operationally — a party allowed to measure
  a signature consumes it, so unrestricted verification is itself a denial-of-service
  vector against legitimate verifiers.

- Detection is deterministic: a token either validates or it does not. There is no
  statistical uncertainty and therefore no false-positive rate, unlike the measurement-
  based detectors used for the quantum attacks.

- No artificial intelligence or machine learning is used.
"""

import secrets
from typing import Any, Dict, List, Optional

from core.backend import QuantumBackendAdapter
from core.models import SessionContext
from qds.session import (
    NonceRegistry,
    authorize_verifier,
    generate_master_secret,
    issue_verifier_token,
)
from qds.verification import verify_signature


ATTACKER_PROFILES = ("NO_TOKEN", "FORGED_TOKEN", "WRONG_IDENTITY")


def build_attacker_token(
    profile: str,
    master_secret: bytes,
    legitimate_verifier_id: str = "bob",
) -> Optional[str]:
    """
    Construct the token an unauthorized party would present under a given profile.

    Args:
        profile: One of ATTACKER_PROFILES.
        master_secret: Master secret held by the signing authority.
        legitimate_verifier_id: Identity of the genuinely authorized verifier, used by the
            WRONG_IDENTITY profile to model token substitution.

    Returns:
        Hex token string, or None for the NO_TOKEN profile.
    """
    if profile not in ATTACKER_PROFILES:
        raise ValueError(f"Unknown attacker profile '{profile}'. Must be one of {ATTACKER_PROFILES}.")

    if profile == "NO_TOKEN":
        return None
    if profile == "FORGED_TOKEN":
        # A fabricated token of the correct shape but with no relation to the secret.
        return secrets.token_hex(32)
    # WRONG_IDENTITY: a real token, but issued to somebody else.
    return issue_verifier_token(legitimate_verifier_id, master_secret)


def run_unauthorized_verification_attack(
    message: str,
    shared_key: List[int],
    attacker_profile: str = "NO_TOKEN",
    attacker_id: str = "eve",
    legitimate_verifier_id: str = "bob",
    master_secret: Optional[bytes] = None,
    session: Optional[SessionContext] = None,
    nonce_registry: Optional[NonceRegistry] = None,
    sample_indices: Optional[List[int]] = None,
    baseline_error_rate: float = 0.02,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute an unauthorized verification attempt and confirm it is denied.

    For contrast, the same signature is then verified by the legitimate verifier holding a
    valid token, demonstrating that access control denies the attacker without impairing
    authorized use.

    Args:
        message: Classical message string being verified.
        shared_key: Pre-shared secret key K (256 bits).
        attacker_profile: One of ATTACKER_PROFILES.
        attacker_id: Identity the unauthorized party claims.
        legitimate_verifier_id: Identity of the genuinely authorized verifier.
        master_secret: Master secret. A fresh one is generated when omitted.
        session: Optional SessionContext bound into the digest.
        nonce_registry: Optional NonceRegistry. A fresh one is used when omitted so the
            attacker's denial does not consume the legitimate verifier's nonce.
        sample_indices: Optional subset of signature indices to verify.
        baseline_error_rate: Calibrated baseline p0 for the legitimate control run.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.

    Returns:
        Dictionary describing the denial, the control verification, and the threat verdict.
    """
    if len(shared_key) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(shared_key)}.")
    if attacker_profile not in ATTACKER_PROFILES:
        raise ValueError(
            f"Unknown attacker profile '{attacker_profile}'. Must be one of {ATTACKER_PROFILES}."
        )

    if master_secret is None:
        master_secret = generate_master_secret()

    attacker_token = build_attacker_token(
        profile=attacker_profile,
        master_secret=master_secret,
        legitimate_verifier_id=legitimate_verifier_id,
    )

    # --- Unauthorized attempt --------------------------------------------------------
    attacker_registry = nonce_registry if nonce_registry is not None else NonceRegistry()

    attacker_result = verify_signature(
        message=message,
        key_bits=shared_key,
        backend=backend,
        sample_indices=sample_indices,
        seed_simulator=seed,
        session=session,
        nonce_registry=attacker_registry,
        verifier_id=attacker_id,
        verifier_token=attacker_token,
        master_secret=master_secret,
        baseline_error_rate=baseline_error_rate,
    )

    authorization = attacker_result.authorization
    denied = authorization is not None and not authorization.authorized
    quantum_states_consumed = attacker_result.num_qubits

    # --- Legitimate control run (fresh registry so the nonce is still unused) --------
    legitimate_token = issue_verifier_token(legitimate_verifier_id, master_secret)
    control_result = verify_signature(
        message=message,
        key_bits=shared_key,
        backend=backend,
        sample_indices=sample_indices,
        seed_simulator=seed,
        session=session,
        nonce_registry=NonceRegistry(),
        verifier_id=legitimate_verifier_id,
        verifier_token=legitimate_token,
        master_secret=master_secret,
        baseline_error_rate=baseline_error_rate,
    )

    profile_descriptions = {
        "NO_TOKEN": "presented no authorization token",
        "FORGED_TOKEN": "presented a fabricated 256-bit token",
        "WRONG_IDENTITY": (
            f"presented a token validly issued to '{legitimate_verifier_id}' while claiming "
            f"to be '{attacker_id}'"
        ),
    }

    interpretation = (
        f"UNAUTHORIZED VERIFICATION {'BLOCKED' if denied else 'NOT BLOCKED'}: '{attacker_id}' "
        f"{profile_descriptions[attacker_profile]} and was "
        f"{'denied' if denied else 'incorrectly allowed'}. "
        f"{quantum_states_consumed} signature states were measured during the attempt "
        f"(0 is correct: denial precedes the quantum stage, so no signature is consumed). "
        f"The legitimate verifier '{legitimate_verifier_id}' holding a valid HMAC-SHA256 token "
        f"was {'accepted' if control_result.accepted else 'not accepted'} on the same signature, "
        f"confirming access control does not impair authorized use."
    )

    return {
        "attack_type": "unauthorized_verification",
        "attacker_profile": attacker_profile,
        "attacker_id": attacker_id,
        "legitimate_verifier_id": legitimate_verifier_id,
        "message": message,
        "token_presented": attacker_token is not None,
        "authorization_result": authorization,
        "denied": denied,
        "threat_detected": denied,
        "detection_is_deterministic": True,
        "quantum_states_consumed_by_attacker": quantum_states_consumed,
        "control_verification_accepted": control_result.accepted,
        "control_error_rate": control_result.error_rate,
        "control_decision": control_result.decision,
        "baseline_error_rate": baseline_error_rate,
        "interpretation": interpretation,
    }


def run_authorization_profile_sweep(
    message: str,
    shared_key: List[int],
    sample_indices: Optional[List[int]] = None,
    baseline_error_rate: float = 0.02,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Run every unauthorized-verifier profile and collect the outcomes.

    Args:
        message: Classical message string being verified.
        shared_key: Pre-shared secret key K (256 bits).
        sample_indices: Optional subset of signature indices to verify.
        baseline_error_rate: Calibrated baseline p0.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed.

    Returns:
        List of result dictionaries, one per attacker profile.
    """
    # One shared master secret so all profiles are evaluated against the same authority.
    master_secret = generate_master_secret()

    return [
        run_unauthorized_verification_attack(
            message=message,
            shared_key=shared_key,
            attacker_profile=profile,
            master_secret=master_secret,
            sample_indices=sample_indices,
            baseline_error_rate=baseline_error_rate,
            backend=backend,
            seed=seed,
        )
        for profile in ATTACKER_PROFILES
    ]
