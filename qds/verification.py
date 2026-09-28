"""
Signature Verification Engine for Quantum Digital Signatures.

Evaluates teleported Pauli eigenstates against expected measurement bases and eigenvalues
derived from classical digest bits and secret shared key K.

VERIFICATION PIPELINE (checks are ordered cheapest-first, so an attack is rejected at the
earliest possible stage and no quantum resource is wasted on it):

  1. AUTHORIZATION   O(1)   Is this verifier entitled to verify at all?
  2. FRESHNESS       O(1)   Has this session nonce already been consumed?
  3. QUANTUM         O(n)   Do the teleported states carry the expected eigenvalues?
  4. DECISION        O(1)   Three-way ACCEPT / ABORT / REJECT against calibrated thresholds.

SCIENTIFIC DISCLOSURES:
- Stages 1 and 2 are classical mechanisms resting on HMAC-SHA256 and SHA-256; stage 3 is
  the information-theoretic component that depends on the secret key K.
- `accepted` retains its original meaning (error_rate == 0.0, deterministic acceptance on
  an ideal channel). The three-way `decision` field is the threshold-based verdict that
  remains correct on a noisy channel, where a zero-error requirement would reject every
  legitimate signature.
"""

from typing import List, Optional

from core.models import (
    EncodedQubit,
    TeleportationResult,
    SignatureVerificationResult,
    SessionContext,
    DecisionThresholds,
)
from core.backend import QuantumBackendAdapter
from core.seeding import ShotSeeder
from qds_statistics.detector import decide_signature
from .encoding import encode_message
from .session import NonceRegistry, authorize_verifier
from .teleportation import teleport_and_measure


def verify_encoded_qubit(
    encoded_qubit: EncodedQubit,
    backend: Optional[QuantumBackendAdapter] = None,
    seed_simulator: Optional[int] = None,
) -> TeleportationResult:
    """
    Verify a single encoded signature qubit by performing 3-qubit quantum teleportation
    and checking the observed eigenvalue against the expected protocol eigenvalue.

    Args:
        encoded_qubit: EncodedQubit record containing state_label, basis, and expected_eigenvalue.
        backend: Optional QuantumBackendAdapter (uses AerSimulator default if None).
        seed_simulator: Optional seed for execution reproducibility.

    Returns:
        TeleportationResult instance.
    """
    return teleport_and_measure(
        state_label=encoded_qubit.state_label,
        basis=encoded_qubit.basis,
        expected_eigenvalue=encoded_qubit.expected_eigenvalue,
        backend=backend,
        seed_simulator=seed_simulator,
    )


def verify_signature(
    message: str,
    key_bits: List[int],
    backend: Optional[QuantumBackendAdapter] = None,
    sample_indices: Optional[List[int]] = None,
    seed_simulator: Optional[int] = None,
    session: Optional[SessionContext] = None,
    nonce_registry: Optional[NonceRegistry] = None,
    verifier_id: Optional[str] = None,
    verifier_token: Optional[str] = None,
    master_secret: Optional[bytes] = None,
    baseline_error_rate: Optional[float] = None,
    thresholds: Optional[DecisionThresholds] = None,
) -> SignatureVerificationResult:
    """
    Perform end-to-end verification of a Quantum Digital Signature sequence.

    Args:
        message: Classical message string to verify (e.g., "ABC").
        key_bits: List of 256 integers (0 or 1) representing the pre-shared secret key K.
        backend: Optional QuantumBackendAdapter backend instance.
        sample_indices: Optional list of qubit indices (0 to 255) to verify.
                        If None, verifies all 256 signature qubits.
        seed_simulator: Optional random seed for reproducible testing.
        session: Optional SessionContext bound into the digest for replay resistance.
        nonce_registry: Optional verifier NonceRegistry. When supplied together with a
            session, the nonce is checked and consumed before quantum verification.
        verifier_id: Identity of the party attempting verification. Triggers an
            authorization check when supplied with master_secret.
        verifier_token: HMAC token presented by that party.
        master_secret: Master secret the token is validated against.
        baseline_error_rate: Calibrated baseline p0. When supplied (or when thresholds are
            given), a three-way ACCEPT / ABORT / REJECT decision is computed.
        thresholds: Optional pre-computed DecisionThresholds.

    Returns:
        SignatureVerificationResult instance. When authorization or freshness fails, the
        quantum stage is skipped entirely and the result carries zero evaluated qubits.
    """
    encoded_qubits = encode_message(message, key_bits, session=session)

    if sample_indices is not None:
        target_qubits = [encoded_qubits[idx] for idx in sample_indices if 0 <= idx < 256]
    else:
        target_qubits = encoded_qubits

    if not target_qubits:
        raise ValueError("No valid signature qubits selected for verification.")

    # --- Stage 1: verifier authorization (O(1), no quantum cost) ---------------------
    authorization = None
    if verifier_id is not None and master_secret is not None:
        authorization = authorize_verifier(
            verifier_id=verifier_id,
            presented_token=verifier_token,
            master_secret=master_secret,
        )
        if not authorization.authorized:
            return SignatureVerificationResult(
                message=message,
                num_qubits=0,
                num_matches=0,
                num_errors=0,
                error_rate=0.0,
                accepted=False,
                results=[],
                decision=None,
                freshness=None,
                authorization=authorization,
            )

    # --- Stage 2: freshness / replay check (O(1), no quantum cost) -------------------
    freshness = None
    if nonce_registry is not None and session is not None:
        freshness = nonce_registry.consume(session)
        if not freshness.is_fresh:
            return SignatureVerificationResult(
                message=message,
                num_qubits=0,
                num_matches=0,
                num_errors=0,
                error_rate=0.0,
                accepted=False,
                results=[],
                decision=None,
                freshness=freshness,
                authorization=authorization,
            )

    # --- Stage 3: quantum verification (O(n)) ----------------------------------------
    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    seeder = ShotSeeder(seed_simulator)

    results: List[TeleportationResult] = []
    num_matches = 0
    num_errors = 0

    for q_record in target_qubits:
        res = verify_encoded_qubit(q_record, backend=backend, seed_simulator=seeder.next())
        results.append(res)

        if res.matched:
            num_matches += 1
        else:
            num_errors += 1

    total_eval = len(target_qubits)
    error_rate = num_errors / total_eval
    accepted = error_rate == 0.0

    # --- Stage 4: three-way threshold decision (O(1)) --------------------------------
    decision = None
    if thresholds is not None or baseline_error_rate is not None:
        decision = decide_signature(
            error_count=num_errors,
            total_trials=total_eval,
            baseline_error_rate=(
                baseline_error_rate
                if baseline_error_rate is not None
                else thresholds.baseline_error_rate
            ),
            thresholds=thresholds,
        )

    return SignatureVerificationResult(
        message=message,
        num_qubits=total_eval,
        num_matches=num_matches,
        num_errors=num_errors,
        error_rate=error_rate,
        accepted=accepted,
        results=results,
        decision=decision,
        freshness=freshness,
        authorization=authorization,
    )
