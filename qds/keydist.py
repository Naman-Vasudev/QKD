"""
Entanglement-Based Quantum Key Distribution (BBM92) for QDS Key Establishment.

PURPOSE:
Establishes the shared secret key K from quantum measurements instead of assuming a
pre-shared classical key. This supplies the "quantum public key distribution using
Bell-state entanglement" stage of the protocol, and removes the weak-key problem that
arises when K is a fixed or publicly guessable pattern.

PROTOCOL (BBM92 — the entanglement-based equivalent of BB84)
------------------------------------------------------------
For each raw bit:
  1. A Bell state |Phi+> = (|00> + |11>)/sqrt(2) is prepared and split; Alice holds q0,
     Bob holds q1.
  2. Alice and Bob each independently choose a measurement basis at random and measure.
  3. Over an authenticated public channel they disclose their basis choices only.
  4. Positions where the bases disagree are discarded (SIFTING).
  5. A random sample of the surviving positions is disclosed to estimate the QBER; those
     positions are then discarded. The rest becomes the key.

CORRELATION STRUCTURE OF |Phi+>:
    <ZZ> = +1   Z/Z measurements agree            -> key bit = Alice's bit
    <XX> = +1   X/X measurements agree            -> key bit = Alice's bit
    <YY> = -1   Y/Y measurements ANTI-correlate   -> Bob must flip his bit

The Y-basis anti-correlation is a real and easily-missed property of |Phi+>: measuring
Y (x) Y on this state always yields opposite outcomes. Bob therefore applies a NOT to his
Y-basis results during reconciliation. Restricting the protocol to the {Z, X} bases (the
default here) reproduces textbook BB84/BBM92 exactly and avoids the correction entirely.

EAVESDROPPER DETECTION:
An intercept-resend adversary on Bob's arm measures in a basis she must guess.
  - With B bases in use, she guesses correctly with probability 1/B.
  - When she guesses wrong the state collapses and Bob errs with probability 1/2.
  - On sifted bits the expected QBER is therefore (1 - 1/B) * 1/2.
      B = 2 (Z, X):     QBER = 25%     <- textbook BB84 value
      B = 3 (Z, X, Y):  QBER = 33.3%
An honest channel on an ideal simulator yields QBER = 0, so any non-zero QBER is
attributable to eavesdropping or hardware noise. The same exact binomial detector used
for signature verification evaluates the QBER sample.

SCIENTIFIC DISCLOSURES:
- Basis reconciliation and QBER sample disclosure are assumed to occur over an
  authenticated public classical channel, as BBM92 requires. Authenticating that channel
  is out of scope for this prototype.
- No privacy amplification or information reconciliation (e.g. Cascade, LDPC) is
  implemented, so the sifted key is NOT composably secure. It is a faithful simulation of
  the distribution and eavesdropper-detection stages only.
- Measurement outcomes come from actual Qiskit circuit execution; QBER is never hardcoded.
- No artificial intelligence or machine learning is used.
"""

import random
from typing import Dict, List, Optional, Tuple

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister

from core.backend import QuantumBackendAdapter
from core.models import SiftedKeyResult
from core.seeding import ShotSeeder
from qds_statistics.detector import detect_threat
from .states import apply_basis_rotation, apply_state_preparation


# Restricting to {Z, X} reproduces textbook BBM92 with a 25% intercept-resend QBER.
DEFAULT_QKD_BASES: Tuple[str, ...] = ("Z", "X")
ALL_QKD_BASES: Tuple[str, ...] = ("Z", "X", "Y")

# Bases whose two-qubit correlation on |Phi+> is negative, requiring Bob to flip.
ANTI_CORRELATED_BASES = frozenset({"Y"})


def build_bell_pair_measurement_circuit(
    alice_basis: str,
    bob_basis: str,
    eve_basis: Optional[str] = None,
) -> QuantumCircuit:
    """
    Build a Bell-pair distribution and measurement circuit, optionally with an eavesdropper.

    Qubit layout:
        q0: Alice's half of the Bell pair.
        q1: Bob's half of the Bell pair.

    Args:
        alice_basis: Alice's measurement basis ('Z', 'X', or 'Y').
        bob_basis: Bob's measurement basis ('Z', 'X', or 'Y').
        eve_basis: When provided, Eve intercepts Bob's qubit in transit, measures it in
            this basis, and resends a replacement eigenstate matching her outcome.

    Returns:
        Configured QuantumCircuit with classical registers c_a, c_b (and c_e if Eve acts).
    """
    qr = QuantumRegister(2, "q")
    c_a = ClassicalRegister(1, "c_a")
    c_b = ClassicalRegister(1, "c_b")

    if eve_basis is not None:
        c_e = ClassicalRegister(1, "c_e")
        qc = QuantumCircuit(qr, c_e, c_a, c_b, name=f"BBM92_A{alice_basis}_B{bob_basis}_E{eve_basis}")
    else:
        qc = QuantumCircuit(qr, c_a, c_b, name=f"BBM92_A{alice_basis}_B{bob_basis}")

    # 1. Prepare the Bell state |Phi+> = (|00> + |11>) / sqrt(2)
    qc.h(0)
    qc.cx(0, 1)

    # 2. Optional intercept-resend on Bob's arm
    if eve_basis is not None:
        eve_creg = qc.cregs[0]
        apply_basis_rotation(qc, 1, eve_basis)
        qc.measure(1, eve_creg[0])
        qc.reset(1)
        with qc.if_test((eve_creg[0], 0)):
            if eve_basis == "Z":
                apply_state_preparation(qc, 1, "|0>")
            elif eve_basis == "X":
                apply_state_preparation(qc, 1, "|+>")
            else:
                apply_state_preparation(qc, 1, "|+i>")
        with qc.if_test((eve_creg[0], 1)):
            if eve_basis == "Z":
                apply_state_preparation(qc, 1, "|1>")
            elif eve_basis == "X":
                apply_state_preparation(qc, 1, "|->")
            else:
                apply_state_preparation(qc, 1, "|-i>")

    # 3. Alice and Bob rotate into their chosen bases and measure
    apply_basis_rotation(qc, 0, alice_basis)
    apply_basis_rotation(qc, 1, bob_basis)

    alice_creg = qc.cregs[-2]
    bob_creg = qc.cregs[-1]
    qc.measure(0, alice_creg[0])
    qc.measure(1, bob_creg[0])

    return qc


def _read_bits(exec_res: Dict, num_registers: int) -> List[int]:
    """
    Decode single-shot measurement bits from a backend result.

    Qiskit reports classical registers left-to-right in reverse declaration order, so the
    returned list is re-reversed into declaration order.

    Args:
        exec_res: Result dict from QuantumBackendAdapter.run_circuit.
        num_registers: Number of single-bit classical registers declared.

    Returns:
        List of bit values in classical-register declaration order.
    """
    memory = exec_res.get("memory", [])
    raw = memory[0] if memory else list(exec_res["counts"].keys())[0]
    clean = raw.replace(" ", "")
    # clean[0] is the last-declared register; reverse to get declaration order.
    bits = [int(ch) for ch in clean][::-1]
    while len(bits) < num_registers:
        bits.append(0)
    return bits[:num_registers]


def run_key_distribution(
    raw_bits: int = 512,
    bases: Tuple[str, ...] = DEFAULT_QKD_BASES,
    eavesdropper_present: bool = False,
    qber_sample_fraction: float = 0.25,
    baseline_error_rate: float = 0.02,
    alpha: float = 0.05,
    target_key_length: Optional[int] = 256,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> SiftedKeyResult:
    """
    Run entanglement-based quantum key distribution to establish a shared secret key.

    Args:
        raw_bits: Number of Bell pairs to distribute (> 0). Roughly raw_bits / len(bases)
            survive sifting, and a further qber_sample_fraction of those is sacrificed to
            QBER estimation, so budget about 3x the desired key length for 2 bases.
        bases: Measurement bases available to both parties.
        eavesdropper_present: Simulate an intercept-resend adversary on Bob's arm.
        qber_sample_fraction: Fraction of sifted bits disclosed to estimate QBER.
        baseline_error_rate: Calibrated baseline p0 for the binomial detector.
        alpha: Significance threshold for eavesdropper detection.
        target_key_length: Truncate the final key to this length. None keeps everything.
        backend: Optional QuantumBackendAdapter (ideal AerSimulator by default).
        seed: Optional random seed for reproducible basis choices and execution.

    Returns:
        SiftedKeyResult instance.
    """
    if raw_bits <= 0:
        raise ValueError(f"Raw bit count must be positive, got {raw_bits}.")
    if not bases:
        raise ValueError("At least one measurement basis must be supplied.")
    for basis in bases:
        if basis not in ALL_QKD_BASES:
            raise ValueError(f"Unsupported basis '{basis}'. Must be one of {ALL_QKD_BASES}.")
    if not (0.0 <= qber_sample_fraction < 1.0):
        raise ValueError(
            f"QBER sample fraction must be in range [0.0, 1.0), got {qber_sample_fraction}."
        )

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    rng = random.Random(seed)
    seeder = ShotSeeder(seed)

    sifted_alice: List[int] = []
    sifted_bob: List[int] = []

    for index in range(raw_bits):
        alice_basis = rng.choice(bases)
        bob_basis = rng.choice(bases)

        # Sifting discards mismatched bases, so skip the execution entirely — this is the
        # same statistical outcome at a third of the circuit cost.
        if alice_basis != bob_basis:
            continue

        eve_basis = rng.choice(bases) if eavesdropper_present else None

        qc = build_bell_pair_measurement_circuit(
            alice_basis=alice_basis,
            bob_basis=bob_basis,
            eve_basis=eve_basis,
        )
        exec_res = backend.run_circuit(qc, shots=1, seed_simulator=seeder.next())

        num_registers = 3 if eve_basis is not None else 2
        bits = _read_bits(exec_res, num_registers)
        alice_bit = bits[-2]
        bob_bit = bits[-1]

        # |Phi+> anti-correlates under Y (x) Y, so Bob inverts his Y-basis outcomes.
        if alice_basis in ANTI_CORRELATED_BASES:
            bob_bit ^= 1

        sifted_alice.append(alice_bit)
        sifted_bob.append(bob_bit)

    sifted_length = len(sifted_alice)
    if sifted_length == 0:
        raise ValueError(
            "Basis reconciliation discarded every position. Increase raw_bits."
        )

    # --- QBER estimation on a disclosed random sample --------------------------------
    sample_size = int(sifted_length * qber_sample_fraction)
    sample_indices = set(rng.sample(range(sifted_length), sample_size)) if sample_size > 0 else set()

    qber_errors = sum(
        1 for i in sample_indices if sifted_alice[i] != sifted_bob[i]
    )
    qber = (qber_errors / sample_size) if sample_size > 0 else 0.0

    threat_result = None
    if sample_size > 0:
        threat_result = detect_threat(
            error_count=qber_errors,
            total_trials=sample_size,
            baseline_error_rate=baseline_error_rate,
            alpha=alpha,
        )

    # Disclosed positions are burned; the remainder forms the key.
    key_bits = [
        sifted_alice[i] for i in range(sifted_length) if i not in sample_indices
    ]
    if target_key_length is not None:
        key_bits = key_bits[:target_key_length]

    expected_qber = (1.0 - 1.0 / len(bases)) * 0.5 if eavesdropper_present else 0.0

    if eavesdropper_present:
        interpretation = (
            f"EAVESDROPPER SIMULATED: intercept-resend on Bob's arm with {len(bases)} bases in use. "
            f"Theory predicts QBER = (1 - 1/{len(bases)}) x 1/2 = {expected_qber:.4f}; measured QBER "
            f"= {qber:.4f} over {sample_size} disclosed bits. "
            + (
                "The binomial detector flagged the channel, so this key must be discarded."
                if threat_result is not None and threat_result.threat_detected
                else "The disclosed sample was too small to reach significance; disclose more bits."
            )
        )
    else:
        interpretation = (
            f"HONEST CHANNEL: {sifted_length} of {raw_bits} raw bits survived basis reconciliation "
            f"({len(bases)} bases). Measured QBER = {qber:.4f} over {sample_size} disclosed bits. "
            f"An ideal simulator yields QBER = 0 because |Phi+> is perfectly correlated when both "
            f"parties measure in the same basis; any excess is hardware noise or eavesdropping."
        )

    return SiftedKeyResult(
        raw_bits=raw_bits,
        sifted_length=sifted_length,
        key_bits=key_bits,
        sample_size=sample_size,
        qber_errors=qber_errors,
        qber=qber,
        eavesdropper_present=eavesdropper_present,
        threat_result=threat_result,
        bases_used=list(bases),
        interpretation=interpretation,
    )


def establish_signing_key(
    key_length: int = 256,
    bases: Tuple[str, ...] = DEFAULT_QKD_BASES,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
    max_attempts: int = 4,
) -> Tuple[List[int], SiftedKeyResult]:
    """
    Establish a signing key of exactly `key_length` bits via BBM92.

    Distributes enough raw Bell pairs to survive sifting and QBER sampling, retrying with
    a larger budget if the yield falls short.

    Args:
        key_length: Required key length in bits (> 0).
        bases: Measurement bases available to both parties.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed.
        max_attempts: Maximum number of escalating attempts before failing.

    Returns:
        Tuple of (key bits of exactly key_length, final SiftedKeyResult).

    Raises:
        ValueError: If a key of the requested length could not be established.
    """
    if key_length <= 0:
        raise ValueError(f"Key length must be positive, got {key_length}.")

    # Sifting keeps ~1/len(bases); QBER sampling burns 25% of what survives.
    yield_factor = len(bases) / 0.75
    raw_estimate = int(key_length * yield_factor * 1.3) + len(bases) * 8

    result: Optional[SiftedKeyResult] = None
    for attempt in range(max_attempts):
        result = run_key_distribution(
            raw_bits=raw_estimate,
            bases=bases,
            eavesdropper_present=False,
            target_key_length=key_length,
            backend=backend,
            seed=(seed + attempt * 10_000) if seed is not None else None,
        )
        if len(result.key_bits) >= key_length:
            return result.key_bits[:key_length], result
        raw_estimate *= 2

    raise ValueError(
        f"Failed to establish a {key_length}-bit key after {max_attempts} attempts; "
        f"last yield was {len(result.key_bits) if result else 0} bits."
    )
