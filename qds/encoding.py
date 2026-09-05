"""
Classical Preprocessing and Message-to-Quantum Encoding Module.

SCIENTIFIC DISCLOSURES:
- SHA-256 is used as a deterministic classical hashing preprocessor for arbitrary payload string M.
- SHA-256 does NOT constitute a quantum digital signature by itself.
- The pre-shared secret key K is required to provide authentication and unforgeability;
  without K, anyone could construct valid quantum states for an arbitrary digest.
"""

import hashlib
from typing import List
from core.models import EncodedQubit


def sha256_bits(message: str) -> List[int]:
    """
    Compute the SHA-256 digest of a UTF-8 message and return it as a list of 256 bits.

    Args:
        message: Classical payload text string (e.g., "ABC").

    Returns:
        List of 256 integers (each 0 or 1).
    """
    digest_bytes = hashlib.sha256(message.encode("utf-8")).digest()
    bits: List[int] = []
    for byte in digest_bytes:
        for bit_index in range(7, -1, -1):
            bits.append((byte >> bit_index) & 1)
    return bits


def encode_message(message: str, key_bits: List[int]) -> List[EncodedQubit]:
    """
    Encode a classical message string into 256 Quantum Digital Signature records.

    Encoding Protocol:
    1. Compute D = SHA-256(message) -> 256 digest bits d_i.
    2. Compute b_i = d_i XOR K_i for each bit index i in 0..255.
    3. Select basis B_i using deterministic schedule:
       - i % 3 == 0 -> Basis 'Z'
       - i % 3 == 1 -> Basis 'X'
       - i % 3 == 2 -> Basis 'Y'
    4. Map (encoded_bit b_i, Basis B_i) to Pauli eigenstate and expected eigenvalue:
       - Basis Z: b=0 -> |0> (+1), b=1 -> |1> (-1)
       - Basis X: b=0 -> |+> (+1), b=1 -> |-> (-1)
       - Basis Y: b=0 -> |+i> (+1), b=1 -> |-i> (-1)

    Args:
        message: UTF-8 input string.
        key_bits: List of 256 integers (0 or 1) representing secret shared key K.

    Returns:
        List of 256 EncodedQubit objects.
    """
    if len(key_bits) != 256:
        raise ValueError(f"Secret key must contain exactly 256 bits, got {len(key_bits)}.")
    for bit in key_bits:
        if bit not in (0, 1):
            raise ValueError("All key bits must be 0 or 1.")

    digest = sha256_bits(message)
    encoded_qubits: List[EncodedQubit] = []

    for i in range(256):
        d_i = digest[i]
        k_i = key_bits[i]
        b_i = d_i ^ k_i

        rem = i % 3
        if rem == 0:
            basis = "Z"
            if b_i == 0:
                state_label = "|0>"
                expected_eigenvalue = +1
            else:
                state_label = "|1>"
                expected_eigenvalue = -1
        elif rem == 1:
            basis = "X"
            if b_i == 0:
                state_label = "|+>"
                expected_eigenvalue = +1
            else:
                state_label = "|->"
                expected_eigenvalue = -1
        else:  # rem == 2
            basis = "Y"
            if b_i == 0:
                state_label = "|+i>"
                expected_eigenvalue = +1
            else:
                state_label = "|-i>"
                expected_eigenvalue = -1

        record = EncodedQubit(
            index=i,
            digest_bit=d_i,
            key_bit=k_i,
            encoded_bit=b_i,
            basis=basis,
            state_label=state_label,
            expected_eigenvalue=expected_eigenvalue,
        )
        encoded_qubits.append(record)

    return encoded_qubits
