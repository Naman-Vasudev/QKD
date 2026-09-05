"""
Cyber Threat Attack Simulation Package for Quantum Digital Signatures.

Provides physical quantum channel tampering (bit-flip noise injection),
signature forgery, impersonation, and quantum interception (intercept-resend) attack simulations.
"""

from .channel import (
    apply_bit_flip_channel,
    run_single_qubit_channel_attack,
    run_channel_attack,
)
from .forgery import (
    create_forged_encoded_qubits,
    run_forgery_attack,
)
from .impersonation import (
    create_impersonation_encoded_qubits,
    run_impersonation_attack,
)
from .interception import (
    select_eve_basis,
    build_intercepted_teleportation_circuit,
    run_single_qubit_interception_attack,
    run_interception_attack,
)
from .replay import (
    capture_legitimate_signature,
    compute_digest_hamming_distance,
    run_replay_attack,
)

__all__ = [
    "apply_bit_flip_channel",
    "run_single_qubit_channel_attack",
    "run_channel_attack",
    "create_forged_encoded_qubits",
    "run_forgery_attack",
    "create_impersonation_encoded_qubits",
    "run_impersonation_attack",
    "select_eve_basis",
    "build_intercepted_teleportation_circuit",
    "run_single_qubit_interception_attack",
    "run_interception_attack",
    "capture_legitimate_signature",
    "compute_digest_hamming_distance",
    "run_replay_attack",
]

