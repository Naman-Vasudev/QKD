"""
Quantum Digital Signature (QDS) Module.

Contains quantum state preparation, classical message encoding,
3-qubit teleportation, and projective measurement verification logic.
"""

from .states import (
    SUPPORTED_STATES,
    SUPPORTED_BASES,
    apply_state_preparation,
    apply_basis_rotation,
)
from .encoding import (
    sha256_bits,
    encode_message,
)
from .teleportation import (
    build_teleportation_circuit,
    teleport_and_measure,
)
from .verification import (
    verify_encoded_qubit,
    verify_signature,
)
from .circuit_visualization import (
    get_state_math_info,
    build_demonstration_teleportation_circuit,
    draw_circuit_mpl,
    draw_circuit_ascii,
)

__all__ = [
    "SUPPORTED_STATES",
    "SUPPORTED_BASES",
    "apply_state_preparation",
    "apply_basis_rotation",
    "sha256_bits",
    "encode_message",
    "build_teleportation_circuit",
    "teleport_and_measure",
    "verify_encoded_qubit",
    "verify_signature",
    "get_state_math_info",
    "build_demonstration_teleportation_circuit",
    "draw_circuit_mpl",
    "draw_circuit_ascii",
]

