"""
Integrated Security Evaluation Package for Quantum Digital Signatures.

Provides unified experiment orchestration, result normalization, attack comparison,
and channel tampering sweep evaluation engines for the QDS Security Laboratory.
"""

from .runner import (
    ExperimentResult,
    run_experiment,
    run_security_comparison,
    run_channel_tampering_sweep,
    run_basis_wise_channel_sweep,
)

__all__ = [
    "ExperimentResult",
    "run_experiment",
    "run_security_comparison",
    "run_channel_tampering_sweep",
    "run_basis_wise_channel_sweep",
]

