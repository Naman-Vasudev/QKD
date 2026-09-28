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
from .performance import (
    measure_verification_performance,
    measure_encoding_performance,
    analyze_verification_complexity,
    classify_slope,
    build_complexity_table,
)

__all__ = [
    "ExperimentResult",
    "run_experiment",
    "run_security_comparison",
    "run_channel_tampering_sweep",
    "run_basis_wise_channel_sweep",
    "measure_verification_performance",
    "measure_encoding_performance",
    "analyze_verification_complexity",
    "classify_slope",
    "build_complexity_table",
]

