"""
Statistical Cyber Threat Detection Package for Quantum Digital Signatures.

Provides:
- Exact non-ML Binomial hypothesis testing for channel anomaly detection (detector).
- Two-threshold ACCEPT / ABORT / REJECT verification decision rules (detector).
- Basis-resolved threat classification across all modelled attacks (classifier).
- Information-theoretic forgery probability bounds and detector power (bounds).

NOTE ON THE PACKAGE NAME:
This package is deliberately named `qds_statistics` rather than `statistics`. A top-level
package named `statistics` shadows the Python standard library module of the same name for
every module in the process, because the application directory is prepended to sys.path.
"""

from .detector import (
    MIN_MODELLED_ATTACK_ERROR_RATE,
    calibrate_baseline,
    detect_threat,
    compute_decision_thresholds,
    decide_signature,
)
from .classifier import (
    BASES,
    THREAT_DISPLAY_NAMES,
    matthews_correlation,
    minimum_trials_for_resolution,
    build_basis_error_profile,
    classify_threat,
)
from .bounds import (
    ATTACK_ERROR_RATES,
    key_success_probability,
    forgery_success_probability,
    forgery_bound_curve,
    critical_error_count,
    detection_power,
    detection_power_curve,
    attack_detection_summary,
)

__all__ = [
    "MIN_MODELLED_ATTACK_ERROR_RATE",
    "calibrate_baseline",
    "detect_threat",
    "compute_decision_thresholds",
    "decide_signature",
    "BASES",
    "THREAT_DISPLAY_NAMES",
    "matthews_correlation",
    "minimum_trials_for_resolution",
    "build_basis_error_profile",
    "classify_threat",
    "ATTACK_ERROR_RATES",
    "key_success_probability",
    "forgery_success_probability",
    "forgery_bound_curve",
    "critical_error_count",
    "detection_power",
    "detection_power_curve",
    "attack_detection_summary",
]
