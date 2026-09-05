"""
Statistical Cyber Threat Detection Package for Quantum Digital Signatures.

Provides exact non-ML Binomial hypothesis testing for channel anomaly detection.
"""

from .detector import calibrate_baseline, detect_threat

__all__ = [
    "calibrate_baseline",
    "detect_threat",
]
