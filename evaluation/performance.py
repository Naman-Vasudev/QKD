"""
Performance and Computational Complexity Measurement.

PURPOSE:
Supplies the measured performance evidence for the framework's efficiency claims. The
protocol is asserted to verify in O(n) time for a signature of length n; this module
measures it rather than asserting it, by timing real executions across a range of n and
fitting the log-log slope.

WHY THE SLOPE IS THE RIGHT STATISTIC:
If duration T scales as T = c * n^k, then log T = log c + k log n. A least-squares fit of
log T against log n recovers k directly:
    k ~ 1.0  linear      O(n)
    k ~ 2.0  quadratic   O(n^2)
    k ~ 0.0  constant    O(1)

EXPECTED COMPLEXITY OF THIS PROTOCOL:
  Stage                        Complexity   Notes
  ---------------------------  -----------  -------------------------------------------
  SHA-256 digest               O(|M|)       Independent of n; one hash per signature.
  Session binding              O(1)         String concatenation plus one hash.
  Encoding (XOR + basis map)   O(n)         One pass over n positions.
  Nonce registry check         O(1)         Hash-set membership test.
  Verifier authorization       O(1)         Single HMAC evaluation.
  Teleport + measure           O(n)         n independent 3-qubit circuits.
  Binomial detector            O(n)         One exact tail evaluation.
  Threat classifier            O(n)         One pass to build the basis profile.
  ---------------------------  -----------  -------------------------------------------
  TOTAL                        O(n)         Dominated by n circuit executions.

The constant factor is dominated by simulator overhead per circuit, not by protocol
arithmetic, so wall-clock timings characterise the simulation environment as much as the
protocol. Circuit-execution counts are reported alongside timings for that reason.

SCIENTIFIC DISCLOSURES:
- Timings are wall-clock measurements on the host machine and will vary between runs and
  between machines. They are reproducible in order of magnitude, not to the millisecond.
- Measurements on a simulator do not predict runtime on physical quantum hardware, where
  queue latency dominates and is outside the protocol's control.
- No artificial intelligence or machine learning is used.
"""

import math
import time
from typing import Any, Dict, List, Optional

from core.backend import QuantumBackendAdapter
from core.models import PerformanceMetrics, ComplexityAnalysis, SessionContext
from qds.encoding import encode_message
from qds.verification import verify_signature


def measure_verification_performance(
    message: str,
    shared_key: List[int],
    signature_length: int = 256,
    shots_per_qubit: int = 1,
    session: Optional[SessionContext] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
) -> PerformanceMetrics:
    """
    Time a full signature verification over a signature of the requested length.

    Args:
        message: Classical message string.
        shared_key: Pre-shared secret key K (256 bits).
        signature_length: Number of signature positions to verify (1 to 256).
        shots_per_qubit: Execution shots per position (>= 1).
        session: Optional SessionContext bound into the digest.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.

    Returns:
        PerformanceMetrics instance.
    """
    if not (1 <= signature_length <= 256):
        raise ValueError(f"Signature length must be in range [1, 256], got {signature_length}.")
    if shots_per_qubit < 1:
        raise ValueError(f"Shots per qubit must be at least 1, got {shots_per_qubit}.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    indices = list(range(signature_length))

    start = time.perf_counter()
    for shot in range(shots_per_qubit):
        verify_signature(
            message=message,
            key_bits=shared_key,
            backend=backend,
            sample_indices=indices,
            seed_simulator=(seed + shot * 1000) if seed is not None else None,
            session=session,
        )
    elapsed = time.perf_counter() - start

    executions = signature_length * shots_per_qubit

    return PerformanceMetrics(
        operation="signature_verification",
        signature_length=signature_length,
        shots_per_qubit=shots_per_qubit,
        total_seconds=elapsed,
        seconds_per_qubit=elapsed / max(1, executions),
        qubits_per_second=(executions / elapsed) if elapsed > 0 else float("inf"),
        circuit_executions=executions,
        backend_name=backend.backend_name,
    )


def measure_encoding_performance(
    message: str,
    shared_key: List[int],
    repetitions: int = 200,
    session: Optional[SessionContext] = None,
) -> PerformanceMetrics:
    """
    Time the purely classical encoding stage (hash, XOR, basis schedule, state mapping).

    Isolating this from circuit execution shows that the classical portion of the protocol
    is negligible: it is microseconds per signature against milliseconds per circuit.

    Args:
        message: Classical message string.
        shared_key: Pre-shared secret key K (256 bits).
        repetitions: Number of encoding passes to average over (>= 1).
        session: Optional SessionContext bound into the digest.

    Returns:
        PerformanceMetrics instance.
    """
    if repetitions < 1:
        raise ValueError(f"Repetitions must be at least 1, got {repetitions}.")

    start = time.perf_counter()
    for _ in range(repetitions):
        encode_message(message, shared_key, session=session)
    elapsed = time.perf_counter() - start

    per_pass = elapsed / repetitions

    return PerformanceMetrics(
        operation="classical_encoding",
        signature_length=256,
        shots_per_qubit=1,
        total_seconds=elapsed,
        seconds_per_qubit=per_pass / 256,
        qubits_per_second=(256 / per_pass) if per_pass > 0 else float("inf"),
        circuit_executions=0,
        backend_name="classical",
    )


def _least_squares_slope(xs: List[float], ys: List[float]) -> tuple:
    """
    Fit y = a + b*x by ordinary least squares.

    Args:
        xs: Independent variable values.
        ys: Dependent variable values.

    Returns:
        Tuple of (slope b, r_squared).
    """
    n = len(xs)
    if n < 2:
        return 0.0, 0.0

    mean_x = sum(xs) / n
    mean_y = sum(ys) / n

    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))

    if sxx == 0:
        return 0.0, 0.0

    slope = sxy / sxx
    intercept = mean_y - slope * mean_x

    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 1.0

    return slope, r_squared


def classify_slope(slope: float) -> str:
    """
    Map a measured log-log slope onto a complexity class label.

    Args:
        slope: Fitted exponent k in T ~ n^k.

    Returns:
        Human-readable complexity classification.
    """
    if slope < 0.35:
        return f"O(1) constant (measured exponent {slope:.3f})"
    if slope < 1.35:
        return f"O(n) linear (measured exponent {slope:.3f})"
    if slope < 1.75:
        return f"O(n log n) near-linear (measured exponent {slope:.3f})"
    if slope < 2.4:
        return f"O(n^2) quadratic (measured exponent {slope:.3f})"
    return f"super-quadratic (measured exponent {slope:.3f})"


def analyze_verification_complexity(
    message: str,
    shared_key: List[int],
    sizes: Optional[List[int]] = None,
    session: Optional[SessionContext] = None,
    backend: Optional[QuantumBackendAdapter] = None,
    seed: Optional[int] = None,
    repeats: int = 3,
    warmup: bool = True,
) -> ComplexityAnalysis:
    """
    Measure empirical runtime scaling of verification across signature lengths.

    BENCHMARK METHODOLOGY:
    A single timing per size is not usable for fitting an exponent. Interpreter warm-up,
    garbage collection, and OS scheduling produce outliers that can distort the fitted
    slope by 50% or more. This function therefore:
      - runs an untimed warm-up pass so imports, caches, and JIT paths are hot,
      - times each size `repeats` times and keeps the MINIMUM.
    The minimum is the standard estimator for this kind of measurement: timing noise is
    strictly additive (interference only ever makes a run slower), so the fastest observed
    run is the closest estimate of true cost.

    Args:
        message: Classical message string.
        shared_key: Pre-shared secret key K (256 bits).
        sizes: Signature lengths to time (default [16, 32, 64, 128, 256]).
        session: Optional SessionContext bound into the digest.
        backend: Optional QuantumBackendAdapter.
        seed: Optional random seed for reproducibility.
        repeats: Timed repetitions per size; the minimum is kept (>= 1).
        warmup: Run one untimed pass before measuring.

    Returns:
        ComplexityAnalysis instance.
    """
    if sizes is None:
        sizes = [16, 32, 64, 128, 256]

    for size in sizes:
        if not (1 <= size <= 256):
            raise ValueError(f"Signature lengths must be in range [1, 256], got {size}.")
    if len(sizes) < 2:
        raise ValueError("At least two sizes are required to fit a scaling exponent.")
    if repeats < 1:
        raise ValueError(f"Repeats must be at least 1, got {repeats}.")

    if backend is None:
        backend = QuantumBackendAdapter("aer_simulator")

    if warmup:
        # Untimed: warms imports, transpilation caches, and allocator state so the first
        # timed size is not penalised relative to the rest.
        measure_verification_performance(
            message=message,
            shared_key=shared_key,
            signature_length=min(sizes),
            shots_per_qubit=1,
            session=session,
            backend=backend,
            seed=seed,
        )

    durations: List[float] = []
    for size in sizes:
        trials = [
            measure_verification_performance(
                message=message,
                shared_key=shared_key,
                signature_length=size,
                shots_per_qubit=1,
                session=session,
                backend=backend,
                seed=seed,
            ).total_seconds
            for _ in range(repeats)
        ]
        durations.append(min(trials))

    # Guard against zero durations, which would make the logarithm undefined.
    safe_durations = [max(d, 1e-9) for d in durations]
    log_sizes = [math.log(s) for s in sizes]
    log_durations = [math.log(d) for d in safe_durations]

    slope, r_squared = _least_squares_slope(log_sizes, log_durations)

    per_qubit = sum(d / s for d, s in zip(durations, sizes)) / len(sizes)

    return ComplexityAnalysis(
        sizes=list(sizes),
        durations=durations,
        log_log_slope=slope,
        r_squared=r_squared,
        classification=classify_slope(slope),
        per_qubit_seconds=per_qubit,
    )


def build_complexity_table() -> List[Dict[str, str]]:
    """
    Return the analytic per-stage complexity table for reporting.

    Returns:
        List of dicts with stage, complexity, and note fields.
    """
    return [
        {
            "stage": "SHA-256 digest",
            "complexity": "O(|M|)",
            "note": "One hash per signature; independent of signature length n.",
        },
        {
            "stage": "Session binding (nonce)",
            "complexity": "O(1)",
            "note": "String concatenation plus one hash.",
        },
        {
            "stage": "Encoding (XOR + basis schedule)",
            "complexity": "O(n)",
            "note": "Single pass over n signature positions.",
        },
        {
            "stage": "Verifier authorization (HMAC)",
            "complexity": "O(1)",
            "note": "One HMAC-SHA256 evaluation, constant-time comparison.",
        },
        {
            "stage": "Nonce freshness check",
            "complexity": "O(1)",
            "note": "Hash-set membership test in the verifier's registry.",
        },
        {
            "stage": "Teleportation + measurement",
            "complexity": "O(n)",
            "note": "n independent 3-qubit circuits; dominates the constant factor.",
        },
        {
            "stage": "Exact binomial detector",
            "complexity": "O(n)",
            "note": "One exact upper-tail evaluation over n trials.",
        },
        {
            "stage": "Threat classification",
            "complexity": "O(n)",
            "note": "One pass to build the basis-resolved error profile.",
        },
        {
            "stage": "TOTAL",
            "complexity": "O(n)",
            "note": "Linear in signature length; no stage exceeds O(n).",
        },
    ]
