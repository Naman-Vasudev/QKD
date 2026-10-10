# AUDIT.md

Audit of the Quantum Digital Signature Security Laboratory codebase.
Prepared before making any changes. All claims below are traceable to specific file and line numbers.

---

## 1. What the code actually implements

### Protocol core (`qds/`)

**`encoding.py`**
- Hashes an arbitrary UTF-8 message (with optional session context) using SHA-256 to obtain a 256-bit
  digest.
- XORs each digest bit with the corresponding bit of a pre-shared 256-bit secret key K to produce
  encoded bits b_i = d_i XOR K_i.
- Maps each (b_i, basis_i) pair to one of six Pauli eigenstates across a fully deterministic basis
  schedule: position i uses basis Z (i mod 3 = 0), X (i mod 3 = 1), Y (i mod 3 = 2).
- Note: the basis schedule is completely public and deterministic. Security rests entirely on the
  secrecy of key K, not on basis secrecy.

**`states.py`**
- Implements Qiskit gate sequences to prepare the six Pauli eigenstates (|0>, |1>, |+>, |->, |+i>,
  |-i>) on a given qubit, and to rotate the measurement basis from Z, X, or Y into the computational
  Z basis for readout.
- Mathematically correct. The |-i> preparation (X -> H -> S) is verified.

**`teleportation.py`**
- Builds a 3-qubit circuit: state preparation on q0, Bell pair (|Phi+>) on q1-q2, joint Bell-basis
  measurement on q0-q1 (CNOT then H on q0, measure both), feedforward X and Z corrections on q2
  conditioned on classical bits c1 and c0 respectively, then basis rotation and measurement on q2.
- Executes with `shots=1` per qubit per call via `backend.run_circuit`. For a 256-bit signature this
  means 256 separate single-shot circuit executions, not one batched job.
- Parses results by string manipulation of Qiskit's counts/memory keys. Fragile across Qiskit versions
  (see Bugs section).

**`verification.py`**
- Orchestrates: HMAC-SHA256 authorization check -> nonce freshness check -> 256 sequential
  teleportation calls -> binomial hypothesis test and three-way threshold decision.
- Aborts and returns an AUTH_DENIED or FRESHNESS_FAILED result before any quantum circuit runs if
  classical checks fail. This is correct and efficient.

**`session.py`**
- Implements session nonce binding: payload P = M | signer_id | nonce | counter | timestamp; digest
  D = SHA256(P).
- `NonceRegistry`: an in-memory (Python set + dict) append-only registry. Rejects replayed nonces
  before quantum measurement. State is lost on process restart.
- HMAC-SHA256 verifier authorization, constant-time comparison via `hmac.compare_digest`.

**`keydist.py`**
- Implements BBM92 protocol using Z and X (optionally Y) bases.
- Simulates intercept-resend eavesdropper by inserting an intermediate random-basis measurement.
- Y-basis negative correlation (<YY> = -1) is handled correctly by inverting Bob's Y-basis outcomes.
- Sifting is simulated by skipping circuit execution for mismatched-basis pairs. In a real deployment
  bits would be transmitted then sifted; here circuit runs are skipped before the bases are compared,
  which is a simulation shortcut correctly noted in the code.
- No privacy amplification or information reconciliation.

### Statistical engine (`qds_statistics/`)

**`detector.py`**
- `detect_threat`: exact one-sided binomial test (H0: p = p0, H1: p > p0) via `scipy.stats.binomtest`.
- `compute_decision_thresholds`: derives s_accept = p0 + 3*sigma and s_reject = (s_accept + q_min)/2
  where q_min = 1/3. Also clamps s_accept at 0.5 * q_min if baseline noise is high.
- `decide_signature`: three-way ACCEPT/ABORT/REJECT based on observed error rate vs thresholds.
- The `MIN_MODELLED_ATTACK_ERROR_RATE = 1/3` is the intercept-resend error rate (correct in theory,
  verified in code).

**`classifier.py`**
- Computes basis-resolved error profile (e_Z, e_X, e_Y) and scores against analytic signatures.
- Discriminators: X-basis immunity for channel tampering, Matthews correlation coefficient (MCC)
  between error indicator and key vector for forgery vs impersonation, Hamming distance for replay.
- Deterministic scoring; no ML.

**`bounds.py`**
- Closed-form binomial forgery bound: P_forge(n, s_a) = sum_{j=0}^{floor(s_a*n)} C(n,j)*(1/2)^n.
- Detection power: exact binomial power calculation against each attack's theoretical error rate.
- `ATTACK_ERROR_RATES` dict covers channel tampering, interception, forgery, impersonation, and
  different-message replay. Same-message replay and unauthorized verification are noted as
  deterministic (no statistical error rate applies).

### Attacks (`attacks/`)

**`channel.py`**
- Applies Pauli-X with probability p_attack to q2 before Bob's measurement. Produces the correct
  theoretical basis-resolved profile: (p, 0, p) for (e_Z, e_X, e_Y).

**`forgery.py`**
- Constructs states assuming K = 0 (i.e. b_i = d_i). Errors occur at positions where K_i = 1.
  Predicted error rate = key 1-density (~0.5 for a balanced key).

**`impersonation.py`**
- Randomly guesses each encoded bit. Predicted error rate = 0.5.

**`interception.py`**
- Intercept-resend: Eve measures in a random (or fixed) basis, then sends the post-measurement
  eigenstate. In the `uniform_random` strategy, for each position Eve picks a random basis. When it
  matches Alice's basis (probability 1/3), no error. When it differs (probability 2/3), Bob sees an
  error with probability 1/2. Expected rate = (2/3)(1/2) = 1/3. This matches the circuit implementation.

**`replay.py`**
- Captures legitimate states for M_original, presents them as verification for M_target.
- Different-message: errors at positions where digest bits differ; predicted rate = HD(D, D')/256
  (~0.5 by SHA-256 avalanche). Correct.
- Same-message (legacy mode): error rate is 0 (encoding is deterministic). Correctly documented as
  undetectable without session binding.
- Same-message (freshness mode): nonce registry detects replay in O(1). If Eve uses fresh nonce,
  digest changes, forcing the forgery regime (~0.5 error). Both mechanisms implemented correctly.

**`unauthorized.py`**
- Three profiles: NO_TOKEN, FORGED_TOKEN, WRONG_IDENTITY.
- HMAC-SHA256 checked via constant-time `hmac.compare_digest`. Detected deterministically.

### Evaluation (`evaluation/`)

**`runner.py`**
- `run_experiment`: dispatches to the correct attack module, attaches classification, decision, and
  optional audit logging.
- `run_security_comparison`: executes 8 scenarios (baseline + 7 attacks) with independent per-scenario
  seeds via `derive_seed`.
- `run_channel_tampering_sweep`: sweeps p_attack over a configurable range.
- `run_basis_wise_channel_sweep`: sweeps p_attack and extracts per-basis error rates.

**`performance.py`**
- Times verification across signature lengths. Reports log-log regression slope.
- `build_complexity_table`: analytical O-notation table; values are assertions, not measurements.

### Infrastructure (`core/`)

**`models.py`**: pure dataclasses, no logic.

**`audit.py`**: thread-safe JSONL logger with secret sanitization via field-name matching.

**`seeding.py`**: derives simulator seeds via string-keyed `random.Random` to avoid correlated-seed
bias in Qiskit Aer (correctly explained in docstring).

**`backend.py`**: wraps AerSimulator and FakeBackend providers. IBM hardware integration is present
but requires an API key and is not exercised by the automated tests.

---

## 2. Claims in the README that the code does not fully support

| # | Claim (verbatim or paraphrased) | Assessment |
|---|---|---|
| 1 | "A first-of-its-kind interactive security research platform" | Marketing language; no evidence provided. **Remove.** |
| 2 | "making it theoretically unbreakable even by quantum computers" | Misleading. The protocol's security rests on the no-cloning theorem and the secrecy of key K *within the stated simulation scope*. This is a simulation-based evaluation; no formal security proof is included. Individual-qubit adversaries only. **Rewrite precisely.** |
| 3 | "No quantum computer, however powerful, can copy or intercept these quantum states without leaving a trace. This is guaranteed by the No-Cloning Theorem" | True for the physical principle, but overstates what this *simulation* proves. The code uses Qiskit Aer, which is a classical simulator. No fault-tolerance or physical hardware is modelled. **Qualify.** |
| 4 | "k = 1.01 with R^2 = 0.9997, confirming O(n) at approximately 1.7 ms per position" | Performance numbers come from `evaluation/performance.py`. They are produced by code that runs on the current machine with the current Qiskit version. They are *not* machine-independent and should not be stated as absolutes in the README. **Report with methodology and caveat.** |
| 5 | "193.5 bits of security" | Computed from `bounds.py` via exact binomial formula. Claim is mathematically correct *given the stated assumptions* (uniform random key, adversary has no information about K, individual-qubit attacks only). Not a security proof; formal proofs are out of scope. **State assumptions explicitly.** |
| 6 | "220 unit tests" | Verified by running pytest: `220 passed`. Accurate. |
| 7 | "Detection Power > 0.999999 for Forgery, Impersonation, Interception, Replay" | Computed from `bounds.py`. Correct given the analytic model; power is the exact binomial probability and assumes error rates hit theoretical values exactly. In simulation with finite shots deviations occur. **Qualify as analytic bound, not measured rate.** |
| 8 | "O(n) at approximately 1.7 ms per position" | This is simulator overhead on one specific machine; QPU times are dominated by queue latency. **Already noted in performance.py but not in README.** |
| 9 | "validated on real IBM Quantum QPUs" | The hardware section is optional and requires an API key. Tests do not exercise real QPUs. Main evaluation uses Qiskit Aer. Calling it "validated on real QPUs" in the main README is misleading without context. **Qualify: 3-qubit representative circuit only; full evaluation is simulation-based.** |

---

## 3. Bugs and doubtful design choices

### B1 — Brittle counts-key parsing in `teleportation.py` and `keydist.py` (MEDIUM)
Both files parse Qiskit result strings using:
```python
counts_key = list(exec_res["counts"].keys())[0].replace(" ", "")
c2_val = int(counts_key[0])
```
The order and spacing of classical register bits in Qiskit's output has changed across versions. The
current code assumes `c2` is bit index 0, `c1` is index 1, `c0` is index 2 (reading left-to-right in
the counts string). This is correct for the current register declaration order (c0, c1, c2 added in that
order), but it is version-sensitive and not validated against Qiskit's register ordering semantics.
**Not a logic bug in the current version, but a maintenance risk.**

### B2 — `audit.py` sanitize_detail does not recurse into lists (LOW)
`sanitize_detail` in `core/audit.py` recursively handles nested dicts but not lists of dicts. If a
caller logs a detail containing `{"results": [{"key": value, "secret_key_bits": [...]}]}`, the
`secret_key_bits` field inside the list is not redacted.
**Not currently triggered because callers log scalar or top-level-dict details, but is a latent risk.**

### B3 — One circuit per qubit, per shot (PERFORMANCE, not correctness)
`verify_signature` calls `teleport_and_measure` 256 times individually, each submitting one 3-qubit
circuit to Qiskit Aer with `shots=1`. Qiskit Aer can batch many circuits in a single `backend.run`
call, which would be orders of magnitude faster. For the purposes of this simulation-based evaluation
this is not a bug (results are correct), but it is why verification takes seconds rather than
milliseconds and why the measured "1.7 ms per position" is largely Python overhead, not circuit
execution time.
**Not a correctness bug. Noted for any reader who interprets performance numbers.**

### D1 — Deterministic basis schedule (DESIGN CHOICE, DOCUMENTED)
The basis for each of the 256 positions is `i mod 3`. This is fully public. Security relies entirely
on key K, not basis secrecy. This is explicitly stated in the code docstrings. It differs from
BB84/BBM92 where basis secrecy provides an additional layer, but this is an accepted design choice for
a digest-based QDS and is consistent with the threat model (adversary does not know K).

### D2 — Intercept-resend skips circuit for matching-basis positions (SIMULATION SHORTCUT)
In `interception.py` and `keydist.py`, when Eve's basis matches Alice's, the code skips re-measuring
and marks the position as a match. In a real implementation the circuit would still run; the result
just happens to be correct. The simulation outcome is correct but the circuit execution count is lower
than in reality.

### D3 — `NonceRegistry` is in-memory only (DEPLOYMENT LIMITATION)
Registry state is lost on process restart. Acceptable for a simulation/demo context; must be persisted
to a database for any real deployment. The code does not claim persistence.

### D4 — s_reject threshold derivation (DOUBTFUL FOR SOME PARAMETERS)
`s_reject = (s_accept + q_min) / 2` is designed so that intercept-resend (q = 1/3) always exceeds
`s_reject`. However, if a user sets `p0` high (e.g., p0 = 0.15), the clamping logic caps `s_accept`
at `q_min * 0.5 = 1/6 ≈ 0.167` and `s_reject` at `(0.167 + 0.333) / 2 = 0.25`. For the baseline
p0 = 0.15, the 3-sigma bound is 0.15 + 3*sqrt(0.15*0.85/256) ≈ 0.217, which exceeds the ceiling and
gets clamped. The clamping is intentional and correct, but means the ACCEPT band becomes very narrow
when p0 is high. This is documented in the code but is a confusing user experience.

---

## 4. Summary of what is NOT implemented

- No formal security proof (the code is a simulation-based evaluation).
- No privacy amplification or information reconciliation in QKD.
- No transferability / non-repudiation (this is a two-party shared-key scheme).
- No coherent or collective attacks (only individual-qubit adversary model).
- No authenticated classical channel (assumed, not implemented).
- `NonceRegistry` is in-memory; not persistent across restarts.
- Full 256-position experiments run on Qiskit Aer (classical simulation); hardware validation uses a
  representative 3-qubit circuit only.
- Simulator performance numbers are machine- and version-dependent; not independently reproducible
  without specifying the exact environment.
