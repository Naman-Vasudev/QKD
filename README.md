# Quantum Digital Signature (QDS) Simulation and Threat Detection Testbed

This repository provides an open simulation and benchmarking testbed for a teleportation-based Quantum Digital Signature (QDS) scheme, developed in Python with Qiskit and Streamlit. The system models signature generation, quantum teleportation of Pauli eigenstates, exact non-machine-learning statistical anomaly detection, deterministic basis-resolved threat classification, and classical session-nonce freshness binding.

**Central Research Question:**
*How does hardware noise limit detection in a teleportation-based QDS, and can a session nonce close the same-message replay gap?*

> **Note on Origins and Attribution:** This project originated as a team submission for Smart India Hackathon 2026 (Problem Statement 5: Quantum-Inspired Cyber Threat Detection for Digital Signature Security; Team Ghost Protocol / EGRESO QUANTA) and was subsequently expanded into an experimental testbed. Repository: [https://github.com/Naman-Vasudev/QKD.git](https://github.com/Naman-Vasudev/QKD.git).

---

## Threat Model and Assumptions

### Protocol Setup
1. **Key Establishment:** Alice and Bob share a secret key vector $K \in \{0, 1\}^{256}$, either pre-shared or established via entanglement-based BBM92 Quantum Key Distribution.
2. **Payload Binding:** The classical message $M$ is bound to a signer identifier, counter, timestamp, and single-use session nonce $N$:
   $$P = M \parallel \text{signer\_id} \parallel N \parallel \text{counter} \parallel \text{timestamp}$$
   The bound digest is $D = \text{SHA-256}(P)$.
3. **State Encoding:** Each digest bit $d_i$ is combined with key bit $K_i$ via $b_i = d_i \oplus K_i$. Bit $b_i$ selects an eigenstate from one of six Pauli states across a deterministic public basis schedule ($i \pmod 3 \in \{Z, X, Y\}$):
   - $Z$: $|0\rangle$ ($+1$), $|1\rangle$ ($-1$)
   - $X$: $|+\rangle$ ($+1$), $|-\rangle$ ($-1$)
   - $Y$: $|+i\rangle$ ($+1$), $|-i\rangle$ ($-1$)
4. **Transmission:** Alice teleports each state to Bob using sequential 3-qubit teleportation circuits with Bell-state measurements and feedforward Pauli corrections ($X^{c_1} Z^{c_0}$).
5. **Verification:** Bob measures each received state in Alice's assigned basis. In a noiseless channel with a legitimate signature, measurement eigenvalues match expectations with probability 1.0. Observed error counts are evaluated using exact one-sided Binomial hypothesis testing ($H_0: p = p_0$ vs $H_1: p > p_0$).

### Adversary Capabilities and Threat Classes
The adversary Eve sits on the quantum channel between Alice and Bob under an individual-qubit attack model:
1. **Channel Tampering:** Injects physical bit-flip noise (Pauli-$X$) on the transmission channel with probability $p$.
2. **Signature Forgery:** Knows message $M$ and digest $D$, but does not know secret key $K$. Attempts state preparation assuming $K = 0$.
3. **Impersonation:** Randomly guesses encoded states ($\text{Bernoulli}(0.5)$) without knowledge of $K$.
4. **Quantum Interception (Intercept-Resend):** Measures transmitted qubits in randomly selected bases and re-sends the collapsed eigenstates.
5. **Replay Attacks:** Captures a previously valid quantum signature:
   - *Different-Message Replay:* Replays a captured signature for message $M'$ against target message $M$.
   - *Same-Message Replay (Legacy Mode):* Replays captured states verbatim without session binding.
   - *Same-Message Replay (Protected Mode):* Replays captured states against an append-only NonceRegistry.
6. **Unauthorized Verification:** An adversary attempts verification without a valid constant-time HMAC-SHA256 token.

### Explicit Cryptographic Assumptions
- The public classical channel used for BBM92 sifting and teleportation correction bits is assumed to be authenticated.
- Coherent, collective, and adaptive quantum attacks are not modeled.
- Security against forgery rests on the secrecy of key $K$ and the no-cloning theorem; this repository provides a simulation-based evaluation, not a formal security proof.
- The baseline noise rate $p_0$ is a calibrated experimental parameter, not a universal constant.

---

## Experimental Results

All experiments below were generated using Qiskit Aer (`AerSimulator`) with fixed random seed `20260101` via `python evaluation/make_results.py`. Data points represent repeated independent runs (20 repeats per point) with Wilson 95% confidence intervals.

### Figure 1: Detection Rate vs. Channel Tampering Strength
![Detection Rate vs Channel Tampering](assets/results/fig1_detection_vs_attack_strength.png)
*Data source: [`results/detection_vs_attack_strength.csv`](results/detection_vs_attack_strength.csv)*

**Observation:** At baseline calibration $p_0 = 0.02$ and $\alpha = 0.05$ ($n = 64$), the detection rate is 0.00 at $p = 0.00$, rises to 0.55 at $p = 0.075$, reaches 0.85 at $p = 0.150$, and achieves 1.00 for $p \ge 0.225$. Weak channel disturbances below $p \approx 0.05$ remain difficult to distinguish from baseline noise under finite sampling.

### Figure 2: Observed Error Rate vs. Injected Baseline Noise
![Observed Error Rate vs Injected Noise](assets/results/fig2_error_rate_vs_noise.png)
*Data source: [`results/error_rate_vs_noise.csv`](results/error_rate_vs_noise.csv)*

**Observation:** Under legitimate traffic subjected to physical Pauli-$X$ channel noise at probability $p_{\text{noise}}$, the observed error rate follows $\frac{2}{3} p_{\text{noise}}$ (e.g., mean error 0.0328 at $p = 0.05$, 0.0570 at $p = 0.10$, and 0.1094 at $p = 0.15$). This matches theory because Pauli-$X$ transforms $Z$ and $Y$ eigenstates but leaves the $X$ basis undisturbed.

### Figure 3: Detector False-Positive Rate Under Calibrated Noise
![False Positive Rate Under Noise](assets/results/fig3_false_positive_rate.png)
*Data source: [`results/false_positive_rate.csv`](results/false_positive_rate.csv)*

**Observation:** When the detector's baseline parameter $p_0$ is correctly calibrated to the channel noise level, the false-positive rate across 20 trials per level is 0.00 for 14 of 16 tested levels and 0.05 for two levels ($p = 0.01$ and $p = 0.10$). The empirical false-alarm rate is consistent with the nominal significance threshold $\alpha = 0.05$.

### Figure 4: Detection Rate vs. Signature Length ($n$)
![Detection Rate vs Signature Length](assets/results/fig4_detection_vs_n.png)
*Data source: [`results/detection_vs_n.csv`](results/detection_vs_n.csv)*

**Observation:** Signature forgery and random impersonation achieve a 1.00 detection rate across all tested signature lengths ($n \in \{16, 32, 64, 128, 256\}$) due to their ~50% error rate. Interception achieves 0.90 detection at $n = 16$ and 1.00 for $n \ge 32$, whereas channel tampering at $p = 0.20$ (error rate $\approx 13.3\%$) requires $n \ge 128$ to achieve a 1.00 detection rate.

### Figure 5: Replay Attack Scenarios and Nonce Binding
![Replay Attack Scenarios](assets/results/fig5_replay_scenarios.png)
*Data source: [`results/replay_scenarios.csv`](results/replay_scenarios.csv)*

**Observation:** Without session binding, same-message replay produces an observed error rate of 0.0000 and is undetectable by measurement alone. Binding a session nonce allows the verifier's `NonceRegistry` to block the replay classically in $\mathcal{O}(1)$ time prior to quantum measurement, while different-message replay produces a mean error rate of 0.5469 (theoretical 0.5352) and is detected with 1.00 probability.

---

## Known Limitations

1. **Simulation vs. Physical Hardware:** The full 256-qubit protocol evaluation runs entirely in simulation using Qiskit Aer. Real hardware execution via IBM Quantum is supported only for single representative 3-qubit teleportation primitives due to device queue latency and gate noise.
2. **Two-Party Authentication Only:** The secret key $K$ is shared symmetrically between Alice and Bob. Consequently, Bob possesses sufficient information to forge any signature that Alice could create. The protocol does not provide non-repudiation or multi-party transferability without asymmetric key partitioning (e.g., Gottesman-Chuang style schemes).
3. **No Composable Key Security:** While the BBM92 module simulates Bell-state measurements, sifting, and QBER threshold estimation, it does not implement classical information reconciliation (error correction) or privacy amplification.
4. **Restricted Adversary Model:** The threat simulation models only individual-qubit operations. Coherent, collective, and adaptive quantum measurement attacks are outside the scope of this implementation.
5. **Classical Freshness Dependencies:** The replay resistance mechanism and authorization checks rely on classical primitives (`secrets`, SHA-256, HMAC-SHA256). These provide computational and architectural guarantees rather than information-theoretic bounds.
6. **In-Memory Registry:** The `NonceRegistry` stores consumed nonces in volatile process memory and does not persist state across restarts.
7. **Noise Calibration Requirement:** The statistical decision engine requires an explicitly calibrated baseline error rate $p_0$. Disturbances weaker than the calibrated baseline noise floor are information-theoretically indistinguishable from channel noise.

---

## Reproducibility

### Environment Setup
```bash
git clone https://github.com/Naman-Vasudev/QKD.git
cd QKD
python -m venv .venv

# Linux / macOS
source .venv/bin/activate
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### Reproducing Benchmark Experiments
To regenerate all 5 CSV data tables in `results/` and PNG figures in `assets/results/`:
```bash
python evaluation/make_results.py
```

### Running Test Suite
To execute the automated regression test suite (220 tests):
```bash
pytest
```

### Running Interactive Web Laboratory
```bash
streamlit run app.py
```

---

## Project Structure

```
.
├── app.py                     # Streamlit web application (12 interactive modules)
├── requirements.txt           # Dependencies (qiskit, qiskit-aer, scipy, streamlit, etc.)
├── AUDIT.md                   # Pre-submission codebase audit and claim validation
├── qds/                       # Protocol core implementation
│   ├── encoding.py            # SHA-256 preprocessing, session binding, XOR key encoding
│   ├── states.py              # 6 Pauli eigenstate preparation and basis rotations
│   ├── teleportation.py       # 3-qubit teleportation circuit construction and execution
│   ├── verification.py        # End-to-end verification pipeline (Auth -> Freshness -> Quantum)
│   ├── session.py             # NonceRegistry, session binding, and HMAC authorization
│   └── keydist.py             # BBM92 entanglement-based quantum key distribution
├── core/                      # Infrastructure and execution
│   ├── backend.py             # Qiskit Aer and IBM noise model backend adapter
│   ├── hardware.py            # IBM Quantum cloud authentication and QPU discovery
│   ├── seeding.py             # Unbiased PRNG seed derivation for simulator shots
│   ├── models.py              # Dataclasses and type definitions
│   └── audit.py               # Append-only JSONL security event logger
├── attacks/                   # Attack simulation modules
│   ├── channel.py             # Pauli-X channel tampering simulation
│   ├── forgery.py             # Digest-only signature forgery simulation
│   ├── impersonation.py       # Random guessing impersonation simulation
│   ├── interception.py        # Intercept-resend eavesdropping simulation
│   ├── replay.py              # Nonce-aware replay attack simulations
│   └── unauthorized.py        # Unauthorized verifier access simulation
├── qds_statistics/            # Statistical decision engine (non-ML)
│   ├── detector.py            # Exact Binomial hypothesis testing and decision thresholds
│   ├── classifier.py          # Basis-resolved error profiling and threat classification
│   └── bounds.py              # Analytical forgery probability and detection power bounds
├── evaluation/                # Benchmarking and experimental scripts
│   ├── make_results.py        # Reproducible experiment runner generating CSVs and figures
│   ├── runner.py              # Unified scenario dispatcher and multi-attack sweeps
│   └── performance.py         # Empirical runtime complexity measurement
├── tests/                     # 220 automated unit tests
├── results/                   # Generated experimental CSV data tables
└── assets/results/            # Generated high-resolution experiment plots
```

---

## My Contribution

I designed the evaluation experiments, formulated the threat scenarios and statistical decision criteria, and directed the architecture and implementation. The codebase was developed using AI-assisted pair programming. This project began as part of a Smart India Hackathon 2026 team submission (Team Ghost Protocol / EGRESO QUANTA) and was subsequently refined into an open simulation and benchmarking testbed.

---

## License

MIT License. Free to use, modify, and distribute with attribution.
