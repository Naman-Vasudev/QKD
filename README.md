# Quantum Digital Signature Security Laboratory

> **A first-of-its-kind interactive security research platform that lets you sign messages using the laws of quantum physics — and then watch hackers fail to break it.**

Built for **Smart India Hackathon 2026 (SIH2026)** · Powered by **IBM Quantum + Qiskit** · Runs in your browser

---

## What Is This? (Plain English)

Imagine you want to send someone a signed document and you need to prove:
1. **You** actually wrote it (not a hacker pretending to be you)
2. The document **wasn't tampered with** during delivery
3. Nobody can **reuse your signature** on a different document later

Traditional digital signatures (like those on your bank transactions) rely on mathematical problems that future quantum computers could solve. This lab explores a **quantum-powered alternative** that uses the fundamental laws of physics — making it theoretically unbreakable even by quantum computers.

This website is a **live, interactive laboratory** where you can:
- Sign messages using quantum physics
- Launch real cyberattacks against the system
- Watch whether the system detects and blocks those attacks
- Run the actual quantum circuits on **real IBM Quantum computers** in the cloud

---

## The Big Idea: Quantum Digital Signatures

A **Quantum Digital Signature (QDS)** works like this:

1. **Your message** gets hashed (converted into a unique fingerprint using SHA-256)
2. **Each bit of that fingerprint** gets encoded into a quantum state — a tiny particle that can exist in multiple states at once (superposition)
3. These quantum states are **teleported** to the receiver using quantum entanglement
4. The receiver **measures** the quantum states — and any tampering disturbs the particles in a detectable way
5. A **statistical test** checks whether the received pattern matches what was sent — flagging any anomaly as a potential attack

No quantum computer, however powerful, can copy or intercept these quantum states without leaving a trace. This is guaranteed by the **laws of physics** (the No-Cloning Theorem), not just hard math.

---

## What Can You Do on This Website?

The lab has **12 sections** accessible from the left sidebar:

---

### 1. Overview

A high-level explanation of what Quantum Digital Signatures are, why they matter for future cybersecurity, and how this lab demonstrates the concept. Great starting point if you are new to the topic.

---

### 2. Protocol — How Signing Actually Works

Opens on the **Mathematical Model**: the formal protocol description with rendered equations — Bell-state entanglement, the teleportation expansion in the Bell basis, Pauli correction operations, projective measurement operators, the two-threshold decision rule, and the derived error rate of every attack. The full derivation lives in [`docs/mathematical_model.md`](docs/mathematical_model.md).

Then a step-by-step walkthrough of the complete QDS process:

| Step | What Happens |
|------|-------------|
| **Message Input** | Type any message (e.g. "Transfer Rs 10,000 to Ojas") |
| **SHA-256 Hashing** | The message gets converted into a 256-bit unique fingerprint |
| **Quantum Encoding** | Each bit is encoded into a quantum particle state (one of 6 possible states) |
| **Quantum Teleportation** | The state is transmitted using a 3-qubit quantum teleportation circuit |
| **Measurement** | The receiver measures each particle in the correct basis (Z, X, or Y) |
| **Verification** | A statistical test confirms whether the received signature is authentic |

You can change the message, the quantum state, and the measurement basis — and see the circuit diagram update in real time.

---

### 3. Key Distribution — Establish the Key with Quantum Physics

Rather than assuming a pre-shared key, this section establishes it with **BBM92**, the entanglement-based equivalent of BB84:

1. A Bell pair is prepared and split between the two parties
2. Each measures in an independently chosen random basis
3. Bases are compared publicly; mismatches are discarded (**sifting**)
4. A random sample is disclosed to estimate the **QBER**, then discarded
5. The remainder becomes the key

Switch on the intercept-resend eavesdropper and watch the QBER jump to the predicted `(1 − 1/B)/2` — **25%** with two bases, **33.3%** with three. An honest channel gives exactly 0% on the ideal simulator.

> Note: |Φ⁺⟩ *anti*-correlates under Y⊗Y (⟨YY⟩ = −1), so the receiver inverts Y-basis outcomes during reconciliation. Getting this wrong produces a 100% error rate on Y-sifted positions.

---

### 4. Quantum Lab — Run Experiments

This is the heart of the lab. You can run **256-qubit simulations** and tune every parameter:

- **Number of signature bits** — how long the signature is (more bits = more secure)
- **Number of shots** — how many times to run the experiment (more = more accurate statistics)
- **Quantum backend** — choose between ideal simulation, noise-affected simulation, or real hardware
- **Noise level** — introduce realistic hardware noise and see how it affects security

The lab shows you:
- Live **measurement outcome charts** (what the quantum computer actually measured)
- **Fidelity score** — how close the received state is to what was sent (1.0 = perfect, lower = noise/attack)
- **Verification result** — PASS or FAIL
- Full **circuit diagrams** rendered as professional quantum circuit art

---

### 5. Hardware Validation — Run on Real IBM Quantum Computers

This section connects to **real quantum hardware** hosted by IBM in data centres around the world.

**What you need:**
- A free IBM Quantum account at quantum.ibm.com
- Your **API Key** from your IBM Cloud dashboard
- Your **Instance CRN** (the resource identifier from your IBM Quantum instance)

**What happens when you connect:**
- The lab authenticates to IBM's quantum cloud
- It discovers which physical quantum computers (QPUs) are available for your account
- You select a QPU — e.g. `ibm_fez` (156 qubits), `ibm_marrakesh` (156 qubits), or `ibm_kingston` (156 qubits)
- Your quantum circuit is **transpiled** (optimised for the specific hardware) and submitted to the cloud queue
- When the physical QPU runs your circuit, results come back and are compared side-by-side against ideal simulation

**Don't want to wait in the cloud queue?**
Select **IBM Realistic QPU Noise Simulators (Offline / Instant)** instead. These run on your own machine in 1-2 seconds but use the same calibrated noise data from real IBM hardware — so results are nearly identical to running on the actual QPU.

**Available QPUs (IBM Open Plan — Free):**

| QPU Name | Qubits | Processor Type |
|----------|--------|----------------|
| `ibm_fez` | 156 | Heron r2 |
| `ibm_marrakesh` | 156 | Heron r2 |
| `ibm_kingston` | 156 | Heron r2 |

**Available Offline Noise Simulators (Instant):**

| Simulator | Based On | Qubits |
|-----------|---------|--------|
| `fake_fez` | IBM Fez calibration data | 156 |
| `fake_marrakesh` | IBM Marrakesh calibration data | 156 |
| `fake_kingston` | IBM Kingston calibration data | 156 |
| `fake_brisbane` | IBM Brisbane calibration data | 127 |
| `fake_torino` | IBM Torino calibration data | 133 |
| `fake_sherbrooke` | IBM Sherbrooke calibration data | 127 |

---

### 6. Security Lab — Attack the System

This is the most exciting section. You can **launch 6 different cyberattacks** against the QDS system and watch whether the built-in detector catches them.

#### Attack 1: Channel Tampering (Bit-Flip)

**What it simulates:** An attacker intercepts the quantum channel and flips some bits during transmission (like a man-in-the-middle attack).

**What happens:** The tampered bits cause measurement anomalies. The Binomial detector flags the error rate as statistically impossible under normal noise, raising a threat alert.

---

#### Attack 2: Signature Forgery

**What it simulates:** Eve (the attacker) tries to forge your signature by guessing your secret key is all zeros.

**What happens:** Without knowing your actual secret key, Eve's forged signature has ~50% errors — immediately detected as fraudulent.

---

#### Attack 3: Impersonation

**What it simulates:** Eve tries to impersonate you by randomly guessing what quantum states you sent.

**What happens:** Random guessing produces ~50% error rate. The statistical test has near-100% detection probability.

---

#### Attack 4: Quantum Interception (Intercept-Resend)

**What it simulates:** Eve intercepts each quantum particle, measures it in a random basis, and re-sends a new particle. This is the quantum equivalent of wiretapping.

**What happens:** Eve's basis matches the sender's for 1/3 of positions (no disturbance) and differs for the other 2/3, where measurement collapses the state and the receiver errs half the time. The resulting error rate is exactly **1/3 (≈33.3%)** — the famous **quantum eavesdropping detection** principle, and a direct consequence of the no-cloning theorem.

---

#### Attack 5: Replay Attack

**What it simulates:** Eve captures a valid signed message and tries to reuse it later (e.g. send the same "Transfer Rs 10,000" message again).

**What happens:**
- **Different message replay** — SHA-256 avalanche effect causes ~50% bit difference, detected immediately
- **Same message replay** — **detected** via the session nonce bound into the digest. The verifier's nonce registry rejects the reused nonce in O(1), before any quantum state is measured. If Eve substitutes a fresh nonce to evade the registry, the digest changes and she must re-derive all 256 states without the key — which is the forgery problem, detected at ~50% error.

The lab runs both the legacy (unbound) and protected (nonce-bound) modes side by side so you can see exactly what the freshness mechanism buys.

---

#### Attack 6: Unauthorized Verification Attempt

**What it simulates:** A party tries to verify a signature without being entitled to — presenting no token, a fabricated token, or a token validly issued to someone else.

**What happens:** Verification is gated by an HMAC-SHA256 authorization token compared in constant time. All three profiles are denied **deterministically** (no statistical uncertainty, no false positives) and, critically, **before any quantum state is measured**. Since measurement destroys a signature, letting an unauthorized party verify would itself be a denial-of-service vector.

---

### 7. Threat Classification — *Which* Attack Was It?

A single error rate tells you *something* is wrong. It cannot tell you **what**, because forgery, impersonation, and different-message replay all produce ~50% errors.

This section classifies the threat from the **basis-resolved error signature** `(e_Z, e_X, e_Y)` plus deterministic discriminators:

| Threat | e_Z | e_X | e_Y | MCC(E,K) | Discriminator |
|---|---|---|---|---|---|
| No attack | p₀ | p₀ | p₀ | ~0 | All bases at baseline |
| Channel tampering | p | **~0** | p | ~0 | **X-basis immunity** |
| Intercept-resend | 1/3 | 1/3 | 1/3 | ~0 | Uniform at 1/3 |
| Forgery | ρ | ρ | ρ | **~+1** | **Errors track K=1** |
| Impersonation | 1/2 | 1/2 | 1/2 | ~0 | Uniform, independent of K |
| Replay (diff. msg) | h | h | h | ~0 | Classical digest mismatch |
| Replay (same msg) | p₀ | p₀ | p₀ | ~0 | Nonce registry |
| Unauthorized verify | — | — | — | — | HMAC validation |

Two discriminators do the heavy lifting:

- **X-basis immunity.** A Pauli-X error maps |+⟩→|+⟩ and |−⟩→−|−⟩ — both X eigenstates, so the X basis records no error at all. No other attack spares an entire basis.
- **Key correlation.** A digest-only forger errs *exactly* where Kᵢ = 1, so the error pattern is a copy of the key (Matthews correlation → +1). An impersonator guessing at random errs independently of K (→ 0).

Verified at **18/18 correct** across all six classes at n = 256. Classification is only reliable when the sample can resolve the hypotheses — separating 1/3 from 1/2 needs n ≥ 153 at 3σ — so the classifier reports a **resolution warning** and scales confidence down on small subsets.

> No AI or ML: classification is deterministic distance scoring against closed-form signatures.

---

### 8. Analysis — Deep Dive Results

After running experiments, this section gives you publication-quality charts and tables:

- **Interactive Binomial Explorer** — the hypothesis test with its critical region
- **Basis-wise Noise Analysis** — which measurement basis (Z, X, Y) is most and least affected
- **Security Comparison Table** — side-by-side comparison across all attack types
- **Multi-Attack Sweep** — run every attack in one click

---

### 9. Security Bounds — How Strong Is It, Exactly?

Exact closed-form binomial quantities, not simulations.

**Forgery probability.** An adversary without the key has no information about `bᵢ = dᵢ ⊕ Kᵢ`, so their best strategy at each position is a coin flip:

```
P_forge(n, s_a) = Σ(j=0 to ⌊s_a·n⌋) C(n,j) · (1/2)^n
```

| n | Max tolerated errors | P_forge | Security |
|---|---|---|---|
| 16 | 0 | 1.53 × 10⁻⁵ | 16.0 bits |
| 64 | 2 | 1.13 × 10⁻¹⁶ | 53.0 bits |
| **256** | **11** | **5.64 × 10⁻⁵⁹** | **193.5 bits** |

This bound is **information-theoretic** — it holds against unbounded computational power, including a quantum computer, because the attacker lacks *information* about K rather than facing a hard computation. Shor's algorithm has nothing to attack.

**Detection power.** The exact power of the binomial detector against each attack at n = 256, p₀ = 0.02, α = 0.05:

| Attack | Error rate q | Detection power | False-positive rate |
|---|---|---|---|
| Channel tampering, p = 0.10 | 0.067 | 0.978 | 0.035 |
| Intercept-resend | 0.333 | > 0.999999 | 0.035 |
| Forgery / Impersonation / Replay | 0.500 | > 0.999999 | 0.035 |

**Decision thresholds.** The three-way rule and its honest limits are shown, including the fact that weak channel tampering lands in ABORT rather than REJECT.

---

### 10. Performance — Measured, Not Asserted

- **Analytic complexity table** for every protocol stage
- **Empirical scaling**: times verification across signature lengths and fits the log-log slope. Measured exponent **k = 1.01 with R² = 0.9997**, confirming **O(n)** at ≈1.7 ms per position
- **Classical vs quantum cost**: the classical stage is ~1000× cheaper per position than circuit execution, confirming the constant factor is simulator overhead rather than protocol arithmetic

Benchmark methodology: one untimed warm-up pass, then the **minimum of N timed runs**. Timing noise is strictly additive, so the fastest run is the closest estimate of true cost. (A single measurement per size distorted the fitted slope from 1.02 to 1.49 during development.)

---

### 11. Audit Log — Security Event Trail

Append-only **JSON Lines** record of every verification, threat detection, authorization denial, replay block, and key-establishment run. Filter by severity, inspect individual event payloads, and export as JSON.

**Secret hygiene:** key material is never written. Only non-invertible derived quantities are recorded — the key's 1-bit density, a 16-character digest prefix, and the nonce (a public value needed for replay forensics). Fields matching known-sensitive names are replaced with `[REDACTED]` as defence in depth, so the log is safe to export.

---

### 12. Reproducibility — Full Experiment Record

Environment, every parameter, key provenance, decision thresholds, and seed-derivation method, exportable as JSON.

---

## Who Is This For?

| Audience | What They Get |
|----------|--------------|
| **Students** | Hands-on quantum computing experience without needing any hardware |
| **Researchers** | Reproducible QDS protocol implementation with full parameter control |
| **Cybersecurity professionals** | Live attack simulation and statistical threat detection framework |
| **IBM Quantum users** | Direct integration with real QPUs and noise simulators |
| **Hackathon judges** | Complete end-to-end quantum cryptography demonstration |

---

## How to Run It Locally

### Prerequisites
- Python 3.10 or higher
- A terminal (Command Prompt, PowerShell, or bash)

### Step 1 — Clone the repository
```bash
git clone https://github.com/ojasbisht1962/QKD.git
cd QKD
```

### Step 2 — Create a virtual environment
```bash
python -m venv .venv
```

Windows (PowerShell):
```powershell
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:
```bash
source .venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Launch the app
```bash
streamlit run app.py
```

The app opens automatically at **http://localhost:8501** in your browser.

> No IBM account required to use Local Simulation mode. All quantum experiments run instantly on your own computer using Qiskit's built-in simulator.

---

## Connecting to IBM Quantum Hardware (Optional)

To run circuits on real quantum computers:

1. Sign up for free at quantum.ibm.com
2. Create an IBM Cloud instance (Open Plan is free)
3. Copy your **API Key** from IBM Cloud → API Keys
4. Copy your **Instance CRN** from your quantum instance card
5. Open the **Hardware Validation** tab in the app
6. Paste your API Key and CRN into the fields
7. Select channel: `ibm_cloud`
8. Click **AUTHENTICATE & SAVE CREDENTIALS**
9. Select a QPU and run your experiment

Your credentials are never stored in the code or sent anywhere except directly to IBM's servers.

---

## Running the Test Suite

```bash
pytest
```

All **220 unit tests** pass in about 6 minutes using local simulation — no IBM account needed.

Coverage includes: the analytic error rate of every attack, classification accuracy across all six threat classes, forgery bounds checked against independently computed exact binomial values, nonce replay rejection, HMAC authorization on all three attacker profiles, BBM92 QBER against its 25% / 33.3% theoretical values, audit-log secret hygiene, and the O(n) complexity exponent.

---

## Project Structure

```
SIH2026/
├── app.py                        # Main Streamlit web application (all 12 sections)
├── requirements.txt              # Python dependencies
│
├── docs/
│   └── mathematical_model.md     # Formal protocol model, derivations, security scope
│
├── qds/                          # Core quantum protocol implementation
│   ├── encoding.py               # SHA-256 hashing, session binding, secret key XOR
│   ├── states.py                 # Pauli eigenstate preparation & basis rotation
│   ├── teleportation.py          # 3-qubit teleportation + Pauli corrections
│   ├── verification.py           # Verification pipeline (auth -> freshness -> quantum)
│   ├── session.py                # Session nonces, replay registry, verifier authorization
│   ├── keydist.py                # BBM92 entanglement-based quantum key distribution
│   └── circuit_visualization.py  # Circuit builder & renderer
│
├── core/                         # Infrastructure
│   ├── models.py                 # All protocol dataclasses
│   ├── backend.py                # AerSimulator + IBM noise model adapter
│   ├── hardware.py               # IBM Quantum cloud authentication & QPU management
│   ├── seeding.py                # Reproducible, unbiased per-shot simulator seeds
│   └── audit.py                  # Append-only security event logging
│
├── attacks/                      # All 6 attack simulations
│   ├── channel.py                # Channel tampering (bit-flip)
│   ├── forgery.py                # Signature forgery
│   ├── impersonation.py          # Identity impersonation
│   ├── interception.py           # Quantum intercept-resend attack
│   ├── replay.py                 # Replay attack (nonce-aware) + Hamming distance
│   └── unauthorized.py           # Unauthorized verification attempts
│
├── qds_statistics/               # Threat detection & analysis engine
│   ├── detector.py               # Binomial test + three-way decision rule
│   ├── classifier.py             # Basis-resolved threat classification
│   └── bounds.py                 # Forgery probability & detection power
│
├── evaluation/                   # Experiment orchestration & measurement
│   ├── runner.py                 # Multi-attack sweep, security comparison
│   └── performance.py            # Timing, throughput, complexity scaling
│
├── tests/                        # 220 unit tests (full regression suite)
│
└── assets/                       # Background image and static assets
```

> The threat-detection package is named `qds_statistics`, not `statistics`. A top-level package named `statistics` shadows the Python standard library module of the same name for every module in the process, because the application directory is prepended to `sys.path`.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| **Quantum Computing** | Qiskit 2.5+ (IBM's open-source quantum SDK) |
| **Quantum Simulation** | Qiskit Aer (high-performance local simulator) |
| **Real Hardware** | IBM Quantum via qiskit-ibm-runtime |
| **Web Interface** | Streamlit (Python-based interactive web apps) |
| **Statistical Tests** | SciPy (Binomial hypothesis testing, exact tails) |
| **Charts & Visualisation** | Matplotlib |
| **Cryptographic Hashing** | Python hashlib (SHA-256), hmac (HMAC-SHA256) |
| **Secure Randomness** | Python secrets (CSPRNG) |
| **Language** | Python 3.11+ |

---

## Key Concepts Explained Simply

**Qubit** — A quantum bit. Unlike a classical bit (0 or 1), a qubit can be 0, 1, or both at the same time (superposition). When measured, it collapses to 0 or 1.

**Quantum Teleportation** — Transmitting a quantum state from one place to another using entanglement — without physically moving the particle. The state is destroyed at the source and recreated at the destination. Information is perfectly transferred.

**Quantum Entanglement** — Two particles linked such that measuring one instantly determines the state of the other, regardless of distance. Einstein called it "spooky action at a distance."

**No-Cloning Theorem** — It is physically impossible to make a perfect copy of an unknown quantum state. This means an eavesdropper cannot intercept and copy quantum-encoded information without being detected.

**Fidelity** — A score from 0 to 1 measuring how similar the received quantum state is to the original. 1.0 = perfect transmission. Any attack or hardware noise reduces fidelity.

**Binomial Hypothesis Test** — A statistical method that asks: "How likely is it to see this many errors by pure chance?" If that probability falls below the significance level α, the system raises a threat alert.

**Transpilation** — Converting a generic quantum circuit into instructions the specific hardware understands (each quantum computer has its own set of native operations).

**Session Nonce** — A single-use random value bound into the hashed payload. Because the digest changes with the nonce, a captured signature cannot be presented twice: the verifier's registry rejects the reused nonce outright.

**QBER (Quantum Bit Error Rate)** — The disagreement rate between two parties' sifted key bits. Zero on an honest ideal channel; an eavesdropper forces it up to a predictable value (25% with two bases), which is how eavesdropping is caught.

**Information-Theoretic Security** — Security that holds against an attacker with unlimited computing power, because they lack *information* rather than lacking *time*. This is why a quantum computer does not help: there is no computation to speed up.

---

## Problem Statement Coverage

Built against SIH2026 PS5, *Quantum-Inspired Cyber Threat Detection for Digital Signature Security*.

| # | Deliverable | Where |
|---|---|---|
| 1 | Mathematical model of teleportation-based QDS | [`docs/mathematical_model.md`](docs/mathematical_model.md) + Protocol → Mathematical Model |
| 2 | Quantum-inspired threat detection framework | `qds_statistics/detector.py`, `qds_statistics/classifier.py` → Threat Classification |
| 3 | Signature generation & verification module | `qds/encoding.py`, `qds/teleportation.py`, `qds/verification.py`, `qds/keydist.py` → Key Distribution |
| 4 | Attack simulation module | `attacks/` (6 attacks) → Security Lab |
| 5 | Security analysis & performance evaluation | `qds_statistics/bounds.py`, `evaluation/performance.py` → Security Bounds, Performance |
| 6 | Software framework / prototype | `app.py` (12 sections), `core/audit.py` → Audit Log |

All four named threat classes — forgery, impersonation, replay, and channel manipulation — plus unauthorized verification attempts are detected **and identified by class**.

---

## Scientific Disclosures

- All numerical results are traceable to actual Qiskit Aer simulations — nothing is fabricated
- IBM Quantum hardware validation uses 3-qubit representative circuits (full 256-position experiments run locally on the simulator for speed and reproducibility). Note that "256-qubit" means 256 sequential 3-qubit teleportation circuits, not a single 256-qubit circuit
- The baseline noise rate is a calibrated experimental parameter, not a universal constant
- Statistical detection establishes inconsistency with calibrated noise; it does **not** prove adversarial intent
- Threat classification is deterministic distance scoring against closed-form analytic signatures. **No artificial intelligence or machine learning is used anywhere in this system**
- Per-shot simulator seeds are drawn from a seeded RNG rather than consecutive integers. Consecutive seeds bias single-shot Aer sampling — measured at 55.6% versus a true 50% over 800 shots (z ≈ +3.2)

### Known Limitations

- **Non-repudiation / transferability is not provided.** A full QDS scheme lets a recipient forward a signature to a third party who reaches the same verdict. This is a two-party authentication scheme: K is shared, so the verifier could have produced any signature the signer could. Transferability requires per-recipient key halves and a Gottesman–Chuang two-threshold construction
- **No privacy amplification** in key distribution, so the sifted key is not composably secure
- **Weak channel tampering is not always rejected.** The error rate is (2/3)p, so p = 0.10 lands in ABORT and anything below the calibrated noise floor is information-theoretically indistinguishable from noise. Such an attack corrupts a few positions without forging anything
- **Only individual-qubit adversaries are modelled** — coherent and collective attacks are out of scope
- **Freshness and verifier authorization are classical mechanisms** resting on SHA-256 and HMAC-SHA256, not information-theoretic guarantees. They complement the quantum layer rather than replacing it
- The **classical channel is assumed authenticated**, as BBM92 requires; authenticating it is not implemented

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

*Built for Smart India Hackathon 2026 — Quantum Cybersecurity Track*
