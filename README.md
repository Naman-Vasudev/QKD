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

The lab has **6 main sections** accessible from the left sidebar:

---

### 1. Overview

A high-level explanation of what Quantum Digital Signatures are, why they matter for future cybersecurity, and how this lab demonstrates the concept. Great starting point if you are new to the topic.

---

### 2. Protocol — How Signing Actually Works

Step-by-step walkthrough of the complete QDS process:

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

### 3. Quantum Lab — Run Experiments

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

### 4. Hardware Validation — Run on Real IBM Quantum Computers

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

### 5. Security Lab — Attack the System

This is the most exciting section. You can **launch 5 different cyberattacks** against the QDS system and watch whether the built-in detector catches them.

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

**What happens:** Measuring in the wrong basis disturbs the quantum state. This introduces detectable errors — the famous **quantum eavesdropping detection** principle.

---

#### Attack 5: Replay Attack

**What it simulates:** Eve captures a valid signed message and tries to reuse it later (e.g. send the same "Transfer Rs 10,000" message again).

**What happens:**
- **Same message replay** — currently undetected (known limitation, explained in the results panel)
- **Different message replay** — SHA-256 avalanche effect causes ~50% bit difference, detected immediately

---

### 6. Analysis — Deep Dive Results

After running experiments, this section gives you publication-quality charts and tables:

- **Attack Detection Probability Curves** — how detection rate changes as attack intensity increases
- **Basis-wise Noise Analysis** — which measurement basis (Z, X, Y) is most and least affected by noise
- **Security Comparison Table** — side-by-side comparison across all 5 attack types
- **Multi-Attack Sweep** — run all attacks in one click and compare detection rates in a single dashboard
- **Reproducibility Report** — full record of every experiment run, parameters used, and results obtained

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

All **78 unit tests** pass in under 2 minutes using local simulation — no IBM account needed.

---

## Project Structure

```
SIH2026/
├── app.py                        # Main Streamlit web application (all 6 sections)
├── requirements.txt              # Python dependencies
│
├── qds/                          # Core quantum protocol implementation
│   ├── encoding.py               # SHA-256 hashing and secret key XOR encoding
│   └── circuit_visualization.py  # 3-qubit teleportation circuit builder & renderer
│
├── core/                         # Quantum backend infrastructure
│   ├── backend.py                # AerSimulator + IBM noise model adapter
│   └── hardware.py               # IBM Quantum cloud authentication & QPU management
│
├── attacks/                      # All 5 attack simulations
│   ├── channel.py                # Channel tampering (bit-flip)
│   ├── forgery.py                # Signature forgery
│   ├── impersonation.py          # Identity impersonation
│   ├── interception.py           # Quantum intercept-resend attack
│   └── replay.py                 # Replay attack + Hamming distance detection
│
├── statistics/                   # Threat detection engine
│   └── detector.py               # Exact Binomial upper-tail hypothesis test
│
├── evaluation/                   # Experiment runner & comparative analytics
│   └── runner.py                 # Multi-attack sweep, security comparison, sweeps
│
├── tests/                        # 78 unit tests (full regression suite)
│
└── assets/                       # Background image and static assets
```

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| **Quantum Computing** | Qiskit 2.5+ (IBM's open-source quantum SDK) |
| **Quantum Simulation** | Qiskit Aer (high-performance local simulator) |
| **Real Hardware** | IBM Quantum via qiskit-ibm-runtime |
| **Web Interface** | Streamlit (Python-based interactive web apps) |
| **Statistical Tests** | SciPy (Binomial hypothesis testing) |
| **Charts & Visualisation** | Matplotlib |
| **Cryptographic Hashing** | Python hashlib (SHA-256) |
| **Language** | Python 3.11 |

---

## Key Concepts Explained Simply

**Qubit** — A quantum bit. Unlike a classical bit (0 or 1), a qubit can be 0, 1, or both at the same time (superposition). When measured, it collapses to 0 or 1.

**Quantum Teleportation** — Transmitting a quantum state from one place to another using entanglement — without physically moving the particle. The state is destroyed at the source and recreated at the destination. Information is perfectly transferred.

**Quantum Entanglement** — Two particles linked such that measuring one instantly determines the state of the other, regardless of distance. Einstein called it "spooky action at a distance."

**No-Cloning Theorem** — It is physically impossible to make a perfect copy of an unknown quantum state. This means an eavesdropper cannot intercept and copy quantum-encoded information without being detected.

**Fidelity** — A score from 0 to 1 measuring how similar the received quantum state is to the original. 1.0 = perfect transmission. Any attack or hardware noise reduces fidelity.

**Binomial Hypothesis Test** — A statistical method that asks: "How likely is it to see this many errors by pure chance?" If the probability is less than 1%, the system raises a threat alert.

**Transpilation** — Converting a generic quantum circuit into instructions the specific hardware understands (each quantum computer has its own set of native operations).

---

## Scientific Disclosures

- All numerical results are traceable to actual Qiskit Aer simulations — nothing is fabricated
- IBM Quantum hardware validation uses 3-qubit representative circuits (full 256-qubit experiments run locally on the simulator for speed and reproducibility)
- The baseline noise rate is a calibrated experimental parameter, not a universal constant
- Replay attack detection for same-message replays is a known open limitation (session nonce not yet implemented)
- No artificial intelligence or machine learning is used anywhere in this system

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

*Built for Smart India Hackathon 2026 — Quantum Cybersecurity Track*
