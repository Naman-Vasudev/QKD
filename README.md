# Quantum Digital Signature Security Laboratory

A scientific research prototype for **Quantum Digital Signature (QDS)** protocol simulation, physical attack modeling, exact Binomial threat detection, and optional IBM Quantum hardware validation.

---

## Features

- **Core QDS Protocol (Phase 1)**: SHA-256 digest pre-processing, secret key XOR encoding ($b_i = d_i \oplus K_i$), 6 Pauli eigenstate preparation ($|0\rangle, |1\rangle, |+\rangle, |-\rangle, |+i\rangle, |-i\rangle$), deterministic Z/X/Y basis schedule, and 3-qubit quantum teleportation state transmission.
- **Statistical Threat Detector (Phase 2A)**: Exact Binomial upper-tail hypothesis test ($P(K \ge k \mid n, p_0)$) implemented via `scipy.stats.binom.sf`.
- **Physical Attack Laboratory (Phases 2B - 2F)**:
  - **Channel Tampering**: Pauli-X bit-flip errors injected on Bob's qubit $q_2$.
  - **Signature Forgery**: Eve attempts signature generation assuming $K=0$.
  - **Impersonation**: Random Bernoulli(0.5) state guessing.
  - **Quantum Interception**: Intercept-resend attack with Eve basis selection.
  - **Replay Attack**: Captured signature reuse (disclosing same-message freshness vulnerability vs. different-message digest Hamming distance detection).
- **Integrated Security Evaluation & UI (Phase 3 & 4)**: Multi-attack comparative sweep, interactive hypothesis test explorer, basis-wise noise response analysis, and zero-emoji scientific visual design.
- **Cyber-Quantum Purplish-Pinkish UI Theme**: Modern dark glassmorphism interface styled with neon pink (`#EC4899`) and purple (`#A855F7`) accents, Google Fonts (`Outfit`, `Inter`, `JetBrains Mono`), dark cyber Matplotlib charts, and a Qpi AI Quantum Dilution Refrigerator background overlay.
- **Optional IBM Quantum Hardware Validation (Phase 5)**: Execute representative 3-qubit teleportation circuits on physical IBM Quantum QPUs (`qiskit-ibm-runtime`) with side-by-side ideal vs. hardware noise comparison.

---

## Recent Updates & Enhancements

### 🎨 UI & Design System Overhaul
- **Purplish-Pinkish Theme**: Modernized Streamlit frontend with a sleek dark purple and neon pink color system (`.streamlit/config.toml` & custom CSS).
- **Typography**: Integrated Google Fonts—`Outfit` for futuristic titles, `Inter` for interface elements, and `JetBrains Mono` for code & metrics.
- **Quantum Hardware Background**: Added base64 image background integration featuring the Qpi AI Quantum Hardware Dilution Refrigerator (`assets/quantum_bg.png`) with an adjustable gradient opacity overlay.
- **Dark Matplotlib Charts**: Customized figure plotting functions (`_plot_pmf`, 256-qubit outcome maps, single-qubit histograms, and basis sweeps) to match dark canvas aesthetics (`#130825` / `#0B0414`).

### 🐛 Bug Fixes & Code Improvements
- **Typing Imports**: Fixed missing `Tuple` import in `attacks/impersonation.py`.
- **State Math Metadata**: Added `state_label` field to `get_state_math_info` in `qds/circuit_visualization.py`.
- **Full Test Suite Verification**: All **75 unit tests** pass cleanly in local simulation mode.

---

## Local Installation

1. **Clone repository and navigate to root**:
   ```bash
   git clone https://github.com/Naman-Vasudev/QKD.git
   cd QKD
   ```

2. **Create and activate virtual environment (Python 3.10+)**:
   ```bash
   python -m venv .venv
   ```
   - On Windows (PowerShell):
     ```powershell
     .\.venv\Scripts\Activate.ps1
     ```
   - On Linux/macOS:
     ```bash
     source .venv/bin/activate
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Application

Launch the Streamlit interactive laboratory:
```bash
streamlit run app.py
```

The application starts immediately in **Local Quantum Simulation** mode using Qiskit `AerSimulator`. No IBM API token is required for local simulation or full 256-qubit security evaluation.

---

## Running the Test Suite

Run the full regression test suite (75 tests):
```bash
python -m unittest discover -s tests -v
```

All 75 unit tests run in local simulation mode without requiring real IBM Quantum hardware access.

---

## Optional IBM Quantum Hardware Setup

To enable real QPU execution on IBM Quantum hardware:

### Option A: Streamlit Secrets (Recommended for Cloud Deployment)
Create `.streamlit/secrets.toml`:
```toml
IBM_QUANTUM_API_TOKEN = "your_actual_ibm_quantum_api_token_here"
```

### Option B: Environment Variable
```bash
export IBM_QUANTUM_API_TOKEN="your_actual_ibm_quantum_api_token_here"
```

When credentials are configured, navigate to **[ HARDWARE VALIDATION ]** in the sidebar to run representative 3-qubit teleportation circuits on available physical IBM backends.

---

## Deploying to Streamlit Community Cloud

1. Push repository to GitHub (ensure `.env` and `.streamlit/secrets.toml` are in `.gitignore`).
2. Connect your GitHub repository to [Streamlit Community Cloud](https://streamlit.io/cloud).
3. In Advanced Settings, set Python version to 3.10 or 3.11.
4. Optionally paste `IBM_QUANTUM_API_TOKEN = "your_token"` into Secrets.
5. Deploy app.

---

## Scientific Disclosures & Limitations

1. **Replay Freshness**: The prototype lacks a session nonce or sequence counter. Same-message replay is indistinguishable from fresh transmission (0 verification errors). Different-message replay causes ~50% verification errors due to SHA-256 avalanche properties.
2. **Baseline Noise Rate ($p_0$)**: $p_0$ is a calibrated experimental parameter for statistical hypothesis testing, not a universal constant.
3. **Simulation Backend**: 256-qubit security experiments use Qiskit `AerSimulator`. Physical hardware validation is performed on 3-qubit representative primitives.
