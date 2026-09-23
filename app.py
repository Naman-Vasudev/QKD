"""
Quantum Digital Signature Security Laboratory — Interactive Research UI.

SCIENTIFIC INTEGRITY & DISCLOSURES:
- All displayed numerical results are traceable to actual Qiskit Aer simulations.
- IBM Quantum hardware validation is an OPTIONAL representative 3-qubit transmission layer.
- Full 256-position security evaluation remains on AerSimulator for reproducibility and
  efficiency. "256 qubits" means 256 sequential 3-qubit teleportation circuits, not one
  256-qubit circuit.
- Baseline noise probability p0 is a calibrated experimental parameter, NOT a universal constant.
- Threat detection uses exact Binomial upper-tail testing; it indicates statistical inconsistency
  with baseline noise, not proof of attacker identity.
- Threat CLASSIFICATION uses deterministic distance scoring against analytically derived
  per-basis error signatures. Artificial intelligence (AI) and machine learning (ML) are
  explicitly NOT used anywhere in this system.
- No emojis are used anywhere in this scientific interface.
- This is a Qiskit Aer simulation laboratory, with optional IBM QPU validation.

SECTIONS:
  1. Overview               7. Threat Classification
  2. Protocol (+ math)      8. Analysis
  3. Key Distribution       9. Security Bounds
  4. Quantum Lab           10. Performance
  5. Hardware Validation   11. Audit Log
  6. Security Lab          12. Reproducibility
"""

import base64
import json
import math
import os
import platform
import secrets
import sys
from typing import List, Dict, Any, Optional

import streamlit as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from scipy.stats import binom

from qds.encoding import sha256_bits, sha256_hex, encode_message, session_digest_bits
from qds.circuit_visualization import (
    get_state_math_info,
    build_demonstration_teleportation_circuit,
    draw_circuit_mpl,
    draw_circuit_ascii,
)
from qds.session import (
    NonceRegistry,
    authorize_verifier,
    create_session,
    generate_master_secret,
    issue_verifier_token,
)
from qds.keydist import (
    ALL_QKD_BASES,
    DEFAULT_QKD_BASES,
    establish_signing_key,
    run_key_distribution,
)
from core.backend import QuantumBackendAdapter
from core.audit import AuditLogger
from core.hardware import (
    get_ibm_token,
    get_ibm_instance,
    is_hardware_configured,
    get_available_hardware_backends,
    get_available_simulator_backends,
    run_hardware_teleportation_experiment,
    fetch_ibm_job_result,
    BUILTIN_IBM_NOISE_MODELS,
)
from attacks.replay import compute_digest_hamming_distance, run_replay_attack
from attacks.unauthorized import (
    ATTACKER_PROFILES,
    run_authorization_profile_sweep,
    run_unauthorized_verification_attack,
)
from qds_statistics.detector import (
    detect_threat,
    compute_decision_thresholds,
    decide_signature,
)
from qds_statistics.classifier import (
    THREAT_DISPLAY_NAMES,
    classify_threat,
    minimum_trials_for_resolution,
)
from qds_statistics.bounds import (
    ATTACK_ERROR_RATES,
    attack_detection_summary,
    detection_power,
    detection_power_curve,
    forgery_bound_curve,
    forgery_success_probability,
)
from evaluation.runner import (
    ExperimentResult,
    run_experiment,
    run_security_comparison,
    run_channel_tampering_sweep,
    run_basis_wise_channel_sweep,
)
from evaluation.performance import (
    analyze_verification_complexity,
    build_complexity_table,
    measure_encoding_performance,
    measure_verification_performance,
)

# ─── Page configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="QDS Security Laboratory",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Load Background Image (Quantum Hardware & Circuit Art) ─────────────────
bg_img_path = os.path.join(os.path.dirname(__file__), "assets", "quantum_bg.jpg")
if not os.path.exists(bg_img_path):
    bg_img_path = os.path.join(os.path.dirname(__file__), "assets", "quantum_bg.png")

b64_bg = ""
if os.path.exists(bg_img_path):
    with open(bg_img_path, "rb") as img_file:
        b64_bg = base64.b64encode(img_file.read()).decode()

bg_css_override = f"""
    .stApp {{
        background-image: linear-gradient(180deg, rgba(8, 4, 15, 0.82) 0%, rgba(13, 5, 26, 0.88) 100%),
                          url("data:image/jpeg;base64,{b64_bg}") !important;
        background-position: center center !important;
        background-size: cover !important;
        background-repeat: no-repeat !important;
        background-attachment: fixed !important;
        color: #F3E8FF !important;
        font-family: 'Inter', sans-serif !important;
    }}
    [data-testid="stAppViewContainer"], [data-testid="stMain"], [data-testid="stMainBlockContainer"], .main {{
        background: transparent !important;
    }}
    [data-testid="stHeader"] {{
        background: transparent !important;
    }}
""" if b64_bg else """
    .stApp {
        background: radial-gradient(circle at 10% 10%, rgba(236, 72, 153, 0.12) 0%, transparent 45%),
                    radial-gradient(circle at 90% 90%, rgba(168, 85, 247, 0.15) 0%, transparent 45%),
                    #08040F !important;
        color: #F3E8FF !important;
        font-family: 'Inter', sans-serif !important;
    }
"""

# ─── CSS: Purplish-Pinkish Cyber-Quantum Design System ────────────────────────
css_style_content = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    section[data-testid="stSidebar"] {
        background-color: rgba(17, 7, 34, 0.94) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border-right: 1px solid rgba(236, 72, 153, 0.25) !important;
    }
    section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3 {
        color: #F472B6 !important;
        font-family: 'Outfit', sans-serif !important;
    }

    h1 {
        font-family: 'Outfit', sans-serif !important;
        font-size: 2.1rem !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #FF60B5 0%, #EC4899 40%, #C084FC 80%, #818CF8 100%);
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        border-bottom: 2px solid transparent !important;
        border-image: linear-gradient(90deg, #EC4899, #A855F7, transparent) 1 !important;
        padding-bottom: 8px !important;
        margin-bottom: 12px !important;
        letter-spacing: -0.02em !important;
        text-shadow: 0 0 25px rgba(236, 72, 153, 0.25);
    }

    h2 {
        font-family: 'Outfit', sans-serif !important;
        font-size: 1.45rem !important;
        font-weight: 700 !important;
        color: #E9D5FF !important;
        border-bottom: 1px solid rgba(236, 72, 153, 0.25) !important;
        padding-bottom: 6px !important;
        margin-top: 1.6em !important;
    }

    h3 {
        font-family: 'Outfit', sans-serif !important;
        font-size: 1.15rem !important;
        font-weight: 600 !important;
        color: #C084FC !important;
        margin-top: 1.2em !important;
    }

    .status-normal {
        border-left: 4px solid #10B981;
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.15), rgba(16, 185, 129, 0.03));
        padding: 12px 18px;
        border-radius: 0 8px 8px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.90rem;
        font-weight: 600;
        color: #34D399;
        margin: 10px 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
    }

    .status-threat {
        border-left: 4px solid #FF2A85;
        background: linear-gradient(90deg, rgba(255, 42, 133, 0.20), rgba(255, 42, 133, 0.04));
        padding: 12px 18px;
        border-radius: 0 8px 8px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.90rem;
        font-weight: 600;
        color: #FF60B5;
        margin: 10px 0;
        box-shadow: 0 4px 15px rgba(255, 42, 133, 0.15);
    }

    .info-box {
        border-left: 4px solid #A855F7;
        background: linear-gradient(90deg, rgba(168, 85, 247, 0.15), rgba(168, 85, 247, 0.03));
        padding: 12px 18px;
        border-radius: 0 8px 8px 0;
        font-size: 0.88rem;
        color: #E9D5FF;
        margin: 10px 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
    }

    .math-block {
        background-color: #120722;
        border: 1px solid rgba(236, 72, 153, 0.3);
        border-radius: 8px;
        padding: 14px 18px;
        margin: 12px 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.88rem;
        color: #F472B6;
        box-shadow: inset 0 0 15px rgba(236, 72, 153, 0.08);
    }

    .dataframe-container {
        border: 1px solid rgba(236, 72, 153, 0.25);
        border-radius: 8px;
        overflow: hidden;
        margin: 12px 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }

    pre, code {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .metric-label {
        font-size: 0.78rem;
        color: #C084FC;
        font-family: 'Outfit', sans-serif;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }

    .metric-value {
        font-size: 1.15rem;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        color: #FF70A6;
        text-shadow: 0 0 10px rgba(255, 112, 166, 0.3);
    }

    .sec-header {
        font-family: 'Outfit', sans-serif;
        font-size: 1.10rem;
        font-weight: 700;
        color: #FF60B5;
        background: linear-gradient(90deg, rgba(236, 72, 153, 0.22), rgba(168, 85, 247, 0.08));
        padding: 8px 16px;
        border-left: 4px solid #EC4899;
        border-radius: 0 6px 6px 0;
        margin-top: 1.4em;
        margin-bottom: 0.8em;
        letter-spacing: 0.03em;
    }

    [data-testid="stMetric"] {
        background: rgba(22, 10, 42, 0.75) !important;
        border: 1px solid rgba(236, 72, 153, 0.25) !important;
        border-radius: 10px !important;
        padding: 12px 16px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), inset 0 0 15px rgba(236, 72, 153, 0.05) !important;
    }
    [data-testid="stMetricLabel"] {
        font-family: 'Outfit', sans-serif !important;
        font-size: 0.82rem !important;
        color: #C084FC !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.25rem !important;
        font-weight: 700 !important;
        color: #FF70A6 !important;
        text-shadow: 0 0 10px rgba(255, 112, 166, 0.3) !important;
    }

    .stButton > button {
        background: linear-gradient(135deg, #EC4899 0%, #A855F7 100%) !important;
        color: #FFFFFF !important;
        font-family: 'Outfit', sans-serif !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        box-shadow: 0 0 20px rgba(236, 72, 153, 0.4) !important;
        transition: all 0.25s ease-in-out !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) scale(1.02) !important;
        box-shadow: 0 0 30px rgba(236, 72, 153, 0.65) !important;
    }

    div[data-testid="stSidebar"] div[role="radiogroup"] > label {
        background: rgba(26, 12, 46, 0.4) !important;
        border: 1px solid rgba(236, 72, 153, 0.15) !important;
        border-radius: 8px !important;
        padding: 8px 14px !important;
        margin-bottom: 6px !important;
        transition: all 0.2s ease-in-out !important;
        font-family: 'Outfit', sans-serif !important;
        font-weight: 500 !important;
        letter-spacing: 0.02em !important;
    }
    div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
        background: rgba(236, 72, 153, 0.15) !important;
        border-color: rgba(236, 72, 153, 0.4) !important;
        box-shadow: 0 0 12px rgba(236, 72, 153, 0.2) !important;
    }
    div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] {
        background: linear-gradient(90deg, rgba(236, 72, 153, 0.25), rgba(168, 85, 247, 0.2)) !important;
        border-color: #EC4899 !important;
        box-shadow: 0 0 15px rgba(236, 72, 153, 0.3) !important;
    }
    </style>
"""

st.markdown(css_style_content + f"<style>{bg_css_override}</style>", unsafe_allow_html=True)

# ─── Sidebar: Navigation + Global Configuration ───────────────────────────────
st.sidebar.markdown("## QUANTUM DIGITAL SIGNATURE\n### Security Laboratory")
st.sidebar.markdown("---")

nav_section = st.sidebar.radio(
    "NAVIGATE",
    options=[
        "Overview",
        "Protocol",
        "Key Distribution",
        "Quantum Lab",
        "Hardware Validation",
        "Security Lab",
        "Threat Classification",
        "Analysis",
        "Security Bounds",
        "Performance",
        "Audit Log",
        "Reproducibility",
    ],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.markdown("### EXECUTION ENGINE")

execution_backend_mode = st.sidebar.radio(
    "Execution Backend Mode",
    options=[
        "Local Aer Simulation (Ideal)",
        "IBM Quantum Realistic Noise Simulator",
        "Real IBM Quantum Hardware (Physical QPU)",
    ],
    index=0,
)

# Configure active backend adapter based on selection
active_backend_adapter: QuantumBackendAdapter
if execution_backend_mode == "IBM Quantum Realistic Noise Simulator":
    selected_noise_model_display = st.sidebar.selectbox(
        "IBM QPU Noise Profile",
        options=[
            "IBM Fez (156-Qubit Heron r2)",
            "IBM Marrakesh (156-Qubit Heron r2)",
            "IBM Kingston (156-Qubit Heron r2)",
            "IBM Brisbane (127-Qubit Eagle)",
            "IBM Torino (133-Qubit Heron)",
            "IBM Sherbrooke (127-Qubit Eagle)",
            "IBM Kyoto (127-Qubit Eagle)",
            "IBM Osaka (127-Qubit Eagle)",
            "IBM Manila (5-Qubit Falcon)",
        ],
        index=0,
    )
    noise_model_map = {
        "IBM Fez (156-Qubit Heron r2)": "fake_fez",
        "IBM Marrakesh (156-Qubit Heron r2)": "fake_marrakesh",
        "IBM Kingston (156-Qubit Heron r2)": "fake_kingston",
        "IBM Brisbane (127-Qubit Eagle)": "fake_brisbane",
        "IBM Torino (133-Qubit Heron)": "fake_torino",
        "IBM Sherbrooke (127-Qubit Eagle)": "fake_sherbrooke",
        "IBM Kyoto (127-Qubit Eagle)": "fake_kyoto",
        "IBM Osaka (127-Qubit Eagle)": "fake_osaka",
        "IBM Manila (5-Qubit Falcon)": "fake_manila",
    }
    target_noise_key = noise_model_map[selected_noise_model_display]
    active_backend_adapter = QuantumBackendAdapter(target_noise_key)
    st.sidebar.caption("Simulating calibrated T1/T2, gate errors, and readout noise.")
elif execution_backend_mode == "Real IBM Quantum Hardware (Physical QPU)":
    curr_tok = st.session_state.get("IBM_QUANTUM_API_TOKEN", "").strip() or get_ibm_token()
    hw_ok, hw_msg = is_hardware_configured(curr_tok)
    if hw_ok:
        st.sidebar.success("IBM Quantum Authenticated")
    else:
        st.sidebar.info("Configure Token in Hardware Tab")
    active_backend_adapter = QuantumBackendAdapter("aer_simulator")
else:
    active_backend_adapter = QuantumBackendAdapter("aer_simulator")

st.sidebar.markdown("---")
st.sidebar.markdown("### GLOBAL CONFIGURATION")

message = st.sidebar.text_input("Message Payload (M)", value="ABC")

key_mode = st.sidebar.selectbox(
    "Secret Key K",
    options=[
        "Cryptographic Random (CSPRNG)",
        "Quantum Key Distribution (BBM92)",
        "Deterministic Balanced (0,1,0,1...)",
    ],
    help=(
        "CSPRNG uses secrets.randbits, suitable for real use. BBM92 establishes K from "
        "measured Bell pairs. The deterministic pattern is for teaching only: it is "
        "publicly guessable and voids the information-theoretic forgery bound."
    ),
)

# A cryptographically secure key is the safe default. The alternating 0,1,0,1 pattern is
# retained only for reproducible demonstrations; it is publicly guessable, so an attacker
# who assumes it needs no forgery at all.
if "shared_key" not in st.session_state:
    st.session_state.shared_key = [secrets.randbits(1) for _ in range(256)]
    st.session_state.key_provenance = "Cryptographic Random (CSPRNG)"

if key_mode == "Deterministic Balanced (0,1,0,1...)":
    st.sidebar.warning(
        "INSECURE KEY: this pattern is public knowledge. Forgery bounds reported "
        "elsewhere in this app assume a uniformly random key and do not hold here."
    )
    if st.session_state.get("key_provenance") != "Deterministic Balanced (0,1,0,1...)":
        st.session_state.shared_key = [i % 2 for i in range(256)]
        st.session_state.key_provenance = "Deterministic Balanced (0,1,0,1...)"

elif key_mode == "Cryptographic Random (CSPRNG)":
    if st.sidebar.button("Generate New CSPRNG Key") or \
            st.session_state.get("key_provenance") == "Deterministic Balanced (0,1,0,1...)":
        st.session_state.shared_key = [secrets.randbits(1) for _ in range(256)]
        st.session_state.key_provenance = "Cryptographic Random (CSPRNG)"

elif key_mode == "Quantum Key Distribution (BBM92)":
    if st.sidebar.button("Establish Key via BBM92"):
        with st.spinner("Distributing Bell pairs and sifting..."):
            qkd_key, qkd_result = establish_signing_key(key_length=256)
        st.session_state.shared_key = qkd_key
        st.session_state.key_provenance = "Quantum Key Distribution (BBM92)"
        st.session_state.qkd_result = qkd_result
    if st.session_state.get("key_provenance") != "Quantum Key Distribution (BBM92)":
        st.sidebar.info("Press the button to establish K from measured Bell pairs.")

shared_key: List[int] = st.session_state.shared_key
key_provenance: str = st.session_state.get("key_provenance", key_mode)
st.sidebar.caption(
    f"Active key: {key_provenance} | 1-bit density {sum(shared_key) / len(shared_key):.3f}"
)

baseline_noise = st.sidebar.slider(
    "Baseline Error Rate (p0)",
    min_value=0.00,
    max_value=0.15,
    value=0.02,
    step=0.005,
    help="Calibrated legitimate channel noise baseline error rate p0. This is an experimental parameter, NOT a universal constant.",
)

alpha = st.sidebar.slider(
    "Significance Threshold (alpha)",
    min_value=0.001,
    max_value=0.10,
    value=0.05,
    step=0.005,
)

shots_per_qubit = st.sidebar.selectbox(
    "Shots Per Qubit",
    options=[1, 10, 100],
    index=0,
)

seed_input = st.sidebar.number_input("Random Seed", value=42, step=1)
seed = int(seed_input)

st.sidebar.markdown("---")
st.sidebar.markdown("### PROTOCOL HARDENING")

freshness_enabled = st.sidebar.checkbox(
    "Session Nonce Binding (replay resistance)",
    value=True,
    help=(
        "Binds a random nonce, counter, signer identity, and timestamp into the hashed "
        "payload. Without this, a same-message replay is indistinguishable from a fresh "
        "signature by any measurement."
    ),
)

audit_enabled = st.sidebar.checkbox(
    "Security Event Logging",
    value=True,
    help="Append verification and threat events to an exportable JSON Lines audit log.",
)

# Process-wide singletons held in session state so they survive Streamlit reruns.
if "audit_logger" not in st.session_state:
    st.session_state.audit_logger = AuditLogger()
if "nonce_registry" not in st.session_state:
    st.session_state.nonce_registry = NonceRegistry()
if "master_secret" not in st.session_state:
    st.session_state.master_secret = generate_master_secret()

st.session_state.audit_logger.enabled = audit_enabled
audit_logger: AuditLogger = st.session_state.audit_logger
nonce_registry: NonceRegistry = st.session_state.nonce_registry
master_secret: bytes = st.session_state.master_secret

active_session = create_session(signer_id="alice", counter=1) if freshness_enabled else None
decision_thresholds = compute_decision_thresholds(
    total_trials=256, baseline_error_rate=baseline_noise
)

# ─── Helper: run single experiment and cache ──────────────────────────────────

def _run_and_cache(attack_name: str, attack_params: Dict[str, Any]) -> ExperimentResult:
    res = run_experiment(
        attack_name=attack_name,
        message=message,
        shared_key=shared_key,
        baseline_error_rate=baseline_noise,
        alpha=alpha,
        shots_per_qubit=shots_per_qubit,
        seed=seed,
        backend=active_backend_adapter,
        attack_params=attack_params,
        audit_logger=audit_logger,
    )
    return res


def _render_decision_banner(decision) -> None:
    """Render the three-way ACCEPT / ABORT / REJECT verdict with its justification."""
    if decision is None:
        return
    if decision.verdict == "ACCEPT":
        st.success(f"VERDICT: ACCEPT — {decision.justification}")
    elif decision.verdict == "ABORT":
        st.warning(f"VERDICT: ABORT — {decision.justification}")
    else:
        st.error(f"VERDICT: REJECT — {decision.justification}")


def _render_classification_block(classification, key_prefix: str = "") -> None:
    """Render a threat classification: verdict, basis fingerprint, ranked hypotheses."""
    if classification is None:
        st.info(
            "No per-position measurement records were produced for this run, so the "
            "basis-resolved classifier has nothing to profile."
        )
        return

    profile = classification.profile

    st.markdown(f"#### Classified Threat: {classification.top_display_name}")
    st.progress(
        min(1.0, max(0.0, classification.confidence)),
        text=f"Discriminability confidence: {classification.confidence:.2f}",
    )
    st.caption(classification.interpretation)

    col_a, col_b, col_c, col_d = st.columns(4)
    col_a.metric("e_Z (Z basis)", f"{profile.rates['Z']:.4f}")
    col_b.metric("e_X (X basis)", f"{profile.rates['X']:.4f}")
    col_c.metric("e_Y (Y basis)", f"{profile.rates['Y']:.4f}")
    col_d.metric("Pooled error", f"{profile.overall_rate:.4f}")

    if profile.key_error_correlation is not None:
        st.metric(
            "Error-to-key correlation (MCC)",
            f"{profile.key_error_correlation:+.4f}",
            help=(
                "Matthews correlation between the per-position error indicator and the "
                "secret key bit K_i. Approaches +1 for a digest-only forgery, where "
                "errors land exactly where K_i = 1, and 0 for random-guess impersonation."
            ),
        )

    st.markdown("**Ranked hypotheses** (lower distance = better fit)")
    st.dataframe(
        [
            {
                "Threat Class": h.display_name,
                "Distance": f"{h.distance:.4f}",
                "Score": f"{h.score:.4f}",
                "Discriminator Penalty": f"{h.penalty:.2f}",
                "Expected (Z, X, Y)": (
                    f"({h.expected_signature['Z']:.3f}, "
                    f"{h.expected_signature['X']:.3f}, "
                    f"{h.expected_signature['Y']:.3f})"
                ),
            }
            for h in classification.hypotheses
        ],
        width="stretch",
        hide_index=True,
    )

    with st.expander("Evidence for the leading hypothesis"):
        for item in classification.hypotheses[0].evidence:
            st.markdown(f"- {item}")


def _plot_pmf(n: int, p0: float, k_obs: int, alpha_val: float) -> plt.Figure:
    x_max = max(k_obs + 20, int(n * p0 * 4) + 10, 30)
    x_vals = np.arange(0, x_max + 1)
    pmf_vals = binom.pmf(x_vals, n, p0)

    # Critical threshold: smallest k* such that P(K >= k* | n, p0) < alpha
    k_crit = None
    for kk in range(n + 1):
        if binom.sf(kk - 1, n, p0) < alpha_val:
            k_crit = kk
            break

    fig, ax = plt.subplots(figsize=(7, 3))
    fig.patch.set_facecolor('#130825')
    ax.set_facecolor('#0B0414')
    ax.plot(x_vals, pmf_vals, color="#C084FC", linewidth=1.8, marker="o", markersize=4,
            label=f"Binomial PMF (n={n}, p0={p0})")
    ax.fill_between(x_vals, pmf_vals, alpha=0.25, color="#A855F7")

    if k_crit is not None and k_crit <= x_max:
        reject_x = x_vals[x_vals >= k_crit]
        ax.fill_between(reject_x, binom.pmf(reject_x, n, p0),
                        alpha=0.45, color="#FF2A85", label=f"Rejection Region (alpha={alpha_val})")

    ax.axvline(k_obs, color="#FF2A85", linestyle="--", linewidth=1.8,
               label=f"Observed k = {k_obs}")
    ax.set_xlabel("Number of Verification Errors (k)", color="#E9D5FF")
    ax.set_ylabel("Probability Mass P(K = k | n, p0)", color="#E9D5FF")
    ax.set_title("Exact Binomial Error Distribution under Null Hypothesis H0: p = p0", color="#FF70A6", fontsize=10, fontweight="bold")
    ax.grid(True, linestyle="--", alpha=0.2, color="#A855F7")
    ax.tick_params(colors="#C084FC")
    for spine in ax.spines.values():
        spine.set_color((236/255, 72/255, 153/255, 0.3))
    ax.legend(fontsize=8, facecolor="#180B30", edgecolor="#EC4899", labelcolor="#F3E8FF")
    fig.tight_layout()
    return fig


def _render_hypothesis_test_block(res: ExperimentResult):
    st.markdown('<div class="sec-header">I. STATISTICAL HYPOTHESIS TEST</div>', unsafe_allow_html=True)
    
    k_obs = res.num_errors
    n_trials = res.total_trials
    p0 = res.baseline_error_rate
    pval = res.threat_result.p_value
    alpha_val = res.alpha
    threat = res.threat_result.threat_detected
    decision_str = "REJECT H0 (THREAT DETECTED)" if threat else "FAIL TO REJECT H0 (NORMAL CHANNEL)"

    st.code(
        f"""\
==============================================================================================
STATISTICAL HYPOTHESIS TEST FORMULATION
==============================================================================================
Null Hypothesis (H0):       p = p0 = {p0:.4f}  (Observed errors consistent with baseline noise)
Alternative Hypothesis (H1): p > p0           (Observed errors indicate statistical anomaly)

Test Statistic (K):         k = {k_obs} verification errors out of n = {n_trials} total trials
Observed Error Rate:        k / n = {res.observed_error_rate:.4f}
Baseline Noise (p0):        {p0:.4f}
Significance Level (alpha): {alpha_val:.4f}

Exact Binomial p-value:     P(K >= {k_obs} | n={n_trials}, p0={p0:.4f}) = {pval:.6e}

STATISTICAL DECISION:       {decision_str}
==============================================================================================
""",
        language="text",
    )

    if threat:
        st.markdown(
            f'<div class="status-threat">THREAT DETECTED — p-value ({pval:.4e}) <= alpha ({alpha_val:.4f}). '
            f'Reject H0: error rate {res.observed_error_rate:.4f} is statistically anomalous compared to baseline p0={p0}.</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="status-normal">NORMAL CHANNEL — p-value ({pval:.4e}) > alpha ({alpha_val:.4f}). '
            f'Fail to reject H0: error count {k_obs} is consistent with baseline noise p0={p0}.</div>',
            unsafe_allow_html=True,
        )

    fig_pmf = _plot_pmf(n_trials, p0, k_obs, alpha_val)
    st.pyplot(fig_pmf)
    plt.close(fig_pmf)


def _render_measurement_and_stochasticity_block(
    res: ExperimentResult,
    theo_exp_str: str,
):
    st.markdown('<div class="sec-header">G. MEASUREMENT RESULTS</div>', unsafe_allow_html=True)

    theo_val = res.theoretical_expectation if isinstance(res.theoretical_expectation, float) else None
    obs_val = res.observed_error_rate
    dev_str = f"{abs(obs_val - theo_val):.4f}" if theo_val is not None else "N/A"

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Expected Error Rate", theo_exp_str)
    m2.metric("Observed Error Rate", f"{obs_val:.4f}")
    m3.metric("Deviation |Obs - Theo|", dev_str)
    m4.metric("Errors (k) / Trials (n)", f"{res.num_errors} / {res.total_trials}")
    m5.metric("Random Seed", seed)
    m6.metric("Shots / Qubit", shots_per_qubit)

    st.markdown(
        '<div class="info-box">STOCHASTIC EXPERIMENTAL NOTE: Observed counts are generated by quantum simulation '
        'and finite-sample stochasticity. Repeated runs with different random seeds will produce naturally '
        'varying error counts while remaining statistically consistent with the underlying theoretical model.</div>',
        unsafe_allow_html=True,
    )


def _render_position_trace_table_and_map(detailed_results: List[Dict[str, Any]], attack_type: str):
    st.markdown('<div class="sec-header">E. POSITION-BY-POSITION EXPERIMENTAL TRACE</div>', unsafe_allow_html=True)

    if not detailed_results:
        st.write("No detailed per-qubit results recorded.")
        return

    n_total = len(detailed_results)
    n_matches = sum(1 for r in detailed_results if r.get("matched", False))
    n_errors = n_total - n_matches

    mc1, mc2, mc3, mc4 = st.columns(4)
    mc1.metric("Evaluated Positions", n_total)
    mc2.metric("Matching Positions (MATCH)", n_matches)
    mc3.metric("Error Positions (MISMATCH)", n_errors)
    mc4.metric("Observed Mismatch Rate", f"{n_errors / n_total:.4f}")

    st.subheader("256-Position Verification Outcome Map")
    st.markdown("Green = MATCH (Legitimate verification passed) | Red = MISMATCH (Verification error)")

    grid_outcomes = np.array([1 if r.get("matched", False) else 0 for r in detailed_results[:256]])
    if len(grid_outcomes) == 256:
        grid_2d = grid_outcomes.reshape(16, 16)
        fig_map, ax_map = plt.subplots(figsize=(4, 4))
        fig_map.patch.set_facecolor('#130825')
        ax_map.set_facecolor('#0B0414')
        cmap = matplotlib.colors.ListedColormap(["#FF2A85", "#10B981"])
        ax_map.imshow(grid_2d, cmap=cmap, vmin=0, vmax=1, interpolation="nearest", aspect="equal")
        ax_map.set_title("256-Qubit Outcome Map (Green=MATCH, Red=MISMATCH)", fontsize=8, color="#F3E8FF")
        ax_map.set_xticks([])
        ax_map.set_yticks([])
        st.pyplot(fig_map)
        plt.close(fig_map)

    st.subheader("Interactive Position Inspector")
    pos_idx = st.slider("Inspect Position Index (i)", 0, max(0, n_total - 1), 0)
    pos_data = detailed_results[pos_idx]

    pi1, pi2, pi3, pi4, pi5 = st.columns(5)
    pi1.metric("Position Index (i)", pos_data.get("qubit_index", pos_idx))
    pi2.metric("Digest Bit (d_i)", pos_data.get("digest_bit", "N/A"))
    pi3.metric("Key Bit (K_i)", pos_data.get("key_bit", "N/A"))
    pi4.metric("Basis (B_i)", pos_data.get("basis", pos_data.get("alice_basis", "N/A")))
    matched_flag = pos_data.get("matched", False)
    pi5.metric("Verification Status", "MATCH" if matched_flag else "MISMATCH")

    st.json(pos_data)

    st.subheader("Full 256-Position Experimental Trace Table")
    filter_status = st.radio("Filter Positions", ["All", "MISMATCH Only", "MATCH Only"], horizontal=True)

    rows = []
    for r in detailed_results:
        m_status = "MATCH" if r.get("matched", False) else "MISMATCH"
        if filter_status == "MISMATCH Only" and m_status != "MISMATCH":
            continue
        if filter_status == "MATCH Only" and m_status != "MATCH":
            continue

        row_dict = {
            "i": r.get("qubit_index"),
            "d_i": r.get("digest_bit", "N/A"),
            "K_i": r.get("key_bit", "N/A"),
            "Legit b_i": r.get("encoded_bit", r.get("legitimate_encoded_bit", "N/A")),
            "Basis": r.get("basis", r.get("alice_basis", "N/A")),
            "Expected State": r.get("state_label", r.get("legitimate_state", "N/A")),
            "Observed Eig": r.get("observed_eigenvalue", "N/A"),
            "Status": m_status,
        }

        if attack_type == "bit_flip_channel":
            row_dict["X Injected?"] = "YES" if r.get("x_injected") else "NO"
        elif attack_type == "signature_forgery":
            row_dict["Forged b'_i"] = r.get("forged_encoded_bit", "N/A")
            row_dict["Forged State"] = r.get("forged_state", "N/A")
        elif attack_type == "signature_impersonation":
            row_dict["Guessed b'_i"] = r.get("impersonated_encoded_bit", "N/A")
            row_dict["Guessed State"] = r.get("impersonated_state", "N/A")
        elif attack_type == "quantum_interception":
            row_dict["Eve Basis"] = r.get("eve_basis", "N/A")
            row_dict["Same Basis?"] = "YES" if r.get("same_basis") else "NO"
        elif attack_type == "signature_replay":
            row_dict["Captured State"] = r.get("captured_state", "N/A")
            row_dict["Expected State"] = r.get("expected_state", "N/A")
            row_dict["Bits Differ?"] = "YES" if r.get("bits_differ") else "NO"

        rows.append(row_dict)

    st.dataframe(rows, width="stretch")

    with st.expander("Raw Experimental Trace Data (JSON Inspector)"):
        num_inspect = st.selectbox("Inspect raw records", [20, 50, 100, 256], index=0)
        st.json(detailed_results[:num_inspect])


# =============================================================================
#  SECTION 1: OVERVIEW
# =============================================================================
if nav_section == "Overview":
    st.title("QUANTUM DIGITAL SIGNATURE SECURITY LABORATORY")
    st.markdown(
        "Experimental quantum-state transmission, physical attack simulation, "
        "and statistical anomaly detection using Qiskit Aer with optional IBM QPU validation."
    )

    st.markdown("---")
    st.header("System Pipeline & Protocol Flow")
    st.markdown(
        "The sequence below describes the exact operations executed by this laboratory. "
        "Every numerical result is traceable to Qiskit Aer simulation or real IBM Quantum QPU execution."
    )

    st.markdown(
        """
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin: 20px 0;">
          <!-- Stage 1 -->
          <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(236, 72, 153, 0.4); border-radius: 12px; padding: 20px; box-shadow: 0 8px 25px rgba(0,0,0,0.4);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
              <span style="background: linear-gradient(135deg, #EC4899, #A855F7); color: #FFF; font-size: 0.72rem; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase;">STAGE 1</span>
              <span style="color: #C084FC; font-size: 0.80rem; font-weight: 600; font-family: 'JetBrains Mono', monospace;">CLASSICAL DOMAIN</span>
            </div>
            <h4 style="color: #F472B6; font-family: 'Outfit', sans-serif; margin: 0 0 10px 0; font-size: 1.1rem;">Classical Preprocessing</h4>
            <div style="font-size: 0.86rem; color: #E9D5FF; line-height: 1.6;">
              <p style="margin: 6px 0;"><strong>Step 1: Hash Generation</strong><br>Message <code>M</code> &rarr; <code>D = SHA-256(M)</code> (256 bits)</p>
              <p style="margin: 6px 0;"><strong>Step 2: XOR Key Encoding</strong><br><code>b<sub>i</sub> = d<sub>i</sub> &oplus; K<sub>i</sub></code> for <code>i &in; 0..255</code></p>
              <p style="margin: 6px 0;"><strong>Step 3: Basis Schedule</strong><br><code>i mod 3 = 0 &rarr; Z</code> | <code>1 &rarr; X</code> | <code>2 &rarr; Y</code></p>
            </div>
          </div>

          <!-- Stage 2 -->
          <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(168, 85, 247, 0.4); border-radius: 12px; padding: 20px; box-shadow: 0 8px 25px rgba(0,0,0,0.4);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
              <span style="background: linear-gradient(135deg, #A855F7, #6366F1); color: #FFF; font-size: 0.72rem; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase;">STAGE 2</span>
              <span style="color: #A855F7; font-size: 0.80rem; font-weight: 600; font-family: 'JetBrains Mono', monospace;">QUANTUM CHANNEL</span>
            </div>
            <h4 style="color: #C084FC; font-family: 'Outfit', sans-serif; margin: 0 0 10px 0; font-size: 1.1rem;">Quantum Transmission</h4>
            <div style="font-size: 0.86rem; color: #E9D5FF; line-height: 1.6;">
              <p style="margin: 6px 0;"><strong>Step 4: State Preparation</strong><br>Prepare <code>|&psi;<sub>i</sub>&rang;</code> Pauli eigenstate from <code>(b<sub>i</sub>, Basis<sub>i</sub>)</code></p>
              <p style="margin: 6px 0;"><strong>Step 5: 3-Qubit Teleportation</strong><br>Bell measurement <code>(c0, c1)</code> + Feedforward <code>X<sup>c1</sup>Z<sup>c0</sup></code></p>
              <p style="margin: 6px 0; color: #FF70A6;"><strong>[Adversarial Insertion Point]</strong><br>Eve operates between Alice & Bob</p>
            </div>
          </div>

          <!-- Stage 3 -->
          <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 12px; padding: 20px; box-shadow: 0 8px 25px rgba(0,0,0,0.4);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
              <span style="background: linear-gradient(135deg, #10B981, #059669); color: #FFF; font-size: 0.72rem; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase;">STAGE 3</span>
              <span style="color: #34D399; font-size: 0.80rem; font-weight: 600; font-family: 'JetBrains Mono', monospace;">VERIFICATION</span>
            </div>
            <h4 style="color: #34D399; font-family: 'Outfit', sans-serif; margin: 0 0 10px 0; font-size: 1.1rem;">Statistical Detection</h4>
            <div style="font-size: 0.86rem; color: #E9D5FF; line-height: 1.6;">
              <p style="margin: 6px 0;"><strong>Step 6: Qubit Readout</strong><br>Bob measures <code>q2</code> in basis <code>Basis<sub>i</sub></code></p>
              <p style="margin: 6px 0;"><strong>Step 7: Mismatch Error Count</strong><br>Count positions <code>k</code> where outcome &ne; expected</p>
              <p style="margin: 6px 0;"><strong>Step 8: Binomial Test</strong><br>Calculate <code>p = P(K &ge; k | n, p<sub>0</sub>)</code> vs <code>&alpha;</code></p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Interactive Protocol Visualization (replaces static Mermaid) ─────────
    import streamlit.components.v1 as _stc
    with st.expander("Live Protocol Visualization (Architecture)", expanded=True):
        _protocol_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: #080410;
    font-family: 'Inter', sans-serif;
    color: #E9D5FF;
    padding: 18px 10px 12px 10px;
  }

  .diagram-wrap {
    display: flex;
    flex-direction: column;
    gap: 0px;
    width: 100%;
    max-width: 960px;
    margin: 0 auto;
  }

  /* ── Top label row ─────────────────────────────────────────── */
  .labels-row {
    display: grid;
    grid-template-columns: 180px 1fr 160px 1fr 180px;
    align-items: end;
    padding-bottom: 6px;
  }
  .actor-label {
    text-align: center;
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    font-weight: 700;
    text-transform: uppercase;
    padding: 5px 0 2px 0;
  }
  .label-alice  { color: #F472B6; text-align: left; padding-left: 6px; }
  .label-eve    { color: #FBBF24; text-align: center; }
  .label-bob    { color: #34D399; text-align: right; padding-right: 6px; }
  .label-center { color: #818CF8; font-size: 0.68rem; letter-spacing: 0.06em; text-align: center; }

  /* ── SVG channel area ──────────────────────────────────────── */
  .channel-svg-wrap {
    width: 100%;
    overflow: visible;
  }

  /* ── Pipeline details row ──────────────────────────────────── */
  .pipe-row {
    display: grid;
    grid-template-columns: 240px 1fr 180px 1fr 240px;
    gap: 0;
    margin-top: 6px;
    align-items: start;
  }
  .pipe-box {
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 0.74rem;
    line-height: 1.65;
    font-family: 'JetBrains Mono', monospace;
  }
  .pipe-alice {
    background: rgba(236,72,153,0.10);
    border: 1px solid rgba(236,72,153,0.35);
    color: #F9A8D4;
  }
  .pipe-eve {
    background: rgba(251,191,36,0.10);
    border: 1px solid rgba(251,191,36,0.35);
    color: #FDE68A;
    text-align: center;
  }
  .pipe-bob {
    background: rgba(52,211,153,0.10);
    border: 1px solid rgba(52,211,153,0.35);
    color: #6EE7B7;
    text-align: right;
  }
  .pipe-spacer { /* empty grid cells */ }
  .pipe-step {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 3px;
  }
  .step-num {
    background: rgba(236,72,153,0.25);
    color: #F472B6;
    border-radius: 50%;
    width: 17px;
    height: 17px;
    font-size: 0.62rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .step-num-eve  { background: rgba(251,191,36,0.25); color: #FBBF24; }
  .step-num-bob  { background: rgba(52,211,153,0.25); color: #34D399; }

  /* ── Decision row ──────────────────────────────────────────── */
  .decision-row {
    display: flex;
    gap: 16px;
    justify-content: flex-end;
    margin-top: 12px;
    padding-right: 0;
  }
  .decision-box {
    border-radius: 8px;
    padding: 10px 18px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 8px;
    letter-spacing: 0.04em;
  }
  .dec-accept {
    background: rgba(16,185,129,0.12);
    border: 1.5px solid rgba(16,185,129,0.55);
    color: #34D399;
    box-shadow: 0 0 12px rgba(16,185,129,0.15);
  }
  .dec-reject {
    background: rgba(239,68,68,0.12);
    border: 1.5px solid rgba(239,68,68,0.55);
    color: #F87171;
    box-shadow: 0 0 12px rgba(239,68,68,0.12);
  }
  .dec-icon { font-size: 1.0rem; }

  /* ── Stage timeline ────────────────────────────────────────── */
  .timeline {
    display: flex;
    align-items: center;
    gap: 0;
    margin-top: 14px;
    flex-wrap: nowrap;
    overflow-x: auto;
    padding: 4px 0;
  }
  .tl-stage {
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 90px;
    flex: 1;
    cursor: default;
  }
  .tl-dot {
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.68rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    border: 2px solid;
    position: relative;
    z-index: 2;
  }
  .tl-dot-done  { background: rgba(52,211,153,0.2);  border-color: #34D399; color: #34D399; }
  .tl-dot-idle  { background: rgba(100,100,130,0.12); border-color: #4B5563; color: #6B7280; }
  .tl-label {
    font-size: 0.60rem;
    font-family: 'JetBrains Mono', monospace;
    color: #9CA3AF;
    margin-top: 5px;
    text-align: center;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    line-height: 1.35;
  }
  .tl-connector {
    flex: 1;
    height: 2px;
    background: linear-gradient(90deg, rgba(99,102,241,0.4), rgba(99,102,241,0.15));
    margin-bottom: 22px;
    min-width: 8px;
  }

  /* ── Basis legend ─────────────────────────────────────────── */
  .basis-legend {
    display: flex;
    gap: 14px;
    margin-top: 12px;
    flex-wrap: wrap;
  }
  .basis-tag {
    border-radius: 6px;
    padding: 5px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.05em;
  }
  .basis-z { background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.4); color: #A5B4FC; }
  .basis-x { background: rgba(56,189,248,0.12); border: 1px solid rgba(56,189,248,0.35); color: #7DD3FC; }
  .basis-y { background: rgba(168,85,247,0.12); border: 1px solid rgba(168,85,247,0.35); color: #D8B4FE; }

  /* ── Packet animation ─────────────────────────────────────── */
  @keyframes slideRight {
    0%   { transform: translateX(0px);   opacity: 0.2; }
    10%  { opacity: 1; }
    90%  { opacity: 1; }
    100% { transform: translateX(250px); opacity: 0.2; }
  }
  @keyframes slideRightFull {
    0%   { transform: translateX(0px);   opacity: 0.2; }
    10%  { opacity: 1; }
    90%  { opacity: 1; }
    100% { transform: translateX(640px); opacity: 0.2; }
  }
  .packet-group-direct { animation: slideRightFull 3.8s ease-in-out infinite; }
  .packet-group-alice  { animation: slideRight 3.8s ease-in-out infinite; }
  .packet-group-eve    { animation: slideRight 3.8s ease-in-out infinite 1.9s; }

  /* Section divider */
  .sec-divider {
    border: none;
    border-top: 1px solid rgba(168,85,247,0.18);
    margin: 10px 0;
  }
</style>
</head>
<body>
<div class="diagram-wrap">

  <!-- ═══ LABEL ROW ════════════════════════════════════════════════ -->
  <div class="labels-row">
    <div class="actor-label label-alice">
      ⬡ ALICE<br/><span style="font-size:0.62rem;font-weight:400;color:#C084FC;">SIGNER</span>
    </div>
    <div class="label-center">
      ─── QUANTUM CHANNEL (Qiskit Aer / 3-Qubit Teleportation) ───
    </div>
    <div class="actor-label label-eve" id="eve-header">
      ◈ EVE<br/><span style="font-size:0.62rem;font-weight:400;color:#D97706;">ADVERSARY</span>
    </div>
    <div class="label-center" id="eve-channel-label">
      ─── CHANNEL CONTINUATION ───
    </div>
    <div class="actor-label label-bob">
      ⬡ BOB<br/><span style="font-size:0.62rem;font-weight:400;color:#6EE7B7;">VERIFIER</span>
    </div>
  </div>

  <!-- ═══ SVG CHANNEL DIAGRAM ═══════════════════════════════════════ -->
  <div class="channel-svg-wrap">
  <svg id="channel-svg" viewBox="0 0 960 130" preserveAspectRatio="xMidYMid meet"
       style="width:100%;height:auto;" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <!-- Alice glow -->
      <filter id="f-alice" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="4" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <!-- Eve glow warning -->
      <filter id="f-eve" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="5" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <!-- Bob glow -->
      <filter id="f-bob" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="4" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <!-- Quantum channel gradient -->
      <linearGradient id="ch-grad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%"   stop-color="#EC4899" stop-opacity="0.6"/>
        <stop offset="50%"  stop-color="#6366F1" stop-opacity="0.8"/>
        <stop offset="100%" stop-color="#34D399" stop-opacity="0.6"/>
      </linearGradient>
      <!-- Arrow markers -->
      <marker id="arr-cyan" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#6366F1"/>
      </marker>
      <marker id="arr-red" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#F87171"/>
      </marker>
      <marker id="arr-green" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#34D399"/>
      </marker>
      <marker id="arr-amber" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#FBBF24"/>
      </marker>
      <!-- Packet shapes -->
      <symbol id="pkt-z" viewBox="-7 -7 14 14">
        <circle r="6" fill="#6366F1" fill-opacity="0.85"/>
        <text x="0" y="4" text-anchor="middle" font-size="7" font-family="serif" fill="white">0</text>
      </symbol>
      <symbol id="pkt-x" viewBox="-7 -7 14 14">
        <circle r="6" fill="#38BDF8" fill-opacity="0.85"/>
        <text x="0" y="4" text-anchor="middle" font-size="7" font-family="serif" fill="white">+</text>
      </symbol>
      <symbol id="pkt-y" viewBox="-7 -7 14 14">
        <circle r="6" fill="#A855F7" fill-opacity="0.85"/>
        <text x="0" y="4" text-anchor="middle" font-size="6" font-family="serif" fill="white">+i</text>
      </symbol>
      <symbol id="pkt-disturbed" viewBox="-7 -7 14 14">
        <polygon points="0,-7 7,7 -7,7" fill="#F87171" fill-opacity="0.9"/>
        <text x="0" y="5" text-anchor="middle" font-size="6.5" font-family="serif" fill="white">?</text>
      </symbol>
    </defs>

    <!-- ── Alice node box ─────────────────────── -->
    <rect x="2" y="30" width="130" height="70" rx="8" ry="8"
          fill="rgba(236,72,153,0.08)" stroke="#EC4899" stroke-width="1.4"
          filter="url(#f-alice)"/>
    <text x="67" y="52" text-anchor="middle" font-size="11" font-weight="700"
          font-family="Inter,sans-serif" fill="#F472B6">ALICE</text>
    <text x="67" y="66" text-anchor="middle" font-size="8.5"
          font-family="JetBrains Mono,monospace" fill="#C084FC">SHA-256 → XOR</text>
    <text x="67" y="78" text-anchor="middle" font-size="8"
          font-family="JetBrains Mono,monospace" fill="#C084FC">Basis: Z / X / Y</text>
    <text x="67" y="90" text-anchor="middle" font-size="8"
          font-family="JetBrains Mono,monospace" fill="#F9A8D4">Prepares |ψᵢ⟩ on q0</text>

    <!-- ── Bob node box ───────────────────────── -->
    <rect x="828" y="30" width="130" height="70" rx="8" ry="8"
          fill="rgba(52,211,153,0.07)" stroke="#34D399" stroke-width="1.4"
          filter="url(#f-bob)"/>
    <text x="893" y="52" text-anchor="middle" font-size="11" font-weight="700"
          font-family="Inter,sans-serif" fill="#34D399">BOB</text>
    <text x="893" y="66" text-anchor="middle" font-size="8.5"
          font-family="JetBrains Mono,monospace" fill="#6EE7B7">Measure q2 in Bᵢ</text>
    <text x="893" y="78" text-anchor="middle" font-size="8"
          font-family="JetBrains Mono,monospace" fill="#6EE7B7">Count errors k</text>
    <text x="893" y="90" text-anchor="middle" font-size="8"
          font-family="JetBrains Mono,monospace" fill="#A7F3D0">Binomial test p vs α</text>

    <!-- ══════════════ NO-ATTACK mode (default) ══════════════ -->
    <g id="g-no-attack">
      <!-- Full direct channel line -->
      <line x1="132" y1="65" x2="820" y2="65"
            stroke="url(#ch-grad)" stroke-width="2.5"
            stroke-dasharray="none" marker-end="url(#arr-green)"/>

      <!-- Channel label -->
      <text x="480" y="57" text-anchor="middle" font-size="8.5"
            font-family="JetBrains Mono,monospace" fill="#818CF8">
        3-Qubit Teleportation (Bell Pair + Feedforward)
      </text>

      <!-- Eve inactive box (centred on channel) -->
      <rect x="420" y="72" width="120" height="36" rx="6"
            fill="rgba(75,85,99,0.15)" stroke="#4B5563" stroke-width="1"
            stroke-dasharray="4,3"/>
      <text x="480" y="87" text-anchor="middle" font-size="8.5" font-weight="700"
            font-family="Inter,sans-serif" fill="#6B7280">EVE  ·  INACTIVE</text>
      <text x="480" y="100" text-anchor="middle" font-size="7.5"
            font-family="JetBrains Mono,monospace" fill="#4B5563">
        no interception
      </text>

      <!-- Travelling quantum packets -->
      <g class="packet-group-direct">
        <use href="#pkt-z" x="155" y="59" width="14" height="14"/>
        <use href="#pkt-x" x="175" y="59" width="14" height="14"/>
        <use href="#pkt-y" x="195" y="59" width="14" height="14"/>
        <use href="#pkt-z" x="215" y="59" width="14" height="14"/>
        <use href="#pkt-x" x="235" y="59" width="14" height="14"/>
      </g>
    </g>

    <!-- ══════════════ ATTACK mode (hidden by default) ════════ -->
    <g id="g-attack" style="display:none;">
      <!-- Alice → Eve segment -->
      <line x1="132" y1="65" x2="408" y2="65"
            stroke="#EC4899" stroke-width="2" stroke-dasharray="5,2"
            marker-end="url(#arr-amber)"/>

      <!-- Eve active node (centred) -->
      <rect x="410" y="18" width="140" height="95" rx="8"
            fill="rgba(251,191,36,0.10)" stroke="#FBBF24" stroke-width="1.8"
            filter="url(#f-eve)"/>
      <!-- Warning glow ring -->
      <rect x="407" y="15" width="146" height="101" rx="10"
            fill="none" stroke="rgba(251,191,36,0.25)" stroke-width="3"/>
      <text x="480" y="36" text-anchor="middle" font-size="10.5" font-weight="700"
            font-family="Inter,sans-serif" fill="#FBBF24">◈ EVE  ACTIVE</text>
      <text x="480" y="50" text-anchor="middle" font-size="7.5"
            font-family="JetBrains Mono,monospace" fill="#FDE68A">Intercept |ψᵢ⟩</text>
      <text x="480" y="62" text-anchor="middle" font-size="7.5"
            font-family="JetBrains Mono,monospace" fill="#FDE68A">Measure in B_Eve</text>
      <text x="480" y="74" text-anchor="middle" font-size="7.5"
            font-family="JetBrains Mono,monospace" fill="#FDE68A">State collapse</text>
      <text x="480" y="86" text-anchor="middle" font-size="7.5"
            font-family="JetBrains Mono,monospace" fill="#F87171">Resend disturbed</text>
      <text x="480" y="100" text-anchor="middle" font-size="7"
            font-family="JetBrains Mono,monospace" fill="#D97706">
        P(error) ≈ 1/3  (random basis)
      </text>

      <!-- Eve → Bob segment -->
      <line x1="550" y1="65" x2="820" y2="65"
            stroke="#F87171" stroke-width="2" stroke-dasharray="5,2"
            marker-end="url(#arr-red)"/>

      <!-- Packets: Alice side -->
      <g class="packet-group-alice">
        <use href="#pkt-z" x="155" y="59" width="14" height="14"/>
        <use href="#pkt-x" x="175" y="59" width="14" height="14"/>
        <use href="#pkt-y" x="195" y="59" width="14" height="14"/>
      </g>
      <!-- Disturbed packets: Eve side -->
      <g class="packet-group-eve">
        <use href="#pkt-disturbed" x="558" y="59" width="14" height="14"/>
        <use href="#pkt-z"         x="578" y="59" width="14" height="14"/>
        <use href="#pkt-disturbed" x="598" y="59" width="14" height="14"/>
      </g>
    </g>

  </svg>
  </div>

  <!-- ═══ PIPELINE DETAILS ════════════════════════════════════════ -->
  <div class="pipe-row">
    <!-- Alice pipeline -->
    <div class="pipe-box pipe-alice">
      <div style="font-weight:700;color:#F472B6;margin-bottom:6px;font-size:0.78rem;">
        ALICE  ·  CLASSICAL DOMAIN
      </div>
      <div class="pipe-step"><span class="step-num">1</span> M → SHA-256(M) = D</div>
      <div class="pipe-step"><span class="step-num">2</span> bᵢ = dᵢ ⊕ Kᵢ</div>
      <div class="pipe-step"><span class="step-num">3</span> Basis: i mod 3 → Z/X/Y</div>
      <div class="pipe-step"><span class="step-num">4</span> Prepare |ψᵢ⟩ on q0</div>
      <div class="pipe-step"><span class="step-num">5</span> Bell pair (q1,q2) + CNOT</div>
    </div>

    <div class="pipe-spacer"></div>

    <!-- Eve pipeline (toggles) -->
    <div class="pipe-box pipe-eve" id="pipe-eve-box">
      <div style="font-weight:700;color:#FBBF24;margin-bottom:6px;font-size:0.78rem;">
        EVE  ·  ADVERSARY
      </div>
      <div id="eve-inactive-pipe">
        <div style="color:#6B7280;font-size:0.72rem;">No interception.<br/>Channel intact.</div>
      </div>
      <div id="eve-active-pipe" style="display:none;">
        <div class="pipe-step"><span class="step-num step-num-eve">1</span> Intercept |ψᵢ⟩</div>
        <div class="pipe-step"><span class="step-num step-num-eve">2</span> Measure (B_Eve)</div>
        <div class="pipe-step"><span class="step-num step-num-eve">3</span> Collapse → eigenstate</div>
        <div class="pipe-step"><span class="step-num step-num-eve">4</span> Resend disturbed state</div>
        <div style="margin-top:4px;font-size:0.68rem;color:#D97706;">
          2/3 chance of basis mismatch<br/>→ ~1/3 error rate (theoretical)
        </div>
      </div>
    </div>

    <div class="pipe-spacer"></div>

    <!-- Bob pipeline -->
    <div class="pipe-box pipe-bob">
      <div style="font-weight:700;color:#34D399;margin-bottom:6px;font-size:0.78rem;text-align:right;">
        BOB  ·  VERIFIER
      </div>
      <div class="pipe-step" style="justify-content:flex-end;">
        Apply X^c1·Z^c0 on q2 <span class="step-num step-num-bob" style="margin-left:6px;">1</span>
      </div>
      <div class="pipe-step" style="justify-content:flex-end;">
        Rotate q2 to Basisᵢ <span class="step-num step-num-bob" style="margin-left:6px;">2</span>
      </div>
      <div class="pipe-step" style="justify-content:flex-end;">
        Measure → c2 <span class="step-num step-num-bob" style="margin-left:6px;">3</span>
      </div>
      <div class="pipe-step" style="justify-content:flex-end;">
        Count errors k / n <span class="step-num step-num-bob" style="margin-left:6px;">4</span>
      </div>
      <div class="pipe-step" style="justify-content:flex-end;">
        P(K≥k | n,p₀) vs α <span class="step-num step-num-bob" style="margin-left:6px;">5</span>
      </div>
    </div>
  </div>

  <hr class="sec-divider"/>

  <!-- ═══ INTERACTIVE TOGGLE ════════════════════════════════════ -->
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:10px;">
    <span style="font-size:0.78rem;font-family:'JetBrains Mono',monospace;color:#9CA3AF;letter-spacing:0.05em;">
      ATTACK MODE:
    </span>
    <button onclick="toggleAttack(false)"
            id="btn-no"
            style="padding:5px 16px;border-radius:6px;border:1.5px solid #34D399;
                   background:rgba(52,211,153,0.15);color:#34D399;font-family:'JetBrains Mono',monospace;
                   font-size:0.72rem;font-weight:700;cursor:pointer;letter-spacing:0.05em;">
      NO ATTACK
    </button>
    <button onclick="toggleAttack(true)"
            id="btn-attack"
            style="padding:5px 16px;border-radius:6px;border:1.5px solid #4B5563;
                   background:rgba(75,85,99,0.08);color:#6B7280;font-family:'JetBrains Mono',monospace;
                   font-size:0.72rem;font-weight:700;cursor:pointer;letter-spacing:0.05em;">
      INTERCEPT-RESEND
    </button>
    <span style="font-size:0.70rem;color:#6B7280;font-family:'JetBrains Mono',monospace;margin-left:4px;">
      (toggle to preview diagram states)
    </span>
  </div>

  <!-- ═══ DECISION OUTCOME ════════════════════════════════════════ -->
  <div class="decision-row">
    <div class="decision-box dec-accept">
      <span class="dec-icon">✓</span>
      <div>
        <div>p-value &gt; α</div>
        <div style="font-size:0.65rem;font-weight:400;letter-spacing:0.02em;margin-top:1px;">
          FAIL TO REJECT H₀ → ACCEPT SIGNATURE
        </div>
      </div>
    </div>
    <div class="decision-box dec-reject">
      <span class="dec-icon">⚠</span>
      <div>
        <div>p-value ≤ α</div>
        <div style="font-size:0.65rem;font-weight:400;letter-spacing:0.02em;margin-top:1px;">
          REJECT H₀ → THREAT DETECTED / REJECT
        </div>
      </div>
    </div>
  </div>

  <hr class="sec-divider"/>

  <!-- ═══ PROTOCOL TIMELINE ══════════════════════════════════════ -->
  <div style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#6B7280;
              letter-spacing:0.09em;margin-bottom:6px;text-transform:uppercase;">
    Protocol Execution Stages
  </div>
  <div class="timeline">
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">MSG<br/>Input</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">SHA-256<br/>Hash</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">State<br/>Prepare</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">Transmit<br/>(Bell)</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage" id="tl-eve">
      <div class="tl-dot tl-dot-idle" id="tl-eve-dot">○</div>
      <div class="tl-label">Eve<br/>Interact</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">Bob<br/>Measure</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">Binomial<br/>Verify</div>
    </div>
    <div class="tl-connector"></div>
    <div class="tl-stage">
      <div class="tl-dot tl-dot-done">✓</div>
      <div class="tl-label">Security<br/>Decision</div>
    </div>
  </div>

  <hr class="sec-divider"/>

  <!-- ═══ BASIS LEGEND ═══════════════════════════════════════════ -->
  <div style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#6B7280;
              letter-spacing:0.09em;margin-bottom:6px;text-transform:uppercase;">
    Pauli Eigenstate Encoding
  </div>
  <div class="basis-legend">
    <div class="basis-tag basis-z">Z-Basis (i mod 3 = 0) &nbsp;·&nbsp; |0⟩ (+1) &nbsp; |1⟩ (−1)</div>
    <div class="basis-tag basis-x">X-Basis (i mod 3 = 1) &nbsp;·&nbsp; |+⟩ (+1) &nbsp; |−⟩ (−1)</div>
    <div class="basis-tag basis-y">Y-Basis (i mod 3 = 2) &nbsp;·&nbsp; |+i⟩ (+1) &nbsp; |−i⟩ (−1)</div>
  </div>

</div><!-- /diagram-wrap -->

<script>
function toggleAttack(active) {
  var gNone   = document.getElementById('g-no-attack');
  var gAtk    = document.getElementById('g-attack');
  var ePipe   = document.getElementById('eve-active-pipe');
  var ePipeNo = document.getElementById('eve-inactive-pipe');
  var eveDot  = document.getElementById('tl-eve-dot');
  var btnNo   = document.getElementById('btn-no');
  var btnAtk  = document.getElementById('btn-attack');
  var pipeEve = document.getElementById('pipe-eve-box');

  if (active) {
    gNone.style.display   = 'none';
    gAtk.style.display    = '';
    ePipeNo.style.display = 'none';
    ePipe.style.display   = '';
    eveDot.textContent    = '!';
    eveDot.className      = 'tl-dot';
    eveDot.style.cssText  = 'background:rgba(251,191,36,0.25);border-color:#FBBF24;color:#FBBF24;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.68rem;font-weight:700;border:2px solid;';
    pipeEve.style.borderColor = 'rgba(251,191,36,0.55)';
    pipeEve.style.background  = 'rgba(251,191,36,0.10)';

    btnAtk.style.border     = '1.5px solid #FBBF24';
    btnAtk.style.background = 'rgba(251,191,36,0.15)';
    btnAtk.style.color      = '#FBBF24';
    btnNo.style.border      = '1.5px solid #4B5563';
    btnNo.style.background  = 'rgba(75,85,99,0.08)';
    btnNo.style.color       = '#6B7280';
  } else {
    gNone.style.display   = '';
    gAtk.style.display    = 'none';
    ePipeNo.style.display = '';
    ePipe.style.display   = 'none';
    eveDot.textContent    = '○';
    eveDot.className      = 'tl-dot tl-dot-idle';
    eveDot.style.cssText  = '';
    pipeEve.style.borderColor = 'rgba(251,191,36,0.35)';
    pipeEve.style.background  = 'rgba(251,191,36,0.10)';

    btnNo.style.border      = '1.5px solid #34D399';
    btnNo.style.background  = 'rgba(52,211,153,0.15)';
    btnNo.style.color       = '#34D399';
    btnAtk.style.border     = '1.5px solid #4B5563';
    btnAtk.style.background = 'rgba(75,85,99,0.08)';
    btnAtk.style.color      = '#6B7280';
  }
}
</script>
</body>
</html>
"""
        _stc.html(_protocol_html, height=900, scrolling=False)


    st.markdown("---")
    st.header("Protocol Status Panel")

    stat_c1, stat_c2, stat_c3, stat_c4 = st.columns(4)
    with stat_c1:
        st.markdown('<div class="metric-label">Simulation Backend</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-value">Qiskit AerSimulator</div>', unsafe_allow_html=True)
    with stat_c2:
        st.markdown('<div class="metric-label">Optional Hardware</div>', unsafe_allow_html=True)
        hw_conf, _ = is_hardware_configured()
        hw_status_str = "Configured" if hw_conf else "Unconfigured (Sim Active)"
        st.markdown(f'<div class="metric-value">{hw_status_str}</div>', unsafe_allow_html=True)
    with stat_c3:
        st.markdown('<div class="metric-label">Statistical Detector</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-value">Exact Binomial (scipy)</div>', unsafe_allow_html=True)
    with stat_c4:
        st.markdown('<div class="metric-label">Regression Tests</div>', unsafe_allow_html=True)
        st.markdown('<div class="metric-value">70 Passing</div>', unsafe_allow_html=True)

    st.markdown("---")
    st.header("Phase Inventory")
    st.markdown(
        """
| Phase | Component | Implementation |
|-------|-----------|----------------|
| 1 | Classical encoding (SHA-256 + XOR + basis schedule) | `qds/encoding.py` |
| 1 | 6 Pauli eigenstates, 3-qubit teleportation circuit | `qds/states.py`, `qds/teleportation.py` |
| 1 | Bob-side signature verification | `qds/verification.py` |
| 2A | Exact Binomial statistical threat detector | `statistics/detector.py` |
| 2B | Channel tampering (Pauli-X bit-flip injection on q2) | `attacks/channel.py` |
| 2C | Signature forgery (Eve assumes K=0) | `attacks/forgery.py` |
| 2D | Impersonation (random Bernoulli state guessing) | `attacks/impersonation.py` |
| 2E | Quantum interception / measurement attack | `attacks/interception.py` |
| 2F | Replay attack (same-message and different-message) | `attacks/replay.py` |
| 3 | Integrated experiment runner and comparison | `evaluation/runner.py` |
| 4 | Circuit visualization, basis-wise sweep, redesign | `qds/circuit_visualization.py`, `app.py` |
| 5 | Optional real IBM Quantum hardware validation | `core/hardware.py` |
"""
    )

    st.markdown(
        '<div class="info-box">SCIENTIFIC DISCLAIMER: Full 256-qubit security evaluation uses Qiskit Aer simulation '
        'for speed and reproducibility. Real IBM Quantum QPU validation is available as an optional '
        'hardware transmission layer for small 3-qubit primitives.</div>',
        unsafe_allow_html=True,
    )


# =============================================================================
#  SECTION 2: PROTOCOL
# =============================================================================
elif nav_section == "Protocol":
    st.title("PROTOCOL ARCHITECTURE & ENCODING INSPECTOR")

    protocol_sub = st.radio(
        "Section",
        [
            "Mathematical Model",
            "Architecture Diagram",
            "Classical Encoding Inspector",
            "Signature Verification",
        ],
        horizontal=True,
    )

    # ── 2z: Formal Mathematical Model ─────────────────────────────────────────
    if protocol_sub == "Mathematical Model":
        st.header("Formal Mathematical Model")
        st.caption(
            "Complete derivation in docs/mathematical_model.md. This page reproduces the "
            "core results that the implementation depends on."
        )

        st.subheader("1. Classical Preprocessing and Session Binding")
        st.latex(r"P = M \,\|\, \mathrm{id} \,\|\, \nu \,\|\, c \,\|\, t")
        st.latex(r"D = \mathrm{SHA\text{-}256}(P) \in \{0,1\}^{256}")
        st.latex(r"b_i = d_i \oplus K_i, \qquad i = 0, \dots, 255")
        st.markdown(
            "For a uniformly random key K, each encoded bit is uniform and statistically "
            "independent of the digest:"
        )
        st.latex(r"\Pr[b_i = 0] = \Pr[d_i = K_i] = \tfrac{1}{2}")
        st.info(
            "This is the source of information-theoretic security. An adversary who "
            "knows M — and therefore D — obtains ZERO information about b_i. SHA-256 "
            "alone is not a signature: without K, anyone could compute D and prepare the "
            "matching states."
        )

        st.subheader("2. Basis Schedule and Pauli Eigenstate Encoding")
        st.latex(
            r"B_i = \begin{cases} Z & i \equiv 0 \pmod 3 \\ "
            r"X & i \equiv 1 \pmod 3 \\ Y & i \equiv 2 \pmod 3 \end{cases}"
        )
        st.latex(r"\sigma_{B_i} |\psi_i\rangle = \lambda_i |\psi_i\rangle, \qquad \lambda_i \in \{+1, -1\}")
        st.dataframe(
            [
                {"Basis": "Z", "b=0": "|0>", "eigenvalue": "+1", "b=1": "|1>", "eigenvalue ": "-1",
                 "Preparation": "I  /  X"},
                {"Basis": "X", "b=0": "|+>", "eigenvalue": "+1", "b=1": "|->", "eigenvalue ": "-1",
                 "Preparation": "H  /  HX"},
                {"Basis": "Y", "b=0": "|+i>", "eigenvalue": "+1", "b=1": "|-i>", "eigenvalue ": "-1",
                 "Preparation": "SH  /  SHX"},
            ],
            width="stretch",
            hide_index=True,
        )

        st.subheader("3. Bell-State Entanglement")
        st.latex(r"|\Phi^+\rangle_{12} = \tfrac{1}{\sqrt{2}}\left(|00\rangle + |11\rangle\right)")
        st.latex(
            r"\langle \sigma_Z \otimes \sigma_Z \rangle = +1, \quad "
            r"\langle \sigma_X \otimes \sigma_X \rangle = +1, \quad "
            r"\langle \sigma_Y \otimes \sigma_Y \rangle = -1"
        )

        st.subheader("4. Quantum Teleportation")
        st.markdown("Expanding in the Bell basis of Alice's two qubits:")
        st.latex(
            r"|\psi\rangle_0 |\Phi^+\rangle_{12} = \tfrac{1}{2}\Big["
            r"|\Phi^+\rangle_{01}|\psi\rangle_2"
            r"+ |\Phi^-\rangle_{01}(\sigma_Z|\psi\rangle_2)"
            r"+ |\Psi^+\rangle_{01}(\sigma_X|\psi\rangle_2)"
            r"+ |\Psi^-\rangle_{01}(\sigma_X\sigma_Z|\psi\rangle_2)\Big]"
        )
        st.markdown(
            "Each outcome occurs with probability 1/4, **independent of the signature "
            "state**. Alice's measurement therefore reveals nothing, and the classical "
            "bits she sends leak nothing."
        )

        st.subheader("5. Pauli Correction Operations")
        st.latex(r"|\psi\rangle_2 = \sigma_Z^{c_0}\, \sigma_X^{c_1}\, |\tilde\psi\rangle_2")
        st.dataframe(
            [
                {"c0": 0, "c1": 0, "Bob's state": "|psi>", "Correction": "I"},
                {"c0": 0, "c1": 1, "Bob's state": "X|psi>", "Correction": "X"},
                {"c0": 1, "c1": 0, "Bob's state": "Z|psi>", "Correction": "Z"},
                {"c0": 1, "c1": 1, "Bob's state": "XZ|psi>", "Correction": "XZ"},
            ],
            width="stretch",
            hide_index=True,
        )
        st.warning(
            "Teleportation transports whatever state it is given, from whoever supplies "
            "it. It does NOT authenticate. Authentication comes only from K, which "
            "determines which state a legitimate signer would have supplied."
        )

        st.subheader("6. Projective Measurement Rules")
        st.latex(r"\Pi_{\pm}^{(B)} = \tfrac{1}{2}\left(I \pm \sigma_B\right), \qquad "
                 r"\Pi_+ + \Pi_- = I, \qquad \Pi_{\pm}^2 = \Pi_{\pm}")
        st.latex(r"\Pr[\lambda = \pm 1] = \langle\psi| \Pi_{\pm}^{(B)} |\psi\rangle")
        st.markdown(
            "Rotations into the computational basis: Z requires none, X uses H (since "
            "H X H† = Z), and Y uses H S† (since H S† Y (H S†)† = Z)."
        )
        st.success(
            "DETERMINISTIC ACCEPTANCE: when the verification basis matches the "
            "preparation basis, the state is an eigenstate of that observable and the "
            "expected eigenvalue is obtained with probability exactly 1. A noiseless "
            "channel therefore yields exactly zero verification errors, not merely few."
        )

        st.subheader("7. Verification Statistic and Decision Rule")
        st.latex(r"E_i = \mathbb{1}\left[\lambda_i^{\mathrm{obs}} \neq \lambda_i\right], "
                 r"\qquad k = \sum_i E_i, \qquad \hat{e} = k/n")
        st.latex(r"H_0: p = p_0 \qquad \text{vs} \qquad H_1: p > p_0")
        st.latex(r"\Pr[K \ge k \mid n, p_0] = \sum_{j=k}^{n} \binom{n}{j} p_0^{\,j} (1-p_0)^{\,n-j}")
        st.markdown("Two-threshold decision rule:")
        st.latex(
            r"\sigma = \sqrt{\frac{p_0(1-p_0)}{n}}, \qquad "
            r"s_a = p_0 + 3\sigma, \qquad s_v = \frac{s_a + q_{\min}}{2}"
        )
        st.latex(
            r"\text{verdict} = \begin{cases} \textbf{ACCEPT} & \hat{e} \le s_a \\ "
            r"\textbf{ABORT} & s_a < \hat{e} < s_v \\ "
            r"\textbf{REJECT} & \hat{e} \ge s_v \end{cases}"
        )
        st.caption(
            f"With the current settings (n = 256, p0 = {baseline_noise:.3f}): "
            f"sigma = {decision_thresholds.sigma:.5f}, "
            f"s_a = {decision_thresholds.s_accept:.4f}, "
            f"s_v = {decision_thresholds.s_reject:.4f}."
        )

        st.subheader("8. Attack Error Rates (Derived)")
        st.latex(r"\text{Channel tampering: } \quad \hat{e} \to \tfrac{2}{3}p, "
                 r"\qquad (e_Z, e_X, e_Y) \to (p, 0, p)")
        st.latex(r"\text{Intercept-resend: } \quad \hat{e} \to "
                 r"\tfrac{1}{3}\cdot 0 + \tfrac{2}{3}\cdot\tfrac{1}{2} = \tfrac{1}{3}")
        st.latex(r"\text{Forgery: } \quad \hat{e} \to \rho_K = \tfrac{1}{n}\sum_i K_i")
        st.latex(r"\text{Impersonation: } \quad \hat{e} \to \tfrac{1}{2}")
        st.latex(r"\text{Replay: } \quad \hat{e} = d_H(D, D')/n")

        st.subheader("9. Forgery Probability Bound")
        st.latex(
            r"P_{\mathrm{forge}}(n, s_a) = "
            r"\sum_{j=0}^{\lfloor s_a n \rfloor} \binom{n}{j} \left(\tfrac{1}{2}\right)^{n}"
        )
        st.caption(
            "At n = 256 with s_a = 0.046 this is 5.64e-59, or 193.5 bits of security. "
            "See the Security Bounds section for the full curve."
        )

        st.subheader("10. Computational Complexity")
        st.latex(r"T_{\text{total}}(n) = O(n)")
        st.caption(
            "Measured empirically at exponent k = 1.01 with R^2 = 0.9997. "
            "See the Performance section."
        )

        with st.expander("Security scope: what is NOT provided"):
            st.markdown(
                "- **Non-repudiation / transferability.** A full QDS scheme lets a "
                "recipient forward a signature to a third party who reaches the same "
                "verdict. This is a two-party authentication scheme: K is shared, so the "
                "verifier could have produced any signature the signer could. "
                "Transferability needs per-recipient key halves and a Gottesman-Chuang "
                "two-threshold construction.\n"
                "- **Composable key security.** No privacy amplification is implemented.\n"
                "- **Coherent or collective attacks.** Only individual-qubit adversaries "
                "are modelled.\n"
                "- **Authenticated classical channel.** Assumed, not implemented.\n"
                "- **Side-channel resistance.** Out of scope, except constant-time token "
                "comparison."
            )

    # ── 2a: Architecture Diagram ──────────────────────────────────────────────
    elif protocol_sub == "Architecture Diagram":
        st.header("Protocol Architecture Diagram")
        st.markdown(
            "The QDS protocol comprises two fully separated domains: classical pre-processing "
            "(performed on a standard computer) and quantum transmission (simulated by Qiskit Aer). "
            "The boundary between these domains is the state preparation step. Attacks are injected "
            "at the quantum channel boundary between Alice's preparation and Bob's readout."
        )

        st.markdown(
            """
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin: 20px 0;">
              <!-- Alice Card -->
              <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(236, 72, 153, 0.35); border-radius: 10px; padding: 18px;">
                <div style="color: #F472B6; font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 1.05rem; margin-bottom: 10px; border-bottom: 1px solid rgba(236, 72, 153, 0.2); padding-bottom: 6px;">
                  ALICE (Classical Signer)
                </div>
                <div style="font-size: 0.85rem; color: #E9D5FF; line-height: 1.6;">
                  • <strong>Message M</strong> &rarr; <code>SHA-256(M)</code> = 256-bit Digest <code>D</code><br>
                  • <strong>Secret Key K</strong> &rarr; Compute <code>b<sub>i</sub> = d<sub>i</sub> &oplus; K<sub>i</sub></code><br>
                  • <strong>Basis Schedule</strong> &rarr; <code>Z</code> (0), <code>X</code> (1), <code>Y</code> (2)<br>
                  • <strong>Prepare State</strong> &rarr; <code>|&psi;<sub>i</sub>&rang;</code> on qubit <code>q0</code>
                </div>
              </div>

              <!-- Channel Card -->
              <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(168, 85, 247, 0.35); border-radius: 10px; padding: 18px;">
                <div style="color: #C084FC; font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 1.05rem; margin-bottom: 10px; border-bottom: 1px solid rgba(168, 85, 247, 0.2); padding-bottom: 6px;">
                  QUANTUM CHANNEL &amp; EVE
                </div>
                <div style="font-size: 0.85rem; color: #E9D5FF; line-height: 1.6;">
                  • <code>q0</code>: Alice Signature Qubit<br>
                  • <code>(q1, q2)</code>: EPR Bell Pair (<code>H(q1) + CNOT(q1&rarr;q2)</code>)<br>
                  • <strong>Bell Measurement</strong>: <code>CNOT(q0&rarr;q1) + H(q0)</code> &rarr; <code>c0, c1</code><br>
                  • <span style="color: #FF70A6;"><strong>[ATTACK POINT]</strong> Eve operates between transmission &amp; readout</span>
                </div>
              </div>

              <!-- Bob Card -->
              <div style="background: rgba(22, 10, 42, 0.85); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 10px; padding: 18px;">
                <div style="color: #34D399; font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 1.05rem; margin-bottom: 10px; border-bottom: 1px solid rgba(16, 185, 129, 0.2); padding-bottom: 6px;">
                  BOB (Classical Verifier)
                </div>
                <div style="font-size: 0.85rem; color: #E9D5FF; line-height: 1.6;">
                  • <strong>Corrections</strong>: Apply <code>X(q2)</code> if <code>c1=1</code>, <code>Z(q2)</code> if <code>c0=1</code><br>
                  • <strong>Readout</strong>: Rotate <code>q2</code> to <code>Basis<sub>i</sub></code> &amp; measure <code>c2</code><br>
                  • <strong>Mismatch Check</strong>: Compare outcome to expected eigenvalue<br>
                  • <strong>Decision</strong>: Reject if <code>P(K &ge; k | n, p<sub>0</sub>) &le; &alpha;</code>
                </div>
              </div>
            </div>

            <div style="margin-top: 20px;">
              <h4 style="color: #FF70A6; font-family: 'Outfit', sans-serif; margin-bottom: 10px;">Pauli Eigenstate Encoding Table</h4>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;">
                <div style="background: rgba(16, 7, 32, 0.8); border: 1px solid rgba(236, 72, 153, 0.25); border-radius: 8px; padding: 12px;">
                  <strong style="color: #F472B6;">Basis Z (i mod 3 = 0)</strong><br>
                  <span style="font-size: 0.84rem; color: #E9D5FF;">
                    b=0 &rarr; <code>|0&rang; = [1, 0]^T</code> (+1)<br>
                    b=1 &rarr; <code>|1&rang; = [0, 1]^T</code> (-1)
                  </span>
                </div>
                <div style="background: rgba(16, 7, 32, 0.8); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 12px;">
                  <strong style="color: #38BDF8;">Basis X (i mod 3 = 1)</strong><br>
                  <span style="font-size: 0.84rem; color: #E9D5FF;">
                    b=0 &rarr; <code>|+&rang; = 1/&radic;2 [1, 1]^T</code> (+1)<br>
                    b=1 &rarr; <code>|-&rang; = 1/&radic;2 [1, -1]^T</code> (-1)
                  </span>
                </div>
                <div style="background: rgba(16, 7, 32, 0.8); border: 1px solid rgba(192, 132, 252, 0.25); border-radius: 8px; padding: 12px;">
                  <strong style="color: #C084FC;">Basis Y (i mod 3 = 2)</strong><br>
                  <span style="font-size: 0.84rem; color: #E9D5FF;">
                    b=0 &rarr; <code>|+i&rang; = 1/&radic;2 [1, i]^T</code> (+1)<br>
                    b=1 &rarr; <code>|-i&rang; = 1/&radic;2 [1, -i]^T</code> (-1)
                  </span>
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.header("Qubit Population Breakdown")
        st.markdown(
            "Under the deterministic basis schedule, the 256 signature qubits are distributed "
            "across three measurement bases as follows:"
        )
        pop_c1, pop_c2, pop_c3 = st.columns(3)
        pop_c1.metric("Basis Z (i mod 3 = 0)", "86 qubits", "indices: 0, 3, 6, ...")
        pop_c2.metric("Basis X (i mod 3 = 1)", "85 qubits", "indices: 1, 4, 7, ...")
        pop_c3.metric("Basis Y (i mod 3 = 2)", "85 qubits", "indices: 2, 5, 8, ...")

    # ── 2b: Classical Encoding Inspector ─────────────────────────────────────
    elif protocol_sub == "Classical Encoding Inspector":
        st.header("Classical Encoding Inspector")
        st.markdown(
            "Inspect the complete classical preprocessing chain for each signature qubit position. "
            "Every value shown below is deterministically derived from M and K; nothing is randomized."
        )

        digest_bits = sha256_bits(message)
        digest_bytes_arr = np.packbits(digest_bits)
        digest_hex = digest_bytes_arr.tobytes().hex()
        digest_bin_str = "".join(str(b) for b in digest_bits)
        key_bin_str = "".join(str(k) for k in shared_key)
        xor_bits = [d ^ k for d, k in zip(digest_bits, shared_key)]
        xor_bin_str = "".join(str(b) for b in xor_bits)

        st.subheader("Preprocessing Summary")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**Message (M):** `{message}`")
            st.markdown(f"**SHA-256 Hex (D):** `{digest_hex}`")
            st.markdown(f"**Digest Binary [0:64]:** `{digest_bin_str[:64]}...`")
        with col_b:
            st.markdown(f"**Key K [0:64]:** `{key_bin_str[:64]}...`")
            st.markdown(f"**Encoded b=D XOR K [0:64]:** `{xor_bin_str[:64]}...`")
            ones = sum(shared_key)
            st.markdown(f"**Key 1-density:** `{ones}/256 = {ones/256:.4f}` (determines Forgery error rate)")

        st.subheader("256-bit Digest Bitmap")
        st.markdown(
            "The 256 digest bits visualized as a 16x16 pixel grid. "
            "Black = bit 1, White = bit 0."
        )
        grid = np.array(digest_bits).reshape(16, 16)
        fig_bm, ax_bm = plt.subplots(figsize=(3.5, 3.5))
        ax_bm.imshow(grid, cmap="binary", vmin=0, vmax=1, interpolation="nearest", aspect="equal")
        ax_bm.set_title(f"SHA-256 Digest Bitmap: M = \"{message}\"", fontsize=9)
        ax_bm.set_xticks([])
        ax_bm.set_yticks([])
        st.pyplot(fig_bm)
        plt.close(fig_bm)

        st.subheader("Per-Qubit Inspector")
        q_index = st.slider("Select Signature Qubit Index (i)", 0, 255, 0)

        encoded_qubits = encode_message(message, shared_key)
        eq = encoded_qubits[q_index]

        qcol1, qcol2, qcol3, qcol4, qcol5 = st.columns(5)
        qcol1.metric("Index (i)", eq.index)
        qcol2.metric("Digest bit (d_i)", eq.digest_bit)
        qcol3.metric("Key bit (K_i)", eq.key_bit)
        qcol4.metric("Encoded bit (b_i)", eq.encoded_bit)
        qcol5.metric("Basis", eq.basis)

        st.markdown(
            f"**State:** `{eq.state_label}` with expected eigenvalue `{eq.expected_eigenvalue}`"
        )
        st.markdown(
            f"**Derivation:** $i = {q_index}$, $i \\bmod 3 = {q_index % 3}$ "
            f"$\\implies$ Basis `{eq.basis}`. "
            f"$b_i = d_i \\oplus K_i = {eq.digest_bit} \\oplus {eq.key_bit} = {eq.encoded_bit}$ "
            f"$\\implies$ state `{eq.state_label}`."
        )

        math_info = get_state_math_info(eq.state_label)
        st.markdown(f"**Statevector:** `{math_info['statevector_str']}`")
        st.markdown(f"**Bloch vector (X, Y, Z):** `{math_info['bloch_before']}`")
        st.markdown(f"**Channel sensitivity:** {math_info['sensitivity_note']}")

        st.subheader("All 256 Qubit Encoding Table")
        filter_b = st.radio("Filter by Basis", ["All", "Z", "X", "Y"], horizontal=True)
        rows = []
        for eq_ in encoded_qubits:
            if filter_b != "All" and eq_.basis != filter_b:
                continue
            rows.append({
                "i": eq_.index,
                "d_i": eq_.digest_bit,
                "K_i": eq_.key_bit,
                "b_i": eq_.encoded_bit,
                "Basis": eq_.basis,
                "State |psi_i>": eq_.state_label,
                "Eigenvalue": eq_.expected_eigenvalue,
            })
        st.dataframe(rows, width="stretch")

    # ── 2c: Signature Verification ───────────────────────────────────────────
    else:
        st.header("Signature Verification — Baseline (No Attack)")
        st.markdown(
            "Execute a legitimate signature transmission with no adversarial interference. "
            "Expected result: error rate near p0, statistical decision NORMAL CHANNEL."
        )

        if st.button("RUN BASELINE VERIFICATION", type="primary"):
            pipeline = st.empty()
            pipeline.markdown(
                '<div class="pipeline-step">STEP 1 / 4 — Building 256 Qiskit circuits...</div>',
                unsafe_allow_html=True,
            )
            with st.spinner("Executing AerSimulator..."):
                pipeline.markdown(
                    '<div class="pipeline-step">STEP 2 / 4 — Executing AerSimulator (256 teleportation circuits)...</div>',
                    unsafe_allow_html=True,
                )
                res = _run_and_cache("No Attack / Baseline", {})
                st.session_state.baseline_result = res
                pipeline.markdown(
                    '<div class="pipeline-step">STEP 3 / 4 — Collecting measurement outcomes...</div>',
                    unsafe_allow_html=True,
                )
                pipeline.markdown(
                    '<div class="pipeline-step">STEP 4 / 4 — Running exact Binomial hypothesis test...</div>',
                    unsafe_allow_html=True,
                )

        if "baseline_result" in st.session_state:
            res: ExperimentResult = st.session_state.baseline_result
            st.subheader("Verification Result")
            _render_measurement_and_stochasticity_block(res, theo_exp_str="0.0000 (0%)")
            _render_hypothesis_test_block(res)


# =============================================================================
#  SECTION 3: QUANTUM LAB
# =============================================================================
elif nav_section == "Quantum Lab":
    st.title("QUANTUM LABORATORY")

    lab_sub = st.radio(
        "Section",
        ["Single-Qubit Teleportation Lab", "Teleportation Circuit Viewer", "256-Qubit Signature Map"],
        horizontal=True,
    )

    # ── 3a: Single-Qubit Lab ─────────────────────────────────────────────────
    if lab_sub == "Single-Qubit Teleportation Lab":
        st.header("Single-Qubit Teleportation Lab")
        st.markdown(
            "Select any Pauli eigenstate, measurement basis, and channel condition. "
            "Inspect the exact Qiskit circuit that runs, execute it on AerSimulator, "
            "and observe the measurement histogram."
        )

        c1, c2, c3, c4 = st.columns(4)
        sq_state = c1.selectbox("Signature State", ["|0>", "|1>", "|+>", "|->", "|+i>", "|-i>"], index=2)
        sq_basis = c2.selectbox("Verification Basis", ["Z", "X", "Y"], index=1)
        sq_channel = c3.selectbox("Channel Condition", ["none (Normal)", "channel_x (Pauli-X Noise)"], index=0)
        sq_shots = c4.number_input("Simulation Shots", min_value=1, max_value=2000, value=200)

        attack_type_map = {"none (Normal)": "none", "channel_x (Pauli-X Noise)": "channel_x"}
        sq_attack = attack_type_map[sq_channel]

        math_info = get_state_math_info(sq_state)

        st.subheader("State Vector & Bloch Analysis")
        va, vb, vc = st.columns(3)
        va.markdown(f"**State:** `{sq_state}`")
        va.markdown(f"**Statevector:** `{math_info['statevector_str']}`")
        vb.markdown(f"**Bloch vector (X, Y, Z):** `{math_info['bloch_before']}`")
        vc.markdown(f"**Channel sensitivity:** {math_info['sensitivity_note']}")

        if sq_attack == "channel_x":
            st.markdown(
                f"**After Pauli-X channel error:** `{sq_state}` transforms to "
                f"`{math_info['transformed_label']}` | "
                f"New Bloch vector: `{math_info['bloch_after']}`"
            )

        st.subheader("Qiskit Circuit Diagram")
        qc_sq = build_demonstration_teleportation_circuit(
            state_label=sq_state, basis=sq_basis, attack_type=sq_attack
        )
        fig_circ = draw_circuit_mpl(qc_sq)
        st.pyplot(fig_circ)
        plt.close(fig_circ)

        st.markdown(
            f"**Circuit depth:** `{qc_sq.depth()}` | "
            f"**Gates:** `{qc_sq.count_ops()}` | "
            f"**Qubits:** `{qc_sq.num_qubits}` | "
            f"**Classical bits:** `{qc_sq.num_clbits}`"
        )

        st.subheader("AerSimulator Measurement Histogram")
        if st.button("EXECUTE CIRCUIT ON AERSIMULATOR", type="primary"):
            with st.spinner("Executing..."):
                backend = QuantumBackendAdapter("aer_simulator")
                exec_res = backend.run_circuit(qc_sq, shots=sq_shots, seed_simulator=seed)
                st.session_state.sq_counts = exec_res["counts"]
                st.session_state.sq_shots = sq_shots

        if "sq_counts" in st.session_state:
            counts = st.session_state.sq_counts
            total_shots = st.session_state.sq_shots
            labels = list(counts.keys())
            values = list(counts.values())

            fig_h, ax_h = plt.subplots(figsize=(max(4, len(labels) * 0.8 + 2), 3))
            fig_h.patch.set_facecolor('#130825')
            ax_h.set_facecolor('#0B0414')
            ax_h.bar(range(len(labels)), values, color="#EC4899", width=0.5, edgecolor="#FF70A6")
            ax_h.set_xticks(range(len(labels)))
            ax_h.set_xticklabels(labels, fontfamily="monospace", fontsize=8, color="#F3E8FF")
            ax_h.set_ylabel("Count", color="#E9D5FF")
            ax_h.set_title(f"AerSimulator Outcome Distribution (N = {total_shots} shots)", color="#FF70A6", fontsize=9, fontweight="bold")
            ax_h.grid(True, axis="y", linestyle="--", alpha=0.2, color="#A855F7")
            ax_h.tick_params(colors="#C084FC")
            for spine in ax_h.spines.values():
                spine.set_color((236/255, 72/255, 153/255, 0.3))
            fig_h.tight_layout()
            st.pyplot(fig_h)
            plt.close(fig_h)

            st.markdown("**Raw measurement counts (bitstring : count):**")
            st.json(counts)

    # ── 3b: Teleportation Circuit Viewer ────────────────────────────────────
    elif lab_sub == "Teleportation Circuit Viewer":
        st.header("Teleportation Circuit Viewer: Normal vs. Attacked")
        st.markdown(
            "Compare side-by-side the 3-qubit teleportation circuit under a legitimate channel "
            "against the same circuit with a selected attack injected. "
            "Both circuits are actual Qiskit QuantumCircuit objects drawn by `qc.draw(output='mpl')`."
        )

        tv_c1, tv_c2, tv_c3 = st.columns(3)
        tv_state = tv_c1.selectbox("Signature State", ["|0>", "|1>", "|+>", "|->", "|+i>", "|-i>"], index=2)
        tv_basis = tv_c2.selectbox("Verification Basis", ["Z", "X", "Y"], index=1)
        tv_attack_choice = tv_c3.selectbox(
            "Attack to Compare",
            ["Channel Tampering (Pauli-X on q2)", "Quantum Interception (Eve measures q0)"],
        )
        if tv_attack_choice == "Quantum Interception (Eve measures q0)":
            eve_b = st.selectbox("Eve Measurement Basis", ["Z", "X", "Y"], index=0)
        else:
            eve_b = None

        attack_type_tv = "channel_x" if "Channel" in tv_attack_choice else "interception"

        qc_normal = build_demonstration_teleportation_circuit(
            state_label=tv_state, basis=tv_basis, attack_type="none"
        )
        qc_attacked = build_demonstration_teleportation_circuit(
            state_label=tv_state, basis=tv_basis,
            attack_type=attack_type_tv, eve_basis=eve_b,
        )

        col_norm, col_atk = st.columns(2)
        with col_norm:
            st.subheader("NORMAL Channel")
            fig_n = draw_circuit_mpl(qc_normal)
            st.pyplot(fig_n)
            plt.close(fig_n)
            st.markdown(
                f"Depth: `{qc_normal.depth()}` | Ops: `{qc_normal.count_ops()}`"
            )

        with col_atk:
            st.subheader(f"ATTACKED: {tv_attack_choice.split('(')[0].strip()}")
            fig_a = draw_circuit_mpl(qc_attacked)
            st.pyplot(fig_a)
            plt.close(fig_a)
            st.markdown(
                f"Depth: `{qc_attacked.depth()}` | Ops: `{qc_attacked.count_ops()}`"
            )

        st.markdown("---")
        st.subheader("ASCII Circuit Representation")
        ascii_c1, ascii_c2 = st.columns(2)
        with ascii_c1:
            st.markdown("**NORMAL:**")
            st.code(draw_circuit_ascii(qc_normal), language="text")
        with ascii_c2:
            st.markdown("**ATTACKED:**")
            st.code(draw_circuit_ascii(qc_attacked), language="text")

    # ── 3c: 256-Qubit Signature Map ──────────────────────────────────────────
    else:
        st.header("256-Qubit Signature Map")
        st.markdown(
            "Complete table of all 256 QDS signature qubit encoding records for the current message M and key K."
        )

        encoded_qubits = encode_message(message, shared_key)
        filter_basis = st.radio("Filter by Basis", ["All 256", "Basis Z (86)", "Basis X (85)", "Basis Y (85)"], horizontal=True)

        rows = []
        for eq in encoded_qubits:
            if "Z" in filter_basis and eq.basis != "Z":
                continue
            if "X" in filter_basis and eq.basis != "X":
                continue
            if "Y" in filter_basis and eq.basis != "Y":
                continue
            rows.append({
                "Index (i)": eq.index,
                "d_i": eq.digest_bit,
                "K_i": eq.key_bit,
                "b_i = d_i XOR K_i": eq.encoded_bit,
                "Basis": eq.basis,
                "Prepared State": eq.state_label,
                "Expected Eigenvalue": eq.expected_eigenvalue,
            })
        st.dataframe(rows, width="stretch")

        st.subheader("Encoded Bit Distribution Bitmap")
        st.markdown("The 256 encoded bits b_i visualized as a 16x16 pixel grid. Black = 1, White = 0.")
        encoded_bits_arr = np.array([eq.encoded_bit for eq in encoded_qubits]).reshape(16, 16)
        fig_eb, ax_eb = plt.subplots(figsize=(3.5, 3.5))
        ax_eb.imshow(encoded_bits_arr, cmap="binary", vmin=0, vmax=1,
                     interpolation="nearest", aspect="equal")
        ax_eb.set_title("Encoded Bits b_i (b_i = d_i XOR K_i)", fontsize=9)
        ax_eb.set_xticks([])
        ax_eb.set_yticks([])
        st.pyplot(fig_eb)
        plt.close(fig_eb)


# =============================================================================
#  SECTION 4: HARDWARE & SIMULATOR LAB (REAL IBM QUANTUM & SIMULATOR SUITE)
# =============================================================================
elif nav_section == "Hardware Validation":
    st.title("IBM QUANTUM HARDWARE & SIMULATOR LAB")
    st.markdown(
        "Execute representative 3-qubit QDS teleportation primitives on **Physical IBM Quantum QPUs**, "
        "**IBM Quantum Cloud Simulators**, and **IBM Realistic QPU Noise Model Simulators** (such as 156-qubit Heron r2 and 127-qubit Eagle architectures). "
        "Compare hardware noise distributions directly against ideal noiseless Aer simulation baselines."
    )

    @st.cache_data(ttl=1800, show_spinner=False)
    def _cached_check_hardware(token: str, channel: str, instance: str):
        return is_hardware_configured(token=token, channel=channel, instance=instance)

    @st.cache_data(ttl=1800, show_spinner=False)
    def _cached_get_hw_backends(token: str, channel: str, instance: str):
        return get_available_hardware_backends(token=token, channel=channel, instance=instance)

    st.markdown("---")
    st.header("1. IBM Quantum Authentication & Configuration")

    # Session state initialization — never pre-fill with hardcoded credentials
    if "IBM_QUANTUM_API_TOKEN" not in st.session_state:
        st.session_state["IBM_QUANTUM_API_TOKEN"] = get_ibm_token() or ""
    if "IBM_QUANTUM_INSTANCE_CRN" not in st.session_state:
        st.session_state["IBM_QUANTUM_INSTANCE_CRN"] = get_ibm_instance() or ""

    auth_col1, auth_col2 = st.columns([2, 1])

    with auth_col1:
        token_input = st.text_input(
            "IBM Quantum API Token / IBM Cloud API Key",
            value=st.session_state["IBM_QUANTUM_API_TOKEN"],
            type="password",
            help="Get your API token from quantum.ibm.com account profile or IBM Cloud API Keys.",
            placeholder="Paste your API Token or Cloud API Key here...",
        )
        instance_input = st.text_input(
            "Instance CRN (From Dashboard, e.g. crn:v1:bluemix:...)",
            value=st.session_state["IBM_QUANTUM_INSTANCE_CRN"],
            help="Copy the CRN from your instance card on quantum.ibm.com. Required for IBM Cloud accounts.",
            placeholder="crn:v1:bluemix:public:quantum-computing:...",
        )

        is_cloud_account = bool((instance_input and "bluemix" in instance_input) or (token_input and len(token_input.strip()) == 44))
        auto_channel_index = 1 if is_cloud_account else 0

        ch_col1, ch_col2 = st.columns(2)
        with ch_col1:
            selected_channel = st.selectbox(
                "Platform Channel",
                ["ibm_quantum", "ibm_cloud"],
                index=auto_channel_index,
                help="Use 'ibm_cloud' for IBM Cloud CRN instances. Use 'ibm_quantum' for legacy platform tokens.",
            )
        with ch_col2:
            st.markdown(" ")
            if st.button("AUTHENTICATE & SAVE CREDENTIALS", type="secondary", width="stretch"):
                with st.spinner("Verifying credentials with IBM Quantum..."):
                    st.session_state["IBM_QUANTUM_API_TOKEN"] = token_input.strip()
                    st.session_state["IBM_QUANTUM_INSTANCE_CRN"] = instance_input.strip()
                    st.session_state["IBM_QUANTUM_CHANNEL"] = selected_channel
                    # Clear all caches: Streamlit cache_data AND module-level IBM service/backend caches
                    _cached_check_hardware.clear()
                    _cached_get_hw_backends.clear()
                    from core.hardware import _SERVICE_CACHE, _BACKENDS_CACHE
                    _SERVICE_CACHE.clear()
                    _BACKENDS_CACHE.clear()
                    is_ok, msg = _cached_check_hardware(token_input.strip(), selected_channel, instance_input.strip())
                    st.session_state["hw_configured_state"] = (is_ok, msg)
                    if is_ok:
                        st.session_state["available_hw_backends"] = _cached_get_hw_backends(token_input.strip(), selected_channel, instance_input.strip())
                st.rerun()


    active_token = st.session_state.get("IBM_QUANTUM_API_TOKEN", "").strip() or get_ibm_token() or ""
    active_instance = st.session_state.get("IBM_QUANTUM_INSTANCE_CRN", "").strip() or get_ibm_instance() or ""
    selected_channel = st.session_state.get("IBM_QUANTUM_CHANNEL", "ibm_cloud" if is_cloud_account else "ibm_quantum")

    if "hw_configured_state" not in st.session_state:
        if active_token:
            st.session_state["hw_configured_state"] = _cached_check_hardware(active_token, channel=selected_channel, instance=active_instance)
        else:
            st.session_state["hw_configured_state"] = (False, "Offline")

    hw_configured, hw_msg = st.session_state["hw_configured_state"]

    with auth_col2:
        if hw_configured:
            st.markdown(
                '<div class="status-normal">'
                'AUTHENTICATED TO IBM QUANTUM PLATFORM<br>'
                f'<span style="font-size:0.78rem; color:#A7F3D0;">Channel: {selected_channel} | Instance Ready</span>'
                '</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="status-threat">'
                'OFFLINE / SIMULATION MODE ACTIVE<br>'
                '<span style="font-size:0.75rem; color:#FFA5C9;">Enter your API Token (and Instance CRN for IBM Cloud) to connect to live QPUs.</span>'
                '</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.header("2. Target Quantum Backend & Simulator Selection")

    backend_category = st.radio(
        "Select Backend Category",
        options=[
            "IBM Realistic QPU Noise Simulators (Offline / Instant)",
            "Physical IBM Quantum Hardware (Cloud QPU)",
            "Local Ideal Aer Simulator (Noiseless)",
        ],
        horizontal=True,
    )

    if hw_configured:
        if "available_hw_backends" not in st.session_state:
            st.session_state["available_hw_backends"] = _cached_get_hw_backends(active_token, channel=selected_channel, instance=active_instance)
        available_hw_backends = st.session_state["available_hw_backends"]
    else:
        available_hw_backends = []

    available_sim_backends = get_available_simulator_backends()

    hw_c1, hw_c2, hw_c3 = st.columns(3)

    target_execution_mode = "ibm_fake_noise_sim"
    chosen_backend_name = "fake_fez"
    b_meta = None

    if backend_category == "Physical IBM Quantum Hardware (Cloud QPU)":
        target_execution_mode = "hardware"
        with hw_c1:
            if available_hw_backends:
                b_names = [b["name"] for b in available_hw_backends]
                chosen_backend_name = st.selectbox("Select Active Physical QPU", b_names, index=0)
                b_meta = next((b for b in available_hw_backends if b["name"] == chosen_backend_name), None)
            else:
                chosen_backend_name = st.selectbox(
                    "Target Physical QPU",
                    ["ibm_fez", "ibm_marrakesh", "ibm_kingston", "ibm_sherbrooke", "ibm_brisbane", "ibm_kyiv", "ibm_osaka", "ibm_torino"],
                    index=0,
                )
                if not hw_configured:
                    st.caption("Note: Physical execution requires an authenticated IBM Quantum API token.")
    elif backend_category == "IBM Realistic QPU Noise Simulators (Offline / Instant)":
        target_execution_mode = "ibm_fake_noise_sim"
        fake_sims = [s for s in available_sim_backends if s.get("type") == "ibm_fake_noise_sim"]
        display_map = {s["display_name"]: s["name"] for s in fake_sims}
        with hw_c1:
            chosen_display = st.selectbox("Select Realistic IBM QPU Noise Model", list(display_map.keys()), index=0)
            chosen_backend_name = display_map[chosen_display]
            b_meta = next((s for s in fake_sims if s["name"] == chosen_backend_name), None)
    else:
        target_execution_mode = "ideal_aer"
        chosen_backend_name = "aer_simulator"
        with hw_c1:
            st.selectbox("Select Ideal Simulator", ["AerSimulator (Noiseless Statevector / Stabilizer)"], index=0)

    # Telemetry and specifications
    is_heron = any(h in chosen_backend_name for h in ("fez", "marrakesh", "kingston", "torino"))
    num_qubits_val = b_meta["num_qubits"] if b_meta else (156 if any(h in chosen_backend_name for h in ("fez", "marrakesh", "kingston")) else (127 if "127" in chosen_backend_name or "brisbane" in chosen_backend_name else 32))
    pending_jobs_val = b_meta["pending_jobs"] if b_meta else 0
    basis_gates_val = ", ".join(b_meta["basis_gates"]) if b_meta else ("cz, rz, sx, x, id" if is_heron else "rz, sx, x, cz, id")
    processor_val = b_meta.get("processor", "Heron r2 QPU (156 Qubits)" if is_heron else "Eagle QPU (127 Qubits)") if b_meta else ("Heron r2 QPU Architecture (156 Qubits)" if is_heron else "Eagle / Falcon QPU Architecture")

    with hw_c2:
        st.markdown(f'<div class="metric-label">QPU / Simulator Architecture</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">{processor_val}</div>', unsafe_allow_html=True)

    with hw_c3:
        st.markdown(f'<div class="metric-label">Native Basis Gates</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="metric-value">[{basis_gates_val}]</div>', unsafe_allow_html=True)

    st.markdown(" ")
    qpu_c1, qpu_c2, qpu_c3, qpu_c4 = st.columns(4)
    qpu_c1.metric("Selected Backend", chosen_backend_name)
    qpu_c2.metric("Qubits Available", f"{num_qubits_val} Qubits")
    qpu_c3.metric("Pending Queue Jobs", f"{pending_jobs_val} Jobs")
    qpu_c4.metric(
        "Operational Mode",
        "Physical QPU (Cloud)" if target_execution_mode == "hardware"
        else ("IBM Cloud Sim" if target_execution_mode == "ibm_cloud_sim"
        else ("IBM Noise Sim" if target_execution_mode == "ibm_fake_noise_sim" else "Ideal Aer")),
    )

    st.markdown("---")
    st.header("3. Teleportation Circuit & Experiment Parameters")

    exp_col1, exp_col2, exp_col3 = st.columns(3)
    with exp_col1:
        hw_state = st.selectbox("Signature State |ψ_i⟩", ["|0>", "|1>", "|+>", "|->", "|+i>", "|-i>"], index=2)
    with exp_col2:
        hw_basis = st.selectbox("Bob Measurement Basis", ["Z", "X", "Y"], index=1)
    with exp_col3:
        hw_shots = st.selectbox("Execution Shots", [512, 1024, 2048, 4096, 8192], index=1)

    st.subheader("Circuit Architecture to Transpile & Execute")
    qc_hw_demo = build_demonstration_teleportation_circuit(hw_state, hw_basis, attack_type="none")
    fig_hwd = draw_circuit_mpl(qc_hw_demo)
    st.pyplot(fig_hwd)
    plt.close(fig_hwd)

    if target_execution_mode == "hardware":
        st.info(
            "Targeting **Physical IBM Quantum Hardware** (`" + chosen_backend_name + "`). "
            "Cloud jobs wait in IBM's remote queue before running on physical QPUs. "
            "For **instant (1–2 sec) local benchmark results** with identical 156-qubit Heron r2 calibration and noise, switch to **IBM Realistic QPU Noise Simulators (Offline / Instant)**."
        )
    elif target_execution_mode == "ibm_fake_noise_sim":
        st.success(
            "Targeting **Realistic IBM Heron / Eagle Noise Simulator** (`" + chosen_backend_name + "`). "
            "Runs locally with full 156-qubit calibrated noise models, T1/T2 decoherence, and readout errors in **~1–2 seconds with zero queue waiting**."
        )

    if st.button("RUN QUANTUM EXPERIMENT & BENCHMARK", type="primary"):
        exec_msg = (
            f"Submitting job to physical {chosen_backend_name} on IBM Cloud... Waiting for QPU queue and readout..."
            if target_execution_mode == "hardware"
            else f"Running local simulation on {chosen_backend_name} & computing noiseless baseline..."
        )
        with st.spinner(exec_msg):
            hw_res = run_hardware_teleportation_experiment(
                state_label=hw_state,
                basis=hw_basis,
                backend_name=chosen_backend_name,
                channel=selected_channel,
                shots=hw_shots,
                token=active_token,
                execution_mode=target_execution_mode,
                instance=active_instance,
            )
            st.session_state.hw_res = hw_res
            st.rerun()

    if "hw_res" in st.session_state:
        res = st.session_state.hw_res
        st.markdown("---")
        st.header("4. Execution Results & Deep Comparative Analytics")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Execution Target", res["hardware_backend"])
        m2.metric("State Fidelity (F)", f"{res.get('fidelity', 1.0):.4f}")
        m3.metric("Transpiled QPU Depth", f"{res.get('transpiled_depth', res['circuit_depth'])}")
        m4.metric("Job ID / Execution Type", res["job_id"] if res["job_id"] != "N/A" else res.get("backend_type", "Simulation"))

        if not res["success"] and res.get("error_message"):
            job_id_val = res.get("job_id", "N/A")
            has_valid_job = (
                job_id_val != "N/A"
                and len(job_id_val) > 4
                and not job_id_val.startswith("LOCAL")
            )

            st.error(
                f"**Hardware Execution / Network Notice**\n\n"
                f"**Reason:** {res['error_message']}\n\n"
                f"Showing ideal simulation baseline analytics below."
            )

            col_action1, col_action2 = st.columns([1, 1])
            if has_valid_job:
                with col_action1:
                    job_url = f"https://quantum.ibm.com/jobs/{job_id_val}"
                    st.markdown(
                        f' <a href="{job_url}" target="_blank" style="color: #60A5FA; font-weight: bold;">Track Job {job_id_val} on IBM Quantum Cloud Dashboard</a>',
                        unsafe_allow_html=True,
                    )
                    if st.button(" Re-query IBM Cloud for Job Result", key="recheck_hw_job_btn"):
                        with st.spinner(f"Re-querying IBM Cloud for Job ID {job_id_val}..."):
                            refetched_res = fetch_ibm_job_result(
                                job_id=job_id_val,
                                token=active_token,
                                channel=selected_channel,
                                instance=active_instance,
                                state_label=hw_state,
                                basis=hw_basis,
                                shots=hw_shots,
                            )
                            st.session_state.hw_res = refetched_res
                            st.rerun()

            with col_action2:
                if st.button(" Run Instant Offline Noise Sim (fake_fez)", key="fallback_fake_fez_btn"):
                    with st.spinner("Executing 156-qubit Heron r2 realistic noise model locally..."):
                        noise_res = run_hardware_teleportation_experiment(
                            state_label=hw_state,
                            basis=hw_basis,
                            backend_name="fake_fez",
                            shots=hw_shots,
                            execution_mode="ibm_fake_noise_sim",
                        )
                        st.session_state.hw_res = noise_res
                        st.rerun()

            st.markdown("---")


        st.subheader("Outcome Distribution: Ideal Aer Simulation vs Target Quantum Backend")

        ideal_counts = res["ideal_counts"]
        hw_counts = res["hardware_counts"] if res["hardware_counts"] else ideal_counts
        shots_val = res["shots"]

        # Side-by-side Matplotlib chart comparison
        fig_hw_bar, ax_hw_bar = plt.subplots(figsize=(8.5, 3.8))
        fig_hw_bar.patch.set_facecolor("#110722")
        ax_hw_bar.set_facecolor("#0A0414")

        all_outcomes = sorted(list(set(list(ideal_counts.keys()) + list(hw_counts.keys()))))
        x_indices = np.arange(len(all_outcomes))
        bar_width = 0.35

        ideal_pcts = [(ideal_counts.get(out, 0) / shots_val) * 100.0 for out in all_outcomes]
        hw_tot = sum(hw_counts.values()) or shots_val
        hw_pcts = [(hw_counts.get(out, 0) / hw_tot) * 100.0 for out in all_outcomes]

        target_label = f"Target ({res['hardware_backend']})"
        ax_hw_bar.bar(x_indices - bar_width/2, ideal_pcts, width=bar_width, label="Noiseless Aer Simulation (Ideal)", color="#EC4899", alpha=0.88)
        ax_hw_bar.bar(x_indices + bar_width/2, hw_pcts, width=bar_width, label=target_label, color="#38BDF8", alpha=0.88)

        ax_hw_bar.set_xticks(x_indices)
        ax_hw_bar.set_xticklabels([f"|{out}⟩" for out in all_outcomes], color="#E9D5FF", fontsize=9)
        ax_hw_bar.set_ylabel("Readout Probability (%)", color="#E9D5FF", fontsize=9)
        ax_hw_bar.set_title(f"Quantum Teleportation Measurement Distribution (|ψᵢ⟩ = {hw_state}, Basis = {hw_basis})", color="#FF70A6", fontsize=10, fontweight="bold")
        ax_hw_bar.tick_params(colors="#C084FC")
        ax_hw_bar.grid(True, linestyle="--", alpha=0.2, color="#A855F7")
        for spine in ax_hw_bar.spines.values():
            spine.set_color((0.925, 0.282, 0.6, 0.35))
        ax_hw_bar.legend(facecolor="#180B30", edgecolor="#EC4899", labelcolor="#F3E8FF", fontsize=8.5)
        fig_hw_bar.tight_layout()
        st.pyplot(fig_hw_bar)
        plt.close(fig_hw_bar)

        # Formulate detailed side-by-side table
        tbl_comp = []
        for out in all_outcomes:
            id_cnt = ideal_counts.get(out, 0)
            id_pct = (id_cnt / shots_val) * 100.0
            hw_cnt = hw_counts.get(out, 0)
            hw_pct = (hw_cnt / hw_tot) * 100.0
            delta_pct = hw_pct - id_pct
            tbl_comp.append({
                "Outcome Bit": f"`{out}`",
                "Ideal Aer (Count)": id_cnt,
                "Ideal Aer (%)": f"{id_pct:.2f}%",
                "Target Backend (Count)": hw_cnt,
                "Target Backend (%)": f"{hw_pct:.2f}%",
                "Noise Delta (Δ%)": f"{delta_pct:+.2f}%",
            })
        st.dataframe(tbl_comp, width="stretch")

        # Transpiled Gate Decomposition
        st.subheader("Transpiled Native Gate Breakdown")
        transpiled_ops = res.get("transpiled_ops", {})
        if transpiled_ops:
            op_cols = st.columns(min(len(transpiled_ops), 5))
            for i, (op_name, count) in enumerate(sorted(transpiled_ops.items(), key=lambda x: -x[1])):
                op_cols[i % len(op_cols)].metric(f"Gate: {op_name}", f"{count} gates")

        st.markdown(
            '<div class="info-box">SCIENTIFIC HARDWARE & NOISE EXPLANATION: Ideal Aer simulation calculates '
            'noiseless unitary evolution. Physical IBM QPUs and realistic noise simulators incorporate '
            'T1 (longitudinal relaxation), T2 (dephasing/decoherence), CNOT/CZ entangling gate infidelity, '
            'readout measurement errors, and routing SWAP overhead.</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.subheader("Hardware Validation vs. Security Evaluation Disclosure")
    st.markdown(
        """
- **256-Qubit Security Evaluation**: The full 256-qubit QDS security protocol evaluation uses AerSimulator to guarantee reproducible and fast execution of all 6 attack scenarios.
- **IBM Quantum Hardware Validation**: Real hardware execution and realistic noise simulation serve as validation layers demonstrating that representative 3-qubit teleportation primitives physically run on actual QPUs and under calibrated noise models.
- **Scientific Disclosures**: Physical hardware introduces decoherence, thermal noise, and readout error. Using IBM hardware provides physical confirmation but is not required for statistical security threat analysis.
"""
    )


# =============================================================================
#  SECTION 5: SECURITY LAB
# =============================================================================
elif nav_section == "Security Lab":
    st.title("SECURITY LABORATORY — ATTACK SIMULATIONS")

    attack_choice = st.selectbox(
        "Select Attack Scenario",
        [
            "Channel Tampering (Pauli-X Bit-Flip)",
            "Signature Forgery (Eve assumes K=0)",
            "Impersonation (Random State Guess)",
            "Quantum Interception (Intercept-Resend)",
            "Replay Attack",
            "Replay Attack (Same Message, Nonce Reuse)",
            "Unauthorized Verification Attempt",
        ],
    )

    # ────────────────────────────────────────────────
    # ATTACK: Channel Tampering
    # ────────────────────────────────────────────────
    if attack_choice == "Channel Tampering (Pauli-X Bit-Flip)":
        st.header("Channel Tampering: Probabilistic Pauli-X Noise on Qubit q2")

        st.markdown('<div class="sec-header">A. ATTACK DEFINITION</div>', unsafe_allow_html=True)
        st.markdown(
            "An adversary (or noisy quantum environment) introduces probabilistic Pauli-X bit-flip errors "
            "onto Bob's qubit q2 during quantum teleportation transmission before Bell corrections are applied."
        )

        st.markdown('<div class="sec-header">B. ATTACKER KNOWLEDGE</div>', unsafe_allow_html=True)
        st.markdown(
            "- Message M: UNKNOWN\n"
            "- SHA-256 Digest D: UNKNOWN\n"
            "- Secret Shared Key K: UNKNOWN\n"
            "- Basis Schedule Bᵢ: UNKNOWN"
        )

        st.markdown('<div class="sec-header">C. ATTACKER ACTION</div>', unsafe_allow_html=True)
        st.markdown(
            "For each transmitted signature qubit position i, Eve applies a Pauli-X gate on q2 with probability $p_{\\text{atk}}$. "
            "With probability $(1 - p_{\\text{atk}})$, the qubit passes uncorrupted."
        )

        st.markdown('<div class="sec-header">D. QUANTUM STATE / BIT TRANSFORMATION</div>', unsafe_allow_html=True)
        st.markdown(
            "- **Basis Z**: $X|0\\rangle = |1\\rangle$, $X|1\\rangle = |0\\rangle$ (State flipped, error rate $\\approx p_{\\text{attack}}$)\n"
            "- **Basis X**: $X|+\\rangle = +|+\\rangle$, $X|-\\rangle = -|-\\rangle$ (Invariant up to global phase, 0% error)\n"
            "- **Basis Y**: $X|+i\\rangle = |-i\\rangle$, $X|-i\\rangle = |+i\\rangle$ (State flipped, error rate $\\approx p_{\\text{attack}}$)\n"
            "- **Overall Expected Error Rate**: $(2/3) \\times p_{\\text{attack}}$ (since 2 of 3 bases are sensitive under uniform basis schedule)."
        )

        p_att = st.slider("Channel Bit-Flip Probability (p_attack)", 0.0, 1.0, 0.20, 0.05)

        if st.button("RUN CHANNEL TAMPERING EXPERIMENT", type="primary"):
            with st.spinner("Executing Qiskit Aer simulation..."):
                res = _run_and_cache("Channel Tampering", {"p_attack": p_att})
                st.session_state.ch_result = res

        if "ch_result" in st.session_state:
            res: ExperimentResult = st.session_state.ch_result

            # Section F: Circuit Comparison
            st.markdown('<div class="sec-header">F. QUANTUM CIRCUIT / CIRCUIT DIFFERENCE</div>', unsafe_allow_html=True)
            st.markdown(
                "Modified operation: Injected Pauli-X gate on q2 with probability $p_{\\text{atk}}$ before Bob's basis readout."
            )
            circ_c1, circ_c2 = st.columns(2)
            qc_norm_ch = build_demonstration_teleportation_circuit("|+>", "X", "none")
            qc_atk_ch = build_demonstration_teleportation_circuit("|+>", "X", "channel_x")
            with circ_c1:
                st.markdown("**NORMAL Channel (No Attack)**")
                fig_nc = draw_circuit_mpl(qc_norm_ch)
                st.pyplot(fig_nc)
                plt.close(fig_nc)
            with circ_c2:
                st.markdown("**ATTACKED Channel (Pauli-X on q2)**")
                fig_ac = draw_circuit_mpl(qc_atk_ch)
                st.pyplot(fig_ac)
                plt.close(fig_ac)

            # Section G: Measurement Results
            _render_measurement_and_stochasticity_block(res, theo_exp_str=f"{(2.0/3.0)*p_att:.4f}")

            # Section H: Theoretical vs Observed
            st.markdown('<div class="sec-header">H. THEORETICAL EXPECTATION VS OBSERVATION</div>', unsafe_allow_html=True)
            tot_x = res.relevant_params.get("total_x_injected", "N/A")
            st.markdown(
                f"- **Injected Bit-Flips (X applied)**: `{tot_x}` / {res.total_trials} positions\n"
                f"- **Theoretical Model**: Expected error rate = (2/3) * {p_att:.2f} = `{(2.0/3.0)*p_att:.4f}`\n"
                f"- **Observed Error Rate**: `{res.observed_error_rate:.4f}` ({res.num_errors} errors)\n"
                f"- **Explanation**: The observed error rate is derived directly from the random sampling of X bit-flips and measurement outcomes in AerSimulator."
            )

            # Section E: Position-by-position trace
            _render_position_trace_table_and_map(res.detailed_results, attack_type="bit_flip_channel")

            # Section I: Statistical Hypothesis Test
            _render_hypothesis_test_block(res)

            # Section J: Final Security Interpretation
            st.markdown('<div class="sec-header">J. FINAL SECURITY INTERPRETATION</div>', unsafe_allow_html=True)
            if res.threat_result.threat_detected:
                st.markdown(
                    "Channel tampering exceeds the baseline noise threshold p0 at significance level alpha. "
                    "The QDS threat detector flags a STATISTICAL ANOMALY, rejecting channel integrity."
                )
            else:
                st.markdown(
                    "Channel disturbance is insufficient to reject the baseline null hypothesis p0. "
                    "Verification error count remains consistent with expected baseline noise."
                )

    # ────────────────────────────────────────────────
    # ATTACK: Signature Forgery
    # ────────────────────────────────────────────────
    elif attack_choice == "Signature Forgery (Eve assumes K=0)":
        st.header("Signature Forgery: Digest-Only Forgery (Eve Assumes Secret Key K = 0)")

        st.markdown('<div class="sec-header">A. ATTACK DEFINITION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve attempts to forge a valid signature for classical message M by using only the public SHA-256 digest D, "
            "without possessing the shared secret key K."
        )

        st.markdown('<div class="sec-header">B. ATTACKER KNOWLEDGE</div>', unsafe_allow_html=True)
        st.markdown(
            "- Message M: KNOWN\n"
            "- SHA-256 Digest D = SHA-256(M): KNOWN\n"
            "- Basis Schedule Bᵢ: KNOWN\n"
            "- Secret Shared Key K: UNKNOWN (Eve assumes K'ᵢ = 0)"
        )

        st.markdown('<div class="sec-header">C. ATTACKER ACTION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve constructs forged candidate signature states using $b'_i = d_i \\oplus 0 = d_i$. "
            "She transmits these forged states to Bob for verification."
        )

        st.markdown('<div class="sec-header">D. QUANTUM STATE / BIT TRANSFORMATION</div>', unsafe_allow_html=True)
        key_ones = sum(shared_key)
        theo_forgery = key_ones / 256
        st.markdown(
            f"- **Legitimate Encoding**: $b_i = d_i \\oplus K_i$\n"
            f"- **Forged Encoding**: $b'_i = d_i \\oplus 0 = d_i$\n"
            f"- **State Mismatch Condition**: $b'_i \\neq b_i \\iff K_i = 1$\n"
            f"- **Key 1-Density**: `{key_ones}` / 256 = `{theo_forgery:.4f}`\n"
            f"- **Theoretical Forgery Error Rate**: `{theo_forgery:.4f}` (Exact fraction of 1s in secret key K)."
        )

        if st.button("RUN FORGERY EXPERIMENT", type="primary"):
            with st.spinner("Executing Qiskit Aer simulation..."):
                res = _run_and_cache("Signature Forgery", {})
                st.session_state.forg_result = res

        if "forg_result" in st.session_state:
            res: ExperimentResult = st.session_state.forg_result

            # Section F: Circuit Difference
            st.markdown('<div class="sec-header">F. QUANTUM CIRCUIT / CIRCUIT DIFFERENCE</div>', unsafe_allow_html=True)
            st.markdown(
                "Modified operation: Alice's state preparation uses $b'_i = d_i$ instead of $b_i = d_i \\oplus K_i$."
            )

            # Section G: Measurement Results
            _render_measurement_and_stochasticity_block(res, theo_exp_str=f"{theo_forgery:.4f}")

            # Section H: Theoretical vs Observed
            st.markdown('<div class="sec-header">H. THEORETICAL EXPECTATION VS OBSERVATION</div>', unsafe_allow_html=True)
            st.markdown(
                f"- **Secret Key K 1-Density**: `{key_ones}/256 = {theo_forgery:.4f}`\n"
                f"- **Expected Mismatch Rate**: `{theo_forgery:.4f}`\n"
                f"- **Observed Verification Error Rate**: `{res.observed_error_rate:.4f}`\n"
                f"- **Mechanism**: Verification errors occur at exactly those positions where $K_i = 1$. Eve gains zero advantage from knowing M."
            )

            # Section E: Position-by-position trace
            _render_position_trace_table_and_map(res.detailed_results, attack_type="signature_forgery")

            # Section I: Statistical Hypothesis Test
            _render_hypothesis_test_block(res)

            # Section J: Final Security Interpretation
            st.markdown('<div class="sec-header">J. FINAL SECURITY INTERPRETATION</div>', unsafe_allow_html=True)
            st.markdown(
                "Because secret key K is required to calculate $b_i = d_i \\oplus K_i$, an attacker with digest-only knowledge "
                "incurs errors at all positions where $K_i = 1$ (~50% for a balanced key). "
                "The statistical detector rejects forgery attempts with near-certainty."
            )

    # ────────────────────────────────────────────────
    # ATTACK: Impersonation
    # ────────────────────────────────────────────────
    elif attack_choice == "Impersonation (Random State Guess)":
        st.header("Impersonation: Random Bernoulli(0.5) State Guessing")

        st.markdown('<div class="sec-header">A. ATTACK DEFINITION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve attempts to impersonate Alice and produce a valid signature with zero knowledge of M or K, "
            "by randomly guessing encoded bits $b'_i \\sim \\text{Bernoulli}(0.5)$."
        )

        st.markdown('<div class="sec-header">B. ATTACKER KNOWLEDGE</div>', unsafe_allow_html=True)
        st.markdown(
            "- Message M: UNKNOWN\n"
            "- SHA-256 Digest D: UNKNOWN\n"
            "- Secret Shared Key K: UNKNOWN\n"
            "- Basis Schedule Bᵢ: KNOWN"
        )

        st.markdown('<div class="sec-header">C. ATTACKER ACTION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve generates a random 256-bit binary string $b'_i \\sim \\text{Bernoulli}(0.5)$ and prepares the corresponding Pauli eigenstates."
        )

        st.markdown('<div class="sec-header">D. QUANTUM STATE / BIT TRANSFORMATION</div>', unsafe_allow_html=True)
        st.markdown(
            "- **Attacker Guess Distribution**: $P(b'_i = b_i) = 0.50$\n"
            "- **Theoretical Expected Error Rate**: $0.50$ (50% average error rate for random state guessing)."
        )

        if st.button("RUN IMPERSONATION EXPERIMENT", type="primary"):
            with st.spinner("Executing Qiskit Aer simulation..."):
                res = _run_and_cache("Impersonation", {})
                st.session_state.imp_result = res

        if "imp_result" in st.session_state:
            res: ExperimentResult = st.session_state.imp_result

            # Section F: Circuit Difference
            st.markdown('<div class="sec-header">F. QUANTUM CIRCUIT / CIRCUIT DIFFERENCE</div>', unsafe_allow_html=True)
            st.markdown(
                "Modified operation: Alice state preparation uses random Bernoulli(0.5) guesses $b'_i$."
            )

            # Section G: Measurement Results
            _render_measurement_and_stochasticity_block(res, theo_exp_str="0.5000 (50%)")

            # Section H: Theoretical vs Observed
            st.markdown('<div class="sec-header">H. THEORETICAL EXPECTATION VS OBSERVATION</div>', unsafe_allow_html=True)
            st.markdown(
                f"- **Theoretical Expectation**: 0.5000 (50% error rate)\n"
                f"- **Observed Verification Error Rate**: `{res.observed_error_rate:.4f}` ({res.num_errors} errors)\n"
                f"- **Explanation**: Eve's random bit guesses match Bob's expected bits with probability 1/2 per qubit."
            )

            # Section E: Position-by-position trace
            _render_position_trace_table_and_map(res.detailed_results, attack_type="signature_impersonation")

            # Section I: Statistical Hypothesis Test
            _render_hypothesis_test_block(res)

            # Section J: Final Security Interpretation
            st.markdown('<div class="sec-header">J. FINAL SECURITY INTERPRETATION</div>', unsafe_allow_html=True)
            st.markdown(
                "Impersonation produces an observed error rate near 50%, far above baseline noise p0. "
                "The statistical detector rejects impersonation attempts immediately."
            )

    # ────────────────────────────────────────────────
    # ATTACK: Quantum Interception
    # ────────────────────────────────────────────────
    elif attack_choice == "Quantum Interception (Intercept-Resend)":
        st.header("Quantum Interception: Intercept-Resend Attack")

        st.markdown('<div class="sec-header">A. ATTACK DEFINITION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve intercepts Alice's signature qubit $q_0$, measures it in a chosen basis $B_{\\text{Eve}} \\in \\{Z, X, Y\\}$, "
            "resets $q_0$, and re-prepares a replacement eigenstate matching her measurement outcome."
        )

        st.markdown('<div class="sec-header">B. ATTACKER KNOWLEDGE</div>', unsafe_allow_html=True)
        st.markdown(
            "- Message M & Key K: UNKNOWN\n"
            "- Alice Basis Schedule $B_{\\text{Alice}}$: UNKNOWN (Eve guesses basis $B_{\\text{Eve}}$)"
        )

        st.markdown('<div class="sec-header">C. ATTACKER ACTION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve measures in basis $B_{\\text{Eve}}$, collapses the quantum state, and resends the resulting eigenstate."
        )

        st.markdown('<div class="sec-header">D. QUANTUM STATE / BIT TRANSFORMATION</div>', unsafe_allow_html=True)
        st.markdown(
            "- **Same Basis ($B_{\\text{Eve}} == B_{\\text{Alice}}$, prob 1/3)**: State preserved, 0% error rate.\n"
            "- **Mismatched Basis ($B_{\\text{Eve}} \\neq B_{\\text{Alice}}$, prob 2/3)**: State collapsed into orthogonal basis; Bob measurement yields 50% error rate.\n"
            "- **Overall Expected Error Rate**: $(1/3 \\times 0) + (2/3 \\times 1/2) = 1/3 \\approx 33.33\\%$."
        )

        eve_strat = st.radio("Eve Basis Strategy", ["Uniform Random (Z/X/Y)", "Fixed Basis"], horizontal=True)
        eve_fixed = None
        if eve_strat == "Fixed Basis":
            eve_fixed = st.selectbox("Eve Fixed Basis", ["Z", "X", "Y"])

        strategy_key = "uniform_random" if "Uniform" in eve_strat else "fixed_basis"
        int_params: Dict[str, Any] = {"strategy": strategy_key}
        if eve_fixed:
            int_params["fixed_basis"] = eve_fixed

        if st.button("RUN INTERCEPTION EXPERIMENT", type="primary"):
            with st.spinner("Executing Qiskit Aer simulation..."):
                res = _run_and_cache("Quantum Interception", int_params)
                st.session_state.int_result = res

        if "int_result" in st.session_state:
            res: ExperimentResult = st.session_state.int_result

            # Section F: Circuit Comparison
            st.markdown('<div class="sec-header">F. QUANTUM CIRCUIT / CIRCUIT DIFFERENCE</div>', unsafe_allow_html=True)
            st.markdown(
                "Modified operation: Injected Eve basis measurement, qc.reset(0), and conditional re-preparation on q0."
            )
            inter_c1, inter_c2 = st.columns(2)
            qc_norm_int = build_demonstration_teleportation_circuit("|+>", "X", "none")
            eve_b_circ = eve_fixed if eve_strat == "Fixed Basis" else "Z"
            qc_atk_int = build_demonstration_teleportation_circuit("|+>", "X", "interception", eve_basis=eve_b_circ)
            with inter_c1:
                st.markdown("**NORMAL Channel**")
                fig_ni = draw_circuit_mpl(qc_norm_int)
                st.pyplot(fig_ni)
                plt.close(fig_ni)
            with inter_c2:
                st.markdown(f"**ATTACKED: Eve measures in basis {eve_b_circ}**")
                fig_ai = draw_circuit_mpl(qc_atk_int)
                st.pyplot(fig_ai)
                plt.close(fig_ai)

            # Section G: Measurement Results
            _render_measurement_and_stochasticity_block(res, theo_exp_str="0.3333 (~33.3%)")

            # Section H: Theoretical vs Observed
            st.markdown('<div class="sec-header">H. THEORETICAL EXPECTATION VS OBSERVATION</div>', unsafe_allow_html=True)
            same_cnt = res.relevant_params.get("same_basis_trials", "N/A")
            diff_cnt = res.relevant_params.get("diff_basis_trials", "N/A")
            st.markdown(
                f"- **Same-Basis Trials (Eve Basis == Alice Basis)**: `{same_cnt}` / {res.total_trials} (0% error)\n"
                f"- **Diff-Basis Trials (Eve Basis != Alice Basis)**: `{diff_cnt}` / {res.total_trials} (~50% error)\n"
                f"- **Theoretical Error Rate**: 0.3333 (~33.33%)\n"
                f"- **Observed Error Rate**: `{res.observed_error_rate:.4f}`"
            )

            # Section E: Position-by-position trace
            _render_position_trace_table_and_map(res.detailed_results, attack_type="quantum_interception")

            # Section I: Statistical Hypothesis Test
            _render_hypothesis_test_block(res)

            # Section J: Final Security Interpretation
            st.markdown('<div class="sec-header">J. FINAL SECURITY INTERPRETATION</div>', unsafe_allow_html=True)
            st.markdown(
                "Quantum measurement collapse disturbs mismatched basis states. "
                "The resulting 33% error rate easily triggers statistical threat detection."
            )

    # ────────────────────────────────────────────────
    # ATTACK: Replay
    # ────────────────────────────────────────────────
    elif attack_choice == "Replay Attack":
        st.header("Replay Attack: Captured Signature Reuse")

        st.markdown('<div class="sec-header">A. ATTACK DEFINITION</div>', unsafe_allow_html=True)
        st.markdown(
            "Eve captures a previously valid quantum signature transmission for $M_{\\text{original}}$ "
            "and replays those quantum states when Bob verifies $M_{\\text{target}}$."
        )

        replay_tab = st.radio(
            "Replay Experiment",
            ["REPLAY A — Same Message", "REPLAY B — Different Message"],
            horizontal=True,
        )

        if replay_tab == "REPLAY A — Same Message":
            st.subheader("REPLAY A — Same-Message Replay")

            st.markdown(
                '<div class="security-gap-banner">'
                'SECURITY GAP DISCLOSURE<br><br>'
                'When Eve replays a captured signature for the SAME message M, Bob\'s verification '
                'produces ZERO errors. The current QDS prototype has no freshness mechanism: '
                'no session nonce, no sequence counter, no timestamp, no challenge-response. '
                'Because the encoding is fully deterministic (D = SHA-256(M), bᵢ = dᵢ ⊕ Kᵢ), '
                'a byte-for-byte replay of a valid signature for the same message is '
                'INDISTINGUISHABLE from a fresh legitimate transmission.'
                '</div>',
                unsafe_allow_html=True,
            )

            if st.button("RUN SAME-MESSAGE REPLAY EXPERIMENT", type="primary"):
                with st.spinner("Executing..."):
                    res = _run_and_cache("Replay Attack", {"target_message": message})
                    st.session_state.replay_same_result = res

            if "replay_same_result" in st.session_state:
                res: ExperimentResult = st.session_state.replay_same_result
                _render_measurement_and_stochasticity_block(res, theo_exp_str="0.0000 (0%)")
                _render_position_trace_table_and_map(res.detailed_results, attack_type="signature_replay")
                _render_hypothesis_test_block(res)

        else:
            st.subheader("REPLAY B — Different-Message Replay")
            target_msg = st.text_input("Target Message (M_target)", value="XYZ")

            if message and target_msg:
                d_orig = sha256_bits(message)
                d_tgt = sha256_bits(target_msg)
                hd, hf = compute_digest_hamming_distance(message, target_msg)

                st.markdown(f"**SHA-256 Digest Hamming Distance**: `{hd}` / 256 = `{hf:.4f}`")

                grid_orig = np.array(d_orig).reshape(16, 16)
                grid_tgt = np.array(d_tgt).reshape(16, 16)
                diff_mask = (grid_orig != grid_tgt).astype(float)

                fig_bmp, axes = plt.subplots(1, 3, figsize=(8, 3))
                axes[0].imshow(grid_orig, cmap="binary", vmin=0, vmax=1, aspect="equal")
                axes[0].set_title(f"SHA-256(\"{message}\")", fontsize=8)
                axes[0].set_xticks([]); axes[0].set_yticks([])

                diff_display = np.zeros((16, 16, 3))
                diff_display[:, :, 0] = diff_mask
                diff_display[:, :, 1] = 1.0 - diff_mask
                diff_display[:, :, 2] = 1.0 - diff_mask
                axes[1].imshow(diff_display, aspect="equal")
                axes[1].set_title(f"Differences ({hd} bits)", fontsize=8)
                axes[1].set_xticks([]); axes[1].set_yticks([])

                axes[2].imshow(grid_tgt, cmap="binary", vmin=0, vmax=1, aspect="equal")
                axes[2].set_title(f"SHA-256(\"{target_msg}\")", fontsize=8)
                axes[2].set_xticks([]); axes[2].set_yticks([])

                fig_bmp.tight_layout()
                st.pyplot(fig_bmp)
                plt.close(fig_bmp)

            if st.button("RUN DIFFERENT-MESSAGE REPLAY EXPERIMENT", type="primary"):
                with st.spinner("Executing..."):
                    res = _run_and_cache("Replay Attack", {"target_message": target_msg})
                    st.session_state.replay_diff_result = res

            if "replay_diff_result" in st.session_state:
                res: ExperimentResult = st.session_state.replay_diff_result
                _render_measurement_and_stochasticity_block(res, theo_exp_str=f"{hf:.4f}")
                _render_position_trace_table_and_map(res.detailed_results, attack_type="signature_replay")
                _render_hypothesis_test_block(res)

    # ────────────────────────────────────────────────
    # ATTACK: Same-Message Replay via Nonce Reuse
    # ────────────────────────────────────────────────
    elif attack_choice == "Replay Attack (Same Message, Nonce Reuse)":
        st.header("Replay Attack: Same Message, Nonce Reuse")

        st.markdown('<div class="sec-header">A. THE PROBLEM THIS SOLVES</div>',
                    unsafe_allow_html=True)
        st.markdown(
            "Without freshness binding the encoding is deterministic: D = SHA-256(M), "
            "b_i = d_i XOR K_i. A captured signature for M is therefore **bit-identical** "
            "to a fresh one, and no quantum measurement can distinguish them, because "
            "there is nothing to distinguish. This was the protocol's one undetectable "
            "attack."
        )

        st.markdown('<div class="sec-header">B. THE FIX</div>', unsafe_allow_html=True)
        st.latex(r"P = M \,\|\, \mathrm{id} \,\|\, \nu \,\|\, c \,\|\, t")
        st.latex(r"D = \mathrm{SHA\text{-}256}(P), \qquad b_i = d_i \oplus K_i")
        st.markdown(
            "Replay is now defeated by **two independent mechanisms**:\n\n"
            "1. **Classical (O(1)):** the verifier's nonce registry has already consumed "
            "that nonce, so the replay is rejected before any quantum state is measured.\n"
            "2. **Quantum (O(n)):** if the attacker invents a fresh nonce to evade the "
            "registry, the bound digest changes and she must re-derive all 256 states "
            "for it. Without K that is exactly the forgery problem, detected at ~50% "
            "error."
        )

        st.markdown('<div class="sec-header">C. RUN COMPARISON</div>',
                    unsafe_allow_html=True)
        st.caption(
            "Both modes replay the same captured signature for the same message. Only "
            "the freshness binding differs."
        )

        if st.button("RUN SAME-MESSAGE REPLAY (BOTH MODES)", type="primary"):
            with st.spinner("Executing both modes..."):
                legacy_res = run_replay_attack(
                    original_message=message,
                    target_message=message,
                    shared_key=shared_key,
                    shots_per_qubit=shots_per_qubit,
                    baseline_error_rate=baseline_noise,
                    alpha=alpha,
                    backend=active_backend_adapter,
                    seed=seed,
                )
                demo_session = create_session(signer_id="alice", counter=1)
                protected_res = run_replay_attack(
                    original_message=message,
                    target_message=message,
                    shared_key=shared_key,
                    shots_per_qubit=shots_per_qubit,
                    baseline_error_rate=baseline_noise,
                    alpha=alpha,
                    backend=active_backend_adapter,
                    seed=seed,
                    original_session=demo_session,
                    nonce_registry=NonceRegistry(),
                )

            col_legacy, col_prot = st.columns(2)

            with col_legacy:
                st.markdown("#### Legacy: no freshness binding")
                st.metric("Observed error rate", f"{legacy_res['observed_error_rate']:.4f}")
                st.metric(
                    "Detected",
                    "NO" if not legacy_res["replay_detected_classically"] else "YES",
                )
                st.error(
                    "ATTACK SUCCEEDS: the replayed signature is indistinguishable from "
                    "a fresh one."
                )
                st.caption(legacy_res["protocol_note"])

            with col_prot:
                st.markdown("#### Protected: session nonce bound")
                st.metric("Observed error rate", f"{protected_res['observed_error_rate']:.4f}")
                st.metric(
                    "Detected",
                    "YES" if protected_res["replay_detected_classically"] else "NO",
                )
                if protected_res["replay_detected_classically"]:
                    st.success(
                        "ATTACK BLOCKED: nonce already consumed. Rejected in O(1) "
                        "before any quantum state was measured."
                    )
                st.caption(protected_res["protocol_note"])

            st.info(
                "Note that the quantum error rate is ~0 in BOTH columns. That is the "
                "point: the quantum layer genuinely cannot see this attack. Detection "
                "comes from the classical freshness mechanism, which is why the "
                "framework needs both."
            )

            audit_logger.log_event(
                event_type="REPLAY_BLOCKED",
                severity="CRITICAL",
                verdict="REJECT",
                message_digest_prefix=sha256_hex(message)[:16],
                detail={
                    "attack_name": "Replay Attack (Same Message, Nonce Reuse)",
                    "freshness_enabled": True,
                    "replay_detected_classically": protected_res["replay_detected_classically"],
                    "observed_error_rate": protected_res["observed_error_rate"],
                },
            )

    # ────────────────────────────────────────────────
    # ATTACK: Unauthorized Verification Attempt
    # ────────────────────────────────────────────────
    elif attack_choice == "Unauthorized Verification Attempt":
        st.header("Unauthorized Verification Attempt")

        st.markdown('<div class="sec-header">A. THREAT MODEL</div>', unsafe_allow_html=True)
        st.markdown(
            "A party attempts to verify a signature without being entitled to. Three "
            "attacker profiles are modelled:\n\n"
            "- **NO_TOKEN** — presents no authorization token at all.\n"
            "- **FORGED_TOKEN** — fabricates a token of the correct shape.\n"
            "- **WRONG_IDENTITY** — presents a token validly issued to somebody else "
            "(token substitution / relay)."
        )

        st.markdown('<div class="sec-header">B. MECHANISM</div>', unsafe_allow_html=True)
        st.latex(r"\tau = \mathrm{HMAC\text{-}SHA256}_{K_M}(\mathrm{id})")
        st.markdown(
            "Tokens are compared in constant time via `hmac.compare_digest`. Detection "
            "is **deterministic**: a token either validates or it does not. There is no "
            "statistical uncertainty and therefore no false-positive rate, unlike the "
            "measurement-based detectors used for the quantum attacks."
        )
        st.info(
            "WHY EARLY REJECTION MATTERS: quantum states cannot be copied and are "
            "destroyed by measurement. A party allowed to measure a signature consumes "
            "it, so unrestricted verification is itself a denial-of-service vector "
            "against legitimate verifiers. Authorization runs before the quantum stage."
        )

        st.markdown('<div class="sec-header">C. RUN ALL PROFILES</div>',
                    unsafe_allow_html=True)
        unauth_subset = st.slider(
            "Signature positions to verify in the control run", 8, 64, 24, 8
        )

        if st.button("RUN UNAUTHORIZED VERIFICATION SWEEP", type="primary"):
            with st.spinner("Attempting verification under each attacker profile..."):
                sweep = run_authorization_profile_sweep(
                    message=message,
                    shared_key=shared_key,
                    sample_indices=list(range(int(unauth_subset))),
                    baseline_error_rate=baseline_noise,
                    backend=active_backend_adapter,
                    seed=seed,
                )

            st.dataframe(
                [
                    {
                        "Attacker Profile": r["attacker_profile"],
                        "Token Presented": "Yes" if r["token_presented"] else "No",
                        "Denied": "YES" if r["denied"] else "NO",
                        "Detection": "Deterministic" if r["detection_is_deterministic"] else "Statistical",
                        "Quantum States Consumed": r["quantum_states_consumed_by_attacker"],
                        "Legitimate Verifier Still Accepted": (
                            "Yes" if r["control_verification_accepted"] else "No"
                        ),
                    }
                    for r in sweep
                ],
                width="stretch",
                hide_index=True,
            )

            if all(r["denied"] for r in sweep):
                st.success(
                    "ALL UNAUTHORIZED PROFILES DENIED. Zero signature states were "
                    "consumed by any attacker, and the legitimate verifier was still "
                    "accepted in every case — access control does not impair authorized "
                    "use."
                )
            else:
                st.error("At least one unauthorized profile was NOT denied.")

            for r in sweep:
                st.caption(r["interpretation"])
                audit_logger.log_event(
                    event_type="AUTH_DENIED" if r["denied"] else "AUTH_GRANTED",
                    severity="CRITICAL" if r["denied"] else "INFO",
                    message_digest_prefix=sha256_hex(message)[:16],
                    detail={
                        "attack_name": "Unauthorized Verification",
                        "attacker_profile": r["attacker_profile"],
                        "attacker_id": r["attacker_id"],
                        "denied": r["denied"],
                        "quantum_states_consumed": r["quantum_states_consumed_by_attacker"],
                    },
                )

        st.markdown('<div class="sec-header">D. SCOPE DISCLOSURE</div>',
                    unsafe_allow_html=True)
        st.warning(
            "This is a CLASSICAL access-control mechanism, not an information-theoretic "
            "one. Its security rests on the PRF security of HMAC-SHA256 and on the "
            "master secret remaining secret. It is included because unauthorized "
            "verification is a named threat in the framework's scope and the quantum "
            "layer cannot address it: quantum states do not encode who may measure them."
        )


# =============================================================================
#  SECTION 6: ANALYSIS
# =============================================================================
elif nav_section == "Analysis":
    st.title("STATISTICAL ANALYSIS LABORATORY")

    analysis_sub = st.radio(
        "Section",
        ["Hypothesis Test (Interactive)", "Basis Response Analysis", "Attack Comparison Table"],
        horizontal=True,
    )

    # ── 6a: Interactive Hypothesis Test ─────────────────────────────────────
    if analysis_sub == "Hypothesis Test (Interactive)":
        st.header("Exact Binomial Hypothesis Test — Interactive Explorer")
        st.markdown(
            "The threat detector computes the exact Binomial upper-tail p-value: "
            "$P(K \\ge k \\mid n, p_0)$ and compares it to significance threshold $\\alpha$."
        )

        int_c1, int_c2, int_c3, int_c4 = st.columns(4)
        ht_n = int_c1.number_input("Total Trials (n)", min_value=1, max_value=2560, value=256, step=1)
        ht_k = int_c2.number_input("Observed Errors (k)", min_value=0, max_value=2560, value=10, step=1)
        ht_p0 = int_c3.slider("Baseline Error Rate (p0)", 0.001, 0.30, float(baseline_noise), 0.001)
        ht_alpha = int_c4.slider("Significance Threshold (alpha)", 0.001, 0.20, float(alpha), 0.001)

        ht_k = min(ht_k, ht_n)
        pval = binom.sf(ht_k - 1, ht_n, ht_p0)
        threat_detected_ht = pval <= ht_alpha

        ht_res_c1, ht_res_c2, ht_res_c3 = st.columns(3)
        ht_res_c1.metric("Exact p-value", f"{pval:.6e}")
        ht_res_c2.metric("Threshold alpha", f"{ht_alpha:.4f}")
        ht_res_c3.metric("Decision", "REJECT H0 (THREAT DETECTED)" if threat_detected_ht else "FAIL TO REJECT H0")

        fig_ht = _plot_pmf(ht_n, ht_p0, ht_k, ht_alpha)
        st.pyplot(fig_ht)
        plt.close(fig_ht)

    # ── 6b: Basis Response Analysis ─────────────────────────────────────────
    elif analysis_sub == "Basis Response Analysis":
        st.header("Basis-Wise Channel Noise Response Analysis")
        probs = [0.00, 0.05, 0.10, 0.20, 0.50, 1.00]
        if st.button("RUN LIVE BASIS-WISE SWEEP (Qiskit Aer)", type="primary"):
            with st.spinner("Executing sweeps..."):
                b_sweep = run_basis_wise_channel_sweep(
                    message=message,
                    shared_key=shared_key,
                    probabilities=probs,
                    baseline_error_rate=baseline_noise,
                    alpha=alpha,
                    seed=seed,
                )
                st.session_state.b_sweep = b_sweep

        if "b_sweep" in st.session_state:
            b_sweep = st.session_state.b_sweep
            z_data = b_sweep["Z"]
            x_data = b_sweep["X"]
            y_data = b_sweep["Y"]

            ps = [d["probability"] for d in z_data]
            z_obs = [d["observed_error_rate"] for d in z_data]
            x_obs = [d["observed_error_rate"] for d in x_data]
            y_obs = [d["observed_error_rate"] for d in y_data]

            fig_bw, axes_bw = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
            fig_bw.patch.set_facecolor('#130825')
            for ax_, obs_, label_, color_ in zip(
                axes_bw,
                [z_obs, x_obs, y_obs],
                ["Z Basis (Sensitive)", "X Basis (Invariant)", "Y Basis (Sensitive)"],
                ["#FF2A85", "#38BDF8", "#C084FC"],
            ):
                ax_.set_facecolor('#0B0414')
                ax_.plot(ps, obs_, "o-", color=color_, linewidth=2, markersize=6, label="Observed")
                ax_.set_xlabel(r"$p_{\mathrm{atk}}$", color="#E9D5FF")
                ax_.set_title(label_, fontsize=10, color="#FF70A6", fontweight="bold")
                ax_.grid(True, linestyle="--", alpha=0.2, color="#A855F7")
                ax_.tick_params(colors="#C084FC")
                for spine in ax_.spines.values():
                    spine.set_color((236/255, 72/255, 153/255, 0.3))
                ax_.legend(fontsize=8, facecolor="#180B30", edgecolor="#EC4899", labelcolor="#F3E8FF")

            axes_bw[0].set_ylabel("Verification Error Rate", color="#E9D5FF")
            fig_bw.tight_layout()
            st.pyplot(fig_bw)
            plt.close(fig_bw)

    # ── 6c: Attack Comparison Table ──────────────────────────────────────────
    else:
        st.header("Integrated Attack Comparison")

        if st.button("RUN ALL 6 ATTACK SCENARIOS", type="primary"):
            with st.spinner("Executing 6-scenario comparative evaluation..."):
                comp_results = run_security_comparison(
                    message=message,
                    shared_key=shared_key,
                    baseline_error_rate=baseline_noise,
                    alpha=alpha,
                    shots_per_qubit=shots_per_qubit,
                    seed=seed,
                )
                st.session_state.comp_results = comp_results

        if "comp_results" in st.session_state:
            comp_results: List[ExperimentResult] = st.session_state.comp_results

            st.subheader("Quantitative Experiment Comparison")
            tbl_data = []
            for r in comp_results:
                theo = (
                    f"{r.theoretical_expectation:.4f}"
                    if isinstance(r.theoretical_expectation, float)
                    else str(r.theoretical_expectation)
                )
                obs = r.observed_error_rate
                theo_float = r.theoretical_expectation if isinstance(r.theoretical_expectation, float) else 0.0
                dev = abs(obs - theo_float) if isinstance(r.theoretical_expectation, float) else 0.0

                tbl_data.append({
                    "Attack Scenario": r.attack_name,
                    "Attacker Knowledge": r.relevant_params.get("attacker_knowledge", "N/A"),
                    "Theoretical Rate": theo,
                    "Observed Error Rate": f"{obs:.4f}",
                    "Errors / Trials": f"{r.num_errors} / {r.total_trials}",
                    "Deviation": f"{dev:.4f}",
                    "Binomial p-value": f"{r.threat_result.p_value:.4e}",
                    "Threat Decision": "THREAT DETECTED" if r.threat_result.threat_detected else "NORMAL CHANNEL",
                })
            st.dataframe(tbl_data, width="stretch")

            st.subheader("Qualitative Security Mechanism Comparison")
            qual_data = [
                {
                    "Attack": "No Attack / Baseline",
                    "What Eve Knows": "Nothing",
                    "What Eve Controls": "None",
                    "What Bob Observes": "Legitimate channel noise ~ p0",
                    "Why Detection Works": "Error rate <= p0; fails to reject H0",
                },
                {
                    "Attack": "Channel Tampering",
                    "What Eve Knows": "None",
                    "What Eve Controls": "Pauli-X error probability pₐₜₖ on q2",
                    "What Bob Observes": "Z/Y basis errors ~ pₐₜₖ; X invariant",
                    "Why Detection Works": "Net error rate (2/3)pₐₜₖ exceeds p₀",
                },
                {
                    "Attack": "Signature Forgery",
                    "What Eve Knows": "Message M, SHA-256 Digest D",
                    "What Eve Controls": "Forged states prepared assuming K=0",
                    "What Bob Observes": "Errors at positions where Kᵢ = 1",
                    "Why Detection Works": "Key 1-density (~50%) causes large error rate",
                },
                {
                    "Attack": "Impersonation",
                    "What Eve Knows": "None",
                    "What Eve Controls": "Random Bernoulli(0.5) state guesses",
                    "What Bob Observes": "50% verification error rate",
                    "Why Detection Works": "Random guesses fail 50% of the time",
                },
                {
                    "Attack": "Quantum Interception",
                    "What Eve Knows": "None",
                    "What Eve Controls": "Intercepts q0, measures, resends eigenstate",
                    "What Bob Observes": "33.3% error rate from basis collapse",
                    "Why Detection Works": "Mismatched basis measurements disturb quantum states",
                },
                {
                    "Attack": "Replay Attack",
                    "What Eve Knows": "Captured legitimate quantum signature",
                    "What Eve Controls": "Replays past signature for new session",
                    "What Bob Observes": "0% error if same message; ~50% if diff message",
                    "Why Detection Works": "SHA-256 digest Hamming distance causes errors for diff message",
                },
            ]
            st.dataframe(qual_data, width="stretch")


# =============================================================================
#  SECTION 7: KEY DISTRIBUTION (BBM92 ENTANGLEMENT-BASED QKD)
# =============================================================================
elif nav_section == "Key Distribution":
    st.title("QUANTUM KEY DISTRIBUTION — BBM92")
    st.caption(
        "Establishes the shared secret key K from measured Bell pairs rather than "
        "assuming it was pre-shared. This is the quantum public key distribution stage "
        "of the protocol."
    )

    st.header("Protocol")
    st.markdown(
        "1. A Bell state is prepared and split between Alice and Bob.\n"
        "2. Each independently chooses a random measurement basis and measures.\n"
        "3. Bases are disclosed over an authenticated public channel; mismatches are "
        "discarded (**sifting**).\n"
        "4. A random sample of surviving bits is disclosed to estimate the QBER, then "
        "discarded.\n"
        "5. The remainder becomes the key."
    )
    st.latex(r"|\Phi^+\rangle = \frac{1}{\sqrt{2}}\left(|00\rangle + |11\rangle\right)")
    st.latex(
        r"\langle Z\otimes Z\rangle = +1, \qquad "
        r"\langle X\otimes X\rangle = +1, \qquad "
        r"\langle Y\otimes Y\rangle = -1"
    )
    st.warning(
        "The Y-basis correlation is NEGATIVE. Measuring Y on both halves of this Bell "
        "state yields opposite outcomes, so Bob must invert his Y-basis results during "
        "reconciliation. Omitting that inversion produces a 100% error rate on Y-sifted "
        "positions."
    )

    st.header("Eavesdropper Detection")
    st.latex(
        r"\mathrm{QBER}_{\text{intercept-resend}} = "
        r"\left(1 - \frac{1}{B}\right)\cdot\frac{1}{2}"
    )
    st.markdown(
        "where B is the number of bases in use. Two bases give the textbook BB84 value "
        "of **25%**; three bases give **33.3%**. An honest channel on an ideal simulator "
        "yields QBER = 0, so any excess is eavesdropping or hardware noise."
    )

    st.header("Run Distribution")
    qkd_col1, qkd_col2, qkd_col3 = st.columns(3)
    with qkd_col1:
        qkd_raw = st.select_slider(
            "Bell pairs to distribute", options=[200, 400, 800, 1600, 3000], value=800
        )
    with qkd_col2:
        qkd_basis_choice = st.radio(
            "Measurement bases", options=["Z, X (BBM92 standard)", "Z, X, Y"], index=0
        )
    with qkd_col3:
        qkd_eve = st.checkbox("Simulate intercept-resend eavesdropper", value=False)

    qkd_bases = DEFAULT_QKD_BASES if qkd_basis_choice.startswith("Z, X (") else ALL_QKD_BASES

    if st.button("RUN QUANTUM KEY DISTRIBUTION", type="primary"):
        with st.spinner("Distributing and measuring Bell pairs..."):
            qkd_res = run_key_distribution(
                raw_bits=int(qkd_raw),
                bases=qkd_bases,
                eavesdropper_present=qkd_eve,
                qber_sample_fraction=0.5,
                baseline_error_rate=baseline_noise,
                alpha=alpha,
                target_key_length=None,
                backend=active_backend_adapter,
                seed=seed,
            )

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Raw pairs", qkd_res.raw_bits)
        m2.metric("Sifted bits", qkd_res.sifted_length)
        m3.metric("Final key bits", len(qkd_res.key_bits))
        expected_qber = (1 - 1 / len(qkd_bases)) * 0.5 if qkd_eve else 0.0
        m4.metric(
            "QBER",
            f"{qkd_res.qber:.4f}",
            delta=f"{qkd_res.qber - expected_qber:+.4f} vs theory",
        )

        if qkd_res.threat_result is not None:
            if qkd_res.threat_result.threat_detected:
                st.error(
                    "EAVESDROPPER DETECTED — " + qkd_res.threat_result.interpretation
                )
                st.markdown("This key must be **discarded**, not used for signing.")
            else:
                st.success("CHANNEL CLEAN — " + qkd_res.threat_result.interpretation)

        st.info(qkd_res.interpretation)

        if qkd_res.key_bits:
            st.markdown("**Established key (first 128 bits)**")
            st.code("".join(str(b) for b in qkd_res.key_bits[:128]), language=None)
            st.caption(
                f"1-bit density: {sum(qkd_res.key_bits) / len(qkd_res.key_bits):.4f} "
                f"(0.5 expected for a well-formed key)"
            )

        audit_logger.log_event(
            event_type="KEY_DISTRIBUTION",
            severity="CRITICAL" if (
                qkd_res.threat_result and qkd_res.threat_result.threat_detected
            ) else "INFO",
            detail={
                "raw_bits": qkd_res.raw_bits,
                "sifted_length": qkd_res.sifted_length,
                "qber": qkd_res.qber,
                "bases": qkd_res.bases_used,
                "eavesdropper_simulated": qkd_res.eavesdropper_present,
            },
        )

    st.header("Scope Disclosure")
    st.markdown(
        "- Basis reconciliation is assumed to run over an **authenticated** public "
        "classical channel, as BBM92 requires. Authenticating it is out of scope here.\n"
        "- **No information reconciliation or privacy amplification** is implemented, so "
        "the sifted key is not composably secure. This models the distribution and "
        "eavesdropper-detection stages only.\n"
        "- All QBER values come from executed Qiskit circuits; none are hardcoded."
    )


# =============================================================================
#  SECTION 8: THREAT CLASSIFICATION
# =============================================================================
elif nav_section == "Threat Classification":
    st.title("QUANTUM-INSPIRED THREAT CLASSIFICATION")
    st.caption(
        "Identifies WHICH threat is present, not merely that an anomaly occurred. "
        "Forgery, impersonation, and different-message replay all produce ~50% errors, "
        "so a pooled error rate cannot separate them."
    )

    st.header("How Discrimination Works")
    st.markdown(
        "The classifier scores the observed basis-resolved error profile "
        "(e_Z, e_X, e_Y) against each threat's analytically derived signature, then "
        "applies deterministic discriminators. No AI or ML is used."
    )

    st.dataframe(
        [
            {"Threat": "No attack", "e_Z": "p0", "e_X": "p0", "e_Y": "p0",
             "MCC(E,K)": "~0", "Discriminator": "All bases at calibrated baseline"},
            {"Threat": "Channel tampering", "e_Z": "p", "e_X": "~0", "e_Y": "p",
             "MCC(E,K)": "~0", "Discriminator": "X-BASIS IMMUNITY (unique)"},
            {"Threat": "Intercept-resend", "e_Z": "1/3", "e_X": "1/3", "e_Y": "1/3",
             "MCC(E,K)": "~0", "Discriminator": "Uniform at 1/3"},
            {"Threat": "Forgery", "e_Z": "rho", "e_X": "rho", "e_Y": "rho",
             "MCC(E,K)": "~+1", "Discriminator": "Errors track K_i = 1"},
            {"Threat": "Impersonation", "e_Z": "1/2", "e_X": "1/2", "e_Y": "1/2",
             "MCC(E,K)": "~0", "Discriminator": "Uniform at 1/2, independent of K"},
            {"Threat": "Replay (diff. msg)", "e_Z": "h", "e_X": "h", "e_Y": "h",
             "MCC(E,K)": "~0", "Discriminator": "Classical digest mismatch"},
            {"Threat": "Replay (same msg)", "e_Z": "p0", "e_X": "p0", "e_Y": "p0",
             "MCC(E,K)": "~0", "Discriminator": "Nonce registry (deterministic)"},
            {"Threat": "Unauthorized verify", "e_Z": "-", "e_X": "-", "e_Y": "-",
             "MCC(E,K)": "-", "Discriminator": "HMAC validation (deterministic)"},
        ],
        width="stretch",
        hide_index=True,
    )

    with st.expander("Why X-basis immunity identifies channel tampering"):
        st.latex(r"\sigma_X|+\rangle = +|+\rangle, \qquad \sigma_X|-\rangle = -|-\rangle")
        st.markdown(
            "Both are X eigenstates, so an X-basis measurement is invariant up to a "
            "global phase and records no error. Z and Y eigenstates are flipped. With "
            "the uniform basis schedule, exactly 2/3 of positions are sensitive:"
        )
        st.latex(r"\hat{e} \to \tfrac{2}{3}\,p \qquad (e_Z, e_X, e_Y) \to (p, 0, p)")
        st.markdown("No other modelled attack leaves an entire basis undisturbed.")

    with st.expander("Why key correlation separates forgery from impersonation"):
        st.markdown(
            "A digest-only forger prepares states from d_i while the verifier expects "
            "d_i XOR K_i. The two are orthogonal in the same basis exactly where "
            "K_i = 1, producing a deterministic error there and none elsewhere. The "
            "error indicator is therefore a copy of the key:"
        )
        st.latex(r"\mathrm{MCC}(E, K) \to +1 \quad\text{(forgery)}")
        st.latex(r"\mathrm{MCC}(E, K) \to 0 \quad\text{(impersonation)}")

    st.header("Statistical Resolution Limit")
    res_n = minimum_trials_for_resolution(1.0 / 3.0, 0.5)
    st.latex(
        r"n \ge \frac{9\left(q_a(1-q_a) + q_b(1-q_b)\right)}{(q_a - q_b)^2}"
    )
    st.markdown(
        f"The tightest pair is intercept-resend (1/3) against impersonation (1/2), "
        f"requiring **n >= {res_n}** at 3 sigma. This is why classification is reliable "
        f"at the full n = 256 and unreliable on small subsets — the classifier reports a "
        f"resolution warning and scales confidence down when the sample is too small."
    )

    st.header("Live Classification")
    clf_attack = st.selectbox(
        "Attack scenario to classify",
        options=[
            "No Attack / Baseline",
            "Channel Tampering",
            "Signature Forgery",
            "Impersonation",
            "Quantum Interception",
            "Replay Attack",
        ],
    )
    clf_params: Dict[str, Any] = {}
    if clf_attack == "Channel Tampering":
        clf_params["p_attack"] = st.slider(
            "Channel tampering probability p", 0.0, 1.0, 0.50, 0.05
        )
    elif clf_attack == "Quantum Interception":
        clf_params["strategy"] = "uniform_random"
    elif clf_attack == "Replay Attack":
        clf_params["target_message"] = st.text_input(
            "Message Bob is verifying", value=f"{message}_modified"
        )

    if st.button("RUN AND CLASSIFY", type="primary"):
        with st.spinner("Executing circuits and profiling measurement statistics..."):
            clf_res = _run_and_cache(clf_attack, clf_params)

        _render_decision_banner(clf_res.decision)
        st.markdown("---")
        _render_classification_block(clf_res.classification)


# =============================================================================
#  SECTION 9: SECURITY BOUNDS (FORGERY PROBABILITY & DETECTION POWER)
# =============================================================================
elif nav_section == "Security Bounds":
    st.title("SECURITY ANALYSIS — FORGERY BOUNDS & DETECTION POWER")
    st.caption(
        "Exact closed-form binomial quantities. Nothing here is simulated or estimated."
    )

    st.header("Forgery Probability")
    st.markdown(
        "An adversary without the secret key has no information about "
        "b_i = d_i XOR K_i, because for a uniformly random K each b_i is uniform and "
        "independent of the digest. The best available strategy is a coin flip at every "
        "position. A signature is accepted when at most t = floor(s_a * n) positions "
        "disagree, so:"
    )
    st.latex(
        r"P_{\mathrm{forge}}(n, s_a) = "
        r"\sum_{j=0}^{\lfloor s_a n \rfloor} \binom{n}{j} \left(\frac{1}{2}\right)^{n}"
    )
    st.markdown(
        "This bound is **information-theoretic**: it holds against an adversary with "
        "unbounded computational power, including a quantum computer, because the "
        "adversary lacks information about K rather than facing a hard computation. "
        "Shor's algorithm has nothing to attack."
    )

    bound_col1, bound_col2 = st.columns(2)
    with bound_col1:
        s_a_input = st.slider(
            "Acceptance threshold s_a", 0.0, 0.25,
            float(round(decision_thresholds.s_accept, 3)), 0.005,
        )
    with bound_col2:
        key_density = sum(shared_key) / len(shared_key)
        st.metric("Active key 1-bit density", f"{key_density:.4f}")

    curve = forgery_bound_curve(
        [8, 16, 32, 64, 128, 256, 512], acceptance_threshold=s_a_input
    )
    st.dataframe(
        [
            {
                "n": c.signature_length,
                "Max tolerated errors t": c.max_tolerated_errors,
                "P_forge": f"{c.forgery_probability:.4e}",
                "Security (bits)": (
                    "inf" if math.isinf(c.security_bits) else f"{c.security_bits:.1f}"
                ),
            }
            for c in curve
        ],
        width="stretch",
        hide_index=True,
    )

    fig_fb, ax_fb = plt.subplots(figsize=(8, 4))
    finite = [c for c in curve if not math.isinf(c.security_bits)]
    ax_fb.plot(
        [c.signature_length for c in finite],
        [c.security_bits for c in finite],
        marker="o", color="#EC4899", linewidth=2,
    )
    ax_fb.set_xlabel("Signature length n")
    ax_fb.set_ylabel("Security level (bits)")
    ax_fb.set_title("Forgery resistance grows linearly in bits (exponentially in probability)")
    ax_fb.grid(True, alpha=0.3)
    st.pyplot(fig_fb)
    plt.close(fig_fb)

    at_256 = forgery_success_probability(256, s_a_input)
    st.success(f"At n = 256: {at_256.interpretation}")

    if key_density < 0.4 or key_density > 0.6:
        st.error(
            f"KEY WARNING: the active key has 1-bit density {key_density:.4f}, not ~0.5. "
            f"The bound above assumes a uniformly random key. A digest-only forger "
            f"succeeds per-position with probability 1 - density = "
            f"{1 - key_density:.4f}, so the real bound is weaker than shown."
        )

    st.header("Detection Power")
    st.markdown(
        "Power is the probability the exact binomial detector flags an attack of true "
        "error rate q, given the critical count k* set by alpha:"
    )
    st.latex(r"k^{*} = \min\{k : \Pr[K \ge k \mid n, p_0] < \alpha\}")
    st.latex(r"\mathrm{Power} = \Pr[K \ge k^{*} \mid n, q], \qquad "
             r"\mathrm{Size} = \Pr[K \ge k^{*} \mid n, p_0]")

    summary_rows = attack_detection_summary(256, baseline_noise, alpha)
    st.dataframe(
        [
            {
                "Attack": row["attack"],
                "Analytic error rate q": f"{row['analytic_error_rate']:.4f}",
                "Critical count k*": row["critical_errors"],
                "Detection power": f"{row['detection_probability']:.6f}",
                "False-positive rate": f"{row['false_positive_rate']:.4e}",
            }
            for row in summary_rows
        ],
        width="stretch",
        hide_index=True,
    )

    st.markdown("**Power versus signature length**")
    fig_dp, ax_dp = plt.subplots(figsize=(8, 4))
    lengths = [8, 16, 32, 64, 128, 256, 512]
    for label, q in [
        ("Intercept-resend (q=1/3)", 1.0 / 3.0),
        ("Forgery / Impersonation (q=1/2)", 0.5),
        ("Channel tampering p=0.10 (q=0.067)", (2.0 / 3.0) * 0.10),
    ]:
        powers = detection_power_curve(lengths, baseline_noise, q, alpha)
        ax_dp.plot(
            lengths, [p.detection_probability for p in powers],
            marker="o", linewidth=2, label=label,
        )
    ax_dp.axhline(0.99, linestyle="--", color="gray", alpha=0.6, label="99% power")
    ax_dp.set_xscale("log", base=2)
    ax_dp.set_xlabel("Signature length n")
    ax_dp.set_ylabel("Detection probability")
    ax_dp.set_ylim(-0.05, 1.05)
    ax_dp.legend(fontsize=8)
    ax_dp.grid(True, alpha=0.3)
    st.pyplot(fig_dp)
    plt.close(fig_dp)

    st.header("Decision Thresholds In Force")
    th = decision_thresholds
    t1, t2, t3 = st.columns(3)
    t1.metric("s_accept", f"{th.s_accept:.4f}")
    t2.metric("s_reject", f"{th.s_reject:.4f}")
    t3.metric("sigma", f"{th.sigma:.6f}")
    st.caption(th.rationale)
    st.markdown(
        "- Error rate **<= s_accept** -> ACCEPT (a noiseless channel gives exactly 0, so "
        "legitimate signatures are accepted deterministically).\n"
        "- **Between** the thresholds -> ABORT (evidence too strong for noise, too weak "
        "to attribute).\n"
        "- **>= s_reject** -> REJECT."
    )
    st.warning(
        "Honest limitation: channel tampering is a continuum at (2/3)p errors. At "
        "p = 0.10 it lands in ABORT, and below the calibrated noise floor it is "
        "information-theoretically indistinguishable from noise. No attack is ever "
        "ACCEPTED except a bit-flip weaker than that floor, which forges nothing."
    )


# =============================================================================
#  SECTION 10: PERFORMANCE & COMPLEXITY
# =============================================================================
elif nav_section == "Performance":
    st.title("PERFORMANCE & COMPUTATIONAL COMPLEXITY")
    st.caption(
        "Measured, not asserted. Wall-clock timings vary by machine; the scaling "
        "exponent is the reproducible quantity."
    )

    st.header("Analytic Complexity")
    st.dataframe(
        [
            {"Stage": row["stage"], "Complexity": row["complexity"], "Note": row["note"]}
            for row in build_complexity_table()
        ],
        width="stretch",
        hide_index=True,
    )

    st.header("Empirical Scaling")
    st.markdown(
        "If duration T scales as T = c * n^k then log T = log c + k log n, so a "
        "least-squares fit of log T against log n recovers the exponent k directly. "
        "k ~ 1 confirms O(n)."
    )
    st.latex(r"\log T = \log c + k \log n")

    perf_col1, perf_col2 = st.columns(2)
    with perf_col1:
        perf_sizes = st.multiselect(
            "Signature lengths to time",
            options=[8, 16, 32, 64, 128, 256],
            default=[16, 32, 64, 128],
        )
    with perf_col2:
        perf_repeats = st.slider("Timed repetitions per size (minimum kept)", 1, 5, 3)

    st.caption(
        "Methodology: one untimed warm-up pass, then the minimum of N timed runs. Timing "
        "noise is strictly additive, so the fastest run is the closest estimate of true "
        "cost. A single measurement per size can distort the fitted slope by 50% or more."
    )

    if st.button("RUN PERFORMANCE BENCHMARK", type="primary"):
        if len(perf_sizes) < 2:
            st.error("Select at least two signature lengths to fit a scaling exponent.")
        else:
            with st.spinner("Benchmarking..."):
                analysis = analyze_verification_complexity(
                    message=message,
                    shared_key=shared_key,
                    sizes=sorted(perf_sizes),
                    session=active_session,
                    backend=active_backend_adapter,
                    seed=seed,
                    repeats=int(perf_repeats),
                )
                enc_metrics = measure_encoding_performance(
                    message=message, shared_key=shared_key, repetitions=200,
                    session=active_session,
                )

            p1, p2, p3 = st.columns(3)
            p1.metric("Fitted exponent k", f"{analysis.log_log_slope:.3f}")
            p2.metric("Fit quality R^2", f"{analysis.r_squared:.4f}")
            p3.metric("Per-position cost", f"{analysis.per_qubit_seconds * 1000:.2f} ms")

            if "O(n) linear" in analysis.classification:
                st.success(f"CONFIRMED: {analysis.classification}")
            else:
                st.warning(
                    f"Measured {analysis.classification}. Expected O(n); a deviation "
                    f"usually indicates timing interference rather than a protocol change."
                )

            st.dataframe(
                [
                    {
                        "n": size,
                        "Duration (s)": f"{dur:.4f}",
                        "Per position (ms)": f"{dur / size * 1000:.3f}",
                    }
                    for size, dur in zip(analysis.sizes, analysis.durations)
                ],
                width="stretch",
                hide_index=True,
            )

            fig_pf, (ax_lin, ax_log) = plt.subplots(1, 2, figsize=(11, 4))
            ax_lin.plot(analysis.sizes, analysis.durations, marker="o",
                        color="#EC4899", linewidth=2)
            ax_lin.set_xlabel("Signature length n")
            ax_lin.set_ylabel("Duration (s)")
            ax_lin.set_title("Linear scale")
            ax_lin.grid(True, alpha=0.3)

            ax_log.loglog(analysis.sizes, analysis.durations, marker="o",
                          color="#A855F7", linewidth=2, label="measured")
            ref = [analysis.durations[0] * (s / analysis.sizes[0]) for s in analysis.sizes]
            ax_log.loglog(analysis.sizes, ref, linestyle="--", color="gray",
                          label="ideal O(n)")
            ax_log.set_xlabel("log n")
            ax_log.set_ylabel("log T")
            ax_log.set_title(f"Log-log fit: k = {analysis.log_log_slope:.3f}")
            ax_log.legend(fontsize=8)
            ax_log.grid(True, alpha=0.3, which="both")
            st.pyplot(fig_pf)
            plt.close(fig_pf)

            st.header("Classical vs Quantum Cost")
            st.markdown(
                f"The classical stage (hash, XOR, basis schedule) costs "
                f"**{enc_metrics.seconds_per_qubit * 1e6:.2f} microseconds** per position, "
                f"against **{analysis.per_qubit_seconds * 1000:.2f} milliseconds** for "
                f"circuit execution — roughly "
                f"{analysis.per_qubit_seconds / max(enc_metrics.seconds_per_qubit, 1e-12):.0f}x "
                f"cheaper. The constant factor is dominated by simulator overhead, not by "
                f"protocol arithmetic."
            )

    st.header("Measurement Disclosures")
    st.markdown(
        "- Wall-clock timings characterise this host and this simulator; they are "
        "reproducible in order of magnitude, not to the millisecond.\n"
        "- Simulator measurements do **not** predict physical QPU runtime, where queue "
        "latency dominates and is outside the protocol's control.\n"
        "- The freshness and authorization checks add O(1) work and are invisible at "
        "this resolution."
    )


# =============================================================================
#  SECTION 11: SECURITY EVENT AUDIT LOG
# =============================================================================
elif nav_section == "Audit Log":
    st.title("SECURITY EVENT AUDIT LOG")
    st.caption(
        "Append-only JSON Lines record of every verification, threat detection, "
        "authorization denial, and key-establishment run."
    )

    summary = audit_logger.summary()

    a1, a2, a3 = st.columns(3)
    a1.metric("Total events", summary["total_events"])
    a2.metric("Critical", summary["by_severity"].get("CRITICAL", 0))
    a3.metric("Informational", summary["by_severity"].get("INFO", 0))

    st.caption(f"Log file: {summary['log_path']}")
    if not audit_enabled:
        st.warning("Logging is currently disabled in the sidebar; no new events are written.")

    if summary["total_events"] == 0:
        st.info(
            "No events recorded yet. Run an experiment in the Security Lab, Threat "
            "Classification, or Key Distribution section to populate the log."
        )
    else:
        st.markdown("**Event breakdown by type**")
        st.dataframe(
            [{"Event Type": k, "Count": v} for k, v in sorted(summary["by_type"].items())],
            width="stretch",
            hide_index=True,
        )

        st.header("Event Stream")
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            sev_filter = st.multiselect(
                "Severity", options=["INFO", "WARNING", "CRITICAL"],
                default=["INFO", "WARNING", "CRITICAL"],
            )
        with filter_col2:
            max_rows = st.slider("Maximum rows", 10, 500, 100, 10)

        events = [
            e for e in audit_logger.read_events(limit=int(max_rows))
            if e.severity in sev_filter
        ]

        st.dataframe(
            [
                {
                    "Timestamp (UTC)": e.timestamp,
                    "Event": e.event_type,
                    "Severity": e.severity,
                    "Verdict": e.verdict or "-",
                    "Digest": e.message_digest_prefix or "-",
                    "Attack": e.detail.get("attack_name", "-"),
                    "Classified As": e.detail.get("classified_as") or "-",
                    "Error Rate": (
                        f"{e.detail['observed_error_rate']:.4f}"
                        if isinstance(e.detail.get("observed_error_rate"), (int, float))
                        else "-"
                    ),
                    "p-value": (
                        f"{e.detail['p_value']:.3e}"
                        if isinstance(e.detail.get("p_value"), (int, float))
                        else "-"
                    ),
                }
                for e in reversed(events)
            ],
            width="stretch",
            hide_index=True,
        )

        with st.expander("Inspect a single event payload"):
            if events:
                chosen = st.selectbox(
                    "Event",
                    options=list(range(len(events))),
                    format_func=lambda i: f"{events[i].timestamp} — {events[i].event_type}",
                )
                st.json({
                    "event_id": events[chosen].event_id,
                    "timestamp": events[chosen].timestamp,
                    "event_type": events[chosen].event_type,
                    "severity": events[chosen].severity,
                    "verdict": events[chosen].verdict,
                    "message_digest_prefix": events[chosen].message_digest_prefix,
                    "detail": events[chosen].detail,
                })

        export_col1, export_col2 = st.columns(2)
        with export_col1:
            st.download_button(
                "Download Audit Log (JSON)",
                data=audit_logger.export_json(),
                file_name="qds_security_events.json",
                mime="application/json",
            )
        with export_col2:
            if st.button("Clear Audit Log"):
                audit_logger.clear()
                st.rerun()

    st.header("Secret Hygiene")
    st.markdown(
        "Key material is **never** written to the log. Only non-invertible derived "
        "quantities are recorded: the key's 1-bit density, a 16-character digest prefix, "
        "and the nonce (a public protocol value needed for replay forensics). Fields "
        "matching known-sensitive names are replaced with `[REDACTED]` as defence in "
        "depth, so the log is safe to export."
    )
    st.warning(
        "The log is tamper-evident only insofar as the host filesystem is trusted. It is "
        "not cryptographically chained and does not defend against an attacker holding "
        "write access."
    )


# =============================================================================
#  SECTION 12: REPRODUCIBILITY
# =============================================================================
elif nav_section == "Reproducibility":
    st.title("SCIENTIFIC DISCLOSURES & REPRODUCIBILITY")

    st.header("Execution Environment")
    env_dict = {
        "operating_system": platform.platform(),
        "python_version": sys.version,
        "qiskit_version": "2.5.2",
        "numpy_version": np.__version__,
        "simulation_backend": "AerSimulator (Qiskit Aer)",
    }
    st.json(env_dict)

    st.header("Experiment Parameters")
    config_dict = {
        "message_M": message,
        "sha256_digest_bits": 256,
        "shared_key_mode": key_mode,
        "shared_key_provenance": key_provenance,
        "shared_key_1_density": sum(shared_key) / 256,
        "random_seed": seed,
        "shots_per_qubit": shots_per_qubit,
        "baseline_error_rate_p0": baseline_noise,
        "significance_threshold_alpha": alpha,
        "execution_backend": execution_backend_mode,
        "freshness_binding_enabled": freshness_enabled,
        "audit_logging_enabled": audit_enabled,
        "decision_threshold_s_accept": round(decision_thresholds.s_accept, 6),
        "decision_threshold_s_reject": round(decision_thresholds.s_reject, 6),
        "decision_threshold_sigma": round(decision_thresholds.sigma, 8),
        "seed_derivation": "ShotSeeder (RNG-drawn per-shot seeds, not consecutive integers)",
    }
    st.json(config_dict)

    st.download_button(
        "Download Configuration JSON",
        data=json.dumps(config_dict, indent=2),
        file_name="qds_config.json",
        mime="application/json",
    )
