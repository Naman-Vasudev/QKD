"""
IBM Quantum Hardware & Simulator Integration Module.

SCIENTIFIC INTEGRITY & DISCLOSURES:
- Provides hardware validation and noise simulation for representative 3-qubit teleportation primitives.
- Supports physical IBM Quantum QPUs, IBM Quantum Cloud Simulators, and Offline IBM Fake QPU Noise Models.
- Full 256-qubit security evaluation remains on AerSimulator for reproducibility and efficiency.
- Never hardcodes, displays, or logs API tokens.
- Gracefully degrades to simulation mode when hardware is unconfigured or unavailable.
"""

import os
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from qiskit import transpile

from qds.circuit_visualization import build_demonstration_teleportation_circuit
from core.backend import QuantumBackendAdapter, HAS_FAKE_BACKENDS, FAKE_BACKEND_MAP

# Optional import of Qiskit IBM Runtime
try:
    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    HAS_IBM_RUNTIME = True
except ImportError:
    HAS_IBM_RUNTIME = False

# Catalog of built-in IBM QPU Realistic Noise Simulators (offline, zero queue)
BUILTIN_IBM_NOISE_MODELS = [
    {
        "name": "fake_fez",
        "display_name": "IBM Fez (156-Qubit Heron r2 Noise Model)",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 QPU (156 Qubits, Tunable Couplers)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_marrakesh",
        "display_name": "IBM Marrakesh (156-Qubit Heron r2 Noise Model)",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 QPU (156 Qubits, Tunable Couplers)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_kingston",
        "display_name": "IBM Kingston (156-Qubit Heron r2 Noise Model)",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 QPU (156 Qubits, Tunable Couplers)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_brisbane",
        "display_name": "IBM Brisbane (127-Qubit Eagle Noise Model)",
        "num_qubits": 127,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cz", "id"],
        "processor": "Eagle r3 QPU (Calibrated Physical Noise)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_torino",
        "display_name": "IBM Torino (133-Qubit Heron Noise Model)",
        "num_qubits": 133,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cz", "id"],
        "processor": "Heron r1 QPU (Tunable Coupler Noise)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_sherbrooke",
        "display_name": "IBM Sherbrooke (127-Qubit Eagle Noise Model)",
        "num_qubits": 127,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cz", "id"],
        "processor": "Eagle r3 QPU (Calibrated Thermal/Readout Noise)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_kyoto",
        "display_name": "IBM Kyoto (127-Qubit Eagle Noise Model)",
        "num_qubits": 127,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cz", "id"],
        "processor": "Eagle r3 QPU (Physical Relaxation Noise)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_osaka",
        "display_name": "IBM Osaka (127-Qubit Eagle Noise Model)",
        "num_qubits": 127,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cz", "id"],
        "processor": "Eagle r3 QPU (Calibrated Noise)",
        "type": "ibm_fake_noise_sim",
    },
    {
        "name": "fake_manila",
        "display_name": "IBM Manila (5-Qubit Falcon Noise Model)",
        "num_qubits": 5,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["rz", "sx", "x", "cx", "id"],
        "processor": "Falcon r5 QPU (Legacy Benchmark Noise)",
        "type": "ibm_fake_noise_sim",
    },
]


def get_ibm_token() -> Optional[str]:
    """
    Retrieve IBM Quantum API token from environment variable or Streamlit secrets.
    Never exposes or logs the token.
    """
    token = os.environ.get("IBM_QUANTUM_API_TOKEN")
    if token and token.strip():
        return token.strip()

    try:
        import streamlit as st
        if hasattr(st, "secrets") and "IBM_QUANTUM_API_TOKEN" in st.secrets:
            sec_token = str(st.secrets["IBM_QUANTUM_API_TOKEN"]).strip()
            if sec_token:
                return sec_token
    except Exception:
        pass

    return None


def get_ibm_instance() -> Optional[str]:
    """
    Retrieve IBM Quantum / Cloud instance CRN from environment variable or Streamlit secrets.
    """
    inst = os.environ.get("IBM_QUANTUM_INSTANCE_CRN") or os.environ.get("IBM_QUANTUM_CRN")
    if inst and inst.strip():
        return inst.strip()

    try:
        import streamlit as st
        if hasattr(st, "secrets"):
            for k in ("IBM_QUANTUM_INSTANCE_CRN", "IBM_QUANTUM_CRN", "IBM_INSTANCE"):
                if k in st.secrets:
                    sec_inst = str(st.secrets[k]).strip()
                    if sec_inst:
                        return sec_inst
    except Exception:
        pass

    return None


def is_hardware_configured(
    token: Optional[str] = None,
    channel: Optional[str] = None,
    instance: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Check if IBM Quantum hardware access is available and configured.
    """
    if not HAS_IBM_RUNTIME:
        return False, "qiskit-ibm-runtime package is not installed."

    tok = token or get_ibm_token()
    if not tok:
        return False, "IBM Quantum API Token is not configured. Enter a token to authenticate."

    inst = instance or get_ibm_instance()

    try:
        service = _get_runtime_service(token=tok, channel=channel or "ibm_quantum", instance=inst)
        active_channel = getattr(service, "channel", "ibm_quantum")
        return True, f"Authenticated to IBM Quantum Platform ({active_channel})."
    except Exception as exc:
        return False, f"Authentication check failed: {str(exc)}"


_SERVICE_CACHE: Dict[Tuple[str, str, str], Any] = {}
_BACKENDS_CACHE: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
# Token-only fallback cache: reuse existing service for same token regardless of instance/channel.
# This prevents double-instantiation of QiskitRuntimeService which causes a native C segfault on
# Streamlit Cloud (Python 3.14 + qiskit-ibm-runtime). The full cache key is still preferred,
# but if a service was already created for this token we return it instead of creating a new one.
_SERVICE_BY_TOKEN: Dict[str, Any] = {}


DEFAULT_KNOWN_HERON_QPUS: List[Dict[str, Any]] = [
    {
        "name": "ibm_fez",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 (156 Qubits, Tunable Couplers)",
        "type": "physical_qpu",
    },
    {
        "name": "ibm_marrakesh",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 (156 Qubits, Tunable Couplers)",
        "type": "physical_qpu",
    },
    {
        "name": "ibm_kingston",
        "num_qubits": 156,
        "operational": True,
        "pending_jobs": 0,
        "basis_gates": ["cz", "rz", "sx", "x", "id"],
        "processor": "Heron r2 (156 Qubits, Tunable Couplers)",
        "type": "physical_qpu",
    },
]


def _get_runtime_service(
    token: Optional[str] = None,
    channel: str = "ibm_quantum",
    instance: Optional[str] = None,
) -> "QiskitRuntimeService":
    """
    Initialize QiskitRuntimeService, caching the result to prevent redundant network delays.

    Uses two cache layers:
    1. Full cache key (token, channel, instance) — exact match.
    2. Token-only fallback — reuses any existing service for the same token, regardless of
       channel/instance. This prevents double-instantiation which causes a native C segfault
       on Streamlit Cloud (Python 3.14 + qiskit-ibm-runtime).
    """
    if not HAS_IBM_RUNTIME:
        raise ImportError("qiskit-ibm-runtime package is not installed.")

    tok = token or get_ibm_token() or ""
    inst = instance or get_ibm_instance() or ""

    # Auto-detect IBM Cloud channel
    effective_channel = channel
    if (inst and ("bluemix" in inst or "crn:" in inst)) or (tok and len(tok) == 44 and not tok.startswith("ey")):
        effective_channel = "ibm_cloud"

    cache_key = (tok, effective_channel, inst)
    if cache_key in _SERVICE_CACHE:
        return _SERVICE_CACHE[cache_key]

    # Token-only fallback: reuse any existing service for this token to avoid
    # creating a second QiskitRuntimeService instance (causes segfault on Streamlit Cloud).
    if tok and tok in _SERVICE_BY_TOKEN:
        cached_srv = _SERVICE_BY_TOKEN[tok]
        _SERVICE_CACHE[cache_key] = cached_srv
        return cached_srv

    channels_to_try = [effective_channel]
    if effective_channel == "ibm_quantum":
        channels_to_try.append("ibm_cloud")

    last_exc = None
    for ch in channels_to_try:
        kwargs: Dict[str, Any] = {"channel": ch}
        if tok:
            kwargs["token"] = tok
        if inst:
            kwargs["instance"] = inst

        try:
            srv = QiskitRuntimeService(**kwargs)
            _SERVICE_CACHE[cache_key] = srv
            if tok:
                _SERVICE_BY_TOKEN[tok] = srv
            try:
                QiskitRuntimeService.save_account(channel=ch, token=tok, instance=inst or None, overwrite=True, set_as_default=True)
            except Exception:
                pass
            return srv
        except Exception as exc:
            last_exc = exc
            if inst:
                try:
                    kwargs_no_inst = {"channel": ch}
                    if tok:
                        kwargs_no_inst["token"] = tok
                    srv = QiskitRuntimeService(**kwargs_no_inst)
                    _SERVICE_CACHE[cache_key] = srv
                    if tok:
                        _SERVICE_BY_TOKEN[tok] = srv
                    return srv
                except Exception:
                    pass

    try:
        srv = QiskitRuntimeService()
        _SERVICE_CACHE[cache_key] = srv
        if tok:
            _SERVICE_BY_TOKEN[tok] = srv
        return srv
    except Exception as exc:
        raise last_exc or exc



def get_available_hardware_backends(
    token: Optional[str] = None,
    channel: str = "ibm_quantum",
    instance: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve available physical IBM Quantum hardware backends (QPUs).
    """
    if not HAS_IBM_RUNTIME:
        return []

    tok = token or get_ibm_token()
    if not tok:
        return []

    inst = instance or get_ibm_instance()
    cache_key = (tok, channel, inst or "")
    if cache_key in _BACKENDS_CACHE and _BACKENDS_CACHE[cache_key]:
        return _BACKENDS_CACHE[cache_key]

    try:
        service = _get_runtime_service(token=tok, channel=channel, instance=inst)
    except Exception:
        return []

    try:
        backends = service.backends(simulator=False, operational=True)
        results = []
        for b in backends:
            pending = 0
            try:
                status_obj = getattr(b, "status", lambda: None)()
                pending = getattr(status_obj, "pending_jobs", 0) if status_obj else 0
            except Exception:
                pass

            basis_gates = ["cz", "rz", "sx", "x", "id"]
            try:
                cfg = b.configuration()
                basis_gates = getattr(cfg, "basis_gates", basis_gates)
            except Exception:
                pass

            processor = "Heron r2 QPU"
            try:
                cfg = b.configuration()
                processor = getattr(cfg, "processor_type", {}).get("family", processor)
            except Exception:
                pass

            results.append({
                "name": b.name,
                "num_qubits": b.num_qubits,
                "operational": getattr(b, "operational", True),
                "pending_jobs": pending,
                "basis_gates": basis_gates,
                "processor": processor,
                "type": "physical_qpu",
            })
        if results:
            _BACKENDS_CACHE[cache_key] = results
            return results
    except Exception:
        pass

    _BACKENDS_CACHE[cache_key] = DEFAULT_KNOWN_HERON_QPUS
    return DEFAULT_KNOWN_HERON_QPUS


def get_available_simulator_backends(
    token: Optional[str] = None,
    channel: str = "ibm_quantum",
    instance: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve available IBM Quantum Simulator backends.
    Returns immediately from built-in high-fidelity noise models without blocking network queries.
    """
    return list(BUILTIN_IBM_NOISE_MODELS)


def _extract_bob_counts(raw_counts: Dict[str, Any]) -> Dict[str, int]:
    """Extract Bob measurement outcome (c2 register) from count strings."""
    bob_counts: Dict[str, int] = {}
    for k, v in raw_counts.items():
        bit_str = str(k).strip()
        bob_bit = bit_str.split()[0] if " " in bit_str else bit_str[0]
        bob_counts[bob_bit] = bob_counts.get(bob_bit, 0) + int(v)
    return bob_counts


def run_hardware_teleportation_experiment(
    state_label: str = "|+>",
    basis: str = "X",
    backend_name: Optional[str] = None,
    channel: str = "ibm_cloud",
    shots: int = 512,
    token: Optional[str] = None,
    execution_mode: str = "auto",
    instance: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a 3-qubit teleportation demonstration experiment on real IBM Quantum hardware,
    an IBM Quantum Cloud Simulator, or an Offline IBM Realistic QPU Noise Model Simulator.

    ROUTING LOGIC:
    - backend_name starts with "fake_"  OR  execution_mode == "ibm_fake_noise_sim"
      -> Local offline noise simulation (no IBM Cloud contact, instant results)
    - backend_name starts with "ibm_"   OR  execution_mode == "hardware"
      -> Real IBM Quantum Cloud QPU job (SamplerV2, waits in queue, consumes QPU time)
    """
    # 1. Always run ideal simulation baseline (noiseless Aer)
    qc_ideal = build_demonstration_teleportation_circuit(state_label, basis, attack_type="none")
    sim_backend = QuantumBackendAdapter("aer_simulator")
    sim_res = sim_backend.run_circuit(qc_ideal, shots=shots, seed_simulator=42)
    ideal_counts = _extract_bob_counts(sim_res["counts"])

    tot_sim = sum(ideal_counts.values()) or shots
    ideal_probs = {k: v / tot_sim for k, v in ideal_counts.items()}

    b_name = backend_name or "aer_simulator"
    result_dict: Dict[str, Any] = {
        "success": False,
        "state_label": state_label,
        "basis": basis,
        "shots": shots,
        "ideal_counts": ideal_counts,
        "ideal_probs": ideal_probs,
        "circuit_depth": qc_ideal.depth(),
        "num_qubits": qc_ideal.num_qubits,
        "num_clbits": qc_ideal.num_clbits,
        "gate_counts": dict(qc_ideal.count_ops()),
        "error_message": "",
        "hardware_backend": b_name,
        "backend_type": "simulation",
        "job_id": "N/A",
        "hardware_counts": {},
        "hardware_probs": {},
        "transpiled_depth": qc_ideal.depth(),
        "transpiled_ops": dict(qc_ideal.count_ops()),
        "fidelity": 1.0,
    }

    # 2. Route: local fake noise simulator (fake_* prefix only)
    #    IMPORTANT: real ibm_* names are NOT in FAKE_BACKEND_MAP anymore —
    #    they go through the IBM Cloud path below.
    is_fake_noise = (
        execution_mode == "ibm_fake_noise_sim"
        or b_name.lower().startswith("fake_")
        or b_name.lower().replace("-", "_") in FAKE_BACKEND_MAP
    )

    if is_fake_noise and HAS_FAKE_BACKENDS:
        try:
            fake_adapter = QuantumBackendAdapter(b_name)
            noisy_res = fake_adapter.run_circuit(qc_ideal, shots=shots, seed_simulator=42)
            hw_counts = _extract_bob_counts(noisy_res["counts"])

            tot_hw = sum(hw_counts.values()) or shots
            hw_probs = {k: v / tot_hw for k, v in hw_counts.items()}

            all_keys = set(ideal_probs.keys()).union(hw_probs.keys())
            bhatt = sum(np.sqrt(ideal_probs.get(k, 0.0) * hw_probs.get(k, 0.0)) for k in all_keys)
            fidelity = float(bhatt ** 2)

            target_dev = fake_adapter._target_device
            tqc = transpile(qc_ideal, target_dev, optimization_level=1) if target_dev else qc_ideal

            result_dict["success"] = True
            result_dict["hardware_backend"] = b_name
            result_dict["backend_type"] = "IBM Realistic Noise Model Simulator"
            result_dict["job_id"] = "LOCAL-IBM-NOISE-SIM"
            result_dict["hardware_counts"] = hw_counts
            result_dict["hardware_probs"] = hw_probs
            result_dict["fidelity"] = fidelity
            result_dict["transpiled_depth"] = tqc.depth()
            result_dict["transpiled_ops"] = dict(tqc.count_ops())
            return result_dict
        except Exception as exc:
            result_dict["error_message"] = f"Noise simulation error: {str(exc)}"
            return result_dict

    # 3. Real IBM Quantum Cloud QPU or Cloud Simulator
    if not HAS_IBM_RUNTIME:
        result_dict["error_message"] = "qiskit-ibm-runtime package not installed."
        return result_dict

    tok = token or get_ibm_token()
    inst = instance or get_ibm_instance()
    if not tok:
        result_dict["error_message"] = "IBM Quantum API token not configured."
        return result_dict

    try:
        service = _get_runtime_service(token=tok, channel=channel, instance=inst)

        if not backend_name or backend_name in ("ibm_cloud", "ibm_quantum", "unconfigured", "aer_simulator"):
            target_backend = service.least_busy(simulator=False, operational=True)
        else:
            target_backend = service.backend(backend_name)

        result_dict["hardware_backend"] = target_backend.name

        # V2 backends expose .simulator directly; avoid calling .configuration()
        is_cloud_sim = bool(getattr(target_backend, "simulator", False))
        result_dict["backend_type"] = "IBM Cloud Simulator" if is_cloud_sim else "Physical IBM Quantum QPU"

        # Transpile for the real hardware target
        try:
            pm = generate_preset_pass_manager(backend=target_backend, optimization_level=1)
        except TypeError:
            pm = generate_preset_pass_manager(target_backend=target_backend, optimization_level=1)
        isa_circuit = pm.run(qc_ideal)

        # Submit job via SamplerV2
        try:
            sampler = SamplerV2(mode=target_backend)
        except TypeError:
            sampler = SamplerV2(backend=target_backend)

        job = sampler.run([isa_circuit], shots=shots)
        job_id = job.job_id()
        result_dict["job_id"] = job_id  # Surface immediately so user can track

        # Wait up to 120 seconds for result; if queue is longer, surface job_id
        try:
            job_result = job.result(timeout=120)
        except Exception as timeout_exc:
            err_lower = str(timeout_exc).lower()
            if any(kw in err_lower for kw in ("timeout", "timed out", "time out")):
                result_dict["error_message"] = (
                    f"Job submitted to IBM (Job ID: {job_id}). "
                    f"The QPU queue is taking longer than 2 minutes. "
                    f"Track at: https://quantum.ibm.com/jobs/{job_id}"
                )
            elif any(kw in err_lower for kw in ("nameresolutionerror", "getaddrinfo failed", "max retries exceeded", "connectionerror")):
                result_dict["error_message"] = (
                    f"Network connection error while retrieving Job ID `{job_id}`: "
                    f"Unable to resolve or reach `quantum.cloud.ibm.com`. Please verify internet connectivity or track at: "
                    f"https://quantum.ibm.com/jobs/{job_id}"
                )
            else:
                result_dict["error_message"] = (
                    f"Job result retrieval failed (Job ID: {job_id}): {timeout_exc}. "
                    f"Track at: https://quantum.ibm.com/jobs/{job_id}"
                )
            return result_dict

        pub_result = job_result[0]

        # Extract counts — try c2 register first, then any register with get_counts
        hw_counts: Dict[str, int] = {}
        data = pub_result.data
        if hasattr(data, "c2"):
            raw = data.c2.get_counts()
            hw_counts = {str(k): int(v) for k, v in raw.items()}
        else:
            for reg_name in dir(data):
                if not reg_name.startswith("_"):
                    val = getattr(data, reg_name)
                    if hasattr(val, "get_counts"):
                        raw = val.get_counts()
                        hw_counts = {str(k): int(v) for k, v in raw.items()}
                        break

        if not hw_counts:
            result_dict["error_message"] = (
                f"Job {job_id} on {target_backend.name} returned empty counts. "
                f"Inspect at: https://quantum.ibm.com/jobs/{job_id}"
            )
            return result_dict

        tot_hw = sum(hw_counts.values()) or shots
        hw_probs = {k: v / tot_hw for k, v in hw_counts.items()}

        all_keys = set(ideal_probs.keys()).union(hw_probs.keys())
        bhatt = sum(np.sqrt(ideal_probs.get(k, 0.0) * hw_probs.get(k, 0.0)) for k in all_keys)
        fidelity = float(bhatt ** 2)

        result_dict["success"] = True
        result_dict["hardware_counts"] = hw_counts
        result_dict["hardware_probs"] = hw_probs
        result_dict["fidelity"] = fidelity
        result_dict["transpiled_depth"] = isa_circuit.depth()
        result_dict["transpiled_ops"] = dict(isa_circuit.count_ops())
        return result_dict

    except Exception as exc:
        result_dict["error_message"] = f"Hardware execution error: {exc}"
        return result_dict


def fetch_ibm_job_result(
    job_id: str,
    token: Optional[str] = None,
    channel: str = "ibm_cloud",
    instance: Optional[str] = None,
    state_label: str = "|+>",
    basis: str = "X",
    shots: int = 512,
) -> Dict[str, Any]:
    """
    Re-check or retrieve the status/results of a previously submitted IBM Quantum job by job_id.
    """
    qc_ideal = build_demonstration_teleportation_circuit(state_label, basis, attack_type="none")
    sim_backend = QuantumBackendAdapter("aer_simulator")
    sim_res = sim_backend.run_circuit(qc_ideal, shots=shots, seed_simulator=42)
    ideal_counts = _extract_bob_counts(sim_res["counts"])
    tot_sim = sum(ideal_counts.values()) or shots
    ideal_probs = {k: v / tot_sim for k, v in ideal_counts.items()}

    result_dict: Dict[str, Any] = {
        "success": False,
        "state_label": state_label,
        "basis": basis,
        "shots": shots,
        "ideal_counts": ideal_counts,
        "ideal_probs": ideal_probs,
        "circuit_depth": qc_ideal.depth(),
        "num_qubits": qc_ideal.num_qubits,
        "num_clbits": qc_ideal.num_clbits,
        "gate_counts": dict(qc_ideal.count_ops()),
        "error_message": "",
        "hardware_backend": "ibm_cloud",
        "backend_type": "Physical IBM Quantum QPU",
        "job_id": job_id,
        "hardware_counts": {},
        "hardware_probs": {},
        "transpiled_depth": qc_ideal.depth(),
        "transpiled_ops": dict(qc_ideal.count_ops()),
        "fidelity": 1.0,
    }

    if not HAS_IBM_RUNTIME:
        result_dict["error_message"] = "qiskit-ibm-runtime package not installed."
        return result_dict

    tok = token or get_ibm_token()
    inst = instance or get_ibm_instance()
    if not tok:
        result_dict["error_message"] = "IBM Quantum API token not configured."
        return result_dict

    try:
        service = _get_runtime_service(token=tok, channel=channel, instance=inst)
        job = service.job(job_id)
        status = job.status()
        status_str = str(status).upper()
        backend_obj = getattr(job, "backend", None)
        if backend_obj:
            result_dict["hardware_backend"] = getattr(backend_obj, "name", "ibm_cloud")

        if status_str not in ("DONE", "COMPLETED"):
            result_dict["error_message"] = (
                f"Job `{job_id}` status is currently: **{status_str}**. "
                f"It is still in the QPU queue or executing. Track at: https://quantum.ibm.com/jobs/{job_id}"
            )
            return result_dict

        job_result = job.result()
        pub_result = job_result[0]

        hw_counts: Dict[str, int] = {}
        data = pub_result.data
        if hasattr(data, "c2"):
            raw = data.c2.get_counts()
            hw_counts = {str(k): int(v) for k, v in raw.items()}
        else:
            for reg_name in dir(data):
                if not reg_name.startswith("_"):
                    val = getattr(data, reg_name)
                    if hasattr(val, "get_counts"):
                        raw = val.get_counts()
                        hw_counts = {str(k): int(v) for k, v in raw.items()}
                        break

        if not hw_counts:
            result_dict["error_message"] = f"Job `{job_id}` completed but returned empty counts."
            return result_dict

        tot_hw = sum(hw_counts.values()) or shots
        hw_probs = {k: v / tot_hw for k, v in hw_counts.items()}
        all_keys = set(ideal_probs.keys()).union(hw_probs.keys())
        bhatt = sum(np.sqrt(ideal_probs.get(k, 0.0) * hw_probs.get(k, 0.0)) for k in all_keys)
        fidelity = float(bhatt ** 2)

        result_dict["success"] = True
        result_dict["hardware_counts"] = hw_counts
        result_dict["hardware_probs"] = hw_probs
        result_dict["fidelity"] = fidelity
        return result_dict
    except Exception as exc:
        err_str = str(exc)
        if any(kw in err_str.lower() for kw in ("nameresolutionerror", "getaddrinfo failed", "max retries exceeded")):
            result_dict["error_message"] = (
                f"Network connection failed while fetching Job `{job_id}`: "
                f"Unable to resolve `quantum.cloud.ibm.com`. Please verify internet connection or check at https://quantum.ibm.com/jobs/{job_id}"
            )
        else:
            result_dict["error_message"] = f"Error retrieving Job `{job_id}`: {err_str}"
        return result_dict

