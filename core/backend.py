"""
Backend Abstraction Layer for Quantum Circuit Execution.

Provides a unified interface for executing Qiskit circuits on local Aer simulators,
realistic IBM Quantum noise model simulators (Fake QPU backends), and hardware adapters.
"""

from typing import Dict, Any, Optional, Union
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

# Try importing fake backends for realistic IBM noise simulation
try:
    from qiskit_ibm_runtime.fake_provider import (
        FakeBrisbane,
        FakeKyoto,
        FakeSherbrooke,
        FakeTorino,
        FakeOsaka,
        FakeManilaV2,
        FakeNairobiV2,
        FakeFez,
        FakeMarrakesh,
        FakeKingston,
    )
    HAS_FAKE_BACKENDS = True
    FAKE_BACKEND_MAP = {
        # ONLY fake_* prefixed names are local noise simulators.
        # Real ibm_* names (ibm_fez, ibm_marrakesh, etc.) must NOT be here
        # — they must go through the IBM Cloud job submission path.
        "fake_fez": FakeFez,
        "fake_marrakesh": FakeMarrakesh,
        "fake_kingston": FakeKingston,
        "fake_brisbane": FakeBrisbane,
        "fake_torino": FakeTorino,
        "fake_kyoto": FakeKyoto,
        "fake_sherbrooke": FakeSherbrooke,
        "fake_osaka": FakeOsaka,
        "fake_manila": FakeManilaV2,
        "fake_nairobi": FakeNairobiV2,
    }
except ImportError:
    HAS_FAKE_BACKENDS = False
    FAKE_BACKEND_MAP = {}


class QuantumBackendAdapter:
    """
    Abstract adapter for running quantum circuits on simulation or hardware backends.
    Supports ideal Qiskit AerSimulator, realistic IBM QPU noise model simulators,
    and external backend wrappers.
    """

    def __init__(
        self,
        backend_name: str = "aer_simulator",
        backend_instance: Optional[Any] = None,
    ) -> None:
        """
        Initialize the backend adapter.

        Args:
            backend_name: Name of backend to instantiate ("aer_simulator" default,
                          or "fake_brisbane", "fake_torino", "fake_kyoto", "fake_sherbrooke", etc.).
            backend_instance: Optional pre-instantiated Backend or AerSimulator instance.
        """
        self.backend_name = backend_name
        self._target_device = None
        self._is_noisy = False

        if backend_instance is not None:
            self._simulator = backend_instance
            self.backend_name = getattr(backend_instance, "name", str(backend_name))
        elif backend_name in ("aer_simulator", "ideal", "noiseless"):
            self._simulator = AerSimulator()
            self.backend_name = "aer_simulator"
        else:
            clean_name = backend_name.lower().replace("-", "_")
            if HAS_FAKE_BACKENDS and clean_name in FAKE_BACKEND_MAP:
                fake_cls = FAKE_BACKEND_MAP[clean_name]
                self._target_device = fake_cls()
                self._simulator = AerSimulator.from_backend(self._target_device)
                self._is_noisy = True
                self.backend_name = clean_name
            else:
                raise ValueError(
                    f"Backend '{backend_name}' is not recognized. "
                    f"Supported options: 'aer_simulator' (ideal) or realistic IBM models: "
                    f"{list(FAKE_BACKEND_MAP.keys()) if HAS_FAKE_BACKENDS else 'None'}."
                )

    @property
    def is_noisy(self) -> bool:
        """Return True if backend executes with a realistic physical noise model."""
        return self._is_noisy

    def get_backend_metadata(self) -> Dict[str, Any]:
        """Return metadata describing the active backend."""
        num_qubits = 127
        basis_gates = ["rz", "sx", "x", "cz", "id"]
        if self._target_device is not None:
            num_qubits = getattr(self._target_device, "num_qubits", 127)
            if hasattr(self._target_device, "configuration"):
                cfg = self._target_device.configuration()
                basis_gates = getattr(cfg, "basis_gates", basis_gates)

        return {
            "backend_name": self.backend_name,
            "is_noisy": self._is_noisy,
            "num_qubits": num_qubits,
            "basis_gates": basis_gates,
            "type": "Noise-Model Aer Simulator" if self._is_noisy else "Ideal Aer Simulator",
        }

    def run_circuit(
        self,
        circuit: QuantumCircuit,
        shots: int = 1,
        seed_simulator: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a QuantumCircuit on the backend simulator.

        Args:
            circuit: The Qiskit QuantumCircuit to execute.
            shots: Number of execution shots (default: 1 for deterministic eigenstate check).
            seed_simulator: Optional random seed for reproducible testing.

        Returns:
            Dictionary containing 'counts', 'memory' (if available), and metadata.
        """
        run_kwargs: Dict[str, Any] = {"shots": shots, "memory": True}
        if seed_simulator is not None:
            run_kwargs["seed_simulator"] = seed_simulator

        # If noisy backend, transpile to match the device coupling map and basis gates
        circ_to_run = circuit
        if self._is_noisy and self._target_device is not None:
            circ_to_run = transpile(circuit, self._target_device, optimization_level=1)

        job = self._simulator.run(circ_to_run, **run_kwargs)
        result = job.result()

        counts = result.get_counts(circ_to_run)
        try:
            memory = result.get_memory(circ_to_run)
        except Exception:
            memory = []

        return {
            "counts": counts,
            "memory": memory,
            "raw_result": result,
            "backend_name": self.backend_name,
            "is_noisy": self._is_noisy,
        }
