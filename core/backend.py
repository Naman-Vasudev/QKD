"""
Backend Abstraction Layer for Quantum Circuit Execution.

Provides a unified interface for executing Qiskit circuits on local Aer simulators.
IBM Quantum hardware integration is represented as a stub interface and will not be
invoked automatically or require online API credentials.
"""

from typing import Dict, Any, Optional
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


class QuantumBackendAdapter:
    """
    Abstract adapter for running quantum circuits on simulation or hardware backends.
    Default execution uses local Qiskit AerSimulator.
    """

    def __init__(self, backend_name: str = "aer_simulator") -> None:
        """
        Initialize the backend adapter.

        Args:
            backend_name: Name of backend to instantiate ("aer_simulator" default).
        """
        self.backend_name = backend_name
        if backend_name == "aer_simulator":
            self._simulator = AerSimulator()
        else:
            raise ValueError(
                f"Backend '{backend_name}' is not supported for offline execution. "
                "Only 'aer_simulator' is supported in local prototype mode."
            )

    def run_circuit(
        self,
        circuit: QuantumCircuit,
        shots: int = 1,
        seed_simulator: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a QuantumCircuit on the AerSimulator.

        Args:
            circuit: The Qiskit QuantumCircuit to execute.
            shots: Number of execution shots (default: 1 for deterministic eigenstate check).
            seed_simulator: Optional random seed for reproducible testing.

        Returns:
            Dictionary containing 'counts' and 'memory' (if available).
        """
        run_kwargs: Dict[str, Any] = {"shots": shots, "memory": True}
        if seed_simulator is not None:
            run_kwargs["seed_simulator"] = seed_simulator

        job = self._simulator.run(circuit, **run_kwargs)
        result = job.result()

        counts = result.get_counts(circuit)
        try:
            memory = result.get_memory(circuit)
        except Exception:
            memory = []

        return {
            "counts": counts,
            "memory": memory,
            "raw_result": result,
        }
