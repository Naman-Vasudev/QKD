"""
Unit tests for core/hardware.py (Optional IBM Quantum Hardware Integration Module).

Verifies safe fallback when API tokens are missing, mock hardware execution,
and absence of hardcoded credentials.
"""

import unittest
from unittest.mock import patch, MagicMock
import os

from core.hardware import (
    get_ibm_token,
    is_hardware_configured,
    get_available_hardware_backends,
    run_hardware_teleportation_experiment,
    HAS_IBM_RUNTIME,
)


class TestHardwareIntegration(unittest.TestCase):
    """Test suite for core/hardware.py."""

    def test_missing_api_key_returns_none(self):
        """Verify get_ibm_token returns None when environment variable is unset."""
        with patch.dict(os.environ, {}, clear=True):
            token = get_ibm_token()
            self.assertIsNone(token)

    def test_hardware_configured_check_without_token(self):
        """Verify is_hardware_configured returns False when no token is present."""
        with patch.dict(os.environ, {}, clear=True):
            configured, msg = is_hardware_configured()
            self.assertFalse(configured)
            self.assertIn("API Token", msg)

    def test_backend_discovery_without_token(self):
        """Verify get_available_hardware_backends returns empty list without token."""
        with patch.dict(os.environ, {}, clear=True):
            backends = get_available_hardware_backends()
            self.assertEqual(backends, [])

    def test_hardware_experiment_fallback_to_simulation(self):
        """Verify experiment runs simulation baseline even when hardware token is missing."""
        with patch.dict(os.environ, {}, clear=True):
            res = run_hardware_teleportation_experiment(
                state_label="|+>",
                basis="X",
                shots=100,
            )
            # Should have simulation results even if hardware fails/missing
            self.assertIn("ideal_counts", res)
            self.assertIn("ideal_probs", res)
            self.assertEqual(res["num_qubits"], 3)
            self.assertFalse(res["success"])
            self.assertIn("token not configured", res["error_message"].lower())

    @patch("core.hardware.QiskitRuntimeService")
    def test_mock_backend_discovery(self, mock_service_cls):
        """Verify backend discovery parses QiskitRuntimeService response correctly."""
        mock_backend = MagicMock()
        mock_backend.name = "ibm_fake_qpu"
        mock_backend.num_qubits = 127
        mock_backend.operational = True
        mock_backend.status.return_value.pending_jobs = 3

        mock_service = MagicMock()
        mock_service.backends.return_value = [mock_backend]
        mock_service_cls.return_value = mock_service

        backends = get_available_hardware_backends(token="fake_token_123")
        self.assertEqual(len(backends), 1)
        self.assertEqual(backends[0]["name"], "ibm_fake_qpu")
        self.assertEqual(backends[0]["num_qubits"], 127)
        self.assertEqual(backends[0]["pending_jobs"], 3)

    @patch("core.hardware.QiskitRuntimeService")
    def test_invalid_credentials_handling(self, mock_service_cls):
        """Verify authentication error in service initialization is handled gracefully."""
        mock_service_cls.side_effect = Exception("Invalid API Token supplied")

        backends = get_available_hardware_backends(token="invalid_token")
        self.assertEqual(backends, [])

        res = run_hardware_teleportation_experiment(token="invalid_token")
        self.assertFalse(res["success"])
        self.assertIn("Hardware execution error", res["error_message"])

    def test_no_hardcoded_credentials_in_module(self):
        """Audit hardware.py source code to confirm no hardcoded API tokens exist."""
        import core.hardware as hw_mod
        with open(hw_mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("eyJ", source)  # Common JWT prefix
        self.assertNotIn("ibm_quantum", source[:50])  # Token string check


if __name__ == "__main__":
    unittest.main()
