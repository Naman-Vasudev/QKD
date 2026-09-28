"""
Unit Test Suite for Entanglement-Based Quantum Key Distribution (BBM92).

Checks the two properties that make the protocol meaningful:
  - an honest channel yields perfectly correlated keys (QBER = 0 on an ideal simulator),
  - an intercept-resend eavesdropper is exposed by an elevated QBER.
"""

import unittest

from qds.keydist import (
    ALL_QKD_BASES,
    DEFAULT_QKD_BASES,
    build_bell_pair_measurement_circuit,
    establish_signing_key,
    run_key_distribution,
)


class TestBellPairCircuit(unittest.TestCase):

    def test_1_circuit_shape_without_eve(self) -> None:
        qc = build_bell_pair_measurement_circuit("Z", "Z")
        self.assertEqual(qc.num_qubits, 2)
        self.assertEqual(len(qc.cregs), 2)

    def test_2_circuit_shape_with_eve(self) -> None:
        qc = build_bell_pair_measurement_circuit("Z", "Z", eve_basis="X")
        self.assertEqual(qc.num_qubits, 2)
        self.assertEqual(len(qc.cregs), 3)
        # Eve's interception requires a reset to model resending a fresh qubit.
        self.assertIn("reset", {inst.operation.name for inst in qc.data})


class TestHonestChannel(unittest.TestCase):

    def test_1_two_basis_honest_qber_is_zero(self) -> None:
        result = run_key_distribution(
            raw_bits=400, eavesdropper_present=False,
            qber_sample_fraction=0.5, seed=17,
        )
        self.assertEqual(result.qber_errors, 0)
        self.assertEqual(result.qber, 0.0)
        self.assertFalse(result.threat_result.threat_detected)

    def test_2_three_basis_honest_qber_is_zero(self) -> None:
        # Exercises the Y-basis anti-correlation correction: |Phi+> has <YY> = -1, so a
        # missing bit flip here would show up as ~100% QBER on Y-sifted positions.
        result = run_key_distribution(
            raw_bits=600, bases=ALL_QKD_BASES, eavesdropper_present=False,
            qber_sample_fraction=0.5, seed=19,
        )
        self.assertEqual(result.qber_errors, 0)
        self.assertEqual(result.qber, 0.0)

    def test_3_sifting_keeps_roughly_one_over_b(self) -> None:
        raw = 900
        result = run_key_distribution(
            raw_bits=raw, bases=DEFAULT_QKD_BASES,
            eavesdropper_present=False, seed=23,
        )
        # Two bases -> about half the positions survive reconciliation.
        self.assertGreater(result.sifted_length, raw * 0.35)
        self.assertLess(result.sifted_length, raw * 0.65)

    def test_4_disclosed_sample_is_excluded_from_the_key(self) -> None:
        result = run_key_distribution(
            raw_bits=400, eavesdropper_present=False,
            qber_sample_fraction=0.25, target_key_length=None, seed=29,
        )
        self.assertEqual(
            len(result.key_bits), result.sifted_length - result.sample_size
        )

    def test_5_key_bits_are_binary(self) -> None:
        result = run_key_distribution(raw_bits=300, eavesdropper_present=False, seed=31)
        self.assertTrue(all(bit in (0, 1) for bit in result.key_bits))


class TestEavesdropperDetection(unittest.TestCase):

    def test_1_two_basis_qber_approaches_one_quarter(self) -> None:
        # Textbook BB84/BBM92: intercept-resend on 2 bases gives QBER = 25%.
        result = run_key_distribution(
            raw_bits=3000, bases=DEFAULT_QKD_BASES, eavesdropper_present=True,
            qber_sample_fraction=0.5, seed=37,
        )
        self.assertGreater(result.sample_size, 300)
        self.assertAlmostEqual(result.qber, 0.25, delta=0.06)
        self.assertTrue(result.threat_result.threat_detected)

    def test_2_three_basis_qber_approaches_one_third(self) -> None:
        # With 3 bases Eve guesses right only 1/3 of the time: QBER = (1 - 1/3)/2 = 1/3.
        result = run_key_distribution(
            raw_bits=4000, bases=ALL_QKD_BASES, eavesdropper_present=True,
            qber_sample_fraction=0.5, seed=41,
        )
        self.assertAlmostEqual(result.qber, 1.0 / 3.0, delta=0.07)
        self.assertTrue(result.threat_result.threat_detected)

    def test_3_eavesdropper_qber_exceeds_honest_qber(self) -> None:
        honest = run_key_distribution(
            raw_bits=1200, eavesdropper_present=False,
            qber_sample_fraction=0.5, seed=43,
        )
        tapped = run_key_distribution(
            raw_bits=1200, eavesdropper_present=True,
            qber_sample_fraction=0.5, seed=43,
        )
        self.assertGreater(tapped.qber, honest.qber)


class TestKeyEstablishment(unittest.TestCase):

    def test_1_establishes_exact_length(self) -> None:
        key, result = establish_signing_key(key_length=256, seed=47)
        self.assertEqual(len(key), 256)
        self.assertTrue(all(bit in (0, 1) for bit in key))
        self.assertEqual(result.qber, 0.0)

    def test_2_key_is_not_degenerate(self) -> None:
        key, _ = establish_signing_key(key_length=256, seed=53)
        density = sum(key) / len(key)
        # A measured key must be roughly balanced; this is exactly what the old
        # hardcoded 0101... default failed to be in any meaningful sense.
        self.assertGreater(density, 0.3)
        self.assertLess(density, 0.7)
        self.assertGreater(len(set(key)), 1)

    def test_3_reproducible_under_seed(self) -> None:
        first, _ = establish_signing_key(key_length=64, seed=59)
        second, _ = establish_signing_key(key_length=64, seed=59)
        self.assertEqual(first, second)

    def test_4_different_seeds_give_different_keys(self) -> None:
        first, _ = establish_signing_key(key_length=64, seed=61)
        second, _ = establish_signing_key(key_length=64, seed=67)
        self.assertNotEqual(first, second)

    def test_5_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            establish_signing_key(key_length=0)
        with self.assertRaises(ValueError):
            run_key_distribution(raw_bits=0)
        with self.assertRaises(ValueError):
            run_key_distribution(raw_bits=100, bases=())
        with self.assertRaises(ValueError):
            run_key_distribution(raw_bits=100, bases=("W",))
        with self.assertRaises(ValueError):
            run_key_distribution(raw_bits=100, qber_sample_fraction=1.0)


if __name__ == "__main__":
    unittest.main()
