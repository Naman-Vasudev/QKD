"""
Unit tests for SHA-256 Digest and Message-to-Quantum Encoding Routines.
"""

import unittest
from qds.encoding import sha256_bits, encode_message


class TestQDSEncoding(unittest.TestCase):

    def setUp(self) -> None:
        self.key_zeros = [0] * 256
        self.key_ones = [1] * 256
        self.key_alternating = [i % 2 for i in range(256)]

    def test_sha256_properties(self) -> None:
        message = "ABC"
        digest1 = sha256_bits(message)
        digest2 = sha256_bits(message)

        # 1. Deterministic digest
        self.assertEqual(digest1, digest2)
        # 2. Exact 256 bits
        self.assertEqual(len(digest1), 256)
        # 3. Valid bit values
        self.assertTrue(all(bit in (0, 1) for bit in digest1))

        # 4. Different message -> different digest
        diff_digest = sha256_bits("ABD")
        self.assertNotEqual(digest1, diff_digest)

    def test_encoding_basis_schedule(self) -> None:
        encoded = encode_message("ABC", self.key_zeros)
        self.assertEqual(len(encoded), 256)

        for i, record in enumerate(encoded):
            rem = i % 3
            if rem == 0:
                self.assertEqual(record.basis, "Z")
            elif rem == 1:
                self.assertEqual(record.basis, "X")
            else:
                self.assertEqual(record.basis, "Y")

    def test_encoding_key_effect(self) -> None:
        encoded_zeros = encode_message("ABC", self.key_zeros)
        encoded_ones = encode_message("ABC", self.key_ones)

        for rec0, rec1 in zip(encoded_zeros, encoded_ones):
            # Key inverted -> encoded bit inverted
            self.assertEqual(rec0.encoded_bit ^ 1, rec1.encoded_bit)
            self.assertNotEqual(rec0.expected_eigenvalue, rec1.expected_eigenvalue)
            self.assertNotEqual(rec0.state_label, rec1.state_label)

    def test_invalid_key_length(self) -> None:
        with self.assertRaises(ValueError):
            encode_message("ABC", [0] * 128)

        with self.assertRaises(ValueError):
            encode_message("ABC", [0] * 255 + [2])


if __name__ == "__main__":
    unittest.main()
