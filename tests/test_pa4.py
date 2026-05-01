"""
Test suite for PA #4 — Modes of Operation (CBC / OFB / CTR).

Verifies:
  - Correctness for CBC, OFB, CTR across all message lengths
  - Randomized IV/nonce produces different ciphertexts on identical plaintexts
  - Decrypt(Encrypt(m)) == m
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa4.modes import Modes, CBC, OFB, CTR


class TestModesCorrectness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modes = Modes()
        cls.key = os.urandom(16)

    def _check_roundtrip(self, mode, msg):
        enc = self.modes.encrypt(mode, self.key, msg)
        dec = self.modes.decrypt(mode, self.key, enc)
        self.assertEqual(dec, msg, f"{mode} roundtrip failed for len={len(msg)}")

    def test_cbc_short(self):
        self._check_roundtrip('CBC', b"hi")
    def test_cbc_exact(self):
        self._check_roundtrip('CBC', b"A" * 16)
    def test_cbc_multi(self):
        self._check_roundtrip('CBC', b"Multi block message here!" * 4)

    def test_ofb_short(self):
        self._check_roundtrip('OFB', b"hi")
    def test_ofb_exact(self):
        self._check_roundtrip('OFB', b"A" * 16)
    def test_ofb_multi(self):
        self._check_roundtrip('OFB', b"Multi block message here!" * 4)

    def test_ctr_short(self):
        self._check_roundtrip('CTR', b"hi")
    def test_ctr_exact(self):
        self._check_roundtrip('CTR', b"A" * 16)
    def test_ctr_multi(self):
        self._check_roundtrip('CTR', b"Multi block message here!" * 4)


class TestModesRandomization(unittest.TestCase):
    """Each call to encrypt should produce different ciphertext for same plaintext."""

    def setUp(self):
        self.m = Modes()
        self.key = os.urandom(16)
        self.msg = b"same plaintext bytes!"

    def test_cbc_random_iv(self):
        ct1 = self.m.encrypt('CBC', self.key, self.msg)
        ct2 = self.m.encrypt('CBC', self.key, self.msg)
        self.assertNotEqual(ct1['iv'], ct2['iv'])

    def test_ofb_random_iv(self):
        ct1 = self.m.encrypt('OFB', self.key, self.msg)
        ct2 = self.m.encrypt('OFB', self.key, self.msg)
        self.assertNotEqual(ct1['iv'], ct2['iv'])

    def test_ctr_random_nonce(self):
        ct1 = self.m.encrypt('CTR', self.key, self.msg)
        ct2 = self.m.encrypt('CTR', self.key, self.msg)
        self.assertNotEqual(ct1['r'], ct2['r'])


class TestModesUnifiedAPI(unittest.TestCase):
    def test_invalid_mode_returns_none(self):
        m = Modes()
        result = m.encrypt('UNKNOWN', os.urandom(16), b"x")
        # Invalid mode falls through and returns None - acceptable
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
