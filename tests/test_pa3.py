"""
Test suite for PA #3 — CPA-Secure Symmetric Encryption.

Verifies:
  - Correctness: Dec(Enc(m)) == m for various message lengths
  - Randomized: encrypting same message twice gives different ciphertexts
  - Multi-block messages handled correctly
  - Broken deterministic variant: encrypting same message gives same CT
  - IND-CPA game: dummy random adversary has negligible advantage
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa3.cpa_enc import CPA_Enc, BrokenDeterministicEnc, IND_CPA_Game


class TestCPA_Enc_Correctness(unittest.TestCase):
    def setUp(self):
        self.enc = CPA_Enc()
        self.key = os.urandom(16)

    def test_short_message(self):
        m = b"hi"
        r, ct = self.enc.encrypt(self.key, m)
        self.assertEqual(self.enc.decrypt(self.key, r, ct), m)

    def test_exact_block(self):
        m = b"A" * 16
        r, ct = self.enc.encrypt(self.key, m)
        self.assertEqual(self.enc.decrypt(self.key, r, ct), m)

    def test_multi_block(self):
        m = b"This message spans multiple blocks of AES." * 3
        r, ct = self.enc.encrypt(self.key, m)
        self.assertEqual(self.enc.decrypt(self.key, r, ct), m)

    def test_empty_message(self):
        m = b""
        r, ct = self.enc.encrypt(self.key, m)
        self.assertEqual(self.enc.decrypt(self.key, r, ct), m)


class TestCPA_Enc_Randomized(unittest.TestCase):
    def test_same_message_different_ciphertexts(self):
        enc = CPA_Enc()
        key = os.urandom(16)
        m = b"identical plaintext!"
        r1, ct1 = enc.encrypt(key, m)
        r2, ct2 = enc.encrypt(key, m)
        # Either nonce differs, or ciphertext differs (overwhelmingly nonce)
        self.assertTrue(r1 != r2 or ct1 != ct2,
            "Randomized encryption must differ across calls")


class TestBrokenDeterministicEnc(unittest.TestCase):
    def test_deterministic_breaks_security(self):
        broken = BrokenDeterministicEnc()
        key = os.urandom(16)
        m = b"vote:Alice??????"
        r1, ct1 = broken.encrypt(key, m)
        r2, ct2 = broken.encrypt(key, m)
        self.assertEqual(ct1, ct2,
            "Broken deterministic CT should be reproducible")


class TestIND_CPA_Game(unittest.TestCase):
    def test_dummy_adversary_advantage(self):
        enc = CPA_Enc()
        game = IND_CPA_Game(enc)
        result = game.run_dummy_adversary(50)
        # Random guess advantage should be small (≤ ~0.15 with 50 rounds)
        self.assertLess(result['advantage'], 0.2,
            f"Random guesser should have small advantage, got {result['advantage']}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
