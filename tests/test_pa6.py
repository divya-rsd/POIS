"""
Test suite for PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC).

Critical: must catch tampering ANYWHERE in the ciphertext, not just the first block.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa6.cca_enc import CCA_Enc


class TestCCAEnc(unittest.TestCase):
    def setUp(self):
        self.enc = CCA_Enc()
        self.ke = os.urandom(16)
        self.km = os.urandom(16)

    def test_correctness(self):
        m = b"CCA secure please"
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        self.assertEqual(self.enc.decrypt(self.ke, self.km, blob, t), m)

    def test_correctness_long(self):
        m = b"long message that spans multiple blocks " * 5
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        self.assertEqual(self.enc.decrypt(self.ke, self.km, blob, t), m)

    def test_tamper_in_first_block(self):
        m = b"important message"
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        tampered = bytearray(blob)
        tampered[0] ^= 0xFF
        result = self.enc.decrypt(self.ke, self.km, bytes(tampered), t)
        self.assertIsNone(result, "Tampering byte 0 must be detected")

    def test_tamper_in_ciphertext_block(self):
        # CRITICAL: the bug we're hunting — CCA must reject tampering ANY byte,
        # including bytes beyond the first MAC-block (which the buggy PRF-MAC
        # truncation-style implementation would miss).
        m = b"long message that spans multiple blocks " * 3
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        tampered = bytearray(blob)
        # Tamper a byte that is in the middle of the ciphertext
        tampered[40] ^= 0xFF
        result = self.enc.decrypt(self.ke, self.km, bytes(tampered), t)
        self.assertIsNone(result,
            "CCA scheme must reject tampering ANYWHERE in the blob, not just first 16 bytes")

    def test_tamper_in_last_block(self):
        m = b"x" * 100
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        result = self.enc.decrypt(self.ke, self.km, bytes(tampered), t)
        self.assertIsNone(result, "Tampering last byte must be detected")

    def test_tamper_tag(self):
        m = b"some msg"
        blob, t = self.enc.encrypt(self.ke, self.km, m)
        bad_t = bytes([t[0] ^ 0xFF]) + t[1:]
        result = self.enc.decrypt(self.ke, self.km, blob, bad_t)
        self.assertIsNone(result, "Tag tampering must be detected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
