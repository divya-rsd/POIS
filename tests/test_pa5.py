"""
Test suite for PA #5 — Message Authentication Codes.

Verifies:
  - PRF-MAC correctness on one-block messages
  - CBC-MAC correctness for variable-length messages
  - CBC-MAC distinguishes different messages (no truncation collision!)
  - Verify rejects tampered tags
  - EUF-CMA: random fake tags do not pass verification
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa5.mac import PRF_MAC, CBC_MAC, EUF_CMA_Game


class TestPRF_MAC(unittest.TestCase):
    def setUp(self):
        self.mac = PRF_MAC()
        self.key = os.urandom(16)

    def test_verify_correct_tag(self):
        m = b"one block msg!! "  # 16 bytes (one block)
        t = self.mac.mac(self.key, m)
        self.assertTrue(self.mac.verify(self.key, m, t))

    def test_verify_wrong_tag(self):
        m = b"one block msg!! "
        t = self.mac.mac(self.key, m)
        bad = bytes([t[0] ^ 0xFF]) + t[1:]
        self.assertFalse(self.mac.verify(self.key, m, bad))


class TestCBC_MAC(unittest.TestCase):
    def setUp(self):
        self.mac = CBC_MAC()
        self.key = os.urandom(16)

    def test_correct_verify(self):
        m = b"some variable length message that spans many blocks here today."
        t = self.mac.mac(self.key, m)
        self.assertTrue(self.mac.verify(self.key, m, t))

    def test_different_messages_different_tags(self):
        # Crucial: CBC-MAC must NOT produce same tag for different messages
        # whose first 16 bytes are identical
        prefix = b"AAAAAAAAAAAAAAAA"  # 16 bytes
        m1 = prefix + b"one"
        m2 = prefix + b"two"
        t1 = self.mac.mac(self.key, m1)
        t2 = self.mac.mac(self.key, m2)
        self.assertNotEqual(t1, t2,
            "CBC-MAC must distinguish messages that differ after the first block")

    def test_modified_message_fails_verify(self):
        m = b"original message bytes here"
        t = self.mac.mac(self.key, m)
        self.assertFalse(self.mac.verify(self.key, b"modified message bytes!!", t))


class TestEUF_CMA_Game(unittest.TestCase):
    def test_random_forgeries_rejected(self):
        mac = PRF_MAC()
        game = EUF_CMA_Game(mac)
        # Pre-populate with signed messages
        for i in range(50):
            game.sign(f"signed_{i}".encode())
        # Try 100 random forgeries on a never-seen message
        successes = 0
        for _ in range(100):
            ok, _ = game.submit_forgery(b"never_seen_!!", os.urandom(16))
            if ok:
                successes += 1
        self.assertEqual(successes, 0,
            f"Random forgeries should not succeed; got {successes}/100")


if __name__ == "__main__":
    unittest.main(verbosity=2)
