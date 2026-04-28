"""
Test suite for PA #1 — One-Way Functions & Pseudorandom Generators.

Verifies:
  - OWF DLP correctness (deterministic, in-group)
  - OWF AES Davies-Meyer correctness
  - PRG from OWF produces requested length, deterministic on same seed
  - Different seeds give different output
  - PRG output passes basic statistical sanity (≈50/50 ones)
  - Bidirectional: f(s)=G(s) (PRG ⇒ OWF)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa1.owf_prg import (
    AES128, OWF_DLP, OWF_AES, PRG_from_OWF, OWF_from_PRG,
    StatisticalTests, mod_exp, miller_rabin_is_prime,
)


class TestAES128(unittest.TestCase):
    def test_known_vector(self):
        # FIPS-197 known test: key = 16 zero bytes, plaintext = 16 zero bytes
        key = bytes(16)
        pt = bytes(16)
        ct = AES128.encrypt_block(key, pt)
        # Expected ciphertext for AES-128(0, 0):
        expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
        self.assertEqual(ct, expected,
            "AES-128 should match the FIPS-197 known answer for all-zero key/plaintext")

    def test_block_size(self):
        ct = AES128.encrypt_block(b"k" * 16, b"p" * 16)
        self.assertEqual(len(ct), 16)


class TestOWF_DLP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owf = OWF_DLP(prime_bits=64)

    def test_deterministic(self):
        x = 12345
        self.assertEqual(self.owf.evaluate(x), self.owf.evaluate(x))

    def test_in_group(self):
        # f(x) must lie in [1, p-1] and be in the order-q subgroup
        for x in [1, 2, 100, self.owf.q - 1]:
            y = self.owf.evaluate(x)
            self.assertGreater(y, 0)
            self.assertLess(y, self.owf.p)
            # y^q mod p == 1 (order-q subgroup)
            self.assertEqual(mod_exp(y, self.owf.q, self.owf.p), 1)

    def test_safe_prime(self):
        self.assertTrue(miller_rabin_is_prime(self.owf.p))
        self.assertTrue(miller_rabin_is_prime(self.owf.q))
        self.assertEqual(self.owf.p, 2 * self.owf.q + 1)


class TestOWF_AES(unittest.TestCase):
    def test_deterministic_and_length(self):
        owf = OWF_AES()
        k = b"\x01" * 16
        y1 = owf.evaluate(k)
        y2 = owf.evaluate(k)
        self.assertEqual(y1, y2)
        self.assertEqual(len(y1), 16)

    def test_different_keys_give_different_outputs(self):
        owf = OWF_AES()
        y1 = owf.evaluate(b"\x01" * 16)
        y2 = owf.evaluate(b"\x02" * 16)
        self.assertNotEqual(y1, y2)


class TestPRG_from_OWF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owf = OWF_DLP(prime_bits=48)
        cls.prg = PRG_from_OWF(cls.owf)

    def test_deterministic(self):
        out1 = self.prg.generate(42, 64)
        out2 = self.prg.generate(42, 64)
        self.assertEqual(out1, out2,
            "PRG must be deterministic on the same seed")

    def test_different_seeds_diverge(self):
        out1 = self.prg.generate(42, 64)
        out2 = self.prg.generate(43, 64)
        self.assertNotEqual(out1, out2)

    def test_correct_length(self):
        for n in (8, 16, 64, 128, 200):
            out = self.prg.generate(7, n)
            self.assertEqual(len(out) * 8, ((n + 7) // 8) * 8)

    def test_balanced_ones(self):
        # PRG over 1024 bits should be near 50/50 ones (sanity not security)
        out = self.prg.generate(99, 1024)
        ones = sum(bin(b).count("1") for b in out)
        ratio = ones / (len(out) * 8)
        self.assertGreater(ratio, 0.30,
            f"PRG output too few ones ({ratio:.3f}); something is biased.")
        self.assertLess(ratio, 0.70,
            f"PRG output too many ones ({ratio:.3f}); something is biased.")


class TestStatisticalTests(unittest.TestCase):
    def test_freq_pass_for_balanced_data(self):
        # 50/50 alternating bits
        data = bytes([0xAA] * 256)  # 10101010 pattern
        r = StatisticalTests.frequency_monobit(data)
        self.assertTrue(r['pass'])

    def test_freq_fail_for_all_ones(self):
        data = bytes([0xFF] * 256)
        r = StatisticalTests.frequency_monobit(data)
        self.assertFalse(r['pass'])


class TestPRG_to_OWF_Backward(unittest.TestCase):
    """Bidirectional: PRG ⇒ OWF (define f(s) = G(s))."""

    def test_owf_is_deterministic(self):
        owf = OWF_DLP(prime_bits=48)
        prg = PRG_from_OWF(owf)
        f = OWF_from_PRG(prg, output_bits=64)
        s = 12345
        y1 = f.evaluate(s)
        y2 = f.evaluate(s)
        self.assertEqual(y1, y2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
