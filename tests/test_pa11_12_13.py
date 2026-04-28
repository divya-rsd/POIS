"""
Test suite for PA #11 (Diffie-Hellman), PA #12 (RSA + PKCS#1 v1.5),
PA #13 (Miller-Rabin Primality Testing).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa13.primality import miller_rabin, is_prime, gen_prime, gen_safe_prime, _mod_exp
from pa12.rsa import RSA, RSA_PKCS15, _mod_inverse
from pa11.dh import DH


class TestMillerRabin(unittest.TestCase):
    def test_small_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 7919, 104729]:
            self.assertTrue(is_prime(p), f"{p} should be prime")

    def test_small_composites(self):
        for n in [4, 6, 8, 9, 10, 15, 21, 25, 27, 100]:
            self.assertFalse(is_prime(n), f"{n} should be composite")

    def test_carmichael_561(self):
        # 561 fools Fermat but Miller-Rabin should reject
        self.assertFalse(miller_rabin(561, 40))

    def test_other_carmichael_numbers(self):
        for n in [1105, 1729, 2465, 2821, 6601]:
            self.assertFalse(miller_rabin(n, 40),
                f"Carmichael {n} should be rejected by Miller-Rabin")

    def test_gen_prime_correct_bit_length(self):
        for bits in [64, 128, 256]:
            p = gen_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_prime(p))

    def test_gen_safe_prime(self):
        p, q = gen_safe_prime(128)
        self.assertTrue(is_prime(p))
        self.assertTrue(is_prime(q))
        self.assertEqual(p, 2 * q + 1)


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA(bits=512)

    def test_correctness(self):
        for m in [0, 1, 2, 42, 12345, self.rsa.N - 1]:
            c = self.rsa.encrypt(m)
            self.assertEqual(self.rsa.decrypt(c), m, f"Decrypt failed for m={m}")

    def test_crt_decrypt_matches(self):
        m = 12345
        c = self.rsa.encrypt(m)
        self.assertEqual(self.rsa.decrypt_crt(c), m)

    def test_textbook_is_deterministic(self):
        m = 1234
        self.assertEqual(self.rsa.encrypt(m), self.rsa.encrypt(m))

    def test_modulus_bits(self):
        # ~512 bits ± 1 (bits//2 + bits//2)
        self.assertGreaterEqual(self.rsa.N.bit_length(), 510)
        self.assertLessEqual(self.rsa.N.bit_length(), 514)


class TestRSAPKCS15(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA(bits=512)
        cls.pkcs = RSA_PKCS15(cls.rsa)

    def test_correctness(self):
        m = b"hello padding"
        c = cls.pkcs.encrypt(m) if False else self.pkcs.encrypt(m)
        self.assertEqual(self.pkcs.decrypt(c), m)

    def test_randomized(self):
        m = b"same"
        c1 = self.pkcs.encrypt(m)
        c2 = self.pkcs.encrypt(m)
        self.assertNotEqual(c1, c2,
            "PKCS#1 v1.5 must produce different ciphertexts for the same plaintext")

    def test_decrypts_to_original(self):
        for m in [b"a", b"longer message", b"x" * 50]:
            c = self.pkcs.encrypt(m)
            self.assertEqual(self.pkcs.decrypt(c), m)


class TestModInverse(unittest.TestCase):
    def test_inverse_correctness(self):
        for a, m in [(3, 7), (5, 11), (7, 13), (17, 23)]:
            inv = _mod_inverse(a, m)
            self.assertEqual((a * inv) % m, 1)


class TestDH(unittest.TestCase):
    def test_keys_match(self):
        dh = DH(bits=128)
        a, A = dh.alice_step1()
        b, B = dh.bob_step1()
        Ka = dh.alice_step2(a, B)
        Kb = dh.bob_step2(b, A)
        self.assertEqual(Ka, Kb, "Diffie-Hellman shared keys must match")

    def test_different_runs_different_keys(self):
        dh = DH(bits=128)
        a1, A1 = dh.alice_step1()
        a2, A2 = dh.alice_step1()
        # Random exponents should differ
        self.assertNotEqual(a1, a2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
