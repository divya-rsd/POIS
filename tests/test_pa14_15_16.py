"""
Test suite for PA #14 (CRT + Håstad), PA #15 (Digital Signatures), PA #16 (ElGamal).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa14_15_16.crt_sig_elgamal import (
    crt, integer_nth_root, hastad_attack, RSA_Sign, ElGamal,
)
from pa12.rsa import RSA, _fast_pow


class TestCRT(unittest.TestCase):
    def test_basic_textbook(self):
        # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) -> x = 23
        self.assertEqual(crt([2, 3, 2], [3, 5, 7]), 23)

    def test_two_moduli(self):
        # x ≡ 1 (mod 4), x ≡ 2 (mod 9) -> x = 29
        self.assertEqual(crt([1, 2], [4, 9]), 29)

    def test_satisfies_all_congruences(self):
        residues = [3, 4, 5]
        moduli = [11, 13, 17]
        x = crt(residues, moduli)
        for a, m in zip(residues, moduli):
            self.assertEqual(x % m, a)


class TestIntegerNthRoot(unittest.TestCase):
    def test_perfect_cubes(self):
        for n in [8, 27, 1000, 42**3, 99999**3]:
            k = 3
            r = integer_nth_root(n, k)
            self.assertEqual(r ** k, n, f"Cube root failed for {n}")


class TestHastadBroadcast(unittest.TestCase):
    def test_recovers_message(self):
        # Generate three RSA moduli with e=3 manually
        rsas = [RSA(bits=256) for _ in range(3)]
        m = 42
        cts = [_fast_pow(m, 3, r.N) for r in rsas]
        mods = [r.N for r in rsas]
        recovered = hastad_attack(cts, mods, e=3)
        self.assertEqual(recovered, m, "Håstad attack should recover the plaintext")


class TestRSASign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = RSA(bits=512)
        cls.signer = RSA_Sign(cls.rsa)

    def test_verify_valid_signature(self):
        m = b"sign me"
        sig = self.signer.sign(m)
        self.assertTrue(self.signer.verify(m, sig))

    def test_verify_rejects_tampered_message(self):
        m = b"original"
        sig = self.signer.sign(m)
        self.assertFalse(self.signer.verify(b"tampered", sig))

    def test_verify_rejects_random_signature(self):
        m = b"original"
        self.assertFalse(self.signer.verify(m, 12345))


class TestElGamal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eg = ElGamal(bits=128)

    def test_correctness(self):
        keys = self.eg.keygen()
        sk, pk = keys['sk'], keys['pk']
        for m in [1, 2, 100, 12345]:
            c1, c2 = self.eg.encrypt(pk, m)
            self.assertEqual(self.eg.decrypt(sk, pk, c1, c2), m)

    def test_randomized(self):
        keys = self.eg.keygen()
        c1a, c2a = self.eg.encrypt(keys['pk'], 42)
        c1b, c2b = self.eg.encrypt(keys['pk'], 42)
        # ElGamal is randomized: ciphertexts differ even for same plaintext
        self.assertTrue(c1a != c1b or c2a != c2b)

    def test_malleability(self):
        keys = self.eg.keygen()
        sk, pk = keys['sk'], keys['pk']
        m = 100
        c1, c2 = self.eg.encrypt(pk, m)
        c1m, c2m = self.eg.malleability_demo(pk, c1, c2)
        # Decrypts to 2m
        self.assertEqual(self.eg.decrypt(sk, pk, c1m, c2m), 2 * m)


if __name__ == "__main__":
    unittest.main(verbosity=2)
