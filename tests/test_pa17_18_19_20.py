"""
Test suite for PA #17 (CCA-PKC / Signcrypt), PA #18 (OT), PA #19 (Secure AND/XOR),
PA #20 (2-Party MPC).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa17_18_19_20.mpc import (
    CCA_PKC, OT_1of2, SecureGates, SecureCircuit,
)


class TestCCA_PKC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cca = CCA_PKC(bits=128)

    def test_correctness(self):
        m = 12345
        c1, c2, sig = self.cca.encrypt(self.cca.pk, m)
        self.assertEqual(self.cca.decrypt(self.cca.sk, self.cca.pk, c1, c2, sig), m)

    def test_tampered_c2_rejected(self):
        m = 12345
        c1, c2, sig = self.cca.encrypt(self.cca.pk, m)
        # Tamper c2 — must be rejected by the signature verification
        c2_bad = (c2 + 1) % self.cca.pk[0]
        result = self.cca.decrypt(self.cca.sk, self.cca.pk, c1, c2_bad, sig)
        self.assertIsNone(result, "Tampered ciphertext must be rejected")

    def test_tampered_c1_rejected(self):
        m = 6789
        c1, c2, sig = self.cca.encrypt(self.cca.pk, m)
        c1_bad = (c1 + 1) % self.cca.pk[0]
        result = self.cca.decrypt(self.cca.sk, self.cca.pk, c1_bad, c2, sig)
        self.assertIsNone(result)


class TestOT(unittest.TestCase):
    def setUp(self):
        self.ot = OT_1of2(bits=128)

    def test_b0_gets_m0(self):
        m0, m1 = 111, 222
        pk0, pk1, st = self.ot.receiver_step1(0)
        c0, c1 = self.ot.sender_step(pk0, pk1, m0, m1)
        self.assertEqual(self.ot.receiver_step2(st, c0, c1), m0)

    def test_b1_gets_m1(self):
        m0, m1 = 333, 444
        pk0, pk1, st = self.ot.receiver_step1(1)
        c0, c1 = self.ot.sender_step(pk0, pk1, m0, m1)
        self.assertEqual(self.ot.receiver_step2(st, c0, c1), m1)

    def test_many_runs(self):
        # 20 runs with random b
        import random
        for _ in range(20):
            b = random.choice([0, 1])
            m0, m1 = random.randint(1, 1000), random.randint(1, 1000)
            pk0, pk1, st = self.ot.receiver_step1(b)
            c0, c1 = self.ot.sender_step(pk0, pk1, m0, m1)
            got = self.ot.receiver_step2(st, c0, c1)
            self.assertEqual(got, m0 if b == 0 else m1)


class TestSecureGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g = SecureGates(bits=128)

    def test_AND_truth_table(self):
        for a in (0, 1):
            for b in (0, 1):
                self.assertEqual(self.g.AND(a, b), a & b,
                    f"AND({a},{b}) failed")

    def test_XOR_truth_table(self):
        for a in (0, 1):
            for b in (0, 1):
                self.assertEqual(self.g.XOR(a, b), a ^ b)

    def test_NOT(self):
        self.assertEqual(self.g.NOT(0), 1)
        self.assertEqual(self.g.NOT(1), 0)


class TestSecureCircuit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gates = SecureGates(bits=128)
        cls.circuit = SecureCircuit(cls.gates)

    def test_millionaires_richer(self):
        # 4-bit (0..15) values
        for a, b in [(7, 12), (15, 3), (0, 0), (5, 5), (8, 9), (10, 1)]:
            r = self.circuit.millionaires(a, b)
            expected = "Alice richer" if a > b else ("Bob richer" if b > a else "Equal")
            self.assertEqual(r, expected, f"millionaires({a},{b}) wrong")

    def test_secure_equality(self):
        for a in range(0, 16, 2):
            for b in range(0, 16, 3):
                self.assertEqual(bool(self.circuit.secure_equality(a, b, bits=4)), a == b)

    def test_secure_addition(self):
        for a in [0, 1, 5, 9, 15]:
            for b in [0, 1, 8, 14]:
                self.assertEqual(
                    self.circuit.secure_add(a, b, bits=4),
                    (a + b) % 16,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
