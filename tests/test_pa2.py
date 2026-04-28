"""
Test suite for PA #2 — Pseudorandom Functions via GGM Tree.

Verifies:
  - GGM PRF deterministic on (key, x)
  - Different inputs produce different outputs (with high probability)
  - AES_PRF deterministic and length-preserving
  - PRG from PRF (backward) deterministic and length-correct
  - PRF interface F(k, x) consistent
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa2.prf_ggm import (
    LengthDoublingPRG, GGM_PRF, AES_PRF, PRG_from_PRF, PRF,
)


class TestLengthDoublingPRG(unittest.TestCase):
    def test_lengths(self):
        prg = LengthDoublingPRG()
        seed = b"abcdefgh"
        full = prg.G(seed)
        self.assertEqual(len(full), 32, "G expands seed to 2× block size")
        self.assertEqual(prg.G0(seed) + prg.G1(seed), full,
            "G(s) must equal G0(s) || G1(s)")

    def test_deterministic(self):
        prg = LengthDoublingPRG()
        s = b"1" * 8
        self.assertEqual(prg.G(s), prg.G(s))

    def test_different_seeds(self):
        prg = LengthDoublingPRG()
        self.assertNotEqual(prg.G(b"a" * 8), prg.G(b"b" * 8))


class TestGGM_PRF(unittest.TestCase):
    def setUp(self):
        self.prf = GGM_PRF()
        self.key = b"\x01" * 16

    def test_deterministic(self):
        out1 = self.prf.evaluate(self.key, 0b1011, 4)
        out2 = self.prf.evaluate(self.key, 0b1011, 4)
        self.assertEqual(out1, out2)

    def test_distinct_inputs(self):
        # Different inputs should give different outputs (high probability for n=8)
        outputs = set()
        for x in range(256):
            outputs.add(self.prf.evaluate(self.key, x, 8))
        self.assertGreater(len(outputs), 200,
            "GGM PRF should have very few collisions on 256 distinct inputs")

    def test_path_length(self):
        # Path should have n_bits + 1 entries (root + n_bits levels)
        path = self.prf.get_path(self.key, 0b1011, n_bits=4)
        self.assertEqual(len(path), 5)


class TestAES_PRF(unittest.TestCase):
    def test_deterministic(self):
        k = b"\x01" * 16
        x = b"\x02" * 16
        self.assertEqual(AES_PRF.evaluate(k, x), AES_PRF.evaluate(k, x))

    def test_block_length(self):
        k = b"\x00" * 16
        x = b"\x00" * 16
        self.assertEqual(len(AES_PRF.evaluate(k, x)), 16)


class TestPRG_from_PRF_Backward(unittest.TestCase):
    """Backward: PRF ⇒ PRG."""

    def test_deterministic_and_length(self):
        prf = GGM_PRF()
        prg = PRG_from_PRF(prf, n_bits=8)
        seed = b"\x07" * 8
        out1 = prg.generate(seed, 64)
        out2 = prg.generate(seed, 64)
        self.assertEqual(out1, out2)
        self.assertEqual(len(out1), 64)


class TestPRF_Interface(unittest.TestCase):
    def test_interface_is_deterministic(self):
        prf = PRF(use_aes=True)
        k = b"k" * 16
        x = b"x" * 16
        self.assertEqual(prf.evaluate(k, x), prf.evaluate(k, x))


if __name__ == "__main__":
    unittest.main(verbosity=2)
