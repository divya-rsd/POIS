"""
Test suite for PA #7 — Merkle-Damgård Transform.

Verifies:
  - MD-strengthening padding ends with a 64-bit length field
  - Padded length is a multiple of block size
  - Hash is deterministic
  - Distinct messages give distinct hashes (no trivial collisions)
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa7.merkle_damgard import MerkleDamgard, md_pad, BLOCK_SIZE


class TestMDPadding(unittest.TestCase):
    def test_padded_length_is_multiple_of_block_size(self):
        for n in [0, 1, 5, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, 100]:
            padded = md_pad(b"x" * n)
            self.assertEqual(len(padded) % BLOCK_SIZE, 0,
                f"Padded length not block-aligned for input size {n}")

    def test_padding_starts_with_0x80(self):
        padded = md_pad(b"hi")
        self.assertEqual(padded[2], 0x80)

    def test_length_field_is_correct(self):
        msg = b"hello world"
        padded = md_pad(msg)
        # Last 8 bytes are big-endian bit-length
        length_field = struct.unpack('>Q', padded[-8:])[0]
        self.assertEqual(length_field, len(msg) * 8)


class TestMerkleDamgard(unittest.TestCase):
    def setUp(self):
        self.md = MerkleDamgard()

    def test_deterministic(self):
        m = b"some message"
        self.assertEqual(self.md.hash(m), self.md.hash(m))

    def test_distinct_messages(self):
        # Without a length field these would collide:
        h1 = self.md.hash(b"abc")
        h2 = self.md.hash(b"abcd")
        self.assertNotEqual(h1, h2,
            "MD with length-strengthening must distinguish prefixes")

    def test_handles_empty(self):
        # Empty must still hash without crashing
        h = self.md.hash(b"")
        self.assertEqual(len(h), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
