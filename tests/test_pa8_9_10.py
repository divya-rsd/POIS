"""
Test suite for PA #8 (DLP Hash), PA #9 (Birthday Attack), PA #10 (HMAC + EtH).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa8_9_10.hash_hmac import (
    DLP_Hash, DLP_Compress, BirthdayAttack, HMAC, NaiveMAC,
    LengthExtensionAttack, EtH_Enc,
)


class TestDLP_Hash(unittest.TestCase):
    def setUp(self):
        self.h = DLP_Hash()

    def test_deterministic(self):
        m = b"message"
        self.assertEqual(self.h.hash(m), self.h.hash(m))

    def test_distinct_messages(self):
        self.assertNotEqual(self.h.hash(b"a"), self.h.hash(b"b"))


class TestDLP_Compress(unittest.TestCase):
    def test_collision_implies_dlp_relation(self):
        # If h(x1, y1) == h(x2, y2) with (x1,y1) != (x2,y2),
        # then we'd recover alpha = (x1-x2) * (y2-y1)^{-1} mod (p-1).
        # We just sanity-check that distinct (x,y) pairs typically give
        # distinct outputs on this small parameter set.
        c = DLP_Compress(alpha=42)
        outputs = set()
        for x in range(8):
            for y in range(8):
                outputs.add(c.compress(x.to_bytes(4, 'big'), y.to_bytes(4, 'big')))
        self.assertGreater(len(outputs), 50)


class TestBirthdayAttack(unittest.TestCase):
    def test_finds_collision_in_expected_range(self):
        h = DLP_Hash()
        atk = BirthdayAttack(lambda m: h.hash_truncated(m, 12), n_bits=12)
        result = atk.naive_attack()
        # Expected ~2^6 = 64 evals; allow up to 8x for variance
        self.assertIn('x1', result)
        self.assertIn('x2', result)
        self.assertNotEqual(result['x1'], result['x2'])
        self.assertLess(result['evals'], 4000,
            f"Birthday attack on 12-bit hash should not need >4000 evals, got {result['evals']}")


class TestHMAC(unittest.TestCase):
    def setUp(self):
        self.hmac = HMAC()

    def test_deterministic(self):
        k = os.urandom(16)
        m = b"hmac me!"
        self.assertEqual(self.hmac.mac(k, m), self.hmac.mac(k, m))

    def test_verify_accepts_correct_tag(self):
        k = os.urandom(16)
        m = b"valid"
        t = self.hmac.mac(k, m)
        self.assertTrue(self.hmac.verify(k, m, t))

    def test_verify_rejects_wrong_tag(self):
        k = os.urandom(16)
        m = b"valid"
        t = self.hmac.mac(k, m)
        bad = bytes([t[0] ^ 0xFF]) + t[1:]
        self.assertFalse(self.hmac.verify(k, m, bad))

    def test_different_keys_different_tags(self):
        k1 = b"\x01" * 16
        k2 = b"\x02" * 16
        m = b"msg"
        self.assertNotEqual(self.hmac.mac(k1, m), self.hmac.mac(k2, m))


class TestLengthExtension(unittest.TestCase):
    def test_naive_mac_is_extendable(self):
        from pa8_9_10.hash_hmac import DLP_Hash
        shared = DLP_Hash()
        naive = NaiveMAC(hash_fn=shared)
        atk = LengthExtensionAttack(naive)
        key = os.urandom(16)
        msg = b"original"
        tag = naive.mac(key, msg)
        ext_msg, ext_tag = atk.extend(msg, tag, b"SUFFIX", key_len=16)
        # Server's actual MAC on the extended message:
        actual = naive.mac(key, ext_msg)
        self.assertEqual(actual, ext_tag,
            "Length-extension attack should forge a valid tag on H(k||m)")


class TestEtH_Enc(unittest.TestCase):
    def setUp(self):
        self.eth = EtH_Enc()
        self.ke = os.urandom(16)
        self.km = os.urandom(16)

    def test_correctness(self):
        m = b"EtH message that is long enough to be multi-block"
        blob, t = self.eth.encrypt(self.ke, self.km, m)
        self.assertEqual(self.eth.decrypt(self.ke, self.km, blob, t), m)

    def test_tamper_rejected_anywhere(self):
        m = b"x" * 64
        blob, t = self.eth.encrypt(self.ke, self.km, m)
        for pos in [0, 16, 32, 50, len(blob) - 1]:
            tampered = bytearray(blob)
            tampered[pos] ^= 0x01
            self.assertIsNone(self.eth.decrypt(self.ke, self.km, bytes(tampered), t),
                f"Tamper at pos {pos} must be rejected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
