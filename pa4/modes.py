"""PA #4 — Modes of Operation (CBC / OFB / CTR).

CBC follows the spec exactly:  C_i = E_k(C_{i-1} XOR M_i),  C_0 = IV.
Decryption requires the inverse cipher, so this module uses AES128.encrypt_block
and AES128.decrypt_block (true PRP) — not just the forward PRF.

OFB and CTR remain stream-cipher modes that need only the forward direction.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa1.owf_prg import AES128

BLOCK = 16


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(d, bs=BLOCK):
    """PKCS#7 padding."""
    n = bs - len(d) % bs
    return d + bytes([n] * n)


def _unpad(d):
    n = d[-1]
    if n < 1 or n > BLOCK:
        raise ValueError(f"Invalid padding byte {n}")
    if d[-n:] != bytes([n] * n):
        raise ValueError("Padding bytes inconsistent")
    return d[:-n]


def _int_block(n):
    return n.to_bytes(BLOCK, 'big')


def _block_int(b):
    return int.from_bytes(b, 'big')


def _enc(key, block):
    return AES128.encrypt_block(key, block)


def _dec(key, block):
    return AES128.decrypt_block(key, block)


# ─────────────── CBC (true Cipher Block Chaining) ───────────────
class CBC:
    """C_i = E_k(C_{i-1} XOR M_i),  C_0 = IV.

    Decryption: M_i = D_k(C_i) XOR C_{i-1} — needs AES decrypt.
    """

    def encrypt(self, key, iv, msg):
        p = _pad(msg)
        prev = iv
        ct = b''
        for i in range(len(p) // BLOCK):
            blk = p[i * BLOCK:(i + 1) * BLOCK]
            cb = _enc(key, _xor(prev, blk))
            ct += cb
            prev = cb
        return ct

    def decrypt(self, key, iv, ct):
        prev = iv
        pt = b''
        for i in range(len(ct) // BLOCK):
            blk = ct[i * BLOCK:(i + 1) * BLOCK]
            pt += _xor(_dec(key, blk), prev)
            prev = blk
        return _unpad(pt)


# ─────────────── OFB (Output Feedback) ───────────────
class OFB:
    """O_0 = E_k(IV); O_i = E_k(O_{i-1}); keystream = O_0 || O_1 || ...

    Encryption and decryption are the same operation (XOR with keystream).
    """

    def _ks(self, key, iv, n_blocks):
        ks = b''
        s = iv
        for _ in range(n_blocks):
            s = _enc(key, s)
            ks += s
        return ks

    def encrypt(self, key, iv, msg):
        p = _pad(msg)
        ks = self._ks(key, iv, len(p) // BLOCK)
        return _xor(p, ks)

    def decrypt(self, key, iv, ct):
        # ct length is always a multiple of BLOCK because encrypt padded.
        if len(ct) % BLOCK != 0:
            raise ValueError("OFB ciphertext must be a multiple of BLOCK")
        ks = self._ks(key, iv, len(ct) // BLOCK)
        return _unpad(_xor(ct, ks))


# ─────────────── CTR (Randomized Counter) ───────────────
class CTR:
    """C_i = M_i XOR E_k(r + i mod 2^128) where r is a fresh random nonce."""

    def encrypt(self, key, msg):
        r = os.urandom(BLOCK)
        p = _pad(msg)
        ct = b''
        r_int = _block_int(r)
        for i in range(len(p) // BLOCK):
            ctr = _int_block((r_int + i) % (2 ** 128))
            ct += _xor(_enc(key, ctr), p[i * BLOCK:(i + 1) * BLOCK])
        return r, ct

    def decrypt(self, key, r, ct):
        if len(ct) % BLOCK != 0:
            raise ValueError("CTR ciphertext must be a multiple of BLOCK")
        pt = b''
        r_int = _block_int(r)
        for i in range(len(ct) // BLOCK):
            ctr = _int_block((r_int + i) % (2 ** 128))
            pt += _xor(_enc(key, ctr), ct[i * BLOCK:(i + 1) * BLOCK])
        return _unpad(pt)


# ─────────────── Unified API ───────────────
class Modes:
    def __init__(self):
        self.cbc = CBC()
        self.ofb = OFB()
        self.ctr = CTR()

    def encrypt(self, mode, key, msg):
        if mode == 'CBC':
            iv = os.urandom(BLOCK)
            return {'iv': iv, 'ct': self.cbc.encrypt(key, iv, msg), 'mode': 'CBC'}
        if mode == 'OFB':
            iv = os.urandom(BLOCK)
            return {'iv': iv, 'ct': self.ofb.encrypt(key, iv, msg), 'mode': 'OFB'}
        if mode == 'CTR':
            r, ct = self.ctr.encrypt(key, msg)
            return {'r': r, 'ct': ct, 'mode': 'CTR'}
        return None

    def decrypt(self, mode, key, data):
        if mode == 'CBC':
            return self.cbc.decrypt(key, data['iv'], data['ct'])
        if mode == 'OFB':
            return self.ofb.decrypt(key, data['iv'], data['ct'])
        if mode == 'CTR':
            return self.ctr.decrypt(key, data['r'], data['ct'])
        return None


def demo():
    print("=" * 60); print("PA #4 — Modes of Operation"); print("=" * 60)
    m = Modes()
    key = os.urandom(16)
    for mode in ['CBC', 'OFB', 'CTR']:
        for tag, msg in [('short', b"Hi!"), ('exact', b"ExactOneBlock!!!"), ('multi', b"Multi block message here!")]:
            enc = m.encrypt(mode, key, msg)
            dec = m.decrypt(mode, key, enc)
            print(f"  {mode} [{tag}]: {'✓' if msg == dec else '✗ ' + repr(dec)}")

    # IV-reuse attack on CBC: two messages encrypted under same key+IV with
    # identical first block produce identical first ciphertext blocks.
    print("\n  [CBC IV-reuse attack]")
    iv = os.urandom(BLOCK)
    cbc = CBC()
    block0 = b"AAAAAAAAAAAAAAAA"  # 16 bytes — exactly one block, identical in both messages
    c1 = cbc.encrypt(key, iv, block0 + b"tail-one")
    c2 = cbc.encrypt(key, iv, block0 + b"tail-two")
    print(f"  Block 0 leak: c1[0:16]==c2[0:16] → {c1[:16] == c2[:16]} (matching prefix leaks)")

    print("✓ PA#4 complete.")


if __name__ == "__main__":
    demo()
