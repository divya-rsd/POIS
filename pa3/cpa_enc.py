"""
PA #3 — CPA-Secure Symmetric Encryption

Enc(k, m) = ⟨r, Fk(r) ⊕ m⟩  where r is fresh random nonce
Dec(k, r, c) = Fk(r) ⊕ c

Implements:
  - CPA-secure encryption and decryption
  - Multi-block support (counter-based)
  - IND-CPA game simulation
  - Broken variant (nonce reuse attack demo)
  - Interface: Enc/Dec for PA#6
"""

import os
import struct
from typing import Tuple
import sys, os as _os
sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from pa2.prf_ggm import PRF


BLOCK_SIZE = 16  # bytes


def _int_to_block(n: int) -> bytes:
    return n.to_bytes(BLOCK_SIZE, 'big')


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS#7-style padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    assert 1 <= pad_len <= BLOCK_SIZE
    assert data[-pad_len:] == bytes([pad_len] * pad_len)
    return data[:-pad_len]


# ─────────────────────────────────────────────────────────────
# CPA-Secure Encryption
# ─────────────────────────────────────────────────────────────
class CPA_Enc:
    """
    Encryption scheme: Enc(k, m) = ⟨r, Fk(r) ⊕ m⟩
    Security: CPA-secure if Fk is a PRF.
    """

    def __init__(self, prf: PRF = None):
        self.prf = prf or PRF(use_aes=True)

    def _prf_block(self, key: bytes, counter_block: bytes) -> bytes:
        return self.prf.evaluate(key, counter_block)

    def encrypt(self, key: bytes, message: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt message m under key k.
        Returns (r, ciphertext) where r is fresh random nonce.
        Supports multi-block messages via counter extension.
        """
        r = os.urandom(BLOCK_SIZE)
        padded = _pad(message)
        ciphertext = bytearray()
        n_blocks = len(padded) // BLOCK_SIZE
        for i in range(n_blocks):
            # Counter block: r || (r_int + i) mod 2^128
            r_int = int.from_bytes(r, 'big')
            ctr = ((r_int + i) % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self._prf_block(key, ctr)
            pt_block = padded[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            ciphertext.extend(_xor_bytes(keystream, pt_block))
        return r, bytes(ciphertext)

    def decrypt(self, key: bytes, r: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext c with nonce r."""
        padded = bytearray()
        n_blocks = len(ciphertext) // BLOCK_SIZE
        for i in range(n_blocks):
            r_int = int.from_bytes(r, 'big')
            ctr = ((r_int + i) % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self._prf_block(key, ctr)
            ct_block = ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            padded.extend(_xor_bytes(keystream, ct_block))
        return _unpad(bytes(padded))

    def encrypt_full(self, key: bytes, message: bytes) -> bytes:
        """Convenience: returns r || ciphertext as single blob."""
        r, ct = self.encrypt(key, message)
        return r + ct

    def decrypt_full(self, key: bytes, blob: bytes) -> bytes:
        r, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
        return self.decrypt(key, r, ct)


# ─────────────────────────────────────────────────────────────
# Broken Variant — Nonce Reuse Attack
# ─────────────────────────────────────────────────────────────
class BrokenDeterministicEnc:
    """
    Broken: deterministic encryption (fixed nonce = 0).
    Enc(k, m1) == Enc(k, m1) always — breaks CPA security.
    """

    def __init__(self, prf: PRF = None):
        self.prf = prf or PRF(use_aes=True)
        self._fixed_nonce = b'\x00' * BLOCK_SIZE

    def encrypt(self, key: bytes, message: bytes) -> Tuple[bytes, bytes]:
        padded = _pad(message)
        ciphertext = bytearray()
        n_blocks = len(padded) // BLOCK_SIZE
        for i in range(n_blocks):
            keystream = self.prf.evaluate(key, self._fixed_nonce)
            pt_block = padded[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            ciphertext.extend(_xor_bytes(keystream, pt_block))
        return self._fixed_nonce, bytes(ciphertext)


# ─────────────────────────────────────────────────────────────
# IND-CPA Game Simulation
# ─────────────────────────────────────────────────────────────
class IND_CPA_Game:
    """
    IND-CPA security game.
    Adversary queries encryption oracle, then submits challenge.
    """

    def __init__(self, scheme: CPA_Enc):
        self.scheme = scheme
        self.key = os.urandom(16)
        self._oracle_queries = 0
        self._wins = 0
        self._rounds = 0

    def encrypt_oracle(self, message: bytes) -> bytes:
        """Encryption oracle for adversary."""
        self._oracle_queries += 1
        return self.scheme.encrypt_full(self.key, message)

    def challenge(self, m0: bytes, m1: bytes) -> bytes:
        """Challenger encrypts one of m0, m1; adversary must guess which."""
        assert len(m0) == len(m1), "Challenge messages must be equal length"
        import random
        self._b = random.randint(0, 1)
        chosen = m0 if self._b == 0 else m1
        return self.scheme.encrypt_full(self.key, chosen)

    def guess(self, b_prime: int) -> bool:
        """Adversary's guess: 0 or 1."""
        self._rounds += 1
        correct = (b_prime == self._b)
        if correct:
            self._wins += 1
        return correct

    def advantage(self) -> float:
        """Adversary's advantage = |Pr[win] - 1/2|."""
        if self._rounds == 0:
            return 0.0
        return abs(self._wins / self._rounds - 0.5)

    def run_dummy_adversary(self, n_rounds: int = 50) -> dict:
        """Simulate dummy adversary (random guessing) — advantage ≈ 0."""
        import random
        self._wins = 0
        self._rounds = 0
        # Adversary queries oracle 50 times first
        for _ in range(50):
            self.encrypt_oracle(b"query message!!")
        # Then plays n_rounds of challenge
        for _ in range(n_rounds):
            ct = self.challenge(b"message zero!!!!",
                                b"message one!!!! ")
            b_guess = random.randint(0, 1)  # Random guess
            self.guess(b_guess)
        return {
            'rounds': self._rounds,
            'wins': self._wins,
            'advantage': round(self.advantage(), 4),
            'expected_advantage': '≈ 0 (negligible)',
            'secure': self.advantage() < 0.1
        }

    def run_nonce_reuse_adversary(self, broken_enc: BrokenDeterministicEnc,
                                   n_rounds: int = 20) -> dict:
        """Adversary that exploits nonce reuse — wins every time."""
        broken_key = os.urandom(16)
        wins = 0
        for _ in range(n_rounds):
            m0 = b"vote:Alice??????"
            m1 = b"vote:Bob????????"
            # Encrypt m0 and m1 separately — nonce reuse means same CT if same msg
            _, ct0 = broken_enc.encrypt(broken_key, m0)
            _, ct1 = broken_enc.encrypt(broken_key, m1)
            # Get challenge
            import random
            b_actual = random.randint(0, 1)
            m_chosen = m0 if b_actual == 0 else m1
            _, ct_challenge = broken_enc.encrypt(broken_key, m_chosen)
            # Adversary: compare challenge CT to known CTs
            if ct_challenge == ct0:
                b_guess = 0
            elif ct_challenge == ct1:
                b_guess = 1
            else:
                b_guess = random.randint(0, 1)
            if b_guess == b_actual:
                wins += 1
        adv = abs(wins / n_rounds - 0.5)
        return {
            'rounds': n_rounds,
            'wins': wins,
            'advantage': round(adv, 4),
            'secure': adv < 0.1,
            'note': 'Nonce reuse breaks CPA security — identical CT for identical PT'
        }


# ─────────────────────────────────────────────────────────────
# Demo
# ─────────────────────────────────────────────────────────────
def demo():
    print("=" * 60)
    print("PA #3 — CPA-Secure Symmetric Encryption")
    print("=" * 60)

    enc = CPA_Enc()
    key = os.urandom(16)

    # Basic encrypt/decrypt
    print("\n[Encrypt/Decrypt]")
    msg = b"Hello, Minicrypt!"
    r, ct = enc.encrypt(key, msg)
    decrypted = enc.decrypt(key, r, ct)
    print(f"  Plaintext:  {msg}")
    print(f"  Nonce r:    {r.hex()}")
    print(f"  Ciphertext: {ct.hex()}")
    print(f"  Decrypted:  {decrypted}")
    print(f"  Correct:    {msg == decrypted} ✓")

    # Multi-block
    print("\n[Multi-block message]")
    long_msg = b"A" * 64
    r2, ct2 = enc.encrypt(key, long_msg)
    dec2 = enc.decrypt(key, r2, ct2)
    print(f"  64-byte message correctly decrypted: {long_msg == dec2} ✓")

    # IND-CPA game
    print("\n[IND-CPA Game — Dummy Adversary]")
    game = IND_CPA_Game(enc)
    result = game.run_dummy_adversary(50)
    print(f"  Rounds: {result['rounds']}, Wins: {result['wins']}")
    print(f"  Advantage: {result['advantage']} (expected ≈ 0)")
    print(f"  Secure: {result['secure']} ✓")

    # Nonce reuse attack
    print("\n[Nonce Reuse Attack on Broken Scheme]")
    broken = BrokenDeterministicEnc()
    broken_result = game.run_nonce_reuse_adversary(broken, 20)
    print(f"  Advantage: {broken_result['advantage']} (close to 0.5 = broken!)")
    print(f"  Note: {broken_result['note']}")

    print("\n✓ PA#3 complete.")


if __name__ == "__main__":
    demo()
