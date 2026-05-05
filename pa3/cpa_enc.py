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
import secrets
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
        ciphertext = bytearray()
        
        # Ceiling division to get total blocks needed
        n_blocks = (len(message) + BLOCK_SIZE - 1) // BLOCK_SIZE 
        
        for i in range(n_blocks):
            r_int = int.from_bytes(r, 'big')
            ctr = ((r_int + i) % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self._prf_block(key, ctr)
            
            # Slice the message chunk (might be smaller than BLOCK_SIZE on last iteration)
            pt_chunk = message[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            
            # Truncate keystream to match the chunk size
            keystream = keystream[:len(pt_chunk)] 
            
            ciphertext.extend(_xor_bytes(keystream, pt_chunk))
            
        return r, bytes(ciphertext)

    def decrypt(self, key: bytes, r: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext c with nonce r."""
        plaintext = bytearray()
        n_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE
        
        for i in range(n_blocks):
            r_int = int.from_bytes(r, 'big')
            ctr = ((r_int + i) % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self._prf_block(key, ctr)
            
            ct_chunk = ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            keystream = keystream[:len(ct_chunk)]
            
            plaintext.extend(_xor_bytes(keystream, ct_chunk))
            
        return bytes(plaintext)

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
        ciphertext = bytearray()
        n_blocks = (len(message) + BLOCK_SIZE - 1) // BLOCK_SIZE 
        for i in range(n_blocks):
            r_int = int.from_bytes(self._fixed_nonce, 'big')
            ctr = ((r_int + i) % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self.prf.evaluate(key, ctr)
            
            pt_chunk = message[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
            keystream = keystream[:len(pt_chunk)] 
            
            ciphertext.extend(_xor_bytes(keystream, pt_chunk))
        return self._fixed_nonce, bytes(ciphertext)

    def encrypt_full(self, key: bytes, message: bytes) -> bytes:
        r, ct = self.encrypt(key, message)
        return r + ct


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
        # CSPRNG bit (secrets.randbits → os.urandom).
        self._b = secrets.randbits(1)
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
        self._oracle_queries = 0
        self._wins = 0
        self._rounds = 0
        # Adversary queries oracle 50 times first
        for _ in range(50):
            self.encrypt_oracle(b"query message!!")
        # Then plays n_rounds of challenge
        for _ in range(n_rounds):
            ct = self.challenge(b"message zero!!!!",
                                b"message one!!!! ")
            b_guess = secrets.randbits(1)  # CSPRNG random guess
            self.guess(b_guess)
        return {
            'rounds': self._rounds,
            'wins': self._wins,
            'advantage': round(self.advantage(), 4),
            'expected_advantage': '≈ 0 (negligible)',
            'secure': self.advantage() < 0.1
        }

    def run_nonce_reuse_adversary(self, n_rounds: int = 20) -> dict:
        """Adversary that exploits nonce reuse using ONLY the oracle."""
        # We assume self.scheme is currently set to the Broken variant
        self._oracle_queries = 0
        self._wins = 0
        self._rounds = 0
        for _ in range(n_rounds):
            m0 = b"vote:Alice??????"
            m1 = b"vote:Bob????????"
            
            # 1. Get the challenge ciphertext from the challenger
            ct_challenge = self.challenge(m0, m1)
            
            # 2. Query the ORACLE for m0 (Adversary does NOT know the key)
            ct0 = self.encrypt_oracle(m0)
            
            # 3. Compare. If they match, the challenger encrypted m0.
            if ct_challenge == ct0:
                b_guess = 0
            else:
                b_guess = 1
                
            self.guess(b_guess)

        adv = self.advantage()
        return {
            'rounds': n_rounds,
            'wins': self._wins,
            'advantage': round(adv, 4),
            'secure': adv < 0.1,
            'note': 'Nonce reuse breaks CPA security — adversary queries oracle to find match.'
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
    broken_game = IND_CPA_Game(broken)
    broken_result = broken_game.run_nonce_reuse_adversary(20)
    print(f"  Advantage: {broken_result['advantage']} (close to 0.5 = broken!)")
    print(f"  Note: {broken_result['note']}")

    print("\n✓ PA#3 complete.")


if __name__ == "__main__":
    demo()
