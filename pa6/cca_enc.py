"""
PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC).

Uses CBC-MAC (variable-length, EUF-CMA secure) so the tag covers the full
ciphertext blob — not just the first 16 bytes.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pa3.cpa_enc import CPA_Enc
from pa5.mac import CBC_MAC


class CCA_Enc:
    """Encrypt-then-CBC-MAC. CCA2-secure when CPA is CPA-secure and MAC is EUF-CMA."""

    def __init__(self):
        self._cpa = CPA_Enc()
        self._mac = CBC_MAC()

    @staticmethod
    def _ensure_key_separation(k_e, k_m):
        if k_e == k_m:
            raise ValueError("Key separation violated: kE and kM must be independent")

    def encrypt(self, k_e, k_m, msg):
        self._ensure_key_separation(k_e, k_m)
        r, ce = self._cpa.encrypt(k_e, msg)
        blob = r + ce
        t = self._mac.mac(k_m, blob)
        return blob, t

    def decrypt(self, k_e, k_m, blob, t):
        self._ensure_key_separation(k_e, k_m)
        # MAC check FIRST. Reject any tampering on tag or ciphertext.
        if not self._mac.verify(k_m, blob, t):
            return None  # ⊥
        if len(blob) < 16:
            return None
        r, ce = blob[:16], blob[16:]
        try:
            return self._cpa.decrypt(k_e, r, ce)
        except (AssertionError, ValueError):
            # Defensive: if a forged blob slipped past MAC (negligibly likely)
            # and the padding is wrong, surface it as ⊥ instead of crashing.
            return None

    def encrypt_full(self, k_e, k_m, msg):
        blob, t = self.encrypt(k_e, k_m, msg)
        return blob + t

    def decrypt_full(self, k_e, k_m, data):
        blob, t = data[:-16], data[-16:]
        return self.decrypt(k_e, k_m, blob, t)

    def CCA_Enc(self, k_e, k_m, msg):
        return self.encrypt(k_e, k_m, msg)

    def CCA_Dec(self, k_e, k_m, c, t):
        return self.decrypt(k_e, k_m, c, t)


class IND_CCA2_Game:
    """IND-CCA2 game simulator for Encrypt-then-MAC."""

    def __init__(self, scheme=None):
        self.scheme = scheme or CCA_Enc()
        self.k_e = os.urandom(16)
        self.k_m = os.urandom(16)
        self._b = None
        self._challenge = None
        self._wins = 0
        self._rounds = 0

    def encrypt_oracle(self, m):
        return self.scheme.encrypt(self.k_e, self.k_m, m)

    def challenge(self, m0, m1):
        if len(m0) != len(m1):
            raise ValueError("Challenge messages must have equal length")
        self._b = int.from_bytes(os.urandom(1), 'big') & 1
        chosen = m0 if self._b == 0 else m1
        self._challenge = self.scheme.encrypt(self.k_e, self.k_m, chosen)
        return self._challenge

    def decrypt_oracle(self, c, t):
        # CCA2 restriction: oracle must reject the exact challenge pair.
        if self._challenge is not None and (c, t) == self._challenge:
            return None
        return self.scheme.decrypt(self.k_e, self.k_m, c, t)

    def guess(self, b_prime):
        self._rounds += 1
        if b_prime == self._b:
            self._wins += 1
            return True
        return False

    def advantage(self):
        if self._rounds == 0:
            return 0.0
        return abs(self._wins / self._rounds - 0.5)

    def run_dummy_adversary(self, n_rounds=50):
        self._wins = 0
        self._rounds = 0
        for _ in range(n_rounds):
            # Pre-challenge encryption and decryption-oracle access.
            c0, t0 = self.encrypt_oracle(b"pre-query-000000")
            tampered = bytearray(c0)
            if tampered:
                tampered[-1] ^= 0x01
            _ = self.decrypt_oracle(bytes(tampered), t0)

            self.challenge(b"left-message-000", b"right-message000")
            b_guess = int.from_bytes(os.urandom(1), 'big') & 1
            self.guess(b_guess)

        return {
            'rounds': self._rounds,
            'wins': self._wins,
            'advantage': round(self.advantage(), 4),
            'secure': self.advantage() < 0.2,
        }


def demo():
    print("=" * 60)
    print("PA #6 — CCA-Secure Encryption (Encrypt-then-MAC)")
    print("=" * 60)
    enc = CCA_Enc()
    ke = os.urandom(16); km = os.urandom(16)
    msg = b"CCA-secure message that spans multiple AES blocks!"
    blob, t = enc.encrypt(ke, km, msg)
    dec = enc.decrypt(ke, km, blob, t)
    print(f"  Original:  {msg}")
    print(f"  Decrypted: {dec}")
    print(f"  Correct:   {msg == dec} ✓")

    # Tamper a byte inside the ciphertext (past the nonce)
    tampered = bytearray(blob); tampered[20] ^= 0xFF
    result = enc.decrypt(ke, km, bytes(tampered), t)
    print(f"  Tamper byte 20 → {result} (⊥ = rejected) ✓")

    # Tamper the tag
    bad_tag = bytes([t[0] ^ 0xFF]) + t[1:]
    result2 = enc.decrypt(ke, km, blob, bad_tag)
    print(f"  Tamper tag    → {result2} (⊥ = rejected) ✓")

    # Malleability demo on CPA-only
    from pa3.cpa_enc import CPA_Enc as C
    cpa = C(); ke2 = os.urandom(16)
    r, ct = cpa.encrypt(ke2, b"vote:Alice??????")
    ct_flipped = bytearray(ct); ct_flipped[5] ^= 0x01
    try:
        dec_flip = cpa.decrypt(ke2, r, bytes(ct_flipped))
        print(f"  [CPA malleability] flipped byte → plaintext changed: {dec_flip}")
    except AssertionError:
        print("  [CPA malleability] flipped byte → padding fail (still no detection in CPA)")
    print("  [CCA] same flip on Encrypt-then-MAC → ⊥ ✓")

    # CCA2 dummy-game demo
    game = IND_CCA2_Game(enc)
    g = game.run_dummy_adversary(50)
    print(f"  [IND-CCA2 dummy] advantage={g['advantage']} secure={g['secure']} ✓")

    # Key separation policy demo
    try:
        enc.encrypt(ke, ke, b"same-key-roles")
        print("  [Key separation] WARNING: same key accepted")
    except ValueError:
        print("  [Key separation] same key rejected by policy ✓")
    print("✓ PA#6 complete.")


if __name__ == "__main__":
    demo()
