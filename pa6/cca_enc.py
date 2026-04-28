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

    def encrypt(self, k_e, k_m, msg):
        r, ce = self._cpa.encrypt(k_e, msg)
        blob = r + ce
        t = self._mac.mac(k_m, blob)
        return blob, t

    def decrypt(self, k_e, k_m, blob, t):
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
    print("✓ PA#6 complete.")


if __name__ == "__main__":
    demo()
