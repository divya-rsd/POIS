"""
PA #14 — CRT + Håstad's Broadcast Attack
PA #15 — Digital Signatures (RSA)
PA #16 — ElGamal Public-Key Cryptosystem
"""
import os, sys, math, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa12.rsa import RSA, RSA_PKCS15, _mod_inverse, _fast_pow
from pa11.dh import DH, _rand_exp
from pa8_9_10.hash_hmac import DLP_Hash

# ─────────── PA #14 — CRT ───────────
def crt(residues, moduli):
    N = 1
    for m in moduli: N *= m
    x = 0
    for a,m in zip(residues,moduli):
        Mi = N//m
        x += a * Mi * _mod_inverse(Mi,m)
    return x % N

def integer_nth_root(n, k):
    """Newton's method integer nth root."""
    if n == 0: return 0
    x = int(n**(1/k)) + 1
    while True:
        x1 = ((k-1)*x + n//(x**(k-1))) // k
        if x1 >= x: return x
        x = x1

def hastad_attack(ciphertexts, moduli, e=3):
    x = crt(ciphertexts, moduli)
    return integer_nth_root(x, e)

def demo_pa14():
    print("="*60); print("PA #14 — CRT + Håstad's Broadcast Attack"); print("="*60)
    # Toy RSA with e=3
    rsa_list = [RSA(bits=256) for _ in range(3)]
    # Force e=3
    for r in rsa_list:
        r.e = 3
        try: r.d = _mod_inverse(3,(r.p-1)*(r.q-1))
        except: pass
    m = 42
    cts = [_fast_pow(m, 3, r.N) for r in rsa_list]
    mods = [r.N for r in rsa_list]
    recovered = hastad_attack(cts, mods, e=3)
    print(f"  Message: {m}, Recovered: {recovered}, Match: {m==recovered} ✓")
    # CRT correctness
    res = crt([2,3,2],[3,5,7])
    print(f"  CRT(2 mod 3, 3 mod 5, 2 mod 7) = {res} (expected 23)")
    print("✓ PA#14 complete.")

# ─────────── PA #15 — Digital Signatures ───────────
class RSA_Sign:
    def __init__(self, rsa: RSA, hash_fn=None):
        self.rsa = rsa
        self._hash = hash_fn or DLP_Hash()

    def sign(self, msg: bytes) -> int:
        h = self._hash.hash(msg)
        h_int = int.from_bytes(h, 'big') % self.rsa.N
        return self.rsa.decrypt(h_int)  # σ = H(m)^d mod N

    def verify(self, msg: bytes, sig: int) -> bool:
        h = self._hash.hash(msg)
        h_int = int.from_bytes(h, 'big') % self.rsa.N
        recovered = _fast_pow(sig, self.rsa.e, self.rsa.N)
        return recovered == h_int

def demo_pa15():
    print("="*60); print("PA #15 — Digital Signatures"); print("="*60)
    rsa = RSA(bits=512); signer = RSA_Sign(rsa)
    msg = b"Sign this message"
    sig = signer.sign(msg)
    print(f"  Signature: {hex(sig)[:24]}…")
    print(f"  Verify:    {signer.verify(msg, sig)} ✓")
    # Tamper test
    print(f"  Tampered:  {signer.verify(b'tampered!', sig)} ✗")
    # Multiplicative forgery on raw RSA (no hash)
    print("\n  [Raw RSA multiplicative forgery]")
    m1=3; m2=7
    s1=rsa.decrypt(m1); s2=rsa.decrypt(m2)
    # σ(m1*m2) = σ(m1)*σ(m2) mod N
    s12=s1*s2 % rsa.N
    valid=_fast_pow(s12,rsa.e,rsa.N)==(m1*m2)%rsa.N
    print(f"  Forge σ(m1·m2) from σ(m1),σ(m2): {valid} ← WHY we hash-then-sign!")
    print("✓ PA#15 complete.")

# ─────────── PA #16 — ElGamal ───────────
class ElGamal:
    def __init__(self, bits=128):
        dh = DH(bits)
        self.p = dh.p; self.g = dh.g; self.q = dh.q

    def keygen(self):
        x = _rand_exp(self.q)
        h = _fast_pow(self.g, x, self.p)  # public key h = g^x
        return {'sk': x, 'pk': (self.p, self.g, self.q, h)}

    def encrypt(self, pk, m: int):
        p,g,q,h = pk
        r = _rand_exp(q)
        c1 = _fast_pow(g, r, p)
        c2 = m * _fast_pow(h, r, p) % p
        return c1, c2

    def decrypt(self, sk_x, pk, c1, c2):
        p,g,q,h = pk
        s = _fast_pow(c1, sk_x, p)
        return c2 * _mod_inverse(s, p) % p

    def malleability_demo(self, pk, c1, c2):
        """Given Enc(m) = (c1,c2), produce Enc(2m) = (c1, 2*c2 mod p)."""
        p,*_ = pk
        return c1, 2*c2 % p

def demo_pa16():
    print("="*60); print("PA #16 — ElGamal PKC"); print("="*60)
    eg = ElGamal(bits=128)
    keys = eg.keygen()
    sk=keys['sk']; pk=keys['pk']
    m = 1234
    c1,c2 = eg.encrypt(pk, m)
    dec = eg.decrypt(sk, pk, c1, c2)
    print(f"  Encrypt/Decrypt m={m}: {dec==m} ✓")
    # Malleability
    c1m, c2m = eg.malleability_demo(pk, c1, c2)
    dec_m = eg.decrypt(sk, pk, c1m, c2m)
    print(f"  Malleability: Dec(Enc(2m)) = {dec_m} = 2×{m} = {2*m}, match={dec_m==2*m} ✓")
    print("✓ PA#16 complete.")

if __name__ == "__main__":
    demo_pa14(); print(); demo_pa15(); print(); demo_pa16()
