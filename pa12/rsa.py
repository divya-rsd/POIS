"""
PA #12 — Textbook RSA + PKCS#1 v1.5
"""
import os, sys, math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa13.primality import gen_prime, _mod_exp

def _extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = _extended_gcd(b%a, a)
    return g, y-(b//a)*x, x

def _mod_inverse(a, m):
    g, x, _ = _extended_gcd(a%m, m)
    if g != 1: raise ValueError("No inverse")
    return x % m

def _fast_pow(base, exp, mod): return _mod_exp(base,exp,mod)

class RSA:
    def __init__(self, bits=512):
        self.bits = bits
        p = gen_prime(bits//2); q = gen_prime(bits//2)
        while p == q: q = gen_prime(bits//2)
        self.p = p; self.q = q
        self.N = p*q
        phi = (p-1)*(q-1)
        self.e = 65537
        self.d = _mod_inverse(self.e, phi)
        self.dp = self.d % (p-1)
        self.dq = self.d % (q-1)
        self.q_inv = _mod_inverse(q, p)
        self.pk = (self.N, self.e)
        self.sk = (self.N, self.d, p, q, self.dp, self.dq, self.q_inv)

    def encrypt(self, m: int) -> int:
        N,e = self.pk; return _fast_pow(m,e,N)

    def decrypt(self, c: int) -> int:
        N,d,*_ = self.sk; return _fast_pow(c,d,N)

    def decrypt_crt(self, c: int) -> int:
        N,d,p,q,dp,dq,q_inv = self.sk
        mp = _fast_pow(c,dp,p); mq = _fast_pow(c,dq,q)
        h = q_inv*(mp-mq) % p
        return mq + h*q

class RSA_PKCS15:
    def __init__(self, rsa: RSA):
        self.rsa = rsa
        self.k = (rsa.N.bit_length()+7)//8  # modulus byte length

    def _i2osp(self, n, length):
        return n.to_bytes(length, 'big')

    def _os2ip(self, b):
        return int.from_bytes(b, 'big')

    def encrypt(self, msg: bytes) -> int:
        assert len(msg) <= self.k-11
        ps_len = self.k - len(msg) - 3
        ps = b''
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b'\x00': ps += b
        em = b'\x00\x02' + ps + b'\x00' + msg
        m = self._os2ip(em)
        return self.rsa.encrypt(m)

    def decrypt(self, c: int) -> bytes:
        m = self.rsa.decrypt_crt(c)
        em = self._i2osp(m, self.k)
        if em[0] != 0 or em[1] != 2: return None  # ⊥
        sep = em.find(b'\x00', 2)
        if sep < 10: return None  # PS too short
        return em[sep+1:]

def demo():
    print("="*60); print("PA #12 — RSA + PKCS#1 v1.5"); print("="*60)
    rsa = RSA(bits=512); pkcs = RSA_PKCS15(rsa)
    # Textbook RSA
    m=42; c=rsa.encrypt(m); dec=rsa.decrypt(c)
    print(f"  Textbook RSA: m={m}, dec={dec}, correct={m==dec} ✓")
    # CRT decryption
    dec_crt=rsa.decrypt_crt(c)
    print(f"  CRT decrypt: {dec_crt}, correct={m==dec_crt} ✓")
    # Determinism attack
    c1=rsa.encrypt(1234); c2=rsa.encrypt(1234)
    print(f"\n  Textbook determinism: c1==c2: {c1==c2} ← INSECURE")
    # PKCS padding
    msg=b"vote:Alice"
    c_pad1=pkcs.encrypt(msg); c_pad2=pkcs.encrypt(msg)
    dec_pad=pkcs.decrypt(c_pad1)
    print(f"  PKCS enc1 == enc2: {c_pad1==c_pad2} (randomized ✓)")
    print(f"  PKCS decrypt: {dec_pad} ✓")
    print("✓ PA#12 complete.")

if __name__ == "__main__": demo()
