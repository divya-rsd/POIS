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

def bleichenbacher_attack(oracle, N, e, c0, k, max_queries=150000):
    """
    Simplified BB98 adaptive chosen-ciphertext attack.
    Recovers the plaintext m0 for a PKCS#1 v1.5 conforming ciphertext c0.
    """
    B = 2**(8*(k - 2))
    M = [(2*B, 3*B - 1)]
    s_i = 1
    
    # Step 2a: Starting the search
    # Find smallest s_1 >= ceil(N / 3B) such that c0 * s_1^e is conforming
    s_i = (N + 3*B - 1) // (3*B)
    queries = 0
    while True:
        queries += 1
        c_test = (c0 * _fast_pow(s_i, e, N)) % N
        if oracle(c_test): break
        s_i += 1
        if queries > max_queries: return None, queries
    
    def update_intervals(M_prev, s):
        M_new = []
        for a, b in M_prev:
            r_lower = (a * s - 3*B + 1 + N - 1) // N
            r_upper = (b * s - 2*B) // N
            for r in range(r_lower, r_upper + 1):
                new_a = max(a, (2*B + r*N + s - 1) // s)
                new_b = min(b, (3*B - 1 + r*N) // s)
                if new_a <= new_b:
                    M_new.append((new_a, new_b))
        if not M_new: return []
        M_new.sort(key=lambda x: x[0])
        merged = [M_new[0]]
        for cur in M_new[1:]:
            last = merged[-1]
            if cur[0] <= last[1]:
                merged[-1] = (last[0], max(last[1], cur[1]))
            else: merged.append(cur)
        return merged

    M = update_intervals(M, s_i)
    
    while True:
        if len(M) == 1 and M[0][0] == M[0][1]:
            # Step 4: Solution found
            return M[0][0], queries
            
        if len(M) > 1:
            # Step 2b: Searching with more than one interval
            s_i += 1
            while True:
                queries += 1
                c_test = (c0 * _fast_pow(s_i, e, N)) % N
                if oracle(c_test): break
                s_i += 1
                if queries > max_queries: return None, queries
        else:
            # Step 2c: Searching with one interval left
            a, b = M[0]
            r = 2 * (b * s_i - 2*B + N - 1) // N
            found = False
            while not found:
                s_lower = (2*B + r*N + b - 1) // b
                s_upper = (3*B - 1 + r*N) // a
                for s_try in range(s_lower, s_upper + 1):
                    queries += 1
                    c_test = (c0 * _fast_pow(s_try, e, N)) % N
                    if oracle(c_test):
                        s_i = s_try
                        found = True
                        break
                    if queries > max_queries: return None, queries
                if not found: r += 1
                
        # Step 3: Narrowing
        M = update_intervals(M, s_i)


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
    
    # BB98 Padding Oracle Attack
    print("\n  [Bleichenbacher Padding Oracle Attack]")
    def padding_oracle(c_test):
        m = rsa.decrypt_crt(c_test)
        try:
            em = pkcs._i2osp(m, pkcs.k)
        except OverflowError:
            return False
        return len(em) == pkcs.k and em[0] == 0 and em[1] == 2
        
    print(f"  Target message: {msg}")
    print(f"  Recovering plaintext from ciphertext... (this may take a few seconds)")
    recovered_int, queries = bleichenbacher_attack(padding_oracle, rsa.N, rsa.e, c_pad1, pkcs.k, max_queries=100000)
    if recovered_int:
        em_rec = pkcs._i2osp(recovered_int, pkcs.k)
        sep = em_rec.find(b'\x00', 2)
        recovered_msg = em_rec[sep+1:]
        print(f"  Recovered: {recovered_msg} in {queries} queries ✓ (CCA INSECURE)")
    else:
        print(f"  Attack failed or exceeded {queries} queries ✗")
        
    print("✓ PA#12 complete.")

if __name__ == "__main__": demo()
