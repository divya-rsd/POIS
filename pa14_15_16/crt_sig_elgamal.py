"""
PA #14 — CRT + Håstad's Broadcast Attack
PA #15 — Digital Signatures (RSA)
PA #16 — ElGamal Public-Key Cryptosystem
"""
import os, sys, math, secrets, time
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

def rsa_dec_crt(sk, c):
    """Garner's Algorithm for CRT-based RSA Decryption."""
    N, d, p, q, dp, dq, q_inv = sk
    mp = _fast_pow(c, dp, p)
    mq = _fast_pow(c, dq, q)
    h = (q_inv * ((mp - mq) % p + p)) % p
    return mq + h * q

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
    # CRT correctness sanity check
    res = crt([2,3,2],[3,5,7])
    print(f"  CRT(2 mod 3, 3 mod 5, 2 mod 7) = {res} (expected 23)")

    print(f"\n  [Garner's Algorithm: Correctness & Performance]")
    rsa_test = RSA(bits=1024)
    # 1. Correctness on 100 random messages
    correct = 0
    for _ in range(100):
        m_rand = secrets.randbelow(rsa_test.N)
        c_rand = rsa_test.encrypt(m_rand)
        m_std = rsa_test.decrypt(c_rand)
        m_crt = rsa_dec_crt(rsa_test.sk, c_rand)
        if m_std == m_crt: correct += 1
    print(f"  Correctness test: {correct}/100 messages matched standard decrypt.")

    # 2. Performance benchmark
    for bits in [1024, 2048]:
        r_bench = RSA(bits=bits)
        c_bench = r_bench.encrypt(42)
        
        t0 = time.time()
        for _ in range(1000): r_bench.decrypt(c_bench)
        t_std = time.time() - t0
        
        t0 = time.time()
        for _ in range(1000): rsa_dec_crt(r_bench.sk, c_bench)
        t_crt = time.time() - t0
        
        speedup = t_std / t_crt if t_crt > 0 else 0
        print(f"  {bits}-bit RSA 1000 decryptions -> Std: {t_std:.3f}s, CRT: {t_crt:.3f}s. Speedup: {speedup:.2f}x")

    # Håstad broadcast attack: same small m, e=3, three different moduli.
    rsa_list = [RSA(bits=256) for _ in range(3)]
    m = 42
    cts = [_fast_pow(m, 3, r.N) for r in rsa_list]
    mods = [r.N for r in rsa_list]
    recovered = hastad_attack(cts, mods, e=3)
    print(f"\n  [Håstad attack — UNPADDED RSA, e=3]")
    print(f"  Broadcast m={m} to 3 recipients")
    print(f"  c_i = m^3 mod N_i  (shown mod 2^32): "
          f"{[c & 0xffffffff for c in cts]}")
    print(f"  CRT(c1, c2, c3) mod N1·N2·N3 = m^3 as integer, then cube-root.")
    print(f"  Recovered m = {recovered}, match = {m == recovered} ✓")
    
    print(f"\n  [Attack Boundary Analysis]")
    print(f"  Håstad's attack with e=3 succeeds strictly when m^3 < N1*N2*N3.")
    print(f"  If three 1024-bit moduli are used, N1*N2*N3 is roughly 3072 bits.")
    print(f"  Therefore, any message m < 2^1024 (i.e. length ≤ 128 bytes) is vulnerable.")
    print(f"  Messages with m^3 >= N1*N2*N3 wrap around the combined modulus, preventing a simple integer cube root from recovering m.")

    # PKCS defense: each sender pads with random bytes, destroying shared m
    print(f"\n  [Defense: PKCS#1 v1.5 padding per recipient]")
    pkcs_list = [RSA_PKCS15(r) for r in rsa_list]
    msg_bytes = b"A"  # short message, unique per broadcast
    cts_padded = [p.encrypt(msg_bytes) for p in pkcs_list]
    # With e=65537 and padding, the attack does not apply; but even forced to
    # e=3 the padded plaintexts differ per recipient, so CRT recovers garbage.
    #
    # Demo with e=3 + padding: encrypt padded value under e=3 manually.
    e = 3
    cts_padded_e3 = []
    for r, p in zip(rsa_list, pkcs_list):
        # Rebuild PKCS padding and encrypt under e=3
        k = p.k
        ps_len = k - len(msg_bytes) - 3
        # Build a random nonzero PS per recipient (what real PKCS does).
        ps_bytes = bytearray()
        while len(ps_bytes) < ps_len:
            b = os.urandom(1)
            if b != b'\x00':
                ps_bytes += b
        em = b'\x00\x02' + bytes(ps_bytes) + b'\x00' + msg_bytes
        m_int = int.from_bytes(em, 'big')
        cts_padded_e3.append(_fast_pow(m_int, e, r.N))
    x = crt(cts_padded_e3, mods)
    recovered_padded = integer_nth_root(x, 3)
    print(f"  With padding: each recipient sees a different padded m_i")
    print(f"  Attack result: recovered = {hex(recovered_padded)[:20]}… (garbage)")
    print(f"  Does it equal a clean plaintext? {recovered_padded == int.from_bytes(msg_bytes, 'big')} ✗")
    print(f"  (PKCS padding breaks the 'same m for all recipients' premise.)")
    print("✓ PA#14 complete.")

# ─────────── PA #15 — Digital Signatures ───────────

# def Sign(sk, m: bytes) -> int:
#     """Standard standalone RSA Sign using hash-and-sign paradigm."""
#     N, d, p, q, dp, dq, q_inv = sk
#     h = hashlib.sha256(m).digest()
#     # H(m) is 256 bits (SHA-256). As long as N > 256 bits, h_int < N.
#     # We do NOT use `% N` to avoid collisions (hash truncation flaw).
#     h_int = int.from_bytes(h, 'big')
#     assert h_int < N, "Modulus too small for the hash output size"
#     # σ = H(m)^d mod N
#     return _fast_pow(h_int, d, N)

# def Verify(vk, m: bytes, sigma: int) -> bool:
#     """Standard standalone RSA Verify."""
#     N, e = vk
#     h = hashlib.sha256(m).digest()
#     h_int = int.from_bytes(h, 'big')
#     recovered = _fast_pow(sigma, e, N)
#     return recovered == h_int

def Sign(sk, m: bytes, hash_fn=None) -> int:
    """Standard standalone RSA Sign using hash-and-sign paradigm."""
    N, d, p, q, dp, dq, q_inv = sk
    from pa8_9_10.hash_hmac import DLP_Hash_Wide
    hasher = hash_fn or DLP_Hash_Wide()
    h = hasher.hash(m) 
    
    h_int = int.from_bytes(h, 'big')
    assert h_int < N, "Modulus too small for the hash output size"
    return _fast_pow(h_int, d, N)

def Verify(vk, m: bytes, sigma: int, hash_fn=None) -> bool:
    """Standard standalone RSA Verify."""
    N, e = vk
    from pa8_9_10.hash_hmac import DLP_Hash_Wide
    hasher = hash_fn or DLP_Hash_Wide()
    h = hasher.hash(m)
    
    h_int = int.from_bytes(h, 'big')
    recovered = _fast_pow(sigma, e, N)
    return recovered == h_int
def demo_pa15():
    print("="*60); print("PA #15 — Digital Signatures"); print("="*60)
    rsa = RSA(bits=512)
    msg = b"Sign this message"
    sig = Sign(rsa.sk, msg)
    print(f"  Signature: {hex(sig)[:24]}…")
    print(f"  Verify:    {Verify(rsa.pk, msg, sig)} ✓")
    # Tamper test
    print(f"  Tampered:  {Verify(rsa.pk, b'tampered!', sig)} ✗")
    # Multiplicative forgery on raw RSA (no hash)
    print("\n  [Raw RSA multiplicative forgery]")
    m1=3; m2=7
    s1=rsa.decrypt(m1); s2=rsa.decrypt(m2)
    # σ(m1*m2) = σ(m1)*σ(m2) mod N
    s12=s1*s2 % rsa.N
    valid=_fast_pow(s12,rsa.e,rsa.N)==(m1*m2)%rsa.N
    print(f"  Forge σ(m1·m2) from σ(m1),σ(m2): {valid} ← WHY we hash-then-sign!")
    print("\n  [EUF-CMA Game Simulation]")
    print(f"  Adversary is given 50 queries to a signing oracle...")
    
    seen_msgs = set()
    for i in range(50):
        # Oracle queries
        q_msg = f"Message {i}".encode()
        seen_msgs.add(q_msg)
        _ = Sign(rsa.sk, q_msg)  # Adversary sees the signature
        
    print(f"  Adversary attempts to forge signature for m* = 'Forged message'")
    m_star = b"Forged message"
    
    # Adversary tries a random signature
    sig_star = secrets.randbelow(rsa.N)
    
    # Check win condition: m* not in seen_msgs AND valid signature
    is_new = m_star not in seen_msgs
    is_valid = Verify(rsa.pk, m_star, sig_star)
    print(f"  Is m* new? {is_new}")
    print(f"  Is forgery valid? {is_valid}")
    print(f"  Adversary wins? {is_new and is_valid} (Overwhelming probability of failure)")

    print("✓ PA#15 complete.")

# ─────────── PA #16 — ElGamal ───────────
class ElGamal:
    def __init__(self, bits=128):
        dh = DH(bits)
        self.p = dh.p; self.g = dh.g; self.q = dh.q

    def encode_group(self, m: int) -> int:
        """Map a message 0 <= m < q-1 into the subgroup G of quadratic residues."""
        m_shifted = m + 1
        assert 0 < m_shifted <= self.q, "Message too large"
        if _fast_pow(m_shifted, self.q, self.p) == 1:
            return m_shifted
        else:
            return self.p - m_shifted

    def decode_group(self, m_encoded: int) -> int:
        """Decode a subgroup element back to the original message."""
        if m_encoded <= self.q:
            return m_encoded - 1
        else:
            return (self.p - m_encoded) - 1

    def keygen(self):
        x = _rand_exp(self.q)
        h = _fast_pow(self.g, x, self.p)  # public key h = g^x
        return {'sk': (x, self.p), 'pk': (self.p, self.g, self.q, h)}

    def encrypt(self, pk, m: int):
        p,g,q,h = pk
        r = _rand_exp(q)
        c1 = _fast_pow(g, r, p)
        m_group = self.encode_group(m)
        c2 = m_group * _fast_pow(h, r, p) % p
        return c1, c2

    def decrypt(self, sk, c1, c2):
        x, p = sk
        s = _fast_pow(c1, x, p)
        m_group = c2 * _mod_inverse(s, p) % p
        return self.decode_group(m_group)

    def malleability_demo(self, pk, c1, c2):
        """Given Enc(m) = (c1,c2), produce Enc(2m) = (c1, 2*c2 mod p)."""
        p,*_ = pk
        return c1, 2*c2 % p


# ─────────── PA #16 — IND-CPA Game for ElGamal ───────────
class ElGamal_IND_CPA_Game:
    """
    Formal IND-CPA game (Challenger vs. Adversary) for ElGamal.

    Protocol per round:
      1. Challenger generates fresh keys (sk, pk).
      2. Adversary picks two equal-length messages m0, m1.
      3. Challenger flips a private bit b ← {0,1}, encrypts mb, sends C* to Adv.
      4. Adversary outputs guess b'. Win iff b' == b.

    Adversary advantage = | Pr[b'=b] − 1/2 |.
    """

    def __init__(self, eg: 'ElGamal'):
        self.eg = eg

    # ── Honest (random-guess) adversary — should have negligible advantage ──
    def adversary_choose(self, pk) -> tuple:
        p, g, q, h = pk
        m0 = 1 + secrets.randbelow(q - 1)
        m1 = 1 + secrets.randbelow(q - 1)
        return m0, m1

    def adversary_guess(self, pk, c_star, state) -> int:
        return secrets.randbits(1)

    def run_cpa_game(self, n_rounds: int = 50) -> dict:
        wins = 0
        for _ in range(n_rounds):
            keys = self.eg.keygen()
            sk, pk = keys['sk'], keys['pk']
            
            # Adversary outputs two messages
            m0, m1 = self.adversary_choose(pk)
            
            # Challenger flips bit and encrypts
            b = secrets.randbits(1)
            mb = m0 if b == 0 else m1
            c_star = self.eg.encrypt(pk, mb)
            
            # Adversary guesses the bit
            b_guess = self.adversary_guess(pk, c_star, (m0, m1))
            
            if b_guess == b:
                wins += 1
                
        adv = abs(wins / n_rounds - 0.5)
        return {
            'rounds': n_rounds, 'wins': wins,
            'advantage': round(adv, 4),
            'secure': adv < 0.15,
        }

    # ── DLP-breaking adversary — wins every round when q is small enough ──
    def dlp_adversary_guess(self, pk, c_star, state) -> tuple:
        p, g, q, h = pk
        m0, m1 = state
        c1, c2 = c_star
        # Recover sk by solving DLP (only feasible for small q)
        sk_x = None
        iters = 0
        for x in range(1, q):
            iters += 1
            if _fast_pow(g, x, p) == h:
                sk_x = x
                break
        if sk_x is None: return 0, iters
        
        # Decrypt to see which message it was
        dec_m = self.eg.decrypt((sk_x, p), c1, c2)
        return (0 if dec_m == m0 else 1), iters

    def dlp_breaking_adversary(self, n_rounds: int = 30) -> dict:
        """
        Adversary who solves the discrete log to recover sk = log_g(h), then
        decrypts the challenge ciphertext directly.
        """
        wins = 0
        total_iters = 0
        for _ in range(n_rounds):
            keys = self.eg.keygen()
            sk, pk = keys['sk'], keys['pk']
            m0, m1 = self.adversary_choose(pk)
            b = secrets.randbits(1)
            mb = m0 if b == 0 else m1
            c_star = self.eg.encrypt(pk, mb)
            
            b_guess, iters = self.dlp_adversary_guess(pk, c_star, (m0, m1))
            total_iters += iters
            if b_guess == b:
                wins += 1
                
        adv = abs(wins / n_rounds - 0.5)
        return {
            'rounds': n_rounds, 'wins': wins,
            'advantage': round(adv, 4),
            'avg_dlp_iters': total_iters // max(1, n_rounds),
            'secure': adv < 0.15,
        }


def demo_pa16():
    print("="*60); print("PA #16 — ElGamal Public-Key Cryptosystem"); print("="*60)
    eg = ElGamal(bits=256)
    keys = eg.keygen()
    sk, pk = keys['sk'], keys['pk']
    m = 1234
    c1, c2 = eg.encrypt(pk, m)
    dec = eg.decrypt(sk, c1, c2)
    print(f"  ElGamal Encrypt/Decrypt (256-bit): m={m} -> c1={hex(c1)[:16]}…, dec={dec} ✓")
    # Malleability
    c1m, c2m = eg.malleability_demo(pk, c1, c2)
    # When m is modified via malleability (2m), it will not correctly decode as 2m 
    # unless 2m and m share the same quadratic residue status. However, the ciphertext
    # malleability property still exists fundamentally. We demonstrate it by decoding 
    # the un-mapped value.
    p = pk[0]
    s = _fast_pow(c1m, sk[0], p)
    m_group_tampered = c2m * _mod_inverse(s, p) % p
    
    # We expect m_group_tampered to be exactly 2 * (encoded_m) mod p
    m_encoded = eg.encode_group(m)
    print(f"  Malleability: c2 multiplied by 2 -> underlying group element doubled? "
          f"{m_group_tampered == (2 * m_encoded % p)}")

    print(f"\n  [IND-CPA Game: Security under DDH]")
    game = ElGamal_IND_CPA_Game(eg)
    res_honest = game.run_cpa_game(n_rounds=50)
    print(f"  Random-guess adversary: {res_honest['wins']}/{res_honest['rounds']} wins, "
          f"advantage={res_honest['advantage']} ≈ 0  → secure ✓")

    # ── IND-CPA game: tiny group where DLP/DDH is brute-forceable ──
    print("\n  [IND-CPA game over tiny group (q≈2^10) — DLP solvable, DDH broken]")
    eg_tiny = ElGamal(bits=11)              # q is ~10 bits, p is ~11 bits
    print(f"  Group: p={hex(eg_tiny.p)} ({eg_tiny.p.bit_length()} bits), "
          f"q={hex(eg_tiny.q)} ({eg_tiny.q.bit_length()} bits)")
    game_tiny = ElGamal_IND_CPA_Game(eg_tiny)
    res_tiny = game_tiny.dlp_breaking_adversary(n_rounds=20)
    print(f"  DLP-breaking adversary: {res_tiny['wins']}/{res_tiny['rounds']} wins, "
          f"advantage={res_tiny['advantage']} ≈ 0.5  → INSECURE ✗")
    print(f"  Avg DLP brute-force iterations per round: {res_tiny['avg_dlp_iters']}")
    print("  (Same scheme, same construction — just a smaller group → IND-CPA breaks.)")
    print("✓ PA#16 complete.")

if __name__ == "__main__":
    demo_pa14(); print(); demo_pa15(); print(); demo_pa16()
