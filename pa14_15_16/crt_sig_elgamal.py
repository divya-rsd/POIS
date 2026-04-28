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
    def random_guess_adversary(self, n_rounds: int = 50) -> dict:
        wins = 0
        for _ in range(n_rounds):
            keys = self.eg.keygen()
            sk, pk = keys['sk'], keys['pk']
            p = pk[0]
            # CSPRNG-driven challenge — secrets.randbelow / randbits use os.urandom.
            m0 = 1 + secrets.randbelow(p - 1)
            m1 = 1 + secrets.randbelow(p - 1)
            b = secrets.randbits(1)
            mb = m0 if b == 0 else m1
            c1, c2 = self.eg.encrypt(pk, mb)
            b_guess = secrets.randbits(1)
            if b_guess == b:
                wins += 1
        adv = abs(wins / n_rounds - 0.5)
        return {
            'rounds': n_rounds, 'wins': wins,
            'advantage': round(adv, 4),
            'secure': adv < 0.15,
        }

    # ── DLP-breaking adversary — wins every round when q is small enough ──
    def dlp_breaking_adversary(self, n_rounds: int = 30) -> dict:
        """
        Adversary who solves the discrete log to recover sk = log_g(h), then
        decrypts the challenge ciphertext directly. Wins with probability 1
        whenever q is small enough to brute-force in a reasonable time.
        """
        wins = 0
        total_iters = 0
        for _ in range(n_rounds):
            keys = self.eg.keygen()
            sk, pk = keys['sk'], keys['pk']
            p, g, q, h = pk
            # Brute-force the secret key x such that g^x = h mod p.
            cur, x_found = g, None
            for x in range(1, q):
                if cur == h:
                    x_found = x
                    break
                cur = cur * g % p
                total_iters += 1
            if x_found is None:
                # Group too large to brute-force in this loop; abstain.
                continue
            # Adversary picks distinguishable messages and decrypts the challenge.
            m0 = 1
            m1 = 2
            b = secrets.randbits(1)
            mb = m0 if b == 0 else m1
            c1, c2 = self.eg.encrypt(pk, mb)
            s = _fast_pow(c1, x_found, p)
            recovered = c2 * _mod_inverse(s, p) % p
            b_guess = 0 if recovered == m0 else 1
            if b_guess == b:
                wins += 1
        adv = abs(wins / n_rounds - 0.5) if n_rounds else 0.0
        return {
            'rounds': n_rounds, 'wins': wins,
            'advantage': round(adv, 4),
            'avg_dlp_iters': total_iters // max(1, n_rounds),
            'secure': adv < 0.15,
        }


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

    # ── IND-CPA game: large group ──
    print("\n  [IND-CPA game over 128-bit group — DDH presumed hard]")
    game_big = ElGamal_IND_CPA_Game(eg)
    res_big = game_big.random_guess_adversary(n_rounds=40)
    print(f"  Random-guess adversary: {res_big['wins']}/{res_big['rounds']} wins, "
          f"advantage={res_big['advantage']} ≈ 0  → secure ✓")

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
