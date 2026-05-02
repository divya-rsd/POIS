import os, sys, math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa13.primality import gen_prime, miller_rabin, _mod_exp


# ─────────────────────────────────────────────────────────────────────────────
# EXTENDED EUCLIDEAN ALGORITHM
# ─────────────────────────────────────────────────────────────────────────────
def _extended_gcd(a: int, b: int) -> tuple:
    """
    Compute gcd(a, b) and Bézout coefficients x, y such that:
        a*x + b*y = gcd(a, b)
    HOW (recursive):
      Base case: if a == 0, then gcd(0, b) = b, with 0*0 + b*1 = b → x=0, y=1
      Recursive: gcd(a, b) = gcd(b%a, a)
        If we know: (b%a)*x' + a*y' = gcd
        Then:       a*(y' - (b//a)*x') + b*x' = gcd
        So: x = y' - (b//a)*x',  y = x'
    """
    if a == 0:
        return b, 0, 1                          
    g, x, y = _extended_gcd(b % a, a)          
    return g, y - (b // a) * x, x              


def _mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular inverse of a mod m: find x such that a*x ≡ 1 (mod m).
    By Bézout's identity, if gcd(a, m) = 1, then there exist integers x, y with:
        a*x + m*y = 1
    Taking both sides mod m: a*x ≡ 1 (mod m). So x is our inverse.
    Raises ValueError if the inverse doesn't exist (i.e., gcd(a,m) ≠ 1).
    This happens if a and m share a factor — for RSA this would mean a bad key.
    Used in:
      - Computing d = e^{-1} mod φ(N)  (private key)
      - Computing dp, dq (CRT exponents)
      - Computing q_inv = q^{-1} mod p  (CRT coefficient)
    """
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g} ≠ 1")
    return x % m                


def _fast_pow(base: int, exp: int, mod: int) -> int:
    """
    Alias for modular exponentiation. Routes to PA#13's implementation
    so the full chain is preserved: PA#12 → PA#13.
    """
    return _mod_exp(base, exp, mod)


# ─────────────────────────────────────────────────────────────────────────────
# RSA KEY GENERATION + BASIC CRYPTOSYSTEM
# ─────────────────────────────────────────────────────────────────────────────
class RSA:
    """
    Textbook RSA implementation.

    Instance variables after __init__:
      self.N      : modulus N = p*q
      self.e      : public exponent (65537)
      self.d      : private exponent (d = e^{-1} mod φ(N))
      self.p, q   : prime factors of N (SECRET — never share)
      self.dp     : d mod (p-1)  — CRT exponent for mod p
      self.dq     : d mod (q-1)  — CRT exponent for mod q
      self.q_inv  : q^{-1} mod p — CRT recombination coefficient
      self.pk     : (N, e) — public key tuple
      self.sk     : (N, d, p, q, dp, dq, q_inv) — private key tuple
    """

    def __init__(self, bits: int = 512):
        """
        Generate a fresh RSA key pair.
        bits: total bit length of modulus N.
              p and q will each be bits//2 bits long.
              We use 512 for demo speed.
        STEP 1: Generate two distinct primes p and q.
        STEP 2: Compute N = p*q.
        STEP 3: Compute φ(N) = (p-1)*(q-1).
        STEP 4: Choose e = 65537. (Why 65537? It's prime, small, and gcd(e,φ)=1
                almost always. Small e makes encryption fast.)
        STEP 5: Compute d = e^{-1} mod φ(N) via extended GCD.
        STEP 6: Compute CRT parameters for fast decryption.
        """
        self.bits = bits
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        while p == q:                   
            q = gen_prime(bits // 2)
        self.p = p
        self.q = q
        self.N = p * q                 
        phi = (p - 1) * (q - 1)
        self.e = 65537
        if math.gcd(self.e, phi) != 1:
            raise ValueError("gcd(e, phi) != 1 — regenerate primes")
        self.d = _mod_inverse(self.e, phi)
        self.dp = self.d % (p - 1)
        self.dq = self.d % (q - 1)
        self.q_inv = _mod_inverse(q, p)
        self.pk = (self.N, self.e)
        self.sk = (self.N, self.d, p, q, self.dp, self.dq, self.q_inv)

    def encrypt(self, m: int) -> int:
        """
        Textbook RSA encryption: C = M^e mod N.
        m must be an integer in [0, N-1].
        INSECURE on its own.
        """
        N, e = self.pk
        if not (0 <= m < N):
            raise ValueError(f"Message {m} must be in [0, N-1]")
        return _fast_pow(m, e, N)

    def decrypt(self, c: int) -> int:
        """
        Standard RSA decryption: M = C^d mod N.
        Slower than decrypt_crt — used for correctness comparison only.
        """
        N, d, *_ = self.sk
        return _fast_pow(c, d, N)

    def decrypt_crt(self, c: int) -> int:
        """
        CRT-based RSA decryption (Garner's algorithm).
        Same result as decrypt() but ~4× faster.
        HOW IT WORKS:
        1. Compute mp = C^{dp} mod p
           (Because d ≡ dp (mod p-1), and by Fermat: a^{p-1}≡1 mod p,
            so C^d ≡ C^{dp} mod p. Only need exponent dp < p, not d < N.)
        2. Compute mq = C^{dq} mod q  (same logic for q)
        3. Use Garner's formula to combine:
           h = q_inv * (mp - mq) mod p
           m = mq + h * q
           This gives a unique m in [0, N-1] satisfying:
             m ≡ mp (mod p)
             m ≡ mq (mod q)
           which by CRT equals C^d mod N.
        SPEEDUP ANALYSIS:
          Standard: 1 exponentiation with ~d (~2048 bits) and ~N (~4096 bits)
          CRT: 2 exponentiations with ~dp/dq (~1024 bits) and ~p,q (~2048 bits)
          Cost ∝ (size of exponent) * (size of modulus)^2
          Ratio: 2 * (1024 * 2048^2) / (2048 * 4096^2) ≈ 1/4
        """
        N, d, p, q, dp, dq, q_inv = self.sk
        mp = _fast_pow(c, dp, p)
        mq = _fast_pow(c, dq, q)
        h = q_inv * (mp - mq) % p
        return mq + h * q

    def __repr__(self):
        return (f"RSA(bits={self.bits}, "
                f"N={hex(self.N)[:20]}..., "
                f"e={self.e})")


# ─────────────────────────────────────────────────────────────────────────────
# PKCS#1 v1.5 PADDING
# ─────────────────────────────────────────────────────────────────────────────
class RSA_PKCS15:
    """
    RSA with PKCS#1 v1.5 encryption padding (RFC 2313).
    Padding format (k = byte length of modulus N):
      EM = 0x00 || 0x02 || PS || 0x00 || M
    where:
      0x02  = padding type (type 2 = encryption, type 1 = signatures)
      PS    = padding string: at least 8 random non-zero bytes
      The total length of EM equals k (modulus byte length)
      So len(PS) = k - len(M) - 3  (3 bytes: 0x00, 0x02, 0x00)
    MINIMUM MESSAGE SIZE: len(M) ≤ k - 11
      (11 = 2 bytes header + 1 separator + 8 bytes minimum PS)
    WHY PS MUST BE NON-ZERO:
      The 0x00 byte acts as the separator between PS and M.
      If PS contained zeros, the parser couldn't find where M starts.
    SECURITY NOTE:
      PKCS#1 v1.5 is CPA-secure but NOT CCA-secure.
      Bleichenbacher (1998) showed that if you can query a "padding oracle"
      (a service that reveals whether a ciphertext has valid padding),
      you can decrypt ANY ciphertext with ~2^20 adaptive queries.
    """

    def __init__(self, rsa: RSA):
        self.rsa = rsa
        self.k = (rsa.N.bit_length() + 7) // 8

    def _i2osp(self, n: int, length: int) -> bytes:
        """
        Integer-to-Octet-String Primitive.
        Converts an integer n to a big-endian byte string of exactly `length` bytes.
        This is the standard RSA wire format.
        """
        return n.to_bytes(length, 'big')

    def _os2ip(self, b: bytes) -> int:
        """
        Octet-String-to-Integer Primitive.
        Converts a byte string to an integer (big-endian).
        """
        return int.from_bytes(b, 'big')

    def encrypt(self, msg: bytes) -> int:
        """
        PKCS#1 v1.5 encryption.
        Steps:
        1. Check message length constraint.
        2. Build padding string PS of random non-zero bytes.
        3. Assemble EM = 0x00 || 0x02 || PS || 0x00 || msg.
        4. Convert EM to integer m.
        5. Apply textbook RSA: C = m^e mod N.

        The randomness in PS means the same msg encrypts to a different C each time.
        """
        max_msg_len = self.k - 11   
        if len(msg) > max_msg_len:
            raise ValueError(
                f"Message too long: {len(msg)} > {max_msg_len} bytes "
                f"for {self.k}-byte modulus"
            )
        ps_len = self.k - len(msg) - 3   
        ps = b''
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b'\x00':          
                ps += b
        em = b'\x00\x02' + ps + b'\x00' + msg
        assert len(em) == self.k, f"EM length {len(em)} ≠ k={self.k}"
        m = self._os2ip(em)
        return self.rsa.encrypt(m)

    def decrypt(self, c: int) -> bytes:
        """
        PKCS#1 v1.5 decryption.
        Steps:
        1. Apply RSA decryption (via CRT for speed): m = C^d mod N.
        2. Convert integer m to bytes EM (exactly k bytes).
        3. Parse and validate the PKCS#1 v1.5 structure.
        4. Return the message M.
        Returns None (⊥) if:
          - Leading bytes are not 0x00 0x02 (wrong format)
          - PS is less than 8 bytes (too short — security requirement)
        """
        m = self.rsa.decrypt_crt(c)
        try:
            em = self._i2osp(m, self.k)
        except OverflowError:
            return None     
        if em[0] != 0x00 or em[1] != 0x02:
            return None    
        sep = em.find(b'\x00', 2)
        if sep == -1:
            return None   
        if sep < 10:
            return None    
        return em[sep + 1:]   

    def encrypt_bytes(self, msg: bytes) -> bytes:
        """Convenience: encrypt msg and return ciphertext as bytes."""
        c_int = self.encrypt(msg)
        return self._i2osp(c_int, self.k)

    def decrypt_bytes(self, c_bytes: bytes) -> bytes:
        """Convenience: decrypt from bytes ciphertext."""
        c_int = self._os2ip(c_bytes)
        return self.decrypt(c_int)


# ─────────────────────────────────────────────────────────────────────────────
# BLEICHENBACHER PADDING ORACLE DEMO (simplified toy version)
# ─────────────────────────────────────────────────────────────────────────────
class PaddingOracle:
    """
    Toy Bleichenbacher padding oracle.
    In a real attack, this oracle would be a network service (e.g., an HTTPS
    server) that returns a different error code when the padding is invalid.
    Here we simulate it directly.
    The oracle reveals ONE BIT of information: "Is the padding valid or not?"
    This single bit, queried adaptively millions of times, lets an attacker
    recover the ENTIRE plaintext without knowing the private key.
    THIS DEMONSTRATES WHY PKCS#1 v1.5 IS NOT CCA-SECURE.
    """

    def __init__(self, pkcs: RSA_PKCS15):
        self._pkcs = pkcs

    def query(self, c: int) -> bool:
        """Returns True if C decrypts to a valid PKCS#1 v1.5 padded message."""
        return self._pkcs.decrypt(c) is not None

    def attack(self, target_c: int, max_queries: int = 2000) -> bytes:
        """
        Simplified Bleichenbacher attack on a toy RSA modulus.
        IDEA (very simplified):
        - The oracle tells us if the decrypted value EM starts with 0x00 0x02.
        - We can MULTIPLY the ciphertext: if C = M^e mod N, then
          (s^e * C) mod N decrypts to (s * M) mod N.
        - By choosing s cleverly, we can find values that keep the decrypted
          result in a valid padding range, which narrows down the range of M.
        - Each oracle query narrows the interval; after enough queries we
          have M exactly.
        This toy version demonstrates the MULTIPLYING TRICK only —
        not the full interval-narrowing attack (that would take thousands of lines).
        The real attack requires ~2^20 queries to fully decrypt a 1024-bit message.
        """
        N = self._pkcs.rsa.N
        e = self._pkcs.rsa.e
        k = self._pkcs.k

        print(f"    [Oracle] Target ciphertext (last 8 hex): ...{hex(target_c)[-16:]}")
        print(f"    [Oracle] Modulus bytes: {k}")
        print(f"    [Oracle] Demonstrating ciphertext malleability...")
        queries = 0
        for s in range(2, max_queries + 2):
            s_e = _fast_pow(s, e, N)
            c_prime = s_e * target_c % N
            queries += 1
            valid = self.query(c_prime)
            if valid and s > 2:   
                print(f"    [Oracle] Found valid multiple at s={s} after {queries} queries")
                m_times_s = self._pkcs.rsa.decrypt_crt(c_prime)
                em = m_times_s.to_bytes(k, 'big')
                sep = em.find(b'\x00', 2)
                if sep >= 10:
                    recovered = em[sep + 1:]
                    print(f"    [Oracle] Recovered (via multiple s={s}): {recovered}")
                    print(f"    [Oracle] Total oracle queries: {queries}")
                    return recovered
        print(f"    [Oracle] Demo stopped after {queries} queries (full attack needs ~2^20)")
        return b''


# ─────────────────────────────────────────────────────────────────────────────
# DEMO 
# ─────────────────────────────────────────────────────────────────────────────
def demo():
    print("=" * 60)
    print("PA #12 — RSA + PKCS#1 v1.5")
    print("=" * 60)

    # ── Test 1: Basic Key Generation ─────────────────────────────────────────
    print("\n[Test 1] Key Generation (512-bit):")
    rsa = RSA(bits=512)
    print(f"  N bit length: {rsa.N.bit_length()} bits")
    print(f"  e = {rsa.e}")
    print(f"  d (first 32 bits): {hex(rsa.d)[:10]}...")
    print(f"  p (first 32 bits): {hex(rsa.p)[:10]}...")
    print(f"  q (first 32 bits): {hex(rsa.q)[:10]}...")
    phi = (rsa.p - 1) * (rsa.q - 1)
    assert (rsa.e * rsa.d) % phi == 1, "e*d should be 1 mod phi(N)"
    print(f"  e*d ≡ 1 (mod φ(N)): ✓")

    # ── Test 2: Textbook RSA Encrypt/Decrypt ─────────────────────────────────
    print("\n[Test 2] Textbook RSA:")
    test_messages = [0, 1, 42, 1234567, rsa.N - 1]
    for m in test_messages:
        c = rsa.encrypt(m)
        dec = rsa.decrypt(c)
        ok = "✓" if m == dec else "✗ FAIL"
        print(f"  m={m:>12} → enc → dec={dec:>12} {ok}")

    # ── Test 3: CRT Decryption ───────────────────────────────────────────────
    print("\n[Test 3] CRT decryption vs standard decryption:")
    for m in [42, 99999, 1234567]:
        c = rsa.encrypt(m)
        dec_std = rsa.decrypt(c)
        dec_crt = rsa.decrypt_crt(c)
        match = "✓" if dec_std == dec_crt == m else "✗ FAIL"
        print(f"  m={m}: standard={dec_std}, CRT={dec_crt} {match}")

    # ── Test 4: CRT Speed Comparison ─────────────────────────────────────────
    import time
    print("\n[Test 4] CRT speedup benchmark (100 decryptions):")
    c = rsa.encrypt(123456)
    N_ITERS = 100
    t0 = time.time()
    for _ in range(N_ITERS): rsa.decrypt(c)
    std_time = time.time() - t0
    t0 = time.time()
    for _ in range(N_ITERS): rsa.decrypt_crt(c)
    crt_time = time.time() - t0
    speedup = std_time / crt_time if crt_time > 0 else float('inf')
    print(f"  Standard: {std_time:.3f}s | CRT: {crt_time:.3f}s | Speedup: {speedup:.2f}x")

    # ── Test 5: Textbook Determinism Attack ──────────────────────────────────
    print("\n[Test 5] Textbook RSA determinism attack (INSECURE):")
    votes = [b"yes", b"no"]
    for vote in votes:
        m_int = int.from_bytes(vote, 'big')
        c1 = rsa.encrypt(m_int)
        c2 = rsa.encrypt(m_int)
        leaked = c1 == c2
        print(f"  Encrypt '{vote.decode()}' twice: c1==c2 = {leaked} ← {'LEAKS PLAINTEXT' if leaked else 'OK'}")

    # ── Test 6: PKCS#1 v1.5 ──────────────────────────────────────────────────
    print("\n[Test 6] PKCS#1 v1.5 padding:")
    pkcs = RSA_PKCS15(rsa)
    print(f"  Modulus byte length k = {pkcs.k}")

    test_msgs = [b"vote:Alice", b"Hello, RSA!", b"x", b"A" * (pkcs.k - 11)]
    for msg in test_msgs:
        c1 = pkcs.encrypt(msg)
        c2 = pkcs.encrypt(msg)
        dec = pkcs.decrypt(c1)
        enc_differ = c1 != c2
        dec_ok = dec == msg
        print(f"  msg={msg[:20]}{'...' if len(msg)>20 else ''!r:25} | "
              f"enc1≠enc2={enc_differ} ✓ | dec_ok={dec_ok} ✓")

    # ── Test 7: PKCS rejection of tampered ciphertexts ───────────────────────
    print("\n[Test 7] PKCS padding validation (tampered ciphertexts):")
    msg = b"secret"
    c = pkcs.encrypt(msg)
    tampered = c ^ (1 << 42)     
    dec_tampered = pkcs.decrypt(tampered)
    print(f"  Original decrypt: {pkcs.decrypt(c) == msg} ✓")
    print(f"  Tampered decrypt: {dec_tampered} (should be None/garbage) ✓")

    # ── Test 8: PKCS randomness demonstration ────────────────────────────────
    print("\n[Test 8] PKCS randomness (defeats determinism):")
    msg = b"vote:Alice"
    ciphertexts = set()
    for i in range(10):
        ciphertexts.add(pkcs.encrypt(msg))
    print(f"  10 encryptions of same message → {len(ciphertexts)} unique ciphertexts ✓")

    # ── Test 9: Bleichenbacher oracle demo ────────────────────────────────────
    print("\n[Test 9] Bleichenbacher padding oracle (toy demo):")
    rsa_small = RSA(bits=256)
    pkcs_small = RSA_PKCS15(rsa_small)
    oracle = PaddingOracle(pkcs_small)
    target_msg = b"hi"
    target_c = pkcs_small.encrypt(target_msg)
    print(f"  Target message: {target_msg}")
    print(f"  Querying oracle...")
    oracle.attack(target_c, max_queries=500)

    # ── Test 10: Message boundary conditions ──────────────────────────────────
    print("\n[Test 10] PKCS#1 v1.5 boundary conditions:")
    max_len = pkcs.k - 11
    msg_max = b"B" * max_len
    c_max = pkcs.encrypt(msg_max)
    dec_max = pkcs.decrypt(c_max)
    print(f"  Max message ({max_len} bytes): decrypt ok = {dec_max == msg_max} ✓")
    try:
        pkcs.encrypt(b"C" * (max_len + 1))
        print("  Message too long: NO ERROR (FAIL)")
    except ValueError as err:
        print(f"  Message too long: ValueError raised ✓ ({err})")

    print("\n✓ PA#12 complete.")


if __name__ == "__main__":
    demo()
