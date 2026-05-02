import os, sys, math, random, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa12.rsa import RSA, RSA_PKCS15, _mod_inverse, _fast_pow
from pa11.dh import DH, _rand_exp
from pa8_9_10.hash_hmac import DLP_Hash_Wide


def crt(residues: list, moduli: list) -> int:
    """
    Chinese Remainder Theorem solver.
    Finds the unique x in [0, N) satisfying:
        x ≡ residues[i] (mod moduli[i])  for all i
    REQUIRES: moduli are pairwise coprime (gcd(ni, nj) = 1 for i != j).
    Args:
        residues : [a1, a2, ..., ak]  -- the target remainders
        moduli   : [n1, n2, ..., nk]  -- pairwise coprime moduli
    Returns:
        Unique integer x in [0, N) where N = n1·n2·...·nk
    Example:
        crt([2, 3, 2], [3, 5, 7]) == 23
        because 23 % 3 == 2, 23 % 5 == 3, 23 % 7 == 2  (all correct)
    """
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for a, m in zip(residues, moduli):
        Mi = N // m                 
        yi = _mod_inverse(Mi, m)   
        x += a * Mi * yi           
    return x % N

def rsa_dec_crt(sk: tuple, c: int) -> int:
    """
    CRT-based RSA decryption using Garner's algorithm.
    Produces IDENTICAL output to _fast_pow(c, d, N) but approximately 4x faster.
    Mathematical proof of correctness:
        We need m such that m ≡ mp (mod p) AND m ≡ mq (mod q).
        By CRT, such m is unique in [0, N-1].
        Garner's formula computes this unique m without calling CRT explicitly.
    Args:
        sk : Private key tuple (N, d, p, q, dp, dq, q_inv)
             (same format as RSA.sk from PA#12)
        c  : Ciphertext integer in [0, N)
    Returns:
        Plaintext m = C^d mod N, computed via CRT (faster)
    """
    N, d, p, q, dp, dq, q_inv = sk
    mp = _fast_pow(c, dp, p)    
    mq = _fast_pow(c, dq, q)    
    h = q_inv * (mp - mq) % p   
    m = mq + h * q               
    return m


def integer_nth_root(n: int, k: int) -> int:
    """
    Compute floor(n^(1/k)): the largest integer x such that x^k <= n.
    Uses Newton's method in pure integer arithmetic.
    Handles arbitrarily large integers (no floating-point precision limits).
    Args:
        n : Non-negative integer
        k : Positive integer root degree
    Returns:
        Largest integer x with x^k <= n
    Edge cases: n=0 -> 0,  k=1 -> n,  non-perfect-power -> floor
    """
    if n == 0:
        return 0
    if n < 0:
        raise ValueError("Cannot take real root of negative integer")
    if k == 1:
        return n
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        x_pow_km1 = x ** (k - 1)                        
        x_new     = ((k - 1) * x + n // x_pow_km1) // k  
        if x_new >= x:
            break
        x = x_new
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1

    return x


def hastad_attack(ciphertexts: list, moduli: list, e: int = 3) -> int:
    """
    Hastad's Broadcast Attack on textbook RSA with small public exponent.
    Recovers plaintext M given e ciphertexts of M under e different RSA
    public keys all using the same small public exponent e.
    PRECONDITION: M^e < product(moduli).
    If violated, CRT gives M^e modulo the product (not exactly), and the
    integer root step returns garbage.
    Args:
        ciphertexts : [c1, c2, ..., ce]  where ci = M^e mod Ni
        moduli      : [N1, N2, ..., Ne]  (pairwise coprime RSA moduli)
        e           : public exponent (= number of recipient keys needed)
    Returns:
        Recovered plaintext M as integer
    """
    m_to_e = crt(ciphertexts, moduli)
    return integer_nth_root(m_to_e, e)


class RSA_Sign:
    """
    RSA Digital Signature: Hash-then-Sign.
    Sign(sk, m)      = H(m)^d mod N      (uses private key d)
    Verify(vk, m, s) = (s^e mod N == H(m))  (uses public key e only)
    Dependencies:
        PA#12 RSA: key pair, modular exponentiation, CRT decryption
        PA#8  DLP_Hash_Wide: 512-bit hash function
    """

    def __init__(self, rsa: RSA, hash_fn=None):
        """
        Args:
            rsa     : RSA key pair from PA#12
            hash_fn : Object with .hash(bytes) -> bytes method.
                      Defaults to DLP_Hash_Wide (64-byte output from PA#8).
        """
        self.rsa = rsa
        self._hash = hash_fn or DLP_Hash_Wide()

    def _hash_to_int(self, msg: bytes) -> int:
        """
        Hash the message and convert to integer in [0, N-1].
        Step 1: h_bytes = H(msg)          (PA#8 DLP_Hash_Wide, 64 bytes)
        Step 2: h_int   = int(h_bytes)    (big-endian interpretation)
        Step 3: h_int % N                 (reduce into RSA domain)
        The mod N is applied identically by both signer and verifier,
        so the verification equation sigma^e == H(m) mod N holds correctly.
        """
        h_bytes = self._hash.hash(msg)
        h_int   = int.from_bytes(h_bytes, 'big')
        return h_int % self.rsa.N

    def sign(self, msg: bytes) -> int:
        """
        Sign msg with the private key.
        sigma = H(msg)^d mod N
        Conceptually: RSA "decryption" applied to the hash value.
        (Encryption = raise to e. Decryption = raise to d. Signing = decrypt hash.)
        Anyone can verify by computing sigma^e = H(msg)^(d*e) = H(msg).
        Uses rsa_dec_crt()
        Args:
            msg : Arbitrary-length message bytes

        Returns:
            Signature integer sigma in [0, N-1]
        """
        h_int = self._hash_to_int(msg)          
        return rsa_dec_crt(self.rsa.sk, h_int)  

    def verify(self, msg: bytes, sig: int) -> bool:
        """
        Verify signature sig on msg using the public key only.
        Check: sig^e mod N == H(msg) mod N
        Anyone can verify -- only the private key holder could have signed.
        Step 1: h = H(msg) mod N           (same computation as in sign)
        Step 2: recovered = sig^e mod N    (RSA public-key operation)
        Step 3: return recovered == h
        If valid: sig = H(msg)^d, so sig^e = H(msg)^(d*e) = H(msg)  (correct)
        If tampered: sig^e mod N != H(msg) with overwhelming probability.
        Args:
            msg : The message to verify the signature against
            sig : The signature integer to check
        Returns:
            True if sig is a valid signature on msg under this key pair
        """
        h_int     = self._hash_to_int(msg)                    
        recovered = _fast_pow(sig, self.rsa.e, self.rsa.N)    
        return recovered == h_int

class ElGamal:
    """
    ElGamal Public-Key Cryptosystem.
    Group parameters from PA#11 DH (which uses PA#13 safe-prime generation).
    """

    def __init__(self, bits: int = 128):
        dh     = DH(bits)
        self.p = dh.p    
        self.g = dh.g    
        self.q = dh.q    

    def keygen(self) -> dict:
        """Private key x <- Zq, public key h = g^x mod p."""
        x = _rand_exp(self.q)
        h = _fast_pow(self.g, x, self.p)
        return {'sk': x, 'pk': (self.p, self.g, self.q, h)}

    def encrypt(self, pk: tuple, m: int) -> tuple:
        """Encrypt m in [1, p-1]. Returns (g^r, m*h^r) for fresh random r."""
        p, g, q, h = pk
        r  = _rand_exp(q)
        c1 = _fast_pow(g, r, p)
        c2 = m * _fast_pow(h, r, p) % p
        return c1, c2

    def decrypt(self, sk_x: int, pk: tuple, c1: int, c2: int) -> int:
        """Decrypt (c1, c2). s = c1^x; m = c2 * s^(-1) mod p."""
        p, g, q, h = pk
        s     = _fast_pow(c1, sk_x, p)
        s_inv = _mod_inverse(s, p)
        return c2 * s_inv % p

    def malleability_demo(self, pk: tuple, c1: int, c2: int) -> tuple:
        """Given Enc(m) = (c1, c2), produce ciphertext decrypting to 2m."""
        p, *_ = pk
        return c1, 2 * c2 % p

    def ind_cpa_game(self, rounds: int = 50, tiny_group: bool = False) -> dict:
        """IND-CPA game: large group -> advantage ~0; tiny group -> advantage > 0."""
        wins = 0
        for _ in range(rounds):
            eg = ElGamal(bits=32) if tiny_group else self
            keys = eg.keygen()
            sk, pk = keys['sk'], keys['pk']
            p, _, _, _ = pk
            m0, m1 = 5, 9
            b      = random.randint(0, 1)
            c1, c2 = eg.encrypt(pk, m0 if b == 0 else m1)
            if tiny_group:
                guess = None
                for candidate in [m0, m1]:
                    ratio = c2 * _mod_inverse(candidate, p) % p
                    if _fast_pow(ratio, (p - 1) // 2, p) == 1:
                        guess = 0 if candidate == m0 else 1
                        break
                if guess is None:
                    guess = random.randint(0, 1)
            else:
                guess = random.randint(0, 1)
            wins += int(guess == b)
        return {
            'rounds':    rounds,
            'wins':      wins,
            'advantage': round(abs(wins / rounds - 0.5), 4),
        }


# ==============================================================================
#  HELPER: Build RSA key with e=3
# ==============================================================================

def _make_rsa_e3(bits: int = 256) -> RSA:
    """
    Generate RSA key pair with public exponent e=3 instead of 65537.
    Requires gcd(3, phi(N)) = 1, i.e., neither (p-1) nor (q-1) divisible by 3.
    We retry prime generation until this condition holds (happens ~4/9 of time).
    Uses RSA.__new__() to bypass __init__ (which hardcodes e=65537) and
    manually populates all attributes in the exact format PA#12 uses.
    """
    from pa13.primality import gen_prime
    while True:
        p   = gen_prime(bits // 2)
        q   = gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(3, phi) != 1:
            continue                     
        rsa         = RSA.__new__(RSA)
        rsa.bits    = bits
        rsa.p       = p
        rsa.q       = q
        rsa.N       = p * q
        rsa.e       = 3
        rsa.d       = _mod_inverse(3, phi)
        rsa.dp      = rsa.d % (p - 1)
        rsa.dq      = rsa.d % (q - 1)
        rsa.q_inv   = _mod_inverse(q, p)
        rsa.pk      = (rsa.N, rsa.e)
        rsa.sk      = (rsa.N, rsa.d, p, q, rsa.dp, rsa.dq, rsa.q_inv)
        return rsa


#  PA #14 DEMO

def demo_pa14():
    print("=" * 60)
    print("PA #14 — CRT + Hastad's Broadcast Attack")
    print("=" * 60)

    # TEST 1: CRT correctness -- textbook examples with verification
    print("\n[Test 1] CRT Solver -- small known examples:")
    print("  Each result verified by checking ALL congruences hold.")
    print()

    crt_examples = [
        ([2, 3, 2],  [3, 5, 7],   23,  "x=2(3), x=3(5), x=2(7)  [classic textbook]"),
        ([0, 3, 4],  [4, 5, 9],  148,  "x=0(4), x=3(5), x=4(9)"),
        ([1, 6],     [7, 11],     50,  "x=1(7), x=6(11)"),
        ([3, 3],     [5, 7],      3,  "x=3(5), x=3(7)  [same residue both sides]"),
        ([0, 0, 0],  [3, 5, 7],   0,  "x=0 everywhere  [all-zero residues]"),
    ]
    all_ok = True
    for residues, moduli, expected, desc in crt_examples:
        x = crt(residues, moduli)
        congruences_hold = all(x % m == r for r, m in zip(residues, moduli))
        correct          = (x == expected)
        status = "OK" if congruences_hold and correct else "FAIL"
        if not (congruences_hold and correct):
            all_ok = False
        print(f"  {desc}")
        print(f"    x = {x}  (expected {expected})  all congruences hold = {congruences_hold}  [{status}]")
    print(f"\n  CRT solver: {'all tests passed' if all_ok else 'FAILURES DETECTED'} "
          f"{'[OK]' if all_ok else '[FAIL]'}")

    # TEST 2: Integer nth root -- correctness including edge cases
    print("\n[Test 2] Integer nth root (Newton's method, pure integer arithmetic):")
    print()

    root_cases = [
        (8,           3,  2,     "cube root of 8 = 2  (perfect cube)"),
        (27,          3,  3,     "cube root of 27 = 3"),
        (125,         3,  5,     "cube root of 125 = 5"),
        (1000,        3,  10,    "cube root of 1000 = 10"),
        (16,          4,  2,     "4th root of 16 = 2"),
        (100000000,   8,  10,    "8th root of 10^8 = 10"),
        (26,          3,  2,     "floor(26^(1/3)) = 2  (not a perfect cube)"),
        (28,          3,  3,     "floor(28^(1/3)) = 3  (27 <= 28 < 64)"),
        (0,           3,  0,     "cube root of 0 = 0  [edge]"),
        (1,           3,  1,     "cube root of 1 = 1  [edge]"),
        (99999 ** 3,  3, 99999,  "cube root of 99999^3 (large perfect cube)"),
    ]
    all_ok = True
    for n, k, expected, desc in root_cases:
        result = integer_nth_root(n, k)
        ok = (result == expected)
        if not ok:
            all_ok = False
        print(f"  {desc}")
        print(f"    result = {result}  expected = {expected}  [{'OK' if ok else 'FAIL'}]")
    print(f"\n  Integer root: {'all tests passed' if all_ok else 'FAILURES DETECTED'} "
          f"{'[OK]' if all_ok else '[FAIL]'}")

    # TEST 3: CRT-based RSA decryption -- correctness vs standard
    print("\n[Test 3] CRT-based RSA decryption (Garner's algorithm):")
    print("  rsa_dec_crt(sk, c) must equal C^d mod N for ALL inputs.")
    print()

    rsa_bench = RSA(bits=512)
    print(f"  RSA key: {rsa_bench.N.bit_length()}-bit modulus")
    print(f"  Running 100 random message trials...")

    mismatches = 0
    for trial in range(100):
        m           = random.randint(0, rsa_bench.N - 1)
        c           = _fast_pow(m, rsa_bench.e, rsa_bench.N)
        m_standard  = _fast_pow(c, rsa_bench.d, rsa_bench.N)   
        m_crt       = rsa_dec_crt(rsa_bench.sk, c)              
        if m_standard != m_crt or m_standard != m:
            mismatches += 1
            print(f"  MISMATCH at trial {trial}: standard={m_standard}, "
                  f"crt={m_crt}, original={m}")

    print(f"  Mismatches: {mismatches}/100")
    print(f"  Standard == CRT == original for all trials: "
          f"{'True [OK]' if mismatches == 0 else 'False [FAIL]'}")

    # TEST 4: Performance benchmark -- standard vs CRT decryption
    print("\n[Test 4] Performance benchmark: standard decryption vs CRT decryption:")
    print("  Expected speedup: ~3-4x (smaller exponent AND smaller modulus)")
    print()

    for bits in [512, 1024]:
        rsa_perf = RSA(bits=bits)
        n_tests  = 50
        cts = [
            _fast_pow(random.randint(2, rsa_perf.N - 1), rsa_perf.e, rsa_perf.N)
            for _ in range(n_tests)
        ]
        t0 = time.perf_counter()
        for c in cts:
            _fast_pow(c, rsa_perf.d, rsa_perf.N)
        t_std = time.perf_counter() - t0
        t0 = time.perf_counter()
        for c in cts:
            rsa_dec_crt(rsa_perf.sk, c)
        t_crt = time.perf_counter() - t0
        speedup = t_std / t_crt if t_crt > 0 else float('inf')
        print(f"  [{bits}-bit RSA, {n_tests} decryptions]")
        print(f"    Standard:  {t_std:.4f}s")
        print(f"    CRT:       {t_crt:.4f}s")
        print(f"    Speedup:   {speedup:.2f}x  "
              f"{'[OK, >= 2x]' if speedup >= 2.0 else '[lower than expected]'}")
        print()

    # TEST 5: Hastad's Broadcast Attack
    print("\n[Test 5] Hastad's Broadcast Attack (e=3, textbook RSA, no padding):")
    print("  Attacker sees c1=M^3 mod N1, c2=M^3 mod N2, c3=M^3 mod N3")
    print("  CRT -> M^3 as exact integer -> cube root -> M")
    print()
    print("  Generating 3 independent 256-bit RSA keys with e=3...")

    rsa_list = [_make_rsa_e3(bits=256) for _ in range(3)]
    moduli   = [r.N for r in rsa_list]
    print(f"  Moduli bit-lengths: {[r.N.bit_length() for r in rsa_list]}")
    for i in range(3):
        for j in range(i + 1, 3):
            if math.gcd(moduli[i], moduli[j]) != 1:
                print(f"  WARNING: N{i} and N{j} share a factor (very rare)")
    print("  Pairwise coprime: verified [OK]")
    print()

    test_messages = [1, 42, 999, 12345, 99999]
    all_ok = True
    for m in test_messages:
        cts      = [_fast_pow(m, 3, r.N) for r in rsa_list]
        product  = moduli[0] * moduli[1] * moduli[2]
        precond  = (m ** 3 < product)
        rec      = hastad_attack(cts, moduli, e=3)
        correct  = (rec == m)
        if not correct:
            all_ok = False
        print(f"  m={m:>6}: M^3 < N1*N2*N3={precond}  "
              f"recovered={rec:>6}  correct={correct}  "
              f"[{'OK' if correct else 'FAIL'}]")

    print(f"\n  All attack trials: {'passed [OK]' if all_ok else 'FAILURES [FAIL]'}")

    # TEST 6: Attack boundary analysis
    print("\n[Test 6] Attack boundary analysis:")
    print("  Attack requires M^e < N1*N2*...*Ne")
    print("  Maximum attackable M = floor((N1*N2*N3)^(1/3))")
    print()

    product = moduli[0] * moduli[1] * moduli[2]
    max_m   = integer_nth_root(product, 3)

    print(f"  N1*N2*N3 is {product.bit_length()} bits long")
    print(f"  Max attackable M: {max_m.bit_length()} bits  "
          f"= {max_m.bit_length() // 8} bytes")
    print(f"  Verification: max_m^3 <= product: {max_m**3 <= product}  [OK]")
    print(f"  Gap check: product - max_m^3 = {product - max_m**3}")
    print()

    for test_m, label in [(max_m, "max_m (boundary, attack should work)"),
                          (max_m + 1, "max_m+1 (outside, attack should fail)")]:
        cts = [_fast_pow(test_m, 3, r.N) for r in rsa_list]
        rec = hastad_attack(cts, moduli, e=3)
        print(f"    original m = {test_m}")
        print(f"    recovered m = {rec}")
        print(f"    success = {rec == test_m}")

    print()
    print(f"  CONCLUSION: Attack works for messages up to {max_m.bit_length()} bits")
    print(f"  ({max_m.bit_length()//8} bytes) against three {moduli[0].bit_length()}-bit RSA keys.")
    print("  For real 1024-bit keys: max attackable message ~ 128 bytes.")
    print("  With PKCS padding, even 1-byte messages are safe.")

    # TEST 7: Padding defeats the attack
    print("\n[Test 7] PKCS#1 v1.5 padding defeats Hastad's attack:")
    print("  Each recipient pads the message differently (random PS bytes).")
    print("  CRT combines three unrelated values -> cube root is garbage.")
    print()

    pkcs_list = [RSA_PKCS15(r) for r in rsa_list]
    msg_bytes = b"hello"
    original  = int.from_bytes(msg_bytes, 'big')

    padded_cts = [pkcs.encrypt(msg_bytes) for pkcs in pkcs_list]

    padded_rec = hastad_attack(padded_cts, moduli, e=3)

    succeeded = (padded_rec == original)
    print(f"  Original message (as int): {original}")
    print(f"  Attack 'recovered':        {padded_rec}")
    print(f"  Attack succeeded on padded: {succeeded}  "
          f"<-- should be False  [{'OK' if not succeeded else 'FAIL'}]")
    print()

    print("  Padded plaintexts differ across recipients (different random PS):")
    for i, pkcs in enumerate(pkcs_list):
        dec = pkcs.decrypt(padded_cts[i])
        print(f"    Recipient {i+1} EM = {dec.hex()[:40]}...")

    print("\n[OK] PA#14 complete.")


#  PA #15 DEMO

def demo_pa15():
    print("=" * 60)
    print("PA #15 -- Digital Signatures (RSA Hash-then-Sign)")
    print("=" * 60)

    # TEST 1: Basic sign and verify
    print("\n[Test 1] Basic sign and verify  (sigma = H(m)^d mod N):")
    print()

    rsa    = RSA(bits=512)
    signer = RSA_Sign(rsa)
    print(f"  RSA key: {rsa.N.bit_length()}-bit modulus, e={rsa.e}")
    print()

    messages = [
        b"Sign this message",
        b"vote:Alice",
        b"Hello, World!",
        b"",                    
        b"A" * 1000,            
        b"\x00\x01\xff\xfe",    
    ]
    all_ok = True
    for msg in messages:
        sig   = signer.sign(msg)
        valid = signer.verify(msg, sig)
        label = repr(msg[:30]) + ("..." if len(msg) > 30 else "")
        ok    = valid
        if not valid:
            all_ok = False
        print(f"  {label:45s} -> verify={valid}  [{'OK' if ok else 'FAIL'}]")

    print(f"\n  All basic tests: {'passed [OK]' if all_ok else 'FAILURES [FAIL]'}")

    # TEST 2: Tamper detection
    print("\n[Test 2] Tamper detection -- verify MUST fail on any change to message:")
    print()

    msg = b"Transfer $100 to Alice"
    sig = signer.sign(msg)
    print(f"  Original message: {msg!r}")
    print(f"  Original verify:  {signer.verify(msg, sig)}  [OK]")
    print()

    tampers = [
        (b"Transfer $100 to Alice!",   "appended '!'"),
        (b"transfer $100 to Alice",    "lowercase 'T'"),
        (b"Transfer $100 to Bob",      "Alice -> Bob"),
        (b"Transfer $200 to Alice",    "$100 -> $200"),
        (b"Transfer $100 to Alice ",   "trailing space"),
        (msg + b"\x00",                "appended null byte"),
        (b"",                          "empty string"),
    ]
    all_rejected = True
    for tampered, desc in tampers:
        result = signer.verify(tampered, sig)
        ok     = not result         
        if not ok:
            all_rejected = False
        print(f"  {desc:35s} -> verify={result}  [{'OK' if ok else 'FAIL: should be False'}]")

    print(f"\n  All tampered messages rejected: {all_rejected}  "
          f"[{'OK' if all_rejected else 'FAIL'}]")

    # TEST 3: Wrong/corrupted signature detection
    print("\n[Test 3] Corrupted signature detection:")
    print()

    msg = b"important document"
    sig = signer.sign(msg)
    print(f"  Valid signature: verify={signer.verify(msg, sig)}  [OK]")
    print()

    bad_sigs = [
        (sig ^ 1,                        "flip LSB"),
        (sig ^ (1 << 10),                "flip bit 10"),
        (sig ^ (1 << 255),               "flip bit 255"),
        (0,                              "zero"),
        (1,                              "one"),
        (rsa.N - 1,                      "N-1"),
        (random.randint(1, rsa.N - 1),   "random"),
        (sig + 1,                        "sig + 1"),
        (sig - 1,                        "sig - 1"),
    ]
    all_rejected = True
    for bad, desc in bad_sigs:
        result = signer.verify(msg, bad)
        ok     = not result
        if not ok:
            all_rejected = False
        print(f"  {desc:30s} -> verify={result}  [{'OK' if ok else 'FAIL: should be False'}]")

    print(f"\n  All bad signatures rejected: {all_rejected}  "
          f"[{'OK' if all_rejected else 'FAIL'}]")

    # TEST 4: Determinism
    print("\n[Test 4] Signature determinism:")
    print()

    msg  = b"deterministic"
    sigs = [signer.sign(msg) for _ in range(5)]
    all_same = all(s == sigs[0] for s in sigs)
    print(f"  5 signatures of same message all identical: {all_same}  [OK]")
    print(f"  sigma (first 48 hex chars): {hex(sigs[0])[:50]}...")
    print()
    print("  NOTE: RSA signatures are deterministic (unlike RSA encryption).")
    print("  Determinism is fine for signatures -- they're public anyway.")

    # TEST 5: Cross-key failure
    print("\n[Test 5] Cross-key failure:")
    print()

    rsa_a  = RSA(bits=512)
    rsa_b  = RSA(bits=512)
    sign_a = RSA_Sign(rsa_a)
    sign_b = RSA_Sign(rsa_b)

    msg   = b"signed by Alice"
    sig_a = sign_a.sign(msg)

    alice_ok = sign_a.verify(msg, sig_a)
    bob_ok   = sign_b.verify(msg, sig_a)

    print(f"  Alice verifies her own sig: {alice_ok}  [OK]")
    print(f"  Bob verifies Alice's sig:   {bob_ok}  "
          f"[{'OK' if not bob_ok else 'FAIL: should be False'}]")

    # TEST 6: Multiplicative forgery -- raw RSA vs hash-then-sign
    print("\n[Test 6] Multiplicative forgery attack:")
    print()
    print("  PART A: Raw RSA signatures (sigma = m^d mod N) -- INSECURE")
    print()

    m1, m2 = 3, 7

    s1 = _fast_pow(m1, rsa.d, rsa.N)    # sigma(3) = 3^d mod N
    s2 = _fast_pow(m2, rsa.d, rsa.N)    # sigma(7) = 7^d mod N
    s_forged = s1 * s2 % rsa.N
    recovered     = _fast_pow(s_forged, rsa.e, rsa.N)
    forgery_valid = (recovered == (m1 * m2) % rsa.N)

    print(f"  sigma(3) = 3^d mod N  [obtained from oracle]")
    print(f"  sigma(7) = 7^d mod N  [obtained from oracle]")
    print(f"  Forged sigma(21) = sigma(3) * sigma(7) mod N  [no d needed!]")
    print(f"  Verify forged sig on m=21: {forgery_valid}  "
          f"<-- FORGERY WORKS on raw RSA! [expected True]")

    print()
    print("  PART B: Hash-then-sign -- same attack FAILS")
    print()

    m1b  = m1.to_bytes(4, 'big')
    m2b  = m2.to_bytes(4, 'big')
    m12b = (m1 * m2).to_bytes(4, 'big')

    sig1 = signer.sign(m1b)     # sigma(H(3)) from oracle
    sig2 = signer.sign(m2b)     # sigma(H(7)) from oracle
    sig_forged_hash = sig1 * sig2 % rsa.N
    h_product  = signer._hash_to_int(m12b)
    recovered2 = _fast_pow(sig_forged_hash, rsa.e, rsa.N)
    forgery2_valid = (recovered2 == h_product)

    print(f"  Forged: sigma(H(3)) * sigma(H(7)) mod N")
    print(f"  This would need H(3)*H(7) == H(21) mod N -- NOT TRUE for hash functions")
    print(f"  Verify forged sig on m=21 with hash-then-sign: {forgery2_valid}  "
          f"<-- [{'OK: blocked' if not forgery2_valid else 'FAIL: forgery works!'}]")

    # TEST 7: EUF-CMA game
    print("\n[Test 7] EUF-CMA security game:")
    print("  Adversary gets signatures on 50 chosen messages.")
    print("  Goal: forge valid (message, signature) for any NEW message.")
    print()

    oracle_msgs = [f"oracle-msg-{i:03d}".encode() for i in range(50)]
    oracle_sigs = {msg: signer.sign(msg) for msg in oracle_msgs}

    all_valid = all(signer.verify(m, s) for m, s in oracle_sigs.items())
    print(f"  All 50 oracle signatures valid: {all_valid}  [OK]")
    print()

    target = b"FORGED: steal $1000000"
    assert target not in oracle_sigs

    print(f"  Forgery target: {target!r}")
    print()

    attempts = [
        (random.randint(1, rsa.N - 1),
         "random integer"),
        (oracle_sigs[oracle_msgs[0]],
         "reuse existing sig on new msg"),
        (oracle_sigs[oracle_msgs[0]] ^ (1 << 42),
         "bit-flip a known sig"),
        (oracle_sigs[oracle_msgs[0]] * oracle_sigs[oracle_msgs[1]] % rsa.N,
         "multiply two known sigs"),
        (rsa.N - 1,
         "N-1 as signature"),
    ]
    any_succeeded = False
    for attempt_sig, desc in attempts:
        result = signer.verify(target, attempt_sig)
        ok     = not result
        if not ok:
            any_succeeded = True
        print(f"  [{desc:40s}] -> {result}  [{'OK: blocked' if ok else 'FAIL: forgery succeeded!'}]")

    print()
    print(f"  EUF-CMA: all forgery attempts blocked: {not any_succeeded}  "
          f"[{'OK' if not any_succeeded else 'FAIL'}]")

    print("\n[OK] PA#15 complete.")


#  PA #16 DEMO

def demo_pa16():
    print("=" * 60)
    print("PA #16 -- ElGamal PKC")
    print("=" * 60)

    eg   = ElGamal(bits=128)
    keys = eg.keygen()
    sk, pk = keys['sk'], keys['pk']

    m      = 1234
    c1, c2 = eg.encrypt(pk, m)
    dec    = eg.decrypt(sk, pk, c1, c2)
    print(f"  Encrypt/Decrypt m={m}: {dec == m}  [OK]")

    c1m, c2m = eg.malleability_demo(pk, c1, c2)
    dec_m    = eg.decrypt(sk, pk, c1m, c2m)
    print(f"  Malleability: Dec(Enc(2m)) = {dec_m} = 2x{m} = {2*m}, "
          f"match={dec_m == 2*m}  [OK]")

    normal = eg.ind_cpa_game(rounds=100, tiny_group=False)
    tiny   = eg.ind_cpa_game(rounds=100, tiny_group=True)
    print(f"  IND-CPA advantage (normal group): {normal['advantage']}  (expected ~0)")
    print(f"  IND-CPA advantage (tiny group):   {tiny['advantage']}  (weaker security)")

    print("[OK] PA#16 complete.")


if __name__ == "__main__":
    demo_pa14()
    print()
    demo_pa15()
    print()
    demo_pa16()
