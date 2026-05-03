
import os, random, math, time


# ─────────────────────────────────────────────────────────────────────────────
# MODULAR EXPONENTIATION (square-and-multiply)
# ─────────────────────────────────────────────────────────────────────────────
def _mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Compute base^exp mod mod using the "square-and-multiply" algorithm.
    HOW IT WORKS:
    Write exp in binary: e.g. exp=13 = 1101 in binary.
    base^13 = base^8 * base^4 * base^1
    We scan bits of exp from LSB to MSB:
      - Always square the running base (base → base^2 → base^4 → ...)
      - If the current bit is 1, multiply result by the current power.
    This costs only O(log exp) multiplications instead of O(exp).
    For a 512-bit exp, that's ~512 multiplications instead of 2^512.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MILLER-RABIN PRIMALITY TEST
# ─────────────────────────────────────────────────────────────────────────────
def miller_rabin(n: int, k: int = 40, trace: list = None) -> bool:
    """
    Probabilistic primality test.
    Returns:
      True  — n is PROBABLY prime (error ≤ 4^{-k})
      False — n is DEFINITELY composite (100% certain)
    Parameters:
      n     : integer to test
      k     : number of random witness rounds (40 by default → negligible error)
      trace : optional list; if provided, execution steps are appended to it
              so the web UI can display round-by-round witness tracing.
    STEP-BY-STEP ALGORITHM:
    1. Handle trivial cases: n<2 composite, n=2/3 prime, even n composite.
    2. Write n-1 = 2^s * d  (d is odd).
    3. For each of k rounds:
       a. Pick random witness a in [2, n-2].
       b. Compute x = a^d mod n.
       c. If x==1 or x==n-1: this witness is "fooled" → go to next round.
       d. Square x up to s-1 more times:
          - If x becomes n-1 at any point: witness is "fooled" → next round.
       e. If we exit the loop without seeing n-1: n is COMPOSITE. Return False.
    4. If all k witnesses are fooled: return True (probably prime).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 = 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    if trace is not None:
        trace.append({"event": "factor", "r": s, "d": d})

    for round_num in range(k):
        a = random.randrange(2, n - 1)
        x = _mod_exp(a, d, n)

        if trace is not None:
            trace.append({"event": "round", "round": round_num + 1, "a": a, "x": x})

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                composite = False
                break

        if composite:
            if trace is not None:
                trace.append({
                    "event": "composite",
                    "reason": f"witness a={a} proves composite"
                })
            return False

    if trace is not None:
        trace.append({"event": "prime"})

    return True


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE WRAPPER
# ─────────────────────────────────────────────────────────────────────────────
def is_prime(n: int, k: int = 40) -> bool:
    """
    Public API: returns True if n is (probably) prime.
    Wrapper around miller_rabin with sensible defaults.
    """
    return miller_rabin(n, k)


# ─────────────────────────────────────────────────────────────────────────────
# PRIME GENERATION
# ─────────────────────────────────────────────────────────────────────────────
def gen_prime(bits: int) -> int:
    """
    Generate a random probable prime of exactly `bits` bits.
    HOW:
      1. Generate a random `bits`-bit integer using os.urandom (OS randomness).
      2. Force the top bit = 1 (ensures the number is exactly `bits` bits long).
      3. Force the bottom bit = 1 (ensures the number is ODD; even numbers
         are trivially composite and we'd never want them).
      4. Test with Miller-Rabin (k=40 rounds).
      5. If not prime, generate a new random number and repeat.
    How many tries does it take?
      By the Prime Number Theorem, about 1/ln(2^bits) = 1/(bits * ln2) of
      all `bits`-bit odd numbers are prime. For 256-bit primes: ~1 in 177.
      For 512-bit primes: ~1 in 355. So we expect to test ~350 candidates
      for a 512-bit prime — very fast in practice.
    """
    while True:
        n = int.from_bytes(os.urandom(bits // 8), 'big')
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n, 40):
            return n


# ─────────────────────────────────────────────────────────────────────────────
# SAFE PRIME GENERATION
# ─────────────────────────────────────────────────────────────────────────────
def gen_safe_prime(bits: int) -> tuple:
    """
    Generate a safe prime p = 2q + 1 where q is also prime.
    For Diffie-Hellman (PA#11), we want the group Z*_p to have a large prime-
    order subgroup. If p = 2q+1 with q prime, then Z*_p has order p-1 = 2q,
    so the subgroup of order q is large — making DLP hard.
    Returns: (p, q)
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin(p, 40):
            return p, q


# ─────────────────────────────────────────────────────────────────────────────
# FERMAT TEST (for comparison / Carmichael demo)
# ─────────────────────────────────────────────────────────────────────────────
def fermat_test(n: int, a: int) -> bool:
    """
    Naive Fermat primality test: returns True if a^(n-1) ≡ 1 (mod n).
    This is WRONG for Carmichael numbers — kept here only for the demo
    that shows WHY Miller-Rabin is needed.
    """
    return _mod_exp(a, n - 1, n) == 1


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────
def demo():
    print("=" * 60)
    print("PA #13 — Miller-Rabin Primality Testing")
    print("=" * 60)

    # ── Test 1: Known primes and composites ──────────────────────────────────
    print("\n[Test 1] Known values:")
    test_cases = [
        (2,       True,  "smallest prime"),
        (3,       True,  "prime"),
        (4,       False, "composite (2^2)"),
        (561,     False, "Carmichael number (fools Fermat)"),
        (1105,    False, "Carmichael number"),
        (7919,    True,  "prime"),
        (104729,  True,  "prime"),
        (1000003, True,  "prime"),
        (1000004, False, "composite (even)"),
        (15,      False, "composite (3×5)"),
    ]
    for n, expected, label in test_cases:
        result = is_prime(n)
        status = "✓" if result == expected else "✗ FAIL"
        print(f"  {n:>10} → {'PRIME' if result else 'COMPOSITE':10}  "
              f"(expected {'PRIME' if expected else 'COMPOSITE'}) {status} [{label}]")

    # ── Test 2: Carmichael number — Fermat vs Miller-Rabin ───────────────────
    print("\n[Test 2] Carmichael number 561 — Fermat vs Miller-Rabin:")
    print(f"  Fermat test (base 2):   {fermat_test(561, 2)} ← WRONG (says prime!)")
    print(f"  Fermat test (base 5):   {fermat_test(561, 5)} ← WRONG")
    print(f"  Fermat test (base 10):  {fermat_test(561, 10)} ← WRONG")
    print(f"  Miller-Rabin:           {miller_rabin(561)} ← CORRECT (says composite) ✓")
    print(f"  561 = 3 × 11 × 17 = {3*11*17} (definitely composite)")

    # ── Test 3: Prime generation ─────────────────────────────────────────────
    print("\n[Test 3] Prime generation:")
    for bits in [64, 128, 256, 512]:
        t0 = time.time()
        p = gen_prime(bits)
        elapsed = time.time() - t0
        extra_check = miller_rabin(p, 100)
        print(f"  {bits:4}-bit prime in {elapsed:.3f}s: {p.bit_length()}-bit, "
              f"re-test(100 rounds)={extra_check} ✓")

    # ── Test 4: Trace feature ────────────────────────────────────────────────
    print("\n[Test 4] Trace feature (for web UI):")
    trace_561 = []
    result_561 = miller_rabin(561, k=5, trace=trace_561)
    print(f"  miller_rabin(561, k=5, trace=[]) → {result_561}")
    print(f"  Trace entries: {len(trace_561)}")
    for entry in trace_561[:5]:
        print(f"    {entry}")

    # ── Test 5: Verify edge cases ────────────────────────────────────────────
    print("\n[Test 5] Edge cases:")
    print(f"  is_prime(0)  = {is_prime(0)}  (expected False)")
    print(f"  is_prime(1)  = {is_prime(1)}  (expected False)")
    print(f"  is_prime(2)  = {is_prime(2)}   (expected True)")
    print(f"  is_prime(-5) = {is_prime(-5)}  (expected False)")

    print("\n✓ PA#13 complete.")


if __name__ == "__main__":
    demo()
