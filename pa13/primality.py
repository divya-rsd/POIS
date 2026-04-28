"""
PA #13 — Miller-Rabin Primality Testing
"""
import os, secrets, math, time

def _mod_exp(b,e,m):
    r=1; b%=m
    while e>0:
        if e&1: r=r*b%m
        e>>=1; b=b*b%m
    return r

def miller_rabin(n: int, k: int = 40) -> bool:
    """Returns True if n is probably prime, False if definitely composite.

    Witnesses are drawn from a CSPRNG (secrets.randbelow → os.urandom),
    not the predictable Mersenne-Twister `random` module.
    """
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    # Write n-1 = 2^s * d
    s, d = 0, n-1
    while d % 2 == 0: s += 1; d //= 2
    for _ in range(k):
        # secrets.randbelow(N) returns in [0, N) drawn from os.urandom — CSPRNG.
        a = 2 + secrets.randbelow(n - 3)        # a ∈ [2, n-2]
        x = _mod_exp(a, d, n)
        if x == 1 or x == n-1: continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else:
            return False
    return True

def is_prime(n: int) -> bool:
    return miller_rabin(n, 40)

def gen_prime(bits: int) -> int:
    """Generate a random probable prime of given bit length."""
    while True:
        n = int.from_bytes(os.urandom(bits//8), 'big')
        n |= (1 << (bits-1)) | 1  # ensure top bit set and odd
        if miller_rabin(n, 40):
            return n

def gen_safe_prime(bits: int) -> tuple:
    """Generate safe prime p=2q+1 where q is also prime. Returns (p, q)."""
    while True:
        q = gen_prime(bits-1)
        p = 2*q + 1
        if miller_rabin(p, 40):
            return p, q

def demo():
    print("="*60); print("PA #13 — Miller-Rabin Primality Testing"); print("="*60)
    tests = [(561,'Carmichael — composite'),(7919,'prime'),(104729,'prime'),(1000003,'prime')]
    for n,label in tests:
        print(f"  {n}: {'PRIME' if is_prime(n) else 'COMPOSITE'} (expected: {label})")
    print("\n  Carmichael 561 Fermat test (should wrongly say prime):")
    print(f"  Fermat(561,2): {_mod_exp(2,559,561)==1} (wrong!), Miller-Rabin: {miller_rabin(561)} (correct ✓)")
    print("\n  Generating 512-bit prime…")
    t0=time.time(); p=gen_prime(512); elapsed=time.time()-t0
    print(f"  {p.bit_length()}-bit prime in {elapsed:.3f}s")
    print("✓ PA#13 complete.")

if __name__ == "__main__": demo()
