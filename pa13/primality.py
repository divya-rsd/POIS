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

def miller_rabin(n: int, k: int = 40, trace: list = None) -> bool:
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
        if trace is not None:
            trace.append({"a": a, "x": x, "result": "continue" if (x == 1 or x == n-1) else "check_s"})
            
        if x == 1 or x == n-1: continue
        
        is_composite = True
        for _ in range(s-1):
            x = x*x % n
            if trace is not None:
                trace[-1]["x"] = x  # update last x seen in this round
            if x == n-1:
                is_composite = False
                if trace is not None: trace[-1]["result"] = "continue"
                break
        
        if is_composite:
            if trace is not None: trace[-1]["result"] = "composite"
            return False
            
    return True

def is_prime(n: int) -> bool:
    return miller_rabin(n, 40)

def gen_prime(bits: int, track_candidates: list = None) -> int:
    """Generate a random probable prime of given bit length."""
    candidates = 0
    while True:
        candidates += 1
        n = int.from_bytes(os.urandom(bits//8), 'big')
        n |= (1 << (bits-1)) | 1  # ensure top bit set and odd
        if miller_rabin(n, 40):
            assert miller_rabin(n, 100), "100-round sanity check failed!"
            if track_candidates is not None:
                track_candidates.append(candidates)
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
    print(f"  Fermat(561,2): {_mod_exp(2,560,561)==1} (wrong!), Miller-Rabin: {miller_rabin(561)} (correct ✓)")
    
    print("\n  [Performance Benchmark] Generating Primes...")
    for bits in [512, 1024, 2048]:
        counts = []
        t0 = time.time()
        p = gen_prime(bits, track_candidates=counts)
        elapsed = time.time() - t0
        actual_count = counts[0]
        # PNT says average distance between primes near 2^b is ln(2^b) = b * ln(2).
        # Since we only test odd numbers, the average candidates is half of that: (b * ln(2)) / 2
        theory_count = int(bits * math.log(2) / 2)
        print(f"  {bits}-bit prime generated in {elapsed:.3f}s")
        print(f"    Candidates sampled: {actual_count}")
        print(f"    Theoretical avg (odds only): ~{theory_count}")
        
    print("\n✓ PA#13 complete.")

if __name__ == "__main__": demo()
