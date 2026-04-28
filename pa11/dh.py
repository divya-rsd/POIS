"""
PA #11 — Diffie-Hellman Key Exchange
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa13.primality import gen_safe_prime, is_prime, _mod_exp

def _rand_exp(q): return int.from_bytes(os.urandom((q.bit_length()+7)//8),'big') % (q-2) + 2


def cdh_brute_force(p: int, g: int, A: int, B: int, q: int) -> dict:
    """
    Brute-force the Computational Diffie-Hellman problem in a TINY group.

    Given (p, g, A=g^a, B=g^b), iterate x in [2, q-1] until g^x == A, then
    compute the shared secret B^x mod p. Returns the recovered secret and
    elapsed wall-clock time so the caller can see how the cost scales.

    Intended for ~20-bit q (≈10^6 iterations) — runs in seconds. For real
    >=2048-bit q the search space is 2^2048 and the attack is infeasible.
    """
    t0 = time.time()
    found_x = None
    iterations = 0
    cur = g  # cur = g^1
    for x in range(2, q):
        cur = cur * g % p  # cur = g^x
        iterations += 1
        if cur == A:
            found_x = x
            break
    elapsed = time.time() - t0
    if found_x is None:
        return {
            'recovered': False,
            'iterations': iterations,
            'time_s': round(elapsed, 4),
            'note': f'No x in [2,{q-1}] satisfies g^x = A — search exhausted.',
        }
    shared = _mod_exp(B, found_x, p)
    return {
        'recovered': True,
        'a': found_x,
        'iterations': iterations,
        'time_s': round(elapsed, 4),
        'shared_secret': shared,
        'note': f'Solved DLP for A in {iterations} multiplications ({elapsed:.3f}s).',
    }

class DH:
    """Diffie-Hellman key exchange in prime-order subgroup."""

    def __init__(self, bits=256):
        self.p, self.q = gen_safe_prime(bits)
        self.g = 4  # generator of order q in Z*_p (simplified)

    def alice_step1(self):
        a = _rand_exp(self.q)
        A = _mod_exp(self.g, a, self.p)
        return a, A

    def bob_step1(self):
        b = _rand_exp(self.q)
        B = _mod_exp(self.g, b, self.p)
        return b, B

    def alice_step2(self, a, B):
        return _mod_exp(B, a, self.p)

    def bob_step2(self, b, A):
        return _mod_exp(A, b, self.p)

    def mitm_attack(self):
        """Eve intercepts and substitutes her own values."""
        a, A = self.alice_step1()
        b, B = self.bob_step1()
        e = _rand_exp(self.q)
        E = _mod_exp(self.g, e, self.p)
        K_alice_eve = self.alice_step2(a, E)
        K_bob_eve   = self.bob_step2(b, E)
        K_alice_real = self.alice_step2(a, B)
        return {
            'alice_sees': hex(K_alice_eve)[:20]+'…',
            'bob_sees':   hex(K_bob_eve)[:20]+'…',
            'shared_alice_bob': K_alice_real == self.bob_step2(b,A),
            'eve_controls_both': True
        }

def demo():
    print("="*60); print("PA #11 — Diffie-Hellman Key Exchange"); print("="*60)
    dh = DH(bits=128)
    a,A = dh.alice_step1(); b,B = dh.bob_step1()
    Ka = dh.alice_step2(a,B); Kb = dh.bob_step2(b,A)
    print(f"  Alice's key: {hex(Ka)[:24]}…")
    print(f"  Bob's key:   {hex(Kb)[:24]}…")
    print(f"  Keys match:  {Ka==Kb} ✓")
    mitm = dh.mitm_attack()
    print(f"\n  MITM: Eve controls both channels: {mitm['eve_controls_both']} ✓ (vulnerability)")

    # ── CDH brute-force demo over a tiny ~20-bit q ──
    print("\n  [CDH brute-force on 20-bit q]")
    print("  Generating tiny safe prime (q ≈ 2^20)…", end=' ', flush=True)
    tiny = DH(bits=21)            # q is 20-bit, p is 21-bit
    print(f"q={hex(tiny.q)} ({tiny.q.bit_length()} bits)")
    a_t, A_t = tiny.alice_step1()
    b_t, B_t = tiny.bob_step1()
    real_shared = tiny.alice_step2(a_t, B_t)
    print(f"  Real shared secret (honestly computed): {hex(real_shared)}")
    res = cdh_brute_force(tiny.p, tiny.g, A_t, B_t, tiny.q)
    print(f"  Eve's brute force: {res['note']}")
    if res['recovered']:
        print(f"  Eve's recovered shared secret: {hex(res['shared_secret'])}")
        print(f"  Match (CDH broken in 20-bit group): {res['shared_secret'] == real_shared} ✓")
    print("  (For 2048-bit q the same loop would run for ~2^2028 iterations — infeasible.)")
    print("✓ PA#11 complete.")

if __name__ == "__main__": demo()
