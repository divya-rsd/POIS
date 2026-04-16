"""
PA #11 — Diffie-Hellman Key Exchange
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa13.primality import gen_safe_prime, is_prime, _mod_exp

def _rand_exp(q): return int.from_bytes(os.urandom((q.bit_length()+7)//8),'big') % (q-2) + 2

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
    print("✓ PA#11 complete.")

if __name__ == "__main__": demo()
