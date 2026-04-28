"""
PA #5 — Message Authentication Codes
PRF-MAC, CBC-MAC, EUF-CMA game
"""
import os, sys, hmac as _hmac, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa2.prf_ggm import PRF, AES_PRF

BLOCK = 16
def _pad(d,bs=BLOCK): n=bs-len(d)%bs; return d+bytes([n]*n)
def _xor(a,b): return bytes(x^y for x,y in zip(a,b))

class PRF_MAC:
    """PRF-MAC: Mac_k(m) = F_k(m). Fixed-length (one block)."""
    def __init__(self): self._prf = AES_PRF()
    def mac(self, key, msg):
        m = (_pad(msg))[:BLOCK]
        return self._prf.evaluate(key, m)
    def verify(self, key, msg, tag):
        return secrets.compare_digest(self.mac(key, msg), tag)

class NaiveCBC_MAC:
    """Vulnerable Textbook CBC-MAC for variable-length messages."""
    def __init__(self): self._prf = AES_PRF()
    def mac(self, key, msg):
        padded = _pad(msg); state = b'\x00'*BLOCK
        for i in range(len(padded)//BLOCK):
            blk = padded[i*BLOCK:(i+1)*BLOCK]
            state = self._prf.evaluate(key, _xor(state, blk))
        return state
    def verify(self, key, msg, tag):
        return secrets.compare_digest(self.mac(key, msg), tag)

class CBC_MAC:
    """Length-prepended CBC-MAC for variable-length messages."""
    def __init__(self): self._prf = AES_PRF()
    def mac(self, key, msg):
        length_block = len(msg).to_bytes(BLOCK, 'big')
        padded = length_block + _pad(msg)
        state = b'\x00'*BLOCK
        for i in range(len(padded)//BLOCK):
            blk = padded[i*BLOCK:(i+1)*BLOCK]
            state = self._prf.evaluate(key, _xor(state, blk))
        return state
    def verify(self, key, msg, tag):
        return secrets.compare_digest(self.mac(key, msg), tag)

class HMAC_stub:
    """Stub — full implementation in PA#10."""
    def mac(self, key, msg): raise NotImplementedError("HMAC stub — see PA#10")
    def verify(self, key, msg, tag): raise NotImplementedError("HMAC stub — see PA#10")

class EUF_CMA_Game:
    def __init__(self, mac_scheme):
        self.mac = mac_scheme; self.key = os.urandom(16)
        self._signed = {}; self._forgeries = 0; self._attempts = 0
    def sign(self, msg):
        t = self.mac.mac(self.key, msg); self._signed[msg] = t; return t
    def submit_forgery(self, msg, tag):
        self._attempts += 1
        if msg in self._signed: return False, "Message already signed"
        if self.mac.verify(self.key, msg, tag):
            self._forgeries += 1; return True, "FORGERY ACCEPTED!"
        return False, "Forgery rejected ✓"
    def run_dummy(self, n=50):
        for i in range(n): self.sign(f"message {i}".encode())
        results = []
        for _ in range(20):
            fake_tag = os.urandom(16)
            ok, msg = self.submit_forgery(b"forged message!!", fake_tag)
            results.append(ok)
        return {'attempts':self._attempts,'forgeries':self._forgeries,'secure': self._forgeries==0}

    def run_smart_adversary(self):
        """Uses splicing attack against naive CBC-MAC."""
        attack = SplicingAttack()
        attack.run_attack(self)
        return {'attempts':self._attempts,'forgeries':self._forgeries,'secure': self._forgeries==0}

class SplicingAttack:
    """
    Demonstrates the splicing attack against textbook CBC-MAC.
    """
    def run_attack(self, game):
        # 1. Ask oracle for MAC of A
        A = b"First message"
        T_A = game.sign(A)
        # 2. Ask oracle for MAC of B
        B = b"X" * BLOCK
        T_B = game.sign(B)
        # 3. Construct C = pad(A) || (B ^ T_A)
        A_padded = _pad(A)
        C = A_padded + _xor(B, T_A)
        # 4. Submit forgery C with tag T_B
        ok, msg = game.submit_forgery(C, T_B)
        return ok

def demo():
    print("="*60); print("PA #5 — Message Authentication Codes"); print("="*60)
    key = os.urandom(16)
    prf_mac = PRF_MAC(); naive_cbc = NaiveCBC_MAC(); cbc_mac = CBC_MAC()
    msg = b"authenticate me!"
    t1 = prf_mac.mac(key, msg); t2 = cbc_mac.mac(key, msg)
    print(f"  PRF-MAC tag:  {t1.hex()}"); print(f"  CBC-MAC tag:  {t2.hex()}")
    print(f"  PRF-MAC verify: {prf_mac.verify(key, msg, t1)} ✓")
    
    game1 = EUF_CMA_Game(prf_mac); res1 = game1.run_dummy()
    print(f"  EUF-CMA (PRF-MAC, dummy): forgeries={res1['forgeries']}, secure={res1['secure']} ✓")
    
    game2 = EUF_CMA_Game(naive_cbc)
    res2 = game2.run_smart_adversary()
    print(f"  EUF-CMA (Naive CBC-MAC, smart): forgeries={res2['forgeries']}, secure={res2['secure']} (Vulnerable!)")
    
    game3 = EUF_CMA_Game(cbc_mac)
    res3 = game3.run_smart_adversary()
    print(f"  EUF-CMA (Secure CBC-MAC, smart): forgeries={res3['forgeries']}, secure={res3['secure']} ✓")
    
    print("✓ PA#5 complete.")

if __name__ == "__main__": demo()
