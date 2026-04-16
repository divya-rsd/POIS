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

class CBC_MAC:
    """CBC-MAC for variable-length messages."""
    def __init__(self): self._prf = AES_PRF()
    def mac(self, key, msg):
        padded = _pad(msg); state = b'\x00'*BLOCK
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

def demo():
    print("="*60); print("PA #5 — Message Authentication Codes"); print("="*60)
    key = os.urandom(16)
    prf_mac = PRF_MAC(); cbc_mac = CBC_MAC()
    msg = b"authenticate me!"
    t1 = prf_mac.mac(key, msg); t2 = cbc_mac.mac(key, msg)
    print(f"  PRF-MAC tag:  {t1.hex()}"); print(f"  CBC-MAC tag:  {t2.hex()}")
    print(f"  PRF-MAC verify: {prf_mac.verify(key, msg, t1)} ✓")
    game = EUF_CMA_Game(prf_mac); res = game.run_dummy()
    print(f"  EUF-CMA: forgeries={res['forgeries']}, secure={res['secure']} ✓")
    print("✓ PA#5 complete.")

if __name__ == "__main__": demo()
