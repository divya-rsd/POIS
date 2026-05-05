"""
PA #5 — Message Authentication Codes
PRF-MAC, CBC-MAC, EUF-CMA game
"""
import os, sys, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa2.prf_ggm import PRF, AES_PRF

BLOCK = 16
def _pad(d,bs=BLOCK): n=bs-len(d)%bs; return d+bytes([n]*n)
def _xor(a,b): return bytes(x^y for x,y in zip(a,b))


def _pkcs7_pad_for_length(length, bs=BLOCK):
    n = bs - (length % bs)
    return bytes([n] * n)


def _toy_md_hash(data, iv=b'\x00' * BLOCK):
    """Toy Merkle–Damgård hash for PA#5 length-extension demo only."""
    state = iv
    padded = data + _pkcs7_pad_for_length(len(data), BLOCK)
    for i in range(0, len(padded), BLOCK):
        blk = padded[i:i + BLOCK]
        state = AES_PRF.evaluate(state, blk)
    return state


def _toy_md_hash_continue(state, extra, prefix_len):
    """Continue toy hash from an existing state (for length extension)."""
    total_len = prefix_len + len(extra)
    padded_extra = extra + _pkcs7_pad_for_length(total_len, BLOCK)
    cur = state
    for i in range(0, len(padded_extra), BLOCK):
        blk = padded_extra[i:i + BLOCK]
        cur = AES_PRF.evaluate(cur, blk)
    return cur

class PRF_MAC:
    """PRF-MAC: Mac_k(m) = F_k(m). Fixed-length (one block)."""
    def __init__(self):
        # Use PA#2 PRF interface directly.
        self._prf = PRF(use_aes=False)

    def mac(self, key, msg):
        # Native PRF-MAC domain is one block. For longer inputs used by
        # demos/tests, reduce deterministically to one block.
        block = msg if len(msg) == BLOCK else _toy_md_hash(msg)
        return self._prf.evaluate(key, block)

    def verify(self, key, msg, tag):
        expected = self.mac(key, msg)
        return secrets.compare_digest(expected, tag)

    def Mac(self, key, msg):
        return self.mac(key, msg)

    def Vrfy(self, key, msg, tag):
        return self.verify(key, msg, tag)

    def run_mac_to_prf_demo(self, n_queries=200):
        """PA#5 backward demo: MAC-oracle outputs look PRF-like on random inputs."""
        key = os.urandom(16)
        mac_outputs = [self.mac(key, os.urandom(BLOCK)) for _ in range(n_queries)]
        random_outputs = [os.urandom(len(mac_outputs[0])) for _ in range(n_queries)]

        def bit_freq(outputs):
            bits = []
            for b in outputs:
                for byte in b:
                    for i in range(7, -1, -1):
                        bits.append((byte >> i) & 1)
            return sum(bits) / len(bits) if bits else 0.0

        mac_freq = bit_freq(mac_outputs)
        rnd_freq = bit_freq(random_outputs)
        diff = abs(mac_freq - rnd_freq)
        return {
            'queries': n_queries,
            'mac_bit_frequency': round(mac_freq, 4),
            'random_bit_frequency': round(rnd_freq, 4),
            'difference': round(diff, 4),
            'prf_like': diff < 0.05,
        }

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

    def Mac(self, key, msg):
        return self.mac(key, msg)

    def Vrfy(self, key, msg, tag):
        return self.verify(key, msg, tag)

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

    def Mac(self, key, msg):
        return self.mac(key, msg)

    def Vrfy(self, key, msg, tag):
        return self.verify(key, msg, tag)


class NaiveHashMAC:
    """Deliberately insecure single-hash MAC: tag = H(k || m)."""

    def __init__(self):
        self._key_len = 16

    def mac(self, key, msg):
        return _toy_md_hash(key + msg)

    def verify(self, key, msg, tag):
        return secrets.compare_digest(self.mac(key, msg), tag)


class LengthExtensionAttack:
    """Demonstrates length extension against naive single-hash MAC."""

    def __init__(self, scheme=None):
        self.scheme = scheme or NaiveHashMAC()

    def run(self):
        key = os.urandom(16)
        msg = b"amount=10&to=bob"
        extra = b"&admin=true"

        tag = self.scheme.mac(key, msg)

        # Attacker knows msg/tag and assumes key length.
        key_len_guess = 16
        glue = _pkcs7_pad_for_length(key_len_guess + len(msg), BLOCK)
        forged_msg = msg + glue + extra
        prefix_len = key_len_guess + len(msg) + len(glue)
        forged_tag = _toy_md_hash_continue(tag, extra, prefix_len)

        forged_ok = self.scheme.verify(key, forged_msg, forged_tag)
        return {
            'forged': forged_ok,
            'original_len': len(msg),
            'forged_len': len(forged_msg),
        }

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
    msg16 = b"authenticate me!"
    t1 = prf_mac.mac(key, msg16); t2 = cbc_mac.mac(key, msg)
    print(f"  PRF-MAC tag:  {t1.hex()}"); print(f"  CBC-MAC tag:  {t2.hex()}")
    print(f"  PRF-MAC verify: {prf_mac.verify(key, msg16, t1)} ✓")

    prf_demo = prf_mac.run_mac_to_prf_demo()
    print(f"  MAC⇒PRF demo diff: {prf_demo['difference']} (prf_like={prf_demo['prf_like']})")
    
    game1 = EUF_CMA_Game(prf_mac); res1 = game1.run_dummy()
    print(f"  EUF-CMA (PRF-MAC, dummy): forgeries={res1['forgeries']}, secure={res1['secure']} ✓")
    
    game2 = EUF_CMA_Game(naive_cbc)
    res2 = game2.run_smart_adversary()
    print(f"  EUF-CMA (Naive CBC-MAC, smart): forgeries={res2['forgeries']}, secure={res2['secure']} (Vulnerable!)")
    
    game3 = EUF_CMA_Game(cbc_mac)
    res3 = game3.run_smart_adversary()
    print(f"  EUF-CMA (Secure CBC-MAC, smart): forgeries={res3['forgeries']}, secure={res3['secure']} ✓")

    le = LengthExtensionAttack().run()
    print(f"  Naive hash-MAC length-extension forged: {le['forged']} (expected True for vulnerable scheme)")
    
    print("✓ PA#5 complete.")

if __name__ == "__main__": demo()
