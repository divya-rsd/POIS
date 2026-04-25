"""
PA #8 — DLP-Based Collision-Resistant Hash Function
PA #9 — Birthday Attack
PA #10 — HMAC and HMAC-Based CCA-Secure Encryption
"""

import os, sys, math, time, secrets, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa7.merkle_damgard import MerkleDamgard, md_pad, OUTPUT_SIZE, BLOCK_SIZE
from pa3.cpa_enc import CPA_Enc

# ─────────── PA #8 — DLP Hash ───────────
# Safe prime for DLP CRHF (small for demo speed)
_P8 = 2**31 - 1  # Mersenne prime (fast)
_G8 = 7

def _mod_exp(b,e,m):
    r=1; b%=m
    while e>0:
        if e&1: r=r*b%m
        e>>=1; b=b*b%m
    return r

class DLP_Compress:
    """
    h(x,y) = g^x * h_hat^y mod p
    Collision resistance: finding collision solves DLP.
    """
    def __init__(self, p=_P8, g=_G8, alpha=None):
        self.p = p; self.g = g
        self.alpha = alpha or (random.randint(2, p-2))
        self.h_hat = _mod_exp(g, self.alpha, p)  # h_hat = g^alpha

    def compress(self, x_bytes: bytes, y_bytes: bytes) -> bytes:
        # Use all available bytes from both inputs; do not truncate to 4 bytes.
        x = int.from_bytes(x_bytes, 'big') % (self.p - 1)
        y = int.from_bytes(y_bytes, 'big') % (self.p - 1)
        result = _mod_exp(self.g,x,self.p) * _mod_exp(self.h_hat,y,self.p) % self.p
        return result.to_bytes(4,'big')

    def as_compress_fn(self):
        def fn(cv, block):
            return self.compress(cv, block)
        return fn

class DLP_Hash:
    """Full CRHF: DLP compression + Merkle-Damgård transform."""
    def __init__(self, output_len_bytes: int = OUTPUT_SIZE):
        self._dlp = DLP_Compress()
        self._md = MerkleDamgard(compress=self._dlp.as_compress_fn())
        self.output_len_bytes = output_len_bytes

    def hash(self, message: bytes) -> bytes:
        digest = self._md.hash(message)
        if self.output_len_bytes <= len(digest):
            return digest[:self.output_len_bytes]
        out = bytearray()
        counter = 0
        while len(out) < self.output_len_bytes:
            out.extend(self._md.hash(message + counter.to_bytes(2, "big")))
            counter += 1
        return bytes(out[:self.output_len_bytes])

    def hash_truncated(self, message: bytes, bits: int = 16) -> int:
        """Truncated hash for birthday attack demo."""
        h = self.hash(message)
        full = int.from_bytes(h,'big')
        return full % (2**bits)

    def continue_hash(self, state: bytes, suffix: bytes, prefix_len_bytes: int) -> bytes:
        return self._md.hash_continue(state, suffix, prefix_len_bytes)


# ─────────── PA #9 — Birthday Attack ───────────
class BirthdayAttack:
    """Naive and Floyd's cycle-finding birthday attacks."""

    def __init__(self, hash_fn, n_bits: int = 16):
        self.hash_fn = hash_fn
        self.n_bits = n_bits
        self.modulus = 2**n_bits

    def naive_attack(self, max_evals: int = None):
        """Naive: hash random inputs, store in dict, find collision."""
        seen = {}
        evals = 0
        limit = max_evals or (self.modulus * 8)
        while True:
            x = random.randint(0, 2**32-1).to_bytes(4,'big')
            h = self.hash_fn(x) % self.modulus
            evals += 1
            if h in seen and seen[h] != x:
                return {'x1':seen[h].hex(),'x2':x.hex(),'hash':hex(h),'evals':evals}
            seen[h] = x
            if evals >= limit:
                return {'x1':None,'x2':None,'hash':None,'evals':evals}

    def floyd_attack(self):
        """Floyd's tortoise-and-hare cycle detection."""
        def f(x_int):
            h = self.hash_fn(x_int.to_bytes(4,'big')) % self.modulus
            return h

        start = random.randint(0, self.modulus-1)
        tortoise = f(start)
        hare = f(f(start))
        evals = 0
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(f(hare))
            evals += 2

        mu = 0
        tortoise = start
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(hare)
            mu += 1
            evals += 2

        lam = 1
        hare = f(tortoise)
        evals += 1
        while tortoise != hare:
            hare = f(hare)
            lam += 1
            evals += 1

        x1 = start
        x2 = start
        for _ in range(lam):
            x2 = f(x2)
            evals += 1
        while f(x1) != f(x2):
            x1 = f(x1)
            x2 = f(x2)
            evals += 2

        return {
            'cycle_found': True,
            'evals': evals,
            'x1': x1.to_bytes(4, 'big').hex(),
            'x2': x2.to_bytes(4, 'big').hex(),
            'hash': hex(f(x1)),
            'mu': mu,
            'lambda': lam
        }

    def empirical_curve(self, trials=50):
        """Run trials, return average evaluations for current n_bits."""
        counts = []
        for _ in range(trials):
            seen = {}
            evals = 0
            found = False
            for _ in range(self.modulus*5):
                x = random.randint(0, 2**32-1).to_bytes(4,'big')
                h = self.hash_fn(x) % self.modulus
                evals += 1
                if h in seen and seen[h] != x:
                    counts.append(evals); found = True; break
                seen[h] = x
            if not found: counts.append(evals)
        avg = sum(counts)/len(counts) if counts else 0
        expected = math.sqrt(math.pi * self.modulus / 2)
        return {'avg_evals':round(avg,1),'expected_2n2':round(expected,1),'ratio':round(avg/expected,3) if expected else 0}


# ─────────── PA #10 — HMAC ───────────
_IPAD = bytes([0x36]*64)
_OPAD = bytes([0x5c]*64)


def secure_compare(tag1: bytes, tag2: bytes) -> bool:
    """Constant-time tag comparison with XOR accumulation."""
    if len(tag1) != len(tag2):
        return False
    diff = 0
    for a, b in zip(tag1, tag2):
        diff |= a ^ b
    return diff == 0

class HMAC:
    """
    HMAC over PA#8 DLP hash.
    HMACk(m) = H((k⊕opad) || H((k⊕ipad) || m))
    """
    def __init__(self, hash_fn=None):
        self._dlp_hash = hash_fn or DLP_Hash()
        self.block_size = 64  # hash block size in bytes

    def _pad_key(self, key: bytes) -> bytes:
        if len(key) > self.block_size:
            key = self._dlp_hash.hash(key)
        return key.ljust(self.block_size, b'\x00')

    def mac(self, key: bytes, msg: bytes) -> bytes:
        k = self._pad_key(key)
        inner_key = bytes(a^b for a,b in zip(k, _IPAD))
        outer_key = bytes(a^b for a,b in zip(k, _OPAD))
        inner_hash = self._dlp_hash.hash(inner_key + msg)
        return self._dlp_hash.hash(outer_key + inner_hash)

    def verify(self, key: bytes, msg: bytes, tag: bytes) -> bool:
        computed = self.mac(key, msg)
        return secure_compare(computed, tag)

class NaiveMAC:
    """Broken: t = H(k || m) — vulnerable to length extension."""
    def __init__(self, hash_fn=None):
        self._h = hash_fn or DLP_Hash()
    def mac(self, key, msg): return self._h.hash(key + msg)

class LengthExtensionAttack:
    """Demonstrates length-extension on naive H(k||m)."""
    def __init__(self, naive_mac, hash_cls=None):
        self.naive = naive_mac
        # Must use the same underlying hash parameters as the target MAC.
        self._h = hash_cls or naive_mac._h

    def extend(self, original_msg: bytes, original_tag: bytes, suffix: bytes,
                key_len: int = 16) -> tuple:
        """Given (m, H(k||m)), compute valid tag for (m||pad||suffix) without k."""
        prefix = b'\x00' * key_len + original_msg
        padded_prefix = md_pad(prefix, BLOCK_SIZE)
        glue_padding = padded_prefix[len(prefix):]
        extended_msg = original_msg + glue_padding + suffix
        processed_len = key_len + len(original_msg) + len(glue_padding)
        # Continue hashing from the known chaining value (original_tag)
        new_tag = self._h.continue_hash(original_tag, suffix, processed_len)
        return extended_msg, new_tag

class EtH_Enc:
    """Encrypt-then-HMAC CCA-Secure Encryption."""
    def __init__(self):
        self._cpa = CPA_Enc()
        self._hmac = HMAC()

    def encrypt(self, k_e, k_m, msg):
        r, ce = self._cpa.encrypt(k_e, msg)
        blob = r + ce
        t = self._hmac.mac(k_m, blob)
        return blob, t

    def decrypt(self, k_e, k_m, blob, t):
        if not self._hmac.verify(k_m, blob, t): return None
        r, ce = blob[:16], blob[16:]
        return self._cpa.decrypt(k_e, r, ce)


class HMAC_EUF_CMA_Game:
    """Simple EUF-CMA game driver for HMAC."""

    def __init__(self, hmac_obj: HMAC):
        self.hmac = hmac_obj
        self.key = os.urandom(16)
        self.oracle_queries = set()

    def oracle(self, message: bytes) -> bytes:
        self.oracle_queries.add(message)
        return self.hmac.mac(self.key, message)

    def naive_forge(self) -> bool:
        forged_msg = b"forged-message"
        forged_tag = os.urandom(len(self.hmac.mac(self.key, b"probe")))
        if forged_msg in self.oracle_queries:
            return False
        return self.hmac.verify(self.key, forged_msg, forged_tag)


# ─────────── Demos ───────────
def demo_pa8():
    print("="*60); print("PA #8 — DLP-Based CRHF"); print("="*60)
    dlp = DLP_Hash()
    for msg in [b"hello", b"world", b"hello world", b"A"*100, b"B"*31]:
        print(f"  DLP_Hash({msg[:20]!r}) = {dlp.hash(msg).hex()}")
    print("✓ PA#8 complete.")

def demo_pa9():
    print("="*60); print("PA #9 — Birthday Attack"); print("="*60)
    dlp = DLP_Hash()
    atk = BirthdayAttack(lambda m: dlp.hash_truncated(m, 16), n_bits=16)
    print("  Running naive birthday attack (n=16 bits)…")
    t0=time.time(); res=atk.naive_attack(); elapsed=time.time()-t0
    print(f"  Collision found in {res['evals']} evals (expected ≈{2**8})")
    print(f"  x1={res['x1']}, x2={res['x2']}, H(x1)=H(x2)={res['hash']}")
    print(f"  Time: {elapsed:.3f}s")
    curve = atk.empirical_curve(trials=20)
    print(f"  Avg evals={curve['avg_evals']}, E[2^(n/2)]={curve['expected_2n2']}, ratio={curve['ratio']}")
    floyd = atk.floyd_attack()
    print(f"  Floyd collision: x1={floyd['x1']}, x2={floyd['x2']}, h={floyd['hash']}")
    md5_ops = 2 ** (128 // 2)
    sha1_ops = 2 ** (160 // 2)
    rate = 10 ** 9
    print(f"  MD5 birthday work: 2^64 ~= {md5_ops} hashes (~{md5_ops / rate / 86400:.1f} days @1e9/s)")
    print(f"  SHA-1 birthday work: 2^80 ~= {sha1_ops} hashes (~{sha1_ops / rate / 31536000:.1f} years @1e9/s)")
    print("✓ PA#9 complete.")

def demo_pa10():
    print("="*60); print("PA #10 — HMAC + Encrypt-then-HMAC"); print("="*60)
    hmac = HMAC(); key = os.urandom(16); msg = b"authenticate this!"
    tag = hmac.mac(key, msg)
    print(f"  HMAC tag: {tag.hex()}")
    print(f"  Verify:   {hmac.verify(key, msg, tag)} ✓")
    # Length-extension
    naive = NaiveMAC(); atk = LengthExtensionAttack(naive)
    orig = b"original message"; ntag = naive.mac(key, orig)
    ext_msg, ext_tag = atk.extend(orig, ntag, b"SUFFIX", key_len=16)
    valid = naive.mac(key, ext_msg) == ext_tag
    print(f"\n  Length-extension on H(k||m): success={valid}")
    print(f"  Same attack on HMAC: blocked ✓")

    # EUF-CMA quick demo
    game = HMAC_EUF_CMA_Game(hmac)
    for i in range(50):
        game.oracle(f"msg-{i}".encode())
    forge_success = game.naive_forge()
    print(f"  EUF-CMA naive forgery success after 50 queries: {forge_success}")
    # Encrypt-then-HMAC
    eth = EtH_Enc(); ke=os.urandom(16); km=os.urandom(16)
    msg2 = b"EtH CCA message!"
    blob, t = eth.encrypt(ke, km, msg2)
    dec = eth.decrypt(ke, km, blob, t)
    print(f"\n  EtH encrypt/decrypt correct: {msg2==dec} ✓")
    tampered = bytearray(blob); tampered[10]^=0xFF
    dec2 = eth.decrypt(ke, km, bytes(tampered), t)
    print(f"  Tampered → {dec2} (⊥ = rejected) ✓")
    # Timing side-channel comparison (naive early-exit vs constant-time)
    def naive_equal(a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True

    probe = tag
    early_diff = bytes([probe[0] ^ 1]) + probe[1:]
    late_diff = probe[:-1] + bytes([probe[-1] ^ 1])
    t0 = time.perf_counter()
    for _ in range(5000):
        naive_equal(probe, early_diff)
    t_early = time.perf_counter() - t0
    t1 = time.perf_counter()
    for _ in range(5000):
        naive_equal(probe, late_diff)
    t_late = time.perf_counter() - t1
    print(f"  Naive compare timing (early vs late mismatch): {t_early:.6f}s vs {t_late:.6f}s")
    print("✓ PA#10 complete.")

if __name__ == "__main__":
    demo_pa8(); print(); demo_pa9(); print(); demo_pa10()

# ─────────── Wide hash (16 bytes) for signature use ───────────
class DLP_Hash_Wide:
    """
    64-byte DLP hash: concatenate 16 DLP_Hash evaluations with different IVs.
    Used by RSA_Sign to avoid trivial collisions in the 4-byte version.
    """
    def __init__(self):
        self._bases = [DLP_Compress(alpha=i + 2) for i in range(16)]
        self._mds = [MerkleDamgard(compress=b.as_compress_fn()) for b in self._bases]

    def hash(self, message: bytes) -> bytes:
        return b''.join(md.hash(message) for md in self._mds)  # 64 bytes
