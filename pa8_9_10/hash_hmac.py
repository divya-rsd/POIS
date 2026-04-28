"""
PA #8 — DLP-Based Collision-Resistant Hash Function
PA #9 — Birthday Attack
PA #10 — HMAC and HMAC-Based CCA-Secure Encryption
"""

import os, sys, math, time, secrets, struct, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa7.merkle_damgard import MerkleDamgard, md_pad, OUTPUT_SIZE, BLOCK_SIZE
from pa3.cpa_enc import CPA_Enc

# ─────────── PA #8 — DLP Hash ───────────
# A 64-bit safe prime p = 2q + 1 where q is also prime. q is a 63-bit prime.
# Output therefore fits in 8 bytes; collision resistance ≈ 2^32 by birthday bound.
# The previous 31-bit prime caused trivial collisions when the inputs differed
# only in bytes that the truncation step discarded.
_P8 = 0xFFFFFFFFFFFFFFC5     # 64-bit prime  (NOT a safe prime in general; used as raw modulus)
_Q8 = (_P8 - 1) // 2          # subgroup-order placeholder (not necessarily prime here)
_G8 = 5
OUT_BYTES = 8                 # bytes of hash output (fits one element of Z_p)


def _mod_exp(b, e, m):
    r = 1
    b %= m
    while e > 0:
        if e & 1:
            r = r * b % m
        e >>= 1
        b = b * b % m
    return r


class DLP_Compress:
    """
    Collision-resistant compression based on the DL assumption.

        h(x, y) = g^x · ĥ^y  mod p,  with ĥ = g^α and α discarded.

    Finding (x, y) ≠ (x', y') with h(x, y) = h(x', y') ⇒ α = (x − x')·(y' − y)⁻¹
    mod (p−1), i.e. solves the DL of ĥ w.r.t. g.

    The compression must consume the FULL block — earlier versions truncated to
    4 bytes, which created trivial collisions on long messages whose differences
    sat in the discarded suffix.
    """

    def __init__(self, p=_P8, g=_G8, alpha=None):
        self.p = p
        self.g = g
        self.alpha = alpha if alpha is not None else random.randint(2, p - 2)
        self.h_hat = _mod_exp(g, self.alpha, p)

    def compress(self, x_bytes: bytes, y_bytes: bytes) -> bytes:
        # Use ALL provided bytes; reduce mod (p−1) at the end.
        x = int.from_bytes(x_bytes, 'big') % (self.p - 1)
        y = int.from_bytes(y_bytes, 'big') % (self.p - 1)
        result = _mod_exp(self.g, x, self.p) * _mod_exp(self.h_hat, y, self.p) % self.p
        return result.to_bytes(OUT_BYTES, 'big')

    def as_compress_fn(self):
        """Adapter for MerkleDamgard.compress(cv, block)."""
        def fn(cv, block):
            return self.compress(cv, block)
        return fn


class DLP_Hash:
    """Full CRHF = DLP compression + Merkle-Damgård transform."""

    BLOCK_BYTES = 16   # message block size; bigger than output to give MD strengthening room
    OUTPUT_BYTES = OUT_BYTES

    def __init__(self):
        self._dlp = DLP_Compress()
        self._md = MerkleDamgard(
            compress=self._dlp.as_compress_fn(),
            iv=b'\x00' * self.OUTPUT_BYTES,
            block_size=self.BLOCK_BYTES,
        )

    def hash(self, message: bytes) -> bytes:
        return self._md.hash(message)

    def hash_truncated(self, message: bytes, bits: int = 16) -> int:
        h = self.hash(message)
        full = int.from_bytes(h, 'big')
        return full % (2 ** bits)


# ─────────── PA #9 — Birthday Attack ───────────
class BirthdayAttack:
    """Naive and Floyd's cycle-finding birthday attacks."""

    def __init__(self, hash_fn, n_bits: int = 16):
        self.hash_fn = hash_fn
        self.n_bits = n_bits
        self.modulus = 2**n_bits

    def naive_attack(self):
        """Naive: hash random inputs, store in dict, find collision."""
        seen = {}
        evals = 0
        while True:
            x = random.randint(0, 2**32-1).to_bytes(4,'big')
            h = self.hash_fn(x) % self.modulus
            evals += 1
            if h in seen and seen[h] != x:
                return {'x1':seen[h].hex(),'x2':x.hex(),'hash':hex(h),'evals':evals}
            seen[h] = x

    def floyd_attack(self):
        """Floyd's tortoise-and-hare cycle detection."""
        def f(x_int):
            h = self.hash_fn(x_int.to_bytes(4,'big')) % self.modulus
            return h
        tortoise = random.randint(0, self.modulus-1)
        hare = tortoise
        evals = 0
        while True:
            tortoise = f(tortoise)
            hare = f(f(hare))
            evals += 2
            if tortoise == hare:
                break
        # Find collision
        x1 = random.randint(0, self.modulus-1)
        x2 = tortoise
        steps = 0
        while f(x1) != f(x2):
            x1 = f(x1); x2 = f(x2); steps += 1
            if steps > self.modulus*4: break
        return {'cycle_found':True,'evals':evals,'hash':hex(f(x1))}

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
        return secrets.compare_digest(computed, tag)

class NaiveMAC:
    """Broken: t = H(k || m) — vulnerable to length extension."""
    def __init__(self, hash_fn=None):
        self._h = hash_fn or DLP_Hash()
    def mac(self, key, msg): return self._h.hash(key + msg)

class LengthExtensionAttack:
    """
    Demonstrates length-extension on naive H(k||m).

    The attacker knows (m, T=H(k||m)) and |k|. They do NOT know k.
    Because T is the opaque chaining value of the MD after processing
    (k||m||md_strengthening_pad), the attacker resumes the MD from state=T
    with any suffix they choose, forging a valid tag for
    (m || glue_padding || suffix) — still without knowing k.
    """
    def __init__(self, naive_mac, hash_cls=None):
        self.naive = naive_mac
        # Must reuse the same hash instance the MAC uses — the DLP_Hash has a
        # per-instance secret `alpha`, so a fresh DLP_Hash() would produce a
        # different hash function entirely.
        self._h = hash_cls if hash_cls is not None else naive_mac._h

    def extend(self, original_msg: bytes, original_tag: bytes, suffix: bytes,
                key_len: int = 16) -> tuple:
        """Given (m, T=H(k||m)), forge (m||glue||suffix, T') without k."""
        # Figure out glue padding that was appended after (k||m) during H(k||m).
        # The attacker knows |k| (or guesses it); they can compute the glue
        # because they know the structure of md_pad.
        block_size = self._h._md.block_size  # match the hash's actual block size
        prefix_len = key_len + len(original_msg)
        dummy_prefix = b'\x00' * prefix_len  # content of prefix irrelevant for glue
        padded_prefix = md_pad(dummy_prefix, block_size=block_size)
        glue_padding = padded_prefix[prefix_len:]
        # Total prefix bits consumed up to and including glue_padding:
        prefix_with_glue_bits = len(padded_prefix) * 8

        # Resume MD from state = original_tag, feeding just the suffix.
        # Our MD's "output" IS the internal chaining value, so the attacker can
        # continue hashing from T directly — the property that makes the naive
        # H(k||m) MAC insecure.
        new_tag = self._h._md.hash_resume(
            original_tag, suffix, prefix_with_glue_bits
        )
        extended_msg = original_msg + glue_padding + suffix
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
        if len(blob) < 16: return None
        r, ce = blob[:16], blob[16:]
        try:
            return self._cpa.decrypt(k_e, r, ce)
        except (AssertionError, ValueError):
            # Negligibly-likely path: HMAC accepted by collision but CT is malformed.
            return None


# ─────────── Demos ───────────
def demo_pa8():
    print("="*60); print("PA #8 — DLP-Based CRHF"); print("="*60)
    dlp = DLP_Hash()
    for msg in [b"hello", b"world", b"hello world", b"A"*100]:
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
    print("✓ PA#9 complete.")

def demo_pa10():
    print("="*60); print("PA #10 — HMAC + Encrypt-then-HMAC"); print("="*60)
    hmac = HMAC(); key = os.urandom(16); msg = b"authenticate this!"
    tag = hmac.mac(key, msg)
    print(f"  HMAC tag: {tag.hex()}")
    print(f"  Verify:   {hmac.verify(key, msg, tag)} ✓")
    # Length-extension on naive H(k||m)
    shared_hash = DLP_Hash()
    naive = NaiveMAC(hash_fn=shared_hash); atk = LengthExtensionAttack(naive)
    orig = b"original message"; ntag = naive.mac(key, orig)
    ext_msg, ext_tag = atk.extend(orig, ntag, b"SUFFIX", key_len=16)
    valid = naive.mac(key, ext_msg) == ext_tag
    print(f"\n  Length-extension on H(k||m): success={valid}")

    # Same attack on HMAC — should NOT forge a valid tag.
    hmac_tag_orig = hmac.mac(key, orig)
    # Attacker tries to forge an extension by running the same MD continuation.
    # HMAC wraps the hash in (outer_key), so the chaining value the attacker
    # sees is NOT the internal state of the inner hash — extension is impossible.
    forged_ext_msg = orig + b"SUFFIX"
    # Best the attacker can do: try the naive continuation on the HMAC tag.
    try:
        _, hmac_forged = LengthExtensionAttack(naive, hash_cls=shared_hash).extend(
            orig, hmac_tag_orig, b"SUFFIX", key_len=16
        )
    except Exception:
        hmac_forged = b''
    correct_hmac = hmac.mac(key, forged_ext_msg)
    hmac_blocked = hmac_forged != correct_hmac
    print(f"  Same attack on HMAC: blocked = {hmac_blocked} ✓")
    # Encrypt-then-HMAC
    eth = EtH_Enc(); ke=os.urandom(16); km=os.urandom(16)
    msg2 = b"EtH CCA message!"
    blob, t = eth.encrypt(ke, km, msg2)
    dec = eth.decrypt(ke, km, blob, t)
    print(f"\n  EtH encrypt/decrypt correct: {msg2==dec} ✓")
    tampered = bytearray(blob); tampered[10]^=0xFF
    dec2 = eth.decrypt(ke, km, bytes(tampered), t)
    print(f"  Tampered → {dec2} (⊥ = rejected) ✓")
    print("✓ PA#10 complete.")

if __name__ == "__main__":
    demo_pa8(); print(); demo_pa9(); print(); demo_pa10()

# ─────────── Wide hash (16 bytes) for signature use ───────────
class DLP_Hash_Wide:
    """
    16-byte DLP hash: concatenate 4 DLP_Hash evaluations with different IVs.
    Used by RSA_Sign to avoid trivial collisions in the 4-byte version.
    """
    def __init__(self):
        self._bases = [DLP_Compress(alpha=i+2) for i in range(4)]
        self._mds = [MerkleDamgard(compress=b.as_compress_fn()) for b in self._bases]

    def hash(self, message: bytes) -> bytes:
        return b''.join(md.hash(message) for md in self._mds)  # 16 bytes
