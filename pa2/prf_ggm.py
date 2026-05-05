"""
PA #2 — Pseudorandom Functions via GGM Tree

Implements:
  - GGM PRF from PA#1 PRG (forward: PRG → PRF)
  - PRG from PRF (backward: PRF → PRG)
  - AES plug-in as alternative PRF
  - Distinguishing game demo
  - Interface: F(k, x) for downstream PAs
"""

import os
import sys
import secrets
from typing import Callable, Optional, Union

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pa1.owf_prg import AES128, PRG_from_OWF, OWF_DLP, StatisticalTests


# ─────────────────────────────────────────────────────────────
# Length-doubling PRG wrapper (needed by GGM)
# G: {0,1}^n → {0,1}^2n  split into G0 (left) and G1 (right)
# ─────────────────────────────────────────────────────────────
class LengthDoublingPRG:
    """Wraps any seed-expansion function to provide G0/G1 split."""

    def __init__(self, block_bytes: int = 4, forward_prg: Optional[PRG_from_OWF] = None):
        self.block_bytes = block_bytes
        # Use PA#1 PRG (PRG_from_OWF) as the default expansion primitive.
        # Instantiate a lightweight OWF/DLP-backed PRG if none supplied.
        self._forward_prg = forward_prg or PRG_from_OWF(OWF_DLP(prime_bits=64))

    def _expand(self, seed_bytes: bytes) -> bytes:
        """Expand seed to 2x length using the PA#1 PRG.

        We interpret `seed_bytes` as a big-endian integer seed s and call
        PRG_from_OWF.generate(s, ell_bits) with a 128-bit seed space so that
        the PRG produces 256 total bits (32 bytes), matching the existing
        GGM test/visualization contract.
        """
        seed_bytes = seed_bytes.rjust(16, b'\x00')[:16]
        seed_bits = 128
        seed_int = int.from_bytes(seed_bytes, 'big')
        # Request a 256-bit expansion directly from PA#1.
        prg_out = self._forward_prg.generate(seed_int, seed_bits * 2)
        return prg_out

    def G0(self, seed: bytes) -> bytes:
        """Left half of G(seed)."""
        expanded = self._expand(seed)
        return expanded[:len(expanded) // 2]

    def G1(self, seed: bytes) -> bytes:
        """Right half of G(seed)."""
        expanded = self._expand(seed)
        return expanded[len(expanded) // 2:]

    def G(self, seed: bytes) -> bytes:
        """Full expansion G(seed) = G0(seed) || G1(seed)."""
        return self._expand(seed)


# ─────────────────────────────────────────────────────────────
# GGM PRF Construction
# Fk(b1 b2 ... bn) = G_{bn}( ... G_{b2}( G_{b1}(k) ) ... )
# ─────────────────────────────────────────────────────────────
class GGM_PRF:
    """
    Forward: PRG → PRF via GGM tree construction.
    Key k ∈ {0,1}^n, input x ∈ {0,1}^n (as bit string).
    Fk(x) = G_{x_n}( ... G_{x_1}(k) )
    """

    def __init__(self, prg: Optional[LengthDoublingPRG] = None):
        self.prg = prg or LengthDoublingPRG()

    def _bits(self, x: Union[int, bytes], n_bits: int) -> list:
        """Convert an integer or byte string into a bit list (MSB first)."""
        if isinstance(x, bytes):
            bits = []
            for byte in x:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)
            return bits
        return [(x >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]

    def evaluate(self, key: bytes, x: Union[int, bytes], n_bits: int = 8) -> bytes:
        """
        Evaluate PRF: Fk(x).
        key: n-byte seed
        x: integer query (n_bits wide)
        """
        bits = self._bits(x, n_bits)
        state = key
        for bit in bits:
            state = self.prg.G0(state) if bit == 0 else self.prg.G1(state)
        return state

    def __call__(self, key: bytes, x: Union[int, bytes], n_bits: int = 8) -> bytes:
        return self.evaluate(key, x, n_bits)

    def get_path(self, key: bytes, x: Union[int, bytes], n_bits: int = 8) -> list:
        """Return full root-to-leaf path (for visualization)."""
        bits = self._bits(x, n_bits)
        path = [{'level': 0, 'bit': None, 'value': key.hex(), 'node': 'root'}]
        state = key
        for i, bit in enumerate(bits):
            state = self.prg.G0(state) if bit == 0 else self.prg.G1(state)
            path.append({
                'level': i + 1,
                'bit': bit,
                'fn': f'G{bit}',
                'value': state.hex(),
                'node': f'level-{i+1}-bit{bit}'
            })
        return path


# ─────────────────────────────────────────────────────────────
# AES-based PRF (plug-in alternative)
# ─────────────────────────────────────────────────────────────
class AES_PRF:
    """
    Concrete PRF using AES-128: Fk(x) = AES_k(x).
    Satisfies no-library rule — uses our own AES128 implementation.
    """

    @staticmethod
    def evaluate(key: bytes, x: bytes) -> bytes:
        """Fk(x) = AES_k(x). key and x must be 16 bytes."""
        k = key.ljust(16, b'\x00')[:16]
        blk = (x + b'\x00' * 16)[:16]
        return AES128.encrypt_block(k, blk)

    @staticmethod
    def __call__(key: bytes, x: bytes) -> bytes:
        return AES_PRF.evaluate(key, x)


# ─────────────────────────────────────────────────────────────
# Backward: PRG from PRF
# G(s) = Fs(0^n) || Fs(1^n)
# ─────────────────────────────────────────────────────────────
class PRG_from_PRF:
    """
    Backward direction: PRF → PRG
    G(s) = Fs(0ⁿ) || Fs(1ⁿ)
    If G were distinguishable from random, the distinguisher breaks PRF security.
    """

    def __init__(self, prf: GGM_PRF, n_bits: int = 8):
        self.prf = prf
        self.n_bits = n_bits

    def generate(self, seed: bytes, output_bytes: int = 8) -> bytes:
        """Produce pseudorandom output using counter-based PRF expansion.

        The first block follows the assignment-style length-doubling shape
        Fs(0^n) || Fs(1^n); additional blocks are produced with fresh
        counters to avoid periodic repetition.
        """
        if output_bytes <= 0:
            return b''

        zero = 0
        ones = (1 << self.n_bits) - 1
        blocks = [self.prf.evaluate(seed, zero, self.n_bits), self.prf.evaluate(seed, ones, self.n_bits)]
        counter = 2
        while sum(len(block) for block in blocks) < output_bytes:
            blocks.append(self.prf.evaluate(seed, counter, self.n_bits))
            counter += 1
        return b''.join(blocks)[:output_bytes]

    def statistical_test(self, seed: bytes, n_bytes: int = 256) -> list:
        """Run same statistical tests as PA#1."""
        data = self.generate(seed, n_bytes)
        return StatisticalTests.run_all(data)


# ─────────────────────────────────────────────────────────────
# Distinguishing Game Demo
# ─────────────────────────────────────────────────────────────
class PRFDistinguishingGame:
    """
    IND-PRF game: adversary queries Fk on 100 inputs.
    Compare with truly random function on same inputs.
    No statistical difference should be detectable.
    """

    def __init__(self, prf: GGM_PRF, key: bytes, n_bits: int = 8):
        self.prf = prf
        self.key = key
        self.n_bits = n_bits
        self._block_len = len(self.prf.evaluate(self.key, 0, self.n_bits))
        # Build a "truly random" oracle
        self._random_oracle: dict = {}

    def query_prf(self, x: int) -> bytes:
        return self.prf.evaluate(self.key, x, self.n_bits)

    def query_random(self, x: int) -> bytes:
        if x not in self._random_oracle:
            self._random_oracle[x] = os.urandom(self._block_len)
        return self._random_oracle[x]

    def run_experiment(self, n_queries: int = 100) -> dict:
        # CSPRNG-driven queries (secrets → os.urandom).
        queries = [secrets.randbelow(2 ** self.n_bits) for _ in range(n_queries)]
        prf_outputs = [self.query_prf(q) for q in queries]
        rand_outputs = [self.query_random(q) for q in queries]

        # Statistical comparison: bit frequency
        def bit_freq(outputs):
            bits = []
            for b in outputs:
                for byte in b:
                    for i in range(7, -1, -1):
                        bits.append((byte >> i) & 1)
            return sum(bits) / len(bits) if bits else 0

        prf_freq = bit_freq(prf_outputs)
        rand_freq = bit_freq(rand_outputs)

        return {
            'queries': n_queries,
            'prf_bit_frequency': round(prf_freq, 4),
            'random_bit_frequency': round(rand_freq, 4),
            'difference': round(abs(prf_freq - rand_freq), 4),
            'indistinguishable': abs(prf_freq - rand_freq) < 0.05,
            'conclusion': 'PRF output indistinguishable from random ✓'
                          if abs(prf_freq - rand_freq) < 0.05
                          else 'WARNING: Statistical difference detected!'
        }


# ─────────────────────────────────────────────────────────────
# Unified Interface F(k, x) for downstream PAs
# ─────────────────────────────────────────────────────────────
class PRF:
    """
    Unified PRF interface for PA#3, PA#4, PA#5.
    Backed by GGM construction or AES plug-in.
    """

    def __init__(self, use_aes: bool = True):
        self.use_aes = use_aes
        if not use_aes:
            self._ggm = GGM_PRF()
        self._aes = AES_PRF()

    def evaluate(self, key: bytes, x: bytes) -> bytes:
        """Fk(x) — main interface."""
        if self.use_aes:
            return self._aes.evaluate(key, x)
        k_bytes = (key + b'\x00' * 16)[:16]
        return self._ggm.evaluate(k_bytes, x)

    def __call__(self, key: bytes, x: bytes) -> bytes:
        return self.evaluate(key, x)


# ─────────────────────────────────────────────────────────────
# Demo
# ─────────────────────────────────────────────────────────────
def demo():
    print("=" * 60)
    print("PA #2 — Pseudorandom Functions via GGM Tree")
    print("=" * 60)

    prg = LengthDoublingPRG()
    prf = GGM_PRF(prg)
    key = os.urandom(8)

    print(f"\n[GGM PRF]  key = {key.hex()}")
    for x in [0b1011, 0b0110, 0b1100]:
        out = prf.evaluate(key, x, n_bits=4)
        print(f"  F_k({x:04b}) = {out.hex()}")

    # Show path
    path = prf.get_path(key, 0b1011, n_bits=4)
    print("\n  GGM root-to-leaf path for x=1011:")
    for step in path:
        if step['bit'] is None:
            print(f"    Root: {step['value'][:16]}…")
        else:
            print(f"    Level {step['level']} ({step['fn']}): {step['value'][:16]}…")

    # AES plug-in
    print("\n[AES PRF plug-in]")
    aes_prf = AES_PRF()
    ak = os.urandom(16)
    ax = b'\x10\x11\x12\x13' + b'\x00' * 12
    print(f"  AES_k(x) = {aes_prf.evaluate(ak, ax).hex()}")

    # Backward: PRG from PRF
    print("\n[Backward: PRG from PRF]")
    prg_from_prf = PRG_from_PRF(prf)
    seed = os.urandom(8)
    prg_out = prg_from_prf.generate(seed, 64)
    print(f"  G(seed) = {prg_out.hex()[:32]}…")
    test_results = prg_from_prf.statistical_test(seed)
    for r in test_results:
        print(f"  {r['test']}: p={r.get('p_value','N/A')} [{'PASS ✓' if r['pass'] else 'FAIL ✗'}]")

    # Distinguishing game
    print("\n[Distinguishing Game — 100 queries]")
    game = PRFDistinguishingGame(prf, key)
    result = game.run_experiment(100)
    print(f"  PRF bit freq:    {result['prf_bit_frequency']}")
    print(f"  Random bit freq: {result['random_bit_frequency']}")
    print(f"  {result['conclusion']}")

    print("\n✓ PA#2 complete.")


if __name__ == "__main__":
    demo()
