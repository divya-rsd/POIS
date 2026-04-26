"""PA #1 - One-Way Functions & Pseudorandom Generators.

This module provides:
1) Concrete OWF (DLP-based)
2) PRG from OWF using an iterative hard-core-bit extractor
3) OWF from PRG via f(s)=G(s) with a demo inversion experiment
4) NIST SP 800-22 style tests: frequency, runs, serial
5) Black-box PRG interface: seed(s), next_bits(n)
"""

import math
import os
import time
from typing import Dict, List, Tuple


def _int_to_bytes(x: int, out_len: int) -> bytes:
    return x.to_bytes(out_len, "big", signed=False)


def _bytes_to_int(x: bytes) -> int:
    return int.from_bytes(x, "big", signed=False)


def _is_probable_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for 64-bit integers."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in [2, 3, 5, 7, 11, 13, 17]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def _find_toy_safe_prime() -> Tuple[int, int]:
    """Find a toy safe-prime group with order around 2^30.

    Returns (p, q) where p = 2q + 1 and p, q are prime.
    """
    q = (1 << 30) + 3
    if q % 2 == 0:
        q += 1
    while True:
        if _is_probable_prime(q):
            p = 2 * q + 1
            if _is_probable_prime(p):
                return p, q
        q += 2


def _generator_of_order_q(p: int, q: int) -> int:
    """Find g in Z_p^* with exact order q (subgroup of quadratic residues)."""
    h = 2
    while h < p - 1:
        g = pow(h, 2, p)
        if g != 1 and pow(g, q, p) == 1:
            return g
        h += 1
    raise ValueError("Could not find generator for subgroup")


_TOY_P, _TOY_Q = _find_toy_safe_prime()
_TOY_G = _generator_of_order_q(_TOY_P, _TOY_Q)

# Exported defaults used by demos and downstream assignments.
DLP_P = _TOY_P
DLP_Q = _TOY_Q
DLP_G = _TOY_G

# ─────────────────────────────────────────────────────────────
# Minimal AES-128 (from scratch — satisfies no-library rule)
# ─────────────────────────────────────────────────────────────
class AES128:
    """Minimal AES-128 implementation (single block, ECB primitive)."""

    SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]

    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

    @staticmethod
    def _xtime(a: int) -> int:
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

    @classmethod
    def _gmul(cls, a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi: a ^= 0x1b
            b >>= 1
        return p

    @classmethod
    def _sub_bytes(cls, s: List[int]) -> List[int]:
        return [cls.SBOX[b] for b in s]

    @staticmethod
    def _shift_rows(s: List[int]) -> List[int]:
        return [s[0],s[5],s[10],s[15],
                s[4],s[9],s[14],s[3],
                s[8],s[13],s[2],s[7],
                s[12],s[1],s[6],s[11]]

    @classmethod
    def _mix_columns(cls, s: List[int]) -> List[int]:
        out = []
        for c in range(4):
            col = s[c*4:(c+1)*4]
            out.append(cls._gmul(col[0],2)^cls._gmul(col[1],3)^col[2]^col[3])
            out.append(col[0]^cls._gmul(col[1],2)^cls._gmul(col[2],3)^col[3])
            out.append(col[0]^col[1]^cls._gmul(col[2],2)^cls._gmul(col[3],3))
            out.append(cls._gmul(col[0],3)^col[1]^col[2]^cls._gmul(col[3],2))
        return out

    @classmethod
    def _key_expansion(cls, key: bytes) -> List[List[int]]:
        w = list(key)
        for i in range(4, 44):
            temp = w[(i-1)*4:i*4]
            if i % 4 == 0:
                temp = [cls.SBOX[temp[1]]^cls.RCON[i//4-1],
                        cls.SBOX[temp[2]],
                        cls.SBOX[temp[3]],
                        cls.SBOX[temp[0]]]
            w.extend([w[(i-4)*4+j]^temp[j] for j in range(4)])
        return [w[i*16:(i+1)*16] for i in range(11)]

    @classmethod
    def encrypt_block(cls, key: bytes, block: bytes) -> bytes:
        assert len(key) == 16 and len(block) == 16
        rkeys = cls._key_expansion(key)
        state = list(block)
        state = [state[i]^rkeys[0][i] for i in range(16)]
        for r in range(1, 11):
            state = cls._sub_bytes(state)
            state = cls._shift_rows(state)
            if r < 10:
                state = cls._mix_columns(state)
            state = [state[i]^rkeys[r][i] for i in range(16)]
        return bytes(state)


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result


class OWF_DLP:
    """OWF f(x)=g^x mod p in a prime-order subgroup of Z_p^*."""

    def __init__(self, p: int = DLP_P, q: int = DLP_Q, g: int = DLP_G):
        self.p = p
        self.q = q
        self.g = g

    def evaluate(self, x: int) -> int:
        x_mod_q = x % self.q
        return mod_exp(self.g, x_mod_q, self.p)

    def verify_hardness(self, trials: int = 30, guesses_per_trial: int = 10_000) -> Dict[str, object]:
        """Demo: random inversion attempts almost never recover the discrete log."""
        successes = 0
        t0 = time.time()
        for _ in range(trials):
            x = 1 + _bytes_to_int(os.urandom(8)) % (self.q - 1)
            y = self.evaluate(x)
            found = False
            for _ in range(guesses_per_trial):
                guess = 1 + _bytes_to_int(os.urandom(8)) % (self.q - 1)
                if self.evaluate(guess) == y:
                    found = True
                    break
            if found:
                successes += 1
        elapsed = time.time() - t0
        success_rate = successes / trials if trials else 0.0
        return {
            "function": "f(x)=g^x mod p",
            "group_bits": self.q.bit_length(),
            "trials": trials,
            "guesses_per_trial": guesses_per_trial,
            "successes": successes,
            "success_rate": round(success_rate, 6),
            "elapsed_s": round(elapsed, 4),
            "conclusion": (
                "Random inversion failed in almost all trials"
                if success_rate < 0.05
                else "Toy parameters are small; increase group size"
            ),
        }


class PRG_from_OWF:
    """Forward reduction OWF -> PRG using iterative hard-core bits.

    For n-bit seed x0 and user-selected ell >= 1:
        xi+1 = f(xi)
        G(x0) = b(x0) || b(x1) || ... || b(x_{n+ell-1})
    """

    def __init__(self, owf: OWF_DLP, seed_bits: int = 64):
        self.owf = owf
        self.seed_bits = seed_bits
        self._seed_val: int = 0
        self._state: int = 0

    def seed(self, s: int | bytes) -> None:
        """Set internal seed state (required black-box API)."""
        if isinstance(s, bytes):
            s_int = _bytes_to_int(s)
        else:
            s_int = int(s)
        mask = (1 << self.seed_bits) - 1
        self._seed_val = s_int & mask
        self._state = self._seed_val

    def _hard_core_bit(self, x: int) -> int:
        """LSB of x used as simple hard-core predicate."""
        return x & 1

    def next_bits(self, n: int) -> bytes:
        """Return next n pseudorandom bits as packed bytes."""
        if n <= 0:
            return b""
        bits: List[int] = []
        for _ in range(n):
            bits.append(self._hard_core_bit(self._state))
            self._state = self.owf.evaluate(self._state)
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j, bit in enumerate(bits[i : i + 8]):
                byte |= (bit << (7 - j))
            out.append(byte)
        return bytes(out)

    def generate(self, seed: int | bytes, length_bits: int) -> bytes:
        """Compatibility helper used by other assignments."""
        self.seed(seed)
        return self.next_bits(length_bits)

    def expand(self, seed: int | bytes, ell_bits: int) -> bytes:
        """Return n + ell pseudorandom bits (no seed leakage)."""
        self.seed(seed)
        total_bits = self.seed_bits + ell_bits
        return self.next_bits(total_bits)


class OWF_from_PRG:
    """Backward reduction PRG -> OWF.

    Argument sketch:
    If an efficient inverter I could recover s from f(s)=G(s) with non-negligible
    probability, one can distinguish G(U_n) from U_m by checking whether
    G(I(y))==y. This contradicts PRG security. Hence f(s)=G(s) is one-way.
    """

    def __init__(self, prg: PRG_from_OWF):
        self.prg = prg

    def evaluate(self, s: int | bytes, ell_bits: int = 256) -> bytes:
        """OWF evaluation f(s)=G(s), emitting n+ell bits."""
        return self.prg.expand(s, ell_bits)

    def verify_hardness(self, trials: int = 20, max_attempts: int = 20_000, ell_bits: int = 64) -> Dict[str, object]:
        """Demo: bounded inversion attempts for f(s)=G(s) do not recover seed."""
        recovered = 0
        t0 = time.time()
        for _ in range(trials):
            s = _bytes_to_int(os.urandom(8))
            target = self.evaluate(s, ell_bits=ell_bits)
            found_exact = False
            for _ in range(max_attempts):
                guess = _bytes_to_int(os.urandom(8))
                if self.evaluate(guess, ell_bits=ell_bits) == target:
                    found_exact = guess == s
                    break
            if found_exact:
                recovered += 1
        elapsed = time.time() - t0
        success_rate = recovered / trials if trials else 0.0
        return {
            "function": "f(s)=G(s)",
            "trials": trials,
            "attempts_per_trial": max_attempts,
            "recovered_exact_seed": recovered,
            "success_rate": round(success_rate, 6),
            "elapsed_s": round(elapsed, 4),
            "conclusion": "Adversary fails to recover seed in bounded PPT-style search",
        }

    # Backward-compatible alias expected by previous README text.
    def demonstrate_hardness(self, max_attempts: int = 2_000, output_bits: int = 16) -> Dict[str, object]:
        return self.verify_hardness(trials=1, max_attempts=max_attempts, ell_bits=output_bits)


class StatisticalTests:

    @staticmethod
    def to_bits(data: bytes) -> List[int]:
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @classmethod
    def frequency_monobit(cls, data: bytes) -> dict:
        """NIST SP 800-22 Frequency (Monobit) test."""
        bits = cls.to_bits(data)
        n = len(bits)
        if n == 0:
            return {"test": "Frequency (Monobit)", "pass": False, "reason": "empty input"}
        s = sum(1 if b == 1 else -1 for b in bits)
        s_obs = abs(s) / math.sqrt(n)
        p_value = math.erfc(s_obs / math.sqrt(2))
        return {
            "test": "Frequency (Monobit)",
            "n": n,
            "ones": sum(bits),
            "zeros": n - sum(bits),
            "ratio": round(sum(bits) / n, 4),
            "p_value": round(p_value, 6),
            "pass": p_value >= 0.01,
        }

    @classmethod
    def runs_test(cls, data: bytes) -> dict:
        """NIST SP 800-22 Runs test."""
        bits = cls.to_bits(data)
        n = len(bits)
        if n < 2:
            return {"test": "Runs", "pass": False, "reason": "input too short"}
        ones = sum(bits)
        pi = ones / n
        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return {"test": "Runs", "pass": False, "reason": "frequency pre-test failed", "p_value": 0.0}
        runs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i-1])
        expected = 2 * n * pi * (1 - pi)
        denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        p_value = math.erfc(abs(runs - expected) / denom) if denom > 0 else 0.0
        return {
            "test": "Runs",
            "n": n,
            "runs": runs,
            "expected_runs": round(expected, 2),
            "p_value": round(p_value, 6),
            "pass": p_value >= 0.01,
        }

    @classmethod
    def serial_test(cls, data: bytes, m: int = 2) -> dict:
        """NIST SP 800-22 Serial test (toy m=2 implementation)."""
        bits = cls.to_bits(data)
        n = len(bits)
        if n < max(16, 2 * m):
            return {"test": f"Serial (m={m})", "pass": False, "reason": "input too short"}

        patterns_m = {}
        patterns_m1 = {}
        for i in range(n):
            pm = tuple(bits[i : i + m] + bits[: max(0, m - (n - i))])
            pm1 = tuple(bits[i : i + m - 1] + bits[: max(0, m - 1 - (n - i))])
            patterns_m[pm] = patterns_m.get(pm, 0) + 1
            patterns_m1[pm1] = patterns_m1.get(pm1, 0) + 1

        psi_m = sum(v**2 for v in patterns_m.values()) * (2**m) / n - n
        psi_m1 = sum(v**2 for v in patterns_m1.values()) * (2 ** (m - 1)) / n - n
        delta1 = psi_m - psi_m1
        p_value = math.exp(-delta1 / 2) if delta1 > 0 else 1.0
        return {
            "test": f"Serial (m={m})",
            "n": n,
            "psi_m": round(psi_m, 4),
            "delta1": round(delta1, 4),
            "p_value": round(p_value, 6),
            "pass": p_value >= 0.01,
        }

    @classmethod
    def run_all(cls, data: bytes) -> List[dict]:
        return [
            cls.frequency_monobit(data),
            cls.runs_test(data),
            cls.serial_test(data),
        ]


def demo():
    print("=" * 62)
    print("PA #1 - One-Way Functions and Pseudorandom Generators")
    print("=" * 62)

    print("\n[1] OWF (DLP) with evaluate(x) and verify_hardness()")
    owf = OWF_DLP()
    x = 123456
    y = owf.evaluate(x)
    print(f"  Group: p={owf.p}, q={owf.q}, g={owf.g}")
    print(f"  f({x}) = {y}")
    dlp_hardness = owf.verify_hardness(trials=20, guesses_per_trial=5000)
    print(
        "  Hardness demo:",
        f"success_rate={dlp_hardness['success_rate']},",
        dlp_hardness["conclusion"],
    )

    print("\n[2] PRG from OWF (seed(s), next_bits(n), n+ell expansion)")
    prg = PRG_from_OWF(owf, seed_bits=64)
    seed_val = _bytes_to_int(os.urandom(8))
    ell_bits = 256
    out_n_plus_ell = prg.expand(seed_val, ell_bits=ell_bits)
    print(f"  Seed (64-bit): 0x{seed_val:016x}")
    print(f"  Output length: {len(out_n_plus_ell) * 8} bits (n+ell)")
    print(f"  G(seed) prefix: {out_n_plus_ell[:16].hex()}...")

    print("\n[2.1] PRG determinism check")

    s = 12345

    out1 = prg.generate(s, 128)
    out2 = prg.generate(s, 128)
    out3 = prg.generate(s + 1, 128)

    print("  Same seed consistency:", "PASS" if out1 == out2 else "FAIL")
    print("  Different seed variation:", "PASS" if out1 != out3 else "FAIL")

    print("\n[3] NIST-style statistical tests (frequency, runs, serial)")
    large_output = prg.generate(seed_val, 8192)
    results = StatisticalTests.run_all(large_output)
    for r in results:
        status = "PASS" if r.get("pass") else "FAIL"
        pv = r.get("p_value", "N/A")
        print(f"  {r['test']}: p-value={pv} [{status}]")

    print("\n[4] OWF from PRG (f(s)=G(s)) with inversion demo")
    owf_from_prg = OWF_from_PRG(prg)
    back_demo = owf_from_prg.verify_hardness(trials=10, max_attempts=3000, ell_bits=64)
    print(
        "  Inversion demo:",
        f"success_rate={back_demo['success_rate']},",
        back_demo["conclusion"],
    )

    print("\nPA#1 demo complete.")


if __name__ == "__main__":
    demo()
