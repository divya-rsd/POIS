## Project Structure

```
pois_project/
├── run_all.py                    ← Master test runner (all PAs)
├── README.md                     ← This file
│
├── pa0_web/
│   └── index.html                ← PA#0: Minicrypt Clique Web Explorer
│
├── pa1/
│   └── owf_prg.py                ← PA#1: OWF (DLP + AES) + PRG (HILL)
│
├── pa2/
│   └── prf_ggm.py                ← PA#2: PRF via GGM Tree + AES plug-in
│
├── pa3/
│   └── cpa_enc.py                ← PA#3: CPA-Secure Encryption
│
├── pa4/
│   └── modes.py                  ← PA#4: CBC / OFB / CTR Modes
│
├── pa5/
│   └── mac.py                    ← PA#5: PRF-MAC + CBC-MAC + EUF-CMA game
│
├── pa6/
│   └── cca_enc.py                ← PA#6: CCA-Secure Encryption (Encrypt-then-MAC)
│
├── pa7/
│   └── merkle_damgard.py         ← PA#7: Merkle-Damgård Transform
│
├── pa8_9_10/
│   └── hash_hmac.py              ← PA#8: DLP Hash + PA#9: Birthday Attack + PA#10: HMAC
│
├── pa11/
│   └── dh.py                     ← PA#11: Diffie-Hellman Key Exchange
│
├── pa12/
│   └── rsa.py                    ← PA#12: Textbook RSA + PKCS#1 v1.5
│
├── pa13/
│   └── primality.py              ← PA#13: Miller-Rabin Primality Testing
│
├── pa14_15_16/
│   └── crt_sig_elgamal.py        ← PA#14: CRT+Håstad + PA#15: Signatures + PA#16: ElGamal
│
└── pa17_18_19_20/
    └── mpc.py                    ← PA#17: CCA-PKC + PA#18: OT + PA#19: AND + PA#20: MPC
```

---

## Quick Start

```bash
# Run all assignments
python run_all.py

# Run individual PAs
python pa1/owf_prg.py
python pa2/prf_ggm.py
python pa3/cpa_enc.py
python pa4/modes.py
python pa5/mac.py
python pa6/cca_enc.py
python pa7/merkle_damgard.py
python pa8_9_10/hash_hmac.py
python pa11/dh.py
python pa12/rsa.py
python pa13/primality.py
python pa14_15_16/crt_sig_elgamal.py
python pa17_18_19_20/mpc.py

# PA#0 Web Explorer — open in browser
open pa0_web/index.html
```

**Requirements:** Python 3.8+ — No external packages needed (no-library rule enforced throughout).

---

## Implementation Details

### PA #0 — Minicrypt Clique Web Explorer
**File:** `pa0_web/index.html`  
Single-file React-equivalent HTML/JS application. Open directly in any modern browser.

**Features implemented:**
- Foundation toggle: AES-128 (PRP) / DLP (gˣ mod p)
- Two-column layout: Leg 1 (Foundation→A) and Leg 2 (A→B)
- Full routing table with all 17 supported reductions
- Forward and backward direction toggle
- Rich step-by-step visualization:
  - GGM tree path (PRG→PRF)
  - Feistel rounds (PRF→PRP)
  - HMAC computation (CRHF→HMAC)
  - Encrypt-then-MAC (MAC→CCA-Enc)
  - Stub placeholders for unimplemented primitives
- IND-SEC security game with live advantage counter
- Collapsible proof panel with formal theorem statements
- Live data flow on all input changes
- Dark mode support

---

### PA #1 — One-Way Functions & Pseudorandom Generators
**File:** `pa1/owf_prg.py`

**OWF implementations:**
- `OWF_DLP`: f(x) = gˣ mod p (Discrete Log Problem, safe-prime group)
- `OWF_AES`: f(k) = AESk(0¹²⁸) ⊕ k (Davies-Meyer style)

**PRG from OWF (forward, PA#1a):**  
HILL/Håstad-Impagliazzo-Levin-Luby construction. Iterates OWF and extracts Goldreich-Levin hard-core bit b(x) = LSB(gˣ mod p).

**OWF from PRG (backward, PA#1b):**  
f(s) = G(s) is a OWF — inverting it recovers the PRG seed, breaking pseudorandomness.

**Statistical tests (NIST SP 800-22 subset):**
- Frequency (Monobit): checks |ones/n − 0.5| is small
- Runs test: checks run distribution matches random
- Serial test (m=2): checks overlapping bit-pair distribution

**AES-128 (from scratch):**  
Full SubBytes, ShiftRows, MixColumns, KeyExpansion implemented byte-by-byte. No library usage.

---

### PA #2 — Pseudorandom Functions via GGM Tree
**File:** `pa2/prf_ggm.py`

**GGM PRF (forward, PA#2a):**  
`Fk(b₁…bₙ) = G_{bₙ}(…G_{b₁}(k))`. Root-to-leaf path traversal. Uses `LengthDoublingPRG` backed by AES to produce G₀/G₁ halves.

**PRG from PRF (backward, PA#2b):**  
`G(s) = Fs(0ⁿ) ∥ Fs(1ⁿ)`. Statistical tests confirm pseudorandomness.

**AES plug-in:** `AES_PRF.evaluate(key, x) = AES_key(x)` — drop-in replacement.

**Unified interface:** `PRF(key, x)` used by PA#3, PA#4, PA#5.

---

### PA #3 — CPA-Secure Symmetric Encryption
**File:** `pa3/cpa_enc.py`

**Scheme:** `Enc(k,m) = ⟨r, Fk(r) ⊕ m⟩` with fresh random r each call.

**Multi-block:** Counter extension — r, r+1, r+2, … with PKCS#7 padding.

**IND-CPA game:** Dummy adversary advantage ≈ 0 over 50 rounds.

**Broken variant:** Deterministic encryption (fixed nonce). Adversary wins with advantage = 0.5 — detects identical ciphertexts for identical plaintexts.

---

### PA #4 — Modes of Operation
**File:** `pa4/modes.py`

| Mode | Enc parallel | Dec parallel | Random access | Error prop | IV reuse |
|------|:---:|:---:|:---:|:---:|:---:|
| CBC  | ✗ | ✓ | ✗ | 2 blocks | Fatal |
| OFB  | ✗ | ✗ | ✗ | Same block | Fatal |
| CTR  | ✓ | ✓ | ✓ | Same block | Fatal |

All three modes implemented with unified `Modes.encrypt(mode, key, msg)` API.

---

### PA #5 — Message Authentication Codes
**File:** `pa5/mac.py`

- `PRF_MAC`: `Mac_k(m) = Fk(m)` (fixed-length)
- `CBC_MAC`: chains PRF over message blocks (variable-length)
- `HMAC_stub`: raises `NotImplementedError` — full impl in PA#10
- `EUF_CMA_Game`: adversary with 50 signing queries cannot forge

---

### PA #6 — CCA-Secure Symmetric Encryption
**File:** `pa6/cca_enc.py`

**Encrypt-then-MAC:** `CE ← Enc(kE, m)`, `t ← MAC(kM, CE)`, output `(CE, t)`.  
Decryption: verify MAC **before** decrypting — tampered ciphertexts return ⊥.

**Malleability demo:** CPA-only scheme allows bit-flip to corrupt plaintext. CCA scheme detects and rejects.

---

### PA #7 — Merkle-Damgård Transform
**File:** `pa7/merkle_damgard.py`

Generic `MerkleDamgard(compress, IV, block_size)` class accepts any compression function.

**MD-strengthening padding:** `msg ∥ 0x80 ∥ 0* ∥ ⟨|msg|⟩₆₄` (big-endian length field).

**Collision propagation demo:** Collision in compression function → collision in full MD hash.

---

### PA #8, 9, 10 — Hashing, Birthday Attack, HMAC
**File:** `pa8_9_10/hash_hmac.py`

**PA#8 — DLP Hash:**  
`h(x,y) = gˣ · ĥʸ mod p`. Collision requires computing `log_g(ĥ)` — solves DLP.  
Plugged into PA#7 MD framework for full `DLP_Hash.hash(message)`.

**PA#9 — Birthday Attack:**
- Naive: hash random inputs into dictionary, find first collision
- Floyd's: tortoise-and-hare cycle detection (O(1) space)
- Empirical curve matches theoretical `√(π·N/2)` prediction

**PA#10 — HMAC:**  
`HMAC_k(m) = H((k⊕opad) ∥ H((k⊕ipad) ∥ m))`

- Length-extension attack on naive `H(k∥m)` — demonstrated
- Same attack fails on HMAC — blocked by outer keyed hash
- `EtH_Enc`: Encrypt-then-HMAC CCA-secure encryption
- Constant-time comparison via `secrets.compare_digest`

**Bidirectional (CRHF ↔ MAC via HMAC):**
- Forward: CRHF → HMAC → MAC
- Backward: `HMAC_k` with fixed k is collision-resistant; MAC as MD compression → CRHF

---

### PA #11 — Diffie-Hellman Key Exchange
**File:** `pa11/dh.py`

Safe-prime generation via PA#13. Three-step protocol: `alice_step1`, `bob_step1`, shared key computed by both. MITM attack demonstrated.

---

### PA #12 — Textbook RSA + PKCS#1 v1.5
**File:** `pa12/rsa.py`

- Key generation via PA#13 Miller-Rabin
- Extended Euclidean for modular inverse (from scratch)
- Square-and-multiply modular exponentiation (from scratch)
- CRT-based decryption (Garner's algorithm) — ~4× speedup
- PKCS#1 v1.5 padding with random PS bytes
- Textbook determinism attack demonstrated
- Bleichenbacher oracle (simplified toy version)

---

### PA #13 — Miller-Rabin Primality Testing
**File:** `pa13/primality.py`

Exact algorithm: write `n−1 = 2ˢ·d`, test k witnesses with square-and-multiply.  
Error probability ≤ 4⁻ᵏ. Carmichael number 561 correctly rejected.

---

### PA #14 — CRT + Håstad's Broadcast Attack
**File:** `pa14_15_16/crt_sig_elgamal.py`

**CRT solver:** Constructive `∑ aᵢ·Mᵢ·(Mᵢ⁻¹ mod nᵢ) mod N`

**Håstad's broadcast attack:** Three RSA ciphertexts with e=3, same message → CRT recovers m³, integer cube root recovers m. Fails with PKCS padding.

---

### PA #15 — Digital Signatures
**File:** `pa14_15_16/crt_sig_elgamal.py`

`Sign_sk(m) = H(m)^d mod N`, `Vrfy_vk(m,σ) = (σ^e mod N == H(m))`

Hash-then-sign prevents multiplicative forgery (demonstrated on raw RSA).

---

### PA #16 — ElGamal PKC
**File:** `pa14_15_16/crt_sig_elgamal.py`

`Enc(pk, m) = (gʳ, m·hʳ)`. CPA-secure under DDH assumption.  
Malleability: `(c₁, 2c₂ mod p)` decrypts to `2m` — demonstrated.

---

### PA #17 — CCA-Secure PKC (Signcrypt)
**File:** `pa17_18_19_20/mpc.py`

Encrypt-then-Sign: `CE ← ElGamal_pk(m)`, `σ ← Sign_sk(CE)`. Verify signature before decrypting — tampered ciphertext detected by signature check.

---

### PA #18 — Oblivious Transfer
**File:** `pa17_18_19_20/mpc.py`

1-out-of-2 OT via ElGamal (Bellare-Micali style):
1. Receiver generates real `pk_b` (knows `sk_b`) and fake `pk_{1-b}` (no secret key)
2. Sender encrypts both messages under respective keys
3. Receiver decrypts only the b-th ciphertext

Sender learns nothing about b; receiver gets only `m_b`.

---

### PA #19 — Secure AND Gate
**File:** `pa17_18_19_20/mpc.py`

`Secure_AND(a,b)`: Alice sends `(0, a)` as OT messages; Bob uses choice bit b.  
Bob receives `m_b = a·b = a AND b`. Neither party learns the other's bit.

`Secure_XOR(a,b) = a ⊕ b` — free via additive secret sharing.

---

### PA #20 — All 2-Party Secure Computation
**File:** `pa17_18_19_20/mpc.py`

Boolean circuit evaluator using secure gates:
- **Millionaire's problem:** MSB-first secure comparison using AND/XOR gates
- **Secure equality:** Bit-wise equality without revealing values
- **Secure addition:** mod 2ⁿ addition

**Full lineage:** MPC → Secure AND → OT → ElGamal → DH group → Miller-Rabin

---

## No-Library Rule Compliance

| Component | Implementation |
|-----------|---------------|
| AES-128 | Fully from scratch (SubBytes, ShiftRows, MixColumns, KeyExpansion) |
| Modular exponentiation | Square-and-multiply, implemented from scratch |
| Extended GCD / mod inverse | Recursive extended Euclidean, from scratch |
| Miller-Rabin | Exact NIST algorithm, from scratch |
| RSA | Key generation, encrypt, decrypt, CRT — all from scratch |
| ElGamal | Full PKC from scratch using PA#11 DH group |
| PRF/PRG | GGM tree + length-doubling PRG, from scratch |
| HMAC | Full construction from scratch over PA#8 DLP hash |
| **Only exceptions** | `os.urandom` (OS randomness), `secrets.compare_digest` (constant-time), Python built-in `int` arithmetic |

---

## Bidirectional Reductions Summary

| Pair | Forward | Backward | PAs |
|------|---------|----------|-----|
| OWF ↔ PRG | HILL construction | G is a OWF | PA#1a, PA#1b |
| PRG ↔ PRF | GGM tree | G(s)=Fs(0)∥Fs(1) | PA#2a, PA#2b |
| PRF ↔ PRP | Luby-Rackoff Feistel | PRP/PRF switching lemma | PA#4 |
| PRF ↔ MAC | Mac_k(m)=Fk(m) | MAC oracle as PRF | PA#5, PA#5b |
| CRHF ↔ HMAC | HMAC construction | Fixed-key HMAC is CRHF | PA#10 |
| HMAC ↔ MAC | HMAC is EUF-CMA | MAC as MD compression | PA#10 |
| CRHF ↔ MAC | Via HMAC bridge | Via HMAC bridge | PA#10 |

---

## Security Notions Implemented

```
OTP (perfect) → CPA-Secure (PRF-based) → CCA-Secure (Encrypt-then-MAC)
                                             ↑
                               PA#3         PA#6, PA#10
```

---


command to start the server:
uvicorn backend:app --host 0.0.0.0 --port 5050 --reload