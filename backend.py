"""
PA #0 — Backend HTTP API connecting the React/HTML explorer (pa0_web/) to the
real Python implementations of PA#1–PA#20.

The previous build had no backend at all; the JS used toy in-browser stubs.
This file fills that gap: each endpoint calls a real PA module (PA#1 OWF/PRG,
PA#2 GGM PRF, PA#5 MAC, PA#10 HMAC, etc.) and returns the actual intermediate
hex values so the explorer can show genuine cryptographic computation.

Run with:
    python3 backend.py        # serves on http://localhost:5050
"""
import os
import sys
import time
import binascii
import traceback
import secrets
from typing import Any, Dict

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn

# Real implementations — lazy imports keep startup fast
from pa1.owf_prg import (
    AES128, OWF_DLP, OWF_AES, PRG_from_OWF, mod_exp,
)
from pa2.prf_ggm import GGM_PRF, AES_PRF, LengthDoublingPRG
from pa3.cpa_enc import CPA_Enc
from pa4.modes import Modes
from pa5.mac import PRF_MAC, CBC_MAC
from pa6.cca_enc import CCA_Enc
from pa7.merkle_damgard import MerkleDamgard, md_pad
from pa8_9_10.hash_hmac import DLP_Hash, HMAC, EtH_Enc, BirthdayAttack
from pa11.dh import DH
from pa12.rsa import RSA, RSA_PKCS15
from pa13.primality import is_prime, gen_prime, miller_rabin
from pa14_15_16.crt_sig_elgamal import (
    crt as crt_solver, hastad_attack, ElGamal,
)
from pa17_18_19_20.mpc import CCA_PKC, OT_1of2, SecureGates, SecureCircuit


# ─────────────────────────────────────────────────────────────────────────────
# Singletons (created once; key/group params reused across requests)
# ─────────────────────────────────────────────────────────────────────────────
_OWF_DLP = OWF_DLP(prime_bits=48)         # small for snappy response
_OWF_AES = OWF_AES()
_PRG     = PRG_from_OWF(_OWF_DLP)
_GGM     = GGM_PRF(LengthDoublingPRG())
_AES_PRF = AES_PRF()
_CPA     = CPA_Enc()
_MODES   = Modes()
_PRFMAC  = PRF_MAC()
_CBCMAC  = CBC_MAC()
_CCA     = CCA_Enc()
_MD      = MerkleDamgard()
_DLPH    = DLP_Hash()
_HMAC    = HMAC(hash_fn=_DLPH)
_ETH     = EtH_Enc()
_DH      = None                            # generated lazily (slow)
_RSA     = None
_PKCS    = None
_ELG     = None
_OT      = OT_1of2(bits=128)
_GATES   = SecureGates(bits=128)
_CIRCUIT = SecureCircuit(_GATES)
_CCA_PKC = None


def _ensure_dh():
    global _DH
    if _DH is None:
        _DH = DH(bits=128)
    return _DH

def _ensure_rsa():
    global _RSA, _PKCS
    if _RSA is None:
        _RSA = RSA(bits=512)
        _PKCS = RSA_PKCS15(_RSA)
    return _RSA, _PKCS

def _ensure_elg():
    global _ELG
    if _ELG is None:
        _ELG = ElGamal(bits=128)
    return _ELG

def _ensure_rsa_sign_keys():
    rsa, _ = _ensure_rsa()
    return rsa.sk, rsa.pk

_EG_KEYS = None
def _ensure_eg_keys():
    global _EG_KEYS
    eg = _ensure_elg()
    if _EG_KEYS is None:
        _EG_KEYS = eg.keygen()
    return _EG_KEYS


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Minicrypt Backend API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "trace": traceback.format_exc()}
    )

async def safe_json(request: Request) -> dict:
    try:
        return await request.json()
    except Exception:
        return {}




# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _hex_to_bytes(s: str, fallback_len: int = 16) -> bytes:
    """Tolerant hex parse: accept hex or text; pad/truncate to fallback_len bytes."""
    s = (s or "").strip()
    try:
        b = binascii.unhexlify(s)
    except Exception:
        b = s.encode()
    if len(b) < fallback_len:
        b = b + b"\x00" * (fallback_len - len(b))
    return b[:fallback_len]


def _to_hex(b) -> str:
    if isinstance(b, int):
        return hex(b)[2:].upper()
    if isinstance(b, (bytes, bytearray)):
        return b.hex().upper()
    return str(b)


def _exact_iroot(n: int, k: int) -> tuple:
    """Return (root, exact) where root = floor(n^(1/k)) and exact iff root**k == n.

    The PA module's `integer_nth_root` seeds Newton with `int(n**(1/k))+1`, which
    silently loses precision once n exceeds ~2^53. We use a bit-length seed
    (no float math) and verify, so the demo's cube-root step is reliable on
    arbitrary-precision integers.
    """
    if n < 0:
        raise ValueError("negative n")
    if n < 2 or k == 1:
        return n, True
    # Bit-length seed: floor(log2 n)/k bits, rounded up.
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        t = x ** (k - 1)
        y = ((k - 1) * x + n // t) // k
        if y >= x:
            break
        x = y
    # x is now an upper estimate; correct any off-by-one.
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x, x ** k == n


# ─────────────────────────────────────────────────────────────────────────────
# PA#1 — OWF + PRG
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa1/owf_dlp")
async def api_pa1_owf_dlp(req: Request):
    data = await safe_json(req)
    x = int(data.get("x", 1)) % _OWF_DLP.q
    y = _OWF_DLP.evaluate(x)
    return {
        "x": x, "y": _to_hex(y),
        "p": _to_hex(_OWF_DLP.p), "q": _to_hex(_OWF_DLP.q), "g": _OWF_DLP.g,
    }


@app.post("/api/pa1/owf_aes")
async def api_pa1_owf_aes(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    fk = _OWF_AES.evaluate(k)
    return {"k": _to_hex(k), "fk": _to_hex(fk)}


@app.post("/api/pa1/prg")
async def api_pa1_prg(req: Request):
    data = await safe_json(req)
    seed = int(data.get("seed", 42)) % _OWF_DLP.q
    nbits = int(data.get("bits", 128))
    out = _PRG.generate(seed, nbits)
    
    # Optional randomness test (runs chi-square roughly)
    ones = bin(int.from_bytes(out, 'big')).count('1')
    total_bits = len(out) * 8
    ratio = ones / max(1, total_bits)
    
    return {"seed": seed, "bits": nbits, "out": _to_hex(out), "ratio": ratio}


# ─────────────────────────────────────────────────────────────────────────────
# PA#2 — PRF (GGM)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa2/ggm")
async def api_pa2_ggm(req: Request):
    data = await safe_json(req)
    key = _hex_to_bytes(data.get("key", ""), 8)
    bits_str = (data.get("bits", "1011") or "").strip()
    bits = ''.join(c for c in bits_str if c in "01") or "1011"
    n = len(bits)
    x = int(bits, 2) if bits else 0
    path = _GGM.get_path(key, x, n_bits=n)
    out = _GGM.evaluate(key, x, n_bits=n)
    return {
        "key": _to_hex(key), "bits": bits, "n": n,
        "out": _to_hex(out),
        "path": path,
    }


@app.post("/api/pa2/aes_prf")
async def api_pa2_aes_prf(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    x = _hex_to_bytes(data.get("x", ""), 16)
    return {"k": _to_hex(k), "x": _to_hex(x), "y": _to_hex(_AES_PRF.evaluate(k, x))}


# ─────────────────────────────────────────────────────────────────────────────
# PA#3 — CPA-Enc
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa3/encrypt")
async def api_pa3_enc(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    r, ct = _CPA.encrypt(k, m)
    return {"k": _to_hex(k), "r": _to_hex(r), "ct": _to_hex(ct)}


@app.post("/api/pa3/game")
async def api_pa3_game(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    m0 = (data.get("m0", "msg0") or "").encode()
    m1 = (data.get("m1", "msg1") or "").encode()
    reuse_nonce = data.get("reuse_nonce", False)
    
    # Encrypt one randomly
    b = secrets.randbits(1)
    mb = m1 if b else m0
    
    # If reuse nonce, fix the randomness r
    if reuse_nonce:
        fixed_r = b"\x00" * 16 # Not secure, forces same r
        # CPA-Enc uses GGM internally. Let's do it manually for the game to show failure
        pad = _GGM.evaluate(k, int.from_bytes(fixed_r, 'big'), n_bits=len(mb)*8)
        mb_int = int.from_bytes(mb, 'big')
        pad_int = int.from_bytes(pad[:len(mb)], 'big')
        ct_int = mb_int ^ pad_int
        ct = ct_int.to_bytes(len(mb), 'big')
        r = fixed_r
    else:
        r, ct = _CPA.encrypt(k, mb)
        
    return {"r": _to_hex(r), "ct": _to_hex(ct), "b": b}

# ─────────────────────────────────────────────────────────────────────────────
# PA#4 — Modes of Operation
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa4/modes")
async def api_pa4_modes(req: Request):
    data = await safe_json(req)
    mode = data.get("mode", "CBC")
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    iv_str = data.get("iv", None)
    
    iv = _hex_to_bytes(iv_str, 16) if iv_str else None
    
    try:
        if not iv:
            iv = os.urandom(16)
            
        if mode == "CBC":
            ct = _MODES.cbc.encrypt(k, iv, m)
            return {"mode": "CBC", "iv": _to_hex(iv), "ct": _to_hex(ct)}
        elif mode == "OFB":
            ct = _MODES.ofb.encrypt(k, iv, m)
            return {"mode": "OFB", "iv": _to_hex(iv), "ct": _to_hex(ct)}
        elif mode == "CTR":
            r, ct = _MODES.ctr.encrypt(k, m)
            return {"mode": "CTR", "iv": _to_hex(r), "ct": _to_hex(ct)}
        else:
            return JSONResponse(status_code=400, content={"error": "Invalid mode"})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/pa4/decrypt")
async def api_pa4_decrypt(req: Request):
    data = await safe_json(req)
    mode = data.get("mode", "CBC")
    k = _hex_to_bytes(data.get("k", ""), 16)
    ct = bytes.fromhex(data.get("ct", ""))
    iv = bytes.fromhex(data.get("iv", ""))
    
    try:
        if mode == "CBC":
            pt = _MODES.cbc.decrypt(k, iv, ct)
        elif mode == "OFB":
            pt = _MODES.ofb.decrypt(k, iv, ct)
        elif mode == "CTR":
            pt = _MODES.ctr.decrypt(k, iv, ct)
        else:
            return JSONResponse(status_code=400, content={"error": "Invalid mode"})
        return {"mode": mode, "pt": pt.decode("latin1", errors="replace")}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# PA#5 — MAC
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa5/prf_mac")
async def api_pa5_prf_mac(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "")[:16].ljust(16, "\x00").encode()
    return {"k": _to_hex(k), "m": _to_hex(m), "tag": _to_hex(_PRFMAC.mac(k, m))}


@app.post("/api/pa5/cbc_mac")
async def api_pa5_cbc_mac(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    return {"k": _to_hex(k), "m": m.decode("latin1"), "tag": _to_hex(_CBCMAC.mac(k, m))}


# ─────────────────────────────────────────────────────────────────────────────
# PA#6 — CCA-Enc (Encrypt-then-MAC)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa6/encrypt")
async def api_pa6_enc(req: Request):
    data = await safe_json(req)
    ke = _hex_to_bytes(data.get("ke", ""), 16)
    km = _hex_to_bytes(data.get("km", ""), 16)
    m = (data.get("m", "") or "").encode()
    blob, t = _CCA.encrypt(ke, km, m)
    return {"blob": _to_hex(blob), "tag": _to_hex(t)}


@app.post("/api/pa6/decrypt")
async def api_pa6_dec(req: Request):
    data = await safe_json(req)
    ke = _hex_to_bytes(data.get("ke", ""), 16)
    km = _hex_to_bytes(data.get("km", ""), 16)
    blob = bytes.fromhex(data.get("blob", ""))
    tag = bytes.fromhex(data.get("tag", ""))
    pt = _CCA.decrypt(ke, km, blob, tag)
    return {"pt": pt.decode("latin1") if pt else None, "rejected": pt is None}


# ─────────────────────────────────────────────────────────────────────────────
# PA#7 — Merkle-Damgård
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa7/hash")
async def api_pa7_hash(req: Request):
    data = await safe_json(req)
    m = (data.get("m", "") or "").encode()
    out = _MD.hash_with_trace(m)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# PA#8 — DLP Hash
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa8/hash")
async def api_pa8_hash(req: Request):
    data = await safe_json(req)
    m = (data.get("m", "") or "").encode()
    return {"hash": _to_hex(_DLPH.hash(m)), "msg": m.decode("latin1")}

@app.post("/api/pa8/hunt")
async def api_pa8_hunt(req: Request):
    data = await safe_json(req)
    n_bits = int(data.get("bits", 16))
    
    # We use a smaller truncation to hunt collisions easily without blocking server
    truncate_to = min(n_bits, 16)
    
    # Basic birthday attack search
    seen = {}
    iters = 0
    while iters < 10000:
        m = os.urandom(8)
        h = _DLPH.hash_truncated(m, truncate_to)
        h_hex = _to_hex(h)
        if h_hex in seen:
            return {"collision": True, "m1": _to_hex(seen[h_hex]), "m2": _to_hex(m), "hash": h_hex, "iters": iters}
        seen[h_hex] = m
        iters += 1
        
    return {"collision": False, "iters": iters}

# ─────────────────────────────────────────────────────────────────────────────
# PA#9 — Birthday Attack
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa9/birthday")
async def api_pa9_birthday(req: Request):
    data = await safe_json(req)
    n_bits = int(data.get("n_bits", 16))
    atk = BirthdayAttack(lambda m: _DLPH.hash_truncated(m, n_bits), n_bits=n_bits)
    return atk.naive_attack()


# ─────────────────────────────────────────────────────────────────────────────
# PA#10 — HMAC + EtH
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa10/hmac")
async def api_pa10_hmac(req: Request):
    data = await safe_json(req)
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    return {"key": _to_hex(k), "msg": m.decode("latin1"), "tag": _to_hex(_HMAC.mac(k, m))}


# ─────────────────────────────────────────────────────────────────────────────
# PA#11 — Diffie-Hellman
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa11/dh")
async def api_pa11_dh(req: Request):
    data = await safe_json(req)
    mitm = data.get("mitm", False)
    dh = _ensure_dh()
    a, A = dh.alice_step1()
    b, B = dh.bob_step1()
    
    if mitm:
        # Eve creates her own keys to MitM
        e_a, E_A = dh.alice_step1()
        e_b, E_B = dh.bob_step1()
        Ka = dh.alice_step2(a, E_B) # Alice thinks E_B is Bob's
        Kb = dh.bob_step2(b, E_A) # Bob thinks E_A is Alice's
        return {
            "p": _to_hex(dh.p), "g": dh.g,
            "A": _to_hex(A), "B": _to_hex(B),
            "E_A": _to_hex(E_A), "E_B": _to_hex(E_B),
            "Ka": _to_hex(Ka), "Kb": _to_hex(Kb),
            "match": False,
            "mitm": True
        }
    else:
        Ka = dh.alice_step2(a, B)
        Kb = dh.bob_step2(b, A)
        return {
            "p": _to_hex(dh.p), "g": dh.g,
            "A": _to_hex(A), "B": _to_hex(B),
            "Ka": _to_hex(Ka), "Kb": _to_hex(Kb),
            "match": Ka == Kb,
            "mitm": False
        }


# ─────────────────────────────────────────────────────────────────────────────
# PA#12 — RSA / PKCS#1 v1.5
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa12/rsa_textbook")
async def api_pa12_rsa(req: Request):
    rsa, _ = _ensure_rsa()
    data = await safe_json(req)
    m = int(data.get("m", 42)) % rsa.N
    c = rsa.encrypt(m)
    dec = rsa.decrypt(c)
    return {
        "N": _to_hex(rsa.N), "e": rsa.e,
        "m": m, "c": _to_hex(c), "dec": dec, "match": dec == m,
    }


@app.post("/api/pa12/pkcs15")
async def api_pa12_pkcs15(req: Request):
    _, pkcs = _ensure_rsa()
    data = await safe_json(req)
    msg = (data.get("m", "hi") or "")[:pkcs.k - 11].encode()
    c = pkcs.encrypt(msg)
    dec = pkcs.decrypt(c)
    return {
        "msg": msg.decode("latin1"),
        "c": _to_hex(c),
        "dec": dec.decode("latin1") if dec else None,
        "match": dec == msg,
    }

@app.post("/api/pa12/encrypt_twice")
async def api_pa12_encrypt_twice(req: Request):
    rsa, pkcs = _ensure_rsa()
    data = await safe_json(req)
    msg_str = data.get("m", "yes")
    mode = data.get("mode", "textbook")
    
    if mode == "textbook":
        # Convert string to int
        m = int.from_bytes(msg_str.encode('utf-8'), 'big')
        c1 = rsa.encrypt(m)
        c2 = rsa.encrypt(m)
        return {
            "mode": mode,
            "m": msg_str,
            "c1": _to_hex(c1),
            "c2": _to_hex(c2),
            "match": c1 == c2
        }
    else:
        # PKCS#1 v1.5
        msg_bytes = msg_str.encode('utf-8')
        c1 = pkcs.encrypt(msg_bytes)
        c2 = pkcs.encrypt(msg_bytes)
        
        m1_padded = rsa.decrypt_crt(c1)
        em1 = pkcs._i2osp(m1_padded, pkcs.k)
        sep1 = em1.find(b'\x00', 2)
        ps1 = em1[2:sep1]
        
        m2_padded = rsa.decrypt_crt(c2)
        em2 = pkcs._i2osp(m2_padded, pkcs.k)
        sep2 = em2.find(b'\x00', 2)
        ps2 = em2[2:sep2]
        
        return {
            "mode": mode,
            "m": msg_str,
            "c1": _to_hex(c1),
            "c2": _to_hex(c2),
            "ps1": _to_hex(ps1),
            "ps2": _to_hex(ps2),
            "match": c1 == c2
        }

# ─────────────────────────────────────────────────────────────────────────────
# PA#13 — Miller-Rabin
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa13/miller_rabin")
async def api_pa13_miller_rabin(req: Request):
    data = await safe_json(req)
    n_str = data.get("n", "")
    k = int(data.get("k", 40))
    try:
        n = int(n_str)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid integer format."})

    raw_trace: list = []
    t0 = time.time()
    from pa13.primality import miller_rabin
    res = miller_rabin(n, k, trace=raw_trace)
    elapsed = time.time() - t0

    # The PA module records each round as {a, x, result}. Reshape into the
    # structured events the demo renders ('factor' once, then per-round entries,
    # then a final verdict) without touching the PA logic itself.
    enriched: list = []
    if n < 2:
        enriched.append({"event": "composite", "reason": f"n={n} < 2 — not prime by definition"})
    elif n in (2, 3):
        enriched.append({"event": "prime"})
    elif n % 2 == 0:
        enriched.append({"event": "composite", "reason": f"n={n} is even (divisible by 2)"})
    else:
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
        enriched.append({"event": "factor", "r": s, "d": str(d)})

    for i, item in enumerate(raw_trace, start=1):
        a = item.get("a")
        x = item.get("x")
        rr = item.get("result")
        enriched.append({
            "event": "round",
            "round": i,
            "a": str(a),
            "x": str(x),
            "result": rr,
        })
        if rr == "composite":
            enriched.append({
                "event": "composite",
                "reason": f"witness a={a} produced x={x} ≠ n−1 through all squarings",
            })
            break

    if res and not any(e.get("event") == "prime" for e in enriched):
        enriched.append({"event": "prime"})

    return {
        "n": n_str,
        "k": k,
        "is_prime": res,
        "time_ms": round(elapsed * 1000, 2),
        "trace": enriched,
    }


# ─────────────────────────────────────────────────────────────────────────────
# PA#14 — CRT + Håstad
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa14/hastad")
async def api_pa14_hastad(req: Request):
    data = await safe_json(req)
    m_str = data.get("m", "A")
    use_padding = bool(data.get("use_padding", False))
    e = 3
    
    # Use 256-bit so PKCS#1 v1.5 padding fits. It is instant computation.
    rsas = [RSA(bits=256) for _ in range(3)]
    mods = [r.N for r in rsas]
    
    if use_padding:
        pkcs_list = [RSA_PKCS15(r) for r in rsas]
        msg_bytes = m_str.encode()
        # Ensure we use e=3 for encrypting the padded bytes manually to simulate Håstad
        cts = []
        for r, p in zip(rsas, pkcs_list):
            k = p.k
            ps_len = k - len(msg_bytes) - 3
            ps_bytes = bytearray()
            while len(ps_bytes) < ps_len:
                b = os.urandom(1)
                if b != b'\x00': ps_bytes += b
            em = b'\x00\x02' + bytes(ps_bytes) + b'\x00' + msg_bytes
            m_int = int.from_bytes(em, 'big')
            cts.append(pow(m_int, e, r.N))
    else:
        m = int.from_bytes(m_str.encode(), 'big')
        cts = [pow(m, e, r.N) for r in rsas]
        
    from pa14_15_16.crt_sig_elgamal import crt
    x = crt(cts, mods)
    recovered_int, exact = _exact_iroot(x, e)
    if exact:
        try:
            recovered_str = recovered_int.to_bytes(
                (recovered_int.bit_length() + 7) // 8, 'big'
            ).decode('utf-8')
        except Exception:
            recovered_str = "GARBAGE (decoded bytes are not UTF-8)"
    else:
        # Cube root is non-integral — exactly the failure mode the PKCS path
        # is supposed to exhibit. Surface the floor root for the panel anyway.
        recovered_str = "GARBAGE (cube root is not an integer)"

    return {
        "m": m_str,
        "recovered": recovered_str,
        "match": recovered_str == m_str,
        "x_hex": _to_hex(x),
        "moduli": [_to_hex(N) for N in mods],
        "ciphertexts": [_to_hex(c) for c in cts],
    }


# ─────────────────────────────────────────────────────────────────────────────
# PA#15 — Digital Signatures
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa15/sign")
async def api_pa15_sign(req: Request):
    rsa, _ = _ensure_rsa()
    from pa14_15_16.crt_sig_elgamal import Sign
    data = await safe_json(req)
    m_str = data.get("m", "")
    raw = data.get("raw", False)
    
    m_bytes = m_str.encode('utf-8')
    if raw:
        # Raw RSA sign: sig = m^d mod N.
        # Ensure m < N. We'll use int.from_bytes
        m_int = int.from_bytes(m_bytes, 'big')
        sig = rsa.decrypt(m_int)
    else:
        sig = Sign(rsa.sk, m_bytes)
        
    return {
        "m": m_str,
        "sig": _to_hex(sig),
        "raw": raw
    }

@app.post("/api/pa15/verify")
async def api_pa15_verify(req: Request):
    rsa, _ = _ensure_rsa()
    from pa14_15_16.crt_sig_elgamal import Verify
    data = await safe_json(req)
    m_str = data.get("m", "")
    sig_hex = data.get("sig", "0")
    raw = data.get("raw", False)
    
    try:
        sig = int(sig_hex, 16)
    except ValueError:
        return {"valid": False, "error": "Invalid signature format"}
        
    m_bytes = m_str.encode('utf-8')
    recovered_hash = pow(sig, rsa.e, rsa.N)
    
    if raw:
        m_int = int.from_bytes(m_bytes, 'big')
        valid = recovered_hash == m_int
        expected = m_int
    else:
        from pa8_9_10.hash_hmac import DLP_Hash_Wide
        hasher = DLP_Hash_Wide()
        h = hasher.hash(m_bytes)
        h_int = int.from_bytes(h, 'big')
        valid = Verify(rsa.pk, m_bytes, sig)
        expected = h_int
        
    return {
        "valid": valid,
        "recovered": _to_hex(recovered_hash),
        "expected": _to_hex(expected),
        "raw": raw
    }


# ─────────────────────────────────────────────────────────────────────────────
# PA#16 — ElGamal
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa16/encrypt")
async def api_pa16_encrypt(req: Request):
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    sk, pk = keys["sk"], keys["pk"]
    data = await safe_json(req)
    m = int(data.get("m", 1234)) % eg.q
    c1, c2 = eg.encrypt(pk, m)
    return {"m": m, "c1": _to_hex(c1), "c2": _to_hex(c2)}

@app.post("/api/pa16/malleate")
async def api_pa16_malleate(req: Request):
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    p = keys["pk"][0]
    data = await safe_json(req)
    c1 = int(data.get("c1", "0"), 16)
    c2 = int(data.get("c2", "0"), 16)
    k = int(data.get("k", 1))
    c2_m = (c2 * k) % p
    return {"c1": _to_hex(c1), "c2": _to_hex(c2_m)}

@app.post("/api/pa16/decrypt")
async def api_pa16_decrypt(req: Request):
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    sk = keys["sk"]
    data = await safe_json(req)
    c1 = int(data.get("c1", "0"), 16)
    c2 = int(data.get("c2", "0"), 16)
    dec = eg.decrypt(sk, c1, c2)
    return {"m": dec}


# ─────────────────────────────────────────────────────────────────────────────
# PA#17 — CCA-PKC (Signcrypt)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa17/encrypt")
async def api_pa17_enc(req: Request):
    eg = _ensure_elg()
    signer_sk, _ = _ensure_rsa_sign_keys()
    keys = _ensure_eg_keys()
    pk_enc = keys['pk']
    data = await safe_json(req)
    m = int(data.get("m", 1234)) % eg.q
    
    # 1. Plain ElGamal
    plain_c1, plain_c2 = eg.encrypt(pk_enc, m)
    
    # 2. Signcrypt
    c1, c2, sig = CCA_PKC.CCA_PKC_Enc(eg, pk_enc, signer_sk, m)
    
    return {
        "m": m, 
        "plain_c1": _to_hex(plain_c1), "plain_c2": _to_hex(plain_c2),
        "c1": _to_hex(c1), "c2": _to_hex(c2), "sig": _to_hex(sig)
    }

@app.post("/api/pa17/decrypt_elgamal")
async def api_pa17_dec_elgamal(req: Request):
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    sk_enc = keys['sk']
    data = await safe_json(req)
    c1 = int(data.get("c1", "0"), 16)
    c2 = int(data.get("c2", "0"), 16)
    
    dec = eg.decrypt(sk_enc, c1, c2)
    return {"dec": dec}

@app.post("/api/pa17/decrypt_signcrypt")
async def api_pa17_dec_signcrypt(req: Request):
    eg = _ensure_elg()
    rsa, _ = _ensure_rsa()
    keys = _ensure_eg_keys()
    sk_enc, pk_enc = keys['sk'], keys['pk']
    data = await safe_json(req)
    c1 = int(data.get("c1", "0"), 16)
    c2 = int(data.get("c2", "0"), 16)
    sig = int(data.get("sig", "0"), 16)
    
    dec = CCA_PKC.CCA_PKC_Dec(eg, sk_enc, rsa.pk, c1, c2, sig)
    return {"dec": dec if dec is not None else "Invalid Signature"}


# ─────────────────────────────────────────────────────────────────────────────
# PA#18 — Oblivious Transfer
# ─────────────────────────────────────────────────────────────────────────────
_PA18_STATE = {}

@app.post("/api/pa18/demo_setup")
async def api_pa18_demo_setup(req: Request):
    data = await safe_json(req)
    m0 = int(data.get("m0", 100))
    m1 = int(data.get("m1", 200))
    _PA18_STATE['m0'] = m0
    _PA18_STATE['m1'] = m1
    return {"m0": m0, "m1": m1}

@app.post("/api/pa18/demo_step1")
async def api_pa18_demo_step1(req: Request):
    data = await safe_json(req)
    b = int(data.get("b", 0)) & 1
    _PA18_STATE['b'] = b
    pk0, pk1, st = _OT.receiver_step1(b)
    _PA18_STATE['receiver_state'] = st
    _PA18_STATE['pk0'] = pk0
    _PA18_STATE['pk1'] = pk1
    return {
        "pk0_h": _to_hex(pk0[3]),
        "pk1_h": _to_hex(pk1[3])
    }

@app.post("/api/pa18/demo_step2")
async def api_pa18_demo_step2(req: Request):
    pk0 = _PA18_STATE.get('pk0')
    pk1 = _PA18_STATE.get('pk1')
    m0 = _PA18_STATE.get('m0')
    m1 = _PA18_STATE.get('m1')
    if not pk0 or not m0:
        return JSONResponse(status_code=400, content={"error": "run setup and step1 first"})
    c0, c1 = _OT.sender_step(pk0, pk1, m0, m1)
    _PA18_STATE['c0'] = c0
    _PA18_STATE['c1'] = c1
    return {
        "c0_c1": _to_hex(c0[0]), "c0_c2": _to_hex(c0[1]),
        "c1_c1": _to_hex(c1[0]), "c1_c2": _to_hex(c1[1])
    }

@app.post("/api/pa18/demo_step3")
async def api_pa18_demo_step3(req: Request):
    st = _PA18_STATE.get('receiver_state')
    c0 = _PA18_STATE.get('c0')
    c1 = _PA18_STATE.get('c1')
    if not st or not c0:
        return JSONResponse(status_code=400, content={"error": "run step2 first"})
    got = _OT.receiver_step2(st, c0, c1)
    b = _PA18_STATE['b']
    m_expected = _PA18_STATE['m0'] if b == 0 else _PA18_STATE['m1']
    return {"got": got, "correct": got == m_expected}

@app.post("/api/pa18/demo_cheat")
async def api_pa18_demo_cheat(req: Request):
    st = _PA18_STATE.get('receiver_state')
    c0 = _PA18_STATE.get('c0')
    c1 = _PA18_STATE.get('c1')
    b = _PA18_STATE.get('b')
    m_other = _PA18_STATE.get('m1') if b == 0 else _PA18_STATE.get('m0')
    if not st or not c0:
        return JSONResponse(status_code=400, content={"error": "run step2 first"})
    res = _OT.dlp_break_other_message(st, c0, c1, m_other, max_iters=100000)
    return res


# ─────────────────────────────────────────────────────────────────────────────
# PA#19 — Secure AND/XOR
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa19/and")
async def api_pa19_and(req: Request):
    data = await safe_json(req)
    a = int(data.get("a", 1)) & 1
    b = int(data.get("b", 1)) & 1
    return {"a": a, "b": b, "and": _GATES.AND(a, b), "xor": _GATES.XOR(a, b)}

@app.post("/api/pa19/demo_and")
async def api_pa19_demo_and(req: Request):
    data = await safe_json(req)
    a = int(data.get("a", 1)) & 1
    b = int(data.get("b", 1)) & 1
    
    _GATES.reset_metrics()
    res = _GATES.AND(a, b)
    
    # We want to format the transcript properly since it contains large ints/tuples
    formatted_transcript = []
    for op, payload in _GATES.transcript:
        fmt_payload = {}
        for k, v in payload.items():
            if isinstance(v, int):
                fmt_payload[k] = _to_hex(v) if v > 10 else v
            elif isinstance(v, tuple):
                fmt_payload[k] = "(" + ", ".join(
                    _to_hex(x) if isinstance(x, int) and x > 10 else str(x) for x in v
                ) + ")"
            else:
                fmt_payload[k] = str(v)
        formatted_transcript.append({"op": op, "payload": fmt_payload})
        
    return {
        "a": a, "b": b, "res": res, 
        "transcript": formatted_transcript
    }


# ─────────────────────────────────────────────────────────────────────────────
# PA#20 — 2-Party MPC (Millionaire's Problem)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa20/millionaires")
async def api_pa20_millionaires(req: Request):
    data = await safe_json(req)
    x = int(data.get("x", 7)) & 0xF
    y = int(data.get("y", 12)) & 0xF
    res = _CIRCUIT.millionaires(x, y)
    return {
        "x": x, 
        "y": y, 
        "result": res,
        "trace": _CIRCUIT.last_metrics.get('trace', [])
    }


# ─────────────────────────────────────────────────────────────────────────────
# Health / Index
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def api_health():
    return {"ok": True, "endpoints": sorted([
        r.path for r in app.routes if r.path.startswith("/api/")
    ])}


# ─────────────────────────────────────────────────────────────────────────────
# Static File Mounting
# ─────────────────────────────────────────────────────────────────────────────
app.mount("/demos", StaticFiles(directory=os.path.join(ROOT, "pa0_web"), html=True), name="demos")
app.mount("/", StaticFiles(directory=os.path.join(ROOT, "pa0_react", "dist"), html=True), name="spa")

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("PA#0 backend serving real Python implementations on http://localhost:5050 via FastAPI")
    uvicorn.run("backend:app", host="127.0.0.1", port=5050, reload=True)
