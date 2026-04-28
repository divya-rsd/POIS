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
import binascii
import traceback
from typing import Any, Dict

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from flask import Flask, request, jsonify, send_from_directory

# Real implementations — lazy imports keep startup fast
from pa1.owf_prg import (
    AES128, OWF_DLP, OWF_AES, PRG_from_OWF, mod_exp,
)
from pa2.prf_ggm import GGM_PRF, AES_PRF, LengthDoublingPRG
from pa3.cpa_enc import CPA_Enc
from pa5.mac import PRF_MAC, CBC_MAC
from pa6.cca_enc import CCA_Enc
from pa7.merkle_damgard import MerkleDamgard, md_pad
from pa8_9_10.hash_hmac import DLP_Hash, HMAC, EtH_Enc, BirthdayAttack
from pa11.dh import DH
from pa12.rsa import RSA, RSA_PKCS15
from pa13.primality import is_prime, gen_prime, miller_rabin
from pa14_15_16.crt_sig_elgamal import (
    crt as crt_solver, hastad_attack, RSA_Sign, ElGamal,
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

def _ensure_rsa_sign():
    global _CCA_PKC
    if _CCA_PKC is None:
        rsa, _ = _ensure_rsa()
        _CCA_PKC = RSA_Sign(rsa)
    return _CCA_PKC

_EG_KEYS = None
def _ensure_eg_keys():
    global _EG_KEYS
    eg = _ensure_elg()
    if _EG_KEYS is None:
        _EG_KEYS = eg.keygen()
    return _EG_KEYS


# ─────────────────────────────────────────────────────────────────────────────
# Flask app
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=os.path.join(ROOT, "pa0_web"), static_url_path="")


@app.errorhandler(Exception)
def _on_err(e):
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/")
def _root():
    return send_from_directory(app.static_folder, "index.html")


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


# ─────────────────────────────────────────────────────────────────────────────
# PA#1 — OWF + PRG
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa1/owf_dlp")
def api_pa1_owf_dlp():
    data = request.get_json(silent=True) or {}
    x = int(data.get("x", 1)) % _OWF_DLP.q
    y = _OWF_DLP.evaluate(x)
    return jsonify({
        "x": x, "y": _to_hex(y),
        "p": _to_hex(_OWF_DLP.p), "q": _to_hex(_OWF_DLP.q), "g": _OWF_DLP.g,
    })


@app.post("/api/pa1/owf_aes")
def api_pa1_owf_aes():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    fk = _OWF_AES.evaluate(k)
    return jsonify({"k": _to_hex(k), "fk": _to_hex(fk)})


@app.post("/api/pa1/prg")
def api_pa1_prg():
    data = request.get_json(silent=True) or {}
    seed = int(data.get("seed", 42)) % _OWF_DLP.q
    nbits = int(data.get("bits", 128))
    out = _PRG.generate(seed, nbits)
    return jsonify({"seed": seed, "bits": nbits, "out": _to_hex(out)})


# ─────────────────────────────────────────────────────────────────────────────
# PA#2 — PRF (GGM)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa2/ggm")
def api_pa2_ggm():
    data = request.get_json(silent=True) or {}
    key = _hex_to_bytes(data.get("key", ""), 8)
    bits_str = (data.get("bits", "1011") or "").strip()
    bits = ''.join(c for c in bits_str if c in "01") or "1011"
    n = len(bits)
    x = int(bits, 2) if bits else 0
    path = _GGM.get_path(key, x, n_bits=n)
    out = _GGM.evaluate(key, x, n_bits=n)
    return jsonify({
        "key": _to_hex(key), "bits": bits, "n": n,
        "out": _to_hex(out),
        "path": path,
    })


@app.post("/api/pa2/aes_prf")
def api_pa2_aes_prf():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    x = _hex_to_bytes(data.get("x", ""), 16)
    return jsonify({"k": _to_hex(k), "x": _to_hex(x), "y": _to_hex(_AES_PRF.evaluate(k, x))})


# ─────────────────────────────────────────────────────────────────────────────
# PA#3 — CPA-Enc
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa3/encrypt")
def api_pa3_enc():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    r, ct = _CPA.encrypt(k, m)
    return jsonify({"k": _to_hex(k), "r": _to_hex(r), "ct": _to_hex(ct)})


# ─────────────────────────────────────────────────────────────────────────────
# PA#5 — MAC
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa5/prf_mac")
def api_pa5_prf_mac():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "")[:16].ljust(16, "\x00").encode()
    return jsonify({"k": _to_hex(k), "m": _to_hex(m), "tag": _to_hex(_PRFMAC.mac(k, m))})


@app.post("/api/pa5/cbc_mac")
def api_pa5_cbc_mac():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    return jsonify({"k": _to_hex(k), "m": m.decode("latin1"), "tag": _to_hex(_CBCMAC.mac(k, m))})


# ─────────────────────────────────────────────────────────────────────────────
# PA#6 — CCA-Enc (Encrypt-then-MAC)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa6/encrypt")
def api_pa6_enc():
    data = request.get_json(silent=True) or {}
    ke = _hex_to_bytes(data.get("ke", ""), 16)
    km = _hex_to_bytes(data.get("km", ""), 16)
    m = (data.get("m", "") or "").encode()
    blob, t = _CCA.encrypt(ke, km, m)
    return jsonify({"blob": _to_hex(blob), "tag": _to_hex(t)})


@app.post("/api/pa6/decrypt")
def api_pa6_dec():
    data = request.get_json(silent=True) or {}
    ke = _hex_to_bytes(data.get("ke", ""), 16)
    km = _hex_to_bytes(data.get("km", ""), 16)
    blob = bytes.fromhex(data.get("blob", ""))
    tag = bytes.fromhex(data.get("tag", ""))
    pt = _CCA.decrypt(ke, km, blob, tag)
    return jsonify({"pt": pt.decode("latin1") if pt else None, "rejected": pt is None})


# ─────────────────────────────────────────────────────────────────────────────
# PA#7 — Merkle-Damgård
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa7/hash")
def api_pa7_hash():
    data = request.get_json(silent=True) or {}
    m = (data.get("m", "") or "").encode()
    out = _MD.hash_with_trace(m)
    return jsonify(out)


# ─────────────────────────────────────────────────────────────────────────────
# PA#8 — DLP Hash
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa8/hash")
def api_pa8_hash():
    data = request.get_json(silent=True) or {}
    m = (data.get("m", "") or "").encode()
    return jsonify({"hash": _to_hex(_DLPH.hash(m)), "msg": m.decode("latin1")})


# ─────────────────────────────────────────────────────────────────────────────
# PA#9 — Birthday Attack
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa9/birthday")
def api_pa9_birthday():
    data = request.get_json(silent=True) or {}
    n_bits = int(data.get("n_bits", 16))
    atk = BirthdayAttack(lambda m: _DLPH.hash_truncated(m, n_bits), n_bits=n_bits)
    return jsonify(atk.naive_attack())


# ─────────────────────────────────────────────────────────────────────────────
# PA#10 — HMAC + EtH
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa10/hmac")
def api_pa10_hmac():
    data = request.get_json(silent=True) or {}
    k = _hex_to_bytes(data.get("k", ""), 16)
    m = (data.get("m", "") or "").encode()
    return jsonify({"key": _to_hex(k), "msg": m.decode("latin1"), "tag": _to_hex(_HMAC.mac(k, m))})


# ─────────────────────────────────────────────────────────────────────────────
# PA#11 — Diffie-Hellman
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa11/dh")
def api_pa11_dh():
    dh = _ensure_dh()
    a, A = dh.alice_step1()
    b, B = dh.bob_step1()
    Ka = dh.alice_step2(a, B)
    Kb = dh.bob_step2(b, A)
    return jsonify({
        "p": _to_hex(dh.p), "g": dh.g,
        "A": _to_hex(A), "B": _to_hex(B),
        "Ka": _to_hex(Ka), "Kb": _to_hex(Kb),
        "match": Ka == Kb,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#12 — RSA / PKCS#1 v1.5
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa12/rsa_textbook")
def api_pa12_rsa():
    rsa, _ = _ensure_rsa()
    data = request.get_json(silent=True) or {}
    m = int(data.get("m", 42)) % rsa.N
    c = rsa.encrypt(m)
    dec = rsa.decrypt(c)
    return jsonify({
        "N": _to_hex(rsa.N), "e": rsa.e,
        "m": m, "c": _to_hex(c), "dec": dec, "match": dec == m,
    })


@app.post("/api/pa12/pkcs15")
def api_pa12_pkcs15():
    _, pkcs = _ensure_rsa()
    data = request.get_json(silent=True) or {}
    msg = (data.get("m", "hi") or "")[:pkcs.k - 11].encode()
    c = pkcs.encrypt(msg)
    dec = pkcs.decrypt(c)
    return jsonify({
        "msg": msg.decode("latin1"),
        "c": _to_hex(c),
        "dec": dec.decode("latin1") if dec else None,
        "match": dec == msg,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#13 — Miller-Rabin
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa13/primality")
def api_pa13_primality():
    data = request.get_json(silent=True) or {}
    try:
        n = int(data.get("n", 7919))
    except ValueError:
        return jsonify({"error": "n must be an integer"}), 400
    rounds = int(data.get("rounds", 40))
    return jsonify({"n": n, "is_prime": miller_rabin(n, rounds), "rounds": rounds})


# ─────────────────────────────────────────────────────────────────────────────
# PA#14 — CRT + Håstad
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa14/hastad")
def api_pa14_hastad():
    data = request.get_json(silent=True) or {}
    m = int(data.get("m", 42))
    e = 3
    rsas = [RSA(bits=256) for _ in range(3)]
    cts = [pow(m, e, r.N) for r in rsas]
    mods = [r.N for r in rsas]
    recovered = hastad_attack(cts, mods, e=e)
    return jsonify({
        "m": m, "recovered": recovered, "match": recovered == m,
        "moduli": [_to_hex(N) for N in mods],
        "ciphertexts": [_to_hex(c) for c in cts],
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#15 — Digital Signatures
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa15/sign")
def api_pa15_sign():
    rsa, _ = _ensure_rsa()
    signer = RSA_Sign(rsa)
    data = request.get_json(silent=True) or {}
    m = (data.get("m", "") or "").encode()
    sig = signer.sign(m)
    return jsonify({
        "msg": m.decode("latin1"),
        "sig": _to_hex(sig),
        "verify": signer.verify(m, sig),
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#16 — ElGamal
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa16/elgamal")
def api_pa16_elgamal():
    eg = _ensure_elg()
    keys = eg.keygen()
    sk, pk = keys["sk"], keys["pk"]
    data = request.get_json(silent=True) or {}
    m = int(data.get("m", 1234)) % pk[0]
    c1, c2 = eg.encrypt(pk, m)
    dec = eg.decrypt(sk, pk, c1, c2)
    return jsonify({
        "m": m, "c1": _to_hex(c1), "c2": _to_hex(c2),
        "dec": dec, "match": dec == m,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#17 — CCA-PKC (Signcrypt)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa17/encrypt")
def api_pa17_enc():
    eg = _ensure_elg()
    signer = _ensure_rsa_sign()
    keys = _ensure_eg_keys()
    pk_enc = keys['pk']
    data = request.get_json(silent=True) or {}
    m = int(data.get("m", 1234)) % pk_enc[0]
    
    # 1. Plain ElGamal
    plain_c1, plain_c2 = eg.encrypt(pk_enc, m)
    
    # 2. Signcrypt
    c1, c2, sig = CCA_PKC.CCA_PKC_Enc(eg, pk_enc, signer, m)
    
    return jsonify({
        "m": m, 
        "plain_c1": _to_hex(plain_c1), "plain_c2": _to_hex(plain_c2),
        "c1": _to_hex(c1), "c2": _to_hex(c2), "sig": _to_hex(sig)
    })

@app.post("/api/pa17/decrypt_elgamal")
def api_pa17_dec_elgamal():
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    sk_enc, pk_enc = keys['sk'], keys['pk']
    data = request.get_json(silent=True) or {}
    c1 = int(data.get("c1", ""), 16)
    c2 = int(data.get("c2", ""), 16)
    dec = eg.decrypt(sk_enc, pk_enc, c1, c2)
    return jsonify({"dec": dec})

@app.post("/api/pa17/decrypt_signcrypt")
def api_pa17_dec_signcrypt():
    eg = _ensure_elg()
    keys = _ensure_eg_keys()
    sk_enc, pk_enc = keys['sk'], keys['pk']
    verifier = _ensure_rsa_sign()
    data = request.get_json(silent=True) or {}
    c1 = int(data.get("c1", ""), 16)
    c2 = int(data.get("c2", ""), 16)
    sig = int(data.get("sig", ""), 16)
    dec = CCA_PKC.CCA_PKC_Dec(eg, sk_enc, pk_enc, verifier, c1, c2, sig)
    return jsonify({"dec": dec, "rejected": dec is None})


# ─────────────────────────────────────────────────────────────────────────────
# PA#18 — Oblivious Transfer
# ─────────────────────────────────────────────────────────────────────────────
_PA18_STATE = {}

@app.post("/api/pa18/demo_setup")
def api_pa18_demo_setup():
    data = request.get_json(silent=True) or {}
    m0 = int(data.get("m0", 100))
    m1 = int(data.get("m1", 200))
    _PA18_STATE['m0'] = m0
    _PA18_STATE['m1'] = m1
    return jsonify({"m0": m0, "m1": m1})

@app.post("/api/pa18/demo_step1")
def api_pa18_demo_step1():
    data = request.get_json(silent=True) or {}
    b = int(data.get("b", 0)) & 1
    _PA18_STATE['b'] = b
    pk0, pk1, st = _OT.receiver_step1(b)
    _PA18_STATE['receiver_state'] = st
    _PA18_STATE['pk0'] = pk0
    _PA18_STATE['pk1'] = pk1
    return jsonify({
        "pk0_h": _to_hex(pk0[3]),
        "pk1_h": _to_hex(pk1[3])
    })

@app.post("/api/pa18/demo_step2")
def api_pa18_demo_step2():
    pk0 = _PA18_STATE.get('pk0')
    pk1 = _PA18_STATE.get('pk1')
    m0 = _PA18_STATE.get('m0')
    m1 = _PA18_STATE.get('m1')
    if not pk0 or not m0:
        return jsonify({"error": "run setup and step1 first"}), 400
    c0, c1 = _OT.sender_step(pk0, pk1, m0, m1)
    _PA18_STATE['c0'] = c0
    _PA18_STATE['c1'] = c1
    return jsonify({
        "c0_c1": _to_hex(c0[0]), "c0_c2": _to_hex(c0[1]),
        "c1_c1": _to_hex(c1[0]), "c1_c2": _to_hex(c1[1])
    })

@app.post("/api/pa18/demo_step3")
def api_pa18_demo_step3():
    st = _PA18_STATE.get('receiver_state')
    c0 = _PA18_STATE.get('c0')
    c1 = _PA18_STATE.get('c1')
    if not st or not c0:
        return jsonify({"error": "run step2 first"}), 400
    got = _OT.receiver_step2(st, c0, c1)
    b = _PA18_STATE['b']
    m_expected = _PA18_STATE['m0'] if b == 0 else _PA18_STATE['m1']
    return jsonify({"got": got, "correct": got == m_expected})

@app.post("/api/pa18/demo_cheat")
def api_pa18_demo_cheat():
    st = _PA18_STATE.get('receiver_state')
    c0 = _PA18_STATE.get('c0')
    c1 = _PA18_STATE.get('c1')
    b = _PA18_STATE.get('b')
    m_other = _PA18_STATE.get('m1') if b == 0 else _PA18_STATE.get('m0')
    if not st or not c0:
        return jsonify({"error": "run step2 first"}), 400
    res = _OT.dlp_break_other_message(st, c0, c1, m_other, max_iters=100000)
    return jsonify(res)


# ─────────────────────────────────────────────────────────────────────────────
# PA#19 — Secure AND/XOR
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa19/and")
def api_pa19_and():
    data = request.get_json(silent=True) or {}
    a = int(data.get("a", 1)) & 1
    b = int(data.get("b", 1)) & 1
    return jsonify({"a": a, "b": b, "and": _GATES.AND(a, b), "xor": _GATES.XOR(a, b)})

@app.post("/api/pa19/demo_and")
def api_pa19_demo_and():
    data = request.get_json(silent=True) or {}
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
        
    return jsonify({
        "a": a, "b": b, "res": res, 
        "transcript": formatted_transcript
    })


# ─────────────────────────────────────────────────────────────────────────────
# PA#20 — 2-Party MPC (Millionaire's Problem)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/pa20/millionaires")
def api_pa20_millionaires():
    data = request.get_json(silent=True) or {}
    x = int(data.get("x", 7)) & 0xF
    y = int(data.get("y", 12)) & 0xF
    res = _CIRCUIT.millionaires(x, y)
    return jsonify({
        "x": x, 
        "y": y, 
        "result": res,
        "trace": _CIRCUIT.last_metrics.get('trace', [])
    })


# ─────────────────────────────────────────────────────────────────────────────
# Health / Index
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "endpoints": sorted([
        r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api/")
    ])})


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("PA#0 backend serving real Python implementations on http://localhost:5050")
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
