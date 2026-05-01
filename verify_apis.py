import pytest
from fastapi.testclient import TestClient
from backend import app

client = TestClient(app)

endpoints = [
    ("/api/pa1/owf_dlp", {"x": 1}),
    ("/api/pa1/owf_aes", {"k": "00"*16}),
    ("/api/pa1/prg", {"seed": 42, "bits": 128}),
    ("/api/pa2/ggm", {"key": "00"*8, "bits": "1011"}),
    ("/api/pa2/aes_prf", {"k": "00"*16, "x": "00"*16}),
    ("/api/pa3/encrypt", {"k": "00"*16, "m": "hello"}),
    ("/api/pa3/game", {"k": "00"*16, "m0": "hello", "m1": "world", "reuse_nonce": False}),
    ("/api/pa4/modes", {"mode": "CBC", "k": "00"*16, "m": "hello"}),
    ("/api/pa4/decrypt", {"mode": "CBC", "k": "00"*16, "ct": "00"*16, "iv": "00"*16}),
    ("/api/pa5/prf_mac", {"k": "00"*16, "m": "hello"}),
    ("/api/pa5/cbc_mac", {"k": "00"*16, "m": "hello"}),
    ("/api/pa6/encrypt", {"ke": "00"*16, "km": "00"*16, "m": "hello"}),
    ("/api/pa6/decrypt", {"ke": "00"*16, "km": "00"*16, "blob": "00"*16, "tag": "00"*16}),
    ("/api/pa7/hash", {"m": "hello"}),
    ("/api/pa8/hash", {"m": "hello"}),
    ("/api/pa8/hunt", {"bits": 8}),
    ("/api/pa9/birthday", {"n_bits": 8}),
    ("/api/pa10/hmac", {"k": "00"*16, "m": "hello"}),
    ("/api/pa11/dh", {"mitm": False}),
    ("/api/pa12/rsa_textbook", {"m": 42}),
    ("/api/pa12/pkcs15", {"m": "hi"}),
    ("/api/pa12/encrypt_twice", {"m": "yes", "mode": "textbook"}),
    ("/api/pa13/miller_rabin", {"n": "561", "k": 40}),
    ("/api/pa14/hastad", {"m": "A", "use_padding": False}),
    ("/api/pa15/sign", {"m": "hello", "raw": False}),
    ("/api/pa15/verify", {"m": "hello", "sig": "0", "raw": False}),
    ("/api/pa16/encrypt", {"m": 42}),
    ("/api/pa16/malleate", {"c1": "0", "c2": "0", "k": 2}),
    ("/api/pa16/decrypt", {"c1": "0", "c2": "0"}),
    ("/api/pa17/encrypt", {"m": 42}),
    ("/api/pa17/decrypt_signcrypt", {"c1": "0", "c2": "0", "sig": "0"}),
    ("/api/pa18/demo_setup", {"m0": 100, "m1": 200}),
    ("/api/pa18/demo_step1", {"b": 0}),
    ("/api/pa18/demo_step2", {}),
    ("/api/pa19/and", {"a": 0, "b": 1}),
    ("/api/pa20/millionaires", {"x": 5, "y": 7}),
]

def test_all():
    failed = []
    for ep, payload in endpoints:
        try:
            # First hit setup if needed (PA18)
            if ep == "/api/pa18/demo_step2":
                client.post("/api/pa18/demo_setup", json={"m0": 100, "m1": 200})
                client.post("/api/pa18/demo_step1", json={"b": 0})
                
            res = client.post(ep, json=payload)
            if res.status_code != 200:
                print(f"FAILED {ep}: {res.status_code} - {res.text}")
                failed.append(ep)
            else:
                data = res.json()
                if isinstance(data, dict) and "error" in data:
                     print(f"ERROR RETURNED BY {ep}: {data['error']}")
                     failed.append(ep)
                else:
                     print(f"SUCCESS {ep}")
        except Exception as e:
            print(f"CRASH {ep}: {e}")
            failed.append(ep)
    
    if failed:
        print(f"\\nFailed endpoints: {len(failed)}/{len(endpoints)}")
    else:
        print("\\nAll endpoints succeeded!")

if __name__ == '__main__':
    test_all()
