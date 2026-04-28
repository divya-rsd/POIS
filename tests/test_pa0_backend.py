"""
Test suite for PA #0 — Flask backend connecting the React-style explorer to
the real Python implementations. Spawns backend.py in a thread, then exercises
every documented endpoint.
"""
import json
import os
import subprocess
import sys
import time
import unittest
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PORT = 5051  # use a different port from the dev backend


def _post(path: str, body: dict):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/api/{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _get(path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=20) as r:
        return json.loads(r.read())


class BackendSmokeTest(unittest.TestCase):
    proc: subprocess.Popen | None = None

    @classmethod
    def setUpClass(cls):
        env = os.environ.copy()
        env["FLASK_RUN_FROM_CLI"] = "false"
        # Override port via a tiny shim
        cls.proc = subprocess.Popen(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {ROOT!r}); "
             "from backend import app; "
             f"app.run(host='127.0.0.1', port={PORT}, debug=False, use_reloader=False)"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        # Wait for /api/health to become reachable
        for _ in range(40):
            try:
                _get("/api/health")
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.5)
        else:
            raise RuntimeError("Backend did not come up within 20s")

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()

    def test_health(self):
        r = _get("/api/health")
        self.assertTrue(r["ok"])
        self.assertGreater(len(r["endpoints"]), 20)

    def test_pa1_owf_dlp(self):
        r = _post("pa1/owf_dlp", {"x": 42})
        self.assertEqual(r["x"], 42)
        self.assertIn("y", r)

    def test_pa1_prg(self):
        r = _post("pa1/prg", {"seed": 1, "bits": 64})
        self.assertEqual(len(bytes.fromhex(r["out"])), 8)

    def test_pa2_ggm(self):
        r = _post("pa2/ggm", {"key": "a3f2c1b4", "bits": "1011"})
        self.assertEqual(r["bits"], "1011")
        self.assertEqual(len(r["path"]), 5)

    def test_pa3_encrypt(self):
        r = _post("pa3/encrypt", {"k": "00" * 16, "m": "hi"})
        self.assertIn("ct", r)
        self.assertIn("r", r)

    def test_pa6_roundtrip(self):
        enc = _post("pa6/encrypt", {"ke": "00" * 16, "km": "11" * 16, "m": "hello world"})
        dec = _post("pa6/decrypt", {
            "ke": "00" * 16, "km": "11" * 16,
            "blob": enc["blob"], "tag": enc["tag"],
        })
        self.assertEqual(dec["pt"], "hello world")
        self.assertFalse(dec["rejected"])

    def test_pa6_tamper_rejected(self):
        enc = _post("pa6/encrypt", {"ke": "00" * 16, "km": "11" * 16, "m": "secret"})
        # Flip one bit of the blob
        bad = bytearray(bytes.fromhex(enc["blob"]))
        bad[0] ^= 0xFF
        dec = _post("pa6/decrypt", {
            "ke": "00" * 16, "km": "11" * 16,
            "blob": bad.hex(), "tag": enc["tag"],
        })
        self.assertTrue(dec["rejected"])

    def test_pa7_hash(self):
        r = _post("pa7/hash", {"m": "hello"})
        self.assertIn("digest", r)
        self.assertIn("trace", r)

    def test_pa8_hash(self):
        r = _post("pa8/hash", {"m": "hello"})
        self.assertIn("hash", r)

    def test_pa10_hmac(self):
        r1 = _post("pa10/hmac", {"k": "00" * 16, "m": "hello"})
        r2 = _post("pa10/hmac", {"k": "00" * 16, "m": "hello"})
        self.assertEqual(r1["tag"], r2["tag"])  # deterministic

    def test_pa13_primality(self):
        self.assertFalse(_post("pa13/primality", {"n": 561})["is_prime"])
        self.assertTrue(_post("pa13/primality", {"n": 7919})["is_prime"])

    def test_pa14_hastad(self):
        r = _post("pa14/hastad", {"m": 42})
        self.assertEqual(r["m"], 42)
        self.assertEqual(r["recovered"], 42)
        self.assertTrue(r["match"])

    def test_pa18_ot(self):
        r0 = _post("pa18/ot", {"b": 0, "m0": 100, "m1": 200})
        self.assertEqual(r0["got"], 100)
        r1 = _post("pa18/ot", {"b": 1, "m0": 100, "m1": 200})
        self.assertEqual(r1["got"], 200)

    def test_pa19_and(self):
        for a in (0, 1):
            for b in (0, 1):
                r = _post("pa19/and", {"a": a, "b": b})
                self.assertEqual(r["and"], a & b)
                self.assertEqual(r["xor"], a ^ b)

    def test_pa20_millionaires(self):
        r = _post("pa20/millionaires", {"x": 7, "y": 12})
        self.assertEqual(r["result"], "Bob richer")
        r = _post("pa20/millionaires", {"x": 15, "y": 3})
        self.assertEqual(r["result"], "Alice richer")
        r = _post("pa20/millionaires", {"x": 5, "y": 5})
        self.assertEqual(r["result"], "Equal")


if __name__ == "__main__":
    unittest.main(verbosity=2)
