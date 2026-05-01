const API_BASE = 'http://127.0.0.1:5050';

const Backend = {
  async post(path, body) {
    const r = await fetch(`${API_BASE}/api/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    if (!r.ok) {
      const t = await r.text().catch(() => '');
      throw new Error(`API ${path} failed (${r.status}): ${t.slice(0, 200)}`);
    }
    return r.json();
  },

  // Part I: Symmetric Crypto
  pa1OwfDlp: (x) => Backend.post('pa1/owf_dlp', { x }),
  pa1OwfAes: (k) => Backend.post('pa1/owf_aes', { k }),
  pa1Prg: (seed, bits) => Backend.post('pa1/prg', { seed, bits }),
  pa2Ggm: (key, bits) => Backend.post('pa2/ggm', { key, bits }),
  pa2AesPrf: (k, x) => Backend.post('pa2/aes_prf', { k, x }),
  pa3Encrypt: (k, m) => Backend.post('pa3/encrypt', { k, m }),
  pa3Game: (k, m0, m1, reuse_nonce) => Backend.post('pa3/game', { k, m0, m1, reuse_nonce }),
  pa4Modes: (mode, k, m, iv) => Backend.post('pa4/modes', { mode, k, m, iv }),
  pa4Decrypt: (mode, k, ct, iv) => Backend.post('pa4/decrypt', { mode, k, ct, iv }),
  pa5PrfMac: (k, m) => Backend.post('pa5/prf_mac', { k, m }),
  pa5CbcMac: (k, m) => Backend.post('pa5/cbc_mac', { k, m }),
  pa6Encrypt: (ke, km, m) => Backend.post('pa6/encrypt', { ke, km, m }),
  pa6Decrypt: (ke, km, blob, tag) => Backend.post('pa6/decrypt', { ke, km, blob, tag }),

  // Part II: Hashing and Data Integrity
  pa7Hash: (m) => Backend.post('pa7/hash', { m }),
  pa8Hash: (m) => Backend.post('pa8/hash', { m }),
  pa8Hunt: (bits) => Backend.post('pa8/hunt', { bits }),
  pa9Birthday: (n_bits) => Backend.post('pa9/birthday', { n_bits }),
  pa10Hmac: (k, m) => Backend.post('pa10/hmac', { k, m }),
};

export default Backend;
