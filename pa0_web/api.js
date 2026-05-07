// ════════════════════════════════════════════════
// BACKEND BRIDGE
// Connects the explorer to the real Python PA implementations via FastAPI.
// ════════════════════════════════════════════════

const API_BASE = (typeof window !== 'undefined' && window.__POIS_API_BASE__) || 'http://127.0.0.1:5050';

const Backend = {
  available: null,
  endpoints: [],

  async ping() {
    if (this.available !== null) return this.available;
    try {
      const r = await fetch(`${API_BASE}/api/health`, { method: 'GET' });
      if (!r.ok) throw new Error(`status ${r.status}`);
      const j = await r.json();
      this.endpoints = j.endpoints || [];
      this.available = true;
    } catch (e) {
      console.info('PA#0: backend not reachable, using JS stubs.', e.message);
      this.available = false;
    }
    return this.available;
  },

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
  pa3Decrypt: (k, r, ct) => Backend.post('pa3/decrypt', { k, r, ct }),
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

  // Part III: Public-Key Cryptography
  pa11Dh: (mitm) => Backend.post('pa11/dh', { mitm }),
  pa12RsaTextbook: (m) => Backend.post('pa12/rsa_textbook', { m }),
  pa12Pkcs15: (m) => Backend.post('pa12/pkcs15', { m }),
  pa12EncryptTwice: (m, mode) => Backend.post('pa12/encrypt_twice', { m, mode }),
  pa13Primality: (n, k) => Backend.post('pa13/miller_rabin', { n, k }),
  pa14Hastad: (m, use_padding) => Backend.post('pa14/hastad', { m, use_padding }),
  pa15Sign: (m, raw) => Backend.post('pa15/sign', { m, raw }),
  pa15Verify: (m, sig, raw) => Backend.post('pa15/verify', { m, sig, raw }),
  pa16Encrypt: (m) => Backend.post('pa16/encrypt', { m }),
  pa16Malleate: (c1, c2, k) => Backend.post('pa16/malleate', { c1, c2, k }),
  pa16Decrypt: (c1, c2) => Backend.post('pa16/decrypt', { c1, c2 }),
  pa17Encrypt: (m) => Backend.post('pa17/encrypt', { m }),
  pa17DecryptElgamal: (c1, c2) => Backend.post('pa17/decrypt_elgamal', { c1, c2 }),
  pa17DecryptSigncrypt: (c1, c2, sig) => Backend.post('pa17/decrypt_signcrypt', { c1, c2, sig }),

  // Part IV: Secure Multi-Party Computation
  pa18DemoSetup: (m0, m1) => Backend.post('pa18/demo_setup', { m0, m1 }),
  pa18DemoStep1: (b) => Backend.post('pa18/demo_step1', { b }),
  pa18DemoStep2: () => Backend.post('pa18/demo_step2', {}),
  pa18DemoStep3: () => Backend.post('pa18/demo_step3', {}),
  pa18DemoCheat: () => Backend.post('pa18/demo_cheat', {}),
  pa19And: (a, b) => Backend.post('pa19/and', { a, b }),
  pa19DemoAnd: (a, b) => Backend.post('pa19/demo_and', { a, b }),
  pa20Millionaires: (x, y) => Backend.post('pa20/millionaires', { x, y }),
};

// Show a small banner so users know which mode is active.
async function _initBackendBanner() {
  await Backend.ping();
  const tag = document.createElement('div');
  tag.id = 'backend-status';
  tag.style.cssText =
    'position:fixed;bottom:8px;right:10px;font-family:var(--mono,monospace);' +
    'font-size:10px;padding:4px 8px;border-radius:4px;letter-spacing:.06em;' +
    'z-index:50;border:1px solid;backdrop-filter:blur(4px);';
  if (Backend.available) {
    tag.style.background = 'rgba(110,231,183,.08)';
    tag.style.color = '#6ee7b7';
    tag.style.borderColor = 'rgba(110,231,183,.25)';
    tag.textContent = `● real PA backend (${Backend.endpoints.length} endpoints)`;
  } else {
    tag.style.background = 'rgba(251,191,36,.06)';
    tag.style.color = '#fbbf24';
    tag.style.borderColor = 'rgba(251,191,36,.25)';
    tag.textContent = '○ JS stubs (start backend.py for real crypto)';
  }
  document.body.appendChild(tag);
}

if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', _initBackendBanner);
}
