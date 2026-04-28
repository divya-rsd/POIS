// ════════════════════════════════════════════════
// BACKEND BRIDGE
// Connects the explorer to the real Python PA implementations.
//
// Detection: tries /api/health on first call. On success, real-PA mode is on
// and the routes below override the local stubs. On failure (e.g. opening the
// HTML directly without backend.py running), the explorer falls back to the
// in-browser stubs in crypto.js (toy values, per the PA#0 spec).
// ════════════════════════════════════════════════

const API_BASE = (typeof window !== 'undefined' && window.__POIS_API_BASE__) || '';

const Backend = {
  available: null, // null = unknown, true/false = decided
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

  // Convenience wrappers — one per PA endpoint
  pa1OwfDlp: (x) => Backend.post('pa1/owf_dlp', { x }),
  pa1OwfAes: (k) => Backend.post('pa1/owf_aes', { k }),
  pa1Prg: (seed, bits) => Backend.post('pa1/prg', { seed, bits }),
  pa2Ggm: (key, bits) => Backend.post('pa2/ggm', { key, bits }),
  pa2AesPrf: (k, x) => Backend.post('pa2/aes_prf', { k, x }),
  pa3Encrypt: (k, m) => Backend.post('pa3/encrypt', { k, m }),
  pa5PrfMac: (k, m) => Backend.post('pa5/prf_mac', { k, m }),
  pa5CbcMac: (k, m) => Backend.post('pa5/cbc_mac', { k, m }),
  pa6Encrypt: (ke, km, m) => Backend.post('pa6/encrypt', { ke, km, m }),
  pa7Hash: (m) => Backend.post('pa7/hash', { m }),
  pa8Hash: (m) => Backend.post('pa8/hash', { m }),
  pa9Birthday: (n_bits) => Backend.post('pa9/birthday', { n_bits }),
  pa10Hmac: (k, m) => Backend.post('pa10/hmac', { k, m }),
  pa11Dh: () => Backend.post('pa11/dh', {}),
  pa12RsaTextbook: (m) => Backend.post('pa12/rsa_textbook', { m }),
  pa12Pkcs15: (m) => Backend.post('pa12/pkcs15', { m }),
  pa13Primality: (n) => Backend.post('pa13/primality', { n }),
  pa14Hastad: (m) => Backend.post('pa14/hastad', { m }),
  pa15Sign: (m) => Backend.post('pa15/sign', { m }),
  pa16Elgamal: (m) => Backend.post('pa16/elgamal', { m }),
  pa17Encrypt: (m) => Backend.post('pa17/encrypt', { m }),
  pa18Ot: (b, m0, m1) => Backend.post('pa18/ot', { b, m0, m1 }),
  pa19And: (a, b) => Backend.post('pa19/and', { a, b }),
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
