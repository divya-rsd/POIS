// ════════════════════════════════════════════════
// TINY CRYPTO (toy, deterministic — per PA#0 spec)
// ════════════════════════════════════════════════
const H   = (x, s = 0) => { let h = s ^ 0x811c9dc5; for (let i = 0; i < x.length; i++) { h ^= x.charCodeAt ? x.charCodeAt(i) : x[i]; h = (h * 0x01000193) >>> 0; } return h; };
const mix = (a, b) => ((a ^ b) * 0xc2b2ae35 + 0x27d4eb2f) >>> 0;
const toHex = (n, len = 8) => n.toString(16).toUpperCase().padStart(len, '0');
const ks2n = (s) => { let n = 0; for (let i = 0; i < Math.min(s.length, 8); i++) n = ((n * 256) + s.charCodeAt(i)) >>> 0; return n; };

function pseudoBlock(key, x) {
  const k = ks2n(key); const xi = typeof x === 'string' ? ks2n(x) : x;
  let v = ((k ^ xi) * 0x9e3779b9 + 0x6c62272e) >>> 0;
  v = (v ^ (v >>> 16)) * 0x45d9f3b >>> 0; return v ^ (v >>> 16);
}

function ggmPath(key, bits) {
  const k = ks2n(key); let state = k;
  const path = [{ level: 0, bit: null, val: toHex(state) }];
  for (let i = 0; i < bits.length; i++) {
    const b = parseInt(bits[i]);
    state = pseudoBlock(toHex(state), b ? 'ff000000' : '00000000');
    path.push({ level: i + 1, bit: b, fn: `G${b}`, val: toHex(state) });
  }
  return path;
}

function feistelEnc(key, x) {
  let L = (ks2n(key) ^ (x >>> 16)) & 0xFFFF, R = x & 0xFFFF;
  const rounds = [];
  for (let r = 1; r <= 3; r++) {
    const f = pseudoBlock(key, toHex(R));
    const nL = R, nR = (L ^ f) & 0xFFFF;
    rounds.push({ r, L: toHex(L, 4), R: toHex(R, 4), f: toHex(f, 4), nL: toHex(nL, 4), nR: toHex(nR, 4) });
    L = nL; R = nR;
  }
  return { rounds, out: toHex((L << 16) | R) };
}

function hmacCalc(key, msg) {
  const k = ks2n(key), m = ks2n(msg);
  const inner = pseudoBlock(toHex(k ^ 0x36363636), toHex(m));
  const outer = pseudoBlock(toHex(k ^ 0x5c5c5c5c), toHex(inner));
  return { inner: toHex(inner), outer: toHex(outer) };
}

function dlpHash(msg) {
  const g = 7, p = 2147483647;
  let x = ks2n(msg) % 1000 + 2;
  return toHex(g ** Math.min(x % 20, 19) % (p - 1));
}

function randHex(n = 8) {
  let s = ''; for (let i = 0; i < n; i++) s += (Math.floor(Math.random() * 256)).toString(16).padStart(2, '0');
  return s.toUpperCase();
}

// ════════════════════════════════════════════════
// PA METADATA
// ════════════════════════════════════════════════
const PA_NUM = { OWF: 'PA#1', PRG: 'PA#1', PRF: 'PA#2', PRP: 'PA#4', MAC: 'PA#5', CRHF: 'PA#8', HMAC: 'PA#10', 'CPA-Enc': 'PA#3', 'CCA-Enc': 'PA#6' };

// PRIMS drives the clique map — must include all selectable primitives
const PRIMS = ['OWF', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC', 'CPA-Enc', 'CCA-Enc'];

// ════════════════════════════════════════════════
// FOUNDATION → PRIMITIVE CHAINS (Leg 1)
// ════════════════════════════════════════════════
const FOUND_CHAINS = {
  AES: {
    OWF:  [{ fn: 'AES Davies-Meyer', op: 'f(k) = AES_k(0¹²⁸) ⊕ k', thm: 'OWF from PRP compression', key_out: (k) => toHex(pseudoBlock(k, '00000000') ^ ks2n(k)) }],
    PRG:  [{ fn: 'AES-128 as PRF', op: 'F_k = AES_k(·)', thm: 'PRP/PRF switching lemma', key_out: (k) => toHex(pseudoBlock(k, 'aabbccdd')) },
           { fn: 'PRG = F_k(0) ∥ F_k(1)', op: 'G(s) = F_k(0) ∥ F_k(1)', thm: 'PRG from PRF', key_out: (k) => toHex(pseudoBlock(k, '00000000')) + toHex(pseudoBlock(k, 'ffffffff')) }],
    PRF:  [{ fn: 'AES-128 (direct PRP/PRF)', op: 'F_k(x) = AES_k(x)', thm: 'Concrete PRP used as PRF', key_out: (k) => toHex(pseudoBlock(k, 'feedface')) }],
    PRP:  [{ fn: 'AES-128 (foundation PRP)', op: 'PRP_k = AES_k(·)', thm: 'AES is the concrete PRP', key_out: (k) => toHex(pseudoBlock(k, 'cafebabe')) }],
    MAC:  [{ fn: 'AES as PRF', op: 'F_k = AES_k(·)', thm: 'PRP/PRF switching lemma', key_out: (k) => toHex(pseudoBlock(k, '1a2b3c4d')) },
           { fn: 'PRF → MAC: tag = F_k(m)', op: 'Mac_k(m) = F_k(m)', thm: 'PRF ⇒ MAC (direct)', key_out: () => '[awaits Leg 2 message]' }],
    CRHF: [{ fn: 'AES Davies-Meyer compression', op: 'h(cv, M) = AES_M(cv) ⊕ cv', thm: 'PRF-based compression', key_out: (k) => toHex(pseudoBlock(k, '00000000') ^ ks2n(k)) },
           { fn: 'Merkle-Damgård transform (PA#7)', op: 'z_i = h(z_{i-1}, M_i)', thm: 'MD domain extension', key_out: (k) => toHex(mix(pseudoBlock(k, 'aabbccdd'), ks2n(k))) }],
    HMAC: [{ fn: 'AES → CRHF via MD', op: 'H = MD[AES-DM]', thm: 'Collision resistance from PRF compression', key_out: (k) => toHex(pseudoBlock(k, '11223344')) },
           { fn: 'HMAC over AES hash', op: 'H((k⊕opad) ∥ H((k⊕ipad) ∥ m))', thm: 'CRHF → HMAC (PA#10)', key_out: (k) => { const r = hmacCalc(k, 'demo'); return r.outer; } }],
  },
  DLP: {
    OWF:  [{ fn: 'DLP: f(x) = gˣ mod p', op: 'g=7, p=2¹²⁷−1, x from seed', thm: 'OWP/OWF under DL assumption', key_out: (k) => toHex(pseudoBlock(k, 'dlpowfff')) }],
    PRG:  [{ fn: 'DLP OWF: f(x) = gˣ mod p', op: 'x₀ from seed, x_{i+1} = f(x_i)', thm: 'Modular exponentiation', key_out: (k) => toHex(pseudoBlock(k, 'dlp00001')) },
           { fn: 'HILL hard-core bit b(x)', op: 'b(x) = LSB(gˣ mod p) — Goldreich-Levin', thm: 'Hard-core predicate (HILL)', key_out: (k) => `bit: ${pseudoBlock(k, 'hcbit') & 1}` },
           { fn: 'G(x₀) = b(x₀)∥b(x₁)∥…', op: 'Iterate OWF, extract bits', thm: 'PRG from OWF (HILL theorem)', key_out: (k) => `${pseudoBlock(k,'b0')&1}${pseudoBlock(k,'b1')&1}${pseudoBlock(k,'b2')&1}${pseudoBlock(k,'b3')&1}…` }],
    PRF:  [{ fn: 'DLP → HILL PRG', op: 'G(s) = b(f(s))∥b(f²(s))∥…', thm: 'OWF → PRG (HILL)', key_out: (k) => toHex(pseudoBlock(k, 'hlldlp0')) },
           { fn: 'PRG → PRF via GGM tree', op: 'F_k(b₁…bₙ) = G_{bₙ}(…G_{b₁}(k))', thm: 'GGM construction (PA#2)', key_out: (k) => toHex(pseudoBlock(k, 'ggmdlpxx')) }],
    PRP:  [{ fn: 'DLP → PRG → PRF', op: 'Chain: OWF→HILL→GGM', thm: 'Complete Minicrypt chain', key_out: (k) => toHex(pseudoBlock(k, 'dlpchain')) },
           { fn: 'PRF → PRP: Luby-Rackoff Feistel', op: '3-round Feistel with PRF round fn', thm: 'Luby-Rackoff theorem', key_out: (k) => toHex(pseudoBlock(k, 'feistell')) }],
    MAC:  [{ fn: 'DLP → PRG → PRF', op: 'OWF→HILL→GGM', thm: 'Full Minicrypt chain', key_out: (k) => toHex(pseudoBlock(k, 'dlpmac0')) },
           { fn: 'PRF → MAC', op: 'Mac_k(m) = F_k(m)', thm: 'PRF ⇒ MAC', key_out: () => '[awaits Leg 2 message]' }],
    CRHF: [{ fn: 'DLP compression: h(x,y)=gˣ·ĥʸ mod p', op: 'Collision ⇒ DLP solved', thm: 'CRHF under DL assumption (PA#8)', key_out: (k) => toHex(pseudoBlock(k, 'dlpcrhf0')) },
           { fn: 'Merkle-Damgård over DLP compression', op: 'z_i = h(z_{i-1}, M_i)', thm: 'MD transform (PA#7)', key_out: (k) => toHex(mix(pseudoBlock(k, 'dlpcrhf0'), ks2n(k))) }],
    HMAC: [{ fn: 'DLP → CRHF (PA#8 + PA#7)', op: 'DLP compression + MD transform', thm: 'CRHF under DLP', key_out: (k) => toHex(pseudoBlock(k, 'dlpcrhf1')) },
           { fn: 'HMAC over DLP hash (PA#10)', op: 'H((k⊕opad) ∥ H((k⊕ipad) ∥ m))', thm: 'CRHF ⇒ HMAC', key_out: (k) => { const r = hmacCalc(k, 'dlphmac'); return r.outer; } }],
  }
};

// ════════════════════════════════════════════════
// REDUCTION ROUTES (Leg 2)
// ════════════════════════════════════════════════
const ROUTES = {
  'OWF→PRG':    { thm: 'HILL Hard-Core Bit Construction',     pa: 'PA#1a',  desc: 'Apply f repeatedly, extract b(x)=Goldreich-Levin predicate; G(x₀)=b(x₀)∥b(x₁)∥…' },
  'OWF→OWP':    { thm: 'DLP is already a OWP (identity)',     pa: 'PA#1',   desc: 'f(x)=gˣ mod p is a bijection on ℤq — immediately a OWP. Backward: OWP is a special OWF.' },
  'PRG→PRF':    { thm: 'GGM Tree Construction',               pa: 'PA#2a',  desc: 'G:{0,1}ⁿ→{0,1}²ⁿ split G₀/G₁. F_k(b₁…bₙ)=G_{bₙ}(…G_{b₁}(k)). One root-to-leaf path per query.' },
  'PRF→PRP':    { thm: 'Luby-Rackoff 3-Round Feistel',        pa: 'PA#4',   desc: 'Apply PRF as Feistel round fn: 3 rounds → secure PRP; 4 rounds → strong PRP.' },
  'PRF→MAC':    { thm: 'PRF ⇒ MAC (direct)',                  pa: 'PA#5',   desc: 'Mac_k(m)=F_k(m). Any forger distinguishes F_k from random → breaks PRF security.' },
  'PRP→MAC':    { thm: 'PRP/PRF Switching Lemma + PRF⇒MAC',   pa: 'PA#5',   desc: 'PRP over super-poly domain ≈ PRF. Apply PRF→MAC. Concretely: AES-CMAC, CBC-MAC.' },
  'CRHF→HMAC':  { thm: 'HMAC Construction (PA#10)',           pa: 'PA#10',  desc: 'HMAC_k(m)=H((k⊕opad)∥H((k⊕ipad)∥m)). Inner acts as PRF; outer prevents length-extension.' },
  'HMAC→MAC':   { thm: 'HMAC is EUF-CMA secure',              pa: 'PA#10',  desc: 'If compression function is PRF-secure, HMAC is a secure MAC. Direct instantiation.' },
  'CRHF→MAC':   { thm: 'CRHF ⇒ HMAC ⇒ MAC (two steps)',      pa: 'PA#10',  desc: 'DLP hash (PA#8) → HMAC (PA#10) → secure MAC. Full bridge closing the Minicrypt clique.' },
  'PRF→CPA-Enc':{ thm: 'PRF ⇒ CPA-Enc (nonce-based)',        pa: 'PA#3',   desc: 'Enc(k,m)=⟨r,F_k(r)⊕m⟩ with fresh r. CPA-secure since r is never reused and F_k is pseudo-random.' },
  'MAC→CCA-Enc':{ thm: 'Encrypt-then-MAC → CCA2-secure',      pa: 'PA#6',   desc: 'CE←CPA_Enc(k_E,m), t←MAC(k_M,CE), output(CE,t). Verify before decrypt: any tamper detected.' },
  'PRF→HMAC':   { thm: 'PRF ⇒ CRHF ⇒ HMAC',                  pa: 'PA#10',  desc: 'PRF as compression fn → CRHF (MD) → HMAC construction. Two-step chain.' },
  'MAC→PRF':    { thm: 'MAC ⇒ PRF (backward)',                pa: 'PA#5b',  desc: 'EUF-CMA MAC on uniform messages is a PRF. MAC oracle serves as PRF oracle; unforgeability implies pseudorandomness.' },
  'PRF→PRG':    { thm: 'PRF ⇒ PRG (backward)',                pa: 'PA#2b',  desc: 'G(s)=F_s(0ⁿ)∥F_s(1ⁿ). If G distinguishable, distinguisher breaks PRF security.' },
  'PRP→PRF':    { thm: 'PRP/PRF Switching Lemma (backward)',  pa: 'PA#4b',  desc: 'A PRP on super-poly domain is computationally indistinguishable from a PRF. AES used as PRF in CTR/GCM.' },
  'HMAC→CRHF':  { thm: 'HMAC ⇒ CRHF (fix key)',              pa: 'PA#10b', desc: "Fix k. H'(m)=HMAC_k(m). Collision in H' is a MAC forgery. Use HMAC compression step in new MD hash." },
  'MAC→CRHF':   { thm: 'MAC ⇒ CRHF (backward, via MD)',       pa: 'PA#7b',  desc: 'MAC as collision-resistant compression fn + MD transform → CRHF. Any MD collision → MAC forgery.' },
  'PRG→OWF':    { thm: 'PRG ⇒ OWF (immediate)',               pa: 'PA#1b',  desc: 'f(s)=G(s) is a OWF. Inverting f recovers seed, breaking PRG pseudorandomness.' },
};