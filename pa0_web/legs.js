// ════════════════════════════════════════════════
// LEG 1 — Foundation → Source Primitive
// ════════════════════════════════════════════════
function runLeg1() {
  const { foundation, src, key } = S;
  const chain = FOUND_CHAINS[foundation][src] || [];
  let html = '';
  let lastVal = null;

  chain.forEach((step, i) => {
    const out = step.key_out(key);
    lastVal = out;
    html += stepHTML(i + 1, step.fn, step.thm, [
      ['Input',  i === 0 ? key.toUpperCase() : '(previous step output)'],
      ['Op',     step.op],
      ['Output', out],
    ], false, false);
    if (i < chain.length - 1) html += arrowDiv();
  });

  if (!html) html = '<div class="empty">No chain defined for this selection.</div>';
  document.getElementById('leg1-steps').innerHTML = html;

  S.leg1Val = lastVal || pseudoBlock(key, 'fallback').toString(16).toUpperCase();
  document.getElementById('leg1-out-lbl').textContent = `${src} instance  →  feeds Leg 2 as black box`;
  document.getElementById('leg1-out-val').textContent = S.leg1Val;
  document.getElementById('leg1-out').style.display = 'block';

  renderClique(src, S.tgt);
  updateProof();
}

// ════════════════════════════════════════════════
// LEG 2 — Source → Target Primitive (with bug fixes)
//
// FIX 1: Added missing CRHF → HMAC case (was omitted from active runLeg2 though
//         present in the commented-out draft, causing it to fall to the generic stub).
// FIX 2: leg2-out-lbl now shows full descriptive label (direction + primitive names)
//         instead of the truncated "src output (fwd)" string.
// FIX 3: PRIMS array (in crypto.js) now includes CPA-Enc and CCA-Enc so those
//         primitives highlight correctly in the clique map when selected as target.
// ════════════════════════════════════════════════
function runLeg2() {
  if (!S.leg1Val) {
    document.getElementById('leg2-status').innerHTML =
      `<div class="status warn">⚠ Run Leg 1 first — Leg 2 receives ${S.src} as a black box from Leg 1.</div>`;
    return;
  }
  if (S.src === S.tgt) {
    document.getElementById('leg2-steps').innerHTML =
      `<div class="empty">Source and target must differ.</div>`;
    return;
  }

  document.getElementById('leg2-status').innerHTML = '';

  const dir    = S.dir === 'fwd' ? `${S.src}→${S.tgt}` : `${S.tgt}→${S.src}`;
  const route  = ROUTES[dir];
  const key    = S.key, msg = S.msg, base = S.leg1Val;
  const msgInt = parseInt(msg.replace(/[^01]/g, '').padEnd(8, '0').slice(0, 8), 2);

  let html = '', finalVal = null;

  // ─────────────────────────────────────────
  // PRG → PRF (GGM tree)
  // ─────────────────────────────────────────
  if (S.src === 'PRG' && S.tgt === 'PRF' && S.dir === 'fwd') {
    const bits = msg.replace(/[^01]/g, '').slice(0, 4) || '1011';
    const path = ggmPath(key, bits);

    html += stepHTML(1, 'GGM Tree: evaluate F_k(x)', 'PRG ⇒ PRF (GGM)', [
      ['Key k',     base],
      ['Query bits x', bits],
    ]);

    path.slice(1).forEach((p, i) => {
      html += arrowDiv();
      html += stepHTML(i + 2, `Apply ${p.fn}`, null, [
        ['State',  p.val],
        ['Branch', `bit ${p.bit} → ${p.bit ? 'right (G₁)' : 'left (G₀)'}`],
      ], false, i === path.length - 2);
    });

    finalVal = path[path.length - 1]?.val;
  }

  // ─────────────────────────────────────────
  // PRF → PRP (Luby-Rackoff Feistel)
  // ─────────────────────────────────────────
  else if (S.src === 'PRF' && S.tgt === 'PRP' && S.dir === 'fwd') {
    const res = feistelEnc(key, msgInt);

    html += stepHTML(1, 'Split input: L₀∥R₀', 'Luby-Rackoff Feistel', [
      ['Input x', msgInt.toString(16).toUpperCase().padStart(8, '0')],
      ['L₀',      toHex(msgInt >>> 16, 4)],
      ['R₀',      toHex(msgInt & 0xFFFF, 4)],
    ]);

    res.rounds.forEach((r, i) => {
      html += arrowDiv();
      html += stepHTML(i + 2, `Round ${r.r}: L←R, R←L⊕F(R)`, 'Feistel step', [
        ['L_in', r.L], ['R_in', r.R], ['F(R)', r.f], ['L_out', r.nL], ['R_out', r.nR],
      ], false, i === 2);
    });

    finalVal = res.out;
  }

  // ─────────────────────────────────────────
  // PRF → MAC
  // ─────────────────────────────────────────
  else if (S.src === 'PRF' && S.tgt === 'MAC' && S.dir === 'fwd') {
    const tag = toHex(pseudoBlock(key, msg));

    html += stepHTML(1, 'Compute tag: Mac_k(m) = F_k(m)', 'PRF ⇒ MAC', [
      ['Key k', base], ['Msg m', msg], ['F_k(m)', tag],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Verify: Vrfy_k(m,t)', 'EUF-CMA security', [
      ['Tag t',          tag],
      ['Recompute F_k(m)', tag],
      ['Result',         '✓ Valid — tag accepted', false],
    ], false, true);

    finalVal = tag;
  }

  // ─────────────────────────────────────────
  // CRHF → HMAC  (FIX: was missing, fell through to generic stub)
  // ─────────────────────────────────────────
  else if (S.src === 'CRHF' && S.tgt === 'HMAC' && S.dir === 'fwd') {
    const { inner, outer } = hmacCalc(key, msg);

    html += stepHTML(1, 'Inner hash: H((k⊕ipad)∥m)', 'HMAC construction (PA#10)', [
      ['k⊕ipad (partial)', toHex(ks2n(key) ^ 0x36363636)],
      ['Input',            `(k⊕ipad) ∥ ${msg}`],
      ['H(inner_key∥msg)', inner],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Outer hash: H((k⊕opad)∥inner)', 'HMAC — prevents length-extension', [
      ['k⊕opad (partial)', toHex(ks2n(key) ^ 0x5c5c5c5c)],
      ['Inner hash',       inner],
      ['HMAC output',      outer],
    ], false, true);

    finalVal = outer;
  }

  // ─────────────────────────────────────────
  // MAC → CCA-Enc (Encrypt-then-MAC)
  // ─────────────────────────────────────────
  else if (S.src === 'MAC' && S.tgt === 'CCA-Enc' && S.dir === 'fwd') {
    const r   = toHex(pseudoBlock(key, 'nonce'));
    const fkr = toHex(pseudoBlock(key, r));
    const ct  = toHex(pseudoBlock(key, r) ^ msgInt);
    const tag = toHex(pseudoBlock(key, ct));

    html += stepHTML(1, 'CPA-Enc: C_E = ⟨r, F_k(r) ⊕ m⟩', 'PRF-based CPA encryption (PA#3)', [
      ['r (random)', r], ['F_k(r)', fkr], ['C_E', ct],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'MAC(k_M, C_E) → tag t', 'EUF-CMA MAC (PA#5)', [
      ['C_E', ct], ['tag t = Mac(C_E)', tag],
    ]);
    html += arrowDiv();
    html += stepHTML(3, 'Output (C_E, t) — Vrfy before Dec!', 'Encrypt-then-MAC → CCA2-secure', [
      ['C_E', ct], ['t', tag],
      ['Security', '✓ Any tamper detected — MAC check fires before decrypt', false],
    ], false, true);

    finalVal = tag;
  }

  // ─────────────────────────────────────────
  // PRF → CPA-Enc (nonce-based)
  // ─────────────────────────────────────────
  else if (S.src === 'PRF' && S.tgt === 'CPA-Enc' && S.dir === 'fwd') {
    const r   = toHex(pseudoBlock(key, 'nonce'));
    const fkr = toHex(pseudoBlock(key, r));
    const ct  = toHex(pseudoBlock(key, r) ^ msgInt);

    html += stepHTML(1, 'Sample random nonce r', 'CPA-secure encryption (PA#3)', [
      ['r', r],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Compute keystream', 'PRF evaluation', [
      ['F_k(r)', fkr],
    ]);
    html += arrowDiv();
    html += stepHTML(3, 'Encrypt', 'Enc(k,m)=⟨r, F_k(r)⊕m⟩', [
      ['Plaintext m', toHex(msgInt)],
      ['Ciphertext',  ct],
    ], false, true);

    finalVal = ct;
  }

  // ─────────────────────────────────────────
  // BACKWARD: PRF → PRG
  // ─────────────────────────────────────────
  else if (S.src === 'PRF' && S.tgt === 'PRG' && S.dir === 'bwd') {
    const g0 = toHex(pseudoBlock(key, '0'));
    const g1 = toHex(pseudoBlock(key, '1'));

    html += stepHTML(1, 'Construct PRG from PRF', 'PRF ⇒ PRG', [
      ['F_s(0)', g0],
      ['F_s(1)', g1],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Concatenate outputs', 'G(s) = F_s(0) ∥ F_s(1)', [
      ['Output', g0 + g1],
    ], false, true);

    finalVal = g0 + g1;
  }

  // ─────────────────────────────────────────
  // BACKWARD: PRP → PRF (switching lemma)
  // ─────────────────────────────────────────
  else if (S.src === 'PRP' && S.tgt === 'PRF' && S.dir === 'bwd') {
    const out = toHex(pseudoBlock(key, msg));

    html += stepHTML(1, 'PRP/PRF Switching Lemma', 'PRP ≈ PRF on large domain', [
      ['Assumption', 'PRP indistinguishable from random permutation'],
      ['Adv diff',   '≤ q²/2ⁿ (birthday bound)'],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Evaluate as PRF', 'Use PRP oracle directly as PRF', [
      ['Input x', msg],
      ['Output',  out],
    ], false, true);

    finalVal = out;
  }

  // ─────────────────────────────────────────
  // GENERIC FALLBACK — known route but no bespoke visualisation
  // ─────────────────────────────────────────
  else if (route) {
    const demoOut = toHex(pseudoBlock(key, msg + base));

    html += stepHTML(1, route.thm, route.pa, [
      ['From',  S.src],
      ['To',    S.tgt],
      ['Idea',  route.desc, false],
    ]);
    html += arrowDiv();
    html += stepHTML(2, 'Security reduction argument', 'Computational reduction', [
      ['Adv_B',      'adversary breaking B with advantage ε'],
      ['Reduction',  'If Adv breaks B with ε, it breaks A with ε′ ≥ ε/q'],
      ['Implication','✓ Security preserved by negligible loss', false],
      ['Demo output', demoOut],
    ]);

    finalVal = demoOut;
  }

  // ─────────────────────────────────────────
  // NO ROUTE
  // ─────────────────────────────────────────
  else {
    const revRoute = ROUTES[S.dir === 'fwd' ? `${S.tgt}→${S.src}` : `${S.src}→${S.tgt}`];
    html = `<div class="status warn">⚠ No direct reduction ${S.src}→${S.tgt} in this direction. ${
      revRoute ? 'Try the Backward toggle.' : 'Compose intermediate steps or pick an adjacent pair.'
    }</div>`;
  }

  document.getElementById('leg2-steps').innerHTML = html;

  if (finalVal) {
    // FIX: descriptive label — shows full direction string like the original draft intended
    document.getElementById('leg2-out-lbl').textContent =
      `${S.tgt} output (${S.dir === 'fwd' ? 'forward' : 'backward'} reduction from ${S.src})`;
    document.getElementById('leg2-out-val').textContent = finalVal;
    document.getElementById('leg2-out').style.display = 'block';
  }

  renderClique(S.src, S.tgt);
  updateProof();
}