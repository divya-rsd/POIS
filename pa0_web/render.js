// ════════════════════════════════════════════════
// RENDER HELPERS
// ════════════════════════════════════════════════

function stepHTML(idx, name, thm, rows, isStub = false, isDone = false) {
  const numCls = isStub ? 'stub' : (isDone ? 'done' : '');
  const delay = `animation-delay:${idx * 0.06}s`;
  return `<div class="step-card" style="${delay}">
    <div class="step-head">
      <div class="step-num ${numCls}">${idx}</div>
      <span style="color:var(--text2)">${name}</span>
      ${thm ? `<span class="thm-tag">${thm}</span>` : ''}
    </div>
    <div class="step-body">
      ${rows.map(([k, v, mono = true, stub = false]) => `
        <div class="step-row">
          <span class="step-key">${k}</span>
          ${mono
            ? `<span class="mono ${stub ? 'stub-val' : ''}">${v}</span>`
            : `<span class="step-val-plain ${stub ? 'stub-val' : ''}">${v}</span>`
          }
        </div>`).join('')}
    </div>
  </div>`;
}

function stubStep(idx, name, paNum, desc) {
  return stepHTML(idx, name, null, [
    ['Status', `Not yet implemented — ${paNum}`, true, true],
    ['Method', desc, true, true],
    ['Demo',   'Returning stub fixed value for PA#0 scaffold', false, true],
  ], true);
}

function arrowDiv() {
  return '<div class="arrow-mid">↓</div>';
}

// ════════════════════════════════════════════════
// CLIQUE MAP
// ════════════════════════════════════════════════
function renderClique(src, tgt) {
  const makeHTML = (pill) => PRIMS.map((p, i) => {
    const isSrc = p === src, isTgt = p === tgt, isBoth = isSrc && isTgt;
    const cls = isBoth ? 'both' : (isSrc ? 'src' : (isTgt ? 'tgt' : ''));
    const arrow = i < PRIMS.length - 1 ? `<span class="${pill ? 'cpill-arrow' : 'carrow'}">→</span>` : '';
    return `<span class="${pill ? 'cpill' : 'cnode'} ${cls}">${p}</span>${arrow}`;
  }).join('');

  document.getElementById('clique-map').innerHTML  = makeHTML(false);
  document.getElementById('hero-clique').innerHTML = makeHTML(true);

  // Update badges
  document.getElementById('leg1-badge').textContent = `${S.foundation} → ${src}`;
  document.getElementById('leg2-badge').textContent = S.dir === 'fwd' ? `${src} → ${tgt}` : `${tgt} → ${src}`;
}

// ════════════════════════════════════════════════
// PROOF PANEL
// ════════════════════════════════════════════════
function updateProof() {
  const { foundation, src, tgt, dir } = S;
  const routeKey = dir === 'fwd' ? `${src}→${tgt}` : `${tgt}→${src}`;
  const route = ROUTES[routeKey];
  const chain = FOUND_CHAINS[foundation][src] || [];
  document.getElementById('proof-chain-inline').textContent = `${foundation} → ${src} → ${tgt}`;

  const cards = [];
  const fDesc = {
    AES: `AES-128: concrete PRP (substitution-permutation network). Security conjecture: AES behaves as an ideal PRP. Used as PRF via PRP/PRF switching lemma (negligible advantage loss). Implements: PA#2 AES plug-in.`,
    DLP: `DLP: f(x)=gˣ mod p in safe-prime group. Security: Discrete Logarithm hardness assumption. Basis for Diffie-Hellman (PA#11) and DLP-based CRHF (PA#8). Implements: PA#1 OWF.`
  }[foundation];

  cards.push(`<div class="proof-card">
    <div class="pc-title"><span class="tag tag-blue">Foundation</span> ${foundation}</div>
    <div class="pc-body">${fDesc}</div>
  </div>`);

  const chainDesc = chain.map(s => `<b>${s.fn}:</b> <code>${s.op}</code> [${s.thm}]`).join('<br>');
  cards.push(`<div class="proof-card">
    <div class="pc-title"><span class="tag tag-blue">Leg 1</span> ${foundation} → ${src}</div>
    <div class="pc-body">${chainDesc || '(direct instantiation)'}<br><i>Implements: ${PA_NUM[src] || '—'}</i></div>
  </div>`);

  if (route) {
    cards.push(`<div class="proof-card">
      <div class="pc-title"><span class="tag tag-green">Leg 2</span> ${src} → ${tgt}</div>
      <div class="pc-body">
        <b>${route.thm}</b><br>${route.desc}<br>
        <i>Security: If adversary breaks <b>${tgt}</b> with advantage ε, it breaks <b>${src}</b> with ε′ ≥ ε/q.<br>
        Implements: ${route.pa || PA_NUM[tgt] || '—'}</i>
      </div>
    </div>`);
  } else {
    cards.push(`<div class="proof-card">
      <div class="pc-title"><span class="tag tag-amber">Leg 2</span> ${src} → ${tgt}</div>
      <div class="pc-body"><i>No direct single-step reduction in this direction. Use the Backward toggle or pick adjacent clique members.</i></div>
    </div>`);
  }

  cards.push(`<div class="proof-card">
    <div class="pc-title">Full Reduction Chain</div>
    <div class="chain-mono">${foundation} ──[${foundation === 'AES' ? 'PRP/PRF switching lemma' : 'HILL + GGM'}]──▶ ${src} ──[${route?.thm || '?'}]──▶ ${tgt}</div>
    <div class="pc-body" style="margin-top:10px">
      Security claim: ${foundation}-security ⇒ ${src}-security ⇒ ${tgt}-security.<br>
      Each reduction preserves negligible adversarial advantage up to polynomial loss. The Minicrypt Equivalence Theorem guarantees all clique primitives are mutually reducible.
    </div>
  </div>`);

  const bwKey = dir === 'fwd' ? `${tgt}→${src}` : `${src}→${tgt}`;
  const bw = ROUTES[bwKey];
  if (bw) {
    cards.push(`<div class="proof-card">
      <div class="pc-title"><span class="tag tag-purple">Backward</span> ${tgt} → ${src}</div>
      <div class="pc-body"><b>${bw.thm}</b><br>${bw.desc}<br><i>Implements: ${bw.pa}</i></div>
    </div>`);
  }

  document.getElementById('proof-cards').innerHTML = cards.join('');
}