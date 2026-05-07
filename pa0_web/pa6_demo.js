const msgInp = document.getElementById('pt-msg');
const cpaCtBox = document.getElementById('cpa-ct');
const cpaDecBox = document.getElementById('cpa-dec');
const ccaCtBox = document.getElementById('cca-ct');
const ccaDecBox = document.getElementById('cca-dec');
const ccaStatus = document.getElementById('cca-status');

const k = '00112233445566778899aabbccddeeff';
const ke = '00112233445566778899aabbccddeeff';
const km = 'ffeeddccbbaa99887766554433221100';

let baseCpaR = '';
let baseCpaCt = '';
let baseCcaBlob = '';
let baseCcaTag = '';

let selectedBitIndex = null;

function ensureBitToolStyles() {
  if (document.getElementById('pa6-bit-style')) return;
  const style = document.createElement('style');
  style.id = 'pa6-bit-style';
  style.textContent = `
    .bit-tool { display:flex; flex-direction:column; gap:6px; }
    .bit-meta { font-size:10px; color:var(--text3); font-family:var(--mono); }
    .bit-grid { font-family:var(--mono); font-size:10px; line-height:1.8; user-select:none; }
    .bit-cell {
      display:inline-block;
      min-width:10px;
      text-align:center;
      border-radius:4px;
      margin:1px;
      padding:0 1px;
      cursor:pointer;
      color:var(--text2);
      transition:all .12s ease;
    }
    .bit-cell:hover { background:var(--surface2); color:var(--accent); }
    .bit-cell.active { background:rgba(251,191,36,.2); color:var(--amber); border:1px solid rgba(251,191,36,.5); }
    .bit-sep { color:var(--text3); margin:0 2px; }
    .bit-actions { display:flex; gap:6px; }
    .btn-mini {
      padding:4px 8px;
      font-size:10px;
      border:1px dashed var(--text3);
      color:var(--text3);
      background:transparent;
      border-radius:var(--r);
      cursor:pointer;
    }
    .btn-mini:hover { border-color:var(--accent); color:var(--accent); background:var(--surface2); }
  `;
  document.head.appendChild(style);
}

function hexToBits(hex) {
  const clean = (hex || '').trim();
  const bits = [];
  for (let i = 0; i < clean.length; i += 1) {
    const nibble = Number.parseInt(clean[i], 16);
    const val = Number.isNaN(nibble) ? 0 : nibble;
    bits.push(((val >> 3) & 1).toString());
    bits.push(((val >> 2) & 1).toString());
    bits.push(((val >> 1) & 1).toString());
    bits.push((val & 1).toString());
  }
  return bits;
}

function bitsToHex(bits) {
  if (!bits.length) return '';
  let out = '';
  for (let i = 0; i < bits.length; i += 4) {
    const nibble =
      ((bits[i] === '1' ? 1 : 0) << 3)
      | ((bits[i + 1] === '1' ? 1 : 0) << 2)
      | ((bits[i + 2] === '1' ? 1 : 0) << 1)
      | (bits[i + 3] === '1' ? 1 : 0);
    out += nibble.toString(16);
  }
  return out;
}

function flipBitInHex(hex, bitIndex) {
  const bits = hexToBits(hex);
  if (bitIndex == null || bitIndex < 0 || bitIndex >= bits.length) {
    return hex;
  }
  bits[bitIndex] = bits[bitIndex] === '1' ? '0' : '1';
  return bitsToHex(bits);
}

function getMutatedCpa() {
  const full = `${baseCpaR}${baseCpaCt}`;
  return flipBitInHex(full, selectedBitIndex);
}

function getMutatedCcaBlob() {
  return flipBitInHex(baseCcaBlob, selectedBitIndex);
}

function splitCpaFull(fullHex) {
  const rHexLen = baseCpaR.length;
  return {
    r: fullHex.slice(0, rHexLen),
    ct: fullHex.slice(rHexLen),
  };
}

function renderBitTool(container, hex, title) {
  const bits = hexToBits(hex);
  const selectedLabel = selectedBitIndex == null ? 'none' : selectedBitIndex;

  container.innerHTML = '';

  const root = document.createElement('div');
  root.className = 'bit-tool';

  const meta = document.createElement('div');
  meta.className = 'bit-meta';
  meta.textContent = `${title} | bits: ${bits.length} | selected: ${selectedLabel}`;
  root.appendChild(meta);

  const grid = document.createElement('div');
  grid.className = 'bit-grid';

  bits.forEach((bit, idx) => {
    const span = document.createElement('span');
    span.className = `bit-cell${selectedBitIndex === idx ? ' active' : ''}`;
    span.textContent = bit;
    span.title = `Bit ${idx}`;
    span.addEventListener('click', () => {
      selectedBitIndex = selectedBitIndex === idx ? null : idx;
      void updateLivePanels();
    });
    grid.appendChild(span);

    if ((idx + 1) % 8 === 0 && idx !== bits.length - 1) {
      const sep = document.createElement('span');
      sep.className = 'bit-sep';
      sep.textContent = ' ';
      grid.appendChild(sep);
    }
  });

  root.appendChild(grid);

  const actions = document.createElement('div');
  actions.className = 'bit-actions';

  const clearBtn = document.createElement('button');
  clearBtn.className = 'btn-mini';
  clearBtn.type = 'button';
  clearBtn.textContent = 'Clear Flip';
  clearBtn.addEventListener('click', () => {
    selectedBitIndex = null;
    void updateLivePanels();
  });

  actions.appendChild(clearBtn);
  root.appendChild(actions);

  container.appendChild(root);
}

async function decryptCpaLive() {
  if (!baseCpaR || !baseCpaCt) {
    cpaDecBox.value = '';
    return;
  }

  try {
    const fullMut = getMutatedCpa();
    const { r, ct } = splitCpaFull(fullMut);
    const res = await Backend.pa3Decrypt(k, r, ct);
    cpaDecBox.value = res.pt ?? '';
  } catch (e) {
    cpaDecBox.value = `Error: ${e.message}`;
  }
}

async function decryptCcaLive() {
  if (!baseCcaBlob || !baseCcaTag) {
    ccaDecBox.value = '';
    ccaStatus.style.display = 'none';
    return;
  }

  try {
    const blob = getMutatedCcaBlob();
    const res = await Backend.pa6Decrypt(ke, km, blob, baseCcaTag);

    ccaStatus.style.display = 'block';
    if (res.rejected) {
      ccaStatus.className = 'status err';
      ccaStatus.textContent = '⊥ REJECTED: Invalid MAC Tag';
      ccaDecBox.value = '---';
    } else {
      ccaStatus.className = 'status ok';
      ccaStatus.textContent = 'VERIFIED & DECRYPTED';
      ccaDecBox.value = res.pt ?? '';
    }
  } catch (e) {
    ccaStatus.style.display = 'block';
    ccaStatus.className = 'status err';
    ccaStatus.textContent = `⊥ REJECTED: ${e.message}`;
    ccaDecBox.value = '---';
  }
}

async function updateLivePanels() {
  if (!baseCpaR || !baseCpaCt || !baseCcaBlob) return;

  const cpaFull = getMutatedCpa();
  const ccaBlob = getMutatedCcaBlob();

  renderBitTool(cpaCtBox, cpaFull, 'CPA ciphertext C = <r, ct>');
  renderBitTool(ccaCtBox, ccaBlob, 'CCA ciphertext blob');

  await Promise.all([decryptCpaLive(), decryptCcaLive()]);
}

document.getElementById('btn-enc').addEventListener('click', async () => {
  const m = msgInp.value;
  if (!m) return;

  cpaDecBox.value = '';
  ccaDecBox.value = '';
  ccaStatus.style.display = 'none';

  try {
    const resCpa = await Backend.pa3Encrypt(k, m);
    baseCpaR = resCpa.r;
    baseCpaCt = resCpa.ct;

    const resCca = await Backend.pa6Encrypt(ke, km, m);
    baseCcaBlob = resCca.blob;
    baseCcaTag = resCca.tag;

    selectedBitIndex = null;
    await updateLivePanels();
  } catch (e) {
    alert(`Encryption failed: ${e.message}`);
  }
});

// Keep old controls working, but route them into the new live bit tool.
document.getElementById('btn-flip-cpa').addEventListener('click', async () => {
  if (!baseCpaR || !baseCpaCt) return;
  selectedBitIndex = selectedBitIndex == null ? 0 : selectedBitIndex;
  await updateLivePanels();
});

document.getElementById('btn-flip-cca').addEventListener('click', async () => {
  if (!baseCcaBlob) return;
  selectedBitIndex = selectedBitIndex == null ? 0 : selectedBitIndex;
  await updateLivePanels();
});

document.getElementById('btn-dec-cpa').addEventListener('click', async () => {
  await decryptCpaLive();
});

document.getElementById('btn-dec-cca').addEventListener('click', async () => {
  await decryptCcaLive();
});

ensureBitToolStyles();