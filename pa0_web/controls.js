// ════════════════════════════════════════════════
// APPLICATION STATE
// ════════════════════════════════════════════════
const S = {
  foundation: 'AES', dir: 'fwd',
  src: 'PRF', tgt: 'PRP',
  key: 'a3f2c1b4e9d05678feedcafe',
  msg: '1011',
  leg1Val: null,
  gameRounds: 0, gameWins: 0,
};

// ════════════════════════════════════════════════
// CONTROL HANDLERS
// ════════════════════════════════════════════════
function setFoundation(f) {
  S.foundation = f;
  document.querySelectorAll('#seg-found button')
    .forEach(b => b.classList.toggle('on', b.textContent.startsWith(f)));
  clearOutputs(); updateProof();
}

function setDir(d) {
  S.dir = d;
  document.querySelectorAll('#seg-dir button')
    .forEach(b => b.classList.toggle('on', b.getAttribute('onclick').includes(`'${d}'`)));
  clearOutputs(); updateProof();
}

function onSrcChange() {
  S.src = document.getElementById('sel-src').value;
  clearOutputs(); renderClique(S.src, S.tgt); updateProof();
}

function onTgtChange() {
  S.tgt = document.getElementById('sel-tgt').value;
  renderClique(S.src, S.tgt); updateProof();
}

function onKeyChange() { S.key = document.getElementById('inp-key').value; }
function onMsgChange() { S.msg = document.getElementById('inp-msg').value; }

function clearOutputs() {
  S.leg1Val = null;
  document.getElementById('leg1-steps').innerHTML  = '<div class="empty">Select a primitive and click Build from Foundation</div>';
  document.getElementById('leg1-out').style.display = 'none';
  document.getElementById('leg2-steps').innerHTML  = '<div class="empty">Run Leg 1 first, then click Run Reduction</div>';
  document.getElementById('leg2-out').style.display = 'none';
  document.getElementById('leg2-status').innerHTML  = '';
  document.getElementById('game-area').innerHTML    = '';
}

function clearAll() { clearOutputs(); updateProof(); }

function randomize() {
  S.key = randHex(12);
  document.getElementById('inp-key').value = S.key;
  const bits = ['0', '1']; let b = '';
  for (let i = 0; i < 4; i++) b += bits[Math.floor(Math.random() * 2)];
  S.msg = b;
  document.getElementById('inp-msg').value = S.msg;
}

// ════════════════════════════════════════════════
// INIT — run after DOM is ready
// ════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  renderClique(S.src, S.tgt);
  updateProof();
});