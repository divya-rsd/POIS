// ════════════════════════════════════════════════
// SECURITY GAME
// ════════════════════════════════════════════════
let gameState = { b: 0, active: false };

function launchGame() {
  if (!S.leg1Val) {
    document.getElementById('game-area').innerHTML =
      `<div class="status warn">⚠ Run Leg 1 first.</div>`;
    return;
  }
  S.gameRounds = 0; S.gameWins = 0;
  gameState.b = Math.round(Math.random());
  const m0 = randHex(4), m1 = randHex(4);
  const chosen = gameState.b === 0 ? m0 : m1;
  const ct = toHex(pseudoBlock(S.key, chosen));
  gameState = { b: gameState.b, m0, m1, ct, active: true };
  renderGame();
}

function renderGame() {
  const { m0, m1, ct } = gameState;
  const adv = S.gameRounds ? Math.abs(S.gameWins / S.gameRounds - 0.5) : 0;
  const pct = Math.round(adv * 200);
  document.getElementById('game-area').innerHTML = `
  <div class="game-box">
    <div class="game-head">
      <span class="game-head-dot"></span>
      IND-${S.tgt || 'SEC'} Security Game &nbsp;·&nbsp; Round ${S.gameRounds + 1} &nbsp;·&nbsp; Wins: ${S.gameWins}/${S.gameRounds}
    </div>
    <div class="game-body">
      <div class="game-row"><span class="game-label">m₀ =</span><span class="game-ct">${m0}</span></div>
      <div class="game-row"><span class="game-label">m₁ =</span><span class="game-ct">${m1}</span></div>
      <div class="game-row"><span class="game-label">C* = Enc(m_b) =</span><span class="game-ct">${ct}</span></div>
      <div class="game-btns">
        <button class="btn-guess" onclick="gameGuess(0)">b = 0</button>
        <button class="btn-guess" onclick="gameGuess(1)">b = 1</button>
        <button class="btn btn-ghost btn-sm" onclick="launchGame()" style="margin-left:auto">↺ New</button>
      </div>
      <div>
        <div class="adv-bar-wrap"><div class="adv-bar${pct > 30 ? ' bad' : ''}" style="width:${pct}%"></div></div>
        <div class="adv-label">Adversary advantage: ${adv.toFixed(3)} — secure scheme converges to 0</div>
      </div>
    </div>
  </div>`;
}

function gameGuess(g) {
  if (!gameState.active) return;
  S.gameRounds++;
  if (g === gameState.b) S.gameWins++;
  const correct = g === gameState.b;
  const statusDiv = document.createElement('div');
  statusDiv.className = 'status ' + (correct ? 'ok' : 'warn');
  statusDiv.style.marginTop = '6px';
  statusDiv.textContent = `${correct ? '✓ Correct' : '✗ Wrong'}: b was ${gameState.b}, you guessed ${g}. Plaintext: ${gameState['m' + gameState.b]}`;
  document.querySelector('.game-body').appendChild(statusDiv);
  setTimeout(() => {
    gameState.b = Math.round(Math.random());
    const m0 = randHex(4), m1 = randHex(4);
    const ct = toHex(pseudoBlock(S.key, gameState.b === 0 ? m0 : m1));
    gameState = { ...gameState, b: gameState.b, m0, m1, ct, active: true };
    renderGame();
  }, 1400);
}