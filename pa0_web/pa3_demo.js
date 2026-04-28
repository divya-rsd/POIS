const m0Inp = document.getElementById('cpa-m0');
const m1Inp = document.getElementById('cpa-m1');
const reuseChk = document.getElementById('cpa-reuse');
const ctOut = document.getElementById('cpa-ct');
const guessArea = document.getElementById('guess-area');
const resArea = document.getElementById('result-area');
const statPlayed = document.getElementById('stat-played');
const statWin = document.getElementById('stat-winrate');

let played = 0;
let wins = 0;
let currentB = -1;
const k = "00112233445566778899aabbccddeeff"; // static key for demo

document.getElementById('btn-chal').addEventListener('click', async () => {
  resArea.style.display = 'none';
  try {
    const res = await Backend.pa3Game(k, m0Inp.value, m1Inp.value, reuseChk.checked);
    currentB = res.b;
    ctOut.value = "r : " + res.r + "\nct: " + res.ct;
    guessArea.style.display = 'block';
  } catch(e) {
    ctOut.value = "Error: " + e.message;
  }
});

function handleGuess(guess) {
  if (currentB === -1) return;
  played++;
  const win = (guess === currentB);
  if (win) wins++;
  
  guessArea.style.display = 'none';
  resArea.style.display = 'block';
  resArea.className = 'status ' + (win ? 'ok' : 'err');
  resArea.textContent = win ? `Correct! It was m${currentB}.` : `Wrong. It was m${currentB}.`;
  
  statPlayed.textContent = played;
  statWin.textContent = Math.round((wins/played)*100) + "%";
  currentB = -1;
}

document.getElementById('btn-guess-0').addEventListener('click', () => handleGuess(0));
document.getElementById('btn-guess-1').addEventListener('click', () => handleGuess(1));
