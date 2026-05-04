let aliceBit = 0;
let bobBit = 0;

const aliceBtns = document.querySelectorAll('.bit-btn.alice');
const bobBtns = document.querySelectorAll('.bit-btn.bob');
const btnEval = document.getElementById('btn-eval');
const chatLog = document.getElementById('chat-log');
const statusDiv = document.getElementById('and-status');

aliceBtns.forEach(b => {
  b.addEventListener('click', () => {
    aliceBtns.forEach(btn => btn.classList.remove('active'));
    b.classList.add('active');
    aliceBit = parseInt(b.getAttribute('data-val'), 10);
  });
});

bobBtns.forEach(b => {
  b.addEventListener('click', () => {
    bobBtns.forEach(btn => btn.classList.remove('active'));
    b.classList.add('active');
    bobBit = parseInt(b.getAttribute('data-val'), 10);
  });
});

function logSys(msg) { chatLog.innerHTML += `<div class="log-entry log-sys">${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logAlice(msg) { chatLog.innerHTML += `<div class="log-entry log-alice"><b>Alice:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logBob(msg) { chatLog.innerHTML += `<div class="log-entry log-bob"><b>Bob:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

btnEval.addEventListener('click', async () => {
  btnEval.disabled = true;
  chatLog.innerHTML = '';
  statusDiv.style.display = 'none';

  logSys(`Starting Secure AND. Alice's bit a=${aliceBit}, Bob's bit b=${bobBit} stay private.`);

  try {
    // pa19/demo_and runs the SecureGates.AND protocol once and returns the OT transcript.
    const res = await Backend.pa19DemoAnd(aliceBit, bobBit);

    logAlice(`I act as the OT sender with messages (m0, m1) = (0, a) = (0, ${aliceBit}).`);
    await delay(700);
    logBob(`I act as the OT receiver with choice b = ${bobBit}. I will obtain m_b = a · b.`);
    await delay(700);

    logSys(`Underlying OT exchange (transcript captured by SecureGates):`);
    if (Array.isArray(res.transcript)) {
      res.transcript.forEach(entry => {
        const keys = Object.keys(entry.payload || {}).join(', ');
        logSys(`  [${entry.op}] payload keys: {${keys}} — no a/b bits ever cross the wire`);
      });
    }

    await delay(500);
    logBob(`OT delivered m_${bobBit} = ${res.res}.`);
    logSys(`Output a AND b = ${res.res} (expected ${aliceBit & bobBit}). ${res.res === (aliceBit & bobBit) ? '✓' : '✗'}`);

    statusDiv.style.display = 'block';
    statusDiv.className = 'status ok';
    statusDiv.textContent = `RESULT: ${aliceBit} AND ${bobBit} = ${res.res}`;
  } catch (e) {
    logSys(`Error: ${e.message}`);
  } finally {
    btnEval.disabled = false;
  }
});
