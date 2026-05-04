const btnC0 = document.getElementById('btn-c0');
const btnC1 = document.getElementById('btn-c1');
const btnCheat = document.getElementById('btn-cheat');
const cheatRow = document.getElementById('cheat-row');
const chatLog = document.getElementById('chat-log');

const m0Inp = document.getElementById('alice-m0');
const m1Inp = document.getElementById('alice-m1');

let lastChoice = -1;
let protocolReady = false;

function logSys(msg) { chatLog.innerHTML += `<div class="log-entry log-sys">${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logAlice(msg) { chatLog.innerHTML += `<div class="log-entry log-alice"><b>Alice:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logBob(msg) { chatLog.innerHTML += `<div class="log-entry log-bob"><b>Bob:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }

function shortenHex(h) {
  if (!h) return '';
  return h.length > 20 ? h.slice(0, 10) + '…' + h.slice(-6) : h;
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function startProtocol(choice) {
  const m0 = parseInt(m0Inp.value, 10);
  const m1 = parseInt(m1Inp.value, 10);
  if (isNaN(m0) || isNaN(m1) || m0 < 0 || m1 < 0) {
    alert('Please enter non-negative integer messages.');
    return;
  }

  btnC0.disabled = true;
  btnC1.disabled = true;
  chatLog.innerHTML = '';
  cheatRow.style.display = 'none';
  protocolReady = false;
  lastChoice = choice;

  logSys(`Starting OT protocol. Bob chooses b = ${choice}.`);

  try {
    // 1. Alice publishes (m0, m1) onto the demo state.
    await Backend.pa18DemoSetup(m0, m1);
    logAlice(`I have m0=${m0}, m1=${m1} loaded into the protocol state.`);

    // 2. Receiver picks b and sends pk_0, pk_1 (only sk for pk_b is known).
    await delay(500);
    const step1 = await Backend.pa18DemoStep1(choice);
    logBob(`I generated (pk0, pk1). Only sk_${choice} is mine; pk_${1 - choice} is a uniform group element with no trapdoor.`);
    logBob(`pk0.h = ${shortenHex(step1.pk0_h)}`);
    logBob(`pk1.h = ${shortenHex(step1.pk1_h)}`);
    logBob('Sending (pk0, pk1) to Alice…');

    // 3. Sender encrypts m0 under pk0 and m1 under pk1.
    await delay(700);
    const step2 = await Backend.pa18DemoStep2();
    logAlice(`Received (pk0, pk1). I cannot tell which key Bob holds the trapdoor for.`);
    logAlice(`c0 = Enc(pk0, m0) = (${shortenHex(step2.c0_c1)}, ${shortenHex(step2.c0_c2)})`);
    logAlice(`c1 = Enc(pk1, m1) = (${shortenHex(step2.c1_c1)}, ${shortenHex(step2.c1_c2)})`);
    logAlice('Sending (c0, c1) back to Bob…');

    // 4. Receiver decrypts c_b with sk_b.
    await delay(700);
    const step3 = await Backend.pa18DemoStep3();
    logBob(`Decrypting c${choice} with sk_${choice}…`);
    logBob(`<b>Recovered m_${choice} = ${step3.got}</b> ${step3.correct ? '✓' : '✗'}`);

    logSys(`OT complete. Bob learned m_${choice} only; Alice learned nothing about Bob's choice.`);
    cheatRow.style.display = 'block';
    protocolReady = true;
  } catch (e) {
    logSys(`Error: ${e.message}`);
  } finally {
    btnC0.disabled = false;
    btnC1.disabled = false;
  }
}

btnC0.addEventListener('click', () => startProtocol(0));
btnC1.addEventListener('click', () => startProtocol(1));

btnCheat.addEventListener('click', async () => {
  if (!protocolReady) return;
  const other = 1 - lastChoice;
  logBob(`<i>Trying to brute-force log_g(fake_h) so I can decrypt c${other}…</i>`);

  try {
    const res = await Backend.pa18DemoCheat();
    if (res.recovered) {
      logSys(`Cheat succeeded in ${res.iters} iters (${res.time_s}s) — only because q is tiny in the demo group.`);
      logBob(`Recovered m_${other} = ${res.recovered_message} (matches truth: ${res.matches_truth}).`);
      logSys('In a real-world 2048-bit group this loop is 2^2048 iterations — sender privacy reduces to DLP.');
    } else {
      logSys(`Cheat failed after ${res.iters} iterations (${res.time_s}s): DLP brute force exceeded the cap.`);
      logSys('Sender privacy holds: recovering m_{1-b} is exactly as hard as solving DLP in the group.');
    }
  } catch (e) {
    logSys(`Error: ${e.message}`);
  }
});
