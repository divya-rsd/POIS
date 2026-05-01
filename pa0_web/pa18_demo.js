const btnC0 = document.getElementById('btn-c0');
const btnC1 = document.getElementById('btn-c1');
const btnCheat = document.getElementById('btn-cheat');
const cheatRow = document.getElementById('cheat-row');
const chatLog = document.getElementById('chat-log');

const m0Inp = document.getElementById('alice-m0');
const m1Inp = document.getElementById('alice-m1');

let lastSession = null;
let lastChoice = -1;

function logSys(msg) { chatLog.innerHTML += `<div class="log-entry log-sys">${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logAlice(msg) { chatLog.innerHTML += `<div class="log-entry log-alice"><b>Alice:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logBob(msg) { chatLog.innerHTML += `<div class="log-entry log-bob"><b>Bob:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }

async function startProtocol(choice) {
  const m0 = m0Inp.value;
  const m1 = m1Inp.value;
  if(!m0 || !m1) return;
  
  btnC0.disabled = true; btnC1.disabled = true;
  chatLog.innerHTML = '';
  cheatRow.style.display = 'none';
  lastChoice = choice;
  
  logSys(`Starting OT protocol. Bob chooses b = ${choice}.`);
  
  try {
    const res = await Backend.pa18Ot(m0, m1, choice);
    lastSession = res;
    
    // Simulate interactive flow
    logBob(`I generated two public keys (pk0, pk1). I only know the secret key for pk${choice}.`);
    setTimeout(() => {
      logBob(`Sending pk0 and pk1 to Alice...`);
      setTimeout(() => {
        logAlice(`Received pk0 and pk1. I don't know which one you have the secret key for.`);
        logAlice(`Encrypting m0 under pk0 -> ct0`);
        logAlice(`Encrypting m1 under pk1 -> ct1`);
        logAlice(`Sending (ct0, ct1) back to Bob...`);
        
        setTimeout(() => {
          logBob(`Received ciphertexts. Decrypting ct${choice}...`);
          logBob(`<b>Decrypted Message: ${res.m_chosen}</b>`);
          
          logSys(`OT complete. Bob learned m${choice}, Alice learned nothing about Bob's choice.`);
          cheatRow.style.display = 'block';
          
          btnC0.disabled = false; btnC1.disabled = false;
        }, 800);
      }, 800);
    }, 800);
    
  } catch(e) {
    logSys(`Error: ${e.message}`);
    btnC0.disabled = false; btnC1.disabled = false;
  }
}

btnC0.addEventListener('click', () => startProtocol(0));
btnC1.addEventListener('click', () => startProtocol(1));

btnCheat.addEventListener('click', async () => {
  if(!lastSession) return;
  const other = 1 - lastChoice;
  logBob(`<i>Attempting to cheat... I will try to decrypt ct${other} to get m${other} without the secret key.</i>`);
  
  setTimeout(() => {
    logSys(`Cheat Failed. Bob's decryption of ct${other} yields garbage: `);
    // simulate garbage
    const garbage = Array.from({length: 16}, () => Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join('');
    logBob(`Result: ${garbage}`);
    logSys(`Semantic security of the underlying public key encryption prevents Bob from learning the unchosen message.`);
  }, 1000);
});
