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

btnEval.addEventListener('click', async () => {
  btnEval.disabled = true;
  chatLog.innerHTML = '';
  statusDiv.style.display = 'none';
  
  logSys(`Starting Secure AND evaluation...`);
  
  try {
    const res = await Backend.pa19And(aliceBit, bobBit);
    
    // Simulate steps
    logAlice(`I have my bit x. I'm generating a random share s_a = ${res.alice_share}.`);
    logAlice(`My secret is x = ${aliceBit}. I prepare a truth table for OT:`);
    logAlice(`T[0][0] = (0 AND 0) ⊕ ${res.alice_share} = ${res.T[0][0]}`);
    logAlice(`T[0][1] = (0 AND 1) ⊕ ${res.alice_share} = ${res.T[0][1]}`);
    logAlice(`T[1][0] = (1 AND 0) ⊕ ${res.alice_share} = ${res.T[1][0]}`);
    logAlice(`T[1][1] = (1 AND 1) ⊕ ${res.alice_share} = ${res.T[1][1]}`);
    
    setTimeout(() => {
      logBob(`I have my bit y = ${bobBit}. I act as the receiver in a 1-out-of-4 Oblivious Transfer.`);
      logBob(`I request the element at (x=${aliceBit}, y=${bobBit})... wait, I don't know x! I request row x from Alice using OT.`);
      
      setTimeout(() => {
        logSys(`Oblivious Transfer executes...`);
        logBob(`I received my share s_b = ${res.bob_share} from the OT.`);
        
        setTimeout(() => {
          logSys(`Both parties now hold random shares of the result.`);
          logAlice(`My final share: ${res.alice_share}`);
          logBob(`My final share: ${res.bob_share}`);
          
          const result = res.alice_share ^ res.bob_share;
          logSys(`Reconstructing output: s_a ⊕ s_b = ${res.alice_share} ⊕ ${res.bob_share} = ${result}`);
          
          statusDiv.style.display = 'block';
          statusDiv.className = 'status ok';
          statusDiv.textContent = `RESULT: ${aliceBit} AND ${bobBit} = ${result}`;
          
          btnEval.disabled = false;
        }, 1000);
      }, 1000);
    }, 1000);
    
  } catch(e) {
    logSys(`Error: ${e.message}`);
    btnEval.disabled = false;
  }
});
