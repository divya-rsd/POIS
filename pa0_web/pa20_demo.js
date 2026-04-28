const aliceW = document.getElementById('alice-w');
const bobW = document.getElementById('bob-w');
const btnEval = document.getElementById('btn-eval');
const chatLog = document.getElementById('chat-log');
const statusDiv = document.getElementById('mpc-status');

function logSys(msg) { chatLog.innerHTML += `<div class="log-entry log-sys">${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logAlice(msg) { chatLog.innerHTML += `<div class="log-entry log-alice"><b>Alice:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logBob(msg) { chatLog.innerHTML += `<div class="log-entry log-bob"><b>Bob:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }

btnEval.addEventListener('click', async () => {
  const a = parseInt(aliceW.value, 10);
  const b = parseInt(bobW.value, 10);
  
  if(isNaN(a) || isNaN(b) || a < 0 || a > 15 || b < 0 || b > 15) {
    alert("Please enter values between 0 and 15.");
    return;
  }
  
  btnEval.disabled = true;
  chatLog.innerHTML = '';
  statusDiv.style.display = 'none';
  
  logSys(`Starting Yao's Millionaires' Protocol for values A=${a}, B=${b} (max 4-bits)`);
  
  try {
    const res = await Backend.pa20Millionaire(a, b);
    
    // Simulate steps
    logAlice(`I generated a Garbled Circuit for the function (A > B).`);
    logAlice(`I encode my input A=${a} into wire labels.`);
    
    setTimeout(() => {
      logAlice(`Sending Garbled Circuit and my encoded inputs to Bob...`);
      
      setTimeout(() => {
        logBob(`Received circuit. Now I need the wire labels for my input B=${b}.`);
        logBob(`Initiating Oblivious Transfer to securely retrieve my labels from Alice without revealing B...`);
        
        setTimeout(() => {
          logSys(`OT complete. Bob has his labels.`);
          logBob(`Evaluating the Garbled Circuit using the provided labels...`);
          
          setTimeout(() => {
            logSys(`Circuit evaluation complete.`);
            logBob(`The result output label corresponds to: ${res.alice_is_richer ? 'True' : 'False'}`);
            
            statusDiv.style.display = 'block';
            statusDiv.className = 'status ok';
            if (res.alice_is_richer) {
              statusDiv.textContent = `RESULT: Alice is richer! (${a} > ${b})`;
            } else {
              statusDiv.textContent = `RESULT: Bob is richer (or equal)! (${a} <= ${b})`;
            }
            
            btnEval.disabled = false;
          }, 1000);
        }, 1000);
      }, 1000);
    }, 1000);
    
  } catch(e) {
    logSys(`Error: ${e.message}`);
    btnEval.disabled = false;
  }
});
