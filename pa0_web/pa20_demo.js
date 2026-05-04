const aliceW = document.getElementById('alice-w');
const bobW = document.getElementById('bob-w');
const btnEval = document.getElementById('btn-eval');
const chatLog = document.getElementById('chat-log');
const statusDiv = document.getElementById('mpc-status');

function logSys(msg) { chatLog.innerHTML += `<div class="log-entry log-sys">${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logAlice(msg) { chatLog.innerHTML += `<div class="log-entry log-alice"><b>Alice:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }
function logBob(msg) { chatLog.innerHTML += `<div class="log-entry log-bob"><b>Bob:</b> ${msg}</div>`; chatLog.scrollTop = chatLog.scrollHeight; }

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

btnEval.addEventListener('click', async () => {
  const a = parseInt(aliceW.value, 10);
  const b = parseInt(bobW.value, 10);

  if (isNaN(a) || isNaN(b) || a < 0 || a > 15 || b < 0 || b > 15) {
    alert('Please enter values between 0 and 15.');
    return;
  }

  btnEval.disabled = true;
  chatLog.innerHTML = '';
  statusDiv.style.display = 'none';

  logSys(`Starting 4-bit secure compare. A=${a}, B=${b} stay private.`);

  try {
    const res = await Backend.pa20Millionaires(a, b);

    logAlice('I build a boolean DAG that evaluates equality and greater-than over 4-bit inputs.');
    await delay(500);
    logBob('I receive my OT-based AND/XOR shares for each gate. No plaintext bit of B leaks.');
    await delay(500);

    const trace = Array.isArray(res.trace) ? res.trace : [];
    if (trace.length) {
      const summary = trace.reduce((acc, g) => {
        acc[g.op] = (acc[g.op] || 0) + 1;
        return acc;
      }, {});
      const parts = Object.keys(summary).map(k => `${k}=${summary[k]}`).join(', ');
      logSys(`Circuit executed ${trace.length} secure gates [${parts}].`);

      // Show the last few gates so the trace stays readable.
      trace.slice(-5).forEach(g => {
        logSys(`  gate ${g.op} (in=${JSON.stringify(g.inputs)}) → wire ${g.output_wire} = ${g.output_val}`);
      });
    }

    await delay(400);
    logSys(`Output reconstructed from secure gates: "${res.result}".`);

    statusDiv.style.display = 'block';
    statusDiv.className = 'status ok';
    if (res.result === 'Alice richer') {
      statusDiv.textContent = `RESULT: Alice is richer (${a} > ${b}).`;
    } else if (res.result === 'Bob richer') {
      statusDiv.textContent = `RESULT: Bob is richer (${a} < ${b}).`;
    } else {
      statusDiv.textContent = `RESULT: They are equal (${a} = ${b}).`;
    }
  } catch (e) {
    logSys(`Error: ${e.message}`);
  } finally {
    btnEval.disabled = false;
  }
});
