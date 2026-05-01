const msgInp = document.getElementById('hastad-m');
const pkcsChk = document.getElementById('hastad-pkcs');
const btnBc = document.getElementById('btn-broadcast');

const n1Box = document.getElementById('hastad-n1');
const c1Box = document.getElementById('hastad-c1');
const n2Box = document.getElementById('hastad-n2');
const c2Box = document.getElementById('hastad-c2');
const n3Box = document.getElementById('hastad-n3');
const c3Box = document.getElementById('hastad-c3');

const xBox = document.getElementById('hastad-x');
const mBox = document.getElementById('hastad-recover');
const statusBox = document.getElementById('hastad-status');

function clearBoxes() {
  [n1Box, c1Box, n2Box, c2Box, n3Box, c3Box, xBox, mBox].forEach(b => b.textContent = '');
  statusBox.style.display = 'none';
}

btnBc.addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m) return;
  
  btnBc.disabled = true;
  clearBoxes();
  xBox.textContent = 'Calculating...';
  
  try {
    const usePad = pkcsChk.checked;
    const res = await Backend.pa14Hastad(m, usePad);
    
    n1Box.textContent = res.N1; c1Box.textContent = res.c1;
    n2Box.textContent = res.N2; c2Box.textContent = res.c2;
    n3Box.textContent = res.N3; c3Box.textContent = res.c3;
    
    // Simulate some "computation time" for the visualizer
    setTimeout(() => {
      xBox.textContent = res.x;
      
      setTimeout(() => {
        statusBox.style.display = 'block';
        if(res.success) {
          mBox.textContent = res.m_recovered;
          statusBox.className = 'status err';
          statusBox.textContent = 'ATTACK SUCCESS: Eve recovered the message using the integer cube root of x.';
        } else {
          mBox.textContent = "Cube root failed to produce a valid string.";
          statusBox.className = 'status ok';
          statusBox.textContent = 'ATTACK FAILED: PKCS#1 v1.5 padding randomized the messages, so c_i are NOT encryptions of the same integer. The cube root of x is meaningless.';
        }
      }, 800);
    }, 800);
    
  } catch(e) {
    statusBox.style.display = 'block';
    statusBox.className = 'status err';
    statusBox.textContent = 'Error: ' + e.message;
  }
  
  btnBc.disabled = false;
});
