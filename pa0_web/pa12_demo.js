const tabs = document.querySelectorAll('.tab');
let activeMode = 'textbook';

tabs.forEach(t => {
  t.addEventListener('click', () => {
    tabs.forEach(tb => tb.classList.remove('active'));
    t.classList.add('active');
    activeMode = t.getAttribute('data-mode');
    
    document.getElementById('status-box').style.display = 'none';
    document.getElementById('box-c1').textContent = '';
    document.getElementById('box-c2').textContent = '';
    document.getElementById('padding-panel').style.display = 'none';
  });
});

const btnEnc = document.getElementById('btn-enc');
const statusBox = document.getElementById('status-box');
const boxC1 = document.getElementById('box-c1');
const boxC2 = document.getElementById('box-c2');
const padPanel = document.getElementById('padding-panel');
const padPs1 = document.getElementById('pad-ps1');
const padPs2 = document.getElementById('pad-ps2');
const inpMsg = document.getElementById('inp-msg');

btnEnc.addEventListener('click', async () => {
  const m = inpMsg.value;
  if(!m) return;
  
  btnEnc.disabled = true;
  statusBox.style.display = 'none';
  padPanel.style.display = 'none';
  
  try {
    const res = await Backend.pa12EncryptTwice(m, activeMode);
    
    boxC1.textContent = res.c1;
    boxC2.textContent = res.c2;
    
    statusBox.style.display = 'block';
    if(res.match) {
      statusBox.className = 'status err';
      statusBox.textContent = 'VULNERABLE: C1 and C2 are identical. The cipher is deterministic (not CPA secure).';
    } else {
      statusBox.className = 'status ok';
      statusBox.textContent = 'SECURE: C1 and C2 are completely different.';
      
      if(activeMode === 'pkcs') {
        padPanel.style.display = 'block';
        padPs1.textContent = res.ps1;
        padPs2.textContent = res.ps2;
      }
    }
  } catch(e) {
    statusBox.style.display = 'block';
    statusBox.className = 'status err';
    statusBox.textContent = 'Error: ' + e.message;
  }
  
  btnEnc.disabled = false;
});
