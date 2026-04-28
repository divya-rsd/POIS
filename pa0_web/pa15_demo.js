const msgInp = document.getElementById('sig-msg');
const modeSel = document.getElementById('sig-mode');
const sigOut = document.getElementById('sig-out');
const verifyStatus = document.getElementById('verify-status');

let currentSig = null;

document.getElementById('btn-sign').addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m) return;
  
  verifyStatus.style.display = 'none';
  sigOut.textContent = 'Signing...';
  
  try {
    const res = await Backend.pa15Sign(m, modeSel.value);
    currentSig = res.sig;
    sigOut.textContent = currentSig;
  } catch(e) {
    sigOut.textContent = "Error: " + e.message;
  }
});

function flipHexBit(hex) {
  if(!hex) return hex;
  let lastChar = hex[hex.length-1];
  let val = parseInt(lastChar, 16);
  val = val ^ 1;
  return hex.substring(0, hex.length-1) + val.toString(16);
}

document.getElementById('btn-flip-sig').addEventListener('click', () => {
  if(!currentSig) return;
  currentSig = flipHexBit(currentSig);
  sigOut.textContent = currentSig;
  verifyStatus.style.display = 'none';
});

document.getElementById('btn-flip-msg').addEventListener('click', () => {
  if(!msgInp.value) return;
  // change last character
  let chars = msgInp.value.split('');
  let c = chars[chars.length-1].charCodeAt(0);
  chars[chars.length-1] = String.fromCharCode(c ^ 1);
  msgInp.value = chars.join('');
  verifyStatus.style.display = 'none';
});

document.getElementById('btn-verify').addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m || !currentSig) return;
  
  try {
    const res = await Backend.pa15Verify(m, currentSig, modeSel.value);
    
    verifyStatus.style.display = 'block';
    if(res.valid) {
      verifyStatus.className = 'status ok';
      verifyStatus.textContent = 'SIGNATURE VALID: The document is authentic and has not been tampered with.';
    } else {
      verifyStatus.className = 'status err';
      verifyStatus.textContent = 'SIGNATURE INVALID: Verification failed! The signature or document was tampered with.';
    }
  } catch(e) {
    verifyStatus.style.display = 'block';
    verifyStatus.className = 'status err';
    verifyStatus.textContent = 'Error: ' + e.message;
  }
});
