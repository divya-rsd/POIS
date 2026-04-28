const mInp = document.getElementById('elg-m');
const kInp = document.getElementById('elg-k');
const aliceCt = document.getElementById('alice-ct');
const eveCt = document.getElementById('eve-ct');
const bobDec = document.getElementById('bob-dec');
const statusDiv = document.getElementById('elg-status');

let currentCt = null;
let currentIsForged = false;

document.getElementById('btn-enc').addEventListener('click', async () => {
  const m = mInp.value;
  if(!m) return;
  
  statusDiv.style.display = 'none';
  eveCt.textContent = '';
  bobDec.textContent = '';
  currentIsForged = false;
  
  try {
    const res = await Backend.pa16Encrypt(m);
    currentCt = { c1: res.c1, c2: res.c2 };
    aliceCt.textContent = `c1: ${currentCt.c1}\nc2: ${currentCt.c2}`;
  } catch(e) {
    aliceCt.textContent = "Error: " + e.message;
  }
});

document.getElementById('btn-mal').addEventListener('click', async () => {
  if(!currentCt) return;
  const k = kInp.value;
  if(!k) return;
  
  statusDiv.style.display = 'none';
  bobDec.textContent = '';
  
  try {
    const res = await Backend.pa16Malleate(currentCt.c1, currentCt.c2, k);
    currentCt = { c1: res.c1, c2: res.c2 };
    currentIsForged = true;
    eveCt.textContent = `c1: ${currentCt.c1}\nc2': ${currentCt.c2}`;
  } catch(e) {
    eveCt.textContent = "Error: " + e.message;
  }
});

document.getElementById('btn-dec').addEventListener('click', async () => {
  if(!currentCt) return;
  
  try {
    const res = await Backend.pa16Decrypt(currentCt.c1, currentCt.c2);
    bobDec.textContent = res.m;
    
    statusDiv.style.display = 'block';
    if(currentIsForged) {
      statusDiv.className = 'status err';
      statusDiv.textContent = `MALLEABILITY EXPLOITED: Eve successfully modified the ciphertext so it decrypts to m * ${kInp.value} = ${res.m} without knowing the private key!`;
    } else {
      statusDiv.className = 'status ok';
      statusDiv.textContent = 'Decryption successful. No tampering detected (ElGamal cannot detect tampering).';
    }
  } catch(e) {
    bobDec.textContent = "Error: " + e.message;
  }
});
