const msgInp = document.getElementById('pt-msg');
const cpaCtBox = document.getElementById('cpa-ct');
const cpaDecBox = document.getElementById('cpa-dec');
const cpaKInp = document.getElementById('cpa-k');

const ccaCtBox = document.getElementById('cca-ct');
const ccaDecBox = document.getElementById('cca-dec');
const ccaKInp = document.getElementById('cca-k');
const ccaStatus = document.getElementById('cca-status');

let currentCpa = null;
let currentCca = null;

document.getElementById('btn-enc').addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m) return;
  
  cpaDecBox.value = '';
  ccaDecBox.value = '';
  ccaStatus.style.display = 'none';
  
  try {
    // 1. CPA (Plain ElGamal)
    const resCpa = await Backend.pa16Encrypt(m);
    currentCpa = { c1: res.c1, c2: res.c2 };
    cpaCtBox.textContent = `c1: ${resCpa.c1}\nc2: ${resCpa.c2}`;
    
    // 2. CCA (Encrypt-then-Sign)
    const resCca = await Backend.pa17CcaEncrypt(m);
    currentCca = { c1: resCca.c1, c2: resCca.c2, sig: resCca.sig };
    ccaCtBox.textContent = `c1: ${resCca.c1}\nc2: ${resCca.c2}\nsig: ${resCca.sig.substring(0,20)}...`;
    
  } catch(e) {
    alert("Encryption failed: " + e.message);
  }
});

document.getElementById('btn-mal-cpa').addEventListener('click', async () => {
  if(!currentCpa) return;
  const k = cpaKInp.value;
  if(!k) return;
  
  try {
    // Malleate
    const resMal = await Backend.pa16Malleate(currentCpa.c1, currentCpa.c2, k);
    cpaCtBox.textContent = `c1: ${resMal.c1}\nc2: ${resMal.c2} (tampered)`;
    
    // Decrypt
    const resDec = await Backend.pa16Decrypt(resMal.c1, resMal.c2);
    cpaDecBox.value = resDec.m;
  } catch(e) {
    cpaDecBox.value = "Error: " + e.message;
  }
});

document.getElementById('btn-mal-cca').addEventListener('click', async () => {
  if(!currentCca) return;
  const k = ccaKInp.value;
  if(!k) return;
  
  try {
    // Malleate ciphertext (signature stays same, meaning it will be invalid for new CT)
    const resMal = await Backend.pa16Malleate(currentCca.c1, currentCca.c2, k);
    ccaCtBox.textContent = `c1: ${resMal.c1}\nc2: ${resMal.c2} (tampered)\nsig: ${currentCca.sig.substring(0,20)}...`;
    
    // Decrypt
    const resDec = await Backend.pa17CcaDecrypt(resMal.c1, resMal.c2, currentCca.sig);
    
    ccaStatus.style.display = 'block';
    if(resDec.valid) {
      ccaStatus.className = 'status ok';
      ccaStatus.textContent = 'Decrypted successfully.';
      ccaDecBox.value = resDec.m;
    } else {
      ccaStatus.className = 'status err';
      ccaStatus.textContent = 'REJECTED: Invalid Signature. Malleability attack thwarted.';
      ccaDecBox.value = '---';
    }
  } catch(e) {
    ccaDecBox.value = "Error: " + e.message;
  }
});
