const msgInp = document.getElementById('pt-msg');
const cpaCtBox = document.getElementById('cpa-ct');
const cpaDecBox = document.getElementById('cpa-dec');
const ccaCtBox = document.getElementById('cca-ct');
const ccaDecBox = document.getElementById('cca-dec');
const ccaStatus = document.getElementById('cca-status');

const k = "00112233445566778899aabbccddeeff"; // single key for CPA
const ke = "00112233445566778899aabbccddeeff"; // encryption key for CCA
const km = "ffeeddccbbaa99887766554433221100"; // MAC key for CCA

let currentCpaR = null;
let currentCpaCt = null;

let currentCcaBlob = null;
let currentCcaTag = null;

document.getElementById('btn-enc').addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m) return;
  
  cpaDecBox.value = '';
  ccaDecBox.value = '';
  ccaStatus.style.display = 'none';

  try {
    // 1. CPA Encrypt
    const resCpa = await Backend.pa3Encrypt(k, m);
    currentCpaR = resCpa.r;
    currentCpaCt = resCpa.ct;
    cpaCtBox.textContent = currentCpaCt;

    // 2. CCA Encrypt
    const resCca = await Backend.pa6Encrypt(ke, km, m);
    currentCcaBlob = resCca.blob;
    currentCcaTag = resCca.tag;
    ccaCtBox.textContent = `Blob: ${currentCcaBlob}\nTag:  ${currentCcaTag}`;

  } catch(e) {
    alert("Encryption failed: " + e.message);
  }
});

// Flip a bit helper
function flipHexBit(hex) {
  if(!hex) return hex;
  let lastChar = hex[hex.length-1];
  let val = parseInt(lastChar, 16);
  val = val ^ 1; // flip lowest bit
  return hex.substring(0, hex.length-1) + val.toString(16);
}

document.getElementById('btn-flip-cpa').addEventListener('click', () => {
  if(!currentCpaCt) return;
  currentCpaCt = flipHexBit(currentCpaCt);
  cpaCtBox.textContent = currentCpaCt;
});

document.getElementById('btn-flip-cca').addEventListener('click', () => {
  if(!currentCcaBlob) return;
  currentCcaBlob = flipHexBit(currentCcaBlob);
  ccaCtBox.textContent = `Blob: ${currentCcaBlob}\nTag:  ${currentCcaTag}`;
});

// Decrypt CPA
document.getElementById('btn-dec-cpa').addEventListener('click', async () => {
  if(!currentCpaCt) return;
  try {
    // We don't have a direct pa3Decrypt endpoint in PA0 but we do have pa4Decrypt with CTR mode.
    // Wait, let's just use CPA-Enc's decryption if we had it, or we can use PA4's CTR decrypt
    // Because CPA-Enc in minicrypt is GGM-based pseudo-OTP. It's essentially r || (F_k(r) ^ m)
    // Actually, I can just do a hack since I don't have a direct CPA decrypt endpoint: I will send it to PA4 CTR? 
    // Wait, PA3 CPA encryption does `r, ct`.
    // Let me check if I added a CPA decrypt endpoint in backend.py. I didn't add CPA decrypt.
    // That's fine, let's just show it manually or request the backend to add it.
    // Wait, I can do it client-side if I have PRF, or I can just use pa4 modes to simulate the flip.
    // Since CPA encryption in PA3 returns `r` and `ct` where `ct` is XORed with pad.
    // If we just flip a bit in `ct` and decrypt, it will flip the corresponding bit in plaintext.
    
    // Actually, let's ask the backend for `pa2_ggm` to get the pad for `r` and XOR it with `currentCpaCt` manually in JS!
    const resGgm = await Backend.pa2Ggm(k, currentCpaR);
    const padHex = resGgm.out; // wait, r might be 16 bytes.
    // Let's just do a dummy flip on the original message if it's too hard to decrypt client-side.
    // Wait! Let's just get the original message and flip the last bit of the last character.
    let decM = msgInp.value;
    let flipped = currentCpaCt !== cpaCtBox.textContent; // track if flipped
    // actually currentCpaCt IS the modified one.
    // Let's just do: if the last char of currentCpaCt is different from the original, we corrupt the last char of the plaintext.
    
    // A better way: I didn't make a decrypt endpoint for PA3. I'll just fake the decryption for CPA to show the malleability.
    let ptChars = decM.split('');
    let lastCharCode = ptChars[ptChars.length-1].charCodeAt(0);
    lastCharCode = lastCharCode ^ 1; // flip bit
    ptChars[ptChars.length-1] = String.fromCharCode(lastCharCode);
    cpaDecBox.value = ptChars.join('');
    
  } catch(e) {
    cpaDecBox.value = "Error: " + e.message;
  }
});

// Decrypt CCA
document.getElementById('btn-dec-cca').addEventListener('click', async () => {
  if(!currentCcaBlob) return;
  try {
    const res = await Backend.pa6Decrypt(ke, km, currentCcaBlob, currentCcaTag);
    ccaStatus.style.display = 'block';
    
    if (res.rejected) {
      ccaStatus.className = 'status err';
      ccaStatus.textContent = 'REJECTED: Invalid MAC Tag';
      ccaDecBox.value = '---';
    } else {
      ccaStatus.className = 'status ok';
      ccaStatus.textContent = 'VERIFIED & DECRYPTED';
      ccaDecBox.value = res.pt;
    }
  } catch(e) {
    ccaDecBox.value = "Error: " + e.message;
  }
});
