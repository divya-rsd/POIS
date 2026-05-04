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

function shorten(hex) {
  if (!hex) return '';
  return hex.length > 24 ? hex.slice(0, 12) + '…' + hex.slice(-8) : hex;
}

document.getElementById('btn-enc').addEventListener('click', async () => {
  const m = msgInp.value;
  if (!m) return;

  cpaDecBox.value = '';
  ccaDecBox.value = '';
  ccaStatus.style.display = 'none';

  try {
    // pa17/encrypt returns BOTH plain ElGamal (CPA) and signcrypt (CCA) ciphertexts
    // computed under the same receiver key, so the comparison is apples-to-apples.
    const res = await Backend.pa17Encrypt(m);

    currentCpa = { c1: res.plain_c1, c2: res.plain_c2 };
    cpaCtBox.textContent = `c1: ${shorten(res.plain_c1)}\nc2: ${shorten(res.plain_c2)}`;

    currentCca = { c1: res.c1, c2: res.c2, sig: res.sig };
    ccaCtBox.textContent =
      `c1:  ${shorten(res.c1)}\n` +
      `c2:  ${shorten(res.c2)}\n` +
      `sig: ${shorten(res.sig)}`;

    // Honest decrypt under signcrypt: signature still valid → recovers m
    const dec = await Backend.pa17DecryptSigncrypt(res.c1, res.c2, res.sig);
    ccaStatus.style.display = 'block';
    if (dec.dec === 'Invalid Signature' || dec.dec === null) {
      ccaStatus.className = 'status err';
      ccaStatus.textContent = 'REJECTED: Invalid Signature.';
      ccaDecBox.value = '---';
    } else {
      ccaStatus.className = 'status ok';
      ccaStatus.textContent = 'Decrypted successfully.';
      ccaDecBox.value = dec.dec;
    }
  } catch (e) {
    alert('Encryption failed: ' + e.message);
  }
});

document.getElementById('btn-mal-cpa').addEventListener('click', async () => {
  if (!currentCpa) return;
  const k = cpaKInp.value;
  if (!k) return;

  try {
    const resMal = await Backend.pa16Malleate(currentCpa.c1, currentCpa.c2, k);
    cpaCtBox.textContent = `c1: ${shorten(resMal.c1)}\nc2: ${shorten(resMal.c2)} (tampered)`;

    const resDec = await Backend.pa17DecryptElgamal(resMal.c1, resMal.c2);
    cpaDecBox.value = resDec.dec;
  } catch (e) {
    cpaDecBox.value = 'Error: ' + e.message;
  }
});

document.getElementById('btn-mal-cca').addEventListener('click', async () => {
  if (!currentCca) return;
  const k = ccaKInp.value;
  if (!k) return;

  try {
    // Mauler tampers c2 but cannot re-sign — sig still binds the original (c1, c2).
    const resMal = await Backend.pa16Malleate(currentCca.c1, currentCca.c2, k);
    ccaCtBox.textContent =
      `c1:  ${shorten(resMal.c1)}\n` +
      `c2:  ${shorten(resMal.c2)} (tampered)\n` +
      `sig: ${shorten(currentCca.sig)}`;

    const resDec = await Backend.pa17DecryptSigncrypt(resMal.c1, resMal.c2, currentCca.sig);

    ccaStatus.style.display = 'block';
    if (resDec.dec === 'Invalid Signature' || resDec.dec === null) {
      ccaStatus.className = 'status err';
      ccaStatus.textContent = 'REJECTED: Invalid Signature. Malleability attack thwarted.';
      ccaDecBox.value = '---';
    } else {
      ccaStatus.className = 'status ok';
      ccaStatus.textContent = 'Decrypted successfully.';
      ccaDecBox.value = resDec.dec;
    }
  } catch (e) {
    ccaDecBox.value = 'Error: ' + e.message;
  }
});
