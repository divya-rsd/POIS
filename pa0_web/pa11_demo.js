const chkMitm = document.getElementById('dh-mitm');
const evePanel = document.getElementById('panel-eve');
const btnExchange = document.getElementById('btn-exchange');
const statusDiv = document.getElementById('dh-status');

// Alice fields
const aA = document.getElementById('alice-A');
const aRec = document.getElementById('alice-rec');
const aK = document.getElementById('alice-K');

// Bob fields
const bB = document.getElementById('bob-B');
const bRec = document.getElementById('bob-rec');
const bK = document.getElementById('bob-K');

// Eve fields
const eRecA = document.getElementById('eve-rec-A');
const eRecB = document.getElementById('eve-rec-B');
const eSent = document.getElementById('eve-sent');

// Arrows
const arrTop = document.getElementById('arr-top');
const arrBot = document.getElementById('arr-bot');

chkMitm.addEventListener('change', () => {
  evePanel.style.display = chkMitm.checked ? 'flex' : 'none';
  clearFields();
});

function clearFields() {
  [aA, aRec, aK, bB, bRec, bK, eRecA, eRecB, eSent].forEach(el => el.textContent = '');
  arrTop.classList.remove('show');
  arrBot.classList.remove('show');
  statusDiv.style.display = 'none';
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

btnExchange.addEventListener('click', async () => {
  clearFields();
  btnExchange.disabled = true;
  const isMitm = chkMitm.checked;

  try {
    const res = await Backend.pa11Dh(isMitm);
    
    // Step 1: Generate Public Keys
    aA.textContent = res.A;
    bB.textContent = res.B;
    
    await sleep(600);
    arrTop.classList.add('show');
    arrBot.classList.add('show');
    await sleep(600);
    
    // Step 2: Receive & MITM logic
    if (isMitm) {
      eRecA.textContent = res.A;
      eRecB.textContent = res.B;
      eSent.textContent = `E_A: ${res.E_A}\nE_B: ${res.E_B}`;
      
      await sleep(800);
      aRec.textContent = res.E_B; // Alice gets Eve's fake B
      bRec.textContent = res.E_A; // Bob gets Eve's fake A
      
    } else {
      aRec.textContent = res.B;
      bRec.textContent = res.A;
    }
    
    await sleep(800);
    
    // Step 3: Compute Secret
    aK.textContent = res.Ka;
    bK.textContent = res.Kb;
    
    statusDiv.style.display = 'block';
    if (isMitm) {
      statusDiv.className = 'status err';
      statusDiv.textContent = 'MITM SUCCESS: Alice and Bob computed different secrets, both shared with Eve instead of each other!';
    } else {
      statusDiv.className = 'status ok';
      statusDiv.textContent = 'EXCHANGE SUCCESS: Alice and Bob securely agreed on the same secret!';
    }
    
  } catch(e) {
    statusDiv.style.display = 'block';
    statusDiv.className = 'status err';
    statusDiv.textContent = 'Error: ' + e.message;
  }
  
  btnExchange.disabled = false;
});
