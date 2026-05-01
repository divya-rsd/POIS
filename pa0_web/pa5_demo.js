const tabs = document.querySelectorAll('.tab');
tabs.forEach(t => {
  t.addEventListener('click', () => {
    tabs.forEach(tb => tb.classList.remove('active'));
    t.classList.add('active');
    const tabId = t.getAttribute('data-tab');
    document.getElementById('tab-eufcma').style.display = tabId === 'eufcma' ? 'block' : 'none';
    document.getElementById('tab-lenext').style.display = tabId === 'lenext' ? 'block' : 'none';
  });
});

const k = "112233445566778899aabbccddeeff00"; // static 16-byte key for demo

// EUF-CMA
let oracleQueries = [];
document.getElementById('btn-gen-oracle').addEventListener('click', async () => {
  const list = document.getElementById('mac-list');
  list.innerHTML = '';
  oracleQueries = [];
  
  for(let i=0; i<50; i++) {
    let msg = "msg_" + Math.random().toString(36).substring(7);
    try {
      const res = await Backend.pa5PrfMac(k, msg);
      oracleQueries.push({m: msg, tag: res.tag});
      
      const item = document.createElement('div');
      item.className = 'mac-item';
      item.innerHTML = `<span>${msg}</span><span style="color:var(--accent)">${res.tag}</span>`;
      list.appendChild(item);
    } catch(e) {}
  }
});

document.getElementById('btn-forge').addEventListener('click', async () => {
  const fm = document.getElementById('forgery-msg').value.trim();
  const ft = document.getElementById('forgery-tag').value.trim();
  const resBox = document.getElementById('forge-res');
  
  if(!fm || !ft) return;
  
  // check if in oracle
  if(oracleQueries.some(q => q.m === fm)) {
    resBox.style.display = 'block';
    resBox.className = 'status err';
    resBox.textContent = "Invalid forgery: Message was queried to the oracle.";
    return;
  }
  
  try {
    const res = await Backend.pa5PrfMac(k, fm);
    const valid = (res.tag.toLowerCase() === ft.toLowerCase());
    resBox.style.display = 'block';
    if(valid) {
      resBox.className = 'status ok';
      resBox.textContent = "Forgery SUCCESS! You broke EUF-CMA.";
    } else {
      resBox.className = 'status err';
      resBox.textContent = `Forgery FAILED. Expected ${res.tag}`;
    }
  } catch(e) {
    resBox.style.display = 'block';
    resBox.className = 'status err';
    resBox.textContent = "Error verifying: " + e.message;
  }
});

// Length-Extension (CBC-MAC)
document.getElementById('btn-le-mac').addEventListener('click', async () => {
  const m = document.getElementById('le-m').value;
  try {
    // PAD TO 16 for demo simplicity
    let padM = m.padEnd(16, '\0');
    const res = await Backend.pa5CbcMac(k, padM);
    document.getElementById('le-t').value = res.tag;
  } catch(e) {
    alert(e.message);
  }
});

document.getElementById('btn-le-forge').addEventListener('click', async () => {
  const m = document.getElementById('le-m').value.padEnd(16, '\0');
  const tHex = document.getElementById('le-t').value;
  const appendM = document.getElementById('le-append').value.padEnd(16, '\0');
  
  if(!tHex) { alert("Get original tag first"); return; }
  
  // The attack: to forge MAC for (m || x), we just need to MAC(t XOR x) under the same key.
  // We can simulate this by asking the backend to CBC-MAC (t XOR x)
  
  // 1. Convert t and x to bytes
  let tBytes = [];
  for(let i=0; i<tHex.length; i+=2) tBytes.push(parseInt(tHex.substring(i,i+2), 16));
  
  let xBytes = new TextEncoder().encode(appendM);
  let xorBytes = new Uint8Array(16);
  for(let i=0; i<16; i++) xorBytes[i] = tBytes[i] ^ xBytes[i];
  
  // We need to send this to the backend as the string/bytes
  let xorStr = new TextDecoder("latin1").decode(xorBytes);
  
  try {
    // The forged tag is just CBC-MAC of (t XOR x)
    const resForge = await Backend.pa5CbcMac(k, xorStr);
    document.getElementById('le-forge-t').value = resForge.tag;
    
    // Verify it is actually the valid tag for m || appendM
    const resReal = await Backend.pa5CbcMac(k, m + appendM);
    
    const verBox = document.getElementById('le-verify-res');
    verBox.style.display = 'block';
    if(resReal.tag === resForge.tag) {
      verBox.className = 'status ok';
      verBox.textContent = "Length-extension successful! Forged tag matches the actual CBC-MAC of the concatenated message.";
    } else {
      verBox.className = 'status err';
      verBox.textContent = "Length-extension failed. Check padding/logic.";
    }
    
  } catch(e) {
    alert(e.message);
  }
});
