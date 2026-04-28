let currentState = null;

async function runEncrypt() {
    const m = parseInt(document.getElementById('inp-msg').value) || 1234;
    
    try {
        const res = await fetch('/api/pa17/encrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ m })
        });
        const data = await res.json();
        
        currentState = data;
        
        // Populate Signcrypt Panel
        document.getElementById('sc-c1').innerText = truncateHex(data.c1);
        document.getElementById('sc-c2').innerText = truncateHex(data.c2);
        document.getElementById('sc-sig').innerText = truncateHex(data.sig);
        document.getElementById('sc-out').style.display = 'block';
        document.getElementById('tamper-row').style.display = 'flex';
        document.getElementById('sc-dec-out').style.display = 'none';

        // Populate ElGamal Panel
        document.getElementById('eg-c1').innerText = truncateHex(data.plain_c1);
        document.getElementById('eg-c2').innerText = truncateHex(data.plain_c2);
        document.getElementById('eg-out').style.display = 'block';
        document.getElementById('eg-tamper-row').style.display = 'flex';
        document.getElementById('eg-dec-out').style.display = 'none';

    } catch(err) {
        alert("Error connecting to backend: " + err);
    }
}

function truncateHex(hexStr, chars=48) {
    if (!hexStr) return "";
    if (hexStr.length > chars) return hexStr.substring(0, chars) + "...";
    return hexStr;
}

// Tamper Functions - visually update the UI and state
function tamperSigncrypt() {
    if(!currentState) return;
    // Simulate multiplying c2 by 2 by appending a visual marker or just changing the last char to show modification
    // Since c2 is a hex string, to properly do c2*2 we'd need bigint math, but let's let the backend do the math.
    // For visual representation we just show it's tampered. We will send the tamper flag to backend or just modify the hex string.
    // Actually, it's easier to just do it via big int if we have it, or let the backend do it.
    // Let's modify the hex visually:
    const oldVal = document.getElementById('sc-c2').innerText;
    document.getElementById('sc-c2').innerText = "[TAMPERED] " + oldVal;
    currentState.sc_tampered = true;
}

function tamperElGamal() {
    if(!currentState) return;
    const oldVal = document.getElementById('eg-c2').innerText;
    document.getElementById('eg-c2').innerText = "[TAMPERED] " + oldVal;
    currentState.eg_tampered = true;
}

async function decryptSigncrypt() {
    if(!currentState) return;
    
    // If tampered, we simulate multiplying c2 by 2 using BigInt
    let c2_val = currentState.c2;
    if(currentState.sc_tampered) {
        c2_val = (BigInt('0x' + currentState.c2) * 2n).toString(16);
    }

    try {
        const res = await fetch('/api/pa17/decrypt_signcrypt', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                c1: currentState.c1, 
                c2: c2_val, 
                sig: currentState.sig 
            })
        });
        const data = await res.json();
        
        const outBox = document.getElementById('sc-dec-out');
        const outVal = document.getElementById('sc-dec-val');
        outBox.style.display = 'block';
        
        if(data.rejected) {
            outVal.innerHTML = "<span style='color:var(--red)'>Signature check failed! Decryption aborted. Output: ⊥</span>";
        } else {
            outVal.innerHTML = `<span style='color:var(--green)'>Signature valid. Decrypted: ${data.dec}</span>`;
        }
    } catch(err) {
        alert("Error: " + err);
    }
}

async function decryptElGamal() {
    if(!currentState) return;
    
    let c2_val = currentState.plain_c2;
    if(currentState.eg_tampered) {
        c2_val = (BigInt('0x' + currentState.plain_c2) * 2n).toString(16);
    }

    try {
        const res = await fetch('/api/pa17/decrypt_elgamal', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                c1: currentState.plain_c1, 
                c2: c2_val
            })
        });
        const data = await res.json();
        
        const outBox = document.getElementById('eg-dec-out');
        const outVal = document.getElementById('eg-dec-val');
        outBox.style.display = 'block';
        
        outVal.innerHTML = `<span style='color:var(--green)'>Decrypted without verification. Output: ${data.dec}</span>`;
        if (currentState.eg_tampered && data.dec == currentState.m * 2) {
            outVal.innerHTML += `<br><br><span style='color:var(--amber)'>Adversary successfully mauled the plaintext to 2m!</span>`;
        }
    } catch(err) {
        alert("Error: " + err);
    }
}
